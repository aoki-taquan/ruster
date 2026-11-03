//! Opt-in exit protection of `ruster run` (`[exit-protection]`, OPS-EXIT).
//!
//! When the router exits, it detaches XDP from its ports (AF_PACKET: closes
//! its sockets); from then on the kernel handles their frames again and may
//! forward, answer, or route them without the router's firewall and NAT.
//! The startup checks refuse a kernel that would do that at startup, and the
//! link watch warns (AF_PACKET: fails) when it starts to while running, but
//! nothing stops an operator or another tool from turning kernel forwarding
//! on later, and `--allow-kernel-forwarding` runs with it on. Two opt-in
//! exit actions close the gap; both rewrite operator and kernel state, so
//! both default to off:
//!
//! - `ipv4-forwarding-off`: write `0` to every port's
//!   `net.ipv4.conf.<device>.forwarding` (the kernel then forwards nothing
//!   that arrives on the port). The files are opened write-only before the
//!   privilege drop and the filesystem confinement; Landlock checks only at
//!   open and the syscall filter allows `write`.
//! - `link-down`: clear `IFF_UP` of every port over rtnetlink (the kernel
//!   then neither receives nor sends on it, and drops the routes through
//!   it), on a socket opened before the syscall filter.
//!
//! Both need `CAP_NET_ADMIN` over the port's network namespace *at the
//! time of the change*, which no thread keeps after the default privilege
//! drop: rtnetlink checks the sending thread's capability at every change
//! request (`netlink_net_capable`: the socket opener's and the current
//! credentials), as do `SIOCSIFFLAGS` and the sysfs `flags` file, and
//! Linux re-checks a sysctl's permission at every write
//! (`proc_sys_call_handler`, `EPERM`), so a file opened before the drop
//! does not help either (verified on Linux 7.0 with uid 0 kept and no
//! capability: the write fails `EPERM`). Either key is therefore refused at
//! startup unless `--keep-privileges` (`EXIT_LINK_DOWN_NEEDS_PRIVILEGES`,
//! `EXIT_FORWARDING_NEEDS_PRIVILEGES`). Keeping one capability on one
//! thread would break the every-thread drop verification and protects
//! nothing within one address space; a helper process forked before the
//! drop that keeps `CAP_NET_ADMIN` and acts on its pipe's end of file is
//! the design that would also cover the default drop and `SIGKILL`
//! (proposed, not implemented: it keeps a privileged process alive).
//!
//! # When
//!
//! The actions are armed when the router reports readiness (it serves the
//! ports from then on) and run once, after the shutdown drain (which needs
//! the links up to complete TX) and before the ports are detached, so no
//! moment has the port detached and unprotected. That covers every exit of
//! a router that served: a stop signal, a fatal health or device event, a
//! backend fault, an invariant violation, and a panic (the guard's `Drop`
//! runs the actions while the panic unwinds, before the sessions close).
//! A startup that fails or is cancelled never arms them: the ports keep
//! the operator's state. A process killed outright (`SIGKILL`, a syscall
//! the filter kills, the OOM killer) runs nothing; a supervisor's
//! post-stop hook covers that (`docs/runbook-m2.md`).
//!
//! # Failure
//!
//! Each port and action is tried even when an earlier one failed. A
//! failure is reported as `exit protection failed: port=if<id>
//! action=<action> code=<code>` (value-free) and makes the exit status 1;
//! success is `exit protection applied: ...` with the counts.

use std::fmt;

use ruster_config::ExitProtectionV1;

// The panic path of the exit actions is the guard's `Drop` while the panic
// unwinds; with `panic = "abort"` it would never run.
#[cfg(panic = "abort")]
compile_error!(
    "ruster run needs panic = \"unwind\": the exit protection runs while a panic unwinds"
);
use ruster_core::IfId;

use super::fs_confine::FsConfineMode;
use super::netlink::NetlinkError;
use super::privileges::PrivilegePolicy;
use super::seccomp::SeccompMode;
use super::startup::token;

/// One exit action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitAction {
    /// `net.ipv4.conf.<device>.forwarding` = 0.
    Ipv4ForwardingOff,
    /// `IFF_UP` cleared.
    LinkDown,
}

impl ExitAction {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ipv4ForwardingOff => "ipv4-forwarding-off",
            Self::LinkDown => "link-down",
        }
    }
}

/// Why an exit action failed, or its resources could not be opened.
/// Value-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitError {
    /// A file call failed with this errno.
    Errno(i32),
    /// The sysctl write took fewer bytes than given.
    ShortWrite,
    /// The rtnetlink request failed.
    Netlink(NetlinkError),
    /// After its sysctl file was opened, the port's name no longer
    /// resolves to the port's interface index (a rename or a replacement
    /// between the startup checks and the open).
    Renamed,
    /// A failure injected by a test host.
    #[cfg(test)]
    Injected,
}

impl fmt::Display for ExitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Errno(errno) => write!(formatter, "ERRNO_{errno}"),
            Self::ShortWrite => formatter.write_str("SHORT_WRITE"),
            Self::Renamed => formatter.write_str("RENAMED"),
            Self::Netlink(NetlinkError::Kernel(error)) => {
                write!(formatter, "KERNEL_{}", error.unsigned_abs())
            }
            Self::Netlink(error) => write!(formatter, "NETLINK.{}", token(error)),
            #[cfg(test)]
            Self::Injected => formatter.write_str("INJECTED"),
        }
    }
}

/// One failed action of one port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitFailure {
    pub interface: IfId,
    pub action: ExitAction,
    pub error: ExitError,
}

/// What the exit actions did.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExitReport {
    /// Ports whose forwarding sysctl was written.
    pub forwarding_off: u32,
    /// Ports set down.
    pub link_down: u32,
    pub failures: Vec<ExitFailure>,
}

impl ExitReport {
    /// Records one action's outcome.
    pub fn record(&mut self, interface: IfId, action: ExitAction, result: Result<(), ExitError>) {
        match result {
            Ok(()) => match action {
                ExitAction::Ipv4ForwardingOff => self.forwarding_off += 1,
                ExitAction::LinkDown => self.link_down += 1,
            },
            Err(error) => self.failures.push(ExitFailure {
                interface,
                action,
                error,
            }),
        }
    }
}

/// The host's exit actions over resources opened before the privilege
/// drop. `apply` tries every port and action once.
pub trait ExitActions {
    fn apply(&mut self, report: &mut ExitReport);
}

/// Why `[exit-protection]` cannot work with the run's privilege policy.
/// Checked before any resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitPreflight {
    /// `link-down` without `--keep-privileges`.
    LinkDownNeedsPrivileges,
    /// `ipv4-forwarding-off` without `--keep-privileges`.
    ForwardingNeedsPrivileges,
    /// Either key with `--seccomp off` or `log`: the kept privileges would
    /// run with no syscall filter (`log` reports a violation and lets it
    /// run; it is a diagnostics mode, follow-up L2).
    NeedsSeccomp,
    /// Either key with `--fs-confine off`: the kept privileges would run
    /// with the whole filesystem view.
    NeedsFsConfine,
}

impl ExitPreflight {
    pub const fn code(self) -> &'static str {
        match self {
            Self::LinkDownNeedsPrivileges => "EXIT_LINK_DOWN_NEEDS_PRIVILEGES",
            Self::ForwardingNeedsPrivileges => "EXIT_FORWARDING_NEEDS_PRIVILEGES",
            Self::NeedsSeccomp => "EXIT_PROTECTION_NEEDS_SECCOMP",
            Self::NeedsFsConfine => "EXIT_PROTECTION_NEEDS_FS_CONFINE",
        }
    }

    pub const fn path(self) -> &'static str {
        match self {
            Self::LinkDownNeedsPrivileges => "exit-protection.link-down",
            Self::ForwardingNeedsPrivileges => "exit-protection.ipv4-forwarding-off",
            Self::NeedsSeccomp | Self::NeedsFsConfine => "exit-protection",
        }
    }

    /// The operator hint.
    pub const fn hint(self) -> &'static str {
        match self {
            Self::LinkDownNeedsPrivileges => {
                "setting a link down needs CAP_NET_ADMIN at exit; run with --keep-privileges \
                 (every capability stays on every thread), or set the link down in the \
                 supervisor's post-stop hook"
            }
            Self::ForwardingNeedsPrivileges => {
                "writing the forwarding sysctl needs CAP_NET_ADMIN at exit; run with \
                 --keep-privileges (every capability stays on every thread), or write it in \
                 the supervisor's post-stop hook"
            }
            Self::NeedsSeccomp => {
                "exit protection keeps every capability; it is refused unless the syscall \
                 filter kills (use --seccomp kill; log and off let every syscall run)"
            }
            Self::NeedsFsConfine => {
                "exit protection keeps every capability; it is refused without the filesystem \
                 confinement (use --fs-confine landlock)"
            }
        }
    }
}

/// Whether `protection` can work under `policy`: every exit action needs
/// `CAP_NET_ADMIN` at exit, so only `--keep-privileges` keeps it. Since
/// that keeps every capability on every thread, the interim posture
/// (until the owner decides on the helper process, see the architecture
/// document) also refuses it without the syscall filter or the
/// filesystem confinement (fail closed).
pub fn preflight(
    protection: ExitProtectionV1,
    policy: PrivilegePolicy,
    seccomp: SeccompMode,
    fs_confine: FsConfineMode,
) -> Result<(), ExitPreflight> {
    if !protection.any() {
        return Ok(());
    }
    if policy != PrivilegePolicy::Keep {
        return Err(if protection.link_down {
            ExitPreflight::LinkDownNeedsPrivileges
        } else {
            ExitPreflight::ForwardingNeedsPrivileges
        });
    }
    if seccomp != SeccompMode::Kill {
        return Err(ExitPreflight::NeedsSeccomp);
    }
    if fs_confine == FsConfineMode::Off {
        return Err(ExitPreflight::NeedsFsConfine);
    }
    Ok(())
}

/// The exit actions of one run: armed at readiness, run at most once
/// ([`Self::fire`], or `Drop` while a panic unwinds).
pub struct ExitGuard<A: ExitActions> {
    actions: Option<A>,
    armed: bool,
}

impl<A: ExitActions> ExitGuard<A> {
    /// `actions` is `None` when `[exit-protection]` is off.
    pub const fn new(actions: Option<A>) -> Self {
        Self {
            actions,
            armed: false,
        }
    }

    /// The router serves the ports from now on.
    pub fn arm(&mut self) -> bool {
        self.armed = self.actions.is_some();
        self.armed
    }

    /// Runs the actions once if armed; `None` if off or never armed (the
    /// ports were never served).
    pub fn fire(&mut self) -> Option<ExitReport> {
        if !self.armed {
            return None;
        }
        self.armed = false;
        let mut actions = self.actions.take()?;
        let mut report = ExitReport::default();
        actions.apply(&mut report);
        Some(report)
    }
}

impl<A: ExitActions> Drop for ExitGuard<A> {
    /// A panic between readiness and the end of the drain: the actions
    /// still run, unreported, before the ports are detached.
    fn drop(&mut self) {
        let _ = self.fire();
    }
}

/// The `exit protection armed:` line.
pub fn armed_line(protection: ExitProtectionV1, ports: usize) -> String {
    format!(
        "exit protection armed: ipv4-forwarding-off={} link-down={} ports={ports}",
        protection.ipv4_forwarding_off, protection.link_down
    )
}

/// The lines of a report: one per failure, then the summary.
pub fn report_lines(report: &ExitReport) -> Vec<String> {
    let mut lines: Vec<String> = report
        .failures
        .iter()
        .map(|failure| {
            format!(
                "exit protection failed: port=if{} action={} code={}",
                failure.interface.0,
                failure.action.label(),
                failure.error
            )
        })
        .collect();
    lines.push(format!(
        "exit protection applied: ipv4-forwarding-off={} link-down={} failed={}",
        report.forwarding_off,
        report.link_down,
        report.failures.len()
    ));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::privileges::Identity;

    const BOTH: ExitProtectionV1 = ExitProtectionV1 {
        link_down: true,
        ipv4_forwarding_off: true,
    };
    const FORWARDING: ExitProtectionV1 = ExitProtectionV1 {
        link_down: false,
        ipv4_forwarding_off: true,
    };

    #[test]
    fn preflight_requires_kept_privileges_for_either_key() {
        let drop = PrivilegePolicy::Drop { identity: None };
        let switch = PrivilegePolicy::Drop {
            identity: Some(Identity { uid: 1, gid: 1 }),
        };
        let off = ExitProtectionV1::default();
        for policy in [PrivilegePolicy::Keep, drop, switch] {
            assert_eq!(
                preflight(off, policy, SeccompMode::Off, FsConfineMode::Off),
                Ok(())
            );
        }
        assert_eq!(
            preflight(
                BOTH,
                PrivilegePolicy::Keep,
                SeccompMode::Kill,
                FsConfineMode::Landlock
            ),
            Ok(())
        );
        assert_eq!(
            preflight(
                FORWARDING,
                PrivilegePolicy::Keep,
                SeccompMode::Log,
                FsConfineMode::Landlock
            ),
            Err(ExitPreflight::NeedsSeccomp)
        );
        for policy in [drop, switch] {
            assert_eq!(
                preflight(BOTH, policy, SeccompMode::Kill, FsConfineMode::Landlock),
                Err(ExitPreflight::LinkDownNeedsPrivileges)
            );
            assert_eq!(
                preflight(
                    FORWARDING,
                    policy,
                    SeccompMode::Kill,
                    FsConfineMode::Landlock
                ),
                Err(ExitPreflight::ForwardingNeedsPrivileges)
            );
        }
        assert_eq!(
            preflight(
                BOTH,
                PrivilegePolicy::Keep,
                SeccompMode::Off,
                FsConfineMode::Landlock
            ),
            Err(ExitPreflight::NeedsSeccomp)
        );
        assert_eq!(
            preflight(
                BOTH,
                PrivilegePolicy::Keep,
                SeccompMode::Kill,
                FsConfineMode::Off
            ),
            Err(ExitPreflight::NeedsFsConfine)
        );
        assert_eq!(
            ExitPreflight::NeedsSeccomp.code(),
            "EXIT_PROTECTION_NEEDS_SECCOMP"
        );
        assert_eq!(
            ExitPreflight::LinkDownNeedsPrivileges.code(),
            "EXIT_LINK_DOWN_NEEDS_PRIVILEGES"
        );
        assert_eq!(
            ExitPreflight::ForwardingNeedsPrivileges.code(),
            "EXIT_FORWARDING_NEEDS_PRIVILEGES"
        );
    }

    struct Counting<'a>(&'a std::cell::Cell<u32>);

    impl ExitActions for Counting<'_> {
        fn apply(&mut self, report: &mut ExitReport) {
            self.0.set(self.0.get() + 1);
            report.record(IfId(1), ExitAction::Ipv4ForwardingOff, Ok(()));
            report.record(
                IfId(2),
                ExitAction::LinkDown,
                Err(ExitError::Netlink(NetlinkError::Kernel(-1))),
            );
        }
    }

    #[test]
    fn the_guard_fires_once_and_only_when_armed() {
        let calls = std::cell::Cell::new(0);
        // Never armed (a failed or cancelled startup): nothing, not even on
        // drop.
        let mut guard = ExitGuard::new(Some(Counting(&calls)));
        assert_eq!(guard.fire(), None);
        drop(guard);
        assert_eq!(calls.get(), 0);
        // Armed: once.
        let mut guard = ExitGuard::new(Some(Counting(&calls)));
        assert!(guard.arm());
        let report = guard.fire().expect("armed");
        assert_eq!(report.forwarding_off, 1);
        assert_eq!(report.link_down, 0);
        assert_eq!(guard.fire(), None);
        drop(guard);
        assert_eq!(calls.get(), 1);
        assert_eq!(
            report_lines(&report),
            [
                "exit protection failed: port=if2 action=link-down code=KERNEL_1",
                "exit protection applied: ipv4-forwarding-off=1 link-down=0 failed=1",
            ]
        );
        // Armed and unwound (a panic): the drop runs it.
        let mut guard = ExitGuard::new(Some(Counting(&calls)));
        guard.arm();
        drop(guard);
        assert_eq!(calls.get(), 2);
        // Off: arming does nothing.
        let mut off = ExitGuard::<Counting<'_>>::new(None);
        assert!(!off.arm());
        assert_eq!(off.fire(), None);
    }

    #[test]
    fn codes_are_value_free_tokens() {
        assert_eq!(ExitError::Errno(13).to_string(), "ERRNO_13");
        assert_eq!(ExitError::ShortWrite.to_string(), "SHORT_WRITE");
        assert_eq!(
            ExitError::Netlink(NetlinkError::Truncated).to_string(),
            "NETLINK.TRUNCATED"
        );
        assert_eq!(
            ExitError::Netlink(NetlinkError::Kernel(-19)).to_string(),
            "KERNEL_19"
        );
        assert_eq!(
            armed_line(BOTH, 2),
            "exit protection armed: ipv4-forwarding-off=true link-down=true ports=2"
        );
    }
}
