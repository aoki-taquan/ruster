//! Privilege drop of `ruster run` after startup (H6, CLI-089 to CLI-095).
//!
//! Startup needs `CAP_NET_ADMIN`, `CAP_NET_RAW`, and `CAP_BPF` +
//! `CAP_PERFMON` (or `CAP_SYS_ADMIN`) to open the AF_XDP sockets, register
//! the UMEMs, and load and attach the XDP programs. Nothing after that
//! needs a capability: the XSK kicks (`sendto`, `poll`) and
//! `getsockopt(XDP_STATISTICS)` act on sockets this process owns, ring and
//! UMEM access is plain memory, the link watch creates `NETLINK_ROUTE`
//! sockets and sends dump requests (open to every user), the sysctls it
//! reads are world-readable, a reload never opens a socket or attaches a
//! program (backend changes are restart-required and refused), and the
//! teardown closes the XDP link fd (which detaches), deletes the socket's
//! XSKMAP entry through the map fd this process holds (Linux 6.5 and newer
//! need no capability for that; see [`teardown_without_capabilities`]),
//! and unmaps and closes the rest.
//!
//! So once generation 1 is active and before the first tick, the process
//! drops everything, irreversibly ([`PrivilegePolicy::Drop`], the default;
//! `--keep-privileges` opts out). Linux credentials are per thread, and the
//! drop uses raw per-thread syscalls (not the C library's process-wide
//! `setuid` broadcast), so every thread drops itself:
//!
//! - the two output threads at spawn, before they write anything (they
//!   never need a privilege), and the spawn waits for the outcome;
//! - the router thread after startup.
//!
//! The router thread then reads `/proc/self/task/*/status` and requires
//! every thread of the process to hold no capability (fail closed). The
//! steps per thread, in order:
//!
//! 0. `PR_SET_DUMPABLE` 0 (per process; repeated right after `setresuid`,
//!    which resets it to `fs.suid_dumpable`, and read back at the end), so
//!    the target user cannot `ptrace` a switched thread while another
//!    thread is still privileged;
//! 1. `PR_SET_KEEPCAPS` 0 (an identity switch clears every capability);
//! 2. with `CAP_SETPCAP` effective, `PR_CAPBSET_DROP` of every capability
//!    (without it the bounding set stays as it was: reported as `kept`;
//!    with `no_new_privs` and empty permitted sets nothing can be regained
//!    from it);
//! 3. `PR_CAP_AMBIENT_CLEAR_ALL`;
//! 4. with `--user`/`--group`: `setgroups(0)`, `setresgid`, `setresuid`
//!    (real, effective, and saved);
//! 5. `capset` of empty effective, permitted, and inheritable sets;
//! 6. `PR_SET_NO_NEW_PRIVS` 1;
//! 7. `/proc/thread-self/status` must show `CapInh`, `CapPrm`, `CapEff`,
//!    and `CapAmb` 0, `NoNewPrivs` 1, the cleared bounding set, and with an
//!    identity switch every uid and gid switched and no supplementary
//!    group.
//!
//! Any failure aborts startup with a full rollback (exit 1,
//! `stage=privilege-drop`).

use std::fmt;

use ruster_core::{FieldValue, FieldVisitor, ObservableFields};

/// `CAP_SETPCAP`: needed to shrink the bounding set.
pub const CAP_SETPCAP: u32 = 8;

/// The unprivileged identity to switch to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub uid: u32,
    pub gid: u32,
}

/// What `ruster run` does with its privileges after startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivilegePolicy {
    /// `--keep-privileges`: every capability stays for the whole run.
    Keep,
    /// The default: drop every capability, optionally switch identity.
    Drop { identity: Option<Identity> },
}

impl Default for PrivilegePolicy {
    fn default() -> Self {
        Self::Drop { identity: None }
    }
}

/// The step of a per-thread drop that failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropStep {
    /// `PR_SET_DUMPABLE` 0 (or reading it back).
    Dumpable,
    Keepcaps,
    Bounding,
    Ambient,
    Groups,
    Gid,
    Uid,
    Capset,
    NoNewPrivs,
}

/// What a thread still held after its drop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Residue {
    /// A nonzero `CapInh`, `CapPrm`, `CapEff`, or `CapAmb`.
    Capabilities,
    /// A bounding set other than the expected one.
    Bounding,
    /// `NoNewPrivs` is not 1.
    NoNewPrivs,
    /// A uid or gid other than the configured identity.
    Identity,
    /// A supplementary group after an identity switch.
    Groups,
    /// The process is still dumpable (`PR_GET_DUMPABLE` is not 0).
    Dumpable,
}

/// Why a privilege drop failed. Value-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropFailure {
    /// A syscall of the drop failed with this errno.
    Syscall { step: DropStep, errno: i32 },
    /// A thread's `/proc/.../status` could not be read or parsed, or the
    /// task list could not be read.
    Unreadable,
    /// A thread of the process still holds this after the drop.
    NotDropped(Residue),
    /// A failure injected by a test host.
    #[cfg(test)]
    Injected,
}

impl fmt::Display for DropFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        use super::startup::token;
        match self {
            Self::Syscall { step, errno } => {
                write!(formatter, "code={}/ERRNO_{errno}", token(step))
            }
            Self::Unreadable => formatter.write_str("code=STATUS_UNREADABLE"),
            Self::NotDropped(residue) => write!(formatter, "code=NOT_DROPPED/{}", token(residue)),
            #[cfg(test)]
            Self::Injected => formatter.write_str("code=INJECTED"),
        }
    }
}

/// The credential facts of one thread (`/proc/<pid>/task/<tid>/status`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Credentials {
    pub inheritable: u64,
    pub permitted: u64,
    pub effective: u64,
    pub bounding: u64,
    pub ambient: u64,
    pub no_new_privs: bool,
    /// Real, effective, saved, and filesystem uid.
    pub uids: [u32; 4],
    /// Real, effective, saved, and filesystem gid.
    pub gids: [u32; 4],
    /// Number of supplementary groups.
    pub groups: usize,
}

fn hex_row(status: &str, name: &str) -> Option<u64> {
    let value = row(status, name)?.trim();
    if value.is_empty() || value.len() > 16 {
        return None;
    }
    u64::from_str_radix(value, 16).ok()
}

fn row<'a>(status: &'a str, name: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
}

fn ids(status: &str, name: &str) -> Option<[u32; 4]> {
    let mut fields = row(status, name)?.split_whitespace();
    let mut out = [0_u32; 4];
    for slot in &mut out {
        *slot = fields.next()?.parse().ok()?;
    }
    fields.next().is_none().then_some(out)
}

/// Parses the credential rows of a `status` file; `None` if one is
/// missing or malformed (fail closed).
pub fn parse_status(status: &str) -> Option<Credentials> {
    let no_new_privs = match row(status, "NoNewPrivs")?.trim() {
        "0" => false,
        "1" => true,
        _ => return None,
    };
    let groups = row(status, "Groups")?;
    let mut count = 0;
    for group in groups.split_whitespace() {
        group.parse::<u32>().ok()?;
        count += 1;
    }
    Some(Credentials {
        inheritable: hex_row(status, "CapInh")?,
        permitted: hex_row(status, "CapPrm")?,
        effective: hex_row(status, "CapEff")?,
        bounding: hex_row(status, "CapBnd")?,
        ambient: hex_row(status, "CapAmb")?,
        no_new_privs,
        uids: ids(status, "Uid")?,
        gids: ids(status, "Gid")?,
        groups: count,
    })
}

/// What every thread must show after the drop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Expected {
    /// The bounding set (0 once cleared).
    pub bounding: u64,
    pub identity: Option<Identity>,
}

/// Checks one thread's credentials after the drop.
pub fn check(credentials: &Credentials, expected: Expected) -> Result<(), Residue> {
    if credentials.inheritable != 0
        || credentials.permitted != 0
        || credentials.effective != 0
        || credentials.ambient != 0
    {
        return Err(Residue::Capabilities);
    }
    if credentials.bounding != expected.bounding {
        return Err(Residue::Bounding);
    }
    if !credentials.no_new_privs {
        return Err(Residue::NoNewPrivs);
    }
    if let Some(identity) = expected.identity {
        if credentials.uids != [identity.uid; 4] || credentials.gids != [identity.gid; 4] {
            return Err(Residue::Identity);
        }
        if credentials.groups != 0 {
            return Err(Residue::Groups);
        }
    }
    Ok(())
}

/// Whether the drop clears the bounding set: only with `CAP_SETPCAP`
/// effective (`PR_CAPBSET_DROP` needs it).
pub const fn clears_bounding(effective: u64) -> bool {
    effective & (1 << CAP_SETPCAP) != 0
}

/// Whether the teardown after the drop (the `BPF_MAP_DELETE_ELEM` of each
/// socket's XSKMAP entry on a map fd this process holds) works without a
/// capability. Before Linux 6.5 every `bpf(2)` command was refused without
/// `CAP_BPF`/`CAP_SYS_ADMIN` while `kernel.unprivileged_bpf_disabled` is
/// nonzero (the default since 5.16); 6.5 moved that check into map and
/// program creation. `release` is `/proc/sys/kernel/osrelease`; an
/// unparsable release counts as old (fail closed). Vendor kernels that
/// backported the 6.5 change under an older version number are not
/// detected and are refused too (fail closed: `--keep-privileges` there).
pub fn teardown_without_capabilities(release: &str, unprivileged_bpf_disabled: u32) -> bool {
    if unprivileged_bpf_disabled == 0 {
        return true;
    }
    kernel_version(release).is_some_and(|version| version >= (6, 5))
}

/// `(major, minor)` of a kernel release such as `6.8.0-45-generic`.
pub fn kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.trim().split(['.', '-', '+', '_']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Whether the bounding set was cleared.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bounding {
    Cleared,
    /// Without `CAP_SETPCAP` it cannot be shrunk; it stays as inherited.
    Kept,
}

/// The outcome of a successful process-wide drop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DropReport {
    /// Threads verified (every thread of the process).
    pub threads: u32,
    pub bounding: Bounding,
    pub identity_switched: bool,
}

/// The privilege state of the running router, for the stats blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivilegeState {
    Dropped(DropReport),
    Kept,
}

impl PrivilegeState {
    /// The value-free startup line.
    pub fn line(self) -> String {
        match self {
            Self::Dropped(report) => format!(
                "privileges dropped: threads={} capabilities=none bounding-set={} \
                 no-new-privs=1 identity={}",
                report.threads,
                bounding_label(report.bounding),
                identity_label(report.identity_switched),
            ),
            Self::Kept => "warning: privileges kept (--keep-privileges): every capability \
                           stays for the whole run"
                .to_owned(),
        }
    }
}

const fn bounding_label(bounding: Bounding) -> &'static str {
    match bounding {
        Bounding::Cleared => "cleared",
        Bounding::Kept => "kept",
    }
}

const fn identity_label(switched: bool) -> &'static str {
    if switched {
        "switched"
    } else {
        "unchanged"
    }
}

impl ObservableFields for PrivilegeState {
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        const SECTION: &str = "privileges";
        match self {
            Self::Dropped(report) => {
                visitor.field(SECTION, "state", FieldValue::Label("dropped"));
                visitor.field(
                    SECTION,
                    "bounding_set",
                    FieldValue::Label(bounding_label(report.bounding)),
                );
                visitor.field(
                    SECTION,
                    "identity",
                    FieldValue::Label(identity_label(report.identity_switched)),
                );
                visitor.field(
                    SECTION,
                    "threads",
                    FieldValue::Count(u64::from(report.threads)),
                );
            }
            Self::Kept => {
                visitor.field(SECTION, "state", FieldValue::Label("kept"));
                visitor.field(SECTION, "bounding_set", FieldValue::Label("kept"));
                visitor.field(SECTION, "identity", FieldValue::Label("unchanged"));
                visitor.field(SECTION, "threads", FieldValue::Count(0));
            }
        }
    }
}

/// The live drop: x86_64 Linux only (raw syscall numbers).
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
pub mod linux {
    use std::fs;

    use super::{
        check, clears_bounding, parse_status, Bounding, Credentials, DropFailure, DropReport,
        DropStep, Expected, Identity, PrivilegePolicy, Residue,
    };

    /// What one thread's drop left: its own credentials and whether it
    /// cleared the bounding set.
    #[derive(Clone, Copy, Debug)]
    pub struct ThreadDrop {
        pub credentials: Credentials,
        pub bounding: Bounding,
    }

    fn thread_status() -> Result<Credentials, DropFailure> {
        let text =
            fs::read_to_string("/proc/thread-self/status").map_err(|_| DropFailure::Unreadable)?;
        parse_status(&text).ok_or(DropFailure::Unreadable)
    }

    fn step<T>(step: DropStep, result: Result<T, i32>) -> Result<T, DropFailure> {
        result.map_err(|errno| DropFailure::Syscall { step, errno })
    }

    /// Drops every privilege of the calling thread (only), then verifies it
    /// from `/proc/thread-self/status`. Does nothing for
    /// [`PrivilegePolicy::Keep`].
    pub fn drop_thread(policy: PrivilegePolicy) -> Result<Option<ThreadDrop>, DropFailure> {
        let PrivilegePolicy::Drop { identity } = policy else {
            return Ok(None);
        };
        let before = thread_status()?;
        let bounding = if clears_bounding(before.effective) {
            Bounding::Cleared
        } else {
            Bounding::Kept
        };
        // Not dumpable before any identity change: a dumpable process whose
        // thread already runs as the target uid could be `ptrace`d by that
        // user while another thread is still privileged.
        step(DropStep::Dumpable, sys::set_not_dumpable())?;
        step(DropStep::Keepcaps, sys::set_keepcaps_off())?;
        if bounding == Bounding::Cleared {
            step(DropStep::Bounding, sys::clear_bounding_set())?;
        }
        step(DropStep::Ambient, sys::clear_ambient())?;
        if let Some(Identity { uid, gid }) = identity {
            step(DropStep::Groups, sys::clear_supplementary_groups())?;
            step(DropStep::Gid, sys::set_gid(gid))?;
            step(DropStep::Uid, sys::set_uid(uid))?;
            // An euid change resets the (per-process) dumpable flag to
            // `fs.suid_dumpable`; clear it again at once.
            step(DropStep::Dumpable, sys::set_not_dumpable())?;
        }
        step(DropStep::Capset, sys::clear_capabilities())?;
        step(DropStep::NoNewPrivs, sys::set_no_new_privs())?;
        if step(DropStep::Dumpable, sys::dumpable())? {
            return Err(DropFailure::NotDropped(Residue::Dumpable));
        }
        let after = thread_status()?;
        let expected = Expected {
            bounding: match bounding {
                Bounding::Cleared => 0,
                Bounding::Kept => before.bounding,
            },
            identity,
        };
        check(&after, expected).map_err(DropFailure::NotDropped)?;
        Ok(Some(ThreadDrop {
            credentials: after,
            bounding,
        }))
    }

    /// Drops the calling thread's privileges (the other threads already
    /// dropped their own at spawn), then requires every thread of the
    /// process (`/proc/self/task/*/status`) to show the same dropped
    /// state.
    pub fn drop_process(identity: Option<Identity>) -> Result<DropReport, DropFailure> {
        let own =
            drop_thread(PrivilegePolicy::Drop { identity })?.ok_or(DropFailure::Unreadable)?;
        let expected = Expected {
            bounding: own.credentials.bounding,
            identity,
        };
        let mut threads = 0_u32;
        let tasks = fs::read_dir("/proc/self/task").map_err(|_| DropFailure::Unreadable)?;
        for task in tasks {
            let task = task.map_err(|_| DropFailure::Unreadable)?;
            let text = fs::read_to_string(task.path().join("status"))
                .map_err(|_| DropFailure::Unreadable)?;
            let credentials = parse_status(&text).ok_or(DropFailure::Unreadable)?;
            check(&credentials, expected).map_err(DropFailure::NotDropped)?;
            threads = threads.saturating_add(1);
        }
        if threads == 0 {
            return Err(DropFailure::Unreadable);
        }
        Ok(DropReport {
            threads,
            bounding: own.bounding,
            identity_switched: identity.is_some(),
        })
    }

    /// Raw per-thread credential syscalls (x86_64 numbers). The C
    /// library's `setuid`/`setgroups` wrappers would change every thread
    /// of the process at once (the nptl/musl set-id broadcast), which the
    /// output threads must not do while the router thread still needs its
    /// privileges; `syscall(2)` changes only the calling thread.
    #[allow(unsafe_code)]
    mod sys {
        use std::os::raw::{c_int, c_long};

        const SYS_CAPSET: c_long = 126;
        const SYS_PRCTL: c_long = 157;
        const SYS_SETGROUPS: c_long = 116;
        const SYS_SETRESUID: c_long = 117;
        const SYS_SETRESGID: c_long = 119;

        const PR_SET_KEEPCAPS: c_long = 8;
        const PR_CAPBSET_DROP: c_long = 24;
        const PR_SET_NO_NEW_PRIVS: c_long = 38;
        const PR_GET_DUMPABLE: c_long = 3;
        const PR_SET_DUMPABLE: c_long = 4;
        const PR_CAP_AMBIENT: c_long = 47;
        const PR_CAP_AMBIENT_CLEAR_ALL: c_long = 4;
        const EINVAL: i32 = 22;
        /// `_LINUX_CAPABILITY_VERSION_3` (two 32-bit words per set).
        const CAPABILITY_VERSION_3: u32 = 0x2008_0522;
        /// Upper bound of the capability numbers tried (64-bit sets).
        const CAPABILITY_LIMIT: c_long = 64;

        /// `struct __user_cap_header_struct`.
        #[repr(C)]
        struct CapHeader {
            version: u32,
            pid: c_int,
        }

        /// `struct __user_cap_data_struct`.
        #[repr(C)]
        #[derive(Clone, Copy, Default)]
        struct CapData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }

        extern "C" {
            // `long syscall(long number, ...)` from the C library std
            // already links (glibc or musl); it passes up to six
            // `long`-sized arguments to the kernel and returns -1 with
            // `errno` set on failure.
            fn syscall(number: c_long, ...) -> c_long;
        }

        fn errno() -> i32 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        }

        fn result(value: c_long) -> Result<(), i32> {
            if value == -1 {
                Err(errno())
            } else {
                Ok(())
            }
        }

        fn prctl(option: c_long, argument: c_long) -> Result<(), i32> {
            // SAFETY: `prctl` with these options reads only its integer
            // arguments (the unused ones are passed as 0, as the ambient
            // and no_new_privs options require); no memory is passed. It
            // changes only the calling thread's credentials.
            result(unsafe { syscall(SYS_PRCTL, option, argument, 0_i64, 0_i64, 0_i64) })
        }

        pub fn set_keepcaps_off() -> Result<(), i32> {
            prctl(PR_SET_KEEPCAPS, 0)
        }

        /// Drops every capability from the bounding set, up to the first
        /// number the kernel does not know (`EINVAL`).
        pub fn clear_bounding_set() -> Result<(), i32> {
            for capability in 0..CAPABILITY_LIMIT {
                match prctl(PR_CAPBSET_DROP, capability) {
                    Ok(()) => {}
                    Err(EINVAL) if capability > 0 => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        }

        pub fn clear_ambient() -> Result<(), i32> {
            // SAFETY: as in `prctl`: integers only, calling thread only.
            result(unsafe {
                syscall(
                    SYS_PRCTL,
                    PR_CAP_AMBIENT,
                    PR_CAP_AMBIENT_CLEAR_ALL,
                    0_i64,
                    0_i64,
                    0_i64,
                )
            })
        }

        /// `PR_SET_DUMPABLE` 0: no core dump, and `ptrace` of any thread
        /// needs `CAP_SYS_PTRACE` (per process: it is a flag of the mm).
        pub fn set_not_dumpable() -> Result<(), i32> {
            prctl(PR_SET_DUMPABLE, 0)
        }

        /// Whether the process is dumpable (`PR_GET_DUMPABLE` nonzero).
        pub fn dumpable() -> Result<bool, i32> {
            // SAFETY: as in `prctl`: integers only, no memory passed; the
            // result is the flag (0, 1, or 2) or -1 with errno.
            let value = unsafe { syscall(SYS_PRCTL, PR_GET_DUMPABLE, 0_i64, 0_i64, 0_i64, 0_i64) };
            if value == -1 {
                return Err(errno());
            }
            Ok(value != 0)
        }

        pub fn set_no_new_privs() -> Result<(), i32> {
            prctl(PR_SET_NO_NEW_PRIVS, 1)
        }

        pub fn clear_supplementary_groups() -> Result<(), i32> {
            // SAFETY: `setgroups(0, NULL)`: a zero size and a null list,
            // which the kernel never dereferences; calling thread only (the
            // raw syscall, not the C library's broadcast).
            result(unsafe { syscall(SYS_SETGROUPS, 0_i64, 0_i64) })
        }

        pub fn set_gid(gid: u32) -> Result<(), i32> {
            let gid = c_long::from(gid);
            // SAFETY: `setresgid` takes three integers; calling thread
            // only.
            result(unsafe { syscall(SYS_SETRESGID, gid, gid, gid) })
        }

        pub fn set_uid(uid: u32) -> Result<(), i32> {
            let uid = c_long::from(uid);
            // SAFETY: `setresuid` takes three integers; calling thread
            // only.
            result(unsafe { syscall(SYS_SETRESUID, uid, uid, uid) })
        }

        /// Empty effective, permitted, and inheritable sets.
        pub fn clear_capabilities() -> Result<(), i32> {
            let mut header = CapHeader {
                version: CAPABILITY_VERSION_3,
                pid: 0,
            };
            let data = [CapData::default(); 2];
            // SAFETY: `header` is a live, initialized `repr(C)`
            // `__user_cap_header_struct` (the kernel may write the
            // preferred version back into it on a version mismatch, so it
            // is passed mutably) and `data` two live, initialized `repr(C)`
            // `__user_cap_data_struct`s, as version 3 requires; the kernel
            // only reads `data`. Both outlive the call. `pid` 0 is the
            // calling thread.
            result(unsafe {
                syscall(
                    SYS_CAPSET,
                    (&raw mut header).cast::<u8>(),
                    data.as_ptr().cast::<u8>(),
                )
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "Name:\truster\nUmask:\t0022\nState:\tR (running)\n\
        Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nFDSize:\t64\nGroups:\t0 1 \n\
        NoNewPrivs:\t0\nSeccomp:\t0\nCapInh:\t0000000000000000\n\
        CapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\n\
        CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n";

    const DROPPED: &str = "Name:\truster\nUid:\t990\t990\t990\t990\n\
        Gid:\t991\t991\t991\t991\nGroups:\t\nNoNewPrivs:\t1\n\
        CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n\
        CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n\
        CapAmb:\t0000000000000000\n";

    #[test]
    fn status_rows_parse_and_fail_closed() {
        let root = parse_status(ROOT).expect("root status");
        assert_eq!(root.effective, 0x1ff_ffff_ffff);
        assert_eq!(root.bounding, 0x1ff_ffff_ffff);
        assert_eq!(root.inheritable, 0);
        assert!(!root.no_new_privs);
        assert_eq!(root.uids, [0; 4]);
        assert_eq!(root.groups, 2);
        let dropped = parse_status(DROPPED).expect("dropped status");
        assert_eq!(dropped.groups, 0);
        assert!(dropped.no_new_privs);
        assert_eq!(dropped.uids, [990; 4]);
        assert_eq!(dropped.gids, [991; 4]);
        // Every row is required; a malformed one fails closed.
        for row in [
            "CapInh",
            "CapPrm",
            "CapEff",
            "CapBnd",
            "CapAmb",
            "NoNewPrivs",
            "Uid",
            "Gid",
            "Groups",
        ] {
            let without: String = DROPPED
                .lines()
                .filter(|line| !line.starts_with(&format!("{row}:")))
                .map(|line| format!("{line}\n"))
                .collect();
            assert_eq!(parse_status(&without), None, "{row} missing");
        }
        for broken in [
            DROPPED.replace("NoNewPrivs:\t1", "NoNewPrivs:\t2"),
            DROPPED.replace("CapEff:\t0000000000000000", "CapEff:\tzz"),
            DROPPED.replace("CapEff:\t0000000000000000", "CapEff:\t00000000000000000"),
            DROPPED.replace("Uid:\t990\t990\t990\t990", "Uid:\t990\t990\t990"),
            DROPPED.replace("Uid:\t990\t990\t990\t990", "Uid:\t990\t990\t990\t990\t1"),
            DROPPED.replace("Groups:\t", "Groups:\tx"),
        ] {
            assert_eq!(parse_status(&broken), None, "{broken}");
        }
        // A row name is matched exactly (no prefix match).
        let shadowed = format!("CapEffX:\t1\n{DROPPED}");
        assert_eq!(parse_status(&shadowed).map(|c| c.effective), Some(0));
    }

    #[test]
    fn check_requires_every_set_empty_no_new_privs_and_the_identity() {
        let dropped = parse_status(DROPPED).expect("dropped");
        let identity = Identity { uid: 990, gid: 991 };
        let expected = Expected {
            bounding: 0,
            identity: Some(identity),
        };
        assert_eq!(check(&dropped, expected), Ok(()));
        let with = |edit: fn(&mut Credentials)| {
            let mut credentials = dropped;
            edit(&mut credentials);
            check(&credentials, expected)
        };
        assert_eq!(with(|c| c.effective = 1 << 12), Err(Residue::Capabilities));
        assert_eq!(with(|c| c.permitted = 1), Err(Residue::Capabilities));
        assert_eq!(
            with(|c| c.inheritable = 1 << 39),
            Err(Residue::Capabilities)
        );
        assert_eq!(with(|c| c.ambient = 1 << 13), Err(Residue::Capabilities));
        assert_eq!(with(|c| c.bounding = 1), Err(Residue::Bounding));
        assert_eq!(with(|c| c.no_new_privs = false), Err(Residue::NoNewPrivs));
        assert_eq!(with(|c| c.uids[2] = 0), Err(Residue::Identity));
        assert_eq!(with(|c| c.uids[3] = 0), Err(Residue::Identity));
        assert_eq!(with(|c| c.gids[0] = 0), Err(Residue::Identity));
        assert_eq!(with(|c| c.groups = 1), Err(Residue::Groups));
        // Without an identity switch the ids and groups are not checked,
        // and a kept bounding set must equal the expected one.
        let root_dropped = Credentials {
            uids: [0; 4],
            gids: [0; 4],
            groups: 1,
            bounding: 0xff,
            ..dropped
        };
        let kept = Expected {
            bounding: 0xff,
            identity: None,
        };
        assert_eq!(check(&root_dropped, kept), Ok(()));
        assert_eq!(
            check(
                &root_dropped,
                Expected {
                    bounding: 0,
                    ..kept
                }
            ),
            Err(Residue::Bounding)
        );
    }

    #[test]
    fn the_bounding_set_is_cleared_only_with_cap_setpcap() {
        assert!(clears_bounding(1 << CAP_SETPCAP));
        assert!(clears_bounding(u64::MAX));
        assert!(!clears_bounding(!(1 << CAP_SETPCAP)));
        assert!(!clears_bounding(0));
    }

    #[test]
    fn teardown_needs_6_5_unless_unprivileged_bpf_is_allowed() {
        assert_eq!(kernel_version("6.8.0-45-generic"), Some((6, 8)));
        assert_eq!(kernel_version("7.0.0-34-generic\n"), Some((7, 0)));
        assert_eq!(kernel_version("6.5"), Some((6, 5)));
        assert_eq!(kernel_version("5.15.0+"), Some((5, 15)));
        assert_eq!(kernel_version("garbage"), None);
        assert_eq!(kernel_version("6"), None);
        for release in ["6.5.0", "6.8.0-45-generic", "7.0.0-34-generic", "10.0.1"] {
            for disabled in [0, 1, 2] {
                assert!(
                    teardown_without_capabilities(release, disabled),
                    "{release}"
                );
            }
        }
        for release in ["6.4.16", "5.15.0-1-azure", "5.9.0", "4.20.0", "x.y"] {
            assert!(!teardown_without_capabilities(release, 1), "{release}");
            assert!(!teardown_without_capabilities(release, 2), "{release}");
            assert!(teardown_without_capabilities(release, 0), "{release}");
        }
    }

    /// The live per-thread drop on this kernel, on a dedicated thread of
    /// the test process (the drop is irreversible for that thread only):
    /// every set empty and `NoNewPrivs` 1 there, the spawning thread
    /// untouched (raw per-thread syscalls, no set-id broadcast), and the
    /// process-wide verification fails closed while another thread still
    /// holds what the dropped one gave up.
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn the_live_drop_changes_only_the_calling_thread() {
        let status = |path: &str| {
            parse_status(&std::fs::read_to_string(path).expect("status")).expect("parse")
        };
        let parent = status("/proc/thread-self/status");
        let parent_tid = std::fs::read_link("/proc/thread-self").expect("thread-self");
        let parent_path = format!("/proc/{}/status", parent_tid.display());
        let (dropped, report) = std::thread::spawn(move || {
            let dropped = linux::drop_thread(PrivilegePolicy::Drop { identity: None })
                .expect("drop")
                .expect("dropped");
            // Irreversible on this thread: a second drop finds nothing
            // left to drop and passes again.
            let again = linux::drop_thread(PrivilegePolicy::Drop { identity: None });
            assert!(matches!(again, Ok(Some(_))), "{again:?}");
            (dropped, linux::drop_process(None))
        })
        .join()
        .expect("thread");
        let own = dropped.credentials;
        assert_eq!(
            (own.inheritable, own.permitted, own.effective, own.ambient),
            (0, 0, 0, 0)
        );
        assert!(own.no_new_privs);
        assert_eq!(own.uids, parent.uids, "no identity switch");
        match dropped.bounding {
            Bounding::Cleared => assert_eq!(own.bounding, 0),
            Bounding::Kept => assert_eq!(own.bounding, parent.bounding),
        }
        assert_eq!(
            dropped.bounding == Bounding::Cleared,
            clears_bounding(parent.effective)
        );
        // The spawning thread kept everything it had.
        let after = status(&parent_path);
        assert_eq!(after, parent, "the drop leaked to another thread");
        // `drop_process` checks every thread: the parent (and the test
        // harness's other threads) still differ unless they hold nothing
        // and already have no_new_privs (a sandboxed test process).
        let parent_clean = check(
            &parent,
            Expected {
                bounding: own.bounding,
                identity: None,
            },
        )
        .is_ok();
        match report {
            Err(DropFailure::NotDropped(_)) => assert!(!parent_clean),
            Ok(report) => {
                assert!(parent_clean, "an undropped thread passed");
                assert!(report.threads >= 2);
            }
            Err(other) => panic!("{other:?}"),
        }
    }

    /// The identity switch: with `CAP_SETGID` it switches this thread
    /// only; without it the first set-id step fails with `EPERM` (fail
    /// closed) before it reaches the uid, `capset`, or no_new_privs steps
    /// (the earlier dumpable, keepcaps, bounding, and ambient steps have run
    /// on that thread).
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn the_live_identity_switch_needs_setgid_and_stays_on_its_thread() {
        let parent = parse_status(&std::fs::read_to_string("/proc/thread-self/status").unwrap())
            .expect("parse");
        let identity = Identity {
            uid: 65_534,
            gid: 65_534,
        };
        let result = std::thread::spawn(move || {
            linux::drop_thread(PrivilegePolicy::Drop {
                identity: Some(identity),
            })
        })
        .join()
        .expect("thread");
        if parent.effective & super::super::checks::SWITCH_CAPABILITIES
            == super::super::checks::SWITCH_CAPABILITIES
        {
            let dropped = result.expect("switched").expect("dropped");
            assert_eq!(dropped.credentials.uids, [65_534; 4]);
            assert_eq!(dropped.credentials.gids, [65_534; 4]);
            assert_eq!(dropped.credentials.groups, 0);
            assert_eq!(dropped.credentials.effective, 0);
            let after = parse_status(&std::fs::read_to_string("/proc/thread-self/status").unwrap())
                .expect("parse");
            assert_eq!(after.uids, parent.uids, "the switch leaked to this thread");
        } else {
            assert_eq!(
                result.map(|dropped| dropped.map(|d| d.credentials)),
                Err(DropFailure::Syscall {
                    step: DropStep::Groups,
                    errno: 1
                })
            );
        }
    }

    #[test]
    fn state_line_and_fields_are_value_free() {
        let dropped = PrivilegeState::Dropped(DropReport {
            threads: 3,
            bounding: Bounding::Cleared,
            identity_switched: true,
        });
        assert_eq!(
            dropped.line(),
            "privileges dropped: threads=3 capabilities=none bounding-set=cleared \
             no-new-privs=1 identity=switched"
        );
        let mut text = String::new();
        super::super::stats::write_fields(&mut text, None, &dropped);
        assert_eq!(
            text,
            "privileges.state=dropped\nprivileges.bounding_set=cleared\n\
             privileges.identity=switched\nprivileges.threads=3\n"
        );
        let mut text = String::new();
        super::super::stats::write_fields(&mut text, None, &PrivilegeState::Kept);
        assert_eq!(
            text,
            "privileges.state=kept\nprivileges.bounding_set=kept\n\
             privileges.identity=unchanged\nprivileges.threads=0\n"
        );
        assert!(PrivilegeState::Kept.line().contains("--keep-privileges"));
        assert_eq!(
            DropFailure::Syscall {
                step: DropStep::NoNewPrivs,
                errno: 1
            }
            .to_string(),
            "code=NO_NEW_PRIVS/ERRNO_1"
        );
        assert_eq!(
            DropFailure::NotDropped(Residue::Capabilities).to_string(),
            "code=NOT_DROPPED/CAPABILITIES"
        );
        assert_eq!(
            PrivilegePolicy::default(),
            PrivilegePolicy::Drop { identity: None }
        );
    }
}
