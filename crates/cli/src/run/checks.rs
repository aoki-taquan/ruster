//! Startup checks of `ruster run`: privileges and memlock (before any
//! resource), and the XDP-063 per-port device checks (after the session is
//! open, before XDP attach).
//!
//! The decisions are pure functions over facts read from procfs and
//! rtnetlink (link facts and kernel IPv4 addresses of the session's
//! interface index, in the caller's network namespace), so they are tested
//! without a kernel.
//! Every reader fails closed: a fact that cannot be read refuses startup,
//! except the forwarding sysctls, which only ever warn.

use std::fmt;

use ruster_config::{AfXdpModeV1, ValidatedAfXdpV1};

/// Linux capability bits (`include/uapi/linux/capability.h`).
pub mod cap {
    pub const NET_ADMIN: u32 = 12;
    pub const NET_RAW: u32 = 13;
    pub const IPC_LOCK: u32 = 14;
    pub const SYS_ADMIN: u32 = 21;
    pub const PERFMON: u32 = 38;
    pub const BPF: u32 = 39;
}

const fn bit(capability: u32) -> u64 {
    1 << capability
}

/// What [`evaluate_privileges`] refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivilegeFailure {
    /// `/proc/self/status` or `/proc/self/limits` could not be read or
    /// parsed.
    Unreadable(ProcSource),
    /// The effective capability set lacks the listed capabilities (bit set
    /// of [`cap`] numbers).
    MissingCapabilities(u64),
    /// Without `CAP_IPC_LOCK`, the soft `RLIMIT_MEMLOCK` is below what the
    /// UMEMs pin.
    MemlockLimit { limit: u64, required: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcSource {
    Status,
    Limits,
}

impl ProcSource {
    const fn path(self) -> &'static str {
        match self {
            Self::Status => "/proc/self/status",
            Self::Limits => "/proc/self/limits",
        }
    }
}

/// `CAP_*` names of a missing-capability set, comma separated.
pub fn capability_names(set: u64) -> String {
    const NAMES: [(u32, &str); 6] = [
        (cap::NET_ADMIN, "CAP_NET_ADMIN"),
        (cap::NET_RAW, "CAP_NET_RAW"),
        (cap::IPC_LOCK, "CAP_IPC_LOCK"),
        (cap::SYS_ADMIN, "CAP_SYS_ADMIN"),
        (cap::PERFMON, "CAP_PERFMON"),
        (cap::BPF, "CAP_BPF"),
    ];
    let mut names = String::new();
    for (number, name) in NAMES {
        if set & bit(number) != 0 {
            if !names.is_empty() {
                names.push(',');
            }
            names.push_str(name);
        }
    }
    names
}

impl fmt::Display for PrivilegeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable(source) => write!(formatter, "UNREADABLE source={}", source.path()),
            Self::MissingCapabilities(set) => {
                write!(
                    formatter,
                    "MISSING_CAPABILITIES missing={}",
                    capability_names(*set)
                )
            }
            Self::MemlockLimit { limit, required } => write!(
                formatter,
                "MEMLOCK_LIMIT limit-bytes={limit} required-bytes={required}"
            ),
        }
    }
}

/// The soft `RLIMIT_MEMLOCK`: `None` is unlimited.
pub type MemlockLimit = Option<u64>;

/// Memlock reserved per port for its BPF objects (the redirect program and
/// a `queue + 1` entry XSKMAP). Linux before 5.11 charges BPF maps and
/// programs to `RLIMIT_MEMLOCK` (later kernels use memcg); the program is
/// a few instructions and the map a few pages, so 64 KiB is a generous
/// margin, not an exact kernel figure.
pub const BPF_MEMLOCK_MARGIN_PER_PORT: u64 = 64 * 1_024;

/// Bytes that `ruster run` expects to pin against `RLIMIT_MEMLOCK`: each
/// port's UMEM rounded up to whole 4 KiB pages, twice for `mode = "auto"`
/// (XDP-045: the copy fallback registers a second UMEM while the first
/// one's accounting is still released from deferred work), plus
/// [`BPF_MEMLOCK_MARGIN_PER_PORT`].
///
/// This is a lower bound: the kernel charges the pages to the user
/// (`user->locked_vm`), so other processes of the same user and a
/// just-closed previous run count too, and the BPF figure is an estimate
/// for pre-5.11 kernels.
pub fn required_memlock(backend: &ValidatedAfXdpV1) -> u64 {
    const PAGE: u64 = 4_096;
    backend.ports().iter().fold(0_u64, |total, port| {
        let pages = port.umem().byte_len().div_ceil(PAGE).saturating_mul(PAGE);
        let factor = match port.mode() {
            AfXdpModeV1::Auto => 2,
            AfXdpModeV1::Copy | AfXdpModeV1::ZeroCopy => 1,
        };
        total
            .saturating_add(pages.saturating_mul(factor))
            .saturating_add(BPF_MEMLOCK_MARGIN_PER_PORT)
    })
}

/// Capabilities the effective set must hold: `CAP_NET_RAW` (AF_XDP socket),
/// `CAP_NET_ADMIN` (XSKMAP, XDP link), and either `CAP_BPF` with
/// `CAP_PERFMON` or `CAP_SYS_ADMIN` (program and map load). Root holds all
/// of them.
pub fn missing_capabilities(effective: u64) -> u64 {
    let mut missing = 0;
    for capability in [cap::NET_ADMIN, cap::NET_RAW] {
        if effective & bit(capability) == 0 {
            missing |= bit(capability);
        }
    }
    let bpf = bit(cap::BPF) | bit(cap::PERFMON);
    if effective & bit(cap::SYS_ADMIN) == 0 && effective & bpf != bpf {
        missing |= bpf & !effective;
    }
    missing
}

/// Refuses startup unless the effective capabilities and the memlock
/// limit suffice. `CAP_IPC_LOCK` lifts the memlock limit.
pub fn evaluate_privileges(
    effective: u64,
    memlock: MemlockLimit,
    required: u64,
) -> Result<(), PrivilegeFailure> {
    let missing = missing_capabilities(effective);
    if missing != 0 {
        return Err(PrivilegeFailure::MissingCapabilities(missing));
    }
    if effective & bit(cap::IPC_LOCK) == 0 {
        if let Some(limit) = memlock {
            if limit < required {
                return Err(PrivilegeFailure::MemlockLimit { limit, required });
            }
        }
    }
    Ok(())
}

/// `CapEff:` of `/proc/<pid>/status`, a hex mask.
pub fn parse_cap_eff(status: &str) -> Option<u64> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))?
        .trim();
    if value.is_empty() || value.len() > 16 {
        return None;
    }
    u64::from_str_radix(value, 16).ok()
}

/// The soft limit of the `Max locked memory` row of `/proc/<pid>/limits`
/// (`unlimited` or bytes).
pub fn parse_memlock(limits: &str) -> Option<MemlockLimit> {
    let row = limits
        .lines()
        .find_map(|line| line.strip_prefix("Max locked memory"))?;
    let soft = row.split_whitespace().next()?;
    if soft == "unlimited" {
        return Some(None);
    }
    soft.parse::<u64>().ok().map(Some)
}

/// Facts of one port's device read after the session opened.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceFacts {
    /// The session's interface index (the link watch queries it later).
    pub ifindex: u32,
    /// `IFLA_NUM_RX_QUEUES` of the session's interface index (rtnetlink
    /// `RTM_GETLINK`, so in the caller's network namespace): the
    /// allocated RX queue count, which is never below the active one; 0
    /// if the kernel did not report it.
    pub rx_queues: u32,
    /// `IFLA_MTU` of the session's interface index (rtnetlink).
    pub link_mtu: u32,
    /// The MTU the session read at open, which bounds every TX of the
    /// adapter (`mtu + 14`).
    pub session_mtu: u32,
    /// The longest frame a UMEM frame of this port holds
    /// (`frame-size` minus the 256-byte kernel headroom).
    pub frame_capacity: u32,
    /// Kernel IPv4 addresses on the device (netlink `RTM_GETADDR`).
    pub ipv4_addresses: u32,
    /// Main-table kernel IPv4 routes out of the device
    /// (`/proc/net/route`).
    pub ipv4_routes: u32,
    /// `/proc/sys/net/ipv4/ip_forward`; `None` if unreadable.
    pub forwarding_global: Option<bool>,
    /// `/proc/sys/net/ipv4/conf/<dev>/forwarding`; `None` if unreadable.
    pub forwarding_device: Option<bool>,
}

/// Operator overrides of the device checks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CheckPolicy {
    /// `--allow-multi-queue`.
    pub allow_multi_queue: bool,
}

/// Why a port's device check refused startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckFailure {
    /// The device has (allocates) more than one RX queue and
    /// `--allow-multi-queue` was not given: frames on the other queues
    /// would be dropped by the XDP program (XDP-050).
    MultiQueue { rx_queues: u32 },
    /// The kernel holds IPv4 addresses on the port (refused, see
    /// [`evaluate_device`]).
    KernelIpv4Addresses { count: u32 },
    /// The kernel's main table routes IPv4 out of the port.
    KernelIpv4Routes { count: u32 },
    /// The device MTU plus the 14-byte Ethernet header does not fit a
    /// UMEM frame: the kernel would drop (copy mode) or split (driver
    /// multi-buffer) every longer frame before the router sees it.
    /// `limit` is the largest MTU the frames hold.
    MtuAboveFrame { mtu: u32, limit: u32 },
    /// A fact could not be read or did not belong to the opened device.
    Unverifiable(Probe),
}

/// Which device fact could not be established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Probe {
    /// The rtnetlink `RTM_GETLINK` query of the session's interface index
    /// failed.
    Link,
    /// The link reply carried no (or a zero) `IFLA_NUM_RX_QUEUES`
    /// (a kernel without `CONFIG_RPS`).
    RxQueues,
    /// The link's MTU differs from the one the session read at open (the
    /// MTU changed in between, or the session's sysfs view is not this
    /// namespace's device).
    Mtu,
    /// The netlink address dump failed.
    Ipv4Addresses,
    /// `/proc/net/route` could not be read or parsed.
    Ipv4Routes,
}

impl fmt::Display for CheckFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MultiQueue { rx_queues } => {
                write!(formatter, "MULTI_QUEUE_DEVICE rx-queues={rx_queues}")
            }
            Self::KernelIpv4Addresses { count } => {
                write!(formatter, "KERNEL_IPV4_ADDRESSES count={count}")
            }
            Self::KernelIpv4Routes { count } => {
                write!(formatter, "KERNEL_IPV4_ROUTES count={count}")
            }
            Self::MtuAboveFrame { mtu, limit } => {
                write!(formatter, "MTU_ABOVE_FRAME mtu={mtu} limit={limit}")
            }
            Self::Unverifiable(Probe::Link) => formatter.write_str("UNVERIFIABLE probe=link"),
            Self::Unverifiable(Probe::RxQueues) => {
                formatter.write_str("UNVERIFIABLE probe=rx-queues")
            }
            Self::Unverifiable(Probe::Mtu) => formatter.write_str("UNVERIFIABLE probe=mtu"),
            Self::Unverifiable(Probe::Ipv4Addresses) => {
                formatter.write_str("UNVERIFIABLE probe=ipv4-addresses")
            }
            Self::Unverifiable(Probe::Ipv4Routes) => {
                formatter.write_str("UNVERIFIABLE probe=ipv4-routes")
            }
        }
    }
}

/// Non-fatal findings of one port's device check.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Warnings {
    /// A multi-queue device accepted through `--allow-multi-queue`.
    pub multi_queue: Option<u32>,
    /// `net.ipv4.ip_forward` is on.
    pub forwarding_global: bool,
    /// `net.ipv4.conf.<dev>.forwarding` is on.
    pub forwarding_device: bool,
    /// A forwarding sysctl could not be read.
    pub forwarding_unreadable: bool,
}

impl Warnings {
    /// Stable warning codes, in a fixed order.
    pub fn codes(&self) -> impl Iterator<Item = String> + '_ {
        let multi = self
            .multi_queue
            .map(|queues| format!("MULTI_QUEUE_ALLOWED rx-queues={queues}"));
        let global = self
            .forwarding_global
            .then(|| "IPV4_FORWARDING_ENABLED scope=global".to_owned());
        let device = self
            .forwarding_device
            .then(|| "IPV4_FORWARDING_ENABLED scope=device".to_owned());
        let unreadable = self
            .forwarding_unreadable
            .then(|| "IPV4_FORWARDING_UNVERIFIABLE".to_owned());
        multi
            .into_iter()
            .chain(global)
            .chain(device)
            .chain(unreadable)
    }
}

/// XDP-063 decision for one port.
///
/// - RX queues: exactly one, or `--allow-multi-queue` (warned). The XDP
///   program drops frames of queues without a socket (XDP-050, fail
///   closed), so a multi-queue device silently loses traffic unless the
///   operator steers everything to the bound queue (`ethtool -X`/ntuple).
/// - Kernel IPv4 addresses: refused. While the program is attached the
///   kernel never sees the port's frames, so an address only matters when
///   it is detached: before startup, after shutdown, and after a crash or
///   `SIGKILL` (the unpinned link auto-detaches). Then the kernel answers
///   ARP and, with forwarding on, routes between the ports without the
///   firewall or NAT (fail open). An address also lets the host's own
///   traffic leave through the port with the kernel's source and ARP.
///   Refusing keeps the documented operating requirement (no kernel L3 on
///   ports, XDP-050) checked instead of assumed.
/// - Kernel IPv4 routes out of the port (main table, for example
///   `ip route add 10.0.0.0/8 dev <port>` without an address): refused for
///   the same reason; addresses are checked first, so a connected route
///   reports its address.
/// - Forwarding sysctls: warned only. `ip_forward` is namespace-wide and
///   may be needed by other interfaces of the host (containers, VPN);
///   without kernel addresses or routes on the ports the kernel has no
///   connected route through them, so refusing would block legitimate
///   hosts for a second-order risk. Unreadable sysctls are warned too.
/// - MTU: the rtnetlink MTU must equal the one the session read at open
///   (which bounds TX), and it must fit a UMEM frame with its Ethernet
///   header ([`mtu_limit`]); both refusals keep the run-time MTU rule of
///   the link watch (a change beyond that bound is fatal) true from the
///   first tick.
///
/// The RX queue count is `IFLA_NUM_RX_QUEUES`, the *allocated* count: a
/// driver that allocates more queues than it activates (`ethtool -l`
/// shows `Combined: 1` of a larger maximum) is counted as multi-queue and
/// needs `--allow-multi-queue` (fail closed: the netlink count is
/// namespace-correct, the active count is only in sysfs, whose mount may
/// belong to another namespace).
pub fn evaluate_device(facts: &DeviceFacts, policy: CheckPolicy) -> Result<Warnings, CheckFailure> {
    if facts.rx_queues == 0 {
        return Err(CheckFailure::Unverifiable(Probe::RxQueues));
    }
    if facts.link_mtu != facts.session_mtu {
        return Err(CheckFailure::Unverifiable(Probe::Mtu));
    }
    let limit = mtu_limit(facts.frame_capacity);
    if facts.link_mtu > limit {
        return Err(CheckFailure::MtuAboveFrame {
            mtu: facts.link_mtu,
            limit,
        });
    }
    let mut warnings = Warnings::default();
    if facts.rx_queues > 1 {
        if !policy.allow_multi_queue {
            return Err(CheckFailure::MultiQueue {
                rx_queues: facts.rx_queues,
            });
        }
        warnings.multi_queue = Some(facts.rx_queues);
    }
    if facts.ipv4_addresses != 0 {
        return Err(CheckFailure::KernelIpv4Addresses {
            count: facts.ipv4_addresses,
        });
    }
    if facts.ipv4_routes != 0 {
        return Err(CheckFailure::KernelIpv4Routes {
            count: facts.ipv4_routes,
        });
    }
    warnings.forwarding_global = facts.forwarding_global == Some(true);
    warnings.forwarding_device = facts.forwarding_device == Some(true);
    warnings.forwarding_unreadable =
        facts.forwarding_global.is_none() || facts.forwarding_device.is_none();
    Ok(warnings)
}

/// The largest MTU whose frames (MTU plus the 14-byte Ethernet header)
/// fit a UMEM frame of `frame_capacity` bytes.
pub const fn mtu_limit(frame_capacity: u32) -> u32 {
    frame_capacity.saturating_sub(14)
}

/// A `0`/`1` sysctl file.
pub fn parse_flag(text: &str) -> Option<bool> {
    match text.trim() {
        "0" => Some(false),
        "1" => Some(true),
        // `ip_forward` and `conf/*/forwarding` hold only 0 or 1.
        _ => None,
    }
}

/// Counts the routes out of `device` in `/proc/net/route` text (main
/// table; header `Iface\tDestination...`, the interface name first on
/// every row). The file is empty while the namespace has no main table
/// (Linux `fib_route_seq_start`), which is zero routes. `None` if a
/// non-empty file lacks the header.
pub fn count_routes(text: &str, device: &str) -> Option<u32> {
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return Some(0);
    };
    if header.split_whitespace().next() != Some("Iface") {
        return None;
    }
    let count = lines
        .filter(|line| line.split_whitespace().next() == Some(device))
        .count();
    Some(u32::try_from(count).unwrap_or(u32::MAX))
}

/// Linux readers of the facts above (cold path, std only, no `unsafe`).
#[cfg(target_os = "linux")]
pub mod linux {
    use std::fs;

    use super::super::netlink::LinkFacts;
    use super::{
        count_routes, evaluate_privileges, parse_cap_eff, parse_flag, parse_memlock, CheckFailure,
        DeviceFacts, PrivilegeFailure, Probe, ProcSource,
    };

    /// Reads the effective capabilities and memlock limit of this process
    /// and evaluates them against `required` memlock bytes.
    pub fn check_privileges(required: u64) -> Result<(), PrivilegeFailure> {
        let effective = fs::read_to_string("/proc/self/status")
            .ok()
            .as_deref()
            .and_then(parse_cap_eff)
            .ok_or(PrivilegeFailure::Unreadable(ProcSource::Status))?;
        let memlock = fs::read_to_string("/proc/self/limits")
            .ok()
            .as_deref()
            .and_then(parse_memlock)
            .ok_or(PrivilegeFailure::Unreadable(ProcSource::Limits))?;
        evaluate_privileges(effective, memlock, required)
    }

    /// What [`device_facts`] needs from the opened session and the config.
    #[derive(Clone, Copy, Debug)]
    pub struct SessionFacts {
        pub ifindex: u32,
        pub mtu: u32,
        pub frame_capacity: u32,
    }

    /// Reads the device facts of the session's interface index: RX queues
    /// and MTU from `link` (rtnetlink `RTM_GETLINK`), kernel IPv4
    /// addresses from `addresses` (rtnetlink `RTM_GETADDR`), routes and
    /// forwarding sysctls from procfs (the reading process's namespace).
    ///
    /// `device` was accepted by `SessionConfig::new` (no `/`, not `.` or
    /// `..`), so it is one path component.
    pub fn device_facts(
        device: &str,
        session: SessionFacts,
        link: impl FnOnce(u32) -> Option<LinkFacts>,
        addresses: impl FnOnce(u32) -> Option<u32>,
    ) -> Result<DeviceFacts, CheckFailure> {
        let ifindex = session.ifindex;
        let link = link(ifindex).ok_or(CheckFailure::Unverifiable(Probe::Link))?;
        let rx_queues = link.rx_queues.unwrap_or(0);
        let ipv4_addresses =
            addresses(ifindex).ok_or(CheckFailure::Unverifiable(Probe::Ipv4Addresses))?;
        // `/proc/net` is the reading process's network namespace, the
        // session's.
        let ipv4_routes = fs::read_to_string("/proc/net/route")
            .ok()
            .and_then(|text| count_routes(&text, device))
            .ok_or(CheckFailure::Unverifiable(Probe::Ipv4Routes))?;
        let flag = |path: String| {
            fs::read_to_string(path)
                .ok()
                .as_deref()
                .and_then(parse_flag)
        };
        Ok(DeviceFacts {
            ifindex,
            rx_queues,
            link_mtu: link.mtu,
            session_mtu: session.mtu,
            frame_capacity: session.frame_capacity,
            ipv4_addresses,
            ipv4_routes,
            forwarding_global: flag("/proc/sys/net/ipv4/ip_forward".to_owned()),
            forwarding_device: flag(format!("/proc/sys/net/ipv4/conf/{device}/forwarding")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: u64 = (1 << 41) - 1;

    #[test]
    fn capabilities_follow_the_documented_rule() {
        assert_eq!(missing_capabilities(ALL), 0, "root");
        let admin_raw = bit(cap::NET_ADMIN) | bit(cap::NET_RAW);
        assert_eq!(missing_capabilities(admin_raw | bit(cap::SYS_ADMIN)), 0);
        assert_eq!(
            missing_capabilities(admin_raw | bit(cap::BPF) | bit(cap::PERFMON)),
            0
        );
        assert_eq!(
            missing_capabilities(admin_raw | bit(cap::BPF)),
            bit(cap::PERFMON)
        );
        assert_eq!(
            missing_capabilities(admin_raw),
            bit(cap::BPF) | bit(cap::PERFMON)
        );
        assert_eq!(
            missing_capabilities(bit(cap::SYS_ADMIN)),
            bit(cap::NET_ADMIN) | bit(cap::NET_RAW)
        );
        assert_eq!(
            capability_names(missing_capabilities(0)),
            "CAP_NET_ADMIN,CAP_NET_RAW,CAP_PERFMON,CAP_BPF"
        );
    }

    #[test]
    fn memlock_is_checked_unless_ipc_lock_or_unlimited() {
        let caps = bit(cap::NET_ADMIN) | bit(cap::NET_RAW) | bit(cap::SYS_ADMIN);
        assert_eq!(evaluate_privileges(caps, None, u64::MAX), Ok(()));
        assert_eq!(evaluate_privileges(caps, Some(100), 100), Ok(()));
        assert_eq!(
            evaluate_privileges(caps, Some(99), 100),
            Err(PrivilegeFailure::MemlockLimit {
                limit: 99,
                required: 100
            })
        );
        assert_eq!(
            evaluate_privileges(caps | bit(cap::IPC_LOCK), Some(0), 100),
            Ok(())
        );
        // Capabilities are reported before the limit.
        assert_eq!(
            evaluate_privileges(0, Some(0), 100),
            Err(PrivilegeFailure::MissingCapabilities(missing_capabilities(
                0
            )))
        );
    }

    #[test]
    fn proc_files_parse_or_fail_closed() {
        let status = "Name:\truster\nCapInh:\t0000000000000000\nCapEff:\t000001ffffffffff\n";
        assert_eq!(parse_cap_eff(status), Some(0x1ff_ffff_ffff));
        assert_eq!(parse_cap_eff("CapEff:\t\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\tzz\n"), None);
        assert_eq!(parse_cap_eff("CapPrm:\t0\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\t00000000000000000\n"), None);
        let limits = "Limit                     Soft Limit           Hard Limit           Units     \n\
                      Max locked memory         8388608              8388608              bytes     \n";
        assert_eq!(parse_memlock(limits), Some(Some(8_388_608)));
        let unlimited =
            "Max locked memory         unlimited            unlimited            bytes\n";
        assert_eq!(parse_memlock(unlimited), Some(None));
        assert_eq!(parse_memlock("Max open files 1024 1024 files\n"), None);
        assert_eq!(parse_memlock("Max locked memory  lots  lots bytes\n"), None);
    }

    #[test]
    fn device_checks_refuse_or_warn_as_documented() {
        let clean = DeviceFacts {
            ifindex: 7,
            rx_queues: 1,
            link_mtu: 1500,
            session_mtu: 1500,
            frame_capacity: 1792,
            ipv4_addresses: 0,
            ipv4_routes: 0,
            forwarding_global: Some(false),
            forwarding_device: Some(false),
        };
        let strict = CheckPolicy::default();
        let lenient = CheckPolicy {
            allow_multi_queue: true,
        };
        assert_eq!(evaluate_device(&clean, strict), Ok(Warnings::default()));
        let multi = DeviceFacts {
            rx_queues: 4,
            ..clean
        };
        assert_eq!(
            evaluate_device(&multi, strict),
            Err(CheckFailure::MultiQueue { rx_queues: 4 })
        );
        assert_eq!(
            evaluate_device(&multi, lenient).map(|w| w.multi_queue),
            Ok(Some(4))
        );
        let addressed = DeviceFacts {
            ipv4_addresses: 2,
            ..clean
        };
        for policy in [strict, lenient] {
            assert_eq!(
                evaluate_device(&addressed, policy),
                Err(CheckFailure::KernelIpv4Addresses { count: 2 })
            );
        }
        assert_eq!(
            evaluate_device(
                &DeviceFacts {
                    rx_queues: 0,
                    ..clean
                },
                lenient
            ),
            Err(CheckFailure::Unverifiable(Probe::RxQueues))
        );
        let routed = DeviceFacts {
            ipv4_routes: 1,
            ..clean
        };
        assert_eq!(
            evaluate_device(&routed, lenient),
            Err(CheckFailure::KernelIpv4Routes { count: 1 })
        );
        // An address is reported before its connected route.
        assert_eq!(
            evaluate_device(
                &DeviceFacts {
                    ipv4_addresses: 1,
                    ..routed
                },
                strict
            ),
            Err(CheckFailure::KernelIpv4Addresses { count: 1 })
        );
        let forwarding = DeviceFacts {
            forwarding_global: Some(true),
            forwarding_device: None,
            ..clean
        };
        let warnings = evaluate_device(&forwarding, strict).expect("only warnings");
        assert!(warnings.forwarding_global && !warnings.forwarding_device);
        assert!(warnings.forwarding_unreadable);
        assert_eq!(
            warnings.codes().collect::<Vec<_>>(),
            [
                "IPV4_FORWARDING_ENABLED scope=global",
                "IPV4_FORWARDING_UNVERIFIABLE"
            ]
        );
    }

    #[test]
    fn mtu_must_match_the_session_and_fit_a_frame() {
        let clean = DeviceFacts {
            ifindex: 7,
            rx_queues: 1,
            link_mtu: 1778,
            session_mtu: 1778,
            frame_capacity: 1792,
            ..DeviceFacts::default()
        };
        let policy = CheckPolicy::default();
        assert_eq!(mtu_limit(1792), 1778);
        assert_eq!(mtu_limit(10), 0);
        assert!(evaluate_device(&clean, policy).is_ok(), "exactly the limit");
        assert_eq!(
            evaluate_device(
                &DeviceFacts {
                    link_mtu: 1779,
                    session_mtu: 1779,
                    ..clean
                },
                policy
            ),
            Err(CheckFailure::MtuAboveFrame {
                mtu: 1779,
                limit: 1778
            })
        );
        assert_eq!(
            evaluate_device(
                &DeviceFacts {
                    session_mtu: 1500,
                    ..clean
                },
                policy
            ),
            Err(CheckFailure::Unverifiable(Probe::Mtu))
        );
        assert_eq!(
            CheckFailure::MtuAboveFrame {
                mtu: 9000,
                limit: 1778
            }
            .to_string(),
            "MTU_ABOVE_FRAME mtu=9000 limit=1778"
        );
        assert_eq!(
            CheckFailure::Unverifiable(Probe::Link).to_string(),
            "UNVERIFIABLE probe=link"
        );
    }

    #[test]
    fn routes_and_flags_parse_strictly() {
        let routes = "Iface\tDestination\tGateway \tFlags\n\
                      ra\t0000620A\t00000000\t0001\n\
                      rb\t00000000\t017100CB\t0003\n\
                      ra2\t0000630A\t00000000\t0001\n";
        assert_eq!(count_routes(routes, "ra"), Some(1));
        assert_eq!(count_routes(routes, "rc"), Some(0));
        assert_eq!(count_routes("ra\t0\n", "ra"), None);
        assert_eq!(count_routes("", "ra"), Some(0), "no main table yet");
        assert_eq!(count_routes("\n", "ra"), None);
        assert_eq!(parse_flag("1\n"), Some(true));
        assert_eq!(parse_flag("0"), Some(false));
        assert_eq!(parse_flag("2"), None);
        assert_eq!(parse_flag(""), None);
    }
}
