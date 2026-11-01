//! Startup checks of `ruster run`: privileges and memlock (before any
//! resource), and the XDP-063 per-port device checks (after the session is
//! open, before XDP attach).
//!
//! The decisions are pure functions over facts read from procfs/sysfs (and
//! netlink for kernel IPv4 addresses), so they are tested without a kernel.
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
    /// `rx-<n>` entries of `/sys/class/net/<dev>/queues`.
    pub rx_queues: u32,
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
    /// The device has more than one RX queue and `--allow-multi-queue`
    /// was not given: frames on the other queues would be dropped by the
    /// XDP program (XDP-050).
    MultiQueue { rx_queues: u32 },
    /// The kernel holds IPv4 addresses on the port (refused, see
    /// [`evaluate_device`]).
    KernelIpv4Addresses { count: u32 },
    /// The kernel's main table routes IPv4 out of the port.
    KernelIpv4Routes { count: u32 },
    /// A fact could not be read or did not belong to the opened device.
    Unverifiable(Probe),
}

/// Which device fact could not be established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Probe {
    /// `/sys/class/net/<dev>/ifindex` is not the session's ifindex (or is
    /// unreadable): the sysfs view is certainly not the session's device.
    /// A match does not prove the namespace (another namespace's device
    /// can share the ifindex); run under `ip netns exec`, which remounts
    /// `/sys`. Reading the count over rtnetlink is deferred (CLI-034).
    SysfsIdentity,
    /// `/sys/class/net/<dev>/queues` could not be listed or had no RX
    /// queue.
    RxQueues,
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
            Self::Unverifiable(Probe::SysfsIdentity) => {
                formatter.write_str("UNVERIFIABLE probe=sysfs-ifindex")
            }
            Self::Unverifiable(Probe::RxQueues) => {
                formatter.write_str("UNVERIFIABLE probe=rx-queues")
            }
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
pub fn evaluate_device(facts: &DeviceFacts, policy: CheckPolicy) -> Result<Warnings, CheckFailure> {
    if facts.rx_queues == 0 {
        return Err(CheckFailure::Unverifiable(Probe::RxQueues));
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

/// Counts `rx-<n>` names.
pub fn count_rx_queues<'a>(names: impl IntoIterator<Item = &'a str>) -> u32 {
    let count = names
        .into_iter()
        .filter(|name| {
            name.strip_prefix("rx-")
                .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
        })
        .count();
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// Linux readers of the facts above (cold path, std only, no `unsafe`).
#[cfg(target_os = "linux")]
pub mod linux {
    use std::fs;

    use super::{
        count_routes, count_rx_queues, evaluate_privileges, parse_cap_eff, parse_flag,
        parse_memlock, CheckFailure, DeviceFacts, PrivilegeFailure, Probe, ProcSource,
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

    /// Reads the device facts of `device`, after checking that the sysfs
    /// view's `ifindex` is `ifindex` (the opened session's; see
    /// [`Probe::SysfsIdentity`] for what this does not prove), and counts
    /// kernel IPv4 addresses with `addresses`.
    ///
    /// `device` was accepted by `SessionConfig::new` (no `/`, not `.` or
    /// `..`), so it is one path component.
    pub fn device_facts(
        device: &str,
        ifindex: u32,
        addresses: impl FnOnce(u32) -> Option<u32>,
    ) -> Result<DeviceFacts, CheckFailure> {
        let base = format!("/sys/class/net/{device}");
        let proven = fs::read_to_string(format!("{base}/ifindex"))
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok())
            == Some(ifindex);
        if !proven {
            return Err(CheckFailure::Unverifiable(Probe::SysfsIdentity));
        }
        let entries = fs::read_dir(format!("{base}/queues"))
            .map_err(|_| CheckFailure::Unverifiable(Probe::RxQueues))?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| CheckFailure::Unverifiable(Probe::RxQueues))?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_owned());
            }
        }
        let rx_queues = count_rx_queues(names.iter().map(String::as_str));
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
            rx_queues,
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
            rx_queues: 1,
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
    fn rx_queue_names_and_flags_parse_strictly() {
        assert_eq!(
            count_rx_queues(["rx-0", "tx-0", "rx-1", "rx-", "rx-x", "rxq-2"]),
            2
        );
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
