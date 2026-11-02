//! Startup checks of `ruster run`: privileges and memlock (before any
//! resource), and the XDP-063 per-port device checks (after the session is
//! open, before XDP attach).
//!
//! The decisions are pure functions over facts read from procfs and
//! rtnetlink (link facts, kernel IPv4/IPv6 addresses and routes of the
//! session's interface index, in the caller's network namespace), so they
//! are tested without a kernel.
//! Every reader fails closed: a fact that cannot be read refuses startup,
//! including the IPv4 forwarding sysctls unless `--allow-kernel-forwarding`
//! and the IPv6 facts unless `--allow-kernel-ipv6`.

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
    /// Kernel IPv4 routes out of the device in every table (netlink
    /// `RTM_GETROUTE`, [`super::netlink::route_matches`]).
    pub ipv4_routes: u32,
    /// `/proc/sys/net/ipv4/ip_forward`; `None` if unreadable.
    pub forwarding_global: Option<bool>,
    /// `/proc/sys/net/ipv4/conf/<dev>/forwarding`; `None` if unreadable.
    pub forwarding_device: Option<bool>,
    /// `conf/all/mc_forwarding` or `conf/<dev>/mc_forwarding` (a multicast
    /// routing daemon is running; an absent file is off); `None` if
    /// unreadable.
    pub forwarding_multicast: Option<bool>,
    /// Weak-host exposure of the address-less port: the effective
    /// `rp_filter` (the larger of `conf/all` and `conf/<dev>`) and the
    /// effective `arp_ignore` (likewise) are both 0; `None` if unreadable.
    pub weak_host: Option<bool>,
    /// The kernel IPv6 stack on the device.
    pub ipv6: Ipv6Facts,
}

/// Kernel IPv6 facts of one port. `None` is unreadable; the default is
/// all unreadable (fail closed).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ipv6Facts {
    /// `/proc/sys/net/ipv6/conf/<dev>/disable_ipv6`, or `Some(true)` if
    /// the namespace has no IPv6 at all (`/proc/sys/net/ipv6` is absent:
    /// a kernel without IPv6 or booted with `ipv6.disable=1`). When true
    /// the other facts are not read: the kernel drops every IPv6 frame
    /// received on or sent through the device, removes its IPv6 addresses
    /// and routes, and refuses new ones.
    pub disabled: Option<bool>,
    /// Kernel IPv6 addresses on the device outside `fe80::/10`
    /// (`RTM_GETADDR`, [`super::netlink::address_matches`]).
    pub addresses: Option<u32>,
    /// Kernel IPv6 routes out of the device in every table, without the
    /// automatic link-local and multicast ones (`RTM_GETROUTE`,
    /// [`super::netlink::route_matches`]).
    pub routes: Option<u32>,
    /// `/proc/sys/net/ipv6/conf/all/forwarding`.
    pub forwarding_global: Option<bool>,
    /// `/proc/sys/net/ipv6/conf/<dev>/forwarding` (on its own it does
    /// not make the kernel forward IPv6, `ip6_forward` reads
    /// `conf/all/forwarding`; checked anyway).
    pub forwarding_device: Option<bool>,
    /// `conf/<dev>/force_forwarding` or `conf/all/force_forwarding`
    /// (Linux 6.17+: forwarding on that ingress device even with
    /// `conf/all/forwarding` 0; an absent file is off).
    pub forwarding_force: Option<bool>,
    /// `conf/<dev>/mc_forwarding` or `conf/all/mc_forwarding` (an IPv6
    /// multicast routing daemon; an absent file is off).
    pub forwarding_multicast: Option<bool>,
}

impl Ipv6Facts {
    /// IPv6 off on the port: nothing else is read.
    pub const DISABLED: Self = Self {
        disabled: Some(true),
        addresses: None,
        routes: None,
        forwarding_global: None,
        forwarding_device: None,
        forwarding_force: None,
        forwarding_multicast: None,
    };
    /// IPv6 on, with only link-local addresses and routes, forwarding off.
    #[cfg(test)]
    pub const CLEAN: Self = Self {
        disabled: Some(false),
        addresses: Some(0),
        routes: Some(0),
        forwarding_global: Some(false),
        forwarding_device: Some(false),
        forwarding_force: Some(false),
        forwarding_multicast: Some(false),
    };
}

/// Operator overrides of the device checks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CheckPolicy {
    /// `--allow-multi-queue`.
    pub allow_multi_queue: bool,
    /// `--allow-kernel-forwarding`: kernel IPv4 forwarding (or an
    /// unreadable forwarding sysctl) is warned instead of refused.
    pub allow_kernel_forwarding: bool,
    /// `--allow-kernel-ipv6`: kernel IPv6 enabled on a port (and with it
    /// addresses, routes, forwarding, or an unreadable IPv6 fact) is warned
    /// instead of refused.
    pub allow_kernel_ipv6: bool,
}

/// Which forwarding sysctl was on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardingScope {
    /// `net.ipv4.ip_forward` (IPv6: `net.ipv6.conf.all.forwarding`).
    Global,
    /// `net.ipv4.conf.<dev>.forwarding` (IPv6:
    /// `net.ipv6.conf.<dev>.forwarding`).
    Device,
    /// IPv6 only: `net.ipv6.conf.<dev>.force_forwarding` or
    /// `conf.all.force_forwarding` (Linux 6.17+).
    Force,
    /// `conf/<dev>/mc_forwarding` or `conf/all/mc_forwarding`: a multicast
    /// routing daemon forwards multicast between interfaces.
    Multicast,
}

impl ForwardingScope {
    const fn name(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Device => "device",
            Self::Force => "force",
            Self::Multicast => "multicast",
        }
    }
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
    /// A kernel table (any, policy routing included) routes IPv4 out of
    /// the port.
    KernelIpv4Routes { count: u32 },
    /// The kernel holds IPv6 addresses outside `fe80::/10` on the port and
    /// `--allow-kernel-ipv6` was not given.
    KernelIpv6Addresses { count: u32 },
    /// A kernel table routes IPv6 out of the port (beyond the automatic
    /// link-local and multicast routes) and `--allow-kernel-ipv6` was not
    /// given.
    KernelIpv6Routes { count: u32 },
    /// Kernel IPv6 forwarding is on (and IPv6 is not disabled on the
    /// port) and `--allow-kernel-ipv6` was not given.
    KernelIpv6ForwardingEnabled(ForwardingScope),
    /// IPv6 is enabled on the port (`disable_ipv6 = 0`) and
    /// `--allow-kernel-ipv6` was not given: while detached the kernel's
    /// IPv6 stack receives on the port (weak host model: every local IPv6
    /// address of the host is reachable through it).
    KernelIpv6Enabled,
    /// The device MTU plus the 14-byte Ethernet header does not fit a
    /// UMEM frame: the kernel would drop (copy mode) or split (driver
    /// multi-buffer) every longer frame before the router sees it.
    /// `limit` is the largest MTU the frames hold.
    MtuAboveFrame { mtu: u32, limit: u32 },
    /// Kernel IPv4 forwarding is on and `--allow-kernel-forwarding` was not
    /// given.
    KernelForwardingEnabled(ForwardingScope),
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
    /// The netlink IPv4 route dump failed (or a route could not be
    /// attributed to a device).
    Ipv4Routes,
    /// A forwarding sysctl could not be read (refused without
    /// `--allow-kernel-forwarding`).
    Forwarding,
    /// `conf/<dev>/disable_ipv6` could not be read although the namespace
    /// has IPv6.
    Ipv6Disabled,
    /// The netlink IPv6 address dump failed.
    Ipv6Addresses,
    /// The netlink IPv6 route dump failed.
    Ipv6Routes,
    /// An IPv6 forwarding sysctl could not be read.
    Ipv6Forwarding,
}

impl Probe {
    /// The stable `probe=` token.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::RxQueues => "rx-queues",
            Self::Mtu => "mtu",
            Self::Ipv4Addresses => "ipv4-addresses",
            Self::Ipv4Routes => "ipv4-routes",
            Self::Forwarding => "forwarding",
            Self::Ipv6Disabled => "ipv6-disabled",
            Self::Ipv6Addresses => "ipv6-addresses",
            Self::Ipv6Routes => "ipv6-routes",
            Self::Ipv6Forwarding => "ipv6-forwarding",
        }
    }
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
            Self::KernelIpv6Addresses { count } => {
                write!(formatter, "KERNEL_IPV6_ADDRESSES count={count}")
            }
            Self::KernelIpv6Routes { count } => {
                write!(formatter, "KERNEL_IPV6_ROUTES count={count}")
            }
            Self::Unverifiable(probe) => write!(formatter, "UNVERIFIABLE probe={}", probe.name()),
            Self::KernelForwardingEnabled(scope) => {
                write!(
                    formatter,
                    "KERNEL_FORWARDING_ENABLED scope={}",
                    scope.name()
                )
            }
            Self::KernelIpv6ForwardingEnabled(scope) => write!(
                formatter,
                "KERNEL_IPV6_FORWARDING_ENABLED scope={}",
                scope.name()
            ),
            Self::KernelIpv6Enabled => formatter.write_str("KERNEL_IPV6_ENABLED"),
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
    /// IPv4 `mc_forwarding` is on.
    pub forwarding_multicast: bool,
    /// A forwarding sysctl could not be read.
    pub forwarding_unreadable: bool,
    /// `rp_filter` and `arp_ignore` both 0 (or unreadable): weak-host
    /// exposure while detached (never refused).
    pub weak_host: bool,
    /// Accepted through `--allow-kernel-ipv6`: IPv6 is enabled on the port.
    pub ipv6_enabled: bool,
    /// ... the first IPv6 fact that could not be read.
    pub ipv6_unverifiable: Option<Probe>,
    /// ... IPv6 addresses outside `fe80::/10` on the port.
    pub ipv6_addresses: Option<u32>,
    /// ... IPv6 routes out of the port.
    pub ipv6_routes: Option<u32>,
    /// ... `net.ipv6.conf.all.forwarding` on.
    pub ipv6_forwarding_global: bool,
    /// ... `net.ipv6.conf.<dev>.forwarding` on.
    pub ipv6_forwarding_device: bool,
    /// ... IPv6 `force_forwarding` on.
    pub ipv6_forwarding_force: bool,
    /// ... IPv6 `mc_forwarding` on.
    pub ipv6_forwarding_multicast: bool,
}

impl Warnings {
    /// Stable warning codes, in a fixed order.
    pub fn codes(&self) -> impl Iterator<Item = String> + '_ {
        let multi = self
            .multi_queue
            .map(|queues| format!("MULTI_QUEUE_ALLOWED rx-queues={queues}"));
        let flags = [
            (
                self.forwarding_global,
                "IPV4_FORWARDING_ENABLED scope=global",
            ),
            (
                self.forwarding_device,
                "IPV4_FORWARDING_ENABLED scope=device",
            ),
            (
                self.forwarding_multicast,
                "IPV4_FORWARDING_ENABLED scope=multicast",
            ),
            (self.forwarding_unreadable, "IPV4_FORWARDING_UNVERIFIABLE"),
            (self.weak_host, "IPV4_WEAK_HOST_EXPOSURE"),
            (self.ipv6_enabled, "IPV6_ENABLED_ALLOWED"),
        ];
        let ipv4 = flags
            .into_iter()
            .filter(|(on, _)| *on)
            .map(|(_, code)| code.to_owned());
        let ipv6_unverifiable = self
            .ipv6_unverifiable
            .map(|probe| format!("IPV6_UNVERIFIABLE probe={}", probe.name()));
        let ipv6_addresses = self
            .ipv6_addresses
            .map(|count| format!("IPV6_ADDRESSES_ALLOWED count={count}"));
        let ipv6_routes = self
            .ipv6_routes
            .map(|count| format!("IPV6_ROUTES_ALLOWED count={count}"));
        let ipv6_forwarding = [
            (self.ipv6_forwarding_global, ForwardingScope::Global),
            (self.ipv6_forwarding_device, ForwardingScope::Device),
            (self.ipv6_forwarding_force, ForwardingScope::Force),
            (self.ipv6_forwarding_multicast, ForwardingScope::Multicast),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, scope)| format!("IPV6_FORWARDING_ENABLED scope={}", scope.name()));
        multi
            .into_iter()
            .chain(ipv4)
            .chain(ipv6_unverifiable)
            .chain(ipv6_addresses)
            .chain(ipv6_routes)
            .chain(ipv6_forwarding)
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
/// - Kernel IPv4 routes out of the port in any table (main, local, and
///   every policy-routing table, by `RTA_OIF` or a multipath nexthop; for
///   example `ip route add 10.0.0.0/8 dev <port> table 100` without an
///   address): refused for the same reason; addresses are checked first,
///   so a connected route reports its address.
/// - Forwarding sysctls (`net.ipv4.ip_forward`, `conf/<dev>/forwarding`,
///   and `mc_forwarding` of `conf/all` or the device, set while a
///   multicast routing daemon runs; an absent `mc_forwarding` is off):
///   refused by default (`KERNEL_FORWARDING_ENABLED
///   scope=global|device|multicast`, unreadable: `UNVERIFIABLE
///   probe=forwarding`). Whenever the router is
///   not attached (before startup, after any exit including a fatal health
///   event, after a crash), kernel forwarding is what could carry traffic
///   between the ports around the firewall and NAT, so the fail-closed
///   default keeps it off. `ip_forward` is namespace-wide and other
///   interfaces of the host (containers, VPN) may need it, so
///   `--allow-kernel-forwarding` accepts it with the old warnings; the
///   address and route refusals still keep the kernel without a connected
///   route through the ports.
/// - IPv4 weak host: an address-less port still receives, while detached,
///   frames addressed to any local IPv4 address of the host (Linux's weak
///   host model) and answers ARP for them unless `arp_ignore` is set.
///   With the effective `rp_filter` and `arp_ignore` both 0 (or
///   unreadable) a warning `IPV4_WEAK_HOST_EXPOSURE`, never a refusal
///   (whether to refuse is an open owner question, CLI-034).
/// - Kernel IPv6 ([`evaluate_ipv6`]): refused whenever IPv6 is enabled on
///   the port, unless `--allow-kernel-ipv6`.
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
    warnings.forwarding_multicast = facts.forwarding_multicast == Some(true);
    warnings.forwarding_unreadable = facts.forwarding_global.is_none()
        || facts.forwarding_device.is_none()
        || facts.forwarding_multicast.is_none();
    if !policy.allow_kernel_forwarding {
        for (on, scope) in [
            (warnings.forwarding_global, ForwardingScope::Global),
            (warnings.forwarding_device, ForwardingScope::Device),
            (warnings.forwarding_multicast, ForwardingScope::Multicast),
        ] {
            if on {
                return Err(CheckFailure::KernelForwardingEnabled(scope));
            }
        }
        if warnings.forwarding_unreadable {
            return Err(CheckFailure::Unverifiable(Probe::Forwarding));
        }
    }
    warnings.weak_host = facts.weak_host != Some(false);
    evaluate_ipv6(&facts.ipv6, policy.allow_kernel_ipv6, &mut warnings)?;
    Ok(warnings)
}

/// The IPv6 part of [`evaluate_device`].
///
/// The router is IPv4 only, so while it is detached (before startup, after
/// any exit, after a crash) the kernel's IPv6 stack is the only one on the
/// ports. With IPv6 disabled on the port (`disable_ipv6 = 1`, or no IPv6
/// in the namespace) nothing else matters: the kernel drops every IPv6
/// frame received on or sent through it and keeps no IPv6 address or
/// route there.
///
/// With IPv6 enabled even only the kernel's own link-local address is
/// exposure: Linux implements the weak host model and IPv6 has no
/// `rp_filter`, so a frame arriving on the port for any local IPv6 address
/// of the host (another interface's global address, `::1` is excluded by
/// the stack) is delivered to local sockets, and services bound to `[::]`
/// (sshd, tunnels, ...) answer through the port; Neighbor Discovery and
/// ICMPv6 answer on the segment. Only forwarding between interfaces needs
/// more than link-local (a link-local source or destination is never
/// forwarded, RFC 4291 2.5.6). So an enabled port is refused
/// (`KERNEL_IPV6_ENABLED`) unless `allow` (`--allow-kernel-ipv6`).
///
/// The more specific findings are reported first, so each stays visible
/// and testable: the disable flag unreadable (`probe=ipv6-disabled`), the
/// address dump (`probe=ipv6-addresses`, then `KERNEL_IPV6_ADDRESSES`),
/// the route dump (`probe=ipv6-routes`, then `KERNEL_IPV6_ROUTES`), the
/// forwarding sysctls (`probe=ipv6-forwarding`, then
/// `KERNEL_IPV6_FORWARDING_ENABLED scope=global|device|force|multicast`),
/// and only then `KERNEL_IPV6_ENABLED`. With `allow` every one of them is a
/// warning instead (`IPV6_ENABLED_ALLOWED`, `IPV6_UNVERIFIABLE`,
/// `IPV6_ADDRESSES_ALLOWED`, `IPV6_ROUTES_ALLOWED`,
/// `IPV6_FORWARDING_ENABLED scope=...`).
///
/// One override for the whole IPv6 stack, not one per fact: the router
/// does not implement IPv6, so the only safe setting is `disable_ipv6 = 1`,
/// and an operator who cannot do that yet accepts the kernel's IPv6 on the
/// ports as a whole. It is separate from `--allow-kernel-forwarding`,
/// which keeps meaning IPv4 only.
pub fn evaluate_ipv6(
    facts: &Ipv6Facts,
    allow: bool,
    warnings: &mut Warnings,
) -> Result<(), CheckFailure> {
    if facts.disabled == Some(true) {
        return Ok(());
    }
    let unverifiable = |probe: Probe, warnings: &mut Warnings| {
        if !allow {
            return Err(CheckFailure::Unverifiable(probe));
        }
        warnings.ipv6_unverifiable.get_or_insert(probe);
        Ok(())
    };
    if facts.disabled.is_none() {
        unverifiable(Probe::Ipv6Disabled, warnings)?;
    }
    match facts.addresses {
        None => unverifiable(Probe::Ipv6Addresses, warnings)?,
        Some(0) => {}
        Some(count) if allow => warnings.ipv6_addresses = Some(count),
        Some(count) => return Err(CheckFailure::KernelIpv6Addresses { count }),
    }
    match facts.routes {
        None => unverifiable(Probe::Ipv6Routes, warnings)?,
        Some(0) => {}
        Some(count) if allow => warnings.ipv6_routes = Some(count),
        Some(count) => return Err(CheckFailure::KernelIpv6Routes { count }),
    }
    for (flag, scope) in [
        (facts.forwarding_global, ForwardingScope::Global),
        (facts.forwarding_device, ForwardingScope::Device),
        (facts.forwarding_force, ForwardingScope::Force),
        (facts.forwarding_multicast, ForwardingScope::Multicast),
    ] {
        match flag {
            None => unverifiable(Probe::Ipv6Forwarding, warnings)?,
            Some(false) => {}
            Some(true) if allow => {
                *match scope {
                    ForwardingScope::Global => &mut warnings.ipv6_forwarding_global,
                    ForwardingScope::Device => &mut warnings.ipv6_forwarding_device,
                    ForwardingScope::Force => &mut warnings.ipv6_forwarding_force,
                    ForwardingScope::Multicast => &mut warnings.ipv6_forwarding_multicast,
                } = true
            }
            Some(true) => return Err(CheckFailure::KernelIpv6ForwardingEnabled(scope)),
        }
    }
    if !allow {
        return Err(CheckFailure::KernelIpv6Enabled);
    }
    warnings.ipv6_enabled = true;
    Ok(())
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

/// Linux readers of the facts above (cold path, std only, no `unsafe`).
#[cfg(target_os = "linux")]
pub mod linux {
    use std::fs;

    use std::path::{Path, PathBuf};

    use super::super::netlink::{Dump, Family, LinkProbe};
    use super::{
        evaluate_privileges, parse_cap_eff, parse_flag, parse_memlock, CheckFailure, DeviceFacts,
        Ipv6Facts, PrivilegeFailure, Probe, ProcSource,
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

    /// Reads a `0`/`1` sysctl file into a stack buffer: no allocation (a
    /// short path is converted on the stack by std), for the run-time link
    /// round. `None` if unreadable or not exactly `0` or `1`.
    pub fn read_flag(path: &std::path::Path) -> Option<bool> {
        use std::io::Read;
        let mut file = fs::File::open(path).ok()?;
        let mut buffer = [0_u8; 8];
        let mut len = 0;
        loop {
            let read = file.read(&mut buffer[len..]).ok()?;
            if read == 0 {
                break;
            }
            len += read;
            if len == buffer.len() {
                return None;
            }
        }
        parse_flag(std::str::from_utf8(&buffer[..len]).ok()?)
    }

    /// Why a sysctl read failed.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ReadError {
        /// The file does not exist.
        Absent,
        /// Anything else: unreadable, too long, or not a number.
        Unreadable,
    }

    /// Reads a short decimal sysctl into a stack buffer: no allocation (a
    /// short path is converted on the stack by std).
    fn read_number(path: &Path) -> Result<u32, ReadError> {
        use std::io::Read;
        let mut file = fs::File::open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ReadError::Absent
            } else {
                ReadError::Unreadable
            }
        })?;
        let mut buffer = [0_u8; 8];
        let mut len = 0;
        loop {
            let read = file
                .read(&mut buffer[len..])
                .map_err(|_| ReadError::Unreadable)?;
            if read == 0 {
                break;
            }
            len += read;
            if len == buffer.len() {
                return Err(ReadError::Unreadable);
            }
        }
        let text = std::str::from_utf8(&buffer[..len]).map_err(|_| ReadError::Unreadable)?;
        let text = text.trim();
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ReadError::Unreadable);
        }
        text.parse().map_err(|_| ReadError::Unreadable)
    }

    /// A `0`/`1` flag whose absence means off (sysctls newer than the
    /// minimum kernel, such as `force_forwarding`, and `mc_forwarding`).
    fn read_flag_or_absent(path: &Path) -> Option<bool> {
        match read_number(path) {
            Ok(0) | Err(ReadError::Absent) => Some(false),
            Ok(1) => Some(true),
            _ => None,
        }
    }

    /// Either of two flags: on if either is known on, otherwise unknown if
    /// either is unknown (fail closed), otherwise off.
    fn either(a: Option<bool>, b: Option<bool>) -> Option<bool> {
        if a == Some(true) || b == Some(true) {
            return Some(true);
        }
        Some(a? || b?)
    }

    /// `/proc/sys/net/ipv6`: present whenever the namespace has IPv6.
    pub const IPV6_SYSCTLS: &str = "/proc/sys/net/ipv6";
    /// `/proc/sys/net/ipv4`: always present with a mounted procfs.
    pub const IPV4_SYSCTLS: &str = "/proc/sys/net/ipv4";
    const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
    const IPV4_MC_FORWARDING_ALL: &str = "/proc/sys/net/ipv4/conf/all/mc_forwarding";
    const IPV4_RP_FILTER_ALL: &str = "/proc/sys/net/ipv4/conf/all/rp_filter";
    const IPV4_ARP_IGNORE_ALL: &str = "/proc/sys/net/ipv4/conf/all/arp_ignore";
    const IPV6_FORWARDING_ALL: &str = "/proc/sys/net/ipv6/conf/all/forwarding";
    const IPV6_FORCE_FORWARDING_ALL: &str = "/proc/sys/net/ipv6/conf/all/force_forwarding";
    const IPV6_MC_FORWARDING_ALL: &str = "/proc/sys/net/ipv6/conf/all/mc_forwarding";

    /// `conf/<dev>/disable_ipv6`: `Some(true)` also when the namespace has
    /// no IPv6 at all ([`IPV6_SYSCTLS`] does not exist while
    /// [`IPV4_SYSCTLS`] does: nothing IPv6 can happen); `None` if the flag
    /// cannot be read otherwise (fail closed: then every other IPv6 fact
    /// is read). No allocation.
    pub fn ipv6_disabled(disable_ipv6: &Path) -> Option<bool> {
        if let Some(flag) = read_flag(disable_ipv6) {
            return Some(flag);
        }
        let ipv6_missing = matches!(
            fs::metadata(IPV6_SYSCTLS),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        );
        without_flag(ipv6_missing, fs::metadata(IPV4_SYSCTLS).is_ok())
    }

    /// The disable flag could not be read: IPv6 counts as absent (off)
    /// only if `/proc/sys/net/ipv6` does not exist while
    /// `/proc/sys/net/ipv4` does (so procfs is there and the namespace
    /// simply has no IPv6); anything else is unverifiable.
    fn without_flag(ipv6_missing: bool, ipv4_present: bool) -> Option<bool> {
        (ipv6_missing && ipv4_present).then_some(true)
    }

    /// Weak-host exposure from `(all, device)` pairs of `rp_filter` and
    /// `arp_ignore`: the kernel applies the larger value of each pair
    /// (`IN_DEV_MAXCONF`), and only both effective values 0 are exposed.
    fn weak_host(rp_filter: (u32, u32), arp_ignore: (u32, u32)) -> bool {
        rp_filter.0.max(rp_filter.1) == 0 && arp_ignore.0.max(arp_ignore.1) == 0
    }

    /// The IPv4 procfs facts of one port.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Ipv4Sysctls {
        pub forwarding_global: Option<bool>,
        pub forwarding_device: Option<bool>,
        pub forwarding_multicast: Option<bool>,
        pub weak_host: Option<bool>,
    }

    /// The IPv6 forwarding facts of one port.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Ipv6Forwarding {
        pub global: Option<bool>,
        pub device: Option<bool>,
        pub force: Option<bool>,
        pub multicast: Option<bool>,
    }

    /// The procfs paths of one port, built once (cold); reading them
    /// never allocates, so the run-time link round uses the same reader as
    /// the startup check.
    ///
    /// The paths name the device, so they follow the name, not the
    /// interface index: if the port is renamed its sysctls become
    /// unreadable (a failed query, `LINK_UNVERIFIABLE` after three rounds),
    /// and if another device then takes the old name its sysctls are read
    /// instead until the next restart (whose startup reads the new
    /// device's own). Do not rename ports while the router runs.
    #[derive(Clone, Debug)]
    pub struct PortSysctls {
        ipv4_forwarding: PathBuf,
        ipv4_mc_forwarding: PathBuf,
        ipv4_rp_filter: PathBuf,
        ipv4_arp_ignore: PathBuf,
        ipv6_disable: PathBuf,
        ipv6_forwarding: PathBuf,
        ipv6_force_forwarding: PathBuf,
        ipv6_mc_forwarding: PathBuf,
    }

    impl PortSysctls {
        /// `device` was accepted by `SessionConfig::new` (no `/`, not `.`
        /// or `..`), so it is one path component.
        pub fn new(device: &str) -> Self {
            let v4 = |name: &str| PathBuf::from(format!("/proc/sys/net/ipv4/conf/{device}/{name}"));
            let v6 = |name: &str| PathBuf::from(format!("/proc/sys/net/ipv6/conf/{device}/{name}"));
            Self {
                ipv4_forwarding: v4("forwarding"),
                ipv4_mc_forwarding: v4("mc_forwarding"),
                ipv4_rp_filter: v4("rp_filter"),
                ipv4_arp_ignore: v4("arp_ignore"),
                ipv6_disable: v6("disable_ipv6"),
                ipv6_forwarding: v6("forwarding"),
                ipv6_force_forwarding: v6("force_forwarding"),
                ipv6_mc_forwarding: v6("mc_forwarding"),
            }
        }

        /// IPv4 forwarding (`ip_forward`, the device's `forwarding`, and
        /// `mc_forwarding` of `all` or the device) and the weak-host
        /// exposure (effective `rp_filter` and `arp_ignore`, the larger of
        /// `all` and the device as the kernel takes them, both 0).
        pub fn ipv4(&self) -> Ipv4Sysctls {
            let pair = |all: &str, device: &Path| -> Option<(u32, u32)> {
                Some((read_number(Path::new(all)).ok()?, read_number(device).ok()?))
            };
            let weak_host = pair(IPV4_RP_FILTER_ALL, &self.ipv4_rp_filter)
                .zip(pair(IPV4_ARP_IGNORE_ALL, &self.ipv4_arp_ignore))
                .map(|(rp_filter, arp_ignore)| weak_host(rp_filter, arp_ignore));
            Ipv4Sysctls {
                forwarding_global: read_flag(Path::new(IP_FORWARD)),
                forwarding_device: read_flag(&self.ipv4_forwarding),
                forwarding_multicast: either(
                    read_flag_or_absent(Path::new(IPV4_MC_FORWARDING_ALL)),
                    read_flag_or_absent(&self.ipv4_mc_forwarding),
                ),
                weak_host,
            }
        }

        /// [`ipv6_disabled`] of this port.
        pub fn ipv6_disabled(&self) -> Option<bool> {
            ipv6_disabled(&self.ipv6_disable)
        }

        /// The IPv6 forwarding sysctls: `conf/all/forwarding`, the device's
        /// `forwarding`, `force_forwarding` of the device or `all` (Linux
        /// 6.17+, absent is off), `mc_forwarding` of the device or `all`
        /// (absent is off).
        pub fn ipv6_forwarding(&self) -> Ipv6Forwarding {
            Ipv6Forwarding {
                global: read_flag(Path::new(IPV6_FORWARDING_ALL)),
                device: read_flag(&self.ipv6_forwarding),
                force: either(
                    read_flag_or_absent(Path::new(IPV6_FORCE_FORWARDING_ALL)),
                    read_flag_or_absent(&self.ipv6_force_forwarding),
                ),
                multicast: either(
                    read_flag_or_absent(Path::new(IPV6_MC_FORWARDING_ALL)),
                    read_flag_or_absent(&self.ipv6_mc_forwarding),
                ),
            }
        }
    }

    /// What [`device_facts`] needs from the opened session and the config.
    #[derive(Clone, Copy, Debug)]
    pub struct SessionFacts {
        pub ifindex: u32,
        pub mtu: u32,
        pub frame_capacity: u32,
    }

    /// Reads the device facts of the session's interface index through
    /// one connected rtnetlink socket (`probe`, `None` if it could not be
    /// opened): RX queues and MTU (`RTM_GETLINK`), kernel IPv4 and IPv6
    /// addresses (`RTM_GETADDR`) and routes of every table
    /// (`RTM_GETROUTE`), then the procfs sysctls of `sysctls` (the reading
    /// process's namespace).
    pub fn device_facts(
        sysctls: &PortSysctls,
        session: SessionFacts,
        probe: Option<&mut LinkProbe>,
    ) -> Result<DeviceFacts, CheckFailure> {
        let ifindex = session.ifindex;
        let probe = probe.ok_or(CheckFailure::Unverifiable(Probe::Link))?;
        let link = probe
            .query(ifindex)
            .map_err(|_| CheckFailure::Unverifiable(Probe::Link))?;
        let rx_queues = link.rx_queues.unwrap_or(0);
        let ipv4_addresses = probe
            .ipv4_addresses(ifindex)
            .map_err(|_| CheckFailure::Unverifiable(Probe::Ipv4Addresses))?;
        let ipv4_routes = probe
            .count(Dump::Routes(Family::Ipv4), ifindex)
            .map_err(|_| CheckFailure::Unverifiable(Probe::Ipv4Routes))?;
        let disabled = sysctls.ipv6_disabled();
        let ipv6 = if disabled == Some(true) {
            Ipv6Facts::DISABLED
        } else {
            let forwarding = sysctls.ipv6_forwarding();
            Ipv6Facts {
                disabled,
                addresses: probe.count(Dump::Addresses(Family::Ipv6), ifindex).ok(),
                routes: probe.count(Dump::Routes(Family::Ipv6), ifindex).ok(),
                forwarding_global: forwarding.global,
                forwarding_device: forwarding.device,
                forwarding_force: forwarding.force,
                forwarding_multicast: forwarding.multicast,
            }
        };
        let ipv4 = sysctls.ipv4();
        Ok(DeviceFacts {
            ifindex,
            rx_queues,
            link_mtu: link.mtu,
            session_mtu: session.mtu,
            frame_capacity: session.frame_capacity,
            ipv4_addresses,
            ipv4_routes,
            forwarding_global: ipv4.forwarding_global,
            forwarding_device: ipv4.forwarding_device,
            forwarding_multicast: ipv4.forwarding_multicast,
            weak_host: ipv4.weak_host,
            ipv6,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Without a readable `disable_ipv6`, only a namespace that has
        /// IPv4 sysctls but no IPv6 ones counts as IPv6 off.
        #[test]
        fn a_missing_ipv6_tree_is_off_only_with_ipv4_present() {
            assert_eq!(without_flag(true, true), Some(true));
            assert_eq!(without_flag(true, false), None, "no procfs at all");
            assert_eq!(
                without_flag(false, true),
                None,
                "IPv6 there, flag unreadable"
            );
            assert_eq!(without_flag(false, false), None);
        }

        /// The effective `rp_filter`/`arp_ignore` is the larger of `all`
        /// and the device.
        #[test]
        fn weak_host_takes_the_larger_of_all_and_the_device() {
            assert!(weak_host((0, 0), (0, 0)));
            for (rp_filter, arp_ignore) in [
                ((0, 1), (0, 0)),
                ((2, 0), (0, 0)),
                ((0, 0), (1, 0)),
                ((0, 0), (0, 8)),
            ] {
                assert!(
                    !weak_host(rp_filter, arp_ignore),
                    "{rp_filter:?} {arp_ignore:?}"
                );
            }
        }

        /// Absent optional flags are off, unreadable ones unknown, and
        /// `either` is on if either is on, else unknown if either is.
        #[test]
        fn optional_flags_and_their_combination_fail_closed() {
            assert_eq!(
                read_flag_or_absent(Path::new("/proc/sys/net/ipv4/conf/nonexistent0/x")),
                Some(false)
            );
            assert_eq!(read_flag_or_absent(Path::new("/proc/sys/net/ipv4")), None);
            let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
            assert_eq!(read_flag_or_absent(Path::new(manifest)), None);
            assert_eq!(
                read_number(Path::new("/dev/null")),
                Err(ReadError::Unreadable)
            );
            assert!(read_number(Path::new("/proc/sys/net/ipv4/conf/all/arp_ignore")).is_ok());
            for (a, b, both) in [
                (Some(true), None, Some(true)),
                (None, Some(true), Some(true)),
                (Some(false), None, None),
                (None, Some(false), None),
                (Some(false), Some(false), Some(false)),
                (Some(false), Some(true), Some(true)),
            ] {
                assert_eq!(either(a, b), both, "{a:?} {b:?}");
            }
            // A real port name's sysctls read (loopback exists everywhere).
            let lo = PortSysctls::new("lo").ipv4();
            assert!(lo.forwarding_device.is_some() && lo.forwarding_multicast.is_some());
            assert!(lo.weak_host.is_some());
            let gone = PortSysctls::new("nonexistent0").ipv4();
            assert_eq!(
                (
                    gone.forwarding_device,
                    gone.weak_host,
                    gone.forwarding_multicast
                ),
                (None, None, Some(false)),
                "a missing device: unreadable, mc_forwarding absent is off"
            );
        }
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
            forwarding_multicast: Some(false),
            weak_host: Some(false),
            ipv6: Ipv6Facts::DISABLED,
        };
        let strict = CheckPolicy::default();
        let lenient = CheckPolicy {
            allow_multi_queue: true,
            ..CheckPolicy::default()
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
        let allowed = CheckPolicy {
            allow_kernel_forwarding: true,
            ..strict
        };
        let warnings = evaluate_device(&forwarding, allowed).expect("only warnings");
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

    /// The run-time sysctl reader: a real procfs flag reads, anything
    /// that is not exactly `0`/`1` (empty, missing, a directory) is `None`.
    #[cfg(target_os = "linux")]
    #[test]
    fn sysctl_flags_read_without_allocation_or_fail() {
        use std::path::Path;
        assert!(linux::read_flag(Path::new("/proc/sys/net/ipv4/ip_forward")).is_some());
        assert_eq!(linux::read_flag(Path::new("/dev/null")), None);
        assert_eq!(linux::read_flag(Path::new("/proc/sys/net/ipv4")), None);
        assert_eq!(linux::read_flag(Path::new("/nonexistent/forwarding")), None);
        // A longer file than a flag is refused, not truncated.
        let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
        assert_eq!(linux::read_flag(Path::new(manifest)), None);
    }

    #[test]
    fn kernel_forwarding_is_refused_unless_allowed() {
        let clean = DeviceFacts {
            ifindex: 7,
            rx_queues: 1,
            link_mtu: 1500,
            session_mtu: 1500,
            frame_capacity: 1792,
            forwarding_global: Some(false),
            forwarding_device: Some(false),
            forwarding_multicast: Some(false),
            weak_host: Some(false),
            ipv6: Ipv6Facts::DISABLED,
            ..DeviceFacts::default()
        };
        let strict = CheckPolicy::default();
        let allowed = CheckPolicy {
            allow_kernel_forwarding: true,
            ..strict
        };
        for (global, device, refusal) in [
            (
                Some(true),
                Some(false),
                CheckFailure::KernelForwardingEnabled(ForwardingScope::Global),
            ),
            (
                Some(false),
                Some(true),
                CheckFailure::KernelForwardingEnabled(ForwardingScope::Device),
            ),
            (
                Some(true),
                Some(true),
                CheckFailure::KernelForwardingEnabled(ForwardingScope::Global),
            ),
            (
                None,
                Some(false),
                CheckFailure::Unverifiable(Probe::Forwarding),
            ),
            (
                Some(false),
                None,
                CheckFailure::Unverifiable(Probe::Forwarding),
            ),
        ] {
            let facts = DeviceFacts {
                forwarding_global: global,
                forwarding_device: device,
                ..clean
            };
            assert_eq!(evaluate_device(&facts, strict), Err(refusal), "{facts:?}");
            let warnings = evaluate_device(&facts, allowed).expect("warned when allowed");
            assert!(warnings.codes().next().is_some(), "{facts:?}");
        }
        assert_eq!(evaluate_device(&clean, strict), Ok(Warnings::default()));
        assert_eq!(evaluate_device(&clean, allowed), Ok(Warnings::default()));
        assert_eq!(
            CheckFailure::KernelForwardingEnabled(ForwardingScope::Device).to_string(),
            "KERNEL_FORWARDING_ENABLED scope=device"
        );
        assert_eq!(
            CheckFailure::Unverifiable(Probe::Forwarding).to_string(),
            "UNVERIFIABLE probe=forwarding"
        );
    }

    fn ipv6_clean() -> DeviceFacts {
        DeviceFacts {
            ifindex: 7,
            rx_queues: 1,
            link_mtu: 1500,
            session_mtu: 1500,
            frame_capacity: 1792,
            forwarding_global: Some(false),
            forwarding_device: Some(false),
            forwarding_multicast: Some(false),
            weak_host: Some(false),
            ipv6: Ipv6Facts::CLEAN,
            ..DeviceFacts::default()
        }
    }

    /// IPv6 enabled on a port is refused (`KERNEL_IPV6_ENABLED`) unless
    /// `--allow-kernel-ipv6`, after the more specific findings (addresses
    /// outside link-local, routes, forwarding of every scope, unreadable
    /// facts), each refused with its own code first; the override turns all
    /// of them into warnings. `disable_ipv6 = 1` makes every other fact
    /// irrelevant, also unreadable ones.
    #[test]
    fn kernel_ipv6_is_refused_unless_allowed_or_disabled() {
        let strict = CheckPolicy::default();
        let allowed = CheckPolicy {
            allow_kernel_ipv6: true,
            ..strict
        };
        let clean = ipv6_clean();
        // Link-local only: still refused, warned under the override.
        assert_eq!(
            evaluate_device(&clean, strict),
            Err(CheckFailure::KernelIpv6Enabled)
        );
        assert_eq!(
            evaluate_device(&clean, allowed).map(|w| w.codes().collect::<Vec<_>>()),
            Ok(vec!["IPV6_ENABLED_ALLOWED".to_owned()])
        );
        let disabled_port = DeviceFacts {
            ipv6: Ipv6Facts::DISABLED,
            ..clean
        };
        assert_eq!(
            evaluate_device(&disabled_port, strict),
            Ok(Warnings::default())
        );
        let with = |ipv6: Ipv6Facts| DeviceFacts { ipv6, ..clean };
        let cases = [
            (
                Ipv6Facts {
                    addresses: Some(2),
                    ..Ipv6Facts::CLEAN
                },
                CheckFailure::KernelIpv6Addresses { count: 2 },
                "IPV6_ADDRESSES_ALLOWED count=2",
            ),
            (
                Ipv6Facts {
                    routes: Some(3),
                    ..Ipv6Facts::CLEAN
                },
                CheckFailure::KernelIpv6Routes { count: 3 },
                "IPV6_ROUTES_ALLOWED count=3",
            ),
            (
                Ipv6Facts {
                    forwarding_global: Some(true),
                    ..Ipv6Facts::CLEAN
                },
                CheckFailure::KernelIpv6ForwardingEnabled(ForwardingScope::Global),
                "IPV6_FORWARDING_ENABLED scope=global",
            ),
            (
                Ipv6Facts {
                    forwarding_device: Some(true),
                    ..Ipv6Facts::CLEAN
                },
                CheckFailure::KernelIpv6ForwardingEnabled(ForwardingScope::Device),
                "IPV6_FORWARDING_ENABLED scope=device",
            ),
            (
                Ipv6Facts {
                    forwarding_force: Some(true),
                    ..Ipv6Facts::CLEAN
                },
                CheckFailure::KernelIpv6ForwardingEnabled(ForwardingScope::Force),
                "IPV6_FORWARDING_ENABLED scope=force",
            ),
            (
                Ipv6Facts {
                    forwarding_multicast: Some(true),
                    ..Ipv6Facts::CLEAN
                },
                CheckFailure::KernelIpv6ForwardingEnabled(ForwardingScope::Multicast),
                "IPV6_FORWARDING_ENABLED scope=multicast",
            ),
            (
                Ipv6Facts {
                    disabled: None,
                    ..Ipv6Facts::CLEAN
                },
                CheckFailure::Unverifiable(Probe::Ipv6Disabled),
                "IPV6_UNVERIFIABLE probe=ipv6-disabled",
            ),
            (
                Ipv6Facts {
                    addresses: None,
                    ..Ipv6Facts::CLEAN
                },
                CheckFailure::Unverifiable(Probe::Ipv6Addresses),
                "IPV6_UNVERIFIABLE probe=ipv6-addresses",
            ),
            (
                Ipv6Facts {
                    routes: None,
                    ..Ipv6Facts::CLEAN
                },
                CheckFailure::Unverifiable(Probe::Ipv6Routes),
                "IPV6_UNVERIFIABLE probe=ipv6-routes",
            ),
            (
                Ipv6Facts {
                    forwarding_device: None,
                    ..Ipv6Facts::CLEAN
                },
                CheckFailure::Unverifiable(Probe::Ipv6Forwarding),
                "IPV6_UNVERIFIABLE probe=ipv6-forwarding",
            ),
            (
                Ipv6Facts {
                    forwarding_force: None,
                    ..Ipv6Facts::CLEAN
                },
                CheckFailure::Unverifiable(Probe::Ipv6Forwarding),
                "IPV6_UNVERIFIABLE probe=ipv6-forwarding",
            ),
        ];
        for (ipv6, refusal, warning) in cases {
            let facts = with(ipv6);
            assert_eq!(evaluate_device(&facts, strict), Err(refusal), "{ipv6:?}");
            // --allow-kernel-forwarding is IPv4 only.
            let ipv4_only = CheckPolicy {
                allow_kernel_forwarding: true,
                ..strict
            };
            assert_eq!(evaluate_device(&facts, ipv4_only), Err(refusal), "{ipv6:?}");
            let warnings = evaluate_device(&facts, allowed).expect("warned when allowed");
            assert_eq!(
                warnings.codes().collect::<Vec<_>>(),
                ["IPV6_ENABLED_ALLOWED", warning],
                "{ipv6:?}"
            );
            // Disabled on the port: nothing else matters.
            let disabled = Ipv6Facts {
                disabled: Some(true),
                ..ipv6
            };
            assert_eq!(
                evaluate_device(&with(disabled), strict),
                Ok(Warnings::default()),
                "{ipv6:?}"
            );
        }
        // Everything at once: the order of refusals, and every warning.
        let exposed = Ipv6Facts {
            disabled: None,
            addresses: Some(1),
            routes: Some(1),
            forwarding_global: Some(true),
            forwarding_device: Some(true),
            forwarding_force: Some(true),
            forwarding_multicast: Some(true),
        };
        assert_eq!(
            evaluate_device(&with(exposed), strict),
            Err(CheckFailure::Unverifiable(Probe::Ipv6Disabled))
        );
        assert_eq!(
            evaluate_device(
                &with(Ipv6Facts {
                    disabled: Some(false),
                    ..exposed
                }),
                strict
            ),
            Err(CheckFailure::KernelIpv6Addresses { count: 1 })
        );
        assert_eq!(
            evaluate_device(
                &with(Ipv6Facts {
                    disabled: Some(false),
                    addresses: Some(0),
                    ..exposed
                }),
                strict
            ),
            Err(CheckFailure::KernelIpv6Routes { count: 1 })
        );
        let all = evaluate_device(&with(exposed), allowed).expect("allowed");
        assert_eq!(
            all.codes().collect::<Vec<_>>(),
            [
                "IPV6_ENABLED_ALLOWED",
                "IPV6_UNVERIFIABLE probe=ipv6-disabled",
                "IPV6_ADDRESSES_ALLOWED count=1",
                "IPV6_ROUTES_ALLOWED count=1",
                "IPV6_FORWARDING_ENABLED scope=global",
                "IPV6_FORWARDING_ENABLED scope=device",
                "IPV6_FORWARDING_ENABLED scope=force",
                "IPV6_FORWARDING_ENABLED scope=multicast",
            ]
        );
        // The default facts are unreadable: fail closed.
        assert_eq!(
            evaluate_device(
                &DeviceFacts {
                    ipv6: Ipv6Facts::default(),
                    ..clean
                },
                strict
            ),
            Err(CheckFailure::Unverifiable(Probe::Ipv6Disabled))
        );
        // IPv4 refusals come first; the IPv6 override does not touch them.
        assert_eq!(
            evaluate_device(
                &DeviceFacts {
                    ipv4_routes: 1,
                    ipv6: exposed,
                    ..clean
                },
                allowed
            ),
            Err(CheckFailure::KernelIpv4Routes { count: 1 })
        );
        for (failure, text) in [
            (
                CheckFailure::KernelIpv6Addresses { count: 2 },
                "KERNEL_IPV6_ADDRESSES count=2",
            ),
            (
                CheckFailure::KernelIpv6Routes { count: 1 },
                "KERNEL_IPV6_ROUTES count=1",
            ),
            (
                CheckFailure::KernelIpv6ForwardingEnabled(ForwardingScope::Global),
                "KERNEL_IPV6_FORWARDING_ENABLED scope=global",
            ),
            (
                CheckFailure::KernelIpv6ForwardingEnabled(ForwardingScope::Force),
                "KERNEL_IPV6_FORWARDING_ENABLED scope=force",
            ),
            (CheckFailure::KernelIpv6Enabled, "KERNEL_IPV6_ENABLED"),
            (
                CheckFailure::KernelForwardingEnabled(ForwardingScope::Multicast),
                "KERNEL_FORWARDING_ENABLED scope=multicast",
            ),
            (
                CheckFailure::KernelIpv4Routes { count: 4 },
                "KERNEL_IPV4_ROUTES count=4",
            ),
            (
                CheckFailure::Unverifiable(Probe::Ipv4Routes),
                "UNVERIFIABLE probe=ipv4-routes",
            ),
            (
                CheckFailure::Unverifiable(Probe::Ipv6Routes),
                "UNVERIFIABLE probe=ipv6-routes",
            ),
        ] {
            assert_eq!(failure.to_string(), text);
        }
    }

    /// IPv4 `mc_forwarding` is refused like the other forwarding sysctls
    /// (warned under `--allow-kernel-forwarding`); the weak-host exposure
    /// (or an unreadable `rp_filter`/`arp_ignore`) only ever warns.
    #[test]
    fn multicast_forwarding_refuses_and_weak_host_only_warns() {
        let clean = DeviceFacts {
            ipv6: Ipv6Facts::DISABLED,
            ..ipv6_clean()
        };
        let strict = CheckPolicy::default();
        let allowed = CheckPolicy {
            allow_kernel_forwarding: true,
            ..strict
        };
        let multicast = DeviceFacts {
            forwarding_multicast: Some(true),
            ..clean
        };
        assert_eq!(
            evaluate_device(&multicast, strict),
            Err(CheckFailure::KernelForwardingEnabled(
                ForwardingScope::Multicast
            ))
        );
        assert_eq!(
            evaluate_device(&multicast, allowed).map(|w| w.codes().collect::<Vec<_>>()),
            Ok(vec!["IPV4_FORWARDING_ENABLED scope=multicast".to_owned()])
        );
        assert_eq!(
            evaluate_device(
                &DeviceFacts {
                    forwarding_multicast: None,
                    ..clean
                },
                strict
            ),
            Err(CheckFailure::Unverifiable(Probe::Forwarding))
        );
        for weak_host in [Some(true), None] {
            let facts = DeviceFacts { weak_host, ..clean };
            let warnings = evaluate_device(&facts, strict).expect("never refused");
            assert_eq!(
                warnings.codes().collect::<Vec<_>>(),
                ["IPV4_WEAK_HOST_EXPOSURE"],
                "{weak_host:?}"
            );
        }
        assert_eq!(evaluate_device(&clean, strict), Ok(Warnings::default()));
    }

    /// The `disable_ipv6` reader: a present flag reads; a missing flag
    /// counts as disabled only when the namespace has no IPv6 at all.
    #[cfg(target_os = "linux")]
    #[test]
    fn ipv6_disabled_is_read_or_fails_closed() {
        use std::path::Path;
        let has_ipv6 = Path::new(linux::IPV6_SYSCTLS).exists();
        let lo = linux::ipv6_disabled(Path::new("/proc/sys/net/ipv6/conf/lo/disable_ipv6"));
        let missing = linux::ipv6_disabled(Path::new("/proc/sys/net/ipv6/conf/nonexistent0/x"));
        if has_ipv6 {
            assert!(lo.is_some());
            assert_eq!(missing, None, "unreadable with IPv6 present");
        } else {
            assert_eq!((lo, missing), (Some(true), Some(true)), "no IPv6");
        }
    }

    #[test]
    fn mtu_must_match_the_session_and_fit_a_frame() {
        let clean = DeviceFacts {
            ifindex: 7,
            rx_queues: 1,
            link_mtu: 1778,
            session_mtu: 1778,
            frame_capacity: 1792,
            forwarding_global: Some(false),
            forwarding_device: Some(false),
            forwarding_multicast: Some(false),
            weak_host: Some(false),
            ipv6: Ipv6Facts::DISABLED,
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
    fn flags_parse_strictly() {
        assert_eq!(parse_flag("1\n"), Some(true));
        assert_eq!(parse_flag("0"), Some(false));
        assert_eq!(parse_flag("2"), None);
        assert_eq!(parse_flag(""), None);
    }
}
