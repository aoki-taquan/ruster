use std::fmt;

use serde::Deserialize;

/// A parsed configuration selected by its explicit schema version.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VersionedConfig {
    V1(ConfigV1),
}

/// Exact schema version 1 syntax.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConfigV1 {
    pub schema_version: u32,
    #[serde(default)]
    pub interfaces: Vec<InterfaceV1>,
    #[serde(default)]
    pub addresses: Vec<AddressV1>,
    #[serde(default)]
    pub routes: Vec<RouteV1>,
    #[serde(default)]
    pub neighbors: Vec<NeighborV1>,
    pub ipv4_origin: Option<Ipv4OriginV1>,
    /// ARP receive policy; absent means RFC 826 behavior.
    pub arp: Option<ArpV1>,
    pub resolution: Option<ResolutionV1>,
    pub icmpv4_errors: Option<Icmpv4ErrorV1>,
    pub nat44: Option<Nat44V1>,
    pub firewall: Option<FirewallV1>,
    pub tick: Option<TickBudgetV1>,
    /// IPv4 fragmentation of forwarded DF-clear datagrams (MTU2 part B);
    /// absent means [`FragmentationV1::default`] (on, RFC 1812 §4.2.2.7).
    pub fragmentation: Option<FragmentationV1>,
    /// IPv4 fragment association for the NAT and the firewall (NAT-FRAG);
    /// absent means [`FragmentTrackingV1::default`] (`associate`, RFC 4787
    /// REQ-14).
    pub fragment_tracking: Option<FragmentTrackingV1>,
    /// Packet backend; absent means [`BackendKindV1::Sim`].
    pub backend: Option<BackendV1>,
    /// What an applied reload does with runtime state; absent means
    /// [`ReloadStateV1::Carry`].
    pub reload: Option<ReloadV1>,
    /// `ruster run` health thresholds (`[health]`, OPS-LOG); a key that is
    /// absent falls back to the matching `ruster run` flag, then to the
    /// built-in default. Ignored by `run-sim`.
    pub health: Option<HealthV1>,
    /// `ruster run` watch intervals (`[watch]`, OPS-LOG); same fallback as
    /// [`HealthV1`].
    pub watch: Option<WatchV1>,
    /// What `ruster run` does to the ports' kernel state when it exits
    /// after serving (`[exit-protection]`, OPS-EXIT); absent means
    /// [`ExitProtectionV1::default`] (nothing). Restart-required. Ignored by
    /// `run-sim`.
    pub exit_protection: Option<ExitProtectionV1>,
}

/// `[exit-protection]`: opt-in changes `ruster run` makes to every port's
/// kernel state when it exits after it served (OPS-EXIT). Detaching the
/// router hands the ports back to the kernel, which may then forward,
/// answer, or route their traffic without the router's firewall and NAT;
/// these keys close that gap. Both rewrite operator and kernel state, so
/// both default to off. Changing either is restart-required.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ExitProtectionV1 {
    /// Set every port's link administratively down (`IFF_UP` cleared over
    /// rtnetlink) at exit. Needs `CAP_NET_ADMIN` at exit, so `ruster run`
    /// refuses it unless `--keep-privileges`.
    #[serde(default)]
    pub link_down: bool,
    /// Write 0 to every port's `net.ipv4.conf.<device>.forwarding` at exit.
    /// The files are opened before the privilege drop, but Linux checks
    /// `CAP_NET_ADMIN` at every write, so `ruster run` refuses it unless
    /// `--keep-privileges`.
    #[serde(default)]
    pub ipv4_forwarding_off: bool,
}

impl ExitProtectionV1 {
    /// Whether any exit action is on.
    #[must_use]
    pub const fn any(self) -> bool {
        self.link_down || self.ipv4_forwarding_off
    }
}

/// `[health]`: the health thresholds of `ruster run`'s watch (OPS-LOG).
///
/// Every key is optional; validation bounds each one
/// ([`crate::HEALTH_MS_RANGE`] and the other `HEALTH_*` bounds) and fails
/// closed. A fatal threshold of 0 turns that fatal exit into a warning.
/// All of them are reloadable.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct HealthV1 {
    /// The oldest in-flight TX frame unchanged this long: warning
    /// `TX_STALL`.
    pub tx_stall_warn_ms: Option<u64>,
    /// ... this long: fatal `TX_STALL`; 0 never. At least
    /// `tx-stall-warn-ms` unless 0.
    pub tx_stall_fatal_ms: Option<u64>,
    /// Kick errors growing in every sample this long: fatal
    /// `KICK_ERRORS`; 0 never.
    pub kick_errors_fatal_ms: Option<u64>,
    /// Fill starved this long: warning `FILL_STARVED`.
    pub fill_starved_warn_ms: Option<u64>,
    /// Failed link queries of one kind in a row: fatal
    /// `LINK_UNVERIFIABLE`.
    pub link_probe_failures_fatal: Option<u64>,
    /// AF_PACKET stacked-device dumps interrupted in a row: fatal
    /// `LINK_UNVERIFIABLE`.
    pub link_dump_interrupted_fatal: Option<u64>,
    /// AF_XDP frames quarantined on a port since startup: fatal
    /// `FRAMES_QUARANTINED`; 0 never (the first one always warns).
    pub frames_quarantined_fatal: Option<u64>,
    /// AF_XDP TX descriptors the kernel refused on a port since startup
    /// (`XDP_STATISTICS` `tx_invalid_descs`): fatal `TX_INVALID_DESCS`; 0
    /// never (the first one always warns).
    pub tx_invalid_descs_fatal: Option<u64>,
}

/// `[watch]`: the cold-path watch intervals of `ruster run` (OPS-LOG). All
/// reloadable.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct WatchV1 {
    /// Backend health sample interval.
    pub health_interval_ms: Option<u64>,
    /// Link round interval (link, address, route, forwarding, IPv6, and
    /// weak-host exposure probes of every port).
    pub link_interval_ms: Option<u64>,
    /// Age of an outstanding link round from which every due round is
    /// stale (a failed link query).
    pub link_stale_ms: Option<u64>,
}

/// Reload behavior (`[reload]`, RELOAD-CARRY). Read from the document being
/// applied, so a reload can switch it.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ReloadV1 {
    #[serde(default)]
    pub state: ReloadStateV1,
    /// What a reload does while a port whose link is down holds TX
    /// (OPS-EXIT); absent means [`DownLinkTxV1::Send`].
    #[serde(default)]
    pub down_link_tx: DownLinkTxV1,
}

/// `[reload] down-link-tx` (OPS-EXIT): TX frames a port whose link is down
/// still holds (the kernel sends them when the link returns, AF_XDP cannot
/// take them back) do not block a reload. `send` (the default) applies the
/// reload and lets them leave when the link returns, possibly after the
/// new generation is active; `refuse` is the hardening: such a reload is
/// refused (`code=DOWN_LINK_TX_HELD`) and a restart (which discards them)
/// applies the change.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum DownLinkTxV1 {
    #[default]
    Send,
    Refuse,
}

/// `[reload] state`: whether an applied reload keeps NAT44 mappings and
/// sessions, firewall flows, and learned ARP neighbors that the new
/// document does not invalidate (`carry`, the default), or flushes all of
/// them and rotates every hash key (`flush`, the behavior before
/// RELOAD-CARRY).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ReloadStateV1 {
    #[default]
    Carry,
    Flush,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct InterfaceV1 {
    pub id: u16,
    pub name: String,
    pub device: String,
    pub mac: String,
    /// IPv4 MTU of the link (the largest IPv4 datagram the interface sends,
    /// without the Ethernet header); absent means
    /// [`ruster_core::ETHERNET_DEFAULT_MTU`] (1500). 68
    /// ([`ruster_core::IPV4_MIN_MTU`]) to 65535. Forwarding sends nothing
    /// longer out of the interface (Fragmentation Needed with this MTU for
    /// DF datagrams). `ruster run` refuses an MTU above the device's.
    pub mtu: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AddressV1 {
    pub interface: String,
    pub ipv4: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RouteV1 {
    pub prefix: String,
    pub egress: String,
    pub via: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NeighborV1 {
    pub interface: String,
    pub address: String,
    pub mac: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Ipv4OriginV1 {
    pub default_ttl: u8,
    /// Answer Echo Requests to router addresses (RFC 1812 §4.3.3.6 option;
    /// default `true`).
    #[serde(default = "enabled")]
    pub echo_reply: bool,
}

const fn enabled() -> bool {
    true
}

/// Default `[fragmentation] datagrams`: DF-clear datagrams one tick can
/// fragment. A full RX batch of such datagrams fits when it is at least
/// `[tick] rx`; each slot holds one datagram of the largest interface MTU.
pub const DEFAULT_FRAGMENTATION_DATAGRAMS: u32 = 64;

/// Largest `[fragmentation] datagrams` (`CAPACITY_LIMIT_EXCEEDED`).
pub const MAX_FRAGMENTATION_DATAGRAMS: u32 = 1024;

const fn default_fragmentation_datagrams() -> u32 {
    DEFAULT_FRAGMENTATION_DATAGRAMS
}

const fn default_max_fragments_per_datagram() -> u32 {
    ruster_core::IPV4_FRAGMENTATION_DEFAULT_MAX_FRAGMENTS as u32
}

/// `[fragmentation]`: fragmentation of forwarded DF-clear datagrams above
/// their egress MTU (RFC 791 §3.2, RFC 1812 §4.2.2.7, MTU2 part B).
///
/// Every field defaults to RFC behaviour; turning it off or lowering the
/// bound is hardening.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FragmentationV1 {
    /// `false` keeps the MTU1 behaviour (`IPV4_FRAGMENTATION_REQUIRED`, no
    /// fragment, no slot storage). Default `true` (RFC 1812 MUST).
    #[serde(default = "enabled")]
    pub enabled: bool,
    /// Most fragments one datagram may be cut into, 2 to 1365
    /// ([`ruster_core::IPV4_FRAGMENTATION_MAX_FRAGMENTS`], the most any
    /// datagram can need); more is `IPV4_FRAGMENTATION_TOO_MANY_FRAGMENTS`.
    /// Default 1365.
    #[serde(default = "default_max_fragments_per_datagram")]
    pub max_fragments_per_datagram: u32,
    /// Datagrams one tick can fragment (slots), 1 to
    /// [`MAX_FRAGMENTATION_DATAGRAMS`]; more is
    /// `IPV4_FRAGMENTATION_QUEUE_FULL`. Default
    /// [`DEFAULT_FRAGMENTATION_DATAGRAMS`].
    #[serde(default = "default_fragmentation_datagrams")]
    pub datagrams: u32,
}

impl Default for FragmentationV1 {
    fn default() -> Self {
        Self {
            enabled: true,
            max_fragments_per_datagram: default_max_fragments_per_datagram(),
            datagrams: DEFAULT_FRAGMENTATION_DATAGRAMS,
        }
    }
}

/// `[fragment-tracking] mode`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum FragmentTrackingModeV1 {
    /// Default (RFC 4787 REQ-14, RFC 1812): the first fragment of a datagram
    /// gets the firewall and NAT decision on its transport header and every
    /// later fragment follows it; a later fragment that arrives first is
    /// held (bounded) until its first fragment decides.
    #[default]
    Associate,
    /// Hardening: every received fragment is refused as before NAT-FRAG
    /// (`FIREWALL_FRAGMENT_UNSUPPORTED` first), and no association storage
    /// exists.
    Refuse,
}

/// Default `[fragment-tracking] entries`: datagrams in flight at once.
pub const DEFAULT_FRAGMENT_TRACKING_ENTRIES: u32 = 256;
/// Largest `[fragment-tracking] entries` (`CAPACITY_LIMIT_EXCEEDED`).
pub const MAX_FRAGMENT_TRACKING_ENTRIES: u32 = 1 << 14;
/// Default `[fragment-tracking] entries-per-host`.
pub const DEFAULT_FRAGMENT_TRACKING_ENTRIES_PER_HOST: u32 = 32;
/// Default `[fragment-tracking] held-fragments`.
pub const DEFAULT_FRAGMENT_TRACKING_HELD: u32 = 64;
/// Largest `[fragment-tracking] held-fragments` (`CAPACITY_LIMIT_EXCEEDED`).
pub const MAX_FRAGMENT_TRACKING_HELD: u32 = 512;
/// Default `[fragment-tracking] held-per-host`.
pub const DEFAULT_FRAGMENT_TRACKING_HELD_PER_HOST: u32 = 16;

const fn default_fragment_tracking_entries() -> u32 {
    DEFAULT_FRAGMENT_TRACKING_ENTRIES
}

const fn default_fragment_tracking_entries_per_host() -> u32 {
    DEFAULT_FRAGMENT_TRACKING_ENTRIES_PER_HOST
}

const fn default_fragment_tracking_held() -> u32 {
    DEFAULT_FRAGMENT_TRACKING_HELD
}

const fn default_fragment_tracking_held_per_host() -> u32 {
    DEFAULT_FRAGMENT_TRACKING_HELD_PER_HOST
}

const fn default_fragment_tracking_timeout_ms() -> u32 {
    ruster_core::IPV4_FRAGMENT_TRACKING_DEFAULT_TIMEOUT_MS
}

/// `[fragment-tracking]`: IPv4 fragment association for the NAT and the
/// stateful firewall (NAT-FRAG, RFC 4787 REQ-14).
///
/// Every field defaults to the RFC behaviour (`associate`); `refuse` and
/// smaller bounds are hardening.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FragmentTrackingV1 {
    #[serde(default)]
    pub mode: FragmentTrackingModeV1,
    /// Datagrams associated at once, 1 to [`MAX_FRAGMENT_TRACKING_ENTRIES`];
    /// a new one beyond is `IPV4_FRAGMENT_TABLE_FULL`. Default
    /// [`DEFAULT_FRAGMENT_TRACKING_ENTRIES`].
    #[serde(default = "default_fragment_tracking_entries")]
    pub entries: u32,
    /// Datagrams of one source associated at once (at least 1); beyond is
    /// `IPV4_FRAGMENT_HOST_LIMIT`. Default
    /// [`DEFAULT_FRAGMENT_TRACKING_ENTRIES_PER_HOST`].
    #[serde(default = "default_fragment_tracking_entries_per_host")]
    pub entries_per_host: u32,
    /// Fragments held because they arrived before their first fragment, 0
    /// to [`MAX_FRAGMENT_TRACKING_HELD`] (0 refuses them all,
    /// `IPV4_FRAGMENT_HOLD_FULL`). Needs `[fragmentation]` on (the held
    /// fragments leave through its slots); none are held without it.
    /// Default [`DEFAULT_FRAGMENT_TRACKING_HELD`].
    #[serde(default = "default_fragment_tracking_held")]
    pub held_fragments: u32,
    /// Fragments of one source held at once; beyond is
    /// `IPV4_FRAGMENT_HOST_HOLD_LIMIT`. Default
    /// [`DEFAULT_FRAGMENT_TRACKING_HELD_PER_HOST`].
    #[serde(default = "default_fragment_tracking_held_per_host")]
    pub held_per_host: u32,
    /// Lifetime of an association from the first fragment seen, 100 to
    /// 60000 ms. Default 5000.
    #[serde(default = "default_fragment_tracking_timeout_ms")]
    pub timeout_ms: u32,
    /// The share of `entries` the datagrams of one ingress interface may
    /// take, 1 to 100 percent (100 does not partition). Default 50: a flood
    /// on one interface cannot take the other's entries.
    #[serde(default = "default_fragment_tracking_ingress_share_percent")]
    pub ingress_share_percent: u8,
}

const fn default_fragment_tracking_ingress_share_percent() -> u8 {
    ruster_core::IPV4_FRAGMENT_TRACKING_DEFAULT_INGRESS_SHARE_PERCENT
}

impl Default for FragmentTrackingV1 {
    fn default() -> Self {
        Self {
            mode: FragmentTrackingModeV1::Associate,
            entries: DEFAULT_FRAGMENT_TRACKING_ENTRIES,
            entries_per_host: DEFAULT_FRAGMENT_TRACKING_ENTRIES_PER_HOST,
            held_fragments: DEFAULT_FRAGMENT_TRACKING_HELD,
            held_per_host: DEFAULT_FRAGMENT_TRACKING_HELD_PER_HOST,
            timeout_ms: default_fragment_tracking_timeout_ms(),
            ingress_share_percent: default_fragment_tracking_ingress_share_percent(),
        }
    }
}

/// ARP receive policy (`[arp]`).
///
/// Every field defaults to RFC 826 behavior; hardening is opt-in.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ArpV1 {
    /// ARP-031 hardening (default `false`, RFC 826): drop an ARP Request or
    /// Reply whose sender is a host outside every direct route out of the
    /// ingress interface and not one of its gateways, as
    /// `ARP_SENDER_NOT_ON_LINK`, without learning or replying.
    #[serde(default)]
    pub require_on_link_sender: bool,
}

const fn default_inbound_sessions_per_remote() -> u8 {
    ruster_core::NAT44_TCP_DEFAULT_INBOUND_SESSIONS_PER_REMOTE
}

/// Default `[nat44.tcp] opening-idle-ttl-ms` and `closing-idle-ttl-ms`:
/// the RFC 5382 REQ-5 transitory floor of 4 minutes.
const fn default_transitory_idle_ttl_ms() -> u64 {
    ruster_core::NAT44_TCP_DEFAULT_TRANSITORY_IDLE_TTL_MS
}

/// Default `[nat44.tcp.capacity] unsolicited-syn-holds`. Each hold lasts
/// [`ruster_core::NAT44_TCP_UNSOLICITED_SYN_HOLD_MS`] (6 s) and the default
/// Port Unreachable limiter sends at most one error per egress per second,
/// so 64 slots (592 bytes each, about 37 KiB) leave ample room for
/// retransmissions and bursts while keeping the RFC 5382 REQ-4 default on.
/// With the switch off, 0 frees them.
pub const DEFAULT_UNSOLICITED_SYN_HOLDS: u32 = 64;

const fn default_unsolicited_syn_holds() -> u32 {
    DEFAULT_UNSOLICITED_SYN_HOLDS
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ResolutionPolicyV1 {
    pub interval_ms: u64,
    pub state_ttl_ms: u64,
    pub dynamic_neighbor_ttl_ms: u64,
    pub max_attempts: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ResolutionCapacityV1 {
    pub states: u32,
    pub actions: u32,
    pub dynamic_neighbors: u32,
    pub failure_holds: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ResolutionV1 {
    pub policy: ResolutionPolicyV1,
    pub capacity: ResolutionCapacityV1,
    /// Hold and replay of datagrams whose next hop is being resolved
    /// (`[resolution.hold]`, ARP-HOLD); absent means
    /// [`ResolutionHoldV1::default`] (on, RFC 1122 §2.3.2.2).
    pub hold: Option<ResolutionHoldV1>,
}

/// `[resolution.hold]`: bounded hold and replay of forwarded datagrams whose
/// next hop is being resolved by ARP (ARP-HOLD; RFC 1122 §2.3.2.2 and RFC
/// 1812 §3.3.2: save at least the latest datagram per unresolved address and
/// send it on resolution).
///
/// Every key is optional and defaults to the RFC behaviour (on);
/// `enabled = false` and smaller bounds are hardening. Every bound present
/// is checked, also with `enabled = false` (fail closed). Part of the
/// storage shape (restart-required). The hold needs `[fragmentation]` on (a
/// replayed datagram leaves through its slots): without it nothing is held,
/// and an explicit `enabled = true` is refused
/// (`ARP_HOLD_WITHOUT_FRAGMENTATION`).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ResolutionHoldV1 {
    /// `false` drops such a datagram (`NEIGHBOR_UNRESOLVED`, the behaviour
    /// before ARP-HOLD) and allocates no hold storage. Default `true`.
    pub enabled: Option<bool>,
    /// Datagrams held per (egress, next hop), 1 to
    /// [`ruster_core::ARP_HOLD_MAX_PER_NEIGHBOR`] and at most `packets`; a
    /// new one beyond replaces an older one (the sender's own oldest if it
    /// has one, else the oldest: the latest is kept). Default
    /// [`ruster_core::ARP_HOLD_DEFAULT_PER_NEIGHBOR`] (at most `packets`).
    pub per_neighbor: Option<u16>,
    /// Datagrams held per (ingress, source), 1 to `packets`; beyond is
    /// `ARP_HOLD_HOST_LIMIT`. Default
    /// [`ruster_core::ARP_HOLD_DEFAULT_PER_HOST`] (at most `packets`).
    pub per_host: Option<u16>,
    /// Datagrams held per ingress interface, 1 to `packets`; beyond is
    /// `ARP_HOLD_INGRESS_LIMIT`, so a flood on one interface (sources are
    /// not authenticated) cannot take another's slots. Default half of
    /// `packets` (at least 1); `packets` does not partition.
    pub per_ingress: Option<u16>,
    /// Datagrams held in all (slots), 1 to
    /// [`ruster_core::ARP_HOLD_MAX_PACKETS`]; beyond is `ARP_HOLD_FULL`.
    /// Each slot is a fragmentation slot's size. Default
    /// [`ruster_core::ARP_HOLD_DEFAULT_PACKETS`].
    pub packets: Option<u32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Icmpv4ErrorPolicyV1 {
    pub interval_ms: u64,
    pub state_ttl_ms: u64,
    /// Minimum interval between two ICMP Port Unreachable errors (the TCP
    /// NAT's RFC 5382 REQ-4 answer to unsolicited inbound SYNs) on one
    /// egress. Port Unreachable has its own limiter, so it never uses up
    /// `interval-ms` of the other kinds. Default
    /// [`ruster_core::ICMPV4_DEFAULT_PORT_UNREACHABLE_INTERVAL_MS`] (1 s).
    #[serde(default = "default_port_unreachable_interval_ms")]
    pub port_unreachable_interval_ms: u64,
    /// Minimum interval between two ICMP Fragmentation Needed errors
    /// (MTU1, Path MTU Discovery) on one egress. Fragmentation Needed has
    /// its own limiter, so other errors never use it up. Must not be 0.
    /// Default [`ruster_core::ICMPV4_DEFAULT_FRAGMENTATION_NEEDED_INTERVAL_MS`]
    /// (10 ms).
    #[serde(default = "default_fragmentation_needed_interval_ms")]
    pub fragmentation_needed_interval_ms: u64,
}

const fn default_fragmentation_needed_interval_ms() -> u64 {
    ruster_core::ICMPV4_DEFAULT_FRAGMENTATION_NEEDED_INTERVAL_MS
}

const fn default_port_unreachable_interval_ms() -> u64 {
    ruster_core::ICMPV4_DEFAULT_PORT_UNREACHABLE_INTERVAL_MS
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Icmpv4ErrorCapacityV1 {
    pub states: u32,
    pub actions: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Icmpv4ErrorV1 {
    pub policy: Icmpv4ErrorPolicyV1,
    pub capacity: Icmpv4ErrorCapacityV1,
    #[serde(default)]
    pub generate: Icmpv4ErrorGenerateV1,
    /// Rate limit of external errors NAT44 translates toward an inside
    /// host; absent means the defaults.
    #[serde(default)]
    pub translated: Icmpv4ErrorTranslatedV1,
}

/// `[icmpv4-errors.translated]`: per (inside host, quoted remote) rate limit of external
/// ICMPv4 errors that NAT44 translates (RFC 5508 REQ-10 f, RFC 1812
/// §4.3.2.8; NAT44-065). Part of the ICMPv4 error policy, so a change is
/// restart-required.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Icmpv4ErrorTranslatedV1 {
    /// Sustained errors per second per (inside host, quoted remote); absent means
    /// [`ruster_core::ICMPV4_DEFAULT_TRANSLATED_RATE_PER_SECOND`]. 1 to
    /// [`ruster_core::ICMPV4_MAX_TRANSLATED_LIMIT`]; there is no unlimited
    /// setting (both keys at the maximum is effectively off).
    #[serde(default = "default_translated_rate_per_second")]
    pub rate_per_second: u32,
    /// Errors one (inside host, quoted remote) can receive at one instant; absent means
    /// [`ruster_core::ICMPV4_DEFAULT_TRANSLATED_BURST`]. Same bounds.
    #[serde(default = "default_translated_burst")]
    pub burst: u32,
}

const fn default_translated_rate_per_second() -> u32 {
    ruster_core::ICMPV4_DEFAULT_TRANSLATED_RATE_PER_SECOND
}

const fn default_translated_burst() -> u32 {
    ruster_core::ICMPV4_DEFAULT_TRANSLATED_BURST
}

impl Default for Icmpv4ErrorTranslatedV1 {
    fn default() -> Self {
        Self {
            rate_per_second: default_translated_rate_per_second(),
            burst: default_translated_burst(),
        }
    }
}

/// Per-kind generation switches. Every kind defaults to `true` (RFC 1812).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Icmpv4ErrorGenerateV1 {
    /// Time Exceeded, TTL exceeded in transit (Type 11/Code 0).
    #[serde(default = "enabled")]
    pub time_exceeded: bool,
    /// Destination Unreachable, Network (Type 3/Code 0) on a route miss.
    #[serde(default = "enabled")]
    pub net_unreachable: bool,
    /// Destination Unreachable, Host (Type 3/Code 1) after fruitless ARP.
    #[serde(default = "enabled")]
    pub host_unreachable: bool,
    /// Destination Unreachable, Fragmentation Needed and DF Set (Type
    /// 3/Code 4) for a DF datagram longer than its egress MTU. Turning it
    /// off black-holes Path MTU Discovery (RFC 1191) through the router.
    #[serde(default = "enabled")]
    pub fragmentation_needed: bool,
    /// Destination Unreachable, Protocol Unreachable (Type 3/Code 2) for a
    /// datagram addressed to the router whose IP protocol it does not
    /// implement (ICMP-ERR).
    #[serde(default = "enabled")]
    pub protocol_unreachable: bool,
    /// Destination Unreachable, Port Unreachable (Type 3/Code 3) for a UDP
    /// datagram addressed to the router (no UDP port is open). The TCP
    /// NAT's Port Unreachable for unsolicited SYNs is
    /// `[nat44.tcp.policy] unsolicited-syn-icmp`, not this switch.
    #[serde(default = "enabled")]
    pub udp_port_unreachable: bool,
    /// Parameter Problem (Type 12/Code 0) for a truncated datagram (Total
    /// Length past the frame) or malformed IPv4 options (ICMP-ERR).
    #[serde(default = "enabled")]
    pub parameter_problem: bool,
    /// Destination Unreachable, Communication Administratively Prohibited
    /// (Type 3/Code 13) for a datagram the forward firewall denies. Default
    /// `false`: a deny stays a silent drop (RFC 1812 §5.2.7.1 allows this
    /// option; owner decision).
    #[serde(default)]
    pub admin_prohibited: bool,
}

impl Default for Icmpv4ErrorGenerateV1 {
    fn default() -> Self {
        Self {
            time_exceeded: true,
            net_unreachable: true,
            host_unreachable: true,
            fragmentation_needed: true,
            protocol_unreachable: true,
            udp_port_unreachable: true,
            parameter_problem: true,
            admin_prohibited: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44V1 {
    pub realm: Nat44RealmV1,
    pub udp: Option<Nat44UdpV1>,
    pub tcp: Option<Nat44TcpV1>,
    /// ICMP query NAT (N5, RFC 5508 §3). Absent means ICMP queries
    /// crossing the NAT are dropped (`NAT44_UDP_UNSUPPORTED_TRANSPORT`), the
    /// RFC 5508 REQ-1 "unless explicitly overridden by local policy" case.
    pub icmp: Option<Nat44IcmpV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44RealmV1 {
    pub inside: String,
    pub outside: String,
    pub public_address: String,
    pub ports: Nat44PortRangeV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44PortRangeV1 {
    pub first: u16,
    pub last: u16,
}

/// Received ICMPv4 error translation of one NAT44 protocol (RFC 5508).
///
/// The default, `bidirectional`, is the RFC 5508 behavior: external errors
/// (REQ-4), inside errors toward the external realm (REQ-5), and hairpinned
/// errors (REQ-7). `external-only` and `disabled` are security options.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Nat44Icmpv4ErrorsV1 {
    Disabled,
    ExternalOnly,
    #[default]
    Bidirectional,
}

/// Inbound filtering behavior of one NAT44 protocol (RFC 4787 §5).
///
/// The default, `address-dependent`, is the RECOMMENDED "more stringent"
/// behavior of RFC 4787 REQ-8 (UDP) and RFC 5382 REQ-3 (TCP).
/// `endpoint-independent` is the RECOMMENDED "application transparency"
/// behavior; `address-and-port-dependent` is a stricter opt-in.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Nat44FilteringV1 {
    EndpointIndependent,
    #[default]
    AddressDependent,
    AddressAndPortDependent,
}

/// `[nat44.tcp] inbound-rst`: `closing` (default, RFC 7857 §2.2) or
/// `corroborate` (inbound RST/FIN and handshake ACKs need outbound
/// corroboration).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Nat44TcpInboundRstV1 {
    #[default]
    Closing,
    Corroborate,
}

/// Raw textual NAT allocator seed with redacted formatting.
///
/// TOML integers are signed 64-bit values, so V1 uses text to preserve the
/// complete future `u64` input domain. Semantic parsing is a later stage.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(transparent)]
pub struct AllocatorSeedV1(String);

impl AllocatorSeedV1 {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AllocatorSeedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AllocatorSeedV1([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44UdpV1 {
    pub idle_ttl_ms: u64,
    pub allocator_seed: AllocatorSeedV1,
    /// ICMPv4 error translation; absent means `bidirectional`.
    #[serde(default)]
    pub icmpv4_errors: Nat44Icmpv4ErrorsV1,
    /// Inbound filtering; absent means `address-dependent`.
    #[serde(default)]
    pub filtering: Nat44FilteringV1,
    /// Hairpinning (RFC 4787 REQ-9 / RFC 5382 REQ-8); absent means `true`.
    /// `false` is an RFC 1812 §1.1.3 security option.
    #[serde(default = "enabled")]
    pub hairpinning: bool,
    /// Port preservation (RFC 4787 §4.2.1): a new mapping keeps the internal
    /// port when it is in the pool and free; absent means `true`, the
    /// port-preserving NAPT of RFC 6056 §4 / RFC 7857 §9. `false` always selects
    /// a keyed, obfuscated port.
    #[serde(default = "enabled")]
    pub port_preservation: bool,
    /// Limit on the mappings one internal IPv4 address may hold (N3,
    /// NAT44-092, RFC 6888 REQ-4); `0` means no limit. Absent means 0: RFC
    /// 6888 asks a NAT to support a limit, not for a value. A nonzero limit
    /// adds per-host storage sized from `capacity.mappings`, so switching
    /// between `0` and a limit is restart-required; changing a nonzero
    /// limit is reloadable.
    #[serde(default)]
    pub mappings_per_host: u16,
    /// Limit on the filter peers the mappings of one internal IPv4 address
    /// may hold together (N6, NAT44-119, RFC 6888 REQ-5); `0` means no
    /// limit. Absent means 0. A nonzero limit needs the per-host storage
    /// (as `mappings-per-host` does), so switching between "neither limit
    /// set" and "a limit set" is restart-required; other changes are
    /// reloadable.
    #[serde(default)]
    pub peers_per_host: u16,
    pub capacity: Nat44UdpCapacityV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44UdpCapacityV1 {
    pub mappings: u32,
    pub peers: u32,
}

/// Default `[nat44.icmp] idle-ttl-ms`: the RFC 5508 REQ-2 floor of 60 s.
const fn default_icmp_idle_ttl_ms() -> u64 {
    ruster_core::NAT44_ICMP_DEFAULT_IDLE_TTL_MS
}

/// `[nat44.icmp]`: ICMP query NAT (N5, RFC 5508 §3). Echo and Timestamp
/// queries from the inside are translated with an endpoint-independent
/// identifier mapping (REQ-1 a).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44IcmpV1 {
    /// Query mapping idle timeout; at least 60000 (RFC 5508 REQ-2), absent
    /// means 60000. Only outbound queries refresh it.
    #[serde(default = "default_icmp_idle_ttl_ms")]
    pub idle_ttl_ms: u64,
    /// Non-secret salt of the keyed identifier selection; absent means "0".
    pub allocator_seed: Option<AllocatorSeedV1>,
    /// Translation of ICMP errors quoting a query; absent means
    /// `bidirectional`.
    #[serde(default)]
    pub icmpv4_errors: Nat44Icmpv4ErrorsV1,
    /// Reply filtering: `address-dependent` (default) or
    /// `endpoint-independent`. `address-and-port-dependent` is refused (a
    /// query has no port).
    #[serde(default)]
    pub filtering: Nat44FilteringV1,
    /// Keep the internal identifier when it is in the pool and free; absent
    /// means `true`. `false` always selects a keyed identifier.
    #[serde(default = "enabled")]
    pub identifier_preservation: bool,
    /// Per-internal-host query mapping limit (N3 applied to queries); `0`
    /// (default) is no limit. Switching between 0 and a limit is
    /// restart-required.
    #[serde(default)]
    pub mappings_per_host: u16,
    /// Per-internal-host query peer limit (N6, the UDP `peers-per-host`
    /// applied to queries); `0` (default) is no limit. It shares the
    /// per-host storage of `mappings-per-host`.
    #[serde(default)]
    pub peers_per_host: u16,
    /// Public identifier pool; absent means the `[nat44.realm.ports]`
    /// numbers. One owner slot per identifier, so the pool sizes storage.
    pub identifiers: Option<Nat44PortRangeV1>,
    pub capacity: Nat44IcmpCapacityV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44IcmpCapacityV1 {
    pub mappings: u32,
    pub peers: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44TcpV1 {
    /// Established connection idle timeout (RFC 5382 REQ-5, at least
    /// 2h4m).
    pub idle_ttl_ms: u64,
    /// Idle timeout of a partially open connection (SYN and ACK not yet
    /// seen in both directions); absent means 240000 (4 minutes, the RFC
    /// 5382 REQ-5 transitory floor). Validated to at least that floor and
    /// at most `idle-ttl-ms`.
    #[serde(default = "default_transitory_idle_ttl_ms")]
    pub opening_idle_ttl_ms: u64,
    /// Idle timeout of a closing connection (FIN in both directions) and
    /// of one whose last segment was a RST (RFC 7857 §2.2); absent means
    /// 240000. Same bounds as `opening-idle-ttl-ms`.
    #[serde(default = "default_transitory_idle_ttl_ms")]
    pub closing_idle_ttl_ms: u64,
    pub allocator_seed: AllocatorSeedV1,
    /// ICMPv4 error translation; absent means `bidirectional`.
    #[serde(default)]
    pub icmpv4_errors: Nat44Icmpv4ErrorsV1,
    /// Inbound filtering; absent means `address-dependent`.
    #[serde(default)]
    pub filtering: Nat44FilteringV1,
    /// Hairpinning (RFC 4787 REQ-9 / RFC 5382 REQ-8); absent means `true`.
    /// `false` is an RFC 1812 §1.1.3 security option.
    #[serde(default = "enabled")]
    pub hairpinning: bool,
    /// Port preservation (RFC 4787 §4.2.1): a new mapping keeps the internal
    /// port when it is in the pool and free; absent means `true`, the
    /// port-preserving NAPT of RFC 6056 §4 / RFC 7857 §9. `false` always selects
    /// a keyed, obfuscated port.
    #[serde(default = "enabled")]
    pub port_preservation: bool,
    /// Limit on live sessions that external inbound initial SYNs created on
    /// one mapping from one remote IPv4 address; `0` means no limit. Absent
    /// means 0 (no limit): a limit is an opt-in local security policy, and
    /// closed connections count until their closing idle TTL (4 minutes by
    /// default). Validated to at most 16 (the
    /// bounded inbound chain walk).
    #[serde(default = "default_inbound_sessions_per_remote")]
    pub inbound_sessions_per_remote: u8,
    /// Delayed ICMP Port Unreachable for unsolicited inbound SYNs (RFC 5382
    /// REQ-4); absent means `true` (the RFC SHOULD). `false` keeps the
    /// REQ-4 a silent drop as the only policy.
    #[serde(default = "enabled")]
    pub unsolicited_syn_icmp: bool,
    /// What inbound RST/FIN segments do to a session's phase; absent means
    /// `closing` (RFC 7857 §2.2). `corroborate` is a local security policy.
    #[serde(default)]
    pub inbound_rst: Nat44TcpInboundRstV1,
    /// Limit on the mappings one internal IPv4 address may hold (N3,
    /// NAT44-092, RFC 6888 REQ-4); `0` means no limit. Absent means 0: RFC
    /// 6888 asks a NAT to support a limit, not for a value. A nonzero limit
    /// adds per-host storage sized from `capacity.mappings`, so switching
    /// between `0` and a limit is restart-required; changing a nonzero
    /// limit is reloadable.
    #[serde(default)]
    pub mappings_per_host: u16,
    /// Limit on the sessions one internal IPv4 address opens with outbound
    /// SYNs and keeps alive (N6, NAT44-119, RFC 6888 REQ-5); `0` means no
    /// limit. Absent means 0. Sessions created by inbound SYNs never count.
    /// A nonzero limit adds per-session host storage sized from
    /// `capacity.sessions`, so switching between `0` and a limit is
    /// restart-required; changing a nonzero limit is reloadable.
    #[serde(default)]
    pub sessions_per_host: u16,
    pub capacity: Nat44TcpCapacityV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44TcpCapacityV1 {
    pub mappings: u32,
    pub sessions: u32,
    /// Slots of the unsolicited-SYN hold table (each holds a quoted
    /// datagram); absent means [`DEFAULT_UNSOLICITED_SYN_HOLDS`]. `0`
    /// disables the delayed ICMP like `unsolicited-syn-icmp = false`.
    #[serde(default = "default_unsolicited_syn_holds")]
    pub unsolicited_syn_holds: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FirewallV1 {
    pub policy: FirewallPolicyV1,
    pub capacity: FirewallCapacityV1,
    #[serde(default)]
    pub rules: Vec<FirewallRuleV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FirewallPolicyV1 {
    pub udp_idle_ttl_ms: u64,
    pub tcp_opening_idle_ttl_ms: u64,
    pub tcp_active_idle_ttl_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FirewallCapacityV1 {
    pub states: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FirewallRuleV1 {
    pub id: u32,
    pub ingress: Option<String>,
    pub egress: Option<String>,
    pub source: String,
    pub destination: String,
    pub protocol: FirewallProtocolV1,
    /// Required for `tcp`/`udp`; must be absent for `icmp`.
    pub source_ports: Option<Nat44PortRangeV1>,
    /// Required for `tcp`/`udp`; must be absent for `icmp`.
    pub destination_ports: Option<Nat44PortRangeV1>,
    pub action: FirewallActionV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallProtocolV1 {
    Tcp,
    Udp,
    /// ICMP queries (Echo, Timestamp; N5). The rule has no port ranges and
    /// matches every identifier.
    Icmp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallActionV1 {
    AllowStateful,
    Deny,
}

/// Per-phase worker limits. Values are syntax only until runtime validation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TickBudgetV1 {
    pub rx: u32,
    pub resolution_timer_scans: u32,
    pub failure_dispatch_scans: u32,
    pub generated_arp: u32,
    pub generated_icmpv4: u32,
    /// Fragment frames per tick (MTU2 part B); absent means
    /// [`DEFAULT_TICK_GENERATED_FRAGMENTS`]. 1 to
    /// [`MAX_TICK_GENERATED_FRAGMENTS`].
    #[serde(default = "default_tick_generated_fragments")]
    pub generated_fragments: u32,
}

/// Default `[tick] generated-fragments`: fragment frames one tick may send
/// (MTU2 part B). The fragment phase runs after generated ARP and ICMPv4, so
/// this bounds how much of a port's generated pool and TX ring forwarded
/// fragments take per tick; 64 is 32 datagrams of 1500 bytes over a 1280- or
/// 1400-byte link.
pub const DEFAULT_TICK_GENERATED_FRAGMENTS: u32 = 64;

/// Largest `[tick] generated-fragments` (`CAPACITY_LIMIT_EXCEEDED`).
pub const MAX_TICK_GENERATED_FRAGMENTS: u32 = 1 << 16;

const fn default_tick_generated_fragments() -> u32 {
    DEFAULT_TICK_GENERATED_FRAGMENTS
}

/// Packet backend selection (`[backend]`).
///
/// The section is optional and defaults to the deterministic simulation
/// backend, so every schema-version 1 document written before the section
/// existed keeps its meaning. `ports` is valid only with `kind = "af-xdp"`,
/// `af-packet` only with `kind = "af-packet"`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct BackendV1 {
    /// Absent means `sim`.
    #[serde(default)]
    pub kind: BackendKindV1,
    /// What to do when a device already has an XDP program attached.
    /// Absent means `refuse`, the only supported policy.
    #[serde(default)]
    pub existing_xdp_program: ExistingXdpProgramV1,
    /// One AF_XDP socket per entry (`[[backend.ports]]`).
    #[serde(default)]
    pub ports: Vec<AfXdpPortV1>,
    /// The AF_PACKET backend (`[backend.af-packet]`).
    #[serde(default)]
    pub af_packet: Option<AfPacketV1>,
}

/// The AF_PACKET (TPACKET_V3) backend (`[backend.af-packet]`).
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AfPacketV1 {
    /// The longest Ethernet frame (header included, FCS excluded) of every
    /// port; every port's device MTU must be at most this minus 14 (so the
    /// largest port's MTU plus 14 for mixed MTUs). Absent means
    /// 1514 (MTU 1500).
    #[serde(default)]
    pub max_frame_len: Option<u32>,
    /// One packet socket per entry (`[[backend.af-packet.ports]]`).
    #[serde(default)]
    pub ports: Vec<AfPacketPortV1>,
}

/// One AF_PACKET socket bound to one configured interface's device.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AfPacketPortV1 {
    /// `name` of an `[[interfaces]]` entry; its `device` is bound.
    pub interface: String,
    /// The TPACKET_V3 RX ring.
    pub rx: AfPacketRxRingV1,
    /// The TPACKET_V3 TX ring.
    pub tx: AfPacketTxRingV1,
}

/// Geometry of one port's RX ring: `block-count` blocks of `block-size`
/// bytes; the kernel hands a block over when it is full or
/// `retire-timeout-ms` after its first frame.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AfPacketRxRingV1 {
    pub block_size: u32,
    pub block_count: u32,
    pub retire_timeout_ms: u32,
}

/// Geometry of one port's TX ring: `block-count` blocks of `block-size`
/// bytes, cut into fixed frames that hold the maximum frame.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AfPacketTxRingV1 {
    pub block_size: u32,
    pub block_count: u32,
}

/// Which packet backend a router process drives.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKindV1 {
    /// Deterministic in-process simulation (`ruster run-sim`).
    #[default]
    Sim,
    /// Linux AF_XDP sockets on real devices.
    AfXdp,
    /// Linux AF_PACKET (TPACKET_V3) sockets on real devices: the
    /// debug/fallback backend.
    AfPacket,
}

impl BackendKindV1 {
    /// The kebab-case spelling used in configuration and plan text.
    #[must_use]
    pub const fn config_name(self) -> &'static str {
        match self {
            Self::Sim => "sim",
            Self::AfXdp => "af-xdp",
            Self::AfPacket => "af-packet",
        }
    }
}

/// Policy for a device that already has an XDP program attached.
///
/// Only `refuse` exists: the backend never replaces or detaches a program it
/// did not attach. The field is kept so that the policy is explicit and can
/// grow without a schema change.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ExistingXdpProgramV1 {
    #[default]
    Refuse,
}

impl ExistingXdpProgramV1 {
    /// The kebab-case spelling used in configuration and plan text.
    #[must_use]
    pub const fn config_name(self) -> &'static str {
        match self {
            Self::Refuse => "refuse",
        }
    }
}

/// Requested AF_XDP copy policy of one socket.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AfXdpModeV1 {
    /// Require copy mode (`XDP_COPY`).
    Copy,
    /// Require zero-copy mode (`XDP_ZEROCOPY`).
    ZeroCopy,
    /// Let the kernel choose zero-copy when available, else copy.
    Auto,
}

impl AfXdpModeV1 {
    /// The kebab-case spelling used in configuration and plan text.
    #[must_use]
    pub const fn config_name(self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::ZeroCopy => "zero-copy",
            Self::Auto => "auto",
        }
    }
}

/// How the XDP program that redirects to the socket is attached.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum XdpAttachModeV1 {
    /// Driver (native) XDP, `XDP_FLAGS_DRV_MODE`.
    Native,
    /// Generic (skb) XDP, `XDP_FLAGS_SKB_MODE`; copy mode only.
    Generic,
}

impl XdpAttachModeV1 {
    /// The kebab-case spelling used in configuration and plan text.
    #[must_use]
    pub const fn config_name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Generic => "generic",
        }
    }
}

/// One AF_XDP socket bound to one queue of one configured interface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AfXdpPortV1 {
    /// `name` of an `[[interfaces]]` entry; its `device` is bound.
    pub interface: String,
    /// Device RX/TX queue id.
    pub queue: u32,
    pub mode: AfXdpModeV1,
    /// `XDP_USE_NEED_WAKEUP`; absent means `true`, the only supported value.
    #[serde(default = "enabled")]
    pub need_wakeup: bool,
    pub xdp_attach: XdpAttachModeV1,
    pub rings: AfXdpRingsV1,
    /// UMEM chunk size in bytes.
    pub frame_size: u32,
    /// Total UMEM chunks of this socket.
    pub frame_count: u32,
    /// Chunks reserved for router-generated ARP/ICMPv4 frames.
    pub generated_frames: u32,
    /// UMEM headroom in addition to the kernel's fixed 256 bytes; absent
    /// means 0.
    #[serde(default)]
    pub headroom: u32,
}

/// Entry counts of the four AF_XDP rings of one socket.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AfXdpRingsV1 {
    pub fill: u32,
    pub rx: u32,
    pub tx: u32,
    pub completion: u32,
}
