use std::{fmt, mem::size_of, net::Ipv4Addr, num::ParseIntError};

use ruster_core::{
    port_free_bitmap_words, validate_firewall_rules, ArpHoldPolicy, ArpHoldPolicyError,
    ArpHoldSlot, ArpPolicy, DirectoryBucket, DirectoryNode, DynamicNeighborSlot, FirewallAction,
    FirewallConfigError, FirewallInterface, FirewallIpv4Prefix, FirewallIpv4PrefixError,
    FirewallPolicy, FirewallPolicyError, FirewallPortRange, FirewallPortRangeError,
    FirewallProtocol, FirewallRule, FirewallRuleId, FirewallStateSlot, ForwardingSnapshot,
    Icmpv4ErrorActionSlot, Icmpv4ErrorKind, Icmpv4ErrorPolicy, Icmpv4ErrorPolicyError,
    Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address, Ipv4FragmentEntrySlot,
    Ipv4FragmentHeldSlot, Ipv4FragmentHostSlot, Ipv4FragmentSlot, Ipv4FragmentTombstoneSlot,
    Ipv4FragmentTrackingPolicy, Ipv4FragmentTrackingPolicyError, Ipv4FragmentationPolicy,
    Ipv4FragmentationPolicyError, Ipv4OriginPolicy, Ipv4OriginPolicyError, LocalIpv4Binding,
    MacAddress, Nat44Filtering, Nat44HostLink, Nat44IcmpConfig, Nat44IcmpConfigError,
    Nat44IcmpPolicy, Nat44IcmpPolicyError, Nat44Icmpv4ErrorPolicy, Nat44TcpConfig,
    Nat44TcpConfigError, Nat44TcpMappingSlot, Nat44TcpPolicy, Nat44TcpPolicyError,
    Nat44TcpSessionSlot, Nat44TcpSynHoldSlot, Nat44UdpConfig, Nat44UdpConfigError,
    Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpPolicyError, Neighbor,
    PortOwnerSlot, ResolutionActionSlot, ResolutionFailureHoldSlot, ResolutionPolicy,
    ResolutionPolicyError, ResolutionStateSlot, Route, RouteError, SnapshotError, SourceValidation,
    SourceValidationBinding,
};

use ruster_io_xdp::native_profile::{
    BindMode, RingConfig, UmemConfig, ValidatedBindFlags, SUPPORTED_ALIGNED_CHUNK_SIZES, XDP_COPY,
    XDP_PACKET_HEADROOM, XDP_USE_NEED_WAKEUP, XDP_ZEROCOPY,
};

use crate::{
    AfPacketPortV1, AfPacketV1, AfXdpModeV1, AfXdpPortV1, BackendKindV1, BackendV1, ConfigV1,
    ExistingXdpProgramV1, ExitProtectionV1, FirewallActionV1, FirewallProtocolV1, HealthV1,
    Nat44FilteringV1, Nat44Icmpv4ErrorsV1, Nat44TcpInboundRstV1, ReloadStateV1, SourcePath,
    VersionedConfig, WatchV1, XdpAttachModeV1,
};

/// Caller-selected cold-path bounds for runtime storage requested by V1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationLimits {
    /// Largest slot count of any one runtime table, directory bucket array,
    /// or NAT44 port owner table (`CAPACITY_LIMIT_EXCEEDED`).
    pub max_slots_per_table: u32,
    /// Largest slot count of a table whose every slot carries a quoted
    /// original IPv4 datagram (up to 548 bytes; `CAPACITY_LIMIT_EXCEEDED`;
    /// also bounded by `max_slots_per_table`):
    /// `resolution.capacity.failure-holds` and
    /// `icmpv4-errors.capacity.actions`.
    pub max_quote_slots_per_table: u32,
    /// Largest preallocated runtime storage in bytes, summed over every
    /// table (`RUNTIME_STORAGE_BYTES_EXCEEDED`).
    pub max_runtime_bytes: usize,
}

/// Storage bounds of a production router (`ruster run`, and `ruster
/// validate`/`plan` of a document whose `backend.kind` is `af-xdp`).
/// Coordinator defaults, not owner decisions (H3).
///
/// - `max_slots_per_table` = 2^16 for every table that is not a quote
///   table: the resolution states, actions, and dynamic neighbors, the
///   ICMPv4 error states, and the NAT44 and firewall tables. No per-packet
///   path scans any of them. Resolution states, dynamic neighbors, and
///   failure holds are found through keyed chains of at most
///   [`ruster_core::RESOLUTION_INDEX_CHAIN_LIMIT`] slots, and a free or
///   reusable slot through a bitmap (H4b). The ICMPv4 error states are
///   searched only up to the occupied prefix, at most one state per egress
///   interface in use ([`crate::MAX_INTERFACES`]). NAT44 finds a reusable
///   mapping, peer, or session and a free public port in O(1)
///   (activity-ordered slot lists and a free-port bitmap, H4a). The
///   firewall probe is keyed SipHash with occupancy capped near 75%, so
///   only its amortized expiry sweep is linear. Home NAT needs many
///   sessions, and 2^16 also equals the largest NAT44 port pool
///   (1..=65535).
/// - `max_quote_slots_per_table` = 4096 (2^12) for the two tables whose
///   slots each hold a quoted datagram: resolution failure holds (656
///   bytes per slot) and ICMPv4 error actions (592 bytes). The bound is
///   memory, not cost: at 2^16 these two tables alone would need 78.0 MiB.
///   4096 equals [`crate::MAX_NEIGHBORS`].
/// - `max_runtime_bytes` = 64 MiB, the simulator's value. Every table at its
///   limit (with the widest port pool) needs 53592256 bytes (51.11 MiB)
///   with the current slot sizes, so the per-table limits bind and this
///   bound only fails closed if a slot type grows. The storage is ordinary
///   heap (not memlocked), allocated once at startup.
pub const PRODUCTION_VALIDATION_LIMITS: ValidationLimits = ValidationLimits {
    max_slots_per_table: 1 << 16,
    max_quote_slots_per_table: 1 << 12,
    max_runtime_bytes: 64 << 20,
};

/// Stable, value-free semantic rejection reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValidationCode {
    InvalidSchemaVersion,
    ListTooLong,
    TextTooLarge,
    EmptyInterfaceName,
    EmptyDeviceName,
    /// An interface `name` is longer than [`MAX_INTERFACE_LABEL_BYTES`], uses
    /// a byte outside `[A-Za-z0-9._-]`, is `.`/`..`, or starts with `-`.
    InvalidInterfaceName,
    /// A `device` is longer than [`MAX_INTERFACE_LABEL_BYTES`], uses a byte
    /// outside `[A-Za-z0-9._-]`, is `.`/`..`, or starts with `-`.
    InvalidDeviceName,
    DuplicateInterfaceId,
    DuplicateInterfaceName,
    DuplicateDeviceName,
    /// An interface `mtu` outside 68 ([`ruster_core::IPV4_MIN_MTU`], RFC
    /// 791) to 65535.
    InterfaceMtuOutOfRange,
    /// `source-validation-allow-default` on an interface whose
    /// `source-validation` is not `loose` (URPF): strict already accepts a
    /// default route out of the ingress, and off checks nothing.
    SourceValidationAllowDefaultNotLoose,
    InvalidMac,
    NonCanonicalMac,
    MacNotUnicast,
    InvalidIpv4,
    NonCanonicalIpv4,
    InvalidIpv4Prefix,
    NonCanonicalIpv4Prefix,
    AddressNotHost,
    UnknownInterface,
    DuplicateLocalAddress,
    DuplicateInterfaceAddress,
    Route(RouteError),
    DuplicateRoute,
    GatewayNotHost,
    GatewayNotOnLink,
    DuplicateNeighbor,
    NeighborNotHost,
    NeighborNotOnLink,
    Forwarding(SnapshotError),
    Ipv4Origin(Ipv4OriginPolicyError),
    ResolutionPolicy(ResolutionPolicyError),
    Icmpv4ErrorPolicy(Icmpv4ErrorPolicyError),
    /// `[fragmentation] max-fragments-per-datagram` outside 2..=1365.
    FragmentationPolicy(Ipv4FragmentationPolicyError),
    /// `[fragmentation] datagrams` is 0 while fragmentation is enabled.
    FragmentationDatagramsZero,
    /// Fragmentation is enabled but a backend port could never send a
    /// fragment set: fewer than 4 AF_XDP `generated-frames` or AF_PACKET TX
    /// ring frames (two fragments plus the router reserve of two).
    FragmentationBackendRoomTooSmall,
    /// `[tick] generated-fragments` is 0 (no fragment could ever be sent).
    TickGeneratedFragmentsZero,
    /// `[fragment-tracking] timeout-ms` outside 100..=60000,
    /// `entries-per-host` 0, or `ingress-share-percent` outside 1..=100
    /// (NAT-FRAG).
    FragmentTrackingPolicy(Ipv4FragmentTrackingPolicyError),
    /// `[fragment-tracking] entries` is 0 in `associate` mode (NAT-FRAG).
    FragmentTrackingEntriesZero,
    /// `[resolution.hold] per-neighbor` outside 1..=64 or `per-host` 0
    /// (ARP-HOLD).
    ArpHoldPolicy(ArpHoldPolicyError),
    /// `[resolution.hold] packets` is 0 (ARP-HOLD; `enabled = false` is the
    /// switch).
    ArpHoldPacketsZero,
    /// `[resolution.hold] per-neighbor`, `per-host`, or `per-ingress` is
    /// above `packets` (ARP-HOLD; a bound the table can never reach).
    ArpHoldBoundAbovePackets,
    /// `[resolution.hold] enabled = true` with `[fragmentation] enabled =
    /// false`: a replay leaves through the fragmentation slots, so nothing
    /// could be held (ARP-HOLD).
    ArpHoldWithoutFragmentation,
    /// `[arp] announce-count` outside 1..=10, `announce-interval-ms`
    /// outside 1000..=3600000, or `announce-min-interval-ms` above 3600000
    /// or shorter than one sequence (ARP-034).
    ArpAnnouncePolicy(ruster_core::ArpAnnouncePolicyError),
    /// `[tick] generated-arp = 0` with `[arp] announce` or
    /// `conflict-defense` on: an owed Announcement could never be sent
    /// (ARP-034; it would also keep the idle loop from waiting).
    ArpAnnounceWithoutGeneratedArp,
    InvalidAllocatorSeed,
    NonCanonicalAllocatorSeed,
    Nat44RealmWithoutProtocol,
    Nat44UdpPolicy(Nat44UdpPolicyError),
    Nat44UdpConfig(Nat44UdpConfigError),
    Nat44TcpPolicy(Nat44TcpPolicyError),
    Nat44TcpConfig(Nat44TcpConfigError),
    /// `[nat44.icmp]` (N5): idle timeout below the RFC 5508 REQ-2 floor or
    /// above the maximum, or `address-and-port-dependent` filtering.
    Nat44IcmpPolicy(Nat44IcmpPolicyError),
    /// `[nat44.icmp]` realm or identifier pool (0 in the pool, reversed).
    Nat44IcmpConfig(Nat44IcmpConfigError),
    /// A `tcp`/`udp` firewall rule without `source-ports` or
    /// `destination-ports`.
    FirewallRulePortsRequired,
    /// An `icmp` firewall rule with `source-ports` or `destination-ports`
    /// (a query has no ports).
    FirewallIcmpRulePorts,
    FirewallPrefix(FirewallIpv4PrefixError),
    FirewallPortRange(FirewallPortRangeError),
    FirewallPolicy(FirewallPolicyError),
    FirewallRules(FirewallConfigError),
    CapacityLimitExceeded,
    CapacityNotRepresentable,
    CapacityArithmeticOverflow,
    RuntimeStorageBytesExceeded,
    /// `[[backend.ports]]` is non-empty but `backend.kind` is not `af-xdp`.
    BackendPortsWithoutAfXdp,
    /// `backend.kind = "af-xdp"` with no `[[backend.ports]]`.
    BackendNoPorts,
    /// A configured interface has no `[[backend.ports]]` entry.
    BackendInterfaceUnbound,
    /// Two ports bind the same (device, queue).
    BackendDuplicateQueue,
    /// A second queue of one interface; M2 binds one queue per interface.
    BackendMultipleQueuesPerInterface,
    /// `queue` is above [`MAX_AF_XDP_QUEUE_ID`].
    BackendQueueOutOfRange,
    /// `need-wakeup = false`; the native profile requires
    /// `XDP_USE_NEED_WAKEUP`.
    BackendNeedWakeupRequired,
    /// `mode = "zero-copy"` or `"auto"` with `xdp-attach = "generic"`:
    /// generic (skb) XDP always copies, so only `mode = "copy"` states what
    /// the socket will do.
    BackendModeRequiresNativeAttach,
    /// A ring entry count is not a power of two.
    BackendRingNotPowerOfTwo,
    /// A ring entry count is outside
    /// [`MIN_AF_XDP_RING_ENTRIES`]..=[`MAX_AF_XDP_RING_ENTRIES`].
    BackendRingOutOfRange,
    /// The Completion ring is smaller than the TX ring.
    BackendCompletionRingTooSmall,
    /// `frame-size` is not one of the reviewed aligned chunk sizes.
    BackendFrameSizeUnsupported,
    /// `headroom` leaves less than [`MIN_AF_XDP_VISIBLE_FRAME_BYTES`] of
    /// packet space after the kernel's fixed headroom.
    BackendHeadroomTooLarge,
    /// `generated-frames` is zero.
    BackendGeneratedFramesZero,
    /// `frame-count` is below `fill + tx + generated-frames`.
    BackendFrameCountTooSmall,
    /// `icmpv4-errors.capacity.states` is below the number of interfaces
    /// plus one (twice the number of interfaces plus one while
    /// Fragmentation Needed is generated, MTU1) while the TCP NAT can send
    /// delayed Port Unreachable errors (`unsolicited-syn-icmp` on and
    /// `unsolicited-syn-holds` above 0). Limiter states are keyed by egress
    /// and class, and Port Unreachable has its own class on the outside
    /// egress (Fragmentation Needed its own on every egress), so up to
    /// interfaces + 1 (2 x interfaces + 1) states can be in use at once. With fewer, a SYN flood could keep the
    /// Port Unreachable state alive and leave another egress `StateFull`,
    /// which would silently suppress its Time Exceeded and Destination
    /// Unreachable errors.
    Icmpv4ErrorStatesTooFewForPortUnreachable,
    /// `icmpv4-errors.capacity.states` is below twice the number of
    /// interfaces while Fragmentation Needed is generated
    /// (`generate.fragmentation-needed`, MTU1). Fragmentation Needed has its
    /// own limiter class on every egress besides the class of the other
    /// errors, so up to two states per interface can be in use at once.
    /// With fewer, a flood of one class could leave another egress
    /// `StateFull` and silently suppress its errors (Path MTU Discovery
    /// included).
    Icmpv4ErrorStatesTooFewForFragmentationNeeded,
    /// One socket's UMEM exceeds [`MAX_AF_XDP_UMEM_BYTES_PER_PORT`].
    BackendUmemTooLarge,
    /// The UMEM of all sockets exceeds [`MAX_AF_XDP_UMEM_BYTES`].
    BackendTotalUmemTooLarge,
    /// The native AF_XDP profile rejected a geometry the configuration
    /// checks accepted. Unreachable unless the two drift apart.
    BackendNativeProfile,
    /// `[backend.af-packet]` is present but `backend.kind` is not
    /// `af-packet`.
    BackendAfPacketWithoutKind,
    /// Two `[[backend.af-packet.ports]]` bind the same interface.
    BackendDuplicateInterface,
    /// `max-frame-len` is outside
    /// [`MIN_AF_PACKET_FRAME_LEN`]..=[`MAX_AF_PACKET_FRAME_LEN`].
    BackendMaxFrameLenOutOfRange,
    /// A ring `block-size` is not a power of two within
    /// [`MIN_AF_PACKET_BLOCK_SIZE`]..=[`MAX_AF_PACKET_BLOCK_SIZE`].
    BackendBlockSizeInvalid,
    /// A ring `block-size` cannot hold one maximum frame with its TPACKET
    /// headers (RX: block descriptor, packet header, and frame; RX and TX:
    /// the frame slot the geometry derives from `max-frame-len`).
    BackendBlockTooSmall,
    /// A ring `block-count` is outside 1..=[`MAX_AF_PACKET_BLOCK_COUNT`].
    BackendBlockCountOutOfRange,
    /// The RX `retire-timeout-ms` is outside
    /// 1..=[`MAX_AF_PACKET_RETIRE_TIMEOUT_MS`].
    BackendRetireTimeoutOutOfRange,
    /// One port's RX plus TX ring exceeds
    /// [`MAX_AF_PACKET_RING_BYTES_PER_PORT`].
    BackendRingTooLarge,
    /// The rings of all ports exceed [`MAX_AF_PACKET_RING_BYTES`].
    BackendTotalRingTooLarge,
    /// A `[health]` key outside its range (OPS-LOG; `limit` is the bound
    /// it crossed).
    HealthValueOutOfRange,
    /// `[health] tx-stall-fatal-ms` is neither 0 nor at least
    /// `tx-stall-warn-ms`.
    HealthFatalBelowWarning,
    /// A `[watch]` interval outside its range (OPS-LOG; `limit` is the
    /// bound it crossed).
    WatchIntervalOutOfRange,
}

impl ValidationCode {
    /// Stable SCREAMING_SNAKE_CASE code for machine-readable output.
    ///
    /// Exhaustive, so a new variant fails to compile until it has a code.
    /// Nested detail is collapsed to the outer variant.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidSchemaVersion => "INVALID_SCHEMA_VERSION",
            Self::ListTooLong => "LIST_TOO_LONG",
            Self::TextTooLarge => "TEXT_TOO_LARGE",
            Self::EmptyInterfaceName => "EMPTY_INTERFACE_NAME",
            Self::EmptyDeviceName => "EMPTY_DEVICE_NAME",
            Self::InvalidInterfaceName => "INVALID_INTERFACE_NAME",
            Self::InvalidDeviceName => "INVALID_DEVICE_NAME",
            Self::DuplicateInterfaceId => "DUPLICATE_INTERFACE_ID",
            Self::DuplicateInterfaceName => "DUPLICATE_INTERFACE_NAME",
            Self::DuplicateDeviceName => "DUPLICATE_DEVICE_NAME",
            Self::InterfaceMtuOutOfRange => "INTERFACE_MTU_OUT_OF_RANGE",
            Self::SourceValidationAllowDefaultNotLoose => {
                "SOURCE_VALIDATION_ALLOW_DEFAULT_NOT_LOOSE"
            }
            Self::InvalidMac => "INVALID_MAC",
            Self::NonCanonicalMac => "NON_CANONICAL_MAC",
            Self::MacNotUnicast => "MAC_NOT_UNICAST",
            Self::InvalidIpv4 => "INVALID_IPV4",
            Self::NonCanonicalIpv4 => "NON_CANONICAL_IPV4",
            Self::InvalidIpv4Prefix => "INVALID_IPV4_PREFIX",
            Self::NonCanonicalIpv4Prefix => "NON_CANONICAL_IPV4_PREFIX",
            Self::AddressNotHost => "ADDRESS_NOT_HOST",
            Self::UnknownInterface => "UNKNOWN_INTERFACE",
            Self::DuplicateLocalAddress => "DUPLICATE_LOCAL_ADDRESS",
            Self::DuplicateInterfaceAddress => "DUPLICATE_INTERFACE_ADDRESS",
            Self::Route(_) => "ROUTE",
            Self::DuplicateRoute => "DUPLICATE_ROUTE",
            Self::GatewayNotHost => "GATEWAY_NOT_HOST",
            Self::GatewayNotOnLink => "GATEWAY_NOT_ON_LINK",
            Self::DuplicateNeighbor => "DUPLICATE_NEIGHBOR",
            Self::NeighborNotHost => "NEIGHBOR_NOT_HOST",
            Self::NeighborNotOnLink => "NEIGHBOR_NOT_ON_LINK",
            Self::Forwarding(_) => "FORWARDING",
            Self::Ipv4Origin(_) => "IPV4_ORIGIN",
            Self::ResolutionPolicy(_) => "RESOLUTION_POLICY",
            Self::Icmpv4ErrorPolicy(_) => "ICMPV4_ERROR_POLICY",
            Self::FragmentationPolicy(_) => "FRAGMENTATION_POLICY",
            Self::FragmentationDatagramsZero => "FRAGMENTATION_DATAGRAMS_ZERO",
            Self::FragmentationBackendRoomTooSmall => "FRAGMENTATION_BACKEND_ROOM_TOO_SMALL",
            Self::TickGeneratedFragmentsZero => "TICK_GENERATED_FRAGMENTS_ZERO",
            Self::FragmentTrackingPolicy(_) => "FRAGMENT_TRACKING_POLICY",
            Self::FragmentTrackingEntriesZero => "FRAGMENT_TRACKING_ENTRIES_ZERO",
            Self::ArpHoldPolicy(_) => "ARP_HOLD_POLICY",
            Self::ArpHoldPacketsZero => "ARP_HOLD_PACKETS_ZERO",
            Self::ArpHoldBoundAbovePackets => "ARP_HOLD_BOUND_ABOVE_PACKETS",
            Self::ArpHoldWithoutFragmentation => "ARP_HOLD_WITHOUT_FRAGMENTATION",
            Self::ArpAnnouncePolicy(_) => "ARP_ANNOUNCE_POLICY",
            Self::ArpAnnounceWithoutGeneratedArp => "ARP_ANNOUNCE_WITHOUT_GENERATED_ARP",
            Self::InvalidAllocatorSeed => "INVALID_ALLOCATOR_SEED",
            Self::NonCanonicalAllocatorSeed => "NON_CANONICAL_ALLOCATOR_SEED",
            Self::Nat44RealmWithoutProtocol => "NAT44_REALM_WITHOUT_PROTOCOL",
            Self::Nat44UdpPolicy(_) => "NAT44_UDP_POLICY",
            Self::Nat44UdpConfig(_) => "NAT44_UDP_CONFIG",
            Self::Nat44TcpPolicy(_) => "NAT44_TCP_POLICY",
            Self::Nat44TcpConfig(_) => "NAT44_TCP_CONFIG",
            Self::Nat44IcmpPolicy(_) => "NAT44_ICMP_POLICY",
            Self::Nat44IcmpConfig(_) => "NAT44_ICMP_CONFIG",
            Self::FirewallRulePortsRequired => "FIREWALL_RULE_PORTS_REQUIRED",
            Self::FirewallIcmpRulePorts => "FIREWALL_ICMP_RULE_PORTS",
            Self::FirewallPrefix(_) => "FIREWALL_PREFIX",
            Self::FirewallPortRange(_) => "FIREWALL_PORT_RANGE",
            Self::FirewallPolicy(_) => "FIREWALL_POLICY",
            Self::FirewallRules(_) => "FIREWALL_RULES",
            Self::CapacityLimitExceeded => "CAPACITY_LIMIT_EXCEEDED",
            Self::CapacityNotRepresentable => "CAPACITY_NOT_REPRESENTABLE",
            Self::CapacityArithmeticOverflow => "CAPACITY_ARITHMETIC_OVERFLOW",
            Self::RuntimeStorageBytesExceeded => "RUNTIME_STORAGE_BYTES_EXCEEDED",
            Self::BackendPortsWithoutAfXdp => "BACKEND_PORTS_WITHOUT_AF_XDP",
            Self::BackendNoPorts => "BACKEND_NO_PORTS",
            Self::BackendInterfaceUnbound => "BACKEND_INTERFACE_UNBOUND",
            Self::BackendDuplicateQueue => "BACKEND_DUPLICATE_QUEUE",
            Self::BackendMultipleQueuesPerInterface => "BACKEND_MULTIPLE_QUEUES_PER_INTERFACE",
            Self::BackendQueueOutOfRange => "BACKEND_QUEUE_OUT_OF_RANGE",
            Self::BackendNeedWakeupRequired => "BACKEND_NEED_WAKEUP_REQUIRED",
            Self::BackendModeRequiresNativeAttach => "BACKEND_MODE_REQUIRES_NATIVE_ATTACH",
            Self::BackendRingNotPowerOfTwo => "BACKEND_RING_NOT_POWER_OF_TWO",
            Self::BackendRingOutOfRange => "BACKEND_RING_OUT_OF_RANGE",
            Self::BackendCompletionRingTooSmall => "BACKEND_COMPLETION_RING_TOO_SMALL",
            Self::BackendFrameSizeUnsupported => "BACKEND_FRAME_SIZE_UNSUPPORTED",
            Self::BackendHeadroomTooLarge => "BACKEND_HEADROOM_TOO_LARGE",
            Self::BackendGeneratedFramesZero => "BACKEND_GENERATED_FRAMES_ZERO",
            Self::BackendFrameCountTooSmall => "BACKEND_FRAME_COUNT_TOO_SMALL",
            Self::Icmpv4ErrorStatesTooFewForPortUnreachable => {
                "ICMPV4_ERROR_STATES_TOO_FEW_FOR_PORT_UNREACHABLE"
            }
            Self::Icmpv4ErrorStatesTooFewForFragmentationNeeded => {
                "ICMPV4_ERROR_STATES_TOO_FEW_FOR_FRAGMENTATION_NEEDED"
            }
            Self::BackendUmemTooLarge => "BACKEND_UMEM_TOO_LARGE",
            Self::BackendTotalUmemTooLarge => "BACKEND_TOTAL_UMEM_TOO_LARGE",
            Self::BackendNativeProfile => "BACKEND_NATIVE_PROFILE",
            Self::BackendAfPacketWithoutKind => "BACKEND_AF_PACKET_WITHOUT_KIND",
            Self::BackendDuplicateInterface => "BACKEND_DUPLICATE_INTERFACE",
            Self::BackendMaxFrameLenOutOfRange => "BACKEND_MAX_FRAME_LEN_OUT_OF_RANGE",
            Self::BackendBlockSizeInvalid => "BACKEND_BLOCK_SIZE_INVALID",
            Self::BackendBlockTooSmall => "BACKEND_BLOCK_TOO_SMALL",
            Self::BackendBlockCountOutOfRange => "BACKEND_BLOCK_COUNT_OUT_OF_RANGE",
            Self::BackendRetireTimeoutOutOfRange => "BACKEND_RETIRE_TIMEOUT_OUT_OF_RANGE",
            Self::BackendRingTooLarge => "BACKEND_RING_TOO_LARGE",
            Self::BackendTotalRingTooLarge => "BACKEND_TOTAL_RING_TOO_LARGE",
            Self::HealthValueOutOfRange => "HEALTH_VALUE_OUT_OF_RANGE",
            Self::HealthFatalBelowWarning => "HEALTH_FATAL_BELOW_WARNING",
            Self::WatchIntervalOutOfRange => "WATCH_INTERVAL_OUT_OF_RANGE",
        }
    }
}

/// A semantic error that never retains source values.
#[derive(Clone, Eq, PartialEq)]
pub struct ValidationError {
    code: ValidationCode,
    path: SourcePath,
    limit: Option<u64>,
    actual: Option<u64>,
}

impl ValidationError {
    fn new(code: ValidationCode, path: SourcePath) -> Self {
        Self {
            code,
            path,
            limit: None,
            actual: None,
        }
    }

    fn bounded(code: ValidationCode, path: SourcePath, limit: u64, actual: u64) -> Self {
        Self {
            code,
            path,
            limit: Some(limit),
            actual: Some(actual),
        }
    }

    #[must_use]
    pub const fn code(&self) -> ValidationCode {
        self.code
    }

    #[must_use]
    pub const fn path(&self) -> &SourcePath {
        &self.path
    }

    #[must_use]
    pub const fn limit(&self) -> Option<u64> {
        self.limit
    }

    #[must_use]
    pub const fn actual(&self) -> Option<u64> {
        self.actual
    }
}

impl fmt::Debug for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidationError")
            .field("code", &self.code)
            .field("path", &self.path)
            .field("limit", &self.limit)
            .field("actual", &self.actual)
            .finish()
    }
}

/// Canonical control-plane identity for one forwarding interface.
#[derive(Clone, Eq, PartialEq)]
pub struct InterfaceBindingV1 {
    id: IfId,
    name: Box<str>,
    device: Box<str>,
    mac: MacAddress,
    mtu: u16,
}

impl InterfaceBindingV1 {
    #[must_use]
    pub const fn id(&self) -> IfId {
        self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn device(&self) -> &str {
        &self.device
    }

    #[must_use]
    pub const fn mac(&self) -> MacAddress {
        self.mac
    }

    /// The IPv4 MTU of the interface (`mtu`, default
    /// [`ruster_core::ETHERNET_DEFAULT_MTU`]).
    #[must_use]
    pub const fn mtu(&self) -> u16 {
        self.mtu
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionStorageShapeV1 {
    pub states: u32,
    pub actions: u32,
    pub dynamic_neighbors: u32,
    pub failure_holds: u32,
    /// One RFC 5227 announcement slot per interface (ARP-033,
    /// [`ruster_core::ArpAnnounceSlot`], 48 bytes each), whether `[arp]
    /// announce` is on or off, so the switch is reloadable.
    pub announce_slots: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Icmpv4ErrorStorageShapeV1 {
    pub states: u32,
    pub actions: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Nat44UdpStorageShapeV1 {
    pub mappings: u32,
    pub peers: u32,
    pub mapping_buckets: u32,
    pub mapping_nodes: u32,
    pub peer_buckets: u32,
    pub peer_nodes: u32,
    pub port_owners: u32,
    /// Host slots of the per-host accounting (N3, N6): `mappings` with a
    /// nonzero `mappings-per-host` or `peers-per-host`, else 0. Each comes
    /// with a per-mapping link and a host directory node, and the host
    /// directory has `mapping_buckets` buckets; `required_bytes` counts all
    /// of them.
    pub hosts: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Nat44TcpStorageShapeV1 {
    pub mappings: u32,
    pub sessions: u32,
    pub mapping_buckets: u32,
    pub mapping_nodes: u32,
    /// Dimensions of both the exact session directory and the
    /// remote-address directory over the same session slots, which TCP
    /// address-dependent filtering uses. `required_bytes` counts both.
    pub session_buckets: u32,
    pub session_nodes: u32,
    pub port_owners: u32,
    /// Slots of the unsolicited-SYN hold table (RFC 5382 REQ-4), each with
    /// a quoted datagram.
    pub unsolicited_syn_holds: u32,
    /// Host slots of the per-host mapping accounting (N3): `mappings` with
    /// a nonzero `mappings-per-host`, else 0, as for UDP.
    pub hosts: u32,
    /// Host slots of the per-host session accounting (N6): `sessions` with
    /// a nonzero `sessions-per-host`, else 0. Each comes with a per-session
    /// link and a host directory node, and that directory has
    /// `session_buckets` buckets; `required_bytes` counts all of them.
    pub session_hosts: u32,
}

/// Storage of the ICMP query NAT (N5): the datagram mapping engine's
/// tables, with one owner slot per public identifier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Nat44IcmpStorageShapeV1 {
    pub mappings: u32,
    pub peers: u32,
    pub mapping_buckets: u32,
    pub mapping_nodes: u32,
    pub peer_buckets: u32,
    pub peer_nodes: u32,
    /// One owner slot per identifier of the pool (`port_owners` of the
    /// engine), plus its free bitmap.
    pub identifier_owners: u32,
    /// Host slots of the per-host accounting: `mappings` with a nonzero
    /// `mappings-per-host` or `peers-per-host`, else 0.
    pub hosts: u32,
}

/// Storage of IPv4 fragmentation (MTU2 part B): `datagrams` slots of
/// `slot_bytes` bytes (an Ethernet header plus the largest interface MTU)
/// and one [`Ipv4FragmentSlot`] each.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FragmentationStorageShapeV1 {
    pub datagrams: u32,
    pub slot_bytes: u32,
}

/// Storage of IPv4 fragment association (NAT-FRAG): `entries` entry and
/// host slots with two keyed directories of `buckets` buckets and `entries`
/// nodes each, and `held` held-fragment records of `held_slot_bytes` bytes
/// (a fragmentation slot's size; 0 held without fragmentation).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FragmentTrackingStorageShapeV1 {
    pub entries: u32,
    pub buckets: u32,
    pub held: u32,
    pub held_slot_bytes: u32,
}

/// Storage of the ARP hold table (ARP-HOLD): `packets` hold records of
/// `slot_bytes` bytes each (a fragmentation slot's size).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArpHoldStorageShapeV1 {
    pub packets: u32,
    pub slot_bytes: u32,
}

/// Complete caller-owned runtime storage requested by one V1 candidate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeStorageShapeV1 {
    pub resolution: Option<ResolutionStorageShapeV1>,
    pub icmpv4_errors: Option<Icmpv4ErrorStorageShapeV1>,
    pub nat44_udp: Option<Nat44UdpStorageShapeV1>,
    pub nat44_tcp: Option<Nat44TcpStorageShapeV1>,
    /// `None` without `[nat44.icmp]`.
    pub nat44_icmp: Option<Nat44IcmpStorageShapeV1>,
    pub firewall_states: Option<u32>,
    /// `None` with `[fragmentation] enabled = false`.
    pub fragmentation: Option<FragmentationStorageShapeV1>,
    /// `None` with `[fragment-tracking] mode = "refuse"`.
    pub fragment_tracking: Option<FragmentTrackingStorageShapeV1>,
    /// `None` with `[resolution.hold] enabled = false`, without
    /// `[resolution]`, or without fragmentation (ARP-HOLD).
    pub arp_hold: Option<ArpHoldStorageShapeV1>,
    pub required_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TickBudgetsV1 {
    pub rx: u32,
    pub resolution_timer_scans: u32,
    pub failure_dispatch_scans: u32,
    pub generated_arp: u32,
    pub generated_icmpv4: u32,
    /// Fragment frames per tick (MTU2 part B); 0 only when `[tick]` is
    /// absent, like every other budget.
    pub generated_fragments: u32,
}

/// Validated `[fragmentation]` (defaults when absent).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedFragmentationV1 {
    policy: Ipv4FragmentationPolicy,
    storage: Option<FragmentationStorageShapeV1>,
}

impl ValidatedFragmentationV1 {
    #[must_use]
    pub const fn policy(&self) -> Ipv4FragmentationPolicy {
        self.policy
    }

    /// `None` when fragmentation is off (no slot storage).
    #[must_use]
    pub const fn storage(&self) -> Option<FragmentationStorageShapeV1> {
        self.storage
    }
}

/// Validated `[fragment-tracking]` (defaults when absent, NAT-FRAG).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedFragmentTrackingV1 {
    policy: Option<Ipv4FragmentTrackingPolicy>,
    storage: Option<FragmentTrackingStorageShapeV1>,
}

impl ValidatedFragmentTrackingV1 {
    /// `None` in `refuse` mode (every fragment refused, no storage).
    #[must_use]
    pub const fn policy(&self) -> Option<Ipv4FragmentTrackingPolicy> {
        self.policy
    }

    /// `None` in `refuse` mode.
    #[must_use]
    pub const fn storage(&self) -> Option<FragmentTrackingStorageShapeV1> {
        self.storage
    }
}

/// Validated `[resolution.hold]` (ARP-HOLD; defaults when absent).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedArpHoldV1 {
    policy: Option<ArpHoldPolicy>,
    storage: Option<ArpHoldStorageShapeV1>,
}

impl ValidatedArpHoldV1 {
    /// `None` when holding is off (switched off, no `[resolution]`, or no
    /// fragmentation to replay through).
    #[must_use]
    pub const fn policy(&self) -> Option<ArpHoldPolicy> {
        self.policy
    }

    /// `None` when holding is off.
    #[must_use]
    pub const fn storage(&self) -> Option<ArpHoldStorageShapeV1> {
        self.storage
    }
}

pub struct ValidatedResolutionV1 {
    policy: ResolutionPolicy,
    storage: ResolutionStorageShapeV1,
}

impl ValidatedResolutionV1 {
    #[must_use]
    pub const fn policy(&self) -> ResolutionPolicy {
        self.policy
    }

    #[must_use]
    pub const fn storage(&self) -> ResolutionStorageShapeV1 {
        self.storage
    }
}

pub struct ValidatedIcmpv4ErrorV1 {
    policy: Icmpv4ErrorPolicy,
    storage: Icmpv4ErrorStorageShapeV1,
}

impl ValidatedIcmpv4ErrorV1 {
    #[must_use]
    pub const fn policy(&self) -> Icmpv4ErrorPolicy {
        self.policy
    }

    #[must_use]
    pub const fn storage(&self) -> Icmpv4ErrorStorageShapeV1 {
        self.storage
    }
}

pub struct ValidatedNat44UdpV1 {
    inside: IfId,
    outside: IfId,
    public_address: Ipv4Address,
    first_port: u16,
    last_port: u16,
    policy: Nat44UdpPolicy,
    storage: Nat44UdpStorageShapeV1,
}

impl ValidatedNat44UdpV1 {
    #[must_use]
    pub const fn inside(&self) -> IfId {
        self.inside
    }

    #[must_use]
    pub const fn outside(&self) -> IfId {
        self.outside
    }

    #[must_use]
    pub const fn public_address(&self) -> Ipv4Address {
        self.public_address
    }

    #[must_use]
    pub const fn first_port(&self) -> u16 {
        self.first_port
    }

    #[must_use]
    pub const fn last_port(&self) -> u16 {
        self.last_port
    }

    #[must_use]
    pub const fn policy(&self) -> Nat44UdpPolicy {
        self.policy
    }

    #[must_use]
    pub const fn storage(&self) -> Nat44UdpStorageShapeV1 {
        self.storage
    }
}

pub struct ValidatedNat44TcpV1 {
    inside: IfId,
    outside: IfId,
    public_address: Ipv4Address,
    first_port: u16,
    last_port: u16,
    policy: Nat44TcpPolicy,
    storage: Nat44TcpStorageShapeV1,
}

impl ValidatedNat44TcpV1 {
    #[must_use]
    pub const fn inside(&self) -> IfId {
        self.inside
    }

    #[must_use]
    pub const fn outside(&self) -> IfId {
        self.outside
    }

    #[must_use]
    pub const fn public_address(&self) -> Ipv4Address {
        self.public_address
    }

    #[must_use]
    pub const fn first_port(&self) -> u16 {
        self.first_port
    }

    #[must_use]
    pub const fn last_port(&self) -> u16 {
        self.last_port
    }

    #[must_use]
    pub const fn policy(&self) -> Nat44TcpPolicy {
        self.policy
    }

    #[must_use]
    pub const fn storage(&self) -> Nat44TcpStorageShapeV1 {
        self.storage
    }
}

/// Validated `[nat44.icmp]` (N5) on the shared realm.
pub struct ValidatedNat44IcmpV1 {
    inside: IfId,
    outside: IfId,
    public_address: Ipv4Address,
    first_identifier: u16,
    last_identifier: u16,
    policy: Nat44IcmpPolicy,
    storage: Nat44IcmpStorageShapeV1,
}

impl ValidatedNat44IcmpV1 {
    #[must_use]
    pub const fn inside(&self) -> IfId {
        self.inside
    }

    #[must_use]
    pub const fn outside(&self) -> IfId {
        self.outside
    }

    #[must_use]
    pub const fn public_address(&self) -> Ipv4Address {
        self.public_address
    }

    #[must_use]
    pub const fn first_identifier(&self) -> u16 {
        self.first_identifier
    }

    #[must_use]
    pub const fn last_identifier(&self) -> u16 {
        self.last_identifier
    }

    #[must_use]
    pub const fn policy(&self) -> Nat44IcmpPolicy {
        self.policy
    }

    #[must_use]
    pub const fn storage(&self) -> Nat44IcmpStorageShapeV1 {
        self.storage
    }
}

pub struct ValidatedNat44V1 {
    udp: Option<ValidatedNat44UdpV1>,
    tcp: Option<ValidatedNat44TcpV1>,
    icmp: Option<ValidatedNat44IcmpV1>,
}

impl ValidatedNat44V1 {
    /// ICMP query NAT (N5); `None` without `[nat44.icmp]`.
    #[must_use]
    pub const fn icmp(&self) -> Option<&ValidatedNat44IcmpV1> {
        self.icmp.as_ref()
    }

    #[must_use]
    pub const fn udp(&self) -> Option<&ValidatedNat44UdpV1> {
        self.udp.as_ref()
    }

    #[must_use]
    pub const fn tcp(&self) -> Option<&ValidatedNat44TcpV1> {
        self.tcp.as_ref()
    }
}

pub struct ValidatedFirewallV1 {
    rules: Box<[FirewallRule]>,
    policy: FirewallPolicy,
    state_slots: u32,
}

impl ValidatedFirewallV1 {
    #[must_use]
    pub fn rules(&self) -> &[FirewallRule] {
        &self.rules
    }

    #[must_use]
    pub const fn policy(&self) -> FirewallPolicy {
        self.policy
    }

    #[must_use]
    pub const fn state_slots(&self) -> u32 {
        self.state_slots
    }
}

/// Largest accepted AF_XDP device queue id.
pub const MAX_AF_XDP_QUEUE_ID: u32 = 1_023;
/// Smallest accepted AF_XDP ring entry count.
pub const MIN_AF_XDP_RING_ENTRIES: u32 = 64;
/// Largest accepted AF_XDP ring entry count.
pub const MAX_AF_XDP_RING_ENTRIES: u32 = 16_384;
/// Packet bytes every UMEM chunk must keep after the configured and the
/// kernel's fixed headroom: one untagged 1500-byte-MTU Ethernet II frame
/// without FCS, so the single-buffer profile never needs scatter/gather.
pub const MIN_AF_XDP_VISIBLE_FRAME_BYTES: u32 = 1_514;
/// Largest UMEM of one AF_XDP socket (256 MiB).
pub const MAX_AF_XDP_UMEM_BYTES_PER_PORT: u64 = 256 << 20;
/// Largest UMEM of all AF_XDP sockets of one configuration (1 GiB).
pub const MAX_AF_XDP_UMEM_BYTES: u64 = 1 << 30;

/// One validated AF_XDP socket: an interface queue with checked native
/// bind flags, ring capacities, and UMEM geometry.
///
/// The ring and UMEM values are the `ruster-io-xdp::native_profile` types (shared with `ruster-io-xdp-native`),
/// built by that crate's own validators, so the configuration cannot accept
/// a geometry the native backend would reject.
///
/// The port owns a copy of the bound device name, so two ports compare
/// unequal when the interface keeps its IfId but moves to another device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAfXdpPortV1 {
    interface: IfId,
    device: Box<str>,
    queue: u32,
    mode: AfXdpModeV1,
    bind_flags: ValidatedBindFlags,
    attach: XdpAttachModeV1,
    rings: RingConfig,
    umem: UmemConfig,
}

impl ValidatedAfXdpPortV1 {
    /// The bound interface.
    #[must_use]
    pub const fn interface(&self) -> IfId {
        self.interface
    }

    /// The bound device: the `device` of [`Self::interface`], already
    /// restricted to the CONFIG-003 label charset.
    #[must_use]
    pub fn device(&self) -> &str {
        &self.device
    }

    #[must_use]
    pub const fn queue(&self) -> u32 {
        self.queue
    }

    #[must_use]
    pub const fn mode(&self) -> AfXdpModeV1 {
        self.mode
    }

    /// Checked `sockaddr_xdp.sxdp_flags`: need-wakeup plus the copy policy
    /// of [`Self::mode`], never shared UMEM.
    #[must_use]
    pub const fn bind_flags(&self) -> ValidatedBindFlags {
        self.bind_flags
    }

    #[must_use]
    pub const fn attach(&self) -> XdpAttachModeV1 {
        self.attach
    }

    #[must_use]
    pub const fn rings(&self) -> RingConfig {
        self.rings
    }

    /// UMEM geometry. `rx_frames()` is `frame-count - generated-frames`.
    #[must_use]
    pub const fn umem(&self) -> UmemConfig {
        self.umem
    }
}

/// Validated AF_XDP backend: sockets in interface IfId order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAfXdpV1 {
    existing_program: ExistingXdpProgramV1,
    ports: Box<[ValidatedAfXdpPortV1]>,
    umem_bytes: u64,
}

impl ValidatedAfXdpV1 {
    #[must_use]
    pub const fn existing_program(&self) -> ExistingXdpProgramV1 {
        self.existing_program
    }

    /// One socket per interface, sorted by IfId.
    #[must_use]
    pub fn ports(&self) -> &[ValidatedAfXdpPortV1] {
        &self.ports
    }

    /// Sum of every socket's UMEM byte length.
    #[must_use]
    pub const fn umem_bytes(&self) -> u64 {
        self.umem_bytes
    }
}

/// Default `max-frame-len` of the AF_PACKET backend: one untagged
/// 1500-byte-MTU Ethernet II frame without FCS.
pub const DEFAULT_AF_PACKET_FRAME_LEN: u32 = 1_514;
/// Smallest AF_PACKET `max-frame-len`: the largest frame the router itself
/// generates (a 576-byte ICMPv4 error plus the 14-byte Ethernet header),
/// so every generated frame fits a TX frame.
pub const MIN_AF_PACKET_FRAME_LEN: u32 = 590;
/// Largest AF_PACKET `max-frame-len`: a 9216-byte jumbo MTU plus the
/// Ethernet header.
pub const MAX_AF_PACKET_FRAME_LEN: u32 = 9_230;
/// Smallest AF_PACKET ring block (one 4 KiB page).
pub const MIN_AF_PACKET_BLOCK_SIZE: u32 = 4_096;
/// Largest AF_PACKET ring block (4 MiB).
pub const MAX_AF_PACKET_BLOCK_SIZE: u32 = 4 << 20;
/// Largest AF_PACKET ring block count.
pub const MAX_AF_PACKET_BLOCK_COUNT: u32 = 65_536;
/// Largest RX block retire timeout (1 s): a lone frame on an idle port
/// waits up to this long.
pub const MAX_AF_PACKET_RETIRE_TIMEOUT_MS: u32 = 1_000;
/// Largest RX plus TX ring of one AF_PACKET port (256 MiB).
pub const MAX_AF_PACKET_RING_BYTES_PER_PORT: u64 = 256 << 20;
/// Largest ring memory of all AF_PACKET ports of one configuration
/// (1 GiB).
pub const MAX_AF_PACKET_RING_BYTES: u64 = 1 << 30;

/// `TPACKET_ALIGNMENT`.
const AF_PACKET_ALIGNMENT: u32 = 16;
/// Offset of the Ethernet header in a TPACKET_V3 `SOCK_RAW` RX frame: the
/// network header at `TPACKET_ALIGN(TPACKET3_HDRLEN + 16)` (96) minus the
/// 14-byte Ethernet header.
const AF_PACKET_RX_MAC_OFFSET: u32 = 82;
/// Data offset of a TPACKET_V3 TX frame (`TPACKET3_HDRLEN -
/// sizeof(struct sockaddr_ll)`).
const AF_PACKET_TX_DATA_OFFSET: u32 = 48;
/// `BLK_PLUS_PRIV(0)`: the TPACKET_V3 block descriptor.
const AF_PACKET_BLOCK_HEADER: u32 = 48;

/// One validated TPACKET_V3 ring: `block_count` blocks of `block_size`
/// bytes, each cut into `frame_size` slots (the smallest power of two
/// that holds the kernel's per-frame header and the maximum frame). The
/// page-size and kernel-layout checks run again when `ruster run` opens
/// the socket (`ruster-io-afpacket`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AfPacketRingV1 {
    block_size: u32,
    block_count: u32,
    frame_size: u32,
    retire_timeout_ms: u32,
}

impl AfPacketRingV1 {
    #[must_use]
    pub const fn block_size(self) -> u32 {
        self.block_size
    }

    #[must_use]
    pub const fn block_count(self) -> u32 {
        self.block_count
    }

    /// The derived frame slot size.
    #[must_use]
    pub const fn frame_size(self) -> u32 {
        self.frame_size
    }

    /// `block_size / frame_size * block_count`, saturating (the bounds
    /// keep it far below `u32::MAX`).
    #[must_use]
    pub const fn frame_count(self) -> u32 {
        (self.block_size / self.frame_size).saturating_mul(self.block_count)
    }

    /// RX: the block retire timeout; TX: 0.
    #[must_use]
    pub const fn retire_timeout_ms(self) -> u32 {
        self.retire_timeout_ms
    }

    /// Mapped bytes of the ring.
    #[must_use]
    pub const fn byte_len(self) -> u64 {
        self.block_size as u64 * self.block_count as u64
    }
}

/// One validated AF_PACKET socket: an interface's device with checked RX
/// and TX ring geometry.
///
/// The port owns a copy of the bound device name, so two ports compare
/// unequal when the interface keeps its IfId but moves to another device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAfPacketPortV1 {
    interface: IfId,
    device: Box<str>,
    rx: AfPacketRingV1,
    tx: AfPacketRingV1,
}

impl ValidatedAfPacketPortV1 {
    /// The bound interface.
    #[must_use]
    pub const fn interface(&self) -> IfId {
        self.interface
    }

    /// The bound device: the `device` of [`Self::interface`], already
    /// restricted to the CONFIG-003 label charset.
    #[must_use]
    pub fn device(&self) -> &str {
        &self.device
    }

    #[must_use]
    pub const fn rx(&self) -> AfPacketRingV1 {
        self.rx
    }

    #[must_use]
    pub const fn tx(&self) -> AfPacketRingV1 {
        self.tx
    }
}

/// Validated AF_PACKET backend: sockets in interface IfId order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAfPacketV1 {
    max_frame_len: u32,
    ports: Box<[ValidatedAfPacketPortV1]>,
    ring_bytes: u64,
}

impl ValidatedAfPacketV1 {
    /// The longest Ethernet frame of every port (each port's MTU must be
    /// this minus 14).
    #[must_use]
    pub const fn max_frame_len(&self) -> u32 {
        self.max_frame_len
    }

    /// One socket per interface, sorted by IfId.
    #[must_use]
    pub fn ports(&self) -> &[ValidatedAfPacketPortV1] {
        &self.ports
    }

    /// Sum of every port's RX and TX ring bytes.
    #[must_use]
    pub const fn ring_bytes(&self) -> u64 {
        self.ring_bytes
    }
}

/// Validated packet backend.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValidatedBackendV1 {
    Sim,
    AfXdp(ValidatedAfXdpV1),
    AfPacket(ValidatedAfPacketV1),
}

impl ValidatedBackendV1 {
    #[must_use]
    pub const fn kind(&self) -> BackendKindV1 {
        match self {
            Self::Sim => BackendKindV1::Sim,
            Self::AfXdp(_) => BackendKindV1::AfXdp,
            Self::AfPacket(_) => BackendKindV1::AfPacket,
        }
    }

    /// The AF_XDP sockets, or `None` for another backend.
    #[must_use]
    pub const fn af_xdp(&self) -> Option<&ValidatedAfXdpV1> {
        match self {
            Self::AfXdp(af_xdp) => Some(af_xdp),
            Self::Sim | Self::AfPacket(_) => None,
        }
    }

    /// The AF_PACKET sockets, or `None` for another backend.
    #[must_use]
    pub const fn af_packet(&self) -> Option<&ValidatedAfPacketV1> {
        match self {
            Self::AfPacket(af_packet) => Some(af_packet),
            Self::Sim | Self::AfXdp(_) => None,
        }
    }
}

/// Owned, canonical, semantically validated schema V1.
///
/// This type deliberately has no `Debug` implementation because it owns
/// topology and configured NAT allocator seeds. Callers choose individual
/// accessors when emitting operational telemetry.
///
/// ```compile_fail
/// use ruster_config::ValidatedConfigV1;
///
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<ValidatedConfigV1>();
/// ```
pub struct ValidatedConfigV1 {
    interfaces: Box<[InterfaceBindingV1]>,
    core_interfaces: Box<[Interface]>,
    routes: Box<[Route]>,
    neighbors: Box<[Neighbor]>,
    local_ipv4: Box<[LocalIpv4Binding]>,
    ipv4_origin: Ipv4OriginPolicy,
    arp: ArpPolicy,
    source_validation: Box<[SourceValidationBinding]>,
    resolution: Option<ValidatedResolutionV1>,
    icmpv4_errors: Option<ValidatedIcmpv4ErrorV1>,
    nat44: Option<ValidatedNat44V1>,
    firewall: Option<ValidatedFirewallV1>,
    tick: TickBudgetsV1,
    fragmentation: ValidatedFragmentationV1,
    fragment_tracking: ValidatedFragmentTrackingV1,
    arp_hold: ValidatedArpHoldV1,
    storage: RuntimeStorageShapeV1,
    backend: ValidatedBackendV1,
    reload_state: ReloadStateV1,
    down_link_tx: crate::DownLinkTxV1,
    health: HealthV1,
    watch: WatchV1,
    exit_protection: ExitProtectionV1,
}

impl ValidatedConfigV1 {
    /// `[health]` (OPS-LOG), every key within its bound; `None` for a key
    /// the document does not set (all `None` without the table).
    #[must_use]
    pub const fn health(&self) -> HealthV1 {
        self.health
    }

    /// `[watch]` (OPS-LOG), every key within its bound; `None` for a key
    /// the document does not set.
    #[must_use]
    pub const fn watch(&self) -> WatchV1 {
        self.watch
    }

    /// `[exit-protection]` (OPS-EXIT); every key false when absent.
    #[must_use]
    pub const fn exit_protection(&self) -> ExitProtectionV1 {
        self.exit_protection
    }

    /// `[reload] state` ([`ReloadStateV1::Carry`] when absent): what an
    /// applied reload to this document does with runtime state.
    #[must_use]
    pub const fn reload_state(&self) -> ReloadStateV1 {
        self.reload_state
    }

    /// `[reload] down-link-tx` (OPS-EXIT), read from the document being
    /// applied like [`Self::reload_state`].
    #[must_use]
    pub const fn reload_down_link_tx(&self) -> crate::DownLinkTxV1 {
        self.down_link_tx
    }

    #[must_use]
    pub fn interfaces(&self) -> &[InterfaceBindingV1] {
        &self.interfaces
    }

    #[must_use]
    pub fn core_interfaces(&self) -> &[Interface] {
        &self.core_interfaces
    }

    #[must_use]
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    #[must_use]
    pub fn neighbors(&self) -> &[Neighbor] {
        &self.neighbors
    }

    #[must_use]
    pub fn local_ipv4(&self) -> &[LocalIpv4Binding] {
        &self.local_ipv4
    }

    #[must_use]
    pub const fn ipv4_origin(&self) -> Ipv4OriginPolicy {
        self.ipv4_origin
    }

    /// The `[arp]` receive policy ([`ArpPolicy::RFC826`] when absent).
    #[must_use]
    pub const fn arp(&self) -> ArpPolicy {
        self.arp
    }

    /// The `[[interfaces]] source-validation` (URPF) of every interface
    /// whose mode is not off, sorted by interface; empty when every
    /// interface is off (the RFC 1812 §5.3.8 default).
    #[must_use]
    pub fn source_validation(&self) -> &[SourceValidationBinding] {
        &self.source_validation
    }

    #[must_use]
    pub const fn resolution(&self) -> Option<&ValidatedResolutionV1> {
        self.resolution.as_ref()
    }

    #[must_use]
    pub const fn icmpv4_errors(&self) -> Option<&ValidatedIcmpv4ErrorV1> {
        self.icmpv4_errors.as_ref()
    }

    #[must_use]
    pub const fn nat44(&self) -> Option<&ValidatedNat44V1> {
        self.nat44.as_ref()
    }

    #[must_use]
    pub const fn firewall(&self) -> Option<&ValidatedFirewallV1> {
        self.firewall.as_ref()
    }

    #[must_use]
    pub const fn tick(&self) -> TickBudgetsV1 {
        self.tick
    }

    /// `[fragmentation]` (MTU2 part B); defaults (on) when absent.
    #[must_use]
    pub const fn fragmentation(&self) -> ValidatedFragmentationV1 {
        self.fragmentation
    }

    /// `[fragment-tracking]` (NAT-FRAG); defaults (`associate`) when absent.
    #[must_use]
    pub const fn fragment_tracking(&self) -> ValidatedFragmentTrackingV1 {
        self.fragment_tracking
    }

    /// `[resolution.hold]` (ARP-HOLD); defaults (on) when absent.
    #[must_use]
    pub const fn arp_hold(&self) -> ValidatedArpHoldV1 {
        self.arp_hold
    }

    #[must_use]
    pub const fn storage_shape(&self) -> RuntimeStorageShapeV1 {
        self.storage
    }

    /// Packet backend; [`ValidatedBackendV1::Sim`] when `[backend]` is
    /// absent.
    #[must_use]
    pub const fn backend(&self) -> &ValidatedBackendV1 {
        &self.backend
    }
}

#[non_exhaustive]
pub enum ValidatedConfig {
    V1(ValidatedConfigV1),
}

/// Validates and canonicalizes parsed configuration without touching runtime
/// state, a packet backend, a random source, or publication generation.
pub fn validate(
    parsed: VersionedConfig,
    limits: ValidationLimits,
) -> Result<ValidatedConfig, ValidationError> {
    match parsed {
        VersionedConfig::V1(config) => validate_v1(config, limits).map(ValidatedConfig::V1),
    }
}

#[derive(Clone, Copy)]
struct ParsedCidr {
    address: Ipv4Address,
    prefix_len: u8,
}

#[derive(Clone)]
struct InterfaceRecord {
    binding: InterfaceBindingV1,
    core: Interface,
}

#[derive(Clone)]
struct ConnectedRoute {
    route: Route,
    source_path: SourcePath,
}

#[derive(Clone)]
struct RoutedValue {
    route: Route,
    source_path: SourcePath,
}

/// Maximum byte length of an interface `name` or `device` (Linux
/// `IFNAMSIZ - 1`).
pub const MAX_INTERFACE_LABEL_BYTES: usize = 15;

/// Interface labels are operator-facing text that later output prints
/// verbatim, so they are restricted to a conservative charset with no
/// whitespace, control, or separator characters, and may not be `.`, `..`,
/// or start with `-`.
fn check_label(label: &str, code: ValidationCode, path: SourcePath) -> Result<(), ValidationError> {
    if label.len() > MAX_INTERFACE_LABEL_BYTES {
        return Err(ValidationError::bounded(
            code,
            path,
            MAX_INTERFACE_LABEL_BYTES as u64,
            u64::try_from(label.len()).unwrap_or(u64::MAX),
        ));
    }
    // `.` and `..` are rejected like Linux `dev_valid_name`; a leading `-`
    // would read as a command-line option.
    if matches!(label, "." | "..")
        || label.starts_with('-')
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ValidationError::new(code, path));
    }
    Ok(())
}

fn validate_v1(
    config: ConfigV1,
    limits: ValidationLimits,
) -> Result<ValidatedConfigV1, ValidationError> {
    if config.schema_version != crate::SCHEMA_VERSION_V1 {
        return Err(ValidationError::new(
            ValidationCode::InvalidSchemaVersion,
            path(&["schema-version"]),
        ));
    }
    preflight_public_dto(&config)?;
    let health = validate_health(config.health.unwrap_or_default())?;
    let watch = validate_watch(config.watch.unwrap_or_default())?;
    let exit_protection = config.exit_protection.unwrap_or_default();
    let mut interface_records = Vec::with_capacity(config.interfaces.len());
    let mut source_validation = Vec::new();
    for (index, source) in config.interfaces.into_iter().enumerate() {
        let base = indexed_path("interfaces", index);
        if source.name.is_empty() {
            return Err(ValidationError::new(
                ValidationCode::EmptyInterfaceName,
                child_path(&base, "name"),
            ));
        }
        if source.device.is_empty() {
            return Err(ValidationError::new(
                ValidationCode::EmptyDeviceName,
                child_path(&base, "device"),
            ));
        }
        check_label(
            &source.name,
            ValidationCode::InvalidInterfaceName,
            child_path(&base, "name"),
        )?;
        check_label(
            &source.device,
            ValidationCode::InvalidDeviceName,
            child_path(&base, "device"),
        )?;
        if interface_records
            .iter()
            .any(|record: &InterfaceRecord| record.binding.id == IfId(source.id))
        {
            return Err(ValidationError::new(
                ValidationCode::DuplicateInterfaceId,
                child_path(&base, "id"),
            ));
        }
        if interface_records
            .iter()
            .any(|record| record.binding.name.as_ref() == source.name)
        {
            return Err(ValidationError::new(
                ValidationCode::DuplicateInterfaceName,
                child_path(&base, "name"),
            ));
        }
        if interface_records
            .iter()
            .any(|record| record.binding.device.as_ref() == source.device)
        {
            return Err(ValidationError::new(
                ValidationCode::DuplicateDeviceName,
                child_path(&base, "device"),
            ));
        }
        let mac = parse_mac(&source.mac, child_path(&base, "mac"))?;
        let mtu = match source.mtu {
            None => ruster_core::ETHERNET_DEFAULT_MTU,
            Some(mtu) => u16::try_from(mtu)
                .ok()
                .filter(|mtu| *mtu >= ruster_core::IPV4_MIN_MTU)
                .ok_or_else(|| {
                    ValidationError::new(
                        ValidationCode::InterfaceMtuOutOfRange,
                        child_path(&base, "mtu"),
                    )
                })?,
        };
        let allow_default = source.source_validation_allow_default.unwrap_or(false);
        let mode = match (source.source_validation.unwrap_or_default(), allow_default) {
            (crate::SourceValidationV1::Loose, false) => SourceValidation::Loose,
            (crate::SourceValidationV1::Loose, true) => SourceValidation::LooseAllowDefault,
            (_, true) => {
                return Err(ValidationError::new(
                    ValidationCode::SourceValidationAllowDefaultNotLoose,
                    child_path(&base, "source-validation-allow-default"),
                ));
            }
            (crate::SourceValidationV1::Off, false) => SourceValidation::Off,
            (crate::SourceValidationV1::Strict, false) => SourceValidation::Strict,
        };
        if mode != SourceValidation::Off {
            source_validation.push(SourceValidationBinding {
                interface: IfId(source.id),
                mode,
            });
        }
        let binding = InterfaceBindingV1 {
            id: IfId(source.id),
            name: source.name.into_boxed_str(),
            device: source.device.into_boxed_str(),
            mac,
            mtu,
        };
        interface_records.push(InterfaceRecord {
            core: Interface {
                id: binding.id,
                mac,
                mtu,
            },
            binding,
        });
    }

    let interface_names = interface_records
        .iter()
        .map(|record| (record.binding.name.clone(), record.binding.id))
        .collect::<Vec<_>>();
    let find_interface = |name: &str| {
        interface_names
            .iter()
            .find(|(candidate, _)| candidate.as_ref() == name)
            .map(|(_, id)| *id)
    };

    let mut local_ipv4_with_paths = Vec::with_capacity(config.addresses.len());
    let mut connected = Vec::with_capacity(config.addresses.len());
    for (index, source) in config.addresses.into_iter().enumerate() {
        let base = indexed_path("addresses", index);
        let interface = find_interface(&source.interface).ok_or_else(|| {
            ValidationError::new(
                ValidationCode::UnknownInterface,
                child_path(&base, "interface"),
            )
        })?;
        let cidr = parse_cidr(&source.ipv4, child_path(&base, "ipv4"))?;
        if !is_host_for_prefix(cidr.address, cidr.prefix_len) {
            return Err(ValidationError::new(
                ValidationCode::AddressNotHost,
                child_path(&base, "ipv4"),
            ));
        }
        if local_ipv4_with_paths
            .iter()
            .any(|(binding, _): &(LocalIpv4Binding, SourcePath)| binding.interface == interface)
        {
            return Err(ValidationError::new(
                ValidationCode::DuplicateInterfaceAddress,
                child_path(&base, "interface"),
            ));
        }
        if local_ipv4_with_paths
            .iter()
            .any(|(binding, _)| binding.address == cidr.address)
        {
            return Err(ValidationError::new(
                ValidationCode::DuplicateLocalAddress,
                child_path(&base, "ipv4"),
            ));
        }
        let binding = LocalIpv4Binding {
            interface,
            address: cidr.address,
        };
        local_ipv4_with_paths.push((binding, base.clone()));
        let network = network_address(cidr.address, cidr.prefix_len);
        let route = Route::new(network, cidr.prefix_len, interface, None).map_err(|error| {
            ValidationError::new(ValidationCode::Route(error), child_path(&base, "ipv4"))
        })?;
        connected.push(ConnectedRoute {
            route,
            source_path: child_path(&base, "ipv4"),
        });
    }

    let mut routed: Vec<RoutedValue> = connected
        .iter()
        .map(|entry| RoutedValue {
            route: entry.route,
            source_path: entry.source_path.clone(),
        })
        .collect();
    for (index, source) in config.routes.into_iter().enumerate() {
        let base = indexed_path("routes", index);
        let egress = find_interface(&source.egress).ok_or_else(|| {
            ValidationError::new(
                ValidationCode::UnknownInterface,
                child_path(&base, "egress"),
            )
        })?;
        let cidr = parse_cidr(&source.prefix, child_path(&base, "prefix"))?;
        let next_hop = source
            .via
            .as_deref()
            .map(|value| parse_ipv4(value, child_path(&base, "via")))
            .transpose()?;
        if let Some(gateway) = next_hop {
            if !is_basic_host(gateway) {
                return Err(ValidationError::new(
                    ValidationCode::GatewayNotHost,
                    child_path(&base, "via"),
                ));
            }
            if !connected
                .iter()
                .any(|entry| route_host_matches(entry.route, gateway))
            {
                return Err(ValidationError::new(
                    ValidationCode::GatewayNotOnLink,
                    child_path(&base, "via"),
                ));
            }
            if !connected.iter().any(|entry| {
                entry.route.egress() == egress && route_host_matches(entry.route, gateway)
            }) {
                return Err(ValidationError::new(
                    ValidationCode::GatewayNotOnLink,
                    child_path(&base, "via"),
                ));
            }
        }
        let route =
            Route::new(cidr.address, cidr.prefix_len, egress, next_hop).map_err(|error| {
                ValidationError::new(ValidationCode::Route(error), child_path(&base, "prefix"))
            })?;
        routed.push(RoutedValue {
            route,
            source_path: child_path(&base, "prefix"),
        });
    }
    routed.sort_by_key(|entry| route_sort_key(entry.route));
    for pair in routed.windows(2) {
        if route_prefix_key(pair[0].route) == route_prefix_key(pair[1].route) {
            return Err(ValidationError::new(
                ValidationCode::DuplicateRoute,
                pair[1].source_path.clone(),
            ));
        }
    }

    let mut neighbors_with_paths = Vec::with_capacity(config.neighbors.len());
    for (index, source) in config.neighbors.into_iter().enumerate() {
        let base = indexed_path("neighbors", index);
        let interface = find_interface(&source.interface).ok_or_else(|| {
            ValidationError::new(
                ValidationCode::UnknownInterface,
                child_path(&base, "interface"),
            )
        })?;
        let address = parse_ipv4(&source.address, child_path(&base, "address"))?;
        if !is_basic_host(address) {
            return Err(ValidationError::new(
                ValidationCode::NeighborNotHost,
                child_path(&base, "address"),
            ));
        }
        if !connected.iter().any(|entry| {
            entry.route.egress() == interface && route_host_matches(entry.route, address)
        }) {
            return Err(ValidationError::new(
                ValidationCode::NeighborNotOnLink,
                child_path(&base, "address"),
            ));
        }
        let mac = parse_mac(&source.mac, child_path(&base, "mac"))?;
        if neighbors_with_paths
            .iter()
            .any(|(neighbor, _): &(Neighbor, SourcePath)| {
                neighbor.interface == interface && neighbor.target == address
            })
        {
            return Err(ValidationError::new(
                ValidationCode::DuplicateNeighbor,
                child_path(&base, "address"),
            ));
        }
        neighbors_with_paths.push((
            Neighbor {
                interface,
                target: address,
                mac,
            },
            base,
        ));
    }

    let ipv4_origin = match config.ipv4_origin {
        Some(source) => Ipv4OriginPolicy::new(source.default_ttl)
            .map_err(|error| {
                ValidationError::new(
                    ValidationCode::Ipv4Origin(error),
                    path(&["ipv4-origin", "default-ttl"]),
                )
            })?
            .with_echo_reply(source.echo_reply),
        None => Ipv4OriginPolicy::default(),
    };
    let arp_source = config.arp.unwrap_or_default();
    // ARP-034: the announcement values are checked even when `announce =
    // false`, so switching it on by reload cannot meet a bad value.
    let announce = ruster_core::ArpAnnouncePolicy::new(
        arp_source.announce_count,
        arp_source.announce_interval_ms,
        arp_source.announce_min_interval_ms,
    )
    .map_err(|error| {
        let key = match error {
            ruster_core::ArpAnnouncePolicyError::CountOutOfRange => "announce-count",
            ruster_core::ArpAnnouncePolicyError::IntervalOutOfRange => "announce-interval-ms",
            ruster_core::ArpAnnouncePolicyError::MinIntervalOutOfRange => {
                "announce-min-interval-ms"
            }
        };
        ValidationError::new(
            ValidationCode::ArpAnnouncePolicy(error),
            path(&["arp", key]),
        )
    })?;
    let arp = ArpPolicy::RFC826
        .with_require_on_link_sender(arp_source.require_on_link_sender)
        .with_announce(arp_source.announce.then_some(announce))
        .with_defend_conflicts(arp_source.conflict_defense);

    interface_records.sort_by_key(|record| record.binding.id);
    source_validation.sort_by_key(|binding| binding.interface);
    local_ipv4_with_paths.sort_by_key(|(binding, _)| binding.interface);
    neighbors_with_paths.sort_by_key(|(neighbor, _)| {
        (
            neighbor.interface,
            u32::from_be_bytes(neighbor.target.octets()),
        )
    });
    let interfaces: Box<[InterfaceBindingV1]> = interface_records
        .iter()
        .map(|record| record.binding.clone())
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let core_interfaces = interface_records
        .into_iter()
        .map(|record| record.core)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let routes = routed
        .into_iter()
        .map(|entry| entry.route)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let local_ipv4 = local_ipv4_with_paths
        .into_iter()
        .map(|(binding, _)| binding)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let neighbors = neighbors_with_paths
        .into_iter()
        .map(|(neighbor, _)| neighbor)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let snapshot = ForwardingSnapshot::with_ipv4_origin_policy(
        &routes,
        &core_interfaces,
        &neighbors,
        &local_ipv4,
        ipv4_origin,
    )
    .map_err(|error| {
        ValidationError::new(ValidationCode::Forwarding(error), SourcePath::default())
    })?;

    let resolution_source = config.resolution;
    let resolution_policy = resolution_source
        .map(|source| {
            ResolutionPolicy::with_retry_and_dynamic_neighbor_ttl(
                source.policy.interval_ms,
                source.policy.state_ttl_ms,
                source.policy.max_attempts,
                source.policy.dynamic_neighbor_ttl_ms,
            )
            .map_err(|error| {
                ValidationError::new(
                    ValidationCode::ResolutionPolicy(error),
                    path(&["resolution", "policy"]),
                )
            })
        })
        .transpose()?;

    let icmp_source = config.icmpv4_errors;
    let icmp_policy = icmp_source
        .map(|source| {
            let generate = source.generate;
            Icmpv4ErrorPolicy::new(source.policy.interval_ms, source.policy.state_ttl_ms)
                .and_then(|policy| {
                    policy.with_port_unreachable_interval_ms(
                        source.policy.port_unreachable_interval_ms,
                    )
                })
                .and_then(|policy| {
                    policy.with_fragmentation_needed_interval_ms(
                        source.policy.fragmentation_needed_interval_ms,
                    )
                })
                .map(|policy| {
                    policy
                        .with_generation(Icmpv4ErrorKind::TimeExceededTtl, generate.time_exceeded)
                        .with_generation(
                            Icmpv4ErrorKind::DestinationUnreachableNetwork,
                            generate.net_unreachable,
                        )
                        .with_generation(
                            Icmpv4ErrorKind::DestinationUnreachableHost,
                            generate.host_unreachable,
                        )
                        .with_generation(
                            Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded,
                            generate.fragmentation_needed,
                        )
                        .with_generation(
                            Icmpv4ErrorKind::DestinationUnreachableProtocol,
                            generate.protocol_unreachable,
                        )
                        .with_generation(
                            Icmpv4ErrorKind::DestinationUnreachableLocalPort,
                            generate.udp_port_unreachable,
                        )
                        .with_generation(
                            Icmpv4ErrorKind::ParameterProblem,
                            generate.parameter_problem,
                        )
                        .with_generation(
                            Icmpv4ErrorKind::DestinationUnreachableAdministrativelyProhibited,
                            generate.admin_prohibited,
                        )
                })
                .map_err(|error| {
                    ValidationError::new(
                        ValidationCode::Icmpv4ErrorPolicy(error),
                        path(&["icmpv4-errors", "policy"]),
                    )
                })
                .and_then(|policy| {
                    policy
                        .with_translated_limit(
                            source.translated.rate_per_second,
                            source.translated.burst,
                        )
                        .map_err(|error| {
                            ValidationError::new(
                                ValidationCode::Icmpv4ErrorPolicy(error),
                                path(&["icmpv4-errors", "translated"]),
                            )
                        })
                })
        })
        .transpose()?;
    // Fragmentation Needed has its own limiter class on every egress
    // (MTU1): room for both classes on every interface, so neither can make
    // another egress StateFull.
    let fragmentation_needed_states = match (icmp_source, icmp_policy) {
        (Some(source), Some(policy))
            if policy.generates(Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded) =>
        {
            let needed = core_interfaces.len() as u64;
            if u64::from(source.capacity.states) < 2 * needed {
                return Err(ValidationError::new(
                    ValidationCode::Icmpv4ErrorStatesTooFewForFragmentationNeeded,
                    path(&["icmpv4-errors", "capacity", "states"]),
                ));
            }
            needed
        }
        _ => 0,
    };

    let nat_source = config.nat44;
    let mut validated_udp = None;
    let mut validated_tcp = None;
    let mut udp_capacity = None;
    let mut tcp_capacity = None;
    let mut validated_icmp = None;
    let mut icmp_capacity = None;
    if let Some(nat) = nat_source {
        if nat.udp.is_none() && nat.tcp.is_none() {
            return Err(ValidationError::new(
                ValidationCode::Nat44RealmWithoutProtocol,
                path(&["nat44"]),
            ));
        }
        let inside = find_interface(&nat.realm.inside).ok_or_else(|| {
            ValidationError::new(
                ValidationCode::UnknownInterface,
                path(&["nat44", "realm", "inside"]),
            )
        })?;
        let outside = find_interface(&nat.realm.outside).ok_or_else(|| {
            ValidationError::new(
                ValidationCode::UnknownInterface,
                path(&["nat44", "realm", "outside"]),
            )
        })?;
        let public_address = parse_ipv4(
            &nat.realm.public_address,
            path(&["nat44", "realm", "public-address"]),
        )?;
        if let Some(source) = nat.udp {
            let seed = parse_seed(
                source.allocator_seed.expose(),
                path(&["nat44", "udp", "allocator-seed"]),
            )?;
            let policy = Nat44UdpPolicy::new(source.idle_ttl_ms, seed)
                .map_err(|error| {
                    ValidationError::new(
                        ValidationCode::Nat44UdpPolicy(error),
                        path(&["nat44", "udp", "idle-ttl-ms"]),
                    )
                })?
                .with_icmpv4_errors(map_icmp_policy(source.icmpv4_errors))
                .with_filtering(map_filtering(source.filtering))
                .with_hairpinning(source.hairpinning)
                .with_port_preservation(source.port_preservation)
                .with_mappings_per_host(source.mappings_per_host)
                .with_peers_per_host(source.peers_per_host);
            Nat44UdpConfig::new(
                &snapshot,
                inside,
                outside,
                public_address,
                nat.realm.ports.first,
                nat.realm.ports.last,
                policy,
            )
            .map_err(|error| {
                ValidationError::new(
                    ValidationCode::Nat44UdpConfig(error),
                    path(&["nat44", "realm"]),
                )
            })?;
            udp_capacity = Some(source.capacity);
            validated_udp = Some((inside, outside, public_address, nat.realm.ports, policy));
        }
        if let Some(source) = nat.tcp {
            let seed = parse_seed(
                source.allocator_seed.expose(),
                path(&["nat44", "tcp", "allocator-seed"]),
            )?;
            let policy = Nat44TcpPolicy::new(source.idle_ttl_ms, seed)
                .map_err(|error| {
                    ValidationError::new(
                        ValidationCode::Nat44TcpPolicy(error),
                        path(&["nat44", "tcp", "idle-ttl-ms"]),
                    )
                })?
                // RFC 5382 REQ-5: transitory timeouts of at least 4 minutes
                // (and no longer than the established one).
                .with_opening_idle_ttl_ms(source.opening_idle_ttl_ms)
                .map_err(|error| {
                    ValidationError::new(
                        ValidationCode::Nat44TcpPolicy(error),
                        path(&["nat44", "tcp", "opening-idle-ttl-ms"]),
                    )
                })?
                .with_closing_idle_ttl_ms(source.closing_idle_ttl_ms)
                .map_err(|error| {
                    ValidationError::new(
                        ValidationCode::Nat44TcpPolicy(error),
                        path(&["nat44", "tcp", "closing-idle-ttl-ms"]),
                    )
                })?
                .with_icmpv4_errors(map_icmp_policy(source.icmpv4_errors))
                .with_filtering(map_filtering(source.filtering))
                .with_hairpinning(source.hairpinning)
                .with_port_preservation(source.port_preservation)
                .with_mappings_per_host(source.mappings_per_host)
                .with_sessions_per_host(source.sessions_per_host)
                .with_unsolicited_syn_icmp(source.unsolicited_syn_icmp)
                .with_inbound_rst(map_inbound_rst(source.inbound_rst))
                .with_inbound_sessions_per_remote(source.inbound_sessions_per_remote)
                .map_err(|error| {
                    ValidationError::new(
                        ValidationCode::Nat44TcpPolicy(error),
                        path(&["nat44", "tcp", "inbound-sessions-per-remote"]),
                    )
                })?;
            Nat44TcpConfig::new(
                &snapshot,
                inside,
                outside,
                public_address,
                nat.realm.ports.first,
                nat.realm.ports.last,
                policy,
            )
            .map_err(|error| {
                ValidationError::new(
                    ValidationCode::Nat44TcpConfig(error),
                    path(&["nat44", "realm"]),
                )
            })?;
            // Delayed Port Unreachable (RFC 5382 REQ-4) uses its own
            // limiter state on the outside egress besides the one per
            // egress of the other kinds (and of Fragmentation Needed):
            // require room for all so a SYN flood can never make another
            // egress StateFull.
            if let Some(icmp) = icmp_source {
                let sends_port_unreachable =
                    policy.unsolicited_syn_icmp() && source.capacity.unsolicited_syn_holds > 0;
                let needed = core_interfaces.len() as u64 + fragmentation_needed_states + 1;
                if sends_port_unreachable && u64::from(icmp.capacity.states) < needed {
                    return Err(ValidationError::new(
                        ValidationCode::Icmpv4ErrorStatesTooFewForPortUnreachable,
                        path(&["icmpv4-errors", "capacity", "states"]),
                    ));
                }
            }
            tcp_capacity = Some(source.capacity);
            validated_tcp = Some((inside, outside, public_address, nat.realm.ports, policy));
        }
        if let Some(source) = nat.icmp {
            let seed = source
                .allocator_seed
                .as_ref()
                .map(|seed| parse_seed(seed.expose(), path(&["nat44", "icmp", "allocator-seed"])))
                .transpose()?
                .unwrap_or(0);
            let policy_error = |field: &str| {
                let field = field.to_owned();
                move |error| {
                    ValidationError::new(
                        ValidationCode::Nat44IcmpPolicy(error),
                        path(&["nat44", "icmp", &field]),
                    )
                }
            };
            let policy = Nat44IcmpPolicy::new(source.idle_ttl_ms, seed)
                .map_err(policy_error("idle-ttl-ms"))?
                .with_filtering(map_filtering(source.filtering))
                .map_err(policy_error("filtering"))?
                .with_icmpv4_errors(map_icmp_policy(source.icmpv4_errors))
                .with_identifier_preservation(source.identifier_preservation)
                .with_mappings_per_host(source.mappings_per_host)
                .with_peers_per_host(source.peers_per_host);
            let identifiers = source.identifiers.unwrap_or(nat.realm.ports);
            Nat44IcmpConfig::new(
                &snapshot,
                inside,
                outside,
                public_address,
                identifiers.first,
                identifiers.last,
                policy,
            )
            .map_err(|error| {
                ValidationError::new(
                    ValidationCode::Nat44IcmpConfig(error),
                    if source.identifiers.is_some() {
                        path(&["nat44", "icmp", "identifiers"])
                    } else {
                        path(&["nat44", "realm"])
                    },
                )
            })?;
            icmp_capacity = Some(source.capacity);
            validated_icmp = Some((inside, outside, public_address, identifiers, policy));
        }
    }

    let firewall_source = config.firewall;
    let mut firewall_policy = None;
    let mut firewall_rules = None;
    let mut firewall_capacity = None;
    if let Some(source) = firewall_source {
        let policy = FirewallPolicy::new(
            source.policy.udp_idle_ttl_ms,
            source.policy.tcp_opening_idle_ttl_ms,
            source.policy.tcp_active_idle_ttl_ms,
        )
        .map_err(|error| {
            ValidationError::new(
                ValidationCode::FirewallPolicy(error),
                path(&["firewall", "policy"]),
            )
        })?;
        let mut rules = Vec::with_capacity(source.rules.len());
        for (index, source_rule) in source.rules.into_iter().enumerate() {
            let base = indexed_nested_path("firewall", "rules", index);
            let ingress = source_rule
                .ingress
                .as_deref()
                .map(|name| {
                    find_interface(name)
                        .map(FirewallInterface::Interface)
                        .ok_or_else(|| {
                            ValidationError::new(
                                ValidationCode::UnknownInterface,
                                child_path(&base, "ingress"),
                            )
                        })
                })
                .transpose()?
                .unwrap_or(FirewallInterface::Any);
            let egress = source_rule
                .egress
                .as_deref()
                .map(|name| {
                    find_interface(name)
                        .map(FirewallInterface::Interface)
                        .ok_or_else(|| {
                            ValidationError::new(
                                ValidationCode::UnknownInterface,
                                child_path(&base, "egress"),
                            )
                        })
                })
                .transpose()?
                .unwrap_or(FirewallInterface::Any);
            let source_prefix = parse_cidr(&source_rule.source, child_path(&base, "source"))?;
            let source_prefix =
                FirewallIpv4Prefix::new(source_prefix.address, source_prefix.prefix_len).map_err(
                    |error| {
                        ValidationError::new(
                            ValidationCode::FirewallPrefix(error),
                            child_path(&base, "source"),
                        )
                    },
                )?;
            let destination =
                parse_cidr(&source_rule.destination, child_path(&base, "destination"))?;
            let destination = FirewallIpv4Prefix::new(destination.address, destination.prefix_len)
                .map_err(|error| {
                    ValidationError::new(
                        ValidationCode::FirewallPrefix(error),
                        child_path(&base, "destination"),
                    )
                })?;
            // ICMP rules (N5) have no ports and match every identifier;
            // TCP and UDP rules must name both ranges.
            let ports = |range: Option<crate::Nat44PortRangeV1>, field: &str| {
                let field_path = child_path(&base, field);
                match (source_rule.protocol, range) {
                    (FirewallProtocolV1::Icmp, None) => {
                        Ok(FirewallPortRange::new(0, u16::MAX).expect("the full range is ordered"))
                    }
                    (FirewallProtocolV1::Icmp, Some(_)) => Err(ValidationError::new(
                        ValidationCode::FirewallIcmpRulePorts,
                        field_path,
                    )),
                    (FirewallProtocolV1::Tcp | FirewallProtocolV1::Udp, None) => Err(
                        ValidationError::new(ValidationCode::FirewallRulePortsRequired, field_path),
                    ),
                    (FirewallProtocolV1::Tcp | FirewallProtocolV1::Udp, Some(range)) => {
                        FirewallPortRange::new(range.first, range.last).map_err(|error| {
                            ValidationError::new(
                                ValidationCode::FirewallPortRange(error),
                                field_path,
                            )
                        })
                    }
                }
            };
            let source_ports = ports(source_rule.source_ports, "source-ports")?;
            let destination_ports = ports(source_rule.destination_ports, "destination-ports")?;
            rules.push(FirewallRule::new(
                FirewallRuleId(source_rule.id),
                ingress,
                egress,
                source_prefix,
                destination,
                match source_rule.protocol {
                    FirewallProtocolV1::Tcp => FirewallProtocol::Tcp,
                    FirewallProtocolV1::Udp => FirewallProtocol::Udp,
                    FirewallProtocolV1::Icmp => FirewallProtocol::Icmp,
                },
                source_ports,
                destination_ports,
                match source_rule.action {
                    FirewallActionV1::AllowStateful => FirewallAction::AllowStateful,
                    FirewallActionV1::Deny => FirewallAction::Deny,
                },
            ));
        }
        validate_firewall_rules(&snapshot, &rules).map_err(|error| {
            ValidationError::new(
                ValidationCode::FirewallRules(error),
                path(&["firewall", "rules"]),
            )
        })?;
        firewall_policy = Some(policy);
        firewall_capacity = Some(source.capacity.states);
        firewall_rules = Some(rules.into_boxed_slice());
    }

    // Before the fragmentation slots, whose size depends on the largest
    // frame an AF_PACKET port receives.
    let backend_source = config.backend.unwrap_or_default();
    // Port order and interface names of the source, for the fragmentation
    // room check below (the validated ports are sorted by IfId).
    let backend_port_names: Vec<String> = match backend_source.kind {
        BackendKindV1::AfXdp => backend_source
            .ports
            .iter()
            .map(|port| port.interface.clone())
            .collect(),
        BackendKindV1::AfPacket => backend_source
            .af_packet
            .as_ref()
            .map(|af_packet| {
                af_packet
                    .ports
                    .iter()
                    .map(|port| port.interface.clone())
                    .collect()
            })
            .unwrap_or_default(),
        BackendKindV1::Sim => Vec::new(),
    };
    let backend = validate_backend(backend_source, &interfaces)?;

    let fragmentation_source = config.fragmentation.unwrap_or_default();
    let fragmentation_path = |field: &str| path(&["fragmentation", field]);
    let fragmentation_policy = u16::try_from(fragmentation_source.max_fragments_per_datagram)
        .map_err(|_| Ipv4FragmentationPolicyError::MaxFragmentsOutOfRange)
        .and_then(|max| Ipv4FragmentationPolicy::new(fragmentation_source.enabled, max))
        .map_err(|error| {
            ValidationError::new(
                ValidationCode::FragmentationPolicy(error),
                fragmentation_path("max-fragments-per-datagram"),
            )
        })?;
    let fragmentation_slots = if fragmentation_policy.enabled() {
        if fragmentation_source.datagrams == 0 {
            return Err(ValidationError::new(
                ValidationCode::FragmentationDatagramsZero,
                fragmentation_path("datagrams"),
            ));
        }
        if fragmentation_source.datagrams > crate::MAX_FRAGMENTATION_DATAGRAMS {
            return Err(ValidationError::bounded(
                ValidationCode::CapacityLimitExceeded,
                fragmentation_path("datagrams"),
                u64::from(crate::MAX_FRAGMENTATION_DATAGRAMS),
                u64::from(fragmentation_source.datagrams),
            ));
        }
        check_fragment_set_room(&backend, &interfaces, &backend_port_names)?;
        // A slot holds the longest datagram the router can receive. The
        // configured interface MTU is not enforced at ingress (a device MTU
        // may be larger, `MTU_BELOW_DEVICE`), so the bound is the largest of
        // every interface MTU, the longest datagram an AF_XDP frame can carry
        // (`FRAGMENTATION_MIN_SLOT_DATAGRAM`), and, for AF_PACKET, its
        // `max-frame-len` minus the Ethernet header (up to 9216). A datagram
        // within it is fragmented as RFC 1812 §4.2.2.7 requires even when it
        // is above every configured MTU. So an AF_PACKET `max-frame-len`
        // above 3840 changes the storage shape (restart-required anyway).
        let received = interfaces
            .iter()
            .map(InterfaceBindingV1::mtu)
            .max()
            .unwrap_or(ruster_core::ETHERNET_DEFAULT_MTU)
            .max(FRAGMENTATION_MIN_SLOT_DATAGRAM)
            .max(af_packet_received_datagram(&backend));
        Some(FragmentationStorageShapeV1 {
            datagrams: fragmentation_source.datagrams,
            slot_bytes: u32::try_from(ruster_core::ipv4_fragment_slot_bytes(received))
                .expect("14 + a u16 MTU fits u32"),
        })
    } else {
        None
    };

    let (fragment_tracking_policy, fragment_tracking_storage) = validate_fragment_tracking(
        config.fragment_tracking.unwrap_or_default(),
        fragmentation_slots,
    )?;
    let (arp_hold_policy, arp_hold_storage) = validate_arp_hold(
        resolution_source.map(|source| source.hold.unwrap_or_default()),
        fragmentation_slots,
    )?;

    let storage = build_storage_shape(
        StorageInputs {
            resolution: resolution_source.map(|source| source.capacity),
            interfaces: u32::try_from(interfaces.len())
                .expect("the parser bounds interfaces at 256"),
            icmp: icmp_source.map(|source| source.capacity),
            udp: udp_capacity.zip(validated_udp.map(|(_, _, _, ports, policy)| {
                (
                    (ports.first, ports.last),
                    per_host_key(policy.mappings_per_host(), policy.peers_per_host()),
                )
            })),
            tcp: tcp_capacity.zip(validated_tcp.map(|(_, _, _, ports, policy)| {
                (
                    (ports.first, ports.last),
                    (
                        policy.mappings_per_host() != 0,
                        policy.sessions_per_host() != 0,
                    ),
                )
            })),
            icmp_query: icmp_capacity.zip(validated_icmp.map(|(_, _, _, ids, policy)| {
                (
                    (ids.first, ids.last),
                    per_host_key(policy.mappings_per_host(), policy.peers_per_host()),
                )
            })),
            firewall_states: firewall_capacity,
            fragmentation: fragmentation_slots,
            fragment_tracking: fragment_tracking_storage,
            arp_hold: arp_hold_storage,
        },
        limits,
    )?;

    let resolution = resolution_policy
        .zip(storage.resolution)
        .map(|(policy, storage)| ValidatedResolutionV1 { policy, storage });
    let icmpv4_errors = icmp_policy
        .zip(storage.icmpv4_errors)
        .map(|(policy, storage)| ValidatedIcmpv4ErrorV1 { policy, storage });
    let nat44 = (validated_udp.is_some() || validated_tcp.is_some()).then(|| ValidatedNat44V1 {
        udp: validated_udp.zip(storage.nat44_udp).map(
            |((inside, outside, public_address, ports, policy), storage)| ValidatedNat44UdpV1 {
                inside,
                outside,
                public_address,
                first_port: ports.first,
                last_port: ports.last,
                policy,
                storage,
            },
        ),
        tcp: validated_tcp.zip(storage.nat44_tcp).map(
            |((inside, outside, public_address, ports, policy), storage)| ValidatedNat44TcpV1 {
                inside,
                outside,
                public_address,
                first_port: ports.first,
                last_port: ports.last,
                policy,
                storage,
            },
        ),
        icmp: validated_icmp.zip(storage.nat44_icmp).map(
            |((inside, outside, public_address, ids, policy), storage)| ValidatedNat44IcmpV1 {
                inside,
                outside,
                public_address,
                first_identifier: ids.first,
                last_identifier: ids.last,
                policy,
                storage,
            },
        ),
    });
    let firewall = firewall_policy
        .zip(firewall_rules)
        .zip(firewall_capacity)
        .map(|((policy, rules), state_slots)| ValidatedFirewallV1 {
            rules,
            policy,
            state_slots,
        });
    let tick = config
        .tick
        .map_or_else(TickBudgetsV1::default, |tick| TickBudgetsV1 {
            rx: tick.rx,
            resolution_timer_scans: tick.resolution_timer_scans,
            failure_dispatch_scans: tick.failure_dispatch_scans,
            generated_arp: tick.generated_arp,
            generated_icmpv4: tick.generated_icmpv4,
            generated_fragments: tick.generated_fragments,
        });
    if let Some(source) = config.tick {
        // ARP-034: the RFC 5227 frames leave through the generated ARP
        // budget; with none they could never be sent.
        if source.generated_arp == 0 && (arp.announce().is_some() || arp.defend_conflicts()) {
            return Err(ValidationError::new(
                ValidationCode::ArpAnnounceWithoutGeneratedArp,
                path(&["tick", "generated-arp"]),
            ));
        }
        let budget_path = path(&["tick", "generated-fragments"]);
        if source.generated_fragments == 0 {
            return Err(ValidationError::new(
                ValidationCode::TickGeneratedFragmentsZero,
                budget_path,
            ));
        }
        if source.generated_fragments > crate::MAX_TICK_GENERATED_FRAGMENTS {
            return Err(ValidationError::bounded(
                ValidationCode::CapacityLimitExceeded,
                budget_path,
                u64::from(crate::MAX_TICK_GENERATED_FRAGMENTS),
                u64::from(source.generated_fragments),
            ));
        }
    }

    Ok(ValidatedConfigV1 {
        interfaces,
        core_interfaces,
        routes,
        neighbors,
        local_ipv4,
        ipv4_origin,
        arp,
        source_validation: source_validation.into_boxed_slice(),
        resolution,
        icmpv4_errors,
        nat44,
        firewall,
        tick,
        fragmentation: ValidatedFragmentationV1 {
            policy: fragmentation_policy,
            storage: fragmentation_slots,
        },
        fragment_tracking: ValidatedFragmentTrackingV1 {
            policy: fragment_tracking_policy,
            storage: fragment_tracking_storage,
        },
        arp_hold: ValidatedArpHoldV1 {
            policy: arp_hold_policy,
            storage: arp_hold_storage,
        },
        storage,
        backend,
        reload_state: config.reload.unwrap_or_default().state,
        down_link_tx: config.reload.unwrap_or_default().down_link_tx,
        health,
        watch,
        exit_protection,
    })
}

/// Validates `[fragment-tracking]` (NAT-FRAG). `refuse` has no policy and no
/// storage. In `associate` mode the held fragments leave through the
/// fragmentation slots, so they are sized like one and there are none
/// without fragmentation (`[fragmentation] enabled = false`): every fragment
/// that arrives before its first fragment is then `IPV4_FRAGMENT_HOLD_FULL`.
fn validate_fragment_tracking(
    source: crate::FragmentTrackingV1,
    fragmentation: Option<FragmentationStorageShapeV1>,
) -> Result<
    (
        Option<Ipv4FragmentTrackingPolicy>,
        Option<FragmentTrackingStorageShapeV1>,
    ),
    ValidationError,
> {
    let field = |name: &str| path(&["fragment-tracking", name]);
    if source.mode == crate::FragmentTrackingModeV1::Refuse {
        return Ok((None, None));
    }
    let policy = Ipv4FragmentTrackingPolicy::new(
        source.timeout_ms,
        source.entries_per_host,
        source.held_per_host,
    )
    .and_then(|policy| policy.with_ingress_share_percent(source.ingress_share_percent))
    .map_err(|error| {
        let name = match error {
            Ipv4FragmentTrackingPolicyError::EntriesPerHostZero => "entries-per-host",
            Ipv4FragmentTrackingPolicyError::IngressShareOutOfRange => "ingress-share-percent",
            _ => "timeout-ms",
        };
        ValidationError::new(ValidationCode::FragmentTrackingPolicy(error), field(name))
    })?;
    if source.entries == 0 {
        return Err(ValidationError::new(
            ValidationCode::FragmentTrackingEntriesZero,
            field("entries"),
        ));
    }
    if source.entries > crate::MAX_FRAGMENT_TRACKING_ENTRIES {
        return Err(ValidationError::bounded(
            ValidationCode::CapacityLimitExceeded,
            field("entries"),
            u64::from(crate::MAX_FRAGMENT_TRACKING_ENTRIES),
            u64::from(source.entries),
        ));
    }
    if source.held_fragments > crate::MAX_FRAGMENT_TRACKING_HELD {
        return Err(ValidationError::bounded(
            ValidationCode::CapacityLimitExceeded,
            field("held-fragments"),
            u64::from(crate::MAX_FRAGMENT_TRACKING_HELD),
            u64::from(source.held_fragments),
        ));
    }
    let (held, held_slot_bytes) = match fragmentation {
        Some(slots) if source.held_fragments > 0 => (source.held_fragments, slots.slot_bytes),
        _ => (0, 0),
    };
    let buckets = u32::try_from(ruster_core::ipv4_fragment_tracking_buckets(
        usize::try_from(source.entries).expect("bounded entries fit usize"),
    ))
    .expect("bounded entries have a u32 bucket count");
    Ok((
        Some(policy),
        Some(FragmentTrackingStorageShapeV1 {
            entries: source.entries,
            buckets,
            held,
            held_slot_bytes,
        }),
    ))
}

/// Validates `[resolution.hold]` (ARP-HOLD). Every bound present is
/// checked, also when the hold is off (fail closed). Nothing is held
/// without `[resolution]` (no ARP), with `enabled = false`, or without
/// fragmentation (a replayed datagram leaves through its slots, so a hold
/// slot is sized like one); `enabled = true` written without fragmentation
/// is refused rather than silently ignored.
fn validate_arp_hold(
    source: Option<crate::ResolutionHoldV1>,
    fragmentation: Option<FragmentationStorageShapeV1>,
) -> Result<(Option<ArpHoldPolicy>, Option<ArpHoldStorageShapeV1>), ValidationError> {
    let field = |name: &str| path(&["resolution", "hold", name]);
    let Some(source) = source else {
        return Ok((None, None));
    };
    let packets = source
        .packets
        .unwrap_or(ruster_core::ARP_HOLD_DEFAULT_PACKETS);
    if packets == 0 {
        return Err(ValidationError::new(
            ValidationCode::ArpHoldPacketsZero,
            field("packets"),
        ));
    }
    if packets > ruster_core::ARP_HOLD_MAX_PACKETS {
        return Err(ValidationError::bounded(
            ValidationCode::CapacityLimitExceeded,
            field("packets"),
            u64::from(ruster_core::ARP_HOLD_MAX_PACKETS),
            u64::from(packets),
        ));
    }
    let capped = |default: u16| default.min(u16::try_from(packets).unwrap_or(u16::MAX));
    let per_neighbor = source
        .per_neighbor
        .unwrap_or_else(|| capped(ruster_core::ARP_HOLD_DEFAULT_PER_NEIGHBOR));
    let per_host = source
        .per_host
        .unwrap_or_else(|| capped(ruster_core::ARP_HOLD_DEFAULT_PER_HOST));
    let per_ingress = source
        .per_ingress
        .unwrap_or_else(|| capped(u16::try_from(packets / 2).unwrap_or(u16::MAX).max(1)));
    let policy = ArpHoldPolicy::new(per_neighbor, per_host)
        .and_then(|policy| policy.with_per_ingress(per_ingress))
        .map_err(|error| {
            let name = match error {
                ArpHoldPolicyError::PerHost => "per-host",
                ArpHoldPolicyError::PerIngress => "per-ingress",
                _ => "per-neighbor",
            };
            ValidationError::new(ValidationCode::ArpHoldPolicy(error), field(name))
        })?;
    for (name, value) in [
        ("per-neighbor", per_neighbor),
        ("per-host", per_host),
        ("per-ingress", per_ingress),
    ] {
        if u32::from(value) > packets {
            return Err(ValidationError::bounded(
                ValidationCode::ArpHoldBoundAbovePackets,
                field(name),
                u64::from(packets),
                u64::from(value),
            ));
        }
    }
    if source.enabled == Some(false) {
        return Ok((None, None));
    }
    match fragmentation {
        Some(slots) => Ok((
            Some(policy),
            Some(ArpHoldStorageShapeV1 {
                packets,
                slot_bytes: slots.slot_bytes,
            }),
        )),
        None if source.enabled == Some(true) => Err(ValidationError::new(
            ValidationCode::ArpHoldWithoutFragmentation,
            field("enabled"),
        )),
        None => Ok((None, None)),
    }
}

/// Bounds of the `[health]` durations (milliseconds): 100 ms to one hour.
pub const HEALTH_MS_RANGE: (u64, u64) = (100, 3_600_000);
/// Bounds of `[health] link-probe-failures-fatal`.
pub const HEALTH_LINK_PROBE_FAILURES_RANGE: (u64, u64) = (1, 100);
/// Bounds of `[health] link-dump-interrupted-fatal`.
pub const HEALTH_LINK_DUMP_INTERRUPTED_RANGE: (u64, u64) = (1, 1_000);
/// Largest `[health] frames-quarantined-fatal` and
/// `tx-invalid-descs-fatal` (0 disables the fatal exit).
pub const HEALTH_INTEGRITY_FATAL_MAX: u64 = 1_000_000;
/// Bounds of `[watch] health-interval-ms`. At least 100 ms: `KICK_ERRORS`
/// needs growth in every sample and `FILL_STARVED` a sample without RX,
/// so a much shorter interval would sample between kick retries and
/// arrivals and rarely see either (PR #339 review L4).
pub const WATCH_HEALTH_INTERVAL_RANGE: (u64, u64) = (100, 60_000);
/// Bounds of `[watch] link-interval-ms`.
pub const WATCH_LINK_INTERVAL_RANGE: (u64, u64) = (100, 60_000);
/// Bounds of `[watch] link-stale-ms`.
pub const WATCH_LINK_STALE_RANGE: (u64, u64) = (1_000, 3_600_000);

/// Checks `value` of `table.key` against `range` (inclusive); `zero_ok`
/// also accepts 0 (a disabled fatal exit).
fn check_ops_value(
    code: ValidationCode,
    table: &str,
    key: &str,
    value: Option<u64>,
    range: (u64, u64),
    zero_ok: bool,
) -> Result<(), ValidationError> {
    let Some(value) = value else {
        return Ok(());
    };
    if zero_ok && value == 0 {
        return Ok(());
    }
    let (min, max) = range;
    if value < min {
        return Err(ValidationError::bounded(
            code,
            path(&[table, key]),
            min,
            value,
        ));
    }
    if value > max {
        return Err(ValidationError::bounded(
            code,
            path(&[table, key]),
            max,
            value,
        ));
    }
    Ok(())
}

/// Bounded validation of `[health]` (OPS-LOG): every key in range and a
/// nonzero `tx-stall-fatal-ms` at least `tx-stall-warn-ms` when both are
/// set (the CLI checks the merged values again, with the flag fallback).
fn validate_health(health: HealthV1) -> Result<HealthV1, ValidationError> {
    let code = ValidationCode::HealthValueOutOfRange;
    for (key, value, range, zero_ok) in [
        (
            "tx-stall-warn-ms",
            health.tx_stall_warn_ms,
            HEALTH_MS_RANGE,
            false,
        ),
        (
            "tx-stall-fatal-ms",
            health.tx_stall_fatal_ms,
            HEALTH_MS_RANGE,
            true,
        ),
        (
            "kick-errors-fatal-ms",
            health.kick_errors_fatal_ms,
            HEALTH_MS_RANGE,
            true,
        ),
        (
            "fill-starved-warn-ms",
            health.fill_starved_warn_ms,
            HEALTH_MS_RANGE,
            false,
        ),
        (
            "link-probe-failures-fatal",
            health.link_probe_failures_fatal,
            HEALTH_LINK_PROBE_FAILURES_RANGE,
            false,
        ),
        (
            "link-dump-interrupted-fatal",
            health.link_dump_interrupted_fatal,
            HEALTH_LINK_DUMP_INTERRUPTED_RANGE,
            false,
        ),
        (
            "frames-quarantined-fatal",
            health.frames_quarantined_fatal,
            (1, HEALTH_INTEGRITY_FATAL_MAX),
            true,
        ),
        (
            "tx-invalid-descs-fatal",
            health.tx_invalid_descs_fatal,
            (1, HEALTH_INTEGRITY_FATAL_MAX),
            true,
        ),
    ] {
        check_ops_value(code, "health", key, value, range, zero_ok)?;
    }
    if let (Some(warn), Some(fatal)) = (health.tx_stall_warn_ms, health.tx_stall_fatal_ms) {
        if fatal != 0 && fatal < warn {
            return Err(ValidationError::bounded(
                ValidationCode::HealthFatalBelowWarning,
                path(&["health", "tx-stall-fatal-ms"]),
                warn,
                fatal,
            ));
        }
    }
    Ok(health)
}

/// Bounded validation of `[watch]` (OPS-LOG).
fn validate_watch(watch: WatchV1) -> Result<WatchV1, ValidationError> {
    let code = ValidationCode::WatchIntervalOutOfRange;
    for (key, value, range) in [
        (
            "health-interval-ms",
            watch.health_interval_ms,
            WATCH_HEALTH_INTERVAL_RANGE,
        ),
        (
            "link-interval-ms",
            watch.link_interval_ms,
            WATCH_LINK_INTERVAL_RANGE,
        ),
        ("link-stale-ms", watch.link_stale_ms, WATCH_LINK_STALE_RANGE),
    ] {
        check_ops_value(code, "watch", key, value, range, false)?;
    }
    Ok(watch)
}

/// The longest IPv4 datagram an AF_XDP frame can carry: the largest
/// supported chunk (4096 bytes) minus the kernel's XDP headroom and the
/// Ethernet header, 3826 bytes. Fragmentation slots are at least this long
/// (MTU2 part B), so every datagram a production port receives fits a slot
/// whatever the device MTU.
pub const FRAGMENTATION_MIN_SLOT_DATAGRAM: u16 = 4096 - 256 - 14;

const _: () = {
    let mut largest = 0;
    let mut index = 0;
    while index < SUPPORTED_ALIGNED_CHUNK_SIZES.len() {
        if SUPPORTED_ALIGNED_CHUNK_SIZES[index] > largest {
            largest = SUPPORTED_ALIGNED_CHUNK_SIZES[index];
        }
        index += 1;
    }
    assert!(
        largest as u64 - XDP_PACKET_HEADROOM as u64 - 14 == FRAGMENTATION_MIN_SLOT_DATAGRAM as u64
    );
};

/// The fewest frames of a fragment set: a fragmented datagram has at least
/// two fragments.
const FRAGMENT_SET_MIN_FRAMES: u32 = 2;

/// The frames a backend keeps for the router's own single frames (ARP,
/// ICMP errors) out of the room it offers a fragment set: `max(2, frames /
/// 8)`, capped at `frames`. The AF_XDP adapter's `generated_reserve` and
/// the AF_PACKET engine's `tx_router_reserve` use this formula.
const fn router_reserve(frames: u32) -> u32 {
    let eighth = frames / 8;
    let reserve = if eighth > 2 { eighth } else { 2 };
    if reserve < frames {
        reserve
    } else {
        frames
    }
}

/// With fragmentation on, every port must offer a fragment set room for at
/// least two fragments beyond its router reserve; otherwise every DF-clear
/// datagram above an MTU would commit its state and then be dropped
/// (`dropped_unavailable`) every time. AF_XDP: `generated-frames` (the TX
/// ring is at least 64). AF_PACKET: the TX ring frames. Both need at least
/// 4 (`FRAGMENTATION_BACKEND_ROOM_TOO_SMALL`, fail closed at the port).
fn check_fragment_set_room(
    backend: &ValidatedBackendV1,
    interfaces: &[InterfaceBindingV1],
    port_names: &[String],
) -> Result<(), ValidationError> {
    let source_index = |interface: IfId| {
        interfaces
            .iter()
            .find(|binding| binding.id() == interface)
            .and_then(|binding| port_names.iter().position(|name| name == binding.name()))
            .unwrap_or(0)
    };
    let too_small = |frames: u32| frames - router_reserve(frames) < FRAGMENT_SET_MIN_FRAMES;
    match backend {
        ValidatedBackendV1::Sim => Ok(()),
        ValidatedBackendV1::AfXdp(af_xdp) => {
            for port in af_xdp.ports() {
                let frames = port.umem().generated_frames();
                if too_small(frames) {
                    let base =
                        indexed_nested_path("backend", "ports", source_index(port.interface()));
                    return Err(ValidationError::new(
                        ValidationCode::FragmentationBackendRoomTooSmall,
                        child_path(&base, "generated-frames"),
                    ));
                }
            }
            Ok(())
        }
        ValidatedBackendV1::AfPacket(af_packet) => {
            for port in af_packet.ports() {
                if too_small(port.tx().frame_count()) {
                    let mut base = path(&["backend", "af-packet", "ports"]);
                    base.push_index(source_index(port.interface()));
                    return Err(ValidationError::new(
                        ValidationCode::FragmentationBackendRoomTooSmall,
                        child_path(&base, "tx"),
                    ));
                }
            }
            Ok(())
        }
    }
}

/// The longest IPv4 datagram an AF_PACKET port receives (its frame minus the
/// Ethernet header); 0 for the other backends.
fn af_packet_received_datagram(backend: &ValidatedBackendV1) -> u16 {
    match backend {
        ValidatedBackendV1::AfPacket(af_packet) => u16::try_from(
            af_packet
                .max_frame_len()
                .saturating_sub(ruster_core::ETHERNET_HEADER_LEN as u32),
        )
        .unwrap_or(u16::MAX),
        ValidatedBackendV1::Sim | ValidatedBackendV1::AfXdp(_) => 0,
    }
}

/// Validates `[backend]` against the validated interfaces.
///
/// Every check is bounded (at most [`crate::MAX_BACKEND_PORTS`] ports, each
/// compared with the earlier ones) and uses checked or widened arithmetic.
/// Ports are checked in source order, fields in schema order; the result is
/// sorted by IfId.
fn validate_backend(
    source: BackendV1,
    interfaces: &[InterfaceBindingV1],
) -> Result<ValidatedBackendV1, ValidationError> {
    let ports_path = path(&["backend", "ports"]);
    if source.kind != BackendKindV1::AfXdp && !source.ports.is_empty() {
        return Err(ValidationError::new(
            ValidationCode::BackendPortsWithoutAfXdp,
            ports_path,
        ));
    }
    if source.kind != BackendKindV1::AfPacket && source.af_packet.is_some() {
        return Err(ValidationError::new(
            ValidationCode::BackendAfPacketWithoutKind,
            path(&["backend", "af-packet"]),
        ));
    }
    match source.kind {
        BackendKindV1::Sim => return Ok(ValidatedBackendV1::Sim),
        BackendKindV1::AfPacket => {
            return validate_af_packet(source.af_packet.unwrap_or_default(), interfaces)
                .map(ValidatedBackendV1::AfPacket);
        }
        BackendKindV1::AfXdp => {}
    }
    if source.ports.is_empty() {
        return Err(ValidationError::new(
            ValidationCode::BackendNoPorts,
            ports_path,
        ));
    }

    let mut ports: Vec<ValidatedAfXdpPortV1> = Vec::with_capacity(source.ports.len());
    let mut umem_bytes = 0_u64;
    for (index, port) in source.ports.iter().enumerate() {
        let mut base = ports_path.clone();
        base.push_index(index);
        let validated = validate_af_xdp_port(port, interfaces, &ports, &base)?;
        umem_bytes = umem_bytes
            .checked_add(validated.umem.byte_len())
            .filter(|total| *total <= MAX_AF_XDP_UMEM_BYTES)
            .ok_or_else(|| {
                ValidationError::bounded(
                    ValidationCode::BackendTotalUmemTooLarge,
                    child_path(&base, "frame-count"),
                    MAX_AF_XDP_UMEM_BYTES,
                    umem_bytes.saturating_add(validated.umem.byte_len()),
                )
            })?;
        ports.push(validated);
    }
    for (index, interface) in interfaces.iter().enumerate() {
        if !ports.iter().any(|port| port.interface == interface.id) {
            return Err(ValidationError::new(
                ValidationCode::BackendInterfaceUnbound,
                child_path(&indexed_path("interfaces", index), "name"),
            ));
        }
    }
    ports.sort_unstable_by_key(|port| port.interface);
    Ok(ValidatedBackendV1::AfXdp(ValidatedAfXdpV1 {
        existing_program: source.existing_xdp_program,
        ports: ports.into_boxed_slice(),
        umem_bytes,
    }))
}

/// Validates `[backend.af-packet]`: the maximum frame, then each port in
/// source order (interface, RX ring, TX ring, ring bytes), then that every
/// interface has a port. Bounded like [`validate_backend`]; the result is
/// sorted by IfId.
fn validate_af_packet(
    source: AfPacketV1,
    interfaces: &[InterfaceBindingV1],
) -> Result<ValidatedAfPacketV1, ValidationError> {
    let base = path(&["backend", "af-packet"]);
    let max_frame_len = source.max_frame_len.unwrap_or(DEFAULT_AF_PACKET_FRAME_LEN);
    if !(MIN_AF_PACKET_FRAME_LEN..=MAX_AF_PACKET_FRAME_LEN).contains(&max_frame_len) {
        let limit = if max_frame_len < MIN_AF_PACKET_FRAME_LEN {
            MIN_AF_PACKET_FRAME_LEN
        } else {
            MAX_AF_PACKET_FRAME_LEN
        };
        return Err(ValidationError::bounded(
            ValidationCode::BackendMaxFrameLenOutOfRange,
            child_path(&base, "max-frame-len"),
            u64::from(limit),
            u64::from(max_frame_len),
        ));
    }
    let ports_path = child_path(&base, "ports");
    if source.ports.is_empty() {
        return Err(ValidationError::new(
            ValidationCode::BackendNoPorts,
            ports_path,
        ));
    }
    let mut ports: Vec<ValidatedAfPacketPortV1> = Vec::with_capacity(source.ports.len());
    let mut ring_bytes = 0_u64;
    for (index, port) in source.ports.iter().enumerate() {
        let mut port_path = ports_path.clone();
        port_path.push_index(index);
        let validated =
            validate_af_packet_port(port, interfaces, &ports, max_frame_len, &port_path)?;
        let bytes = validated.rx.byte_len() + validated.tx.byte_len();
        ring_bytes = ring_bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_AF_PACKET_RING_BYTES)
            .ok_or_else(|| {
                ValidationError::bounded(
                    ValidationCode::BackendTotalRingTooLarge,
                    child_path(&port_path, "rx"),
                    MAX_AF_PACKET_RING_BYTES,
                    ring_bytes.saturating_add(bytes),
                )
            })?;
        ports.push(validated);
    }
    for (index, interface) in interfaces.iter().enumerate() {
        if !ports.iter().any(|port| port.interface == interface.id) {
            return Err(ValidationError::new(
                ValidationCode::BackendInterfaceUnbound,
                child_path(&indexed_path("interfaces", index), "name"),
            ));
        }
    }
    ports.sort_unstable_by_key(|port| port.interface);
    Ok(ValidatedAfPacketV1 {
        max_frame_len,
        ports: ports.into_boxed_slice(),
        ring_bytes,
    })
}

/// The smallest power-of-two frame slot that holds `offset` bytes of
/// TPACKET header and a `max_frame_len` frame, `TPACKET_ALIGNMENT`
/// aligned (both bounded, so nothing overflows).
const fn af_packet_frame_size(offset: u32, max_frame_len: u32) -> u32 {
    let aligned = (offset + max_frame_len).div_ceil(AF_PACKET_ALIGNMENT) * AF_PACKET_ALIGNMENT;
    aligned.next_power_of_two()
}

fn validate_af_packet_port(
    port: &AfPacketPortV1,
    interfaces: &[InterfaceBindingV1],
    earlier: &[ValidatedAfPacketPortV1],
    max_frame_len: u32,
    base: &SourcePath,
) -> Result<ValidatedAfPacketPortV1, ValidationError> {
    let binding = interfaces
        .iter()
        .find(|binding| binding.name() == port.interface)
        .ok_or_else(|| {
            ValidationError::new(
                ValidationCode::UnknownInterface,
                child_path(base, "interface"),
            )
        })?;
    let interface = binding.id();
    // Interface devices are unique, so the same IfId is the same device.
    if earlier.iter().any(|other| other.interface == interface) {
        return Err(ValidationError::new(
            ValidationCode::BackendDuplicateInterface,
            child_path(base, "interface"),
        ));
    }
    let rx_path = child_path(base, "rx");
    let rx_frame = af_packet_frame_size(AF_PACKET_RX_MAC_OFFSET, max_frame_len);
    // An RX block holds its descriptor, then a packet header and the frame.
    let rx_minimum =
        (AF_PACKET_BLOCK_HEADER + AF_PACKET_RX_MAC_OFFSET + max_frame_len).max(rx_frame);
    let rx = af_packet_ring(
        port.rx.block_size,
        port.rx.block_count,
        rx_frame,
        rx_minimum,
        &rx_path,
    )?;
    if !(1..=MAX_AF_PACKET_RETIRE_TIMEOUT_MS).contains(&port.rx.retire_timeout_ms) {
        let limit = if port.rx.retire_timeout_ms == 0 {
            1
        } else {
            MAX_AF_PACKET_RETIRE_TIMEOUT_MS
        };
        return Err(ValidationError::bounded(
            ValidationCode::BackendRetireTimeoutOutOfRange,
            child_path(&rx_path, "retire-timeout-ms"),
            u64::from(limit),
            u64::from(port.rx.retire_timeout_ms),
        ));
    }
    let rx = AfPacketRingV1 {
        retire_timeout_ms: port.rx.retire_timeout_ms,
        ..rx
    };
    let tx_frame = af_packet_frame_size(AF_PACKET_TX_DATA_OFFSET, max_frame_len);
    let tx = af_packet_ring(
        port.tx.block_size,
        port.tx.block_count,
        tx_frame,
        tx_frame,
        &child_path(base, "tx"),
    )?;
    let bytes = rx.byte_len() + tx.byte_len();
    if bytes > MAX_AF_PACKET_RING_BYTES_PER_PORT {
        return Err(ValidationError::bounded(
            ValidationCode::BackendRingTooLarge,
            rx_path,
            MAX_AF_PACKET_RING_BYTES_PER_PORT,
            bytes,
        ));
    }
    Ok(ValidatedAfPacketPortV1 {
        interface,
        device: binding.device().into(),
        rx,
        tx,
    })
}

/// One ring's `block-size` and `block-count` with the derived frame slot.
fn af_packet_ring(
    block_size: u32,
    block_count: u32,
    frame_size: u32,
    minimum_block: u32,
    base: &SourcePath,
) -> Result<AfPacketRingV1, ValidationError> {
    let size_path = child_path(base, "block-size");
    if !block_size.is_power_of_two()
        || !(MIN_AF_PACKET_BLOCK_SIZE..=MAX_AF_PACKET_BLOCK_SIZE).contains(&block_size)
    {
        return Err(ValidationError::new(
            ValidationCode::BackendBlockSizeInvalid,
            size_path,
        ));
    }
    // Both are powers of two: a block at least as large as the frame slot
    // is a whole number of slots.
    if block_size < minimum_block {
        return Err(ValidationError::bounded(
            ValidationCode::BackendBlockTooSmall,
            size_path,
            u64::from(minimum_block.next_power_of_two()),
            u64::from(block_size),
        ));
    }
    if !(1..=MAX_AF_PACKET_BLOCK_COUNT).contains(&block_count) {
        let limit = if block_count == 0 {
            1
        } else {
            MAX_AF_PACKET_BLOCK_COUNT
        };
        return Err(ValidationError::bounded(
            ValidationCode::BackendBlockCountOutOfRange,
            child_path(base, "block-count"),
            u64::from(limit),
            u64::from(block_count),
        ));
    }
    Ok(AfPacketRingV1 {
        block_size,
        block_count,
        frame_size,
        retire_timeout_ms: 0,
    })
}

fn validate_af_xdp_port(
    port: &AfXdpPortV1,
    interfaces: &[InterfaceBindingV1],
    earlier: &[ValidatedAfXdpPortV1],
    base: &SourcePath,
) -> Result<ValidatedAfXdpPortV1, ValidationError> {
    let binding = interfaces
        .iter()
        .find(|binding| binding.name() == port.interface)
        .ok_or_else(|| {
            ValidationError::new(
                ValidationCode::UnknownInterface,
                child_path(base, "interface"),
            )
        })?;
    let interface = binding.id();
    let queue_path = child_path(base, "queue");
    if port.queue > MAX_AF_XDP_QUEUE_ID {
        return Err(ValidationError::bounded(
            ValidationCode::BackendQueueOutOfRange,
            queue_path,
            u64::from(MAX_AF_XDP_QUEUE_ID),
            u64::from(port.queue),
        ));
    }
    // Interface devices are unique, so the same IfId is the same device.
    if let Some(other) = earlier.iter().find(|other| other.interface == interface) {
        let code = if other.queue == port.queue {
            ValidationCode::BackendDuplicateQueue
        } else {
            ValidationCode::BackendMultipleQueuesPerInterface
        };
        return Err(ValidationError::new(code, queue_path));
    }
    if port.mode != AfXdpModeV1::Copy && port.xdp_attach == XdpAttachModeV1::Generic {
        return Err(ValidationError::new(
            ValidationCode::BackendModeRequiresNativeAttach,
            child_path(base, "mode"),
        ));
    }
    if !port.need_wakeup {
        return Err(ValidationError::new(
            ValidationCode::BackendNeedWakeupRequired,
            child_path(base, "need-wakeup"),
        ));
    }

    let rings_path = child_path(base, "rings");
    let crate::AfXdpRingsV1 {
        fill,
        rx,
        tx,
        completion,
    } = port.rings;
    for (name, entries) in [
        ("fill", fill),
        ("rx", rx),
        ("tx", tx),
        ("completion", completion),
    ] {
        let ring_path = child_path(&rings_path, name);
        if !entries.is_power_of_two() {
            return Err(ValidationError::new(
                ValidationCode::BackendRingNotPowerOfTwo,
                ring_path,
            ));
        }
        let limit = if entries < MIN_AF_XDP_RING_ENTRIES {
            Some(MIN_AF_XDP_RING_ENTRIES)
        } else if entries > MAX_AF_XDP_RING_ENTRIES {
            Some(MAX_AF_XDP_RING_ENTRIES)
        } else {
            None
        };
        if let Some(limit) = limit {
            return Err(ValidationError::bounded(
                ValidationCode::BackendRingOutOfRange,
                ring_path,
                u64::from(limit),
                u64::from(entries),
            ));
        }
    }
    if completion < tx {
        return Err(ValidationError::bounded(
            ValidationCode::BackendCompletionRingTooSmall,
            child_path(&rings_path, "completion"),
            u64::from(tx),
            u64::from(completion),
        ));
    }

    let frame_size_path = child_path(base, "frame-size");
    if !SUPPORTED_ALIGNED_CHUNK_SIZES.contains(&port.frame_size) {
        return Err(ValidationError::new(
            ValidationCode::BackendFrameSizeUnsupported,
            frame_size_path,
        ));
    }
    // frame-size >= 2048 > 256 + 1514, so the subtraction cannot wrap.
    let max_headroom = port.frame_size - XDP_PACKET_HEADROOM - MIN_AF_XDP_VISIBLE_FRAME_BYTES;
    if port.headroom > max_headroom {
        return Err(ValidationError::bounded(
            ValidationCode::BackendHeadroomTooLarge,
            child_path(base, "headroom"),
            u64::from(max_headroom),
            u64::from(port.headroom),
        ));
    }
    if port.generated_frames == 0 {
        return Err(ValidationError::new(
            ValidationCode::BackendGeneratedFramesZero,
            child_path(base, "generated-frames"),
        ));
    }
    let frame_count_path = child_path(base, "frame-count");
    // u32 + u32 + u32 cannot overflow u64.
    let required = u64::from(fill) + u64::from(tx) + u64::from(port.generated_frames);
    if u64::from(port.frame_count) < required {
        return Err(ValidationError::bounded(
            ValidationCode::BackendFrameCountTooSmall,
            frame_count_path,
            required,
            u64::from(port.frame_count),
        ));
    }
    // u32 * u32 cannot overflow u64.
    let byte_len = u64::from(port.frame_count) * u64::from(port.frame_size);
    if byte_len > MAX_AF_XDP_UMEM_BYTES_PER_PORT {
        return Err(ValidationError::bounded(
            ValidationCode::BackendUmemTooLarge,
            frame_count_path,
            MAX_AF_XDP_UMEM_BYTES_PER_PORT,
            byte_len,
        ));
    }

    let native = |_| ValidationError::new(ValidationCode::BackendNativeProfile, base.clone());
    let mode_flag = match port.mode {
        AfXdpModeV1::Copy => XDP_COPY,
        AfXdpModeV1::ZeroCopy => XDP_ZEROCOPY,
        AfXdpModeV1::Auto => 0,
    };
    let bind_flags = ValidatedBindFlags::new(XDP_USE_NEED_WAKEUP | mode_flag).map_err(native)?;
    debug_assert_eq!(
        bind_flags.mode(),
        match port.mode {
            AfXdpModeV1::Copy => BindMode::CopyRequired,
            AfXdpModeV1::ZeroCopy => BindMode::ZeroCopyRequired,
            AfXdpModeV1::Auto => BindMode::Automatic,
        }
    );
    let rings = RingConfig::new(fill, rx, tx, completion).map_err(native)?;
    // frame-count >= required > generated-frames, so this cannot wrap.
    let rx_frames = port.frame_count - port.generated_frames;
    let umem = UmemConfig::new(
        port.frame_count,
        port.frame_size,
        port.headroom,
        rx_frames,
        port.generated_frames,
        0,
    )
    .map_err(native)?;
    Ok(ValidatedAfXdpPortV1 {
        interface,
        device: binding.device().into(),
        queue: port.queue,
        mode: port.mode,
        bind_flags,
        attach: port.xdp_attach,
        rings,
        umem,
    })
}

fn preflight_public_dto(config: &ConfigV1) -> Result<(), ValidationError> {
    for (field, actual, limit) in [
        ("interfaces", config.interfaces.len(), crate::MAX_INTERFACES),
        ("addresses", config.addresses.len(), crate::MAX_ADDRESSES),
        ("routes", config.routes.len(), crate::MAX_ROUTES),
        ("neighbors", config.neighbors.len(), crate::MAX_NEIGHBORS),
    ] {
        check_list_bound(path(&[field]), actual, limit)?;
    }
    if let Some(firewall) = &config.firewall {
        check_list_bound(
            path(&["firewall", "rules"]),
            firewall.rules.len(),
            crate::MAX_FIREWALL_RULES,
        )?;
    }
    if let Some(backend) = &config.backend {
        check_list_bound(
            path(&["backend", "ports"]),
            backend.ports.len(),
            crate::MAX_BACKEND_PORTS,
        )?;
        if let Some(af_packet) = &backend.af_packet {
            check_list_bound(
                path(&["backend", "af-packet", "ports"]),
                af_packet.ports.len(),
                crate::MAX_BACKEND_PORTS,
            )?;
        }
    }

    let mut text = TextBudget { used: 0 };
    for (index, interface) in config.interfaces.iter().enumerate() {
        let base = indexed_path("interfaces", index);
        text.add(&interface.name, child_path(&base, "name"))?;
        text.add(&interface.device, child_path(&base, "device"))?;
        text.add(&interface.mac, child_path(&base, "mac"))?;
    }
    for (index, address) in config.addresses.iter().enumerate() {
        let base = indexed_path("addresses", index);
        text.add(&address.interface, child_path(&base, "interface"))?;
        text.add(&address.ipv4, child_path(&base, "ipv4"))?;
    }
    for (index, route) in config.routes.iter().enumerate() {
        let base = indexed_path("routes", index);
        text.add(&route.prefix, child_path(&base, "prefix"))?;
        text.add(&route.egress, child_path(&base, "egress"))?;
        if let Some(via) = &route.via {
            text.add(via, child_path(&base, "via"))?;
        }
    }
    for (index, neighbor) in config.neighbors.iter().enumerate() {
        let base = indexed_path("neighbors", index);
        text.add(&neighbor.interface, child_path(&base, "interface"))?;
        text.add(&neighbor.address, child_path(&base, "address"))?;
        text.add(&neighbor.mac, child_path(&base, "mac"))?;
    }
    if let Some(nat44) = &config.nat44 {
        text.add(&nat44.realm.inside, path(&["nat44", "realm", "inside"]))?;
        text.add(&nat44.realm.outside, path(&["nat44", "realm", "outside"]))?;
        text.add(
            &nat44.realm.public_address,
            path(&["nat44", "realm", "public-address"]),
        )?;
        if let Some(udp) = &nat44.udp {
            text.add(
                udp.allocator_seed.expose(),
                path(&["nat44", "udp", "allocator-seed"]),
            )?;
        }
        if let Some(tcp) = &nat44.tcp {
            text.add(
                tcp.allocator_seed.expose(),
                path(&["nat44", "tcp", "allocator-seed"]),
            )?;
        }
        if let Some(seed) = nat44
            .icmp
            .as_ref()
            .and_then(|icmp| icmp.allocator_seed.as_ref())
        {
            text.add(seed.expose(), path(&["nat44", "icmp", "allocator-seed"]))?;
        }
    }
    if let Some(firewall) = &config.firewall {
        for (index, rule) in firewall.rules.iter().enumerate() {
            let base = indexed_nested_path("firewall", "rules", index);
            if let Some(ingress) = &rule.ingress {
                text.add(ingress, child_path(&base, "ingress"))?;
            }
            if let Some(egress) = &rule.egress {
                text.add(egress, child_path(&base, "egress"))?;
            }
            text.add(&rule.source, child_path(&base, "source"))?;
            text.add(&rule.destination, child_path(&base, "destination"))?;
        }
    }
    if let Some(backend) = &config.backend {
        for (index, port) in backend.ports.iter().enumerate() {
            let base = indexed_nested_path("backend", "ports", index);
            text.add(&port.interface, child_path(&base, "interface"))?;
        }
    }
    Ok(())
}

fn check_list_bound(path: SourcePath, actual: usize, limit: usize) -> Result<(), ValidationError> {
    if actual > limit {
        return Err(ValidationError::bounded(
            ValidationCode::ListTooLong,
            path,
            u64::try_from(limit).unwrap_or(u64::MAX),
            u64::try_from(actual).unwrap_or(u64::MAX),
        ));
    }
    Ok(())
}

struct TextBudget {
    used: usize,
}

impl TextBudget {
    fn add(&mut self, value: &str, path: SourcePath) -> Result<(), ValidationError> {
        self.used = self.used.checked_add(value.len()).ok_or_else(|| {
            ValidationError::bounded(
                ValidationCode::TextTooLarge,
                path.clone(),
                crate::MAX_CONFIG_BYTES as u64,
                u64::MAX,
            )
        })?;
        if self.used > crate::MAX_CONFIG_BYTES {
            return Err(ValidationError::bounded(
                ValidationCode::TextTooLarge,
                path,
                crate::MAX_CONFIG_BYTES as u64,
                u64::try_from(self.used).unwrap_or(u64::MAX),
            ));
        }
        Ok(())
    }
}

/// Port pool of one NAT44 protocol and whether its per-host mapping limit
/// is set (N3).
/// Port (or identifier) pool of a datagram NAT44 table and the limit key
/// that adds its per-host storage, if any (N3, N6).
type NatStorageInputs = ((u16, u16), Option<&'static str>);

/// The key that adds a datagram NAT44 runtime's per-host storage: the
/// mapping limit if set, else the peer limit if set (N3, N6), so a byte
/// budget error names a key the operator actually set.
fn per_host_key(mappings_per_host: u16, peers_per_host: u16) -> Option<&'static str> {
    if mappings_per_host != 0 {
        Some("mappings-per-host")
    } else if peers_per_host != 0 {
        Some("peers-per-host")
    } else {
        None
    }
}
/// TCP port pool and whether its per-host mapping (N3) and session (N6)
/// limits are set.
type TcpStorageInputs = ((u16, u16), (bool, bool));

struct StorageInputs {
    resolution: Option<crate::ResolutionCapacityV1>,
    /// Interfaces of the document: one announcement slot each (ARP-033).
    interfaces: u32,
    icmp: Option<crate::Icmpv4ErrorCapacityV1>,
    udp: Option<(crate::Nat44UdpCapacityV1, NatStorageInputs)>,
    tcp: Option<(crate::Nat44TcpCapacityV1, TcpStorageInputs)>,
    /// ICMP query NAT (N5): capacity, identifier pool, per-host limit set.
    icmp_query: Option<(crate::Nat44IcmpCapacityV1, NatStorageInputs)>,
    firewall_states: Option<u32>,
    fragmentation: Option<FragmentationStorageShapeV1>,
    fragment_tracking: Option<FragmentTrackingStorageShapeV1>,
    arp_hold: Option<ArpHoldStorageShapeV1>,
}

fn build_storage_shape(
    inputs: StorageInputs,
    limits: ValidationLimits,
) -> Result<RuntimeStorageShapeV1, ValidationError> {
    let mut bytes = 0usize;
    let resolution = inputs
        .resolution
        .map(|capacity| {
            for (field, value, quote) in [
                ("states", capacity.states, false),
                ("actions", capacity.actions, false),
                ("dynamic-neighbors", capacity.dynamic_neighbors, false),
                ("failure-holds", capacity.failure_holds, true),
            ] {
                let path = path(&["resolution", "capacity", field]);
                if quote {
                    check_quote_slots(value, limits, path)?;
                } else {
                    check_slots(value, limits, path)?;
                }
            }
            add_bytes::<ResolutionStateSlot>(
                &mut bytes,
                capacity.states,
                path(&["resolution", "capacity", "states"]),
            )?;
            add_bytes::<ResolutionActionSlot>(
                &mut bytes,
                capacity.actions,
                path(&["resolution", "capacity", "actions"]),
            )?;
            add_bytes::<DynamicNeighborSlot>(
                &mut bytes,
                capacity.dynamic_neighbors,
                path(&["resolution", "capacity", "dynamic-neighbors"]),
            )?;
            add_bytes::<ResolutionFailureHoldSlot>(
                &mut bytes,
                capacity.failure_holds,
                path(&["resolution", "capacity", "failure-holds"]),
            )?;
            add_bytes::<ruster_core::ArpAnnounceSlot>(
                &mut bytes,
                inputs.interfaces,
                path(&["interfaces"]),
            )?;
            Ok(ResolutionStorageShapeV1 {
                states: capacity.states,
                actions: capacity.actions,
                dynamic_neighbors: capacity.dynamic_neighbors,
                failure_holds: capacity.failure_holds,
                announce_slots: inputs.interfaces,
            })
        })
        .transpose()?;
    let icmpv4_errors = inputs
        .icmp
        .map(|capacity| {
            check_slots(
                capacity.states,
                limits,
                path(&["icmpv4-errors", "capacity", "states"]),
            )?;
            check_quote_slots(
                capacity.actions,
                limits,
                path(&["icmpv4-errors", "capacity", "actions"]),
            )?;
            add_bytes::<Icmpv4ErrorStateSlot>(
                &mut bytes,
                capacity.states,
                path(&["icmpv4-errors", "capacity", "states"]),
            )?;
            add_bytes::<Icmpv4ErrorActionSlot>(
                &mut bytes,
                capacity.actions,
                path(&["icmpv4-errors", "capacity", "actions"]),
            )?;
            Ok(Icmpv4ErrorStorageShapeV1 {
                states: capacity.states,
                actions: capacity.actions,
            })
        })
        .transpose()?;
    let nat44_udp = inputs
        .udp
        .map(|(capacity, (ports, per_host))| {
            let shape = udp_shape(capacity, ports, per_host.is_some(), limits)?;
            add_bytes::<Nat44UdpMappingSlot>(
                &mut bytes,
                shape.mappings,
                path(&["nat44", "udp", "capacity", "mappings"]),
            )?;
            add_bytes::<Nat44UdpPeerSlot>(
                &mut bytes,
                shape.peers,
                path(&["nat44", "udp", "capacity", "peers"]),
            )?;
            add_directory_bytes(&mut bytes, shape.mapping_buckets, shape.mapping_nodes)?;
            add_directory_bytes(&mut bytes, shape.peer_buckets, shape.peer_nodes)?;
            add_port_owner_bytes(&mut bytes, shape.port_owners)?;
            add_host_bytes::<1>(
                &mut bytes,
                shape.hosts,
                shape.mapping_buckets,
                PEER_COUNTING,
                path(&["nat44", "udp", per_host.unwrap_or("mappings-per-host")]),
            )?;
            Ok(shape)
        })
        .transpose()?;
    let nat44_tcp = inputs
        .tcp
        .map(|(capacity, (ports, per_host))| {
            let shape = tcp_shape(capacity, ports, per_host, limits)?;
            add_bytes::<Nat44TcpMappingSlot>(
                &mut bytes,
                shape.mappings,
                path(&["nat44", "tcp", "capacity", "mappings"]),
            )?;
            add_bytes::<Nat44TcpSessionSlot>(
                &mut bytes,
                shape.sessions,
                path(&["nat44", "tcp", "capacity", "sessions"]),
            )?;
            add_directory_bytes(&mut bytes, shape.mapping_buckets, shape.mapping_nodes)?;
            add_directory_bytes(&mut bytes, shape.session_buckets, shape.session_nodes)?;
            // Session remote-address directory: same dimensions.
            add_directory_bytes(&mut bytes, shape.session_buckets, shape.session_nodes)?;
            add_port_owner_bytes(&mut bytes, shape.port_owners)?;
            add_bytes::<Nat44TcpSynHoldSlot>(
                &mut bytes,
                shape.unsolicited_syn_holds,
                path(&["nat44", "tcp", "capacity", "unsolicited-syn-holds"]),
            )?;
            add_host_bytes::<2>(
                &mut bytes,
                shape.hosts,
                shape.mapping_buckets,
                LISTS_ONLY,
                path(&["nat44", "tcp", "mappings-per-host"]),
            )?;
            add_host_bytes::<3>(
                &mut bytes,
                shape.session_hosts,
                shape.session_buckets,
                LINK_WORDS,
                path(&["nat44", "tcp", "sessions-per-host"]),
            )?;
            Ok(shape)
        })
        .transpose()?;
    let nat44_icmp = inputs
        .icmp_query
        .map(|(capacity, (identifiers, per_host))| {
            let shape = icmp_shape(capacity, identifiers, per_host.is_some(), limits)?;
            add_bytes::<Nat44UdpMappingSlot>(
                &mut bytes,
                shape.mappings,
                path(&["nat44", "icmp", "capacity", "mappings"]),
            )?;
            add_bytes::<Nat44UdpPeerSlot>(
                &mut bytes,
                shape.peers,
                path(&["nat44", "icmp", "capacity", "peers"]),
            )?;
            add_directory_bytes(&mut bytes, shape.mapping_buckets, shape.mapping_nodes)?;
            add_directory_bytes(&mut bytes, shape.peer_buckets, shape.peer_nodes)?;
            add_port_owner_bytes(&mut bytes, shape.identifier_owners)?;
            add_host_bytes::<1>(
                &mut bytes,
                shape.hosts,
                shape.mapping_buckets,
                PEER_COUNTING,
                path(&["nat44", "icmp", per_host.unwrap_or("mappings-per-host")]),
            )?;
            Ok(shape)
        })
        .transpose()?;
    if let Some(states) = inputs.firewall_states {
        check_slots(states, limits, path(&["firewall", "capacity", "states"]))?;
        add_bytes::<FirewallStateSlot>(
            &mut bytes,
            states,
            path(&["firewall", "capacity", "states"]),
        )?;
    }
    if let Some(shape) = inputs.fragmentation {
        let datagrams_path = path(&["fragmentation", "datagrams"]);
        add_bytes::<Ipv4FragmentSlot>(&mut bytes, shape.datagrams, datagrams_path.clone())?;
        let slot_bytes = usize::try_from(shape.slot_bytes).map_err(|_| {
            ValidationError::new(
                ValidationCode::CapacityNotRepresentable,
                datagrams_path.clone(),
            )
        })?;
        let datagrams = usize::try_from(shape.datagrams).map_err(|_| {
            ValidationError::new(
                ValidationCode::CapacityNotRepresentable,
                datagrams_path.clone(),
            )
        })?;
        let arena = datagrams
            .checked_mul(slot_bytes)
            .and_then(|arena| bytes.checked_add(arena))
            .ok_or_else(|| {
                ValidationError::new(ValidationCode::CapacityArithmeticOverflow, datagrams_path)
            })?;
        bytes = arena;
    }
    if let Some(shape) = inputs.fragment_tracking {
        let entries_path = path(&["fragment-tracking", "entries"]);
        add_bytes::<Ipv4FragmentEntrySlot>(&mut bytes, shape.entries, entries_path.clone())?;
        add_bytes::<Ipv4FragmentHostSlot>(&mut bytes, shape.entries, entries_path.clone())?;
        for _ in 0..2 {
            add_bytes::<DirectoryBucket>(&mut bytes, shape.buckets, entries_path.clone())?;
            add_bytes::<DirectoryNode>(&mut bytes, shape.entries, entries_path.clone())?;
        }
        // Tombstones of evicted allowing or poisoned keys, with their own
        // directory: derived from the entries.
        let tombstones = u32::try_from(ruster_core::ipv4_fragment_tracking_tombstones(
            usize::try_from(shape.entries).expect("bounded entries fit usize"),
        ))
        .expect("bounded entries have a u32 tombstone count");
        let tombstone_buckets = u32::try_from(ruster_core::ipv4_fragment_tracking_buckets(
            usize::try_from(tombstones).expect("u32 fits usize"),
        ))
        .expect("bounded tombstones have a u32 bucket count");
        add_bytes::<Ipv4FragmentTombstoneSlot>(&mut bytes, tombstones, entries_path.clone())?;
        add_bytes::<DirectoryBucket>(&mut bytes, tombstone_buckets, entries_path.clone())?;
        add_bytes::<DirectoryNode>(&mut bytes, tombstones, entries_path.clone())?;
        let held_path = path(&["fragment-tracking", "held-fragments"]);
        add_bytes::<Ipv4FragmentHeldSlot>(&mut bytes, shape.held, held_path.clone())?;
        let arena = usize::try_from(u64::from(shape.held) * u64::from(shape.held_slot_bytes))
            .ok()
            .and_then(|arena| bytes.checked_add(arena))
            .ok_or_else(|| {
                ValidationError::new(ValidationCode::CapacityArithmeticOverflow, held_path)
            })?;
        bytes = arena;
    }
    let before_hold = bytes;
    if let Some(shape) = inputs.arp_hold {
        let packets_path = path(&["resolution", "hold", "packets"]);
        add_bytes::<ArpHoldSlot>(&mut bytes, shape.packets, packets_path.clone())?;
        let arena = usize::try_from(u64::from(shape.packets) * u64::from(shape.slot_bytes))
            .ok()
            .and_then(|arena| bytes.checked_add(arena))
            .ok_or_else(|| {
                ValidationError::new(ValidationCode::CapacityArithmeticOverflow, packets_path)
            })?;
        bytes = arena;
    }
    if bytes > limits.max_runtime_bytes {
        // A document that fits without the ARP hold (ARP-HOLD made the
        // default storage larger) points at `[resolution.hold]`: lower
        // `packets` or set `enabled = false`.
        let hint = if inputs.arp_hold.is_some() && before_hold <= limits.max_runtime_bytes {
            path(&["resolution", "hold", "packets"])
        } else {
            SourcePath::default()
        };
        return Err(ValidationError::bounded(
            ValidationCode::RuntimeStorageBytesExceeded,
            hint,
            u64::try_from(limits.max_runtime_bytes).unwrap_or(u64::MAX),
            u64::try_from(bytes).unwrap_or(u64::MAX),
        ));
    }
    Ok(RuntimeStorageShapeV1 {
        resolution,
        icmpv4_errors,
        nat44_udp,
        nat44_tcp,
        nat44_icmp,
        firewall_states: inputs.firewall_states,
        fragmentation: inputs.fragmentation,
        fragment_tracking: inputs.fragment_tracking,
        arp_hold: inputs.arp_hold,
        required_bytes: bytes,
    })
}

fn icmp_shape(
    capacity: crate::Nat44IcmpCapacityV1,
    identifiers: (u16, u16),
    per_host: bool,
    limits: ValidationLimits,
) -> Result<Nat44IcmpStorageShapeV1, ValidationError> {
    let mapping_path = path(&["nat44", "icmp", "capacity", "mappings"]);
    let peer_path = path(&["nat44", "icmp", "capacity", "peers"]);
    check_slots(capacity.mappings, limits, mapping_path.clone())?;
    check_slots(capacity.peers, limits, peer_path.clone())?;
    let mapping_buckets = directory_buckets(capacity.mappings, limits, mapping_path)?;
    let peer_buckets = directory_buckets(capacity.peers, limits, peer_path)?;
    let identifier_owners = port_count(identifiers);
    check_slots(
        identifier_owners,
        limits,
        path(&["nat44", "icmp", "identifiers"]),
    )?;
    Ok(Nat44IcmpStorageShapeV1 {
        mappings: capacity.mappings,
        peers: capacity.peers,
        mapping_buckets,
        mapping_nodes: capacity.mappings,
        peer_buckets,
        peer_nodes: capacity.peers,
        identifier_owners,
        hosts: if per_host { capacity.mappings } else { 0 },
    })
}

fn udp_shape(
    capacity: crate::Nat44UdpCapacityV1,
    ports: (u16, u16),
    per_host: bool,
    limits: ValidationLimits,
) -> Result<Nat44UdpStorageShapeV1, ValidationError> {
    let mapping_path = path(&["nat44", "udp", "capacity", "mappings"]);
    let peer_path = path(&["nat44", "udp", "capacity", "peers"]);
    check_slots(capacity.mappings, limits, mapping_path.clone())?;
    check_slots(capacity.peers, limits, peer_path.clone())?;
    let mapping_buckets = directory_buckets(capacity.mappings, limits, mapping_path)?;
    let peer_buckets = directory_buckets(capacity.peers, limits, peer_path)?;
    let port_owners = port_count(ports);
    check_slots(port_owners, limits, path(&["nat44", "realm", "ports"]))?;
    Ok(Nat44UdpStorageShapeV1 {
        mappings: capacity.mappings,
        peers: capacity.peers,
        mapping_buckets,
        mapping_nodes: capacity.mappings,
        peer_buckets,
        peer_nodes: capacity.peers,
        port_owners,
        hosts: if per_host { capacity.mappings } else { 0 },
    })
}

fn tcp_shape(
    capacity: crate::Nat44TcpCapacityV1,
    ports: (u16, u16),
    (per_host, sessions_per_host): (bool, bool),
    limits: ValidationLimits,
) -> Result<Nat44TcpStorageShapeV1, ValidationError> {
    let mapping_path = path(&["nat44", "tcp", "capacity", "mappings"]);
    let session_path = path(&["nat44", "tcp", "capacity", "sessions"]);
    check_slots(capacity.mappings, limits, mapping_path.clone())?;
    check_slots(capacity.sessions, limits, session_path.clone())?;
    let mapping_buckets = directory_buckets(capacity.mappings, limits, mapping_path)?;
    let session_buckets = directory_buckets(capacity.sessions, limits, session_path)?;
    let port_owners = port_count(ports);
    check_slots(port_owners, limits, path(&["nat44", "realm", "ports"]))?;
    check_quote_slots(
        capacity.unsolicited_syn_holds,
        limits,
        path(&["nat44", "tcp", "capacity", "unsolicited-syn-holds"]),
    )?;
    Ok(Nat44TcpStorageShapeV1 {
        mappings: capacity.mappings,
        sessions: capacity.sessions,
        mapping_buckets,
        mapping_nodes: capacity.mappings,
        session_buckets,
        session_nodes: capacity.sessions,
        port_owners,
        unsolicited_syn_holds: capacity.unsolicited_syn_holds,
        hosts: if per_host { capacity.mappings } else { 0 },
        session_hosts: if sessions_per_host {
            capacity.sessions
        } else {
            0
        },
    })
}

fn directory_buckets(
    capacity: u32,
    limits: ValidationLimits,
    path: SourcePath,
) -> Result<u32, ValidationError> {
    let buckets = if capacity == 0 {
        0
    } else {
        capacity.checked_next_power_of_two().ok_or_else(|| {
            ValidationError::new(ValidationCode::CapacityNotRepresentable, path.clone())
        })?
    };
    check_slots(buckets, limits, path)?;
    Ok(buckets)
}

fn check_slots(
    slots: u32,
    limits: ValidationLimits,
    path: SourcePath,
) -> Result<(), ValidationError> {
    if slots > limits.max_slots_per_table {
        return Err(ValidationError::bounded(
            ValidationCode::CapacityLimitExceeded,
            path,
            u64::from(limits.max_slots_per_table),
            u64::from(slots),
        ));
    }
    usize::try_from(slots)
        .map(|_| ())
        .map_err(|_| ValidationError::new(ValidationCode::CapacityNotRepresentable, path))
}

/// [`check_slots`], then the bound of a table whose slots hold a quote.
fn check_quote_slots(
    slots: u32,
    limits: ValidationLimits,
    path: SourcePath,
) -> Result<(), ValidationError> {
    check_slots(slots, limits, path.clone())?;
    if slots > limits.max_quote_slots_per_table {
        return Err(ValidationError::bounded(
            ValidationCode::CapacityLimitExceeded,
            path,
            u64::from(limits.max_quote_slots_per_table),
            u64::from(slots),
        ));
    }
    Ok(())
}

fn add_directory_bytes(bytes: &mut usize, buckets: u32, nodes: u32) -> Result<(), ValidationError> {
    add_bytes::<DirectoryBucket>(bytes, buckets, SourcePath::default())?;
    add_bytes::<DirectoryNode>(bytes, nodes, SourcePath::default())
}

/// The UDP and ICMP query host tables count filter peers (N6): a link word
/// and a host counter per host slot.
const PEER_COUNTING: (bool, bool) = (true, true);
/// The TCP mapping host table (N3) has lists only.
const LISTS_ONLY: (bool, bool) = (false, false);
/// The TCP session host table (N6) has a link word per session slot.
const LINK_WORDS: (bool, bool) = (true, false);

/// Per-host accounting of one NAT44 table with `LISTS` host lists (N3,
/// N6): one link and one host slot per host, a host directory of `hosts`
/// nodes and, when there are hosts, the accounted table's directory bucket
/// count (`buckets`), and the link words and host counters the table needs
/// (`optional`). `path` names the limit that adds it.
fn add_host_bytes<const LISTS: usize>(
    bytes: &mut usize,
    hosts: u32,
    buckets: u32,
    (words, counters): (bool, bool),
    path: SourcePath,
) -> Result<(), ValidationError> {
    add_bytes::<Nat44HostLink>(bytes, hosts, path.clone())?;
    add_bytes::<ruster_core::Nat44HostSlot<LISTS>>(bytes, hosts, path.clone())?;
    add_bytes::<u32>(bytes, if words { hosts } else { 0 }, path.clone())?;
    add_bytes::<ruster_core::Nat44HostCounter>(bytes, if counters { hosts } else { 0 }, path)?;
    add_directory_bytes(bytes, if hosts == 0 { 0 } else { buckets }, hosts)
}

/// One port-owner slot per pool port plus the free-port bitmap words
/// (`ruster_core::port_free_bitmap_words`) of one NAT44 protocol.
fn add_port_owner_bytes(bytes: &mut usize, port_owners: u32) -> Result<(), ValidationError> {
    let ports = path(&["nat44", "realm", "ports"]);
    add_bytes::<PortOwnerSlot>(bytes, port_owners, ports.clone())?;
    let words = usize::try_from(port_owners)
        .ok()
        .map(port_free_bitmap_words)
        .and_then(|words| u32::try_from(words).ok())
        .ok_or_else(|| {
            ValidationError::new(ValidationCode::CapacityNotRepresentable, ports.clone())
        })?;
    add_bytes::<u64>(bytes, words, ports)
}

fn add_bytes<T>(bytes: &mut usize, count: u32, path: SourcePath) -> Result<(), ValidationError> {
    let count = usize::try_from(count).map_err(|_| {
        ValidationError::new(ValidationCode::CapacityNotRepresentable, path.clone())
    })?;
    let required = count.checked_mul(size_of::<T>()).ok_or_else(|| {
        ValidationError::new(ValidationCode::CapacityArithmeticOverflow, path.clone())
    })?;
    *bytes = bytes
        .checked_add(required)
        .ok_or_else(|| ValidationError::new(ValidationCode::CapacityArithmeticOverflow, path))?;
    Ok(())
}

fn port_count((first, last): (u16, u16)) -> u32 {
    u32::from(last) - u32::from(first) + 1
}

const fn map_filtering(filtering: Nat44FilteringV1) -> Nat44Filtering {
    match filtering {
        Nat44FilteringV1::EndpointIndependent => Nat44Filtering::EndpointIndependent,
        Nat44FilteringV1::AddressDependent => Nat44Filtering::AddressDependent,
        Nat44FilteringV1::AddressAndPortDependent => Nat44Filtering::AddressAndPortDependent,
    }
}

const fn map_inbound_rst(policy: Nat44TcpInboundRstV1) -> ruster_core::Nat44TcpInboundRst {
    match policy {
        Nat44TcpInboundRstV1::Closing => ruster_core::Nat44TcpInboundRst::Closing,
        Nat44TcpInboundRstV1::Corroborate => ruster_core::Nat44TcpInboundRst::Corroborate,
    }
}

fn map_icmp_policy(policy: Nat44Icmpv4ErrorsV1) -> Nat44Icmpv4ErrorPolicy {
    match policy {
        Nat44Icmpv4ErrorsV1::Disabled => Nat44Icmpv4ErrorPolicy::Disabled,
        Nat44Icmpv4ErrorsV1::ExternalOnly => Nat44Icmpv4ErrorPolicy::ExternalOnly,
        Nat44Icmpv4ErrorsV1::Bidirectional => Nat44Icmpv4ErrorPolicy::Bidirectional,
    }
}

fn parse_seed(value: &str, path: SourcePath) -> Result<u64, ValidationError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ValidationError::new(
            ValidationCode::InvalidAllocatorSeed,
            path,
        ));
    }
    let parsed = value.parse::<u64>().map_err(|_: ParseIntError| {
        ValidationError::new(ValidationCode::InvalidAllocatorSeed, path.clone())
    })?;
    if parsed.to_string() != value {
        return Err(ValidationError::new(
            ValidationCode::NonCanonicalAllocatorSeed,
            path,
        ));
    }
    Ok(parsed)
}

fn parse_mac(value: &str, path: SourcePath) -> Result<MacAddress, ValidationError> {
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 6
        || parts
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(ValidationError::new(ValidationCode::InvalidMac, path));
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(ValidationError::new(ValidationCode::NonCanonicalMac, path));
    }
    let mut octets = [0u8; 6];
    for (index, part) in parts.into_iter().enumerate() {
        octets[index] = u8::from_str_radix(part, 16)
            .map_err(|_| ValidationError::new(ValidationCode::InvalidMac, path.clone()))?;
    }
    if octets == [0; 6] || octets == [0xff; 6] || octets[0] & 1 != 0 {
        return Err(ValidationError::new(ValidationCode::MacNotUnicast, path));
    }
    Ok(MacAddress(octets))
}

fn parse_ipv4(value: &str, path: SourcePath) -> Result<Ipv4Address, ValidationError> {
    let parsed = value
        .parse::<Ipv4Addr>()
        .map_err(|_| ValidationError::new(ValidationCode::InvalidIpv4, path.clone()))?;
    if parsed.to_string() != value {
        return Err(ValidationError::new(ValidationCode::NonCanonicalIpv4, path));
    }
    Ok(Ipv4Address::from_octets(parsed.octets()))
}

fn parse_cidr(value: &str, path: SourcePath) -> Result<ParsedCidr, ValidationError> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| ValidationError::new(ValidationCode::InvalidIpv4Prefix, path.clone()))?;
    if prefix.is_empty()
        || !prefix.bytes().all(|byte| byte.is_ascii_digit())
        || (prefix.len() > 1 && prefix.starts_with('0'))
    {
        return Err(ValidationError::new(
            ValidationCode::NonCanonicalIpv4Prefix,
            path,
        ));
    }
    let prefix_len = prefix
        .parse::<u8>()
        .ok()
        .filter(|prefix| *prefix <= 32)
        .ok_or_else(|| ValidationError::new(ValidationCode::InvalidIpv4Prefix, path.clone()))?;
    Ok(ParsedCidr {
        address: parse_ipv4(address, path)?,
        prefix_len,
    })
}

fn is_basic_host(address: Ipv4Address) -> bool {
    let octets = address.octets();
    !address.is_unspecified()
        && octets[0] != 0
        && octets[0] != 127
        && octets[0] < 224
        && octets != [255; 4]
}

fn is_host_for_prefix(address: Ipv4Address, prefix_len: u8) -> bool {
    if !is_basic_host(address) {
        return false;
    }
    if prefix_len >= 31 {
        return true;
    }
    let value = u32::from_be_bytes(address.octets());
    let mask = prefix_mask(prefix_len);
    value != value & mask && value != value | !mask
}

fn route_host_matches(route: Route, address: Ipv4Address) -> bool {
    let value = u32::from_be_bytes(address.octets());
    let prefix = u32::from_be_bytes(route.prefix().octets());
    let mask = prefix_mask(route.prefix_len());
    value & mask == prefix && is_host_for_prefix(address, route.prefix_len())
}

fn network_address(address: Ipv4Address, prefix_len: u8) -> Ipv4Address {
    Ipv4Address::from_octets(
        (u32::from_be_bytes(address.octets()) & prefix_mask(prefix_len)).to_be_bytes(),
    )
}

fn prefix_mask(prefix_len: u8) -> u32 {
    match prefix_len {
        0 => 0,
        1..=32 => u32::MAX << (32 - u32::from(prefix_len)),
        _ => unreachable!("CIDR parser validates prefix length"),
    }
}

fn route_prefix_key(route: Route) -> (u32, u8) {
    (
        u32::from_be_bytes(route.prefix().octets()),
        route.prefix_len(),
    )
}

fn route_sort_key(route: Route) -> (u32, u8, u16, u32) {
    let next_hop = route
        .next_hop()
        .map_or(0, |address| u32::from_be_bytes(address.octets()));
    let (prefix, prefix_len) = route_prefix_key(route);
    (prefix, prefix_len, route.egress().0, next_hop)
}

fn path(fields: &[&str]) -> SourcePath {
    let Some((first, rest)) = fields.split_first() else {
        return SourcePath::default();
    };
    let mut path = SourcePath::root_field(*first);
    for field in rest {
        path.push_field(*field);
    }
    path
}

fn indexed_path(field: &str, index: usize) -> SourcePath {
    let mut path = SourcePath::root_field(field);
    path.push_index(index);
    path
}

fn indexed_nested_path(field: &str, nested: &str, index: usize) -> SourcePath {
    let mut path = SourcePath::root_field(field);
    path.push_field(nested);
    path.push_index(index);
    path
}

fn child_path(parent: &SourcePath, field: &str) -> SourcePath {
    let mut path = parent.clone();
    path.push_field(field);
    path
}
