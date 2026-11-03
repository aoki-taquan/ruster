#![forbid(unsafe_code)]
//! Versioned declarative configuration parsing and cold semantic validation.
//!
//! Parsing preserves the exact V1 source schema. Semantic validation resolves
//! names, canonicalizes order-independent tables, synthesizes connected routes,
//! and owns canonical core tables without minting a publication identity.
//! Publication generations, fresh hash-key generation, planning, and apply
//! belong to later control-plane stages.

mod diagnostic;
mod model;
mod parse;
mod validate;

pub use diagnostic::{Diagnostic, DiagnosticCode, PathSegment, SourcePath};
pub use model::{
    AddressV1, AfPacketPortV1, AfPacketRxRingV1, AfPacketTxRingV1, AfPacketV1, AfXdpModeV1,
    AfXdpPortV1, AfXdpRingsV1, AllocatorSeedV1, ArpV1, BackendKindV1, BackendV1, ConfigV1,
    ExistingXdpProgramV1, ExitProtectionV1, FirewallActionV1, FirewallCapacityV1, FirewallPolicyV1,
    FirewallProtocolV1, FirewallRuleV1, FirewallV1, FragmentTrackingModeV1, FragmentTrackingV1,
    FragmentationV1, HealthV1, Icmpv4ErrorCapacityV1, Icmpv4ErrorGenerateV1, Icmpv4ErrorPolicyV1,
    Icmpv4ErrorTranslatedV1, Icmpv4ErrorV1, InterfaceV1, Ipv4OriginV1, Nat44FilteringV1,
    Nat44IcmpCapacityV1, Nat44IcmpV1, Nat44Icmpv4ErrorsV1, Nat44PortRangeV1, Nat44RealmV1,
    Nat44TcpCapacityV1, Nat44TcpInboundRstV1, Nat44TcpV1, Nat44UdpCapacityV1, Nat44UdpV1, Nat44V1,
    NeighborV1, ReloadStateV1, ReloadV1, ResolutionCapacityV1, ResolutionHoldV1,
    ResolutionPolicyV1, ResolutionV1, RouteV1, TickBudgetV1, VersionedConfig, WatchV1,
    XdpAttachModeV1, DEFAULT_FRAGMENTATION_DATAGRAMS, DEFAULT_FRAGMENT_TRACKING_ENTRIES,
    DEFAULT_FRAGMENT_TRACKING_ENTRIES_PER_HOST, DEFAULT_FRAGMENT_TRACKING_HELD,
    DEFAULT_FRAGMENT_TRACKING_HELD_PER_HOST, DEFAULT_TICK_GENERATED_FRAGMENTS,
    DEFAULT_UNSOLICITED_SYN_HOLDS, MAX_FRAGMENTATION_DATAGRAMS, MAX_FRAGMENT_TRACKING_ENTRIES,
    MAX_FRAGMENT_TRACKING_HELD, MAX_TICK_GENERATED_FRAGMENTS,
};
pub use parse::{
    parse, MAX_ADDRESSES, MAX_BACKEND_PORTS, MAX_CONFIG_BYTES, MAX_FIREWALL_RULES, MAX_INTERFACES,
    MAX_NEIGHBORS, MAX_ROUTES, SCHEMA_VERSION_V1,
};
pub use validate::{
    validate, AfPacketRingV1, ArpHoldStorageShapeV1, FragmentTrackingStorageShapeV1,
    FragmentationStorageShapeV1, Icmpv4ErrorStorageShapeV1, InterfaceBindingV1,
    Nat44IcmpStorageShapeV1, Nat44TcpStorageShapeV1, Nat44UdpStorageShapeV1,
    ResolutionStorageShapeV1, RuntimeStorageShapeV1, TickBudgetsV1, ValidatedAfPacketPortV1,
    ValidatedAfPacketV1, ValidatedAfXdpPortV1, ValidatedAfXdpV1, ValidatedArpHoldV1,
    ValidatedBackendV1, ValidatedConfig, ValidatedConfigV1, ValidatedFirewallV1,
    ValidatedFragmentTrackingV1, ValidatedFragmentationV1, ValidatedIcmpv4ErrorV1,
    ValidatedNat44IcmpV1, ValidatedNat44TcpV1, ValidatedNat44UdpV1, ValidatedNat44V1,
    ValidatedResolutionV1, ValidationCode, ValidationError, ValidationLimits,
    DEFAULT_AF_PACKET_FRAME_LEN, FRAGMENTATION_MIN_SLOT_DATAGRAM, HEALTH_INTEGRITY_FATAL_MAX,
    HEALTH_LINK_DUMP_INTERRUPTED_RANGE, HEALTH_LINK_PROBE_FAILURES_RANGE, HEALTH_MS_RANGE,
    MAX_AF_PACKET_BLOCK_COUNT, MAX_AF_PACKET_BLOCK_SIZE, MAX_AF_PACKET_FRAME_LEN,
    MAX_AF_PACKET_RETIRE_TIMEOUT_MS, MAX_AF_PACKET_RING_BYTES, MAX_AF_PACKET_RING_BYTES_PER_PORT,
    MAX_AF_XDP_QUEUE_ID, MAX_AF_XDP_RING_ENTRIES, MAX_AF_XDP_UMEM_BYTES,
    MAX_AF_XDP_UMEM_BYTES_PER_PORT, MAX_INTERFACE_LABEL_BYTES, MIN_AF_PACKET_BLOCK_SIZE,
    MIN_AF_PACKET_FRAME_LEN, MIN_AF_XDP_RING_ENTRIES, MIN_AF_XDP_VISIBLE_FRAME_BYTES,
    PRODUCTION_VALIDATION_LIMITS, WATCH_HEALTH_INTERVAL_RANGE, WATCH_LINK_INTERVAL_RANGE,
    WATCH_LINK_STALE_RANGE,
};
