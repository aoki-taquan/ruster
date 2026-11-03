#![forbid(unsafe_code)]
#![doc = "A small, allocation-free IPv4 and ARP packet-processing core."]

mod arp_hold;
mod checksum;
mod firewall;
mod fixed_directory;
mod forwarding;
mod generated;
mod icmpv4_error;
mod icmpv4_translated_limit;
mod io;
mod ipv4_fragment_tracking;
mod ipv4_fragmentation;
mod nat44;
mod nat44_host_quota;
mod nat44_ipv4_id;
mod nat44_syn_hold;
mod nat44_tcp_state;
mod observability;
mod packet;
mod reload_state;
mod resolution;
#[cfg(test)]
mod resolution_reference;
mod route;
mod slot_index;
mod slot_list;

pub use arp_hold::{
    ArpHoldCounters, ArpHoldPolicy, ArpHoldPolicyError, ArpHoldRuntime, ArpHoldSlot,
    ArpHoldStorageError, ARP_HOLD_DEFAULT_PACKETS, ARP_HOLD_DEFAULT_PER_HOST,
    ARP_HOLD_DEFAULT_PER_NEIGHBOR, ARP_HOLD_MAX_PACKETS, ARP_HOLD_MAX_PER_NEIGHBOR,
};
pub use checksum::{internet_checksum, ipv4_header_checksum, rfc1624_update};
#[cfg(feature = "validation-test-hooks")]
#[doc(hidden)]
pub use firewall::take_full_firewall_validation_count;
pub use firewall::{
    validate_firewall_rules, FirewallAction, FirewallAuditBuffer, FirewallAuditRecord,
    FirewallCommitError, FirewallConfig, FirewallConfigError, FirewallConnectionClass,
    FirewallCounters, FirewallDisposition, FirewallFailure, FirewallHashKey, FirewallHashKeyError,
    FirewallInterface, FirewallIpv4Prefix, FirewallIpv4PrefixError, FirewallPlanError,
    FirewallPolicy, FirewallPolicyError, FirewallPolicySource, FirewallPortRange,
    FirewallPortRangeError, FirewallProtocol, FirewallReconcileError, FirewallReconcilePermit,
    FirewallReconcileReport, FirewallRelatedIcmpv4Error, FirewallRelatedIcmpv4Flow, FirewallRule,
    FirewallRuleId, FirewallRuntime, FirewallStateSlot, FirewallTcpPhase, FirewallVerdict,
    ValidatedFirewallOwner, FIREWALL_CARRY_REEVALUATION_BUDGET, FIREWALL_CARRY_ROUTE_LOOKUP_WEIGHT,
    FIREWALL_MAX_IDLE_TTL_MS, FIREWALL_TCP_ACTIVE_DEFAULT_IDLE_TTL_MS,
    FIREWALL_TCP_ACTIVE_MIN_IDLE_TTL_MS, FIREWALL_TCP_OPENING_DEFAULT_IDLE_TTL_MS,
    FIREWALL_TCP_OPENING_MIN_IDLE_TTL_MS, FIREWALL_UDP_DEFAULT_IDLE_TTL_MS,
    FIREWALL_UDP_MIN_IDLE_TTL_MS,
};
pub use fixed_directory::{port_free_bitmap_words, DirectoryBucket, DirectoryNode, PortOwnerSlot};
#[cfg(feature = "validation-test-hooks")]
#[doc(hidden)]
pub use forwarding::take_full_forwarding_validation_count;
pub use forwarding::{
    dispatch_nat44_tcp_unsolicited_syns, Nat44TcpUnsolicitedSynDispatchError,
    Nat44TcpUnsolicitedSynDispatchReport, Nat44TcpUnsolicitedSynDisposition,
};
pub use forwarding::{
    forward_batch, forward_batch_with_firewall, forward_batch_with_firewall_and_icmpv4_errors,
    forward_batch_with_firewall_and_icmpv4_errors_audited, forward_batch_with_firewall_audited,
    forward_batch_with_nat44_tcp, forward_batch_with_nat44_tcp_and_icmpv4_errors,
    forward_batch_with_nat44_udp, forward_batch_with_nat44_udp_and_icmpv4_errors,
    forward_batch_with_nat44_udp_and_tcp, forward_batch_with_nat44_udp_and_tcp_and_firewall,
    forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors,
    forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors_audited,
    forward_batch_with_nat44_udp_and_tcp_and_firewall_audited,
    forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors,
    forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors_and_fragment_tracking,
    forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors_and_fragment_tracking_and_arp_hold,
    forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors_and_fragmentation,
    forward_batch_with_nat44_udp_and_tcp_and_icmp_and_icmpv4_errors,
    forward_batch_with_nat44_udp_and_tcp_and_icmpv4_errors, forward_batch_with_resolution,
    forward_batch_with_resolution_and_icmpv4_errors, replay_arp_holds, ArpPolicy, BatchReport,
    DropReason, ForwardingSnapshot, Ipv4OriginPolicy, Ipv4OriginPolicyError,
    Nat44Icmpv4Disposition, NoTrace, SnapshotError, TraceEvent, TraceSink,
    ValidatedForwardingOwner, ValidatedForwardingOwnerError,
};
pub use generated::{
    GeneratedAllocationError, GeneratedBatchCompletion, GeneratedPacketBatch, GeneratedPacketIo,
    GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion,
};
pub use icmpv4_error::{
    execute_one_icmpv4_error, execute_one_icmpv4_time_exceeded, ExecuteIcmpv4Error,
    ExecuteIcmpv4TimeExceededError, GeneratedIcmpv4Report, GeneratedIcmpv4Trace,
    GeneratedIcmpv4TraceSink, Icmpv4ErrorAction, Icmpv4ErrorActionSlot, Icmpv4ErrorBuildError,
    Icmpv4ErrorCounters, Icmpv4ErrorDisposition, Icmpv4ErrorKind, Icmpv4ErrorPolicy,
    Icmpv4ErrorPolicyError, Icmpv4ErrorPublicationError, Icmpv4ErrorPublicationPermit,
    Icmpv4ErrorPublicationReport, Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot,
    Icmpv4TimeExceededAction, Icmpv4TimeExceededBuildError, Icmpv4TimeExceededDisposition,
    NoGeneratedIcmpv4Trace, ICMPV4_DEFAULT_FRAGMENTATION_NEEDED_INTERVAL_MS,
    ICMPV4_DEFAULT_PORT_UNREACHABLE_INTERVAL_MS, ICMPV4_ERROR_MAX_FRAME_LEN,
    ICMPV4_ERROR_MAX_QUOTE_LEN, ICMPV4_TIME_EXCEEDED_MAX_FRAME_LEN,
    ICMPV4_TIME_EXCEEDED_MAX_QUOTE_LEN,
};
pub use icmpv4_translated_limit::{
    ICMPV4_DEFAULT_TRANSLATED_BURST, ICMPV4_DEFAULT_TRANSLATED_RATE_PER_SECOND,
    ICMPV4_MAX_TRANSLATED_LIMIT, ICMPV4_TRANSLATED_LIMIT_BUCKETS,
};
pub use io::{
    BatchCompletion, ConsumeReason, PacketBatch, PacketIo, PacketLease, PacketSlot,
    PublicationQuiescence, PublicationQuiescenceDisposition, PublicationQuiescenceGuard,
    PublicationQuiescenceWitness, SlotCompletion,
};
pub use ipv4_fragment_tracking::{
    ipv4_fragment_tracking_buckets, ipv4_fragment_tracking_ingress_cap,
    ipv4_fragment_tracking_tombstones, Ipv4FragmentEntrySlot, Ipv4FragmentHeldSlot,
    Ipv4FragmentHostSlot, Ipv4FragmentTombstoneSlot, Ipv4FragmentTracker,
    Ipv4FragmentTrackingCounters, Ipv4FragmentTrackingPolicy, Ipv4FragmentTrackingPolicyError,
    Ipv4FragmentTrackingStorage, Ipv4FragmentTrackingStorageError,
    IPV4_FRAGMENT_TRACKING_DEFAULT_INGRESS_SHARE_PERCENT,
    IPV4_FRAGMENT_TRACKING_DEFAULT_TIMEOUT_MS, IPV4_FRAGMENT_TRACKING_HELD_PER_DATAGRAM,
    IPV4_FRAGMENT_TRACKING_MAX_INGRESSES, IPV4_FRAGMENT_TRACKING_MAX_TIMEOUT_MS,
    IPV4_FRAGMENT_TRACKING_MIN_TIMEOUT_MS,
};
pub use ipv4_fragmentation::{
    execute_one_ipv4_fragmentation, ipv4_fragment_slot_bytes, GeneratedIpv4FragmentReport,
    Ipv4FragmentOutcome, Ipv4FragmentSlot, Ipv4FragmentationCounters, Ipv4FragmentationPolicy,
    Ipv4FragmentationPolicyError, Ipv4FragmentationRuntime, Ipv4FragmentationStorageError,
    IPV4_FRAGMENTATION_DEFAULT_MAX_FRAGMENTS, IPV4_FRAGMENTATION_MAX_FRAGMENTS,
    IPV4_FRAGMENTATION_MIN_MAX_FRAGMENTS,
};
pub use nat44::{
    Nat44CarryIdentity, Nat44Filtering, Nat44IcmpConfig, Nat44IcmpConfigError, Nat44IcmpCounters,
    Nat44IcmpDisposition, Nat44IcmpHashKey, Nat44IcmpHashKeyError, Nat44IcmpIndexStorage,
    Nat44IcmpMappingSlot, Nat44IcmpOccupancy, Nat44IcmpPeerSlot, Nat44IcmpPolicy,
    Nat44IcmpPolicyError, Nat44IcmpReconcileError, Nat44IcmpReconcilePermit,
    Nat44IcmpReconcileReport, Nat44IcmpRuntime, Nat44IcmpRuntimeConfigError, Nat44IcmpStorageShape,
    Nat44Icmpv4ErrorPolicy, Nat44TcpConfig, Nat44TcpConfigError, Nat44TcpCounters,
    Nat44TcpDisposition, Nat44TcpHashKey, Nat44TcpHashKeyError, Nat44TcpIndexStorage,
    Nat44TcpMappingSlot, Nat44TcpOccupancy, Nat44TcpPolicy, Nat44TcpPolicyError,
    Nat44TcpReconcileError, Nat44TcpReconcilePermit, Nat44TcpReconcileReport, Nat44TcpRuntime,
    Nat44TcpRuntimeConfigError, Nat44TcpSessionSlot, Nat44TcpStorageShape, Nat44UdpConfig,
    Nat44UdpConfigError, Nat44UdpCounters, Nat44UdpDisposition, Nat44UdpHashKey,
    Nat44UdpHashKeyError, Nat44UdpIndexStorage, Nat44UdpMappingSlot, Nat44UdpOccupancy,
    Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpPolicyError, Nat44UdpReconcileError,
    Nat44UdpReconcilePermit, Nat44UdpReconcileReport, Nat44UdpRuntime, Nat44UdpRuntimeConfigError,
    Nat44UdpStorageShape, NAT44_DEFAULT_MAPPINGS_PER_HOST, NAT44_DEFAULT_STATE_PER_HOST,
    NAT44_ICMP_DEFAULT_IDLE_TTL_MS, NAT44_ICMP_MAX_IDLE_TTL_MS, NAT44_ICMP_MIN_IDLE_TTL_MS,
    NAT44_PORT_TAKEOVER_PROBES, NAT44_TCP_DEFAULT_IDLE_TTL_MS,
    NAT44_TCP_DEFAULT_INBOUND_SESSIONS_PER_REMOTE, NAT44_TCP_DEFAULT_TRANSITORY_IDLE_TTL_MS,
    NAT44_TCP_INBOUND_SLOT_PROBES, NAT44_TCP_MAX_IDLE_TTL_MS,
    NAT44_TCP_MAX_INBOUND_SESSIONS_PER_REMOTE, NAT44_TCP_MIN_IDLE_TTL_MS,
    NAT44_TCP_MIN_TRANSITORY_IDLE_TTL_MS, NAT44_UDP_DEFAULT_IDLE_TTL_MS, NAT44_UDP_MAX_IDLE_TTL_MS,
    NAT44_UDP_MIN_IDLE_TTL_MS,
};
pub use nat44_host_quota::{
    Nat44HostCounter, Nat44HostLink, Nat44HostSlot, Nat44HostStorage, Nat44TcpHostSlot,
    Nat44TcpSessionHostSlot, Nat44UdpHostSlot,
};
pub use nat44_syn_hold::{
    Nat44TcpSynHoldSlot, NAT44_TCP_SYN_HOLD_CHAIN_LIMIT, NAT44_TCP_UNSOLICITED_SYN_CLOCK_MARGIN_MS,
    NAT44_TCP_UNSOLICITED_SYN_HOLD_MS,
};
pub use nat44_tcp_state::{Nat44TcpInboundRst, Nat44TcpSessionPhase};
pub(crate) use observability::OccupancyCounter;
pub use observability::{
    BackendMode, BackendStats, FieldValue, FieldVisitor, ObservableFields, TableOccupancy,
};
pub use packet::{
    validate_arp, validate_arp_request, validate_ipv4_frame, ArpOpcode, MacAddress, ValidatedArp,
    ValidatedArpRequest, ValidatedIpv4, ARP_ETHERTYPE, ETHERNET_HEADER_LEN, IPV4_ETHERTYPE,
};
pub use reload_state::{StateCarryConflict, StateCarryOutcome};
pub use resolution::{
    dispatch_host_unreachable_failures, execute_one_arp_request, poll_resolution_timers,
    ArpRequestAction, ArpRequestBuildError, ControlDisposition, DynamicNeighborSlot,
    ExecuteArpRequestError, GeneratedArpReport, GeneratedArpTrace, GeneratedTraceSink,
    MonotonicMillis, NoGeneratedTrace, NoResolutionFailureTrace, NoResolutionTimerTrace,
    ResolutionActionSlot, ResolutionCounters, ResolutionFailureCapture, ResolutionFailureCounters,
    ResolutionFailureDispatchError, ResolutionFailureDispatchReport, ResolutionFailureHoldPhase,
    ResolutionFailureHoldSlot, ResolutionFailureTrace, ResolutionFailureTraceSink,
    ResolutionGenerationToken, ResolutionHashKey, ResolutionHashKeyError, ResolutionIndexCounters,
    ResolutionPhase, ResolutionPolicy, ResolutionPolicyError, ResolutionPublicationError,
    ResolutionPublicationPermit, ResolutionPublicationReport, ResolutionResult, ResolutionRuntime,
    ResolutionStateSlot, ResolutionStatus, ResolutionTimerError, ResolutionTimerReport,
    ResolutionTimerTrace, ResolutionTimerTraceSink, StaticReconcileReport, ARP_REQUEST_FRAME_LEN,
    RESOLUTION_INDEX_CHAIN_LIMIT,
};
pub use route::{
    IfId, Interface, Ipv4Address, LocalIpv4Binding, Neighbor, Route, RouteError,
    ETHERNET_DEFAULT_MTU, IPV4_MIN_MTU,
};
