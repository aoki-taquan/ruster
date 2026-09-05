#![deny(unsafe_code)]
#![doc = "A small, allocation-free IPv4 and ARP packet-processing core."]

mod checksum;
mod firewall;
mod fixed_directory;
mod forwarding;
mod generated;
mod icmpv4_error;
mod io;
mod nat44;
mod packet;
mod resolution;
mod route;

pub use checksum::{internet_checksum, ipv4_header_checksum, rfc1624_update};
#[cfg(feature = "validation-test-hooks")]
#[doc(hidden)]
pub use firewall::take_full_firewall_validation_count;
pub use firewall::{
    validate_firewall_rules, FirewallAction, FirewallAuditBuffer, FirewallAuditRecord,
    FirewallAuthorityEvidence, FirewallCommitError, FirewallConfig, FirewallConfigError,
    FirewallConnectionClass, FirewallCounters, FirewallDisposition, FirewallFailure,
    FirewallHashKey, FirewallHashKeyError, FirewallInterface, FirewallIpv4Prefix,
    FirewallIpv4PrefixError, FirewallPlanError, FirewallPolicy, FirewallPolicyError,
    FirewallPolicySource, FirewallPortRange, FirewallPortRangeError, FirewallProtocol,
    FirewallReconcileError, FirewallReconcilePermit, FirewallReconcileReport,
    FirewallRelatedIcmpv4Error, FirewallRelatedIcmpv4Flow, FirewallRule, FirewallRuleId,
    FirewallRuntime, FirewallStateSlot, FirewallTcpPhase, FirewallVerdict, ValidatedFirewallOwner,
    FIREWALL_MAX_IDLE_TTL_MS, FIREWALL_TCP_ACTIVE_DEFAULT_IDLE_TTL_MS,
    FIREWALL_TCP_ACTIVE_MIN_IDLE_TTL_MS, FIREWALL_TCP_OPENING_DEFAULT_IDLE_TTL_MS,
    FIREWALL_TCP_OPENING_MIN_IDLE_TTL_MS, FIREWALL_UDP_DEFAULT_IDLE_TTL_MS,
    FIREWALL_UDP_MIN_IDLE_TTL_MS,
};
pub use fixed_directory::{DirectoryBucket, DirectoryNode, PortOwnerSlot};
#[cfg(feature = "validation-test-hooks")]
#[doc(hidden)]
pub use forwarding::take_full_forwarding_validation_count;
pub use forwarding::{
    forward_batch, forward_batch_with_firewall, forward_batch_with_firewall_and_icmpv4_errors,
    forward_batch_with_firewall_and_icmpv4_errors_audited, forward_batch_with_firewall_audited,
    forward_batch_with_nat44_tcp, forward_batch_with_nat44_tcp_and_icmpv4_errors,
    forward_batch_with_nat44_udp, forward_batch_with_nat44_udp_and_icmpv4_errors,
    forward_batch_with_nat44_udp_and_tcp, forward_batch_with_nat44_udp_and_tcp_and_firewall,
    forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors,
    forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors_audited,
    forward_batch_with_nat44_udp_and_tcp_and_firewall_audited,
    forward_batch_with_nat44_udp_and_tcp_and_icmpv4_errors, forward_batch_with_resolution,
    forward_batch_with_resolution_and_icmpv4_errors, BatchReport, DropReason, ForwardingSnapshot,
    Ipv4OriginPolicy, Ipv4OriginPolicyError, Nat44Icmpv4Disposition, NoTrace, SnapshotError,
    TraceEvent, TraceSink, ValidatedForwardingOwner, ValidatedForwardingOwnerError,
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
    NoGeneratedIcmpv4Trace, ICMPV4_ERROR_MAX_FRAME_LEN, ICMPV4_ERROR_MAX_QUOTE_LEN,
    ICMPV4_TIME_EXCEEDED_MAX_FRAME_LEN, ICMPV4_TIME_EXCEEDED_MAX_QUOTE_LEN,
};
pub use io::{
    bind_publication_backend, BatchCompletion, BoundPublicationBackend, ConsumeReason,
    MatchedPublicationQuiescenceGuard, PacketBatch, PacketIo, PacketLease, PacketSlot,
    PublicationBackendAuthority, PublicationBackendControl, PublicationBindingIdentityExhausted,
    PublicationOwnerBinding, PublicationQuiescence, PublicationQuiescenceBackend,
    PublicationQuiescenceDisposition, PublicationQuiescenceGuard, SlotCompletion,
};
pub use nat44::{
    Nat44Icmpv4ErrorPolicy, Nat44TcpAuthorityEvidence, Nat44TcpConfig, Nat44TcpConfigError,
    Nat44TcpCounters, Nat44TcpDisposition, Nat44TcpHashKey, Nat44TcpHashKeyError,
    Nat44TcpIndexStorage, Nat44TcpMappingSlot, Nat44TcpPolicy, Nat44TcpPolicyError,
    Nat44TcpReconcileError, Nat44TcpReconcilePermit, Nat44TcpReconcileReport, Nat44TcpRuntime,
    Nat44TcpRuntimeConfigError, Nat44TcpSessionSlot, Nat44TcpStorageShape,
    Nat44UdpAuthorityEvidence, Nat44UdpConfig, Nat44UdpConfigError, Nat44UdpCounters,
    Nat44UdpDisposition, Nat44UdpHashKey, Nat44UdpHashKeyError, Nat44UdpIndexStorage,
    Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpPolicyError,
    Nat44UdpReconcileError, Nat44UdpReconcilePermit, Nat44UdpReconcileReport, Nat44UdpRuntime,
    Nat44UdpRuntimeConfigError, Nat44UdpStorageShape, NAT44_TCP_DEFAULT_IDLE_TTL_MS,
    NAT44_TCP_MAX_IDLE_TTL_MS, NAT44_TCP_MIN_IDLE_TTL_MS, NAT44_UDP_DEFAULT_IDLE_TTL_MS,
    NAT44_UDP_MAX_IDLE_TTL_MS, NAT44_UDP_MIN_IDLE_TTL_MS,
};
pub use packet::{
    validate_arp, validate_arp_request, validate_ipv4_frame, ArpOpcode, MacAddress, ValidatedArp,
    ValidatedArpRequest, ValidatedIpv4, ARP_ETHERTYPE, ETHERNET_HEADER_LEN, IPV4_ETHERTYPE,
};
pub use resolution::{
    dispatch_host_unreachable_failures, execute_one_arp_request, execute_one_held_datagram,
    poll_resolution_timers, ArpRequestAction, ArpRequestBuildError, ControlDisposition,
    DynamicNeighborSlot, ExecuteArpRequestError, ExecuteHeldDatagramError, GeneratedArpReport,
    GeneratedArpTrace, GeneratedHeldDatagramTrace, GeneratedHeldDatagramTraceSink,
    GeneratedTraceSink, HeldDatagramBuildError, HeldDatagramReport, MonotonicMillis,
    NoGeneratedHeldDatagramTrace, NoGeneratedTrace, NoResolutionFailureTrace,
    NoResolutionTimerTrace, ResolutionActionSlot, ResolutionCounters, ResolutionDatagramHoldSlot,
    ResolutionFailureCapture, ResolutionFailureCounters, ResolutionFailureDispatchError,
    ResolutionFailureDispatchReport, ResolutionFailureHoldPhase, ResolutionFailureHoldSlot,
    ResolutionFailureTrace, ResolutionFailureTraceSink, ResolutionGenerationToken,
    ResolutionHoldCounters, ResolutionHoldDisposition, ResolutionPhase, ResolutionPolicy,
    ResolutionPolicyError, ResolutionPublicationError, ResolutionPublicationPermit,
    ResolutionPublicationReport, ResolutionResult, ResolutionRuntime, ResolutionStateSlot,
    ResolutionStatus, ResolutionTimerError, ResolutionTimerReport, ResolutionTimerTrace,
    ResolutionTimerTraceSink, StaticReconcileReport, ARP_REQUEST_FRAME_LEN,
    RESOLUTION_HOLD_MAX_FRAME_LEN,
};
pub use route::{
    IfId, Interface, Ipv4Address, Ipv4Mtu, Ipv4MtuError, LocalIpv4Binding, Neighbor, Route,
    RouteError, IPV4_MINIMUM_MTU,
};
