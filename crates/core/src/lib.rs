#![forbid(unsafe_code)]
#![doc = "A small, allocation-free IPv4 and ARP packet-processing core."]

mod checksum;
mod forwarding;
mod generated;
mod icmpv4_error;
mod io;
mod nat44;
mod packet;
mod resolution;
mod route;

pub use checksum::{internet_checksum, ipv4_header_checksum, rfc1624_update};
pub use forwarding::{
    forward_batch, forward_batch_with_nat44_tcp, forward_batch_with_nat44_tcp_and_icmpv4_errors,
    forward_batch_with_nat44_udp, forward_batch_with_nat44_udp_and_icmpv4_errors,
    forward_batch_with_nat44_udp_and_tcp, forward_batch_with_nat44_udp_and_tcp_and_icmpv4_errors,
    forward_batch_with_resolution, forward_batch_with_resolution_and_icmpv4_errors, BatchReport,
    DropReason, ForwardingSnapshot, Ipv4OriginPolicy, Ipv4OriginPolicyError,
    Nat44Icmpv4Disposition, NoTrace, SnapshotError, TraceEvent, TraceSink,
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
    Icmpv4ErrorPolicyError, Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, Icmpv4TimeExceededAction,
    Icmpv4TimeExceededBuildError, Icmpv4TimeExceededDisposition, NoGeneratedIcmpv4Trace,
    ICMPV4_ERROR_MAX_FRAME_LEN, ICMPV4_ERROR_MAX_QUOTE_LEN, ICMPV4_TIME_EXCEEDED_MAX_FRAME_LEN,
    ICMPV4_TIME_EXCEEDED_MAX_QUOTE_LEN,
};
pub use io::{
    BatchCompletion, ConsumeReason, PacketBatch, PacketIo, PacketLease, PacketSlot, SlotCompletion,
};
pub use nat44::{
    Nat44Icmpv4ErrorPolicy, Nat44TcpConfig, Nat44TcpConfigError, Nat44TcpCounters,
    Nat44TcpDisposition, Nat44TcpMappingSlot, Nat44TcpPolicy, Nat44TcpPolicyError,
    Nat44TcpReconcileReport, Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44UdpConfig,
    Nat44UdpConfigError, Nat44UdpCounters, Nat44UdpDisposition, Nat44UdpMappingSlot,
    Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpPolicyError, Nat44UdpReconcileReport,
    Nat44UdpRuntime, NAT44_TCP_DEFAULT_IDLE_TTL_MS, NAT44_TCP_MAX_IDLE_TTL_MS,
    NAT44_TCP_MIN_IDLE_TTL_MS, NAT44_UDP_DEFAULT_IDLE_TTL_MS, NAT44_UDP_MAX_IDLE_TTL_MS,
    NAT44_UDP_MIN_IDLE_TTL_MS,
};
pub use packet::{
    validate_arp, validate_arp_request, validate_ipv4_frame, ArpOpcode, MacAddress, ValidatedArp,
    ValidatedArpRequest, ValidatedIpv4, ARP_ETHERTYPE, ETHERNET_HEADER_LEN, IPV4_ETHERTYPE,
};
pub use resolution::{
    dispatch_host_unreachable_failures, execute_one_arp_request, poll_resolution_timers,
    ArpRequestAction, ArpRequestBuildError, ControlDisposition, DynamicNeighborSlot,
    ExecuteArpRequestError, GeneratedArpReport, GeneratedArpTrace, GeneratedTraceSink,
    MonotonicMillis, NoGeneratedTrace, NoResolutionFailureTrace, NoResolutionTimerTrace,
    ResolutionActionSlot, ResolutionCounters, ResolutionFailureCapture, ResolutionFailureCounters,
    ResolutionFailureDispatchError, ResolutionFailureDispatchReport, ResolutionFailureHoldPhase,
    ResolutionFailureHoldSlot, ResolutionFailureTrace, ResolutionFailureTraceSink,
    ResolutionGenerationToken, ResolutionPhase, ResolutionPolicy, ResolutionPolicyError,
    ResolutionResult, ResolutionRuntime, ResolutionStateSlot, ResolutionStatus,
    ResolutionTimerError, ResolutionTimerReport, ResolutionTimerTrace, ResolutionTimerTraceSink,
    StaticReconcileReport, ARP_REQUEST_FRAME_LEN,
};
pub use route::{IfId, Interface, Ipv4Address, LocalIpv4Binding, Neighbor, Route, RouteError};
