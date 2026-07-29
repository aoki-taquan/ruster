#![forbid(unsafe_code)]
#![doc = "A small, allocation-free IPv4 and ARP packet-processing core."]

mod checksum;
mod forwarding;
mod generated;
mod icmpv4_error;
mod io;
mod packet;
mod resolution;
mod route;

pub use checksum::{internet_checksum, ipv4_header_checksum, rfc1624_update};
pub use forwarding::{
    forward_batch, forward_batch_with_resolution, forward_batch_with_resolution_and_icmpv4_errors,
    BatchReport, DropReason, ForwardingSnapshot, Ipv4OriginPolicy, Ipv4OriginPolicyError, NoTrace,
    SnapshotError, TraceEvent, TraceSink,
};
pub use generated::{
    GeneratedAllocationError, GeneratedBatchCompletion, GeneratedPacketBatch, GeneratedPacketIo,
    GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion,
};
pub use icmpv4_error::{
    execute_one_icmpv4_time_exceeded, ExecuteIcmpv4TimeExceededError, GeneratedIcmpv4Report,
    GeneratedIcmpv4Trace, GeneratedIcmpv4TraceSink, Icmpv4ErrorActionSlot, Icmpv4ErrorCounters,
    Icmpv4ErrorPolicy, Icmpv4ErrorPolicyError, Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot,
    Icmpv4TimeExceededAction, Icmpv4TimeExceededBuildError, Icmpv4TimeExceededDisposition,
    NoGeneratedIcmpv4Trace, ICMPV4_TIME_EXCEEDED_MAX_FRAME_LEN, ICMPV4_TIME_EXCEEDED_MAX_QUOTE_LEN,
};
pub use io::{
    BatchCompletion, ConsumeReason, PacketBatch, PacketIo, PacketLease, PacketSlot, SlotCompletion,
};
pub use packet::{
    validate_arp, validate_arp_request, validate_ipv4_frame, ArpOpcode, MacAddress, ValidatedArp,
    ValidatedArpRequest, ValidatedIpv4, ARP_ETHERTYPE, ETHERNET_HEADER_LEN, IPV4_ETHERTYPE,
};
pub use resolution::{
    execute_one_arp_request, ArpRequestAction, ArpRequestBuildError, ControlDisposition,
    DynamicNeighborSlot, ExecuteArpRequestError, GeneratedArpReport, GeneratedArpTrace,
    GeneratedTraceSink, MonotonicMillis, NoGeneratedTrace, ResolutionActionSlot,
    ResolutionCounters, ResolutionPolicy, ResolutionPolicyError, ResolutionResult,
    ResolutionRuntime, ResolutionStateSlot, StaticReconcileReport, ARP_REQUEST_FRAME_LEN,
};
pub use route::{IfId, Interface, Ipv4Address, LocalIpv4Binding, Neighbor, Route, RouteError};
