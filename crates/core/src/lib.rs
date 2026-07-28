#![forbid(unsafe_code)]
#![doc = "A small, allocation-free IPv4 and ARP packet-processing core."]

mod checksum;
mod forwarding;
mod io;
mod packet;
mod route;

pub use checksum::{ipv4_header_checksum, rfc1624_update};
pub use forwarding::{
    forward_batch, BatchReport, DropReason, ForwardingSnapshot, NoTrace, SnapshotError, TraceEvent,
    TraceSink,
};
pub use io::{BatchCompletion, PacketBatch, PacketIo, PacketLease, PacketSlot, SlotCompletion};
pub use packet::{
    validate_arp_request, validate_ipv4_frame, MacAddress, ValidatedArpRequest, ValidatedIpv4,
    ARP_ETHERTYPE, ETHERNET_HEADER_LEN, IPV4_ETHERTYPE,
};
pub use route::{IfId, Interface, Ipv4Address, LocalIpv4Binding, Neighbor, Route, RouteError};
