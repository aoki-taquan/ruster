#![forbid(unsafe_code)]
#![doc = "A small, allocation-free IPv4 forwarding core."]

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
pub use packet::{validate_ipv4_frame, MacAddress, ValidatedIpv4, ETHERNET_HEADER_LEN};
pub use route::{IfId, Interface, Ipv4Address, Neighbor, Route, RouteError};
