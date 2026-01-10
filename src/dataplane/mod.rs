//! Data plane components
//!
//! Handles packet processing: parsing, forwarding decisions, and transmission.

mod arp_processor;
mod arp_table;
mod fdb;
mod forwarder;
mod napt;
mod ndp_processor;
mod neighbor_table;
mod pbr;
mod router;
mod routing;

pub use arp_processor::{process_arp, ArpAction, ArpPendingQueue};
pub use arp_table::{ArpState, ArpTable};
pub use fdb::Fdb;
pub use forwarder::{ForwardAction, Forwarder, InterfaceInfo};
pub use napt::{NaptProcessor, NaptProtocol, NaptResult, NaptTable};
pub use ndp_processor::{
    process_neighbor_advertisement, process_neighbor_solicitation, NdpAction, NdpPendingQueue,
};
pub use neighbor_table::{NeighborState, NeighborTable};
pub use pbr::{PacketKey, PolicyAction, PolicyMatch, PolicyResult, PolicyRouter, PolicyRule};
pub use router::{Interface, Router};
pub use routing::{LookupResult, Route, RouteSource, RoutingSystem, RoutingTable};
