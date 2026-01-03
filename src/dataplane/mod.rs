//! Data plane components
//!
//! Handles packet processing: parsing, forwarding decisions, and transmission.

mod arp_processor;
mod arp_table;
mod fdb;
mod forwarder;
mod routing;

pub use arp_processor::{process_arp, ArpAction, ArpPendingQueue};
pub use arp_table::{ArpState, ArpTable};
pub use fdb::{Fdb, L2ForwardAction, PortId, DEFAULT_AGING_TIME_SECS, DEFAULT_VLAN};
pub use forwarder::{ForwardAction, Forwarder, InterfaceInfo};
pub use routing::{Route, RouteSource, RoutingTable};
