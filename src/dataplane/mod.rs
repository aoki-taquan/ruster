//! Data plane components
//!
//! Handles packet processing: parsing, forwarding decisions, and transmission.

mod arp_processor;
mod arp_table;
mod conntrack;
mod dhcp6_client;
mod dhcp_client;
mod dhcp_server;
mod dns_forwarder;
mod fdb;
mod filter;
mod firewall;
mod forwarder;
mod napt;
mod ndp_processor;
mod neighbor_table;
mod pbr;
mod pppoe_client;
mod ra_client;
mod ra_server;
mod router;
mod routing;

pub use arp_processor::{process_arp, ArpAction, ArpPendingQueue};
pub use arp_table::{ArpState, ArpTable};
pub use dhcp6_client::{
    Dhcp6Client, Dhcp6ClientAction, Dhcp6ClientInterface, Dhcp6Lease, Dhcp6State, LeaseAddress,
};
pub use dhcp_client::{DhcpClient, DhcpClientAction, DhcpClientState, DhcpLease};
pub use dhcp_server::{DhcpAction, DhcpPool, DhcpPoolConfig, DhcpServer, LeaseEntry, LeaseState};
pub use dns_forwarder::{DnsAction, DnsForwarder, DnsForwarderConfig, PendingQuery};
pub use fdb::Fdb;
pub use filter::{
    icmpv6_type, protocol, Action, Chain, FilterContext, FilterRule, IpAddr as FilterIpAddr,
    IpCidr, Ipv4Cidr, Ipv6Cidr, PacketFilter, PortRange,
};
pub use forwarder::{ForwardAction, Forwarder, InterfaceInfo};
pub use napt::{NaptProcessor, NaptProtocol, NaptResult, NaptTable};
pub use ndp_processor::{
    process_neighbor_advertisement, process_neighbor_solicitation, NdpAction, NdpPendingQueue,
};
pub use neighbor_table::{NeighborState, NeighborTable};
pub use pbr::{PacketKey, PolicyAction, PolicyMatch, PolicyResult, PolicyRouter, PolicyRule};
pub use pppoe_client::{PppoeClient, PppoeClientAction, PppoeClientState, PppoeSession, PPPOE_MTU};
pub use ra_client::{
    LearnedPrefix, LearnedRouter, RaClient, RaClientAction, RaClientInterface, RaClientState,
};
pub use ra_server::{
    AdvertisedPrefix, RaServer, RaServerAction, RaServerConfig, RaServerInterface,
};
pub use router::{Interface, Router};
pub use routing::{network_address, LookupResult, Route, RouteSource, RoutingSystem, RoutingTable};

// SPI (Stateful Packet Inspection)
pub use conntrack::{ConnEntry, ConnKey, ConnProtocol, ConnState, ConnTrackTable};
pub use firewall::{FirewallVerdict, StatefulFirewall};
