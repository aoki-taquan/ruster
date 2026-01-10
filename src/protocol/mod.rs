//! Network protocol implementations
//!
//! All L2+ protocols are implemented from scratch for learning purposes.

pub mod arp;
pub mod chap;
pub mod dhcp;
pub mod dhcpv6;
pub mod dns;
pub mod ethernet;
pub mod icmp;
pub mod icmpv6;
pub mod ipcp;
pub mod ipv4;
pub mod ipv6;
pub mod lcp;
pub mod pap;
pub mod ppp;
pub mod pppoe;
pub mod tcp;
pub mod types;
pub mod udp;

pub use types::*;
