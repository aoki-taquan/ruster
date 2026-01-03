//! Packet forwarder
//!
//! Handles IPv4 packet forwarding with routing table lookup,
//! next-hop resolution via ARP, and TTL handling.

use crate::dataplane::{ArpPendingQueue, ArpState, ArpTable, RoutingTable};
use crate::protocol::arp::ArpPacket;
use crate::protocol::ipv4::Ipv4Packet;
use crate::protocol::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Result of a forwarding decision
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardAction {
    /// Forward packet to the specified interface with given destination MAC
    Forward {
        interface: String,
        next_hop_mac: MacAddr,
        packet: Vec<u8>,
    },
    /// Send ARP request to resolve next-hop, packet is queued
    ArpRequest {
        interface: String,
        target_ip: Ipv4Addr,
        request: ArpPacket,
    },
    /// Packet is for the local router (e.g., ICMP to us)
    Local,
    /// Drop packet: TTL expired (should send ICMP Time Exceeded)
    TtlExpired {
        src_addr: Ipv4Addr,
        original_packet: Vec<u8>,
    },
    /// Drop packet: no route to destination (should send ICMP Destination Unreachable)
    NoRoute { dst_addr: Ipv4Addr },
    /// Drop packet: ARP queue is full
    Dropped,
}

/// Interface information needed for forwarding
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub ip_addr: Ipv4Addr,
    pub mac_addr: MacAddr,
    pub prefix_len: u8,
}

/// Packet forwarder handling routing and ARP resolution
pub struct Forwarder {
    /// Our interface IP/MAC addresses
    interfaces: HashMap<String, InterfaceInfo>,
}

impl Forwarder {
    pub fn new() -> Self {
        Self {
            interfaces: HashMap::new(),
        }
    }

    /// Register an interface with its IP and MAC address
    pub fn add_interface(&mut self, name: String, info: InterfaceInfo) {
        self.interfaces.insert(name, info);
    }

    /// Remove an interface
    pub fn remove_interface(&mut self, name: &str) {
        self.interfaces.remove(name);
    }

    /// Get interface info by name
    pub fn get_interface(&self, name: &str) -> Option<&InterfaceInfo> {
        self.interfaces.get(name)
    }

    /// Check if destination IP is one of our interfaces
    pub fn is_local(&self, dst_ip: Ipv4Addr) -> bool {
        self.interfaces.values().any(|info| info.ip_addr == dst_ip)
    }

    /// Forward an IPv4 packet
    ///
    /// # Arguments
    /// * `packet_data` - Raw IPv4 packet bytes
    /// * `routing_table` - Routing table for lookup
    /// * `arp_table` - ARP table for MAC resolution
    /// * `pending_queue` - Queue for packets awaiting ARP resolution
    ///
    /// # Returns
    /// ForwardAction indicating what to do with the packet
    pub fn forward(
        &self,
        packet_data: &[u8],
        routing_table: &RoutingTable,
        arp_table: &ArpTable,
        pending_queue: &mut ArpPendingQueue,
    ) -> ForwardAction {
        // Parse IPv4 packet
        let mut ip_packet = match Ipv4Packet::from_bytes(packet_data) {
            Ok(pkt) => pkt,
            Err(_) => return ForwardAction::Dropped,
        };

        let dst_addr = ip_packet.dst_addr();

        // Check if packet is for us
        if self.is_local(dst_addr) {
            return ForwardAction::Local;
        }

        // Decrement TTL
        if !ip_packet.decrement_ttl() {
            return ForwardAction::TtlExpired {
                src_addr: ip_packet.src_addr(),
                original_packet: packet_data.to_vec(),
            };
        }

        // Lookup route
        let route = match routing_table.lookup(dst_addr) {
            Some(r) => r,
            None => return ForwardAction::NoRoute { dst_addr },
        };

        // Resolve the output interface
        let out_interface = if route.interface.is_empty() {
            // Route doesn't specify interface, find it from next-hop
            self.find_interface_for_next_hop(route.next_hop.unwrap_or(dst_addr), routing_table)
        } else {
            Some(route.interface.clone())
        };

        let out_interface = match out_interface {
            Some(iface) => iface,
            None => return ForwardAction::NoRoute { dst_addr },
        };

        // Get our interface info
        let iface_info = match self.interfaces.get(&out_interface) {
            Some(info) => info,
            None => return ForwardAction::NoRoute { dst_addr },
        };

        // Determine next-hop IP for ARP resolution
        let next_hop_ip = route.next_hop.unwrap_or(dst_addr);

        // Resolve next-hop MAC via ARP
        match arp_table.lookup(&next_hop_ip) {
            Some((mac, ArpState::Reachable)) => {
                // We have the MAC, forward the packet
                ForwardAction::Forward {
                    interface: out_interface,
                    next_hop_mac: mac,
                    packet: ip_packet.into_bytes(),
                }
            }
            Some((_, ArpState::Stale)) | Some((_, ArpState::Incomplete)) | None => {
                // Need to resolve MAC via ARP
                // Queue the packet
                let packet_bytes = ip_packet.into_bytes();
                if !pending_queue.enqueue(next_hop_ip, packet_bytes) {
                    return ForwardAction::Dropped;
                }

                // Generate ARP request
                let arp_request =
                    ArpPacket::request(iface_info.mac_addr, iface_info.ip_addr, next_hop_ip);

                ForwardAction::ArpRequest {
                    interface: out_interface,
                    target_ip: next_hop_ip,
                    request: arp_request,
                }
            }
        }
    }

    /// Find the interface that can reach a given IP address
    fn find_interface_for_next_hop(
        &self,
        next_hop: Ipv4Addr,
        routing_table: &RoutingTable,
    ) -> Option<String> {
        // First, try to find a connected route for the next-hop
        if let Some(route) = routing_table.lookup(next_hop) {
            if !route.interface.is_empty() && route.next_hop.is_none() {
                // This is a connected route
                return Some(route.interface.clone());
            }
        }

        // Check if next-hop is directly reachable through any interface
        for (name, info) in &self.interfaces {
            if is_in_network(next_hop, info.ip_addr, info.prefix_len) {
                return Some(name.clone());
            }
        }

        None
    }
}

impl Default for Forwarder {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if an IP is in the same network as an interface
fn is_in_network(ip: Ipv4Addr, interface_ip: Ipv4Addr, prefix_len: u8) -> bool {
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };

    let ip_bits = u32::from(ip);
    let iface_bits = u32::from(interface_ip);

    (ip_bits & mask) == (iface_bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataplane::{Route, RouteSource, RoutingTable};
    use std::time::Duration;

    fn make_forwarder() -> Forwarder {
        let mut fwd = Forwarder::new();
        fwd.add_interface(
            "eth0".to_string(),
            InterfaceInfo {
                ip_addr: Ipv4Addr::new(192, 168, 1, 1),
                mac_addr: MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                prefix_len: 24,
            },
        );
        fwd.add_interface(
            "eth1".to_string(),
            InterfaceInfo {
                ip_addr: Ipv4Addr::new(10, 0, 0, 1),
                mac_addr: MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                prefix_len: 8,
            },
        );
        fwd
    }

    fn make_routing_table() -> RoutingTable {
        let mut table = RoutingTable::new();

        // Connected routes
        table.add(Route {
            destination: Ipv4Addr::new(192, 168, 1, 0),
            prefix_len: 24,
            next_hop: None,
            interface: "eth0".to_string(),
            metric: 0,
            source: RouteSource::Connected,
        });

        table.add(Route {
            destination: Ipv4Addr::new(10, 0, 0, 0),
            prefix_len: 8,
            next_hop: None,
            interface: "eth1".to_string(),
            metric: 0,
            source: RouteSource::Connected,
        });

        // Default route
        table.add(Route {
            destination: Ipv4Addr::new(0, 0, 0, 0),
            prefix_len: 0,
            next_hop: Some(Ipv4Addr::new(192, 168, 1, 254)),
            interface: "eth0".to_string(),
            metric: 100,
            source: RouteSource::Static,
        });

        table
    }

    fn make_ip_packet(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8) -> Vec<u8> {
        use crate::protocol::ipv4::Ipv4Builder;

        Ipv4Builder::new()
            .src_addr(src)
            .dst_addr(dst)
            .ttl(ttl)
            .protocol(1) // ICMP
            .payload(&[0x08, 0x00, 0x00, 0x00]) // Echo request
            .build()
    }

    #[test]
    fn test_is_local() {
        let fwd = make_forwarder();

        assert!(fwd.is_local(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(fwd.is_local(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!fwd.is_local(Ipv4Addr::new(192, 168, 1, 100)));
        assert!(!fwd.is_local(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_forward_local() {
        let fwd = make_forwarder();
        let table = make_routing_table();
        let arp = ArpTable::new(Duration::from_secs(30), Duration::from_secs(120));
        let mut pending = ArpPendingQueue::new(3, 60);

        // Packet destined for our interface
        let packet = make_ip_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            64,
        );

        let action = fwd.forward(&packet, &table, &arp, &mut pending);
        assert_eq!(action, ForwardAction::Local);
    }

    #[test]
    fn test_forward_ttl_expired() {
        let fwd = make_forwarder();
        let table = make_routing_table();
        let arp = ArpTable::new(Duration::from_secs(30), Duration::from_secs(120));
        let mut pending = ArpPendingQueue::new(3, 60);

        // Packet with TTL=1 (will expire)
        let packet = make_ip_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(8, 8, 8, 8),
            1,
        );

        let action = fwd.forward(&packet, &table, &arp, &mut pending);
        match action {
            ForwardAction::TtlExpired { src_addr, .. } => {
                assert_eq!(src_addr, Ipv4Addr::new(192, 168, 1, 100));
            }
            _ => panic!("Expected TtlExpired"),
        }
    }

    #[test]
    fn test_forward_no_route() {
        let fwd = make_forwarder();
        let table = RoutingTable::new(); // Empty table
        let arp = ArpTable::new(Duration::from_secs(30), Duration::from_secs(120));
        let mut pending = ArpPendingQueue::new(3, 60);

        let packet = make_ip_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(8, 8, 8, 8),
            64,
        );

        let action = fwd.forward(&packet, &table, &arp, &mut pending);
        match action {
            ForwardAction::NoRoute { dst_addr } => {
                assert_eq!(dst_addr, Ipv4Addr::new(8, 8, 8, 8));
            }
            _ => panic!("Expected NoRoute"),
        }
    }

    #[test]
    fn test_forward_arp_needed() {
        let fwd = make_forwarder();
        let table = make_routing_table();
        let arp = ArpTable::new(Duration::from_secs(30), Duration::from_secs(120));
        let mut pending = ArpPendingQueue::new(3, 60);

        // Packet to connected network (no ARP entry)
        let packet = make_ip_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 100),
            64,
        );

        let action = fwd.forward(&packet, &table, &arp, &mut pending);
        match action {
            ForwardAction::ArpRequest {
                interface,
                target_ip,
                ..
            } => {
                assert_eq!(interface, "eth0");
                assert_eq!(target_ip, Ipv4Addr::new(192, 168, 1, 100));
            }
            _ => panic!("Expected ArpRequest, got {:?}", action),
        }

        // Packet should be queued
        assert!(pending.has_pending(&Ipv4Addr::new(192, 168, 1, 100)));
    }

    #[test]
    fn test_forward_with_arp() {
        let fwd = make_forwarder();
        let table = make_routing_table();
        let mut arp = ArpTable::new(Duration::from_secs(30), Duration::from_secs(120));
        let mut pending = ArpPendingQueue::new(3, 60);

        // Add ARP entry for destination
        let dst_mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        arp.insert(Ipv4Addr::new(192, 168, 1, 100), dst_mac);

        let packet = make_ip_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 100),
            64,
        );

        let action = fwd.forward(&packet, &table, &arp, &mut pending);
        match action {
            ForwardAction::Forward {
                interface,
                next_hop_mac,
                packet,
            } => {
                assert_eq!(interface, "eth0");
                assert_eq!(next_hop_mac, dst_mac);
                // TTL should be decremented
                let forwarded = Ipv4Packet::from_bytes(&packet).unwrap();
                assert_eq!(forwarded.ttl(), 63);
            }
            _ => panic!("Expected Forward, got {:?}", action),
        }
    }

    #[test]
    fn test_forward_via_gateway() {
        let fwd = make_forwarder();
        let table = make_routing_table();
        let mut arp = ArpTable::new(Duration::from_secs(30), Duration::from_secs(120));
        let mut pending = ArpPendingQueue::new(3, 60);

        // Add ARP entry for default gateway
        let gw_mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        arp.insert(Ipv4Addr::new(192, 168, 1, 254), gw_mac);

        // Packet to external address (uses default route)
        let packet = make_ip_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(8, 8, 8, 8),
            64,
        );

        let action = fwd.forward(&packet, &table, &arp, &mut pending);
        match action {
            ForwardAction::Forward {
                interface,
                next_hop_mac,
                ..
            } => {
                assert_eq!(interface, "eth0");
                // Should use gateway's MAC, not destination's
                assert_eq!(next_hop_mac, gw_mac);
            }
            _ => panic!("Expected Forward, got {:?}", action),
        }
    }

    #[test]
    fn test_is_in_network() {
        // Same /24 network
        assert!(is_in_network(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            24
        ));

        // Different /24 network
        assert!(!is_in_network(
            Ipv4Addr::new(192, 168, 2, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            24
        ));

        // Same /8 network
        assert!(is_in_network(
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::new(10, 0, 0, 1),
            8
        ));

        // /0 matches everything
        assert!(is_in_network(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(192, 168, 1, 1),
            0
        ));
    }
}
