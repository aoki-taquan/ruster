//! Stateful Firewall for Packet Inspection (SPI)
//!
//! Provides packet filtering based on connection state tracking.
//! Blocks unsolicited inbound connections from WAN interfaces.

use super::conntrack::{ConnKey, ConnProtocol, ConnTrackTable};
use crate::protocol::icmp::{IcmpPacket, IcmpType};
use crate::protocol::ipv4::Ipv4Header;
use crate::protocol::tcp::TcpHeader;
use crate::protocol::udp::UdpHeader;
use std::collections::HashSet;

/// Firewall verdict
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallVerdict {
    /// Allow the packet
    Accept,
    /// Drop the packet silently
    Drop,
}

/// Stateful firewall
pub struct StatefulFirewall {
    /// Connection tracking table
    conntrack: ConnTrackTable,
    /// WAN interface names (where SPI is applied)
    wan_interfaces: HashSet<String>,
}

impl StatefulFirewall {
    /// Create a new stateful firewall
    pub fn new(wan_interfaces: Vec<String>) -> Self {
        Self {
            conntrack: ConnTrackTable::new(),
            wan_interfaces: wan_interfaces.into_iter().collect(),
        }
    }

    /// Check if an interface is a WAN interface
    pub fn is_wan_interface(&self, iface: &str) -> bool {
        self.wan_interfaces.contains(iface)
    }

    /// Inspect a packet and return verdict
    ///
    /// This should be called before processing/forwarding the packet.
    /// For inbound packets from WAN, only tracked connections are allowed.
    pub fn inspect(&self, ip_packet: &[u8], ingress_iface: &str) -> FirewallVerdict {
        // Only apply SPI to WAN interfaces
        if !self.is_wan_interface(ingress_iface) {
            return FirewallVerdict::Accept;
        }

        // Parse IPv4 header
        let ip_header = match Ipv4Header::parse(ip_packet) {
            Ok(h) => h,
            Err(_) => return FirewallVerdict::Drop,
        };

        let protocol = match ConnProtocol::from_u8(ip_header.protocol()) {
            Some(p) => p,
            None => return FirewallVerdict::Accept, // Unsupported protocol, pass through
        };

        // Extract connection key from packet
        let key = match self.extract_key(&ip_header, protocol) {
            Some(k) => k,
            None => return FirewallVerdict::Drop,
        };

        // Check if this is a tracked connection (reply to outbound)
        if self.conntrack.is_tracked(&key) {
            return FirewallVerdict::Accept;
        }

        // Check ICMP error messages (RELATED)
        if protocol == ConnProtocol::Icmp && self.is_related_icmp(&ip_header) {
            return FirewallVerdict::Accept;
        }

        // Not tracked and not RELATED - drop
        FirewallVerdict::Drop
    }

    /// Track a packet for connection state
    ///
    /// This should be called after forwarding decision for outbound packets.
    pub fn track(&mut self, ip_packet: &[u8], ingress_iface: &str) {
        // Only track outbound packets (from LAN interfaces)
        if self.is_wan_interface(ingress_iface) {
            // This is an inbound packet - update existing connection
            self.track_inbound(ip_packet);
            return;
        }

        // Parse IPv4 header
        let ip_header = match Ipv4Header::parse(ip_packet) {
            Ok(h) => h,
            Err(_) => return,
        };

        let protocol = match ConnProtocol::from_u8(ip_header.protocol()) {
            Some(p) => p,
            None => return,
        };

        // Extract connection key
        let key = match self.extract_key(&ip_header, protocol) {
            Some(k) => k,
            None => return,
        };

        // Track outbound connection
        self.conntrack.track_outbound(key.clone());

        // Update TCP state if applicable
        if protocol == ConnProtocol::Tcp {
            self.update_tcp_state(&ip_header, &key);
        }
    }

    /// Track inbound packet (update existing connection state)
    fn track_inbound(&mut self, ip_packet: &[u8]) {
        let ip_header = match Ipv4Header::parse(ip_packet) {
            Ok(h) => h,
            Err(_) => return,
        };

        let protocol = match ConnProtocol::from_u8(ip_header.protocol()) {
            Some(p) => p,
            None => return,
        };

        let key = match self.extract_key(&ip_header, protocol) {
            Some(k) => k,
            None => return,
        };

        // Update reply tracking
        self.conntrack.track_reply(&key);

        // Update TCP state
        if protocol == ConnProtocol::Tcp {
            self.update_tcp_state(&ip_header, &key);
        }
    }

    /// Extract connection key from packet
    fn extract_key(&self, ip_header: &Ipv4Header, protocol: ConnProtocol) -> Option<ConnKey> {
        let payload = ip_header.payload();

        let (src_port, dst_port) = match protocol {
            ConnProtocol::Tcp => {
                let tcp = TcpHeader::parse(payload).ok()?;
                (tcp.src_port(), tcp.dst_port())
            }
            ConnProtocol::Udp => {
                let udp = UdpHeader::parse(payload).ok()?;
                (udp.src_port(), udp.dst_port())
            }
            ConnProtocol::Icmp => {
                let icmp = IcmpPacket::parse(payload).ok()?;
                // For echo, use identifier as "port"
                // Echo Request: src_port = id, dst_port = 0
                // Echo Reply: src_port = 0, dst_port = id (so reverse matches)
                if icmp.is_echo_request() {
                    (icmp.identifier(), 0)
                } else if icmp.is_echo_reply() {
                    (0, icmp.identifier())
                } else {
                    // For error messages, return None (handled separately)
                    return None;
                }
            }
        };

        Some(ConnKey::new(
            ip_header.src_addr(),
            ip_header.dst_addr(),
            src_port,
            dst_port,
            protocol,
        ))
    }

    /// Update TCP state from packet flags
    fn update_tcp_state(&mut self, ip_header: &Ipv4Header, key: &ConnKey) {
        let payload = ip_header.payload();
        if let Ok(tcp) = TcpHeader::parse(payload) {
            let flags = tcp.flags();
            self.conntrack
                .update_tcp_state(key, flags.syn, flags.fin, flags.rst, flags.ack);
        }
    }

    /// Check if ICMP packet is related to an existing connection
    fn is_related_icmp(&self, ip_header: &Ipv4Header) -> bool {
        let payload = ip_header.payload();
        let icmp = match IcmpPacket::parse(payload) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Only error messages can be RELATED
        let icmp_type = match icmp.message_type() {
            Some(t) => t,
            None => return false,
        };

        match icmp_type {
            IcmpType::DestinationUnreachable
            | IcmpType::TimeExceeded
            | IcmpType::ParameterProblem => {
                // Extract original packet from ICMP error
                self.check_original_packet(icmp.original_datagram())
            }
            _ => false,
        }
    }

    /// Check if the original packet in ICMP error is from a tracked connection
    fn check_original_packet(&self, original: &[u8]) -> bool {
        // Original datagram contains at least IP header + 8 bytes of original transport
        let ip_header = match Ipv4Header::parse(original) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let protocol = match ConnProtocol::from_u8(ip_header.protocol()) {
            Some(p) => p,
            None => return false,
        };

        // Extract key from original packet (reversed direction)
        let payload = ip_header.payload();
        if payload.len() < 8 {
            return false;
        }

        let (src_port, dst_port) = match protocol {
            ConnProtocol::Tcp | ConnProtocol::Udp => {
                // First 4 bytes are ports
                let src = u16::from_be_bytes([payload[0], payload[1]]);
                let dst = u16::from_be_bytes([payload[2], payload[3]]);
                (src, dst)
            }
            ConnProtocol::Icmp => {
                // For ICMP echo, identifier is at offset 4-5
                if payload.len() < 6 {
                    return false;
                }
                let id = u16::from_be_bytes([payload[4], payload[5]]);
                (id, 0)
            }
        };

        // The original packet was sent by us (outbound), so check original direction
        let key = ConnKey::new(
            ip_header.src_addr(),
            ip_header.dst_addr(),
            src_port,
            dst_port,
            protocol,
        );

        self.conntrack.is_tracked(&key)
    }

    /// Run maintenance (expire old entries)
    pub fn run_maintenance(&mut self) {
        self.conntrack.expire_old_entries();
    }

    /// Get number of tracked connections
    pub fn connection_count(&self) -> usize {
        self.conntrack.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::icmp::icmp_checksum;
    use crate::protocol::ipv4::{Ipv4Builder, Protocol};
    use crate::protocol::tcp::tcp_checksum;
    use crate::protocol::udp::udp_checksum;
    use std::net::Ipv4Addr;

    fn make_tcp_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        syn: bool,
        ack: bool,
    ) -> Vec<u8> {
        let mut flags: u8 = 0;
        if syn {
            flags |= 0x02;
        }
        if ack {
            flags |= 0x10;
        }

        let mut tcp = vec![
            (src_port >> 8) as u8,
            (src_port & 0xFF) as u8,
            (dst_port >> 8) as u8,
            (dst_port & 0xFF) as u8,
            0,
            0,
            0,
            1, // seq
            0,
            0,
            0,
            0, // ack
            0x50,
            flags, // offset + flags
            0x72,
            0x10, // window
            0,
            0, // checksum
            0,
            0, // urgent
        ];

        let checksum = tcp_checksum(src_ip, dst_ip, &tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

        Ipv4Builder::new()
            .src_addr(src_ip)
            .dst_addr(dst_ip)
            .protocol(Protocol::Tcp as u8)
            .ttl(64)
            .payload(&tcp)
            .build()
    }

    fn make_udp_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let payload = b"test";
        let length = 8 + payload.len() as u16;

        let mut udp = vec![
            (src_port >> 8) as u8,
            (src_port & 0xFF) as u8,
            (dst_port >> 8) as u8,
            (dst_port & 0xFF) as u8,
            (length >> 8) as u8,
            (length & 0xFF) as u8,
            0,
            0,
        ];
        udp.extend_from_slice(payload);

        let checksum = udp_checksum(src_ip, dst_ip, &udp);
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());

        Ipv4Builder::new()
            .src_addr(src_ip)
            .dst_addr(dst_ip)
            .protocol(Protocol::Udp as u8)
            .ttl(64)
            .payload(&udp)
            .build()
    }

    fn make_icmp_echo(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, id: u16, is_reply: bool) -> Vec<u8> {
        let icmp_type = if is_reply { 0 } else { 8 };
        let mut icmp = vec![
            icmp_type,
            0, // type, code
            0,
            0, // checksum
            (id >> 8) as u8,
            (id & 0xFF) as u8, // identifier
            0,
            1, // sequence
        ];

        let checksum = icmp_checksum(&icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

        Ipv4Builder::new()
            .src_addr(src_ip)
            .dst_addr(dst_ip)
            .protocol(Protocol::Icmp as u8)
            .ttl(64)
            .payload(&icmp)
            .build()
    }

    #[test]
    fn test_lan_traffic_accepted() {
        let fw = StatefulFirewall::new(vec!["wan0".to_string()]);

        // Traffic from LAN interface is always accepted
        let lan_ip = Ipv4Addr::new(192, 168, 1, 100);
        let server_ip = Ipv4Addr::new(10, 0, 0, 1);
        let packet = make_tcp_packet(lan_ip, server_ip, 12345, 80, true, false);

        let verdict = fw.inspect(&packet, "lan0");
        assert_eq!(verdict, FirewallVerdict::Accept);
    }

    #[test]
    fn test_unsolicited_wan_blocked() {
        let fw = StatefulFirewall::new(vec!["wan0".to_string()]);

        // Unsolicited traffic from WAN is blocked
        let external_ip = Ipv4Addr::new(93, 184, 216, 34);
        let internal_ip = Ipv4Addr::new(192, 168, 1, 100);
        let packet = make_tcp_packet(external_ip, internal_ip, 80, 12345, true, false);

        let verdict = fw.inspect(&packet, "wan0");
        assert_eq!(verdict, FirewallVerdict::Drop);
    }

    #[test]
    fn test_tracked_response_accepted() {
        let mut fw = StatefulFirewall::new(vec!["wan0".to_string()]);

        let internal_ip = Ipv4Addr::new(192, 168, 1, 100);
        let external_ip = Ipv4Addr::new(93, 184, 216, 34);

        // Track outbound SYN (from LAN)
        let syn = make_tcp_packet(internal_ip, external_ip, 12345, 80, true, false);
        fw.track(&syn, "lan0");

        // Now SYN-ACK from WAN should be accepted
        let syn_ack = make_tcp_packet(external_ip, internal_ip, 80, 12345, true, true);
        let verdict = fw.inspect(&syn_ack, "wan0");
        assert_eq!(verdict, FirewallVerdict::Accept);
    }

    #[test]
    fn test_udp_tracking() {
        let mut fw = StatefulFirewall::new(vec!["wan0".to_string()]);

        let internal_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dns_server = Ipv4Addr::new(8, 8, 8, 8);

        // Track outbound DNS query
        let query = make_udp_packet(internal_ip, dns_server, 54321, 53);
        fw.track(&query, "lan0");

        // DNS response should be accepted
        let response = make_udp_packet(dns_server, internal_ip, 53, 54321);
        let verdict = fw.inspect(&response, "wan0");
        assert_eq!(verdict, FirewallVerdict::Accept);
    }

    #[test]
    fn test_icmp_echo_tracking() {
        let mut fw = StatefulFirewall::new(vec!["wan0".to_string()]);

        let internal_ip = Ipv4Addr::new(192, 168, 1, 100);
        let target_ip = Ipv4Addr::new(8, 8, 8, 8);

        // Track outbound ping
        let request = make_icmp_echo(internal_ip, target_ip, 0x1234, false);
        fw.track(&request, "lan0");

        // Ping reply should be accepted
        let reply = make_icmp_echo(target_ip, internal_ip, 0x1234, true);
        let verdict = fw.inspect(&reply, "wan0");
        assert_eq!(verdict, FirewallVerdict::Accept);
    }

    #[test]
    fn test_wrong_source_blocked() {
        let mut fw = StatefulFirewall::new(vec!["wan0".to_string()]);

        let internal_ip = Ipv4Addr::new(192, 168, 1, 100);
        let server_ip = Ipv4Addr::new(93, 184, 216, 34);
        let attacker_ip = Ipv4Addr::new(1, 2, 3, 4);

        // Track outbound connection to server
        let syn = make_tcp_packet(internal_ip, server_ip, 12345, 80, true, false);
        fw.track(&syn, "lan0");

        // Response from different IP should be blocked
        let fake_response = make_tcp_packet(attacker_ip, internal_ip, 80, 12345, true, true);
        let verdict = fw.inspect(&fake_response, "wan0");
        assert_eq!(verdict, FirewallVerdict::Drop);
    }

    #[test]
    fn test_connection_count() {
        let mut fw = StatefulFirewall::new(vec!["wan0".to_string()]);

        assert_eq!(fw.connection_count(), 0);

        let internal_ip = Ipv4Addr::new(192, 168, 1, 100);
        let server_ip = Ipv4Addr::new(93, 184, 216, 34);

        fw.track(
            &make_tcp_packet(internal_ip, server_ip, 12345, 80, true, false),
            "lan0",
        );
        assert_eq!(fw.connection_count(), 1);

        fw.track(
            &make_tcp_packet(internal_ip, server_ip, 12346, 443, true, false),
            "lan0",
        );
        assert_eq!(fw.connection_count(), 2);
    }
}
