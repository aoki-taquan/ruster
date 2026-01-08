//! NAPT (Network Address Port Translation) - RFC 3022, 4787, 5382, 5508
//!
//! Implements N:1 NAT (IPマスカレード) with Endpoint-Independent Mapping (EIM).

use crate::protocol::icmp::IcmpMutablePacket;
use crate::protocol::ipv4::Ipv4Packet;
use crate::protocol::tcp::{TcpFlags, TcpPacket};
use crate::protocol::udp::UdpPacket;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// NAPT-supported protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NaptProtocol {
    Tcp,
    Udp,
    Icmp,
}

impl NaptProtocol {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(NaptProtocol::Icmp),
            6 => Some(NaptProtocol::Tcp),
            17 => Some(NaptProtocol::Udp),
            _ => None,
        }
    }
}

/// Internal endpoint identifier (source side before NAT)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InternalEndpoint {
    pub src_ip: Ipv4Addr,
    pub src_port: u16, // For ICMP: identifier
    pub protocol: NaptProtocol,
}

/// External endpoint identifier (for reverse lookup on inbound)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExternalKey {
    pub external_port: u16, // Mapped port (or ICMP identifier)
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16, // For ICMP: 0
    pub protocol: NaptProtocol,
}

/// TCP connection state for timeout management (RFC 5382)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// Initial SYN seen
    SynSent,
    /// SYN-ACK received, connection established
    Established,
    /// FIN seen, waiting for close
    FinWait,
    /// Connection closed
    Closed,
}

/// NAPT mapping entry
#[derive(Debug, Clone)]
pub struct NaptEntry {
    /// Original internal endpoint
    pub internal: InternalEndpoint,
    /// Original destination (for Endpoint-Independent Mapping)
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    /// Assigned external port
    pub external_port: u16,
    /// Entry creation time (for debugging/logging)
    #[allow(dead_code)]
    pub created_at: Instant,
    /// Last packet time (for timeout)
    pub last_used: Instant,
    /// TCP state (only for TCP)
    pub tcp_state: Option<TcpState>,
}

/// NAPT timeout configuration (RFC 4787, 5382)
#[derive(Debug, Clone)]
pub struct NaptTimeouts {
    /// TCP established connection timeout (default: 2 hours)
    pub tcp_established: Duration,
    /// TCP transitory state timeout (default: 4 minutes)
    pub tcp_transitory: Duration,
    /// UDP timeout (default: 2 minutes for outbound, RFC 4787 recommends 5 min)
    pub udp: Duration,
    /// ICMP timeout (default: 60 seconds)
    pub icmp: Duration,
}

impl Default for NaptTimeouts {
    fn default() -> Self {
        Self {
            tcp_established: Duration::from_secs(7200), // 2 hours
            tcp_transitory: Duration::from_secs(240),   // 4 minutes
            udp: Duration::from_secs(300),              // 5 minutes
            icmp: Duration::from_secs(60),              // 1 minute
        }
    }
}

/// NAPT translation table
pub struct NaptTable {
    /// Internal -> Entry mapping (for SNAT lookup)
    internal_map: HashMap<InternalEndpoint, NaptEntry>,
    /// External key -> Internal endpoint (for DNAT lookup)
    external_map: HashMap<ExternalKey, InternalEndpoint>,
    /// External IP address (WAN interface IP)
    external_ip: Ipv4Addr,
    /// Next port to try for allocation
    next_port: u16,
    /// Port allocation range
    port_range: (u16, u16),
    /// Timeout configuration
    timeouts: NaptTimeouts,
}

impl NaptTable {
    /// Create a new NAPT table
    pub fn new(external_ip: Ipv4Addr) -> Self {
        Self {
            internal_map: HashMap::new(),
            external_map: HashMap::new(),
            external_ip,
            next_port: 1024,
            port_range: (1024, 65535),
            timeouts: NaptTimeouts::default(),
        }
    }

    /// Set external IP address
    pub fn set_external_ip(&mut self, ip: Ipv4Addr) {
        self.external_ip = ip;
    }

    /// Get external IP address
    pub fn external_ip(&self) -> Ipv4Addr {
        self.external_ip
    }

    /// Get or create a mapping for outbound traffic (SNAT)
    ///
    /// Uses Endpoint-Independent Mapping: same internal endpoint always gets
    /// the same external port regardless of destination.
    pub fn get_or_create_mapping(
        &mut self,
        internal: InternalEndpoint,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    ) -> Option<u16> {
        // Check existing mapping
        if let Some(entry) = self.internal_map.get_mut(&internal) {
            entry.last_used = Instant::now();
            return Some(entry.external_port);
        }

        // Allocate new external port
        let external_port = self.allocate_port()?;

        let now = Instant::now();
        let tcp_state = if internal.protocol == NaptProtocol::Tcp {
            Some(TcpState::SynSent)
        } else {
            None
        };

        let entry = NaptEntry {
            internal: internal.clone(),
            dst_ip,
            dst_port,
            external_port,
            created_at: now,
            last_used: now,
            tcp_state,
        };

        // Create reverse mapping key
        let external_key = ExternalKey {
            external_port,
            dst_ip,
            dst_port,
            protocol: internal.protocol,
        };

        self.internal_map.insert(internal.clone(), entry);
        self.external_map.insert(external_key, internal);

        Some(external_port)
    }

    /// Lookup internal endpoint for inbound traffic (DNAT)
    pub fn lookup_external(
        &mut self,
        external_port: u16,
        src_ip: Ipv4Addr,
        src_port: u16,
        protocol: NaptProtocol,
    ) -> Option<&InternalEndpoint> {
        let key = ExternalKey {
            external_port,
            dst_ip: src_ip, // Inbound: src is the original dst
            dst_port: src_port,
            protocol,
        };

        if let Some(internal) = self.external_map.get(&key) {
            // Update last_used
            if let Some(entry) = self.internal_map.get_mut(internal) {
                entry.last_used = Instant::now();
            }
            return self.external_map.get(&key);
        }

        None
    }

    /// Update TCP state based on flags (RFC 5382)
    pub fn update_tcp_state(&mut self, internal: &InternalEndpoint, flags: &TcpFlags) {
        if let Some(entry) = self.internal_map.get_mut(internal) {
            if let Some(ref mut state) = entry.tcp_state {
                *state = match *state {
                    TcpState::SynSent => {
                        if flags.is_syn_ack() {
                            TcpState::Established
                        } else if flags.is_rst() {
                            TcpState::Closed
                        } else {
                            TcpState::SynSent
                        }
                    }
                    TcpState::Established => {
                        if flags.is_fin() {
                            TcpState::FinWait
                        } else if flags.is_rst() {
                            TcpState::Closed
                        } else {
                            TcpState::Established
                        }
                    }
                    TcpState::FinWait => {
                        if flags.is_fin() || flags.is_rst() {
                            TcpState::Closed
                        } else {
                            TcpState::FinWait
                        }
                    }
                    TcpState::Closed => TcpState::Closed,
                };
            }
        }
    }

    /// Remove expired entries
    pub fn expire_old_entries(&mut self) {
        let now = Instant::now();
        let timeouts = &self.timeouts;

        // Collect expired internal endpoints
        let expired: Vec<InternalEndpoint> = self
            .internal_map
            .iter()
            .filter_map(|(internal, entry)| {
                let timeout = match entry.internal.protocol {
                    NaptProtocol::Tcp => {
                        match entry.tcp_state {
                            Some(TcpState::Established) => timeouts.tcp_established,
                            Some(TcpState::Closed) => Duration::from_secs(0), // Immediate
                            _ => timeouts.tcp_transitory,
                        }
                    }
                    NaptProtocol::Udp => timeouts.udp,
                    NaptProtocol::Icmp => timeouts.icmp,
                };

                if now.duration_since(entry.last_used) > timeout {
                    Some(internal.clone())
                } else {
                    None
                }
            })
            .collect();

        // Remove expired entries
        for internal in expired {
            if let Some(entry) = self.internal_map.remove(&internal) {
                let key = ExternalKey {
                    external_port: entry.external_port,
                    dst_ip: entry.dst_ip,
                    dst_port: entry.dst_port,
                    protocol: entry.internal.protocol,
                };
                self.external_map.remove(&key);
            }
        }
    }

    /// Allocate a new external port
    fn allocate_port(&mut self) -> Option<u16> {
        let (min, max) = self.port_range;
        let range_size = max - min + 1;

        // Try to find an unused port
        for _ in 0..range_size {
            let port = self.next_port;
            self.next_port = if self.next_port >= max {
                min
            } else {
                self.next_port + 1
            };

            // Check if port is in use
            let in_use = self.internal_map.values().any(|e| e.external_port == port);
            if !in_use {
                return Some(port);
            }
        }

        None // Port exhaustion
    }

    /// Get number of active mappings
    pub fn len(&self) -> usize {
        self.internal_map.len()
    }

    /// Check if table is empty
    pub fn is_empty(&self) -> bool {
        self.internal_map.is_empty()
    }
}

/// Result of NAPT translation
#[derive(Debug)]
pub enum NaptResult {
    /// Successfully translated packet
    Translated {
        /// Modified IPv4 packet bytes
        packet: Vec<u8>,
    },
    /// Packet should pass through without translation
    PassThrough,
    /// No mapping found (for inbound), drop packet
    NoMapping,
    /// Protocol not supported for NAPT
    Unsupported,
    /// Error during translation
    Error(String),
}

/// NAPT processor combining table and packet transformation
pub struct NaptProcessor {
    /// Translation table
    table: NaptTable,
    /// WAN interface name
    wan_interface: String,
}

impl NaptProcessor {
    /// Create a new NAPT processor
    pub fn new(wan_interface: String, external_ip: Ipv4Addr) -> Self {
        Self {
            table: NaptTable::new(external_ip),
            wan_interface,
        }
    }

    /// Get WAN interface name
    pub fn wan_interface(&self) -> &str {
        &self.wan_interface
    }

    /// Set external IP (e.g., after DHCP)
    pub fn set_external_ip(&mut self, ip: Ipv4Addr) {
        self.table.set_external_ip(ip);
    }

    /// Get external IP
    pub fn external_ip(&self) -> Ipv4Addr {
        self.table.external_ip()
    }

    /// Process outbound packet (LAN -> WAN): apply SNAT
    pub fn process_outbound(&mut self, ip_packet: &[u8]) -> NaptResult {
        let mut packet = match Ipv4Packet::from_bytes(ip_packet) {
            Ok(p) => p,
            Err(e) => return NaptResult::Error(format!("Invalid IPv4: {}", e)),
        };

        let protocol = match NaptProtocol::from_u8(packet.protocol()) {
            Some(p) => p,
            None => return NaptResult::PassThrough, // Unsupported protocol
        };

        let src_ip = packet.src_addr();
        let dst_ip = packet.dst_addr();
        let external_ip = self.table.external_ip();

        match protocol {
            NaptProtocol::Tcp => {
                self.translate_tcp_outbound(&mut packet, src_ip, dst_ip, external_ip)
            }
            NaptProtocol::Udp => {
                self.translate_udp_outbound(&mut packet, src_ip, dst_ip, external_ip)
            }
            NaptProtocol::Icmp => {
                self.translate_icmp_outbound(&mut packet, src_ip, dst_ip, external_ip)
            }
        }
    }

    /// Process inbound packet (WAN -> LAN): apply DNAT
    pub fn process_inbound(&mut self, ip_packet: &[u8]) -> NaptResult {
        let mut packet = match Ipv4Packet::from_bytes(ip_packet) {
            Ok(p) => p,
            Err(e) => return NaptResult::Error(format!("Invalid IPv4: {}", e)),
        };

        let protocol = match NaptProtocol::from_u8(packet.protocol()) {
            Some(p) => p,
            None => return NaptResult::PassThrough,
        };

        let src_ip = packet.src_addr();
        let dst_ip = packet.dst_addr();

        // Check if destined for our external IP
        if dst_ip != self.table.external_ip() {
            return NaptResult::PassThrough;
        }

        match protocol {
            NaptProtocol::Tcp => self.translate_tcp_inbound(&mut packet, src_ip),
            NaptProtocol::Udp => self.translate_udp_inbound(&mut packet, src_ip),
            NaptProtocol::Icmp => self.translate_icmp_inbound(&mut packet, src_ip),
        }
    }

    /// Translate TCP outbound
    fn translate_tcp_outbound(
        &mut self,
        packet: &mut Ipv4Packet,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        external_ip: Ipv4Addr,
    ) -> NaptResult {
        let payload = packet.payload();
        let mut tcp = match TcpPacket::from_bytes(payload) {
            Ok(t) => t,
            Err(e) => return NaptResult::Error(format!("Invalid TCP: {}", e)),
        };

        let src_port = tcp.src_port();
        let dst_port = tcp.dst_port();
        let flags = tcp.flags();

        let internal = InternalEndpoint {
            src_ip,
            src_port,
            protocol: NaptProtocol::Tcp,
        };

        let external_port =
            match self
                .table
                .get_or_create_mapping(internal.clone(), dst_ip, dst_port)
            {
                Some(p) => p,
                None => return NaptResult::Error("Port exhaustion".into()),
            };

        // Update TCP state
        self.table.update_tcp_state(&internal, &flags);

        // Modify TCP header
        tcp.set_src_port(external_port);
        tcp.update_checksum(external_ip, dst_ip);

        // Replace payload
        let tcp_bytes = tcp.into_bytes();
        packet.payload_mut()[..tcp_bytes.len()].copy_from_slice(&tcp_bytes);

        // Modify IP header
        packet.set_src_addr(external_ip);

        NaptResult::Translated {
            packet: packet.as_bytes().to_vec(),
        }
    }

    /// Translate TCP inbound
    fn translate_tcp_inbound(&mut self, packet: &mut Ipv4Packet, src_ip: Ipv4Addr) -> NaptResult {
        let payload = packet.payload();
        let mut tcp = match TcpPacket::from_bytes(payload) {
            Ok(t) => t,
            Err(e) => return NaptResult::Error(format!("Invalid TCP: {}", e)),
        };

        let external_port = tcp.dst_port();
        let src_port = tcp.src_port();
        let flags = tcp.flags();

        // Lookup mapping
        let internal =
            match self
                .table
                .lookup_external(external_port, src_ip, src_port, NaptProtocol::Tcp)
            {
                Some(i) => i.clone(),
                None => return NaptResult::NoMapping,
            };

        // Update TCP state
        self.table.update_tcp_state(&internal, &flags);

        // Modify TCP header
        tcp.set_dst_port(internal.src_port);
        tcp.update_checksum(src_ip, internal.src_ip);

        // Replace payload
        let tcp_bytes = tcp.into_bytes();
        packet.payload_mut()[..tcp_bytes.len()].copy_from_slice(&tcp_bytes);

        // Modify IP header
        packet.set_dst_addr(internal.src_ip);

        NaptResult::Translated {
            packet: packet.as_bytes().to_vec(),
        }
    }

    /// Translate UDP outbound
    fn translate_udp_outbound(
        &mut self,
        packet: &mut Ipv4Packet,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        external_ip: Ipv4Addr,
    ) -> NaptResult {
        let payload = packet.payload();
        let mut udp = match UdpPacket::from_bytes(payload) {
            Ok(u) => u,
            Err(e) => return NaptResult::Error(format!("Invalid UDP: {}", e)),
        };

        let src_port = udp.src_port();
        let dst_port = udp.dst_port();

        let internal = InternalEndpoint {
            src_ip,
            src_port,
            protocol: NaptProtocol::Udp,
        };

        let external_port = match self.table.get_or_create_mapping(internal, dst_ip, dst_port) {
            Some(p) => p,
            None => return NaptResult::Error("Port exhaustion".into()),
        };

        // Modify UDP header
        udp.set_src_port(external_port);
        udp.update_checksum(external_ip, dst_ip);

        // Replace payload
        let udp_bytes = udp.into_bytes();
        packet.payload_mut()[..udp_bytes.len()].copy_from_slice(&udp_bytes);

        // Modify IP header
        packet.set_src_addr(external_ip);

        NaptResult::Translated {
            packet: packet.as_bytes().to_vec(),
        }
    }

    /// Translate UDP inbound
    fn translate_udp_inbound(&mut self, packet: &mut Ipv4Packet, src_ip: Ipv4Addr) -> NaptResult {
        let payload = packet.payload();
        let mut udp = match UdpPacket::from_bytes(payload) {
            Ok(u) => u,
            Err(e) => return NaptResult::Error(format!("Invalid UDP: {}", e)),
        };

        let external_port = udp.dst_port();
        let src_port = udp.src_port();

        // Lookup mapping
        let internal =
            match self
                .table
                .lookup_external(external_port, src_ip, src_port, NaptProtocol::Udp)
            {
                Some(i) => i.clone(),
                None => return NaptResult::NoMapping,
            };

        // Modify UDP header
        udp.set_dst_port(internal.src_port);
        udp.update_checksum(src_ip, internal.src_ip);

        // Replace payload
        let udp_bytes = udp.into_bytes();
        packet.payload_mut()[..udp_bytes.len()].copy_from_slice(&udp_bytes);

        // Modify IP header
        packet.set_dst_addr(internal.src_ip);

        NaptResult::Translated {
            packet: packet.as_bytes().to_vec(),
        }
    }

    /// Translate ICMP outbound (Echo Request)
    fn translate_icmp_outbound(
        &mut self,
        packet: &mut Ipv4Packet,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        external_ip: Ipv4Addr,
    ) -> NaptResult {
        let payload = packet.payload();
        let mut icmp = match IcmpMutablePacket::from_bytes(payload) {
            Ok(i) => i,
            Err(e) => return NaptResult::Error(format!("Invalid ICMP: {}", e)),
        };

        // Only translate Echo Request/Reply
        if !icmp.is_echo() {
            return NaptResult::PassThrough;
        }

        let identifier = icmp.identifier();

        let internal = InternalEndpoint {
            src_ip,
            src_port: identifier,
            protocol: NaptProtocol::Icmp,
        };

        let external_id = match self.table.get_or_create_mapping(internal, dst_ip, 0) {
            Some(p) => p,
            None => return NaptResult::Error("ID exhaustion".into()),
        };

        // Modify ICMP identifier
        icmp.set_identifier(external_id);

        // Replace payload
        let icmp_bytes = icmp.into_bytes();
        packet.payload_mut()[..icmp_bytes.len()].copy_from_slice(&icmp_bytes);

        // Modify IP header
        packet.set_src_addr(external_ip);

        NaptResult::Translated {
            packet: packet.as_bytes().to_vec(),
        }
    }

    /// Translate ICMP inbound (Echo Reply)
    fn translate_icmp_inbound(&mut self, packet: &mut Ipv4Packet, src_ip: Ipv4Addr) -> NaptResult {
        let payload = packet.payload();
        let mut icmp = match IcmpMutablePacket::from_bytes(payload) {
            Ok(i) => i,
            Err(e) => return NaptResult::Error(format!("Invalid ICMP: {}", e)),
        };

        // Only translate Echo Request/Reply
        if !icmp.is_echo() {
            return NaptResult::PassThrough;
        }

        let external_id = icmp.identifier();

        // Lookup mapping
        let internal = match self
            .table
            .lookup_external(external_id, src_ip, 0, NaptProtocol::Icmp)
        {
            Some(i) => i.clone(),
            None => return NaptResult::NoMapping,
        };

        // Modify ICMP identifier
        icmp.set_identifier(internal.src_port);

        // Replace payload
        let icmp_bytes = icmp.into_bytes();
        packet.payload_mut()[..icmp_bytes.len()].copy_from_slice(&icmp_bytes);

        // Modify IP header
        packet.set_dst_addr(internal.src_ip);

        NaptResult::Translated {
            packet: packet.as_bytes().to_vec(),
        }
    }

    /// Run periodic maintenance (expire old entries)
    pub fn run_maintenance(&mut self) {
        self.table.expire_old_entries();
    }

    /// Get number of active mappings
    pub fn active_mappings(&self) -> usize {
        self.table.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ipv4::{Ipv4Builder, Protocol};
    use crate::protocol::tcp::tcp_checksum;
    use crate::protocol::udp::udp_checksum;

    fn make_tcp_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        // Create TCP segment
        let mut tcp = vec![
            (src_port >> 8) as u8,
            (src_port & 0xFF) as u8, // src port
            (dst_port >> 8) as u8,
            (dst_port & 0xFF) as u8, // dst port
            0,
            0,
            0,
            1, // seq
            0,
            0,
            0,
            0, // ack
            0x50,
            0x02, // offset + SYN flag
            0x72,
            0x10, // window
            0,
            0, // checksum
            0,
            0, // urgent
        ];

        // Calculate TCP checksum
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
            0, // checksum
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

    fn make_icmp_echo_request(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, identifier: u16) -> Vec<u8> {
        use crate::protocol::icmp::{icmp_checksum, IcmpType};

        let mut icmp = vec![
            IcmpType::EchoRequest as u8,
            0, // code
            0,
            0, // checksum
            (identifier >> 8) as u8,
            (identifier & 0xFF) as u8,
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
    fn test_napt_table_new() {
        let table = NaptTable::new(Ipv4Addr::new(203, 0, 113, 1));
        assert!(table.is_empty());
        assert_eq!(table.external_ip(), Ipv4Addr::new(203, 0, 113, 1));
    }

    #[test]
    fn test_napt_table_create_mapping() {
        let mut table = NaptTable::new(Ipv4Addr::new(203, 0, 113, 1));

        let internal = InternalEndpoint {
            src_ip: Ipv4Addr::new(192, 168, 1, 100),
            src_port: 12345,
            protocol: NaptProtocol::Tcp,
        };

        let port =
            table.get_or_create_mapping(internal.clone(), Ipv4Addr::new(93, 184, 216, 34), 80);

        assert!(port.is_some());
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_napt_table_reuse_mapping() {
        let mut table = NaptTable::new(Ipv4Addr::new(203, 0, 113, 1));

        let internal = InternalEndpoint {
            src_ip: Ipv4Addr::new(192, 168, 1, 100),
            src_port: 12345,
            protocol: NaptProtocol::Tcp,
        };

        let port1 = table
            .get_or_create_mapping(internal.clone(), Ipv4Addr::new(93, 184, 216, 34), 80)
            .unwrap();

        // Same internal endpoint should get same port (EIM)
        let port2 = table
            .get_or_create_mapping(
                internal,
                Ipv4Addr::new(1, 2, 3, 4), // Different destination
                443,
            )
            .unwrap();

        assert_eq!(port1, port2);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_napt_table_lookup_external() {
        let mut table = NaptTable::new(Ipv4Addr::new(203, 0, 113, 1));

        let internal = InternalEndpoint {
            src_ip: Ipv4Addr::new(192, 168, 1, 100),
            src_port: 12345,
            protocol: NaptProtocol::Tcp,
        };

        let dst_ip = Ipv4Addr::new(93, 184, 216, 34);
        let dst_port = 80;

        let external_port = table
            .get_or_create_mapping(internal.clone(), dst_ip, dst_port)
            .unwrap();

        // Lookup from external side (inbound)
        let found = table.lookup_external(external_port, dst_ip, dst_port, NaptProtocol::Tcp);
        assert!(found.is_some());
        assert_eq!(found.unwrap(), &internal);
    }

    #[test]
    fn test_napt_processor_tcp_outbound() {
        let wan_ip = Ipv4Addr::new(203, 0, 113, 1);
        let mut processor = NaptProcessor::new("eth0".into(), wan_ip);

        let packet = make_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(93, 184, 216, 34),
            12345,
            80,
        );

        let result = processor.process_outbound(&packet);

        match result {
            NaptResult::Translated { packet: translated } => {
                let ip = Ipv4Packet::from_bytes(&translated).unwrap();
                assert_eq!(ip.src_addr(), wan_ip);
            }
            _ => panic!("Expected Translated result"),
        }
    }

    #[test]
    fn test_napt_processor_tcp_roundtrip() {
        let wan_ip = Ipv4Addr::new(203, 0, 113, 1);
        let lan_ip = Ipv4Addr::new(192, 168, 1, 100);
        let server_ip = Ipv4Addr::new(93, 184, 216, 34);
        let lan_port = 12345u16;
        let server_port = 80u16;

        let mut processor = NaptProcessor::new("eth0".into(), wan_ip);

        // Outbound: LAN -> WAN
        let outbound = make_tcp_packet(lan_ip, server_ip, lan_port, server_port);
        let out_result = processor.process_outbound(&outbound);

        let external_port = match out_result {
            NaptResult::Translated { ref packet } => {
                let tcp = TcpPacket::from_bytes(&Ipv4Packet::from_bytes(packet).unwrap().payload())
                    .unwrap();
                tcp.src_port()
            }
            _ => panic!("Expected Translated"),
        };

        // Inbound: WAN -> LAN (response)
        let inbound = make_tcp_packet(server_ip, wan_ip, server_port, external_port);
        let in_result = processor.process_inbound(&inbound);

        match in_result {
            NaptResult::Translated { packet } => {
                let ip = Ipv4Packet::from_bytes(&packet).unwrap();
                assert_eq!(ip.dst_addr(), lan_ip);

                let tcp = TcpPacket::from_bytes(ip.payload()).unwrap();
                assert_eq!(tcp.dst_port(), lan_port);
            }
            _ => panic!("Expected Translated for inbound"),
        }
    }

    #[test]
    fn test_napt_processor_udp_outbound() {
        let wan_ip = Ipv4Addr::new(203, 0, 113, 1);
        let mut processor = NaptProcessor::new("eth0".into(), wan_ip);

        let packet = make_udp_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(8, 8, 8, 8),
            54321,
            53,
        );

        let result = processor.process_outbound(&packet);

        match result {
            NaptResult::Translated { packet: translated } => {
                let ip = Ipv4Packet::from_bytes(&translated).unwrap();
                assert_eq!(ip.src_addr(), wan_ip);
            }
            _ => panic!("Expected Translated"),
        }
    }

    #[test]
    fn test_napt_processor_icmp_outbound() {
        let wan_ip = Ipv4Addr::new(203, 0, 113, 1);
        let mut processor = NaptProcessor::new("eth0".into(), wan_ip);

        let packet = make_icmp_echo_request(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(8, 8, 8, 8),
            0x1234,
        );

        let result = processor.process_outbound(&packet);

        match result {
            NaptResult::Translated { packet: translated } => {
                let ip = Ipv4Packet::from_bytes(&translated).unwrap();
                assert_eq!(ip.src_addr(), wan_ip);
            }
            _ => panic!("Expected Translated"),
        }
    }

    #[test]
    fn test_napt_processor_inbound_no_mapping() {
        let wan_ip = Ipv4Addr::new(203, 0, 113, 1);
        let mut processor = NaptProcessor::new("eth0".into(), wan_ip);

        // Inbound packet without prior outbound
        let packet = make_tcp_packet(Ipv4Addr::new(93, 184, 216, 34), wan_ip, 80, 12345);

        let result = processor.process_inbound(&packet);

        match result {
            NaptResult::NoMapping => {}
            _ => panic!("Expected NoMapping"),
        }
    }

    #[test]
    fn test_napt_table_expire_entries() {
        let mut table = NaptTable::new(Ipv4Addr::new(203, 0, 113, 1));

        // Set very short timeout for testing
        table.timeouts.tcp_transitory = Duration::from_millis(1);

        let internal = InternalEndpoint {
            src_ip: Ipv4Addr::new(192, 168, 1, 100),
            src_port: 12345,
            protocol: NaptProtocol::Tcp,
        };

        table.get_or_create_mapping(internal, Ipv4Addr::new(1, 2, 3, 4), 80);
        assert_eq!(table.len(), 1);

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(10));

        table.expire_old_entries();
        assert_eq!(table.len(), 0);
    }
}
