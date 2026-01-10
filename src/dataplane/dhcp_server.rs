//! DHCPv4 Server
//!
//! DHCP server implementation for automatic IP address assignment.
//! Supports DISCOVER/OFFER/REQUEST/ACK flow (DORA) per RFC 2131.

use crate::protocol::dhcp::{DhcpBuilder, DhcpHeader, DhcpMessageType};
use crate::protocol::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

/// DHCP server processing result
#[derive(Debug)]
pub enum DhcpAction {
    /// Send a DHCP reply
    Reply {
        /// Interface to send on
        interface: String,
        /// DHCP payload (to be wrapped in UDP/IP/Ethernet)
        packet: Vec<u8>,
        /// Destination IP (broadcast or unicast)
        dst_ip: Ipv4Addr,
        /// Destination MAC
        dst_mac: MacAddr,
    },
    /// No action needed
    None,
}

/// State of an IP address lease
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// Available for allocation
    Available,
    /// Offered but not yet confirmed (waiting for REQUEST)
    Offered,
    /// Actively leased to a client
    Leased,
}

/// A single lease entry
#[derive(Debug, Clone)]
pub struct LeaseEntry {
    /// Assigned IP address
    pub ip_addr: Ipv4Addr,
    /// Client MAC address
    pub mac_addr: [u8; 6],
    /// Current state
    pub state: LeaseState,
    /// When the offer was sent (for offer timeout)
    pub offered_at: Option<Instant>,
    /// When the lease was confirmed
    pub leased_at: Option<Instant>,
    /// When the lease expires
    pub expires_at: Option<Instant>,
    /// Client hostname (if provided)
    pub hostname: Option<String>,
}

impl LeaseEntry {
    fn new(ip_addr: Ipv4Addr) -> Self {
        Self {
            ip_addr,
            mac_addr: [0; 6],
            state: LeaseState::Available,
            offered_at: None,
            leased_at: None,
            expires_at: None,
            hostname: None,
        }
    }
}

/// DHCP pool configuration for a single interface
#[derive(Debug, Clone)]
pub struct DhcpPoolConfig {
    /// Interface name
    pub interface: String,
    /// Start of IP range
    pub range_start: Ipv4Addr,
    /// End of IP range (inclusive)
    pub range_end: Ipv4Addr,
    /// Subnet mask
    pub subnet_mask: Ipv4Addr,
    /// Default gateway
    pub gateway: Ipv4Addr,
    /// DNS servers
    pub dns_servers: Vec<Ipv4Addr>,
    /// Lease time in seconds
    pub lease_time: u32,
    /// Offer timeout in seconds (how long to hold an offer)
    pub offer_timeout: u64,
}

/// DHCP pool for a single interface
#[derive(Debug)]
pub struct DhcpPool {
    config: DhcpPoolConfig,
    /// IP -> LeaseEntry mapping
    leases: HashMap<Ipv4Addr, LeaseEntry>,
    /// MAC -> IP reverse mapping for quick lookup
    mac_to_ip: HashMap<[u8; 6], Ipv4Addr>,
}

impl DhcpPool {
    /// Create a new DHCP pool
    pub fn new(config: DhcpPoolConfig) -> Self {
        let mut leases = HashMap::new();

        // Initialize all IPs in range as available
        let start = u32::from(config.range_start);
        let end = u32::from(config.range_end);

        for ip_num in start..=end {
            let ip = Ipv4Addr::from(ip_num);
            leases.insert(ip, LeaseEntry::new(ip));
        }

        debug!(
            "DHCP pool created for {} with {} addresses ({} - {})",
            config.interface,
            leases.len(),
            config.range_start,
            config.range_end
        );

        Self {
            config,
            leases,
            mac_to_ip: HashMap::new(),
        }
    }

    /// Find an existing lease for a MAC address
    pub fn find_by_mac(&self, mac: &[u8; 6]) -> Option<Ipv4Addr> {
        self.mac_to_ip.get(mac).copied()
    }

    /// Allocate an IP for a client
    ///
    /// Returns existing allocation if client already has one,
    /// otherwise finds a free IP.
    pub fn allocate_ip(&mut self, mac: [u8; 6]) -> Option<Ipv4Addr> {
        // Check for existing allocation
        if let Some(ip) = self.find_by_mac(&mac) {
            return Some(ip);
        }

        // Find first available IP
        let available_ip = self
            .leases
            .values()
            .find(|e| e.state == LeaseState::Available)
            .map(|e| e.ip_addr);

        if let Some(ip) = available_ip {
            // Mark as offered
            if let Some(entry) = self.leases.get_mut(&ip) {
                entry.mac_addr = mac;
                entry.state = LeaseState::Offered;
                entry.offered_at = Some(Instant::now());
            }
            self.mac_to_ip.insert(mac, ip);
            debug!("Allocated IP {} for MAC {:02x?}", ip, mac);
            Some(ip)
        } else {
            warn!("DHCP pool exhausted for {}", self.config.interface);
            None
        }
    }

    /// Confirm a lease (after REQUEST)
    pub fn confirm_lease(&mut self, ip: Ipv4Addr, mac: [u8; 6]) -> bool {
        if let Some(entry) = self.leases.get_mut(&ip) {
            // Verify MAC matches
            if entry.mac_addr != mac {
                warn!("Lease confirmation failed: MAC mismatch for {}", ip);
                return false;
            }

            // Only confirm if offered or already leased (renewal)
            if entry.state == LeaseState::Offered || entry.state == LeaseState::Leased {
                let now = Instant::now();
                entry.state = LeaseState::Leased;
                entry.leased_at = Some(now);
                entry.expires_at = Some(now + Duration::from_secs(self.config.lease_time as u64));
                debug!("Lease confirmed for IP {} MAC {:02x?}", ip, mac);
                return true;
            }
        }
        false
    }

    /// Release a lease
    pub fn release(&mut self, ip: Ipv4Addr, mac: [u8; 6]) {
        if let Some(entry) = self.leases.get_mut(&ip) {
            if entry.mac_addr == mac {
                self.mac_to_ip.remove(&mac);
                *entry = LeaseEntry::new(ip);
                debug!("Lease released for IP {}", ip);
            }
        }
    }

    /// Check if an IP is valid for a specific MAC
    pub fn is_valid_for_mac(&self, ip: Ipv4Addr, mac: &[u8; 6]) -> bool {
        if let Some(entry) = self.leases.get(&ip) {
            // IP must be offered or leased to this MAC
            (entry.state == LeaseState::Offered || entry.state == LeaseState::Leased)
                && entry.mac_addr == *mac
        } else {
            false
        }
    }

    /// Expire old offers and leases
    pub fn run_maintenance(&mut self) {
        let now = Instant::now();
        let offer_timeout = Duration::from_secs(self.config.offer_timeout);

        let mut expired_macs = Vec::new();

        for entry in self.leases.values_mut() {
            let should_expire = match entry.state {
                LeaseState::Offered => {
                    // Expire offers that weren't confirmed
                    entry
                        .offered_at
                        .is_some_and(|t| now.duration_since(t) > offer_timeout)
                }
                LeaseState::Leased => {
                    // Expire old leases
                    entry.expires_at.is_some_and(|t| now > t)
                }
                LeaseState::Available => false,
            };

            if should_expire {
                trace!("Expiring lease for IP {}", entry.ip_addr);
                expired_macs.push(entry.mac_addr);
                *entry = LeaseEntry::new(entry.ip_addr);
            }
        }

        // Clean up reverse mapping
        for mac in expired_macs {
            self.mac_to_ip.remove(&mac);
        }
    }

    /// Get number of available addresses
    pub fn available_count(&self) -> usize {
        self.leases
            .values()
            .filter(|e| e.state == LeaseState::Available)
            .count()
    }

    /// Get number of leased addresses
    pub fn leased_count(&self) -> usize {
        self.leases
            .values()
            .filter(|e| e.state == LeaseState::Leased)
            .count()
    }

    /// Get the config
    pub fn config(&self) -> &DhcpPoolConfig {
        &self.config
    }
}

/// DHCP Server supporting multiple interfaces
#[derive(Debug, Default)]
pub struct DhcpServer {
    /// Interface name -> pool mapping
    pools: HashMap<String, DhcpPool>,
}

impl DhcpServer {
    /// Create a new DHCP server
    pub fn new() -> Self {
        Self {
            pools: HashMap::new(),
        }
    }

    /// Add a DHCP pool for an interface
    pub fn add_pool(&mut self, config: DhcpPoolConfig) {
        let interface = config.interface.clone();
        self.pools.insert(interface, DhcpPool::new(config));
    }

    /// Remove a DHCP pool
    pub fn remove_pool(&mut self, interface: &str) {
        self.pools.remove(interface);
    }

    /// Check if DHCP is enabled for an interface
    pub fn has_pool(&self, interface: &str) -> bool {
        self.pools.contains_key(interface)
    }

    /// Process a DHCP packet
    ///
    /// # Arguments
    /// * `interface` - The interface the packet arrived on
    /// * `server_ip` - Our IP address on this interface
    /// * `dhcp_payload` - The DHCP message (UDP payload)
    pub fn process_dhcp(
        &mut self,
        interface: &str,
        server_ip: Ipv4Addr,
        dhcp_payload: &[u8],
    ) -> DhcpAction {
        // Parse DHCP message
        let msg = match DhcpHeader::parse(dhcp_payload) {
            Ok(m) => m,
            Err(e) => {
                debug!("Failed to parse DHCP message: {}", e);
                return DhcpAction::None;
            }
        };

        // Must be a request (client -> server)
        if msg.op() != 1 {
            return DhcpAction::None;
        }

        // Get message type
        let msg_type = match msg.message_type() {
            Some(t) => t,
            None => {
                debug!("DHCP message without message type");
                return DhcpAction::None;
            }
        };

        // Get pool for this interface
        let pool = match self.pools.get_mut(interface) {
            Some(p) => p,
            None => {
                debug!("No DHCP pool for interface {}", interface);
                return DhcpAction::None;
            }
        };

        debug!(
            "Processing DHCP {:?} from {:02x?} on {}",
            msg_type,
            msg.client_mac(),
            interface
        );

        match msg_type {
            DhcpMessageType::Discover => Self::handle_discover(pool, interface, server_ip, &msg),
            DhcpMessageType::Request => Self::handle_request(pool, interface, server_ip, &msg),
            DhcpMessageType::Release => {
                Self::handle_release(pool, &msg);
                DhcpAction::None
            }
            DhcpMessageType::Decline => {
                Self::handle_decline(pool, &msg);
                DhcpAction::None
            }
            DhcpMessageType::Inform => {
                // INFORM: Client has IP, just wants config
                Self::handle_inform(pool, interface, server_ip, &msg)
            }
            _ => {
                // Other message types (OFFER, ACK, NAK) are server->client
                DhcpAction::None
            }
        }
    }

    /// Handle DHCP DISCOVER - allocate and offer an IP
    fn handle_discover(
        pool: &mut DhcpPool,
        interface: &str,
        server_ip: Ipv4Addr,
        msg: &DhcpHeader,
    ) -> DhcpAction {
        let client_mac = msg.client_mac();

        // Allocate an IP for this client
        let offered_ip = match pool.allocate_ip(client_mac) {
            Some(ip) => ip,
            None => return DhcpAction::None,
        };

        // Build OFFER
        let config = pool.config();
        let packet = DhcpBuilder::reply(msg)
            .message_type(DhcpMessageType::Offer)
            .yiaddr(offered_ip)
            .siaddr(server_ip)
            .server_id(server_ip)
            .subnet_mask(config.subnet_mask)
            .router(&[config.gateway])
            .dns(&config.dns_servers)
            .lease_time(config.lease_time)
            .renewal_time(config.lease_time / 2)
            .rebinding_time(config.lease_time * 7 / 8)
            .build();

        debug!("Sending DHCP OFFER: {} to {:02x?}", offered_ip, client_mac);

        // Determine destination
        let (dst_ip, dst_mac) = if msg.is_broadcast() || msg.ciaddr() == Ipv4Addr::UNSPECIFIED {
            // Broadcast
            (
                Ipv4Addr::BROADCAST,
                MacAddr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            )
        } else {
            // Unicast to client
            (msg.ciaddr(), MacAddr(client_mac))
        };

        DhcpAction::Reply {
            interface: interface.to_string(),
            packet,
            dst_ip,
            dst_mac,
        }
    }

    /// Handle DHCP REQUEST - confirm or reject the lease
    fn handle_request(
        pool: &mut DhcpPool,
        interface: &str,
        server_ip: Ipv4Addr,
        msg: &DhcpHeader,
    ) -> DhcpAction {
        let client_mac = msg.client_mac();

        // Check if this request is for us
        if let Some(requested_server) = msg.server_id() {
            if requested_server != server_ip {
                // Request is for another server, ignore
                debug!("DHCP REQUEST for different server: {}", requested_server);
                return DhcpAction::None;
            }
        }

        // Determine requested IP
        let requested_ip = msg.requested_ip().or_else(|| {
            // During renewal, client uses ciaddr
            let ci = msg.ciaddr();
            if ci != Ipv4Addr::UNSPECIFIED {
                Some(ci)
            } else {
                None
            }
        });

        let requested_ip = match requested_ip {
            Some(ip) => ip,
            None => {
                debug!("DHCP REQUEST without requested IP");
                return Self::send_nak(pool, interface, server_ip, msg);
            }
        };

        // Verify the request is valid
        if !pool.is_valid_for_mac(requested_ip, &client_mac) {
            debug!(
                "DHCP REQUEST for invalid IP {} from {:02x?}",
                requested_ip, client_mac
            );
            return Self::send_nak(pool, interface, server_ip, msg);
        }

        // Confirm the lease
        if !pool.confirm_lease(requested_ip, client_mac) {
            return Self::send_nak(pool, interface, server_ip, msg);
        }

        // Build ACK
        let config = pool.config();
        let packet = DhcpBuilder::reply(msg)
            .message_type(DhcpMessageType::Ack)
            .yiaddr(requested_ip)
            .siaddr(server_ip)
            .server_id(server_ip)
            .subnet_mask(config.subnet_mask)
            .router(&[config.gateway])
            .dns(&config.dns_servers)
            .lease_time(config.lease_time)
            .renewal_time(config.lease_time / 2)
            .rebinding_time(config.lease_time * 7 / 8)
            .build();

        debug!("Sending DHCP ACK: {} to {:02x?}", requested_ip, client_mac);

        // Determine destination
        let (dst_ip, dst_mac) = if msg.is_broadcast() || msg.ciaddr() == Ipv4Addr::UNSPECIFIED {
            (
                Ipv4Addr::BROADCAST,
                MacAddr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            )
        } else {
            (msg.ciaddr(), MacAddr(client_mac))
        };

        DhcpAction::Reply {
            interface: interface.to_string(),
            packet,
            dst_ip,
            dst_mac,
        }
    }

    /// Send a DHCP NAK
    fn send_nak(
        pool: &DhcpPool,
        interface: &str,
        server_ip: Ipv4Addr,
        msg: &DhcpHeader,
    ) -> DhcpAction {
        let _ = pool; // unused but kept for consistency

        let packet = DhcpBuilder::reply(msg)
            .message_type(DhcpMessageType::Nak)
            .server_id(server_ip)
            .build();

        debug!("Sending DHCP NAK to {:02x?}", msg.client_mac());

        // NAK is always broadcast
        DhcpAction::Reply {
            interface: interface.to_string(),
            packet,
            dst_ip: Ipv4Addr::BROADCAST,
            dst_mac: MacAddr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        }
    }

    /// Handle DHCP RELEASE
    fn handle_release(pool: &mut DhcpPool, msg: &DhcpHeader) {
        let client_mac = msg.client_mac();
        let client_ip = msg.ciaddr();

        if client_ip != Ipv4Addr::UNSPECIFIED {
            debug!("DHCP RELEASE: {} from {:02x?}", client_ip, client_mac);
            pool.release(client_ip, client_mac);
        }
    }

    /// Handle DHCP DECLINE
    fn handle_decline(pool: &mut DhcpPool, msg: &DhcpHeader) {
        // Client detected IP conflict - mark as unavailable
        if let Some(ip) = msg.requested_ip() {
            warn!("DHCP DECLINE for {} - IP conflict detected", ip);
            // For simplicity, we just release it
            // A production server might mark it as "bad" for a while
            pool.release(ip, msg.client_mac());
        }
    }

    /// Handle DHCP INFORM - client has IP, just wants config
    fn handle_inform(
        pool: &mut DhcpPool,
        interface: &str,
        server_ip: Ipv4Addr,
        msg: &DhcpHeader,
    ) -> DhcpAction {
        let config = pool.config();

        // INFORM response: ACK without yiaddr or lease time
        let packet = DhcpBuilder::reply(msg)
            .message_type(DhcpMessageType::Ack)
            .siaddr(server_ip)
            .server_id(server_ip)
            .subnet_mask(config.subnet_mask)
            .router(&[config.gateway])
            .dns(&config.dns_servers)
            .build();

        debug!("Sending DHCP ACK (INFORM) to {:02x?}", msg.client_mac());

        // INFORM response is unicast to ciaddr
        let client_ip = msg.ciaddr();
        let (dst_ip, dst_mac) = if client_ip != Ipv4Addr::UNSPECIFIED {
            (client_ip, MacAddr(msg.client_mac()))
        } else {
            (
                Ipv4Addr::BROADCAST,
                MacAddr([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            )
        };

        DhcpAction::Reply {
            interface: interface.to_string(),
            packet,
            dst_ip,
            dst_mac,
        }
    }

    /// Run maintenance on all pools (expire old leases)
    pub fn run_maintenance(&mut self) {
        for pool in self.pools.values_mut() {
            pool.run_maintenance();
        }
    }

    /// Get statistics for an interface
    pub fn get_stats(&self, interface: &str) -> Option<(usize, usize)> {
        self.pools
            .get(interface)
            .map(|p| (p.available_count(), p.leased_count()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pool_config() -> DhcpPoolConfig {
        DhcpPoolConfig {
            interface: "eth0".to_string(),
            range_start: Ipv4Addr::new(192, 168, 1, 100),
            range_end: Ipv4Addr::new(192, 168, 1, 110),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
            lease_time: 3600,
            offer_timeout: 60,
        }
    }

    fn make_discover(mac: [u8; 6]) -> Vec<u8> {
        let mut packet = vec![0u8; 300];
        packet[0] = 1; // BOOTREQUEST
        packet[1] = 1; // Ethernet
        packet[2] = 6; // MAC length
        packet[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
        packet[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // Broadcast
        packet[28..34].copy_from_slice(&mac);
        packet[236..240].copy_from_slice(&[99, 130, 83, 99]); // Magic cookie
        packet[240] = 53; // Message type option
        packet[241] = 1;
        packet[242] = 1; // DISCOVER
        packet[243] = 255; // END
        packet
    }

    fn make_request(mac: [u8; 6], requested_ip: Ipv4Addr, server_id: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 300];
        packet[0] = 1; // BOOTREQUEST
        packet[1] = 1;
        packet[2] = 6;
        packet[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
        packet[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
        packet[28..34].copy_from_slice(&mac);
        packet[236..240].copy_from_slice(&[99, 130, 83, 99]);

        let mut pos = 240;
        // Message type = REQUEST
        packet[pos] = 53;
        packet[pos + 1] = 1;
        packet[pos + 2] = 3;
        pos += 3;
        // Requested IP
        packet[pos] = 50;
        packet[pos + 1] = 4;
        packet[pos + 2..pos + 6].copy_from_slice(&requested_ip.octets());
        pos += 6;
        // Server ID
        packet[pos] = 54;
        packet[pos + 1] = 4;
        packet[pos + 2..pos + 6].copy_from_slice(&server_id.octets());
        pos += 6;
        // END
        packet[pos] = 255;

        packet
    }

    #[test]
    fn test_pool_allocate() {
        let config = make_pool_config();
        let mut pool = DhcpPool::new(config);

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ip = pool.allocate_ip(mac).unwrap();

        assert!(ip >= Ipv4Addr::new(192, 168, 1, 100));
        assert!(ip <= Ipv4Addr::new(192, 168, 1, 110));

        // Same MAC should get same IP
        let ip2 = pool.allocate_ip(mac).unwrap();
        assert_eq!(ip, ip2);

        // Different MAC should get different IP
        let mac2 = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ip3 = pool.allocate_ip(mac2).unwrap();
        assert_ne!(ip, ip3);
    }

    #[test]
    fn test_pool_exhaust() {
        let mut config = make_pool_config();
        config.range_start = Ipv4Addr::new(192, 168, 1, 100);
        config.range_end = Ipv4Addr::new(192, 168, 1, 101); // Only 2 IPs
        let mut pool = DhcpPool::new(config);

        let mac1 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mac2 = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mac3 = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        assert!(pool.allocate_ip(mac1).is_some());
        assert!(pool.allocate_ip(mac2).is_some());
        assert!(pool.allocate_ip(mac3).is_none()); // Pool exhausted
    }

    #[test]
    fn test_pool_confirm_lease() {
        let config = make_pool_config();
        let mut pool = DhcpPool::new(config);

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ip = pool.allocate_ip(mac).unwrap();

        // Should be offered, not leased
        assert_eq!(pool.leased_count(), 0);

        // Confirm the lease
        assert!(pool.confirm_lease(ip, mac));
        assert_eq!(pool.leased_count(), 1);

        // Wrong MAC should fail
        let wrong_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert!(!pool.confirm_lease(ip, wrong_mac));
    }

    #[test]
    fn test_pool_release() {
        let config = make_pool_config();
        let mut pool = DhcpPool::new(config);

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ip = pool.allocate_ip(mac).unwrap();
        pool.confirm_lease(ip, mac);

        assert_eq!(pool.leased_count(), 1);

        pool.release(ip, mac);
        assert_eq!(pool.leased_count(), 0);
        assert!(pool.find_by_mac(&mac).is_none());
    }

    #[test]
    fn test_server_discover_offer() {
        let config = make_pool_config();
        let mut server = DhcpServer::new();
        server.add_pool(config);

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let discover = make_discover(mac);
        let server_ip = Ipv4Addr::new(192, 168, 1, 1);

        let action = server.process_dhcp("eth0", server_ip, &discover);

        match action {
            DhcpAction::Reply { packet, dst_ip, .. } => {
                assert_eq!(dst_ip, Ipv4Addr::BROADCAST);
                let header = DhcpHeader::parse(&packet).unwrap();
                assert_eq!(header.message_type(), Some(DhcpMessageType::Offer));
                assert!(header.yiaddr() >= Ipv4Addr::new(192, 168, 1, 100));
            }
            _ => panic!("Expected Reply action"),
        }
    }

    #[test]
    fn test_server_request_ack() {
        let config = make_pool_config();
        let mut server = DhcpServer::new();
        server.add_pool(config);

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let server_ip = Ipv4Addr::new(192, 168, 1, 1);

        // First, DISCOVER
        let discover = make_discover(mac);
        let offer_action = server.process_dhcp("eth0", server_ip, &discover);
        let offered_ip = match offer_action {
            DhcpAction::Reply { packet, .. } => DhcpHeader::parse(&packet).unwrap().yiaddr(),
            _ => panic!("Expected offer"),
        };

        // Then, REQUEST
        let request = make_request(mac, offered_ip, server_ip);
        let ack_action = server.process_dhcp("eth0", server_ip, &request);

        match ack_action {
            DhcpAction::Reply { packet, .. } => {
                let header = DhcpHeader::parse(&packet).unwrap();
                assert_eq!(header.message_type(), Some(DhcpMessageType::Ack));
                assert_eq!(header.yiaddr(), offered_ip);
            }
            _ => panic!("Expected ACK"),
        }
    }

    #[test]
    fn test_server_request_wrong_server() {
        let config = make_pool_config();
        let mut server = DhcpServer::new();
        server.add_pool(config);

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let server_ip = Ipv4Addr::new(192, 168, 1, 1);
        let other_server = Ipv4Addr::new(192, 168, 1, 2);

        // First, DISCOVER
        let discover = make_discover(mac);
        server.process_dhcp("eth0", server_ip, &discover);

        // REQUEST for different server
        let request = make_request(mac, Ipv4Addr::new(192, 168, 1, 100), other_server);
        let action = server.process_dhcp("eth0", server_ip, &request);

        // Should be ignored (not for us)
        match action {
            DhcpAction::None => {}
            _ => panic!("Expected None for request to different server"),
        }
    }

    #[test]
    fn test_server_request_invalid_ip() {
        let config = make_pool_config();
        let mut server = DhcpServer::new();
        server.add_pool(config);

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let server_ip = Ipv4Addr::new(192, 168, 1, 1);

        // REQUEST without DISCOVER (invalid IP)
        let request = make_request(mac, Ipv4Addr::new(192, 168, 1, 100), server_ip);
        let action = server.process_dhcp("eth0", server_ip, &request);

        match action {
            DhcpAction::Reply { packet, .. } => {
                let header = DhcpHeader::parse(&packet).unwrap();
                assert_eq!(header.message_type(), Some(DhcpMessageType::Nak));
            }
            _ => panic!("Expected NAK"),
        }
    }

    #[test]
    fn test_server_no_pool() {
        let mut server = DhcpServer::new();
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let discover = make_discover(mac);

        let action = server.process_dhcp("eth0", Ipv4Addr::new(192, 168, 1, 1), &discover);

        match action {
            DhcpAction::None => {}
            _ => panic!("Expected None for interface without pool"),
        }
    }

    #[test]
    fn test_pool_maintenance() {
        let mut config = make_pool_config();
        config.offer_timeout = 0; // Immediate timeout for test
        let mut pool = DhcpPool::new(config);

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ip = pool.allocate_ip(mac).unwrap();

        // Should be offered
        assert!(pool.find_by_mac(&mac).is_some());

        // Wait a tiny bit and run maintenance
        std::thread::sleep(std::time::Duration::from_millis(10));
        pool.run_maintenance();

        // Should be expired
        assert!(pool.find_by_mac(&mac).is_none());

        // IP should be available again
        let ip2 = pool.allocate_ip(mac).unwrap();
        assert_eq!(ip, ip2);
    }
}
