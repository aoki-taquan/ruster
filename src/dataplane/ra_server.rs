//! Router Advertisement Server
//!
//! RA server implementation for advertising IPv6 prefixes on LAN interfaces.
//! Responds to Router Solicitations and sends periodic unsolicited RAs.
//! Follows RFC 4861 (NDP).

use crate::protocol::icmpv6::{
    set_checksum, PrefixInformation, RouterAdvertisement, RouterSolicitation,
};
use crate::protocol::MacAddr;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

/// RA server processing result
#[derive(Debug)]
pub enum RaServerAction {
    /// Send a Router Advertisement
    SendRa {
        /// Interface to send on
        interface: String,
        /// ICMPv6 RA payload (to be wrapped in IPv6/Ethernet)
        packet: Vec<u8>,
        /// Destination IPv6 address
        dst_ip: Ipv6Addr,
        /// Destination MAC address
        dst_mac: MacAddr,
    },
    /// No action needed
    None,
}

/// Prefix to advertise
#[derive(Debug, Clone)]
pub struct AdvertisedPrefix {
    /// Prefix address
    pub prefix: Ipv6Addr,
    /// Prefix length
    pub prefix_len: u8,
    /// On-link flag (L)
    pub on_link: bool,
    /// Autonomous flag (A) - enables SLAAC
    pub autonomous: bool,
    /// Valid lifetime in seconds (0xFFFFFFFF = infinite)
    pub valid_lifetime: u32,
    /// Preferred lifetime in seconds
    pub preferred_lifetime: u32,
}

impl AdvertisedPrefix {
    /// Create a new prefix for advertising
    pub fn new(prefix: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            prefix,
            prefix_len,
            on_link: true,
            autonomous: true,
            valid_lifetime: 2592000,    // 30 days
            preferred_lifetime: 604800, // 7 days
        }
    }

    /// Set on-link flag
    pub fn with_on_link(mut self, on_link: bool) -> Self {
        self.on_link = on_link;
        self
    }

    /// Set autonomous flag
    pub fn with_autonomous(mut self, autonomous: bool) -> Self {
        self.autonomous = autonomous;
        self
    }

    /// Set valid lifetime
    pub fn with_valid_lifetime(mut self, seconds: u32) -> Self {
        self.valid_lifetime = seconds;
        self
    }

    /// Set preferred lifetime
    pub fn with_preferred_lifetime(mut self, seconds: u32) -> Self {
        self.preferred_lifetime = seconds;
        self
    }

    /// Convert to PrefixInformation for RA
    fn to_prefix_info(&self) -> PrefixInformation {
        PrefixInformation::new(
            self.prefix,
            self.prefix_len,
            self.on_link,
            self.autonomous,
            self.valid_lifetime,
            self.preferred_lifetime,
        )
    }
}

/// RA server configuration for an interface
#[derive(Debug, Clone)]
pub struct RaServerConfig {
    /// Interface name
    pub interface: String,
    /// Prefixes to advertise
    pub prefixes: Vec<AdvertisedPrefix>,
    /// M flag: Use DHCPv6 for address configuration
    pub managed_flag: bool,
    /// O flag: Use DHCPv6 for other configuration (DNS, etc.)
    pub other_flag: bool,
    /// Current hop limit to advertise (0 = unspecified)
    pub cur_hop_limit: u8,
    /// Router lifetime in seconds (0 = not a default router)
    pub router_lifetime: u16,
    /// Reachable time in milliseconds (0 = unspecified)
    pub reachable_time: u32,
    /// Retrans timer in milliseconds (0 = unspecified)
    pub retrans_timer: u32,
    /// MTU to advertise (None = don't include MTU option)
    pub mtu: Option<u32>,
    /// Minimum RA interval in seconds
    pub min_ra_interval: u16,
    /// Maximum RA interval in seconds
    pub max_ra_interval: u16,
    /// DNS servers to advertise (RDNSS)
    pub dns_servers: Vec<Ipv6Addr>,
    /// DNS lifetime in seconds
    pub dns_lifetime: u32,
}

impl Default for RaServerConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            prefixes: Vec::new(),
            managed_flag: false,
            other_flag: false,
            cur_hop_limit: 64,
            router_lifetime: 1800,
            reachable_time: 0,
            retrans_timer: 0,
            mtu: None,
            min_ra_interval: 200,
            max_ra_interval: 600,
            dns_servers: Vec::new(),
            dns_lifetime: 0,
        }
    }
}

impl RaServerConfig {
    /// Create a new RA server configuration
    pub fn new(interface: String) -> Self {
        Self {
            interface,
            ..Default::default()
        }
    }

    /// Add a prefix to advertise
    pub fn with_prefix(mut self, prefix: AdvertisedPrefix) -> Self {
        self.prefixes.push(prefix);
        self
    }

    /// Set managed flag (M)
    pub fn with_managed(mut self, managed: bool) -> Self {
        self.managed_flag = managed;
        self
    }

    /// Set other flag (O)
    pub fn with_other(mut self, other: bool) -> Self {
        self.other_flag = other;
        self
    }

    /// Set router lifetime
    pub fn with_router_lifetime(mut self, seconds: u16) -> Self {
        self.router_lifetime = seconds;
        self
    }

    /// Set MTU
    pub fn with_mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set RA intervals
    pub fn with_intervals(mut self, min: u16, max: u16) -> Self {
        self.min_ra_interval = min;
        self.max_ra_interval = max;
        self
    }

    /// Set DNS servers
    pub fn with_dns_servers(mut self, servers: Vec<Ipv6Addr>, lifetime: u32) -> Self {
        self.dns_servers = servers;
        self.dns_lifetime = lifetime;
        self
    }
}

/// RA server instance for a single interface
#[derive(Debug)]
pub struct RaServerInterface {
    /// Configuration
    config: RaServerConfig,
    /// Interface MAC address
    mac_addr: MacAddr,
    /// Interface link-local address
    link_local: Ipv6Addr,
    /// Last RA send time
    last_ra_time: Option<Instant>,
    /// Next RA send time
    next_ra_time: Instant,
    /// Number of initial RAs sent
    initial_ra_count: u32,
}

/// Maximum initial RAs to send quickly
const MAX_INITIAL_RTR_ADVERTISEMENTS: u32 = 3;
/// Delay between initial RAs
const MAX_INITIAL_RTR_ADVERT_INTERVAL: Duration = Duration::from_secs(16);
/// Minimum delay after RS before sending RA
const MIN_DELAY_BETWEEN_RAS: Duration = Duration::from_millis(500);

impl RaServerInterface {
    /// Create a new RA server for an interface
    pub fn new(config: RaServerConfig, mac_addr: MacAddr) -> Self {
        let link_local = Self::generate_link_local(&mac_addr);

        Self {
            config,
            mac_addr,
            link_local,
            last_ra_time: None,
            next_ra_time: Instant::now(),
            initial_ra_count: 0,
        }
    }

    /// Generate link-local address from MAC
    fn generate_link_local(mac: &MacAddr) -> Ipv6Addr {
        let m = &mac.0;
        let eui64: [u8; 8] = [m[0] ^ 0x02, m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]];

        Ipv6Addr::new(
            0xfe80,
            0,
            0,
            0,
            u16::from_be_bytes([eui64[0], eui64[1]]),
            u16::from_be_bytes([eui64[2], eui64[3]]),
            u16::from_be_bytes([eui64[4], eui64[5]]),
            u16::from_be_bytes([eui64[6], eui64[7]]),
        )
    }

    /// Get interface name
    pub fn interface(&self) -> &str {
        &self.config.interface
    }

    /// Get link-local address
    pub fn link_local(&self) -> Ipv6Addr {
        self.link_local
    }

    /// Get configuration
    pub fn config(&self) -> &RaServerConfig {
        &self.config
    }

    /// Build RA packet
    fn build_ra(&self) -> Vec<u8> {
        let mut ra = RouterAdvertisement::new(
            self.config.cur_hop_limit,
            self.config.managed_flag,
            self.config.other_flag,
            self.config.router_lifetime,
            self.config.reachable_time,
            self.config.retrans_timer,
        )
        .with_source_link_addr(self.mac_addr);

        if let Some(mtu) = self.config.mtu {
            ra = ra.with_mtu(mtu);
        }

        for prefix in &self.config.prefixes {
            ra = ra.with_prefix(prefix.to_prefix_info());
        }

        if !self.config.dns_servers.is_empty() {
            ra = ra.with_rdnss(self.config.dns_servers.clone(), self.config.dns_lifetime);
        }

        ra.to_bytes()
    }

    /// Process incoming Router Solicitation
    pub fn process_rs(&mut self, rs: &RouterSolicitation, src_ip: Ipv6Addr) -> RaServerAction {
        debug!(
            interface = %self.config.interface,
            src = %src_ip,
            "Received Router Solicitation"
        );

        // Check rate limiting
        if let Some(last_ra) = self.last_ra_time {
            if last_ra.elapsed() < MIN_DELAY_BETWEEN_RAS {
                trace!(
                    interface = %self.config.interface,
                    "Rate limiting RA response"
                );
                return RaServerAction::None;
            }
        }

        // Build and send RA
        let mut packet = self.build_ra();

        // Determine destination
        let (dst_ip, dst_mac) = if src_ip.is_unspecified() {
            // DAD - send to all-nodes
            (
                Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
                MacAddr([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]),
            )
        } else {
            // Unicast reply if source link-layer address is known
            if let Some(src_mac) = rs.source_link_addr {
                (src_ip, src_mac)
            } else {
                // No SLLA, send to all-nodes
                (
                    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
                    MacAddr([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]),
                )
            }
        };

        set_checksum(&mut packet, &self.link_local, &dst_ip);

        self.last_ra_time = Some(Instant::now());

        RaServerAction::SendRa {
            interface: self.config.interface.clone(),
            packet,
            dst_ip,
            dst_mac,
        }
    }

    /// Run periodic maintenance (unsolicited RA)
    pub fn run_maintenance(&mut self) -> RaServerAction {
        let now = Instant::now();

        if now < self.next_ra_time {
            return RaServerAction::None;
        }

        // Build unsolicited RA
        let mut packet = self.build_ra();

        // Send to all-nodes multicast
        let dst_ip = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        let dst_mac = MacAddr([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);

        set_checksum(&mut packet, &self.link_local, &dst_ip);

        self.last_ra_time = Some(now);
        self.initial_ra_count += 1;

        // Calculate next RA time
        let interval = if self.initial_ra_count <= MAX_INITIAL_RTR_ADVERTISEMENTS {
            MAX_INITIAL_RTR_ADVERT_INTERVAL
        } else {
            // Random interval between min and max
            let min = self.config.min_ra_interval as u64;
            let max = self.config.max_ra_interval as u64;
            let secs = min + (now.elapsed().as_nanos() % (max - min + 1) as u128) as u64;
            Duration::from_secs(secs)
        };
        self.next_ra_time = now + interval;

        debug!(
            interface = %self.config.interface,
            next_in_secs = interval.as_secs(),
            "Sending unsolicited RA"
        );

        RaServerAction::SendRa {
            interface: self.config.interface.clone(),
            packet,
            dst_ip,
            dst_mac,
        }
    }

    /// Update configuration
    pub fn update_config(&mut self, config: RaServerConfig) {
        self.config = config;
    }
}

/// RA server managing multiple interfaces
#[derive(Debug, Default)]
pub struct RaServer {
    servers: HashMap<String, RaServerInterface>,
}

impl RaServer {
    /// Create a new RA server manager
    pub fn new() -> Self {
        Self {
            servers: HashMap::new(),
        }
    }

    /// Add an interface to the RA server
    pub fn add_interface(&mut self, config: RaServerConfig, mac: &MacAddr) -> RaServerAction {
        let interface = config.interface.clone();
        debug!(interface = %interface, "Adding interface to RA server");

        let server = RaServerInterface::new(config, *mac);
        self.servers.insert(interface, server);

        // Send initial RA immediately
        if let Some(server) = self.servers.values_mut().last() {
            return server.run_maintenance();
        }

        RaServerAction::None
    }

    /// Remove an interface from the RA server
    pub fn remove_interface(&mut self, interface: &str) -> RaServerAction {
        if let Some(mut server) = self.servers.remove(interface) {
            // Send RA with router_lifetime=0 to indicate we're no longer a router
            server.config.router_lifetime = 0;

            let mut packet = server.build_ra();
            let dst_ip = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
            let dst_mac = MacAddr([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
            set_checksum(&mut packet, &server.link_local, &dst_ip);

            return RaServerAction::SendRa {
                interface: interface.to_string(),
                packet,
                dst_ip,
                dst_mac,
            };
        }

        RaServerAction::None
    }

    /// Process RS on an interface
    pub fn process_rs(
        &mut self,
        interface: &str,
        rs: &RouterSolicitation,
        src_ip: Ipv6Addr,
    ) -> RaServerAction {
        if let Some(server) = self.servers.get_mut(interface) {
            server.process_rs(rs, src_ip)
        } else {
            RaServerAction::None
        }
    }

    /// Run maintenance on all interfaces
    pub fn run_maintenance(&mut self) -> Vec<RaServerAction> {
        let mut actions = Vec::new();
        for server in self.servers.values_mut() {
            match server.run_maintenance() {
                RaServerAction::None => {}
                action => actions.push(action),
            }
        }
        actions
    }

    /// Get server for an interface
    pub fn get_server(&self, interface: &str) -> Option<&RaServerInterface> {
        self.servers.get(interface)
    }

    /// Check if RA server is enabled on an interface
    pub fn is_enabled(&self, interface: &str) -> bool {
        self.servers.contains_key(interface)
    }

    /// Update configuration for an interface
    pub fn update_config(&mut self, config: RaServerConfig) {
        let interface = config.interface.clone();
        if let Some(server) = self.servers.get_mut(&interface) {
            server.update_config(config);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::icmpv6::Icmpv6Type;

    fn make_mac() -> MacAddr {
        MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    }

    fn make_config() -> RaServerConfig {
        RaServerConfig::new("eth0".to_string())
            .with_prefix(AdvertisedPrefix::new("2001:db8::".parse().unwrap(), 64))
            .with_router_lifetime(1800)
    }

    #[test]
    fn test_advertised_prefix_new() {
        let prefix = AdvertisedPrefix::new("2001:db8::".parse().unwrap(), 64);
        assert!(prefix.on_link);
        assert!(prefix.autonomous);
        assert_eq!(prefix.valid_lifetime, 2592000);
        assert_eq!(prefix.preferred_lifetime, 604800);
    }

    #[test]
    fn test_ra_server_config_builder() {
        let config = RaServerConfig::new("eth0".to_string())
            .with_prefix(AdvertisedPrefix::new("2001:db8::".parse().unwrap(), 64))
            .with_managed(true)
            .with_other(true)
            .with_router_lifetime(3600)
            .with_mtu(1500)
            .with_dns_servers(vec!["2001:4860:4860::8888".parse().unwrap()], 3600);

        assert_eq!(config.interface, "eth0");
        assert!(config.managed_flag);
        assert!(config.other_flag);
        assert_eq!(config.router_lifetime, 3600);
        assert_eq!(config.mtu, Some(1500));
        assert_eq!(config.dns_servers.len(), 1);
    }

    #[test]
    fn test_ra_server_interface_new() {
        let config = make_config();
        let server = RaServerInterface::new(config, make_mac());

        assert_eq!(server.interface(), "eth0");
        assert!(server.link_local().to_string().starts_with("fe80:"));
    }

    #[test]
    fn test_build_ra() {
        let config = make_config();
        let server = RaServerInterface::new(config, make_mac());

        let packet = server.build_ra();

        assert_eq!(packet[0], Icmpv6Type::RouterAdvertisement as u8);
        assert_eq!(packet[4], 64); // cur_hop_limit
    }

    #[test]
    fn test_process_rs_basic() {
        let config = make_config();
        let mut server = RaServerInterface::new(config, make_mac());

        let rs = RouterSolicitation::new(Some(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])));
        let src_ip: Ipv6Addr = "fe80::1".parse().unwrap();

        let action = server.process_rs(&rs, src_ip);

        match action {
            RaServerAction::SendRa {
                interface,
                packet,
                dst_ip,
                dst_mac,
            } => {
                assert_eq!(interface, "eth0");
                assert_eq!(packet[0], Icmpv6Type::RouterAdvertisement as u8);
                assert_eq!(dst_ip, src_ip);
                assert_eq!(dst_mac.0, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
            }
            _ => panic!("Expected SendRa action"),
        }
    }

    #[test]
    fn test_process_rs_unspecified_source() {
        let config = make_config();
        let mut server = RaServerInterface::new(config, make_mac());

        let rs = RouterSolicitation::new(None);
        let src_ip = Ipv6Addr::UNSPECIFIED;

        let action = server.process_rs(&rs, src_ip);

        match action {
            RaServerAction::SendRa {
                dst_ip, dst_mac, ..
            } => {
                // Should send to all-nodes
                assert_eq!(dst_ip, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
                assert_eq!(dst_mac.0, [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
            }
            _ => panic!("Expected SendRa action"),
        }
    }

    #[test]
    fn test_ra_server_manager() {
        let mut manager = RaServer::new();

        let config = make_config();
        let mac = make_mac();
        let action = manager.add_interface(config, &mac);

        // Should send initial RA
        assert!(matches!(action, RaServerAction::SendRa { .. }));
        assert!(manager.is_enabled("eth0"));

        let removed = manager.remove_interface("eth0");
        // Should send RA with router_lifetime=0
        match removed {
            RaServerAction::SendRa { packet, .. } => {
                // Router lifetime at bytes 6-7 should be 0
                assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 0);
            }
            _ => panic!("Expected SendRa action"),
        }
        assert!(!manager.is_enabled("eth0"));
    }

    #[test]
    fn test_ra_with_dns() {
        let config = RaServerConfig::new("eth0".to_string())
            .with_prefix(AdvertisedPrefix::new("2001:db8::".parse().unwrap(), 64))
            .with_dns_servers(vec!["2001:4860:4860::8888".parse().unwrap()], 3600);

        let server = RaServerInterface::new(config, make_mac());
        let packet = server.build_ra();

        // Verify RDNSS option is present (type 25)
        let mut offset = 16; // Skip RA header + SLLA
        let mut found_rdnss = false;
        while offset + 2 <= packet.len() {
            let opt_type = packet[offset];
            let opt_len = packet[offset + 1] as usize * 8;
            if opt_type == 25 {
                found_rdnss = true;
                break;
            }
            if opt_len == 0 {
                break;
            }
            offset += opt_len;
        }
        assert!(found_rdnss, "RDNSS option not found in RA packet");

        // Note: The packet structure may vary, so we just check it was built without error
        assert!(packet.len() > 16);
    }
}
