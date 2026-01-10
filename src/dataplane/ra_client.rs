//! Router Advertisement Client
//!
//! RA client implementation for IPv6 autoconfiguration on WAN interfaces.
//! Receives Router Advertisements from upstream routers and performs SLAAC.
//! Follows RFC 4861 (NDP) and RFC 4862 (SLAAC).

use crate::protocol::icmpv6::{
    set_checksum, PrefixInformation, RouterAdvertisement, RouterSolicitation,
};
use crate::protocol::MacAddr;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

/// RA client processing result
#[derive(Debug)]
pub enum RaClientAction {
    /// Send a Router Solicitation
    SendRs {
        /// Interface to send on
        interface: String,
        /// ICMPv6 RS payload (to be wrapped in IPv6/Ethernet)
        packet: Vec<u8>,
    },
    /// Prefix acquired via SLAAC
    PrefixAcquired {
        /// Interface name
        interface: String,
        /// Prefix information
        prefix: PrefixInformation,
        /// Generated address (via EUI-64)
        address: Ipv6Addr,
        /// Default router link-local address
        router: Ipv6Addr,
        /// DNS servers from RDNSS
        dns_servers: Vec<Ipv6Addr>,
    },
    /// Prefix expired
    PrefixExpired {
        /// Interface name
        interface: String,
        /// Expired address
        address: Ipv6Addr,
    },
    /// Default router updated
    DefaultRouterUpdate {
        /// Interface name
        interface: String,
        /// Router link-local address (None = removed)
        router: Option<Ipv6Addr>,
        /// Router lifetime
        lifetime: u16,
    },
    /// No action needed
    None,
}

/// RA client state machine states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaClientState {
    /// Initial state, sending RS
    Soliciting,
    /// RA received, addresses configured
    Configured,
    /// Waiting for periodic RA updates
    Monitoring,
}

/// Learned prefix information
#[derive(Debug, Clone)]
pub struct LearnedPrefix {
    /// Prefix address
    pub prefix: Ipv6Addr,
    /// Prefix length
    pub prefix_len: u8,
    /// On-link flag
    pub on_link: bool,
    /// Autonomous flag (SLAAC)
    pub autonomous: bool,
    /// Valid lifetime in seconds
    pub valid_lifetime: u32,
    /// Preferred lifetime in seconds
    pub preferred_lifetime: u32,
    /// When the prefix was learned
    pub acquired_at: Instant,
    /// Generated address via SLAAC (if autonomous)
    pub generated_address: Option<Ipv6Addr>,
}

impl LearnedPrefix {
    /// Check if the prefix is still valid
    pub fn is_valid(&self) -> bool {
        if self.valid_lifetime == 0xFFFFFFFF {
            return true; // Infinite
        }
        if self.valid_lifetime == 0 {
            return false;
        }
        self.acquired_at.elapsed() < Duration::from_secs(self.valid_lifetime as u64)
    }

    /// Check if the prefix is still preferred
    pub fn is_preferred(&self) -> bool {
        if self.preferred_lifetime == 0xFFFFFFFF {
            return true; // Infinite
        }
        if self.preferred_lifetime == 0 {
            return false;
        }
        self.acquired_at.elapsed() < Duration::from_secs(self.preferred_lifetime as u64)
    }
}

/// Information learned from a router
#[derive(Debug, Clone)]
pub struct LearnedRouter {
    /// Router's link-local address
    pub link_local: Ipv6Addr,
    /// Router's MAC address (from SLLA option)
    pub mac_addr: Option<MacAddr>,
    /// Router lifetime (seconds)
    pub lifetime: u16,
    /// When we last received RA from this router
    pub last_seen: Instant,
    /// Learned prefixes from this router
    pub prefixes: Vec<LearnedPrefix>,
    /// DNS servers from RDNSS option
    pub dns_servers: Vec<Ipv6Addr>,
    /// DNS lifetime
    pub dns_lifetime: u32,
    /// Cur hop limit advertised
    pub cur_hop_limit: u8,
    /// M flag (managed address configuration)
    pub managed_flag: bool,
    /// O flag (other configuration)
    pub other_flag: bool,
}

impl LearnedRouter {
    /// Check if this router is still valid as default router
    pub fn is_valid_default_router(&self) -> bool {
        if self.lifetime == 0 {
            return false;
        }
        self.last_seen.elapsed() < Duration::from_secs(self.lifetime as u64)
    }
}

/// RA client instance for a single interface
#[derive(Debug)]
pub struct RaClientInterface {
    /// Interface name
    interface: String,
    /// Interface MAC address
    mac_addr: MacAddr,
    /// Current state
    state: RaClientState,
    /// RS retry count
    rs_count: u32,
    /// Last RS send time
    last_rs_time: Option<Instant>,
    /// Learned routers
    routers: HashMap<Ipv6Addr, LearnedRouter>,
    /// Current default router
    default_router: Option<Ipv6Addr>,
}

/// Maximum RS retransmissions (RFC 4861)
const MAX_RTR_SOLICITATIONS: u32 = 3;
/// RS retransmission interval (RFC 4861)
const RTR_SOLICITATION_INTERVAL: Duration = Duration::from_secs(4);

impl RaClientInterface {
    /// Create a new RA client for an interface
    pub fn new(interface: String, mac_addr: MacAddr) -> Self {
        Self {
            interface,
            mac_addr,
            state: RaClientState::Soliciting,
            rs_count: 0,
            last_rs_time: None,
            routers: HashMap::new(),
            default_router: None,
        }
    }

    /// Get interface name
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Get current state
    pub fn state(&self) -> RaClientState {
        self.state
    }

    /// Get default router
    pub fn default_router(&self) -> Option<Ipv6Addr> {
        self.default_router
    }

    /// Get all learned routers
    pub fn routers(&self) -> &HashMap<Ipv6Addr, LearnedRouter> {
        &self.routers
    }

    /// Start the RA client
    pub fn start(&mut self) -> Vec<RaClientAction> {
        debug!(interface = %self.interface, "Starting RA client");
        self.state = RaClientState::Soliciting;
        self.rs_count = 0;
        self.last_rs_time = None;
        self.send_rs()
    }

    /// Generate link-local address from MAC (EUI-64)
    pub fn generate_link_local(&self) -> Ipv6Addr {
        let mac = &self.mac_addr.0;
        let eui64: [u8; 8] = [
            mac[0] ^ 0x02, // Flip U/L bit
            mac[1],
            mac[2],
            0xff,
            0xfe,
            mac[3],
            mac[4],
            mac[5],
        ];

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

    /// Generate global address from prefix using EUI-64
    #[allow(dead_code)]
    pub fn generate_eui64_address(&self, prefix: &Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
        Self::generate_eui64_address_from_mac(prefix, prefix_len, &self.mac_addr)
    }

    /// Generate global address from prefix using EUI-64 (static version)
    fn generate_eui64_address_from_mac(
        prefix: &Ipv6Addr,
        prefix_len: u8,
        mac: &MacAddr,
    ) -> Ipv6Addr {
        if prefix_len != 64 {
            // EUI-64 only works with /64 prefixes
            warn!(
                prefix_len = prefix_len,
                "SLAAC requires /64 prefix for EUI-64"
            );
        }

        let m = &mac.0;
        let eui64: [u8; 8] = [m[0] ^ 0x02, m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]];

        let prefix_octets = prefix.octets();
        let mut addr_octets = [0u8; 16];
        addr_octets[..8].copy_from_slice(&prefix_octets[..8]);
        addr_octets[8..].copy_from_slice(&eui64);

        Ipv6Addr::from(addr_octets)
    }

    /// Send Router Solicitation
    fn send_rs(&mut self) -> Vec<RaClientAction> {
        let link_local = self.generate_link_local();

        let rs = RouterSolicitation::new(Some(self.mac_addr));
        let mut packet = rs.to_bytes();

        // All-routers multicast: ff02::2
        let dst = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
        set_checksum(&mut packet, &link_local, &dst);

        self.rs_count += 1;
        self.last_rs_time = Some(Instant::now());

        debug!(
            interface = %self.interface,
            rs_count = self.rs_count,
            "Sending Router Solicitation"
        );

        vec![RaClientAction::SendRs {
            interface: self.interface.clone(),
            packet,
        }]
    }

    /// Process received Router Advertisement
    pub fn process_ra(
        &mut self,
        ra: &RouterAdvertisement,
        src_ip: Ipv6Addr,
    ) -> Vec<RaClientAction> {
        debug!(
            interface = %self.interface,
            router = %src_ip,
            lifetime = ra.router_lifetime,
            prefixes = ra.prefixes.len(),
            "Received Router Advertisement"
        );

        let mut actions = Vec::new();
        let now = Instant::now();

        // Update or create router entry
        let router = self.routers.entry(src_ip).or_insert_with(|| LearnedRouter {
            link_local: src_ip,
            mac_addr: None,
            lifetime: 0,
            last_seen: now,
            prefixes: Vec::new(),
            dns_servers: Vec::new(),
            dns_lifetime: 0,
            cur_hop_limit: 0,
            managed_flag: false,
            other_flag: false,
        });

        // Update router info
        router.last_seen = now;
        router.lifetime = ra.router_lifetime;
        router.mac_addr = ra.source_link_addr;
        router.cur_hop_limit = ra.cur_hop_limit;
        router.managed_flag = ra.managed_flag;
        router.other_flag = ra.other_flag;

        if !ra.rdnss.is_empty() {
            router.dns_servers = ra.rdnss.clone();
            router.dns_lifetime = ra.rdnss_lifetime;
        }

        // Process prefixes
        for prefix_info in &ra.prefixes {
            // Find or create prefix entry
            let existing_prefix = router.prefixes.iter_mut().find(|p| {
                p.prefix == prefix_info.prefix && p.prefix_len == prefix_info.prefix_length
            });

            if let Some(existing) = existing_prefix {
                // Update existing prefix
                existing.valid_lifetime = prefix_info.valid_lifetime;
                existing.preferred_lifetime = prefix_info.preferred_lifetime;
                existing.acquired_at = now;
                trace!(
                    prefix = %prefix_info.prefix,
                    prefix_len = prefix_info.prefix_length,
                    "Updated existing prefix"
                );
            } else if prefix_info.autonomous_flag && prefix_info.prefix_length == 64 {
                // New prefix with A flag - generate address via SLAAC
                let addr = Self::generate_eui64_address_from_mac(
                    &prefix_info.prefix,
                    prefix_info.prefix_length,
                    &self.mac_addr,
                );

                let learned = LearnedPrefix {
                    prefix: prefix_info.prefix,
                    prefix_len: prefix_info.prefix_length,
                    on_link: prefix_info.on_link_flag,
                    autonomous: prefix_info.autonomous_flag,
                    valid_lifetime: prefix_info.valid_lifetime,
                    preferred_lifetime: prefix_info.preferred_lifetime,
                    acquired_at: now,
                    generated_address: Some(addr),
                };
                router.prefixes.push(learned);

                debug!(
                    interface = %self.interface,
                    prefix = %prefix_info.prefix,
                    generated_addr = %addr,
                    "SLAAC: Generated address from prefix"
                );

                actions.push(RaClientAction::PrefixAcquired {
                    interface: self.interface.clone(),
                    prefix: prefix_info.clone(),
                    address: addr,
                    router: src_ip,
                    dns_servers: router.dns_servers.clone(),
                });
            } else {
                // New prefix without A flag or non-/64
                let learned = LearnedPrefix {
                    prefix: prefix_info.prefix,
                    prefix_len: prefix_info.prefix_length,
                    on_link: prefix_info.on_link_flag,
                    autonomous: prefix_info.autonomous_flag,
                    valid_lifetime: prefix_info.valid_lifetime,
                    preferred_lifetime: prefix_info.preferred_lifetime,
                    acquired_at: now,
                    generated_address: None,
                };
                router.prefixes.push(learned);
            }
        }

        // Update default router
        let old_default = self.default_router;
        if ra.router_lifetime > 0 {
            // This router can be default
            if self.default_router.is_none() {
                self.default_router = Some(src_ip);
                actions.push(RaClientAction::DefaultRouterUpdate {
                    interface: self.interface.clone(),
                    router: Some(src_ip),
                    lifetime: ra.router_lifetime,
                });
            }
        } else if self.default_router == Some(src_ip) {
            // Router lifetime is 0, remove as default
            self.default_router = None;
            actions.push(RaClientAction::DefaultRouterUpdate {
                interface: self.interface.clone(),
                router: None,
                lifetime: 0,
            });

            // Try to find another default router
            for (router_ip, router_info) in &self.routers {
                if router_info.is_valid_default_router() {
                    self.default_router = Some(*router_ip);
                    actions.push(RaClientAction::DefaultRouterUpdate {
                        interface: self.interface.clone(),
                        router: Some(*router_ip),
                        lifetime: router_info.lifetime,
                    });
                    break;
                }
            }
        }

        // Update state
        if self.state == RaClientState::Soliciting {
            self.state = RaClientState::Configured;
            debug!(
                interface = %self.interface,
                "RA client: Soliciting -> Configured"
            );
        }

        // If we got an RA but old_default changed, log it
        if old_default != self.default_router {
            debug!(
                interface = %self.interface,
                old_default = ?old_default,
                new_default = ?self.default_router,
                "Default router changed"
            );
        }

        actions
    }

    /// Run periodic maintenance
    pub fn run_maintenance(&mut self) -> Vec<RaClientAction> {
        let mut actions = Vec::new();
        let _now = Instant::now();

        match self.state {
            RaClientState::Soliciting => {
                // Check if we should retransmit RS
                if let Some(last_rs) = self.last_rs_time {
                    if last_rs.elapsed() >= RTR_SOLICITATION_INTERVAL {
                        if self.rs_count < MAX_RTR_SOLICITATIONS {
                            actions.extend(self.send_rs());
                        } else {
                            // Max retries reached, keep waiting for unsolicited RA
                            trace!(
                                interface = %self.interface,
                                "Max RS retries reached, waiting for unsolicited RA"
                            );
                        }
                    }
                }
            }
            RaClientState::Configured | RaClientState::Monitoring => {
                // Check for expired prefixes
                for router in self.routers.values_mut() {
                    router.prefixes.retain(|prefix| {
                        if !prefix.is_valid() {
                            if let Some(addr) = prefix.generated_address {
                                debug!(
                                    interface = %self.interface,
                                    address = %addr,
                                    "Prefix expired"
                                );
                                actions.push(RaClientAction::PrefixExpired {
                                    interface: self.interface.clone(),
                                    address: addr,
                                });
                            }
                            false
                        } else {
                            true
                        }
                    });
                }

                // Check for expired default router
                if let Some(default_ip) = self.default_router {
                    if let Some(router) = self.routers.get(&default_ip) {
                        if !router.is_valid_default_router() {
                            debug!(
                                interface = %self.interface,
                                router = %default_ip,
                                "Default router expired"
                            );
                            self.default_router = None;
                            actions.push(RaClientAction::DefaultRouterUpdate {
                                interface: self.interface.clone(),
                                router: None,
                                lifetime: 0,
                            });

                            // Try to find another default router
                            for (router_ip, router_info) in &self.routers {
                                if router_info.is_valid_default_router() {
                                    self.default_router = Some(*router_ip);
                                    actions.push(RaClientAction::DefaultRouterUpdate {
                                        interface: self.interface.clone(),
                                        router: Some(*router_ip),
                                        lifetime: router_info.lifetime,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }

                // Remove stale routers (no valid prefixes and not default router)
                self.routers.retain(|ip, router| {
                    let is_default = self.default_router == Some(*ip);
                    let has_valid_prefixes = router.prefixes.iter().any(|p| p.is_valid());
                    let is_valid_default = router.is_valid_default_router();

                    is_default || has_valid_prefixes || is_valid_default
                });
            }
        }

        actions
    }

    /// Get DNS servers from all routers
    pub fn get_dns_servers(&self) -> Vec<Ipv6Addr> {
        let mut servers = Vec::new();
        for router in self.routers.values() {
            for dns in &router.dns_servers {
                if !servers.contains(dns) {
                    servers.push(*dns);
                }
            }
        }
        servers
    }

    /// Get all configured addresses
    pub fn get_addresses(&self) -> Vec<Ipv6Addr> {
        let mut addresses = Vec::new();
        for router in self.routers.values() {
            for prefix in &router.prefixes {
                if let Some(addr) = prefix.generated_address {
                    if prefix.is_valid() && !addresses.contains(&addr) {
                        addresses.push(addr);
                    }
                }
            }
        }
        addresses
    }
}

/// RA client managing multiple interfaces
#[derive(Debug, Default)]
pub struct RaClient {
    clients: HashMap<String, RaClientInterface>,
}

impl RaClient {
    /// Create a new RA client manager
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    /// Add an interface to the RA client
    pub fn add_interface(&mut self, interface: String, mac: &MacAddr) -> Vec<RaClientAction> {
        debug!(interface = %interface, "Adding interface to RA client");
        let mut client = RaClientInterface::new(interface.clone(), *mac);
        let actions = client.start();
        self.clients.insert(interface, client);
        actions
    }

    /// Remove an interface from the RA client
    pub fn remove_interface(&mut self, interface: &str) -> Vec<RaClientAction> {
        let mut actions = Vec::new();

        if let Some(client) = self.clients.remove(interface) {
            // Generate PrefixExpired actions for all addresses
            for router in client.routers.values() {
                for prefix in &router.prefixes {
                    if let Some(addr) = prefix.generated_address {
                        actions.push(RaClientAction::PrefixExpired {
                            interface: interface.to_string(),
                            address: addr,
                        });
                    }
                }
            }

            // Remove default router
            if client.default_router.is_some() {
                actions.push(RaClientAction::DefaultRouterUpdate {
                    interface: interface.to_string(),
                    router: None,
                    lifetime: 0,
                });
            }
        }

        actions
    }

    /// Process received RA on an interface
    pub fn process_ra(
        &mut self,
        interface: &str,
        ra: &RouterAdvertisement,
        src_ip: Ipv6Addr,
    ) -> Vec<RaClientAction> {
        if let Some(client) = self.clients.get_mut(interface) {
            client.process_ra(ra, src_ip)
        } else {
            Vec::new()
        }
    }

    /// Run maintenance on all interfaces
    pub fn run_maintenance(&mut self) -> Vec<RaClientAction> {
        let mut actions = Vec::new();
        for client in self.clients.values_mut() {
            actions.extend(client.run_maintenance());
        }
        actions
    }

    /// Get client for an interface
    pub fn get_client(&self, interface: &str) -> Option<&RaClientInterface> {
        self.clients.get(interface)
    }

    /// Check if RA client is enabled on an interface
    pub fn is_enabled(&self, interface: &str) -> bool {
        self.clients.contains_key(interface)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::icmpv6::Icmpv6Type;

    fn make_mac() -> MacAddr {
        MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
    }

    #[test]
    fn test_ra_client_new() {
        let client = RaClientInterface::new("eth0".to_string(), make_mac());
        assert_eq!(client.interface(), "eth0");
        assert_eq!(client.state(), RaClientState::Soliciting);
        assert!(client.default_router().is_none());
    }

    #[test]
    fn test_generate_link_local() {
        let client = RaClientInterface::new("eth0".to_string(), make_mac());
        let ll = client.generate_link_local();

        // MAC: 00:11:22:33:44:55
        // EUI-64: 02:11:22:ff:fe:33:44:55 (flip U/L bit, insert ff:fe)
        assert!(ll.to_string().starts_with("fe80:"));
        assert_eq!(ll.segments()[4], 0x0211);
        assert_eq!(ll.segments()[5], 0x22ff);
        assert_eq!(ll.segments()[6], 0xfe33);
        assert_eq!(ll.segments()[7], 0x4455);
    }

    #[test]
    fn test_generate_eui64_address() {
        let client = RaClientInterface::new("eth0".to_string(), make_mac());
        let prefix: Ipv6Addr = "2001:db8:1::".parse().unwrap();
        let addr = client.generate_eui64_address(&prefix, 64);

        assert_eq!(addr.segments()[0], 0x2001);
        assert_eq!(addr.segments()[1], 0x0db8);
        assert_eq!(addr.segments()[2], 0x0001);
        assert_eq!(addr.segments()[3], 0x0000);
        assert_eq!(addr.segments()[4], 0x0211);
        assert_eq!(addr.segments()[5], 0x22ff);
        assert_eq!(addr.segments()[6], 0xfe33);
        assert_eq!(addr.segments()[7], 0x4455);
    }

    #[test]
    fn test_start_sends_rs() {
        let mut client = RaClientInterface::new("eth0".to_string(), make_mac());
        let actions = client.start();

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            RaClientAction::SendRs { interface, packet } => {
                assert_eq!(interface, "eth0");
                assert_eq!(packet[0], Icmpv6Type::RouterSolicitation as u8);
            }
            _ => panic!("Expected SendRs action"),
        }
        assert_eq!(client.rs_count, 1);
    }

    #[test]
    fn test_process_ra_basic() {
        let mut client = RaClientInterface::new("eth0".to_string(), make_mac());
        client.start();

        let prefix = PrefixInformation::new(
            "2001:db8::".parse().unwrap(),
            64,
            true,
            true,
            2592000,
            604800,
        );

        let ra = RouterAdvertisement::new(64, false, false, 1800, 0, 0)
            .with_source_link_addr(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
            .with_prefix(prefix);

        let router_ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let actions = client.process_ra(&ra, router_ip);

        // Should have PrefixAcquired and DefaultRouterUpdate
        assert!(!actions.is_empty());
        assert_eq!(client.state(), RaClientState::Configured);
        assert_eq!(client.default_router(), Some(router_ip));
    }

    #[test]
    fn test_process_ra_with_rdnss() {
        let mut client = RaClientInterface::new("eth0".to_string(), make_mac());
        client.start();

        let dns: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
        let ra = RouterAdvertisement::new(64, false, false, 1800, 0, 0).with_rdnss(vec![dns], 3600);

        let router_ip: Ipv6Addr = "fe80::1".parse().unwrap();
        client.process_ra(&ra, router_ip);

        let servers = client.get_dns_servers();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0], dns);
    }

    #[test]
    fn test_learned_prefix_validity() {
        let prefix = LearnedPrefix {
            prefix: "2001:db8::".parse().unwrap(),
            prefix_len: 64,
            on_link: true,
            autonomous: true,
            valid_lifetime: 100,
            preferred_lifetime: 50,
            acquired_at: Instant::now(),
            generated_address: Some("2001:db8::1".parse().unwrap()),
        };

        assert!(prefix.is_valid());
        assert!(prefix.is_preferred());
    }

    #[test]
    fn test_learned_prefix_infinite() {
        let prefix = LearnedPrefix {
            prefix: "2001:db8::".parse().unwrap(),
            prefix_len: 64,
            on_link: true,
            autonomous: true,
            valid_lifetime: 0xFFFFFFFF,
            preferred_lifetime: 0xFFFFFFFF,
            acquired_at: Instant::now(),
            generated_address: None,
        };

        assert!(prefix.is_valid());
        assert!(prefix.is_preferred());
    }

    #[test]
    fn test_learned_router_validity() {
        let router = LearnedRouter {
            link_local: "fe80::1".parse().unwrap(),
            mac_addr: None,
            lifetime: 1800,
            last_seen: Instant::now(),
            prefixes: Vec::new(),
            dns_servers: Vec::new(),
            dns_lifetime: 0,
            cur_hop_limit: 64,
            managed_flag: false,
            other_flag: false,
        };

        assert!(router.is_valid_default_router());

        let expired_router = LearnedRouter {
            lifetime: 0,
            ..router
        };
        assert!(!expired_router.is_valid_default_router());
    }

    #[test]
    fn test_ra_client_manager() {
        let mut manager = RaClient::new();

        let mac = make_mac();
        let actions = manager.add_interface("eth0".to_string(), &mac);
        assert_eq!(actions.len(), 1);
        assert!(manager.is_enabled("eth0"));

        let _removed = manager.remove_interface("eth0");
        assert!(!manager.is_enabled("eth0"));
    }

    #[test]
    fn test_router_lifetime_zero_removes_default() {
        let mut client = RaClientInterface::new("eth0".to_string(), make_mac());
        client.start();

        let router_ip: Ipv6Addr = "fe80::1".parse().unwrap();

        // First RA with positive lifetime
        let ra1 = RouterAdvertisement::new(64, false, false, 1800, 0, 0);
        client.process_ra(&ra1, router_ip);
        assert_eq!(client.default_router(), Some(router_ip));

        // Second RA with zero lifetime
        let ra2 = RouterAdvertisement::new(64, false, false, 0, 0, 0);
        let actions = client.process_ra(&ra2, router_ip);

        // Should have DefaultRouterUpdate with None
        let has_removal = actions
            .iter()
            .any(|a| matches!(a, RaClientAction::DefaultRouterUpdate { router: None, .. }));
        assert!(has_removal);
        assert!(client.default_router().is_none());
    }
}
