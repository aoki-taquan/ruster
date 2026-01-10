//! Routing table
//!
//! Implements static routing with longest prefix match (LPM).
//! Supports connected routes (auto-generated) and static routes (from config).
//! Supports policy-based routing (PBR) with multiple routing tables.

use crate::config::{InterfaceConfig, RoutingConfig, StaticRoute};
use crate::dataplane::pbr::{PacketKey, PolicyResult, PolicyRouter};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Route entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Destination network
    pub destination: Ipv4Addr,
    /// Network prefix length
    pub prefix_len: u8,
    /// Next hop (None for directly connected)
    pub next_hop: Option<Ipv4Addr>,
    /// Outgoing interface name
    pub interface: String,
    /// Route metric
    pub metric: u32,
    /// Route source
    pub source: RouteSource,
}

/// Source of a route
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSource {
    /// Directly connected network
    Connected,
    /// Static route from config
    Static,
    /// Learned via DHCP
    Dhcp,
    /// Learned via routing protocol (future)
    Protocol,
}

/// Routing table using longest prefix match
#[derive(Debug, Default)]
pub struct RoutingTable {
    routes: Vec<Route>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    /// Add a route
    pub fn add(&mut self, route: Route) {
        // Remove existing route with same destination/prefix
        self.routes
            .retain(|r| r.destination != route.destination || r.prefix_len != route.prefix_len);

        self.routes.push(route);

        // Sort by prefix length (longest first) for LPM
        self.routes.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
    }

    /// Remove a route
    pub fn remove(&mut self, destination: Ipv4Addr, prefix_len: u8) {
        self.routes
            .retain(|r| r.destination != destination || r.prefix_len != prefix_len);
    }

    /// Lookup route using longest prefix match
    pub fn lookup(&self, addr: Ipv4Addr) -> Option<&Route> {
        let addr_bits = u32::from(addr);

        for route in &self.routes {
            let dest_bits = u32::from(route.destination);
            let mask = if route.prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - route.prefix_len)
            };

            if (addr_bits & mask) == (dest_bits & mask) {
                return Some(route);
            }
        }

        None
    }

    /// Get all routes
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Remove all routes from a specific source
    pub fn remove_by_source(&mut self, source: RouteSource) {
        self.routes.retain(|r| r.source != source);
    }

    /// Load static routes from config
    pub fn load_static_routes(&mut self, config: &RoutingConfig) {
        for static_route in &config.static_routes {
            if let Some(route) = parse_static_route(static_route) {
                self.add(route);
            }
        }
    }

    /// Generate connected routes from interface configurations
    ///
    /// For each interface with a static IP address, creates a connected route
    /// for the directly attached network.
    pub fn add_connected_routes(&mut self, interfaces: &HashMap<String, InterfaceConfig>) {
        for (name, iface) in interfaces {
            if let Some(ref addr_str) = iface.address {
                if let Some(route) = parse_connected_route(name, addr_str) {
                    self.add(route);
                }
            }
        }
    }
}

/// Parse a static route from config
fn parse_static_route(config: &StaticRoute) -> Option<Route> {
    let (destination, prefix_len) = parse_cidr(&config.destination)?;
    let gateway: Ipv4Addr = config.gateway.parse().ok()?;

    // For static routes, interface can be determined by gateway lookup
    // or specified explicitly in config
    let interface = config.interface.clone().unwrap_or_default();

    Some(Route {
        destination,
        prefix_len,
        next_hop: Some(gateway),
        interface,
        metric: 100, // Default metric for static routes
        source: RouteSource::Static,
    })
}

/// Parse a connected route from interface address
fn parse_connected_route(interface_name: &str, addr_str: &str) -> Option<Route> {
    let (ip, prefix_len) = parse_cidr(addr_str)?;

    // Calculate network address from IP and prefix
    let network = network_address(ip, prefix_len);

    Some(Route {
        destination: network,
        prefix_len,
        next_hop: None, // Connected routes have no next-hop
        interface: interface_name.to_string(),
        metric: 0, // Connected routes have lowest metric
        source: RouteSource::Connected,
    })
}

/// Parse CIDR notation (e.g., "192.168.1.0/24" or "192.168.1.1/24")
fn parse_cidr(cidr: &str) -> Option<(Ipv4Addr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let ip: Ipv4Addr = parts[0].parse().ok()?;
    let prefix_len: u8 = parts[1].parse().ok()?;

    if prefix_len > 32 {
        return None;
    }

    Some((ip, prefix_len))
}

/// Calculate network address from IP and prefix length
pub fn network_address(ip: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let ip_bits = u32::from(ip);
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    Ipv4Addr::from(ip_bits & mask)
}

// ============================================================================
// Routing System with Policy-Based Routing
// ============================================================================

/// Result of a routing lookup
#[derive(Debug, Clone)]
pub enum LookupResult {
    /// Route found
    Route {
        next_hop: Option<Ipv4Addr>,
        interface: String,
    },
    /// Drop the packet
    Drop,
    /// No route found
    NoRoute,
}

/// Routing system with policy-based routing support
#[derive(Debug)]
pub struct RoutingSystem {
    /// Main routing table (table 0 / default)
    main_table: RoutingTable,
    /// Additional named tables
    tables: HashMap<u32, RoutingTable>,
    /// Policy router
    policy: PolicyRouter,
}

impl Default for RoutingSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingSystem {
    pub fn new() -> Self {
        Self {
            main_table: RoutingTable::new(),
            tables: HashMap::new(),
            policy: PolicyRouter::new(),
        }
    }

    /// Get reference to the main routing table
    pub fn main_table(&self) -> &RoutingTable {
        &self.main_table
    }

    /// Get mutable reference to the main routing table
    pub fn main_table_mut(&mut self) -> &mut RoutingTable {
        &mut self.main_table
    }

    /// Get reference to the policy router
    pub fn policy(&self) -> &PolicyRouter {
        &self.policy
    }

    /// Get mutable reference to the policy router
    pub fn policy_mut(&mut self) -> &mut PolicyRouter {
        &mut self.policy
    }

    /// Add a routing table with the given ID
    pub fn add_table(&mut self, table_id: u32, table: RoutingTable) {
        self.tables.insert(table_id, table);
    }

    /// Get a routing table by ID (None for main table)
    pub fn get_table(&self, table_id: u32) -> Option<&RoutingTable> {
        if table_id == 0 {
            Some(&self.main_table)
        } else {
            self.tables.get(&table_id)
        }
    }

    /// Get a mutable routing table by ID
    pub fn get_table_mut(&mut self, table_id: u32) -> Option<&mut RoutingTable> {
        if table_id == 0 {
            Some(&mut self.main_table)
        } else {
            self.tables.get_mut(&table_id)
        }
    }

    /// Lookup with policy evaluation
    ///
    /// First evaluates policy rules, then falls back to main routing table.
    pub fn lookup_with_policy(&self, key: &PacketKey) -> LookupResult {
        // 1. Evaluate policy rules first
        match self.policy.evaluate(key) {
            PolicyResult::Route {
                next_hop,
                interface,
            } => {
                // Policy specifies exact route
                LookupResult::Route {
                    next_hop,
                    interface: interface.unwrap_or_default(),
                }
            }
            PolicyResult::TableLookup { table_id } => {
                // Use alternate table
                let table = self.tables.get(&table_id).unwrap_or(&self.main_table);
                self.table_lookup(table, key.dst_ip)
            }
            PolicyResult::Drop => LookupResult::Drop,
            PolicyResult::UseDefault => {
                // Fall through to main table
                self.table_lookup(&self.main_table, key.dst_ip)
            }
        }
    }

    /// Simple lookup using only destination IP (no policy)
    pub fn lookup(&self, dst_ip: Ipv4Addr) -> LookupResult {
        self.table_lookup(&self.main_table, dst_ip)
    }

    /// Lookup in a specific table
    fn table_lookup(&self, table: &RoutingTable, dst: Ipv4Addr) -> LookupResult {
        match table.lookup(dst) {
            Some(route) => LookupResult::Route {
                next_hop: route.next_hop,
                interface: route.interface.clone(),
            },
            None => LookupResult::NoRoute,
        }
    }

    /// Load static routes into main table
    pub fn load_static_routes(&mut self, config: &RoutingConfig) {
        self.main_table.load_static_routes(config);
    }

    /// Add connected routes to main table
    pub fn add_connected_routes(&mut self, interfaces: &HashMap<String, InterfaceConfig>) {
        self.main_table.add_connected_routes(interfaces);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Addressing, InterfaceConfig, InterfaceRole};

    #[test]
    fn test_longest_prefix_match() {
        let mut table = RoutingTable::new();

        // Default route
        table.add(Route {
            destination: Ipv4Addr::new(0, 0, 0, 0),
            prefix_len: 0,
            next_hop: Some(Ipv4Addr::new(192, 168, 1, 1)),
            interface: "eth0".to_string(),
            metric: 100,
            source: RouteSource::Static,
        });

        // More specific route
        table.add(Route {
            destination: Ipv4Addr::new(10, 0, 0, 0),
            prefix_len: 8,
            next_hop: Some(Ipv4Addr::new(192, 168, 1, 2)),
            interface: "eth1".to_string(),
            metric: 10,
            source: RouteSource::Static,
        });

        // Should match 10.0.0.0/8
        let route = table.lookup(Ipv4Addr::new(10, 1, 2, 3));
        assert!(route.is_some());
        assert_eq!(route.unwrap().prefix_len, 8);

        // Should match default route
        let route = table.lookup(Ipv4Addr::new(8, 8, 8, 8));
        assert!(route.is_some());
        assert_eq!(route.unwrap().prefix_len, 0);
    }

    #[test]
    fn test_parse_cidr() {
        // Valid CIDR
        let (ip, prefix) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix, 24);

        // Valid CIDR with host address
        let (ip, prefix) = parse_cidr("10.0.0.1/8").unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(prefix, 8);

        // Default route
        let (ip, prefix) = parse_cidr("0.0.0.0/0").unwrap();
        assert_eq!(ip, Ipv4Addr::UNSPECIFIED);
        assert_eq!(prefix, 0);

        // Host route
        let (ip, prefix) = parse_cidr("192.168.1.1/32").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(prefix, 32);

        // Invalid: no prefix
        assert!(parse_cidr("192.168.1.0").is_none());

        // Invalid: bad IP
        assert!(parse_cidr("999.168.1.0/24").is_none());

        // Invalid: prefix too large
        assert!(parse_cidr("192.168.1.0/33").is_none());
    }

    #[test]
    fn test_network_address() {
        // /24 network
        assert_eq!(
            network_address(Ipv4Addr::new(192, 168, 1, 100), 24),
            Ipv4Addr::new(192, 168, 1, 0)
        );

        // /16 network
        assert_eq!(
            network_address(Ipv4Addr::new(172, 16, 50, 100), 16),
            Ipv4Addr::new(172, 16, 0, 0)
        );

        // /8 network
        assert_eq!(
            network_address(Ipv4Addr::new(10, 1, 2, 3), 8),
            Ipv4Addr::new(10, 0, 0, 0)
        );

        // /32 host route
        assert_eq!(
            network_address(Ipv4Addr::new(192, 168, 1, 1), 32),
            Ipv4Addr::new(192, 168, 1, 1)
        );

        // /0 default
        assert_eq!(
            network_address(Ipv4Addr::new(8, 8, 8, 8), 0),
            Ipv4Addr::UNSPECIFIED
        );

        // /30 point-to-point
        assert_eq!(
            network_address(Ipv4Addr::new(192, 168, 1, 5), 30),
            Ipv4Addr::new(192, 168, 1, 4)
        );
    }

    #[test]
    fn test_parse_static_route() {
        let config = StaticRoute {
            destination: "0.0.0.0/0".to_string(),
            gateway: "192.168.1.1".to_string(),
            interface: Some("eth0".to_string()),
        };

        let route = parse_static_route(&config).unwrap();
        assert_eq!(route.destination, Ipv4Addr::UNSPECIFIED);
        assert_eq!(route.prefix_len, 0);
        assert_eq!(route.next_hop, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(route.interface, "eth0");
        assert_eq!(route.source, RouteSource::Static);
    }

    #[test]
    fn test_parse_static_route_no_interface() {
        let config = StaticRoute {
            destination: "10.0.0.0/8".to_string(),
            gateway: "192.168.1.254".to_string(),
            interface: None,
        };

        let route = parse_static_route(&config).unwrap();
        assert_eq!(route.destination, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(route.prefix_len, 8);
        assert_eq!(route.next_hop, Some(Ipv4Addr::new(192, 168, 1, 254)));
        assert!(route.interface.is_empty());
    }

    #[test]
    fn test_parse_connected_route() {
        let route = parse_connected_route("eth0", "192.168.1.1/24").unwrap();

        assert_eq!(route.destination, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(route.prefix_len, 24);
        assert_eq!(route.next_hop, None);
        assert_eq!(route.interface, "eth0");
        assert_eq!(route.metric, 0);
        assert_eq!(route.source, RouteSource::Connected);
    }

    #[test]
    fn test_add_connected_routes() {
        let mut table = RoutingTable::new();
        let mut interfaces = HashMap::new();

        interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Lan,
                addressing: Addressing::Static,
                address: Some("192.168.1.1/24".to_string()),
                mtu: None,
                vlan_mode: None,
                vlan_config: None,
            },
        );
        interfaces.insert(
            "eth1".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Wan,
                addressing: Addressing::Static,
                address: Some("10.0.0.1/8".to_string()),
                mtu: None,
                vlan_mode: None,
                vlan_config: None,
            },
        );

        table.add_connected_routes(&interfaces);

        assert_eq!(table.len(), 2);

        // Lookup should work for both networks
        let route = table.lookup(Ipv4Addr::new(192, 168, 1, 100));
        assert!(route.is_some());
        assert_eq!(route.unwrap().interface, "eth0");

        let route = table.lookup(Ipv4Addr::new(10, 1, 2, 3));
        assert!(route.is_some());
        assert_eq!(route.unwrap().interface, "eth1");
    }

    #[test]
    fn test_load_static_routes() {
        let mut table = RoutingTable::new();
        let config = RoutingConfig {
            static_routes: vec![
                StaticRoute {
                    destination: "0.0.0.0/0".to_string(),
                    gateway: "192.168.1.1".to_string(),
                    interface: Some("eth0".to_string()),
                },
                StaticRoute {
                    destination: "172.16.0.0/12".to_string(),
                    gateway: "192.168.1.254".to_string(),
                    interface: None,
                },
            ],
            policy: Vec::new(),
            tables: Vec::new(),
        };

        table.load_static_routes(&config);

        assert_eq!(table.len(), 2);

        // Default route
        let route = table.lookup(Ipv4Addr::new(8, 8, 8, 8));
        assert!(route.is_some());
        assert_eq!(route.unwrap().prefix_len, 0);

        // 172.16.0.0/12 route
        let route = table.lookup(Ipv4Addr::new(172, 20, 1, 1));
        assert!(route.is_some());
        assert_eq!(route.unwrap().prefix_len, 12);
    }

    #[test]
    fn test_remove_by_source() {
        let mut table = RoutingTable::new();

        table.add(Route {
            destination: Ipv4Addr::new(192, 168, 1, 0),
            prefix_len: 24,
            next_hop: None,
            interface: "eth0".to_string(),
            metric: 0,
            source: RouteSource::Connected,
        });

        table.add(Route {
            destination: Ipv4Addr::new(0, 0, 0, 0),
            prefix_len: 0,
            next_hop: Some(Ipv4Addr::new(192, 168, 1, 1)),
            interface: "eth0".to_string(),
            metric: 100,
            source: RouteSource::Static,
        });

        assert_eq!(table.len(), 2);

        // Remove static routes
        table.remove_by_source(RouteSource::Static);
        assert_eq!(table.len(), 1);

        // Only connected route should remain
        let route = table.lookup(Ipv4Addr::new(192, 168, 1, 100));
        assert!(route.is_some());
        assert_eq!(route.unwrap().source, RouteSource::Connected);

        // No default route anymore
        let route = table.lookup(Ipv4Addr::new(8, 8, 8, 8));
        assert!(route.is_none());
    }

    #[test]
    fn test_connected_route_preferred_over_static() {
        let mut table = RoutingTable::new();

        // Add static route for a network
        table.add(Route {
            destination: Ipv4Addr::new(192, 168, 1, 0),
            prefix_len: 24,
            next_hop: Some(Ipv4Addr::new(10, 0, 0, 1)),
            interface: "eth1".to_string(),
            metric: 100,
            source: RouteSource::Static,
        });

        // Add connected route for the same network (should replace)
        table.add(Route {
            destination: Ipv4Addr::new(192, 168, 1, 0),
            prefix_len: 24,
            next_hop: None,
            interface: "eth0".to_string(),
            metric: 0,
            source: RouteSource::Connected,
        });

        // Should only have one route
        assert_eq!(table.len(), 1);

        // Should be the connected route
        let route = table.lookup(Ipv4Addr::new(192, 168, 1, 100)).unwrap();
        assert_eq!(route.source, RouteSource::Connected);
        assert_eq!(route.interface, "eth0");
    }
}
