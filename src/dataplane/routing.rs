//! Routing table

use std::net::Ipv4Addr;

/// Route entry
#[derive(Debug, Clone)]
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
