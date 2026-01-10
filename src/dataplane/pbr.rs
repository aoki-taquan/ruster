//! Policy-Based Routing (PBR)
//!
//! Allows routing decisions based on criteria beyond destination IP:
//! - Source IP
//! - Protocol (TCP/UDP/ICMP)
//! - Source/Destination ports
//! - Ingress interface

use std::net::Ipv4Addr;
use std::ops::RangeInclusive;

/// Match criteria for a policy rule
#[derive(Debug, Clone, Default)]
pub struct PolicyMatch {
    /// Source IP prefix (address, prefix_len)
    pub src_ip: Option<(Ipv4Addr, u8)>,
    /// Destination IP prefix (address, prefix_len)
    pub dst_ip: Option<(Ipv4Addr, u8)>,
    /// IP protocol number (1=ICMP, 6=TCP, 17=UDP)
    pub protocol: Option<u8>,
    /// Source port range (TCP/UDP only)
    pub src_port: Option<RangeInclusive<u16>>,
    /// Destination port range (TCP/UDP only)
    pub dst_port: Option<RangeInclusive<u16>>,
    /// Ingress interface name
    pub ingress_interface: Option<String>,
}

impl PolicyMatch {
    /// Check if packet key matches this criteria
    pub fn matches(&self, key: &PacketKey) -> bool {
        // All specified criteria must match
        if let Some((addr, prefix_len)) = self.src_ip {
            if !ip_matches(key.src_ip, addr, prefix_len) {
                return false;
            }
        }

        if let Some((addr, prefix_len)) = self.dst_ip {
            if !ip_matches(key.dst_ip, addr, prefix_len) {
                return false;
            }
        }

        if let Some(proto) = self.protocol {
            if key.protocol != proto {
                return false;
            }
        }

        if let Some(ref range) = self.src_port {
            match key.src_port {
                Some(port) if range.contains(&port) => {}
                _ => return false,
            }
        }

        if let Some(ref range) = self.dst_port {
            match key.dst_port {
                Some(port) if range.contains(&port) => {}
                _ => return false,
            }
        }

        if let Some(ref iface) = self.ingress_interface {
            if key.ingress_interface != *iface {
                return false;
            }
        }

        true
    }
}

/// Check if an IP address matches a prefix
fn ip_matches(ip: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
    let ip_bits = u32::from(ip);
    let net_bits = u32::from(network);
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    (ip_bits & mask) == (net_bits & mask)
}

/// Action to take when policy matches
#[derive(Debug, Clone)]
pub enum PolicyAction {
    /// Forward via specific next-hop gateway
    RouteVia {
        next_hop: Ipv4Addr,
        interface: Option<String>,
    },
    /// Forward directly to interface (no gateway)
    RouteInterface { interface: String },
    /// Use a specific routing table
    UseTable { table_id: u32 },
    /// Drop the packet
    Drop,
    /// Use default routing (skip remaining policy rules)
    UseDefault,
}

/// A single policy rule
#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// Rule priority (lower = higher precedence)
    pub priority: u32,
    /// Optional rule name for identification
    pub name: Option<String>,
    /// Match conditions
    pub match_criteria: PolicyMatch,
    /// Action when matched
    pub action: PolicyAction,
    /// Rule enabled flag
    pub enabled: bool,
}

/// Packet classification key (extracted for matching)
#[derive(Debug, Clone)]
pub struct PacketKey {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub protocol: u8,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub ingress_interface: String,
}

impl Default for PacketKey {
    fn default() -> Self {
        Self {
            src_ip: Ipv4Addr::UNSPECIFIED,
            dst_ip: Ipv4Addr::UNSPECIFIED,
            protocol: 0,
            src_port: None,
            dst_port: None,
            ingress_interface: String::new(),
        }
    }
}

/// Result of policy evaluation
#[derive(Debug, Clone)]
pub enum PolicyResult {
    /// Use the specified route
    Route {
        next_hop: Option<Ipv4Addr>,
        interface: Option<String>,
    },
    /// Use routing table lookup with table_id
    TableLookup { table_id: u32 },
    /// Drop packet
    Drop,
    /// No policy matched - use default routing
    UseDefault,
}

/// Policy-based routing table
#[derive(Debug, Default)]
pub struct PolicyRouter {
    /// Rules sorted by priority (ascending - lower priority value = higher precedence)
    rules: Vec<PolicyRule>,
}

impl PolicyRouter {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a policy rule (maintains priority order)
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority);
    }

    /// Remove a rule by name
    pub fn remove_rule(&mut self, name: &str) {
        self.rules.retain(|r| r.name.as_deref() != Some(name));
    }

    /// Clear all rules
    pub fn clear(&mut self) {
        self.rules.clear();
    }

    /// Get number of rules
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluate policy rules against a packet key
    pub fn evaluate(&self, key: &PacketKey) -> PolicyResult {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if rule.match_criteria.matches(key) {
                return match &rule.action {
                    PolicyAction::RouteVia {
                        next_hop,
                        interface,
                    } => PolicyResult::Route {
                        next_hop: Some(*next_hop),
                        interface: interface.clone(),
                    },
                    PolicyAction::RouteInterface { interface } => PolicyResult::Route {
                        next_hop: None,
                        interface: Some(interface.clone()),
                    },
                    PolicyAction::UseTable { table_id } => PolicyResult::TableLookup {
                        table_id: *table_id,
                    },
                    PolicyAction::Drop => PolicyResult::Drop,
                    PolicyAction::UseDefault => PolicyResult::UseDefault,
                };
            }
        }

        // No rule matched - use default routing
        PolicyResult::UseDefault
    }

    /// Get all rules (for inspection/debugging)
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_matches() {
        // /24 network
        assert!(ip_matches(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 0),
            24
        ));
        assert!(!ip_matches(
            Ipv4Addr::new(192, 168, 2, 100),
            Ipv4Addr::new(192, 168, 1, 0),
            24
        ));

        // /16 network
        assert!(ip_matches(
            Ipv4Addr::new(172, 16, 50, 100),
            Ipv4Addr::new(172, 16, 0, 0),
            16
        ));

        // /0 matches everything
        assert!(ip_matches(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(0, 0, 0, 0),
            0
        ));

        // /32 exact match
        assert!(ip_matches(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            32
        ));
        assert!(!ip_matches(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            32
        ));
    }

    #[test]
    fn test_policy_match_src_ip() {
        let match_criteria = PolicyMatch {
            src_ip: Some((Ipv4Addr::new(192, 168, 1, 0), 24)),
            ..Default::default()
        };

        // Should match
        let key = PacketKey {
            src_ip: Ipv4Addr::new(192, 168, 1, 100),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            protocol: 6,
            src_port: Some(12345),
            dst_port: Some(80),
            ingress_interface: "eth0".to_string(),
        };
        assert!(match_criteria.matches(&key));

        // Should not match (different subnet)
        let key2 = PacketKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            ..key.clone()
        };
        assert!(!match_criteria.matches(&key2));
    }

    #[test]
    fn test_policy_match_port_range() {
        let match_criteria = PolicyMatch {
            protocol: Some(6), // TCP
            dst_port: Some(80..=443),
            ..Default::default()
        };

        // HTTP (port 80) should match
        let http_key = PacketKey {
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            protocol: 6,
            src_port: Some(54321),
            dst_port: Some(80),
            ingress_interface: "eth0".to_string(),
        };
        assert!(match_criteria.matches(&http_key));

        // HTTPS (port 443) should match
        let https_key = PacketKey {
            dst_port: Some(443),
            ..http_key.clone()
        };
        assert!(match_criteria.matches(&https_key));

        // SSH (port 22) should not match
        let ssh_key = PacketKey {
            dst_port: Some(22),
            ..http_key.clone()
        };
        assert!(!match_criteria.matches(&ssh_key));

        // UDP should not match (wrong protocol)
        let udp_key = PacketKey {
            protocol: 17,
            ..http_key.clone()
        };
        assert!(!match_criteria.matches(&udp_key));
    }

    #[test]
    fn test_policy_match_ingress_interface() {
        let match_criteria = PolicyMatch {
            ingress_interface: Some("eth1".to_string()),
            ..Default::default()
        };

        let key1 = PacketKey {
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            protocol: 6,
            src_port: Some(12345),
            dst_port: Some(80),
            ingress_interface: "eth1".to_string(),
        };
        assert!(match_criteria.matches(&key1));

        let key2 = PacketKey {
            ingress_interface: "eth0".to_string(),
            ..key1.clone()
        };
        assert!(!match_criteria.matches(&key2));
    }

    #[test]
    fn test_policy_router_priority_order() {
        let mut router = PolicyRouter::new();

        // Add lower priority (higher precedence) rule second
        router.add_rule(PolicyRule {
            priority: 100,
            name: Some("low-priority".into()),
            match_criteria: PolicyMatch {
                src_ip: Some((Ipv4Addr::new(192, 168, 0, 0), 16)),
                ..Default::default()
            },
            action: PolicyAction::RouteVia {
                next_hop: Ipv4Addr::new(10, 0, 0, 1),
                interface: None,
            },
            enabled: true,
        });

        router.add_rule(PolicyRule {
            priority: 50,
            name: Some("high-priority".into()),
            match_criteria: PolicyMatch {
                src_ip: Some((Ipv4Addr::new(192, 168, 0, 0), 16)),
                ..Default::default()
            },
            action: PolicyAction::Drop,
            enabled: true,
        });

        let key = PacketKey {
            src_ip: Ipv4Addr::new(192, 168, 1, 100),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            protocol: 6,
            src_port: Some(12345),
            dst_port: Some(80),
            ingress_interface: "eth0".to_string(),
        };

        // Should match priority 50 rule (Drop) first
        assert!(matches!(router.evaluate(&key), PolicyResult::Drop));
    }

    #[test]
    fn test_policy_router_disabled_rule() {
        let mut router = PolicyRouter::new();

        router.add_rule(PolicyRule {
            priority: 50,
            name: Some("disabled".into()),
            match_criteria: PolicyMatch::default(),
            action: PolicyAction::Drop,
            enabled: false,
        });

        router.add_rule(PolicyRule {
            priority: 100,
            name: Some("enabled".into()),
            match_criteria: PolicyMatch::default(),
            action: PolicyAction::UseDefault,
            enabled: true,
        });

        let key = PacketKey::default();

        // Should skip disabled rule and match enabled one
        assert!(matches!(router.evaluate(&key), PolicyResult::UseDefault));
    }

    #[test]
    fn test_policy_router_no_match() {
        let mut router = PolicyRouter::new();

        router.add_rule(PolicyRule {
            priority: 100,
            name: Some("specific".into()),
            match_criteria: PolicyMatch {
                src_ip: Some((Ipv4Addr::new(10, 0, 0, 0), 8)),
                ..Default::default()
            },
            action: PolicyAction::Drop,
            enabled: true,
        });

        let key = PacketKey {
            src_ip: Ipv4Addr::new(192, 168, 1, 1), // Doesn't match 10.0.0.0/8
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            protocol: 6,
            src_port: Some(12345),
            dst_port: Some(80),
            ingress_interface: "eth0".to_string(),
        };

        // Should return UseDefault when no rule matches
        assert!(matches!(router.evaluate(&key), PolicyResult::UseDefault));
    }

    #[test]
    fn test_policy_router_use_table() {
        let mut router = PolicyRouter::new();

        router.add_rule(PolicyRule {
            priority: 100,
            name: Some("alt-table".into()),
            match_criteria: PolicyMatch {
                ingress_interface: Some("eth1".to_string()),
                ..Default::default()
            },
            action: PolicyAction::UseTable { table_id: 100 },
            enabled: true,
        });

        let key = PacketKey {
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            protocol: 6,
            src_port: Some(12345),
            dst_port: Some(80),
            ingress_interface: "eth1".to_string(),
        };

        match router.evaluate(&key) {
            PolicyResult::TableLookup { table_id } => assert_eq!(table_id, 100),
            _ => panic!("Expected TableLookup"),
        }
    }

    #[test]
    fn test_policy_router_remove_rule() {
        let mut router = PolicyRouter::new();

        router.add_rule(PolicyRule {
            priority: 100,
            name: Some("to-remove".into()),
            match_criteria: PolicyMatch::default(),
            action: PolicyAction::Drop,
            enabled: true,
        });

        assert_eq!(router.len(), 1);

        router.remove_rule("to-remove");
        assert_eq!(router.len(), 0);
    }
}
