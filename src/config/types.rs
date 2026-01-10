//! Configuration types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// User-defined configuration (config.toml)
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub logging: Option<LoggingConfig>,
    #[serde(default)]
    pub interfaces: HashMap<String, InterfaceConfig>,
    #[serde(default)]
    pub dhcp: HashMap<String, DhcpConfig>,
    #[serde(default)]
    pub nat: Option<NatConfig>,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub filtering: Option<FilteringConfig>,
}

/// Logging configuration
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    /// Log level: error, warn, info, debug, trace
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Output format: pretty, compact, json
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "pretty".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct InterfaceConfig {
    pub role: InterfaceRole,
    #[serde(default)]
    pub addressing: Addressing,
    pub address: Option<String>,
    pub mtu: Option<u16>,
    pub vlan_mode: Option<VlanMode>,
    pub vlan_config: Option<VlanConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceRole {
    Wan,
    Lan,
    Trunk,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Addressing {
    #[default]
    Static,
    Dhcp,
    Pppoe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VlanMode {
    Access,
    Trunk,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VlanConfig {
    pub native_vlan: Option<u16>,
    pub access_vlan: Option<u16>,
    pub allowed_vlans: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DhcpConfig {
    pub range: (Ipv4Addr, Ipv4Addr),
    pub gateway: Ipv4Addr,
    #[serde(default)]
    pub dns: Vec<Ipv4Addr>,
    pub lease_time: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NatConfig {
    pub enabled: bool,
    pub wan: String,
    pub lan: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RoutingConfig {
    #[serde(default)]
    pub static_routes: Vec<StaticRoute>,
    #[serde(default)]
    pub policy: Vec<PolicyRuleConfig>,
    #[serde(default)]
    pub tables: Vec<RoutingTableConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StaticRoute {
    pub destination: String,
    pub gateway: String,
    #[serde(default)]
    pub interface: Option<String>,
}

/// Policy rule from configuration
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRuleConfig {
    pub name: Option<String>,
    pub priority: u32,
    #[serde(rename = "match", default)]
    pub match_config: PolicyMatchConfig,
    pub action: PolicyActionConfig,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Policy match conditions from configuration
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyMatchConfig {
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    /// Protocol: "tcp", "udp", "icmp", or number
    pub protocol: Option<String>,
    /// Port or range: "80" or "1024-65535"
    pub src_port: Option<String>,
    /// Port or range: "80" or "1024-65535"
    pub dst_port: Option<String>,
    pub ingress_interface: Option<String>,
}

/// Policy action from configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyActionConfig {
    RouteVia {
        next_hop: String,
        interface: Option<String>,
    },
    RouteInterface {
        interface: String,
    },
    UseTable {
        table_id: u32,
    },
    Drop,
    UseDefault,
}

/// Named routing table configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RoutingTableConfig {
    pub id: u32,
    pub name: Option<String>,
    #[serde(default)]
    pub routes: Vec<StaticRoute>,
}

/// Packet filtering configuration
#[derive(Debug, Clone, Deserialize)]
pub struct FilteringConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Default action: "accept" or "drop"
    #[serde(default = "default_accept")]
    pub default_action: String,
    #[serde(default)]
    pub rules: Vec<FilterRuleConfig>,
}

fn default_accept() -> String {
    "accept".to_string()
}

/// Filter rule from configuration
#[derive(Debug, Clone, Deserialize)]
pub struct FilterRuleConfig {
    /// Chain: "input", "output", "forward"
    pub chain: String,
    /// Protocol: "icmp", "icmpv6", "tcp", "udp", or number
    #[serde(default)]
    pub protocol: Option<String>,
    /// Source IP/CIDR (IPv4 or IPv6)
    #[serde(default)]
    pub src_ip: Option<String>,
    /// Destination IP/CIDR (IPv4 or IPv6)
    #[serde(default)]
    pub dst_ip: Option<String>,
    /// Source port or range: "80" or "1024-65535"
    #[serde(default)]
    pub src_port: Option<String>,
    /// Destination port or range: "80" or "1024-65535"
    #[serde(default)]
    pub dst_port: Option<String>,
    /// Input interface name
    #[serde(default)]
    pub in_interface: Option<String>,
    /// Output interface name
    #[serde(default)]
    pub out_interface: Option<String>,
    /// Action: "accept", "drop", "reject"
    pub action: String,
    /// Priority (lower = higher priority)
    #[serde(default = "default_priority")]
    pub priority: u32,
}

fn default_priority() -> u32 {
    1000
}

// ============================================================================
// Lock file types (generated, includes all defaults)
// ============================================================================

/// Generated lock file with all defaults filled in
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigLock {
    pub generated_at: String,
    pub source_hash: String,
    #[serde(default)]
    pub logging: LoggingLock,
    pub interfaces: HashMap<String, InterfaceLock>,
    pub dhcp: HashMap<String, DhcpLock>,
    pub nat: Option<NatLock>,
    pub routing: RoutingLock,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filtering: Option<FilteringLock>,
}

/// Logging configuration in lock file (with defaults filled in)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoggingLock {
    pub level: String,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceLock {
    pub role: String,
    pub addressing: String,
    pub address: Option<String>,
    pub mtu: u16,
    pub mac: String,
    pub duplex: String,
    pub vlan_mode: Option<String>,
    pub vlan_config: Option<VlanLockConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlanLockConfig {
    pub native_vlan: u16,
    pub access_vlan: Option<u16>,
    pub allowed_vlans: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLock {
    pub interface: String,
    pub range: (Ipv4Addr, Ipv4Addr),
    pub gateway: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub lease_time: u32,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatLock {
    pub enabled: bool,
    pub wan: String,
    pub lan: Vec<String>,
    pub nat_type: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutingLock {
    pub static_routes: Vec<StaticRouteLock>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy: Vec<PolicyRuleLock>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tables: Vec<RoutingTableLock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticRouteLock {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub source: String,
}

/// Policy rule in lock file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleLock {
    pub name: String,
    pub priority: u32,
    pub enabled: bool,
    #[serde(rename = "match")]
    pub match_lock: PolicyMatchLock,
    pub action: PolicyActionLock,
}

/// Policy match conditions in lock file
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyMatchLock {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_interface: Option<String>,
}

/// Policy action in lock file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyActionLock {
    RouteVia {
        next_hop: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        interface: Option<String>,
    },
    RouteInterface {
        interface: String,
    },
    UseTable {
        table_id: u32,
    },
    Drop,
    UseDefault,
}

/// Routing table in lock file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingTableLock {
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub routes: Vec<StaticRouteLock>,
}

/// Filtering configuration in lock file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilteringLock {
    pub enabled: bool,
    pub default_action: String,
    pub rules: Vec<FilterRuleLock>,
}

/// Filter rule in lock file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRuleLock {
    pub chain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_interface: Option<String>,
    pub action: String,
    pub priority: u32,
}

impl ConfigLock {
    pub fn from_config(config: &Config, source_hash: String) -> Self {
        let interfaces = config
            .interfaces
            .iter()
            .map(|(name, iface)| {
                let vlan_mode = iface.vlan_mode.map(|m| match m {
                    VlanMode::Access => "access".to_string(),
                    VlanMode::Trunk => "trunk".to_string(),
                });

                let vlan_config = iface.vlan_config.as_ref().map(|cfg| VlanLockConfig {
                    native_vlan: cfg.native_vlan.unwrap_or(1),
                    access_vlan: cfg.access_vlan,
                    allowed_vlans: cfg.allowed_vlans.clone().unwrap_or_default(),
                });

                (
                    name.clone(),
                    InterfaceLock {
                        role: format!("{:?}", iface.role).to_lowercase(),
                        addressing: format!("{:?}", iface.addressing).to_lowercase(),
                        address: iface.address.clone(),
                        mtu: iface.mtu.unwrap_or(1500),
                        mac: "auto".to_string(),
                        duplex: "auto".to_string(),
                        vlan_mode,
                        vlan_config,
                    },
                )
            })
            .collect();

        let dhcp = config
            .dhcp
            .iter()
            .map(|(name, dhcp_cfg)| {
                (
                    name.clone(),
                    DhcpLock {
                        interface: name.clone(),
                        range: dhcp_cfg.range,
                        gateway: dhcp_cfg.gateway,
                        dns: dhcp_cfg.dns.clone(),
                        lease_time: dhcp_cfg.lease_time.unwrap_or(86400),
                        domain: String::new(),
                    },
                )
            })
            .collect();

        let nat = config.nat.as_ref().map(|n| NatLock {
            enabled: n.enabled,
            wan: n.wan.clone(),
            lan: n.lan.clone(),
            nat_type: "napt".to_string(),
        });

        // Generate static routes with defaults filled in
        let static_routes: Vec<StaticRouteLock> = config
            .routing
            .static_routes
            .iter()
            .map(|route| StaticRouteLock {
                destination: route.destination.clone(),
                gateway: route.gateway.clone(),
                interface: route.interface.clone().unwrap_or_default(),
                source: "config".to_string(),
            })
            .collect();

        // Add implicit routes for directly connected networks
        let mut all_routes = static_routes;
        for (name, iface) in &config.interfaces {
            if let Some(ref addr) = iface.address {
                // Extract network from address (e.g., "192.168.1.1/24" -> "192.168.1.0/24")
                if let Some(network) = extract_network(addr) {
                    all_routes.push(StaticRouteLock {
                        destination: network,
                        gateway: "direct".to_string(),
                        interface: name.clone(),
                        source: "auto".to_string(),
                    });
                }
            }
        }

        let logging = config
            .logging
            .as_ref()
            .map(|l| LoggingLock {
                level: l.level.clone(),
                format: l.format.clone(),
            })
            .unwrap_or_else(|| LoggingLock {
                level: default_log_level(),
                format: default_log_format(),
            });

        // Generate policy rules lock
        let policy: Vec<PolicyRuleLock> = config
            .routing
            .policy
            .iter()
            .enumerate()
            .map(|(i, rule)| PolicyRuleLock {
                name: rule.name.clone().unwrap_or_else(|| format!("policy-{}", i)),
                priority: rule.priority,
                enabled: rule.enabled,
                match_lock: PolicyMatchLock {
                    src_ip: rule.match_config.src_ip.clone(),
                    dst_ip: rule.match_config.dst_ip.clone(),
                    protocol: rule.match_config.protocol.clone(),
                    src_port: rule.match_config.src_port.clone(),
                    dst_port: rule.match_config.dst_port.clone(),
                    ingress_interface: rule.match_config.ingress_interface.clone(),
                },
                action: match &rule.action {
                    PolicyActionConfig::RouteVia {
                        next_hop,
                        interface,
                    } => PolicyActionLock::RouteVia {
                        next_hop: next_hop.clone(),
                        interface: interface.clone(),
                    },
                    PolicyActionConfig::RouteInterface { interface } => {
                        PolicyActionLock::RouteInterface {
                            interface: interface.clone(),
                        }
                    }
                    PolicyActionConfig::UseTable { table_id } => PolicyActionLock::UseTable {
                        table_id: *table_id,
                    },
                    PolicyActionConfig::Drop => PolicyActionLock::Drop,
                    PolicyActionConfig::UseDefault => PolicyActionLock::UseDefault,
                },
            })
            .collect();

        // Generate routing tables lock
        let tables: Vec<RoutingTableLock> = config
            .routing
            .tables
            .iter()
            .map(|table| RoutingTableLock {
                id: table.id,
                name: table.name.clone(),
                routes: table
                    .routes
                    .iter()
                    .map(|route| StaticRouteLock {
                        destination: route.destination.clone(),
                        gateway: route.gateway.clone(),
                        interface: route.interface.clone().unwrap_or_default(),
                        source: "config".to_string(),
                    })
                    .collect(),
            })
            .collect();

        // Generate filtering lock
        let filtering = config.filtering.as_ref().map(|f| FilteringLock {
            enabled: f.enabled,
            default_action: f.default_action.clone(),
            rules: f
                .rules
                .iter()
                .map(|rule| FilterRuleLock {
                    chain: rule.chain.clone(),
                    protocol: rule.protocol.clone(),
                    src_ip: rule.src_ip.clone(),
                    dst_ip: rule.dst_ip.clone(),
                    src_port: rule.src_port.clone(),
                    dst_port: rule.dst_port.clone(),
                    in_interface: rule.in_interface.clone(),
                    out_interface: rule.out_interface.clone(),
                    action: rule.action.clone(),
                    priority: rule.priority,
                })
                .collect(),
        });

        ConfigLock {
            generated_at: chrono::Utc::now().to_rfc3339(),
            source_hash,
            logging,
            interfaces,
            dhcp,
            nat,
            routing: RoutingLock {
                static_routes: all_routes,
                policy,
                tables,
            },
            filtering,
        }
    }
}

/// Extract network address from CIDR notation (e.g., "192.168.1.1/24" -> "192.168.1.0/24")
fn extract_network(cidr: &str) -> Option<String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let addr: std::net::Ipv4Addr = parts[0].parse().ok()?;
    let prefix_len: u8 = parts[1].parse().ok()?;

    if prefix_len > 32 {
        return None;
    }

    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };

    let network_bits = u32::from(addr) & mask;
    let network_addr = std::net::Ipv4Addr::from(network_bits);

    Some(format!("{}/{}", network_addr, prefix_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_network_24() {
        assert_eq!(
            extract_network("192.168.1.100/24"),
            Some("192.168.1.0/24".to_string())
        );
    }

    #[test]
    fn test_extract_network_16() {
        assert_eq!(
            extract_network("10.1.2.3/16"),
            Some("10.1.0.0/16".to_string())
        );
    }

    #[test]
    fn test_extract_network_32() {
        assert_eq!(
            extract_network("192.168.1.1/32"),
            Some("192.168.1.1/32".to_string())
        );
    }

    #[test]
    fn test_extract_network_0() {
        assert_eq!(
            extract_network("192.168.1.1/0"),
            Some("0.0.0.0/0".to_string())
        );
    }

    #[test]
    fn test_extract_network_invalid_no_prefix() {
        assert_eq!(extract_network("192.168.1.1"), None);
    }

    #[test]
    fn test_extract_network_invalid_prefix() {
        assert_eq!(extract_network("192.168.1.1/33"), None);
    }

    #[test]
    fn test_extract_network_invalid_addr() {
        assert_eq!(extract_network("invalid/24"), None);
    }

    #[test]
    fn test_config_lock_from_config() {
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

        let config = Config {
            logging: None,
            interfaces,
            dhcp: HashMap::new(),
            nat: None,
            routing: RoutingConfig::default(),
            filtering: None,
        };

        let lock = ConfigLock::from_config(&config, "testhash".to_string());

        assert_eq!(lock.source_hash, "testhash");
        assert_eq!(lock.logging.level, "info");
        assert_eq!(lock.logging.format, "pretty");
        assert_eq!(lock.interfaces.len(), 1);

        let eth0 = &lock.interfaces["eth0"];
        assert_eq!(eth0.role, "lan");
        assert_eq!(eth0.mtu, 1500); // default
        assert_eq!(eth0.mac, "auto");
        assert!(eth0.vlan_mode.is_none());
        assert!(eth0.vlan_config.is_none());

        // Should have auto-generated connected route
        assert_eq!(lock.routing.static_routes.len(), 1);
        let route = &lock.routing.static_routes[0];
        assert_eq!(route.destination, "192.168.1.0/24");
        assert_eq!(route.gateway, "direct");
        assert_eq!(route.source, "auto");
    }

    #[test]
    fn test_config_lock_with_vlan_access() {
        let mut interfaces = HashMap::new();
        interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Lan,
                addressing: Addressing::Static,
                address: Some("192.168.1.1/24".to_string()),
                mtu: None,
                vlan_mode: Some(VlanMode::Access),
                vlan_config: Some(VlanConfig {
                    native_vlan: Some(1),
                    access_vlan: Some(10),
                    allowed_vlans: None,
                }),
            },
        );

        let config = Config {
            logging: None,
            interfaces,
            dhcp: HashMap::new(),
            nat: None,
            routing: RoutingConfig::default(),
            filtering: None,
        };

        let lock = ConfigLock::from_config(&config, "testhash".to_string());
        let eth0 = &lock.interfaces["eth0"];

        assert_eq!(eth0.vlan_mode, Some("access".to_string()));
        let vlan_cfg = eth0.vlan_config.as_ref().unwrap();
        assert_eq!(vlan_cfg.native_vlan, 1);
        assert_eq!(vlan_cfg.access_vlan, Some(10));
        assert!(vlan_cfg.allowed_vlans.is_empty());
    }

    #[test]
    fn test_config_lock_with_vlan_trunk() {
        let mut interfaces = HashMap::new();
        interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Trunk,
                addressing: Addressing::Static,
                address: None,
                mtu: None,
                vlan_mode: Some(VlanMode::Trunk),
                vlan_config: Some(VlanConfig {
                    native_vlan: Some(1),
                    access_vlan: None,
                    allowed_vlans: Some(vec![1, 10, 20]),
                }),
            },
        );

        let config = Config {
            logging: None,
            interfaces,
            dhcp: HashMap::new(),
            nat: None,
            routing: RoutingConfig::default(),
            filtering: None,
        };

        let lock = ConfigLock::from_config(&config, "testhash".to_string());
        let eth0 = &lock.interfaces["eth0"];

        assert_eq!(eth0.vlan_mode, Some("trunk".to_string()));
        let vlan_cfg = eth0.vlan_config.as_ref().unwrap();
        assert_eq!(vlan_cfg.native_vlan, 1);
        assert_eq!(vlan_cfg.access_vlan, None);
        assert_eq!(vlan_cfg.allowed_vlans, vec![1, 10, 20]);
    }
}
