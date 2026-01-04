//! Configuration validation

use super::{Config, InterfaceRole};

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    pub fn error(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn print_diagnostics(&self) {
        for warning in &self.warnings {
            println!("[WARN] {}", warning);
        }
        for error in &self.errors {
            println!("[ERROR] {}", error);
        }
    }
}

impl Default for ValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate configuration and return warnings/errors
pub fn validate(config: &Config) -> ValidationResult {
    let mut result = ValidationResult::new();

    validate_interfaces(config, &mut result);
    validate_dhcp(config, &mut result);
    validate_nat(config, &mut result);
    validate_routing(config, &mut result);

    result
}

fn validate_interfaces(config: &Config, result: &mut ValidationResult) {
    for (name, iface) in &config.interfaces {
        // Check MTU defaults
        if iface.mtu.is_none() {
            result.warn(format!(
                "interfaces.{}: mtu not specified, using default 1500",
                name
            ));
        }

        // LAN interface should have static address
        if iface.role == InterfaceRole::Lan && iface.address.is_none() {
            result.error(format!(
                "interfaces.{}: LAN interface requires static address",
                name
            ));
        }

        // WAN with static addressing should have address
        if iface.role == InterfaceRole::Wan {
            use super::Addressing;
            if matches!(iface.addressing, Addressing::Static) && iface.address.is_none() {
                result.error(format!(
                    "interfaces.{}: WAN interface with static addressing requires address",
                    name
                ));
            }
        }
    }
}

fn validate_dhcp(config: &Config, result: &mut ValidationResult) {
    for (name, dhcp) in &config.dhcp {
        // Check if interface exists
        if !config.interfaces.contains_key(name) {
            // Check if any LAN interface matches
            let has_lan = config
                .interfaces
                .iter()
                .any(|(_, iface)| iface.role == InterfaceRole::Lan);
            if !has_lan {
                result.error(format!("dhcp.{}: no matching LAN interface defined", name));
            }
        }

        // Check lease_time default
        if dhcp.lease_time.is_none() {
            result.warn(format!(
                "dhcp.{}: lease_time not specified, using default 86400",
                name
            ));
        }

        // Check DNS servers
        if dhcp.dns.is_empty() {
            result.warn(format!("dhcp.{}: no DNS servers specified", name));
        }

        // Validate range
        if dhcp.range.0 > dhcp.range.1 {
            result.error(format!(
                "dhcp.{}: invalid range - start ({}) > end ({})",
                name, dhcp.range.0, dhcp.range.1
            ));
        }
    }
}

fn validate_nat(config: &Config, result: &mut ValidationResult) {
    if let Some(nat) = &config.nat {
        if !nat.enabled {
            return;
        }

        // Check WAN interface exists
        if !config.interfaces.contains_key(&nat.wan) {
            result.error(format!("nat.wan: interface '{}' not defined", nat.wan));
        } else {
            let wan_iface = &config.interfaces[&nat.wan];
            if wan_iface.role != InterfaceRole::Wan {
                result.error(format!(
                    "nat.wan: interface '{}' is not configured as WAN role",
                    nat.wan
                ));
            }
        }

        // Check LAN interfaces exist
        for lan in &nat.lan {
            if !config.interfaces.contains_key(lan) {
                result.error(format!("nat.lan: interface '{}' not defined", lan));
            } else {
                let lan_iface = &config.interfaces[lan];
                if lan_iface.role != InterfaceRole::Lan {
                    result.error(format!(
                        "nat.lan: interface '{}' is not configured as LAN role",
                        lan
                    ));
                }
            }
        }
    }
}

fn validate_routing(config: &Config, result: &mut ValidationResult) {
    for (i, route) in config.routing.static_routes.iter().enumerate() {
        // Check interface reference if specified
        if let Some(ref iface) = route.interface {
            if !config.interfaces.contains_key(iface) {
                result.error(format!(
                    "routing.static[{}]: interface '{}' not defined",
                    i, iface
                ));
            }
        }

        // Validate destination is valid CIDR
        if !route.destination.contains('/') {
            result.warn(format!(
                "routing.static[{}]: destination '{}' missing prefix length",
                i, route.destination
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Addressing, DhcpConfig, InterfaceConfig, InterfaceRole, NatConfig, RoutingConfig,
        StaticRoute,
    };
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    fn make_config() -> Config {
        Config {
            interfaces: HashMap::new(),
            dhcp: HashMap::new(),
            nat: None,
            routing: RoutingConfig::default(),
        }
    }

    #[test]
    fn test_valid_minimal_config() {
        let config = make_config();
        let result = validate(&config);
        assert!(!result.has_errors());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_lan_interface_requires_address() {
        let mut config = make_config();
        config.interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Lan,
                addressing: Addressing::Static,
                address: None, // Missing!
                mtu: Some(1500),
            },
        );
        let result = validate(&config);
        assert!(result.has_errors());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("LAN interface requires static address")));
    }

    #[test]
    fn test_wan_static_requires_address() {
        let mut config = make_config();
        config.interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Wan,
                addressing: Addressing::Static,
                address: None, // Missing!
                mtu: Some(1500),
            },
        );
        let result = validate(&config);
        assert!(result.has_errors());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("static addressing requires address")));
    }

    #[test]
    fn test_wan_dhcp_no_address_required() {
        let mut config = make_config();
        config.interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Wan,
                addressing: Addressing::Dhcp,
                address: None, // OK for DHCP
                mtu: Some(1500),
            },
        );
        let result = validate(&config);
        assert!(!result.has_errors());
    }

    #[test]
    fn test_mtu_default_warning() {
        let mut config = make_config();
        config.interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Lan,
                addressing: Addressing::Static,
                address: Some("192.168.1.1/24".to_string()),
                mtu: None, // Will warn
            },
        );
        let result = validate(&config);
        assert!(!result.has_errors());
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("mtu not specified")));
    }

    #[test]
    fn test_dhcp_invalid_range() {
        let mut config = make_config();
        config.dhcp.insert(
            "lan".to_string(),
            DhcpConfig {
                range: (
                    Ipv4Addr::new(192, 168, 1, 200),
                    Ipv4Addr::new(192, 168, 1, 100),
                ), // start > end
                gateway: Ipv4Addr::new(192, 168, 1, 1),
                dns: vec![],
                lease_time: Some(86400),
            },
        );
        let result = validate(&config);
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| e.contains("invalid range")));
    }

    #[test]
    fn test_nat_undefined_wan() {
        let mut config = make_config();
        config.nat = Some(NatConfig {
            enabled: true,
            wan: "eth0".to_string(), // Not defined
            lan: vec![],
        });
        let result = validate(&config);
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| e.contains("not defined")));
    }

    #[test]
    fn test_nat_wrong_role() {
        let mut config = make_config();
        config.interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Lan, // Wrong role
                addressing: Addressing::Static,
                address: Some("192.168.1.1/24".to_string()),
                mtu: Some(1500),
            },
        );
        config.nat = Some(NatConfig {
            enabled: true,
            wan: "eth0".to_string(),
            lan: vec![],
        });
        let result = validate(&config);
        assert!(result.has_errors());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("not configured as WAN")));
    }

    #[test]
    fn test_routing_undefined_interface() {
        let mut config = make_config();
        config.routing.static_routes.push(StaticRoute {
            destination: "0.0.0.0/0".to_string(),
            gateway: "192.168.1.1".to_string(),
            interface: Some("eth99".to_string()), // Not defined
        });
        let result = validate(&config);
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| e.contains("eth99")));
    }

    #[test]
    fn test_routing_missing_prefix() {
        let mut config = make_config();
        config.routing.static_routes.push(StaticRoute {
            destination: "10.0.0.0".to_string(), // Missing /prefix
            gateway: "192.168.1.1".to_string(),
            interface: None,
        });
        let result = validate(&config);
        assert!(!result.has_errors());
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("missing prefix length")));
    }
}
