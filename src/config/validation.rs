//! Configuration validation

use super::{Config, InterfaceRole, VlanMode};

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
            eprintln!("[WARN] {}", warning);
        }
        for error in &self.errors {
            eprintln!("[ERROR] {}", error);
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
    validate_vlan(config, &mut result);
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

fn validate_vlan(config: &Config, result: &mut ValidationResult) {
    for (name, iface) in &config.interfaces {
        let Some(mode) = &iface.vlan_mode else {
            continue;
        };

        let vlan_cfg = iface.vlan_config.as_ref();

        // Helper to check VLAN ID range (1-4094)
        let check_vid = |vid: u16, field: &str| -> Option<String> {
            if vid == 0 || vid > 4094 {
                Some(format!(
                    "interfaces.{}: {} {} is invalid (must be 1-4094)",
                    name, field, vid
                ))
            } else {
                None
            }
        };

        // Check VLAN ID ranges
        if let Some(cfg) = vlan_cfg {
            if let Some(vid) = cfg.native_vlan {
                if let Some(err) = check_vid(vid, "native_vlan") {
                    result.error(err);
                }
            }
            if let Some(vid) = cfg.access_vlan {
                if let Some(err) = check_vid(vid, "access_vlan") {
                    result.error(err);
                }
            }
            if let Some(vlans) = &cfg.allowed_vlans {
                for vid in vlans {
                    if let Some(err) = check_vid(*vid, "allowed_vlans entry") {
                        result.error(err);
                    }
                }
            }
        }

        // Access mode: access_vlan required
        if *mode == VlanMode::Access {
            let has_access_vlan = vlan_cfg
                .map(|cfg| cfg.access_vlan.is_some())
                .unwrap_or(false);
            if !has_access_vlan {
                result.error(format!(
                    "interfaces.{}: access mode requires access_vlan",
                    name
                ));
            }
        }

        // Trunk mode: allowed_vlans required
        if *mode == VlanMode::Trunk {
            let has_allowed_vlans = vlan_cfg
                .map(|cfg| cfg.allowed_vlans.is_some())
                .unwrap_or(false);
            if !has_allowed_vlans {
                result.error(format!(
                    "interfaces.{}: trunk mode requires allowed_vlans",
                    name
                ));
            }

            // Check native_vlan is in allowed_vlans
            if let Some(cfg) = vlan_cfg {
                if let (Some(native), Some(allowed)) = (cfg.native_vlan, &cfg.allowed_vlans) {
                    if !allowed.contains(&native) {
                        result.warn(format!(
                            "interfaces.{}: native_vlan {} is not in allowed_vlans",
                            name, native
                        ));
                    }
                }
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
        StaticRoute, VlanConfig, VlanMode,
    };
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    fn make_config() -> Config {
        Config {
            logging: None,
            interfaces: HashMap::new(),
            dhcp: HashMap::new(),
            nat: None,
            firewall: None,
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
                vlan_mode: None,
                vlan_config: None,
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
                vlan_mode: None,
                vlan_config: None,
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
                vlan_mode: None,
                vlan_config: None,
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
                vlan_mode: None,
                vlan_config: None,
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
                vlan_mode: None,
                vlan_config: None,
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

    // VLAN validation tests

    #[test]
    fn test_vlan_access_valid() {
        let mut config = make_config();
        config.interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Lan,
                addressing: Addressing::Static,
                address: Some("192.168.1.1/24".to_string()),
                mtu: Some(1500),
                vlan_mode: Some(VlanMode::Access),
                vlan_config: Some(VlanConfig {
                    native_vlan: Some(1),
                    access_vlan: Some(10),
                    allowed_vlans: None,
                }),
            },
        );
        let result = validate(&config);
        assert!(!result.has_errors());
    }

    #[test]
    fn test_vlan_trunk_valid() {
        let mut config = make_config();
        config.interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Trunk,
                addressing: Addressing::Static,
                address: None,
                mtu: Some(1500),
                vlan_mode: Some(VlanMode::Trunk),
                vlan_config: Some(VlanConfig {
                    native_vlan: Some(1),
                    access_vlan: None,
                    allowed_vlans: Some(vec![1, 10, 20]),
                }),
            },
        );
        let result = validate(&config);
        assert!(!result.has_errors());
    }

    #[test]
    fn test_vlan_invalid_vid_zero() {
        let mut config = make_config();
        config.interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Lan,
                addressing: Addressing::Static,
                address: Some("192.168.1.1/24".to_string()),
                mtu: Some(1500),
                vlan_mode: Some(VlanMode::Access),
                vlan_config: Some(VlanConfig {
                    native_vlan: Some(0), // Invalid!
                    access_vlan: Some(10),
                    allowed_vlans: None,
                }),
            },
        );
        let result = validate(&config);
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| e.contains("native_vlan 0")));
    }

    #[test]
    fn test_vlan_invalid_vid_4095() {
        let mut config = make_config();
        config.interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Lan,
                addressing: Addressing::Static,
                address: Some("192.168.1.1/24".to_string()),
                mtu: Some(1500),
                vlan_mode: Some(VlanMode::Access),
                vlan_config: Some(VlanConfig {
                    native_vlan: Some(1),
                    access_vlan: Some(4095), // Invalid!
                    allowed_vlans: None,
                }),
            },
        );
        let result = validate(&config);
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| e.contains("access_vlan 4095")));
    }

    #[test]
    fn test_vlan_access_missing_access_vlan() {
        let mut config = make_config();
        config.interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Lan,
                addressing: Addressing::Static,
                address: Some("192.168.1.1/24".to_string()),
                mtu: Some(1500),
                vlan_mode: Some(VlanMode::Access),
                vlan_config: Some(VlanConfig {
                    native_vlan: Some(1),
                    access_vlan: None, // Missing!
                    allowed_vlans: None,
                }),
            },
        );
        let result = validate(&config);
        assert!(result.has_errors());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("access mode requires access_vlan")));
    }

    #[test]
    fn test_vlan_trunk_missing_allowed_vlans() {
        let mut config = make_config();
        config.interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Trunk,
                addressing: Addressing::Static,
                address: None,
                mtu: Some(1500),
                vlan_mode: Some(VlanMode::Trunk),
                vlan_config: Some(VlanConfig {
                    native_vlan: Some(1),
                    access_vlan: None,
                    allowed_vlans: None, // Missing!
                }),
            },
        );
        let result = validate(&config);
        assert!(result.has_errors());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("trunk mode requires allowed_vlans")));
    }

    #[test]
    fn test_vlan_trunk_native_not_in_allowed() {
        let mut config = make_config();
        config.interfaces.insert(
            "eth0".to_string(),
            InterfaceConfig {
                role: InterfaceRole::Trunk,
                addressing: Addressing::Static,
                address: None,
                mtu: Some(1500),
                vlan_mode: Some(VlanMode::Trunk),
                vlan_config: Some(VlanConfig {
                    native_vlan: Some(100), // Not in allowed_vlans
                    access_vlan: None,
                    allowed_vlans: Some(vec![1, 10, 20]),
                }),
            },
        );
        let result = validate(&config);
        assert!(!result.has_errors()); // Warning, not error
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("native_vlan 100 is not in allowed_vlans")));
    }
}
