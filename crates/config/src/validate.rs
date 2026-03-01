use crate::model::{InterfaceRole, RouterConfig};
use std::collections::HashSet;

#[derive(Debug)]
pub struct ValidationError {
    pub field: String,
    pub reason: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.reason)
    }
}

pub fn validate(config: &RouterConfig) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    check_worker_count(config, &mut errors);
    check_unique_interface_names(config, &mut errors);
    check_unique_port_ids(config, &mut errors);
    check_bridge_domain_members(config, &mut errors);
    check_static_route_out_ifs(config, &mut errors);
    check_nat_external_if(config, &mut errors);
    check_nat_requires_firewall(config, &mut errors);
    check_firewall_rule_states(config, &mut errors);
    check_ipv4_addrs(config, &mut errors);
    check_route_addresses(config, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn interface_names(config: &RouterConfig) -> HashSet<&str> {
    config.interfaces.iter().map(|i| i.name.as_str()).collect()
}

fn check_worker_count(config: &RouterConfig, errors: &mut Vec<ValidationError>) {
    if config.dataplane.worker_count < 1 {
        errors.push(ValidationError {
            field: "dataplane.worker_count".to_string(),
            reason: "worker_count must be >= 1".to_string(),
        });
    }
}

fn check_unique_interface_names(config: &RouterConfig, errors: &mut Vec<ValidationError>) {
    let mut seen = HashSet::new();
    for iface in &config.interfaces {
        if !seen.insert(&iface.name) {
            errors.push(ValidationError {
                field: format!("interfaces.name={}", iface.name),
                reason: "duplicate interface name".to_string(),
            });
        }
    }
}

fn check_unique_port_ids(config: &RouterConfig, errors: &mut Vec<ValidationError>) {
    let mut seen = HashSet::new();
    for iface in &config.interfaces {
        if !seen.insert(iface.port_id) {
            errors.push(ValidationError {
                field: format!("interfaces.port_id={}", iface.port_id),
                reason: "duplicate port_id".to_string(),
            });
        }
    }
}

fn check_bridge_domain_members(config: &RouterConfig, errors: &mut Vec<ValidationError>) {
    let names = interface_names(config);
    for bd in &config.l2.bridge_domains {
        for member in &bd.members {
            if !names.contains(member.as_str()) {
                errors.push(ValidationError {
                    field: format!("l2.bridge_domains[name={}].members", bd.name),
                    reason: format!("member '{}' not found in interfaces", member),
                });
            }
        }
    }
}

fn check_static_route_out_ifs(config: &RouterConfig, errors: &mut Vec<ValidationError>) {
    let names = interface_names(config);
    for route in &config.routing.ipv4_static_routes {
        if !names.contains(route.out_if.as_str()) {
            errors.push(ValidationError {
                field: format!("routing.ipv4_static_routes[prefix={}].out_if", route.prefix),
                reason: format!("out_if '{}' not found in interfaces", route.out_if),
            });
        }
    }
}

fn check_nat_external_if(config: &RouterConfig, errors: &mut Vec<ValidationError>) {
    let wan_if = config
        .interfaces
        .iter()
        .find(|i| i.name == config.nat.external_if);
    match wan_if {
        None => {
            errors.push(ValidationError {
                field: "nat.external_if".to_string(),
                reason: format!("'{}' not found in interfaces", config.nat.external_if),
            });
        }
        Some(iface) if iface.role != InterfaceRole::Wan => {
            errors.push(ValidationError {
                field: "nat.external_if".to_string(),
                reason: format!(
                    "'{}' has role {:?}, expected wan",
                    config.nat.external_if, iface.role
                ),
            });
        }
        _ => {}
    }
}

fn check_nat_requires_firewall(config: &RouterConfig, errors: &mut Vec<ValidationError>) {
    if config.nat.enabled && !config.firewall.enabled {
        errors.push(ValidationError {
            field: "nat.enabled".to_string(),
            reason: "nat.enabled=true requires firewall.enabled=true".to_string(),
        });
    }
}

fn check_firewall_rule_states(config: &RouterConfig, errors: &mut Vec<ValidationError>) {
    for rule in &config.firewall.rules {
        if rule.state.is_empty() {
            errors.push(ValidationError {
                field: format!("firewall.rules[name={}].state", rule.name),
                reason: "state must not be empty".to_string(),
            });
        }
    }
}

/// Validate that every `ipv4_addrs` entry on each interface is a valid CIDR
/// string (e.g. "192.168.1.1/24").
fn check_ipv4_addrs(config: &RouterConfig, errors: &mut Vec<ValidationError>) {
    for iface in &config.interfaces {
        for (i, addr) in iface.ipv4_addrs.iter().enumerate() {
            if !is_valid_cidr(addr) {
                errors.push(ValidationError {
                    field: format!("interfaces[name={}].ipv4_addrs[{}]", iface.name, i),
                    reason: format!("invalid CIDR address '{}'", addr),
                });
            }
        }
    }
}

/// Validate that every static route has a valid CIDR prefix and a valid IPv4
/// next-hop address.
fn check_route_addresses(config: &RouterConfig, errors: &mut Vec<ValidationError>) {
    for route in &config.routing.ipv4_static_routes {
        if !is_valid_cidr(&route.prefix) {
            errors.push(ValidationError {
                field: format!("routing.ipv4_static_routes[prefix={}].prefix", route.prefix),
                reason: format!("invalid CIDR prefix '{}'", route.prefix),
            });
        }
        if !is_valid_ipv4(&route.next_hop) {
            errors.push(ValidationError {
                field: format!(
                    "routing.ipv4_static_routes[prefix={}].next_hop",
                    route.prefix
                ),
                reason: format!("invalid IPv4 address '{}'", route.next_hop),
            });
        }
    }
}

/// Check whether a string is a valid IPv4 address (e.g. "192.168.1.1").
fn is_valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

/// Check whether a string is a valid IPv4 CIDR notation (e.g. "192.168.1.0/24").
fn is_valid_cidr(s: &str) -> bool {
    let Some((ip_str, len_str)) = s.split_once('/') else {
        return false;
    };
    if !is_valid_ipv4(ip_str) {
        return false;
    }
    let Ok(prefix_len) = len_str.parse::<u8>() else {
        return false;
    };
    prefix_len <= 32
}
