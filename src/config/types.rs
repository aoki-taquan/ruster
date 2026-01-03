//! Configuration types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// User-defined configuration (config.toml)
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub interfaces: HashMap<String, InterfaceConfig>,
    #[serde(default)]
    pub dhcp: HashMap<String, DhcpConfig>,
    #[serde(default)]
    pub nat: Option<NatConfig>,
    #[serde(default)]
    pub routing: RoutingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InterfaceConfig {
    pub role: InterfaceRole,
    #[serde(default)]
    pub addressing: Addressing,
    pub address: Option<String>,
    pub mtu: Option<u16>,
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct StaticRoute {
    pub destination: String,
    pub gateway: String,
    #[serde(default)]
    pub interface: Option<String>,
}

// ============================================================================
// Lock file types (generated, includes all defaults)
// ============================================================================

/// Generated lock file with all defaults filled in
#[derive(Debug, Clone, Serialize)]
pub struct ConfigLock {
    pub generated_at: String,
    pub source_hash: String,
    pub interfaces: HashMap<String, InterfaceLock>,
    pub dhcp: HashMap<String, DhcpLock>,
    pub nat: Option<NatLock>,
    pub routing: RoutingLock,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceLock {
    pub role: String,
    pub addressing: String,
    pub address: Option<String>,
    pub mtu: u16,
    pub mac: String,
    pub duplex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DhcpLock {
    pub interface: String,
    pub range: (Ipv4Addr, Ipv4Addr),
    pub gateway: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub lease_time: u32,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NatLock {
    pub enabled: bool,
    pub wan: String,
    pub lan: Vec<String>,
    pub nat_type: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RoutingLock {
    pub static_routes: Vec<StaticRouteLock>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StaticRouteLock {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub source: String,
}

impl ConfigLock {
    pub fn from_config(config: &Config) -> Self {
        let interfaces = config
            .interfaces
            .iter()
            .map(|(name, iface)| {
                (
                    name.clone(),
                    InterfaceLock {
                        role: format!("{:?}", iface.role).to_lowercase(),
                        addressing: format!("{:?}", iface.addressing).to_lowercase(),
                        address: iface.address.clone(),
                        mtu: iface.mtu.unwrap_or(1500),
                        mac: "auto".to_string(),
                        duplex: "auto".to_string(),
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

        ConfigLock {
            generated_at: chrono::Utc::now().to_rfc3339(),
            source_hash: "TODO".to_string(),
            interfaces,
            dhcp,
            nat,
            routing: RoutingLock::default(),
        }
    }
}
