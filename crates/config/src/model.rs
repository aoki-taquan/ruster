use serde::{Deserialize, Serialize};

// ── Enums ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceRole {
    Wan,
    Lan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceZone {
    Wan,
    Lan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NatMode {
    Napt44,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortForwardProto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicy {
    Accept,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Input,
    Forward,
    Output,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Accept,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleProto {
    Any,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallZone {
    Wan,
    Lan,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnState {
    New,
    Established,
    Related,
}

// ── Structs ──

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetaConfig {
    pub schema: String,
    pub hostname: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataplaneConfig {
    pub backend: String,
    pub lcore_list: String,
    pub memory_mb: u32,
    pub rx_queue_size: u32,
    pub tx_queue_size: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceConfig {
    pub name: String,
    pub port_id: u16,
    pub role: InterfaceRole,
    pub admin_up: bool,
    pub mtu: u16,
    pub mac: String,
    pub ipv4_addrs: Vec<String>,
    pub zone: InterfaceZone,
    pub l2_domain: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeDomain {
    pub name: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L2Config {
    pub mac_table_max_entries: u32,
    pub mac_aging_sec: u32,
    pub arp_table_max_entries: u32,
    pub arp_timeout_sec: u32,
    pub bridge_domains: Vec<BridgeDomain>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticRoute {
    pub prefix: String,
    pub next_hop: String,
    pub out_if: String,
    pub metric: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    pub ipv4_static_routes: Vec<StaticRoute>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortForward {
    pub name: String,
    pub proto: PortForwardProto,
    pub external_port: u16,
    pub internal_addr: String,
    pub internal_port: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatConfig {
    pub enabled: bool,
    pub mode: NatMode,
    pub external_if: String,
    pub hairpin: bool,
    pub session_table_max_entries: u32,
    pub tcp_established_timeout_sec: u32,
    pub tcp_transitory_timeout_sec: u32,
    pub udp_timeout_sec: u32,
    pub icmp_timeout_sec: u32,
    pub port_forwards: Vec<PortForward>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRule {
    pub name: String,
    pub chain: Chain,
    pub action: RuleAction,
    pub proto: RuleProto,
    pub src_zone: FirewallZone,
    pub dst_zone: FirewallZone,
    pub state: Vec<ConnState>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallConfig {
    pub enabled: bool,
    pub default_input: DefaultPolicy,
    pub default_forward: DefaultPolicy,
    pub default_output: DefaultPolicy,
    pub allow_established_related: bool,
    pub rules: Vec<FirewallRule>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterConfig {
    pub meta: MetaConfig,
    pub dataplane: DataplaneConfig,
    pub interfaces: Vec<InterfaceConfig>,
    pub l2: L2Config,
    pub routing: RoutingConfig,
    pub nat: NatConfig,
    pub firewall: FirewallConfig,
}
