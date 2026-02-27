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
    #[serde(default)]
    pub ipv6_addrs: Vec<String>,
    pub zone: InterfaceZone,
    pub l2_domain: String,
    #[serde(default)]
    pub linux_if: Option<String>,
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
    /// Maximum number of packets held per unresolved next-hop IP in the
    /// ARP hold queue.  Packets beyond this limit are tail-dropped.
    #[serde(default = "default_arp_hold_queue_per_ip")]
    pub arp_hold_queue_per_ip: u32,
    /// Global maximum number of packets across all unresolved next-hops
    /// in the ARP hold queue.  Packets beyond this limit are tail-dropped.
    #[serde(default = "default_arp_hold_queue_max")]
    pub arp_hold_queue_max: u32,
    pub bridge_domains: Vec<BridgeDomain>,
}

fn default_arp_hold_queue_per_ip() -> u32 {
    3
}

fn default_arp_hold_queue_max() -> u32 {
    1024
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
pub struct Ipv6StaticRoute {
    pub prefix: String,
    pub next_hop: String,
    pub out_if: String,
    pub metric: u32,
}

/// BGP peer configuration for a single eBGP neighbor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpPeerConfig {
    /// Peer IPv4 address.
    pub address: String,
    /// Remote autonomous system number.
    pub remote_as: u32,
    /// Hold time in seconds (default: 90).
    #[serde(default = "default_bgp_hold_time")]
    pub hold_time: u16,
}

fn default_bgp_hold_time() -> u16 {
    90
}

/// BGP configuration section.
///
/// RFC-REF: RFC 4271 Section 3
/// "A BGP speaker may be configured with a set of policies [...] and a
/// set of networks that it can reach directly."
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpConfig {
    /// Local autonomous system number.
    pub local_as: u32,
    /// BGP router ID in dotted-decimal notation (e.g. "10.0.0.1").
    pub router_id: String,
    /// List of eBGP peers.
    #[serde(default)]
    pub peers: Vec<BgpPeerConfig>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    pub ipv4_static_routes: Vec<StaticRoute>,
    #[serde(default)]
    pub ipv6_static_routes: Vec<Ipv6StaticRoute>,
    /// OSPFv2 configuration (optional).
    #[serde(default)]
    pub ospf: Option<OspfRoutingConfig>,
    /// Optional BGP configuration.
    #[serde(default)]
    pub bgp: Option<BgpConfig>,
}

/// OSPFv2 routing configuration.
///
/// ```toml
/// [routing.ospf]
/// router_id = "10.0.0.1"
/// [[routing.ospf.areas]]
/// id = "0.0.0.0"
/// interfaces = ["eth0"]
/// hello_interval = 10
/// dead_interval = 40
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OspfRoutingConfig {
    /// Router ID in dotted-decimal form.
    pub router_id: String,
    /// OSPF area configurations.
    pub areas: Vec<OspfAreaConfig>,
}

/// OSPF area configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OspfAreaConfig {
    /// Area ID in dotted-decimal form (e.g. "0.0.0.0" for backbone).
    pub id: String,
    /// Interface names participating in this area.
    pub interfaces: Vec<String>,
    /// Hello interval in seconds (default: 10).
    #[serde(default = "default_hello_interval")]
    pub hello_interval: u16,
    /// Router dead interval in seconds (default: 40).
    #[serde(default = "default_dead_interval")]
    pub dead_interval: u16,
}

fn default_hello_interval() -> u16 {
    10
}

fn default_dead_interval() -> u16 {
    40
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

/// SRv6 local SID configuration entry.
///
/// RFC-REF: RFC 8986 Section 4
/// Defines a local SID and its associated action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Srv6LocalSid {
    /// SID address (e.g., "fd00:1::"), optionally with prefix (e.g., "fd00::/32").
    pub sid: String,
    /// Action name: "end", "end_dt4", "end_dt6", "un".
    pub action: String,
    /// Optional VRF table name for decap actions.
    #[serde(default)]
    pub table: Option<String>,
}

/// SRv6 configuration section.
///
/// RFC-REF: RFC 8986 (SRv6 Network Programming)
/// RFC-REF: RFC 8754 (IPv6 Segment Routing Header)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Srv6Config {
    /// Locator block prefix (e.g., "fd00::").
    pub locator_block: String,
    /// Block prefix length in bits (default: 32).
    #[serde(default = "default_srv6_block_len")]
    pub block_len: u8,
    /// uSID length in bits (default: 16).
    #[serde(default = "default_srv6_usid_len")]
    pub usid_len: u8,
    /// Local SID entries.
    #[serde(default)]
    pub local_sids: Vec<Srv6LocalSid>,
}

fn default_srv6_block_len() -> u8 {
    32
}

fn default_srv6_usid_len() -> u8 {
    16
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
    /// SRv6 configuration (optional).
    #[serde(default)]
    pub srv6: Option<Srv6Config>,
}
