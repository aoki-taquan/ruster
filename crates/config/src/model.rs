use std::fmt;

use serde::Deserialize;

/// A parsed configuration selected by its explicit schema version.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VersionedConfig {
    V1(ConfigV1),
}

/// Exact schema version 1 syntax.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConfigV1 {
    pub schema_version: u32,
    #[serde(default)]
    pub interfaces: Vec<InterfaceV1>,
    #[serde(default)]
    pub addresses: Vec<AddressV1>,
    #[serde(default)]
    pub routes: Vec<RouteV1>,
    #[serde(default)]
    pub neighbors: Vec<NeighborV1>,
    pub ipv4_origin: Option<Ipv4OriginV1>,
    pub resolution: Option<ResolutionV1>,
    pub icmpv4_errors: Option<Icmpv4ErrorV1>,
    pub nat44: Option<Nat44V1>,
    pub firewall: Option<FirewallV1>,
    pub tick: Option<TickBudgetV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct InterfaceV1 {
    pub id: u16,
    pub name: String,
    pub device: String,
    pub mac: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AddressV1 {
    pub interface: String,
    pub ipv4: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RouteV1 {
    pub prefix: String,
    pub egress: String,
    pub via: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NeighborV1 {
    pub interface: String,
    pub address: String,
    pub mac: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Ipv4OriginV1 {
    pub default_ttl: u8,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ResolutionPolicyV1 {
    pub interval_ms: u64,
    pub state_ttl_ms: u64,
    pub dynamic_neighbor_ttl_ms: u64,
    pub max_attempts: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ResolutionCapacityV1 {
    pub states: u32,
    pub actions: u32,
    pub dynamic_neighbors: u32,
    pub failure_holds: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ResolutionV1 {
    pub policy: ResolutionPolicyV1,
    pub capacity: ResolutionCapacityV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Icmpv4ErrorPolicyV1 {
    pub interval_ms: u64,
    pub state_ttl_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Icmpv4ErrorCapacityV1 {
    pub states: u32,
    pub actions: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Icmpv4ErrorV1 {
    pub policy: Icmpv4ErrorPolicyV1,
    pub capacity: Icmpv4ErrorCapacityV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44V1 {
    pub realm: Nat44RealmV1,
    pub udp: Option<Nat44UdpV1>,
    pub tcp: Option<Nat44TcpV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44RealmV1 {
    pub inside: String,
    pub outside: String,
    pub public_address: String,
    pub ports: Nat44PortRangeV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44PortRangeV1 {
    pub first: u16,
    pub last: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Nat44Icmpv4ErrorsV1 {
    Disabled,
    ExternalOnly,
}

/// Raw textual NAT allocator seed with redacted formatting.
///
/// TOML integers are signed 64-bit values, so V1 uses text to preserve the
/// complete future `u64` input domain. Semantic parsing is a later stage.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(transparent)]
pub struct AllocatorSeedV1(String);

impl AllocatorSeedV1 {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AllocatorSeedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AllocatorSeedV1([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44UdpV1 {
    pub idle_ttl_ms: u64,
    pub allocator_seed: AllocatorSeedV1,
    pub icmpv4_errors: Nat44Icmpv4ErrorsV1,
    pub capacity: Nat44UdpCapacityV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44UdpCapacityV1 {
    pub mappings: u32,
    pub peers: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44TcpV1 {
    pub idle_ttl_ms: u64,
    pub allocator_seed: AllocatorSeedV1,
    pub icmpv4_errors: Nat44Icmpv4ErrorsV1,
    pub capacity: Nat44TcpCapacityV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Nat44TcpCapacityV1 {
    pub mappings: u32,
    pub sessions: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FirewallV1 {
    pub policy: FirewallPolicyV1,
    pub capacity: FirewallCapacityV1,
    #[serde(default)]
    pub rules: Vec<FirewallRuleV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FirewallPolicyV1 {
    pub udp_idle_ttl_ms: u64,
    pub tcp_opening_idle_ttl_ms: u64,
    pub tcp_active_idle_ttl_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FirewallCapacityV1 {
    pub states: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FirewallRuleV1 {
    pub id: u32,
    pub ingress: Option<String>,
    pub egress: Option<String>,
    pub source: String,
    pub destination: String,
    pub protocol: FirewallProtocolV1,
    pub source_ports: Nat44PortRangeV1,
    pub destination_ports: Nat44PortRangeV1,
    pub action: FirewallActionV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallProtocolV1 {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallActionV1 {
    AllowStateful,
    Deny,
}

/// Per-phase worker limits. Values are syntax only until runtime validation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TickBudgetV1 {
    pub rx_packets: u32,
    pub resolution_timers: u32,
    pub icmpv4_error_timers: u32,
    pub nat44_udp_cleanup: u32,
    pub nat44_tcp_cleanup: u32,
    pub firewall_cleanup: u32,
    pub generated_packets: u32,
}
