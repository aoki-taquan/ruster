use std::fmt;

use serde::{de, Deserialize, Deserializer};

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
    /// Selects the packet I/O implementation. An omitted value is the
    /// backwards-compatible AF_PACKET default.
    #[serde(default)]
    pub backend: Option<BackendV1>,
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

/// Versioned packet-I/O backend selection.
///
/// The AF_XDP fields intentionally mirror the checked native setup seams:
/// [`ruster_io_xdp_native::XdpResourceBuilder`], [`ruster_io_xdp_native::UmemConfig`],
/// [`ruster_io_xdp_native::RingConfig`], [`ruster_io_xdp_native::ValidatedBindFlags`],
/// [`ruster_io_xdp_native::XskMap`], and the XDP attach mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendV1 {
    /// Keep the existing AF_PACKET runtime behavior.
    AfPacket,
    /// Configure the two native AF_XDP queues used by the fixed LAN/WAN
    /// aggregate. The common cold-path geometry is applied to each resource.
    AfXdp {
        /// Exactly two declared interfaces and their hardware queues. Each
        /// entry becomes one independent `XdpResource` and one independent
        /// XSKMAP/program/attachment. Equal queue ids are therefore valid when
        /// they belong to different interfaces.
        resources: Vec<AfXdpResourceV1>,
        /// Maximum XSKMAP entries passed to `XskMap::new`.
        xskmap_max_entries: u32,
        /// Raw `sockaddr_xdp.sxdp_flags` checked by `ValidatedBindFlags::new`.
        bind_flags: u16,
        /// XDP execution mode selected for rtnetlink attachment.
        attach_mode: XdpAttachModeV1,
        /// UMEM geometry passed to `UmemConfig::new`.
        umem: XdpUmemV1,
        /// Four AF_XDP ring capacities passed to `RingConfig::new`.
        rings: XdpRingsV1,
    },
}

impl<'de> Deserialize<'de> for BackendV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // TOML's enum deserializer implements the externally tagged TOML
        // representation, while the public configuration deliberately uses a
        // stable `{ kind = ..., ... }` table. Decode that table as an ordinary
        // struct first, then enforce the variant-specific field set here.
        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case", deny_unknown_fields)]
        struct RawBackend {
            kind: BackendKind,
            #[serde(default)]
            resources: Option<Vec<AfXdpResourceV1>>,
            #[serde(default, rename = "xskmap-max-entries")]
            xskmap_max_entries: Option<u32>,
            #[serde(default, rename = "bind-flags")]
            bind_flags: Option<u16>,
            #[serde(default, rename = "attach-mode")]
            attach_mode: Option<XdpAttachModeV1>,
            #[serde(default)]
            umem: Option<XdpUmemV1>,
            #[serde(default)]
            rings: Option<XdpRingsV1>,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        enum BackendKind {
            AfPacket,
            AfXdp,
        }

        let raw = RawBackend::deserialize(deserializer)?;
        match raw.kind {
            BackendKind::AfPacket => {
                if raw.resources.is_some() {
                    return Err(de::Error::unknown_field("resources", &["kind"]));
                }
                if raw.xskmap_max_entries.is_some() {
                    return Err(de::Error::unknown_field("xskmap-max-entries", &["kind"]));
                }
                if raw.bind_flags.is_some() {
                    return Err(de::Error::unknown_field("bind-flags", &["kind"]));
                }
                if raw.attach_mode.is_some() {
                    return Err(de::Error::unknown_field("attach-mode", &["kind"]));
                }
                if raw.umem.is_some() {
                    return Err(de::Error::unknown_field("umem", &["kind"]));
                }
                if raw.rings.is_some() {
                    return Err(de::Error::unknown_field("rings", &["kind"]));
                }
                Ok(Self::AfPacket)
            }
            BackendKind::AfXdp => Ok(Self::AfXdp {
                resources: raw
                    .resources
                    .ok_or_else(|| de::Error::missing_field("resources"))?,
                xskmap_max_entries: raw
                    .xskmap_max_entries
                    .ok_or_else(|| de::Error::missing_field("xskmap-max-entries"))?,
                bind_flags: raw
                    .bind_flags
                    .ok_or_else(|| de::Error::missing_field("bind-flags"))?,
                attach_mode: raw
                    .attach_mode
                    .ok_or_else(|| de::Error::missing_field("attach-mode"))?,
                umem: raw.umem.ok_or_else(|| de::Error::missing_field("umem"))?,
                rings: raw.rings.ok_or_else(|| de::Error::missing_field("rings"))?,
            }),
        }
    }
}

/// One logical interface/queue in the fixed AF_XDP pair.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AfXdpResourceV1 {
    /// Name of a declared forwarding interface.
    pub interface: String,
    /// Hardware queue passed to `XdpResourceBuilder::new`.
    pub queue_id: u32,
}

/// Raw versioned UMEM parameters for the AF_XDP backend.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct XdpUmemV1 {
    pub frame_count: u32,
    pub frame_size: u32,
    pub headroom: u32,
    pub rx_frames: u32,
    pub generated_frames: u32,
    pub raw_flags: u32,
}

/// Raw versioned AF_XDP ring capacities.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct XdpRingsV1 {
    pub fill: u32,
    pub rx: u32,
    pub tx: u32,
    pub completion: u32,
}

/// Versioned spelling of the native XDP attach mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum XdpAttachModeV1 {
    Skb,
    Drv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct InterfaceV1 {
    pub id: u16,
    pub name: String,
    pub device: String,
    pub mac: String,
    /// The link MTU in bytes. Absent means the Ethernet default of 1500, so an
    /// existing configuration keeps the behaviour it had before MTU existed.
    pub mtu: Option<u16>,
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
    pub rx: u32,
    pub resolution_timer_scans: u32,
    pub failure_dispatch_scans: u32,
    pub generated_arp: u32,
    pub generated_icmpv4: u32,
}
