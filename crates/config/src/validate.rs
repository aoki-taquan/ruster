use std::{fmt, mem::size_of, net::Ipv4Addr, num::ParseIntError};

use ruster_core::{
    validate_firewall_rules, DirectoryBucket, DirectoryNode, DynamicNeighborSlot, FirewallAction,
    FirewallConfigError, FirewallInterface, FirewallIpv4Prefix, FirewallIpv4PrefixError,
    FirewallPolicy, FirewallPolicyError, FirewallPortRange, FirewallPortRangeError,
    FirewallProtocol, FirewallRule, FirewallRuleId, FirewallStateSlot, ForwardingSnapshot,
    Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy, Icmpv4ErrorPolicyError, Icmpv4ErrorStateSlot, IfId,
    Interface, Ipv4Address, Ipv4OriginPolicy, Ipv4OriginPolicyError, LocalIpv4Binding, MacAddress,
    Nat44Icmpv4ErrorPolicy, Nat44TcpConfig, Nat44TcpConfigError, Nat44TcpMappingSlot,
    Nat44TcpPolicy, Nat44TcpPolicyError, Nat44TcpSessionSlot, Nat44UdpConfig, Nat44UdpConfigError,
    Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpPolicyError, Neighbor,
    PortOwnerSlot, ResolutionActionSlot, ResolutionFailureHoldSlot, ResolutionPolicy,
    ResolutionPolicyError, ResolutionStateSlot, Route, RouteError, SnapshotError,
};

use crate::{
    ConfigV1, FirewallActionV1, FirewallProtocolV1, Nat44Icmpv4ErrorsV1, SourcePath,
    VersionedConfig,
};

/// Caller-selected cold-path bounds for runtime storage requested by V1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationLimits {
    pub max_slots_per_table: u32,
    pub max_runtime_bytes: usize,
}

/// Stable, value-free semantic rejection reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValidationCode {
    InvalidSchemaVersion,
    ListTooLong,
    TextTooLarge,
    EmptyInterfaceName,
    EmptyDeviceName,
    DuplicateInterfaceId,
    DuplicateInterfaceName,
    DuplicateDeviceName,
    InvalidMac,
    NonCanonicalMac,
    MacNotUnicast,
    InvalidIpv4,
    NonCanonicalIpv4,
    InvalidIpv4Prefix,
    NonCanonicalIpv4Prefix,
    AddressNotHost,
    UnknownInterface,
    DuplicateLocalAddress,
    DuplicateInterfaceAddress,
    Route(RouteError),
    DuplicateRoute,
    GatewayNotHost,
    GatewayNotOnLink,
    DuplicateNeighbor,
    NeighborNotHost,
    NeighborNotOnLink,
    Forwarding(SnapshotError),
    Ipv4Origin(Ipv4OriginPolicyError),
    ResolutionPolicy(ResolutionPolicyError),
    Icmpv4ErrorPolicy(Icmpv4ErrorPolicyError),
    InvalidAllocatorSeed,
    NonCanonicalAllocatorSeed,
    Nat44RealmWithoutProtocol,
    Nat44UdpPolicy(Nat44UdpPolicyError),
    Nat44UdpConfig(Nat44UdpConfigError),
    Nat44TcpPolicy(Nat44TcpPolicyError),
    Nat44TcpConfig(Nat44TcpConfigError),
    FirewallPrefix(FirewallIpv4PrefixError),
    FirewallPortRange(FirewallPortRangeError),
    FirewallPolicy(FirewallPolicyError),
    FirewallRules(FirewallConfigError),
    CapacityLimitExceeded,
    CapacityNotRepresentable,
    CapacityArithmeticOverflow,
    RuntimeStorageBytesExceeded,
}

/// A semantic error that never retains source values.
#[derive(Clone, Eq, PartialEq)]
pub struct ValidationError {
    code: ValidationCode,
    path: SourcePath,
    limit: Option<u64>,
    actual: Option<u64>,
}

impl ValidationError {
    fn new(code: ValidationCode, path: SourcePath) -> Self {
        Self {
            code,
            path,
            limit: None,
            actual: None,
        }
    }

    fn bounded(code: ValidationCode, path: SourcePath, limit: u64, actual: u64) -> Self {
        Self {
            code,
            path,
            limit: Some(limit),
            actual: Some(actual),
        }
    }

    #[must_use]
    pub const fn code(&self) -> ValidationCode {
        self.code
    }

    #[must_use]
    pub const fn path(&self) -> &SourcePath {
        &self.path
    }

    #[must_use]
    pub const fn limit(&self) -> Option<u64> {
        self.limit
    }

    #[must_use]
    pub const fn actual(&self) -> Option<u64> {
        self.actual
    }
}

impl fmt::Debug for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidationError")
            .field("code", &self.code)
            .field("path", &self.path)
            .field("limit", &self.limit)
            .field("actual", &self.actual)
            .finish()
    }
}

/// Canonical control-plane identity for one forwarding interface.
#[derive(Clone, Eq, PartialEq)]
pub struct InterfaceBindingV1 {
    id: IfId,
    name: Box<str>,
    device: Box<str>,
    mac: MacAddress,
}

impl InterfaceBindingV1 {
    #[must_use]
    pub const fn id(&self) -> IfId {
        self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn device(&self) -> &str {
        &self.device
    }

    #[must_use]
    pub const fn mac(&self) -> MacAddress {
        self.mac
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionStorageShapeV1 {
    pub states: u32,
    pub actions: u32,
    pub dynamic_neighbors: u32,
    pub failure_holds: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Icmpv4ErrorStorageShapeV1 {
    pub states: u32,
    pub actions: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Nat44UdpStorageShapeV1 {
    pub mappings: u32,
    pub peers: u32,
    pub mapping_buckets: u32,
    pub mapping_nodes: u32,
    pub peer_buckets: u32,
    pub peer_nodes: u32,
    pub port_owners: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Nat44TcpStorageShapeV1 {
    pub mappings: u32,
    pub sessions: u32,
    pub mapping_buckets: u32,
    pub mapping_nodes: u32,
    pub session_buckets: u32,
    pub session_nodes: u32,
    pub port_owners: u32,
}

/// Complete caller-owned runtime storage requested by one V1 candidate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeStorageShapeV1 {
    pub resolution: Option<ResolutionStorageShapeV1>,
    pub icmpv4_errors: Option<Icmpv4ErrorStorageShapeV1>,
    pub nat44_udp: Option<Nat44UdpStorageShapeV1>,
    pub nat44_tcp: Option<Nat44TcpStorageShapeV1>,
    pub firewall_states: Option<u32>,
    pub required_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TickBudgetsV1 {
    pub rx: u32,
    pub resolution_timer_scans: u32,
    pub failure_dispatch_scans: u32,
    pub generated_arp: u32,
    pub generated_icmpv4: u32,
}

pub struct ValidatedResolutionV1 {
    policy: ResolutionPolicy,
    storage: ResolutionStorageShapeV1,
}

impl ValidatedResolutionV1 {
    #[must_use]
    pub const fn policy(&self) -> ResolutionPolicy {
        self.policy
    }

    #[must_use]
    pub const fn storage(&self) -> ResolutionStorageShapeV1 {
        self.storage
    }
}

pub struct ValidatedIcmpv4ErrorV1 {
    policy: Icmpv4ErrorPolicy,
    storage: Icmpv4ErrorStorageShapeV1,
}

impl ValidatedIcmpv4ErrorV1 {
    #[must_use]
    pub const fn policy(&self) -> Icmpv4ErrorPolicy {
        self.policy
    }

    #[must_use]
    pub const fn storage(&self) -> Icmpv4ErrorStorageShapeV1 {
        self.storage
    }
}

pub struct ValidatedNat44UdpV1 {
    inside: IfId,
    outside: IfId,
    public_address: Ipv4Address,
    first_port: u16,
    last_port: u16,
    policy: Nat44UdpPolicy,
    storage: Nat44UdpStorageShapeV1,
}

impl ValidatedNat44UdpV1 {
    #[must_use]
    pub const fn inside(&self) -> IfId {
        self.inside
    }

    #[must_use]
    pub const fn outside(&self) -> IfId {
        self.outside
    }

    #[must_use]
    pub const fn public_address(&self) -> Ipv4Address {
        self.public_address
    }

    #[must_use]
    pub const fn first_port(&self) -> u16 {
        self.first_port
    }

    #[must_use]
    pub const fn last_port(&self) -> u16 {
        self.last_port
    }

    #[must_use]
    pub const fn policy(&self) -> Nat44UdpPolicy {
        self.policy
    }

    #[must_use]
    pub const fn storage(&self) -> Nat44UdpStorageShapeV1 {
        self.storage
    }
}

pub struct ValidatedNat44TcpV1 {
    inside: IfId,
    outside: IfId,
    public_address: Ipv4Address,
    first_port: u16,
    last_port: u16,
    policy: Nat44TcpPolicy,
    storage: Nat44TcpStorageShapeV1,
}

impl ValidatedNat44TcpV1 {
    #[must_use]
    pub const fn inside(&self) -> IfId {
        self.inside
    }

    #[must_use]
    pub const fn outside(&self) -> IfId {
        self.outside
    }

    #[must_use]
    pub const fn public_address(&self) -> Ipv4Address {
        self.public_address
    }

    #[must_use]
    pub const fn first_port(&self) -> u16 {
        self.first_port
    }

    #[must_use]
    pub const fn last_port(&self) -> u16 {
        self.last_port
    }

    #[must_use]
    pub const fn policy(&self) -> Nat44TcpPolicy {
        self.policy
    }

    #[must_use]
    pub const fn storage(&self) -> Nat44TcpStorageShapeV1 {
        self.storage
    }
}

pub struct ValidatedNat44V1 {
    udp: Option<ValidatedNat44UdpV1>,
    tcp: Option<ValidatedNat44TcpV1>,
}

impl ValidatedNat44V1 {
    #[must_use]
    pub const fn udp(&self) -> Option<&ValidatedNat44UdpV1> {
        self.udp.as_ref()
    }

    #[must_use]
    pub const fn tcp(&self) -> Option<&ValidatedNat44TcpV1> {
        self.tcp.as_ref()
    }
}

pub struct ValidatedFirewallV1 {
    rules: Box<[FirewallRule]>,
    policy: FirewallPolicy,
    state_slots: u32,
}

impl ValidatedFirewallV1 {
    #[must_use]
    pub fn rules(&self) -> &[FirewallRule] {
        &self.rules
    }

    #[must_use]
    pub const fn policy(&self) -> FirewallPolicy {
        self.policy
    }

    #[must_use]
    pub const fn state_slots(&self) -> u32 {
        self.state_slots
    }
}

/// Owned, canonical, semantically validated schema V1.
///
/// This type deliberately has no `Debug` implementation because it owns
/// topology and configured NAT allocator seeds. Callers choose individual
/// accessors when emitting operational telemetry.
///
/// ```compile_fail
/// use ruster_config::ValidatedConfigV1;
///
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<ValidatedConfigV1>();
/// ```
pub struct ValidatedConfigV1 {
    interfaces: Box<[InterfaceBindingV1]>,
    core_interfaces: Box<[Interface]>,
    routes: Box<[Route]>,
    neighbors: Box<[Neighbor]>,
    local_ipv4: Box<[LocalIpv4Binding]>,
    ipv4_origin: Ipv4OriginPolicy,
    resolution: Option<ValidatedResolutionV1>,
    icmpv4_errors: Option<ValidatedIcmpv4ErrorV1>,
    nat44: Option<ValidatedNat44V1>,
    firewall: Option<ValidatedFirewallV1>,
    tick: TickBudgetsV1,
    storage: RuntimeStorageShapeV1,
}

impl ValidatedConfigV1 {
    #[must_use]
    pub fn interfaces(&self) -> &[InterfaceBindingV1] {
        &self.interfaces
    }

    #[must_use]
    pub fn core_interfaces(&self) -> &[Interface] {
        &self.core_interfaces
    }

    #[must_use]
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    #[must_use]
    pub fn neighbors(&self) -> &[Neighbor] {
        &self.neighbors
    }

    #[must_use]
    pub fn local_ipv4(&self) -> &[LocalIpv4Binding] {
        &self.local_ipv4
    }

    #[must_use]
    pub const fn ipv4_origin(&self) -> Ipv4OriginPolicy {
        self.ipv4_origin
    }

    #[must_use]
    pub const fn resolution(&self) -> Option<&ValidatedResolutionV1> {
        self.resolution.as_ref()
    }

    #[must_use]
    pub const fn icmpv4_errors(&self) -> Option<&ValidatedIcmpv4ErrorV1> {
        self.icmpv4_errors.as_ref()
    }

    #[must_use]
    pub const fn nat44(&self) -> Option<&ValidatedNat44V1> {
        self.nat44.as_ref()
    }

    #[must_use]
    pub const fn firewall(&self) -> Option<&ValidatedFirewallV1> {
        self.firewall.as_ref()
    }

    #[must_use]
    pub const fn tick(&self) -> TickBudgetsV1 {
        self.tick
    }

    #[must_use]
    pub const fn storage_shape(&self) -> RuntimeStorageShapeV1 {
        self.storage
    }
}

#[non_exhaustive]
pub enum ValidatedConfig {
    V1(ValidatedConfigV1),
}

/// Validates and canonicalizes parsed configuration without touching runtime
/// state, a packet backend, a random source, or publication generation.
pub fn validate(
    parsed: VersionedConfig,
    limits: ValidationLimits,
) -> Result<ValidatedConfig, ValidationError> {
    match parsed {
        VersionedConfig::V1(config) => validate_v1(config, limits).map(ValidatedConfig::V1),
    }
}

#[derive(Clone, Copy)]
struct ParsedCidr {
    address: Ipv4Address,
    prefix_len: u8,
}

#[derive(Clone)]
struct InterfaceRecord {
    binding: InterfaceBindingV1,
    core: Interface,
}

#[derive(Clone)]
struct ConnectedRoute {
    route: Route,
    source_path: SourcePath,
}

#[derive(Clone)]
struct RoutedValue {
    route: Route,
    source_path: SourcePath,
}

fn validate_v1(
    config: ConfigV1,
    limits: ValidationLimits,
) -> Result<ValidatedConfigV1, ValidationError> {
    if config.schema_version != crate::SCHEMA_VERSION_V1 {
        return Err(ValidationError::new(
            ValidationCode::InvalidSchemaVersion,
            path(&["schema-version"]),
        ));
    }
    preflight_public_dto(&config)?;
    let mut interface_records = Vec::with_capacity(config.interfaces.len());
    for (index, source) in config.interfaces.into_iter().enumerate() {
        let base = indexed_path("interfaces", index);
        if source.name.is_empty() {
            return Err(ValidationError::new(
                ValidationCode::EmptyInterfaceName,
                child_path(&base, "name"),
            ));
        }
        if source.device.is_empty() {
            return Err(ValidationError::new(
                ValidationCode::EmptyDeviceName,
                child_path(&base, "device"),
            ));
        }
        if interface_records
            .iter()
            .any(|record: &InterfaceRecord| record.binding.id == IfId(source.id))
        {
            return Err(ValidationError::new(
                ValidationCode::DuplicateInterfaceId,
                child_path(&base, "id"),
            ));
        }
        if interface_records
            .iter()
            .any(|record| record.binding.name.as_ref() == source.name)
        {
            return Err(ValidationError::new(
                ValidationCode::DuplicateInterfaceName,
                child_path(&base, "name"),
            ));
        }
        if interface_records
            .iter()
            .any(|record| record.binding.device.as_ref() == source.device)
        {
            return Err(ValidationError::new(
                ValidationCode::DuplicateDeviceName,
                child_path(&base, "device"),
            ));
        }
        let mac = parse_mac(&source.mac, child_path(&base, "mac"))?;
        let binding = InterfaceBindingV1 {
            id: IfId(source.id),
            name: source.name.into_boxed_str(),
            device: source.device.into_boxed_str(),
            mac,
        };
        interface_records.push(InterfaceRecord {
            core: Interface {
                id: binding.id,
                mac,
            },
            binding,
        });
    }

    let interface_names = interface_records
        .iter()
        .map(|record| (record.binding.name.clone(), record.binding.id))
        .collect::<Vec<_>>();
    let find_interface = |name: &str| {
        interface_names
            .iter()
            .find(|(candidate, _)| candidate.as_ref() == name)
            .map(|(_, id)| *id)
    };

    let mut local_ipv4_with_paths = Vec::with_capacity(config.addresses.len());
    let mut connected = Vec::with_capacity(config.addresses.len());
    for (index, source) in config.addresses.into_iter().enumerate() {
        let base = indexed_path("addresses", index);
        let interface = find_interface(&source.interface).ok_or_else(|| {
            ValidationError::new(
                ValidationCode::UnknownInterface,
                child_path(&base, "interface"),
            )
        })?;
        let cidr = parse_cidr(&source.ipv4, child_path(&base, "ipv4"))?;
        if !is_host_for_prefix(cidr.address, cidr.prefix_len) {
            return Err(ValidationError::new(
                ValidationCode::AddressNotHost,
                child_path(&base, "ipv4"),
            ));
        }
        if local_ipv4_with_paths
            .iter()
            .any(|(binding, _): &(LocalIpv4Binding, SourcePath)| binding.interface == interface)
        {
            return Err(ValidationError::new(
                ValidationCode::DuplicateInterfaceAddress,
                child_path(&base, "interface"),
            ));
        }
        if local_ipv4_with_paths
            .iter()
            .any(|(binding, _)| binding.address == cidr.address)
        {
            return Err(ValidationError::new(
                ValidationCode::DuplicateLocalAddress,
                child_path(&base, "ipv4"),
            ));
        }
        let binding = LocalIpv4Binding {
            interface,
            address: cidr.address,
        };
        local_ipv4_with_paths.push((binding, base.clone()));
        let network = network_address(cidr.address, cidr.prefix_len);
        let route = Route::new(network, cidr.prefix_len, interface, None).map_err(|error| {
            ValidationError::new(ValidationCode::Route(error), child_path(&base, "ipv4"))
        })?;
        connected.push(ConnectedRoute {
            route,
            source_path: child_path(&base, "ipv4"),
        });
    }

    let mut routed: Vec<RoutedValue> = connected
        .iter()
        .map(|entry| RoutedValue {
            route: entry.route,
            source_path: entry.source_path.clone(),
        })
        .collect();
    for (index, source) in config.routes.into_iter().enumerate() {
        let base = indexed_path("routes", index);
        let egress = find_interface(&source.egress).ok_or_else(|| {
            ValidationError::new(
                ValidationCode::UnknownInterface,
                child_path(&base, "egress"),
            )
        })?;
        let cidr = parse_cidr(&source.prefix, child_path(&base, "prefix"))?;
        let next_hop = source
            .via
            .as_deref()
            .map(|value| parse_ipv4(value, child_path(&base, "via")))
            .transpose()?;
        if let Some(gateway) = next_hop {
            if !is_basic_host(gateway) {
                return Err(ValidationError::new(
                    ValidationCode::GatewayNotHost,
                    child_path(&base, "via"),
                ));
            }
            if !connected
                .iter()
                .any(|entry| route_host_matches(entry.route, gateway))
            {
                return Err(ValidationError::new(
                    ValidationCode::GatewayNotOnLink,
                    child_path(&base, "via"),
                ));
            }
            if !connected.iter().any(|entry| {
                entry.route.egress() == egress && route_host_matches(entry.route, gateway)
            }) {
                return Err(ValidationError::new(
                    ValidationCode::GatewayNotOnLink,
                    child_path(&base, "via"),
                ));
            }
        }
        let route =
            Route::new(cidr.address, cidr.prefix_len, egress, next_hop).map_err(|error| {
                ValidationError::new(ValidationCode::Route(error), child_path(&base, "prefix"))
            })?;
        routed.push(RoutedValue {
            route,
            source_path: child_path(&base, "prefix"),
        });
    }
    routed.sort_by_key(|entry| route_sort_key(entry.route));
    for pair in routed.windows(2) {
        if route_prefix_key(pair[0].route) == route_prefix_key(pair[1].route) {
            return Err(ValidationError::new(
                ValidationCode::DuplicateRoute,
                pair[1].source_path.clone(),
            ));
        }
    }

    let mut neighbors_with_paths = Vec::with_capacity(config.neighbors.len());
    for (index, source) in config.neighbors.into_iter().enumerate() {
        let base = indexed_path("neighbors", index);
        let interface = find_interface(&source.interface).ok_or_else(|| {
            ValidationError::new(
                ValidationCode::UnknownInterface,
                child_path(&base, "interface"),
            )
        })?;
        let address = parse_ipv4(&source.address, child_path(&base, "address"))?;
        if !is_basic_host(address) {
            return Err(ValidationError::new(
                ValidationCode::NeighborNotHost,
                child_path(&base, "address"),
            ));
        }
        if !connected.iter().any(|entry| {
            entry.route.egress() == interface && route_host_matches(entry.route, address)
        }) {
            return Err(ValidationError::new(
                ValidationCode::NeighborNotOnLink,
                child_path(&base, "address"),
            ));
        }
        let mac = parse_mac(&source.mac, child_path(&base, "mac"))?;
        if neighbors_with_paths
            .iter()
            .any(|(neighbor, _): &(Neighbor, SourcePath)| {
                neighbor.interface == interface && neighbor.target == address
            })
        {
            return Err(ValidationError::new(
                ValidationCode::DuplicateNeighbor,
                child_path(&base, "address"),
            ));
        }
        neighbors_with_paths.push((
            Neighbor {
                interface,
                target: address,
                mac,
            },
            base,
        ));
    }

    let ipv4_origin = match config.ipv4_origin {
        Some(source) => Ipv4OriginPolicy::new(source.default_ttl).map_err(|error| {
            ValidationError::new(
                ValidationCode::Ipv4Origin(error),
                path(&["ipv4-origin", "default-ttl"]),
            )
        })?,
        None => Ipv4OriginPolicy::default(),
    };

    interface_records.sort_by_key(|record| record.binding.id);
    local_ipv4_with_paths.sort_by_key(|(binding, _)| binding.interface);
    neighbors_with_paths.sort_by_key(|(neighbor, _)| {
        (
            neighbor.interface,
            u32::from_be_bytes(neighbor.target.octets()),
        )
    });
    let interfaces: Box<[InterfaceBindingV1]> = interface_records
        .iter()
        .map(|record| record.binding.clone())
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let core_interfaces = interface_records
        .into_iter()
        .map(|record| record.core)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let routes = routed
        .into_iter()
        .map(|entry| entry.route)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let local_ipv4 = local_ipv4_with_paths
        .into_iter()
        .map(|(binding, _)| binding)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let neighbors = neighbors_with_paths
        .into_iter()
        .map(|(neighbor, _)| neighbor)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let snapshot = ForwardingSnapshot::with_ipv4_origin_policy(
        &routes,
        &core_interfaces,
        &neighbors,
        &local_ipv4,
        ipv4_origin,
    )
    .map_err(|error| {
        ValidationError::new(ValidationCode::Forwarding(error), SourcePath::default())
    })?;

    let resolution_source = config.resolution;
    let resolution_policy = resolution_source
        .map(|source| {
            ResolutionPolicy::with_retry_and_dynamic_neighbor_ttl(
                source.policy.interval_ms,
                source.policy.state_ttl_ms,
                source.policy.max_attempts,
                source.policy.dynamic_neighbor_ttl_ms,
            )
            .map_err(|error| {
                ValidationError::new(
                    ValidationCode::ResolutionPolicy(error),
                    path(&["resolution", "policy"]),
                )
            })
        })
        .transpose()?;

    let icmp_source = config.icmpv4_errors;
    let icmp_policy = icmp_source
        .map(|source| {
            Icmpv4ErrorPolicy::new(source.policy.interval_ms, source.policy.state_ttl_ms).map_err(
                |error| {
                    ValidationError::new(
                        ValidationCode::Icmpv4ErrorPolicy(error),
                        path(&["icmpv4-errors", "policy"]),
                    )
                },
            )
        })
        .transpose()?;

    let nat_source = config.nat44;
    let mut validated_udp = None;
    let mut validated_tcp = None;
    let mut udp_capacity = None;
    let mut tcp_capacity = None;
    if let Some(nat) = nat_source {
        if nat.udp.is_none() && nat.tcp.is_none() {
            return Err(ValidationError::new(
                ValidationCode::Nat44RealmWithoutProtocol,
                path(&["nat44"]),
            ));
        }
        let inside = find_interface(&nat.realm.inside).ok_or_else(|| {
            ValidationError::new(
                ValidationCode::UnknownInterface,
                path(&["nat44", "realm", "inside"]),
            )
        })?;
        let outside = find_interface(&nat.realm.outside).ok_or_else(|| {
            ValidationError::new(
                ValidationCode::UnknownInterface,
                path(&["nat44", "realm", "outside"]),
            )
        })?;
        let public_address = parse_ipv4(
            &nat.realm.public_address,
            path(&["nat44", "realm", "public-address"]),
        )?;
        if let Some(source) = nat.udp {
            let seed = parse_seed(
                source.allocator_seed.expose(),
                path(&["nat44", "udp", "allocator-seed"]),
            )?;
            let policy = Nat44UdpPolicy::new(source.idle_ttl_ms, seed)
                .map_err(|error| {
                    ValidationError::new(
                        ValidationCode::Nat44UdpPolicy(error),
                        path(&["nat44", "udp", "idle-ttl-ms"]),
                    )
                })?
                .with_icmpv4_errors(map_icmp_policy(source.icmpv4_errors));
            Nat44UdpConfig::new(
                &snapshot,
                inside,
                outside,
                public_address,
                nat.realm.ports.first,
                nat.realm.ports.last,
                policy,
            )
            .map_err(|error| {
                ValidationError::new(
                    ValidationCode::Nat44UdpConfig(error),
                    path(&["nat44", "realm"]),
                )
            })?;
            udp_capacity = Some(source.capacity);
            validated_udp = Some((inside, outside, public_address, nat.realm.ports, policy));
        }
        if let Some(source) = nat.tcp {
            let seed = parse_seed(
                source.allocator_seed.expose(),
                path(&["nat44", "tcp", "allocator-seed"]),
            )?;
            let policy = Nat44TcpPolicy::new(source.idle_ttl_ms, seed)
                .map_err(|error| {
                    ValidationError::new(
                        ValidationCode::Nat44TcpPolicy(error),
                        path(&["nat44", "tcp", "idle-ttl-ms"]),
                    )
                })?
                .with_icmpv4_errors(map_icmp_policy(source.icmpv4_errors));
            Nat44TcpConfig::new(
                &snapshot,
                inside,
                outside,
                public_address,
                nat.realm.ports.first,
                nat.realm.ports.last,
                policy,
            )
            .map_err(|error| {
                ValidationError::new(
                    ValidationCode::Nat44TcpConfig(error),
                    path(&["nat44", "realm"]),
                )
            })?;
            tcp_capacity = Some(source.capacity);
            validated_tcp = Some((inside, outside, public_address, nat.realm.ports, policy));
        }
    }

    let firewall_source = config.firewall;
    let mut firewall_policy = None;
    let mut firewall_rules = None;
    let mut firewall_capacity = None;
    if let Some(source) = firewall_source {
        let policy = FirewallPolicy::new(
            source.policy.udp_idle_ttl_ms,
            source.policy.tcp_opening_idle_ttl_ms,
            source.policy.tcp_active_idle_ttl_ms,
        )
        .map_err(|error| {
            ValidationError::new(
                ValidationCode::FirewallPolicy(error),
                path(&["firewall", "policy"]),
            )
        })?;
        let mut rules = Vec::with_capacity(source.rules.len());
        for (index, source_rule) in source.rules.into_iter().enumerate() {
            let base = indexed_nested_path("firewall", "rules", index);
            let ingress = source_rule
                .ingress
                .as_deref()
                .map(|name| {
                    find_interface(name)
                        .map(FirewallInterface::Interface)
                        .ok_or_else(|| {
                            ValidationError::new(
                                ValidationCode::UnknownInterface,
                                child_path(&base, "ingress"),
                            )
                        })
                })
                .transpose()?
                .unwrap_or(FirewallInterface::Any);
            let egress = source_rule
                .egress
                .as_deref()
                .map(|name| {
                    find_interface(name)
                        .map(FirewallInterface::Interface)
                        .ok_or_else(|| {
                            ValidationError::new(
                                ValidationCode::UnknownInterface,
                                child_path(&base, "egress"),
                            )
                        })
                })
                .transpose()?
                .unwrap_or(FirewallInterface::Any);
            let source_prefix = parse_cidr(&source_rule.source, child_path(&base, "source"))?;
            let source_prefix =
                FirewallIpv4Prefix::new(source_prefix.address, source_prefix.prefix_len).map_err(
                    |error| {
                        ValidationError::new(
                            ValidationCode::FirewallPrefix(error),
                            child_path(&base, "source"),
                        )
                    },
                )?;
            let destination =
                parse_cidr(&source_rule.destination, child_path(&base, "destination"))?;
            let destination = FirewallIpv4Prefix::new(destination.address, destination.prefix_len)
                .map_err(|error| {
                    ValidationError::new(
                        ValidationCode::FirewallPrefix(error),
                        child_path(&base, "destination"),
                    )
                })?;
            let source_ports = FirewallPortRange::new(
                source_rule.source_ports.first,
                source_rule.source_ports.last,
            )
            .map_err(|error| {
                ValidationError::new(
                    ValidationCode::FirewallPortRange(error),
                    child_path(&base, "source-ports"),
                )
            })?;
            let destination_ports = FirewallPortRange::new(
                source_rule.destination_ports.first,
                source_rule.destination_ports.last,
            )
            .map_err(|error| {
                ValidationError::new(
                    ValidationCode::FirewallPortRange(error),
                    child_path(&base, "destination-ports"),
                )
            })?;
            rules.push(FirewallRule::new(
                FirewallRuleId(source_rule.id),
                ingress,
                egress,
                source_prefix,
                destination,
                match source_rule.protocol {
                    FirewallProtocolV1::Tcp => FirewallProtocol::Tcp,
                    FirewallProtocolV1::Udp => FirewallProtocol::Udp,
                },
                source_ports,
                destination_ports,
                match source_rule.action {
                    FirewallActionV1::AllowStateful => FirewallAction::AllowStateful,
                    FirewallActionV1::Deny => FirewallAction::Deny,
                },
            ));
        }
        validate_firewall_rules(&snapshot, &rules).map_err(|error| {
            ValidationError::new(
                ValidationCode::FirewallRules(error),
                path(&["firewall", "rules"]),
            )
        })?;
        firewall_policy = Some(policy);
        firewall_capacity = Some(source.capacity.states);
        firewall_rules = Some(rules.into_boxed_slice());
    }

    let storage = build_storage_shape(
        StorageInputs {
            resolution: resolution_source.map(|source| source.capacity),
            icmp: icmp_source.map(|source| source.capacity),
            udp: udp_capacity
                .zip(validated_udp.map(|(_, _, _, ports, _)| (ports.first, ports.last))),
            tcp: tcp_capacity
                .zip(validated_tcp.map(|(_, _, _, ports, _)| (ports.first, ports.last))),
            firewall_states: firewall_capacity,
        },
        limits,
    )?;

    let resolution = resolution_policy
        .zip(storage.resolution)
        .map(|(policy, storage)| ValidatedResolutionV1 { policy, storage });
    let icmpv4_errors = icmp_policy
        .zip(storage.icmpv4_errors)
        .map(|(policy, storage)| ValidatedIcmpv4ErrorV1 { policy, storage });
    let nat44 = (validated_udp.is_some() || validated_tcp.is_some()).then(|| ValidatedNat44V1 {
        udp: validated_udp.zip(storage.nat44_udp).map(
            |((inside, outside, public_address, ports, policy), storage)| ValidatedNat44UdpV1 {
                inside,
                outside,
                public_address,
                first_port: ports.first,
                last_port: ports.last,
                policy,
                storage,
            },
        ),
        tcp: validated_tcp.zip(storage.nat44_tcp).map(
            |((inside, outside, public_address, ports, policy), storage)| ValidatedNat44TcpV1 {
                inside,
                outside,
                public_address,
                first_port: ports.first,
                last_port: ports.last,
                policy,
                storage,
            },
        ),
    });
    let firewall = firewall_policy
        .zip(firewall_rules)
        .zip(firewall_capacity)
        .map(|((policy, rules), state_slots)| ValidatedFirewallV1 {
            rules,
            policy,
            state_slots,
        });
    let tick = config
        .tick
        .map_or_else(TickBudgetsV1::default, |tick| TickBudgetsV1 {
            rx: tick.rx,
            resolution_timer_scans: tick.resolution_timer_scans,
            failure_dispatch_scans: tick.failure_dispatch_scans,
            generated_arp: tick.generated_arp,
            generated_icmpv4: tick.generated_icmpv4,
        });

    Ok(ValidatedConfigV1 {
        interfaces,
        core_interfaces,
        routes,
        neighbors,
        local_ipv4,
        ipv4_origin,
        resolution,
        icmpv4_errors,
        nat44,
        firewall,
        tick,
        storage,
    })
}

fn preflight_public_dto(config: &ConfigV1) -> Result<(), ValidationError> {
    for (field, actual, limit) in [
        ("interfaces", config.interfaces.len(), crate::MAX_INTERFACES),
        ("addresses", config.addresses.len(), crate::MAX_ADDRESSES),
        ("routes", config.routes.len(), crate::MAX_ROUTES),
        ("neighbors", config.neighbors.len(), crate::MAX_NEIGHBORS),
    ] {
        check_list_bound(path(&[field]), actual, limit)?;
    }
    if let Some(firewall) = &config.firewall {
        check_list_bound(
            path(&["firewall", "rules"]),
            firewall.rules.len(),
            crate::MAX_FIREWALL_RULES,
        )?;
    }

    let mut text = TextBudget { used: 0 };
    for (index, interface) in config.interfaces.iter().enumerate() {
        let base = indexed_path("interfaces", index);
        text.add(&interface.name, child_path(&base, "name"))?;
        text.add(&interface.device, child_path(&base, "device"))?;
        text.add(&interface.mac, child_path(&base, "mac"))?;
    }
    for (index, address) in config.addresses.iter().enumerate() {
        let base = indexed_path("addresses", index);
        text.add(&address.interface, child_path(&base, "interface"))?;
        text.add(&address.ipv4, child_path(&base, "ipv4"))?;
    }
    for (index, route) in config.routes.iter().enumerate() {
        let base = indexed_path("routes", index);
        text.add(&route.prefix, child_path(&base, "prefix"))?;
        text.add(&route.egress, child_path(&base, "egress"))?;
        if let Some(via) = &route.via {
            text.add(via, child_path(&base, "via"))?;
        }
    }
    for (index, neighbor) in config.neighbors.iter().enumerate() {
        let base = indexed_path("neighbors", index);
        text.add(&neighbor.interface, child_path(&base, "interface"))?;
        text.add(&neighbor.address, child_path(&base, "address"))?;
        text.add(&neighbor.mac, child_path(&base, "mac"))?;
    }
    if let Some(nat44) = &config.nat44 {
        text.add(&nat44.realm.inside, path(&["nat44", "realm", "inside"]))?;
        text.add(&nat44.realm.outside, path(&["nat44", "realm", "outside"]))?;
        text.add(
            &nat44.realm.public_address,
            path(&["nat44", "realm", "public-address"]),
        )?;
        if let Some(udp) = &nat44.udp {
            text.add(
                udp.allocator_seed.expose(),
                path(&["nat44", "udp", "allocator-seed"]),
            )?;
        }
        if let Some(tcp) = &nat44.tcp {
            text.add(
                tcp.allocator_seed.expose(),
                path(&["nat44", "tcp", "allocator-seed"]),
            )?;
        }
    }
    if let Some(firewall) = &config.firewall {
        for (index, rule) in firewall.rules.iter().enumerate() {
            let base = indexed_nested_path("firewall", "rules", index);
            if let Some(ingress) = &rule.ingress {
                text.add(ingress, child_path(&base, "ingress"))?;
            }
            if let Some(egress) = &rule.egress {
                text.add(egress, child_path(&base, "egress"))?;
            }
            text.add(&rule.source, child_path(&base, "source"))?;
            text.add(&rule.destination, child_path(&base, "destination"))?;
        }
    }
    Ok(())
}

fn check_list_bound(path: SourcePath, actual: usize, limit: usize) -> Result<(), ValidationError> {
    if actual > limit {
        return Err(ValidationError::bounded(
            ValidationCode::ListTooLong,
            path,
            u64::try_from(limit).unwrap_or(u64::MAX),
            u64::try_from(actual).unwrap_or(u64::MAX),
        ));
    }
    Ok(())
}

struct TextBudget {
    used: usize,
}

impl TextBudget {
    fn add(&mut self, value: &str, path: SourcePath) -> Result<(), ValidationError> {
        self.used = self.used.checked_add(value.len()).ok_or_else(|| {
            ValidationError::bounded(
                ValidationCode::TextTooLarge,
                path.clone(),
                crate::MAX_CONFIG_BYTES as u64,
                u64::MAX,
            )
        })?;
        if self.used > crate::MAX_CONFIG_BYTES {
            return Err(ValidationError::bounded(
                ValidationCode::TextTooLarge,
                path,
                crate::MAX_CONFIG_BYTES as u64,
                u64::try_from(self.used).unwrap_or(u64::MAX),
            ));
        }
        Ok(())
    }
}

struct StorageInputs {
    resolution: Option<crate::ResolutionCapacityV1>,
    icmp: Option<crate::Icmpv4ErrorCapacityV1>,
    udp: Option<(crate::Nat44UdpCapacityV1, (u16, u16))>,
    tcp: Option<(crate::Nat44TcpCapacityV1, (u16, u16))>,
    firewall_states: Option<u32>,
}

fn build_storage_shape(
    inputs: StorageInputs,
    limits: ValidationLimits,
) -> Result<RuntimeStorageShapeV1, ValidationError> {
    let mut bytes = 0usize;
    let resolution = inputs
        .resolution
        .map(|capacity| {
            for (field, value) in [
                ("states", capacity.states),
                ("actions", capacity.actions),
                ("dynamic-neighbors", capacity.dynamic_neighbors),
                ("failure-holds", capacity.failure_holds),
            ] {
                check_slots(value, limits, path(&["resolution", "capacity", field]))?;
            }
            add_bytes::<ResolutionStateSlot>(
                &mut bytes,
                capacity.states,
                path(&["resolution", "capacity", "states"]),
            )?;
            add_bytes::<ResolutionActionSlot>(
                &mut bytes,
                capacity.actions,
                path(&["resolution", "capacity", "actions"]),
            )?;
            add_bytes::<DynamicNeighborSlot>(
                &mut bytes,
                capacity.dynamic_neighbors,
                path(&["resolution", "capacity", "dynamic-neighbors"]),
            )?;
            add_bytes::<ResolutionFailureHoldSlot>(
                &mut bytes,
                capacity.failure_holds,
                path(&["resolution", "capacity", "failure-holds"]),
            )?;
            Ok(ResolutionStorageShapeV1 {
                states: capacity.states,
                actions: capacity.actions,
                dynamic_neighbors: capacity.dynamic_neighbors,
                failure_holds: capacity.failure_holds,
            })
        })
        .transpose()?;
    let icmpv4_errors = inputs
        .icmp
        .map(|capacity| {
            for (field, value) in [("states", capacity.states), ("actions", capacity.actions)] {
                check_slots(value, limits, path(&["icmpv4-errors", "capacity", field]))?;
            }
            add_bytes::<Icmpv4ErrorStateSlot>(
                &mut bytes,
                capacity.states,
                path(&["icmpv4-errors", "capacity", "states"]),
            )?;
            add_bytes::<Icmpv4ErrorActionSlot>(
                &mut bytes,
                capacity.actions,
                path(&["icmpv4-errors", "capacity", "actions"]),
            )?;
            Ok(Icmpv4ErrorStorageShapeV1 {
                states: capacity.states,
                actions: capacity.actions,
            })
        })
        .transpose()?;
    let nat44_udp = inputs
        .udp
        .map(|(capacity, ports)| {
            let shape = udp_shape(capacity, ports, limits)?;
            add_bytes::<Nat44UdpMappingSlot>(
                &mut bytes,
                shape.mappings,
                path(&["nat44", "udp", "capacity", "mappings"]),
            )?;
            add_bytes::<Nat44UdpPeerSlot>(
                &mut bytes,
                shape.peers,
                path(&["nat44", "udp", "capacity", "peers"]),
            )?;
            add_directory_bytes(&mut bytes, shape.mapping_buckets, shape.mapping_nodes)?;
            add_directory_bytes(&mut bytes, shape.peer_buckets, shape.peer_nodes)?;
            add_bytes::<PortOwnerSlot>(
                &mut bytes,
                shape.port_owners,
                path(&["nat44", "realm", "ports"]),
            )?;
            Ok(shape)
        })
        .transpose()?;
    let nat44_tcp = inputs
        .tcp
        .map(|(capacity, ports)| {
            let shape = tcp_shape(capacity, ports, limits)?;
            add_bytes::<Nat44TcpMappingSlot>(
                &mut bytes,
                shape.mappings,
                path(&["nat44", "tcp", "capacity", "mappings"]),
            )?;
            add_bytes::<Nat44TcpSessionSlot>(
                &mut bytes,
                shape.sessions,
                path(&["nat44", "tcp", "capacity", "sessions"]),
            )?;
            add_directory_bytes(&mut bytes, shape.mapping_buckets, shape.mapping_nodes)?;
            add_directory_bytes(&mut bytes, shape.session_buckets, shape.session_nodes)?;
            add_bytes::<PortOwnerSlot>(
                &mut bytes,
                shape.port_owners,
                path(&["nat44", "realm", "ports"]),
            )?;
            Ok(shape)
        })
        .transpose()?;
    if let Some(states) = inputs.firewall_states {
        check_slots(states, limits, path(&["firewall", "capacity", "states"]))?;
        add_bytes::<FirewallStateSlot>(
            &mut bytes,
            states,
            path(&["firewall", "capacity", "states"]),
        )?;
    }
    if bytes > limits.max_runtime_bytes {
        return Err(ValidationError::bounded(
            ValidationCode::RuntimeStorageBytesExceeded,
            SourcePath::default(),
            u64::try_from(limits.max_runtime_bytes).unwrap_or(u64::MAX),
            u64::try_from(bytes).unwrap_or(u64::MAX),
        ));
    }
    Ok(RuntimeStorageShapeV1 {
        resolution,
        icmpv4_errors,
        nat44_udp,
        nat44_tcp,
        firewall_states: inputs.firewall_states,
        required_bytes: bytes,
    })
}

fn udp_shape(
    capacity: crate::Nat44UdpCapacityV1,
    ports: (u16, u16),
    limits: ValidationLimits,
) -> Result<Nat44UdpStorageShapeV1, ValidationError> {
    let mapping_path = path(&["nat44", "udp", "capacity", "mappings"]);
    let peer_path = path(&["nat44", "udp", "capacity", "peers"]);
    check_slots(capacity.mappings, limits, mapping_path.clone())?;
    check_slots(capacity.peers, limits, peer_path.clone())?;
    let mapping_buckets = directory_buckets(capacity.mappings, limits, mapping_path)?;
    let peer_buckets = directory_buckets(capacity.peers, limits, peer_path)?;
    let port_owners = port_count(ports);
    check_slots(port_owners, limits, path(&["nat44", "realm", "ports"]))?;
    Ok(Nat44UdpStorageShapeV1 {
        mappings: capacity.mappings,
        peers: capacity.peers,
        mapping_buckets,
        mapping_nodes: capacity.mappings,
        peer_buckets,
        peer_nodes: capacity.peers,
        port_owners,
    })
}

fn tcp_shape(
    capacity: crate::Nat44TcpCapacityV1,
    ports: (u16, u16),
    limits: ValidationLimits,
) -> Result<Nat44TcpStorageShapeV1, ValidationError> {
    let mapping_path = path(&["nat44", "tcp", "capacity", "mappings"]);
    let session_path = path(&["nat44", "tcp", "capacity", "sessions"]);
    check_slots(capacity.mappings, limits, mapping_path.clone())?;
    check_slots(capacity.sessions, limits, session_path.clone())?;
    let mapping_buckets = directory_buckets(capacity.mappings, limits, mapping_path)?;
    let session_buckets = directory_buckets(capacity.sessions, limits, session_path)?;
    let port_owners = port_count(ports);
    check_slots(port_owners, limits, path(&["nat44", "realm", "ports"]))?;
    Ok(Nat44TcpStorageShapeV1 {
        mappings: capacity.mappings,
        sessions: capacity.sessions,
        mapping_buckets,
        mapping_nodes: capacity.mappings,
        session_buckets,
        session_nodes: capacity.sessions,
        port_owners,
    })
}

fn directory_buckets(
    capacity: u32,
    limits: ValidationLimits,
    path: SourcePath,
) -> Result<u32, ValidationError> {
    let buckets = if capacity == 0 {
        0
    } else {
        capacity.checked_next_power_of_two().ok_or_else(|| {
            ValidationError::new(ValidationCode::CapacityNotRepresentable, path.clone())
        })?
    };
    check_slots(buckets, limits, path)?;
    Ok(buckets)
}

fn check_slots(
    slots: u32,
    limits: ValidationLimits,
    path: SourcePath,
) -> Result<(), ValidationError> {
    if slots > limits.max_slots_per_table {
        return Err(ValidationError::bounded(
            ValidationCode::CapacityLimitExceeded,
            path,
            u64::from(limits.max_slots_per_table),
            u64::from(slots),
        ));
    }
    usize::try_from(slots)
        .map(|_| ())
        .map_err(|_| ValidationError::new(ValidationCode::CapacityNotRepresentable, path))
}

fn add_directory_bytes(bytes: &mut usize, buckets: u32, nodes: u32) -> Result<(), ValidationError> {
    add_bytes::<DirectoryBucket>(bytes, buckets, SourcePath::default())?;
    add_bytes::<DirectoryNode>(bytes, nodes, SourcePath::default())
}

fn add_bytes<T>(bytes: &mut usize, count: u32, path: SourcePath) -> Result<(), ValidationError> {
    let count = usize::try_from(count).map_err(|_| {
        ValidationError::new(ValidationCode::CapacityNotRepresentable, path.clone())
    })?;
    let required = count.checked_mul(size_of::<T>()).ok_or_else(|| {
        ValidationError::new(ValidationCode::CapacityArithmeticOverflow, path.clone())
    })?;
    *bytes = bytes
        .checked_add(required)
        .ok_or_else(|| ValidationError::new(ValidationCode::CapacityArithmeticOverflow, path))?;
    Ok(())
}

fn port_count((first, last): (u16, u16)) -> u32 {
    u32::from(last) - u32::from(first) + 1
}

fn map_icmp_policy(policy: Nat44Icmpv4ErrorsV1) -> Nat44Icmpv4ErrorPolicy {
    match policy {
        Nat44Icmpv4ErrorsV1::Disabled => Nat44Icmpv4ErrorPolicy::Disabled,
        Nat44Icmpv4ErrorsV1::ExternalOnly => Nat44Icmpv4ErrorPolicy::ExternalOnly,
    }
}

fn parse_seed(value: &str, path: SourcePath) -> Result<u64, ValidationError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ValidationError::new(
            ValidationCode::InvalidAllocatorSeed,
            path,
        ));
    }
    let parsed = value.parse::<u64>().map_err(|_: ParseIntError| {
        ValidationError::new(ValidationCode::InvalidAllocatorSeed, path.clone())
    })?;
    if parsed.to_string() != value {
        return Err(ValidationError::new(
            ValidationCode::NonCanonicalAllocatorSeed,
            path,
        ));
    }
    Ok(parsed)
}

fn parse_mac(value: &str, path: SourcePath) -> Result<MacAddress, ValidationError> {
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 6
        || parts
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(ValidationError::new(ValidationCode::InvalidMac, path));
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(ValidationError::new(ValidationCode::NonCanonicalMac, path));
    }
    let mut octets = [0u8; 6];
    for (index, part) in parts.into_iter().enumerate() {
        octets[index] = u8::from_str_radix(part, 16)
            .map_err(|_| ValidationError::new(ValidationCode::InvalidMac, path.clone()))?;
    }
    if octets == [0; 6] || octets == [0xff; 6] || octets[0] & 1 != 0 {
        return Err(ValidationError::new(ValidationCode::MacNotUnicast, path));
    }
    Ok(MacAddress(octets))
}

fn parse_ipv4(value: &str, path: SourcePath) -> Result<Ipv4Address, ValidationError> {
    let parsed = value
        .parse::<Ipv4Addr>()
        .map_err(|_| ValidationError::new(ValidationCode::InvalidIpv4, path.clone()))?;
    if parsed.to_string() != value {
        return Err(ValidationError::new(ValidationCode::NonCanonicalIpv4, path));
    }
    Ok(Ipv4Address::from_octets(parsed.octets()))
}

fn parse_cidr(value: &str, path: SourcePath) -> Result<ParsedCidr, ValidationError> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| ValidationError::new(ValidationCode::InvalidIpv4Prefix, path.clone()))?;
    if prefix.is_empty()
        || !prefix.bytes().all(|byte| byte.is_ascii_digit())
        || (prefix.len() > 1 && prefix.starts_with('0'))
    {
        return Err(ValidationError::new(
            ValidationCode::NonCanonicalIpv4Prefix,
            path,
        ));
    }
    let prefix_len = prefix
        .parse::<u8>()
        .ok()
        .filter(|prefix| *prefix <= 32)
        .ok_or_else(|| ValidationError::new(ValidationCode::InvalidIpv4Prefix, path.clone()))?;
    Ok(ParsedCidr {
        address: parse_ipv4(address, path)?,
        prefix_len,
    })
}

fn is_basic_host(address: Ipv4Address) -> bool {
    let octets = address.octets();
    !address.is_unspecified()
        && octets[0] != 0
        && octets[0] != 127
        && octets[0] < 224
        && octets != [255; 4]
}

fn is_host_for_prefix(address: Ipv4Address, prefix_len: u8) -> bool {
    if !is_basic_host(address) {
        return false;
    }
    if prefix_len >= 31 {
        return true;
    }
    let value = u32::from_be_bytes(address.octets());
    let mask = prefix_mask(prefix_len);
    value != value & mask && value != value | !mask
}

fn route_host_matches(route: Route, address: Ipv4Address) -> bool {
    let value = u32::from_be_bytes(address.octets());
    let prefix = u32::from_be_bytes(route.prefix().octets());
    let mask = prefix_mask(route.prefix_len());
    value & mask == prefix && is_host_for_prefix(address, route.prefix_len())
}

fn network_address(address: Ipv4Address, prefix_len: u8) -> Ipv4Address {
    Ipv4Address::from_octets(
        (u32::from_be_bytes(address.octets()) & prefix_mask(prefix_len)).to_be_bytes(),
    )
}

fn prefix_mask(prefix_len: u8) -> u32 {
    match prefix_len {
        0 => 0,
        1..=32 => u32::MAX << (32 - u32::from(prefix_len)),
        _ => unreachable!("CIDR parser validates prefix length"),
    }
}

fn route_prefix_key(route: Route) -> (u32, u8) {
    (
        u32::from_be_bytes(route.prefix().octets()),
        route.prefix_len(),
    )
}

fn route_sort_key(route: Route) -> (u32, u8, u16, u32) {
    let next_hop = route
        .next_hop()
        .map_or(0, |address| u32::from_be_bytes(address.octets()));
    let (prefix, prefix_len) = route_prefix_key(route);
    (prefix, prefix_len, route.egress().0, next_hop)
}

fn path(fields: &[&str]) -> SourcePath {
    let Some((first, rest)) = fields.split_first() else {
        return SourcePath::default();
    };
    let mut path = SourcePath::root_field(*first);
    for field in rest {
        path.push_field(*field);
    }
    path
}

fn indexed_path(field: &str, index: usize) -> SourcePath {
    let mut path = SourcePath::root_field(field);
    path.push_index(index);
    path
}

fn indexed_nested_path(field: &str, nested: &str, index: usize) -> SourcePath {
    let mut path = SourcePath::root_field(field);
    path.push_field(nested);
    path.push_index(index);
    path
}

fn child_path(parent: &SourcePath, field: &str) -> SourcePath {
    let mut path = parent.clone();
    path.push_field(field);
    path
}
