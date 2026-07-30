use std::mem::size_of;

use ruster_config::{
    parse, validate, ConfigV1, PathSegment, RuntimeStorageShapeV1, ValidatedConfig,
    ValidatedConfigV1, ValidationCode, ValidationLimits, VersionedConfig, MAX_ADDRESSES,
    MAX_CONFIG_BYTES, MAX_FIREWALL_RULES, MAX_INTERFACES, MAX_NEIGHBORS, MAX_ROUTES,
};
use ruster_core::{
    DirectoryBucket, DirectoryNode, DynamicNeighborSlot, FirewallRuleId, FirewallStateSlot,
    Icmpv4ErrorActionSlot, Icmpv4ErrorStateSlot, Nat44TcpMappingSlot, Nat44TcpSessionSlot,
    Nat44UdpMappingSlot, Nat44UdpPeerSlot, PortOwnerSlot, ResolutionActionSlot,
    ResolutionFailureHoldSlot, ResolutionStateSlot, RouteError,
};

const VALID: &str = r#"
schema-version = 1

[[interfaces]]
id = 2
name = "wan"
device = "eth1"
mac = "02:00:00:00:00:02"

[[interfaces]]
id = 1
name = "lan"
device = "eth0"
mac = "02:00:00:00:00:01"

[[addresses]]
interface = "wan"
ipv4 = "198.51.100.10/24"

[[addresses]]
interface = "lan"
ipv4 = "192.0.2.1/24"

[[routes]]
prefix = "0.0.0.0/0"
egress = "wan"
via = "198.51.100.1"

[[neighbors]]
interface = "wan"
address = "198.51.100.1"
mac = "02:00:00:00:00:03"

[[neighbors]]
interface = "lan"
address = "192.0.2.20"
mac = "02:00:00:00:00:04"

[ipv4-origin]
default-ttl = 64

[resolution.policy]
interval-ms = 1000
state-ttl-ms = 3000
dynamic-neighbor-ttl-ms = 60000
max-attempts = 3

[resolution.capacity]
states = 2
actions = 3
dynamic-neighbors = 4
failure-holds = 5

[icmpv4-errors.policy]
interval-ms = 100
state-ttl-ms = 60000

[icmpv4-errors.capacity]
states = 2
actions = 3

[nat44.realm]
inside = "lan"
outside = "wan"
public-address = "198.51.100.10"

[nat44.realm.ports]
first = 40000
last = 40007

[nat44.udp]
idle-ttl-ms = 300000
allocator-seed = "7"
icmpv4-errors = "external-only"

[nat44.udp.capacity]
mappings = 3
peers = 5

[nat44.tcp]
idle-ttl-ms = 7440000
allocator-seed = "11"
icmpv4-errors = "disabled"

[nat44.tcp.capacity]
mappings = 3
sessions = 5

[firewall.policy]
udp-idle-ttl-ms = 300000
tcp-opening-idle-ttl-ms = 240000
tcp-active-idle-ttl-ms = 7440000

[firewall.capacity]
states = 6

[[firewall.rules]]
id = 2
ingress = "lan"
egress = "wan"
source = "192.0.2.0/24"
destination = "0.0.0.0/0"
protocol = "tcp"
action = "allow-stateful"

[firewall.rules.source-ports]
first = 0
last = 65535

[firewall.rules.destination-ports]
first = 443
last = 443

[[firewall.rules]]
id = 1
source = "0.0.0.0/0"
destination = "0.0.0.0/0"
protocol = "udp"
action = "deny"

[firewall.rules.source-ports]
first = 0
last = 65535

[firewall.rules.destination-ports]
first = 0
last = 65535

[tick]
rx = 64
resolution-timer-scans = 16
failure-dispatch-scans = 8
generated-arp = 4
generated-icmpv4 = 2
"#;

const GENEROUS: ValidationLimits = ValidationLimits {
    max_slots_per_table: 1_048_576,
    max_runtime_bytes: 1 << 30,
};

fn validated_with(
    source: &str,
    limits: ValidationLimits,
) -> Result<ValidatedConfigV1, ruster_config::ValidationError> {
    match validate(parse(source.as_bytes()).expect("syntax fixture"), limits)? {
        ValidatedConfig::V1(config) => Ok(config),
        _ => unreachable!("test fixture selects schema V1"),
    }
}

fn validated(source: &str) -> ValidatedConfigV1 {
    validated_with(source, GENEROUS).expect("semantic fixture")
}

fn error(source: &str) -> ruster_config::ValidationError {
    validated_with(source, GENEROUS).err().expect("must reject")
}

fn dto() -> ConfigV1 {
    let VersionedConfig::V1(dto) = parse(VALID.as_bytes()).unwrap() else {
        unreachable!("only schema V1 exists");
    };
    dto
}

fn dto_error(dto: ConfigV1) -> ruster_config::ValidationError {
    validate(VersionedConfig::V1(dto), GENEROUS)
        .err()
        .expect("direct DTO must reject")
}

#[test]
fn semantic_validation_canonicalizes_only_order_independent_tables() {
    let config = validated(VALID);
    assert_eq!(
        config
            .interfaces()
            .iter()
            .map(|interface| (interface.id().0, interface.name(), interface.device()))
            .collect::<Vec<_>>(),
        vec![(1, "lan", "eth0"), (2, "wan", "eth1")]
    );
    assert_eq!(
        config
            .local_ipv4()
            .iter()
            .map(|binding| binding.interface.0)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(config.routes().len(), 3);
    assert_eq!(
        config
            .neighbors()
            .iter()
            .map(|neighbor| neighbor.interface.0)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(
        config
            .firewall()
            .unwrap()
            .rules()
            .iter()
            .map(|rule| rule.id())
            .collect::<Vec<_>>(),
        vec![FirewallRuleId(2), FirewallRuleId(1)],
        "firewall first-match order must not be canonicalized"
    );
    assert_eq!(config.tick().rx, 64);
    assert_eq!(config.nat44().unwrap().udp().unwrap().inside().0, 1);
    assert_eq!(config.nat44().unwrap().tcp().unwrap().outside().0, 2);
}

#[test]
fn complete_storage_shape_counts_every_runtime_and_index_array() {
    let shape = validated(VALID).storage_shape();
    assert_eq!(
        shape,
        RuntimeStorageShapeV1 {
            resolution: Some(ruster_config::ResolutionStorageShapeV1 {
                states: 2,
                actions: 3,
                dynamic_neighbors: 4,
                failure_holds: 5,
            }),
            icmpv4_errors: Some(ruster_config::Icmpv4ErrorStorageShapeV1 {
                states: 2,
                actions: 3,
            }),
            nat44_udp: Some(ruster_config::Nat44UdpStorageShapeV1 {
                mappings: 3,
                peers: 5,
                mapping_buckets: 4,
                mapping_nodes: 3,
                peer_buckets: 8,
                peer_nodes: 5,
                port_owners: 8,
            }),
            nat44_tcp: Some(ruster_config::Nat44TcpStorageShapeV1 {
                mappings: 3,
                sessions: 5,
                mapping_buckets: 4,
                mapping_nodes: 3,
                session_buckets: 8,
                session_nodes: 5,
                port_owners: 8,
            }),
            firewall_states: Some(6),
            required_bytes: shape.required_bytes,
        }
    );
    let expected = 2 * size_of::<ResolutionStateSlot>()
        + 3 * size_of::<ResolutionActionSlot>()
        + 4 * size_of::<DynamicNeighborSlot>()
        + 5 * size_of::<ResolutionFailureHoldSlot>()
        + 2 * size_of::<Icmpv4ErrorStateSlot>()
        + 3 * size_of::<Icmpv4ErrorActionSlot>()
        + 3 * size_of::<Nat44UdpMappingSlot>()
        + 5 * size_of::<Nat44UdpPeerSlot>()
        + (4 + 8) * size_of::<DirectoryBucket>()
        + (3 + 5) * size_of::<DirectoryNode>()
        + 8 * size_of::<PortOwnerSlot>()
        + 3 * size_of::<Nat44TcpMappingSlot>()
        + 5 * size_of::<Nat44TcpSessionSlot>()
        + (4 + 8) * size_of::<DirectoryBucket>()
        + (3 + 5) * size_of::<DirectoryNode>()
        + 8 * size_of::<PortOwnerSlot>()
        + 6 * size_of::<FirewallStateSlot>();
    assert_eq!(shape.required_bytes, expected);

    assert!(validated_with(
        VALID,
        ValidationLimits {
            max_slots_per_table: 8,
            max_runtime_bytes: expected,
        }
    )
    .is_ok());
    let bounded = validated_with(
        VALID,
        ValidationLimits {
            max_slots_per_table: 8,
            max_runtime_bytes: expected - 1,
        },
    )
    .err()
    .expect("byte limit must reject");
    assert_eq!(bounded.code(), ValidationCode::RuntimeStorageBytesExceeded);
    assert_eq!(bounded.limit(), Some((expected - 1) as u64));
    assert_eq!(bounded.actual(), Some(expected as u64));
}

#[test]
fn capacity_zero_exact_limit_and_next_power_overflow_are_typed() {
    let zero = VALID
        .replace("mappings = 3", "mappings = 0")
        .replace("peers = 5", "peers = 0")
        .replace("sessions = 5", "sessions = 0");
    let shape = validated_with(
        &zero,
        ValidationLimits {
            max_slots_per_table: 8,
            max_runtime_bytes: 1 << 30,
        },
    )
    .unwrap()
    .storage_shape();
    assert_eq!(shape.nat44_udp.unwrap().mapping_buckets, 0);
    assert_eq!(shape.nat44_tcp.unwrap().session_buckets, 0);
    assert_eq!(shape.nat44_udp.unwrap().port_owners, 8);

    let over_limit = VALID.replacen("peers = 5", "peers = 9", 1);
    let error = validated_with(
        &over_limit,
        ValidationLimits {
            max_slots_per_table: 8,
            max_runtime_bytes: usize::MAX,
        },
    )
    .err()
    .expect("slot limit must reject");
    assert_eq!(error.code(), ValidationCode::CapacityLimitExceeded);
    assert_eq!(error.limit(), Some(8));
    assert_eq!(error.actual(), Some(9));

    let overflow = VALID.replacen("mappings = 3", "mappings = 2147483649", 1);
    let error = validated_with(
        &overflow,
        ValidationLimits {
            max_slots_per_table: u32::MAX,
            max_runtime_bytes: usize::MAX,
        },
    )
    .err()
    .expect("next power overflow must reject");
    assert_eq!(error.code(), ValidationCode::CapacityNotRepresentable);
}

#[test]
fn canonical_text_and_stable_precedence_reject_before_core_construction() {
    for (from, to, expected) in [
        (
            "mac = \"02:00:00:00:00:01\"",
            "mac = \"02:00:00:00:00:0A\"",
            ValidationCode::NonCanonicalMac,
        ),
        (
            "ipv4 = \"192.0.2.1/24\"",
            "ipv4 = \"192.0.2.01/24\"",
            ValidationCode::InvalidIpv4,
        ),
        (
            "ipv4 = \"192.0.2.1/24\"",
            "ipv4 = \"192.0.2.1/024\"",
            ValidationCode::NonCanonicalIpv4Prefix,
        ),
        (
            "allocator-seed = \"7\"",
            "allocator-seed = \"07\"",
            ValidationCode::NonCanonicalAllocatorSeed,
        ),
    ] {
        assert_eq!(error(&VALID.replacen(from, to, 1)).code(), expected);
    }

    let duplicate_before_bad_mac = VALID.replace("name = \"lan\"", "name = \"wan\"").replace(
        "mac = \"02:00:00:00:00:01\"",
        "mac = \"DO_NOT_ECHO_INVALID_MAC\"",
    );
    assert_eq!(
        error(&duplicate_before_bad_mac).code(),
        ValidationCode::DuplicateInterfaceName
    );
}

#[test]
fn duplicate_unknown_and_on_link_checks_are_value_free() {
    let duplicate_route = VALID.replace(
        "[[neighbors]]",
        "[[routes]]\nprefix = \"192.0.2.0/24\"\negress = \"lan\"\n\n[[neighbors]]",
    );
    assert_eq!(
        error(&duplicate_route).code(),
        ValidationCode::DuplicateRoute
    );
    let duplicate_neighbor = VALID.replace(
        "[ipv4-origin]",
        "[[neighbors]]\ninterface = \"wan\"\naddress = \"198.51.100.1\"\nmac = \"02:00:00:00:00:05\"\n\n[ipv4-origin]",
    );
    assert_eq!(
        error(&duplicate_neighbor).code(),
        ValidationCode::DuplicateNeighbor
    );

    let unknown = VALID.replacen("egress = \"wan\"", "egress = \"DO_NOT_ECHO_IFACE\"", 1);
    let unknown_error = error(&unknown);
    assert_eq!(unknown_error.code(), ValidationCode::UnknownInterface);
    assert!(!format!("{unknown_error:?}").contains("DO_NOT_ECHO_IFACE"));

    let off_link_gateway = VALID.replacen("via = \"198.51.100.1\"", "via = \"203.0.113.1\"", 1);
    assert_eq!(
        error(&off_link_gateway).code(),
        ValidationCode::GatewayNotOnLink
    );
    let off_link_neighbor =
        VALID.replacen("address = \"198.51.100.1\"", "address = \"203.0.113.1\"", 1);
    assert_eq!(
        error(&off_link_neighbor).code(),
        ValidationCode::NeighborNotOnLink
    );
}

#[test]
fn core_policy_nat_realm_and_firewall_semantics_are_preserved() {
    assert_eq!(
        error(&VALID.replacen("default-ttl = 64", "default-ttl = 0", 1)).code(),
        ValidationCode::Ipv4Origin(ruster_core::Ipv4OriginPolicyError::DefaultTtlZero)
    );
    assert_eq!(
        error(&VALID.replacen("interval-ms = 1000", "interval-ms = 999", 1)).code(),
        ValidationCode::ResolutionPolicy(ruster_core::ResolutionPolicyError::IntervalTooShort)
    );
    assert_eq!(
        error(&VALID.replacen("idle-ttl-ms = 300000", "idle-ttl-ms = 119999", 1)).code(),
        ValidationCode::Nat44UdpPolicy(ruster_core::Nat44UdpPolicyError::IdleTtlTooShort)
    );
    assert_eq!(
        error(&VALID.replacen("inside = \"lan\"", "inside = \"wan\"", 1)).code(),
        ValidationCode::Nat44UdpConfig(ruster_core::Nat44UdpConfigError::InterfacesEqual)
    );
    assert_eq!(
        error(&VALID.replacen(
            "public-address = \"198.51.100.10\"",
            "public-address = \"192.0.2.1\"",
            1
        ))
        .code(),
        ValidationCode::Nat44UdpConfig(
            ruster_core::Nat44UdpConfigError::PublicBindingWrongInterface
        )
    );
    assert_eq!(
        error(&VALID.replacen("source = \"192.0.2.0/24\"", "source = \"192.0.2.1/24\"", 1)).code(),
        ValidationCode::FirewallPrefix(ruster_core::FirewallIpv4PrefixError::HostBitsSet)
    );
    assert_eq!(
        error(&VALID.replacen("id = 2\ningress", "id = 0\ningress", 1)).code(),
        ValidationCode::FirewallRules(ruster_core::FirewallConfigError::RuleIdZero)
    );
    let mut empty_realm = dto();
    let nat = empty_realm.nat44.as_mut().unwrap();
    nat.udp = None;
    nat.tcp = None;
    assert_eq!(
        dto_error(empty_realm).code(),
        ValidationCode::Nat44RealmWithoutProtocol
    );

    let policy_before_capacity = VALID
        .replacen("idle-ttl-ms = 300000", "idle-ttl-ms = 119999", 1)
        .replacen("peers = 5", "peers = 4294967295", 1);
    assert_eq!(
        error(&policy_before_capacity).code(),
        ValidationCode::Nat44UdpPolicy(ruster_core::Nat44UdpPolicyError::IdleTtlTooShort)
    );
}

#[test]
fn diagnostics_and_assertion_panics_never_echo_secret_or_topology_values() {
    let poison = VALID.replacen(
        "allocator-seed = \"7\"",
        "allocator-seed = \"18446744073709551616_DO_NOT_ECHO\"",
        1,
    );
    let first = error(&poison);
    let second = error(&VALID.replacen("allocator-seed = \"7\"", "allocator-seed = \"07\"", 1));
    let compact = format!("{first:?}");
    let pretty = format!("{first:#?}");
    assert_eq!(
        compact,
        "ValidationError { code: InvalidAllocatorSeed, path: [Field(\"nat44\"), Field(\"udp\"), Field(\"allocator-seed\")], limit: None, actual: None }"
    );
    for forbidden in [
        "18446744073709551616",
        "DO_NOT_ECHO",
        "198.51.100.10",
        "02:00:00:00:00:01",
        "eth0",
    ] {
        assert!(!compact.contains(forbidden));
        assert!(!pretty.contains(forbidden));
    }
    let panic = std::panic::catch_unwind(|| assert_eq!(first, second)).unwrap_err();
    let panic = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("assertion panic text");
    assert!(!panic.contains("DO_NOT_ECHO"));
    assert!(!panic.contains("18446744073709551616"));
}

#[test]
fn semantic_surface_has_no_runtime_dependency_or_secret_bearing_debug_derive() {
    let manifest = include_str!("../Cargo.toml");
    let source = include_str!("../src/validate.rs");
    assert!(!manifest.contains("ruster-runtime"));
    assert!(!source.contains("ruster_runtime"));
    assert!(!source.contains("ValidatedForwardingOwner"));

    for declaration in [
        "pub struct InterfaceBindingV1",
        "pub struct ValidatedResolutionV1",
        "pub struct ValidatedIcmpv4ErrorV1",
        "pub struct ValidatedNat44UdpV1",
        "pub struct ValidatedNat44TcpV1",
        "pub struct ValidatedNat44V1",
        "pub struct ValidatedFirewallV1",
        "pub struct ValidatedConfigV1",
        "pub enum ValidatedConfig",
    ] {
        let offset = source.find(declaration).expect("declaration exists");
        let prefix = &source[..offset];
        let boundary = prefix.rfind("\n}").map_or(0, |boundary| boundary + 2);
        assert!(
            !prefix[boundary..].lines().any(|line| {
                line.trim_start().starts_with("#[derive") && line.contains("Debug")
            }),
            "{declaration} must not derive Debug"
        );
    }
}

#[test]
fn validator_rechecks_schema_version_without_trusting_parser_provenance() {
    let mut dto = dto();
    dto.schema_version = 42;
    let error = dto_error(dto);
    assert_eq!(error.code(), ValidationCode::InvalidSchemaVersion);
    assert_eq!(
        error.path().segments(),
        &[PathSegment::Field("schema-version".to_owned())]
    );
}

#[test]
fn validator_rechecks_all_public_dto_list_bounds_before_nested_work() {
    let mut interfaces = dto();
    interfaces.interfaces =
        vec![interfaces.interfaces[0].clone(); MAX_INTERFACES.saturating_add(1)];
    let mut addresses = dto();
    addresses.addresses = vec![addresses.addresses[0].clone(); MAX_ADDRESSES.saturating_add(1)];
    let mut routes = dto();
    routes.routes = vec![routes.routes[0].clone(); MAX_ROUTES.saturating_add(1)];
    let mut neighbors = dto();
    neighbors.neighbors = vec![neighbors.neighbors[0].clone(); MAX_NEIGHBORS.saturating_add(1)];
    let mut firewall = dto();
    let rules = &mut firewall.firewall.as_mut().unwrap().rules;
    *rules = vec![rules[0].clone(); MAX_FIREWALL_RULES.saturating_add(1)];

    for (candidate, field, limit) in [
        (interfaces, "interfaces", MAX_INTERFACES),
        (addresses, "addresses", MAX_ADDRESSES),
        (routes, "routes", MAX_ROUTES),
        (neighbors, "neighbors", MAX_NEIGHBORS),
    ] {
        let error = dto_error(candidate);
        assert_eq!(error.code(), ValidationCode::ListTooLong);
        assert_eq!(error.limit(), Some(limit as u64));
        assert_eq!(error.actual(), Some((limit + 1) as u64));
        assert_eq!(
            error.path().segments(),
            &[PathSegment::Field(field.to_owned())]
        );
    }
    let error = dto_error(firewall);
    assert_eq!(error.code(), ValidationCode::ListTooLong);
    assert_eq!(error.limit(), Some(MAX_FIREWALL_RULES as u64));
    assert_eq!(error.actual(), Some((MAX_FIREWALL_RULES + 1) as u64));
    assert_eq!(
        error.path().segments(),
        &[
            PathSegment::Field("firewall".to_owned()),
            PathSegment::Field("rules".to_owned()),
        ]
    );

    let mut precedence = dto();
    precedence.schema_version = 42;
    precedence.interfaces =
        vec![precedence.interfaces[0].clone(); MAX_INTERFACES.saturating_add(1)];
    assert_eq!(
        dto_error(precedence).code(),
        ValidationCode::InvalidSchemaVersion
    );
}

#[test]
fn validator_rechecks_aggregate_text_bytes_for_direct_dto_and_deserialize_bypass() {
    let mut direct = dto();
    direct.interfaces[0].name = "x".repeat(MAX_CONFIG_BYTES + 1);
    let error = dto_error(direct);
    assert_eq!(error.code(), ValidationCode::TextTooLarge);
    assert_eq!(error.limit(), Some(MAX_CONFIG_BYTES as u64));
    assert!(error.actual().unwrap() > MAX_CONFIG_BYTES as u64);
    assert_eq!(
        error.path().segments(),
        &[
            PathSegment::Field("interfaces".to_owned()),
            PathSegment::Index(0),
            PathSegment::Field("name".to_owned()),
        ]
    );

    let oversized_seed = "9".repeat(MAX_CONFIG_BYTES + 1);
    let source = VALID.replacen(
        "allocator-seed = \"7\"",
        &format!("allocator-seed = \"{oversized_seed}\""),
        1,
    );
    let bypassed: ConfigV1 = toml::from_str(&source).expect("direct Deserialize bypass");
    let error = dto_error(bypassed);
    assert_eq!(error.code(), ValidationCode::TextTooLarge);
    assert_eq!(
        error.path().segments(),
        &[
            PathSegment::Field("nat44".to_owned()),
            PathSegment::Field("udp".to_owned()),
            PathSegment::Field("allocator-seed".to_owned()),
        ]
    );
    assert!(!format!("{error:?}").contains(&oversized_seed[..64]));
}

#[test]
fn route_host_bits_and_error_path_are_exact() {
    let invalid = VALID.replacen("prefix = \"0.0.0.0/0\"", "prefix = \"10.0.0.1/8\"", 1);
    let error = error(&invalid);
    assert_eq!(error.code(), ValidationCode::Route(RouteError::HostBitsSet));
    assert_eq!(
        error.path().segments(),
        &[
            PathSegment::Field("routes".to_owned()),
            PathSegment::Index(0),
            PathSegment::Field("prefix".to_owned()),
        ]
    );
}
