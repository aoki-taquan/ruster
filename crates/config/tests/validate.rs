use std::mem::size_of;

use ruster_config::{
    parse, validate, ConfigV1, PathSegment, RuntimeStorageShapeV1, ValidatedConfig,
    ValidatedConfigV1, ValidationCode, ValidationLimits, VersionedConfig, MAX_ADDRESSES,
    MAX_CONFIG_BYTES, MAX_FIREWALL_RULES, MAX_INTERFACES, MAX_INTERFACE_LABEL_BYTES, MAX_NEIGHBORS,
    MAX_ROUTES,
};
use ruster_core::{
    port_free_bitmap_words, DirectoryBucket, DirectoryNode, DynamicNeighborSlot, FirewallRuleId,
    FirewallStateSlot, Icmpv4ErrorActionSlot, Icmpv4ErrorStateSlot, Nat44TcpMappingSlot,
    Nat44TcpSessionSlot, Nat44TcpSynHoldSlot, Nat44UdpMappingSlot, Nat44UdpPeerSlot, PortOwnerSlot,
    ResolutionActionSlot, ResolutionFailureHoldSlot, ResolutionStateSlot, RouteError,
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
states = 5
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
unsolicited-syn-holds = 7

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
    max_quote_slots_per_table: 1_048_576,
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
                states: 5,
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
                hosts: 0,
            }),
            nat44_tcp: Some(ruster_config::Nat44TcpStorageShapeV1 {
                mappings: 3,
                sessions: 5,
                mapping_buckets: 4,
                mapping_nodes: 3,
                session_buckets: 8,
                session_nodes: 5,
                port_owners: 8,
                unsolicited_syn_holds: 7,
                hosts: 0,
                session_hosts: 0,
            }),
            nat44_icmp: None,
            firewall_states: Some(6),
            // `[fragmentation]` absent: on, 64 slots of 14 + 3826 bytes (the
            // longest datagram an AF_XDP frame carries, above every MTU here).
            fragmentation: Some(ruster_config::FragmentationStorageShapeV1 {
                datagrams: 64,
                slot_bytes: 3840,
            }),
            // `[fragment-tracking]` absent: `associate`, 256 entries (256
            // buckets per directory) and 64 held fragments sized like a
            // fragmentation slot (NAT-FRAG).
            fragment_tracking: Some(ruster_config::FragmentTrackingStorageShapeV1 {
                entries: 256,
                buckets: 256,
                held: 64,
                held_slot_bytes: 3840,
            }),
            required_bytes: shape.required_bytes,
        }
    );
    let expected = 2 * size_of::<ResolutionStateSlot>()
        + 3 * size_of::<ResolutionActionSlot>()
        + 4 * size_of::<DynamicNeighborSlot>()
        + 5 * size_of::<ResolutionFailureHoldSlot>()
        + 5 * size_of::<Icmpv4ErrorStateSlot>()
        + 3 * size_of::<Icmpv4ErrorActionSlot>()
        + 3 * size_of::<Nat44UdpMappingSlot>()
        + 5 * size_of::<Nat44UdpPeerSlot>()
        + (4 + 8) * size_of::<DirectoryBucket>()
        + (3 + 5) * size_of::<DirectoryNode>()
        + 8 * size_of::<PortOwnerSlot>()
        + 3 * size_of::<Nat44TcpMappingSlot>()
        + 5 * size_of::<Nat44TcpSessionSlot>()
        // mapping, session, and session remote-address directories
        + (4 + 8 + 8) * size_of::<DirectoryBucket>()
        + (3 + 5 + 5) * size_of::<DirectoryNode>()
        + 8 * size_of::<PortOwnerSlot>()
        // free-port bitmaps of the UDP and TCP port-owner indexes
        + 2 * port_free_bitmap_words(8) * size_of::<u64>()
        + 7 * size_of::<Nat44TcpSynHoldSlot>()
        + 6 * size_of::<FirewallStateSlot>()
        + 64 * (size_of::<ruster_core::Ipv4FragmentSlot>() + 3840)
        // fragment association: entries, hosts, two directories, held
        + 256
            * (size_of::<ruster_core::Ipv4FragmentEntrySlot>()
                + size_of::<ruster_core::Ipv4FragmentHostSlot>())
        + 2 * 256 * (size_of::<DirectoryBucket>() + size_of::<DirectoryNode>())
        + 64 * (size_of::<ruster_core::Ipv4FragmentHeldSlot>() + 3840);
    assert_eq!(shape.required_bytes, expected);

    assert!(validated_with(
        VALID,
        ValidationLimits {
            max_slots_per_table: 8,
            max_quote_slots_per_table: 8,
            max_runtime_bytes: expected,
        }
    )
    .is_ok());
    let bounded = validated_with(
        VALID,
        ValidationLimits {
            max_slots_per_table: 8,
            max_quote_slots_per_table: 8,
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
            max_quote_slots_per_table: 8,
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
            max_quote_slots_per_table: 8,
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
            max_quote_slots_per_table: u32::MAX,
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

#[test]
fn interface_labels_are_restricted_to_a_conservative_charset() {
    let at = |code, field: &'static str| {
        move |source: String| {
            let rejected = error(&source);
            assert_eq!(rejected.code(), code, "{source}");
            let segments = rejected.path().segments();
            assert_eq!(segments.last(), Some(&PathSegment::Field(field.to_owned())));
        }
    };
    let name = at(ValidationCode::InvalidInterfaceName, "name");
    let device = at(ValidationCode::InvalidDeviceName, "device");
    // A label crafted to forge a plan line and emit a terminal escape.
    let forged = r"wan device x -> name y\n  route - 0.0.0.0\u001b[31m";
    name(VALID.replace("name = \"wan\"", &format!("name = \"{forged}\"")));
    device(VALID.replace("device = \"eth1\"", &format!("device = \"{forged}\"")));
    for bad in [
        "a b", r"a\tb", "a/b", "a:b", "\u{e9}", "a->b", r"a\u0000", ".", "..", "-a", "-",
    ] {
        name(VALID.replace("name = \"wan\"", &format!("name = \"{bad}\"")));
        device(VALID.replace("device = \"eth1\"", &format!("device = \"{bad}\"")));
    }
    let long = "a".repeat(MAX_INTERFACE_LABEL_BYTES + 1);
    let rejected = error(&VALID.replace("device = \"eth1\"", &format!("device = \"{long}\"")));
    assert_eq!(rejected.code(), ValidationCode::InvalidDeviceName);
    assert_eq!(rejected.limit(), Some(15));
    assert_eq!(rejected.actual(), Some(16));

    let edge = "Aa0._-".to_owned() + &"z".repeat(MAX_INTERFACE_LABEL_BYTES - 6);
    // The renamed interface is also referenced by name elsewhere.
    let config = validated(
        &VALID
            .replace("\"wan\"", &format!("\"{edge}\""))
            .replace("device = \"eth1\"", &format!("device = \"{edge}\"")),
    );
    assert!(config
        .interfaces()
        .iter()
        .any(|binding| binding.name() == edge));
    assert!(config
        .interfaces()
        .iter()
        .any(|binding| binding.device() == edge));
}

#[test]
fn icmpv4_generation_switches_map_onto_core_policies() {
    use ruster_core::{Icmpv4ErrorKind, Icmpv4ErrorPolicy, Ipv4OriginPolicy};

    let defaults = validated(VALID);
    assert_eq!(defaults.ipv4_origin(), Ipv4OriginPolicy::default());
    assert!(defaults.ipv4_origin().echo_reply());
    let policy = defaults.icmpv4_errors().unwrap().policy();
    assert_eq!(policy, Icmpv4ErrorPolicy::new(100, 60_000).unwrap());

    let all_on_explicitly = VALID
        .replacen(
            "default-ttl = 64\n",
            "default-ttl = 64\necho-reply = true\n",
            1,
        )
        .replacen(
            "[icmpv4-errors.capacity]",
            "[icmpv4-errors.generate]\ntime-exceeded = true\nnet-unreachable = true\n\
             host-unreachable = true\n\n[icmpv4-errors.capacity]",
            1,
        );
    let explicit = validated(&all_on_explicitly);
    assert_eq!(explicit.ipv4_origin(), defaults.ipv4_origin());
    assert_eq!(
        explicit.icmpv4_errors().unwrap().policy(),
        defaults.icmpv4_errors().unwrap().policy()
    );

    let disabled = VALID
        .replacen(
            "default-ttl = 64\n",
            "default-ttl = 64\necho-reply = false\n",
            1,
        )
        .replacen(
            "[icmpv4-errors.capacity]",
            "[icmpv4-errors.generate]\nnet-unreachable = false\n\n[icmpv4-errors.capacity]",
            1,
        );
    let config = validated(&disabled);
    assert!(!config.ipv4_origin().echo_reply());
    assert_eq!(config.ipv4_origin().default_ttl(), 64);
    let policy = config.icmpv4_errors().unwrap().policy();
    assert!(policy.generates(Icmpv4ErrorKind::TimeExceededTtl));
    assert!(!policy.generates(Icmpv4ErrorKind::DestinationUnreachableNetwork));
    assert!(policy.generates(Icmpv4ErrorKind::DestinationUnreachableHost));
    assert_eq!((policy.interval_ms(), policy.state_ttl_ms()), (100, 60_000));
    // Storage shape is unaffected by a switch.
    assert_eq!(config.storage_shape(), defaults.storage_shape());

    // Policy validation still applies with switches present.
    assert_eq!(
        error(&disabled.replacen("interval-ms = 100\n", "interval-ms = 0\n", 1)).code(),
        ValidationCode::Icmpv4ErrorPolicy(ruster_core::Icmpv4ErrorPolicyError::IntervalZero)
    );
}

/// B3: the Port Unreachable limiter interval defaults to 1 s, is a policy
/// field (restart-required with the rest of the ICMPv4 error policy), and
/// must not be 0.
#[test]
fn icmpv4_port_unreachable_interval_maps_onto_the_core_policy() {
    use ruster_core::{
        Icmpv4ErrorPolicy, Icmpv4ErrorPolicyError, ICMPV4_DEFAULT_PORT_UNREACHABLE_INTERVAL_MS,
    };
    let with = |value: u64| {
        VALID.replacen(
            "state-ttl-ms = 60000

[icmpv4-errors.capacity]",
            &format!(
                "state-ttl-ms = 60000
port-unreachable-interval-ms = {value}

\
                 [icmpv4-errors.capacity]"
            ),
            1,
        )
    };
    let defaults = validated(VALID);
    let policy = defaults.icmpv4_errors().unwrap().policy();
    assert_eq!(
        policy.port_unreachable_interval_ms(),
        ICMPV4_DEFAULT_PORT_UNREACHABLE_INTERVAL_MS
    );
    assert_eq!(
        validated(&with(1_000)).icmpv4_errors().unwrap().policy(),
        policy
    );
    let slower = validated(&with(5_000));
    let slower = slower.icmpv4_errors().unwrap().policy();
    assert_eq!(slower.port_unreachable_interval_ms(), 5_000);
    assert_eq!(
        slower,
        Icmpv4ErrorPolicy::new(100, 60_000)
            .unwrap()
            .with_port_unreachable_interval_ms(5_000)
            .unwrap()
    );
    assert_eq!(slower.interval_ms(), 100, "the other kinds keep theirs");
    assert_eq!(
        error(&with(0)).code(),
        ValidationCode::Icmpv4ErrorPolicy(Icmpv4ErrorPolicyError::IntervalZero)
    );
}

/// NAT44-065: `[icmpv4-errors.translated]` is optional, defaults to the
/// core defaults, maps onto the restart-required ICMPv4 error policy, and
/// rejects 0 and values above the maximum at its own path.
#[test]
fn icmpv4_translated_limit_maps_onto_the_core_policy() {
    use ruster_core::{
        Icmpv4ErrorPolicy, Icmpv4ErrorPolicyError, ICMPV4_DEFAULT_TRANSLATED_BURST,
        ICMPV4_DEFAULT_TRANSLATED_RATE_PER_SECOND, ICMPV4_MAX_TRANSLATED_LIMIT,
    };
    let with = |table: &str| {
        VALID.replacen(
            "[icmpv4-errors.capacity]",
            &format!("[icmpv4-errors.translated]\n{table}\n\n[icmpv4-errors.capacity]"),
            1,
        )
    };
    let defaults = validated(VALID);
    let policy = defaults.icmpv4_errors().unwrap().policy();
    assert_eq!(
        (
            policy.translated_rate_per_second(),
            policy.translated_burst()
        ),
        (
            ICMPV4_DEFAULT_TRANSLATED_RATE_PER_SECOND,
            ICMPV4_DEFAULT_TRANSLATED_BURST
        )
    );
    assert_eq!(policy, Icmpv4ErrorPolicy::new(100, 60_000).unwrap());
    // An empty table and the defaults spelled out are the same policy.
    for table in ["", "rate-per-second = 100\nburst = 100"] {
        assert_eq!(
            validated(&with(table)).icmpv4_errors().unwrap().policy(),
            policy
        );
    }
    let custom = validated(&with("rate-per-second = 7\nburst = 3"));
    let custom = custom.icmpv4_errors().unwrap().policy();
    assert_eq!(
        custom,
        policy.with_translated_limit(7, 3).unwrap(),
        "only the translated limit changes"
    );
    assert_eq!(custom.interval_ms(), 100);
    let max = ICMPV4_MAX_TRANSLATED_LIMIT;
    let at_max = validated(&with(&format!("rate-per-second = {max}\nburst = {max}")));
    assert_eq!(
        at_max
            .icmpv4_errors()
            .unwrap()
            .policy()
            .translated_rate_per_second(),
        max
    );
    for table in [
        "rate-per-second = 0".to_owned(),
        "burst = 0".to_owned(),
        format!("rate-per-second = {}", max + 1),
        format!("burst = {}", max + 1),
    ] {
        let rejected = error(&with(&table));
        assert_eq!(
            rejected.code(),
            ValidationCode::Icmpv4ErrorPolicy(Icmpv4ErrorPolicyError::TranslatedLimitOutOfRange),
            "{table}"
        );
        assert_eq!(
            rejected.path().segments(),
            &[
                PathSegment::Field("icmpv4-errors".to_owned()),
                PathSegment::Field("translated".to_owned()),
            ],
            "{table}"
        );
    }
}

#[test]
fn nat44_filtering_maps_onto_core_policies_per_protocol() {
    use ruster_core::{Nat44Filtering, Nat44TcpPolicy, Nat44UdpPolicy};

    let defaults = validated(VALID);
    let nat = defaults.nat44().unwrap();
    let (udp, tcp) = (nat.udp().unwrap().policy(), nat.tcp().unwrap().policy());
    assert_eq!(udp.filtering(), Nat44Filtering::AddressDependent);
    assert_eq!(tcp.filtering(), Nat44Filtering::AddressDependent);
    // The absent key equals the core default policy apart from the
    // explicitly configured fields.
    assert_eq!(
        udp.filtering(),
        Nat44UdpPolicy::default().filtering(),
        "UDP default"
    );
    assert_eq!(
        tcp.filtering(),
        Nat44TcpPolicy::default().filtering(),
        "TCP default"
    );

    let edit = |udp: &str, tcp: &str| {
        VALID
            .replacen(
                "icmpv4-errors = \"external-only\"\n",
                &format!("icmpv4-errors = \"external-only\"\nfiltering = \"{udp}\"\n"),
                1,
            )
            .replacen(
                "icmpv4-errors = \"disabled\"\n",
                &format!("icmpv4-errors = \"disabled\"\nfiltering = \"{tcp}\"\n"),
                1,
            )
    };
    let explicit = validated(&edit("address-dependent", "address-dependent"));
    let explicit = explicit.nat44().unwrap();
    assert!(explicit.udp().unwrap().policy() == defaults.nat44().unwrap().udp().unwrap().policy());
    assert!(explicit.tcp().unwrap().policy() == defaults.nat44().unwrap().tcp().unwrap().policy());

    let mixed = validated(&edit("endpoint-independent", "address-and-port-dependent"));
    let nat = mixed.nat44().unwrap();
    let (udp, tcp) = (nat.udp().unwrap().policy(), nat.tcp().unwrap().policy());
    assert_eq!(udp.filtering(), Nat44Filtering::EndpointIndependent);
    assert_eq!(tcp.filtering(), Nat44Filtering::AddressAndPortDependent);
    // Only the filtering differs from the default policies.
    assert_eq!(
        udp.with_filtering(Nat44Filtering::AddressDependent),
        defaults.nat44().unwrap().udp().unwrap().policy()
    );
    assert_eq!(
        tcp.with_filtering(Nat44Filtering::AddressDependent),
        defaults.nat44().unwrap().tcp().unwrap().policy()
    );
    // Storage shape does not depend on the mode.
    assert_eq!(mixed.storage_shape(), defaults.storage_shape());

    // Policy validation still applies with the key present.
    assert_eq!(
        error(&mixed_text_with_short_ttl()).code(),
        ValidationCode::Nat44TcpPolicy(ruster_core::Nat44TcpPolicyError::IdleTtlTooShort)
    );

    fn mixed_text_with_short_ttl() -> String {
        VALID
            .replacen(
                "icmpv4-errors = \"disabled\"\n",
                "icmpv4-errors = \"disabled\"\nfiltering = \"endpoint-independent\"\n",
                1,
            )
            .replacen("idle-ttl-ms = 7440000\n", "idle-ttl-ms = 7439999\n", 1)
    }
}

#[test]
fn nat44_icmpv4_errors_map_onto_core_policies_per_protocol() {
    use ruster_core::{Nat44Icmpv4ErrorPolicy, Nat44TcpPolicy, Nat44UdpPolicy};

    // VALID spells both protocols out: UDP external-only, TCP disabled.
    let explicit = validated(VALID);
    let nat = explicit.nat44().unwrap();
    assert_eq!(
        nat.udp().unwrap().policy().icmpv4_errors(),
        Nat44Icmpv4ErrorPolicy::ExternalOnly
    );
    assert_eq!(
        nat.tcp().unwrap().policy().icmpv4_errors(),
        Nat44Icmpv4ErrorPolicy::Disabled
    );

    // Absent keys: bidirectional, equal to the core default.
    let defaults = validated(
        &VALID
            .replacen("icmpv4-errors = \"external-only\"\n", "", 1)
            .replacen("icmpv4-errors = \"disabled\"\n", "", 1),
    );
    let nat = defaults.nat44().unwrap();
    let (udp, tcp) = (nat.udp().unwrap().policy(), nat.tcp().unwrap().policy());
    assert_eq!(udp.icmpv4_errors(), Nat44Icmpv4ErrorPolicy::Bidirectional);
    assert_eq!(tcp.icmpv4_errors(), Nat44Icmpv4ErrorPolicy::Bidirectional);
    assert_eq!(
        Nat44UdpPolicy::default().icmpv4_errors(),
        Nat44Icmpv4ErrorPolicy::Bidirectional
    );
    assert_eq!(
        Nat44TcpPolicy::default().icmpv4_errors(),
        Nat44Icmpv4ErrorPolicy::Bidirectional
    );
    // Only the switch differs; storage shape does not depend on it.
    assert_eq!(
        udp.with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly),
        explicit.nat44().unwrap().udp().unwrap().policy()
    );
    assert_eq!(explicit.storage_shape(), defaults.storage_shape());

    for policy in Nat44Icmpv4ErrorPolicy::ALL {
        let spelled = validated(&VALID.replacen(
            "icmpv4-errors = \"disabled\"\n",
            &format!("icmpv4-errors = \"{}\"\n", policy.config_name()),
            1,
        ));
        assert_eq!(
            spelled
                .nat44()
                .unwrap()
                .tcp()
                .unwrap()
                .policy()
                .icmpv4_errors(),
            policy
        );
    }
}

#[test]
fn nat44_hairpinning_maps_onto_core_policies_per_protocol() {
    use ruster_core::{Nat44TcpPolicy, Nat44UdpPolicy};

    let defaults = validated(VALID);
    let nat = defaults.nat44().unwrap();
    let (udp, tcp) = (nat.udp().unwrap().policy(), nat.tcp().unwrap().policy());
    // Absent key: on, the RFC-conforming default, equal to the core default.
    assert!(udp.hairpinning() && tcp.hairpinning());
    assert!(Nat44UdpPolicy::default().hairpinning());
    assert!(Nat44TcpPolicy::default().hairpinning());

    let off = validated(
        &VALID
            .replacen(
                "icmpv4-errors = \"external-only\"\n",
                "icmpv4-errors = \"external-only\"\nhairpinning = false\n",
                1,
            )
            .replacen(
                "icmpv4-errors = \"disabled\"\n",
                "icmpv4-errors = \"disabled\"\nhairpinning = false\n",
                1,
            ),
    );
    let off_nat = off.nat44().unwrap();
    let (udp_off, tcp_off) = (
        off_nat.udp().unwrap().policy(),
        off_nat.tcp().unwrap().policy(),
    );
    assert!(!udp_off.hairpinning() && !tcp_off.hairpinning());
    // Only the switch differs; storage shape does not depend on it.
    assert_eq!(udp_off.with_hairpinning(true), udp);
    assert_eq!(tcp_off.with_hairpinning(true), tcp);
    assert_eq!(off.storage_shape(), defaults.storage_shape());
}

/// N2: `port-preservation` maps onto both core policies (default on, as
/// the core default) and does not change the storage shape.
#[test]
fn nat44_port_preservation_maps_onto_core_without_changing_storage() {
    use ruster_core::{Nat44TcpPolicy, Nat44UdpPolicy};
    const UDP: &str = "icmpv4-errors = \"external-only\"\n";
    const TCP: &str = "icmpv4-errors = \"disabled\"\n";
    let on = validated(VALID);
    let nat = on.nat44().unwrap();
    assert!(nat.udp().unwrap().policy().port_preservation());
    assert!(nat.tcp().unwrap().policy().port_preservation());
    assert!(Nat44UdpPolicy::default().port_preservation());
    assert!(Nat44TcpPolicy::default().port_preservation());
    let off = validated(
        &VALID
            .replacen(UDP, &format!("{UDP}port-preservation = false\n"), 1)
            .replacen(TCP, &format!("{TCP}port-preservation = false\n"), 1),
    );
    let off_nat = off.nat44().unwrap();
    let (udp_off, tcp_off) = (
        off_nat.udp().unwrap().policy(),
        off_nat.tcp().unwrap().policy(),
    );
    assert!(!udp_off.port_preservation() && !tcp_off.port_preservation());
    assert_eq!(
        udp_off.with_port_preservation(true),
        nat.udp().unwrap().policy()
    );
    assert_eq!(
        tcp_off.with_port_preservation(true),
        nat.tcp().unwrap().policy()
    );
    assert_eq!(off.storage_shape(), on.storage_shape());
}

/// N3: `mappings-per-host` maps onto both core policies (default `0`, as
/// the core default). A nonzero limit adds per-host storage sized from the
/// protocol's mapping capacity (one host link, host slot, and directory
/// node per mapping slot, and the mapping directory's bucket count), which
/// `required_bytes` counts exactly; the limit's value does not change the
/// shape beyond that, and the per-table byte limit still applies.
#[test]
fn nat44_mappings_per_host_maps_onto_core_and_sizes_host_storage() {
    use ruster_core::{
        DirectoryBucket, DirectoryNode, Nat44HostLink, Nat44TcpHostSlot, Nat44TcpPolicy,
        Nat44UdpHostSlot, Nat44UdpPolicy, NAT44_DEFAULT_MAPPINGS_PER_HOST,
    };
    const UDP: &str = "icmpv4-errors = \"external-only\"\n";
    const TCP: &str = "icmpv4-errors = \"disabled\"\n";
    let with_limits = |udp: u16, tcp: u16| {
        VALID
            .replacen(UDP, &format!("{UDP}mappings-per-host = {udp}\n"), 1)
            .replacen(TCP, &format!("{TCP}mappings-per-host = {tcp}\n"), 1)
    };
    let defaults = validated(VALID);
    let nat = defaults.nat44().unwrap();
    assert_eq!(NAT44_DEFAULT_MAPPINGS_PER_HOST, 0);
    assert_eq!(nat.udp().unwrap().policy().mappings_per_host(), 0);
    assert_eq!(nat.tcp().unwrap().policy().mappings_per_host(), 0);
    assert_eq!(Nat44UdpPolicy::default().mappings_per_host(), 0);
    assert_eq!(Nat44TcpPolicy::default().mappings_per_host(), 0);
    let shape = defaults.storage_shape();
    assert_eq!(shape.nat44_udp.unwrap().hosts, 0);
    assert_eq!(shape.nat44_tcp.unwrap().hosts, 0);
    // Explicit zero is the default.
    assert_eq!(validated(&with_limits(0, 0)).storage_shape(), shape);

    let limited = validated(&with_limits(2, 3));
    let limited_nat = limited.nat44().unwrap();
    let (udp, tcp) = (
        limited_nat.udp().unwrap().policy(),
        limited_nat.tcp().unwrap().policy(),
    );
    assert_eq!((udp.mappings_per_host(), tcp.mappings_per_host()), (2, 3));
    assert_eq!(udp.with_mappings_per_host(0), nat.udp().unwrap().policy());
    assert_eq!(tcp.with_mappings_per_host(0), nat.tcp().unwrap().policy());
    let limited_shape = limited.storage_shape();
    let (udp_shape, tcp_shape) = (
        limited_shape.nat44_udp.unwrap(),
        limited_shape.nat44_tcp.unwrap(),
    );
    assert_eq!((udp_shape.hosts, tcp_shape.hosts), (3, 3));
    // UDP and TCP: 3 mapping slots, a 4-bucket mapping directory.
    // UDP also has a link word and a peer counter per slot (N6).
    let host_bytes = 3 * (2 * size_of::<Nat44HostLink>() + 2 * size_of::<DirectoryNode>())
        + 3 * (size_of::<Nat44UdpHostSlot>() + size_of::<Nat44TcpHostSlot>())
        + 3 * (size_of::<u32>() + size_of::<ruster_core::Nat44HostCounter>())
        + 2 * 4 * size_of::<DirectoryBucket>();
    assert_eq!(
        limited_shape.required_bytes,
        shape.required_bytes + host_bytes
    );
    // Only the switch between zero and a limit changes the shape.
    assert_eq!(
        validated(&with_limits(65_535, 1)).storage_shape(),
        limited_shape
    );
    let udp_only = validated(&with_limits(5, 0)).storage_shape();
    assert_eq!(
        (
            udp_only.nat44_udp.unwrap().hosts,
            udp_only.nat44_tcp.unwrap().hosts
        ),
        (3, 0)
    );
    // The byte limit counts the host storage (fail closed).
    let tight = ValidationLimits {
        max_runtime_bytes: shape.required_bytes,
        ..GENEROUS
    };
    assert!(validated_with(VALID, tight).is_ok());
    let error = validated_with(&with_limits(2, 3), tight)
        .err()
        .expect("host storage exceeds the byte limit");
    assert_eq!(
        error.code(),
        ruster_config::ValidationCode::RuntimeStorageBytesExceeded
    );
}

/// N6: `peers-per-host` (UDP) and `sessions-per-host` (TCP) map onto the
/// core policies (default `0`). A UDP peer limit needs the same per-host
/// storage as a UDP mapping limit (each with a link word and a host
/// counter), so with a mapping limit already set it does not change the
/// shape; a TCP session limit adds per-session host storage (one host link,
/// link word, host slot with three lists, and directory node per session
/// slot, and the session directory's bucket count). `required_bytes`
/// counts it all exactly, and only switching storage on or off changes the
/// shape.
#[test]
fn nat44_peer_and_session_limits_map_onto_core_and_size_their_storage() {
    use ruster_core::{
        DirectoryBucket, DirectoryNode, Nat44HostCounter, Nat44HostLink, Nat44TcpPolicy,
        Nat44TcpSessionHostSlot, Nat44UdpHostSlot, Nat44UdpPolicy, NAT44_DEFAULT_STATE_PER_HOST,
    };
    const UDP: &str = "icmpv4-errors = \"external-only\"\n";
    const TCP: &str = "icmpv4-errors = \"disabled\"\n";
    let with = |udp: &str, tcp: &str| {
        VALID
            .replacen(UDP, &format!("{UDP}{udp}"), 1)
            .replacen(TCP, &format!("{TCP}{tcp}"), 1)
    };
    let defaults = validated(VALID);
    let nat = defaults.nat44().unwrap();
    assert_eq!(NAT44_DEFAULT_STATE_PER_HOST, 0);
    assert_eq!(nat.udp().unwrap().policy().peers_per_host(), 0);
    assert_eq!(nat.tcp().unwrap().policy().sessions_per_host(), 0);
    assert_eq!(Nat44UdpPolicy::default().peers_per_host(), 0);
    assert_eq!(Nat44TcpPolicy::default().sessions_per_host(), 0);
    let shape = defaults.storage_shape();
    assert_eq!(shape.nat44_tcp.unwrap().session_hosts, 0);
    assert_eq!(
        validated(&with("peers-per-host = 0\n", "sessions-per-host = 0\n")).storage_shape(),
        shape
    );

    let limited = validated(&with("peers-per-host = 4\n", "sessions-per-host = 5\n"));
    let limited_nat = limited.nat44().unwrap();
    let (udp, tcp) = (
        limited_nat.udp().unwrap().policy(),
        limited_nat.tcp().unwrap().policy(),
    );
    assert_eq!((udp.peers_per_host(), tcp.sessions_per_host()), (4, 5));
    assert_eq!(udp.with_peers_per_host(0), nat.udp().unwrap().policy());
    assert_eq!(tcp.with_sessions_per_host(0), nat.tcp().unwrap().policy());
    let limited_shape = limited.storage_shape();
    let (udp_shape, tcp_shape) = (
        limited_shape.nat44_udp.unwrap(),
        limited_shape.nat44_tcp.unwrap(),
    );
    // UDP: 3 mapping slots, a 4-bucket mapping directory; TCP: 5 session
    // slots, an 8-bucket session directory; no TCP mapping host storage.
    assert_eq!(
        (udp_shape.hosts, tcp_shape.hosts, tcp_shape.session_hosts),
        (3, 0, 5)
    );
    let udp_bytes = 3
        * (size_of::<Nat44HostLink>()
            + size_of::<Nat44UdpHostSlot>()
            + size_of::<u32>()
            + size_of::<Nat44HostCounter>()
            + size_of::<DirectoryNode>())
        + 4 * size_of::<DirectoryBucket>();
    let tcp_bytes = 5
        * (size_of::<Nat44HostLink>()
            + size_of::<Nat44TcpSessionHostSlot>()
            + size_of::<u32>()
            + size_of::<DirectoryNode>())
        + 8 * size_of::<DirectoryBucket>();
    assert_eq!(
        limited_shape.required_bytes,
        shape.required_bytes + udp_bytes + tcp_bytes
    );
    // Other nonzero values keep the shape (reloadable).
    assert_eq!(
        validated(&with("peers-per-host = 65535\n", "sessions-per-host = 1\n")).storage_shape(),
        limited_shape
    );
    // A UDP peer limit next to a mapping limit shares its storage.
    let mapping_limit = validated(&with("mappings-per-host = 2\n", "")).storage_shape();
    assert_eq!(
        validated(&with("mappings-per-host = 2\npeers-per-host = 9\n", "")).storage_shape(),
        mapping_limit
    );
    // The byte limit counts the storage (fail closed).
    let tight = ValidationLimits {
        max_runtime_bytes: shape.required_bytes + udp_bytes,
        ..GENEROUS
    };
    assert!(validated_with(&with("peers-per-host = 4\n", ""), tight).is_ok());
    let error = validated_with(&with("", "sessions-per-host = 5\n"), tight)
        .err()
        .expect("session host storage exceeds the byte limit");
    assert_eq!(
        error.code(),
        ruster_config::ValidationCode::RuntimeStorageBytesExceeded
    );
}

/// B3: the switch maps onto the core TCP policy without changing the
/// storage shape; the hold capacity is a quote table (bounded by
/// `max_quote_slots_per_table`) counted in `required_bytes`.
#[test]
fn nat44_unsolicited_syn_switch_and_holds_map_onto_core_and_storage() {
    use ruster_config::ValidationCode;
    use ruster_core::Nat44TcpPolicy;
    const TCP: &str = "icmpv4-errors = \"disabled\"\n";

    let on = validated(VALID);
    let tcp_on = on.nat44().unwrap().tcp().unwrap().policy();
    assert!(tcp_on.unsolicited_syn_icmp());
    assert!(Nat44TcpPolicy::default().unsolicited_syn_icmp());
    let off = validated(&VALID.replacen(TCP, &format!("{TCP}unsolicited-syn-icmp = false\n"), 1));
    let tcp_off = off.nat44().unwrap().tcp().unwrap().policy();
    assert!(!tcp_off.unsolicited_syn_icmp());
    assert_eq!(tcp_off.with_unsolicited_syn_icmp(true), tcp_on);
    assert_eq!(off.storage_shape(), on.storage_shape());

    let holds = |value: u32| {
        VALID.replacen(
            "unsolicited-syn-holds = 7\n",
            &format!("unsolicited-syn-holds = {value}\n"),
            1,
        )
    };
    let bytes = |value: u32| validated(&holds(value)).storage_shape().required_bytes;
    assert_eq!(bytes(8) - bytes(7), size_of::<Nat44TcpSynHoldSlot>());
    assert_eq!(
        validated(&holds(0))
            .storage_shape()
            .nat44_tcp
            .unwrap()
            .unsolicited_syn_holds,
        0
    );
    let limits = ValidationLimits {
        max_slots_per_table: 1 << 16,
        max_quote_slots_per_table: 8,
        max_runtime_bytes: 1 << 30,
    };
    assert!(validated_with(&holds(8), limits).is_ok());
    let refused = validated_with(&holds(9), limits)
        .err()
        .expect("over the quote limit");
    assert_eq!(refused.code(), ValidationCode::CapacityLimitExceeded);
    assert_eq!(
        refused.path().segments(),
        ["nat44", "tcp", "capacity", "unsolicited-syn-holds"]
            .map(|field| ruster_config::PathSegment::Field(field.to_owned()))
    );
}

/// While the TCP NAT can send delayed Port Unreachable errors, the ICMPv4
/// limiter needs one state per interface plus one for the Port Unreachable
/// class on the outside egress; fewer is refused with a value-free code at
/// the states path. With the switch off or no holds, any size is accepted.
#[test]
fn icmpv4_states_must_cover_every_interface_plus_port_unreachable() {
    const TCP: &str = "icmpv4-errors = \"disabled\"\n";
    // VALID has two interfaces: two classes each (MTU1: Fragmentation
    // Needed has its own) plus the Port Unreachable class.
    let states = |source: &str, value: u32| {
        source.replacen(
            "[icmpv4-errors.capacity]\nstates = 5\n",
            &format!("[icmpv4-errors.capacity]\nstates = {value}\n"),
            1,
        )
    };
    validated(&states(VALID, 5));
    let refused = error(&states(VALID, 4));
    assert_eq!(
        refused.code(),
        ValidationCode::Icmpv4ErrorStatesTooFewForPortUnreachable
    );
    assert_eq!(
        refused.code().code(),
        "ICMPV4_ERROR_STATES_TOO_FEW_FOR_PORT_UNREACHABLE"
    );
    assert_eq!(
        refused.path().segments(),
        ["icmpv4-errors", "capacity", "states"]
            .map(|field| ruster_config::PathSegment::Field(field.to_owned()))
    );
    assert_eq!((refused.limit(), refused.actual()), (None, None));
    // Fewer than two per interface: refused for Fragmentation Needed.
    let refused = error(&states(VALID, 3));
    assert_eq!(
        refused.code(),
        ValidationCode::Icmpv4ErrorStatesTooFewForFragmentationNeeded
    );
    assert_eq!(
        refused.code().code(),
        "ICMPV4_ERROR_STATES_TOO_FEW_FOR_FRAGMENTATION_NEEDED"
    );
    assert_eq!(
        refused.path().segments(),
        ["icmpv4-errors", "capacity", "states"]
            .map(|field| ruster_config::PathSegment::Field(field.to_owned()))
    );
    // No Port Unreachable can be sent: two per interface are enough.
    let off = VALID.replacen(TCP, &format!("{TCP}unsolicited-syn-icmp = false\n"), 1);
    validated(&states(&off, 4));
    let no_holds = VALID.replacen(
        "unsolicited-syn-holds = 7\n",
        "unsolicited-syn-holds = 0\n",
        1,
    );
    validated(&states(&no_holds, 4));
    // Fragmentation Needed off: one per interface plus Port Unreachable.
    let frag_off = VALID.replacen(
        "[icmpv4-errors.capacity]",
        "[icmpv4-errors.generate]\nfragmentation-needed = false\n\n[icmpv4-errors.capacity]",
        1,
    );
    validated(&states(&frag_off, 3));
    assert_eq!(
        error(&states(&frag_off, 2)).code(),
        ValidationCode::Icmpv4ErrorStatesTooFewForPortUnreachable
    );
    let both_off = frag_off.replacen(TCP, &format!("{TCP}unsolicited-syn-icmp = false\n"), 1);
    validated(&states(&both_off, 2));
}

#[test]
fn nat44_tcp_inbound_sessions_per_remote_maps_onto_the_core_policy() {
    use ruster_core::{
        Nat44TcpPolicy, Nat44TcpPolicyError, NAT44_TCP_DEFAULT_INBOUND_SESSIONS_PER_REMOTE,
    };
    const TCP: &str = "icmpv4-errors = \"disabled\"\n";
    let with = |value: &str| {
        VALID.replacen(
            TCP,
            &format!("{TCP}inbound-sessions-per-remote = {value}\n"),
            1,
        )
    };

    let defaults = validated(VALID);
    let tcp = defaults.nat44().unwrap().tcp().unwrap().policy();
    // Absent key: the documented default, equal to the core default.
    assert_eq!(
        tcp.inbound_sessions_per_remote(),
        NAT44_TCP_DEFAULT_INBOUND_SESSIONS_PER_REMOTE
    );
    assert_eq!(
        Nat44TcpPolicy::default().inbound_sessions_per_remote(),
        NAT44_TCP_DEFAULT_INBOUND_SESSIONS_PER_REMOTE
    );
    for limit in [0_u8, 1, 16] {
        let config = validated(&with(&limit.to_string()));
        let policy = config.nat44().unwrap().tcp().unwrap().policy();
        assert_eq!(policy.inbound_sessions_per_remote(), limit);
        // Only the limit differs, and storage does not depend on it.
        assert_eq!(
            policy
                .with_inbound_sessions_per_remote(NAT44_TCP_DEFAULT_INBOUND_SESSIONS_PER_REMOTE)
                .unwrap(),
            tcp
        );
        assert_eq!(config.storage_shape(), defaults.storage_shape());
    }
    for limit in [17_u8, 255] {
        let error = error(&with(&limit.to_string()));
        assert_eq!(
            error.code(),
            ValidationCode::Nat44TcpPolicy(Nat44TcpPolicyError::InboundSessionsPerRemoteTooLarge)
        );
        assert_eq!(error.code().code(), "NAT44_TCP_POLICY");
        assert_eq!(
            error.path().segments(),
            &[
                PathSegment::Field("nat44".to_owned()),
                PathSegment::Field("tcp".to_owned()),
                PathSegment::Field("inbound-sessions-per-remote".to_owned()),
            ]
        );
    }
}

/// N1: the opening and closing idle timeouts map onto the core policy,
/// default to the RFC 5382 REQ-5 transitory floor, and are refused below it
/// or above the established timeout with a typed, value-free error at the
/// key's path. Storage does not depend on them.
#[test]
fn nat44_tcp_transitory_idle_ttls_map_onto_the_core_policy() {
    use ruster_core::{
        Nat44TcpPolicyError, Nat44TcpSessionPhase, NAT44_TCP_MIN_TRANSITORY_IDLE_TTL_MS,
    };
    const TCP: &str = "icmpv4-errors = \"disabled\"\n";
    let with = |key: &str, value: u64| VALID.replacen(TCP, &format!("{TCP}{key} = {value}\n"), 1);

    let defaults = validated(VALID);
    let policy = defaults.nat44().unwrap().tcp().unwrap().policy();
    assert_eq!(policy.opening_idle_ttl_ms(), 240_000);
    assert_eq!(policy.closing_idle_ttl_ms(), 240_000);
    assert_eq!(
        policy.session_idle_ttl_ms(Nat44TcpSessionPhase::Established),
        policy.idle_ttl_ms()
    );
    let established = policy.idle_ttl_ms();
    for key in ["opening-idle-ttl-ms", "closing-idle-ttl-ms"] {
        for value in [NAT44_TCP_MIN_TRANSITORY_IDLE_TTL_MS, 300_000, established] {
            let config = validated(&with(key, value));
            let policy = config.nat44().unwrap().tcp().unwrap().policy();
            let (set, other) = if key.starts_with("opening") {
                (policy.opening_idle_ttl_ms(), policy.closing_idle_ttl_ms())
            } else {
                (policy.closing_idle_ttl_ms(), policy.opening_idle_ttl_ms())
            };
            assert_eq!((set, other), (value, 240_000), "{key}");
            assert_eq!(config.storage_shape(), defaults.storage_shape());
        }
        for (value, refusal) in [
            (0, Nat44TcpPolicyError::TransitoryIdleTtlTooShort),
            (
                NAT44_TCP_MIN_TRANSITORY_IDLE_TTL_MS - 1,
                Nat44TcpPolicyError::TransitoryIdleTtlTooShort,
            ),
            (
                established + 1,
                Nat44TcpPolicyError::TransitoryIdleTtlAboveEstablished,
            ),
            (
                i64::MAX as u64,
                Nat44TcpPolicyError::TransitoryIdleTtlAboveEstablished,
            ),
        ] {
            let error = error(&with(key, value));
            assert_eq!(
                error.code(),
                ValidationCode::Nat44TcpPolicy(refusal),
                "{key}"
            );
            assert_eq!(error.code().code(), "NAT44_TCP_POLICY");
            assert_eq!(
                error.path().segments(),
                &[
                    PathSegment::Field("nat44".to_owned()),
                    PathSegment::Field("tcp".to_owned()),
                    PathSegment::Field(key.to_owned()),
                ]
            );
        }
    }
}

/// N1: `inbound-rst` maps onto the core policy and does not change storage.
#[test]
fn nat44_tcp_inbound_rst_maps_onto_the_core_policy() {
    use ruster_core::Nat44TcpInboundRst;
    const TCP: &str = "icmpv4-errors = \"disabled\"\n";
    let defaults = validated(VALID);
    let policy = defaults.nat44().unwrap().tcp().unwrap().policy();
    assert_eq!(policy.inbound_rst(), Nat44TcpInboundRst::Closing);
    let strict =
        validated(&VALID.replacen(TCP, &format!("{TCP}inbound-rst = \"corroborate\"\n"), 1));
    let strict_policy = strict.nat44().unwrap().tcp().unwrap().policy();
    assert_eq!(strict_policy.inbound_rst(), Nat44TcpInboundRst::Corroborate);
    assert_eq!(
        strict_policy.with_inbound_rst(Nat44TcpInboundRst::Closing),
        policy
    );
    assert_eq!(strict.storage_shape(), defaults.storage_shape());
}

/// `[arp]` maps onto the core ARP policy: absent or empty is RFC 826 (no
/// on-link condition on the sender), `require-on-link-sender = true` opts
/// into ARP-031.
#[test]
fn arp_policy_maps_onto_the_core_policy() {
    use ruster_core::ArpPolicy;

    let defaults = validated(VALID);
    assert_eq!(defaults.arp(), ArpPolicy::RFC826);
    let with = |body: &str| {
        VALID.replacen(
            "[resolution.policy]",
            &format!("[arp]\n{body}\n[resolution.policy]"),
            1,
        )
    };
    assert_eq!(validated(&with("")).arp(), ArpPolicy::RFC826);
    assert_eq!(
        validated(&with("require-on-link-sender = false\n")).arp(),
        ArpPolicy::RFC826
    );
    assert_eq!(
        validated(&with("require-on-link-sender = true\n")).arp(),
        ArpPolicy::RFC826.with_require_on_link_sender(true)
    );
}

/// N5: `[nat44.icmp]` maps onto the core ICMP query policy with RFC 5508
/// defaults (60 s, address-dependent, identifier preservation, errors
/// bidirectional), the identifier pool defaults to the realm ports, and its
/// storage (engine tables plus one owner slot per identifier) is counted
/// exactly.
#[test]
fn nat44_icmp_section_maps_onto_core_with_rfc5508_defaults_and_exact_storage() {
    use ruster_config::{Nat44IcmpStorageShapeV1, ValidationCode};
    use ruster_core::{
        DirectoryBucket, DirectoryNode, Nat44Filtering, Nat44IcmpConfigError, Nat44IcmpPolicy,
        Nat44IcmpPolicyError, Nat44Icmpv4ErrorPolicy, Nat44UdpMappingSlot, Nat44UdpPeerSlot,
        PortOwnerSlot,
    };
    const SECTION: &str = "\n[nat44.icmp.capacity]\nmappings = 3\npeers = 5\n";
    let with = |keys: &str, extra: &str| {
        VALID.replacen(
            "[firewall.policy]",
            &format!("[nat44.icmp]\n{keys}{extra}{SECTION}\n[firewall.policy]"),
            1,
        )
    };
    let base = validated(VALID);
    assert!(base.nat44().unwrap().icmp().is_none());
    assert_eq!(base.storage_shape().nat44_icmp, None);

    let config = validated(&with("", ""));
    let icmp = config.nat44().unwrap().icmp().unwrap();
    assert_eq!(icmp.policy(), Nat44IcmpPolicy::default());
    assert_eq!(icmp.policy().idle_ttl_ms(), 60_000);
    assert_eq!(icmp.policy().filtering(), Nat44Filtering::AddressDependent);
    assert!(icmp.policy().identifier_preservation());
    assert_eq!(
        icmp.policy().icmpv4_errors(),
        Nat44Icmpv4ErrorPolicy::Bidirectional
    );
    assert_eq!(
        (icmp.first_identifier(), icmp.last_identifier()),
        (40_000, 40_007)
    );
    assert_eq!((icmp.inside().0, icmp.outside().0), (1, 2));
    let shape = config.storage_shape();
    assert_eq!(
        shape.nat44_icmp,
        Some(Nat44IcmpStorageShapeV1 {
            mappings: 3,
            peers: 5,
            mapping_buckets: 4,
            mapping_nodes: 3,
            peer_buckets: 8,
            peer_nodes: 5,
            identifier_owners: 8,
            hosts: 0,
        })
    );
    let icmp_bytes = 3 * size_of::<Nat44UdpMappingSlot>()
        + 5 * size_of::<Nat44UdpPeerSlot>()
        + (4 + 8) * size_of::<DirectoryBucket>()
        + (3 + 5) * size_of::<DirectoryNode>()
        + 8 * size_of::<PortOwnerSlot>()
        + ruster_core::port_free_bitmap_words(8) * size_of::<u64>();
    assert_eq!(
        shape.required_bytes,
        base.storage_shape().required_bytes + icmp_bytes
    );

    let tuned = validated(&with(
        "idle-ttl-ms = 90000\nallocator-seed = \"9\"\nfiltering = \"endpoint-independent\"\n\
         icmpv4-errors = \"external-only\"\nidentifier-preservation = false\n\
         mappings-per-host = 4\n",
        "\n[nat44.icmp.identifiers]\nfirst = 1\nlast = 65535\n",
    ));
    let icmp = tuned.nat44().unwrap().icmp().unwrap();
    let policy = icmp.policy();
    assert_eq!(policy.idle_ttl_ms(), 90_000);
    assert_eq!(policy.allocator_seed(), 9);
    assert_eq!(policy.filtering(), Nat44Filtering::EndpointIndependent);
    assert_eq!(policy.icmpv4_errors(), Nat44Icmpv4ErrorPolicy::ExternalOnly);
    assert!(!policy.identifier_preservation());
    assert_eq!(policy.mappings_per_host(), 4);
    assert_eq!(
        (icmp.first_identifier(), icmp.last_identifier()),
        (1, 65_535)
    );
    let tuned_shape = tuned.storage_shape().nat44_icmp.unwrap();
    assert_eq!(
        (tuned_shape.identifier_owners, tuned_shape.hosts),
        (65_535, 3)
    );

    let cases = [
        (
            "idle-ttl-ms = 59999\n",
            "",
            ValidationCode::Nat44IcmpPolicy(Nat44IcmpPolicyError::IdleTtlTooShort),
            "nat44.icmp.idle-ttl-ms",
        ),
        (
            "filtering = \"address-and-port-dependent\"\n",
            "",
            ValidationCode::Nat44IcmpPolicy(Nat44IcmpPolicyError::FilteringNeedsPorts),
            "nat44.icmp.filtering",
        ),
        (
            "allocator-seed = \"07\"\n",
            "",
            ValidationCode::NonCanonicalAllocatorSeed,
            "nat44.icmp.allocator-seed",
        ),
        (
            "",
            "\n[nat44.icmp.identifiers]\nfirst = 0\nlast = 10\n",
            ValidationCode::Nat44IcmpConfig(Nat44IcmpConfigError::IdentifierPoolIncludesZero),
            "nat44.icmp.identifiers",
        ),
        (
            "",
            "\n[nat44.icmp.identifiers]\nfirst = 10\nlast = 9\n",
            ValidationCode::Nat44IcmpConfig(Nat44IcmpConfigError::IdentifierPoolReversed),
            "nat44.icmp.identifiers",
        ),
    ];
    for (keys, extra, code, field) in cases {
        let rejected = error(&with(keys, extra));
        assert_eq!(rejected.code(), code, "{keys}{extra}");
        assert_eq!(dotted(rejected.path()), field, "{keys}{extra}");
    }
    // The identifier pool is a bounded table.
    let tight = ValidationLimits {
        max_slots_per_table: 1_024,
        ..GENEROUS
    };
    let bounded = validated_with(
        &with("", "\n[nat44.icmp.identifiers]\nfirst = 1\nlast = 2048\n"),
        tight,
    )
    .err()
    .unwrap();
    assert_eq!(bounded.code(), ValidationCode::CapacityLimitExceeded);
    assert_eq!(dotted(bounded.path()), "nat44.icmp.identifiers");
}

/// N5: `protocol = "icmp"` firewall rules have no ports; TCP and UDP rules
/// still need both ranges.
#[test]
fn firewall_icmp_rules_have_no_ports_and_tcp_udp_rules_need_them() {
    use ruster_config::ValidationCode;
    use ruster_core::FirewallProtocol;
    const ICMP_RULE: &str = "[[firewall.rules]]\nid = 3\ningress = \"lan\"\negress = \"wan\"\n\
        source = \"192.0.2.0/24\"\ndestination = \"0.0.0.0/0\"\nprotocol = \"icmp\"\n\
        action = \"allow-stateful\"\n\n";
    let with_rule = |rule: &str| VALID.replacen("[tick]", &format!("{rule}[tick]"), 1);
    let config = validated(&with_rule(ICMP_RULE));
    let rule = config.firewall().unwrap().rules()[2];
    assert_eq!(rule.protocol(), FirewallProtocol::Icmp);
    assert_eq!(
        (rule.source_ports().first(), rule.source_ports().last()),
        (0, 65_535)
    );
    assert_eq!(
        (
            rule.destination_ports().first(),
            rule.destination_ports().last()
        ),
        (0, 65_535)
    );
    let with_ports = with_rule(&format!(
        "{ICMP_RULE}[firewall.rules.source-ports]\nfirst = 0\nlast = 65535\n\n"
    ));
    let rejected = error(&with_ports);
    assert_eq!(rejected.code(), ValidationCode::FirewallIcmpRulePorts);
    assert_eq!(dotted(rejected.path()), "firewall.rules[2].source-ports");
    let udp_without_ports = with_rule(&ICMP_RULE.replace("\"icmp\"", "\"udp\""));
    let rejected = error(&udp_without_ports);
    assert_eq!(rejected.code(), ValidationCode::FirewallRulePortsRequired);
    assert_eq!(dotted(rejected.path()), "firewall.rules[2].source-ports");
}

/// `a.b[2].c` spelling of a source path, for compact assertions.
fn dotted(path: &ruster_config::SourcePath) -> String {
    let mut text = String::new();
    for segment in path.segments() {
        match segment {
            PathSegment::Field(name) => {
                if !text.is_empty() {
                    text.push('.');
                }
                text.push_str(name);
            }
            PathSegment::Index(index) => text.push_str(&format!("[{index}]")),
            _ => text.push('?'),
        }
    }
    text
}

/// MTU1: `[[interfaces]] mtu` defaults to the Ethernet MTU 1500, accepts 68
/// (RFC 791) to 65535, reaches the core interface, and is refused outside
/// that range at its own path. `fragmentation-needed` is a generation
/// switch like the others.
#[test]
fn interface_mtu_defaults_to_1500_and_is_bounded_by_rfc791() {
    use ruster_core::{Icmpv4ErrorKind, IfId, ETHERNET_DEFAULT_MTU, IPV4_MIN_MTU};

    let defaults = validated(VALID);
    assert!(defaults
        .core_interfaces()
        .iter()
        .all(|interface| interface.mtu == ETHERNET_DEFAULT_MTU));
    assert!(defaults
        .interfaces()
        .iter()
        .all(|binding| binding.mtu() == ETHERNET_DEFAULT_MTU));
    let policy = defaults.icmpv4_errors().unwrap().policy();
    assert!(policy.generates(Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded));

    let with_mtu = |mtu: u64| {
        VALID.replacen(
            "mac = \"02:00:00:00:00:01\"\n",
            &format!("mac = \"02:00:00:00:00:01\"\nmtu = {mtu}\n"),
            1,
        )
    };
    let mtu_of = |config: &ValidatedConfigV1, id: u16| {
        config
            .core_interfaces()
            .iter()
            .find(|interface| interface.id == IfId(id))
            .unwrap()
            .mtu
    };
    for mtu in [u64::from(IPV4_MIN_MTU), 1400, 9000, 65_535] {
        let config = validated(&with_mtu(mtu));
        assert_eq!(u64::from(mtu_of(&config, 1)), mtu);
        assert_eq!(mtu_of(&config, 2), ETHERNET_DEFAULT_MTU);
        // Only the fragmentation slots follow the largest MTU (MTU2 part B).
        let shape = config.storage_shape();
        let slot_bytes = 14 + u32::try_from(mtu.max(3826)).unwrap();
        assert_eq!(
            shape.fragmentation.map(|slots| slots.slot_bytes),
            Some(slot_bytes)
        );
        let without_fragmentation =
            |shape: ruster_config::RuntimeStorageShapeV1| ruster_config::RuntimeStorageShapeV1 {
                fragmentation: None,
                fragment_tracking: None,
                required_bytes: 0,
                ..shape
            };
        assert_eq!(
            without_fragmentation(shape),
            without_fragmentation(defaults.storage_shape())
        );
        assert_eq!(
            i64::try_from(shape.required_bytes).unwrap()
                - i64::try_from(defaults.storage_shape().required_bytes).unwrap(),
            // 64 fragmentation slots and 64 held fragments (NAT-FRAG).
            2 * 64 * (i64::from(slot_bytes) - 3840)
        );
    }
    for mtu in [0, 67, 65_536, u64::from(u32::MAX)] {
        let rejected = error(&with_mtu(mtu));
        assert_eq!(
            rejected.code(),
            ValidationCode::InterfaceMtuOutOfRange,
            "{mtu}"
        );
        assert_eq!(rejected.code().code(), "INTERFACE_MTU_OUT_OF_RANGE");
        assert_eq!(dotted(rejected.path()), "interfaces[1].mtu", "{mtu}");
    }

    let off = VALID.replacen(
        "[icmpv4-errors.capacity]",
        "[icmpv4-errors.generate]\nfragmentation-needed = false\n\n[icmpv4-errors.capacity]",
        1,
    );
    let policy = validated(&off).icmpv4_errors().unwrap().policy();
    assert!(!policy.generates(Icmpv4ErrorKind::DestinationUnreachableFragmentationNeeded));
    assert!(policy.generates(Icmpv4ErrorKind::TimeExceededTtl));
    assert!(policy.generates(Icmpv4ErrorKind::DestinationUnreachableHost));

    // Review M1: its own limiter interval, default 10 ms, never 0.
    assert_eq!(
        defaults
            .icmpv4_errors()
            .unwrap()
            .policy()
            .fragmentation_needed_interval_ms(),
        ruster_core::ICMPV4_DEFAULT_FRAGMENTATION_NEEDED_INTERVAL_MS
    );
    let interval = |value: u64| {
        VALID.replacen(
            "state-ttl-ms = 60000\n\n[icmpv4-errors.capacity]",
            &format!(
                "state-ttl-ms = 60000\nfragmentation-needed-interval-ms = {value}\n\n\
                 [icmpv4-errors.capacity]"
            ),
            1,
        )
    };
    assert_eq!(
        validated(&interval(250))
            .icmpv4_errors()
            .unwrap()
            .policy()
            .fragmentation_needed_interval_ms(),
        250
    );
    let rejected = error(&interval(0));
    assert_eq!(
        rejected.code(),
        ValidationCode::Icmpv4ErrorPolicy(ruster_core::Icmpv4ErrorPolicyError::IntervalZero)
    );
    assert_eq!(dotted(rejected.path()), "icmpv4-errors.policy");
}

/// MTU2 part B: `[fragmentation]` defaults to RFC 1812 §4.2.2.7 behaviour
/// (on, every datagram fragmented: up to 1365 fragments, 64 slots of the
/// largest interface MTU); off has no slot storage; every bound fails
/// closed with a value-free code at the field.
#[test]
fn fragmentation_section_defaults_on_and_fails_closed() {
    use ruster_config::{FragmentationStorageShapeV1, MAX_FRAGMENTATION_DATAGRAMS};
    use ruster_core::{Ipv4FragmentSlot, Ipv4FragmentationPolicy, Ipv4FragmentationPolicyError};
    let with = |section: &str| VALID.replacen("[tick]", &format!("{section}\n[tick]"), 1);
    let absent = validated(VALID);
    assert_eq!(
        absent.fragmentation().policy(),
        Ipv4FragmentationPolicy::DEFAULT
    );
    let shape = FragmentationStorageShapeV1 {
        datagrams: 64,
        slot_bytes: 3840,
    };
    assert_eq!(absent.fragmentation().storage(), Some(shape));
    let empty = validated(&with("[fragmentation]\n"));
    assert_eq!(empty.fragmentation(), absent.fragmentation());
    assert_eq!(empty.storage_shape(), absent.storage_shape());

    let off = validated(&with("[fragmentation]\nenabled = false\n"));
    assert!(!off.fragmentation().policy().enabled());
    assert_eq!(off.fragmentation().storage(), None);
    assert_eq!(off.storage_shape().fragmentation, None);
    // Without fragmentation the fragment association table holds nothing
    // either (NAT-FRAG: held fragments leave through the fragmentation
    // slots), so its 64 held fragments go too.
    assert_eq!(
        off.storage_shape()
            .fragment_tracking
            .map(|shape| shape.held),
        Some(0)
    );
    assert_eq!(
        absent.storage_shape().required_bytes - off.storage_shape().required_bytes,
        64 * (size_of::<Ipv4FragmentSlot>() + 3840)
            + 64 * (size_of::<ruster_core::Ipv4FragmentHeldSlot>() + 3840)
    );
    // Off ignores the slot count (no storage), but still checks the bound.
    let off_zero = validated(&with("[fragmentation]\nenabled = false\ndatagrams = 0\n"));
    assert_eq!(off_zero.storage_shape(), off.storage_shape());

    let tuned = validated(&with(
        "[fragmentation]\nmax-fragments-per-datagram = 2\ndatagrams = 1024\n",
    ));
    assert_eq!(tuned.fragmentation().policy().max_fragments(), 2);
    assert_eq!(
        tuned.fragmentation().storage(),
        Some(FragmentationStorageShapeV1 {
            datagrams: MAX_FRAGMENTATION_DATAGRAMS,
            slot_bytes: 3840,
        })
    );

    for value in [1_u64, 1366, 70_000] {
        let source = with(&format!(
            "[fragmentation]\nmax-fragments-per-datagram = {value}\n"
        ));
        let rejected = error(&source);
        assert_eq!(
            rejected.code(),
            ValidationCode::FragmentationPolicy(
                Ipv4FragmentationPolicyError::MaxFragmentsOutOfRange
            ),
            "{value}"
        );
        assert_eq!(rejected.code().code(), "FRAGMENTATION_POLICY");
        assert_eq!(
            dotted(rejected.path()),
            "fragmentation.max-fragments-per-datagram"
        );
    }
    let zero = error(&with("[fragmentation]\ndatagrams = 0\n"));
    assert_eq!(zero.code(), ValidationCode::FragmentationDatagramsZero);
    assert_eq!(zero.code().code(), "FRAGMENTATION_DATAGRAMS_ZERO");
    assert_eq!(dotted(zero.path()), "fragmentation.datagrams");
    let above = error(&with("[fragmentation]\ndatagrams = 1025\n"));
    assert_eq!(above.code(), ValidationCode::CapacityLimitExceeded);
    assert_eq!(above.limit(), Some(1024));
    assert_eq!(above.actual(), Some(1025));
    assert_eq!(dotted(above.path()), "fragmentation.datagrams");
    let unknown = parse(with("[fragmentation]\nqueue-bytes = 1\n").as_bytes());
    assert!(unknown.is_err(), "unknown field refused");
}

/// MTU2 part B review: `[tick] generated-fragments` bounds the fragment
/// frames of one tick (default 64), 1 to 65536, fail closed.
#[test]
fn tick_generated_fragments_defaults_and_fails_closed() {
    use ruster_config::{DEFAULT_TICK_GENERATED_FRAGMENTS, MAX_TICK_GENERATED_FRAGMENTS};
    assert_eq!(
        validated(VALID).tick().generated_fragments,
        DEFAULT_TICK_GENERATED_FRAGMENTS
    );
    assert_eq!(DEFAULT_TICK_GENERATED_FRAGMENTS, 64);
    let with = |value: u64| {
        VALID.replacen(
            "[tick]\n",
            &format!("[tick]\ngenerated-fragments = {value}\n"),
            1,
        )
    };
    assert_eq!(validated(&with(1)).tick().generated_fragments, 1);
    assert_eq!(
        validated(&with(65_536)).tick().generated_fragments,
        MAX_TICK_GENERATED_FRAGMENTS
    );
    let zero = error(&with(0));
    assert_eq!(zero.code(), ValidationCode::TickGeneratedFragmentsZero);
    assert_eq!(zero.code().code(), "TICK_GENERATED_FRAGMENTS_ZERO");
    assert_eq!(dotted(zero.path()), "tick.generated-fragments");
    let above = error(&with(65_537));
    assert_eq!(above.code(), ValidationCode::CapacityLimitExceeded);
    assert_eq!(
        (above.limit(), above.actual()),
        (Some(65_536), Some(65_537))
    );
    assert_eq!(dotted(above.path()), "tick.generated-fragments");
}

/// NAT-FRAG (CONFIG-011): `[fragment-tracking]` absent is `associate` with
/// the default bounds; `refuse` has no policy and no storage; held
/// fragments are sized like a fragmentation slot and exist only with
/// fragmentation on; every bound fails closed with a value-free code at
/// the field.
#[test]
fn fragment_tracking_section_defaults_to_association_and_fails_closed() {
    use ruster_config::{FragmentTrackingStorageShapeV1, MAX_FRAGMENT_TRACKING_ENTRIES};
    use ruster_core::{Ipv4FragmentTrackingPolicy, Ipv4FragmentTrackingPolicyError};

    let with = |section: &str| VALID.replacen("[tick]", &format!("{section}\n[tick]"), 1);
    let absent = validated(VALID);
    let defaults = Ipv4FragmentTrackingPolicy::new(5_000, 32, 16).unwrap();
    assert_eq!(absent.fragment_tracking().policy(), Some(defaults));
    let shape = FragmentTrackingStorageShapeV1 {
        entries: 256,
        buckets: 256,
        held: 64,
        held_slot_bytes: 3840,
    };
    assert_eq!(absent.fragment_tracking().storage(), Some(shape));
    let empty = validated(&with("[fragment-tracking]\n"));
    assert_eq!(empty.fragment_tracking(), absent.fragment_tracking());
    assert_eq!(empty.storage_shape(), absent.storage_shape());

    // The hardening switch: no association, no storage.
    let refuse = validated(&with("[fragment-tracking]\nmode = \"refuse\"\n"));
    assert_eq!(refuse.fragment_tracking().policy(), None);
    assert_eq!(refuse.storage_shape().fragment_tracking, None);
    let directory = size_of::<DirectoryBucket>() + size_of::<DirectoryNode>();
    assert_eq!(
        absent.storage_shape().required_bytes - refuse.storage_shape().required_bytes,
        256 * (size_of::<ruster_core::Ipv4FragmentEntrySlot>()
            + size_of::<ruster_core::Ipv4FragmentHostSlot>()
            + 2 * directory)
            + 64 * (size_of::<ruster_core::Ipv4FragmentHeldSlot>() + 3840)
    );
    // `refuse` does not look at the other keys.
    let refuse_zero = validated(&with(
        "[fragment-tracking]\nmode = \"refuse\"\nentries = 0\ntimeout-ms = 1\n",
    ));
    assert_eq!(refuse_zero.storage_shape(), refuse.storage_shape());

    let tuned = validated(&with(
        "[fragment-tracking]\nentries = 16384\nentries-per-host = 1\nheld-fragments = 0\nheld-per-host = 0\ntimeout-ms = 100\n",
    ));
    assert_eq!(
        tuned.fragment_tracking().policy(),
        Some(Ipv4FragmentTrackingPolicy::new(100, 1, 0).unwrap())
    );
    let whole = validated(&with("[fragment-tracking]\ningress-share-percent = 100\n"));
    assert_eq!(
        whole
            .fragment_tracking()
            .policy()
            .map(Ipv4FragmentTrackingPolicy::ingress_share_percent),
        Some(100)
    );
    assert_eq!(
        tuned.fragment_tracking().storage(),
        Some(FragmentTrackingStorageShapeV1 {
            entries: MAX_FRAGMENT_TRACKING_ENTRIES,
            buckets: MAX_FRAGMENT_TRACKING_ENTRIES,
            held: 0,
            held_slot_bytes: 0,
        })
    );
    // A non-power-of-two count gets the next power of two of buckets.
    let odd = validated(&with("[fragment-tracking]\nentries = 300\n"));
    assert_eq!(
        odd.fragment_tracking().storage().map(|shape| shape.buckets),
        Some(512)
    );
    // Held fragments leave through the fragmentation slots: none without.
    let no_fragmentation = validated(&with("[fragmentation]\nenabled = false\n"));
    assert_eq!(
        no_fragmentation
            .fragment_tracking()
            .storage()
            .map(|shape| (shape.held, shape.held_slot_bytes)),
        Some((0, 0))
    );

    for (section, code, field) in [
        (
            "timeout-ms = 99",
            ValidationCode::FragmentTrackingPolicy(
                Ipv4FragmentTrackingPolicyError::TimeoutOutOfRange,
            ),
            "fragment-tracking.timeout-ms",
        ),
        (
            "timeout-ms = 60001",
            ValidationCode::FragmentTrackingPolicy(
                Ipv4FragmentTrackingPolicyError::TimeoutOutOfRange,
            ),
            "fragment-tracking.timeout-ms",
        ),
        (
            "entries-per-host = 0",
            ValidationCode::FragmentTrackingPolicy(
                Ipv4FragmentTrackingPolicyError::EntriesPerHostZero,
            ),
            "fragment-tracking.entries-per-host",
        ),
        (
            "entries = 0",
            ValidationCode::FragmentTrackingEntriesZero,
            "fragment-tracking.entries",
        ),
        (
            "ingress-share-percent = 0",
            ValidationCode::FragmentTrackingPolicy(
                Ipv4FragmentTrackingPolicyError::IngressShareOutOfRange,
            ),
            "fragment-tracking.ingress-share-percent",
        ),
        (
            "ingress-share-percent = 101",
            ValidationCode::FragmentTrackingPolicy(
                Ipv4FragmentTrackingPolicyError::IngressShareOutOfRange,
            ),
            "fragment-tracking.ingress-share-percent",
        ),
    ] {
        let rejected = error(&with(&format!("[fragment-tracking]\n{section}\n")));
        assert_eq!(rejected.code(), code, "{section}");
        assert_eq!(dotted(rejected.path()), field, "{section}");
    }
    assert_eq!(
        error(&with("[fragment-tracking]\ntimeout-ms = 1\n"))
            .code()
            .code(),
        "FRAGMENT_TRACKING_POLICY"
    );
    assert_eq!(
        error(&with("[fragment-tracking]\nentries = 0\n"))
            .code()
            .code(),
        "FRAGMENT_TRACKING_ENTRIES_ZERO"
    );
    for (section, field, limit, actual) in [
        ("entries = 16385", "fragment-tracking.entries", 16384, 16385),
        (
            "held-fragments = 513",
            "fragment-tracking.held-fragments",
            512,
            513,
        ),
    ] {
        let above = error(&with(&format!("[fragment-tracking]\n{section}\n")));
        assert_eq!(above.code(), ValidationCode::CapacityLimitExceeded);
        assert_eq!(above.limit(), Some(limit));
        assert_eq!(above.actual(), Some(actual));
        assert_eq!(dotted(above.path()), field);
    }
    for unknown in [
        "[fragment-tracking]\nqueue = 1\n",
        "[fragment-tracking]\nmode = \"reassemble\"\n",
    ] {
        assert!(parse(with(unknown).as_bytes()).is_err(), "{unknown}");
    }
}
