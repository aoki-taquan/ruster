use std::num::NonZeroU64;

use ruster_config::{parse, validate, ValidatedConfig, ValidatedConfigV1, ValidationLimits};
use ruster_control::{
    candidate_from_config, ConfigBridgeError, KeySourceError, KeySourceKind, PublicationKeySource,
    PublicationKeys, RuntimeService, SimDeterministicKeySource, SuccessorError, ValidatedCandidate,
};
use ruster_core::{FirewallHashKey, IfId, Ipv4Address, Nat44TcpHashKey, Nat44UdpHashKey};

const SIM_SEED: u64 = 0x5eed_0bad_cafe_f00d;
const ALLOCATOR_SEED_TEXT: &str = "9876543210123";

/// LAN/WAN router with a default route, static neighbors, UDP/TCP NAT and a
/// stateful firewall.
const CONFIG: &str = r#"
schema-version = 1

[[interfaces]]
id = 1
name = "lan"
device = "eth0"
mac = "02:00:00:00:00:01"

[[interfaces]]
id = 2
name = "wan"
device = "eth1"
mac = "02:00:00:00:00:02"

[[addresses]]
interface = "lan"
ipv4 = "192.0.2.1/24"

[[addresses]]
interface = "wan"
ipv4 = "198.51.100.10/24"

[[routes]]
prefix = "0.0.0.0/0"
egress = "wan"
via = "198.51.100.1"

[[neighbors]]
interface = "wan"
address = "198.51.100.1"
mac = "02:00:00:00:00:03"

[ipv4-origin]
default-ttl = 64

[resolution.policy]
interval-ms = 1000
state-ttl-ms = 3000
dynamic-neighbor-ttl-ms = 60000
max-attempts = 3

[resolution.capacity]
states = 8
actions = 8
dynamic-neighbors = 16
failure-holds = 8

[icmpv4-errors.policy]
interval-ms = 100
state-ttl-ms = 60000

[icmpv4-errors.capacity]
states = 8
actions = 8

[nat44.realm]
inside = "lan"
outside = "wan"
public-address = "198.51.100.10"

[nat44.realm.ports]
first = 40000
last = 40015

[nat44.udp]
idle-ttl-ms = 300000
allocator-seed = "9876543210123"
icmpv4-errors = "external-only"

[nat44.udp.capacity]
mappings = 16
peers = 32

[nat44.tcp]
idle-ttl-ms = 7440000
allocator-seed = "11"
icmpv4-errors = "disabled"

[nat44.tcp.capacity]
mappings = 16
sessions = 32

[firewall.policy]
udp-idle-ttl-ms = 300000
tcp-opening-idle-ttl-ms = 240000
tcp-active-idle-ttl-ms = 7440000

[firewall.capacity]
states = 64

[[firewall.rules]]
id = 1
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
id = 2
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
"#;

const LIMITS: ValidationLimits = ValidationLimits {
    max_slots_per_table: 1 << 20,
    max_runtime_bytes: 1 << 30,
};

fn validated(source: &str) -> ValidatedConfigV1 {
    match validate(parse(source.as_bytes()).expect("syntax"), LIMITS).expect("semantics") {
        ValidatedConfig::V1(config) => config,
        _ => unreachable!("fixture selects schema V1"),
    }
}

fn generation(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).unwrap()
}

fn sim_candidate(config: &ValidatedConfigV1, value: u64) -> ValidatedCandidate {
    candidate_from_config(
        config,
        generation(value),
        &mut SimDeterministicKeySource::new(SIM_SEED),
    )
    .expect("bridge candidate")
}

/// Removes the TOML table headed by `header` and its sub-tables.
fn without_table(source: &str, header: &str) -> String {
    let prefix = &header[..header.len() - 1];
    let mut output = String::new();
    let mut skipping = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            let name = trimmed.trim_start_matches('[').trim_end_matches(']');
            let base = prefix.trim_start_matches('[');
            skipping = name == base || name.starts_with(&format!("{base}."));
        }
        if !skipping {
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

struct CountingSource {
    calls: u32,
    inner: SimDeterministicKeySource,
}

impl PublicationKeySource for CountingSource {
    const KIND: KeySourceKind = KeySourceKind::DeterministicSimulation;

    fn publication_keys(
        &mut self,
        generation: NonZeroU64,
    ) -> Result<PublicationKeys, KeySourceError> {
        self.calls += 1;
        self.inner.publication_keys(generation)
    }
}

/// Returns the same key set for every generation, violating the contract.
struct ReusingSource;

impl PublicationKeySource for ReusingSource {
    const KIND: KeySourceKind = KeySourceKind::DeterministicSimulation;

    fn publication_keys(&mut self, _: NonZeroU64) -> Result<PublicationKeys, KeySourceError> {
        Ok(PublicationKeys::new(
            Nat44UdpHashKey::new(1, 2).unwrap(),
            Nat44TcpHashKey::new(3, 4).unwrap(),
            FirewallHashKey::new(5, 6).unwrap(),
        ))
    }
}

struct FailingSource;

impl PublicationKeySource for FailingSource {
    const KIND: KeySourceKind = KeySourceKind::DeterministicSimulation;

    fn publication_keys(&mut self, _: NonZeroU64) -> Result<PublicationKeys, KeySourceError> {
        Err(KeySourceError::AllZeroKey(RuntimeService::Firewall))
    }
}

#[test]
fn config_bridge_builds_candidates_and_rejects_missing_services() {
    let config = validated(CONFIG);
    let candidate = sim_candidate(&config, 7);
    assert_eq!(candidate.generation(), generation(7));

    let storage = config.storage_shape();
    let shape = candidate.storage_shape();
    let resolution = storage.resolution.unwrap();
    assert_eq!(shape.resolution().state_slots(), resolution.states);
    assert_eq!(shape.resolution().action_slots(), resolution.actions);
    assert_eq!(
        shape.resolution().dynamic_neighbor_slots(),
        resolution.dynamic_neighbors
    );
    assert_eq!(
        shape.resolution().failure_hold_slots(),
        resolution.failure_holds
    );
    let icmp = storage.icmpv4_errors.unwrap();
    assert_eq!(shape.icmpv4_errors().state_slots(), icmp.states);
    assert_eq!(shape.icmpv4_errors().action_slots(), icmp.actions);
    let udp = storage.nat44_udp.unwrap();
    assert_eq!(shape.nat44_udp().mapping_slots(), udp.mappings);
    assert_eq!(shape.nat44_udp().peer_slots(), udp.peers);
    assert_eq!(shape.nat44_udp().mapping_buckets(), udp.mapping_buckets);
    assert_eq!(shape.nat44_udp().peer_buckets(), udp.peer_buckets);
    assert_eq!(shape.nat44_udp().port_owner_slots(), 16);
    let tcp = storage.nat44_tcp.unwrap();
    assert_eq!(shape.nat44_tcp().mapping_slots(), tcp.mappings);
    assert_eq!(shape.nat44_tcp().session_slots(), tcp.sessions);
    assert_eq!(shape.nat44_tcp().session_buckets(), tcp.session_buckets);
    assert_eq!(shape.nat44_tcp().port_owner_slots(), 16);
    assert_eq!(shape.firewall_state_slots(), 64);

    let expected_keys = SimDeterministicKeySource::new(SIM_SEED)
        .publication_keys(generation(7))
        .unwrap();
    let authority = candidate.authority();
    assert_eq!(authority.generation(), generation(7));
    assert_eq!(authority.nat44_udp_hash_key(), expected_keys.nat44_udp());
    assert_eq!(authority.nat44_tcp_hash_key(), expected_keys.nat44_tcp());
    assert_eq!(
        authority.firewall_config().hash_key(),
        expected_keys.firewall()
    );
    assert_eq!(
        authority.resolution_policy(),
        config.resolution().unwrap().policy()
    );
    assert_eq!(
        authority.icmpv4_error_policy(),
        config.icmpv4_errors().unwrap().policy()
    );
    let nat = config.nat44().unwrap();
    let udp_config = authority.nat44_udp_config();
    assert_eq!(udp_config.inside(), IfId(1));
    assert_eq!(udp_config.outside(), IfId(2));
    assert_eq!(
        udp_config.public_address(),
        Ipv4Address::from_octets([198, 51, 100, 10])
    );
    assert_eq!(
        (udp_config.first_port(), udp_config.last_port()),
        (40000, 40015)
    );
    assert_eq!(udp_config.policy(), nat.udp().unwrap().policy());
    assert_eq!(udp_config.policy().allocator_seed(), 9_876_543_210_123);
    assert_eq!(
        authority.nat44_tcp_config().policy(),
        nat.tcp().unwrap().policy()
    );
    let firewall = authority.firewall_config();
    assert_eq!(firewall.rules(), config.firewall().unwrap().rules());
    assert_eq!(firewall.policy(), config.firewall().unwrap().policy());
    assert_eq!(firewall.generation(), 7);

    let missing = [
        ("[resolution]", RuntimeService::Resolution),
        ("[icmpv4-errors]", RuntimeService::Icmpv4Errors),
        ("[nat44.udp]", RuntimeService::Nat44Udp),
        ("[nat44.tcp]", RuntimeService::Nat44Tcp),
        ("[nat44]", RuntimeService::Nat44Udp),
        ("[firewall]", RuntimeService::Firewall),
    ];
    for (table, service) in missing {
        let reduced = validated(&without_table(CONFIG, table));
        let mut source = CountingSource {
            calls: 0,
            inner: SimDeterministicKeySource::new(SIM_SEED),
        };
        let error = candidate_from_config(&reduced, generation(1), &mut source)
            .err()
            .expect("missing service must reject");
        assert_eq!(error, ConfigBridgeError::MissingService(service), "{table}");
        assert_eq!(source.calls, 0, "{table}: no key drawn before rejection");
    }

    let mut source = CountingSource {
        calls: 0,
        inner: SimDeterministicKeySource::new(SIM_SEED),
    };
    assert!(candidate_from_config(&config, generation(1), &mut source).is_ok());
    assert_eq!(source.calls, 1);
    assert_eq!(
        candidate_from_config(&config, generation(1), &mut FailingSource)
            .err()
            .unwrap(),
        ConfigBridgeError::KeySource(KeySourceError::AllZeroKey(RuntimeService::Firewall))
    );
}

#[test]
fn sim_key_source_is_deterministic_generation_distinct_and_simulation_only() {
    assert_eq!(
        SimDeterministicKeySource::KIND,
        KeySourceKind::DeterministicSimulation
    );
    let mut first = SimDeterministicKeySource::new(SIM_SEED);
    let mut second = SimDeterministicKeySource::new(SIM_SEED);
    let mut other_seed = SimDeterministicKeySource::new(SIM_SEED ^ 1);
    let mut zero_seed = SimDeterministicKeySource::new(0);

    let generations: Vec<u64> = (1..=256).chain([u64::MAX - 1, u64::MAX]).collect();
    let keys: Vec<PublicationKeys> = generations
        .iter()
        .map(|&value| first.publication_keys(generation(value)).unwrap())
        .collect();
    for (index, &value) in generations.iter().enumerate() {
        // Same seed and generation is reproducible, also out of order.
        assert_eq!(
            second.publication_keys(generation(value)).unwrap(),
            keys[index]
        );
        let alternative = other_seed.publication_keys(generation(value)).unwrap();
        assert_ne!(alternative.nat44_udp(), keys[index].nat44_udp());
        assert!(zero_seed.publication_keys(generation(value)).is_ok());
        let key = &keys[index];
        for later in &keys[index + 1..] {
            assert_ne!(later.nat44_udp(), key.nat44_udp());
            assert_ne!(later.nat44_tcp(), key.nat44_tcp());
            assert_ne!(later.firewall(), key.firewall());
        }
    }
}

#[test]
fn bridge_candidates_pass_successor_validation_and_reject_key_reuse() {
    let config = validated(CONFIG);
    let mut source = SimDeterministicKeySource::new(SIM_SEED);
    let first = candidate_from_config(&config, generation(1), &mut source).unwrap();
    let second = candidate_from_config(&config, generation(2), &mut source).unwrap();
    assert_eq!(first.validate_successor(&second), Ok(()));

    // Re-publishing the same document as a new generation (M1 rollback).
    let rollback = candidate_from_config(&config, generation(3), &mut source).unwrap();
    assert_eq!(second.validate_successor(&rollback), Ok(()));

    let replay = sim_candidate(&config, 2);
    assert_eq!(
        second.validate_successor(&replay),
        Err(SuccessorError::GenerationNotIncreasing)
    );

    let reused_first = candidate_from_config(&config, generation(1), &mut ReusingSource).unwrap();
    let reused_second = candidate_from_config(&config, generation(2), &mut ReusingSource).unwrap();
    assert_eq!(
        reused_first.validate_successor(&reused_second),
        Err(SuccessorError::Nat44UdpHashKeyReused)
    );

    let resized = validated(&CONFIG.replace("states = 64", "states = 128"));
    let resized = sim_candidate(&resized, 4);
    assert_eq!(
        rollback.validate_successor(&resized),
        Err(SuccessorError::StorageShapeChanged)
    );

    let rerouted = validated(&CONFIG.replace("via = \"198.51.100.1\"", "via = \"198.51.100.2\""));
    let rerouted = sim_candidate(&rerouted, 4);
    assert_eq!(rollback.validate_successor(&rerouted), Ok(()));
}

#[test]
fn bridge_errors_and_key_material_are_redacted() {
    let mut source = SimDeterministicKeySource::new(SIM_SEED);
    let keys = source.publication_keys(generation(1)).unwrap();
    let config = validated(CONFIG);
    let candidate = candidate_from_config(&config, generation(1), &mut source).unwrap();
    let authority = candidate.authority();

    let rendered = [
        format!("{source:?}"),
        format!("{keys:?}"),
        format!("{:#?}", keys),
        format!("{:?}", keys.nat44_udp()),
        format!("{:?}", keys.nat44_tcp()),
        format!("{:?}", keys.firewall()),
        format!("{:?}", authority.nat44_udp_config()),
        format!("{:?}", authority.nat44_tcp_config()),
        format!("{:?}", authority.nat44_udp_config().policy()),
        format!(
            "{:?}",
            ConfigBridgeError::MissingService(RuntimeService::Nat44Tcp)
        ),
        format!(
            "{:?}",
            ConfigBridgeError::KeySource(KeySourceError::AllZeroKey(RuntimeService::Nat44Udp))
        ),
    ];
    assert_eq!(rendered[0], "SimDeterministicKeySource([REDACTED])");
    assert_eq!(rendered[1], "PublicationKeys([REDACTED])");
    assert_eq!(rendered[9], "MissingService(Nat44Tcp)");
    assert_eq!(rendered[10], "KeySource(AllZeroKey(Nat44Udp))");
    let forbidden = [
        SIM_SEED.to_string(),
        format!("{SIM_SEED:x}"),
        format!("{SIM_SEED:X}"),
        ALLOCATOR_SEED_TEXT.to_owned(),
        "5eed".to_owned(),
    ];
    for text in &rendered {
        for secret in &forbidden {
            assert!(!text.contains(secret.as_str()), "{text} leaks a secret");
        }
    }

    let source_text = include_str!("../src/config_bridge.rs");
    for forbidden in [
        "derive(Debug",
        "derive(Clone, Copy, Debug, Eq, PartialEq)]\npub struct",
        "Mutex<",
        "dyn ",
        "unsafe",
        "panic!",
        "unwrap(",
        "expect(",
        "ruster-runtime",
        "ruster_runtime",
    ] {
        assert!(
            !source_text.contains(forbidden),
            "forbidden source: {forbidden}"
        );
    }
}
