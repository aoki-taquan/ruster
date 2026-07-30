use ruster_config::{
    parse, DiagnosticCode, PathSegment, VersionedConfig, MAX_ADDRESSES, MAX_CONFIG_BYTES,
    MAX_FIREWALL_RULES, MAX_INTERFACES, MAX_NEIGHBORS, MAX_ROUTES,
};

const VALID_V1: &str = r#"
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
states = 64
actions = 64
dynamic-neighbors = 64
failure-holds = 64

[icmpv4-errors.policy]
interval-ms = 100
state-ttl-ms = 60000

[icmpv4-errors.capacity]
states = 64
actions = 64

[nat44.realm]
inside = "lan"
outside = "wan"
public-address = "198.51.100.10"

[nat44.realm.ports]
first = 40000
last = 60999

[nat44.udp]
idle-ttl-ms = 300000
allocator-seed = "7"
icmpv4-errors = "external-only"

[nat44.udp.capacity]
mappings = 1024
peers = 4096

[nat44.tcp]
idle-ttl-ms = 7440000
allocator-seed = "11"
icmpv4-errors = "disabled"

[nat44.tcp.capacity]
mappings = 1024
sessions = 4096

[firewall.policy]
udp-idle-ttl-ms = 300000
tcp-opening-idle-ttl-ms = 240000
tcp-active-idle-ttl-ms = 7440000

[firewall.capacity]
states = 4096

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

[tick]
rx = 64
resolution-timer-scans = 16
failure-dispatch-scans = 16
generated-arp = 16
generated-icmpv4 = 16
"#;

#[test]
fn v1_exact_dto_decodes_every_roadmap_section() {
    let config = match parse(VALID_V1.as_bytes()).unwrap() {
        VersionedConfig::V1(config) => config,
        _ => panic!("schema version 1 must produce the V1 DTO"),
    };
    assert_eq!(config.schema_version, 1);
    assert_eq!(config.interfaces.len(), 2);
    assert_eq!(config.addresses.len(), 1);
    assert_eq!(config.routes.len(), 1);
    assert_eq!(config.neighbors.len(), 1);
    assert_eq!(config.ipv4_origin.unwrap().default_ttl, 64);
    assert_eq!(config.resolution.unwrap().capacity.states, 64);
    assert_eq!(config.icmpv4_errors.unwrap().capacity.actions, 64);
    assert_eq!(config.nat44.unwrap().realm.inside, "lan");
    assert_eq!(config.firewall.unwrap().rules.len(), 1);
    let tick = config.tick.unwrap();
    assert_eq!(tick.rx, 64);
    assert_eq!(tick.resolution_timer_scans, 16);
    assert_eq!(tick.failure_dispatch_scans, 16);
    assert_eq!(tick.generated_arp, 16);
    assert_eq!(tick.generated_icmpv4, 16);
}

#[test]
fn schema_version_predispatch_precedes_v1_decode() {
    let input = br#"
schema-version = 42
generation = "not-a-number"
interfaces = "not-a-list"
"#;
    let diagnostic = parse(input).unwrap_err();
    assert_eq!(diagnostic.code(), DiagnosticCode::UnsupportedSchemaVersion);
    assert_eq!(
        diagnostic.path().segments(),
        &[PathSegment::Field("schema-version".to_owned())]
    );
}

#[test]
fn version_header_and_encoding_rejections_are_typed() {
    assert_eq!(
        parse(b"interfaces=[]\n").unwrap_err().code(),
        DiagnosticCode::MissingSchemaVersion
    );
    assert_eq!(
        parse(b"schema-version=\"one\"\n").unwrap_err().code(),
        DiagnosticCode::InvalidSchemaVersion
    );
    assert_eq!(
        parse(&[0xff]).unwrap_err().code(),
        DiagnosticCode::InvalidUtf8
    );
}

#[test]
fn unknown_and_duplicate_fields_fail_closed() {
    let unknown = br#"
schema-version = 1
[[interfaces]]
id = 1
name = "lan"
device = "eth0"
mac = "02:00:00:00:00:01"
surprise = "DO_NOT_ECHO_UNKNOWN_VALUE"
"#;
    let diagnostic = parse(unknown).unwrap_err();
    assert_eq!(diagnostic.code(), DiagnosticCode::UnknownField);
    assert!(diagnostic
        .path()
        .segments()
        .contains(&PathSegment::Index(0)));
    let debug = format!("{diagnostic:?}");
    assert!(!debug.contains("surprise"));
    assert!(!debug.contains("DO_NOT_ECHO_UNKNOWN_VALUE"));

    let hostile_key =
        b"schema-version=1\n\"DO_NOT_ECHO_SECRET_KEY\"=\"DO_NOT_ECHO_SECRET_VALUE\"\n";
    let debug = format!("{:?}", parse(hostile_key).unwrap_err());
    assert!(!debug.contains("DO_NOT_ECHO_SECRET_KEY"));
    assert!(!debug.contains("DO_NOT_ECHO_SECRET_VALUE"));

    for duplicate in [
        "schema-version=1\nschema-version=1\n",
        "schema-version=1\na.b=1\na.b=2\n",
        "schema-version=1\n[a]\nx=1\n[a]\ny=2\n",
        "schema-version=1\n[[interfaces]]\nid=1\nid=2\n",
    ] {
        assert_eq!(
            parse(duplicate.as_bytes()).unwrap_err().code(),
            DiagnosticCode::DuplicateField
        );
    }
}

#[test]
fn invalid_types_report_value_free_indexed_paths() {
    let input = br#"
schema-version = 1
interfaces = [
  { id = "DO_NOT_ECHO_TYPE_VALUE", name = "lan", device = "eth0", mac = "02:00:00:00:00:01" },
]
"#;
    let diagnostic = parse(input).unwrap_err();
    assert_eq!(diagnostic.code(), DiagnosticCode::InvalidType);
    assert!(diagnostic
        .path()
        .segments()
        .contains(&PathSegment::Index(0)));
    assert!(!format!("{diagnostic:?}").contains("DO_NOT_ECHO_TYPE_VALUE"));
}

#[test]
fn input_and_every_v1_list_are_bounded() {
    let oversized = vec![b' '; MAX_CONFIG_BYTES + 1];
    let diagnostic = parse(&oversized).unwrap_err();
    assert_eq!(diagnostic.code(), DiagnosticCode::InputTooLarge);
    assert_eq!(diagnostic.limit(), Some(MAX_CONFIG_BYTES));
    assert_eq!(diagnostic.actual(), Some(MAX_CONFIG_BYTES + 1));

    assert_list_limit(
        "interfaces",
        "{ id=1, name=\"x\", device=\"x\", mac=\"x\" }",
        MAX_INTERFACES,
        "",
    );
    assert_list_limit(
        "addresses",
        "{ interface=\"x\", ipv4=\"x\" }",
        MAX_ADDRESSES,
        "",
    );
    assert_list_limit("routes", "{ prefix=\"x\", egress=\"x\" }", MAX_ROUTES, "");
    assert_list_limit(
        "neighbors",
        "{ interface=\"x\", address=\"x\", mac=\"x\" }",
        MAX_NEIGHBORS,
        "",
    );
    assert_list_limit(
        "rules",
        concat!(
            "{ id=1, source=\"x\", destination=\"x\", protocol=\"tcp\", ",
            "source-ports={first=0,last=0}, destination-ports={first=0,last=0}, ",
            "action=\"deny\" }"
        ),
        MAX_FIREWALL_RULES,
        concat!(
            "[firewall]\n",
            "policy={udp-idle-ttl-ms=1,tcp-opening-idle-ttl-ms=1,",
            "tcp-active-idle-ttl-ms=1}\n",
            "capacity={states=1}\n"
        ),
    );
}

#[test]
fn exact_input_and_v1_list_limits_are_accepted() {
    let mut exact_input = b"schema-version=1\n".to_vec();
    exact_input.resize(MAX_CONFIG_BYTES, b' ');
    assert_eq!(exact_input.len(), MAX_CONFIG_BYTES);
    assert!(parse(&exact_input).is_ok());

    assert_list_at_limit(
        "interfaces",
        "{ id=1, name=\"x\", device=\"x\", mac=\"x\" }",
        MAX_INTERFACES,
        "",
    );
    assert_list_at_limit(
        "addresses",
        "{ interface=\"x\", ipv4=\"x\" }",
        MAX_ADDRESSES,
        "",
    );
    assert_list_at_limit("routes", "{ prefix=\"x\", egress=\"x\" }", MAX_ROUTES, "");
    assert_list_at_limit(
        "neighbors",
        "{ interface=\"x\", address=\"x\", mac=\"x\" }",
        MAX_NEIGHBORS,
        "",
    );
    assert_list_at_limit(
        "rules",
        concat!(
            "{ id=1, source=\"x\", destination=\"x\", protocol=\"tcp\", ",
            "source-ports={first=0,last=0}, destination-ports={first=0,last=0}, ",
            "action=\"deny\" }"
        ),
        MAX_FIREWALL_RULES,
        concat!(
            "[firewall]\n",
            "policy={udp-idle-ttl-ms=1,tcp-opening-idle-ttl-ms=1,",
            "tcp-active-idle-ttl-ms=1}\n",
            "capacity={states=1}\n"
        ),
    );
}

#[test]
fn future_runtime_fields_are_forbidden_and_secret_values_are_redacted() {
    for field in [
        "config-generation",
        "generation",
        "hash-key",
        "firewall-hash-key",
        "ownership",
        "ownership-generation",
        "queue",
        "queues",
        "shard",
        "shards",
        "UMEM",
        "worker-count",
    ] {
        let input =
            format!("schema-version = 1\n[nat44]\n{field} = \"DO_NOT_ECHO_SECRET_VALUE\"\n");
        let diagnostic = parse(input.as_bytes()).unwrap_err();
        assert_eq!(diagnostic.code(), DiagnosticCode::ForbiddenField);
        let debug = format!("{diagnostic:?}");
        assert!(!debug.contains("DO_NOT_ECHO_SECRET_VALUE"));
    }

    let hostile_parent = br#"
schema-version=1
["DO_NOT_ECHO_PARENT"]
generation="DO_NOT_ECHO_NESTED_SECRET"
"#;
    let diagnostic = parse(hostile_parent).unwrap_err();
    assert_eq!(diagnostic.code(), DiagnosticCode::ForbiddenField);
    let debug = format!("{diagnostic:?}");
    assert!(!debug.contains("DO_NOT_ECHO_PARENT"));
    assert!(!debug.contains("DO_NOT_ECHO_NESTED_SECRET"));
}

#[test]
fn dto_debug_redacts_allocator_seeds() {
    const SEED: &str = "18446744073709551613";
    let input = format!(
        concat!(
            "schema-version=1\n",
            "[nat44.realm]\n",
            "inside=\"lan\"\n",
            "outside=\"wan\"\n",
            "public-address=\"198.51.100.10\"\n",
            "[nat44.realm.ports]\n",
            "first=40000\n",
            "last=40001\n",
            "[nat44.udp]\n",
            "idle-ttl-ms=300000\n",
            "allocator-seed=\"{SEED}\"\n",
            "icmpv4-errors=\"disabled\"\n",
            "[nat44.udp.capacity]\n",
            "mappings=1\n",
            "peers=1\n"
        ),
        SEED = SEED,
    );
    let config = parse(input.as_bytes()).unwrap();
    let debug = format!("{config:?}");
    assert!(!debug.contains(SEED));
    assert!(debug.contains("[REDACTED]"));
}

#[test]
fn versioned_config_parser_is_exact_bounded_and_redacted() {
    assert!(parse(VALID_V1.as_bytes()).is_ok());
    assert_eq!(
        parse(b"schema-version=1\nunknown=\"SECRET\"\n")
            .unwrap_err()
            .code(),
        DiagnosticCode::UnknownField
    );
    assert_eq!(
        parse(b"schema-version=2\nunknown=\"SECRET\"\n")
            .unwrap_err()
            .code(),
        DiagnosticCode::UnsupportedSchemaVersion
    );
}

fn assert_list_limit(field: &str, item: &str, limit: usize, prefix: &str) {
    let mut input = String::from("schema-version=1\n");
    input.push_str(prefix);
    input.push_str(field);
    input.push_str("=[");
    for index in 0..=limit {
        if index != 0 {
            input.push(',');
        }
        input.push_str(item);
    }
    input.push_str("]\n");
    let diagnostic = parse(input.as_bytes()).unwrap_err();
    assert_eq!(diagnostic.code(), DiagnosticCode::ListTooLong);
    assert_eq!(diagnostic.limit(), Some(limit));
    assert_eq!(diagnostic.actual(), Some(limit + 1));
}

fn assert_list_at_limit(field: &str, item: &str, limit: usize, prefix: &str) {
    let mut input = String::from("schema-version=1\n");
    input.push_str(prefix);
    input.push_str(field);
    input.push_str("=[");
    for index in 0..limit {
        if index != 0 {
            input.push(',');
        }
        input.push_str(item);
    }
    input.push_str("]\n");
    assert!(
        parse(input.as_bytes()).is_ok(),
        "{field} must accept exactly {limit} entries"
    );
}
