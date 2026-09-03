use std::num::NonZeroU64;

use ruster_config::{parse, validate, ValidatedConfig, ValidatedConfigV1, ValidationLimits};
use ruster_control::FullServicePlanInputs;
use ruster_core::{FirewallHashKey, Nat44TcpHashKey, Nat44UdpHashKey};

const BASE: &str = r#"
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
"#;

const RESOLUTION: &str = r#"
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
"#;

const ICMPV4_ERRORS: &str = r#"
[icmpv4-errors.policy]
interval-ms = 100
state-ttl-ms = 60000

[icmpv4-errors.capacity]
states = 6
actions = 7
"#;

const NAT44_REALM: &str = r#"
[nat44.realm]
inside = "lan"
outside = "wan"
public-address = "198.51.100.10"

[nat44.realm.ports]
first = 40000
last = 40012
"#;

const NAT44_UDP: &str = r#"
[nat44.udp]
idle-ttl-ms = 300000
allocator-seed = "7"
icmpv4-errors = "external-only"

[nat44.udp.capacity]
mappings = 3
peers = 9
"#;

const NAT44_TCP: &str = r#"
[nat44.tcp]
idle-ttl-ms = 7440000
allocator-seed = "11"
icmpv4-errors = "disabled"

[nat44.tcp.capacity]
mappings = 5
sessions = 17
"#;

const FIREWALL: &str = r#"
[firewall.policy]
udp-idle-ttl-ms = 300000
tcp-opening-idle-ttl-ms = 240000
tcp-active-idle-ttl-ms = 7440000

[firewall.capacity]
states = 11

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
"#;

const TICK: &str = r#"
[tick]
rx = 64
resolution-timer-scans = 16
failure-dispatch-scans = 8
generated-arp = 4
generated-icmpv4 = 2
"#;

#[derive(Clone, Copy)]
pub struct Services {
    pub resolution: bool,
    pub icmpv4_errors: bool,
    pub nat44_udp: bool,
    pub nat44_tcp: bool,
    pub firewall: bool,
}

impl Services {
    pub const ALL: Self = Self {
        resolution: true,
        icmpv4_errors: true,
        nat44_udp: true,
        nat44_tcp: true,
        firewall: true,
    };
}

pub fn validated(services: Services) -> ValidatedConfigV1 {
    let mut source = BASE.to_owned();
    if services.resolution {
        source.push_str(RESOLUTION);
    }
    if services.icmpv4_errors {
        source.push_str(ICMPV4_ERRORS);
    }
    if services.nat44_udp || services.nat44_tcp {
        source.push_str(NAT44_REALM);
    }
    if services.nat44_udp {
        source.push_str(NAT44_UDP);
    }
    if services.nat44_tcp {
        source.push_str(NAT44_TCP);
    }
    if services.firewall {
        source.push_str(FIREWALL);
    }
    source.push_str(TICK);

    let parsed = parse(source.as_bytes()).expect("syntax fixture");
    match validate(
        parsed,
        ValidationLimits {
            max_slots_per_table: 1_048_576,
            max_runtime_bytes: 1 << 30,
        },
    )
    .expect("semantic fixture")
    {
        ValidatedConfig::V1(config) => config,
        _ => unreachable!("test fixture selects schema V1"),
    }
}

pub fn inputs(generation: u64, seed: u64) -> FullServicePlanInputs {
    FullServicePlanInputs::new(
        NonZeroU64::new(generation).unwrap(),
        Nat44UdpHashKey::new(seed, seed + 1).unwrap(),
        Nat44TcpHashKey::new(seed + 2, seed + 3).unwrap(),
        FirewallHashKey::new(seed + 4, seed + 5).unwrap(),
    )
}
