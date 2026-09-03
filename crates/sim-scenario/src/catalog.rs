use std::fmt;

use ruster_core::{IfId, MonotonicMillis};

use crate::{
    fixtures::{
        arp_reply, arp_request, tcp_syn_frame, udp_frame, EthernetHop, DIRECT_WAN_ROUTE,
        FULL_SERVICE, HOST_IP, HOST_MAC, LAN_IP, LAN_MAC, REMOTE_IP, UDP_NAT, WAN_IP, WAN_MAC,
    },
    run_descriptor, RunNamedScenarioError, Scenario, ScenarioDescriptor, ScenarioDescriptorError,
    ScenarioLookupError, ScenarioPublicationEvent, TickOutcome,
};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_HOP: EthernetHop = EthernetHop {
    dest_mac: LAN_MAC,
    src_mac: HOST_MAC,
};
const RESOLVABLE_HOST_IP: [u8; 4] = [203, 0, 113, 50];
const RESOLVABLE_HOST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 30];
const UNREACHABLE_HOST_IP: [u8; 4] = [203, 0, 113, 99];

/// Number of compiled named scenarios.
pub const NAMED_SCENARIO_COUNT: usize = 8;

/// Stable ordered names of every compiled named scenario.
pub const NAMED_SCENARIO_NAMES: [&str; NAMED_SCENARIO_COUNT] = [
    "lan_local_arp",
    "wan_udp_nat",
    "wan_tcp_allow",
    "wan_udp_deny",
    "dynamic_arp_then_forward",
    "ttl_exceeded",
    "host_unreachable_after_max_arp_attempts",
    "reload_rollback",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NamedScenarioKind {
    LanLocalArp,
    WanUdpNat,
    WanTcpAllow,
    WanUdpDeny,
    DynamicArpThenForward,
    TtlExceeded,
    HostUnreachableAfterMaxArpAttempts,
    ReloadRollback,
}

/// Metadata handle for one compiled named scenario.
///
/// The config authority, frame construction, identity seed, and logical event
/// stream are private to this crate. Consumers receive only stable metadata or
/// the high-level run result.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NamedScenario {
    name: &'static str,
    summary: &'static str,
    kind: NamedScenarioKind,
}

static NAMED_SCENARIOS: [NamedScenario; NAMED_SCENARIO_COUNT] = [
    NamedScenario {
        name: "lan_local_arp",
        summary: "LAN-local ARP reply and forwarding",
        kind: NamedScenarioKind::LanLocalArp,
    },
    NamedScenario {
        name: "wan_udp_nat",
        summary: "WAN UDP NAT44 forwarding",
        kind: NamedScenarioKind::WanUdpNat,
    },
    NamedScenario {
        name: "wan_tcp_allow",
        summary: "WAN TCP allow with NAT44",
        kind: NamedScenarioKind::WanTcpAllow,
    },
    NamedScenario {
        name: "wan_udp_deny",
        summary: "WAN UDP firewall deny",
        kind: NamedScenarioKind::WanUdpDeny,
    },
    NamedScenario {
        name: "dynamic_arp_then_forward",
        summary: "Dynamic ARP resolution then forwarding",
        kind: NamedScenarioKind::DynamicArpThenForward,
    },
    NamedScenario {
        name: "ttl_exceeded",
        summary: "IPv4 TTL exceeded ICMPv4 reply",
        kind: NamedScenarioKind::TtlExceeded,
    },
    NamedScenario {
        name: "host_unreachable_after_max_arp_attempts",
        summary: "Host unreachable after ARP exhaustion",
        kind: NamedScenarioKind::HostUnreachableAfterMaxArpAttempts,
    },
    NamedScenario {
        name: "reload_rollback",
        summary: "Finite logical-time reload and rollback",
        kind: NamedScenarioKind::ReloadRollback,
    },
];

impl NamedScenario {
    /// Returns the exact stable catalog name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the exact stable human-readable catalog summary.
    #[must_use]
    pub const fn summary(&self) -> &'static str {
        self.summary
    }

    /// Runs this compiled scenario with a fresh runtime and simulator.
    pub fn run(&self) -> Result<Vec<TickOutcome>, RunNamedScenarioError> {
        let descriptor = descriptor_for(self.kind).map_err(RunNamedScenarioError::Descriptor)?;
        run_descriptor(&descriptor).map_err(RunNamedScenarioError::Scenario)
    }
}

impl fmt::Debug for NamedScenario {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NamedScenario")
            .field("name", &self.name)
            .field("summary", &self.summary)
            .finish()
    }
}

impl fmt::Display for NamedScenario {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "NamedScenario(name={}, summary={})",
            self.name, self.summary
        )
    }
}

/// Returns the ordered compiled catalog.
#[must_use]
pub fn named_scenarios() -> &'static [NamedScenario] {
    &NAMED_SCENARIOS
}

/// Looks up one catalog entry using exact, case-sensitive, non-normalized
/// matching. The error never retains or formats the supplied input.
pub fn named_scenario(name: &str) -> Result<&'static NamedScenario, ScenarioLookupError> {
    NAMED_SCENARIOS
        .iter()
        .find(|scenario| scenario.name == name)
        .ok_or(ScenarioLookupError::UnknownName)
}

/// Looks up and runs one compiled named scenario.
pub fn run_named_scenario(name: &str) -> Result<Vec<TickOutcome>, RunNamedScenarioError> {
    let scenario = named_scenario(name).map_err(RunNamedScenarioError::Lookup)?;
    scenario.run()
}

fn descriptor_for(kind: NamedScenarioKind) -> Result<ScenarioDescriptor, ScenarioDescriptorError> {
    match kind {
        NamedScenarioKind::LanLocalArp => ScenarioDescriptor::new(lan_local_arp(), Vec::new()),
        NamedScenarioKind::WanUdpNat => ScenarioDescriptor::new(wan_udp_nat(), Vec::new()),
        NamedScenarioKind::WanTcpAllow => ScenarioDescriptor::new(wan_tcp_allow(), Vec::new()),
        NamedScenarioKind::WanUdpDeny => ScenarioDescriptor::new(wan_udp_deny(), Vec::new()),
        NamedScenarioKind::DynamicArpThenForward => {
            ScenarioDescriptor::new(dynamic_arp_then_forward(), Vec::new())
        }
        NamedScenarioKind::TtlExceeded => ScenarioDescriptor::new(ttl_exceeded(), Vec::new()),
        NamedScenarioKind::HostUnreachableAfterMaxArpAttempts => {
            ScenarioDescriptor::new(host_unreachable_after_max_arp_attempts(), Vec::new())
        }
        NamedScenarioKind::ReloadRollback => reload_rollback(),
    }
}

fn one_tick_scenario(
    name: &'static str,
    config_toml: &'static str,
    seed: u64,
    interface: IfId,
    frame: Vec<u8>,
) -> Scenario {
    Scenario {
        name,
        config_toml,
        generation: 7,
        seed,
        ticks: vec![crate::ScenarioTick {
            now: MonotonicMillis(0),
            ingress: vec![crate::ScenarioIngress::new(interface, frame)],
        }],
    }
}

fn lan_local_arp() -> Scenario {
    one_tick_scenario(
        "lan_local_arp",
        FULL_SERVICE,
        11,
        LAN,
        arp_request(HOST_MAC, HOST_IP, LAN_IP),
    )
}

fn wan_udp_nat() -> Scenario {
    one_tick_scenario(
        "wan_udp_nat",
        UDP_NAT,
        11,
        LAN,
        udp_frame(LAN_HOP, HOST_IP, REMOTE_IP, 51_000, 53, 64, b"query"),
    )
}

fn wan_tcp_allow() -> Scenario {
    one_tick_scenario(
        "wan_tcp_allow",
        FULL_SERVICE,
        11,
        LAN,
        tcp_syn_frame(LAN_HOP, HOST_IP, REMOTE_IP, 52_000, 443, 64, 1000),
    )
}

fn wan_udp_deny() -> Scenario {
    one_tick_scenario(
        "wan_udp_deny",
        FULL_SERVICE,
        11,
        LAN,
        udp_frame(LAN_HOP, HOST_IP, REMOTE_IP, 51_000, 53, 64, b"query"),
    )
}

fn dynamic_arp_then_forward() -> Scenario {
    Scenario {
        name: "dynamic_arp_then_forward",
        config_toml: DIRECT_WAN_ROUTE,
        generation: 7,
        seed: 11,
        ticks: vec![
            crate::ScenarioTick {
                now: MonotonicMillis(0),
                ingress: vec![crate::ScenarioIngress::new(
                    LAN,
                    udp_frame(
                        LAN_HOP,
                        HOST_IP,
                        RESOLVABLE_HOST_IP,
                        51_100,
                        53,
                        64,
                        b"hello",
                    ),
                )],
            },
            crate::ScenarioTick {
                now: MonotonicMillis(500),
                ingress: vec![crate::ScenarioIngress::new(
                    WAN,
                    arp_reply(RESOLVABLE_HOST_MAC, RESOLVABLE_HOST_IP, WAN_MAC, WAN_IP),
                )],
            },
            crate::ScenarioTick {
                now: MonotonicMillis(600),
                ingress: vec![crate::ScenarioIngress::new(
                    LAN,
                    udp_frame(
                        LAN_HOP,
                        HOST_IP,
                        RESOLVABLE_HOST_IP,
                        51_100,
                        53,
                        64,
                        b"hello",
                    ),
                )],
            },
        ],
    }
}

fn ttl_exceeded() -> Scenario {
    one_tick_scenario(
        "ttl_exceeded",
        UDP_NAT,
        11,
        LAN,
        udp_frame(LAN_HOP, HOST_IP, REMOTE_IP, 51_000, 53, 1, b"query"),
    )
}

fn host_unreachable_after_max_arp_attempts() -> Scenario {
    Scenario {
        name: "host_unreachable_after_max_arp_attempts",
        config_toml: DIRECT_WAN_ROUTE,
        generation: 7,
        seed: 11,
        ticks: vec![
            crate::ScenarioTick {
                now: MonotonicMillis(0),
                ingress: vec![crate::ScenarioIngress::new(
                    LAN,
                    udp_frame(
                        LAN_HOP,
                        HOST_IP,
                        UNREACHABLE_HOST_IP,
                        51_000,
                        9_999,
                        64,
                        b"probe",
                    ),
                )],
            },
            crate::ScenarioTick {
                now: MonotonicMillis(1_000),
                ingress: Vec::new(),
            },
            crate::ScenarioTick {
                now: MonotonicMillis(2_000),
                ingress: Vec::new(),
            },
            crate::ScenarioTick {
                now: MonotonicMillis(3_000),
                ingress: Vec::new(),
            },
        ],
    }
}

fn reload_rollback() -> Result<ScenarioDescriptor, ScenarioDescriptorError> {
    let scenario = Scenario {
        name: "reload_rollback",
        config_toml: UDP_NAT,
        generation: 7,
        seed: 11,
        ticks: vec![
            crate::ScenarioTick {
                now: MonotonicMillis(0),
                ingress: vec![crate::ScenarioIngress::new(
                    LAN,
                    udp_frame(LAN_HOP, HOST_IP, REMOTE_IP, 51_000, 53, 64, b"query"),
                )],
            },
            crate::ScenarioTick {
                now: MonotonicMillis(1_000),
                ingress: vec![crate::ScenarioIngress::new(
                    LAN,
                    udp_frame(LAN_HOP, HOST_IP, REMOTE_IP, 51_000, 53, 64, b"query"),
                )],
            },
            crate::ScenarioTick {
                now: MonotonicMillis(2_000),
                ingress: vec![crate::ScenarioIngress::new(
                    LAN,
                    udp_frame(LAN_HOP, HOST_IP, REMOTE_IP, 51_000, 53, 64, b"query"),
                )],
            },
        ],
    };
    let reload = ScenarioPublicationEvent::reload(MonotonicMillis(1_000), 8, FULL_SERVICE, 111)
        .expect("compiled reload event is structurally valid");
    let rollback = ScenarioPublicationEvent::rollback(MonotonicMillis(2_000), 9, 7, 211)
        .expect("compiled rollback event is structurally valid");
    ScenarioDescriptor::new(scenario, vec![reload, rollback])
}

#[cfg(test)]
mod tests {
    use super::{descriptor_for, NamedScenarioKind};
    use crate::{
        run_named_scenario,
        test_observer::{BatchEvidence, InjectionEvidence, RecycleEvidence, RxEvidence},
        PublicationSummary, Scenario, TickOutcome,
    };
    use ruster_core::{DropReason, IfId, Ipv4Address, MonotonicMillis, TraceEvent};
    use ruster_runtime::{TickPhase, TickPhaseTrace};

    // This is deliberately a test-owned copy of the scenario contract. The
    // oracle below must not derive its expected input from `fixtures.rs` or
    // from the production `udp_frame` builder it verifies.
    const TEST_FULL_SERVICE: &str = include_str!("../tests/fixtures/full-service-golden.toml");
    const TEST_SCENARIO_NAME: &str = "wan_udp_deny";
    const TEST_GENERATION: u64 = 7;
    const TEST_SEED: u64 = 11;
    const TEST_INGRESS: IfId = IfId(1);

    const TEST_DESTINATION_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
    const TEST_SOURCE_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 4];
    const TEST_ETHERTYPE_IPV4: u16 = 0x0800;
    const TEST_SOURCE_IP: [u8; 4] = [192, 0, 2, 20];
    const TEST_DESTINATION_IP: [u8; 4] = [203, 0, 113, 5];
    const TEST_IPV4_TOTAL_LENGTH: u16 = 33;
    const TEST_IPV4_IDENTIFICATION: u16 = 0;
    const TEST_IPV4_FLAGS_FRAGMENT: u16 = 0x4000;
    const TEST_IPV4_TTL: u8 = 64;
    const TEST_IPPROTO_UDP: u8 = 17;
    const TEST_IPV4_HEADER_CHECKSUM: u16 = 0x3cb2;
    const TEST_SOURCE_PORT: u16 = 51_000;
    const TEST_DESTINATION_PORT: u16 = 53;
    const TEST_UDP_LENGTH: u16 = 13;
    const TEST_UDP_CHECKSUM: u16 = 0xea63;
    const TEST_PAYLOAD: &[u8; 5] = b"query";
    const TEST_UDP_SEGMENT_LENGTH: usize = 8 + TEST_PAYLOAD.len();
    const TEST_PSEUDO_LENGTH: usize = 12 + TEST_UDP_SEGMENT_LENGTH;
    const TEST_FRAME_LENGTH: usize = 14 + 20 + TEST_UDP_SEGMENT_LENGTH;

    fn fold_checksum(mut sum: u32) -> u32 {
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum
    }

    fn test_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0_u32;
        for chunk in bytes.chunks(2) {
            let word =
                (u32::from(chunk[0]) << 8) | u32::from(chunk.get(1).copied().unwrap_or_default());
            sum = fold_checksum(sum + word);
        }
        (!fold_checksum(sum)) as u16
    }

    fn test_owned_udp_query_frame() -> [u8; TEST_FRAME_LENGTH] {
        let mut frame = [0_u8; TEST_FRAME_LENGTH];
        frame[0..6].copy_from_slice(&TEST_DESTINATION_MAC);
        frame[6..12].copy_from_slice(&TEST_SOURCE_MAC);
        frame[12..14].copy_from_slice(&TEST_ETHERTYPE_IPV4.to_be_bytes());

        let mut ip = [0_u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&TEST_IPV4_TOTAL_LENGTH.to_be_bytes());
        ip[4..6].copy_from_slice(&TEST_IPV4_IDENTIFICATION.to_be_bytes());
        ip[6..8].copy_from_slice(&TEST_IPV4_FLAGS_FRAGMENT.to_be_bytes());
        ip[8] = TEST_IPV4_TTL;
        ip[9] = TEST_IPPROTO_UDP;
        ip[12..16].copy_from_slice(&TEST_SOURCE_IP);
        ip[16..20].copy_from_slice(&TEST_DESTINATION_IP);
        let ip_checksum = test_checksum(&ip);
        assert_eq!(ip_checksum, TEST_IPV4_HEADER_CHECKSUM);
        ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        frame[14..34].copy_from_slice(&ip);

        let mut udp = [0_u8; TEST_UDP_SEGMENT_LENGTH];
        udp[0..2].copy_from_slice(&TEST_SOURCE_PORT.to_be_bytes());
        udp[2..4].copy_from_slice(&TEST_DESTINATION_PORT.to_be_bytes());
        udp[4..6].copy_from_slice(&TEST_UDP_LENGTH.to_be_bytes());
        udp[8..].copy_from_slice(TEST_PAYLOAD);

        let mut pseudo = [0_u8; TEST_PSEUDO_LENGTH];
        pseudo[0..4].copy_from_slice(&TEST_SOURCE_IP);
        pseudo[4..8].copy_from_slice(&TEST_DESTINATION_IP);
        pseudo[9] = TEST_IPPROTO_UDP;
        pseudo[10..12].copy_from_slice(&TEST_UDP_LENGTH.to_be_bytes());
        pseudo[12..].copy_from_slice(&udp);
        let udp_checksum = test_checksum(&pseudo);
        assert_eq!(udp_checksum, TEST_UDP_CHECKSUM);
        udp[6..8].copy_from_slice(&udp_checksum.to_be_bytes());
        frame[34..].copy_from_slice(&udp);
        frame
    }

    fn input_matches_independent_oracle(scenario: &Scenario) -> bool {
        if scenario.name != TEST_SCENARIO_NAME
            || scenario.config_toml != TEST_FULL_SERVICE
            || scenario.generation != TEST_GENERATION
            || scenario.seed != TEST_SEED
        {
            return false;
        }

        let Some(tick) = scenario.ticks.as_slice().first() else {
            return false;
        };
        if scenario.ticks.len() != 1 || tick.now != MonotonicMillis(0) {
            return false;
        }
        let Some(ingress) = tick.ingress.as_slice().first() else {
            return false;
        };
        if tick.ingress.len() != 1 || ingress.interface != TEST_INGRESS {
            return false;
        }

        let frame = ingress.bytes.as_slice();
        if frame.len() != TEST_FRAME_LENGTH
            || frame != test_owned_udp_query_frame().as_slice()
            || frame[0..6] != TEST_DESTINATION_MAC
            || frame[6..12] != TEST_SOURCE_MAC
            || u16::from_be_bytes([frame[12], frame[13]]) != TEST_ETHERTYPE_IPV4
        {
            return false;
        }

        let ip = &frame[14..34];
        if ip[0] != 0x45
            || u16::from_be_bytes([ip[2], ip[3]]) != TEST_IPV4_TOTAL_LENGTH
            || u16::from_be_bytes([ip[4], ip[5]]) != TEST_IPV4_IDENTIFICATION
            || u16::from_be_bytes([ip[6], ip[7]]) != TEST_IPV4_FLAGS_FRAGMENT
            || ip[8] != TEST_IPV4_TTL
            || ip[9] != TEST_IPPROTO_UDP
            || u16::from_be_bytes([ip[10], ip[11]]) != TEST_IPV4_HEADER_CHECKSUM
            || ip[12..16] != TEST_SOURCE_IP
            || ip[16..20] != TEST_DESTINATION_IP
        {
            return false;
        }
        let mut ip_for_checksum = [0_u8; 20];
        ip_for_checksum.copy_from_slice(ip);
        ip_for_checksum[10..12].fill(0);
        if test_checksum(&ip_for_checksum) != TEST_IPV4_HEADER_CHECKSUM {
            return false;
        }

        let udp = &frame[34..];
        if u16::from_be_bytes([udp[0], udp[1]]) != TEST_SOURCE_PORT
            || u16::from_be_bytes([udp[2], udp[3]]) != TEST_DESTINATION_PORT
            || u16::from_be_bytes([udp[4], udp[5]]) != TEST_UDP_LENGTH
            || u16::from_be_bytes([udp[6], udp[7]]) != TEST_UDP_CHECKSUM
            || &udp[8..] != TEST_PAYLOAD.as_slice()
        {
            return false;
        }
        let mut udp_for_checksum = [0_u8; TEST_UDP_SEGMENT_LENGTH];
        udp_for_checksum.copy_from_slice(udp);
        udp_for_checksum[6..8].fill(0);
        let mut pseudo = [0_u8; TEST_PSEUDO_LENGTH];
        pseudo[0..4].copy_from_slice(&TEST_SOURCE_IP);
        pseudo[4..8].copy_from_slice(&TEST_DESTINATION_IP);
        pseudo[9] = TEST_IPPROTO_UDP;
        pseudo[10..12].copy_from_slice(&TEST_UDP_LENGTH.to_be_bytes());
        pseudo[12..].copy_from_slice(&udp_for_checksum);
        test_checksum(&pseudo) == TEST_UDP_CHECKSUM
    }

    fn fresh_wan_udp_deny_scenario() -> Scenario {
        descriptor_for(NamedScenarioKind::WanUdpDeny)
            .expect("wan_udp_deny descriptor must be structurally valid")
            .initial_scenario()
            .clone()
    }

    #[test]
    fn r11sim_030_wan_udp_deny_descriptor_has_exact_valid_udp_query_input() {
        let scenario = fresh_wan_udp_deny_scenario();
        assert!(
            input_matches_independent_oracle(&scenario),
            "wan_udp_deny must inject the exact test-owned valid UDP query"
        );
    }

    #[test]
    fn r11sim_031_wan_udp_deny_input_oracle_rejects_payload_mutation() {
        let mut scenario = fresh_wan_udp_deny_scenario();
        scenario.ticks[0].ingress[0].bytes[42] ^= 1;
        assert!(!input_matches_independent_oracle(&scenario));
    }

    #[test]
    fn r11sim_032_wan_udp_deny_input_oracle_rejects_empty_frame() {
        let mut scenario = fresh_wan_udp_deny_scenario();
        scenario.ticks[0].ingress[0].bytes.clear();
        assert!(!input_matches_independent_oracle(&scenario));
    }

    #[test]
    fn r11sim_033_wan_udp_deny_input_oracle_rejects_truncated_frame() {
        let mut scenario = fresh_wan_udp_deny_scenario();
        scenario.ticks[0].ingress[0]
            .bytes
            .truncate(TEST_FRAME_LENGTH - 1);
        assert!(!input_matches_independent_oracle(&scenario));
    }

    #[test]
    fn r11sim_034_wan_udp_deny_input_oracle_rejects_udp_port_mutation() {
        let mut scenario = fresh_wan_udp_deny_scenario();
        scenario.ticks[0].ingress[0].bytes[34] ^= 1;
        assert!(!input_matches_independent_oracle(&scenario));
    }

    #[test]
    fn r11sim_035_wan_udp_deny_input_oracle_rejects_udp_length_mutation() {
        let mut scenario = fresh_wan_udp_deny_scenario();
        scenario.ticks[0].ingress[0].bytes[39] = 12;
        assert!(!input_matches_independent_oracle(&scenario));
    }

    #[test]
    fn r11sim_036_wan_udp_deny_input_oracle_rejects_ttl_mutation() {
        let mut scenario = fresh_wan_udp_deny_scenario();
        scenario.ticks[0].ingress[0].bytes[22] ^= 1;
        assert!(!input_matches_independent_oracle(&scenario));
    }

    #[test]
    fn r11sim_037_wan_udp_deny_input_oracle_rejects_ip_mutation() {
        let mut scenario = fresh_wan_udp_deny_scenario();
        scenario.ticks[0].ingress[0].bytes[33] ^= 1;
        assert!(!input_matches_independent_oracle(&scenario));
    }

    #[test]
    fn r11sim_038_wan_udp_deny_input_oracle_rejects_ipv4_checksum_mutation() {
        let mut scenario = fresh_wan_udp_deny_scenario();
        scenario.ticks[0].ingress[0].bytes[24] ^= 1;
        assert!(!input_matches_independent_oracle(&scenario));
    }

    #[test]
    fn r11sim_039_wan_udp_deny_input_oracle_rejects_udp_checksum_mutation() {
        let mut scenario = fresh_wan_udp_deny_scenario();
        scenario.ticks[0].ingress[0].bytes[40] ^= 1;
        assert!(!input_matches_independent_oracle(&scenario));
    }

    #[test]
    fn r11sim_040_wan_udp_deny_public_execution_reaches_firewall_rule_denied() {
        let (outcomes, evidence) = {
            let observer = crate::test_observer::scoped();
            let outcomes = run_named_scenario("wan_udp_deny").expect("named scenario must run");
            assert_eq!(
                outcomes,
                vec![TickOutcome {
                    now: MonotonicMillis(0),
                    generation: std::num::NonZeroU64::new(7).expect("literal is nonzero"),
                    publication: PublicationSummary::Unchanged,
                    active: true,
                    tx: Vec::new(),
                }]
            );
            let evidence = observer.finish();
            (outcomes, evidence)
        };

        assert!(crate::test_observer::is_clear());
        assert_eq!(evidence.tick_count(), 1);
        assert!(!evidence.overflowed());

        let tick = evidence.tick(0).expect("one public tick must be captured");
        assert_eq!(tick.now(), MonotonicMillis(0));
        assert_eq!(tick.generation().get(), 7);
        assert!(tick.active());
        assert!(!tick.overflowed());
        assert_eq!(
            tick.injections().collect::<Vec<_>>(),
            vec![InjectionEvidence {
                now: MonotonicMillis(0),
                ingress: IfId(1),
                sequence: 0,
            }]
        );
        assert_eq!(tick.pending_rx(), 0);
        assert_eq!(tick.pending_tx(), 0);
        assert_eq!(
            tick.rx(),
            RxEvidence::Completed(BatchEvidence {
                received: 1,
                tx_requested: 0,
                dropped: 1,
                consumed: 0,
                completion_tx_requested: 0,
                completion_tx_accepted: 0,
                completion_tx_rejected: 0,
                completion_recycled: 1,
                completion_error: false,
                invariants_hold: true,
            })
        );
        assert_eq!(
            tick.recycled().collect::<Vec<_>>(),
            vec![RecycleEvidence {
                sequence: 0,
                ingress: IfId(1),
                cause: ruster_io_sim::RecycleCause::Forwarding(DropReason::FirewallRuleDenied),
            }]
        );

        assert_eq!(
            tick.trace_events().collect::<Vec<_>>(),
            vec![
                TraceEvent::Ipv4Validated {
                    ingress: IfId(1),
                    destination: Ipv4Address::from_octets([203, 0, 113, 5]),
                },
                TraceEvent::Dropped {
                    ingress: IfId(1),
                    reason: DropReason::FirewallRuleDenied,
                },
                TraceEvent::BatchCompleted {
                    tx_accepted: 0,
                    tx_rejected: 0,
                },
            ]
        );
        assert_eq!(
            tick.trace_events()
                .filter_map(|event| match event {
                    TraceEvent::Dropped { ingress, reason } => Some((ingress, reason)),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            vec![(IfId(1), DropReason::FirewallRuleDenied)]
        );
        assert_eq!(
            tick.phase_events().collect::<Vec<_>>(),
            vec![
                TickPhaseTrace::TickStarted,
                TickPhaseTrace::PhaseStarted(TickPhase::Publication),
                TickPhaseTrace::PhaseFinished(TickPhase::Publication),
                TickPhaseTrace::PhaseStarted(TickPhase::Rx),
                TickPhaseTrace::PhaseFinished(TickPhase::Rx),
                TickPhaseTrace::PhaseStarted(TickPhase::ResolutionTimers),
                TickPhaseTrace::PhaseFinished(TickPhase::ResolutionTimers),
                TickPhaseTrace::PhaseStarted(TickPhase::FailureDispatch),
                TickPhaseTrace::PhaseFinished(TickPhase::FailureDispatch),
                TickPhaseTrace::PhaseStarted(TickPhase::GeneratedArp),
                TickPhaseTrace::PhaseFinished(TickPhase::GeneratedArp),
                TickPhaseTrace::PhaseStarted(TickPhase::GeneratedIcmpv4),
                TickPhaseTrace::PhaseFinished(TickPhase::GeneratedIcmpv4),
                TickPhaseTrace::TickFinished,
            ]
        );
        assert!(!tick
            .phase_events()
            .any(|event| matches!(event, TickPhaseTrace::PhaseSkipped { .. })));

        assert!(crate::test_observer::is_clear());
        let other = run_named_scenario("lan_local_arp").expect("other named scenario must run");
        assert_eq!(other.len(), 1);
        assert!(crate::test_observer::is_clear());

        drop(outcomes);
        assert!(crate::test_observer::is_clear());
    }
}
