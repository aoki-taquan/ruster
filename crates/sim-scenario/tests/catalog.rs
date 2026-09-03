mod support;

use ruster_core::{IfId, MonotonicMillis};
use ruster_sim_scenario::{
    attempt_publication, named_scenario, named_scenarios, run_descriptor, run_named_scenario,
    FrameOrigin, NamedScenario, PublicationSummary, RunNamedScenarioError, Scenario,
    ScenarioDescriptor, ScenarioDescriptorError, ScenarioError, ScenarioIngress,
    ScenarioLookupError, ScenarioPublicationEvent, ScenarioPublicationFailureKind,
    ScenarioPublicationKind, ScenarioRejectReason, ScenarioRestartReason, ScenarioTick,
    TickOutcome, MAX_SCENARIO_PUBLICATION_EVENTS, MAX_SCENARIO_TICKS, NAMED_SCENARIO_COUNT,
    NAMED_SCENARIO_NAMES,
};
use support::{
    arp_reply, arp_request, icmp_error_frame, ipv4_udp_packet, tcp_syn_frame, udp_frame,
    EthernetHop, FULL_SERVICE, HOST_IP, HOST_MAC, LAN, LAN_HOP, LAN_IP, LAN_MAC, REMOTE_IP,
    RESOLVABLE_HOST_IP, RESOLVABLE_HOST_MAC, UDP_NAT, UNREACHABLE_HOST_IP, WAN_IP, WAN_MAC,
    WAN_NEXT_HOP_MAC,
};

const SHAPE_CHANGED_CONFIG: &str = include_str!("fixtures/full-service-shape-changed.toml");
const EXPECTED_CATALOG_NAMES: [&str; 8] = [
    "lan_local_arp",
    "wan_udp_nat",
    "wan_tcp_allow",
    "wan_udp_deny",
    "dynamic_arp_then_forward",
    "ttl_exceeded",
    "host_unreachable_after_max_arp_attempts",
    "reload_rollback",
];

fn scenario_with_times(times: &[u64], generation: u64, seed: u64) -> Scenario {
    Scenario {
        name: "catalog-test",
        config_toml: FULL_SERVICE,
        generation,
        seed,
        ticks: times
            .iter()
            .copied()
            .map(|now| ScenarioTick {
                now: MonotonicMillis(now),
                ingress: Vec::new(),
            })
            .collect(),
    }
}

fn reload(at: u64, generation: u64, seed: u64) -> ScenarioPublicationEvent {
    ScenarioPublicationEvent::reload(MonotonicMillis(at), generation, FULL_SERVICE, seed)
        .expect("test reload event must have a nonzero generation")
}

fn udp_ingress() -> ScenarioIngress {
    ScenarioIngress::new(
        LAN,
        udp_frame(LAN_HOP, HOST_IP, REMOTE_IP, 51_000, 53, 64, b"query"),
    )
}

fn bare_scenario(config_toml: &'static str, generation: u64, seed: u64) -> Scenario {
    Scenario {
        name: "catalog-publication-test",
        config_toml,
        generation,
        seed,
        ticks: Vec::new(),
    }
}

#[test]
fn r11sim_010_compiled_catalog_has_exact_order_metadata_and_lookup() {
    assert_eq!(NAMED_SCENARIO_COUNT, 8);
    assert_eq!(NAMED_SCENARIO_NAMES, EXPECTED_CATALOG_NAMES);
    let catalog = named_scenarios();
    assert_eq!(catalog.len(), NAMED_SCENARIO_COUNT);
    let names = catalog.iter().map(NamedScenario::name).collect::<Vec<_>>();
    assert_eq!(names, EXPECTED_CATALOG_NAMES);
    assert!(names.windows(2).all(|pair| pair[0] != pair[1]));
    for (entry, expected_name) in catalog.iter().zip(EXPECTED_CATALOG_NAMES) {
        assert_eq!(entry.name(), expected_name);
        assert!(!entry.summary().is_empty());
        assert_eq!(named_scenario(expected_name), Ok(entry));
    }
}

#[test]
fn r11sim_011_lookup_is_exact_and_unknown_errors_are_value_free() {
    let unknown_inputs = [
        "",
        "LAN_LOCAL_ARP",
        "wAn_udp_nat",
        "wan-udp-nat",
        concat!("wan_udp_n", "\u{0430}", "t"),
        " lan_local_arp",
        "lan_local_arp ",
        "catalog-input-sentinel",
    ];
    let mut first_error = None;
    for input in unknown_inputs {
        let error = named_scenario(input).expect_err("non-exact names must not resolve");
        assert_eq!(error, ScenarioLookupError::UnknownName);
        let debug = format!("{error:?}");
        let display = error.to_string();
        if !input.is_empty() {
            assert!(!debug.contains(input));
            assert!(!display.contains(input));
        }
        first_error.get_or_insert(error);
    }
    assert_eq!(first_error, Some(ScenarioLookupError::UnknownName));
    let run_error = run_named_scenario("catalog-input-sentinel").expect_err("lookup must fail");
    assert_eq!(
        run_error,
        RunNamedScenarioError::Lookup(ScenarioLookupError::UnknownName)
    );
    assert!(!format!("{run_error:?}").contains("catalog-input-sentinel"));
    assert!(!run_error.to_string().contains("catalog-input-sentinel"));
}

#[test]
fn r11sim_018_debug_error_and_public_frame_summary_redact_raw_values() {
    const SECRET_SEED: u64 = 0xfeed_face_cafe_beef;
    let initial = bare_scenario(FULL_SERVICE, 7, SECRET_SEED);
    let successor = bare_scenario(SHAPE_CHANGED_CONFIG, 8, SECRET_SEED + 100);
    let error = attempt_publication(&initial, &successor).expect_err("shape change must reject");
    let failure = match error {
        ScenarioError::Publication(failure) => *failure,
        other => panic!("expected retained publication failure, got {other:?}"),
    };

    let outcome = run_named_scenario("wan_udp_nat")
        .expect("compiled UDP scenario must run")
        .pop()
        .expect("compiled UDP scenario has one tick");
    let frame = outcome
        .tx
        .first()
        .expect("compiled UDP scenario emits one frame");
    let rendered = [
        format!("{:?}", outcome),
        format!("{:#?}", outcome),
        outcome.to_string(),
        format!("{:?}", frame),
        format!("{:#?}", frame),
        frame.to_string(),
        format!("{:?}", failure),
        format!("{:#?}", failure),
        failure.to_string(),
        format!("{:?}", ScenarioError::UnexpectedPublication),
        ScenarioError::UnexpectedPublication.to_string(),
    ];
    for output in rendered {
        assert!(!output.contains("bytes:"));
        assert!(!output.contains("payload"));
        assert!(!output.contains("query"));
        assert!(!output.contains(&SECRET_SEED.to_string()));
        assert!(!output.contains("allocator-seed"));
        assert!(!output.contains("hash_key"));
        assert!(!output.contains("authority"));
    }
    let outcome_debug = format!("{:?}", outcome);
    assert!(outcome_debug.contains("tx_count"));
    assert!(outcome_debug.contains("byte_len"));
    assert!(format!("{:?}", frame).contains("egress"));
    failure.discard_candidate();
}

#[test]
fn r11sim_019_public_candidate_authority_is_closed_to_value_only_summary() {
    const SECRET_SEED: u64 = 0x1234_5678_9abc_def0;
    let initial = bare_scenario(FULL_SERVICE, 7, SECRET_SEED);
    let successor = bare_scenario(SHAPE_CHANGED_CONFIG, 8, SECRET_SEED + 100);
    let error = attempt_publication(&initial, &successor).expect_err("shape change must reject");
    let failure = match error {
        ScenarioError::Publication(failure) => *failure,
        other => panic!("expected retained publication failure, got {other:?}"),
    };
    let summary = failure.candidate_summary();
    assert_eq!(summary.generation().get(), 8);
    assert_eq!(summary.tick().rx(), 64);
    assert_eq!(summary.tick().resolution_timer_scans(), 16);
    let summary_debug = format!("{summary:?}");
    assert!(!summary_debug.contains("key"));
    assert!(!summary_debug.contains("seed"));
    assert!(!summary_debug.contains("config"));
    failure.discard_candidate();
}

#[test]
fn r11sim_020_restart_required_preserves_candidate_and_active_generation() {
    let initial = bare_scenario(FULL_SERVICE, 7, 11);
    let successor = bare_scenario(SHAPE_CHANGED_CONFIG, 8, 111);
    let error = attempt_publication(&initial, &successor).expect_err("shape change must reject");
    let failure = match error {
        ScenarioError::Publication(failure) => *failure,
        other => panic!("expected retained publication failure, got {other:?}"),
    };
    assert_eq!(
        failure.kind(),
        ScenarioPublicationFailureKind::RestartRequired(
            ScenarioRestartReason::RuntimeStorageShapeChanged
        )
    );
    assert_eq!(failure.active_generation().get(), 7);
    assert_eq!(failure.candidate_summary().generation().get(), 8);
    assert_eq!(failure.into_candidate().summary().generation().get(), 8);
}

#[test]
fn r11sim_021_generation_rejection_preserves_candidate_and_active_generation() {
    let initial = bare_scenario(FULL_SERVICE, 7, 11);
    let successor = bare_scenario(FULL_SERVICE, 7, 111);
    let error =
        attempt_publication(&initial, &successor).expect_err("stale generation must reject");
    let failure = match error {
        ScenarioError::Publication(failure) => *failure,
        other => panic!("expected retained publication failure, got {other:?}"),
    };
    assert_eq!(
        failure.kind(),
        ScenarioPublicationFailureKind::Rejected(ScenarioRejectReason::GenerationNotIncreasing)
    );
    assert_eq!(failure.active_generation().get(), 7);
    assert_eq!(failure.candidate_summary().generation().get(), 7);
    failure.into_candidate().discard();
}

#[test]
fn r11sim_022_hash_key_rejection_preserves_candidate_and_active_generation() {
    let initial = bare_scenario(FULL_SERVICE, 7, 11);
    let successor = bare_scenario(FULL_SERVICE, 8, 11);
    let error = attempt_publication(&initial, &successor).expect_err("reused key must reject");
    let failure = match error {
        ScenarioError::Publication(failure) => *failure,
        other => panic!("expected retained publication failure, got {other:?}"),
    };
    assert_eq!(
        failure.kind(),
        ScenarioPublicationFailureKind::Rejected(ScenarioRejectReason::Nat44UdpHashKeyReused)
    );
    assert_eq!(failure.active_generation().get(), 7);
    assert_eq!(failure.candidate_summary().generation().get(), 8);
    failure.discard_candidate();
}

#[test]
fn r11sim_012_descriptor_bounds_times_binding_and_generation_validation() {
    let max_times = (0..MAX_SCENARIO_TICKS as u64).collect::<Vec<_>>();
    assert!(ScenarioDescriptor::new(scenario_with_times(&max_times, 1, 10), Vec::new()).is_ok());
    let too_many_times = (0..=MAX_SCENARIO_TICKS as u64).collect::<Vec<_>>();
    assert_eq!(
        ScenarioDescriptor::new(scenario_with_times(&too_many_times, 1, 10), Vec::new())
            .expect_err("tick limit must be finite"),
        ScenarioDescriptorError::TooManyTicks
    );

    let event_times = (1..=MAX_SCENARIO_PUBLICATION_EVENTS as u64).collect::<Vec<_>>();
    let all_event_ticks = (0..=MAX_SCENARIO_PUBLICATION_EVENTS as u64).collect::<Vec<_>>();
    let events = event_times
        .iter()
        .copied()
        .enumerate()
        .map(|(index, at)| reload(at, index as u64 + 2, index as u64 + 100))
        .collect::<Vec<_>>();
    assert!(ScenarioDescriptor::new(scenario_with_times(&all_event_ticks, 1, 10), events).is_ok());

    let too_many_events = (1..=MAX_SCENARIO_PUBLICATION_EVENTS as u64 + 1)
        .enumerate()
        .map(|(index, at)| reload(at, index as u64 + 2, index as u64 + 100))
        .collect::<Vec<_>>();
    let too_many_event_ticks = (0..=MAX_SCENARIO_PUBLICATION_EVENTS as u64 + 1).collect::<Vec<_>>();
    assert_eq!(
        ScenarioDescriptor::new(
            scenario_with_times(&too_many_event_ticks, 1, 10),
            too_many_events,
        )
        .expect_err("publication limit must be finite"),
        ScenarioDescriptorError::TooManyPublicationEvents
    );

    assert_eq!(
        ScenarioDescriptor::new(scenario_with_times(&[0, 1, 1], 1, 10), Vec::new())
            .expect_err("equal tick times must fail"),
        ScenarioDescriptorError::TickTimeNotStrictlyIncreasing
    );
    assert_eq!(
        ScenarioDescriptor::new(scenario_with_times(&[0, 2, 1], 1, 10), Vec::new())
            .expect_err("decreasing tick times must fail"),
        ScenarioDescriptorError::TickTimeNotStrictlyIncreasing
    );
    assert_eq!(
        ScenarioDescriptor::new(scenario_with_times(&[0, 1], 1, 10), vec![reload(2, 2, 11)])
            .expect_err("event must bind to a tick"),
        ScenarioDescriptorError::PublicationEventNotOnTick
    );
    assert_eq!(
        ScenarioDescriptor::new(
            scenario_with_times(&[0, 1, 2], 1, 10),
            vec![reload(1, 2, 11), reload(1, 3, 12)],
        )
        .expect_err("one tick accepts at most one event"),
        ScenarioDescriptorError::MoreThanOnePublicationAtTick
    );
    assert_eq!(
        ScenarioDescriptor::new(
            scenario_with_times(&[0, 1, 2], 1, 10),
            vec![reload(2, 2, 11), reload(1, 3, 12)],
        )
        .expect_err("event times must increase"),
        ScenarioDescriptorError::PublicationEventTimeNotStrictlyIncreasing
    );
    assert_eq!(
        ScenarioDescriptor::new(scenario_with_times(&[0], 0, 10), Vec::new())
            .expect_err("initial generation must be nonzero"),
        ScenarioDescriptorError::InitialGenerationZero
    );
    assert_eq!(
        ScenarioPublicationEvent::reload(MonotonicMillis(0), 0, FULL_SERVICE, 11)
            .expect_err("event generation must be nonzero"),
        ScenarioDescriptorError::GenerationZero
    );
    assert_eq!(
        ScenarioDescriptor::new(scenario_with_times(&[0, 1], 1, 10), vec![reload(1, 1, 11)])
            .expect_err("equal generation must fail"),
        ScenarioDescriptorError::GenerationNotIncreasing
    );
    assert_eq!(
        ScenarioDescriptor::new(
            scenario_with_times(&[0, 1, 2], 1, 10),
            vec![reload(1, 3, 11), reload(2, 2, 12)],
        )
        .expect_err("decreasing generation must fail"),
        ScenarioDescriptorError::GenerationNotIncreasing
    );
    assert_eq!(
        ScenarioDescriptor::new(
            scenario_with_times(&[0, 1], u64::MAX, 10),
            vec![reload(1, 1, 11)]
        )
        .expect_err("generation exhaustion must fail"),
        ScenarioDescriptorError::GenerationExhausted
    );

    assert_eq!(
        ScenarioDescriptor::new(
            scenario_with_times(&[0, 1, 2], 1, 10),
            vec![reload(1, 2, 11), reload(2, 3, 11)],
        )
        .expect_err("adjacent identity reuse must fail"),
        ScenarioDescriptorError::IdentityReused
    );
    assert_eq!(
        ScenarioDescriptor::new(
            scenario_with_times(&[0, 1, 2, 3], 1, 10),
            vec![reload(1, 2, 11), reload(2, 3, 12), reload(3, 4, 11)],
        )
        .expect_err("non-adjacent identity reuse must fail"),
        ScenarioDescriptorError::IdentityReused
    );
    assert_eq!(
        ScenarioDescriptor::new(
            scenario_with_times(&[0, 1], 1, 10),
            vec![
                ScenarioPublicationEvent::rollback(MonotonicMillis(1), 2, 2, 11)
                    .expect("source generation is nonzero"),
            ],
        )
        .expect_err("rollback source must be earlier and present"),
        ScenarioDescriptorError::RollbackSourceNotEarlier
    );
    assert_eq!(
        ScenarioDescriptor::new(
            scenario_with_times(&[0, 1], 1, 10),
            vec![
                ScenarioPublicationEvent::rollback(MonotonicMillis(1), 3, 4, 11)
                    .expect("source generation is nonzero"),
            ],
        )
        .expect_err("future rollback source must fail"),
        ScenarioDescriptorError::RollbackSourceNotEarlier
    );
    assert_eq!(
        ScenarioDescriptor::new(
            scenario_with_times(&[0, 1], 1, 10),
            vec![
                ScenarioPublicationEvent::rollback(MonotonicMillis(1), 3, 2, 11)
                    .expect("source generation is nonzero"),
            ],
        )
        .expect_err("rollback source must exist in history"),
        ScenarioDescriptorError::RollbackSourceMissing
    );
}

#[test]
fn r11sim_013_reload_applies_before_same_tick_rx_with_fresh_history_identity() {
    let scenario = Scenario {
        name: "reload-test",
        config_toml: UDP_NAT,
        generation: 7,
        seed: 11,
        ticks: vec![
            ScenarioTick {
                now: MonotonicMillis(0),
                ingress: vec![udp_ingress()],
            },
            ScenarioTick {
                now: MonotonicMillis(1_000),
                ingress: vec![udp_ingress()],
            },
        ],
    };
    let descriptor = ScenarioDescriptor::new(scenario, vec![reload(1_000, 8, 111)])
        .expect("valid reload descriptor");
    let outcomes = run_descriptor(&descriptor).expect("reload scenario must run");
    assert_eq!(outcomes.len(), 2);
    assert_eq!(outcomes[0].generation.get(), 7);
    assert_eq!(outcomes[0].publication, PublicationSummary::Unchanged);
    assert_eq!(outcomes[0].tx.len(), 1);
    assert_eq!(outcomes[1].generation.get(), 8);
    assert_eq!(
        outcomes[1].publication,
        PublicationSummary::Applied {
            previous_generation: std::num::NonZeroU64::new(7).unwrap(),
            generation: std::num::NonZeroU64::new(8).unwrap(),
        }
    );
    assert!(
        outcomes[1].tx.is_empty(),
        "deny config must govern same-tick RX"
    );
}

#[test]
fn r11sim_014_rollback_reuses_old_config_with_new_generation_and_identity() {
    let scenario = Scenario {
        name: "rollback-test",
        config_toml: UDP_NAT,
        generation: 7,
        seed: 11,
        ticks: vec![
            ScenarioTick {
                now: MonotonicMillis(0),
                ingress: vec![udp_ingress()],
            },
            ScenarioTick {
                now: MonotonicMillis(1_000),
                ingress: vec![udp_ingress()],
            },
            ScenarioTick {
                now: MonotonicMillis(2_000),
                ingress: vec![udp_ingress()],
            },
        ],
    };
    let descriptor = ScenarioDescriptor::new(
        scenario,
        vec![
            reload(1_000, 8, 111),
            ScenarioPublicationEvent::rollback(MonotonicMillis(2_000), 9, 7, 211)
                .expect("valid rollback event"),
        ],
    )
    .expect("valid rollback descriptor");
    let outcomes = run_descriptor(&descriptor).expect("rollback scenario must run");
    assert_eq!(
        outcomes
            .iter()
            .map(|outcome| outcome.generation.get())
            .collect::<Vec<_>>(),
        [7, 8, 9]
    );
    assert_eq!(outcomes[0].publication, PublicationSummary::Unchanged);
    assert_eq!(outcomes[0].tx.len(), 1);
    assert_eq!(
        outcomes[1].publication,
        PublicationSummary::Applied {
            previous_generation: std::num::NonZeroU64::new(7).unwrap(),
            generation: std::num::NonZeroU64::new(8).unwrap(),
        }
    );
    assert!(outcomes[1].tx.is_empty());
    assert_eq!(
        outcomes[2].publication,
        PublicationSummary::Applied {
            previous_generation: std::num::NonZeroU64::new(8).unwrap(),
            generation: std::num::NonZeroU64::new(9).unwrap(),
        }
    );
    assert_eq!(outcomes[2].tx.len(), 1);
    assert_eq!(outcomes[2].tx[0].egress, IfId(2));
    assert_eq!(
        outcomes[2].tx[0].origin,
        FrameOrigin::Received { ingress: LAN }
    );
    let compiled =
        run_named_scenario("reload_rollback").expect("compiled reload/rollback scenario must run");
    assert_eq!(
        compiled
            .iter()
            .map(|outcome| outcome.generation.get())
            .collect::<Vec<_>>(),
        [7, 8, 9]
    );
    assert_eq!(
        compiled
            .iter()
            .map(|outcome| outcome.tx.len())
            .collect::<Vec<_>>(),
        [1, 0, 1]
    );
}

#[test]
fn r11sim_015_debug_and_display_redact_config_seed_key_and_lookup_input() {
    const SECRET_CONFIG: &str = "PRIVATE_CONFIG_SENTINEL";
    const SECRET_SEED: u64 = 0xfeed_face_cafe_beef;
    let scenario = Scenario {
        name: "redaction-scenario",
        config_toml: SECRET_CONFIG,
        generation: 7,
        seed: SECRET_SEED,
        ticks: vec![ScenarioTick {
            now: MonotonicMillis(0),
            ingress: Vec::new(),
        }],
    };
    let event =
        ScenarioPublicationEvent::reload(MonotonicMillis(0), 8, SECRET_CONFIG, SECRET_SEED + 1)
            .expect("redaction event generation is valid");
    let descriptor = ScenarioDescriptor::new(scenario.clone(), vec![event.clone()])
        .expect("redaction descriptor is structurally valid");
    let rendered = [
        format!("{:?}", scenario),
        format!("{:#?}", scenario),
        scenario.to_string(),
        format!("{:?}", descriptor),
        format!("{:#?}", descriptor),
        descriptor.to_string(),
        format!("{:?}", event),
        format!("{:#?}", event),
        event.to_string(),
        format!("{:?}", ScenarioError::UnexpectedPublication),
        ScenarioError::UnexpectedPublication.to_string(),
    ];
    for output in rendered {
        assert!(!output.contains(SECRET_CONFIG));
        assert!(!output.contains(&SECRET_SEED.to_string()));
    }
    let lookup_error = named_scenario("private-name-sentinel").expect_err("must not resolve");
    assert!(!format!("{lookup_error:?}").contains("private-name-sentinel"));
    assert!(!lookup_error.to_string().contains("private-name-sentinel"));
}

#[test]
fn r11sim_016_every_catalog_entry_replays_with_complete_tick_equality() {
    for name in NAMED_SCENARIO_NAMES {
        let first = run_named_scenario(name).expect("compiled scenario must run");
        let second = run_named_scenario(name).expect("compiled scenario must replay");
        assert_eq!(first, second, "catalog replay must be exact");
        assert!(first.iter().all(|outcome| outcome.active));
    }
}

#[test]
fn r11sim_017_named_surface_runs_without_external_runtime_inputs() {
    for name in NAMED_SCENARIO_NAMES {
        let entry = named_scenario(name).expect("catalog name must resolve");
        let outcomes = entry.run().expect("named composition must run");
        assert!(!outcomes.is_empty());
        assert_eq!(
            run_named_scenario(name).expect("named wrapper must run"),
            outcomes
        );
    }
}

#[test]
fn r11sim_error_wrappers_remain_value_free() {
    let descriptor_error = ScenarioDescriptorError::IdentityReused;
    let run_error = RunNamedScenarioError::Descriptor(descriptor_error);
    assert_eq!(
        run_error.to_string(),
        "named scenario descriptor is invalid"
    );
    assert!(!format!("{run_error:?}").contains("seed"));
    let scenario_error = ScenarioError::Descriptor(descriptor_error);
    assert!(!scenario_error.to_string().contains("seed"));
    let _unused_type_check: Option<TickOutcome> = None;
    assert_eq!(
        ScenarioPublicationKind::Reload,
        ScenarioPublicationKind::Reload
    );
}

#[derive(Clone, Copy)]
enum PublicationOracle {
    Unchanged,
    Applied {
        previous_generation: u64,
        generation: u64,
    },
}

#[derive(Clone, Copy)]
enum FrameMarker {
    ArpReply,
    ArpRequest { target: [u8; 4] },
    UdpNat,
    UdpResolved,
    TcpNat,
    IcmpTimeExceeded,
    IcmpHostUnreachable,
}

#[derive(Clone, Copy)]
struct FrameOracle {
    sequence: u64,
    ingress: IfId,
    egress: IfId,
    origin: FrameOrigin,
    marker: FrameMarker,
}

struct TickOracle {
    now: u64,
    generation: u64,
    publication: PublicationOracle,
    frames: &'static [FrameOracle],
}

struct CatalogOracle {
    name: &'static str,
    ticks: &'static [TickOracle],
}

const ARP_REPLY_FRAME: FrameOracle = FrameOracle {
    sequence: 0,
    ingress: LAN,
    egress: LAN,
    origin: FrameOrigin::Received { ingress: LAN },
    marker: FrameMarker::ArpReply,
};
const UDP_NAT_FRAME: FrameOracle = FrameOracle {
    sequence: 0,
    ingress: LAN,
    egress: IfId(2),
    origin: FrameOrigin::Received { ingress: LAN },
    marker: FrameMarker::UdpNat,
};
const UDP_RESOLVED_FRAME: FrameOracle = FrameOracle {
    sequence: 3,
    ingress: LAN,
    egress: IfId(2),
    origin: FrameOrigin::Received { ingress: LAN },
    marker: FrameMarker::UdpResolved,
};
const TCP_NAT_FRAME: FrameOracle = FrameOracle {
    sequence: 0,
    ingress: LAN,
    egress: IfId(2),
    origin: FrameOrigin::Received { ingress: LAN },
    marker: FrameMarker::TcpNat,
};
const ARP_REQUEST_FRAME: FrameOracle = FrameOracle {
    sequence: 1,
    ingress: IfId(2),
    egress: IfId(2),
    origin: FrameOrigin::Generated,
    marker: FrameMarker::ArpRequest {
        target: RESOLVABLE_HOST_IP,
    },
};
const HOST_ARP_REQUEST_FRAME: FrameOracle = FrameOracle {
    sequence: 1,
    ingress: IfId(2),
    egress: IfId(2),
    origin: FrameOrigin::Generated,
    marker: FrameMarker::ArpRequest {
        target: UNREACHABLE_HOST_IP,
    },
};
const TTL_FRAME: FrameOracle = FrameOracle {
    sequence: 1,
    ingress: LAN,
    egress: LAN,
    origin: FrameOrigin::Generated,
    marker: FrameMarker::IcmpTimeExceeded,
};
const HOST_UNREACHABLE_FRAME: FrameOracle = FrameOracle {
    sequence: 4,
    ingress: LAN,
    egress: LAN,
    origin: FrameOrigin::Generated,
    marker: FrameMarker::IcmpHostUnreachable,
};

const ONE_ARP_REPLY: [FrameOracle; 1] = [ARP_REPLY_FRAME];
const ONE_UDP_NAT: [FrameOracle; 1] = [UDP_NAT_FRAME];
const ONE_UDP_RESOLVED: [FrameOracle; 1] = [UDP_RESOLVED_FRAME];
const ONE_TCP_NAT: [FrameOracle; 1] = [TCP_NAT_FRAME];
const ONE_ARP_REQUEST: [FrameOracle; 1] = [ARP_REQUEST_FRAME];
const ONE_HOST_ARP_REQUEST_SEQUENCE_2: [FrameOracle; 1] = [FrameOracle {
    sequence: 2,
    ..HOST_ARP_REQUEST_FRAME
}];
const ONE_HOST_ARP_REQUEST_SEQUENCE_3: [FrameOracle; 1] = [FrameOracle {
    sequence: 3,
    ..HOST_ARP_REQUEST_FRAME
}];
const ONE_HOST_ARP_REQUEST: [FrameOracle; 1] = [HOST_ARP_REQUEST_FRAME];
const ONE_TTL: [FrameOracle; 1] = [TTL_FRAME];
const ONE_HOST_UNREACHABLE: [FrameOracle; 1] = [HOST_UNREACHABLE_FRAME];
const ONE_UDP_NAT_SEQUENCE_2: [FrameOracle; 1] = [FrameOracle {
    sequence: 2,
    ..UDP_NAT_FRAME
}];
const NO_FRAMES: [FrameOracle; 0] = [];

const LAN_LOCAL_TICKS: [TickOracle; 1] = [TickOracle {
    now: 0,
    generation: 7,
    publication: PublicationOracle::Unchanged,
    frames: &ONE_ARP_REPLY,
}];
const UDP_NAT_TICKS: [TickOracle; 1] = [TickOracle {
    now: 0,
    generation: 7,
    publication: PublicationOracle::Unchanged,
    frames: &ONE_UDP_NAT,
}];
const TCP_NAT_TICKS: [TickOracle; 1] = [TickOracle {
    now: 0,
    generation: 7,
    publication: PublicationOracle::Unchanged,
    frames: &ONE_TCP_NAT,
}];
const UDP_DENY_TICKS: [TickOracle; 1] = [TickOracle {
    now: 0,
    generation: 7,
    publication: PublicationOracle::Unchanged,
    frames: &NO_FRAMES,
}];
const DYNAMIC_ARP_TICKS: [TickOracle; 3] = [
    TickOracle {
        now: 0,
        generation: 7,
        publication: PublicationOracle::Unchanged,
        frames: &ONE_ARP_REQUEST,
    },
    TickOracle {
        now: 500,
        generation: 7,
        publication: PublicationOracle::Unchanged,
        frames: &NO_FRAMES,
    },
    TickOracle {
        now: 600,
        generation: 7,
        publication: PublicationOracle::Unchanged,
        frames: &ONE_UDP_RESOLVED,
    },
];
const TTL_TICKS: [TickOracle; 1] = [TickOracle {
    now: 0,
    generation: 7,
    publication: PublicationOracle::Unchanged,
    frames: &ONE_TTL,
}];
const HOST_UNREACHABLE_TICKS: [TickOracle; 4] = [
    TickOracle {
        now: 0,
        generation: 7,
        publication: PublicationOracle::Unchanged,
        frames: &ONE_HOST_ARP_REQUEST,
    },
    TickOracle {
        now: 1_000,
        generation: 7,
        publication: PublicationOracle::Unchanged,
        frames: &ONE_HOST_ARP_REQUEST_SEQUENCE_2,
    },
    TickOracle {
        now: 2_000,
        generation: 7,
        publication: PublicationOracle::Unchanged,
        frames: &ONE_HOST_ARP_REQUEST_SEQUENCE_3,
    },
    TickOracle {
        now: 3_000,
        generation: 7,
        publication: PublicationOracle::Unchanged,
        frames: &ONE_HOST_UNREACHABLE,
    },
];
const RELOAD_ROLLBACK_TICKS: [TickOracle; 3] = [
    TickOracle {
        now: 0,
        generation: 7,
        publication: PublicationOracle::Unchanged,
        frames: &ONE_UDP_NAT,
    },
    TickOracle {
        now: 1_000,
        generation: 8,
        publication: PublicationOracle::Applied {
            previous_generation: 7,
            generation: 8,
        },
        frames: &NO_FRAMES,
    },
    TickOracle {
        now: 2_000,
        generation: 9,
        publication: PublicationOracle::Applied {
            previous_generation: 8,
            generation: 9,
        },
        frames: &ONE_UDP_NAT_SEQUENCE_2,
    },
];

const CATALOG_ORACLE: [CatalogOracle; 8] = [
    CatalogOracle {
        name: "lan_local_arp",
        ticks: &LAN_LOCAL_TICKS,
    },
    CatalogOracle {
        name: "wan_udp_nat",
        ticks: &UDP_NAT_TICKS,
    },
    CatalogOracle {
        name: "wan_tcp_allow",
        ticks: &TCP_NAT_TICKS,
    },
    CatalogOracle {
        name: "wan_udp_deny",
        ticks: &UDP_DENY_TICKS,
    },
    CatalogOracle {
        name: "dynamic_arp_then_forward",
        ticks: &DYNAMIC_ARP_TICKS,
    },
    CatalogOracle {
        name: "ttl_exceeded",
        ticks: &TTL_TICKS,
    },
    CatalogOracle {
        name: "host_unreachable_after_max_arp_attempts",
        ticks: &HOST_UNREACHABLE_TICKS,
    },
    CatalogOracle {
        name: "reload_rollback",
        ticks: &RELOAD_ROLLBACK_TICKS,
    },
];

fn assert_publication(actual: PublicationSummary, expected: PublicationOracle) {
    match (actual, expected) {
        (PublicationSummary::Unchanged, PublicationOracle::Unchanged) => {}
        (
            PublicationSummary::Applied {
                previous_generation,
                generation,
            },
            PublicationOracle::Applied {
                previous_generation: expected_previous,
                generation: expected_generation,
            },
        ) => {
            assert_eq!(previous_generation.get(), expected_previous);
            assert_eq!(generation.get(), expected_generation);
        }
        _ => panic!("publication outcome differs from independent catalog oracle"),
    }
}

fn expected_frame(marker: FrameMarker) -> Vec<u8> {
    match marker {
        FrameMarker::ArpReply => arp_reply(LAN_MAC, LAN_IP, HOST_MAC, HOST_IP),
        FrameMarker::ArpRequest { target } => arp_request(WAN_MAC, WAN_IP, target),
        FrameMarker::UdpNat => udp_frame(
            EthernetHop {
                dest_mac: WAN_NEXT_HOP_MAC,
                src_mac: WAN_MAC,
            },
            WAN_IP,
            REMOTE_IP,
            40_005,
            53,
            63,
            b"query",
        ),
        FrameMarker::UdpResolved => udp_frame(
            EthernetHop {
                dest_mac: RESOLVABLE_HOST_MAC,
                src_mac: WAN_MAC,
            },
            WAN_IP,
            RESOLVABLE_HOST_IP,
            40_007,
            53,
            63,
            b"hello",
        ),
        FrameMarker::TcpNat => tcp_syn_frame(
            EthernetHop {
                dest_mac: WAN_NEXT_HOP_MAC,
                src_mac: WAN_MAC,
            },
            WAN_IP,
            REMOTE_IP,
            40_011,
            443,
            63,
            1_000,
        ),
        FrameMarker::IcmpTimeExceeded => {
            let quote = ipv4_udp_packet(HOST_IP, REMOTE_IP, 51_000, 53, 1, b"query");
            icmp_error_frame(HOST_MAC, LAN_MAC, LAN_IP, HOST_IP, 0xc0, 64, 11, 0, &quote)
        }
        FrameMarker::IcmpHostUnreachable => {
            let quote = ipv4_udp_packet(HOST_IP, UNREACHABLE_HOST_IP, 51_000, 9_999, 64, b"probe");
            icmp_error_frame(HOST_MAC, LAN_MAC, LAN_IP, HOST_IP, 0xc0, 64, 3, 1, &quote)
        }
    }
}

fn assert_frame(frame: &ruster_sim_scenario::TxFrame, expected: FrameOracle, case_name: &str) {
    assert_eq!(frame.sequence, expected.sequence, "case {case_name}");
    assert_eq!(frame.ingress, expected.ingress, "case {case_name}");
    assert_eq!(frame.egress, expected.egress, "case {case_name}");
    assert_eq!(frame.origin, expected.origin, "case {case_name}");
    assert_eq!(
        frame.bytes,
        expected_frame(expected.marker),
        "case {case_name}"
    );
}

#[test]
fn r11sim_023_independent_catalog_oracle_covers_all_names_order_and_semantics() {
    assert_eq!(CATALOG_ORACLE.len(), 8);
    let oracle_names = CATALOG_ORACLE.map(|case| case.name);
    assert_eq!(oracle_names, EXPECTED_CATALOG_NAMES);
    assert_eq!(NAMED_SCENARIO_NAMES, EXPECTED_CATALOG_NAMES);
    assert_eq!(
        named_scenarios()
            .iter()
            .map(NamedScenario::name)
            .collect::<Vec<_>>(),
        EXPECTED_CATALOG_NAMES
    );
    for case in CATALOG_ORACLE {
        let outcomes = run_named_scenario(case.name).expect("compiled scenario must run");
        assert_eq!(outcomes.len(), case.ticks.len(), "case {}", case.name);
        for (outcome, expected) in outcomes.iter().zip(case.ticks) {
            assert_eq!(outcome.now.0, expected.now, "case {}", case.name);
            assert_eq!(
                outcome.generation.get(),
                expected.generation,
                "case {}",
                case.name
            );
            assert!(outcome.active, "case {}", case.name);
            assert_publication(outcome.publication, expected.publication);
            assert_eq!(
                outcome.tx.len(),
                expected.frames.len(),
                "case {}",
                case.name
            );
            for (frame, expected_frame) in outcome.tx.iter().zip(expected.frames) {
                assert_frame(frame, *expected_frame, case.name);
            }
        }
    }
}
