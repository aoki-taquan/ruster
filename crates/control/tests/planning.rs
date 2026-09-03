mod common;

use std::num::NonZeroU64;

use common::{inputs, validated, Services};
use ruster_config::{
    parse, validate, RouteV1, ValidatedConfig, ValidatedConfigV1, ValidationLimits, VersionedConfig,
};
use ruster_control::{
    plan_full_service_v1, plan_successor, FullServiceCandidateError, FullServicePlanInputs,
    FullServicePlanV1, FullServicePlanningError, FullServiceStorageShape, Icmpv4ErrorStorageShape,
    Nat44TcpStoragePlan, Nat44UdpStoragePlan, PlanOutcome, ResolutionStorageShape, RuntimeService,
};
use ruster_core::{FirewallHashKey, Nat44Icmpv4ErrorPolicy, Nat44TcpHashKey, Nat44UdpHashKey};

fn planned(config: ValidatedConfigV1, inputs: FullServicePlanInputs) -> FullServicePlanV1 {
    match plan_full_service_v1(config, inputs) {
        Ok(plan) => plan,
        Err(failure) => panic!("full-service config must plan: {:?}", failure.error()),
    }
}

fn validated_source(source: VersionedConfig) -> ValidatedConfigV1 {
    match validate(
        source,
        ValidationLimits {
            max_slots_per_table: 1_048_576,
            max_runtime_bytes: 1 << 30,
        },
    )
    .expect("full-service config must validate")
    {
        ValidatedConfig::V1(config) => config,
        _ => unreachable!("fixture selects schema V1"),
    }
}

#[test]
fn consumed_validated_config_moves_full_service_plan_with_caller_supplied_keys() {
    let first_config = validated(Services::ALL);
    let first_interfaces = first_config.interfaces().as_ptr();
    let first_routes = first_config.routes().as_ptr();
    let first_neighbors = first_config.neighbors().as_ptr();
    let first_local_ipv4 = first_config.local_ipv4().as_ptr();
    let first_firewall_rules = first_config
        .firewall()
        .expect("fixture enables firewall")
        .rules()
        .as_ptr();
    let first_required_bytes = first_config.storage_shape().required_bytes;
    let first_plan = planned(first_config, inputs(1, 10));
    let second_config = validated(Services::ALL);
    let second_interfaces = second_config.interfaces().as_ptr();
    let second_required_bytes = second_config.storage_shape().required_bytes;
    let second_plan = planned(second_config, inputs(2, 100));

    assert_eq!(first_plan.generation(), NonZeroU64::new(1).unwrap());
    assert_eq!(second_plan.generation(), NonZeroU64::new(2).unwrap());
    assert_eq!(first_plan.required_runtime_bytes(), first_required_bytes);
    assert_eq!(second_plan.required_runtime_bytes(), second_required_bytes);
    assert_eq!(first_plan.interfaces().as_ptr(), first_interfaces);
    assert_eq!(second_plan.interfaces().as_ptr(), second_interfaces);
    for interfaces in [first_plan.interfaces(), second_plan.interfaces()] {
        assert_eq!(
            interfaces
                .iter()
                .map(|interface| (interface.id().0, interface.name(), interface.device()))
                .collect::<Vec<_>>(),
            vec![(1, "lan", "eth0"), (2, "wan", "eth1")]
        );
    }
    for tick in [first_plan.tick(), second_plan.tick()] {
        assert_eq!(tick.rx, 64);
        assert_eq!(tick.resolution_timer_scans, 16);
        assert_eq!(tick.failure_dispatch_scans, 8);
        assert_eq!(tick.generated_arp, 4);
        assert_eq!(tick.generated_icmpv4, 2);
    }

    let first: Result<_, FullServiceCandidateError> = first_plan.into_candidate();
    let second: Result<_, FullServiceCandidateError> = second_plan.into_candidate();
    let first = first.expect("first publication must validate");
    let second = second.expect("second publication must validate");
    assert_eq!(first.generation(), NonZeroU64::new(1).unwrap());
    assert_eq!(second.generation(), NonZeroU64::new(2).unwrap());
    assert_eq!(first.interfaces().as_ptr(), first_interfaces);
    assert_eq!(second.interfaces().as_ptr(), second_interfaces);
    assert_eq!(first.required_runtime_bytes(), first_required_bytes);
    assert_eq!(second.required_runtime_bytes(), second_required_bytes);
    assert_eq!(first.tick().rx, 64);
    assert_eq!(second.tick().rx, 64);
    assert_eq!(
        first.storage_shape(),
        FullServiceStorageShape::new(
            ResolutionStorageShape::new(2, 3, 4, 5),
            Icmpv4ErrorStorageShape::new(6, 7),
            Nat44UdpStoragePlan::new(3, 9, 4, 3, 16, 9, 13),
            Nat44TcpStoragePlan::new(5, 17, 8, 5, 32, 17, 13),
            11,
        )
    );
    let first_authority = first.authority();
    assert_eq!(first_authority.generation(), first.generation());
    assert_eq!(first_authority.snapshot().routes().as_ptr(), first_routes);
    assert_eq!(
        first_authority.snapshot().neighbors().as_ptr(),
        first_neighbors
    );
    assert_eq!(
        first_authority.snapshot().local_ipv4().as_ptr(),
        first_local_ipv4
    );
    assert_eq!(
        first_authority.nat44_udp_hash_key(),
        Nat44UdpHashKey::new(10, 11).unwrap()
    );
    assert_eq!(
        first_authority.nat44_tcp_hash_key(),
        Nat44TcpHashKey::new(12, 13).unwrap()
    );
    assert_eq!(
        first_authority.firewall_config().hash_key(),
        FirewallHashKey::new(14, 15).unwrap()
    );
    let firewall_rules = first_authority.firewall_config().rules();
    assert_eq!(firewall_rules.as_ptr(), first_firewall_rules);
    assert_eq!(firewall_rules.len(), 2);
    assert_eq!([firewall_rules[0].id().0, firewall_rules[1].id().0], [2, 1]);
    assert_eq!(first.validate_successor(&second), Ok(()));

    for (error, debug) in [
        (
            FullServiceCandidateError::ForwardingPublicationNonceExhausted,
            "ForwardingPublicationNonceExhausted",
        ),
        (
            FullServiceCandidateError::FirewallPublicationNonceExhausted,
            "FirewallPublicationNonceExhausted",
        ),
        (
            FullServiceCandidateError::InternalInvariantViolation,
            "InternalInvariantViolation",
        ),
    ] {
        assert_eq!(format!("{error:?}"), debug);
    }

    assert_missing_services_reject_in_stable_order();
}

#[test]
fn full_service_planning_forwards_every_nested_policy_realm_and_storage_value() {
    let config = validated(Services::ALL);
    let interface_pointer = config.interfaces().as_ptr();
    let required_bytes = config.storage_shape().required_bytes;
    let plan = planned(config, inputs(7, 700));
    assert_eq!(plan.interfaces().as_ptr(), interface_pointer);
    assert_eq!(plan.required_runtime_bytes(), required_bytes);
    assert_eq!(
        plan.tick(),
        ruster_config::TickBudgetsV1 {
            rx: 64,
            resolution_timer_scans: 16,
            failure_dispatch_scans: 8,
            generated_arp: 4,
            generated_icmpv4: 2,
        }
    );

    let candidate = plan
        .into_candidate()
        .expect("full-service plan must validate");
    let authority = candidate.authority();
    assert_eq!(authority.snapshot().ipv4_origin_policy().default_ttl(), 64);

    let resolution_policy = authority.resolution_policy();
    for (field, actual, expected) in [
        ("interval-ms", resolution_policy.interval_ms(), 1_000),
        ("state-ttl-ms", resolution_policy.failed_hold_ms(), 3_000),
        (
            "max-attempts",
            u64::from(resolution_policy.max_attempts()),
            3,
        ),
        (
            "dynamic-neighbor-ttl-ms",
            resolution_policy.dynamic_neighbor_ttl_ms(),
            60_000,
        ),
    ] {
        assert_eq!(actual, expected, "resolution {field}");
    }

    let icmpv4_error_policy = authority.icmpv4_error_policy();
    for (field, actual, expected) in [
        ("interval-ms", icmpv4_error_policy.interval_ms(), 100),
        ("state-ttl-ms", icmpv4_error_policy.state_ttl_ms(), 60_000),
    ] {
        assert_eq!(actual, expected, "ICMPv4 error {field}");
    }

    let udp_config = authority.nat44_udp_config();
    assert_eq!(udp_config.inside().0, 1);
    assert_eq!(udp_config.outside().0, 2);
    assert_eq!(udp_config.public_address().octets(), [198, 51, 100, 10]);
    assert_eq!(udp_config.first_port(), 40_000);
    assert_eq!(udp_config.last_port(), 40_012);
    let udp_policy = udp_config.policy();
    assert_eq!(udp_policy.idle_ttl_ms(), 300_000);
    assert_eq!(udp_policy.allocator_seed(), 7);
    assert_eq!(
        udp_policy.icmpv4_errors(),
        Nat44Icmpv4ErrorPolicy::ExternalOnly
    );

    let tcp_config = authority.nat44_tcp_config();
    assert_eq!(tcp_config.inside().0, 1);
    assert_eq!(tcp_config.outside().0, 2);
    assert_eq!(tcp_config.public_address().octets(), [198, 51, 100, 10]);
    assert_eq!(tcp_config.first_port(), 40_000);
    assert_eq!(tcp_config.last_port(), 40_012);
    let tcp_policy = tcp_config.policy();
    assert_eq!(tcp_policy.idle_ttl_ms(), 7_440_000);
    assert_eq!(tcp_policy.allocator_seed(), 11);
    assert_eq!(tcp_policy.icmpv4_errors(), Nat44Icmpv4ErrorPolicy::Disabled);

    let firewall = authority.firewall_config();
    let firewall_policy = firewall.policy();
    for (field, actual, expected) in [
        (
            "udp-idle-ttl-ms",
            firewall_policy.udp_idle_ttl_ms(),
            300_000,
        ),
        (
            "tcp-opening-idle-ttl-ms",
            firewall_policy.tcp_opening_idle_ttl_ms(),
            240_000,
        ),
        (
            "tcp-active-idle-ttl-ms",
            firewall_policy.tcp_active_idle_ttl_ms(),
            7_440_000,
        ),
    ] {
        assert_eq!(actual, expected, "firewall {field}");
    }
    assert_eq!(firewall.rules().len(), 2);
    assert_eq!(firewall.rules()[0].id().0, 2);
    assert_eq!(firewall.rules()[1].id().0, 1);

    let storage = candidate.storage_shape();
    let resolution_storage = storage.resolution();
    for (field, actual, expected) in [
        ("states", resolution_storage.state_slots(), 2),
        ("actions", resolution_storage.action_slots(), 3),
        (
            "dynamic-neighbors",
            resolution_storage.dynamic_neighbor_slots(),
            4,
        ),
        ("failure-holds", resolution_storage.failure_hold_slots(), 5),
    ] {
        assert_eq!(actual, expected, "resolution storage {field}");
    }
    let icmpv4_error_storage = storage.icmpv4_errors();
    for (field, actual, expected) in [
        ("states", icmpv4_error_storage.state_slots(), 6),
        ("actions", icmpv4_error_storage.action_slots(), 7),
    ] {
        assert_eq!(actual, expected, "ICMPv4 error storage {field}");
    }
    let udp_storage = storage.nat44_udp();
    for (field, actual, expected) in [
        ("mappings", udp_storage.mapping_slots(), 3),
        ("peers", udp_storage.peer_slots(), 9),
        ("mapping-buckets", udp_storage.mapping_buckets(), 4),
        ("mapping-nodes", udp_storage.mapping_nodes(), 3),
        ("peer-buckets", udp_storage.peer_buckets(), 16),
        ("peer-nodes", udp_storage.peer_nodes(), 9),
        ("port-owners", udp_storage.port_owner_slots(), 13),
    ] {
        assert_eq!(actual, expected, "UDP storage {field}");
    }
    let tcp_storage = storage.nat44_tcp();
    for (field, actual, expected) in [
        ("mappings", tcp_storage.mapping_slots(), 5),
        ("sessions", tcp_storage.session_slots(), 17),
        ("mapping-buckets", tcp_storage.mapping_buckets(), 8),
        ("mapping-nodes", tcp_storage.mapping_nodes(), 5),
        ("session-buckets", tcp_storage.session_buckets(), 32),
        ("session-nodes", tcp_storage.session_nodes(), 17),
        ("port-owners", tcp_storage.port_owner_slots(), 13),
    ] {
        assert_eq!(actual, expected, "TCP storage {field}");
    }
    assert_eq!(storage.firewall_state_slots(), 11);
}

fn assert_missing_services_reject_in_stable_order() {
    let cases = [
        (
            Services {
                resolution: false,
                icmpv4_errors: false,
                nat44_udp: false,
                nat44_tcp: false,
                firewall: false,
            },
            RuntimeService::Resolution,
        ),
        (
            Services {
                resolution: true,
                icmpv4_errors: false,
                nat44_udp: false,
                nat44_tcp: false,
                firewall: false,
            },
            RuntimeService::Icmpv4Errors,
        ),
        (
            Services {
                resolution: true,
                icmpv4_errors: true,
                nat44_udp: false,
                nat44_tcp: false,
                firewall: false,
            },
            RuntimeService::Nat44Udp,
        ),
        (
            Services {
                resolution: true,
                icmpv4_errors: true,
                nat44_udp: true,
                nat44_tcp: false,
                firewall: false,
            },
            RuntimeService::Nat44Tcp,
        ),
        (
            Services {
                firewall: false,
                ..Services::ALL
            },
            RuntimeService::Firewall,
        ),
    ];

    for (index, (services, service)) in cases.into_iter().enumerate() {
        let config = validated(services);
        let interface_pointer = config.interfaces().as_ptr();
        let failure = match plan_full_service_v1(config, inputs(1, 1_000 + index as u64 * 10)) {
            Ok(_) => panic!("missing service must reject planning"),
            Err(failure) => failure,
        };
        assert_eq!(
            failure.error(),
            FullServicePlanningError::MissingService(service)
        );
        let (error, config, _inputs) = failure.into_parts();
        assert_eq!(error, FullServicePlanningError::MissingService(service));
        assert_eq!(config.interfaces().as_ptr(), interface_pointer);
        let tick = config.tick();
        assert_eq!(tick.rx, 64);
        assert_eq!(tick.resolution_timer_scans, 16);
        assert_eq!(tick.failure_dispatch_scans, 8);
        assert_eq!(tick.generated_arp, 4);
        assert_eq!(tick.generated_icmpv4, 2);
    }
}

#[test]
fn full_service_planning_rejects_missing_services_in_stable_order() {
    assert_missing_services_reject_in_stable_order();
}

#[test]
fn full_service_planning_error_debug_and_dependency_direction_are_value_free() {
    let failure = match plan_full_service_v1(
        validated(Services {
            firewall: false,
            ..Services::ALL
        }),
        inputs(1, u64::MAX - 20),
    ) {
        Ok(_) => panic!("missing firewall must reject planning"),
        Err(failure) => failure,
    };
    assert_eq!(format!("{:?}", failure.error()), "MissingService(Firewall)");

    let control_manifest = include_str!("../Cargo.toml");
    let config_manifest = include_str!("../../config/Cargo.toml");
    let planning_source = include_str!("../src/planning.rs");
    assert!(control_manifest.contains("ruster-config"));
    assert!(!config_manifest.contains("ruster-control"));
    assert!(planning_source.contains("#[non_exhaustive]\npub enum FullServiceCandidateError"));
}

#[test]
fn config_input_order_is_canonicalized_before_candidate_forwarding_diff() {
    let parsed = parse(include_bytes!("full-service.toml")).expect("fixture must parse");
    let mut ordered = parsed.clone();
    let VersionedConfig::V1(config) = &mut ordered else {
        unreachable!("fixture selects schema V1")
    };
    config.routes.push(RouteV1 {
        prefix: "203.0.113.0/24".to_owned(),
        egress: "wan".to_owned(),
        via: None,
    });

    let mut reordered = ordered.clone();
    let VersionedConfig::V1(config) = &mut reordered else {
        unreachable!("fixture selects schema V1")
    };
    config.interfaces.reverse();
    config.addresses.reverse();
    config.routes.reverse();
    config.neighbors.reverse();

    let current = planned(validated_source(ordered), inputs(1, 10))
        .into_candidate()
        .expect("ordered candidate must validate");
    let next = planned(validated_source(reordered), inputs(2, 100))
        .into_candidate()
        .expect("reordered candidate must validate");
    let outcome = plan_successor(Some(&current), &next);
    assert!(matches!(outcome, PlanOutcome::InPlaceEligible { .. }));
    let diff = outcome.section_diff().expect("successor has a diff");
    assert!(!diff.interfaces_changed());
    assert!(!diff.routes_changed());
    assert!(!diff.neighbors_changed());
    assert!(!diff.local_ipv4_bindings_changed());
}

#[test]
fn nested_planning_source_contract_has_exact_seams_and_inventory() {
    let config_source = include_str!("../../config/src/validate.rs");
    for exact_destructure in [
        "let Self { policy, storage } = self;",
        "let Self { udp, tcp } = self;",
        "let Self {\n            inside,\n            outside,\n            public_address,\n            first_port,\n            last_port,\n            policy,\n            storage,\n        } = self;",
        "let Self {\n            rules,\n            policy,\n            state_slots,\n        } = self;",
        "let Self {\n            resolution,\n            icmpv4_errors,\n            nat44_udp,\n            nat44_tcp,\n            firewall_states,\n            required_bytes,\n        } = self;",
        "let Self {\n            rx,\n            resolution_timer_scans,\n            failure_dispatch_scans,\n            generated_arp,\n            generated_icmpv4,\n        } = self;",
        "let Self {\n            states,\n            actions,\n            dynamic_neighbors,\n            failure_holds,\n        } = self;",
        "let Self {\n            mappings,\n            peers,\n            mapping_buckets,\n            mapping_nodes,\n            peer_buckets,\n            peer_nodes,\n            port_owners,\n        } = self;",
        "let Self {\n            mappings,\n            sessions,\n            mapping_buckets,\n            mapping_nodes,\n            session_buckets,\n            session_nodes,\n            port_owners,\n        } = self;",
        "let Self {\n            interfaces,\n            core_interfaces,\n            routes,\n            neighbors,\n            local_ipv4,\n            ipv4_origin,\n            resolution,\n            icmpv4_errors,\n            nat44,\n            firewall,\n            tick,\n            storage,\n            backend,\n            required_runtime_bytes,\n        } = self;",
        "let Self {\n            interfaces,\n            core_interfaces,\n            routes,\n            neighbors,\n            local_ipv4,\n            ipv4_origin,\n            resolution,\n            icmpv4_errors,\n            nat44,\n            firewall,\n            tick,\n            storage,\n            backend,\n        } = self;",
    ] {
        assert!(
            config_source.contains(exact_destructure),
            "missing exact config seam: {exact_destructure}"
        );
    }
    assert_eq!(
        config_source
            .match_indices("let Self { policy, storage } = self;")
            .count(),
        2
    );
    assert_eq!(
        config_source
            .match_indices(
                "let Self {\n            inside,\n            outside,\n            public_address,\n            first_port,\n            last_port,\n            policy,\n            storage,\n        } = self;"
            )
            .count(),
        2
    );
    assert!(config_source.contains("pub fn into_rules(self) -> Box<[FirewallRule]>"));
    assert!(config_source.contains(
        "let Self {\n            rules,\n            policy: _policy,\n            state_slots: _state_slots,\n        } = self;"
    ));

    let planning_source = include_str!("../src/planning.rs");
    assert!(!planning_source.contains("into_rules"));
    let transfer_start = planning_source
        .find("    let (\n        interfaces,")
        .expect("planner transfer destructure exists");
    let transfer_tail = &planning_source[transfer_start..];
    let transfer_end = transfer_tail
        .find(" = config.into_parts().into_planning_parts();")
        .expect("planner transfer call exists");
    let transfer = &transfer_tail[..transfer_end];
    for bound in [
        "interfaces",
        "core_interfaces",
        "routes",
        "neighbors",
        "local_ipv4",
        "ipv4_origin",
        "resolution",
        "icmpv4_errors",
        "nat44",
        "firewall",
        "tick",
        "runtime_storage",
        "backend",
        "required_runtime_bytes",
    ] {
        assert!(transfer.contains(bound), "planner does not bind {bound}");
    }
    assert!(!transfer.contains("\n        _,"));
    assert!(!transfer.contains(".."));
    assert!(planning_source.contains(
        "let Self {\n            error,\n            config,\n            inputs,\n        } = self;"
    ));
    for exact_planner_destructure in [
        "let (resolution_policy, resolution_storage) = resolution.into_planning_parts();",
        "let (icmpv4_error_policy, icmpv4_error_storage) = icmpv4_errors.into_planning_parts();",
        "let (nat44_udp, nat44_tcp) = nat44.into_planning_parts();",
        "let (\n        nat44_udp_inside,\n        nat44_udp_outside,\n        nat44_udp_public_address,\n        nat44_udp_first_port,\n        nat44_udp_last_port,\n        nat44_udp_policy,\n        nat44_udp_storage,\n    ) = nat44_udp.into_planning_parts();",
        "let (\n        nat44_tcp_inside,\n        nat44_tcp_outside,\n        nat44_tcp_public_address,\n        nat44_tcp_first_port,\n        nat44_tcp_last_port,\n        nat44_tcp_policy,\n        nat44_tcp_storage,\n    ) = nat44_tcp.into_planning_parts();",
        "let (firewall_rules, firewall_policy, firewall_state_slots) = firewall.into_planning_parts();",
        "let (\n        tick_rx,\n        tick_resolution_timer_scans,\n        tick_failure_dispatch_scans,\n        tick_generated_arp,\n        tick_generated_icmpv4,\n    ) = tick.into_planning_parts();",
        "let (\n        runtime_resolution_storage,\n        runtime_icmpv4_error_storage,\n        runtime_nat44_udp_storage,\n        runtime_nat44_tcp_storage,\n        runtime_firewall_state_slots,\n        runtime_required_bytes,\n    ) = runtime_storage.into_planning_parts();",
    ] {
        assert!(
            planning_source.contains(exact_planner_destructure),
            "missing exact planner inventory: {exact_planner_destructure}"
        );
    }
    for call in [
        "resolution.into_planning_parts()",
        "icmpv4_errors.into_planning_parts()",
        "nat44.into_planning_parts()",
        "nat44_udp.into_planning_parts()",
        "nat44_tcp.into_planning_parts()",
        "firewall.into_planning_parts()",
        "tick.into_planning_parts()",
        "runtime_storage.into_planning_parts()",
    ] {
        assert!(
            planning_source.contains(call),
            "planner seam call missing: {call}"
        );
    }
}
