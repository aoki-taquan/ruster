//! RELOAD-CARRY for the stateful firewall: a successor with the same rules
//! keeps every flow and the table key without evaluating anything; changed
//! rules re-evaluate every carried flow's initiating packet and revoke the
//! flows they no longer admit (fail closed, before any further packet);
//! the re-evaluation is bounded by `FIREWALL_CARRY_REEVALUATION_BUDGET` and
//! flushes above it; a refused preflight changes nothing.

use super::*;
use crate::{StateCarryConflict, StateCarryOutcome};

fn udp_flow(port: u16) -> FirewallPacket {
    FirewallPacket {
        source_port: port,
        ..packet(FirewallProtocol::Udp, 0)
    }
}

fn reply(flow: FirewallPacket) -> FirewallPacket {
    FirewallPacket {
        ingress: flow.egress,
        egress: flow.ingress,
        source: flow.destination,
        destination: flow.source,
        source_port: flow.destination_port,
        destination_port: flow.source_port,
        ..flow
    }
}

/// Plans and commits `packet`; returns its disposition class, or the error.
fn pass(
    runtime: &mut FirewallRuntime<'_>,
    config: &FirewallConfig<'_>,
    packet: FirewallPacket,
    now: u64,
) -> Result<FirewallConnectionClass, FirewallPlanError> {
    let plan = runtime.plan_packet(config, packet, now)?;
    runtime.commit(plan).unwrap();
    Ok(plan.disposition().class)
}

fn udp_rule(id: u32, action: FirewallAction, destination_ports: (u16, u16)) -> FirewallRule {
    FirewallRule::new(
        FirewallRuleId(id),
        FirewallInterface::Interface(LAN),
        FirewallInterface::Interface(WAN),
        any().into(),
        any().into(),
        FirewallProtocol::Udp,
        FirewallPortRange::new(0, u16::MAX).unwrap(),
        FirewallPortRange::new(destination_ports.0, destination_ports.1).unwrap(),
        action,
    )
}

fn config<'a>(
    snapshot: &ForwardingSnapshot<'_>,
    rules: &'a [FirewallRule],
    generation: u64,
    key: FirewallHashKey,
) -> FirewallConfig<'a> {
    FirewallConfig::new(snapshot, rules, FirewallPolicy::default(), generation, key).unwrap()
}

#[test]
fn unchanged_rules_carry_every_flow_and_the_key_without_evaluating() {
    with_snapshot(|snapshot| {
        let rules = [udp_rule(1, FirewallAction::AllowStateful, (1, u16::MAX))];
        let current = config(snapshot, &rules, 1, hash_key());
        let same_rules = rules;
        let next = config(snapshot, &same_rules, 2, rotated_hash_key());
        let mut states = [FirewallStateSlot::default(); 8];
        let mut runtime = FirewallRuntime::new(current, &mut states);
        for port in [1_000, 1_001, 1_002] {
            assert_eq!(
                pass(&mut runtime, &current, udp_flow(port), 10),
                Ok(FirewallConnectionClass::New)
            );
        }
        let flows = runtime.states.to_vec();
        let evaluations = runtime.counters.rule_evaluations;

        let permit = runtime
            .preflight_reconcile_carrying(current, next, *snapshot, *snapshot)
            .unwrap();
        assert_eq!(permit.outcome(), StateCarryOutcome::Carried);
        assert!(!permit.reevaluates());
        let preview = permit.preview();
        let report = permit.commit();
        assert_eq!(report, preview);
        assert_eq!(
            report,
            FirewallReconcileReport {
                states_flushed: 0,
                states_carried: 3,
                states_revoked: 0,
                outcome: StateCarryOutcome::Carried,
            }
        );
        assert_eq!(runtime.states.to_vec(), flows, "slots untouched");
        assert_eq!(runtime.counters.rule_evaluations, evaluations);
        assert!(runtime.config_matches(&next));
        assert!(!runtime.config_matches(&current));
        assert_eq!(runtime.table_key, hash_key(), "the table keeps its key");
        assert_eq!(runtime.table_generation, 1);
        // Both directions of each carried flow are established hits.
        for port in [1_000, 1_001, 1_002] {
            assert_eq!(
                pass(&mut runtime, &next, reply(udp_flow(port)), 20),
                Ok(FirewallConnectionClass::Established)
            );
            assert_eq!(
                pass(&mut runtime, &next, udp_flow(port), 20),
                Ok(FirewallConnectionClass::Established)
            );
        }
        // A new flow after the carry is placed under the carried key too.
        assert_eq!(
            pass(&mut runtime, &next, udp_flow(2_000), 30),
            Ok(FirewallConnectionClass::New)
        );
        assert_eq!(
            pass(&mut runtime, &next, reply(udp_flow(2_000)), 30),
            Ok(FirewallConnectionClass::Established)
        );
    });
}

#[test]
fn changed_rules_revoke_exactly_the_flows_they_no_longer_admit() {
    with_snapshot(|snapshot| {
        let rules = [udp_rule(1, FirewallAction::AllowStateful, (1, u16::MAX))];
        let current = config(snapshot, &rules, 1, hash_key());
        // The successor denies destination port 53 first and allows the
        // rest under a new rule id.
        let next_rules = [
            udp_rule(5, FirewallAction::Deny, (53, 53)),
            udp_rule(7, FirewallAction::AllowStateful, (1, u16::MAX)),
        ];
        let next = config(snapshot, &next_rules, 2, rotated_hash_key());
        let mut states = [FirewallStateSlot::default(); 8];
        let mut runtime = FirewallRuntime::new(current, &mut states);
        let dns = FirewallPacket {
            destination_port: 53,
            ..udp_flow(1_000)
        };
        let https = udp_flow(1_001);
        pass(&mut runtime, &current, dns, 10).unwrap();
        pass(&mut runtime, &current, https, 10).unwrap();
        let evaluations = runtime.counters.rule_evaluations;

        let permit = runtime
            .preflight_reconcile_carrying(current, next, *snapshot, *snapshot)
            .unwrap();
        let preview = permit.preview();
        assert!(permit.reevaluates());
        // The dry run does not evaluate: both live flows are carried before
        // the commit's pass.
        assert_eq!((preview.states_carried, preview.states_revoked), (2, 0));
        let report = permit.commit();
        assert_eq!(
            report,
            FirewallReconcileReport {
                states_flushed: 0,
                states_carried: 1,
                states_revoked: 1,
                outcome: StateCarryOutcome::Carried,
            }
        );
        assert_eq!(runtime.counters.states_revoked, 1);
        let expired = runtime.counters.states_expired;
        // DNS: first match is the deny (1 test); HTTPS: deny, then allow.
        assert_eq!(runtime.counters.rule_evaluations, evaluations + 3);
        // The revoked flow passes nothing more, in either direction: its
        // reply is a new inbound attempt (default deny), and its next
        // outbound packet is decided as new by the deny rule.
        assert_eq!(
            pass(&mut runtime, &next, reply(dns), 20),
            Err(FirewallPlanError::DefaultDenied)
        );
        assert_eq!(
            pass(&mut runtime, &next, dns, 20),
            Err(FirewallPlanError::RuleDenied(FirewallRuleId(5)))
        );
        // The admitted flow continues and now reports the rule that admits
        // it under the successor.
        let plan = runtime.plan_packet(&next, reply(https), 20).unwrap();
        assert_eq!(
            plan.disposition().class,
            FirewallConnectionClass::Established
        );
        assert_eq!(
            plan.disposition().source,
            FirewallPolicySource::Rule(FirewallRuleId(7))
        );
        runtime.commit(plan).unwrap();
        // The probes reclaimed the revoked slot like an expired one, without
        // counting it as expired.
        assert_eq!(runtime.occupancy.occupied(), 1);
        assert_eq!(runtime.counters.states_expired, expired);
        assert!(!runtime.reclaim_one_expired(20));
    });
}

#[test]
fn reevaluation_is_bounded_by_the_budget_and_flushes_above_it() {
    with_snapshot(|snapshot| {
        let rules = [udp_rule(1, FirewallAction::AllowStateful, (1, u16::MAX))];
        let current = config(snapshot, &rules, 1, hash_key());
        // 4096 rules: 4095 that never match, then the allow.
        let mut next_rules: Vec<FirewallRule> = (0..4_095)
            .map(|id| udp_rule(10 + id, FirewallAction::Deny, (2, 2)))
            .collect();
        next_rules.push(udp_rule(
            9_999,
            FirewallAction::AllowStateful,
            (1, u16::MAX),
        ));
        let budget_flows =
            usize::try_from(FIREWALL_CARRY_REEVALUATION_BUDGET).unwrap() / next_rules.len();
        assert_eq!(budget_flows, 1_024);
        let next = config(snapshot, &next_rules, 2, rotated_hash_key());

        // Exactly at the budget: re-evaluated and carried.
        let mut states = vec![FirewallStateSlot::default(); 2_048];
        let mut runtime = FirewallRuntime::new(current, &mut states);
        for port in 0..budget_flows {
            pass(&mut runtime, &current, udp_flow(1_000 + port as u16), 10).unwrap();
        }
        let evaluations = runtime.counters.rule_evaluations;
        let report = runtime
            .preflight_reconcile_carrying(current, next, *snapshot, *snapshot)
            .unwrap()
            .commit();
        assert_eq!(report.outcome, StateCarryOutcome::Carried);
        assert_eq!(report.states_carried, budget_flows);
        assert_eq!(
            runtime.counters.rule_evaluations - evaluations,
            FIREWALL_CARRY_REEVALUATION_BUDGET
        );

        // One flow more: a flush with a fresh key instead.
        let mut states = vec![FirewallStateSlot::default(); 2_048];
        let mut runtime = FirewallRuntime::new(current, &mut states);
        for port in 0..=budget_flows {
            pass(&mut runtime, &current, udp_flow(1_000 + port as u16), 10).unwrap();
        }
        let evaluations = runtime.counters.rule_evaluations;
        // The flushing fallback still requires a rotated key.
        let same_key = config(snapshot, &next_rules, 2, hash_key());
        assert_eq!(
            runtime
                .preflight_reconcile_carrying(current, same_key, *snapshot, *snapshot)
                .err(),
            Some(FirewallReconcileError::HashKeyNotRotated)
        );
        let permit = runtime
            .preflight_reconcile_carrying(current, next, *snapshot, *snapshot)
            .unwrap();
        assert_eq!(
            permit.outcome(),
            StateCarryOutcome::FlushIncompatible(StateCarryConflict::ReevaluationBudget)
        );
        let report = permit.commit();
        assert_eq!(
            (report.states_flushed, report.states_carried),
            (budget_flows + 1, 0)
        );
        assert_eq!(runtime.counters.rule_evaluations, evaluations);
        assert_eq!(runtime.table_key, rotated_hash_key());
        assert_eq!(runtime.occupancy.occupied(), 0);
    });
}

#[test]
fn refused_carrying_preflights_change_nothing() {
    with_snapshot(|snapshot| {
        let rules = [udp_rule(1, FirewallAction::AllowStateful, (1, u16::MAX))];
        let current = config(snapshot, &rules, 2, hash_key());
        let mut states = [FirewallStateSlot::default(); 8];
        let mut runtime = FirewallRuntime::new(current, &mut states);
        pass(&mut runtime, &current, udp_flow(1_000), 10).unwrap();
        let before = runtime_image(&runtime);
        let other = config(snapshot, &rules, 3, rotated_hash_key());
        let older = config(snapshot, &rules, 1, rotated_hash_key());
        for (claimed, next, expected) in [
            (other, other, FirewallReconcileError::CurrentConfigMismatch),
            (current, older, FirewallReconcileError::GenerationRegression),
        ] {
            assert_eq!(
                runtime
                    .preflight_reconcile_carrying(claimed, next, *snapshot, *snapshot)
                    .err(),
                Some(expected)
            );
            assert_eq!(runtime_image(&runtime), before);
        }
        // A permit that is dropped changes nothing either, even with
        // changed rules to re-evaluate.
        let next_rules = [udp_rule(5, FirewallAction::Deny, (1, u16::MAX))];
        let next = config(snapshot, &next_rules, 3, rotated_hash_key());
        let permit = runtime
            .preflight_reconcile_carrying(current, next, *snapshot, *snapshot)
            .unwrap();
        assert!(permit.reevaluates());
        drop(permit);
        assert_eq!(runtime_image(&runtime), before);
    });
}

#[test]
fn a_shorter_idle_timeout_applies_to_carried_flows_and_reopens_the_sweep() {
    with_snapshot(|snapshot| {
        let rules = [udp_rule(1, FirewallAction::AllowStateful, (1, u16::MAX))];
        let long =
            FirewallPolicy::new(3 * FIREWALL_UDP_MIN_IDLE_TTL_MS, 240_000, 7_440_000).unwrap();
        let short = FirewallPolicy::new(FIREWALL_UDP_MIN_IDLE_TTL_MS, 240_000, 7_440_000).unwrap();
        let current = FirewallConfig::new(snapshot, &rules, long, 1, hash_key()).unwrap();
        let next = FirewallConfig::new(snapshot, &rules, short, 2, rotated_hash_key()).unwrap();
        let mut states = [FirewallStateSlot::default(); 4];
        let mut runtime = FirewallRuntime::new(current, &mut states);
        pass(&mut runtime, &current, udp_flow(1_000), 0).unwrap();
        pass(&mut runtime, &current, udp_flow(1_001), 0).unwrap();
        pass(&mut runtime, &current, udp_flow(1_002), 0).unwrap();
        // A refused fourth flow raised the sweep bound to the old deadline.
        assert!(matches!(
            runtime.plan_packet(&current, udp_flow(1_003), 1),
            Err(FirewallPlanError::StateFull(_))
        ));
        assert_eq!(
            runtime.reclaim_not_before_ms,
            3 * FIREWALL_UDP_MIN_IDLE_TTL_MS
        );
        runtime
            .preflight_reconcile_carrying(current, next, *snapshot, *snapshot)
            .unwrap()
            .commit();
        assert_eq!(runtime.reclaim_not_before_ms, 0);
        // Under the new timeout the carried flows idled out at `TTL`, so a
        // new flow takes a reclaimed slot then, not at `3 TTL`.
        assert_eq!(
            pass(
                &mut runtime,
                &next,
                udp_flow(1_003),
                FIREWALL_UDP_MIN_IDLE_TTL_MS
            ),
            Ok(FirewallConnectionClass::New)
        );
        assert_eq!(
            pass(
                &mut runtime,
                &next,
                reply(udp_flow(1_000)),
                FIREWALL_UDP_MIN_IDLE_TTL_MS
            ),
            Err(FirewallPlanError::DefaultDenied)
        );
    });
}

/// The reviewers' probe (core M1): a UDP flow at 0 with timeout T, a carry
/// at 5 T to a 10 T timeout. A longer timeout would make the expired, not
/// yet reclaimed flow live again; it flushes instead, so the pinhole stays
/// closed. Flows expired at the watermark are dropped by every carry and
/// do not count against the budget.
#[test]
fn expired_flows_never_revive_across_a_carry() {
    with_snapshot(|snapshot| {
        let rules = [udp_rule(1, FirewallAction::AllowStateful, (1, u16::MAX))];
        let ttl = FIREWALL_UDP_MIN_IDLE_TTL_MS;
        let policy = |udp| FirewallPolicy::new(udp, 240_000, 7_440_000).unwrap();
        let current = FirewallConfig::new(snapshot, &rules, policy(ttl), 1, hash_key()).unwrap();
        let longer =
            FirewallConfig::new(snapshot, &rules, policy(10 * ttl), 2, rotated_hash_key()).unwrap();
        let mut states = [FirewallStateSlot::default(); 8];
        let mut runtime = FirewallRuntime::new(current, &mut states);
        pass(&mut runtime, &current, udp_flow(1_000), 0).unwrap();
        // Another flow moves the watermark to 5 T.
        pass(&mut runtime, &current, udp_flow(1_001), 5 * ttl).unwrap();
        let permit = runtime
            .preflight_reconcile_carrying(current, longer, *snapshot, *snapshot)
            .unwrap();
        assert_eq!(
            permit.outcome(),
            StateCarryOutcome::FlushIncompatible(StateCarryConflict::Timers)
        );
        permit.commit();
        assert_eq!(
            pass(&mut runtime, &longer, reply(udp_flow(1_000)), 5 * ttl + 1),
            Err(FirewallPlanError::DefaultDenied)
        );

        // The same timeout: the flow expired at the watermark is dropped
        // (counted as expired), the live one is carried.
        let mut states = [FirewallStateSlot::default(); 8];
        let mut runtime = FirewallRuntime::new(current, &mut states);
        pass(&mut runtime, &current, udp_flow(1_000), 0).unwrap();
        pass(&mut runtime, &current, udp_flow(1_001), 5 * ttl).unwrap();
        let same =
            FirewallConfig::new(snapshot, &rules, policy(ttl), 2, rotated_hash_key()).unwrap();
        let expired = runtime.counters.states_expired;
        let permit = runtime
            .preflight_reconcile_carrying(current, same, *snapshot, *snapshot)
            .unwrap();
        assert_eq!(permit.preview().states_carried, 1, "only live flows count");
        let report = permit.commit();
        assert_eq!((report.states_carried, report.states_revoked), (1, 0));
        assert_eq!(runtime.counters.states_expired, expired + 1);
        assert_eq!(
            pass(&mut runtime, &same, reply(udp_flow(1_000)), 5 * ttl + 1),
            Err(FirewallPlanError::DefaultDenied)
        );
        assert_eq!(
            pass(&mut runtime, &same, reply(udp_flow(1_001)), 5 * ttl + 1),
            Ok(FirewallConnectionClass::Established)
        );
    });
}

/// Sec M2: when the route to a flow's endpoint changes (or disappears),
/// the flow is revoked, so the remote cannot keep the reverse direction
/// open; flows whose routes did not change are carried.
#[test]
fn a_changed_route_revokes_the_flows_it_moves() {
    with_snapshot(|snapshot| {
        let rules = [udp_rule(1, FirewallAction::AllowStateful, (1, u16::MAX))];
        let current = config(snapshot, &rules, 1, hash_key());
        // The next routes send 198.51.100.0/24 out of LAN instead of WAN
        // and keep everything else.
        let mut routes = snapshot.routes.to_vec();
        routes
            .push(Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, LAN, None).unwrap());
        let moved = ForwardingSnapshot::new(
            &routes,
            snapshot.interfaces,
            snapshot.neighbors,
            snapshot.local_ipv4,
        )
        .unwrap();
        let next = config(&moved, &rules, 2, rotated_hash_key());
        let mut states = [FirewallStateSlot::default(); 8];
        let mut runtime = FirewallRuntime::new(current, &mut states);
        let other = FirewallPacket {
            destination: Ipv4Address::from_octets([203, 0, 113, 50]).into(),
            ..udp_flow(1_001)
        };
        pass(&mut runtime, &current, udp_flow(1_000), 10).unwrap();
        pass(&mut runtime, &current, other, 10).unwrap();
        let permit = runtime
            .preflight_reconcile_carrying(current, next, *snapshot, moved)
            .unwrap();
        assert!(permit.reevaluates());
        let report = permit.commit();
        assert_eq!((report.states_carried, report.states_revoked), (1, 1));
        // The moved flow's remote cannot refresh it any more.
        assert_eq!(
            pass(&mut runtime, &next, reply(udp_flow(1_000)), 20),
            Err(FirewallPlanError::DefaultDenied)
        );
        assert_eq!(
            pass(&mut runtime, &next, reply(other), 20),
            Ok(FirewallConnectionClass::Established)
        );
    });
}

/// A next hop that changes out of the same interface keeps the flows (their
/// state still matches both directions); route lookups count against the
/// budget: 4032 rules plus 4 lookups of weight 16 per flow, so 1024 flows are exactly the
/// budget and 1025 flush.
#[test]
fn a_new_next_hop_keeps_flows_and_route_work_counts_against_the_budget() {
    with_snapshot(|snapshot| {
        let rules = [udp_rule(1, FirewallAction::AllowStateful, (1, u16::MAX))];
        let current = config(snapshot, &rules, 1, hash_key());
        // The default route now goes through another gateway on WAN.
        let mut routes = snapshot.routes.to_vec();
        routes[1] = Route::new(
            Ipv4Address::from_octets([0; 4]),
            0,
            WAN,
            Some(Ipv4Address::from_octets([203, 0, 113, 9])),
        )
        .unwrap();
        let regatewayed = ForwardingSnapshot::new(
            &routes,
            snapshot.interfaces,
            snapshot.neighbors,
            snapshot.local_ipv4,
        )
        .unwrap();
        let next = config(&regatewayed, &rules, 2, rotated_hash_key());
        let mut states = [FirewallStateSlot::default(); 8];
        let mut runtime = FirewallRuntime::new(current, &mut states);
        pass(&mut runtime, &current, udp_flow(1_000), 10).unwrap();
        let permit = runtime
            .preflight_reconcile_carrying(current, next, *snapshot, regatewayed)
            .unwrap();
        assert!(permit.reevaluates());
        let report = permit.commit();
        assert_eq!((report.states_carried, report.states_revoked), (1, 0));

        let mut next_rules: Vec<FirewallRule> = (0..3_999)
            .map(|id| udp_rule(10 + id, FirewallAction::Deny, (2, 2)))
            .collect();
        next_rules.push(udp_rule(
            9_999,
            FirewallAction::AllowStateful,
            (1, u16::MAX),
        ));
        let next = config(&regatewayed, &next_rules, 2, rotated_hash_key());
        for (flows, carried) in [(1_024_u16, true), (1_025, false)] {
            let mut states = vec![FirewallStateSlot::default(); 2_048];
            let mut runtime = FirewallRuntime::new(current, &mut states);
            for port in 0..flows {
                pass(&mut runtime, &current, udp_flow(1_000 + port), 10).unwrap();
            }
            let permit = runtime
                .preflight_reconcile_carrying(current, next, *snapshot, regatewayed)
                .unwrap();
            assert_eq!(permit.outcome().carried(), carried, "{flows} flows");
        }
    });
}

/// Core L2: an endpoint that is a router address in both snapshots (the
/// NAT public address in a hairpin flow's canonical tuple) is never routed
/// to, so a route change toward it keeps the flow; a forwarded endpoint
/// behind the same changed route is revoked.
#[test]
fn a_route_change_toward_a_router_address_keeps_the_flow() {
    with_snapshot(|snapshot| {
        let rules = [udp_rule(1, FirewallAction::AllowStateful, (1, u16::MAX))];
        let current = config(snapshot, &rules, 1, hash_key());
        // 10.0.0.0/30 (the router's 10.0.0.1 and the host 10.0.0.2) now
        // leaves through WAN.
        let mut routes = snapshot.routes.to_vec();
        routes.push(Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 30, WAN, None).unwrap());
        let moved = ForwardingSnapshot::new(
            &routes,
            snapshot.interfaces,
            snapshot.neighbors,
            snapshot.local_ipv4,
        )
        .unwrap();
        let next = config(&moved, &rules, 2, rotated_hash_key());
        let mut states = [FirewallStateSlot::default(); 8];
        let mut runtime = FirewallRuntime::new(current, &mut states);
        let toward = |last: u8, port: u16| FirewallPacket {
            source: Ipv4Address::from_octets([10, 0, 0, 77]).into(),
            destination: Ipv4Address::from_octets([10, 0, 0, last]).into(),
            ..udp_flow(port)
        };
        pass(&mut runtime, &current, toward(1, 1_000), 10).unwrap();
        pass(&mut runtime, &current, toward(2, 1_001), 10).unwrap();
        let report = runtime
            .preflight_reconcile_carrying(current, next, *snapshot, moved)
            .unwrap()
            .commit();
        assert_eq!((report.states_carried, report.states_revoked), (1, 1));
        assert_eq!(
            pass(&mut runtime, &next, reply(toward(1, 1_000)), 20),
            Ok(FirewallConnectionClass::Established)
        );
        assert_eq!(
            pass(&mut runtime, &next, reply(toward(2, 1_001)), 20),
            Err(FirewallPlanError::DefaultDenied)
        );
    });
}

/// The apply-time bound for a full production table (2^16 slots, 49152
/// usable) re-evaluated against 85 rules (4,177,920 tests, just under the
/// budget). Run with `cargo test --release -p ruster-core --lib
/// worst_case -- --ignored --nocapture` to measure; the architecture
/// document records the result.
#[test]
#[ignore = "timing measurement; run in release"]
fn worst_case_reevaluation_at_the_budget_takes_milliseconds() {
    with_snapshot(|snapshot| {
        let rules = [udp_rule(1, FirewallAction::AllowStateful, (1, u16::MAX))];
        let current = config(snapshot, &rules, 1, hash_key());
        let mut next_rules: Vec<FirewallRule> = (0..84)
            .map(|id| udp_rule(10 + id, FirewallAction::Deny, (2, 2)))
            .collect();
        next_rules.push(udp_rule(999, FirewallAction::AllowStateful, (1, u16::MAX)));
        let next = config(snapshot, &next_rules, 2, rotated_hash_key());
        let mut states = vec![FirewallStateSlot::default(); 1 << 16];
        let mut runtime = FirewallRuntime::new(current, &mut states);
        let usable = runtime.usable_capacity();
        for flow in 0..usable {
            let packet = FirewallPacket {
                source: Ipv4Address::from_octets([10, 0, (flow >> 8) as u8, flow as u8]).into(),
                ..udp_flow(1_000)
            };
            pass(&mut runtime, &current, packet, 10).unwrap();
        }
        let work = usable as u64 * next_rules.len() as u64;
        assert!(work <= FIREWALL_CARRY_REEVALUATION_BUDGET);
        let started = std::time::Instant::now();
        let report = runtime
            .preflight_reconcile_carrying(current, next, *snapshot, *snapshot)
            .unwrap()
            .commit();
        let elapsed = started.elapsed();
        assert_eq!(report.states_carried, usable);
        eprintln!(
            "firewall carry re-evaluation: {usable} flows x {} rules = {work} tests in {elapsed:?}",
            next_rules.len()
        );
    });
}

/// Sec L-a: the worst case with rules and routes both changed, over a large
/// indexed route table. Measures the cost of one route lookup against one
/// first-match rule test, which sets `FIREWALL_CARRY_ROUTE_LOOKUP_WEIGHT`.
/// Run with `cargo test --release -p ruster-core --lib
/// worst_case_with_rules_and_routes -- --ignored --nocapture`.
#[test]
#[ignore = "timing measurement; run in release"]
fn worst_case_with_rules_and_routes_changed_stays_within_the_bound() {
    use crate::{Interface, Ipv4OriginPolicy, LocalIpv4Binding, MacAddress, Neighbor};
    // 4096 routes (the config limit), all /24s out of WAN plus the LAN
    // connected route; the next table moves one /24 to LAN.
    let owner = |moved: bool| {
        let mut routes =
            vec![Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 8, LAN, None).unwrap()];
        for index in 0..4_095_u32 {
            let egress = if moved && index == 0 { LAN } else { WAN };
            routes.push(
                Route::new(
                    Ipv4Address::from_octets([100 + (index >> 8) as u8, index as u8, 0, 0]),
                    24,
                    egress,
                    if egress == WAN {
                        Some(Ipv4Address::from_octets([203, 0, 113, 1]))
                    } else {
                        None
                    },
                )
                .unwrap(),
            );
        }
        routes.push(Route::new(Ipv4Address::from_octets([203, 0, 113, 0]), 24, WAN, None).unwrap());
        crate::ValidatedForwardingOwner::new(
            routes.into(),
            vec![
                Interface {
                    id: LAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 1]),
                    mtu: 1500,
                },
                Interface {
                    id: WAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 2]),
                    mtu: 1500,
                },
            ]
            .into(),
            Vec::<Neighbor>::new().into(),
            vec![
                LocalIpv4Binding {
                    interface: LAN,
                    address: Ipv4Address::from_octets([10, 0, 0, 1]),
                },
                LocalIpv4Binding {
                    interface: WAN,
                    address: Ipv4Address::from_octets([203, 0, 113, 2]),
                },
            ]
            .into(),
            Ipv4OriginPolicy::default(),
        )
        .unwrap()
    };
    let (current_owner, next_owner) = (owner(false), owner(true));
    let (current_snapshot, next_snapshot) = (current_owner.snapshot(), next_owner.snapshot());
    let rules = [udp_rule(1, FirewallAction::AllowStateful, (1, u16::MAX))];
    let current = config(&current_snapshot, &rules, 1, hash_key());
    // `count` rules whose last one admits every flow (the first-match
    // worst case for an admitted flow).
    let rules_of = |count: u64| {
        let mut rules: Vec<FirewallRule> = (0..count - 1)
            .map(|id| udp_rule(10 + id as u32, FirewallAction::Deny, (2, 2)))
            .collect();
        rules.push(udp_rule(999, FirewallAction::AllowStateful, (1, u16::MAX)));
        rules
    };
    // 85 rules to measure a rule test; with routes changed too, as many as
    // the budget allows for a full table at the lookup weight.
    let changed = rules_of(85);
    let both_rules = rules_of(
        FIREWALL_CARRY_REEVALUATION_BUDGET / 49_152 - 4 * FIREWALL_CARRY_ROUTE_LOOKUP_WEIGHT,
    );
    // Flows to remotes spread over every /24 (cache misses in the index).
    let flow = |flow: usize| FirewallPacket {
        source: Ipv4Address::from_octets([10, 0, (flow >> 8) as u8, flow as u8]).into(),
        destination: Ipv4Address::from_octets([
            100 + ((flow % 4_095) >> 8) as u8,
            (flow % 4_095) as u8,
            0,
            7,
        ])
        .into(),
        ..udp_flow(1_000)
    };
    let run = |next_rules: &[FirewallRule], next_snapshot| {
        let next = config(&next_snapshot, next_rules, 2, rotated_hash_key());
        let mut states = vec![FirewallStateSlot::default(); 1 << 16];
        let mut runtime = FirewallRuntime::new(current, &mut states);
        let usable = runtime.usable_capacity();
        for index in 0..usable {
            pass(&mut runtime, &current, flow(index), 10).unwrap();
        }
        let permit = runtime
            .preflight_reconcile_carrying(current, next, current_snapshot, next_snapshot)
            .unwrap();
        assert!(permit.outcome().carried());
        let started = std::time::Instant::now();
        let report = permit.commit();
        (started.elapsed(), report, usable)
    };
    let (rules_only, _, usable) = run(&changed, current_snapshot);
    let (routes_only, report, _) = run(&rules, next_snapshot);
    assert!(report.states_revoked > 0);
    let (both, _, _) = run(&both_rules, next_snapshot);
    let per_test = rules_only.as_secs_f64() / (usable * changed.len()) as f64;
    let per_lookup = routes_only.as_secs_f64() / (usable * 4) as f64;
    let work = usable as u64 * (both_rules.len() as u64 + 4 * FIREWALL_CARRY_ROUTE_LOOKUP_WEIGHT);
    assert!(work <= FIREWALL_CARRY_REEVALUATION_BUDGET);
    // The ratio is printed, not asserted: timing on a shared host is noisy.
    eprintln!(
        "carry worst case: {usable} flows; rules only {rules_only:?} ({:.1} ns/test), routes only \
         {routes_only:?} ({:.1} ns/lookup, ratio {:.1}), both ({} rules) {both:?}; weighted work \
         {work} of budget {FIREWALL_CARRY_REEVALUATION_BUDGET}",
        per_test * 1e9,
        per_lookup * 1e9,
        per_lookup / per_test,
        both_rules.len(),
    );
}
