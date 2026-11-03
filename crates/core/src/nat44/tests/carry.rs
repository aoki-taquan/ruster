//! RELOAD-CARRY for the UDP NAT (and, through its engine, ICMP query NAT):
//! a compatible successor keeps every mapping, peer, index, port owner, the
//! hash key, the epoch, and the clock watermark; an incompatible one flushes
//! with a fresh key and names the conflict; timers and quotas of the
//! successor apply to carried state.

use super::*;

const TTL: u64 = NAT44_UDP_MIN_IDLE_TTL_MS;

fn policy() -> Nat44UdpPolicy {
    Nat44UdpPolicy::new(TTL, 0).unwrap()
}

fn outbound(
    runtime: &mut Nat44UdpRuntime<'_>,
    address: Ipv4Address,
    port: u16,
    remote: Ipv4Address,
    now: u64,
) -> Result<Nat44UdpOutboundPlan, Nat44UdpPlanError> {
    let plan = runtime
        .plan_outbound(address, port, remote, TEST_REMOTE_PORT, now)
        .inspect_err(|error| runtime.record_plan_error(*error))?;
    runtime.commit_outbound(plan, now).unwrap();
    Ok(plan)
}

fn inbound(
    runtime: &Nat44UdpRuntime<'_>,
    port: u16,
    remote: Ipv4Address,
    now: u64,
) -> Result<(), Nat44UdpPlanError> {
    runtime
        .plan_inbound_read_only(port, remote, TEST_REMOTE_PORT, now)
        .map(|_| ())
}

/// Every runtime field a carry must keep, as one comparable image.
fn kept(runtime: &Nat44UdpRuntime<'_>) -> impl PartialEq + std::fmt::Debug {
    (
        runtime.mappings.to_vec(),
        runtime.peers.to_vec(),
        runtime.hash_key,
        runtime.runtime_epoch,
        runtime.watermark_ms,
        runtime.next_generation,
        runtime.state_revision,
        runtime.occupancy(),
        runtime.validate_indexes(),
    )
}

#[test]
fn a_compatible_successor_carries_every_mapping_and_its_key() {
    with_port_config(policy(), 40_000, 40_015, |current| {
        // A successor with another idle TTL, seed, hairpinning, and port
        // preservation, from another snapshot: still compatible.
        let next_policy = Nat44UdpPolicy::new(TTL * 2, 99)
            .unwrap()
            .with_hairpinning(false)
            .with_port_preservation(false);
        with_port_config(next_policy, 40_000, 40_015, |next| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 4];
            let mut peers = [Nat44UdpPeerSlot::default(); 8];
            let mut indexes = TestNat44UdpIndexes::new(current, mappings.len(), peers.len());
            let mut runtime = indexes.runtime(current, &mut mappings, &mut peers);
            let first = outbound(&mut runtime, INTERNAL, 1_000, REMOTE1, 10).unwrap();
            outbound(&mut runtime, INTERNAL2, 1_000, REMOTE2, 20).unwrap();
            let before = kept(&runtime);
            let reconciliations = runtime.counters().reconciliations;

            assert_eq!(runtime.carry_conflict(next), None);
            let permit = runtime
                .preflight_reconcile_carrying(next, rotated_udp_hash_key())
                .unwrap();
            assert_eq!(permit.outcome(), crate::StateCarryOutcome::Carried);
            let report = permit.commit();
            assert_eq!(
                report,
                Nat44UdpReconcileReport {
                    mappings_flushed: 0,
                    peers_flushed: 0,
                    mappings_carried: 2,
                    peers_carried: 2,
                    outcome: crate::StateCarryOutcome::Carried,
                }
            );
            assert_eq!(kept(&runtime), before, "a carry changes no state");
            assert_eq!(runtime.config(), next);
            assert!(runtime.publication_binding_matches(next, test_udp_hash_key()));
            assert!(!runtime.publication_binding_matches(next, rotated_udp_hash_key()));
            assert_eq!(runtime.counters().reconciliations, reconciliations + 1);

            // The carried mapping still translates replies, and the new,
            // longer TTL applies from its last outbound activity.
            let port = first.public_port();
            assert_eq!(inbound(&runtime, port, REMOTE1, 10 + TTL), Ok(()));
            assert_eq!(inbound(&runtime, port, REMOTE1, 10 + 2 * TTL - 1), Ok(()));
            assert_eq!(
                inbound(&runtime, port, REMOTE1, 10 + 2 * TTL),
                Err(Nat44UdpPlanError::MappingMiss)
            );
            // The reused mapping keeps its port; nothing was rehashed.
            let again = outbound(&mut runtime, INTERNAL, 1_000, REMOTE1, 30).unwrap();
            assert!(!again.mapping_created);
            assert_eq!(again.public_port(), port);
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
    });
}

#[test]
fn a_shorter_ttl_reevaluates_carried_mappings_from_their_last_activity() {
    with_port_config(
        Nat44UdpPolicy::new(TTL * 3, 0).unwrap(),
        40_000,
        40_015,
        |current| {
            with_port_config(policy(), 40_000, 40_015, |next| {
                let mut mappings = [Nat44UdpMappingSlot::default(); 4];
                let mut peers = [Nat44UdpPeerSlot::default(); 8];
                let mut indexes = TestNat44UdpIndexes::new(current, mappings.len(), peers.len());
                let mut runtime = indexes.runtime(current, &mut mappings, &mut peers);
                let port = outbound(&mut runtime, INTERNAL, 1_000, REMOTE1, 0)
                    .unwrap()
                    .public_port();
                assert_eq!(inbound(&runtime, port, REMOTE1, 2 * TTL), Ok(()));
                runtime
                    .preflight_reconcile_carrying(next, rotated_udp_hash_key())
                    .unwrap()
                    .commit();
                // Under the new TTL the mapping idled out at `TTL`, not `3 TTL`.
                assert_eq!(inbound(&runtime, port, REMOTE1, TTL - 1), Ok(()));
                assert_eq!(
                    inbound(&runtime, port, REMOTE1, TTL),
                    Err(Nat44UdpPlanError::MappingMiss)
                );
            });
        },
    );
}

#[test]
fn a_lowered_quota_keeps_live_mappings_and_refuses_new_ones_until_below_it() {
    let quota = |limit| policy().with_mappings_per_host(limit);
    with_port_config(quota(3), 40_000, 40_063, |current| {
        with_port_config(quota(1), 40_000, 40_063, |next| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 8];
            let mut peers = [Nat44UdpPeerSlot::default(); 16];
            let mut indexes = TestNat44UdpIndexes::new(current, mappings.len(), peers.len());
            let mut runtime = indexes.runtime(current, &mut mappings, &mut peers);
            let ports: Vec<u16> = (0..3)
                .map(|index| {
                    outbound(
                        &mut runtime,
                        INTERNAL,
                        1_000 + index,
                        REMOTE1,
                        10 * u64::from(index),
                    )
                    .unwrap()
                    .public_port()
                })
                .collect();
            runtime
                .preflight_reconcile_carrying(next, rotated_udp_hash_key())
                .unwrap()
                .commit();
            // No live mapping is evicted: all three still translate.
            for port in &ports {
                assert_eq!(inbound(&runtime, *port, REMOTE1, 100), Ok(()));
            }
            // A new mapping for the host is refused while it holds more than
            // the new limit of live mappings, without any state change.
            let before = (runtime.mappings.to_vec(), runtime.peers.to_vec());
            assert_eq!(
                outbound(&mut runtime, INTERNAL, 1_003, REMOTE1, 100).map(|_| ()),
                Err(Nat44UdpPlanError::HostQuotaExceeded)
            );
            assert_eq!((runtime.mappings.to_vec(), runtime.peers.to_vec()), before);
            // Existing mappings keep working (refresh, new peer).
            outbound(&mut runtime, INTERNAL, 1_002, REMOTE2, 100).unwrap();
            // Other hosts are unaffected.
            outbound(&mut runtime, INTERNAL2, 1_000, REMOTE1, 100).unwrap();
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
    });
}

#[test]
fn an_incompatible_successor_flushes_with_a_fresh_key_and_names_the_conflict() {
    use crate::{StateCarryConflict, StateCarryOutcome};
    let filtering = policy().with_filtering(Nat44Filtering::EndpointIndependent);
    let cases: [(Nat44UdpPolicy, u16, u16, StateCarryConflict); 2] = [
        (policy(), 40_016, 40_031, StateCarryConflict::PortRange),
        (filtering, 40_000, 40_015, StateCarryConflict::Filtering),
    ];
    for (next_policy, first, last, conflict) in cases {
        with_port_config(policy(), 40_000, 40_015, |current| {
            with_port_config(next_policy, first, last, |next| {
                let mut mappings = [Nat44UdpMappingSlot::default(); 4];
                let mut peers = [Nat44UdpPeerSlot::default(); 8];
                let mut indexes = TestNat44UdpIndexes::new(current, mappings.len(), peers.len());
                let mut runtime = indexes.runtime(current, &mut mappings, &mut peers);
                let port = outbound(&mut runtime, INTERNAL, 1_000, REMOTE1, 10)
                    .unwrap()
                    .public_port();
                assert_eq!(runtime.carry_conflict(next), Some(conflict));
                // The key must still rotate on the flushing path.
                assert_eq!(
                    runtime
                        .preflight_reconcile_carrying(next, test_udp_hash_key())
                        .err(),
                    Some(Nat44UdpReconcileError::HashKeyNotRotated)
                );
                let report = runtime
                    .preflight_reconcile_carrying(next, rotated_udp_hash_key())
                    .unwrap()
                    .commit();
                assert_eq!(
                    report.outcome,
                    StateCarryOutcome::FlushIncompatible(conflict)
                );
                assert_eq!((report.mappings_flushed, report.mappings_carried), (1, 0));
                assert!(runtime.publication_binding_matches(next, rotated_udp_hash_key()));
                assert!(runtime.mappings.iter().all(|slot| !slot.occupied));
                assert_eq!(
                    inbound(&runtime, port, REMOTE1, 20),
                    Err(Nat44UdpPlanError::MappingMiss)
                );
            });
        });
    }
}

#[test]
fn carry_identity_orders_the_conflicts_and_ignores_the_policy_knobs() {
    use crate::StateCarryConflict;
    let base = Nat44CarryIdentity::new(
        INSIDE,
        OUTSIDE,
        PUBLIC,
        40_000,
        40_015,
        Nat44Filtering::AddressDependent,
    );
    assert_eq!(base.carry_conflict(base), None);
    let all = Nat44CarryIdentity::new(
        OUTSIDE,
        INSIDE,
        Ipv4Address::from_octets([203, 0, 113, 11]),
        40_001,
        40_015,
        Nat44Filtering::EndpointIndependent,
    );
    assert_eq!(
        base.carry_conflict(all),
        Some(StateCarryConflict::Interfaces)
    );
    let public = Nat44CarryIdentity {
        inside: INSIDE,
        outside: OUTSIDE,
        ..all
    };
    assert_eq!(
        base.carry_conflict(public),
        Some(StateCarryConflict::PublicAddress)
    );
    let ports = Nat44CarryIdentity {
        public_address: PUBLIC,
        ..public
    };
    assert_eq!(
        base.carry_conflict(ports),
        Some(StateCarryConflict::PortRange)
    );
    let last = Nat44CarryIdentity {
        first_port: 40_000,
        last_port: 40_014,
        ..ports
    };
    assert_eq!(
        base.carry_conflict(last),
        Some(StateCarryConflict::PortRange)
    );
    let filtering = Nat44CarryIdentity {
        last_port: 40_015,
        ..last
    };
    assert_eq!(
        base.carry_conflict(filtering),
        Some(StateCarryConflict::Filtering)
    );
    let inside = Nat44CarryIdentity {
        inside: OUTSIDE,
        ..base
    };
    assert_eq!(
        base.carry_conflict(inside),
        Some(StateCarryConflict::Interfaces)
    );
    let outside = Nat44CarryIdentity {
        outside: INSIDE,
        ..base
    };
    assert_eq!(
        base.carry_conflict(outside),
        Some(StateCarryConflict::Interfaces)
    );
}

#[test]
fn a_dropped_carry_permit_changes_nothing() {
    with_port_config(policy(), 40_000, 40_015, |current| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 4];
        let mut peers = [Nat44UdpPeerSlot::default(); 8];
        let mut indexes = TestNat44UdpIndexes::new(current, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(current, &mut mappings, &mut peers);
        outbound(&mut runtime, INTERNAL, 1_000, REMOTE1, 10).unwrap();
        let before = (kept(&runtime), runtime.config(), runtime.counters());
        let permit = runtime
            .preflight_reconcile_carrying(current, rotated_udp_hash_key())
            .unwrap();
        drop(permit);
        assert_eq!(
            (kept(&runtime), runtime.config(), runtime.counters()),
            before
        );
    });
}
