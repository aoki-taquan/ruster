//! RELOAD-CARRY for the UDP NAT (and, through its engine, ICMP query NAT):
//! a compatible successor keeps every mapping, peer, index, port owner, the
//! hash key, the epoch, and the clock watermark; an incompatible one flushes
//! with a fresh key and names the conflict. State that expired under the old
//! policy never becomes live again: a longer idle timeout and a lowered or
//! new per-host limit flush.

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
        // A successor with another seed, hairpinning, and port
        // preservation, from another snapshot: still compatible.
        let next_policy = Nat44UdpPolicy::new(TTL, 99)
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

            // The carried mapping still translates replies until its TTL
            // from its last outbound activity.
            let port = first.public_port();
            assert_eq!(inbound(&runtime, port, REMOTE1, 10 + TTL - 1), Ok(()));
            assert_eq!(
                inbound(&runtime, port, REMOTE1, 10 + TTL),
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
fn a_lowered_or_new_quota_flushes_and_a_raised_or_removed_one_carries() {
    use crate::{StateCarryConflict, StateCarryOutcome};
    let quota = |mappings, peers| {
        policy()
            .with_mappings_per_host(mappings)
            .with_peers_per_host(peers)
    };
    // (current, next, carried): the reclaim paths take over a host's
    // expired slot one for one, so a host above a lowered limit would never
    // come down to it; a lower or new limit therefore flushes (and takes
    // effect at once), a higher or removed one carries.
    for (current_policy, next_policy, carried) in [
        (quota(3, 0), quota(1, 0), false),
        (quota(3, 4), quota(3, 2), false),
        (quota(0, 4), quota(2, 4), false),
        (quota(3, 4), quota(3, 0), true),
        (quota(1, 4), quota(3, 8), true),
    ] {
        with_port_config(current_policy, 40_000, 40_063, |current| {
            with_port_config(next_policy, 40_000, 40_063, |next| {
                let mut mappings = [Nat44UdpMappingSlot::default(); 8];
                let mut peers = [Nat44UdpPeerSlot::default(); 16];
                let mut indexes = TestNat44UdpIndexes::new(current, mappings.len(), peers.len());
                let mut runtime = indexes.runtime(current, &mut mappings, &mut peers);
                let port = outbound(&mut runtime, INTERNAL, 1_000, REMOTE1, 10)
                    .unwrap()
                    .public_port();
                let report = runtime
                    .preflight_reconcile_carrying(next, rotated_udp_hash_key())
                    .unwrap()
                    .commit();
                if carried {
                    assert_eq!(report.outcome, StateCarryOutcome::Carried);
                    assert_eq!(inbound(&runtime, port, REMOTE1, 20), Ok(()));
                } else {
                    assert_eq!(
                        report.outcome,
                        StateCarryOutcome::FlushIncompatible(StateCarryConflict::Quota)
                    );
                    assert_eq!(report.mappings_flushed, 1);
                    assert_eq!(
                        inbound(&runtime, port, REMOTE1, 20),
                        Err(Nat44UdpPlanError::MappingMiss)
                    );
                }
                assert_eq!(runtime.validate_indexes(), Ok(()));
            });
        });
    }
}

/// The reviewers' probe (H1): mappings 4, peers 3. A maps to two remotes
/// at 0, B to one at T - 1; at T + 5 B's new peer parks A's expired
/// mapping. A carry to a 3 T timeout would make the parked mapping count
/// as live again and corrupt the reuse lists; it flushes instead, and a
/// shorter timeout carries with consistent indexes.
#[test]
fn a_longer_idle_timeout_flushes_so_parked_mappings_never_revive() {
    use crate::{StateCarryConflict, StateCarryOutcome};
    for (next_ttl, carried) in [(3 * TTL, false), (TTL, true)] {
        with_port_config(policy(), 40_000, 40_015, |current| {
            let next_policy = Nat44UdpPolicy::new(next_ttl, 0).unwrap();
            with_port_config(next_policy, 40_000, 40_015, |next| {
                let mut mappings = [Nat44UdpMappingSlot::default(); 4];
                let mut peers = [Nat44UdpPeerSlot::default(); 3];
                let mut indexes = TestNat44UdpIndexes::new(current, mappings.len(), peers.len());
                let mut runtime = indexes.runtime(current, &mut mappings, &mut peers);
                let a = outbound(&mut runtime, INTERNAL, 1_000, REMOTE1, 0)
                    .unwrap()
                    .public_port();
                outbound(&mut runtime, INTERNAL, 1_000, REMOTE2, 0).unwrap();
                outbound(&mut runtime, INTERNAL2, 1_000, REMOTE1, TTL - 1).unwrap();
                outbound(&mut runtime, INTERNAL2, 1_000, REMOTE2, TTL + 5).unwrap();
                assert!(runtime
                    .mappings
                    .iter()
                    .any(|slot| slot.occupied && slot.link.list != UdpMappingList::Lru));
                assert_eq!(runtime.validate_indexes(), Ok(()));
                let report = runtime
                    .preflight_reconcile_carrying(next, rotated_udp_hash_key())
                    .unwrap()
                    .commit();
                assert_eq!(report.outcome.carried(), carried);
                if !carried {
                    assert_eq!(
                        report.outcome,
                        StateCarryOutcome::FlushIncompatible(StateCarryConflict::Timers)
                    );
                }
                assert_eq!(runtime.validate_indexes(), Ok(()));
                // The expired mapping of A does not translate, and A's next
                // outbound refresh works with consistent indexes.
                assert_eq!(
                    inbound(&runtime, a, REMOTE1, TTL + 6),
                    Err(Nat44UdpPlanError::MappingMiss)
                );
                outbound(&mut runtime, INTERNAL, 1_000, REMOTE1, TTL + 7).unwrap();
                assert_eq!(runtime.validate_indexes(), Ok(()));
            });
        });
    }
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
