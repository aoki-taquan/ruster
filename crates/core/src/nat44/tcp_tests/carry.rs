//! RELOAD-CARRY for the TCP NAT: an established session (RFC 5382 REQ-5,
//! idle at least 2 h 4 min) survives a compatible publication with its
//! phase, mapping, port, and key; unsolicited-SYN holds never carry; a
//! successor that changes the realm, pool, filtering, or a phase timeout
//! (TCP mappings keep absolute deadlines) flushes with a fresh key.

use super::*;

const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;

fn seg(flags: u8) -> Nat44TcpSegment {
    Nat44TcpSegment::from_flags(flags)
}

fn out(
    runtime: &mut Nat44TcpRuntime<'_>,
    internal: (Ipv4Address, u16),
    remote: (Ipv4Address, u16),
    flags: u8,
    now: u64,
) -> (usize, usize) {
    let plan = runtime
        .plan_outbound(internal.0, internal.1, remote.0, remote.1, seg(flags), now)
        .unwrap();
    runtime.commit_outbound(plan, now).unwrap();
    (plan.mapping_index(), plan.session_index())
}

fn inbound(
    runtime: &mut Nat44TcpRuntime<'_>,
    port: u16,
    remote: (Ipv4Address, u16),
    flags: u8,
    now: u64,
) {
    let plan = runtime
        .plan_inbound(port, remote.0, remote.1, seg(flags), now)
        .unwrap();
    runtime.commit_inbound(plan, now).unwrap();
}

fn probe(
    runtime: &Nat44TcpRuntime<'_>,
    port: u16,
    remote: (Ipv4Address, u16),
    now: u64,
) -> Result<(), Nat44TcpPlanError> {
    runtime
        .plan_inbound_read_only(port, remote.0, remote.1, seg(ACK), now)
        .map(|_| ())
}

const HOST: (Ipv4Address, u16) = (INTERNAL, 40_000);
const PEER: (Ipv4Address, u16) = (REMOTE1, 443);
const ESTABLISHED: u64 = NAT44_TCP_MIN_IDLE_TTL_MS;

#[test]
fn an_established_session_survives_a_compatible_successor_with_its_key() {
    let current_policy = Nat44TcpPolicy::new(ESTABLISHED, 0).unwrap();
    // Another seed, RST policy, and per-remote limit: compatible.
    let next_policy = Nat44TcpPolicy::new(ESTABLISHED, 7)
        .unwrap()
        .with_inbound_rst(Nat44TcpInboundRst::Corroborate)
        .with_inbound_sessions_per_remote(8)
        .unwrap();
    with_config(current_policy, 40_000, 40_007, |current| {
        with_config(next_policy, 40_000, 40_007, |next| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 2];
            let mut sessions = [Nat44TcpSessionSlot::default(); 4];
            let mut runtime = test_tcp_runtime(current, &mut mappings, &mut sessions);
            let (mapping, session) = out(&mut runtime, HOST, PEER, SYN, 0);
            let port = runtime.mappings[mapping].public_port;
            inbound(&mut runtime, port, PEER, SYN_ACK, 10);
            out(&mut runtime, HOST, PEER, ACK, 20);
            assert_eq!(
                runtime.sessions[session].phase(),
                Nat44TcpSessionPhase::Established
            );
            let image = (
                runtime.mappings.to_vec(),
                runtime.sessions.to_vec(),
                runtime.runtime_epoch,
                runtime.watermark_ms,
            );

            assert_eq!(runtime.carry_conflict(next), None);
            let report = runtime
                .preflight_reconcile_carrying(next, rotated_test_tcp_hash_key())
                .unwrap()
                .commit();
            assert_eq!(
                report,
                Nat44TcpReconcileReport {
                    mappings_flushed: 0,
                    sessions_flushed: 0,
                    mappings_carried: 1,
                    sessions_carried: 1,
                    outcome: crate::StateCarryOutcome::Carried,
                }
            );
            assert_eq!(
                (
                    runtime.mappings.to_vec(),
                    runtime.sessions.to_vec(),
                    runtime.runtime_epoch,
                    runtime.watermark_ms,
                ),
                image
            );
            assert!(runtime.publication_binding_matches(next, test_tcp_hash_key()));
            assert_eq!(runtime.validate_indexes(), Ok(()));
            // The data path continues with the established TTL (RFC 5382
            // REQ-5) running from the last segment.
            assert_eq!(probe(&runtime, port, PEER, 20 + ESTABLISHED - 1), Ok(()));
            assert_eq!(
                probe(&runtime, port, PEER, 20 + ESTABLISHED),
                Err(Nat44TcpPlanError::MappingMiss)
            );
            inbound(&mut runtime, port, PEER, ACK, 30);
            out(&mut runtime, HOST, PEER, ACK, 40);
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
    });
}

#[test]
fn a_carry_drops_unsolicited_syn_holds_and_keeps_sessions() {
    let policy = Nat44TcpPolicy::new(ESTABLISHED, 0).unwrap();
    with_config(policy, 40_000, 40_007, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 2];
        let mut sessions = [Nat44TcpSessionSlot::default(); 4];
        let mut holds = [crate::Nat44TcpSynHoldSlot::EMPTY; 4];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions)
            .with_unsolicited_syn_holds(&mut holds)
            .unwrap();
        out(&mut runtime, HOST, PEER, SYN, 0);
        let hold = runtime.hold_unsolicited_syn(40_005, REMOTE2, 1_234, 0, &[0x45; 28], 0);
        assert_eq!(hold, Some(crate::nat44_syn_hold::SynHoldInsert::Held));
        assert_eq!(runtime.syn_holds.len(), 1);
        let report = runtime
            .preflight_reconcile_carrying(config, rotated_test_tcp_hash_key())
            .unwrap()
            .commit();
        assert!(report.outcome.carried());
        assert_eq!(runtime.syn_holds.len(), 0, "no hold outlives a publication");
        assert_eq!(report.sessions_carried, 1);
    });
}

#[test]
fn an_incompatible_tcp_successor_flushes_with_a_fresh_key() {
    use crate::StateCarryConflict;
    let policy = Nat44TcpPolicy::new(ESTABLISHED, 0).unwrap();
    let cases = [
        (
            policy.with_filtering(Nat44Filtering::AddressAndPortDependent),
            StateCarryConflict::Filtering,
        ),
        (
            Nat44TcpPolicy::new(ESTABLISHED * 2, 0).unwrap(),
            StateCarryConflict::Timers,
        ),
        (
            policy.with_opening_idle_ttl_ms(300_000).unwrap(),
            StateCarryConflict::Timers,
        ),
        (
            policy.with_closing_idle_ttl_ms(300_000).unwrap(),
            StateCarryConflict::Timers,
        ),
    ];
    for (next_policy, conflict) in cases {
        incompatible(policy, next_policy, conflict);
    }
}

fn incompatible(
    policy: Nat44TcpPolicy,
    next_policy: Nat44TcpPolicy,
    conflict: crate::StateCarryConflict,
) {
    with_config(policy, 40_000, 40_007, |current| {
        with_config(next_policy, 40_000, 40_007, |next| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 2];
            let mut sessions = [Nat44TcpSessionSlot::default(); 4];
            let mut runtime = test_tcp_runtime(current, &mut mappings, &mut sessions);
            out(&mut runtime, HOST, PEER, SYN, 0);
            assert_eq!(runtime.carry_conflict(next), Some(conflict));
            let report = runtime
                .preflight_reconcile_carrying(next, rotated_test_tcp_hash_key())
                .unwrap()
                .commit();
            assert_eq!(
                report.outcome,
                crate::StateCarryOutcome::FlushIncompatible(conflict)
            );
            assert_eq!((report.mappings_flushed, report.sessions_flushed), (1, 1));
            assert!(runtime.publication_binding_matches(next, rotated_test_tcp_hash_key()));
            assert!(runtime.sessions.iter().all(|slot| !slot.occupied));
        });
    });
}
