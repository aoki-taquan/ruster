//! N1: per-phase TCP session timers (RFC 5382 REQ-5, RFC 7857 §2) in the
//! TCP NAT runtime. A child of `nat44::tcp_tests`, sharing its helpers.

use super::*;

const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;
const FIN_ACK: u8 = 0x11;
const RST: u8 = 0x04;
const RST_ACK: u8 = 0x14;

/// Distinct opening and closing timeouts, so a test can tell which one a
/// session uses; the established one is the RFC floor.
const OPENING: u64 = 300_000;
const CLOSING: u64 = 250_000;
const ESTABLISHED: u64 = NAT44_TCP_MIN_IDLE_TTL_MS;

fn timer_policy() -> Nat44TcpPolicy {
    Nat44TcpPolicy::new(ESTABLISHED, 0)
        .unwrap()
        .with_opening_idle_ttl_ms(OPENING)
        .unwrap()
        .with_closing_idle_ttl_ms(CLOSING)
        .unwrap()
        .with_filtering(Nat44Filtering::EndpointIndependent)
}

fn seg(flags: u8) -> Nat44TcpSegment {
    Nat44TcpSegment::from_flags(flags)
}

/// Plans and commits an outbound segment; returns (mapping, session).
fn out(
    runtime: &mut Nat44TcpRuntime<'_>,
    internal: (Ipv4Address, u16),
    remote: (Ipv4Address, u16),
    flags: u8,
    now: u64,
) -> Result<(usize, usize), Nat44TcpPlanError> {
    let plan =
        runtime.plan_outbound(internal.0, internal.1, remote.0, remote.1, seg(flags), now)?;
    runtime.commit_outbound(plan, now).unwrap();
    assert_eq!(runtime.validate_indexes(), Ok(()));
    Ok((plan.mapping_index(), plan.session_index()))
}

/// Plans and commits an inbound segment; returns the session.
fn inbound(
    runtime: &mut Nat44TcpRuntime<'_>,
    public_port: u16,
    remote: (Ipv4Address, u16),
    flags: u8,
    now: u64,
) -> Result<usize, Nat44TcpPlanError> {
    let plan = runtime.plan_inbound(public_port, remote.0, remote.1, seg(flags), now)?;
    runtime.commit_inbound(plan, now).unwrap();
    assert_eq!(runtime.validate_indexes(), Ok(()));
    Ok(plan.session_index)
}

/// Outbound-initiated three-way handshake at `now`; returns the session.
fn handshake(
    runtime: &mut Nat44TcpRuntime<'_>,
    internal: (Ipv4Address, u16),
    remote: (Ipv4Address, u16),
    now: u64,
) -> (usize, usize) {
    let (mapping, session) = out(runtime, internal, remote, SYN, now).unwrap();
    let port = runtime.mappings[mapping].public_port;
    inbound(runtime, port, remote, SYN_ACK, now).unwrap();
    out(runtime, internal, remote, ACK, now).unwrap();
    assert_eq!(
        runtime.sessions[session].phase(),
        Nat44TcpSessionPhase::Established
    );
    (mapping, session)
}

/// Whether an ACK from `remote` to `public_port` would be translated now
/// (read-only): `Ok`, `SessionMiss` (live mapping, no live session), or
/// `MappingMiss`.
fn probe(
    runtime: &Nat44TcpRuntime<'_>,
    public_port: u16,
    remote: (Ipv4Address, u16),
    now: u64,
) -> Result<(), Nat44TcpPlanError> {
    runtime
        .plan_inbound_read_only(public_port, remote.0, remote.1, seg(ACK), now)
        .map(|_| ())
}

const HOST: (Ipv4Address, u16) = (INTERNAL, 40_000);
const PEER: (Ipv4Address, u16) = (REMOTE1, 443);
const PEER2: (Ipv4Address, u16) = (REMOTE2, 443);

#[test]
fn transitory_ttls_are_bounded_by_the_rfc_floor_and_the_established_ttl() {
    let policy = Nat44TcpPolicy::default();
    assert_eq!(
        (
            policy.opening_idle_ttl_ms(),
            policy.closing_idle_ttl_ms(),
            policy.idle_ttl_ms()
        ),
        (240_000, 240_000, 7_440_000)
    );
    assert_eq!(NAT44_TCP_MIN_TRANSITORY_IDLE_TTL_MS, 4 * 60 * 1000);
    for set in [
        Nat44TcpPolicy::with_opening_idle_ttl_ms,
        Nat44TcpPolicy::with_closing_idle_ttl_ms,
    ] {
        assert_eq!(
            set(policy, NAT44_TCP_MIN_TRANSITORY_IDLE_TTL_MS - 1),
            Err(Nat44TcpPolicyError::TransitoryIdleTtlTooShort)
        );
        assert_eq!(
            set(policy, policy.idle_ttl_ms() + 1),
            Err(Nat44TcpPolicyError::TransitoryIdleTtlAboveEstablished)
        );
        assert!(set(policy, NAT44_TCP_MIN_TRANSITORY_IDLE_TTL_MS).is_ok());
        assert!(set(policy, policy.idle_ttl_ms()).is_ok());
    }
    let policy = timer_policy();
    assert_eq!(
        [
            Nat44TcpSessionPhase::Opening,
            Nat44TcpSessionPhase::Established,
            Nat44TcpSessionPhase::Closing
        ]
        .map(|phase| policy.session_idle_ttl_ms(phase)),
        [OPENING, ESTABLISHED, CLOSING]
    );
}

/// Each phase expires exactly at its own TTL after the last segment, never
/// earlier: opening (SYN only), established (after the final handshake
/// ACK, and with a FIN in one direction), closing (FIN in both). The
/// mapping follows: established while an established session exists, then
/// the longer transitory TTL after the last segment.
#[test]
fn each_phase_expires_exactly_at_its_ttl_and_the_mapping_follows() {
    with_config(timer_policy(), 40_000, 40_000, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 1];
        let mut sessions = [Nat44TcpSessionSlot::default(); 2];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let (mapping, session) = out(&mut runtime, HOST, PEER, SYN, 0).unwrap();
        let port = runtime.mappings[mapping].public_port;
        assert_eq!(
            runtime.sessions[session].phase(),
            Nat44TcpSessionPhase::Opening
        );
        assert_eq!(probe(&runtime, port, PEER, OPENING - 1), Ok(()));
        assert_eq!(
            probe(&runtime, port, PEER, OPENING),
            Err(Nat44TcpPlanError::MappingMiss)
        );
        assert_eq!(runtime.mappings[mapping].expires_ms, OPENING);

        inbound(&mut runtime, port, PEER, SYN_ACK, 1_000).unwrap();
        assert_eq!(
            runtime.sessions[session].phase(),
            Nat44TcpSessionPhase::Opening
        );
        out(&mut runtime, HOST, PEER, ACK, 2_000).unwrap();
        assert_eq!(
            runtime.sessions[session].phase(),
            Nat44TcpSessionPhase::Established
        );
        assert_eq!(probe(&runtime, port, PEER, 2_000 + ESTABLISHED - 1), Ok(()));
        assert_eq!(
            probe(&runtime, port, PEER, 2_000 + ESTABLISHED),
            Err(Nat44TcpPlanError::MappingMiss)
        );
        assert_eq!(
            runtime.mappings[mapping].link.list,
            TcpMappingList::Established
        );
        assert_eq!(runtime.mappings[mapping].established_sessions, 1);

        // A FIN in one direction keeps the established TTL.
        out(&mut runtime, HOST, PEER, FIN_ACK, 3_000).unwrap();
        assert_eq!(probe(&runtime, port, PEER, 3_000 + ESTABLISHED - 1), Ok(()));

        // FIN in both directions: closing TTL for the session, and the
        // mapping, with no established session left, the longer transitory
        // TTL (here the opening one).
        inbound(&mut runtime, port, PEER, FIN_ACK, 4_000).unwrap();
        assert_eq!(
            runtime.sessions[session].phase(),
            Nat44TcpSessionPhase::Closing
        );
        assert_eq!(runtime.mappings[mapping].established_sessions, 0);
        assert_eq!(
            runtime.mappings[mapping].link.list,
            TcpMappingList::Transitory
        );
        assert_eq!(probe(&runtime, port, PEER, 4_000 + CLOSING - 1), Ok(()));
        assert_eq!(
            probe(&runtime, port, PEER, 4_000 + CLOSING),
            Err(Nat44TcpPlanError::SessionMiss)
        );
        assert_eq!(
            probe(&runtime, port, PEER, 4_000 + OPENING),
            Err(Nat44TcpPlanError::MappingMiss)
        );
        let counters = runtime.counters();
        assert_eq!(
            (counters.sessions_established, counters.sessions_closed),
            (1, 1)
        );

        // The freed slots are reused: the session as a closing expiry.
        out(
            &mut runtime,
            (INTERNAL2, 40_000),
            PEER2,
            SYN,
            4_000 + OPENING,
        )
        .unwrap();
        let counters = runtime.counters();
        assert_eq!(
            (
                counters.mappings_expired,
                counters.sessions_expired,
                counters.sessions_expired_closing
            ),
            (1, 1, 1)
        );
    });
}

/// RFC 7857 §2.2: a RST (either direction, any other flags) never ends a
/// session at once: it moves to the closing TTL, which every further RST
/// restarts, and the first non-RST segment returns it to its phase.
#[test]
fn rst_keeps_the_session_for_the_closing_ttl_and_traffic_restores_it() {
    for (direction_inbound, flags) in [(true, RST), (false, RST), (true, RST_ACK), (false, RST_ACK)]
    {
        with_config(timer_policy(), 40_000, 40_000, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 1];
            let mut sessions = [Nat44TcpSessionSlot::default(); 1];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let (mapping, session) = handshake(&mut runtime, HOST, PEER, 0);
            let port = runtime.mappings[mapping].public_port;
            let reset = |runtime: &mut Nat44TcpRuntime<'_>, now| {
                if direction_inbound {
                    inbound(runtime, port, PEER, flags, now).unwrap();
                } else {
                    out(runtime, HOST, PEER, flags, now).unwrap();
                }
            };
            reset(&mut runtime, 10_000);
            assert_eq!(
                runtime.sessions[session].phase(),
                Nat44TcpSessionPhase::Closing
            );
            assert_eq!(runtime.counters().sessions_reset, 1);
            assert_eq!(probe(&runtime, port, PEER, 10_000 + CLOSING - 1), Ok(()));
            assert_eq!(
                probe(&runtime, port, PEER, 10_000 + CLOSING),
                Err(Nat44TcpPlanError::SessionMiss)
            );
            // A repeated RST restarts the closing timer (not counted twice).
            reset(&mut runtime, 100_000);
            assert_eq!(probe(&runtime, port, PEER, 100_000 + CLOSING - 1), Ok(()));
            assert_eq!(runtime.counters().sessions_reset, 1);
            // Traffic restores the established phase and its TTL.
            inbound(&mut runtime, port, PEER, ACK, 200_000).unwrap();
            assert_eq!(
                runtime.sessions[session].phase(),
                Nat44TcpSessionPhase::Established
            );
            assert_eq!(runtime.counters().sessions_established, 2);
            assert_eq!(
                probe(&runtime, port, PEER, 200_000 + ESTABLISHED - 1),
                Ok(())
            );
            assert_eq!(runtime.mappings[mapping].expires_ms, 200_000 + ESTABLISHED);
        });
    }
}

/// A mapping never expires before any of its sessions: while another
/// session is established it keeps the established expiry when one
/// session closes, and it drops to the transitory TTL only when the last
/// established session closes.
#[test]
fn a_mapping_keeps_the_established_ttl_until_its_last_established_session_closes() {
    with_config(timer_policy(), 40_000, 40_000, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 1];
        let mut sessions = [Nat44TcpSessionSlot::default(); 3];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let (mapping, _) = handshake(&mut runtime, HOST, PEER, 0);
        let port = runtime.mappings[mapping].public_port;
        handshake(&mut runtime, HOST, PEER2, 0);
        assert_eq!(runtime.mappings[mapping].established_sessions, 2);

        out(&mut runtime, HOST, PEER, FIN_ACK, 1_000).unwrap();
        inbound(&mut runtime, port, PEER, FIN_ACK, 1_000).unwrap();
        // PEER2 is still established: the mapping keeps its established
        // expiry (from the last established commit, PEER's FIN at 1 s).
        assert_eq!(runtime.mappings[mapping].established_sessions, 1);
        assert_eq!(
            runtime.mappings[mapping].link.list,
            TcpMappingList::Established
        );
        assert_eq!(runtime.mappings[mapping].expires_ms, 1_000 + ESTABLISHED);
        assert_eq!(probe(&runtime, port, PEER2, ESTABLISHED - 1), Ok(()));

        out(&mut runtime, HOST, PEER2, FIN_ACK, 2_000).unwrap();
        inbound(&mut runtime, port, PEER2, FIN_ACK, 2_000).unwrap();
        assert_eq!(runtime.mappings[mapping].established_sessions, 0);
        assert_eq!(runtime.mappings[mapping].expires_ms, 2_000 + OPENING);
        assert_eq!(probe(&runtime, port, PEER2, 2_000 + CLOSING - 1), Ok(()));
        assert_eq!(
            probe(&runtime, port, PEER2, 2_000 + OPENING),
            Err(Nat44TcpPlanError::MappingMiss)
        );
    });
}

/// An expired established session reclaimed by another mapping leaves its
/// own mapping's established count (the index check compares every count
/// with a full scan), so that mapping drops to the transitory TTL when its
/// remaining established session closes.
#[test]
fn reclaiming_an_expired_established_session_releases_its_mapping_count() {
    with_config(timer_policy(), 40_000, 40_001, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 2];
        let mut sessions = [Nat44TcpSessionSlot::default(); 2];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let (a, first) = handshake(&mut runtime, HOST, PEER, 0);
        let port = runtime.mappings[a].public_port;
        handshake(&mut runtime, HOST, PEER2, ESTABLISHED - 1_000);
        assert_eq!(runtime.mappings[a].established_sessions, 2);

        let (b, reclaimed) =
            out(&mut runtime, (INTERNAL2, 40_001), PEER, SYN, ESTABLISHED).unwrap();
        assert_ne!(a, b);
        assert_eq!(reclaimed, first);
        assert_eq!(runtime.mappings[a].established_sessions, 1);
        assert_eq!(runtime.counters().sessions_expired_established, 1);

        let at = ESTABLISHED + 10;
        out(&mut runtime, HOST, PEER2, FIN_ACK, at).unwrap();
        inbound(&mut runtime, port, PEER2, FIN_ACK, at).unwrap();
        assert_eq!(runtime.mappings[a].established_sessions, 0);
        assert_eq!(runtime.mappings[a].expires_ms, at + OPENING);
    });
}

/// NAT44-041 with the phase timers: closed, reset, and never-completed
/// externally created sessions stop counting against the per-remote
/// inbound quota after the closing or opening TTL instead of 2h4m.
#[test]
fn the_inbound_quota_is_released_by_the_transitory_timers() {
    let policy = timer_policy()
        .with_filtering(Nat44Filtering::AddressDependent)
        .with_inbound_sessions_per_remote(2)
        .unwrap();
    with_config(policy, 40_000, 40_000, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 1];
        let mut sessions = [Nat44TcpSessionSlot::default(); 8];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        // The inside host talks to REMOTE1 (address-dependent admission).
        let (mapping, _) = handshake(&mut runtime, HOST, PEER, 0);
        let port = runtime.mappings[mapping].public_port;
        // Two external SYNs from REMOTE1: one completes and is reset, the
        // other is never answered by the remote (a spoofed SYN).
        let reset = (REMOTE1, 1_001);
        let spoofed = (REMOTE1, 1_002);
        inbound(&mut runtime, port, reset, SYN, 1).unwrap();
        inbound(&mut runtime, port, spoofed, SYN, 1).unwrap();
        out(&mut runtime, HOST, reset, SYN_ACK, 2).unwrap();
        out(&mut runtime, HOST, spoofed, SYN_ACK, 2).unwrap();
        inbound(&mut runtime, port, reset, ACK, 3).unwrap();
        inbound(&mut runtime, port, reset, RST, 10).unwrap();
        let quota = |runtime: &Nat44TcpRuntime<'_>, remote_port, now| {
            runtime
                .plan_inbound_read_only(port, REMOTE1, remote_port, seg(SYN), now)
                .map(|_| ())
        };
        assert_eq!(
            quota(&runtime, 1_003, 10 + CLOSING - 1),
            Err(Nat44TcpPlanError::InboundRemoteQuotaExceeded)
        );
        // The reset session expired: one slot of quota is free again.
        inbound(&mut runtime, port, (REMOTE1, 1_003), SYN, 10 + CLOSING).unwrap();
        assert_eq!(
            quota(&runtime, 1_004, 10 + CLOSING),
            Err(Nat44TcpPlanError::InboundRemoteQuotaExceeded)
        );
        // The spoofed SYN's session, answered only by the inside SYN-ACK,
        // stayed opening and expires after the opening TTL.
        assert_eq!(
            runtime
                .sessions
                .iter()
                .find(|session| session.remote_port == 1_002)
                .unwrap()
                .phase(),
            Nat44TcpSessionPhase::Opening
        );
        assert_eq!(
            quota(&runtime, 1_004, 2 + OPENING - 1),
            Err(Nat44TcpPlanError::InboundRemoteQuotaExceeded)
        );
        assert_eq!(quota(&runtime, 1_004, 2 + OPENING), Ok(()));
    });
}

/// RFC 5382 REQ-8 hairpinning: each half drives its own session, so the
/// hairpinned connection X1 -> P:x2' is established on both sides after
/// the handshake and closes on both after FIN in both directions.
#[test]
fn hairpin_halves_track_both_sessions() {
    with_config(timer_policy(), 40_000, 40_003, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 2];
        let mut sessions = [Nat44TcpSessionSlot::default(); 4];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let x1 = (INTERNAL, 40_001);
        let x2 = (INTERNAL2, 40_002);
        // X2's mapping exists (it talked to REMOTE1).
        let (m2, _) = out(&mut runtime, x2, PEER, SYN, 0).unwrap();
        let p2 = runtime.mappings[m2].public_port;
        // One hairpinned segment: outbound half on X1's mapping (remote
        // P:p2), then inbound half on X2's mapping (remote P:p1).
        let hairpin = |runtime: &mut Nat44TcpRuntime<'_>,
                       from: (Ipv4Address, u16),
                       to_port: u16,
                       flags: u8,
                       now: u64| {
            let outbound = runtime
                .plan_outbound(from.0, from.1, PUBLIC, to_port, seg(flags), now)
                .unwrap();
            runtime.prevalidate_outbound_commit(outbound, now).unwrap();
            runtime.commit_prevalidated_hairpin_outbound(outbound, now);
            let inbound = runtime
                .plan_hairpin_inbound(to_port, PUBLIC, outbound.public_port(), seg(flags), now)
                .unwrap();
            runtime.prevalidate_inbound_commit(inbound, now).unwrap();
            runtime.commit_prevalidated_hairpin_inbound(inbound, now);
            assert_eq!(runtime.validate_indexes(), Ok(()));
            (
                outbound.session_index(),
                inbound.session_index,
                outbound.public_port(),
            )
        };
        let (s1, s2, p1) = hairpin(&mut runtime, x1, p2, SYN, 1);
        assert_eq!(hairpin(&mut runtime, x2, p1, SYN_ACK, 2).0, s2);
        hairpin(&mut runtime, x1, p2, ACK, 3);
        for session in [s1, s2] {
            assert_eq!(
                runtime.sessions[session].phase(),
                Nat44TcpSessionPhase::Established
            );
            assert!(!runtime.sessions[session].external_inbound);
        }
        hairpin(&mut runtime, x1, p2, FIN_ACK, 4);
        hairpin(&mut runtime, x2, p1, FIN_ACK, 5);
        for session in [s1, s2] {
            assert_eq!(
                runtime.sessions[session].phase(),
                Nat44TcpSessionPhase::Closing
            );
        }
        assert!(runtime.session_is_live(runtime.sessions[s1], 5 + CLOSING - 1));
        assert!(!runtime.session_is_live(runtime.sessions[s1], 5 + CLOSING));
    });
}

/// Seeded churn of every segment kind (SYN, SYN-ACK, ACK, FIN, RST, both
/// directions) and time steps around every TTL on small tables, checked
/// after every plan against a full-scan reference over the slots: a plan
/// translates exactly when a live exact session (or, for an initial SYN,
/// the slots it needs) exists, fails as full exactly when no slot is
/// reusable, and the index check (exact established counts, every mapping
/// outliving its sessions, the phase and expiry order of every activity
/// list) holds after every commit. The reference shares only the slot
/// liveness predicates with the runtime; the list-head searches under test
/// do not appear in it.
#[test]
fn mixed_phase_reuse_matches_a_full_scan_reference_under_seeded_churn() {
    const FLAGS: [u8; 8] = [SYN, SYN, SYN_ACK, ACK, ACK, FIN_ACK, RST, RST_ACK];
    let mut outcomes = [0_usize; 8];
    for seed in 0..48_u64 {
        let policy = timer_policy();
        with_config(policy, 40_000, 40_003, |config| {
            let mut mappings = vec![Nat44TcpMappingSlot::default(); 3 + 2 * (seed as usize % 2)];
            let mut sessions = vec![Nat44TcpSessionSlot::default(); 4 + seed as usize % 3];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let mut rng = seed ^ 0x005e_ed0f_71e5;
            let mut now = 0;
            for _ in 0..400 {
                now += match next_random(&mut rng) % 12 {
                    0 => ESTABLISHED,
                    1 => ESTABLISHED / 2,
                    2 => OPENING,
                    3 => CLOSING,
                    4 => CLOSING / 2,
                    5..=7 => 1_000,
                    _ => 0,
                };
                let flags = FLAGS[(next_random(&mut rng) % 8) as usize];
                let segment = seg(flags);
                let remote = (
                    [REMOTE1, REMOTE2][(next_random(&mut rng) % 2) as usize],
                    1 + (next_random(&mut rng) % 3) as u16,
                );
                let session_available = (0..runtime.sessions.len())
                    .any(|index| runtime.session_slot_reusable(index, now));
                // Full scan: the live mapping and live exact session of a
                // tuple, by slot contents alone.
                let live_session = |runtime: &Nat44TcpRuntime<'_>, mapping: usize| {
                    let owner = runtime.mappings[mapping];
                    runtime.sessions.iter().any(|session| {
                        session.occupied
                            && session.mapping_index == mapping
                            && session.mapping_generation == owner.generation
                            && session.mapping_lifecycle_epoch == owner.lifecycle_epoch
                            && (session.remote_address, session.remote_port) == remote
                            && runtime.session_is_live(*session, now)
                    })
                };
                if next_random(&mut rng).is_multiple_of(3) {
                    let public_port = 40_000 + (next_random(&mut rng) % 4) as u16;
                    let live_mapping = (0..runtime.mappings.len()).find(|&index| {
                        let mapping = runtime.mappings[index];
                        mapping.port_owned
                            && mapping.public_port == public_port
                            && runtime.mapping_is_live(mapping, now)
                    });
                    let exact = live_mapping.is_some_and(|index| live_session(&runtime, index));
                    match runtime.plan_inbound(public_port, remote.0, remote.1, segment, now) {
                        Ok(plan) => {
                            assert!(live_mapping.is_some());
                            assert_eq!(plan.session_created, !exact);
                            assert!(exact || (segment.is_initial_syn() && session_available));
                            runtime.commit_inbound(plan, now).unwrap();
                            outcomes[0] += 1;
                        }
                        Err(Nat44TcpPlanError::MappingMiss) => assert!(live_mapping.is_none()),
                        Err(Nat44TcpPlanError::SessionMiss) => {
                            assert!(live_mapping.is_some() && !exact && !segment.is_initial_syn());
                            outcomes[1] += 1;
                        }
                        Err(Nat44TcpPlanError::SessionFull) => {
                            assert!(live_mapping.is_some() && !exact && !session_available);
                            outcomes[2] += 1;
                        }
                        Err(error) => panic!("unexpected inbound {error:?}"),
                    }
                } else {
                    let host = (
                        Ipv4Address::from_octets([
                            10,
                            0,
                            0,
                            10 + (next_random(&mut rng) % 5) as u8,
                        ]),
                        39_999 + (next_random(&mut rng) % 6) as u16,
                    );
                    let live_mapping = (0..runtime.mappings.len()).find(|&index| {
                        let mapping = runtime.mappings[index];
                        mapping.occupied
                            && (mapping.internal_address, mapping.internal_port) == host
                            && runtime.mapping_is_live(mapping, now)
                    });
                    let exact = live_mapping.is_some_and(|index| live_session(&runtime, index));
                    let mapping_available = runtime
                        .mappings
                        .iter()
                        .any(|mapping| !runtime.mapping_is_live(*mapping, now));
                    match runtime.plan_outbound(host.0, host.1, remote.0, remote.1, segment, now) {
                        Ok(plan) => {
                            assert_eq!(plan.session_created, !exact);
                            assert_eq!(plan.mapping_created, live_mapping.is_none());
                            assert!(exact || segment.is_initial_syn());
                            runtime.commit_outbound(plan, now).unwrap();
                            outcomes[3 + usize::from(plan.mapping_created)] += 1;
                        }
                        Err(Nat44TcpPlanError::InvalidInitialFlags) => {
                            assert!(!exact && !segment.is_initial_syn());
                            outcomes[5] += 1;
                        }
                        Err(Nat44TcpPlanError::SessionFull) => {
                            assert!(!exact && segment.is_initial_syn() && !session_available);
                            outcomes[6] += 1;
                        }
                        Err(Nat44TcpPlanError::MappingFull) => {
                            assert!(live_mapping.is_none() && !mapping_available);
                            outcomes[7] += 1;
                        }
                        Err(Nat44TcpPlanError::PortExhausted) => {
                            assert!(live_mapping.is_none() && mapping_available);
                        }
                        Err(error) => panic!("unexpected outbound {error:?}"),
                    }
                }
                assert_eq!(runtime.validate_indexes(), Ok(()));
            }
        });
    }
    // Every outcome the reference distinguishes was exercised.
    assert!(outcomes.iter().all(|count| *count > 0), "{outcomes:?}");
}

/// PERF-001 with the phase timers: a 65536-slot table with every public
/// port owned and sessions spread over all three phases (established,
/// closed, opening) still finds each new flow's mapping, session, and port
/// with at most four mapping list-head checks, three session list-head
/// checks, two port owners, and 34 bitmap words, whichever list holds the
/// expired slots.
#[test]
fn new_flow_work_stays_constant_with_sessions_in_every_phase() {
    const SLOTS: usize = 65_536;
    const GROUP: usize = 21_845;
    let policy = Nat44TcpPolicy::new(ESTABLISHED, 0x5eed_1234_5678_9abc)
        .unwrap()
        .with_filtering(Nat44Filtering::EndpointIndependent);
    let transitory = policy.opening_idle_ttl_ms();
    with_config(policy, 1, 65_535, |config| {
        let mut mappings = vec![Nat44TcpMappingSlot::default(); SLOTS];
        let mut sessions = vec![Nat44TcpSessionSlot::default(); SLOTS];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let host = |flow: usize| {
            (
                Ipv4Address::from_octets([
                    10,
                    1 + (flow >> 16) as u8,
                    (flow >> 8) as u8,
                    flow as u8,
                ]),
                7,
            )
        };
        let segment =
            |runtime: &mut Nat44TcpRuntime<'_>, flow: usize, inbound: bool, flags, now| {
                if inbound {
                    let port = runtime
                        .find_mapping(host(flow).0, 7)
                        .unwrap()
                        .unwrap()
                        .1
                        .public_port;
                    let plan = runtime
                        .plan_inbound(port, REMOTE1, 443, seg(flags), now)
                        .unwrap();
                    runtime.commit_inbound(plan, now).unwrap();
                } else {
                    let plan = runtime
                        .plan_outbound(host(flow).0, 7, REMOTE1, 443, seg(flags), now)
                        .unwrap();
                    runtime.commit_outbound(plan, now).unwrap();
                }
            };
        // [mapping checks, session checks, port owners, bitmap words]
        let mut worst = [0_usize; 4];
        let mut new_flow = |runtime: &mut Nat44TcpRuntime<'_>, flow: usize, now: u64| {
            runtime.reset_index_probe_counts();
            let result = runtime.plan_outbound(host(flow).0, 7, REMOTE1, 443, seg(SYN), now);
            let (_, _, mapping_checks, session_checks, owner_probes) = runtime.index_probe_counts();
            let words = runtime.port_owners.take_bitmap_word_reads();
            for (worst, seen) in
                worst
                    .iter_mut()
                    .zip([mapping_checks, session_checks, owner_probes, words])
            {
                *worst = (*worst).max(seen);
            }
            let plan = result?;
            runtime.commit_outbound(plan, now).unwrap();
            Ok::<u16, Nat44TcpPlanError>(plan.mapping.public_port)
        };
        // Established at 0, then 1000 closed (FIN both ways) at 0, then
        // opening at 1 s.
        let closed = 65_535 - GROUP - 1_000;
        for flow in 0..65_535 - GROUP {
            new_flow(&mut runtime, flow, 0).unwrap();
            segment(&mut runtime, flow, true, SYN_ACK, 0);
            segment(&mut runtime, flow, false, ACK, 0);
            if flow >= closed {
                segment(&mut runtime, flow, false, FIN_ACK, 0);
                segment(&mut runtime, flow, true, FIN_ACK, 0);
            }
        }
        for flow in 65_535 - GROUP..65_535 {
            new_flow(&mut runtime, flow, 1_000).unwrap();
        }
        assert_eq!(
            new_flow(&mut runtime, 65_535, 1_000),
            Err(Nat44TcpPlanError::PortExhausted)
        );
        // At the transitory TTL the closed group has expired: new flows
        // take its mappings (transitory list), sessions (closing list), and
        // ports while the established and opening heads stay live.
        for flow in 65_536..66_536 {
            assert_ne!(new_flow(&mut runtime, flow, transitory).unwrap(), 0);
        }
        assert_eq!(
            new_flow(&mut runtime, 66_536, transitory),
            Err(Nat44TcpPlanError::PortExhausted)
        );
        // One second later the opening group has expired: new flows take
        // its mappings and sessions (opening list).
        for flow in 66_537..67_537 {
            assert_ne!(new_flow(&mut runtime, flow, transitory + 1_000).unwrap(), 0);
        }
        let counters = runtime.counters();
        assert_eq!(counters.mappings_expired, 2_000);
        assert_eq!(counters.sessions_expired_closing, 1_000);
        assert_eq!(counters.sessions_expired_opening, 1_000);
        assert_eq!(counters.sessions_expired_established, 0);
        assert!(runtime.reuse_lists_are_consistent());
        assert!(runtime.port_owners.bitmap_matches_slots());
        assert!(
            worst[0] <= 4 && worst[1] <= 3 && worst[2] <= 2 && worst[3] <= 34,
            "work per new flow {worst:?}"
        );
    });
}
