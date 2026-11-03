//! N6: the per-internal-host session limit of the TCP NAT (NAT44-119, RFC
//! 6888 REQ-5), and the half-close fix of the host-driven expiry
//! (NAT44-096). A child of `nat44::tcp_tests`, sharing its helpers.

use std::collections::HashMap;

use super::*;

const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;
const FIN: u8 = 0x01;
const FIN_ACK: u8 = 0x11;
const RST: u8 = 0x04;
const TRANSITORY: u64 = NAT44_TCP_DEFAULT_TRANSITORY_IDLE_TTL_MS;
const ESTABLISHED: u64 = NAT44_TCP_DEFAULT_IDLE_TTL_MS;

fn session_policy(limit: u16) -> Nat44TcpPolicy {
    Nat44TcpPolicy::default()
        .with_filtering(Nat44Filtering::EndpointIndependent)
        .with_sessions_per_host(limit)
}

fn seg(flags: u8) -> Nat44TcpSegment {
    Nat44TcpSegment::from_flags(flags)
}

fn out(
    runtime: &mut Nat44TcpRuntime<'_>,
    internal: (Ipv4Address, u16),
    remote: (Ipv4Address, u16),
    flags: u8,
    now: u64,
) -> Result<Nat44TcpOutboundPlan, Nat44TcpPlanError> {
    let plan = runtime
        .plan_outbound(internal.0, internal.1, remote.0, remote.1, seg(flags), now)
        .inspect_err(|error| runtime.record_plan_error(*error))?;
    runtime.commit_outbound(plan, now).unwrap();
    Ok(plan)
}

fn inbound(
    runtime: &mut Nat44TcpRuntime<'_>,
    public_port: u16,
    remote: (Ipv4Address, u16),
    flags: u8,
    now: u64,
) -> Result<Nat44TcpInboundPlan, Nat44TcpPlanError> {
    let plan = runtime.plan_inbound(public_port, remote.0, remote.1, seg(flags), now)?;
    runtime.commit_inbound(plan, now).unwrap();
    Ok(plan)
}

fn session_count(runtime: &Nat44TcpRuntime<'_>, address: Ipv4Address) -> usize {
    runtime
        .session_hosts
        .find(address)
        .unwrap()
        .map_or(0, |host| runtime.session_hosts.count(host))
}

fn remote(index: usize) -> (Ipv4Address, u16) {
    (
        Ipv4Address::from_octets([198, 51, 100, 20 + (index / 1000) as u8]),
        443 + (index % 1000) as u16,
    )
}

/// At the limit a new host-initiated session is refused before any state
/// changes, on an existing mapping and for a new one alike, nothing is
/// evicted, and the host's existing sessions keep working. Sessions that
/// inbound SYNs create never count, so a remote cannot spend the host's
/// budget; another host keeps its own.
#[test]
fn tcp_host_session_quota_refuses_without_state_change_and_ignores_inbound_sessions() {
    with_config(session_policy(2), 40_000, 40_063, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 8];
        let mut sessions = [Nat44TcpSessionSlot::default(); 32];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let first = out(&mut runtime, (INTERNAL, 1_000), remote(0), SYN, 0).unwrap();
        out(&mut runtime, (INTERNAL, 1_000), remote(1), SYN, 0).unwrap();
        assert_eq!(session_count(&runtime, INTERNAL), 2);
        // Twenty strangers open connections to the host's public port; its
        // stack accepts them. They do not count.
        for index in 0..20 {
            let stranger = (REMOTE2, 30_000 + index);
            inbound(&mut runtime, first.public_port(), stranger, SYN, 10).unwrap();
            out(&mut runtime, (INTERNAL, 1_000), stranger, SYN_ACK, 10).unwrap();
            inbound(&mut runtime, first.public_port(), stranger, ACK, 10).unwrap();
        }
        assert_eq!(session_count(&runtime, INTERNAL), 2);
        let mappings_before = runtime.mappings.to_vec();
        let sessions_before = runtime.sessions.to_vec();
        for (port, peer) in [(1_000, remote(2)), (1_001, remote(0)), (1_002, remote(3))] {
            assert_eq!(
                out(&mut runtime, (INTERNAL, port), peer, SYN, 20).map(|_| ()),
                Err(Nat44TcpPlanError::HostSessionQuotaExceeded),
                "port {port}"
            );
        }
        assert_eq!(runtime.counters().host_session_quota_exceeded, 3);
        assert_eq!(runtime.counters().session_full, 0);
        assert_eq!(runtime.mappings, &mappings_before[..]);
        assert_eq!(runtime.sessions, &sessions_before[..]);
        // Existing sessions: the handshake completes and data flows.
        inbound(&mut runtime, first.public_port(), remote(0), SYN_ACK, 30).unwrap();
        out(&mut runtime, (INTERNAL, 1_000), remote(0), ACK, 30).unwrap();
        // Another host has its own budget.
        out(&mut runtime, (INTERNAL2, 1_000), remote(0), SYN, 40).unwrap();
        out(&mut runtime, (INTERNAL2, 1_001), remote(0), SYN, 40).unwrap();
        assert_eq!(
            out(&mut runtime, (INTERNAL2, 1_002), remote(0), SYN, 40).map(|_| ()),
            Err(Nat44TcpPlanError::HostSessionQuotaExceeded)
        );
        assert_eq!(session_count(&runtime, INTERNAL), 2);
        assert_eq!(session_count(&runtime, INTERNAL2), 2);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// A host recovers as soon as it stops driving one of its sessions for the
/// session's timeout: a SYN the remote never answers counts for the opening
/// timeout, an established connection the remote keeps alive by itself for
/// the established one. The new session is admitted and the old one stops
/// counting; the old session itself is not ended (only the remote keeps the
/// established one alive), so nothing live is evicted.
#[test]
fn tcp_host_session_quota_recovers_when_the_host_stops_driving_a_session() {
    with_config(session_policy(1), 40_000, 40_063, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 8];
        let mut sessions = [Nat44TcpSessionSlot::default(); 16];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let opening = out(&mut runtime, (INTERNAL, 1_000), remote(0), SYN, 0).unwrap();
        assert_eq!(
            out(
                &mut runtime,
                (INTERNAL, 1_001),
                remote(1),
                SYN,
                TRANSITORY - 1
            )
            .map(|_| ()),
            Err(Nat44TcpPlanError::HostSessionQuotaExceeded)
        );
        let next = out(&mut runtime, (INTERNAL, 1_001), remote(1), SYN, TRANSITORY).unwrap();
        assert_eq!(next.host_session_reclaim(), Some(opening.session_index()));
        assert_eq!(session_count(&runtime, INTERNAL), 1);
        assert_eq!(runtime.validate_indexes(), Ok(()));

        // An established connection that only the remote keeps alive.
        let now = TRANSITORY;
        inbound(&mut runtime, next.public_port(), remote(1), SYN_ACK, now).unwrap();
        out(&mut runtime, (INTERNAL, 1_001), remote(1), ACK, now).unwrap();
        let mut at = now;
        while at + 600_000 < now + ESTABLISHED {
            at += 600_000;
            inbound(&mut runtime, next.public_port(), remote(1), ACK, at).unwrap();
            assert_eq!(
                out(&mut runtime, (INTERNAL, 1_002), remote(2), SYN, at).map(|_| ()),
                Err(Nat44TcpPlanError::HostSessionQuotaExceeded)
            );
        }
        let later = now + ESTABLISHED;
        inbound(&mut runtime, next.public_port(), remote(1), ACK, later).unwrap();
        let admitted = out(&mut runtime, (INTERNAL, 1_002), remote(2), SYN, later).unwrap();
        assert_eq!(admitted.host_session_reclaim(), Some(next.session_index()));
        // The remote-kept session stays: live, established, uncounted.
        let kept = runtime.sessions[next.session_index()];
        assert!(runtime.session_is_live(kept, later));
        assert_eq!(kept.phase(), Nat44TcpSessionPhase::Established);
        assert_eq!(session_count(&runtime, INTERNAL), 1);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// NAT44-096 fix: once the inside host has sent a FIN on an established
/// connection (a half-close), its own later segments refresh the mapping's
/// and the session's host-driven expiry with the transitory timeout. A
/// server that never sends its FIN and keeps the connection established by
/// itself can then hold the host's quotas for 4 minutes after the host's
/// last segment, not for the established timeout (2 h 4 min). A host that
/// still reads the half-closed connection keeps it counted with each ACK.
#[test]
fn a_half_closed_connection_counts_only_for_the_transitory_timeout() {
    let policy = session_policy(1).with_mappings_per_host(1);
    let server = remote(0);
    let open_and_half_close = |runtime: &mut Nat44TcpRuntime<'_>| {
        let first = out(runtime, (INTERNAL, 1_000), server, SYN, 0).unwrap();
        inbound(runtime, first.public_port(), server, SYN_ACK, 0).unwrap();
        out(runtime, (INTERNAL, 1_000), server, ACK, 0).unwrap();
        out(runtime, (INTERNAL, 1_000), server, FIN_ACK, 0).unwrap();
        first
    };
    // The server never sends its FIN and keeps sending; the host's stack
    // stays silent (its FIN-WAIT-2 timer ends the socket).
    with_config(policy, 40_000, 40_063, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 8];
        let mut sessions = [Nat44TcpSessionSlot::default(); 16];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let first = open_and_half_close(&mut runtime);
        inbound(&mut runtime, first.public_port(), server, ACK, 200_000).unwrap();
        assert_eq!(
            out(
                &mut runtime,
                (INTERNAL, 1_001),
                remote(1),
                SYN,
                TRANSITORY - 1
            )
            .map(|_| ()),
            Err(Nat44TcpPlanError::HostQuotaExceeded)
        );
        let mut now = 200_000;
        while now < 2_400_000 {
            now += 200_000;
            inbound(&mut runtime, first.public_port(), server, ACK, now).unwrap();
        }
        let session = runtime.sessions[first.session_index()];
        assert_eq!(session.phase(), Nat44TcpSessionPhase::Established);
        assert!(runtime.session_is_live(session, now));
        let fresh = out(&mut runtime, (INTERNAL, 1_001), remote(1), SYN, now).unwrap();
        assert_eq!(fresh.host_session_reclaim(), Some(first.session_index()));
        assert_eq!(fresh.mapping_index(), first.mapping_index());
        assert_eq!(runtime.counters().host_quota_exceeded, 1);
        assert_eq!(runtime.counters().host_session_quota_exceeded, 0);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
    // The host keeps reading: each of its ACKs refreshes for 4 minutes.
    with_config(policy, 40_000, 40_063, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 8];
        let mut sessions = [Nat44TcpSessionSlot::default(); 16];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let first = open_and_half_close(&mut runtime);
        let mut now = 0;
        while now < 2_400_000 {
            now += 200_000;
            inbound(&mut runtime, first.public_port(), server, ACK, now).unwrap();
            out(&mut runtime, (INTERNAL, 1_000), server, ACK, now).unwrap();
            // A second SYN of the same mapping (another remote) is a new
            // session: refused by the session limit.
            assert_eq!(
                out(&mut runtime, (INTERNAL, 1_000), remote(1), SYN, now).map(|_| ()),
                Err(Nat44TcpPlanError::HostSessionQuotaExceeded)
            );
            assert_eq!(
                out(&mut runtime, (INTERNAL, 1_001), remote(1), SYN, now).map(|_| ()),
                Err(Nat44TcpPlanError::HostQuotaExceeded)
            );
        }
        // Silent from here: both quotas free after the transitory timeout.
        assert_eq!(
            out(
                &mut runtime,
                (INTERNAL, 1_001),
                remote(1),
                SYN,
                now + TRANSITORY - 1
            )
            .map(|_| ()),
            Err(Nat44TcpPlanError::HostQuotaExceeded)
        );
        out(
            &mut runtime,
            (INTERNAL, 1_001),
            remote(1),
            SYN,
            now + TRANSITORY,
        )
        .unwrap();
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// The session analogue of the N3 review M1 re-check: the remote of one of
/// the victim's own connections keeps sending on the original 4-tuple every
/// 200 s for 2400 s, and the victim's stack answers with a segment that
/// leaves the session closing (a RST, or an ACK from TIME-WAIT). That is
/// not host-driven, so at a session limit of 1 the victim's new connection
/// is admitted after the transitory timeout, while the remote keeps the old
/// session alive. Same five variants as the mapping quota's test.
#[test]
fn a_remote_answered_on_the_old_tuple_cannot_pin_the_session_budget() {
    type Variant<'a> = (&'a [(bool, u8)], u8, u8);
    let attacker = (REMOTE1, 443);
    let victim = (INTERNAL, 1_000);
    let variants: [Variant<'_>; 5] = [
        (
            &[
                (true, SYN),
                (false, SYN_ACK),
                (true, ACK),
                (false, FIN | ACK),
                (true, FIN | ACK),
                (false, ACK),
            ],
            ACK,
            RST,
        ),
        (&[(true, SYN)], SYN_ACK, RST),
        (
            &[
                (true, SYN),
                (false, SYN_ACK),
                (true, ACK),
                (true, FIN | ACK),
                (false, FIN | ACK),
                (true, ACK),
            ],
            SYN,
            RST,
        ),
        (
            &[
                (true, SYN),
                (false, SYN_ACK),
                (true, ACK),
                (true, FIN | ACK),
                (false, FIN | ACK),
                (true, ACK),
            ],
            ACK,
            ACK,
        ),
        (
            &[(true, SYN), (false, SYN_ACK), (true, ACK), (true, RST)],
            ACK,
            RST,
        ),
    ];
    for (index, (setup, remote_flags, answer)) in variants.into_iter().enumerate() {
        with_config(session_policy(1), 40_000, 40_063, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 8];
            let mut sessions = [Nat44TcpSessionSlot::default(); 16];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let first = out(&mut runtime, victim, attacker, SYN, 0).unwrap();
            for (outbound, flags) in setup.iter().skip(1).copied() {
                if outbound {
                    out(&mut runtime, victim, attacker, flags, 0).unwrap();
                } else {
                    inbound(&mut runtime, first.public_port(), attacker, flags, 0).unwrap();
                }
            }
            let mut now = 0;
            while now < 2_400_000 {
                now += 200_000;
                inbound(
                    &mut runtime,
                    first.public_port(),
                    attacker,
                    remote_flags,
                    now,
                )
                .unwrap_or_else(|error| panic!("variant {index}: {error:?}"));
                out(&mut runtime, victim, attacker, answer, now)
                    .unwrap_or_else(|error| panic!("variant {index}: {error:?}"));
            }
            assert!(
                runtime.session_is_live(runtime.sessions[first.session_index()], now),
                "variant {index}"
            );
            assert!(
                !runtime.session_is_host_live(first.session_index(), now),
                "variant {index}"
            );
            let fresh = out(&mut runtime, (INTERNAL, 2_000), (REMOTE2, 80), SYN, now)
                .unwrap_or_else(|error| panic!("variant {index}: {error:?}"));
            assert_eq!(
                fresh.host_session_reclaim(),
                Some(first.session_index()),
                "variant {index}"
            );
            assert_eq!(
                runtime.counters().host_session_quota_exceeded,
                0,
                "variant {index}"
            );
            assert_eq!(runtime.validate_indexes(), Ok(()), "variant {index}");
        });
    }
}

/// Slot reuse, mapping recreation, and flush keep the count exact: a
/// counted session whose slot another session takes stops counting; a
/// counted session of a mapping the N3 quota reclaims (remote-kept) is past
/// its host-driven expiry and is the next to stop counting; a flush forgets
/// every count.
#[test]
fn reuse_recreation_and_flush_release_a_hosts_sessions() {
    let policy = session_policy(2).with_mappings_per_host(1);
    with_config(policy, 40_000, 40_063, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 4];
        let mut sessions = [Nat44TcpSessionSlot::default(); 3];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let first = out(&mut runtime, (INTERNAL, 1_000), remote(0), SYN, 0).unwrap();
        // A stranger keeps the mapping (not the host's session) alive.
        inbound(
            &mut runtime,
            first.public_port(),
            (REMOTE2, 7),
            SYN,
            100_000,
        )
        .unwrap();
        assert_eq!(session_count(&runtime, INTERNAL), 1);
        // The host's expired opening session is the reused slot of another
        // host's new session (expired slots before never-used ones).
        let other = out(&mut runtime, (INTERNAL2, 1_000), remote(0), SYN, TRANSITORY).unwrap();
        assert_eq!(other.session_index(), first.session_index());
        assert_eq!(session_count(&runtime, INTERNAL), 0);
        assert_eq!(session_count(&runtime, INTERNAL2), 1);
        assert_eq!(runtime.validate_indexes(), Ok(()));
        // The N3 quota reclaims INTERNAL's remote-kept mapping (past its
        // host-driven expiry); the stranger's session on it is stale and
        // never counted.
        let now = 100_000 + TRANSITORY - 1;
        let pinned = runtime.mappings[first.mapping_index()];
        assert!(runtime.mapping_is_live(pinned, now) && !runtime.mapping_is_host_live(pinned, now));
        let next = out(&mut runtime, (INTERNAL, 1_001), remote(1), SYN, now).unwrap();
        assert_eq!(next.mapping_index(), first.mapping_index());
        assert_eq!(session_count(&runtime, INTERNAL), 1);
        assert_eq!(runtime.validate_indexes(), Ok(()));
        runtime
            .reconcile(config, rotated_test_tcp_hash_key())
            .unwrap();
        assert_eq!(session_count(&runtime, INTERNAL), 0);
        assert_eq!(session_count(&runtime, INTERNAL2), 0);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// The per-slot reference of the churn test: for each session slot the
/// host initiated (an outbound initial SYN created or restarted it), the
/// internal address, the time of the host's last host-driven segment on it,
/// and whether it counts.
type Reference = HashMap<usize, (Ipv4Address, u64, bool)>;

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Seeded churn of several hosts' connections (outbound SYN, ACK, FIN, RST,
/// inbound answers, and strangers' inbound SYNs) against small tables,
/// checked after every segment against a reference the test keeps from the
/// segments it sends (not from the runtime's lists): which session slots
/// an outbound initial SYN created, and when the host last sent a segment
/// that is host-driven by the rule (outbound, not leaving the session
/// closing, on a session the host opened or an established one). With all
/// three idle timeouts equal the reference's host-driven expiry is simply
/// that time plus the timeout:
///
/// - a new host-initiated session is refused as `HostSessionQuotaExceeded`
///   only when the reference finds at least `limit` of the host's counted
///   sessions within their host-driven expiry, and a created one was
///   admitted only below that; the session that stops counting is one the
///   reference counts and finds past that expiry;
/// - each host's count equals the reference's and never exceeds the limit;
/// - the full index validation holds (lists in expiry order, the expiry
///   never past the session's own, recreated mappings' sessions past it).
#[test]
fn tcp_host_session_quota_matches_a_reference_of_host_driven_activity_under_seeded_churn() {
    const LIMIT: u16 = 3;
    const TTL: u64 = NAT44_TCP_MIN_IDLE_TTL_MS;
    let mut outcomes = [0_usize; 6];
    for seed in 1..=16_u64 {
        let hosts = if seed % 4 == 0 { 8 } else { 3 };
        let filtering = if seed % 2 == 0 {
            Nat44Filtering::EndpointIndependent
        } else {
            Nat44Filtering::AddressDependent
        };
        let policy = Nat44TcpPolicy::new(TTL, seed)
            .unwrap()
            .with_opening_idle_ttl_ms(TTL)
            .unwrap()
            .with_closing_idle_ttl_ms(TTL)
            .unwrap()
            .with_filtering(filtering)
            .with_sessions_per_host(LIMIT)
            .with_mappings_per_host(if seed % 3 == 0 { 2 } else { 0 });
        with_config(policy, 40_000, 40_015, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 8];
            let mut sessions = [Nat44TcpSessionSlot::default(); 12];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let mut reference = Reference::new();
            let mut random = seed;
            let mut now = 0_u64;
            for _ in 0..2_500 {
                now += next_random(&mut random) % (TTL / 5);
                let address =
                    Ipv4Address::from_octets([10, 0, 1, (next_random(&mut random) % hosts) as u8]);
                let port = 40_000 + (next_random(&mut random) % 3) as u16;
                let peer = remote((next_random(&mut random) % 3) as usize);
                let flags =
                    [SYN, SYN, ACK, FIN_ACK, RST, SYN_ACK][(next_random(&mut random) % 6) as usize];
                let host_live = |reference: &Reference| {
                    reference
                        .values()
                        .filter(|(owner, last, counted)| {
                            *owner == address && *counted && now < last + TTL
                        })
                        .count()
                };
                let live = host_live(&reference);
                match runtime
                    .plan_outbound(address, port, peer.0, peer.1, seg(flags), now)
                    .inspect_err(|error| runtime.record_plan_error(*error))
                {
                    Err(Nat44TcpPlanError::HostSessionQuotaExceeded) => {
                        assert!(live >= usize::from(LIMIT), "seed {seed}");
                        outcomes[0] += 1;
                    }
                    Err(_) => outcomes[1] += 1,
                    Ok(plan) => {
                        if plan.session_created || plan.session_recount {
                            assert!(live < usize::from(LIMIT), "seed {seed}");
                            outcomes[2] += 1;
                        }
                        if plan.session_recount {
                            outcomes[5] += 1;
                        }
                        if let Some(index) = plan.host_session_reclaim() {
                            let entry = reference.get_mut(&index).expect("host-initiated");
                            assert!(entry.0 == address && entry.2, "seed {seed}");
                            assert!(now >= entry.1 + TTL, "seed {seed}");
                            entry.2 = false;
                            outcomes[3] += 1;
                        }
                        runtime.commit_outbound(plan, now).unwrap();
                        let index = plan.session_index();
                        let session = runtime.sessions[index];
                        if plan.session_created {
                            reference.insert(index, (address, now, true));
                        } else if !session.is_host_initiated() {
                            // A restart the remote opened.
                            reference.remove(&index);
                        } else {
                            let established = session.phase() == Nat44TcpSessionPhase::Established;
                            if session.phase() != Nat44TcpSessionPhase::Closing
                                && (!session.is_external_inbound() || established)
                            {
                                // Host-driven: counted again if it was not.
                                let entry = reference.entry(index).or_insert((address, now, false));
                                entry.1 = now;
                                assert!(entry.2 || plan.session_recount, "seed {seed}");
                                entry.2 = true;
                            }
                        }
                    }
                }
                // Remotes answer, and strangers send SYNs to public ports.
                if next_random(&mut random).is_multiple_of(2) {
                    let public = runtime
                        .find_mapping(address, port)
                        .unwrap()
                        .map(|(_, mapping)| mapping.public_port);
                    let stranger = (REMOTE2, 1_024 + (next_random(&mut random) % 4) as u16);
                    let (from, flags) = if next_random(&mut random).is_multiple_of(3) {
                        (stranger, SYN)
                    } else {
                        (
                            peer,
                            [SYN_ACK, ACK, FIN_ACK, RST][(next_random(&mut random) % 4) as usize],
                        )
                    };
                    if let Some(public) = public {
                        if let Ok(plan) = inbound(&mut runtime, public, from, flags, now) {
                            if plan.session_created {
                                reference.remove(&plan.session_index);
                                outcomes[4] += 1;
                            }
                        }
                    }
                }
                for index in 0..hosts {
                    let address = Ipv4Address::from_octets([10, 0, 1, index as u8]);
                    let counted = reference
                        .values()
                        .filter(|(owner, _, counted)| *owner == address && *counted)
                        .count();
                    assert_eq!(session_count(&runtime, address), counted, "seed {seed}");
                    assert!(counted <= usize::from(LIMIT), "seed {seed}");
                }
                // Every host-initiated session the host drives counts.
                for (owner, last, counted) in reference.values() {
                    assert!(*counted || now >= last + TTL, "seed {seed} {owner:?}");
                }
                assert_eq!(runtime.validate_indexes(), Ok(()), "seed {seed}");
            }
        });
    }
    assert!(outcomes.iter().all(|count| *count > 0), "{outcomes:?}");
}

/// The same churn with the default (unequal) timeouts, the half-close rule,
/// and the mapping quota on: the count follows the reference of which slots
/// outbound SYNs created or counted again (less those the runtime stopped
/// counting, each past its host-driven expiry, and remote-opened restarts),
/// never exceeds the limit, and a refusal
/// means every counted session of the host is live and of its mapping's
/// generation (host-driven liveness implies liveness).
#[test]
fn tcp_host_session_quota_stays_consistent_with_unequal_timeouts() {
    const LIMIT: u16 = 2;
    let mut outcomes = [0_usize; 3];
    for seed in 1..=16_u64 {
        let policy = session_policy(LIMIT)
            .with_mappings_per_host(if seed % 2 == 0 { 2 } else { 0 })
            .with_closing_idle_ttl_ms(TRANSITORY + 60_000 * (seed % 3))
            .unwrap();
        with_config(policy, 40_000, 40_015, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 8];
            let mut sessions = [Nat44TcpSessionSlot::default(); 12];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let mut counted: HashMap<usize, Ipv4Address> = HashMap::new();
            let mut random = seed;
            let mut now = 0_u64;
            for _ in 0..2_500 {
                now += next_random(&mut random) % (TRANSITORY / 3);
                let address =
                    Ipv4Address::from_octets([10, 0, 1, (next_random(&mut random) % 3) as u8]);
                let port = 40_000 + (next_random(&mut random) % 3) as u16;
                let peer = remote((next_random(&mut random) % 3) as usize);
                let flags = [SYN, SYN, ACK, FIN_ACK, RST][(next_random(&mut random) % 5) as usize];
                match out(&mut runtime, (address, port), peer, flags, now) {
                    Err(Nat44TcpPlanError::HostSessionQuotaExceeded) => {
                        let host = runtime.session_hosts.find(address).unwrap().unwrap();
                        for (&index, owner) in &counted {
                            if *owner == address {
                                let session = runtime.sessions[index];
                                assert!(runtime.session_is_live(session, now), "seed {seed}");
                                assert!(!runtime.session_slot_reusable(index, now));
                            }
                        }
                        assert_eq!(runtime.session_hosts.count(host), usize::from(LIMIT));
                        outcomes[0] += 1;
                    }
                    Err(_) => {}
                    Ok(plan) => {
                        if let Some(index) = plan.host_session_reclaim() {
                            assert_eq!(counted.remove(&index), Some(address), "seed {seed}");
                            outcomes[1] += 1;
                        }
                        if plan.session_created || plan.session_recount {
                            counted.insert(plan.session_index(), address);
                            outcomes[2] += 1;
                        }
                        // A restart the remote opened stops counting.
                        if !runtime.sessions[plan.session_index()].is_host_initiated() {
                            counted.remove(&plan.session_index());
                        }
                    }
                }
                if next_random(&mut random).is_multiple_of(2) {
                    if let Some((_, mapping)) = runtime.find_mapping(address, port).unwrap() {
                        let flags = [SYN_ACK, ACK, FIN_ACK, RST, SYN]
                            [(next_random(&mut random) % 5) as usize];
                        let from = if flags == SYN { (REMOTE2, 9) } else { peer };
                        if let Ok(plan) =
                            inbound(&mut runtime, mapping.public_port, from, flags, now)
                        {
                            if plan.session_created {
                                counted.remove(&plan.session_index);
                            }
                        }
                    }
                }
                for index in 0..3 {
                    let address = Ipv4Address::from_octets([10, 0, 1, index]);
                    let expected = counted.values().filter(|owner| **owner == address).count();
                    assert_eq!(session_count(&runtime, address), expected, "seed {seed}");
                    assert!(expected <= usize::from(LIMIT));
                }
                assert_eq!(runtime.validate_indexes(), Ok(()), "seed {seed}");
            }
        });
    }
    assert!(outcomes.iter().all(|count| *count > 0), "{outcomes:?}");
}

/// Constant work in a full 65536-session table: 4096 hosts with 16
/// sessions each (one mapping, 16 remotes) at a limit of 16 hold every
/// session slot. A refused SYN costs one session host lookup and three list
/// head expiry reads; after the opening timeout a SYN is admitted with the
/// revalidation's and the commit's lookups and one O(1) uncount.
#[test]
fn tcp_host_session_quota_work_is_constant_in_a_full_65536_session_table() {
    const SLOTS: usize = 65_536;
    const LIMIT: usize = 16;
    with_config(session_policy(LIMIT as u16), 1, 65_535, |config| {
        let mut mappings = vec![Nat44TcpMappingSlot::default(); SLOTS];
        let mut sessions = vec![Nat44TcpSessionSlot::default(); SLOTS];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let address = |host: usize| {
            Ipv4Address::from_octets([10, 1 + (host >> 16) as u8, (host >> 8) as u8, host as u8])
        };
        for flow in 0..SLOTS {
            let peer = remote(flow % LIMIT);
            let plan = runtime
                .plan_outbound(address(flow / LIMIT), 1, peer.0, peer.1, seg(SYN), 0)
                .unwrap();
            runtime.commit_outbound(plan, 0).unwrap();
        }
        let mut worst = [0_usize; 2];
        let mut syn_work = |runtime: &mut Nat44TcpRuntime<'_>, host: usize, now: u64| {
            runtime.session_hosts.take_lookup_probes();
            let finds = runtime.session_hosts.finds();
            let peer = remote(999);
            let result = runtime
                .plan_outbound(address(host), 1, peer.0, peer.1, seg(SYN), now)
                .map(|plan| runtime.commit_outbound(plan, now).unwrap());
            let seen = [
                runtime.session_hosts.finds() - finds,
                runtime.session_hosts.take_lookup_probes(),
            ];
            for (worst, seen) in worst.iter_mut().zip(seen) {
                *worst = (*worst).max(seen);
            }
            result
        };
        for host in (0..4_096).step_by(97) {
            assert_eq!(
                syn_work(&mut runtime, host, 1),
                Err(Nat44TcpPlanError::HostSessionQuotaExceeded)
            );
        }
        // The mapping (established TTL floor) is still live; its opening
        // sessions are past their (host-driven) expiry.
        for host in (0..4_096).step_by(97) {
            syn_work(&mut runtime, host, TRANSITORY).unwrap();
            assert_eq!(session_count(&runtime, address(host)), LIMIT);
        }
        // The lookups are the plan's, the commit revalidation's, and the
        // commit's (as for the N3 host table).
        assert!(worst[0] <= 3 && worst[1] <= 6, "work per new SYN {worst:?}");
    });
}

/// Review core M (N6): a host that lets a session pass its host-driven
/// expiry (it delays its ACK while the remote keeps the session alive),
/// opens a new session in its place, and then resumes the old one must not
/// end up driving more sessions than its limit. The resumed session is
/// counted again like a new one: within the limit it takes the place of a
/// session past its host-driven expiry, otherwise its segment is refused.
/// Over ten rounds the host never drives more than `limit` sessions at the
/// same time and the count never exceeds the limit (the probe ended with
/// ten driven sessions counted as one before the fix).
#[test]
fn resuming_an_uncounted_session_counts_it_again_within_the_limit() {
    with_config(session_policy(1), 40_000, 40_063, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 16];
        let mut sessions = [Nat44TcpSessionSlot::default(); 32];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let mut opened: Vec<(u16, (Ipv4Address, u16), u16)> = Vec::new();
        let mut refused_resumes = 0;
        for round in 0..10_u16 {
            let now = u64::from(round) * TRANSITORY;
            // Every remote keeps its connection alive by itself.
            for (_, peer, public) in &opened {
                inbound(&mut runtime, *public, *peer, SYN_ACK, now).unwrap();
            }
            // The host opens a new connection in place of the one past its
            // host-driven expiry ...
            let mut driven = 0;
            let port = 1_000 + round;
            let peer = remote(round as usize);
            let new = out(&mut runtime, (INTERNAL, port), peer, SYN, now)
                .unwrap_or_else(|error| panic!("round {round}: {error:?}"));
            driven += 1;
            // ... and resumes every earlier one (its delayed ACK).
            for (port, peer, _) in &opened {
                match out(&mut runtime, (INTERNAL, *port), *peer, ACK, now) {
                    Ok(_) => driven += 1,
                    Err(Nat44TcpPlanError::HostSessionQuotaExceeded) => refused_resumes += 1,
                    Err(error) => panic!("round {round}: {error:?}"),
                }
            }
            opened.push((port, peer, new.public_port()));
            // Midway, the remotes keep their connections alive again.
            for (_, peer, public) in &opened {
                inbound(&mut runtime, *public, *peer, SYN_ACK, now + TRANSITORY / 2).unwrap();
            }
            assert!(
                driven <= 1,
                "round {round}: {driven} sessions driven at once"
            );
            assert!(session_count(&runtime, INTERNAL) <= 1, "round {round}");
            assert_eq!(runtime.validate_indexes(), Ok(()), "round {round}");
        }
        assert_eq!(refused_resumes, 45);
    });
}

/// Review sec L1: a FIN-closed session the host opened, which the remote
/// restarts (its SYN on the same tuple, answered by the host's SYN-ACK), is
/// a remote-opened connection and stops counting. Review sec L2: a
/// FIN-closed session a remote opened, which the host restarts with its own
/// SYN, becomes host-initiated and counts (refused at the limit like a new
/// session).
#[test]
fn restarts_follow_who_opened_the_connection() {
    let peer = remote(0);
    let close = |runtime: &mut Nat44TcpRuntime<'_>, public: u16, now: u64| {
        inbound(runtime, public, peer, FIN_ACK, now).unwrap();
        out(runtime, (INTERNAL, 1_000), peer, FIN_ACK, now).unwrap();
        inbound(runtime, public, peer, ACK, now).unwrap();
    };
    with_config(session_policy(1), 40_000, 40_063, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 8];
        let mut sessions = [Nat44TcpSessionSlot::default(); 16];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let first = out(&mut runtime, (INTERNAL, 1_000), peer, SYN, 0).unwrap();
        inbound(&mut runtime, first.public_port(), peer, SYN_ACK, 0).unwrap();
        out(&mut runtime, (INTERNAL, 1_000), peer, ACK, 0).unwrap();
        close(&mut runtime, first.public_port(), 0);
        assert_eq!(session_count(&runtime, INTERNAL), 1);
        // The remote reconnects on the same tuple; the host accepts.
        inbound(&mut runtime, first.public_port(), peer, SYN, 10).unwrap();
        out(&mut runtime, (INTERNAL, 1_000), peer, SYN_ACK, 10).unwrap();
        let session = runtime.sessions[first.session_index()];
        assert!(!session.is_host_initiated() && session.is_external_inbound());
        assert_eq!(session_count(&runtime, INTERNAL), 0);
        out(&mut runtime, (INTERNAL, 2_000), remote(1), SYN, 20).unwrap();
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
    with_config(session_policy(1), 40_000, 40_063, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 8];
        let mut sessions = [Nat44TcpSessionSlot::default(); 16];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let server = out(&mut runtime, (INTERNAL, 1_000), remote(1), SYN, 0).unwrap();
        // A remote-opened connection on the host's mapping, closed.
        let at = 100_000;
        let accepted = inbound(&mut runtime, server.public_port(), peer, SYN, at).unwrap();
        out(&mut runtime, (INTERNAL, 1_000), peer, SYN_ACK, at).unwrap();
        inbound(&mut runtime, server.public_port(), peer, ACK, at).unwrap();
        close(&mut runtime, server.public_port(), at);
        assert_eq!(session_count(&runtime, INTERNAL), 1);
        // The host reconnects on the same tuple: a session it opens, over
        // the limit while its first session is alive.
        let before = runtime.sessions.to_vec();
        assert_eq!(
            out(&mut runtime, (INTERNAL, 1_000), peer, SYN, at + 10).map(|_| ()),
            Err(Nat44TcpPlanError::HostSessionQuotaExceeded)
        );
        assert_eq!(runtime.sessions, &before[..]);
        // Once the first one is past its host-driven expiry, it counts.
        let restart = out(&mut runtime, (INTERNAL, 1_000), peer, SYN, TRANSITORY).unwrap();
        assert!(restart.session_recount && !restart.session_created);
        assert_eq!(restart.session_index(), accepted.session_index);
        assert!(runtime.sessions[accepted.session_index].is_host_initiated());
        assert_eq!(session_count(&runtime, INTERNAL), 1);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}
