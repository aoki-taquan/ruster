//! N3: the per-internal-host mapping quota of the TCP NAT (NAT44-092, RFC
//! 6888 REQ-4). A child of `nat44::tcp_tests`, sharing its helpers.

use super::*;

const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;
const FIN_ACK: u8 = 0x11;
const RST: u8 = 0x04;
const TRANSITORY: u64 = NAT44_TCP_DEFAULT_TRANSITORY_IDLE_TTL_MS;

fn quota_policy(limit: u16) -> Nat44TcpPolicy {
    Nat44TcpPolicy::default()
        .with_filtering(Nat44Filtering::EndpointIndependent)
        .with_mappings_per_host(limit)
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
) -> Result<(), Nat44TcpPlanError> {
    let plan = runtime.plan_inbound(public_port, remote.0, remote.1, seg(flags), now)?;
    runtime.commit_inbound(plan, now).unwrap();
    Ok(())
}

fn host_count(runtime: &Nat44TcpRuntime<'_>, address: Ipv4Address) -> usize {
    runtime
        .hosts
        .find(address)
        .unwrap()
        .map_or(0, |host| runtime.hosts.count(host))
}

/// Mappings of `address` that own a port and those live at `now`, by a
/// full scan of the slots.
/// Mappings of `address` that own a port and those its host keeps alive
/// at `now` (host-driven liveness, N3), by a full scan of the slots.
fn scan(runtime: &Nat44TcpRuntime<'_>, address: Ipv4Address, now: u64) -> (usize, usize) {
    let mut counted = 0;
    let mut host_live = 0;
    for mapping in runtime.mappings.iter().copied() {
        if mapping.occupied && mapping.internal_address == address {
            counted += usize::from(mapping.port_owned);
            host_live += usize::from(runtime.mapping_is_host_live(mapping, now));
        }
    }
    (counted, host_live)
}

/// At the limit a new mapping is refused without any state change, while
/// new sessions on the host's existing mappings (outbound to another remote
/// and filtered inbound) still work, and another host keeps its own quota.
#[test]
fn tcp_host_quota_refuses_new_mappings_but_not_new_sessions() {
    with_config(quota_policy(2), 40_000, 40_063, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 8];
        let mut sessions = [Nat44TcpSessionSlot::default(); 16];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let first = out(&mut runtime, (INTERNAL, 1_000), (REMOTE1, 443), SYN, 0).unwrap();
        out(&mut runtime, (INTERNAL, 1_001), (REMOTE1, 443), SYN, 0).unwrap();
        let mappings_before = runtime.mappings.to_vec();
        let sessions_before = runtime.sessions.to_vec();
        assert_eq!(
            out(&mut runtime, (INTERNAL, 1_002), (REMOTE1, 443), SYN, 10).map(|_| ()),
            Err(Nat44TcpPlanError::HostQuotaExceeded)
        );
        assert_eq!(runtime.mappings, &mappings_before[..]);
        assert_eq!(runtime.sessions, &sessions_before[..]);
        assert_eq!(runtime.counters().host_quota_exceeded, 1);
        // A new session of an existing mapping is not a new mapping.
        let second = out(&mut runtime, (INTERNAL, 1_000), (REMOTE2, 80), SYN, 20).unwrap();
        assert!(!second.mapping_created && second.session_created);
        inbound(
            &mut runtime,
            first.public_port(),
            (Ipv4Address::from_octets([192, 0, 2, 99]), 5_000),
            SYN,
            20,
        )
        .unwrap();
        assert_eq!(host_count(&runtime, INTERNAL), 2);
        out(&mut runtime, (INTERNAL2, 1_000), (REMOTE1, 443), SYN, 30).unwrap();
        assert_eq!(host_count(&runtime, INTERNAL2), 1);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// The host's mappings expire in phase order, not activity order: an
/// established mapping created first outlives a half-open one created
/// later. At the limit, the new mapping reclaims the one that expired (the
/// half-open one, from the host's transitory list), exactly at its expiry.
#[test]
fn tcp_host_quota_reclaims_the_hosts_mapping_that_expired_first() {
    with_config(quota_policy(2), 40_000, 40_063, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 8];
        let mut sessions = [Nat44TcpSessionSlot::default(); 16];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let established = out(&mut runtime, (INTERNAL, 1_000), (REMOTE1, 443), SYN, 0).unwrap();
        inbound(
            &mut runtime,
            established.public_port(),
            (REMOTE1, 443),
            SYN_ACK,
            0,
        )
        .unwrap();
        out(&mut runtime, (INTERNAL, 1_000), (REMOTE1, 443), ACK, 0).unwrap();
        let half_open = out(&mut runtime, (INTERNAL, 1_001), (REMOTE1, 443), SYN, 1_000).unwrap();
        let expiry = 1_000 + TRANSITORY;
        assert_eq!(
            out(
                &mut runtime,
                (INTERNAL, 1_002),
                (REMOTE1, 443),
                SYN,
                expiry - 1
            )
            .map(|_| ()),
            Err(Nat44TcpPlanError::HostQuotaExceeded)
        );
        let reclaimed = out(&mut runtime, (INTERNAL, 1_002), (REMOTE1, 443), SYN, expiry).unwrap();
        assert!(reclaimed.mapping_created && reclaimed.mapping_expired);
        assert_eq!(reclaimed.mapping_index(), half_open.mapping_index());
        // The established mapping is untouched and still translates.
        let kept = runtime.mappings[established.mapping_index()];
        assert!(kept.port_owned && kept.internal_port == 1_000);
        out(&mut runtime, (INTERNAL, 1_000), (REMOTE1, 443), ACK, expiry).unwrap();
        assert_eq!(host_count(&runtime, INTERNAL), 2);
        assert_eq!(runtime.validate_indexes(), Ok(()));
        // A reconcile flush forgets every host.
        runtime
            .reconcile(config, rotated_test_tcp_hash_key())
            .unwrap();
        assert_eq!(runtime.hosts.host_counts(), (0, 0));
        out(&mut runtime, (INTERNAL, 1_003), (REMOTE1, 443), SYN, expiry).unwrap();
        assert_eq!(host_count(&runtime, INTERNAL), 1);
    });
}

/// With both host lists' heads expired, the new mapping reclaims the one
/// that expired first (here the established mapping, older by expiry though
/// it is on the longer-lived list), and a returning endpoint whose own
/// expired mapping still holds its port recreates it in place at the limit
/// even when another of the host's mappings expired earlier.
#[test]
fn tcp_host_quota_reclaims_the_earliest_expiry_and_exempts_returning_endpoints() {
    let established_ttl = NAT44_TCP_DEFAULT_IDLE_TTL_MS;
    with_config(quota_policy(2), 40_000, 40_063, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 8];
        let mut sessions = [Nat44TcpSessionSlot::default(); 16];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let established = out(&mut runtime, (INTERNAL, 1_000), (REMOTE1, 443), SYN, 0).unwrap();
        inbound(
            &mut runtime,
            established.public_port(),
            (REMOTE1, 443),
            SYN_ACK,
            0,
        )
        .unwrap();
        out(&mut runtime, (INTERNAL, 1_000), (REMOTE1, 443), ACK, 0).unwrap();
        // Expires at established_ttl - 100_000 + TRANSITORY, after the
        // established mapping (established_ttl).
        let start = established_ttl - 100_000;
        let half_open = out(&mut runtime, (INTERNAL, 1_001), (REMOTE1, 443), SYN, start).unwrap();
        let now = start + TRANSITORY;
        assert!(!runtime.mapping_is_live(runtime.mappings[established.mapping_index()], now));
        assert!(!runtime.mapping_is_live(runtime.mappings[half_open.mapping_index()], now));
        // The half-open endpoint returns: its own slot and port, not the
        // established mapping's (which expired first).
        let back = out(&mut runtime, (INTERNAL, 1_001), (REMOTE2, 80), SYN, now).unwrap();
        assert!(back.mapping_created);
        assert_eq!(back.mapping_index(), half_open.mapping_index());
        assert_eq!(back.public_port(), half_open.public_port());
        assert!(runtime.mappings[established.mapping_index()].port_owned);
        assert_eq!(host_count(&runtime, INTERNAL), 2);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
    with_config(quota_policy(2), 40_000, 40_063, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 8];
        let mut sessions = [Nat44TcpSessionSlot::default(); 16];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let established = out(&mut runtime, (INTERNAL, 1_000), (REMOTE1, 443), SYN, 0).unwrap();
        inbound(
            &mut runtime,
            established.public_port(),
            (REMOTE1, 443),
            SYN_ACK,
            0,
        )
        .unwrap();
        out(&mut runtime, (INTERNAL, 1_000), (REMOTE1, 443), ACK, 0).unwrap();
        let start = established_ttl - 100_000;
        out(&mut runtime, (INTERNAL, 1_001), (REMOTE1, 443), SYN, start).unwrap();
        let now = start + TRANSITORY;
        // A new endpoint takes the mapping that expired first.
        let reclaimed = out(&mut runtime, (INTERNAL, 1_002), (REMOTE1, 443), SYN, now).unwrap();
        assert_eq!(reclaimed.mapping_index(), established.mapping_index());
        assert_eq!(host_count(&runtime, INTERNAL), 2);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// Review N3 sec M1 regression: a remote cannot pin an inside host's quota.
/// The victim opens two connections to the attacker's server and closes
/// them; for 2400 s the attacker then sends an inbound SYN to each public
/// port every 200 s (under address-dependent filtering from the contacted
/// address with a fresh source port, under endpoint-independent filtering
/// from anywhere), and the victim's stack answers each with a RST. The SYNs
/// keep both mappings live, but only the host's own activity counts for the
/// quota, so the victim's new connection is accepted and reclaims one of
/// them (its stale inbound sessions end with it).
#[test]
fn inbound_only_activity_cannot_pin_a_hosts_quota() {
    const FIN: u8 = 0x01;
    let attacker = (REMOTE1, 443);
    for filtering in [
        Nat44Filtering::AddressDependent,
        Nat44Filtering::EndpointIndependent,
    ] {
        let policy = quota_policy(2).with_filtering(filtering);
        with_config(policy, 40_000, 40_063, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 8];
            let mut sessions = [Nat44TcpSessionSlot::default(); 32];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let mut ports = Vec::new();
            for internal in [1_000, 1_001] {
                let syn = out(&mut runtime, (INTERNAL, internal), attacker, SYN, 0).unwrap();
                inbound(&mut runtime, syn.public_port(), attacker, SYN_ACK, 0).unwrap();
                out(&mut runtime, (INTERNAL, internal), attacker, ACK, 0).unwrap();
                ports.push((syn.mapping_index(), syn.public_port()));
            }
            // The victim closes both connections.
            for (internal, (_, public)) in [1_000, 1_001].into_iter().zip(ports.clone()) {
                out(
                    &mut runtime,
                    (INTERNAL, internal),
                    attacker,
                    FIN | ACK,
                    1_000,
                )
                .unwrap();
                inbound(&mut runtime, public, attacker, FIN | ACK, 1_000).unwrap();
                out(&mut runtime, (INTERNAL, internal), attacker, ACK, 1_000).unwrap();
            }
            let spoofed = if filtering == Nat44Filtering::AddressDependent {
                REMOTE1
            } else {
                Ipv4Address::from_octets([192, 0, 2, 77])
            };
            let mut now = 1_000;
            let mut source_port = 20_000;
            while now < 2_400_000 {
                now += 200_000;
                for (index, (internal, (_, public))) in [1_000_u16, 1_001]
                    .into_iter()
                    .zip(ports.clone())
                    .enumerate()
                {
                    source_port += 1;
                    let remote = (spoofed, source_port + index as u16);
                    inbound(&mut runtime, public, remote, SYN, now).unwrap();
                    // The victim's stack refuses the connection.
                    out(&mut runtime, (INTERNAL, internal), remote, RST, now).unwrap();
                }
            }
            for (mapping, _) in &ports {
                let pinned = runtime.mappings[*mapping];
                assert!(runtime.mapping_is_live(pinned, now));
                assert!(!runtime.mapping_is_host_live(pinned, now));
            }
            let fresh = out(&mut runtime, (INTERNAL, 2_000), (REMOTE2, 80), SYN, now).unwrap();
            assert!(fresh.mapping_created);
            assert!(ports
                .iter()
                .any(|(mapping, _)| *mapping == fresh.mapping_index()));
            assert_eq!(runtime.counters().host_quota_exceeded, 0);
            assert_eq!(host_count(&runtime, INTERNAL), 2);
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
    }
}

/// The host-driven expiry follows the mapping expiry rule: an established
/// connection the host opened keeps the mapping on the established TTL even
/// after the host's last segment opened another connection that never
/// completed, so an idle established connection is not reclaimed after the
/// transitory TTL.
#[test]
fn an_idle_established_connection_keeps_counting_after_a_later_half_open() {
    with_config(quota_policy(1), 40_000, 40_063, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 8];
        let mut sessions = [Nat44TcpSessionSlot::default(); 16];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let first = out(&mut runtime, (INTERNAL, 1_000), (REMOTE1, 22), SYN, 0).unwrap();
        inbound(&mut runtime, first.public_port(), (REMOTE1, 22), SYN_ACK, 0).unwrap();
        out(&mut runtime, (INTERNAL, 1_000), (REMOTE1, 22), ACK, 0).unwrap();
        out(&mut runtime, (INTERNAL, 1_000), (REMOTE2, 80), SYN, 10).unwrap();
        let later = 10 + TRANSITORY + 1;
        assert!(runtime.mapping_is_host_live(runtime.mappings[first.mapping_index()], later));
        assert_eq!(
            out(&mut runtime, (INTERNAL, 1_001), (REMOTE1, 443), SYN, later).map(|_| ()),
            Err(Nat44TcpPlanError::HostQuotaExceeded)
        );
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// A returning endpoint whose own mapping was retired, at the limit, while
/// the host's only reclaimable mapping is still live because a remote keeps
/// sending to it: the plan cannot recreate the returning endpoint's slot
/// without retiring that live mapping (its port would move while its
/// endpoint can still translate), so it is refused instead. Any other new
/// endpoint of the host takes over the remote-pinned mapping.
#[test]
fn a_retired_endpoint_at_the_limit_never_retires_a_live_mapping() {
    let host_a = Ipv4Address::from_octets([10, 0, 1, 1]);
    let host_b = Ipv4Address::from_octets([10, 0, 1, 2]);
    let host_c = Ipv4Address::from_octets([10, 0, 1, 3]);
    let stranger = Ipv4Address::from_octets([192, 0, 2, 77]);
    with_config(quota_policy(2), 40_000, 40_063, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 8];
        let mut sessions = [Nat44TcpSessionSlot::default(); 32];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let returning = out(&mut runtime, (host_a, 40_000), (REMOTE1, 443), SYN, 0).unwrap();
        let pinned = out(&mut runtime, (host_a, 5), (REMOTE1, 443), SYN, 0).unwrap();
        out(&mut runtime, (host_c, 40_001), (REMOTE1, 443), SYN, 0).unwrap();
        out(&mut runtime, (host_b, 40_001), (REMOTE1, 443), SYN, 0).unwrap();
        out(&mut runtime, (host_b, 40_000), (REMOTE1, 443), SYN, 0).unwrap();
        assert_eq!(returning.public_port(), 40_000);
        // A stranger keeps A's second mapping live.
        inbound(
            &mut runtime,
            pinned.public_port(),
            (stranger, 7),
            SYN,
            200_000,
        )
        .unwrap();
        let now = TRANSITORY;
        // B's endpoints return and take their internal ports back, retiring
        // C's mapping and then A's endpoint 40000.
        out(&mut runtime, (host_b, 40_001), (REMOTE1, 443), SYN, now).unwrap();
        out(&mut runtime, (host_b, 40_000), (REMOTE1, 443), SYN, now).unwrap();
        assert!(!runtime.mappings[returning.mapping_index()].port_owned);
        // A refills to its limit with a live mapping (in C's retired slot).
        out(&mut runtime, (host_a, 6), (REMOTE1, 443), SYN, now).unwrap();
        assert_eq!(host_count(&runtime, host_a), 2);
        let pinned_slot = runtime.mappings[pinned.mapping_index()];
        assert!(runtime.mapping_is_live(pinned_slot, now));
        assert!(!runtime.mapping_is_host_live(pinned_slot, now));
        assert_eq!(
            out(&mut runtime, (host_a, 40_000), (REMOTE2, 80), SYN, now).map(|_| ()),
            Err(Nat44TcpPlanError::HostQuotaExceeded)
        );
        assert!(runtime.mappings[pinned.mapping_index()].port_owned);
        assert_eq!(runtime.validate_indexes(), Ok(()));
        // A new endpoint takes over the remote-pinned mapping.
        let fresh = out(&mut runtime, (host_a, 7), (REMOTE2, 80), SYN, now).unwrap();
        assert_eq!(fresh.mapping_index(), pinned.mapping_index());
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// The other side of the review fix: an inside server whose inbound
/// connections are established and that keeps answering them keeps its
/// mapping counting, so at the limit its new outbound mapping is refused
/// and its inbound service is never reclaimed while it is in use.
#[test]
fn an_active_inside_server_keeps_its_mapping_counted() {
    with_config(quota_policy(1), 40_000, 40_063, |config| {
        let mut mappings = [Nat44TcpMappingSlot::default(); 8];
        let mut sessions = [Nat44TcpSessionSlot::default(); 32];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let server = out(&mut runtime, (INTERNAL, 8_080), (REMOTE1, 443), SYN, 0).unwrap();
        let client = (Ipv4Address::from_octets([192, 0, 2, 50]), 30_000);
        inbound(&mut runtime, server.public_port(), client, SYN, 0).unwrap();
        out(&mut runtime, (INTERNAL, 8_080), client, SYN_ACK, 0).unwrap();
        inbound(&mut runtime, server.public_port(), client, ACK, 0).unwrap();
        let mut now = 0;
        while now < 2_400_000 {
            now += 200_000;
            inbound(&mut runtime, server.public_port(), client, ACK, now).unwrap();
            out(&mut runtime, (INTERNAL, 8_080), client, ACK, now).unwrap();
            assert!(runtime.mapping_is_host_live(runtime.mappings[server.mapping_index()], now));
            assert_eq!(
                out(&mut runtime, (INTERNAL, 9_000), (REMOTE2, 80), SYN, now).map(|_| ()),
                Err(Nat44TcpPlanError::HostQuotaExceeded)
            );
        }
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// Seeded churn of SYN, SYN-ACK, ACK, FIN, and RST segments of several
/// hosts' connections against a small pool and table, checked after every
/// segment against a full scan of the slots (not an independent NAT model):
/// a new mapping is refused as `HostQuotaExceeded` exactly when the scan
/// finds `limit` mappings its host keeps alive (host-driven liveness; some
/// strangers also send inbound SYNs, which keep mappings live but not
/// host-live); every host's count equals its scanned port-owning mappings
/// and never exceeds the limit; the full index validation, including the
/// host lists in host-driven expiry order and the host-driven expiry never
/// outliving the mapping, holds.
#[test]
fn tcp_host_quota_matches_a_full_scan_of_the_slots_under_seeded_churn() {
    const LIMIT: u16 = 2;
    let mut pinned = 0_usize;
    for seed in 1..=16_u64 {
        let hosts = if seed % 4 == 0 { 12 } else { 4 };
        let policy = quota_policy(LIMIT).with_port_preservation(seed % 2 == 0);
        with_config(policy, 40_000, 40_009, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 8];
            let mut sessions = [Nat44TcpSessionSlot::default(); 16];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let mut random = seed;
            let mut now = 0_u64;
            let mut outcomes = [0_usize; 4];
            for _ in 0..2_000 {
                now += next_random(&mut random) % (TRANSITORY / 4);
                let address =
                    Ipv4Address::from_octets([10, 0, 1, (next_random(&mut random) % hosts) as u8]);
                let port = 40_000 + (next_random(&mut random) % 4) as u16;
                let remote = (REMOTE1, 443 + (next_random(&mut random) % 2) as u16);
                let flags = [SYN, SYN, ACK, FIN_ACK, RST][(next_random(&mut random) % 5) as usize];
                let exact_live = runtime
                    .find_mapping(address, port)
                    .unwrap()
                    .is_some_and(|(_, mapping)| runtime.mapping_is_live(mapping, now));
                let (_, live) = scan(&runtime, address, now);
                match out(&mut runtime, (address, port), remote, flags, now) {
                    Err(Nat44TcpPlanError::HostQuotaExceeded) => {
                        assert!(flags == SYN && !exact_live, "seed {seed}");
                        assert!(live >= usize::from(LIMIT), "seed {seed}");
                        outcomes[0] += 1;
                    }
                    Err(_) => {
                        assert!(exact_live || live < usize::from(LIMIT) || flags != SYN);
                    }
                    Ok(plan) => {
                        outcomes[1] += usize::from(plan.mapping_created);
                        // Some remotes answer, so sessions establish.
                        if flags == SYN && next_random(&mut random).is_multiple_of(2) {
                            let _ = inbound(&mut runtime, plan.public_port(), remote, SYN_ACK, now);
                            outcomes[2] += 1;
                        }
                        // Some remotes keep sending unsolicited SYNs to the
                        // public port (inbound-only activity, review M1).
                        if next_random(&mut random).is_multiple_of(3) {
                            let stranger = (
                                Ipv4Address::from_octets([192, 0, 2, 60]),
                                (next_random(&mut random) % 50_000) as u16 + 1_024,
                            );
                            if inbound(&mut runtime, plan.public_port(), stranger, SYN, now).is_ok()
                            {
                                outcomes[3] += 1;
                            }
                        }
                    }
                }
                for index in 0..hosts {
                    let address = Ipv4Address::from_octets([10, 0, 1, index as u8]);
                    let (counted, live) = scan(&runtime, address, now);
                    assert_eq!(host_count(&runtime, address), counted, "seed {seed}");
                    assert!(counted <= usize::from(LIMIT) && live <= counted);
                }
                assert_eq!(runtime.validate_indexes(), Ok(()), "seed {seed}");
                // Pinned mappings: live but past their host-driven expiry.
                pinned += runtime
                    .mappings
                    .iter()
                    .filter(|mapping| {
                        runtime.mapping_is_live(**mapping, now)
                            && !runtime.mapping_is_host_live(**mapping, now)
                    })
                    .count();
            }
            assert!(outcomes.iter().all(|count| *count > 0), "{outcomes:?}");
        });
    }
    // Inbound SYNs kept some mappings live past their host-driven expiry.
    assert!(pinned > 0);
}

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Constant work in a full 65536-slot table: 4095 hosts at a limit of 16
/// hold every port; a refused SYN costs one host lookup and two head
/// liveness checks, and after expiry a SYN reclaims the host's own mapping
/// with one port-owner check.
#[test]
fn tcp_host_quota_work_is_constant_in_a_full_65536_slot_table() {
    const SLOTS: usize = 65_536;
    const LIMIT: usize = 16;
    with_config(quota_policy(LIMIT as u16), 1, 65_535, |config| {
        let mut mappings = vec![Nat44TcpMappingSlot::default(); SLOTS];
        let mut sessions = vec![Nat44TcpSessionSlot::default(); SLOTS];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let address = |host: usize| {
            Ipv4Address::from_octets([10, 1 + (host >> 16) as u8, (host >> 8) as u8, host as u8])
        };
        for flow in 0..65_535 {
            let plan = runtime
                .plan_outbound(
                    address(flow / LIMIT),
                    (flow % LIMIT) as u16 + 1,
                    REMOTE1,
                    443,
                    seg(SYN),
                    0,
                )
                .unwrap();
            runtime.commit_outbound(plan, 0).unwrap();
        }
        let mut worst = [0_usize; 3];
        let mut syn_work = |runtime: &mut Nat44TcpRuntime<'_>, host: usize, now: u64| {
            runtime.reset_liveness_checks();
            runtime.reset_index_probe_counts();
            runtime.hosts.take_lookup_probes();
            let result = runtime
                .plan_outbound(address(host), 100, REMOTE2, 80, seg(SYN), now)
                .map(|plan| runtime.commit_outbound(plan, now).unwrap());
            let (mapping_checks, _) = runtime.liveness_checks();
            let (_, _, _, _, owner_probes) = runtime.index_probe_counts();
            let seen = [
                mapping_checks,
                owner_probes,
                runtime.hosts.take_lookup_probes(),
            ];
            for (worst, seen) in worst.iter_mut().zip(seen) {
                *worst = (*worst).max(seen);
            }
            result
        };
        for host in (0..4_095).step_by(97) {
            assert_eq!(
                syn_work(&mut runtime, host, 1),
                Err(Nat44TcpPlanError::HostQuotaExceeded)
            );
        }
        for host in (0..4_095).step_by(97) {
            syn_work(&mut runtime, host, TRANSITORY).unwrap();
        }
        assert!(
            worst[0] <= 4 && worst[1] <= 2 + NAT44_PORT_TAKEOVER_PROBES && worst[2] <= 6,
            "work per new SYN {worst:?}"
        );
        assert!(runtime.port_owners.bitmap_matches_slots());
    });
}
