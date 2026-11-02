//! Per-internal-host filter peer limit of the UDP NAT (N6, NAT44-119, RFC
//! 6888 REQ-5): refusal at the limit without state change, recovery when a
//! counted mapping expires, inbound traffic never holding a host's budget,
//! the count under seeded churn against a full scan of the peer slots, and
//! constant work in a full table.

use super::*;

const TTL: u64 = NAT44_UDP_MIN_IDLE_TTL_MS;

fn peer_policy(limit: u16) -> Nat44UdpPolicy {
    Nat44UdpPolicy::new(TTL, 0)
        .unwrap()
        .with_peers_per_host(limit)
}

fn host(index: usize) -> Ipv4Address {
    Ipv4Address::from_octets([10, 0, (index >> 8) as u8, index as u8])
}

fn remote(index: usize) -> Ipv4Address {
    Ipv4Address::from_octets([198, 51, (100 + (index >> 8)) as u8, index as u8])
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

/// Peers of `address` on its live mappings, by a full scan of the peer
/// slots: occupied peers of the current generation of a live mapping of
/// that internal address.
fn live_peers(runtime: &Nat44UdpRuntime<'_>, address: Ipv4Address, now: u64) -> usize {
    runtime
        .peers
        .iter()
        .filter(|peer| {
            let mapping = runtime.mappings[peer.mapping_index];
            peer.occupied
                && mapping.occupied
                && mapping.internal_address == address
                && mapping.generation == peer.mapping_generation
                && mapping.lifecycle_epoch == peer.mapping_lifecycle_epoch
                && runtime.mapping_is_live(mapping, now)
        })
        .count()
}

/// Peers chained to `address`'s mappings that are still on the activity
/// list (live or expired, not yet parked or reused), by a full scan.
fn chained_peers(runtime: &Nat44UdpRuntime<'_>, address: Ipv4Address) -> usize {
    runtime
        .peers
        .iter()
        .filter(|peer| {
            let mapping = runtime.mappings[peer.mapping_index];
            peer.occupied
                && mapping.occupied
                && mapping.internal_address == address
                && mapping.link.list == UdpMappingList::Lru
                && mapping.generation == peer.mapping_generation
                && mapping.lifecycle_epoch == peer.mapping_lifecycle_epoch
        })
        .count()
}

fn host_peers(runtime: &Nat44UdpRuntime<'_>, address: Ipv4Address) -> usize {
    runtime
        .hosts
        .find(address)
        .unwrap()
        .map_or(0, |host| runtime.hosts.members(host))
}

/// At the limit a new peer is refused before any state changes, on an
/// existing mapping and for a new mapping alike, nothing is evicted, and
/// the host's existing peers keep working (refresh, inbound). Another host
/// keeps its own budget.
#[test]
fn udp_host_peer_quota_refuses_at_the_limit_without_state_change() {
    with_port_config(peer_policy(3), 40_000, 40_063, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 8];
        let mut peers = [Nat44UdpPeerSlot::default(); 16];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        let first = outbound(&mut runtime, INTERNAL, 1_000, remote(1), 10).unwrap();
        outbound(&mut runtime, INTERNAL, 1_000, remote(2), 10).unwrap();
        outbound(&mut runtime, INTERNAL, 1_001, remote(3), 10).unwrap();
        assert_eq!(host_peers(&runtime, INTERNAL), 3);
        let mappings_before = runtime.mappings.to_vec();
        let peers_before = runtime.peers.to_vec();
        let revision = runtime.state_revision;
        for (port, peer) in [(1_000, remote(4)), (1_001, remote(4)), (1_002, remote(1))] {
            assert_eq!(
                outbound(&mut runtime, INTERNAL, port, peer, 20).map(|_| ()),
                Err(Nat44UdpPlanError::HostPeerQuotaExceeded),
                "port {port}"
            );
        }
        assert_eq!(runtime.counters().host_peer_quota_exceeded, 3);
        assert_eq!(runtime.counters().peer_full, 0);
        assert_eq!(runtime.mappings, &mappings_before[..]);
        assert_eq!(runtime.peers, &peers_before[..]);
        assert_eq!(runtime.state_revision, revision + 1);
        // Existing peers: refresh and inbound.
        let refresh = outbound(&mut runtime, INTERNAL, 1_000, remote(2), 30).unwrap();
        assert!(!refresh.mapping_created && !refresh.peer_created);
        let inbound = runtime
            .plan_inbound(first.public_port(), remote(1), TEST_REMOTE_PORT, 30)
            .unwrap();
        runtime.commit_inbound(inbound, 30).unwrap();
        // Another host has its own budget.
        for index in 0..3 {
            outbound(&mut runtime, INTERNAL2, 1_000, remote(index), 40).unwrap();
        }
        assert_eq!(
            outbound(&mut runtime, INTERNAL2, 1_000, remote(9), 40).map(|_| ()),
            Err(Nat44UdpPlanError::HostPeerQuotaExceeded)
        );
        assert_eq!(host_peers(&runtime, INTERNAL), 3);
        assert_eq!(host_peers(&runtime, INTERNAL2), 3);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// A host recovers the moment one of its counted mappings expires: its
/// (dead) peers stop counting and the new peer is admitted in the same
/// commit; the expired mapping keeps its slot, port, and chain until the
/// table reuses them, and still counts toward the mapping limit.
#[test]
fn udp_host_peer_quota_recovers_when_a_counted_mapping_expires() {
    let policy = peer_policy(3).with_mappings_per_host(4);
    with_port_config(policy, 40_000, 40_063, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 8];
        let mut peers = [Nat44UdpPeerSlot::default(); 16];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        // Another host's mapping expires first, so the table parks it (not
        // the host's) when the admitted peer needs a slot.
        outbound(&mut runtime, INTERNAL2, 1_000, remote(1), 0).unwrap();
        let old = outbound(&mut runtime, INTERNAL, 1_000, remote(1), 1).unwrap();
        outbound(&mut runtime, INTERNAL, 1_000, remote(2), 1).unwrap();
        let young = outbound(&mut runtime, INTERNAL, 1_001, remote(3), 1_000).unwrap();
        assert_eq!(
            outbound(&mut runtime, INTERNAL, 1_001, remote(4), TTL).map(|_| ()),
            Err(Nat44UdpPlanError::HostPeerQuotaExceeded)
        );
        let admitted = outbound(&mut runtime, INTERNAL, 1_001, remote(4), TTL + 1).unwrap();
        assert_eq!(admitted.host_peer_reclaim(), Some(old.mapping_index()));
        assert!(admitted.peer_created && !admitted.mapping_created);
        assert_eq!(admitted.mapping_index(), young.mapping_index());
        // The expired mapping no longer counts its two dead peers, but it
        // still owns its port and its chain.
        assert_eq!(host_peers(&runtime, INTERNAL), 2);
        let expired = runtime.mappings[old.mapping_index()];
        assert!(expired.port_owned && expired.link.list == UdpMappingList::Lru);
        assert!(expired.link.peers.head().is_some());
        let host = runtime.hosts.find(INTERNAL).unwrap().unwrap();
        assert_eq!(runtime.hosts.count(host), 2);
        assert_eq!(runtime.hosts.cursor(host), Some(young.mapping_index()));
        assert_eq!(live_peers(&runtime, INTERNAL, TTL + 1), 2);
        assert_eq!(runtime.validate_indexes(), Ok(()));
        // A new mapping is admitted too (its peer fits); the host is then at
        // its limit again, so the expired endpoint's return (a new
        // generation with a new peer) is refused.
        outbound(&mut runtime, INTERNAL, 1_002, remote(5), TTL + 1).unwrap();
        assert_eq!(host_peers(&runtime, INTERNAL), 3);
        assert_eq!(
            outbound(&mut runtime, INTERNAL, 1_000, remote(1), TTL + 1).map(|_| ()),
            Err(Nat44UdpPlanError::HostPeerQuotaExceeded)
        );
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// Inbound packets never keep a host at its peer limit: UDP mappings (and
/// so their peers) live only by outbound packets, so a remote that keeps
/// sending to the host's public ports cannot hold the host's budget past
/// the idle timeout of the host's last outbound packet.
#[test]
fn inbound_traffic_cannot_hold_a_hosts_peer_budget() {
    with_port_config(peer_policy(2), 40_000, 40_063, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 8];
        let mut peers = [Nat44UdpPeerSlot::default(); 16];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        let first = outbound(&mut runtime, INTERNAL, 1_000, remote(1), 0).unwrap();
        outbound(&mut runtime, INTERNAL, 1_000, remote(2), 0).unwrap();
        let mut now = 0;
        while now + TTL / 4 < TTL {
            now += TTL / 4;
            for peer in [remote(1), remote(2)] {
                let plan = runtime
                    .plan_inbound(first.public_port(), peer, TEST_REMOTE_PORT, now)
                    .unwrap();
                runtime.commit_inbound(plan, now).unwrap();
            }
            assert_eq!(
                outbound(&mut runtime, INTERNAL, 1_001, remote(3), now).map(|_| ()),
                Err(Nat44UdpPlanError::HostPeerQuotaExceeded)
            );
        }
        let admitted = outbound(&mut runtime, INTERNAL, 1_001, remote(3), TTL).unwrap();
        assert!(admitted.mapping_created && admitted.peer_created);
        assert_eq!(host_peers(&runtime, INTERNAL), 1);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// Parking and reuse keep the count exact: when the table parks a host's
/// expired mapping (its peers go to the stale chain) or reuses its slot for
/// another host, the host's count drops by that mapping's peers, and a
/// flush forgets every count.
#[test]
fn parking_reuse_and_flush_release_a_hosts_peers() {
    with_port_config(peer_policy(4), 40_000, 40_063, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 2];
        let mut peers = [Nat44UdpPeerSlot::default(); 4];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        let old = outbound(&mut runtime, INTERNAL, 1_000, remote(1), 0).unwrap();
        outbound(&mut runtime, INTERNAL, 1_000, remote(2), 0).unwrap();
        outbound(&mut runtime, INTERNAL2, 1_000, remote(1), 10).unwrap();
        outbound(&mut runtime, INTERNAL2, 1_000, remote(2), 10).unwrap();
        assert_eq!(host_peers(&runtime, INTERNAL), 2);
        // The peer table is full; another host's new peer takes the expired
        // head's first peer, parking that mapping.
        let parked = outbound(&mut runtime, INTERNAL2, 1_000, remote(3), TTL).unwrap();
        assert!(parked.peer_created);
        assert_eq!(
            runtime.mappings[old.mapping_index()].link.list,
            UdpMappingList::Parked
        );
        assert_eq!(host_peers(&runtime, INTERNAL), 0);
        assert_eq!(host_peers(&runtime, INTERNAL2), 3);
        assert_eq!(runtime.validate_indexes(), Ok(()));
        // A third host reuses the parked slot.
        let reused = outbound(&mut runtime, host(7), 1_000, remote(1), TTL + 5).unwrap();
        assert_eq!(reused.mapping_index(), old.mapping_index());
        assert_eq!(host_peers(&runtime, INTERNAL), 0);
        assert_eq!(host_peers(&runtime, host(7)), 1);
        assert_eq!(runtime.validate_indexes(), Ok(()));
        runtime.reconcile(config, rotated_udp_hash_key()).unwrap();
        assert_eq!(host_peers(&runtime, INTERNAL2), 0);
        assert_eq!(host_peers(&runtime, host(7)), 0);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// Seeded churn of several hosts' endpoints and remotes against small
/// tables, checked after every packet against a full scan of the peer
/// slots (computed from the slots, not an independent NAT model):
///
/// - a new peer is refused as `HostPeerQuotaExceeded` only when the scan
///   finds at least `limit` peers on the host's live mappings, and a peer
///   the runtime creates was admitted only below that;
/// - the host's count never exceeds the limit, never undercounts its live
///   peers, and never exceeds the peers still chained to its mappings;
/// - the full index validation (uncounted prefix, cursor, per-mapping peer
///   counts and their sums) holds.
///
/// Half the seeds also set a mapping limit, some use filtering that keys
/// peers by remote port, and the small peer table forces parking.
#[test]
fn udp_host_peer_quota_matches_a_full_scan_under_seeded_churn() {
    const LIMIT: u16 = 4;
    let mut outcomes = [0_usize; 5];
    for seed in 1..=24_u64 {
        let hosts = if seed % 3 == 0 { 9 } else { 4 };
        let filtering = [
            Nat44Filtering::AddressDependent,
            Nat44Filtering::EndpointIndependent,
            Nat44Filtering::AddressAndPortDependent,
        ][(seed % 3) as usize];
        let policy = peer_policy(LIMIT)
            .with_mappings_per_host(if seed % 2 == 0 { 3 } else { 0 })
            .with_filtering(filtering);
        with_port_config(policy, 40_000, 40_011, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 10];
            let mut peers = [Nat44UdpPeerSlot::default(); 20];
            let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            let mut random = seed;
            let mut now = 0_u64;
            for _ in 0..3_000 {
                now += next_random(&mut random) % (TTL / 6);
                let address = host((next_random(&mut random) as usize) % hosts);
                let port = 40_000 + (next_random(&mut random) % 4) as u16;
                let peer = remote((next_random(&mut random) % 6) as usize);
                let remote_port = 50 + (next_random(&mut random) % 2) as u16;
                let live = live_peers(&runtime, address, now);
                let result = runtime
                    .plan_outbound(address, port, peer, remote_port, now)
                    .inspect_err(|error| runtime.record_plan_error(*error));
                match result {
                    Err(Nat44UdpPlanError::HostPeerQuotaExceeded) => {
                        assert!(live >= usize::from(LIMIT), "seed {seed}");
                        outcomes[0] += 1;
                    }
                    Err(error) => {
                        assert!(
                            matches!(
                                error,
                                Nat44UdpPlanError::HostQuotaExceeded
                                    | Nat44UdpPlanError::MappingFull
                                    | Nat44UdpPlanError::PeerFull
                                    | Nat44UdpPlanError::PortExhausted
                            ),
                            "seed {seed}: {error:?}"
                        );
                        outcomes[1] += 1;
                    }
                    Ok(plan) => {
                        if plan.peer_created {
                            assert!(live < usize::from(LIMIT), "seed {seed}");
                            outcomes[2] += 1;
                        }
                        if plan.host_peer_reclaim().is_some() {
                            outcomes[3] += 1;
                        }
                        runtime.commit_outbound(plan, now).unwrap();
                    }
                }
                // Some remotes answer.
                if next_random(&mut random).is_multiple_of(3) {
                    if let Ok(Some((_, mapping))) = runtime.find_mapping(address, port) {
                        if let Ok(plan) =
                            runtime.plan_inbound(mapping.public_port, peer, remote_port, now)
                        {
                            runtime.commit_inbound(plan, now).unwrap();
                            outcomes[4] += 1;
                        }
                    }
                }
                for index in 0..hosts {
                    let address = host(index);
                    let counted = host_peers(&runtime, address);
                    assert!(counted <= usize::from(LIMIT), "seed {seed}");
                    assert!(live_peers(&runtime, address, now) <= counted, "seed {seed}");
                    assert!(counted <= chained_peers(&runtime, address), "seed {seed}");
                }
                assert_eq!(runtime.validate_indexes(), Ok(()), "seed {seed}");
            }
        });
    }
    // Every branch is exercised by the fixed seeds.
    assert!(outcomes.iter().all(|count| *count > 0), "{outcomes:?}");
}

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Constant work in a full 65536-slot table: 4096 hosts with 16 peers
/// each (one mapping and 16 remotes) at a limit of 16 hold every peer slot;
/// a refused new peer costs one liveness check of the host's cursor and no
/// host lookup (a live mapping finds its host through its link), and after
/// expiry the admitted peer stops counting the cursor's peers in O(1).
#[test]
fn udp_host_peer_quota_work_is_constant_in_a_full_65536_slot_table() {
    const SLOTS: usize = 65_536;
    const LIMIT: usize = 16;
    with_port_config(peer_policy(LIMIT as u16), 1, 65_535, |config| {
        let mut mappings = vec![Nat44UdpMappingSlot::default(); SLOTS];
        let mut peers = vec![Nat44UdpPeerSlot::default(); SLOTS];
        let mut indexes = TestNat44UdpIndexes::new(config, SLOTS, SLOTS);
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        runtime.skip_commit_validation.set(true);
        let address = |host: usize| {
            Ipv4Address::from_octets([10, 1 + (host >> 16) as u8, (host >> 8) as u8, host as u8])
        };
        for flow in 0..SLOTS {
            let plan = runtime
                .plan_outbound(
                    address(flow / LIMIT),
                    1,
                    remote(flow % LIMIT),
                    TEST_REMOTE_PORT,
                    0,
                )
                .unwrap();
            runtime.commit_outbound(plan, 0).unwrap();
        }
        let mut worst = [0_usize; 3];
        let mut flow_work = |runtime: &mut Nat44UdpRuntime<'_>, host: usize, now: u64| {
            runtime.reset_index_probe_counts();
            runtime.take_reuse_visits();
            runtime.hosts.take_lookup_probes();
            let finds = runtime.hosts.finds();
            let result = runtime
                .plan_outbound(address(host), 1, remote(99), TEST_REMOTE_PORT, now)
                .map(|plan| runtime.commit_outbound(plan, now).unwrap());
            let (mapping_probes, peer_probes, _) = runtime.index_probe_counts();
            let seen = [
                runtime.take_reuse_visits(),
                runtime.hosts.finds() - finds,
                mapping_probes + peer_probes,
            ];
            for (worst, seen) in worst.iter_mut().zip(seen) {
                *worst = (*worst).max(seen);
            }
            result
        };
        for host in (0..4_096).step_by(97) {
            assert_eq!(
                flow_work(&mut runtime, host, 1),
                Err(Nat44UdpPlanError::HostPeerQuotaExceeded)
            );
        }
        // Every mapping expires at `TTL`: a new mapping of the host needs a
        // peer, which the expired activity head supplies; the host's own
        // expired mapping stops counting its 16 peers.
        for host in (0..4_096).step_by(97) {
            flow_work(&mut runtime, host, TTL).unwrap();
            let slot = runtime.hosts.find(address(host)).unwrap().unwrap();
            assert!(runtime.hosts.members(slot) <= 1);
        }
        assert!(
            worst[0] <= 4 && worst[1] <= 2 && worst[2] <= 8,
            "work per new peer {worst:?}"
        );
        assert!(runtime.reuse_lists_are_consistent());
    });
}

/// Review sec M1, documented behaviour (NAT44-125): under endpoint-
/// independent filtering an inside host that runs a UDP responder (a game
/// or SIP server, a P2P node) answers whatever remote reaches its public
/// port, and each answer to a new remote is a new filter peer that counts.
/// Remotes (or spoofed sources) can therefore spend the host's whole peer
/// budget, after which the host's own new peers, its DNS client included,
/// are refused while it keeps answering. Under address-dependent filtering
/// (the default) the same packets are filtered before the host sees them,
/// so its budget is untouched. The runbook advises against EIF together
/// with `peers-per-host` for hosts that run UDP services.
#[test]
fn zz_sec_eif_responder_lets_remote_spend_peer_budget() {
    for filtering in [
        Nat44Filtering::EndpointIndependent,
        Nat44Filtering::AddressDependent,
    ] {
        let policy = peer_policy(4).with_filtering(filtering);
        with_port_config(policy, 40_000, 40_063, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 8];
            let mut peers = [Nat44UdpPeerSlot::default(); 16];
            let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            // The responder registers with its server, opening its mapping.
            let server = outbound(&mut runtime, INTERNAL, 5_060, remote(0), 0).unwrap();
            // Strangers send to the public port; the host answers each.
            for index in 1..8 {
                let stranger = remote(index);
                if let Ok(plan) =
                    runtime.plan_inbound(server.public_port(), stranger, TEST_REMOTE_PORT, 1)
                {
                    runtime.commit_inbound(plan, 1).unwrap();
                    let _ = outbound(&mut runtime, INTERNAL, 5_060, stranger, 1);
                }
            }
            let dns = outbound(&mut runtime, INTERNAL, 53_000, remote(99), 2).map(|_| ());
            if filtering == Nat44Filtering::EndpointIndependent {
                assert_eq!(host_peers(&runtime, INTERNAL), 4);
                assert_eq!(dns, Err(Nat44UdpPlanError::HostPeerQuotaExceeded));
            } else {
                assert_eq!(dns, Ok(()));
                assert_eq!(host_peers(&runtime, INTERNAL), 2);
            }
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
    }
}
