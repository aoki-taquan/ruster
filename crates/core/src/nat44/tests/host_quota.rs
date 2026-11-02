//! Per-internal-host mapping quota of the UDP NAT (N3, NAT44-092, RFC 6888
//! REQ-4): refusal at the limit without state change, recovery by expiry
//! through the host's own mapping, the counter invariant under churn
//! against a full scan of the slots, and constant work in a full table.

use super::*;

const TTL: u64 = NAT44_UDP_MIN_IDLE_TTL_MS;

fn quota_policy(limit: u16) -> Nat44UdpPolicy {
    Nat44UdpPolicy::new(TTL, 0)
        .unwrap()
        .with_mappings_per_host(limit)
}

fn host(index: usize) -> Ipv4Address {
    Ipv4Address::from_octets([10, 0, (index >> 8) as u8, index as u8])
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

/// Mappings of `address` that count (occupied and owning a port) and
/// those that are live at `now`, by a full scan of the slots.
fn scan(runtime: &Nat44UdpRuntime<'_>, address: Ipv4Address, now: u64) -> (usize, usize) {
    let mut counted = 0;
    let mut live = 0;
    for mapping in runtime.mappings.iter().copied() {
        if mapping.occupied && mapping.internal_address == address {
            counted += usize::from(mapping.port_owned);
            live += usize::from(runtime.mapping_is_live(mapping, now));
        }
    }
    (counted, live)
}

fn host_count(runtime: &Nat44UdpRuntime<'_>, address: Ipv4Address) -> usize {
    runtime
        .hosts
        .find(address)
        .unwrap()
        .map_or(0, |host| runtime.hosts.count(host))
}

/// At the limit a new mapping is refused before any state changes, nothing
/// is evicted, and the host's existing mappings keep working: refreshes,
/// new peers on them, and inbound packets. Another host is unaffected.
#[test]
fn udp_host_quota_refuses_at_the_limit_without_state_change() {
    with_port_config(quota_policy(3), 40_000, 40_063, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 8];
        let mut peers = [Nat44UdpPeerSlot::default(); 16];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        let ports: Vec<u16> = (0..3)
            .map(|index| {
                outbound(&mut runtime, INTERNAL, 1_000 + index, REMOTE1, 10)
                    .unwrap()
                    .public_port()
            })
            .collect();
        assert_eq!(host_count(&runtime, INTERNAL), 3);
        let mappings_before = runtime.mappings.to_vec();
        let peers_before = runtime.peers.to_vec();
        let revision = runtime.state_revision;
        assert_eq!(
            outbound(&mut runtime, INTERNAL, 1_003, REMOTE1, 20).map(|_| ()),
            Err(Nat44UdpPlanError::HostQuotaExceeded)
        );
        // Retransmissions are refused the same way; nothing changed.
        assert_eq!(
            outbound(&mut runtime, INTERNAL, 1_003, REMOTE2, 20).map(|_| ()),
            Err(Nat44UdpPlanError::HostQuotaExceeded)
        );
        assert_eq!(runtime.counters().host_quota_exceeded, 2);
        assert_eq!(runtime.mappings, &mappings_before[..]);
        assert_eq!(runtime.peers, &peers_before[..]);
        // `observe_now` advanced the revision for the new time only.
        assert_eq!(runtime.state_revision, revision + 1);
        // Existing mappings: refresh, a new peer, and inbound.
        outbound(&mut runtime, INTERNAL, 1_000, REMOTE1, 30).unwrap();
        let plan = outbound(&mut runtime, INTERNAL, 1_001, REMOTE2, 30).unwrap();
        assert!(!plan.mapping_created && plan.peer_created);
        let inbound = runtime
            .plan_inbound(ports[2], REMOTE1, TEST_REMOTE_PORT, 30)
            .unwrap();
        runtime.commit_inbound(inbound, 30).unwrap();
        // Another host has its own quota.
        for index in 0..3 {
            outbound(&mut runtime, INTERNAL2, 1_000 + index, REMOTE1, 40).unwrap();
        }
        assert_eq!(
            outbound(&mut runtime, INTERNAL2, 1_003, REMOTE1, 40).map(|_| ()),
            Err(Nat44UdpPlanError::HostQuotaExceeded)
        );
        assert_eq!(host_count(&runtime, INTERNAL), 3);
        assert_eq!(host_count(&runtime, INTERNAL2), 3);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// Expiry frees quota with no manual action: one tick before the oldest
/// mapping of the host expires a new mapping is refused; from its expiry
/// the new mapping reclaims exactly that slot (with a newly selected port), not the slot
/// or port of another host's expired mapping (even an older one).
#[test]
fn udp_host_quota_recovers_by_reclaiming_the_hosts_own_expired_mapping() {
    with_port_config(quota_policy(2), 40_000, 40_063, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 8];
        let mut peers = [Nat44UdpPeerSlot::default(); 8];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        // Another host's mapping, expiring first.
        let other = outbound(&mut runtime, INTERNAL2, 1_000, REMOTE1, 0).unwrap();
        let oldest = outbound(&mut runtime, INTERNAL, 1_000, REMOTE1, 100).unwrap();
        outbound(&mut runtime, INTERNAL, 1_001, REMOTE1, 200).unwrap();
        assert_eq!(
            outbound(&mut runtime, INTERNAL, 1_002, REMOTE1, 100 + TTL - 1).map(|_| ()),
            Err(Nat44UdpPlanError::HostQuotaExceeded)
        );
        let reclaimed = outbound(&mut runtime, INTERNAL, 1_002, REMOTE1, 100 + TTL).unwrap();
        assert!(reclaimed.mapping_created && reclaimed.mapping_expired);
        assert_eq!(reclaimed.mapping_index(), oldest.mapping_index());
        // The port comes from the normal selection (N2), not the reclaimed
        // mapping's: here the keyed search finds a free port, and the
        // reclaimed mapping's old port is released.
        assert_ne!(reclaimed.public_port(), oldest.public_port());
        assert_eq!(reclaimed.displaced_port_mapping_index(), None);
        assert_eq!(runtime.port_owners.owner(oldest.public_port()), Ok(None));
        // The other host's expired mapping keeps its slot and port.
        let untouched = runtime.mappings[other.mapping_index()];
        assert!(untouched.port_owned && untouched.internal_address == INTERNAL2);
        assert_eq!(untouched.public_port, other.public_port());
        assert_eq!(host_count(&runtime, INTERNAL), 2);
        assert_eq!(host_count(&runtime, INTERNAL2), 1);
        // The reclaimed endpoint's old mapping is gone; it would need quota.
        assert_eq!(
            outbound(&mut runtime, INTERNAL, 1_000, REMOTE1, 100 + TTL).map(|_| ()),
            Err(Nat44UdpPlanError::HostQuotaExceeded)
        );
        assert_eq!(runtime.counters().mappings_expired, 1);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// A returning endpoint whose own expired mapping still holds its port is
/// recreated in place even when the host is at its limit and its other
/// mappings are live: the count does not change (EIM, NAT44-004 step 2).
#[test]
fn udp_returning_endpoint_at_the_limit_recreates_its_own_mapping() {
    with_port_config(quota_policy(2), 40_000, 40_063, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 4];
        let mut peers = [Nat44UdpPeerSlot::default(); 4];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        let first = outbound(&mut runtime, INTERNAL, 1_000, REMOTE1, 0).unwrap();
        let second = outbound(&mut runtime, INTERNAL, 1_001, REMOTE1, 1_000).unwrap();
        let back = outbound(&mut runtime, INTERNAL, 1_000, REMOTE2, TTL).unwrap();
        assert!(back.mapping_created && back.mapping_expired);
        assert_eq!(back.mapping_index(), first.mapping_index());
        assert_eq!(back.public_port(), first.public_port());
        assert_eq!(host_count(&runtime, INTERNAL), 2);
        assert_eq!(runtime.counters().host_quota_exceeded, 0);
        assert_eq!(runtime.validate_indexes(), Ok(()));
        // `second` is refreshed after `first`; once both have expired,
        // `second` returns while `first` is the host's oldest expired
        // mapping: `second` still gets its own slot and port back, and
        // `first` keeps its own.
        outbound(&mut runtime, INTERNAL, 1_001, REMOTE1, TTL + 5).unwrap();
        let now = TTL + 5 + TTL;
        let again = outbound(&mut runtime, INTERNAL, 1_001, REMOTE2, now).unwrap();
        assert_eq!(again.mapping_index(), second.mapping_index());
        assert_eq!(again.public_port(), second.public_port());
        let first_slot = runtime.mappings[first.mapping_index()];
        assert!(first_slot.port_owned && first_slot.public_port == first.public_port());
        assert!(!runtime.mapping_is_live(first_slot, now));
        assert_eq!(host_count(&runtime, INTERNAL), 2);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// The rare at-limit return: an endpoint of a host at its limit whose own
/// mapping was retired (another mapping took its port) comes back while the
/// host's oldest counted mapping has expired. The retired slot is recreated
/// in place for the endpoint (no duplicate key), the expired mapping gives up
/// its port to it and is retired, and the host's count stays at the limit.
#[test]
fn udp_retired_endpoint_at_the_limit_takes_the_hosts_expired_port() {
    let host_a = host(1);
    let host_b = host(2);
    let host_c = host(3);
    with_port_config(quota_policy(2), 40_000, 40_063, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 8];
        let mut peers = [Nat44UdpPeerSlot::default(); 16];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        // A's endpoint 40000 and C's 40001 keep their ports (preservation);
        // B's endpoints with the same internal ports get keyed ports.
        let returning = outbound(&mut runtime, host_a, 40_000, REMOTE1, 0).unwrap();
        let oldest = outbound(&mut runtime, host_a, 5, REMOTE1, 0).unwrap();
        outbound(&mut runtime, host_c, 40_001, REMOTE1, 0).unwrap();
        outbound(&mut runtime, host_b, 40_001, REMOTE1, 0).unwrap();
        outbound(&mut runtime, host_b, 40_000, REMOTE1, 0).unwrap();
        assert_eq!(returning.public_port(), 40_000);
        // Everything expired: B's endpoints return and take their internal
        // ports back, retiring C's mapping and then A's endpoint 40000.
        outbound(&mut runtime, host_b, 40_001, REMOTE1, TTL).unwrap();
        outbound(&mut runtime, host_b, 40_000, REMOTE1, TTL).unwrap();
        let retired = runtime.mappings[returning.mapping_index()];
        assert!(retired.occupied && !retired.port_owned);
        assert_eq!(host_count(&runtime, host_a), 1);
        // A refills to its limit; the new mapping takes C's retired slot.
        let refill = outbound(&mut runtime, host_a, 6, REMOTE1, TTL).unwrap();
        assert_ne!(refill.mapping_index(), returning.mapping_index());
        assert_eq!(host_count(&runtime, host_a), 2);
        // A's retired endpoint returns at the limit.
        let back = outbound(&mut runtime, host_a, 40_000, REMOTE2, TTL).unwrap();
        assert!(back.mapping_created);
        assert_eq!(back.mapping_index(), returning.mapping_index());
        assert_eq!(back.public_port(), oldest.public_port());
        assert_eq!(
            back.displaced_port_mapping_index(),
            Some(oldest.mapping_index())
        );
        assert!(!runtime.mappings[oldest.mapping_index()].port_owned);
        assert_eq!(host_count(&runtime, host_a), 2);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// A reconcile flush forgets every host; the limit `0` is unlimited; and a
/// runtime refuses a limit without per-host storage, at construction and at
/// reconcile.
#[test]
fn udp_host_quota_flush_unlimited_and_storage_requirement() {
    with_port_config(quota_policy(1), 40_000, 40_063, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 4];
        let mut peers = [Nat44UdpPeerSlot::default(); 4];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        outbound(&mut runtime, INTERNAL, 1_000, REMOTE1, 0).unwrap();
        assert_eq!(
            outbound(&mut runtime, INTERNAL, 1_001, REMOTE1, 0).map(|_| ()),
            Err(Nat44UdpPlanError::HostQuotaExceeded)
        );
        runtime.reconcile(config, rotated_udp_hash_key()).unwrap();
        assert_eq!(runtime.hosts.host_counts(), (0, 0));
        outbound(&mut runtime, INTERNAL, 1_001, REMOTE1, 0).unwrap();
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
    with_port_config(quota_policy(0), 40_000, 40_063, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 8];
        let mut peers = [Nat44UdpPeerSlot::default(); 8];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        for port in 0..8 {
            outbound(&mut runtime, INTERNAL, 1_000 + port, REMOTE1, 0).unwrap();
        }
        // Accounting still runs (the storage is there); only the limit is off.
        assert_eq!(host_count(&runtime, INTERNAL), 8);
        assert_eq!(runtime.counters().host_quota_exceeded, 0);
    });
    with_port_config(quota_policy(1), 40_000, 40_001, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 1];
        let mut peers = [Nat44UdpPeerSlot::default(); 1];
        let mut mapping_buckets = [DirectoryBucket::default(); 1];
        let mut mapping_nodes = [DirectoryNode::default(); 1];
        let mut peer_buckets = [DirectoryBucket::default(); 1];
        let mut peer_nodes = [DirectoryNode::default(); 1];
        let mut owners = [PortOwnerSlot::default(); 2];
        let mut owner_bits = vec![0_u64; crate::port_free_bitmap_words(2)];
        let storage = Nat44UdpIndexStorage::new(
            &mut mapping_buckets,
            &mut mapping_nodes,
            &mut peer_buckets,
            &mut peer_nodes,
            &mut owners,
            &mut owner_bits,
            Nat44HostStorage::disabled(),
        );
        assert!(matches!(
            Nat44UdpRuntime::new(
                config,
                &mut mappings,
                &mut peers,
                storage,
                test_udp_hash_key()
            ),
            Err(Nat44UdpRuntimeConfigError::HostTableInvalid)
        ));
    });
    with_port_config(Nat44UdpPolicy::default(), 40_000, 40_001, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 1];
        let mut peers = [Nat44UdpPeerSlot::default(); 1];
        let mut mapping_buckets = [DirectoryBucket::default(); 1];
        let mut mapping_nodes = [DirectoryNode::default(); 1];
        let mut peer_buckets = [DirectoryBucket::default(); 1];
        let mut peer_nodes = [DirectoryNode::default(); 1];
        let mut owners = [PortOwnerSlot::default(); 2];
        let mut owner_bits = vec![0_u64; crate::port_free_bitmap_words(2)];
        let mut runtime = Nat44UdpRuntime::new(
            config,
            &mut mappings,
            &mut peers,
            Nat44UdpIndexStorage::new(
                &mut mapping_buckets,
                &mut mapping_nodes,
                &mut peer_buckets,
                &mut peer_nodes,
                &mut owners,
                &mut owner_bits,
                Nat44HostStorage::disabled(),
            ),
            test_udp_hash_key(),
        )
        .unwrap();
        outbound(&mut runtime, INTERNAL, 1_000, REMOTE1, 0).unwrap();
        assert_eq!(runtime.validate_indexes(), Ok(()));
        // Without per-host storage (limit 0) no host lookup is made at all.
        assert_eq!(runtime.hosts.finds(), 0);
        let limited = with_port_config(quota_policy(4), 40_000, 40_001, |limited| limited);
        assert_eq!(
            runtime
                .preflight_reconcile(limited, rotated_udp_hash_key())
                .map(|_| ()),
            Err(Nat44UdpReconcileError::HostTableMissing)
        );
        // Unchanged by the refusal.
        assert!(runtime.mappings[0].occupied);
    });
}

/// Seeded churn of several hosts' endpoints against a small pool and table,
/// checked after every packet against a full scan of the mapping slots (a
/// reference computed from the slots, not an independent NAT model):
///
/// - a new mapping is refused as `HostQuotaExceeded` exactly when the scan
///   finds `limit` live mappings of its host (and is never refused for a
///   host below that);
/// - the host table's count of each host equals the scanned number of its
///   mappings that own a port, which never exceeds the limit;
/// - the full index validation (host lists, empty list, directory) holds.
///
/// A third of the seeds use more hosts than mapping slots, so the host
/// table fills; the test requires that a new host then arrives while every
/// host slot holds a mapping (it takes the slot of the host whose last
/// mapping the commit reclaims). The rarer at-limit return of an endpoint
/// whose mapping was retired has its own directed test.
#[test]
fn udp_host_quota_matches_a_full_scan_of_the_slots_under_seeded_churn() {
    const LIMIT: u16 = 3;
    let mut full_table_new_hosts = 0_usize;
    for seed in 1..=24_u64 {
        let hosts = if seed % 3 == 0 { 14 } else { 5 };
        let policy = quota_policy(LIMIT).with_port_preservation(seed % 2 == 0);
        // 12 ports for 10 slots: takeovers, retirements, and exhaustion.
        with_port_config(policy, 40_000, 40_011, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 10];
            let mut peers = [Nat44UdpPeerSlot::default(); 24];
            let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            let mut random = seed;
            let mut now = 0_u64;
            let mut outcomes = [0_usize; 4];
            for _ in 0..3_000 {
                now += next_random(&mut random) % (TTL / 8);
                let address = host((next_random(&mut random) as usize) % hosts);
                let port = 40_000 + (next_random(&mut random) % 6) as u16;
                let remote =
                    Ipv4Address::from_octets([198, 51, 100, (next_random(&mut random) % 3) as u8]);
                let exact_live = runtime
                    .find_mapping(address, port)
                    .unwrap()
                    .is_some_and(|(_, mapping)| runtime.mapping_is_live(mapping, now));
                let (_, live) = scan(&runtime, address, now);
                let host_slot = runtime.hosts.find(address).unwrap();
                let (allocated, with_mappings) = runtime.hosts.host_counts();
                let table_full = allocated == runtime.mappings.len() && with_mappings == allocated;
                let result = outbound(&mut runtime, address, port, remote, now);
                if result.is_ok() && host_slot.is_none() && table_full {
                    full_table_new_hosts += 1;
                }
                match result {
                    Err(Nat44UdpPlanError::HostQuotaExceeded) => {
                        assert!(!exact_live && live >= usize::from(LIMIT), "seed {seed}");
                        outcomes[0] += 1;
                    }
                    Err(error) => {
                        assert!(
                            matches!(
                                error,
                                Nat44UdpPlanError::MappingFull
                                    | Nat44UdpPlanError::PeerFull
                                    | Nat44UdpPlanError::PortExhausted
                            ),
                            "seed {seed}: {error:?}"
                        );
                        assert!(exact_live || live < usize::from(LIMIT));
                        outcomes[1] += 1;
                    }
                    Ok(plan) if plan.mapping_created => {
                        assert!(live < usize::from(LIMIT) || plan.mapping_expired);
                        outcomes[2] += 1;
                    }
                    Ok(_) => outcomes[3] += 1,
                }
                for index in 0..hosts {
                    let (counted, live) = scan(&runtime, host(index), now);
                    assert_eq!(host_count(&runtime, host(index)), counted, "seed {seed}");
                    assert!(counted <= usize::from(LIMIT) && live <= counted);
                }
            }
            assert_eq!(runtime.validate_indexes(), Ok(()));
            // Every branch is exercised by the fixed seeds.
            assert!(outcomes.iter().all(|count| *count > 0), "{outcomes:?}");
        });
    }
    assert!(full_table_new_hosts > 0);
}

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// Constant work in a full 65536-slot table: every port taken by 4095
/// hosts at a limit of 16, a new flow of a host at its limit is refused
/// with one host lookup and one head liveness check, and after expiry a new
/// flow reclaims the host's own mapping with the usual bounded port work.
#[test]
fn udp_host_quota_work_is_constant_in_a_full_65536_slot_table() {
    const SLOTS: usize = 65_536;
    const LIMIT: usize = 16;
    let policy = Nat44UdpPolicy::new(TTL, 0)
        .unwrap()
        .with_mappings_per_host(LIMIT as u16);
    with_port_config(policy, 1, 65_535, |config| {
        let mut mappings = vec![Nat44UdpMappingSlot::default(); SLOTS];
        let mut peers = vec![Nat44UdpPeerSlot::default(); SLOTS];
        let mut indexes = TestNat44UdpIndexes::new(config, SLOTS, SLOTS);
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        runtime.skip_commit_validation.set(true);
        let address = |host: usize| {
            Ipv4Address::from_octets([10, 1 + (host >> 16) as u8, (host >> 8) as u8, host as u8])
        };
        // 4095 hosts x 16 mappings plus one host with 15: 65535 ports.
        for flow in 0..65_535 {
            let plan = runtime
                .plan_outbound(
                    address(flow / LIMIT),
                    (flow % LIMIT) as u16 + 1,
                    REMOTE1,
                    TEST_REMOTE_PORT,
                    0,
                )
                .unwrap();
            runtime.commit_outbound(plan, 0).unwrap();
        }
        let mut worst = [0_usize; 4];
        let mut flow_work = |runtime: &mut Nat44UdpRuntime<'_>, host: usize, now: u64| {
            runtime.reset_index_probe_counts();
            runtime.hosts.take_lookup_probes();
            let result = runtime
                .plan_outbound(address(host), 100, REMOTE2, TEST_REMOTE_PORT, now)
                .map(|plan| runtime.commit_outbound(plan, now).unwrap());
            let (_, _, owner_probes) = runtime.index_probe_counts();
            let seen = [
                runtime.take_reuse_visits(),
                owner_probes,
                runtime.port_owners.take_bitmap_word_reads(),
                runtime.hosts.take_lookup_probes(),
            ];
            for (worst, seen) in worst.iter_mut().zip(seen) {
                *worst = (*worst).max(seen);
            }
            result
        };
        for host in (0..4_095).step_by(97) {
            assert_eq!(
                flow_work(&mut runtime, host, 1),
                Err(Nat44UdpPlanError::HostQuotaExceeded)
            );
        }
        for host in (0..4_095).step_by(97) {
            flow_work(&mut runtime, host, TTL).unwrap();
        }
        // Reclaiming selects a port the normal bounded way (every pool port
        // is owned here, so keyed takeover probes); the host lookups are
        // the plan's and the commit's.
        assert!(
            worst[0] <= 4
                && worst[1] <= 2 + NAT44_PORT_TAKEOVER_PROBES
                && worst[2] <= 34
                && worst[3] <= 6,
            "work per new flow {worst:?}"
        );
        assert!(runtime.reuse_lists_are_consistent());
        assert!(runtime.port_owners.bitmap_matches_slots());
    });
}
