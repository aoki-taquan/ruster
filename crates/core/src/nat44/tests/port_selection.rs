//! Keyed public-port selection of the UDP NAT (N2, NAT44-020): RFC 6056
//! Algorithm 3 adapted to endpoint-independent mapping, with the secret
//! runtime hash key, preservation on and off, and keyed takeover when every
//! pool port has an owner.

use super::*;

/// A distinct internal host per index (outside the pool's port range is
/// chosen by the callers, so port preservation does not apply).
fn host(index: usize) -> Ipv4Address {
    Ipv4Address::from_octets([10, (index >> 16) as u8, (index >> 8) as u8, index as u8])
}

fn outbound(
    runtime: &mut Nat44UdpRuntime<'_>,
    host: Ipv4Address,
    port: u16,
    now: u64,
) -> Result<u16, Nat44UdpPlanError> {
    let plan = runtime.plan_outbound(host, port, REMOTE1, TEST_REMOTE_PORT, now)?;
    runtime.commit_outbound(plan, now).unwrap();
    Ok(plan.mapping.public_port)
}

/// Pearson's chi-square statistic of `counts` against a uniform
/// distribution over its bins.
fn chi_square(counts: &[usize]) -> f64 {
    let total = counts.iter().sum::<usize>() as f64;
    let expected = total / counts.len() as f64;
    counts
        .iter()
        .map(|&count| {
            let delta = count as f64 - expected;
            delta * delta / expected
        })
        .sum()
}

/// Upper acceptance bound for a chi-square statistic with `bins - 1`
/// degrees of freedom: mean plus six standard deviations. The keys are
/// fixed, so each test is deterministic; the bound only documents how far
/// from uniform the fixed outcome may be.
fn chi_square_bound(bins: usize) -> f64 {
    let dof = (bins - 1) as f64;
    dof + 6.0 * (2.0 * dof).sqrt()
}

/// Number of consecutive values whose difference is exactly `+1` modulo
/// `pool` (the pattern of a sequential allocator or of a start that mixes
/// the endpoint in linearly).
fn sequential_steps(values: &[usize], pool: usize) -> usize {
    values
        .windows(2)
        .filter(|pair| (pair[0] + 1) % pool == pair[1])
        .count()
}

/// The search start is a keyed PRF of the internal endpoint: uniform over
/// the pool, without a sequential pattern for consecutive addresses or
/// ports (which the pre-N2 XOR mix had: consecutive addresses gave
/// consecutive starts), and unrelated across a key rotation.
#[test]
fn keyed_search_start_is_uniform_unsequential_and_rotates_with_the_key() {
    const POOL: usize = 256;
    const ENDPOINTS: usize = 65_536;
    with_port_config(Nat44UdpPolicy::default(), 40_000, 40_255, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 1];
        let mut peers = [Nat44UdpPeerSlot::default(); 1];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        let starts = |runtime: &Nat44UdpRuntime<'_>| {
            let key = runtime.port_selection_key();
            let by_address = (0..ENDPOINTS)
                .map(|index| key.search_start(host(index), 1_000))
                .collect::<Vec<_>>();
            let by_port = (0..ENDPOINTS)
                .map(|port| key.search_start(INTERNAL, port as u16))
                .collect::<Vec<_>>();
            (by_address, by_port)
        };
        let (by_address, by_port) = starts(&runtime);
        for values in [&by_address, &by_port] {
            let mut counts = [0_usize; POOL];
            for &start in values.iter() {
                assert!(start < POOL);
                counts[start] += 1;
            }
            let statistic = chi_square(&counts);
            assert!(
                statistic < chi_square_bound(POOL),
                "chi-square {statistic} over {POOL} bins"
            );
            // About ENDPOINTS / POOL = 256 sequential steps by chance.
            let sequential = sequential_steps(values, POOL);
            assert!(sequential < 2 * ENDPOINTS / POOL, "{sequential}");
        }

        runtime.reconcile(config, rotated_udp_hash_key()).unwrap();
        let (rotated_address, rotated_port) = starts(&runtime);
        for (before, after) in [(&by_address, &rotated_address), (&by_port, &rotated_port)] {
            // About ENDPOINTS / POOL = 256 agree by chance.
            let same = before.iter().zip(after).filter(|(a, b)| a == b).count();
            assert!(same < 2 * ENDPOINTS / POOL, "{same}");
        }
    });
}

/// The UDP runtime selects with its own key, its own hash domains, and its
/// configuration, and a reconcile switches to the new key.
#[test]
fn udp_port_selection_uses_the_udp_key_and_domains() {
    let policy = Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS, 3).unwrap();
    with_port_config(policy, 1, 65_535, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 1];
        let mut peers = [Nat44UdpPeerSlot::default(); 1];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        let udp = runtime.port_selection_key();
        assert_eq!(udp.key, test_udp_hash_key().0);
        assert_eq!(udp.start_domain, DirectoryHashDomain::UdpPortStart);
        assert_eq!(udp.takeover_domain, DirectoryHashDomain::UdpPortTakeover);
        assert_eq!(
            (
                udp.first_port,
                udp.last_port,
                udp.inside,
                udp.public_address
            ),
            (1, 65_535, INSIDE, PUBLIC)
        );
        assert_eq!(udp.allocator_seed, 3);
        runtime.reconcile(config, rotated_udp_hash_key()).unwrap();
        assert_eq!(runtime.port_selection_key().key, rotated_udp_hash_key().0);
    });
}

/// The UDP and TCP selections use separate hash domains (and the start and
/// the takeover probes separate domains of their own): with the same key
/// bits and endpoint they agree only by chance.
#[test]
fn port_selection_domains_are_separated() {
    let key = DirectoryHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap();
    let selection = |start_domain, takeover_domain| PortSelectionKey {
        key,
        start_domain,
        takeover_domain,
        first_port: 1,
        last_port: 65_535,
        inside: INSIDE,
        public_address: PUBLIC,
        allocator_seed: 7,
    };
    let udp = selection(
        DirectoryHashDomain::UdpPortStart,
        DirectoryHashDomain::UdpPortTakeover,
    );
    let tcp = selection(
        DirectoryHashDomain::TcpPortStart,
        DirectoryHashDomain::TcpPortTakeover,
    );
    let swapped = selection(
        DirectoryHashDomain::UdpPortTakeover,
        DirectoryHashDomain::UdpPortStart,
    );
    let mut same = [0_usize; 3];
    for index in 0..4_096 {
        let address = host(index);
        let start = udp.search_start(address, 1_000);
        same[0] += usize::from(start == tcp.search_start(address, 1_000));
        same[1] += usize::from(
            udp.takeover_port(address, 1_000, 1, 0, 0)
                == tcp.takeover_port(address, 1_000, 1, 0, 0),
        );
        same[2] += usize::from(start == swapped.search_start(address, 1_000));
    }
    assert!(same.iter().all(|&same| same <= 2), "{same:?}");
    // The allocator seed is an input too (an operator salt).
    let salted = PortSelectionKey {
        allocator_seed: 8,
        ..udp
    };
    let differ = (0..4_096)
        .filter(|&index| {
            udp.search_start(host(index), 1_000) != salted.search_start(host(index), 1_000)
        })
        .count();
    assert!(differ >= 4_090, "{differ}");
}

/// Under churn (half the pool live, each new endpoint taking the first
/// unowned port from its keyed start, expired mappings reused), the chosen
/// public ports cover the pool uniformly and consecutive new endpoints get
/// no sequential pattern.
#[test]
fn new_mapping_ports_are_uniform_under_churn() {
    const POOL: usize = 64;
    const LIVE: usize = 32;
    const ALLOCATIONS: usize = POOL * 200;
    let ttl = NAT44_UDP_MIN_IDLE_TTL_MS;
    let step = ttl.div_ceil(LIVE as u64);
    let policy = Nat44UdpPolicy::new(ttl, 0x5eed).unwrap();
    with_port_config(policy, 40_000, 40_063, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); LIVE];
        let mut peers = [Nat44UdpPeerSlot::default(); LIVE];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        runtime.skip_commit_validation.set(true);
        let mut counts = [0_usize; POOL];
        let mut offsets = Vec::with_capacity(ALLOCATIONS);
        for index in 0..ALLOCATIONS {
            let port = outbound(&mut runtime, host(index), 1_000, index as u64 * step).unwrap();
            let offset = usize::from(port - 40_000);
            counts[offset] += 1;
            offsets.push(offset);
        }
        assert!(runtime.reuse_lists_are_consistent());
        assert!(runtime.port_owners.bitmap_matches_slots());
        let statistic = chi_square(&counts);
        assert!(
            statistic < chi_square_bound(POOL),
            "chi-square {statistic} over {POOL} bins: {counts:?}"
        );
        // A sequential allocator would make nearly every step +1.
        let sequential = sequential_steps(&offsets, POOL);
        assert!(sequential < ALLOCATIONS / 16, "{sequential}");
    });
}

/// Different keys give unrelated port sequences for the same endpoints, and
/// neither is sequential.
#[test]
fn different_keys_give_unrelated_port_sequences() {
    const ENDPOINTS: usize = 64;
    let policy = Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS, 3).unwrap();
    with_port_config(policy, 40_000, 49_999, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); ENDPOINTS];
        let mut peers = [Nat44UdpPeerSlot::default(); ENDPOINTS];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        let sequence = |runtime: &mut Nat44UdpRuntime<'_>| {
            (0..ENDPOINTS)
                .map(|index| {
                    usize::from(outbound(runtime, host(index), 1_000, 0).unwrap() - 40_000)
                })
                .collect::<Vec<_>>()
        };
        let first = sequence(&mut runtime);
        runtime.reconcile(config, rotated_udp_hash_key()).unwrap();
        let second = sequence(&mut runtime);
        let same = first.iter().zip(&second).filter(|(a, b)| a == b).count();
        assert!(same <= 1, "{same}");
        for values in [&first, &second] {
            assert!(sequential_steps(values, 10_000) <= 1, "{values:?}");
        }
    });
}

/// Port preservation on (the default) keeps an in-pool internal port;
/// off, the port is the first unowned port from the keyed start, so it
/// equals the internal port only by chance.
#[test]
fn port_preservation_on_keeps_and_off_obfuscates_in_pool_internal_ports() {
    const ENDPOINTS: usize = 100;
    let internal_port = |index: usize| 40_000 + (index * 7) as u16;
    for preserve in [true, false] {
        let policy = Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS, 3)
            .unwrap()
            .with_port_preservation(preserve);
        with_port_config(policy, 40_000, 40_999, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); ENDPOINTS];
            let mut peers = [Nat44UdpPeerSlot::default(); ENDPOINTS];
            let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            let mut preserved = 0;
            for index in 0..ENDPOINTS {
                let keyed = runtime.port_owners.first_unowned_port_from(
                    runtime
                        .port_selection_key()
                        .search_start(host(index), internal_port(index)),
                );
                let port = outbound(&mut runtime, host(index), internal_port(index), 0).unwrap();
                if preserve {
                    assert_eq!(port, internal_port(index));
                } else {
                    assert_eq!(Some(port), keyed);
                }
                preserved += usize::from(port == internal_port(index));
            }
            if !preserve {
                // About ENDPOINTS / 1000 = 0.1 by chance.
                assert!(preserved <= 1, "{preserved}");
            }
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
    }
}

/// Step 2 does not depend on port preservation: with it off, an endpoint
/// whose mapping expired still gets its own port back while the mapping
/// owns it, although unowned ports exist.
#[test]
fn returning_endpoint_keeps_its_port_without_preservation() {
    let ttl = NAT44_UDP_MIN_IDLE_TTL_MS;
    let policy = Nat44UdpPolicy::new(ttl, 3)
        .unwrap()
        .with_port_preservation(false);
    with_port_config(policy, 40_000, 40_999, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); 2];
        let mut peers = [Nat44UdpPeerSlot::default(); 2];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        let first = outbound(&mut runtime, INTERNAL, 40_500, 0).unwrap();
        let other = outbound(&mut runtime, INTERNAL2, 40_501, 1).unwrap();
        assert_ne!(first, other);
        let returned = outbound(&mut runtime, INTERNAL, 40_500, ttl).unwrap();
        assert_eq!(returned, first);
        assert_eq!(runtime.counters.mappings_expired, 1);
        assert_eq!(runtime.validate_indexes(), Ok(()));
    });
}

/// Every port has an owner, and every owner has expired: each new endpoint
/// takes the port of a keyed pseudorandom expired owner and recreates that
/// owner's slot, so no port is released in expiry order. The ports given
/// up do not follow the expiry order (which the pre-N2 rule used), differ
/// under another key, and each costs a constant number of owner checks.
#[test]
fn full_pool_takeover_is_keyed_and_not_expiry_ordered() {
    const POOL: usize = 64;
    let ttl = NAT44_UDP_MIN_IDLE_TTL_MS;
    let policy = Nat44UdpPolicy::new(ttl, 3).unwrap();
    with_port_config(policy, 40_000, 40_063, |config| {
        let mut mappings = [Nat44UdpMappingSlot::default(); POOL + 1];
        let mut peers = [Nat44UdpPeerSlot::default(); POOL + 1];
        let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
        let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
        let run = |runtime: &mut Nat44UdpRuntime<'_>| {
            let expired_before = runtime.counters.mappings_expired;
            // Expiry order: the mapping of endpoint i expires at ttl + i.
            let expiry_order = (0..POOL)
                .map(|index| outbound(runtime, host(index), 1_000, index as u64).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(runtime.port_owners.first_unowned_port_from(0), None);
            let now = ttl + POOL as u64;
            let mut taken = Vec::with_capacity(POOL);
            for index in 0..POOL {
                runtime.reset_index_probe_counts();
                let port = outbound(runtime, host(POOL + index), 1_000, now).unwrap();
                let (_, _, owner_probes) = runtime.index_probe_counts();
                assert!(owner_probes <= 1 + NAT44_PORT_TAKEOVER_PROBES + 2);
                assert!(runtime.port_owners.take_bitmap_word_reads() <= 34);
                // The new mapping reused the slot of the owner it displaced:
                // still no unowned port.
                assert_eq!(runtime.port_owners.first_unowned_port_from(0), None);
                taken.push(port);
            }
            assert_eq!(runtime.validate_indexes(), Ok(()));
            assert_eq!(
                runtime.counters.mappings_expired - expired_before,
                POOL as u64
            );
            let mut distinct = taken.clone();
            distinct.sort_unstable();
            distinct.dedup();
            assert_eq!(distinct.len(), POOL);
            // Every port is live now: the next new endpoint is refused.
            assert_eq!(
                outbound(runtime, host(3 * POOL), 1_000, now),
                Err(Nat44UdpPlanError::PortExhausted)
            );
            let in_expiry_order = taken
                .iter()
                .zip(&expiry_order)
                .filter(|(a, b)| a == b)
                .count();
            (taken, in_expiry_order)
        };
        let (first, in_order) = run(&mut runtime);
        // Late takeovers, when few expired owners remain, fall back to the
        // expiry order after missing with every probe; the rest is keyed.
        assert!(in_order <= POOL / 4, "{in_order} of {POOL} in expiry order");
        runtime.reconcile(config, rotated_udp_hash_key()).unwrap();
        let (second, _) = run(&mut runtime);
        let same = first.iter().zip(&second).filter(|(a, b)| a == b).count();
        assert!(same <= POOL / 4, "{same}");
    });
}
