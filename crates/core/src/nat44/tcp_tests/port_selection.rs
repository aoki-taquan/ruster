//! Keyed public-port selection of the TCP NAT (N2, NAT44-020), the TCP
//! counterpart of `nat44/tests/port_selection.rs`.

use super::*;

fn host(index: usize) -> Ipv4Address {
    Ipv4Address::from_octets([10, (index >> 16) as u8, (index >> 8) as u8, index as u8])
}

fn syn(
    runtime: &mut Nat44TcpRuntime<'_>,
    host: Ipv4Address,
    port: u16,
    now: u64,
) -> Result<u16, Nat44TcpPlanError> {
    let plan = runtime.plan_outbound(host, port, REMOTE1, 443, true, now)?;
    runtime.commit_outbound(plan, now).unwrap();
    Ok(plan.mapping.public_port)
}

/// Port preservation on (the default) keeps an in-pool internal port; off,
/// the port is the first unowned port from the keyed start.
#[test]
fn tcp_port_preservation_on_keeps_and_off_obfuscates_in_pool_internal_ports() {
    const ENDPOINTS: usize = 100;
    let internal_port = |index: usize| 40_000 + (index * 7) as u16;
    for preserve in [true, false] {
        let policy = Nat44TcpPolicy::new(NAT44_TCP_MIN_IDLE_TTL_MS, 3)
            .unwrap()
            .with_port_preservation(preserve);
        with_config(policy, 40_000, 40_999, |config| {
            let mut mappings = vec![Nat44TcpMappingSlot::default(); ENDPOINTS];
            let mut sessions = vec![Nat44TcpSessionSlot::default(); ENDPOINTS];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let mut preserved = 0;
            for index in 0..ENDPOINTS {
                let keyed = runtime.port_owners.first_unowned_port_from(
                    runtime
                        .port_selection_key()
                        .search_start(host(index), internal_port(index)),
                );
                let port = syn(&mut runtime, host(index), internal_port(index), 0).unwrap();
                if preserve {
                    assert_eq!(port, internal_port(index));
                } else {
                    assert_eq!(Some(port), keyed);
                }
                preserved += usize::from(port == internal_port(index));
            }
            if !preserve {
                assert!(preserved <= 1, "{preserved}");
            }
            assert!(runtime.reuse_lists_are_consistent());
        });
    }
}

/// A returning endpoint keeps its port with preservation off, and a
/// reconcile (new key) gives the same endpoints unrelated ports.
#[test]
fn tcp_returning_endpoint_is_stable_and_keys_give_unrelated_sequences() {
    const ENDPOINTS: usize = 64;
    let ttl = NAT44_TCP_MIN_IDLE_TTL_MS;
    let policy = Nat44TcpPolicy::new(ttl, 3)
        .unwrap()
        .with_port_preservation(false);
    with_config(policy, 40_000, 49_999, |config| {
        let mut mappings = vec![Nat44TcpMappingSlot::default(); ENDPOINTS];
        let mut sessions = vec![Nat44TcpSessionSlot::default(); ENDPOINTS];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let first = (0..ENDPOINTS)
            .map(|index| syn(&mut runtime, host(index), 1_000, 0).unwrap())
            .collect::<Vec<_>>();
        // Every mapping has expired (the opening timeout is shorter than the
        // established one); each endpoint returns to its own port.
        for (index, port) in first.iter().enumerate() {
            assert_eq!(syn(&mut runtime, host(index), 1_000, ttl).unwrap(), *port);
        }
        assert_eq!(runtime.counters.mappings_expired, ENDPOINTS as u64);
        runtime
            .reconcile(config, rotated_test_tcp_hash_key())
            .unwrap();
        let second = (0..ENDPOINTS)
            .map(|index| syn(&mut runtime, host(index), 1_000, ttl).unwrap())
            .collect::<Vec<_>>();
        let same = first.iter().zip(&second).filter(|(a, b)| a == b).count();
        assert!(same <= 1, "{same}");
        let sequential = |ports: &[u16]| {
            ports
                .windows(2)
                .filter(|pair| pair[0].wrapping_add(1) == pair[1])
                .count()
        };
        assert!(sequential(&first) <= 1 && sequential(&second) <= 1);
    });
}

/// The TCP runtime selects with its own key, its own hash domains, and its
/// configuration: the same inputs under the UDP domains (or the TCP domains
/// swapped) give other starts.
#[test]
fn tcp_port_selection_uses_the_tcp_key_and_domains() {
    let policy = Nat44TcpPolicy::new(NAT44_TCP_MIN_IDLE_TTL_MS, 3).unwrap();
    with_config(policy, 1, 65_535, |config| {
        let mut mappings = vec![Nat44TcpMappingSlot::default(); 1];
        let mut sessions = vec![Nat44TcpSessionSlot::default(); 1];
        let runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let tcp = runtime.port_selection_key();
        assert_eq!(tcp.key, test_tcp_hash_key().0);
        assert_eq!(tcp.start_domain, DirectoryHashDomain::TcpPortStart);
        assert_eq!(tcp.takeover_domain, DirectoryHashDomain::TcpPortTakeover);
        assert_eq!(
            (
                tcp.first_port,
                tcp.last_port,
                tcp.inside,
                tcp.public_address
            ),
            (1, 65_535, LAN, PUBLIC)
        );
        assert_eq!(tcp.allocator_seed, 3);
        let udp = PortSelectionKey {
            start_domain: DirectoryHashDomain::UdpPortStart,
            takeover_domain: DirectoryHashDomain::UdpPortTakeover,
            ..tcp
        };
        let same = (0..1_024)
            .filter(|&index| {
                tcp.search_start(host(index), 1_000) == udp.search_start(host(index), 1_000)
            })
            .count();
        assert!(same <= 1, "{same}");
    });
}

/// Every port has an expired owner: new endpoints take keyed pseudorandom
/// expired owners' ports and slots, not the expiry order, in a constant
/// number of owner checks, and exhaustion is exact afterwards.
#[test]
fn tcp_full_pool_takeover_is_keyed_and_not_expiry_ordered() {
    const POOL: usize = 64;
    let ttl = NAT44_TCP_MIN_IDLE_TTL_MS;
    let policy = Nat44TcpPolicy::new(ttl, 3).unwrap();
    with_config(policy, 40_000, 40_063, |config| {
        let mut mappings = vec![Nat44TcpMappingSlot::default(); POOL + 1];
        let mut sessions = vec![Nat44TcpSessionSlot::default(); POOL + 1];
        let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
        let expiry_order = (0..POOL)
            .map(|index| syn(&mut runtime, host(index), 1_000, index as u64).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(runtime.port_owners.first_unowned_port_from(0), None);
        let now = ttl + POOL as u64;
        let mut taken = Vec::with_capacity(POOL);
        for index in 0..POOL {
            runtime.reset_index_probe_counts();
            let port = syn(&mut runtime, host(POOL + index), 1_000, now).unwrap();
            let (_, _, _, _, owner_probes) = runtime.index_probe_counts();
            assert!(owner_probes <= 1 + NAT44_PORT_TAKEOVER_PROBES + 1);
            assert!(runtime.port_owners.take_bitmap_word_reads() <= 34);
            assert_eq!(runtime.port_owners.first_unowned_port_from(0), None);
            taken.push(port);
        }
        assert!(runtime.reuse_lists_are_consistent());
        assert!(runtime.port_owners.bitmap_matches_slots());
        let mut distinct = taken.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), POOL);
        assert_eq!(
            syn(&mut runtime, host(3 * POOL), 1_000, now),
            Err(Nat44TcpPlanError::PortExhausted)
        );
        let in_order = taken
            .iter()
            .zip(&expiry_order)
            .filter(|(a, b)| a == b)
            .count();
        assert!(in_order <= POOL / 4, "{in_order} of {POOL} in expiry order");
    });
}
