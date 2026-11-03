//! ICMP query NAT runtime (N5, RFC 5508 §3): mapping lifecycle, identifier
//! selection, endpoint-independent mapping, reply filtering, per-host quota,
//! and error authority.

use super::*;
use crate::{Interface, LocalIpv4Binding, MacAddress, Neighbor, Route};

const INSIDE: IfId = IfId(1);
const OUTSIDE: IfId = IfId(2);
const HOST_A: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
const HOST_B: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 11]);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const REMOTE1: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
const REMOTE2: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 2]);

fn with_config<R>(
    policy: Nat44IcmpPolicy,
    first: u16,
    last: u16,
    run: impl FnOnce(Nat44IcmpConfig) -> R,
) -> R {
    let routes = [
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, INSIDE, None).unwrap(),
        Route::new(
            Ipv4Address::from_octets([0, 0, 0, 0]),
            0,
            OUTSIDE,
            Some(Ipv4Address::from_octets([203, 0, 113, 1])),
        )
        .unwrap(),
    ];
    let interfaces = [
        Interface {
            id: INSIDE,
            mac: MacAddress([2, 0, 0, 0, 0, 1]),
            mtu: 1500,
        },
        Interface {
            id: OUTSIDE,
            mac: MacAddress([2, 0, 0, 0, 0, 2]),
            mtu: 1500,
        },
    ];
    let neighbors: [Neighbor; 0] = [];
    let bindings = [
        LocalIpv4Binding {
            interface: INSIDE,
            address: Ipv4Address::from_octets([10, 0, 0, 1]),
        },
        LocalIpv4Binding {
            interface: OUTSIDE,
            address: PUBLIC,
        },
    ];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config =
        Nat44IcmpConfig::new(&snapshot, INSIDE, OUTSIDE, PUBLIC, first, last, policy).unwrap();
    run(config)
}

fn key() -> Nat44IcmpHashKey {
    Nat44IcmpHashKey::new(0x0bad_cafe_dead_beef, 0x1234_5678_9abc_def0).unwrap()
}

struct Tables {
    mappings: Vec<Nat44IcmpMappingSlot>,
    peers: Vec<Nat44IcmpPeerSlot>,
    indexes: TestNat44UdpIndexes,
}

impl Tables {
    fn new(config: Nat44IcmpConfig, mappings: usize, peers: usize) -> Self {
        Self {
            mappings: vec![Nat44IcmpMappingSlot::default(); mappings],
            peers: vec![Nat44IcmpPeerSlot::default(); peers],
            indexes: TestNat44UdpIndexes::new(config.0, mappings, peers),
        }
    }

    fn runtime(&mut self, config: Nat44IcmpConfig) -> Nat44IcmpRuntime<'_> {
        let engine = self
            .indexes
            .runtime(config.0, &mut self.mappings, &mut self.peers);
        Nat44IcmpRuntime { engine }
    }
}

/// Plans and commits one outbound query, returning the public identifier.
fn query(
    runtime: &mut Nat44IcmpRuntime<'_>,
    host: Ipv4Address,
    identifier: u16,
    remote: Ipv4Address,
    now: u64,
) -> Result<u16, Nat44UdpPlanError> {
    let plan = runtime.plan_outbound(host, identifier, remote, now)?;
    runtime.prevalidate_outbound_commit(plan, now).unwrap();
    runtime.commit_outbound(plan, now).unwrap();
    Ok(plan.public_port())
}

/// Plans and commits one inbound reply, returning the internal endpoint.
fn reply(
    runtime: &mut Nat44IcmpRuntime<'_>,
    public_identifier: u16,
    remote: Ipv4Address,
    now: u64,
) -> Result<(Ipv4Address, u16), Nat44UdpPlanError> {
    let plan = runtime.plan_inbound(public_identifier, remote, now)?;
    runtime.commit_inbound(plan, now).unwrap();
    Ok((plan.internal_address(), plan.internal_port()))
}

#[test]
fn policy_enforces_the_rfc5508_floor_and_refuses_port_dependent_filtering() {
    assert_eq!(
        Nat44IcmpPolicy::new(NAT44_ICMP_MIN_IDLE_TTL_MS - 1, 0),
        Err(Nat44IcmpPolicyError::IdleTtlTooShort)
    );
    assert_eq!(
        Nat44IcmpPolicy::new(NAT44_ICMP_MAX_IDLE_TTL_MS + 1, 0),
        Err(Nat44IcmpPolicyError::IdleTtlTooLong)
    );
    let policy = Nat44IcmpPolicy::new(NAT44_ICMP_MIN_IDLE_TTL_MS, 7).unwrap();
    assert_eq!(policy, Nat44IcmpPolicy::default().with_seed_for_test(7));
    assert_eq!(policy.idle_ttl_ms(), 60_000);
    assert_eq!(policy.filtering(), Nat44Filtering::AddressDependent);
    assert!(policy.identifier_preservation());
    assert_eq!(policy.mappings_per_host(), 0);
    assert_eq!(
        policy.icmpv4_errors(),
        Nat44Icmpv4ErrorPolicy::Bidirectional
    );
    assert_eq!(
        policy.with_filtering(Nat44Filtering::AddressAndPortDependent),
        Err(Nat44IcmpPolicyError::FilteringNeedsPorts)
    );
    let eif = policy
        .with_filtering(Nat44Filtering::EndpointIndependent)
        .unwrap();
    assert_eq!(eif.filtering(), Nat44Filtering::EndpointIndependent);
    // The engine never hairpins and round-trips every other field.
    let tuned = eif
        .with_identifier_preservation(false)
        .with_mappings_per_host(3)
        .with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly);
    assert!(!tuned.engine().hairpinning);
    assert_eq!(Nat44IcmpPolicy::from_engine(tuned.engine()), tuned);
    assert_eq!(
        format!("{tuned:?}"),
        "Nat44IcmpPolicy { idle_ttl_ms: 60000, allocator_seed: [REDACTED], \
         icmpv4_errors: ExternalOnly, filtering: EndpointIndependent, \
         identifier_preservation: false, mappings_per_host: 3, peers_per_host: 0 }"
    );
    assert_eq!(format!("{:?}", key()), "Nat44IcmpHashKey([REDACTED])");
    assert_eq!(
        Nat44IcmpHashKey::new(0, 0),
        Err(Nat44IcmpHashKeyError::AllZero)
    );
}

impl Nat44IcmpPolicy {
    const fn with_seed_for_test(mut self, seed: u64) -> Self {
        self.allocator_seed = seed;
        self
    }
}

#[test]
fn config_validates_the_identifier_pool_and_redacts_authority() {
    with_config(Nat44IcmpPolicy::default(), 1, 65_535, |config| {
        assert_eq!(config.first_identifier(), 1);
        assert_eq!(config.last_identifier(), 65_535);
        assert_eq!(config.inside(), INSIDE);
        assert_eq!(config.outside(), OUTSIDE);
        assert_eq!(config.public_address(), PUBLIC);
        assert_eq!(config.policy(), Nat44IcmpPolicy::default());
        let debug = format!("{config:?}");
        assert!(debug.contains("first_identifier: 1"));
        assert!(debug.contains("authority: [REDACTED]"));
        assert!(debug.contains("snapshot_identity: [REDACTED]"));
        assert!(config.realm_matches(INSIDE, OUTSIDE, PUBLIC));
        assert!(!config.realm_matches(OUTSIDE, INSIDE, PUBLIC));
    });
    let routes: [Route; 0] = [];
    let interfaces = [
        Interface {
            id: INSIDE,
            mac: MacAddress([2, 0, 0, 0, 0, 1]),
            mtu: 1500,
        },
        Interface {
            id: OUTSIDE,
            mac: MacAddress([2, 0, 0, 0, 0, 2]),
            mtu: 1500,
        },
    ];
    let bindings = [LocalIpv4Binding {
        interface: OUTSIDE,
        address: PUBLIC,
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let new = |first, last| {
        Nat44IcmpConfig::new(
            &snapshot,
            INSIDE,
            OUTSIDE,
            PUBLIC,
            first,
            last,
            Nat44IcmpPolicy::default(),
        )
    };
    assert_eq!(
        new(0, 10),
        Err(Nat44IcmpConfigError::IdentifierPoolIncludesZero)
    );
    assert_eq!(
        new(10, 9),
        Err(Nat44IcmpConfigError::IdentifierPoolReversed)
    );
    assert_eq!(
        Nat44IcmpConfig::new(
            &snapshot,
            INSIDE,
            INSIDE,
            PUBLIC,
            1,
            2,
            Nat44IcmpPolicy::default()
        ),
        Err(Nat44IcmpConfigError::InterfacesEqual)
    );
    assert_eq!(
        Nat44IcmpConfig::new(
            &snapshot,
            OUTSIDE,
            INSIDE,
            PUBLIC,
            1,
            2,
            Nat44IcmpPolicy::default()
        ),
        Err(Nat44IcmpConfigError::PublicBindingWrongInterface)
    );
}

/// REQ-1 a: the mapping is external-host independent. The same internal
/// identifier toward two remotes keeps one public identifier, and each
/// remote is a separate filter peer.
#[test]
fn mapping_is_endpoint_independent_and_preserves_the_identifier() {
    with_config(Nat44IcmpPolicy::default(), 1, 65_535, |config| {
        let mut tables = Tables::new(config, 4, 8);
        let mut runtime = tables.runtime(config);
        assert_eq!(query(&mut runtime, HOST_A, 0x1234, REMOTE1, 0), Ok(0x1234));
        assert_eq!(query(&mut runtime, HOST_A, 0x1234, REMOTE2, 1), Ok(0x1234));
        let counters = runtime.counters();
        assert_eq!(counters.mappings_created, 1);
        assert_eq!(counters.peers_created, 2);
        assert_eq!(counters.outbound_translated, 2);
        assert_eq!(runtime.occupancy().mappings.occupied(), 1);
        assert_eq!(runtime.occupancy().peers.occupied(), 2);
        // A second host using the same identifier gets another one.
        let other = query(&mut runtime, HOST_B, 0x1234, REMOTE1, 2).unwrap();
        assert_ne!(other, 0x1234);
        assert_eq!(
            reply(&mut runtime, 0x1234, REMOTE1, 3),
            Ok((HOST_A, 0x1234))
        );
        assert_eq!(reply(&mut runtime, other, REMOTE1, 3), Ok((HOST_B, 0x1234)));
        assert_eq!(runtime.counters().inbound_translated, 2);
    });
}

/// Identifier 0 is a valid internal identifier but never a public one: it
/// is outside every pool, so it is always replaced by a keyed identifier.
#[test]
fn identifier_zero_and_out_of_pool_identifiers_get_a_keyed_identifier() {
    with_config(Nat44IcmpPolicy::default(), 40_000, 40_015, |config| {
        let mut tables = Tables::new(config, 4, 4);
        let mut runtime = tables.runtime(config);
        let zero = query(&mut runtime, HOST_A, 0, REMOTE1, 0).unwrap();
        assert!((40_000..=40_015).contains(&zero));
        let outside = query(&mut runtime, HOST_A, 7, REMOTE1, 0).unwrap();
        assert!((40_000..=40_015).contains(&outside));
        assert_ne!(zero, outside);
        assert_eq!(reply(&mut runtime, zero, REMOTE1, 1), Ok((HOST_A, 0)));
    });
}

/// With preservation off, a free in-pool identifier is still replaced by the
/// keyed identifier, which is stable for the endpoint within one key.
#[test]
fn identifier_preservation_off_always_uses_the_keyed_identifier() {
    let policy = Nat44IcmpPolicy::default().with_identifier_preservation(false);
    with_config(policy, 1, 65_535, |config| {
        let mut tables = Tables::new(config, 64, 64);
        let mut runtime = tables.runtime(config);
        let mut preserved = 0;
        for identifier in 1..=32_u16 {
            let public = query(&mut runtime, HOST_A, identifier, REMOTE1, 0).unwrap();
            preserved += usize::from(public == identifier);
        }
        // A keyed start lands on the internal identifier with probability
        // 1/65535 per mapping; 32 mappings never all (or even mostly) do.
        assert!(preserved <= 1, "{preserved} identifiers preserved");
    });
}

/// REQ-2: the mapping lives for the idle timeout after the last outbound
/// query and no longer; replies do not refresh it (RFC 7857 §7.1 outbound
/// refresh, as for UDP).
#[test]
fn idle_expiry_is_exact_and_only_queries_refresh() {
    with_config(Nat44IcmpPolicy::default(), 1, 65_535, |config| {
        let mut tables = Tables::new(config, 2, 2);
        let mut runtime = tables.runtime(config);
        let ttl = NAT44_ICMP_DEFAULT_IDLE_TTL_MS;
        let public = query(&mut runtime, HOST_A, 9, REMOTE1, 1_000).unwrap();
        // A reply just before expiry is translated but does not refresh.
        assert_eq!(
            reply(&mut runtime, public, REMOTE1, 1_000 + ttl - 1),
            Ok((HOST_A, 9))
        );
        assert_eq!(
            runtime.plan_inbound(public, REMOTE1, 1_000 + ttl).err(),
            Some(Nat44UdpPlanError::MappingMiss)
        );
        // A new query recreates the mapping (expired slot reused).
        assert_eq!(query(&mut runtime, HOST_A, 9, REMOTE1, 1_000 + ttl), Ok(9));
        assert_eq!(runtime.counters().mappings_expired, 1);
        // A query refreshes: one ms before the refreshed deadline is live.
        let refreshed = 1_000 + ttl;
        assert!(runtime
            .plan_inbound(public, REMOTE1, refreshed + ttl - 1)
            .is_ok());
    });
}

/// Address-dependent filtering admits replies only from remotes the mapping
/// has queried; endpoint-independent filtering admits any remote. Error
/// authority needs a queried peer in both modes.
#[test]
fn reply_filtering_follows_the_policy_and_error_authority_needs_a_peer() {
    for (filtering, other_remote_admitted) in [
        (Nat44Filtering::AddressDependent, false),
        (Nat44Filtering::EndpointIndependent, true),
    ] {
        let policy = Nat44IcmpPolicy::default()
            .with_filtering(filtering)
            .unwrap();
        with_config(policy, 1, 65_535, |config| {
            let mut tables = Tables::new(config, 2, 2);
            let mut runtime = tables.runtime(config);
            let public = query(&mut runtime, HOST_A, 5, REMOTE1, 0).unwrap();
            assert_eq!(reply(&mut runtime, public, REMOTE1, 1), Ok((HOST_A, 5)));
            let other = runtime.plan_inbound(public, REMOTE2, 1);
            assert_eq!(other.is_ok(), other_remote_admitted, "{filtering:?}");
            if !other_remote_admitted {
                assert_eq!(other.err(), Some(Nat44UdpPlanError::FilterDenied));
            }
            // RFC 5508 REQ-4/REQ-6: read-only, peer-bound error authority.
            let lookup = runtime.inspect_error_quote(public, REMOTE1, 2).unwrap();
            assert_eq!(lookup.internal_address(), HOST_A);
            assert_eq!(lookup.internal_port(), 5);
            assert_eq!(
                runtime.inspect_error_quote(public, REMOTE2, 2).err(),
                Some(Nat44UdpPlanError::FilterDenied)
            );
            assert_eq!(
                runtime.inspect_inbound_quote(HOST_A, 5, REMOTE1, 2),
                Ok(public)
            );
            assert_eq!(
                runtime.inspect_inbound_quote(HOST_A, 5, REMOTE2, 2),
                Err(Nat44UdpPlanError::FilterDenied)
            );
            assert_eq!(
                runtime.inspect_inbound_quote(HOST_B, 5, REMOTE1, 2),
                Err(Nat44UdpPlanError::MappingMiss)
            );
        });
    }
}

/// Error lookups are read-only: they neither refresh nor count.
#[test]
fn error_lookups_do_not_refresh_or_count() {
    with_config(Nat44IcmpPolicy::default(), 1, 65_535, |config| {
        let mut tables = Tables::new(config, 1, 1);
        let mut runtime = tables.runtime(config);
        let public = query(&mut runtime, HOST_A, 5, REMOTE1, 0).unwrap();
        let before = runtime.counters();
        let ttl = NAT44_ICMP_DEFAULT_IDLE_TTL_MS;
        assert!(runtime
            .inspect_error_quote(public, REMOTE1, ttl - 1)
            .is_ok());
        assert!(runtime
            .inspect_inbound_quote(HOST_A, 5, REMOTE1, ttl - 1)
            .is_ok());
        assert_eq!(runtime.counters(), before);
        assert_eq!(
            runtime.inspect_error_quote(public, REMOTE1, ttl).err(),
            Some(Nat44UdpPlanError::MappingMiss)
        );
    });
}

/// Capacity: a full table refuses a new mapping without evicting a live
/// one, the pool refuses when every identifier is owned, and the per-host
/// quota refuses a host's extra mapping while another host still maps.
#[test]
fn capacity_pool_and_host_quota_fail_closed_without_eviction() {
    with_config(Nat44IcmpPolicy::default(), 1, 65_535, |config| {
        let mut tables = Tables::new(config, 2, 4);
        let mut runtime = tables.runtime(config);
        query(&mut runtime, HOST_A, 1, REMOTE1, 0).unwrap();
        query(&mut runtime, HOST_A, 2, REMOTE1, 0).unwrap();
        assert_eq!(
            runtime.plan_outbound(HOST_A, 3, REMOTE1, 1).err(),
            Some(Nat44UdpPlanError::MappingFull)
        );
        assert_eq!(reply(&mut runtime, 1, REMOTE1, 1), Ok((HOST_A, 1)));
    });
    with_config(Nat44IcmpPolicy::default(), 100, 101, |config| {
        let mut tables = Tables::new(config, 4, 4);
        let mut runtime = tables.runtime(config);
        query(&mut runtime, HOST_A, 1, REMOTE1, 0).unwrap();
        query(&mut runtime, HOST_A, 2, REMOTE1, 0).unwrap();
        assert_eq!(
            runtime.plan_outbound(HOST_A, 3, REMOTE1, 1).err(),
            Some(Nat44UdpPlanError::PortExhausted)
        );
        runtime.record_plan_error(Nat44UdpPlanError::PortExhausted);
        assert_eq!(runtime.counters().identifier_exhausted, 1);
    });
    let policy = Nat44IcmpPolicy::default().with_mappings_per_host(1);
    with_config(policy, 1, 65_535, |config| {
        let mut tables = Tables::new(config, 4, 4);
        let mut runtime = tables.runtime(config);
        query(&mut runtime, HOST_A, 1, REMOTE1, 0).unwrap();
        assert_eq!(
            runtime.plan_outbound(HOST_A, 2, REMOTE1, 1).err(),
            Some(Nat44UdpPlanError::HostQuotaExceeded)
        );
        // The same mapping toward a new remote is not a new mapping.
        query(&mut runtime, HOST_A, 1, REMOTE2, 1).unwrap();
        query(&mut runtime, HOST_B, 2, REMOTE1, 1).unwrap();
        // The host recovers when its mapping expires.
        let ttl = NAT44_ICMP_DEFAULT_IDLE_TTL_MS;
        assert!(query(&mut runtime, HOST_A, 2, REMOTE1, 1 + ttl).is_ok());
    });
}

/// The per-host peer limit (N6) applied to queries: a host that already
/// queries `limit` remote addresses on live mappings is refused a new
/// remote (on its mapping or a new one) without state change, maps the
/// refusal to its own disposition and counter, keeps its existing peers
/// working, and recovers when a mapping expires.
#[test]
fn per_host_peer_limit_refuses_new_remotes_and_recovers_by_expiry() {
    let policy = Nat44IcmpPolicy::default().with_peers_per_host(2);
    assert_eq!(policy.peers_per_host(), 2);
    assert_eq!(Nat44IcmpPolicy::default().peers_per_host(), 0);
    with_config(policy, 1, 65_535, |config| {
        assert_eq!(config.policy().peers_per_host(), 2);
        let mut tables = Tables::new(config, 4, 8);
        let mut runtime = tables.runtime(config);
        query(&mut runtime, HOST_A, 1, REMOTE1, 0).unwrap();
        query(&mut runtime, HOST_A, 1, REMOTE2, 0).unwrap();
        let mappings = runtime.mappings().to_vec();
        let peers = runtime.peers().to_vec();
        let third = Ipv4Address::from_octets([198, 51, 100, 99]);
        for identifier in [1, 2] {
            let error = runtime.plan_outbound(HOST_A, identifier, third, 1).err();
            assert_eq!(error, Some(Nat44UdpPlanError::HostPeerQuotaExceeded));
            runtime.record_plan_error(Nat44UdpPlanError::HostPeerQuotaExceeded);
        }
        assert_eq!(
            Nat44IcmpDisposition::from_engine(Nat44UdpDisposition::HostPeerQuotaExceeded),
            Nat44IcmpDisposition::HostPeerQuotaExceeded
        );
        assert_eq!(runtime.counters().host_peer_quota_exceeded, 2);
        assert_eq!(runtime.mappings(), &mappings[..]);
        assert_eq!(runtime.peers(), &peers[..]);
        // Existing peers keep working; another host has its own budget.
        query(&mut runtime, HOST_A, 1, REMOTE1, 1).unwrap();
        assert_eq!(reply(&mut runtime, 1, REMOTE2, 1), Ok((HOST_A, 1)));
        query(&mut runtime, HOST_B, 7, third, 1).unwrap();
        let ttl = NAT44_ICMP_DEFAULT_IDLE_TTL_MS;
        query(&mut runtime, HOST_A, 2, third, 1 + ttl).unwrap();
        assert_eq!(runtime.engine().validate_indexes(), Ok(()));
    });
}

/// Reconcile flushes every mapping and peer and requires a rotated key;
/// the binding check sees config and key.
#[test]
fn reconcile_flushes_and_requires_a_rotated_key() {
    with_config(Nat44IcmpPolicy::default(), 1, 65_535, |config| {
        let mut tables = Tables::new(config, 2, 2);
        let mut runtime = tables.runtime(config);
        query(&mut runtime, HOST_A, 1, REMOTE1, 0).unwrap();
        let test_key = Nat44IcmpHashKey(crate::nat44::test_udp_hash_key());
        assert!(runtime.publication_binding_matches(config, test_key));
        assert_eq!(
            runtime.reconcile(config, test_key).err(),
            Some(Nat44IcmpReconcileError::HashKeyNotRotated)
        );
        let report = runtime.reconcile(config, key()).unwrap();
        assert_eq!(report.mappings_flushed, 1);
        assert_eq!(report.peers_flushed, 1);
        assert!(runtime.publication_binding_matches(config, key()));
        assert_eq!(runtime.counters().reconciliations, 1);
        assert_eq!(
            runtime.plan_inbound(1, REMOTE1, 1).err(),
            Some(Nat44UdpPlanError::MappingMiss)
        );
        assert_eq!(runtime.config(), config);
        assert_eq!(runtime.storage_shape().mapping_slots(), 2);
        assert_eq!(runtime.mappings().len(), 2);
        assert_eq!(runtime.peers().len(), 2);
        assert!(!runtime.engine().config().policy.hairpinning);
    });
}

/// Deterministic 64-bit LCG for seeded churn (no external RNG).
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// A reference model of the RFC 5508 §3 query semantics, written
/// independently of the engine: a map from the internal endpoint to its
/// public identifier, the time of its last outbound query, and the remotes
/// it queried since it was created. It models what must hold, not how slots
/// are reused: tables are sized so capacity is never reached.
#[derive(Default)]
struct ReferenceQueryNat {
    mappings: std::collections::HashMap<([u8; 4], u16), ReferenceMapping>,
}

struct ReferenceMapping {
    public: u16,
    last_query_ms: u64,
    remotes: std::collections::HashSet<[u8; 4]>,
}

impl ReferenceQueryNat {
    fn live(mapping: &ReferenceMapping, now: u64) -> bool {
        now < mapping.last_query_ms + NAT44_ICMP_DEFAULT_IDLE_TTL_MS
    }

    /// The public identifier a live mapping must keep (REQ-1 a), if any.
    fn outbound(&self, host: Ipv4Address, id: u16, now: u64) -> Option<u16> {
        self.mappings
            .get(&(host.octets(), id))
            .filter(|mapping| Self::live(mapping, now))
            .map(|mapping| mapping.public)
    }

    fn record_outbound(
        &mut self,
        host: Ipv4Address,
        id: u16,
        remote: Ipv4Address,
        public: u16,
        now: u64,
    ) {
        let fresh = self
            .mappings
            .get(&(host.octets(), id))
            .is_none_or(|mapping| !Self::live(mapping, now));
        let entry = self
            .mappings
            .entry((host.octets(), id))
            .or_insert(ReferenceMapping {
                public,
                last_query_ms: now,
                remotes: std::collections::HashSet::new(),
            });
        if fresh {
            entry.public = public;
            entry.remotes.clear();
        }
        entry.last_query_ms = now;
        entry.remotes.insert(remote.octets());
    }

    /// Which internal endpoint a reply reaches, under `filtering`.
    fn inbound(
        &self,
        public: u16,
        remote: Ipv4Address,
        now: u64,
        filtering: Nat44Filtering,
    ) -> Result<(Ipv4Address, u16), Nat44UdpPlanError> {
        let Some((endpoint, mapping)) = self
            .mappings
            .iter()
            .find(|(_, mapping)| mapping.public == public && Self::live(mapping, now))
        else {
            return Err(Nat44UdpPlanError::MappingMiss);
        };
        if filtering == Nat44Filtering::AddressDependent
            && !mapping.remotes.contains(&remote.octets())
        {
            return Err(Nat44UdpPlanError::FilterDenied);
        }
        Ok((Ipv4Address::from_octets(endpoint.0), endpoint.1))
    }

    fn live_publics(&self, now: u64) -> Vec<u16> {
        self.mappings
            .values()
            .filter(|mapping| Self::live(mapping, now))
            .map(|mapping| mapping.public)
            .collect()
    }
}

/// Seeded churn of queries, replies, and idle gaps (with expiry and
/// re-creation) under both filtering modes: every outcome of the runtime
/// equals the reference model's, live public identifiers stay unique and
/// in the pool, and the engine's indexes stay consistent.
#[test]
fn query_nat_matches_a_reference_model_under_seeded_churn() {
    for (seed, filtering) in [
        (1_u64, Nat44Filtering::AddressDependent),
        (2, Nat44Filtering::EndpointIndependent),
        (3, Nat44Filtering::AddressDependent),
    ] {
        let policy = Nat44IcmpPolicy::default()
            .with_filtering(filtering)
            .unwrap();
        with_config(policy, 1_000, 1_999, |config| {
            let mut tables = Tables::new(config, 64, 256);
            let mut runtime = tables.runtime(config);
            let mut reference = ReferenceQueryNat::default();
            let mut rng = Lcg(seed);
            let hosts = [HOST_A, HOST_B, Ipv4Address::from_octets([10, 0, 0, 12])];
            let remotes = [
                REMOTE1,
                REMOTE2,
                Ipv4Address::from_octets([198, 51, 100, 3]),
            ];
            let mut now = 0_u64;
            for _ in 0..6_000 {
                now += match rng.below(100) {
                    0 => NAT44_ICMP_DEFAULT_IDLE_TTL_MS,
                    1..=9 => rng.below(NAT44_ICMP_DEFAULT_IDLE_TTL_MS / 4),
                    _ => rng.below(50),
                };
                let host = hosts[rng.below(3) as usize];
                // Identifiers in and out of the pool, colliding across hosts.
                let id = [7, 1_000, 1_001, 1_500, 40_000, 0, 1_999, 65_535][rng.below(8) as usize];
                let remote = remotes[rng.below(3) as usize];
                if rng.below(2) == 0 {
                    let expected = reference.outbound(host, id, now);
                    let public = query(&mut runtime, host, id, remote, now).unwrap();
                    assert!((1_000..=1_999).contains(&public));
                    if let Some(expected) = expected {
                        assert_eq!(public, expected, "a live mapping keeps its identifier");
                    } else if (1_000..=1_999).contains(&id)
                        && !reference.live_publics(now).contains(&id)
                    {
                        assert_eq!(public, id, "a free in-pool identifier is preserved");
                    }
                    reference.record_outbound(host, id, remote, public, now);
                    let mut live = reference.live_publics(now);
                    live.sort_unstable();
                    let count = live.len();
                    live.dedup();
                    assert_eq!(live.len(), count, "live public identifiers are unique");
                } else {
                    let candidates = reference.live_publics(now);
                    let public = if candidates.is_empty() || rng.below(4) == 0 {
                        1_000 + rng.below(1_000) as u16
                    } else {
                        candidates[rng.below(candidates.len() as u64) as usize]
                    };
                    let expected = reference.inbound(public, remote, now, filtering);
                    let actual = reply(&mut runtime, public, remote, now);
                    assert_eq!(actual, expected, "reply {public} from {remote:?} at {now}");
                }
            }
            assert_eq!(runtime.engine().validate_indexes(), Ok(()));
            let counters = runtime.counters();
            assert_eq!(counters.mapping_full + counters.peer_full, 0);
            assert!(counters.mappings_expired > 0, "churn exercised expiry");
        });
    }
}

/// Adversarial cost at capacity: with every mapping slot live, a flood of
/// queries from new endpoints is refused (no eviction) with a bounded number
/// of index probes and no reuse-list walk, however full the table is.
#[test]
fn a_full_table_refuses_new_endpoints_with_bounded_work() {
    with_config(Nat44IcmpPolicy::default(), 1, 65_535, |config| {
        const CAPACITY: usize = 4_096;
        let mut tables = Tables::new(config, CAPACITY, CAPACITY);
        let mut runtime = tables.runtime(config);
        runtime.engine().skip_commit_validation.set(true);
        for index in 0..CAPACITY {
            let host = Ipv4Address::from_octets([10, 1, (index >> 8) as u8, index as u8]);
            query(&mut runtime, host, 1, REMOTE1, 0).unwrap();
        }
        let mut worst = (0, 0, 0, 0);
        for index in 0..CAPACITY {
            let host = Ipv4Address::from_octets([10, 2, (index >> 8) as u8, index as u8]);
            runtime.engine().reset_index_probe_counts();
            let error = runtime.plan_outbound(host, index as u16, REMOTE2, 1).err();
            assert_eq!(error, Some(Nat44UdpPlanError::MappingFull));
            let (mapping, peer, owner) = runtime.engine().index_probe_counts();
            let visits = runtime.engine().take_reuse_visits();
            worst = (
                worst.0.max(mapping),
                worst.1.max(peer),
                worst.2.max(owner),
                worst.3.max(visits),
            );
        }
        // A fixed bound (directory probe chains and list heads), not O(N).
        assert!(
            worst.0 <= 8 && worst.1 <= 8 && worst.2 <= 16 && worst.3 <= 4,
            "{worst:?}"
        );
        runtime.engine().skip_commit_validation.set(false);
        assert_eq!(runtime.engine().validate_indexes(), Ok(()));
        assert_eq!(runtime.occupancy().mappings.occupied(), CAPACITY);
    });
}
