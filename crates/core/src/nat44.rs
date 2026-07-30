use std::{
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(test)]
use std::cell::Cell;

use crate::{
    fixed_directory::{
        DirectoryHashDomain, DirectoryHashKey, DirectorySemanticError, FixedDirectory,
        PortOwnerError, PortOwnerExpectation, PortOwnerSemanticError, PortOwnerTable,
        PortOwnerToken, PreparedDirectoryLink, PreparedDirectoryRelink,
        PreparedPortOwnerMoveTopology,
    },
    route, DirectoryBucket, DirectoryNode, ForwardingSnapshot, IfId, Ipv4Address, PortOwnerSlot,
};

pub const NAT44_UDP_MIN_IDLE_TTL_MS: u64 = 120_000;
pub const NAT44_UDP_DEFAULT_IDLE_TTL_MS: u64 = 300_000;
pub const NAT44_UDP_MAX_IDLE_TTL_MS: u64 = 86_400_000;
pub const NAT44_TCP_MIN_IDLE_TTL_MS: u64 = 7_440_000;
pub const NAT44_TCP_DEFAULT_IDLE_TTL_MS: u64 = 7_440_000;
pub const NAT44_TCP_MAX_IDLE_TTL_MS: u64 = 604_800_000;
const UDP_INDEX_NONE: u32 = u32::MAX;
const TCP_INDEX_NONE: u32 = u32::MAX;
static NEXT_UDP_RUNTIME_IDENTITY: AtomicU64 = AtomicU64::new(1);

fn allocate_udp_runtime_identity() -> Result<u64, Nat44UdpRuntimeConfigError> {
    allocate_udp_runtime_identity_from(&NEXT_UDP_RUNTIME_IDENTITY)
}

fn allocate_udp_runtime_identity_from(
    identities: &AtomicU64,
) -> Result<u64, Nat44UdpRuntimeConfigError> {
    identities
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |identity| {
            identity.checked_add(1)
        })
        .map_err(|_| Nat44UdpRuntimeConfigError::RuntimeIdentityExhausted)
}

fn encode_udp_index(index: usize) -> u32 {
    u32::try_from(index).expect("validated UDP NAT capacity fits u32")
}

fn encode_optional_udp_index(index: Option<usize>) -> u32 {
    index.map_or(UDP_INDEX_NONE, encode_udp_index)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44Icmpv4ErrorPolicy {
    #[default]
    Disabled,
    ExternalOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44UdpPolicy {
    idle_ttl_ms: u64,
    allocator_seed: u64,
    icmpv4_errors: Nat44Icmpv4ErrorPolicy,
}

#[cfg(test)]
mod tcp_tests {
    use super::*;
    use crate::{Interface, LocalIpv4Binding, MacAddress, Neighbor, Route};

    const LAN: IfId = IfId(1);
    const WAN: IfId = IfId(2);
    const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
    const INTERNAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
    const INTERNAL2: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 11]);
    const REMOTE1: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
    const REMOTE2: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 30]);

    fn test_tcp_hash_key() -> Nat44TcpHashKey {
        Nat44TcpHashKey::new(0x3141_5926_5358_9793, 0x2384_6264_3383_2795).unwrap()
    }

    fn rotated_test_tcp_hash_key() -> Nat44TcpHashKey {
        Nat44TcpHashKey::new(0xa5a5_5a5a_c3c3_3c3c, 0x1357_9bdf_2468_ace0).unwrap()
    }

    fn test_tcp_runtime<'a>(
        config: Nat44TcpConfig,
        mappings: &'a mut [Nat44TcpMappingSlot],
        sessions: &'a mut [Nat44TcpSessionSlot],
    ) -> Nat44TcpRuntime<'a> {
        let mapping_bucket_count = if mappings.is_empty() {
            0
        } else {
            mappings.len().next_power_of_two()
        };
        let session_bucket_count = if sessions.is_empty() {
            0
        } else {
            sessions.len().next_power_of_two()
        };
        let mapping_buckets =
            Box::leak(vec![DirectoryBucket::default(); mapping_bucket_count].into_boxed_slice());
        let mapping_nodes =
            Box::leak(vec![DirectoryNode::default(); mappings.len()].into_boxed_slice());
        let session_buckets =
            Box::leak(vec![DirectoryBucket::default(); session_bucket_count].into_boxed_slice());
        let session_nodes =
            Box::leak(vec![DirectoryNode::default(); sessions.len()].into_boxed_slice());
        let port_count = usize::from(config.last_port - config.first_port) + 1;
        let port_owners = Box::leak(vec![PortOwnerSlot::default(); port_count].into_boxed_slice());
        Nat44TcpRuntime::new(
            config,
            mappings,
            sessions,
            Nat44TcpIndexStorage::new(
                mapping_buckets,
                mapping_nodes,
                session_buckets,
                session_nodes,
                port_owners,
            ),
            test_tcp_hash_key(),
        )
        .unwrap()
    }

    fn with_config<T>(
        policy: Nat44TcpPolicy,
        first: u16,
        last: u16,
        test: impl FnOnce(Nat44TcpConfig) -> T,
    ) -> T {
        let routes = [
            Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
            Route::new(
                Ipv4Address::from_octets([0; 4]),
                0,
                WAN,
                Some(Ipv4Address::from_octets([203, 0, 113, 1])),
            )
            .unwrap(),
        ];
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 1]),
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
            },
        ];
        let neighbors = [Neighbor {
            interface: WAN,
            target: Ipv4Address::from_octets([203, 0, 113, 1]),
            mac: MacAddress([2, 0, 0, 0, 0, 3]),
        }];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: Ipv4Address::from_octets([10, 0, 0, 1]),
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        test(Nat44TcpConfig::new(&snapshot, LAN, WAN, PUBLIC, first, last, policy).unwrap())
    }

    #[test]
    fn tcp_policy_bounds_and_default_are_conservative() {
        assert_eq!(
            Nat44TcpPolicy::new(NAT44_TCP_MIN_IDLE_TTL_MS - 1, 0),
            Err(Nat44TcpPolicyError::IdleTtlTooShort)
        );
        assert_eq!(
            Nat44TcpPolicy::new(NAT44_TCP_MAX_IDLE_TTL_MS + 1, 0),
            Err(Nat44TcpPolicyError::IdleTtlTooLong)
        );
        assert_eq!(
            Nat44TcpPolicy::default().idle_ttl_ms(),
            NAT44_TCP_DEFAULT_IDLE_TTL_MS
        );
    }

    #[test]
    fn tcp_zero_and_full_capacity_never_evict_live_state() {
        with_config(Nat44TcpPolicy::default(), 40_000, 40_001, |config| {
            let mut no_mappings = [];
            let mut sessions = [Nat44TcpSessionSlot::default(); 1];
            let mut runtime = test_tcp_runtime(config, &mut no_mappings, &mut sessions);
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0),
                Err(Nat44TcpPlanError::MappingFull)
            ));
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, u64::MAX),
                Err(Nat44TcpPlanError::MappingFull)
            ));
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, u64::MAX - 1),
                Err(Nat44TcpPlanError::ClockRegression)
            ));
        });

        with_config(Nat44TcpPolicy::default(), 40_000, 40_001, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 2];
            let mut sessions = [Nat44TcpSessionSlot::default(); 1];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0)
                .unwrap();
            runtime.commit_outbound(first, 0).unwrap();
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE2, 443, true, 1),
                Err(Nat44TcpPlanError::SessionFull)
            ));
            assert!(matches!(
                runtime.plan_outbound(INTERNAL2, 40_001, REMOTE2, 443, true, 2),
                Err(Nat44TcpPlanError::SessionFull)
            ));
            assert_eq!(runtime.mappings()[0].internal_address(), INTERNAL);
            assert_eq!(runtime.sessions()[0].remote_address(), REMOTE1);

            let replacement = runtime
                .plan_outbound(
                    INTERNAL2,
                    40_001,
                    REMOTE2,
                    443,
                    true,
                    NAT44_TCP_DEFAULT_IDLE_TTL_MS,
                )
                .unwrap();
            runtime
                .commit_outbound(replacement, NAT44_TCP_DEFAULT_IDLE_TTL_MS)
                .unwrap();
            assert_eq!(runtime.mappings()[0].internal_address(), INTERNAL2);
            assert_eq!(runtime.counters().mappings_expired, 1);
        });
    }

    #[test]
    fn tcp_exact_expiry_recreates_generation_and_reconcile_flushes() {
        with_config(
            Nat44TcpPolicy::new(NAT44_TCP_MIN_IDLE_TTL_MS, 7).unwrap(),
            40_000,
            40_000,
            |config| {
                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = [Nat44TcpSessionSlot::default(); 1];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                let first = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0)
                    .unwrap();
                runtime.commit_outbound(first, 0).unwrap();
                assert!(runtime
                    .plan_inbound(40_000, REMOTE1, 443, NAT44_TCP_MIN_IDLE_TTL_MS - 1)
                    .is_ok());
                assert!(matches!(
                    runtime.plan_inbound(40_000, REMOTE1, 443, NAT44_TCP_MIN_IDLE_TTL_MS),
                    Err(Nat44TcpPlanError::MappingMiss)
                ));
                assert!(matches!(
                    runtime.plan_outbound(
                        INTERNAL,
                        40_000,
                        REMOTE1,
                        443,
                        false,
                        NAT44_TCP_MIN_IDLE_TTL_MS
                    ),
                    Err(Nat44TcpPlanError::InvalidInitialFlags)
                ));
                let recreated = runtime
                    .plan_outbound(
                        INTERNAL,
                        40_000,
                        REMOTE1,
                        443,
                        true,
                        NAT44_TCP_MIN_IDLE_TTL_MS,
                    )
                    .unwrap();
                runtime
                    .commit_outbound(recreated, NAT44_TCP_MIN_IDLE_TTL_MS)
                    .unwrap();
                assert_eq!(runtime.counters().mappings_expired, 1);
                assert_eq!(runtime.counters().sessions_expired, 1);
                let report = runtime
                    .reconcile(config, rotated_test_tcp_hash_key())
                    .unwrap();
                assert_eq!(
                    report,
                    Nat44TcpReconcileReport {
                        mappings_flushed: 1,
                        sessions_flushed: 1,
                    }
                );
                assert!(runtime.mappings().iter().all(|slot| !slot.is_occupied()));
                assert!(runtime.sessions().iter().all(|slot| !slot.is_occupied()));
                assert!(runtime
                    .mappings()
                    .iter()
                    .all(|slot| slot.last_activity_ms == 0));
            },
        );
    }

    #[test]
    fn tcp_mapping_summary_tracks_staggered_sessions_at_exact_expiry() {
        let ttl = NAT44_TCP_MIN_IDLE_TTL_MS;
        with_config(
            Nat44TcpPolicy::new(ttl, 0).unwrap(),
            40_000,
            40_000,
            |config| {
                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = [Nat44TcpSessionSlot::default(); 2];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);

                let first = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0)
                    .unwrap();
                runtime.commit_outbound(first, 0).unwrap();
                let generation = runtime.mappings()[0].generation;

                let second = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE2, 8443, true, ttl - 1)
                    .unwrap();
                runtime.commit_outbound(second, ttl - 1).unwrap();
                assert_eq!(runtime.mappings()[0].last_activity_ms, ttl - 1);

                assert!(matches!(
                    runtime.plan_inbound(40_000, REMOTE1, 443, ttl),
                    Err(Nat44TcpPlanError::SessionMiss)
                ));
                let third = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 9443, true, ttl)
                    .unwrap();
                runtime.commit_outbound(third, ttl).unwrap();

                assert_eq!(runtime.mappings()[0].generation, generation);
                assert_eq!(runtime.mappings()[0].last_activity_ms, ttl);
                assert!(runtime.sessions().iter().any(|session| {
                    session.occupied
                        && session.remote_address == REMOTE1
                        && session.remote_port == 9443
                }));
                assert!(runtime.sessions().iter().any(|session| {
                    session.occupied
                        && session.remote_address == REMOTE2
                        && session.remote_port == 8443
                }));
                assert!(matches!(
                    runtime.plan_inbound(40_000, REMOTE2, 8443, ttl * 2 - 1),
                    Err(Nat44TcpPlanError::SessionMiss)
                ));
                assert!(matches!(
                    runtime.plan_inbound(40_000, REMOTE1, 9443, ttl * 2),
                    Err(Nat44TcpPlanError::MappingMiss)
                ));
            },
        );
    }

    #[test]
    fn discarded_tcp_refresh_plans_do_not_extend_mapping_summary() {
        let ttl = NAT44_TCP_MIN_IDLE_TTL_MS;
        with_config(
            Nat44TcpPolicy::new(ttl, 0).unwrap(),
            40_000,
            40_000,
            |config| {
                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = [Nat44TcpSessionSlot::default(); 1];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                let first = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 100)
                    .unwrap();
                runtime.commit_outbound(first, 100).unwrap();

                let before_mapping = runtime.mappings()[0];
                let before_session = runtime.sessions()[0];
                let before_watermark = runtime.watermark_ms;
                let before_counters = runtime.counters();
                let outbound = runtime
                    .plan_outbound_read_only(INTERNAL, 40_000, REMOTE1, 443, false, 200)
                    .unwrap();
                let inbound = runtime
                    .plan_inbound_read_only(40_000, REMOTE1, 443, 300)
                    .unwrap();
                let _ = (outbound, inbound);

                assert_eq!(runtime.mappings()[0], before_mapping);
                assert_eq!(runtime.sessions()[0], before_session);
                assert_eq!(runtime.watermark_ms, before_watermark);
                assert_eq!(runtime.counters(), before_counters);
                assert!(matches!(
                    runtime.inspect_icmpv4(40_000, REMOTE1, 443, 100 + ttl),
                    Err(Nat44TcpPlanError::MappingMiss)
                ));
            },
        );
    }

    #[test]
    fn stale_outbound_plan_after_reconcile_is_rejected_atomically() {
        with_config(Nat44TcpPolicy::default(), 40_000, 40_000, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 1];
            let mut sessions = [Nat44TcpSessionSlot::default(); 1];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0)
                .unwrap();
            runtime.commit_outbound(first, 0).unwrap();
            let stale = runtime
                .plan_outbound_read_only(INTERNAL, 40_000, REMOTE1, 443, false, 1)
                .unwrap();

            runtime
                .reconcile(config, rotated_test_tcp_hash_key())
                .unwrap();
            let before_mapping = runtime.mappings()[0];
            let before_session = runtime.sessions()[0];
            let before_watermark = runtime.watermark_ms;
            let before_epoch = runtime.runtime_epoch;
            let before_generation = runtime.next_generation;
            let before_counters = runtime.counters();
            assert_eq!(
                runtime.commit_outbound(stale, 1),
                Err(Nat44TcpCommitError::StalePlan)
            );
            assert_eq!(runtime.mappings()[0], before_mapping);
            assert_eq!(runtime.sessions()[0], before_session);
            assert_eq!(runtime.watermark_ms, before_watermark);
            assert_eq!(runtime.runtime_epoch, before_epoch);
            assert_eq!(runtime.next_generation, before_generation);
            assert_eq!(runtime.counters(), before_counters);
        });
    }

    #[test]
    fn stale_inbound_plan_cannot_aba_after_same_generation_recreation() {
        with_config(Nat44TcpPolicy::default(), 40_000, 40_000, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 1];
            let mut sessions = [Nat44TcpSessionSlot::default(); 1];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0)
                .unwrap();
            runtime.commit_outbound(first, 0).unwrap();
            let stale = runtime
                .plan_inbound_read_only(40_000, REMOTE1, 443, 0)
                .unwrap();
            let stale_mapping = runtime.mappings()[0];
            let stale_session = runtime.sessions()[0];

            runtime
                .reconcile(config, rotated_test_tcp_hash_key())
                .unwrap();
            let recreated = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0)
                .unwrap();
            runtime.commit_outbound(recreated, 0).unwrap();
            assert_eq!(runtime.mappings()[0].generation, stale_mapping.generation);
            assert_ne!(
                runtime.mappings()[0].lifecycle_epoch,
                stale_mapping.lifecycle_epoch
            );
            assert_eq!(
                runtime.sessions()[0].mapping_generation,
                stale_session.mapping_generation
            );
            assert_ne!(
                runtime.sessions()[0].mapping_lifecycle_epoch,
                stale_session.mapping_lifecycle_epoch
            );

            let before_mapping = runtime.mappings()[0];
            let before_session = runtime.sessions()[0];
            let before_watermark = runtime.watermark_ms;
            let before_epoch = runtime.runtime_epoch;
            let before_counters = runtime.counters();
            assert_eq!(
                runtime.commit_inbound(stale, 0),
                Err(Nat44TcpCommitError::StalePlan)
            );
            assert_eq!(runtime.mappings()[0], before_mapping);
            assert_eq!(runtime.sessions()[0], before_session);
            assert_eq!(runtime.watermark_ms, before_watermark);
            assert_eq!(runtime.runtime_epoch, before_epoch);
            assert_eq!(runtime.counters(), before_counters);
        });
    }

    #[test]
    fn stale_bidirectional_plans_cannot_overwrite_reused_mapping_slot() {
        let ttl = NAT44_TCP_MIN_IDLE_TTL_MS;
        with_config(
            Nat44TcpPolicy::new(ttl, 0).unwrap(),
            40_000,
            40_000,
            |config| {
                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = [Nat44TcpSessionSlot::default(); 1];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                let first = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0)
                    .unwrap();
                runtime.commit_outbound(first, 0).unwrap();
                let stale_outbound = runtime
                    .plan_outbound_read_only(INTERNAL, 40_000, REMOTE1, 443, false, 0)
                    .unwrap();
                let stale_inbound = runtime
                    .plan_inbound_read_only(40_000, REMOTE1, 443, 0)
                    .unwrap();

                let replacement = runtime
                    .plan_outbound(INTERNAL2, 40_000, REMOTE2, 8443, true, ttl)
                    .unwrap();
                runtime.commit_outbound(replacement, ttl).unwrap();
                let before_mapping = runtime.mappings()[0];
                let before_session = runtime.sessions()[0];
                let before_watermark = runtime.watermark_ms;
                let before_epoch = runtime.runtime_epoch;
                let before_generation = runtime.next_generation;
                let before_counters = runtime.counters();

                assert_eq!(
                    runtime.commit_outbound(stale_outbound, 0),
                    Err(Nat44TcpCommitError::StalePlan)
                );
                assert_eq!(
                    runtime.commit_inbound(stale_inbound, 0),
                    Err(Nat44TcpCommitError::StalePlan)
                );
                assert_eq!(runtime.mappings()[0], before_mapping);
                assert_eq!(runtime.sessions()[0], before_session);
                assert_eq!(runtime.mappings()[0].internal_address, INTERNAL2);
                assert_eq!(runtime.sessions()[0].remote_address, REMOTE2);
                assert_eq!(runtime.watermark_ms, before_watermark);
                assert_eq!(runtime.runtime_epoch, before_epoch);
                assert_eq!(runtime.next_generation, before_generation);
                assert_eq!(runtime.counters(), before_counters);
            },
        );
    }

    #[test]
    fn tcp_mapping_liveness_never_inspects_session_storage() {
        with_config(Nat44TcpPolicy::default(), 40_000, 40_002, |config| {
            let internal3 = Ipv4Address::from_octets([10, 0, 0, 12]);
            let mut mappings = [Nat44TcpMappingSlot::default(); 3];
            let mut sessions = [Nat44TcpSessionSlot::default(); 64];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            for (internal, port) in [(INTERNAL, 40_000), (INTERNAL2, 40_001), (internal3, 40_002)] {
                let plan = runtime
                    .plan_outbound(internal, port, REMOTE1, 443, true, 0)
                    .unwrap();
                runtime.commit_outbound(plan, 0).unwrap();
            }

            runtime.reset_liveness_checks();
            assert!(runtime.find_mapping(internal3, 40_002).unwrap().is_some());
            assert_eq!(runtime.liveness_checks(), (0, 0));

            runtime.reset_liveness_checks();
            assert!(runtime.select_port(40_002, 0).unwrap().is_none());
            assert_eq!(runtime.liveness_checks(), (1, 0));
        });
    }

    #[test]
    fn tcp_icmp_lookup_is_read_only_across_time_generation_and_zero_capacity() {
        with_config(
            Nat44TcpPolicy::new(NAT44_TCP_MIN_IDLE_TTL_MS, 0)
                .unwrap()
                .with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly),
            40_000,
            40_000,
            |config| {
                let mut no_mappings = [];
                let mut no_sessions = [];
                let empty = test_tcp_runtime(config, &mut no_mappings, &mut no_sessions);
                assert!(matches!(
                    empty.inspect_icmpv4(40_000, REMOTE1, 443, 0),
                    Err(Nat44TcpPlanError::MappingMiss)
                ));

                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = [Nat44TcpSessionSlot::default(); 1];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                let first = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 100)
                    .unwrap();
                runtime.commit_outbound(first, 100).unwrap();
                let before_mapping = runtime.mappings()[0];
                let before_session = runtime.sessions()[0];
                let before_counters = runtime.counters();
                let before_mapping_directory = runtime.mapping_directory.backing_snapshot();
                let before_session_directory = runtime.session_directory.backing_snapshot();
                let before_port_owners = runtime.port_owners.backing_snapshot();
                assert!(matches!(
                    runtime.inspect_icmpv4(40_000, REMOTE1, 443, 99),
                    Err(Nat44TcpPlanError::ClockRegression)
                ));
                for now in [100, 100 + NAT44_TCP_MIN_IDLE_TTL_MS - 1] {
                    let lookup = runtime.inspect_icmpv4(40_000, REMOTE1, 443, now).unwrap();
                    assert_eq!(lookup.internal_address(), INTERNAL);
                    assert_eq!(lookup.internal_port(), 40_000);
                }
                assert!(matches!(
                    runtime.inspect_icmpv4(40_000, REMOTE1, 443, 100 + NAT44_TCP_MIN_IDLE_TTL_MS),
                    Err(Nat44TcpPlanError::MappingMiss)
                ));
                assert!(runtime.inspect_icmpv4(40_000, REMOTE1, 443, 100).is_ok());
                assert_eq!(runtime.mappings()[0], before_mapping);
                assert_eq!(runtime.sessions()[0], before_session);
                assert_eq!(runtime.counters(), before_counters);
                assert_eq!(
                    runtime.mapping_directory.backing_snapshot(),
                    before_mapping_directory
                );
                assert_eq!(
                    runtime.session_directory.backing_snapshot(),
                    before_session_directory
                );
                assert_eq!(runtime.port_owners.backing_snapshot(), before_port_owners);

                let reused = runtime
                    .plan_outbound(
                        INTERNAL2,
                        40_000,
                        REMOTE2,
                        8443,
                        true,
                        100 + NAT44_TCP_MIN_IDLE_TTL_MS,
                    )
                    .unwrap();
                runtime
                    .commit_outbound(reused, 100 + NAT44_TCP_MIN_IDLE_TTL_MS)
                    .unwrap();
                assert!(matches!(
                    runtime.inspect_icmpv4(
                        reused.public_port(),
                        REMOTE1,
                        443,
                        100 + NAT44_TCP_MIN_IDLE_TTL_MS
                    ),
                    Err(Nat44TcpPlanError::SessionMiss)
                ));
                assert!(runtime
                    .inspect_icmpv4(
                        reused.public_port(),
                        REMOTE2,
                        8443,
                        100 + NAT44_TCP_MIN_IDLE_TTL_MS
                    )
                    .is_ok());
            },
        );
    }

    #[test]
    fn tcp_allocator_preserves_scans_once_and_never_overloads() {
        with_config(
            Nat44TcpPolicy::new(NAT44_TCP_MIN_IDLE_TTL_MS, u64::MAX).unwrap(),
            40_000,
            40_001,
            |config| {
                let mut mappings = [Nat44TcpMappingSlot::default(); 3];
                let mut sessions = [Nat44TcpSessionSlot::default(); 3];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                let first = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0)
                    .unwrap();
                assert_eq!(first.public_port(), 40_000);
                runtime.commit_outbound(first, 0).unwrap();
                let second = runtime
                    .plan_outbound(INTERNAL2, 40_000, REMOTE1, 443, true, 0)
                    .unwrap();
                assert_eq!(second.public_port(), 40_001);
                runtime.commit_outbound(second, 0).unwrap();
                assert!(matches!(
                    runtime.plan_outbound(
                        Ipv4Address::from_octets([10, 0, 0, 12]),
                        50_000,
                        REMOTE2,
                        443,
                        true,
                        0
                    ),
                    Err(Nat44TcpPlanError::PortExhausted)
                ));
            },
        );
    }

    #[test]
    fn tcp_index_shape_key_guard_sizes_and_probe_bounds_are_exact() {
        with_config(Nat44TcpPolicy::default(), 40_000, 40_004, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 3];
            let mut sessions = [Nat44TcpSessionSlot::default(); 5];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let shape = runtime.storage_shape();
            assert_eq!(
                (
                    shape.mapping_slots(),
                    shape.session_slots(),
                    shape.mapping_buckets(),
                    shape.mapping_nodes(),
                    shape.session_buckets(),
                    shape.session_nodes(),
                    shape.port_owner_slots(),
                ),
                (3, 5, 4, 3, 8, 5, 5)
            );
            assert_eq!(
                format!("{:?}", test_tcp_hash_key()),
                "Nat44TcpHashKey([REDACTED])"
            );
            assert_eq!(
                Nat44TcpHashKey::new(0, 0),
                Err(Nat44TcpHashKeyError::AllZero)
            );
            assert_eq!(
                Nat44TcpRuntime::mapping_lookup_words(LAN, INTERNAL, 40_000),
                [1, 0x0a00_000a, 40_000]
            );
            assert_eq!(
                Nat44TcpRuntime::session_lookup_words(
                    7,
                    11,
                    0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
                    REMOTE1,
                    443,
                ),
                [
                    7,
                    11,
                    0x0011_2233_4455_6677,
                    0x8899_aabb_ccdd_eeff,
                    0xc633_6414,
                    443,
                ]
            );
            assert_eq!(std::mem::size_of::<Nat44TcpMappingSlot>(), 48);
            assert_eq!(std::mem::size_of::<Nat44TcpSessionSlot>(), 48);
            assert!(
                std::mem::size_of::<Nat44TcpOutboundPlan>() <= 256,
                "plan size {}",
                std::mem::size_of::<Nat44TcpOutboundPlan>()
            );

            let before = runtime.runtime_binding;
            drop(
                runtime
                    .preflight_reconcile(config, rotated_test_tcp_hash_key())
                    .unwrap(),
            );
            assert!(runtime.runtime_binding == before);
            assert!(matches!(
                runtime.preflight_reconcile(config, test_tcp_hash_key()),
                Err(Nat44TcpReconcileError::HashKeyNotRotated)
            ));

            runtime.reset_index_probe_counts();
            let plan = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0)
                .unwrap();
            let before_commit = runtime.index_probe_counts();
            runtime.prevalidate_outbound_commit(plan, 0).unwrap();
            runtime.commit_prevalidated_outbound(plan, 0);
            assert_eq!(runtime.index_probe_counts(), before_commit);
            let (mapping, session, reusable_mapping, reusable_session, owner) =
                runtime.index_probe_counts();
            assert!(mapping <= 3);
            assert!(session <= 5);
            assert!(reusable_mapping <= 3);
            assert!(reusable_session <= 5);
            assert!(owner <= 5);
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
    }

    #[test]
    fn tcp_runtime_identity_allocator_never_wraps_or_recovers_after_exhaustion() {
        let identities = AtomicU64::new(u64::MAX - 1);
        assert_eq!(
            allocate_tcp_runtime_identity_from(&identities),
            Ok(u64::MAX - 1)
        );
        assert_eq!(identities.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(
            allocate_tcp_runtime_identity_from(&identities),
            Err(Nat44TcpRuntimeConfigError::RuntimeIdentityExhausted)
        );
        assert_eq!(
            allocate_tcp_runtime_identity_from(&identities),
            Err(Nat44TcpRuntimeConfigError::RuntimeIdentityExhausted)
        );
        assert_eq!(identities.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn tcp_zero_capacity_same_backing_uses_a_fresh_runtime_identity() {
        with_config(Nat44TcpPolicy::default(), 40_000, 40_000, |config| {
            let mut mappings = [];
            let mut sessions = [];
            let mut mapping_buckets = [];
            let mut mapping_nodes = [];
            let mut session_buckets = [];
            let mut session_nodes = [];
            let mut owners = [PortOwnerSlot::default(); 1];
            let first_binding = {
                let first = Nat44TcpRuntime::new(
                    config,
                    &mut mappings,
                    &mut sessions,
                    Nat44TcpIndexStorage::new(
                        &mut mapping_buckets,
                        &mut mapping_nodes,
                        &mut session_buckets,
                        &mut session_nodes,
                        &mut owners,
                    ),
                    test_tcp_hash_key(),
                )
                .unwrap();
                first.runtime_binding
            };
            let mut replacement = Nat44TcpRuntime::new(
                config,
                &mut mappings,
                &mut sessions,
                Nat44TcpIndexStorage::new(
                    &mut mapping_buckets,
                    &mut mapping_nodes,
                    &mut session_buckets,
                    &mut session_nodes,
                    &mut owners,
                ),
                test_tcp_hash_key(),
            )
            .unwrap();
            let replacement_binding = replacement.runtime_binding;
            assert_ne!(
                first_binding.runtime_identity,
                replacement_binding.runtime_identity
            );
            assert_eq!(first_binding.mappings, replacement_binding.mappings);
            assert_eq!(first_binding.sessions, replacement_binding.sessions);
            assert_eq!(
                first_binding.mapping_buckets,
                replacement_binding.mapping_buckets
            );
            assert_eq!(
                first_binding.mapping_nodes,
                replacement_binding.mapping_nodes
            );
            assert_eq!(
                first_binding.session_buckets,
                replacement_binding.session_buckets
            );
            assert_eq!(
                first_binding.session_nodes,
                replacement_binding.session_nodes
            );
            assert_eq!(first_binding.port_owners, replacement_binding.port_owners);
            assert_eq!(
                replacement
                    .preflight_reconcile(config, rotated_test_tcp_hash_key())
                    .unwrap()
                    .commit(),
                Nat44TcpReconcileReport {
                    mappings_flushed: 0,
                    sessions_flushed: 0,
                }
            );
            assert!(replacement.publication_binding_matches(config, rotated_test_tcp_hash_key()));
            assert_eq!(replacement.validate_indexes(), Ok(()));
        });
    }

    #[test]
    fn tcp_invalid_index_storage_and_reconcile_fail_without_partial_mutation() {
        with_config(Nat44TcpPolicy::default(), 40_000, 40_000, |config| {
            let occupied_mapping = Nat44TcpMappingSlot {
                occupied: true,
                generation: 9,
                lifecycle_epoch: 7,
                port_owned: true,
                inside: LAN,
                internal_address: INTERNAL,
                internal_port: 40_000,
                public_port: 40_000,
                last_activity_ms: 3,
            };
            let occupied_session = Nat44TcpSessionSlot {
                occupied: true,
                mapping_index: 0,
                mapping_generation: 9,
                mapping_lifecycle_epoch: 7,
                remote_address: REMOTE1,
                remote_port: 443,
                last_activity_ms: 3,
            };
            let mut mappings = [occupied_mapping];
            let mut sessions = [occupied_session];
            let mut mapping_buckets = [DirectoryBucket::default(); 1];
            let mut no_mapping_nodes = [];
            let mut session_buckets = [DirectoryBucket::default(); 1];
            let mut session_nodes = [DirectoryNode::default(); 1];
            let mut owners = [PortOwnerSlot::default(); 1];
            let before_mapping_buckets = mapping_buckets;
            let before_session_buckets = session_buckets;
            let before_session_nodes = session_nodes;
            let before_owners = owners;
            let storage = Nat44TcpIndexStorage::new(
                &mut mapping_buckets,
                &mut no_mapping_nodes,
                &mut session_buckets,
                &mut session_nodes,
                &mut owners,
            );
            assert!(matches!(
                Nat44TcpRuntime::new(
                    config,
                    &mut mappings,
                    &mut sessions,
                    storage,
                    test_tcp_hash_key(),
                ),
                Err(Nat44TcpRuntimeConfigError::MappingNodeCountMismatch)
            ));
            assert_eq!(mappings, [occupied_mapping]);
            assert_eq!(sessions, [occupied_session]);
            assert_eq!(mapping_buckets, before_mapping_buckets);
            assert_eq!(session_buckets, before_session_buckets);
            assert_eq!(session_nodes, before_session_nodes);
            assert_eq!(owners, before_owners);

            let mut mappings = [Nat44TcpMappingSlot::default(); 1];
            let mut sessions = [Nat44TcpSessionSlot::default(); 1];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let plan = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0)
                .unwrap();
            runtime.commit_outbound(plan, 0).unwrap();
            let before_mapping = runtime.mappings()[0];
            let before_session = runtime.sessions()[0];
            let before_config = runtime.config;
            let before_hash_key = runtime.hash_key;
            let before_watermark = runtime.watermark_ms;
            let before_generation = runtime.next_generation;
            let before_epoch = runtime.runtime_epoch;
            let before_revision = runtime.state_revision;
            let before_binding = runtime.runtime_binding;
            let before_counters = runtime.counters();
            let before_mapping_directory = runtime.mapping_directory.backing_snapshot();
            let before_session_directory = runtime.session_directory.backing_snapshot();
            let before_port_owners = runtime.port_owners.backing_snapshot();

            assert_eq!(
                runtime.reconcile(config, test_tcp_hash_key()),
                Err(Nat44TcpReconcileError::HashKeyNotRotated)
            );
            with_config(
                Nat44TcpPolicy::default(),
                40_000,
                40_001,
                |oversized_config| {
                    assert!(matches!(
                        runtime.preflight_reconcile(oversized_config, rotated_test_tcp_hash_key()),
                        Err(Nat44TcpReconcileError::PortOwnerTableInvalid)
                    ));
                },
            );
            runtime.runtime_epoch = u128::MAX;
            assert_eq!(
                runtime.reconcile(config, rotated_test_tcp_hash_key()),
                Err(Nat44TcpReconcileError::RuntimeEpochExhausted)
            );

            assert_eq!(runtime.mappings(), &[before_mapping]);
            assert_eq!(runtime.sessions(), &[before_session]);
            assert_eq!(runtime.config, before_config);
            assert_eq!(runtime.hash_key, before_hash_key);
            assert_eq!(runtime.watermark_ms, before_watermark);
            assert_eq!(runtime.next_generation, before_generation);
            assert_eq!(runtime.runtime_epoch, u128::MAX);
            assert_eq!(runtime.state_revision, before_revision);
            assert!(runtime.runtime_binding == before_binding);
            assert_eq!(runtime.counters(), before_counters);
            assert_eq!(
                runtime.mapping_directory.backing_snapshot(),
                before_mapping_directory
            );
            assert_eq!(
                runtime.session_directory.backing_snapshot(),
                before_session_directory
            );
            assert_eq!(runtime.port_owners.backing_snapshot(), before_port_owners);
            assert_eq!(runtime.validate_indexes(), Ok(()));
            assert_eq!(before_epoch, 1);
        });
    }

    #[test]
    fn tcp_read_only_outbound_revision_exhaustion_is_byte_atomic() {
        with_config(Nat44TcpPolicy::default(), 40_000, 40_000, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 1];
            let mut sessions = [Nat44TcpSessionSlot::default(); 1];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let plan = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0)
                .unwrap();
            runtime.commit_outbound(plan, 0).unwrap();
            runtime.state_revision = u128::MAX;

            let before_mappings: [Nat44TcpMappingSlot; 1] = runtime.mappings().try_into().unwrap();
            let before_sessions: [Nat44TcpSessionSlot; 1] = runtime.sessions().try_into().unwrap();
            let before_mapping_directory = runtime.mapping_directory.backing_snapshot();
            let before_session_directory = runtime.session_directory.backing_snapshot();
            let before_port_owners = runtime.port_owners.backing_snapshot();
            let before_watermark = runtime.watermark_ms;
            let before_generation = runtime.next_generation;
            let before_epoch = runtime.runtime_epoch;
            let before_binding = runtime.runtime_binding;
            let before_counters = runtime.counters();

            assert!(matches!(
                runtime.plan_outbound_read_only(INTERNAL, 40_000, REMOTE1, 443, false, 0,),
                Err(Nat44TcpPlanError::StateRevisionExhausted)
            ));
            assert_eq!(runtime.mappings(), &before_mappings);
            assert_eq!(runtime.sessions(), &before_sessions);
            assert_eq!(
                runtime.mapping_directory.backing_snapshot(),
                before_mapping_directory
            );
            assert_eq!(
                runtime.session_directory.backing_snapshot(),
                before_session_directory
            );
            assert_eq!(runtime.port_owners.backing_snapshot(), before_port_owners);
            assert_eq!(runtime.watermark_ms, before_watermark);
            assert_eq!(runtime.next_generation, before_generation);
            assert_eq!(runtime.runtime_epoch, before_epoch);
            assert_eq!(runtime.state_revision, u128::MAX);
            assert!(runtime.runtime_binding == before_binding);
            assert_eq!(runtime.counters(), before_counters);
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
    }

    #[test]
    fn tcp_mapping_recreation_keeps_stale_sessions_lazy_and_capacity_reusable() {
        with_config(
            Nat44TcpPolicy::new(NAT44_TCP_MIN_IDLE_TTL_MS, 0).unwrap(),
            40_000,
            40_000,
            |config| {
                const SESSION_COUNT: usize = 8;
                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = [Nat44TcpSessionSlot::default(); SESSION_COUNT];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                for remote in 1..=SESSION_COUNT {
                    let plan = runtime
                        .plan_outbound(
                            INTERNAL,
                            40_000,
                            Ipv4Address::from_octets([198, 51, 100, remote as u8]),
                            443,
                            true,
                            0,
                        )
                        .unwrap();
                    runtime.commit_outbound(plan, 0).unwrap();
                }
                assert_eq!(
                    runtime
                        .sessions()
                        .iter()
                        .filter(|session| session.is_occupied())
                        .count(),
                    SESSION_COUNT
                );
                runtime.reset_index_probe_counts();
                let recreated = runtime
                    .plan_outbound(
                        INTERNAL,
                        40_000,
                        Ipv4Address::from_octets([203, 0, 113, 200]),
                        8443,
                        true,
                        NAT44_TCP_MIN_IDLE_TTL_MS,
                    )
                    .unwrap();
                let probes_before_commit = runtime.index_probe_counts();
                runtime
                    .commit_outbound(recreated, NAT44_TCP_MIN_IDLE_TTL_MS)
                    .unwrap();
                assert_eq!(runtime.index_probe_counts(), probes_before_commit);
                assert_eq!(
                    runtime
                        .sessions()
                        .iter()
                        .filter(|session| session.is_occupied())
                        .count(),
                    SESSION_COUNT
                );
                assert_eq!(runtime.validate_indexes(), Ok(()));
                for remote in 201..(201 + SESSION_COUNT as u8 - 1) {
                    let plan = runtime
                        .plan_outbound(
                            INTERNAL,
                            40_000,
                            Ipv4Address::from_octets([203, 0, 113, remote]),
                            8443,
                            true,
                            NAT44_TCP_MIN_IDLE_TTL_MS,
                        )
                        .unwrap();
                    runtime
                        .commit_outbound(plan, NAT44_TCP_MIN_IDLE_TTL_MS)
                        .unwrap();
                    assert_eq!(runtime.validate_indexes(), Ok(()));
                }
            },
        );
    }

    #[test]
    fn tcp_deterministic_property_model_is_bounded_and_replayable() {
        #[derive(Clone, Copy)]
        struct ModelMapping {
            identity: u64,
            internal_address: Ipv4Address,
            internal_port: u16,
            public_port: u16,
        }

        #[derive(Clone, Copy)]
        struct ModelSession {
            mapping_identity: u64,
            remote_address: Ipv4Address,
            remote_port: u16,
            last_activity_ms: u64,
        }

        const SEEDS: [u64; 16] = [
            0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987,
        ];
        const BUDGET: usize = 1024;
        const MAPPING_CAPACITY: usize = 7;
        const SESSION_CAPACITY: usize = 13;
        const PORT_CAPACITY: usize = 5;
        assert_eq!(SEEDS.len() * BUDGET, 16_384);
        for seed in SEEDS {
            with_config(
                Nat44TcpPolicy::new(NAT44_TCP_MIN_IDLE_TTL_MS, seed).unwrap(),
                40_000,
                40_004,
                |config| {
                    let mut mappings = [Nat44TcpMappingSlot::default(); MAPPING_CAPACITY];
                    let mut sessions = [Nat44TcpSessionSlot::default(); SESSION_CAPACITY];
                    let mut mapping_buckets = [DirectoryBucket::default(); 8];
                    let mut mapping_nodes = [DirectoryNode::default(); MAPPING_CAPACITY];
                    let mut session_buckets = [DirectoryBucket::default(); 16];
                    let mut session_nodes = [DirectoryNode::default(); SESSION_CAPACITY];
                    let mut owners = [PortOwnerSlot::default(); PORT_CAPACITY];
                    let mut runtime = Nat44TcpRuntime::new(
                        config,
                        &mut mappings,
                        &mut sessions,
                        Nat44TcpIndexStorage::new(
                            &mut mapping_buckets,
                            &mut mapping_nodes,
                            &mut session_buckets,
                            &mut session_nodes,
                            &mut owners,
                        ),
                        test_tcp_hash_key(),
                    )
                    .unwrap();
                    let mut model_mappings: [Option<ModelMapping>; MAPPING_CAPACITY] =
                        [None; MAPPING_CAPACITY];
                    let mut model_sessions: [Option<ModelSession>; SESSION_CAPACITY] =
                        [None; SESSION_CAPACITY];
                    let mut next_model_identity = 1_u64;
                    let mut random = seed;
                    let mut now = 0_u64;
                    for step in 0..BUDGET {
                        random = random.wrapping_add(0x9e37_79b9_7f4a_7c15);
                        let mut mixed = random;
                        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                        mixed ^= mixed >> 31;
                        if step != 0 && step % 127 == 0 {
                            now = now.saturating_add(NAT44_TCP_MIN_IDLE_TTL_MS);
                        }
                        let local = (mixed as u8) % 8;
                        let remote = ((mixed >> 8) as u8) % 16;
                        let internal =
                            Ipv4Address::from_octets([10, 0, 0, local.saturating_add(1)]);
                        let remote_address =
                            Ipv4Address::from_octets([198, 51, 100, remote.saturating_add(1)]);
                        let internal_port = 40_000 + u16::from(local);
                        let remote_port = 443 + u16::from(remote);
                        let initial_syn = mixed & 3 != 0;

                        for session in &mut model_sessions {
                            if session.is_some_and(|session| {
                                now.saturating_sub(session.last_activity_ms)
                                    >= NAT44_TCP_MIN_IDLE_TTL_MS
                            }) {
                                *session = None;
                            }
                        }
                        for mapping in &mut model_mappings {
                            if mapping.is_some_and(|mapping| {
                                !model_sessions.iter().any(|session| {
                                    session.is_some_and(|session| {
                                        session.mapping_identity == mapping.identity
                                    })
                                })
                            }) {
                                *mapping = None;
                            }
                        }

                        let model_mapping_index = model_mappings.iter().position(|mapping| {
                            mapping.is_some_and(|mapping| {
                                mapping.internal_address == internal
                                    && mapping.internal_port == internal_port
                            })
                        });
                        let model_session_index = model_mapping_index.and_then(|mapping_index| {
                            let mapping = model_mappings[mapping_index].unwrap();
                            model_sessions.iter().position(|session| {
                                session.is_some_and(|session| {
                                    session.mapping_identity == mapping.identity
                                        && session.remote_address == remote_address
                                        && session.remote_port == remote_port
                                })
                            })
                        });
                        let expected_error = if model_session_index.is_some() {
                            None
                        } else if !initial_syn {
                            Some(Nat44TcpPlanError::InvalidInitialFlags)
                        } else if model_mapping_index.is_some() {
                            (!model_sessions.iter().any(Option::is_none))
                                .then_some(Nat44TcpPlanError::SessionFull)
                        } else if !model_mappings.iter().any(Option::is_none) {
                            Some(Nat44TcpPlanError::MappingFull)
                        } else if !model_sessions.iter().any(Option::is_none) {
                            Some(Nat44TcpPlanError::SessionFull)
                        } else if model_mappings.iter().flatten().count() == PORT_CAPACITY {
                            Some(Nat44TcpPlanError::PortExhausted)
                        } else {
                            None
                        };

                        runtime.reset_index_probe_counts();
                        let before_mappings: [Nat44TcpMappingSlot; MAPPING_CAPACITY] =
                            runtime.mappings().try_into().unwrap();
                        let before_sessions: [Nat44TcpSessionSlot; SESSION_CAPACITY] =
                            runtime.sessions().try_into().unwrap();
                        let planned = runtime.plan_outbound(
                            internal,
                            internal_port,
                            remote_address,
                            remote_port,
                            initial_syn,
                            now,
                        );
                        match (planned, expected_error) {
                            (Ok(plan), None) if mixed & 0x10 == 0 => {
                                let public_port = plan.public_port();
                                runtime.prevalidate_outbound_commit(plan, now).unwrap();
                                runtime.commit_prevalidated_outbound(plan, now);

                                let mapping_index = model_mapping_index.unwrap_or_else(|| {
                                    let index =
                                        model_mappings.iter().position(Option::is_none).unwrap();
                                    assert!(
                                        !model_mappings
                                            .iter()
                                            .flatten()
                                            .any(|mapping| { mapping.public_port == public_port }),
                                        "seed={seed} step={step}"
                                    );
                                    assert!(
                                        (40_000..=40_004).contains(&public_port),
                                        "seed={seed} step={step}"
                                    );
                                    model_mappings[index] = Some(ModelMapping {
                                        identity: next_model_identity,
                                        internal_address: internal,
                                        internal_port,
                                        public_port,
                                    });
                                    next_model_identity += 1;
                                    index
                                });
                                let mapping = model_mappings[mapping_index].unwrap();
                                assert_eq!(
                                    mapping.public_port, public_port,
                                    "seed={seed} step={step}"
                                );
                                if let Some(session_index) = model_session_index {
                                    model_sessions[session_index]
                                        .as_mut()
                                        .unwrap()
                                        .last_activity_ms = now;
                                } else {
                                    let session_index =
                                        model_sessions.iter().position(Option::is_none).unwrap();
                                    model_sessions[session_index] = Some(ModelSession {
                                        mapping_identity: mapping.identity,
                                        remote_address,
                                        remote_port,
                                        last_activity_ms: now,
                                    });
                                }
                            }
                            (Ok(_), None) => {
                                assert_eq!(runtime.mappings(), &before_mappings);
                                assert_eq!(runtime.sessions(), &before_sessions);
                            }
                            (Err(actual), Some(expected)) => {
                                assert_eq!(actual, expected, "seed={seed} step={step}");
                                assert_eq!(runtime.mappings(), &before_mappings);
                                assert_eq!(runtime.sessions(), &before_sessions);
                            }
                            (Ok(_), Some(expected)) => {
                                panic!(
                                    "unexpected success for {expected:?}, seed={seed} step={step}"
                                )
                            }
                            (Err(actual), None) => {
                                panic!("unexpected {actual:?}, seed={seed} step={step}")
                            }
                        }

                        assert_eq!(runtime.validate_indexes(), Ok(()));
                        let runtime_live_mappings = runtime
                            .mappings()
                            .iter()
                            .filter(|mapping| {
                                mapping.occupied && runtime.mapping_is_live(**mapping, now)
                            })
                            .count();
                        assert_eq!(
                            runtime_live_mappings,
                            model_mappings.iter().flatten().count(),
                            "seed={seed} step={step}"
                        );
                        for model_mapping in model_mappings.iter().flatten() {
                            let (mapping_index, runtime_mapping) = runtime
                                .mappings()
                                .iter()
                                .copied()
                                .enumerate()
                                .find(|(_, mapping)| {
                                    mapping.occupied
                                        && runtime.mapping_is_live(*mapping, now)
                                        && mapping.internal_address
                                            == model_mapping.internal_address
                                        && mapping.internal_port == model_mapping.internal_port
                                })
                                .unwrap_or_else(|| {
                                    panic!("missing model mapping, seed={seed} step={step}")
                                });
                            assert_eq!(
                                runtime_mapping.public_port, model_mapping.public_port,
                                "seed={seed} step={step}"
                            );
                            let runtime_live_sessions = runtime
                                .sessions()
                                .iter()
                                .filter(|session| {
                                    session.occupied
                                        && session.mapping_index == mapping_index
                                        && session.mapping_generation == runtime_mapping.generation
                                        && session.mapping_lifecycle_epoch
                                            == runtime_mapping.lifecycle_epoch
                                        && runtime.session_is_live(**session, now)
                                })
                                .count();
                            let model_live_sessions = model_sessions
                                .iter()
                                .flatten()
                                .filter(|session| {
                                    session.mapping_identity == model_mapping.identity
                                })
                                .count();
                            assert_eq!(
                                runtime_live_sessions, model_live_sessions,
                                "seed={seed} step={step}"
                            );
                            for model_session in model_sessions.iter().flatten().filter(|session| {
                                session.mapping_identity == model_mapping.identity
                            }) {
                                assert!(
                                    runtime.sessions().iter().any(|session| {
                                        session.occupied
                                            && session.mapping_index == mapping_index
                                            && session.mapping_generation
                                                == runtime_mapping.generation
                                            && session.mapping_lifecycle_epoch
                                                == runtime_mapping.lifecycle_epoch
                                            && runtime.session_is_live(*session, now)
                                            && session.remote_address
                                                == model_session.remote_address
                                            && session.remote_port == model_session.remote_port
                                            && session.last_activity_ms
                                                == model_session.last_activity_ms
                                    }),
                                    "missing model session, seed={seed} step={step}"
                                );
                            }
                        }
                        let (mapping, session, reusable_mapping, reusable_session, owner) =
                            runtime.index_probe_counts();
                        assert!(mapping <= MAPPING_CAPACITY, "seed={seed} step={step}");
                        assert!(session <= SESSION_CAPACITY, "seed={seed} step={step}");
                        assert!(
                            reusable_mapping <= MAPPING_CAPACITY,
                            "seed={seed} step={step}"
                        );
                        assert!(
                            reusable_session <= SESSION_CAPACITY,
                            "seed={seed} step={step}"
                        );
                        assert!(owner <= PORT_CAPACITY, "seed={seed} step={step}");
                    }
                },
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44UdpPolicyError {
    IdleTtlTooShort,
    IdleTtlTooLong,
}

impl Nat44UdpPolicy {
    pub const fn new(idle_ttl_ms: u64, allocator_seed: u64) -> Result<Self, Nat44UdpPolicyError> {
        if idle_ttl_ms < NAT44_UDP_MIN_IDLE_TTL_MS {
            return Err(Nat44UdpPolicyError::IdleTtlTooShort);
        }
        if idle_ttl_ms > NAT44_UDP_MAX_IDLE_TTL_MS {
            return Err(Nat44UdpPolicyError::IdleTtlTooLong);
        }
        Ok(Self {
            idle_ttl_ms,
            allocator_seed,
            icmpv4_errors: Nat44Icmpv4ErrorPolicy::Disabled,
        })
    }

    #[must_use]
    pub const fn idle_ttl_ms(self) -> u64 {
        self.idle_ttl_ms
    }

    #[must_use]
    pub const fn allocator_seed(self) -> u64 {
        self.allocator_seed
    }

    #[must_use]
    pub const fn with_icmpv4_errors(mut self, policy: Nat44Icmpv4ErrorPolicy) -> Self {
        self.icmpv4_errors = policy;
        self
    }

    #[must_use]
    pub const fn icmpv4_errors(self) -> Nat44Icmpv4ErrorPolicy {
        self.icmpv4_errors
    }
}

impl Default for Nat44UdpPolicy {
    fn default() -> Self {
        Self {
            idle_ttl_ms: NAT44_UDP_DEFAULT_IDLE_TTL_MS,
            allocator_seed: 0,
            icmpv4_errors: Nat44Icmpv4ErrorPolicy::Disabled,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Nat44UdpHashKey(DirectoryHashKey);

impl std::fmt::Debug for Nat44UdpHashKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Nat44UdpHashKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44UdpHashKeyError {
    AllZero,
}

impl Nat44UdpHashKey {
    /// Constructs a control-plane supplied UDP NAT index key.
    ///
    /// The control plane must generate a fresh unpredictable key for every
    /// runtime construction and successful publication.
    pub const fn new(first: u64, second: u64) -> Result<Self, Nat44UdpHashKeyError> {
        match DirectoryHashKey::new(first, second) {
            Ok(key) => Ok(Self(key)),
            Err(_) => Err(Nat44UdpHashKeyError::AllZero),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44UdpConfig {
    inside: IfId,
    outside: IfId,
    public_address: Ipv4Address,
    first_port: u16,
    last_port: u16,
    policy: Nat44UdpPolicy,
    authority: u64,
    snapshot_identity: [usize; 8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44UdpConfigError {
    InterfacesEqual,
    InsideInterfaceMissing,
    OutsideInterfaceMissing,
    PublicAddressNotHostUnicast,
    PublicBindingMissing,
    PublicBindingWrongInterface,
    PortPoolIncludesZero,
    PortPoolReversed,
}

impl Nat44UdpConfig {
    pub fn new(
        snapshot: &ForwardingSnapshot<'_>,
        inside: IfId,
        outside: IfId,
        public_address: Ipv4Address,
        first_port: u16,
        last_port: u16,
        policy: Nat44UdpPolicy,
    ) -> Result<Self, Nat44UdpConfigError> {
        if inside == outside {
            return Err(Nat44UdpConfigError::InterfacesEqual);
        }
        if !snapshot
            .interfaces
            .iter()
            .any(|interface| interface.id == inside)
        {
            return Err(Nat44UdpConfigError::InsideInterfaceMissing);
        }
        if !snapshot
            .interfaces
            .iter()
            .any(|interface| interface.id == outside)
        {
            return Err(Nat44UdpConfigError::OutsideInterfaceMissing);
        }
        if !address_is_host_unicast(snapshot, public_address) {
            return Err(Nat44UdpConfigError::PublicAddressNotHostUnicast);
        }
        let Some(binding) = snapshot
            .local_ipv4
            .iter()
            .find(|binding| binding.address == public_address)
        else {
            return Err(Nat44UdpConfigError::PublicBindingMissing);
        };
        if binding.interface != outside {
            return Err(Nat44UdpConfigError::PublicBindingWrongInterface);
        }
        if first_port == 0 {
            return Err(Nat44UdpConfigError::PortPoolIncludesZero);
        }
        if first_port > last_port {
            return Err(Nat44UdpConfigError::PortPoolReversed);
        }
        Ok(Self {
            inside,
            outside,
            public_address,
            first_port,
            last_port,
            policy,
            authority: snapshot_authority(snapshot),
            snapshot_identity: snapshot.identity(),
        })
    }

    #[must_use]
    pub const fn inside(self) -> IfId {
        self.inside
    }

    #[must_use]
    pub const fn outside(self) -> IfId {
        self.outside
    }

    #[must_use]
    pub const fn public_address(self) -> Ipv4Address {
        self.public_address
    }

    #[must_use]
    pub const fn first_port(self) -> u16 {
        self.first_port
    }

    #[must_use]
    pub const fn last_port(self) -> u16 {
        self.last_port
    }

    #[must_use]
    pub const fn policy(self) -> Nat44UdpPolicy {
        self.policy
    }

    pub(crate) fn authority_matches(self, snapshot: &ForwardingSnapshot<'_>) -> bool {
        self.authority == snapshot_authority(snapshot)
            && self.snapshot_identity == snapshot.identity()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44UdpMappingSlot {
    occupied: bool,
    generation: u64,
    lifecycle_epoch: u128,
    port_owned: bool,
    inside: IfId,
    internal_address: Ipv4Address,
    internal_port: u16,
    public_port: u16,
    last_outbound_ms: u64,
}

impl Default for Nat44UdpMappingSlot {
    fn default() -> Self {
        Self {
            occupied: false,
            generation: 0,
            lifecycle_epoch: 0,
            port_owned: false,
            inside: IfId(0),
            internal_address: Ipv4Address::from_octets([0; 4]),
            internal_port: 0,
            public_port: 0,
            last_outbound_ms: 0,
        }
    }
}

impl Nat44UdpMappingSlot {
    #[must_use]
    pub const fn is_occupied(self) -> bool {
        self.occupied
    }

    #[must_use]
    pub const fn internal_address(self) -> Ipv4Address {
        self.internal_address
    }

    #[must_use]
    pub const fn internal_port(self) -> u16 {
        self.internal_port
    }

    #[must_use]
    pub const fn public_port(self) -> u16 {
        self.public_port
    }

    #[must_use]
    pub const fn last_outbound_ms(self) -> u64 {
        self.last_outbound_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44UdpPeerSlot {
    occupied: bool,
    mapping_index: usize,
    mapping_generation: u64,
    mapping_lifecycle_epoch: u128,
    remote_address: Ipv4Address,
}

impl Default for Nat44UdpPeerSlot {
    fn default() -> Self {
        Self {
            occupied: false,
            mapping_index: 0,
            mapping_generation: 0,
            mapping_lifecycle_epoch: 0,
            remote_address: Ipv4Address::from_octets([0; 4]),
        }
    }
}

impl Nat44UdpPeerSlot {
    #[must_use]
    pub const fn is_occupied(self) -> bool {
        self.occupied
    }

    #[must_use]
    pub const fn remote_address(self) -> Ipv4Address {
        self.remote_address
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Nat44UdpCounters {
    pub mappings_created: u64,
    pub mappings_reused: u64,
    pub mappings_expired: u64,
    pub peers_created: u64,
    pub outbound_translated: u64,
    pub inbound_translated: u64,
    pub mapping_misses: u64,
    pub filter_denied: u64,
    pub mapping_full: u64,
    pub peer_full: u64,
    pub port_exhausted: u64,
    pub clock_regressions: u64,
    pub config_mismatches: u64,
    pub reconciliations: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44UdpDisposition {
    OutboundTranslated {
        public_port: u16,
        mapping_created: bool,
        peer_created: bool,
    },
    InboundTranslated {
        internal_address: Ipv4Address,
        internal_port: u16,
    },
    MappingMiss,
    FilterDenied,
    MappingFull,
    PeerFull,
    PortExhausted,
    ClockRegression,
    ConfigMismatch,
    Rejected {
        reason: crate::DropReason,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44UdpReconcileReport {
    pub mappings_flushed: usize,
    pub peers_flushed: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct Nat44UdpOutboundPlan {
    mapping_index: u32,
    mapping: Nat44UdpMappingSlot,
    peer_index: u32,
    peer: Option<Nat44UdpPeerSlot>,
    mapping_created: bool,
    mapping_expired: bool,
    peer_created: bool,
    expected_runtime_epoch: u128,
    expected_revision: u128,
    planned_now_ms: u64,
    displaced_port_mapping_index: u32,
    prepared: PreparedNat44UdpOutboundCommit,
}

impl Nat44UdpOutboundPlan {
    const fn mapping_index(self) -> usize {
        self.mapping_index as usize
    }

    fn peer_index(self) -> Option<usize> {
        (self.peer_index != UDP_INDEX_NONE).then_some(self.peer_index as usize)
    }

    fn displaced_port_mapping_index(self) -> Option<usize> {
        (self.displaced_port_mapping_index != UDP_INDEX_NONE)
            .then_some(self.displaced_port_mapping_index as usize)
    }

    pub(crate) const fn public_port(self) -> u16 {
        self.mapping.public_port
    }

    pub(crate) const fn disposition(self) -> Nat44UdpDisposition {
        Nat44UdpDisposition::OutboundTranslated {
            public_port: self.mapping.public_port,
            mapping_created: self.mapping_created,
            peer_created: self.peer_created,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Nat44UdpInboundPlan {
    mapping_index: usize,
    mapping_generation: u64,
    internal_address: Ipv4Address,
    internal_port: u16,
    expected_runtime_epoch: u128,
    expected_revision: u128,
    planned_now_ms: u64,
}

impl Nat44UdpInboundPlan {
    pub(crate) const fn internal_address(self) -> Ipv4Address {
        self.internal_address
    }

    pub(crate) const fn internal_port(self) -> u16 {
        self.internal_port
    }

    pub(crate) const fn disposition(self) -> Nat44UdpDisposition {
        Nat44UdpDisposition::InboundTranslated {
            internal_address: self.internal_address,
            internal_port: self.internal_port,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Nat44UdpPlanError {
    MappingMiss,
    FilterDenied,
    MappingFull,
    PeerFull,
    PortExhausted,
    ClockRegression,
    IndexCorrupt,
    GenerationExhausted,
    StateRevisionExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Nat44UdpCommitError {
    RuntimeEpochChanged,
    StateRevisionChanged,
    CommitTimeChanged,
    MappingSlotChanged,
    IndexCorrupt,
    StateRevisionExhausted,
}

#[derive(Clone, Copy)]
struct Nat44UdpPortSelection {
    port: u16,
    expected_owner: Option<PortOwnerToken>,
    displaced_mapping_index: Option<usize>,
}

#[derive(Clone, Copy)]
enum PreparedUdpDirectoryMutation {
    Link(PreparedDirectoryLink),
    Relink(PreparedDirectoryRelink),
}

#[derive(Clone, Copy)]
struct PreparedNat44UdpOutboundCommit {
    mapping: Option<PreparedUdpDirectoryMutation>,
    peer: Option<PreparedUdpDirectoryMutation>,
    owner: Option<PreparedPortOwnerMoveTopology>,
}

impl PreparedNat44UdpOutboundCommit {
    const EMPTY: Self = Self {
        mapping: None,
        peer: None,
        owner: None,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Nat44UdpIndexInvariantError {
    Mapping(DirectorySemanticError),
    Peer(DirectorySemanticError),
    Port(PortOwnerSemanticError),
    DuplicateMappingKey,
    DuplicatePeerKey,
}

#[derive(Clone, Copy)]
pub(crate) struct Nat44UdpIcmpv4Lookup {
    internal_address: Ipv4Address,
    internal_port: u16,
}

impl Nat44UdpIcmpv4Lookup {
    pub(crate) const fn internal_address(self) -> Ipv4Address {
        self.internal_address
    }

    pub(crate) const fn internal_port(self) -> u16 {
        self.internal_port
    }
}

/// Caller-owned storage for the three UDP NAT hot-path indexes.
pub struct Nat44UdpIndexStorage<'a> {
    mapping_buckets: &'a mut [DirectoryBucket],
    mapping_nodes: &'a mut [DirectoryNode],
    peer_buckets: &'a mut [DirectoryBucket],
    peer_nodes: &'a mut [DirectoryNode],
    port_owners: &'a mut [PortOwnerSlot],
}

impl<'a> Nat44UdpIndexStorage<'a> {
    pub fn new(
        mapping_buckets: &'a mut [DirectoryBucket],
        mapping_nodes: &'a mut [DirectoryNode],
        peer_buckets: &'a mut [DirectoryBucket],
        peer_nodes: &'a mut [DirectoryNode],
        port_owners: &'a mut [PortOwnerSlot],
    ) -> Self {
        Self {
            mapping_buckets,
            mapping_nodes,
            peer_buckets,
            peer_nodes,
            port_owners,
        }
    }
}

#[cfg(test)]
pub(crate) struct TestNat44UdpIndexes {
    mapping_buckets: Vec<DirectoryBucket>,
    mapping_nodes: Vec<DirectoryNode>,
    peer_buckets: Vec<DirectoryBucket>,
    peer_nodes: Vec<DirectoryNode>,
    port_owners: Vec<PortOwnerSlot>,
}

#[cfg(test)]
fn test_udp_hash_key() -> Nat44UdpHashKey {
    Nat44UdpHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap()
}

#[cfg(test)]
impl TestNat44UdpIndexes {
    pub(crate) fn new(
        config: Nat44UdpConfig,
        mapping_capacity: usize,
        peer_capacity: usize,
    ) -> Self {
        let mapping_bucket_count = if mapping_capacity == 0 {
            0
        } else {
            mapping_capacity.next_power_of_two()
        };
        let peer_bucket_count = if peer_capacity == 0 {
            0
        } else {
            peer_capacity.next_power_of_two()
        };
        let port_count = usize::from(config.last_port - config.first_port) + 1;
        Self {
            mapping_buckets: vec![DirectoryBucket::default(); mapping_bucket_count],
            mapping_nodes: vec![DirectoryNode::default(); mapping_capacity],
            peer_buckets: vec![DirectoryBucket::default(); peer_bucket_count],
            peer_nodes: vec![DirectoryNode::default(); peer_capacity],
            port_owners: vec![PortOwnerSlot::default(); port_count],
        }
    }

    pub(crate) fn runtime<'a>(
        &'a mut self,
        config: Nat44UdpConfig,
        mappings: &'a mut [Nat44UdpMappingSlot],
        peers: &'a mut [Nat44UdpPeerSlot],
    ) -> Nat44UdpRuntime<'a> {
        let indexes = Nat44UdpIndexStorage::new(
            &mut self.mapping_buckets,
            &mut self.mapping_nodes,
            &mut self.peer_buckets,
            &mut self.peer_nodes,
            &mut self.port_owners,
        );
        Nat44UdpRuntime::new(config, mappings, peers, indexes, test_udp_hash_key()).unwrap()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44UdpRuntimeConfigError {
    MappingNodeCountMismatch,
    PeerNodeCountMismatch,
    MappingDirectoryInvalid,
    PeerDirectoryInvalid,
    PortOwnerTableInvalid,
    RuntimeIdentityExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44UdpReconcileError {
    HashKeyNotRotated,
    PortOwnerTableInvalid,
    RuntimeEpochExhausted,
}

/// Validated caller-owned capacity of a UDP NAT runtime and all of its indexes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44UdpStorageShape {
    mapping_slots: u32,
    peer_slots: u32,
    mapping_buckets: u32,
    mapping_nodes: u32,
    peer_buckets: u32,
    peer_nodes: u32,
    port_owner_slots: u32,
}

impl Nat44UdpStorageShape {
    #[must_use]
    pub const fn mapping_slots(self) -> u32 {
        self.mapping_slots
    }

    #[must_use]
    pub const fn peer_slots(self) -> u32 {
        self.peer_slots
    }

    #[must_use]
    pub const fn mapping_buckets(self) -> u32 {
        self.mapping_buckets
    }

    #[must_use]
    pub const fn mapping_nodes(self) -> u32 {
        self.mapping_nodes
    }

    #[must_use]
    pub const fn peer_buckets(self) -> u32 {
        self.peer_buckets
    }

    #[must_use]
    pub const fn peer_nodes(self) -> u32 {
        self.peer_nodes
    }

    #[must_use]
    pub const fn port_owner_slots(self) -> u32 {
        self.port_owner_slots
    }
}

/// Lifetime-bound proof that a UDP NAT reconcile can commit without failure.
///
/// The permit exclusively borrows the exact runtime that produced it. It is
/// intentionally opaque, non-cloneable, non-copyable, and non-debuggable.
/// Dropping it releases the borrow without changing the runtime.
///
/// ```compile_fail
/// use ruster_core::Nat44UdpReconcilePermit;
/// fn assert_clone<T: Clone>() {}
/// assert_clone::<Nat44UdpReconcilePermit<'static, 'static>>();
/// ```
///
/// ```compile_fail
/// use ruster_core::Nat44UdpReconcilePermit;
/// fn assert_copy<T: Copy>() {}
/// assert_copy::<Nat44UdpReconcilePermit<'static, 'static>>();
/// ```
///
/// ```compile_fail
/// use ruster_core::Nat44UdpReconcilePermit;
/// fn assert_debug<T: std::fmt::Debug>() {}
/// assert_debug::<Nat44UdpReconcilePermit<'static, 'static>>();
/// ```
///
/// ```compile_fail
/// use ruster_core::{
///     Nat44UdpConfig, Nat44UdpHashKey, Nat44UdpReconcileError, Nat44UdpRuntime,
/// };
///
/// fn runtime_stays_exclusively_borrowed<'storage>(
///     runtime: &mut Nat44UdpRuntime<'storage>,
///     config: Nat44UdpConfig,
///     key: Nat44UdpHashKey,
/// ) -> Result<(), Nat44UdpReconcileError> {
///     let permit = runtime.preflight_reconcile(config, key)?;
///     let _ = runtime.config();
///     permit.commit();
///     Ok(())
/// }
/// ```
///
/// ```compile_fail
/// use ruster_core::{
///     Nat44UdpConfig, Nat44UdpHashKey, Nat44UdpReconcileError, Nat44UdpRuntime,
/// };
///
/// fn permit_cannot_be_applied_to_another_runtime<'storage>(
///     first: &mut Nat44UdpRuntime<'storage>,
///     second: &mut Nat44UdpRuntime<'storage>,
///     config: Nat44UdpConfig,
///     key: Nat44UdpHashKey,
/// ) -> Result<(), Nat44UdpReconcileError> {
///     let permit = first.preflight_reconcile(config, key)?;
///     second.commit_reconcile(permit);
///     Ok(())
/// }
/// ```
#[must_use = "dropping a UDP NAT reconcile permit leaves the runtime unchanged"]
pub struct Nat44UdpReconcilePermit<'runtime, 'storage> {
    runtime: &'runtime mut Nat44UdpRuntime<'storage>,
    config: Nat44UdpConfig,
    hash_key: Nat44UdpHashKey,
    next_runtime_epoch: u128,
}

impl Nat44UdpReconcilePermit<'_, '_> {
    /// Consumes this one-shot permit and applies its prevalidated reconcile.
    pub fn commit(self) -> Nat44UdpReconcileReport {
        self.runtime.commit_prevalidated_reconcile(
            self.config,
            self.hash_key,
            self.next_runtime_epoch,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Nat44UdpBackingIdentity {
    address: usize,
    length: usize,
}

impl Nat44UdpBackingIdentity {
    fn of<T>(storage: &[T]) -> Self {
        Self {
            address: storage.as_ptr() as usize,
            length: storage.len(),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Nat44UdpReconcileBinding {
    runtime_identity: u64,
    mappings: Nat44UdpBackingIdentity,
    peers: Nat44UdpBackingIdentity,
    mapping_buckets: Nat44UdpBackingIdentity,
    mapping_nodes: Nat44UdpBackingIdentity,
    peer_buckets: Nat44UdpBackingIdentity,
    peer_nodes: Nat44UdpBackingIdentity,
    port_owners: Nat44UdpBackingIdentity,
}

impl Nat44UdpReconcileBinding {
    fn new(
        runtime_identity: u64,
        mappings: &[Nat44UdpMappingSlot],
        peers: &[Nat44UdpPeerSlot],
        indexes: &Nat44UdpIndexStorage<'_>,
    ) -> Self {
        Self {
            runtime_identity,
            mappings: Nat44UdpBackingIdentity::of(mappings),
            peers: Nat44UdpBackingIdentity::of(peers),
            mapping_buckets: Nat44UdpBackingIdentity::of(indexes.mapping_buckets),
            mapping_nodes: Nat44UdpBackingIdentity::of(indexes.mapping_nodes),
            peer_buckets: Nat44UdpBackingIdentity::of(indexes.peer_buckets),
            peer_nodes: Nat44UdpBackingIdentity::of(indexes.peer_nodes),
            port_owners: Nat44UdpBackingIdentity::of(indexes.port_owners),
        }
    }
}

/// Fixed-capacity, worker-local UDP NAPT state.
///
/// The caller owns the mapping, peer, directory, and port-owner storage.
/// Recreating the runtime deliberately clears it. The `Rc` marker makes the
/// runtime `!Send + !Sync`, so a mapping shard cannot accidentally migrate
/// between packet workers.
///
/// ```compile_fail
/// use ruster_core::Nat44UdpRuntime;
/// fn assert_send<T: Send>() {}
/// assert_send::<Nat44UdpRuntime<'static>>();
/// ```
///
/// ```compile_fail
/// use ruster_core::Nat44UdpRuntime;
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<Nat44UdpRuntime<'static>>();
/// ```
pub struct Nat44UdpRuntime<'a> {
    config: Nat44UdpConfig,
    mappings: &'a mut [Nat44UdpMappingSlot],
    peers: &'a mut [Nat44UdpPeerSlot],
    mapping_directory: FixedDirectory<'a>,
    peer_directory: FixedDirectory<'a>,
    port_owners: PortOwnerTable<'a>,
    hash_key: Nat44UdpHashKey,
    watermark_ms: Option<u64>,
    next_generation: u64,
    runtime_epoch: u128,
    state_revision: u128,
    #[allow(dead_code)] // Retained as defense-in-depth for the publication owner.
    reconcile_binding: Nat44UdpReconcileBinding,
    counters: Nat44UdpCounters,
    #[cfg(test)]
    mapping_lookup_probes: Cell<usize>,
    #[cfg(test)]
    peer_lookup_probes: Cell<usize>,
    #[cfg(test)]
    port_owner_probes: Cell<usize>,
    _worker_local: PhantomData<Rc<()>>,
}

impl<'a> Nat44UdpRuntime<'a> {
    pub fn new(
        config: Nat44UdpConfig,
        mappings: &'a mut [Nat44UdpMappingSlot],
        peers: &'a mut [Nat44UdpPeerSlot],
        indexes: Nat44UdpIndexStorage<'a>,
        hash_key: Nat44UdpHashKey,
    ) -> Result<Self, Nat44UdpRuntimeConfigError> {
        if indexes.mapping_nodes.len() != mappings.len() {
            return Err(Nat44UdpRuntimeConfigError::MappingNodeCountMismatch);
        }
        if indexes.peer_nodes.len() != peers.len() {
            return Err(Nat44UdpRuntimeConfigError::PeerNodeCountMismatch);
        }
        FixedDirectory::validate_config(indexes.mapping_buckets.len(), indexes.mapping_nodes.len())
            .map_err(|_| Nat44UdpRuntimeConfigError::MappingDirectoryInvalid)?;
        FixedDirectory::validate_config(indexes.peer_buckets.len(), indexes.peer_nodes.len())
            .map_err(|_| Nat44UdpRuntimeConfigError::PeerDirectoryInvalid)?;
        PortOwnerTable::validate_config(
            indexes.port_owners.len(),
            config.first_port,
            config.last_port,
            mappings.len(),
        )
        .map_err(|_| Nat44UdpRuntimeConfigError::PortOwnerTableInvalid)?;
        let runtime_identity = allocate_udp_runtime_identity()?;
        let reconcile_binding =
            Nat44UdpReconcileBinding::new(runtime_identity, mappings, peers, &indexes);
        let mapping_directory =
            FixedDirectory::new(indexes.mapping_buckets, indexes.mapping_nodes, hash_key.0)
                .expect("mapping directory dimensions were preflighted");
        let peer_directory =
            FixedDirectory::new(indexes.peer_buckets, indexes.peer_nodes, hash_key.0)
                .expect("peer directory dimensions were preflighted");
        let port_owners = PortOwnerTable::new(
            indexes.port_owners,
            config.first_port,
            config.last_port,
            mappings.len(),
        )
        .expect("port owner dimensions were preflighted");
        mappings.fill(Nat44UdpMappingSlot::default());
        peers.fill(Nat44UdpPeerSlot::default());
        Ok(Self {
            config,
            mappings,
            peers,
            mapping_directory,
            peer_directory,
            port_owners,
            hash_key,
            watermark_ms: None,
            next_generation: 1,
            runtime_epoch: 1,
            state_revision: 0,
            reconcile_binding,
            counters: Nat44UdpCounters::default(),
            #[cfg(test)]
            mapping_lookup_probes: Cell::new(0),
            #[cfg(test)]
            peer_lookup_probes: Cell::new(0),
            #[cfg(test)]
            port_owner_probes: Cell::new(0),
            _worker_local: PhantomData,
        })
    }

    #[must_use]
    pub const fn config(&self) -> Nat44UdpConfig {
        self.config
    }

    /// Checks the exact control-plane binding without exposing the hash key.
    #[must_use]
    pub fn publication_binding_matches(
        &self,
        config: Nat44UdpConfig,
        hash_key: Nat44UdpHashKey,
    ) -> bool {
        self.config == config && self.hash_key == hash_key
    }

    #[must_use]
    pub const fn counters(&self) -> Nat44UdpCounters {
        self.counters
    }

    #[must_use]
    pub fn mappings(&self) -> &[Nat44UdpMappingSlot] {
        self.mappings
    }

    #[must_use]
    pub fn peers(&self) -> &[Nat44UdpPeerSlot] {
        self.peers
    }

    #[must_use]
    pub fn storage_shape(&self) -> Nat44UdpStorageShape {
        Nat44UdpStorageShape {
            mapping_slots: u32::try_from(self.mappings.len())
                .expect("validated mapping capacity fits u32"),
            peer_slots: u32::try_from(self.peers.len()).expect("validated peer capacity fits u32"),
            mapping_buckets: u32::try_from(self.mapping_directory.bucket_count())
                .expect("validated mapping bucket count fits u32"),
            mapping_nodes: u32::try_from(self.mapping_directory.node_capacity())
                .expect("validated mapping node count fits u32"),
            peer_buckets: u32::try_from(self.peer_directory.bucket_count())
                .expect("validated peer bucket count fits u32"),
            peer_nodes: u32::try_from(self.peer_directory.node_capacity())
                .expect("validated peer node count fits u32"),
            port_owner_slots: u32::try_from(self.port_owners.slot_count())
                .expect("validated port-owner count fits u32"),
        }
    }

    #[cfg(test)]
    fn reset_index_probe_counts(&self) {
        self.mapping_lookup_probes.set(0);
        self.peer_lookup_probes.set(0);
        self.port_owner_probes.set(0);
    }

    #[cfg(test)]
    fn index_probe_counts(&self) -> (usize, usize, usize) {
        (
            self.mapping_lookup_probes.get(),
            self.peer_lookup_probes.get(),
            self.port_owner_probes.get(),
        )
    }

    pub fn reconcile(
        &mut self,
        config: Nat44UdpConfig,
        hash_key: Nat44UdpHashKey,
    ) -> Result<Nat44UdpReconcileReport, Nat44UdpReconcileError> {
        self.preflight_reconcile(config, hash_key)
            .map(Nat44UdpReconcilePermit::commit)
    }

    pub fn preflight_reconcile<'runtime>(
        &'runtime mut self,
        config: Nat44UdpConfig,
        hash_key: Nat44UdpHashKey,
    ) -> Result<Nat44UdpReconcilePermit<'runtime, 'a>, Nat44UdpReconcileError> {
        if hash_key == self.hash_key {
            return Err(Nat44UdpReconcileError::HashKeyNotRotated);
        }
        let next_runtime_epoch = self
            .runtime_epoch
            .checked_add(1)
            .ok_or(Nat44UdpReconcileError::RuntimeEpochExhausted)?;
        if PortOwnerTable::validate_config(
            self.port_owners.slot_count(),
            config.first_port,
            config.last_port,
            self.mappings.len(),
        )
        .is_err()
        {
            return Err(Nat44UdpReconcileError::PortOwnerTableInvalid);
        }
        Ok(Nat44UdpReconcilePermit {
            runtime: self,
            config,
            hash_key,
            next_runtime_epoch,
        })
    }

    fn commit_prevalidated_reconcile(
        &mut self,
        config: Nat44UdpConfig,
        hash_key: Nat44UdpHashKey,
        next_runtime_epoch: u128,
    ) -> Nat44UdpReconcileReport {
        let mappings_flushed = self
            .mappings
            .iter()
            .filter(|mapping| mapping.occupied)
            .count();
        let peers_flushed = self.peers.iter().filter(|peer| peer.occupied).count();
        self.mappings.fill(Nat44UdpMappingSlot::default());
        self.peers.fill(Nat44UdpPeerSlot::default());
        self.mapping_directory.clear_with_key(hash_key.0);
        self.peer_directory.clear_with_key(hash_key.0);
        self.port_owners.reconfigure_prevalidated_and_clear(
            config.first_port,
            config.last_port,
            self.mappings.len(),
        );
        self.config = config;
        self.hash_key = hash_key;
        self.watermark_ms = None;
        self.next_generation = 1;
        self.runtime_epoch = next_runtime_epoch;
        self.state_revision = 0;
        self.counters.reconciliations = self.counters.reconciliations.saturating_add(1);
        Nat44UdpReconcileReport {
            mappings_flushed,
            peers_flushed,
        }
    }

    #[allow(dead_code)] // Test/future publication-owner identity; not a permit authority.
    fn reconcile_binding(&self) -> Nat44UdpReconcileBinding {
        self.reconcile_binding
    }

    pub(crate) fn record_config_mismatch(&mut self) {
        self.counters.config_mismatches = self.counters.config_mismatches.saturating_add(1);
    }

    pub(crate) fn observe_now(&mut self, now_ms: u64) -> Result<(), Nat44UdpPlanError> {
        if self
            .watermark_ms
            .is_some_and(|watermark| now_ms < watermark)
        {
            self.counters.clock_regressions = self.counters.clock_regressions.saturating_add(1);
            return Err(Nat44UdpPlanError::ClockRegression);
        }
        if self.watermark_ms != Some(now_ms) {
            self.state_revision = self
                .state_revision
                .checked_add(1)
                .ok_or(Nat44UdpPlanError::StateRevisionExhausted)?;
            self.watermark_ms = Some(now_ms);
        }
        Ok(())
    }

    pub(crate) fn plan_outbound(
        &mut self,
        internal_address: Ipv4Address,
        internal_port: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<Nat44UdpOutboundPlan, Nat44UdpPlanError> {
        self.observe_now(now_ms)?;
        self.plan_outbound_after_clock(internal_address, internal_port, remote_address, now_ms)
    }

    pub(crate) fn plan_outbound_read_only(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<Nat44UdpOutboundPlan, Nat44UdpPlanError> {
        self.check_now_read_only(now_ms)?;
        self.plan_outbound_after_clock(internal_address, internal_port, remote_address, now_ms)
    }

    fn plan_outbound_after_clock(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<Nat44UdpOutboundPlan, Nat44UdpPlanError> {
        if self.state_revision == u128::MAX {
            return Err(Nat44UdpPlanError::StateRevisionExhausted);
        }
        let exact_mapping = self.find_mapping(internal_address, internal_port)?;
        if let Some((mapping_index, mapping)) =
            exact_mapping.filter(|(_, mapping)| self.mapping_is_live(*mapping, now_ms))
        {
            if self.peer_exists(mapping_index, mapping.generation, remote_address)? {
                let mut refreshed = mapping;
                refreshed.last_outbound_ms = now_ms;
                return self.prepare_outbound_plan(
                    Nat44UdpOutboundPlan {
                        mapping_index: encode_udp_index(mapping_index),
                        mapping: refreshed,
                        peer_index: UDP_INDEX_NONE,
                        peer: None,
                        mapping_created: false,
                        mapping_expired: false,
                        peer_created: false,
                        expected_runtime_epoch: self.runtime_epoch,
                        expected_revision: self.state_revision,
                        planned_now_ms: now_ms,
                        displaced_port_mapping_index: UDP_INDEX_NONE,
                        prepared: PreparedNat44UdpOutboundCommit::EMPTY,
                    },
                    None,
                );
            }
            let Some(peer_index) = self.find_reusable_peer(now_ms) else {
                return Err(Nat44UdpPlanError::PeerFull);
            };
            let mut refreshed = mapping;
            refreshed.last_outbound_ms = now_ms;
            return self.prepare_outbound_plan(
                Nat44UdpOutboundPlan {
                    mapping_index: encode_udp_index(mapping_index),
                    mapping: refreshed,
                    peer_index: encode_udp_index(peer_index),
                    peer: Some(Nat44UdpPeerSlot {
                        occupied: true,
                        mapping_index,
                        mapping_generation: mapping.generation,
                        mapping_lifecycle_epoch: mapping.lifecycle_epoch,
                        remote_address,
                    }),
                    mapping_created: false,
                    mapping_expired: false,
                    peer_created: true,
                    expected_runtime_epoch: self.runtime_epoch,
                    expected_revision: self.state_revision,
                    planned_now_ms: now_ms,
                    displaced_port_mapping_index: UDP_INDEX_NONE,
                    prepared: PreparedNat44UdpOutboundCommit::EMPTY,
                },
                None,
            );
        }

        let mapping_index = if let Some((mapping_index, _)) = exact_mapping {
            mapping_index
        } else if let Some(mapping_index) = self.find_reusable_mapping(now_ms) {
            mapping_index
        } else {
            return Err(Nat44UdpPlanError::MappingFull);
        };
        let Some(peer_index) = self.find_reusable_peer(now_ms) else {
            return Err(Nat44UdpPlanError::PeerFull);
        };
        let Some(port) = self.allocate_port(internal_address, internal_port, now_ms)? else {
            return Err(Nat44UdpPlanError::PortExhausted);
        };
        let generation = self.next_nonzero_generation()?;
        let mapping_expired = self.mappings[mapping_index].occupied;
        self.prepare_outbound_plan(
            Nat44UdpOutboundPlan {
                mapping_index: encode_udp_index(mapping_index),
                mapping: Nat44UdpMappingSlot {
                    occupied: true,
                    generation,
                    lifecycle_epoch: self.runtime_epoch,
                    port_owned: true,
                    inside: self.config.inside,
                    internal_address,
                    internal_port,
                    public_port: port.port,
                    last_outbound_ms: now_ms,
                },
                peer_index: encode_udp_index(peer_index),
                peer: Some(Nat44UdpPeerSlot {
                    occupied: true,
                    mapping_index,
                    mapping_generation: generation,
                    mapping_lifecycle_epoch: self.runtime_epoch,
                    remote_address,
                }),
                mapping_created: true,
                mapping_expired,
                peer_created: true,
                expected_runtime_epoch: self.runtime_epoch,
                expected_revision: self.state_revision,
                planned_now_ms: now_ms,
                displaced_port_mapping_index: encode_optional_udp_index(
                    port.displaced_mapping_index,
                ),
                prepared: PreparedNat44UdpOutboundCommit::EMPTY,
            },
            port.expected_owner,
        )
    }

    pub(crate) fn commit_outbound(
        &mut self,
        plan: Nat44UdpOutboundPlan,
        now_ms: u64,
    ) -> Result<(), Nat44UdpCommitError> {
        self.revalidate_outbound_commit(plan, now_ms)?;
        let prepared = plan.prepared;
        if let Some(mutation) = prepared.mapping {
            self.apply_mapping_directory_mutation(mutation);
        }
        if let Some(mutation) = prepared.peer {
            self.apply_peer_directory_mutation(mutation);
        }
        if let Some(owner) = prepared.owner {
            let replacement = PortOwnerToken::from_prevalidated_index(
                plan.mapping_index,
                plan.mapping.generation,
                plan.mapping.lifecycle_epoch,
            );
            self.port_owners
                .apply_prepared_move_topology(owner, replacement);
        }
        if let Some(index) = plan
            .displaced_port_mapping_index()
            .filter(|index| *index != plan.mapping_index())
        {
            self.mappings[index].port_owned = false;
        }
        self.mappings[plan.mapping_index()] = plan.mapping;
        if let (Some(index), Some(peer)) = (plan.peer_index(), plan.peer) {
            self.peers[index] = peer;
        }
        self.watermark_ms = Some(now_ms);
        self.state_revision = self
            .state_revision
            .checked_add(1)
            .expect("preflight rejected state revision exhaustion");
        if plan.mapping_created {
            self.counters.mappings_created = self.counters.mappings_created.saturating_add(1);
            if plan.mapping_expired {
                self.counters.mappings_expired = self.counters.mappings_expired.saturating_add(1);
            }
            self.next_generation = plan
                .mapping
                .generation
                .checked_add(1)
                .expect("preflight rejected mapping generation exhaustion");
        } else {
            self.counters.mappings_reused = self.counters.mappings_reused.saturating_add(1);
        }
        if plan.peer_created {
            self.counters.peers_created = self.counters.peers_created.saturating_add(1);
        }
        self.counters.outbound_translated = self.counters.outbound_translated.saturating_add(1);
        debug_assert!(self.validate_indexes().is_ok());
        Ok(())
    }

    pub(crate) fn plan_inbound(
        &mut self,
        public_port: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<Nat44UdpInboundPlan, Nat44UdpPlanError> {
        self.observe_now(now_ms)?;
        self.plan_inbound_after_clock(public_port, remote_address, now_ms)
    }

    pub(crate) fn plan_inbound_read_only(
        &self,
        public_port: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<Nat44UdpInboundPlan, Nat44UdpPlanError> {
        self.check_now_read_only(now_ms)?;
        self.plan_inbound_after_clock(public_port, remote_address, now_ms)
    }

    fn plan_inbound_after_clock(
        &self,
        public_port: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<Nat44UdpInboundPlan, Nat44UdpPlanError> {
        if self.state_revision == u128::MAX {
            return Err(Nat44UdpPlanError::StateRevisionExhausted);
        }
        let Some((mapping_index, mapping)) = self.mapping_for_public_port(public_port, now_ms)?
        else {
            return Err(Nat44UdpPlanError::MappingMiss);
        };
        if !self.peer_exists(mapping_index, mapping.generation, remote_address)? {
            return Err(Nat44UdpPlanError::FilterDenied);
        }
        Ok(Nat44UdpInboundPlan {
            mapping_index,
            mapping_generation: mapping.generation,
            internal_address: mapping.internal_address,
            internal_port: mapping.internal_port,
            expected_runtime_epoch: self.runtime_epoch,
            expected_revision: self.state_revision,
            planned_now_ms: now_ms,
        })
    }

    pub(crate) fn commit_inbound(
        &mut self,
        plan: Nat44UdpInboundPlan,
        now_ms: u64,
    ) -> Result<(), Nat44UdpCommitError> {
        if plan.expected_runtime_epoch != self.runtime_epoch {
            return Err(Nat44UdpCommitError::RuntimeEpochChanged);
        }
        if plan.expected_revision != self.state_revision {
            return Err(Nat44UdpCommitError::StateRevisionChanged);
        }
        if plan.planned_now_ms != now_ms {
            return Err(Nat44UdpCommitError::CommitTimeChanged);
        }
        if !self
            .mappings
            .get(plan.mapping_index)
            .is_some_and(|mapping| {
                mapping.occupied && mapping.generation == plan.mapping_generation
            })
        {
            return Err(Nat44UdpCommitError::MappingSlotChanged);
        }
        let next_revision = self
            .state_revision
            .checked_add(1)
            .ok_or(Nat44UdpCommitError::StateRevisionExhausted)?;
        self.watermark_ms = Some(now_ms);
        self.state_revision = next_revision;
        self.counters.inbound_translated = self.counters.inbound_translated.saturating_add(1);
        debug_assert!(self.validate_indexes().is_ok());
        Ok(())
    }

    pub(crate) fn record_plan_error(&mut self, error: Nat44UdpPlanError) {
        match error {
            Nat44UdpPlanError::MappingMiss => {
                self.counters.mapping_misses = self.counters.mapping_misses.saturating_add(1);
            }
            Nat44UdpPlanError::FilterDenied => {
                self.counters.filter_denied = self.counters.filter_denied.saturating_add(1);
            }
            Nat44UdpPlanError::MappingFull => {
                self.counters.mapping_full = self.counters.mapping_full.saturating_add(1);
            }
            Nat44UdpPlanError::PeerFull => {
                self.counters.peer_full = self.counters.peer_full.saturating_add(1);
            }
            Nat44UdpPlanError::PortExhausted => {
                self.counters.port_exhausted = self.counters.port_exhausted.saturating_add(1);
            }
            Nat44UdpPlanError::ClockRegression => {
                // `observe_now` owns this counter so a forwarding caller can
                // record the typed plan error without double-counting it.
            }
            Nat44UdpPlanError::IndexCorrupt
            | Nat44UdpPlanError::GenerationExhausted
            | Nat44UdpPlanError::StateRevisionExhausted => {
                self.counters.config_mismatches = self.counters.config_mismatches.saturating_add(1);
            }
        }
    }

    pub(crate) fn record_read_only_plan_error(&mut self, error: Nat44UdpPlanError) {
        self.record_plan_error(error);
        if error == Nat44UdpPlanError::ClockRegression {
            self.counters.clock_regressions = self.counters.clock_regressions.saturating_add(1);
        }
    }

    pub(crate) fn inspect_icmpv4(
        &self,
        public_port: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<Nat44UdpIcmpv4Lookup, Nat44UdpPlanError> {
        if self
            .watermark_ms
            .is_some_and(|watermark| now_ms < watermark)
        {
            return Err(Nat44UdpPlanError::ClockRegression);
        }
        let Some((mapping_index, mapping)) = self.mapping_for_public_port(public_port, now_ms)?
        else {
            return Err(Nat44UdpPlanError::MappingMiss);
        };
        if !self.peer_exists(mapping_index, mapping.generation, remote_address)? {
            return Err(Nat44UdpPlanError::FilterDenied);
        }
        Ok(Nat44UdpIcmpv4Lookup {
            internal_address: mapping.internal_address,
            internal_port: mapping.internal_port,
        })
    }

    fn prepare_outbound_plan(
        &self,
        mut plan: Nat44UdpOutboundPlan,
        expected_port_owner: Option<PortOwnerToken>,
    ) -> Result<Nat44UdpOutboundPlan, Nat44UdpPlanError> {
        plan.prepared = self
            .prepare_outbound_index_mutations(plan, expected_port_owner, plan.planned_now_ms)
            .map_err(|_| Nat44UdpPlanError::IndexCorrupt)?;
        Ok(plan)
    }

    fn prepare_outbound_index_mutations(
        &self,
        plan: Nat44UdpOutboundPlan,
        expected_port_owner: Option<PortOwnerToken>,
        now_ms: u64,
    ) -> Result<PreparedNat44UdpOutboundCommit, Nat44UdpCommitError> {
        if plan.expected_runtime_epoch != self.runtime_epoch {
            return Err(Nat44UdpCommitError::RuntimeEpochChanged);
        }
        if plan.expected_revision != self.state_revision {
            return Err(Nat44UdpCommitError::StateRevisionChanged);
        }
        if plan.planned_now_ms != now_ms {
            return Err(Nat44UdpCommitError::CommitTimeChanged);
        }
        if self.state_revision == u128::MAX {
            return Err(Nat44UdpCommitError::StateRevisionExhausted);
        }
        if let Some(index) = plan.displaced_port_mapping_index() {
            let displaced = self
                .mappings
                .get(index)
                .copied()
                .ok_or(Nat44UdpCommitError::MappingSlotChanged)?;
            if !displaced.occupied
                || !displaced.port_owned
                || self.mapping_is_live(displaced, now_ms)
            {
                return Err(Nat44UdpCommitError::MappingSlotChanged);
            }
        }

        let mapping = if plan.mapping_created {
            let mapping_index = plan.mapping_index();
            let expected_mapping = self.mappings[mapping_index];
            let words = Self::mapping_words(plan.mapping);
            Some(if expected_mapping.occupied {
                PreparedUdpDirectoryMutation::Relink(
                    self.mapping_directory
                        .prepare_relink(mapping_index, DirectoryHashDomain::UdpMapping, &words)
                        .map_err(|_| Nat44UdpCommitError::IndexCorrupt)?,
                )
            } else {
                PreparedUdpDirectoryMutation::Link(
                    self.mapping_directory
                        .prepare_link(mapping_index, DirectoryHashDomain::UdpMapping, &words)
                        .map_err(|_| Nat44UdpCommitError::IndexCorrupt)?,
                )
            })
        } else {
            None
        };

        let peer = if let (Some(index), Some(peer)) = (plan.peer_index(), plan.peer) {
            let expected_peer = self.peers[index];
            let words = Self::peer_words(peer);
            Some(if expected_peer.occupied {
                PreparedUdpDirectoryMutation::Relink(
                    self.peer_directory
                        .prepare_relink(index, DirectoryHashDomain::UdpPeer, &words)
                        .map_err(|_| Nat44UdpCommitError::IndexCorrupt)?,
                )
            } else {
                PreparedUdpDirectoryMutation::Link(
                    self.peer_directory
                        .prepare_link(index, DirectoryHashDomain::UdpPeer, &words)
                        .map_err(|_| Nat44UdpCommitError::IndexCorrupt)?,
                )
            })
        } else {
            None
        };

        let owner = if plan.mapping_created {
            let mapping_index = plan.mapping_index();
            let expected_mapping = self.mappings[mapping_index];
            let old_owner = if expected_mapping.occupied && expected_mapping.port_owned {
                Some((
                    expected_mapping.public_port,
                    self.mapping_owner_token(mapping_index, expected_mapping)
                        .map_err(|_| Nat44UdpCommitError::IndexCorrupt)?,
                ))
            } else {
                None
            };
            let replacement = self
                .mapping_owner_token(mapping_index, plan.mapping)
                .map_err(|_| Nat44UdpCommitError::IndexCorrupt)?;
            Some(
                self.port_owners
                    .prepare_move(
                        old_owner,
                        plan.mapping.public_port,
                        expected_port_owner,
                        replacement,
                    )
                    .map_err(|_| Nat44UdpCommitError::IndexCorrupt)?
                    .topology(),
            )
        } else {
            None
        };

        if !mapping.is_none_or(|mutation| self.mapping_mutation_matches(mutation))
            || !peer.is_none_or(|mutation| self.peer_mutation_matches(mutation))
        {
            return Err(Nat44UdpCommitError::IndexCorrupt);
        }
        Ok(PreparedNat44UdpOutboundCommit {
            mapping,
            peer,
            owner,
        })
    }

    fn revalidate_outbound_commit(
        &self,
        plan: Nat44UdpOutboundPlan,
        now_ms: u64,
    ) -> Result<(), Nat44UdpCommitError> {
        if plan.expected_runtime_epoch != self.runtime_epoch {
            return Err(Nat44UdpCommitError::RuntimeEpochChanged);
        }
        if plan.expected_revision != self.state_revision {
            return Err(Nat44UdpCommitError::StateRevisionChanged);
        }
        if plan.planned_now_ms != now_ms {
            return Err(Nat44UdpCommitError::CommitTimeChanged);
        }
        if self.state_revision == u128::MAX {
            return Err(Nat44UdpCommitError::StateRevisionExhausted);
        }
        if !plan
            .prepared
            .mapping
            .is_none_or(|mutation| self.mapping_mutation_matches(mutation))
            || !plan
                .prepared
                .peer
                .is_none_or(|mutation| self.peer_mutation_matches(mutation))
        {
            return Err(Nat44UdpCommitError::IndexCorrupt);
        }
        Ok(())
    }

    fn mapping_mutation_matches(&self, mutation: PreparedUdpDirectoryMutation) -> bool {
        match mutation {
            PreparedUdpDirectoryMutation::Link(prepared) => {
                self.mapping_directory.prepared_link_matches(prepared)
            }
            PreparedUdpDirectoryMutation::Relink(prepared) => {
                self.mapping_directory.prepared_relink_matches(prepared)
            }
        }
    }

    fn peer_mutation_matches(&self, mutation: PreparedUdpDirectoryMutation) -> bool {
        match mutation {
            PreparedUdpDirectoryMutation::Link(prepared) => {
                self.peer_directory.prepared_link_matches(prepared)
            }
            PreparedUdpDirectoryMutation::Relink(prepared) => {
                self.peer_directory.prepared_relink_matches(prepared)
            }
        }
    }

    fn apply_mapping_directory_mutation(&mut self, mutation: PreparedUdpDirectoryMutation) {
        match mutation {
            PreparedUdpDirectoryMutation::Link(prepared) => {
                self.mapping_directory.apply_prepared_link(prepared);
            }
            PreparedUdpDirectoryMutation::Relink(prepared) => {
                self.mapping_directory.apply_prepared_relink(prepared);
            }
        }
    }

    fn apply_peer_directory_mutation(&mut self, mutation: PreparedUdpDirectoryMutation) {
        match mutation {
            PreparedUdpDirectoryMutation::Link(prepared) => {
                self.peer_directory.apply_prepared_link(prepared);
            }
            PreparedUdpDirectoryMutation::Relink(prepared) => {
                self.peer_directory.apply_prepared_relink(prepared);
            }
        }
    }

    fn mapping_for_public_port(
        &self,
        public_port: u16,
        now_ms: u64,
    ) -> Result<Option<(usize, Nat44UdpMappingSlot)>, Nat44UdpPlanError> {
        let owner = match self.port_owners.owner(public_port) {
            Ok(owner) => owner,
            Err(PortOwnerError::PortOutOfRange) => return Ok(None),
            Err(_) => return Err(Nat44UdpPlanError::IndexCorrupt),
        };
        let Some(owner) = owner else {
            return Ok(None);
        };
        if owner.runtime_epoch() != self.runtime_epoch {
            return Err(Nat44UdpPlanError::IndexCorrupt);
        }
        let mapping = self
            .mappings
            .get(owner.state_index())
            .copied()
            .ok_or(Nat44UdpPlanError::IndexCorrupt)?;
        if !mapping.occupied
            || !mapping.port_owned
            || mapping.generation != owner.state_generation()
            || mapping.lifecycle_epoch != owner.runtime_epoch()
            || mapping.public_port != public_port
        {
            return Err(Nat44UdpPlanError::IndexCorrupt);
        }
        if !self.mapping_is_live(mapping, now_ms) {
            return Ok(None);
        }
        Ok(Some((owner.state_index(), mapping)))
    }

    fn mapping_owner_token(
        &self,
        mapping_index: usize,
        mapping: Nat44UdpMappingSlot,
    ) -> Result<PortOwnerToken, PortOwnerError> {
        PortOwnerToken::new(mapping_index, mapping.generation, mapping.lifecycle_epoch)
    }

    const fn mapping_lookup_words(
        inside: IfId,
        internal_address: Ipv4Address,
        internal_port: u16,
    ) -> [u64; 3] {
        [
            inside.0 as u64,
            u32::from_be_bytes(internal_address.octets()) as u64,
            internal_port as u64,
        ]
    }

    const fn mapping_words(mapping: Nat44UdpMappingSlot) -> [u64; 3] {
        Self::mapping_lookup_words(
            mapping.inside,
            mapping.internal_address,
            mapping.internal_port,
        )
    }

    const fn peer_lookup_words(
        mapping_index: usize,
        mapping_generation: u64,
        lifecycle_epoch: u128,
        remote_address: Ipv4Address,
    ) -> [u64; 5] {
        [
            mapping_index as u64,
            mapping_generation,
            (lifecycle_epoch >> 64) as u64,
            lifecycle_epoch as u64,
            u32::from_be_bytes(remote_address.octets()) as u64,
        ]
    }

    const fn peer_words(peer: Nat44UdpPeerSlot) -> [u64; 5] {
        Self::peer_lookup_words(
            peer.mapping_index,
            peer.mapping_generation,
            peer.mapping_lifecycle_epoch,
            peer.remote_address,
        )
    }

    fn validate_indexes(&self) -> Result<(), Nat44UdpIndexInvariantError> {
        let hash_key = self.hash_key.0;
        self.mapping_directory
            .validate_semantics(|index| {
                let mapping = self.mappings[index];
                mapping.occupied.then(|| {
                    hash_key.hash_words(
                        DirectoryHashDomain::UdpMapping,
                        &Self::mapping_words(mapping),
                    )
                })
            })
            .map_err(Nat44UdpIndexInvariantError::Mapping)?;
        self.peer_directory
            .validate_semantics(|index| {
                let peer = self.peers[index];
                peer.occupied.then(|| {
                    hash_key.hash_words(DirectoryHashDomain::UdpPeer, &Self::peer_words(peer))
                })
            })
            .map_err(Nat44UdpIndexInvariantError::Peer)?;
        self.port_owners
            .validate_semantics(|index| {
                let mapping = self.mappings[index];
                (mapping.occupied && mapping.port_owned).then_some(PortOwnerExpectation {
                    port: mapping.public_port,
                    state_generation: mapping.generation,
                    runtime_epoch: mapping.lifecycle_epoch,
                })
            })
            .map_err(Nat44UdpIndexInvariantError::Port)?;
        for (index, mapping) in self.mappings.iter().copied().enumerate() {
            if !mapping.occupied {
                continue;
            }
            if self.mappings[..index].iter().copied().any(|other| {
                other.occupied
                    && other.inside == mapping.inside
                    && other.internal_address == mapping.internal_address
                    && other.internal_port == mapping.internal_port
            }) {
                return Err(Nat44UdpIndexInvariantError::DuplicateMappingKey);
            }
        }
        for (index, peer) in self.peers.iter().copied().enumerate() {
            if !peer.occupied {
                continue;
            }
            if self.peers[..index].iter().copied().any(|other| {
                other.occupied
                    && other.mapping_index == peer.mapping_index
                    && other.mapping_generation == peer.mapping_generation
                    && other.mapping_lifecycle_epoch == peer.mapping_lifecycle_epoch
                    && other.remote_address == peer.remote_address
            }) {
                return Err(Nat44UdpIndexInvariantError::DuplicatePeerKey);
            }
        }
        Ok(())
    }

    fn mapping_is_live(&self, mapping: Nat44UdpMappingSlot, now_ms: u64) -> bool {
        mapping.occupied
            && now_ms >= mapping.last_outbound_ms
            && now_ms - mapping.last_outbound_ms < self.config.policy.idle_ttl_ms
    }

    fn find_mapping(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
    ) -> Result<Option<(usize, Nat44UdpMappingSlot)>, Nat44UdpPlanError> {
        let words = Self::mapping_lookup_words(self.config.inside, internal_address, internal_port);
        let probe = self
            .mapping_directory
            .lookup(DirectoryHashDomain::UdpMapping, &words, |index| {
                let mapping = self.mappings[index];
                mapping.occupied
                    && mapping.inside == self.config.inside
                    && mapping.internal_address == internal_address
                    && mapping.internal_port == internal_port
            })
            .map_err(|_| Nat44UdpPlanError::IndexCorrupt)?;
        #[cfg(test)]
        self.mapping_lookup_probes.set(
            self.mapping_lookup_probes
                .get()
                .saturating_add(probe.probes),
        );
        Ok(probe.state_index.map(|index| (index, self.mappings[index])))
    }

    fn find_reusable_mapping(&self, now_ms: u64) -> Option<usize> {
        self.mappings
            .iter()
            .position(|mapping| !self.mapping_is_live(*mapping, now_ms))
    }

    fn peer_exists(
        &self,
        mapping_index: usize,
        mapping_generation: u64,
        remote_address: Ipv4Address,
    ) -> Result<bool, Nat44UdpPlanError> {
        let mapping = self
            .mappings
            .get(mapping_index)
            .copied()
            .ok_or(Nat44UdpPlanError::IndexCorrupt)?;
        if !mapping.occupied || mapping.generation != mapping_generation {
            return Err(Nat44UdpPlanError::IndexCorrupt);
        }
        let words = Self::peer_lookup_words(
            mapping_index,
            mapping_generation,
            mapping.lifecycle_epoch,
            remote_address,
        );
        let probe = self
            .peer_directory
            .lookup(DirectoryHashDomain::UdpPeer, &words, |index| {
                let peer = self.peers[index];
                peer.occupied
                    && peer.mapping_index == mapping_index
                    && peer.mapping_generation == mapping_generation
                    && peer.mapping_lifecycle_epoch == mapping.lifecycle_epoch
                    && peer.remote_address == remote_address
            })
            .map_err(|_| Nat44UdpPlanError::IndexCorrupt)?;
        #[cfg(test)]
        self.peer_lookup_probes
            .set(self.peer_lookup_probes.get().saturating_add(probe.probes));
        Ok(probe.state_index.is_some())
    }

    fn find_reusable_peer(&self, now_ms: u64) -> Option<usize> {
        self.peers.iter().position(|peer| {
            if !peer.occupied {
                return true;
            }
            self.mappings.get(peer.mapping_index).is_none_or(|mapping| {
                !self.mapping_is_live(*mapping, now_ms)
                    || mapping.generation != peer.mapping_generation
                    || mapping.lifecycle_epoch != peer.mapping_lifecycle_epoch
            })
        })
    }

    fn select_port(
        &self,
        port: u16,
        now_ms: u64,
    ) -> Result<Option<Nat44UdpPortSelection>, Nat44UdpPlanError> {
        #[cfg(test)]
        self.port_owner_probes
            .set(self.port_owner_probes.get().saturating_add(1));
        let owner = self
            .port_owners
            .owner(port)
            .map_err(|_| Nat44UdpPlanError::IndexCorrupt)?;
        let Some(owner) = owner else {
            return Ok(Some(Nat44UdpPortSelection {
                port,
                expected_owner: None,
                displaced_mapping_index: None,
            }));
        };
        if owner.runtime_epoch() != self.runtime_epoch {
            return Err(Nat44UdpPlanError::IndexCorrupt);
        }
        let mapping = self
            .mappings
            .get(owner.state_index())
            .copied()
            .ok_or(Nat44UdpPlanError::IndexCorrupt)?;
        if !mapping.occupied
            || !mapping.port_owned
            || mapping.generation != owner.state_generation()
            || mapping.lifecycle_epoch != owner.runtime_epoch()
            || mapping.public_port != port
        {
            return Err(Nat44UdpPlanError::IndexCorrupt);
        }
        if self.mapping_is_live(mapping, now_ms) {
            return Ok(None);
        }
        Ok(Some(Nat44UdpPortSelection {
            port,
            expected_owner: Some(owner),
            displaced_mapping_index: Some(owner.state_index()),
        }))
    }

    fn allocate_port(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
        now_ms: u64,
    ) -> Result<Option<Nat44UdpPortSelection>, Nat44UdpPlanError> {
        if (self.config.first_port..=self.config.last_port).contains(&internal_port) {
            if let Some(selection) = self.select_port(internal_port, now_ms)? {
                return Ok(Some(selection));
            }
        }
        let pool_size = u32::from(self.config.last_port) - u32::from(self.config.first_port) + 1;
        let address = u32::from_be_bytes(internal_address.octets());
        let mixed = self.config.policy.allocator_seed
            ^ u64::from(address)
            ^ u64::from(internal_port).rotate_left(17);
        let start = u32::try_from(mixed % u64::from(pool_size))
            .map_err(|_| Nat44UdpPlanError::IndexCorrupt)?;
        for step in 0..pool_size {
            let offset = (start + step) % pool_size;
            let candidate = u16::try_from(u32::from(self.config.first_port) + offset)
                .map_err(|_| Nat44UdpPlanError::IndexCorrupt)?;
            if candidate == internal_port {
                continue;
            }
            if let Some(selection) = self.select_port(candidate, now_ms)? {
                return Ok(Some(selection));
            }
        }
        Ok(None)
    }

    fn next_nonzero_generation(&self) -> Result<u64, Nat44UdpPlanError> {
        if self.next_generation == 0 || self.next_generation == u64::MAX {
            return Err(Nat44UdpPlanError::GenerationExhausted);
        }
        Ok(self.next_generation)
    }

    fn check_now_read_only(&self, now_ms: u64) -> Result<(), Nat44UdpPlanError> {
        if self
            .watermark_ms
            .is_some_and(|watermark| now_ms < watermark)
        {
            Err(Nat44UdpPlanError::ClockRegression)
        } else {
            Ok(())
        }
    }
}

fn address_is_host_unicast(snapshot: &ForwardingSnapshot<'_>, address: Ipv4Address) -> bool {
    let octets = address.octets();
    if octets[0] == 0 || octets[0] == 127 || octets[0] >= 224 || octets == [255; 4] {
        return false;
    }
    !route::lookup(snapshot.routes, address).is_some_and(|selected| {
        selected.is_prefix_network_address(address)
            || selected.is_prefix_directed_broadcast(address)
    })
}

pub(crate) fn snapshot_authority(snapshot: &ForwardingSnapshot<'_>) -> u64 {
    snapshot.authority()
}

static NEXT_TCP_RUNTIME_IDENTITY: AtomicU64 = AtomicU64::new(1);

fn allocate_tcp_runtime_identity() -> Result<u64, Nat44TcpRuntimeConfigError> {
    allocate_tcp_runtime_identity_from(&NEXT_TCP_RUNTIME_IDENTITY)
}

fn allocate_tcp_runtime_identity_from(
    identities: &AtomicU64,
) -> Result<u64, Nat44TcpRuntimeConfigError> {
    identities
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |identity| {
            identity.checked_add(1)
        })
        .map_err(|_| Nat44TcpRuntimeConfigError::RuntimeIdentityExhausted)
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Nat44TcpHashKey(DirectoryHashKey);

impl std::fmt::Debug for Nat44TcpHashKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Nat44TcpHashKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44TcpHashKeyError {
    AllZero,
}

impl Nat44TcpHashKey {
    pub const fn new(first: u64, second: u64) -> Result<Self, Nat44TcpHashKeyError> {
        match DirectoryHashKey::new(first, second) {
            Ok(key) => Ok(Self(key)),
            Err(_) => Err(Nat44TcpHashKeyError::AllZero),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44TcpPolicy {
    idle_ttl_ms: u64,
    allocator_seed: u64,
    icmpv4_errors: Nat44Icmpv4ErrorPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44TcpPolicyError {
    IdleTtlTooShort,
    IdleTtlTooLong,
}

impl Nat44TcpPolicy {
    pub const fn new(idle_ttl_ms: u64, allocator_seed: u64) -> Result<Self, Nat44TcpPolicyError> {
        if idle_ttl_ms < NAT44_TCP_MIN_IDLE_TTL_MS {
            return Err(Nat44TcpPolicyError::IdleTtlTooShort);
        }
        if idle_ttl_ms > NAT44_TCP_MAX_IDLE_TTL_MS {
            return Err(Nat44TcpPolicyError::IdleTtlTooLong);
        }
        Ok(Self {
            idle_ttl_ms,
            allocator_seed,
            icmpv4_errors: Nat44Icmpv4ErrorPolicy::Disabled,
        })
    }

    #[must_use]
    pub const fn idle_ttl_ms(self) -> u64 {
        self.idle_ttl_ms
    }

    #[must_use]
    pub const fn allocator_seed(self) -> u64 {
        self.allocator_seed
    }

    #[must_use]
    pub const fn with_icmpv4_errors(mut self, policy: Nat44Icmpv4ErrorPolicy) -> Self {
        self.icmpv4_errors = policy;
        self
    }

    #[must_use]
    pub const fn icmpv4_errors(self) -> Nat44Icmpv4ErrorPolicy {
        self.icmpv4_errors
    }
}

impl Default for Nat44TcpPolicy {
    fn default() -> Self {
        Self {
            idle_ttl_ms: NAT44_TCP_DEFAULT_IDLE_TTL_MS,
            allocator_seed: 0,
            icmpv4_errors: Nat44Icmpv4ErrorPolicy::Disabled,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44TcpConfig {
    inside: IfId,
    outside: IfId,
    public_address: Ipv4Address,
    first_port: u16,
    last_port: u16,
    policy: Nat44TcpPolicy,
    authority: u64,
    snapshot_identity: [usize; 8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44TcpConfigError {
    InterfacesEqual,
    InsideInterfaceMissing,
    OutsideInterfaceMissing,
    PublicAddressNotHostUnicast,
    PublicBindingMissing,
    PublicBindingWrongInterface,
    PortPoolIncludesZero,
    PortPoolReversed,
}

impl Nat44TcpConfig {
    pub fn new(
        snapshot: &ForwardingSnapshot<'_>,
        inside: IfId,
        outside: IfId,
        public_address: Ipv4Address,
        first_port: u16,
        last_port: u16,
        policy: Nat44TcpPolicy,
    ) -> Result<Self, Nat44TcpConfigError> {
        if inside == outside {
            return Err(Nat44TcpConfigError::InterfacesEqual);
        }
        if !snapshot
            .interfaces
            .iter()
            .any(|interface| interface.id == inside)
        {
            return Err(Nat44TcpConfigError::InsideInterfaceMissing);
        }
        if !snapshot
            .interfaces
            .iter()
            .any(|interface| interface.id == outside)
        {
            return Err(Nat44TcpConfigError::OutsideInterfaceMissing);
        }
        if !address_is_host_unicast(snapshot, public_address) {
            return Err(Nat44TcpConfigError::PublicAddressNotHostUnicast);
        }
        let Some(binding) = snapshot
            .local_ipv4
            .iter()
            .find(|binding| binding.address == public_address)
        else {
            return Err(Nat44TcpConfigError::PublicBindingMissing);
        };
        if binding.interface != outside {
            return Err(Nat44TcpConfigError::PublicBindingWrongInterface);
        }
        if first_port == 0 {
            return Err(Nat44TcpConfigError::PortPoolIncludesZero);
        }
        if first_port > last_port {
            return Err(Nat44TcpConfigError::PortPoolReversed);
        }
        Ok(Self {
            inside,
            outside,
            public_address,
            first_port,
            last_port,
            policy,
            authority: snapshot_authority(snapshot),
            snapshot_identity: snapshot.identity(),
        })
    }

    #[must_use]
    pub const fn inside(self) -> IfId {
        self.inside
    }

    #[must_use]
    pub const fn outside(self) -> IfId {
        self.outside
    }

    #[must_use]
    pub const fn public_address(self) -> Ipv4Address {
        self.public_address
    }

    #[must_use]
    pub const fn first_port(self) -> u16 {
        self.first_port
    }

    #[must_use]
    pub const fn last_port(self) -> u16 {
        self.last_port
    }

    #[must_use]
    pub const fn policy(self) -> Nat44TcpPolicy {
        self.policy
    }

    pub(crate) fn authority_matches(self, snapshot: &ForwardingSnapshot<'_>) -> bool {
        self.authority == snapshot_authority(snapshot)
            && self.snapshot_identity == snapshot.identity()
    }

    pub(crate) fn realm_matches_udp(self, udp: Nat44UdpConfig) -> bool {
        self.inside == udp.inside
            && self.outside == udp.outside
            && self.public_address == udp.public_address
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44TcpMappingSlot {
    occupied: bool,
    generation: u64,
    lifecycle_epoch: u128,
    port_owned: bool,
    inside: IfId,
    internal_address: Ipv4Address,
    internal_port: u16,
    public_port: u16,
    last_activity_ms: u64,
}

impl Default for Nat44TcpMappingSlot {
    fn default() -> Self {
        Self {
            occupied: false,
            generation: 0,
            lifecycle_epoch: 0,
            port_owned: false,
            inside: IfId(0),
            internal_address: Ipv4Address::from_octets([0; 4]),
            internal_port: 0,
            public_port: 0,
            last_activity_ms: 0,
        }
    }
}

impl Nat44TcpMappingSlot {
    #[must_use]
    pub const fn is_occupied(self) -> bool {
        self.occupied
    }

    #[must_use]
    pub const fn internal_address(self) -> Ipv4Address {
        self.internal_address
    }

    #[must_use]
    pub const fn internal_port(self) -> u16 {
        self.internal_port
    }

    #[must_use]
    pub const fn public_port(self) -> u16 {
        self.public_port
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44TcpSessionSlot {
    occupied: bool,
    mapping_index: usize,
    mapping_generation: u64,
    mapping_lifecycle_epoch: u128,
    remote_address: Ipv4Address,
    remote_port: u16,
    last_activity_ms: u64,
}

impl Default for Nat44TcpSessionSlot {
    fn default() -> Self {
        Self {
            occupied: false,
            mapping_index: 0,
            mapping_generation: 0,
            mapping_lifecycle_epoch: 0,
            remote_address: Ipv4Address::from_octets([0; 4]),
            remote_port: 0,
            last_activity_ms: 0,
        }
    }
}

impl Nat44TcpSessionSlot {
    #[must_use]
    pub const fn is_occupied(self) -> bool {
        self.occupied
    }

    #[must_use]
    pub const fn remote_address(self) -> Ipv4Address {
        self.remote_address
    }

    #[must_use]
    pub const fn remote_port(self) -> u16 {
        self.remote_port
    }

    #[must_use]
    pub const fn last_activity_ms(self) -> u64 {
        self.last_activity_ms
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Nat44TcpCounters {
    pub mappings_created: u64,
    pub mappings_reused: u64,
    pub mappings_expired: u64,
    pub sessions_created: u64,
    pub sessions_reused: u64,
    pub sessions_expired: u64,
    pub outbound_translated: u64,
    pub inbound_translated: u64,
    pub mapping_misses: u64,
    pub session_misses: u64,
    pub invalid_initial_flags: u64,
    pub mapping_full: u64,
    pub session_full: u64,
    pub port_exhausted: u64,
    pub clock_regressions: u64,
    pub config_mismatches: u64,
    pub reconciliations: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44TcpDisposition {
    OutboundTranslated {
        public_port: u16,
        mapping_created: bool,
        session_created: bool,
    },
    InboundTranslated {
        internal_address: Ipv4Address,
        internal_port: u16,
    },
    MappingMiss,
    SessionMiss,
    InvalidInitialFlags,
    MappingFull,
    SessionFull,
    PortExhausted,
    ClockRegression,
    ConfigMismatch,
    Rejected {
        reason: crate::DropReason,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44TcpReconcileReport {
    pub mappings_flushed: usize,
    pub sessions_flushed: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct Nat44TcpOutboundPlan {
    authority: Nat44TcpPlanAuthority,
    mapping_index: u32,
    mapping: Nat44TcpMappingSlot,
    session_index: u32,
    session: Nat44TcpSessionSlot,
    mapping_created: bool,
    mapping_expired: bool,
    session_created: bool,
    session_expired: bool,
    displaced_port_mapping_index: u32,
    prepared: PreparedNat44TcpOutboundCommit,
}

impl Nat44TcpOutboundPlan {
    const fn mapping_index(self) -> usize {
        self.mapping_index as usize
    }

    const fn session_index(self) -> usize {
        self.session_index as usize
    }

    fn displaced_port_mapping_index(self) -> Option<usize> {
        (self.displaced_port_mapping_index != TCP_INDEX_NONE)
            .then_some(self.displaced_port_mapping_index as usize)
    }

    pub(crate) const fn public_port(self) -> u16 {
        self.mapping.public_port
    }

    pub(crate) const fn disposition(self) -> Nat44TcpDisposition {
        Nat44TcpDisposition::OutboundTranslated {
            public_port: self.mapping.public_port,
            mapping_created: self.mapping_created,
            session_created: self.session_created,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Nat44TcpInboundPlan {
    authority: Nat44TcpPlanAuthority,
    mapping_index: usize,
    mapping: Nat44TcpMappingSlot,
    session_index: usize,
    session: Nat44TcpSessionSlot,
}

#[derive(Clone, Copy)]
struct Nat44TcpPlanAuthority {
    runtime_epoch: u128,
    state_revision: u128,
    watermark_ms: Option<u64>,
    planned_now_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Nat44TcpCommitError {
    StalePlan,
}

impl Nat44TcpInboundPlan {
    pub(crate) const fn internal_address(self) -> Ipv4Address {
        self.mapping.internal_address
    }

    pub(crate) const fn internal_port(self) -> u16 {
        self.mapping.internal_port
    }

    pub(crate) const fn disposition(self) -> Nat44TcpDisposition {
        Nat44TcpDisposition::InboundTranslated {
            internal_address: self.mapping.internal_address,
            internal_port: self.mapping.internal_port,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Nat44TcpPlanError {
    MappingMiss,
    SessionMiss,
    InvalidInitialFlags,
    MappingFull,
    SessionFull,
    PortExhausted,
    ClockRegression,
    IndexCorrupt,
    GenerationExhausted,
    StateRevisionExhausted,
}

#[derive(Clone, Copy)]
enum PreparedTcpDirectoryMutation {
    Link(PreparedDirectoryLink),
    Relink(PreparedDirectoryRelink),
}

#[derive(Clone, Copy)]
struct PreparedNat44TcpOutboundCommit {
    mapping: Option<PreparedTcpDirectoryMutation>,
    session: Option<PreparedTcpDirectoryMutation>,
    owner: Option<PreparedPortOwnerMoveTopology>,
}

impl PreparedNat44TcpOutboundCommit {
    const EMPTY: Self = Self {
        mapping: None,
        session: None,
        owner: None,
    };
}

#[derive(Clone, Copy)]
struct Nat44TcpPortSelection {
    port: u16,
    expected_owner: Option<PortOwnerToken>,
    displaced_mapping_index: Option<usize>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Nat44TcpIndexInvariantError {
    Mapping(DirectorySemanticError),
    Session(DirectorySemanticError),
    Port(PortOwnerSemanticError),
    DuplicateMappingKey,
    DuplicateSessionKey,
    MappingWithoutCurrentSession,
    MappingSummaryMismatch,
}

#[derive(Clone, Copy)]
pub(crate) struct Nat44TcpIcmpv4Lookup {
    internal_address: Ipv4Address,
    internal_port: u16,
}

impl Nat44TcpIcmpv4Lookup {
    pub(crate) const fn internal_address(self) -> Ipv4Address {
        self.internal_address
    }

    pub(crate) const fn internal_port(self) -> u16 {
        self.internal_port
    }
}

/// Caller-owned storage for TCP NAT mapping, session, and port-owner indexes.
pub struct Nat44TcpIndexStorage<'a> {
    mapping_buckets: &'a mut [DirectoryBucket],
    mapping_nodes: &'a mut [DirectoryNode],
    session_buckets: &'a mut [DirectoryBucket],
    session_nodes: &'a mut [DirectoryNode],
    port_owners: &'a mut [PortOwnerSlot],
}

impl<'a> Nat44TcpIndexStorage<'a> {
    pub fn new(
        mapping_buckets: &'a mut [DirectoryBucket],
        mapping_nodes: &'a mut [DirectoryNode],
        session_buckets: &'a mut [DirectoryBucket],
        session_nodes: &'a mut [DirectoryNode],
        port_owners: &'a mut [PortOwnerSlot],
    ) -> Self {
        Self {
            mapping_buckets,
            mapping_nodes,
            session_buckets,
            session_nodes,
            port_owners,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44TcpRuntimeConfigError {
    MappingNodeCountMismatch,
    SessionNodeCountMismatch,
    MappingDirectoryInvalid,
    SessionDirectoryInvalid,
    PortOwnerTableInvalid,
    RuntimeIdentityExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44TcpReconcileError {
    HashKeyNotRotated,
    PortOwnerTableInvalid,
    RuntimeEpochExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44TcpStorageShape {
    mapping_slots: u32,
    session_slots: u32,
    mapping_buckets: u32,
    mapping_nodes: u32,
    session_buckets: u32,
    session_nodes: u32,
    port_owner_slots: u32,
}

impl Nat44TcpStorageShape {
    pub const fn mapping_slots(self) -> u32 {
        self.mapping_slots
    }
    pub const fn session_slots(self) -> u32 {
        self.session_slots
    }
    pub const fn mapping_buckets(self) -> u32 {
        self.mapping_buckets
    }
    pub const fn mapping_nodes(self) -> u32 {
        self.mapping_nodes
    }
    pub const fn session_buckets(self) -> u32 {
        self.session_buckets
    }
    pub const fn session_nodes(self) -> u32 {
        self.session_nodes
    }
    pub const fn port_owner_slots(self) -> u32 {
        self.port_owner_slots
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Nat44TcpRuntimeBinding {
    runtime_identity: u64,
    mappings: Nat44UdpBackingIdentity,
    sessions: Nat44UdpBackingIdentity,
    mapping_buckets: Nat44UdpBackingIdentity,
    mapping_nodes: Nat44UdpBackingIdentity,
    session_buckets: Nat44UdpBackingIdentity,
    session_nodes: Nat44UdpBackingIdentity,
    port_owners: Nat44UdpBackingIdentity,
}

impl Nat44TcpRuntimeBinding {
    fn new(
        runtime_identity: u64,
        mappings: &[Nat44TcpMappingSlot],
        sessions: &[Nat44TcpSessionSlot],
        indexes: &Nat44TcpIndexStorage<'_>,
    ) -> Self {
        Self {
            runtime_identity,
            mappings: Nat44UdpBackingIdentity::of(mappings),
            sessions: Nat44UdpBackingIdentity::of(sessions),
            mapping_buckets: Nat44UdpBackingIdentity::of(indexes.mapping_buckets),
            mapping_nodes: Nat44UdpBackingIdentity::of(indexes.mapping_nodes),
            session_buckets: Nat44UdpBackingIdentity::of(indexes.session_buckets),
            session_nodes: Nat44UdpBackingIdentity::of(indexes.session_nodes),
            port_owners: Nat44UdpBackingIdentity::of(indexes.port_owners),
        }
    }
}

/// Lifetime-bound proof that a TCP NAT reconcile can commit without failure.
///
/// The permit exclusively borrows the exact runtime that produced it. It is
/// intentionally opaque, non-cloneable, non-copyable, and non-debuggable.
/// Dropping it releases the borrow without changing the runtime.
///
/// ```compile_fail
/// use ruster_core::Nat44TcpReconcilePermit;
/// fn assert_clone<T: Clone>() {}
/// assert_clone::<Nat44TcpReconcilePermit<'static, 'static>>();
/// ```
///
/// ```compile_fail
/// use ruster_core::Nat44TcpReconcilePermit;
/// fn assert_copy<T: Copy>() {}
/// assert_copy::<Nat44TcpReconcilePermit<'static, 'static>>();
/// ```
///
/// ```compile_fail
/// use ruster_core::Nat44TcpReconcilePermit;
/// fn assert_debug<T: std::fmt::Debug>() {}
/// assert_debug::<Nat44TcpReconcilePermit<'static, 'static>>();
/// ```
///
/// ```compile_fail
/// use ruster_core::{
///     Nat44TcpConfig, Nat44TcpHashKey, Nat44TcpReconcileError, Nat44TcpRuntime,
/// };
///
/// fn runtime_stays_exclusively_borrowed<'storage>(
///     runtime: &mut Nat44TcpRuntime<'storage>,
///     config: Nat44TcpConfig,
///     key: Nat44TcpHashKey,
/// ) -> Result<(), Nat44TcpReconcileError> {
///     let permit = runtime.preflight_reconcile(config, key)?;
///     let _ = runtime.config();
///     permit.commit();
///     Ok(())
/// }
/// ```
///
/// ```compile_fail
/// use ruster_core::{
///     Nat44TcpConfig, Nat44TcpHashKey, Nat44TcpReconcileError, Nat44TcpRuntime,
/// };
///
/// fn permit_cannot_be_applied_to_another_runtime<'storage>(
///     first: &mut Nat44TcpRuntime<'storage>,
///     second: &mut Nat44TcpRuntime<'storage>,
///     config: Nat44TcpConfig,
///     key: Nat44TcpHashKey,
/// ) -> Result<(), Nat44TcpReconcileError> {
///     let permit = first.preflight_reconcile(config, key)?;
///     second.commit_reconcile(permit);
///     Ok(())
/// }
/// ```
#[must_use = "dropping a TCP NAT reconcile permit leaves the runtime unchanged"]
pub struct Nat44TcpReconcilePermit<'runtime, 'storage> {
    runtime: &'runtime mut Nat44TcpRuntime<'storage>,
    config: Nat44TcpConfig,
    hash_key: Nat44TcpHashKey,
    next_runtime_epoch: u128,
}

impl Nat44TcpReconcilePermit<'_, '_> {
    pub fn commit(self) -> Nat44TcpReconcileReport {
        self.runtime.commit_prevalidated_reconcile(
            self.config,
            self.hash_key,
            self.next_runtime_epoch,
        )
    }
}

/// Fixed-capacity, worker-local outbound-initiated TCP NAPT state.
///
/// This intentionally models exact remote endpoint sessions, not TCP sequence
/// or window state. FIN and RST are translated like any other packet and do
/// not shorten the conservative idle lifetime.
///
/// ```compile_fail
/// use ruster_core::Nat44TcpRuntime;
/// fn assert_send<T: Send>() {}
/// assert_send::<Nat44TcpRuntime<'static>>();
/// ```
///
/// ```compile_fail
/// use ruster_core::Nat44TcpRuntime;
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<Nat44TcpRuntime<'static>>();
/// ```
pub struct Nat44TcpRuntime<'a> {
    config: Nat44TcpConfig,
    mappings: &'a mut [Nat44TcpMappingSlot],
    sessions: &'a mut [Nat44TcpSessionSlot],
    mapping_directory: FixedDirectory<'a>,
    session_directory: FixedDirectory<'a>,
    port_owners: PortOwnerTable<'a>,
    hash_key: Nat44TcpHashKey,
    watermark_ms: Option<u64>,
    runtime_epoch: u128,
    next_generation: u64,
    state_revision: u128,
    #[allow(dead_code)]
    runtime_binding: Nat44TcpRuntimeBinding,
    counters: Nat44TcpCounters,
    #[cfg(test)]
    mapping_liveness_checks: Cell<usize>,
    #[cfg(test)]
    session_liveness_checks: Cell<usize>,
    #[cfg(test)]
    mapping_lookup_probes: Cell<usize>,
    #[cfg(test)]
    session_lookup_probes: Cell<usize>,
    #[cfg(test)]
    reusable_mapping_checks: Cell<usize>,
    #[cfg(test)]
    reusable_session_checks: Cell<usize>,
    #[cfg(test)]
    port_owner_probes: Cell<usize>,
    _worker_local: PhantomData<Rc<()>>,
}

impl<'a> Nat44TcpRuntime<'a> {
    pub fn new(
        config: Nat44TcpConfig,
        mappings: &'a mut [Nat44TcpMappingSlot],
        sessions: &'a mut [Nat44TcpSessionSlot],
        indexes: Nat44TcpIndexStorage<'a>,
        hash_key: Nat44TcpHashKey,
    ) -> Result<Self, Nat44TcpRuntimeConfigError> {
        if indexes.mapping_nodes.len() != mappings.len() {
            return Err(Nat44TcpRuntimeConfigError::MappingNodeCountMismatch);
        }
        if indexes.session_nodes.len() != sessions.len() {
            return Err(Nat44TcpRuntimeConfigError::SessionNodeCountMismatch);
        }
        FixedDirectory::validate_config(indexes.mapping_buckets.len(), indexes.mapping_nodes.len())
            .map_err(|_| Nat44TcpRuntimeConfigError::MappingDirectoryInvalid)?;
        FixedDirectory::validate_config(indexes.session_buckets.len(), indexes.session_nodes.len())
            .map_err(|_| Nat44TcpRuntimeConfigError::SessionDirectoryInvalid)?;
        PortOwnerTable::validate_config(
            indexes.port_owners.len(),
            config.first_port,
            config.last_port,
            mappings.len(),
        )
        .map_err(|_| Nat44TcpRuntimeConfigError::PortOwnerTableInvalid)?;
        let runtime_identity = allocate_tcp_runtime_identity()?;
        let runtime_binding =
            Nat44TcpRuntimeBinding::new(runtime_identity, mappings, sessions, &indexes);
        let mapping_directory =
            FixedDirectory::new(indexes.mapping_buckets, indexes.mapping_nodes, hash_key.0)
                .expect("mapping directory dimensions were preflighted");
        let session_directory =
            FixedDirectory::new(indexes.session_buckets, indexes.session_nodes, hash_key.0)
                .expect("session directory dimensions were preflighted");
        let port_owners = PortOwnerTable::new(
            indexes.port_owners,
            config.first_port,
            config.last_port,
            mappings.len(),
        )
        .expect("port owner dimensions were preflighted");
        mappings.fill(Nat44TcpMappingSlot::default());
        sessions.fill(Nat44TcpSessionSlot::default());
        Ok(Self {
            config,
            mappings,
            sessions,
            mapping_directory,
            session_directory,
            port_owners,
            hash_key,
            watermark_ms: None,
            runtime_epoch: 1,
            next_generation: 1,
            state_revision: 0,
            runtime_binding,
            counters: Nat44TcpCounters::default(),
            #[cfg(test)]
            mapping_liveness_checks: Cell::new(0),
            #[cfg(test)]
            session_liveness_checks: Cell::new(0),
            #[cfg(test)]
            mapping_lookup_probes: Cell::new(0),
            #[cfg(test)]
            session_lookup_probes: Cell::new(0),
            #[cfg(test)]
            reusable_mapping_checks: Cell::new(0),
            #[cfg(test)]
            reusable_session_checks: Cell::new(0),
            #[cfg(test)]
            port_owner_probes: Cell::new(0),
            _worker_local: PhantomData,
        })
    }

    #[must_use]
    pub const fn config(&self) -> Nat44TcpConfig {
        self.config
    }

    #[must_use]
    pub const fn counters(&self) -> Nat44TcpCounters {
        self.counters
    }

    #[must_use]
    pub fn mappings(&self) -> &[Nat44TcpMappingSlot] {
        self.mappings
    }

    #[must_use]
    pub fn sessions(&self) -> &[Nat44TcpSessionSlot] {
        self.sessions
    }

    pub fn storage_shape(&self) -> Nat44TcpStorageShape {
        Nat44TcpStorageShape {
            mapping_slots: u32::try_from(self.mappings.len()).expect("validated capacity"),
            session_slots: u32::try_from(self.sessions.len()).expect("validated capacity"),
            mapping_buckets: u32::try_from(self.mapping_directory.bucket_count())
                .expect("validated capacity"),
            mapping_nodes: u32::try_from(self.mapping_directory.node_capacity())
                .expect("validated capacity"),
            session_buckets: u32::try_from(self.session_directory.bucket_count())
                .expect("validated capacity"),
            session_nodes: u32::try_from(self.session_directory.node_capacity())
                .expect("validated capacity"),
            port_owner_slots: u32::try_from(self.port_owners.slot_count())
                .expect("validated capacity"),
        }
    }

    pub fn publication_binding_matches(
        &self,
        config: Nat44TcpConfig,
        hash_key: Nat44TcpHashKey,
    ) -> bool {
        self.config == config && self.hash_key == hash_key
    }

    pub fn reconcile(
        &mut self,
        config: Nat44TcpConfig,
        hash_key: Nat44TcpHashKey,
    ) -> Result<Nat44TcpReconcileReport, Nat44TcpReconcileError> {
        self.preflight_reconcile(config, hash_key)
            .map(Nat44TcpReconcilePermit::commit)
    }

    pub fn preflight_reconcile<'runtime>(
        &'runtime mut self,
        config: Nat44TcpConfig,
        hash_key: Nat44TcpHashKey,
    ) -> Result<Nat44TcpReconcilePermit<'runtime, 'a>, Nat44TcpReconcileError> {
        if hash_key == self.hash_key {
            return Err(Nat44TcpReconcileError::HashKeyNotRotated);
        }
        let next_runtime_epoch = self
            .runtime_epoch
            .checked_add(1)
            .ok_or(Nat44TcpReconcileError::RuntimeEpochExhausted)?;
        if PortOwnerTable::validate_config(
            self.port_owners.slot_count(),
            config.first_port,
            config.last_port,
            self.mappings.len(),
        )
        .is_err()
        {
            return Err(Nat44TcpReconcileError::PortOwnerTableInvalid);
        }
        Ok(Nat44TcpReconcilePermit {
            runtime: self,
            config,
            hash_key,
            next_runtime_epoch,
        })
    }

    fn commit_prevalidated_reconcile(
        &mut self,
        config: Nat44TcpConfig,
        hash_key: Nat44TcpHashKey,
        next_runtime_epoch: u128,
    ) -> Nat44TcpReconcileReport {
        let mappings_flushed = self.mappings.iter().filter(|slot| slot.occupied).count();
        let sessions_flushed = self.sessions.iter().filter(|slot| slot.occupied).count();
        self.mappings.fill(Nat44TcpMappingSlot::default());
        self.sessions.fill(Nat44TcpSessionSlot::default());
        self.mapping_directory.clear_with_key(hash_key.0);
        self.session_directory.clear_with_key(hash_key.0);
        self.port_owners.reconfigure_prevalidated_and_clear(
            config.first_port,
            config.last_port,
            self.mappings.len(),
        );
        self.config = config;
        self.hash_key = hash_key;
        self.watermark_ms = None;
        self.runtime_epoch = next_runtime_epoch;
        self.next_generation = 1;
        self.state_revision = 0;
        self.counters.reconciliations = self.counters.reconciliations.saturating_add(1);
        Nat44TcpReconcileReport {
            mappings_flushed,
            sessions_flushed,
        }
    }

    pub(crate) fn record_config_mismatch(&mut self) {
        self.counters.config_mismatches = self.counters.config_mismatches.saturating_add(1);
    }

    #[cfg(test)]
    pub(crate) fn exhaust_state_revision_at_for_test(&mut self, now_ms: u64) {
        self.state_revision = u128::MAX;
        self.watermark_ms = Some(now_ms);
    }

    pub(crate) fn observe_now(&mut self, now_ms: u64) -> Result<(), Nat44TcpPlanError> {
        if self
            .watermark_ms
            .is_some_and(|watermark| now_ms < watermark)
        {
            self.counters.clock_regressions = self.counters.clock_regressions.saturating_add(1);
            return Err(Nat44TcpPlanError::ClockRegression);
        }
        if self.watermark_ms != Some(now_ms) {
            self.state_revision = self
                .state_revision
                .checked_add(1)
                .ok_or(Nat44TcpPlanError::StateRevisionExhausted)?;
            self.watermark_ms = Some(now_ms);
        }
        Ok(())
    }

    pub(crate) fn plan_outbound(
        &mut self,
        internal_address: Ipv4Address,
        internal_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        initial_syn: bool,
        now_ms: u64,
    ) -> Result<Nat44TcpOutboundPlan, Nat44TcpPlanError> {
        if self.state_revision == u128::MAX {
            return Err(Nat44TcpPlanError::StateRevisionExhausted);
        }
        self.observe_now(now_ms)?;
        self.plan_outbound_after_clock(
            internal_address,
            internal_port,
            remote_address,
            remote_port,
            initial_syn,
            now_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn plan_outbound_read_only(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        initial_syn: bool,
        now_ms: u64,
    ) -> Result<Nat44TcpOutboundPlan, Nat44TcpPlanError> {
        self.check_now_read_only(now_ms)?;
        self.plan_outbound_after_clock(
            internal_address,
            internal_port,
            remote_address,
            remote_port,
            initial_syn,
            now_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn plan_outbound_after_clock(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        initial_syn: bool,
        now_ms: u64,
    ) -> Result<Nat44TcpOutboundPlan, Nat44TcpPlanError> {
        if self.state_revision == u128::MAX {
            return Err(Nat44TcpPlanError::StateRevisionExhausted);
        }
        let exact_mapping = self.find_mapping(internal_address, internal_port)?;
        if let Some((mapping_index, mut mapping)) =
            exact_mapping.filter(|(_, mapping)| self.mapping_is_live(*mapping, now_ms))
        {
            let mapping_before = mapping;
            let exact_session = self.find_session(
                mapping_index,
                mapping.generation,
                mapping.lifecycle_epoch,
                remote_address,
                remote_port,
            )?;
            if let Some((session_index, mut session)) =
                exact_session.filter(|(_, session)| self.session_is_live(*session, now_ms))
            {
                let session_before = session;
                mapping.last_activity_ms = now_ms;
                session.last_activity_ms = now_ms;
                return self.prepare_outbound_plan(
                    Nat44TcpOutboundPlan {
                        authority: self.plan_authority(now_ms, mapping_before, session_before),
                        mapping_index: encode_udp_index(mapping_index),
                        mapping,
                        session_index: encode_udp_index(session_index),
                        session,
                        mapping_created: false,
                        mapping_expired: false,
                        session_created: false,
                        session_expired: false,
                        displaced_port_mapping_index: TCP_INDEX_NONE,
                        prepared: PreparedNat44TcpOutboundCommit::EMPTY,
                    },
                    None,
                );
            }
            if !initial_syn {
                return Err(Nat44TcpPlanError::InvalidInitialFlags);
            }
            let session_index = if let Some((session_index, _)) = exact_session {
                session_index
            } else if let Some(session_index) = self.find_reusable_session(now_ms) {
                session_index
            } else {
                return Err(Nat44TcpPlanError::SessionFull);
            };
            let session_before = self.sessions[session_index];
            let session_expired = session_before.occupied;
            mapping.last_activity_ms = now_ms;
            return self.prepare_outbound_plan(
                Nat44TcpOutboundPlan {
                    authority: self.plan_authority(now_ms, mapping_before, session_before),
                    mapping_index: encode_udp_index(mapping_index),
                    mapping,
                    session_index: encode_udp_index(session_index),
                    session: Nat44TcpSessionSlot {
                        occupied: true,
                        mapping_index,
                        mapping_generation: mapping.generation,
                        mapping_lifecycle_epoch: mapping.lifecycle_epoch,
                        remote_address,
                        remote_port,
                        last_activity_ms: now_ms,
                    },
                    mapping_created: false,
                    mapping_expired: false,
                    session_created: true,
                    session_expired,
                    displaced_port_mapping_index: TCP_INDEX_NONE,
                    prepared: PreparedNat44TcpOutboundCommit::EMPTY,
                },
                None,
            );
        }
        if !initial_syn {
            return Err(Nat44TcpPlanError::InvalidInitialFlags);
        }
        let mapping_index = if let Some((mapping_index, _)) = exact_mapping {
            mapping_index
        } else if let Some(mapping_index) = self.find_reusable_mapping(now_ms) {
            mapping_index
        } else {
            return Err(Nat44TcpPlanError::MappingFull);
        };
        let Some(session_index) = self.find_reusable_session(now_ms) else {
            return Err(Nat44TcpPlanError::SessionFull);
        };
        let Some(port) = self.allocate_port(internal_address, internal_port, now_ms)? else {
            return Err(Nat44TcpPlanError::PortExhausted);
        };
        if self.next_generation == 0 || self.next_generation == u64::MAX {
            return Err(Nat44TcpPlanError::GenerationExhausted);
        }
        let generation = self.next_generation;
        let mapping_before = self.mappings[mapping_index];
        let session_before = self.sessions[session_index];
        let mapping_expired = mapping_before.occupied;
        let session_expired = session_before.occupied;
        self.prepare_outbound_plan(
            Nat44TcpOutboundPlan {
                authority: self.plan_authority(now_ms, mapping_before, session_before),
                mapping_index: encode_udp_index(mapping_index),
                mapping: Nat44TcpMappingSlot {
                    occupied: true,
                    generation,
                    lifecycle_epoch: self.runtime_epoch,
                    port_owned: true,
                    inside: self.config.inside,
                    internal_address,
                    internal_port,
                    public_port: port.port,
                    last_activity_ms: now_ms,
                },
                session_index: encode_udp_index(session_index),
                session: Nat44TcpSessionSlot {
                    occupied: true,
                    mapping_index,
                    mapping_generation: generation,
                    mapping_lifecycle_epoch: self.runtime_epoch,
                    remote_address,
                    remote_port,
                    last_activity_ms: now_ms,
                },
                mapping_created: true,
                mapping_expired,
                session_created: true,
                session_expired,
                displaced_port_mapping_index: encode_optional_udp_index(
                    port.displaced_mapping_index,
                ),
                prepared: PreparedNat44TcpOutboundCommit::EMPTY,
            },
            port.expected_owner,
        )
    }

    pub(crate) fn plan_inbound(
        &mut self,
        public_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        now_ms: u64,
    ) -> Result<Nat44TcpInboundPlan, Nat44TcpPlanError> {
        self.observe_now(now_ms)?;
        self.plan_inbound_after_clock(public_port, remote_address, remote_port, now_ms)
    }

    pub(crate) fn plan_inbound_read_only(
        &self,
        public_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        now_ms: u64,
    ) -> Result<Nat44TcpInboundPlan, Nat44TcpPlanError> {
        self.check_now_read_only(now_ms)?;
        self.plan_inbound_after_clock(public_port, remote_address, remote_port, now_ms)
    }

    fn plan_inbound_after_clock(
        &self,
        public_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        now_ms: u64,
    ) -> Result<Nat44TcpInboundPlan, Nat44TcpPlanError> {
        if self.state_revision == u128::MAX {
            return Err(Nat44TcpPlanError::StateRevisionExhausted);
        }
        let Some((mapping_index, mut mapping)) =
            self.mapping_for_public_port(public_port, now_ms)?
        else {
            return Err(Nat44TcpPlanError::MappingMiss);
        };
        let mapping_before = mapping;
        let Some((session_index, mut session)) = self.find_session(
            mapping_index,
            mapping.generation,
            mapping.lifecycle_epoch,
            remote_address,
            remote_port,
        )?
        else {
            return Err(Nat44TcpPlanError::SessionMiss);
        };
        if !self.session_is_live(session, now_ms) {
            return Err(Nat44TcpPlanError::SessionMiss);
        }
        let session_before = session;
        mapping.last_activity_ms = now_ms;
        session.last_activity_ms = now_ms;
        Ok(Nat44TcpInboundPlan {
            authority: self.plan_authority(now_ms, mapping_before, session_before),
            mapping_index,
            mapping,
            session_index,
            session,
        })
    }

    #[allow(dead_code)] // Typed stale-plan API retained for core callers and tests.
    pub(crate) fn commit_outbound(
        &mut self,
        plan: Nat44TcpOutboundPlan,
        now_ms: u64,
    ) -> Result<(), Nat44TcpCommitError> {
        self.prevalidate_outbound_commit(plan, now_ms)?;
        self.commit_prevalidated_outbound(plan, now_ms);
        Ok(())
    }

    pub(crate) fn prevalidate_outbound_commit(
        &self,
        plan: Nat44TcpOutboundPlan,
        now_ms: u64,
    ) -> Result<(), Nat44TcpCommitError> {
        self.validate_commit_authority(
            plan.authority,
            plan.mapping_index(),
            plan.session_index(),
            now_ms,
        )?;
        if !plan
            .prepared
            .mapping
            .is_none_or(|mutation| self.mapping_mutation_matches(mutation))
            || !plan
                .prepared
                .session
                .is_none_or(|mutation| self.session_mutation_matches(mutation))
        {
            return Err(Nat44TcpCommitError::StalePlan);
        }
        Ok(())
    }

    pub(crate) fn commit_prevalidated_outbound(&mut self, plan: Nat44TcpOutboundPlan, now_ms: u64) {
        if let Some(mutation) = plan.prepared.mapping {
            self.apply_mapping_mutation(mutation);
        }
        if let Some(mutation) = plan.prepared.session {
            self.apply_session_mutation(mutation);
        }
        if let Some(owner) = plan.prepared.owner {
            let replacement = PortOwnerToken::from_prevalidated_index(
                plan.mapping_index,
                plan.mapping.generation,
                plan.mapping.lifecycle_epoch,
            );
            self.port_owners
                .apply_prepared_move_topology(owner, replacement);
        }
        if let Some(displaced) = plan
            .displaced_port_mapping_index()
            .filter(|index| *index != plan.mapping_index())
        {
            self.mappings[displaced].port_owned = false;
        }
        self.mappings[plan.mapping_index()] = plan.mapping;
        self.sessions[plan.session_index()] = plan.session;
        self.watermark_ms = Some(now_ms);
        self.state_revision = plan.authority.state_revision + 1;
        if plan.mapping_created {
            self.counters.mappings_created = self.counters.mappings_created.saturating_add(1);
            if plan.mapping_expired {
                self.counters.mappings_expired = self.counters.mappings_expired.saturating_add(1);
            }
            self.next_generation = plan.mapping.generation + 1;
        } else {
            self.counters.mappings_reused = self.counters.mappings_reused.saturating_add(1);
        }
        if plan.session_created {
            self.counters.sessions_created = self.counters.sessions_created.saturating_add(1);
            if plan.session_expired {
                self.counters.sessions_expired = self.counters.sessions_expired.saturating_add(1);
            }
        } else {
            self.counters.sessions_reused = self.counters.sessions_reused.saturating_add(1);
        }
        self.counters.outbound_translated = self.counters.outbound_translated.saturating_add(1);
    }

    #[allow(dead_code)] // Typed stale-plan API retained for core callers and tests.
    pub(crate) fn commit_inbound(
        &mut self,
        plan: Nat44TcpInboundPlan,
        now_ms: u64,
    ) -> Result<(), Nat44TcpCommitError> {
        self.prevalidate_inbound_commit(plan, now_ms)?;
        self.commit_prevalidated_inbound(plan, now_ms);
        Ok(())
    }

    pub(crate) fn prevalidate_inbound_commit(
        &self,
        plan: Nat44TcpInboundPlan,
        now_ms: u64,
    ) -> Result<(), Nat44TcpCommitError> {
        self.validate_commit_authority(
            plan.authority,
            plan.mapping_index,
            plan.session_index,
            now_ms,
        )
    }

    pub(crate) fn commit_prevalidated_inbound(&mut self, plan: Nat44TcpInboundPlan, now_ms: u64) {
        self.mappings[plan.mapping_index] = plan.mapping;
        self.sessions[plan.session_index] = plan.session;
        self.watermark_ms = Some(now_ms);
        self.state_revision = plan.authority.state_revision + 1;
        self.counters.sessions_reused = self.counters.sessions_reused.saturating_add(1);
        self.counters.inbound_translated = self.counters.inbound_translated.saturating_add(1);
    }

    fn plan_authority(
        &self,
        planned_now_ms: u64,
        _mapping_before: Nat44TcpMappingSlot,
        _session_before: Nat44TcpSessionSlot,
    ) -> Nat44TcpPlanAuthority {
        Nat44TcpPlanAuthority {
            runtime_epoch: self.runtime_epoch,
            state_revision: self.state_revision,
            watermark_ms: self.watermark_ms,
            planned_now_ms,
        }
    }

    fn validate_commit_authority(
        &self,
        authority: Nat44TcpPlanAuthority,
        mapping_index: usize,
        session_index: usize,
        now_ms: u64,
    ) -> Result<(), Nat44TcpCommitError> {
        if authority.runtime_epoch != self.runtime_epoch
            || authority.state_revision != self.state_revision
            || authority.watermark_ms != self.watermark_ms
            || authority.planned_now_ms != now_ms
            || self.mappings.get(mapping_index).is_none()
            || self.sessions.get(session_index).is_none()
        {
            return Err(Nat44TcpCommitError::StalePlan);
        }
        Ok(())
    }

    pub(crate) fn record_plan_error(&mut self, error: Nat44TcpPlanError) {
        match error {
            Nat44TcpPlanError::MappingMiss => {
                self.counters.mapping_misses = self.counters.mapping_misses.saturating_add(1);
            }
            Nat44TcpPlanError::SessionMiss => {
                self.counters.session_misses = self.counters.session_misses.saturating_add(1);
            }
            Nat44TcpPlanError::InvalidInitialFlags => {
                self.counters.invalid_initial_flags =
                    self.counters.invalid_initial_flags.saturating_add(1);
            }
            Nat44TcpPlanError::MappingFull => {
                self.counters.mapping_full = self.counters.mapping_full.saturating_add(1);
            }
            Nat44TcpPlanError::SessionFull => {
                self.counters.session_full = self.counters.session_full.saturating_add(1);
            }
            Nat44TcpPlanError::PortExhausted => {
                self.counters.port_exhausted = self.counters.port_exhausted.saturating_add(1);
            }
            Nat44TcpPlanError::ClockRegression => {}
            Nat44TcpPlanError::IndexCorrupt
            | Nat44TcpPlanError::GenerationExhausted
            | Nat44TcpPlanError::StateRevisionExhausted => {
                self.counters.config_mismatches = self.counters.config_mismatches.saturating_add(1);
            }
        }
    }

    pub(crate) fn record_read_only_plan_error(&mut self, error: Nat44TcpPlanError) {
        self.record_plan_error(error);
        if error == Nat44TcpPlanError::ClockRegression {
            self.counters.clock_regressions = self.counters.clock_regressions.saturating_add(1);
        }
    }

    pub(crate) fn inspect_icmpv4(
        &self,
        public_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        now_ms: u64,
    ) -> Result<Nat44TcpIcmpv4Lookup, Nat44TcpPlanError> {
        if self
            .watermark_ms
            .is_some_and(|watermark| now_ms < watermark)
        {
            return Err(Nat44TcpPlanError::ClockRegression);
        }
        let Some((mapping_index, mapping)) = self.mapping_for_public_port(public_port, now_ms)?
        else {
            return Err(Nat44TcpPlanError::MappingMiss);
        };
        if self
            .find_session(
                mapping_index,
                mapping.generation,
                mapping.lifecycle_epoch,
                remote_address,
                remote_port,
            )?
            .is_none_or(|(_, session)| !self.session_is_live(session, now_ms))
        {
            return Err(Nat44TcpPlanError::SessionMiss);
        }
        Ok(Nat44TcpIcmpv4Lookup {
            internal_address: mapping.internal_address,
            internal_port: mapping.internal_port,
        })
    }

    fn session_is_live(&self, session: Nat44TcpSessionSlot, now_ms: u64) -> bool {
        #[cfg(test)]
        self.session_liveness_checks
            .set(self.session_liveness_checks.get().saturating_add(1));
        session.occupied
            && now_ms >= session.last_activity_ms
            && now_ms - session.last_activity_ms < self.config.policy.idle_ttl_ms
    }

    fn check_now_read_only(&self, now_ms: u64) -> Result<(), Nat44TcpPlanError> {
        if self
            .watermark_ms
            .is_some_and(|watermark| now_ms < watermark)
        {
            Err(Nat44TcpPlanError::ClockRegression)
        } else {
            Ok(())
        }
    }

    fn mapping_is_live(&self, mapping: Nat44TcpMappingSlot, now_ms: u64) -> bool {
        #[cfg(test)]
        self.mapping_liveness_checks
            .set(self.mapping_liveness_checks.get().saturating_add(1));
        mapping.occupied
            && now_ms >= mapping.last_activity_ms
            && now_ms - mapping.last_activity_ms < self.config.policy.idle_ttl_ms
    }

    #[cfg(test)]
    fn reset_liveness_checks(&self) {
        self.mapping_liveness_checks.set(0);
        self.session_liveness_checks.set(0);
    }

    #[cfg(test)]
    fn liveness_checks(&self) -> (usize, usize) {
        (
            self.mapping_liveness_checks.get(),
            self.session_liveness_checks.get(),
        )
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn reset_index_probe_counts(&self) {
        self.mapping_lookup_probes.set(0);
        self.session_lookup_probes.set(0);
        self.reusable_mapping_checks.set(0);
        self.reusable_session_checks.set(0);
        self.port_owner_probes.set(0);
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn index_probe_counts(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.mapping_lookup_probes.get(),
            self.session_lookup_probes.get(),
            self.reusable_mapping_checks.get(),
            self.reusable_session_checks.get(),
            self.port_owner_probes.get(),
        )
    }

    fn find_mapping(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
    ) -> Result<Option<(usize, Nat44TcpMappingSlot)>, Nat44TcpPlanError> {
        let words = Self::mapping_lookup_words(self.config.inside, internal_address, internal_port);
        let probe = self
            .mapping_directory
            .lookup(DirectoryHashDomain::TcpMapping, &words, |index| {
                let mapping = self.mappings[index];
                mapping.occupied
                    && mapping.inside == self.config.inside
                    && mapping.internal_address == internal_address
                    && mapping.internal_port == internal_port
            })
            .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?;
        #[cfg(test)]
        self.mapping_lookup_probes.set(
            self.mapping_lookup_probes
                .get()
                .saturating_add(probe.probes),
        );
        Ok(probe.state_index.map(|index| (index, self.mappings[index])))
    }

    fn find_session(
        &self,
        mapping_index: usize,
        mapping_generation: u64,
        mapping_lifecycle_epoch: u128,
        remote_address: Ipv4Address,
        remote_port: u16,
    ) -> Result<Option<(usize, Nat44TcpSessionSlot)>, Nat44TcpPlanError> {
        let words = Self::session_lookup_words(
            mapping_index,
            mapping_generation,
            mapping_lifecycle_epoch,
            remote_address,
            remote_port,
        );
        let probe = self
            .session_directory
            .lookup(DirectoryHashDomain::TcpSession, &words, |index| {
                let session = self.sessions[index];
                session.occupied
                    && session.mapping_index == mapping_index
                    && session.mapping_generation == mapping_generation
                    && session.mapping_lifecycle_epoch == mapping_lifecycle_epoch
                    && session.remote_address == remote_address
                    && session.remote_port == remote_port
            })
            .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?;
        #[cfg(test)]
        self.session_lookup_probes.set(
            self.session_lookup_probes
                .get()
                .saturating_add(probe.probes),
        );
        Ok(probe.state_index.map(|index| (index, self.sessions[index])))
    }

    fn find_reusable_mapping(&self, now_ms: u64) -> Option<usize> {
        self.mappings.iter().copied().position(|mapping| {
            #[cfg(test)]
            self.reusable_mapping_checks
                .set(self.reusable_mapping_checks.get().saturating_add(1));
            !self.mapping_is_live(mapping, now_ms)
        })
    }

    fn find_reusable_session(&self, now_ms: u64) -> Option<usize> {
        self.sessions.iter().position(|session| {
            #[cfg(test)]
            self.reusable_session_checks
                .set(self.reusable_session_checks.get().saturating_add(1));
            !self.session_is_live(*session, now_ms)
                || self
                    .mappings
                    .get(session.mapping_index)
                    .is_none_or(|mapping| {
                        !mapping.occupied
                            || mapping.generation != session.mapping_generation
                            || mapping.lifecycle_epoch != session.mapping_lifecycle_epoch
                    })
        })
    }

    fn mapping_for_public_port(
        &self,
        public_port: u16,
        now_ms: u64,
    ) -> Result<Option<(usize, Nat44TcpMappingSlot)>, Nat44TcpPlanError> {
        let owner = match self.port_owners.owner(public_port) {
            Ok(owner) => owner,
            Err(PortOwnerError::PortOutOfRange) => return Ok(None),
            Err(_) => return Err(Nat44TcpPlanError::IndexCorrupt),
        };
        let Some(owner) = owner else {
            return Ok(None);
        };
        let mapping = self
            .mappings
            .get(owner.state_index())
            .copied()
            .ok_or(Nat44TcpPlanError::IndexCorrupt)?;
        if !mapping.occupied
            || !mapping.port_owned
            || mapping.generation != owner.state_generation()
            || mapping.lifecycle_epoch != owner.runtime_epoch()
            || mapping.public_port != public_port
        {
            return Err(Nat44TcpPlanError::IndexCorrupt);
        }
        if !self.mapping_is_live(mapping, now_ms) {
            return Ok(None);
        }
        Ok(Some((owner.state_index(), mapping)))
    }

    fn select_port(
        &self,
        port: u16,
        now_ms: u64,
    ) -> Result<Option<Nat44TcpPortSelection>, Nat44TcpPlanError> {
        #[cfg(test)]
        self.port_owner_probes
            .set(self.port_owner_probes.get().saturating_add(1));
        let owner = self
            .port_owners
            .owner(port)
            .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?;
        let Some(owner) = owner else {
            return Ok(Some(Nat44TcpPortSelection {
                port,
                expected_owner: None,
                displaced_mapping_index: None,
            }));
        };
        let mapping = self
            .mappings
            .get(owner.state_index())
            .copied()
            .ok_or(Nat44TcpPlanError::IndexCorrupt)?;
        if !mapping.occupied
            || !mapping.port_owned
            || mapping.generation != owner.state_generation()
            || mapping.lifecycle_epoch != owner.runtime_epoch()
            || mapping.public_port != port
        {
            return Err(Nat44TcpPlanError::IndexCorrupt);
        }
        if self.mapping_is_live(mapping, now_ms) {
            return Ok(None);
        }
        Ok(Some(Nat44TcpPortSelection {
            port,
            expected_owner: Some(owner),
            displaced_mapping_index: Some(owner.state_index()),
        }))
    }

    const fn mapping_lookup_words(
        inside: IfId,
        internal_address: Ipv4Address,
        internal_port: u16,
    ) -> [u64; 3] {
        [
            inside.0 as u64,
            u32::from_be_bytes(internal_address.octets()) as u64,
            internal_port as u64,
        ]
    }

    const fn mapping_words(mapping: Nat44TcpMappingSlot) -> [u64; 3] {
        Self::mapping_lookup_words(
            mapping.inside,
            mapping.internal_address,
            mapping.internal_port,
        )
    }

    const fn session_lookup_words(
        mapping_index: usize,
        mapping_generation: u64,
        lifecycle_epoch: u128,
        remote_address: Ipv4Address,
        remote_port: u16,
    ) -> [u64; 6] {
        [
            mapping_index as u64,
            mapping_generation,
            (lifecycle_epoch >> 64) as u64,
            lifecycle_epoch as u64,
            u32::from_be_bytes(remote_address.octets()) as u64,
            remote_port as u64,
        ]
    }

    const fn session_words(session: Nat44TcpSessionSlot) -> [u64; 6] {
        Self::session_lookup_words(
            session.mapping_index,
            session.mapping_generation,
            session.mapping_lifecycle_epoch,
            session.remote_address,
            session.remote_port,
        )
    }

    fn mapping_owner_token(
        mapping_index: usize,
        mapping: Nat44TcpMappingSlot,
    ) -> Result<PortOwnerToken, PortOwnerError> {
        PortOwnerToken::new(mapping_index, mapping.generation, mapping.lifecycle_epoch)
    }

    fn prepare_outbound_plan(
        &self,
        mut plan: Nat44TcpOutboundPlan,
        expected_owner: Option<PortOwnerToken>,
    ) -> Result<Nat44TcpOutboundPlan, Nat44TcpPlanError> {
        let mapping = if plan.mapping_created {
            let words = Self::mapping_words(plan.mapping);
            let mapping_index = plan.mapping_index();
            let before = self.mappings[mapping_index];
            Some(if before.occupied {
                PreparedTcpDirectoryMutation::Relink(
                    self.mapping_directory
                        .prepare_relink(mapping_index, DirectoryHashDomain::TcpMapping, &words)
                        .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?,
                )
            } else {
                PreparedTcpDirectoryMutation::Link(
                    self.mapping_directory
                        .prepare_link(mapping_index, DirectoryHashDomain::TcpMapping, &words)
                        .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?,
                )
            })
        } else {
            None
        };
        let session = if plan.session_created {
            let words = Self::session_words(plan.session);
            let session_index = plan.session_index();
            let before = self.sessions[session_index];
            Some(if before.occupied {
                PreparedTcpDirectoryMutation::Relink(
                    self.session_directory
                        .prepare_relink(session_index, DirectoryHashDomain::TcpSession, &words)
                        .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?,
                )
            } else {
                PreparedTcpDirectoryMutation::Link(
                    self.session_directory
                        .prepare_link(session_index, DirectoryHashDomain::TcpSession, &words)
                        .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?,
                )
            })
        } else {
            None
        };
        let owner = if plan.mapping_created {
            let mapping_index = plan.mapping_index();
            let before = self.mappings[mapping_index];
            let old_owner = if before.occupied && before.port_owned {
                Some((
                    before.public_port,
                    Self::mapping_owner_token(mapping_index, before)
                        .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?,
                ))
            } else {
                None
            };
            let replacement = Self::mapping_owner_token(mapping_index, plan.mapping)
                .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?;
            Some(
                self.port_owners
                    .prepare_move(
                        old_owner,
                        plan.mapping.public_port,
                        expected_owner,
                        replacement,
                    )
                    .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?
                    .topology(),
            )
        } else {
            None
        };
        plan.prepared = PreparedNat44TcpOutboundCommit {
            mapping,
            session,
            owner,
        };
        Ok(plan)
    }

    fn mapping_mutation_matches(&self, mutation: PreparedTcpDirectoryMutation) -> bool {
        match mutation {
            PreparedTcpDirectoryMutation::Link(prepared) => {
                self.mapping_directory.prepared_link_matches(prepared)
            }
            PreparedTcpDirectoryMutation::Relink(prepared) => {
                self.mapping_directory.prepared_relink_matches(prepared)
            }
        }
    }

    fn session_mutation_matches(&self, mutation: PreparedTcpDirectoryMutation) -> bool {
        match mutation {
            PreparedTcpDirectoryMutation::Link(prepared) => {
                self.session_directory.prepared_link_matches(prepared)
            }
            PreparedTcpDirectoryMutation::Relink(prepared) => {
                self.session_directory.prepared_relink_matches(prepared)
            }
        }
    }

    fn apply_mapping_mutation(&mut self, mutation: PreparedTcpDirectoryMutation) {
        match mutation {
            PreparedTcpDirectoryMutation::Link(prepared) => {
                self.mapping_directory.apply_prepared_link(prepared);
            }
            PreparedTcpDirectoryMutation::Relink(prepared) => {
                self.mapping_directory.apply_prepared_relink(prepared);
            }
        }
    }

    fn apply_session_mutation(&mut self, mutation: PreparedTcpDirectoryMutation) {
        match mutation {
            PreparedTcpDirectoryMutation::Link(prepared) => {
                self.session_directory.apply_prepared_link(prepared);
            }
            PreparedTcpDirectoryMutation::Relink(prepared) => {
                self.session_directory.apply_prepared_relink(prepared);
            }
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn validate_indexes(&self) -> Result<(), Nat44TcpIndexInvariantError> {
        let key = self.hash_key.0;
        self.mapping_directory
            .validate_semantics(|index| {
                let mapping = self.mappings[index];
                mapping.occupied.then(|| {
                    key.hash_words(
                        DirectoryHashDomain::TcpMapping,
                        &Self::mapping_words(mapping),
                    )
                })
            })
            .map_err(Nat44TcpIndexInvariantError::Mapping)?;
        self.session_directory
            .validate_semantics(|index| {
                let session = self.sessions[index];
                session.occupied.then(|| {
                    key.hash_words(
                        DirectoryHashDomain::TcpSession,
                        &Self::session_words(session),
                    )
                })
            })
            .map_err(Nat44TcpIndexInvariantError::Session)?;
        self.port_owners
            .validate_semantics(|index| {
                let mapping = self.mappings[index];
                (mapping.occupied && mapping.port_owned).then_some(PortOwnerExpectation {
                    port: mapping.public_port,
                    state_generation: mapping.generation,
                    runtime_epoch: mapping.lifecycle_epoch,
                })
            })
            .map_err(Nat44TcpIndexInvariantError::Port)?;
        for (index, mapping) in self.mappings.iter().copied().enumerate() {
            if !mapping.occupied {
                continue;
            }
            if self.mappings[..index].iter().copied().any(|other| {
                other.occupied
                    && other.inside == mapping.inside
                    && other.internal_address == mapping.internal_address
                    && other.internal_port == mapping.internal_port
            }) {
                return Err(Nat44TcpIndexInvariantError::DuplicateMappingKey);
            }
            let mut maximum = None;
            for session in self.sessions.iter().copied().filter(|session| {
                session.occupied
                    && session.mapping_index == index
                    && session.mapping_generation == mapping.generation
                    && session.mapping_lifecycle_epoch == mapping.lifecycle_epoch
            }) {
                maximum = Some(maximum.map_or(session.last_activity_ms, |current: u64| {
                    current.max(session.last_activity_ms)
                }));
            }
            if self
                .watermark_ms
                .is_some_and(|now_ms| self.mapping_is_live(mapping, now_ms))
            {
                let Some(maximum) = maximum else {
                    return Err(Nat44TcpIndexInvariantError::MappingWithoutCurrentSession);
                };
                if maximum != mapping.last_activity_ms {
                    return Err(Nat44TcpIndexInvariantError::MappingSummaryMismatch);
                }
            }
        }
        for (index, session) in self.sessions.iter().copied().enumerate() {
            if !session.occupied {
                continue;
            }
            if self.sessions[..index].iter().copied().any(|other| {
                other.occupied
                    && other.mapping_index == session.mapping_index
                    && other.mapping_generation == session.mapping_generation
                    && other.mapping_lifecycle_epoch == session.mapping_lifecycle_epoch
                    && other.remote_address == session.remote_address
                    && other.remote_port == session.remote_port
            }) {
                return Err(Nat44TcpIndexInvariantError::DuplicateSessionKey);
            }
        }
        Ok(())
    }

    fn allocate_port(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
        now_ms: u64,
    ) -> Result<Option<Nat44TcpPortSelection>, Nat44TcpPlanError> {
        if (self.config.first_port..=self.config.last_port).contains(&internal_port) {
            if let Some(selection) = self.select_port(internal_port, now_ms)? {
                return Ok(Some(selection));
            }
        }
        let pool_size = u32::from(self.config.last_port) - u32::from(self.config.first_port) + 1;
        let address = u32::from_be_bytes(internal_address.octets());
        let mixed = self.config.policy.allocator_seed
            ^ u64::from(address)
            ^ u64::from(internal_port).rotate_left(17);
        let start = u32::try_from(mixed % u64::from(pool_size))
            .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?;
        for step in 0..pool_size {
            let offset = (start + step) % pool_size;
            let candidate = u16::try_from(u32::from(self.config.first_port) + offset)
                .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?;
            if candidate == internal_port {
                continue;
            }
            if let Some(selection) = self.select_port(candidate, now_ms)? {
                return Ok(Some(selection));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Interface, LocalIpv4Binding, MacAddress, Neighbor, Route};

    const INSIDE: IfId = IfId(1);
    const OUTSIDE: IfId = IfId(2);
    const INTERNAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
    const INTERNAL2: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 11]);
    const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
    const REMOTE1: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
    const REMOTE2: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 2]);

    fn rotated_udp_hash_key() -> Nat44UdpHashKey {
        Nat44UdpHashKey::new(0xa5a5_5a5a_0123_4567, 0x1357_9bdf_2468_ace0).unwrap()
    }

    fn with_config<R>(policy: Nat44UdpPolicy, run: impl FnOnce(Nat44UdpConfig) -> R) -> R {
        with_port_config(policy, 40_000, 40_001, run)
    }

    fn with_port_config<R>(
        policy: Nat44UdpPolicy,
        first_port: u16,
        last_port: u16,
        run: impl FnOnce(Nat44UdpConfig) -> R,
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
            },
            Interface {
                id: OUTSIDE,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
            },
        ];
        let neighbors = [Neighbor {
            interface: OUTSIDE,
            target: Ipv4Address::from_octets([203, 0, 113, 1]),
            mac: MacAddress([2, 0, 0, 0, 0, 3]),
        }];
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
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let config = Nat44UdpConfig::new(
            &snapshot, INSIDE, OUTSIDE, PUBLIC, first_port, last_port, policy,
        )
        .unwrap();
        run(config)
    }

    #[test]
    fn eim_adf_expiry_and_generation_invalidate_stale_peers() {
        let policy = Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS, 11).unwrap();
        with_config(policy, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 2];
            let mut runtime_indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = runtime_indexes.runtime(config, &mut mappings, &mut peers);
            assert!(runtime.publication_binding_matches(config, test_udp_hash_key()));
            assert!(!runtime.publication_binding_matches(config, rotated_udp_hash_key()));
            let first = runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 0).unwrap();
            assert_eq!(first.public_port(), 40_000);
            runtime.commit_outbound(first, 0).unwrap();
            let second = runtime.plan_outbound(INTERNAL, 40_000, REMOTE2, 1).unwrap();
            assert_eq!(second.public_port(), 40_000);
            runtime.commit_outbound(second, 1).unwrap();
            assert!(runtime.plan_inbound(40_000, REMOTE1, 2).is_ok());
            assert!(runtime.plan_inbound(40_000, REMOTE2, 2).is_ok());

            assert!(matches!(
                runtime.plan_inbound(40_000, REMOTE1, NAT44_UDP_MIN_IDLE_TTL_MS + 1),
                Err(Nat44UdpPlanError::MappingMiss)
            ));
            let reused = runtime
                .plan_outbound(INTERNAL2, 40_000, REMOTE2, NAT44_UDP_MIN_IDLE_TTL_MS + 1)
                .unwrap();
            runtime
                .commit_outbound(reused, NAT44_UDP_MIN_IDLE_TTL_MS + 1)
                .unwrap();
            assert!(matches!(
                runtime.plan_inbound(reused.public_port(), REMOTE1, NAT44_UDP_MIN_IDLE_TTL_MS + 1),
                Err(Nat44UdpPlanError::FilterDenied)
            ));
            assert!(runtime
                .plan_inbound(reused.public_port(), REMOTE2, NAT44_UDP_MIN_IDLE_TTL_MS + 1)
                .is_ok());
        });
    }

    #[test]
    fn udp_icmp_lookup_is_read_only_across_time_generation_and_zero_capacity() {
        let policy = Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS, 0)
            .unwrap()
            .with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly);
        with_config(policy, |config| {
            let mut no_mappings = [];
            let mut no_peers = [];
            let mut empty_indexes =
                TestNat44UdpIndexes::new(config, no_mappings.len(), no_peers.len());
            let empty = empty_indexes.runtime(config, &mut no_mappings, &mut no_peers);
            assert!(matches!(
                empty.inspect_icmpv4(40_000, REMOTE1, 0),
                Err(Nat44UdpPlanError::MappingMiss)
            ));

            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut runtime_indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = runtime_indexes.runtime(config, &mut mappings, &mut peers);
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 100)
                .unwrap();
            runtime.commit_outbound(first, 100).unwrap();
            let before_mapping = runtime.mappings()[0];
            let before_peer = runtime.peers()[0];
            let before_counters = runtime.counters();
            assert!(matches!(
                runtime.inspect_icmpv4(40_000, REMOTE1, 99),
                Err(Nat44UdpPlanError::ClockRegression)
            ));
            for now in [100, 100 + NAT44_UDP_MIN_IDLE_TTL_MS - 1] {
                let lookup = runtime.inspect_icmpv4(40_000, REMOTE1, now).unwrap();
                assert_eq!(lookup.internal_address(), INTERNAL);
                assert_eq!(lookup.internal_port(), 40_000);
            }
            assert!(matches!(
                runtime.inspect_icmpv4(40_000, REMOTE1, 100 + NAT44_UDP_MIN_IDLE_TTL_MS),
                Err(Nat44UdpPlanError::MappingMiss)
            ));
            assert!(runtime.inspect_icmpv4(40_000, REMOTE1, 100).is_ok());
            assert_eq!(runtime.mappings()[0], before_mapping);
            assert_eq!(runtime.peers()[0], before_peer);
            assert_eq!(runtime.counters(), before_counters);

            let reused = runtime
                .plan_outbound(INTERNAL2, 40_000, REMOTE2, 100 + NAT44_UDP_MIN_IDLE_TTL_MS)
                .unwrap();
            runtime
                .commit_outbound(reused, 100 + NAT44_UDP_MIN_IDLE_TTL_MS)
                .unwrap();
            assert!(matches!(
                runtime.inspect_icmpv4(
                    reused.public_port(),
                    REMOTE1,
                    100 + NAT44_UDP_MIN_IDLE_TTL_MS
                ),
                Err(Nat44UdpPlanError::FilterDenied)
            ));
            assert!(runtime
                .inspect_icmpv4(
                    reused.public_port(),
                    REMOTE2,
                    100 + NAT44_UDP_MIN_IDLE_TTL_MS
                )
                .is_ok());
        });
    }

    #[test]
    fn full_tables_do_not_evict_or_refresh_live_state_and_zero_capacity_is_safe() {
        with_config(Nat44UdpPolicy::default(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut runtime_indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = runtime_indexes.runtime(config, &mut mappings, &mut peers);
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 10)
                .unwrap();
            runtime.commit_outbound(first, 10).unwrap();
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE2, 20),
                Err(Nat44UdpPlanError::PeerFull)
            ));
            assert_eq!(runtime.mappings()[0].last_outbound_ms(), 10);
            assert!(matches!(
                runtime.plan_outbound(INTERNAL2, 40_001, REMOTE1, 20),
                Err(Nat44UdpPlanError::MappingFull)
            ));
            assert_eq!(runtime.mappings()[0].internal_address(), INTERNAL);

            let mut no_mappings = [];
            let mut one_peer = [Nat44UdpPeerSlot::default(); 1];
            let mut empty_indexes =
                TestNat44UdpIndexes::new(config, no_mappings.len(), one_peer.len());
            let mut empty = empty_indexes.runtime(config, &mut no_mappings, &mut one_peer);
            assert!(matches!(
                empty.plan_outbound(INTERNAL, 40_000, REMOTE1, 0),
                Err(Nat44UdpPlanError::MappingFull)
            ));
            let mut one_mapping = [Nat44UdpMappingSlot::default(); 1];
            let mut no_peers = [];
            let mut empty_indexes =
                TestNat44UdpIndexes::new(config, one_mapping.len(), no_peers.len());
            let mut empty = empty_indexes.runtime(config, &mut one_mapping, &mut no_peers);
            assert!(matches!(
                empty.plan_outbound(INTERNAL, 40_000, REMOTE1, 0),
                Err(Nat44UdpPlanError::PeerFull)
            ));
        });
    }

    #[test]
    fn seeded_scan_wraps_once_after_a_preserved_port_collision() {
        with_config(Nat44UdpPolicy::default(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 2];
            let mut peers = [Nat44UdpPeerSlot::default(); 2];
            let mut runtime_indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = runtime_indexes.runtime(config, &mut mappings, &mut peers);
            let last = runtime.plan_outbound(INTERNAL, 40_001, REMOTE1, 0).unwrap();
            assert_eq!(last.public_port(), 40_001);
            runtime.commit_outbound(last, 0).unwrap();

            // For INTERNAL2/50000 and seed zero the deterministic start is
            // offset one. It collides with 40001, wraps, and selects 40000.
            let wrapped = runtime
                .plan_outbound(INTERNAL2, 50_000, REMOTE1, 0)
                .unwrap();
            assert_eq!(wrapped.public_port(), 40_000);
            runtime.commit_outbound(wrapped, 0).unwrap();
            assert_ne!(
                runtime.mappings()[0].public_port(),
                runtime.mappings()[1].public_port()
            );
        });
    }

    #[test]
    fn clock_regression_is_atomic_and_equal_time_recovers() {
        with_config(Nat44UdpPolicy::default(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut runtime_indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = runtime_indexes.runtime(config, &mut mappings, &mut peers);
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 100)
                .unwrap();
            runtime.commit_outbound(first, 100).unwrap();
            let before = runtime.mappings()[0];
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 99),
                Err(Nat44UdpPlanError::ClockRegression)
            ));
            assert_eq!(runtime.mappings()[0], before);
            assert_eq!(runtime.counters().clock_regressions, 1);
            let equal = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 100)
                .unwrap();
            runtime.commit_outbound(equal, 100).unwrap();
            assert_eq!(runtime.mappings()[0].last_outbound_ms(), 100);
        });
    }

    #[test]
    fn failed_lookup_and_capacity_operations_advance_the_watermark() {
        let policy = Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS, 0).unwrap();
        with_config(policy, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut runtime_indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = runtime_indexes.runtime(config, &mut mappings, &mut peers);
            let first = runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 0).unwrap();
            runtime.commit_outbound(first, 0).unwrap();
            assert!(matches!(
                runtime.plan_inbound(40_000, REMOTE1, NAT44_UDP_MIN_IDLE_TTL_MS),
                Err(Nat44UdpPlanError::MappingMiss)
            ));
            assert!(matches!(
                runtime.plan_inbound(40_000, REMOTE1, NAT44_UDP_MIN_IDLE_TTL_MS - 1),
                Err(Nat44UdpPlanError::ClockRegression)
            ));
            assert!(matches!(
                runtime.plan_inbound(40_000, REMOTE1, NAT44_UDP_MIN_IDLE_TTL_MS),
                Err(Nat44UdpPlanError::MappingMiss)
            ));
        });

        with_config(Nat44UdpPolicy::default(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut runtime_indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = runtime_indexes.runtime(config, &mut mappings, &mut peers);
            let first = runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 0).unwrap();
            runtime.commit_outbound(first, 0).unwrap();
            assert!(matches!(
                runtime.plan_inbound(40_000, REMOTE2, 100),
                Err(Nat44UdpPlanError::FilterDenied)
            ));
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 99),
                Err(Nat44UdpPlanError::ClockRegression)
            ));
            assert!(runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 100)
                .is_ok());
        });

        with_config(Nat44UdpPolicy::default(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 2];
            let mut runtime_indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = runtime_indexes.runtime(config, &mut mappings, &mut peers);
            let first = runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 0).unwrap();
            runtime.commit_outbound(first, 0).unwrap();
            assert!(matches!(
                runtime.plan_outbound(INTERNAL2, 40_001, REMOTE1, 200),
                Err(Nat44UdpPlanError::MappingFull)
            ));
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 199),
                Err(Nat44UdpPlanError::ClockRegression)
            ));
            assert!(runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 200)
                .is_ok());
        });
    }

    #[test]
    fn reconcile_flushes_every_mapping_and_peer_before_rebinding() {
        with_config(Nat44UdpPolicy::default(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut runtime_indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = runtime_indexes.runtime(config, &mut mappings, &mut peers);
            let first = runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 0).unwrap();
            runtime.commit_outbound(first, 0).unwrap();
            let stale = runtime.plan_inbound_read_only(40_000, REMOTE1, 0).unwrap();
            let before_counters = runtime.counters();
            let permit = runtime
                .preflight_reconcile(config, rotated_udp_hash_key())
                .unwrap();
            let report = permit.commit();
            assert_eq!(
                report,
                Nat44UdpReconcileReport {
                    mappings_flushed: 1,
                    peers_flushed: 1,
                }
            );
            assert!(runtime.mappings().iter().all(|slot| !slot.occupied));
            assert!(runtime.peers().iter().all(|slot| !slot.occupied));
            assert!(matches!(
                runtime.plan_inbound(40_000, REMOTE1, 0),
                Err(Nat44UdpPlanError::MappingMiss)
            ));
            let recreated = runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 0).unwrap();
            runtime.commit_outbound(recreated, 0).unwrap();
            let before_mapping = runtime.mappings()[0];
            let before_peer = runtime.peers()[0];
            assert_eq!(
                runtime.commit_inbound(stale, 0),
                Err(Nat44UdpCommitError::RuntimeEpochChanged)
            );
            assert_eq!(runtime.mappings(), &[before_mapping]);
            assert_eq!(runtime.peers(), &[before_peer]);
            assert_eq!(
                before_counters.reconciliations.saturating_add(1),
                runtime.counters().reconciliations
            );
            assert_eq!(runtime.validate_indexes(), Ok(()));
            assert!(runtime.publication_binding_matches(config, rotated_udp_hash_key()));
            assert!(!runtime.publication_binding_matches(config, test_udp_hash_key()));
            assert!(matches!(
                runtime.preflight_reconcile(config, rotated_udp_hash_key()),
                Err(Nat44UdpReconcileError::HashKeyNotRotated)
            ));
        });
    }

    #[test]
    fn runtime_identity_distinguishes_equal_shaped_alternate_backings() {
        with_config(Nat44UdpPolicy::default(), |config| {
            let mut first_mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut first_peers = [Nat44UdpPeerSlot::default(); 1];
            let mut first_indexes =
                TestNat44UdpIndexes::new(config, first_mappings.len(), first_peers.len());
            let first_binding = {
                let first_runtime =
                    first_indexes.runtime(config, &mut first_mappings, &mut first_peers);
                first_runtime.reconcile_binding()
            };

            let mut second_mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut second_peers = [Nat44UdpPeerSlot::default(); 1];
            let mut second_indexes =
                TestNat44UdpIndexes::new(config, second_mappings.len(), second_peers.len());
            let second_runtime =
                second_indexes.runtime(config, &mut second_mappings, &mut second_peers);
            let second_binding = second_runtime.reconcile_binding();
            assert_ne!(
                first_binding.runtime_identity,
                second_binding.runtime_identity
            );
            assert_ne!(first_binding.mappings, second_binding.mappings);
            assert_ne!(first_binding.peers, second_binding.peers);
            assert_ne!(
                first_binding.mapping_buckets,
                second_binding.mapping_buckets
            );
            assert_ne!(first_binding.mapping_nodes, second_binding.mapping_nodes);
            assert_ne!(first_binding.peer_buckets, second_binding.peer_buckets);
            assert_ne!(first_binding.peer_nodes, second_binding.peer_nodes);
            assert_ne!(first_binding.port_owners, second_binding.port_owners);
        });
    }

    #[test]
    fn dropped_and_rejected_reconcile_permits_are_byte_invariant() {
        with_config(Nat44UdpPolicy::default(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            let plan = runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 0).unwrap();
            runtime.commit_outbound(plan, 0).unwrap();

            let before_mappings = runtime.mappings().to_vec();
            let before_peers = runtime.peers().to_vec();
            let before_config = runtime.config;
            let before_hash_key = runtime.hash_key;
            let before_watermark = runtime.watermark_ms;
            let before_generation = runtime.next_generation;
            let before_epoch = runtime.runtime_epoch;
            let before_revision = runtime.state_revision;
            let before_binding = runtime.reconcile_binding;
            let before_counters = runtime.counters();
            let before_mapping_directory = runtime.mapping_directory.backing_snapshot();
            let before_peer_directory = runtime.peer_directory.backing_snapshot();
            let before_port_owners = runtime.port_owners.backing_snapshot();

            drop(
                runtime
                    .preflight_reconcile(config, rotated_udp_hash_key())
                    .unwrap(),
            );
            assert!(matches!(
                runtime.preflight_reconcile(config, test_udp_hash_key()),
                Err(Nat44UdpReconcileError::HashKeyNotRotated)
            ));
            with_port_config(
                Nat44UdpPolicy::default(),
                40_000,
                40_002,
                |oversized_config| {
                    assert!(matches!(
                        runtime.preflight_reconcile(oversized_config, rotated_udp_hash_key()),
                        Err(Nat44UdpReconcileError::PortOwnerTableInvalid)
                    ));
                },
            );

            assert_eq!(runtime.mappings(), before_mappings);
            assert_eq!(runtime.peers(), before_peers);
            assert_eq!(runtime.config, before_config);
            assert_eq!(runtime.hash_key, before_hash_key);
            assert_eq!(runtime.watermark_ms, before_watermark);
            assert_eq!(runtime.next_generation, before_generation);
            assert_eq!(runtime.runtime_epoch, before_epoch);
            assert_eq!(runtime.state_revision, before_revision);
            assert!(runtime.reconcile_binding == before_binding);
            assert_eq!(runtime.counters(), before_counters);
            assert_eq!(
                runtime.mapping_directory.backing_snapshot(),
                before_mapping_directory
            );
            assert_eq!(
                runtime.peer_directory.backing_snapshot(),
                before_peer_directory
            );
            assert_eq!(runtime.port_owners.backing_snapshot(), before_port_owners);
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
    }

    #[test]
    fn runtime_identity_allocator_never_wraps_or_recovers_after_exhaustion() {
        let identities = AtomicU64::new(u64::MAX - 1);
        assert_eq!(
            allocate_udp_runtime_identity_from(&identities),
            Ok(u64::MAX - 1)
        );
        assert_eq!(identities.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(
            allocate_udp_runtime_identity_from(&identities),
            Err(Nat44UdpRuntimeConfigError::RuntimeIdentityExhausted)
        );
        assert_eq!(
            allocate_udp_runtime_identity_from(&identities),
            Err(Nat44UdpRuntimeConfigError::RuntimeIdentityExhausted)
        );
        assert_eq!(identities.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn zero_capacity_same_backing_uses_a_fresh_runtime_identity() {
        with_port_config(Nat44UdpPolicy::default(), 40_000, 40_000, |config| {
            let mut mappings = [];
            let mut peers = [];
            let mut indexes = TestNat44UdpIndexes::new(config, 0, 0);
            let first_binding = {
                let first_runtime = indexes.runtime(config, &mut mappings, &mut peers);
                first_runtime.reconcile_binding()
            };

            let mut replacement = indexes.runtime(config, &mut mappings, &mut peers);
            let replacement_binding = replacement.reconcile_binding();
            assert_ne!(
                first_binding.runtime_identity,
                replacement_binding.runtime_identity
            );
            assert_eq!(first_binding.mappings, replacement_binding.mappings);
            assert_eq!(first_binding.peers, replacement_binding.peers);
            assert_eq!(
                first_binding.mapping_buckets,
                replacement_binding.mapping_buckets
            );
            assert_eq!(
                first_binding.mapping_nodes,
                replacement_binding.mapping_nodes
            );
            assert_eq!(first_binding.peer_buckets, replacement_binding.peer_buckets);
            assert_eq!(first_binding.peer_nodes, replacement_binding.peer_nodes);
            assert_eq!(first_binding.port_owners, replacement_binding.port_owners);
            assert_eq!(
                replacement
                    .preflight_reconcile(config, rotated_udp_hash_key())
                    .unwrap()
                    .commit(),
                Nat44UdpReconcileReport {
                    mappings_flushed: 0,
                    peers_flushed: 0,
                }
            );
            assert!(replacement.publication_binding_matches(config, rotated_udp_hash_key()));
            assert_eq!(replacement.validate_indexes(), Ok(()));
        });
    }

    #[test]
    fn storage_shape_reports_every_validated_backing_array() {
        with_port_config(Nat44UdpPolicy::default(), 40_000, 40_004, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 3];
            let mut peers = [Nat44UdpPeerSlot::default(); 5];
            let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let runtime = indexes.runtime(config, &mut mappings, &mut peers);
            let shape = runtime.storage_shape();
            assert_eq!(shape.mapping_slots(), 3);
            assert_eq!(shape.peer_slots(), 5);
            assert_eq!(shape.mapping_buckets(), 4);
            assert_eq!(shape.mapping_nodes(), 3);
            assert_eq!(shape.peer_buckets(), 8);
            assert_eq!(shape.peer_nodes(), 5);
            assert_eq!(shape.port_owner_slots(), 5);
            assert!(format!("{shape:?}").contains("port_owner_slots: 5"));
        });
    }

    #[test]
    fn udp_hash_key_and_canonical_index_words_are_exact() {
        let first = Nat44UdpHashKey::new(0x0011_2233_4455_6677, 0x8899_aabb_ccdd_eeff).unwrap();
        let second = Nat44UdpHashKey::new(0xfedc_ba98_7654_3210, 0x0123_4567_89ab_cdef).unwrap();
        assert_eq!(
            Nat44UdpHashKey::new(0, 0),
            Err(Nat44UdpHashKeyError::AllZero)
        );
        assert_eq!(format!("{first:?}"), "Nat44UdpHashKey([REDACTED])");
        assert_eq!(format!("{first:#?}"), "Nat44UdpHashKey([REDACTED])");
        assert_eq!(format!("{first:?}"), format!("{second:?}"));
        assert_eq!(
            Nat44UdpRuntime::mapping_lookup_words(INSIDE, INTERNAL, 40_000),
            [1, 0x0a00_000a, 40_000]
        );
        assert_eq!(
            Nat44UdpRuntime::peer_lookup_words(
                7,
                11,
                0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
                REMOTE1,
            ),
            [
                7,
                11,
                0x0011_2233_4455_6677,
                0x8899_aabb_ccdd_eeff,
                0xc633_6401,
            ]
        );
    }

    #[test]
    fn invalid_index_storage_and_reconcile_fail_without_partial_mutation() {
        with_config(Nat44UdpPolicy::default(), |config| {
            let occupied_mapping = Nat44UdpMappingSlot {
                occupied: true,
                generation: 9,
                lifecycle_epoch: 7,
                port_owned: true,
                inside: INSIDE,
                internal_address: INTERNAL,
                internal_port: 40_000,
                public_port: 40_000,
                last_outbound_ms: 3,
            };
            let occupied_peer = Nat44UdpPeerSlot {
                occupied: true,
                mapping_index: 0,
                mapping_generation: 9,
                mapping_lifecycle_epoch: 7,
                remote_address: REMOTE1,
            };
            let mut mappings = [occupied_mapping];
            let mut peers = [occupied_peer];
            let mut mapping_buckets = [DirectoryBucket::default(); 1];
            let mut no_mapping_nodes = [];
            let mut peer_buckets = [DirectoryBucket::default(); 1];
            let mut peer_nodes = [DirectoryNode::default(); 1];
            let mut owners = [PortOwnerSlot::default(); 2];
            let before_mapping_buckets = mapping_buckets;
            let before_peer_buckets = peer_buckets;
            let before_peer_nodes = peer_nodes;
            let before_owners = owners;
            let storage = Nat44UdpIndexStorage::new(
                &mut mapping_buckets,
                &mut no_mapping_nodes,
                &mut peer_buckets,
                &mut peer_nodes,
                &mut owners,
            );
            assert!(matches!(
                Nat44UdpRuntime::new(
                    config,
                    &mut mappings,
                    &mut peers,
                    storage,
                    test_udp_hash_key(),
                ),
                Err(Nat44UdpRuntimeConfigError::MappingNodeCountMismatch)
            ));
            assert_eq!(mappings, [occupied_mapping]);
            assert_eq!(peers, [occupied_peer]);
            assert_eq!(mapping_buckets, before_mapping_buckets);
            assert_eq!(peer_buckets, before_peer_buckets);
            assert_eq!(peer_nodes, before_peer_nodes);
            assert_eq!(owners, before_owners);

            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            let plan = runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 0).unwrap();
            runtime.commit_outbound(plan, 0).unwrap();
            let before_mapping = runtime.mappings()[0];
            let before_peer = runtime.peers()[0];
            let before_counters = runtime.counters();
            assert_eq!(
                runtime.reconcile(config, test_udp_hash_key()),
                Err(Nat44UdpReconcileError::HashKeyNotRotated)
            );
            assert_eq!(runtime.mappings(), &[before_mapping]);
            assert_eq!(runtime.peers(), &[before_peer]);
            assert_eq!(runtime.counters(), before_counters);
            assert_eq!(runtime.validate_indexes(), Ok(()));

            runtime.runtime_epoch = u128::MAX;
            let before_config = runtime.config;
            let before_hash_key = runtime.hash_key;
            let before_watermark = runtime.watermark_ms;
            let before_generation = runtime.next_generation;
            let before_revision = runtime.state_revision;
            let before_binding = runtime.reconcile_binding;
            let before_counters = runtime.counters();
            let before_mapping_directory = runtime.mapping_directory.backing_snapshot();
            let before_peer_directory = runtime.peer_directory.backing_snapshot();
            let before_port_owners = runtime.port_owners.backing_snapshot();
            assert_eq!(
                runtime.reconcile(config, rotated_udp_hash_key()),
                Err(Nat44UdpReconcileError::RuntimeEpochExhausted)
            );
            assert_eq!(runtime.mappings(), &[before_mapping]);
            assert_eq!(runtime.peers(), &[before_peer]);
            assert_eq!(runtime.config, before_config);
            assert_eq!(runtime.hash_key, before_hash_key);
            assert_eq!(runtime.watermark_ms, before_watermark);
            assert_eq!(runtime.next_generation, before_generation);
            assert_eq!(runtime.runtime_epoch, u128::MAX);
            assert_eq!(runtime.state_revision, before_revision);
            assert!(runtime.reconcile_binding == before_binding);
            assert_eq!(runtime.counters(), before_counters);
            assert_eq!(
                runtime.mapping_directory.backing_snapshot(),
                before_mapping_directory
            );
            assert_eq!(
                runtime.peer_directory.backing_snapshot(),
                before_peer_directory
            );
            assert_eq!(runtime.port_owners.backing_snapshot(), before_port_owners);
        });
    }

    #[test]
    fn composite_stale_plans_and_nonwrapping_authority_are_atomic() {
        with_config(Nat44UdpPolicy::default(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 2];
            let mut peers = [Nat44UdpPeerSlot::default(); 2];
            let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            let stale = runtime
                .plan_outbound_read_only(INTERNAL, 40_000, REMOTE1, 0)
                .unwrap();
            let current = runtime
                .plan_outbound_read_only(INTERNAL2, 40_001, REMOTE2, 0)
                .unwrap();
            runtime.commit_outbound(current, 0).unwrap();
            let before_mappings = [runtime.mappings()[0], runtime.mappings()[1]];
            let before_peers = [runtime.peers()[0], runtime.peers()[1]];
            let before_counters = runtime.counters();
            assert_eq!(
                runtime.commit_outbound(stale, 0),
                Err(Nat44UdpCommitError::StateRevisionChanged)
            );
            assert_eq!(runtime.mappings(), &before_mappings);
            assert_eq!(runtime.peers(), &before_peers);
            assert_eq!(runtime.counters(), before_counters);
            assert_eq!(runtime.validate_indexes(), Ok(()));

            runtime.next_generation = u64::MAX;
            let before_mappings = [runtime.mappings()[0], runtime.mappings()[1]];
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 1),
                Err(Nat44UdpPlanError::GenerationExhausted)
            ));
            assert_eq!(runtime.mappings(), &before_mappings);

            runtime.next_generation = 2;
            runtime.state_revision = u128::MAX;
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 1),
                Err(Nat44UdpPlanError::StateRevisionExhausted)
            ));
            assert_eq!(runtime.mappings(), &before_mappings);
        });
    }

    #[test]
    fn expired_owner_displacement_preserves_eim_uniqueness_and_conservation() {
        let policy = Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS, 0).unwrap();
        with_config(policy, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 2];
            let mut peers = [Nat44UdpPeerSlot::default(); 3];
            let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            let first = runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 0).unwrap();
            runtime.commit_outbound(first, 0).unwrap();
            let second = runtime
                .plan_outbound(INTERNAL2, 40_001, REMOTE1, 0)
                .unwrap();
            runtime.commit_outbound(second, 0).unwrap();
            assert_eq!(runtime.validate_indexes(), Ok(()));

            let replacement = runtime
                .plan_outbound(
                    Ipv4Address::from_octets([10, 0, 0, 12]),
                    40_001,
                    REMOTE2,
                    NAT44_UDP_MIN_IDLE_TTL_MS,
                )
                .unwrap();
            assert_eq!(replacement.mapping_index, 0);
            assert_eq!(replacement.displaced_port_mapping_index(), Some(1));
            runtime
                .commit_outbound(replacement, NAT44_UDP_MIN_IDLE_TTL_MS)
                .unwrap();
            assert!(!runtime.mappings()[1].port_owned);
            assert_eq!(
                runtime
                    .mappings()
                    .iter()
                    .filter(|mapping| mapping.occupied && mapping.port_owned)
                    .map(|mapping| mapping.public_port)
                    .collect::<Vec<_>>(),
                vec![40_001]
            );
            assert_eq!(runtime.validate_indexes(), Ok(()));

            let eim = runtime
                .plan_outbound(
                    Ipv4Address::from_octets([10, 0, 0, 12]),
                    40_001,
                    REMOTE1,
                    NAT44_UDP_MIN_IDLE_TTL_MS,
                )
                .unwrap();
            assert_eq!(eim.public_port(), 40_001);
            runtime
                .commit_outbound(eim, NAT44_UDP_MIN_IDLE_TTL_MS)
                .unwrap();
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
    }

    #[test]
    fn expired_exact_mapping_is_recreated_in_place_without_duplicate_key() {
        let policy = Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS, 0).unwrap();
        with_config(policy, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 2];
            let mut peers = [Nat44UdpPeerSlot::default(); 2];
            let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            let first = runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, 0).unwrap();
            runtime.commit_outbound(first, 0).unwrap();
            let exact = runtime
                .plan_outbound(INTERNAL2, 40_001, REMOTE1, 0)
                .unwrap();
            assert_eq!(exact.mapping_index, 1);
            runtime.commit_outbound(exact, 0).unwrap();

            let recreated = runtime
                .plan_outbound(INTERNAL2, 40_001, REMOTE2, NAT44_UDP_MIN_IDLE_TTL_MS)
                .unwrap();
            assert_eq!(recreated.mapping_index, 1);
            runtime
                .commit_outbound(recreated, NAT44_UDP_MIN_IDLE_TTL_MS)
                .unwrap();
            assert_eq!(
                runtime
                    .mappings()
                    .iter()
                    .filter(|mapping| {
                        mapping.occupied
                            && mapping.inside == INSIDE
                            && mapping.internal_address == INTERNAL2
                            && mapping.internal_port == 40_001
                    })
                    .count(),
                1
            );
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
    }

    #[test]
    fn collision_probes_are_capacity_bounded_and_port_search_is_linear_in_pool_only() {
        with_port_config(Nat44UdpPolicy::default(), 40_000, 40_003, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 5];
            let mut peers = [Nat44UdpPeerSlot::default(); 5];
            let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            let target_bucket = runtime
                .mapping_directory
                .bucket_for_words(
                    DirectoryHashDomain::UdpMapping,
                    &Nat44UdpRuntime::mapping_lookup_words(INSIDE, INTERNAL, 10_000),
                )
                .unwrap();
            let colliding_ports = (10_000..u16::MAX)
                .filter(|port| {
                    runtime.mapping_directory.bucket_for_words(
                        DirectoryHashDomain::UdpMapping,
                        &Nat44UdpRuntime::mapping_lookup_words(INSIDE, INTERNAL, *port),
                    ) == Some(target_bucket)
                })
                .take(4)
                .collect::<Vec<_>>();
            assert_eq!(colliding_ports.len(), 4);
            for (offset, port) in colliding_ports.iter().copied().enumerate() {
                let remote = Ipv4Address::from_octets([198, 51, 100, offset as u8 + 1]);
                let plan = runtime.plan_outbound(INTERNAL, port, remote, 0).unwrap();
                runtime.commit_outbound(plan, 0).unwrap();
                assert_eq!(runtime.validate_indexes(), Ok(()));
            }
            runtime.reset_index_probe_counts();
            assert!(runtime
                .find_mapping(INTERNAL, colliding_ports[0])
                .unwrap()
                .is_some());
            let (mapping_probes, _, _) = runtime.index_probe_counts();
            assert_eq!(mapping_probes, 4);
            assert!(mapping_probes <= runtime.mappings.len());

            runtime.reset_index_probe_counts();
            assert!(matches!(
                runtime
                    .plan_outbound(Ipv4Address::from_octets([10, 0, 0, 99]), 40_000, REMOTE1, 0,),
                Err(Nat44UdpPlanError::PortExhausted)
            ));
            let (_, _, owner_probes) = runtime.index_probe_counts();
            assert_eq!(owner_probes, 4);
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });

        with_port_config(Nat44UdpPolicy::default(), 40_000, 40_000, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 4];
            let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            let target_bucket = runtime
                .peer_directory
                .bucket_for_words(
                    DirectoryHashDomain::UdpPeer,
                    &Nat44UdpRuntime::peer_lookup_words(0, 1, 1, REMOTE1),
                )
                .unwrap();
            let colliding_remotes = (1..=254)
                .map(|last| Ipv4Address::from_octets([198, 51, 100, last]))
                .filter(|remote| {
                    runtime.peer_directory.bucket_for_words(
                        DirectoryHashDomain::UdpPeer,
                        &Nat44UdpRuntime::peer_lookup_words(0, 1, 1, *remote),
                    ) == Some(target_bucket)
                })
                .take(4)
                .collect::<Vec<_>>();
            assert_eq!(colliding_remotes.len(), 4);
            for remote in colliding_remotes.iter().copied() {
                let plan = runtime.plan_outbound(INTERNAL, 40_000, remote, 0).unwrap();
                runtime.commit_outbound(plan, 0).unwrap();
            }
            runtime.reset_index_probe_counts();
            assert!(runtime.peer_exists(0, 1, colliding_remotes[0]).unwrap());
            let (_, peer_probes, _) = runtime.index_probe_counts();
            assert_eq!(peer_probes, 4);
            assert!(peer_probes <= runtime.peers.len());
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
    }

    #[test]
    fn prepared_outbound_plan_stays_within_four_cache_lines() {
        assert!(std::mem::size_of::<Nat44UdpOutboundPlan>() <= 256);
    }

    #[test]
    fn policy_and_config_reject_ambiguous_or_unsafe_authority() {
        assert_eq!(
            Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS - 1, 0),
            Err(Nat44UdpPolicyError::IdleTtlTooShort)
        );
        assert_eq!(
            Nat44UdpPolicy::new(NAT44_UDP_MAX_IDLE_TTL_MS + 1, 0),
            Err(Nat44UdpPolicyError::IdleTtlTooLong)
        );
        with_config(Nat44UdpPolicy::default(), |config| {
            assert_eq!(config.policy().idle_ttl_ms(), NAT44_UDP_DEFAULT_IDLE_TTL_MS);
            assert_ne!(config.inside(), config.outside());
            assert_ne!(config.first_port(), 0);
        });
    }
}
