//! NAT44: NAPT of UDP, TCP and ICMP queries from one inside interface to one
//! public address and port set.
//!
//! # Standards
//!
//! - RFC 4787 (UDP): endpoint-independent mapping (REQ-1); filtering
//!   endpoint-independent, address-dependent or address-and-port-dependent
//!   (REQ-8, [`Nat44Filtering`]); mappings refreshed by outbound packets only
//!   (REQ-6) and kept at least two minutes, five by default (REQ-5); fragments
//!   associated with their first fragment (REQ-14, `ipv4_fragment_tracking`).
//! - RFC 5382 (TCP): endpoint-independent mapping (REQ-1); filtering as for UDP
//!   (REQ-3); an unsolicited SYN held at least six seconds before Port Unreachable
//!   (REQ-4); established sessions kept at least 2 hours 4 minutes (REQ-5),
//!   transitory ones four minutes.
//! - RFC 5508 (ICMP): query identifiers mapped as ports, query mappings kept 60
//!   seconds; ICMP errors about a mapped flow translated both ways (REQ-3 to
//!   REQ-7), never refreshing or deleting state (REQ-6).
//! - RFC 7857: port randomization with a key where the port cannot be preserved
//!   (section 9); TCP RST handling (section 2.2).
//! - RFC 7597 section 5.1: a MAP-E port set (PSID) as the pool.
//!
//! Deviations:
//!
//! - Port Unreachable and Protocol Unreachable from the inside are translated only
//!   from the end host the flow went to.
//! - A TCP RST's sequence number is not checked against the session.
//! - A ping from the inside to the public address is answered by the router, not
//!   hairpinned.
//! - No Destination Unreachable code 13 when a mapping cannot be made (RFC 5508
//!   REQ-8); the packet is dropped.
//! - ICMP query filtering is address-dependent whatever the UDP and TCP filtering.

use std::{
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(test)]
use std::cell::Cell;

mod icmp_query;
pub use icmp_query::{
    Nat44IcmpConfig, Nat44IcmpConfigError, Nat44IcmpCounters, Nat44IcmpDisposition,
    Nat44IcmpHashKey, Nat44IcmpHashKeyError, Nat44IcmpIndexStorage, Nat44IcmpMappingSlot,
    Nat44IcmpOccupancy, Nat44IcmpPeerSlot, Nat44IcmpPolicy, Nat44IcmpPolicyError,
    Nat44IcmpReconcileError, Nat44IcmpReconcilePermit, Nat44IcmpReconcileReport, Nat44IcmpRuntime,
    Nat44IcmpRuntimeConfigError, Nat44IcmpStorageShape, NAT44_ICMP_DEFAULT_IDLE_TTL_MS,
    NAT44_ICMP_MAX_IDLE_TTL_MS, NAT44_ICMP_MIN_IDLE_TTL_MS,
};

use crate::nat44_ipv4_id::Ipv4IdGenerator;
use crate::{
    fixed_directory::{
        port_free_bitmap_words, DirectoryHashDomain, DirectoryHashKey, DirectorySemanticError,
        FixedDirectory, PortOwnerError, PortOwnerExpectation, PortOwnerSemanticError,
        PortOwnerTable, PortOwnerToken, PreparedDirectoryLink, PreparedDirectoryRelink,
        PreparedPortOwnerMoveTopology,
    },
    nat44_host_quota::{
        HostAssignment, HostExpectation, HostTable, HostTableCorrupt, HostTableKind,
        Nat44HostStorage,
    },
    nat44_syn_hold::{
        unsolicited_syn_deadline_ms, MaturedSynHold, SynHoldInsert, SynHoldKey, SynHoldTable,
        MAX_SYN_HOLD_SLOTS,
    },
    nat44_tcp_state::{
        fin_closed, next_state, phase_of, Nat44TcpDirection, Nat44TcpInboundRst, Nat44TcpSegment,
        Nat44TcpSessionPhase,
    },
    slot_list::{Linked, SlotLinks, SlotList, LINK_NONE},
    DirectoryBucket, DirectoryNode, ForwardingSnapshot, IfId, Ipv4Address, Nat44TcpSynHoldSlot,
    OccupancyCounter, PortOwnerSlot, TableOccupancy,
};

pub const NAT44_UDP_MIN_IDLE_TTL_MS: u64 = 120_000;
pub const NAT44_UDP_DEFAULT_IDLE_TTL_MS: u64 = 300_000;
pub const NAT44_UDP_MAX_IDLE_TTL_MS: u64 = 86_400_000;
pub const NAT44_TCP_MIN_IDLE_TTL_MS: u64 = 7_440_000;
pub const NAT44_TCP_DEFAULT_IDLE_TTL_MS: u64 = 7_440_000;
pub const NAT44_TCP_MAX_IDLE_TTL_MS: u64 = 604_800_000;
/// Floor of the TCP transitory connection idle-timeout (RFC 5382 REQ-5:
/// "MUST NOT be less than 4 minutes"), for both the opening (partially
/// open) and the closing phase.
pub const NAT44_TCP_MIN_TRANSITORY_IDLE_TTL_MS: u64 = 240_000;
/// Default opening and closing (transitory) idle timeout: the RFC 5382
/// REQ-5 floor, also RFC 7857 §2.1's RECOMMENDED minimum default.
pub const NAT44_TCP_DEFAULT_TRANSITORY_IDLE_TTL_MS: u64 = NAT44_TCP_MIN_TRANSITORY_IDLE_TTL_MS;
/// Per-packet work bound for an inbound initial SYN that passed the NAT
/// filter: at most this many session slots examined for reuse, and at most
/// this many remote-address chain nodes for address-dependent admission and
/// the per-remote inbound session count.
pub const NAT44_TCP_INBOUND_SLOT_PROBES: usize = 16;
/// Default limit on live TCP sessions that external inbound initial SYNs
/// created on one mapping from one remote IPv4 address: `0`, no limit (the
/// RFC baseline, kept pending an owner decision, NAT44-086). A closed or
/// reset connection keeps its session, and its quota, for the closing idle
/// timeout (default 4 minutes), and a SYN the remote never completes for
/// the opening idle timeout. Operators who admit new inbound flows can opt
/// into a limit (8 is a reasonable choice). See
/// [`Nat44TcpPolicy::with_inbound_sessions_per_remote`].
pub const NAT44_TCP_DEFAULT_INBOUND_SESSIONS_PER_REMOTE: u8 = 0;
/// Largest finite per-remote limit: the count is taken by one remote-address
/// chain walk of at most [`NAT44_TCP_INBOUND_SLOT_PROBES`] nodes.
pub const NAT44_TCP_MAX_INBOUND_SESSIONS_PER_REMOTE: u8 = 16;
/// Default per-internal-host mapping limit of both NAT44 protocols: `0`, no
/// limit (N3, NAT44-092). RFC 6888 REQ-4 asks a NAT to support such a limit
/// but sets no value; see [`Nat44UdpPolicy::with_mappings_per_host`].
pub const NAT44_DEFAULT_MAPPINGS_PER_HOST: u16 = 0;
/// Default per-internal-host limit on UDP and ICMP query filter peers and
/// on TCP host-initiated sessions: `0`, no limit (N6, NAT44-119). RFC 6888
/// REQ-5 asks a NAT to support limiting the sessions per subscriber
/// (SHOULD) but sets no value; see [`Nat44UdpPolicy::with_peers_per_host`]
/// and [`Nat44TcpPolicy::with_sessions_per_host`].
pub const NAT44_DEFAULT_STATE_PER_HOST: u16 = 0;
// A TCP session's host-driven expiry offset is a `u32` of milliseconds
// (N6); a saturated offset reads as expired only if every TTL is below it.
const _: () = assert!(NAT44_TCP_MAX_IDLE_TTL_MS < u32::MAX as u64);
const _: () =
    assert!(NAT44_TCP_MAX_INBOUND_SESSIONS_PER_REMOTE as usize == NAT44_TCP_INBOUND_SLOT_PROBES);
const UDP_INDEX_NONE: u32 = u32::MAX;
const TCP_INDEX_NONE: u32 = u32::MAX;
static NEXT_UDP_RUNTIME_IDENTITY: AtomicU64 = AtomicU64::new(1);

struct Redacted;

impl std::fmt::Debug for Redacted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

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

/// Which received ICMPv4 errors (RFC 5508 §4) one NAT44 protocol translates.
///
/// Translation is read-only: it never creates, refreshes, or deletes NAT or
/// firewall state, and the quoted packet must match a live mapping and its
/// peer (UDP) or exact session (TCP). The supported messages are
/// Destination Unreachable codes 0–4, 6, 7, and 9–15, Time Exceeded code 0,
/// and Parameter Problem codes 0–2 (RFC 5508 REQ-10 a, b.5).
///
/// The default [`Self::Bidirectional`] is the RFC 5508 behavior (REQ-4,
/// REQ-5, and REQ-7 are MUSTs for errors that match an active mapping).
/// [`Self::ExternalOnly`] and [`Self::Disabled`] are RFC 1812 §1.1.3
/// security options ("unless explicitly overridden by local policy" in
/// REQ-4 and REQ-5).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44Icmpv4ErrorPolicy {
    /// No translation: errors to the public address stay unsupported local
    /// control, and inside-originated errors fail closed like any other
    /// non-UDP/TCP inside-to-outside crossing.
    Disabled,
    /// Only errors from the external realm toward the public address
    /// (REQ-4).
    ExternalOnly,
    /// External-realm errors (REQ-4), errors an inside host or router sends
    /// toward the external realm about a packet it received through the NAT
    /// (REQ-5), and hairpinned errors (REQ-7, also gated by hairpinning).
    #[default]
    Bidirectional,
}

impl Nat44Icmpv4ErrorPolicy {
    /// Every variant, from the most to the least restrictive.
    pub const ALL: [Self; 3] = [Self::Disabled, Self::ExternalOnly, Self::Bidirectional];

    /// Whether external-realm errors toward the public address are
    /// translated (RFC 5508 REQ-4).
    #[must_use]
    pub const fn translates_external(self) -> bool {
        matches!(self, Self::ExternalOnly | Self::Bidirectional)
    }

    /// Whether private-realm errors toward the external realm (REQ-5) and
    /// hairpinned errors (REQ-7) are translated.
    #[must_use]
    pub const fn translates_internal(self) -> bool {
        matches!(self, Self::Bidirectional)
    }

    /// The declarative-config spelling (`icmpv4-errors = "..."`).
    #[must_use]
    pub const fn config_name(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ExternalOnly => "external-only",
            Self::Bidirectional => "bidirectional",
        }
    }
}

/// Inbound filtering behavior of one NAT44 protocol (RFC 4787 §5).
///
/// RFC 4787 REQ-8 (UDP) and RFC 5382 REQ-3 (TCP) RECOMMEND
/// [`Nat44Filtering::EndpointIndependent`] when application transparency is
/// most important and [`Nat44Filtering::AddressDependent`] when a more
/// stringent behavior is most important, and allow the behavior to be an
/// administrator option (REQ-8 a, REQ-3 a) that may differ per protocol
/// (RFC 5382 REQ-3 b). The default is the more stringent RECOMMENDED
/// choice, `AddressDependent`. `AddressAndPortDependent` is a stricter
/// opt-in that neither RFC recommends.
///
/// Filtering only decides whether an inbound packet may use an existing live
/// mapping. It never creates a mapping, and any bound firewall still
/// evaluates the translated packet afterwards.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44Filtering {
    /// Any external endpoint may reach a live mapping.
    EndpointIndependent,
    /// Only external IPv4 addresses the mapping has sent to (any port).
    #[default]
    AddressDependent,
    /// Only the exact external IPv4 address and port the mapping has sent to.
    AddressAndPortDependent,
}

impl Nat44Filtering {
    /// Every variant, in RFC 4787 §5 order from loosest to strictest.
    pub const ALL: [Self; 3] = [
        Self::EndpointIndependent,
        Self::AddressDependent,
        Self::AddressAndPortDependent,
    ];

    /// The declarative-config spelling (`filtering = "..."`). Exhaustive in
    /// this crate, so a new variant cannot be rendered without a name.
    #[must_use]
    pub const fn config_name(self) -> &'static str {
        match self {
            Self::EndpointIndependent => "endpoint-independent",
            Self::AddressDependent => "address-dependent",
            Self::AddressAndPortDependent => "address-and-port-dependent",
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Nat44UdpPolicy {
    idle_ttl_ms: u64,
    allocator_seed: u64,
    icmpv4_errors: Nat44Icmpv4ErrorPolicy,
    filtering: Nat44Filtering,
    hairpinning: bool,
    port_preservation: bool,
    mappings_per_host: u16,
    peers_per_host: u16,
}

impl std::fmt::Debug for Nat44UdpPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Nat44UdpPolicy")
            .field("idle_ttl_ms", &self.idle_ttl_ms)
            .field("allocator_seed", &Redacted)
            .field("icmpv4_errors", &self.icmpv4_errors)
            .field("filtering", &self.filtering)
            .field("hairpinning", &self.hairpinning)
            .field("port_preservation", &self.port_preservation)
            .field("mappings_per_host", &self.mappings_per_host)
            .field("peers_per_host", &self.peers_per_host)
            .finish()
    }
}

#[cfg(test)]
mod tcp_tests {
    use super::*;
    use crate::{Interface, LocalIpv4Binding, MacAddress, Neighbor, Route};

    // `nat44/tcp_tests/timers.rs`: the per-phase timers (N1).
    mod timers;

    // `nat44/tcp_tests/port_selection.rs`: keyed public-port selection (N2).
    mod port_selection;

    // `nat44/tcp_tests/host_quota.rs`: the per-host mapping quota (N3).
    mod host_quota;

    // `nat44/tcp_tests/host_session_quota.rs`: the per-host session limit
    // and the half-close host-driven expiry (N6).
    mod host_session_quota;

    // `nat44/tcp_tests/carry.rs`: sessions carried across a publication
    // (RELOAD-CARRY).
    mod carry;

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
        let session_address_buckets =
            Box::leak(vec![DirectoryBucket::default(); session_bucket_count].into_boxed_slice());
        let session_address_nodes =
            Box::leak(vec![DirectoryNode::default(); sessions.len()].into_boxed_slice());
        let port_count = config.ports.count();
        let port_owners = Box::leak(vec![PortOwnerSlot::default(); port_count].into_boxed_slice());
        let port_free_bits =
            Box::leak(vec![0_u64; crate::port_free_bitmap_words(port_count)].into_boxed_slice());
        let hosts = crate::nat44_host_quota::leaked_host_storage(mappings.len());
        let sessions_len = sessions.len();
        Nat44TcpRuntime::new(
            config,
            mappings,
            sessions,
            Nat44TcpIndexStorage::new(
                mapping_buckets,
                mapping_nodes,
                session_buckets,
                session_nodes,
                session_address_buckets,
                session_address_nodes,
                port_owners,
                port_free_bits,
                hosts,
            )
            .with_session_hosts(crate::nat44_host_quota::leaked_host_storage_of(
                sessions_len,
                HostTableKind::Words,
            )),
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
                mtu: 1500,
            },
            Interface {
                id: WAN,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: 1500,
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

    /// A corrupt hold table is flushed and counted, never retried: the
    /// next tick and the next SYN start from an empty, working table.
    #[test]
    fn a_corrupt_unsolicited_syn_hold_table_is_flushed_and_counted() {
        with_config(Nat44TcpPolicy::default(), 40_000, 40_001, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 1];
            let mut sessions = [Nat44TcpSessionSlot::default(); 1];
            let holds = Box::leak(vec![Nat44TcpSynHoldSlot::EMPTY; 4].into_boxed_slice());
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions)
                .with_unsolicited_syn_holds(holds)
                .unwrap();
            let syn = [0x45_u8; 40];
            for port in [1000, 1001] {
                assert_eq!(
                    runtime.hold_unsolicited_syn(40_000, REMOTE1, port, 0, &syn, 0),
                    Some(SynHoldInsert::Held)
                );
            }
            runtime.syn_holds.corrupt_fifo_head();
            assert!(runtime
                .pop_matured_unsolicited_syn(crate::NAT44_TCP_UNSOLICITED_SYN_HOLD_MS)
                .is_err());
            let counters = runtime.counters();
            assert_eq!(counters.unsolicited_syn_index_corrupt, 1);
            assert_eq!(counters.config_mismatches, 0);
            assert_eq!(runtime.unsolicited_syn_holds(), 0);
            assert!(runtime
                .pop_matured_unsolicited_syn(u64::MAX)
                .unwrap()
                .is_none());
            assert_eq!(
                runtime.hold_unsolicited_syn(40_000, REMOTE2, 1002, 0, &syn, 1),
                Some(SynHoldInsert::Held)
            );
            // A corrupt index met by a cancel or an insert is flushed too.
            runtime.syn_holds.corrupt_chain_heads();
            runtime.cancel_unsolicited_syn_hold(SynHoldKey {
                public_port: 40_000,
                remote_address: REMOTE2,
                remote_port: 1002,
            });
            assert_eq!(runtime.counters().unsolicited_syn_index_corrupt, 2);
            assert_eq!(runtime.unsolicited_syn_holds(), 0);
            assert_eq!(
                runtime.hold_unsolicited_syn(40_000, REMOTE2, 1003, 0, &syn, 2),
                Some(SynHoldInsert::Held)
            );
            runtime.syn_holds.corrupt_chain_heads();
            assert_eq!(
                runtime.hold_unsolicited_syn(40_000, REMOTE2, 1004, 0, &syn, 3),
                Some(SynHoldInsert::IndexCorrupt)
            );
            let counters = runtime.counters();
            assert_eq!(counters.unsolicited_syn_index_corrupt, 3);
            assert_eq!(counters.unsolicited_syn_hold_full, 0);
            assert_eq!(runtime.unsolicited_syn_holds(), 0);
            assert_eq!(
                runtime.hold_unsolicited_syn(40_000, REMOTE2, 1004, 0, &syn, 4),
                Some(SynHoldInsert::Held)
            );
        });
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
            single_timer(Nat44TcpPolicy::new(NAT44_TCP_MIN_IDLE_TTL_MS, 7).unwrap()),
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
                    .plan_inbound(40_000, REMOTE1, 443, false, NAT44_TCP_MIN_IDLE_TTL_MS - 1)
                    .is_ok());
                assert!(matches!(
                    runtime.plan_inbound(40_000, REMOTE1, 443, false, NAT44_TCP_MIN_IDLE_TTL_MS),
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
                        mappings_carried: 0,
                        sessions_carried: 0,
                        outcome: crate::StateCarryOutcome::FlushRequested,
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

    /// `(occupied, high_water, capacity)` of one table.
    fn tcp_table(table: TableOccupancy) -> (usize, usize, usize) {
        (table.occupied(), table.high_water(), table.capacity())
    }

    /// The O(1) counters equal a full scan of the slots they count.
    fn assert_tcp_occupancy_exact(runtime: &Nat44TcpRuntime<'_>) {
        let occupancy = runtime.occupancy();
        let mappings = runtime
            .mappings()
            .iter()
            .filter(|slot| slot.occupied)
            .count();
        let sessions = runtime
            .sessions()
            .iter()
            .filter(|slot| slot.occupied)
            .count();
        let external = runtime
            .sessions()
            .iter()
            .filter(|slot| slot.occupied && slot.external_inbound)
            .count();
        assert_eq!(occupancy.mappings.occupied(), mappings);
        assert_eq!(occupancy.sessions.occupied(), sessions);
        assert_eq!(occupancy.external_inbound_sessions.occupied(), external);
        for table in [
            occupancy.mappings,
            occupancy.sessions,
            occupancy.external_inbound_sessions,
        ] {
            assert!(table.occupied() <= table.high_water());
            assert!(table.high_water() <= table.capacity());
        }
    }

    #[test]
    fn tcp_occupancy_is_exact_across_insert_expiry_reuse_and_flush() {
        let ttl = NAT44_TCP_DEFAULT_IDLE_TTL_MS;
        with_config(
            quota_policy(Nat44Filtering::AddressDependent, 0),
            40_000,
            40_000,
            |config| {
                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = [Nat44TcpSessionSlot::default(); 3];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                let occupancy = runtime.occupancy();
                assert_eq!(tcp_table(occupancy.mappings), (0, 0, 1));
                assert_eq!(tcp_table(occupancy.sessions), (0, 0, 3));
                assert_eq!(tcp_table(occupancy.external_inbound_sessions), (0, 0, 3));

                // Insert: outbound mapping/session, then two inbound-created
                // sessions admitted by the outbound session's filter.
                outbound_syn(&mut runtime, REMOTE1, 443, 0);
                assert_tcp_occupancy_exact(&runtime);
                assert_eq!(tcp_table(runtime.occupancy().mappings), (1, 1, 1));
                assert_eq!(tcp_table(runtime.occupancy().sessions), (1, 1, 3));
                let first = inbound_syn(&mut runtime, REMOTE1, 1001, 1).unwrap();
                inbound_syn(&mut runtime, REMOTE1, 1002, 2).unwrap();
                assert_tcp_occupancy_exact(&runtime);
                let occupancy = runtime.occupancy();
                assert_eq!(tcp_table(occupancy.sessions), (3, 3, 3));
                assert_eq!(tcp_table(occupancy.external_inbound_sessions), (2, 2, 3));

                // A refresh keeps the mapping and outbound session live.
                let plan = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, false, ttl / 2)
                    .unwrap();
                runtime.commit_outbound(plan, ttl / 2).unwrap();
                assert_eq!(runtime.occupancy(), occupancy);

                // Expiry is lazy: the first inbound session expired at
                // `ttl + 1` but stays counted until its slot is reused.
                assert!(runtime
                    .plan_inbound(40_000, REMOTE1, 1001, false, ttl + 1)
                    .is_err());
                assert_eq!(runtime.occupancy(), occupancy);

                // Reuse: an outbound SYN reclaims that expired slot in place.
                // The table count stays, the inbound-created count drops, and
                // its high-water mark does not.
                let plan = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 450, true, ttl + 1)
                    .unwrap();
                assert_eq!(plan.session_index(), first);
                runtime.commit_outbound(plan, ttl + 1).unwrap();
                assert_tcp_occupancy_exact(&runtime);
                let occupancy = runtime.occupancy();
                assert_eq!(tcp_table(occupancy.mappings), (1, 1, 1));
                assert_eq!(tcp_table(occupancy.sessions), (3, 3, 3));
                assert_eq!(tcp_table(occupancy.external_inbound_sessions), (1, 2, 3));
                assert_eq!(runtime.counters().sessions_expired, 1);

                // Flush resets every count and high-water mark.
                runtime
                    .reconcile(config, rotated_test_tcp_hash_key())
                    .unwrap();
                assert_tcp_occupancy_exact(&runtime);
                let occupancy = runtime.occupancy();
                assert_eq!(tcp_table(occupancy.mappings), (0, 0, 1));
                assert_eq!(tcp_table(occupancy.sessions), (0, 0, 3));
                assert_eq!(tcp_table(occupancy.external_inbound_sessions), (0, 0, 3));
                outbound_syn(&mut runtime, REMOTE2, 443, 0);
                assert_eq!(tcp_table(runtime.occupancy().sessions), (1, 1, 3));
                assert_eq!(
                    tcp_table(runtime.occupancy().external_inbound_sessions),
                    (0, 0, 3)
                );
            },
        );
    }

    #[test]
    fn tcp_mapping_summary_tracks_staggered_sessions_at_exact_expiry() {
        let ttl = NAT44_TCP_MIN_IDLE_TTL_MS;
        with_config(
            single_timer(Nat44TcpPolicy::new(ttl, 0).unwrap()),
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
                    runtime.plan_inbound(40_000, REMOTE1, 443, false, ttl),
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
                    runtime.plan_inbound(40_000, REMOTE2, 8443, false, ttl * 2 - 1),
                    Err(Nat44TcpPlanError::SessionMiss)
                ));
                assert!(matches!(
                    runtime.plan_inbound(40_000, REMOTE1, 9443, false, ttl * 2),
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
                    .plan_inbound_read_only(40_000, REMOTE1, 443, false, 300)
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
                .plan_inbound_read_only(40_000, REMOTE1, 443, false, 0)
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
                    .plan_inbound_read_only(40_000, REMOTE1, 443, false, 0)
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
            single_timer(Nat44TcpPolicy::new(NAT44_TCP_MIN_IDLE_TTL_MS, 0).unwrap())
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
            // 60 bytes of state (N1 added the established-session count and the
            // expiry) plus the reuse-list links (PERF-001),
            // rounded up to the 16-byte alignment of the lifecycle epoch.
            assert_eq!(std::mem::size_of::<Nat44TcpMappingSlot>(), 80);
            assert_eq!(std::mem::size_of::<Nat44TcpSessionSlot>(), 64);
            // A new session is keyed into both the exact and the
            // remote-address session directory, so the plan carries two
            // prepared session links (336 bytes on x86_64 with the 80-byte
            // mapping copy of N1).
            assert!(
                std::mem::size_of::<Nat44TcpOutboundPlan>() <= 352,
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
    fn tcp_inbound_initiation_is_filtered_bounded_and_stale_plans_are_rejected() {
        for filtering in [
            Nat44Filtering::EndpointIndependent,
            Nat44Filtering::AddressDependent,
            Nat44Filtering::AddressAndPortDependent,
        ] {
            let policy = Nat44TcpPolicy::default().with_filtering(filtering);
            with_config(policy, 40_000, 40_000, |config| {
                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = [Nat44TcpSessionSlot::default(); 4];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                let shape = runtime.storage_shape();
                assert_eq!(
                    (
                        shape.session_address_buckets(),
                        shape.session_address_nodes()
                    ),
                    (shape.session_buckets(), shape.session_nodes())
                );
                let plan = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0)
                    .unwrap();
                runtime.commit_outbound(plan, 0).unwrap();
                assert_eq!(runtime.validate_indexes(), Ok(()));

                // A non-SYN packet without an exact session never initiates.
                assert_eq!(
                    runtime.plan_inbound(40_000, REMOTE1, 8443, false, 1).err(),
                    Some(Nat44TcpPlanError::SessionMiss)
                );
                runtime.session_address_lookup_probes.set(0);
                let planned = runtime.plan_inbound(40_000, REMOTE1, 8443, true, 1);
                let address_probes = runtime.session_address_lookup_probes.get();
                if filtering == Nat44Filtering::AddressDependent {
                    // One bounded keyed lookup, never a session scan.
                    assert!((1..=4).contains(&address_probes));
                } else {
                    assert_eq!(address_probes, 0);
                }
                if filtering == Nat44Filtering::AddressAndPortDependent {
                    assert_eq!(planned.err(), Some(Nat44TcpPlanError::SessionMiss));
                    assert_eq!(runtime.counters().inbound_sessions_created, 0);
                    return;
                }
                let stale = planned.unwrap();
                // Any intervening state revision makes the plan stale.
                runtime.observe_now(2).unwrap();
                assert_eq!(
                    runtime.prevalidate_inbound_commit(stale, 1),
                    Err(Nat44TcpCommitError::StalePlan)
                );
                assert_eq!(runtime.counters().inbound_sessions_created, 0);
                assert_eq!(runtime.validate_indexes(), Ok(()));

                let plan = runtime
                    .plan_inbound(40_000, REMOTE1, 8443, true, 2)
                    .unwrap();
                runtime.commit_inbound(plan, 2).unwrap();
                assert_eq!(runtime.validate_indexes(), Ok(()));
                assert_eq!(runtime.counters().inbound_sessions_created, 1);
                assert_eq!(runtime.counters().sessions_created, 2);
                // The new session is now exact: its packets and the internal
                // answer translate without creating more state.
                let plan = runtime
                    .plan_inbound(40_000, REMOTE1, 8443, false, 3)
                    .unwrap();
                runtime.commit_inbound(plan, 3).unwrap();
                let plan = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 8443, false, 4)
                    .unwrap();
                runtime.commit_outbound(plan, 4).unwrap();
                assert_eq!(runtime.counters().sessions_created, 2);
                assert_eq!(runtime.counters().mappings_created, 1);
                assert_eq!(runtime.validate_indexes(), Ok(()));

                // An unmapped public port is a mapping miss in every mode.
                runtime
                    .reconcile(config, rotated_test_tcp_hash_key())
                    .unwrap();
                assert_eq!(
                    runtime.plan_inbound(40_000, REMOTE1, 8443, true, 5).err(),
                    Some(Nat44TcpPlanError::MappingMiss)
                );
                assert_eq!(runtime.validate_indexes(), Ok(()));
            });
        }
    }

    /// Unauthenticated inbound SYNs that pass the NAT filter run before any
    /// firewall decision, so their work is bounded by
    /// `NAT44_TCP_INBOUND_SLOT_PROBES`, not by the session capacity.
    /// Outbound creation fills slots from index 0, so live slots cluster.
    /// Inbound probes are independent keyed positions: at half occupancy a
    /// miss has probability about 2^-16, not about 1/2 as a window starting
    /// inside the live cluster would give.
    #[test]
    fn tcp_inbound_slot_probes_are_independent_of_outbound_clustering() {
        const SESSIONS: usize = 256;
        let policy = Nat44TcpPolicy::default().with_filtering(Nat44Filtering::EndpointIndependent);
        with_config(policy, 40_000, 40_000, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 1];
            let mut sessions = [Nat44TcpSessionSlot::default(); SESSIONS];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            for port in 1..=(SESSIONS / 2) as u16 {
                let plan = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, port, true, 0)
                    .unwrap();
                runtime.commit_outbound(plan, 0).unwrap();
            }
            // Live slots are exactly the low half.
            assert!(runtime.sessions()[..SESSIONS / 2]
                .iter()
                .all(|slot| slot.is_occupied()));
            assert!(runtime.sessions()[SESSIONS / 2..]
                .iter()
                .all(|slot| !slot.is_occupied()));
            let mut misses = 0;
            for remote_port in 1..=1000 {
                runtime.reusable_session_checks.set(0);
                match runtime.plan_inbound_read_only(40_000, REMOTE2, remote_port, true, 1) {
                    Ok(_) => {}
                    Err(Nat44TcpPlanError::SessionFull) => misses += 1,
                    Err(error) => panic!("unexpected {error:?}"),
                }
                assert!(runtime.reusable_session_checks.get() <= NAT44_TCP_INBOUND_SLOT_PROBES);
            }
            // Expected about 1000 * 2^-16 = 0.015; consecutive windows gave
            // about 440 here.
            assert!(misses <= 2, "{misses} of 1000 inbound SYNs missed");
        });
    }

    /// L-4: the keyed probes of a table just above the full-scan bound
    /// visit 16 distinct slots, so with one free slot among 17 an inbound
    /// SYN finds it on 16 of every 17 positions instead of missing whenever
    /// two draws collide.
    #[test]
    fn tcp_inbound_slot_probes_never_repeat_a_position() {
        const SESSIONS: usize = NAT44_TCP_INBOUND_SLOT_PROBES + 1;
        let policy = Nat44TcpPolicy::default().with_filtering(Nat44Filtering::EndpointIndependent);
        with_config(policy, 40_000, 40_000, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 1];
            let mut sessions = [Nat44TcpSessionSlot::default(); SESSIONS];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            for port in 1..SESSIONS as u16 {
                let plan = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, port, true, 0)
                    .unwrap();
                runtime.commit_outbound(plan, 0).unwrap();
            }
            // Exactly one free slot: the last one.
            assert_eq!(
                runtime
                    .sessions()
                    .iter()
                    .filter(|slot| !slot.is_occupied())
                    .count(),
                1
            );
            let mut misses = 0;
            for remote_port in 1..=170 {
                runtime.reusable_session_checks.set(0);
                match runtime.plan_inbound_read_only(40_000, REMOTE2, remote_port, true, 1) {
                    Ok(_) => {}
                    Err(Nat44TcpPlanError::SessionFull) => {
                        misses += 1;
                        // A miss inspected 16 distinct slots, all live.
                        assert_eq!(
                            runtime.reusable_session_checks.get(),
                            NAT44_TCP_INBOUND_SLOT_PROBES
                        );
                    }
                    Err(error) => panic!("unexpected {error:?}"),
                }
                assert!(runtime.reusable_session_checks.get() <= NAT44_TCP_INBOUND_SLOT_PROBES);
            }
            // Only the start position that excludes the free slot can miss:
            // about 1/17 of SYNs (10 of 170). Independent draws with
            // repeats missed about (16/17)^16 = 38% (65 of 170).
            assert!(misses <= 25, "{misses} of 170 inbound SYNs missed");
        });
    }

    /// A full table answers `SessionFull` on both slot-search branches
    /// (full scan at 16 slots and below, distinct keyed probes above).
    #[test]
    fn full_small_tcp_session_tables_refuse_inbound_syn() {
        for capacity in [
            2,
            NAT44_TCP_INBOUND_SLOT_PROBES,
            NAT44_TCP_INBOUND_SLOT_PROBES + 1,
        ] {
            let policy =
                Nat44TcpPolicy::default().with_filtering(Nat44Filtering::EndpointIndependent);
            with_config(policy, 40_000, 40_000, |config| {
                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = vec![Nat44TcpSessionSlot::default(); capacity];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                for port in 1..=capacity as u16 {
                    let plan = runtime
                        .plan_outbound(INTERNAL, 40_000, REMOTE1, port, true, 0)
                        .unwrap();
                    runtime.commit_outbound(plan, 0).unwrap();
                }
                assert!(runtime.sessions().iter().all(|slot| slot.is_occupied()));
                for remote_port in 1..=8 {
                    runtime.reusable_session_checks.set(0);
                    assert_eq!(
                        runtime
                            .plan_inbound_read_only(40_000, REMOTE2, remote_port, true, 1)
                            .err(),
                        Some(Nat44TcpPlanError::SessionFull),
                        "capacity {capacity}"
                    );
                    assert!(
                        runtime.reusable_session_checks.get()
                            <= capacity.min(NAT44_TCP_INBOUND_SLOT_PROBES)
                    );
                }
            });
        }
    }

    /// L-5: a table of at most `NAT44_TCP_INBOUND_SLOT_PROBES` slots is
    /// scanned whole, so its single free slot is always found, wherever it
    /// is and whatever the tuple. (Capacity 1 cannot have a live mapping
    /// with no live session, so it starts at 2.)
    #[test]
    fn small_tcp_session_table_with_one_free_slot_always_admits_inbound_syn() {
        for capacity in [2, 5, NAT44_TCP_INBOUND_SLOT_PROBES] {
            for free in 0..capacity {
                let policy = single_timer(
                    Nat44TcpPolicy::default().with_filtering(Nat44Filtering::EndpointIndependent),
                );
                with_config(policy, 40_000, 40_000, |config| {
                    let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                    let mut sessions = vec![Nat44TcpSessionSlot::default(); capacity];
                    let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                    // Fill every slot at time 0, refresh all but `free` just
                    // before the idle TTL, and look at the exact boundary,
                    // where only `free` has expired.
                    let ttl = config.policy.idle_ttl_ms();
                    for at in [0, ttl - 1] {
                        for port in 0..capacity as u16 {
                            if at != 0 && usize::from(port) == free {
                                continue;
                            }
                            let plan = runtime
                                .plan_outbound(INTERNAL, 40_000, REMOTE1, port + 1, true, at)
                                .unwrap();
                            runtime.commit_outbound(plan, at).unwrap();
                        }
                    }
                    let now = ttl;
                    let reusable: Vec<usize> = (0..capacity)
                        .filter(|&index| runtime.session_slot_reusable(index, now))
                        .collect();
                    assert_eq!(reusable, [free], "capacity {capacity}");
                    for remote_port in 1..=8 {
                        runtime.reusable_session_checks.set(0);
                        let plan = runtime
                            .plan_inbound_read_only(40_000, REMOTE2, remote_port, true, now)
                            .unwrap_or_else(|error| panic!("capacity {capacity}: {error:?}"));
                        assert_eq!(plan.session_index, free);
                        assert!(runtime.reusable_session_checks.get() <= capacity);
                    }
                });
            }
        }
    }

    /// Plans and commits an external inbound SYN, recording a refusal the
    /// way the forwarding path does.
    fn inbound_syn(
        runtime: &mut Nat44TcpRuntime<'_>,
        remote: Ipv4Address,
        remote_port: u16,
        now_ms: u64,
    ) -> Result<usize, Nat44TcpPlanError> {
        match runtime.plan_inbound(40_000, remote, remote_port, true, now_ms) {
            Ok(plan) => {
                runtime.commit_inbound(plan, now_ms).unwrap();
                Ok(plan.session_index)
            }
            Err(error) => {
                runtime.record_plan_error(error);
                Err(error)
            }
        }
    }

    fn outbound_syn(runtime: &mut Nat44TcpRuntime<'_>, remote: Ipv4Address, port: u16, now: u64) {
        let plan = runtime
            .plan_outbound(INTERNAL, 40_000, remote, port, true, now)
            .unwrap();
        runtime.commit_outbound(plan, now).unwrap();
    }

    fn quota_policy(filtering: Nat44Filtering, limit: u8) -> Nat44TcpPolicy {
        single_timer(
            Nat44TcpPolicy::default()
                .with_filtering(filtering)
                .with_inbound_sessions_per_remote(limit)
                .unwrap(),
        )
    }

    /// `policy` with its opening and closing idle timeouts raised to its
    /// established one: every phase shares one TTL, the profile before
    /// N1. Tests of slot reuse, expiry boundaries, quota release, and index
    /// bookkeeping that predate TCP state tracking use it, so their
    /// sessions (which see only SYNs and bare ACKs and stay opening) keep
    /// the single TTL those tests reason about; the per-phase timers have
    /// their own tests below.
    fn single_timer(policy: Nat44TcpPolicy) -> Nat44TcpPolicy {
        let ttl = policy.idle_ttl_ms();
        policy
            .with_opening_idle_ttl_ms(ttl)
            .unwrap()
            .with_closing_idle_ttl_ms(ttl)
            .unwrap()
    }

    #[test]
    fn tcp_inbound_sessions_per_remote_policy_bounds_and_default() {
        assert_eq!(
            Nat44TcpPolicy::default().inbound_sessions_per_remote(),
            NAT44_TCP_DEFAULT_INBOUND_SESSIONS_PER_REMOTE
        );
        assert_eq!(
            Nat44TcpPolicy::new(NAT44_TCP_MIN_IDLE_TTL_MS, 0)
                .unwrap()
                .inbound_sessions_per_remote(),
            NAT44_TCP_DEFAULT_INBOUND_SESSIONS_PER_REMOTE
        );
        for limit in [0, 1, NAT44_TCP_MAX_INBOUND_SESSIONS_PER_REMOTE] {
            assert_eq!(
                Nat44TcpPolicy::default()
                    .with_inbound_sessions_per_remote(limit)
                    .unwrap()
                    .inbound_sessions_per_remote(),
                limit
            );
        }
        for limit in [NAT44_TCP_MAX_INBOUND_SESSIONS_PER_REMOTE + 1, u8::MAX] {
            assert_eq!(
                Nat44TcpPolicy::default().with_inbound_sessions_per_remote(limit),
                Err(Nat44TcpPolicyError::InboundSessionsPerRemoteTooLarge)
            );
        }
    }

    /// NAT44-041: at the limit an external SYN from the same remote IPv4 is
    /// refused with a typed error and changes no slot or index; outbound
    /// sessions to that remote are not counted, and other remotes keep
    /// their own quota.
    #[test]
    fn tcp_inbound_remote_quota_refuses_without_state_change() {
        for filtering in [
            Nat44Filtering::EndpointIndependent,
            Nat44Filtering::AddressDependent,
        ] {
            with_config(quota_policy(filtering, 2), 40_000, 40_000, |config| {
                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = [Nat44TcpSessionSlot::default(); 16];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                // Three outbound sessions to REMOTE1 and one to REMOTE2 on
                // the same mapping: more than the limit, none counted.
                for port in [443, 444, 445] {
                    outbound_syn(&mut runtime, REMOTE1, port, 0);
                }
                outbound_syn(&mut runtime, REMOTE2, 443, 0);
                assert!(runtime.sessions().iter().all(|s| !s.is_external_inbound()));

                for (offset, port) in [1001, 1002].into_iter().enumerate() {
                    let index = inbound_syn(&mut runtime, REMOTE1, port, 1 + offset as u64)
                        .expect("under the limit");
                    assert!(runtime.sessions()[index].is_external_inbound());
                }
                assert_eq!(runtime.counters().inbound_sessions_created, 2);

                let mappings_before = runtime.mappings().to_vec();
                let sessions_before = runtime.sessions().to_vec();
                let counters_before = runtime.counters();
                let directory_before = runtime.session_address_directory.backing_snapshot();
                let exact_before = runtime.session_directory.backing_snapshot();
                runtime.session_address_lookup_probes.set(0);
                assert_eq!(
                    inbound_syn(&mut runtime, REMOTE1, 1003, 3),
                    Err(Nat44TcpPlanError::InboundRemoteQuotaExceeded)
                );
                assert!(
                    runtime.session_address_lookup_probes.get() <= NAT44_TCP_INBOUND_SLOT_PROBES
                );
                // Nothing created, refreshed, or evicted.
                assert_eq!(runtime.mappings(), mappings_before.as_slice());
                assert_eq!(runtime.sessions(), sessions_before.as_slice());
                assert_eq!(
                    runtime.session_address_directory.backing_snapshot(),
                    directory_before
                );
                assert_eq!(runtime.session_directory.backing_snapshot(), exact_before);
                assert_eq!(
                    runtime.counters(),
                    Nat44TcpCounters {
                        inbound_remote_quota_exceeded: 1,
                        ..counters_before
                    }
                );
                assert_eq!(runtime.validate_indexes(), Ok(()));
                // A retransmission is refused again (no slot was taken).
                assert_eq!(
                    inbound_syn(&mut runtime, REMOTE1, 1003, 3),
                    Err(Nat44TcpPlanError::InboundRemoteQuotaExceeded)
                );

                // Existing inbound-created sessions still translate both ways.
                let plan = runtime
                    .plan_inbound(40_000, REMOTE1, 1001, false, 4)
                    .unwrap();
                runtime.commit_inbound(plan, 4).unwrap();
                let plan = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 1002, false, 4)
                    .unwrap();
                runtime.commit_outbound(plan, 4).unwrap();
                // Outbound creation to the same remote is unaffected.
                outbound_syn(&mut runtime, REMOTE1, 446, 4);

                // Another remote has its own quota.
                for port in [2001, 2002] {
                    inbound_syn(&mut runtime, REMOTE2, port, 5).expect("own quota");
                }
                assert_eq!(
                    inbound_syn(&mut runtime, REMOTE2, 2003, 5),
                    Err(Nat44TcpPlanError::InboundRemoteQuotaExceeded)
                );
                assert_eq!(runtime.counters().inbound_remote_quota_exceeded, 3);
                assert_eq!(runtime.counters().inbound_sessions_created, 4);
                assert_eq!(runtime.validate_indexes(), Ok(()));
            });
        }
    }

    /// The count is derived from live slots, so an expired inbound-created
    /// session frees its quota without bookkeeping, and the next SYN reuses
    /// an expired slot of the same mapping and remote.
    #[test]
    fn tcp_inbound_remote_quota_is_released_by_expiry_and_reuse() {
        let ttl = NAT44_TCP_DEFAULT_IDLE_TTL_MS;
        with_config(
            quota_policy(Nat44Filtering::AddressDependent, 2),
            40_000,
            40_000,
            |config| {
                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = [Nat44TcpSessionSlot::default(); 4];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                outbound_syn(&mut runtime, REMOTE1, 443, 0);
                let first = inbound_syn(&mut runtime, REMOTE1, 1001, 1).unwrap();
                let second = inbound_syn(&mut runtime, REMOTE1, 1002, 2).unwrap();
                assert_eq!(
                    inbound_syn(&mut runtime, REMOTE1, 1003, 3),
                    Err(Nat44TcpPlanError::InboundRemoteQuotaExceeded)
                );
                // Keep the mapping and the outbound (admitting) session live.
                let plan = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, false, ttl / 2)
                    .unwrap();
                runtime.commit_outbound(plan, ttl / 2).unwrap();
                // One tick before the first inbound session expires: full.
                assert_eq!(
                    inbound_syn(&mut runtime, REMOTE1, 1003, ttl),
                    Err(Nat44TcpPlanError::InboundRemoteQuotaExceeded)
                );
                // The first expires: one SYN fits, into an expired slot of the
                // same (mapping, remote).
                let reused = inbound_syn(&mut runtime, REMOTE1, 1003, ttl + 1).unwrap();
                assert_eq!(reused, first);
                assert_eq!(
                    inbound_syn(&mut runtime, REMOTE1, 1004, ttl + 1),
                    Err(Nat44TcpPlanError::InboundRemoteQuotaExceeded)
                );
                // The second expires: its slot is reused next.
                assert_eq!(
                    inbound_syn(&mut runtime, REMOTE1, 1004, ttl + 2).unwrap(),
                    second
                );
                assert_eq!(runtime.validate_indexes(), Ok(()));
                assert_eq!(runtime.counters().inbound_sessions_created, 4);
                assert_eq!(runtime.counters().sessions_expired, 2);
                assert_eq!(
                    runtime
                        .sessions()
                        .iter()
                        .filter(|session| session.is_occupied())
                        .count(),
                    3
                );

                // An outbound session that reuses an expired inbound-created
                // slot is not counted: the flag follows the slot's new origin.
                let refresh = ttl + ttl / 2 - 1;
                let plan = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, false, refresh)
                    .unwrap();
                runtime.commit_outbound(plan, refresh).unwrap();
                let later = ttl * 2 + 2;
                let plan = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 450, true, later)
                    .unwrap();
                assert_eq!(plan.session_index(), first);
                runtime.commit_outbound(plan, later).unwrap();
                assert!(!runtime.sessions()[first].is_external_inbound());
                assert_eq!(
                    inbound_syn(&mut runtime, REMOTE1, 1005, later).unwrap(),
                    second
                );
                inbound_syn(&mut runtime, REMOTE1, 1006, later).expect("outbound not counted");
                assert_eq!(
                    inbound_syn(&mut runtime, REMOTE1, 1007, later),
                    Err(Nat44TcpPlanError::InboundRemoteQuotaExceeded)
                );
                assert_eq!(runtime.validate_indexes(), Ok(()));
            },
        );
    }

    /// In a large table an expired slot of the same mapping and remote seen
    /// by the admission walk is reused before any random probe, so expired
    /// nodes do not pile up in that remote-address chain.
    #[test]
    fn tcp_inbound_syn_reuses_an_expired_slot_of_the_same_remote() {
        let ttl = NAT44_TCP_DEFAULT_IDLE_TTL_MS;
        with_config(
            quota_policy(Nat44Filtering::AddressDependent, 2),
            40_000,
            40_000,
            |config| {
                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = [Nat44TcpSessionSlot::default(); 256];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                outbound_syn(&mut runtime, REMOTE1, 443, 0);
                let mut previous = inbound_syn(&mut runtime, REMOTE1, 1000, 1).unwrap();
                assert_ne!(previous, 0, "keyed probe, not the outbound slot");
                for round in 1..8_u64 {
                    // Keep the mapping and the admitting outbound session live.
                    let now = round * ttl + 1;
                    for at in [now - ttl / 2, now] {
                        let plan = runtime
                            .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, false, at)
                            .unwrap();
                        runtime.commit_outbound(plan, at).unwrap();
                    }
                    let port = 1000 + u16::try_from(round).unwrap();
                    let index = inbound_syn(&mut runtime, REMOTE1, port, now).unwrap();
                    assert_eq!(index, previous, "round {round}");
                    previous = index;
                }
                assert_eq!(
                    runtime
                        .sessions()
                        .iter()
                        .filter(|session| session.is_occupied())
                        .count(),
                    2
                );
                assert_eq!(runtime.validate_indexes(), Ok(()));
            },
        );
    }

    /// Reconcile flushes every slot, so the next publication starts with a
    /// full quota; mapping recreation keys a fresh chain likewise.
    #[test]
    fn tcp_inbound_remote_quota_is_reset_by_flush() {
        with_config(
            quota_policy(Nat44Filtering::EndpointIndependent, 1),
            40_000,
            40_000,
            |config| {
                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = [Nat44TcpSessionSlot::default(); 8];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                outbound_syn(&mut runtime, REMOTE1, 443, 0);
                inbound_syn(&mut runtime, REMOTE2, 1001, 1).unwrap();
                assert_eq!(
                    inbound_syn(&mut runtime, REMOTE2, 1002, 1),
                    Err(Nat44TcpPlanError::InboundRemoteQuotaExceeded)
                );
                let report = runtime
                    .reconcile(config, rotated_test_tcp_hash_key())
                    .unwrap();
                assert_eq!(report.sessions_flushed, 2);
                assert!(runtime.sessions().iter().all(|s| !s.is_occupied()));
                outbound_syn(&mut runtime, REMOTE1, 443, 2);
                inbound_syn(&mut runtime, REMOTE2, 1002, 3).expect("flushed quota");
                assert_eq!(
                    inbound_syn(&mut runtime, REMOTE2, 1003, 3),
                    Err(Nat44TcpPlanError::InboundRemoteQuotaExceeded)
                );
                assert_eq!(runtime.validate_indexes(), Ok(()));
            },
        );
    }

    /// `0` disables the limit: the pre-NAT44-041 behavior, bounded only by
    /// the session table.
    #[test]
    fn tcp_inbound_remote_quota_zero_means_unlimited() {
        with_config(
            quota_policy(Nat44Filtering::EndpointIndependent, 0),
            40_000,
            40_000,
            |config| {
                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = [Nat44TcpSessionSlot::default(); 8];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                outbound_syn(&mut runtime, REMOTE1, 443, 0);
                runtime.session_address_lookup_probes.set(0);
                for port in 1..8 {
                    inbound_syn(&mut runtime, REMOTE2, port, 1).unwrap();
                }
                // Endpoint-independent filtering without a limit walks nothing.
                assert_eq!(runtime.session_address_lookup_probes.get(), 0);
                assert_eq!(
                    inbound_syn(&mut runtime, REMOTE2, 8, 1),
                    Err(Nat44TcpPlanError::SessionFull)
                );
                assert_eq!(runtime.counters().inbound_remote_quota_exceeded, 0);
            },
        );
    }

    /// A chain the bounded walk cannot finish fails closed: the count is not
    /// proven below the limit, so the SYN is refused, after at most
    /// `NAT44_TCP_INBOUND_SLOT_PROBES` nodes.
    #[test]
    fn tcp_inbound_remote_quota_fails_closed_beyond_the_walk_budget() {
        let limit = NAT44_TCP_MAX_INBOUND_SESSIONS_PER_REMOTE;
        with_config(
            quota_policy(Nat44Filtering::AddressDependent, limit),
            40_000,
            40_000,
            |config| {
                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = [Nat44TcpSessionSlot::default(); 64];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                // Two outbound sessions put the chain one node over budget
                // once 15 inbound sessions exist.
                outbound_syn(&mut runtime, REMOTE1, 443, 0);
                outbound_syn(&mut runtime, REMOTE1, 444, 0);
                for port in 1..16 {
                    inbound_syn(&mut runtime, REMOTE1, port, 1).unwrap();
                }
                runtime.session_address_lookup_probes.set(0);
                assert_eq!(
                    inbound_syn(&mut runtime, REMOTE1, 16, 2),
                    Err(Nat44TcpPlanError::InboundRemoteQuotaExceeded)
                );
                assert_eq!(
                    runtime.session_address_lookup_probes.get(),
                    NAT44_TCP_INBOUND_SLOT_PROBES
                );
                assert_eq!(runtime.counters().inbound_sessions_created, 15);
            },
        );
    }

    /// Hairpinned inbound halves are neither limited nor counted: their
    /// remote is the public address shared by every inside host.
    #[test]
    fn tcp_hairpin_inbound_halves_are_exempt_from_the_remote_quota() {
        with_config(
            quota_policy(Nat44Filtering::EndpointIndependent, 1),
            40_000,
            40_010,
            |config| {
                let mut mappings = [Nat44TcpMappingSlot::default(); 1];
                let mut sessions = [Nat44TcpSessionSlot::default(); 32];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                let plan = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0)
                    .unwrap();
                let public_port = plan.public_port();
                runtime.commit_outbound(plan, 0).unwrap();
                // More hairpin halves than the walk budget: no walk, no limit.
                for sender_port in 41_000..41_020 {
                    let plan = runtime
                        .plan_hairpin_inbound(public_port, PUBLIC, sender_port, true, 1)
                        .unwrap();
                    assert!(!plan.session.is_external_inbound());
                    runtime.commit_prevalidated_hairpin_inbound(plan, 1);
                }
                // Hairpin sessions do not use up an external remote's quota.
                assert!(runtime
                    .plan_inbound_read_only(public_port, REMOTE2, 1001, true, 1)
                    .is_ok());
                // External SYNs are still limited after the hairpin halves.
                let plan = runtime
                    .plan_inbound(public_port, REMOTE2, 1001, true, 1)
                    .unwrap();
                runtime.commit_inbound(plan, 1).unwrap();
                assert_eq!(
                    runtime
                        .plan_inbound(public_port, REMOTE2, 1002, true, 1)
                        .err(),
                    Some(Nat44TcpPlanError::InboundRemoteQuotaExceeded)
                );
                assert_eq!(runtime.counters().hairpin_translated, 20);
                assert_eq!(runtime.validate_indexes(), Ok(()));
            },
        );
    }

    #[test]
    fn tcp_inbound_syn_work_is_bounded_independent_of_session_capacity() {
        const SESSIONS: usize = 64;
        // A full table: every slot live. The old full scan examined all 64.
        let policy = Nat44TcpPolicy::default().with_filtering(Nat44Filtering::EndpointIndependent);
        with_config(policy, 40_000, 40_000, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 1];
            let mut sessions = [Nat44TcpSessionSlot::default(); SESSIONS];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            for port in 1..=SESSIONS as u16 {
                let plan = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, port, true, 0)
                    .unwrap();
                runtime.commit_outbound(plan, 0).unwrap();
            }
            for remote_port in 1..=8 {
                runtime.reusable_session_checks.set(0);
                assert_eq!(
                    runtime
                        .plan_inbound(40_000, REMOTE2, remote_port, true, 1)
                        .err(),
                    Some(Nat44TcpPlanError::SessionFull)
                );
                assert!(
                    runtime.reusable_session_checks.get() <= NAT44_TCP_INBOUND_SLOT_PROBES,
                    "examined {}",
                    runtime.reusable_session_checks.get()
                );
            }
            // The outbound path checks only the head of the session
            // activity list (PERF-001): the least recently active session
            // is live, so every session is.
            runtime.reusable_session_checks.set(0);
            assert_eq!(
                runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE2, 1, true, 1)
                    .err(),
                Some(Nat44TcpPlanError::SessionFull)
            );
            assert_eq!(runtime.reusable_session_checks.get(), 1);
        });

        // Address-dependent: a long chain of expired (mapping, REMOTE1)
        // sessions is walked at most NAT44_TCP_INBOUND_SLOT_PROBES nodes
        // deep and refuses (fails closed).
        let policy = Nat44TcpPolicy::default();
        with_config(policy, 40_000, 40_000, |config| {
            let ttl = config.policy().idle_ttl_ms();
            let mut mappings = [Nat44TcpMappingSlot::default(); 1];
            let mut sessions = [Nat44TcpSessionSlot::default(); SESSIONS];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            for port in 1..=40 {
                let plan = runtime
                    .plan_outbound(INTERNAL, 40_000, REMOTE1, port, true, 0)
                    .unwrap();
                runtime.commit_outbound(plan, 0).unwrap();
            }
            let plan = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE2, 443, true, ttl - 1)
                .unwrap();
            runtime.commit_outbound(plan, ttl - 1).unwrap();
            runtime.session_address_lookup_probes.set(0);
            assert_eq!(
                runtime.plan_inbound(40_000, REMOTE1, 9, true, ttl).err(),
                Some(Nat44TcpPlanError::SessionMiss)
            );
            let probes = runtime.session_address_lookup_probes.get();
            assert!(probes <= NAT44_TCP_INBOUND_SLOT_PROBES, "probes {probes}");
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });

        // With free slots available the bounded window still admits.
        let policy = Nat44TcpPolicy::default().with_filtering(Nat44Filtering::EndpointIndependent);
        with_config(policy, 40_000, 40_000, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 1];
            let mut sessions = [Nat44TcpSessionSlot::default(); SESSIONS];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let plan = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0)
                .unwrap();
            runtime.commit_outbound(plan, 0).unwrap();
            runtime.reusable_session_checks.set(0);
            let plan = runtime.plan_inbound(40_000, REMOTE2, 443, true, 1).unwrap();
            assert!(runtime.reusable_session_checks.get() <= NAT44_TCP_INBOUND_SLOT_PROBES);
            runtime.commit_inbound(plan, 1).unwrap();
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
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
            let mut session_address_buckets = session_buckets;
            let mut session_address_nodes = session_nodes;
            let mut owners = [PortOwnerSlot::default(); 1];
            let mut owner_bits = vec![0_u64; crate::port_free_bitmap_words(1)];
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
                        &mut session_address_buckets,
                        &mut session_address_nodes,
                        &mut owners,
                        &mut owner_bits,
                        crate::nat44_host_quota::leaked_host_storage(0),
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
                    &mut session_address_buckets,
                    &mut session_address_nodes,
                    &mut owners,
                    &mut owner_bits,
                    crate::nat44_host_quota::leaked_host_storage(0),
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
                    mappings_carried: 0,
                    sessions_carried: 0,
                    outcome: crate::StateCarryOutcome::FlushRequested,
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
                established_sessions: 0,
                last_activity_ms: 3,
                expires_ms: 3 + NAT44_TCP_DEFAULT_TRANSITORY_IDLE_TTL_MS,
                link: TcpMappingLink::default(),
                host_expires_ms: 0,
            };
            let occupied_session = Nat44TcpSessionSlot {
                occupied: true,
                mapping_index: 0,
                mapping_generation: 9,
                mapping_lifecycle_epoch: 7,
                remote_address: REMOTE1,
                remote_port: 443,
                last_activity_ms: 3,
                external_inbound: false,
                host_initiated: true,
                state: 0,
                links: SlotLinks::UNLINKED,
            };
            let mut mappings = [occupied_mapping];
            let mut sessions = [occupied_session];
            let mut mapping_buckets = [DirectoryBucket::default(); 1];
            let mut no_mapping_nodes = [];
            let mut session_buckets = [DirectoryBucket::default(); 1];
            let mut session_nodes = [DirectoryNode::default(); 1];
            let mut session_address_buckets = session_buckets;
            let mut session_address_nodes = session_nodes;
            let mut owners = [PortOwnerSlot::default(); 1];
            let mut owner_bits = vec![0_u64; crate::port_free_bitmap_words(1)];
            let before_mapping_buckets = mapping_buckets;
            let before_session_buckets = session_buckets;
            let before_session_nodes = session_nodes;
            let before_owners = owners;
            let storage = Nat44TcpIndexStorage::new(
                &mut mapping_buckets,
                &mut no_mapping_nodes,
                &mut session_buckets,
                &mut session_nodes,
                &mut session_address_buckets,
                &mut session_address_nodes,
                &mut owners,
                &mut owner_bits,
                crate::nat44_host_quota::leaked_host_storage(1),
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
                    let mut session_address_buckets = session_buckets;
                    let mut session_address_nodes = session_nodes;
                    let mut owners = [PortOwnerSlot::default(); PORT_CAPACITY];
                    let mut owner_bits = vec![0_u64; crate::port_free_bitmap_words(PORT_CAPACITY)];
                    let mut runtime = Nat44TcpRuntime::new(
                        config,
                        &mut mappings,
                        &mut sessions,
                        Nat44TcpIndexStorage::new(
                            &mut mapping_buckets,
                            &mut mapping_nodes,
                            &mut session_buckets,
                            &mut session_nodes,
                            &mut session_address_buckets,
                            &mut session_address_nodes,
                            &mut owners,
                            &mut owner_bits,
                            crate::nat44_host_quota::leaked_host_storage(MAPPING_CAPACITY),
                        ),
                        test_tcp_hash_key(),
                    )
                    .unwrap();
                    let mut model_mappings: [Option<ModelMapping>; MAPPING_CAPACITY] =
                        [None; MAPPING_CAPACITY];
                    let mut model_sessions: [Option<ModelSession>; SESSION_CAPACITY] =
                        [None; SESSION_CAPACITY];
                    let mut next_model_identity = 1_u64;
                    let mut previous_occupancy = runtime.occupancy();
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
                        assert_tcp_occupancy_exact(&runtime);
                        let occupancy = runtime.occupancy();
                        assert!(
                            occupancy.mappings.high_water()
                                >= previous_occupancy.mappings.high_water()
                                && occupancy.sessions.high_water()
                                    >= previous_occupancy.sessions.high_water(),
                            "seed={seed} step={step}"
                        );
                        previous_occupancy = occupancy;
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
                        assert!(
                            owner <= 3 + NAT44_PORT_TAKEOVER_PROBES,
                            "seed={seed} step={step}"
                        );
                    }
                },
            );
        }
    }

    fn next_random(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = *state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    /// Model of the port rule (NAT44-004, NAT44-068), computed by walking
    /// the pool: `Some(port)` when determined, `None` when only ports of
    /// expired owners remain (any of them is correct), and `Err` when every
    /// port has a live owner. `previous` is the public port the endpoint's
    /// expired mapping still owns, if any.
    fn model_tcp_port(
        runtime: &Nat44TcpRuntime<'_>,
        internal_address: Ipv4Address,
        internal_port: u16,
        previous: Option<u16>,
        now_ms: u64,
    ) -> Result<Option<u16>, ()> {
        let config = runtime.config;
        let owner_live =
            |port: u16| {
                runtime.port_owners.owner(port).unwrap().map(|owner| {
                    runtime.mapping_is_live(runtime.mappings[owner.state_index()], now_ms)
                })
            };
        if config.policy.port_preservation
            && config.ports.contains(internal_port)
            && owner_live(internal_port) != Some(true)
        {
            return Ok(Some(internal_port));
        }
        if let Some(port) = previous {
            return Ok(Some(port));
        }
        let pool = config.ports.count();
        let start = runtime
            .port_selection_key()
            .search_start(internal_address, internal_port);
        if let Some(port) = (0..pool)
            .map(|step| config.ports.port((start + step) % pool))
            .find(|port| owner_live(*port).is_none())
        {
            return Ok(Some(port));
        }
        if (0..pool).any(|index| owner_live(config.ports.port(index)) == Some(false)) {
            Ok(None)
        } else {
            Err(())
        }
    }

    /// Random outbound and inbound SYNs, refreshes, and expiry on small
    /// tables, checked against full scans of the slots: a new mapping
    /// or session fails as full exactly when no slot is reusable (as the
    /// scans before PERF-001 decided), the port follows the modelled rule
    /// (`model_tcp_port`), exhaustion is exact, and
    /// the indexes and reuse lists stay consistent after every commit.
    #[test]
    fn tcp_reuse_matches_a_full_scan_reference_under_seeded_churn() {
        let ttl = NAT44_TCP_MIN_IDLE_TTL_MS;
        let mut outcomes = [0_usize; 8];
        for seed in 0..32_u64 {
            let policy = Nat44TcpPolicy::new(ttl, seed.wrapping_mul(0x2545_f491_4f6c_dd1d))
                .unwrap()
                .with_filtering(Nat44Filtering::EndpointIndependent)
                // N2: a quarter of the seeds run without port preservation.
                .with_port_preservation(seed % 4 != 3);
            with_config(policy, 40_000, 40_003, |config| {
                // Three mappings fill before the four ports; five exhaust them.
                let mut mappings =
                    vec![Nat44TcpMappingSlot::default(); 3 + 2 * (seed as usize % 2)];
                let mut sessions = [Nat44TcpSessionSlot::default(); 9];
                let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
                let mut rng = seed ^ 0x0bad_cafe;
                let mut now = 0;
                for _ in 0..300 {
                    now += match next_random(&mut rng) % 10 {
                        0 => ttl,
                        1 => ttl / 2,
                        2..=4 => 1_000,
                        _ => 0,
                    };
                    let remote = [REMOTE1, REMOTE2][(next_random(&mut rng) % 2) as usize];
                    let remote_port = 1 + (next_random(&mut rng) % 3) as u16;
                    let session_available = (0..runtime.sessions.len())
                        .any(|index| runtime.session_slot_reusable(index, now));
                    if next_random(&mut rng).is_multiple_of(4) {
                        let public_port = 40_000 + (next_random(&mut rng) % 4) as u16;
                        let live = runtime
                            .mapping_for_public_port(public_port, now)
                            .unwrap()
                            .is_some();
                        match runtime.plan_inbound(public_port, remote, remote_port, true, now) {
                            Ok(plan) => {
                                assert!(live && (!plan.session_created || session_available));
                                runtime.commit_inbound(plan, now).unwrap();
                                outcomes[0] += 1;
                            }
                            Err(Nat44TcpPlanError::MappingMiss) => assert!(!live),
                            Err(Nat44TcpPlanError::SessionFull) => {
                                assert!(live && !session_available);
                                outcomes[1] += 1;
                            }
                            Err(error) => panic!("unexpected inbound {error:?}"),
                        }
                    } else {
                        let host = Ipv4Address::from_octets([
                            10,
                            0,
                            0,
                            10 + (next_random(&mut rng) % 7) as u8,
                        ]);
                        let internal_port = 39_998 + (next_random(&mut rng) % 9) as u16;
                        let exact = runtime
                            .find_mapping(host, internal_port)
                            .unwrap()
                            .filter(|(_, mapping)| runtime.mapping_is_live(*mapping, now));
                        let mapping_available = runtime
                            .mappings
                            .iter()
                            .any(|mapping| !runtime.mapping_is_live(*mapping, now));
                        let previous = runtime
                            .find_mapping(host, internal_port)
                            .unwrap()
                            .map(|(_, mapping)| mapping)
                            .filter(|mapping| {
                                mapping.port_owned && !runtime.mapping_is_live(*mapping, now)
                            })
                            .map(|mapping| mapping.public_port);
                        let port = model_tcp_port(&runtime, host, internal_port, previous, now);
                        let owners_before = runtime.port_owners.backing_snapshot();
                        let result = runtime.plan_outbound(
                            host,
                            internal_port,
                            remote,
                            remote_port,
                            true,
                            now,
                        );
                        match result {
                            Ok(plan) if plan.mapping_created => {
                                assert!(exact.is_none() && mapping_available && session_available);
                                match port {
                                    Ok(Some(expected)) => {
                                        assert_eq!(plan.mapping.public_port, expected);
                                    }
                                    Ok(None) => {
                                        let offset = usize::from(plan.mapping.public_port - 40_000);
                                        assert_ne!(owners_before[offset], PortOwnerSlot::default());
                                        // Any expired owner is correct (N2: keyed takeover
                                        // probes), never a live one.
                                        let owner = runtime
                                            .port_owners
                                            .owner(plan.mapping.public_port)
                                            .unwrap()
                                            .unwrap();
                                        assert!(!runtime.mapping_is_live(
                                            runtime.mappings[owner.state_index()],
                                            now
                                        ));
                                        outcomes[7] += 1;
                                    }
                                    Err(()) => panic!("allocated past exhaustion"),
                                }
                                runtime.commit_outbound(plan, now).unwrap();
                                outcomes[2] += 1;
                            }
                            Ok(plan) => {
                                assert!(exact.is_some());
                                assert!(!plan.session_created || session_available);
                                runtime.commit_outbound(plan, now).unwrap();
                                outcomes[3] += 1;
                            }
                            Err(Nat44TcpPlanError::MappingFull) => {
                                assert!(exact.is_none() && !mapping_available);
                                outcomes[6] += 1;
                            }
                            Err(Nat44TcpPlanError::SessionFull) => {
                                assert!(!session_available);
                                assert!(exact.is_some() || mapping_available);
                                outcomes[4] += 1;
                            }
                            Err(Nat44TcpPlanError::PortExhausted) => {
                                assert!(exact.is_none() && mapping_available && session_available);
                                assert_eq!(port, Err(()));
                                outcomes[5] += 1;
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

    /// PERF-001 cost bound: with 65536-slot tables and the widest pool,
    /// every new flow, even with every public port owned, examines at most
    /// four mapping list heads (two per activity list), three session list heads
    /// (one per phase), two port owners, and 34 bitmap
    /// words; the search before PERF-001 visited up to every mapping slot,
    /// every session slot, and every pool port.
    #[test]
    fn tcp_new_flow_work_is_constant_in_a_nearly_full_65536_slot_table() {
        const SLOTS: usize = 65_536;
        let ttl = NAT44_TCP_MIN_IDLE_TTL_MS;
        let policy = single_timer(Nat44TcpPolicy::new(ttl, 0x5eed_1234_5678_9abc).unwrap());
        with_config(policy, 1, 65_535, |config| {
            let mut mappings = vec![Nat44TcpMappingSlot::default(); SLOTS];
            let mut sessions = vec![Nat44TcpSessionSlot::default(); SLOTS];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let host = |flow: usize| {
                Ipv4Address::from_octets([
                    10,
                    1 + (flow >> 16) as u8,
                    (flow >> 8) as u8,
                    flow as u8,
                ])
            };
            // [mapping slots, session slots, port owners, bitmap words]
            let mut worst = [0_usize; 4];
            let mut new_flow = |runtime: &mut Nat44TcpRuntime<'_>, flow: usize, now: u64| {
                runtime.reset_index_probe_counts();
                let result = runtime.plan_outbound(host(flow), 7, REMOTE1, 443, true, now);
                let (_, _, mapping_checks, session_checks, owner_probes) =
                    runtime.index_probe_counts();
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
            // Every public port taken, half the flows at 0 and half at 1 s.
            for flow in 0..65_535 {
                let now = if flow < 32_768 { 0 } else { 1_000 };
                new_flow(&mut runtime, flow, now).unwrap();
            }
            assert_eq!(
                new_flow(&mut runtime, 65_535, 1_000),
                Err(Nat44TcpPlanError::PortExhausted)
            );
            // At the TTL the first half has expired: each new flow takes the
            // oldest expired mapping, its session slot, and its public port.
            for flow in 65_536..66_536 {
                let port = new_flow(&mut runtime, flow, ttl).unwrap();
                assert_ne!(port, 0);
            }
            assert_eq!(runtime.counters.mappings_expired, 1_000);
            assert_eq!(runtime.counters.sessions_expired, 1_000);
            assert!(runtime.reuse_lists_are_consistent());
            assert!(runtime.port_owners.bitmap_matches_slots());
            assert!(
                worst[0] <= 4
                    && worst[1] <= 3
                    && worst[2] <= 2 + NAT44_PORT_TAKEOVER_PROBES
                    && worst[3] <= 34,
                "work per new flow {worst:?}"
            );
        });
    }

    /// Defense in depth: an outbound or inbound plan whose never-used
    /// target slot is no longer the lowest never-used slot is refused as
    /// stale before anything mutates (the forwarding path then drops the
    /// packet as `NAT44_TCP_CONFIG_MISMATCH`).
    #[test]
    fn tcp_commit_rejects_a_target_slot_the_reuse_lists_no_longer_offer() {
        let policy = Nat44TcpPolicy::default().with_filtering(Nat44Filtering::EndpointIndependent);
        with_config(policy, 40_000, 40_001, |config| {
            let mut mappings = [Nat44TcpMappingSlot::default(); 2];
            let mut sessions = [Nat44TcpSessionSlot::default(); 4];
            let mut runtime = test_tcp_runtime(config, &mut mappings, &mut sessions);
            let plan = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, 443, true, 0)
                .unwrap();
            runtime.reuse_lists.next_fresh_mapping += 1;
            assert_eq!(
                runtime.prevalidate_outbound_commit(plan, 0),
                Err(Nat44TcpCommitError::StalePlan)
            );
            runtime.reuse_lists.next_fresh_mapping -= 1;
            runtime.reuse_lists.next_fresh_session += 1;
            assert_eq!(
                runtime.prevalidate_outbound_commit(plan, 0),
                Err(Nat44TcpCommitError::StalePlan)
            );
            runtime.reuse_lists.next_fresh_session -= 1;
            runtime.commit_outbound(plan, 0).unwrap();

            let plan = runtime.plan_inbound(40_000, REMOTE2, 80, true, 1).unwrap();
            assert!(plan.session_created);
            let before = (runtime.mappings.to_vec(), runtime.sessions.to_vec());
            runtime.reuse_lists.next_fresh_session += 1;
            assert_eq!(
                runtime.commit_inbound(plan, 1),
                Err(Nat44TcpCommitError::StalePlan)
            );
            assert_eq!(
                (runtime.mappings.to_vec(), runtime.sessions.to_vec()),
                before
            );
            runtime.reuse_lists.next_fresh_session -= 1;
            runtime.commit_inbound(plan, 1).unwrap();
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
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
            icmpv4_errors: Nat44Icmpv4ErrorPolicy::Bidirectional,
            filtering: Nat44Filtering::AddressDependent,
            hairpinning: true,
            port_preservation: true,
            mappings_per_host: NAT44_DEFAULT_MAPPINGS_PER_HOST,
            peers_per_host: NAT44_DEFAULT_STATE_PER_HOST,
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

    /// Enables or disables port preservation, the first step of the
    /// public-port selection: a new mapping keeps the internal port when it
    /// is in the pool and has no live owner (RFC 4787 §4.2.1). The default
    /// `true` is the port-preserving NAPT of RFC 6056 §4 and RFC 7857 §9,
    /// which obfuscate the public port only when it must change; `false`
    /// always selects an obfuscated port (RFC 6056 §4, NAPT without port
    /// preservation), so the public port does not repeat a host's own,
    /// possibly predictable, source port.
    #[must_use]
    pub const fn with_port_preservation(mut self, enabled: bool) -> Self {
        self.port_preservation = enabled;
        self
    }

    #[must_use]
    pub const fn port_preservation(self) -> bool {
        self.port_preservation
    }

    /// Limits the mappings one internal IPv4 address may hold (N3,
    /// NAT44-092, RFC 6888 REQ-4): with a nonzero `limit`, a new mapping
    /// for an internal address that already holds `limit` live mappings is
    /// refused fail closed (`NAT44_UDP_HOST_QUOTA_EXCEEDED`) without
    /// evicting anything. Each counted mapping owns one public port, so
    /// this is the number of external ports per internal host. Existing
    /// mappings, their refreshes, and new peers on them are unaffected.
    /// When the address holds `limit` mappings and the one that expires
    /// first has expired, the new mapping takes over that mapping's slot
    /// (its public port comes from the normal selection), so the host can
    /// make a new mapping again as soon as one of its mappings expires,
    /// with no scan or timer. The default `0` is no limit (RFC 6888 asks only that a
    /// limit be supported). A nonzero limit needs per-host storage
    /// ([`Nat44HostStorage`]); the runtime refuses to start or reconcile to
    /// one without it.
    #[must_use]
    pub const fn with_mappings_per_host(mut self, limit: u16) -> Self {
        self.mappings_per_host = limit;
        self
    }

    /// The per-internal-host mapping limit; `0` means no limit.
    #[must_use]
    pub const fn mappings_per_host(self) -> u16 {
        self.mappings_per_host
    }

    /// Limits the filter peers (remote endpoints of the filter key) the
    /// mappings of one internal IPv4 address may hold together (N6,
    /// NAT44-119, RFC 6888 REQ-5): with a nonzero `limit`, a new peer for
    /// an internal address that already holds `limit` peers on live
    /// mappings is refused fail closed (`NAT44_UDP_HOST_PEER_QUOTA_EXCEEDED`,
    /// also for the new mapping that would carry it) without evicting
    /// anything. Peers live and die with their mapping, which only outbound
    /// packets refresh, so a remote cannot keep a host's peers counting
    /// once the host stops sending. Every peer the host's own outbound
    /// packets create counts, including answers to remotes that reached it
    /// first: under [`Nat44Filtering::EndpointIndependent`] a host that runs
    /// a UDP responder can have its budget spent by remotes (or spoofed
    /// sources) it answers, so do not combine endpoint-independent filtering
    /// with this limit for such hosts (NAT44-125). When the
    /// address holds `limit` peers and its least recently used counted
    /// mapping has expired, that mapping's (dead) peers stop counting and
    /// the new peer is admitted, so a host recovers as soon as one of its
    /// mappings expires, in O(1). Refreshes and inbound traffic are
    /// unaffected. The default `0` is no limit. A nonzero limit needs
    /// per-host storage ([`Nat44HostStorage`]), as for
    /// [`Self::with_mappings_per_host`].
    #[must_use]
    pub const fn with_peers_per_host(mut self, limit: u16) -> Self {
        self.peers_per_host = limit;
        self
    }

    /// The per-internal-host filter peer limit; `0` means no limit.
    #[must_use]
    pub const fn peers_per_host(self) -> u16 {
        self.peers_per_host
    }

    /// Whether the runtime keeps per-host accounting (N3, N6): a mapping or
    /// a peer limit is set.
    pub(crate) const fn per_host_accounting(self) -> bool {
        self.mappings_per_host != 0 || self.peers_per_host != 0
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

    /// Selects the inbound filtering behavior. The default is
    /// [`Nat44Filtering::AddressDependent`].
    #[must_use]
    pub const fn with_filtering(mut self, filtering: Nat44Filtering) -> Self {
        self.filtering = filtering;
        self
    }

    #[must_use]
    pub const fn filtering(self) -> Nat44Filtering {
        self.filtering
    }

    /// Enables or disables hairpinning: an inside host addressing the
    /// public address and port of a live mapping is translated back into
    /// the inside realm with the external source address and port of its own
    /// mapping (RFC 4787 REQ-9, REQ-9 a for UDP; RFC 5382 REQ-8 for TCP).
    /// The default `true` conforms to those MUSTs; `false` is an RFC 1812
    /// §1.1.3 security option that drops such packets before any NAT,
    /// firewall, or resolution state changes.
    #[must_use]
    pub const fn with_hairpinning(mut self, enabled: bool) -> Self {
        self.hairpinning = enabled;
        self
    }

    #[must_use]
    pub const fn hairpinning(self) -> bool {
        self.hairpinning
    }
}

impl Default for Nat44UdpPolicy {
    fn default() -> Self {
        Self {
            idle_ttl_ms: NAT44_UDP_DEFAULT_IDLE_TTL_MS,
            allocator_seed: 0,
            icmpv4_errors: Nat44Icmpv4ErrorPolicy::Bidirectional,
            filtering: Nat44Filtering::AddressDependent,
            hairpinning: true,
            port_preservation: true,
            mappings_per_host: NAT44_DEFAULT_MAPPINGS_PER_HOST,
            peers_per_host: NAT44_DEFAULT_STATE_PER_HOST,
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

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Nat44UdpConfig {
    inside: IfId,
    outside: IfId,
    public_address: Ipv4Address,
    first_port: u16,
    last_port: u16,
    /// The public ports; `first_port..=last_port` are its bounds.
    ports: crate::PortSet,
    policy: Nat44UdpPolicy,
    authority: u64,
    snapshot_identity: [usize; 8],
}

impl std::fmt::Debug for Nat44UdpConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Nat44UdpConfig")
            .field("inside", &self.inside)
            .field("outside", &self.outside)
            .field("public_address", &self.public_address)
            .field("first_port", &self.first_port)
            .field("last_port", &self.last_port)
            .field("policy", &self.policy)
            .field("authority", &Redacted)
            .field("snapshot_identity", &Redacted)
            .finish()
    }
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
        if first_port == 0 {
            return Err(Nat44UdpConfigError::PortPoolIncludesZero);
        }
        if first_port > last_port {
            return Err(Nat44UdpConfigError::PortPoolReversed);
        }
        let ports = crate::PortSet::range(first_port, last_port)
            .map_err(|_| Nat44UdpConfigError::PortPoolReversed)?;
        Self::with_port_set(snapshot, inside, outside, public_address, ports, policy)
    }

    /// Like [`Self::new`] with any port set, such as a MAP-E one
    /// ([`crate::PortSet::psid`]).
    pub fn with_port_set(
        snapshot: &ForwardingSnapshot<'_>,
        inside: IfId,
        outside: IfId,
        public_address: Ipv4Address,
        ports: crate::PortSet,
        policy: Nat44UdpPolicy,
    ) -> Result<Self, Nat44UdpConfigError> {
        if inside == outside {
            return Err(Nat44UdpConfigError::InterfacesEqual);
        }
        if snapshot.interface(inside).is_none() {
            return Err(Nat44UdpConfigError::InsideInterfaceMissing);
        }
        if snapshot.interface(outside).is_none() {
            return Err(Nat44UdpConfigError::OutsideInterfaceMissing);
        }
        if !address_is_host_unicast(snapshot, public_address) {
            return Err(Nat44UdpConfigError::PublicAddressNotHostUnicast);
        }
        let Some(binding) = snapshot.local_binding_for(public_address) else {
            return Err(Nat44UdpConfigError::PublicBindingMissing);
        };
        if binding.interface != outside {
            return Err(Nat44UdpConfigError::PublicBindingWrongInterface);
        }
        let (first_port, last_port) = ports.bounds();
        Ok(Self {
            inside,
            outside,
            public_address,
            first_port,
            last_port,
            ports,
            policy,
            authority: snapshot_authority(snapshot),
            snapshot_identity: snapshot.identity(),
        })
    }

    /// The fields that must stay equal for state to carry across a
    /// publication (RELOAD-CARRY).
    #[must_use]
    pub const fn carry_identity(self) -> Nat44CarryIdentity {
        Nat44CarryIdentity::new(
            self.inside,
            self.outside,
            self.public_address,
            self.ports,
            self.policy.filtering,
        )
        .with_idle_ttl(self.policy.idle_ttl_ms)
        .with_host_limits([self.policy.mappings_per_host, self.policy.peers_per_host])
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

    /// The public ports.
    #[must_use]
    pub const fn ports(self) -> crate::PortSet {
        self.ports
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

/// Which reuse set a UDP mapping slot is in (PERF-001). Every slot is in
/// exactly one, so a reusable slot, peer, or port is found at a list head in
/// O(1) instead of by scanning the table.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum UdpMappingList {
    /// Never used since construction or the last flush: the slots at and
    /// after the fresh boundary, untouched (equal to the default slot).
    /// Slots leave this set only in index order, so no links are needed.
    #[default]
    Free,
    /// Occupied, owning its public port and at least one peer, in
    /// `last_outbound_ms` order (oldest first). Every outbound commit
    /// stamps the current time and moves the slot to the tail, and time is
    /// monotonic, so the head is the first to expire: if any slot on this
    /// list is expired, the head is.
    Lru,
    /// Expired, owning its public port, with its peers released to the
    /// stale-peer chain.
    Parked,
    /// Expired, owning neither a public port nor peers.
    Retired,
}

/// Head and tail of a singly linked chain of UDP peer slots.
#[derive(Clone, Copy, Eq, PartialEq)]
struct PeerChain {
    head: u32,
    tail: u32,
}

impl PeerChain {
    const EMPTY: Self = Self {
        head: LINK_NONE,
        tail: LINK_NONE,
    };

    const fn head(self) -> Option<usize> {
        if self.head == LINK_NONE {
            None
        } else {
            Some(self.head as usize)
        }
    }
}

impl Default for PeerChain {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Reuse bookkeeping embedded in a UDP mapping slot: its list links and
/// list, and the chain of the peers of its current generation.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct UdpMappingLink {
    links: SlotLinks,
    list: UdpMappingList,
    peers: PeerChain,
}

/// The fresh boundary and the three UDP mapping reuse lists.
#[derive(Clone, Copy)]
struct UdpMappingLists {
    /// Slots at and after this index have never been used since the last
    /// flush; those before it are occupied.
    next_fresh: usize,
    lru: SlotList,
    parked: SlotList,
    retired: SlotList,
}

impl UdpMappingLists {
    /// Every slot fresh (construction and reconcile flush).
    const FLUSHED: Self = Self {
        next_fresh: 0,
        lru: SlotList::EMPTY,
        parked: SlotList::EMPTY,
        retired: SlotList::EMPTY,
    };

    /// The lowest never-used slot, if any.
    fn fresh(&self, capacity: usize) -> Option<usize> {
        (self.next_fresh < capacity).then_some(self.next_fresh)
    }

    /// Takes slot `index` out of `list`: unlinks it, or for a never-used
    /// slot (always the lowest) advances the fresh boundary past it. O(1).
    fn detach(&mut self, mappings: &mut [Nat44UdpMappingSlot], index: usize, list: UdpMappingList) {
        match list {
            UdpMappingList::Free => {
                debug_assert!(index == self.next_fresh);
                self.next_fresh += 1;
            }
            UdpMappingList::Lru => self.lru.unlink(mappings, index),
            UdpMappingList::Parked => self.parked.unlink(mappings, index),
            UdpMappingList::Retired => self.retired.unlink(mappings, index),
        }
    }

    /// Appends the detached slot `index` to `list` (never the free set).
    fn attach(&mut self, mappings: &mut [Nat44UdpMappingSlot], index: usize, list: UdpMappingList) {
        mappings[index].link.list = list;
        match list {
            UdpMappingList::Free => debug_assert!(false, "slots never return to the free set"),
            UdpMappingList::Lru => self.lru.push_back(mappings, index),
            UdpMappingList::Parked => self.parked.push_back(mappings, index),
            UdpMappingList::Retired => self.retired.push_back(mappings, index),
        }
    }
}

/// Where the peer slot of an outbound plan comes from; derived from the
/// lists at plan time and checked again before the commit mutates anything.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpPeerSource {
    /// The head of the stale-peer chain.
    Stale,
    /// The first peer of the expired head of the activity list, whose
    /// peers the commit releases to the stale chain first (the mapping is
    /// parked).
    ExpiredHead(usize),
    /// The next never-used peer slot.
    Fresh,
}

#[derive(Clone, Copy, Eq, PartialEq)]
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
    link: UdpMappingLink,
}

impl Linked for Nat44UdpMappingSlot {
    fn links(&self) -> SlotLinks {
        self.link.links
    }

    fn links_mut(&mut self) -> &mut SlotLinks {
        &mut self.link.links
    }
}

impl std::fmt::Debug for Nat44UdpMappingSlot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Nat44UdpMappingSlot")
            .field("occupied", &self.occupied)
            .field("inside", &self.inside)
            .field("public_port", &self.public_port)
            .field("last_outbound_ms", &self.last_outbound_ms)
            .finish_non_exhaustive()
    }
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
            link: UdpMappingLink::default(),
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

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Nat44UdpPeerSlot {
    occupied: bool,
    mapping_index: usize,
    mapping_generation: u64,
    mapping_lifecycle_epoch: u128,
    remote_address: Ipv4Address,
    /// Filter key port: the remote UDP port under
    /// [`Nat44Filtering::AddressAndPortDependent`], otherwise zero.
    remote_port: u16,
    /// Next peer on this slot's chain: the peers of one live-ordered
    /// mapping, or the stale-peer chain (`LINK_NONE` at the end and for
    /// unoccupied slots).
    next: u32,
}

impl std::fmt::Debug for Nat44UdpPeerSlot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Nat44UdpPeerSlot")
            .field("occupied", &self.occupied)
            .finish_non_exhaustive()
    }
}

impl Default for Nat44UdpPeerSlot {
    fn default() -> Self {
        Self {
            occupied: false,
            mapping_index: 0,
            mapping_generation: 0,
            mapping_lifecycle_epoch: 0,
            remote_address: Ipv4Address::from_octets([0; 4]),
            remote_port: 0,
            next: LINK_NONE,
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

    /// Remote UDP port of the filter key. Zero unless the runtime uses
    /// [`Nat44Filtering::AddressAndPortDependent`].
    #[must_use]
    pub const fn remote_port(self) -> u16 {
        self.remote_port
    }
}

/// Slot occupancy of a [`Nat44UdpRuntime`]; see [`Nat44UdpRuntime::occupancy`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Nat44UdpOccupancy {
    pub mappings: TableOccupancy,
    pub peers: TableOccupancy,
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
    /// Hairpinned packets translated back into the inside realm (both
    /// halves committed). Not counted in `outbound_translated` or
    /// `inbound_translated`.
    pub hairpin_translated: u64,
    /// Hairpinned packets dropped after their outbound half committed: the
    /// destination mapping's filtering, a bound firewall, capacity, or
    /// inside route/neighbor work refused the inbound half. The sender's
    /// mapping and filter state stay, as for an outbound packet a remote NAT
    /// drops (hole punching, RFC 5128 §3.3.2 for UDP and §3.4 for TCP).
    /// Filter refusals are not also counted in the ordinary inbound
    /// miss/deny counters.
    pub hairpin_inbound_refused: u64,
    /// Hairpinned packets dropped because hairpinning is disabled.
    pub hairpin_disabled: u64,
    /// New mappings refused because their internal address already held
    /// the per-host limit of live mappings (N3).
    pub host_quota_exceeded: u64,
    /// New peers (and the new mappings that would carry them) refused
    /// because their internal address already held the per-host limit of
    /// peers on live mappings (N6).
    pub host_peer_quota_exceeded: u64,
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
    /// The outbound half of a hairpinned packet committed the sender's
    /// mapping and filter state; `public_port` is its external source port.
    HairpinOutboundCommitted {
        public_port: u16,
        mapping_created: bool,
        peer_created: bool,
    },
    /// A hairpinned packet was translated back into the inside realm with
    /// external source `public_port` and internal destination
    /// `internal_address:internal_port`.
    HairpinTranslated {
        public_port: u16,
        internal_address: Ipv4Address,
        internal_port: u16,
    },
    MappingMiss,
    FilterDenied,
    MappingFull,
    PeerFull,
    PortExhausted,
    /// The internal address already holds the per-host limit of live
    /// mappings (N3).
    HostQuotaExceeded,
    /// The internal address already holds the per-host limit of filter
    /// peers on live mappings (N6).
    HostPeerQuotaExceeded,
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
    /// Allocated mapping and peer slots kept by a carry (RELOAD-CARRY),
    /// counted like the flushed ones: expired slots not yet reclaimed count.
    pub mappings_carried: usize,
    pub peers_carried: usize,
    pub outcome: crate::StateCarryOutcome,
}

/// The part of a NAT44 configuration that NAT state depends on
/// (RELOAD-CARRY): mappings store internal and public endpoints and filter
/// peers are keyed by the filtering mode, so state carries across a
/// publication only when these are equal. TCP mappings also store absolute
/// expiry deadlines, so the TCP phase timeouts must be equal too. The UDP and
/// ICMP idle timeout, quotas, the allocator seed, hairpinning, port
/// preservation, and the ICMPv4 error policy apply to carried state exactly
/// as to new state, so they may change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44CarryIdentity {
    inside: IfId,
    outside: IfId,
    public_address: Ipv4Address,
    ports: crate::PortSet,
    filtering: Nat44Filtering,
    /// TCP (established, opening, closing) idle timeouts; zero for UDP and
    /// ICMP, whose liveness is computed from the bound timeout.
    timers: [u64; 3],
    /// UDP/ICMP idle timeout; zero for TCP. A carry may lower it but not
    /// raise it: a longer timeout would make mappings that already expired
    /// (and may already be parked or retired) live again.
    idle_ttl_ceiling: u64,
    /// Per-host limits (mappings, then peers or sessions; `0` = none). A
    /// carry may raise or remove a limit but not lower or add one: the
    /// reclaim paths take over a host's expired slot one for one, so a host
    /// above a lowered limit would never come down to it.
    host_limits: [u16; 2],
}

impl Nat44CarryIdentity {
    /// `ports` is the public port pool, or the ICMP
    /// identifier pool.
    #[must_use]
    pub const fn new(
        inside: IfId,
        outside: IfId,
        public_address: Ipv4Address,
        ports: crate::PortSet,
        filtering: Nat44Filtering,
    ) -> Self {
        Self {
            inside,
            outside,
            public_address,
            ports,
            filtering,
            timers: [0; 3],
            idle_ttl_ceiling: 0,
            host_limits: [0; 2],
        }
    }

    /// This identity with the UDP or ICMP idle timeout, which a carry may
    /// lower but not raise.
    #[must_use]
    pub const fn with_idle_ttl(mut self, idle_ttl_ms: u64) -> Self {
        self.idle_ttl_ceiling = idle_ttl_ms;
        self
    }

    /// This identity with the per-host limits (mappings, then peers or
    /// sessions; `0` = none), which a carry may raise but not lower.
    #[must_use]
    pub const fn with_host_limits(mut self, limits: [u16; 2]) -> Self {
        self.host_limits = limits;
        self
    }

    /// This identity with the TCP (established, opening, closing) idle
    /// timeouts, which must stay equal for TCP state to carry.
    #[must_use]
    pub const fn with_tcp_timers(mut self, timers: [u64; 3]) -> Self {
        self.timers = timers;
        self
    }

    /// Why state created under `self` cannot carry into `next`, in this
    /// order: interfaces, public address, pool, filtering, timers (any TCP
    /// timeout change, a longer UDP/ICMP timeout), per-host limits (a lower
    /// or new limit).
    #[must_use]
    pub fn carry_conflict(self, next: Self) -> Option<crate::StateCarryConflict> {
        use crate::StateCarryConflict;
        if (self.inside, self.outside) != (next.inside, next.outside) {
            Some(StateCarryConflict::Interfaces)
        } else if self.public_address != next.public_address {
            Some(StateCarryConflict::PublicAddress)
        } else if self.ports != next.ports {
            Some(StateCarryConflict::PortRange)
        } else if self.filtering != next.filtering {
            Some(StateCarryConflict::Filtering)
        } else if self.timers != next.timers || next.idle_ttl_ceiling > self.idle_ttl_ceiling {
            Some(StateCarryConflict::Timers)
        } else if (0..2).any(|list| {
            let (old, new) = (self.host_limits[list], next.host_limits[list]);
            new != 0 && (old == 0 || new < old)
        }) {
            Some(StateCarryConflict::Quota)
        } else {
            None
        }
    }
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
    /// The host's expired mapping whose peers stop counting so this plan's
    /// new peer fits the per-host peer limit (N6), or `UDP_INDEX_NONE`.
    host_peer_reclaim: u32,
    prepared: PreparedNat44UdpOutboundCommit,
}

impl Nat44UdpOutboundPlan {
    const fn mapping_index(self) -> usize {
        self.mapping_index as usize
    }

    fn host_peer_reclaim(self) -> Option<usize> {
        (self.host_peer_reclaim != UDP_INDEX_NONE).then_some(self.host_peer_reclaim as usize)
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

    pub(crate) const fn hairpin_disposition(self) -> Nat44UdpDisposition {
        Nat44UdpDisposition::HairpinOutboundCommitted {
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
    HostQuotaExceeded,
    HostPeerQuotaExceeded,
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
    ReuseLists,
    Hosts,
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
///
/// `port_free_bits` is the free-port bitmap of the port-owner index and must
/// have exactly [`port_free_bitmap_words`](crate::port_free_bitmap_words)
/// of the port-owner count words.
pub struct Nat44UdpIndexStorage<'a> {
    mapping_buckets: &'a mut [DirectoryBucket],
    mapping_nodes: &'a mut [DirectoryNode],
    peer_buckets: &'a mut [DirectoryBucket],
    peer_nodes: &'a mut [DirectoryNode],
    port_owners: &'a mut [PortOwnerSlot],
    port_free_bits: &'a mut [u64],
    hosts: Nat44HostStorage<'a, 1>,
}

impl<'a> Nat44UdpIndexStorage<'a> {
    /// `hosts` is the per-host accounting (N3, N6): empty
    /// ([`Nat44HostStorage::disabled`]) for a runtime whose
    /// [`Nat44UdpPolicy::mappings_per_host`] and
    /// [`Nat44UdpPolicy::peers_per_host`] are `0`, else one link, host
    /// slot, directory node, link word, and host counter per mapping slot
    /// and the mapping directory's bucket count.
    pub fn new(
        mapping_buckets: &'a mut [DirectoryBucket],
        mapping_nodes: &'a mut [DirectoryNode],
        peer_buckets: &'a mut [DirectoryBucket],
        peer_nodes: &'a mut [DirectoryNode],
        port_owners: &'a mut [PortOwnerSlot],
        port_free_bits: &'a mut [u64],
        hosts: Nat44HostStorage<'a, 1>,
    ) -> Self {
        Self {
            mapping_buckets,
            mapping_nodes,
            peer_buckets,
            peer_nodes,
            port_owners,
            port_free_bits,
            hosts,
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
    port_free_bits: Vec<u64>,
    host_links: Vec<crate::Nat44HostLink>,
    hosts: Vec<crate::Nat44UdpHostSlot>,
    host_buckets: Vec<DirectoryBucket>,
    host_nodes: Vec<DirectoryNode>,
    host_words: Vec<u32>,
    host_counters: Vec<crate::Nat44HostCounter>,
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
        let port_count = config.ports.count();
        Self {
            mapping_buckets: vec![DirectoryBucket::default(); mapping_bucket_count],
            mapping_nodes: vec![DirectoryNode::default(); mapping_capacity],
            peer_buckets: vec![DirectoryBucket::default(); peer_bucket_count],
            peer_nodes: vec![DirectoryNode::default(); peer_capacity],
            port_owners: vec![PortOwnerSlot::default(); port_count],
            port_free_bits: vec![0; crate::port_free_bitmap_words(port_count)],
            host_links: vec![crate::Nat44HostLink::EMPTY; mapping_capacity],
            hosts: vec![crate::Nat44UdpHostSlot::EMPTY; mapping_capacity],
            host_buckets: vec![DirectoryBucket::default(); mapping_bucket_count],
            host_nodes: vec![DirectoryNode::default(); mapping_capacity],
            host_words: vec![0; mapping_capacity],
            host_counters: vec![crate::Nat44HostCounter::EMPTY; mapping_capacity],
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
            &mut self.port_free_bits,
            Nat44HostStorage::new(
                &mut self.host_links,
                &mut self.hosts,
                &mut self.host_buckets,
                &mut self.host_nodes,
            )
            .with_link_words(&mut self.host_words)
            .with_host_counters(&mut self.host_counters),
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
    /// The per-host accounting storage (N3) does not have one host slot
    /// and one directory node per mapping slot, or its directory is
    /// invalid.
    HostTableInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44UdpReconcileError {
    HashKeyNotRotated,
    PortOwnerTableInvalid,
    RuntimeEpochExhausted,
    /// The new configuration sets a per-host mapping limit (N3) but the
    /// runtime has no per-host storage (a storage-shape change).
    HostTableMissing,
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
    port_bitmap_words: u32,
    host_slots: u32,
    host_buckets: u32,
    host_nodes: u32,
}

impl Nat44UdpStorageShape {
    /// Host slots of the per-host mapping accounting (N3), one per mapping
    /// slot.
    #[must_use]
    pub const fn host_slots(self) -> u32 {
        self.host_slots
    }

    /// Buckets of the host directory, as many as the mapping directory's.
    #[must_use]
    pub const fn host_buckets(self) -> u32 {
        self.host_buckets
    }

    /// Nodes of the host directory, one per host slot.
    #[must_use]
    pub const fn host_nodes(self) -> u32 {
        self.host_nodes
    }

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

    /// Words of the free-port bitmap of the port-owner index.
    #[must_use]
    pub const fn port_bitmap_words(self) -> u32 {
        self.port_bitmap_words
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
    /// `Carried` keeps every slot, index, the hash key, the epoch, and the
    /// clock watermark; anything else flushes and rotates the key.
    outcome: crate::StateCarryOutcome,
}

impl Nat44UdpReconcilePermit<'_, '_> {
    /// Consumes this one-shot permit and applies its prevalidated reconcile.
    pub fn commit(self) -> Nat44UdpReconcileReport {
        if self.outcome.carried() {
            return self.runtime.commit_prevalidated_carry(self.config);
        }
        let mut report = self.runtime.commit_prevalidated_reconcile(
            self.config,
            self.hash_key,
            self.next_runtime_epoch,
        );
        report.outcome = self.outcome;
        report
    }

    /// What [`Self::commit`] will do with the state.
    #[must_use]
    pub const fn outcome(&self) -> crate::StateCarryOutcome {
        self.outcome
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Nat44UdpBackingIdentity {
    address: usize,
    length: usize,
}

impl std::fmt::Debug for Nat44UdpBackingIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Nat44UdpBackingIdentity([REDACTED])")
    }
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
    port_free_bits: Nat44UdpBackingIdentity,
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
            port_free_bits: Nat44UdpBackingIdentity::of(indexes.port_free_bits),
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
/// Every per-packet search is bounded (PERF-001). A new mapping, peer, or
/// public port is found in O(1) from intrusive lists embedded in the slots:
/// occupied mappings in last-outbound order (the head is the first to
/// expire), expired mappings whose peers or port were already taken, a
/// chain of the peers of each mapping and of stale peers, and a fresh-slot
/// boundary. Ports come from a free-port bitmap: the internal port if
/// unowned or expired, else the port the endpoint's expired mapping still
/// owns, else the first unowned port from the seeded start, else the port
/// of an expired mapping (see `allocate_port`). Expiry stays lazy (no timer
/// or sweep): expired state is reclaimed when a new flow needs it.
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
    /// Per-internal-host lists of the port-owning mappings (N3) and their
    /// peer counts (N6).
    hosts: HostTable<'a, 1>,
    hash_key: Nat44UdpHashKey,
    /// IDs of translated non-atomic datagrams (RFC 6864 §5.3.1), keyed by
    /// the construction key and kept across reconcile and flush.
    ipv4_ids: Ipv4IdGenerator,
    watermark_ms: Option<u64>,
    next_generation: u64,
    runtime_epoch: u128,
    state_revision: u128,
    #[allow(dead_code)] // Retained as defense-in-depth for the publication owner.
    reconcile_binding: Nat44UdpReconcileBinding,
    counters: Nat44UdpCounters,
    /// Allocated mapping and peer slots; see [`Nat44UdpRuntime::occupancy`].
    mapping_occupancy: OccupancyCounter,
    peer_occupancy: OccupancyCounter,
    /// Mapping reuse lists; see [`UdpMappingList`].
    mapping_lists: UdpMappingLists,
    /// Peers of expired or recreated mappings, all reusable.
    stale_peers: u32,
    /// Peer slots at and after this index have never been used since the
    /// last flush; those before it are occupied.
    next_fresh_peer: usize,
    #[cfg(test)]
    reuse_visits: Cell<usize>,
    /// Lets a test fill a 65536-slot table without the O(N^2) full index
    /// validation after every commit.
    #[cfg(test)]
    skip_commit_validation: Cell<bool>,
    /// Peer slots written by the reuse-list bookkeeping (cost tests).
    #[cfg(test)]
    peer_link_writes: Cell<usize>,
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
            indexes.port_free_bits.len(),
            config.ports,
            mappings.len(),
        )
        .map_err(|_| Nat44UdpRuntimeConfigError::PortOwnerTableInvalid)?;
        HostTable::validate_config(&indexes.hosts, mappings.len(), HostTableKind::Members)
            .map_err(|_| Nat44UdpRuntimeConfigError::HostTableInvalid)?;
        if config.policy.per_host_accounting()
            && !mappings.is_empty()
            && indexes.hosts.hosts.is_empty()
        {
            return Err(Nat44UdpRuntimeConfigError::HostTableInvalid);
        }
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
            indexes.port_free_bits,
            config.ports,
            mappings.len(),
        )
        .expect("port owner dimensions were preflighted");
        let hosts = HostTable::new(indexes.hosts, hash_key.0, DirectoryHashDomain::UdpHost)
            .expect("host table dimensions were preflighted");
        mappings.fill(Nat44UdpMappingSlot::default());
        peers.fill(Nat44UdpPeerSlot::default());
        Ok(Self {
            config,
            mappings,
            peers,
            mapping_directory,
            peer_directory,
            port_owners,
            hosts,
            hash_key,
            ipv4_ids: Ipv4IdGenerator::new(hash_key.0),
            watermark_ms: None,
            next_generation: 1,
            runtime_epoch: 1,
            state_revision: 0,
            reconcile_binding,
            counters: Nat44UdpCounters::default(),
            mapping_occupancy: OccupancyCounter::default(),
            peer_occupancy: OccupancyCounter::default(),
            mapping_lists: UdpMappingLists::FLUSHED,
            stale_peers: LINK_NONE,
            next_fresh_peer: 0,
            #[cfg(test)]
            reuse_visits: Cell::new(0),
            #[cfg(test)]
            skip_commit_validation: Cell::new(false),
            #[cfg(test)]
            peer_link_writes: Cell::new(0),
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

    /// The ID of the next non-atomic datagram this runtime translates into
    /// the (source, destination, protocol) tuple (RFC 6864 §5.3.1,
    /// NAT44-126); the public address selects the direction's counters.
    pub(crate) fn next_ipv4_id(
        &mut self,
        source: [u8; 4],
        destination: [u8; 4],
        protocol: u8,
    ) -> u16 {
        let public = self.config.public_address().octets();
        self.ipv4_ids.next(source, destination, protocol, public)
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

    /// Exact allocated mapping and filter-peer slots and their high-water
    /// marks since construction or the last reconcile flush, in O(1).
    ///
    /// A slot counts from the outbound commit that first fills it until a
    /// reconcile flush. Expiry is lazy and an expired slot is reclaimed by
    /// overwriting it in place, so expired mappings and peers of expired or
    /// recreated mappings still count until a flush. Within one generation
    /// the counts therefore never decrease and equal the number of distinct
    /// slots used since the flush.
    #[must_use]
    pub fn occupancy(&self) -> Nat44UdpOccupancy {
        Nat44UdpOccupancy {
            mappings: self.mapping_occupancy.snapshot(self.mappings.len()),
            peers: self.peer_occupancy.snapshot(self.peers.len()),
        }
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
            port_bitmap_words: u32::try_from(port_free_bitmap_words(self.port_owners.slot_count()))
                .expect("validated port-owner count fits u32"),
            host_slots: u32::try_from(self.hosts.slot_count())
                .expect("validated host count fits u32"),
            host_buckets: u32::try_from(self.hosts.bucket_count())
                .expect("validated host bucket count fits u32"),
            host_nodes: u32::try_from(self.hosts.node_capacity())
                .expect("validated host node count fits u32"),
        }
    }

    #[cfg(test)]
    fn reset_index_probe_counts(&self) {
        self.mapping_lookup_probes.set(0);
        self.peer_lookup_probes.set(0);
        self.port_owner_probes.set(0);
        self.port_owners.take_bitmap_word_reads();
        self.take_reuse_visits();
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
            port_free_bitmap_words(self.port_owners.slot_count()),
            config.ports,
            self.mappings.len(),
        )
        .is_err()
        {
            return Err(Nat44UdpReconcileError::PortOwnerTableInvalid);
        }
        if config.policy.per_host_accounting() && !self.mappings.is_empty() && !self.hosts.enabled()
        {
            return Err(Nat44UdpReconcileError::HostTableMissing);
        }
        Ok(Nat44UdpReconcilePermit {
            runtime: self,
            config,
            hash_key,
            next_runtime_epoch,
            outcome: crate::StateCarryOutcome::FlushRequested,
        })
    }

    /// Why `config` cannot carry this runtime's state, if it cannot
    /// (RELOAD-CARRY); see [`Self::preflight_reconcile_carrying`].
    #[must_use]
    pub fn carry_conflict(&self, config: Nat44UdpConfig) -> Option<crate::StateCarryConflict> {
        self.config
            .carry_identity()
            .carry_conflict(config.carry_identity())
    }

    /// Preflights a successor that keeps this runtime's state when it can
    /// (RELOAD-CARRY).
    ///
    /// When [`Self::carry_conflict`] finds nothing, the permit carries: its
    /// commit only binds `config` and keeps every mapping, peer, index,
    /// port owner, per-host count, the hash key, the runtime epoch, and the
    /// clock watermark, in O(1). A shorter idle timeout and the rest of the
    /// policy then apply to carried state exactly as to new state: liveness
    /// is always the last activity plus the bound TTL, which only makes
    /// more mappings expired. A longer timeout or a lowered or new per-host
    /// limit is a conflict (it would revive parked or retired mappings, or
    /// never take effect for a churning host), so state that expired under
    /// the old policy never becomes live again. `hash_key` is not used by a
    /// carry; the old key stays secret and keeps keying the indexes.
    ///
    /// Otherwise this is [`Self::preflight_reconcile`] (flush and key
    /// rotation), reported as [`crate::StateCarryOutcome::FlushIncompatible`].
    pub fn preflight_reconcile_carrying<'runtime>(
        &'runtime mut self,
        config: Nat44UdpConfig,
        hash_key: Nat44UdpHashKey,
    ) -> Result<Nat44UdpReconcilePermit<'runtime, 'a>, Nat44UdpReconcileError> {
        if let Some(conflict) = self.carry_conflict(config) {
            let mut permit = self.preflight_reconcile(config, hash_key)?;
            permit.outcome = crate::StateCarryOutcome::FlushIncompatible(conflict);
            return Ok(permit);
        }
        if config.policy.per_host_accounting() && !self.mappings.is_empty() && !self.hosts.enabled()
        {
            return Err(Nat44UdpReconcileError::HostTableMissing);
        }
        let next_runtime_epoch = self.runtime_epoch;
        Ok(Nat44UdpReconcilePermit {
            runtime: self,
            config,
            hash_key,
            next_runtime_epoch,
            outcome: crate::StateCarryOutcome::Carried,
        })
    }

    fn commit_prevalidated_carry(&mut self, config: Nat44UdpConfig) -> Nat44UdpReconcileReport {
        let mappings_carried = self
            .mappings
            .iter()
            .filter(|mapping| mapping.occupied)
            .count();
        let peers_carried = self.peers.iter().filter(|peer| peer.occupied).count();
        self.config = config;
        self.counters.reconciliations = self.counters.reconciliations.saturating_add(1);
        Nat44UdpReconcileReport {
            mappings_flushed: 0,
            peers_flushed: 0,
            mappings_carried,
            peers_carried,
            outcome: crate::StateCarryOutcome::Carried,
        }
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
        self.mapping_lists = UdpMappingLists::FLUSHED;
        self.stale_peers = LINK_NONE;
        self.next_fresh_peer = 0;
        self.mapping_occupancy.flush();
        self.peer_occupancy.flush();
        self.mapping_directory.clear_with_key(hash_key.0);
        self.peer_directory.clear_with_key(hash_key.0);
        self.hosts.clear_with_key(hash_key.0);
        self.port_owners
            .reconfigure_prevalidated_and_clear(config.ports, self.mappings.len());
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
            mappings_carried: 0,
            peers_carried: 0,
            outcome: crate::StateCarryOutcome::FlushRequested,
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
        remote_port: u16,
        now_ms: u64,
    ) -> Result<Nat44UdpOutboundPlan, Nat44UdpPlanError> {
        self.observe_now(now_ms)?;
        self.plan_outbound_after_clock(
            internal_address,
            internal_port,
            remote_address,
            remote_port,
            now_ms,
        )
    }

    pub(crate) fn plan_outbound_read_only(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        now_ms: u64,
    ) -> Result<Nat44UdpOutboundPlan, Nat44UdpPlanError> {
        self.check_now_read_only(now_ms)?;
        self.plan_outbound_after_clock(
            internal_address,
            internal_port,
            remote_address,
            remote_port,
            now_ms,
        )
    }

    /// Port component of a peer filter key: the remote port only under
    /// address-and-port-dependent filtering. Endpoint-independent runtimes
    /// still record address-granular peers, which authorize only the
    /// read-only quoted ICMPv4 translation.
    const fn peer_key_port(&self, remote_port: u16) -> u16 {
        match self.config.policy.filtering {
            Nat44Filtering::AddressAndPortDependent => remote_port,
            Nat44Filtering::EndpointIndependent | Nat44Filtering::AddressDependent => 0,
        }
    }

    fn plan_outbound_after_clock(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        now_ms: u64,
    ) -> Result<Nat44UdpOutboundPlan, Nat44UdpPlanError> {
        if self.state_revision == u128::MAX {
            return Err(Nat44UdpPlanError::StateRevisionExhausted);
        }
        let remote_port = self.peer_key_port(remote_port);
        let exact_mapping = self.find_mapping(internal_address, internal_port)?;
        if let Some((mapping_index, mapping)) =
            exact_mapping.filter(|(_, mapping)| self.mapping_is_live(*mapping, now_ms))
        {
            if self.peer_exists(
                mapping_index,
                mapping.generation,
                remote_address,
                remote_port,
            )? {
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
                        host_peer_reclaim: UDP_INDEX_NONE,
                        prepared: PreparedNat44UdpOutboundCommit::EMPTY,
                    },
                    None,
                );
            }
            // A live mapping owns its port, so it counts toward its host.
            let host_peer_reclaim =
                self.host_peer_reclaim(self.hosts.mapping_host(mapping_index), now_ms)?;
            let Some((peer_index, _)) = self.find_reusable_peer(now_ms)? else {
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
                        remote_port,
                        next: LINK_NONE,
                    }),
                    mapping_created: false,
                    mapping_expired: false,
                    peer_created: true,
                    expected_runtime_epoch: self.runtime_epoch,
                    expected_revision: self.state_revision,
                    planned_now_ms: now_ms,
                    displaced_port_mapping_index: UDP_INDEX_NONE,
                    host_peer_reclaim: encode_optional_udp_index(host_peer_reclaim),
                    prepared: PreparedNat44UdpOutboundCommit::EMPTY,
                },
                None,
            );
        }

        let host = self
            .hosts
            .find(internal_address)
            .map_err(|_| Nat44UdpPlanError::IndexCorrupt)?;
        let quota_reclaim = self.host_quota_reclaim(exact_mapping, host, now_ms)?;
        // The new mapping carries a new peer (N6). A reclaimed slot of the
        // same host releases its peers in the commit as well, which only
        // lowers the count further.
        let host_peer_reclaim = self.host_peer_reclaim(host, now_ms)?;
        let mapping_index = if let Some((mapping_index, _)) = exact_mapping {
            mapping_index
        } else if let Some(reclaimed) = quota_reclaim {
            reclaimed
        } else if let Some(mapping_index) = self.find_reusable_mapping(now_ms) {
            mapping_index
        } else {
            return Err(Nat44UdpPlanError::MappingFull);
        };
        let Some((peer_index, _)) = self.find_reusable_peer(now_ms)? else {
            return Err(Nat44UdpPlanError::PeerFull);
        };
        let previous = exact_mapping.map(|(_, mapping)| mapping);
        let port = match (quota_reclaim, exact_mapping) {
            // A returning endpoint whose own mapping was retired keeps that
            // slot; the host's reclaimed mapping gives up its port.
            (Some(reclaimed), Some(_)) => self.reclaimed_port(reclaimed)?,
            // At the per-host limit the host's reclaimed slot gets a port by
            // the normal selection (N2 steps 1, 3, 4; another host's expired
            // mapping whose port it takes is retired), its own port if
            // every other one is live.
            (Some(reclaimed), None) => {
                match self.allocate_port(internal_address, internal_port, None, now_ms)? {
                    Some(port) => port,
                    None => self.reclaimed_port(reclaimed)?,
                }
            }
            (None, _) => {
                let Some(port) =
                    self.allocate_port(internal_address, internal_port, previous, now_ms)?
                else {
                    return Err(Nat44UdpPlanError::PortExhausted);
                };
                port
            }
        };
        // A new endpoint that takes the port of an expired mapping (port
        // preservation or a keyed takeover probe) recreates that mapping's
        // slot rather than the list head's, so no other port is released
        // in expiry order for the next new mapping to take (N2, NAT44-020).
        // A quota reclaim keeps the reclaimed slot so the host's count
        // stays exact.
        let mapping_index = match (exact_mapping, quota_reclaim, port.displaced_mapping_index) {
            (None, None, Some(displaced)) => displaced,
            _ => mapping_index,
        };
        // The commit recomputes the host slot from the same state; planning
        // it here fails closed on a corrupt host table before anything else.
        self.hosts
            .plan_assignment(
                internal_address,
                host,
                self.hosts.releasing_host(mapping_index),
            )
            .map_err(|_| Nat44UdpPlanError::IndexCorrupt)?;
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
                    link: UdpMappingLink::default(),
                },
                peer_index: encode_udp_index(peer_index),
                peer: Some(Nat44UdpPeerSlot {
                    occupied: true,
                    mapping_index,
                    mapping_generation: generation,
                    mapping_lifecycle_epoch: self.runtime_epoch,
                    remote_address,
                    remote_port,
                    next: LINK_NONE,
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
                host_peer_reclaim: encode_optional_udp_index(host_peer_reclaim),
                prepared: PreparedNat44UdpOutboundCommit::EMPTY,
            },
            port.expected_owner,
        )
    }

    /// The per-host peer limit check of a new peer for the internal address
    /// whose host slot is `host` (N6, NAT44-119), O(1): `Ok(None)` when the
    /// peer may be created as usual, `Ok(Some(slot))` when the address
    /// holds the limit and its least recently used mapping whose peers
    /// count (`slot`, the host's cursor) has expired (the commit stops
    /// counting that mapping's peers, which are dead with it), and
    /// `HostPeerQuotaExceeded` when it holds the limit on live mappings.
    ///
    /// The host's list is in activity order and one idle TTL applies; the
    /// mappings from the cursor on are exactly those whose peers count, so
    /// the cursor is expired exactly when one of them is: a live cursor
    /// means every counted peer belongs to a live mapping. A counted
    /// mapping is on the activity list and so has at least one peer, and
    /// the commit lowers the count by at least the one it adds.
    fn host_peer_reclaim(
        &self,
        host: Option<usize>,
        now_ms: u64,
    ) -> Result<Option<usize>, Nat44UdpPlanError> {
        let limit = usize::from(self.config.policy.peers_per_host);
        let Some(host) = host else {
            return Ok(None);
        };
        if limit == 0 || self.hosts.members(host) < limit {
            return Ok(None);
        }
        let cursor = self
            .hosts
            .cursor(host)
            .ok_or(Nat44UdpPlanError::IndexCorrupt)?;
        if self.mapping_is_live(self.mappings[cursor], now_ms) {
            return Err(Nat44UdpPlanError::HostPeerQuotaExceeded);
        }
        Ok(Some(cursor))
    }

    /// Whether `index` is still a mapping the commit may stop counting the
    /// peers of (N6): its host's cursor, on the activity list, and expired.
    fn host_peer_reclaim_matches(&self, index: usize, now_ms: u64) -> bool {
        self.hosts
            .mapping_host(index)
            .is_some_and(|host| self.hosts.cursor(host) == Some(index))
            && self.mappings[index].link.list == UdpMappingList::Lru
            && !self.mapping_is_live(self.mappings[index], now_ms)
    }

    /// Stops counting the peers of the expired mapping in slot `index`, its
    /// host's cursor (N6): it joins its host's uncounted prefix, still
    /// owning its port (so it still counts toward the mapping limit) and,
    /// until it is parked or reused, its dead peers. O(1); no-op for a
    /// mapping whose peers already do not count.
    fn uncount_host_peers(&mut self, index: usize) {
        self.hosts.uncount(index);
    }

    /// The per-host quota check of a new mapping for the internal address
    /// whose host slot is `host` (N3, NAT44-092), O(1): `Ok(None)` when the
    /// mapping may be created as usual, `Ok(Some(slot))` when the address
    /// holds the limit and its longest-idle mapping `slot` has expired (the
    /// new mapping takes over that slot), and
    /// `HostQuotaExceeded` when it holds the limit of live mappings.
    ///
    /// Recreating the endpoint's own expired, still-counted mapping in place
    /// never needs the check: the host's count stays the same. A host's
    /// list is in activity order and one idle TTL applies, so its head is
    /// expired exactly when one of its mappings is.
    fn host_quota_reclaim(
        &self,
        exact_mapping: Option<(usize, Nat44UdpMappingSlot)>,
        host: Option<usize>,
        now_ms: u64,
    ) -> Result<Option<usize>, Nat44UdpPlanError> {
        let limit = usize::from(self.config.policy.mappings_per_host);
        let Some(host) = host else {
            return Ok(None);
        };
        if limit == 0
            || self.hosts.count(host) < limit
            || exact_mapping.is_some_and(|(index, _)| self.hosts.mapping_host(index).is_some())
        {
            return Ok(None);
        }
        let head = self
            .hosts
            .head(host, 0)
            .ok_or(Nat44UdpPlanError::IndexCorrupt)?;
        if self.mapping_is_live(self.mappings[head], now_ms) {
            return Err(Nat44UdpPlanError::HostQuotaExceeded);
        }
        Ok(Some(head))
    }

    /// The port the reclaimed mapping in slot `reclaimed` owns, as a
    /// selection that moves it (N3).
    fn reclaimed_port(&self, reclaimed: usize) -> Result<Nat44UdpPortSelection, Nat44UdpPlanError> {
        let port = self.mappings[reclaimed].public_port;
        let owner = self
            .port_owners
            .owner(port)
            .map_err(|_| Nat44UdpPlanError::IndexCorrupt)?
            .filter(|owner| owner.state_index() == reclaimed)
            .ok_or(Nat44UdpPlanError::IndexCorrupt)?;
        Ok(Nat44UdpPortSelection {
            port,
            expected_owner: Some(owner),
            displaced_mapping_index: Some(reclaimed),
        })
    }

    /// The host slot of a new mapping for `address` that overwrites mapping
    /// slot `mapping_index` (N3) from the current state: the plan checks
    /// it, the revalidation checks it again, and the commit recomputes it
    /// before mutating anything, so all three agree.
    fn host_assignment(
        &self,
        mapping_index: usize,
        address: Ipv4Address,
    ) -> Result<Option<HostAssignment>, HostTableCorrupt> {
        let found = self.hosts.find(address)?;
        self.hosts
            .plan_assignment(address, found, self.hosts.releasing_host(mapping_index))
    }

    pub(crate) fn commit_outbound(
        &mut self,
        plan: Nat44UdpOutboundPlan,
        now_ms: u64,
    ) -> Result<(), Nat44UdpCommitError> {
        self.commit_outbound_counted(plan, now_ms, false)
    }

    /// Commits the outbound half of a hairpinned packet: exactly the state
    /// [`Self::commit_outbound`] commits for the same plan, without counting
    /// an outbound translation (the packet does not leave the inside realm).
    pub(crate) fn commit_hairpin_outbound(
        &mut self,
        plan: Nat44UdpOutboundPlan,
        now_ms: u64,
    ) -> Result<(), Nat44UdpCommitError> {
        self.commit_outbound_counted(plan, now_ms, true)
    }

    fn commit_outbound_counted(
        &mut self,
        plan: Nat44UdpOutboundPlan,
        now_ms: u64,
        hairpin: bool,
    ) -> Result<(), Nat44UdpCommitError> {
        let (peer_source, host_assignment) = self.revalidate_outbound_commit(plan, now_ms)?;
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
        // Reuse lists, each step O(1): take the planned peer slot, retire a
        // displaced port owner, then move the written mapping to the tail of
        // the activity list and chain the new peer to it.
        if let (Some(index), Some(source)) = (plan.peer_index(), peer_source) {
            self.take_peer_slot(index, source);
        }
        if let Some(index) = plan
            .displaced_port_mapping_index()
            .filter(|index| *index != plan.mapping_index())
        {
            self.mappings[index].port_owned = false;
            self.retire_mapping(index);
        }
        // Per-host peer limit (N6): the host's expired mapping stops
        // counting its dead peers, unless an earlier step already parked
        // or retired it or this commit recreates it.
        if let Some(index) = plan
            .host_peer_reclaim()
            .filter(|index| *index != plan.mapping_index())
        {
            self.uncount_host_peers(index);
        }
        let mapping_before = self.mappings[plan.mapping_index()].occupied;
        // Per-host lists (N3): a new mapping leaves the reclaimed slot's
        // host and joins its own host's tail; a refresh moves to the tail.
        if plan.mapping_created {
            self.hosts.detach(plan.mapping_index());
            self.write_mapping(plan.mapping_index(), plan.mapping);
            self.hosts.attach_new(
                plan.mapping_index(),
                host_assignment,
                plan.mapping.internal_address,
                0,
            );
        } else {
            self.write_mapping(plan.mapping_index(), plan.mapping);
            self.hosts.relist(plan.mapping_index(), 0);
        }
        self.mapping_occupancy
            .transition(mapping_before, plan.mapping.occupied);
        if let (Some(index), Some(peer)) = (plan.peer_index(), plan.peer) {
            let peer_before = self.peers[index].occupied;
            self.write_peer(plan.mapping_index(), index, peer);
            self.peer_occupancy.transition(peer_before, peer.occupied);
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
        if !hairpin {
            self.counters.outbound_translated = self.counters.outbound_translated.saturating_add(1);
        }
        debug_assert!(self.commit_validation_skipped() || self.validate_indexes().is_ok());
        Ok(())
    }

    pub(crate) fn plan_inbound(
        &mut self,
        public_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        now_ms: u64,
    ) -> Result<Nat44UdpInboundPlan, Nat44UdpPlanError> {
        self.observe_now(now_ms)?;
        self.plan_inbound_after_clock(public_port, remote_address, remote_port, now_ms)
    }

    pub(crate) fn plan_inbound_read_only(
        &self,
        public_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        now_ms: u64,
    ) -> Result<Nat44UdpInboundPlan, Nat44UdpPlanError> {
        self.check_now_read_only(now_ms)?;
        self.plan_inbound_after_clock(public_port, remote_address, remote_port, now_ms)
    }

    /// Inbound filter (RFC 4787 §5): a live mapping is required in every
    /// mode; address-dependent and address-and-port-dependent modes also
    /// require a recorded peer at their key granularity.
    fn plan_inbound_after_clock(
        &self,
        public_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        now_ms: u64,
    ) -> Result<Nat44UdpInboundPlan, Nat44UdpPlanError> {
        if self.state_revision == u128::MAX {
            return Err(Nat44UdpPlanError::StateRevisionExhausted);
        }
        let Some((mapping_index, mapping)) = self.mapping_for_public_port(public_port, now_ms)?
        else {
            return Err(Nat44UdpPlanError::MappingMiss);
        };
        if self.config.policy.filtering != Nat44Filtering::EndpointIndependent
            && !self.peer_exists(
                mapping_index,
                mapping.generation,
                remote_address,
                self.peer_key_port(remote_port),
            )?
        {
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
        self.commit_inbound_counted(plan, now_ms, false)
    }

    /// Commits the inbound half of a hairpinned packet, planned after its
    /// outbound half committed. Counts `hairpin_translated` instead of
    /// `inbound_translated`.
    pub(crate) fn commit_hairpin_inbound(
        &mut self,
        plan: Nat44UdpInboundPlan,
        now_ms: u64,
    ) -> Result<(), Nat44UdpCommitError> {
        self.commit_inbound_counted(plan, now_ms, true)
    }

    /// Read-only check that an outbound plan (ordinary or hairpin) would
    /// commit: the forwarding path calls it before rewriting the packet, so
    /// a stale or corrupt plan is a counted `NAT44_UDP_CONFIG_MISMATCH` drop
    /// instead of a commit failure.
    pub(crate) fn prevalidate_outbound_commit(
        &self,
        plan: Nat44UdpOutboundPlan,
        now_ms: u64,
    ) -> Result<(), Nat44UdpCommitError> {
        self.revalidate_outbound_commit(plan, now_ms).map(|_| ())
    }

    /// Read-only check that an inbound plan (ordinary or hairpin) would
    /// commit; see [`Self::prevalidate_outbound_commit`].
    pub(crate) fn prevalidate_inbound_commit(
        &self,
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
        if self.state_revision == u128::MAX {
            return Err(Nat44UdpCommitError::StateRevisionExhausted);
        }
        Ok(())
    }

    fn commit_inbound_counted(
        &mut self,
        plan: Nat44UdpInboundPlan,
        now_ms: u64,
        hairpin: bool,
    ) -> Result<(), Nat44UdpCommitError> {
        self.prevalidate_inbound_commit(plan, now_ms)?;
        let next_revision = self
            .state_revision
            .checked_add(1)
            .ok_or(Nat44UdpCommitError::StateRevisionExhausted)?;
        self.watermark_ms = Some(now_ms);
        self.state_revision = next_revision;
        if hairpin {
            self.counters.hairpin_translated = self.counters.hairpin_translated.saturating_add(1);
        } else {
            self.counters.inbound_translated = self.counters.inbound_translated.saturating_add(1);
        }
        debug_assert!(self.commit_validation_skipped() || self.validate_indexes().is_ok());
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
            Nat44UdpPlanError::HostQuotaExceeded => {
                self.counters.host_quota_exceeded =
                    self.counters.host_quota_exceeded.saturating_add(1);
            }
            Nat44UdpPlanError::HostPeerQuotaExceeded => {
                self.counters.host_peer_quota_exceeded =
                    self.counters.host_peer_quota_exceeded.saturating_add(1);
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

    pub(crate) fn record_hairpin_disabled(&mut self) {
        self.counters.hairpin_disabled = self.counters.hairpin_disabled.saturating_add(1);
    }

    pub(crate) fn record_hairpin_inbound_refused(&mut self) {
        self.counters.hairpin_inbound_refused =
            self.counters.hairpin_inbound_refused.saturating_add(1);
    }

    /// Read-only: does `public_port` belong to a live mapping? A hairpinned
    /// packet to an unknown public port commits nothing, not even its
    /// outbound half.
    pub(crate) fn hairpin_destination_is_live(
        &self,
        public_port: u16,
        now_ms: u64,
    ) -> Result<bool, Nat44UdpPlanError> {
        Ok(self.mapping_for_public_port(public_port, now_ms)?.is_some())
    }

    /// Read-only authority for a quoted outbound UDP packet. The quoted
    /// remote endpoint must match a recorded peer at the runtime's peer key
    /// granularity; endpoint-independent runtimes use address-granular peers
    /// here, so a looser inbound filter does not loosen ICMP authority.
    pub(crate) fn inspect_icmpv4(
        &self,
        public_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
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
        if !self.peer_exists(
            mapping_index,
            mapping.generation,
            remote_address,
            self.peer_key_port(remote_port),
        )? {
            return Err(Nat44UdpPlanError::FilterDenied);
        }
        Ok(Nat44UdpIcmpv4Lookup {
            internal_address: mapping.internal_address,
            internal_port: mapping.internal_port,
        })
    }

    /// Read-only authority for a quoted inbound UDP packet `remote ->
    /// internal` that an inside host received (RFC 5508 REQ-5, REQ-7). The
    /// internal endpoint must own a live mapping that still owns its public
    /// port, and the remote must match a recorded peer at the runtime's peer
    /// key granularity (address-granular under endpoint-independent
    /// filtering, as for [`Self::inspect_icmpv4`]). Returns the public port.
    pub(crate) fn inspect_icmpv4_inbound_quote(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        now_ms: u64,
    ) -> Result<u16, Nat44UdpPlanError> {
        self.check_now_read_only(now_ms)?;
        let Some((mapping_index, mapping)) = self.find_mapping(internal_address, internal_port)?
        else {
            return Err(Nat44UdpPlanError::MappingMiss);
        };
        // `port_owned` is the slot's ownership of its public port; the
        // port-owner index is kept consistent with it by every commit.
        if !self.mapping_is_live(mapping, now_ms) || !mapping.port_owned {
            return Err(Nat44UdpPlanError::MappingMiss);
        }
        if !self.peer_exists(
            mapping_index,
            mapping.generation,
            remote_address,
            self.peer_key_port(remote_port),
        )? {
            return Err(Nat44UdpPlanError::FilterDenied);
        }
        Ok(mapping.public_port)
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

    /// Checks that `plan` still applies to exactly the current state and
    /// returns where its new peer slot comes from and the host slot of a
    /// new mapping (N3), before anything mutates.
    #[allow(clippy::type_complexity)]
    fn revalidate_outbound_commit(
        &self,
        plan: Nat44UdpOutboundPlan,
        now_ms: u64,
    ) -> Result<(Option<UdpPeerSource>, Option<HostAssignment>), Nat44UdpCommitError> {
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
        // An unoccupied target mapping slot must be the lowest never-used
        // one; an occupied one must be on a list the commit can unlink from.
        let Some(target) = self.mappings.get(plan.mapping_index()).copied() else {
            return Err(Nat44UdpCommitError::IndexCorrupt);
        };
        if target.occupied == (target.link.list == UdpMappingList::Free)
            || (!target.occupied && plan.mapping_index() != self.mapping_lists.next_fresh)
        {
            return Err(Nat44UdpCommitError::IndexCorrupt);
        }
        let host = if plan.mapping_created {
            self.host_assignment(plan.mapping_index(), plan.mapping.internal_address)
                .map_err(|_| Nat44UdpCommitError::IndexCorrupt)?
        } else {
            None
        };
        if !plan
            .host_peer_reclaim()
            .is_none_or(|index| self.host_peer_reclaim_matches(index, now_ms))
        {
            return Err(Nat44UdpCommitError::IndexCorrupt);
        }
        let peer_source = plan
            .peer_index()
            .map(|index| {
                self.planned_peer_source(index, now_ms)
                    .ok_or(Nat44UdpCommitError::IndexCorrupt)
            })
            .transpose()?;
        Ok((peer_source, host))
    }

    /// Takes peer slot `index` off its source; O(1).
    fn take_peer_slot(&mut self, index: usize, source: UdpPeerSource) {
        match source {
            UdpPeerSource::ExpiredHead(head) => {
                self.park_mapping(head);
                self.pop_stale_peer(index);
            }
            UdpPeerSource::Stale => self.pop_stale_peer(index),
            UdpPeerSource::Fresh => {
                debug_assert!(self.next_fresh_peer == index);
                self.next_fresh_peer += 1;
            }
        }
    }

    #[cfg(test)]
    fn count_peer_link_write(&self) {
        self.peer_link_writes
            .set(self.peer_link_writes.get().saturating_add(1));
    }

    fn pop_stale_peer(&mut self, index: usize) {
        #[cfg(test)]
        self.count_peer_link_write();
        debug_assert!(self.stale_peers as usize == index);
        self.stale_peers = self.peers[index].next;
        self.peers[index].next = LINK_NONE;
    }

    /// Splices a whole peer chain onto the stale chain in O(1).
    fn release_peers(&mut self, chain: PeerChain) {
        if chain.head().is_some() {
            #[cfg(test)]
            self.count_peer_link_write();
            self.peers[chain.tail as usize].next = self.stale_peers;
            self.stale_peers = chain.head;
        }
    }

    fn move_mapping(&mut self, index: usize, to: UdpMappingList) {
        let from = self.mappings[index].link.list;
        self.mapping_lists.detach(self.mappings, index, from);
        self.mapping_lists.attach(self.mappings, index, to);
    }

    /// Moves the expired activity head to the parked list, releasing its
    /// peers to the stale chain; it keeps its public port.
    fn park_mapping(&mut self, index: usize) {
        debug_assert!(self.mappings[index].link.list == UdpMappingList::Lru);
        let peers = self.mappings[index].link.peers;
        self.release_peers(peers);
        self.mappings[index].link.peers = PeerChain::EMPTY;
        self.move_mapping(index, UdpMappingList::Parked);
        // A parked mapping's peers no longer count toward its host (N6): it
        // joins the host's uncounted prefix, unless its peers already
        // stopped counting at the host's peer limit.
        self.uncount_host_peers(index);
    }

    /// Moves an expired mapping that just lost its public port to the
    /// retired list, releasing any peers it still holds.
    fn retire_mapping(&mut self, index: usize) {
        let link = self.mappings[index].link;
        debug_assert!(matches!(
            link.list,
            UdpMappingList::Lru | UdpMappingList::Parked
        ));
        self.hosts.detach(index);
        self.release_peers(link.peers);
        self.mappings[index].link.peers = PeerChain::EMPTY;
        self.move_mapping(index, UdpMappingList::Retired);
    }

    /// Writes `mapping` (just stamped with the current time) into slot
    /// `index` and moves the slot to the tail of the activity list. A new
    /// generation releases the old generation's peers and starts an empty
    /// chain; a refresh keeps the chain.
    fn write_mapping(&mut self, index: usize, mapping: Nat44UdpMappingSlot) {
        let before = self.mappings[index];
        let recreated = !before.occupied
            || before.generation != mapping.generation
            || before.lifecycle_epoch != mapping.lifecycle_epoch;
        debug_assert!(recreated || before.link.list == UdpMappingList::Lru);
        debug_assert!(self
            .mapping_lists
            .lru
            .tail()
            .is_none_or(|tail| self.mappings[tail].last_outbound_ms <= mapping.last_outbound_ms));
        if recreated {
            self.release_peers(before.link.peers);
        }
        self.mapping_lists
            .detach(self.mappings, index, before.link.list);
        self.mappings[index] = Nat44UdpMappingSlot {
            link: UdpMappingLink {
                links: SlotLinks::UNLINKED,
                list: UdpMappingList::Free,
                peers: if recreated {
                    PeerChain::EMPTY
                } else {
                    before.link.peers
                },
            },
            ..mapping
        };
        self.mapping_lists
            .attach(self.mappings, index, UdpMappingList::Lru);
    }

    /// Writes `peer` into slot `index` (already taken off its source) and
    /// appends it to the chain of mapping `mapping_index`.
    fn write_peer(&mut self, mapping_index: usize, index: usize, peer: Nat44UdpPeerSlot) {
        self.peers[index] = Nat44UdpPeerSlot {
            next: LINK_NONE,
            ..peer
        };
        let link = encode_udp_index(index);
        let chain = self.mappings[mapping_index].link.peers;
        // The new peer counts toward the mapping's host (N6).
        debug_assert!(!self.hosts.enabled() || self.hosts.mapping_list(mapping_index) == Some(0));
        self.hosts.add_member(mapping_index);
        #[cfg(test)]
        self.count_peer_link_write();
        if chain.head().is_none() {
            self.mappings[mapping_index].link.peers = PeerChain {
                head: link,
                tail: link,
            };
        } else {
            #[cfg(test)]
            self.count_peer_link_write();
            self.peers[chain.tail as usize].next = link;
            self.mappings[mapping_index].link.peers.tail = link;
        }
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

    /// The key port shares the address word, so address-granular keys (port
    /// zero) hash exactly as before the port component existed.
    const fn peer_lookup_words(
        mapping_index: usize,
        mapping_generation: u64,
        lifecycle_epoch: u128,
        remote_address: Ipv4Address,
        remote_port: u16,
    ) -> [u64; 5] {
        [
            mapping_index as u64,
            mapping_generation,
            (lifecycle_epoch >> 64) as u64,
            lifecycle_epoch as u64,
            (u32::from_be_bytes(remote_address.octets()) as u64) | ((remote_port as u64) << 32),
        ]
    }

    const fn peer_words(peer: Nat44UdpPeerSlot) -> [u64; 5] {
        Self::peer_lookup_words(
            peer.mapping_index,
            peer.mapping_generation,
            peer.mapping_lifecycle_epoch,
            peer.remote_address,
            peer.remote_port,
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
                    && other.remote_port == peer.remote_port
            }) {
                return Err(Nat44UdpIndexInvariantError::DuplicatePeerKey);
            }
        }
        if !self.reuse_lists_are_consistent() {
            return Err(Nat44UdpIndexInvariantError::ReuseLists);
        }
        // A host's list holds its port-owning mappings in activity order:
        // first those whose peers no longer count (every parked mapping and
        // expired ones uncounted at the peer limit), then from the cursor
        // on those whose peers count (every live one), each contributing
        // its chain length.
        if !self.hosts.validate(hash_key, self.mappings.len(), |index| {
            let mapping = self.mappings[index];
            (mapping.occupied && mapping.port_owned).then(|| {
                let live = self
                    .watermark_ms
                    .is_some_and(|now_ms| self.mapping_is_live(mapping, now_ms));
                let counted = if mapping.link.list == UdpMappingList::Parked {
                    Some(false)
                } else if live {
                    Some(true)
                } else {
                    None
                };
                let peers = self
                    .walk_peer_chain(mapping.link.peers.head, |_| true)
                    .map_or(u32::MAX, |(length, _)| {
                        u32::try_from(length).unwrap_or(u32::MAX)
                    });
                HostExpectation {
                    address: mapping.internal_address,
                    list: 0,
                    order: mapping.last_outbound_ms,
                    members: Some(peers),
                    counted,
                }
            })
        }) {
            return Err(Nat44UdpIndexInvariantError::Hosts);
        }
        Ok(())
    }

    /// Exact O(M + P) check of the reuse sets (validation only, no
    /// allocation): the fresh slots are exactly the default slots at and
    /// after the fresh boundary, the three mapping lists hold every other
    /// slot, each slot's recorded set and state agree, the activity list is
    /// in `last_outbound_ms` order, parked and retired mappings are expired,
    /// and every occupied peer is on exactly one chain: its mapping's if
    /// that mapping is on the activity list with the peer's generation,
    /// else the stale chain. Chains of different mappings cannot share a
    /// node (each node matches one mapping key) and the stale chain holds
    /// no node that matches an active mapping, so with every walk bounded
    /// and ending at its tail, equal totals mean each occupied peer is
    /// chained exactly once.
    fn reuse_lists_are_consistent(&self) -> bool {
        let lists = self.mapping_lists;
        let expired_at_watermark = |mapping: Nat44UdpMappingSlot| {
            self.watermark_ms
                .is_none_or(|now_ms| !self.mapping_is_live(mapping, now_ms))
        };
        let Some(fresh) = self.mappings.get(lists.next_fresh..) else {
            return false;
        };
        if fresh
            .iter()
            .any(|mapping| *mapping != Nat44UdpMappingSlot::default())
            || self.mappings[..lists.next_fresh]
                .iter()
                .any(|mapping| !mapping.occupied)
        {
            return false;
        }
        let mut listed = fresh.len();
        for (header, list) in [
            (lists.lru, UdpMappingList::Lru),
            (lists.parked, UdpMappingList::Parked),
            (lists.retired, UdpMappingList::Retired),
        ] {
            let mut previous_ms = 0;
            let consistent = header.validate(self.mappings, |index| {
                listed += 1;
                let mapping = self.mappings[index];
                let has_peers = mapping.link.peers.head().is_some();
                let ordered = previous_ms <= mapping.last_outbound_ms;
                previous_ms = mapping.last_outbound_ms;
                mapping.link.list == list
                    && match list {
                        UdpMappingList::Free => false,
                        UdpMappingList::Lru => {
                            mapping.occupied && mapping.port_owned && has_peers && ordered
                        }
                        UdpMappingList::Parked => {
                            mapping.occupied
                                && mapping.port_owned
                                && !has_peers
                                && expired_at_watermark(mapping)
                        }
                        UdpMappingList::Retired => {
                            mapping.occupied
                                && !mapping.port_owned
                                && !has_peers
                                && expired_at_watermark(mapping)
                        }
                    }
            });
            if !consistent {
                return false;
            }
        }
        if listed != self.mappings.len() || self.next_fresh_peer > self.peers.len() {
            return false;
        }
        let occupied_peers = self.peers.iter().filter(|peer| peer.occupied).count();
        if occupied_peers != self.next_fresh_peer
            || self.peers[..self.next_fresh_peer]
                .iter()
                .any(|peer| !peer.occupied)
        {
            return false;
        }
        let active_owner = |peer: Nat44UdpPeerSlot| {
            self.mappings
                .get(peer.mapping_index)
                .is_some_and(|mapping| {
                    mapping.link.list == UdpMappingList::Lru
                        && mapping.generation == peer.mapping_generation
                        && mapping.lifecycle_epoch == peer.mapping_lifecycle_epoch
                })
        };
        let mut chained = 0_usize;
        let mut chains_consistent = true;
        lists.lru.validate(self.mappings, |index| {
            let mapping = self.mappings[index];
            let belongs = |peer: Nat44UdpPeerSlot| {
                peer.mapping_index == index
                    && peer.mapping_generation == mapping.generation
                    && peer.mapping_lifecycle_epoch == mapping.lifecycle_epoch
            };
            match self.walk_peer_chain(mapping.link.peers.head, belongs) {
                Some((length, last)) if last == mapping.link.peers.tail => chained += length,
                _ => chains_consistent = false,
            }
            chains_consistent
        });
        let stale = self.walk_peer_chain(self.stale_peers, |peer| !active_owner(peer));
        chains_consistent && stale.is_some_and(|(length, _)| chained + length == occupied_peers)
    }

    /// Walks one peer chain from `head` for at most every peer slot and
    /// returns its length and last node, or `None` on a node that is
    /// unoccupied, does not `belong`, or past the bound (validation only).
    fn walk_peer_chain(
        &self,
        head: u32,
        belongs: impl Fn(Nat44UdpPeerSlot) -> bool,
    ) -> Option<(usize, u32)> {
        let mut current = head;
        let mut last = LINK_NONE;
        let mut length = 0_usize;
        while current != LINK_NONE {
            let peer = *self.peers.get(current as usize)?;
            if length == self.peers.len() || !peer.occupied || !belongs(peer) {
                return None;
            }
            length += 1;
            last = current;
            current = peer.next;
        }
        Some((length, last))
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

    #[cfg(test)]
    fn count_reuse_visit(&self) {
        self.reuse_visits
            .set(self.reuse_visits.get().saturating_add(1));
    }

    #[cfg(test)]
    fn take_reuse_visits(&self) -> usize {
        self.reuse_visits.replace(0)
    }

    #[cfg(test)]
    fn commit_validation_skipped(&self) -> bool {
        self.skip_commit_validation.get()
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self)]
    const fn commit_validation_skipped(&self) -> bool {
        false
    }

    /// The head of the activity list when it is expired: the oldest mapping
    /// that still owns its port and peers. One liveness check.
    fn expired_activity_head(&self, now_ms: u64) -> Option<usize> {
        #[cfg(test)]
        self.count_reuse_visit();
        let head = self.mapping_lists.lru.head()?;
        (!self.mapping_is_live(self.mappings[head], now_ms)).then_some(head)
    }

    /// A reusable (unoccupied or expired) mapping slot in O(1), or `None`
    /// exactly when every slot holds a live mapping. Expired slots are
    /// preferred over never-used ones, as before, so occupancy keeps
    /// counting the distinct slots used since the flush.
    fn find_reusable_mapping(&self, now_ms: u64) -> Option<usize> {
        self.mapping_lists
            .retired
            .head()
            .or_else(|| self.mapping_lists.parked.head())
            .or_else(|| self.expired_activity_head(now_ms))
            .or_else(|| self.mapping_lists.fresh(self.mappings.len()))
    }

    fn peer_exists(
        &self,
        mapping_index: usize,
        mapping_generation: u64,
        remote_address: Ipv4Address,
        remote_port: u16,
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
            remote_port,
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
                    && peer.remote_port == remote_port
            })
            .map_err(|_| Nat44UdpPlanError::IndexCorrupt)?;
        #[cfg(test)]
        self.peer_lookup_probes
            .set(self.peer_lookup_probes.get().saturating_add(probe.probes));
        Ok(probe.state_index.is_some())
    }

    /// A reusable peer slot in O(1), with where it comes from, or `None`
    /// exactly when every peer belongs to a live mapping: a peer of an
    /// expired or recreated mapping (stale chain, then the peers of the
    /// expired activity head), else a never-used slot.
    fn find_reusable_peer(
        &self,
        now_ms: u64,
    ) -> Result<Option<(usize, UdpPeerSource)>, Nat44UdpPlanError> {
        if self.stale_peers != LINK_NONE {
            return Ok(Some((self.stale_peers as usize, UdpPeerSource::Stale)));
        }
        if let Some(head) = self.expired_activity_head(now_ms) {
            // Every mapping on the activity list has at least one peer.
            let peer = self.mappings[head]
                .link
                .peers
                .head()
                .ok_or(Nat44UdpPlanError::IndexCorrupt)?;
            return Ok(Some((peer, UdpPeerSource::ExpiredHead(head))));
        }
        Ok((self.next_fresh_peer < self.peers.len())
            .then_some((self.next_fresh_peer, UdpPeerSource::Fresh)))
    }

    /// The source of `peer_index` that [`Self::find_reusable_peer`] reports
    /// in the current state, if it would choose exactly that slot.
    fn planned_peer_source(&self, peer_index: usize, now_ms: u64) -> Option<UdpPeerSource> {
        match self.find_reusable_peer(now_ms) {
            Ok(Some((index, source))) if index == peer_index => Some(source),
            _ => None,
        }
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

    /// Keyed port selection of this runtime ([`PortSelectionKey`]).
    const fn port_selection_key(&self) -> PortSelectionKey {
        PortSelectionKey {
            key: self.hash_key.0,
            start_domain: DirectoryHashDomain::UdpPortStart,
            takeover_domain: DirectoryHashDomain::UdpPortTakeover,
            ports: self.config.ports,
            inside: self.config.inside,
            public_address: self.config.public_address,
            allocator_seed: self.config.policy.allocator_seed,
        }
    }

    /// Public port of a new mapping (NAT44-004, NAT44-068, NAT44-020), in
    /// bounded work (at most 12 owner checks and 34 bitmap words):
    ///
    /// 1. with port preservation on (the default), the internal port, if in
    ///    the pool and unowned or owned by an expired mapping;
    /// 2. the port the same internal endpoint's expired mapping
    ///    (`previous`, recreated in place) still owns, so a returning
    ///    endpoint keeps its public port;
    /// 3. the first unowned port from a keyed start
    ///    ([`PortSelectionKey::search_start`], RFC 6056 Algorithm 3 with
    ///    the secret hash key and without the remote endpoint), found by the
    ///    free-port bitmap in at most 34 word reads;
    /// 4. with every port owned, the port of an expired owner among
    ///    [`NAT44_PORT_TAKEOVER_PROBES`] keyed pseudorandom pool ports
    ///    ([`PortSelectionKey::takeover_port`]), else the port of the
    ///    parked mapping or the expired activity head (expiry order).
    ///
    /// Step 3 prefers an unowned port over any expired-owned one. `None`
    /// only when every port has a live owner.
    fn allocate_port(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
        previous: Option<Nat44UdpMappingSlot>,
        now_ms: u64,
    ) -> Result<Option<Nat44UdpPortSelection>, Nat44UdpPlanError> {
        if self.config.policy.port_preservation && self.config.ports.contains(internal_port) {
            if let Some(selection) = self.select_port(internal_port, now_ms)? {
                return Ok(Some(selection));
            }
        }
        if let Some(previous) = previous.filter(|mapping| mapping.occupied && mapping.port_owned) {
            if let Some(selection) = self.select_port(previous.public_port, now_ms)? {
                return Ok(Some(selection));
            }
        }
        let key = self.port_selection_key();
        // The first unowned port from the keyed start.
        if let Some(port) = self
            .port_owners
            .first_unowned_port_from(key.search_start(internal_address, internal_port))
        {
            return self.select_port(port, now_ms);
        }
        // Every port has an owner: keyed probes for an expired owner, then
        // the port of an expired mapping in expiry order, a parked mapping
        // first, else the expired activity head.
        for probe in 0..NAT44_PORT_TAKEOVER_PROBES {
            let port = key.takeover_port(
                internal_address,
                internal_port,
                self.next_generation,
                now_ms,
                probe,
            );
            if let Some(selection) = self.select_port(port, now_ms)? {
                return Ok(Some(selection));
            }
        }
        for candidate in [
            self.mapping_lists.parked.head(),
            self.expired_activity_head(now_ms),
        ]
        .into_iter()
        .flatten()
        {
            let mapping = self.mappings[candidate];
            if !mapping.port_owned {
                return Err(Nat44UdpPlanError::IndexCorrupt);
            }
            if let Some(selection) = self.select_port(mapping.public_port, now_ms)? {
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

/// Keyed pseudorandom pool ports that step 4 of the public-port selection
/// probes for an expired owner when every pool port has an owner, before
/// it falls back to the expiry-ordered list heads (N2, NAT44-020). Each
/// probe is one O(1) owner check.
pub const NAT44_PORT_TAKEOVER_PROBES: usize = 8;

/// Keyed public-port selection of one NAT44 protocol (N2, NAT44-020): the
/// secret is the runtime's hash key (fresh from the key source and rotated
/// by every reconcile), and each protocol uses its own hash domains.
#[derive(Clone, Copy)]
struct PortSelectionKey {
    key: DirectoryHashKey,
    start_domain: DirectoryHashDomain,
    takeover_domain: DirectoryHashDomain,
    ports: crate::PortSet,
    /// Inside interface, public address, and allocator seed; the internal
    /// endpoint completes [`Self::endpoint_words`].
    inside: IfId,
    public_address: Ipv4Address,
    allocator_seed: u64,
}

impl PortSelectionKey {
    /// Hash input of one internal endpoint: RFC 6056 Algorithm 3's `F()`
    /// with the remote endpoint left out, because an endpoint-independent
    /// mapping (RFC 4787 REQ-1, RFC 5382 REQ-1) must not depend on it. The
    /// configured allocator seed is mixed in as an operator salt only; the
    /// secret is the hash key.
    const fn endpoint_words(self, internal_address: Ipv4Address, internal_port: u16) -> [u64; 5] {
        [
            self.inside.0 as u64,
            u32::from_be_bytes(self.public_address.octets()) as u64,
            u32::from_be_bytes(internal_address.octets()) as u64,
            internal_port as u64,
            self.allocator_seed,
        ]
    }

    /// `hash % pool`. The pool has at most 65535 ports, so the modulo bias
    /// of the 64-bit hash is below 2^-47.
    fn pool_offset(self, domain: DirectoryHashDomain, words: &[u64]) -> usize {
        let pool_size = self.ports.count() as u64;
        usize::try_from(self.key.hash_words(domain, words) % pool_size)
            .expect("a pool offset fits usize")
    }

    /// Pool offset where the search for an unowned port starts (step 3): a
    /// keyed SipHash of the internal endpoint, fixed for the endpoint
    /// within one generation (so a returning endpoint finds its earlier
    /// port first while it is still free) and unpredictable without the
    /// key.
    fn search_start(self, internal_address: Ipv4Address, internal_port: u16) -> usize {
        self.pool_offset(
            self.start_domain,
            &self.endpoint_words(internal_address, internal_port),
        )
    }

    /// Pool port of takeover probe `probe` (step 4) for the mapping
    /// generation `generation` (distinct for every mapping a runtime
    /// creates between flushes) at `now_ms`, so which expired owner gives
    /// up its port is not predictable without the key. The generation
    /// advances only when a plan commits, so a plan that is discarded (a
    /// read-only plan, or one refused at commit) and rebuilt at the same
    /// time probes the same ports; one rebuilt at a later time probes
    /// others.
    fn takeover_port(
        self,
        internal_address: Ipv4Address,
        internal_port: u16,
        generation: u64,
        now_ms: u64,
        probe: usize,
    ) -> u16 {
        let [inside, public, address, port, seed] =
            self.endpoint_words(internal_address, internal_port);
        let offset = self.pool_offset(
            self.takeover_domain,
            &[
                inside,
                public,
                address,
                port,
                seed,
                generation,
                now_ms,
                probe as u64,
            ],
        );
        self.ports.port(offset)
    }
}

fn address_is_host_unicast(snapshot: &ForwardingSnapshot<'_>, address: Ipv4Address) -> bool {
    let octets = address.octets();
    if octets[0] == 0 || octets[0] == 127 || octets[0] >= 224 || octets == [255; 4] {
        return false;
    }
    !snapshot.route_lookup(address).is_some_and(|selected| {
        selected.is_connected_network_address(address)
            || selected.is_connected_directed_broadcast(address)
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

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Nat44TcpPolicy {
    idle_ttl_ms: u64,
    opening_idle_ttl_ms: u64,
    closing_idle_ttl_ms: u64,
    allocator_seed: u64,
    icmpv4_errors: Nat44Icmpv4ErrorPolicy,
    filtering: Nat44Filtering,
    hairpinning: bool,
    inbound_sessions_per_remote: u8,
    unsolicited_syn_icmp: bool,
    inbound_rst: Nat44TcpInboundRst,
    port_preservation: bool,
    mappings_per_host: u16,
    sessions_per_host: u16,
}

impl std::fmt::Debug for Nat44TcpPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Nat44TcpPolicy")
            .field("idle_ttl_ms", &self.idle_ttl_ms)
            .field("opening_idle_ttl_ms", &self.opening_idle_ttl_ms)
            .field("closing_idle_ttl_ms", &self.closing_idle_ttl_ms)
            .field("allocator_seed", &Redacted)
            .field("icmpv4_errors", &self.icmpv4_errors)
            .field("filtering", &self.filtering)
            .field("hairpinning", &self.hairpinning)
            .field(
                "inbound_sessions_per_remote",
                &self.inbound_sessions_per_remote,
            )
            .field("unsolicited_syn_icmp", &self.unsolicited_syn_icmp)
            .field("inbound_rst", &self.inbound_rst)
            .field("port_preservation", &self.port_preservation)
            .field("mappings_per_host", &self.mappings_per_host)
            .field("sessions_per_host", &self.sessions_per_host)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44TcpPolicyError {
    IdleTtlTooShort,
    IdleTtlTooLong,
    /// An opening or closing (transitory) idle timeout below
    /// [`NAT44_TCP_MIN_TRANSITORY_IDLE_TTL_MS`] (RFC 5382 REQ-5).
    TransitoryIdleTtlTooShort,
    /// An opening or closing idle timeout above the established idle
    /// timeout ([`Nat44TcpPolicy::idle_ttl_ms`]).
    TransitoryIdleTtlAboveEstablished,
    /// A finite per-remote inbound session limit above
    /// [`NAT44_TCP_MAX_INBOUND_SESSIONS_PER_REMOTE`].
    InboundSessionsPerRemoteTooLarge,
}

impl Nat44TcpPolicy {
    /// (established, opening, closing) idle timeouts, which TCP state
    /// needs unchanged to carry across a publication (RELOAD-CARRY).
    #[must_use]
    pub const fn carry_timers(self) -> [u64; 3] {
        [
            self.idle_ttl_ms,
            self.opening_idle_ttl_ms,
            self.closing_idle_ttl_ms,
        ]
    }

    /// A policy with established connection idle timeout `idle_ttl_ms`
    /// (RFC 5382 REQ-5: at least [`NAT44_TCP_MIN_IDLE_TTL_MS`], 2h4m) and
    /// the default opening and closing idle timeouts
    /// ([`NAT44_TCP_DEFAULT_TRANSITORY_IDLE_TTL_MS`], 4 minutes).
    ///
    /// # Errors
    ///
    /// [`Nat44TcpPolicyError::IdleTtlTooShort`] or
    /// [`Nat44TcpPolicyError::IdleTtlTooLong`] outside
    /// [`NAT44_TCP_MIN_IDLE_TTL_MS`]..=[`NAT44_TCP_MAX_IDLE_TTL_MS`].
    pub const fn new(idle_ttl_ms: u64, allocator_seed: u64) -> Result<Self, Nat44TcpPolicyError> {
        if idle_ttl_ms < NAT44_TCP_MIN_IDLE_TTL_MS {
            return Err(Nat44TcpPolicyError::IdleTtlTooShort);
        }
        if idle_ttl_ms > NAT44_TCP_MAX_IDLE_TTL_MS {
            return Err(Nat44TcpPolicyError::IdleTtlTooLong);
        }
        Ok(Self {
            idle_ttl_ms,
            opening_idle_ttl_ms: NAT44_TCP_DEFAULT_TRANSITORY_IDLE_TTL_MS,
            closing_idle_ttl_ms: NAT44_TCP_DEFAULT_TRANSITORY_IDLE_TTL_MS,
            allocator_seed,
            icmpv4_errors: Nat44Icmpv4ErrorPolicy::Bidirectional,
            filtering: Nat44Filtering::AddressDependent,
            hairpinning: true,
            inbound_sessions_per_remote: NAT44_TCP_DEFAULT_INBOUND_SESSIONS_PER_REMOTE,
            unsolicited_syn_icmp: true,
            inbound_rst: Nat44TcpInboundRst::Closing,
            port_preservation: true,
            mappings_per_host: NAT44_DEFAULT_MAPPINGS_PER_HOST,
            sessions_per_host: NAT44_DEFAULT_STATE_PER_HOST,
        })
    }

    /// The established connection idle timeout (RFC 5382 REQ-5).
    #[must_use]
    pub const fn idle_ttl_ms(self) -> u64 {
        self.idle_ttl_ms
    }

    /// Sets the opening (partially open phase) idle timeout, one of RFC
    /// 5382's transitory connection idle-timeouts; RFC 7857 §2.1 asks for
    /// the opening and closing timeouts to be configurable separately.
    ///
    /// # Errors
    ///
    /// [`Nat44TcpPolicyError::TransitoryIdleTtlTooShort`] below
    /// [`NAT44_TCP_MIN_TRANSITORY_IDLE_TTL_MS`] (REQ-5 MUST);
    /// [`Nat44TcpPolicyError::TransitoryIdleTtlAboveEstablished`] above
    /// [`Self::idle_ttl_ms`].
    pub const fn with_opening_idle_ttl_ms(
        mut self,
        ttl_ms: u64,
    ) -> Result<Self, Nat44TcpPolicyError> {
        match self.check_transitory(ttl_ms) {
            Ok(()) => {
                self.opening_idle_ttl_ms = ttl_ms;
                Ok(self)
            }
            Err(error) => Err(error),
        }
    }

    /// Sets the closing idle timeout (FIN in both directions, or after a
    /// RST, RFC 7857 §2.2), the other transitory connection idle-timeout.
    ///
    /// # Errors
    ///
    /// As [`Self::with_opening_idle_ttl_ms`].
    pub const fn with_closing_idle_ttl_ms(
        mut self,
        ttl_ms: u64,
    ) -> Result<Self, Nat44TcpPolicyError> {
        match self.check_transitory(ttl_ms) {
            Ok(()) => {
                self.closing_idle_ttl_ms = ttl_ms;
                Ok(self)
            }
            Err(error) => Err(error),
        }
    }

    const fn check_transitory(self, ttl_ms: u64) -> Result<(), Nat44TcpPolicyError> {
        if ttl_ms < NAT44_TCP_MIN_TRANSITORY_IDLE_TTL_MS {
            Err(Nat44TcpPolicyError::TransitoryIdleTtlTooShort)
        } else if ttl_ms > self.idle_ttl_ms {
            Err(Nat44TcpPolicyError::TransitoryIdleTtlAboveEstablished)
        } else {
            Ok(())
        }
    }

    /// The opening (partially open phase) idle timeout.
    #[must_use]
    pub const fn opening_idle_ttl_ms(self) -> u64 {
        self.opening_idle_ttl_ms
    }

    /// The closing idle timeout.
    #[must_use]
    pub const fn closing_idle_ttl_ms(self) -> u64 {
        self.closing_idle_ttl_ms
    }

    /// The idle timeout of a session in `phase`.
    #[must_use]
    pub const fn session_idle_ttl_ms(self, phase: Nat44TcpSessionPhase) -> u64 {
        match phase {
            Nat44TcpSessionPhase::Opening => self.opening_idle_ttl_ms,
            Nat44TcpSessionPhase::Established => self.idle_ttl_ms,
            Nat44TcpSessionPhase::Closing => self.closing_idle_ttl_ms,
        }
    }

    /// The longer transitory timeout: a mapping without an established
    /// session lives this long after its last activity.
    const fn transitory_bound_ms(self) -> u64 {
        if self.opening_idle_ttl_ms > self.closing_idle_ttl_ms {
            self.opening_idle_ttl_ms
        } else {
            self.closing_idle_ttl_ms
        }
    }

    #[must_use]
    pub const fn allocator_seed(self) -> u64 {
        self.allocator_seed
    }

    /// Enables or disables port preservation, the first step of the
    /// public-port selection: a new mapping keeps the internal port when it
    /// is in the pool and has no live owner (RFC 4787 §4.2.1). The default
    /// `true` is the port-preserving NAPT of RFC 6056 §4 and RFC 7857 §9,
    /// which obfuscate the public port only when it must change; `false`
    /// always selects an obfuscated port (RFC 6056 §4, NAPT without port
    /// preservation), so the public port does not repeat a host's own,
    /// possibly predictable, source port.
    #[must_use]
    pub const fn with_port_preservation(mut self, enabled: bool) -> Self {
        self.port_preservation = enabled;
        self
    }

    #[must_use]
    pub const fn port_preservation(self) -> bool {
        self.port_preservation
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

    /// Selects the inbound filtering behavior. The default is
    /// [`Nat44Filtering::AddressDependent`].
    #[must_use]
    pub const fn with_filtering(mut self, filtering: Nat44Filtering) -> Self {
        self.filtering = filtering;
        self
    }

    #[must_use]
    pub const fn filtering(self) -> Nat44Filtering {
        self.filtering
    }

    /// Enables or disables hairpinning: an inside host addressing the
    /// public address and port of a live mapping is translated back into
    /// the inside realm with the external source address and port of its own
    /// mapping (RFC 4787 REQ-9, REQ-9 a for UDP; RFC 5382 REQ-8 for TCP).
    /// The default `true` conforms to those MUSTs; `false` is an RFC 1812
    /// §1.1.3 security option that drops such packets before any NAT,
    /// firewall, or resolution state changes.
    #[must_use]
    pub const fn with_hairpinning(mut self, enabled: bool) -> Self {
        self.hairpinning = enabled;
        self
    }

    #[must_use]
    pub const fn hairpinning(self) -> bool {
        self.hairpinning
    }

    /// Limits the live sessions that external inbound initial SYNs may
    /// create on one mapping from one remote IPv4 address (any remote port).
    /// `0` means no limit and is the default
    /// ([`NAT44_TCP_DEFAULT_INBOUND_SESSIONS_PER_REMOTE`]).
    ///
    /// This is an opt-in local security policy against session-table
    /// exhaustion by spoofed SYNs. RFC 5382 §9 notes that address-dependent
    /// filtering does not fully protect against attackers sharing the
    /// remote's IP address behind a remote NAT, and that a NAT may check
    /// liveness or use more conservative timeouts against resource attacks;
    /// it does not address spoofing, and no REQ of RFC 5382 or RFC 4787
    /// requires admitting every filtered-in SYN. The limit is fixed by
    /// configuration, not adaptive, so the device stays deterministic
    /// (RFC 4787 §13).
    ///
    /// A closed or reset connection keeps counting until its session
    /// expires on the closing idle timeout, and a SYN the remote never
    /// completes until the opening idle timeout. The count is taken over at most
    /// [`NAT44_TCP_INBOUND_SLOT_PROBES`] remote-address chain nodes, which
    /// also hold the outbound-created sessions of the same mapping and
    /// remote; those reduce the effective limit, and a longer chain refuses
    /// (fails closed) even where address-dependent filtering alone would
    /// admit. The maximum of 16 is therefore nominal.
    /// Sessions created by outbound segments are never
    /// limited or counted, and neither are hairpinned inbound halves: their
    /// remote is the NAT's own public address, which every inside host
    /// shares and an outside sender cannot use. A SYN over the limit is
    /// dropped without creating state and without evicting a live session.
    ///
    /// # Errors
    ///
    /// [`Nat44TcpPolicyError::InboundSessionsPerRemoteTooLarge`] above
    /// [`NAT44_TCP_MAX_INBOUND_SESSIONS_PER_REMOTE`].
    pub const fn with_inbound_sessions_per_remote(
        mut self,
        limit: u8,
    ) -> Result<Self, Nat44TcpPolicyError> {
        if limit > NAT44_TCP_MAX_INBOUND_SESSIONS_PER_REMOTE {
            return Err(Nat44TcpPolicyError::InboundSessionsPerRemoteTooLarge);
        }
        self.inbound_sessions_per_remote = limit;
        Ok(self)
    }

    /// The per-remote inbound session limit; `0` means no limit.
    #[must_use]
    pub const fn inbound_sessions_per_remote(self) -> u8 {
        self.inbound_sessions_per_remote
    }

    /// Enables or disables the delayed ICMP Port Unreachable (Type 3,
    /// Code 3) for unsolicited inbound SYNs (RFC 5382 REQ-4).
    ///
    /// An external initial SYN that finds no live mapping for its public
    /// port, or that the configured filtering refuses, is always dropped
    /// silently. With this switch on (the default, the RFC SHOULD) a copy of
    /// it is held for at least [`crate::NAT44_TCP_UNSOLICITED_SYN_HOLD_MS`]
    /// (plus [`crate::NAT44_TCP_UNSOLICITED_SYN_CLOCK_MARGIN_MS`]); if an
    /// outbound SYN for the same connection is translated meanwhile the hold
    /// is dropped silently, otherwise the NAT answers with one ICMP Port
    /// Unreachable through the generated-ICMPv4 queue and its Port
    /// Unreachable limiter class. A bound firewall must admit the SYN as a
    /// new connection to every inside destination (REQ-4 a). The hold
    /// table is fixed caller-backed storage
    /// ([`Nat44TcpRuntime::with_unsolicited_syn_holds`]); without slots, or
    /// with this switch off, every such SYN is only dropped silently
    /// (REQ-4 a). With the switch off, giving no slots also frees their
    /// memory.
    #[must_use]
    pub const fn with_unsolicited_syn_icmp(mut self, enabled: bool) -> Self {
        self.unsolicited_syn_icmp = enabled;
        self
    }

    /// Whether unsolicited inbound SYNs are held for a delayed ICMP Port
    /// Unreachable (default `true`).
    #[must_use]
    pub const fn unsolicited_syn_icmp(self) -> bool {
        self.unsolicited_syn_icmp
    }

    /// Selects what inbound RST and FIN segments (and the handshake ACK)
    /// do to a session's phase. The default
    /// [`Nat44TcpInboundRst::Closing`] is RFC 7857 §2.2;
    /// [`Nat44TcpInboundRst::Corroborate`] is a local security policy
    /// against spoofed inbound segments (the NAT tracks no sequence
    /// numbers).
    #[must_use]
    pub const fn with_inbound_rst(mut self, inbound_rst: Nat44TcpInboundRst) -> Self {
        self.inbound_rst = inbound_rst;
        self
    }

    /// The inbound RST/FIN policy (default [`Nat44TcpInboundRst::Closing`]).
    #[must_use]
    pub const fn inbound_rst(self) -> Nat44TcpInboundRst {
        self.inbound_rst
    }

    /// Limits the mappings one internal IPv4 address may hold (N3,
    /// NAT44-092, RFC 6888 REQ-4): with a nonzero `limit`, a new mapping
    /// for an internal address that already holds `limit` mappings it keeps
    /// alive is refused fail closed (`NAT44_TCP_HOST_QUOTA_EXCEEDED`) without
    /// evicting anything. Each counted mapping owns one public port, so
    /// this is the number of external ports per internal host. Existing
    /// mappings, their refreshes, and new sessions on them are unaffected.
    /// A TCP mapping counts as live for this limit only until its
    /// host-driven expiry: segments the host sends on its own
    /// outbound-initiated or established sessions refresh it, except
    /// segments that leave the session closing (a RST, or an ACK from
    /// TIME-WAIT); remote activity, and the host stack's answers to it,
    /// do not, so a remote cannot keep a host at its limit. When the address holds `limit` mappings and one is past its
    /// host-driven expiry, the new mapping takes over that mapping's slot
    /// (ending any sessions only remotes still kept alive; the public port
    /// comes from the normal selection). The default `0` is no limit (RFC 6888 asks only that a
    /// limit be supported). A nonzero limit needs per-host storage
    /// ([`Nat44HostStorage`]); the runtime refuses to start or reconcile to
    /// one without it.
    #[must_use]
    pub const fn with_mappings_per_host(mut self, limit: u16) -> Self {
        self.mappings_per_host = limit;
        self
    }

    /// The per-internal-host mapping limit; `0` means no limit.
    #[must_use]
    pub const fn mappings_per_host(self) -> u16 {
        self.mappings_per_host
    }

    /// Limits the host-initiated sessions one internal IPv4 address may
    /// hold (N6, NAT44-119, RFC 6888 REQ-5): with a nonzero `limit`, a new
    /// session that an outbound initial SYN of an internal address creates
    /// (also on a new mapping, and the outbound half of a hairpin) is
    /// refused fail closed (`NAT44_TCP_HOST_SESSION_QUOTA_EXCEEDED`)
    /// without evicting anything while the address holds `limit` sessions
    /// it keeps alive. Sessions that inbound SYNs create (external or the
    /// inbound half of a hairpin) never count: a remote cannot spend an
    /// inside host's budget, and the per-remote inbound limit
    /// ([`Self::with_inbound_sessions_per_remote`]) bounds those. Like the
    /// mapping limit, a session counts as kept alive only until its
    /// host-driven expiry: segments the host sends refresh it with the
    /// session's phase timeout (the transitory one once the host has sent
    /// a FIN), except segments that leave the session closing (a RST, or
    /// an ACK from TIME-WAIT), and it never outlives the session. When the
    /// address holds `limit` sessions and one is past that expiry, that
    /// session stops counting (it is not ended; only remotes can still keep
    /// it alive) and the new one is admitted, so a host recovers as soon as
    /// it stops driving one of its sessions, in O(1). A session that stopped
    /// counting counts again with the host's next host-driven segment on it,
    /// within the limit like a new session (refused while every counted
    /// session is still driven), and a session the remote restarts after a
    /// FIN close stops counting. The default `0` is no
    /// limit (RFC 6888 asks only that a limit be supported). A nonzero
    /// limit needs per-session host storage
    /// ([`Nat44TcpIndexStorage::with_session_hosts`]); the runtime refuses
    /// to start or reconcile to one without it.
    #[must_use]
    pub const fn with_sessions_per_host(mut self, limit: u16) -> Self {
        self.sessions_per_host = limit;
        self
    }

    /// The per-internal-host session limit; `0` means no limit.
    #[must_use]
    pub const fn sessions_per_host(self) -> u16 {
        self.sessions_per_host
    }
}

impl Default for Nat44TcpPolicy {
    fn default() -> Self {
        Self {
            idle_ttl_ms: NAT44_TCP_DEFAULT_IDLE_TTL_MS,
            opening_idle_ttl_ms: NAT44_TCP_DEFAULT_TRANSITORY_IDLE_TTL_MS,
            closing_idle_ttl_ms: NAT44_TCP_DEFAULT_TRANSITORY_IDLE_TTL_MS,
            allocator_seed: 0,
            icmpv4_errors: Nat44Icmpv4ErrorPolicy::Bidirectional,
            filtering: Nat44Filtering::AddressDependent,
            hairpinning: true,
            inbound_sessions_per_remote: NAT44_TCP_DEFAULT_INBOUND_SESSIONS_PER_REMOTE,
            unsolicited_syn_icmp: true,
            inbound_rst: Nat44TcpInboundRst::Closing,
            port_preservation: true,
            mappings_per_host: NAT44_DEFAULT_MAPPINGS_PER_HOST,
            sessions_per_host: NAT44_DEFAULT_STATE_PER_HOST,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Nat44TcpConfig {
    inside: IfId,
    outside: IfId,
    public_address: Ipv4Address,
    first_port: u16,
    last_port: u16,
    /// The public ports; `first_port..=last_port` are its bounds.
    ports: crate::PortSet,
    policy: Nat44TcpPolicy,
    authority: u64,
    snapshot_identity: [usize; 8],
}

impl std::fmt::Debug for Nat44TcpConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Nat44TcpConfig")
            .field("inside", &self.inside)
            .field("outside", &self.outside)
            .field("public_address", &self.public_address)
            .field("first_port", &self.first_port)
            .field("last_port", &self.last_port)
            .field("policy", &self.policy)
            .field("authority", &Redacted)
            .field("snapshot_identity", &Redacted)
            .finish()
    }
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
        if first_port == 0 {
            return Err(Nat44TcpConfigError::PortPoolIncludesZero);
        }
        if first_port > last_port {
            return Err(Nat44TcpConfigError::PortPoolReversed);
        }
        let ports = crate::PortSet::range(first_port, last_port)
            .map_err(|_| Nat44TcpConfigError::PortPoolReversed)?;
        Self::with_port_set(snapshot, inside, outside, public_address, ports, policy)
    }

    /// Like [`Self::new`] with any port set, such as a MAP-E one
    /// ([`crate::PortSet::psid`]).
    pub fn with_port_set(
        snapshot: &ForwardingSnapshot<'_>,
        inside: IfId,
        outside: IfId,
        public_address: Ipv4Address,
        ports: crate::PortSet,
        policy: Nat44TcpPolicy,
    ) -> Result<Self, Nat44TcpConfigError> {
        if inside == outside {
            return Err(Nat44TcpConfigError::InterfacesEqual);
        }
        if snapshot.interface(inside).is_none() {
            return Err(Nat44TcpConfigError::InsideInterfaceMissing);
        }
        if snapshot.interface(outside).is_none() {
            return Err(Nat44TcpConfigError::OutsideInterfaceMissing);
        }
        if !address_is_host_unicast(snapshot, public_address) {
            return Err(Nat44TcpConfigError::PublicAddressNotHostUnicast);
        }
        let Some(binding) = snapshot.local_binding_for(public_address) else {
            return Err(Nat44TcpConfigError::PublicBindingMissing);
        };
        if binding.interface != outside {
            return Err(Nat44TcpConfigError::PublicBindingWrongInterface);
        }
        let (first_port, last_port) = ports.bounds();
        Ok(Self {
            inside,
            outside,
            public_address,
            first_port,
            last_port,
            ports,
            policy,
            authority: snapshot_authority(snapshot),
            snapshot_identity: snapshot.identity(),
        })
    }

    /// The fields that must stay equal for state to carry across a
    /// publication (RELOAD-CARRY).
    #[must_use]
    pub const fn carry_identity(self) -> Nat44CarryIdentity {
        Nat44CarryIdentity::new(
            self.inside,
            self.outside,
            self.public_address,
            self.ports,
            self.policy.filtering,
        )
        .with_tcp_timers(self.policy.carry_timers())
        .with_host_limits([self.policy.mappings_per_host, self.policy.sessions_per_host])
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

    /// The public ports.
    #[must_use]
    pub const fn ports(self) -> crate::PortSet {
        self.ports
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

/// Which reuse set a TCP mapping slot is in (PERF-001); every slot is in
/// exactly one.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum TcpMappingList {
    /// Never used since construction or the last flush: the slots at and
    /// after the fresh boundary, untouched (equal to the default slot).
    #[default]
    Free,
    /// Occupied and owning its public port, expiring `idle_ttl_ms` after
    /// its last commit of an established session: `expires_ms` minus that
    /// TTL is a commit time, so the list is in `expires_ms` order and, if
    /// any slot on it is expired, the head is.
    Established,
    /// Occupied and owning its public port, expiring the longer transitory
    /// TTL after its last commit; in `expires_ms` order as above.
    Transitory,
    /// Expired, its public port taken by a newer mapping.
    Retired,
}

/// Reuse bookkeeping embedded in a TCP mapping slot.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct TcpMappingLink {
    links: SlotLinks,
    list: TcpMappingList,
}

/// Fresh boundaries and reuse lists of the TCP mappings and sessions. Slots
/// at and after a fresh boundary have never been used since the last flush
/// (they are default slots) and those before it are occupied: slots leave
/// the fresh set only in index order. An occupied session is on the
/// activity list of its phase ([`Nat44TcpSessionPhase`]), in
/// `last_activity_ms` order (oldest first); each list has one idle TTL, so
/// its head is the first of its sessions to expire.
#[derive(Clone, Copy)]
struct TcpReuseLists {
    next_fresh_mapping: usize,
    mapping_established: SlotList,
    mapping_transitory: SlotList,
    mapping_retired: SlotList,
    next_fresh_session: usize,
    session_lru: [SlotList; Nat44TcpSessionPhase::COUNT],
}

impl TcpReuseLists {
    /// Every slot fresh (construction and reconcile flush).
    const FLUSHED: Self = Self {
        next_fresh_mapping: 0,
        mapping_established: SlotList::EMPTY,
        mapping_transitory: SlotList::EMPTY,
        mapping_retired: SlotList::EMPTY,
        next_fresh_session: 0,
        session_lru: [SlotList::EMPTY; Nat44TcpSessionPhase::COUNT],
    };

    fn mapping_list_mut(&mut self, list: TcpMappingList) -> &mut SlotList {
        match list {
            TcpMappingList::Established => &mut self.mapping_established,
            TcpMappingList::Transitory => &mut self.mapping_transitory,
            TcpMappingList::Retired => &mut self.mapping_retired,
            TcpMappingList::Free => unreachable!("the fresh set is not a list"),
        }
    }

    /// Takes mapping slot `index` out of `list` in O(1).
    fn detach_mapping(
        &mut self,
        mappings: &mut [Nat44TcpMappingSlot],
        index: usize,
        list: TcpMappingList,
    ) {
        match list {
            TcpMappingList::Free => {
                debug_assert!(index == self.next_fresh_mapping);
                self.next_fresh_mapping += 1;
            }
            list => self.mapping_list_mut(list).unlink(mappings, index),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Nat44TcpMappingSlot {
    occupied: bool,
    generation: u64,
    lifecycle_epoch: u128,
    port_owned: bool,
    inside: IfId,
    internal_address: Ipv4Address,
    internal_port: u16,
    public_port: u16,
    /// Established sessions of this generation (occupied slots in the
    /// established phase, live or expired); see [`Self::expires_ms`].
    established_sessions: u32,
    last_activity_ms: u64,
    /// The mapping is live strictly before this time. Every commit sets it
    /// to `now + idle_ttl_ms` when the committed session is established;
    /// otherwise to `now` + the longer transitory TTL when no established
    /// session remains (`established_sessions == 0`; an established session
    /// counts while its slot stays occupied, live or expired, until the slot
    /// is reclaimed), else to the larger of that and its current value. It
    /// is therefore never earlier than any session's expiry (a session of an
    /// expired mapping has expired). Once no established session remains
    /// the mapping expires with its last session; until then it can outlive
    /// its sessions, and may even be live with none left.
    expires_ms: u64,
    link: TcpMappingLink,
    /// Host-driven expiry (N3): like `expires_ms`, but advanced only by
    /// segments the inside host sends on its own outbound-initiated
    /// sessions or on established sessions that do not leave the session
    /// closing, so inbound-only activity (a
    /// remote that keeps sending SYNs to the public port) cannot keep the
    /// mapping counting against the host's mapping quota. Never later than
    /// `expires_ms`; it orders the host's quota lists.
    host_expires_ms: u64,
}

impl Linked for Nat44TcpMappingSlot {
    fn links(&self) -> SlotLinks {
        self.link.links
    }

    fn links_mut(&mut self) -> &mut SlotLinks {
        &mut self.link.links
    }
}

impl std::fmt::Debug for Nat44TcpMappingSlot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Nat44TcpMappingSlot")
            .field("occupied", &self.occupied)
            .field("inside", &self.inside)
            .field("public_port", &self.public_port)
            .field("last_activity_ms", &self.last_activity_ms)
            .finish_non_exhaustive()
    }
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
            established_sessions: 0,
            last_activity_ms: 0,
            expires_ms: 0,
            link: TcpMappingLink::default(),
            host_expires_ms: 0,
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

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Nat44TcpSessionSlot {
    occupied: bool,
    mapping_index: usize,
    mapping_generation: u64,
    mapping_lifecycle_epoch: u128,
    remote_address: Ipv4Address,
    remote_port: u16,
    last_activity_ms: u64,
    /// Created by an external (non-hairpin) inbound initial SYN; counted
    /// against the per-remote inbound session limit while live.
    external_inbound: bool,
    /// Opened by the inside host: created by an outbound initial SYN, or
    /// restarted by one after a FIN close (N6). Only such a session counts
    /// toward its host's session limit; a restart the remote initiates
    /// clears it.
    host_initiated: bool,
    /// TCP flags seen per direction (`nat44_tcp_state`); selects the phase
    /// and with it the idle TTL and the activity list.
    state: u8,
    /// Activity-list links of the slot's phase while occupied.
    links: SlotLinks,
}

impl Linked for Nat44TcpSessionSlot {
    fn links(&self) -> SlotLinks {
        self.links
    }

    fn links_mut(&mut self) -> &mut SlotLinks {
        &mut self.links
    }
}

impl std::fmt::Debug for Nat44TcpSessionSlot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Nat44TcpSessionSlot")
            .field("occupied", &self.occupied)
            .field("last_activity_ms", &self.last_activity_ms)
            .finish_non_exhaustive()
    }
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
            external_inbound: false,
            host_initiated: false,
            state: 0,
            links: SlotLinks::UNLINKED,
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

    /// Whether an external inbound initial SYN created this session, so it
    /// counts against the per-remote inbound session limit while live.
    #[must_use]
    pub const fn is_external_inbound(self) -> bool {
        self.external_inbound
    }

    /// Whether the inside host opened this session (an outbound initial
    /// SYN created or restarted it), so it counts toward the host's
    /// session limit while the host keeps it alive (N6).
    #[must_use]
    pub const fn is_host_initiated(self) -> bool {
        self.host_initiated
    }

    /// The RFC 5382 §5 phase of the session's connection, which selects its
    /// idle TTL ([`Nat44TcpPolicy::session_idle_ttl_ms`]).
    #[must_use]
    pub const fn phase(self) -> Nat44TcpSessionPhase {
        phase_of(self.state)
    }

    /// A new session of `mapping` (in slot `mapping_index`) before its
    /// first segment is stamped ([`Nat44TcpRuntime::stamp_session`]).
    const fn new_for(
        mapping_index: usize,
        mapping: Nat44TcpMappingSlot,
        remote_address: Ipv4Address,
        remote_port: u16,
        external_inbound: bool,
    ) -> Self {
        Self {
            occupied: true,
            mapping_index,
            mapping_generation: mapping.generation,
            mapping_lifecycle_epoch: mapping.lifecycle_epoch,
            remote_address,
            remote_port,
            last_activity_ms: 0,
            external_inbound,
            host_initiated: false,
            state: 0,
            links: SlotLinks::UNLINKED,
        }
    }
}

/// Slot occupancy of a [`Nat44TcpRuntime`]; see [`Nat44TcpRuntime::occupancy`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Nat44TcpOccupancy {
    pub mappings: TableOccupancy,
    pub sessions: TableOccupancy,
    pub external_inbound_sessions: TableOccupancy,
    /// Held unsolicited inbound SYNs (RFC 5382 REQ-4). Unlike the other
    /// tables a hold is freed when it matures or is cancelled.
    pub unsolicited_syn_holds: TableOccupancy,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Nat44TcpCounters {
    pub mappings_created: u64,
    pub mappings_reused: u64,
    pub mappings_expired: u64,
    pub sessions_created: u64,
    /// Sessions created by an inbound initial SYN that the configured
    /// filtering admitted. Also counted in `sessions_created`.
    pub inbound_sessions_created: u64,
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
    /// Hairpinned packets translated back into the inside realm (both
    /// halves committed). Not counted in `outbound_translated` or
    /// `inbound_translated`.
    pub hairpin_translated: u64,
    /// Hairpinned packets dropped after their outbound half committed: the
    /// destination mapping's filtering, a bound firewall, capacity, or
    /// inside route/neighbor work refused the inbound half. The sender's
    /// mapping and filter state stay, as for an outbound packet a remote NAT
    /// drops (hole punching, RFC 5128 §3.3.2 for UDP and §3.4 for TCP).
    /// Filter refusals are not also counted in the ordinary inbound
    /// miss/deny counters.
    pub hairpin_inbound_refused: u64,
    /// Hairpinned packets dropped because hairpinning is disabled.
    pub hairpin_disabled: u64,
    /// External inbound initial SYNs dropped because their mapping already
    /// has the configured number of live inbound-created sessions from the
    /// same remote IPv4 address, or because the count could not be proven
    /// below it within [`NAT44_TCP_INBOUND_SLOT_PROBES`] chain nodes.
    pub inbound_remote_quota_exceeded: u64,
    /// Unsolicited inbound initial SYNs (mapping miss or filter refusal)
    /// held for a delayed ICMP Port Unreachable (RFC 5382 REQ-4).
    pub unsolicited_syn_held: u64,
    /// Retransmitted SYNs of an already held connection: the hold restarted
    /// from the retransmission, nothing else was held.
    pub unsolicited_syn_refreshed: u64,
    /// Unsolicited SYNs not held because the hold table (or the keyed chain
    /// of their connection) was full or inconsistent: dropped silently.
    pub unsolicited_syn_hold_full: u64,
    /// Unsolicited SYNs not held because no ICMP error may answer them:
    /// a source that is not a unicast host, a source whose reverse route
    /// does not leave through the outside interface, or a link-layer group
    /// destination.
    pub unsolicited_syn_ineligible: u64,
    /// Holds dropped silently because an outbound SYN for the same
    /// connection was translated during the hold (simultaneous open).
    pub unsolicited_syn_cancelled: u64,
    /// Matured holds dropped silently because the NAT would now admit a
    /// retransmission of the SYN (a live session or an admitting filter
    /// exists for the connection).
    pub unsolicited_syn_superseded: u64,
    /// Matured holds answered with a queued ICMP Port Unreachable.
    pub unsolicited_syn_icmp_queued: u64,
    /// Matured holds that queued no ICMP: the Port Unreachable limiter, the
    /// action capacity, reverse route, or reverse neighbor refused it, or the NAT
    /// could not re-check the connection. Each hold yields at most one
    /// ICMP, so a refused one is not retried.
    pub unsolicited_syn_icmp_suppressed: u64,
    /// Unsolicited SYNs not held, and matured holds dropped silently,
    /// because the bound firewall would not admit the SYN as a new
    /// connection to every inside destination (RFC 5382 REQ-4 a: no
    /// response that the security policy forbids).
    pub unsolicited_syn_firewall_denied: u64,
    /// Times the hold table was found inconsistent. Each time the whole
    /// table is flushed (every hold dropped silently, fail closed), so a
    /// corrupt entry can never block later holds.
    pub unsolicited_syn_index_corrupt: u64,
    /// Committed segments that moved a session into the established phase
    /// (SYN and ACK now seen in both directions, or a non-RST segment after
    /// a RST on such a session).
    pub sessions_established: u64,
    /// Committed segments that moved a session into the closing phase with
    /// a FIN in both directions (not after a RST).
    pub sessions_closed: u64,
    /// Committed RST segments on a session without a pending RST: the
    /// session moved to the closing idle timeout (RFC 7857 §2.2).
    pub sessions_reset: u64,
    /// Expired sessions reclaimed (also in `sessions_expired`) whose last
    /// phase was opening, established, or closing: which idle timeout
    /// ended them.
    pub sessions_expired_opening: u64,
    pub sessions_expired_established: u64,
    pub sessions_expired_closing: u64,
    /// New mappings refused because their internal address already held
    /// the per-host limit of live mappings (N3).
    pub host_quota_exceeded: u64,
    /// New host-initiated sessions (and the new mappings that would carry
    /// them) refused because their internal address already held the
    /// per-host limit of sessions it keeps alive (N6).
    pub host_session_quota_exceeded: u64,
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
    /// The outbound half of a hairpinned segment committed the sender's
    /// mapping and session; `public_port` is its external source port.
    HairpinOutboundCommitted {
        public_port: u16,
        mapping_created: bool,
        session_created: bool,
    },
    /// A hairpinned segment was translated back into the inside realm with
    /// external source `public_port` and internal destination
    /// `internal_address:internal_port`.
    HairpinTranslated {
        public_port: u16,
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
    /// An external inbound initial SYN over the per-remote inbound session
    /// limit; nothing was created or evicted.
    InboundRemoteQuotaExceeded,
    /// The internal address already holds the per-host limit of live
    /// mappings (N3); nothing was created or evicted.
    HostQuotaExceeded,
    /// The internal address already holds the per-host limit of sessions it
    /// keeps alive (N6); nothing was created or evicted.
    HostSessionQuotaExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44TcpReconcileReport {
    pub mappings_flushed: usize,
    pub sessions_flushed: usize,
    /// Allocated mapping and session slots kept by a carry (RELOAD-CARRY),
    /// counted like the flushed ones.
    pub mappings_carried: usize,
    pub sessions_carried: usize,
    pub outcome: crate::StateCarryOutcome,
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
    /// The host's counted session past its host-driven expiry that stops
    /// counting so this plan's new session fits the per-host session limit
    /// (N6), or `TCP_INDEX_NONE`.
    host_session_reclaim: u32,
    /// The plan's existing session is one the host initiated that does not
    /// count (it stopped counting past its host-driven expiry, or a restart
    /// made it host-initiated) and this host-driven segment counts it again
    /// (N6), within the limit like a new session.
    session_recount: bool,
    prepared: PreparedNat44TcpOutboundCommit,
}

impl Nat44TcpOutboundPlan {
    const fn mapping_index(self) -> usize {
        self.mapping_index as usize
    }

    fn host_session_reclaim(self) -> Option<usize> {
        (self.host_session_reclaim != TCP_INDEX_NONE).then_some(self.host_session_reclaim as usize)
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

    pub(crate) const fn hairpin_disposition(self) -> Nat44TcpDisposition {
        Nat44TcpDisposition::HairpinOutboundCommitted {
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
    session_created: bool,
    session_expired: bool,
    prepared: PreparedNat44TcpSessionLink,
}

/// Who sent an inbound segment: an outside host, or the inbound half of a
/// hairpinned segment (whose remote is the NAT's own public address).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Nat44TcpInboundOrigin {
    External,
    Hairpin,
}

/// What one bounded remote-address chain walk saw for a mapping and remote
/// IPv4 address.
#[derive(Clone, Copy)]
struct Nat44TcpRemoteCensus {
    /// A live session of this mapping with this remote address exists.
    live: bool,
    /// Live externally created sessions seen (stops at the limit).
    counted: usize,
    /// The first expired slot of this mapping and remote address seen.
    expired_slot: Option<usize>,
    /// The walk reached the end of the chain.
    complete: bool,
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
    InboundRemoteQuotaExceeded,
    HostQuotaExceeded,
    HostSessionQuotaExceeded,
}

#[derive(Clone, Copy)]
enum PreparedTcpDirectoryMutation {
    Link(PreparedDirectoryLink),
    Relink(PreparedDirectoryRelink),
}

/// Prepared links of one newly keyed session slot in the exact session
/// directory and the remote-address directory over the same slots.
#[derive(Clone, Copy)]
struct PreparedNat44TcpSessionLink {
    session: Option<PreparedTcpDirectoryMutation>,
    address: Option<PreparedTcpDirectoryMutation>,
}

impl PreparedNat44TcpSessionLink {
    const EMPTY: Self = Self {
        session: None,
        address: None,
    };
}

#[derive(Clone, Copy)]
struct PreparedNat44TcpOutboundCommit {
    mapping: Option<PreparedTcpDirectoryMutation>,
    session: PreparedNat44TcpSessionLink,
    owner: Option<PreparedPortOwnerMoveTopology>,
}

impl PreparedNat44TcpOutboundCommit {
    const EMPTY: Self = Self {
        mapping: None,
        session: PreparedNat44TcpSessionLink::EMPTY,
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
    SessionAddress(DirectorySemanticError),
    Port(PortOwnerSemanticError),
    DuplicateMappingKey,
    DuplicateSessionKey,
    MappingSummaryMismatch,
    MappingExpiresBeforeSession,
    EstablishedCountMismatch,
    ReuseLists,
    Hosts,
    SessionHosts,
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

/// Caller-owned storage for TCP NAT mapping, session, session remote-address,
/// and port-owner indexes.
///
/// The session remote-address directory indexes the same session slots as
/// the exact session directory, keyed by mapping and remote IPv4 only. It
/// answers the address-dependent filtering question "does this mapping have
/// a live session with this remote address" without scanning sessions, so
/// its node count must equal the session count.
pub struct Nat44TcpIndexStorage<'a> {
    mapping_buckets: &'a mut [DirectoryBucket],
    mapping_nodes: &'a mut [DirectoryNode],
    session_buckets: &'a mut [DirectoryBucket],
    session_nodes: &'a mut [DirectoryNode],
    session_address_buckets: &'a mut [DirectoryBucket],
    session_address_nodes: &'a mut [DirectoryNode],
    port_owners: &'a mut [PortOwnerSlot],
    port_free_bits: &'a mut [u64],
    hosts: Nat44HostStorage<'a, 2>,
    session_hosts: Nat44HostStorage<'a, 3>,
}

impl<'a> Nat44TcpIndexStorage<'a> {
    /// `hosts` is the per-host mapping accounting (N3): empty
    /// ([`Nat44HostStorage::disabled`]) for a runtime whose
    /// [`Nat44TcpPolicy::mappings_per_host`] is `0`, else one link, host
    /// slot, and directory node per mapping slot and the mapping
    /// directory's bucket count.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mapping_buckets: &'a mut [DirectoryBucket],
        mapping_nodes: &'a mut [DirectoryNode],
        session_buckets: &'a mut [DirectoryBucket],
        session_nodes: &'a mut [DirectoryNode],
        session_address_buckets: &'a mut [DirectoryBucket],
        session_address_nodes: &'a mut [DirectoryNode],
        port_owners: &'a mut [PortOwnerSlot],
        port_free_bits: &'a mut [u64],
        hosts: Nat44HostStorage<'a, 2>,
    ) -> Self {
        Self {
            mapping_buckets,
            mapping_nodes,
            session_buckets,
            session_nodes,
            session_address_buckets,
            session_address_nodes,
            port_owners,
            port_free_bits,
            hosts,
            session_hosts: Nat44HostStorage::disabled(),
        }
    }

    /// This storage with the per-host session accounting (N6) `storage`:
    /// one link, host slot, and directory node per session slot and the
    /// session directory's bucket count. Without it (the default from
    /// [`Self::new`]) the runtime's [`Nat44TcpPolicy::sessions_per_host`]
    /// must be `0`.
    #[must_use]
    pub fn with_session_hosts(mut self, storage: Nat44HostStorage<'a, 3>) -> Self {
        self.session_hosts = storage;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44TcpRuntimeConfigError {
    MappingNodeCountMismatch,
    SessionNodeCountMismatch,
    SessionAddressNodeCountMismatch,
    MappingDirectoryInvalid,
    SessionDirectoryInvalid,
    SessionAddressDirectoryInvalid,
    PortOwnerTableInvalid,
    RuntimeIdentityExhausted,
    /// More unsolicited-SYN hold slots than indexes can address.
    SynHoldTableTooLarge,
    /// The per-host accounting storage (N3) does not have one host slot
    /// and one directory node per mapping slot, or its directory is
    /// invalid.
    HostTableInvalid,
    /// The per-host session accounting storage (N6) does not have one
    /// host slot and one directory node per session slot, or its directory
    /// is invalid, or it is missing under a nonzero per-host session limit.
    SessionHostTableInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nat44TcpReconcileError {
    HashKeyNotRotated,
    PortOwnerTableInvalid,
    RuntimeEpochExhausted,
    /// The new configuration sets a per-host mapping limit (N3) but the
    /// runtime has no per-host storage (a storage-shape change).
    HostTableMissing,
    /// The new configuration sets a per-host session limit (N6) but the
    /// runtime has no per-host session storage (a storage-shape change).
    SessionHostTableMissing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nat44TcpStorageShape {
    mapping_slots: u32,
    session_slots: u32,
    mapping_buckets: u32,
    mapping_nodes: u32,
    session_buckets: u32,
    session_nodes: u32,
    session_address_buckets: u32,
    session_address_nodes: u32,
    port_owner_slots: u32,
    port_bitmap_words: u32,
    unsolicited_syn_hold_slots: u32,
    host_slots: u32,
    host_buckets: u32,
    host_nodes: u32,
    session_host_slots: u32,
    session_host_buckets: u32,
    session_host_nodes: u32,
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
    pub const fn session_address_buckets(self) -> u32 {
        self.session_address_buckets
    }
    pub const fn session_address_nodes(self) -> u32 {
        self.session_address_nodes
    }
    pub const fn port_owner_slots(self) -> u32 {
        self.port_owner_slots
    }
    /// Words of the free-port bitmap of the port-owner index.
    pub const fn port_bitmap_words(self) -> u32 {
        self.port_bitmap_words
    }
    /// Slots of the unsolicited-SYN hold table (RFC 5382 REQ-4).
    pub const fn unsolicited_syn_hold_slots(self) -> u32 {
        self.unsolicited_syn_hold_slots
    }
    /// Host slots of the per-host mapping accounting (N3), one per mapping
    /// slot.
    pub const fn host_slots(self) -> u32 {
        self.host_slots
    }
    /// Buckets of the host directory, as many as the mapping directory's.
    pub const fn host_buckets(self) -> u32 {
        self.host_buckets
    }
    /// Nodes of the host directory, one per host slot.
    pub const fn host_nodes(self) -> u32 {
        self.host_nodes
    }
    /// Host slots of the per-host session accounting (N6), one per session
    /// slot.
    pub const fn session_host_slots(self) -> u32 {
        self.session_host_slots
    }
    /// Buckets of the session host directory, as many as the session
    /// directory's.
    pub const fn session_host_buckets(self) -> u32 {
        self.session_host_buckets
    }
    /// Nodes of the session host directory, one per session host slot.
    pub const fn session_host_nodes(self) -> u32 {
        self.session_host_nodes
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
    session_address_buckets: Nat44UdpBackingIdentity,
    session_address_nodes: Nat44UdpBackingIdentity,
    port_owners: Nat44UdpBackingIdentity,
    port_free_bits: Nat44UdpBackingIdentity,
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
            session_address_buckets: Nat44UdpBackingIdentity::of(indexes.session_address_buckets),
            session_address_nodes: Nat44UdpBackingIdentity::of(indexes.session_address_nodes),
            port_owners: Nat44UdpBackingIdentity::of(indexes.port_owners),
            port_free_bits: Nat44UdpBackingIdentity::of(indexes.port_free_bits),
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
    /// `Carried` keeps every mapping, session, index, the hash key, the
    /// epoch, and the clock watermark; anything else flushes and rotates.
    outcome: crate::StateCarryOutcome,
}

impl Nat44TcpReconcilePermit<'_, '_> {
    pub fn commit(self) -> Nat44TcpReconcileReport {
        if self.outcome.carried() {
            return self.runtime.commit_prevalidated_carry(self.config);
        }
        let mut report = self.runtime.commit_prevalidated_reconcile(
            self.config,
            self.hash_key,
            self.next_runtime_epoch,
        );
        report.outcome = self.outcome;
        report
    }

    /// What [`Self::commit`] will do with the state.
    #[must_use]
    pub const fn outcome(&self) -> crate::StateCarryOutcome {
        self.outcome
    }
}

/// Fixed-capacity, worker-local outbound-initiated TCP NAPT state.
///
/// This intentionally models exact remote endpoint sessions, not TCP sequence
/// or window state. Each session follows the SYN, ACK, FIN, and RST flags it
/// translates (RFC 7857 §2) and uses the idle TTL of its RFC 5382 §5 phase
/// ([`Nat44TcpSessionPhase`]); a RST moves a session to the closing TTL and
/// never removes it at once (RFC 7857 §2.2).
///
/// Every per-packet search is bounded (PERF-001): a new mapping, session, or
/// public port is found in O(1) from activity-ordered intrusive lists (the
/// head is the first to expire), a retired-mapping list, fresh-slot
/// boundaries, and a free-port bitmap, as for [`Nat44UdpRuntime`]. An
/// external inbound SYN keeps its bounded keyed probe window.
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
    session_address_directory: FixedDirectory<'a>,
    port_owners: PortOwnerTable<'a>,
    /// Per-internal-host lists of the port-owning mappings (N3).
    hosts: HostTable<'a, 2>,
    /// Per-internal-host lists of the host-initiated sessions (N6), by the
    /// idle-timeout kind of their host-driven expiry; see
    /// [`Nat44TcpRuntime::session_host_expiry`].
    session_hosts: HostTable<'a, 3>,
    hash_key: Nat44TcpHashKey,
    /// IDs of translated non-atomic datagrams (RFC 6864 §5.3.1), keyed by
    /// the construction key and kept across reconcile and flush.
    ipv4_ids: Ipv4IdGenerator,
    watermark_ms: Option<u64>,
    runtime_epoch: u128,
    next_generation: u64,
    state_revision: u128,
    #[allow(dead_code)]
    runtime_binding: Nat44TcpRuntimeBinding,
    counters: Nat44TcpCounters,
    /// Allocated mapping, session, and external-inbound session slots; see
    /// [`Nat44TcpRuntime::occupancy`].
    mapping_occupancy: OccupancyCounter,
    session_occupancy: OccupancyCounter,
    external_inbound_occupancy: OccupancyCounter,
    /// Mapping and session reuse lists; see [`TcpReuseLists`].
    reuse_lists: TcpReuseLists,
    /// Unsolicited inbound SYNs held for a delayed ICMP Port Unreachable
    /// (RFC 5382 REQ-4); empty unless
    /// [`Nat44TcpRuntime::with_unsolicited_syn_holds`] supplied slots.
    syn_holds: SynHoldTable<'a>,
    #[cfg(test)]
    mapping_liveness_checks: Cell<usize>,
    #[cfg(test)]
    session_liveness_checks: Cell<usize>,
    #[cfg(test)]
    mapping_lookup_probes: Cell<usize>,
    #[cfg(test)]
    session_lookup_probes: Cell<usize>,
    #[cfg(test)]
    session_address_lookup_probes: Cell<usize>,
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
        if indexes.session_address_nodes.len() != sessions.len() {
            return Err(Nat44TcpRuntimeConfigError::SessionAddressNodeCountMismatch);
        }
        FixedDirectory::validate_config(indexes.mapping_buckets.len(), indexes.mapping_nodes.len())
            .map_err(|_| Nat44TcpRuntimeConfigError::MappingDirectoryInvalid)?;
        FixedDirectory::validate_config(indexes.session_buckets.len(), indexes.session_nodes.len())
            .map_err(|_| Nat44TcpRuntimeConfigError::SessionDirectoryInvalid)?;
        FixedDirectory::validate_config(
            indexes.session_address_buckets.len(),
            indexes.session_address_nodes.len(),
        )
        .map_err(|_| Nat44TcpRuntimeConfigError::SessionAddressDirectoryInvalid)?;
        PortOwnerTable::validate_config(
            indexes.port_owners.len(),
            indexes.port_free_bits.len(),
            config.ports,
            mappings.len(),
        )
        .map_err(|_| Nat44TcpRuntimeConfigError::PortOwnerTableInvalid)?;
        HostTable::validate_config(&indexes.hosts, mappings.len(), HostTableKind::Lists)
            .map_err(|_| Nat44TcpRuntimeConfigError::HostTableInvalid)?;
        if config.policy.mappings_per_host != 0
            && !mappings.is_empty()
            && indexes.hosts.hosts.is_empty()
        {
            return Err(Nat44TcpRuntimeConfigError::HostTableInvalid);
        }
        HostTable::validate_config(&indexes.session_hosts, sessions.len(), HostTableKind::Words)
            .map_err(|_| Nat44TcpRuntimeConfigError::SessionHostTableInvalid)?;
        if config.policy.sessions_per_host != 0
            && !sessions.is_empty()
            && indexes.session_hosts.hosts.is_empty()
        {
            return Err(Nat44TcpRuntimeConfigError::SessionHostTableInvalid);
        }
        let runtime_identity = allocate_tcp_runtime_identity()?;
        let runtime_binding =
            Nat44TcpRuntimeBinding::new(runtime_identity, mappings, sessions, &indexes);
        let mapping_directory =
            FixedDirectory::new(indexes.mapping_buckets, indexes.mapping_nodes, hash_key.0)
                .expect("mapping directory dimensions were preflighted");
        let session_directory =
            FixedDirectory::new(indexes.session_buckets, indexes.session_nodes, hash_key.0)
                .expect("session directory dimensions were preflighted");
        let session_address_directory = FixedDirectory::new(
            indexes.session_address_buckets,
            indexes.session_address_nodes,
            hash_key.0,
        )
        .expect("session address directory dimensions were preflighted");
        let port_owners = PortOwnerTable::new(
            indexes.port_owners,
            indexes.port_free_bits,
            config.ports,
            mappings.len(),
        )
        .expect("port owner dimensions were preflighted");
        let hosts = HostTable::new(indexes.hosts, hash_key.0, DirectoryHashDomain::TcpHost)
            .expect("host table dimensions were preflighted");
        let session_hosts = HostTable::new(
            indexes.session_hosts,
            hash_key.0,
            DirectoryHashDomain::TcpSessionHost,
        )
        .expect("session host table dimensions were preflighted");
        mappings.fill(Nat44TcpMappingSlot::default());
        sessions.fill(Nat44TcpSessionSlot::default());
        Ok(Self {
            config,
            mappings,
            sessions,
            mapping_directory,
            session_directory,
            session_address_directory,
            port_owners,
            hosts,
            session_hosts,
            hash_key,
            ipv4_ids: Ipv4IdGenerator::new(hash_key.0),
            watermark_ms: None,
            runtime_epoch: 1,
            next_generation: 1,
            state_revision: 0,
            runtime_binding,
            counters: Nat44TcpCounters::default(),
            mapping_occupancy: OccupancyCounter::default(),
            session_occupancy: OccupancyCounter::default(),
            external_inbound_occupancy: OccupancyCounter::default(),
            reuse_lists: TcpReuseLists::FLUSHED,
            syn_holds: SynHoldTable::empty(),
            #[cfg(test)]
            mapping_liveness_checks: Cell::new(0),
            #[cfg(test)]
            session_liveness_checks: Cell::new(0),
            #[cfg(test)]
            mapping_lookup_probes: Cell::new(0),
            #[cfg(test)]
            session_lookup_probes: Cell::new(0),
            #[cfg(test)]
            session_address_lookup_probes: Cell::new(0),
            #[cfg(test)]
            reusable_mapping_checks: Cell::new(0),
            #[cfg(test)]
            reusable_session_checks: Cell::new(0),
            #[cfg(test)]
            port_owner_probes: Cell::new(0),
            _worker_local: PhantomData,
        })
    }

    /// Gives the runtime caller-backed storage for unsolicited inbound SYN
    /// holds (RFC 5382 REQ-4; see
    /// [`Nat44TcpPolicy::with_unsolicited_syn_icmp`]). The slots are reset.
    /// Their count is part of [`Self::storage_shape`]; a runtime without
    /// this call has none and drops every unsolicited SYN silently.
    ///
    /// # Errors
    ///
    /// [`Nat44TcpRuntimeConfigError::SynHoldTableTooLarge`] when the slot
    /// count does not fit the `u32` slot links.
    pub fn with_unsolicited_syn_holds(
        mut self,
        holds: &'a mut [Nat44TcpSynHoldSlot],
    ) -> Result<Self, Nat44TcpRuntimeConfigError> {
        if holds.len() > MAX_SYN_HOLD_SLOTS {
            return Err(Nat44TcpRuntimeConfigError::SynHoldTableTooLarge);
        }
        self.syn_holds = SynHoldTable::new(holds);
        Ok(self)
    }

    /// Unsolicited SYNs currently held (RFC 5382 REQ-4), in O(1).
    #[must_use]
    pub fn unsolicited_syn_holds(&self) -> usize {
        self.syn_holds.len()
    }

    #[must_use]
    pub const fn config(&self) -> Nat44TcpConfig {
        self.config
    }

    /// The ID of the next non-atomic datagram this runtime translates into
    /// the (source, destination, protocol) tuple (RFC 6864 §5.3.1,
    /// NAT44-126); the public address selects the direction's counters.
    pub(crate) fn next_ipv4_id(
        &mut self,
        source: [u8; 4],
        destination: [u8; 4],
        protocol: u8,
    ) -> u16 {
        let public = self.config.public_address().octets();
        self.ipv4_ids.next(source, destination, protocol, public)
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

    /// Exact allocated mapping and session slots and their high-water marks
    /// since construction or the last reconcile flush, in O(1).
    ///
    /// A slot counts from the commit that first fills it until a reconcile
    /// flush. Expiry is lazy and an expired slot is reclaimed by overwriting
    /// it in place, so expired mappings and sessions still count until a
    /// flush, and within one generation the counts never decrease.
    /// `external_inbound_sessions` counts the allocated session slots whose
    /// current session was created by an external inbound initial SYN
    /// ([`Nat44TcpSessionSlot::is_external_inbound`]); it drops when such a
    /// slot is reused by an outbound-created session. Its capacity is the
    /// session capacity.
    #[must_use]
    pub fn occupancy(&self) -> Nat44TcpOccupancy {
        Nat44TcpOccupancy {
            mappings: self.mapping_occupancy.snapshot(self.mappings.len()),
            sessions: self.session_occupancy.snapshot(self.sessions.len()),
            external_inbound_sessions: self
                .external_inbound_occupancy
                .snapshot(self.sessions.len()),
            unsolicited_syn_holds: self.syn_holds.occupancy(),
        }
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
            session_address_buckets: u32::try_from(self.session_address_directory.bucket_count())
                .expect("validated capacity"),
            session_address_nodes: u32::try_from(self.session_address_directory.node_capacity())
                .expect("validated capacity"),
            port_owner_slots: u32::try_from(self.port_owners.slot_count())
                .expect("validated capacity"),
            port_bitmap_words: u32::try_from(port_free_bitmap_words(self.port_owners.slot_count()))
                .expect("validated capacity"),
            unsolicited_syn_hold_slots: u32::try_from(self.syn_holds.capacity())
                .expect("validated capacity"),
            host_slots: u32::try_from(self.hosts.slot_count()).expect("validated capacity"),
            host_buckets: u32::try_from(self.hosts.bucket_count()).expect("validated capacity"),
            host_nodes: u32::try_from(self.hosts.node_capacity()).expect("validated capacity"),
            session_host_slots: u32::try_from(self.session_hosts.slot_count())
                .expect("validated capacity"),
            session_host_buckets: u32::try_from(self.session_hosts.bucket_count())
                .expect("validated capacity"),
            session_host_nodes: u32::try_from(self.session_hosts.node_capacity())
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
            port_free_bitmap_words(self.port_owners.slot_count()),
            config.ports,
            self.mappings.len(),
        )
        .is_err()
        {
            return Err(Nat44TcpReconcileError::PortOwnerTableInvalid);
        }
        self.check_host_tables(config)?;
        Ok(Nat44TcpReconcilePermit {
            runtime: self,
            config,
            hash_key,
            next_runtime_epoch,
            outcome: crate::StateCarryOutcome::FlushRequested,
        })
    }

    fn check_host_tables(&self, config: Nat44TcpConfig) -> Result<(), Nat44TcpReconcileError> {
        if config.policy.mappings_per_host != 0
            && !self.mappings.is_empty()
            && !self.hosts.enabled()
        {
            return Err(Nat44TcpReconcileError::HostTableMissing);
        }
        if config.policy.sessions_per_host != 0
            && !self.sessions.is_empty()
            && !self.session_hosts.enabled()
        {
            return Err(Nat44TcpReconcileError::SessionHostTableMissing);
        }
        Ok(())
    }

    /// Why `config` cannot carry this runtime's state, if it cannot
    /// (RELOAD-CARRY); see [`Self::preflight_reconcile_carrying`].
    #[must_use]
    pub fn carry_conflict(&self, config: Nat44TcpConfig) -> Option<crate::StateCarryConflict> {
        self.config
            .carry_identity()
            .carry_conflict(config.carry_identity())
    }

    /// Preflights a successor that keeps this runtime's state when it can
    /// (RELOAD-CARRY); the TCP counterpart of
    /// [`Nat44UdpRuntime::preflight_reconcile_carrying`].
    ///
    /// A carry keeps every mapping, session (with its RFC 7857 phase),
    /// index, port owner, per-host and per-remote count, the hash key, the
    /// runtime epoch, and the clock watermark, in O(1). The phase timeouts
    /// must be unchanged (mappings keep absolute deadlines) and the per-host
    /// limits not lowered or added; otherwise this flushes. Unsolicited-SYN
    /// holds (RFC 5382 REQ-4) are always dropped:
    /// each was admitted by the old firewall and switch for an ICMP error
    /// at most 6 s later, so none is sent on the old authority.
    pub fn preflight_reconcile_carrying<'runtime>(
        &'runtime mut self,
        config: Nat44TcpConfig,
        hash_key: Nat44TcpHashKey,
    ) -> Result<Nat44TcpReconcilePermit<'runtime, 'a>, Nat44TcpReconcileError> {
        if let Some(conflict) = self.carry_conflict(config) {
            let mut permit = self.preflight_reconcile(config, hash_key)?;
            permit.outcome = crate::StateCarryOutcome::FlushIncompatible(conflict);
            return Ok(permit);
        }
        self.check_host_tables(config)?;
        let next_runtime_epoch = self.runtime_epoch;
        Ok(Nat44TcpReconcilePermit {
            runtime: self,
            config,
            hash_key,
            next_runtime_epoch,
            outcome: crate::StateCarryOutcome::Carried,
        })
    }

    fn commit_prevalidated_carry(&mut self, config: Nat44TcpConfig) -> Nat44TcpReconcileReport {
        let mappings_carried = self.mappings.iter().filter(|slot| slot.occupied).count();
        let sessions_carried = self.sessions.iter().filter(|slot| slot.occupied).count();
        self.syn_holds.flush();
        self.config = config;
        self.counters.reconciliations = self.counters.reconciliations.saturating_add(1);
        Nat44TcpReconcileReport {
            mappings_flushed: 0,
            sessions_flushed: 0,
            mappings_carried,
            sessions_carried,
            outcome: crate::StateCarryOutcome::Carried,
        }
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
        self.reuse_lists = TcpReuseLists::FLUSHED;
        self.syn_holds.flush();
        self.mapping_occupancy.flush();
        self.session_occupancy.flush();
        self.external_inbound_occupancy.flush();
        self.mapping_directory.clear_with_key(hash_key.0);
        self.session_directory.clear_with_key(hash_key.0);
        self.session_address_directory.clear_with_key(hash_key.0);
        self.hosts.clear_with_key(hash_key.0);
        self.session_hosts.clear_with_key(hash_key.0);
        self.port_owners
            .reconfigure_prevalidated_and_clear(config.ports, self.mappings.len());
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
            mappings_carried: 0,
            sessions_carried: 0,
            outcome: crate::StateCarryOutcome::FlushRequested,
        }
    }

    pub(crate) fn record_config_mismatch(&mut self) {
        self.counters.config_mismatches = self.counters.config_mismatches.saturating_add(1);
    }

    /// The idle timeout of session host list `list` (N6): the phase whose
    /// [`Nat44TcpSessionPhase::index`] it is.
    const fn session_host_ttl_ms(&self, list: usize) -> u64 {
        let phase = match list {
            0 => Nat44TcpSessionPhase::Opening,
            1 => Nat44TcpSessionPhase::Established,
            _ => Nat44TcpSessionPhase::Closing,
        };
        self.config.policy.session_idle_ttl_ms(phase)
    }

    /// The reference time and list of counted session `index` (N6): its
    /// host-driven expiry is `reference + session_host_ttl_ms(list)`. The
    /// link stores the reference as an offset below the session's last
    /// activity. A saturated offset (more than `u32::MAX` ms) makes the
    /// computed expiry later than the true one, but it is still before the
    /// session's last activity, because every TTL is below `u32::MAX` ms,
    /// so the session reads as past its host-driven expiry either way; the
    /// list order is by insertion and unaffected.
    fn session_host_reference(&self, index: usize) -> Option<(u64, usize)> {
        let list = self.session_hosts.mapping_list(index)?;
        let reference = self.sessions[index]
            .last_activity_ms
            .saturating_sub(u64::from(self.session_hosts.word(index)));
        Some((reference, list))
    }

    /// The host-driven expiry of counted session `index` (N6), if it counts.
    fn session_host_expiry(&self, index: usize) -> Option<u64> {
        self.session_host_reference(index)
            .map(|(reference, list)| reference.saturating_add(self.session_host_ttl_ms(list)))
    }

    /// Whether counted session `index` is still kept alive by its inside
    /// host (N6): before its host-driven expiry. Such a session is live
    /// and of its mapping's generation.
    fn session_is_host_live(&self, index: usize, now_ms: u64) -> bool {
        self.session_host_expiry(index).is_some_and(|expiry| {
            now_ms >= self.sessions[index].last_activity_ms && now_ms < expiry
        })
    }

    /// The host-driven expiry reference and list of a counted session after
    /// one committed segment (N6): `before` is the current one (`None` for
    /// the session the segment creates), `session` the slot after the
    /// segment, `direction` the segment's.
    ///
    /// The rule is the mapping's host-driven expiry (N3, NAT44-097) per
    /// session: a segment the host sends that does not leave the session
    /// closing, on a session it opened or an established one, sets it to
    /// `now` plus the session's phase timeout, the transitory one once the
    /// host has sent a FIN (a half-closed session the remote never closes
    /// must not count for the established timeout, NAT44-096); any other
    /// segment keeps it. Either way it is capped by the session's own
    /// expiry after the segment, so a counted session past its own expiry
    /// is past its host-driven expiry too. Every change sets it to `now`
    /// plus the timeout of the list it moves to, so each list stays in
    /// expiry order.
    /// Whether `direction`'s segment that left the session as `session`
    /// is host-driven (N3, N6): the host sent it, it does not leave the
    /// session closing, and the session is one the host opened (not
    /// externally created) or is established.
    fn segment_is_host_driven(session: Nat44TcpSessionSlot, direction: Nat44TcpDirection) -> bool {
        let phase = session.phase();
        direction == Nat44TcpDirection::Outbound
            && phase != Nat44TcpSessionPhase::Closing
            && (!session.external_inbound || phase == Nat44TcpSessionPhase::Established)
    }

    fn next_session_host_reference(
        &self,
        before: Option<(u64, usize)>,
        session: Nat44TcpSessionSlot,
        direction: Nat44TcpDirection,
        now_ms: u64,
    ) -> (u64, usize) {
        let policy = self.config.policy;
        let phase = session.phase();
        let established = phase == Nat44TcpSessionPhase::Established;
        let host_driven = Self::segment_is_host_driven(session, direction);
        let driven_list =
            if established && session.state & crate::nat44_tcp_state::STATE_FIN_OUT == 0 {
                Nat44TcpSessionPhase::Established.index()
            } else if policy.opening_idle_ttl_ms >= policy.closing_idle_ttl_ms {
                Nat44TcpSessionPhase::Opening.index()
            } else {
                Nat44TcpSessionPhase::Closing.index()
            };
        let candidate = match before {
            Some(before) if !host_driven => before,
            _ => (now_ms, driven_list),
        };
        let cap = (now_ms, phase.index());
        let value = |(reference, list): (u64, usize)| {
            reference.saturating_add(self.session_host_ttl_ms(list))
        };
        if value(candidate) <= value(cap) {
            candidate
        } else {
            cap
        }
    }

    /// Commit-time per-host session accounting of one session slot write
    /// (N6), before the slot is overwritten: a created session ends the
    /// count of the slot's previous session and, when `counted` names its
    /// internal address and planned host slot, counts toward that host; an
    /// existing session stops counting when it is no longer host-initiated,
    /// starts counting again when `counted` is given (a planned recount),
    /// and a counted one's host-driven expiry follows the segment. O(1).
    fn commit_session_host(
        &mut self,
        index: usize,
        session: Nat44TcpSessionSlot,
        created: bool,
        counted: Option<(Ipv4Address, Option<HostAssignment>)>,
        direction: Nat44TcpDirection,
        now_ms: u64,
    ) {
        if !self.session_hosts.enabled() {
            return;
        }
        let lag =
            |reference: u64| u32::try_from(now_ms.saturating_sub(reference)).unwrap_or(u32::MAX);
        if created {
            self.session_hosts.detach(index);
            if let Some((address, assignment)) = counted {
                let (reference, list) =
                    self.next_session_host_reference(None, session, direction, now_ms);
                self.session_hosts
                    .attach_new(index, assignment, address, list);
                self.session_hosts.set_word(index, lag(reference));
            }
            return;
        }
        // A restart the remote initiated (the host answered with a SYN-ACK)
        // is not the host's session: it stops counting.
        if !session.host_initiated {
            self.session_hosts.detach(index);
            return;
        }
        let Some(before) = self.session_host_reference(index) else {
            // An uncounted host-initiated session the planned host-driven
            // segment counts again.
            if let Some((address, assignment)) = counted {
                let (reference, list) =
                    self.next_session_host_reference(None, session, direction, now_ms);
                self.session_hosts
                    .attach_new(index, assignment, address, list);
                self.session_hosts.set_word(index, lag(reference));
            }
            return;
        };
        let after = self.next_session_host_reference(Some(before), session, direction, now_ms);
        if after != before {
            self.session_hosts.relist(index, after.1);
        }
        self.session_hosts.set_word(index, lag(after.0));
    }

    /// The per-host session limit check of a new host-initiated session for
    /// `internal_address` (N6, NAT44-119), O(1): `Ok(None)` when the session
    /// may be created as usual, `Ok(Some(slot))` when the address holds the
    /// limit and its counted session `slot` is past its host-driven expiry
    /// (the commit stops counting it; the session itself stays until it
    /// expires or its slot is reused), and `HostSessionQuotaExceeded` when
    /// every counted session is one the host still keeps alive.
    ///
    /// Each of the host's three lists is in host-driven expiry order, so
    /// some counted session is past it exactly when one of the heads is.
    /// One keyed host lookup, three expiry reads.
    fn host_session_reclaim(
        &self,
        internal_address: Ipv4Address,
        now_ms: u64,
    ) -> Result<Option<usize>, Nat44TcpPlanError> {
        let limit = usize::from(self.config.policy.sessions_per_host);
        if limit == 0 {
            return Ok(None);
        }
        let Some(host) = self
            .session_hosts
            .find(internal_address)
            .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?
        else {
            return Ok(None);
        };
        if self.session_hosts.count(host) < limit {
            return Ok(None);
        }
        let (head, _) = (0..Nat44TcpSessionPhase::COUNT)
            .filter_map(|list| self.session_hosts.head(host, list))
            .filter_map(|head| self.session_host_expiry(head).map(|expiry| (head, expiry)))
            .min_by_key(|(_, expiry)| *expiry)
            .ok_or(Nat44TcpPlanError::IndexCorrupt)?;
        if self.session_is_host_live(head, now_ms) {
            return Err(Nat44TcpPlanError::HostSessionQuotaExceeded);
        }
        Ok(Some(head))
    }

    /// The session host slot of a new host-initiated session for `address`
    /// written into session slot `session_index` (N6), from the current
    /// state; `None` without session accounting. The plan, the
    /// revalidation, and the commit compute it from the same state.
    fn session_host_assignment(
        &self,
        session_index: usize,
        address: Ipv4Address,
    ) -> Result<Option<HostAssignment>, HostTableCorrupt> {
        let found = self.session_hosts.find(address)?;
        self.session_hosts.plan_assignment(
            address,
            found,
            self.session_hosts.releasing_host(session_index),
        )
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
        segment: impl Into<Nat44TcpSegment>,
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
            segment.into(),
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
        segment: impl Into<Nat44TcpSegment>,
        now_ms: u64,
    ) -> Result<Nat44TcpOutboundPlan, Nat44TcpPlanError> {
        self.check_now_read_only(now_ms)?;
        self.plan_outbound_after_clock(
            internal_address,
            internal_port,
            remote_address,
            remote_port,
            segment.into(),
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
        segment: Nat44TcpSegment,
        now_ms: u64,
    ) -> Result<Nat44TcpOutboundPlan, Nat44TcpPlanError> {
        if self.state_revision == u128::MAX {
            return Err(Nat44TcpPlanError::StateRevisionExhausted);
        }
        let initial_syn = segment.is_initial_syn();
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
                self.stamp_session(
                    &mut mapping,
                    &mut session,
                    segment,
                    Nat44TcpDirection::Outbound,
                    false,
                    now_ms,
                )?;
                // A host-initiated session that no longer counts is counted
                // again by the host's next host-driven segment, within the
                // limit like a new session (N6): otherwise a host could let
                // sessions pass their host-driven expiry, open new ones in
                // their place, and then resume the old ones uncounted.
                let session_recount = self.session_hosts.enabled()
                    && session.host_initiated
                    && Self::segment_is_host_driven(session, Nat44TcpDirection::Outbound)
                    && self.session_hosts.mapping_host(session_index).is_none();
                let host_session_reclaim = if session_recount {
                    self.host_session_reclaim(internal_address, now_ms)?
                } else {
                    None
                };
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
                        host_session_reclaim: encode_optional_udp_index(host_session_reclaim),
                        session_recount,
                        prepared: PreparedNat44TcpOutboundCommit::EMPTY,
                    },
                    None,
                );
            }
            if !initial_syn {
                return Err(Nat44TcpPlanError::InvalidInitialFlags);
            }
            let host_session_reclaim = self.host_session_reclaim(internal_address, now_ms)?;
            let session_index = if let Some((session_index, _)) = exact_session {
                session_index
            } else if let Some(session_index) = self.find_reusable_session(now_ms) {
                session_index
            } else {
                return Err(Nat44TcpPlanError::SessionFull);
            };
            let session_before = self.sessions[session_index];
            let session_expired = session_before.occupied;
            let mut session = Nat44TcpSessionSlot::new_for(
                mapping_index,
                mapping,
                remote_address,
                remote_port,
                false,
            );
            session.host_initiated = true;
            self.stamp_session(
                &mut mapping,
                &mut session,
                segment,
                Nat44TcpDirection::Outbound,
                self.established_owner(session_before) == Some(mapping_index),
                now_ms,
            )?;
            return self.prepare_outbound_plan(
                Nat44TcpOutboundPlan {
                    authority: self.plan_authority(now_ms, mapping_before, session_before),
                    mapping_index: encode_udp_index(mapping_index),
                    mapping,
                    session_index: encode_udp_index(session_index),
                    session,
                    mapping_created: false,
                    mapping_expired: false,
                    session_created: true,
                    session_expired,
                    displaced_port_mapping_index: TCP_INDEX_NONE,
                    host_session_reclaim: encode_optional_udp_index(host_session_reclaim),
                    session_recount: false,
                    prepared: PreparedNat44TcpOutboundCommit::EMPTY,
                },
                None,
            );
        }
        if !initial_syn {
            return Err(Nat44TcpPlanError::InvalidInitialFlags);
        }
        let host = self
            .hosts
            .find(internal_address)
            .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?;
        let quota_reclaim = self.host_quota_reclaim(exact_mapping, host, now_ms)?;
        // The new mapping carries a new host-initiated session (N6).
        let host_session_reclaim = self.host_session_reclaim(internal_address, now_ms)?;
        let mapping_index = if let Some((mapping_index, _)) = exact_mapping {
            mapping_index
        } else if let Some(reclaimed) = quota_reclaim {
            reclaimed
        } else if let Some(mapping_index) = self.find_reusable_mapping(now_ms) {
            mapping_index
        } else {
            return Err(Nat44TcpPlanError::MappingFull);
        };
        let Some(session_index) = self.find_reusable_session(now_ms) else {
            return Err(Nat44TcpPlanError::SessionFull);
        };
        let previous = exact_mapping.map(|(_, mapping)| mapping);
        let port = match (quota_reclaim, exact_mapping) {
            // A returning endpoint whose own mapping was retired keeps that
            // slot; the host's reclaimed mapping gives up its port.
            (Some(reclaimed), Some(_)) => self.reclaimed_port(reclaimed)?,
            // At the per-host limit the host's reclaimed slot gets a port by
            // the normal selection (N2 steps 1, 3, 4; another host's expired
            // mapping whose port it takes is retired), its own port if
            // every other one is live.
            (Some(reclaimed), None) => {
                match self.allocate_port(internal_address, internal_port, None, now_ms)? {
                    Some(port) => port,
                    None => self.reclaimed_port(reclaimed)?,
                }
            }
            (None, _) => {
                let Some(port) =
                    self.allocate_port(internal_address, internal_port, previous, now_ms)?
                else {
                    return Err(Nat44TcpPlanError::PortExhausted);
                };
                port
            }
        };
        // A new endpoint that takes the port of an expired mapping (port
        // preservation or a keyed takeover probe) recreates that mapping's
        // slot rather than the list head's, so no other port is released
        // in expiry order for the next new mapping to take (N2, NAT44-020).
        // A quota reclaim keeps the reclaimed slot so the host's count
        // stays exact.
        let mapping_index = match (exact_mapping, quota_reclaim, port.displaced_mapping_index) {
            (None, None, Some(displaced)) => displaced,
            _ => mapping_index,
        };
        if self.next_generation == 0 || self.next_generation == u64::MAX {
            return Err(Nat44TcpPlanError::GenerationExhausted);
        }
        // The commit recomputes the host slot from the same state; planning
        // it here fails closed on a corrupt host table before anything else.
        self.hosts
            .plan_assignment(
                internal_address,
                host,
                self.hosts.releasing_host(mapping_index),
            )
            .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?;
        let generation = self.next_generation;
        let mapping_before = self.mappings[mapping_index];
        let session_before = self.sessions[session_index];
        let mapping_expired = mapping_before.occupied;
        let session_expired = session_before.occupied;
        let mut mapping = Nat44TcpMappingSlot {
            occupied: true,
            generation,
            lifecycle_epoch: self.runtime_epoch,
            port_owned: true,
            inside: self.config.inside,
            internal_address,
            internal_port,
            public_port: port.port,
            established_sessions: 0,
            last_activity_ms: now_ms,
            expires_ms: 0,
            link: TcpMappingLink::default(),
            host_expires_ms: 0,
        };
        let mut session = Nat44TcpSessionSlot::new_for(
            mapping_index,
            mapping,
            remote_address,
            remote_port,
            false,
        );
        session.host_initiated = true;
        // A new generation starts with no established session; one the
        // reused session slot held belongs to another mapping (or to the
        // previous generation of this slot) and is released by the commit.
        self.stamp_session(
            &mut mapping,
            &mut session,
            segment,
            Nat44TcpDirection::Outbound,
            false,
            now_ms,
        )?;
        self.prepare_outbound_plan(
            Nat44TcpOutboundPlan {
                authority: self.plan_authority(now_ms, mapping_before, session_before),
                mapping_index: encode_udp_index(mapping_index),
                mapping,
                session_index: encode_udp_index(session_index),
                session,
                mapping_created: true,
                mapping_expired,
                session_created: true,
                session_expired,
                displaced_port_mapping_index: encode_optional_udp_index(
                    port.displaced_mapping_index,
                ),
                host_session_reclaim: encode_optional_udp_index(host_session_reclaim),
                session_recount: false,
                prepared: PreparedNat44TcpOutboundCommit::EMPTY,
            },
            port.expected_owner,
        )
    }

    /// The per-host quota check of a new mapping for the internal address
    /// whose host slot is `host` (N3, NAT44-092), O(1); see the UDP
    /// runtime's. TCP counts host-driven liveness
    /// ([`Nat44TcpMappingSlot::host_expires_ms`]): the host has two lists
    /// (established and transitory TTL), each in host-driven expiry order,
    /// so the host has a mapping past its host-driven expiry exactly when
    /// one of the two heads is; the one that passed first is reclaimed,
    /// even if remotes still keep it live (its sessions end with it). A
    /// returning endpoint whose own mapping was retired keeps that slot,
    /// so the reclaimed mapping only gives up its port and must have
    /// expired outright: a mapping is never retired while live.
    fn host_quota_reclaim(
        &self,
        exact_mapping: Option<(usize, Nat44TcpMappingSlot)>,
        host: Option<usize>,
        now_ms: u64,
    ) -> Result<Option<usize>, Nat44TcpPlanError> {
        let limit = usize::from(self.config.policy.mappings_per_host);
        let Some(host) = host else {
            return Ok(None);
        };
        if limit == 0
            || self.hosts.count(host) < limit
            || exact_mapping.is_some_and(|(index, _)| self.hosts.mapping_host(index).is_some())
        {
            return Ok(None);
        }
        let retired_return = exact_mapping.is_some();
        let expired = (0..2)
            .filter_map(|list| self.hosts.head(host, list))
            .map(|head| (head, self.mappings[head]))
            .filter(|(_, mapping)| {
                !self.mapping_is_host_live(*mapping, now_ms)
                    && !(retired_return && self.mapping_is_live(*mapping, now_ms))
            })
            .min_by_key(|(_, mapping)| mapping.host_expires_ms)
            .map(|(head, _)| head);
        expired
            .map(Some)
            .ok_or(Nat44TcpPlanError::HostQuotaExceeded)
    }

    /// The port the reclaimed mapping in slot `reclaimed` owns, as a
    /// selection that moves it (N3).
    fn reclaimed_port(&self, reclaimed: usize) -> Result<Nat44TcpPortSelection, Nat44TcpPlanError> {
        let port = self.mappings[reclaimed].public_port;
        let owner = self
            .port_owners
            .owner(port)
            .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?
            .filter(|owner| owner.state_index() == reclaimed)
            .ok_or(Nat44TcpPlanError::IndexCorrupt)?;
        Ok(Nat44TcpPortSelection {
            port,
            expected_owner: Some(owner),
            displaced_mapping_index: Some(reclaimed),
        })
    }

    /// The host slot of a new mapping for `address` that overwrites mapping
    /// slot `mapping_index` (N3) from the current state: the plan checks
    /// it, the revalidation checks it again, and the commit recomputes it
    /// before mutating anything, so all three agree.
    fn host_assignment(
        &self,
        mapping_index: usize,
        address: Ipv4Address,
    ) -> Result<Option<HostAssignment>, HostTableCorrupt> {
        let found = self.hosts.find(address)?;
        self.hosts
            .plan_assignment(address, found, self.hosts.releasing_host(mapping_index))
    }

    pub(crate) fn plan_inbound(
        &mut self,
        public_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        segment: impl Into<Nat44TcpSegment>,
        now_ms: u64,
    ) -> Result<Nat44TcpInboundPlan, Nat44TcpPlanError> {
        self.observe_now(now_ms)?;
        self.plan_inbound_after_clock(
            public_port,
            remote_address,
            remote_port,
            segment.into(),
            Nat44TcpInboundOrigin::External,
            now_ms,
        )
    }

    pub(crate) fn plan_inbound_read_only(
        &self,
        public_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        segment: impl Into<Nat44TcpSegment>,
        now_ms: u64,
    ) -> Result<Nat44TcpInboundPlan, Nat44TcpPlanError> {
        self.check_now_read_only(now_ms)?;
        self.plan_inbound_after_clock(
            public_port,
            remote_address,
            remote_port,
            segment.into(),
            Nat44TcpInboundOrigin::External,
            now_ms,
        )
    }

    /// Plans the inbound half of a hairpinned segment: exactly
    /// [`Self::plan_inbound`] except that a session it creates is not
    /// counted against, or limited by, the per-remote inbound session limit.
    pub(crate) fn plan_hairpin_inbound(
        &mut self,
        public_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        segment: impl Into<Nat44TcpSegment>,
        now_ms: u64,
    ) -> Result<Nat44TcpInboundPlan, Nat44TcpPlanError> {
        self.observe_now(now_ms)?;
        self.plan_inbound_after_clock(
            public_port,
            remote_address,
            remote_port,
            segment.into(),
            Nat44TcpInboundOrigin::Hairpin,
            now_ms,
        )
    }

    /// Read-only variant of [`Self::plan_hairpin_inbound`].
    pub(crate) fn plan_hairpin_inbound_read_only(
        &self,
        public_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        segment: impl Into<Nat44TcpSegment>,
        now_ms: u64,
    ) -> Result<Nat44TcpInboundPlan, Nat44TcpPlanError> {
        self.check_now_read_only(now_ms)?;
        self.plan_inbound_after_clock(
            public_port,
            remote_address,
            remote_port,
            segment.into(),
            Nat44TcpInboundOrigin::Hairpin,
            now_ms,
        )
    }

    /// Plans an inbound packet. An exact live session is always translated.
    /// Without one, only an initial SYN (SYN=1, ACK/RST/FIN=0) may initiate
    /// a session on the live mapping, and only when the configured filtering
    /// admits the remote endpoint (RFC 5382 §4.3, REQ-3): any endpoint under
    /// endpoint-independent filtering, a remote IPv4 with another live
    /// session of this mapping under address-dependent filtering, never under
    /// address-and-port-dependent filtering. Every filter refusal is
    /// `SessionMiss`, a silent drop (REQ-4 a). An external SYN the filter
    /// admits is then refused as `InboundRemoteQuotaExceeded` when the
    /// mapping already has the configured number of live externally created
    /// sessions from the same remote IPv4 (see
    /// [`Nat44TcpPolicy::with_inbound_sessions_per_remote`]).
    fn plan_inbound_after_clock(
        &self,
        public_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        segment: Nat44TcpSegment,
        origin: Nat44TcpInboundOrigin,
        now_ms: u64,
    ) -> Result<Nat44TcpInboundPlan, Nat44TcpPlanError> {
        if self.state_revision == u128::MAX {
            return Err(Nat44TcpPlanError::StateRevisionExhausted);
        }
        let initial_syn = segment.is_initial_syn();
        let Some((mapping_index, mut mapping)) =
            self.mapping_for_public_port(public_port, now_ms)?
        else {
            return Err(Nat44TcpPlanError::MappingMiss);
        };
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
            self.stamp_session(
                &mut mapping,
                &mut session,
                segment,
                Nat44TcpDirection::Inbound,
                false,
                now_ms,
            )?;
            return Ok(Nat44TcpInboundPlan {
                authority: self.plan_authority(now_ms, mapping_before, session_before),
                mapping_index,
                mapping,
                session_index,
                session,
                session_created: false,
                session_expired: false,
                prepared: PreparedNat44TcpSessionLink::EMPTY,
            });
        }
        if !initial_syn {
            return Err(Nat44TcpPlanError::SessionMiss);
        }
        let same_remote_expired =
            self.inbound_admission(mapping_index, mapping, remote_address, origin, now_ms)?;
        // Externally initiated sessions keep their own bounded search: this
        // packet is unauthenticated and a bound firewall has not judged it
        // yet. Reuse the exact expired slot, else an expired slot of this
        // mapping and remote address seen by the admission walk (so such
        // slots do not pile up in the remote-address chain), else probe a
        // bounded keyed window.
        let session_index = if let Some((session_index, _)) = exact_session {
            session_index
        } else if let Some(session_index) = same_remote_expired {
            session_index
        } else if let Some(session_index) = self.find_reusable_session_for_inbound(
            mapping_index,
            mapping,
            remote_address,
            remote_port,
            now_ms,
        ) {
            session_index
        } else {
            return Err(Nat44TcpPlanError::SessionFull);
        };
        let session_before = self.sessions[session_index];
        let mut session = Nat44TcpSessionSlot::new_for(
            mapping_index,
            mapping,
            remote_address,
            remote_port,
            origin == Nat44TcpInboundOrigin::External,
        );
        self.stamp_session(
            &mut mapping,
            &mut session,
            segment,
            Nat44TcpDirection::Inbound,
            self.established_owner(session_before) == Some(mapping_index),
            now_ms,
        )?;
        let prepared = self.prepare_session_link(session_index, session)?;
        Ok(Nat44TcpInboundPlan {
            authority: self.plan_authority(now_ms, mapping_before, session_before),
            mapping_index,
            mapping,
            session_index,
            session,
            session_created: true,
            session_expired: session_before.occupied,
            prepared,
        })
    }

    /// Bounded slot search for an inbound-initiated session.
    ///
    /// A table of at most [`NAT44_TCP_INBOUND_SLOT_PROBES`] slots is
    /// scanned whole. A larger one gets that many probes, each at an
    /// independent position keyed by the runtime's secret hash key, the
    /// tuple, the time, and the probe number. An external sender cannot
    /// steer the positions, and a retransmitted SYN probes others. Probes
    /// are independent of where outbound creation clusters live slots (it
    /// fills never-used slots from index 0 and reuses the least recently
    /// active session first), so with live fraction ρ a miss has probability
    /// about ρ^16 (well under 10^-4 at ρ = 1/2). The probed positions are
    /// distinct: a drawn position that repeats an earlier probe moves to the
    /// next position not yet probed (at most 15 steps), so every probe checks
    /// a new slot and a small, nearly full table is not missed for repeated
    /// draws. A miss is `SessionFull` even if a reusable slot exists
    /// elsewhere. A probe that lands on a never-used slot takes the lowest
    /// never-used slot instead (the same outcome, a fresh slot), so fresh
    /// slots keep leaving the fresh set in index order (PERF-001).
    fn find_reusable_session_for_inbound(
        &self,
        mapping_index: usize,
        mapping: Nat44TcpMappingSlot,
        remote_address: Ipv4Address,
        remote_port: u16,
        now_ms: u64,
    ) -> Option<usize> {
        let capacity = self.sessions.len();
        if capacity == 0 {
            return None;
        }
        if capacity <= NAT44_TCP_INBOUND_SLOT_PROBES {
            return (0..capacity)
                .find(|&index| self.session_slot_reusable(index, now_ms))
                .map(|index| self.reusable_session_or_fresh(index));
        }
        let mut words = [
            mapping_index as u64,
            mapping.generation,
            u64::from(u32::from_be_bytes(remote_address.octets())),
            u64::from(remote_port),
            now_ms,
            0,
        ];
        let mut probed = [0_usize; NAT44_TCP_INBOUND_SLOT_PROBES];
        for probe in 0..NAT44_TCP_INBOUND_SLOT_PROBES {
            words[5] = probe as u64;
            let position = self
                .hash_key
                .0
                .hash_words(DirectoryHashDomain::TcpInboundSlot, &words);
            let mut index =
                usize::try_from(position % capacity as u64).expect("index below capacity");
            // `capacity` exceeds the probes made so far, so an unprobed
            // position is at most `probe` steps away. The step count is
            // also bounded on its own, independent of the full-scan branch
            // above.
            debug_assert!(capacity > NAT44_TCP_INBOUND_SLOT_PROBES);
            let mut steps = 0;
            while steps < NAT44_TCP_INBOUND_SLOT_PROBES && probed[..probe].contains(&index) {
                index = if index + 1 == capacity { 0 } else { index + 1 };
                steps += 1;
            }
            probed[probe] = index;
            if self.session_slot_reusable(index, now_ms) {
                return Some(self.reusable_session_or_fresh(index));
            }
        }
        None
    }

    /// `index` if it is occupied (an expired session to reuse), else the
    /// lowest never-used slot: every unoccupied slot is at or after the
    /// fresh boundary, which is then unoccupied too.
    fn reusable_session_or_fresh(&self, index: usize) -> usize {
        if self.sessions[index].occupied {
            index
        } else {
            debug_assert!(self.reuse_lists.next_fresh_session <= index);
            self.reuse_lists.next_fresh_session
        }
    }

    /// Admission of an inbound initial SYN without an exact live session:
    /// the filtering decision, then (for an external SYN with a finite
    /// limit) the per-remote inbound session limit. Returns an expired slot
    /// of this mapping and remote address that the walk saw, if any.
    ///
    /// Bounded: no lookup for address-and-port-dependent filtering, or for
    /// endpoint-independent filtering without a limit. Otherwise one walk
    /// of the remote-address chain that visits at most
    /// [`NAT44_TCP_INBOUND_SLOT_PROBES`] nodes. Without a limit the walk
    /// stops at the first live session (address-dependent admission). With
    /// a limit it counts the live externally created sessions of this
    /// mapping and remote address and stops when the count reaches the
    /// limit; a chain the budget cannot finish fails closed, because the
    /// count is then not proven below the limit. The count is derived from
    /// live slots on every SYN, so expiry, slot reuse, mapping recreation,
    /// and reconcile release quota without any separate bookkeeping.
    fn inbound_admission(
        &self,
        mapping_index: usize,
        mapping: Nat44TcpMappingSlot,
        remote_address: Ipv4Address,
        origin: Nat44TcpInboundOrigin,
        now_ms: u64,
    ) -> Result<Option<usize>, Nat44TcpPlanError> {
        let filtering = self.config.policy.filtering;
        if filtering == Nat44Filtering::AddressAndPortDependent {
            return Err(Nat44TcpPlanError::SessionMiss);
        }
        let limit = match origin {
            Nat44TcpInboundOrigin::External => {
                usize::from(self.config.policy.inbound_sessions_per_remote)
            }
            Nat44TcpInboundOrigin::Hairpin => 0,
        };
        if filtering == Nat44Filtering::EndpointIndependent && limit == 0 {
            return Ok(None);
        }
        let census = self.remote_census(mapping_index, mapping, remote_address, limit, now_ms)?;
        if filtering == Nat44Filtering::AddressDependent && !census.live {
            return Err(Nat44TcpPlanError::SessionMiss);
        }
        if limit != 0 && (census.counted >= limit || !census.complete) {
            return Err(Nat44TcpPlanError::InboundRemoteQuotaExceeded);
        }
        Ok(census.expired_slot)
    }

    /// One bounded walk of the remote-address chain of
    /// `(mapping, remote_address)`; see [`Self::inbound_admission`].
    fn remote_census(
        &self,
        mapping_index: usize,
        mapping: Nat44TcpMappingSlot,
        remote_address: Ipv4Address,
        limit: usize,
        now_ms: u64,
    ) -> Result<Nat44TcpRemoteCensus, Nat44TcpPlanError> {
        let words = Self::session_address_lookup_words(
            mapping_index,
            mapping.generation,
            mapping.lifecycle_epoch,
            remote_address,
        );
        let mut census = Nat44TcpRemoteCensus {
            live: false,
            counted: 0,
            expired_slot: None,
            complete: false,
        };
        let walk = self
            .session_address_directory
            .walk_bounded(
                DirectoryHashDomain::TcpSessionAddress,
                &words,
                NAT44_TCP_INBOUND_SLOT_PROBES,
                |index| {
                    let session = self.sessions[index];
                    if !(session.occupied
                        && session.mapping_index == mapping_index
                        && session.mapping_generation == mapping.generation
                        && session.mapping_lifecycle_epoch == mapping.lifecycle_epoch
                        && session.remote_address == remote_address)
                    {
                        return false;
                    }
                    if !self.session_is_live(session, now_ms) {
                        census.expired_slot.get_or_insert(index);
                        return false;
                    }
                    census.live = true;
                    if session.external_inbound {
                        census.counted += 1;
                    }
                    if limit == 0 {
                        true
                    } else {
                        census.counted >= limit
                    }
                },
            )
            .map_err(|_| Nat44TcpPlanError::IndexCorrupt)?;
        census.complete = walk.complete;
        #[cfg(test)]
        self.session_address_lookup_probes.set(
            self.session_address_lookup_probes
                .get()
                .saturating_add(walk.probes),
        );
        Ok(census)
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
            || !self.session_link_matches(plan.prepared.session)
            || !self.mapping_target_matches_lists(plan.mapping_index())
            || !self.session_target_matches_lists(plan.session_index())
            || (plan.session_created
                && !self.released_count_matches(plan.session_index(), plan.mapping_index()))
        {
            return Err(Nat44TcpCommitError::StalePlan);
        }
        if plan.mapping_created
            && self
                .host_assignment(plan.mapping_index(), plan.mapping.internal_address)
                .is_err()
        {
            return Err(Nat44TcpCommitError::StalePlan);
        }
        // Per-host sessions (N6): the session that stops counting must
        // still count and be past its host-driven expiry, and the new
        // session's host slot must still be assignable.
        if !plan.host_session_reclaim().is_none_or(|index| {
            self.session_hosts.mapping_host(index).is_some()
                && !self.session_is_host_live(index, now_ms)
        }) || ((plan.session_created || plan.session_recount)
            && self
                .session_host_assignment(plan.session_index(), plan.mapping.internal_address)
                .is_err())
            || (plan.session_recount
                && self
                    .session_hosts
                    .mapping_host(plan.session_index())
                    .is_some())
        {
            return Err(Nat44TcpCommitError::StalePlan);
        }
        Ok(())
    }

    /// An unoccupied target mapping slot must be the lowest never-used one,
    /// and an occupied one must be on the activity or retired list, so the
    /// infallible commit can move it in O(1).
    fn mapping_target_matches_lists(&self, index: usize) -> bool {
        let mapping = self.mappings[index];
        if mapping.occupied {
            mapping.link.list != TcpMappingList::Free
        } else {
            mapping.link.list == TcpMappingList::Free
                && index == self.reuse_lists.next_fresh_mapping
        }
    }

    /// An unoccupied target session slot must be the lowest never-used one.
    fn session_target_matches_lists(&self, index: usize) -> bool {
        self.sessions[index].occupied || index == self.reuse_lists.next_fresh_session
    }

    pub(crate) fn commit_prevalidated_outbound(&mut self, plan: Nat44TcpOutboundPlan, now_ms: u64) {
        self.commit_prevalidated_outbound_counted(plan, now_ms, false);
    }

    /// Commits the prevalidated outbound half of a hairpinned segment:
    /// exactly the state [`Self::commit_prevalidated_outbound`] commits for
    /// the same plan, without counting an outbound translation.
    pub(crate) fn commit_prevalidated_hairpin_outbound(
        &mut self,
        plan: Nat44TcpOutboundPlan,
        now_ms: u64,
    ) {
        self.commit_prevalidated_outbound_counted(plan, now_ms, true);
    }

    fn commit_prevalidated_outbound_counted(
        &mut self,
        plan: Nat44TcpOutboundPlan,
        now_ms: u64,
        hairpin: bool,
    ) {
        let host_assignment = if plan.mapping_created {
            self.host_assignment(plan.mapping_index(), plan.mapping.internal_address)
                .expect("prevalidated host assignment")
        } else {
            None
        };
        let session_host_assignment = if plan.session_created || plan.session_recount {
            self.session_host_assignment(plan.session_index(), plan.mapping.internal_address)
                .expect("prevalidated session host assignment")
        } else {
            None
        };
        if let Some(mutation) = plan.prepared.mapping {
            self.apply_mapping_mutation(mutation);
        }
        self.apply_session_link(plan.prepared.session);
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
            self.retire_mapping(displaced);
        }
        self.record_session_commit(
            plan.session_index(),
            plan.session,
            plan.session_created,
            plan.mapping_index(),
        );
        // Per-host sessions (N6): a counted session past its host-driven
        // expiry stops counting; a session this outbound SYN creates counts
        // toward its internal address (an outbound hairpin half too).
        if let Some(index) = plan.host_session_reclaim() {
            self.session_hosts.detach(index);
        }
        self.commit_session_host(
            plan.session_index(),
            plan.session,
            plan.session_created,
            (plan.session_created || plan.session_recount)
                .then_some((plan.mapping.internal_address, session_host_assignment)),
            Nat44TcpDirection::Outbound,
            now_ms,
        );
        // Per-host lists (N3): a new mapping leaves the reclaimed slot's
        // host and joins its own host's list; a refresh follows its
        // activity list in `write_mapping_slot`.
        if plan.mapping_created {
            self.hosts.detach(plan.mapping_index());
        }
        self.write_mapping_slot(plan.mapping_index(), plan.mapping);
        if plan.mapping_created {
            self.hosts.attach_new(
                plan.mapping_index(),
                host_assignment,
                plan.mapping.internal_address,
                self.host_list_at(plan.mapping.host_expires_ms, now_ms),
            );
        }
        self.write_session_slot(plan.session_index(), plan.session);
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
        if !hairpin {
            self.counters.outbound_translated = self.counters.outbound_translated.saturating_add(1);
            // Only an initial SYN creates a session. A translated outbound
            // SYN for a held connection silently drops the held inbound SYN
            // (RFC 5382 REQ-4). A hairpin half's remote is the NAT's own
            // public address, which no held SYN can have (NAT44-047).
            if plan.session_created {
                self.cancel_unsolicited_syn_hold(SynHoldKey {
                    public_port: plan.mapping.public_port,
                    remote_address: plan.session.remote_address,
                    remote_port: plan.session.remote_port,
                });
            }
        }
    }

    fn cancel_unsolicited_syn_hold(&mut self, key: SynHoldKey) {
        match self.syn_holds.cancel(self.hash_key.0, key) {
            Ok(true) => {
                self.counters.unsolicited_syn_cancelled =
                    self.counters.unsolicited_syn_cancelled.saturating_add(1);
            }
            Ok(false) => {}
            Err(_) => self.flush_corrupt_unsolicited_syn_holds(),
        }
    }

    /// Fail closed on an inconsistent hold table: drop every hold silently
    /// (no ICMP for any of them) and start over with an empty table, so the
    /// inconsistency can neither block later holds nor be retried each
    /// tick. Cold path, O(capacity); it cannot happen without memory
    /// corruption.
    fn flush_corrupt_unsolicited_syn_holds(&mut self) {
        self.syn_holds.flush();
        self.counters.unsolicited_syn_index_corrupt = self
            .counters
            .unsolicited_syn_index_corrupt
            .saturating_add(1);
    }

    /// Offers an unsolicited inbound initial SYN (mapping miss or filter
    /// refusal) for a delayed ICMP Port Unreachable (RFC 5382 REQ-4). The
    /// SYN itself is dropped by the caller in every case. Returns whether it
    /// is now held (new or refreshed). O(1) plus one keyed chain walk of at
    /// most [`crate::NAT44_TCP_SYN_HOLD_CHAIN_LIMIT`] slots.
    pub(crate) fn hold_unsolicited_syn(
        &mut self,
        public_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        original_tos: u8,
        original_ipv4: &[u8],
        now_ms: u64,
    ) -> Option<SynHoldInsert> {
        if !self.config.policy.unsolicited_syn_icmp || self.syn_holds.capacity() == 0 {
            return None;
        }
        let outcome = self.syn_holds.insert(
            self.hash_key.0,
            SynHoldKey {
                public_port,
                remote_address,
                remote_port,
            },
            unsolicited_syn_deadline_ms(now_ms),
            original_tos,
            original_ipv4,
        );
        let counter = match outcome {
            SynHoldInsert::Held => &mut self.counters.unsolicited_syn_held,
            SynHoldInsert::Refreshed => &mut self.counters.unsolicited_syn_refreshed,
            SynHoldInsert::Full => &mut self.counters.unsolicited_syn_hold_full,
            SynHoldInsert::IndexCorrupt => {
                self.flush_corrupt_unsolicited_syn_holds();
                return Some(outcome);
            }
        };
        *counter = counter.saturating_add(1);
        Some(outcome)
    }

    /// Whether an unsolicited SYN would be offered to the hold table at all
    /// (switch on and slots present), so callers skip eligibility work
    /// otherwise.
    pub(crate) fn holds_unsolicited_syns(&self) -> bool {
        self.config.policy.unsolicited_syn_icmp && self.syn_holds.capacity() != 0
    }

    pub(crate) fn record_unsolicited_syn_firewall_denied(&mut self) {
        self.counters.unsolicited_syn_firewall_denied = self
            .counters
            .unsolicited_syn_firewall_denied
            .saturating_add(1);
    }

    pub(crate) fn record_unsolicited_syn_ineligible(&mut self) {
        self.counters.unsolicited_syn_ineligible =
            self.counters.unsolicited_syn_ineligible.saturating_add(1);
    }

    /// Removes the earliest held SYN whose hold has ended at `now_ms`, if
    /// any. O(1); the caller bounds how many it takes per tick. An
    /// inconsistent table is flushed (counted in
    /// [`Nat44TcpCounters::unsolicited_syn_index_corrupt`]) before the error
    /// is returned, so the next call starts from an empty table.
    pub(crate) fn pop_matured_unsolicited_syn(
        &mut self,
        now_ms: u64,
    ) -> Result<Option<MaturedSynHold>, Nat44TcpPlanError> {
        self.syn_holds.pop_matured(now_ms).map_err(|_| {
            self.flush_corrupt_unsolicited_syn_holds();
            Nat44TcpPlanError::IndexCorrupt
        })
    }

    pub(crate) fn record_unsolicited_syn_superseded(&mut self) {
        self.counters.unsolicited_syn_superseded =
            self.counters.unsolicited_syn_superseded.saturating_add(1);
    }

    pub(crate) fn record_unsolicited_syn_icmp(&mut self, queued: bool) {
        let counter = if queued {
            &mut self.counters.unsolicited_syn_icmp_queued
        } else {
            &mut self.counters.unsolicited_syn_icmp_suppressed
        };
        *counter = counter.saturating_add(1);
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
        )?;
        if !self.session_link_matches(plan.prepared)
            || !self.mapping_target_matches_lists(plan.mapping_index)
            || !self.session_target_matches_lists(plan.session_index)
            || (plan.session_created
                && !self.released_count_matches(plan.session_index, plan.mapping_index))
        {
            return Err(Nat44TcpCommitError::StalePlan);
        }
        Ok(())
    }

    pub(crate) fn commit_prevalidated_inbound(&mut self, plan: Nat44TcpInboundPlan, now_ms: u64) {
        self.commit_prevalidated_inbound_counted(plan, now_ms, false);
    }

    /// Commits the prevalidated inbound half of a hairpinned segment,
    /// planned after its outbound half committed. Counts
    /// `hairpin_translated` instead of `inbound_translated`.
    pub(crate) fn commit_prevalidated_hairpin_inbound(
        &mut self,
        plan: Nat44TcpInboundPlan,
        now_ms: u64,
    ) {
        self.commit_prevalidated_inbound_counted(plan, now_ms, true);
    }

    fn commit_prevalidated_inbound_counted(
        &mut self,
        plan: Nat44TcpInboundPlan,
        now_ms: u64,
        hairpin: bool,
    ) {
        self.apply_session_link(plan.prepared);
        self.record_session_commit(
            plan.session_index,
            plan.session,
            plan.session_created,
            plan.mapping_index,
        );
        // Per-host sessions (N6): an inbound-created session never counts.
        self.commit_session_host(
            plan.session_index,
            plan.session,
            plan.session_created,
            None,
            Nat44TcpDirection::Inbound,
            now_ms,
        );
        self.write_mapping_slot(plan.mapping_index, plan.mapping);
        self.write_session_slot(plan.session_index, plan.session);
        self.watermark_ms = Some(now_ms);
        self.state_revision = plan.authority.state_revision + 1;
        if plan.session_created {
            self.counters.sessions_created = self.counters.sessions_created.saturating_add(1);
            self.counters.inbound_sessions_created =
                self.counters.inbound_sessions_created.saturating_add(1);
            if plan.session_expired {
                self.counters.sessions_expired = self.counters.sessions_expired.saturating_add(1);
            }
        } else {
            self.counters.sessions_reused = self.counters.sessions_reused.saturating_add(1);
        }
        if hairpin {
            self.counters.hairpin_translated = self.counters.hairpin_translated.saturating_add(1);
        } else {
            self.counters.inbound_translated = self.counters.inbound_translated.saturating_add(1);
        }
    }

    /// Moves an expired mapping that just lost its public port from the
    /// activity list to the retired list; O(1).
    fn retire_mapping(&mut self, index: usize) {
        let list = self.mappings[index].link.list;
        debug_assert!(matches!(
            list,
            TcpMappingList::Established | TcpMappingList::Transitory
        ));
        self.hosts.detach(index);
        self.reuse_lists
            .mapping_list_mut(list)
            .unlink(self.mappings, index);
        self.mappings[index].link.list = TcpMappingList::Retired;
        self.reuse_lists
            .mapping_retired
            .push_back(self.mappings, index);
    }

    /// Overwrites one mapping slot (just stamped by [`Self::stamp_session`])
    /// and its O(1) occupancy counter. The slot moves to the tail of the
    /// activity list `mapping.link.list` names, unless it is already on
    /// that list with the same expiry (an established mapping whose
    /// established TTL outlasts this transitory commit), where it keeps its
    /// place. Either way each activity list stays in `expires_ms` order.
    fn write_mapping_slot(&mut self, index: usize, mapping: Nat44TcpMappingSlot) {
        let before = self.mappings[index];
        let list = mapping.link.list;
        debug_assert!(matches!(
            list,
            TcpMappingList::Established | TcpMappingList::Transitory
        ));
        if before.occupied && before.link.list == list && before.expires_ms == mapping.expires_ms {
            self.mappings[index] = Nat44TcpMappingSlot {
                link: before.link,
                ..mapping
            };
        } else {
            debug_assert!(self
                .reuse_lists
                .mapping_list_mut(list)
                .tail()
                .is_none_or(|tail| self.mappings[tail].expires_ms <= mapping.expires_ms));
            self.reuse_lists
                .detach_mapping(self.mappings, index, before.link.list);
            self.mappings[index] = Nat44TcpMappingSlot {
                link: TcpMappingLink {
                    links: SlotLinks::UNLINKED,
                    list,
                },
                ..mapping
            };
            self.reuse_lists
                .mapping_list_mut(list)
                .push_back(self.mappings, index);
        }
        // A counted mapping whose host-driven expiry changed moves to the
        // tail of the host list of its new value (a new mapping is attached
        // by the caller; its host link is empty here).
        if before.occupied
            && before.generation == mapping.generation
            && before.host_expires_ms != mapping.host_expires_ms
        {
            let list = self.host_list_at(mapping.host_expires_ms, mapping.last_activity_ms);
            self.hosts.relist(index, list);
        }
        self.mapping_occupancy
            .transition(before.occupied, mapping.occupied);
    }

    /// Overwrites one session slot (just stamped with the current time) and
    /// its O(1) occupancy counters, and moves the slot from the fresh set or
    /// its place on its phase's activity list to the tail of the activity
    /// list of its new phase.
    fn write_session_slot(&mut self, index: usize, session: Nat44TcpSessionSlot) {
        let before = self.sessions[index];
        let list = session.phase().index();
        debug_assert!(self.reuse_lists.session_lru[list]
            .tail()
            .is_none_or(|tail| self.sessions[tail].last_activity_ms <= session.last_activity_ms));
        if before.occupied {
            self.reuse_lists.session_lru[before.phase().index()].unlink(self.sessions, index);
        } else {
            debug_assert!(index == self.reuse_lists.next_fresh_session);
            self.reuse_lists.next_fresh_session += 1;
        }
        self.sessions[index] = Nat44TcpSessionSlot {
            links: SlotLinks::UNLINKED,
            ..session
        };
        self.reuse_lists.session_lru[list].push_back(self.sessions, index);
        self.session_occupancy
            .transition(before.occupied, session.occupied);
        self.external_inbound_occupancy.transition(
            before.occupied && before.external_inbound,
            session.occupied && session.external_inbound,
        );
    }

    /// Applies one committed segment to the planned copies of a session and
    /// its mapping (O(1), no other slot is read): the session's TCP state
    /// advances ([`next_state`]) and its activity is stamped with `now_ms`;
    /// the mapping's established-session count follows the session's phase
    /// change (`released_own_established` when the reused slot held an
    /// expired established session of this same mapping generation), and
    /// the mapping's expiry and activity list are recomputed:
    ///
    /// - an established session: `now + idle_ttl_ms`, the established list;
    /// - otherwise, with no established session left: `now` + the longer
    ///   transitory TTL, the transitory list (this may shorten the
    ///   mapping: every remaining session is transitory and was last active
    ///   at or before `now`);
    /// - otherwise, if the established-list expiry still lies beyond that,
    ///   it is kept (and the slot keeps its place); else as above.
    ///
    /// "No established session left" counts every occupied session slot of
    /// this generation in the established phase, live or expired: an
    /// expired established session keeps the mapping on its established
    /// expiry until its slot is reclaimed. So the mapping never expires
    /// before any of its sessions, which the session reuse search relies
    /// on, and each activity list stays in expiry order: a slot pushed to a
    /// tail gets `now` + the list's TTL, the largest expiry on that list.
    ///
    /// A restart of a FIN-closed session by the inside host is a new
    /// connection: an outbound initial SYN makes it outbound-initiated (it
    /// stops counting as externally created); an outbound SYN-ACK makes it
    /// remote-initiated (it counts, unless it is a hairpin inbound half,
    /// whose remote is the public address).
    ///
    /// # Errors
    ///
    /// [`Nat44TcpPlanError::IndexCorrupt`] when the mapping's established
    /// count is lower than the established sessions this commit releases
    /// (bookkeeping drift; fail closed in release builds too).
    fn stamp_session(
        &self,
        mapping: &mut Nat44TcpMappingSlot,
        session: &mut Nat44TcpSessionSlot,
        segment: Nat44TcpSegment,
        direction: Nat44TcpDirection,
        released_own_established: bool,
        now_ms: u64,
    ) -> Result<(), Nat44TcpPlanError> {
        let policy = self.config.policy;
        let was_established = session.phase() == Nat44TcpSessionPhase::Established;
        let transition = next_state(session.state, segment, direction, policy.inbound_rst);
        session.state = transition.state;
        // A restart after a FIN close by the host's initial SYN is a session
        // the host initiated; one the remote opens (the host answers with a
        // SYN-ACK) is not, and stops counting toward the host's session
        // limit in the commit (N6). New outbound sessions are marked by
        // the plan.
        match transition.restart {
            Some(Nat44TcpDirection::Outbound) => {
                session.external_inbound = false;
                session.host_initiated = true;
            }
            Some(Nat44TcpDirection::Inbound) => {
                session.external_inbound = session.remote_address != self.config.public_address;
                session.host_initiated = false;
            }
            None => {}
        }
        session.last_activity_ms = now_ms;
        let established = session.phase() == Nat44TcpSessionPhase::Established;
        let released = u32::from(was_established) + u32::from(released_own_established);
        mapping.established_sessions = mapping
            .established_sessions
            .checked_sub(released)
            .ok_or(Nat44TcpPlanError::IndexCorrupt)?
            + u32::from(established);
        mapping.last_activity_ms = now_ms;
        let established_expiry = now_ms.saturating_add(policy.idle_ttl_ms);
        let transitory = now_ms.saturating_add(policy.transitory_bound_ms());
        if established {
            mapping.expires_ms = established_expiry;
            mapping.link.list = TcpMappingList::Established;
        } else {
            let keep_established = mapping.established_sessions != 0
                && mapping.link.list == TcpMappingList::Established
                && mapping.expires_ms > transitory;
            if !keep_established {
                mapping.expires_ms = transitory;
                mapping.link.list = TcpMappingList::Transitory;
            }
        }
        // Host-driven expiry (N3): the same rule, applied only to segments
        // the inside host sends on its own outbound-initiated sessions or
        // on established ones, and never to one that leaves the session in
        // the closing phase: a RST, or anything on a FIN-closed connection
        // (an ACK from TIME-WAIT), is what a host's stack sends in answer
        // to whatever a remote sends on the old 4-tuple, so it must not
        // keep the mapping counting (review M1). A value above `transitory`
        // can only come from an established refresh (time is monotonic),
        // so it plays the role of the established list. It is capped by
        // `expires_ms`, so it never outlives the mapping, and every change
        // sets it to `now` plus one of the two TTLs, keeping the host lists
        // in order.
        // Once the host has sent a FIN on an established session (a
        // half-close), its refresh uses the transitory timeout as if no
        // established session held the mapping, unless another one does: a
        // remote that never sends its own FIN keeps the session established
        // but must not keep it counting for the established timeout
        // (NAT44-096); a host still reading refreshes it with each ACK.
        let host_driven = direction == Nat44TcpDirection::Outbound
            && session.phase() != Nat44TcpSessionPhase::Closing
            && (!session.external_inbound || established);
        if host_driven {
            let half_closed = session.state & crate::nat44_tcp_state::STATE_FIN_OUT != 0;
            let other_established = mapping.established_sessions - u32::from(established);
            if established && !half_closed {
                mapping.host_expires_ms = established_expiry;
            } else if other_established == 0 || mapping.host_expires_ms <= transitory {
                mapping.host_expires_ms = transitory;
            }
        }
        mapping.host_expires_ms = mapping.host_expires_ms.min(mapping.expires_ms);
        Ok(())
    }

    /// The host list a TCP mapping with host-driven expiry `host_expires_ms`
    /// set at `now_ms` belongs on (N3): the established-TTL list or the
    /// transitory-TTL list, each in expiry order.
    fn host_list_at(&self, host_expires_ms: u64, now_ms: u64) -> usize {
        usize::from(host_expires_ms != now_ms.saturating_add(self.config.policy.idle_ttl_ms))
    }

    /// Whether `mapping` still counts as kept alive by its inside host
    /// (N3): before its host-driven expiry. A live mapping may be past it
    /// when only remotes kept it alive.
    fn mapping_is_host_live(&self, mapping: Nat44TcpMappingSlot, now_ms: u64) -> bool {
        mapping.occupied && now_ms >= mapping.last_activity_ms && now_ms < mapping.host_expires_ms
    }

    /// Release-build cross-check of a commit that reclaims an expired
    /// established session of another mapping: that mapping's established
    /// count must include it.
    fn released_count_matches(&self, session_index: usize, mapping_index: usize) -> bool {
        self.established_owner(self.sessions[session_index])
            .filter(|owner| *owner != mapping_index)
            .is_none_or(|owner| self.mappings[owner].established_sessions > 0)
    }

    /// The mapping slot whose established-session count includes
    /// `session`: the slot of its mapping when the session is occupied,
    /// established, and of that slot's current generation.
    fn established_owner(&self, session: Nat44TcpSessionSlot) -> Option<usize> {
        if !session.occupied || session.phase() != Nat44TcpSessionPhase::Established {
            return None;
        }
        self.mappings
            .get(session.mapping_index)
            .is_some_and(|mapping| {
                mapping.occupied
                    && mapping.generation == session.mapping_generation
                    && mapping.lifecycle_epoch == session.mapping_lifecycle_epoch
            })
            .then_some(session.mapping_index)
    }

    /// Commit-time bookkeeping of one session slot write, before the slot
    /// is overwritten: an expired established session that a new session
    /// replaces leaves its mapping's established count (unless that is the
    /// committing mapping, whose planned copy already accounts for it or
    /// which is being recreated), and the phase counters advance.
    fn record_session_commit(
        &mut self,
        session_index: usize,
        session: Nat44TcpSessionSlot,
        session_created: bool,
        mapping_index: usize,
    ) {
        let before = self.sessions[session_index];
        let before_state = if session_created {
            if before.occupied {
                if let Some(owner) = self
                    .established_owner(before)
                    .filter(|owner| *owner != mapping_index)
                {
                    let count = &mut self.mappings[owner].established_sessions;
                    debug_assert!(*count > 0);
                    *count = count.saturating_sub(1);
                }
                let counter = match before.phase() {
                    Nat44TcpSessionPhase::Opening => &mut self.counters.sessions_expired_opening,
                    Nat44TcpSessionPhase::Established => {
                        &mut self.counters.sessions_expired_established
                    }
                    Nat44TcpSessionPhase::Closing => &mut self.counters.sessions_expired_closing,
                };
                *counter = counter.saturating_add(1);
            }
            0
        } else {
            before.state
        };
        let (old, new) = (phase_of(before_state), session.phase());
        if new == Nat44TcpSessionPhase::Established && old != new {
            self.counters.sessions_established =
                self.counters.sessions_established.saturating_add(1);
        }
        let reset = crate::nat44_tcp_state::STATE_RESET;
        if session.state & reset != 0 && before_state & reset == 0 {
            self.counters.sessions_reset = self.counters.sessions_reset.saturating_add(1);
        }
        if session.state & reset == 0 && fin_closed(session.state) && !fin_closed(before_state) {
            self.counters.sessions_closed = self.counters.sessions_closed.saturating_add(1);
        }
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
            Nat44TcpPlanError::HostQuotaExceeded => {
                self.counters.host_quota_exceeded =
                    self.counters.host_quota_exceeded.saturating_add(1);
            }
            Nat44TcpPlanError::HostSessionQuotaExceeded => {
                self.counters.host_session_quota_exceeded =
                    self.counters.host_session_quota_exceeded.saturating_add(1);
            }
            Nat44TcpPlanError::InboundRemoteQuotaExceeded => {
                self.counters.inbound_remote_quota_exceeded = self
                    .counters
                    .inbound_remote_quota_exceeded
                    .saturating_add(1);
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

    pub(crate) fn record_hairpin_disabled(&mut self) {
        self.counters.hairpin_disabled = self.counters.hairpin_disabled.saturating_add(1);
    }

    pub(crate) fn record_hairpin_inbound_refused(&mut self) {
        self.counters.hairpin_inbound_refused =
            self.counters.hairpin_inbound_refused.saturating_add(1);
    }

    /// Read-only: does `public_port` belong to a live mapping? A hairpinned
    /// segment to an unknown public port commits nothing, not even its
    /// outbound half.
    pub(crate) fn hairpin_destination_is_live(
        &self,
        public_port: u16,
        now_ms: u64,
    ) -> Result<bool, Nat44TcpPlanError> {
        Ok(self.mapping_for_public_port(public_port, now_ms)?.is_some())
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

    /// Read-only authority for a quoted inbound TCP segment `remote ->
    /// internal` that an inside host received (RFC 5508 REQ-5, REQ-7). The
    /// internal endpoint must own a live mapping that still owns its public
    /// port, with a live session for the exact remote address and port.
    /// Returns the public port.
    pub(crate) fn inspect_icmpv4_inbound_quote(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        now_ms: u64,
    ) -> Result<u16, Nat44TcpPlanError> {
        self.check_now_read_only(now_ms)?;
        let Some((mapping_index, mapping)) = self.find_mapping(internal_address, internal_port)?
        else {
            return Err(Nat44TcpPlanError::MappingMiss);
        };
        if !self.mapping_is_live(mapping, now_ms) || !mapping.port_owned {
            return Err(Nat44TcpPlanError::MappingMiss);
        }
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
        Ok(mapping.public_port)
    }

    fn session_is_live(&self, session: Nat44TcpSessionSlot, now_ms: u64) -> bool {
        #[cfg(test)]
        self.session_liveness_checks
            .set(self.session_liveness_checks.get().saturating_add(1));
        session.occupied
            && now_ms >= session.last_activity_ms
            && now_ms < self.session_expires_ms(session)
    }

    /// When `session` expires: its last activity plus its phase's TTL.
    fn session_expires_ms(&self, session: Nat44TcpSessionSlot) -> u64 {
        session
            .last_activity_ms
            .saturating_add(self.config.policy.session_idle_ttl_ms(session.phase()))
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
        mapping.occupied && now_ms >= mapping.last_activity_ms && now_ms < mapping.expires_ms
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
        self.port_owners.take_bitmap_word_reads();
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

    /// The expired head of the two mapping activity lists that expired
    /// first (the established list on a tie), among mappings that still own
    /// their port. Each list is in expiry order, so some mapping on them is
    /// expired exactly when one of the heads is. Two liveness checks.
    fn expired_mapping_head(&self, now_ms: u64) -> Option<usize> {
        let lists = self.reuse_lists;
        [lists.mapping_established, lists.mapping_transitory]
            .into_iter()
            .filter_map(|list| {
                #[cfg(test)]
                self.reusable_mapping_checks
                    .set(self.reusable_mapping_checks.get().saturating_add(1));
                let head = list.head()?;
                let mapping = self.mappings[head];
                (!self.mapping_is_live(mapping, now_ms)).then_some((mapping.expires_ms, head))
            })
            .min_by_key(|(expires_ms, _)| *expires_ms)
            .map(|(_, head)| head)
    }

    /// A reusable (unoccupied or expired) mapping slot in O(1), or `None`
    /// exactly when every slot holds a live mapping. Expired slots are
    /// preferred over never-used ones, so occupancy keeps counting the
    /// distinct slots used since the flush.
    fn find_reusable_mapping(&self, now_ms: u64) -> Option<usize> {
        self.reuse_lists
            .mapping_retired
            .head()
            .or_else(|| self.expired_mapping_head(now_ms))
            .or_else(|| self.fresh_mapping())
    }

    /// The lowest never-used mapping slot, if any.
    fn fresh_mapping(&self) -> Option<usize> {
        let index = self.reuse_lists.next_fresh_mapping;
        (index < self.mappings.len()).then_some(index)
    }

    /// The lowest never-used session slot, if any.
    fn fresh_session(&self) -> Option<usize> {
        let index = self.reuse_lists.next_fresh_session;
        (index < self.sessions.len()).then_some(index)
    }

    /// A reusable session slot in O(1): of the three phase activity-list
    /// heads (each list has one TTL, so its head expires first), the
    /// reusable one that expired first, else the lowest never-used slot. A
    /// session's mapping is refreshed with it and never expires before it
    /// ([`Self::stamp_session`]), so a session whose mapping expired or was
    /// recreated has itself expired: `None` exactly when every session is
    /// live.
    fn find_reusable_session(&self, now_ms: u64) -> Option<usize> {
        self.reuse_lists
            .session_lru
            .iter()
            .filter_map(|list| list.head())
            .filter(|&head| self.session_slot_reusable(head, now_ms))
            .min_by_key(|&head| self.session_expires_ms(self.sessions[head]))
            .or_else(|| self.fresh_session())
    }

    fn session_slot_reusable(&self, index: usize, now_ms: u64) -> bool {
        #[cfg(test)]
        self.reusable_session_checks
            .set(self.reusable_session_checks.get().saturating_add(1));
        let session = self.sessions[index];
        !self.session_is_live(session, now_ms)
            || self
                .mappings
                .get(session.mapping_index)
                .is_none_or(|mapping| {
                    !mapping.occupied
                        || mapping.generation != session.mapping_generation
                        || mapping.lifecycle_epoch != session.mapping_lifecycle_epoch
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

    const fn session_address_lookup_words(
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

    const fn session_address_words(session: Nat44TcpSessionSlot) -> [u64; 5] {
        Self::session_address_lookup_words(
            session.mapping_index,
            session.mapping_generation,
            session.mapping_lifecycle_epoch,
            session.remote_address,
        )
    }

    /// Prepares keying `session` into slot `session_index` of both session
    /// directories. A slot is linked in both or in neither, so the previous
    /// occupancy selects link or relink for each.
    fn prepare_session_link(
        &self,
        session_index: usize,
        session: Nat44TcpSessionSlot,
    ) -> Result<PreparedNat44TcpSessionLink, Nat44TcpPlanError> {
        let occupied = self.sessions[session_index].occupied;
        let prepare = |directory: &FixedDirectory<'_>, domain, words: &[u64]| {
            if occupied {
                directory
                    .prepare_relink(session_index, domain, words)
                    .map(PreparedTcpDirectoryMutation::Relink)
            } else {
                directory
                    .prepare_link(session_index, domain, words)
                    .map(PreparedTcpDirectoryMutation::Link)
            }
            .map_err(|_| Nat44TcpPlanError::IndexCorrupt)
        };
        Ok(PreparedNat44TcpSessionLink {
            session: Some(prepare(
                &self.session_directory,
                DirectoryHashDomain::TcpSession,
                &Self::session_words(session),
            )?),
            address: Some(prepare(
                &self.session_address_directory,
                DirectoryHashDomain::TcpSessionAddress,
                &Self::session_address_words(session),
            )?),
        })
    }

    fn session_link_matches(&self, link: PreparedNat44TcpSessionLink) -> bool {
        link.session
            .is_none_or(|mutation| self.session_mutation_matches(mutation))
            && link
                .address
                .is_none_or(|mutation| self.session_address_mutation_matches(mutation))
    }

    fn apply_session_link(&mut self, link: PreparedNat44TcpSessionLink) {
        if let Some(mutation) = link.session {
            self.apply_session_mutation(mutation);
        }
        if let Some(mutation) = link.address {
            self.apply_session_address_mutation(mutation);
        }
    }

    fn session_address_mutation_matches(&self, mutation: PreparedTcpDirectoryMutation) -> bool {
        match mutation {
            PreparedTcpDirectoryMutation::Link(prepared) => self
                .session_address_directory
                .prepared_link_matches(prepared),
            PreparedTcpDirectoryMutation::Relink(prepared) => self
                .session_address_directory
                .prepared_relink_matches(prepared),
        }
    }

    fn apply_session_address_mutation(&mut self, mutation: PreparedTcpDirectoryMutation) {
        match mutation {
            PreparedTcpDirectoryMutation::Link(prepared) => {
                self.session_address_directory.apply_prepared_link(prepared);
            }
            PreparedTcpDirectoryMutation::Relink(prepared) => {
                self.session_address_directory
                    .apply_prepared_relink(prepared);
            }
        }
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
            self.prepare_session_link(plan.session_index(), plan.session)?
        } else {
            PreparedNat44TcpSessionLink::EMPTY
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
        self.session_address_directory
            .validate_semantics(|index| {
                let session = self.sessions[index];
                session.occupied.then(|| {
                    key.hash_words(
                        DirectoryHashDomain::TcpSessionAddress,
                        &Self::session_address_words(session),
                    )
                })
            })
            .map_err(Nat44TcpIndexInvariantError::SessionAddress)?;
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
            let mut established = 0_u32;
            for session in self.sessions.iter().copied().filter(|session| {
                session.occupied
                    && session.mapping_index == index
                    && session.mapping_generation == mapping.generation
                    && session.mapping_lifecycle_epoch == mapping.lifecycle_epoch
            }) {
                maximum = Some(maximum.map_or(session.last_activity_ms, |current: u64| {
                    current.max(session.last_activity_ms)
                }));
                if session.phase() == Nat44TcpSessionPhase::Established {
                    established += 1;
                }
                // A mapping never expires before one of its sessions.
                if self.session_expires_ms(session) > mapping.expires_ms {
                    return Err(Nat44TcpIndexInvariantError::MappingExpiresBeforeSession);
                }
            }
            if established != mapping.established_sessions {
                return Err(Nat44TcpIndexInvariantError::EstablishedCountMismatch);
            }
            // The mapping's activity is its latest commit, so no session of
            // it is more recent. Since N1 a live mapping may have no session
            // left (an expired established session kept it on the
            // established expiry, or its sessions expired on a shorter
            // phase TTL and were reclaimed), so neither equality nor the
            // presence of a session is an invariant any more.
            if maximum.is_some_and(|maximum| maximum > mapping.last_activity_ms) {
                return Err(Nat44TcpIndexInvariantError::MappingSummaryMismatch);
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
        if !self.reuse_lists_are_consistent() {
            return Err(Nat44TcpIndexInvariantError::ReuseLists);
        }
        // The host-driven expiry never outlives the mapping (N3), and a
        // counted mapping is on the host list of its host-driven expiry,
        // in that order.
        if self
            .mappings
            .iter()
            .any(|mapping| mapping.occupied && mapping.host_expires_ms > mapping.expires_ms)
        {
            return Err(Nat44TcpIndexInvariantError::Hosts);
        }
        if !self.hosts.validate(key, self.mappings.len(), |index| {
            let mapping = self.mappings[index];
            (mapping.occupied && mapping.port_owned).then(|| HostExpectation {
                address: mapping.internal_address,
                list: self.hosts.mapping_list(index).unwrap_or(usize::MAX),
                order: mapping.host_expires_ms,
                members: None,
                counted: None,
            })
        }) {
            return Err(Nat44TcpIndexInvariantError::Hosts);
        }
        if !self.session_hosts_are_consistent(key) {
            return Err(Nat44TcpIndexInvariantError::SessionHosts);
        }
        Ok(())
    }

    /// Full check of the per-host session accounting (N6, validation
    /// only): the host table's own structure (lists in host-driven expiry
    /// order, directory, empty list); a counted session is occupied and
    /// counts toward its mapping's internal address while that mapping is
    /// of its generation; its host-driven expiry never exceeds its own
    /// expiry; and a counted session whose mapping was recreated or retired
    /// is past its host-driven expiry (so it never blocks its host).
    #[cfg(test)]
    fn session_hosts_are_consistent(&self, key: DirectoryHashKey) -> bool {
        let current = |session: Nat44TcpSessionSlot| {
            self.mappings
                .get(session.mapping_index)
                .filter(|mapping| {
                    mapping.occupied
                        && mapping.generation == session.mapping_generation
                        && mapping.lifecycle_epoch == session.mapping_lifecycle_epoch
                })
                .copied()
        };
        if !self
            .session_hosts
            .validate(key, self.sessions.len(), |index| {
                let session = self.sessions[index];
                let host = self.session_hosts.mapping_host(index)?;
                let list = self.session_hosts.mapping_list(index)?;
                // Only an occupied session the host initiated counts.
                if !session.occupied || !session.host_initiated {
                    return None;
                }
                let address = current(session).map_or_else(
                    || self.session_hosts.address(host),
                    |mapping| mapping.internal_address,
                );
                let expiry = self.session_host_expiry(index)?;
                Some(HostExpectation {
                    address,
                    list,
                    order: expiry,
                    members: None,
                    counted: None,
                })
            })
        {
            return false;
        }
        (0..self.sessions.len()).all(|index| {
            let session = self.sessions[index];
            self.session_host_expiry(index).is_none_or(|expiry| {
                expiry <= self.session_expires_ms(session)
                    && (current(session).is_some()
                        || self.watermark_ms.is_some_and(|now_ms| expiry <= now_ms))
            })
        })
    }

    /// Exact O(M + S) check of the reuse sets (validation only): the fresh
    /// slots are exactly the default slots at and after each fresh
    /// boundary, the lists hold every other slot, each slot's list agrees
    /// with its state, activity lists are in `last_activity_ms` order, and
    /// retired mappings are expired.
    #[cfg(test)]
    fn reuse_lists_are_consistent(&self) -> bool {
        let lists = self.reuse_lists;
        let (Some(fresh_mappings), Some(fresh_sessions)) = (
            self.mappings.get(lists.next_fresh_mapping..),
            self.sessions.get(lists.next_fresh_session..),
        ) else {
            return false;
        };
        if fresh_mappings
            .iter()
            .any(|slot| *slot != Nat44TcpMappingSlot::default())
            || fresh_sessions
                .iter()
                .any(|slot| *slot != Nat44TcpSessionSlot::default())
            || self.mappings[..lists.next_fresh_mapping]
                .iter()
                .any(|slot| !slot.occupied)
            || self.sessions[..lists.next_fresh_session]
                .iter()
                .any(|slot| !slot.occupied)
        {
            return false;
        }
        let mut listed = fresh_mappings.len();
        let policy = self.config.policy;
        for (header, list) in [
            (lists.mapping_established, TcpMappingList::Established),
            (lists.mapping_transitory, TcpMappingList::Transitory),
            (lists.mapping_retired, TcpMappingList::Retired),
        ] {
            let mut previous_ms = 0;
            let consistent = header.validate(self.mappings, |index| {
                listed += 1;
                let mapping = self.mappings[index];
                let ordered = previous_ms <= mapping.expires_ms;
                previous_ms = mapping.expires_ms;
                mapping.link.list == list
                    && match list {
                        TcpMappingList::Free => false,
                        // Expiry is the list's TTL after a commit at or
                        // before the last activity (the last one for the
                        // transitory list).
                        TcpMappingList::Established => {
                            mapping.occupied
                                && mapping.port_owned
                                && ordered
                                && mapping.expires_ms >= policy.idle_ttl_ms
                                && mapping.expires_ms - policy.idle_ttl_ms
                                    <= mapping.last_activity_ms
                        }
                        TcpMappingList::Transitory => {
                            mapping.occupied
                                && mapping.port_owned
                                && ordered
                                && mapping.expires_ms
                                    == mapping
                                        .last_activity_ms
                                        .saturating_add(policy.transitory_bound_ms())
                        }
                        TcpMappingList::Retired => {
                            mapping.occupied
                                && !mapping.port_owned
                                && self
                                    .watermark_ms
                                    .is_none_or(|now_ms| !self.mapping_is_live(mapping, now_ms))
                        }
                    }
            });
            if !consistent {
                return false;
            }
        }
        if listed != self.mappings.len() {
            return false;
        }
        let mut listed = fresh_sessions.len();
        for (phase_index, header) in lists.session_lru.into_iter().enumerate() {
            let mut previous_ms = 0;
            if !header.validate(self.sessions, |index| {
                listed += 1;
                let session = self.sessions[index];
                let ordered = previous_ms <= session.last_activity_ms;
                previous_ms = session.last_activity_ms;
                session.occupied && ordered && session.phase().index() == phase_index
            }) {
                return false;
            }
        }
        listed == self.sessions.len()
    }

    /// Keyed port selection of this runtime ([`PortSelectionKey`]).
    const fn port_selection_key(&self) -> PortSelectionKey {
        PortSelectionKey {
            key: self.hash_key.0,
            start_domain: DirectoryHashDomain::TcpPortStart,
            takeover_domain: DirectoryHashDomain::TcpPortTakeover,
            ports: self.config.ports,
            inside: self.config.inside,
            public_address: self.config.public_address,
            allocator_seed: self.config.policy.allocator_seed,
        }
    }

    /// Public port of a new mapping (NAT44-004, NAT44-068, NAT44-020), in
    /// bounded work (at most 11 owner checks and 34 bitmap words), by the
    /// steps of the UDP allocator with the TCP hash domains:
    ///
    /// 1. with port preservation on (the default), the internal port, if in
    ///    the pool and unowned or owned by an expired mapping;
    /// 2. the port the same internal endpoint's expired mapping
    ///    (`previous`, recreated in place) still owns;
    /// 3. the first unowned port from a keyed start
    ///    ([`PortSelectionKey::search_start`]);
    /// 4. with every port owned, the port of an expired owner among
    ///    [`NAT44_PORT_TAKEOVER_PROBES`] keyed pseudorandom pool ports, else
    ///    the port of the expired activity head.
    ///
    /// `None` only when every port has a live owner.
    fn allocate_port(
        &self,
        internal_address: Ipv4Address,
        internal_port: u16,
        previous: Option<Nat44TcpMappingSlot>,
        now_ms: u64,
    ) -> Result<Option<Nat44TcpPortSelection>, Nat44TcpPlanError> {
        if self.config.policy.port_preservation && self.config.ports.contains(internal_port) {
            if let Some(selection) = self.select_port(internal_port, now_ms)? {
                return Ok(Some(selection));
            }
        }
        if let Some(previous) = previous.filter(|mapping| mapping.occupied && mapping.port_owned) {
            if let Some(selection) = self.select_port(previous.public_port, now_ms)? {
                return Ok(Some(selection));
            }
        }
        let key = self.port_selection_key();
        if let Some(port) = self
            .port_owners
            .first_unowned_port_from(key.search_start(internal_address, internal_port))
        {
            return self.select_port(port, now_ms);
        }
        // Every port has an owner: keyed probes for an expired owner, then
        // the port of the expired activity head, if any.
        for probe in 0..NAT44_PORT_TAKEOVER_PROBES {
            let port = key.takeover_port(
                internal_address,
                internal_port,
                self.next_generation,
                now_ms,
                probe,
            );
            if let Some(selection) = self.select_port(port, now_ms)? {
                return Ok(Some(selection));
            }
        }
        let Some(head) = self.expired_mapping_head(now_ms) else {
            return Ok(None);
        };
        let mapping = self.mappings[head];
        if !mapping.port_owned {
            return Err(Nat44TcpPlanError::IndexCorrupt);
        }
        self.select_port(mapping.public_port, now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Interface, LocalIpv4Binding, MacAddress, Neighbor, Route};

    // `nat44/tests/port_selection.rs`: keyed public-port selection (N2).
    mod port_selection;

    // `nat44/tests/host_quota.rs`: the per-host mapping quota (N3).
    mod host_quota;

    // `nat44/tests/host_peer_quota.rs`: the per-host peer limit (N6).
    mod host_peer_quota;

    // `nat44/tests/carry.rs`: state carried across a publication
    // (RELOAD-CARRY).
    mod carry;

    const INSIDE: IfId = IfId(1);
    const OUTSIDE: IfId = IfId(2);
    const INTERNAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
    const INTERNAL2: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 11]);
    const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
    const REMOTE1: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
    const REMOTE2: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 2]);
    const TEST_REMOTE_PORT: u16 = 53;

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
                mtu: 1500,
            },
            Interface {
                id: OUTSIDE,
                mac: MacAddress([2, 0, 0, 0, 0, 2]),
                mtu: 1500,
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

    fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
        if let Some(message) = payload.downcast_ref::<String>() {
            return message.clone();
        }
        payload
            .downcast_ref::<&str>()
            .map_or_else(String::new, |message| (*message).to_owned())
    }

    #[test]
    fn nat44_public_debug_redaction_is_exact_and_deterministic() {
        const POISON_SEED: u64 = 18_446_744_073_709_551_613;
        const POISON_AUTHORITY: u64 = 18_446_744_073_709_551_611;
        const POISON_POINTER: usize = usize::MAX - 6;

        let udp_policy = Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS, POISON_SEED)
            .unwrap()
            .with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly);
        let tcp_policy = Nat44TcpPolicy::new(NAT44_TCP_MIN_IDLE_TTL_MS, POISON_SEED)
            .unwrap()
            .with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly);

        assert_eq!(
            format!("{udp_policy:?}"),
            "Nat44UdpPolicy { idle_ttl_ms: 120000, allocator_seed: [REDACTED], \
             icmpv4_errors: ExternalOnly, filtering: AddressDependent, hairpinning: true, port_preservation: true, mappings_per_host: 0, peers_per_host: 0 }"
        );
        assert_eq!(
            format!("{udp_policy:#?}"),
            "Nat44UdpPolicy {\n    idle_ttl_ms: 120000,\n    allocator_seed: [REDACTED],\n    \
             icmpv4_errors: ExternalOnly,\n    filtering: AddressDependent,\n    hairpinning: true,\n    port_preservation: true,\n    mappings_per_host: 0,\n    peers_per_host: 0,\n}"
        );
        assert_eq!(
            format!("{tcp_policy:?}"),
            "Nat44TcpPolicy { idle_ttl_ms: 7440000, opening_idle_ttl_ms: 240000, \
             closing_idle_ttl_ms: 240000, allocator_seed: [REDACTED], \
             icmpv4_errors: ExternalOnly, filtering: AddressDependent, hairpinning: true, \
             inbound_sessions_per_remote: 0, unsolicited_syn_icmp: true, \
             inbound_rst: Closing, port_preservation: true, mappings_per_host: 0, sessions_per_host: 0 }"
        );
        assert_eq!(
            format!("{tcp_policy:#?}"),
            "Nat44TcpPolicy {\n    idle_ttl_ms: 7440000,\n    opening_idle_ttl_ms: 240000,\n    closing_idle_ttl_ms: 240000,\n    allocator_seed: [REDACTED],\n    \
             icmpv4_errors: ExternalOnly,\n    filtering: AddressDependent,\n    hairpinning: true,\n    \
             inbound_sessions_per_remote: 0,\n    unsolicited_syn_icmp: true,\n    inbound_rst: Closing,\n    port_preservation: true,\n    mappings_per_host: 0,\n    sessions_per_host: 0,\n}"
        );

        with_config(udp_policy, |udp_config| {
            let tcp_config = Nat44TcpConfig {
                inside: udp_config.inside,
                outside: udp_config.outside,
                public_address: udp_config.public_address,
                first_port: udp_config.first_port,
                last_port: udp_config.last_port,
                ports: udp_config.ports,
                policy: tcp_policy,
                authority: udp_config.authority,
                snapshot_identity: udp_config.snapshot_identity,
            };
            let mut poisoned_udp = udp_config;
            poisoned_udp.policy.allocator_seed = POISON_SEED - 2;
            poisoned_udp.authority = POISON_AUTHORITY;
            poisoned_udp.snapshot_identity = [POISON_POINTER; 8];
            let mut poisoned_tcp = tcp_config;
            poisoned_tcp.policy.allocator_seed = POISON_SEED - 4;
            poisoned_tcp.authority = POISON_AUTHORITY;
            poisoned_tcp.snapshot_identity = [POISON_POINTER; 8];

            assert_eq!(format!("{udp_config:?}"), format!("{poisoned_udp:?}"));
            assert_eq!(format!("{udp_config:#?}"), format!("{poisoned_udp:#?}"));
            assert_eq!(format!("{tcp_config:?}"), format!("{poisoned_tcp:?}"));
            assert_eq!(format!("{tcp_config:#?}"), format!("{poisoned_tcp:#?}"));
            assert_eq!(
                format!("{udp_config:?}"),
                "Nat44UdpConfig { inside: IfId(1), outside: IfId(2), public_address: \
                 Ipv4Address(3405803786), first_port: 40000, last_port: 40001, policy: \
                 Nat44UdpPolicy { idle_ttl_ms: 120000, allocator_seed: [REDACTED], \
                 icmpv4_errors: ExternalOnly, filtering: AddressDependent, hairpinning: true, port_preservation: true, mappings_per_host: 0, peers_per_host: 0 }, authority: \
                 [REDACTED], snapshot_identity: \
                 [REDACTED] }"
            );
            assert_eq!(
                format!("{tcp_config:?}"),
                "Nat44TcpConfig { inside: IfId(1), outside: IfId(2), public_address: \
                 Ipv4Address(3405803786), first_port: 40000, last_port: 40001, policy: \
                 Nat44TcpPolicy { idle_ttl_ms: 7440000, opening_idle_ttl_ms: 240000, \
                 closing_idle_ttl_ms: 240000, allocator_seed: [REDACTED], \
                 icmpv4_errors: ExternalOnly, filtering: AddressDependent, hairpinning: true, \
                 inbound_sessions_per_remote: 0, unsolicited_syn_icmp: true, inbound_rst: Closing, port_preservation: true, mappings_per_host: 0, sessions_per_host: 0 }, authority: \
                 [REDACTED], snapshot_identity: \
                 [REDACTED] }"
            );
            let udp_pretty = format!("{udp_config:#?}");
            let tcp_pretty = format!("{tcp_config:#?}");
            assert_eq!(
                udp_pretty,
                "Nat44UdpConfig {\n    inside: IfId(\n        1,\n    ),\n    outside: IfId(\n        \
                 2,\n    ),\n    public_address: Ipv4Address(\n        3405803786,\n    ),\n    \
                 first_port: 40000,\n    last_port: 40001,\n    policy: Nat44UdpPolicy {\n        \
                 idle_ttl_ms: 120000,\n        allocator_seed: [REDACTED],\n        icmpv4_errors: \
                 ExternalOnly,\n        filtering: AddressDependent,\n        hairpinning: true,\n        port_preservation: true,\n        mappings_per_host: 0,\n        peers_per_host: 0,\n    },\n    authority: \
                 [REDACTED],\n    snapshot_identity: \
                 [REDACTED],\n}"
            );
            assert_eq!(
                tcp_pretty,
                "Nat44TcpConfig {\n    inside: IfId(\n        1,\n    ),\n    outside: IfId(\n        \
                 2,\n    ),\n    public_address: Ipv4Address(\n        3405803786,\n    ),\n    \
                 first_port: 40000,\n    last_port: 40001,\n    policy: Nat44TcpPolicy {\n        \
                 idle_ttl_ms: 7440000,\n        opening_idle_ttl_ms: 240000,\n        closing_idle_ttl_ms: 240000,\n        allocator_seed: [REDACTED],\n        icmpv4_errors: \
                 ExternalOnly,\n        filtering: AddressDependent,\n        hairpinning: true,\n        \
                 inbound_sessions_per_remote: 0,\n        unsolicited_syn_icmp: true,\n        inbound_rst: Closing,\n        port_preservation: true,\n        mappings_per_host: 0,\n        sessions_per_host: 0,\n    },\n    authority: \
                 [REDACTED],\n    snapshot_identity: \
                 [REDACTED],\n}"
            );
            assert_eq!(udp_pretty.matches("[REDACTED]").count(), 3);
            assert_eq!(tcp_pretty.matches("[REDACTED]").count(), 3);
            assert!(udp_pretty.contains("\n    authority: [REDACTED],\n"));
            assert!(udp_pretty.contains("\n    snapshot_identity: [REDACTED],\n"));
            assert!(tcp_pretty.contains("\n    authority: [REDACTED],\n"));
            assert!(tcp_pretty.contains("\n    snapshot_identity: [REDACTED],\n"));

            #[derive(Debug)]
            #[allow(dead_code)]
            struct Nested<T> {
                value: T,
            }
            assert_eq!(
                format!("{:?}", Nested { value: udp_config }),
                format!(
                    "{:?}",
                    Nested {
                        value: poisoned_udp
                    }
                )
            );
            assert_eq!(
                format!("{:#?}", Nested { value: tcp_config }),
                format!(
                    "{:#?}",
                    Nested {
                        value: poisoned_tcp
                    }
                )
            );

            let mut safe_change = udp_config;
            safe_change.last_port -= 1;
            assert_ne!(format!("{udp_config:?}"), format!("{safe_change:?}"));

            let combined =
                format!("{poisoned_udp:?}{poisoned_udp:#?}{poisoned_tcp:?}{poisoned_tcp:#?}");
            for poison in [
                POISON_SEED.to_string(),
                format!("{POISON_SEED:x}"),
                POISON_AUTHORITY.to_string(),
                format!("{POISON_AUTHORITY:x}"),
                POISON_POINTER.to_string(),
                format!("{POISON_POINTER:x}"),
            ] {
                assert!(!combined.contains(&poison), "leaked poison marker");
            }
        });

        let panic = std::panic::catch_unwind(|| {
            assert_eq!(
                Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS, POISON_SEED).unwrap(),
                Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS, POISON_SEED - 1).unwrap()
            );
        })
        .unwrap_err();
        let panic = panic_message(panic);
        assert!(panic.contains("Nat44UdpPolicy"));
        assert!(panic.contains("[REDACTED]"));
        assert!(!panic.contains(&POISON_SEED.to_string()));
        assert!(!panic.contains(&format!("{POISON_SEED:x}")));
    }

    #[test]
    fn nat44_state_slot_debug_exposes_only_allowed_telemetry() {
        const POISON_U64: u64 = 18_446_744_073_709_551_613;
        const POISON_U128: u128 = 0xfedc_ba98_7654_3210_0123_4567_89ab_cdef;
        const POISON_INDEX: usize = usize::MAX - 8;
        const POISON_ADDRESS: Ipv4Address = Ipv4Address::from_octets([253, 252, 251, 250]);

        let udp_mapping = Nat44UdpMappingSlot {
            occupied: true,
            generation: POISON_U64,
            lifecycle_epoch: POISON_U128,
            port_owned: true,
            inside: INSIDE,
            internal_address: POISON_ADDRESS,
            internal_port: 65_533,
            public_port: 40_001,
            last_outbound_ms: 77,
            link: UdpMappingLink::default(),
        };
        let mut udp_mapping_hidden = udp_mapping;
        udp_mapping_hidden.generation -= 1;
        udp_mapping_hidden.lifecycle_epoch -= 1;
        udp_mapping_hidden.port_owned = false;
        udp_mapping_hidden.internal_address = INTERNAL2;
        udp_mapping_hidden.internal_port = 65_531;
        assert_eq!(
            format!("{udp_mapping:?}"),
            "Nat44UdpMappingSlot { occupied: true, inside: IfId(1), public_port: 40001, \
             last_outbound_ms: 77, .. }"
        );
        assert_eq!(
            format!("{udp_mapping:#?}"),
            "Nat44UdpMappingSlot {\n    occupied: true,\n    inside: IfId(\n        1,\n    ),\n    \
             public_port: 40001,\n    last_outbound_ms: 77,\n    ..\n}"
        );
        assert_eq!(
            format!("{udp_mapping:?}"),
            format!("{udp_mapping_hidden:?}")
        );

        let udp_peer = Nat44UdpPeerSlot {
            occupied: true,
            mapping_index: POISON_INDEX,
            mapping_generation: POISON_U64,
            mapping_lifecycle_epoch: POISON_U128,
            remote_address: POISON_ADDRESS,
            remote_port: 0xbeef,
            next: LINK_NONE,
        };
        let mut udp_peer_hidden = udp_peer;
        udp_peer_hidden.remote_port -= 1;
        udp_peer_hidden.mapping_index -= 1;
        udp_peer_hidden.mapping_generation -= 1;
        udp_peer_hidden.mapping_lifecycle_epoch -= 1;
        udp_peer_hidden.remote_address = REMOTE2;
        assert_eq!(
            format!("{udp_peer:?}"),
            "Nat44UdpPeerSlot { occupied: true, .. }"
        );
        assert_eq!(
            format!("{udp_peer:#?}"),
            "Nat44UdpPeerSlot {\n    occupied: true,\n    ..\n}"
        );
        assert_eq!(format!("{udp_peer:?}"), format!("{udp_peer_hidden:?}"));

        let tcp_mapping = Nat44TcpMappingSlot {
            occupied: true,
            generation: POISON_U64,
            lifecycle_epoch: POISON_U128,
            port_owned: true,
            inside: INSIDE,
            internal_address: POISON_ADDRESS,
            internal_port: 65_533,
            public_port: 40_001,
            established_sessions: 7,
            last_activity_ms: 88,
            expires_ms: POISON_U64,
            link: TcpMappingLink::default(),
            host_expires_ms: 0,
        };
        let mut tcp_mapping_hidden = tcp_mapping;
        tcp_mapping_hidden.generation -= 1;
        tcp_mapping_hidden.lifecycle_epoch -= 1;
        tcp_mapping_hidden.port_owned = false;
        tcp_mapping_hidden.internal_address = INTERNAL2;
        tcp_mapping_hidden.internal_port = 65_531;
        assert_eq!(
            format!("{tcp_mapping:?}"),
            "Nat44TcpMappingSlot { occupied: true, inside: IfId(1), public_port: 40001, \
             last_activity_ms: 88, .. }"
        );
        assert_eq!(
            format!("{tcp_mapping:?}"),
            format!("{tcp_mapping_hidden:?}")
        );
        assert_eq!(
            format!("{tcp_mapping:#?}"),
            "Nat44TcpMappingSlot {\n    occupied: true,\n    inside: IfId(\n        1,\n    ),\n    \
             public_port: 40001,\n    last_activity_ms: 88,\n    ..\n}"
        );

        let tcp_session = Nat44TcpSessionSlot {
            occupied: true,
            mapping_index: POISON_INDEX,
            mapping_generation: POISON_U64,
            mapping_lifecycle_epoch: POISON_U128,
            remote_address: POISON_ADDRESS,
            remote_port: 65_529,
            last_activity_ms: 99,
            external_inbound: true,
            host_initiated: false,
            state: 0x7f,
            links: SlotLinks::UNLINKED,
        };
        let mut tcp_session_hidden = tcp_session;
        tcp_session_hidden.mapping_index -= 1;
        tcp_session_hidden.mapping_generation -= 1;
        tcp_session_hidden.mapping_lifecycle_epoch -= 1;
        tcp_session_hidden.remote_address = REMOTE2;
        tcp_session_hidden.remote_port = 65_527;
        assert_eq!(
            format!("{tcp_session:?}"),
            "Nat44TcpSessionSlot { occupied: true, last_activity_ms: 99, .. }"
        );
        assert_eq!(
            format!("{tcp_session:#?}"),
            "Nat44TcpSessionSlot {\n    occupied: true,\n    last_activity_ms: 99,\n    ..\n}"
        );
        assert_eq!(
            format!("{tcp_session:?}"),
            format!("{tcp_session_hidden:?}")
        );

        let backing = Nat44UdpBackingIdentity {
            address: POISON_INDEX,
            length: POISON_INDEX - 2,
        };
        let other_backing = Nat44UdpBackingIdentity {
            address: 1,
            length: 2,
        };
        assert_eq!(
            format!("{backing:?}"),
            "Nat44UdpBackingIdentity([REDACTED])"
        );
        assert_eq!(
            format!("{backing:#?}"),
            "Nat44UdpBackingIdentity([REDACTED])"
        );
        assert_eq!(format!("{backing:?}"), format!("{other_backing:?}"));

        #[derive(Debug)]
        #[allow(dead_code)]
        struct SlotSet {
            udp_mapping: Nat44UdpMappingSlot,
            udp_peer: Nat44UdpPeerSlot,
            tcp_mapping: Nat44TcpMappingSlot,
            tcp_session: Nat44TcpSessionSlot,
            backing: Nat44UdpBackingIdentity,
        }
        let nested = format!(
            "{:#?}",
            SlotSet {
                udp_mapping,
                udp_peer,
                tcp_mapping,
                tcp_session,
                backing,
            }
        );
        for poison in [
            POISON_U64.to_string(),
            format!("{POISON_U64:x}"),
            POISON_U128.to_string(),
            format!("{POISON_U128:x}"),
            POISON_INDEX.to_string(),
            format!("{POISON_INDEX:x}"),
            "253.252.251.250".to_owned(),
            "65533".to_owned(),
            "65529".to_owned(),
        ] {
            assert!(!nested.contains(&poison), "leaked poison marker");
        }

        let mut safe_change = tcp_session;
        safe_change.last_activity_ms += 1;
        assert_ne!(format!("{tcp_session:?}"), format!("{safe_change:?}"));
    }

    #[test]
    fn nat44_debug_source_boundary_is_explicit_and_panic_payloads_are_static() {
        fn assert_custom_debug(source: &str, declaration: &str) {
            let declaration = source
                .find(declaration)
                .unwrap_or_else(|| panic!("missing declaration: {declaration}"));
            let tests = source
                .rfind("#[cfg(test)]\nmod tests {")
                .expect("source has final test module");
            assert!(
                declaration < tests,
                "matched test text instead of production"
            );
            for line in source[..declaration].lines().rev() {
                let line = line.trim();
                if line.is_empty() || line.starts_with("///") {
                    continue;
                }
                if line.starts_with("#[") {
                    assert!(
                        !(line.starts_with("#[derive(") && line.contains("Debug")),
                        "{declaration} must not derive Debug"
                    );
                    continue;
                }
                break;
            }
        }

        fn assert_no_debug_surface(source: &str, declaration: &str, type_name: &str) {
            assert_custom_debug(source, declaration);
            assert!(
                !source.contains(&format!("Debug for {type_name}")),
                "{type_name} must remain non-debuggable"
            );
        }

        fn type_block<'a>(source: &'a str, declaration: &str) -> &'a str {
            let start = source
                .find(declaration)
                .unwrap_or_else(|| panic!("missing declaration: {declaration}"));
            let tests = source
                .rfind("#[cfg(test)]\nmod tests {")
                .expect("source has final test module");
            assert!(start < tests, "matched test text instead of production");
            let remainder = &source[start..tests];
            let end = [
                "\n\n#[derive",
                "\n\nimpl ",
                "\n\n#[cfg",
                "\n\n///",
                "\n\npub(",
                "\n\npub ",
                "\n\nstruct ",
                "\n\nenum ",
                "\n\nfn ",
            ]
            .into_iter()
            .filter_map(|boundary| remainder.find(boundary))
            .min()
            .unwrap_or(remainder.len());
            &remainder[..end]
        }

        fn assert_contains_no_hidden_type(source: &str, declaration: &str) {
            let block = type_block(source, declaration);
            for hidden in [
                "Nat44UdpPolicy",
                "Nat44TcpPolicy",
                "Nat44UdpConfig",
                "Nat44TcpConfig",
                "Nat44UdpHashKey",
                "Nat44TcpHashKey",
                "Nat44UdpMappingSlot",
                "Nat44UdpPeerSlot",
                "Nat44TcpMappingSlot",
                "Nat44TcpSessionSlot",
                "Nat44UdpBackingIdentity",
                "DirectoryBucket",
                "DirectoryNode",
                "PortOwnerSlot",
                "PortOwnerToken",
                "PortOwnerExpectation",
            ] {
                assert!(
                    !block.contains(hidden),
                    "{declaration} unexpectedly nests hidden {hidden}"
                );
            }
        }

        fn public_field_names<'a>(source: &'a str, declaration: &str) -> Vec<&'a str> {
            type_block(source, declaration)
                .lines()
                .filter_map(|line| {
                    line.trim()
                        .strip_prefix("pub ")
                        .and_then(|field| field.split_once(':'))
                        .map(|(name, _)| name)
                })
                .collect()
        }

        let nat_source = include_str!("nat44.rs");
        let directory_source = include_str!("fixed_directory.rs");
        for declaration in [
            "pub struct Nat44UdpPolicy",
            "pub struct Nat44TcpPolicy",
            "pub struct Nat44UdpConfig",
            "pub struct Nat44TcpConfig",
            "pub struct Nat44UdpMappingSlot",
            "pub struct Nat44UdpPeerSlot",
            "pub struct Nat44TcpMappingSlot",
            "pub struct Nat44TcpSessionSlot",
            "struct Nat44UdpBackingIdentity",
        ] {
            assert_custom_debug(nat_source, declaration);
        }
        for declaration in [
            "pub struct DirectoryBucket",
            "pub struct DirectoryNode",
            "pub struct PortOwnerSlot",
            "pub(crate) struct PortOwnerToken",
            "pub(crate) struct PortOwnerExpectation",
        ] {
            assert_custom_debug(directory_source, declaration);
        }
        for (declaration, type_name) in [
            (
                "struct Nat44UdpReconcileBinding",
                "Nat44UdpReconcileBinding",
            ),
            ("struct Nat44TcpRuntimeBinding", "Nat44TcpRuntimeBinding"),
            ("pub struct Nat44UdpIndexStorage", "Nat44UdpIndexStorage"),
            ("pub struct Nat44TcpIndexStorage", "Nat44TcpIndexStorage"),
            ("pub struct Nat44UdpRuntime", "Nat44UdpRuntime"),
            ("pub struct Nat44TcpRuntime", "Nat44TcpRuntime"),
            (
                "pub struct Nat44UdpReconcilePermit",
                "Nat44UdpReconcilePermit",
            ),
            (
                "pub struct Nat44TcpReconcilePermit",
                "Nat44TcpReconcilePermit",
            ),
        ] {
            assert_no_debug_surface(nat_source, declaration, type_name);
        }

        // These are deliberate caller-selected telemetry, unlike accidental
        // formatting of long-lived configuration, state, and backing storage.
        for declaration in [
            "pub enum Nat44UdpDisposition",
            "pub enum Nat44TcpDisposition",
            "pub struct Nat44UdpCounters",
            "pub struct Nat44TcpCounters",
            "pub struct Nat44UdpReconcileReport",
            "pub struct Nat44TcpReconcileReport",
            "pub struct Nat44UdpStorageShape",
            "pub struct Nat44TcpStorageShape",
            "pub(crate) enum Nat44UdpPlanError",
            "pub(crate) enum Nat44TcpPlanError",
            "pub(crate) enum Nat44UdpCommitError",
            "pub(crate) enum Nat44TcpCommitError",
            "pub enum Nat44UdpRuntimeConfigError",
            "pub enum Nat44TcpRuntimeConfigError",
            "pub enum Nat44UdpReconcileError",
            "pub enum Nat44TcpReconcileError",
        ] {
            assert_contains_no_hidden_type(nat_source, declaration);
        }
        for declaration in [
            "pub(crate) enum DirectoryLookupError",
            "pub(crate) struct DirectoryProbe",
            "pub(crate) struct DirectoryConservation",
            "pub(crate) enum DirectorySemanticError",
            "pub(crate) struct PortOwnerConservation",
            "pub(crate) enum PortOwnerSemanticError",
        ] {
            assert_contains_no_hidden_type(directory_source, declaration);
        }

        assert_eq!(
            public_field_names(nat_source, "pub struct Nat44UdpCounters"),
            [
                "mappings_created",
                "mappings_reused",
                "mappings_expired",
                "peers_created",
                "outbound_translated",
                "inbound_translated",
                "mapping_misses",
                "filter_denied",
                "mapping_full",
                "peer_full",
                "port_exhausted",
                "clock_regressions",
                "config_mismatches",
                "reconciliations",
                "hairpin_translated",
                "hairpin_inbound_refused",
                "hairpin_disabled",
                "host_quota_exceeded",
                "host_peer_quota_exceeded",
            ]
        );
        assert_eq!(
            public_field_names(nat_source, "pub struct Nat44TcpCounters"),
            [
                "mappings_created",
                "mappings_reused",
                "mappings_expired",
                "sessions_created",
                "inbound_sessions_created",
                "sessions_reused",
                "sessions_expired",
                "outbound_translated",
                "inbound_translated",
                "mapping_misses",
                "session_misses",
                "invalid_initial_flags",
                "mapping_full",
                "session_full",
                "port_exhausted",
                "clock_regressions",
                "config_mismatches",
                "reconciliations",
                "hairpin_translated",
                "hairpin_inbound_refused",
                "hairpin_disabled",
                "inbound_remote_quota_exceeded",
                "unsolicited_syn_held",
                "unsolicited_syn_refreshed",
                "unsolicited_syn_hold_full",
                "unsolicited_syn_ineligible",
                "unsolicited_syn_cancelled",
                "unsolicited_syn_superseded",
                "unsolicited_syn_icmp_queued",
                "unsolicited_syn_icmp_suppressed",
                "unsolicited_syn_firewall_denied",
                "unsolicited_syn_index_corrupt",
                "sessions_established",
                "sessions_closed",
                "sessions_reset",
                "sessions_expired_opening",
                "sessions_expired_established",
                "sessions_expired_closing",
                "host_quota_exceeded",
                "host_session_quota_exceeded",
            ]
        );
        assert_eq!(
            public_field_names(nat_source, "pub struct Nat44UdpReconcileReport"),
            [
                "mappings_flushed",
                "peers_flushed",
                "mappings_carried",
                "peers_carried",
                "outcome"
            ]
        );
        assert_eq!(
            public_field_names(nat_source, "pub struct Nat44TcpReconcileReport"),
            [
                "mappings_flushed",
                "sessions_flushed",
                "mappings_carried",
                "sessions_carried",
                "outcome"
            ]
        );
        assert_eq!(
            type_block(nat_source, "pub struct Nat44UdpStorageShape")
                .lines()
                .filter_map(|line| {
                    let line = line.trim();
                    line.strip_suffix(':')
                        .or_else(|| line.split_once(':').map(|(name, _)| name))
                        .filter(|name| !name.starts_with("pub struct"))
                })
                .collect::<Vec<_>>(),
            [
                "mapping_slots",
                "peer_slots",
                "mapping_buckets",
                "mapping_nodes",
                "peer_buckets",
                "peer_nodes",
                "port_owner_slots",
                "port_bitmap_words",
                "host_slots",
                "host_buckets",
                "host_nodes",
            ]
        );
        assert_eq!(
            type_block(nat_source, "pub struct Nat44TcpStorageShape")
                .lines()
                .filter_map(|line| {
                    let line = line.trim();
                    line.strip_suffix(':')
                        .or_else(|| line.split_once(':').map(|(name, _)| name))
                        .filter(|name| !name.starts_with("pub struct"))
                })
                .collect::<Vec<_>>(),
            [
                "mapping_slots",
                "session_slots",
                "mapping_buckets",
                "mapping_nodes",
                "session_buckets",
                "session_nodes",
                "session_address_buckets",
                "session_address_nodes",
                "port_owner_slots",
                "port_bitmap_words",
                "unsolicited_syn_hold_slots",
                "host_slots",
                "host_buckets",
                "host_nodes",
                "session_host_slots",
                "session_host_buckets",
                "session_host_nodes",
            ]
        );

        let before_tcp_tests = nat_source
            .split_once("#[cfg(test)]\nmod tcp_tests {")
            .unwrap()
            .0;
        let after_tcp_tests = nat_source
            .split_once("pub enum Nat44UdpPolicyError")
            .unwrap()
            .1
            .split_once("#[cfg(test)]\nmod tests {")
            .unwrap()
            .0;
        let directory_production = directory_source
            .split_once("#[cfg(test)]\nmod tests {")
            .unwrap()
            .0;
        for production in [before_tcp_tests, after_tcp_tests, directory_production] {
            for forbidden in ["panic!(", "assert_eq!(", "assert_ne!("] {
                assert!(
                    !production.contains(forbidden),
                    "production formatting must not use dynamic {forbidden}"
                );
            }
            for line in production.lines().filter(|line| line.contains(".expect(")) {
                assert!(
                    line.contains(".expect(\""),
                    "production expect payload must be a static literal: {line}"
                );
            }
        }
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
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
            assert_eq!(first.public_port(), 40_000);
            runtime.commit_outbound(first, 0).unwrap();
            let second = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE2, TEST_REMOTE_PORT, 1)
                .unwrap();
            assert_eq!(second.public_port(), 40_000);
            runtime.commit_outbound(second, 1).unwrap();
            assert!(runtime
                .plan_inbound(40_000, REMOTE1, TEST_REMOTE_PORT, 2)
                .is_ok());
            assert!(runtime
                .plan_inbound(40_000, REMOTE2, TEST_REMOTE_PORT, 2)
                .is_ok());

            assert!(matches!(
                runtime.plan_inbound(
                    40_000,
                    REMOTE1,
                    TEST_REMOTE_PORT,
                    NAT44_UDP_MIN_IDLE_TTL_MS + 1
                ),
                Err(Nat44UdpPlanError::MappingMiss)
            ));
            let reused = runtime
                .plan_outbound(
                    INTERNAL2,
                    40_000,
                    REMOTE2,
                    TEST_REMOTE_PORT,
                    NAT44_UDP_MIN_IDLE_TTL_MS + 1,
                )
                .unwrap();
            runtime
                .commit_outbound(reused, NAT44_UDP_MIN_IDLE_TTL_MS + 1)
                .unwrap();
            assert!(matches!(
                runtime.plan_inbound(
                    reused.public_port(),
                    REMOTE1,
                    TEST_REMOTE_PORT,
                    NAT44_UDP_MIN_IDLE_TTL_MS + 1
                ),
                Err(Nat44UdpPlanError::FilterDenied)
            ));
            assert!(runtime
                .plan_inbound(
                    reused.public_port(),
                    REMOTE2,
                    TEST_REMOTE_PORT,
                    NAT44_UDP_MIN_IDLE_TTL_MS + 1
                )
                .is_ok());
        });
    }

    #[test]
    fn udp_peer_granularity_follows_filtering_and_bounds_icmp_authority() {
        for filtering in [
            Nat44Filtering::EndpointIndependent,
            Nat44Filtering::AddressDependent,
            Nat44Filtering::AddressAndPortDependent,
        ] {
            let policy = Nat44UdpPolicy::default().with_filtering(filtering);
            with_config(policy, |config| {
                let mut mappings = [Nat44UdpMappingSlot::default(); 1];
                let mut peers = [Nat44UdpPeerSlot::default(); 2];
                let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
                let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
                for (now, remote_port) in [(0, 53), (1, 5353)] {
                    let plan = runtime
                        .plan_outbound(INTERNAL, 40_000, REMOTE1, remote_port, now)
                        .unwrap();
                    runtime.commit_outbound(plan, now).unwrap();
                }
                assert_eq!(runtime.validate_indexes(), Ok(()));
                let port_dependent = filtering == Nat44Filtering::AddressAndPortDependent;
                let keys: Vec<_> = runtime
                    .peers()
                    .iter()
                    .filter(|peer| peer.is_occupied())
                    .map(|peer| (peer.remote_address(), peer.remote_port()))
                    .collect();
                if port_dependent {
                    assert_eq!(keys, [(REMOTE1, 53), (REMOTE1, 5353)]);
                } else {
                    // Address-granular key: port zero, one peer.
                    assert_eq!(keys, [(REMOTE1, 0)]);
                }

                // ICMP authority uses the recorded peers at their key
                // granularity, so endpoint-independent inbound filtering
                // does not admit quotes toward an uncontacted address.
                assert!(runtime.inspect_icmpv4(40_000, REMOTE1, 53, 2).is_ok());
                assert_eq!(
                    runtime.inspect_icmpv4(40_000, REMOTE1, 9999, 2).err(),
                    port_dependent.then_some(Nat44UdpPlanError::FilterDenied)
                );
                assert_eq!(
                    runtime.inspect_icmpv4(40_000, REMOTE2, 53, 2).err(),
                    Some(Nat44UdpPlanError::FilterDenied)
                );
                let peer_probes = runtime.peer_lookup_probes.get();
                let inbound = runtime.plan_inbound(40_000, REMOTE2, 53, 2);
                if filtering == Nat44Filtering::EndpointIndependent {
                    assert!(inbound.is_ok());
                    // Endpoint-independent admission does no peer lookup.
                    assert_eq!(runtime.peer_lookup_probes.get(), peer_probes);
                } else {
                    assert_eq!(inbound.err(), Some(Nat44UdpPlanError::FilterDenied));
                }
            });
        }
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
                empty.inspect_icmpv4(40_000, REMOTE1, TEST_REMOTE_PORT, 0),
                Err(Nat44UdpPlanError::MappingMiss)
            ));

            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut runtime_indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = runtime_indexes.runtime(config, &mut mappings, &mut peers);
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 100)
                .unwrap();
            runtime.commit_outbound(first, 100).unwrap();
            let before_mapping = runtime.mappings()[0];
            let before_peer = runtime.peers()[0];
            let before_counters = runtime.counters();
            assert!(matches!(
                runtime.inspect_icmpv4(40_000, REMOTE1, TEST_REMOTE_PORT, 99),
                Err(Nat44UdpPlanError::ClockRegression)
            ));
            for now in [100, 100 + NAT44_UDP_MIN_IDLE_TTL_MS - 1] {
                let lookup = runtime
                    .inspect_icmpv4(40_000, REMOTE1, TEST_REMOTE_PORT, now)
                    .unwrap();
                assert_eq!(lookup.internal_address(), INTERNAL);
                assert_eq!(lookup.internal_port(), 40_000);
            }
            assert!(matches!(
                runtime.inspect_icmpv4(
                    40_000,
                    REMOTE1,
                    TEST_REMOTE_PORT,
                    100 + NAT44_UDP_MIN_IDLE_TTL_MS
                ),
                Err(Nat44UdpPlanError::MappingMiss)
            ));
            assert!(runtime
                .inspect_icmpv4(40_000, REMOTE1, TEST_REMOTE_PORT, 100)
                .is_ok());
            assert_eq!(runtime.mappings()[0], before_mapping);
            assert_eq!(runtime.peers()[0], before_peer);
            assert_eq!(runtime.counters(), before_counters);

            let reused = runtime
                .plan_outbound(
                    INTERNAL2,
                    40_000,
                    REMOTE2,
                    TEST_REMOTE_PORT,
                    100 + NAT44_UDP_MIN_IDLE_TTL_MS,
                )
                .unwrap();
            runtime
                .commit_outbound(reused, 100 + NAT44_UDP_MIN_IDLE_TTL_MS)
                .unwrap();
            assert!(matches!(
                runtime.inspect_icmpv4(
                    reused.public_port(),
                    REMOTE1,
                    TEST_REMOTE_PORT,
                    100 + NAT44_UDP_MIN_IDLE_TTL_MS
                ),
                Err(Nat44UdpPlanError::FilterDenied)
            ));
            assert!(runtime
                .inspect_icmpv4(
                    reused.public_port(),
                    REMOTE2,
                    TEST_REMOTE_PORT,
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
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 10)
                .unwrap();
            runtime.commit_outbound(first, 10).unwrap();
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE2, TEST_REMOTE_PORT, 20),
                Err(Nat44UdpPlanError::PeerFull)
            ));
            assert_eq!(runtime.mappings()[0].last_outbound_ms(), 10);
            assert!(matches!(
                runtime.plan_outbound(INTERNAL2, 40_001, REMOTE1, TEST_REMOTE_PORT, 20),
                Err(Nat44UdpPlanError::MappingFull)
            ));
            assert_eq!(runtime.mappings()[0].internal_address(), INTERNAL);

            let mut no_mappings = [];
            let mut one_peer = [Nat44UdpPeerSlot::default(); 1];
            let mut empty_indexes =
                TestNat44UdpIndexes::new(config, no_mappings.len(), one_peer.len());
            let mut empty = empty_indexes.runtime(config, &mut no_mappings, &mut one_peer);
            assert!(matches!(
                empty.plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 0),
                Err(Nat44UdpPlanError::MappingFull)
            ));
            let mut one_mapping = [Nat44UdpMappingSlot::default(); 1];
            let mut no_peers = [];
            let mut empty_indexes =
                TestNat44UdpIndexes::new(config, one_mapping.len(), no_peers.len());
            let mut empty = empty_indexes.runtime(config, &mut one_mapping, &mut no_peers);
            assert!(matches!(
                empty.plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 0),
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
            let last = runtime
                .plan_outbound(INTERNAL, 40_001, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
            assert_eq!(last.public_port(), 40_001);
            runtime.commit_outbound(last, 0).unwrap();

            // For INTERNAL2/50000 and seed zero the deterministic start is
            // offset one. It collides with 40001, wraps, and selects 40000.
            let wrapped = runtime
                .plan_outbound(INTERNAL2, 50_000, REMOTE1, TEST_REMOTE_PORT, 0)
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
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 100)
                .unwrap();
            runtime.commit_outbound(first, 100).unwrap();
            let before = runtime.mappings()[0];
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 99),
                Err(Nat44UdpPlanError::ClockRegression)
            ));
            assert_eq!(runtime.mappings()[0], before);
            assert_eq!(runtime.counters().clock_regressions, 1);
            let equal = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 100)
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
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
            runtime.commit_outbound(first, 0).unwrap();
            assert!(matches!(
                runtime.plan_inbound(40_000, REMOTE1, TEST_REMOTE_PORT, NAT44_UDP_MIN_IDLE_TTL_MS),
                Err(Nat44UdpPlanError::MappingMiss)
            ));
            assert!(matches!(
                runtime.plan_inbound(
                    40_000,
                    REMOTE1,
                    TEST_REMOTE_PORT,
                    NAT44_UDP_MIN_IDLE_TTL_MS - 1
                ),
                Err(Nat44UdpPlanError::ClockRegression)
            ));
            assert!(matches!(
                runtime.plan_inbound(40_000, REMOTE1, TEST_REMOTE_PORT, NAT44_UDP_MIN_IDLE_TTL_MS),
                Err(Nat44UdpPlanError::MappingMiss)
            ));
        });

        with_config(Nat44UdpPolicy::default(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut runtime_indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = runtime_indexes.runtime(config, &mut mappings, &mut peers);
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
            runtime.commit_outbound(first, 0).unwrap();
            assert!(matches!(
                runtime.plan_inbound(40_000, REMOTE2, TEST_REMOTE_PORT, 100),
                Err(Nat44UdpPlanError::FilterDenied)
            ));
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 99),
                Err(Nat44UdpPlanError::ClockRegression)
            ));
            assert!(runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 100)
                .is_ok());
        });

        with_config(Nat44UdpPolicy::default(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 2];
            let mut runtime_indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = runtime_indexes.runtime(config, &mut mappings, &mut peers);
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
            runtime.commit_outbound(first, 0).unwrap();
            assert!(matches!(
                runtime.plan_outbound(INTERNAL2, 40_001, REMOTE1, TEST_REMOTE_PORT, 200),
                Err(Nat44UdpPlanError::MappingFull)
            ));
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 199),
                Err(Nat44UdpPlanError::ClockRegression)
            ));
            assert!(runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 200)
                .is_ok());
        });
    }

    /// `(occupied, high_water, capacity)` of one table.
    fn udp_table(table: TableOccupancy) -> (usize, usize, usize) {
        (table.occupied(), table.high_water(), table.capacity())
    }

    /// The O(1) counters equal a full scan of the slots they count.
    fn assert_udp_occupancy_exact(runtime: &Nat44UdpRuntime<'_>) {
        let occupancy = runtime.occupancy();
        let mappings = runtime
            .mappings()
            .iter()
            .filter(|slot| slot.occupied)
            .count();
        let peers = runtime.peers().iter().filter(|slot| slot.occupied).count();
        assert_eq!(occupancy.mappings.occupied(), mappings);
        assert_eq!(occupancy.peers.occupied(), peers);
        for table in [occupancy.mappings, occupancy.peers] {
            assert!(table.occupied() <= table.high_water());
            assert!(table.high_water() <= table.capacity());
        }
    }

    fn udp_outbound(
        runtime: &mut Nat44UdpRuntime<'_>,
        internal: Ipv4Address,
        remote: Ipv4Address,
        now: u64,
    ) {
        let plan = runtime
            .plan_outbound(internal, 40_000, remote, TEST_REMOTE_PORT, now)
            .unwrap();
        runtime.commit_outbound(plan, now).unwrap();
        assert_udp_occupancy_exact(runtime);
    }

    #[test]
    fn udp_occupancy_is_exact_across_insert_expiry_reuse_and_flush() {
        let ttl = NAT44_UDP_MIN_IDLE_TTL_MS;
        let policy = Nat44UdpPolicy::new(ttl, 11).unwrap();
        with_config(policy, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 2];
            let mut peers = [Nat44UdpPeerSlot::default(); 3];
            let mut runtime_indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = runtime_indexes.runtime(config, &mut mappings, &mut peers);
            assert_eq!(udp_table(runtime.occupancy().mappings), (0, 0, 2));
            assert_eq!(udp_table(runtime.occupancy().peers), (0, 0, 3));

            // Insert: a mapping and its first filter peer, then a second peer.
            udp_outbound(&mut runtime, INTERNAL, REMOTE1, 0);
            assert_eq!(udp_table(runtime.occupancy().mappings), (1, 1, 2));
            assert_eq!(udp_table(runtime.occupancy().peers), (1, 1, 3));
            udp_outbound(&mut runtime, INTERNAL, REMOTE2, 1);
            // A refresh of existing state changes nothing.
            udp_outbound(&mut runtime, INTERNAL, REMOTE1, 1);
            assert_eq!(udp_table(runtime.occupancy().mappings), (1, 1, 2));
            assert_eq!(udp_table(runtime.occupancy().peers), (2, 2, 3));

            // Expiry is lazy: an expired mapping and its peers stay allocated
            // and counted, even after a refused lookup at the later time.
            assert!(matches!(
                runtime.plan_inbound(40_000, REMOTE1, TEST_REMOTE_PORT, ttl + 1),
                Err(Nat44UdpPlanError::MappingMiss)
            ));
            assert_eq!(runtime.occupancy().mappings.occupied(), 1);
            assert_eq!(runtime.occupancy().peers.occupied(), 2);

            // Reclaim: a new mapping reuses the expired slot in place and its
            // peer reuses a stale peer slot, so neither count moves.
            udp_outbound(&mut runtime, INTERNAL2, REMOTE1, ttl + 1);
            assert_eq!(runtime.counters().mappings_expired, 1);
            assert_eq!(udp_table(runtime.occupancy().mappings), (1, 1, 2));
            assert_eq!(udp_table(runtime.occupancy().peers), (2, 2, 3));
            // A second live mapping fills the free mapping slot.
            udp_outbound(&mut runtime, INTERNAL, REMOTE2, ttl + 1);
            assert_eq!(udp_table(runtime.occupancy().mappings), (2, 2, 2));
            assert!(runtime.occupancy().peers.occupied() >= 2);

            // Flush resets both counts and high-water marks.
            runtime.reconcile(config, rotated_udp_hash_key()).unwrap();
            assert_udp_occupancy_exact(&runtime);
            assert_eq!(udp_table(runtime.occupancy().mappings), (0, 0, 2));
            assert_eq!(udp_table(runtime.occupancy().peers), (0, 0, 3));
            // The next generation starts its own high-water mark.
            udp_outbound(&mut runtime, INTERNAL, REMOTE1, 0);
            assert_eq!(udp_table(runtime.occupancy().mappings), (1, 1, 2));
            assert_eq!(udp_table(runtime.occupancy().peers), (1, 1, 3));
        });
    }

    #[test]
    fn udp_occupancy_matches_a_scan_under_seeded_churn() {
        const MAPPINGS: usize = 5;
        const PEERS: usize = 7;
        let ttl = NAT44_UDP_MIN_IDLE_TTL_MS;
        with_config(Nat44UdpPolicy::new(ttl, 3).unwrap(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); MAPPINGS];
            let mut peers = [Nat44UdpPeerSlot::default(); PEERS];
            let mut runtime_indexes = TestNat44UdpIndexes::new(config, MAPPINGS, PEERS);
            let mut runtime = runtime_indexes.runtime(config, &mut mappings, &mut peers);
            let mut random = 7_u64;
            let mut now = 0;
            let mut previous = runtime.occupancy();
            let mut key = 1_u64;
            let mut peak = 0;
            for step in 0..2_000_u64 {
                random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                if step % 97 == 96 {
                    now += ttl / 2;
                }
                let host = 10 + ((random >> 33) % 6) as u8;
                let remote = 1 + ((random >> 41) % 4) as u8;
                let internal = Ipv4Address::from_octets([10, 0, 0, host]);
                let remote = Ipv4Address::from_octets([198, 51, 100, remote]);
                if let Ok(plan) = runtime.plan_outbound(internal, 40_000, remote, 53, now) {
                    runtime.commit_outbound(plan, now).unwrap();
                }
                if step % 500 == 499 {
                    key += 1;
                    let hash_key = Nat44UdpHashKey::new(key, key.rotate_left(17)).unwrap();
                    runtime.reconcile(config, hash_key).unwrap();
                    now = 0;
                    previous = runtime.occupancy();
                    assert_eq!(udp_table(previous.mappings), (0, 0, MAPPINGS));
                    assert_eq!(udp_table(previous.peers), (0, 0, PEERS));
                    continue;
                }
                assert_udp_occupancy_exact(&runtime);
                let current = runtime.occupancy();
                assert!(current.mappings.high_water() >= previous.mappings.high_water());
                assert!(current.peers.high_water() >= previous.peers.high_water());
                peak = peak.max(current.mappings.high_water());
                previous = current;
            }
            // The two-port pool, not the mapping table, bounds live mappings.
            let pool = config.ports.count();
            assert_eq!(peak, pool.min(MAPPINGS), "the churn fills the port pool");
        });
    }

    #[test]
    fn reconcile_flushes_every_mapping_and_peer_before_rebinding() {
        with_config(Nat44UdpPolicy::default(), |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut peers = [Nat44UdpPeerSlot::default(); 1];
            let mut runtime_indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = runtime_indexes.runtime(config, &mut mappings, &mut peers);
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
            runtime.commit_outbound(first, 0).unwrap();
            let stale = runtime
                .plan_inbound_read_only(40_000, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
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
                    mappings_carried: 0,
                    peers_carried: 0,
                    outcome: crate::StateCarryOutcome::FlushRequested,
                }
            );
            assert!(runtime.mappings().iter().all(|slot| !slot.occupied));
            assert!(runtime.peers().iter().all(|slot| !slot.occupied));
            assert!(matches!(
                runtime.plan_inbound(40_000, REMOTE1, TEST_REMOTE_PORT, 0),
                Err(Nat44UdpPlanError::MappingMiss)
            ));
            let recreated = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
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
            let plan = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
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
                    mappings_carried: 0,
                    peers_carried: 0,
                    outcome: crate::StateCarryOutcome::FlushRequested,
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
                0,
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
                link: UdpMappingLink::default(),
            };
            let occupied_peer = Nat44UdpPeerSlot {
                occupied: true,
                mapping_index: 0,
                mapping_generation: 9,
                mapping_lifecycle_epoch: 7,
                remote_address: REMOTE1,
                remote_port: 0,
                next: LINK_NONE,
            };
            let mut mappings = [occupied_mapping];
            let mut peers = [occupied_peer];
            let mut mapping_buckets = [DirectoryBucket::default(); 1];
            let mut no_mapping_nodes = [];
            let mut peer_buckets = [DirectoryBucket::default(); 1];
            let mut peer_nodes = [DirectoryNode::default(); 1];
            let mut owners = [PortOwnerSlot::default(); 2];
            let mut owner_bits = vec![0_u64; crate::port_free_bitmap_words(2)];
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
                &mut owner_bits,
                crate::nat44_host_quota::leaked_host_storage_of(2, HostTableKind::Members),
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
            let plan = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
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
                .plan_outbound_read_only(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
            let current = runtime
                .plan_outbound_read_only(INTERNAL2, 40_001, REMOTE2, TEST_REMOTE_PORT, 0)
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
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 1),
                Err(Nat44UdpPlanError::GenerationExhausted)
            ));
            assert_eq!(runtime.mappings(), &before_mappings);

            runtime.next_generation = 2;
            runtime.state_revision = u128::MAX;
            assert!(matches!(
                runtime.plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 1),
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
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
            runtime.commit_outbound(first, 0).unwrap();
            let second = runtime
                .plan_outbound(INTERNAL2, 40_001, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
            runtime.commit_outbound(second, 0).unwrap();
            assert_eq!(runtime.validate_indexes(), Ok(()));

            let replacement = runtime
                .plan_outbound(
                    Ipv4Address::from_octets([10, 0, 0, 12]),
                    40_001,
                    REMOTE2,
                    TEST_REMOTE_PORT,
                    NAT44_UDP_MIN_IDLE_TTL_MS,
                )
                .unwrap();
            // N2: the new endpoint recreates the slot of the expired mapping
            // whose port it takes, so the expired head (slot 0) keeps its
            // port instead of releasing it in expiry order.
            assert_eq!(replacement.mapping_index, 1);
            assert_eq!(replacement.displaced_port_mapping_index(), Some(1));
            runtime
                .commit_outbound(replacement, NAT44_UDP_MIN_IDLE_TTL_MS)
                .unwrap();
            assert!(runtime.mappings()[0].port_owned);
            assert_eq!(
                runtime.mappings()[1].internal_address,
                Ipv4Address::from_octets([10, 0, 0, 12])
            );
            assert_eq!(
                runtime
                    .mappings()
                    .iter()
                    .filter(|mapping| mapping.occupied && mapping.port_owned)
                    .map(|mapping| mapping.public_port)
                    .collect::<Vec<_>>(),
                vec![40_000, 40_001]
            );
            assert_eq!(runtime.validate_indexes(), Ok(()));

            let eim = runtime
                .plan_outbound(
                    Ipv4Address::from_octets([10, 0, 0, 12]),
                    40_001,
                    REMOTE1,
                    TEST_REMOTE_PORT,
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
            let first = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
            runtime.commit_outbound(first, 0).unwrap();
            let exact = runtime
                .plan_outbound(INTERNAL2, 40_001, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
            assert_eq!(exact.mapping_index, 1);
            runtime.commit_outbound(exact, 0).unwrap();

            let recreated = runtime
                .plan_outbound(
                    INTERNAL2,
                    40_001,
                    REMOTE2,
                    TEST_REMOTE_PORT,
                    NAT44_UDP_MIN_IDLE_TTL_MS,
                )
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
    fn collision_probes_are_capacity_bounded_and_port_search_is_bounded() {
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
                let plan = runtime
                    .plan_outbound(INTERNAL, port, remote, TEST_REMOTE_PORT, 0)
                    .unwrap();
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
                runtime.plan_outbound(
                    Ipv4Address::from_octets([10, 0, 0, 99]),
                    40_000,
                    REMOTE1,
                    TEST_REMOTE_PORT,
                    0,
                ),
                Err(Nat44UdpPlanError::PortExhausted)
            ));
            // Exhaustion is decided without walking the pool: one owner
            // check for the preserved port, one bitmap search, the keyed
            // takeover probes, and no expired owner to take.
            let (_, _, owner_probes) = runtime.index_probe_counts();
            assert_eq!(owner_probes, 1 + NAT44_PORT_TAKEOVER_PROBES);
            assert!(runtime.port_owners.take_bitmap_word_reads() <= 3);
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
                    &Nat44UdpRuntime::peer_lookup_words(0, 1, 1, REMOTE1, 0),
                )
                .unwrap();
            let colliding_remotes = (1..=254)
                .map(|last| Ipv4Address::from_octets([198, 51, 100, last]))
                .filter(|remote| {
                    runtime.peer_directory.bucket_for_words(
                        DirectoryHashDomain::UdpPeer,
                        &Nat44UdpRuntime::peer_lookup_words(0, 1, 1, *remote, 0),
                    ) == Some(target_bucket)
                })
                .take(4)
                .collect::<Vec<_>>();
            assert_eq!(colliding_remotes.len(), 4);
            for remote in colliding_remotes.iter().copied() {
                let plan = runtime
                    .plan_outbound(INTERNAL, 40_000, remote, TEST_REMOTE_PORT, 0)
                    .unwrap();
                runtime.commit_outbound(plan, 0).unwrap();
            }
            runtime.reset_index_probe_counts();
            assert!(runtime.peer_exists(0, 1, colliding_remotes[0], 0).unwrap());
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

    fn next_random(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = *state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    /// Model of the port rule (NAT44-004, NAT44-068), computed by walking
    /// the pool: `Some(port)` when determined, `None` when only ports of
    /// expired owners remain (any of them is correct), and `Err` when every
    /// port has a live owner. `previous` is the public port the endpoint's
    /// expired mapping still owns, if any.
    fn model_udp_port(
        runtime: &Nat44UdpRuntime<'_>,
        internal_address: Ipv4Address,
        internal_port: u16,
        previous: Option<u16>,
        now_ms: u64,
    ) -> Result<Option<u16>, ()> {
        let config = runtime.config;
        let owner_live =
            |port: u16| {
                runtime.port_owners.owner(port).unwrap().map(|owner| {
                    runtime.mapping_is_live(runtime.mappings[owner.state_index()], now_ms)
                })
            };
        if config.policy.port_preservation
            && config.ports.contains(internal_port)
            && owner_live(internal_port) != Some(true)
        {
            return Ok(Some(internal_port));
        }
        if let Some(port) = previous {
            return Ok(Some(port));
        }
        let pool = config.ports.count();
        let start = runtime
            .port_selection_key()
            .search_start(internal_address, internal_port);
        if let Some(port) = (0..pool)
            .map(|step| config.ports.port((start + step) % pool))
            .find(|port| owner_live(*port).is_none())
        {
            return Ok(Some(port));
        }
        if (0..pool).any(|index| owner_live(config.ports.port(index)) == Some(false)) {
            Ok(None)
        } else {
            Err(())
        }
    }

    /// Whether any peer slot is reusable, by scanning every slot (the
    /// predicate the search before PERF-001 used).
    fn reference_peer_available(runtime: &Nat44UdpRuntime<'_>, now_ms: u64) -> bool {
        runtime.peers.iter().any(|peer| {
            !peer.occupied
                || runtime
                    .mappings
                    .get(peer.mapping_index)
                    .is_none_or(|mapping| {
                        !runtime.mapping_is_live(*mapping, now_ms)
                            || mapping.generation != peer.mapping_generation
                            || mapping.lifecycle_epoch != peer.mapping_lifecycle_epoch
                    })
        })
    }

    /// Random outbound and inbound UDP, refreshes, and expiry on small
    /// tables, checked against full scans of the slots: a new mapping
    /// or peer fails as full exactly when no slot is reusable (as the scans
    /// before PERF-001 decided), the port follows the modelled rule
    /// (`model_udp_port`), exhaustion is exact, and the
    /// indexes and reuse lists stay consistent after every commit.
    #[test]
    fn udp_reuse_matches_a_full_scan_reference_under_seeded_churn() {
        let ttl = NAT44_UDP_MIN_IDLE_TTL_MS;
        let mut outcomes = [0_usize; 8];
        for seed in 0..32_u64 {
            let filtering = [
                Nat44Filtering::AddressDependent,
                Nat44Filtering::AddressAndPortDependent,
                Nat44Filtering::EndpointIndependent,
            ][seed as usize % 3];
            let policy = Nat44UdpPolicy::new(ttl, seed.wrapping_mul(0x2545_f491_4f6c_dd1d))
                .unwrap()
                .with_filtering(filtering)
                // N2: a quarter of the seeds run without port preservation.
                .with_port_preservation(seed % 4 != 3);
            with_port_config(policy, 40_000, 40_003, |config| {
                // Three mappings fill before the four ports; five exhaust them.
                let mut mappings =
                    vec![Nat44UdpMappingSlot::default(); 3 + 2 * (seed as usize % 2)];
                let mut peers = [Nat44UdpPeerSlot::default(); 7];
                let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
                let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
                let mut rng = seed ^ 0x0bad_cafe;
                let mut now = 0;
                for _ in 0..300 {
                    now += match next_random(&mut rng) % 10 {
                        0 => ttl,
                        1 => ttl / 2,
                        2..=4 => 1_000,
                        _ => 0,
                    };
                    let remote = [REMOTE1, REMOTE2][(next_random(&mut rng) % 2) as usize];
                    let remote_port = 1 + (next_random(&mut rng) % 3) as u16;
                    if next_random(&mut rng).is_multiple_of(5) {
                        let public_port = 40_000 + (next_random(&mut rng) % 4) as u16;
                        if let Ok(plan) =
                            runtime.plan_inbound(public_port, remote, remote_port, now)
                        {
                            runtime.commit_inbound(plan, now).unwrap();
                            outcomes[0] += 1;
                        }
                    } else {
                        let host = Ipv4Address::from_octets([
                            10,
                            0,
                            0,
                            10 + (next_random(&mut rng) % 7) as u8,
                        ]);
                        let internal_port = 39_998 + (next_random(&mut rng) % 9) as u16;
                        let exact = runtime
                            .find_mapping(host, internal_port)
                            .unwrap()
                            .filter(|(_, mapping)| runtime.mapping_is_live(*mapping, now));
                        let mapping_available = runtime
                            .mappings
                            .iter()
                            .any(|mapping| !runtime.mapping_is_live(*mapping, now));
                        let peer_available = reference_peer_available(&runtime, now);
                        let previous = runtime
                            .find_mapping(host, internal_port)
                            .unwrap()
                            .map(|(_, mapping)| mapping)
                            .filter(|mapping| {
                                mapping.port_owned && !runtime.mapping_is_live(*mapping, now)
                            })
                            .map(|mapping| mapping.public_port);
                        let port = model_udp_port(&runtime, host, internal_port, previous, now);
                        let owners_before = runtime.port_owners.backing_snapshot();
                        match runtime.plan_outbound(host, internal_port, remote, remote_port, now) {
                            Ok(plan) if plan.mapping_created => {
                                assert!(exact.is_none() && mapping_available && peer_available);
                                match port {
                                    Ok(Some(expected)) => {
                                        assert_eq!(plan.mapping.public_port, expected);
                                    }
                                    Ok(None) => {
                                        let offset = usize::from(plan.mapping.public_port - 40_000);
                                        assert_ne!(owners_before[offset], PortOwnerSlot::default());
                                        // Any expired owner is correct (N2: keyed takeover
                                        // probes), never a live one.
                                        let owner = runtime
                                            .port_owners
                                            .owner(plan.mapping.public_port)
                                            .unwrap()
                                            .unwrap();
                                        assert!(!runtime.mapping_is_live(
                                            runtime.mappings[owner.state_index()],
                                            now
                                        ));
                                        outcomes[7] += 1;
                                    }
                                    Err(()) => panic!("allocated past exhaustion"),
                                }
                                runtime.commit_outbound(plan, now).unwrap();
                                outcomes[1] += 1;
                            }
                            Ok(plan) => {
                                assert!(exact.is_some());
                                assert!(!plan.peer_created || peer_available);
                                runtime.commit_outbound(plan, now).unwrap();
                                outcomes[2] += 1;
                            }
                            Err(Nat44UdpPlanError::MappingFull) => {
                                assert!(exact.is_none() && !mapping_available);
                                outcomes[3] += 1;
                            }
                            Err(Nat44UdpPlanError::PeerFull) => {
                                assert!(!peer_available);
                                assert!(exact.is_some() || mapping_available);
                                outcomes[4] += 1;
                            }
                            Err(Nat44UdpPlanError::PortExhausted) => {
                                assert!(exact.is_none() && mapping_available && peer_available);
                                assert_eq!(port, Err(()));
                                outcomes[5] += 1;
                            }
                            Err(error) => panic!("unexpected outbound {error:?}"),
                        }
                    }
                    assert_eq!(runtime.validate_indexes(), Ok(()));
                    outcomes[6] += 1;
                }
            });
        }
        // Every outcome the reference distinguishes was exercised.
        assert!(outcomes.iter().all(|count| *count > 0), "{outcomes:?}");
    }

    /// PERF-001 cost bound: with 65536-slot tables and the widest pool,
    /// planning and committing a new flow, even with every public port
    /// owned, makes at most four O(1) list-head checks, two port-owner
    /// checks, and 34 bitmap word reads; the search before PERF-001 visited up
    /// to every mapping slot, every peer slot, and every pool port.
    #[test]
    fn udp_new_flow_work_is_constant_in_a_nearly_full_65536_slot_table() {
        const SLOTS: usize = 65_536;
        let ttl = NAT44_UDP_MIN_IDLE_TTL_MS;
        let policy = Nat44UdpPolicy::new(ttl, 0x5eed_1234_5678_9abc).unwrap();
        with_port_config(policy, 1, 65_535, |config| {
            let mut mappings = vec![Nat44UdpMappingSlot::default(); SLOTS];
            let mut peers = vec![Nat44UdpPeerSlot::default(); SLOTS];
            let mut indexes = TestNat44UdpIndexes::new(config, SLOTS, SLOTS);
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            runtime.skip_commit_validation.set(true);
            let host = |flow: usize| {
                Ipv4Address::from_octets([
                    10,
                    1 + (flow >> 16) as u8,
                    (flow >> 8) as u8,
                    flow as u8,
                ])
            };
            // [list-head checks, port owners, bitmap words]
            let mut worst = [0_usize; 3];
            let mut flow_work = |runtime: &mut Nat44UdpRuntime<'_>,
                                 address: Ipv4Address,
                                 remote: Ipv4Address,
                                 now: u64| {
                runtime.reset_index_probe_counts();
                let result = runtime
                    .plan_outbound(address, 7, remote, TEST_REMOTE_PORT, now)
                    .map(|plan| {
                        runtime.commit_outbound(plan, now).unwrap();
                        plan.mapping.public_port
                    });
                let (_, _, owner_probes) = runtime.index_probe_counts();
                let seen = [
                    runtime.take_reuse_visits(),
                    owner_probes,
                    runtime.port_owners.take_bitmap_word_reads(),
                ];
                for (worst, seen) in worst.iter_mut().zip(seen) {
                    *worst = (*worst).max(seen);
                }
                result
            };
            // Every public port taken, half the flows at 0 and half at 1 s.
            for flow in 0..65_535 {
                let now = if flow < 32_768 { 0 } else { 1_000 };
                flow_work(&mut runtime, host(flow), REMOTE1, now).unwrap();
            }
            assert_eq!(
                flow_work(&mut runtime, host(65_535), REMOTE1, 1_000),
                Err(Nat44UdpPlanError::PortExhausted)
            );
            // The last never-used peer goes to a new peer of a live mapping;
            // the next one finds the peer table full in O(1).
            flow_work(&mut runtime, host(65_534), REMOTE2, 1_000).unwrap();
            assert_eq!(
                flow_work(
                    &mut runtime,
                    host(65_534),
                    Ipv4Address::from_octets([198, 51, 100, 3]),
                    1_000
                ),
                Err(Nat44UdpPlanError::PeerFull)
            );
            // At the TTL the first half has expired: new flows and new peers
            // reuse the oldest expired mappings, their peers, and their ports.
            for flow in 65_536..66_536 {
                flow_work(&mut runtime, host(flow), REMOTE1, ttl).unwrap();
                flow_work(&mut runtime, host(65_534), host(flow), ttl).unwrap();
            }
            assert_eq!(runtime.counters.mappings_expired, 1_000);
            assert!(runtime.reuse_lists_are_consistent());
            assert!(runtime.port_owners.bitmap_matches_slots());
            assert!(
                worst[0] <= 4 && worst[1] <= 2 + NAT44_PORT_TAKEOVER_PROBES && worst[2] <= 34,
                "work per new flow {worst:?}"
            );
        });
    }

    /// Defense in depth: a commit whose planned peer slot is no longer the
    /// one the reuse lists offer fails as `IndexCorrupt` before mutating
    /// anything, and a list head that breaks its invariant (an active
    /// mapping without peers, an expired owner without its port) fails the
    /// plan closed instead of being trusted.
    #[test]
    fn udp_reuse_list_corruption_fails_closed_without_mutation() {
        let ttl = NAT44_UDP_MIN_IDLE_TTL_MS;
        let policy = Nat44UdpPolicy::new(ttl, 7).unwrap();
        with_port_config(policy, 40_000, 40_000, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 2];
            let mut peers = [Nat44UdpPeerSlot::default(); 3];
            let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            let plan = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE1, TEST_REMOTE_PORT, 0)
                .unwrap();
            // A never-used target mapping slot must be the lowest one.
            runtime.mapping_lists.next_fresh += 1;
            assert_eq!(
                runtime.commit_outbound(plan, 0),
                Err(Nat44UdpCommitError::IndexCorrupt)
            );
            runtime.mapping_lists.next_fresh -= 1;
            runtime.commit_outbound(plan, 0).unwrap();

            // The plan takes the next never-used peer; moving the fresh
            // boundary under it (same revision) must refuse the commit.
            let plan = runtime
                .plan_outbound(INTERNAL, 40_000, REMOTE2, TEST_REMOTE_PORT, 1)
                .unwrap();
            assert!(plan.peer_created);
            runtime.next_fresh_peer += 1;
            let before = (runtime.mappings.to_vec(), runtime.peers.to_vec());
            assert_eq!(
                runtime.commit_outbound(plan, 1),
                Err(Nat44UdpCommitError::IndexCorrupt)
            );
            assert_eq!((runtime.mappings.to_vec(), runtime.peers.to_vec()), before);
            runtime.next_fresh_peer -= 1;
            runtime.commit_outbound(plan, 1).unwrap();
            assert_eq!(runtime.validate_indexes(), Ok(()));

            // After expiry the activity head offers its peers and its port.
            let head = runtime.mapping_lists.lru.head().unwrap();
            let peers = runtime.mappings[head].link.peers;
            runtime.mappings[head].link.peers = PeerChain::EMPTY;
            assert_eq!(
                runtime
                    .plan_outbound(INTERNAL2, 1, REMOTE1, TEST_REMOTE_PORT, ttl + 1)
                    .err(),
                Some(Nat44UdpPlanError::IndexCorrupt)
            );
            runtime.mappings[head].link.peers = peers;
            runtime.mappings[head].port_owned = false;
            assert_eq!(
                runtime
                    .plan_outbound(INTERNAL2, 1, REMOTE1, TEST_REMOTE_PORT, ttl + 1)
                    .err(),
                Some(Nat44UdpPlanError::IndexCorrupt)
            );
            runtime.mappings[head].port_owned = true;
            let plan = runtime
                .plan_outbound(INTERNAL2, 1, REMOTE1, TEST_REMOTE_PORT, ttl + 1)
                .unwrap();
            assert_eq!(plan.mapping.public_port, 40_000);
            runtime.commit_outbound(plan, ttl + 1).unwrap();
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
    }

    /// Pins the two port rules that differ from a plain walk of the pool
    /// (NAT44-068): an endpoint whose mapping expired gets its old public
    /// port back while that port is still owned only by its expired
    /// mapping, and a new endpoint takes the first unowned port from its
    /// seeded start even when a port owned by an expired mapping comes
    /// first (the walk before H4a took the expired-owned one).
    #[test]
    fn returning_endpoint_keeps_its_port_and_unowned_ports_come_first() {
        let ttl = NAT44_UDP_MIN_IDLE_TTL_MS;
        let policy = Nat44UdpPolicy::new(ttl, 0x0123_4567).unwrap();
        with_port_config(policy, 40_000, 40_003, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 4];
            let mut peers = [Nat44UdpPeerSlot::default(); 8];
            let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), peers.len());
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            let outbound = |runtime: &mut Nat44UdpRuntime<'_>, host, port, now| {
                let plan = runtime
                    .plan_outbound(host, port, REMOTE1, TEST_REMOTE_PORT, now)
                    .unwrap();
                runtime.commit_outbound(plan, now).unwrap();
                plan.mapping.public_port
            };
            // Internal ports outside the pool: no port preservation.
            let first = outbound(&mut runtime, INTERNAL, 1_000, 0);
            let other = outbound(&mut runtime, INTERNAL2, 1_000, 1);
            assert_ne!(first, other);

            // INTERNAL's mapping expires; it returns and gets the same port
            // although an unowned port exists.
            let returned = outbound(&mut runtime, INTERNAL, 1_000, ttl);
            assert_eq!(returned, first);
            assert_eq!(runtime.counters.mappings_expired, 1);

            // INTERNAL2's mapping (`other`) expires. A new endpoint whose
            // seeded start is `other` gets the next unowned port instead.
            let now = ttl + 1;
            let offset = usize::from(other - 40_000);
            let host = (20..250)
                .map(|last| Ipv4Address::from_octets([10, 0, 0, last]))
                .find(|host| runtime.port_selection_key().search_start(*host, 1_000) == offset)
                .unwrap();
            assert!(runtime.port_owners.owner(other).unwrap().is_some());
            let chosen = outbound(&mut runtime, host, 1_000, now);
            assert_ne!(chosen, other);
            // The new mapping reused INTERNAL2's expired slot (the oldest),
            // which released `other`.
            assert_eq!(runtime.port_owners.owner(other), Ok(None));
            assert_eq!(runtime.validate_indexes(), Ok(()));
        });
    }

    /// Adversarial peer chain: one mapping with 65535 peers is parked
    /// (its whole chain released) and recreated, twice, and each new flow
    /// still does O(1) list work: at most four list-head checks and four
    /// peer-slot link writes, however long the chain.
    #[test]
    fn a_65535_peer_chain_is_parked_and_recreated_in_constant_work() {
        const PEERS: usize = 65_536;
        let ttl = NAT44_UDP_MIN_IDLE_TTL_MS;
        let policy = Nat44UdpPolicy::new(ttl, 3).unwrap();
        with_port_config(policy, 40_000, 40_001, |config| {
            let mut mappings = [Nat44UdpMappingSlot::default(); 2];
            let mut peers = vec![Nat44UdpPeerSlot::default(); PEERS];
            let mut indexes = TestNat44UdpIndexes::new(config, mappings.len(), PEERS);
            let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
            runtime.skip_commit_validation.set(true);
            let remote = |peer: usize| {
                Ipv4Address::from_octets([100, (peer >> 16) as u8, (peer >> 8) as u8, peer as u8])
            };
            let mut worst = [0_usize; 2];
            let mut flow = |runtime: &mut Nat44UdpRuntime<'_>, host, peer: usize, now| {
                runtime.reset_index_probe_counts();
                runtime.peer_link_writes.set(0);
                let plan = runtime
                    .plan_outbound(host, 1_000, remote(peer), TEST_REMOTE_PORT, now)
                    .unwrap();
                runtime.commit_outbound(plan, now).unwrap();
                for (worst, seen) in worst
                    .iter_mut()
                    .zip([runtime.take_reuse_visits(), runtime.peer_link_writes.get()])
                {
                    *worst = (*worst).max(seen);
                }
                plan
            };
            for peer in 0..PEERS - 1 {
                flow(&mut runtime, INTERNAL, peer, 0);
            }
            assert_eq!(runtime.next_fresh_peer, PEERS - 1);
            // Expired at the TTL: a new endpoint takes the expired mapping
            // and the first of its 65535 peers; the rest go to the stale
            // chain in one splice.
            let plan = flow(&mut runtime, INTERNAL2, 0, ttl);
            assert!(plan.mapping_created && plan.mapping_expired);
            assert_eq!(runtime.mapping_lists.parked.head(), None);
            // Its next peers come from the stale chain.
            for peer in 1..4 {
                assert!(flow(&mut runtime, INTERNAL2, peer, ttl).peer_created);
            }
            // Recreated again after another TTL, with 65531 stale peers
            // still chained.
            let plan = flow(&mut runtime, INTERNAL, 9, 2 * ttl);
            assert!(plan.mapping_created);
            assert!(runtime.reuse_lists_are_consistent());
            assert!(
                worst[0] <= 4 && worst[1] <= 4,
                "work per new flow {worst:?}"
            );
        });
    }
}
