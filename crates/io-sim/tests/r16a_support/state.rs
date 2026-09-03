use super::{support::UdpTestIndexes, targets::V1_SEEDS};
use ruster_core::{
    internet_checksum, ipv4_header_checksum, DropReason, DynamicNeighborSlot, FirewallAction,
    FirewallAuthorityEvidence, FirewallConfig, FirewallCounters, FirewallHashKey,
    FirewallInterface, FirewallIpv4Prefix, FirewallPolicy, FirewallPortRange, FirewallProtocol,
    FirewallRule, FirewallRuleId, FirewallRuntime, FirewallStateSlot, ForwardingSnapshot, IfId,
    Interface, Ipv4Address, LocalIpv4Binding, MacAddress, MonotonicMillis,
    Nat44TcpAuthorityEvidence, Nat44TcpConfig, Nat44TcpCounters, Nat44TcpMappingSlot,
    Nat44TcpPolicy, Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44UdpAuthorityEvidence,
    Nat44UdpConfig, Nat44UdpCounters, Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy,
    Nat44UdpRuntime, Neighbor, NoTrace, ResolutionActionSlot, ResolutionCounters,
    ResolutionFailureCounters, ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route,
    FIREWALL_TCP_ACTIVE_MIN_IDLE_TTL_MS, FIREWALL_TCP_OPENING_MIN_IDLE_TTL_MS,
    FIREWALL_UDP_MIN_IDLE_TTL_MS, NAT44_TCP_MIN_IDLE_TTL_MS, NAT44_UDP_MIN_IDLE_TTL_MS,
};
use ruster_io_sim::{FrameOrigin, RecycleCause, RecycledFrameCapture, SimIo, TxFrame, VecTrace};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
const HOST_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 10]);
const GATEWAY_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 20]);
const HOST: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
const LAN_LOCAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 1]);
const WAN_LOCAL: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const OTHER_REMOTE: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 30]);
const GATEWAY: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);

const MAX_STATE_CASES: usize = 12;
const MAX_STATE_SEEDS: usize = 4;

#[derive(Clone, Copy, Debug)]
enum StateCase {
    UdpRewriteAndFilter,
    UdpCapacityTimeoutAndReuse,
    FirewallCapacityExpiryAndTxReject,
    TcpBoundaryAndTxReject,
    NoNeighborReject,
    RejectPathsAreMutationFree,
    CombinedNatFirewallTransaction,
    FirewallDenyModes,
    UdpMalformedChecksumCollision,
    TcpExpiryCapacityAndExhaustion,
    ClockRegressionAndWatermark,
    DeterministicReplayEvidence,
}

impl StateCase {
    const fn name(self) -> &'static str {
        match self {
            Self::UdpRewriteAndFilter => "udp-rewrite-and-filter",
            Self::UdpCapacityTimeoutAndReuse => "udp-capacity-timeout-and-reuse",
            Self::FirewallCapacityExpiryAndTxReject => "firewall-capacity-expiry-and-tx-reject",
            Self::TcpBoundaryAndTxReject => "tcp-boundary-and-tx-reject",
            Self::NoNeighborReject => "no-neighbor-reject",
            Self::RejectPathsAreMutationFree => "reject-paths-are-mutation-free",
            Self::CombinedNatFirewallTransaction => "combined-nat-firewall-transaction",
            Self::FirewallDenyModes => "firewall-deny-modes",
            Self::UdpMalformedChecksumCollision => "udp-malformed-checksum-collision",
            Self::TcpExpiryCapacityAndExhaustion => "tcp-expiry-capacity-and-exhaustion",
            Self::ClockRegressionAndWatermark => "clock-regression-and-watermark",
            Self::DeterministicReplayEvidence => "deterministic-replay-evidence",
        }
    }
}

const STATE_CASES: [StateCase; 12] = [
    StateCase::UdpRewriteAndFilter,
    StateCase::UdpCapacityTimeoutAndReuse,
    StateCase::FirewallCapacityExpiryAndTxReject,
    StateCase::TcpBoundaryAndTxReject,
    StateCase::NoNeighborReject,
    StateCase::RejectPathsAreMutationFree,
    StateCase::CombinedNatFirewallTransaction,
    StateCase::FirewallDenyModes,
    StateCase::UdpMalformedChecksumCollision,
    StateCase::TcpExpiryCapacityAndExhaustion,
    StateCase::ClockRegressionAndWatermark,
    StateCase::DeterministicReplayEvidence,
];

#[derive(Eq, PartialEq)]
struct ReplayEvidence {
    tx: Vec<TxFrame>,
    recycled: Vec<RecycledFrameCapture>,
    unresolved_recycled: Vec<RecycledFrameCapture>,
    trace: Vec<ruster_core::TraceEvent>,
    unresolved_trace: Vec<ruster_core::TraceEvent>,
    resolution_states: Vec<ResolutionStateSlot>,
    resolution_actions: Vec<ResolutionActionSlot>,
    resolution_status: Option<ruster_core::ResolutionStatus>,
    resolution_counters: ResolutionCounters,
    resolution_failure_counters: ResolutionFailureCounters,
}

impl std::fmt::Debug for ReplayEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReplayEvidence")
            .field("tx_frames", &self.tx.len())
            .field("recycled_frames", &self.recycled.len())
            .field(
                "unresolved_recycled_frames",
                &self.unresolved_recycled.len(),
            )
            .field("trace_events", &self.trace.len())
            .field("unresolved_trace_events", &self.unresolved_trace.len())
            .field("resolution_states", &self.resolution_states.len())
            .field("resolution_actions", &self.resolution_actions.len())
            .field("resolution_status", &self.resolution_status)
            .field("resolution_counters", &self.resolution_counters)
            .field(
                "resolution_failure_counters",
                &self.resolution_failure_counters,
            )
            .finish()
    }
}

#[derive(Debug, Eq, PartialEq)]
struct StateEvidence {
    udp_mappings: Vec<Nat44UdpMappingSlot>,
    udp_peers: Vec<Nat44UdpPeerSlot>,
    udp_counters: Option<Nat44UdpCounters>,
    tcp_mappings: Vec<Nat44TcpMappingSlot>,
    tcp_sessions: Vec<Nat44TcpSessionSlot>,
    tcp_counters: Option<Nat44TcpCounters>,
    udp_authority: Option<Nat44UdpAuthorityEvidence>,
    tcp_authority: Option<Nat44TcpAuthorityEvidence>,
    firewall_states: Vec<FirewallStateSlot>,
    firewall_counters: Option<FirewallCounters>,
    firewall_authority: Option<FirewallAuthorityEvidence>,
    resolution_counters: ResolutionCounters,
    resolution_failure_counters: ResolutionFailureCounters,
    resolution_counts: [usize; 4],
    io_counts: [usize; 3],
    replay: Option<ReplayEvidence>,
}

fn capture_state_evidence(
    udp: Option<&Nat44UdpRuntime<'_>>,
    tcp: Option<&Nat44TcpRuntime<'_>>,
    firewall: Option<&FirewallRuntime<'_>>,
    resolution: &ResolutionRuntime<'_>,
    io: &SimIo,
) -> StateEvidence {
    StateEvidence {
        udp_mappings: udp.map_or_else(Vec::new, |runtime| runtime.mappings().to_vec()),
        udp_peers: udp.map_or_else(Vec::new, |runtime| runtime.peers().to_vec()),
        udp_counters: udp.map(Nat44UdpRuntime::counters),
        tcp_mappings: tcp.map_or_else(Vec::new, |runtime| runtime.mappings().to_vec()),
        tcp_sessions: tcp.map_or_else(Vec::new, |runtime| runtime.sessions().to_vec()),
        tcp_counters: tcp.map(Nat44TcpRuntime::counters),
        udp_authority: udp.map(Nat44UdpRuntime::authority_evidence),
        tcp_authority: tcp.map(Nat44TcpRuntime::authority_evidence),
        firewall_states: firewall.map_or_else(Vec::new, |runtime| runtime.states().to_vec()),
        firewall_counters: firewall.map(FirewallRuntime::counters),
        firewall_authority: firewall.map(FirewallRuntime::authority_evidence),
        resolution_counters: resolution.counters(),
        resolution_failure_counters: resolution.failure_counters(),
        resolution_counts: [
            resolution.pending_states(),
            resolution.pending_actions(),
            resolution.pending_failure_holds(),
            resolution.dynamic_neighbor_count(),
        ],
        io_counts: [io.pending_rx(), io.pending_tx(), io.pending_recycled()],
        replay: None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CombinedAuthority {
    udp: Nat44UdpAuthorityEvidence,
    tcp: Nat44TcpAuthorityEvidence,
    firewall: FirewallAuthorityEvidence,
}

fn combined_authority(
    udp: &Nat44UdpRuntime<'_>,
    tcp: &Nat44TcpRuntime<'_>,
    firewall: &FirewallRuntime<'_>,
) -> CombinedAuthority {
    CombinedAuthority {
        udp: udp.authority_evidence(),
        tcp: tcp.authority_evidence(),
        firewall: firewall.authority_evidence(),
    }
}

fn assert_combined_authority_valid(authority: CombinedAuthority, label: &str) {
    assert!(
        authority.udp.indexes_coherent(),
        "{label}: UDP index invariant"
    );
    assert!(
        authority.tcp.indexes_coherent(),
        "{label}: TCP index invariant"
    );
    assert!(
        authority.udp.directories_coherent(),
        "{label}: UDP directory/owner invariant"
    );
    assert!(
        authority.tcp.directories_coherent(),
        "{label}: TCP directory/owner invariant"
    );
    assert!(
        authority.firewall.occupied_count_conserved(),
        "{label}: firewall occupied count must be conserved"
    );
}

fn assert_nat_authority_reject_matches_expected(
    after: Nat44UdpAuthorityEvidence,
    expected: Nat44UdpAuthorityEvidence,
    label: &str,
) {
    assert_eq!(after, expected, "{label}: UDP authority");
}

fn assert_firewall_authority_reject_matches_expected(
    after: FirewallAuthorityEvidence,
    expected: FirewallAuthorityEvidence,
    label: &str,
) {
    assert_eq!(after, expected, "{label}: firewall authority");
}

fn assert_combined_authority_matches_expected(
    actual: CombinedAuthority,
    expected: CombinedAuthority,
    label: &str,
) {
    assert_eq!(actual.udp, expected.udp, "{label}: UDP authority");
    assert_eq!(actual.tcp, expected.tcp, "{label}: TCP authority");
    assert_eq!(
        actual.firewall, expected.firewall,
        "{label}: firewall authority"
    );
    assert_combined_authority_valid(actual, label);
}

fn assert_firewall_clock_regression_preserves_authority(
    before: FirewallAuthorityEvidence,
    after: FirewallAuthorityEvidence,
    label: &str,
) {
    assert_eq!(before, after, "{label}: clock regression changed authority");
}

// This is deliberately a test-side model. It mirrors the fixed-width
// authority contract without calling a production hash, digest, or snapshot
// helper. The model is limited to the R16 fixed cases below: capacities are
// bounded by the fixed arrays and every transition is spelled out by the
// known packet/config operation.
const AUTHORITY_WORDS: usize = 29;
const NAT44_AUTHORITY_COMMITMENT_TAG: u64 = 0x5255_5354_2e4e_4154;
const FIREWALL_AUTHORITY_COMMITMENT_TAG: u64 = 0x5255_5354_2e46_4952;
const FIREWALL_CONFIG_GENERATION: u64 = 1;
const UDP_MAPPING_DOMAIN: u64 = 0x4e41_5434_554d_4150;
const UDP_PEER_DOMAIN: u64 = 0x4e41_5434_5550_4545;
const TCP_MAPPING_DOMAIN: u64 = 0x4e41_5434_544d_4150;
const TCP_SESSION_DOMAIN: u64 = 0x4e41_5434_5453_4553;
const UDP_HASH_KEY: (u64, u64) = (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210);
const TCP_HASH_KEY: (u64, u64) = (0xc001_d00d_f00d_beef, 0x1234_5678_9abc_def0);

#[derive(Clone, Copy, Default)]
struct ModelNatMapping {
    occupied: bool,
    generation: u64,
    lifecycle_epoch: u128,
    port_owned: bool,
    inside: u32,
    internal_address: u32,
    internal_port: u16,
    public_port: u16,
    last_activity_ms: u64,
}

#[derive(Clone, Copy, Default)]
struct ModelUdpPeer {
    occupied: bool,
    mapping_index: usize,
    mapping_generation: u64,
    mapping_lifecycle_epoch: u128,
    remote_address: u32,
}

#[derive(Clone, Copy, Default)]
struct ModelTcpSession {
    occupied: bool,
    mapping_index: usize,
    mapping_generation: u64,
    mapping_lifecycle_epoch: u128,
    remote_address: u32,
    remote_port: u16,
    last_activity_ms: u64,
}

#[derive(Clone, Copy, Default)]
struct ModelFirewallSlot {
    occupied: bool,
    slot_generation: u64,
    config_generation: u64,
    protocol_tcp: bool,
    origin_ingress: u32,
    origin_egress: u32,
    initiator_address: u32,
    responder_address: u32,
    initiator_port: u16,
    responder_port: u16,
    last_activity_ms: u64,
    tcp_phase_active: bool,
    tcp_forward_ack: bool,
    tcp_reverse_ack: bool,
    origin_rule_id: u32,
}

#[derive(Clone, Copy)]
struct ModelFirewallPacket {
    protocol_tcp: bool,
    ingress: u32,
    egress: u32,
    source: u32,
    destination: u32,
    source_port: u16,
    destination_port: u16,
    tcp_flags: u8,
}

struct CombinedAuthorityModel {
    udp_mappings: [ModelNatMapping; 2],
    udp_peers: [ModelUdpPeer; 2],
    udp_mapping_len: usize,
    udp_peer_len: usize,
    udp_first_port: u16,
    udp_port_len: usize,
    udp_allocator_seed: u64,
    udp_watermark_ms: Option<u64>,
    udp_runtime_epoch: u128,
    udp_next_generation: u64,
    udp_state_revision: u128,
    tcp_mappings: [ModelNatMapping; 2],
    tcp_sessions: [ModelTcpSession; 2],
    tcp_mapping_len: usize,
    tcp_session_len: usize,
    tcp_first_port: u16,
    tcp_port_len: usize,
    tcp_allocator_seed: u64,
    tcp_watermark_ms: Option<u64>,
    tcp_runtime_epoch: u128,
    tcp_next_generation: u64,
    tcp_state_revision: u128,
    firewall: [ModelFirewallSlot; 4],
    firewall_len: usize,
    firewall_key: (u64, u64),
    firewall_watermark_ms: Option<u64>,
    firewall_runtime_epoch: u64,
    firewall_next_generation: u64,
}

impl CombinedAuthorityModel {
    #[allow(clippy::too_many_arguments)]
    fn new(
        udp_seed: u64,
        udp_mapping_len: usize,
        udp_peer_len: usize,
        udp_first_port: u16,
        udp_port_len: usize,
        tcp_seed: u64,
        tcp_mapping_len: usize,
        tcp_session_len: usize,
        tcp_first_port: u16,
        tcp_port_len: usize,
        firewall_seed: u64,
        firewall_len: usize,
    ) -> Self {
        assert!(udp_mapping_len <= 2 && udp_peer_len <= 2);
        assert!(tcp_mapping_len <= 2 && tcp_session_len <= 2);
        assert!(firewall_len <= 4);
        Self {
            udp_mappings: [ModelNatMapping::default(); 2],
            udp_peers: [ModelUdpPeer::default(); 2],
            udp_mapping_len,
            udp_peer_len,
            udp_first_port,
            udp_port_len,
            udp_allocator_seed: udp_seed | 1,
            udp_watermark_ms: None,
            udp_runtime_epoch: 1,
            udp_next_generation: 1,
            udp_state_revision: 0,
            tcp_mappings: [ModelNatMapping::default(); 2],
            tcp_sessions: [ModelTcpSession::default(); 2],
            tcp_mapping_len,
            tcp_session_len,
            tcp_first_port,
            tcp_port_len,
            tcp_allocator_seed: tcp_seed | 1,
            tcp_watermark_ms: None,
            tcp_runtime_epoch: 1,
            tcp_next_generation: 1,
            tcp_state_revision: 0,
            firewall: [ModelFirewallSlot::default(); 4],
            firewall_len,
            firewall_key: (firewall_seed | 1, firewall_seed.rotate_left(17) | 1),
            firewall_watermark_ms: None,
            firewall_runtime_epoch: 1,
            firewall_next_generation: 1,
        }
    }

    fn evidence(&self) -> CombinedAuthority {
        CombinedAuthority {
            udp: model_udp_authority(
                &self.udp_mappings[..self.udp_mapping_len],
                &self.udp_peers[..self.udp_peer_len],
                self.udp_first_port,
                self.udp_port_len,
                self.udp_watermark_ms,
                self.udp_runtime_epoch,
                self.udp_next_generation,
                self.udp_state_revision,
            ),
            tcp: model_tcp_authority(
                &self.tcp_mappings[..self.tcp_mapping_len],
                &self.tcp_sessions[..self.tcp_session_len],
                self.tcp_first_port,
                self.tcp_port_len,
                self.tcp_watermark_ms,
                self.tcp_runtime_epoch,
                self.tcp_next_generation,
                self.tcp_state_revision,
            ),
            firewall: model_firewall_authority(
                &self.firewall[..self.firewall_len],
                self.firewall_key,
                self.firewall_watermark_ms,
                self.firewall_runtime_epoch,
                self.firewall_next_generation,
            ),
        }
    }

    fn allow_udp(
        &mut self,
        internal_port: u16,
        remote_address: Ipv4Address,
        now_ms: u64,
        rule_id: u32,
    ) -> u16 {
        model_observe_nat(
            &mut self.udp_watermark_ms,
            &mut self.udp_state_revision,
            now_ms,
        );
        let mapping_index = self
            .udp_mappings
            .iter()
            .take(self.udp_mapping_len)
            .position(|mapping| !mapping.occupied)
            .expect("model UDP mapping capacity");
        let peer_index = self
            .udp_peers
            .iter()
            .take(self.udp_peer_len)
            .position(|peer| !peer.occupied)
            .expect("model UDP peer capacity");
        let public_port = model_allocate_port(
            self.udp_allocator_seed,
            internal_port,
            self.udp_first_port,
            self.udp_port_len,
            &self.udp_mappings[..self.udp_mapping_len],
        );
        let generation = self.udp_next_generation;
        self.udp_mappings[mapping_index] = ModelNatMapping {
            occupied: true,
            generation,
            lifecycle_epoch: self.udp_runtime_epoch,
            port_owned: true,
            inside: u32::from(LAN.0),
            internal_address: address_word(HOST),
            internal_port,
            public_port,
            last_activity_ms: now_ms,
        };
        self.udp_peers[peer_index] = ModelUdpPeer {
            occupied: true,
            mapping_index,
            mapping_generation: generation,
            mapping_lifecycle_epoch: self.udp_runtime_epoch,
            remote_address: address_word(remote_address),
        };
        self.udp_next_generation += 1;
        self.udp_state_revision += 1;
        self.firewall_allow(
            ModelFirewallPacket {
                protocol_tcp: false,
                ingress: u32::from(LAN.0),
                egress: u32::from(WAN.0),
                source: address_word(HOST),
                destination: address_word(remote_address),
                source_port: internal_port,
                destination_port: 53,
                tcp_flags: 0,
            },
            now_ms,
            rule_id,
        );
        public_port
    }

    fn allow_tcp(
        &mut self,
        internal_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        now_ms: u64,
        rule_id: u32,
    ) -> u16 {
        model_observe_nat(
            &mut self.tcp_watermark_ms,
            &mut self.tcp_state_revision,
            now_ms,
        );
        let mapping_index = self
            .tcp_mappings
            .iter()
            .take(self.tcp_mapping_len)
            .position(|mapping| !mapping.occupied)
            .expect("model TCP mapping capacity");
        let session_index = self
            .tcp_sessions
            .iter()
            .take(self.tcp_session_len)
            .position(|session| !session.occupied)
            .expect("model TCP session capacity");
        let public_port = model_allocate_port(
            self.tcp_allocator_seed,
            internal_port,
            self.tcp_first_port,
            self.tcp_port_len,
            &self.tcp_mappings[..self.tcp_mapping_len],
        );
        let generation = self.tcp_next_generation;
        self.tcp_mappings[mapping_index] = ModelNatMapping {
            occupied: true,
            generation,
            lifecycle_epoch: self.tcp_runtime_epoch,
            port_owned: true,
            inside: u32::from(LAN.0),
            internal_address: address_word(HOST),
            internal_port,
            public_port,
            last_activity_ms: now_ms,
        };
        self.tcp_sessions[session_index] = ModelTcpSession {
            occupied: true,
            mapping_index,
            mapping_generation: generation,
            mapping_lifecycle_epoch: self.tcp_runtime_epoch,
            remote_address: address_word(remote_address),
            remote_port,
            last_activity_ms: now_ms,
        };
        self.tcp_next_generation += 1;
        self.tcp_state_revision += 1;
        self.firewall_allow(
            ModelFirewallPacket {
                protocol_tcp: true,
                ingress: u32::from(LAN.0),
                egress: u32::from(WAN.0),
                source: address_word(HOST),
                destination: address_word(remote_address),
                source_port: internal_port,
                destination_port: remote_port,
                tcp_flags: 0x02,
            },
            now_ms,
            rule_id,
        );
        public_port
    }

    fn observe_udp_and_firewall(&mut self, now_ms: u64) {
        model_observe_nat(
            &mut self.udp_watermark_ms,
            &mut self.udp_state_revision,
            now_ms,
        );
        self.observe_firewall(now_ms);
    }

    fn observe_firewall(&mut self, now_ms: u64) {
        if self
            .firewall_watermark_ms
            .is_none_or(|watermark| now_ms >= watermark)
        {
            self.firewall_watermark_ms = Some(now_ms);
        }
    }

    fn firewall_allow(&mut self, packet: ModelFirewallPacket, now_ms: u64, rule_id: u32) {
        self.observe_firewall(now_ms);
        let index = model_firewall_insert(
            &mut self.firewall[..self.firewall_len],
            self.firewall_key,
            packet,
            now_ms,
            self.firewall_next_generation,
            rule_id,
        );
        assert!(index < self.firewall_len);
        self.firewall_next_generation += 1;
    }

    fn inbound_udp(&mut self, internal_port: u16, remote_address: Ipv4Address, now_ms: u64) {
        model_observe_nat(
            &mut self.udp_watermark_ms,
            &mut self.udp_state_revision,
            now_ms,
        );
        self.udp_state_revision += 1;
        self.observe_firewall(now_ms);
        model_firewall_established(
            &mut self.firewall[..self.firewall_len],
            self.firewall_key,
            ModelFirewallPacket {
                protocol_tcp: false,
                ingress: u32::from(WAN.0),
                egress: u32::from(LAN.0),
                source: address_word(remote_address),
                destination: address_word(HOST),
                source_port: 53,
                destination_port: internal_port,
                tcp_flags: 0,
            },
            now_ms,
        );
    }

    fn inbound_tcp(
        &mut self,
        internal_port: u16,
        remote_address: Ipv4Address,
        remote_port: u16,
        now_ms: u64,
    ) {
        model_observe_nat(
            &mut self.tcp_watermark_ms,
            &mut self.tcp_state_revision,
            now_ms,
        );
        self.tcp_mappings[0].last_activity_ms = now_ms;
        self.tcp_sessions[0].last_activity_ms = now_ms;
        self.tcp_state_revision += 1;
        self.observe_firewall(now_ms);
        model_firewall_established(
            &mut self.firewall[..self.firewall_len],
            self.firewall_key,
            ModelFirewallPacket {
                protocol_tcp: true,
                ingress: u32::from(WAN.0),
                egress: u32::from(LAN.0),
                source: address_word(remote_address),
                destination: address_word(HOST),
                source_port: remote_port,
                destination_port: internal_port,
                tcp_flags: 0x10,
            },
            now_ms,
        );
    }
}

fn model_observe_nat(watermark: &mut Option<u64>, revision: &mut u128, now_ms: u64) {
    if watermark.is_none_or(|previous| now_ms >= previous) && *watermark != Some(now_ms) {
        *revision += 1;
        *watermark = Some(now_ms);
    }
}

fn address_word(address: Ipv4Address) -> u32 {
    u32::from_be_bytes(address.octets())
}

fn model_mix(digest: u64, value: u64) -> u64 {
    digest
        .wrapping_add(value.wrapping_mul(0x9e37_79b9_7f4a_7c15))
        .rotate_left(17)
        ^ 0xa5a5_5a5a_c3c3_3c3c
}

fn model_directory_hash(key: (u64, u64), domain: u64, words: &[u64]) -> u64 {
    let mut v0 = key.0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = key.1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = key.0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = key.1 ^ 0x7465_6462_7974_6573;
    for word in std::iter::once(domain).chain(words.iter().copied()) {
        v3 ^= word;
        model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= word;
    }
    let final_word = 0x8000_0000_0000_0000 ^ words.len() as u64;
    v3 ^= final_word;
    model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= final_word;
    v2 ^= 0xff;
    for _ in 0..4 {
        model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^ v1 ^ v2 ^ v3
}

fn model_directory_commitment(
    key: (u64, u64),
    domain: u64,
    expected_hashes: &[Option<u64>],
    bucket_count: usize,
    node_capacity: usize,
) -> u64 {
    assert_eq!(expected_hashes.len(), node_capacity);
    let mut commitment = model_directory_hash(
        key,
        domain,
        &[
            NAT44_AUTHORITY_COMMITMENT_TAG,
            bucket_count as u64,
            node_capacity as u64,
        ],
    );
    for (index, expected) in expected_hashes.iter().copied().enumerate() {
        let linked = expected.is_some();
        commitment = model_mix(commitment, index as u64);
        commitment = model_mix(commitment, u64::from(linked));
        commitment = model_mix(commitment, u64::from(linked));
        if let Some(hash) = expected {
            commitment = model_mix(commitment, hash);
            let bucket = if bucket_count == 0 {
                u64::MAX
            } else {
                hash & (bucket_count as u64 - 1)
            };
            commitment = model_mix(commitment, bucket);
        }
    }
    model_mix(commitment, 1)
}

fn model_sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

fn model_directory_words(linked: &[bool], buckets: &[usize], bucket_count: usize) -> [u64; 6] {
    let mut link_mask = 0_u64;
    let mut topology_digest = 0xcbf2_9ce4_8422_2325_u64;
    let mut bucket_lengths = [0_usize; 4];
    let mut linked_nodes = 0_usize;
    for (index, linked) in linked.iter().copied().enumerate() {
        if linked {
            linked_nodes += 1;
            if index < u64::BITS as usize {
                link_mask |= 1_u64 << index;
            }
            assert!(bucket_count > 0);
            bucket_lengths[buckets[index]] += 1;
        }
        topology_digest = model_mix(topology_digest, index as u64);
        topology_digest = model_mix(topology_digest, u64::from(linked));
    }
    let nonempty_buckets = bucket_lengths[..bucket_count]
        .iter()
        .filter(|length| **length != 0)
        .count();
    let max_chain_len = bucket_lengths[..bucket_count]
        .iter()
        .copied()
        .max()
        .unwrap_or(0);
    [
        1,
        linked_nodes as u64,
        nonempty_buckets as u64,
        max_chain_len as u64,
        link_mask,
        topology_digest,
    ]
}

fn model_port_owner_words(
    mappings: &[ModelNatMapping],
    first_port: u16,
    port_len: usize,
) -> [u64; 5] {
    let mut assigned_mask = 0_u64;
    let mut owner_digest = 0xcbf2_9ce4_8422_2325_u64;
    let mut owners = [None; 2];
    for (index, mapping) in mappings.iter().copied().enumerate() {
        if mapping.occupied && mapping.port_owned {
            let offset = usize::from(mapping.public_port - first_port);
            assert!(offset < port_len);
            owners[offset] = Some((index, mapping.generation, mapping.lifecycle_epoch));
        }
    }
    for (offset, owner) in owners.iter().copied().enumerate().take(port_len) {
        if let Some((state_index, generation, epoch)) = owner {
            if offset < u64::BITS as usize {
                assigned_mask |= 1_u64 << offset;
            }
            owner_digest = model_mix(owner_digest, offset as u64);
            owner_digest = model_mix(owner_digest, state_index as u64);
            owner_digest = model_mix(owner_digest, generation);
            owner_digest = model_mix(owner_digest, epoch as u64);
            owner_digest = model_mix(owner_digest, (epoch >> 64) as u64);
        } else {
            owner_digest = model_mix(owner_digest, offset as u64);
        }
    }
    let assigned = owners[..port_len]
        .iter()
        .filter(|owner| owner.is_some())
        .count();
    [
        1,
        assigned as u64,
        assigned as u64,
        assigned_mask,
        owner_digest,
    ]
}

fn model_mapping_digest(mappings: &[ModelNatMapping]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for (index, mapping) in mappings.iter().copied().enumerate() {
        for value in [
            index as u64,
            u64::from(mapping.occupied),
            mapping.generation,
            mapping.lifecycle_epoch as u64,
            (mapping.lifecycle_epoch >> 64) as u64,
            u64::from(mapping.port_owned),
            u64::from(mapping.inside),
            u64::from(mapping.internal_address),
            u64::from(mapping.internal_port),
            u64::from(mapping.public_port),
            mapping.last_activity_ms,
        ] {
            digest = model_mix(digest, value);
        }
    }
    digest
}

fn model_udp_peer_digest(peers: &[ModelUdpPeer]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for (index, peer) in peers.iter().copied().enumerate() {
        for value in [
            index as u64,
            u64::from(peer.occupied),
            peer.mapping_index as u64,
            peer.mapping_generation,
            peer.mapping_lifecycle_epoch as u64,
            (peer.mapping_lifecycle_epoch >> 64) as u64,
            u64::from(peer.remote_address),
        ] {
            digest = model_mix(digest, value);
        }
    }
    digest
}

fn model_tcp_session_digest(sessions: &[ModelTcpSession]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for (index, session) in sessions.iter().copied().enumerate() {
        for value in [
            index as u64,
            u64::from(session.occupied),
            session.mapping_index as u64,
            session.mapping_generation,
            session.mapping_lifecycle_epoch as u64,
            (session.mapping_lifecycle_epoch >> 64) as u64,
            u64::from(session.remote_address),
            u64::from(session.remote_port),
            session.last_activity_ms,
        ] {
            digest = model_mix(digest, value);
        }
    }
    digest
}

#[allow(clippy::too_many_arguments)]
fn model_udp_authority(
    mappings: &[ModelNatMapping],
    peers: &[ModelUdpPeer],
    first_port: u16,
    port_len: usize,
    watermark_ms: Option<u64>,
    runtime_epoch: u128,
    next_generation: u64,
    state_revision: u128,
) -> Nat44UdpAuthorityEvidence {
    assert!(mappings.len() <= 2 && peers.len() <= 2 && port_len <= 2);
    let mapping_bucket_count = if mappings.is_empty() {
        0
    } else {
        mappings.len().next_power_of_two()
    };
    let peer_bucket_count = if peers.is_empty() {
        0
    } else {
        peers.len().next_power_of_two()
    };
    let mut mapping_hashes = [None; 2];
    let mut mapping_buckets = [0_usize; 2];
    for (index, mapping) in mappings.iter().copied().enumerate() {
        if mapping.occupied {
            let hash = model_directory_hash(
                UDP_HASH_KEY,
                UDP_MAPPING_DOMAIN,
                &[
                    u64::from(mapping.inside),
                    u64::from(mapping.internal_address),
                    u64::from(mapping.internal_port),
                ],
            );
            mapping_hashes[index] = Some(hash);
            mapping_buckets[index] = (hash as usize) & (mapping_bucket_count - 1);
        }
    }
    let mut peer_hashes = [None; 2];
    let mut peer_buckets = [0_usize; 2];
    for (index, peer) in peers.iter().copied().enumerate() {
        if peer.occupied {
            let hash = model_directory_hash(
                UDP_HASH_KEY,
                UDP_PEER_DOMAIN,
                &[
                    peer.mapping_index as u64,
                    peer.mapping_generation,
                    (peer.mapping_lifecycle_epoch >> 64) as u64,
                    peer.mapping_lifecycle_epoch as u64,
                    u64::from(peer.remote_address),
                ],
            );
            peer_hashes[index] = Some(hash);
            peer_buckets[index] = (hash as usize) & (peer_bucket_count - 1);
        }
    }
    let mut mapping_linked = [false; 2];
    for (index, mapping) in mappings.iter().copied().enumerate() {
        mapping_linked[index] = mapping.occupied;
    }
    let mut peer_linked = [false; 2];
    for (index, peer) in peers.iter().copied().enumerate() {
        peer_linked[index] = peer.occupied;
    }
    let mapping_directory = model_directory_words(
        &mapping_linked[..mappings.len()],
        &mapping_buckets[..mappings.len()],
        mapping_bucket_count,
    );
    let peer_directory = model_directory_words(
        &peer_linked[..peers.len()],
        &peer_buckets[..peers.len()],
        peer_bucket_count,
    );
    let owners = model_port_owner_words(mappings, first_port, port_len);
    let mapping_commitment = model_directory_commitment(
        UDP_HASH_KEY,
        UDP_MAPPING_DOMAIN,
        &mapping_hashes[..mappings.len()],
        mapping_bucket_count,
        mappings.len(),
    );
    let peer_commitment = model_directory_commitment(
        UDP_HASH_KEY,
        UDP_PEER_DOMAIN,
        &peer_hashes[..peers.len()],
        peer_bucket_count,
        peers.len(),
    );
    let mut authority_commitment = model_mix(mapping_commitment, peer_commitment);
    for value in owners
        .into_iter()
        .chain([model_mapping_digest(mappings), model_udp_peer_digest(peers)])
    {
        authority_commitment = model_mix(authority_commitment, value);
    }
    let mut words = [0_u64; AUTHORITY_WORDS];
    words[0] = u64::from(watermark_ms.is_some());
    words[1] = watermark_ms.unwrap_or_default();
    words[2] = runtime_epoch as u64;
    words[3] = (runtime_epoch >> 64) as u64;
    words[4] = next_generation;
    words[5] = state_revision as u64;
    words[6] = (state_revision >> 64) as u64;
    words[7] = mappings.iter().filter(|mapping| mapping.occupied).count() as u64;
    words[8] = peers.iter().filter(|peer| peer.occupied).count() as u64;
    words[9..15].copy_from_slice(&mapping_directory);
    words[15..21].copy_from_slice(&peer_directory);
    words[21..26].copy_from_slice(&owners);
    words[26] = 1;
    words[27] = model_mapping_digest(mappings);
    words[28] = authority_commitment;
    Nat44UdpAuthorityEvidence::from_expected_contract(
        mappings.len() as u32,
        peers.len() as u32,
        mapping_bucket_count as u32,
        mappings.len() as u32,
        peer_bucket_count as u32,
        peers.len() as u32,
        port_len as u32,
        words,
    )
}

#[allow(clippy::too_many_arguments)]
fn model_tcp_authority(
    mappings: &[ModelNatMapping],
    sessions: &[ModelTcpSession],
    first_port: u16,
    port_len: usize,
    watermark_ms: Option<u64>,
    runtime_epoch: u128,
    next_generation: u64,
    state_revision: u128,
) -> Nat44TcpAuthorityEvidence {
    assert!(mappings.len() <= 2 && sessions.len() <= 2 && port_len <= 2);
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
    let mut mapping_hashes = [None; 2];
    let mut mapping_buckets = [0_usize; 2];
    for (index, mapping) in mappings.iter().copied().enumerate() {
        if mapping.occupied {
            let hash = model_directory_hash(
                TCP_HASH_KEY,
                TCP_MAPPING_DOMAIN,
                &[
                    u64::from(mapping.inside),
                    u64::from(mapping.internal_address),
                    u64::from(mapping.internal_port),
                ],
            );
            mapping_hashes[index] = Some(hash);
            mapping_buckets[index] = (hash as usize) & (mapping_bucket_count - 1);
        }
    }
    let mut session_hashes = [None; 2];
    let mut session_buckets = [0_usize; 2];
    for (index, session) in sessions.iter().copied().enumerate() {
        if session.occupied {
            let hash = model_directory_hash(
                TCP_HASH_KEY,
                TCP_SESSION_DOMAIN,
                &[
                    session.mapping_index as u64,
                    session.mapping_generation,
                    (session.mapping_lifecycle_epoch >> 64) as u64,
                    session.mapping_lifecycle_epoch as u64,
                    u64::from(session.remote_address),
                    u64::from(session.remote_port),
                ],
            );
            session_hashes[index] = Some(hash);
            session_buckets[index] = (hash as usize) & (session_bucket_count - 1);
        }
    }
    let mut mapping_linked = [false; 2];
    for (index, mapping) in mappings.iter().copied().enumerate() {
        mapping_linked[index] = mapping.occupied;
    }
    let mut session_linked = [false; 2];
    for (index, session) in sessions.iter().copied().enumerate() {
        session_linked[index] = session.occupied;
    }
    let mapping_directory = model_directory_words(
        &mapping_linked[..mappings.len()],
        &mapping_buckets[..mappings.len()],
        mapping_bucket_count,
    );
    let session_directory = model_directory_words(
        &session_linked[..sessions.len()],
        &session_buckets[..sessions.len()],
        session_bucket_count,
    );
    let owners = model_port_owner_words(mappings, first_port, port_len);
    let mapping_commitment = model_directory_commitment(
        TCP_HASH_KEY,
        TCP_MAPPING_DOMAIN,
        &mapping_hashes[..mappings.len()],
        mapping_bucket_count,
        mappings.len(),
    );
    let session_commitment = model_directory_commitment(
        TCP_HASH_KEY,
        TCP_SESSION_DOMAIN,
        &session_hashes[..sessions.len()],
        session_bucket_count,
        sessions.len(),
    );
    let mut authority_commitment = model_mix(mapping_commitment, session_commitment);
    for value in owners.into_iter().chain([
        model_mapping_digest(mappings),
        model_tcp_session_digest(sessions),
    ]) {
        authority_commitment = model_mix(authority_commitment, value);
    }
    let mut words = [0_u64; AUTHORITY_WORDS];
    words[0] = u64::from(watermark_ms.is_some());
    words[1] = watermark_ms.unwrap_or_default();
    words[2] = runtime_epoch as u64;
    words[3] = (runtime_epoch >> 64) as u64;
    words[4] = next_generation;
    words[5] = state_revision as u64;
    words[6] = (state_revision >> 64) as u64;
    words[7] = mappings.iter().filter(|mapping| mapping.occupied).count() as u64;
    words[8] = sessions.iter().filter(|session| session.occupied).count() as u64;
    words[9..15].copy_from_slice(&mapping_directory);
    words[15..21].copy_from_slice(&session_directory);
    words[21..26].copy_from_slice(&owners);
    words[26] = 1;
    words[27] = model_mapping_digest(mappings);
    words[28] = authority_commitment;
    Nat44TcpAuthorityEvidence::from_expected_contract(
        mappings.len() as u32,
        sessions.len() as u32,
        mapping_bucket_count as u32,
        mappings.len() as u32,
        session_bucket_count as u32,
        sessions.len() as u32,
        port_len as u32,
        words,
    )
}

fn model_firewall_digest(states: &[ModelFirewallSlot]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for (index, state) in states.iter().copied().enumerate() {
        for value in [
            index as u64,
            u64::from(state.occupied),
            state.slot_generation,
            state.config_generation,
            u64::from(state.protocol_tcp),
            u64::from(state.origin_ingress),
            u64::from(state.origin_egress),
            u64::from(state.initiator_address),
            u64::from(state.responder_address),
            u64::from(state.initiator_port),
            u64::from(state.responder_port),
            state.last_activity_ms,
            u64::from(state.tcp_phase_active),
            u64::from(state.tcp_forward_ack),
            u64::from(state.tcp_reverse_ack),
            u64::from(state.origin_rule_id),
        ] {
            digest = model_mix(digest, value);
        }
    }
    digest
}

fn model_firewall_authority(
    states: &[ModelFirewallSlot],
    key: (u64, u64),
    watermark_ms: Option<u64>,
    runtime_epoch: u64,
    next_generation: u64,
) -> FirewallAuthorityEvidence {
    let occupied = states.iter().filter(|state| state.occupied).count() as u64;
    let state_digest = model_firewall_digest(states);
    let mut commitment = model_firewall_sip_hash(
        key,
        [
            FIREWALL_AUTHORITY_COMMITMENT_TAG,
            FIREWALL_CONFIG_GENERATION,
            states.len() as u64,
            u64::from(watermark_ms.is_some()),
            watermark_ms.unwrap_or_default(),
            runtime_epoch,
            next_generation,
            occupied,
            occupied,
            state_digest,
        ],
    );
    for (index, state) in states.iter().copied().enumerate() {
        commitment = model_mix(commitment, index as u64);
        commitment = model_mix(commitment, u64::from(state.occupied));
        let node_hash = state.occupied.then(|| {
            model_firewall_hash(
                key,
                ModelFirewallPacket {
                    protocol_tcp: state.protocol_tcp,
                    ingress: state.origin_ingress,
                    egress: state.origin_egress,
                    source: state.initiator_address,
                    destination: state.responder_address,
                    source_port: state.initiator_port,
                    destination_port: state.responder_port,
                    tcp_flags: 0,
                },
            )
        });
        commitment = model_mix(commitment, node_hash.unwrap_or_default());
    }
    FirewallAuthorityEvidence::from_expected_contract([
        u64::from(watermark_ms.is_some()),
        watermark_ms.unwrap_or_default(),
        runtime_epoch,
        next_generation,
        occupied,
        occupied,
        commitment,
    ])
}

fn model_allocate_port(
    allocator_seed: u64,
    internal_port: u16,
    first_port: u16,
    port_len: usize,
    mappings: &[ModelNatMapping],
) -> u16 {
    let pool_size = port_len as u64;
    let mixed =
        allocator_seed ^ u64::from(address_word(HOST)) ^ u64::from(internal_port).rotate_left(17);
    let start = (mixed % pool_size) as usize;
    for step in 0..port_len {
        let offset = (start + step) % port_len;
        let candidate = first_port + offset as u16;
        if candidate == internal_port {
            continue;
        }
        if !mappings.iter().any(|mapping| {
            mapping.occupied && mapping.port_owned && mapping.public_port == candidate
        }) {
            return candidate;
        }
    }
    panic!("model port capacity");
}

fn model_firewall_sip_hash<const WORDS: usize>(key: (u64, u64), words: [u64; WORDS]) -> u64 {
    let mut v0 = key.0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = key.1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = key.0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = key.1 ^ 0x7465_6462_7974_6573;
    for word in words {
        v3 ^= word;
        model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= word;
    }
    let final_block = (WORDS as u64 * 8) << 56;
    v3 ^= final_block;
    model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= final_block;
    v2 ^= 0xff;
    for _ in 0..4 {
        model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^ v1 ^ v2 ^ v3
}

fn model_firewall_hash(key: (u64, u64), packet: ModelFirewallPacket) -> u64 {
    let mut first = (packet.ingress, packet.source, packet.source_port);
    let mut second = (packet.egress, packet.destination, packet.destination_port);
    if second < first {
        std::mem::swap(&mut first, &mut second);
    }
    model_firewall_sip_hash(
        key,
        [
            FIREWALL_CONFIG_GENERATION,
            if packet.protocol_tcp { 6 } else { 17 },
            u64::from(first.0),
            u64::from(first.1),
            u64::from(first.2),
            u64::from(second.0),
            u64::from(second.1),
            u64::from(second.2),
        ],
    )
}

#[test]
fn model_authority_commitment_is_key_sensitive_when_buckets_are_unchanged() {
    let udp_alternate_key = (UDP_HASH_KEY.0 ^ 0x1326, UDP_HASH_KEY.1);
    let udp_port = (16_001_u16..17_001).find(|port| {
        let words = [
            u64::from(LAN.0),
            u64::from(address_word(HOST)),
            u64::from(*port),
        ];
        let canonical = model_directory_hash(UDP_HASH_KEY, UDP_MAPPING_DOMAIN, &words);
        let alternate = model_directory_hash(udp_alternate_key, UDP_MAPPING_DOMAIN, &words);
        (canonical as usize & 1) == (alternate as usize & 1)
    });
    let udp_port = udp_port.expect("bounded UDP alternate-key probe has a shared bucket");
    let udp_words = [
        u64::from(LAN.0),
        u64::from(address_word(HOST)),
        u64::from(udp_port),
    ];
    let udp_hash = model_directory_hash(UDP_HASH_KEY, UDP_MAPPING_DOMAIN, &udp_words);
    let udp_alternate_hash =
        model_directory_hash(udp_alternate_key, UDP_MAPPING_DOMAIN, &udp_words);
    assert_eq!(udp_hash as usize & 1, udp_alternate_hash as usize & 1);
    let udp_commitment = model_directory_commitment(
        UDP_HASH_KEY,
        UDP_MAPPING_DOMAIN,
        &[Some(udp_hash), None],
        2,
        2,
    );
    let udp_alternate_commitment = model_directory_commitment(
        udp_alternate_key,
        UDP_MAPPING_DOMAIN,
        &[Some(udp_alternate_hash), None],
        2,
        2,
    );
    assert!(
        udp_commitment != udp_alternate_commitment,
        "UDP model commitment must bind the alternate key"
    );

    let tcp_alternate_key = (TCP_HASH_KEY.0 ^ 0x0121, TCP_HASH_KEY.1);
    let tcp_port = (16_002_u16..17_002).find(|port| {
        let words = [
            u64::from(LAN.0),
            u64::from(address_word(HOST)),
            u64::from(*port),
        ];
        let canonical = model_directory_hash(TCP_HASH_KEY, TCP_MAPPING_DOMAIN, &words);
        let alternate = model_directory_hash(tcp_alternate_key, TCP_MAPPING_DOMAIN, &words);
        (canonical as usize & 1) == (alternate as usize & 1)
    });
    let tcp_port = tcp_port.expect("bounded TCP alternate-key probe has a shared bucket");
    let tcp_words = [
        u64::from(LAN.0),
        u64::from(address_word(HOST)),
        u64::from(tcp_port),
    ];
    let tcp_hash = model_directory_hash(TCP_HASH_KEY, TCP_MAPPING_DOMAIN, &tcp_words);
    let tcp_alternate_hash =
        model_directory_hash(tcp_alternate_key, TCP_MAPPING_DOMAIN, &tcp_words);
    assert_eq!(tcp_hash as usize & 1, tcp_alternate_hash as usize & 1);
    let tcp_commitment = model_directory_commitment(
        TCP_HASH_KEY,
        TCP_MAPPING_DOMAIN,
        &[Some(tcp_hash), None],
        2,
        2,
    );
    let tcp_alternate_commitment = model_directory_commitment(
        tcp_alternate_key,
        TCP_MAPPING_DOMAIN,
        &[Some(tcp_alternate_hash), None],
        2,
        2,
    );
    assert!(
        tcp_commitment != tcp_alternate_commitment,
        "TCP model commitment must bind the alternate key"
    );

    let firewall_seed = 0x6a09_e667_f3bc_c910_u64;
    let firewall_key = (firewall_seed | 1, firewall_seed.rotate_left(17) | 1);
    let firewall_alternate_key = (firewall_key.0 ^ 0x0005, firewall_key.1);
    let firewall_source_port = (16_001_u16..17_001).find(|source_port| {
        let packet = ModelFirewallPacket {
            protocol_tcp: false,
            ingress: u32::from(LAN.0),
            egress: u32::from(WAN.0),
            source: address_word(HOST),
            destination: address_word(REMOTE),
            source_port: *source_port,
            destination_port: 53,
            tcp_flags: 0,
        };
        let canonical = model_firewall_hash(firewall_key, packet);
        let alternate = model_firewall_hash(firewall_alternate_key, packet);
        (canonical as usize % 4) == (alternate as usize % 4)
    });
    let firewall_source_port =
        firewall_source_port.expect("bounded firewall alternate-key probe has a shared slot");
    let firewall_packet = ModelFirewallPacket {
        protocol_tcp: false,
        ingress: u32::from(LAN.0),
        egress: u32::from(WAN.0),
        source: address_word(HOST),
        destination: address_word(REMOTE),
        source_port: firewall_source_port,
        destination_port: 53,
        tcp_flags: 0,
    };
    let firewall_start = model_firewall_hash(firewall_key, firewall_packet) as usize % 4;
    let alternate_firewall_start =
        model_firewall_hash(firewall_alternate_key, firewall_packet) as usize % 4;
    assert_eq!(firewall_start, alternate_firewall_start);
    let mut firewall_states = [ModelFirewallSlot::default(); 4];
    firewall_states[firewall_start] = ModelFirewallSlot {
        occupied: true,
        slot_generation: 1,
        config_generation: FIREWALL_CONFIG_GENERATION,
        protocol_tcp: false,
        origin_ingress: u32::from(LAN.0),
        origin_egress: u32::from(WAN.0),
        initiator_address: address_word(HOST),
        responder_address: address_word(REMOTE),
        initiator_port: firewall_source_port,
        responder_port: 53,
        last_activity_ms: 10,
        tcp_phase_active: false,
        tcp_forward_ack: false,
        tcp_reverse_ack: false,
        origin_rule_id: 10,
    };
    let firewall_commitment =
        model_firewall_authority(&firewall_states, firewall_key, Some(10), 1, 2);
    let alternate_firewall_commitment =
        model_firewall_authority(&firewall_states, firewall_alternate_key, Some(10), 1, 2);
    assert!(
        firewall_commitment != alternate_firewall_commitment,
        "firewall model commitment must bind the alternate key"
    );
}

fn model_firewall_insert(
    states: &mut [ModelFirewallSlot],
    key: (u64, u64),
    packet: ModelFirewallPacket,
    now_ms: u64,
    generation: u64,
    rule_id: u32,
) -> usize {
    let start = model_firewall_hash(key, packet) as usize % states.len();
    for distance in 0..states.len() {
        let index = (start + distance) % states.len();
        if !states[index].occupied {
            states[index] = ModelFirewallSlot {
                occupied: true,
                slot_generation: generation,
                config_generation: FIREWALL_CONFIG_GENERATION,
                protocol_tcp: packet.protocol_tcp,
                origin_ingress: packet.ingress,
                origin_egress: packet.egress,
                initiator_address: packet.source,
                responder_address: packet.destination,
                initiator_port: packet.source_port,
                responder_port: packet.destination_port,
                last_activity_ms: now_ms,
                tcp_phase_active: false,
                tcp_forward_ack: false,
                tcp_reverse_ack: false,
                origin_rule_id: rule_id,
            };
            return index;
        }
    }
    panic!("model firewall capacity");
}

fn model_firewall_established(
    states: &mut [ModelFirewallSlot],
    key: (u64, u64),
    packet: ModelFirewallPacket,
    now_ms: u64,
) {
    let start = model_firewall_hash(key, packet) as usize % states.len();
    for distance in 0..states.len() {
        let index = (start + distance) % states.len();
        let state = states[index];
        if !state.occupied {
            panic!("model established firewall flow missing");
        }
        if state.protocol_tcp != packet.protocol_tcp {
            continue;
        }
        let direct = state.origin_ingress == packet.ingress
            && state.origin_egress == packet.egress
            && state.initiator_address == packet.source
            && state.responder_address == packet.destination
            && state.initiator_port == packet.source_port
            && state.responder_port == packet.destination_port;
        let reverse = state.origin_ingress == packet.egress
            && state.origin_egress == packet.ingress
            && state.initiator_address == packet.destination
            && state.responder_address == packet.source
            && state.initiator_port == packet.destination_port
            && state.responder_port == packet.source_port;
        if direct || reverse {
            let mut replacement = state;
            if packet.protocol_tcp && packet.tcp_flags & 0x10 != 0 {
                if reverse {
                    replacement.tcp_reverse_ack = true;
                } else {
                    replacement.tcp_forward_ack = true;
                }
                replacement.tcp_phase_active =
                    replacement.tcp_forward_ack && replacement.tcp_reverse_ack;
            }
            if packet.tcp_flags & 0x04 == 0 {
                replacement.last_activity_ms = now_ms;
            }
            states[index] = replacement;
            return;
        }
    }
    panic!("model established firewall flow not found");
}

/// Runs the small, non-ignored state contract matrix used by the ordinary test suite.
pub fn run_short_state_smoke() {
    run_state_matrix(&[V1_SEEDS[0]]);
}

/// Replays the concrete R16 combined NAT/firewall transaction regression.
///
/// The seed is the exact `case_index = 6` matrix seed from the fixed corpus;
/// running it twice keeps the full typed end-state as the replay contract.
pub fn run_combined_nat_firewall_fixed_regression() {
    let seed = V1_SEEDS[0]
        .checked_add(7)
        .expect("fixed combined state seed cannot overflow");
    assert_eq!(seed, 0x6a09_e667_f3bc_c910);
    let first = run_state_case(StateCase::CombinedNatFirewallTransaction, seed);
    let replay = run_state_case(StateCase::CombinedNatFirewallTransaction, seed);
    assert_eq!(first, replay, "fixed combined NAT/firewall replay");
}

/// Runs the fixed four-seed state matrix. Every case owns bounded storage and a
/// fixed packet budget; it deliberately does not extend the R16A envelope target set.
pub fn run_full_state_smoke() {
    run_state_matrix(&V1_SEEDS);
}

fn run_state_matrix(seeds: &[u64]) {
    assert!(!seeds.is_empty(), "state matrix requires at least one seed");
    assert!(
        seeds.len() <= MAX_STATE_SEEDS,
        "state seed count exceeds fixed upper bound"
    );
    assert!(
        STATE_CASES.len() <= MAX_STATE_CASES,
        "state case count exceeds fixed upper bound"
    );
    let run_count = STATE_CASES
        .len()
        .checked_mul(seeds.len())
        .expect("state matrix size overflow");
    assert!(
        run_count <= MAX_STATE_CASES * MAX_STATE_SEEDS,
        "state matrix run count exceeds fixed upper bound"
    );
    for (case_index, case) in STATE_CASES.into_iter().enumerate() {
        for seed in seeds.iter().copied() {
            let case_seed = seed.wrapping_add(case_index as u64 + 1);
            assert!(case_index < MAX_STATE_CASES, "state case index overflow");
            let first = run_state_case(case, case_seed);
            let replay = run_state_case(case, case_seed);
            assert_eq!(
                first,
                replay,
                "state case={} seed={case_seed:#018x} must replay exactly",
                case.name()
            );
        }
    }
}

fn run_state_case(case: StateCase, seed: u64) -> StateEvidence {
    match case {
        StateCase::UdpRewriteAndFilter => udp_rewrite_and_filter(seed),
        StateCase::UdpCapacityTimeoutAndReuse => udp_capacity_timeout_and_reuse(seed),
        StateCase::FirewallCapacityExpiryAndTxReject => {
            firewall_capacity_expiry_and_tx_reject(seed)
        }
        StateCase::TcpBoundaryAndTxReject => tcp_boundary_and_tx_reject(seed),
        StateCase::NoNeighborReject => no_neighbor_reject(seed),
        StateCase::RejectPathsAreMutationFree => reject_paths_are_mutation_free(seed),
        StateCase::CombinedNatFirewallTransaction => combined_nat_firewall_transaction(seed),
        StateCase::FirewallDenyModes => firewall_deny_modes(seed),
        StateCase::UdpMalformedChecksumCollision => udp_malformed_checksum_collision(seed),
        StateCase::TcpExpiryCapacityAndExhaustion => tcp_expiry_capacity_and_exhaustion(seed),
        StateCase::ClockRegressionAndWatermark => clock_regression_and_watermark(seed),
        StateCase::DeterministicReplayEvidence => deterministic_replay_evidence(seed),
    }
}

fn topology() -> (
    [Route; 2],
    [Interface; 2],
    [Neighbor; 2],
    [LocalIpv4Binding; 2],
) {
    (
        [
            Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
            Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(GATEWAY)).unwrap(),
        ],
        [
            Interface {
                id: LAN,
                mac: LAN_MAC,
            },
            Interface {
                id: WAN,
                mac: WAN_MAC,
            },
        ],
        [
            Neighbor {
                interface: LAN,
                target: HOST,
                mac: HOST_MAC,
            },
            Neighbor {
                interface: WAN,
                target: GATEWAY,
                mac: GATEWAY_MAC,
            },
        ],
        [
            LocalIpv4Binding {
                interface: LAN,
                address: LAN_LOCAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: WAN_LOCAL,
            },
        ],
    )
}

fn no_wan_neighbor_topology() -> (
    [Route; 2],
    [Interface; 2],
    [Neighbor; 1],
    [LocalIpv4Binding; 2],
) {
    let (routes, interfaces, neighbors, bindings) = topology();
    (routes, interfaces, [neighbors[0]], bindings)
}

fn new_resolution<'a>(
    states: &'a mut [ResolutionStateSlot],
    actions: &'a mut [ResolutionActionSlot],
) -> ResolutionRuntime<'a> {
    ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        states,
        actions,
    )
}

fn new_resolution_with_dynamic<'a>(
    states: &'a mut [ResolutionStateSlot],
    actions: &'a mut [ResolutionActionSlot],
    dynamic_neighbors: &'a mut [DynamicNeighborSlot],
) -> ResolutionRuntime<'a> {
    ResolutionRuntime::with_dynamic_neighbors(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        states,
        actions,
        dynamic_neighbors,
    )
}

fn udp_config(
    snapshot: &ForwardingSnapshot<'_>,
    seed: u64,
    first_port: u16,
    last_port: u16,
) -> Nat44UdpConfig {
    Nat44UdpConfig::new(
        snapshot,
        LAN,
        WAN,
        WAN_LOCAL,
        first_port,
        last_port,
        Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS, seed | 1).unwrap(),
    )
    .unwrap()
}

fn tcp_config(
    snapshot: &ForwardingSnapshot<'_>,
    seed: u64,
    first_port: u16,
    last_port: u16,
) -> Nat44TcpConfig {
    Nat44TcpConfig::new(
        snapshot,
        LAN,
        WAN,
        WAN_LOCAL,
        first_port,
        last_port,
        Nat44TcpPolicy::new(NAT44_TCP_MIN_IDLE_TTL_MS, seed | 1).unwrap(),
    )
    .unwrap()
}

fn any_prefix() -> FirewallIpv4Prefix {
    FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap()
}

fn allow_rule(id: u32, protocol: FirewallProtocol) -> FirewallRule {
    FirewallRule::new(
        FirewallRuleId(id),
        FirewallInterface::Interface(LAN),
        FirewallInterface::Interface(WAN),
        FirewallIpv4Prefix::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24).unwrap(),
        any_prefix(),
        protocol,
        FirewallPortRange::new(1, u16::MAX).unwrap(),
        FirewallPortRange::new(1, u16::MAX).unwrap(),
        FirewallAction::AllowStateful,
    )
}

fn deny_rule(id: u32, protocol: FirewallProtocol) -> FirewallRule {
    FirewallRule::new(
        FirewallRuleId(id),
        FirewallInterface::Interface(LAN),
        FirewallInterface::Interface(WAN),
        FirewallIpv4Prefix::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24).unwrap(),
        any_prefix(),
        protocol,
        FirewallPortRange::new(1, u16::MAX).unwrap(),
        FirewallPortRange::new(1, u16::MAX).unwrap(),
        FirewallAction::Deny,
    )
}

fn firewall_config<'rules>(
    snapshot: &ForwardingSnapshot<'_>,
    rules: &'rules [FirewallRule],
    seed: u64,
) -> FirewallConfig<'rules> {
    FirewallConfig::new(
        snapshot,
        rules,
        FirewallPolicy::new(
            FIREWALL_UDP_MIN_IDLE_TTL_MS,
            FIREWALL_TCP_OPENING_MIN_IDLE_TTL_MS,
            FIREWALL_TCP_ACTIVE_MIN_IDLE_TTL_MS,
        )
        .unwrap(),
        1,
        FirewallHashKey::new(seed | 1, seed.rotate_left(17) | 1).unwrap(),
    )
    .unwrap()
}

fn udp_frame(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    flags_fragment: u16,
) -> Vec<u8> {
    let payload = [1_u8, 2, 3];
    let udp_len = 8 + payload.len();
    let mut frame = vec![0_u8; 14 + 20 + udp_len + 3];
    let (destination_mac, source_mac) = if source == HOST {
        (LAN_MAC, HOST_MAC)
    } else {
        (WAN_MAC, GATEWAY_MAC)
    };
    frame[0..6].copy_from_slice(&destination_mac.0);
    frame[6..12].copy_from_slice(&source_mac.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&(u16::try_from(20 + udp_len).unwrap()).to_be_bytes());
    frame[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    frame[38..40].copy_from_slice(&(u16::try_from(udp_len).unwrap()).to_be_bytes());
    frame[42..45].copy_from_slice(&payload);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn tcp_frame(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    flags: u8,
    flags_fragment: u16,
) -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 40 + 3];
    let (destination_mac, source_mac) = if source == HOST {
        (LAN_MAC, HOST_MAC)
    } else {
        (WAN_MAC, GATEWAY_MAC)
    };
    frame[0..6].copy_from_slice(&destination_mac.0);
    frame[6..12].copy_from_slice(&source_mac.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&40_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    frame[38..42].copy_from_slice(&1_u32.to_be_bytes());
    frame[42..46].copy_from_slice(&2_u32.to_be_bytes());
    frame[46] = 5 << 4;
    frame[47] = flags;
    frame[48..50].copy_from_slice(&4096_u16.to_be_bytes());
    let mut pseudo_header = Vec::with_capacity(32);
    pseudo_header.extend_from_slice(&source.octets());
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.extend_from_slice(&[0, 6]);
    pseudo_header.extend_from_slice(&20_u16.to_be_bytes());
    pseudo_header.extend_from_slice(&frame[34..54]);
    let checksum = internet_checksum(&pseudo_header);
    frame[50..52].copy_from_slice(&checksum.to_be_bytes());
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn rewrite_ipv4_header_checksum(frame: &mut [u8]) {
    let header_len = usize::from(frame[14] & 0x0f) * 4;
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..14 + header_len]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
}

/// Independent one's-complement checksum reference used only by the R16
/// oracle. It intentionally does not call the production checksum helper.
fn reference_transport_checksum(
    source: Ipv4Address,
    destination: Ipv4Address,
    protocol: u8,
    segment: &[u8],
) -> u16 {
    let source = source.octets();
    let destination = destination.octets();
    let mut sum = u32::from(u16::from_be_bytes([source[0], source[1]]))
        + u32::from(u16::from_be_bytes([source[2], source[3]]))
        + u32::from(u16::from_be_bytes([destination[0], destination[1]]))
        + u32::from(u16::from_be_bytes([destination[2], destination[3]]))
        + u32::from(protocol)
        + u32::try_from(segment.len()).unwrap();
    for chunk in segment.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum = (sum & 0xffff) + (sum >> 16) + u32::from(word);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_frame_with_reference_checksum(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    flags_fragment: u16,
) -> Vec<u8> {
    let mut frame = udp_frame(
        source,
        destination,
        source_port,
        destination_port,
        flags_fragment,
    );
    frame[40..42].fill(0);
    let length = usize::from(u16::from_be_bytes(frame[38..40].try_into().unwrap()));
    let checksum = reference_transport_checksum(source, destination, 17, &frame[34..34 + length]);
    frame[40..42].copy_from_slice(&if checksum == 0 { 0xffff } else { checksum }.to_be_bytes());
    frame
}

fn assert_udp_reference_checksum(frame: &[u8]) {
    let source = Ipv4Address::from_octets(frame[26..30].try_into().unwrap());
    let destination = Ipv4Address::from_octets(frame[30..34].try_into().unwrap());
    let length = usize::from(u16::from_be_bytes(frame[38..40].try_into().unwrap()));
    assert_eq!(
        reference_transport_checksum(source, destination, 17, &frame[34..34 + length]),
        0,
        "independent UDP checksum validation"
    );
}

fn assert_tcp_reference_checksum(frame: &[u8]) {
    let source = Ipv4Address::from_octets(frame[26..30].try_into().unwrap());
    let destination = Ipv4Address::from_octets(frame[30..34].try_into().unwrap());
    let total_len = usize::from(u16::from_be_bytes(frame[16..18].try_into().unwrap()));
    let header_len = usize::from(frame[14] & 0x0f) * 4;
    assert_eq!(
        reference_transport_checksum(
            source,
            destination,
            6,
            &frame[14 + header_len..14 + total_len],
        ),
        0,
        "independent TCP checksum validation"
    );
}

fn assert_drop(io: &mut SimIo, reason: DropReason, original: &[u8]) {
    let dropped = io.pop_recycled().expect("one rejected frame");
    assert_eq!(dropped.cause, RecycleCause::Forwarding(reason));
    assert_eq!(dropped.bytes, original);
}

fn assert_batch(report: &ruster_core::BatchReport<std::convert::Infallible>) {
    assert!(report.invariants_hold());
}

fn assert_no_slot_or_neighbor_state(
    udp: &Nat44UdpRuntime<'_>,
    tcp: &Nat44TcpRuntime<'_>,
    firewall: &FirewallRuntime<'_>,
    resolution: &ResolutionRuntime<'_>,
    io: &SimIo,
) {
    assert!(udp.mappings().iter().all(|slot| !slot.is_occupied()));
    assert!(udp.peers().iter().all(|slot| !slot.is_occupied()));
    assert!(tcp.mappings().iter().all(|slot| !slot.is_occupied()));
    assert!(tcp.sessions().iter().all(|slot| !slot.is_occupied()));
    assert!(firewall.states().iter().all(|slot| !slot.is_occupied()));
    assert_eq!(
        (
            resolution.pending_states(),
            resolution.pending_actions(),
            resolution.pending_failure_holds(),
            resolution.dynamic_neighbor_count(),
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(
        (io.pending_rx(), io.pending_tx(), io.pending_recycled()),
        (0, 0, 0)
    );
}

fn udp_tx_reject_keeps_state(snapshot: &ForwardingSnapshot<'_>, seed: u64) {
    let config = udp_config(snapshot, seed, 40_010, 40_010);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = indexes.runtime(config, &mut mappings, &mut peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = new_resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.set_received_accept_budget(0);
    let packet = udp_frame(HOST, REMOTE, 12_099, 53, 0x4000);
    io.inject(LAN, packet.clone());
    let report = io
        .run_nat44_udp_once(
            1,
            snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_eq!(report.completion.tx_rejected, 1);
    let rejected = io.pop_recycled().expect("rejected UDP TX is recycled");
    assert_eq!(rejected.cause, RecycleCause::TxRejected);
    assert_eq!(&rejected.bytes[26..30], &WAN_LOCAL.octets());
    assert_eq!(&rejected.bytes[30..34], &REMOTE.octets());
    assert_eq!(nat.counters().mappings_created, 1);
    assert_eq!(nat.counters().peers_created, 1);
    assert_eq!(nat.counters().outbound_translated, 1);
    assert!(nat.mappings()[0].is_occupied());
    assert!(nat.peers()[0].is_occupied());
    assert_eq!(resolution.pending_actions(), 0);
}

fn udp_rewrite_and_filter(seed: u64) -> StateEvidence {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = udp_config(&snapshot, seed, 40_000, 40_001);
    let mut mappings = [Nat44UdpMappingSlot::default(); 2];
    let mut peers = [Nat44UdpPeerSlot::default(); 2];
    let mut indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = indexes.runtime(config, &mut mappings, &mut peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = new_resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    let internal_port = 12_000 + (seed as u16 % 500);
    let outbound = udp_frame(HOST, REMOTE, internal_port, 53, 0x4000);
    io.inject(LAN, outbound);
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_eq!(report.completion.tx_accepted, 1);
    let translated = io.pop_tx().expect("UDP outbound translation");
    assert_eq!(translated.egress, WAN);
    assert_eq!(&translated.bytes[26..30], &WAN_LOCAL.octets());
    assert_eq!(&translated.bytes[30..34], &REMOTE.octets());
    let public_port = u16::from_be_bytes(translated.bytes[34..36].try_into().unwrap());
    assert_ne!(public_port, internal_port);
    assert_eq!(
        nat.mappings()
            .iter()
            .filter(|slot| slot.is_occupied())
            .count(),
        1
    );
    assert_eq!(
        nat.peers().iter().filter(|slot| slot.is_occupied()).count(),
        1
    );
    assert_eq!(nat.counters().mappings_created, 1);
    assert_eq!(nat.counters().peers_created, 1);
    assert_eq!(nat.counters().outbound_translated, 1);

    let inbound = udp_frame(REMOTE, WAN_LOCAL, 53, public_port, 0x4000);
    io.inject(WAN, inbound);
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(1),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    let translated = io.pop_tx().expect("UDP reverse translation");
    assert_eq!(translated.egress, LAN);
    assert_eq!(&translated.bytes[26..30], &REMOTE.octets());
    assert_eq!(&translated.bytes[30..34], &HOST.octets());
    assert_eq!(
        u16::from_be_bytes(translated.bytes[36..38].try_into().unwrap()),
        internal_port
    );
    assert_eq!(nat.counters().inbound_translated, 1);

    let denied = udp_frame(OTHER_REMOTE, WAN_LOCAL, 53, public_port, 0x4000);
    let before = nat.mappings().to_vec();
    io.inject(WAN, denied.clone());
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(2),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(&mut io, DropReason::Nat44UdpFilterDenied, &denied);
    assert_eq!(nat.mappings(), before.as_slice());
    assert_eq!(nat.counters().filter_denied, 1);
    udp_tx_reject_keeps_state(&snapshot, seed ^ 0x5a5a);
    capture_state_evidence(Some(&nat), None, None, &resolution, &io)
}

fn udp_capacity_timeout_and_reuse(seed: u64) -> StateEvidence {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = udp_config(&snapshot, seed, 40_000, 40_000);
    let mut mappings = [Nat44UdpMappingSlot::default(); 2];
    let mut peers = [Nat44UdpPeerSlot::default(); 2];
    let mut indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = indexes.runtime(config, &mut mappings, &mut peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = new_resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    let first = udp_frame(HOST, REMOTE, 12_001, 53, 0x4000);
    io.inject(LAN, first.clone());
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    io.pop_tx().expect("first mapping");

    let exhausted = udp_frame(HOST, OTHER_REMOTE, 12_002, 53, 0x4000);
    io.inject(LAN, exhausted.clone());
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(1),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(&mut io, DropReason::Nat44UdpPortExhausted, &exhausted);
    assert_eq!(nat.counters().port_exhausted, 1);
    assert_eq!(
        nat.mappings()
            .iter()
            .filter(|slot| slot.is_occupied())
            .count(),
        1
    );

    let reused = udp_frame(HOST, OTHER_REMOTE, 12_002, 53, 0x4000);
    io.inject(LAN, reused);
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(NAT44_UDP_MIN_IDLE_TTL_MS),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    io.pop_tx().expect("expired mapping reuses its port");
    assert_eq!(nat.counters().mappings_expired, 1);
    assert_eq!(nat.counters().mappings_created, 2);
    assert_eq!(
        nat.mappings()
            .iter()
            .filter(|slot| slot.is_occupied())
            .count(),
        1
    );

    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = udp_config(&snapshot, seed ^ 0x55, 40_000, 40_001);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = indexes.runtime(config, &mut mappings, &mut peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution_for_mapping_capacity = new_resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    let first = udp_frame(HOST, REMOTE, 12_101, 53, 0x4000);
    io.inject(LAN, first.clone());
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution_for_mapping_capacity,
            &config,
            Some(&mut nat),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    io.pop_tx().expect("mapping capacity setup");
    let full = udp_frame(HOST, OTHER_REMOTE, 12_102, 53, 0x4000);
    io.inject(LAN, full.clone());
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution_for_mapping_capacity,
            &config,
            Some(&mut nat),
            MonotonicMillis(1),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(&mut io, DropReason::Nat44UdpMappingTableFull, &full);
    assert_eq!(nat.counters().mapping_full, 1);
    assert_eq!(
        nat.mappings()
            .iter()
            .filter(|slot| slot.is_occupied())
            .count(),
        1
    );
    capture_state_evidence(
        Some(&nat),
        None,
        None,
        &resolution_for_mapping_capacity,
        &io,
    )
}

fn firewall_capacity_expiry_and_tx_reject(seed: u64) -> StateEvidence {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let rules = [allow_rule(10, FirewallProtocol::Udp)];
    let config = firewall_config(&snapshot, &rules, seed);
    let mut slots = [FirewallStateSlot::default(); 1];
    let mut firewall = FirewallRuntime::new(config, &mut slots);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = new_resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.set_received_accept_budget(0);
    let rejected = udp_frame(HOST, REMOTE, 13_001, 53, 0);
    io.inject(LAN, rejected.clone());
    let report = io
        .run_firewall_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut firewall),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_eq!(report.completion.tx_rejected, 1);
    assert_eq!(io.pop_recycled().unwrap().cause, RecycleCause::TxRejected);
    assert!(firewall.states()[0].is_occupied());
    assert_eq!(firewall.counters().allowed_new, 1);

    io.set_received_accept_budget(usize::MAX);
    let full = udp_frame(HOST, OTHER_REMOTE, 13_002, 53, 0);
    io.inject(LAN, full.clone());
    let report = io
        .run_firewall_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut firewall),
            MonotonicMillis(1),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(&mut io, DropReason::FirewallStateTableFull, &full);
    assert_eq!(firewall.counters().state_full, 1);

    let expired = udp_frame(HOST, OTHER_REMOTE, 13_002, 53, 0);
    io.inject(LAN, expired);
    let report = io
        .run_firewall_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut firewall),
            MonotonicMillis(FIREWALL_UDP_MIN_IDLE_TTL_MS),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    io.pop_tx().expect("expired firewall state is reusable");
    assert_eq!(firewall.counters().allowed_new, 2);
    assert_eq!(firewall.counters().states_expired, 1);
    assert_eq!(
        firewall.states()[0].last_activity_ms(),
        FIREWALL_UDP_MIN_IDLE_TTL_MS
    );
    capture_state_evidence(None, None, Some(&firewall), &resolution, &io)
}

fn tcp_boundary_and_tx_reject(seed: u64) -> StateEvidence {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = tcp_config(&snapshot, seed, 41_000, 41_000);
    let mut mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut tcp = super::support::tcp_runtime(config, &mut mappings, &mut sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = new_resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.set_received_accept_budget(0);
    let syn = tcp_frame(HOST, REMOTE, 14_001, 443, 0x02, 0x4000);
    io.inject(LAN, syn);
    let report = io
        .run_nat44_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut tcp),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_eq!(report.completion.tx_rejected, 1);
    assert_eq!(io.pop_recycled().unwrap().cause, RecycleCause::TxRejected);
    assert!(tcp.mappings()[0].is_occupied());
    assert!(tcp.sessions()[0].is_occupied());
    assert_eq!(tcp.counters().outbound_translated, 1);

    io.set_received_accept_budget(usize::MAX);
    let public_port = tcp.mappings()[0].public_port();
    let syn_ack = tcp_frame(REMOTE, WAN_LOCAL, 443, public_port, 0x12, 0x4000);
    io.inject(WAN, syn_ack);
    let report = io
        .run_nat44_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut tcp),
            MonotonicMillis(1),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_eq!(report.completion.tx_accepted, 1);
    let translated = io.pop_tx().expect("TCP SYN-ACK uses retained state");
    assert_eq!(translated.egress, LAN);
    assert_eq!(&translated.bytes[26..30], &REMOTE.octets());
    assert_eq!(&translated.bytes[30..34], &HOST.octets());
    assert_eq!(
        u16::from_be_bytes(translated.bytes[36..38].try_into().unwrap()),
        14_001
    );
    assert_eq!(tcp.counters().inbound_translated, 1);

    let ack = tcp_frame(HOST, REMOTE, 14_001, 443, 0x10, 0x4000);
    io.inject(LAN, ack);
    let report = io
        .run_nat44_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut tcp),
            MonotonicMillis(2),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_eq!(report.completion.tx_accepted, 1);
    io.pop_tx().expect("TCP ACK uses the established session");
    assert_eq!(tcp.counters().outbound_translated, 2);

    let invalid_flags = tcp_frame(HOST, REMOTE, 14_002, 443, 0x10, 0x4000);
    io.inject(LAN, invalid_flags.clone());
    let report = io
        .run_nat44_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut tcp),
            MonotonicMillis(3),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(
        &mut io,
        DropReason::Nat44TcpInvalidInitialFlags,
        &invalid_flags,
    );
    assert_eq!(tcp.counters().invalid_initial_flags, 1);

    let mut too_small = tcp_frame(HOST, REMOTE, 14_002, 443, 0x02, 0x4000);
    too_small[46] = 4 << 4;
    let mut too_large = tcp_frame(HOST, REMOTE, 14_003, 443, 0x02, 0x4000);
    too_large[46] = 6 << 4;
    for (now, frame, reason) in [
        (4, too_small, DropReason::Nat44TcpDataOffsetTooSmall),
        (
            5,
            too_large,
            DropReason::Nat44TcpDataOffsetExceedsIpv4Payload,
        ),
    ] {
        io.inject(LAN, frame.clone());
        let report = io
            .run_nat44_tcp_once(
                1,
                &snapshot,
                &mut resolution,
                &config,
                Some(&mut tcp),
                MonotonicMillis(now),
                &mut NoTrace,
            )
            .unwrap();
        assert_batch(&report);
        assert_drop(&mut io, reason, &frame);
    }
    assert_eq!(
        tcp.mappings()
            .iter()
            .filter(|slot| slot.is_occupied())
            .count(),
        1
    );
    assert_eq!(
        tcp.sessions()
            .iter()
            .filter(|slot| slot.is_occupied())
            .count(),
        1
    );
    capture_state_evidence(None, Some(&tcp), None, &resolution, &io)
}

fn no_neighbor_reject(seed: u64) -> StateEvidence {
    let (routes, interfaces, neighbors, bindings) = no_wan_neighbor_topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = udp_config(&snapshot, seed, 42_000, 42_001);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = indexes.runtime(config, &mut mappings, &mut peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = new_resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    let packet = udp_frame(HOST, REMOTE, 15_001, 53, 0x4000);
    io.inject(LAN, packet.clone());
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(&mut io, DropReason::NeighborUnresolved, &packet);
    assert_eq!(io.pending_tx(), 0);
    assert_eq!(resolution.pending_actions(), 1);
    assert!(nat.mappings().iter().all(|slot| !slot.is_occupied()));
    assert!(nat.peers().iter().all(|slot| !slot.is_occupied()));
    assert_eq!(nat.counters().outbound_translated, 0);
    assert_eq!(nat.counters().mappings_created, 0);
    capture_state_evidence(Some(&nat), None, None, &resolution, &io)
}

#[allow(clippy::too_many_arguments)]
fn assert_combined_reject(
    snapshot: &ForwardingSnapshot<'_>,
    resolution: &mut ResolutionRuntime<'_>,
    udp_config: &Nat44UdpConfig,
    nat: &mut Nat44UdpRuntime<'_>,
    tcp_config: &Nat44TcpConfig,
    tcp: &mut Nat44TcpRuntime<'_>,
    firewall_config: &FirewallConfig<'_>,
    firewall: &mut FirewallRuntime<'_>,
    io: &mut SimIo,
    packet: Vec<u8>,
    reason: DropReason,
    now: u64,
    expected_udp: Nat44UdpCounters,
    expected_tcp: Nat44TcpCounters,
    expected_firewall: FirewallCounters,
    expected_resolution: ResolutionCounters,
    expected_resolution_failure: ResolutionFailureCounters,
) {
    io.inject(LAN, packet.clone());
    let report = io
        .run_nat44_udp_and_tcp_with_firewall_once(
            1,
            snapshot,
            resolution,
            udp_config,
            Some(nat),
            tcp_config,
            Some(tcp),
            firewall_config,
            Some(firewall),
            MonotonicMillis(now),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_eq!(report.dropped, 1);
    assert_drop(io, reason, &packet);
    assert_eq!(nat.counters(), expected_udp);
    assert_eq!(tcp.counters(), expected_tcp);
    assert_eq!(firewall.counters(), expected_firewall);
    assert_eq!(resolution.counters(), expected_resolution);
    assert_eq!(resolution.failure_counters(), expected_resolution_failure);
    assert_no_slot_or_neighbor_state(nat, tcp, firewall, resolution, io);
}

fn reject_paths_are_mutation_free(seed: u64) -> StateEvidence {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let udp_config = udp_config(&snapshot, seed, 40_000, 40_001);
    let tcp_config = tcp_config(&snapshot, seed, 41_000, 41_001);
    let rules = [
        allow_rule(10, FirewallProtocol::Udp),
        allow_rule(20, FirewallProtocol::Tcp),
    ];
    let firewall_config = firewall_config(&snapshot, &rules, seed);
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 2];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 2];
    let mut udp_indexes = UdpTestIndexes::new(udp_config, udp_mappings.len(), udp_peers.len());
    let mut nat = udp_indexes.runtime(udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 2];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 2];
    let mut tcp = super::support::tcp_runtime(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let mut firewall_slots = [FirewallStateSlot::default(); 2];
    let mut firewall = FirewallRuntime::new(firewall_config, &mut firewall_slots);
    let mut resolution_states = [ResolutionStateSlot::EMPTY; 2];
    let mut resolution_actions = [ResolutionActionSlot::EMPTY; 2];
    let mut dynamic_neighbors = [DynamicNeighborSlot::EMPTY; 2];
    let mut resolution = new_resolution_with_dynamic(
        &mut resolution_states,
        &mut resolution_actions,
        &mut dynamic_neighbors,
    );
    let mut io = SimIo::new();

    let before_udp = nat.counters();
    let before_tcp = tcp.counters();
    let before_firewall = firewall.counters();
    let before_resolution = resolution.counters();
    let before_resolution_failure = resolution.failure_counters();
    assert_combined_reject(
        &snapshot,
        &mut resolution,
        &udp_config,
        &mut nat,
        &tcp_config,
        &mut tcp,
        &firewall_config,
        &mut firewall,
        &mut io,
        vec![0; 8],
        DropReason::EthernetHeaderTruncated,
        10,
        before_udp,
        before_tcp,
        before_firewall,
        before_resolution,
        before_resolution_failure,
    );

    let before_udp = nat.counters();
    let before_tcp = tcp.counters();
    let before_firewall = firewall.counters();
    let before_resolution = resolution.counters();
    let before_resolution_failure = resolution.failure_counters();
    let mut admission = udp_frame(HOST, REMOTE, 12_001, 53, 0x4000);
    admission[0..6].copy_from_slice(&[0x02, 9, 9, 9, 9, 9]);
    assert_combined_reject(
        &snapshot,
        &mut resolution,
        &udp_config,
        &mut nat,
        &tcp_config,
        &mut tcp,
        &firewall_config,
        &mut firewall,
        &mut io,
        admission,
        DropReason::EthernetDestinationNotLocal,
        11,
        before_udp,
        before_tcp,
        before_firewall,
        before_resolution,
        before_resolution_failure,
    );

    let before_udp = nat.counters();
    let before_tcp = tcp.counters();
    let before_firewall = firewall.counters();
    let before_resolution = resolution.counters();
    let before_resolution_failure = resolution.failure_counters();
    let mut bad_ip_checksum = udp_frame(HOST, REMOTE, 12_002, 53, 0x4000);
    bad_ip_checksum[24] ^= 1;
    assert_combined_reject(
        &snapshot,
        &mut resolution,
        &udp_config,
        &mut nat,
        &tcp_config,
        &mut tcp,
        &firewall_config,
        &mut firewall,
        &mut io,
        bad_ip_checksum,
        DropReason::Ipv4HeaderChecksumInvalid,
        12,
        before_udp,
        before_tcp,
        before_firewall,
        before_resolution,
        before_resolution_failure,
    );

    let before_udp = nat.counters();
    let before_tcp = tcp.counters();
    let before_firewall = firewall.counters();
    let before_resolution = resolution.counters();
    let before_resolution_failure = resolution.failure_counters();
    let mut bad_udp_checksum = udp_frame(HOST, REMOTE, 12_003, 53, 0x4000);
    bad_udp_checksum[40..42].copy_from_slice(&1_u16.to_be_bytes());
    let mut expected_firewall = before_firewall;
    expected_firewall.invalid_packets = expected_firewall.invalid_packets.saturating_add(1);
    assert_combined_reject(
        &snapshot,
        &mut resolution,
        &udp_config,
        &mut nat,
        &tcp_config,
        &mut tcp,
        &firewall_config,
        &mut firewall,
        &mut io,
        bad_udp_checksum,
        DropReason::FirewallUdpChecksumInvalid,
        13,
        before_udp,
        before_tcp,
        expected_firewall,
        before_resolution,
        before_resolution_failure,
    );

    let (mismatch_routes, mismatch_interfaces, mut mismatch_neighbors, mismatch_bindings) =
        topology();
    mismatch_neighbors[1].mac = MacAddress([0x02, 0, 0, 0, 0, 21]);
    let mismatch_snapshot = ForwardingSnapshot::new(
        &mismatch_routes,
        &mismatch_interfaces,
        &mismatch_neighbors,
        &mismatch_bindings,
    )
    .unwrap();
    let mismatch_udp_config = self::udp_config(&mismatch_snapshot, seed, 40_000, 40_001);
    let mismatch_firewall_config = self::firewall_config(&mismatch_snapshot, &rules, seed);

    let before_udp = nat.counters();
    let before_tcp = tcp.counters();
    let before_firewall = firewall.counters();
    let before_resolution = resolution.counters();
    let before_resolution_failure = resolution.failure_counters();
    let packet = udp_frame(HOST, REMOTE, 12_004, 53, 0x4000);
    io.inject(LAN, packet.clone());
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &mismatch_udp_config,
            Some(&mut nat),
            MonotonicMillis(14),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(&mut io, DropReason::Nat44UdpConfigMismatch, &packet);
    let mut expected_udp = before_udp;
    expected_udp.config_mismatches = expected_udp.config_mismatches.saturating_add(1);
    assert_eq!(nat.counters(), expected_udp);
    assert_eq!(tcp.counters(), before_tcp);
    assert_eq!(firewall.counters(), before_firewall);
    assert_eq!(resolution.counters(), before_resolution);
    assert_eq!(resolution.failure_counters(), before_resolution_failure);
    assert_no_slot_or_neighbor_state(&nat, &tcp, &firewall, &resolution, &io);

    let before_udp = nat.counters();
    let before_tcp = tcp.counters();
    let before_firewall = firewall.counters();
    let before_resolution = resolution.counters();
    let before_resolution_failure = resolution.failure_counters();
    let packet = udp_frame(HOST, REMOTE, 12_005, 53, 0x4000);
    io.inject(LAN, packet.clone());
    let report = io
        .run_firewall_once(
            1,
            &snapshot,
            &mut resolution,
            &mismatch_firewall_config,
            Some(&mut firewall),
            MonotonicMillis(15),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(&mut io, DropReason::FirewallConfigMismatch, &packet);
    let mut expected_firewall = before_firewall;
    expected_firewall.config_mismatches = expected_firewall.config_mismatches.saturating_add(1);
    assert_eq!(nat.counters(), before_udp);
    assert_eq!(tcp.counters(), before_tcp);
    assert_eq!(firewall.counters(), expected_firewall);
    assert_eq!(resolution.counters(), before_resolution);
    assert_eq!(resolution.failure_counters(), before_resolution_failure);
    assert_no_slot_or_neighbor_state(&nat, &tcp, &firewall, &resolution, &io);

    let (all_routes, no_route_interfaces, no_route_neighbors, no_route_bindings) = topology();
    let no_remote_routes = [all_routes[0]];
    let no_route_snapshot = ForwardingSnapshot::new(
        &no_remote_routes,
        &no_route_interfaces,
        &no_route_neighbors,
        &no_route_bindings,
    )
    .unwrap();
    let no_route_config = self::udp_config(&no_route_snapshot, seed, 42_010, 42_010);
    let mut no_route_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut no_route_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut no_route_indexes = UdpTestIndexes::new(
        no_route_config,
        no_route_mappings.len(),
        no_route_peers.len(),
    );
    let mut no_route_nat =
        no_route_indexes.runtime(no_route_config, &mut no_route_mappings, &mut no_route_peers);
    let mut no_route_states = [ResolutionStateSlot::EMPTY; 1];
    let mut no_route_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut no_route_dynamic = [DynamicNeighborSlot::EMPTY; 1];
    let mut no_route_resolution = new_resolution_with_dynamic(
        &mut no_route_states,
        &mut no_route_actions,
        &mut no_route_dynamic,
    );
    let mut no_route_io = SimIo::new();
    let no_route_packet = udp_frame(HOST, REMOTE, 12_006, 53, 0x4000);
    no_route_io.inject(LAN, no_route_packet.clone());
    let report = no_route_io
        .run_nat44_udp_once(
            1,
            &no_route_snapshot,
            &mut no_route_resolution,
            &no_route_config,
            Some(&mut no_route_nat),
            MonotonicMillis(16),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(&mut no_route_io, DropReason::RouteMiss, &no_route_packet);
    assert!(no_route_nat
        .mappings()
        .iter()
        .all(|slot| !slot.is_occupied()));
    assert!(no_route_nat.peers().iter().all(|slot| !slot.is_occupied()));
    assert_eq!(no_route_nat.counters(), Nat44UdpCounters::default());
    assert_eq!(
        no_route_resolution.counters(),
        ResolutionCounters::default()
    );
    assert_eq!(
        no_route_resolution.failure_counters(),
        ResolutionFailureCounters::default()
    );
    assert_eq!(
        (
            no_route_resolution.pending_states(),
            no_route_resolution.pending_actions(),
            no_route_resolution.dynamic_neighbor_count(),
            no_route_io.pending_rx(),
            no_route_io.pending_tx(),
            no_route_io.pending_recycled(),
        ),
        (0, 0, 0, 0, 0, 0)
    );

    capture_state_evidence(Some(&nat), Some(&tcp), Some(&firewall), &resolution, &io)
}

fn combined_nat_firewall_transaction(seed: u64) -> StateEvidence {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let combined_udp_config = udp_config(&snapshot, seed, 40_000, 40_001);
    let combined_tcp_config = tcp_config(&snapshot, seed ^ 0x1010, 41_000, 41_001);
    let rules = [
        allow_rule(10, FirewallProtocol::Udp),
        allow_rule(20, FirewallProtocol::Tcp),
    ];
    let combined_firewall_config = firewall_config(&snapshot, &rules, seed);
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 2];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 2];
    let mut udp_indexes =
        UdpTestIndexes::new(combined_udp_config, udp_mappings.len(), udp_peers.len());
    let mut nat = udp_indexes.runtime(combined_udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 2];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 2];
    let mut tcp =
        super::support::tcp_runtime(combined_tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let mut firewall_slots = [FirewallStateSlot::default(); 4];
    let mut firewall = FirewallRuntime::new(combined_firewall_config, &mut firewall_slots);
    let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
    let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = new_resolution(&mut resolution_states, &mut resolution_actions);
    let mut io = SimIo::new();

    let mut expected_model = CombinedAuthorityModel::new(
        seed,
        2,
        2,
        40_000,
        2,
        seed ^ 0x1010,
        2,
        2,
        41_000,
        2,
        seed,
        4,
    );
    let before_allow_authority = combined_authority(&nat, &tcp, &firewall);
    assert_combined_authority_matches_expected(
        before_allow_authority,
        expected_model.evidence(),
        "combined initial",
    );

    let udp_packet = udp_frame_with_reference_checksum(HOST, REMOTE, 16_001, 53, 0x4000);
    let tcp_packet = tcp_frame(HOST, REMOTE, 16_002, 443, 0x02, 0x4000);
    assert_udp_reference_checksum(&udp_packet);
    assert_tcp_reference_checksum(&tcp_packet);
    io.inject(LAN, udp_packet);
    io.inject(LAN, tcp_packet);
    let report = io
        .run_nat44_udp_and_tcp_with_firewall_once(
            1,
            &snapshot,
            &mut resolution,
            &combined_udp_config,
            Some(&mut nat),
            &combined_tcp_config,
            Some(&mut tcp),
            &combined_firewall_config,
            Some(&mut firewall),
            MonotonicMillis(10),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_eq!(report.tx_requested, 1);
    assert_eq!(report.completion.tx_accepted, 1);
    let udp_out = io.pop_tx().expect("combined UDP allow");
    assert_eq!(udp_out.sequence, 0);
    assert_eq!(udp_out.egress, WAN);
    assert_eq!(udp_out.origin, FrameOrigin::Received { ingress: LAN });
    assert_eq!(&udp_out.bytes[26..30], &WAN_LOCAL.octets());
    assert_udp_reference_checksum(&udp_out.bytes);
    assert_eq!(nat.counters().mappings_created, 1);
    assert_eq!(nat.counters().peers_created, 1);
    assert_eq!(nat.counters().outbound_translated, 1);
    assert_eq!(tcp.counters(), Nat44TcpCounters::default());
    assert_eq!(firewall.counters().allowed_new, 1);
    assert_eq!(
        firewall
            .states()
            .iter()
            .filter(|slot| slot.is_occupied())
            .count(),
        1
    );
    assert!(firewall.states().iter().any(|slot| {
        slot.protocol() == FirewallProtocol::Udp
            && slot.initiator_address() == HOST
            && slot.responder_address() == REMOTE
            && slot.initiator_port() == 16_001
    }));
    let model_udp_public_port = expected_model.allow_udp(16_001, REMOTE, 10, 10);
    let udp_public_port = u16::from_be_bytes(udp_out.bytes[34..36].try_into().unwrap());
    assert_eq!(udp_public_port, model_udp_public_port);
    assert_combined_authority_matches_expected(
        combined_authority(&nat, &tcp, &firewall),
        expected_model.evidence(),
        "combined first allow",
    );

    let report = io
        .run_nat44_udp_and_tcp_with_firewall_once(
            1,
            &snapshot,
            &mut resolution,
            &combined_udp_config,
            Some(&mut nat),
            &combined_tcp_config,
            Some(&mut tcp),
            &combined_firewall_config,
            Some(&mut firewall),
            MonotonicMillis(10),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_eq!(report.tx_requested, 1);
    assert_eq!(report.completion.tx_accepted, 1);
    let tcp_out = io.pop_tx().expect("combined TCP allow");
    assert_eq!(tcp_out.sequence, 1);
    assert_eq!(tcp_out.egress, WAN);
    assert_eq!(tcp_out.origin, FrameOrigin::Received { ingress: LAN });
    assert_eq!(&tcp_out.bytes[26..30], &WAN_LOCAL.octets());
    assert_tcp_reference_checksum(&tcp_out.bytes);
    assert_eq!(tcp.counters().mappings_created, 1);
    assert_eq!(tcp.counters().sessions_created, 1);
    assert_eq!(tcp.counters().outbound_translated, 1);
    assert_eq!(firewall.counters().allowed_new, 2);
    assert_eq!(
        firewall
            .states()
            .iter()
            .filter(|slot| slot.is_occupied())
            .count(),
        2
    );
    assert!(firewall.states().iter().any(|slot| {
        slot.protocol() == FirewallProtocol::Tcp
            && slot.initiator_address() == HOST
            && slot.responder_address() == REMOTE
            && slot.initiator_port() == 16_002
    }));
    let model_tcp_public_port = expected_model.allow_tcp(16_002, REMOTE, 443, 10, 20);
    let tcp_public_port = u16::from_be_bytes(tcp_out.bytes[34..36].try_into().unwrap());
    assert_eq!(tcp_public_port, model_tcp_public_port);
    assert_combined_authority_matches_expected(
        combined_authority(&nat, &tcp, &firewall),
        expected_model.evidence(),
        "combined second allow",
    );
    assert!(
        expected_model
            .firewall
            .iter()
            .any(|slot| slot.occupied && slot.slot_generation == 1)
            && expected_model
                .firewall
                .iter()
                .any(|slot| slot.occupied && slot.slot_generation == 2),
        "model fixes the first two firewall slot generations"
    );
    assert_eq!(expected_model.firewall_next_generation, 3);

    // An old-time packet must fail closed at the combined firewall watermark
    // before either NAT runtime can observe or mutate it.
    let before_old_time_authority = combined_authority(&nat, &tcp, &firewall);
    let before_old_time_udp_counters = nat.counters();
    let before_old_time_tcp_counters = tcp.counters();
    let before_old_time_firewall_counters = firewall.counters();
    let old_time = udp_frame_with_reference_checksum(HOST, REMOTE, 16_001, 53, 0x4000);
    io.inject(LAN, old_time.clone());
    let report = io
        .run_nat44_udp_and_tcp_with_firewall_once(
            1,
            &snapshot,
            &mut resolution,
            &combined_udp_config,
            Some(&mut nat),
            &combined_tcp_config,
            Some(&mut tcp),
            &combined_firewall_config,
            Some(&mut firewall),
            MonotonicMillis(9),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(&mut io, DropReason::FirewallClockRegression, &old_time);
    assert_eq!(nat.counters(), before_old_time_udp_counters);
    assert_eq!(tcp.counters(), before_old_time_tcp_counters);
    let mut expected_old_time_firewall_counters = before_old_time_firewall_counters;
    expected_old_time_firewall_counters.clock_regressions += 1;
    assert_eq!(firewall.counters(), expected_old_time_firewall_counters);
    let after_old_time_authority = combined_authority(&nat, &tcp, &firewall);
    assert_combined_authority_matches_expected(
        after_old_time_authority,
        expected_model.evidence(),
        "combined old-time",
    );
    assert_firewall_clock_regression_preserves_authority(
        before_old_time_authority.firewall,
        after_old_time_authority.firewall,
        "combined old-time",
    );

    // A second UDP flow exercises the next port-owner allocation while the
    // first UDP flow and the independent TCP flow remain live.
    let next_udp = udp_frame_with_reference_checksum(HOST, OTHER_REMOTE, 16_003, 53, 0x4000);
    io.inject(LAN, next_udp.clone());
    let report = io
        .run_nat44_udp_and_tcp_with_firewall_once(
            1,
            &snapshot,
            &mut resolution,
            &combined_udp_config,
            Some(&mut nat),
            &combined_tcp_config,
            Some(&mut tcp),
            &combined_firewall_config,
            Some(&mut firewall),
            MonotonicMillis(11),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    let next_udp_out = io.pop_tx().expect("combined UDP next allocation");
    assert_udp_reference_checksum(&next_udp_out.bytes);
    let next_udp_public_port = u16::from_be_bytes(next_udp_out.bytes[34..36].try_into().unwrap());
    assert_ne!(
        next_udp_public_port, udp_public_port,
        "live UDP flows must not share a port owner"
    );
    let model_next_udp_public_port = expected_model.allow_udp(16_003, OTHER_REMOTE, 11, 10);
    assert_eq!(next_udp_public_port, model_next_udp_public_port);
    assert_combined_authority_matches_expected(
        combined_authority(&nat, &tcp, &firewall),
        expected_model.evidence(),
        "combined next allocation",
    );

    // The actual combined public path must resolve both independent NAT
    // protocols back to their original internal flow. The firewall lookup is
    // also exercised in reverse, so a visible slot count cannot make a broken
    // direction or owner relation appear green.
    let inbound_udp =
        udp_frame_with_reference_checksum(REMOTE, WAN_LOCAL, 53, udp_public_port, 0x4000);
    let inbound_tcp = tcp_frame(REMOTE, WAN_LOCAL, 443, tcp_public_port, 0x10, 0x4000);
    io.inject(WAN, inbound_udp);
    io.inject(WAN, inbound_tcp);
    let report = io
        .run_nat44_udp_and_tcp_with_firewall_once(
            2,
            &snapshot,
            &mut resolution,
            &combined_udp_config,
            Some(&mut nat),
            &combined_tcp_config,
            Some(&mut tcp),
            &combined_firewall_config,
            Some(&mut firewall),
            MonotonicMillis(12),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_eq!(report.completion.tx_accepted, 2);
    let inbound_udp_out = io.pop_tx().expect("combined UDP reverse lookup");
    let inbound_tcp_out = io.pop_tx().expect("combined TCP reverse lookup");
    assert_eq!(inbound_udp_out.egress, LAN);
    assert_eq!(inbound_tcp_out.egress, LAN);
    assert_eq!(&inbound_udp_out.bytes[30..34], &HOST.octets());
    assert_eq!(&inbound_tcp_out.bytes[30..34], &HOST.octets());
    assert_eq!(
        u16::from_be_bytes(inbound_udp_out.bytes[36..38].try_into().unwrap()),
        16_001
    );
    assert_eq!(
        u16::from_be_bytes(inbound_tcp_out.bytes[36..38].try_into().unwrap()),
        16_002
    );
    assert_udp_reference_checksum(&inbound_udp_out.bytes);
    assert_tcp_reference_checksum(&inbound_tcp_out.bytes);
    expected_model.inbound_udp(16_001, REMOTE, 12);
    expected_model.inbound_tcp(16_002, REMOTE, 443, 12);
    assert_combined_authority_matches_expected(
        combined_authority(&nat, &tcp, &firewall),
        expected_model.evidence(),
        "combined reverse lookup",
    );

    // A NAT planning failure occurs after a firewall plan has been prepared.
    // The actual combined path must leave both committed state machines at
    // their previous snapshots.
    {
        let small_udp_config = udp_config(&snapshot, seed ^ 0x2222, 40_010, 40_011);
        let small_tcp_config = tcp_config(&snapshot, seed ^ 0x3333, 41_010, 41_011);
        let small_rules = [allow_rule(30, FirewallProtocol::Udp)];
        let small_firewall_config = firewall_config(&snapshot, &small_rules, seed ^ 0x4444);
        let mut small_mappings = [Nat44UdpMappingSlot::default(); 1];
        let mut small_peers = [Nat44UdpPeerSlot::default(); 1];
        let mut small_indexes =
            UdpTestIndexes::new(small_udp_config, small_mappings.len(), small_peers.len());
        let mut small_nat =
            small_indexes.runtime(small_udp_config, &mut small_mappings, &mut small_peers);
        let mut small_tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
        let mut small_tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
        let mut small_tcp = super::support::tcp_runtime(
            small_tcp_config,
            &mut small_tcp_mappings,
            &mut small_tcp_sessions,
        );
        let mut small_firewall_slots = [FirewallStateSlot::default(); 2];
        let mut small_firewall =
            FirewallRuntime::new(small_firewall_config, &mut small_firewall_slots);
        let mut small_states = [ResolutionStateSlot::EMPTY; 1];
        let mut small_actions = [ResolutionActionSlot::EMPTY; 1];
        let mut small_resolution = new_resolution(&mut small_states, &mut small_actions);
        let mut small_io = SimIo::new();
        let mut small_model = CombinedAuthorityModel::new(
            seed ^ 0x2222,
            1,
            1,
            40_010,
            2,
            seed ^ 0x3333,
            1,
            1,
            41_010,
            2,
            seed ^ 0x4444,
            2,
        );
        assert_combined_authority_matches_expected(
            combined_authority(&small_nat, &small_tcp, &small_firewall),
            small_model.evidence(),
            "mapping-capacity initial",
        );
        let first = udp_frame(HOST, REMOTE, 16_101, 53, 0x4000);
        small_io.inject(LAN, first);
        let report = small_io
            .run_nat44_udp_and_tcp_with_firewall_once(
                1,
                &snapshot,
                &mut small_resolution,
                &small_udp_config,
                Some(&mut small_nat),
                &small_tcp_config,
                Some(&mut small_tcp),
                &small_firewall_config,
                Some(&mut small_firewall),
                MonotonicMillis(0),
                &mut NoTrace,
            )
            .unwrap();
        assert_batch(&report);
        assert_eq!(report.completion.tx_accepted, 1);
        let small_first_out = small_io.pop_tx().expect("capacity setup translation");
        let small_public_port =
            u16::from_be_bytes(small_first_out.bytes[34..36].try_into().unwrap());
        let small_model_public_port = small_model.allow_udp(16_101, REMOTE, 0, 30);
        assert_eq!(small_public_port, small_model_public_port);
        assert_eq!(
            small_firewall
                .states()
                .iter()
                .position(|slot| slot.is_occupied()),
            small_model.firewall.iter().position(|slot| slot.occupied),
            "mapping-capacity firewall slot allocation"
        );
        assert_combined_authority_matches_expected(
            combined_authority(&small_nat, &small_tcp, &small_firewall),
            small_model.evidence(),
            "mapping-capacity first allow",
        );
        let before_udp = small_nat.mappings().to_vec();
        let before_peers = small_nat.peers().to_vec();
        let before_tcp_mappings = small_tcp.mappings().to_vec();
        let before_tcp_sessions = small_tcp.sessions().to_vec();
        let before_firewall = small_firewall.states().to_vec();
        let before_allowed = small_firewall.counters().allowed_new;
        let before_small_authority = combined_authority(&small_nat, &small_tcp, &small_firewall);
        assert_combined_authority_matches_expected(
            before_small_authority,
            small_model.evidence(),
            "mapping-capacity before",
        );
        let second = udp_frame(HOST, OTHER_REMOTE, 16_102, 53, 0x4000);
        small_io.inject(LAN, second.clone());
        let report = small_io
            .run_nat44_udp_and_tcp_with_firewall_once(
                1,
                &snapshot,
                &mut small_resolution,
                &small_udp_config,
                Some(&mut small_nat),
                &small_tcp_config,
                Some(&mut small_tcp),
                &small_firewall_config,
                Some(&mut small_firewall),
                MonotonicMillis(1),
                &mut NoTrace,
            )
            .unwrap();
        assert_batch(&report);
        assert_drop(&mut small_io, DropReason::Nat44UdpMappingTableFull, &second);
        assert_eq!(small_nat.mappings(), before_udp.as_slice());
        assert_eq!(small_nat.peers(), before_peers.as_slice());
        assert_eq!(small_tcp.mappings(), before_tcp_mappings.as_slice());
        assert_eq!(small_tcp.sessions(), before_tcp_sessions.as_slice());
        assert_eq!(small_firewall.states(), before_firewall.as_slice());
        assert_eq!(small_firewall.counters().allowed_new, before_allowed);
        assert_eq!(small_firewall.counters().state_full, 0);
        assert_eq!(small_io.pending_rx(), 0);
        assert_eq!(small_io.pending_tx(), 0);
        let after_small_authority = combined_authority(&small_nat, &small_tcp, &small_firewall);
        small_model.observe_udp_and_firewall(1);
        assert_nat_authority_reject_matches_expected(
            after_small_authority.udp,
            small_model.evidence().udp,
            "mapping-capacity reject",
        );
        assert_eq!(
            after_small_authority.tcp,
            small_model.evidence().tcp,
            "mapping-capacity reject",
        );
        assert_firewall_authority_reject_matches_expected(
            after_small_authority.firewall,
            small_model.evidence().firewall,
            "mapping-capacity reject",
        );
        assert_combined_authority_matches_expected(
            after_small_authority,
            small_model.evidence(),
            "mapping-capacity after",
        );

        // The flow that survived the NAT capacity rejection must still be
        // found through both the NAT reverse mapping and the firewall reverse
        // state, proving that the reject did not orphan either authority.
        let small_inbound =
            udp_frame_with_reference_checksum(REMOTE, WAN_LOCAL, 53, small_public_port, 0x4000);
        small_io.inject(WAN, small_inbound);
        let report = small_io
            .run_nat44_udp_and_tcp_with_firewall_once(
                1,
                &snapshot,
                &mut small_resolution,
                &small_udp_config,
                Some(&mut small_nat),
                &small_tcp_config,
                Some(&mut small_tcp),
                &small_firewall_config,
                Some(&mut small_firewall),
                MonotonicMillis(2),
                &mut NoTrace,
            )
            .unwrap();
        assert_batch(&report);
        let small_inbound_out = small_io
            .pop_tx()
            .expect("flow survives mapping capacity rejection");
        assert_eq!(small_inbound_out.egress, LAN);
        assert_eq!(&small_inbound_out.bytes[30..34], &HOST.octets());
        assert_eq!(
            u16::from_be_bytes(small_inbound_out.bytes[36..38].try_into().unwrap()),
            16_101
        );
        assert_udp_reference_checksum(&small_inbound_out.bytes);
        small_model.inbound_udp(16_101, REMOTE, 2);
        assert_combined_authority_matches_expected(
            combined_authority(&small_nat, &small_tcp, &small_firewall),
            small_model.evidence(),
            "mapping-capacity reverse follow-up",
        );
    }

    // The opposite preflight ordering is also checked: a full firewall table
    // must not commit a NAT mapping that was only considered for the packet.
    {
        let full_udp_config = udp_config(&snapshot, seed ^ 0x5555, 40_020, 40_021);
        let full_tcp_config = tcp_config(&snapshot, seed ^ 0x6666, 41_020, 41_021);
        let full_rules = [allow_rule(40, FirewallProtocol::Udp)];
        let full_firewall_config = firewall_config(&snapshot, &full_rules, seed ^ 0x7777);
        let mut full_mappings = [Nat44UdpMappingSlot::default(); 2];
        let mut full_peers = [Nat44UdpPeerSlot::default(); 2];
        let mut full_indexes =
            UdpTestIndexes::new(full_udp_config, full_mappings.len(), full_peers.len());
        let mut full_nat =
            full_indexes.runtime(full_udp_config, &mut full_mappings, &mut full_peers);
        let mut full_tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
        let mut full_tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
        let mut full_tcp = super::support::tcp_runtime(
            full_tcp_config,
            &mut full_tcp_mappings,
            &mut full_tcp_sessions,
        );
        let mut full_firewall_slots = [FirewallStateSlot::default(); 1];
        let mut full_firewall =
            FirewallRuntime::new(full_firewall_config, &mut full_firewall_slots);
        let mut full_states = [ResolutionStateSlot::EMPTY; 1];
        let mut full_actions = [ResolutionActionSlot::EMPTY; 1];
        let mut full_resolution = new_resolution(&mut full_states, &mut full_actions);
        let mut full_io = SimIo::new();
        let mut full_model = CombinedAuthorityModel::new(
            seed ^ 0x5555,
            2,
            2,
            40_020,
            2,
            seed ^ 0x6666,
            1,
            1,
            41_020,
            2,
            seed ^ 0x7777,
            1,
        );
        assert_combined_authority_matches_expected(
            combined_authority(&full_nat, &full_tcp, &full_firewall),
            full_model.evidence(),
            "firewall-capacity initial",
        );
        let first = udp_frame(HOST, REMOTE, 16_201, 53, 0x4000);
        full_io.inject(LAN, first);
        let report = full_io
            .run_nat44_udp_and_tcp_with_firewall_once(
                1,
                &snapshot,
                &mut full_resolution,
                &full_udp_config,
                Some(&mut full_nat),
                &full_tcp_config,
                Some(&mut full_tcp),
                &full_firewall_config,
                Some(&mut full_firewall),
                MonotonicMillis(0),
                &mut NoTrace,
            )
            .unwrap();
        assert_batch(&report);
        let full_first_out = full_io.pop_tx().expect("firewall capacity setup");
        let full_public_port = u16::from_be_bytes(full_first_out.bytes[34..36].try_into().unwrap());
        let full_model_public_port = full_model.allow_udp(16_201, REMOTE, 0, 40);
        assert_eq!(full_public_port, full_model_public_port);
        assert_combined_authority_matches_expected(
            combined_authority(&full_nat, &full_tcp, &full_firewall),
            full_model.evidence(),
            "firewall-capacity first allow",
        );
        let before_udp = full_nat.mappings().to_vec();
        let before_peers = full_nat.peers().to_vec();
        let before_allowed = full_firewall.counters().allowed_new;
        let before_full_authority = combined_authority(&full_nat, &full_tcp, &full_firewall);
        assert_combined_authority_matches_expected(
            before_full_authority,
            full_model.evidence(),
            "firewall-capacity before",
        );
        let second = udp_frame(HOST, OTHER_REMOTE, 16_202, 53, 0x4000);
        full_io.inject(LAN, second.clone());
        let report = full_io
            .run_nat44_udp_and_tcp_with_firewall_once(
                1,
                &snapshot,
                &mut full_resolution,
                &full_udp_config,
                Some(&mut full_nat),
                &full_tcp_config,
                Some(&mut full_tcp),
                &full_firewall_config,
                Some(&mut full_firewall),
                MonotonicMillis(1),
                &mut NoTrace,
            )
            .unwrap();
        assert_batch(&report);
        assert_drop(&mut full_io, DropReason::FirewallStateTableFull, &second);
        assert_eq!(full_nat.mappings(), before_udp.as_slice());
        assert_eq!(full_nat.peers(), before_peers.as_slice());
        assert_eq!(full_firewall.counters().allowed_new, before_allowed);
        assert_eq!(full_firewall.counters().state_full, 1);
        assert_eq!(full_io.pending_rx(), 0);
        assert_eq!(full_io.pending_tx(), 0);
        let after_full_authority = combined_authority(&full_nat, &full_tcp, &full_firewall);
        full_model.observe_udp_and_firewall(1);
        assert_nat_authority_reject_matches_expected(
            after_full_authority.udp,
            full_model.evidence().udp,
            "firewall-capacity reject",
        );
        assert_eq!(
            after_full_authority.tcp,
            full_model.evidence().tcp,
            "firewall-capacity reject",
        );
        assert_firewall_authority_reject_matches_expected(
            after_full_authority.firewall,
            full_model.evidence().firewall,
            "firewall-capacity reject",
        );
        assert_combined_authority_matches_expected(
            after_full_authority,
            full_model.evidence(),
            "firewall-capacity after",
        );

        // A firewall-capacity reject must leave the existing NAT flow and
        // reverse firewall state usable.
        let full_inbound =
            udp_frame_with_reference_checksum(REMOTE, WAN_LOCAL, 53, full_public_port, 0x4000);
        full_io.inject(WAN, full_inbound);
        let report = full_io
            .run_nat44_udp_and_tcp_with_firewall_once(
                1,
                &snapshot,
                &mut full_resolution,
                &full_udp_config,
                Some(&mut full_nat),
                &full_tcp_config,
                Some(&mut full_tcp),
                &full_firewall_config,
                Some(&mut full_firewall),
                MonotonicMillis(2),
                &mut NoTrace,
            )
            .unwrap();
        assert_batch(&report);
        let full_inbound_out = full_io
            .pop_tx()
            .expect("flow survives firewall capacity rejection");
        assert_eq!(full_inbound_out.egress, LAN);
        assert_eq!(&full_inbound_out.bytes[30..34], &HOST.octets());
        assert_eq!(
            u16::from_be_bytes(full_inbound_out.bytes[36..38].try_into().unwrap()),
            16_201
        );
        assert_udp_reference_checksum(&full_inbound_out.bytes);
        full_model.inbound_udp(16_201, REMOTE, 2);
        assert_combined_authority_matches_expected(
            combined_authority(&full_nat, &full_tcp, &full_firewall),
            full_model.evidence(),
            "firewall-capacity reverse follow-up",
        );
    }

    // Backend rejection is after all three plans have committed. Both
    // protocol runtimes and the firewall must therefore retain their state,
    // while each RX slot is completed exactly once with its egress recorded.
    {
        let reject_udp_config = udp_config(&snapshot, seed ^ 0x8888, 40_030, 40_030);
        let reject_tcp_config = tcp_config(&snapshot, seed ^ 0x9999, 41_030, 41_030);
        let reject_rules = [
            allow_rule(50, FirewallProtocol::Udp),
            allow_rule(60, FirewallProtocol::Tcp),
        ];
        let reject_firewall_config = firewall_config(&snapshot, &reject_rules, seed ^ 0xaaaa);
        let mut reject_mappings = [Nat44UdpMappingSlot::default(); 1];
        let mut reject_peers = [Nat44UdpPeerSlot::default(); 1];
        let mut reject_indexes =
            UdpTestIndexes::new(reject_udp_config, reject_mappings.len(), reject_peers.len());
        let mut reject_nat =
            reject_indexes.runtime(reject_udp_config, &mut reject_mappings, &mut reject_peers);
        let mut reject_tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
        let mut reject_tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
        let mut reject_tcp = super::support::tcp_runtime(
            reject_tcp_config,
            &mut reject_tcp_mappings,
            &mut reject_tcp_sessions,
        );
        let mut reject_firewall_slots = [FirewallStateSlot::default(); 2];
        let mut reject_firewall =
            FirewallRuntime::new(reject_firewall_config, &mut reject_firewall_slots);
        let mut reject_states = [ResolutionStateSlot::EMPTY; 1];
        let mut reject_actions = [ResolutionActionSlot::EMPTY; 1];
        let mut reject_resolution = new_resolution(&mut reject_states, &mut reject_actions);
        let mut reject_io = SimIo::new();
        let mut reject_model = CombinedAuthorityModel::new(
            seed ^ 0x8888,
            1,
            1,
            40_030,
            1,
            seed ^ 0x9999,
            1,
            1,
            41_030,
            1,
            seed ^ 0xaaaa,
            2,
        );
        let before_reject_authority =
            combined_authority(&reject_nat, &reject_tcp, &reject_firewall);
        assert_combined_authority_matches_expected(
            before_reject_authority,
            reject_model.evidence(),
            "TX reject before",
        );
        reject_io.set_received_accept_budget(0);
        reject_io.inject(
            LAN,
            udp_frame_with_reference_checksum(HOST, REMOTE, 16_301, 53, 0x4000),
        );
        reject_io.inject(LAN, tcp_frame(HOST, REMOTE, 16_302, 443, 0x02, 0x4000));
        let report = reject_io
            .run_nat44_udp_and_tcp_with_firewall_once(
                2,
                &snapshot,
                &mut reject_resolution,
                &reject_udp_config,
                Some(&mut reject_nat),
                &reject_tcp_config,
                Some(&mut reject_tcp),
                &reject_firewall_config,
                Some(&mut reject_firewall),
                MonotonicMillis(0),
                &mut NoTrace,
            )
            .unwrap();
        assert_batch(&report);
        assert_eq!(report.tx_requested, 2);
        assert_eq!(report.completion.tx_rejected, 2);
        let mut rejected_public_ports = [0_u16; 2];
        for (sequence, expected_offset) in [(0, WAN_LOCAL.octets()), (1, WAN_LOCAL.octets())] {
            let capture = reject_io
                .pop_recycled_capture()
                .expect("rejected combined TX is recycled");
            assert_eq!(capture.frame.sequence, sequence);
            assert_eq!(capture.frame.cause, RecycleCause::TxRejected);
            assert_eq!(capture.rejected_egress, Some(WAN));
            assert_eq!(&capture.frame.bytes[26..30], &expected_offset);
            rejected_public_ports[sequence as usize] =
                u16::from_be_bytes(capture.frame.bytes[34..36].try_into().unwrap());
        }
        assert!(reject_nat.mappings()[0].is_occupied());
        assert!(reject_nat.peers()[0].is_occupied());
        assert!(reject_tcp.mappings()[0].is_occupied());
        assert!(reject_tcp.sessions()[0].is_occupied());
        assert_eq!(reject_nat.counters().outbound_translated, 1);
        assert_eq!(reject_tcp.counters().outbound_translated, 1);
        assert_eq!(reject_firewall.counters().allowed_new, 2);
        assert_eq!(
            reject_firewall
                .states()
                .iter()
                .filter(|slot| slot.is_occupied())
                .count(),
            2
        );
        assert_eq!(reject_io.pending_rx(), 0);
        assert_eq!(reject_io.pending_tx(), 0);
        let after_reject_authority = combined_authority(&reject_nat, &reject_tcp, &reject_firewall);
        let expected_rejected_udp_port = reject_model.allow_udp(16_301, REMOTE, 0, 50);
        let expected_rejected_tcp_port = reject_model.allow_tcp(16_302, REMOTE, 443, 0, 60);
        assert_eq!(rejected_public_ports[0], expected_rejected_udp_port);
        assert_eq!(rejected_public_ports[1], expected_rejected_tcp_port);
        assert_combined_authority_matches_expected(
            after_reject_authority,
            reject_model.evidence(),
            "TX reject after",
        );

        // TX rejection occurs after all three runtimes commit. Make the
        // backend accept subsequent packets and prove that the committed
        // authority remains coherent and reverse lookup still succeeds.
        reject_io.set_received_accept_budget(usize::MAX);
        let rejected_udp_inbound = udp_frame_with_reference_checksum(
            REMOTE,
            WAN_LOCAL,
            53,
            rejected_public_ports[0],
            0x4000,
        );
        let rejected_tcp_inbound = tcp_frame(
            REMOTE,
            WAN_LOCAL,
            443,
            rejected_public_ports[1],
            0x10,
            0x4000,
        );
        reject_io.inject(WAN, rejected_udp_inbound);
        reject_io.inject(WAN, rejected_tcp_inbound);
        let report = reject_io
            .run_nat44_udp_and_tcp_with_firewall_once(
                2,
                &snapshot,
                &mut reject_resolution,
                &reject_udp_config,
                Some(&mut reject_nat),
                &reject_tcp_config,
                Some(&mut reject_tcp),
                &reject_firewall_config,
                Some(&mut reject_firewall),
                MonotonicMillis(1),
                &mut NoTrace,
            )
            .unwrap();
        assert_batch(&report);
        assert_eq!(report.completion.tx_accepted, 2);
        let rejected_udp_reverse = reject_io
            .pop_tx()
            .expect("TX-rejected UDP flow remains reversible");
        let rejected_tcp_reverse = reject_io
            .pop_tx()
            .expect("TX-rejected TCP flow remains reversible");
        assert_eq!(rejected_udp_reverse.egress, LAN);
        assert_eq!(rejected_tcp_reverse.egress, LAN);
        assert_eq!(&rejected_udp_reverse.bytes[30..34], &HOST.octets());
        assert_eq!(&rejected_tcp_reverse.bytes[30..34], &HOST.octets());
        assert_eq!(
            u16::from_be_bytes(rejected_udp_reverse.bytes[36..38].try_into().unwrap()),
            16_301
        );
        assert_eq!(
            u16::from_be_bytes(rejected_tcp_reverse.bytes[36..38].try_into().unwrap()),
            16_302
        );
        assert_udp_reference_checksum(&rejected_udp_reverse.bytes);
        assert_tcp_reference_checksum(&rejected_tcp_reverse.bytes);
        reject_model.inbound_udp(16_301, REMOTE, 1);
        reject_model.inbound_tcp(16_302, REMOTE, 443, 1);
        assert_combined_authority_matches_expected(
            combined_authority(&reject_nat, &reject_tcp, &reject_firewall),
            reject_model.evidence(),
            "TX reject reverse follow-up",
        );
        capture_state_evidence(
            Some(&reject_nat),
            Some(&reject_tcp),
            Some(&reject_firewall),
            &reject_resolution,
            &reject_io,
        )
    }
}

fn firewall_deny_modes(seed: u64) -> StateEvidence {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();

    let deny_rules = [deny_rule(70, FirewallProtocol::Udp)];
    let deny_udp_config = udp_config(&snapshot, seed, 40_100, 40_100);
    let deny_tcp_config = tcp_config(&snapshot, seed ^ 1, 41_100, 41_100);
    let deny_firewall_config = firewall_config(&snapshot, &deny_rules, seed);
    let mut deny_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut deny_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut deny_indexes =
        UdpTestIndexes::new(deny_udp_config, deny_mappings.len(), deny_peers.len());
    let mut deny_nat = deny_indexes.runtime(deny_udp_config, &mut deny_mappings, &mut deny_peers);
    let mut deny_tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut deny_tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut deny_tcp = super::support::tcp_runtime(
        deny_tcp_config,
        &mut deny_tcp_mappings,
        &mut deny_tcp_sessions,
    );
    let mut deny_slots = [FirewallStateSlot::default(); 1];
    let mut deny_firewall = FirewallRuntime::new(deny_firewall_config, &mut deny_slots);
    let mut deny_states = [ResolutionStateSlot::EMPTY; 1];
    let mut deny_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut deny_resolution = new_resolution(&mut deny_states, &mut deny_actions);
    let mut deny_io = SimIo::new();
    let denied = udp_frame(HOST, REMOTE, 17_001, 53, 0x4000);
    deny_io.inject(LAN, denied.clone());
    let report = deny_io
        .run_nat44_udp_and_tcp_with_firewall_once(
            1,
            &snapshot,
            &mut deny_resolution,
            &deny_udp_config,
            Some(&mut deny_nat),
            &deny_tcp_config,
            Some(&mut deny_tcp),
            &deny_firewall_config,
            Some(&mut deny_firewall),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(&mut deny_io, DropReason::FirewallRuleDenied, &denied);
    assert_eq!(deny_firewall.counters().denied_by_rule, 1);
    assert_eq!(deny_firewall.counters().denied_default, 0);
    assert_eq!(deny_nat.counters(), Nat44UdpCounters::default());
    assert_eq!(deny_tcp.counters(), Nat44TcpCounters::default());
    assert!(deny_nat.mappings().iter().all(|slot| !slot.is_occupied()));
    assert!(deny_nat.peers().iter().all(|slot| !slot.is_occupied()));
    assert!(deny_tcp.mappings().iter().all(|slot| !slot.is_occupied()));
    assert!(deny_tcp.sessions().iter().all(|slot| !slot.is_occupied()));
    assert!(deny_firewall
        .states()
        .iter()
        .all(|slot| !slot.is_occupied()));
    assert_eq!(deny_io.pending_tx(), 0);

    let empty_rules: [FirewallRule; 0] = [];
    let default_udp_config = udp_config(&snapshot, seed ^ 2, 40_101, 40_101);
    let default_tcp_config = tcp_config(&snapshot, seed ^ 3, 41_101, 41_101);
    let default_firewall_config = firewall_config(&snapshot, &empty_rules, seed ^ 4);
    let mut default_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut default_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut default_indexes = UdpTestIndexes::new(
        default_udp_config,
        default_mappings.len(),
        default_peers.len(),
    );
    let mut default_nat = default_indexes.runtime(
        default_udp_config,
        &mut default_mappings,
        &mut default_peers,
    );
    let mut default_tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut default_tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut default_tcp = super::support::tcp_runtime(
        default_tcp_config,
        &mut default_tcp_mappings,
        &mut default_tcp_sessions,
    );
    let mut default_slots = [FirewallStateSlot::default(); 1];
    let mut default_firewall = FirewallRuntime::new(default_firewall_config, &mut default_slots);
    let mut default_states = [ResolutionStateSlot::EMPTY; 1];
    let mut default_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut default_resolution = new_resolution(&mut default_states, &mut default_actions);
    let mut default_io = SimIo::new();
    let default_denied = udp_frame(HOST, OTHER_REMOTE, 17_002, 53, 0x4000);
    default_io.inject(LAN, default_denied.clone());
    let report = default_io
        .run_nat44_udp_and_tcp_with_firewall_once(
            1,
            &snapshot,
            &mut default_resolution,
            &default_udp_config,
            Some(&mut default_nat),
            &default_tcp_config,
            Some(&mut default_tcp),
            &default_firewall_config,
            Some(&mut default_firewall),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(
        &mut default_io,
        DropReason::FirewallDefaultDenied,
        &default_denied,
    );
    assert_eq!(default_firewall.counters().denied_by_rule, 0);
    assert_eq!(default_firewall.counters().denied_default, 1);
    assert_eq!(default_nat.counters(), Nat44UdpCounters::default());
    assert_eq!(default_tcp.counters(), Nat44TcpCounters::default());
    assert!(default_nat
        .mappings()
        .iter()
        .all(|slot| !slot.is_occupied()));
    assert!(default_nat.peers().iter().all(|slot| !slot.is_occupied()));
    assert!(default_tcp
        .mappings()
        .iter()
        .all(|slot| !slot.is_occupied()));
    assert!(default_tcp
        .sessions()
        .iter()
        .all(|slot| !slot.is_occupied()));
    assert!(default_firewall
        .states()
        .iter()
        .all(|slot| !slot.is_occupied()));
    capture_state_evidence(
        Some(&default_nat),
        Some(&default_tcp),
        Some(&default_firewall),
        &default_resolution,
        &default_io,
    )
}

fn udp_malformed_checksum_collision(seed: u64) -> StateEvidence {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = udp_config(&snapshot, seed, 40_200, 40_201);
    let mut mappings = [Nat44UdpMappingSlot::default(); 3];
    let mut peers = [Nat44UdpPeerSlot::default(); 3];
    let mut indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = indexes.runtime(config, &mut mappings, &mut peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = new_resolution(&mut states, &mut actions);
    let mut io = SimIo::new();

    let mut truncated = udp_frame(HOST, REMOTE, 18_001, 53, 0x4000);
    truncated.truncate(14 + 20 + 4);
    truncated[16..18].copy_from_slice(&24_u16.to_be_bytes());
    rewrite_ipv4_header_checksum(&mut truncated);
    let mut length_small = udp_frame(HOST, REMOTE, 18_002, 53, 0x4000);
    length_small[38..40].copy_from_slice(&7_u16.to_be_bytes());
    let mut length_large = udp_frame(HOST, REMOTE, 18_003, 53, 0x4000);
    length_large[38..40].copy_from_slice(&12_u16.to_be_bytes());

    for (now, packet, reason) in [
        (0, truncated, DropReason::Nat44UdpHeaderTruncated),
        (1, length_small, DropReason::Nat44UdpLengthTooSmall),
        (
            2,
            length_large,
            DropReason::Nat44UdpLengthExceedsIpv4Payload,
        ),
    ] {
        let before_mappings = nat.mappings().to_vec();
        let before_peers = nat.peers().to_vec();
        let before_counters = nat.counters();
        let before_resolution = resolution.counters();
        io.inject(LAN, packet.clone());
        let report = io
            .run_nat44_udp_once(
                1,
                &snapshot,
                &mut resolution,
                &config,
                Some(&mut nat),
                MonotonicMillis(now),
                &mut NoTrace,
            )
            .unwrap();
        assert_batch(&report);
        assert_drop(&mut io, reason, &packet);
        assert_eq!(nat.mappings(), before_mappings.as_slice());
        assert_eq!(nat.peers(), before_peers.as_slice());
        assert_eq!(nat.counters(), before_counters);
        assert_eq!(resolution.counters(), before_resolution);
    }

    // Fill both ports, then force allocator wrap after the first owner expires.
    // The same fixed seed must never produce two live owners for one public
    // port, and a port cannot be reused before its TTL boundary.
    let first = udp_frame_with_reference_checksum(HOST, REMOTE, 18_010, 53, 0x4000);
    io.inject(LAN, first);
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(10),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    let first_out = io.pop_tx().expect("first UDP public port");
    assert_udp_reference_checksum(&first_out.bytes);
    let first_port = u16::from_be_bytes(first_out.bytes[34..36].try_into().unwrap());

    let second = udp_frame_with_reference_checksum(HOST, OTHER_REMOTE, 18_011, 53, 0x4000);
    io.inject(LAN, second);
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(NAT44_UDP_MIN_IDLE_TTL_MS - 1 + 10),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    let second_out = io.pop_tx().expect("second UDP public port");
    assert_udp_reference_checksum(&second_out.bytes);
    let second_port = u16::from_be_bytes(second_out.bytes[34..36].try_into().unwrap());
    assert_ne!(
        first_port, second_port,
        "live mappings must have distinct ports"
    );

    let third = udp_frame_with_reference_checksum(HOST, REMOTE, 18_012, 53, 0x4000);
    io.inject(LAN, third.clone());
    let reuse_at = NAT44_UDP_MIN_IDLE_TTL_MS + 10;
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(reuse_at),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    let third_out = io.pop_tx().expect("expired UDP port wraps and reuses");
    assert_udp_reference_checksum(&third_out.bytes);
    assert_eq!(
        u16::from_be_bytes(third_out.bytes[34..36].try_into().unwrap()),
        first_port
    );

    let exhausted = udp_frame_with_reference_checksum(HOST, OTHER_REMOTE, 18_013, 53, 0x4000);
    io.inject(LAN, exhausted.clone());
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(reuse_at + 1),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(&mut io, DropReason::Nat44UdpPortExhausted, &exhausted);
    assert_eq!(nat.counters().port_exhausted, 1);

    let peer_config = udp_config(&snapshot, seed ^ 0xaaaa, 40_210, 40_210);
    let mut peer_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peer_slots = [Nat44UdpPeerSlot::default(); 1];
    let mut peer_indexes = UdpTestIndexes::new(peer_config, 1, 1);
    let mut peer_nat = peer_indexes.runtime(peer_config, &mut peer_mappings, &mut peer_slots);
    let mut peer_states = [ResolutionStateSlot::EMPTY; 1];
    let mut peer_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut peer_resolution = new_resolution(&mut peer_states, &mut peer_actions);
    let mut peer_io = SimIo::new();
    let first_peer = udp_frame(HOST, REMOTE, 18_020, 53, 0x4000);
    peer_io.inject(LAN, first_peer);
    let report = peer_io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut peer_resolution,
            &peer_config,
            Some(&mut peer_nat),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    peer_io.pop_tx().expect("peer capacity setup");
    let before_peer_mappings = peer_nat.mappings().to_vec();
    let before_peer_slots = peer_nat.peers().to_vec();
    let peer_full = udp_frame(HOST, OTHER_REMOTE, 18_020, 53, 0x4000);
    peer_io.inject(LAN, peer_full.clone());
    let report = peer_io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut peer_resolution,
            &peer_config,
            Some(&mut peer_nat),
            MonotonicMillis(1),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(&mut peer_io, DropReason::Nat44UdpPeerTableFull, &peer_full);
    assert_eq!(peer_nat.mappings(), before_peer_mappings.as_slice());
    assert_eq!(peer_nat.peers(), before_peer_slots.as_slice());
    assert_eq!(peer_nat.counters().peer_full, 1);

    // A valid non-zero checksum must survive the real NAT rewrite, and is
    // checked by the independent reference rather than production code.
    let checksum_rules = [allow_rule(80, FirewallProtocol::Udp)];
    let checksum_firewall_config = firewall_config(&snapshot, &checksum_rules, seed ^ 0xbbbb);
    let checksum_udp_config = udp_config(&snapshot, seed ^ 0xcccc, 40_220, 40_220);
    let checksum_tcp_config = tcp_config(&snapshot, seed ^ 0xdddd, 41_220, 41_220);
    let mut checksum_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut checksum_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut checksum_indexes = UdpTestIndexes::new(checksum_udp_config, 1, 1);
    let mut checksum_nat = checksum_indexes.runtime(
        checksum_udp_config,
        &mut checksum_mappings,
        &mut checksum_peers,
    );
    let mut checksum_tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut checksum_tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut checksum_tcp = super::support::tcp_runtime(
        checksum_tcp_config,
        &mut checksum_tcp_mappings,
        &mut checksum_tcp_sessions,
    );
    let mut checksum_firewall_slots = [FirewallStateSlot::default(); 1];
    let mut checksum_firewall =
        FirewallRuntime::new(checksum_firewall_config, &mut checksum_firewall_slots);
    let mut checksum_states = [ResolutionStateSlot::EMPTY; 1];
    let mut checksum_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut checksum_resolution = new_resolution(&mut checksum_states, &mut checksum_actions);
    let mut checksum_io = SimIo::new();
    let checksum_packet = udp_frame_with_reference_checksum(HOST, REMOTE, 18_030, 53, 0x4000);
    assert_udp_reference_checksum(&checksum_packet);
    checksum_io.inject(LAN, checksum_packet);
    let report = checksum_io
        .run_nat44_udp_and_tcp_with_firewall_once(
            1,
            &snapshot,
            &mut checksum_resolution,
            &checksum_udp_config,
            Some(&mut checksum_nat),
            &checksum_tcp_config,
            Some(&mut checksum_tcp),
            &checksum_firewall_config,
            Some(&mut checksum_firewall),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    let checksum_out = checksum_io
        .pop_tx()
        .expect("valid UDP checksum translation");
    assert_udp_reference_checksum(&checksum_out.bytes);

    capture_state_evidence(Some(&nat), None, None, &resolution, &io)
}

fn tcp_expiry_capacity_and_exhaustion(seed: u64) -> StateEvidence {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();

    let mapping_config = tcp_config(&snapshot, seed, 41_300, 41_301);
    let mut mapping_slots = [Nat44TcpMappingSlot::default(); 1];
    let mut mapping_sessions = [Nat44TcpSessionSlot::default(); 2];
    let mut mapping_nat =
        super::support::tcp_runtime(mapping_config, &mut mapping_slots, &mut mapping_sessions);
    let mut mapping_states = [ResolutionStateSlot::EMPTY; 1];
    let mut mapping_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut mapping_resolution = new_resolution(&mut mapping_states, &mut mapping_actions);
    let mut mapping_io = SimIo::new();
    let first = tcp_frame(HOST, REMOTE, 19_001, 443, 0x02, 0x4000);
    mapping_io.inject(LAN, first);
    let report = mapping_io
        .run_nat44_tcp_once(
            1,
            &snapshot,
            &mut mapping_resolution,
            &mapping_config,
            Some(&mut mapping_nat),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    let first_out = mapping_io.pop_tx().expect("mapping capacity setup");
    assert_tcp_reference_checksum(&first_out.bytes);
    let before_mapping = mapping_nat.mappings().to_vec();
    let before_mapping_sessions = mapping_nat.sessions().to_vec();
    let mapping_full = tcp_frame(HOST, OTHER_REMOTE, 19_002, 443, 0x02, 0x4000);
    mapping_io.inject(LAN, mapping_full.clone());
    let report = mapping_io
        .run_nat44_tcp_once(
            1,
            &snapshot,
            &mut mapping_resolution,
            &mapping_config,
            Some(&mut mapping_nat),
            MonotonicMillis(1),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(
        &mut mapping_io,
        DropReason::Nat44TcpMappingTableFull,
        &mapping_full,
    );
    assert_eq!(mapping_nat.mappings(), before_mapping.as_slice());
    assert_eq!(mapping_nat.sessions(), before_mapping_sessions.as_slice());
    assert_eq!(mapping_nat.counters().mapping_full, 1);

    let session_config = tcp_config(&snapshot, seed ^ 1, 41_310, 41_310);
    let mut session_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut session_slots = [Nat44TcpSessionSlot::default(); 1];
    let mut session_nat =
        super::support::tcp_runtime(session_config, &mut session_mappings, &mut session_slots);
    let mut session_states = [ResolutionStateSlot::EMPTY; 1];
    let mut session_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut session_resolution = new_resolution(&mut session_states, &mut session_actions);
    let mut session_io = SimIo::new();
    let first = tcp_frame(HOST, REMOTE, 19_010, 443, 0x02, 0x4000);
    session_io.inject(LAN, first);
    let report = session_io
        .run_nat44_tcp_once(
            1,
            &snapshot,
            &mut session_resolution,
            &session_config,
            Some(&mut session_nat),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    session_io.pop_tx().expect("session capacity setup");
    let before_session_mapping = session_nat.mappings().to_vec();
    let before_session_slots = session_nat.sessions().to_vec();
    let session_full = tcp_frame(HOST, OTHER_REMOTE, 19_010, 443, 0x02, 0x4000);
    session_io.inject(LAN, session_full.clone());
    let report = session_io
        .run_nat44_tcp_once(
            1,
            &snapshot,
            &mut session_resolution,
            &session_config,
            Some(&mut session_nat),
            MonotonicMillis(1),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(
        &mut session_io,
        DropReason::Nat44TcpSessionTableFull,
        &session_full,
    );
    assert_eq!(session_nat.mappings(), before_session_mapping.as_slice());
    assert_eq!(session_nat.sessions(), before_session_slots.as_slice());
    assert_eq!(session_nat.counters().session_full, 1);

    let config = tcp_config(&snapshot, seed ^ 2, 41_320, 41_320);
    let mut mappings = [Nat44TcpMappingSlot::default(); 2];
    let mut sessions = [Nat44TcpSessionSlot::default(); 2];
    let mut nat = super::support::tcp_runtime(config, &mut mappings, &mut sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = new_resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    let ttl = NAT44_TCP_MIN_IDLE_TTL_MS;

    let first = tcp_frame(HOST, REMOTE, 19_020, 443, 0x02, 0x4000);
    io.inject(LAN, first);
    let report = io
        .run_nat44_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    let first_out = io.pop_tx().expect("first TCP public port");
    assert_tcp_reference_checksum(&first_out.bytes);
    let public_port = u16::from_be_bytes(first_out.bytes[34..36].try_into().unwrap());

    let exhausted = tcp_frame(HOST, OTHER_REMOTE, 19_021, 443, 0x02, 0x4000);
    io.inject(LAN, exhausted.clone());
    let report = io
        .run_nat44_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(1),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(&mut io, DropReason::Nat44TcpPortExhausted, &exhausted);

    let refresh = tcp_frame(HOST, REMOTE, 19_020, 443, 0x10, 0x4000);
    io.inject(LAN, refresh);
    let refresh_at = ttl - 1;
    let report = io
        .run_nat44_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(refresh_at),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    let refresh_out = io.pop_tx().expect("TCP TTL-1 remains active");
    assert_tcp_reference_checksum(&refresh_out.bytes);
    assert_eq!(nat.sessions()[0].last_activity_ms(), refresh_at);

    let recreated = tcp_frame(HOST, OTHER_REMOTE, 19_022, 443, 0x02, 0x4000);
    io.inject(LAN, recreated.clone());
    let expiry_at = refresh_at.checked_add(ttl).unwrap();
    let report = io
        .run_nat44_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(expiry_at),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    let recreated_out = io.pop_tx().expect("expired TCP port is reused");
    assert_tcp_reference_checksum(&recreated_out.bytes);
    assert_eq!(
        u16::from_be_bytes(recreated_out.bytes[34..36].try_into().unwrap()),
        public_port
    );
    assert_eq!(nat.counters().port_exhausted, 1);
    assert_eq!(nat.counters().mappings_created, 2);
    assert_eq!(nat.counters().sessions_created, 2);
    assert_eq!(nat.counters().mappings_expired, 1);
    assert_eq!(nat.counters().sessions_expired, 1);
    assert_eq!(nat.counters().mappings_reused, 1);
    assert_eq!(nat.counters().sessions_reused, 1);

    capture_state_evidence(None, Some(&nat), None, &resolution, &io)
}

fn clock_regression_and_watermark(seed: u64) -> StateEvidence {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let clock_udp_config = udp_config(&snapshot, seed, 40_400, 40_400);
    let clock_tcp_config = tcp_config(&snapshot, seed ^ 1, 41_400, 41_400);

    // First exercise both NAT watermarks without a firewall in the way. A
    // regression is a typed drop and does not rewrite any slot or counter
    // other than the regression counter itself.
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut udp_indexes = UdpTestIndexes::new(clock_udp_config, 1, 1);
    let mut nat = udp_indexes.runtime(clock_udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut tcp =
        super::support::tcp_runtime(clock_tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = new_resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(
        LAN,
        udp_frame_with_reference_checksum(HOST, REMOTE, 20_001, 53, 0x4000),
    );
    io.inject(LAN, tcp_frame(HOST, REMOTE, 20_002, 443, 0x02, 0x4000));
    let report = io
        .run_nat44_udp_and_tcp_once(
            2,
            &snapshot,
            &mut resolution,
            &clock_udp_config,
            Some(&mut nat),
            &clock_tcp_config,
            Some(&mut tcp),
            MonotonicMillis(10),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_eq!(report.completion.tx_accepted, 2);
    io.pop_tx().expect("UDP watermark setup");
    io.pop_tx().expect("TCP watermark setup");
    let before_udp = nat.mappings().to_vec();
    let before_peers = nat.peers().to_vec();
    let before_udp_counters = nat.counters();
    let before_tcp = tcp.mappings().to_vec();
    let before_sessions = tcp.sessions().to_vec();
    let before_tcp_counters = tcp.counters();
    let regression_udp = udp_frame_with_reference_checksum(HOST, REMOTE, 20_001, 53, 0x4000);
    let regression_tcp = tcp_frame(HOST, REMOTE, 20_002, 443, 0x10, 0x4000);
    io.inject(LAN, regression_udp.clone());
    io.inject(LAN, regression_tcp.clone());
    let report = io
        .run_nat44_udp_and_tcp_once(
            2,
            &snapshot,
            &mut resolution,
            &clock_udp_config,
            Some(&mut nat),
            &clock_tcp_config,
            Some(&mut tcp),
            MonotonicMillis(9),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(
        &mut io,
        DropReason::Nat44UdpClockRegression,
        &regression_udp,
    );
    assert_drop(
        &mut io,
        DropReason::Nat44TcpClockRegression,
        &regression_tcp,
    );
    assert_eq!(nat.mappings(), before_udp.as_slice());
    assert_eq!(nat.peers(), before_peers.as_slice());
    assert_eq!(tcp.mappings(), before_tcp.as_slice());
    assert_eq!(tcp.sessions(), before_sessions.as_slice());
    let mut expected_udp_counters = before_udp_counters;
    expected_udp_counters.clock_regressions += 1;
    let mut expected_tcp_counters = before_tcp_counters;
    expected_tcp_counters.clock_regressions += 1;
    assert_eq!(nat.counters(), expected_udp_counters);
    assert_eq!(tcp.counters(), expected_tcp_counters);
    assert_eq!(io.pending_tx(), 0);

    let accepted_udp = udp_frame_with_reference_checksum(HOST, REMOTE, 20_001, 53, 0x4000);
    let accepted_tcp = tcp_frame(HOST, REMOTE, 20_002, 443, 0x10, 0x4000);
    io.inject(LAN, accepted_udp);
    io.inject(LAN, accepted_tcp);
    let report = io
        .run_nat44_udp_and_tcp_once(
            2,
            &snapshot,
            &mut resolution,
            &clock_udp_config,
            Some(&mut nat),
            &clock_tcp_config,
            Some(&mut tcp),
            MonotonicMillis(11),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    let udp_out = io.pop_tx().expect("UDP watermark advances forward");
    let tcp_out = io.pop_tx().expect("TCP watermark advances forward");
    assert_udp_reference_checksum(&udp_out.bytes);
    assert_tcp_reference_checksum(&tcp_out.bytes);
    assert_eq!(nat.mappings()[0].last_outbound_ms(), 11);
    assert!(tcp.mappings()[0].is_occupied());
    assert_eq!(tcp.sessions()[0].last_activity_ms(), 11);

    // In the combined security path the firewall observes the logical clock
    // first. Both protocol runtimes and the firewall state must still remain
    // at the last accepted watermark when that observation rejects a packet.
    let rules = [
        allow_rule(90, FirewallProtocol::Udp),
        allow_rule(91, FirewallProtocol::Tcp),
    ];
    let firewall_config = firewall_config(&snapshot, &rules, seed ^ 2);
    let combined_udp_config = udp_config(&snapshot, seed ^ 3, 40_410, 40_410);
    let combined_tcp_config = tcp_config(&snapshot, seed ^ 4, 41_410, 41_410);
    let mut combined_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut combined_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut combined_indexes = UdpTestIndexes::new(combined_udp_config, 1, 1);
    let mut combined_nat = combined_indexes.runtime(
        combined_udp_config,
        &mut combined_mappings,
        &mut combined_peers,
    );
    let mut combined_tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut combined_tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut combined_tcp = super::support::tcp_runtime(
        combined_tcp_config,
        &mut combined_tcp_mappings,
        &mut combined_tcp_sessions,
    );
    let mut combined_firewall_slots = [FirewallStateSlot::default(); 2];
    let mut combined_firewall = FirewallRuntime::new(firewall_config, &mut combined_firewall_slots);
    let mut combined_states = [ResolutionStateSlot::EMPTY; 1];
    let mut combined_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut combined_resolution = new_resolution(&mut combined_states, &mut combined_actions);
    let mut combined_io = SimIo::new();
    combined_io.inject(
        LAN,
        udp_frame_with_reference_checksum(HOST, REMOTE, 20_011, 53, 0x4000),
    );
    combined_io.inject(LAN, tcp_frame(HOST, REMOTE, 20_012, 443, 0x02, 0x4000));
    let report = combined_io
        .run_nat44_udp_and_tcp_with_firewall_once(
            2,
            &snapshot,
            &mut combined_resolution,
            &combined_udp_config,
            Some(&mut combined_nat),
            &combined_tcp_config,
            Some(&mut combined_tcp),
            &firewall_config,
            Some(&mut combined_firewall),
            MonotonicMillis(10),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    combined_io.pop_tx().expect("combined UDP watermark setup");
    combined_io.pop_tx().expect("combined TCP watermark setup");
    let before_combined_udp = combined_nat.mappings().to_vec();
    let before_combined_peers = combined_nat.peers().to_vec();
    let before_combined_tcp = combined_tcp.mappings().to_vec();
    let before_combined_sessions = combined_tcp.sessions().to_vec();
    let before_combined_firewall = combined_firewall.states().to_vec();
    let before_combined_udp_counters = combined_nat.counters();
    let before_combined_tcp_counters = combined_tcp.counters();
    let before_combined_firewall_counters = combined_firewall.counters();
    let regression_udp = udp_frame_with_reference_checksum(HOST, REMOTE, 20_011, 53, 0x4000);
    let regression_tcp = tcp_frame(HOST, REMOTE, 20_012, 443, 0x10, 0x4000);
    combined_io.inject(LAN, regression_udp.clone());
    combined_io.inject(LAN, regression_tcp.clone());
    let report = combined_io
        .run_nat44_udp_and_tcp_with_firewall_once(
            2,
            &snapshot,
            &mut combined_resolution,
            &combined_udp_config,
            Some(&mut combined_nat),
            &combined_tcp_config,
            Some(&mut combined_tcp),
            &firewall_config,
            Some(&mut combined_firewall),
            MonotonicMillis(9),
            &mut NoTrace,
        )
        .unwrap();
    assert_batch(&report);
    assert_drop(
        &mut combined_io,
        DropReason::FirewallClockRegression,
        &regression_udp,
    );
    assert_drop(
        &mut combined_io,
        DropReason::FirewallClockRegression,
        &regression_tcp,
    );
    assert_eq!(combined_nat.mappings(), before_combined_udp.as_slice());
    assert_eq!(combined_nat.peers(), before_combined_peers.as_slice());
    assert_eq!(combined_tcp.mappings(), before_combined_tcp.as_slice());
    assert_eq!(combined_tcp.sessions(), before_combined_sessions.as_slice());
    assert_eq!(
        combined_firewall.states(),
        before_combined_firewall.as_slice()
    );
    assert_eq!(combined_nat.counters(), before_combined_udp_counters);
    assert_eq!(combined_tcp.counters(), before_combined_tcp_counters);
    let mut expected_firewall_counters = before_combined_firewall_counters;
    expected_firewall_counters.clock_regressions += 2;
    assert_eq!(combined_firewall.counters(), expected_firewall_counters);
    assert_eq!(combined_io.pending_tx(), 0);

    capture_state_evidence(
        Some(&combined_nat),
        Some(&combined_tcp),
        Some(&combined_firewall),
        &combined_resolution,
        &combined_io,
    )
}

fn run_replay_evidence(seed: u64) -> ReplayEvidence {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = udp_config(&snapshot, seed, 40_500, 40_500);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut indexes = UdpTestIndexes::new(config, 1, 1);
    let mut nat = indexes.runtime(config, &mut mappings, &mut peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = new_resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    let mut trace = VecTrace::default();
    let valid = udp_frame_with_reference_checksum(HOST, REMOTE, 21_001, 53, 0x4000);
    let mut invalid = udp_frame(HOST, REMOTE, 21_002, 53, 0x4000);
    invalid[24] ^= 1;
    io.inject(LAN, valid);
    io.inject(LAN, invalid);
    let report = io
        .run_nat44_udp_once(
            2,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(7),
            &mut trace,
        )
        .unwrap();
    assert_batch(&report);
    assert_eq!(report.tx_requested, 1);
    assert_eq!(report.dropped, 1);
    let mut tx = Vec::new();
    while let Some(frame) = io.pop_tx() {
        tx.push(frame);
    }
    let mut recycled = Vec::new();
    while let Some(frame) = io.pop_recycled_capture() {
        recycled.push(frame);
    }
    assert_eq!(tx.len(), 1);
    assert_eq!(recycled.len(), 1);
    assert_eq!(tx[0].sequence, 0);
    assert_eq!(tx[0].egress, WAN);
    assert_eq!(tx[0].origin, FrameOrigin::Received { ingress: LAN });
    assert_eq!(
        recycled[0].frame.cause,
        RecycleCause::Forwarding(DropReason::Ipv4HeaderChecksumInvalid)
    );
    assert_eq!(recycled[0].rejected_egress, None);
    assert_udp_reference_checksum(&tx[0].bytes);
    let trace = trace.events().to_vec();

    let (
        resolution_states,
        resolution_actions,
        resolution_status,
        resolution_counters,
        resolution_failure_counters,
        unresolved_recycled,
        unresolved_trace,
    ) = {
        let (routes, interfaces, neighbors, bindings) = no_wan_neighbor_topology();
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let config = udp_config(&snapshot, seed, 40_510, 40_510);
        let mut mappings = [Nat44UdpMappingSlot::default(); 1];
        let mut peers = [Nat44UdpPeerSlot::default(); 1];
        let mut indexes = UdpTestIndexes::new(config, 1, 1);
        let mut nat = indexes.runtime(config, &mut mappings, &mut peers);
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let (
            resolution_status,
            resolution_counters,
            resolution_failure_counters,
            unresolved_recycled,
            unresolved_trace,
        ) = {
            let mut resolution = new_resolution(&mut states, &mut actions);
            let mut io = SimIo::new();
            let mut trace = VecTrace::default();
            let packet = udp_frame_with_reference_checksum(HOST, REMOTE, 21_011, 53, 0x4000);
            io.inject(LAN, packet.clone());
            let report = io
                .run_nat44_udp_once(
                    1,
                    &snapshot,
                    &mut resolution,
                    &config,
                    Some(&mut nat),
                    MonotonicMillis(7),
                    &mut trace,
                )
                .unwrap();
            assert_batch(&report);
            let capture = io.pop_recycled_capture().expect("unresolved RX capture");
            assert_eq!(
                capture.frame.cause,
                RecycleCause::Forwarding(DropReason::NeighborUnresolved)
            );
            assert_eq!(capture.frame.bytes, packet);
            assert_eq!(capture.rejected_egress, None);
            assert_eq!(io.pending_tx(), 0);
            assert_eq!(resolution.pending_states(), 1);
            assert_eq!(resolution.pending_actions(), 1);
            (
                resolution.status(WAN, GATEWAY),
                resolution.counters(),
                resolution.failure_counters(),
                vec![capture],
                trace.events().to_vec(),
            )
        };
        (
            states.to_vec(),
            actions.to_vec(),
            resolution_status,
            resolution_counters,
            resolution_failure_counters,
            unresolved_recycled,
            unresolved_trace,
        )
    };

    ReplayEvidence {
        tx,
        recycled,
        unresolved_recycled,
        trace,
        unresolved_trace,
        resolution_states,
        resolution_actions,
        resolution_status,
        resolution_counters,
        resolution_failure_counters,
    }
}

fn deterministic_replay_evidence(seed: u64) -> StateEvidence {
    let first = run_replay_evidence(seed);
    let second = run_replay_evidence(seed);
    assert!(
        first == second,
        "full deterministic replay evidence diverged"
    );
    let resolution_counters = first.resolution_counters;
    let resolution_failure_counters = first.resolution_failure_counters;
    let resolution_counts = [
        usize::from(first.resolution_status.is_some()),
        resolution_counters.queued,
        0,
        0,
    ];
    StateEvidence {
        udp_mappings: Vec::new(),
        udp_peers: Vec::new(),
        udp_counters: None,
        tcp_mappings: Vec::new(),
        tcp_sessions: Vec::new(),
        tcp_counters: None,
        udp_authority: None,
        tcp_authority: None,
        firewall_states: Vec::new(),
        firewall_counters: None,
        firewall_authority: None,
        resolution_counters,
        resolution_failure_counters,
        resolution_counts,
        io_counts: [0; 3],
        replay: Some(first),
    }
}
