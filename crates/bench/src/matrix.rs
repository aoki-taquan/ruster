use std::convert::Infallible;
use std::hint::black_box;
use std::time::{Duration, Instant};

#[cfg(test)]
use std::cell::RefCell;

use ruster_core::{
    forward_batch, forward_batch_with_firewall, forward_batch_with_nat44_tcp,
    forward_batch_with_nat44_udp, forward_batch_with_nat44_udp_and_tcp_and_firewall,
    ipv4_header_checksum, validate_ipv4_frame, BatchReport, DirectoryBucket, DirectoryNode,
    FirewallAction, FirewallAuthorityEvidence, FirewallConfig, FirewallHashKey, FirewallInterface,
    FirewallIpv4Prefix, FirewallPolicy, FirewallPortRange, FirewallProtocol, FirewallRule,
    FirewallRuleId, FirewallRuntime, FirewallStateSlot, ForwardingSnapshot, IfId, Interface,
    Ipv4Address, Ipv4Mtu, LocalIpv4Binding, MacAddress, Nat44Icmpv4ErrorPolicy,
    Nat44TcpAuthorityEvidence, Nat44TcpConfig, Nat44TcpHashKey, Nat44TcpIndexStorage,
    Nat44TcpMappingSlot, Nat44TcpPolicy, Nat44TcpRuntime, Nat44TcpSessionSlot,
    Nat44UdpAuthorityEvidence, Nat44UdpConfig, Nat44UdpHashKey, Nat44UdpIndexStorage,
    Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpRuntime, Neighbor, NoTrace,
    PacketIo, PortOwnerSlot, ResolutionActionSlot, ResolutionPolicy, ResolutionRuntime,
    ResolutionStateSlot, Route,
};

use crate::backend::BenchBatch;
#[cfg(test)]
use crate::deterministic::R17_DETERMINISTIC_SMOKE_CASES;
use crate::deterministic::{
    r17_hash_role_mapping_digest_for, R17Direction, R17HashConstructorProbe, R17HashRole,
    R17Profile, R17SetupTransport, R17Transport, R17WorkloadDescriptor,
    R17_DETERMINISTIC_SMOKE_CASE_COUNT, R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
    R17_DETERMINISTIC_SMOKE_SEED, R17_WORKLOAD_DESCRIPTOR,
};
use crate::runner::{
    ensure_no_allocations, subtract_setup_control, Measurement, MIN_AGGREGATE_REPETITIONS,
};
use crate::{
    allocation_count, BenchBackend, BenchCompletion, FrameSize, ResultRow, RunConfig, RunError,
    SampleStats,
};

const LAN: IfId = IfId(R17_WORKLOAD_DESCRIPTOR.topology.lan_if);
const WAN: IfId = IfId(R17_WORKLOAD_DESCRIPTOR.topology.wan_if);
const LAN_MAC: MacAddress = MacAddress(R17_WORKLOAD_DESCRIPTOR.topology.lan_mac);
const WAN_MAC: MacAddress = MacAddress(R17_WORKLOAD_DESCRIPTOR.topology.wan_mac);
const HOST_MAC: MacAddress = MacAddress(R17_WORKLOAD_DESCRIPTOR.topology.host_mac);
const GATEWAY_MAC: MacAddress = MacAddress(R17_WORKLOAD_DESCRIPTOR.topology.gateway_mac);
const HOST: Ipv4Address = Ipv4Address::from_octets(R17_WORKLOAD_DESCRIPTOR.topology.host);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets(R17_WORKLOAD_DESCRIPTOR.topology.public);
const REMOTE: Ipv4Address = Ipv4Address::from_octets(R17_WORKLOAD_DESCRIPTOR.topology.remote);
const HOST_PORT: u16 = R17_WORKLOAD_DESCRIPTOR.topology.host_port;
const REMOTE_PORT: u16 = R17_WORKLOAD_DESCRIPTOR.topology.remote_port;
const MATRIX_CASE_COUNT: usize = R17_DETERMINISTIC_SMOKE_CASE_COUNT;
const NAT_MAPPING_CAPACITY: usize = R17_WORKLOAD_DESCRIPTOR.capacities.nat_mapping_slots;
const NAT_PEER_CAPACITY: usize = R17_WORKLOAD_DESCRIPTOR.capacities.nat_peer_slots;
const NAT_SESSION_CAPACITY: usize = R17_WORKLOAD_DESCRIPTOR.capacities.nat_session_slots;
const DIRECTORY_BUCKET_CAPACITY: usize = R17_WORKLOAD_DESCRIPTOR.capacities.directory_buckets;
const DIRECTORY_NODE_CAPACITY: usize = R17_WORKLOAD_DESCRIPTOR.capacities.directory_nodes;
const PORT_OWNER_CAPACITY: usize = R17_WORKLOAD_DESCRIPTOR.capacities.port_owner_slots;
const FIREWALL_STATE_CAPACITY: usize = R17_WORKLOAD_DESCRIPTOR.capacities.firewall_state_slots;
const RESOLUTION_STATE_CAPACITY: usize = R17_WORKLOAD_DESCRIPTOR.capacities.resolution_state_slots;
const RESOLUTION_ACTION_CAPACITY: usize =
    R17_WORKLOAD_DESCRIPTOR.capacities.resolution_action_slots;

fn r17_nat_udp_hash_key() -> Nat44UdpHashKey {
    let role = R17_WORKLOAD_DESCRIPTOR
        .hash_roles
        .role(R17HashRole::NatUdpMappingPeer);
    Nat44UdpHashKey::new(role.first, role.second).expect("benchmark UDP hash key")
}

fn r17_nat_tcp_hash_key() -> Nat44TcpHashKey {
    let role = R17_WORKLOAD_DESCRIPTOR
        .hash_roles
        .role(R17HashRole::NatTcpMappingSession);
    Nat44TcpHashKey::new(role.first, role.second).expect("benchmark TCP hash key")
}

fn r17_firewall_hash_key() -> FirewallHashKey {
    let role = R17_WORKLOAD_DESCRIPTOR
        .hash_roles
        .role(R17HashRole::FirewallStatefulFlow);
    FirewallHashKey::new(role.first, role.second).expect("benchmark firewall hash key")
}

const fn fingerprint_byte(hash: u64, byte: u8) -> u64 {
    (hash ^ byte as u64).wrapping_mul(0x0000_0100_0000_01b3)
}

const fn fingerprint_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    let mut index = 0;
    while index < bytes.len() {
        hash = fingerprint_byte(hash, bytes[index]);
        index += 1;
    }
    hash
}

const fn fingerprint_u16(hash: u64, value: u16) -> u64 {
    fingerprint_bytes(hash, &value.to_be_bytes())
}

const fn fingerprint_u8(hash: u64, value: u8) -> u64 {
    fingerprint_byte(hash, value)
}

const fn fingerprint_u32(hash: u64, value: u32) -> u64 {
    fingerprint_bytes(hash, &value.to_be_bytes())
}

const fn fingerprint_u64(hash: u64, value: u64) -> u64 {
    fingerprint_bytes(hash, &value.to_be_bytes())
}

const fn fingerprint_ip(hash: u64, value: Ipv4Address) -> u64 {
    fingerprint_bytes(hash, &value.octets())
}

fn fingerprint_optional_ip(hash: u64, value: Option<Ipv4Address>) -> u64 {
    match value {
        Some(address) => fingerprint_ip(fingerprint_byte(hash, 1), address),
        None => fingerprint_byte(hash, 0),
    }
}

fn fingerprint_firewall_interface(hash: u64, value: FirewallInterface) -> u64 {
    match value {
        FirewallInterface::Any => fingerprint_byte(hash, 0),
        FirewallInterface::Interface(interface) => {
            fingerprint_u16(fingerprint_byte(hash, 1), interface.0)
        }
    }
}

fn fingerprint_firewall_rule(hash: u64, rule: FirewallRule) -> u64 {
    let mut hash = fingerprint_u64(hash, u64::from(rule.id().0));
    hash = fingerprint_firewall_interface(hash, rule.ingress());
    hash = fingerprint_firewall_interface(hash, rule.egress());
    hash = fingerprint_ip(hash, rule.source().address());
    hash = fingerprint_byte(hash, rule.source().prefix_len());
    hash = fingerprint_ip(hash, rule.destination().address());
    hash = fingerprint_byte(hash, rule.destination().prefix_len());
    hash = fingerprint_byte(
        hash,
        match rule.protocol() {
            FirewallProtocol::Tcp => 6,
            FirewallProtocol::Udp => 17,
        },
    );
    hash = fingerprint_u16(hash, rule.source_ports().first());
    hash = fingerprint_u16(hash, rule.source_ports().last());
    hash = fingerprint_u16(hash, rule.destination_ports().first());
    hash = fingerprint_u16(hash, rule.destination_ports().last());
    fingerprint_byte(
        hash,
        match rule.action() {
            FirewallAction::AllowStateful => 1,
            FirewallAction::Deny => 0,
        },
    )
}

fn fingerprint_fixture(mut hash: u64, phase: &[u8], fixture: &[u8]) -> u64 {
    hash = fingerprint_bytes(hash, phase);
    hash = fingerprint_u64(hash, fixture.len() as u64);
    fingerprint_bytes(hash, fixture)
}

fn fingerprint_bool(hash: u64, value: bool) -> u64 {
    fingerprint_byte(hash, u8::from(value))
}

fn fingerprint_setup_step(mut hash: u64, step: crate::deterministic::R17SetupStep) -> u64 {
    hash = fingerprint_bytes(hash, step.label.as_bytes());
    hash = fingerprint_byte(
        hash,
        match step.transport {
            crate::deterministic::R17SetupTransport::Udp => 17,
            crate::deterministic::R17SetupTransport::Tcp => 6,
        },
    );
    hash = fingerprint_byte(
        hash,
        match step.direction {
            crate::deterministic::R17SetupDirection::Outbound => 0,
            crate::deterministic::R17SetupDirection::Inbound => 1,
        },
    );
    match step.seed {
        crate::deterministic::R17SeedTransform::Base => fingerprint_byte(hash, 0),
        crate::deterministic::R17SeedTransform::Xor(value) => {
            fingerprint_u64(fingerprint_byte(hash, 1), value)
        }
    }
}

fn fingerprint_workload_descriptor(hash: u64) -> u64 {
    fingerprint_workload_descriptor_value(hash, R17_WORKLOAD_DESCRIPTOR)
}

fn fingerprint_workload_descriptor_value(mut hash: u64, descriptor: R17WorkloadDescriptor) -> u64 {
    hash = fingerprint_bytes(hash, b"ruster.r17.workload-descriptor/v2\n");
    hash = fingerprint_u64(hash, descriptor.seed);
    hash = fingerprint_u64(hash, descriptor.logical_time_ms);

    let topology = descriptor.topology;
    hash = fingerprint_u16(hash, topology.lan_if);
    hash = fingerprint_u16(hash, topology.wan_if);
    for mac in [
        topology.lan_mac,
        topology.wan_mac,
        topology.host_mac,
        topology.gateway_mac,
    ] {
        hash = fingerprint_bytes(hash, &mac);
    }
    for address in [
        topology.host,
        topology.lan_local,
        topology.public,
        topology.remote,
        topology.gateway,
        topology.lan_route_prefix,
        topology.default_route_prefix,
        topology.default_route_next_hop,
    ] {
        hash = fingerprint_bytes(hash, &address);
    }
    hash = fingerprint_u16(hash, topology.host_port);
    hash = fingerprint_u16(hash, topology.remote_port);
    hash = fingerprint_u8(hash, topology.lan_route_prefix_len);
    hash = fingerprint_u8(hash, topology.default_route_prefix_len);

    let frame = descriptor.frame;
    hash = fingerprint_bytes(hash, frame.deterministic_size.label().as_bytes());
    hash = fingerprint_u16(hash, frame.ethertype);
    hash = fingerprint_u8(hash, frame.ipv4_version_ihl);
    hash = fingerprint_u16(hash, frame.ipv4_flags);
    hash = fingerprint_u8(hash, frame.ttl);
    hash = fingerprint_bool(hash, frame.udp_zero_checksum);
    hash = fingerprint_bool(hash, frame.udp_transport_checksum);
    hash = fingerprint_bool(hash, frame.tcp_transport_checksum);
    for shift in frame.payload_xorshift {
        hash = fingerprint_u32(hash, shift);
    }
    hash = fingerprint_u32(hash, frame.tcp_sequence);
    hash = fingerprint_u32(hash, frame.tcp_acknowledgement);
    hash = fingerprint_u16(hash, frame.tcp_window);

    let resolution = descriptor.resolution;
    hash = fingerprint_u64(hash, resolution.interval_ms);
    hash = fingerprint_u64(hash, resolution.state_ttl_ms);
    hash = fingerprint_u16(hash, resolution.max_attempts);
    hash = fingerprint_u64(hash, resolution.dynamic_neighbor_ttl_ms);

    let nat = descriptor.nat;
    hash = fingerprint_u64(hash, nat.udp_idle_ttl_ms);
    hash = fingerprint_u64(hash, nat.tcp_idle_ttl_ms);
    hash = fingerprint_u64(hash, nat.allocator_seed);
    hash = fingerprint_u16(hash, nat.public_port_first);
    hash = fingerprint_u16(hash, nat.public_port_last);

    let firewall = descriptor.firewall;
    hash = fingerprint_u64(hash, firewall.udp_idle_ttl_ms);
    hash = fingerprint_u64(hash, firewall.tcp_opening_idle_ttl_ms);
    hash = fingerprint_u64(hash, firewall.tcp_active_idle_ttl_ms);
    hash = fingerprint_u64(hash, firewall.generation);
    for rule in firewall.rules {
        hash = fingerprint_u16(hash, rule.id);
        hash = fingerprint_u8(hash, rule.protocol);
        hash = fingerprint_bytes(hash, &rule.source_prefix);
        hash = fingerprint_u8(hash, rule.source_prefix_len);
        hash = fingerprint_bytes(hash, &rule.destination_prefix);
        hash = fingerprint_u8(hash, rule.destination_prefix_len);
        hash = fingerprint_u16(hash, rule.source_port_first);
        hash = fingerprint_u16(hash, rule.source_port_last);
        hash = fingerprint_u16(hash, rule.destination_port_first);
        hash = fingerprint_u16(hash, rule.destination_port_last);
        hash = fingerprint_bool(hash, rule.allow_stateful);
    }

    let capacities = descriptor.capacities;
    for capacity in [
        capacities.nat_mapping_slots,
        capacities.nat_peer_slots,
        capacities.nat_session_slots,
        capacities.directory_buckets,
        capacities.directory_nodes,
        capacities.port_owner_slots,
        capacities.firewall_state_slots,
        capacities.resolution_state_slots,
        capacities.resolution_action_slots,
    ] {
        hash = fingerprint_u64(hash, capacity as u64);
    }

    hash = fingerprint_u64(
        hash,
        r17_hash_role_mapping_digest_for(descriptor.hash_roles),
    );
    hash = fingerprint_bytes(hash, b"actual-hash-constructor-binding-live/v1\n");
    hash = fingerprint_u64(hash, r17_actual_hash_constructor_binding_digest());

    for (order, step) in descriptor.setup.steps.into_iter().enumerate() {
        hash = fingerprint_u64(hash, order as u64);
        hash = fingerprint_setup_step(hash, step);
        hash = fingerprint_u8(hash, step.tcp_flags);
    }

    for case in descriptor.cases {
        hash = fingerprint_bytes(hash, case.label.as_bytes());
        hash = fingerprint_byte(
            hash,
            match case.profile {
                crate::deterministic::R17Profile::Plain => 0,
                crate::deterministic::R17Profile::Nat => 1,
                crate::deterministic::R17Profile::Firewall => 2,
                crate::deterministic::R17Profile::Combined => 3,
            },
        );
        hash = fingerprint_byte(
            hash,
            match case.transport {
                crate::deterministic::R17Transport::UdpZero => 0,
                crate::deterministic::R17Transport::UdpChecksum => 1,
                crate::deterministic::R17Transport::Tcp => 2,
            },
        );
        hash = fingerprint_byte(
            hash,
            match case.direction {
                crate::deterministic::R17Direction::Outbound => 0,
                crate::deterministic::R17Direction::Inbound => 1,
            },
        );
    }
    hash
}

const R17_HASH_PROBE_OFFSET: u64 = 0x4d59_5f48_4153_485f;
const R17_HASH_PROBE_MULTIPLIER: u64 = 0x9e37_79b9_7f4a_7c15;
const R17_HASH_PROBE_MASK: u64 = 0xa5a5_5a5a_c3c3_3c3c;
const R17_HASH_PROBE_REMOTE_ENDPOINTS: [([u8; 4], u16); 4] = [
    (
        R17_WORKLOAD_DESCRIPTOR.topology.remote,
        R17_WORKLOAD_DESCRIPTOR.topology.remote_port,
    ),
    ([198, 51, 100, 21], 444),
    ([198, 51, 100, 22], 445),
    ([198, 51, 100, 23], 446),
];

const R17_AUTHORITY_WORDS: usize = 29;
const R17_UDP_MAPPING_DOMAIN: u64 = 0x4e41_5434_554d_4150;
const R17_UDP_PEER_DOMAIN: u64 = 0x4e41_5434_5550_4545;
const R17_TCP_MAPPING_DOMAIN: u64 = 0x4e41_5434_544d_4150;
const R17_TCP_SESSION_DOMAIN: u64 = 0x4e41_5434_5453_4553;
const R17_AUTHORITY_COMMITMENT_TAG: u64 = 0x5255_5354_2e4e_4154;
const R17_HASH_PROBE_PUBLIC_PORT: u16 = R17_WORKLOAD_DESCRIPTOR.nat.public_port_first;

#[derive(Clone, Copy, Default)]
struct R17ModelNatMapping {
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
struct R17ModelUdpPeer {
    occupied: bool,
    mapping_index: usize,
    mapping_generation: u64,
    mapping_lifecycle_epoch: u128,
    remote_address: u32,
}

#[derive(Clone, Copy, Default)]
struct R17ModelTcpSession {
    occupied: bool,
    mapping_index: usize,
    mapping_generation: u64,
    mapping_lifecycle_epoch: u128,
    remote_address: u32,
    remote_port: u16,
    last_activity_ms: u64,
}

#[derive(Clone, Copy, Default)]
struct R17ModelFirewallState {
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
struct R17ModelFirewallPacket {
    protocol_tcp: bool,
    ingress: u32,
    egress: u32,
    source: u32,
    destination: u32,
    source_port: u16,
    destination_port: u16,
}

#[derive(Clone, Copy)]
struct R17HashProbeObservation {
    authority_matches: bool,
    primary_occupied: u64,
    secondary_occupied: u64,
    indexes_coherent: bool,
    directories_coherent: bool,
    occupied_count_conserved: bool,
}

#[derive(Clone, Copy)]
#[allow(dead_code)] // Detailed opaque evidence is consumed by the focused R17 mutation test.
struct R17NatHashAuthorityProbe {
    evidence: Nat44UdpAuthorityEvidence,
    semantic: R17HashProbeObservation,
    mapping_buckets: [usize; NAT_MAPPING_CAPACITY],
    secondary_buckets: [usize; NAT_PEER_CAPACITY],
    forwarding_reached: bool,
}

#[derive(Clone, Copy)]
#[allow(dead_code)] // Detailed opaque evidence is consumed by the focused R17 mutation test.
struct R17TcpHashAuthorityProbe {
    evidence: Nat44TcpAuthorityEvidence,
    semantic: R17HashProbeObservation,
    mapping_buckets: [usize; NAT_MAPPING_CAPACITY],
    secondary_buckets: [usize; NAT_SESSION_CAPACITY],
    forwarding_reached: bool,
}

#[derive(Clone, Copy)]
#[allow(dead_code)] // Detailed opaque evidence is consumed by the focused R17 mutation test.
struct R17FirewallHashAuthorityProbe {
    evidence: FirewallAuthorityEvidence,
    semantic: R17HashProbeObservation,
    insertion_starts: [usize; 3],
    forwarding_reached: bool,
}

#[derive(Clone, Copy)]
struct R17ActualHashAuthorityProbes {
    udp: R17NatHashAuthorityProbe,
    tcp: R17TcpHashAuthorityProbe,
    firewall: R17FirewallHashAuthorityProbe,
}

#[derive(Clone, Copy)]
struct R17HashKeyBinding<K> {
    actual: K,
    model: (u64, u64),
}

impl<K> R17HashKeyBinding<K> {
    fn new(actual: K, model: (u64, u64)) -> Self {
        Self { actual, model }
    }
}

impl R17HashProbeObservation {
    const fn baseline(role: R17HashProbeRole) -> Self {
        match role {
            R17HashProbeRole::Udp | R17HashProbeRole::Tcp => Self {
                authority_matches: true,
                primary_occupied: 1,
                secondary_occupied: 4,
                indexes_coherent: true,
                directories_coherent: true,
                occupied_count_conserved: true,
            },
            R17HashProbeRole::Firewall => Self {
                authority_matches: true,
                primary_occupied: 3,
                secondary_occupied: 0,
                indexes_coherent: true,
                directories_coherent: true,
                occupied_count_conserved: true,
            },
        }
    }
}

#[derive(Clone, Copy)]
enum R17HashProbeRole {
    Udp,
    Tcp,
    Firewall,
}

impl R17HashProbeRole {
    const fn marker(self) -> &'static [u8] {
        match self {
            Self::Udp => b"udp-nat44-mapping-peer\n",
            Self::Tcp => b"tcp-nat44-mapping-session\n",
            Self::Firewall => b"firewall-stateful-flow\n",
        }
    }

    const fn legacy_identity(self) -> u64 {
        match self {
            Self::Udp => 0x74c7_bdf3_9f77_9845,
            Self::Tcp => 0xce7d_6c21_d546_4308,
            Self::Firewall => 0xa2b0_0754_0a6f_f5cd,
        }
    }
}

fn r17_model_mix(digest: u64, value: u64) -> u64 {
    digest
        .wrapping_add(value.wrapping_mul(0x9e37_79b9_7f4a_7c15))
        .rotate_left(17)
        ^ 0xa5a5_5a5a_c3c3_3c3c
}

fn r17_model_sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
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

fn r17_model_directory_hash(key: (u64, u64), domain: u64, words: &[u64]) -> u64 {
    let mut v0 = key.0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = key.1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = key.0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = key.1 ^ 0x7465_6462_7974_6573;
    for word in std::iter::once(domain).chain(words.iter().copied()) {
        v3 ^= word;
        r17_model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        r17_model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= word;
    }
    let final_word = 0x8000_0000_0000_0000 ^ words.len() as u64;
    v3 ^= final_word;
    r17_model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    r17_model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= final_word;
    v2 ^= 0xff;
    for _ in 0..4 {
        r17_model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^ v1 ^ v2 ^ v3
}

fn r17_model_directory_commitment(
    key: (u64, u64),
    domain: u64,
    expected_hashes: [Option<u64>; 4],
    bucket_count: usize,
    node_capacity: usize,
) -> u64 {
    let mut commitment = r17_model_directory_hash(
        key,
        domain,
        &[
            R17_AUTHORITY_COMMITMENT_TAG,
            bucket_count as u64,
            node_capacity as u64,
        ],
    );
    for (index, expected) in expected_hashes.into_iter().enumerate().take(node_capacity) {
        let linked = expected.is_some();
        commitment = r17_model_mix(commitment, index as u64);
        commitment = r17_model_mix(commitment, u64::from(linked));
        commitment = r17_model_mix(commitment, u64::from(linked));
        if let Some(hash) = expected {
            commitment = r17_model_mix(commitment, hash);
            let bucket = if bucket_count == 0 {
                u64::MAX
            } else {
                hash & (bucket_count as u64 - 1)
            };
            commitment = r17_model_mix(commitment, bucket);
        }
    }
    r17_model_mix(commitment, 1)
}

fn r17_model_directory_words(linked: [bool; 4], buckets: [usize; 4]) -> [u64; 6] {
    let mut link_mask = 0_u64;
    let mut topology_digest = 0xcbf2_9ce4_8422_2325_u64;
    let mut bucket_lengths = [0_usize; 4];
    let mut linked_nodes = 0_usize;
    for (index, linked) in linked.into_iter().enumerate() {
        if linked {
            linked_nodes += 1;
            link_mask |= 1_u64 << index;
            bucket_lengths[buckets[index]] += 1;
        }
        topology_digest = r17_model_mix(topology_digest, index as u64);
        topology_digest = r17_model_mix(topology_digest, u64::from(linked));
    }
    let nonempty_buckets = bucket_lengths.iter().filter(|length| **length != 0).count();
    let max_chain_len = bucket_lengths.iter().copied().max().unwrap_or(0);
    [
        1,
        linked_nodes as u64,
        nonempty_buckets as u64,
        max_chain_len as u64,
        link_mask,
        topology_digest,
    ]
}

fn r17_model_owner_words(mapping: [R17ModelNatMapping; 4]) -> [u64; 5] {
    let mut assigned_mask = 0_u64;
    let mut owner_digest = 0xcbf2_9ce4_8422_2325_u64;
    let mut assigned = 0_u64;

    // The R17 port range has one slot. Model the table's single offset once;
    // iterating state slots would add owner-digest words that the runtime
    // never emits.
    for offset in 0..PORT_OWNER_CAPACITY {
        let owner = mapping.into_iter().enumerate().find(|(_, mapping)| {
            mapping.occupied
                && mapping.port_owned
                && mapping.public_port == R17_HASH_PROBE_PUBLIC_PORT
        });
        if let Some((index, mapping)) = owner {
            assigned += 1;
            assigned_mask |= 1_u64 << offset;
            owner_digest = r17_model_mix(owner_digest, offset as u64);
            owner_digest = r17_model_mix(owner_digest, index as u64);
            owner_digest = r17_model_mix(owner_digest, mapping.generation);
            owner_digest = r17_model_mix(owner_digest, mapping.lifecycle_epoch as u64);
            owner_digest = r17_model_mix(owner_digest, (mapping.lifecycle_epoch >> 64) as u64);
        } else {
            owner_digest = r17_model_mix(owner_digest, offset as u64);
        }
    }
    [1, assigned, assigned, assigned_mask, owner_digest]
}

fn r17_model_mapping_digest(mapping: [R17ModelNatMapping; 4]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for (index, mapping) in mapping.into_iter().enumerate() {
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
            digest = r17_model_mix(digest, value);
        }
    }
    digest
}

fn r17_model_udp_peer_digest(peers: [R17ModelUdpPeer; 4]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for (index, peer) in peers.into_iter().enumerate() {
        for value in [
            index as u64,
            u64::from(peer.occupied),
            peer.mapping_index as u64,
            peer.mapping_generation,
            peer.mapping_lifecycle_epoch as u64,
            (peer.mapping_lifecycle_epoch >> 64) as u64,
            u64::from(peer.remote_address),
        ] {
            digest = r17_model_mix(digest, value);
        }
    }
    digest
}

fn r17_model_tcp_session_digest(sessions: [R17ModelTcpSession; 4]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for (index, session) in sessions.into_iter().enumerate() {
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
            digest = r17_model_mix(digest, value);
        }
    }
    digest
}

#[allow(clippy::too_many_arguments)]
fn r17_model_nat_words(
    mapping: [R17ModelNatMapping; 4],
    mapping_key: (u64, u64),
    mapping_domain: u64,
    secondary_count: usize,
    secondary_hashes: [Option<u64>; 4],
    secondary_domain: u64,
    secondary_digest: u64,
    revision: u64,
) -> [u64; R17_AUTHORITY_WORDS] {
    let mut mapping_hashes = [None; 4];
    for (index, state) in mapping.into_iter().enumerate() {
        if state.occupied {
            mapping_hashes[index] = Some(r17_model_directory_hash(
                mapping_key,
                mapping_domain,
                &[
                    u64::from(state.inside),
                    u64::from(state.internal_address),
                    u64::from(state.internal_port),
                ],
            ));
        }
    }
    let mut mapping_buckets = [0_usize; 4];
    let mut mapping_linked = [false; 4];
    for index in 0..4 {
        if let Some(hash) = mapping_hashes[index] {
            mapping_linked[index] = true;
            mapping_buckets[index] = hash as usize & 3;
        }
    }
    let mut secondary_buckets = [0_usize; 4];
    let mut secondary_linked = [false; 4];
    for index in 0..4 {
        if let Some(hash) = secondary_hashes[index] {
            secondary_linked[index] = true;
            secondary_buckets[index] = hash as usize & 3;
        }
    }
    let mapping_directory = r17_model_directory_words(mapping_linked, mapping_buckets);
    let secondary_directory = r17_model_directory_words(secondary_linked, secondary_buckets);
    let owners = r17_model_owner_words(mapping);
    let mapping_commitment =
        r17_model_directory_commitment(mapping_key, mapping_domain, mapping_hashes, 4, 4);
    let secondary_commitment =
        r17_model_directory_commitment(mapping_key, secondary_domain, secondary_hashes, 4, 4);
    let mut authority_commitment = r17_model_mix(mapping_commitment, secondary_commitment);
    for value in owners
        .into_iter()
        .chain([r17_model_mapping_digest(mapping), secondary_digest])
    {
        authority_commitment = r17_model_mix(authority_commitment, value);
    }
    let mut words = [0_u64; R17_AUTHORITY_WORDS];
    words[0] = 1;
    words[1] = R17_DETERMINISTIC_SMOKE_LOGICAL_TIME.0;
    words[2] = 1;
    words[4] = 2;
    words[5] = revision;
    words[7] = 1;
    words[8] = secondary_count as u64;
    words[9..15].copy_from_slice(&mapping_directory);
    words[15..21].copy_from_slice(&secondary_directory);
    words[21..26].copy_from_slice(&owners);
    words[26] = 1;
    words[27] = r17_model_mapping_digest(mapping);
    words[28] = authority_commitment;
    words
}

fn r17_expected_hash_key(role: R17HashProbeRole) -> (u64, u64) {
    let descriptor = R17_WORKLOAD_DESCRIPTOR.hash_roles;
    let role = match role {
        R17HashProbeRole::Udp => descriptor.nat_udp,
        R17HashProbeRole::Tcp => descriptor.nat_tcp,
        R17HashProbeRole::Firewall => descriptor.firewall,
    };
    (role.first, role.second)
}

fn r17_expected_udp_authority() -> Nat44UdpAuthorityEvidence {
    r17_expected_udp_authority_with_key(r17_expected_hash_key(R17HashProbeRole::Udp))
}

fn r17_expected_udp_authority_with_key(key: (u64, u64)) -> Nat44UdpAuthorityEvidence {
    let mut mappings = [R17ModelNatMapping::default(); 4];
    mappings[0] = R17ModelNatMapping {
        occupied: true,
        generation: 1,
        lifecycle_epoch: 1,
        port_owned: true,
        inside: u32::from(LAN.0),
        internal_address: u32::from_be_bytes(HOST.octets()),
        internal_port: HOST_PORT,
        public_port: R17_HASH_PROBE_PUBLIC_PORT,
        last_activity_ms: R17_DETERMINISTIC_SMOKE_LOGICAL_TIME.0,
    };
    let mut peers = [R17ModelUdpPeer::default(); 4];
    let mut peer_hashes = [None; 4];
    for (index, (remote, _port)) in R17_HASH_PROBE_REMOTE_ENDPOINTS.into_iter().enumerate() {
        let remote_address = u32::from_be_bytes(remote);
        peers[index] = R17ModelUdpPeer {
            occupied: true,
            mapping_index: 0,
            mapping_generation: 1,
            mapping_lifecycle_epoch: 1,
            remote_address,
        };
        peer_hashes[index] = Some(r17_model_directory_hash(
            key,
            R17_UDP_PEER_DOMAIN,
            &[0, 1, 0, 1, u64::from(remote_address)],
        ));
    }
    let words = r17_model_nat_words(
        mappings,
        key,
        R17_UDP_MAPPING_DOMAIN,
        peers.len(),
        peer_hashes,
        R17_UDP_PEER_DOMAIN,
        r17_model_udp_peer_digest(peers),
        5,
    );
    Nat44UdpAuthorityEvidence::from_expected_contract(4, 4, 4, 4, 4, 4, 1, words)
}

fn r17_expected_tcp_authority() -> Nat44TcpAuthorityEvidence {
    r17_expected_tcp_authority_with_key(r17_expected_hash_key(R17HashProbeRole::Tcp))
}

fn r17_expected_tcp_authority_with_key(key: (u64, u64)) -> Nat44TcpAuthorityEvidence {
    let mut mappings = [R17ModelNatMapping::default(); 4];
    mappings[0] = R17ModelNatMapping {
        occupied: true,
        generation: 1,
        lifecycle_epoch: 1,
        port_owned: true,
        inside: u32::from(LAN.0),
        internal_address: u32::from_be_bytes(HOST.octets()),
        internal_port: HOST_PORT,
        public_port: R17_HASH_PROBE_PUBLIC_PORT,
        last_activity_ms: R17_DETERMINISTIC_SMOKE_LOGICAL_TIME.0,
    };
    let mut sessions = [R17ModelTcpSession::default(); 4];
    let mut session_hashes = [None; 4];
    for (index, (remote, remote_port)) in R17_HASH_PROBE_REMOTE_ENDPOINTS.into_iter().enumerate() {
        let remote_address = u32::from_be_bytes(remote);
        sessions[index] = R17ModelTcpSession {
            occupied: true,
            mapping_index: 0,
            mapping_generation: 1,
            mapping_lifecycle_epoch: 1,
            remote_address,
            remote_port,
            last_activity_ms: R17_DETERMINISTIC_SMOKE_LOGICAL_TIME.0,
        };
        session_hashes[index] = Some(r17_model_directory_hash(
            key,
            R17_TCP_SESSION_DOMAIN,
            &[
                0,
                1,
                0,
                1,
                u64::from(remote_address),
                u64::from(remote_port),
            ],
        ));
    }
    let words = r17_model_nat_words(
        mappings,
        key,
        R17_TCP_MAPPING_DOMAIN,
        sessions.len(),
        session_hashes,
        R17_TCP_SESSION_DOMAIN,
        r17_model_tcp_session_digest(sessions),
        7,
    );
    Nat44TcpAuthorityEvidence::from_expected_contract(4, 4, 4, 4, 4, 4, 1, words)
}

fn r17_model_firewall_sip_hash<const WORDS: usize>(key: (u64, u64), words: [u64; WORDS]) -> u64 {
    let mut v0 = key.0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = key.1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = key.0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = key.1 ^ 0x7465_6462_7974_6573;
    for word in words {
        v3 ^= word;
        r17_model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        r17_model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= word;
    }
    let final_word = (WORDS as u64 * 8) << 56;
    v3 ^= final_word;
    r17_model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    r17_model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= final_word;
    v2 ^= 0xff;
    for _ in 0..4 {
        r17_model_sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^ v1 ^ v2 ^ v3
}

fn r17_model_firewall_hash(key: (u64, u64), packet: R17ModelFirewallPacket) -> u64 {
    let mut first = (packet.ingress, packet.source, packet.source_port);
    let mut second = (packet.egress, packet.destination, packet.destination_port);
    if second < first {
        std::mem::swap(&mut first, &mut second);
    }
    let words = [
        R17_WORKLOAD_DESCRIPTOR.firewall.generation,
        if packet.protocol_tcp { 6 } else { 17 },
        u64::from(first.0),
        u64::from(first.1),
        u64::from(first.2),
        u64::from(second.0),
        u64::from(second.1),
        u64::from(second.2),
    ];
    r17_model_firewall_sip_hash(key, words)
}

fn r17_model_firewall_digest(states: [R17ModelFirewallState; 4]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for (index, state) in states.into_iter().enumerate() {
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
            digest = r17_model_mix(digest, value);
        }
    }
    digest
}

fn r17_model_firewall_commitment(
    key: (u64, u64),
    states: [R17ModelFirewallState; 4],
    watermark_ms: Option<u64>,
    runtime_epoch: u64,
    next_slot_generation: u64,
    occupied_count: u64,
) -> u64 {
    let state_digest = r17_model_firewall_digest(states);
    let mut commitment = r17_model_firewall_sip_hash(
        key,
        [
            0x5255_5354_2e46_4952,
            R17_WORKLOAD_DESCRIPTOR.firewall.generation,
            states.len() as u64,
            u64::from(watermark_ms.is_some()),
            watermark_ms.unwrap_or_default(),
            runtime_epoch,
            next_slot_generation,
            occupied_count,
            occupied_count,
            state_digest,
        ],
    );
    for (index, state) in states.into_iter().enumerate() {
        commitment = r17_model_mix(commitment, index as u64);
        commitment = r17_model_mix(commitment, u64::from(state.occupied));
        let node_hash = state.occupied.then(|| {
            r17_model_firewall_hash(
                key,
                R17ModelFirewallPacket {
                    protocol_tcp: state.protocol_tcp,
                    ingress: state.origin_ingress,
                    egress: state.origin_egress,
                    source: state.initiator_address,
                    destination: state.responder_address,
                    source_port: state.initiator_port,
                    destination_port: state.responder_port,
                },
            )
        });
        commitment = r17_model_mix(commitment, node_hash.unwrap_or_default());
    }
    commitment
}

fn r17_expected_firewall_states(key: (u64, u64)) -> [R17ModelFirewallState; 4] {
    let mut states = [R17ModelFirewallState::default(); 4];
    for (ordinal, source_port) in [HOST_PORT, HOST_PORT + 1, HOST_PORT + 2]
        .into_iter()
        .enumerate()
    {
        let packet = R17ModelFirewallPacket {
            protocol_tcp: false,
            ingress: u32::from(LAN.0),
            egress: u32::from(WAN.0),
            source: u32::from_be_bytes(HOST.octets()),
            destination: u32::from_be_bytes(REMOTE.octets()),
            source_port,
            destination_port: REMOTE_PORT,
        };
        let start = r17_model_firewall_hash(key, packet) as usize & 3;
        let index = (0..4)
            .map(|distance| (start + distance) & 3)
            .find(|index| !states[*index].occupied)
            .expect("R17 firewall model capacity");
        states[index] = R17ModelFirewallState {
            occupied: true,
            slot_generation: ordinal as u64 + 1,
            config_generation: R17_WORKLOAD_DESCRIPTOR.firewall.generation,
            protocol_tcp: false,
            origin_ingress: u32::from(LAN.0),
            origin_egress: u32::from(WAN.0),
            initiator_address: u32::from_be_bytes(HOST.octets()),
            responder_address: u32::from_be_bytes(REMOTE.octets()),
            initiator_port: source_port,
            responder_port: REMOTE_PORT,
            last_activity_ms: R17_DETERMINISTIC_SMOKE_LOGICAL_TIME.0,
            tcp_phase_active: false,
            tcp_forward_ack: false,
            tcp_reverse_ack: false,
            origin_rule_id: 1,
        };
    }
    states
}

fn r17_expected_firewall_authority() -> FirewallAuthorityEvidence {
    r17_expected_firewall_authority_with_key(r17_expected_hash_key(R17HashProbeRole::Firewall))
}

fn r17_expected_firewall_authority_with_key(key: (u64, u64)) -> FirewallAuthorityEvidence {
    let states = r17_expected_firewall_states(key);
    FirewallAuthorityEvidence::from_expected_contract([
        1,
        R17_DETERMINISTIC_SMOKE_LOGICAL_TIME.0,
        1,
        4,
        3,
        3,
        r17_model_firewall_commitment(
            key,
            states,
            Some(R17_DETERMINISTIC_SMOKE_LOGICAL_TIME.0),
            1,
            4,
            3,
        ),
    ])
}

fn r17_firewall_state_layout_coherent(
    actual: &[FirewallStateSlot],
    expected: [R17ModelFirewallState; 4],
) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .copied()
            .zip(expected)
            .all(|(actual, expected)| {
                actual.is_occupied() == expected.occupied
                    && (!expected.occupied
                        || (actual.config_generation() == expected.config_generation
                            && actual.protocol()
                                == if expected.protocol_tcp {
                                    FirewallProtocol::Tcp
                                } else {
                                    FirewallProtocol::Udp
                                }
                            && actual.origin_ingress() == IfId(expected.origin_ingress as u16)
                            && actual.origin_egress() == IfId(expected.origin_egress as u16)
                            && u32::from_be_bytes(actual.initiator_address().octets())
                                == expected.initiator_address
                            && u32::from_be_bytes(actual.responder_address().octets())
                                == expected.responder_address
                            && actual.initiator_port() == expected.initiator_port
                            && actual.responder_port() == expected.responder_port
                            && actual.last_activity_ms() == expected.last_activity_ms
                            && actual.origin_rule_id() == FirewallRuleId(expected.origin_rule_id)))
            })
}

fn r17_hash_probe_semantic_digest(
    role: R17HashProbeRole,
    observation: R17HashProbeObservation,
) -> u64 {
    let mut digest = r17_hash_probe_bytes(R17_HASH_PROBE_OFFSET, b"opaque-authority/v2\n");
    digest = r17_hash_probe_bytes(digest, role.marker());
    for value in [
        u64::from(observation.authority_matches),
        observation.primary_occupied,
        observation.secondary_occupied,
        u64::from(observation.indexes_coherent),
        u64::from(observation.directories_coherent),
        u64::from(observation.occupied_count_conserved),
    ] {
        digest = r17_hash_probe_step(digest, value);
    }
    digest
}

fn r17_hash_probe_role_digest(role: R17HashProbeRole, observation: R17HashProbeObservation) -> u64 {
    role.legacy_identity()
        ^ r17_hash_probe_semantic_digest(role, observation)
        ^ r17_hash_probe_semantic_digest(role, R17HashProbeObservation::baseline(role))
}

fn r17_hash_probe_step(digest: u64, value: u64) -> u64 {
    digest
        .wrapping_add(value.wrapping_mul(R17_HASH_PROBE_MULTIPLIER))
        .rotate_left(23)
        ^ R17_HASH_PROBE_MASK
}

fn r17_hash_probe_bytes(mut digest: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        digest = r17_hash_probe_step(digest, u64::from(byte));
    }
    digest
}

fn r17_hash_constructor_binding_digest(probe: R17HashConstructorProbe) -> u64 {
    let mut digest = r17_hash_probe_bytes(
        R17_HASH_PROBE_OFFSET,
        b"ruster.r17.actual-constructor-binding/v1\n",
    );
    digest = r17_hash_probe_bytes(digest, b"udp-nat44-mapping-peer\n");
    digest = r17_hash_probe_step(digest, probe.nat_udp_mapping_peer);
    digest = r17_hash_probe_bytes(digest, b"tcp-nat44-mapping-session\n");
    digest = r17_hash_probe_step(digest, probe.nat_tcp_mapping_session);
    digest = r17_hash_probe_bytes(digest, b"firewall-stateful-flow\n");
    r17_hash_probe_step(digest, probe.firewall_stateful_flow)
}

/// Observes the key-dependent behavior of every actual R17 stateful runtime
/// constructor through fixed, secret-free authority evidence. The probe is a
/// cold identity check; it never runs in a packet steady path and returns only
/// bounded digests.
pub(crate) fn r17_actual_hash_constructor_binding_digest() -> u64 {
    let roles = R17_WORKLOAD_DESCRIPTOR.hash_roles;
    let probe = r17_actual_hash_constructor_probe_with_keys(
        R17HashKeyBinding::new(
            r17_nat_udp_hash_key(),
            (roles.nat_udp.first, roles.nat_udp.second),
        ),
        R17HashKeyBinding::new(
            r17_nat_tcp_hash_key(),
            (roles.nat_tcp.first, roles.nat_tcp.second),
        ),
        R17HashKeyBinding::new(
            r17_firewall_hash_key(),
            (roles.firewall.first, roles.firewall.second),
        ),
    );
    r17_hash_constructor_binding_digest(probe)
}

fn r17_actual_hash_constructor_probe_with_keys(
    udp: R17HashKeyBinding<Nat44UdpHashKey>,
    tcp: R17HashKeyBinding<Nat44TcpHashKey>,
    firewall: R17HashKeyBinding<FirewallHashKey>,
) -> R17HashConstructorProbe {
    let observations = r17_actual_hash_authority_probes_with_keys(
        udp.actual,
        udp.model,
        tcp.actual,
        tcp.model,
        firewall.actual,
        firewall.model,
    );
    R17HashConstructorProbe {
        nat_udp_mapping_peer: r17_hash_probe_role_digest(
            R17HashProbeRole::Udp,
            observations.udp.semantic,
        ),
        nat_tcp_mapping_session: r17_hash_probe_role_digest(
            R17HashProbeRole::Tcp,
            observations.tcp.semantic,
        ),
        firewall_stateful_flow: r17_hash_probe_role_digest(
            R17HashProbeRole::Firewall,
            observations.firewall.semantic,
        ),
    }
}

fn r17_actual_hash_authority_probes_with_keys(
    udp_hash_key: Nat44UdpHashKey,
    udp_model_key: (u64, u64),
    tcp_hash_key: Nat44TcpHashKey,
    tcp_model_key: (u64, u64),
    firewall_hash_key: FirewallHashKey,
    firewall_model_key: (u64, u64),
) -> R17ActualHashAuthorityProbes {
    assert_eq!(
        udp_hash_key,
        Nat44UdpHashKey::new(udp_model_key.0, udp_model_key.1)
            .expect("R17 UDP model key must be valid"),
        "R17 UDP actual/model hash keys must match"
    );
    assert_eq!(
        tcp_hash_key,
        Nat44TcpHashKey::new(tcp_model_key.0, tcp_model_key.1)
            .expect("R17 TCP model key must be valid"),
        "R17 TCP actual/model hash keys must match"
    );
    assert_eq!(
        firewall_hash_key,
        FirewallHashKey::new(firewall_model_key.0, firewall_model_key.1)
            .expect("R17 firewall model key must be valid"),
        "R17 firewall actual/model hash keys must match"
    );
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings)
        .expect("benchmark snapshot");
    let (udp_config, tcp_config) = nat_configs(&snapshot);
    let udp_probe = r17_hash_probe_udp(&snapshot, udp_config, udp_hash_key, udp_model_key);
    let tcp_probe = r17_hash_probe_tcp(&snapshot, tcp_config, tcp_hash_key, tcp_model_key);
    let rules = firewall_rules();
    let firewall_probe =
        r17_hash_probe_firewall(&snapshot, &rules, firewall_hash_key, firewall_model_key);

    R17ActualHashAuthorityProbes {
        udp: udp_probe,
        tcp: tcp_probe,
        firewall: firewall_probe,
    }
}

fn r17_hash_probe_udp(
    snapshot: &ForwardingSnapshot<'_>,
    config: Nat44UdpConfig,
    hash_key: Nat44UdpHashKey,
    model_key: (u64, u64),
) -> R17NatHashAuthorityProbe {
    let mut mappings = [Nat44UdpMappingSlot::default(); NAT_MAPPING_CAPACITY];
    let mut peers = [Nat44UdpPeerSlot::default(); NAT_PEER_CAPACITY];
    let mut indexes = UdpBenchIndexes::default();
    let mut runtime = indexes.runtime_with_hash_key(config, &mut mappings, &mut peers, hash_key);
    let mut resolution_states: [ResolutionStateSlot; RESOLUTION_STATE_CAPACITY] = [];
    let mut resolution_actions: [ResolutionActionSlot; RESOLUTION_ACTION_CAPACITY] = [];
    let mut resolution = resolution(&mut resolution_states, &mut resolution_actions);
    let case = Case {
        profile: Profile::Nat,
        transport: Transport::UdpChecksum,
        direction: Direction::Outbound,
    };
    let mut forward = |batch: BenchBatch<'_>| {
        forward_batch_with_nat44_udp(
            batch,
            snapshot,
            &mut resolution,
            &config,
            Some(&mut runtime),
            R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
            &mut NoTrace,
        )
    };
    establish_udp(case, &mut forward, R17_DETERMINISTIC_SMOKE_SEED)
        .expect("R17 UDP constructor probe forwarding");
    // Four distinct remote peers make the directory's bounded bucket/chain
    // evidence key-dependent without exposing a keyed hash word.
    for (ordinal, (remote_bytes, remote_port)) in R17_HASH_PROBE_REMOTE_ENDPOINTS
        .into_iter()
        .enumerate()
        .skip(1)
    {
        let remote = Ipv4Address::from_octets(remote_bytes);
        let fixture = udp_fixture_with_endpoints(
            R17_WORKLOAD_DESCRIPTOR.frame.deterministic_size,
            R17_DETERMINISTIC_SMOKE_SEED.wrapping_add(ordinal as u64),
            Direction::Outbound,
            true,
            (HOST, remote, HOST_PORT, remote_port),
        );
        forward_setup(&fixture, LAN, &mut forward)
            .expect("R17 UDP constructor probe peer forwarding");
    }
    assert_eq!(
        runtime
            .mappings()
            .iter()
            .filter(|mapping| mapping.is_occupied())
            .count(),
        1,
        "R17 UDP constructor probe mapping count"
    );
    assert_eq!(
        runtime
            .peers()
            .iter()
            .filter(|peer| peer.is_occupied())
            .count(),
        R17_HASH_PROBE_REMOTE_ENDPOINTS.len(),
        "R17 UDP constructor probe peer count"
    );
    let evidence = runtime.authority_evidence();
    assert_eq!(
        evidence,
        r17_expected_udp_authority_with_key(model_key),
        "R17 UDP actual state must match the expected contract for its bound key"
    );
    let primary_occupied = runtime
        .mappings()
        .iter()
        .filter(|mapping| mapping.is_occupied())
        .count() as u64;
    let secondary_occupied = runtime
        .peers()
        .iter()
        .filter(|peer| peer.is_occupied())
        .count() as u64;
    let mut mapping_buckets = [0_usize; NAT_MAPPING_CAPACITY];
    for (index, mapping) in runtime.mappings().iter().copied().enumerate() {
        if mapping.is_occupied() {
            mapping_buckets[index] = r17_model_directory_hash(
                model_key,
                R17_UDP_MAPPING_DOMAIN,
                &[
                    u64::from(LAN.0),
                    u64::from(u32::from_be_bytes(HOST.octets())),
                    u64::from(HOST_PORT),
                ],
            ) as usize
                & (DIRECTORY_BUCKET_CAPACITY - 1);
        }
    }
    let mut secondary_buckets = [0_usize; NAT_PEER_CAPACITY];
    for (index, (remote, _remote_port)) in R17_HASH_PROBE_REMOTE_ENDPOINTS.into_iter().enumerate() {
        secondary_buckets[index] = r17_model_directory_hash(
            model_key,
            R17_UDP_PEER_DOMAIN,
            &[0, 1, 0, 1, u64::from(u32::from_be_bytes(remote))],
        ) as usize
            & (DIRECTORY_BUCKET_CAPACITY - 1);
    }
    let semantic = R17HashProbeObservation {
        authority_matches: evidence == r17_expected_udp_authority(),
        primary_occupied,
        secondary_occupied,
        indexes_coherent: evidence.indexes_coherent(),
        directories_coherent: evidence.directories_coherent(),
        occupied_count_conserved: primary_occupied == 1 && secondary_occupied == 4,
    };
    R17NatHashAuthorityProbe {
        evidence,
        semantic,
        mapping_buckets,
        secondary_buckets,
        forwarding_reached: true,
    }
}

fn r17_hash_probe_tcp(
    snapshot: &ForwardingSnapshot<'_>,
    config: Nat44TcpConfig,
    hash_key: Nat44TcpHashKey,
    model_key: (u64, u64),
) -> R17TcpHashAuthorityProbe {
    let mut mappings = [Nat44TcpMappingSlot::default(); NAT_MAPPING_CAPACITY];
    let mut sessions = [Nat44TcpSessionSlot::default(); NAT_SESSION_CAPACITY];
    let mut indexes = TcpBenchIndexes::default();
    let mut runtime = indexes.runtime_with_hash_key(config, &mut mappings, &mut sessions, hash_key);
    let mut resolution_states: [ResolutionStateSlot; RESOLUTION_STATE_CAPACITY] = [];
    let mut resolution_actions: [ResolutionActionSlot; RESOLUTION_ACTION_CAPACITY] = [];
    let mut resolution = resolution(&mut resolution_states, &mut resolution_actions);
    let case = Case {
        profile: Profile::Nat,
        transport: Transport::Tcp,
        direction: Direction::Outbound,
    };
    let mut forward = |batch: BenchBatch<'_>| {
        forward_batch_with_nat44_tcp(
            batch,
            snapshot,
            &mut resolution,
            &config,
            Some(&mut runtime),
            R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
            &mut NoTrace,
        )
    };
    establish_tcp(case, &mut forward, R17_DETERMINISTIC_SMOKE_SEED)
        .expect("R17 TCP constructor probe forwarding");
    // Four distinct remote sessions provide the same key-dependent boundary
    // for the TCP session directory.
    for (ordinal, (remote_bytes, remote_port)) in R17_HASH_PROBE_REMOTE_ENDPOINTS
        .into_iter()
        .enumerate()
        .skip(1)
    {
        let remote = Ipv4Address::from_octets(remote_bytes);
        let fixture = tcp_fixture_with_endpoints(
            R17_WORKLOAD_DESCRIPTOR.frame.deterministic_size,
            R17_DETERMINISTIC_SMOKE_SEED.wrapping_add(ordinal as u64),
            Direction::Outbound,
            0x02,
            (HOST, remote, HOST_PORT, remote_port),
        );
        forward_setup(&fixture, LAN, &mut forward)
            .expect("R17 TCP constructor probe session forwarding");
    }
    assert_eq!(
        runtime
            .mappings()
            .iter()
            .filter(|mapping| mapping.is_occupied())
            .count(),
        1,
        "R17 TCP constructor probe mapping count"
    );
    assert_eq!(
        runtime
            .sessions()
            .iter()
            .filter(|session| session.is_occupied())
            .count(),
        R17_HASH_PROBE_REMOTE_ENDPOINTS.len(),
        "R17 TCP constructor probe session count"
    );
    let evidence = runtime.authority_evidence();
    assert_eq!(
        evidence,
        r17_expected_tcp_authority_with_key(model_key),
        "R17 TCP actual state must match the expected contract for its bound key"
    );
    let primary_occupied = runtime
        .mappings()
        .iter()
        .filter(|mapping| mapping.is_occupied())
        .count() as u64;
    let secondary_occupied = runtime
        .sessions()
        .iter()
        .filter(|session| session.is_occupied())
        .count() as u64;
    let mut mapping_buckets = [0_usize; NAT_MAPPING_CAPACITY];
    for (index, mapping) in runtime.mappings().iter().copied().enumerate() {
        if mapping.is_occupied() {
            mapping_buckets[index] = r17_model_directory_hash(
                model_key,
                R17_TCP_MAPPING_DOMAIN,
                &[
                    u64::from(LAN.0),
                    u64::from(u32::from_be_bytes(HOST.octets())),
                    u64::from(HOST_PORT),
                ],
            ) as usize
                & (DIRECTORY_BUCKET_CAPACITY - 1);
        }
    }
    let mut secondary_buckets = [0_usize; NAT_SESSION_CAPACITY];
    for (index, (remote, remote_port)) in R17_HASH_PROBE_REMOTE_ENDPOINTS.into_iter().enumerate() {
        secondary_buckets[index] = r17_model_directory_hash(
            model_key,
            R17_TCP_SESSION_DOMAIN,
            &[
                0,
                1,
                0,
                1,
                u64::from(u32::from_be_bytes(remote)),
                u64::from(remote_port),
            ],
        ) as usize
            & (DIRECTORY_BUCKET_CAPACITY - 1);
    }
    let semantic = R17HashProbeObservation {
        authority_matches: evidence == r17_expected_tcp_authority(),
        primary_occupied,
        secondary_occupied,
        indexes_coherent: evidence.indexes_coherent(),
        directories_coherent: evidence.directories_coherent(),
        occupied_count_conserved: primary_occupied == 1 && secondary_occupied == 4,
    };
    R17TcpHashAuthorityProbe {
        evidence,
        semantic,
        mapping_buckets,
        secondary_buckets,
        forwarding_reached: true,
    }
}

fn r17_hash_probe_firewall(
    snapshot: &ForwardingSnapshot<'_>,
    rules: &[FirewallRule],
    hash_key: FirewallHashKey,
    model_key: (u64, u64),
) -> R17FirewallHashAuthorityProbe {
    let config = firewall_config_with_hash_key(snapshot, rules, hash_key);
    let mut states = [FirewallStateSlot::default(); FIREWALL_STATE_CAPACITY];
    let mut runtime = FirewallRuntime::new(config, &mut states);
    let mut resolution_states: [ResolutionStateSlot; RESOLUTION_STATE_CAPACITY] = [];
    let mut resolution_actions: [ResolutionActionSlot; RESOLUTION_ACTION_CAPACITY] = [];
    let mut resolution = resolution(&mut resolution_states, &mut resolution_actions);
    for (ordinal, source_port) in [HOST_PORT, HOST_PORT + 1, HOST_PORT + 2]
        .into_iter()
        .enumerate()
    {
        let mut fixture = udp_fixture(
            R17_WORKLOAD_DESCRIPTOR.frame.deterministic_size,
            R17_DETERMINISTIC_SMOKE_SEED.wrapping_add(ordinal as u64),
            Direction::Outbound,
            true,
            false,
        );
        fixture[34..36].copy_from_slice(&source_port.to_be_bytes());
        fixture[40..42].fill(0);
        let checksum = transport_checksum(HOST, REMOTE, 17, &fixture[34..]);
        fixture[40..42].copy_from_slice(&checksum.to_be_bytes());
        finish_ipv4_checksum(&mut fixture);
        let mut forward = |batch: BenchBatch<'_>| {
            forward_batch_with_firewall(
                batch,
                snapshot,
                &mut resolution,
                &config,
                Some(&mut runtime),
                R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
                &mut NoTrace,
            )
        };
        forward_setup(&fixture, LAN, &mut forward)
            .expect("R17 firewall constructor probe forwarding");
    }
    assert_eq!(
        runtime
            .states()
            .iter()
            .filter(|state| state.is_occupied())
            .count(),
        3,
        "R17 firewall constructor probe state count"
    );
    let evidence = runtime.authority_evidence();
    let expected_states = r17_expected_firewall_states(model_key);
    let expected_contract = r17_expected_firewall_authority_with_key(model_key);
    let expected_contract_matches = evidence == expected_contract;
    let slot_layout_coherent =
        r17_firewall_state_layout_coherent(runtime.states(), expected_states);
    assert!(
        expected_contract_matches,
        "R17 firewall actual state must match the expected contract for its bound key"
    );
    assert!(
        slot_layout_coherent,
        "R17 firewall actual slots must match the expected state layout for its bound key"
    );
    let primary_occupied = runtime
        .states()
        .iter()
        .filter(|state| state.is_occupied())
        .count() as u64;
    let mut insertion_starts = [0_usize; 3];
    for (ordinal, source_port) in [HOST_PORT, HOST_PORT + 1, HOST_PORT + 2]
        .into_iter()
        .enumerate()
    {
        insertion_starts[ordinal] = r17_model_firewall_hash(
            model_key,
            R17ModelFirewallPacket {
                protocol_tcp: false,
                ingress: u32::from(LAN.0),
                egress: u32::from(WAN.0),
                source: u32::from_be_bytes(HOST.octets()),
                destination: u32::from_be_bytes(REMOTE.octets()),
                source_port,
                destination_port: REMOTE_PORT,
            },
        ) as usize
            & (FIREWALL_STATE_CAPACITY - 1);
    }
    let semantic = R17HashProbeObservation {
        authority_matches: evidence == r17_expected_firewall_authority(),
        primary_occupied,
        secondary_occupied: 0,
        indexes_coherent: slot_layout_coherent && expected_contract_matches,
        directories_coherent: slot_layout_coherent && expected_contract_matches,
        occupied_count_conserved: evidence.occupied_count_conserved(),
    };
    R17FirewallHashAuthorityProbe {
        evidence,
        semantic,
        insertion_starts,
        forwarding_reached: true,
    }
}

fn fingerprint_nat_udp_config(mut hash: u64, config: Nat44UdpConfig) -> u64 {
    hash = fingerprint_u16(hash, config.inside().0);
    hash = fingerprint_u16(hash, config.outside().0);
    hash = fingerprint_ip(hash, config.public_address());
    hash = fingerprint_u16(hash, config.first_port());
    hash = fingerprint_u16(hash, config.last_port());
    let policy = config.policy();
    hash = fingerprint_u64(hash, policy.idle_ttl_ms());
    hash = fingerprint_u64(hash, policy.allocator_seed());
    fingerprint_bytes(
        hash,
        match policy.icmpv4_errors() {
            Nat44Icmpv4ErrorPolicy::Disabled => b"icmp-disabled\n",
            Nat44Icmpv4ErrorPolicy::ExternalOnly => b"icmp-external-only\n",
            _ => b"icmp-unknown\n",
        },
    )
}

fn fingerprint_nat_tcp_config(mut hash: u64, config: Nat44TcpConfig) -> u64 {
    hash = fingerprint_u16(hash, config.inside().0);
    hash = fingerprint_u16(hash, config.outside().0);
    hash = fingerprint_ip(hash, config.public_address());
    hash = fingerprint_u16(hash, config.first_port());
    hash = fingerprint_u16(hash, config.last_port());
    let policy = config.policy();
    hash = fingerprint_u64(hash, policy.idle_ttl_ms());
    hash = fingerprint_u64(hash, policy.allocator_seed());
    fingerprint_bytes(
        hash,
        match policy.icmpv4_errors() {
            Nat44Icmpv4ErrorPolicy::Disabled => b"icmp-disabled\n",
            Nat44Icmpv4ErrorPolicy::ExternalOnly => b"icmp-external-only\n",
            _ => b"icmp-unknown\n",
        },
    )
}

/// Computes the non-secret identity of every deterministic smoke workload
/// ingredient. The expected value lives independently in `deterministic.rs`;
/// changing this live topology, fixture, policy, or key material therefore
/// fails before an artifact can self-validate.
pub(crate) fn r17_deterministic_workload_fingerprint() -> u64 {
    let mut hash = fingerprint_workload_descriptor(0xcbf2_9ce4_8422_2325_u64);

    let (routes, interfaces, neighbors, bindings) = topology();
    hash = fingerprint_bytes(hash, b"topology-live/v1\n");
    for route in routes {
        hash = fingerprint_ip(hash, route.prefix());
        hash = fingerprint_byte(hash, route.prefix_len());
        hash = fingerprint_u16(hash, route.egress().0);
        hash = fingerprint_optional_ip(hash, route.next_hop());
    }
    for interface in interfaces {
        hash = fingerprint_u16(hash, interface.id.0);
        hash = fingerprint_bytes(hash, &interface.mac.0);
    }
    for neighbor in neighbors {
        hash = fingerprint_u16(hash, neighbor.interface.0);
        hash = fingerprint_ip(hash, neighbor.target);
        hash = fingerprint_bytes(hash, &neighbor.mac.0);
    }
    for binding in bindings {
        hash = fingerprint_u16(hash, binding.interface.0);
        hash = fingerprint_ip(hash, binding.address);
    }

    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings)
        .expect("benchmark snapshot");
    let (udp_config, tcp_config) = nat_configs(&snapshot);
    hash = fingerprint_bytes(hash, b"nat-config-live/v2\n");
    hash = fingerprint_nat_udp_config(hash, udp_config);
    hash = fingerprint_nat_tcp_config(hash, tcp_config);

    let rules = firewall_rules();
    hash = fingerprint_bytes(hash, b"firewall-rules-live/v2\n");
    for rule in rules {
        hash = fingerprint_firewall_rule(hash, rule);
    }
    let firewall = firewall_config(&snapshot, &rules);
    let policy = firewall.policy();
    hash = fingerprint_u64(hash, policy.udp_idle_ttl_ms());
    hash = fingerprint_u64(hash, policy.tcp_opening_idle_ttl_ms());
    hash = fingerprint_u64(hash, policy.tcp_active_idle_ttl_ms());
    hash = fingerprint_u64(hash, firewall.generation());

    let resolution_policy = ResolutionPolicy::with_retry_and_dynamic_neighbor_ttl(
        R17_WORKLOAD_DESCRIPTOR.resolution.interval_ms,
        R17_WORKLOAD_DESCRIPTOR.resolution.state_ttl_ms,
        R17_WORKLOAD_DESCRIPTOR.resolution.max_attempts,
        R17_WORKLOAD_DESCRIPTOR.resolution.dynamic_neighbor_ttl_ms,
    )
    .expect("benchmark resolution policy");
    hash = fingerprint_bytes(hash, b"resolution-policy-live/v2\n");
    hash = fingerprint_u64(hash, resolution_policy.interval_ms());
    hash = fingerprint_u64(hash, resolution_policy.failed_hold_ms());
    hash = fingerprint_u16(hash, resolution_policy.max_attempts());
    hash = fingerprint_u64(hash, resolution_policy.dynamic_neighbor_ttl_ms());
    hash = fingerprint_bytes(hash, b"storage-capacity-live/v2\n");
    for capacity in [
        NAT_MAPPING_CAPACITY,
        NAT_PEER_CAPACITY,
        NAT_SESSION_CAPACITY,
        DIRECTORY_BUCKET_CAPACITY,
        DIRECTORY_NODE_CAPACITY,
        PORT_OWNER_CAPACITY,
        FIREWALL_STATE_CAPACITY,
        RESOLUTION_STATE_CAPACITY,
        RESOLUTION_ACTION_CAPACITY,
    ] {
        hash = fingerprint_u64(hash, capacity as u64);
    }

    for (ordinal, case) in matrix_cases().enumerate() {
        let nat = matches!(case.profile, Profile::Nat | Profile::Combined);
        hash = fingerprint_u64(hash, ordinal as u64);
        hash = fingerprint_bytes(hash, case.label().as_bytes());
        hash = fingerprint_byte(
            hash,
            match case.profile {
                Profile::Plain => 0,
                Profile::Nat => 1,
                Profile::Firewall => 2,
                Profile::Combined => 3,
            },
        );
        hash = fingerprint_byte(
            hash,
            match case.transport {
                Transport::UdpZero => 0,
                Transport::UdpChecksum => 1,
                Transport::Tcp => 2,
            },
        );
        hash = fingerprint_byte(
            hash,
            match case.direction {
                Direction::Outbound => 0,
                Direction::Inbound => 1,
            },
        );
        hash = fingerprint_byte(hash, case.checksum_passes());
        hash = fingerprint_fixture(
            hash,
            b"measured",
            &timed_fixture(
                R17_WORKLOAD_DESCRIPTOR.frame.deterministic_size,
                R17_DETERMINISTIC_SMOKE_SEED,
                case,
                nat,
            ),
        );
        if case.profile != Profile::Plain {
            match case.transport {
                Transport::UdpZero | Transport::UdpChecksum => {
                    for step in R17_WORKLOAD_DESCRIPTOR.setup.steps {
                        if step.transport != R17SetupTransport::Udp {
                            continue;
                        }
                        hash = fingerprint_setup_step(hash, step);
                        hash = fingerprint_u8(hash, step.tcp_flags);
                        hash = fingerprint_fixture(
                            hash,
                            step.label.as_bytes(),
                            &setup_fixture(case, R17_DETERMINISTIC_SMOKE_SEED, step),
                        );
                    }
                }
                Transport::Tcp => {
                    for step in R17_WORKLOAD_DESCRIPTOR.setup.steps {
                        if step.transport != R17SetupTransport::Tcp {
                            continue;
                        }
                        hash = fingerprint_setup_step(hash, step);
                        hash = fingerprint_u8(hash, step.tcp_flags);
                        hash = fingerprint_fixture(
                            hash,
                            step.label.as_bytes(),
                            &setup_fixture(case, R17_DETERMINISTIC_SMOKE_SEED, step),
                        );
                    }
                }
            }
        }
    }
    hash
}

#[derive(Default)]
struct UdpBenchIndexes {
    mapping_buckets: [DirectoryBucket; DIRECTORY_BUCKET_CAPACITY],
    mapping_nodes: [DirectoryNode; DIRECTORY_NODE_CAPACITY],
    peer_buckets: [DirectoryBucket; DIRECTORY_BUCKET_CAPACITY],
    peer_nodes: [DirectoryNode; DIRECTORY_NODE_CAPACITY],
    port_owners: [PortOwnerSlot; PORT_OWNER_CAPACITY],
}

impl UdpBenchIndexes {
    fn runtime<'a>(
        &'a mut self,
        config: Nat44UdpConfig,
        mappings: &'a mut [Nat44UdpMappingSlot; NAT_MAPPING_CAPACITY],
        peers: &'a mut [Nat44UdpPeerSlot; NAT_PEER_CAPACITY],
    ) -> Nat44UdpRuntime<'a> {
        self.runtime_with_hash_key(config, mappings, peers, r17_nat_udp_hash_key())
    }

    fn runtime_with_hash_key<'a>(
        &'a mut self,
        config: Nat44UdpConfig,
        mappings: &'a mut [Nat44UdpMappingSlot; NAT_MAPPING_CAPACITY],
        peers: &'a mut [Nat44UdpPeerSlot; NAT_PEER_CAPACITY],
        hash_key: Nat44UdpHashKey,
    ) -> Nat44UdpRuntime<'a> {
        let storage = Nat44UdpIndexStorage::new(
            &mut self.mapping_buckets,
            &mut self.mapping_nodes,
            &mut self.peer_buckets,
            &mut self.peer_nodes,
            &mut self.port_owners,
        );
        Nat44UdpRuntime::new(config, mappings, peers, storage, hash_key)
            .expect("benchmark UDP runtime")
    }
}

#[derive(Default)]
struct TcpBenchIndexes {
    mapping_buckets: [DirectoryBucket; DIRECTORY_BUCKET_CAPACITY],
    mapping_nodes: [DirectoryNode; DIRECTORY_NODE_CAPACITY],
    session_buckets: [DirectoryBucket; DIRECTORY_BUCKET_CAPACITY],
    session_nodes: [DirectoryNode; DIRECTORY_NODE_CAPACITY],
    port_owners: [PortOwnerSlot; PORT_OWNER_CAPACITY],
}

impl TcpBenchIndexes {
    fn runtime<'a>(
        &'a mut self,
        config: Nat44TcpConfig,
        mappings: &'a mut [Nat44TcpMappingSlot; NAT_MAPPING_CAPACITY],
        sessions: &'a mut [Nat44TcpSessionSlot; NAT_SESSION_CAPACITY],
    ) -> Nat44TcpRuntime<'a> {
        self.runtime_with_hash_key(config, mappings, sessions, r17_nat_tcp_hash_key())
    }

    fn runtime_with_hash_key<'a>(
        &'a mut self,
        config: Nat44TcpConfig,
        mappings: &'a mut [Nat44TcpMappingSlot; NAT_MAPPING_CAPACITY],
        sessions: &'a mut [Nat44TcpSessionSlot; NAT_SESSION_CAPACITY],
        hash_key: Nat44TcpHashKey,
    ) -> Nat44TcpRuntime<'a> {
        let storage = Nat44TcpIndexStorage::new(
            &mut self.mapping_buckets,
            &mut self.mapping_nodes,
            &mut self.session_buckets,
            &mut self.session_nodes,
            &mut self.port_owners,
        );
        Nat44TcpRuntime::new(config, mappings, sessions, storage, hash_key)
            .expect("benchmark TCP runtime")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Profile {
    Plain,
    Nat,
    Firewall,
    Combined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Transport {
    UdpZero,
    UdpChecksum,
    Tcp,
}

impl Transport {
    const fn protocol(self) -> u8 {
        match self {
            Self::UdpZero | Self::UdpChecksum => 17,
            Self::Tcp => 6,
        }
    }

    const fn firewall_protocol(self) -> FirewallProtocol {
        match self {
            Self::UdpZero | Self::UdpChecksum => FirewallProtocol::Udp,
            Self::Tcp => FirewallProtocol::Tcp,
        }
    }

    const fn checksum_enabled(self) -> bool {
        match self {
            Self::UdpZero => R17_WORKLOAD_DESCRIPTOR.frame.udp_zero_checksum,
            Self::UdpChecksum => R17_WORKLOAD_DESCRIPTOR.frame.udp_transport_checksum,
            Self::Tcp => R17_WORKLOAD_DESCRIPTOR.frame.tcp_transport_checksum,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    Outbound,
    Inbound,
}

impl Direction {
    const fn ingress(self) -> IfId {
        match self {
            Self::Outbound => LAN,
            Self::Inbound => WAN,
        }
    }

    const fn egress(self) -> IfId {
        match self {
            Self::Outbound => WAN,
            Self::Inbound => LAN,
        }
    }
}

#[derive(Clone, Copy)]
struct Case {
    profile: Profile,
    transport: Transport,
    direction: Direction,
}

#[derive(Clone, Copy)]
enum MeasurementMode {
    Timed,
    DeterministicOnePass,
}

#[derive(Clone, Copy)]
struct CaseExecution<'a> {
    config: &'a RunConfig,
    measurement_mode: MeasurementMode,
}

impl<'a> CaseExecution<'a> {
    const fn timed(config: &'a RunConfig) -> Self {
        Self {
            config,
            measurement_mode: MeasurementMode::Timed,
        }
    }

    const fn deterministic_one_pass(config: &'a RunConfig) -> Self {
        Self {
            config,
            measurement_mode: MeasurementMode::DeterministicOnePass,
        }
    }
}

impl Case {
    const fn label(self) -> &'static str {
        match (self.profile, self.transport, self.direction) {
            (Profile::Plain, Transport::UdpZero, Direction::Outbound) => "ctl-udp0-out",
            (Profile::Plain, Transport::UdpZero, Direction::Inbound) => "ctl-udp0-in",
            (Profile::Plain, Transport::UdpChecksum, Direction::Outbound) => "ctl-udpc-out",
            (Profile::Plain, Transport::UdpChecksum, Direction::Inbound) => "ctl-udpc-in",
            (Profile::Plain, Transport::Tcp, Direction::Outbound) => "ctl-tcp-out",
            (Profile::Plain, Transport::Tcp, Direction::Inbound) => "ctl-tcp-in",
            (Profile::Nat, Transport::UdpZero, Direction::Outbound) => "nat-udp0-out-est",
            (Profile::Nat, Transport::UdpZero, Direction::Inbound) => "nat-udp0-in-est",
            (Profile::Nat, Transport::UdpChecksum, Direction::Outbound) => "nat-udpc-out-est",
            (Profile::Nat, Transport::UdpChecksum, Direction::Inbound) => "nat-udpc-in-est",
            (Profile::Nat, Transport::Tcp, Direction::Outbound) => "nat-tcp-out-est",
            (Profile::Nat, Transport::Tcp, Direction::Inbound) => "nat-tcp-in-est",
            (Profile::Firewall, Transport::UdpZero, Direction::Outbound) => "fw-udp0-out-est",
            (Profile::Firewall, Transport::UdpZero, Direction::Inbound) => "fw-udp0-in-est",
            (Profile::Firewall, Transport::UdpChecksum, Direction::Outbound) => "fw-udpc-out-est",
            (Profile::Firewall, Transport::UdpChecksum, Direction::Inbound) => "fw-udpc-in-est",
            (Profile::Firewall, Transport::Tcp, Direction::Outbound) => "fw-tcp-out-est",
            (Profile::Firewall, Transport::Tcp, Direction::Inbound) => "fw-tcp-in-est",
            (Profile::Combined, Transport::UdpZero, Direction::Outbound) => "both-udp0-out-est",
            (Profile::Combined, Transport::UdpZero, Direction::Inbound) => "both-udp0-in-est",
            (Profile::Combined, Transport::UdpChecksum, Direction::Outbound) => "both-udpc-out-est",
            (Profile::Combined, Transport::UdpChecksum, Direction::Inbound) => "both-udpc-in-est",
            (Profile::Combined, Transport::Tcp, Direction::Outbound) => "both-tcp-out-est",
            (Profile::Combined, Transport::Tcp, Direction::Inbound) => "both-tcp-in-est",
        }
    }

    const fn checksum_passes(self) -> u8 {
        match (self.profile, self.transport) {
            (_, Transport::UdpZero)
            | (Profile::Plain, Transport::UdpChecksum | Transport::Tcp)
            | (Profile::Nat, Transport::UdpChecksum) => 0,
            (Profile::Nat, Transport::Tcp)
            | (Profile::Firewall, Transport::UdpChecksum | Transport::Tcp)
            | (Profile::Combined, Transport::UdpChecksum) => 1,
            (Profile::Combined, Transport::Tcp) => 2,
        }
    }
}

fn matrix_cases() -> impl Iterator<Item = Case> {
    R17_WORKLOAD_DESCRIPTOR.cases.into_iter().map(|case| Case {
        profile: match case.profile {
            R17Profile::Plain => Profile::Plain,
            R17Profile::Nat => Profile::Nat,
            R17Profile::Firewall => Profile::Firewall,
            R17Profile::Combined => Profile::Combined,
        },
        transport: match case.transport {
            R17Transport::UdpZero => Transport::UdpZero,
            R17Transport::UdpChecksum => Transport::UdpChecksum,
            R17Transport::Tcp => Transport::Tcp,
        },
        direction: match case.direction {
            R17Direction::Outbound => Direction::Outbound,
            R17Direction::Inbound => Direction::Inbound,
        },
    })
}

pub(crate) fn run_matrix(
    config: &RunConfig,
    size: FrameSize,
    batch_size: usize,
) -> Result<Vec<ResultRow>, RunError> {
    let mut rows = Vec::with_capacity(MATRIX_CASE_COUNT);
    let execution = CaseExecution::timed(config);
    for case in matrix_cases() {
        rows.push(match case.profile {
            Profile::Plain => run_plain_control(execution, size, batch_size, case)?,
            Profile::Nat => run_nat_case(execution, size, batch_size, case)?,
            Profile::Firewall => run_firewall_case(execution, size, batch_size, case)?,
            Profile::Combined => run_combined_case(execution, size, batch_size, case)?,
        });
    }
    Ok(rows)
}

pub(crate) fn run_deterministic_matrix(config: &RunConfig) -> Result<Vec<ResultRow>, RunError> {
    let execution = CaseExecution::deterministic_one_pass(config);
    let mut rows = Vec::with_capacity(MATRIX_CASE_COUNT);
    for case in matrix_cases() {
        rows.push(match case.profile {
            Profile::Plain => run_plain_control(
                execution,
                R17_WORKLOAD_DESCRIPTOR.frame.deterministic_size,
                1,
                case,
            ),
            Profile::Nat => run_nat_case(
                execution,
                R17_WORKLOAD_DESCRIPTOR.frame.deterministic_size,
                1,
                case,
            ),
            Profile::Firewall => run_firewall_case(
                execution,
                R17_WORKLOAD_DESCRIPTOR.frame.deterministic_size,
                1,
                case,
            ),
            Profile::Combined => run_combined_case(
                execution,
                R17_WORKLOAD_DESCRIPTOR.frame.deterministic_size,
                1,
                case,
            ),
        }?);
    }
    Ok(rows)
}

fn run_plain_control(
    execution: CaseExecution<'_>,
    size: FrameSize,
    batch_size: usize,
    case: Case,
) -> Result<ResultRow, RunError> {
    let config = execution.config;
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings)
        .expect("benchmark snapshot");
    let template = timed_fixture(size, config.seed, case, false);
    let mut backend = BenchBackend::new(batch_size, case.direction.ingress(), &template);
    let row = {
        let mut forward = |batch: BenchBatch<'_>| forward_batch(batch, &snapshot, &mut NoTrace);
        execute_case(
            execution,
            size,
            batch_size,
            case,
            &template,
            &mut backend,
            &mut forward,
        )?
    };
    verify_case(&backend, &template, batch_size, case, false)?;
    Ok(row)
}

fn topology() -> (
    [Route; 2],
    [Interface; 2],
    [Neighbor; 2],
    [LocalIpv4Binding; 2],
) {
    let descriptor = R17_WORKLOAD_DESCRIPTOR.topology;
    (
        [
            Route::new(
                Ipv4Address::from_octets(descriptor.lan_route_prefix),
                descriptor.lan_route_prefix_len,
                IfId(descriptor.lan_if),
                None,
            )
            .expect("benchmark LAN route"),
            Route::new(
                Ipv4Address::from_octets(descriptor.default_route_prefix),
                descriptor.default_route_prefix_len,
                IfId(descriptor.wan_if),
                Some(Ipv4Address::from_octets(descriptor.default_route_next_hop)),
            )
            .expect("benchmark default route"),
        ],
        [
            Interface {
                id: IfId(descriptor.lan_if),
                mac: MacAddress(descriptor.lan_mac),
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: IfId(descriptor.wan_if),
                mac: MacAddress(descriptor.wan_mac),
                mtu: Ipv4Mtu::ETHERNET,
            },
        ],
        [
            Neighbor {
                interface: IfId(descriptor.lan_if),
                target: Ipv4Address::from_octets(descriptor.host),
                mac: MacAddress(descriptor.host_mac),
            },
            Neighbor {
                interface: IfId(descriptor.wan_if),
                target: Ipv4Address::from_octets(descriptor.gateway),
                mac: MacAddress(descriptor.gateway_mac),
            },
        ],
        [
            LocalIpv4Binding {
                interface: IfId(descriptor.lan_if),
                address: Ipv4Address::from_octets(descriptor.lan_local),
            },
            LocalIpv4Binding {
                interface: IfId(descriptor.wan_if),
                address: Ipv4Address::from_octets(descriptor.public),
            },
        ],
    )
}

fn resolution<'a>(
    states: &'a mut [ResolutionStateSlot],
    actions: &'a mut [ResolutionActionSlot],
) -> ResolutionRuntime<'a> {
    ResolutionRuntime::new(
        ResolutionPolicy::with_retry_and_dynamic_neighbor_ttl(
            R17_WORKLOAD_DESCRIPTOR.resolution.interval_ms,
            R17_WORKLOAD_DESCRIPTOR.resolution.state_ttl_ms,
            R17_WORKLOAD_DESCRIPTOR.resolution.max_attempts,
            R17_WORKLOAD_DESCRIPTOR.resolution.dynamic_neighbor_ttl_ms,
        )
        .expect("benchmark resolution policy"),
        states,
        actions,
    )
}

fn nat_configs(snapshot: &ForwardingSnapshot<'_>) -> (Nat44UdpConfig, Nat44TcpConfig) {
    (
        Nat44UdpConfig::new(
            snapshot,
            LAN,
            WAN,
            PUBLIC,
            R17_WORKLOAD_DESCRIPTOR.nat.public_port_first,
            R17_WORKLOAD_DESCRIPTOR.nat.public_port_last,
            Nat44UdpPolicy::new(
                R17_WORKLOAD_DESCRIPTOR.nat.udp_idle_ttl_ms,
                R17_WORKLOAD_DESCRIPTOR.nat.allocator_seed,
            )
            .expect("benchmark UDP policy"),
        )
        .expect("benchmark UDP NAT config"),
        Nat44TcpConfig::new(
            snapshot,
            LAN,
            WAN,
            PUBLIC,
            R17_WORKLOAD_DESCRIPTOR.nat.public_port_first,
            R17_WORKLOAD_DESCRIPTOR.nat.public_port_last,
            Nat44TcpPolicy::new(
                R17_WORKLOAD_DESCRIPTOR.nat.tcp_idle_ttl_ms,
                R17_WORKLOAD_DESCRIPTOR.nat.allocator_seed,
            )
            .expect("benchmark TCP policy"),
        )
        .expect("benchmark TCP NAT config"),
    )
}

fn firewall_rules() -> [FirewallRule; 2] {
    R17_WORKLOAD_DESCRIPTOR.firewall.rules.map(|descriptor| {
        let source = FirewallIpv4Prefix::new(
            Ipv4Address::from_octets(descriptor.source_prefix),
            descriptor.source_prefix_len,
        )
        .expect("benchmark source prefix");
        let destination = FirewallIpv4Prefix::new(
            Ipv4Address::from_octets(descriptor.destination_prefix),
            descriptor.destination_prefix_len,
        )
        .expect("benchmark destination prefix");
        let source_ports =
            FirewallPortRange::new(descriptor.source_port_first, descriptor.source_port_last)
                .expect("benchmark source port range");
        let destination_ports = FirewallPortRange::new(
            descriptor.destination_port_first,
            descriptor.destination_port_last,
        )
        .expect("benchmark destination port range");
        let protocol = match descriptor.protocol {
            6 => FirewallProtocol::Tcp,
            17 => FirewallProtocol::Udp,
            _ => panic!("benchmark firewall protocol is invalid"),
        };
        let action = if descriptor.allow_stateful {
            FirewallAction::AllowStateful
        } else {
            FirewallAction::Deny
        };
        FirewallRule::new(
            FirewallRuleId(u32::from(descriptor.id)),
            FirewallInterface::Interface(LAN),
            FirewallInterface::Interface(WAN),
            source,
            destination,
            protocol,
            source_ports,
            destination_ports,
            action,
        )
    })
}

fn firewall_config<'a>(
    snapshot: &ForwardingSnapshot<'_>,
    rules: &'a [FirewallRule],
) -> FirewallConfig<'a> {
    firewall_config_with_hash_key(snapshot, rules, r17_firewall_hash_key())
}

fn firewall_config_with_hash_key<'a>(
    snapshot: &ForwardingSnapshot<'_>,
    rules: &'a [FirewallRule],
    hash_key: FirewallHashKey,
) -> FirewallConfig<'a> {
    FirewallConfig::new(
        snapshot,
        rules,
        FirewallPolicy::new(
            R17_WORKLOAD_DESCRIPTOR.firewall.udp_idle_ttl_ms,
            R17_WORKLOAD_DESCRIPTOR.firewall.tcp_opening_idle_ttl_ms,
            R17_WORKLOAD_DESCRIPTOR.firewall.tcp_active_idle_ttl_ms,
        )
        .expect("benchmark firewall policy"),
        R17_WORKLOAD_DESCRIPTOR.firewall.generation,
        hash_key,
    )
    .expect("benchmark firewall config")
}

fn run_nat_case(
    execution: CaseExecution<'_>,
    size: FrameSize,
    batch_size: usize,
    case: Case,
) -> Result<ResultRow, RunError> {
    let config = execution.config;
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings)
        .expect("benchmark snapshot");
    let (udp_config, tcp_config) = nat_configs(&snapshot);
    let mut resolution_states: [ResolutionStateSlot; RESOLUTION_STATE_CAPACITY] = [];
    let mut resolution_actions: [ResolutionActionSlot; RESOLUTION_ACTION_CAPACITY] = [];
    let mut resolution = resolution(&mut resolution_states, &mut resolution_actions);
    let template = timed_fixture(size, config.seed, case, true);
    let mut backend = BenchBackend::new(batch_size, case.direction.ingress(), &template);

    match case.transport {
        Transport::UdpZero | Transport::UdpChecksum => {
            let mut mappings = [Nat44UdpMappingSlot::default(); NAT_MAPPING_CAPACITY];
            let mut peers = [Nat44UdpPeerSlot::default(); NAT_PEER_CAPACITY];
            let mut indexes = UdpBenchIndexes::default();
            let mut runtime = indexes.runtime(udp_config, &mut mappings, &mut peers);
            if !runtime.publication_binding_matches(udp_config, r17_nat_udp_hash_key()) {
                return Err(RunError::ForwardingOracle);
            }
            establish_udp(
                case,
                |batch| {
                    forward_batch_with_nat44_udp(
                        batch,
                        &snapshot,
                        &mut resolution,
                        &udp_config,
                        Some(&mut runtime),
                        R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
                        &mut NoTrace,
                    )
                },
                config.seed,
            )?;
            let row = {
                let mut forward = |batch: BenchBatch<'_>| {
                    forward_batch_with_nat44_udp(
                        batch,
                        &snapshot,
                        &mut resolution,
                        &udp_config,
                        Some(&mut runtime),
                        R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
                        &mut NoTrace,
                    )
                };
                execute_case(
                    execution,
                    size,
                    batch_size,
                    case,
                    &template,
                    &mut backend,
                    &mut forward,
                )?
            };
            if runtime
                .mappings()
                .iter()
                .filter(|slot| slot.is_occupied())
                .count()
                != 1
                || runtime
                    .peers()
                    .iter()
                    .filter(|slot| slot.is_occupied())
                    .count()
                    != 1
                || runtime.counters().mappings_created != 1
                || runtime.counters().peers_created != 1
            {
                return Err(RunError::ForwardingOracle);
            }
            verify_case(&backend, &template, batch_size, case, true)?;
            Ok(row)
        }
        Transport::Tcp => {
            let mut mappings = [Nat44TcpMappingSlot::default(); NAT_MAPPING_CAPACITY];
            let mut sessions = [Nat44TcpSessionSlot::default(); NAT_SESSION_CAPACITY];
            let mut indexes = TcpBenchIndexes::default();
            let mut runtime = indexes.runtime(tcp_config, &mut mappings, &mut sessions);
            if !runtime.publication_binding_matches(tcp_config, r17_nat_tcp_hash_key()) {
                return Err(RunError::ForwardingOracle);
            }
            establish_tcp(
                case,
                |batch| {
                    forward_batch_with_nat44_tcp(
                        batch,
                        &snapshot,
                        &mut resolution,
                        &tcp_config,
                        Some(&mut runtime),
                        R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
                        &mut NoTrace,
                    )
                },
                config.seed,
            )?;
            let row = {
                let mut forward = |batch: BenchBatch<'_>| {
                    forward_batch_with_nat44_tcp(
                        batch,
                        &snapshot,
                        &mut resolution,
                        &tcp_config,
                        Some(&mut runtime),
                        R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
                        &mut NoTrace,
                    )
                };
                execute_case(
                    execution,
                    size,
                    batch_size,
                    case,
                    &template,
                    &mut backend,
                    &mut forward,
                )?
            };
            if runtime
                .mappings()
                .iter()
                .filter(|slot| slot.is_occupied())
                .count()
                != 1
                || runtime
                    .sessions()
                    .iter()
                    .filter(|slot| slot.is_occupied())
                    .count()
                    != 1
                || runtime.counters().mappings_created != 1
                || runtime.counters().sessions_created != 1
            {
                return Err(RunError::ForwardingOracle);
            }
            verify_case(&backend, &template, batch_size, case, true)?;
            Ok(row)
        }
    }
}

fn run_firewall_case(
    execution: CaseExecution<'_>,
    size: FrameSize,
    batch_size: usize,
    case: Case,
) -> Result<ResultRow, RunError> {
    let config = execution.config;
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings)
        .expect("benchmark snapshot");
    let rules = firewall_rules();
    let firewall_config = firewall_config(&snapshot, &rules);
    if firewall_config.hash_key() != r17_firewall_hash_key() {
        return Err(RunError::ForwardingOracle);
    }
    let mut firewall_states = [FirewallStateSlot::default(); FIREWALL_STATE_CAPACITY];
    let mut firewall = FirewallRuntime::new(firewall_config, &mut firewall_states);
    let mut resolution_states: [ResolutionStateSlot; RESOLUTION_STATE_CAPACITY] = [];
    let mut resolution_actions: [ResolutionActionSlot; RESOLUTION_ACTION_CAPACITY] = [];
    let mut resolution = resolution(&mut resolution_states, &mut resolution_actions);
    let template = timed_fixture(size, config.seed, case, false);
    let mut backend = BenchBackend::new(batch_size, case.direction.ingress(), &template);

    if case.transport == Transport::Tcp {
        establish_tcp(
            case,
            |batch| {
                forward_batch_with_firewall(
                    batch,
                    &snapshot,
                    &mut resolution,
                    &firewall_config,
                    Some(&mut firewall),
                    R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
                    &mut NoTrace,
                )
            },
            config.seed,
        )?;
    } else {
        establish_udp(
            case,
            |batch| {
                forward_batch_with_firewall(
                    batch,
                    &snapshot,
                    &mut resolution,
                    &firewall_config,
                    Some(&mut firewall),
                    R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
                    &mut NoTrace,
                )
            },
            config.seed,
        )?;
    }
    let row = {
        let mut forward = |batch: BenchBatch<'_>| {
            forward_batch_with_firewall(
                batch,
                &snapshot,
                &mut resolution,
                &firewall_config,
                Some(&mut firewall),
                R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
                &mut NoTrace,
            )
        };
        execute_case(
            execution,
            size,
            batch_size,
            case,
            &template,
            &mut backend,
            &mut forward,
        )?
    };
    let occupied = firewall
        .states()
        .iter()
        .filter(|slot| slot.is_occupied())
        .count();
    if occupied != 1
        || firewall
            .states()
            .iter()
            .find(|slot| slot.is_occupied())
            .map(|slot| slot.protocol())
            != Some(case.transport.firewall_protocol())
        || firewall.counters().allowed_new != 1
    {
        return Err(RunError::ForwardingOracle);
    }
    verify_case(&backend, &template, batch_size, case, false)?;
    Ok(row)
}

fn run_combined_case(
    execution: CaseExecution<'_>,
    size: FrameSize,
    batch_size: usize,
    case: Case,
) -> Result<ResultRow, RunError> {
    let config = execution.config;
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings)
        .expect("benchmark snapshot");
    let (udp_config, tcp_config) = nat_configs(&snapshot);
    let rules = firewall_rules();
    let firewall_config = firewall_config(&snapshot, &rules);
    if firewall_config.hash_key() != r17_firewall_hash_key() {
        return Err(RunError::ForwardingOracle);
    }
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); NAT_MAPPING_CAPACITY];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); NAT_PEER_CAPACITY];
    let mut udp_indexes = UdpBenchIndexes::default();
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); NAT_MAPPING_CAPACITY];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); NAT_SESSION_CAPACITY];
    let mut tcp_indexes = TcpBenchIndexes::default();
    let mut firewall_states = [FirewallStateSlot::default(); FIREWALL_STATE_CAPACITY];
    let mut udp = udp_indexes.runtime(udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp = tcp_indexes.runtime(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    if !udp.publication_binding_matches(udp_config, r17_nat_udp_hash_key())
        || !tcp.publication_binding_matches(tcp_config, r17_nat_tcp_hash_key())
    {
        return Err(RunError::ForwardingOracle);
    }
    let mut firewall = FirewallRuntime::new(firewall_config, &mut firewall_states);
    let mut resolution_states: [ResolutionStateSlot; RESOLUTION_STATE_CAPACITY] = [];
    let mut resolution_actions: [ResolutionActionSlot; RESOLUTION_ACTION_CAPACITY] = [];
    let mut resolution = resolution(&mut resolution_states, &mut resolution_actions);
    let template = timed_fixture(size, config.seed, case, true);
    let mut backend = BenchBackend::new(batch_size, case.direction.ingress(), &template);

    if case.transport == Transport::Tcp {
        establish_tcp(
            case,
            |batch| {
                forward_batch_with_nat44_udp_and_tcp_and_firewall(
                    batch,
                    &snapshot,
                    &mut resolution,
                    &udp_config,
                    Some(&mut udp),
                    &tcp_config,
                    Some(&mut tcp),
                    &firewall_config,
                    Some(&mut firewall),
                    R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
                    &mut NoTrace,
                )
            },
            config.seed,
        )?;
    } else {
        establish_udp(
            case,
            |batch| {
                forward_batch_with_nat44_udp_and_tcp_and_firewall(
                    batch,
                    &snapshot,
                    &mut resolution,
                    &udp_config,
                    Some(&mut udp),
                    &tcp_config,
                    Some(&mut tcp),
                    &firewall_config,
                    Some(&mut firewall),
                    R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
                    &mut NoTrace,
                )
            },
            config.seed,
        )?;
    }
    let row = {
        let mut forward = |batch: BenchBatch<'_>| {
            forward_batch_with_nat44_udp_and_tcp_and_firewall(
                batch,
                &snapshot,
                &mut resolution,
                &udp_config,
                Some(&mut udp),
                &tcp_config,
                Some(&mut tcp),
                &firewall_config,
                Some(&mut firewall),
                R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
                &mut NoTrace,
            )
        };
        execute_case(
            execution,
            size,
            batch_size,
            case,
            &template,
            &mut backend,
            &mut forward,
        )?
    };
    let nat_state_ok = match case.transport {
        Transport::UdpZero | Transport::UdpChecksum => {
            udp.mappings()
                .iter()
                .filter(|slot| slot.is_occupied())
                .count()
                == 1
                && udp.peers().iter().filter(|slot| slot.is_occupied()).count() == 1
                && tcp.mappings().iter().all(|slot| !slot.is_occupied())
                && tcp.sessions().iter().all(|slot| !slot.is_occupied())
        }
        Transport::Tcp => {
            tcp.mappings()
                .iter()
                .filter(|slot| slot.is_occupied())
                .count()
                == 1
                && tcp
                    .sessions()
                    .iter()
                    .filter(|slot| slot.is_occupied())
                    .count()
                    == 1
                && udp.mappings().iter().all(|slot| !slot.is_occupied())
                && udp.peers().iter().all(|slot| !slot.is_occupied())
        }
    };
    if !nat_state_ok
        || firewall
            .states()
            .iter()
            .filter(|slot| slot.is_occupied())
            .count()
            != 1
        || firewall.counters().allowed_new != 1
        || (matches!(case.transport, Transport::UdpZero | Transport::UdpChecksum)
            && (udp.counters().mappings_created != 1 || udp.counters().peers_created != 1))
        || (case.transport == Transport::Tcp
            && (tcp.counters().mappings_created != 1 || tcp.counters().sessions_created != 1))
    {
        return Err(RunError::ForwardingOracle);
    }
    verify_case(&backend, &template, batch_size, case, true)?;
    Ok(row)
}

fn establish_udp<F>(case: Case, mut forward: F, seed: u64) -> Result<(), RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    let step = R17_WORKLOAD_DESCRIPTOR
        .setup
        .steps
        .into_iter()
        .find(|step| step.transport == R17SetupTransport::Udp)
        .expect("benchmark setup descriptor has one UDP step");
    let fixture = setup_fixture(case, seed, step);
    forward_setup(&fixture, setup_ingress(step), &mut forward)?;
    record_r17_setup(case, step, &fixture);
    Ok(())
}

fn establish_tcp<F>(case: Case, mut forward: F, seed: u64) -> Result<(), RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    let nat = case.profile == Profile::Nat || case.profile == Profile::Combined;
    for step in R17_WORKLOAD_DESCRIPTOR.setup.steps {
        if step.transport != R17SetupTransport::Tcp {
            continue;
        }
        let fixture = tcp_fixture(
            R17_WORKLOAD_DESCRIPTOR.frame.deterministic_size,
            setup_seed(seed, step.seed),
            setup_direction(step),
            step.tcp_flags,
            nat,
        );
        forward_setup(&fixture, setup_ingress(step), &mut forward)?;
        record_r17_setup(case, step, &fixture);
    }
    Ok(())
}

fn setup_seed(seed: u64, transform: crate::deterministic::R17SeedTransform) -> u64 {
    match transform {
        crate::deterministic::R17SeedTransform::Base => seed,
        crate::deterministic::R17SeedTransform::Xor(value) => seed ^ value,
    }
}

fn setup_direction(step: crate::deterministic::R17SetupStep) -> Direction {
    match step.direction {
        crate::deterministic::R17SetupDirection::Outbound => Direction::Outbound,
        crate::deterministic::R17SetupDirection::Inbound => Direction::Inbound,
    }
}

fn setup_ingress(step: crate::deterministic::R17SetupStep) -> IfId {
    setup_direction(step).ingress()
}

fn setup_fixture(case: Case, seed: u64, step: crate::deterministic::R17SetupStep) -> Vec<u8> {
    match step.transport {
        crate::deterministic::R17SetupTransport::Udp => packet_fixture(
            R17_WORKLOAD_DESCRIPTOR.frame.deterministic_size,
            setup_seed(seed, step.seed),
            case.transport,
            setup_direction(step),
            false,
            matches!(case.profile, Profile::Nat | Profile::Combined),
        ),
        crate::deterministic::R17SetupTransport::Tcp => tcp_fixture(
            R17_WORKLOAD_DESCRIPTOR.frame.deterministic_size,
            setup_seed(seed, step.seed),
            setup_direction(step),
            step.tcp_flags,
            matches!(case.profile, Profile::Nat | Profile::Combined),
        ),
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct R17SetupKnownAnswer {
    output_count: usize,
    output_bytes: usize,
    output_digest: u64,
    event_order_digest: u64,
    semantic_markers_digest: u64,
}

#[cfg(test)]
const R17_SETUP_KNOWN_ANSWER: R17SetupKnownAnswer = R17SetupKnownAnswer {
    output_count: 30,
    output_bytes: 1_800,
    output_digest: 0x68e9_f945_eb0b_4571,
    event_order_digest: 0xae89_2a47_c58c_c77a,
    semantic_markers_digest: 0x48fc_c51e_d225_4b9c,
};

#[cfg(test)]
fn r17_setup_known_answer() -> R17SetupKnownAnswer {
    R17_SETUP_KNOWN_ANSWER
}

#[cfg(test)]
#[derive(Debug)]
struct R17SetupObservation {
    answer: R17SetupKnownAnswer,
}

#[cfg(test)]
impl R17SetupObservation {
    fn new() -> Self {
        Self {
            answer: R17SetupKnownAnswer {
                output_count: 0,
                output_bytes: 0,
                output_digest: fingerprint_bytes(
                    0xcbf2_9ce4_8422_2325,
                    b"ruster.r17.setup-output/v1\n",
                ),
                event_order_digest: fingerprint_bytes(
                    0xcbf2_9ce4_8422_2325,
                    b"ruster.r17.setup-order/v1\n",
                ),
                semantic_markers_digest: fingerprint_bytes(
                    0xcbf2_9ce4_8422_2325,
                    b"ruster.r17.setup-markers/v1\n",
                ),
            },
        }
    }

    fn record(&mut self, case: Case, step: crate::deterministic::R17SetupStep, fixture: &[u8]) {
        let case_ordinal = R17_DETERMINISTIC_SMOKE_CASES
            .into_iter()
            .position(|label| label == case.label())
            .expect("benchmark setup case is in the canonical matrix");
        let step_ordinal = R17_WORKLOAD_DESCRIPTOR
            .setup
            .steps
            .into_iter()
            .position(|candidate| candidate == step)
            .expect("benchmark setup step is in the canonical sequence");
        let fixture_digest =
            fingerprint_fixture(0xcbf2_9ce4_8422_2325, step.label.as_bytes(), fixture);

        self.answer.output_count += 1;
        self.answer.output_bytes += fixture.len();
        self.answer.output_digest = fingerprint_u64(self.answer.output_digest, case_ordinal as u64);
        self.answer.output_digest = fingerprint_u64(self.answer.output_digest, step_ordinal as u64);
        self.answer.output_digest =
            fingerprint_u64(self.answer.output_digest, fixture.len() as u64);
        self.answer.output_digest = fingerprint_u64(self.answer.output_digest, fixture_digest);

        self.answer.event_order_digest =
            fingerprint_u64(self.answer.event_order_digest, case_ordinal as u64);
        self.answer.event_order_digest =
            fingerprint_u64(self.answer.event_order_digest, step_ordinal as u64);
        self.answer.event_order_digest =
            fingerprint_bytes(self.answer.event_order_digest, step.label.as_bytes());

        self.answer.semantic_markers_digest =
            fingerprint_u64(self.answer.semantic_markers_digest, case_ordinal as u64);
        self.answer.semantic_markers_digest = fingerprint_u8(
            self.answer.semantic_markers_digest,
            case.transport.protocol(),
        );
        self.answer.semantic_markers_digest = fingerprint_u8(
            self.answer.semantic_markers_digest,
            match case.direction {
                Direction::Outbound => 0,
                Direction::Inbound => 1,
            },
        );
        self.answer.semantic_markers_digest = fingerprint_u8(
            self.answer.semantic_markers_digest,
            u8::from(case.transport.checksum_enabled()),
        );
        self.answer.semantic_markers_digest =
            fingerprint_u8(self.answer.semantic_markers_digest, step.tcp_flags);
        self.answer.semantic_markers_digest =
            fingerprint_u8(self.answer.semantic_markers_digest, fixture[14]);
        self.answer.semantic_markers_digest =
            fingerprint_u8(self.answer.semantic_markers_digest, fixture[22]);
    }

    fn finish(self) -> R17SetupKnownAnswer {
        self.answer
    }
}

#[cfg(test)]
thread_local! {
    static R17_SETUP_OBSERVER: RefCell<Option<R17SetupObservation>> = const { RefCell::new(None) };
}

#[cfg(test)]
fn with_r17_setup_observer<F>(run: F) -> Result<(Vec<ResultRow>, R17SetupKnownAnswer), RunError>
where
    F: FnOnce() -> Result<Vec<ResultRow>, RunError>,
{
    R17_SETUP_OBSERVER.with(|slot| {
        assert!(slot.replace(Some(R17SetupObservation::new())).is_none());
        let result = run();
        let observation = slot
            .replace(None)
            .expect("R17 setup observer was installed");
        result.map(|rows| (rows, observation.finish()))
    })
}

#[cfg(test)]
fn record_r17_setup(case: Case, step: crate::deterministic::R17SetupStep, fixture: &[u8]) {
    R17_SETUP_OBSERVER.with(|slot| {
        if let Some(observer) = slot.borrow_mut().as_mut() {
            observer.record(case, step, fixture);
        }
    });
}

#[cfg(not(test))]
#[inline(always)]
fn record_r17_setup(_case: Case, _step: crate::deterministic::R17SetupStep, _fixture: &[u8]) {}

fn forward_setup<F>(fixture: &[u8], ingress: IfId, forward: &mut F) -> Result<(), RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    let mut backend = BenchBackend::new(1, ingress, fixture);
    let batch = backend.receive(1).expect("infallible backend");
    let report = forward(batch);
    verify_report(&report, 1)?;
    if backend.completion(0).is_none() {
        return Err(RunError::ForwardingOracle);
    }
    Ok(())
}

fn execute_case<F>(
    execution: CaseExecution<'_>,
    size: FrameSize,
    batch_size: usize,
    case: Case,
    template: &[u8],
    backend: &mut BenchBackend,
    forward: &mut F,
) -> Result<ResultRow, RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    match execution.measurement_mode {
        MeasurementMode::Timed => measure_case(
            execution.config,
            size,
            batch_size,
            case,
            template,
            backend,
            forward,
        ),
        MeasurementMode::DeterministicOnePass => deterministic_one_pass(
            execution.config,
            size,
            batch_size,
            case,
            template,
            backend,
            forward,
        ),
    }
}

fn deterministic_one_pass<F>(
    config: &RunConfig,
    size: FrameSize,
    batch_size: usize,
    case: Case,
    template: &[u8],
    backend: &mut BenchBackend,
    forward: &mut F,
) -> Result<ResultRow, RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    let before_allocations = allocation_count();
    backend.reset(template);
    let batch = backend.receive(batch_size).expect("infallible backend");
    let report = black_box(forward(batch));
    let allocations = allocation_count() - before_allocations;
    ensure_no_allocations(case.label(), allocations)?;
    verify_report(&report, batch_size)?;
    Ok(ResultRow {
        case: case.label(),
        size,
        batch: batch_size,
        checksum_passes: case.checksum_passes(),
        seed: config.seed,
        repetitions_per_sample: 1,
        timed_allocations: allocations,
        stats: SampleStats {
            samples: 1,
            min_ns: 1.0,
            p50_ns: 1.0,
            p95_ns: 1.0,
            mad_ns: 0.0,
        },
        digest: u16::try_from(report.tx_requested).unwrap_or(u16::MAX),
    })
}

fn measure_case<F>(
    config: &RunConfig,
    size: FrameSize,
    batch_size: usize,
    case: Case,
    template: &[u8],
    backend: &mut BenchBackend,
    forward: &mut F,
) -> Result<ResultRow, RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    warm_case(
        case.label(),
        backend,
        template,
        batch_size,
        config.warmup_time,
        forward,
    )?;
    let repetitions = calibrate_case(
        case.label(),
        backend,
        template,
        batch_size,
        config.sample_time,
        forward,
    )?;
    let mut normalized = Vec::with_capacity(config.samples);
    let mut allocations = 0_u64;
    let mut digest = 0_u16;
    for _ in 0..config.samples {
        let measurement = measure_forward(backend, template, batch_size, repetitions, forward)?;
        allocations += measurement.allocations;
        digest = measurement.digest;
        let packets = repetitions
            .checked_mul(batch_size)
            .ok_or(RunError::RepetitionOverflow)?;
        normalized.push(measurement.elapsed.as_nanos() as f64 / packets as f64);
    }
    ensure_no_allocations(case.label(), allocations)?;
    Ok(ResultRow {
        case: case.label(),
        size,
        batch: batch_size,
        checksum_passes: case.checksum_passes(),
        seed: config.seed,
        repetitions_per_sample: repetitions,
        timed_allocations: allocations,
        stats: SampleStats::from_samples(&normalized).ok_or(RunError::InvalidStatistics)?,
        digest,
    })
}

fn warm_case<F>(
    label: &'static str,
    backend: &mut BenchBackend,
    template: &[u8],
    batch_size: usize,
    warmup: Duration,
    forward: &mut F,
) -> Result<(), RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    let started = Instant::now();
    while started.elapsed() < warmup {
        match measure_forward(
            backend,
            template,
            batch_size,
            MIN_AGGREGATE_REPETITIONS,
            forward,
        ) {
            Ok(measurement) => {
                ensure_no_allocations(label, measurement.allocations)?;
                black_box(measurement);
            }
            Err(RunError::SetupControlExceededMeasured { .. }) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn calibrate_case<F>(
    label: &'static str,
    backend: &mut BenchBackend,
    template: &[u8],
    batch_size: usize,
    target: Duration,
    forward: &mut F,
) -> Result<usize, RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    let mut repetitions = MIN_AGGREGATE_REPETITIONS;
    loop {
        let measurement = match measure_forward(backend, template, batch_size, repetitions, forward)
        {
            Ok(measurement) => measurement,
            Err(RunError::SetupControlExceededMeasured { .. }) => {
                repetitions = repetitions
                    .checked_mul(2)
                    .ok_or(RunError::RepetitionOverflow)?;
                continue;
            }
            Err(error) => return Err(error),
        };
        ensure_no_allocations(label, measurement.allocations)?;
        if measurement.elapsed >= target {
            return Ok(repetitions);
        }
        repetitions = repetitions
            .checked_mul(2)
            .ok_or(RunError::RepetitionOverflow)?;
    }
}

fn measure_forward<F>(
    backend: &mut BenchBackend,
    template: &[u8],
    batch_size: usize,
    repetitions: usize,
    forward: &mut F,
) -> Result<Measurement, RunError>
where
    F: for<'a> FnMut(BenchBatch<'a>) -> BatchReport<Infallible>,
{
    let setup_started = Instant::now();
    for _ in 0..repetitions {
        backend.reset(template);
        let batch = backend.receive(batch_size).expect("infallible backend");
        let _ = black_box(batch);
    }
    let setup_elapsed = setup_started.elapsed();

    let before_allocations = allocation_count();
    let measured_started = Instant::now();
    let mut last_report = None;
    for _ in 0..repetitions {
        backend.reset(template);
        let batch = backend.receive(batch_size).expect("infallible backend");
        last_report = Some(black_box(forward(batch)));
    }
    let measured_elapsed = measured_started.elapsed();
    let allocations = allocation_count() - before_allocations;
    let report = black_box(last_report).expect("repetitions are nonzero");
    verify_report(&report, batch_size)?;
    Ok(Measurement {
        elapsed: subtract_setup_control(setup_elapsed, measured_elapsed)?,
        allocations,
        digest: u16::try_from(report.tx_requested).unwrap_or(u16::MAX),
    })
}

fn verify_report(report: &BatchReport<Infallible>, batch_size: usize) -> Result<(), RunError> {
    if report.received != batch_size
        || report.tx_requested != batch_size
        || report.dropped != 0
        || report.consumed != 0
        || report.completion.tx_requested != batch_size
        || report.completion.tx_accepted != batch_size
        || report.completion.tx_rejected != 0
        || report.completion.recycled != 0
        || report.completion.error.is_some()
    {
        Err(RunError::UnexpectedBatchReport)
    } else {
        Ok(())
    }
}

fn timed_fixture(size: FrameSize, seed: u64, case: Case, nat: bool) -> Vec<u8> {
    packet_fixture(size, seed, case.transport, case.direction, false, nat)
}

fn packet_fixture(
    size: FrameSize,
    seed: u64,
    transport: Transport,
    direction: Direction,
    tcp_syn: bool,
    nat: bool,
) -> Vec<u8> {
    match transport {
        Transport::Tcp => tcp_fixture(
            size,
            seed,
            direction,
            if tcp_syn {
                R17_WORKLOAD_DESCRIPTOR
                    .setup
                    .steps
                    .into_iter()
                    .find(|step| step.transport == R17SetupTransport::Tcp)
                    .expect("benchmark setup descriptor has a TCP step")
                    .tcp_flags
            } else {
                R17_WORKLOAD_DESCRIPTOR
                    .setup
                    .steps
                    .into_iter()
                    .rfind(|step| step.transport == R17SetupTransport::Tcp)
                    .expect("benchmark setup descriptor has a TCP step")
                    .tcp_flags
            },
            nat,
        ),
        Transport::UdpZero | Transport::UdpChecksum => {
            udp_fixture(size, seed, direction, transport.checksum_enabled(), nat)
        }
    }
}

fn endpoints(direction: Direction, nat: bool) -> (Ipv4Address, Ipv4Address, u16, u16) {
    match direction {
        Direction::Outbound => (HOST, REMOTE, HOST_PORT, REMOTE_PORT),
        Direction::Inbound => (
            REMOTE,
            if nat { PUBLIC } else { HOST },
            REMOTE_PORT,
            HOST_PORT,
        ),
    }
}

fn ethernet(direction: Direction) -> (MacAddress, MacAddress) {
    match direction {
        Direction::Outbound => (LAN_MAC, HOST_MAC),
        Direction::Inbound => (WAN_MAC, GATEWAY_MAC),
    }
}

fn base_frame(size: FrameSize, seed: u64, direction: Direction, protocol: u8) -> Vec<u8> {
    let mut frame = vec![0_u8; size.backend_bytes()];
    let (destination_mac, source_mac) = ethernet(direction);
    frame[0..6].copy_from_slice(&destination_mac.0);
    frame[6..12].copy_from_slice(&source_mac.0);
    frame[12..14].copy_from_slice(&R17_WORKLOAD_DESCRIPTOR.frame.ethertype.to_be_bytes());
    frame[14] = R17_WORKLOAD_DESCRIPTOR.frame.ipv4_version_ihl;
    frame[16..18].copy_from_slice(
        &u16::try_from(size.ipv4_total_bytes())
            .expect("benchmark frame length")
            .to_be_bytes(),
    );
    frame[18..20].copy_from_slice(&(seed as u16).to_be_bytes());
    frame[20..22].copy_from_slice(&R17_WORKLOAD_DESCRIPTOR.frame.ipv4_flags.to_be_bytes());
    frame[22] = R17_WORKLOAD_DESCRIPTOR.frame.ttl;
    frame[23] = protocol;
    frame
}

fn udp_fixture(
    size: FrameSize,
    seed: u64,
    direction: Direction,
    checksum: bool,
    nat: bool,
) -> Vec<u8> {
    let (source, destination, source_port, destination_port) = endpoints(direction, nat);
    udp_fixture_with_endpoints(
        size,
        seed,
        direction,
        checksum,
        (source, destination, source_port, destination_port),
    )
}

fn udp_fixture_with_endpoints(
    size: FrameSize,
    seed: u64,
    direction: Direction,
    checksum: bool,
    endpoints: (Ipv4Address, Ipv4Address, u16, u16),
) -> Vec<u8> {
    let (source, destination, source_port, destination_port) = endpoints;
    let mut frame = base_frame(size, seed, direction, 17);
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    let udp_len = size.ipv4_total_bytes() - 20;
    frame[38..40].copy_from_slice(
        &u16::try_from(udp_len)
            .expect("benchmark UDP length")
            .to_be_bytes(),
    );
    fill_payload(&mut frame[42..], seed);
    if checksum {
        let value = transport_checksum(source, destination, 17, &frame[34..]);
        frame[40..42].copy_from_slice(&value.to_be_bytes());
    }
    finish_ipv4_checksum(&mut frame);
    frame
}

fn tcp_fixture(size: FrameSize, seed: u64, direction: Direction, flags: u8, nat: bool) -> Vec<u8> {
    let (source, destination, source_port, destination_port) = endpoints(direction, nat);
    tcp_fixture_with_endpoints(
        size,
        seed,
        direction,
        flags,
        (source, destination, source_port, destination_port),
    )
}

fn tcp_fixture_with_endpoints(
    size: FrameSize,
    seed: u64,
    direction: Direction,
    flags: u8,
    endpoints: (Ipv4Address, Ipv4Address, u16, u16),
) -> Vec<u8> {
    let (source, destination, source_port, destination_port) = endpoints;
    let mut frame = base_frame(size, seed, direction, 6);
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    frame[38..42].copy_from_slice(&R17_WORKLOAD_DESCRIPTOR.frame.tcp_sequence.to_be_bytes());
    frame[42..46].copy_from_slice(
        &R17_WORKLOAD_DESCRIPTOR
            .frame
            .tcp_acknowledgement
            .to_be_bytes(),
    );
    frame[46] = 5 << 4;
    frame[47] = flags;
    frame[48..50].copy_from_slice(&R17_WORKLOAD_DESCRIPTOR.frame.tcp_window.to_be_bytes());
    fill_payload(&mut frame[54..], seed);
    let value = transport_checksum(source, destination, 6, &frame[34..]);
    frame[50..52].copy_from_slice(&value.to_be_bytes());
    finish_ipv4_checksum(&mut frame);
    frame
}

fn fill_payload(payload: &mut [u8], seed: u64) {
    let mut state = seed.max(1);
    for byte in payload {
        state ^= state << R17_WORKLOAD_DESCRIPTOR.frame.payload_xorshift[0];
        state ^= state >> R17_WORKLOAD_DESCRIPTOR.frame.payload_xorshift[1];
        state ^= state << R17_WORKLOAD_DESCRIPTOR.frame.payload_xorshift[2];
        *byte = state as u8;
    }
}

fn finish_ipv4_checksum(frame: &mut [u8]) {
    frame[24..26].fill(0);
    let value = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&value.to_be_bytes());
}

fn transport_checksum(
    source: Ipv4Address,
    destination: Ipv4Address,
    protocol: u8,
    segment: &[u8],
) -> u16 {
    fn add(sum: &mut u32, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            *sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let Some(&last) = chunks.remainder().first() {
            *sum += u32::from(last) << 8;
        }
    }

    let mut sum = 0_u32;
    add(&mut sum, &source.octets());
    add(&mut sum, &destination.octets());
    sum += u32::from(protocol);
    sum += u32::from(u16::try_from(segment.len()).expect("benchmark transport length"));
    add(&mut sum, segment);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let value = !(sum as u16);
    if protocol == 17 && value == 0 {
        0xffff
    } else {
        value
    }
}

fn transport_checksum_valid(
    source: Ipv4Address,
    destination: Ipv4Address,
    protocol: u8,
    segment: &[u8],
) -> bool {
    fn sum_words(bytes: &[u8]) -> u64 {
        let pairs = bytes
            .chunks_exact(2)
            .map(|pair| u64::from(u16::from_be_bytes([pair[0], pair[1]])))
            .sum::<u64>();
        pairs
            + bytes
                .chunks_exact(2)
                .remainder()
                .first()
                .map_or(0, |byte| u64::from(*byte) << 8)
    }

    let pseudo = sum_words(&source.octets())
        + sum_words(&destination.octets())
        + u64::from(protocol)
        + u64::try_from(segment.len()).expect("benchmark transport length")
        + sum_words(segment);
    let mut folded = pseudo;
    while folded >> 16 != 0 {
        folded = (folded & 0xffff) + (folded >> 16);
    }
    folded == 0xffff
}

fn verify_case(
    backend: &BenchBackend,
    template: &[u8],
    batch_size: usize,
    case: Case,
    nat: bool,
) -> Result<(), RunError> {
    let (source, destination, source_port, destination_port) = match (case.direction, nat) {
        (Direction::Outbound, true) => (PUBLIC, REMOTE, HOST_PORT, REMOTE_PORT),
        (Direction::Inbound, true) => (REMOTE, HOST, REMOTE_PORT, HOST_PORT),
        (Direction::Outbound, false) => (HOST, REMOTE, HOST_PORT, REMOTE_PORT),
        (Direction::Inbound, false) => (REMOTE, HOST, REMOTE_PORT, HOST_PORT),
    };
    let (destination_mac, source_mac) = match case.direction {
        Direction::Outbound => (GATEWAY_MAC, WAN_MAC),
        Direction::Inbound => (HOST_MAC, LAN_MAC),
    };
    let mut expected = template.to_vec();
    expected[0..6].copy_from_slice(&destination_mac.0);
    expected[6..12].copy_from_slice(&source_mac.0);
    expected[22] = 63;
    expected[26..30].copy_from_slice(&source.octets());
    expected[30..34].copy_from_slice(&destination.octets());
    expected[34..36].copy_from_slice(&source_port.to_be_bytes());
    expected[36..38].copy_from_slice(&destination_port.to_be_bytes());
    if case.transport.checksum_enabled() {
        let checksum_offset = if case.transport == Transport::Tcp {
            50
        } else {
            40
        };
        expected[checksum_offset..checksum_offset + 2].fill(0);
        let value = transport_checksum(
            source,
            destination,
            case.transport.protocol(),
            &expected[34..],
        );
        expected[checksum_offset..checksum_offset + 2].copy_from_slice(&value.to_be_bytes());
    }
    finish_ipv4_checksum(&mut expected);
    for index in 0..batch_size {
        if backend.completion(index) != Some(BenchCompletion::Transmitted(case.direction.egress()))
        {
            return Err(RunError::ForwardingOracle);
        }
        let bytes = backend.bytes(index).ok_or(RunError::ForwardingOracle)?;
        let ipv4 = validate_ipv4_frame(bytes).map_err(|_| RunError::ForwardingOracle)?;
        let actual_source_port = u16::from_be_bytes([bytes[34], bytes[35]]);
        let actual_destination_port = u16::from_be_bytes([bytes[36], bytes[37]]);
        if bytes[0..6] != destination_mac.0
            || bytes[6..12] != source_mac.0
            || ipv4.ttl != 63
            || ipv4.protocol != case.transport.protocol()
            || ipv4.source != source
            || ipv4.destination != destination
            || actual_source_port != source_port
            || actual_destination_port != destination_port
            || bytes != expected
        {
            return Err(RunError::ForwardingOracle);
        }
        let segment = &bytes[34..14 + ipv4.total_len];
        match case.transport {
            Transport::UdpZero if bytes[40..42] != [0, 0] => {
                return Err(RunError::ForwardingOracle);
            }
            Transport::UdpChecksum | Transport::Tcp
                if !transport_checksum_valid(source, destination, ipv4.protocol, segment) =>
            {
                return Err(RunError::ForwardingOracle);
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These are test-side fixed answers. They intentionally do not come from
    // the descriptor serializer, artifact writer, or the live fingerprint.
    const F07_ACTUAL_CONSTRUCTOR_KNOWN_ANSWER: R17HashConstructorProbe = R17HashConstructorProbe {
        nat_udp_mapping_peer: 0x74c7_bdf3_9f77_9845,
        nat_tcp_mapping_session: 0xce7d_6c21_d546_4308,
        firewall_stateful_flow: 0xa2b0_0754_0a6f_f5cd,
    };
    const F07_ACTUAL_CONSTRUCTOR_DIGEST_KNOWN_ANSWER: u64 = 0x8ee0_09f1_015a_ef75;

    #[test]
    fn transport_fixtures_cover_sizes_directions_and_checksum_modes() {
        for size in FrameSize::ALL {
            for transport in [Transport::UdpZero, Transport::UdpChecksum, Transport::Tcp] {
                for direction in [Direction::Outbound, Direction::Inbound] {
                    let frame = packet_fixture(size, 7, transport, direction, false, true);
                    let ipv4 = validate_ipv4_frame(&frame).unwrap();
                    assert_eq!(frame.len(), size.backend_bytes());
                    assert_eq!(ipv4.total_len, size.ipv4_total_bytes());
                    let segment = &frame[34..14 + ipv4.total_len];
                    if transport == Transport::UdpZero {
                        assert_eq!(&frame[40..42], &[0, 0]);
                    } else {
                        assert!(transport_checksum_valid(
                            ipv4.source,
                            ipv4.destination,
                            ipv4.protocol,
                            segment
                        ));
                    }
                }
            }
        }
    }

    #[test]
    fn short_matrix_identifies_every_case_without_wall_clock_measurement() {
        let config = RunConfig::smoke();
        let execution = CaseExecution::deterministic_one_pass(&config);
        let mut labels = Vec::with_capacity(MATRIX_CASE_COUNT);
        for case in matrix_cases() {
            let result = match case.profile {
                Profile::Plain => run_plain_control(execution, FrameSize::Wire64, 1, case),
                Profile::Nat => run_nat_case(execution, FrameSize::Wire64, 1, case),
                Profile::Firewall => run_firewall_case(execution, FrameSize::Wire64, 1, case),
                Profile::Combined => run_combined_case(execution, FrameSize::Wire64, 1, case),
            }
            .unwrap_or_else(|error| panic!("{}: {error:?}", case.label()));
            assert_eq!(result.case, case.label());
            labels.push(result.case);
        }
        assert_eq!(
            labels,
            [
                "ctl-udp0-out",
                "nat-udp0-out-est",
                "fw-udp0-out-est",
                "both-udp0-out-est",
                "ctl-udp0-in",
                "nat-udp0-in-est",
                "fw-udp0-in-est",
                "both-udp0-in-est",
                "ctl-udpc-out",
                "nat-udpc-out-est",
                "fw-udpc-out-est",
                "both-udpc-out-est",
                "ctl-udpc-in",
                "nat-udpc-in-est",
                "fw-udpc-in-est",
                "both-udpc-in-est",
                "ctl-tcp-out",
                "nat-tcp-out-est",
                "fw-tcp-out-est",
                "both-tcp-out-est",
                "ctl-tcp-in",
                "nat-tcp-in-est",
                "fw-tcp-in-est",
                "both-tcp-in-est",
            ]
        );
    }

    #[test]
    fn checksum_pass_metadata_matches_full_transport_scans() {
        let expectations = [
            (Profile::Plain, Transport::UdpZero, 0),
            (Profile::Plain, Transport::UdpChecksum, 0),
            (Profile::Plain, Transport::Tcp, 0),
            (Profile::Nat, Transport::UdpZero, 0),
            (Profile::Nat, Transport::UdpChecksum, 0),
            (Profile::Nat, Transport::Tcp, 1),
            (Profile::Firewall, Transport::UdpZero, 0),
            (Profile::Firewall, Transport::UdpChecksum, 1),
            (Profile::Firewall, Transport::Tcp, 1),
            (Profile::Combined, Transport::UdpZero, 0),
            (Profile::Combined, Transport::UdpChecksum, 1),
            (Profile::Combined, Transport::Tcp, 2),
        ];
        for (profile, transport, expected) in expectations {
            for direction in [Direction::Outbound, Direction::Inbound] {
                let case = Case {
                    profile,
                    transport,
                    direction,
                };
                assert_eq!(
                    case.checksum_passes(),
                    expected,
                    "{} metadata",
                    case.label()
                );
            }
        }
    }

    #[test]
    fn deterministic_workload_fingerprint_has_an_independent_known_answer() {
        assert_eq!(
            r17_deterministic_workload_fingerprint(),
            crate::R17_DETERMINISTIC_SMOKE_WORKLOAD_FINGERPRINT
        );
        assert_eq!(
            r17_deterministic_workload_fingerprint(),
            0x6920_d887_2e7e_5c38
        );
    }

    #[test]
    fn r17_f07_setup_output_has_an_independent_known_answer() {
        let (rows, observed) =
            with_r17_setup_observer(|| run_deterministic_matrix(&RunConfig::smoke())).unwrap();
        assert_eq!(rows.len(), R17_DETERMINISTIC_SMOKE_CASE_COUNT);
        assert_eq!(observed, r17_setup_known_answer());
    }

    #[test]
    fn r17_f07_actual_constructor_binding_has_an_independent_known_answer() {
        let roles = R17_WORKLOAD_DESCRIPTOR.hash_roles;
        let observed = r17_actual_hash_constructor_probe_with_keys(
            R17HashKeyBinding::new(
                r17_nat_udp_hash_key(),
                (roles.nat_udp.first, roles.nat_udp.second),
            ),
            R17HashKeyBinding::new(
                r17_nat_tcp_hash_key(),
                (roles.nat_tcp.first, roles.nat_tcp.second),
            ),
            R17HashKeyBinding::new(
                r17_firewall_hash_key(),
                (roles.firewall.first, roles.firewall.second),
            ),
        );
        assert_eq!(observed, F07_ACTUAL_CONSTRUCTOR_KNOWN_ANSWER);
        assert_eq!(
            r17_hash_constructor_binding_digest(observed),
            F07_ACTUAL_CONSTRUCTOR_DIGEST_KNOWN_ANSWER
        );
        assert_eq!(
            r17_actual_hash_constructor_binding_digest(),
            F07_ACTUAL_CONSTRUCTOR_DIGEST_KNOWN_ANSWER
        );
    }

    #[test]
    fn r17_f07_constructor_swaps_and_role_omissions_are_rejected() {
        let roles = R17_WORKLOAD_DESCRIPTOR.hash_roles;
        let baseline = F07_ACTUAL_CONSTRUCTOR_KNOWN_ANSWER;
        let actual = r17_actual_hash_constructor_probe_with_keys(
            R17HashKeyBinding::new(
                r17_nat_udp_hash_key(),
                (roles.nat_udp.first, roles.nat_udp.second),
            ),
            R17HashKeyBinding::new(
                r17_nat_tcp_hash_key(),
                (roles.nat_tcp.first, roles.nat_tcp.second),
            ),
            R17HashKeyBinding::new(
                r17_firewall_hash_key(),
                (roles.firewall.first, roles.firewall.second),
            ),
        );
        assert_eq!(actual, baseline);

        let udp_argument_swap = r17_actual_hash_constructor_probe_with_keys(
            R17HashKeyBinding::new(
                Nat44UdpHashKey::new(roles.nat_udp.second, roles.nat_udp.first).unwrap(),
                (roles.nat_udp.second, roles.nat_udp.first),
            ),
            R17HashKeyBinding::new(
                r17_nat_tcp_hash_key(),
                (roles.nat_tcp.first, roles.nat_tcp.second),
            ),
            R17HashKeyBinding::new(
                r17_firewall_hash_key(),
                (roles.firewall.first, roles.firewall.second),
            ),
        );
        assert_ne!(
            udp_argument_swap.nat_udp_mapping_peer,
            baseline.nat_udp_mapping_peer
        );
        assert_ne!(
            r17_hash_constructor_binding_digest(udp_argument_swap),
            F07_ACTUAL_CONSTRUCTOR_DIGEST_KNOWN_ANSWER
        );

        let udp_role_swap = r17_actual_hash_constructor_probe_with_keys(
            R17HashKeyBinding::new(
                Nat44UdpHashKey::new(roles.nat_tcp.first, roles.nat_tcp.second).unwrap(),
                (roles.nat_tcp.first, roles.nat_tcp.second),
            ),
            R17HashKeyBinding::new(
                r17_nat_tcp_hash_key(),
                (roles.nat_tcp.first, roles.nat_tcp.second),
            ),
            R17HashKeyBinding::new(
                r17_firewall_hash_key(),
                (roles.firewall.first, roles.firewall.second),
            ),
        );
        assert_ne!(
            udp_role_swap.nat_udp_mapping_peer,
            baseline.nat_udp_mapping_peer
        );
        assert_ne!(
            r17_hash_constructor_binding_digest(udp_role_swap),
            F07_ACTUAL_CONSTRUCTOR_DIGEST_KNOWN_ANSWER
        );

        let tcp_role_swap = r17_actual_hash_constructor_probe_with_keys(
            R17HashKeyBinding::new(
                r17_nat_udp_hash_key(),
                (roles.nat_udp.first, roles.nat_udp.second),
            ),
            R17HashKeyBinding::new(
                Nat44TcpHashKey::new(roles.nat_udp.first, roles.nat_udp.second).unwrap(),
                (roles.nat_udp.first, roles.nat_udp.second),
            ),
            R17HashKeyBinding::new(
                r17_firewall_hash_key(),
                (roles.firewall.first, roles.firewall.second),
            ),
        );
        assert_ne!(
            tcp_role_swap.nat_tcp_mapping_session,
            baseline.nat_tcp_mapping_session
        );
        assert_ne!(
            r17_hash_constructor_binding_digest(tcp_role_swap),
            F07_ACTUAL_CONSTRUCTOR_DIGEST_KNOWN_ANSWER
        );

        let tcp_argument_swap = r17_actual_hash_constructor_probe_with_keys(
            R17HashKeyBinding::new(
                r17_nat_udp_hash_key(),
                (roles.nat_udp.first, roles.nat_udp.second),
            ),
            R17HashKeyBinding::new(
                Nat44TcpHashKey::new(roles.nat_tcp.second, roles.nat_tcp.first).unwrap(),
                (roles.nat_tcp.second, roles.nat_tcp.first),
            ),
            R17HashKeyBinding::new(
                r17_firewall_hash_key(),
                (roles.firewall.first, roles.firewall.second),
            ),
        );
        assert_ne!(
            tcp_argument_swap.nat_tcp_mapping_session,
            baseline.nat_tcp_mapping_session
        );
        assert_ne!(
            r17_hash_constructor_binding_digest(tcp_argument_swap),
            F07_ACTUAL_CONSTRUCTOR_DIGEST_KNOWN_ANSWER
        );

        let firewall_argument_swap = r17_actual_hash_constructor_probe_with_keys(
            R17HashKeyBinding::new(
                r17_nat_udp_hash_key(),
                (roles.nat_udp.first, roles.nat_udp.second),
            ),
            R17HashKeyBinding::new(
                r17_nat_tcp_hash_key(),
                (roles.nat_tcp.first, roles.nat_tcp.second),
            ),
            R17HashKeyBinding::new(
                FirewallHashKey::new(roles.firewall.second, roles.firewall.first).unwrap(),
                (roles.firewall.second, roles.firewall.first),
            ),
        );
        assert_ne!(
            firewall_argument_swap.firewall_stateful_flow,
            baseline.firewall_stateful_flow
        );
        assert_ne!(
            r17_hash_constructor_binding_digest(firewall_argument_swap),
            F07_ACTUAL_CONSTRUCTOR_DIGEST_KNOWN_ANSWER
        );

        let firewall_role_swap = r17_actual_hash_constructor_probe_with_keys(
            R17HashKeyBinding::new(
                r17_nat_udp_hash_key(),
                (roles.nat_udp.first, roles.nat_udp.second),
            ),
            R17HashKeyBinding::new(
                r17_nat_tcp_hash_key(),
                (roles.nat_tcp.first, roles.nat_tcp.second),
            ),
            R17HashKeyBinding::new(
                FirewallHashKey::new(roles.nat_tcp.first, roles.nat_tcp.second).unwrap(),
                (roles.nat_tcp.first, roles.nat_tcp.second),
            ),
        );
        assert_ne!(
            firewall_role_swap.firewall_stateful_flow,
            baseline.firewall_stateful_flow
        );
        assert_ne!(
            r17_hash_constructor_binding_digest(firewall_role_swap),
            F07_ACTUAL_CONSTRUCTOR_DIGEST_KNOWN_ANSWER
        );

        let udp_firewall_role_swap = r17_actual_hash_constructor_probe_with_keys(
            R17HashKeyBinding::new(
                Nat44UdpHashKey::new(roles.firewall.first, roles.firewall.second).unwrap(),
                (roles.firewall.first, roles.firewall.second),
            ),
            R17HashKeyBinding::new(
                r17_nat_tcp_hash_key(),
                (roles.nat_tcp.first, roles.nat_tcp.second),
            ),
            R17HashKeyBinding::new(
                r17_firewall_hash_key(),
                (roles.firewall.first, roles.firewall.second),
            ),
        );
        assert_ne!(
            udp_firewall_role_swap.nat_udp_mapping_peer,
            baseline.nat_udp_mapping_peer
        );
        assert_ne!(
            r17_hash_constructor_binding_digest(udp_firewall_role_swap),
            F07_ACTUAL_CONSTRUCTOR_DIGEST_KNOWN_ANSWER
        );

        for omitted in [
            R17HashConstructorProbe {
                nat_udp_mapping_peer: 0,
                ..baseline
            },
            R17HashConstructorProbe {
                nat_tcp_mapping_session: 0,
                ..baseline
            },
            R17HashConstructorProbe {
                firewall_stateful_flow: 0,
                ..baseline
            },
        ] {
            assert_ne!(
                r17_hash_constructor_binding_digest(omitted),
                F07_ACTUAL_CONSTRUCTOR_DIGEST_KNOWN_ANSWER
            );
        }
    }

    #[test]
    fn r17_f07_bucket_preserving_alternate_keys_change_opaque_authority() {
        let roles = R17_WORKLOAD_DESCRIPTOR.hash_roles;
        let canonical = r17_actual_hash_authority_probes_with_keys(
            r17_nat_udp_hash_key(),
            (roles.nat_udp.first, roles.nat_udp.second),
            r17_nat_tcp_hash_key(),
            (roles.nat_tcp.first, roles.nat_tcp.second),
            r17_firewall_hash_key(),
            (roles.firewall.first, roles.firewall.second),
        );
        assert_eq!(canonical.udp.evidence, r17_expected_udp_authority());
        assert_eq!(canonical.tcp.evidence, r17_expected_tcp_authority());
        assert_eq!(
            canonical.firewall.evidence,
            r17_expected_firewall_authority()
        );
        let udp_mapping_bucket = r17_model_directory_hash(
            (roles.nat_udp.first, roles.nat_udp.second),
            R17_UDP_MAPPING_DOMAIN,
            &[
                u64::from(LAN.0),
                u64::from(u32::from_be_bytes(HOST.octets())),
                u64::from(HOST_PORT),
            ],
        ) as usize
            & (DIRECTORY_BUCKET_CAPACITY - 1);
        assert_eq!(canonical.udp.mapping_buckets, [udp_mapping_bucket, 0, 0, 0]);
        let tcp_mapping_bucket = r17_model_directory_hash(
            (roles.nat_tcp.first, roles.nat_tcp.second),
            R17_TCP_MAPPING_DOMAIN,
            &[
                u64::from(LAN.0),
                u64::from(u32::from_be_bytes(HOST.octets())),
                u64::from(HOST_PORT),
            ],
        ) as usize
            & (DIRECTORY_BUCKET_CAPACITY - 1);
        assert_eq!(canonical.tcp.mapping_buckets, [tcp_mapping_bucket, 0, 0, 0]);
        assert_eq!(canonical.udp.secondary_buckets, [3, 1, 0, 2]);
        assert_eq!(canonical.tcp.secondary_buckets, [3, 3, 3, 2]);
        assert_eq!(canonical.firewall.insertion_starts, [1, 2, 0]);
        assert!(canonical.udp.forwarding_reached);
        assert!(canonical.tcp.forwarding_reached);
        assert!(canonical.firewall.forwarding_reached);

        let udp_alternate_first = 0x1357_9bdf_2468_bfc6;
        let udp_alternate = r17_actual_hash_authority_probes_with_keys(
            Nat44UdpHashKey::new(udp_alternate_first, roles.nat_udp.second).unwrap(),
            (udp_alternate_first, roles.nat_udp.second),
            r17_nat_tcp_hash_key(),
            (roles.nat_tcp.first, roles.nat_tcp.second),
            r17_firewall_hash_key(),
            (roles.firewall.first, roles.firewall.second),
        );
        assert!(udp_alternate.udp.forwarding_reached);
        assert!(!udp_alternate.udp.semantic.authority_matches);
        assert!(udp_alternate.udp.semantic.indexes_coherent);
        assert!(udp_alternate.udp.semantic.directories_coherent);
        assert!(udp_alternate.udp.semantic.occupied_count_conserved);
        assert_eq!(
            (
                udp_alternate.udp.semantic.primary_occupied,
                udp_alternate.udp.semantic.secondary_occupied,
            ),
            (
                canonical.udp.semantic.primary_occupied,
                canonical.udp.semantic.secondary_occupied,
            )
        );
        assert_eq!(
            udp_alternate.udp.secondary_buckets,
            canonical.udp.secondary_buckets
        );
        assert_eq!(
            udp_alternate.udp.mapping_buckets,
            canonical.udp.mapping_buckets
        );
        assert_ne!(udp_alternate.udp.evidence, r17_expected_udp_authority());
        assert_ne!(
            r17_hash_probe_role_digest(R17HashProbeRole::Udp, udp_alternate.udp.semantic),
            R17HashProbeRole::Udp.legacy_identity()
        );
        let udp_aggregate = R17HashConstructorProbe {
            nat_udp_mapping_peer: r17_hash_probe_role_digest(
                R17HashProbeRole::Udp,
                udp_alternate.udp.semantic,
            ),
            nat_tcp_mapping_session: r17_hash_probe_role_digest(
                R17HashProbeRole::Tcp,
                canonical.tcp.semantic,
            ),
            firewall_stateful_flow: r17_hash_probe_role_digest(
                R17HashProbeRole::Firewall,
                canonical.firewall.semantic,
            ),
        };
        assert_ne!(
            r17_hash_constructor_binding_digest(udp_aggregate),
            F07_ACTUAL_CONSTRUCTOR_DIGEST_KNOWN_ANSWER
        );

        let tcp_alternate_first = 0xc001_d00d_f00d_bfce;
        let tcp_alternate = r17_actual_hash_authority_probes_with_keys(
            r17_nat_udp_hash_key(),
            (roles.nat_udp.first, roles.nat_udp.second),
            Nat44TcpHashKey::new(tcp_alternate_first, roles.nat_tcp.second).unwrap(),
            (tcp_alternate_first, roles.nat_tcp.second),
            r17_firewall_hash_key(),
            (roles.firewall.first, roles.firewall.second),
        );
        assert!(tcp_alternate.tcp.forwarding_reached);
        assert!(!tcp_alternate.tcp.semantic.authority_matches);
        assert!(tcp_alternate.tcp.semantic.indexes_coherent);
        assert!(tcp_alternate.tcp.semantic.directories_coherent);
        assert!(tcp_alternate.tcp.semantic.occupied_count_conserved);
        assert_eq!(
            (
                tcp_alternate.tcp.semantic.primary_occupied,
                tcp_alternate.tcp.semantic.secondary_occupied,
            ),
            (
                canonical.tcp.semantic.primary_occupied,
                canonical.tcp.semantic.secondary_occupied,
            )
        );
        assert_eq!(
            tcp_alternate.tcp.secondary_buckets,
            canonical.tcp.secondary_buckets
        );
        assert_eq!(
            tcp_alternate.tcp.mapping_buckets,
            canonical.tcp.mapping_buckets
        );
        assert_ne!(tcp_alternate.tcp.evidence, r17_expected_tcp_authority());
        assert_ne!(
            r17_hash_probe_role_digest(R17HashProbeRole::Tcp, tcp_alternate.tcp.semantic),
            R17HashProbeRole::Tcp.legacy_identity()
        );
        let tcp_aggregate = R17HashConstructorProbe {
            nat_udp_mapping_peer: r17_hash_probe_role_digest(
                R17HashProbeRole::Udp,
                canonical.udp.semantic,
            ),
            nat_tcp_mapping_session: r17_hash_probe_role_digest(
                R17HashProbeRole::Tcp,
                tcp_alternate.tcp.semantic,
            ),
            firewall_stateful_flow: r17_hash_probe_role_digest(
                R17HashProbeRole::Firewall,
                canonical.firewall.semantic,
            ),
        };
        assert_ne!(
            r17_hash_constructor_binding_digest(tcp_aggregate),
            F07_ACTUAL_CONSTRUCTOR_DIGEST_KNOWN_ANSWER
        );

        let firewall_alternate_first = 0x0f1e_2d3c_4b5a_697d;
        let firewall_alternate = r17_actual_hash_authority_probes_with_keys(
            r17_nat_udp_hash_key(),
            (roles.nat_udp.first, roles.nat_udp.second),
            r17_nat_tcp_hash_key(),
            (roles.nat_tcp.first, roles.nat_tcp.second),
            FirewallHashKey::new(firewall_alternate_first, roles.firewall.second).unwrap(),
            (firewall_alternate_first, roles.firewall.second),
        );
        assert!(firewall_alternate.firewall.forwarding_reached);
        assert!(!firewall_alternate.firewall.semantic.authority_matches);
        assert!(firewall_alternate.firewall.semantic.indexes_coherent);
        assert!(firewall_alternate.firewall.semantic.directories_coherent);
        assert!(
            firewall_alternate
                .firewall
                .semantic
                .occupied_count_conserved
        );
        assert_eq!(
            firewall_alternate.firewall.semantic.primary_occupied,
            canonical.firewall.semantic.primary_occupied
        );
        assert_eq!(
            firewall_alternate.firewall.insertion_starts,
            canonical.firewall.insertion_starts
        );
        assert_ne!(
            firewall_alternate.firewall.evidence,
            r17_expected_firewall_authority()
        );
        assert_ne!(
            r17_hash_probe_role_digest(
                R17HashProbeRole::Firewall,
                firewall_alternate.firewall.semantic
            ),
            R17HashProbeRole::Firewall.legacy_identity()
        );
        let firewall_aggregate = R17HashConstructorProbe {
            nat_udp_mapping_peer: r17_hash_probe_role_digest(
                R17HashProbeRole::Udp,
                canonical.udp.semantic,
            ),
            nat_tcp_mapping_session: r17_hash_probe_role_digest(
                R17HashProbeRole::Tcp,
                canonical.tcp.semantic,
            ),
            firewall_stateful_flow: r17_hash_probe_role_digest(
                R17HashProbeRole::Firewall,
                firewall_alternate.firewall.semantic,
            ),
        };
        assert_ne!(
            r17_hash_constructor_binding_digest(firewall_aggregate),
            F07_ACTUAL_CONSTRUCTOR_DIGEST_KNOWN_ANSWER
        );
    }

    #[test]
    fn r17_f07_workload_descriptor_mutations_cross_the_identity_boundary() {
        let descriptor = R17_WORKLOAD_DESCRIPTOR;
        let baseline = fingerprint_workload_descriptor_value(0xcbf2_9ce4_8422_2325, descriptor);
        assert_eq!(baseline, 0x2ca7_c21d_fe5f_5d51);

        let mut seed = descriptor;
        seed.seed ^= 1;
        assert_ne!(
            fingerprint_workload_descriptor_value(0xcbf2_9ce4_8422_2325, seed),
            baseline
        );

        let mut frame = descriptor;
        frame.frame.ttl += 1;
        assert_ne!(
            fingerprint_workload_descriptor_value(0xcbf2_9ce4_8422_2325, frame),
            baseline
        );

        let mut setup = descriptor;
        setup.setup.steps.swap(1, 2);
        assert_ne!(
            fingerprint_workload_descriptor_value(0xcbf2_9ce4_8422_2325, setup),
            baseline
        );

        let mut key = descriptor;
        key.hash_roles.nat_udp.first ^= 1;
        assert_ne!(
            fingerprint_workload_descriptor_value(0xcbf2_9ce4_8422_2325, key),
            baseline
        );

        let mut role = descriptor;
        role.hash_roles.nat_tcp = role.hash_roles.nat_udp;
        assert_ne!(
            fingerprint_workload_descriptor_value(0xcbf2_9ce4_8422_2325, role),
            baseline
        );
    }
}
