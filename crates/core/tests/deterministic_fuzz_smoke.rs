//! Bounded, reproducible hostile-input smoke coverage for the packet paths.
//!
//! This deliberately stays in the integration-test crate.  In particular, it
//! does not depend on the benchmark crate or on the simulator backend.

use std::{
    cell::Cell,
    fmt,
    panic::{catch_unwind, AssertUnwindSafe},
};

use ruster_core::{
    forward_batch, forward_batch_with_firewall, forward_batch_with_nat44_udp_and_tcp,
    forward_batch_with_nat44_udp_and_tcp_and_icmpv4_errors, internet_checksum,
    ipv4_header_checksum, validate_arp, validate_arp_request, validate_ipv4_frame, BatchCompletion,
    FirewallAction, FirewallConfig, FirewallHashKey, FirewallInterface, Ipv4Mtu, FirewallIpv4Prefix,
    FirewallPolicy, FirewallPortRange, FirewallProtocol, FirewallRule, FirewallRuleId,
    FirewallRuntime, FirewallStateSlot, ForwardingSnapshot, Icmpv4ErrorActionSlot,
    Icmpv4ErrorPolicy, Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address,
    LocalIpv4Binding, MacAddress, MonotonicMillis, Nat44Icmpv4Disposition, Nat44Icmpv4ErrorPolicy,
    Nat44TcpConfig, Nat44TcpHashKey, Nat44TcpIndexStorage, Nat44TcpMappingSlot, Nat44TcpPolicy,
    Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44UdpConfig, Nat44UdpHashKey, Nat44UdpIndexStorage,
    Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpRuntime, Neighbor, NoTrace,
    PacketBatch, PacketLease, PacketSlot, ResolutionActionSlot, ResolutionPolicy,
    ResolutionRuntime, ResolutionStateSlot, Route, SlotCompletion, TraceEvent, TraceSink,
    IPV4_ETHERTYPE,
};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
const HOST_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 10]);
const REMOTE_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 30]);
const GATEWAY_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 20]);
const HOST: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
const LAN_LOCAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 1]);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const GATEWAY: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);

const RANDOM_SEED: u64 = 0x7261_6e64_6f6d_0001;
const STRUCTURED_SEED: u64 = 0x7374_7275_6374_0001;
const DEFAULT_ITERATIONS: usize = 50_000;
const MAX_ITERATIONS: usize = 5_000_000;

const FOCUSED_LENGTHS: [usize; 22] = [
    0, 1, 13, 14, 15, 33, 34, 41, 42, 53, 54, 60, 64, 1_499, 1_500, 1_501, 1_513, 1_514, 1_515,
    8_999, 9_000, 9_001,
];

#[derive(Clone, Copy)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        assert_ne!(seed, 0, "fuzz seed must be nonzero");
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }

    fn index(&mut self, length: usize) -> usize {
        (self.next_u64() as usize) % length
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            *byte = self.next_u64() as u8;
        }
    }
}

struct HexBytes<'a>(&'a [u8]);

impl fmt::Display for HexBytes<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HEX: [&str; 16] = [
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
        ];
        for byte in self.0 {
            formatter.write_str(HEX[usize::from(byte >> 4)])?;
            formatter.write_str(HEX[usize::from(byte & 0x0f)])?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum PlainTransport {
    Udp,
    Tcp,
    IcmpEcho,
}

#[derive(Clone, Copy)]
enum StructuredMutation {
    Ipv4EtherType,
    Ipv4Ihl,
    Ipv4TotalLength,
    Ipv4Protocol,
    Ipv4Fragment,
    UdpLength,
    TcpDataOffset,
    IcmpType,
    IcmpCode,
    ArpHardwareType,
    ArpProtocolType,
    ArpHardwareLength,
    ArpProtocolLength,
    ArpOpcode,
    ArpSenderHardware,
    NatOuterIhl,
    NatOuterTotalLength,
    NatOuterProtocol,
    NatOuterFragment,
    NatIcmpType,
    NatIcmpCode,
    NatQuotedVersion,
    NatQuotedIhl,
    NatQuotedTotalLength,
    NatQuotedTransport,
    NatQuotedProtocol,
    NatQuotedFragment,
    NatQuotedUdpLength,
    NatQuotedTcpDataOffset,
    NatQuotedTruncate,
}

const STRUCTURED_MUTATIONS: [StructuredMutation; 30] = [
    StructuredMutation::Ipv4EtherType,
    StructuredMutation::Ipv4Ihl,
    StructuredMutation::Ipv4TotalLength,
    StructuredMutation::Ipv4Protocol,
    StructuredMutation::Ipv4Fragment,
    StructuredMutation::UdpLength,
    StructuredMutation::TcpDataOffset,
    StructuredMutation::IcmpType,
    StructuredMutation::IcmpCode,
    StructuredMutation::ArpHardwareType,
    StructuredMutation::ArpProtocolType,
    StructuredMutation::ArpHardwareLength,
    StructuredMutation::ArpProtocolLength,
    StructuredMutation::ArpOpcode,
    StructuredMutation::ArpSenderHardware,
    StructuredMutation::NatOuterIhl,
    StructuredMutation::NatOuterTotalLength,
    StructuredMutation::NatOuterProtocol,
    StructuredMutation::NatOuterFragment,
    StructuredMutation::NatIcmpType,
    StructuredMutation::NatIcmpCode,
    StructuredMutation::NatQuotedVersion,
    StructuredMutation::NatQuotedIhl,
    StructuredMutation::NatQuotedTotalLength,
    StructuredMutation::NatQuotedTransport,
    StructuredMutation::NatQuotedProtocol,
    StructuredMutation::NatQuotedFragment,
    StructuredMutation::NatQuotedUdpLength,
    StructuredMutation::NatQuotedTcpDataOffset,
    StructuredMutation::NatQuotedTruncate,
];

struct StructuredInput {
    frame: Vec<u8>,
    ingress: IfId,
    transport_validation: bool,
    nat_quote_transport: Option<PlainTransport>,
}

#[test]
fn deterministic_fuzz_random_frames_do_not_panic() {
    let iterations = configured_iterations();
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut stream = XorShift64::new(RANDOM_SEED);

    for iteration in 0..iterations {
        let case_seed = stream.next_u64();
        let mut case_rng = XorShift64::new(case_seed);
        let frame = random_frame(&mut case_rng, FOCUSED_LENGTHS.get(iteration).copied());
        run_case(RANDOM_SEED, case_seed, iteration, &frame, || {
            inspect_parser_results(&frame);
            run_plain_forwarding(&frame, LAN, &snapshot);
        });
    }

    println!(
        "deterministic fuzz smoke: strategy=random seed=0x{RANDOM_SEED:016x} inputs={iterations}"
    );
}

#[test]
fn deterministic_fuzz_structured_mutations_do_not_panic() {
    let iterations = configured_iterations();
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let firewall_rules = firewall_rules();
    let firewall_config = firewall_config(&snapshot, &firewall_rules);
    let nat_config = nat_config(&snapshot);
    let tcp_config = tcp_config(&snapshot);
    let mut nat_mapping = [Nat44UdpMappingSlot::default(); 1];
    let mut nat_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut mapping_buckets = [ruster_core::DirectoryBucket::default(); 1];
    let mut mapping_nodes = [ruster_core::DirectoryNode::default(); 1];
    let mut peer_buckets = [ruster_core::DirectoryBucket::default(); 1];
    let mut peer_nodes = [ruster_core::DirectoryNode::default(); 1];
    let mut port_owners = [ruster_core::PortOwnerSlot::default(); 1];
    let indexes = Nat44UdpIndexStorage::new(
        &mut mapping_buckets,
        &mut mapping_nodes,
        &mut peer_buckets,
        &mut peer_nodes,
        &mut port_owners,
    );
    let mut nat = Nat44UdpRuntime::new(
        nat_config,
        &mut nat_mapping,
        &mut nat_peers,
        indexes,
        Nat44UdpHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap(),
    )
    .unwrap();
    let mut tcp_mapping = [Nat44TcpMappingSlot::default(); 1];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut tcp_mapping_buckets = [ruster_core::DirectoryBucket::default(); 1];
    let mut tcp_mapping_nodes = [ruster_core::DirectoryNode::default(); 1];
    let mut tcp_session_buckets = [ruster_core::DirectoryBucket::default(); 1];
    let mut tcp_session_nodes = [ruster_core::DirectoryNode::default(); 1];
    let mut tcp_port_owners = [ruster_core::PortOwnerSlot::default(); 1];
    let tcp_indexes = Nat44TcpIndexStorage::new(
        &mut tcp_mapping_buckets,
        &mut tcp_mapping_nodes,
        &mut tcp_session_buckets,
        &mut tcp_session_nodes,
        &mut tcp_port_owners,
    );
    let mut tcp = Nat44TcpRuntime::new(
        tcp_config,
        &mut tcp_mapping,
        &mut tcp_sessions,
        tcp_indexes,
        Nat44TcpHashKey::new(0x3141_5926_5358_9793, 0x2384_6264_3383_2795).unwrap(),
    )
    .unwrap();
    let mut stream = XorShift64::new(STRUCTURED_SEED);

    for iteration in 0..iterations {
        let case_seed = stream.next_u64();
        let mut case_rng = XorShift64::new(case_seed);
        let input = structured_input(&mut case_rng);
        run_case(STRUCTURED_SEED, case_seed, iteration, &input.frame, || {
            inspect_parser_results(&input.frame);
            run_plain_forwarding(&input.frame, input.ingress, &snapshot);
            if input.transport_validation {
                run_firewall_forwarding(&input.frame, &snapshot, &firewall_config);
            }
            if let Some(transport) = input.nat_quote_transport {
                run_nat_quote_forwarding(
                    &input.frame,
                    &snapshot,
                    &nat_config,
                    &mut nat,
                    &tcp_config,
                    &mut tcp,
                    transport,
                );
            }
        });
    }

    println!(
        "deterministic fuzz smoke: strategy=structured seed=0x{STRUCTURED_SEED:016x} inputs={iterations}"
    );
}

fn configured_iterations() -> usize {
    std::env::var("RUSTER_CORE_FUZZ_ITERATIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map_or(DEFAULT_ITERATIONS, |value| value.clamp(1, MAX_ITERATIONS))
}

fn random_frame(rng: &mut XorShift64, forced_length: Option<usize>) -> Vec<u8> {
    let length = forced_length.unwrap_or_else(|| {
        if rng.next_u64() & 3 == 0 {
            let index = rng.index(FOCUSED_LENGTHS.len());
            FOCUSED_LENGTHS[index]
        } else {
            rng.index(9_217)
        }
    });
    let mut frame = vec![0; length];
    rng.fill(&mut frame);
    frame
}

fn structured_input(rng: &mut XorShift64) -> StructuredInput {
    let mutation = STRUCTURED_MUTATIONS[rng.index(STRUCTURED_MUTATIONS.len())];
    match mutation {
        StructuredMutation::Ipv4EtherType
        | StructuredMutation::Ipv4Ihl
        | StructuredMutation::Ipv4TotalLength
        | StructuredMutation::Ipv4Protocol
        | StructuredMutation::Ipv4Fragment
        | StructuredMutation::UdpLength
        | StructuredMutation::TcpDataOffset
        | StructuredMutation::IcmpType
        | StructuredMutation::IcmpCode => {
            let transport = match mutation {
                StructuredMutation::UdpLength => PlainTransport::Udp,
                StructuredMutation::TcpDataOffset => PlainTransport::Tcp,
                StructuredMutation::IcmpType | StructuredMutation::IcmpCode => {
                    PlainTransport::IcmpEcho
                }
                _ => match rng.index(3) {
                    0 => PlainTransport::Udp,
                    1 => PlainTransport::Tcp,
                    _ => PlainTransport::IcmpEcho,
                },
            };
            let mut frame = plain_frame(transport, structured_frame_length(rng, 60), rng);
            apply_plain_mutation(&mut frame, mutation, rng);
            StructuredInput {
                frame,
                ingress: LAN,
                transport_validation: matches!(
                    transport,
                    PlainTransport::Udp | PlainTransport::Tcp
                ),
                nat_quote_transport: None,
            }
        }
        StructuredMutation::ArpHardwareType
        | StructuredMutation::ArpProtocolType
        | StructuredMutation::ArpHardwareLength
        | StructuredMutation::ArpProtocolLength
        | StructuredMutation::ArpOpcode
        | StructuredMutation::ArpSenderHardware => {
            let mut frame = arp_frame(structured_frame_length(rng, 60));
            apply_arp_mutation(&mut frame, mutation);
            StructuredInput {
                frame,
                ingress: LAN,
                transport_validation: false,
                nat_quote_transport: None,
            }
        }
        _ => {
            let transport = match mutation {
                StructuredMutation::NatQuotedUdpLength => PlainTransport::Udp,
                StructuredMutation::NatQuotedTcpDataOffset => PlainTransport::Tcp,
                _ => match rng.index(2) {
                    0 => PlainTransport::Udp,
                    _ => PlainTransport::Tcp,
                },
            };
            let mut frame = nat_frag_needed_frame(structured_frame_length(rng, 70), transport, rng);
            apply_nat_mutation(&mut frame, mutation, transport, rng);
            StructuredInput {
                frame,
                ingress: WAN,
                transport_validation: false,
                nat_quote_transport: Some(transport),
            }
        }
    }
}

fn structured_frame_length(rng: &mut XorShift64, minimum: usize) -> usize {
    minimum.max(FOCUSED_LENGTHS[rng.index(FOCUSED_LENGTHS.len())])
}

fn plain_frame(transport: PlainTransport, length: usize, rng: &mut XorShift64) -> Vec<u8> {
    let (total_length, source, destination, source_mac, destination_mac, protocol) = match transport
    {
        PlainTransport::Udp => (32_u16, HOST, REMOTE, HOST_MAC, LAN_MAC, 17_u8),
        PlainTransport::Tcp => (40_u16, HOST, REMOTE, HOST_MAC, LAN_MAC, 6_u8),
        PlainTransport::IcmpEcho => (28_u16, REMOTE, LAN_LOCAL, REMOTE_MAC, LAN_MAC, 1_u8),
    };
    let mut frame = vec![0; length.max(usize::from(total_length) + 14).max(60)];
    frame[0..6].copy_from_slice(&destination_mac.0);
    frame[6..12].copy_from_slice(&source_mac.0);
    frame[12..14].copy_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = rng.next_u64() as u8;
    frame[16..18].copy_from_slice(&total_length.to_be_bytes());
    frame[18..20].copy_from_slice(&(rng.next_u64() as u16).to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = protocol;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    match transport {
        PlainTransport::Udp => {
            frame[34..36].copy_from_slice(&12_345_u16.to_be_bytes());
            frame[36..38].copy_from_slice(&53_u16.to_be_bytes());
            frame[38..40].copy_from_slice(&12_u16.to_be_bytes());
            frame[40..42].fill(0);
            frame[42..46].copy_from_slice(&[1, 2, 3, 4]);
        }
        PlainTransport::Tcp => {
            frame[34..36].copy_from_slice(&12_345_u16.to_be_bytes());
            frame[36..38].copy_from_slice(&443_u16.to_be_bytes());
            frame[38..42].copy_from_slice(&1_u32.to_be_bytes());
            frame[42..46].copy_from_slice(&2_u32.to_be_bytes());
            frame[46] = 5 << 4;
            frame[47] = 0x02;
            frame[48..50].copy_from_slice(&4096_u16.to_be_bytes());
            frame[50..52].fill(0);
            let mut pseudo = Vec::with_capacity(32);
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(&[0, 6]);
            pseudo.extend_from_slice(&20_u16.to_be_bytes());
            pseudo.extend_from_slice(&frame[34..54]);
            let checksum = internet_checksum(&pseudo);
            frame[50..52].copy_from_slice(&checksum.to_be_bytes());
        }
        PlainTransport::IcmpEcho => {
            frame[34] = 8;
            frame[35] = 0;
            frame[38..42].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
            let checksum = internet_checksum(&frame[34..42]);
            frame[36..38].copy_from_slice(&checksum.to_be_bytes());
        }
    }
    refresh_ipv4_checksum(&mut frame, 14);
    frame
}

fn arp_frame(length: usize) -> Vec<u8> {
    let mut frame = vec![0; length.max(60)];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&HOST_MAC.0);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
    frame[18..22].copy_from_slice(&[6, 4, 0, 1]);
    frame[22..28].copy_from_slice(&HOST_MAC.0);
    frame[28..32].copy_from_slice(&HOST.octets());
    frame[32..38].copy_from_slice(&[0; 6]);
    frame[38..42].copy_from_slice(&LAN_LOCAL.octets());
    frame
}

fn nat_frag_needed_frame(
    length: usize,
    transport: PlainTransport,
    rng: &mut XorShift64,
) -> Vec<u8> {
    let (inner_total_length, outer_total_length, protocol, remote_port) = match transport {
        PlainTransport::Udp => (28_u16, 56_u16, 17_u8, 53_u16),
        PlainTransport::Tcp => (40_u16, 68_u16, 6_u8, 443_u16),
        PlainTransport::IcmpEcho => unreachable!("NAT quotes use UDP or TCP"),
    };
    let mut frame = vec![0; length.max(14 + usize::from(outer_total_length))];
    frame[0..6].copy_from_slice(&WAN_MAC.0);
    frame[6..12].copy_from_slice(&REMOTE_MAC.0);
    frame[12..14].copy_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = rng.next_u64() as u8;
    frame[16..18].copy_from_slice(&outer_total_length.to_be_bytes());
    frame[18..20].copy_from_slice(&0x8888_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&REMOTE.octets());
    frame[30..34].copy_from_slice(&PUBLIC.octets());
    frame[34..36].copy_from_slice(&[3, 4]);
    frame[38..42].copy_from_slice(&[0, 0, 0x05, 0x78]);
    frame[42] = 0x45;
    frame[43] = rng.next_u64() as u8;
    frame[44..46].copy_from_slice(&inner_total_length.to_be_bytes());
    frame[46..48].copy_from_slice(&(rng.next_u64() as u16).to_be_bytes());
    frame[48..50].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[50] = 64;
    frame[51] = protocol;
    frame[54..58].copy_from_slice(&PUBLIC.octets());
    frame[58..62].copy_from_slice(&REMOTE.octets());
    match transport {
        PlainTransport::Udp => {
            frame[62..64].copy_from_slice(&40_000_u16.to_be_bytes());
            frame[64..66].copy_from_slice(&remote_port.to_be_bytes());
            frame[66..68].copy_from_slice(&8_u16.to_be_bytes());
            frame[68..70].fill(0);
        }
        PlainTransport::Tcp => {
            frame[62..64].copy_from_slice(&40_000_u16.to_be_bytes());
            frame[64..66].copy_from_slice(&remote_port.to_be_bytes());
            frame[66..70].copy_from_slice(&1_u32.to_be_bytes());
            frame[70..74].copy_from_slice(&0_u32.to_be_bytes());
            frame[74] = 5 << 4;
            frame[75] = 0x02;
            frame[76..78].copy_from_slice(&4096_u16.to_be_bytes());
            frame[78..80].fill(0);
            frame[80..82].fill(0);
            let mut pseudo = Vec::with_capacity(32);
            pseudo.extend_from_slice(&PUBLIC.octets());
            pseudo.extend_from_slice(&REMOTE.octets());
            pseudo.extend_from_slice(&[0, protocol]);
            pseudo.extend_from_slice(&20_u16.to_be_bytes());
            pseudo.extend_from_slice(&frame[62..82]);
            let checksum = internet_checksum(&pseudo);
            frame[78..80].copy_from_slice(&checksum.to_be_bytes());
        }
        PlainTransport::IcmpEcho => unreachable!("NAT quotes use UDP or TCP"),
    }
    refresh_ipv4_checksum(&mut frame, 42);
    refresh_icmp_checksum(&mut frame);
    refresh_ipv4_checksum(&mut frame, 14);
    frame
}

fn apply_plain_mutation(frame: &mut [u8], mutation: StructuredMutation, rng: &mut XorShift64) {
    match mutation {
        StructuredMutation::Ipv4EtherType => {
            frame[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes())
        }
        StructuredMutation::Ipv4Ihl => frame[14] = 0x44,
        StructuredMutation::Ipv4TotalLength => {
            let current = u16::from_be_bytes([frame[16], frame[17]]);
            let value = if rng.next_u64() & 1 == 0 {
                current.saturating_sub(1)
            } else {
                u16::MAX
            };
            frame[16..18].copy_from_slice(&value.to_be_bytes());
        }
        StructuredMutation::Ipv4Protocol => {
            frame[23] = if frame[23] == 17 { 6 } else { 17 };
            refresh_ipv4_checksum(frame, 14);
        }
        StructuredMutation::Ipv4Fragment => {
            frame[20..22].copy_from_slice(&0x2000_u16.to_be_bytes());
            refresh_ipv4_checksum(frame, 14);
        }
        StructuredMutation::UdpLength => {
            let value = if rng.next_u64() & 1 == 0 { 7 } else { u16::MAX };
            frame[38..40].copy_from_slice(&value.to_be_bytes());
        }
        StructuredMutation::TcpDataOffset => {
            frame[46] = if rng.next_u64() & 1 == 0 {
                4 << 4
            } else {
                15 << 4
            }
        }
        StructuredMutation::IcmpType => {
            frame[34] = 3;
            refresh_icmp_echo_checksum(frame);
        }
        StructuredMutation::IcmpCode => {
            frame[35] = 1;
            refresh_icmp_echo_checksum(frame);
        }
        _ => unreachable!("non-IPv4 mutation applied to an IPv4 frame"),
    }
}

fn apply_arp_mutation(frame: &mut [u8], mutation: StructuredMutation) {
    match mutation {
        StructuredMutation::ArpHardwareType => frame[14..16].copy_from_slice(&2_u16.to_be_bytes()),
        StructuredMutation::ArpProtocolType => {
            frame[16..18].copy_from_slice(&0x86dd_u16.to_be_bytes())
        }
        StructuredMutation::ArpHardwareLength => frame[18] = 5,
        StructuredMutation::ArpProtocolLength => frame[19] = 16,
        StructuredMutation::ArpOpcode => frame[20..22].copy_from_slice(&3_u16.to_be_bytes()),
        StructuredMutation::ArpSenderHardware => frame[22..28].fill(0),
        _ => unreachable!("non-ARP mutation applied to an ARP frame"),
    }
}

fn apply_nat_mutation(
    frame: &mut Vec<u8>,
    mutation: StructuredMutation,
    transport: PlainTransport,
    rng: &mut XorShift64,
) {
    match mutation {
        StructuredMutation::NatOuterIhl => frame[14] = 0x44,
        StructuredMutation::NatOuterTotalLength => {
            let value = if rng.next_u64() & 1 == 0 {
                55
            } else {
                u16::MAX
            };
            frame[16..18].copy_from_slice(&value.to_be_bytes());
            if value == 55 {
                refresh_icmp_checksum(frame);
                refresh_ipv4_checksum(frame, 14);
            }
        }
        StructuredMutation::NatOuterProtocol => {
            frame[23] = 17;
            refresh_ipv4_checksum(frame, 14);
        }
        StructuredMutation::NatOuterFragment => {
            frame[20..22].copy_from_slice(&0x2000_u16.to_be_bytes());
            refresh_ipv4_checksum(frame, 14);
        }
        StructuredMutation::NatIcmpType => {
            frame[34] = 11;
            refresh_icmp_checksum(frame);
        }
        StructuredMutation::NatIcmpCode => {
            frame[35] = 5;
            refresh_icmp_checksum(frame);
        }
        StructuredMutation::NatQuotedVersion => {
            frame[42] = 0x65;
            refresh_icmp_checksum(frame);
        }
        StructuredMutation::NatQuotedIhl => {
            frame[42] = 0x44;
            refresh_icmp_checksum(frame);
        }
        StructuredMutation::NatQuotedTotalLength => {
            let value = if rng.next_u64() & 1 == 0 {
                20
            } else {
                u16::MAX
            };
            frame[44..46].copy_from_slice(&value.to_be_bytes());
            refresh_ipv4_checksum(frame, 42);
            refresh_icmp_checksum(frame);
        }
        StructuredMutation::NatQuotedTransport => {
            frame[51] = if frame[51] == 17 { 6 } else { 17 };
            refresh_ipv4_checksum(frame, 42);
            refresh_icmp_checksum(frame);
        }
        StructuredMutation::NatQuotedProtocol => {
            frame[51] = 0;
            refresh_ipv4_checksum(frame, 42);
            refresh_icmp_checksum(frame);
        }
        StructuredMutation::NatQuotedFragment => {
            frame[48..50].copy_from_slice(&1_u16.to_be_bytes());
            refresh_ipv4_checksum(frame, 42);
            refresh_icmp_checksum(frame);
        }
        StructuredMutation::NatQuotedUdpLength => {
            let value = if rng.next_u64() & 1 == 0 { 7 } else { u16::MAX };
            match transport {
                PlainTransport::Udp => frame[66..68].copy_from_slice(&value.to_be_bytes()),
                PlainTransport::Tcp => frame[74] = if value == 7 { 4 << 4 } else { 15 << 4 },
                PlainTransport::IcmpEcho => unreachable!("NAT quotes use UDP or TCP"),
            }
            refresh_icmp_checksum(frame);
        }
        StructuredMutation::NatQuotedTcpDataOffset => {
            frame[74] = if rng.next_u64() & 1 == 0 {
                4 << 4
            } else {
                15 << 4
            };
            refresh_icmp_checksum(frame);
        }
        StructuredMutation::NatQuotedTruncate => frame.truncate(42 + 8 + 19),
        _ => unreachable!("non-NAT mutation applied to a NAT ICMP frame"),
    }
}

fn refresh_ipv4_checksum(frame: &mut [u8], offset: usize) {
    let Some(first) = frame.get(offset).copied() else {
        return;
    };
    let header_length = usize::from(first & 0x0f) * 4;
    let Some(header_end) = offset.checked_add(header_length) else {
        return;
    };
    let Some(checksum_end) = offset.checked_add(12) else {
        return;
    };
    if header_length < 20 || header_end > frame.len() || checksum_end > frame.len() {
        return;
    }
    frame[offset + 10..offset + 12].fill(0);
    let checksum = ipv4_header_checksum(&frame[offset..header_end]);
    frame[offset + 10..offset + 12].copy_from_slice(&checksum.to_be_bytes());
}

fn refresh_icmp_echo_checksum(frame: &mut [u8]) {
    if frame.len() < 42 {
        return;
    }
    frame[36..38].fill(0);
    let checksum = internet_checksum(&frame[34..42]);
    frame[36..38].copy_from_slice(&checksum.to_be_bytes());
}

fn refresh_icmp_checksum(frame: &mut [u8]) {
    let Some(first) = frame.get(14).copied() else {
        return;
    };
    let header_length = usize::from(first & 0x0f) * 4;
    let Some(icmp_offset) = 14usize.checked_add(header_length) else {
        return;
    };
    let Some(total) = frame
        .get(16..18)
        .map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
    else {
        return;
    };
    let Some(icmp_end) = 14usize.checked_add(total) else {
        return;
    };
    if header_length < 20
        || icmp_offset.checked_add(4).is_none_or(|end| end > icmp_end)
        || icmp_end > frame.len()
    {
        return;
    }
    frame[icmp_offset + 2..icmp_offset + 4].fill(0);
    let checksum = internet_checksum(&frame[icmp_offset..icmp_end]);
    frame[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&checksum.to_be_bytes());
}

fn inspect_parser_results(frame: &[u8]) {
    if let Ok(parsed) = validate_ipv4_frame(frame) {
        assert!(parsed.header_offset <= frame.len());
        let Some(header_end) = parsed.header_offset.checked_add(parsed.header_len) else {
            panic!("successful IPv4 parser result overflowed header offset");
        };
        let Some(total_end) = parsed.header_offset.checked_add(parsed.total_len) else {
            panic!("successful IPv4 parser result overflowed total length");
        };
        assert!(header_end <= frame.len());
        assert!(total_end <= frame.len());
        assert!(parsed.header_len <= parsed.total_len);
    }
    if validate_arp(frame).is_ok() {
        assert!(frame.len() >= 42);
    }
    if validate_arp_request(frame).is_ok() {
        assert!(frame.len() >= 42);
    }
}

fn run_case<F>(strategy_seed: u64, case_seed: u64, iteration: usize, frame: &[u8], action: F)
where
    F: FnOnce(),
{
    if catch_unwind(AssertUnwindSafe(action)).is_err() {
        panic!(
            "deterministic fuzz failure: strategy_seed=0x{strategy_seed:016x} case_seed=0x{case_seed:016x} iteration={iteration} frame_hex={}",
            HexBytes(frame)
        );
    }
}

fn run_plain_forwarding(frame: &[u8], ingress: IfId, snapshot: &ForwardingSnapshot<'_>) {
    let mut packet = frame.to_vec();
    let completion = Cell::new(None);
    let report = forward_batch(
        SinglePacketBatch {
            ingress,
            frame: Some(packet.as_mut_slice()),
            completion: &completion,
        },
        snapshot,
        &mut NoTrace,
    );
    assert_batch_invariants(&report.completion);
    assert!(report.invariants_hold());
    assert!(completion.get().is_some());
}

fn run_firewall_forwarding(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    config: &FirewallConfig<'_>,
) {
    let mut packet = frame.to_vec();
    let completion = Cell::new(None);
    let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
    let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        &mut resolution_states,
        &mut resolution_actions,
    );
    let mut firewall_states = [FirewallStateSlot::default(); 4];
    let mut firewall = FirewallRuntime::new(*config, &mut firewall_states);
    let report = forward_batch_with_firewall(
        SinglePacketBatch {
            ingress: LAN,
            frame: Some(packet.as_mut_slice()),
            completion: &completion,
        },
        snapshot,
        &mut resolution,
        config,
        Some(&mut firewall),
        MonotonicMillis(1_000),
        &mut NoTrace,
    );
    assert_batch_invariants(&report.completion);
    assert!(report.invariants_hold());
    assert!(completion.get().is_some());
}

fn run_nat_quote_forwarding(
    frame: &[u8],
    snapshot: &ForwardingSnapshot<'_>,
    udp_config: &Nat44UdpConfig,
    udp: &mut Nat44UdpRuntime<'_>,
    tcp_config: &Nat44TcpConfig,
    tcp: &mut Nat44TcpRuntime<'_>,
    transport: PlainTransport,
) {
    // The quoted packet is deliberately sent through the public forwarding
    // entry point after a matching outbound flow has been established.  This
    // makes both the UDP and TCP read-only quote lookups reachable instead of
    // merely exercising the parser in isolation.
    run_nat_seed_forwarding(transport, snapshot, udp_config, udp, tcp_config, tcp);
    let other_transport = match transport {
        PlainTransport::Udp => PlainTransport::Tcp,
        PlainTransport::Tcp => PlainTransport::Udp,
        PlainTransport::IcmpEcho => unreachable!("NAT quotes use UDP or TCP"),
    };
    run_nat_seed_forwarding(other_transport, snapshot, udp_config, udp, tcp_config, tcp);
    run_nat_valid_probe(transport, snapshot, udp_config, udp, tcp_config, tcp);

    let mut packet = frame.to_vec();
    let completion = Cell::new(None);
    let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
    let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        &mut resolution_states,
        &mut resolution_actions,
    );
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 2];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 2];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let report = forward_batch_with_nat44_udp_and_tcp_and_icmpv4_errors(
        SinglePacketBatch {
            ingress: WAN,
            frame: Some(packet.as_mut_slice()),
            completion: &completion,
        },
        snapshot,
        &mut resolution,
        &mut errors,
        udp_config,
        Some(udp),
        tcp_config,
        Some(tcp),
        MonotonicMillis(1_000),
        &mut NoTrace,
    );
    assert_batch_invariants(&report.completion);
    assert!(report.invariants_hold());
    assert!(completion.get().is_some());
}

fn run_nat_valid_probe(
    transport: PlainTransport,
    snapshot: &ForwardingSnapshot<'_>,
    udp_config: &Nat44UdpConfig,
    udp: &mut Nat44UdpRuntime<'_>,
    tcp_config: &Nat44TcpConfig,
    tcp: &mut Nat44TcpRuntime<'_>,
) {
    let mut rng = XorShift64::new(match transport {
        PlainTransport::Udp => 0x7661_6c69_6400_0001,
        PlainTransport::Tcp => 0x7661_6c69_6400_0002,
        PlainTransport::IcmpEcho => unreachable!("NAT probes use UDP or TCP"),
    });
    let mut packet = nat_frag_needed_frame(70, transport, &mut rng);
    let completion = Cell::new(None);
    let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
    let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        &mut resolution_states,
        &mut resolution_actions,
    );
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 2];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 2];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let mut trace = NatIcmpTrace::default();
    let report = forward_batch_with_nat44_udp_and_tcp_and_icmpv4_errors(
        SinglePacketBatch {
            ingress: WAN,
            frame: Some(packet.as_mut_slice()),
            completion: &completion,
        },
        snapshot,
        &mut resolution,
        &mut errors,
        udp_config,
        Some(udp),
        tcp_config,
        Some(tcp),
        MonotonicMillis(1_000),
        &mut trace,
    );
    let expected_protocol = match transport {
        PlainTransport::Udp => 17_u8,
        PlainTransport::Tcp => 6_u8,
        PlainTransport::IcmpEcho => unreachable!("NAT probes use UDP or TCP"),
    };
    assert!(matches!(
        trace.disposition,
        Some(Nat44Icmpv4Disposition::Translated {
            quoted_protocol,
            ..
        }) if quoted_protocol == expected_protocol
    ));
    assert_eq!(report.received, 1);
    assert_eq!(report.tx_requested, 1);
    assert_eq!(report.dropped, 0);
    assert!(report.invariants_hold());
    assert!(report.completion.invariants_hold());
}

fn run_nat_seed_forwarding(
    transport: PlainTransport,
    snapshot: &ForwardingSnapshot<'_>,
    udp_config: &Nat44UdpConfig,
    udp: &mut Nat44UdpRuntime<'_>,
    tcp_config: &Nat44TcpConfig,
    tcp: &mut Nat44TcpRuntime<'_>,
) {
    let mut rng = XorShift64::new(match transport {
        PlainTransport::Udp => 0x7365_6564_0000_0001,
        PlainTransport::Tcp => 0x7365_6564_0000_0002,
        PlainTransport::IcmpEcho => unreachable!("NAT seeds use UDP or TCP"),
    });
    let mut packet = plain_frame(transport, 60, &mut rng);
    let completion = Cell::new(None);
    let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
    let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        &mut resolution_states,
        &mut resolution_actions,
    );
    let report = forward_batch_with_nat44_udp_and_tcp(
        SinglePacketBatch {
            ingress: LAN,
            frame: Some(packet.as_mut_slice()),
            completion: &completion,
        },
        snapshot,
        &mut resolution,
        udp_config,
        Some(udp),
        tcp_config,
        Some(tcp),
        MonotonicMillis(1_000),
        &mut NoTrace,
    );
    assert_batch_invariants(&report.completion);
    assert!(report.invariants_hold());
    assert!(completion.get().is_some());
}

#[derive(Default)]
struct NatIcmpTrace {
    disposition: Option<Nat44Icmpv4Disposition>,
}

impl TraceSink for NatIcmpTrace {
    fn record(&mut self, event: TraceEvent) {
        if let TraceEvent::Nat44Icmpv4 { disposition, .. } = event {
            self.disposition = Some(disposition);
        }
    }
}

fn assert_batch_invariants(completion: &BatchCompletion<()>) {
    assert!(completion.invariants_hold());
    assert_eq!(
        completion.tx_accepted + completion.tx_rejected,
        completion.tx_requested
    );
}

struct SinglePacketSlot<'a> {
    ingress: IfId,
    frame: &'a mut [u8],
    completion: &'a Cell<Option<SlotCompletion>>,
}

impl PacketSlot for SinglePacketSlot<'_> {
    fn ingress(&self) -> IfId {
        self.ingress
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.frame
    }

    fn complete(self, completion: SlotCompletion) {
        assert!(self.completion.replace(Some(completion)).is_none());
    }
}

struct SinglePacketBatch<'a> {
    ingress: IfId,
    frame: Option<&'a mut [u8]>,
    completion: &'a Cell<Option<SlotCompletion>>,
}

impl PacketBatch for SinglePacketBatch<'_> {
    type Error = ();
    type Slot<'a>
        = SinglePacketSlot<'a>
    where
        Self: 'a;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        self.frame.take().map(|frame| {
            PacketLease::new(SinglePacketSlot {
                ingress: self.ingress,
                frame,
                completion: self.completion,
            })
        })
    }

    fn finish(self) -> BatchCompletion<Self::Error> {
        match self.completion.get() {
            Some(SlotCompletion::Transmit(_)) => BatchCompletion {
                tx_requested: 1,
                tx_accepted: 1,
                tx_rejected: 0,
                recycled: 0,
                error: None,
            },
            Some(SlotCompletion::Recycle(_))
            | Some(SlotCompletion::Consume(_))
            | Some(SlotCompletion::LeaseAbandoned) => BatchCompletion {
                tx_requested: 0,
                tx_accepted: 0,
                tx_rejected: 0,
                recycled: 1,
                error: None,
            },
            None => panic!("single packet batch finished without completing its slot"),
        }
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
            Route::new(
                Ipv4Address::from_octets([0, 0, 0, 0]),
                0,
                WAN,
                Some(GATEWAY),
            )
            .unwrap(),
        ],
        [
            Interface {
                id: LAN,
                mac: LAN_MAC,
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: WAN_MAC,
                mtu: Ipv4Mtu::ETHERNET,
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
                address: PUBLIC,
            },
        ],
    )
}

fn firewall_rules() -> [FirewallRule; 2] {
    let any_prefix = FirewallIpv4Prefix::new(Ipv4Address::from_octets([0, 0, 0, 0]), 0).unwrap();
    let any_ports = FirewallPortRange::new(0, u16::MAX).unwrap();
    [
        FirewallRule::new(
            FirewallRuleId(1),
            FirewallInterface::Interface(LAN),
            FirewallInterface::Interface(WAN),
            any_prefix,
            any_prefix,
            FirewallProtocol::Udp,
            any_ports,
            any_ports,
            FirewallAction::AllowStateful,
        ),
        FirewallRule::new(
            FirewallRuleId(2),
            FirewallInterface::Interface(LAN),
            FirewallInterface::Interface(WAN),
            any_prefix,
            any_prefix,
            FirewallProtocol::Tcp,
            any_ports,
            any_ports,
            FirewallAction::AllowStateful,
        ),
    ]
}

fn firewall_config<'a>(
    snapshot: &ForwardingSnapshot<'_>,
    rules: &'a [FirewallRule],
) -> FirewallConfig<'a> {
    FirewallConfig::new(
        snapshot,
        rules,
        FirewallPolicy::default(),
        1,
        FirewallHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap(),
    )
    .unwrap()
}

fn nat_config(snapshot: &ForwardingSnapshot<'_>) -> Nat44UdpConfig {
    Nat44UdpConfig::new(
        snapshot,
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44UdpPolicy::default().with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly),
    )
    .unwrap()
}

fn tcp_config(snapshot: &ForwardingSnapshot<'_>) -> Nat44TcpConfig {
    Nat44TcpConfig::new(
        snapshot,
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44TcpPolicy::default().with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly),
    )
    .unwrap()
}
