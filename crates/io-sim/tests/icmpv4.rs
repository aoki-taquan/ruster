use ruster_core::{
    execute_one_arp_request, forward_batch, forward_batch_with_resolution, internet_checksum,
    ipv4_header_checksum, BatchCompletion, ConsumeReason, DropReason, DynamicNeighborSlot,
    ForwardingSnapshot, IfId, Interface, Ipv4Address, Ipv4Mtu, Ipv4OriginPolicy,
    Ipv4OriginPolicyError, LocalIpv4Binding, MacAddress, MonotonicMillis, Neighbor,
    NoGeneratedTrace, NoTrace, PacketBatch, PacketIo, PacketLease, PacketSlot,
    ResolutionActionSlot, ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route,
    SlotCompletion, TraceEvent,
};
use ruster_io_sim::{RecycleCause, SimIo, VecTrace};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LOCAL_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
const PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x20];
const NEXT_HOP_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x30]);
const LOCAL_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const PEER_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 20]);

fn interfaces() -> [Interface; 2] {
    [
        Interface {
            id: LAN,
            mac: LOCAL_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        },
    ]
}

fn local_binding(interface: IfId) -> LocalIpv4Binding {
    LocalIpv4Binding {
        interface,
        address: LOCAL_IP,
    }
}

fn local_snapshot<'a>(
    interfaces: &'a [Interface],
    bindings: &'a [LocalIpv4Binding],
) -> ForwardingSnapshot<'a> {
    ForwardingSnapshot::new(&[], interfaces, &[], bindings).unwrap()
}

fn routed_snapshot<'a>(
    routes: &'a [Route],
    interfaces: &'a [Interface],
    neighbors: &'a [Neighbor],
    bindings: &'a [LocalIpv4Binding],
) -> ForwardingSnapshot<'a> {
    ForwardingSnapshot::new(routes, interfaces, neighbors, bindings).unwrap()
}

fn icmp_message(kind: u8, code: u8, payload: &[u8]) -> Vec<u8> {
    let mut message = vec![0_u8; 8 + payload.len()];
    message[0] = kind;
    message[1] = code;
    message[4..6].copy_from_slice(&0x4567_u16.to_be_bytes());
    message[6..8].copy_from_slice(&0x89ab_u16.to_be_bytes());
    message[8..].copy_from_slice(payload);
    let checksum = internet_checksum(&message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    message
}

fn ipv4_frame(
    destination: Ipv4Address,
    protocol: u8,
    ttl: u8,
    flags_fragment: u16,
    body: &[u8],
    padding: &[u8],
) -> Vec<u8> {
    let total_len = 20 + body.len();
    let mut frame = vec![0_u8; 14 + total_len + padding.len()];
    frame[0..6].copy_from_slice(&LOCAL_MAC.0);
    frame[6..12].copy_from_slice(&PEER_MAC);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = 0xb8;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    frame[22] = ttl;
    frame[23] = protocol;
    frame[26..30].copy_from_slice(&PEER_IP.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..34 + body.len()].copy_from_slice(body);
    frame[34 + body.len()..].copy_from_slice(padding);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn echo_request(payload: &[u8], padding: &[u8]) -> Vec<u8> {
    ipv4_frame(LOCAL_IP, 1, 1, 0, &icmp_message(8, 0, payload), padding)
}

fn echo_request_with_options() -> Vec<u8> {
    let mut frame = echo_request(&[1, 2], &[]);
    frame.splice(34..34, [1, 1, 0, 0]);
    frame[14] = 0x46;
    let total_len = u16::from_be_bytes([frame[16], frame[17]]) + 4;
    frame[16..18].copy_from_slice(&total_len.to_be_bytes());
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..38]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn arp_reply(sender: Ipv4Address, sender_mac: MacAddress) -> Vec<u8> {
    let mut frame = vec![0_u8; 60];
    frame[0..6].copy_from_slice(&LOCAL_MAC.0);
    frame[6..12].copy_from_slice(&sender_mac.0);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18..22].copy_from_slice(&[6, 4, 0, 2]);
    frame[22..28].copy_from_slice(&sender_mac.0);
    frame[28..32].copy_from_slice(&sender.octets());
    frame[32..38].copy_from_slice(&LOCAL_MAC.0);
    frame[38..42].copy_from_slice(&LOCAL_IP.octets());
    frame
}

fn with_ipv4_source(mut frame: Vec<u8>, source: Ipv4Address) -> Vec<u8> {
    frame[26..30].copy_from_slice(&source.octets());
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn assert_drop_atomic(frame: Vec<u8>, snapshot: &ForwardingSnapshot<'_>, expected: DropReason) {
    let original = frame.clone();
    let mut io = SimIo::new();
    io.inject(LAN, frame);
    let report = io.run_once(1, snapshot, &mut NoTrace).unwrap();
    assert_eq!(report.received, 1);
    assert_eq!(report.tx_requested, 0);
    assert_eq!(report.dropped, 1);
    assert_eq!(report.consumed, 0);
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(recycled.cause, RecycleCause::Forwarding(expected));
    assert_eq!(recycled.bytes, original, "drop must be byte-atomic");
}

#[test]
fn local_echo_reply_is_in_place_exact_and_traced() {
    let interfaces = interfaces();
    let bindings = [local_binding(LAN)];
    let snapshot = local_snapshot(&interfaces, &bindings);
    let padding = [0xde, 0xad, 0xbe, 0xef, 0x55];
    let request = echo_request(&[1, 2, 3, 4], &padding);
    let allocation = request.as_ptr();
    let mut io = SimIo::new();
    io.inject(LAN, request);
    let mut trace = VecTrace::default();

    let report = io.run_once(1, &snapshot, &mut trace).unwrap();

    assert_eq!(report.received, 1);
    assert_eq!(report.tx_requested, 1);
    assert_eq!(report.dropped, 0);
    assert_eq!(report.consumed, 0);
    assert_eq!(
        report.completion,
        BatchCompletion {
            tx_requested: 1,
            tx_accepted: 1,
            tx_rejected: 0,
            recycled: 0,
            error: None,
        }
    );
    let reply = io.pop_tx().unwrap();
    assert_eq!(
        reply.bytes.as_ptr(),
        allocation,
        "RX allocation must be reused"
    );
    assert_eq!(reply.ingress, LAN);
    assert_eq!(reply.egress, LAN);
    assert_eq!(&reply.bytes[0..6], &PEER_MAC);
    assert_eq!(&reply.bytes[6..12], &LOCAL_MAC.0);
    assert_eq!(reply.bytes[15], 0xb8, "DSCP/ECN is preserved");
    assert_eq!(&reply.bytes[18..20], &[0, 0], "atomic reply ID is zero");
    assert_eq!(&reply.bytes[20..22], &0x4000_u16.to_be_bytes());
    assert_eq!(reply.bytes[22], 64);
    assert_eq!(reply.bytes[23], 1);
    assert_eq!(&reply.bytes[26..30], &LOCAL_IP.octets());
    assert_eq!(&reply.bytes[30..34], &PEER_IP.octets());
    assert_eq!(ipv4_header_checksum(&reply.bytes[14..34]), 0);
    assert_eq!(reply.bytes[34], 0);
    assert_eq!(reply.bytes[35], 0);
    assert_eq!(&reply.bytes[38..40], &0x4567_u16.to_be_bytes());
    assert_eq!(&reply.bytes[40..42], &0x89ab_u16.to_be_bytes());
    let total_len = usize::from(u16::from_be_bytes([reply.bytes[16], reply.bytes[17]]));
    assert_eq!(internet_checksum(&reply.bytes[34..14 + total_len]), 0);
    assert_eq!(&reply.bytes[42..46], &[1, 2, 3, 4]);
    assert_eq!(&reply.bytes[14 + total_len..], &padding);
    assert!(matches!(
        trace.events(),
        [
            TraceEvent::Ipv4Validated {
                ingress: LAN,
                destination: LOCAL_IP
            },
            TraceEvent::Icmpv4EchoRequestValidated {
                ingress: LAN,
                source: PEER_IP,
                destination: LOCAL_IP
            },
            TraceEvent::Icmpv4EchoReplyRequested {
                egress: LAN,
                source: LOCAL_IP,
                destination: PEER_IP
            },
            TraceEvent::TxRequested { egress: LAN },
            TraceEvent::BatchCompleted {
                tx_accepted: 1,
                tx_rejected: 0
            }
        ]
    ));
}

#[test]
fn odd_length_echo_payload_checksum_and_ttl_zero_are_supported() {
    let interfaces = interfaces();
    let bindings = [local_binding(LAN)];
    let snapshot = local_snapshot(&interfaces, &bindings);
    let mut request = echo_request(&[0xa5], &[]);
    request[22] = 0;
    request[24..26].fill(0);
    let checksum = ipv4_header_checksum(&request[14..34]);
    request[24..26].copy_from_slice(&checksum.to_be_bytes());
    let mut io = SimIo::new();
    io.inject(LAN, request);

    let report = io.run_once(1, &snapshot, &mut NoTrace).unwrap();

    assert_eq!(report.tx_requested, 1);
    let reply = io.pop_tx().unwrap();
    assert_eq!(reply.bytes[22], 64);
    assert_eq!(reply.bytes[42], 0xa5);
    assert_eq!(internet_checksum(&reply.bytes[34..43]), 0);
}

#[test]
fn configured_origin_ttl_is_validated_and_used_for_echo_reply() {
    assert_eq!(
        Ipv4OriginPolicy::new(0),
        Err(Ipv4OriginPolicyError::DefaultTtlZero)
    );
    assert_eq!(Ipv4OriginPolicy::default().default_ttl(), 64);
    let interfaces = interfaces();
    let bindings = [local_binding(LAN)];
    let snapshot = ForwardingSnapshot::with_ipv4_origin_policy(
        &[],
        &interfaces,
        &[],
        &bindings,
        Ipv4OriginPolicy::new(37).unwrap(),
    )
    .unwrap();
    let mut io = SimIo::new();
    io.inject(LAN, echo_request(&[], &[]));

    assert_eq!(
        io.run_once(1, &snapshot, &mut NoTrace)
            .unwrap()
            .tx_requested,
        1
    );
    let reply = io.pop_tx().unwrap();
    assert_eq!(reply.bytes[22], 37);
    assert_eq!(ipv4_header_checksum(&reply.bytes[14..34]), 0);
}

#[test]
fn local_echo_with_ipv4_options_is_an_atomic_documented_deviation() {
    let interfaces = interfaces();
    let bindings = [local_binding(LAN)];
    let snapshot = local_snapshot(&interfaces, &bindings);
    assert_drop_atomic(
        echo_request_with_options(),
        &snapshot,
        DropReason::Ipv4OptionsUnsupported,
    );
}

#[test]
fn exact_icmp_truncation_boundaries_have_stable_atomic_reasons() {
    let interfaces = interfaces();
    let bindings = [local_binding(LAN)];
    let snapshot = local_snapshot(&interfaces, &bindings);

    for body_len in 0..4 {
        assert_drop_atomic(
            ipv4_frame(LOCAL_IP, 1, 64, 0, &vec![0; body_len], &[]),
            &snapshot,
            DropReason::Icmpv4HeaderTruncated,
        );
    }
    for body_len in 4..8 {
        let mut body = vec![0; body_len];
        body[0] = 8;
        assert_drop_atomic(
            ipv4_frame(LOCAL_IP, 1, 64, 0, &body, &[]),
            &snapshot,
            DropReason::Icmpv4EchoHeaderTruncated,
        );
    }
    let mut io = SimIo::new();
    io.inject(LAN, echo_request(&[], &[]));
    assert_eq!(
        io.run_once(1, &snapshot, &mut NoTrace)
            .unwrap()
            .tx_requested,
        1
    );
}

#[test]
fn invalid_ipv4_or_icmp_checksum_and_nonzero_echo_code_are_atomic() {
    let interfaces = interfaces();
    let bindings = [local_binding(LAN)];
    let snapshot = local_snapshot(&interfaces, &bindings);

    let mut bad_ip = echo_request(&[1, 2], &[]);
    bad_ip[24] ^= 1;
    assert_drop_atomic(bad_ip, &snapshot, DropReason::Ipv4HeaderChecksumInvalid);

    let mut bad_icmp = echo_request(&[1, 2], &[]);
    bad_icmp[36] ^= 1;
    assert_drop_atomic(bad_icmp, &snapshot, DropReason::Icmpv4ChecksumInvalid);

    let bad_code = ipv4_frame(LOCAL_IP, 1, 64, 0, &icmp_message(8, 1, &[]), &[]);
    assert_drop_atomic(bad_code, &snapshot, DropReason::Icmpv4EchoCodeInvalid);
}

#[test]
fn local_echo_fragments_are_typed_atomic_drops() {
    let interfaces = interfaces();
    let bindings = [local_binding(LAN)];
    let snapshot = local_snapshot(&interfaces, &bindings);
    for flags_fragment in [0x2000, 0x0001, 0x6000] {
        assert_drop_atomic(
            ipv4_frame(
                LOCAL_IP,
                1,
                64,
                flags_fragment,
                &icmp_message(8, 0, &[]),
                &[],
            ),
            &snapshot,
            DropReason::Icmpv4FragmentUnsupported,
        );
    }
}

#[test]
fn local_echo_reserved_flag_is_accepted_and_cleared_in_reply() {
    let interfaces = interfaces();
    let bindings = [local_binding(LAN)];
    let snapshot = local_snapshot(&interfaces, &bindings);
    let mut io = SimIo::new();
    io.inject(
        LAN,
        ipv4_frame(LOCAL_IP, 1, 64, 0x8000, &icmp_message(8, 0, &[]), &[]),
    );

    let report = io.run_once(1, &snapshot, &mut NoTrace).unwrap();

    assert_eq!(report.tx_requested, 1);
    assert_eq!(report.dropped, 0);
    let reply = io.pop_tx().unwrap();
    assert_eq!(&reply.bytes[18..20], &[0, 0]);
    assert_eq!(&reply.bytes[20..22], &0x4000_u16.to_be_bytes());
    assert_eq!(ipv4_header_checksum(&reply.bytes[14..34]), 0);
    assert_eq!(reply.bytes[34], 0);
    assert_eq!(internet_checksum(&reply.bytes[34..42]), 0);
}

#[test]
fn invalid_echo_ipv4_sources_cannot_trigger_replies() {
    let interfaces = interfaces();
    let routes = [Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, LAN, None).unwrap()];
    let bindings = [local_binding(LAN)];
    let snapshot = routed_snapshot(&routes, &interfaces, &[], &bindings);
    let invalid_sources = [
        (
            Ipv4Address::from_octets([0, 0, 0, 1]),
            DropReason::Ipv4SourceUnspecifiedNetwork,
        ),
        (
            Ipv4Address::from_octets([127, 0, 0, 1]),
            DropReason::Ipv4SourceLoopback,
        ),
        (
            Ipv4Address::from_octets([224, 0, 0, 1]),
            DropReason::Ipv4SourceMulticast,
        ),
        (
            Ipv4Address::from_octets([240, 0, 0, 1]),
            DropReason::Ipv4SourceClassE,
        ),
        (
            Ipv4Address::from_octets([255, 255, 255, 255]),
            DropReason::Ipv4SourceLimitedBroadcast,
        ),
        (
            Ipv4Address::from_octets([192, 0, 2, 0]),
            DropReason::Ipv4SourceNetworkAddress,
        ),
        (
            Ipv4Address::from_octets([192, 0, 2, 255]),
            DropReason::Ipv4SourceDirectedBroadcast,
        ),
        (LOCAL_IP, DropReason::Ipv4SourceLocalAddress),
    ];

    for (source, reason) in invalid_sources {
        assert_drop_atomic(
            with_ipv4_source(echo_request(&[], &[]), source),
            &snapshot,
            reason,
        );
    }
}

#[test]
fn echo_requires_unicast_source_mac_and_exact_local_destination_mac() {
    let interfaces = interfaces();
    let bindings = [local_binding(LAN)];
    let snapshot = local_snapshot(&interfaces, &bindings);

    for (source, reason) in [
        ([0; 6], DropReason::Ipv4EthernetSourceZero),
        ([0xff; 6], DropReason::Ipv4EthernetSourceBroadcast),
        (
            [0x01, 0, 0, 0, 0, 1],
            DropReason::Ipv4EthernetSourceMulticast,
        ),
    ] {
        let mut frame = echo_request(&[], &[]);
        frame[6..12].copy_from_slice(&source);
        assert_drop_atomic(frame, &snapshot, reason);
    }

    for (destination, reason) in [
        ([0xff; 6], DropReason::Ipv4EthernetDestinationBroadcast),
        (
            [0x01, 0, 0, 0, 0, 1],
            DropReason::Ipv4EthernetDestinationMulticast,
        ),
        (
            [0x02, 0, 0, 0, 0, 9],
            DropReason::EthernetDestinationNotLocal,
        ),
    ] {
        let mut frame = echo_request(&[], &[]);
        frame[0..6].copy_from_slice(&destination);
        assert_drop_atomic(frame, &snapshot, reason);
    }
}

#[test]
fn local_address_matching_is_strictly_ingress_scoped() {
    let interfaces = interfaces();
    let routes = [Route::new(LOCAL_IP, 32, LAN, None).unwrap()];
    let neighbors = [Neighbor {
        interface: LAN,
        target: LOCAL_IP,
        mac: NEXT_HOP_MAC,
    }];
    let bindings = [local_binding(WAN)];
    let snapshot = routed_snapshot(&routes, &interfaces, &neighbors, &bindings);
    let mut io = SimIo::new();
    io.inject(
        LAN,
        ipv4_frame(LOCAL_IP, 1, 64, 0, &icmp_message(8, 0, &[1]), &[]),
    );

    let report = io.run_once(1, &snapshot, &mut NoTrace).unwrap();

    assert_eq!(report.tx_requested, 1);
    let forwarded = io.pop_tx().unwrap();
    assert_eq!(forwarded.egress, LAN);
    assert_eq!(&forwarded.bytes[0..6], &NEXT_HOP_MAC.0);
    assert_eq!(&forwarded.bytes[6..12], &LOCAL_MAC.0);
    assert_eq!(forwarded.bytes[22], 63);
    assert_eq!(forwarded.bytes[34], 8, "nonlocal ICMP is not intercepted");
}

#[test]
fn valid_unsupported_local_traffic_is_consumed_without_routing() {
    let interfaces = interfaces();
    let bindings = [local_binding(LAN)];
    let snapshot = local_snapshot(&interfaces, &bindings);
    // RFC 1812 §4.3.3.3: a locally-addressed TCP segment gets no ICMP
    // response (a closed port answers with RST at the transport layer), so
    // TCP is still the one protocol this router silently consumes.
    let tcp = ipv4_frame(LOCAL_IP, 6, 64, 0, &[0; 8], &[]);
    let unreachable = ipv4_frame(LOCAL_IP, 1, 64, 0, &icmp_message(3, 0, &[]), &[]);
    let originals = [tcp.clone(), unreachable.clone()];
    let mut io = SimIo::new();
    io.inject(LAN, tcp);
    io.inject(LAN, unreachable);
    let mut trace = VecTrace::default();

    let report = io.run_once(2, &snapshot, &mut trace).unwrap();

    assert_eq!(report.received, 2);
    assert_eq!(report.tx_requested, 0);
    assert_eq!(report.dropped, 0);
    assert_eq!(report.consumed, 2);
    assert_eq!(
        report.completion,
        BatchCompletion {
            tx_requested: 0,
            tx_accepted: 0,
            tx_rejected: 0,
            recycled: 2,
            error: None,
        }
    );
    for original in originals {
        let recycled = io.pop_recycled().unwrap();
        assert_eq!(
            recycled.cause,
            RecycleCause::Consumed(ConsumeReason::Ipv4LocalUnsupported)
        );
        assert_eq!(recycled.bytes, original);
    }
    assert!(matches!(
        trace.events(),
        [
            TraceEvent::Ipv4Validated {
                ingress: LAN,
                destination: LOCAL_IP
            },
            TraceEvent::Ipv4LocalConsumed {
                ingress: LAN,
                reason: ConsumeReason::Ipv4LocalUnsupported
            },
            TraceEvent::Ipv4Validated {
                ingress: LAN,
                destination: LOCAL_IP
            },
            TraceEvent::Ipv4LocalConsumed {
                ingress: LAN,
                reason: ConsumeReason::Ipv4LocalUnsupported
            },
            TraceEvent::BatchCompleted {
                tx_accepted: 0,
                tx_rejected: 0
            }
        ]
    ));
}

#[test]
fn valid_udp_to_a_local_address_is_dropped_port_unreachable_without_routing() {
    let interfaces = interfaces();
    let bindings = [local_binding(LAN)];
    let snapshot = local_snapshot(&interfaces, &bindings);
    let udp = ipv4_frame(LOCAL_IP, 17, 64, 0, &[0; 8], &[]);
    let original = udp.clone();
    let mut io = SimIo::new();
    io.inject(LAN, udp);
    let mut trace = VecTrace::default();

    let report = io.run_once(1, &snapshot, &mut trace).unwrap();

    assert_eq!(report.received, 1);
    assert_eq!(report.tx_requested, 0);
    assert_eq!(report.dropped, 1);
    assert_eq!(report.consumed, 0);
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::Icmpv4PortUnreachable)
    );
    assert_eq!(recycled.bytes, original);
    assert!(matches!(
        trace.events(),
        [
            TraceEvent::Ipv4Validated {
                ingress: LAN,
                destination: LOCAL_IP
            },
            TraceEvent::Dropped {
                ingress: LAN,
                reason: DropReason::Icmpv4PortUnreachable
            },
            TraceEvent::BatchCompleted {
                tx_accepted: 0,
                tx_rejected: 0
            }
        ]
    ));
}

#[test]
fn local_echo_and_consume_leave_resolution_runtime_untouched() {
    let interfaces = interfaces();
    let routes = [Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, LAN, None).unwrap()];
    let bindings = [local_binding(LAN)];
    let snapshot = routed_snapshot(&routes, &interfaces, &[], &bindings);
    let first = Ipv4Address::from_octets([192, 0, 2, 21]);
    let second = Ipv4Address::from_octets([192, 0, 2, 22]);
    let third = Ipv4Address::from_octets([192, 0, 2, 23]);
    let learned = Ipv4Address::from_octets([192, 0, 2, 24]);
    let mut states = [ResolutionStateSlot::EMPTY; 3];
    let mut actions = [ResolutionActionSlot::EMPTY; 3];
    let mut cache = [DynamicNeighborSlot::EMPTY; 1];
    let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        &mut states,
        &mut actions,
        &mut cache,
    );
    let mut io = SimIo::new();

    io.inject(LAN, arp_reply(learned, NEXT_HOP_MAC));
    let batch = io.receive(1).unwrap();
    forward_batch_with_resolution(
        batch,
        &snapshot,
        &mut runtime,
        MonotonicMillis(100),
        &mut NoTrace,
    );
    io.pop_recycled();
    for target in [first, second] {
        io.inject(LAN, ipv4_frame(target, 17, 64, 0, &[0; 8], &[]));
    }
    let batch = io.receive(2).unwrap();
    forward_batch_with_resolution(
        batch,
        &snapshot,
        &mut runtime,
        MonotonicMillis(100),
        &mut NoTrace,
    );
    io.pop_recycled();
    io.pop_recycled();
    let counters_before = runtime.counters();
    assert_eq!(runtime.dynamic_neighbor_count(), 1);
    assert_eq!(runtime.pending_actions(), 2);

    io.inject(LAN, echo_request(&[], &[]));
    // RFC 1812 §4.3.3.3: a locally-addressed UDP datagram now draws Port
    // Unreachable, so it is dropped rather than silently consumed.
    io.inject(LAN, ipv4_frame(LOCAL_IP, 17, 64, 0, &[0; 8], &[]));
    let batch = io.receive(2).unwrap();
    let local = forward_batch_with_resolution(
        batch,
        &snapshot,
        &mut runtime,
        MonotonicMillis(200),
        &mut NoTrace,
    );

    assert_eq!(
        (
            local.tx_requested,
            local.consumed,
            local.dropped,
            runtime.dynamic_neighbor_count(),
            runtime.pending_actions(),
            runtime.counters()
        ),
        (1, 0, 1, 1, 2, counters_before)
    );
    io.pop_tx();
    io.pop_recycled();

    io.inject(LAN, ipv4_frame(learned, 17, 64, 0, &[0; 8], &[]));
    let batch = io.receive(1).unwrap();
    let learned_forward = forward_batch_with_resolution(
        batch,
        &snapshot,
        &mut runtime,
        MonotonicMillis(150),
        &mut NoTrace,
    );
    assert_eq!(learned_forward.tx_requested, 1);
    assert_eq!(&io.pop_tx().unwrap().bytes[0..6], &NEXT_HOP_MAC.0);
    assert_eq!(runtime.dynamic_neighbor_count(), 1);
    assert_eq!(runtime.pending_actions(), 2);
    assert_eq!(runtime.counters(), counters_before);

    io.inject(LAN, ipv4_frame(third, 17, 64, 0, &[0; 8], &[]));
    let batch = io.receive(1).unwrap();
    let after = forward_batch_with_resolution(
        batch,
        &snapshot,
        &mut runtime,
        MonotonicMillis(150),
        &mut NoTrace,
    );
    assert_eq!(after.dropped, 1);
    assert_eq!(runtime.pending_actions(), 3);
    assert_eq!(runtime.counters().clock_regressions, 0);

    for expected in [first, second, third] {
        let generated = execute_one_arp_request(
            &mut io,
            &mut runtime,
            MonotonicMillis(150),
            &mut NoGeneratedTrace,
        )
        .unwrap()
        .unwrap();
        assert_eq!(generated.action.target_ip, expected);
    }
    assert_eq!(runtime.pending_actions(), 0);
    assert_eq!(runtime.dynamic_neighbor_count(), 1);
}

#[test]
fn malformed_unsupported_local_icmp_checksum_is_dropped() {
    let interfaces = interfaces();
    let bindings = [local_binding(LAN)];
    let snapshot = local_snapshot(&interfaces, &bindings);
    let mut frame = ipv4_frame(LOCAL_IP, 1, 64, 0, &icmp_message(3, 0, &[]), &[]);
    frame[36] ^= 1;
    assert_drop_atomic(frame, &snapshot, DropReason::Icmpv4ChecksumInvalid);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RejectError {
    RingFull,
}

struct RejectBatch {
    packet: Option<Vec<u8>>,
}

struct RejectSlot {
    bytes: Vec<u8>,
}

impl PacketSlot for RejectSlot {
    fn ingress(&self) -> IfId {
        LAN
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    fn complete(self, completion: SlotCompletion) {
        assert_eq!(completion, SlotCompletion::Transmit(LAN));
        assert_eq!(self.bytes[34], 0);
        assert_eq!(internet_checksum(&self.bytes[34..]), 0);
    }
}

impl PacketBatch for RejectBatch {
    type Error = RejectError;
    type Slot<'a> = RejectSlot;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        self.packet
            .take()
            .map(|bytes| PacketLease::new(RejectSlot { bytes }))
    }

    fn finish(self) -> BatchCompletion<Self::Error> {
        BatchCompletion {
            tx_requested: 1,
            tx_accepted: 0,
            tx_rejected: 1,
            recycled: 0,
            error: Some(RejectError::RingFull),
        }
    }
}

#[test]
fn echo_partial_backend_rejection_preserves_lifecycle_and_trace() {
    let interfaces = interfaces();
    let bindings = [local_binding(LAN)];
    let snapshot = local_snapshot(&interfaces, &bindings);
    let batch = RejectBatch {
        packet: Some(echo_request(&[1, 2], &[])),
    };
    let mut trace = VecTrace::default();

    let report = forward_batch(batch, &snapshot, &mut trace);

    assert_eq!(report.received, 1);
    assert_eq!(report.tx_requested, 1);
    assert_eq!(report.dropped, 0);
    assert_eq!(report.consumed, 0);
    assert_eq!(report.completion.tx_accepted, 0);
    assert_eq!(report.completion.tx_rejected, 1);
    assert_eq!(report.completion.error, Some(RejectError::RingFull));
    assert!(matches!(
        trace.events(),
        [
            TraceEvent::Ipv4Validated { .. },
            TraceEvent::Icmpv4EchoRequestValidated { .. },
            TraceEvent::Icmpv4EchoReplyRequested { egress: LAN, .. },
            TraceEvent::TxRequested { egress: LAN },
            TraceEvent::BatchCompleted {
                tx_accepted: 0,
                tx_rejected: 1
            }
        ]
    ));
}
