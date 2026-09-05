use ruster_core::{
    forward_batch, ipv4_header_checksum, validate_ipv4_frame, BatchCompletion, ConsumeReason,
    DropReason, ForwardingSnapshot, IfId, Interface, Ipv4Address, Ipv4Mtu, LocalIpv4Binding,
    MacAddress, Neighbor, NoTrace, PacketBatch, PacketIo, PacketLease, PacketSlot, Route,
    SlotCompletion, SnapshotError, TraceEvent, ETHERNET_HEADER_LEN,
};
use ruster_io_sim::{RecycleCause, SimIo, VecTrace};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x10]);
const ROUTER_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
const NEXT_HOP_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 3]);
const ORIGINAL_DST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 9];
const ORIGINAL_SRC_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const REQUESTER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x20];
const FOREIGN_ETHERNET_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x21];
const LOCAL_IPV4: [u8; 4] = [192, 0, 2, 1];
const REQUESTER_IPV4: [u8; 4] = [192, 0, 2, 20];
const DESTINATION: [u8; 4] = [198, 51, 100, 20];
const GATEWAY: [u8; 4] = [203, 0, 113, 1];

fn ip(octets: [u8; 4]) -> Ipv4Address {
    Ipv4Address::from_octets(octets)
}

fn route(prefix: [u8; 4], prefix_len: u8, egress: IfId, next_hop: Option<[u8; 4]>) -> Route {
    Route::new(ip(prefix), prefix_len, egress, next_hop.map(ip)).unwrap()
}

fn interface() -> Interface {
    Interface {
        id: WAN,
        mac: ROUTER_MAC,
        mtu: Ipv4Mtu::ETHERNET,
    }
}

fn gateway_route() -> Route {
    route([0, 0, 0, 0], 0, WAN, Some(GATEWAY))
}

fn gateway_neighbor() -> Neighbor {
    Neighbor {
        interface: WAN,
        target: ip(GATEWAY),
        mac: NEXT_HOP_MAC,
    }
}

fn local_interface() -> Interface {
    Interface {
        id: LAN,
        mac: LAN_MAC,
        mtu: Ipv4Mtu::ETHERNET,
    }
}

fn local_binding() -> LocalIpv4Binding {
    LocalIpv4Binding {
        interface: LAN,
        address: ip(LOCAL_IPV4),
    }
}

fn arp_frame(
    opcode: u16,
    sender_protocol: [u8; 4],
    target_protocol: [u8; 4],
    ethernet_source: [u8; 6],
    sender_hardware: [u8; 6],
    target_hardware: [u8; 6],
    tail: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0_u8; 42 + tail.len()];
    bytes[0..6].copy_from_slice(&[0xff; 6]);
    bytes[6..12].copy_from_slice(&ethernet_source);
    bytes[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    bytes[14..16].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[18] = 6;
    bytes[19] = 4;
    bytes[20..22].copy_from_slice(&opcode.to_be_bytes());
    bytes[22..28].copy_from_slice(&sender_hardware);
    bytes[28..32].copy_from_slice(&sender_protocol);
    bytes[32..38].copy_from_slice(&target_hardware);
    bytes[38..42].copy_from_slice(&target_protocol);
    bytes[42..].copy_from_slice(tail);
    bytes
}

fn arp_snapshot<'a>(
    interfaces: &'a [Interface],
    bindings: &'a [LocalIpv4Binding],
) -> ForwardingSnapshot<'a> {
    ForwardingSnapshot::new(&[], interfaces, &[], bindings).unwrap()
}

fn frame(ttl: u8, payload: &[u8]) -> Vec<u8> {
    frame_with_options(ttl, payload, &[])
}

fn frame_with_options(ttl: u8, payload: &[u8], options: &[u8]) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0);
    let header_len = 20 + options.len();
    let total_len = header_len + payload.len();
    let mut bytes = vec![0_u8; ETHERNET_HEADER_LEN + total_len];
    bytes[0..6].copy_from_slice(&LAN_MAC.0);
    bytes[6..12].copy_from_slice(&ORIGINAL_SRC_MAC);
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    let ip = ETHERNET_HEADER_LEN;
    bytes[ip] = (4 << 4) | u8::try_from(header_len / 4).unwrap();
    bytes[ip + 2..ip + 4].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    bytes[ip + 4..ip + 6].copy_from_slice(&0x1234_u16.to_be_bytes());
    bytes[ip + 6..ip + 8].copy_from_slice(&0x4000_u16.to_be_bytes());
    bytes[ip + 8] = ttl;
    bytes[ip + 9] = 17;
    bytes[ip + 12..ip + 16].copy_from_slice(&[192, 0, 2, 10]);
    bytes[ip + 16..ip + 20].copy_from_slice(&DESTINATION);
    bytes[ip + 20..ip + header_len].copy_from_slice(options);
    bytes[ip + header_len..].copy_from_slice(payload);
    let checksum = ipv4_header_checksum(&bytes[ip..ip + header_len]);
    bytes[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn assert_forwarding_drop(
    packet: Vec<u8>,
    snapshot: &ForwardingSnapshot<'_>,
    expected: DropReason,
) {
    let original = packet.clone();
    let mut io = SimIo::new();
    io.inject(LAN, packet);
    let report = io.run_once(1, snapshot, &mut NoTrace).unwrap();
    assert_eq!(report.dropped, 1);
    assert_eq!(
        report.completion,
        BatchCompletion {
            tx_requested: 0,
            tx_accepted: 0,
            tx_rejected: 0,
            recycled: 1,
            error: None,
        }
    );
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(recycled.cause, RecycleCause::Forwarding(expected));
    assert_eq!(recycled.bytes, original, "drop must not mutate bytes");
}

fn with_ipv4_addresses(mut packet: Vec<u8>, source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    packet[26..30].copy_from_slice(&source);
    packet[30..34].copy_from_slice(&destination);
    packet[24..26].fill(0);
    let header_len = usize::from(packet[14] & 0x0f) * 4;
    let checksum = ipv4_header_checksum(&packet[14..14 + header_len]);
    packet[24..26].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn assert_arp_control_consumed(packet: Vec<u8>, snapshot: &ForwardingSnapshot<'_>) {
    let original = packet.clone();
    let mut io = SimIo::new();
    io.inject(LAN, packet);
    let report = io.run_once(1, snapshot, &mut NoTrace).unwrap();
    assert_eq!(report.dropped, 0);
    assert_eq!(report.consumed, 1);
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Consumed(ConsumeReason::ArpControl)
    );
    assert_eq!(recycled.bytes, original);
}

#[test]
fn ipv4_ingress_admission_matrix_is_typed_and_atomic() {
    let routes = [
        route([192, 0, 2, 0], 24, WAN, Some(GATEWAY)),
        route([198, 51, 100, 0], 24, WAN, Some(GATEWAY)),
    ];
    let interfaces = [local_interface(), interface()];
    let neighbors = [gateway_neighbor()];
    let bindings = [local_binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let base = frame(64, &[]);

    let mut cases = Vec::new();
    for (source, reason) in [
        ([0; 6], DropReason::Ipv4EthernetSourceZero),
        ([0xff; 6], DropReason::Ipv4EthernetSourceBroadcast),
        (
            [0x01, 0, 0, 0, 0, 1],
            DropReason::Ipv4EthernetSourceMulticast,
        ),
    ] {
        let mut packet = base.clone();
        packet[6..12].copy_from_slice(&source);
        cases.push((packet, reason));
    }
    for (destination, reason) in [
        ([0; 6], DropReason::Ipv4EthernetDestinationZero),
        ([0xff; 6], DropReason::Ipv4EthernetDestinationBroadcast),
        (
            [0x01, 0, 0, 0, 0, 1],
            DropReason::Ipv4EthernetDestinationMulticast,
        ),
        (ORIGINAL_DST_MAC, DropReason::EthernetDestinationNotLocal),
    ] {
        let mut packet = base.clone();
        packet[0..6].copy_from_slice(&destination);
        cases.push((packet, reason));
    }
    for (source, reason) in [
        ([0, 1, 2, 3], DropReason::Ipv4SourceUnspecifiedNetwork),
        ([127, 0, 0, 1], DropReason::Ipv4SourceLoopback),
        ([224, 0, 0, 1], DropReason::Ipv4SourceMulticast),
        ([240, 0, 0, 1], DropReason::Ipv4SourceClassE),
        ([255; 4], DropReason::Ipv4SourceLimitedBroadcast),
        (LOCAL_IPV4, DropReason::Ipv4SourceLocalAddress),
        ([192, 0, 2, 0], DropReason::Ipv4SourceNetworkAddress),
        ([192, 0, 2, 255], DropReason::Ipv4SourceDirectedBroadcast),
    ] {
        cases.push((
            with_ipv4_addresses(base.clone(), source, DESTINATION),
            reason,
        ));
    }
    for (destination, reason) in [
        ([0, 1, 2, 3], DropReason::Ipv4DestinationUnspecifiedNetwork),
        ([127, 0, 0, 1], DropReason::Ipv4DestinationLoopback),
        ([224, 0, 0, 1], DropReason::Ipv4DestinationMulticast),
        ([255; 4], DropReason::Ipv4DestinationLimitedBroadcast),
        ([240, 0, 0, 1], DropReason::Ipv4DestinationClassE),
        ([198, 51, 100, 0], DropReason::Ipv4DestinationNetworkAddress),
        (
            [198, 51, 100, 255],
            DropReason::Ipv4DestinationDirectedBroadcast,
        ),
    ] {
        cases.push((
            with_ipv4_addresses(base.clone(), [192, 0, 2, 10], destination),
            reason,
        ));
    }
    for (packet, reason) in cases {
        assert_forwarding_drop(packet, &snapshot, reason);
    }

    let original = base.clone();
    let mut io = SimIo::new();
    io.inject(IfId(99), base);
    let report = io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    assert_eq!((report.tx_requested, report.dropped), (0, 1));
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::Ipv4IngressInterfaceUnknown)
    );
    assert_eq!(recycled.bytes, original);
}

#[test]
fn ethernet_ingress_exact_mac_and_arp_broadcast_exception_are_atomic() {
    let interfaces = [local_interface(), interface()];
    let bindings = [local_binding()];
    let snapshot = arp_snapshot(&interfaces, &bindings);
    let request = arp_frame(
        1,
        REQUESTER_IPV4,
        LOCAL_IPV4,
        REQUESTER_MAC,
        REQUESTER_MAC,
        [0; 6],
        &[],
    );

    let mut wrong_unicast = request.clone();
    wrong_unicast[0..6].copy_from_slice(&ROUTER_MAC.0);
    assert_forwarding_drop(
        wrong_unicast,
        &snapshot,
        DropReason::EthernetDestinationNotLocal,
    );

    for (source, reason) in [
        ([0; 6], DropReason::ArpEthernetSourceZero),
        ([0xff; 6], DropReason::ArpEthernetSourceBroadcast),
        (
            [0x01, 0, 0, 0, 0, 1],
            DropReason::ArpEthernetSourceMulticast,
        ),
    ] {
        let mut packet = request.clone();
        packet[6..12].copy_from_slice(&source);
        assert_forwarding_drop(packet, &snapshot, reason);
    }
    for (destination, reason) in [
        ([0; 6], DropReason::ArpEthernetDestinationZero),
        (
            [0x01, 0, 0, 0, 0, 1],
            DropReason::ArpEthernetDestinationMulticast,
        ),
    ] {
        let mut packet = request.clone();
        packet[0..6].copy_from_slice(&destination);
        assert_forwarding_drop(packet, &snapshot, reason);
    }

    let mut io = SimIo::new();
    io.inject(LAN, request);
    let report = io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    assert_eq!((report.tx_requested, report.dropped), (1, 0));
    assert_eq!(&io.pop_tx().unwrap().bytes[6..12], &LAN_MAC.0);

    let unknown = arp_frame(
        1,
        REQUESTER_IPV4,
        LOCAL_IPV4,
        REQUESTER_MAC,
        REQUESTER_MAC,
        [0; 6],
        &[],
    );
    let original = unknown.clone();
    io.inject(IfId(99), unknown);
    let report = io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    assert_eq!((report.tx_requested, report.dropped), (0, 1));
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::ArpIngressInterfaceUnknown)
    );
    assert_eq!(recycled.bytes, original);
}

#[test]
fn point_to_point_and_host_route_endpoints_pass_ipv4_ingress_admission() {
    let host_destination = [198, 51, 100, 22];
    let routes = [
        route([198, 51, 100, 20], 31, WAN, None),
        route(host_destination, 32, WAN, None),
    ];
    let interfaces = [local_interface(), interface()];
    let neighbors = [
        Neighbor {
            interface: WAN,
            target: ip([198, 51, 100, 20]),
            mac: NEXT_HOP_MAC,
        },
        Neighbor {
            interface: WAN,
            target: ip([198, 51, 100, 21]),
            mac: NEXT_HOP_MAC,
        },
        Neighbor {
            interface: WAN,
            target: ip(host_destination),
            mac: NEXT_HOP_MAC,
        },
    ];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &[]).unwrap();
    let mut io = SimIo::new();
    for destination in [[198, 51, 100, 20], [198, 51, 100, 21], host_destination] {
        io.inject(
            LAN,
            with_ipv4_addresses(frame(64, &[]), [192, 0, 2, 10], destination),
        );
    }
    let report = io.run_once(3, &snapshot, &mut NoTrace).unwrap();
    assert_eq!((report.tx_requested, report.dropped), (3, 0));
    for _ in 0..3 {
        assert_eq!(io.pop_tx().unwrap().egress, WAN);
    }
}

#[test]
fn gateway_route_rewrites_and_reports_backend_acceptance() {
    let routes = [gateway_route()];
    let interfaces = [local_interface(), interface()];
    let neighbors = [gateway_neighbor()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &[]).unwrap();
    let packet = frame(64, &[1, 2, 3, 4]);
    let allocation = packet.as_ptr();
    let mut io = SimIo::new();
    io.inject(LAN, packet);

    let report = io.run_once(32, &snapshot, &mut NoTrace).unwrap();
    assert_eq!(report.received, 1);
    assert_eq!(report.tx_requested, 1);
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
    let tx = io.pop_tx().unwrap();
    assert_eq!(tx.bytes.as_ptr(), allocation, "RX Vec must move, not clone");
    assert_eq!(&tx.bytes[0..6], &NEXT_HOP_MAC.0);
    assert_eq!(&tx.bytes[6..12], &ROUTER_MAC.0);
    assert_eq!(tx.bytes[22], 63);
    assert_eq!(ipv4_header_checksum(&tx.bytes[14..34]), 0);
}

#[test]
fn connected_route_uses_packet_destination_as_neighbor_target() {
    let routes = [route([198, 51, 100, 0], 24, WAN, None)];
    let interfaces = [local_interface(), interface()];
    let neighbors = [Neighbor {
        interface: WAN,
        target: ip(DESTINATION),
        mac: NEXT_HOP_MAC,
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &[]).unwrap();
    let mut io = SimIo::new();
    io.inject(LAN, frame(10, &[]));
    let report = io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    assert_eq!(report.tx_requested, 1);
    assert_eq!(io.pop_tx().unwrap().egress, WAN);
}

#[test]
fn lpm_supports_default_and_host_routes() {
    let routes = [gateway_route(), route(DESTINATION, 32, IfId(3), None)];
    let interfaces = [
        local_interface(),
        interface(),
        Interface {
            id: IfId(3),
            mac: MacAddress([3; 6]),
            mtu: Ipv4Mtu::ETHERNET,
        },
    ];
    let neighbors = [
        gateway_neighbor(),
        Neighbor {
            interface: IfId(3),
            target: ip(DESTINATION),
            mac: MacAddress([4; 6]),
        },
    ];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &[]).unwrap();
    let mut io = SimIo::new();
    io.inject(LAN, frame(9, &[]));
    io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    assert_eq!(io.pop_tx().unwrap().egress, IfId(3));
}

#[test]
fn snapshot_constructor_rejects_all_broken_references_and_duplicates() {
    let known_interfaces = [interface()];
    let duplicate_routes = [gateway_route(), gateway_route()];
    assert!(matches!(
        ForwardingSnapshot::new(
            &duplicate_routes,
            &known_interfaces,
            &[gateway_neighbor()],
            &[]
        ),
        Err(SnapshotError::DuplicateRoute)
    ));
    let duplicate_interfaces = [interface(), interface()];
    assert!(matches!(
        ForwardingSnapshot::new(&[], &duplicate_interfaces, &[], &[]),
        Err(SnapshotError::DuplicateInterface)
    ));
    let duplicate_neighbors = [gateway_neighbor(), gateway_neighbor()];
    assert!(matches!(
        ForwardingSnapshot::new(&[], &known_interfaces, &duplicate_neighbors, &[]),
        Err(SnapshotError::DuplicateNeighbor)
    ));
    let unknown_route = [route([0, 0, 0, 0], 0, IfId(99), None)];
    assert!(matches!(
        ForwardingSnapshot::new(&unknown_route, &known_interfaces, &[], &[]),
        Err(SnapshotError::RouteUnknownInterface)
    ));
    let unknown_neighbor = [Neighbor {
        interface: IfId(99),
        target: ip(GATEWAY),
        mac: NEXT_HOP_MAC,
    }];
    assert!(matches!(
        ForwardingSnapshot::new(&[], &known_interfaces, &unknown_neighbor, &[]),
        Err(SnapshotError::NeighborUnknownInterface)
    ));
}

#[test]
fn arp_snapshot_rejects_duplicate_or_unknown_local_addresses() {
    let interfaces = [
        local_interface(),
        Interface {
            id: WAN,
            mac: ROUTER_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        },
    ];
    let duplicate = [local_binding(), local_binding()];
    assert!(matches!(
        ForwardingSnapshot::new(&[], &interfaces, &[], &duplicate),
        Err(SnapshotError::DuplicateLocalIpv4Binding)
    ));
    let second_on_interface = [
        local_binding(),
        LocalIpv4Binding {
            interface: LAN,
            address: ip([192, 0, 2, 2]),
        },
    ];
    assert!(matches!(
        ForwardingSnapshot::new(&[], &interfaces, &[], &second_on_interface),
        Err(SnapshotError::DuplicateLocalIpv4Binding)
    ));
    let duplicate_across_interfaces = [
        local_binding(),
        LocalIpv4Binding {
            interface: WAN,
            address: ip(LOCAL_IPV4),
        },
    ];
    assert!(matches!(
        ForwardingSnapshot::new(&[], &interfaces, &[], &duplicate_across_interfaces),
        Err(SnapshotError::DuplicateLocalIpv4Binding)
    ));
    let unknown = [LocalIpv4Binding {
        interface: IfId(99),
        address: ip(LOCAL_IPV4),
    }];
    assert!(matches!(
        ForwardingSnapshot::new(&[], &interfaces, &[], &unknown),
        Err(SnapshotError::LocalIpv4BindingUnknownInterface)
    ));
    let unspecified = [LocalIpv4Binding {
        interface: LAN,
        address: ip([0; 4]),
    }];
    assert!(matches!(
        ForwardingSnapshot::new(&[], &interfaces, &[], &unspecified),
        Err(SnapshotError::LocalIpv4BindingUnspecified)
    ));
}

#[test]
fn all_validation_and_decision_drops_are_granular_and_atomic() {
    let routes = [gateway_route()];
    let interfaces = [local_interface(), interface()];
    let neighbors = [gateway_neighbor()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &[]).unwrap();

    let mut ethernet_type = frame(8, &[]);
    ethernet_type[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    let mut vlan = frame(8, &[]);
    vlan[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
    let mut qinq = frame(8, &[]);
    qinq[12..14].copy_from_slice(&0x88a8_u16.to_be_bytes());
    let mut ipv4_truncated = vec![0; ETHERNET_HEADER_LEN + 19];
    ipv4_truncated[0..6].copy_from_slice(&LAN_MAC.0);
    ipv4_truncated[6..12].copy_from_slice(&ORIGINAL_SRC_MAC);
    ipv4_truncated[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    let mut version = frame(8, &[]);
    version[14] = 0x65;
    let mut ihl = frame(8, &[]);
    ihl[14] = 0x44;
    let mut header_exceeds = frame(8, &[]);
    header_exceeds[14] = 0x4f;
    let mut total_small = frame(8, &[]);
    total_small[16..18].copy_from_slice(&19_u16.to_be_bytes());
    let mut total_large = frame(8, &[]);
    total_large[16..18].copy_from_slice(&100_u16.to_be_bytes());
    let mut checksum = frame(8, &[]);
    checksum[26] ^= 1;
    let options = frame_with_options(8, &[], &[1, 1, 0, 0]);

    let cases = [
        (vec![0; 13], DropReason::EthernetHeaderTruncated),
        (ethernet_type, DropReason::UnsupportedEtherType),
        (vlan, DropReason::UnsupportedEtherType),
        (qinq, DropReason::UnsupportedEtherType),
        (ipv4_truncated, DropReason::Ipv4HeaderTruncated),
        (version, DropReason::Ipv4VersionUnsupported),
        (ihl, DropReason::Ipv4IhlTooSmall),
        (header_exceeds, DropReason::Ipv4HeaderLengthExceedsPacket),
        (total_small, DropReason::Ipv4TotalLengthTooSmall),
        (total_large, DropReason::Ipv4TotalLengthExceedsPacket),
        (checksum, DropReason::Ipv4HeaderChecksumInvalid),
        (options, DropReason::Ipv4OptionsUnsupported),
        (frame(1, &[]), DropReason::Ipv4TtlExpired),
    ];
    for (packet, reason) in cases {
        assert_forwarding_drop(packet, &snapshot, reason);
    }

    let no_routes = ForwardingSnapshot::new(&[], &interfaces, &neighbors, &[]).unwrap();
    assert_forwarding_drop(frame(8, &[]), &no_routes, DropReason::RouteMiss);
    let unresolved = ForwardingSnapshot::new(&routes, &interfaces, &[], &[]).unwrap();
    assert_forwarding_drop(frame(8, &[]), &unresolved, DropReason::NeighborUnresolved);
}

#[test]
fn options_header_is_valid_but_forwarding_is_explicitly_unsupported() {
    let packet = frame_with_options(8, &[], &[1, 1, 0, 0]);
    assert_eq!(validate_ipv4_frame(&packet).unwrap().header_len, 24);
}

#[test]
fn padding_is_ignored_but_preserved() {
    let routes = [gateway_route()];
    let interfaces = [local_interface(), interface()];
    let neighbors = [gateway_neighbor()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &[]).unwrap();
    let mut padded = frame(10, &[7, 8]);
    let datagram_end = padded.len();
    padded.extend_from_slice(&[0xff; 48]);
    assert_eq!(
        validate_ipv4_frame(&padded).unwrap().total_len,
        datagram_end - ETHERNET_HEADER_LEN
    );
    let mut io = SimIo::new();
    io.inject(LAN, padded);
    io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    assert_eq!(&io.pop_tx().unwrap().bytes[datagram_end..], &[0xff; 48]);
}

#[test]
fn fragment_flags_offset_payload_and_checksum_are_preserved_or_updated_correctly() {
    let routes = [gateway_route()];
    let interfaces = [local_interface(), interface()];
    let neighbors = [gateway_neighbor()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &[]).unwrap();
    let mut fragment = frame(5, &[0xaa; 8]);
    fragment[20..22].copy_from_slice(&0xa001_u16.to_be_bytes());
    fragment[24..26].fill(0);
    let checksum = ipv4_header_checksum(&fragment[14..34]);
    fragment[24..26].copy_from_slice(&checksum.to_be_bytes());
    let flags_offset = fragment[20..22].to_vec();
    let payload = fragment[34..].to_vec();
    let mut io = SimIo::new();
    io.inject(LAN, fragment);
    io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    let tx = io.pop_tx().unwrap();
    assert_eq!(&tx.bytes[20..22], flags_offset);
    assert_eq!(&tx.bytes[34..], payload);
    assert_eq!(ipv4_header_checksum(&tx.bytes[14..34]), 0);
}

#[test]
fn mixed_batch_is_fifo_budgeted_and_reports_requested_accepted_recycled() {
    let routes = [gateway_route()];
    let interfaces = [local_interface(), interface()];
    let neighbors = [gateway_neighbor()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &[]).unwrap();
    let mut io = SimIo::new();
    for ttl in [7, 1, 6] {
        io.inject(LAN, frame(ttl, &[]));
    }
    let report = io.run_once(2, &snapshot, &mut NoTrace).unwrap();
    assert_eq!(
        report.completion,
        BatchCompletion {
            tx_requested: 1,
            tx_accepted: 1,
            tx_rejected: 0,
            recycled: 1,
            error: None,
        }
    );
    assert_eq!(io.pending_rx(), 1);
    assert_eq!(io.pop_tx().unwrap().sequence, 0);
    assert_eq!(io.pop_recycled().unwrap().sequence, 1);
    io.run_once(2, &snapshot, &mut NoTrace).unwrap();
    assert_eq!(io.pop_tx().unwrap().sequence, 2);
}

#[test]
fn unfinished_core_lease_is_backend_lifecycle_recycle() {
    let original = frame(2, &[]);
    let mut io = SimIo::new();
    io.inject(LAN, original.clone());
    let completion = {
        let mut batch = io.receive(1).unwrap();
        drop(batch.next_packet().unwrap());
        batch.finish()
    };
    assert_eq!(completion.recycled, 1);
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(recycled.cause, RecycleCause::LeaseAbandoned);
    assert_eq!(recycled.bytes, original);
}

#[test]
fn trace_is_deterministic_and_terminal_event_follows_completion() {
    fn run() -> (Vec<u8>, Vec<TraceEvent>) {
        let routes = [gateway_route()];
        let interfaces = [local_interface(), interface()];
        let neighbors = [gateway_neighbor()];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &[]).unwrap();
        let mut io = SimIo::new();
        let mut trace = VecTrace::default();
        io.inject(LAN, frame(32, &[1, 2, 3]));
        io.run_once(1, &snapshot, &mut trace).unwrap();
        (io.pop_tx().unwrap().bytes, trace.events().to_vec())
    }
    let first = run();
    assert!(matches!(
        first.1.as_slice(),
        [
            TraceEvent::Ipv4Validated { .. },
            TraceEvent::Routed { egress: WAN, .. },
            TraceEvent::TxRequested { egress: WAN },
            TraceEvent::BatchCompleted {
                tx_accepted: 1,
                tx_rejected: 0
            }
        ]
    ));
    assert_eq!(first, run());
}

#[derive(Debug, Eq, PartialEq)]
enum TestBackendError {
    RingFull,
}

struct PartialBatch {
    packet: Option<Vec<u8>>,
}

struct PartialSlot {
    bytes: Vec<u8>,
}

impl PacketSlot for PartialSlot {
    fn ingress(&self) -> IfId {
        LAN
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    fn complete(self, completion: SlotCompletion) {
        assert!(matches!(completion, SlotCompletion::Transmit(WAN)));
    }
}

impl PacketBatch for PartialBatch {
    type Error = TestBackendError;
    type Slot<'a> = PartialSlot;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        self.packet
            .take()
            .map(|bytes| PacketLease::new(PartialSlot { bytes }))
    }

    fn finish(self) -> BatchCompletion<Self::Error> {
        BatchCompletion {
            tx_requested: 1,
            tx_accepted: 0,
            tx_rejected: 1,
            recycled: 0,
            error: Some(TestBackendError::RingFull),
        }
    }
}

#[test]
fn partial_backend_completion_preserves_report_and_aggregate_trace() {
    let routes = [gateway_route()];
    let interfaces = [local_interface(), interface()];
    let neighbors = [gateway_neighbor()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &[]).unwrap();
    let batch = PartialBatch {
        packet: Some(frame(8, &[])),
    };
    let mut trace = VecTrace::default();
    let report = forward_batch(batch, &snapshot, &mut trace);

    assert_eq!(report.received, 1);
    assert_eq!(report.tx_requested, 1);
    assert_eq!(report.completion.tx_accepted, 0);
    assert_eq!(report.completion.tx_rejected, 1);
    assert_eq!(report.completion.error, Some(TestBackendError::RingFull));
    assert!(matches!(
        trace.events(),
        [
            TraceEvent::Ipv4Validated { .. },
            TraceEvent::Routed { .. },
            TraceEvent::TxRequested { egress: WAN },
            TraceEvent::BatchCompleted {
                tx_accepted: 0,
                tx_rejected: 1
            }
        ]
    ));
}

#[test]
fn arp_request_for_local_ipv4_replies_in_place_on_ingress() {
    let interfaces = [local_interface()];
    let bindings = [local_binding()];
    let snapshot = arp_snapshot(&interfaces, &bindings);
    let packet = arp_frame(
        1,
        REQUESTER_IPV4,
        LOCAL_IPV4,
        REQUESTER_MAC,
        REQUESTER_MAC,
        [0; 6],
        &[],
    );
    let allocation = packet.as_ptr();
    let mut io = SimIo::new();
    io.inject(LAN, packet);

    let report = io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    assert_eq!(report.received, 1);
    assert_eq!(report.tx_requested, 1);
    assert_eq!(report.dropped, 0);
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
    let tx = io.pop_tx().unwrap();
    assert_eq!(tx.egress, LAN);
    assert_eq!(tx.bytes.as_ptr(), allocation, "RX Vec must move, not clone");
    assert_eq!(&tx.bytes[0..6], &REQUESTER_MAC);
    assert_eq!(&tx.bytes[6..12], &LAN_MAC.0);
    assert_eq!(&tx.bytes[12..14], &0x0806_u16.to_be_bytes());
    assert_eq!(&tx.bytes[20..22], &2_u16.to_be_bytes());
    assert_eq!(&tx.bytes[22..28], &LAN_MAC.0);
    assert_eq!(&tx.bytes[28..32], &LOCAL_IPV4);
    assert_eq!(&tx.bytes[32..38], &REQUESTER_MAC);
    assert_eq!(&tx.bytes[38..42], &REQUESTER_IPV4);
}

#[test]
fn arp_probe_for_local_ipv4_replies_with_zero_target_protocol() {
    let interfaces = [local_interface()];
    let bindings = [local_binding()];
    let snapshot = arp_snapshot(&interfaces, &bindings);
    let mut io = SimIo::new();
    io.inject(
        LAN,
        arp_frame(
            1,
            [0; 4],
            LOCAL_IPV4,
            REQUESTER_MAC,
            REQUESTER_MAC,
            [0; 6],
            &[],
        ),
    );
    io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    let reply = io.pop_tx().unwrap();
    assert_eq!(&reply.bytes[28..32], &LOCAL_IPV4);
    assert_eq!(&reply.bytes[38..42], &[0; 4]);
}

#[test]
fn arp_request_target_hardware_is_ignored() {
    let interfaces = [local_interface()];
    let bindings = [local_binding()];
    let snapshot = arp_snapshot(&interfaces, &bindings);
    let mut io = SimIo::new();
    io.inject(
        LAN,
        arp_frame(
            1,
            REQUESTER_IPV4,
            LOCAL_IPV4,
            FOREIGN_ETHERNET_MAC,
            REQUESTER_MAC,
            [0xa5; 6],
            &[],
        ),
    );
    io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    let reply = io.pop_tx().unwrap();
    assert_eq!(&reply.bytes[0..6], &REQUESTER_MAC);
    assert_eq!(&reply.bytes[32..38], &REQUESTER_MAC);
}

#[test]
fn arp_foreign_sender_claiming_local_address_gets_normal_reply() {
    let interfaces = [local_interface()];
    let bindings = [local_binding()];
    let snapshot = arp_snapshot(&interfaces, &bindings);
    let mut io = SimIo::new();
    io.inject(
        LAN,
        arp_frame(
            1,
            LOCAL_IPV4,
            LOCAL_IPV4,
            FOREIGN_ETHERNET_MAC,
            REQUESTER_MAC,
            [0; 6],
            &[],
        ),
    );
    let report = io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    assert_eq!(report.tx_requested, 1);
    assert_eq!(report.dropped, 0);
    let reply = io.pop_tx().unwrap();
    assert_eq!(&reply.bytes[0..6], &REQUESTER_MAC);
    assert_eq!(&reply.bytes[38..42], &LOCAL_IPV4);
}

#[test]
fn arp_profile_validation_drops_are_granular_and_atomic() {
    let interfaces = [local_interface()];
    let bindings = [local_binding()];
    let snapshot = arp_snapshot(&interfaces, &bindings);
    let request = || {
        arp_frame(
            1,
            REQUESTER_IPV4,
            LOCAL_IPV4,
            REQUESTER_MAC,
            REQUESTER_MAC,
            [0; 6],
            &[],
        )
    };
    let mut truncated = request();
    truncated.truncate(41);
    let mut hardware_type = request();
    hardware_type[14..16].copy_from_slice(&2_u16.to_be_bytes());
    let mut protocol_type = request();
    protocol_type[16..18].copy_from_slice(&0x86dd_u16.to_be_bytes());
    let mut hardware_length = request();
    hardware_length[18] = 8;
    let mut protocol_length = request();
    protocol_length[19] = 16;
    let mut unknown_opcode = request();
    unknown_opcode[20..22].copy_from_slice(&99_u16.to_be_bytes());

    let cases = [
        (truncated, DropReason::ArpPacketTruncated),
        (hardware_type, DropReason::ArpHardwareTypeUnsupported),
        (protocol_type, DropReason::ArpProtocolTypeUnsupported),
        (hardware_length, DropReason::ArpHardwareLengthUnsupported),
        (protocol_length, DropReason::ArpProtocolLengthUnsupported),
        (unknown_opcode, DropReason::ArpOpcodeUnsupported),
    ];
    for (packet, reason) in cases {
        assert_forwarding_drop(packet, &snapshot, reason);
    }
}

#[test]
fn arp_padding_is_ignored_and_preserved_on_reply() {
    let interfaces = [local_interface()];
    let bindings = [local_binding()];
    let snapshot = arp_snapshot(&interfaces, &bindings);
    let padding = [0xde, 0xad, 0xbe, 0xef, 0xa5, 0x5a];
    let mut io = SimIo::new();
    io.inject(
        LAN,
        arp_frame(
            1,
            REQUESTER_IPV4,
            LOCAL_IPV4,
            REQUESTER_MAC,
            REQUESTER_MAC,
            [0; 6],
            &padding,
        ),
    );
    io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    let reply = io.pop_tx().unwrap();
    assert_eq!(reply.bytes.len(), 42 + padding.len());
    assert_eq!(&reply.bytes[42..], &padding);
}

#[test]
fn arp_nonlocal_and_reply_are_recycled_without_mutation() {
    let interfaces = [local_interface()];
    let bindings = [local_binding()];
    let snapshot = arp_snapshot(&interfaces, &bindings);
    let nonlocal = arp_frame(
        1,
        REQUESTER_IPV4,
        [192, 0, 2, 99],
        REQUESTER_MAC,
        REQUESTER_MAC,
        [0; 6],
        &[],
    );
    assert_arp_control_consumed(nonlocal, &snapshot);
    let reply = arp_frame(
        2,
        REQUESTER_IPV4,
        LOCAL_IPV4,
        REQUESTER_MAC,
        REQUESTER_MAC,
        LAN_MAC.0,
        &[],
    );
    assert_arp_control_consumed(reply, &snapshot);
    let unknown_opcode = arp_frame(
        77,
        REQUESTER_IPV4,
        LOCAL_IPV4,
        REQUESTER_MAC,
        REQUESTER_MAC,
        [0; 6],
        &[],
    );
    assert_forwarding_drop(unknown_opcode, &snapshot, DropReason::ArpOpcodeUnsupported);

    let interfaces = [local_interface(), interface()];
    let wan_binding = [LocalIpv4Binding {
        interface: WAN,
        address: ip(LOCAL_IPV4),
    }];
    let wrong_ingress_snapshot = arp_snapshot(&interfaces, &wan_binding);
    let wrong_ingress = arp_frame(
        1,
        REQUESTER_IPV4,
        LOCAL_IPV4,
        REQUESTER_MAC,
        REQUESTER_MAC,
        [0; 6],
        &[],
    );
    assert_arp_control_consumed(wrong_ingress, &wrong_ingress_snapshot);
}

#[test]
fn arp_trace_is_deterministic_and_tx_follows_commit() {
    fn run() -> (Vec<u8>, Vec<TraceEvent>) {
        let interfaces = [local_interface()];
        let bindings = [local_binding()];
        let snapshot = arp_snapshot(&interfaces, &bindings);
        let mut io = SimIo::new();
        let mut trace = VecTrace::default();
        io.inject(
            LAN,
            arp_frame(
                1,
                REQUESTER_IPV4,
                LOCAL_IPV4,
                REQUESTER_MAC,
                REQUESTER_MAC,
                [0; 6],
                &[],
            ),
        );
        io.run_once(1, &snapshot, &mut trace).unwrap();
        (io.pop_tx().unwrap().bytes, trace.events().to_vec())
    }
    let first = run();
    assert!(matches!(
        first.1.as_slice(),
        [
            TraceEvent::ArpRequestValidated { ingress: LAN, .. },
            TraceEvent::ArpReplyRequested { egress: LAN, .. },
            TraceEvent::TxRequested { egress: LAN },
            TraceEvent::BatchCompleted {
                tx_accepted: 1,
                tx_rejected: 0
            }
        ]
    ));
    assert_eq!(first, run());
}

#[test]
fn mixed_ipv4_and_arp_batch_is_fifo_budgeted_and_deterministic() {
    let routes = [gateway_route()];
    let interfaces = [local_interface(), interface()];
    let neighbors = [gateway_neighbor()];
    let bindings = [local_binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut io = SimIo::new();
    io.inject(LAN, frame(8, &[]));
    io.inject(
        LAN,
        arp_frame(
            1,
            REQUESTER_IPV4,
            LOCAL_IPV4,
            REQUESTER_MAC,
            REQUESTER_MAC,
            [0; 6],
            &[],
        ),
    );
    io.inject(LAN, frame(7, &[]));

    let first = io.run_once(2, &snapshot, &mut NoTrace).unwrap();
    assert_eq!(first.received, 2);
    assert_eq!(first.tx_requested, 2);
    assert_eq!(io.pending_rx(), 1);
    assert_eq!(io.pop_tx().unwrap().sequence, 0);
    assert_eq!(io.pop_tx().unwrap().sequence, 1);
    let second = io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    assert_eq!(second.tx_requested, 1);
    assert_eq!(io.pop_tx().unwrap().sequence, 2);
}

#[test]
fn arp_reply_does_not_learn_or_generate_for_unresolved_neighbor() {
    let routes = [route(REQUESTER_IPV4, 32, LAN, None)];
    let interfaces = [local_interface()];
    let bindings = [local_binding()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let request = arp_frame(
        1,
        REQUESTER_IPV4,
        LOCAL_IPV4,
        REQUESTER_MAC,
        REQUESTER_MAC,
        [0; 6],
        &[],
    );
    let mut toward_sender = frame(8, &[]);
    toward_sender[30..34].copy_from_slice(&REQUESTER_IPV4);
    toward_sender[24..26].fill(0);
    let checksum = ipv4_header_checksum(&toward_sender[14..34]);
    toward_sender[24..26].copy_from_slice(&checksum.to_be_bytes());
    let original_ipv4 = toward_sender.clone();

    let mut io = SimIo::new();
    let mut trace = VecTrace::default();
    io.inject(LAN, request);
    io.inject(LAN, toward_sender);
    let report = io.run_once(2, &snapshot, &mut trace).unwrap();

    assert_eq!(report.received, 2);
    assert_eq!(report.tx_requested, 1, "no generated ARP request");
    assert_eq!(report.dropped, 1);
    assert_eq!(
        report.completion,
        BatchCompletion {
            tx_requested: 1,
            tx_accepted: 1,
            tx_rejected: 0,
            recycled: 1,
            error: None,
        }
    );
    assert_eq!(io.pending_tx(), 1, "only the in-place ARP reply exists");
    let reply = io.pop_tx().unwrap();
    assert_eq!(reply.sequence, 0);
    assert_eq!(&reply.bytes[20..22], &2_u16.to_be_bytes());
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(recycled.sequence, 1);
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::NeighborUnresolved)
    );
    assert_eq!(recycled.bytes, original_ipv4, "unresolved drop is atomic");
    assert_eq!(io.pending_rx(), 0, "the unresolved packet is not held");
    assert!(matches!(
        trace.events(),
        [
            TraceEvent::ArpRequestValidated { .. },
            TraceEvent::ArpReplyRequested { egress: LAN, .. },
            TraceEvent::TxRequested { egress: LAN },
            TraceEvent::Ipv4Validated { ingress: LAN, .. },
            TraceEvent::Dropped {
                ingress: LAN,
                reason: DropReason::NeighborUnresolved
            },
            TraceEvent::BatchCompleted {
                tx_accepted: 1,
                tx_rejected: 0
            }
        ]
    ));
}

#[test]
fn arp_partial_backend_rejection_preserves_error_report_and_trace() {
    let interfaces = [local_interface()];
    let bindings = [local_binding()];
    let snapshot = arp_snapshot(&interfaces, &bindings);
    let batch = ArpPartialBatch {
        packet: Some(arp_frame(
            1,
            REQUESTER_IPV4,
            LOCAL_IPV4,
            REQUESTER_MAC,
            REQUESTER_MAC,
            [0; 6],
            &[],
        )),
    };
    let mut trace = VecTrace::default();
    let report = forward_batch(batch, &snapshot, &mut trace);
    assert_eq!(report.tx_requested, 1);
    assert_eq!(report.completion.tx_requested, 1);
    assert_eq!(report.completion.tx_accepted, 0);
    assert_eq!(report.completion.tx_rejected, 1);
    assert_eq!(report.completion.error, Some(TestBackendError::RingFull));
    assert!(matches!(
        trace.events(),
        [
            TraceEvent::ArpRequestValidated { .. },
            TraceEvent::ArpReplyRequested { egress: LAN, .. },
            TraceEvent::TxRequested { egress: LAN },
            TraceEvent::BatchCompleted {
                tx_accepted: 0,
                tx_rejected: 1
            }
        ]
    ));
}

struct ArpPartialBatch {
    packet: Option<Vec<u8>>,
}

struct ArpPartialSlot {
    bytes: Vec<u8>,
}

impl PacketSlot for ArpPartialSlot {
    fn ingress(&self) -> IfId {
        LAN
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    fn complete(self, completion: SlotCompletion) {
        assert!(matches!(completion, SlotCompletion::Transmit(LAN)));
    }
}

impl PacketBatch for ArpPartialBatch {
    type Error = TestBackendError;
    type Slot<'a> = ArpPartialSlot;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        self.packet
            .take()
            .map(|bytes| PacketLease::new(ArpPartialSlot { bytes }))
    }

    fn finish(self) -> BatchCompletion<Self::Error> {
        BatchCompletion {
            tx_requested: 1,
            tx_accepted: 0,
            tx_rejected: 1,
            recycled: 0,
            error: Some(TestBackendError::RingFull),
        }
    }
}
