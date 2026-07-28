use ruster_core::{
    forward_batch, ipv4_header_checksum, validate_ipv4_frame, BatchCompletion, DropReason,
    ForwardingSnapshot, IfId, Interface, Ipv4Address, MacAddress, Neighbor, NoTrace, PacketBatch,
    PacketIo, PacketLease, PacketSlot, Route, SlotCompletion, SnapshotError, TraceEvent,
    ETHERNET_HEADER_LEN,
};
use ruster_io_sim::{RecycleCause, SimIo, VecTrace};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const ROUTER_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
const NEXT_HOP_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 3]);
const ORIGINAL_DST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 9];
const ORIGINAL_SRC_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
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

fn frame(ttl: u8, payload: &[u8]) -> Vec<u8> {
    frame_with_options(ttl, payload, &[])
}

fn frame_with_options(ttl: u8, payload: &[u8], options: &[u8]) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0);
    let header_len = 20 + options.len();
    let total_len = header_len + payload.len();
    let mut bytes = vec![0_u8; ETHERNET_HEADER_LEN + total_len];
    bytes[0..6].copy_from_slice(&ORIGINAL_DST_MAC);
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

#[test]
fn gateway_route_rewrites_and_reports_backend_acceptance() {
    let routes = [gateway_route()];
    let interfaces = [interface()];
    let neighbors = [gateway_neighbor()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors).unwrap();
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
    let interfaces = [interface()];
    let neighbors = [Neighbor {
        interface: WAN,
        target: ip(DESTINATION),
        mac: NEXT_HOP_MAC,
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors).unwrap();
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
        interface(),
        Interface {
            id: IfId(3),
            mac: MacAddress([3; 6]),
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
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors).unwrap();
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
        ForwardingSnapshot::new(&duplicate_routes, &known_interfaces, &[gateway_neighbor()]),
        Err(SnapshotError::DuplicateRoute)
    ));
    let duplicate_interfaces = [interface(), interface()];
    assert!(matches!(
        ForwardingSnapshot::new(&[], &duplicate_interfaces, &[]),
        Err(SnapshotError::DuplicateInterface)
    ));
    let duplicate_neighbors = [gateway_neighbor(), gateway_neighbor()];
    assert!(matches!(
        ForwardingSnapshot::new(&[], &known_interfaces, &duplicate_neighbors),
        Err(SnapshotError::DuplicateNeighbor)
    ));
    let unknown_route = [route([0, 0, 0, 0], 0, IfId(99), None)];
    assert!(matches!(
        ForwardingSnapshot::new(&unknown_route, &known_interfaces, &[]),
        Err(SnapshotError::RouteUnknownInterface)
    ));
    let unknown_neighbor = [Neighbor {
        interface: IfId(99),
        target: ip(GATEWAY),
        mac: NEXT_HOP_MAC,
    }];
    assert!(matches!(
        ForwardingSnapshot::new(&[], &known_interfaces, &unknown_neighbor),
        Err(SnapshotError::NeighborUnknownInterface)
    ));
}

#[test]
fn all_validation_and_decision_drops_are_granular_and_atomic() {
    let routes = [gateway_route()];
    let interfaces = [interface()];
    let neighbors = [gateway_neighbor()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors).unwrap();

    let mut ethernet_type = frame(8, &[]);
    ethernet_type[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    let mut ipv4_truncated = vec![0; ETHERNET_HEADER_LEN + 19];
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

    let no_routes = ForwardingSnapshot::new(&[], &interfaces, &neighbors).unwrap();
    assert_forwarding_drop(frame(8, &[]), &no_routes, DropReason::RouteMiss);
    let unresolved = ForwardingSnapshot::new(&routes, &interfaces, &[]).unwrap();
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
    let interfaces = [interface()];
    let neighbors = [gateway_neighbor()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors).unwrap();
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
    let interfaces = [interface()];
    let neighbors = [gateway_neighbor()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors).unwrap();
    let mut fragment = frame(5, &[0xaa; 8]);
    fragment[20..22].copy_from_slice(&0x2001_u16.to_be_bytes());
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
    let interfaces = [interface()];
    let neighbors = [gateway_neighbor()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors).unwrap();
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
        let interfaces = [interface()];
        let neighbors = [gateway_neighbor()];
        let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors).unwrap();
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
            TraceEvent::Validated { .. },
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
    let interfaces = [interface()];
    let neighbors = [gateway_neighbor()];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors).unwrap();
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
            TraceEvent::Validated { .. },
            TraceEvent::Routed { .. },
            TraceEvent::TxRequested { egress: WAN },
            TraceEvent::BatchCompleted {
                tx_accepted: 0,
                tx_rejected: 1
            }
        ]
    ));
}
