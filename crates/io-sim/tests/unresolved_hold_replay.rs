//! Holding and replaying the datagram that triggers a resolution.
//!
//! RFC 1122 §2.3.2.2 asks the link layer to save, rather than discard, at
//! least one packet per address being resolved; RFC 1812 §3.3.2 repeats it for
//! routers. Without this the first datagram to every new destination is lost
//! even though the ARP it triggers succeeds moments later.

use ruster_core::{
    execute_one_held_datagram, forward_batch_with_resolution, internet_checksum,
    ipv4_header_checksum, ArpOpcode, DropReason, DynamicNeighborSlot, ForwardingSnapshot,
    GeneratedHeldDatagramTrace, GeneratedHeldDatagramTraceSink, IfId, Interface, Ipv4Address,
    Ipv4Mtu, LocalIpv4Binding, MacAddress, MonotonicMillis, Neighbor, NoTrace, PacketIo,
    ResolutionActionSlot, ResolutionDatagramHoldSlot, ResolutionFailureHoldSlot, ResolutionPolicy,
    ResolutionRuntime, ResolutionStateSlot, Route, MAX_FRAGMENTS_PER_DATAGRAM,
};
use ruster_io_sim::{FrameOrigin, RecycleCause, SimIo};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
const PREVIOUS_HOP_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0xaa];
const LEARNED_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0xcc]);
const LAN_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const WAN_IP: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
const SOURCE: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 50]);
const DESTINATION: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 9]);

#[derive(Default)]
struct HeldTrace {
    events: Vec<GeneratedHeldDatagramTrace>,
}

impl GeneratedHeldDatagramTraceSink for HeldTrace {
    fn record_generated_held_datagram(&mut self, event: GeneratedHeldDatagramTrace) {
        self.events.push(event);
    }
}

fn interfaces() -> [Interface; 2] {
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
    ]
}

fn bindings() -> [LocalIpv4Binding; 2] {
    [
        LocalIpv4Binding {
            interface: LAN,
            address: LAN_IP,
        },
        LocalIpv4Binding {
            interface: WAN,
            address: WAN_IP,
        },
    ]
}

fn routes() -> [Route; 2] {
    [
        Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, WAN, None).unwrap(),
        Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, LAN, None).unwrap(),
    ]
}

fn datagram(payload: u8, payload_len: usize, ttl: u8) -> Vec<u8> {
    let total_len = 20 + payload_len;
    let mut bytes = vec![0; 14 + total_len];
    bytes[0..6].copy_from_slice(&LAN_MAC.0);
    bytes[6..12].copy_from_slice(&PREVIOUS_HOP_MAC);
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    bytes[18..20].copy_from_slice(&0x4d2_u16.to_be_bytes());
    bytes[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    bytes[22] = ttl;
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&SOURCE.octets());
    bytes[30..34].copy_from_slice(&DESTINATION.octets());
    bytes[34..].fill(payload);
    let checksum = ipv4_header_checksum(&bytes[14..34]);
    bytes[24..26].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn arp_reply(sender_ip: Ipv4Address, sender_mac: MacAddress) -> Vec<u8> {
    let mut frame = vec![0; 60];
    frame[0..6].copy_from_slice(&WAN_MAC.0);
    frame[6..12].copy_from_slice(&sender_mac.0);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&(ArpOpcode::Reply as u16 + 2).to_be_bytes());
    frame[20..22].copy_from_slice(&2_u16.to_be_bytes());
    frame[22..28].copy_from_slice(&sender_mac.0);
    frame[28..32].copy_from_slice(&sender_ip.octets());
    frame[32..38].copy_from_slice(&WAN_MAC.0);
    frame[38..42].copy_from_slice(&WAN_IP.octets());
    frame
}

#[test]
fn the_datagram_that_triggers_a_resolution_is_sent_once_the_reply_arrives() {
    let interfaces = interfaces();
    let bindings = bindings();
    let routes = routes();
    let neighbors: [Neighbor; 0] = [];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();

    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 2];
    let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 1];
    let mut datagram_holds = [ResolutionDatagramHoldSlot::EMPTY; 2];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_failure_holds_and_datagram_holds(
        ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 60_000, 60_000).unwrap(),
        &mut states,
        &mut actions,
        &mut dynamic,
        &mut failure_holds,
        &mut datagram_holds,
    );

    // The first datagram to an unresolved next hop.
    let original = datagram(0x5a, 40, 64);
    let mut io = SimIo::new();
    io.inject(LAN, original.clone());
    let batch = io.receive(1).unwrap();
    let report = forward_batch_with_resolution(
        batch,
        &snapshot,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!(
        (report.received, report.dropped, report.tx_requested),
        (1, 1, 0)
    );
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::NeighborUnresolved)
    );
    assert_eq!(
        recycled.bytes, original,
        "the received frame is recycled unchanged; the hold is a copy"
    );
    assert_eq!(resolution.held_datagram_count(), 1);
    assert_eq!(resolution.hold_counters().held, 1);

    // Nothing to replay while the address is still unknown.
    let mut trace = HeldTrace::default();
    assert!(
        execute_one_held_datagram(&mut io, &mut resolution, MonotonicMillis(1), &mut trace)
            .unwrap()
            .is_none()
    );

    // The reply arrives and the address is learned.
    io.inject(WAN, arp_reply(DESTINATION, LEARNED_MAC));
    let batch = io.receive(1).unwrap();
    forward_batch_with_resolution(
        batch,
        &snapshot,
        &mut resolution,
        MonotonicMillis(2),
        &mut NoTrace,
    );
    let _ = io.pop_recycled();

    let replay =
        execute_one_held_datagram(&mut io, &mut resolution, MonotonicMillis(2), &mut trace)
            .unwrap()
            .expect("the held datagram must be released once the hop resolves");
    assert_eq!(replay.egress, WAN);
    assert_eq!(replay.destination_mac, LEARNED_MAC);
    assert_eq!(replay.completion.accepted, 1);
    assert_eq!(replay.completion.rejected, 0);
    assert!(replay.allocation_error.is_none());
    assert!(replay.build_error.is_none());
    assert_eq!(resolution.hold_counters().replayed, 1);
    assert_eq!(resolution.held_datagram_count(), 0);

    let tx = io.pop_tx().expect("the replay must reach the backend");
    assert_eq!(tx.origin, FrameOrigin::Generated);
    assert_eq!(tx.egress, WAN);
    assert_eq!(tx.bytes.len(), original.len(), "length is preserved");
    assert_eq!(&tx.bytes[0..6], &LEARNED_MAC.0, "the learned next hop");
    assert_eq!(&tx.bytes[6..12], &WAN_MAC.0, "the egress interface");
    assert_eq!(&tx.bytes[12..14], &0x0800_u16.to_be_bytes());
    assert_eq!(tx.bytes[22], 63, "the TTL is decremented exactly once");
    assert_eq!(
        ipv4_header_checksum(&tx.bytes[14..34]),
        0,
        "the header checksum matches the decremented TTL"
    );
    assert_eq!(&tx.bytes[26..30], &SOURCE.octets(), "addresses untouched");
    assert_eq!(&tx.bytes[30..34], &DESTINATION.octets());
    assert_eq!(&tx.bytes[34..], &original[34..], "the payload is unchanged");

    assert_eq!(
        trace.events,
        [
            GeneratedHeldDatagramTrace::TxRequested {
                egress: WAN,
                len: original.len()
            },
            GeneratedHeldDatagramTrace::BatchCompleted {
                accepted: 1,
                rejected: 0
            }
        ]
    );

    // The queue is drained: a second call has nothing to send.
    assert!(
        execute_one_held_datagram(&mut io, &mut resolution, MonotonicMillis(3), &mut trace)
            .unwrap()
            .is_none()
    );
    let _ = internet_checksum(&[]);
}

#[test]
fn a_runtime_without_hold_slots_still_drops_the_first_datagram() {
    // The behaviour every existing deployment has today, kept for a
    // configuration that asks for no hold slots.
    let interfaces = interfaces();
    let bindings = bindings();
    let routes = routes();
    let neighbors: [Neighbor; 0] = [];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();

    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 2];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors(
        ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 60_000, 60_000).unwrap(),
        &mut states,
        &mut actions,
        &mut dynamic,
    );

    let mut io = SimIo::new();
    io.inject(LAN, datagram(0x5a, 40, 64));
    let batch = io.receive(1).unwrap();
    forward_batch_with_resolution(
        batch,
        &snapshot,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!(resolution.held_datagram_count(), 0);
    assert_eq!(resolution.hold_counters().held, 0);
    assert_eq!(resolution.hold_counters().queue_full, 1);
}

/// A datagram larger than the egress link with Don't Fragment clear.
fn oversized_datagram(payload_len: usize) -> Vec<u8> {
    let total_len = 20 + payload_len;
    let mut bytes = vec![0; 14 + total_len];
    bytes[0..6].copy_from_slice(&LAN_MAC.0);
    bytes[6..12].copy_from_slice(&PREVIOUS_HOP_MAC);
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    bytes[18..20].copy_from_slice(&0xbeef_u16.to_be_bytes());
    // Don't Fragment clear, so this router may split it.
    bytes[20..22].copy_from_slice(&0_u16.to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&SOURCE.octets());
    bytes[30..34].copy_from_slice(&DESTINATION.octets());
    for (index, byte) in bytes[34..].iter_mut().enumerate() {
        *byte = u8::try_from(index % 251).unwrap();
    }
    let checksum = ipv4_header_checksum(&bytes[14..34]);
    bytes[24..26].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

#[test]
fn an_oversized_datagram_without_dont_fragment_leaves_as_fragments() {
    // RFC 791 §3.2 / RFC 1812 §5.2.7. The egress link is narrower than the
    // datagram, so the router splits it rather than dropping it.
    const WAN_MTU: u16 = 576;
    let interfaces = [
        Interface {
            id: LAN,
            mac: LAN_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
            mtu: Ipv4Mtu::new(WAN_MTU).unwrap(),
        },
    ];
    let bindings = bindings();
    let routes = routes();
    let neighbors = [Neighbor {
        interface: WAN,
        target: DESTINATION,
        mac: LEARNED_MAC,
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();

    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 2];
    let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 1];
    let mut datagram_holds = [ResolutionDatagramHoldSlot::EMPTY; 2];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_failure_holds_and_datagram_holds(
        ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 60_000, 60_000).unwrap(),
        &mut states,
        &mut actions,
        &mut dynamic,
        &mut failure_holds,
        &mut datagram_holds,
    );

    let payload_len = 1_400;
    let original = oversized_datagram(payload_len);
    let mut io = SimIo::new();
    io.inject(LAN, original.clone());
    let batch = io.receive(1).unwrap();
    let report = forward_batch_with_resolution(
        batch,
        &snapshot,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!(
        (
            report.received,
            report.dropped,
            report.consumed,
            report.tx_requested
        ),
        (1, 0, 1, 0),
        "the received datagram is consumed, not dropped"
    );
    assert_eq!(resolution.held_datagram_count(), 1);

    let mut trace = HeldTrace::default();
    let replay =
        execute_one_held_datagram(&mut io, &mut resolution, MonotonicMillis(1), &mut trace)
            .unwrap()
            .expect("the split must be emitted");
    // 576 - 20 = 556, rounded down to a multiple of eight is 552.
    let per_fragment = 552;
    let expected = payload_len.div_ceil(per_fragment);
    assert_eq!(replay.completion.accepted, expected);
    assert_eq!(replay.completion.rejected, 0);

    let mut reassembled = Vec::new();
    let mut expected_offset = 0;
    for index in 0..expected {
        let tx = io.pop_tx().expect("every fragment must reach the backend");
        assert_eq!(tx.egress, WAN);
        assert_eq!(&tx.bytes[0..6], &LEARNED_MAC.0);
        assert_eq!(&tx.bytes[6..12], &WAN_MAC.0);
        assert!(
            tx.bytes.len() - 14 <= usize::from(WAN_MTU),
            "fragment {index} must fit the link"
        );
        assert_eq!(tx.bytes[22], 63, "the TTL is decremented exactly once");
        assert_eq!(
            &tx.bytes[18..20],
            &0xbeef_u16.to_be_bytes(),
            "every fragment keeps the original identification"
        );
        let flags_offset = u16::from_be_bytes([tx.bytes[20], tx.bytes[21]]);
        assert_eq!(flags_offset & 0x4000, 0, "Don't Fragment stays clear");
        assert_eq!(
            usize::from(flags_offset & 0x1fff) * 8,
            expected_offset,
            "fragment {index} offset"
        );
        let more = flags_offset & 0x2000 != 0;
        assert_eq!(
            more,
            index + 1 < expected,
            "More Fragments is set on every fragment but the last"
        );
        let total_len = usize::from(u16::from_be_bytes([tx.bytes[16], tx.bytes[17]]));
        assert_eq!(total_len, tx.bytes.len() - 14, "total length matches");
        assert_eq!(
            ipv4_header_checksum(&tx.bytes[14..34]),
            0,
            "fragment {index} header checksum"
        );
        if more {
            assert_eq!(
                (total_len - 20) % 8,
                0,
                "a non-final fragment must end on an eight-octet boundary"
            );
        }
        reassembled.extend_from_slice(&tx.bytes[34..]);
        expected_offset += total_len - 20;
    }
    assert_eq!(
        reassembled,
        original[34..],
        "the fragments reassemble to the original payload"
    );
    assert!(io.pop_tx().is_none(), "no extra frames");
}

#[test]
fn an_oversized_datagram_carrying_options_is_refused_rather_than_split() {
    // Splitting a header with options requires copying only those whose copied
    // bit is set, and that changes the header length per fragment. Until that
    // is implemented the datagram is refused rather than split wrongly.
    const WAN_MTU: u16 = 576;
    let interfaces = [
        Interface {
            id: LAN,
            mac: LAN_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
            mtu: Ipv4Mtu::new(WAN_MTU).unwrap(),
        },
    ];
    let bindings = bindings();
    let routes = routes();
    let neighbors = [Neighbor {
        interface: WAN,
        target: DESTINATION,
        mac: LEARNED_MAC,
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();

    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 2];
    let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 1];
    let mut datagram_holds = [ResolutionDatagramHoldSlot::EMPTY; 2];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_failure_holds_and_datagram_holds(
        ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 60_000, 60_000).unwrap(),
        &mut states,
        &mut actions,
        &mut dynamic,
        &mut failure_holds,
        &mut datagram_holds,
    );

    // The same oversized datagram, with four octets of no-operation padding
    // inserted into its header.
    let mut original = oversized_datagram(1_400);
    original.splice(34..34, [1, 1, 1, 0]);
    original[14] = 0x46;
    let total_len = u16::from_be_bytes([original[16], original[17]]) + 4;
    original[16..18].copy_from_slice(&total_len.to_be_bytes());
    original[24..26].fill(0);
    let checksum = ipv4_header_checksum(&original[14..38]);
    original[24..26].copy_from_slice(&checksum.to_be_bytes());

    let mut io = SimIo::new();
    io.inject(LAN, original.clone());
    let batch = io.receive(1).unwrap();
    let report = forward_batch_with_resolution(
        batch,
        &snapshot,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!((report.dropped, report.consumed), (1, 0));
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::Ipv4FragmentationRequired)
    );
    assert_eq!(recycled.bytes, original, "the refusal is byte-preserving");
    assert_eq!(resolution.held_datagram_count(), 0);
}

#[test]
fn a_datagram_needing_more_than_the_fragment_bound_is_refused() {
    // Without a bound one datagram could ask the backend for as many frames as
    // the transmit budget holds. The smallest MTU IPv4 allows is 68, so a
    // full-size datagram past the bound is refused rather than split.
    const NARROW_MTU: u16 = 68;
    let interfaces = [
        Interface {
            id: LAN,
            mac: LAN_MAC,
            mtu: Ipv4Mtu::ETHERNET,
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
            mtu: Ipv4Mtu::new(NARROW_MTU).unwrap(),
        },
    ];
    let bindings = bindings();
    let routes = routes();
    let neighbors = [Neighbor {
        interface: WAN,
        target: DESTINATION,
        mac: LEARNED_MAC,
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();

    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 2];
    let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 1];
    let mut datagram_holds = [ResolutionDatagramHoldSlot::EMPTY; 2];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_failure_holds_and_datagram_holds(
        ResolutionPolicy::with_dynamic_neighbor_ttl(1_000, 60_000, 60_000).unwrap(),
        &mut states,
        &mut actions,
        &mut dynamic,
        &mut failure_holds,
        &mut datagram_holds,
    );

    // Each fragment carries at most 48 payload octets at this MTU, so the
    // bound is crossed well before a full-MTU datagram.
    let per_fragment = ((usize::from(NARROW_MTU) - 20) / 8) * 8;
    let payload_len = per_fragment * MAX_FRAGMENTS_PER_DATAGRAM + 1;
    let mut io = SimIo::new();
    io.inject(LAN, oversized_datagram(payload_len));
    let batch = io.receive(1).unwrap();
    let report = forward_batch_with_resolution(
        batch,
        &snapshot,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!((report.dropped, report.consumed), (1, 0));
    assert_eq!(
        io.pop_recycled().unwrap().cause,
        RecycleCause::Forwarding(DropReason::Ipv4FragmentationRequired)
    );
    assert_eq!(resolution.held_datagram_count(), 0);

    // One fragment fewer is split, so the bound is exercised from both sides.
    let mut io = SimIo::new();
    io.inject(
        LAN,
        oversized_datagram(per_fragment * MAX_FRAGMENTS_PER_DATAGRAM),
    );
    let batch = io.receive(1).unwrap();
    let report = forward_batch_with_resolution(
        batch,
        &snapshot,
        &mut resolution,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert_eq!((report.dropped, report.consumed), (0, 1));
    let mut trace = HeldTrace::default();
    let replay =
        execute_one_held_datagram(&mut io, &mut resolution, MonotonicMillis(1), &mut trace)
            .unwrap()
            .expect("a datagram at the bound must still be split");
    assert_eq!(replay.completion.accepted, MAX_FRAGMENTS_PER_DATAGRAM);
}
