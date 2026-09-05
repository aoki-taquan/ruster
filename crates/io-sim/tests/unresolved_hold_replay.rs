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
    ResolutionRuntime, ResolutionStateSlot, Route,
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
