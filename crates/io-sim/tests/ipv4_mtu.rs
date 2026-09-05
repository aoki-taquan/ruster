//! Egress MTU enforcement on the forwarding path.
//!
//! RFC 1812 §4.2.2.7 requires a router not to put a datagram on a link that
//! cannot carry it. Before per-interface MTU existed, an oversized datagram
//! was handed to the backend unchanged, which a real driver rejects, so these
//! tests fix the observable behaviour of both branches: Don't Fragment set
//! produces the RFC 1191 report, and Don't Fragment clear is dropped with a
//! reason of its own because fragmentation is not implemented yet.

use ruster_core::{
    execute_one_icmpv4_time_exceeded, forward_batch_with_resolution_and_icmpv4_errors,
    internet_checksum, ipv4_header_checksum, DropReason, ForwardingSnapshot, GeneratedIcmpv4Trace,
    Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy, Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot,
    Icmpv4TimeExceededDisposition, IfId, Interface, Ipv4Address, Ipv4Mtu, Ipv4OriginPolicy,
    LocalIpv4Binding, MacAddress, MonotonicMillis, Neighbor, NoTrace, PacketIo,
    ResolutionActionSlot, ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route,
    TraceEvent,
};
use ruster_io_sim::{FrameOrigin, RecycleCause, SimIo, VecGeneratedIcmpv4Trace, VecTrace};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
const PREVIOUS_HOP_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0xaa];
const REVERSE_GATEWAY_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0xbb]);
const FORWARD_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0xcc]);
const LAN_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const WAN_IP: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
const SOURCE: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 9]);
const DESTINATION: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 9]);
const REVERSE_GATEWAY: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 254]);

/// The egress link is deliberately narrower than the ingress link, which is
/// the only shape in which the check can be reached.
const WAN_MTU: u16 = 576;
const DONT_FRAGMENT: u16 = 0x4000;

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
            mtu: Ipv4Mtu::new(WAN_MTU).expect("test MTU is above the IPv4 minimum"),
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

fn routes() -> [Route; 3] {
    [
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, WAN, None).unwrap(),
        Route::new(
            Ipv4Address::from_octets([203, 0, 113, 0]),
            24,
            WAN,
            Some(REVERSE_GATEWAY),
        )
        .unwrap(),
        Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, LAN, None).unwrap(),
    ]
}

fn neighbors() -> [Neighbor; 2] {
    [
        Neighbor {
            interface: WAN,
            target: REVERSE_GATEWAY,
            mac: REVERSE_GATEWAY_MAC,
        },
        Neighbor {
            interface: WAN,
            target: DESTINATION,
            mac: FORWARD_MAC,
        },
    ]
}

fn frame(payload_len: usize, flags_fragment: u16) -> Vec<u8> {
    let total_len = 20 + payload_len;
    let mut bytes = vec![0; 14 + total_len];
    bytes[0..6].copy_from_slice(&LAN_MAC.0);
    bytes[6..12].copy_from_slice(&PREVIOUS_HOP_MAC);
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    bytes[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
    bytes[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
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

struct Fixture {
    io: SimIo,
    trace: VecTrace,
    dropped: usize,
    tx_requested: usize,
}

fn forward(packet: Vec<u8>, errors: &mut Icmpv4ErrorRuntime<'_>) -> Fixture {
    let interfaces = interfaces();
    let bindings = bindings();
    let routes = routes();
    let neighbors = neighbors();
    let snapshot = ForwardingSnapshot::with_ipv4_origin_policy(
        &routes,
        &interfaces,
        &neighbors,
        &bindings,
        Ipv4OriginPolicy::new(64).unwrap(),
    )
    .unwrap();
    let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
    let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 60_000).unwrap(),
        &mut resolution_states,
        &mut resolution_actions,
    );
    let mut io = SimIo::new();
    io.inject(LAN, packet);
    let mut trace = VecTrace::default();
    let batch = io.receive(1).unwrap();
    let report = forward_batch_with_resolution_and_icmpv4_errors(
        batch,
        &snapshot,
        &mut resolution,
        errors,
        MonotonicMillis(1_000),
        &mut trace,
    );
    Fixture {
        io,
        trace,
        dropped: report.dropped,
        tx_requested: report.tx_requested,
    }
}

#[test]
fn an_oversized_datagram_with_dont_fragment_reports_the_next_hop_mtu() {
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let original = frame(600, DONT_FRAGMENT);
    let mut fixture = forward(original.clone(), &mut errors);

    assert_eq!((fixture.dropped, fixture.tx_requested), (1, 0));
    let recycled = fixture.io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::Ipv4FragmentationNeeded)
    );
    assert_eq!(recycled.bytes, original, "the drop must be byte-preserving");
    assert!(fixture.trace.events().iter().any(|event| matches!(
        event,
        TraceEvent::Icmpv4TimeExceededDisposition {
            ingress: LAN,
            disposition: Icmpv4TimeExceededDisposition::FragmentationNeededQueued {
                egress: WAN,
                ..
            }
        }
    )));
    assert_eq!(errors.counters().queued_fragmentation_needed, 1);

    let mut generated_trace = VecGeneratedIcmpv4Trace::default();
    let generated = execute_one_icmpv4_time_exceeded(
        &mut fixture.io,
        &mut errors,
        MonotonicMillis(1_000),
        &mut generated_trace,
    )
    .unwrap()
    .unwrap();
    assert!(generated.completion.invariants_hold());
    assert_eq!(
        (generated.completion.accepted, generated.completion.rejected),
        (1, 0)
    );
    assert_eq!(
        generated_trace.events(),
        [
            GeneratedIcmpv4Trace::FragmentationNeededTxRequested {
                egress: WAN,
                destination: SOURCE
            },
            GeneratedIcmpv4Trace::FragmentationNeededBatchCompleted {
                accepted: 1,
                rejected: 0
            }
        ]
    );
    assert_eq!(errors.counters().dequeued_fragmentation_needed, 1);

    let tx = fixture.io.pop_tx().unwrap();
    assert_eq!(tx.origin, FrameOrigin::Generated);
    assert_eq!((tx.ingress, tx.egress), (WAN, WAN));
    assert_eq!(&tx.bytes[0..6], &REVERSE_GATEWAY_MAC.0);
    assert_eq!(&tx.bytes[6..12], &WAN_MAC.0);
    assert_eq!(&tx.bytes[26..30], &WAN_IP.octets());
    assert_eq!(&tx.bytes[30..34], &SOURCE.octets());
    assert_eq!(ipv4_header_checksum(&tx.bytes[14..34]), 0);
    // RFC 792 type 3, RFC 1191 code 4.
    assert_eq!(tx.bytes[34], 3);
    assert_eq!(tx.bytes[35], 4);
    // RFC 1191 §4: the first two octets of the formerly unused field stay
    // zero and the next-hop MTU occupies the second two.
    assert_eq!(&tx.bytes[38..40], &[0, 0]);
    assert_eq!(
        u16::from_be_bytes([tx.bytes[40], tx.bytes[41]]),
        WAN_MTU,
        "the reported MTU must be the link the datagram could not cross"
    );
    assert_eq!(internet_checksum(&tx.bytes[34..]), 0);
    // The quote is the head of the datagram that could not be forwarded.
    assert_eq!(&tx.bytes[42..], &original[14..14 + tx.bytes.len() - 42]);
    // RFC 1812 §4.3.2.3 keeps an ICMP error inside 576 bytes.
    assert!(u16::from_be_bytes([tx.bytes[16], tx.bytes[17]]) <= 576);
}

#[test]
fn an_oversized_datagram_without_dont_fragment_is_dropped_with_its_own_reason() {
    // Fragmentation (RFC 1812 §5.2.7) is not implemented. Until it is, the
    // datagram must be visibly dropped rather than emitted at a length the
    // link cannot carry, and it must not produce an ICMP report, which would
    // be wrong for a sender that never asked to be told.
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let original = frame(600, 0);
    let mut fixture = forward(original.clone(), &mut errors);

    assert_eq!((fixture.dropped, fixture.tx_requested), (1, 0));
    let recycled = fixture.io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::Ipv4FragmentationRequired)
    );
    assert_eq!(recycled.bytes, original, "the drop must be byte-preserving");
    assert_eq!(errors.pending_actions(), 0);
    assert_eq!(errors.counters().queued_fragmentation_needed, 0);
}

#[test]
fn a_datagram_of_exactly_the_egress_mtu_is_forwarded() {
    // The boundary is checked from the forwarded side so the comparison
    // cannot be off by one in the permissive direction.
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let payload = usize::from(WAN_MTU) - 20;
    let mut fixture = forward(frame(payload, DONT_FRAGMENT), &mut errors);

    assert_eq!((fixture.dropped, fixture.tx_requested), (0, 1));
    let tx = fixture.io.pop_tx().unwrap();
    assert_eq!(tx.egress, WAN);
    assert_eq!(&tx.bytes[0..6], &FORWARD_MAC.0);
    assert_eq!(
        u16::from_be_bytes([tx.bytes[16], tx.bytes[17]]),
        WAN_MTU,
        "a datagram of exactly the MTU is carried whole"
    );
    assert_eq!(errors.pending_actions(), 0);
}

#[test]
fn one_byte_over_the_egress_mtu_is_not_forwarded() {
    // The other side of the same boundary.
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let payload = usize::from(WAN_MTU) - 20 + 1;
    let mut fixture = forward(frame(payload, DONT_FRAGMENT), &mut errors);

    assert_eq!((fixture.dropped, fixture.tx_requested), (1, 0));
    assert_eq!(
        fixture.io.pop_recycled().unwrap().cause,
        RecycleCause::Forwarding(DropReason::Ipv4FragmentationNeeded)
    );
}

#[test]
fn a_wide_ingress_link_does_not_relax_a_narrow_egress_link() {
    // The check must read the egress interface, not the ingress one: the LAN
    // side accepts 1500 bytes and the WAN side does not.
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let payload = usize::from(Ipv4Mtu::ETHERNET.bytes()) - 20;
    let mut fixture = forward(frame(payload, DONT_FRAGMENT), &mut errors);

    assert_eq!(fixture.dropped, 1);
    assert_eq!(
        fixture.io.pop_recycled().unwrap().cause,
        RecycleCause::Forwarding(DropReason::Ipv4FragmentationNeeded)
    );
}

#[test]
fn the_drop_reason_names_are_stable() {
    assert_eq!(
        DropReason::Ipv4FragmentationNeeded.code(),
        "IPV4_FRAGMENTATION_NEEDED"
    );
    assert_eq!(
        DropReason::Ipv4FragmentationRequired.code(),
        "IPV4_FRAGMENTATION_REQUIRED"
    );
    let _ = NoTrace;
}
