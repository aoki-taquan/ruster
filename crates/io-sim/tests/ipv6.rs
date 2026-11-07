//! IPv6 forwarding with `ForwardingSnapshot::with_ipv6` and the control queue.

use ruster_core::{
    forward_batch_with_control, ConsumeReason, ControlQueue, DropReason, ForwardingSnapshot, IfId,
    Interface, Ipv6Fib, Ipv6Local, Ipv6Neighbor, Ipv6Route, MacAddress, PacketIo, TraceEvent,
    TraceSink,
};
use ruster_io_sim::{RecycleCause, SimIo};

const LAN: IfId = IfId(0);
const WAN: IfId = IfId(1);
const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const HOST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];
const GATEWAY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];

fn ip(text: &str) -> [u8; 16] {
    text.parse::<std::net::Ipv6Addr>().unwrap().octets()
}

#[derive(Default)]
struct Recorder(Vec<TraceEvent>);

impl TraceSink for Recorder {
    fn record(&mut self, event: TraceEvent) {
        if matches!(
            event,
            TraceEvent::Ipv6ToControl { .. }
                | TraceEvent::Ipv6NeighborMissing { .. }
                | TraceEvent::Dropped { .. }
        ) {
            self.0.push(event);
        }
    }
}

fn interfaces() -> [Interface; 2] {
    [
        Interface {
            id: LAN,
            mac: MacAddress(LAN_MAC),
            mtu: 1500,
        },
        Interface {
            id: WAN,
            mac: MacAddress(WAN_MAC),
            mtu: 1280,
        },
    ]
}

fn fib(with_gateway: bool) -> Ipv6Fib {
    let mut neighbors = vec![Ipv6Neighbor {
        interface: LAN,
        target: ip("2001:db8:1::10"),
        mac: MacAddress(HOST_MAC),
    }];
    if with_gateway {
        neighbors.push(Ipv6Neighbor {
            interface: WAN,
            target: ip("fe80::1"),
            mac: MacAddress(GATEWAY_MAC),
        });
    }
    Ipv6Fib::new(
        vec![
            Ipv6Route::new(ip("2001:db8:1::"), 64, LAN, None).unwrap(),
            Ipv6Route::new(ip("::"), 0, WAN, Some(ip("fe80::1"))).unwrap(),
        ],
        neighbors,
        vec![Ipv6Local {
            interface: LAN,
            address: ip("2001:db8:1::1"),
        }],
    )
    .unwrap()
}

/// An Ethernet frame with an IPv6 header and `payload`.
fn ipv6(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    source: &str,
    destination: &str,
    next_header: u8,
    hop_limit: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&0x86dd_u16.to_be_bytes());
    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    frame.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    frame.push(next_header);
    frame.push(hop_limit);
    frame.extend_from_slice(&ip(source));
    frame.extend_from_slice(&ip(destination));
    frame.extend_from_slice(payload);
    frame
}

fn udp_out(hop_limit: u8, destination: &str) -> Vec<u8> {
    ipv6(
        LAN_MAC,
        HOST_MAC,
        "2001:db8:1::10",
        destination,
        17,
        hop_limit,
        &[0; 16],
    )
}

fn run(io: &mut SimIo, fib: &Ipv6Fib, queue: &mut ControlQueue) -> Recorder {
    let interfaces = interfaces();
    let snapshot = ForwardingSnapshot::new(&[], &interfaces, &[], &[])
        .unwrap()
        .with_ipv6(fib);
    let mut trace = Recorder::default();
    let batch = io.receive(16).unwrap();
    forward_batch_with_control(batch, &snapshot, queue, None, &mut trace);
    trace
}

#[test]
fn a_packet_is_forwarded_to_its_next_hop_with_the_hop_limit_decremented() {
    let fib = fib(true);
    let mut queue = ControlQueue::new(4);
    let mut io = SimIo::new();
    let sent = udp_out(64, "2001:db8:99::7");
    io.inject(LAN, sent.clone());
    run(&mut io, &fib, &mut queue);
    let tx = io.pop_tx().expect("forwarded");
    assert_eq!(tx.egress, WAN);
    assert_eq!(&tx.bytes[0..6], &GATEWAY_MAC);
    assert_eq!(&tx.bytes[6..12], &WAN_MAC);
    assert_eq!(tx.bytes[14 + 7], 63);
    assert_eq!(
        &tx.bytes[14..21],
        &sent[14..21],
        "everything else is unchanged"
    );
    assert_eq!(&tx.bytes[22..], &sent[22..]);
}

#[test]
fn a_packet_to_an_on_link_host_goes_to_that_host() {
    let fib = fib(true);
    let mut queue = ControlQueue::new(4);
    let mut io = SimIo::new();
    let frame = ipv6(
        WAN_MAC,
        GATEWAY_MAC,
        "2001:db8:99::7",
        "2001:db8:1::10",
        17,
        60,
        &[0; 8],
    );
    io.inject(WAN, frame);
    run(&mut io, &fib, &mut queue);
    let tx = io.pop_tx().expect("forwarded");
    assert_eq!(tx.egress, LAN);
    assert_eq!(&tx.bytes[0..6], &HOST_MAC);
    assert_eq!(&tx.bytes[6..12], &LAN_MAC);
}

#[test]
fn neighbor_discovery_goes_to_the_control_queue_unchanged() {
    let fib = fib(true);
    let mut queue = ControlQueue::new(4);
    let mut io = SimIo::new();
    // A Neighbor Solicitation for the router's address to its solicited-node group,
    // and a Router Solicitation to all routers.
    let solicitation = ipv6(
        [0x33, 0x33, 0xff, 0, 0, 1],
        HOST_MAC,
        "2001:db8:1::10",
        "ff02::1:ff00:1",
        58,
        255,
        &[135, 0, 0, 0, 0, 0, 0, 0],
    );
    let router_solicitation = ipv6(
        [0x33, 0x33, 0, 0, 0, 2],
        HOST_MAC,
        "fe80::10",
        "ff02::2",
        58,
        255,
        &[133, 0, 0, 0, 0, 0, 0, 0],
    );
    io.inject(LAN, solicitation.clone());
    io.inject(LAN, router_solicitation.clone());
    let trace = run(&mut io, &fib, &mut queue);
    assert!(io.pop_tx().is_none());
    let frames: Vec<_> = queue
        .frames()
        .iter()
        .map(|f| (f.ingress, f.bytes().to_vec()))
        .collect();
    assert_eq!(frames, [(LAN, solicitation), (LAN, router_solicitation)]);
    assert_eq!(
        io.pop_recycled().map(|frame| frame.cause),
        Some(RecycleCause::Consumed(ConsumeReason::Ipv6Control))
    );
    assert_eq!(
        trace.0,
        [
            TraceEvent::Ipv6ToControl { ingress: LAN },
            TraceEvent::Ipv6ToControl { ingress: LAN }
        ]
    );
    queue.clear();
    assert!(queue.frames().is_empty());
}

#[test]
fn a_full_control_queue_drops_and_counts() {
    let fib = fib(true);
    let mut queue = ControlQueue::new(1);
    let mut io = SimIo::new();
    let advertisement = ipv6(
        LAN_MAC,
        HOST_MAC,
        "2001:db8:1::10",
        "2001:db8:1::1",
        58,
        255,
        &[136, 0, 0, 0, 0, 0, 0, 0],
    );
    io.inject(LAN, advertisement.clone());
    io.inject(LAN, advertisement);
    let trace = run(&mut io, &fib, &mut queue);
    assert_eq!(queue.frames().len(), 1);
    assert!(trace.0.contains(&TraceEvent::Dropped {
        ingress: LAN,
        reason: DropReason::Ipv6ControlQueueFull
    }));
}

#[test]
fn a_missing_next_hop_is_reported() {
    let fib = fib(false);
    let mut queue = ControlQueue::new(4);
    let mut io = SimIo::new();
    io.inject(LAN, udp_out(64, "2001:db8:99::7"));
    let trace = run(&mut io, &fib, &mut queue);
    assert!(io.pop_tx().is_none());
    assert_eq!(
        trace.0,
        [
            TraceEvent::Ipv6NeighborMissing {
                egress: WAN,
                target: ip("fe80::1")
            },
            TraceEvent::Dropped {
                ingress: LAN,
                reason: DropReason::NeighborUnresolved
            }
        ]
    );
}

#[test]
fn packets_that_must_not_be_forwarded_are_dropped() {
    let fib = fib(true);
    let cases = [
        (
            udp_out(1, "2001:db8:99::7"),
            DropReason::Ipv6HopLimitExpired,
        ),
        (
            udp_out(64, "fe80::99"),
            DropReason::Ipv6DestinationNotForwarded,
        ),
        (udp_out(64, "::1"), DropReason::Ipv6DestinationNotForwarded),
        (
            udp_out(64, "ff0e::1"),
            DropReason::Ipv6DestinationNotForwarded,
        ),
        (
            udp_out(64, "2001:db8:1::1"),
            DropReason::Ipv6LocalUnsupported,
        ),
        (
            ipv6(
                LAN_MAC,
                HOST_MAC,
                "fe80::10",
                "2001:db8:99::7",
                17,
                64,
                &[0; 8],
            ),
            DropReason::Ipv6SourceInvalid,
        ),
        (
            ipv6(
                LAN_MAC,
                HOST_MAC,
                "ff02::1",
                "2001:db8:99::7",
                17,
                64,
                &[0; 8],
            ),
            DropReason::Ipv6SourceInvalid,
        ),
        (
            ipv6(
                WAN_MAC,
                HOST_MAC,
                "2001:db8:1::10",
                "2001:db8:99::7",
                17,
                64,
                &[0; 8],
            ),
            DropReason::Ipv6EthernetAddressInvalid,
        ),
        (
            ipv6(
                LAN_MAC,
                HOST_MAC,
                "2001:db8:1::10",
                "2001:db8:99::7",
                17,
                64,
                &[0; 1300],
            ),
            DropReason::Ipv6PacketTooBig,
        ),
        (
            udp_out(64, "2001:db8:99::7")[..50].to_vec(),
            DropReason::Ipv6HeaderTruncated,
        ),
        (
            {
                let mut frame = udp_out(64, "2001:db8:99::7");
                frame[18..20].copy_from_slice(&100_u16.to_be_bytes());
                frame
            },
            DropReason::Ipv6PayloadLengthExceedsPacket,
        ),
    ];
    for (frame, reason) in cases {
        let mut queue = ControlQueue::new(4);
        let mut io = SimIo::new();
        io.inject(LAN, frame);
        let trace = run(&mut io, &fib, &mut queue);
        assert!(io.pop_tx().is_none(), "{reason:?}");
        assert_eq!(
            trace.0,
            [TraceEvent::Dropped {
                ingress: LAN,
                reason
            }],
            "{reason:?}"
        );
    }
}

#[test]
fn without_ipv6_tables_ipv6_is_an_unsupported_ethernet_type() {
    let interfaces = interfaces();
    let snapshot = ForwardingSnapshot::new(&[], &interfaces, &[], &[]).unwrap();
    let mut io = SimIo::new();
    io.inject(LAN, udp_out(64, "2001:db8:99::7"));
    let mut trace = Recorder::default();
    let mut queue = ControlQueue::new(1);
    let batch = io.receive(16).unwrap();
    forward_batch_with_control(batch, &snapshot, &mut queue, None, &mut trace);
    assert_eq!(
        trace.0,
        [TraceEvent::Dropped {
            ingress: LAN,
            reason: DropReason::UnsupportedEtherType
        }]
    );
}

#[test]
fn routes_are_checked() {
    assert!(Ipv6Route::new(ip("2001:db8::1"), 64, LAN, None).is_err());
    assert!(Ipv6Route::new(ip("::"), 129, LAN, None).is_err());
    let route = Ipv6Route::new(ip("2001:db8::"), 32, LAN, None).unwrap();
    assert!(Ipv6Fib::new(vec![route, route], vec![], vec![]).is_err());
}
