//! Several VRFs: each packet is decided with its ingress interface's VRF
//! (`ForwardingSnapshot::with_vrfs`).

use ruster_core::{
    forward_batch, ipv4_header_checksum, ForwardingSnapshot, IfId, Interface, Ipv4Address,
    LocalIpv4Binding, MacAddress, Neighbor, NoTrace, PacketIo, Route,
};
use ruster_io_sim::SimIo;

/// Two customers with the same addresses, and a shared uplink in the default VRF.
const RED: IfId = IfId(0);
const BLUE: IfId = IfId(1);
const UPLINK: IfId = IfId(2);
const RED_UP: IfId = IfId(3);
const BLUE_UP: IfId = IfId(4);

fn mac(last: u8) -> MacAddress {
    MacAddress([2, 0, 0, 0, 0, last])
}

fn a(octets: [u8; 4]) -> Ipv4Address {
    Ipv4Address::from_octets(octets)
}

fn interfaces() -> Vec<Interface> {
    [RED, BLUE, UPLINK, RED_UP, BLUE_UP]
        .into_iter()
        .map(|id| Interface {
            id,
            mac: mac(u8::try_from(id.0).unwrap() + 1),
            mtu: 1500,
        })
        .collect()
}

fn neighbors() -> Vec<Neighbor> {
    vec![
        Neighbor {
            interface: RED_UP,
            target: a([10, 9, 0, 1]),
            mac: mac(0x31),
        },
        Neighbor {
            interface: BLUE_UP,
            target: a([10, 9, 0, 1]),
            mac: mac(0x41),
        },
        Neighbor {
            interface: UPLINK,
            target: a([198, 51, 100, 1]),
            mac: mac(0x51),
        },
    ]
}

fn udp(ingress_mac: MacAddress, destination: [u8; 4]) -> Vec<u8> {
    let mut frame = vec![0_u8; 60];
    frame[0..6].copy_from_slice(&ingress_mac.0);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 0x99]);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&46_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&[10, 0, 0, 10]);
    frame[30..34].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

#[test]
fn each_packet_uses_its_ingress_vrf_and_routes_may_leave_through_another_vrf() {
    let interfaces = interfaces();
    let neighbors = neighbors();
    let bindings: [LocalIpv4Binding; 0] = [];
    // red and blue both send 10.9.0.0/16 to their own uplink; red also leaks the
    // internet to the default VRF's uplink.
    let red_routes = [
        Route::new(a([10, 9, 0, 0]), 16, RED_UP, Some(a([10, 9, 0, 1]))).unwrap(),
        Route::new(a([0, 0, 0, 0]), 0, UPLINK, Some(a([198, 51, 100, 1]))).unwrap(),
    ];
    let blue_routes = [Route::new(a([10, 9, 0, 0]), 16, BLUE_UP, Some(a([10, 9, 0, 1]))).unwrap()];
    let default_routes: [Route; 0] = [];
    let default =
        ForwardingSnapshot::new(&default_routes, &interfaces, &neighbors, &bindings).unwrap();
    let red = ForwardingSnapshot::new(&red_routes, &interfaces, &neighbors, &bindings).unwrap();
    let blue = ForwardingSnapshot::new(&blue_routes, &interfaces, &neighbors, &bindings).unwrap();
    let vrfs = [default, red, blue];
    // RED -> red, BLUE -> blue, the rest default.
    let by_ingress = [1, 2, 0, 1, 2];
    let snapshot = default.with_vrfs(&vrfs, &by_ingress);

    let mut io = SimIo::new();
    io.inject(RED, udp(mac(1), [10, 9, 1, 1]));
    io.inject(BLUE, udp(mac(2), [10, 9, 1, 1]));
    io.inject(RED, udp(mac(1), [203, 0, 113, 7]));
    io.inject(BLUE, udp(mac(2), [203, 0, 113, 7]));
    let batch = io.receive(16).unwrap();
    let report = forward_batch(batch, &snapshot, &mut NoTrace);
    assert_eq!(report.tx_requested, 3);
    assert_eq!(report.dropped, 1, "blue has no route to the internet");

    let mut sent: Vec<(IfId, [u8; 6])> = Vec::new();
    while let Some(frame) = io.pop_tx() {
        let mut dst = [0; 6];
        dst.copy_from_slice(&frame.bytes[0..6]);
        sent.push((frame.egress, dst));
    }
    assert_eq!(
        sent,
        [
            (RED_UP, mac(0x31).0),
            (BLUE_UP, mac(0x41).0),
            (UPLINK, mac(0x51).0),
        ]
    );
}

#[test]
fn an_ingress_without_a_vrf_uses_the_outer_snapshot() {
    let interfaces = interfaces();
    let neighbors = neighbors();
    let bindings: [LocalIpv4Binding; 0] = [];
    let routes = [Route::new(a([0, 0, 0, 0]), 0, UPLINK, Some(a([198, 51, 100, 1]))).unwrap()];
    let none: [Route; 0] = [];
    let outer = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let empty = ForwardingSnapshot::new(&none, &interfaces, &neighbors, &bindings).unwrap();
    let vrfs = [empty];
    // Only RED is listed, and its index is out of range.
    let by_ingress = [5];
    let snapshot = outer.with_vrfs(&vrfs, &by_ingress);
    let mut io = SimIo::new();
    io.inject(RED, udp(mac(1), [203, 0, 113, 7]));
    io.inject(BLUE, udp(mac(2), [203, 0, 113, 7]));
    let batch = io.receive(16).unwrap();
    let report = forward_batch(batch, &snapshot, &mut NoTrace);
    assert_eq!(report.tx_requested, 2);
}
