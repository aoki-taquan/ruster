//! NAT44 through `forward_batch_with_control` and `Services`, with no ARP resolution
//! runtime: the clock is the snapshot's.

mod support;

use ruster_core::{
    forward_batch_with_control, ipv4_header_checksum, ControlQueue, ForwardingSnapshot, IfId,
    Interface, Ipv4Address, LocalIpv4Binding, MacAddress, MonotonicMillis, Nat44UdpConfig,
    Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy, Neighbor, NoTrace, PacketIo, Route,
    Services,
};
use ruster_io_sim::SimIo;
use support::UdpTestIndexes;

const LAN: IfId = IfId(0);
const WAN: IfId = IfId(1);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const HOST_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 10]);
const GATEWAY_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 20]);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const HOST: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const GATEWAY: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);

fn udp(
    dst_mac: MacAddress,
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    let mut frame = vec![0_u8; 50];
    frame[0..6].copy_from_slice(&dst_mac.0);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 0x99]);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&36_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    frame[38..40].copy_from_slice(&16_u16.to_be_bytes());
    frame
}

#[test]
fn napt44_runs_without_an_arp_runtime() {
    let routes = [
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
        Route::new(
            Ipv4Address::from_octets([0, 0, 0, 0]),
            0,
            WAN,
            Some(GATEWAY),
        )
        .unwrap(),
    ];
    let interfaces = [
        Interface {
            id: LAN,
            mac: LAN_MAC,
            mtu: 1500,
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
            mtu: 1500,
        },
    ];
    let neighbors = [
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
    ];
    let bindings = [
        LocalIpv4Binding {
            interface: LAN,
            address: Ipv4Address::from_octets([10, 0, 0, 1]),
        },
        LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        },
    ];
    let base = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = Nat44UdpConfig::new(
        &base,
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_010,
        Nat44UdpPolicy::default(),
    )
    .unwrap();
    let mut indexes = UdpTestIndexes::new(config, 4, 4);
    let mut mappings = [Nat44UdpMappingSlot::default(); 4];
    let mut peers = [Nat44UdpPeerSlot::default(); 4];
    let mut runtime = indexes.runtime(config, &mut mappings, &mut peers);
    let mut queue = ControlQueue::new(4);
    let mut io = SimIo::new();

    // Out: the source becomes the public address and a pool port.
    let snapshot = base.with_now(MonotonicMillis(1_000));
    io.inject(LAN, udp(LAN_MAC, HOST, REMOTE, 5_000, 53));
    let batch = io.receive(8).unwrap();
    let services = Services {
        nat44_udp: Some((&config, &mut runtime)),
        ..Services::default()
    };
    forward_batch_with_control(batch, &snapshot, &mut queue, services, &mut NoTrace);
    let out = io.pop_tx().expect("translated and sent");
    assert_eq!(out.egress, WAN);
    assert_eq!(&out.bytes[0..6], &GATEWAY_MAC.0);
    assert_eq!(&out.bytes[26..30], &PUBLIC.octets());
    let port = u16::from_be_bytes([out.bytes[34], out.bytes[35]]);
    assert!((40_000..=40_010).contains(&port), "{port}");

    // Back: to the host's own address and port.
    let snapshot = base.with_now(MonotonicMillis(2_000));
    io.inject(WAN, udp(WAN_MAC, REMOTE, PUBLIC, 53, port));
    let batch = io.receive(8).unwrap();
    let services = Services {
        nat44_udp: Some((&config, &mut runtime)),
        ..Services::default()
    };
    forward_batch_with_control(batch, &snapshot, &mut queue, services, &mut NoTrace);
    let back = io.pop_tx().expect("translated back");
    assert_eq!(back.egress, LAN);
    assert_eq!(&back.bytes[0..6], &HOST_MAC.0);
    assert_eq!(&back.bytes[30..34], &HOST.octets());
    assert_eq!(u16::from_be_bytes([back.bytes[36], back.bytes[37]]), 5_000);
}
