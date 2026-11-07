//! IPv4 in IPv6 tunnels (DS-Lite B4): IPv4 routed to the tunnel leaves inside IPv6
//! to the AFTR, and the AFTR's IPv6 packets are unwrapped and forwarded.

use ruster_core::{
    forward_batch_with_control, ipv4_header_checksum, ControlQueue, ForwardingSnapshot, IfId,
    Interface, Ipv4Address, Ipv4InIpv6Tunnel, Ipv6Fib, Ipv6Local, Ipv6Neighbor, Ipv6Route,
    LocalIpv4Binding, MacAddress, MonotonicMillis, Neighbor, NoTrace, PacketIo, Route, Services,
};
use ruster_io_sim::SimIo;

const LAN: IfId = IfId(0);
const WAN: IfId = IfId(1);
const SOFTWIRE: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const SOFTWIRE_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 3]);
const HOST_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x10]);
const GATEWAY_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xfe]);
const HOST: [u8; 4] = [192, 168, 0, 10];
const REMOTE: [u8; 4] = [203, 0, 113, 7];

fn ip6(text: &str) -> [u8; 16] {
    text.parse::<std::net::Ipv6Addr>().unwrap().octets()
}

fn b4() -> [u8; 16] {
    ip6("2001:db8:1::2")
}

fn aftr() -> [u8; 16] {
    ip6("2001:db8:ff::1")
}

fn ipv4(dst_mac: MacAddress, source: [u8; 4], destination: [u8; 4], tos: u8) -> Vec<u8> {
    let mut frame = vec![0_u8; 42];
    frame[0..6].copy_from_slice(&dst_mac.0);
    frame[6..12].copy_from_slice(&HOST_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = tos;
    frame[16..18].copy_from_slice(&28_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&source);
    frame[30..34].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame[34..36].copy_from_slice(&1000_u16.to_be_bytes());
    frame[36..38].copy_from_slice(&53_u16.to_be_bytes());
    frame[38..40].copy_from_slice(&8_u16.to_be_bytes());
    frame
}

/// `inner` (an Ethernet + IPv4 frame) wrapped by the AFTR toward the B4.
fn from_aftr(inner: &[u8], source: [u8; 16], destination: [u8; 16]) -> Vec<u8> {
    let payload = &inner[14..];
    let mut frame = Vec::new();
    frame.extend_from_slice(&WAN_MAC.0);
    frame.extend_from_slice(&GATEWAY_MAC.0);
    frame.extend_from_slice(&0x86dd_u16.to_be_bytes());
    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    frame.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&[4, 64]);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(payload);
    frame
}

struct Tables {
    interfaces: [Interface; 3],
    routes: [Route; 2],
    neighbors: [Neighbor; 1],
    bindings: [LocalIpv4Binding; 1],
    ipv6: Ipv6Fib,
    tunnels: [Ipv4InIpv6Tunnel; 1],
}

fn tables() -> Tables {
    let a = Ipv4Address::from_octets;
    Tables {
        interfaces: [
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
            Interface {
                id: SOFTWIRE,
                mac: SOFTWIRE_MAC,
                mtu: 1460,
            },
        ],
        routes: [
            Route::new(a([192, 168, 0, 0]), 24, LAN, None).unwrap(),
            Route::new(a([0, 0, 0, 0]), 0, SOFTWIRE, None).unwrap(),
        ],
        neighbors: [Neighbor {
            interface: LAN,
            target: a(HOST),
            mac: HOST_MAC,
        }],
        bindings: [LocalIpv4Binding {
            interface: LAN,
            address: a([192, 168, 0, 1]),
        }],
        ipv6: Ipv6Fib::new(
            vec![Ipv6Route::new(ip6("::"), 0, WAN, Some(ip6("fe80::1"))).unwrap()],
            vec![Ipv6Neighbor {
                interface: WAN,
                target: ip6("fe80::1"),
                mac: GATEWAY_MAC,
            }],
            vec![Ipv6Local {
                interface: WAN,
                address: b4(),
            }],
        )
        .unwrap(),
        tunnels: [Ipv4InIpv6Tunnel {
            interface: SOFTWIRE,
            local: b4(),
            remote: aftr(),
        }],
    }
}

fn run(tables: &Tables, ingress: IfId, frame: Vec<u8>) -> Option<(IfId, Vec<u8>)> {
    let snapshot = ForwardingSnapshot::new(
        &tables.routes,
        &tables.interfaces,
        &tables.neighbors,
        &tables.bindings,
    )
    .unwrap()
    .with_ipv6(&tables.ipv6)
    .with_tunnels(&tables.tunnels)
    .with_now(MonotonicMillis(1));
    let mut io = SimIo::new();
    io.inject(ingress, frame);
    let batch = io.receive(1).unwrap();
    let mut control = ControlQueue::new(4);
    forward_batch_with_control(
        batch,
        &snapshot,
        &mut control,
        Services::default(),
        &mut NoTrace,
    );
    io.pop_tx().map(|tx| (tx.egress, tx.bytes))
}

#[test]
fn ipv4_to_the_tunnel_leaves_inside_ipv6_to_the_aftr() {
    let tables = tables();
    let (egress, frame) = run(&tables, LAN, ipv4(LAN_MAC, HOST, REMOTE, 0xb8)).expect("sent");
    assert_eq!(egress, WAN);
    assert_eq!(&frame[0..6], &GATEWAY_MAC.0);
    assert_eq!(&frame[6..12], &WAN_MAC.0);
    assert_eq!(&frame[12..14], &[0x86, 0xdd]);
    let ip = 14;
    assert_eq!(frame[ip] >> 4, 6);
    assert_eq!(
        ((frame[ip] & 0x0f) << 4) | (frame[ip + 1] >> 4),
        0xb8,
        "TOS copied"
    );
    assert_eq!(u16::from_be_bytes([frame[ip + 4], frame[ip + 5]]), 28);
    assert_eq!(frame[ip + 6], 4, "IPv4 in IPv6");
    assert_eq!(&frame[ip + 8..ip + 24], &b4());
    assert_eq!(&frame[ip + 24..ip + 40], &aftr());
    let inner = ip + 40;
    assert_eq!(
        &frame[inner + 12..inner + 16],
        &HOST,
        "inner source unchanged"
    );
    assert_eq!(frame[inner + 8], 63, "inner TTL decremented once");
}

#[test]
fn the_aftr_s_ipv6_is_unwrapped_and_forwarded() {
    let tables = tables();
    let inner = ipv4(SOFTWIRE_MAC, REMOTE, HOST, 0);
    let (egress, frame) = run(&tables, WAN, from_aftr(&inner, aftr(), b4())).expect("sent");
    assert_eq!(egress, LAN);
    assert_eq!(&frame[0..6], &HOST_MAC.0);
    assert_eq!(&frame[6..12], &LAN_MAC.0);
    assert_eq!(&frame[12..14], &[0x08, 0x00]);
    assert_eq!(&frame[26..30], &REMOTE);
    assert_eq!(frame[22], 63);
}

#[test]
fn ipv6_from_another_source_is_not_unwrapped() {
    let tables = tables();
    let inner = ipv4(SOFTWIRE_MAC, REMOTE, HOST, 0);
    assert!(run(&tables, WAN, from_aftr(&inner, ip6("2001:db8:ee::1"), b4())).is_none());
}

#[test]
fn a_datagram_longer_than_the_tunnel_mtu_is_not_sent() {
    let tables = tables();
    let mut frame = ipv4(LAN_MAC, HOST, REMOTE, 0);
    frame.resize(14 + 1480, 0);
    frame[16..18].copy_from_slice(&1480_u16.to_be_bytes());
    frame[20] = 0x40;
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    assert!(run(&tables, LAN, frame).is_none_or(|(egress, _)| egress != WAN));
}

#[test]
fn a_destination_options_header_before_the_inner_packet_is_stepped_over() {
    let tables = tables();
    let inner = ipv4(SOFTWIRE_MAC, REMOTE, HOST, 0);
    let mut frame = from_aftr(&inner, aftr(), b4());
    // Next Header 60, then an 8-byte Destination Options header with RFC 2473's
    // Tunnel Encapsulation Limit option (type 4, length 1, limit 4) and a PadN.
    frame[14 + 6] = 60;
    let options = [4, 0, 4, 1, 4, 1, 0, 0];
    frame.splice(54..54, options);
    let payload = u16::from_be_bytes([frame[18], frame[19]]) + 8;
    frame[18..20].copy_from_slice(&payload.to_be_bytes());
    let (egress, out) = run(&tables, WAN, frame).expect("sent");
    assert_eq!(egress, LAN);
    assert_eq!(&out[12..14], &[0x08, 0x00]);
    assert_eq!(&out[26..30], &REMOTE);
}

#[test]
fn a_tunnel_packet_from_another_link_is_not_unwrapped() {
    let tables = tables();
    let inner = ipv4(SOFTWIRE_MAC, REMOTE, HOST, 0);
    // From the LAN, passing itself off as the AFTR.
    let mut frame = from_aftr(&inner, aftr(), b4());
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    assert!(run(&tables, LAN, frame).is_none());
}
