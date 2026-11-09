//! PPPoE sessions (RFC 2516): packets routed to a session's interface leave in the
//! session on its parent port, and the session's frames are taken out and
//! forwarded.

use ruster_core::{
    forward_batch_with_control, ipv4_header_checksum, ControlQueue, ForwardingSnapshot, IfId,
    Interface, Ipv4Address, Ipv6Fib, Ipv6Neighbor, Ipv6Route, LocalIpv4Binding, MacAddress,
    MonotonicMillis, Neighbor, NoTrace, PacketIo, PppoeSession, Route, Services,
};
use ruster_io_sim::SimIo;

const LAN: IfId = IfId(0);
const WAN: IfId = IfId(1);
const PPP: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const PPP_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 3]);
const HOST_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x10]);
const AC_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0xac]);
const HOST: [u8; 4] = [192, 168, 0, 10];
const REMOTE: [u8; 4] = [203, 0, 113, 7];
const SESSION: u16 = 0x1234;

fn ipv4(dst_mac: MacAddress, source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut frame = vec![0_u8; 42];
    frame[0..6].copy_from_slice(&dst_mac.0);
    frame[6..12].copy_from_slice(&HOST_MAC.0);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&28_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&source);
    frame[30..34].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame[38..40].copy_from_slice(&8_u16.to_be_bytes());
    frame
}

/// `inner` (an Ethernet frame) in session `session` from the access concentrator.
fn in_session(inner: &[u8], session: u16, protocol: [u8; 2]) -> Vec<u8> {
    let payload = &inner[14..];
    let mut frame = Vec::new();
    frame.extend_from_slice(&WAN_MAC.0);
    frame.extend_from_slice(&AC_MAC.0);
    frame.extend_from_slice(&[0x88, 0x64, 0x11, 0x00]);
    frame.extend_from_slice(&session.to_be_bytes());
    frame.extend_from_slice(&u16::try_from(payload.len() + 2).unwrap().to_be_bytes());
    frame.extend_from_slice(&protocol);
    frame.extend_from_slice(payload);
    frame
}

struct Tables {
    interfaces: [Interface; 3],
    routes: [Route; 2],
    neighbors: [Neighbor; 1],
    bindings: [LocalIpv4Binding; 1],
    ipv6: Ipv6Fib,
    sessions: [PppoeSession; 1],
}

fn tables() -> Tables {
    let a = Ipv4Address::from_octets;
    let ip6 = |t: &str| t.parse::<std::net::Ipv6Addr>().unwrap().octets();
    Tables {
        interfaces: [
            (LAN, LAN_MAC, 1500),
            (WAN, WAN_MAC, 1500),
            (PPP, PPP_MAC, 1492),
        ]
        .map(|(id, mac, mtu)| Interface { id, mac, mtu }),
        routes: [
            Route::new(a([192, 168, 0, 0]), 24, LAN, None).unwrap(),
            Route::new(a([0, 0, 0, 0]), 0, PPP, None).unwrap(),
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
            vec![
                Ipv6Route::new(ip6("2001:db8:1::"), 64, LAN, None).unwrap(),
                Ipv6Route::new(ip6("::"), 0, PPP, None).unwrap(),
            ],
            vec![Ipv6Neighbor {
                interface: LAN,
                target: ip6("2001:db8:1::10"),
                mac: HOST_MAC,
            }],
            Vec::new(),
        )
        .unwrap(),
        sessions: [PppoeSession {
            interface: PPP,
            parent: WAN,
            session: SESSION,
            peer: AC_MAC,
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
    .with_pppoe(&tables.sessions)
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
fn ipv4_routed_to_the_session_leaves_in_it() {
    let (egress, frame) = run(&tables(), LAN, ipv4(LAN_MAC, HOST, REMOTE)).expect("sent");
    assert_eq!(egress, WAN);
    assert_eq!(&frame[0..6], &AC_MAC.0);
    assert_eq!(&frame[6..12], &WAN_MAC.0);
    assert_eq!(&frame[12..14], &[0x88, 0x64]);
    assert_eq!(&frame[14..16], &[0x11, 0x00]);
    assert_eq!(u16::from_be_bytes([frame[16], frame[17]]), SESSION);
    assert_eq!(u16::from_be_bytes([frame[18], frame[19]]), 28 + 2);
    assert_eq!(&frame[20..22], &[0x00, 0x21], "PPP IPv4");
    assert_eq!(&frame[22 + 12..22 + 16], &HOST);
    assert_eq!(frame[22 + 8], 63);
}

#[test]
fn the_session_s_ipv4_is_taken_out_and_forwarded() {
    let inner = ipv4(PPP_MAC, REMOTE, HOST);
    let (egress, frame) =
        run(&tables(), WAN, in_session(&inner, SESSION, [0x00, 0x21])).expect("sent");
    assert_eq!(egress, LAN);
    assert_eq!(&frame[0..6], &HOST_MAC.0);
    assert_eq!(&frame[12..14], &[0x08, 0x00]);
    assert_eq!(&frame[26..30], &REMOTE);
}

#[test]
fn another_session_and_lcp_are_dropped() {
    let inner = ipv4(PPP_MAC, REMOTE, HOST);
    assert!(run(
        &tables(),
        WAN,
        in_session(&inner, SESSION + 1, [0x00, 0x21])
    )
    .is_none());
    assert!(run(&tables(), WAN, in_session(&inner, SESSION, [0xc0, 0x21])).is_none());
    // The same session ID, for another host on the parent's link (RFC 2516 5.5).
    let mut other_host = in_session(&inner, SESSION, [0x00, 0x21]);
    other_host[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 0x77]);
    assert!(run(&tables(), WAN, other_host).is_none());
}

#[test]
fn ipv6_goes_through_the_session_both_ways() {
    let mut out = Vec::new();
    out.extend_from_slice(&LAN_MAC.0);
    out.extend_from_slice(&HOST_MAC.0);
    out.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0, 0, 8, 17, 64]);
    out.extend_from_slice(
        &"2001:db8:1::10"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    out.extend_from_slice(
        &"2001:db8:9::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    out.extend_from_slice(&[0; 8]);
    let (egress, frame) = run(&tables(), LAN, out.clone()).expect("sent");
    assert_eq!(egress, WAN);
    assert_eq!(&frame[20..22], &[0x00, 0x57], "PPP IPv6");
    assert_eq!(u16::from_be_bytes([frame[18], frame[19]]), 48 + 2);

    let mut back = out;
    back[0..6].copy_from_slice(&PPP_MAC.0);
    back[22..38].copy_from_slice(
        &"2001:db8:9::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    back[38..54].copy_from_slice(
        &"2001:db8:1::10"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    let (egress, frame) =
        run(&tables(), WAN, in_session(&back, SESSION, [0x00, 0x57])).expect("sent");
    assert_eq!(egress, LAN);
    assert_eq!(&frame[12..14], &[0x86, 0xdd]);
}
