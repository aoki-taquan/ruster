//! SRv6 in the FE: the route table's SID (End.DT4 into VRF red) and SR policy (red's
//! 10.2.0.0/16 into fc00:2::4) are built into core's SRv6 table.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::net::UnixStream;

use ruster_core::{ipv4_header_checksum, IfId};
use ruster_fe::{writers, Fe};
use ruster_io_sim::SimIo;
use ruster_proto::coap::Code;
use ruster_proto::session::{Client, Event};
use ruster_proto::table::{Change, Key, NextHop, RouteAction, Srv6Encap, Srv6Local, Value};
use ruster_proto::task::Task;

const WAN: IfId = IfId(0);
const LAN: IfId = IfId(1);
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 3];
const GATEWAY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
const HOST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];
const HOST: [u8; 4] = [192, 168, 0, 10];
const REMOTE: [u8; 4] = [10, 2, 0, 7];

fn v6(text: &str) -> Ipv6Addr {
    text.parse().unwrap()
}

fn iface(name: &str, mac: [u8; 6], vrf: &str) -> Change {
    Change::set(
        Key::Interface { name: name.into() },
        Value::Interface {
            enabled: true,
            mac,
            mtu: 1500,
            vrf: vrf.into(),
            vlan: None,
            tunnel: None,
            pppoe: None,
        },
    )
}

fn route(vrf: &str, prefix: IpAddr, len: u8, action: RouteAction) -> Change {
    Change::set(
        Key::Route {
            vrf: vrf.into(),
            prefix,
            len,
        },
        Value::Route(action),
    )
}

fn bench() -> Fe<SimIo> {
    let mut fe = Fe::new(SimIo::new(), vec!["wan".into(), "lan".into()]);
    let config = [
        iface("wan", WAN_MAC, "default"),
        iface("lan", LAN_MAC, "red"),
        Change::set(
            Key::Address {
                interface: "wan".into(),
                address: v6("2001:db8::1").into(),
            },
            Value::Address { prefix_len: 64 },
        ),
        Change::set(
            Key::Address {
                interface: "lan".into(),
                address: Ipv4Addr::new(192, 168, 0, 1).into(),
            },
            Value::Address { prefix_len: 24 },
        ),
    ];
    let routes = [
        route(
            "default",
            Ipv6Addr::UNSPECIFIED.into(),
            0,
            RouteAction::Forward(vec![NextHop {
                interface: "wan".into(),
                address: Some(v6("fe80::fe").into()),
            }]),
        ),
        route(
            "default",
            v6("fc00:1::4").into(),
            128,
            RouteAction::Srv6Local(Srv6Local::EndDt4 { vrf: "red".into() }),
        ),
        route(
            "red",
            Ipv4Addr::new(192, 168, 0, 0).into(),
            24,
            RouteAction::Forward(vec![NextHop {
                interface: "lan".into(),
                address: None,
            }]),
        ),
        route(
            "red",
            Ipv4Addr::new(10, 2, 0, 0).into(),
            16,
            RouteAction::Srv6Encap(Srv6Encap {
                source: v6("2001:db8::1"),
                segments: vec![v6("fc00:2::4")],
                reduced: false,
            }),
        ),
    ];
    let neighbors = [
        Change::set(
            Key::Neighbor {
                interface: "wan".into(),
                address: v6("fe80::fe").into(),
            },
            Value::Neighbor { mac: GATEWAY_MAC },
        ),
        Change::set(
            Key::Neighbor {
                interface: "lan".into(),
                address: Ipv4Addr::from(HOST).into(),
            },
            Value::Neighbor { mac: HOST_MAC },
        ),
    ];
    for (writer, changes) in [
        (writers::CONFIG, &config[..]),
        (writers::ROUTE, &routes[..]),
        (writers::NEIGHBOR, &neighbors[..]),
    ] {
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, writer).unwrap();
        let mut client = Client::new(b).unwrap();
        let token = client.patch(changes).unwrap();
        assert_eq!(settle(&mut fe, &mut client, token), Code::CHANGED);
    }
    fe
}

fn settle(fe: &mut Fe<SimIo>, client: &mut Client, token: u32) -> Code {
    let mut code = None;
    for _ in 0..1_000 {
        let mut busy = fe.step(0).busy;
        let (progress, events) = client.poll();
        busy |= progress.busy;
        for event in events {
            if let Event::Response {
                token: t, code: c, ..
            } = event
            {
                if t == token {
                    code = Some(c);
                }
            }
        }
        if !busy && code.is_some() {
            break;
        }
    }
    code.expect("response")
}

fn send(fe: &mut Fe<SimIo>, port: IfId, frame: Vec<u8>) -> Vec<(IfId, Vec<u8>)> {
    fe.io_mut().inject(port, frame);
    fe.step(0);
    let mut out = Vec::new();
    while let Some(tx) = fe.io_mut().pop_tx() {
        out.push((tx.egress, tx.bytes));
    }
    out
}

/// An IPv4 UDP packet (no Ethernet header).
fn ipv4(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut ip = vec![0_u8; 28];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&28_u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&source);
    ip[16..20].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    ip[24..26].copy_from_slice(&8_u16.to_be_bytes());
    ip
}

#[test]
fn a_route_with_an_sr_policy_leaves_wrapped() {
    let mut fe = bench();
    let mut frame = LAN_MAC.to_vec();
    frame.extend_from_slice(&HOST_MAC);
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(&ipv4(HOST, REMOTE));
    let out = send(&mut fe, LAN, frame);
    assert_eq!(out.len(), 1);
    let (port, wrapped) = &out[0];
    assert_eq!(*port, WAN);
    assert_eq!(&wrapped[0..6], &GATEWAY_MAC);
    assert_eq!(&wrapped[12..14], &[0x86, 0xdd]);
    assert_eq!(wrapped[14 + 6], 4, "one segment: no SRH");
    assert_eq!(&wrapped[14 + 8..14 + 24], &v6("2001:db8::1").octets());
    assert_eq!(&wrapped[14 + 24..14 + 40], &v6("fc00:2::4").octets());
    assert_eq!(&wrapped[14 + 40 + 16..14 + 40 + 20], &REMOTE);
}

#[test]
fn a_packet_to_an_end_dt4_sid_is_unwrapped_into_its_vrf() {
    let mut fe = bench();
    let inner = ipv4(REMOTE, HOST);
    let mut frame = WAN_MAC.to_vec();
    frame.extend_from_slice(&GATEWAY_MAC);
    frame.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    frame.extend_from_slice(&u16::try_from(24 + inner.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&[43, 64]);
    frame.extend_from_slice(&v6("2001:db8:ff::9").octets());
    frame.extend_from_slice(&v6("fc00:1::4").octets());
    // A Segment Routing Header with no segment left, as Linux puts on.
    frame.extend_from_slice(&[4, 2, 4, 0, 0, 0, 0, 0]);
    frame.extend_from_slice(&v6("fc00:1::4").octets());
    frame.extend_from_slice(&inner);
    let out = send(&mut fe, WAN, frame);
    assert_eq!(out.len(), 1);
    let (port, sent) = &out[0];
    assert_eq!(*port, LAN);
    assert_eq!(&sent[0..6], &HOST_MAC);
    assert_eq!(&sent[12..14], &[0x08, 0x00]);
    assert_eq!(&sent[14 + 16..14 + 20], &HOST);
}

/// An Ethernet frame from the host to `REMOTE` (behind the SR policy): IPv4 UDP,
/// `len` bytes long.
fn long_to_policy(len: usize, df: bool) -> Vec<u8> {
    let mut frame = LAN_MAC.to_vec();
    frame.extend_from_slice(&HOST_MAC);
    frame.extend_from_slice(&[0x08, 0x00]);
    let mut ip = vec![0_u8; len];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    if df {
        ip[6] = 0x40;
    }
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&HOST);
    ip[16..20].copy_from_slice(&REMOTE);
    let checksum = ipv4_header_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    ip[24..26].copy_from_slice(&u16::try_from(len - 20).unwrap().to_be_bytes());
    frame.extend_from_slice(&ip);
    frame
}

#[test]
fn an_ipv4_packet_without_df_too_long_once_wrapped_is_fragmented_then_wrapped() {
    // RFC 8754 5.3 and RFC 2473 7: the outer packet is never fragmented; the inner
    // IPv4 packet (DF clear) is cut to fit 1500 - 40 (RFC 791), each fragment wrapped.
    let mut fe = bench();
    let out = send(&mut fe, LAN, long_to_policy(1500, false));
    assert!(out.len() >= 2, "{} frames", out.len());
    let mut carried = 0;
    for (port, frame) in &out {
        assert_eq!(*port, WAN);
        assert!(frame.len() - 14 <= 1500, "each fits the link");
        assert_eq!(frame[14 + 6], 4, "inner IPv4, no SRH");
        let inner = 14 + 40;
        let total = usize::from(u16::from_be_bytes([frame[inner + 2], frame[inner + 3]]));
        assert!(total <= 1460);
        assert_eq!(
            usize::from(u16::from_be_bytes([frame[14 + 4], frame[14 + 5]])),
            total,
            "outer Payload Length"
        );
        carried += total - 20;
    }
    assert_eq!(carried, 1500 - 20, "all of the payload");
}

#[test]
fn an_ipv4_packet_with_df_too_long_once_wrapped_gets_fragmentation_needed() {
    // RFC 2473 7.2 and RFC 1191 section 4: Destination Unreachable code 4 with the
    // Next-Hop MTU the policy carries, 1500 - 40.
    let mut fe = bench();
    assert!(send(&mut fe, LAN, long_to_policy(1460, true))
        .iter()
        .any(|(port, _)| *port == WAN));
    let out = send(&mut fe, LAN, long_to_policy(1461, true));
    assert!(out.iter().all(|(port, _)| *port != WAN));
    let (port, error) = out.first().expect("an ICMP error back");
    assert_eq!(*port, LAN);
    assert_eq!(&error[0..6], &HOST_MAC);
    assert_eq!(error[14 + 9], 1, "ICMP");
    let icmp = 14 + 20;
    assert_eq!((error[icmp], error[icmp + 1]), (3, 4));
    assert_eq!(u16::from_be_bytes([error[icmp + 6], error[icmp + 7]]), 1460);
}

#[test]
fn routes_with_the_same_policy_share_one_interface() {
    let mut fe = bench();
    // More routes than there are interface ids, all with the policy of the bench's
    // 10.2.0.0/16, and one with another policy.
    let policy = |segment: &str| {
        RouteAction::Srv6Encap(Srv6Encap {
            source: v6("2001:db8::1"),
            segments: vec![v6(segment)],
            reduced: false,
        })
    };
    let mut routes: Vec<Change> = (0..70_000_u32)
        .map(|n| {
            let address = Ipv4Addr::from(0x0b00_0000 | n);
            route("red", address.into(), 32, policy("fc00:2::4"))
        })
        .collect();
    routes.push(route(
        "red",
        Ipv4Addr::new(10, 3, 0, 0).into(),
        16,
        policy("fc00:3::4"),
    ));
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, writers::ROUTE).unwrap();
    let mut client = Client::new(b).unwrap();
    let token = client.patch(&routes).unwrap();
    assert_eq!(settle(&mut fe, &mut client, token), Code::CHANGED);

    let to = |destination: [u8; 4]| {
        let mut frame = LAN_MAC.to_vec();
        frame.extend_from_slice(&HOST_MAC);
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&ipv4(HOST, destination));
        frame
    };
    for (destination, segment) in [
        ([11, 1, 17, 111], "fc00:2::4"),
        (REMOTE, "fc00:2::4"),
        ([10, 3, 0, 9], "fc00:3::4"),
    ] {
        let out = send(&mut fe, LAN, to(destination));
        assert_eq!(out.len(), 1, "{destination:?}");
        assert_eq!(&out[0].1[14 + 24..14 + 40], &v6(segment).octets());
    }
}

/// A frame from the WAN gateway to `sid`, with an SRv6 header with `left` segments
/// left, around `inner` (upper-layer header `next`).
fn to_sid(sid: &str, left: u8, next: u8, inner: &[u8]) -> Vec<u8> {
    let mut frame = WAN_MAC.to_vec();
    frame.extend_from_slice(&GATEWAY_MAC);
    frame.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    frame.extend_from_slice(&u16::try_from(40 + inner.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&[43, 64]);
    frame.extend_from_slice(&v6("2001:db8:ff::9").octets());
    frame.extend_from_slice(&v6(sid).octets());
    frame.extend_from_slice(&[next, 4, 4, left, 1, 0, 0, 0]);
    frame.extend_from_slice(&v6(sid).octets());
    frame.extend_from_slice(&v6("fc00:9::1").octets());
    frame.extend_from_slice(inner);
    frame
}

/// An IPv6 UDP packet (no Ethernet header) with Hop Limit 64.
fn ipv6(source: &str, destination: &str) -> Vec<u8> {
    let mut ip = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
    ip.extend_from_slice(&v6(source).octets());
    ip.extend_from_slice(&v6(destination).octets());
    ip.extend_from_slice(&[0, 1, 0, 2, 0, 8, 0, 0]);
    ip
}

/// The bench with End.DT46 into red, End.DX4 to the LAN host and End.DX6 to the
/// LAN host's link-local address, and an IPv6 default route in red.
fn bench_with_cross_connects() -> Fe<SimIo> {
    let mut fe = bench();
    let lan_host = v6("fe80::10");
    let changes = [
        route(
            "default",
            v6("fc00:1::46").into(),
            128,
            RouteAction::Srv6Local(Srv6Local::EndDt46 { vrf: "red".into() }),
        ),
        route(
            "default",
            v6("fc00:1::d4").into(),
            128,
            RouteAction::Srv6Local(Srv6Local::EndDx4 {
                interface: "lan".into(),
                next_hop: Ipv4Addr::from(HOST),
            }),
        ),
        route(
            "default",
            v6("fc00:1::d6").into(),
            128,
            RouteAction::Srv6Local(Srv6Local::EndDx6 {
                interface: "lan".into(),
                next_hop: lan_host,
            }),
        ),
        route(
            "red",
            Ipv6Addr::UNSPECIFIED.into(),
            0,
            RouteAction::Forward(vec![NextHop {
                interface: "lan".into(),
                address: Some(lan_host.into()),
            }]),
        ),
    ];
    let neighbor = [Change::set(
        Key::Neighbor {
            interface: "lan".into(),
            address: lan_host.into(),
        },
        Value::Neighbor { mac: HOST_MAC },
    )];
    for (writer, changes) in [
        (writers::ROUTE, &changes[..]),
        (writers::NEIGHBOR, &neighbor[..]),
    ] {
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, writer).unwrap();
        let mut client = Client::new(b).unwrap();
        let token = client.patch(changes).unwrap();
        assert_eq!(settle(&mut fe, &mut client, token), Code::CHANGED);
    }
    fe
}

#[test]
fn an_end_dt46_sid_unwraps_ipv4_and_ipv6_into_its_vrf() {
    let mut fe = bench_with_cross_connects();
    let out = send(
        &mut fe,
        WAN,
        to_sid("fc00:1::46", 0, 4, &ipv4(REMOTE, HOST)),
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, LAN);
    assert_eq!(&out[0].1[12..14], &[0x08, 0x00]);
    assert_eq!(&out[0].1[14 + 16..14 + 20], &HOST);

    let inner = ipv6("2001:db8:ff::9", "2001:db8:99::1");
    let out = send(&mut fe, WAN, to_sid("fc00:1::46", 0, 41, &inner));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, LAN);
    assert_eq!(&out[0].1[0..6], &HOST_MAC);
    assert_eq!(&out[0].1[12..14], &[0x86, 0xdd]);
    assert_eq!(out[0].1[14 + 7], 63, "the inner Hop Limit, decremented");
    assert_eq!(&out[0].1[14 + 24..14 + 40], &v6("2001:db8:99::1").octets());
}

#[test]
fn an_end_dx4_sid_sends_the_inner_ipv4_to_its_next_hop_without_a_lookup() {
    let mut fe = bench_with_cross_connects();
    // Red has no route to 10.9.9.9: the SID's next hop is used, not a route.
    let out = send(
        &mut fe,
        WAN,
        to_sid("fc00:1::d4", 0, 4, &ipv4(REMOTE, [10, 9, 9, 9])),
    );
    assert_eq!(out.len(), 1);
    let (port, sent) = &out[0];
    assert_eq!(*port, LAN);
    assert_eq!(&sent[0..6], &HOST_MAC);
    assert_eq!(&sent[12..14], &[0x08, 0x00]);
    assert_eq!(sent[14 + 8], 63, "the inner TTL, decremented");
    assert_eq!(&sent[14 + 16..14 + 20], &[10, 9, 9, 9]);

    // An IPv6 packet inside is not End.DX4's: Parameter Problem back to the source.
    let inner = ipv6("2001:db8:ff::9", "2001:db8:99::1");
    let out = send(&mut fe, WAN, to_sid("fc00:1::d4", 0, 41, &inner));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, WAN);
    // Code 4, SR Upper-layer Header Error.
    assert_eq!(&out[0].1[14 + 40..14 + 42], &[4, 4]);
}

#[test]
fn an_end_dx6_sid_sends_the_inner_ipv6_to_its_next_hop() {
    let mut fe = bench_with_cross_connects();
    let inner = ipv6("2001:db8:ff::9", "2001:db8:77::1");
    let out = send(&mut fe, WAN, to_sid("fc00:1::d6", 0, 41, &inner));
    assert_eq!(out.len(), 1);
    let (port, sent) = &out[0];
    assert_eq!(*port, LAN);
    assert_eq!(&sent[0..6], &HOST_MAC);
    assert_eq!(&sent[14 + 24..14 + 40], &v6("2001:db8:77::1").octets());
}

#[test]
fn a_cross_connect_sid_with_segments_left_gets_a_parameter_problem() {
    let mut fe = bench_with_cross_connects();
    for sid in ["fc00:1::d4", "fc00:1::d6", "fc00:1::46"] {
        let out = send(&mut fe, WAN, to_sid(sid, 1, 4, &ipv4(REMOTE, HOST)));
        assert_eq!(out.len(), 1, "{sid}");
        let (port, error) = &out[0];
        assert_eq!(*port, WAN, "{sid}");
        // ICMPv6 Parameter Problem, code 0, pointing at Segments Left.
        assert_eq!(error[14 + 6], 58, "{sid}");
        assert_eq!(&error[14 + 40..14 + 42], &[4, 0], "{sid}");
        assert_eq!(
            &error[14 + 44..14 + 48],
            &(40_u32 + 3).to_be_bytes(),
            "{sid}"
        );
    }
}

#[test]
fn an_unwrapped_packet_to_the_router_or_neighbor_discovery_is_dropped() {
    let mut fe = bench_with_cross_connects();
    // To the router's address on the SID's interface.
    for sid in ["fc00:1::d4", "fc00:1::46", "fc00:1::4"] {
        let out = send(
            &mut fe,
            WAN,
            to_sid(sid, 0, 4, &ipv4(REMOTE, [192, 168, 0, 1])),
        );
        assert!(out.is_empty(), "{sid}: {out:?}");
    }
    // A Neighbor Advertisement inside, with Hop Limit 255.
    let mut na = ipv6("fe80::99", "ff02::1");
    na[6] = 58;
    na[7] = 255;
    na.truncate(40);
    na.extend_from_slice(&[136, 0, 0, 0, 0x20, 0, 0, 0]);
    na.extend_from_slice(&v6("fe80::fe").octets());
    na[4..6].copy_from_slice(&24_u16.to_be_bytes());
    for sid in ["fc00:1::d6", "fc00:1::46"] {
        let dropped = fe.counters().dropped;
        let out = send(&mut fe, WAN, to_sid(sid, 0, 41, &na));
        assert!(out.is_empty(), "{sid}: {out:?}");
        // Dropped, not handed to the neighbor process.
        assert_eq!(fe.counters().dropped, dropped + 1, "{sid}");
    }
}

/// The bench with End with PSP & USD at fc00:1::50 and End.X with USD at
/// fc00:1::51 (to the WAN gateway).
fn bench_with_flavors() -> Fe<SimIo> {
    use ruster_proto::table::Srv6Flavors;
    let mut fe = bench();
    let both = Srv6Flavors {
        psp: true,
        usd: true,
        ..Srv6Flavors::default()
    };
    let usd = Srv6Flavors {
        usd: true,
        ..Srv6Flavors::default()
    };
    let changes = [
        route(
            "default",
            v6("fc00:1::50").into(),
            128,
            RouteAction::Srv6Local(Srv6Local::End { flavors: both }),
        ),
        route(
            "default",
            v6("fc00:1::51").into(),
            128,
            RouteAction::Srv6Local(Srv6Local::EndX {
                interface: "wan".into(),
                next_hop: v6("fe80::fe"),
                flavors: usd,
            }),
        ),
    ];
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, writers::ROUTE).unwrap();
    let mut client = Client::new(b).unwrap();
    let token = client.patch(&changes).unwrap();
    assert_eq!(settle(&mut fe, &mut client, token), Code::CHANGED);
    fe
}

#[test]
fn psp_takes_the_srh_off_when_its_last_segment_becomes_the_destination() {
    let mut fe = bench_with_flavors();
    // To fc00:1::50 with one segment left: then to fc00:9::1, the last.
    let inner = ipv6("2001:db8:ff::9", "2001:db8:99::1");
    let mut frame = WAN_MAC.to_vec();
    frame.extend_from_slice(&GATEWAY_MAC);
    frame.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    frame.extend_from_slice(&u16::try_from(40 + inner.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&[43, 64]);
    frame.extend_from_slice(&v6("2001:db8:ff::9").octets());
    frame.extend_from_slice(&v6("fc00:1::50").octets());
    frame.extend_from_slice(&[41, 4, 4, 1, 1, 0, 0, 0]);
    frame.extend_from_slice(&v6("fc00:9::1").octets());
    frame.extend_from_slice(&v6("fc00:1::50").octets());
    frame.extend_from_slice(&inner);
    let out = send(&mut fe, WAN, frame);
    assert_eq!(out.len(), 1);
    let (port, sent) = &out[0];
    assert_eq!(*port, WAN);
    assert_eq!(&sent[14 + 24..14 + 40], &v6("fc00:9::1").octets());
    assert_eq!(
        sent[14 + 6],
        41,
        "the SRH is gone: the inner packet follows"
    );
    assert_eq!(
        u16::from_be_bytes([sent[14 + 4], sent[14 + 5]]),
        u16::try_from(inner.len()).unwrap()
    );
    assert_eq!(&sent[14 + 40..], &inner[..]);
}

#[test]
fn usd_unwraps_the_inner_packet_with_no_segment_left() {
    let mut fe = bench_with_flavors();
    let inner = ipv6("2001:db8:ff::9", "2001:db8:99::1");
    // End with USD: the inner packet is routed in the default VRF (out to WAN).
    let out = send(&mut fe, WAN, to_sid("fc00:1::50", 0, 41, &inner));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, WAN);
    assert_eq!(&out[0].1[14 + 24..14 + 40], &v6("2001:db8:99::1").octets());
    assert_eq!(out[0].1[14 + 7], 63);
    // End.X with USD: to its next hop.
    let out = send(&mut fe, WAN, to_sid("fc00:1::51", 0, 41, &inner));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, WAN);
    assert_eq!(&out[0].1[0..6], &GATEWAY_MAC);
    assert_eq!(&out[0].1[14 + 24..14 + 40], &v6("2001:db8:99::1").octets());
}

#[test]
fn an_end_with_next_csid_shifts_the_next_csid_in() {
    use ruster_proto::table::{Srv6Csid, Srv6Flavors};
    let mut fe = bench();
    // The router's uSID fc00:0:1::/48 (32-bit block fc00:0, 16-bit CSIDs).
    let csid = Srv6Flavors {
        next_csid: Some(Srv6Csid {
            block: 32,
            csid: 16,
        }),
        ..Srv6Flavors::default()
    };
    let changes = [route(
        "default",
        v6("fc00:0:1::").into(),
        48,
        RouteAction::Srv6Local(Srv6Local::End { flavors: csid }),
    )];
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, writers::ROUTE).unwrap();
    let mut client = Client::new(b).unwrap();
    let token = client.patch(&changes).unwrap();
    assert_eq!(settle(&mut fe, &mut client, token), Code::CHANGED);

    // To fc00:0:1:2:3:: with no SRH: on to fc00:0:2:3:: (routed out of wan).
    let inner = ipv6("2001:db8:ff::9", "2001:db8:99::1");
    let mut frame = WAN_MAC.to_vec();
    frame.extend_from_slice(&GATEWAY_MAC);
    frame.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    frame.extend_from_slice(&u16::try_from(inner.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&[41, 64]);
    frame.extend_from_slice(&v6("2001:db8:ff::9").octets());
    frame.extend_from_slice(&v6("fc00:0:1:2:3::").octets());
    frame.extend_from_slice(&inner);
    let out = send(&mut fe, WAN, frame);
    assert_eq!(out.len(), 1);
    let (port, sent) = &out[0];
    assert_eq!(*port, WAN);
    assert_eq!(&sent[14 + 24..14 + 40], &v6("fc00:0:2:3::").octets());
    assert_eq!(sent[14 + 7], 63);

    // The last CSID (no argument) and no SRH: the upper layer is not taken.
    let mut last = WAN_MAC.to_vec();
    last.extend_from_slice(&GATEWAY_MAC);
    last.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    last.extend_from_slice(&u16::try_from(inner.len()).unwrap().to_be_bytes());
    last.extend_from_slice(&[41, 64]);
    last.extend_from_slice(&v6("2001:db8:ff::9").octets());
    last.extend_from_slice(&v6("fc00:0:1::").octets());
    last.extend_from_slice(&inner);
    let out = send(&mut fe, WAN, last);
    assert_eq!(out.len(), 1);
    // ICMPv6 Parameter Problem, code 4.
    assert_eq!(&out[0].1[14 + 40..14 + 42], &[4, 4]);
}

#[test]
fn no_error_goes_to_a_source_that_claims_to_be_the_router() {
    let mut fe = bench_with_cross_connects();
    // To End.DT4 with a segment left, from the router's own wan address.
    let mut frame = to_sid("fc00:1::4", 1, 4, &ipv4(REMOTE, HOST));
    frame[14 + 8..14 + 24].copy_from_slice(&v6("2001:db8::1").octets());
    assert_eq!(send(&mut fe, WAN, frame), vec![]);
}

#[test]
fn a_hop_by_hop_header_after_another_header_is_dropped() {
    let mut fe = bench();
    // IPv6, Destination Options, then Hop-by-Hop (not first), to End.DT4.
    let inner = ipv4(REMOTE, HOST);
    let mut frame = WAN_MAC.to_vec();
    frame.extend_from_slice(&GATEWAY_MAC);
    frame.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    frame.extend_from_slice(&u16::try_from(16 + inner.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&[60, 64]);
    frame.extend_from_slice(&v6("2001:db8:ff::9").octets());
    frame.extend_from_slice(&v6("fc00:1::4").octets());
    frame.extend_from_slice(&[0, 0, 1, 4, 0, 0, 0, 0]);
    frame.extend_from_slice(&[4, 0, 1, 4, 0, 0, 0, 0]);
    frame.extend_from_slice(&inner);
    assert_eq!(send(&mut fe, WAN, frame), vec![]);
}

#[test]
fn a_cross_connect_sid_whose_interface_is_missing_drops_its_packets() {
    let mut fe = bench();
    let changes = [route(
        "default",
        v6("fc00:1::d4").into(),
        128,
        RouteAction::Srv6Local(Srv6Local::EndDx4 {
            interface: "gone".into(),
            next_hop: Ipv4Addr::from(HOST),
        }),
    )];
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, writers::ROUTE).unwrap();
    let mut client = Client::new(b).unwrap();
    let token = client.patch(&changes).unwrap();
    assert_eq!(settle(&mut fe, &mut client, token), Code::CHANGED);
    // Not routed as to no SID (the default route would take it out of wan).
    let out = send(
        &mut fe,
        WAN,
        to_sid("fc00:1::d4", 0, 4, &ipv4(REMOTE, HOST)),
    );
    assert_eq!(out, vec![]);
}

#[test]
fn each_sid_counts_its_packets_and_bytes_in_the_state_tables() {
    let mut fe = bench();
    // Two packets to End.DT4 fc00:1::4.
    for _ in 0..2 {
        let out = send(&mut fe, WAN, to_sid("fc00:1::4", 0, 4, &ipv4(REMOTE, HOST)));
        assert_eq!(out.len(), 1);
    }
    // A second later the worker hands the counts over.
    fe.step(1_000);
    fe.step(1_001);
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, writers::READ_ONLY).unwrap();
    let mut reader = Client::new(b).unwrap();
    let token = reader.get_all();
    let mut payload = None;
    for _ in 0..1_000 {
        fe.step(1_002);
        let (_, events) = reader.poll();
        for event in events {
            if let Event::Response {
                token: t,
                payload: p,
                ..
            } = event
            {
                if t == token {
                    payload = Some(p);
                }
            }
        }
        if payload.is_some() {
            break;
        }
    }
    let changes = ruster_proto::session::decode_changes(&payload.expect("answer")).unwrap();
    let counters = changes
        .iter()
        .find(|c| {
            c.key
                == Key::Srv6SidCounters {
                    prefix: v6("fc00:1::4"),
                    len: 128,
                }
        })
        .and_then(|c| c.value.clone());
    // Each packet is 40 + 40 (an SRH of two segments) + 28 bytes from its IPv6
    // header.
    assert_eq!(
        counters,
        Some(Value::Srv6SidCounters {
            packets: 2,
            bytes: 2 * (40 + 40 + 28),
        })
    );
}
