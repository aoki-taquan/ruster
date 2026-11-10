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
