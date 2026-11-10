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
    frame.extend_from_slice(&u16::try_from(inner.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&[4, 64]);
    frame.extend_from_slice(&v6("2001:db8:ff::9").octets());
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
