//! EtherIP in the FE: port p1 and EtherIP interface eip0 in bridge br0; eip0's outer
//! packets go out of wan toward the remote end through a gateway.

use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::net::UnixStream;

use ruster_core::{ipv4_header_checksum, IfId};
use ruster_fe::{writers, Fe};
use ruster_io_sim::SimIo;
use ruster_proto::coap::Code;
use ruster_proto::session::{Client, Event};
use ruster_proto::table::{Change, Key, NextHop, RouteAction, Value};
use ruster_proto::task::Task;

const P1: IfId = IfId(0);
const WAN: IfId = IfId(1);
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const GATEWAY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
const H1: [u8; 6] = [2, 0, 0, 0, 0, 0x11];
const H2: [u8; 6] = [2, 0, 0, 0, 0, 0x12];
const LOCAL: [u8; 4] = [198, 51, 100, 2];
const REMOTE: [u8; 4] = [203, 0, 113, 2];

struct Bench {
    fe: Fe<SimIo>,
}

impl Bench {
    fn new() -> Self {
        let mut fe = Fe::new(SimIo::new(), vec!["p1".into(), "wan".into()]);
        let config = [
            iface("p1", [2, 0, 0, 0, 1, 1]),
            iface("wan", WAN_MAC),
            iface("eip0", [2, 0, 0, 0, 0, 0xe]),
            Change::set(
                Key::Address {
                    interface: "wan".into(),
                    address: Ipv4Addr::from(LOCAL).into(),
                },
                Value::Address { prefix_len: 24 },
            ),
            Change::set(
                Key::EtherIp {
                    interface: "eip0".into(),
                },
                Value::EtherIp {
                    local: IpAddr::from(LOCAL),
                    remote: IpAddr::from(REMOTE),
                },
            ),
            Change::set(
                Key::Bridge { name: "br0".into() },
                Value::Bridge {
                    aging_s: 300,
                    max_learned: 16,
                },
            ),
            member("p1"),
            member("eip0"),
        ];
        let route = Change::set(
            Key::Route {
                vrf: "default".into(),
                prefix: Ipv4Addr::UNSPECIFIED.into(),
                len: 0,
            },
            Value::Route(RouteAction::Forward(vec![NextHop {
                interface: "wan".into(),
                address: Some(Ipv4Addr::new(198, 51, 100, 1).into()),
            }])),
        );
        let neighbor = Change::set(
            Key::Neighbor {
                interface: "wan".into(),
                address: Ipv4Addr::new(198, 51, 100, 1).into(),
            },
            Value::Neighbor { mac: GATEWAY_MAC },
        );
        for (writer, changes) in [
            (writers::CONFIG, &config[..]),
            (writers::ROUTE, &[route][..]),
            (writers::NEIGHBOR, &[neighbor][..]),
        ] {
            let (a, b) = UnixStream::pair().unwrap();
            fe.attach(a, writer).unwrap();
            let mut client = Client::new(b).unwrap();
            let token = client.patch(changes).unwrap();
            assert_eq!(settle(&mut fe, &mut client, token), Code::CHANGED);
        }
        Self { fe }
    }

    /// Sends `frame` in on `port` and returns what left, by port.
    fn send(&mut self, port: IfId, frame: Vec<u8>) -> Vec<(IfId, Vec<u8>)> {
        self.fe.io_mut().inject(port, frame);
        self.fe.step(0);
        let mut out = Vec::new();
        while let Some(tx) = self.fe.io_mut().pop_tx() {
            out.push((tx.egress, tx.bytes));
        }
        out
    }
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

fn iface(name: &str, mac: [u8; 6]) -> Change {
    Change::set(
        Key::Interface { name: name.into() },
        Value::Interface {
            enabled: true,
            mac,
            mtu: 1500,
            vrf: ruster_proto::table::DEFAULT_VRF.into(),
            vlan: None,
            tunnel: None,
            pppoe: None,
        },
    )
}

fn member(name: &str) -> Change {
    Change::set(
        Key::BridgePort {
            interface: name.into(),
        },
        Value::BridgePort {
            bridge: "br0".into(),
        },
    )
}

/// An Ethernet frame of `len` bytes from `src` to `dst`.
fn frame(dst: [u8; 6], src: [u8; 6], len: usize) -> Vec<u8> {
    let mut f = vec![0x5a; len];
    f[0..6].copy_from_slice(&dst);
    f[6..12].copy_from_slice(&src);
    f[12..14].copy_from_slice(&[0x08, 0x00]);
    f
}

/// `inner` as the remote end sends it: in IPv4 from `from` to the router.
fn outer(from: [u8; 4], inner: &[u8]) -> Vec<u8> {
    let mut p = WAN_MAC.to_vec();
    p.extend_from_slice(&GATEWAY_MAC);
    p.extend_from_slice(&[0x08, 0x00]);
    let total = u16::try_from(20 + 2 + inner.len()).unwrap();
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0x40, 0, 64, 97, 0, 0]);
    ip.extend_from_slice(&from);
    ip.extend_from_slice(&LOCAL);
    let checksum = ipv4_header_checksum(&ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    p.extend_from_slice(&ip);
    p.extend_from_slice(&[0x30, 0]);
    p.extend_from_slice(inner);
    p
}

/// Checks that `wrapped` is `inner` in EtherIP to the remote end, through the
/// gateway.
fn assert_wrapped(wrapped: &[u8], inner: &[u8]) {
    assert_eq!(&wrapped[0..6], &GATEWAY_MAC);
    assert_eq!(&wrapped[6..12], &WAN_MAC);
    assert_eq!(&wrapped[12..14], &[0x08, 0x00]);
    assert_eq!(ipv4_header_checksum(&wrapped[14..34]), 0);
    assert_eq!(wrapped[23], 97);
    assert_eq!(&wrapped[26..30], &LOCAL);
    assert_eq!(&wrapped[30..34], &REMOTE);
    assert_eq!(&wrapped[34..36], &[0x30, 0]);
    assert_eq!(&wrapped[36..], inner);
}

#[test]
fn frames_cross_the_tunnel_both_ways() {
    let mut bench = Bench::new();
    // H2 is not known: flooded, wrapped toward the remote end.
    let a = frame(H2, H1, 60);
    let out = bench.send(P1, a.clone());
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, WAN);
    assert_wrapped(&out[0].1, &a);
    // The reply comes back wrapped and goes to p1, where H1 was learned.
    let b = frame(H1, H2, 60);
    assert_eq!(bench.send(WAN, outer(REMOTE, &b)), vec![(P1, b)]);
    // H2 was learned on eip0: the next frame to it is wrapped in place.
    let c = frame(H2, H1, 100);
    let out = bench.send(P1, c.clone());
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, WAN);
    assert_wrapped(&out[0].1, &c);
}

#[test]
fn others_and_frames_too_long_are_dropped_and_counted() {
    let mut bench = Bench::new();
    // From an address that is not the remote end: not let into the bridge.
    let b = frame(H1, H2, 60);
    assert_eq!(bench.send(WAN, outer([203, 0, 113, 9], &b)), vec![]);
    // A frame that does not fit the link once wrapped: 1500 - 22 = 1478 fits.
    let fits = frame(H2, H1, 1478);
    assert_eq!(bench.send(P1, fits).len(), 1);
    let long = frame(H2, H1, 1479);
    assert_eq!(bench.send(P1, long.clone()), vec![]);
    assert_eq!(bench.fe.counters().overlay_too_big, 1);
    // Also once H2 is known (wrapped in place).
    assert_eq!(bench.send(WAN, outer(REMOTE, &b)).len(), 1);
    assert_eq!(bench.send(P1, long), vec![]);
    assert_eq!(bench.fe.counters().overlay_too_big, 2);
}
