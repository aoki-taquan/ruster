//! SRv6 L2 in the FE: port p1 and SRv6 L2 interface sr0 in bridge br0; sr0's frames
//! leave wrapped (H.Encaps.L2) out of wan toward the remote SIDs through a gateway,
//! and packets to its End.DX2 SID bring frames in.

use std::net::Ipv6Addr;
use std::os::unix::net::UnixStream;

use ruster_core::IfId;
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
const LOCAL: &str = "2001:db8::2";
const DX2: &str = "fc00:1::d2";

fn v6(text: &str) -> Ipv6Addr {
    text.parse().unwrap()
}

struct Bench {
    fe: Fe<SimIo>,
}

impl Bench {
    fn new(segments: &[&str], reduced: bool) -> Self {
        let mut fe = Fe::new(SimIo::new(), vec!["p1".into(), "wan".into()]);
        let config = [
            iface("p1", [2, 0, 0, 0, 1, 1]),
            iface("wan", WAN_MAC),
            iface("sr0", [2, 0, 0, 0, 0, 0xe]),
            Change::set(
                Key::Address {
                    interface: "wan".into(),
                    address: v6(LOCAL).into(),
                },
                Value::Address { prefix_len: 64 },
            ),
            Change::set(
                Key::Srv6L2 {
                    interface: "sr0".into(),
                },
                Value::Srv6L2 {
                    source: v6(LOCAL),
                    sid: v6(DX2),
                    segments: segments.iter().map(|s| v6(s)).collect(),
                    reduced,
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
            member("sr0"),
        ];
        let route = Change::set(
            Key::Route {
                vrf: "default".into(),
                prefix: Ipv6Addr::UNSPECIFIED.into(),
                len: 0,
            },
            Value::Route(RouteAction::Forward(vec![NextHop {
                interface: "wan".into(),
                address: Some(v6("fe80::1").into()),
            }])),
        );
        let neighbor = Change::set(
            Key::Neighbor {
                interface: "wan".into(),
                address: v6("fe80::1").into(),
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

/// `inner` as the remote end sends it: to the router's End.DX2 SID, with a Segment
/// Routing Header with `left` segments left.
fn outer(left: u8, inner: &[u8]) -> Vec<u8> {
    let mut p = WAN_MAC.to_vec();
    p.extend_from_slice(&GATEWAY_MAC);
    p.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    p.extend_from_slice(&u16::try_from(24 + inner.len()).unwrap().to_be_bytes());
    p.extend_from_slice(&[43, 64]);
    p.extend_from_slice(&v6("2001:db8::9").octets());
    p.extend_from_slice(&v6(DX2).octets());
    p.extend_from_slice(&[143, 2, 4, left, 0, 0, 0, 0]);
    p.extend_from_slice(&v6(DX2).octets());
    p.extend_from_slice(inner);
    p
}

#[test]
fn frames_cross_srv6_both_ways() {
    let mut bench = Bench::new(&["fc00:2::d2"], false);
    // H2 is not known: flooded, wrapped toward the remote SID with no SRH.
    let a = frame(H2, H1, 60);
    let out = bench.send(P1, a.clone());
    assert_eq!(out.len(), 1);
    let (port, wrapped) = &out[0];
    assert_eq!(*port, WAN);
    assert_eq!(&wrapped[0..6], &GATEWAY_MAC);
    assert_eq!(&wrapped[12..14], &[0x86, 0xdd]);
    assert_eq!(
        wrapped[14 + 6],
        143,
        "the frame right after the IPv6 header"
    );
    assert_eq!(&wrapped[14 + 8..14 + 24], &v6(LOCAL).octets());
    assert_eq!(&wrapped[14 + 24..14 + 40], &v6("fc00:2::d2").octets());
    assert_eq!(&wrapped[14 + 40..], &a[..]);
    // The reply to the End.DX2 SID goes to p1, where H1 was learned.
    let b = frame(H1, H2, 60);
    assert_eq!(bench.send(WAN, outer(0, &b)), vec![(P1, b.clone())]);
    // With segments left it is not End.DX2's.
    assert_eq!(bench.send(WAN, outer(1, &b)), vec![]);
}

#[test]
fn two_segments_get_a_segment_routing_header_and_reduced_leaves_the_first_out() {
    for (reduced, listed) in [(false, 2_usize), (true, 1)] {
        let mut bench = Bench::new(&["fc00:3::1", "fc00:2::d2"], reduced);
        let a = frame(H2, H1, 60);
        let out = bench.send(P1, a.clone());
        assert_eq!(out.len(), 1);
        let w = &out[0].1;
        assert_eq!(w[14 + 6], 43);
        assert_eq!(&w[14 + 24..14 + 40], &v6("fc00:3::1").octets());
        let srh = 14 + 40;
        assert_eq!(w[srh], 143);
        assert_eq!(usize::from(w[srh + 1]), 2 * listed);
        assert_eq!(
            (w[srh + 2], w[srh + 3], w[srh + 4]),
            (4, 1, (listed - 1) as u8)
        );
        // Segment List[0] is the last segment.
        assert_eq!(&w[srh + 8..srh + 24], &v6("fc00:2::d2").octets());
        if !reduced {
            assert_eq!(&w[srh + 24..srh + 40], &v6("fc00:3::1").octets());
        }
        let payload = u16::from_be_bytes([w[14 + 4], w[14 + 5]]);
        assert_eq!(usize::from(payload), 8 + 16 * listed + a.len());
        assert_eq!(&w[srh + 8 + 16 * listed..], &a[..]);
    }
}
