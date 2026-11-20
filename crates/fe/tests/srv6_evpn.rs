//! EVPN over SRv6 in the FE: port p1 and SRv6 EVPN interface se0 (VNI 100) in bridge
//! br0. Its remote ends come from the EVPN tables (the route writer): flooded frames
//! go to each remote End.DT2M SID, frames to a known host to its End.DT2U SID, and
//! packets to the router's End.DT2U and End.DT2M SIDs bring frames in (RFC 8986
//! sections 4.11 and 4.12).

use std::net::{IpAddr, Ipv6Addr};
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
const H3: [u8; 6] = [2, 0, 0, 0, 0, 0x13];
const LOCAL: &str = "2001:db8::2";
const DT2U: &str = "fc00:1::e";
const DT2M: &str = "fc00:1::f";

fn v6(text: &str) -> Ipv6Addr {
    text.parse().unwrap()
}

struct Bench {
    fe: Fe<SimIo>,
    routes: Client,
}

impl Bench {
    fn new() -> Self {
        let mut fe = Fe::new(SimIo::new(), vec!["p1".into(), "wan".into()]);
        let config = [
            iface("p1", [2, 0, 0, 0, 1, 1]),
            iface("wan", WAN_MAC),
            iface("se0", [2, 0, 0, 0, 0, 0xe]),
            Change::set(
                Key::Address {
                    interface: "wan".into(),
                    address: v6(LOCAL).into(),
                },
                Value::Address { prefix_len: 64 },
            ),
            Change::set(
                Key::Srv6Evpn {
                    interface: "se0".into(),
                },
                Value::Srv6Evpn {
                    source: v6(LOCAL),
                    vni: 100,
                    unicast: v6(DT2U),
                    multicast: v6(DT2M),
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
            member("se0"),
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
        let mut clients = Vec::new();
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
            clients.push(client);
        }
        clients.truncate(2);
        let routes = clients.pop().unwrap();
        Self { fe, routes }
    }

    fn evpn(&mut self, changes: &[Change]) {
        let token = self.routes.patch(changes).unwrap();
        assert_eq!(settle(&mut self.fe, &mut self.routes, token), Code::CHANGED);
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

/// `inner` as a remote end sends it to the router's SID `to`, with no Segment
/// Routing Header.
fn outer(to: &str, inner: &[u8]) -> Vec<u8> {
    let mut p = WAN_MAC.to_vec();
    p.extend_from_slice(&GATEWAY_MAC);
    p.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    p.extend_from_slice(&u16::try_from(inner.len()).unwrap().to_be_bytes());
    p.extend_from_slice(&[143, 64]);
    p.extend_from_slice(&v6("2001:db8::9").octets());
    p.extend_from_slice(&v6(to).octets());
    p.extend_from_slice(inner);
    p
}

/// The SID a wrapped frame goes to, checking the rest of its outer headers.
fn sid_of(wrapped: &[u8], inner: &[u8]) -> Ipv6Addr {
    assert_eq!(&wrapped[0..6], &GATEWAY_MAC);
    assert_eq!(&wrapped[12..14], &[0x86, 0xdd]);
    assert_eq!(
        wrapped[14 + 6],
        143,
        "the frame right after the IPv6 header"
    );
    assert_eq!(&wrapped[14 + 8..14 + 24], &v6(LOCAL).octets());
    assert_eq!(&wrapped[14 + 40..], inner);
    Ipv6Addr::from(<[u8; 16]>::try_from(&wrapped[14 + 24..14 + 40]).unwrap())
}

fn sids(out: &[(IfId, Vec<u8>)], inner: &[u8]) -> Vec<Ipv6Addr> {
    let mut sids: Vec<Ipv6Addr> = out
        .iter()
        .map(|(port, w)| {
            assert_eq!(*port, WAN);
            sid_of(w, inner)
        })
        .collect();
    sids.sort_unstable();
    sids
}

#[test]
fn frames_go_to_the_remote_sids_of_the_evpn_tables_and_come_in_on_the_router_s() {
    let mut bench = Bench::new();
    // No remote end yet: a broadcast goes nowhere.
    let broadcast = frame([0xff; 6], H1, 60);
    assert_eq!(bench.send(P1, broadcast.clone()), vec![]);
    let flood = |sid: &str| {
        Change::set(
            Key::EvpnFlood {
                vni: 100,
                vtep: IpAddr::V6(v6(sid)),
            },
            Value::EvpnFlood,
        )
    };
    bench.evpn(&[
        flood("fc00:2::f"),
        flood("fc00:3::f"),
        Change::set(
            Key::EvpnMac { vni: 100, mac: H2 },
            Value::EvpnMac {
                vtep: IpAddr::V6(v6("fc00:2::e")),
            },
        ),
    ]);
    // Flooded to each remote End.DT2M SID.
    let out = bench.send(P1, broadcast.clone());
    assert_eq!(
        sids(&out, &broadcast),
        vec![v6("fc00:2::f"), v6("fc00:3::f")]
    );
    // To H2: its End.DT2U SID only.
    let to_h2 = frame(H2, H1, 100);
    assert_eq!(
        sids(&bench.send(P1, to_h2.clone()), &to_h2),
        vec![v6("fc00:2::e")]
    );
    // To the router's End.DT2U SID: to p1, where H1 was learned.
    let to_h1 = frame(H1, H3, 60);
    assert_eq!(
        bench.send(WAN, outer(DT2U, &to_h1)),
        vec![(P1, to_h1.clone())]
    );
    // To its End.DT2M SID: flooded to p1, not back to the remote ends.
    let flooded = frame([0xff; 6], H3, 60);
    assert_eq!(bench.send(WAN, outer(DT2M, &flooded)), vec![(P1, flooded)]);
    // H3 was not learned from those (the EVPN tables say where hosts are): frames
    // to it are flooded.
    let to_h3 = frame(H3, H1, 60);
    assert_eq!(
        sids(&bench.send(P1, to_h3.clone()), &to_h3),
        vec![v6("fc00:2::f"), v6("fc00:3::f")]
    );

    // H2 moves to p1, then back behind its router (the EVPN tables unchanged):
    // frames to it follow, back to its End.DT2U SID.
    bench.send(P1, frame(H1, H2, 60));
    let to_h2 = frame(H2, H1, 100);
    assert_eq!(
        bench.send(WAN, outer(DT2M, &to_h2)),
        vec![(P1, to_h2.clone())]
    );
    bench.send(WAN, outer(DT2U, &frame(H1, H2, 60)));
    assert_eq!(
        sids(&bench.send(P1, to_h2.clone()), &to_h2),
        vec![v6("fc00:2::e")]
    );
}

#[test]
fn the_router_s_own_sids_and_static_macs_are_not_remote_ends() {
    let mut bench = Bench::new();
    bench.evpn(&[
        Change::set(
            Key::EvpnFlood {
                vni: 100,
                vtep: IpAddr::V6(v6(DT2M)),
            },
            Value::EvpnFlood,
        ),
        Change::set(
            Key::EvpnFlood {
                vni: 100,
                vtep: IpAddr::V6(v6("fc00:2::f")),
            },
            Value::EvpnFlood,
        ),
    ]);
    let broadcast = frame([0xff; 6], H1, 60);
    assert_eq!(
        sids(&bench.send(P1, broadcast.clone()), &broadcast),
        vec![v6("fc00:2::f")]
    );
}
