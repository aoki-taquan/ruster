//! VXLAN in the FE: port p1 and VXLAN interface vx0 (VNI 100, two remote VTEPs) in
//! bridge br0; vx0's outer packets go out of wan through a gateway.

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
const VTEP2: [u8; 4] = [203, 0, 113, 2];
const VTEP3: [u8; 4] = [203, 0, 113, 3];

struct Bench {
    fe: Fe<SimIo>,
    /// The client that wrote the configuration, for changes after.
    config: Client,
}

impl Bench {
    fn new() -> Self {
        Self::with(&[])
    }

    /// The bench, with `more` in the configuration.
    fn with(more: &[Change]) -> Self {
        let mut fe = Fe::new(SimIo::new(), vec!["p1".into(), "wan".into()]);
        let config = [
            iface("p1", [2, 0, 0, 0, 1, 1]),
            iface("wan", WAN_MAC),
            iface("vx0", [2, 0, 0, 0, 0, 0xe]),
            Change::set(
                Key::Address {
                    interface: "wan".into(),
                    address: Ipv4Addr::from(LOCAL).into(),
                },
                Value::Address { prefix_len: 24 },
            ),
            Change::set(
                Key::Vxlan {
                    interface: "vx0".into(),
                },
                Value::Vxlan {
                    vni: 100,
                    local: IpAddr::from(LOCAL),
                    remotes: vec![IpAddr::from(VTEP2), IpAddr::from(VTEP3)],
                    port: 4789,
                    underlay_vrf: "default".into(),
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
            member("vx0"),
        ];
        let config: Vec<Change> = config.into_iter().chain(more.iter().cloned()).collect();
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
        let config = clients.swap_remove(0);
        Self { fe, config }
    }

    fn change(&mut self, changes: &[Change]) {
        assert_eq!(self.try_change(changes), Code::CHANGED);
    }

    fn try_change(&mut self, changes: &[Change]) -> Code {
        let token = self.config.patch(changes).unwrap();
        settle(&mut self.fe, &mut self.config, token)
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

/// `inner` as VTEP `from` sends it: in VXLAN VNI `vni` over IPv4 to the router.
fn outer(from: [u8; 4], vni: u32, inner: &[u8]) -> Vec<u8> {
    let mut p = WAN_MAC.to_vec();
    p.extend_from_slice(&GATEWAY_MAC);
    p.extend_from_slice(&[0x08, 0x00]);
    let total = u16::try_from(20 + 16 + inner.len()).unwrap();
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
    ip.extend_from_slice(&from);
    ip.extend_from_slice(&LOCAL);
    let checksum = ipv4_header_checksum(&ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    p.extend_from_slice(&ip);
    let length = u16::try_from(16 + inner.len()).unwrap();
    p.extend_from_slice(&[0xc0, 0x00, 0x12, 0xb5]);
    p.extend_from_slice(&length.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0x08, 0, 0, 0]);
    p.extend_from_slice(&vni.to_be_bytes()[1..]);
    p.push(0);
    p.extend_from_slice(inner);
    p
}

/// The VTEP `wrapped` goes to, after checking it is `inner` in VXLAN VNI 100.
fn vtep_of(wrapped: &[u8], inner: &[u8]) -> [u8; 4] {
    assert_eq!(&wrapped[0..6], &GATEWAY_MAC);
    assert_eq!(&wrapped[6..12], &WAN_MAC);
    assert_eq!(ipv4_header_checksum(&wrapped[14..34]), 0);
    assert_eq!(wrapped[23], 17);
    assert_eq!(&wrapped[26..30], &LOCAL);
    assert!(u16::from_be_bytes([wrapped[34], wrapped[35]]) >= 49152);
    assert_eq!(&wrapped[36..38], &4789_u16.to_be_bytes());
    assert_eq!(&wrapped[40..42], &[0, 0]);
    assert_eq!(&wrapped[42..50], &[0x08, 0, 0, 0, 0, 0, 100, 0]);
    assert_eq!(&wrapped[50..], inner);
    wrapped[30..34].try_into().unwrap()
}

#[test]
fn a_broadcast_goes_to_every_vtep_and_known_addresses_to_theirs() {
    let mut bench = Bench::new();
    let broadcast = frame([0xff; 6], H1, 60);
    let out = bench.send(P1, broadcast.clone());
    let mut vteps: Vec<[u8; 4]> = out
        .iter()
        .map(|(port, wrapped)| {
            assert_eq!(*port, WAN);
            vtep_of(wrapped, &broadcast)
        })
        .collect();
    vteps.sort_unstable();
    assert_eq!(vteps, vec![VTEP2, VTEP3]);
    // H2 answers from VTEP2: to p1, where H1 was learned.
    let b = frame(H1, H2, 60);
    assert_eq!(bench.send(WAN, outer(VTEP2, 100, &b)), vec![(P1, b)]);
    // H2 was learned behind VTEP2: the next frame to it goes there only.
    let c = frame(H2, H1, 100);
    let out = bench.send(P1, c.clone());
    assert_eq!(out.len(), 1);
    assert_eq!(vtep_of(&out[0].1, &c), VTEP2);
}

#[test]
fn a_flood_from_a_vtep_is_not_sent_to_the_other_vteps() {
    let mut bench = Bench::new();
    let unknown = frame([2, 0, 0, 0, 0, 0x99], H2, 60);
    assert_eq!(
        bench.send(WAN, outer(VTEP2, 100, &unknown)),
        vec![(P1, unknown.clone())]
    );
    // Not from a VTEP of the list, nor with another VNI.
    assert_eq!(
        bench.send(WAN, outer([203, 0, 113, 9], 100, &unknown)),
        vec![]
    );
    assert_eq!(bench.send(WAN, outer(VTEP2, 101, &unknown)), vec![]);
}

fn vxlan(name: &str, vni: u32, remotes: &[[u8; 4]]) -> Change {
    Change::set(
        Key::Vxlan {
            interface: name.into(),
        },
        Value::Vxlan {
            vni,
            local: IpAddr::from(LOCAL),
            remotes: remotes.iter().map(|r| IpAddr::from(*r)).collect(),
            port: 4789,
            underlay_vrf: "default".into(),
        },
    )
}

#[test]
fn a_flood_from_one_vxlan_interface_goes_to_another_of_the_bridge() {
    const VTEP4: [u8; 4] = [203, 0, 113, 4];
    let mut bench = Bench::with(&[
        iface("vx1", [2, 0, 0, 0, 0, 0xf]),
        vxlan("vx1", 200, &[VTEP4]),
        member("vx1"),
    ]);
    let unknown = frame([2, 0, 0, 0, 0, 0x99], H2, 60);
    let mut out = bench.send(WAN, outer(VTEP2, 100, &unknown));
    out.sort();
    // To p1 as it is, and to vx1's VTEP in VNI 200: not to vx0's other VTEP.
    assert_eq!(out.len(), 2, "{out:?}");
    assert!(out.contains(&(P1, unknown.clone())));
    let wrapped = out.iter().find(|(port, _)| *port == WAN).unwrap();
    assert_eq!(&wrapped.1[30..34], &VTEP4);
    assert_eq!(&wrapped.1[46..49], &200_u32.to_be_bytes()[1..]);
}

#[test]
fn an_address_behind_a_vtep_taken_off_the_list_is_forgotten() {
    let mut bench = Bench::new();
    let b = frame(H1, H2, 60);
    bench.send(P1, frame(H2, H1, 60));
    assert_eq!(bench.send(WAN, outer(VTEP2, 100, &b)), vec![(P1, b)]);
    // H2 is behind VTEP2; VTEP2 leaves the list: a frame to H2 is flooded to the
    // VTEPs left, not sent to VTEP2.
    bench.change(&[vxlan("vx0", 100, &[VTEP3])]);
    let c = frame(H2, H1, 100);
    let out = bench.send(P1, c.clone());
    assert_eq!(out.len(), 1);
    assert_eq!(vtep_of(&out[0].1, &c), VTEP3);
}

#[test]
fn two_vxlan_interfaces_of_a_bridge_may_not_share_a_vtep() {
    let mut bench = Bench::new();
    let code = bench.try_change(&[
        iface("vx1", [2, 0, 0, 0, 0, 0xf]),
        vxlan("vx1", 200, &[VTEP3]),
        member("vx1"),
    ]);
    assert_ne!(code, Code::CHANGED);
}

#[test]
fn an_address_learned_in_a_vni_is_forgotten_when_the_interface_changes_vni() {
    let mut bench = Bench::new();
    let b = frame(H1, H2, 60);
    bench.send(P1, frame(H2, H1, 60));
    assert_eq!(bench.send(WAN, outer(VTEP2, 100, &b)), vec![(P1, b)]);
    bench.change(&[vxlan("vx0", 300, &[VTEP2, VTEP3])]);
    // Flooded to both VTEPs again, in VNI 300.
    let c = frame(H2, H1, 100);
    let out = bench.send(P1, c);
    assert_eq!(out.len(), 2, "{out:?}");
    assert!(out
        .iter()
        .all(|(_, w)| w[46..49] == 300_u32.to_be_bytes()[1..]));
}

#[test]
fn another_udp_port_is_sent_to_and_received_on() {
    let mut bench = Bench::new();
    let Change { key, value, .. } = vxlan("vx0", 100, &[VTEP2]);
    let Some(Value::Vxlan {
        vni,
        local,
        remotes,
        ..
    }) = value
    else {
        unreachable!()
    };
    bench.change(&[Change::set(
        key,
        Value::Vxlan {
            vni,
            local,
            remotes,
            port: 8472,
            underlay_vrf: "default".into(),
        },
    )]);
    let broadcast = frame([0xff; 6], H1, 60);
    let out = bench.send(P1, broadcast);
    assert_eq!(out.len(), 1);
    assert_eq!(&out[0].1[36..38], &8472_u16.to_be_bytes());
    // In on 8472, not on 4789.
    let b = frame(H1, H2, 60);
    let on = |port: u16| {
        let mut p = outer(VTEP2, 100, &b);
        p[36..38].copy_from_slice(&port.to_be_bytes());
        p
    };
    // On 4789 it is UDP to the router, not VXLAN: nothing goes to p1.
    assert!(bench
        .send(WAN, on(4789))
        .iter()
        .all(|(port, _)| *port != P1));
    assert_eq!(bench.send(WAN, on(8472)), vec![(P1, b)]);
}

#[test]
fn a_static_address_on_a_vxlan_member_goes_to_its_vtep_only() {
    let mut bench = Bench::with(&[Change::set(
        Key::BridgeMac {
            bridge: "br0".into(),
            mac: H2,
        },
        Value::BridgeMac {
            interface: "vx0".into(),
            vtep: Some(IpAddr::from(VTEP3)),
        },
    )]);
    let c = frame(H2, H1, 100);
    let out = bench.send(P1, c.clone());
    assert_eq!(out.len(), 1);
    assert_eq!(vtep_of(&out[0].1, &c), VTEP3);
    // A VTEP that is not the member's is refused.
    let code = bench.try_change(&[Change::set(
        Key::BridgeMac {
            bridge: "br0".into(),
            mac: H2,
        },
        Value::BridgeMac {
            interface: "vx0".into(),
            vtep: Some(IpAddr::from([203, 0, 113, 99])),
        },
    )]);
    assert_ne!(code, Code::CHANGED);
}

#[test]
fn the_outer_packets_are_in_the_underlay_vrf() {
    // wan, and the route to the VTEPs, in VRF blue; vx0's outer packets there too.
    let mut wan = iface("wan", WAN_MAC);
    if let Some(Value::Interface { vrf, .. }) = wan.value.as_mut() {
        *vrf = "blue".into();
    }
    let Change { key, value, .. } = vxlan("vx0", 100, &[VTEP2]);
    let Some(Value::Vxlan {
        vni,
        local,
        remotes,
        port,
        ..
    }) = value
    else {
        unreachable!()
    };
    let in_blue = Change::set(
        key,
        Value::Vxlan {
            vni,
            local,
            remotes,
            port,
            underlay_vrf: "blue".into(),
        },
    );
    let mut bench = Bench::with(&[wan, in_blue]);
    let route = Change::set(
        Key::Route {
            vrf: "blue".into(),
            prefix: Ipv4Addr::UNSPECIFIED.into(),
            len: 0,
        },
        Value::Route(RouteAction::Forward(vec![NextHop {
            interface: "wan".into(),
            address: Some(Ipv4Addr::new(198, 51, 100, 1).into()),
        }])),
    );
    let (a, b) = UnixStream::pair().unwrap();
    bench.fe.attach(a, writers::ROUTE).unwrap();
    let mut routes = Client::new(b).unwrap();
    let token = routes.patch(&[route]).unwrap();
    assert_eq!(settle(&mut bench.fe, &mut routes, token), Code::CHANGED);

    let broadcast = frame([0xff; 6], H1, 60);
    let out = bench.send(P1, broadcast.clone());
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(vtep_of(&out[0].1, &broadcast), VTEP2);
    let b = frame(H1, H2, 60);
    assert_eq!(bench.send(WAN, outer(VTEP2, 100, &b)), vec![(P1, b)]);
}

#[test]
fn outer_packets_in_another_vrf_than_the_underlay_are_not_taken() {
    // wan in VRF blue, vx0's outer packets in the default VRF: not unwrapped.
    let mut wan = iface("wan", WAN_MAC);
    if let Some(Value::Interface { vrf, .. }) = wan.value.as_mut() {
        *vrf = "blue".into();
    }
    let mut bench = Bench::with(&[wan]);
    let b = frame(H1, H2, 60);
    let out = bench.send(WAN, outer(VTEP2, 100, &b));
    assert!(out.iter().all(|(port, _)| *port != P1), "{out:?}");
}

#[test]
fn an_underlay_vrf_with_no_interface_up_leaves_the_overlay_without_a_route() {
    // vx0's outer packets in VRF blue, which has no enabled interface: the tables
    // are taken, and frames for vx0 go nowhere.
    let mut down = iface("blue0", [2, 0, 0, 0, 0, 0xb]);
    if let Some(Value::Interface { enabled, vrf, .. }) = down.value.as_mut() {
        *enabled = false;
        *vrf = "blue".into();
    }
    let Change { key, value, .. } = vxlan("vx0", 100, &[VTEP2]);
    let Some(Value::Vxlan {
        vni,
        local,
        remotes,
        port,
        ..
    }) = value
    else {
        unreachable!()
    };
    let mut bench = Bench::with(&[
        down,
        Change::set(
            key,
            Value::Vxlan {
                vni,
                local,
                remotes,
                port,
                underlay_vrf: "blue".into(),
            },
        ),
    ]);
    let out = bench.send(P1, frame([0xff; 6], H1, 60));
    assert!(out.iter().all(|(port, _)| *port != WAN), "{out:?}");
}
