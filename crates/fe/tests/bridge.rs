//! Bridges in the FE: two ports in one bridge with an IRB, and a routed port.

use std::net::Ipv4Addr;
use std::os::unix::net::{UnixDatagram, UnixStream};

use ruster_core::{ipv4_header_checksum, IfId};
use ruster_fe::{writers, Fe};
use ruster_io_sim::SimIo;
use ruster_proto::coap::Code;
use ruster_proto::punt::{self, Direction, Punt};
use ruster_proto::session::{Client, Event};
use ruster_proto::table::{Change, Key, NextHop, RouteAction, Value, Vlan};
use ruster_proto::task::Task;

const P1: IfId = IfId(0);
const P2: IfId = IfId(1);
const WAN: IfId = IfId(2);
const IRB_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const H1: [u8; 6] = [2, 0, 0, 0, 0, 0x11];
const H2: [u8; 6] = [2, 0, 0, 0, 0, 0x12];
const GATEWAY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];

struct Bench {
    fe: Fe<SimIo>,
    config: Client,
}

impl Bench {
    /// Ports p1 and p2 in bridge br0 (IRB 192.0.2.1/24, ageing `aging_s`), wan routed.
    fn new(aging_s: u32, extra: &[Change]) -> Self {
        let fe = Fe::new(SimIo::new(), vec!["p1".into(), "p2".into(), "wan".into()]);
        let (a, b) = UnixStream::pair().unwrap();
        let mut bench = Self {
            fe,
            config: Client::new(b).unwrap(),
        };
        bench.fe.attach(a, writers::CONFIG).unwrap();
        let mut changes = vec![
            iface("p1", [2, 0, 0, 0, 1, 1], None),
            iface("p2", [2, 0, 0, 0, 1, 2], None),
            iface("wan", WAN_MAC, None),
            iface("br0", IRB_MAC, None),
            address("br0", [192, 0, 2, 1], 24),
            address("wan", [198, 51, 100, 2], 24),
            Change::set(
                Key::Bridge { name: "br0".into() },
                Value::Bridge {
                    aging_s,
                    max_learned: 16,
                },
            ),
            member("p1"),
            member("p2"),
        ];
        changes.extend_from_slice(extra);
        assert_eq!(bench.patch_config(&changes), Code::CHANGED);
        let (a, b) = UnixStream::pair().unwrap();
        bench.fe.attach(a, writers::ROUTE).unwrap();
        let mut routes = Client::new(b).unwrap();
        let token = routes
            .patch(&[
                route([192, 0, 2, 0], 24, "br0", None),
                route([0, 0, 0, 0], 0, "wan", Some([198, 51, 100, 1])),
            ])
            .unwrap();
        bench.settle(&mut routes, token);
        let (a, b) = UnixStream::pair().unwrap();
        bench.fe.attach(a, writers::NEIGHBOR).unwrap();
        let mut neighbors = Client::new(b).unwrap();
        let token = neighbors
            .patch(&[
                neighbor("br0", [192, 0, 2, 10], H1),
                neighbor("wan", [198, 51, 100, 1], GATEWAY_MAC),
            ])
            .unwrap();
        bench.settle(&mut neighbors, token);
        bench
    }

    fn settle(&mut self, client: &mut Client, token: u32) -> Code {
        let mut code = None;
        for _ in 0..1_000 {
            let mut busy = self.fe.step(0).busy;
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

    fn patch_config(&mut self, changes: &[Change]) -> Code {
        let token = self.config.patch(changes).unwrap();
        let mut config = std::mem::replace(
            &mut self.config,
            Client::new(UnixStream::pair().unwrap().0).unwrap(),
        );
        let code = self.settle(&mut config, token);
        self.config = config;
        code
    }

    /// Sends `frame` in on `port` at `now` and returns what left, by port.
    fn send(&mut self, port: IfId, frame: Vec<u8>, now: u64) -> Vec<(IfId, Vec<u8>)> {
        self.fe.io_mut().inject(port, frame);
        self.fe.step(now);
        let mut out = Vec::new();
        while let Some(tx) = self.fe.io_mut().pop_tx() {
            out.push((tx.egress, tx.bytes));
        }
        out
    }
}

fn iface(name: &str, mac: [u8; 6], vlan: Option<Vlan>) -> Change {
    Change::set(
        Key::Interface { name: name.into() },
        Value::Interface {
            enabled: true,
            mac,
            mtu: 1500,
            vrf: ruster_proto::table::DEFAULT_VRF.into(),
            vlan,
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

fn address(interface: &str, address: [u8; 4], prefix_len: u8) -> Change {
    Change::set(
        Key::Address {
            interface: interface.into(),
            address: Ipv4Addr::from(address).into(),
        },
        Value::Address { prefix_len },
    )
}

fn route(prefix: [u8; 4], len: u8, interface: &str, via: Option<[u8; 4]>) -> Change {
    Change::set(
        Key::Route {
            vrf: "default".into(),
            prefix: Ipv4Addr::from(prefix).into(),
            len,
        },
        Value::Route(RouteAction::Forward(vec![NextHop {
            interface: interface.into(),
            address: via.map(|a| Ipv4Addr::from(a).into()),
        }])),
    )
}

fn neighbor(interface: &str, address: [u8; 4], mac: [u8; 6]) -> Change {
    Change::set(
        Key::Neighbor {
            interface: interface.into(),
            address: Ipv4Addr::from(address).into(),
        },
        Value::Neighbor { mac },
    )
}

/// An Ethernet/IPv4/UDP frame.
fn udp(dst: [u8; 6], src: [u8; 6], from: [u8; 4], to: [u8; 4]) -> Vec<u8> {
    let mut frame = vec![0_u8; 60];
    frame[0..6].copy_from_slice(&dst);
    frame[6..12].copy_from_slice(&src);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    let ip = 14;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&46_u16.to_be_bytes());
    frame[ip + 8] = 64;
    frame[ip + 9] = 17;
    frame[ip + 12..ip + 16].copy_from_slice(&from);
    frame[ip + 16..ip + 20].copy_from_slice(&to);
    let checksum = ipv4_header_checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
    frame[ip + 20..ip + 22].copy_from_slice(&1000_u16.to_be_bytes());
    frame[ip + 22..ip + 24].copy_from_slice(&2000_u16.to_be_bytes());
    frame[ip + 24..ip + 26].copy_from_slice(&26_u16.to_be_bytes());
    frame
}

fn arp_request(sender_mac: [u8; 6], sender: [u8; 4], target: [u8; 4]) -> Vec<u8> {
    let mut frame = vec![0_u8; 42];
    frame[0..6].copy_from_slice(&[0xff; 6]);
    frame[6..12].copy_from_slice(&sender_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x06]);
    frame[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    frame[22..28].copy_from_slice(&sender_mac);
    frame[28..32].copy_from_slice(&sender);
    frame[38..42].copy_from_slice(&target);
    frame
}

fn ports(out: &[(IfId, Vec<u8>)]) -> Vec<IfId> {
    let mut ports: Vec<IfId> = out.iter().map(|(port, _)| *port).collect();
    ports.sort_by_key(|p| p.0);
    ports
}

#[test]
fn hosts_on_two_members_reach_each_other_and_learned_addresses_are_not_flooded() {
    let mut bench = Bench::new(300, &[]);
    let a = udp(H2, H1, [192, 0, 2, 10], [192, 0, 2, 20]);
    // H2 is not known: flooded to p2 only, unchanged.
    let out = bench.send(P1, a.clone(), 0);
    assert_eq!(out, vec![(P2, a)]);
    // H1 was learned on p1: the reply goes there only.
    let b = udp(H1, H2, [192, 0, 2, 20], [192, 0, 2, 10]);
    assert_eq!(bench.send(P2, b.clone(), 1), vec![(P1, b)]);
    let counters = bench.fe.counters();
    assert_eq!(counters.bridge_learned, 2);
    assert_eq!(counters.bridge_flooded, 1);
    assert_eq!(counters.bridge_forwarded, 1);
}

#[test]
fn a_broadcast_is_flooded_and_reaches_the_neighbor_process_on_the_irb() {
    let mut bench = Bench::new(300, &[]);
    let (fe_end, neighd_end) = UnixDatagram::pair().unwrap();
    bench.fe.attach_punt(fe_end).unwrap();
    let request = arp_request(H1, [192, 0, 2, 10], [192, 0, 2, 1]);
    let out = bench.send(P1, request.clone(), 0);
    assert_eq!(out, vec![(P2, request)]);
    let mut buf = [0_u8; 256];
    let n = neighd_end.recv(&mut buf).unwrap();
    let punt = Punt::decode(&buf[..n]).unwrap();
    assert_eq!(punt.reason, punt::reason::ARP);
    assert_eq!(punt.interface, "br0");

    // The neighbor process's broadcast on the IRB leaves every member; its unicast
    // reply only the member the host is on.
    let mut reply = arp_request(IRB_MAC, [192, 0, 2, 1], [192, 0, 2, 10]);
    reply[0..6].copy_from_slice(&H1);
    for (frame, expected) in [
        (
            arp_request(IRB_MAC, [192, 0, 2, 1], [192, 0, 2, 20]),
            vec![P1, P2],
        ),
        (reply, vec![P1]),
    ] {
        let mut message = Vec::new();
        Punt {
            direction: Direction::FromControl,
            reason: punt::reason::ARP,
            interface: "br0",
            frame: &frame,
        }
        .encode(&mut message)
        .unwrap();
        neighd_end.send(&message).unwrap();
        bench.fe.step(1);
        let mut out = Vec::new();
        while let Some(tx) = bench.fe.io_mut().pop_tx() {
            out.push((tx.egress, tx.bytes));
        }
        assert_eq!(ports(&out), expected);
        assert!(out.iter().all(|(_, bytes)| *bytes == frame));
    }
}

#[test]
fn packets_routed_out_of_the_irb_are_flooded_until_the_host_is_learned() {
    let mut bench = Bench::new(300, &[]);
    let from_wan = udp(WAN_MAC, GATEWAY_MAC, [203, 0, 113, 7], [192, 0, 2, 10]);
    let out = bench.send(WAN, from_wan.clone(), 0);
    assert_eq!(ports(&out), vec![P1, P2]);
    assert!(out
        .iter()
        .all(|(_, b)| b[0..6] == H1 && b[6..12] == IRB_MAC));
    // H1 speaks from p1 (to the router: routed out of wan).
    let to_wan = udp(IRB_MAC, H1, [192, 0, 2, 10], [203, 0, 113, 7]);
    let out = bench.send(P1, to_wan, 1);
    assert_eq!(ports(&out), vec![WAN]);
    assert_eq!(out[0].1[0..6], GATEWAY_MAC);
    let out = bench.send(WAN, from_wan, 2);
    assert_eq!(ports(&out), vec![P1]);
}

#[test]
fn learned_addresses_move_and_age() {
    let mut bench = Bench::new(10, &[]);
    bench.send(P1, udp(H2, H1, [192, 0, 2, 10], [192, 0, 2, 20]), 0);
    // H1 shows up on p2.
    bench.send(P2, udp(H2, H1, [192, 0, 2, 10], [192, 0, 2, 20]), 1);
    assert_eq!(bench.fe.counters().bridge_moved, 1);
    let to_h1 = udp(H1, H2, [192, 0, 2, 20], [192, 0, 2, 10]);
    // From p1 now: to p2.
    assert_eq!(ports(&bench.send(P1, to_h1.clone(), 2)), vec![P2]);
    let entries = bench.fe.bridge_entries();
    assert!(entries
        .iter()
        .any(|(bridge, e)| bridge == "br0" && e.mac == H1 && e.member == P2));
    // Past the ageing time (H2 keeps being seen on p1): flooded again.
    let out = bench.send(P1, to_h1, 12_000);
    assert_eq!(ports(&out), vec![P2]);
    assert_eq!(bench.fe.counters().bridge_aged, 1);
    assert_eq!(bench.fe.counters().bridge_flooded, 3);
}

#[test]
fn frames_to_reserved_addresses_and_back_to_their_member_are_dropped() {
    let mut bench = Bench::new(300, &[]);
    let stp = [0x01, 0x80, 0xc2, 0, 0, 0];
    assert!(bench.send(P1, udp(stp, H1, [0; 4], [0; 4]), 0).is_empty());
    bench.send(P2, udp(H1, H2, [192, 0, 2, 20], [192, 0, 2, 10]), 1);
    // H2 is on p2; a frame to it from p2 is not sent back.
    assert!(bench
        .send(P2, udp(H2, H1, [192, 0, 2, 10], [192, 0, 2, 20]), 2)
        .is_empty());
    assert_eq!(bench.fe.counters().bridge_dropped, 2);
}

#[test]
fn a_vlan_sub_interface_is_a_member_and_its_frames_are_tagged() {
    let mut bench = Bench::new(
        300,
        &[
            iface(
                "wan.10",
                WAN_MAC,
                Some(Vlan {
                    parent: "wan".into(),
                    id: 10,
                }),
            ),
            member("wan.10"),
        ],
    );
    let a = udp(H2, H1, [192, 0, 2, 10], [192, 0, 2, 20]);
    let out = bench.send(P1, a.clone(), 0);
    assert_eq!(ports(&out), vec![P2, WAN]);
    let tagged = &out.iter().find(|(p, _)| *p == WAN).unwrap().1;
    assert_eq!(tagged[12..16], [0x81, 0x00, 0x00, 0x0a]);
    assert_eq!(tagged[16..], a[12..]);
    // H2 answers from VLAN 10: the tag comes off toward p1.
    let mut b = udp(H1, H2, [192, 0, 2, 20], [192, 0, 2, 10]);
    let untagged = b.clone();
    b.splice(12..12, [0x81, 0x00, 0x00, 0x0a]);
    assert_eq!(bench.send(WAN, b, 1), vec![(P1, untagged)]);
    // Known now: H1 to H2 goes out tagged, as a relayed frame.
    let out = bench.send(P1, a.clone(), 2);
    assert_eq!(ports(&out), vec![WAN]);
    assert_eq!(out[0].1[12..16], [0x81, 0x00, 0x00, 0x0a]);
}

#[test]
fn a_member_that_leaves_the_bridge_forgets_what_was_learned_on_it() {
    let mut bench = Bench::new(300, &[]);
    bench.send(P2, udp(H1, H2, [192, 0, 2, 20], [192, 0, 2, 10]), 0);
    assert_eq!(bench.fe.bridge_entries().len(), 2 - 1);
    assert_eq!(
        bench.patch_config(&[Change::delete(Key::BridgePort {
            interface: "p2".into()
        })]),
        Code::CHANGED
    );
    assert!(bench.fe.bridge_entries().is_empty());
    // p2 is no member now: its frames are not relayed.
    assert!(bench
        .send(P2, udp(H1, H2, [192, 0, 2, 20], [192, 0, 2, 10]), 1)
        .is_empty());
}

#[test]
fn members_and_parents_of_member_vlans_are_promiscuous() {
    let mut bench = Bench::new(300, &[]);
    assert_eq!(bench.fe.promiscuous_ports(), ["p1", "p2"]);
    let vlan = iface(
        "wan.10",
        WAN_MAC,
        Some(Vlan {
            parent: "wan".into(),
            id: 10,
        }),
    );
    assert_eq!(bench.patch_config(&[vlan, member("wan.10")]), Code::CHANGED);
    assert_eq!(bench.fe.promiscuous_ports(), ["p1", "p2", "wan"]);
    let leave = |name: &str| {
        Change::delete(Key::BridgePort {
            interface: name.into(),
        })
    };
    assert_eq!(
        bench.patch_config(&[leave("p2"), leave("wan.10")]),
        Code::CHANGED
    );
    assert_eq!(bench.fe.promiscuous_ports(), ["p1"]);
}

#[test]
fn links_follow_the_ports_and_a_disabled_interface_is_down() {
    let vlan = iface(
        "wan.10",
        WAN_MAC,
        Some(Vlan {
            parent: "wan".into(),
            id: 10,
        }),
    );
    let mut bench = Bench::new(300, &[vlan]);
    let fe = &bench.fe;
    assert_eq!(fe.ports(), ["p1", "p2", "wan"]);
    // The IRB is up while one member is.
    assert!(fe.link_up("br0", &[false, true, false]));
    assert!(!fe.link_up("br0", &[false, false, true]));
    assert!(fe.link_up("p1", &[true, false, false]));
    assert!(!fe.link_up("p1", &[false, true, true]));
    // A VLAN sub-interface follows its parent.
    assert!(fe.link_up("wan.10", &[false, false, true]));
    assert!(!fe.link_up("wan.10", &[true, true, false]));
    assert!(!fe.link_up("nothing", &[true, true, true]));
    let disabled = Change::set(
        Key::Interface { name: "wan".into() },
        Value::Interface {
            enabled: false,
            mac: WAN_MAC,
            mtu: 1500,
            vrf: ruster_proto::table::DEFAULT_VRF.into(),
            vlan: None,
            tunnel: None,
            pppoe: None,
        },
    );
    assert_eq!(bench.patch_config(&[disabled]), Code::CHANGED);
    assert!(!bench.fe.link_up("wan", &[true, true, true]));
    assert!(!bench.fe.link_up("wan.10", &[true, true, true]));
}
