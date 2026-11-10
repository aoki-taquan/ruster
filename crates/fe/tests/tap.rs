//! IS-IS and OSPF to and from an interface's TAP device (`docs/design/overlay.md`
//! section 6): tables arrive over real sockets, packets go through `SimIo`, and the
//! TAP and the TUN are datagram socket pairs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::net::{UnixDatagram, UnixStream};

use ruster_core::{ipv4_header_checksum, IfId};
use ruster_fe::{writers, Fe};
use ruster_io_sim::SimIo;
use ruster_proto::coap::Code;
use ruster_proto::session::{Client, Event};
use ruster_proto::table::{
    Change, Key, NextHop, PuntClass, PuntDestination, PuntKind, PuntMatch, RouteAction, Value,
};
use ruster_proto::task::Task;

const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];
const WAN_HOST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x20];
const ALL_L1_ISS: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x14];
const ALL_SPF_ROUTERS: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x05];

struct Bench {
    fe: Fe<SimIo>,
    clients: Vec<Client>,
}

impl Bench {
    /// Two ports, lan (192.0.2.1/24, fe80::1) and wan (198.51.100.2/24), with
    /// IS-IS and OSPF of lan going to its TAP, and a TUN for the default VRF.
    fn new() -> (Self, UnixDatagram, UnixDatagram) {
        let mut bench = Self {
            fe: Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]),
            clients: Vec::new(),
        };
        let interface = |name: &str, mac| {
            Change::set(
                Key::Interface { name: name.into() },
                Value::Interface {
                    enabled: true,
                    mac,
                    mtu: 1500,
                    vrf: "default".into(),
                    vlan: None,
                    tunnel: None,
                    pppoe: None,
                },
            )
        };
        let address = |name: &str, address: IpAddr, prefix_len| {
            Change::set(
                Key::Address {
                    interface: name.into(),
                    address,
                },
                Value::Address { prefix_len },
            )
        };
        let tap = |class: &str, kind| {
            Change::set(
                Key::Punt {
                    class: class.into(),
                },
                Value::Punt(PuntClass {
                    matches: PuntMatch::Kind(kind),
                    interface: Some("lan".into()),
                    destination: PuntDestination::Tap,
                    rate: 100,
                    burst: 100,
                }),
            )
        };
        bench.patch(
            writers::CONFIG,
            &[
                interface("lan", LAN_MAC),
                interface("wan", WAN_MAC),
                address("lan", Ipv4Addr::new(192, 0, 2, 1).into(), 24),
                address("lan", "fe80::1".parse().unwrap(), 64),
                address("wan", Ipv4Addr::new(198, 51, 100, 2).into(), 24),
                tap("isis-lan", PuntKind::Isis),
                tap("ospf-lan", PuntKind::Ospf),
            ],
        );
        let route = |prefix: [u8; 4], interface: &str| {
            Change::set(
                Key::Route {
                    vrf: "default".into(),
                    prefix: Ipv4Addr::from(prefix).into(),
                    len: 24,
                },
                Value::Route(RouteAction::Forward(vec![NextHop {
                    interface: interface.into(),
                    address: None,
                }])),
            )
        };
        bench.patch(
            writers::ROUTE,
            &[
                route([192, 0, 2, 0], "lan"),
                route([198, 51, 100, 0], "wan"),
            ],
        );
        let neighbor = |interface: &str, address: IpAddr, mac| {
            Change::set(
                Key::Neighbor {
                    interface: interface.into(),
                    address,
                },
                Value::Neighbor { mac },
            )
        };
        bench.patch(
            writers::NEIGHBOR,
            &[
                neighbor("wan", Ipv4Addr::new(198, 51, 100, 20).into(), WAN_HOST_MAC),
                neighbor("lan", "fe80::10".parse().unwrap(), PEER_MAC),
            ],
        );
        let (fe_tun, tun) = UnixDatagram::pair().unwrap();
        fe_tun.set_nonblocking(true).unwrap();
        bench.fe.attach_local("default", Box::new(fe_tun));
        let (fe_tap, tap) = UnixDatagram::pair().unwrap();
        fe_tap.set_nonblocking(true).unwrap();
        tap.set_nonblocking(true).unwrap();
        tun.set_nonblocking(true).unwrap();
        bench.fe.attach_tap("lan", Box::new(fe_tap));
        (bench, tap, tun)
    }

    fn patch(&mut self, writes: &[u64], changes: &[Change]) {
        let (a, b) = UnixStream::pair().unwrap();
        self.fe.attach(a, writes).unwrap();
        let mut client = Client::new(b).unwrap();
        let token = client.patch(changes).unwrap();
        let mut answered = false;
        for _ in 0..1_000 {
            let busy = self.fe.step(0).busy;
            let (progress, events) = client.poll();
            answered |= events.iter().any(|e| {
                matches!(e, Event::Response { token: t, code, .. } if *t == token && *code == Code::CHANGED)
            });
            if answered && !busy && !progress.busy {
                break;
            }
        }
        assert!(answered, "tables taken");
        self.clients.push(client);
    }
}

fn isis_hello() -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 3 + 40];
    frame[0..6].copy_from_slice(&ALL_L1_ISS);
    frame[6..12].copy_from_slice(&PEER_MAC);
    frame[12..14].copy_from_slice(&43_u16.to_be_bytes());
    frame[14..17].copy_from_slice(&[0xfe, 0xfe, 0x03]);
    frame[17] = 0x83;
    frame
}

/// An IPv4 OSPF packet from `source` to `destination`, in a frame to `mac`.
fn ospf(mac: [u8; 6], source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 20 + 24];
    frame[0..6].copy_from_slice(&mac);
    frame[6..12].copy_from_slice(&PEER_MAC);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    let ip = &mut frame[14..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&44_u16.to_be_bytes());
    ip[8] = 1;
    ip[9] = 89;
    ip[12..16].copy_from_slice(&source);
    ip[16..20].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn recv(socket: &UnixDatagram) -> Option<Vec<u8>> {
    let mut buf = [0_u8; 2048];
    socket.recv(&mut buf).ok().map(|n| buf[..n].to_vec())
}

#[test]
fn is_is_and_ospf_of_the_interface_go_to_its_tap_unchanged() {
    let (mut bench, tap, tun) = Bench::new();
    assert_eq!(bench.fe.tap_interfaces(), ["lan"]);
    let hello = isis_hello();
    let multicast = ospf(ALL_SPF_ROUTERS, [192, 0, 2, 10], [224, 0, 0, 5]);
    let unicast = ospf(LAN_MAC, [192, 0, 2, 10], [192, 0, 2, 1]);
    for frame in [&hello, &multicast, &unicast] {
        bench.fe.io_mut().inject(IfId(0), frame.clone());
        bench.fe.step(1);
        assert_eq!(recv(&tap).as_ref(), Some(frame));
    }
    assert!(recv(&tun).is_none(), "OSPF to the router is not the TUN's");
    // On wan, which runs neither: not to the TAP, and the hello is not forwarded.
    bench.fe.io_mut().inject(IfId(1), hello);
    bench.fe.step(2);
    assert!(recv(&tap).is_none());
    assert!(bench.fe.io_mut().pop_tx().is_none());
    assert_eq!(bench.fe.counters().to_tap, 3);
    let counted: Vec<_> = bench
        .fe
        .punt_counters()
        .into_iter()
        .filter(|(name, _)| name.ends_with("-lan"))
        .map(|(name, c)| (name, c.handed))
        .collect();
    assert_eq!(
        counted,
        [("isis-lan".to_owned(), 1), ("ospf-lan".to_owned(), 2)]
    );
}

#[test]
fn link_frames_from_the_tap_leave_its_interface_and_the_rest_is_routed() {
    let (mut bench, tap, _tun) = Bench::new();
    // IS-IS and OSPF to its group go out of lan as they are.
    let hello = {
        let mut frame = isis_hello();
        frame[6..12].copy_from_slice(&LAN_MAC);
        frame
    };
    let multicast = ospf(ALL_SPF_ROUTERS, [192, 0, 2, 1], [224, 0, 0, 5]);
    for frame in [&hello, &multicast] {
        tap.send(frame).unwrap();
        bench.fe.step(1);
        let tx = bench.fe.io_mut().pop_tx().expect("sent out");
        assert_eq!((tx.egress, &tx.bytes), (IfId(0), frame));
    }
    // To a host on wan: through the routes, to the neighbor's MAC. The kernel put
    // the TAP's own MAC as the destination (NOARP).
    let unicast = ospf(LAN_MAC, [192, 0, 2, 1], [198, 51, 100, 20]);
    tap.send(&unicast).unwrap();
    bench.fe.step(2);
    let tx = bench.fe.io_mut().pop_tx().expect("routed");
    assert_eq!(tx.egress, IfId(1));
    assert_eq!(&tx.bytes[..6], &WAN_HOST_MAC);
    assert_eq!(
        &tx.bytes[14..],
        &unicast[14..],
        "the router's own: TTL kept"
    );
    // ARP does not leave a TAP.
    let mut arp = vec![0_u8; 42];
    arp[12..14].copy_from_slice(&[0x08, 0x06]);
    tap.send(&arp).unwrap();
    bench.fe.step(3);
    assert!(bench.fe.io_mut().pop_tx().is_none());
    let counters = bench.fe.counters();
    assert_eq!((counters.from_tap, counters.from_tap_dropped), (3, 1));
}

/// An IPv6 OSPF packet from fe80::1 to `destination`, in a frame to the TAP's own
/// MAC (as the kernel sends with NOARP).
fn ospf6(destination: &str) -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 40 + 16];
    frame[0..6].copy_from_slice(&LAN_MAC);
    frame[6..12].copy_from_slice(&LAN_MAC);
    frame[12..14].copy_from_slice(&[0x86, 0xdd]);
    let ip = &mut frame[14..];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&16_u16.to_be_bytes());
    ip[6] = 89;
    ip[7] = 1;
    let source: Ipv6Addr = "fe80::1".parse().unwrap();
    ip[8..24].copy_from_slice(&source.octets());
    let destination: Ipv6Addr = destination.parse().unwrap();
    ip[24..40].copy_from_slice(&destination.octets());
    frame
}

#[test]
fn ipv6_to_a_link_local_neighbor_gets_its_mac_or_asks_for_it() {
    let (mut bench, tap, _tun) = Bench::new();
    tap.send(&ospf6("fe80::10")).unwrap();
    bench.fe.step(1);
    let tx = bench.fe.io_mut().pop_tx().expect("sent to the neighbor");
    assert_eq!(tx.egress, IfId(0));
    assert_eq!(&tx.bytes[..6], &PEER_MAC);
    assert_eq!(&tx.bytes[6..], &ospf6("fe80::10")[6..]);

    let (a, b) = UnixStream::pair().unwrap();
    bench.fe.attach(a, writers::READ_ONLY).unwrap();
    let mut observer = Client::new(b).unwrap();
    observer.observe();
    for at in 2..20 {
        bench.fe.step(at);
        observer.poll();
    }
    tap.send(&ospf6("fe80::99")).unwrap();
    let mut asked = false;
    for at in 20..100 {
        bench.fe.step(at);
        let (_, events) = observer.poll();
        asked |= events
            .iter()
            .any(|e| matches!(e, Event::Notification { .. }));
    }
    assert!(asked, "the neighbor is asked for");
    assert!(bench.fe.io_mut().pop_tx().is_none());
    assert_eq!(bench.fe.counters().from_tap_dropped, 1);
}

#[test]
fn without_its_tap_the_frames_are_counted_as_dropped() {
    let (mut bench, _tap, _tun) = Bench::new();
    bench.fe.detach_tap("lan");
    bench.fe.io_mut().inject(IfId(0), isis_hello());
    bench.fe.step(1);
    assert_eq!(bench.fe.counters().to_tap_dropped, 1);
    let dropped = bench
        .fe
        .punt_counters()
        .into_iter()
        .find(|(name, _)| name == "isis-lan")
        .map(|(_, c)| c.dropped);
    assert_eq!(dropped, Some(1));
}
