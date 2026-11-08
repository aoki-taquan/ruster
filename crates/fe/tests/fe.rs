//! FE skeleton tests: tables arrive over real sockets, packets go through `SimIo`.

use std::net::Ipv4Addr;
use std::os::unix::net::{UnixDatagram, UnixStream};

use ruster_core::{ipv4_header_checksum, IfId};
use ruster_fe::{writers, Fe};
use ruster_io_sim::SimIo;
use ruster_proto::cbor::Decoder;
use ruster_proto::coap::Code;
use ruster_proto::punt::{self, Direction, Punt};
use ruster_proto::session::{Client, Event};
use ruster_proto::table::{Change, Key, NextHop, ResolveRequest, RouteAction, Value};
use ruster_proto::task::Task;

const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const HOST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];
const GATEWAY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
const GATEWAY: [u8; 4] = [198, 51, 100, 1];

struct Bench {
    fe: Fe<SimIo>,
    now: u64,
}

impl Bench {
    fn new() -> Self {
        Self {
            fe: Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]),
            now: 0,
        }
    }

    fn connect(&mut self, writes: &[u64]) -> Client {
        let (a, b) = UnixStream::pair().unwrap();
        self.fe.attach(a, writes).unwrap();
        Client::new(b).unwrap()
    }

    /// Steps the FE and the clients until quiet. Returns each client's events.
    fn settle(&mut self, clients: &mut [&mut Client]) -> Vec<Vec<Event>> {
        let mut events = vec![Vec::new(); clients.len()];
        for _ in 0..1_000 {
            let mut busy = self.fe.step(self.now).busy;
            for (client, got) in clients.iter_mut().zip(&mut events) {
                let (progress, mut new) = client.poll();
                busy |= progress.busy;
                got.append(&mut new);
            }
            if !busy {
                return events;
            }
        }
        panic!("never settled");
    }

    fn patch(&mut self, client: &mut Client, changes: &[Change]) -> Code {
        let token = client.patch(changes).unwrap();
        let events = self.settle(&mut [client]).remove(0);
        events
            .iter()
            .find_map(|event| match event {
                Event::Response { token: t, code, .. } if *t == token => Some(*code),
                _ => None,
            })
            .expect("response")
    }
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

/// The tables of a two-port router: LAN 192.0.2.0/24, WAN 198.51.100.0/24, default via
/// the WAN gateway.
fn configure(bench: &mut Bench) -> (Client, Client) {
    let mut config = bench.connect(writers::CONFIG);
    let code = bench.patch(
        &mut config,
        &[
            iface("lan", LAN_MAC),
            iface("wan", WAN_MAC),
            address("lan", [192, 0, 2, 1], 24),
            address("wan", [198, 51, 100, 2], 24),
        ],
    );
    assert_eq!(code, Code::CHANGED);
    let mut routes = bench.connect(writers::ROUTE);
    let code = bench.patch(
        &mut routes,
        &[
            route([192, 0, 2, 0], 24, "lan", None),
            route([198, 51, 100, 0], 24, "wan", None),
            route([0, 0, 0, 0], 0, "wan", Some(GATEWAY)),
        ],
    );
    assert_eq!(code, Code::CHANGED);
    (config, routes)
}

/// An Ethernet/IPv4/UDP frame from the LAN host to `destination`.
fn udp_from_host(destination: [u8; 4]) -> Vec<u8> {
    let mut frame = vec![0_u8; 60];
    frame[0..6].copy_from_slice(&LAN_MAC);
    frame[6..12].copy_from_slice(&HOST_MAC);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    let ip = 14;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&46_u16.to_be_bytes());
    frame[ip + 8] = 64;
    frame[ip + 9] = 17;
    frame[ip + 12..ip + 16].copy_from_slice(&[192, 0, 2, 10]);
    frame[ip + 16..ip + 20].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
    frame[ip + 20..ip + 22].copy_from_slice(&1000_u16.to_be_bytes());
    frame[ip + 22..ip + 24].copy_from_slice(&2000_u16.to_be_bytes());
    frame[ip + 24..ip + 26].copy_from_slice(&26_u16.to_be_bytes());
    frame
}

const INTERNET: [u8; 4] = [203, 0, 113, 7];

#[test]
fn empty_tables_forward_nothing() {
    let mut bench = Bench::new();
    bench.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    bench.fe.step(0);
    assert!(bench.fe.io_mut().pop_tx().is_none());
}

#[test]
fn tables_from_three_writers_forward_a_packet() {
    let mut bench = Bench::new();
    let (_config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    let code = bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]);
    assert_eq!(code, Code::CHANGED);

    bench.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    bench.fe.step(0);
    let tx = bench.fe.io_mut().pop_tx().expect("forwarded");
    assert_eq!(tx.egress, IfId(1));
    assert_eq!(&tx.bytes[0..6], &GATEWAY_MAC);
    assert_eq!(&tx.bytes[6..12], &WAN_MAC);
    assert_eq!(tx.bytes[14 + 8], 63, "TTL decremented");
}

#[test]
fn a_neighbor_miss_becomes_one_resolve_request_per_second() {
    let mut bench = Bench::new();
    let (_config, _routes) = configure(&mut bench);
    let mut watcher = bench.connect(writers::NEIGHBOR);
    watcher.observe();
    bench.settle(&mut [&mut watcher]);

    for now in [0, 10, 500, 1_000] {
        bench.now = now;
        bench.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
        bench.settle(&mut [&mut watcher]);
    }
    let events = bench.settle(&mut [&mut watcher]).remove(0);
    assert!(events.is_empty());
    assert!(
        bench.fe.io_mut().pop_tx().is_none(),
        "the packets were dropped"
    );
    assert_eq!(
        bench.fe.counters().resolve_requests,
        2,
        "at 0 and at 1000 ms"
    );
}

#[test]
fn resolve_request_names_the_interface_and_next_hop() {
    let mut bench = Bench::new();
    let (_config, _routes) = configure(&mut bench);
    let mut watcher = bench.connect(writers::NEIGHBOR);
    watcher.observe();
    bench.settle(&mut [&mut watcher]);
    bench.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    let events = bench.settle(&mut [&mut watcher]).remove(0);
    let payload = events
        .iter()
        .find_map(|e| match e {
            Event::Notification { payload } => Some(payload.clone()),
            Event::Response { .. } => None,
        })
        .expect("notification");
    let request = ResolveRequest::decode(&mut Decoder::new(&payload)).unwrap();
    assert_eq!(
        request,
        ResolveRequest {
            interface: "wan".into(),
            address: Ipv4Addr::from(GATEWAY).into(),
        }
    );
}

fn arp_request(target: [u8; 4]) -> Vec<u8> {
    let mut frame = vec![0_u8; 42];
    frame[0..6].copy_from_slice(&[0xff; 6]);
    frame[6..12].copy_from_slice(&HOST_MAC);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
    frame[22..28].copy_from_slice(&HOST_MAC);
    frame[28..32].copy_from_slice(&[192, 0, 2, 10]);
    frame[38..42].copy_from_slice(&target);
    frame
}

#[test]
fn arp_goes_to_the_neighbor_socket_and_frames_come_back() {
    let mut bench = Bench::new();
    let (_config, _routes) = configure(&mut bench);
    let (fe_end, neighd_end) = UnixDatagram::pair().unwrap();
    bench.fe.attach_punt(fe_end).unwrap();

    bench
        .fe
        .io_mut()
        .inject(IfId(0), arp_request([192, 0, 2, 1]));
    bench.fe.step(0);
    assert!(
        bench.fe.io_mut().pop_tx().is_none(),
        "the FE does not answer ARP"
    );

    let mut buf = [0_u8; 256];
    let n = neighd_end.recv(&mut buf).unwrap();
    let punt = Punt::decode(&buf[..n]).unwrap();
    assert_eq!(punt.direction, Direction::ToControl);
    assert_eq!(punt.reason, punt::reason::ARP);
    assert_eq!(punt.interface, "lan");
    assert_eq!(punt.frame.len(), 28);
    assert_eq!(&punt.frame[8..14], &HOST_MAC, "sender MAC");
    assert_eq!(&punt.frame[24..28], &[192, 0, 2, 1], "target IP");

    let mut reply = vec![0xab_u8; 42];
    reply[12..14].copy_from_slice(&[0x08, 0x06]);
    let mut message = Vec::new();
    Punt {
        direction: Direction::FromControl,
        reason: punt::reason::ARP,
        interface: "lan",
        frame: &reply,
    }
    .encode(&mut message)
    .unwrap();
    neighd_end.send(&message).unwrap();
    bench.fe.step(1);
    let tx = bench.fe.io_mut().pop_tx().expect("sent");
    assert_eq!(tx.egress, IfId(0));
    assert_eq!(tx.bytes, reply);
}

#[test]
fn rejected_tables_leave_the_old_ones_forwarding() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]);

    // The same address on both interfaces is refused by the core.
    let code = bench.patch(&mut config, &[address("wan", [192, 0, 2, 1], 24)]);
    assert_eq!(code, Code::BAD_REQUEST);

    bench.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    bench.fe.step(0);
    assert!(bench.fe.io_mut().pop_tx().is_some());
}

#[test]
fn forwarding_continues_after_every_writer_disconnects() {
    let mut bench = Bench::new();
    let (config, routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]);
    drop((config, routes, neighbors));
    for now in 0..10 {
        bench.fe.step(now);
    }
    bench.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    bench.fe.step(10);
    assert!(bench.fe.io_mut().pop_tx().is_some());
}

#[test]
fn frames_from_the_neighbor_process_only_leave_enabled_interfaces() {
    let mut bench = Bench::new();
    let mut config = bench.connect(writers::CONFIG);
    bench.patch(&mut config, &[iface("lan", LAN_MAC)]);
    let (fe_end, neighd_end) = UnixDatagram::pair().unwrap();
    bench.fe.attach_punt(fe_end).unwrap();
    let mut frame = vec![0xab_u8; 42];
    frame[12..14].copy_from_slice(&[0x08, 0x06]);
    let mut not_arp = Vec::new();
    Punt {
        direction: Direction::FromControl,
        reason: punt::reason::ARP,
        interface: "lan",
        frame: &[0xab_u8; 42],
    }
    .encode(&mut not_arp)
    .unwrap();
    neighd_end.send(&not_arp).unwrap();
    for interface in ["wan", "nope", "lan"] {
        let mut message = Vec::new();
        Punt {
            direction: Direction::FromControl,
            reason: punt::reason::ARP,
            interface,
            frame: &frame,
        }
        .encode(&mut message)
        .unwrap();
        neighd_end.send(&message).unwrap();
    }
    // Too short to be Ethernet.
    let mut runt = Vec::new();
    Punt {
        direction: Direction::FromControl,
        reason: punt::reason::ARP,
        interface: "lan",
        frame: &[1, 2, 3],
    }
    .encode(&mut runt)
    .unwrap();
    neighd_end.send(&runt).unwrap();
    // Longer than the FE accepts.
    neighd_end.send(&[1_u8; 4_000]).unwrap();
    bench.fe.step(0);
    let tx = bench.fe.io_mut().pop_tx().expect("lan only");
    assert_eq!(tx.egress, IfId(0));
    assert!(bench.fe.io_mut().pop_tx().is_none());
    assert_eq!(bench.fe.counters().inject_dropped, 5);
}

#[test]
fn the_resolve_rate_limit_forgets_old_next_hops_and_stays_bounded() {
    let mut bench = Bench::new();
    let (_config, mut routes) = configure(&mut bench);
    bench.patch(&mut routes, &[route([10, 0, 0, 0], 16, "wan", None)]);
    let destination = |n: u32| {
        let [_, _, c, d] = (u32::from_be_bytes([10, 0, 0, 0]) + n).to_be_bytes();
        [10, 0, c, d]
    };

    // Spread out: every next hop gets its request, because old ones are forgotten.
    for n in 1..=1_100_u32 {
        bench.now = u64::from(n) * 2;
        bench
            .fe
            .io_mut()
            .inject(IfId(0), udp_from_host(destination(n)));
        bench.fe.step(bench.now);
    }
    assert_eq!(bench.fe.counters().resolve_requests, 1_100);
    assert_eq!(bench.fe.counters().resolve_requests_dropped, 0);

    // All at one moment: at most 1 024 are remembered, the rest wait.
    bench.now = 1_000_000;
    for n in 10_000..11_100_u32 {
        bench
            .fe
            .io_mut()
            .inject(IfId(0), udp_from_host(destination(n)));
        bench.fe.step(bench.now);
    }
    let counters = bench.fe.counters();
    assert_eq!(counters.resolve_requests, 1_100 + 1_024);
    assert_eq!(counters.resolve_requests_dropped, 1_100 - 1_024);
}

#[test]
fn a_punt_socket_at_a_fixed_path_sends_to_whoever_binds_the_peer_path() {
    let dir = std::env::temp_dir().join(format!("ruster-fe-punt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let mut bench = Bench::new();
    let (_config, _routes) = configure(&mut bench);
    let fe_end = UnixDatagram::bind(dir.join("fe")).unwrap();
    bench.fe.attach_punt_to(fe_end, dir.join("neighd")).unwrap();

    // Nobody at the peer path yet: the ARP packet is counted as dropped.
    bench
        .fe
        .io_mut()
        .inject(IfId(0), arp_request([192, 0, 2, 1]));
    bench.fe.step(0);
    assert_eq!(bench.fe.counters().arp_to_control_dropped, 1);

    // Each neighbor process that binds the path gets the next ones.
    for round in 1..=2 {
        let _ = std::fs::remove_file(dir.join("neighd"));
        let neighd_end = UnixDatagram::bind(dir.join("neighd")).unwrap();
        bench
            .fe
            .io_mut()
            .inject(IfId(0), arp_request([192, 0, 2, 1]));
        bench.fe.step(round);
        let mut buf = [0_u8; 256];
        let n = neighd_end.recv(&mut buf).unwrap();
        assert_eq!(Punt::decode(&buf[..n]).unwrap().interface, "lan");

        let mut reply = vec![0xab_u8; 42];
        reply[12..14].copy_from_slice(&[0x08, 0x06]);
        let mut message = Vec::new();
        Punt {
            direction: Direction::FromControl,
            reason: punt::reason::ARP,
            interface: "lan",
            frame: &reply,
        }
        .encode(&mut message)
        .unwrap();
        neighd_end.send_to(&message, dir.join("fe")).unwrap();
        // The same message from anyone else is not sent.
        let stranger = UnixDatagram::unbound().unwrap();
        stranger.send_to(&message, dir.join("fe")).unwrap();
        bench.fe.step(round);
        assert_eq!(bench.fe.io_mut().pop_tx().expect("sent").bytes, reply);
    }
    assert!(bench.fe.io_mut().pop_tx().is_none());
    assert_eq!(bench.fe.counters().arp_to_control, 2);
    assert_eq!(bench.fe.counters().inject_dropped, 2);
    std::fs::remove_dir_all(dir).unwrap();
}

fn ip6(text: &str) -> std::net::IpAddr {
    text.parse().unwrap()
}

/// IPv6 tables on top of `configure`: addresses, a LAN route, a default route via a
/// link-local gateway, and the gateway's neighbor entry.
fn configure_ipv6(bench: &mut Bench, config: &mut Client, routes: &mut Client) -> Client {
    let address6 = |interface: &str, address: &str| {
        Change::set(
            Key::Address {
                interface: interface.into(),
                address: ip6(address),
            },
            Value::Address { prefix_len: 64 },
        )
    };
    let code = bench.patch(
        config,
        &[address6("lan", "2001:db8:1::1"), address6("wan", "fe80::2")],
    );
    assert_eq!(code, Code::CHANGED);
    let route6 = |prefix: &str, len: u8, interface: &str, via: Option<&str>| {
        Change::set(
            Key::Route {
                vrf: "default".into(),
                prefix: ip6(prefix),
                len,
            },
            Value::Route(RouteAction::Forward(vec![NextHop {
                interface: interface.into(),
                address: via.map(ip6),
            }])),
        )
    };
    let code = bench.patch(
        routes,
        &[
            route6("2001:db8:1::", 64, "lan", None),
            route6("::", 0, "wan", Some("fe80::1")),
        ],
    );
    assert_eq!(code, Code::CHANGED);
    bench.connect(writers::NEIGHBOR)
}

fn ipv6_frame(dst_mac: [u8; 6], destination: &str, next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&HOST_MAC);
    frame.extend_from_slice(&0x86dd_u16.to_be_bytes());
    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    frame.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&[next_header, 64]);
    frame.extend_from_slice(
        &"2001:db8:1::10"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    frame.extend_from_slice(&destination.parse::<std::net::Ipv6Addr>().unwrap().octets());
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn ipv6_is_forwarded_by_the_tables_and_a_missing_next_hop_is_asked_for() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let mut neighbors = configure_ipv6(&mut bench, &mut config, &mut routes);
    let mut observer = bench.connect(writers::READ_ONLY);
    observer.observe();
    bench.settle(&mut [&mut observer]);

    // No gateway neighbor yet: a resolve request for fe80::1 on wan.
    bench
        .fe
        .io_mut()
        .inject(IfId(0), ipv6_frame(LAN_MAC, "2001:db8:99::7", 17, &[0; 8]));
    let events = bench.settle(&mut [&mut observer]).remove(0);
    let requests: Vec<ResolveRequest> = events
        .iter()
        .filter_map(|event| match event {
            Event::Notification { payload } => {
                ResolveRequest::decode(&mut Decoder::new(payload)).ok()
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        requests,
        [ResolveRequest {
            interface: "wan".into(),
            address: ip6("fe80::1"),
        }]
    );

    let code = bench.patch(
        &mut neighbors,
        &[Change::set(
            Key::Neighbor {
                interface: "wan".into(),
                address: ip6("fe80::1"),
            },
            Value::Neighbor { mac: GATEWAY_MAC },
        )],
    );
    assert_eq!(code, Code::CHANGED);
    bench
        .fe
        .io_mut()
        .inject(IfId(0), ipv6_frame(LAN_MAC, "2001:db8:99::7", 17, &[0; 8]));
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("forwarded");
    assert_eq!(tx.egress, IfId(1));
    assert_eq!(&tx.bytes[0..6], &GATEWAY_MAC);
    assert_eq!(tx.bytes[14 + 7], 63);
}

#[test]
fn neighbor_discovery_goes_to_the_neighbor_socket_and_frames_come_back() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let _neighbors = configure_ipv6(&mut bench, &mut config, &mut routes);
    let (fe_end, neighd_end) = UnixDatagram::pair().unwrap();
    bench.fe.attach_punt(fe_end).unwrap();

    let solicitation = ipv6_frame(
        [0x33, 0x33, 0xff, 0, 0, 1],
        "ff02::1:ff00:1",
        58,
        &[135, 0, 0, 0, 0, 0, 0, 0],
    );
    bench.fe.io_mut().inject(IfId(0), solicitation.clone());
    bench.fe.step(0);
    assert!(bench.fe.io_mut().pop_tx().is_none());
    let mut buf = [0_u8; 512];
    let n = neighd_end.recv(&mut buf).unwrap();
    let punt = Punt::decode(&buf[..n]).unwrap();
    assert_eq!(punt.direction, Direction::ToControl);
    assert_eq!(punt.reason, punt::reason::ND);
    assert_eq!(punt.interface, "lan");
    assert_eq!(punt.frame, &solicitation[..], "the whole frame");

    // An advertisement back goes out; an IPv4 frame under the ND reason does not.
    let advertisement = ipv6_frame(HOST_MAC, "2001:db8:1::10", 58, &[136, 0, 0, 0]);
    for (frame, sent) in [
        (advertisement.clone(), true),
        (udp_from_host(GATEWAY), false),
    ] {
        let mut message = Vec::new();
        Punt {
            direction: Direction::FromControl,
            reason: punt::reason::ND,
            interface: "lan",
            frame: &frame,
        }
        .encode(&mut message)
        .unwrap();
        neighd_end.send(&message).unwrap();
        bench.fe.step(1);
        assert_eq!(bench.fe.io_mut().pop_tx().is_some(), sent);
    }
}

#[test]
fn an_expiring_packet_gets_an_icmp_time_exceeded_back() {
    let mut bench = Bench::new();
    let (_config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    let code = bench.patch(
        &mut neighbors,
        &[
            neighbor("lan", [192, 0, 2, 10], HOST_MAC),
            neighbor("wan", GATEWAY, GATEWAY_MAC),
        ],
    );
    assert_eq!(code, Code::CHANGED);
    let mut expiring = udp_from_host([203, 0, 113, 7]);
    expiring[14 + 8] = 1;
    expiring[14 + 10..14 + 12].copy_from_slice(&[0, 0]);
    let checksum = ipv4_header_checksum(&expiring[14..34]);
    expiring[14 + 10..14 + 12].copy_from_slice(&checksum.to_be_bytes());
    bench.fe.io_mut().inject(IfId(0), expiring);
    bench.fe.step(0);
    let tx = bench.fe.io_mut().pop_tx().expect("an error goes back");
    assert_eq!(tx.egress, IfId(0));
    assert_eq!(&tx.bytes[0..6], &HOST_MAC);
    assert_eq!(
        &tx.bytes[14 + 12..14 + 16],
        &[192, 0, 2, 1],
        "from the LAN address"
    );
    assert_eq!(&tx.bytes[14 + 16..14 + 20], &[192, 0, 2, 10]);
    assert_eq!(tx.bytes[14 + 9], 1, "ICMP");
    assert_eq!(tx.bytes[34], 11, "Time Exceeded");
    assert!(bench.fe.io_mut().pop_tx().is_none());
    assert_eq!(bench.fe.counters().icmp_errors_sent, 1);
}

#[test]
fn an_expiring_ipv6_packet_gets_an_icmpv6_time_exceeded_back() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let mut neighbors = configure_ipv6(&mut bench, &mut config, &mut routes);
    let code = bench.patch(
        &mut neighbors,
        &[Change::set(
            Key::Neighbor {
                interface: "lan".into(),
                address: ip6("2001:db8:1::10"),
            },
            Value::Neighbor { mac: HOST_MAC },
        )],
    );
    assert_eq!(code, Code::CHANGED);
    let mut expiring = ipv6_frame(LAN_MAC, "2001:db8:99::7", 17, &[0; 8]);
    expiring[14 + 7] = 1;
    bench.fe.io_mut().inject(IfId(0), expiring);
    bench.fe.step(0);
    let tx = bench.fe.io_mut().pop_tx().expect("an error goes back");
    assert_eq!(tx.egress, IfId(0));
    assert_eq!(&tx.bytes[0..6], &HOST_MAC);
    assert_eq!(tx.bytes[54], 3, "Time Exceeded");
    assert_eq!(bench.fe.counters().icmp_errors_sent, 1);
}

#[test]
fn an_interface_in_another_vrf_uses_that_vrf_s_routes_and_a_lookup_reaches_default() {
    let mut bench = Bench::new();
    let mut config = bench.connect(writers::CONFIG);
    let red_lan = Change::set(
        Key::Interface { name: "lan".into() },
        Value::Interface {
            enabled: true,
            mac: LAN_MAC,
            mtu: 1500,
            vrf: "red".into(),
            vlan: None,
            tunnel: None,
            pppoe: None,
        },
    );
    let code = bench.patch(
        &mut config,
        &[
            red_lan,
            iface("wan", WAN_MAC),
            address("lan", [192, 0, 2, 1], 24),
            address("wan", [198, 51, 100, 2], 24),
        ],
    );
    assert_eq!(code, Code::CHANGED);
    let mut routes = bench.connect(writers::ROUTE);
    let in_vrf = |vrf: &str, prefix: [u8; 4], len: u8, action: RouteAction| {
        Change::set(
            Key::Route {
                vrf: vrf.into(),
                prefix: Ipv4Addr::from(prefix).into(),
                len,
            },
            Value::Route(action),
        )
    };
    let via_gateway = RouteAction::Forward(vec![NextHop {
        interface: "wan".into(),
        address: Some(Ipv4Addr::from(GATEWAY).into()),
    }]);
    let code = bench.patch(
        &mut routes,
        &[
            // The internet is in the default VRF only; red looks it up there.
            in_vrf("default", [0, 0, 0, 0], 0, via_gateway),
            in_vrf(
                "red",
                [0, 0, 0, 0],
                0,
                RouteAction::LookupVrf("default".into()),
            ),
        ],
    );
    assert_eq!(code, Code::CHANGED);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    let code = bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]);
    assert_eq!(code, Code::CHANGED);

    bench
        .fe
        .io_mut()
        .inject(IfId(0), udp_from_host([203, 0, 113, 7]));
    bench.fe.step(0);
    let tx = bench
        .fe
        .io_mut()
        .pop_tx()
        .expect("red reaches the internet");
    assert_eq!(tx.egress, IfId(1));
    assert_eq!(&tx.bytes[0..6], &GATEWAY_MAC);

    // Without the lookup, red has no route.
    let code = bench.patch(
        &mut routes,
        &[Change::delete(Key::Route {
            vrf: "red".into(),
            prefix: Ipv4Addr::UNSPECIFIED.into(),
            len: 0,
        })],
    );
    assert_eq!(code, Code::CHANGED);
    bench
        .fe
        .io_mut()
        .inject(IfId(0), udp_from_host([203, 0, 113, 7]));
    bench.fe.step(1);
    assert!(bench.fe.io_mut().pop_tx().is_none());
}

#[test]
fn traffic_to_the_router_goes_to_the_kernel_pipe_and_the_kernel_s_packets_go_out() {
    let mut bench = Bench::new();
    let (_config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    let code = bench.patch(
        &mut neighbors,
        &[neighbor("lan", [192, 0, 2, 10], HOST_MAC)],
    );
    assert_eq!(code, Code::CHANGED);
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));

    // A packet to the router's LAN address goes to the kernel without Ethernet.
    let mut to_router = udp_from_host([192, 0, 2, 1]);
    to_router[14 + 10..14 + 12].copy_from_slice(&[0, 0]);
    let checksum = ipv4_header_checksum(&to_router[14..34]);
    to_router[14 + 10..14 + 12].copy_from_slice(&checksum.to_be_bytes());
    bench.fe.io_mut().inject(IfId(0), to_router.clone());
    bench.fe.step(0);
    assert!(bench.fe.io_mut().pop_tx().is_none(), "core does not answer");
    let mut buf = [0_u8; 2048];
    let n = kernel.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], &to_router[14..]);
    assert_eq!(bench.fe.counters().to_kernel, 1);

    // The kernel's answer goes out of the route's interface to the neighbor.
    let mut reply = to_router[14..].to_vec();
    reply[12..16].copy_from_slice(&[192, 0, 2, 1]);
    reply[16..20].copy_from_slice(&[192, 0, 2, 10]);
    kernel.send(&reply).unwrap();
    bench.fe.step(1);
    let tx = bench.fe.io_mut().pop_tx().expect("sent out");
    assert_eq!(tx.egress, IfId(0));
    assert_eq!(&tx.bytes[0..6], &HOST_MAC);
    assert_eq!(&tx.bytes[6..12], &LAN_MAC);
    assert_eq!(&tx.bytes[12..14], &[0x08, 0x00]);
    assert_eq!(&tx.bytes[14..], &reply[..]);

    // To a host without a neighbor entry: dropped, and the neighbor is asked for.
    let mut observer = bench.connect(writers::READ_ONLY);
    observer.observe();
    bench.settle(&mut [&mut observer]);
    reply[16..20].copy_from_slice(&[192, 0, 2, 99]);
    reply[10..12].copy_from_slice(&[0, 0]);
    let checksum = ipv4_header_checksum(&reply[..20]);
    reply[10..12].copy_from_slice(&checksum.to_be_bytes());
    kernel.send(&reply).unwrap();
    let events = bench.settle(&mut [&mut observer]).remove(0);
    assert!(bench.fe.io_mut().pop_tx().is_none());
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::Notification { .. })));
    assert_eq!(bench.fe.counters().from_kernel, 1);
    assert_eq!(bench.fe.counters().from_kernel_dropped, 1);
}

fn accept_udp_from_lan(id: u32) -> Change {
    Change::set(
        Key::FirewallRule {
            vrf: "default".into(),
            id,
        },
        Value::FirewallRule(ruster_proto::table::FirewallRule {
            ingress: Some("lan".into()),
            egress: None,
            source: (Ipv4Addr::UNSPECIFIED.into(), 0),
            destination: (Ipv4Addr::UNSPECIFIED.into(), 0),
            protocol: ruster_proto::table::Protocol::Udp,
            source_ports: (0, 65_535),
            destination_ports: (0, 65_535),
            action: ruster_proto::table::FirewallAction::Accept,
        }),
    )
}

/// A UDP frame from the internet host to the LAN host, as the reply to
/// `udp_from_host`.
fn udp_reply_to_host() -> Vec<u8> {
    let mut frame = udp_from_host([192, 0, 2, 10]);
    frame[0..6].copy_from_slice(&WAN_MAC);
    frame[6..12].copy_from_slice(&GATEWAY_MAC);
    let ip = 14;
    frame[ip + 12..ip + 16].copy_from_slice(&INTERNET);
    frame[ip + 10..ip + 12].fill(0);
    let checksum = ipv4_header_checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
    frame[ip + 20..ip + 22].copy_from_slice(&2000_u16.to_be_bytes());
    frame[ip + 22..ip + 24].copy_from_slice(&1000_u16.to_be_bytes());
    frame
}

#[test]
fn firewall_rules_let_the_lan_out_and_only_replies_in_across_table_changes() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    bench.patch(
        &mut neighbors,
        &[
            neighbor("wan", GATEWAY, GATEWAY_MAC),
            neighbor("lan", [192, 0, 2, 10], HOST_MAC),
        ],
    );
    assert_eq!(
        bench.patch(&mut config, &[accept_udp_from_lan(10)]),
        Code::CHANGED
    );

    let send = |bench: &mut Bench, ingress: u16, frame: Vec<u8>| {
        bench.now += 10;
        bench.fe.io_mut().inject(IfId(ingress), frame);
        bench.fe.step(bench.now);
        bench.fe.io_mut().pop_tx().map(|tx| tx.egress)
    };
    assert_eq!(
        send(&mut bench, 1, udp_reply_to_host()),
        None,
        "unsolicited"
    );
    assert_eq!(send(&mut bench, 0, udp_from_host(INTERNET)), Some(IfId(1)));
    assert_eq!(send(&mut bench, 1, udp_reply_to_host()), Some(IfId(0)));

    // Another route: the flow is carried to the new tables.
    let code = bench.patch(
        &mut routes,
        &[route([10, 0, 0, 0], 8, "wan", Some(GATEWAY))],
    );
    assert_eq!(code, Code::CHANGED);
    assert_eq!(send(&mut bench, 1, udp_reply_to_host()), Some(IfId(0)));

    // No rules: no firewall.
    let code = bench.patch(
        &mut config,
        &[Change::delete(Key::FirewallRule {
            vrf: "default".into(),
            id: 10,
        })],
    );
    assert_eq!(code, Code::CHANGED);
    let mut other = udp_reply_to_host();
    other[14 + 20..14 + 22].copy_from_slice(&3000_u16.to_be_bytes());
    assert_eq!(send(&mut bench, 1, other), Some(IfId(0)));
}

#[test]
fn a_firewall_rule_outside_the_default_vrf_is_refused() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut change = accept_udp_from_lan(1);
    change.key = Key::FirewallRule {
        vrf: "red".into(),
        id: 1,
    };
    assert_eq!(bench.patch(&mut config, &[change]), Code::BAD_REQUEST);
}

#[test]
fn a_firewall_whose_rules_all_name_a_disabled_interface_drops_everything() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]);
    let mut dmz_off = iface("dmz", [2, 0, 0, 0, 0, 3]);
    if let Some(Value::Interface { enabled, .. }) = &mut dmz_off.value {
        *enabled = false;
    }
    let mut rule = accept_udp_from_lan(1);
    if let Some(Value::FirewallRule(rule)) = &mut rule.value {
        rule.ingress = Some("dmz".into());
    }
    assert_eq!(bench.patch(&mut config, &[dmz_off, rule]), Code::CHANGED);
    bench.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    bench.fe.step(bench.now);
    assert!(bench.fe.io_mut().pop_tx().is_none());
}

#[test]
fn ipv6_is_not_forwarded_while_the_firewall_is_on() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let mut neighbors = configure_ipv6(&mut bench, &mut config, &mut routes);
    let gateway = Change::set(
        Key::Neighbor {
            interface: "wan".into(),
            address: ip6("fe80::1"),
        },
        Value::Neighbor { mac: GATEWAY_MAC },
    );
    assert_eq!(bench.patch(&mut neighbors, &[gateway]), Code::CHANGED);
    let send = |bench: &mut Bench| {
        bench
            .fe
            .io_mut()
            .inject(IfId(0), ipv6_frame(LAN_MAC, "2001:db8:99::7", 17, &[0; 8]));
        bench.fe.step(bench.now);
        bench.fe.io_mut().pop_tx().is_some()
    };
    assert!(send(&mut bench));
    assert_eq!(
        bench.patch(&mut config, &[accept_udp_from_lan(1)]),
        Code::CHANGED
    );
    assert!(!send(&mut bench));
}

fn nat(first_port: u16, last_port: u16) -> Change {
    Change::set(
        Key::Nat {
            vrf: "default".into(),
        },
        Value::Nat(ruster_proto::table::Nat {
            inside: "lan".into(),
            outside: "wan".into(),
            external: None,
            ports: ruster_proto::table::NatPorts::Range {
                first: first_port,
                last: last_port,
            },
        }),
    )
}

#[test]
fn nat_translates_out_and_back_across_table_changes() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    bench.patch(
        &mut neighbors,
        &[
            neighbor("wan", GATEWAY, GATEWAY_MAC),
            neighbor("lan", [192, 0, 2, 10], HOST_MAC),
        ],
    );
    assert_eq!(
        bench.patch(&mut config, &[nat(40_000, 40_009)]),
        Code::CHANGED
    );

    let send = |bench: &mut Bench, ingress: u16, frame: Vec<u8>| {
        bench.now += 10;
        bench.fe.io_mut().inject(IfId(ingress), frame);
        bench.fe.step(bench.now);
        bench.fe.io_mut().pop_tx()
    };
    let out = send(&mut bench, 0, udp_from_host(INTERNET)).expect("translated");
    assert_eq!(out.egress, IfId(1));
    assert_eq!(&out.bytes[26..30], &[198, 51, 100, 2], "the WAN address");
    let port = u16::from_be_bytes([out.bytes[34], out.bytes[35]]);
    assert!((40_000..=40_009).contains(&port), "{port}");

    let reply = |port: u16| {
        let mut frame = udp_reply_to_host();
        frame[30..34].copy_from_slice(&[198, 51, 100, 2]);
        frame[24..26].fill(0);
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        frame[36..38].copy_from_slice(&port.to_be_bytes());
        frame
    };
    let back = send(&mut bench, 1, reply(port)).expect("translated back");
    assert_eq!(back.egress, IfId(0));
    assert_eq!(&back.bytes[30..34], &[192, 0, 2, 10]);
    assert_eq!(u16::from_be_bytes([back.bytes[36], back.bytes[37]]), 1000);

    // Another route: the mapping is carried to the new tables.
    let code = bench.patch(
        &mut routes,
        &[route([10, 0, 0, 0], 8, "wan", Some(GATEWAY))],
    );
    assert_eq!(code, Code::CHANGED);
    assert!(send(&mut bench, 1, reply(port)).is_some());

    // A port range of another size: new storage, the mapping is gone.
    assert_eq!(
        bench.patch(&mut config, &[nat(40_000, 40_019)]),
        Code::CHANGED
    );
    assert!(send(&mut bench, 1, reply(port)).is_none());

    // No NAT: the LAN address leaves as it is.
    let code = bench.patch(
        &mut config,
        &[Change::delete(Key::Nat {
            vrf: "default".into(),
        })],
    );
    assert_eq!(code, Code::CHANGED);
    let out = send(&mut bench, 0, udp_from_host(INTERNET)).expect("forwarded");
    assert_eq!(&out.bytes[26..30], &[192, 0, 2, 10]);
}

#[test]
fn a_nat_address_other_than_the_outside_interface_s_is_refused() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    // An external address that is not the outside interface's.
    let mut other = nat(1_000, 2_000);
    if let Some(Value::Nat(nat)) = &mut other.value {
        nat.external = Some(Ipv4Addr::new(203, 0, 113, 99));
    }
    assert_eq!(bench.patch(&mut config, &[other]), Code::BAD_REQUEST);
}

#[test]
fn with_nat_the_router_s_own_ports_on_the_wan_address_still_reach_the_kernel() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    kernel.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));
    assert_eq!(
        bench.patch(&mut config, &[nat(40_000, 40_009)]),
        Code::CHANGED
    );
    let to_wan = |port: u16| {
        let mut frame = udp_reply_to_host();
        frame[30..34].copy_from_slice(&[198, 51, 100, 2]);
        frame[24..26].fill(0);
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        frame[36..38].copy_from_slice(&port.to_be_bytes());
        frame
    };
    let mut buf = [0_u8; 2048];
    // Outside the pool: the router's own.
    bench.fe.io_mut().inject(IfId(1), to_wan(53));
    bench.fe.step(bench.now);
    assert!(kernel.recv(&mut buf).is_ok());
    // In the pool, with no mapping: NAT drops it.
    bench.fe.io_mut().inject(IfId(1), to_wan(40_003));
    bench.fe.step(bench.now);
    assert!(kernel.recv(&mut buf).is_err());
    assert!(bench.fe.io_mut().pop_tx().is_none());

    // An ICMP Fragmentation Needed about the router's own UDP from port 53 is the
    // router's too; one about a pool port is NAT's (and has no mapping).
    let frag_needed = |port: u16| {
        let mut quoted = to_wan(2000)[14..42].to_vec();
        quoted[12..16].copy_from_slice(&[198, 51, 100, 2]);
        quoted[16..20].copy_from_slice(&INTERNET);
        quoted[20..22].copy_from_slice(&port.to_be_bytes());
        let mut frame = to_wan(0)[..34].to_vec();
        frame[14 + 9] = 1;
        frame[16..18].copy_from_slice(&(20 + 8 + 28_u16).to_be_bytes());
        frame.extend_from_slice(&[3, 4, 0, 0, 0, 0, 0x05, 0x00]);
        frame.extend_from_slice(&quoted);
        let icmp_checksum = ipv4_header_checksum(&frame[34..]);
        frame[36..38].copy_from_slice(&icmp_checksum.to_be_bytes());
        frame[24..26].fill(0);
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        frame
    };
    bench.fe.io_mut().inject(IfId(1), frag_needed(53));
    bench.fe.step(bench.now);
    assert!(kernel.recv(&mut buf).is_ok(), "the router's own");
    bench.fe.io_mut().inject(IfId(1), frag_needed(40_003));
    bench.fe.step(bench.now);
    assert!(kernel.recv(&mut buf).is_err(), "NAT's");
}

/// A UDP datagram from the LAN host to `INTERNET` with `payload` bytes, with or
/// without Don't Fragment.
fn udp_datagram(payload: usize, df: bool) -> Vec<u8> {
    let mut frame = udp_from_host(INTERNET);
    frame.truncate(42);
    frame.resize(42 + payload, 0xab);
    let total = u16::try_from(28 + payload).unwrap();
    frame[16..18].copy_from_slice(&total.to_be_bytes());
    frame[20..22].copy_from_slice(&(if df { 0x4000_u16 } else { 0 }).to_be_bytes());
    frame[38..40].copy_from_slice(&u16::try_from(8 + payload).unwrap().to_be_bytes());
    frame[40..42].fill(0);
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

/// The IPv4 fragment of `datagram` holding its IP payload bytes `start..end`.
fn fragment_of(datagram: &[u8], start: usize, end: usize, more: bool) -> Vec<u8> {
    let mut frame = datagram[..34].to_vec();
    frame.extend_from_slice(&datagram[34 + start..34 + end]);
    frame[16..18].copy_from_slice(&u16::try_from(20 + end - start).unwrap().to_be_bytes());
    let flags = u16::try_from(start / 8).unwrap() | if more { 0x2000 } else { 0 };
    frame[20..22].copy_from_slice(&flags.to_be_bytes());
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

#[test]
fn a_datagram_longer_than_the_egress_mtu_is_fragmented() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]);
    let mut wan = iface("wan", WAN_MAC);
    if let Some(Value::Interface { mtu, .. }) = &mut wan.value {
        *mtu = 1_000;
    }
    assert_eq!(bench.patch(&mut config, &[wan]), Code::CHANGED);

    bench
        .fe
        .io_mut()
        .inject(IfId(0), udp_datagram(1_400, false));
    bench.fe.step(bench.now);
    let mut sent = Vec::new();
    while let Some(tx) = bench.fe.io_mut().pop_tx() {
        assert_eq!(tx.egress, IfId(1));
        assert!(tx.bytes.len() - 14 <= 1_000);
        sent.push(u16::from_be_bytes([tx.bytes[20], tx.bytes[21]]));
    }
    assert_eq!(sent.len(), 2, "{sent:x?}");
    assert_eq!(sent[0] & 0x2000, 0x2000, "more fragments");
    assert_eq!(sent[1] & 0x2000, 0);
    assert_eq!(bench.fe.counters().fragments_sent, 2);

    // Don't Fragment: nothing goes out on the WAN.
    bench.fe.io_mut().inject(IfId(0), udp_datagram(1_400, true));
    bench.fe.step(bench.now);
    while let Some(tx) = bench.fe.io_mut().pop_tx() {
        assert_eq!(tx.egress, IfId(0), "only an error back to the host");
    }
}

#[test]
fn nat_translates_every_fragment_of_a_datagram() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]);
    assert_eq!(
        bench.patch(&mut config, &[nat(40_000, 40_009)]),
        Code::CHANGED
    );

    let datagram = udp_datagram(64, false);
    for frame in [
        fragment_of(&datagram, 0, 40, true),
        fragment_of(&datagram, 40, 72, false),
    ] {
        bench.fe.io_mut().inject(IfId(0), frame);
    }
    bench.fe.step(bench.now);
    let mut sent = 0;
    while let Some(tx) = bench.fe.io_mut().pop_tx() {
        assert_eq!(tx.egress, IfId(1));
        assert_eq!(&tx.bytes[26..30], &[198, 51, 100, 2], "translated");
        sent += 1;
    }
    assert_eq!(sent, 2);
}

#[test]
fn a_table_change_between_fragments_drops_the_later_ones() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]);
    assert_eq!(
        bench.patch(&mut config, &[nat(40_000, 40_009)]),
        Code::CHANGED
    );
    let datagram = udp_datagram(64, false);
    bench
        .fe
        .io_mut()
        .inject(IfId(0), fragment_of(&datagram, 0, 40, true));
    bench.fe.step(bench.now);
    assert!(bench.fe.io_mut().pop_tx().is_some(), "the first fragment");
    let code = bench.patch(
        &mut routes,
        &[route([10, 0, 0, 0], 8, "wan", Some(GATEWAY))],
    );
    assert_eq!(code, Code::CHANGED);
    bench
        .fe
        .io_mut()
        .inject(IfId(0), fragment_of(&datagram, 40, 72, false));
    bench.fe.step(bench.now);
    assert!(bench.fe.io_mut().pop_tx().is_none(), "no stale rewrite");
}

#[test]
fn a_route_to_a_tunnel_interface_sends_ipv4_inside_ipv6() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let mut neighbors = configure_ipv6(&mut bench, &mut config, &mut routes);
    let gateway = Change::set(
        Key::Neighbor {
            interface: "wan".into(),
            address: ip6("fe80::1"),
        },
        Value::Neighbor { mac: GATEWAY_MAC },
    );
    assert_eq!(bench.patch(&mut neighbors, &[gateway]), Code::CHANGED);
    let tunnel = Change::set(
        Key::Interface {
            name: "dslite".into(),
        },
        Value::Interface {
            enabled: true,
            mac: [2, 0, 0, 0, 0, 9],
            mtu: 1460,
            vrf: ruster_proto::table::DEFAULT_VRF.into(),
            vlan: None,
            tunnel: Some(ruster_proto::table::Tunnel {
                local: "2001:db8:1::1".parse().unwrap(),
                remote: "2001:db8:ff::1".parse().unwrap(),
            }),
            pppoe: None,
        },
    );
    assert_eq!(bench.patch(&mut config, &[tunnel]), Code::CHANGED);
    let to_tunnel = Change::set(
        Key::Route {
            vrf: "default".into(),
            prefix: Ipv4Addr::from(INTERNET).into(),
            len: 32,
        },
        Value::Route(RouteAction::Forward(vec![NextHop {
            interface: "dslite".into(),
            address: None,
        }])),
    );
    assert_eq!(bench.patch(&mut routes, &[to_tunnel]), Code::CHANGED);

    bench.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("sent");
    assert_eq!(tx.egress, IfId(1));
    assert_eq!(&tx.bytes[12..14], &[0x86, 0xdd]);
    assert_eq!(tx.bytes[14 + 6], 4, "IPv4 in IPv6");
    assert_eq!(&tx.bytes[14 + 40 + 16..14 + 40 + 20], &INTERNET);

    // The router's own IPv4 (from the kernel) to the tunnel leaves the same way.
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));
    let mut own = udp_from_host(INTERNET)[14..].to_vec();
    own[12..16].copy_from_slice(&[192, 0, 2, 1]);
    own[10..12].fill(0);
    let checksum = ipv4_header_checksum(&own[..20]);
    own[10..12].copy_from_slice(&checksum.to_be_bytes());
    kernel.send(&own).unwrap();
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("sent from the kernel");
    assert_eq!(tx.egress, IfId(1));
    assert_eq!(&tx.bytes[0..6], &GATEWAY_MAC);
    assert_eq!(&tx.bytes[12..14], &[0x86, 0xdd]);
    assert_eq!(tx.bytes[14 + 6], 4);
    assert_eq!(&tx.bytes[14 + 40..], &own[..]);

    // Too big for the tunnel with DF set: not sent, and the kernel is told the
    // tunnel's MTU.
    kernel.set_nonblocking(true).unwrap();
    let mut big = own.clone();
    big.resize(1500, 0);
    big[2..4].copy_from_slice(&1500_u16.to_be_bytes());
    big[6] = 0x40;
    big[10..12].fill(0);
    let checksum = ipv4_header_checksum(&big[..20]);
    big[10..12].copy_from_slice(&checksum.to_be_bytes());
    kernel.send(&big).unwrap();
    bench.fe.step(bench.now);
    assert!(bench.fe.io_mut().pop_tx().is_none());
    let mut buf = [0_u8; 2048];
    let n = kernel.recv(&mut buf).expect("an ICMP error back");
    let icmp = &buf[..n];
    assert_eq!(
        (icmp[9], icmp[20], icmp[21]),
        (1, 3, 4),
        "Fragmentation Needed"
    );
    assert_eq!(u16::from_be_bytes([icmp[26], icmp[27]]), 1460);
    assert_eq!(&icmp[28..48], &big[..20], "the quoted header");
}

#[test]
fn nat_with_a_psid_port_set_uses_its_ports() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]);
    let mut change = nat(1, 1);
    if let Some(Value::Nat(nat)) = &mut change.value {
        nat.ports = ruster_proto::table::NatPorts::Psid {
            offset: 6,
            length: 6,
            psid: 0x34,
        };
    }
    assert_eq!(bench.patch(&mut config, &[change]), Code::CHANGED);
    bench.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    bench.fe.step(bench.now);
    let out = bench.fe.io_mut().pop_tx().expect("translated");
    let port = u16::from_be_bytes([out.bytes[34], out.bytes[35]]);
    assert_eq!((port >> 4) & 0x3f, 0x34, "the PSID bits of {port}");
    assert!(port >> 10 != 0, "not a well-known port");
}

#[test]
fn a_route_to_a_pppoe_interface_sends_in_its_session() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let ppp = Change::set(
        Key::Interface { name: "ppp".into() },
        Value::Interface {
            enabled: true,
            mac: [2, 0, 0, 0, 0, 8],
            mtu: 1492,
            vrf: ruster_proto::table::DEFAULT_VRF.into(),
            vlan: None,
            tunnel: None,
            pppoe: Some(ruster_proto::table::Pppoe {
                parent: "wan".into(),
                session: 0x1234,
                peer: GATEWAY_MAC,
            }),
        },
    );
    assert_eq!(bench.patch(&mut config, &[ppp]), Code::CHANGED);
    let to_ppp = Change::set(
        Key::Route {
            vrf: "default".into(),
            prefix: Ipv4Addr::from(INTERNET).into(),
            len: 32,
        },
        Value::Route(RouteAction::Forward(vec![NextHop {
            interface: "ppp".into(),
            address: None,
        }])),
    );
    assert_eq!(bench.patch(&mut routes, &[to_ppp]), Code::CHANGED);
    bench.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("sent");
    assert_eq!(tx.egress, IfId(1));
    assert_eq!(&tx.bytes[0..6], &GATEWAY_MAC);
    assert_eq!(&tx.bytes[12..14], &[0x88, 0x64]);
    assert_eq!(u16::from_be_bytes([tx.bytes[16], tx.bytes[17]]), 0x1234);

    // The router's own IPv4 goes the same way.
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));
    let mut own = udp_from_host(INTERNET)[14..].to_vec();
    own[12..16].copy_from_slice(&[192, 0, 2, 1]);
    own[10..12].fill(0);
    let checksum = ipv4_header_checksum(&own[..20]);
    own[10..12].copy_from_slice(&checksum.to_be_bytes());
    kernel.send(&own).unwrap();
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("sent from the kernel");
    assert_eq!(tx.egress, IfId(1));
    assert_eq!(&tx.bytes[12..14], &[0x88, 0x64]);
    assert_eq!(&tx.bytes[20..22], &[0x00, 0x21]);
    assert_eq!(&tx.bytes[22..], &own[..]);

    // Too big for the session with DF set: the kernel is told its MTU.
    kernel.set_nonblocking(true).unwrap();
    let mut big = own.clone();
    big.resize(1500, 0);
    big[2..4].copy_from_slice(&1500_u16.to_be_bytes());
    big[6] = 0x40;
    big[10..12].fill(0);
    let checksum = ipv4_header_checksum(&big[..20]);
    big[10..12].copy_from_slice(&checksum.to_be_bytes());
    kernel.send(&big).unwrap();
    bench.fe.step(bench.now);
    assert!(bench.fe.io_mut().pop_tx().is_none());
    let mut buf = [0_u8; 2048];
    let n = kernel.recv(&mut buf).expect("an ICMP error back");
    assert_eq!((buf[20], buf[21]), (3, 4));
    assert_eq!(u16::from_be_bytes([buf[26], buf[27]]), 1492);
    let _ = n;
}

mod wireguard {
    use super::*;
    use ruster_core::wireguard::{
        decapsulate, encapsulate, AllowedPrefix, InterfaceConfig, PeerConfig, PeerState, Received,
        SessionKeys,
    };
    use ruster_proto::table::{Wireguard, WireguardPeer, WireguardSession};

    const ENDPOINT: [u8; 4] = [203, 0, 113, 9];
    const ROUTER: [u8; 4] = [198, 51, 100, 2];

    fn session() -> Change {
        Change::set(
            Key::WireguardSession {
                interface: "wg0".into(),
                peer: "branch".into(),
            },
            Value::WireguardSession(WireguardSession {
                send: [1; 32],
                receive: [2; 32],
                peer_index: 22,
                local_index: 11,
            }),
        )
    }

    /// The router with a WireGuard interface `wg0` to a peer behind 10.9.0.0/16.
    fn setup(bench: &mut Bench, with_session: bool) {
        let (mut config, mut routes) = configure(bench);
        let mut neighbors = bench.connect(writers::NEIGHBOR);
        assert_eq!(
            bench.patch(
                &mut neighbors,
                &[
                    neighbor("wan", GATEWAY, GATEWAY_MAC),
                    neighbor("lan", [192, 0, 2, 10], HOST_MAC),
                ],
            ),
            Code::CHANGED
        );
        let mut changes = vec![
            Change::set(
                Key::Interface { name: "wg0".into() },
                Value::Interface {
                    enabled: true,
                    mac: [2, 0, 0, 0, 0, 9],
                    mtu: 1420,
                    vrf: ruster_proto::table::DEFAULT_VRF.into(),
                    vlan: None,
                    tunnel: None,
                    pppoe: None,
                },
            ),
            Change::set(
                Key::Wireguard {
                    interface: "wg0".into(),
                },
                Value::Wireguard(Wireguard {
                    listen_port: 51820,
                    local: Ipv4Addr::from(ROUTER),
                }),
            ),
            Change::set(
                Key::WireguardPeer {
                    interface: "wg0".into(),
                    peer: "branch".into(),
                },
                Value::WireguardPeer(WireguardPeer {
                    endpoint: Ipv4Addr::from(ENDPOINT),
                    port: 51821,
                    allowed: vec![(Ipv4Addr::new(10, 9, 0, 0), 16)],
                }),
            ),
        ];
        if with_session {
            changes.push(session());
        }
        assert_eq!(bench.patch(&mut config, &changes), Code::CHANGED);
        assert_eq!(
            bench.patch(&mut routes, &[route([10, 9, 0, 0], 16, "wg0", None)]),
            Code::CHANGED
        );
    }

    /// The peer's end of the session, as the daemon on the other router has it.
    struct Remote {
        allowed: Vec<AllowedPrefix>,
        state: Vec<PeerState>,
    }

    impl Remote {
        fn new() -> Self {
            let mut state = vec![PeerState::default()];
            state[0].set_keys(SessionKeys {
                send: [2; 32],
                receive: [1; 32],
                peer_index: 11,
                local_index: 22,
            });
            Self {
                allowed: vec![AllowedPrefix {
                    address: [192, 0, 2, 0],
                    len: 24,
                }],
                state,
            }
        }
    }

    fn remote_config<'a>(peers: &'a [PeerConfig<'a>]) -> InterfaceConfig<'a> {
        InterfaceConfig {
            local: ENDPOINT,
            listen_port: 51821,
            peers,
        }
    }

    fn peer_of(allowed: &[AllowedPrefix]) -> [PeerConfig<'_>; 1] {
        [PeerConfig {
            endpoint: ROUTER,
            endpoint_port: 51820,
            allowed,
        }]
    }

    fn inner(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0_u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40_u16.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&source);
        p[16..20].copy_from_slice(&destination);
        let checksum = ipv4_header_checksum(&p[..20]);
        p[10..12].copy_from_slice(&checksum.to_be_bytes());
        p
    }

    #[test]
    fn a_route_to_a_wireguard_interface_sends_sealed_to_the_peer() {
        let mut bench = Bench::new();
        setup(&mut bench, true);
        bench
            .fe
            .io_mut()
            .inject(IfId(0), udp_from_host([10, 9, 0, 5]));
        bench.fe.step(bench.now);
        let tx = bench.fe.io_mut().pop_tx().expect("sent");
        assert_eq!(tx.egress, IfId(1));
        assert_eq!(&tx.bytes[0..6], &GATEWAY_MAC);
        assert_eq!(&tx.bytes[6..12], &WAN_MAC);
        assert_eq!(&tx.bytes[26..30], &ROUTER);
        assert_eq!(&tx.bytes[30..34], &ENDPOINT);
        assert_eq!(&tx.bytes[34..36], &51820_u16.to_be_bytes());
        assert_eq!(&tx.bytes[36..38], &51821_u16.to_be_bytes());
        assert_eq!(bench.fe.counters().wireguard_sent, 1);

        let mut remote = Remote::new();
        let peers = peer_of(&remote.allowed);
        let config = remote_config(&peers);
        let mut wire = tx.bytes[14..].to_vec();
        let got = decapsulate(&config, &mut remote.state, &mut wire).unwrap();
        let Received::Data { inner, .. } = got else {
            panic!("{got:?}")
        };
        assert_eq!(&wire[inner.start + 16..inner.start + 20], &[10, 9, 0, 5]);
        assert_eq!(wire[inner.start + 8], 63, "one hop on");
    }

    #[test]
    fn a_sealed_packet_from_the_peer_is_opened_and_forwarded() {
        let mut bench = Bench::new();
        setup(&mut bench, true);
        let mut remote = Remote::new();
        let peers = peer_of(&remote.allowed);
        let config = remote_config(&peers);
        let mut out = vec![0_u8; 14 + 28 + 16 + 64 + 16];
        let packet = inner([10, 9, 0, 7], [192, 0, 2, 10]);
        let (_, len) = encapsulate(&config, &mut remote.state, &packet, &mut out[14..]).unwrap();
        out.truncate(14 + len);
        out[0..6].copy_from_slice(&WAN_MAC);
        out[6..12].copy_from_slice(&GATEWAY_MAC);
        out[12..14].copy_from_slice(&[0x08, 0x00]);
        bench.fe.io_mut().inject(IfId(1), out);
        bench.fe.step(bench.now);
        let tx = bench.fe.io_mut().pop_tx().expect("forwarded");
        assert_eq!(tx.egress, IfId(0));
        assert_eq!(&tx.bytes[0..6], &HOST_MAC);
        assert_eq!(&tx.bytes[26..30], &[10, 9, 0, 7]);
        assert_eq!(tx.bytes[22], 63);
        assert_eq!(tx.bytes.len(), 14 + 40);
    }

    #[test]
    fn without_a_session_nothing_is_sent_and_a_later_session_starts_it() {
        let mut bench = Bench::new();
        setup(&mut bench, false);
        bench
            .fe
            .io_mut()
            .inject(IfId(0), udp_from_host([10, 9, 0, 5]));
        bench.fe.step(bench.now);
        assert!(bench.fe.io_mut().pop_tx().is_none());
        assert_eq!(bench.fe.counters().wireguard_sent, 0);

        let mut config = bench.connect(writers::CONFIG);
        assert_eq!(bench.patch(&mut config, &[session()]), Code::CHANGED);
        bench
            .fe
            .io_mut()
            .inject(IfId(0), udp_from_host([10, 9, 0, 5]));
        bench.fe.step(bench.now);
        assert!(bench.fe.io_mut().pop_tx().is_some());
    }

    fn sent_counter(bench: &mut Bench) -> u64 {
        bench
            .fe
            .io_mut()
            .inject(IfId(0), udp_from_host([10, 9, 0, 5]));
        bench.fe.step(bench.now);
        let tx = bench.fe.io_mut().pop_tx().expect("sent");
        assert_eq!(&tx.bytes[30..34], &ENDPOINT, "to the peer's endpoint");
        assert_eq!(&tx.bytes[36..38], &51821_u16.to_be_bytes());
        assert_eq!(tx.bytes[14 + 28], 4, "a WireGuard data message");
        u64::from_le_bytes(tx.bytes[14 + 28 + 8..14 + 28 + 16].try_into().unwrap())
    }

    fn session_key(key: u8, peer_index: u32) -> Change {
        Change::set(
            Key::WireguardSession {
                interface: "wg0".into(),
                peer: "branch".into(),
            },
            Value::WireguardSession(WireguardSession {
                send: [key; 32],
                receive: [2; 32],
                peer_index,
                local_index: 11,
            }),
        )
    }

    fn delete_session() -> Change {
        Change::delete(Key::WireguardSession {
            interface: "wg0".into(),
            peer: "branch".into(),
        })
    }

    #[test]
    fn the_counter_goes_on_across_table_changes() {
        let mut bench = Bench::new();
        setup(&mut bench, true);
        assert_eq!(sent_counter(&mut bench), 0);
        // A change that leaves the session alone.
        let mut config = bench.connect(writers::CONFIG);
        assert_eq!(
            bench.patch(&mut config, &[address("lan", [192, 0, 2, 3], 24)]),
            Code::CHANGED
        );
        assert_eq!(sent_counter(&mut bench), 1);
    }

    #[test]
    fn a_send_key_never_seals_with_a_counter_it_used_before() {
        let mut bench = Bench::new();
        setup(&mut bench, true);
        assert_eq!(sent_counter(&mut bench), 0);
        assert_eq!(sent_counter(&mut bench), 1);
        let mut config = bench.connect(writers::CONFIG);

        // The session is deleted: nothing is sent. The same keys come back: the
        // counter goes on.
        assert_eq!(bench.patch(&mut config, &[delete_session()]), Code::CHANGED);
        bench
            .fe
            .io_mut()
            .inject(IfId(0), udp_from_host([10, 9, 0, 5]));
        bench.fe.step(bench.now);
        assert!(bench.fe.io_mut().pop_tx().is_none());
        assert_eq!(bench.patch(&mut config, &[session()]), Code::CHANGED);
        assert_eq!(sent_counter(&mut bench), 2);

        // The same send key with another index: it goes on too.
        assert_eq!(
            bench.patch(&mut config, &[session_key(1, 99)]),
            Code::CHANGED
        );
        assert_eq!(sent_counter(&mut bench), 3);

        // A new send key starts from 0.
        assert_eq!(
            bench.patch(&mut config, &[session_key(5, 99)]),
            Code::CHANGED
        );
        assert_eq!(sent_counter(&mut bench), 0);
        // And going back to the first key does not reset it either.
        assert_eq!(bench.patch(&mut config, &[session()]), Code::CHANGED);
        assert_eq!(sent_counter(&mut bench), 4);
    }

    #[test]
    fn a_disabled_interface_that_comes_back_does_not_restart_the_counter() {
        let mut bench = Bench::new();
        setup(&mut bench, true);
        assert_eq!(sent_counter(&mut bench), 0);
        let mut config = bench.connect(writers::CONFIG);
        let wg0 = |enabled| {
            Change::set(
                Key::Interface { name: "wg0".into() },
                Value::Interface {
                    enabled,
                    mac: [2, 0, 0, 0, 0, 9],
                    mtu: 1420,
                    vrf: ruster_proto::table::DEFAULT_VRF.into(),
                    vlan: None,
                    tunnel: None,
                    pppoe: None,
                },
            )
        };
        assert_eq!(bench.patch(&mut config, &[wg0(false)]), Code::CHANGED);
        assert_eq!(bench.patch(&mut config, &[wg0(true)]), Code::CHANGED);
        assert_eq!(sent_counter(&mut bench), 1);
    }

    #[test]
    fn two_peers_with_one_send_key_or_one_local_index_are_refused() {
        let mut bench = Bench::new();
        setup(&mut bench, true);
        let mut config = bench.connect(writers::CONFIG);
        let second = |send: u8, local_index: u32| {
            vec![
                Change::set(
                    Key::WireguardPeer {
                        interface: "wg0".into(),
                        peer: "other".into(),
                    },
                    Value::WireguardPeer(WireguardPeer {
                        endpoint: Ipv4Addr::new(203, 0, 113, 10),
                        port: 51821,
                        allowed: vec![(Ipv4Addr::new(10, 8, 0, 0), 16)],
                    }),
                ),
                Change::set(
                    Key::WireguardSession {
                        interface: "wg0".into(),
                        peer: "other".into(),
                    },
                    Value::WireguardSession(WireguardSession {
                        send: [send; 32],
                        receive: [9; 32],
                        peer_index: 5,
                        local_index,
                    }),
                ),
            ]
        };
        // The first peer's send key is [1; 32] and its local index 11.
        assert_ne!(bench.patch(&mut config, &second(1, 12)), Code::CHANGED);
        assert_ne!(bench.patch(&mut config, &second(7, 11)), Code::CHANGED);
        assert_eq!(bench.patch(&mut config, &second(7, 12)), Code::CHANGED);
    }

    #[test]
    fn a_resync_may_move_a_key_to_a_peer_of_another_name() {
        let mut bench = Bench::new();
        setup(&mut bench, true);
        assert_eq!(sent_counter(&mut bench), 0);
        let mut config = bench.connect(writers::CONFIG);
        config.resync_begin();
        bench.settle(&mut [&mut config]);
        // The whole new tables come in one patch; only the old peer stays stale.
        let renamed = [
            iface("lan", LAN_MAC),
            iface("wan", WAN_MAC),
            address("lan", [192, 0, 2, 1], 24),
            address("wan", [198, 51, 100, 2], 24),
            Change::set(
                Key::Interface { name: "wg0".into() },
                Value::Interface {
                    enabled: true,
                    mac: [2, 0, 0, 0, 0, 9],
                    mtu: 1420,
                    vrf: ruster_proto::table::DEFAULT_VRF.into(),
                    vlan: None,
                    tunnel: None,
                    pppoe: None,
                },
            ),
            Change::set(
                Key::Wireguard {
                    interface: "wg0".into(),
                },
                Value::Wireguard(Wireguard {
                    listen_port: 51820,
                    local: Ipv4Addr::from(ROUTER),
                }),
            ),
            Change::set(
                Key::WireguardPeer {
                    interface: "wg0".into(),
                    peer: "renamed".into(),
                },
                Value::WireguardPeer(WireguardPeer {
                    endpoint: Ipv4Addr::from(ENDPOINT),
                    port: 51821,
                    allowed: vec![(Ipv4Addr::new(10, 9, 0, 0), 16)],
                }),
            ),
            Change::set(
                Key::WireguardSession {
                    interface: "wg0".into(),
                    peer: "renamed".into(),
                },
                Value::WireguardSession(WireguardSession {
                    send: [1; 32],
                    receive: [2; 32],
                    peer_index: 22,
                    local_index: 11,
                }),
            ),
        ];
        assert_eq!(bench.patch(&mut config, &renamed), Code::CHANGED);
        // The key goes on from its counter, under the new name.
        assert_eq!(sent_counter(&mut bench), 1);
    }

    #[test]
    fn two_interfaces_with_one_address_and_port_are_refused() {
        let mut bench = Bench::new();
        setup(&mut bench, true);
        let mut config = bench.connect(writers::CONFIG);
        let second = [
            Change::set(
                Key::Interface { name: "wg1".into() },
                Value::Interface {
                    enabled: true,
                    mac: [2, 0, 0, 0, 0, 10],
                    mtu: 1420,
                    vrf: ruster_proto::table::DEFAULT_VRF.into(),
                    vlan: None,
                    tunnel: None,
                    pppoe: None,
                },
            ),
            Change::set(
                Key::Wireguard {
                    interface: "wg1".into(),
                },
                Value::Wireguard(Wireguard {
                    listen_port: 51820,
                    local: Ipv4Addr::from(ROUTER),
                }),
            ),
        ];
        assert_ne!(bench.patch(&mut config, &second), Code::CHANGED);
    }
}

/// The router's own packets go through the forward firewall like a host's from a
/// port: a rule names their interface `rt-default`.
#[test]
fn the_router_s_own_packets_need_a_rule_for_rt_default() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]),
        Code::CHANGED
    );
    assert_eq!(
        bench.patch(&mut config, &[accept_udp_from_lan(1)]),
        Code::CHANGED
    );
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));
    let mut own = udp_from_host(INTERNET)[14..].to_vec();
    own[12..16].copy_from_slice(&[198, 51, 100, 2]);
    own[10..12].fill(0);
    let checksum = ipv4_header_checksum(&own[..20]);
    own[10..12].copy_from_slice(&checksum.to_be_bytes());

    // Only the LAN's UDP is accepted: the router's own does not leave.
    kernel.send(&own).unwrap();
    bench.fe.step(bench.now);
    assert!(bench.fe.io_mut().pop_tx().is_none());

    let mut from_router = accept_udp_from_lan(2);
    if let Some(Value::FirewallRule(rule)) = &mut from_router.value {
        rule.ingress = Some("rt-default".into());
    }
    assert_eq!(bench.patch(&mut config, &[from_router]), Code::CHANGED);
    kernel.send(&own).unwrap();
    bench.fe.step(bench.now);
    let tx = bench
        .fe
        .io_mut()
        .pop_tx()
        .expect("sent by the rule for rt-default");
    assert_eq!(tx.egress, IfId(1));
    assert_eq!(&tx.bytes[0..6], &GATEWAY_MAC);
}
