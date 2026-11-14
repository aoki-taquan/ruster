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

/// While the ports bring packets in every step, the neighbor process's socket and
/// the kernel's device are read once in eight steps, not in each; a step without
/// packets from the ports reads them at once.
#[test]
fn under_load_what_is_handed_in_still_goes_out_within_a_few_steps() {
    let mut bench = Bench::new();
    let (_config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    let code = bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]);
    assert_eq!(code, Code::CHANGED);
    let (fe_end, neighd_end) = UnixDatagram::pair().unwrap();
    bench.fe.attach_punt(fe_end).unwrap();
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));

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
    // The router's own packet to the Internet, as the kernel writes it.
    let own = udp_from_host(INTERNET)[14..].to_vec();

    // One loaded step: a packet from the LAN is forwarded. Returns what else left.
    let loaded_step = |bench: &mut Bench| {
        bench.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
        bench.fe.step(0);
        let mut others = Vec::new();
        let mut forwarded = 0;
        while let Some(tx) = bench.fe.io_mut().pop_tx() {
            if tx.egress == IfId(1) && tx.bytes[6..12] == WAN_MAC && tx.bytes[22] == 63 {
                forwarded += 1;
            } else {
                others.push(tx);
            }
        }
        assert_eq!(forwarded, 1, "the port's packet is forwarded in every step");
        others
    };
    for _ in 0..4 {
        assert!(loaded_step(&mut bench).is_empty());
    }
    // Handed in under load: both leave, within eight steps and not in every one.
    let mut waited = Vec::new();
    for _ in 0..3 {
        neighd_end.send(&message).unwrap();
        kernel.send(&own).unwrap();
        let mut steps = 0;
        let mut left = 0;
        while left < 2 {
            steps += 1;
            assert!(steps <= 9, "left unread for more than eight steps");
            left += loaded_step(&mut bench).len();
        }
        waited.push(steps);
    }
    assert!(waited.iter().any(|steps| *steps > 1), "{waited:?}");

    // Without packets from the ports the next step reads them at once.
    bench.fe.step(0);
    neighd_end.send(&message).unwrap();
    bench.fe.step(0);
    let tx = bench.fe.io_mut().pop_tx().expect("sent at once");
    assert_eq!((tx.egress, tx.bytes), (IfId(0), reply));
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
        // After steps that forwarded packets the FE may leave the sockets for a
        // later step; the second one reads them.
        bench.fe.step(round);
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

/// With a second worker, a packet it receives that needs no state is forwarded
/// out of its own backend; one for the router is handed to worker 0, which
/// writes it to the kernel. Table changes are answered once both workers moved.
#[test]
fn a_second_worker_forwards_plain_packets_and_hands_the_rest_to_the_first() {
    let mut bench = Bench {
        fe: Fe::with_workers(
            SimIo::new(),
            vec![SimIo::new()],
            vec!["lan".into(), "wan".into()],
        ),
        now: 0,
    };
    let (_config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    let code = bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]);
    assert_eq!(code, Code::CHANGED);
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    kernel.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));

    bench
        .fe
        .worker_io_mut(1)
        .unwrap()
        .inject(IfId(0), udp_from_host(INTERNET));
    bench.fe.step(1);
    let tx = bench
        .fe
        .worker_io_mut(1)
        .unwrap()
        .pop_tx()
        .expect("forwarded by the second worker");
    assert_eq!(tx.egress, IfId(1));
    assert_eq!(&tx.bytes[6..12], &WAN_MAC);
    assert!(bench.fe.io_mut().pop_tx().is_none());

    let mut to_router = udp_from_host([192, 0, 2, 1]);
    to_router[14 + 10..14 + 12].copy_from_slice(&[0, 0]);
    let checksum = ipv4_header_checksum(&to_router[14..34]);
    to_router[14 + 10..14 + 12].copy_from_slice(&checksum.to_be_bytes());
    bench
        .fe
        .worker_io_mut(1)
        .unwrap()
        .inject(IfId(0), to_router.clone());
    bench.fe.step(2);
    let mut buf = [0_u8; 2048];
    let n = kernel
        .recv(&mut buf)
        .expect("written to the kernel by worker 0");
    assert_eq!(&buf[..n], &to_router[14..]);
    let counters = bench.fe.counters();
    assert_eq!(counters.handed_to_owner, 1);
    assert_eq!(counters.to_kernel, 1);
    assert_eq!(counters.forwarded, 1);
}

/// With NAT, a packet the second worker receives from the inside is handed to
/// worker 0, which translates it; its reply, to the public address, too.
#[test]
fn with_nat_a_second_worker_hands_what_nat_translates_to_the_first() {
    let mut bench = Bench {
        fe: Fe::with_workers(
            SimIo::new(),
            vec![SimIo::new()],
            vec!["lan".into(), "wan".into()],
        ),
        now: 0,
    };
    let (mut config, _routes) = configure(&mut bench);
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
    bench
        .fe
        .worker_io_mut(1)
        .unwrap()
        .inject(IfId(0), udp_from_host(INTERNET));
    bench.fe.step(10);
    assert!(bench.fe.worker_io_mut(1).unwrap().pop_tx().is_none());
    let out = bench.fe.io_mut().pop_tx().expect("translated by worker 0");
    assert_eq!(out.egress, IfId(1));
    assert_eq!(&out.bytes[26..30], &[198, 51, 100, 2], "the WAN address");
    let port = u16::from_be_bytes([out.bytes[34], out.bytes[35]]);

    let mut reply = udp_reply_to_host();
    reply[30..34].copy_from_slice(&[198, 51, 100, 2]);
    reply[24..26].fill(0);
    let checksum = ipv4_header_checksum(&reply[14..34]);
    reply[24..26].copy_from_slice(&checksum.to_be_bytes());
    reply[36..38].copy_from_slice(&port.to_be_bytes());
    bench.fe.worker_io_mut(1).unwrap().inject(IfId(1), reply);
    bench.fe.step(20);
    let back = bench
        .fe
        .io_mut()
        .pop_tx()
        .expect("translated back by worker 0");
    assert_eq!(back.egress, IfId(0));
    assert_eq!(&back.bytes[30..34], &[192, 0, 2, 10]);
    assert_eq!(bench.fe.counters().handed_to_owner, 2);
}

/// With the handover's writes on a task of their own, what goes to the kernel is
/// written when that task steps, and counted by the FE once it hears back; a pipe
/// attached afterwards is written to as well.
#[test]
fn with_the_handover_detached_the_kernel_s_traffic_is_written_by_its_task() {
    let mut bench = Bench::new();
    let (_config, _routes) = configure(&mut bench);
    let mut handover = bench.fe.detach_handover().expect("a handover task");
    assert!(bench.fe.detach_handover().is_none(), "taken once");
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    kernel.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));

    let mut to_router = udp_from_host([192, 0, 2, 1]);
    to_router[14 + 10..14 + 12].copy_from_slice(&[0, 0]);
    let checksum = ipv4_header_checksum(&to_router[14..34]);
    to_router[14 + 10..14 + 12].copy_from_slice(&checksum.to_be_bytes());
    bench.fe.io_mut().inject(IfId(0), to_router.clone());
    bench.fe.step(0);
    let mut buf = [0_u8; 2048];
    assert!(kernel.recv(&mut buf).is_err(), "not written by the worker");
    assert_eq!(bench.fe.counters().to_kernel, 0);

    assert!(handover.step(0).busy);
    let n = kernel.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], &to_router[14..]);
    bench.fe.step(1);
    assert_eq!(bench.fe.counters().to_kernel, 1);
    assert!(!handover.fe_gone());
    drop(bench);
    handover.step(2);
    assert!(handover.fe_gone());
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
            filtering: Default::default(),
            ipv4_id_rate_limit: true,
            ports_per_host: 0,
            state_per_host: 0,
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

/// An IPv4 TCP packet (no Ethernet header) from `source` to `destination`.
fn tcp_packet(source: [u8; 4], destination: [u8; 4], ports: (u16, u16), flags: u8) -> Vec<u8> {
    let mut p = vec![0_u8; 40];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&40_u16.to_be_bytes());
    p[8] = 64;
    p[9] = 6;
    p[12..16].copy_from_slice(&source);
    p[16..20].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&p[..20]);
    p[10..12].copy_from_slice(&checksum.to_be_bytes());
    p[20..22].copy_from_slice(&ports.0.to_be_bytes());
    p[22..24].copy_from_slice(&ports.1.to_be_bytes());
    p[32] = 0x50;
    p[33] = flags;
    // The TCP checksum over the pseudo-header and the segment (RFC 793).
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&source);
    pseudo.extend_from_slice(&destination);
    pseudo.extend_from_slice(&[0, 6, 0, 20]);
    pseudo.extend_from_slice(&p[20..]);
    let checksum = ruster_core::internet_checksum(&pseudo);
    p[36..38].copy_from_slice(&checksum.to_be_bytes());
    p
}

fn from_lan(packet: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&LAN_MAC);
    frame.extend_from_slice(&HOST_MAC);
    frame.extend_from_slice(&0x0800_u16.to_be_bytes());
    frame.extend_from_slice(packet);
    frame
}

fn from_wan(packet: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&WAN_MAC);
    frame.extend_from_slice(&GATEWAY_MAC);
    frame.extend_from_slice(&0x0800_u16.to_be_bytes());
    frame.extend_from_slice(packet);
    frame
}

/// Traffic to the router is judged like traffic to a host behind a port: a rule with
/// `egress = "rt-default"` lets a connection in, and its state lets the kernel's
/// replies out.
#[test]
fn a_connection_to_the_router_needs_a_rule_and_its_replies_then_pass() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]),
        Code::CHANGED
    );
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    kernel.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));
    let router = [198, 51, 100, 2];
    let syn = tcp_packet(INTERNET, router, (40_000, 22), 0x02);
    let mut buf = [0_u8; 2048];

    // A firewall with a rule for the LAN only: the SYN does not reach the kernel.
    assert_eq!(
        bench.patch(&mut config, &[accept_udp_from_lan(1)]),
        Code::CHANGED
    );
    bench.fe.io_mut().inject(IfId(1), from_wan(&syn));
    bench.fe.step(bench.now);
    assert!(kernel.recv(&mut buf).is_err(), "nothing for the kernel");

    // SSH to the router is allowed.
    let ssh_in = Change::set(
        Key::FirewallRule {
            vrf: "default".into(),
            id: 2,
        },
        Value::FirewallRule(ruster_proto::table::FirewallRule {
            ingress: None,
            egress: Some("rt-default".into()),
            source: (Ipv4Addr::UNSPECIFIED.into(), 0),
            destination: (Ipv4Addr::UNSPECIFIED.into(), 0),
            protocol: ruster_proto::table::Protocol::Tcp,
            source_ports: (0, 65_535),
            destination_ports: (22, 22),
            action: ruster_proto::table::FirewallAction::Accept,
        }),
    );
    assert_eq!(bench.patch(&mut config, &[ssh_in]), Code::CHANGED);
    bench.fe.io_mut().inject(IfId(1), from_wan(&syn));
    bench.fe.step(bench.now);
    let n = kernel.recv(&mut buf).expect("the SYN reached the kernel");
    assert_eq!(&buf[..n], &syn[..]);

    // The kernel's SYN-ACK and later segments go out by the flow's state.
    for flags in [0x12, 0x10] {
        let reply = tcp_packet(router, INTERNET, (22, 40_000), flags);
        kernel.send(&reply).unwrap();
        bench.fe.step(bench.now);
        let tx = bench.fe.io_mut().pop_tx().expect("the kernel's reply left");
        assert_eq!(tx.egress, IfId(1));
        assert_eq!(&tx.bytes[14..], &reply[..]);
    }
}

fn ipv4_checksummed(mut p: Vec<u8>) -> Vec<u8> {
    p[10..12].fill(0);
    let checksum = ipv4_header_checksum(&p[..20]);
    p[10..12].copy_from_slice(&checksum.to_be_bytes());
    p
}

/// A Fragmentation Needed from `from` to `to`, quoting `quoted` (its header and 8
/// bytes).
fn frag_needed(from: [u8; 4], to: [u8; 4], quoted: &[u8]) -> Vec<u8> {
    let mut icmp = vec![3, 4, 0, 0, 0, 0, 0x05, 0x00];
    icmp.extend_from_slice(&quoted[..28]);
    let checksum = ruster_core::internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    let mut p = vec![0_u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 1;
    p[12..16].copy_from_slice(&from);
    p[16..20].copy_from_slice(&to);
    p.extend_from_slice(&icmp);
    ipv4_checksummed(p)
}

fn router_with_firewall(rules: &[Change]) -> (Bench, UnixDatagram) {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]),
        Code::CHANGED
    );
    assert_eq!(bench.patch(&mut config, rules), Code::CHANGED);
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    kernel.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));
    (bench, kernel)
}

fn rule_for(
    id: u32,
    protocol: ruster_proto::table::Protocol,
    ingress: Option<&str>,
    egress: Option<&str>,
) -> Change {
    Change::set(
        Key::FirewallRule {
            vrf: "default".into(),
            id,
        },
        Value::FirewallRule(ruster_proto::table::FirewallRule {
            ingress: ingress.map(Into::into),
            egress: egress.map(Into::into),
            source: (Ipv4Addr::UNSPECIFIED.into(), 0),
            destination: (Ipv4Addr::UNSPECIFIED.into(), 0),
            protocol,
            source_ports: (0, 65_535),
            destination_ports: (0, 65_535),
            action: ruster_proto::table::FirewallAction::Accept,
        }),
    )
}

/// The router learns the path MTU of its own connections through the firewall.
#[test]
fn a_frag_needed_about_the_router_s_own_flow_reaches_it_and_a_forged_one_does_not() {
    use ruster_proto::table::Protocol;
    let (mut bench, kernel) =
        router_with_firewall(&[rule_for(1, Protocol::Tcp, Some("rt-default"), None)]);
    let router = [198, 51, 100, 2];
    let syn = tcp_packet(router, INTERNET, (40_000, 443), 0x02);
    kernel.send(&syn).unwrap();
    bench.fe.step(bench.now);
    assert!(
        bench.fe.io_mut().pop_tx().is_some(),
        "the router's SYN left"
    );

    let mut buf = [0_u8; 2048];
    let hop = [203, 0, 113, 99];
    let about_it = frag_needed(hop, router, &syn);
    bench.fe.io_mut().inject(IfId(1), from_wan(&about_it));
    bench.fe.step(bench.now);
    let n = kernel.recv(&mut buf).expect("the error reached the kernel");
    assert_eq!(&buf[..n], &about_it[..]);

    let other = tcp_packet(router, INTERNET, (40_001, 443), 0x02);
    let not_a_flow = frag_needed(hop, router, &other);
    let forged_sender = frag_needed(
        hop,
        router,
        &tcp_packet([198, 51, 100, 77], INTERNET, (40_000, 443), 0x02),
    );
    for forged in [not_a_flow, forged_sender] {
        bench.fe.io_mut().inject(IfId(1), from_wan(&forged));
        bench.fe.step(bench.now);
        assert!(
            kernel.recv(&mut buf).is_err(),
            "a forged error does not reach the kernel"
        );
    }
}

/// A datagram for the router in fragments: the first is judged by the rules, the
/// later ones go on to the kernel, which puts them together.
#[test]
fn fragments_for_the_router_reach_it_when_the_rules_let_the_first_in() {
    use ruster_proto::table::Protocol;
    let (mut bench, kernel) =
        router_with_firewall(&[rule_for(1, Protocol::Udp, None, Some("rt-default"))]);
    let router = [198, 51, 100, 2];
    let fragment = |offset_units: u16, more: bool, payload: &[u8]| {
        let mut p = vec![0_u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        p[4..6].copy_from_slice(&7_u16.to_be_bytes());
        let flags = (u16::from(more) << 13) | offset_units;
        p[6..8].copy_from_slice(&flags.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&INTERNET);
        p[16..20].copy_from_slice(&router);
        p.extend_from_slice(payload);
        ipv4_checksummed(p)
    };
    let mut first_payload = vec![0_u8; 16];
    first_payload[0..2].copy_from_slice(&5353_u16.to_be_bytes());
    first_payload[2..4].copy_from_slice(&53_u16.to_be_bytes());
    first_payload[4..6].copy_from_slice(&40_u16.to_be_bytes());
    let first = fragment(0, true, &first_payload);
    let later = fragment(2, false, &[0_u8; 24]);
    let mut buf = [0_u8; 2048];
    for packet in [&first, &later] {
        bench.fe.io_mut().inject(IfId(1), from_wan(packet));
        bench.fe.step(bench.now);
        let n = kernel
            .recv(&mut buf)
            .expect("the fragment reached the kernel");
        assert_eq!(&buf[..n], &packet[..]);
    }
}

fn udp_packet(source: [u8; 4], destination: [u8; 4], ports: (u16, u16)) -> Vec<u8> {
    let mut p = vec![0_u8; 36];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&36_u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&source);
    p[16..20].copy_from_slice(&destination);
    p[20..22].copy_from_slice(&ports.0.to_be_bytes());
    p[22..24].copy_from_slice(&ports.1.to_be_bytes());
    p[24..26].copy_from_slice(&16_u16.to_be_bytes());
    ipv4_checksummed(p)
}

/// The router's own IPv4 from NAT's inside address goes through NAT as a LAN host's,
/// and the reply comes back to the kernel (`fe-ce-split.md`, "kernelは内側のホスト").
#[test]
fn nat_translates_the_router_s_own_packets_and_brings_the_reply_back_to_it() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]),
        Code::CHANGED
    );
    assert_eq!(
        bench.patch(&mut config, &[nat(40_000, 40_009)]),
        Code::CHANGED
    );
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    kernel.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));

    // From the router's LAN address (the kernel's source with NAT).
    let own = udp_packet([192, 0, 2, 1], INTERNET, (5_353, 53));
    kernel.send(&own).unwrap();
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("translated and sent");
    assert_eq!(tx.egress, IfId(1));
    assert_eq!(&tx.bytes[26..30], &[198, 51, 100, 2], "the public address");
    let port = u16::from_be_bytes([tx.bytes[34], tx.bytes[35]]);
    assert!((40_000..=40_009).contains(&port), "{port}");

    // The reply goes back to the kernel, to the router's address and port.
    let reply = udp_packet(INTERNET, [198, 51, 100, 2], (53, port));
    bench.fe.io_mut().inject(IfId(1), from_wan(&reply));
    bench.fe.step(bench.now);
    let mut buf = [0_u8; 2048];
    let n = kernel.recv(&mut buf).expect("the reply reached the kernel");
    assert_eq!(&buf[16..20], &[192, 0, 2, 1]);
    assert_eq!(u16::from_be_bytes([buf[22], buf[23]]), 5_353);
    assert!(n >= 28);
    assert_eq!(buf[8], 64, "the router is not a hop: the TTL stays");
    assert_eq!(ruster_core::internet_checksum(&buf[..20]), 0);
    assert!(bench.fe.io_mut().pop_tx().is_none(), "not sent to the LAN");

    // A Fragmentation Needed about that packet reaches the kernel too, turned back.
    let error = frag_needed([203, 0, 113, 99], [198, 51, 100, 2], &tx.bytes[14..]);
    bench.fe.io_mut().inject(IfId(1), from_wan(&error));
    bench.fe.step(bench.now);
    let n = kernel.recv(&mut buf).expect("the error reached the kernel");
    assert_eq!(&buf[16..20], &[192, 0, 2, 1], "to the router's own address");
    assert_eq!(
        &buf[40..44],
        &[192, 0, 2, 1],
        "about the router's own packet"
    );
    assert_eq!(u16::from_be_bytes([buf[48], buf[49]]), 5_353);
    assert_eq!(buf[8], error[8], "the TTL stays");
    assert_eq!(ruster_core::internet_checksum(&buf[..20]), 0);
    assert_eq!(ruster_core::internet_checksum(&buf[20..n]), 0);
    assert!(bench.fe.io_mut().pop_tx().is_none(), "not sent to the LAN");
}

/// With NAT, the router's packets from its outside address (its services' replies
/// to the internet, such as SSH) pass NAT by and leave as they are.
#[test]
fn nat_lets_the_router_s_packets_from_its_outside_address_pass_as_they_are() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]),
        Code::CHANGED
    );
    assert_eq!(
        bench.patch(&mut config, &[nat(40_000, 40_009)]),
        Code::CHANGED
    );
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    kernel.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));

    let syn_ack = tcp_packet([198, 51, 100, 2], INTERNET, (22, 50_000), 0x12);
    let own_udp = udp_packet([198, 51, 100, 2], INTERNET, (5_353, 53));
    for packet in [syn_ack, own_udp] {
        kernel.send(&packet).unwrap();
        bench.fe.step(bench.now);
        let tx = bench.fe.io_mut().pop_tx().expect("sent");
        assert_eq!(tx.egress, IfId(1));
        assert_eq!(&tx.bytes[26..30], &[198, 51, 100, 2]);
        assert_eq!(&tx.bytes[34..36], &packet[20..22], "the port stays");
    }

    // A LAN host still cannot send as the router.
    let spoofed = udp_packet([192, 0, 2, 1], INTERNET, (5_353, 53));
    bench.fe.io_mut().inject(IfId(0), from_lan(&spoofed));
    bench.fe.step(bench.now);
    assert!(
        bench.fe.io_mut().pop_tx().is_none(),
        "the spoofed packet is dropped"
    );
}

/// A LAN host reaches the router's WAN address: any of the router's addresses is
/// the router's, whichever interface the packet came in on (RFC 1812 5.2.3).
#[test]
fn a_lan_host_reaches_the_router_s_wan_address() {
    let mut bench = Bench::new();
    let (_config, _routes) = configure(&mut bench);
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    kernel.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));

    let to_wan_address = udp_packet([192, 0, 2, 10], [198, 51, 100, 2], (5_000, 22));
    bench.fe.io_mut().inject(IfId(0), from_lan(&to_wan_address));
    bench.fe.step(bench.now);
    let mut buf = [0_u8; 2048];
    let n = kernel.recv(&mut buf).expect("it reached the kernel");
    assert_eq!(&buf[..n], &to_wan_address[..]);
    assert!(bench.fe.io_mut().pop_tx().is_none(), "not routed on");
}

/// With NAT, a LAN host still reaches the router's WAN address (NAT's public
/// address) on a port outside NAT's range; with a firewall, a WAN host's packet to
/// the router's LAN address is dropped when no rule lets it in.
#[test]
fn the_router_s_addresses_with_nat_and_with_a_firewall() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]),
        Code::CHANGED
    );
    assert_eq!(
        bench.patch(&mut config, &[nat(40_000, 40_009)]),
        Code::CHANGED
    );
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    kernel.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));
    let mut buf = [0_u8; 2048];

    let to_wan_address = udp_packet([192, 0, 2, 10], [198, 51, 100, 2], (5_000, 22));
    bench.fe.io_mut().inject(IfId(0), from_lan(&to_wan_address));
    bench.fe.step(bench.now);
    let n = kernel
        .recv(&mut buf)
        .expect("the LAN reaches the WAN address under NAT");
    assert_eq!(&buf[..n], &to_wan_address[..]);

    // A firewall with a rule for the LAN only.
    assert_eq!(
        bench.patch(&mut config, &[accept_udp_from_lan(1)]),
        Code::CHANGED
    );
    let to_lan_address = udp_packet(INTERNET, [192, 0, 2, 1], (5_000, 22));
    bench.fe.io_mut().inject(IfId(1), from_wan(&to_lan_address));
    bench.fe.step(bench.now);
    assert!(
        kernel.recv(&mut buf).is_err(),
        "the LAN address is behind the firewall"
    );
    assert!(bench.fe.io_mut().pop_tx().is_none(), "and nothing answers");
}

/// Without NAT, a Fragmentation Needed or Time Exceeded about a LAN host's flow
/// goes through the firewall as RELATED to it (RFC 1191, RFC 1812 5.2.7), and one
/// about no flow does not.
#[test]
fn the_firewall_passes_icmp_errors_about_a_forwarded_flow() {
    use ruster_proto::table::Protocol;
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(
            &mut neighbors,
            &[
                neighbor("wan", GATEWAY, GATEWAY_MAC),
                neighbor("lan", [192, 0, 2, 10], HOST_MAC),
            ]
        ),
        Code::CHANGED
    );
    assert_eq!(
        bench.patch(
            &mut config,
            &[rule_for(1, Protocol::Tcp, Some("lan"), None)]
        ),
        Code::CHANGED
    );
    let host = [192, 0, 2, 10];
    let syn = tcp_packet(host, INTERNET, (40_000, 443), 0x02);
    bench.fe.io_mut().inject(IfId(0), from_lan(&syn));
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("the SYN left");
    assert_eq!(tx.egress, IfId(1));

    let hop = [203, 0, 113, 99];
    let about_it = frag_needed(hop, host, &syn);
    bench.fe.io_mut().inject(IfId(1), from_wan(&about_it));
    bench.fe.step(bench.now);
    let tx = bench
        .fe
        .io_mut()
        .pop_tx()
        .expect("the error reached the host");
    assert_eq!(tx.egress, IfId(0));
    assert_eq!(&tx.bytes[14 + 16..14 + 20], &host);

    let not_a_flow = frag_needed(hop, host, &tcp_packet(host, INTERNET, (40_001, 443), 0x02));
    let other_host = frag_needed(
        hop,
        host,
        &tcp_packet([192, 0, 2, 11], INTERNET, (40_000, 443), 0x02),
    );
    for forged in [not_a_flow, other_host] {
        bench.fe.io_mut().inject(IfId(1), from_wan(&forged));
        bench.fe.step(bench.now);
        assert!(
            bench.fe.io_mut().pop_tx().is_none(),
            "a forged error is dropped"
        );
    }
}

/// The router's own packets for a PPPoE session (an ICMP error back to the
/// internet, the fragments of a datagram too big for the session) go in the
/// session, as forwarded ones do (RFC 1812 4.2.2.7 and 5.3.1, RFC 2516).
#[test]
fn errors_and_fragments_the_router_makes_go_in_the_pppoe_session() {
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
    assert_eq!(
        bench.patch(&mut config, &[ppp, address("ppp", [100, 64, 0, 1], 32)]),
        Code::CHANGED
    );
    let to_ppp = route(INTERNET, 32, "ppp", None);
    assert_eq!(bench.patch(&mut routes, &[to_ppp]), Code::CHANGED);
    let in_session = |frame: &[u8]| {
        assert_eq!(&frame[12..14], &[0x88, 0x64], "a PPPoE session frame");
        assert_eq!(u16::from_be_bytes([frame[16], frame[17]]), 0x1234);
        assert_eq!(&frame[20..22], &[0x00, 0x21], "IPv4");
        frame[22..].to_vec()
    };

    // A datagram from the internet whose TTL runs out: Time Exceeded goes back.
    let mut expiring = udp_packet(INTERNET, [192, 0, 2, 10], (53, 5_000));
    expiring[8] = 1;
    let expiring = ipv4_checksummed(expiring);
    let mut frame = Vec::new();
    frame.extend_from_slice(&WAN_MAC);
    frame.extend_from_slice(&GATEWAY_MAC);
    frame.extend_from_slice(&[0x88, 0x64, 0x11, 0x00, 0x12, 0x34]);
    frame.extend_from_slice(&((expiring.len() + 2) as u16).to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x21]);
    frame.extend_from_slice(&expiring);
    bench.fe.io_mut().inject(IfId(1), frame);
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("Time Exceeded sent");
    assert_eq!(tx.egress, IfId(1));
    let error = in_session(&tx.bytes);
    assert_eq!(
        &error[12..16],
        &[100, 64, 0, 1],
        "from the session's address"
    );
    assert_eq!(&error[16..20], &INTERNET);
    assert_eq!((error[20], error[21]), (11, 0));

    // A 1500-byte datagram with DF clear from the LAN: fragments in the session.
    let mut big = udp_packet([192, 0, 2, 10], INTERNET, (5_000, 53));
    big.resize(1500, 0);
    big[2..4].copy_from_slice(&1500_u16.to_be_bytes());
    big[24..26].copy_from_slice(&1480_u16.to_be_bytes());
    let big = ipv4_checksummed(big);
    bench.fe.io_mut().inject(IfId(0), from_lan(&big));
    bench.fe.step(bench.now);
    let mut carried = 0;
    while let Some(tx) = bench.fe.io_mut().pop_tx() {
        assert_eq!(tx.egress, IfId(1));
        let fragment = in_session(&tx.bytes);
        assert!(fragment.len() <= 1492);
        carried += fragment.len() - 20;
    }
    assert_eq!(carried, 1480, "every byte of the datagram");
}

/// The fragments of a datagram too big for a tunnel go into the tunnel, each in
/// its own IPv6 packet, as forwarded packets do (RFC 1812 4.2.2.7, RFC 2473).
#[test]
fn fragments_the_router_makes_go_into_the_tunnel() {
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
    assert_eq!(
        bench.patch(&mut routes, &[route(INTERNET, 32, "dslite", None)]),
        Code::CHANGED
    );

    let mut big = udp_packet([192, 0, 2, 10], INTERNET, (5_000, 53));
    big.resize(1500, 0);
    big[2..4].copy_from_slice(&1500_u16.to_be_bytes());
    big[24..26].copy_from_slice(&1480_u16.to_be_bytes());
    let big = ipv4_checksummed(big);
    bench.fe.io_mut().inject(IfId(0), from_lan(&big));
    bench.fe.step(bench.now);
    let mut carried = 0;
    let mut fragments = 0;
    while let Some(tx) = bench.fe.io_mut().pop_tx() {
        assert_eq!(tx.egress, IfId(1));
        assert_eq!(&tx.bytes[0..6], &GATEWAY_MAC);
        assert_eq!(&tx.bytes[12..14], &[0x86, 0xdd]);
        assert_eq!(tx.bytes[14 + 6], 4, "IPv4 in IPv6");
        let inner = &tx.bytes[14 + 40..];
        let payload = u16::from_be_bytes([tx.bytes[18], tx.bytes[19]]);
        assert_eq!(usize::from(payload), inner.len());
        assert!(inner.len() <= 1460);
        carried += inner.len() - 20;
        fragments += 1;
    }
    assert_eq!((fragments, carried), (2, 1480));
}

/// An ICMP error back to a host behind a VLAN sub-interface leaves its parent
/// tagged, as forwarded frames do.
#[test]
fn an_icmp_error_to_a_vlan_host_leaves_tagged() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let sub = Change::set(
        Key::Interface {
            name: "lan.10".into(),
        },
        Value::Interface {
            enabled: true,
            mac: LAN_MAC,
            mtu: 1496,
            vrf: ruster_proto::table::DEFAULT_VRF.into(),
            vlan: Some(ruster_proto::table::Vlan {
                parent: "lan".into(),
                id: 10,
            }),
            tunnel: None,
            pppoe: None,
        },
    );
    assert_eq!(
        bench.patch(&mut config, &[sub, address("lan.10", [10, 10, 0, 1], 24)]),
        Code::CHANGED
    );
    assert_eq!(
        bench.patch(&mut routes, &[route([10, 10, 0, 0], 24, "lan.10", None)]),
        Code::CHANGED
    );
    let host = [10, 10, 0, 5];
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(&mut neighbors, &[neighbor("lan.10", host, HOST_MAC)]),
        Code::CHANGED
    );

    let mut expiring = udp_packet(host, INTERNET, (5_000, 53));
    expiring[8] = 1;
    let expiring = ipv4_checksummed(expiring);
    let mut frame = Vec::new();
    frame.extend_from_slice(&LAN_MAC);
    frame.extend_from_slice(&HOST_MAC);
    frame.extend_from_slice(&[0x81, 0x00, 0x00, 10, 0x08, 0x00]);
    frame.extend_from_slice(&expiring);
    bench.fe.io_mut().inject(IfId(0), frame);
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("Time Exceeded sent");
    assert_eq!(tx.egress, IfId(0));
    assert_eq!(&tx.bytes[0..6], &HOST_MAC);
    assert_eq!(
        &tx.bytes[12..16],
        &[0x81, 0x00, 0x00, 10],
        "tagged for VLAN 10"
    );
    assert_eq!(&tx.bytes[16..18], &[0x08, 0x00]);
    assert_eq!((tx.bytes[18 + 20], tx.bytes[18 + 21]), (11, 0));
    assert_eq!(&tx.bytes[18 + 16..18 + 20], &host);
}

/// A tunnel carries no more than the link below it, less the IPv6 header: a
/// datagram that fits the tunnel's own MTU but not that gets Fragmentation Needed
/// with what the path carries (RFC 2473 6.7, RFC 1191).
#[test]
fn a_tunnel_s_mtu_is_what_the_link_below_carries() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let mut neighbors = configure_ipv6(&mut bench, &mut config, &mut routes);
    let mut narrow_wan = iface("wan", WAN_MAC);
    if let Change {
        value: Some(Value::Interface { mtu, .. }),
        ..
    } = &mut narrow_wan
    {
        *mtu = 1400;
    }
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
    assert_eq!(
        bench.patch(&mut config, &[narrow_wan, tunnel]),
        Code::CHANGED
    );
    assert_eq!(
        bench.patch(&mut routes, &[route(INTERNET, 32, "dslite", None)]),
        Code::CHANGED
    );
    let gateway = Change::set(
        Key::Neighbor {
            interface: "wan".into(),
            address: ip6("fe80::1"),
        },
        Value::Neighbor { mac: GATEWAY_MAC },
    );
    assert_eq!(
        bench.patch(
            &mut neighbors,
            &[gateway, neighbor("lan", [192, 0, 2, 10], HOST_MAC)]
        ),
        Code::CHANGED
    );

    let sized = |len: usize, df: bool| {
        let mut p = udp_packet([192, 0, 2, 10], INTERNET, (5_000, 53));
        p.resize(len, 0);
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        p[6] = if df { 0x40 } else { 0 };
        p[24..26].copy_from_slice(&((len - 20) as u16).to_be_bytes());
        ipv4_checksummed(p)
    };
    // 1360 bytes go in one IPv6 packet of 1400.
    bench
        .fe
        .io_mut()
        .inject(IfId(0), from_lan(&sized(1360, true)));
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("sent");
    assert_eq!(tx.bytes.len(), 14 + 1400);

    // 1361 with DF set: Fragmentation Needed with 1360, nothing into the tunnel.
    bench
        .fe
        .io_mut()
        .inject(IfId(0), from_lan(&sized(1361, true)));
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("an ICMP error");
    assert_eq!(tx.egress, IfId(0));
    assert_eq!((tx.bytes[14 + 20], tx.bytes[14 + 21]), (3, 4));
    assert_eq!(
        u16::from_be_bytes([tx.bytes[14 + 26], tx.bytes[14 + 27]]),
        1360
    );
    assert!(bench.fe.io_mut().pop_tx().is_none());
}

/// The AFTR fragmented a tunnel's IPv6 packet: the FE puts it back together and
/// the IPv4 packet inside reaches the LAN host (RFC 6333 5.3, RFC 2473 7.2).
#[test]
fn a_tunnel_s_fragmented_packet_is_put_back_together() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let mut neighbors = configure_ipv6(&mut bench, &mut config, &mut routes);
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
    let gateway = Change::set(
        Key::Neighbor {
            interface: "wan".into(),
            address: ip6("fe80::1"),
        },
        Value::Neighbor { mac: GATEWAY_MAC },
    );
    assert_eq!(
        bench.patch(
            &mut neighbors,
            &[gateway, neighbor("lan", [192, 0, 2, 10], HOST_MAC)]
        ),
        Code::CHANGED
    );

    let mut inner = udp_packet(INTERNET, [192, 0, 2, 10], (53, 5_000));
    inner.resize(1000, 7);
    inner[2..4].copy_from_slice(&1000_u16.to_be_bytes());
    inner[24..26].copy_from_slice(&980_u16.to_be_bytes());
    let inner = ipv4_checksummed(inner);
    let piece = |offset: usize, more: bool, data: &[u8]| {
        let mut frame = Vec::new();
        frame.extend_from_slice(&WAN_MAC);
        frame.extend_from_slice(&GATEWAY_MAC);
        frame.extend_from_slice(&[0x86, 0xdd]);
        frame.extend_from_slice(&[0x60, 0, 0, 0]);
        frame.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&[44, 64]);
        frame.extend_from_slice(
            &"2001:db8:ff::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        frame.extend_from_slice(
            &"2001:db8:1::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        let field = ((offset / 8) as u16) << 3 | u16::from(more);
        frame.extend_from_slice(&[4, 0]);
        frame.extend_from_slice(&field.to_be_bytes());
        frame.extend_from_slice(&0x1234_5678_u32.to_be_bytes());
        frame.extend_from_slice(data);
        frame
    };
    bench
        .fe
        .io_mut()
        .inject(IfId(1), piece(0, true, &inner[..512]));
    bench
        .fe
        .io_mut()
        .inject(IfId(1), piece(512, false, &inner[512..]));
    bench.fe.step(bench.now);
    assert!(
        bench.fe.io_mut().pop_tx().is_none(),
        "the fragments are held"
    );
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("the inner packet");
    assert_eq!(tx.egress, IfId(0));
    assert_eq!(&tx.bytes[0..6], &HOST_MAC);
    assert_eq!(&tx.bytes[12..14], &[0x08, 0x00]);
    assert_eq!(tx.bytes.len(), 14 + 1000);
    assert_eq!(&tx.bytes[14 + 20..], &inner[20..], "the payload as sent");
    assert_eq!(tx.bytes[14 + 8], 63, "forwarded once");
}

/// A discard route drops silently; a reject route answers Destination Unreachable,
/// as if no route held the destination (RFC 1812 5.2.7.1, RFC 4443 3.1 code 6).
#[test]
fn discard_and_reject_routes_drop_what_they_hold() {
    let mut bench = Bench::new();
    let (_config, mut routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(
            &mut neighbors,
            &[
                neighbor("wan", GATEWAY, GATEWAY_MAC),
                neighbor("lan", [192, 0, 2, 10], HOST_MAC),
            ]
        ),
        Code::CHANGED
    );
    let action = |prefix: [u8; 4], action: RouteAction| {
        Change::set(
            Key::Route {
                vrf: "default".into(),
                prefix: Ipv4Addr::from(prefix).into(),
                len: 8,
            },
            Value::Route(action),
        )
    };
    assert_eq!(
        bench.patch(
            &mut routes,
            &[
                action([10, 0, 0, 0], RouteAction::Discard),
                action([172, 0, 0, 0], RouteAction::Reject),
            ]
        ),
        Code::CHANGED
    );
    bench
        .fe
        .io_mut()
        .inject(IfId(0), udp_from_host([10, 1, 2, 3]));
    bench.fe.step(bench.now);
    assert!(bench.fe.io_mut().pop_tx().is_none(), "discarded silently");

    bench
        .fe
        .io_mut()
        .inject(IfId(0), udp_from_host([172, 1, 2, 3]));
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("Destination Unreachable");
    assert_eq!(tx.egress, IfId(0));
    assert_eq!((tx.bytes[14 + 20], tx.bytes[14 + 21]), (3, 0));
    assert!(bench.fe.io_mut().pop_tx().is_none(), "not sent upstream");
}

/// NAT's default filtering is endpoint-independent (RFC 4787 REQ-8): once a LAN
/// host's UDP has gone out, a packet from another outside endpoint to its mapping
/// reaches it too.
#[test]
fn by_default_nat_lets_any_outside_endpoint_reach_a_mapping() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(
            &mut neighbors,
            &[
                neighbor("wan", GATEWAY, GATEWAY_MAC),
                neighbor("lan", [192, 0, 2, 10], HOST_MAC),
            ]
        ),
        Code::CHANGED
    );
    assert_eq!(
        bench.patch(&mut config, &[nat(40_000, 40_009)]),
        Code::CHANGED
    );
    let out = udp_packet([192, 0, 2, 10], INTERNET, (5_000, 3_478));
    bench.fe.io_mut().inject(IfId(0), from_lan(&out));
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("translated");
    let port = u16::from_be_bytes([tx.bytes[34], tx.bytes[35]]);

    let other = udp_packet([203, 0, 113, 99], [198, 51, 100, 2], (3_479, port));
    bench.fe.io_mut().inject(IfId(1), from_wan(&other));
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("reached the host");
    assert_eq!(tx.egress, IfId(0));
    assert_eq!(&tx.bytes[30..34], &[192, 0, 2, 10]);
    assert_eq!(u16::from_be_bytes([tx.bytes[36], tx.bytes[37]]), 5_000);
}

/// Where no rule decides, the firewall lets outside endpoints reach an inside
/// host's port that has a flow out as its filtering says: by default any
/// (RFC 6092 REC-17), or only addresses it has a flow with, or only the exact flow.
#[test]
fn the_firewall_filters_packets_to_an_inside_endpoint_as_configured() {
    use ruster_proto::table::{NatFiltering, Protocol};
    let host = [192, 0, 2, 10];
    let peer = [203, 0, 113, 7];
    let other = [203, 0, 113, 99];
    for (filtering, other_address, other_port) in [
        (NatFiltering::EndpointIndependent, true, true),
        (NatFiltering::AddressDependent, false, true),
        (NatFiltering::AddressAndPortDependent, false, false),
    ] {
        let mut bench = Bench::new();
        let (mut config, _routes) = configure(&mut bench);
        let mut neighbors = bench.connect(writers::NEIGHBOR);
        assert_eq!(
            bench.patch(
                &mut neighbors,
                &[
                    neighbor("wan", GATEWAY, GATEWAY_MAC),
                    neighbor("lan", host, HOST_MAC),
                ]
            ),
            Code::CHANGED
        );
        let changes = vec![
            rule_for(1, Protocol::Udp, Some("lan"), None),
            outside_wan(filtering),
        ];
        assert_eq!(bench.patch(&mut config, &changes), Code::CHANGED);
        let out = udp_packet(host, peer, (5_000, 3_478));
        bench.fe.io_mut().inject(IfId(0), from_lan(&out));
        bench.fe.step(bench.now);
        assert!(bench.fe.io_mut().pop_tx().is_some(), "the flow out");

        let mut reaches = |source: [u8; 4], port: u16, inside_port: u16| {
            let packet = udp_packet(source, host, (port, inside_port));
            bench.fe.io_mut().inject(IfId(1), from_wan(&packet));
            bench.fe.step(bench.now);
            bench.fe.io_mut().pop_tx().is_some()
        };
        assert!(
            reaches(peer, 3_478, 5_000),
            "{filtering:?}: the flow's own reply"
        );
        assert_eq!(
            reaches(peer, 3_479, 5_000),
            other_port,
            "{filtering:?}: another port"
        );
        assert_eq!(
            reaches(other, 3_478, 5_000),
            other_address,
            "{filtering:?}: another host"
        );
        assert!(
            !reaches(peer, 3_478, 5_001),
            "{filtering:?}: another inside port"
        );
    }
}

/// A rule decides before the filtering: a deny rule keeps outside endpoints out.
/// For TCP, only a SYN may open a flow to the inside endpoint.
#[test]
fn a_deny_rule_wins_over_filtering_and_only_a_syn_opens_tcp() {
    use ruster_proto::table::{FirewallAction, Protocol};
    let host = [192, 0, 2, 10];
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(
            &mut neighbors,
            &[
                neighbor("wan", GATEWAY, GATEWAY_MAC),
                neighbor("lan", host, HOST_MAC),
            ]
        ),
        Code::CHANGED
    );
    let mut deny = rule_for(3, Protocol::Udp, Some("wan"), None);
    if let Change {
        value: Some(Value::FirewallRule(rule)),
        ..
    } = &mut deny
    {
        rule.action = FirewallAction::Drop;
    }
    assert_eq!(
        bench.patch(
            &mut config,
            &[
                rule_for(1, Protocol::Udp, Some("lan"), None),
                rule_for(2, Protocol::Tcp, Some("lan"), None),
                deny,
                outside_wan(ruster_proto::table::NatFiltering::EndpointIndependent),
            ]
        ),
        Code::CHANGED
    );
    let out = udp_packet(host, INTERNET, (5_000, 3_478));
    bench.fe.io_mut().inject(IfId(0), from_lan(&out));
    let syn = tcp_packet(host, INTERNET, (6_000, 443), 0x02);
    bench.fe.io_mut().inject(IfId(0), from_lan(&syn));
    bench.fe.step(bench.now);
    assert_eq!(std::iter::from_fn(|| bench.fe.io_mut().pop_tx()).count(), 2);

    let other = [203, 0, 113, 99];
    let mut sent = |packet: Vec<u8>| {
        bench.fe.io_mut().inject(IfId(1), from_wan(&packet));
        bench.fe.step(bench.now);
        bench.fe.io_mut().pop_tx().is_some()
    };
    assert!(
        !sent(udp_packet(other, host, (1, 5_000))),
        "the deny rule decides"
    );
    assert!(
        !sent(tcp_packet(other, host, (1, 6_000), 0x10)),
        "an ACK opens nothing"
    );
    assert!(
        sent(tcp_packet(other, host, (1, 6_000), 0x02)),
        "a SYN opens a flow"
    );
    assert!(
        sent(tcp_packet(other, host, (1, 6_000), 0x10)),
        "then its packets pass"
    );
}

/// The firewall's policy: `filtering`, with "wan" outside.
fn outside_wan(filtering: ruster_proto::table::NatFiltering) -> Change {
    Change::set(
        Key::FirewallPolicy {
            vrf: "default".into(),
        },
        Value::FirewallPolicy {
            filtering,
            outside: vec!["wan".into()],
        },
    )
}

/// Only a flow from the inside out of the outside makes an inside endpoint: a flow
/// an outside host opened by a rule does not let inside hosts reach it, and the
/// router's own flows open none of its ports (RFC 6092's interior and exterior).
#[test]
fn filtering_opens_only_inside_endpoints_of_flows_out() {
    use ruster_proto::table::{NatFiltering, Protocol};
    let host = [192, 0, 2, 10];
    let attacker = [203, 0, 113, 66];
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(
            &mut neighbors,
            &[
                neighbor("wan", GATEWAY, GATEWAY_MAC),
                neighbor("lan", host, HOST_MAC),
            ]
        ),
        Code::CHANGED
    );
    assert_eq!(
        bench.patch(
            &mut config,
            &[
                rule_for(1, Protocol::Udp, Some("wan"), Some("lan")),
                rule_for(2, Protocol::Udp, Some("rt-default"), None),
                outside_wan(NatFiltering::EndpointIndependent),
            ]
        ),
        Code::CHANGED
    );
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    kernel.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));

    // The attacker's flow in, allowed by the rule.
    let inbound = udp_packet(attacker, host, (9_999, 53));
    bench.fe.io_mut().inject(IfId(1), from_wan(&inbound));
    bench.fe.step(bench.now);
    assert!(bench.fe.io_mut().pop_tx().is_some(), "the rule lets it in");
    // A LAN host from another port still cannot reach it: LAN to WAN is denied.
    let out = udp_packet(host, attacker, (6_000, 9_999));
    bench.fe.io_mut().inject(IfId(0), from_lan(&out));
    bench.fe.step(bench.now);
    assert!(
        bench.fe.io_mut().pop_tx().is_none(),
        "no way out through it"
    );

    // The router's own flow out (from its port 123) opens nothing to others.
    let own = udp_packet([198, 51, 100, 2], INTERNET, (123, 123));
    kernel.send(&own).unwrap();
    // After steps that forwarded packets the FE may leave the sockets for a
    // later step; the second one reads them.
    bench.fe.step(bench.now);
    bench.fe.step(bench.now);
    assert!(
        bench.fe.io_mut().pop_tx().is_some(),
        "the router's packet left"
    );
    let stranger = udp_packet([203, 0, 113, 99], [198, 51, 100, 2], (5_555, 123));
    bench.fe.io_mut().inject(IfId(1), from_wan(&stranger));
    bench.fe.step(bench.now);
    let mut buf = [0_u8; 2048];
    assert!(
        kernel.recv(&mut buf).is_err(),
        "a stranger does not reach it"
    );
}

/// A flow the filtering opened stays only while the rules still let its inside
/// endpoint send to it: removing the rule (and renumbering the others) ends it.
#[test]
fn a_flow_the_filtering_opened_ends_with_the_rule_that_let_its_host_out() {
    use ruster_proto::table::{NatFiltering, Protocol};
    let host = [192, 0, 2, 10];
    let other = [203, 0, 113, 99];
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(
            &mut neighbors,
            &[
                neighbor("wan", GATEWAY, GATEWAY_MAC),
                neighbor("lan", host, HOST_MAC),
            ]
        ),
        Code::CHANGED
    );
    assert_eq!(
        bench.patch(
            &mut config,
            &[
                rule_for(1, Protocol::Udp, Some("lan"), None),
                rule_for(2, Protocol::Tcp, Some("lan"), None),
                outside_wan(NatFiltering::EndpointIndependent),
            ]
        ),
        Code::CHANGED
    );
    let send = |bench: &mut Bench, port: IfId, frame: Vec<u8>| {
        bench.fe.io_mut().inject(port, frame);
        bench.fe.step(bench.now);
        bench.fe.io_mut().pop_tx().is_some()
    };
    assert!(send(
        &mut bench,
        IfId(0),
        from_lan(&udp_packet(host, INTERNET, (5_000, 53)))
    ));
    assert!(send(
        &mut bench,
        IfId(1),
        from_wan(&udp_packet(other, host, (7, 5_000)))
    ));
    assert!(send(
        &mut bench,
        IfId(0),
        from_lan(&udp_packet(host, other, (5_000, 7)))
    ));

    // The UDP rule goes; the TCP one becomes rule 1.
    let removed = Change::delete(Key::FirewallRule {
        vrf: "default".into(),
        id: 2,
    });
    assert_eq!(
        bench.patch(
            &mut config,
            &[rule_for(1, Protocol::Tcp, Some("lan"), None), removed]
        ),
        Code::CHANGED
    );
    assert!(
        !send(
            &mut bench,
            IfId(0),
            from_lan(&udp_packet(host, other, (5_000, 7)))
        ),
        "no UDP out without a rule"
    );
}

/// Packet Too Big has its own rate limit: a burst of other ICMPv6 errors does not
/// keep path MTU discovery from getting it (RFC 4443 2.4(f), RFC 8201).
#[test]
fn many_icmpv6_errors_do_not_use_up_packet_too_big() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let mut neighbors = configure_ipv6(&mut bench, &mut config, &mut routes);
    let mut narrow_wan = iface("wan", WAN_MAC);
    if let Change {
        value: Some(Value::Interface { mtu, .. }),
        ..
    } = &mut narrow_wan
    {
        *mtu = 1_400;
    }
    assert_eq!(bench.patch(&mut config, &[narrow_wan]), Code::CHANGED);
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
    for _ in 0..30 {
        let mut expiring = ipv6_frame(LAN_MAC, "2001:db8:99::7", 17, &[0; 8]);
        expiring[14 + 7] = 1;
        bench.fe.io_mut().inject(IfId(0), expiring);
    }
    bench.fe.step(0);
    let time_exceeded = std::iter::from_fn(|| bench.fe.io_mut().pop_tx()).count();
    assert!(
        time_exceeded < 30,
        "the errors are limited ({time_exceeded})"
    );

    let big = ipv6_frame(LAN_MAC, "2001:db8:99::7", 17, &[0; 1_400]);
    bench.fe.io_mut().inject(IfId(0), big);
    bench.fe.step(0);
    let tx = bench
        .fe
        .io_mut()
        .pop_tx()
        .expect("Packet Too Big still goes back");
    assert_eq!(tx.bytes[54], 2, "Packet Too Big");
    assert_eq!(&tx.bytes[58..62], &1_400_u32.to_be_bytes());
}

/// IPv6 details (RFC 4443 2.4): no forwarding of unicast in an Ethernet multicast
/// frame, no error about an ICMPv6 error behind an extension header, and the quote
/// is the packet, not the frame's padding.
#[test]
fn ipv6_errors_and_multicast_frames_follow_rfc_4443() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let mut neighbors = configure_ipv6(&mut bench, &mut config, &mut routes);
    let code = bench.patch(
        &mut neighbors,
        &[
            Change::set(
                Key::Neighbor {
                    interface: "lan".into(),
                    address: ip6("2001:db8:1::10"),
                },
                Value::Neighbor { mac: HOST_MAC },
            ),
            Change::set(
                Key::Neighbor {
                    interface: "wan".into(),
                    address: ip6("fe80::1"),
                },
                Value::Neighbor { mac: GATEWAY_MAC },
            ),
        ],
    );
    assert_eq!(code, Code::CHANGED);
    let step = |bench: &mut Bench, frame: Vec<u8>| {
        bench.fe.io_mut().inject(IfId(0), frame);
        bench.fe.step(0);
        std::iter::from_fn(|| bench.fe.io_mut().pop_tx()).collect::<Vec<_>>()
    };
    assert_eq!(
        step(
            &mut bench,
            ipv6_frame(LAN_MAC, "2001:db8:99::7", 17, &[0; 8])
        )
        .len(),
        1,
        "to the router's MAC it is forwarded"
    );
    let group = [0x33, 0x33, 0, 0, 0, 1];
    assert!(
        step(&mut bench, ipv6_frame(group, "2001:db8:99::7", 17, &[0; 8])).is_empty(),
        "unicast in a multicast frame is not forwarded"
    );
    // An ICMPv6 Destination Unreachable behind a Destination Options header.
    let mut payload = vec![58, 0, 1, 4, 0, 0, 0, 0];
    payload.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    let mut error = ipv6_frame(LAN_MAC, "2001:db8:99::7", 60, &payload);
    error[14 + 7] = 1;
    assert!(
        step(&mut bench, error).is_empty(),
        "no error about an error"
    );
    // An expiring packet with 20 bytes of padding after it.
    let mut padded = ipv6_frame(LAN_MAC, "2001:db8:99::7", 17, &[0; 8]);
    padded[14 + 7] = 1;
    padded.extend_from_slice(&[0xee; 20]);
    let tx = step(&mut bench, padded);
    assert_eq!(tx.len(), 1, "Time Exceeded");
    let payload_len = u16::from_be_bytes([tx[0].bytes[18], tx[0].bytes[19]]);
    assert_eq!(payload_len, 8 + 48, "the quote is the 48-byte packet");
}

/// IPv6 source checks: the router's own address from outside is forged and dropped;
/// a link-local source toward a global destination gets Destination Unreachable
/// code 2 back on its link (RFC 4443 3.1).
#[test]
fn ipv6_forged_and_link_local_sources_are_refused() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let mut neighbors = configure_ipv6(&mut bench, &mut config, &mut routes);
    let lan_link_local = Change::set(
        Key::Address {
            interface: "lan".into(),
            address: ip6("fe80::5"),
        },
        Value::Address { prefix_len: 64 },
    );
    assert_eq!(bench.patch(&mut config, &[lan_link_local]), Code::CHANGED);
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
    let with_source = |source: &str| {
        let mut frame = ipv6_frame(LAN_MAC, "2001:db8:99::7", 17, &[0; 8]);
        frame[22..38].copy_from_slice(&source.parse::<std::net::Ipv6Addr>().unwrap().octets());
        frame
    };
    bench
        .fe
        .io_mut()
        .inject(IfId(0), with_source("2001:db8:1::1"));
    bench.fe.step(0);
    assert!(
        bench.fe.io_mut().pop_tx().is_none(),
        "the router's own address is forged"
    );

    bench.fe.io_mut().inject(IfId(0), with_source("fe80::10"));
    bench.fe.step(0);
    let tx = bench.fe.io_mut().pop_tx().expect("Destination Unreachable");
    assert_eq!(tx.egress, IfId(0));
    assert_eq!(&tx.bytes[0..6], &HOST_MAC);
    assert_eq!(
        (tx.bytes[54], tx.bytes[55]),
        (1, 2),
        "beyond scope of source address"
    );
    assert_eq!(
        &tx.bytes[22..38],
        &ip6_octets("fe80::5"),
        "from the router's link-local"
    );
    assert_eq!(&tx.bytes[38..54], &ip6_octets("fe80::10"));
}

fn ip6_octets(text: &str) -> [u8; 16] {
    text.parse::<std::net::Ipv6Addr>().unwrap().octets()
}

/// A next hop the neighbor process gave up on (written with an all-zero MAC): the
/// datagram gets Host Unreachable back (RFC 1812 5.2.7.1), and no frame goes out to
/// the all-zero address.
#[test]
fn an_unresolvable_next_hop_gets_host_unreachable() {
    let mut bench = Bench::new();
    let (_config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(
            &mut neighbors,
            &[
                neighbor("wan", GATEWAY, [0; 6]),
                neighbor("lan", [192, 0, 2, 10], HOST_MAC),
            ]
        ),
        Code::CHANGED
    );
    bench.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("Host Unreachable");
    assert_eq!(tx.egress, IfId(0));
    assert_eq!(&tx.bytes[0..6], &HOST_MAC);
    assert_eq!((tx.bytes[34], tx.bytes[35]), (3, 1));
    assert!(bench.fe.io_mut().pop_tx().is_none());
}

/// The router's own ICMP error about a flow NAT translated for it (Port Unreachable
/// for a late reply) goes out translated too, from the public address (RFC 5508
/// REQ-5).
#[test]
fn nat_translates_the_router_s_own_icmp_errors_about_its_flows() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]),
        Code::CHANGED
    );
    assert_eq!(
        bench.patch(&mut config, &[nat(40_000, 40_009)]),
        Code::CHANGED
    );
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    kernel.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));

    kernel
        .send(&udp_packet([192, 0, 2, 1], INTERNET, (5_353, 53)))
        .unwrap();
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("translated and sent");
    let port = u16::from_be_bytes([tx.bytes[34], tx.bytes[35]]);
    let reply = udp_packet(INTERNET, [198, 51, 100, 2], (53, port));
    bench.fe.io_mut().inject(IfId(1), from_wan(&reply));
    bench.fe.step(bench.now);
    let mut buf = [0_u8; 2048];
    let n = kernel.recv(&mut buf).expect("the reply reached the kernel");
    let delivered = buf[..n].to_vec();

    // The kernel's socket is gone: Port Unreachable about the reply it got.
    let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&delivered[..28]);
    let sum = ruster_core::internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut error = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0];
    error.extend_from_slice(&[192, 0, 2, 1]);
    error.extend_from_slice(&INTERNET);
    error.extend_from_slice(&icmp);
    let len = error.len() as u16;
    error[2..4].copy_from_slice(&len.to_be_bytes());
    kernel.send(&ipv4_checksummed(error)).unwrap();
    bench.fe.step(bench.now);
    let tx = bench.fe.io_mut().pop_tx().expect("the error went out");
    assert_eq!(tx.egress, IfId(1));
    assert_eq!(
        &tx.bytes[26..30],
        &[198, 51, 100, 2],
        "from the public address"
    );
    assert_eq!((tx.bytes[34], tx.bytes[35]), (3, 3));
    let quoted = 14 + 20 + 8;
    assert_eq!(
        &tx.bytes[quoted + 16..quoted + 20],
        &[198, 51, 100, 2],
        "quote turned back"
    );
    assert_eq!(
        u16::from_be_bytes([tx.bytes[quoted + 22], tx.bytes[quoted + 23]]),
        port
    );
}

/// With the firewall on, a truncated datagram to a router address gets no answer,
/// so it does not tell which addresses are the router's.
#[test]
fn with_the_firewall_a_truncated_datagram_to_the_router_gets_no_answer() {
    use ruster_proto::table::Protocol;
    let (mut bench, kernel) =
        router_with_firewall(&[rule_for(1, Protocol::Tcp, Some("lan"), None)]);
    let mut truncated = udp_packet(INTERNET, [192, 0, 2, 1], (53, 5_000));
    truncated[2..4].copy_from_slice(&200_u16.to_be_bytes());
    let truncated = ipv4_checksummed(truncated);
    bench.fe.io_mut().inject(IfId(1), from_wan(&truncated));
    bench.fe.step(bench.now);
    assert!(bench.fe.io_mut().pop_tx().is_none(), "no Parameter Problem");
    let mut buf = [0_u8; 2048];
    assert!(kernel.recv(&mut buf).is_err());
}

/// The ICMP error rate limits come from the configuration (RFC 4443 2.4(f), RFC
/// 1812 4.3.2.8): a burst of 2 lets 2 ICMPv6 errors out at once.
#[test]
fn the_icmp_error_limits_come_from_the_configuration() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let mut neighbors = configure_ipv6(&mut bench, &mut config, &mut routes);
    let limits = Change::set(
        Key::IcmpErrors {
            vrf: "default".into(),
        },
        Value::IcmpErrors {
            ipv4_interval_ms: 100,
            ipv6_burst: 2,
            ipv6_interval_ms: 1_000,
        },
    );
    assert_eq!(bench.patch(&mut config, &[limits]), Code::CHANGED);
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
    for _ in 0..10 {
        let mut expiring = ipv6_frame(LAN_MAC, "2001:db8:99::7", 17, &[0; 8]);
        expiring[14 + 7] = 1;
        bench.fe.io_mut().inject(IfId(0), expiring);
    }
    bench.fe.step(0);
    assert_eq!(std::iter::from_fn(|| bench.fe.io_mut().pop_tx()).count(), 2);
}

/// Each VRF has its own limit on packets to its kernel: a flood to the router in
/// one VRF does not crowd out another VRF's traffic to the router.
#[test]
fn a_flood_to_the_router_in_one_vrf_leaves_another_vrf_s_limit() {
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
    let (red_fe, red_kernel) = UnixDatagram::pair().unwrap();
    let (default_fe, default_kernel) = UnixDatagram::pair().unwrap();
    for socket in [&red_fe, &red_kernel, &default_fe, &default_kernel] {
        socket.set_nonblocking(true).unwrap();
    }
    bench.fe.attach_local("red", Box::new(red_fe));
    bench.fe.attach_local("default", Box::new(default_fe));

    // More than a burst to the router in red, all at one moment.
    for port in 0..300_u16 {
        let packet = udp_packet([192, 0, 2, 10], [192, 0, 2, 1], (1_000 + port, 53));
        bench.fe.io_mut().inject(IfId(0), from_lan(&packet));
        bench.fe.step(0);
    }
    let mut buf = [0_u8; 2048];
    let mut red = 0;
    while red_kernel.recv(&mut buf).is_ok() {
        red += 1;
    }
    assert!(red < 300, "red is limited: {red}");

    // The default VRF's packet to the router still goes, at the same moment.
    let packet = udp_packet(GATEWAY, [198, 51, 100, 2], (1_000, 53));
    bench.fe.io_mut().inject(IfId(1), from_wan(&packet));
    bench.fe.step(0);
    let n = default_kernel
        .recv(&mut buf)
        .expect("default is not limited by red");
    assert_eq!(&buf[..n], &packet[..]);
}

/// An IPv4 interval longer than a minute is used as it is, and the limits are only
/// for the default VRF (they are the FE's, for every VRF).
#[test]
fn a_long_icmpv4_error_interval_is_used_and_another_vrf_s_limits_are_refused() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let limits = |vrf: &str, ipv4_interval_ms| {
        Change::set(
            Key::IcmpErrors { vrf: vrf.into() },
            Value::IcmpErrors {
                ipv4_interval_ms,
                ipv6_burst: 10,
                ipv6_interval_ms: 10,
            },
        )
    };
    assert_ne!(
        bench.patch(&mut config, &[limits("red", 100)]),
        Code::CHANGED
    );
    assert_eq!(
        bench.patch(&mut config, &[limits("default", 120_000)]),
        Code::CHANGED
    );
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    let code = bench.patch(
        &mut neighbors,
        &[neighbor("lan", [192, 0, 2, 10], HOST_MAC)],
    );
    assert_eq!(code, Code::CHANGED);
    let mut sent = Vec::new();
    for now in [0, 70_000] {
        let mut expiring = udp_from_host([203, 0, 113, 7]);
        expiring[14 + 8] = 1;
        expiring[14 + 10..14 + 12].copy_from_slice(&[0, 0]);
        let checksum = ipv4_header_checksum(&expiring[14..34]);
        expiring[14 + 10..14 + 12].copy_from_slice(&checksum.to_be_bytes());
        bench.fe.io_mut().inject(IfId(0), expiring);
        bench.fe.step(now);
        sent.push(std::iter::from_fn(|| bench.fe.io_mut().pop_tx()).count());
    }
    assert_eq!(sent, [1, 0], "the second is within 120 s of the first");
}

/// With NAT, an unsolicited TCP SYN from outside is not answered at once; once its
/// 6 seconds are over with no outbound SYN for it, a Port Unreachable goes back
/// (RFC 5382 REQ-4), also when no packet arrives at that time.
#[test]
fn an_unsolicited_syn_gets_a_port_unreachable_after_six_seconds() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]),
        Code::CHANGED
    );
    assert_eq!(
        bench.patch(&mut config, &[nat(40_000, 40_009)]),
        Code::CHANGED
    );

    let syn = tcp_packet(INTERNET, [198, 51, 100, 2], (50_000, 40_005), 0x02);
    bench.fe.io_mut().inject(IfId(1), from_wan(&syn));
    bench.fe.step(1_000);
    assert!(bench.fe.io_mut().pop_tx().is_none(), "not answered at once");
    bench.fe.step(6_000);
    assert!(bench.fe.io_mut().pop_tx().is_none(), "nor within 6 seconds");

    bench.fe.step(7_100);
    let tx = bench.fe.io_mut().pop_tx().expect("a Port Unreachable");
    assert_eq!(tx.egress, IfId(1));
    assert_eq!(&tx.bytes[0..6], &GATEWAY_MAC);
    let ip = 14;
    assert_eq!(tx.bytes[ip + 9], 1, "ICMP");
    assert_eq!(&tx.bytes[ip + 16..ip + 20], &INTERNET);
    assert_eq!((tx.bytes[ip + 20], tx.bytes[ip + 21]), (3, 3));
    assert_eq!(&tx.bytes[ip + 28..ip + 48], &syn[..20], "it quotes the SYN");
    assert!(bench.fe.io_mut().pop_tx().is_none(), "once");
}

/// When the Port Unreachable for an unsolicited SYN is due and the neighbor it goes
/// to is not known yet, the neighbor process is asked for it.
#[test]
fn a_due_syn_answer_to_an_unknown_neighbor_asks_for_it() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    assert_eq!(
        bench.patch(&mut config, &[nat(40_000, 40_009)]),
        Code::CHANGED
    );
    let syn = tcp_packet(INTERNET, [198, 51, 100, 2], (50_000, 40_005), 0x02);
    bench.fe.io_mut().inject(IfId(1), from_wan(&syn));
    bench.fe.step(1_000);
    let before = bench.fe.counters().resolve_requests;
    bench.fe.step(7_100);
    assert_eq!(bench.fe.counters().resolve_requests, before + 1);
}

/// With NAT, datagrams that may be fragmented are limited so that a tuple's IPv4
/// IDs do not repeat within 120 seconds (RFC 6864 5.2): at one instant, 65536 go
/// and the next is dropped. With `ipv4_id_rate_limit` off, it goes. Slow in a
/// debug build (65536 datagrams): `cargo test -p ruster-fe --test fe -- --ignored`.
#[test]
#[ignore = "slow: 65536 datagrams"]
fn the_nat_limits_the_ipv4_ids_and_the_limit_can_be_turned_off() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
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
    let frame = udp_from_host(INTERNET);
    assert_eq!(frame[14 + 6] & 0x40, 0, "DF is clear");
    let mut sent = 0;
    for _ in 0..65_536 / 64 {
        for _ in 0..64 {
            bench.fe.io_mut().inject(IfId(0), frame.clone());
        }
        bench.fe.step(1_000);
        sent += std::iter::from_fn(|| bench.fe.io_mut().pop_tx()).count();
    }
    assert_eq!(sent, 65_536);
    bench.fe.io_mut().inject(IfId(0), frame.clone());
    bench.fe.step(1_000);
    assert!(bench.fe.io_mut().pop_tx().is_none(), "the 65537th waits");

    let Change {
        key,
        value: Some(Value::Nat(mut off)),
    } = nat(40_000, 40_009)
    else {
        unreachable!()
    };
    off.ipv4_id_rate_limit = false;
    assert_eq!(
        bench.patch(&mut config, &[Change::set(key, Value::Nat(off))]),
        Code::CHANGED
    );
    bench.fe.io_mut().inject(IfId(0), frame);
    bench.fe.step(1_000);
    assert!(
        bench.fe.io_mut().pop_tx().is_some(),
        "without the limit it goes"
    );
}

/// With `ports-per-host`, one LAN host holds at most that many public ports
/// (RFC 6888 REQ-4): with 1, its second UDP flow is not translated.
#[test]
fn the_nat_limits_the_ports_of_one_host() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    bench.patch(
        &mut neighbors,
        &[
            neighbor("wan", GATEWAY, GATEWAY_MAC),
            neighbor("lan", [192, 0, 2, 10], HOST_MAC),
        ],
    );
    let Change {
        key,
        value: Some(Value::Nat(mut limited)),
    } = nat(40_000, 40_009)
    else {
        unreachable!()
    };
    limited.ports_per_host = 1;
    assert_eq!(
        bench.patch(&mut config, &[Change::set(key, Value::Nat(limited))]),
        Code::CHANGED
    );
    let flow = |port: u16| from_lan(&udp_packet([192, 0, 2, 10], INTERNET, (port, 53)));
    bench.fe.io_mut().inject(IfId(0), flow(5_000));
    bench.fe.step(1_000);
    assert!(bench.fe.io_mut().pop_tx().is_some(), "the first flow");
    bench.fe.io_mut().inject(IfId(0), flow(5_001));
    bench.fe.step(1_000);
    assert!(
        bench.fe.io_mut().pop_tx().is_none(),
        "a second port is refused"
    );
    bench.fe.io_mut().inject(IfId(0), flow(5_000));
    bench.fe.step(1_000);
    assert!(
        bench.fe.io_mut().pop_tx().is_some(),
        "the first flow goes on"
    );
}

/// With a firewall, the Port Unreachable the router's kernel sends about a UDP
/// datagram a rule let in leaves as related to that flow (RFC 6092); one about a
/// datagram no flow saw does not.
#[test]
fn the_router_s_icmp_error_about_a_flow_it_received_leaves_as_related() {
    let udp_in = rule_for(
        1,
        ruster_proto::table::Protocol::Udp,
        None,
        Some("rt-default"),
    );
    let (mut bench, kernel) = router_with_firewall(&[udp_in]);
    let router = [198, 51, 100, 2];
    let datagram = udp_packet(INTERNET, router, (40_000, 9_999));
    bench.fe.io_mut().inject(IfId(1), from_wan(&datagram));
    bench.fe.step(bench.now);
    let mut buf = [0_u8; 2048];
    let n = kernel.recv(&mut buf).expect("the rule lets it in");
    assert_eq!(&buf[..n], &datagram[..]);

    let port_unreachable = |quoted: &[u8]| {
        let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&quoted[..28]);
        let checksum = ruster_core::internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        let mut p = vec![0_u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 1;
        p[12..16].copy_from_slice(&router);
        p[16..20].copy_from_slice(&INTERNET);
        p.extend_from_slice(&icmp);
        ipv4_checksummed(p)
    };
    kernel.send(&port_unreachable(&datagram)).unwrap();
    bench.fe.step(bench.now);
    let tx = bench
        .fe
        .io_mut()
        .pop_tx()
        .expect("related to the flow, it leaves");
    assert_eq!(tx.egress, IfId(1));
    assert_eq!((tx.bytes[34], tx.bytes[35]), (3, 3));

    // About a datagram that never came in: nothing of it is in the firewall.
    let other = udp_packet([203, 0, 113, 99], router, (40_001, 9_999));
    let mut stray = port_unreachable(&other);
    stray[16..20].copy_from_slice(&[203, 0, 113, 99]);
    let stray = ipv4_checksummed(stray);
    kernel.send(&stray).unwrap();
    bench.fe.step(bench.now);
    assert!(
        bench.fe.io_mut().pop_tx().is_none(),
        "unrelated, it is dropped"
    );
}

/// An interface keeps its id across a table change: a firewall flow through VLAN
/// 20 still lets its replies in after VLAN 10, whose name comes first, is added.
#[test]
fn a_flow_through_a_vlan_survives_adding_a_vlan_before_it() {
    let mut bench = Bench::new();
    let (mut config, mut routes) = configure(&mut bench);
    let sub = |name: &str, id: u16| {
        Change::set(
            Key::Interface { name: name.into() },
            Value::Interface {
                enabled: true,
                mac: LAN_MAC,
                mtu: 1496,
                vrf: ruster_proto::table::DEFAULT_VRF.into(),
                vlan: Some(ruster_proto::table::Vlan {
                    parent: "lan".into(),
                    id,
                }),
                tunnel: None,
                pppoe: None,
            },
        )
    };
    let udp_out = rule_for(1, ruster_proto::table::Protocol::Udp, Some("lan.20"), None);
    assert_eq!(
        bench.patch(
            &mut config,
            &[
                sub("lan.20", 20),
                address("lan.20", [10, 20, 0, 1], 24),
                udp_out
            ]
        ),
        Code::CHANGED
    );
    assert_eq!(
        bench.patch(&mut routes, &[route([10, 20, 0, 0], 24, "lan.20", None)]),
        Code::CHANGED
    );
    let host = [10, 20, 0, 5];
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(
            &mut neighbors,
            &[
                neighbor("lan.20", host, HOST_MAC),
                neighbor("wan", GATEWAY, GATEWAY_MAC)
            ]
        ),
        Code::CHANGED
    );
    let mut out = Vec::new();
    out.extend_from_slice(&LAN_MAC);
    out.extend_from_slice(&HOST_MAC);
    out.extend_from_slice(&[0x81, 0x00, 0x00, 20, 0x08, 0x00]);
    out.extend_from_slice(&udp_packet(host, INTERNET, (5_000, 53)));
    bench.fe.io_mut().inject(IfId(0), out);
    bench.fe.step(bench.now);
    assert_eq!(bench.fe.io_mut().pop_tx().expect("out").egress, IfId(1));
    let reply = || from_wan(&udp_packet(INTERNET, host, (53, 5_000)));
    bench.fe.io_mut().inject(IfId(1), reply());
    bench.fe.step(bench.now);
    assert!(bench.fe.io_mut().pop_tx().is_some(), "the reply comes in");

    assert_eq!(
        bench.patch(
            &mut config,
            &[sub("lan.10", 10), address("lan.10", [10, 10, 0, 1], 24)]
        ),
        Code::CHANGED
    );
    bench.fe.io_mut().inject(IfId(1), reply());
    bench.fe.step(bench.now);
    let tx = bench
        .fe
        .io_mut()
        .pop_tx()
        .expect("the flow was carried across the change");
    assert_eq!(&tx.bytes[12..16], &[0x81, 0x00, 0x00, 20]);
}

/// A flow red leaked into the default VRF (through red's `lookup-vrf`) and the
/// default VRF's firewall let out stops letting replies in once red's lookup is
/// removed: the flow's own VRF has another route then.
#[test]
fn a_leaked_flow_goes_when_the_leak_is_removed() {
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
    // The default VRF's rules name no other VRF's interface: by red's addresses.
    let udp_from_red = Change::set(
        Key::FirewallRule {
            vrf: "default".into(),
            id: 1,
        },
        Value::FirewallRule(ruster_proto::table::FirewallRule {
            ingress: None,
            egress: None,
            source: (Ipv4Addr::new(192, 0, 2, 0).into(), 24),
            destination: (Ipv4Addr::UNSPECIFIED.into(), 0),
            protocol: ruster_proto::table::Protocol::Udp,
            source_ports: (0, 65_535),
            destination_ports: (0, 65_535),
            action: ruster_proto::table::FirewallAction::Accept,
        }),
    );
    assert_eq!(
        bench.patch(
            &mut config,
            &[
                red_lan,
                iface("wan", WAN_MAC),
                address("lan", [192, 0, 2, 1], 24),
                address("wan", [198, 51, 100, 2], 24),
                udp_from_red,
            ],
        ),
        Code::CHANGED
    );
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
    let back_to_red = RouteAction::Forward(vec![NextHop {
        interface: "lan".into(),
        address: None,
    }]);
    assert_eq!(
        bench.patch(
            &mut routes,
            &[
                in_vrf("default", [0, 0, 0, 0], 0, via_gateway),
                in_vrf("default", [192, 0, 2, 0], 24, back_to_red),
                in_vrf(
                    "red",
                    [0, 0, 0, 0],
                    0,
                    RouteAction::LookupVrf("default".into())
                ),
            ],
        ),
        Code::CHANGED
    );
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(
            &mut neighbors,
            &[
                neighbor("wan", GATEWAY, GATEWAY_MAC),
                neighbor("lan", [192, 0, 2, 10], HOST_MAC)
            ]
        ),
        Code::CHANGED
    );
    bench
        .fe
        .io_mut()
        .inject(IfId(0), udp_from_host([203, 0, 113, 7]));
    bench.fe.step(bench.now);
    assert_eq!(
        bench.fe.io_mut().pop_tx().expect("leaked out").egress,
        IfId(1)
    );
    let reply = || from_wan(&udp_packet([203, 0, 113, 7], [192, 0, 2, 10], (2000, 1000)));
    bench.fe.io_mut().inject(IfId(1), reply());
    bench.fe.step(bench.now);
    let back = bench.fe.io_mut().pop_tx();
    assert_eq!(
        back.map(|tx| tx.egress),
        Some(IfId(0)),
        "the reply comes back"
    );

    // Red's lookup into the default VRF is removed.
    assert_eq!(
        bench.patch(
            &mut routes,
            &[Change::delete(Key::Route {
                vrf: "red".into(),
                prefix: Ipv4Addr::UNSPECIFIED.into(),
                len: 0,
            })]
        ),
        Code::CHANGED
    );
    bench.fe.io_mut().inject(IfId(1), reply());
    bench.fe.step(bench.now);
    assert!(
        bench.fe.io_mut().pop_tx().is_none(),
        "the leaked flow is gone"
    );
}

/// A table change that raises a per-host limit keeps the NAT's flows; one that
/// lowers it flushes them, so no host is carried over its new limit.
#[test]
fn raising_a_per_host_limit_keeps_flows_and_lowering_it_flushes_them() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    bench.patch(
        &mut neighbors,
        &[
            neighbor("wan", GATEWAY, GATEWAY_MAC),
            neighbor("lan", [192, 0, 2, 10], HOST_MAC),
        ],
    );
    let limited = |ports| {
        let Change {
            key,
            value: Some(Value::Nat(mut nat)),
        } = nat(40_000, 40_009)
        else {
            unreachable!()
        };
        nat.ports_per_host = ports;
        Change::set(key, Value::Nat(nat))
    };
    assert_eq!(bench.patch(&mut config, &[limited(4)]), Code::CHANGED);
    let out = |bench: &mut Bench| {
        bench.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
        bench.fe.step(bench.now);
        let tx = bench.fe.io_mut().pop_tx().expect("translated");
        u16::from_be_bytes([tx.bytes[34], tx.bytes[35]])
    };
    let port = out(&mut bench);
    let reply_gets_in = |bench: &mut Bench| {
        let mut frame = udp_reply_to_host();
        frame[30..34].copy_from_slice(&[198, 51, 100, 2]);
        frame[36..38].copy_from_slice(&port.to_be_bytes());
        frame[24..26].fill(0);
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        frame[40..42].fill(0);
        bench.fe.io_mut().inject(IfId(1), frame);
        bench.fe.step(bench.now);
        bench.fe.io_mut().pop_tx().is_some()
    };
    assert!(reply_gets_in(&mut bench));

    assert_eq!(bench.patch(&mut config, &[limited(8)]), Code::CHANGED);
    assert!(
        reply_gets_in(&mut bench),
        "a higher limit keeps the mapping"
    );
    assert_eq!(bench.patch(&mut config, &[limited(2)]), Code::CHANGED);
    assert!(!reply_gets_in(&mut bench), "a lower limit flushes it");
}

/// An error from outside about the router's own translated flow reaches the
/// router's kernel even with TTL 1: it is not forwarded on.
#[test]
fn an_outside_error_with_ttl_1_about_the_router_s_flow_reaches_it() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    assert_eq!(
        bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]),
        Code::CHANGED
    );
    assert_eq!(
        bench.patch(&mut config, &[nat(40_000, 40_009)]),
        Code::CHANGED
    );
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    kernel.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));

    // The router's own UDP, from its LAN address, goes out through NAT.
    kernel
        .send(&udp_packet([192, 0, 2, 1], INTERNET, (5_353, 53)))
        .unwrap();
    bench.fe.step(bench.now);
    let out = bench.fe.io_mut().pop_tx().expect("translated");
    let translated = out.bytes[14..].to_vec();
    assert_eq!(&translated[12..16], &[198, 51, 100, 2]);

    let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&translated[..28]);
    let checksum = ruster_core::internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    let mut error = vec![0_u8; 20];
    error[0] = 0x45;
    error[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    error[8] = 1;
    error[9] = 1;
    error[12..16].copy_from_slice(&INTERNET);
    error[16..20].copy_from_slice(&[198, 51, 100, 2]);
    error.extend_from_slice(&icmp);
    let mut buf = [0_u8; 2048];
    // TTL 1, and TTL 0 too: neither is forwarded, and its TTL stays.
    for ttl in [1, 0] {
        error[8] = ttl;
        let error = ipv4_checksummed(error.clone());
        bench.fe.io_mut().inject(IfId(1), from_wan(&error));
        bench.fe.step(bench.now);
        kernel.recv(&mut buf).expect("the error reached the router");
        assert_eq!((buf[20], buf[21]), (3, 3));
        assert_eq!(buf[8], ttl, "its TTL stays");
        assert_eq!(
            &buf[16..20],
            &[192, 0, 2, 1],
            "addressed back to the LAN address"
        );
    }
}

fn punt_class(
    name: &str,
    matches: ruster_proto::table::PuntMatch,
    interface: Option<&str>,
    destination: ruster_proto::table::PuntDestination,
    rate: u32,
    burst: u32,
) -> Change {
    Change::set(
        Key::Punt { class: name.into() },
        Value::Punt(ruster_proto::table::PuntClass {
            matches,
            interface: interface.map(Into::into),
            destination,
            rate,
            burst,
        }),
    )
}

fn udp_port(protocol: u8, ports: Option<(u16, u16)>) -> ruster_proto::table::PuntMatch {
    ruster_proto::table::PuntMatch::Ip { protocol, ports }
}

/// A UDP packet from the LAN host to the router's LAN address, port 2000.
fn udp_to_router() -> Vec<u8> {
    let mut frame = udp_from_host([192, 0, 2, 1]);
    frame[14 + 10..14 + 12].copy_from_slice(&[0, 0]);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[14 + 10..14 + 12].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn punt_counter(bench: &Bench, name: &str) -> ruster_fe::PuntCounters {
    bench
        .fe
        .punt_counters()
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, c)| c)
        .unwrap_or_else(|| panic!("no class {name}"))
}

#[test]
fn punt_classes_limit_and_drop_traffic_to_the_kernel_by_their_own_rates() {
    use ruster_proto::table::{PuntDestination, PuntKind, PuntMatch};
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    kernel.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));

    // Port 2000 on the LAN: 2 at once; the built-in udp class: 3 at once.
    let code = bench.patch(
        &mut config,
        &[
            punt_class(
                "app",
                udp_port(17, Some((2000, 2000))),
                Some("lan"),
                PuntDestination::Kernel,
                1,
                2,
            ),
            punt_class(
                "udp",
                PuntMatch::Kind(PuntKind::Udp),
                None,
                PuntDestination::Kernel,
                1,
                3,
            ),
        ],
    );
    assert_eq!(code, Code::CHANGED);
    for _ in 0..5 {
        bench.fe.io_mut().inject(IfId(0), udp_to_router());
    }
    bench.fe.step(0);
    let mut buf = [0_u8; 2048];
    let mut got = 0;
    while kernel.recv(&mut buf).is_ok() {
        got += 1;
    }
    assert_eq!(got, 2);
    let app = punt_counter(&bench, "app");
    assert_eq!((app.handed, app.dropped), (2, 3));

    // Another port falls into the built-in udp class.
    let mut other = udp_to_router();
    other[14 + 22..14 + 24].copy_from_slice(&2001_u16.to_be_bytes());
    for _ in 0..5 {
        bench.fe.io_mut().inject(IfId(0), other.clone());
    }
    bench.fe.step(0);
    let udp = punt_counter(&bench, "udp");
    assert_eq!((udp.handed, udp.dropped), (3, 2));
    while kernel.recv(&mut buf).is_ok() {}

    // Dropping the class: nothing more reaches the kernel; its counters stay.
    let code = bench.patch(
        &mut config,
        &[punt_class(
            "app",
            udp_port(17, Some((2000, 2000))),
            Some("lan"),
            PuntDestination::Drop,
            1,
            2,
        )],
    );
    assert_eq!(code, Code::CHANGED);
    bench.fe.io_mut().inject(IfId(0), udp_to_router());
    bench.fe.step(10_000);
    assert!(kernel.recv(&mut buf).is_err());
    let app = punt_counter(&bench, "app");
    assert_eq!((app.handed, app.dropped), (2, 4));

    // Deleting the built-in class's entry brings back its default rate.
    let code = bench.patch(
        &mut config,
        &[Change::delete(Key::Punt {
            class: "udp".into(),
        })],
    );
    assert_eq!(code, Code::CHANGED);
    for _ in 0..50 {
        bench.fe.io_mut().inject(IfId(0), other.clone());
    }
    bench.fe.step(20_000);
    assert_eq!(punt_counter(&bench, "udp").handed, 3 + 50);
}

#[test]
fn arp_is_counted_by_its_built_in_class() {
    let mut bench = Bench::new();
    let (_config, _routes) = configure(&mut bench);
    let (fe_end, _neighd_end) = UnixDatagram::pair().unwrap();
    bench.fe.attach_punt(fe_end).unwrap();
    bench
        .fe
        .io_mut()
        .inject(IfId(0), arp_request([192, 0, 2, 1]));
    bench.fe.step(0);
    let arp = punt_counter(&bench, "arp");
    assert_eq!((arp.handed, arp.dropped), (1, 0));
    let names: Vec<String> = bench
        .fe
        .punt_counters()
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(
        names,
        [
            "arp",
            "nd",
            "icmp-error",
            "icmp",
            "tcp-syn",
            "tcp",
            "udp",
            "other"
        ]
    );
}

#[test]
fn punt_classes_that_break_the_rules_are_refused() {
    use ruster_proto::table::{PuntDestination, PuntKind, PuntMatch};
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let neighd = || PuntDestination::Control("neighd".into());
    let refused = [
        // ARP only goes to the neighbor process.
        vec![punt_class(
            "arp",
            PuntMatch::Kind(PuntKind::Arp),
            None,
            PuntDestination::Drop,
            1,
            1,
        )],
        // A built-in class has no interface.
        vec![punt_class(
            "icmp",
            PuntMatch::Kind(PuntKind::Icmp),
            Some("lan"),
            PuntDestination::Kernel,
            1,
            1,
        )],
        // A built-in name with another match.
        vec![punt_class(
            "udp",
            udp_port(17, None),
            None,
            PuntDestination::Kernel,
            1,
            1,
        )],
        // A fixed kind under another name.
        vec![punt_class(
            "more-arp",
            PuntMatch::Kind(PuntKind::Arp),
            None,
            neighd(),
            1,
            1,
        )],
        // Two classes that can match the same packet.
        vec![
            punt_class(
                "a",
                udp_port(17, Some((60, 70))),
                Some("lan"),
                PuntDestination::Kernel,
                1,
                1,
            ),
            punt_class(
                "b",
                udp_port(17, Some((70, 80))),
                None,
                PuntDestination::Kernel,
                1,
                1,
            ),
        ],
        vec![
            punt_class("a", udp_port(6, None), None, PuntDestination::Kernel, 1, 1),
            punt_class(
                "b",
                udp_port(6, Some((22, 22))),
                Some("wan"),
                PuntDestination::Kernel,
                1,
                1,
            ),
        ],
    ];
    for changes in refused {
        assert_eq!(
            bench.patch(&mut config, &changes),
            Code::BAD_REQUEST,
            "{changes:?}"
        );
    }
    // The same ports on two interfaces, and other ports, are fine; so is changing
    // ARP's rate.
    let code = bench.patch(
        &mut config,
        &[
            punt_class(
                "a",
                udp_port(17, Some((60, 70))),
                Some("lan"),
                PuntDestination::Kernel,
                1,
                1,
            ),
            punt_class(
                "b",
                udp_port(17, Some((60, 70))),
                Some("wan"),
                PuntDestination::Kernel,
                1,
                1,
            ),
            punt_class(
                "c",
                udp_port(17, Some((71, 80))),
                None,
                PuntDestination::Kernel,
                1,
                1,
            ),
            punt_class(
                "arp",
                PuntMatch::Kind(PuntKind::Arp),
                None,
                neighd(),
                10,
                10,
            ),
        ],
    );
    assert_eq!(code, Code::CHANGED);
}

fn to_control(name: &str) -> ruster_proto::table::PuntDestination {
    ruster_proto::table::PuntDestination::Control(name.into())
}

/// A DHCPDISCOVER-like frame from the LAN host to 255.255.255.255, port 67.
fn dhcp_broadcast() -> Vec<u8> {
    let mut frame = udp_from_host([255, 255, 255, 255]);
    frame[0..6].copy_from_slice(&[0xff; 6]);
    frame[14 + 12..14 + 16].copy_from_slice(&[0, 0, 0, 0]);
    frame[14 + 20..14 + 22].copy_from_slice(&68_u16.to_be_bytes());
    frame[14 + 22..14 + 24].copy_from_slice(&67_u16.to_be_bytes());
    frame
}

fn recv_punt(socket: &UnixDatagram) -> (u16, String, Vec<u8>) {
    let mut buf = [0_u8; 2048];
    let n = socket
        .recv(&mut buf)
        .expect("a frame for the control process");
    let punt = Punt::decode(&buf[..n]).unwrap();
    assert_eq!(punt.direction, Direction::ToControl);
    (punt.reason, punt.interface.to_owned(), punt.frame.to_vec())
}

fn send_punt(socket: &UnixDatagram, reason: u16, interface: &str, frame: &[u8]) {
    let mut message = Vec::new();
    Punt {
        direction: Direction::FromControl,
        reason,
        interface,
        frame,
    }
    .encode(&mut message)
    .unwrap();
    socket.send(&message).unwrap();
}

#[test]
fn dhcp_from_the_lan_goes_to_its_control_process_and_its_replies_go_out() {
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let (fe_end, kernel) = UnixDatagram::pair().unwrap();
    fe_end.set_nonblocking(true).unwrap();
    kernel.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(fe_end));
    let code = bench.patch(
        &mut config,
        &[punt_class(
            "dhcpv4",
            udp_port(17, Some((67, 67))),
            Some("lan"),
            to_control("ruster-kea"),
            100,
            2,
        )],
    );
    assert_eq!(code, Code::CHANGED);
    let (fe_end, kea) = UnixDatagram::pair().unwrap();
    kea.set_nonblocking(true).unwrap();
    bench.fe.attach_control("ruster-kea", fe_end).unwrap();

    // To the broadcast address, and to the router's own address: whole frames.
    let broadcast = dhcp_broadcast();
    let mut unicast = udp_to_router();
    unicast[14 + 22..14 + 24].copy_from_slice(&67_u16.to_be_bytes());
    bench.fe.io_mut().inject(IfId(0), broadcast.clone());
    bench.fe.io_mut().inject(IfId(0), unicast.clone());
    bench.fe.step(0);
    assert_eq!(recv_punt(&kea), (punt::reason::IP, "lan".into(), broadcast));
    assert_eq!(recv_punt(&kea), (punt::reason::IP, "lan".into(), unicast));
    let mut buf = [0_u8; 2048];
    assert!(kernel.recv(&mut buf).is_err(), "not to the kernel");
    assert!(bench.fe.io_mut().pop_tx().is_none(), "nor forwarded");

    // The burst is 2: a third is dropped and counted.
    bench.fe.io_mut().inject(IfId(0), dhcp_broadcast());
    bench.fe.step(0);
    assert!(kea.recv(&mut buf).is_err());
    let counters = punt_counter(&bench, "dhcpv4");
    assert_eq!((counters.handed, counters.dropped), (2, 1));
    // On the WAN the class does not apply: the broadcast is not forwarded either.
    bench.fe.io_mut().inject(IfId(1), dhcp_broadcast());
    bench.fe.step(1_000);
    assert!(kea.recv(&mut buf).is_err());

    // The reply goes out of the named interface as it is; a PPPoE frame from this
    // process, which has no PPPoE class, does not.
    let mut reply = dhcp_broadcast();
    reply[6..12].copy_from_slice(&LAN_MAC);
    send_punt(&kea, punt::reason::IP, "lan", &reply);
    let mut padi = vec![0xff_u8; 6];
    padi.extend_from_slice(&LAN_MAC);
    padi.extend_from_slice(&[0x88, 0x63, 0x11, 0x09, 0, 0, 0, 0]);
    send_punt(&kea, punt::reason::PPPOE_DISCOVERY, "lan", &padi);
    let dropped = bench.fe.counters().inject_dropped;
    // After steps that forwarded packets the FE may leave the sockets for a
    // later step; the second one reads them.
    bench.fe.step(1_000);
    bench.fe.step(1_000);
    let tx = bench.fe.io_mut().pop_tx().expect("the reply");
    assert_eq!((tx.egress, tx.bytes), (IfId(0), reply));
    assert!(bench.fe.io_mut().pop_tx().is_none());
    assert_eq!(bench.fe.counters().inject_dropped, dropped + 1);
}

/// A PPPoE frame from the access concentrator to the WAN port.
fn pppoe_frame(ethertype: u16, session: u16, protocol: Option<u16>) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&WAN_MAC);
    frame.extend_from_slice(&GATEWAY_MAC);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(&[0x11, if protocol.is_some() { 0 } else { 0x07 }]);
    frame.extend_from_slice(&session.to_be_bytes());
    frame.extend_from_slice(&6_u16.to_be_bytes());
    if let Some(protocol) = protocol {
        frame.extend_from_slice(&protocol.to_be_bytes());
    }
    frame.resize(60, 0);
    frame
}

#[test]
fn pppoe_control_goes_to_its_control_process() {
    use ruster_proto::table::{PuntKind, PuntMatch};
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let code = bench.patch(
        &mut config,
        &[
            punt_class(
                "pppoe-discovery",
                PuntMatch::Kind(PuntKind::PppoeDiscovery),
                Some("wan"),
                to_control("ruster-pppoed"),
                10,
                10,
            ),
            punt_class(
                "ppp-control",
                PuntMatch::Kind(PuntKind::PppControl),
                Some("wan"),
                to_control("ruster-pppoed"),
                10,
                10,
            ),
        ],
    );
    assert_eq!(code, Code::CHANGED);
    let (fe_end, pppoed) = UnixDatagram::pair().unwrap();
    pppoed.set_nonblocking(true).unwrap();
    bench.fe.attach_control("ruster-pppoed", fe_end).unwrap();

    let pado = pppoe_frame(0x8863, 0, None);
    let lcp = pppoe_frame(0x8864, 0x1234, Some(0xc021));
    let ipv4 = pppoe_frame(0x8864, 0x1234, Some(0x0021));
    for frame in [&pado, &lcp, &ipv4] {
        bench.fe.io_mut().inject(IfId(1), frame.clone());
    }
    bench.fe.step(0);
    assert_eq!(
        recv_punt(&pppoed),
        (punt::reason::PPPOE_DISCOVERY, "wan".into(), pado)
    );
    assert_eq!(
        recv_punt(&pppoed),
        (punt::reason::PPP_CONTROL, "wan".into(), lcp.clone())
    );
    let mut buf = [0_u8; 2048];
    assert!(
        pppoed.recv(&mut buf).is_err(),
        "session data is not control"
    );

    // The daemon's own LCP goes out of the WAN port.
    let mut answer = lcp;
    answer[0..6].copy_from_slice(&GATEWAY_MAC);
    answer[6..12].copy_from_slice(&WAN_MAC);
    send_punt(&pppoed, punt::reason::PPP_CONTROL, "wan", &answer);
    bench.fe.step(1);
    let tx = bench.fe.io_mut().pop_tx().expect("sent");
    assert_eq!((tx.egress, tx.bytes), (IfId(1), answer));
}

#[test]
fn with_a_socket_directory_the_fe_binds_a_socket_per_control_process() {
    let dir = std::env::temp_dir().join(format!("ruster-fe-control-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let mut bench = Bench::new();
    bench.fe.set_punt_dir(dir.clone());
    let (mut config, _routes) = configure(&mut bench);
    let code = bench.patch(
        &mut config,
        &[punt_class(
            "dhcpv4",
            udp_port(17, Some((67, 67))),
            Some("lan"),
            to_control("ruster-kea"),
            100,
            10,
        )],
    );
    assert_eq!(code, Code::CHANGED);
    let fe_path = dir.join("fe/punt/ruster-kea.sock");
    assert!(fe_path.exists());
    std::fs::create_dir(dir.join("ruster-kea")).unwrap();
    let kea = UnixDatagram::bind(dir.join("ruster-kea/punt.sock")).unwrap();
    kea.connect(&fe_path).unwrap();
    bench.fe.io_mut().inject(IfId(0), dhcp_broadcast());
    bench.fe.step(0);
    assert_eq!(recv_punt(&kea).1, "lan");

    // Frames back only from the process's own path.
    let mut reply = dhcp_broadcast();
    reply[6..12].copy_from_slice(&LAN_MAC);
    send_punt(&kea, punt::reason::IP, "lan", &reply);
    let stranger = UnixDatagram::unbound().unwrap();
    stranger.connect(&fe_path).unwrap();
    send_punt(&stranger, punt::reason::IP, "lan", &reply);
    bench.fe.step(1);
    assert_eq!(bench.fe.io_mut().pop_tx().expect("sent").bytes, reply);
    assert!(bench.fe.io_mut().pop_tx().is_none());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn punt_classes_for_control_processes_follow_the_rules() {
    use ruster_proto::table::{PuntKind, PuntMatch};
    let mut bench = Bench::new();
    let (mut config, _routes) = configure(&mut bench);
    let discovery = |interface: Option<&str>| {
        punt_class(
            "pppoe-discovery",
            PuntMatch::Kind(PuntKind::PppoeDiscovery),
            interface,
            to_control("ruster-pppoed"),
            1,
            1,
        )
    };
    let refused = [
        // Only ARP and ND go to the neighbor process.
        vec![punt_class(
            "x",
            udp_port(17, None),
            None,
            to_control("neighd"),
            1,
            1,
        )],
        // A name whose socket would be the neighbor process's.
        vec![punt_class(
            "x",
            udp_port(17, None),
            None,
            to_control("arp-nd"),
            1,
            1,
        )],
        // ICMPv6 to link-local multicast is Neighbor Discovery's.
        vec![punt_class(
            "x",
            udp_port(58, None),
            None,
            to_control("ruster-x"),
            1,
            1,
        )],
        // Two classes for PPPoE Discovery on the same interface.
        vec![discovery(Some("wan")), {
            let Change { key: _, value } = discovery(None);
            Change {
                key: Key::Punt {
                    class: "more".into(),
                },
                value,
            }
        }],
    ];
    for changes in refused {
        assert_eq!(
            bench.patch(&mut config, &changes),
            Code::BAD_REQUEST,
            "{changes:?}"
        );
    }
}

/// The response to `token`, if `client` has it by now.
fn response(client: &mut Client, token: u32) -> Option<Code> {
    client.poll().1.iter().find_map(|event| match event {
        Event::Response { token: t, code, .. } if *t == token => Some(*code),
        _ => None,
    })
}

/// A sub-interface of `parent` for VLAN `vid`.
fn vlan(name: &str, parent: &str, vid: u16) -> Change {
    Change::set(
        Key::Interface { name: name.into() },
        Value::Interface {
            enabled: true,
            mac: LAN_MAC,
            mtu: 1496,
            vrf: ruster_proto::table::DEFAULT_VRF.into(),
            vlan: Some(ruster_proto::table::Vlan {
                parent: parent.into(),
                id: vid,
            }),
            tunnel: None,
            pppoe: None,
        },
    )
}

#[test]
fn a_detached_control_task_takes_the_connections_and_the_fe_steps_only_its_worker() {
    let mut fe = Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]);
    let mut control = fe.detach_control().expect("the first time");
    assert!(fe.detach_control().is_none());
    assert!(fe.store().is_none());
    let (a, _b) = UnixStream::pair().unwrap();
    assert!(fe.attach(a, writers::CONFIG).is_err());

    let (a, b) = UnixStream::pair().unwrap();
    control.attach(a, writers::CONFIG).unwrap();
    let mut config = Client::new(b).unwrap();
    let token = config
        .patch(&[iface("lan", LAN_MAC), iface("wan", WAN_MAC)])
        .unwrap();
    // The FE alone does not answer: the connection is the control task's.
    fe.step(0);
    assert_eq!(response(&mut config, token), None);
    // Nor the control task alone: the answer says that the worker uses the change.
    control.step(0);
    assert_eq!(response(&mut config, token), None);
    fe.step(0);
    assert_eq!(response(&mut config, token), None);
    control.step(0);
    assert_eq!(response(&mut config, token), Some(Code::CHANGED));
    assert!(!fe.control_gone() && !control.fe_gone());

    drop(control);
    fe.step(0);
    assert!(fe.control_gone());
}

#[test]
fn a_detached_control_task_knows_when_the_fe_is_gone() {
    let mut fe = Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]);
    let mut control = fe.detach_control().unwrap();
    control.step(0);
    assert!(!control.fe_gone());
    drop(fe);
    control.step(0);
    assert!(control.fe_gone());
}

#[test]
fn the_next_change_waits_until_the_worker_uses_the_version_sent() {
    let mut fe = Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]);
    let mut control = fe.detach_control().unwrap();
    let (a, b) = UnixStream::pair().unwrap();
    control.attach(a, writers::CONFIG).unwrap();
    let mut config = Client::new(b).unwrap();

    // "lan.20" takes the first id after the ports.
    let first = config
        .patch(&[
            iface("lan", LAN_MAC),
            iface("wan", WAN_MAC),
            vlan("lan.20", "lan", 20),
        ])
        .unwrap();
    config.poll();
    control.step(0);

    // "lan.10" sorts before it. Built on the ids of the tables before the first
    // change, it would take that id and move "lan.20", which the worker may
    // already use under it. So the change is not looked at yet; and the first is
    // not answered before the worker uses it.
    let second = config.patch(&[vlan("lan.10", "lan", 10)]).unwrap();
    config.poll();
    for _ in 0..3 {
        control.step(0);
        let (_, events) = config.poll();
        assert!(events.is_empty(), "{events:?}");
    }

    // The worker moves to the first version and says so: the first change is
    // answered, and the second is built, on the first one's ids.
    fe.step(0);
    control.step(0);
    assert_eq!(response(&mut config, first), Some(Code::CHANGED));
    assert_eq!(response(&mut config, second), None);
    fe.step(0);
    control.step(0);
    assert_eq!(response(&mut config, second), Some(Code::CHANGED));
    assert!(fe.link_up("lan.20", &[true, true]));
    assert!(fe.link_up("lan.10", &[true, true]));
}

#[test]
fn a_control_task_on_another_thread_feeds_the_worker_and_passes_its_requests_on() {
    let mut fe = Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]);
    let mut control = fe.detach_control().unwrap();
    let mut clients = Vec::new();
    for writes in [writers::CONFIG, writers::ROUTE, writers::NEIGHBOR] {
        let (a, b) = UnixStream::pair().unwrap();
        control.attach(a, writes).unwrap();
        clients.push(Client::new(b).unwrap());
    }
    let thread = std::thread::spawn(move || {
        while !control.fe_gone() {
            if !control.step(0).busy {
                control.wait(std::time::Duration::from_millis(1));
            }
        }
    });
    // Steps the worker until the control thread answered request `token`.
    let answer = |fe: &mut Fe<SimIo>, client: &mut Client, token: u32| {
        for _ in 0..5_000 {
            fe.step(0);
            if let Some(code) = response(client, token) {
                return code;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        panic!("no answer from the control thread");
    };
    let patch = |fe: &mut Fe<SimIo>, client: &mut Client, changes: &[Change]| {
        let token = client.patch(changes).unwrap();
        answer(fe, client, token)
    };
    // Before there is a route, so that the first request is seen. The registration
    // has no answer of its own; the request after it on the same connection has.
    clients[2].observe();
    let token = clients[2].get(&["c"]);
    assert_eq!(answer(&mut fe, &mut clients[2], token), Code::CONTENT);
    let code = patch(
        &mut fe,
        &mut clients[0],
        &[
            iface("lan", LAN_MAC),
            iface("wan", WAN_MAC),
            address("lan", [192, 0, 2, 1], 24),
            address("wan", [198, 51, 100, 2], 24),
        ],
    );
    assert_eq!(code, Code::CHANGED);
    let code = patch(
        &mut fe,
        &mut clients[1],
        &[
            route([192, 0, 2, 0], 24, "lan", None),
            route([198, 51, 100, 0], 24, "wan", None),
            route([0, 0, 0, 0], 0, "wan", Some(GATEWAY)),
        ],
    );
    assert_eq!(code, Code::CHANGED);

    // No neighbor yet: the worker's resolve request reaches the observer through
    // the control thread.
    let mut asked = false;
    for _ in 0..5_000 {
        fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
        fe.step(0);
        let (_, events) = clients[2].poll();
        if events
            .iter()
            .any(|e| matches!(e, Event::Notification { .. }))
        {
            asked = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(asked, "no resolve request");
    while fe.io_mut().pop_tx().is_some() {}

    let code = patch(
        &mut fe,
        &mut clients[2],
        &[neighbor("wan", GATEWAY, GATEWAY_MAC)],
    );
    assert_eq!(code, Code::CHANGED);
    // The answer comes when the version is built, a moment before it is sent to
    // the worker: packets are tried until one is forwarded by it.
    let mut forwarded = None;
    for _ in 0..5_000 {
        fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
        fe.step(0);
        forwarded = fe.io_mut().pop_tx();
        if forwarded.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let tx = forwarded.expect("forwarded");
    assert_eq!(tx.egress, IfId(1));
    assert_eq!(&tx.bytes[0..6], &GATEWAY_MAC);

    drop(fe);
    thread.join().unwrap();
}

/// Steps the control task, then the worker, until the worker sends a frame: the
/// frame, if it came within a few rounds.
fn released(fe: &mut Fe<SimIo>, control: &mut ruster_fe::Control) -> Option<Vec<u8>> {
    for _ in 0..4 {
        control.step(0);
        fe.step(0);
        if let Some(tx) = fe.io_mut().pop_tx() {
            return Some(tx.bytes);
        }
    }
    None
}

#[test]
fn a_frame_from_a_control_process_leaves_after_the_table_change_sent_before_it() {
    let mut fe = Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]);
    let mut control = fe.detach_control().unwrap();
    let (a, b) = UnixStream::pair().unwrap();
    control.attach(a, writers::CONFIG).unwrap();
    let mut config = Client::new(b).unwrap();
    let (a, b) = UnixStream::pair().unwrap();
    control.attach(a, writers::NEIGHBOR).unwrap();
    let mut neighbors = Client::new(b).unwrap();
    let (fe_end, neighd_end) = UnixDatagram::pair().unwrap();
    fe.attach_punt(fe_end).unwrap();
    let token = config
        .patch(&[
            iface("lan", LAN_MAC),
            iface("wan", WAN_MAC),
            address("lan", [192, 0, 2, 1], 24),
        ])
        .unwrap();
    config.poll();
    control.step(0);
    fe.step(0);
    control.step(0);
    assert_eq!(response(&mut config, token), Some(Code::CHANGED));

    // As the neighbor process does: the neighbor first, then the ARP reply to it.
    let token = neighbors
        .patch(&[neighbor("lan", [192, 0, 2, 10], HOST_MAC)])
        .unwrap();
    neighbors.poll();
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

    // The worker has the frame, but the control task has not looked at the change.
    for _ in 0..3 {
        assert!(fe.step(0).busy, "busy while a frame waits");
        assert!(fe.io_mut().pop_tx().is_none(), "the frame waits");
    }
    // It builds the version; the frame still waits for the worker to use it.
    control.step(0);
    fe.step(0);
    assert!(fe.io_mut().pop_tx().is_none(), "the frame waits");
    // Nothing more had arrived: the control task says so, and the frame leaves.
    assert_eq!(released(&mut fe, &mut control), Some(reply));
    assert_eq!(response(&mut neighbors, token), Some(Code::CHANGED));
    assert!(!fe.step(0).busy, "idle again");
}

#[test]
fn without_table_changes_a_frame_from_a_control_process_leaves_once_the_control_task_ran() {
    let mut fe = Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]);
    let mut control = fe.detach_control().unwrap();
    let (a, b) = UnixStream::pair().unwrap();
    control.attach(a, writers::CONFIG).unwrap();
    let mut config = Client::new(b).unwrap();
    let token = config.patch(&[iface("lan", LAN_MAC)]).unwrap();
    config.poll();
    control.step(0);
    fe.step(0);
    control.step(0);
    assert_eq!(response(&mut config, token), Some(Code::CHANGED));
    let (fe_end, neighd_end) = UnixDatagram::pair().unwrap();
    fe.attach_punt(fe_end).unwrap();

    for round in 0..3_u8 {
        // Not zero: a frame to an all-zero address never leaves a port.
        let mut reply = vec![0xa0 + round; 42];
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
        fe.step(0);
        assert!(fe.io_mut().pop_tx().is_none());
        assert_eq!(released(&mut fe, &mut control), Some(reply));
    }

    // With the control task gone nobody answers: frames leave at once.
    drop(control);
    fe.step(0);
    let mut reply = vec![9_u8; 42];
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
    fe.step(0);
    assert_eq!(fe.io_mut().pop_tx().expect("sent").bytes, reply);
}

/// A frame from the neighbor process: an ARP packet out of "lan".
fn frame_from_neighd(fill: u8) -> (Vec<u8>, Vec<u8>) {
    let mut reply = vec![fill; 42];
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
    (reply, message)
}

#[test]
fn a_frame_waits_for_a_change_that_is_behind_more_requests_than_one_step_takes() {
    let mut fe = Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]);
    let mut control = fe.detach_control().unwrap();
    let mut clients = Vec::new();
    for writes in [writers::CONFIG, writers::ROUTE, writers::NEIGHBOR] {
        let (a, b) = UnixStream::pair().unwrap();
        control.attach(a, writes).unwrap();
        clients.push(Client::new(b).unwrap());
    }
    let (fe_end, neighd_end) = UnixDatagram::pair().unwrap();
    fe.attach_punt(fe_end).unwrap();
    let config = clients[0]
        .patch(&[
            iface("lan", LAN_MAC),
            iface("wan", WAN_MAC),
            address("lan", [192, 0, 2, 1], 24),
            address("wan", [198, 51, 100, 2], 24),
        ])
        .unwrap();
    clients[0].poll();
    let routes = clients[1]
        .patch(&[
            route([192, 0, 2, 0], 24, "lan", None),
            route([198, 51, 100, 0], 24, "wan", None),
            route([0, 0, 0, 0], 0, "wan", Some(GATEWAY)),
        ])
        .unwrap();
    clients[1].poll();
    for _ in 0..4 {
        control.step(0);
        fe.step(0);
    }
    assert_eq!(response(&mut clients[0], config), Some(Code::CHANGED));
    assert_eq!(response(&mut clients[1], routes), Some(Code::CHANGED));

    // A hundred requests, more than one step of the control task takes from a
    // connection; then the neighbor; then the frame.
    for _ in 0..100 {
        clients[2].get(&["c"]);
    }
    clients[2]
        .patch(&[neighbor("wan", GATEWAY, GATEWAY_MAC)])
        .unwrap();
    clients[2].flush();
    let (reply, message) = frame_from_neighd(0xab);
    neighd_end.send(&message).unwrap();
    fe.step(0);
    assert!(fe.io_mut().pop_tx().is_none(), "the frame waits");
    assert_eq!(released(&mut fe, &mut control), Some(reply));

    // The worker already uses the neighbor: a packet through it is forwarded with
    // no further step of the control task.
    fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    fe.step(0);
    let tx = fe.io_mut().pop_tx().expect("forwarded");
    assert_eq!(&tx.bytes[0..6], &GATEWAY_MAC);
}

#[test]
fn a_frame_leaves_while_another_writer_never_pauses() {
    let mut fe = Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]);
    let mut control = fe.detach_control().unwrap();
    let (a, b) = UnixStream::pair().unwrap();
    control.attach(a, writers::CONFIG).unwrap();
    let mut config = Client::new(b).unwrap();
    let (fe_end, neighd_end) = UnixDatagram::pair().unwrap();
    fe.attach_punt(fe_end).unwrap();
    config.patch(&[iface("lan", LAN_MAC)]).unwrap();
    config.flush();
    control.step(0);
    fe.step(0);

    let (reply, message) = frame_from_neighd(0xab);
    neighd_end.send(&message).unwrap();
    let mut left_after = None;
    for round in 1..=20_u8 {
        // Another change, each time before the control task looks.
        config
            .patch(&[iface("wan", [2, 0, 0, 0, 1, round])])
            .unwrap();
        config.flush();
        control.step(0);
        fe.step(0);
        if let Some(tx) = fe.io_mut().pop_tx() {
            assert_eq!(tx.bytes, reply);
            left_after = Some(round);
            break;
        }
    }
    // Asked on the first step of the worker, answered on the control task's fourth
    // after that.
    assert_eq!(left_after, Some(5));
}

#[test]
fn a_change_refused_after_its_tables_were_built_does_not_stay_in_the_routes_kept() {
    let mut bench = Bench {
        fe: Fe::new(SimIo::new(), vec!["lan".into(), "wan".into(), "dmz".into()]),
        now: 0,
    };
    let mut config = bench.connect(writers::CONFIG);
    let mut routes = bench.connect(writers::ROUTE);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    let dmz_mac = [2, 0, 0, 0, 0, 3];
    let server_mac = [2, 0, 0, 0, 0, 0x30];
    let code = bench.patch(
        &mut config,
        &[
            iface("lan", LAN_MAC),
            iface("wan", WAN_MAC),
            iface("dmz", dmz_mac),
            address("lan", [192, 0, 2, 1], 24),
            address("wan", [198, 51, 100, 2], 24),
        ],
    );
    assert_eq!(code, Code::CHANGED);
    let code = bench.patch(
        &mut routes,
        &[
            route([192, 0, 2, 0], 24, "lan", None),
            route([10, 0, 0, 0], 8, "dmz", None),
        ],
    );
    assert_eq!(code, Code::CHANGED);
    let code = bench.patch(
        &mut neighbors,
        &[neighbor("dmz", [10, 1, 1, 1], server_mac)],
    );
    assert_eq!(code, Code::CHANGED);

    // One change: "dmz" disabled, and a NAT whose address is not the outside
    // interface's. The tables are built for it; the NAT is refused after that.
    let mut disabled = iface("dmz", dmz_mac);
    if let Some(Value::Interface { enabled, .. }) = &mut disabled.value {
        *enabled = false;
    }
    let mut other = nat(1_000, 2_000);
    if let Some(Value::Nat(nat)) = &mut other.value {
        nat.external = Some(Ipv4Addr::new(203, 0, 113, 99));
    }
    assert_eq!(
        bench.patch(&mut config, &[disabled, other]),
        Code::BAD_REQUEST
    );

    // A change of routes alone follows. The route through "dmz" is still there:
    // the refused change, which would have taken it away, left nothing behind.
    let code = bench.patch(&mut routes, &[route([203, 0, 113, 0], 24, "wan", None)]);
    assert_eq!(code, Code::CHANGED);
    bench
        .fe
        .io_mut()
        .inject(IfId(0), udp_from_host([10, 1, 1, 1]));
    bench.fe.step(0);
    let tx = bench.fe.io_mut().pop_tx().expect("forwarded");
    assert_eq!(tx.egress, IfId(2));
    assert_eq!(&tx.bytes[0..6], &server_mac);
}

/// How long one step of the FE takes with a two-port router's tables, without
/// packets and with batches of forwarded packets. The time around `step` only:
/// putting the packets into `SimIo` and taking them out is not counted.
///
/// Release timing, run on demand:
/// `cargo test --release -p ruster-fe --test fe step_timing -- --ignored --nocapture`
#[test]
#[ignore = "timing report, not a pass/fail test"]
fn step_timing_without_packets_and_with_batches() {
    use std::time::{Duration, Instant};

    let mut bench = Bench::new();
    let (_config, _routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    let code = bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]);
    assert_eq!(code, Code::CHANGED);

    const ROUNDS: u32 = 200_000;
    let frame = udp_from_host(INTERNET);
    let report = |bench: &mut Bench, what: &str| {
        let started = Instant::now();
        for _ in 0..ROUNDS {
            bench.fe.step(0);
        }
        let empty = started.elapsed() / ROUNDS;
        println!("{what}, a step without packets: {empty:?}");
        for batch in [1_u32, 8, 32, 64] {
            let rounds = 100_000 / batch;
            let mut spent = Duration::ZERO;
            for _ in 0..rounds {
                for _ in 0..batch {
                    bench.fe.io_mut().inject(IfId(0), frame.clone());
                }
                let started = Instant::now();
                bench.fe.step(0);
                spent += started.elapsed();
                for _ in 0..batch {
                    assert!(bench.fe.io_mut().pop_tx().is_some(), "forwarded");
                }
            }
            let step = spent / rounds;
            println!(
                "{what}, a step with {batch:>2} packets: {step:?}, {:?} for each packet",
                step / batch
            );
        }
    };
    // As `--one-thread` runs it: the connections are read in the same step.
    report(&mut bench, "with the connections");
    // As it runs by default: the control task is another thread's.
    let _control = bench.fe.detach_control().expect("the control task");
    report(&mut bench, "the worker alone");
    // As the daemon has it: the neighbor process's socket and the default VRF's
    // kernel device are there to be read, with nothing in them.
    let (punt, _neighd) = UnixDatagram::pair().unwrap();
    bench.fe.attach_punt(punt).unwrap();
    let (pipe, _kernel) = UnixDatagram::pair().unwrap();
    pipe.set_nonblocking(true).unwrap();
    bench.fe.attach_local("default", Box::new(pipe));
    report(&mut bench, "the worker with its sockets");
}

/// How long the whole FE takes to make one route change with many routes: the
/// patch answered and the worker forwarding by the new tables.
///
/// Release timing, run on demand:
/// `cargo test --release -p ruster-fe --test fe version_timing -- --ignored --nocapture`
#[test]
#[ignore = "timing report, not a pass/fail test"]
fn version_timing_up_to_a_full_table() {
    use std::time::{Duration, Instant};

    let mut bench = Bench::new();
    let (_config, mut routes) = configure(&mut bench);
    let mut neighbors = bench.connect(writers::NEIGHBOR);
    let code = bench.patch(&mut neighbors, &[neighbor("wan", GATEWAY, GATEWAY_MAC)]);
    assert_eq!(code, Code::CHANGED);
    let route_at = |index: u32| {
        route(
            (0x1000_0000 + (index << 8)).to_be_bytes(),
            24,
            "wan",
            Some(GATEWAY),
        )
    };
    let mut loaded = 0;
    for count in [131_072_u32, 1_048_576] {
        let started = Instant::now();
        for first in (loaded..count).step_by(1000) {
            let changes: Vec<Change> = (first..count.min(first + 1000)).map(route_at).collect();
            assert_eq!(bench.patch(&mut routes, &changes), Code::CHANGED);
        }
        let load = started.elapsed();
        loaded = count;
        let mut spent = Duration::ZERO;
        for round in 0..20 {
            let mut change = route_at(count / 2);
            if round % 2 == 0 {
                change = route(
                    (0x1000_0000 + ((count / 2) << 8)).to_be_bytes(),
                    24,
                    "lan",
                    None,
                );
            }
            let started = Instant::now();
            assert_eq!(bench.patch(&mut routes, &[change]), Code::CHANGED);
            spent += started.elapsed();
        }
        println!(
            "{count} routes: loaded in {load:?}, one route changed in {:?}",
            spent / 20
        );
    }
}
