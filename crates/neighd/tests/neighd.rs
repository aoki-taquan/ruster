//! neighd with a real FE over Unix sockets, packets through `SimIo`.

use std::net::Ipv4Addr;
use std::os::unix::net::{UnixDatagram, UnixStream};

use ruster_core::{ipv4_header_checksum, IfId};
use ruster_fe::{writers, Fe};
use ruster_io_sim::SimIo;
use ruster_neighd::Neighd;
use ruster_proto::session::Client;
use ruster_proto::table::{Change, Key, NextHop, RouteAction, Value};
use ruster_proto::task::Task;

const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const HOST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];
const GATEWAY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
const LAN_IP: [u8; 4] = [192, 0, 2, 1];
const WAN_IP: [u8; 4] = [198, 51, 100, 2];
const HOST: [u8; 4] = [192, 0, 2, 10];
const GATEWAY: [u8; 4] = [198, 51, 100, 1];
const INTERNET: [u8; 4] = [203, 0, 113, 7];

fn local_tables() -> Vec<Change> {
    let iface = |name: &str, mac| {
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
    };
    let address = |name: &str, ip: [u8; 4]| {
        Change::set(
            Key::Address {
                interface: name.into(),
                address: Ipv4Addr::from(ip).into(),
            },
            Value::Address { prefix_len: 24 },
        )
    };
    vec![
        iface("lan", LAN_MAC),
        iface("wan", WAN_MAC),
        address("lan", LAN_IP),
        address("wan", WAN_IP),
    ]
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

struct Lab {
    fe: Fe<SimIo>,
    neighd: Neighd,
    /// Stands in for confd and ribd.
    writers: Vec<Client>,
    now: u64,
}

impl Lab {
    fn new() -> Self {
        let mut fe = Fe::new(SimIo::new(), vec!["lan".into(), "wan".into()]);
        let mut writers = Vec::new();
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, writers::CONFIG).unwrap();
        let mut config = Client::new(b).unwrap();
        config.patch(&local_tables()).unwrap();
        writers.push(config);
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, writers::ROUTE).unwrap();
        let mut routes = Client::new(b).unwrap();
        routes
            .patch(&[
                route([192, 0, 2, 0], 24, "lan", None),
                route([198, 51, 100, 0], 24, "wan", None),
                route([0, 0, 0, 0], 0, "wan", Some(GATEWAY)),
            ])
            .unwrap();
        writers.push(routes);
        let neighd = start_neighd(&mut fe, &mut writers);
        let mut lab = Self {
            fe,
            neighd,
            writers,
            now: 0,
        };
        lab.settle();
        lab
    }

    fn settle(&mut self) {
        for _ in 0..1_000 {
            let mut busy = self.fe.step(self.now).busy;
            busy |= self.neighd.step(self.now).busy;
            for writer in &mut self.writers {
                busy |= writer.poll().0.busy;
            }
            if !busy {
                return;
            }
        }
        panic!("never settled");
    }

    fn restart_neighd(&mut self) {
        self.writers.pop();
        self.neighd = start_neighd(&mut self.fe, &mut self.writers);
        self.settle();
    }

    /// The frames sent, without the probes and announcements of the router's own
    /// addresses ([`Lab::all_tx`] has them).
    fn tx(&mut self) -> Vec<(IfId, Vec<u8>)> {
        self.all_tx()
            .into_iter()
            .filter(|(_, frame)| !is_claim(frame))
            .collect()
    }

    fn all_tx(&mut self) -> Vec<(IfId, Vec<u8>)> {
        let mut out = Vec::new();
        while let Some(frame) = self.fe.io_mut().pop_tx() {
            out.push((frame.egress, frame.bytes));
        }
        out
    }
}

/// An ARP Probe or Announcement (RFC 5227): from no address, or with the sender as
/// the target.
fn is_claim(frame: &[u8]) -> bool {
    frame.len() >= 42
        && frame[12..14] == [0x08, 0x06]
        && (frame[28..32] == [0; 4] || frame[28..32] == frame[38..42])
}

/// Connects a new neighd to the FE (neighbor writer and punt socket) and gives it the
/// local tables the way confd would. The confd stand-in is the last writer.
fn start_neighd(fe: &mut Fe<SimIo>, writers: &mut Vec<Client>) -> Neighd {
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, writers::NEIGHBOR).unwrap();
    let (fe_punt, neighd_punt) = UnixDatagram::pair().unwrap();
    fe.attach_punt(fe_punt).unwrap();
    let mut neighd = Neighd::new(b, neighd_punt).unwrap();
    let (a, b) = UnixStream::pair().unwrap();
    neighd.attach_config(a).unwrap();
    let mut confd = Client::new(b).unwrap();
    confd.patch(&local_tables()).unwrap();
    writers.push(confd);
    neighd
}

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
    frame[ip + 12..ip + 16].copy_from_slice(&HOST);
    frame[ip + 16..ip + 20].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
    frame[ip + 24..ip + 26].copy_from_slice(&26_u16.to_be_bytes());
    frame
}

fn arp(
    opcode: u16,
    destination: [u8; 6],
    sender_mac: [u8; 6],
    sender: [u8; 4],
    target: [u8; 4],
) -> Vec<u8> {
    let mut frame = vec![0_u8; 42];
    frame[0..6].copy_from_slice(&destination);
    frame[6..12].copy_from_slice(&sender_mac);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&opcode.to_be_bytes());
    frame[22..28].copy_from_slice(&sender_mac);
    frame[28..32].copy_from_slice(&sender);
    frame[38..42].copy_from_slice(&target);
    frame
}

#[test]
fn a_missing_gateway_is_resolved_and_then_forwarded_to() {
    let mut lab = Lab::new();
    lab.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    lab.settle();

    let tx = lab.tx();
    assert_eq!(tx.len(), 1, "only the ARP request leaves");
    let (egress, request) = &tx[0];
    assert_eq!(*egress, IfId(1));
    assert_eq!(&request[0..6], &[0xff; 6]);
    assert_eq!(&request[20..22], &1_u16.to_be_bytes());
    assert_eq!(
        &request[28..32],
        &WAN_IP,
        "asks from the router's WAN address"
    );
    assert_eq!(&request[38..42], &GATEWAY);

    lab.fe
        .io_mut()
        .inject(IfId(1), arp(2, WAN_MAC, GATEWAY_MAC, GATEWAY, WAN_IP));
    lab.settle();
    assert_eq!(lab.neighd.counters().learned, 1);

    lab.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    lab.settle();
    let tx = lab.tx();
    assert_eq!(tx.len(), 1);
    assert_eq!(tx[0].0, IfId(1));
    assert_eq!(&tx[0].1[0..6], &GATEWAY_MAC);
}

#[test]
fn arp_for_the_router_is_answered_and_the_asker_learned() {
    let mut lab = Lab::new();
    lab.fe
        .io_mut()
        .inject(IfId(0), arp(1, [0xff; 6], HOST_MAC, HOST, LAN_IP));
    lab.settle();
    let tx = lab.tx();
    assert_eq!(tx.len(), 1);
    let (egress, reply) = &tx[0];
    assert_eq!(*egress, IfId(0));
    assert_eq!(&reply[0..6], &HOST_MAC);
    assert_eq!(&reply[20..22], &2_u16.to_be_bytes());
    assert_eq!(&reply[22..28], &LAN_MAC);
    assert_eq!(&reply[28..32], &LAN_IP);
    assert_eq!(lab.neighd.counters().learned, 1);

    // The host is now reachable without another ARP round.
    let mut to_host = udp_from_host(HOST);
    to_host[14 + 12..14 + 16].copy_from_slice(&[198, 51, 100, 9]);
    let checksum = ipv4_header_checksum(&{
        let mut header = to_host[14..34].to_vec();
        header[10] = 0;
        header[11] = 0;
        header
    });
    to_host[14 + 10..14 + 12].copy_from_slice(&checksum.to_be_bytes());
    to_host[0..6].copy_from_slice(&WAN_MAC);
    lab.fe.io_mut().inject(IfId(1), to_host);
    lab.settle();
    let tx = lab.tx();
    assert_eq!(tx.len(), 1);
    assert_eq!(&tx[0].1[0..6], &HOST_MAC);
}

#[test]
fn an_unanswered_next_hop_is_tried_three_times() {
    let mut lab = Lab::new();
    lab.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    lab.settle();
    for now in [1_000, 2_000, 3_000, 4_000] {
        lab.now = now;
        lab.settle();
    }
    let requests = lab.tx().len();
    assert_eq!(requests, 3);
    assert_eq!(lab.neighd.counters().given_up, 1);
}

#[test]
fn a_restarted_neighd_keeps_the_fe_neighbors() {
    let mut lab = Lab::new();
    lab.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    lab.settle();
    lab.tx();
    lab.fe
        .io_mut()
        .inject(IfId(1), arp(2, WAN_MAC, GATEWAY_MAC, GATEWAY, WAN_IP));
    lab.settle();

    lab.restart_neighd();
    assert_eq!(lab.neighd.counters().adopted, 1);
    assert_eq!(lab.neighd.known(), 1);

    lab.fe.io_mut().inject(IfId(0), udp_from_host(INTERNET));
    lab.settle();
    let tx = lab.tx();
    assert_eq!(tx.len(), 1, "forwarded, no new ARP");
    assert_eq!(&tx[0].1[0..6], &GATEWAY_MAC);
}

/// RFC 5227: each of the router's addresses is probed three times, one second
/// apart, and two seconds later announced twice, two seconds apart.
#[test]
fn the_router_s_addresses_are_probed_and_announced() {
    let mut lab = Lab::new();
    let mut seen = Vec::new();
    for now in (0..=8_000).step_by(500) {
        lab.now = now;
        lab.settle();
        for (egress, frame) in lab.all_tx() {
            if is_claim(&frame) && egress == IfId(0) {
                assert_eq!(&frame[0..6], &[0xff; 6], "broadcast");
                assert_eq!(&frame[38..42], &LAN_IP);
                let probe = frame[28..32] == [0; 4];
                seen.push((now, probe));
            }
        }
    }
    assert_eq!(
        seen,
        [
            (0, true),
            (1_000, true),
            (2_000, true),
            (4_000, false),
            (6_000, false)
        ]
    );
}

/// RFC 5227 section 2.4 (c): another host claiming the router's address is
/// answered with an Announcement, at most once in ten seconds.
#[test]
fn a_host_claiming_the_router_s_address_is_answered_once_in_ten_seconds() {
    let mut lab = Lab::new();
    // The probes and announcements of the start are over by 8 seconds.
    for now in (0..=8_000).step_by(500) {
        lab.now = now;
        lab.settle();
    }
    lab.all_tx();
    let other = [2, 0, 0, 0, 0, 0x66];
    let mut defended = Vec::new();
    for now in [10_000, 12_000, 20_000] {
        lab.now = now;
        lab.fe
            .io_mut()
            .inject(IfId(0), arp(1, [0xff; 6], other, LAN_IP, LAN_IP));
        lab.settle();
        let announcements = lab
            .all_tx()
            .into_iter()
            .filter(|(egress, frame)| *egress == IfId(0) && is_claim(frame))
            .count();
        defended.push(announcements);
    }
    assert_eq!(defended, [1, 0, 1]);
    assert_eq!(lab.neighd.counters().conflicts, 3);
}
