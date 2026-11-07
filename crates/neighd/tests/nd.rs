//! IPv6 Neighbor Discovery: neighd with a real FE over Unix sockets, packets through
//! `SimIo`.

use std::net::{IpAddr, Ipv6Addr};
use std::os::unix::net::{UnixDatagram, UnixStream};

use ruster_core::IfId;
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

fn ip(text: &str) -> Ipv6Addr {
    text.parse().unwrap()
}

fn local_tables() -> Vec<Change> {
    let iface = |name: &str, mac| {
        Change::set(
            Key::Interface { name: name.into() },
            Value::Interface {
                enabled: true,
                mac,
                mtu: 1500,
            },
        )
    };
    let address = |name: &str, address: &str| {
        Change::set(
            Key::Address {
                interface: name.into(),
                address: IpAddr::V6(ip(address)),
            },
            Value::Address { prefix_len: 64 },
        )
    };
    vec![
        iface("lan", LAN_MAC),
        iface("wan", WAN_MAC),
        address("lan", "2001:db8:1::1"),
        address("lan", "fe80::1"),
        address("wan", "fe80::2"),
    ]
}

fn route(prefix: &str, len: u8, interface: &str, via: Option<&str>) -> Change {
    Change::set(
        Key::Route {
            vrf: "default".into(),
            prefix: IpAddr::V6(ip(prefix)),
            len,
        },
        Value::Route(RouteAction::Forward(vec![NextHop {
            interface: interface.into(),
            address: via.map(|v| IpAddr::V6(ip(v))),
        }])),
    )
}

struct Lab {
    fe: Fe<SimIo>,
    neighd: Neighd,
    writers: Vec<Client>,
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
                route("2001:db8:1::", 64, "lan", None),
                route("::", 0, "wan", Some("fe80::fe")),
            ])
            .unwrap();
        writers.push(routes);
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
        let mut lab = Self {
            fe,
            neighd,
            writers,
        };
        lab.settle();
        lab
    }

    fn settle(&mut self) {
        for _ in 0..1_000 {
            let mut busy = self.fe.step(0).busy;
            busy |= self.neighd.step(0).busy;
            for writer in &mut self.writers {
                busy |= writer.poll().0.busy;
            }
            if !busy {
                return;
            }
        }
        panic!("never settled");
    }

    fn tx(&mut self) -> Vec<(IfId, Vec<u8>)> {
        let mut out = Vec::new();
        while let Some(frame) = self.fe.io_mut().pop_tx() {
            out.push((frame.egress, frame.bytes));
        }
        out
    }
}

fn checksum(source: Ipv6Addr, destination: Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&destination.octets());
    bytes.extend_from_slice(&u32::try_from(icmp.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 58]);
    bytes.extend_from_slice(icmp);
    if bytes.len() % 2 == 1 {
        bytes.push(0);
    }
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv6(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    hop_limit: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    frame.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&[next_header, hop_limit]);
    frame.extend_from_slice(&source.octets());
    frame.extend_from_slice(&destination.octets());
    frame.extend_from_slice(payload);
    frame
}

/// An ICMPv6 ND message (type, flags, target, one link-layer option) with its checksum.
#[allow(clippy::too_many_arguments)]
fn nd(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    kind: u8,
    flags: u8,
    target: Ipv6Addr,
    option: u8,
) -> Vec<u8> {
    let mut icmp = vec![kind, 0, 0, 0, flags, 0, 0, 0];
    icmp.extend_from_slice(&target.octets());
    icmp.extend_from_slice(&[option, 1]);
    icmp.extend_from_slice(&src_mac);
    let sum = checksum(source, destination, &icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    ipv6(dst_mac, src_mac, source, destination, 58, 255, &icmp)
}

fn udp_from_host(destination: &str) -> Vec<u8> {
    ipv6(
        LAN_MAC,
        HOST_MAC,
        ip("2001:db8:1::10"),
        ip(destination),
        17,
        64,
        &[0; 8],
    )
}

#[test]
fn a_missing_gateway_is_solicited_and_then_forwarded_to() {
    let mut lab = Lab::new();
    lab.fe
        .io_mut()
        .inject(IfId(0), udp_from_host("2001:db8:99::7"));
    lab.settle();
    let tx = lab.tx();
    assert_eq!(tx.len(), 1, "only the solicitation leaves");
    let (egress, ns) = &tx[0];
    assert_eq!(*egress, IfId(1));
    assert_eq!(
        &ns[0..6],
        &[0x33, 0x33, 0xff, 0, 0, 0xfe],
        "solicited-node group"
    );
    assert_eq!(
        &ns[22..38],
        &ip("fe80::2").octets(),
        "from the WAN link-local"
    );
    assert_eq!(&ns[38..54], &ip("ff02::1:ff00:fe").octets());
    assert_eq!(ns[54], 135);
    assert_eq!(&ns[62..78], &ip("fe80::fe").octets(), "target");
    assert_eq!(&ns[78..80], &[1, 1], "Source Link-Layer Address option");
    assert_eq!(&ns[80..86], &WAN_MAC);
    assert_eq!(
        checksum(ip("fe80::2"), ip("ff02::1:ff00:fe"), &ns[54..]),
        0,
        "valid checksum"
    );

    let advertisement = nd(
        WAN_MAC,
        GATEWAY_MAC,
        ip("fe80::fe"),
        ip("fe80::2"),
        136,
        0xe0,
        ip("fe80::fe"),
        2,
    );
    lab.fe.io_mut().inject(IfId(1), advertisement);
    lab.settle();
    assert_eq!(lab.neighd.counters().learned, 1);

    lab.fe
        .io_mut()
        .inject(IfId(0), udp_from_host("2001:db8:99::7"));
    lab.settle();
    let tx = lab.tx();
    assert_eq!(tx.len(), 1);
    assert_eq!(tx[0].0, IfId(1));
    assert_eq!(&tx[0].1[0..6], &GATEWAY_MAC);
}

#[test]
fn a_solicitation_for_the_router_is_answered_and_the_asker_learned() {
    let mut lab = Lab::new();
    let solicitation = nd(
        [0x33, 0x33, 0xff, 0, 0, 1],
        HOST_MAC,
        ip("2001:db8:1::10"),
        ip("ff02::1:ff00:1"),
        135,
        0,
        ip("2001:db8:1::1"),
        1,
    );
    lab.fe.io_mut().inject(IfId(0), solicitation);
    lab.settle();
    let tx = lab.tx();
    assert_eq!(tx.len(), 1);
    let (egress, na) = &tx[0];
    assert_eq!(*egress, IfId(0));
    assert_eq!(&na[0..6], &HOST_MAC);
    assert_eq!(&na[22..38], &ip("2001:db8:1::1").octets());
    assert_eq!(&na[38..54], &ip("2001:db8:1::10").octets());
    assert_eq!(na[54], 136);
    assert_eq!(na[58], 0xe0, "router, solicited, override");
    assert_eq!(&na[80..86], &LAN_MAC, "Target Link-Layer Address");
    assert_eq!(lab.neighd.counters().learned, 1);

    // The host is reachable without another solicitation.
    let to_host = ipv6(
        WAN_MAC,
        GATEWAY_MAC,
        ip("2001:db8:99::7"),
        ip("2001:db8:1::10"),
        17,
        64,
        &[0; 8],
    );
    lab.fe.io_mut().inject(IfId(1), to_host);
    lab.settle();
    let tx = lab.tx();
    assert_eq!(tx.len(), 1);
    assert_eq!(&tx[0].1[0..6], &HOST_MAC);
}

#[test]
fn duplicate_address_detection_for_our_address_gets_an_all_nodes_advertisement() {
    let mut lab = Lab::new();
    let probe = {
        let mut icmp = vec![135, 0, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&ip("2001:db8:1::1").octets());
        let sum = checksum(Ipv6Addr::UNSPECIFIED, ip("ff02::1:ff00:1"), &icmp);
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());
        ipv6(
            [0x33, 0x33, 0xff, 0, 0, 1],
            HOST_MAC,
            Ipv6Addr::UNSPECIFIED,
            ip("ff02::1:ff00:1"),
            58,
            255,
            &icmp,
        )
    };
    lab.fe.io_mut().inject(IfId(0), probe);
    lab.settle();
    let tx = lab.tx();
    assert_eq!(tx.len(), 1);
    assert_eq!(&tx[0].1[0..6], &[0x33, 0x33, 0, 0, 0, 1]);
    assert_eq!(&tx[0].1[38..54], &ip("ff02::1").octets());
    assert_eq!(tx[0].1[58], 0xa0, "router, override, not solicited");
    assert_eq!(lab.neighd.counters().learned, 0);
}

#[test]
fn unwanted_advertisements_and_off_link_askers_are_not_learned() {
    let mut lab = Lab::new();
    // Nobody asked for fe80::99.
    lab.fe.io_mut().inject(
        IfId(1),
        nd(
            WAN_MAC,
            GATEWAY_MAC,
            ip("fe80::99"),
            ip("fe80::2"),
            136,
            0x60,
            ip("fe80::99"),
            2,
        ),
    );
    // An asker from a prefix the interface does not have.
    lab.fe.io_mut().inject(
        IfId(0),
        nd(
            [0x33, 0x33, 0xff, 0, 0, 1],
            HOST_MAC,
            ip("2001:db8:77::10"),
            ip("ff02::1:ff00:1"),
            135,
            0,
            ip("2001:db8:1::1"),
            1,
        ),
    );
    lab.settle();
    assert_eq!(lab.neighd.counters().learned, 0);
    assert_eq!(lab.neighd.known(), 0);
}
