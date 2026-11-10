//! Frames to and from the FE, and what the client writes to confd and ribd.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ruster_dhcpc::client4;
use ruster_dhcpc::client6;
use ruster_dhcpc::dhcp6::IaPrefix;
use ruster_dhcpc::frame;
use ruster_dhcpc::values::{route4, route6, values4, values6, LIFETIME};
use ruster_proto::table::{Key, NextHop, RouteAction, Value};

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];

fn ones(bytes: &[u8], mut acc: u32) -> u16 {
    for pair in bytes.chunks(2) {
        acc += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

#[test]
fn an_ipv4_frame_has_good_checksums_and_reads_back() {
    let payload = [7_u8; 301];
    let from = Ipv4Addr::new(198, 51, 100, 20);
    let to = Ipv4Addr::new(198, 51, 100, 1);
    let f = frame::ipv4(MAC, Some([2, 0, 0, 0, 0, 1]), from, to, &payload);
    assert_eq!(&f[..6], &[2, 0, 0, 0, 0, 1]);
    assert_eq!(&f[6..12], &MAC);
    assert_eq!(ones(&f[14..34], 0), 0xffff, "IP header checksum");
    let udp = &f[34..];
    let mut pseudo = ones(&from.octets(), 0) as u32 + ones(&to.octets(), 0) as u32;
    pseudo += 17 + udp.len() as u32;
    assert_eq!(ones(udp, pseudo), 0xffff, "UDP checksum");
    let got = frame::read(&f).unwrap();
    assert_eq!(got.port, 67);
    assert_eq!(got.from, IpAddr::V4(from));
    assert_eq!(got.payload, &payload[..]);
    let broadcast = frame::ipv4(
        MAC,
        None,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        &payload,
    );
    assert_eq!(&broadcast[..6], &[0xff; 6]);
}

#[test]
fn an_ipv6_frame_goes_to_all_servers_and_reads_back() {
    let from: Ipv6Addr = "fe80::ff:fe00:2".parse().unwrap();
    let payload = [1_u8, 2, 3];
    let f = frame::ipv6(MAC, from, &payload);
    assert_eq!(&f[..6], &[0x33, 0x33, 0, 1, 0, 2]);
    assert_eq!(f[21], 1, "hop limit");
    let udp = &f[54..];
    let to = ruster_dhcpc::dhcp6::ALL_SERVERS;
    let pseudo =
        ones(&from.octets(), 0) as u32 + ones(&to.octets(), 0) as u32 + 17 + udp.len() as u32;
    assert_eq!(ones(udp, pseudo), 0xffff);
    let got = frame::read(&f).unwrap();
    assert_eq!((got.port, got.payload), (547, &payload[..]));
}

#[test]
fn frames_cut_short_or_of_other_kinds_are_not_read() {
    let f = frame::ipv4(
        MAC,
        None,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        &[0; 300],
    );
    for len in 0..42 {
        assert!(frame::read(&f[..len]).is_none(), "{len}");
    }
    assert!(frame::read(&f[..f.len() - 1]).is_none());
    let mut fragment = f.clone();
    fragment[20] = 0x20;
    assert!(frame::read(&fragment).is_none());
    let mut tcp = f.clone();
    tcp[23] = 6;
    assert!(frame::read(&tcp).is_none());
    let v6 = frame::ipv6(MAC, "fe80::1".parse().unwrap(), &[0; 10]);
    assert!(frame::read(&v6[..v6.len() - 1]).is_none());
}

fn lease4(routers: Vec<Ipv4Addr>) -> client4::Lease {
    client4::Lease {
        address: Ipv4Addr::new(198, 51, 100, 20),
        prefix_len: 24,
        routers,
        dns: vec![
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(192, 0, 2, 53),
            Ipv4Addr::new(192, 0, 2, 53),
            Ipv4Addr::BROADCAST,
        ],
        server: Ipv4Addr::new(198, 51, 100, 1),
        lease_time: 3600,
        t1: 1800,
        t2: 3150,
    }
}

#[test]
fn a_dhcpv4_lease_gives_the_address_dns_and_default_route() {
    let lease = lease4(vec![
        Ipv4Addr::new(203, 0, 113, 1),
        Ipv4Addr::new(198, 51, 100, 1),
    ]);
    let changes = values4("dhcp-wan", Some(&lease));
    assert_eq!(
        changes[0].value,
        Some(Value::SourceIpv4 {
            address: lease.address,
            prefix_len: 24,
            lifetime: LIFETIME
        })
    );
    // Once each, and only those confd takes.
    assert_eq!(
        changes[1].value,
        Some(Value::SourceDns {
            servers: vec![Ipv4Addr::new(192, 0, 2, 53).into()],
            lifetime: LIFETIME
        })
    );
    for change in &changes {
        change.validate().unwrap();
    }
    assert!(values4("dhcp-wan", None).iter().all(|c| c.value.is_none()));
    // The first router in the subnet.
    let route = route4("default", "wan", Some(&lease));
    assert_eq!(
        route.value,
        Some(Value::Route(RouteAction::Forward(vec![NextHop {
            interface: "wan".into(),
            address: Some(Ipv4Addr::new(198, 51, 100, 1).into())
        }])))
    );
    assert!(route4("default", "wan", Some(&lease4(Vec::new())))
        .value
        .is_none());
    assert!(route4("default", "wan", None).value.is_none());
}

#[test]
fn a_dhcpv6_lease_gives_the_prefix_and_a_route_via_the_server() {
    let lease = client6::Lease {
        address: None,
        prefix: Some(IaPrefix {
            prefix: "2001:db8:12:3400::".parse().unwrap(),
            len: 56,
            preferred: 3600,
            valid: 7200,
        }),
        dns: Vec::new(),
        server_id: vec![1],
        t1: 1800,
        t2: 2880,
    };
    let changes = values6("dhcp6-wan", Some(&lease));
    assert!(matches!(
        changes[0].value,
        Some(Value::SourcePrefix {
            prefix_len: 56,
            preferred: 3600,
            valid: 7200,
            ..
        })
    ));
    assert!(changes[1].value.is_none(), "no address");
    let link_local = client6::Lease {
        prefix: Some(IaPrefix {
            prefix: "fe80::".parse().unwrap(),
            len: 64,
            preferred: 1,
            valid: 1,
        }),
        dns: vec!["ff02::1".parse().unwrap()],
        ..lease.clone()
    };
    assert!(values6("dhcp6-wan", Some(&link_local))
        .iter()
        .all(|c| c.value.is_none()));
    assert!(changes[2].value.is_none(), "no DNS servers");
    for change in &changes {
        change.validate().unwrap();
        assert!(matches!(
            change.key,
            Key::SourcePrefix { .. } | Key::SourceIpv6 { .. } | Key::SourceDns { .. }
        ));
    }
    let via: Ipv6Addr = "fe80::1".parse().unwrap();
    assert!(route6("default", "wan", Some(via)).value.is_some());
    // Only a link-local next hop.
    assert!(
        route6("default", "wan", Some("2001:db8::1".parse().unwrap()))
            .value
            .is_none()
    );
}
