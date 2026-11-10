//! Table entry encoding tests.

use std::net::{IpAddr, Ipv4Addr};

use ruster_proto::cbor::{Decoder, Encoder};
use ruster_proto::sid;
use ruster_proto::table::{
    entry_line, format_mac, parse_mac, Change, Key, ModelError, NextHop, RouteAction, Value, Vlan,
    DEFAULT_VRF,
};

fn round_trip(change: &Change) -> Change {
    let mut out = Vec::new();
    change.encode(&mut Encoder::new(&mut out)).unwrap();
    let mut d = Decoder::new(&out);
    let back = Change::decode(&mut d).unwrap();
    assert!(d.is_empty());
    back
}

fn ip(a: [u8; 4]) -> IpAddr {
    Ipv4Addr::from(a).into()
}

fn ip6(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn every_table_round_trips() {
    let changes = [
        Change::set(
            Key::Interface {
                name: "eth0".into(),
            },
            Value::Interface {
                enabled: true,
                mac: [2, 0, 0, 0, 0, 1],
                mtu: 1500,
                vrf: ruster_proto::table::DEFAULT_VRF.into(),
                vlan: None,
                tunnel: None,
                pppoe: None,
            },
        ),
        Change::set(
            Key::Address {
                interface: "eth0".into(),
                address: ip([192, 0, 2, 1]),
            },
            Value::Address { prefix_len: 24 },
        ),
        Change::set(
            Key::Route {
                vrf: "default".into(),
                prefix: ip([0, 0, 0, 0]),
                len: 0,
            },
            Value::Route(RouteAction::Forward(vec![
                NextHop {
                    interface: "eth1".into(),
                    address: Some(ip([198, 51, 100, 1])),
                },
                NextHop {
                    interface: "eth2".into(),
                    address: None,
                },
            ])),
        ),
        Change::set(
            Key::Route {
                vrf: "default".into(),
                prefix: ip([203, 0, 113, 0]),
                len: 24,
            },
            Value::Route(RouteAction::Reject),
        ),
        Change::set(
            Key::Neighbor {
                interface: "eth1".into(),
                address: ip([198, 51, 100, 1]),
            },
            Value::Neighbor {
                mac: [2, 0, 0, 0, 0, 0xfe],
            },
        ),
        Change::delete(Key::Interface {
            name: "eth9".into(),
        }),
    ];
    for change in &changes {
        assert_eq!(&round_trip(change), change);
    }
}

#[test]
fn a_change_is_one_map_with_the_instance_identifier_as_key() {
    let change = Change::set(
        Key::Address {
            interface: "e".into(),
            address: ip([10, 0, 0, 1]),
        },
        Value::Address { prefix_len: 8 },
    );
    let mut out = Vec::new();
    change.encode(&mut Encoder::new(&mut out)).unwrap();
    // {[60020, "e", "10.0.0.1"]: {1: 8}}
    let mut expected = vec![0xa1, 0x83, 0x19, 0xea, 0x74, 0x61, b'e', 0x68];
    expected.extend_from_slice(b"10.0.0.1");
    expected.extend_from_slice(&[0xa1, 0x01, 0x08]);
    assert_eq!(out, expected);
}

#[test]
fn sid_file_matches_the_constants() {
    let text = include_str!("../sid/ruster-fe.sid");
    for (path, value) in sid::ALL {
        let identifier = format!("\"identifier\": \"{path}\"");
        let at = text
            .find(&identifier)
            .unwrap_or_else(|| panic!("{path} missing from the .sid file"));
        let rest = &text[at..];
        let sid_field = format!("\"sid\": {value},");
        let next_item = rest[1..]
            .find("\"identifier\"")
            .map_or(rest.len(), |n| n + 1);
        assert!(
            rest[..next_item].contains(&sid_field),
            "{path} should have SID {value}"
        );
    }
    let mut values: Vec<u64> = sid::ALL.iter().map(|&(_, v)| v).collect();
    values.sort_unstable();
    values.dedup();
    assert_eq!(values.len(), sid::ALL.len(), "SIDs must be unique");
    assert_eq!(
        text.matches("\"identifier\"").count(),
        sid::ALL.len(),
        "the .sid file has items the code does not"
    );
    // Inside the file's assignment range.
    assert!(text.contains("\"entry-point\": 60000,\n        \"size\": 300"));
    assert!(
        values.iter().all(|v| (60_000..60_300).contains(v)),
        "{values:?}"
    );
}

fn decode_bytes(bytes: &[u8]) -> Result<Change, ModelError> {
    Change::decode(&mut Decoder::new(bytes))
}

fn encoded(f: impl FnOnce(&mut Encoder<'_>)) -> Vec<u8> {
    let mut out = Vec::new();
    f(&mut Encoder::new(&mut out));
    out
}

#[test]
fn bad_changes_are_rejected() {
    // Unknown table.
    let bytes = encoded(|e| {
        e.map(1).array(2).u64(60_099).text("x").null();
    });
    assert_eq!(decode_bytes(&bytes), Err(ModelError::UnknownTable(60_099)));

    // Route prefix with host bits.
    let bytes = encoded(|e| {
        e.map(1)
            .array(3)
            .u64(sid::ROUTE)
            .text("default")
            .text("10.0.0.1/8")
            .null();
    });
    assert!(matches!(decode_bytes(&bytes), Err(ModelError::Invalid(_))));

    // A member of another table.
    let bytes = encoded(|e| {
        e.map(1)
            .array(2)
            .u64(sid::INTERFACE)
            .text("eth0")
            .map(1)
            .u64(sid::NEIGHBOR_LINK_LAYER_ADDRESS - sid::INTERFACE)
            .text("02:00:00:00:00:01");
    });
    assert!(matches!(
        decode_bytes(&bytes),
        Err(ModelError::UnknownMember(_))
    ));

    // Interface without a MAC.
    let bytes = encoded(|e| {
        e.map(1).array(2).u64(sid::INTERFACE).text("eth0").map(0);
    });
    assert_eq!(
        decode_bytes(&bytes),
        Err(ModelError::Missing("phys-address"))
    );

    // Forward route with no next hop.
    let bytes = encoded(|e| {
        e.map(1)
            .array(3)
            .u64(sid::ROUTE)
            .text("default")
            .text("0.0.0.0/0")
            .map(1)
            .u64(sid::ROUTE_NEXT_HOP - sid::ROUTE)
            .array(0);
    });
    assert_eq!(decode_bytes(&bytes), Err(ModelError::Missing("next-hop")));

    // Empty interface name.
    let bytes = encoded(|e| {
        e.map(1).array(2).u64(sid::INTERFACE).text("").null();
    });
    assert!(matches!(decode_bytes(&bytes), Err(ModelError::Invalid(_))));
}

#[test]
fn mac_text_round_trips_and_rejects_bad_forms() {
    let mac = [0x02, 0xab, 0, 0x10, 0xff, 1];
    assert_eq!(format_mac(&mac), "02:ab:00:10:ff:01");
    assert_eq!(parse_mac("02:ab:00:10:ff:01"), Ok(mac));
    for bad in [
        "",
        "02:ab:00:10:ff",
        "02:ab:00:10:ff:01:02",
        "2:ab:00:10:ff:01",
        "zz:ab:00:10:ff:01",
    ] {
        assert!(parse_mac(bad).is_err(), "{bad}");
    }
}

#[test]
fn duplicate_members_and_two_route_actions_are_rejected() {
    let two_macs = encoded(|e| {
        e.map(1)
            .array(3)
            .u64(sid::NEIGHBOR)
            .text("eth0")
            .text("10.0.0.1")
            .map(2)
            .u64(1)
            .text("02:00:00:00:00:01")
            .u64(1)
            .text("02:00:00:00:00:02");
    });
    assert_eq!(
        decode_bytes(&two_macs),
        Err(ModelError::Invalid("duplicate member"))
    );

    let two_actions = encoded(|e| {
        e.map(1)
            .array(3)
            .u64(sid::ROUTE)
            .text("default")
            .text("0.0.0.0/0")
            .map(2)
            .u64(sid::ROUTE_NEXT_HOP - sid::ROUTE)
            .array(1)
            .map(1)
            .u64(1)
            .text("eth0")
            .u64(sid::ROUTE_LOCAL - sid::ROUTE)
            .bool(true);
    });
    assert_eq!(
        decode_bytes(&two_actions),
        Err(ModelError::Invalid("duplicate member"))
    );
}

#[test]
fn encode_refuses_what_decode_would_refuse() {
    let bad = [
        Change::delete(Key::Interface {
            name: String::new(),
        }),
        Change::delete(Key::Route {
            vrf: "default".into(),
            prefix: ip([10, 0, 0, 1]),
            len: 8,
        }),
        Change::delete(Key::Route {
            vrf: "default".into(),
            prefix: ip([0, 0, 0, 0]),
            len: 33,
        }),
        Change::set(
            Key::Address {
                interface: "eth0".into(),
                address: ip([10, 0, 0, 1]),
            },
            Value::Address { prefix_len: 40 },
        ),
        Change::set(
            Key::Route {
                vrf: "default".into(),
                prefix: ip([0, 0, 0, 0]),
                len: 0,
            },
            Value::Route(RouteAction::Forward(vec![])),
        ),
        Change::set(
            Key::Route {
                vrf: "default".into(),
                prefix: ip([0, 0, 0, 0]),
                len: 0,
            },
            Value::Route(RouteAction::Forward(vec![NextHop {
                interface: String::new(),
                address: None,
            }])),
        ),
        Change::set(
            Key::Interface {
                name: "eth0".into(),
            },
            Value::Interface {
                enabled: true,
                mac: [2, 0, 0, 0, 0, 1],
                mtu: 0,
                vrf: ruster_proto::table::DEFAULT_VRF.into(),
                vlan: None,
                tunnel: None,
                pppoe: None,
            },
        ),
        Change::set(
            Key::Interface {
                name: "eth0".into(),
            },
            Value::Neighbor {
                mac: [2, 0, 0, 0, 0, 1],
            },
        ),
    ];
    for change in &bad {
        let mut out = Vec::new();
        assert!(
            change.encode(&mut Encoder::new(&mut out)).is_err(),
            "{change:?}"
        );
        assert!(out.is_empty());
    }
}

#[test]
fn non_canonical_text_is_rejected() {
    for prefix in [
        "10.0.0.0/+8",
        "10.0.0.0/008",
        "10.0.0.0/",
        "1.0.0.0/33",
        "1.0.0.0/0",
    ] {
        let bytes = encoded(|e| {
            e.map(1)
                .array(3)
                .u64(sid::ROUTE)
                .text("default")
                .text(prefix)
                .null();
        });
        assert!(decode_bytes(&bytes).is_err(), "{prefix}");
    }
    assert!(parse_mac("+f:00:00:00:00:00").is_err());
}

#[test]
fn member_delta_overflow_is_rejected() {
    let bytes = encoded(|e| {
        e.map(1)
            .array(2)
            .u64(sid::INTERFACE)
            .text("eth0")
            .map(1)
            .u64(u64::MAX)
            .bool(true);
    });
    assert!(decode_bytes(&bytes).is_err());
}

#[test]
fn ipv6_entries_round_trip() {
    let changes = [
        Change::set(
            Key::Address {
                interface: "eth0".into(),
                address: ip6("2001:db8::1"),
            },
            Value::Address { prefix_len: 64 },
        ),
        Change::set(
            Key::Route {
                vrf: "default".into(),
                prefix: ip6("::"),
                len: 0,
            },
            Value::Route(RouteAction::Forward(vec![NextHop {
                interface: "eth1".into(),
                address: Some(ip6("fe80::1")),
            }])),
        ),
        Change::set(
            Key::Route {
                vrf: "default".into(),
                prefix: ip6("2001:db8:1::"),
                len: 48,
            },
            Value::Route(RouteAction::Discard),
        ),
        Change::set(
            Key::Neighbor {
                interface: "eth1".into(),
                address: ip6("fe80::1"),
            },
            Value::Neighbor {
                mac: [2, 0, 0, 0, 0, 0xfe],
            },
        ),
    ];
    for change in &changes {
        assert_eq!(&round_trip(change), change);
    }
}

#[test]
fn ipv6_entries_are_checked_for_their_family() {
    let bad = [
        // Host bits after the prefix length.
        Change::delete(Key::Route {
            vrf: "default".into(),
            prefix: ip6("2001:db8::1"),
            len: 64,
        }),
        // Longer than 128.
        Change::delete(Key::Route {
            vrf: "default".into(),
            prefix: ip6("::"),
            len: 129,
        }),
        // An IPv4 prefix length limit does not apply, but 129 does.
        Change::set(
            Key::Address {
                interface: "eth0".into(),
                address: ip6("2001:db8::1"),
            },
            Value::Address { prefix_len: 129 },
        ),
        // A next hop of the other family.
        Change::set(
            Key::Route {
                vrf: "default".into(),
                prefix: ip6("::"),
                len: 0,
            },
            Value::Route(RouteAction::Forward(vec![NextHop {
                interface: "eth1".into(),
                address: Some(ip([192, 0, 2, 1])),
            }])),
        ),
    ];
    for change in &bad {
        assert!(change.validate().is_err(), "{change:?}");
    }
    // 33 is fine for IPv6 but not for IPv4.
    let ipv6_33 = Change::set(
        Key::Address {
            interface: "eth0".into(),
            address: ip6("2001:db8::1"),
        },
        Value::Address { prefix_len: 33 },
    );
    assert!(ipv6_33.validate().is_ok());
}

#[test]
fn an_address_not_in_its_canonical_text_is_refused() {
    // RFC 5952: "2001:DB8::1" and "2001:db8:0::1" are the same address as
    // "2001:db8::1"; only the canonical spelling is a key.
    let encoded = |address: &str| {
        let mut payload = Vec::new();
        let mut e = Encoder::new(&mut payload);
        e.map(1)
            .array(3)
            .u64(sid::ADDRESS)
            .text("eth0")
            .text(address)
            .map(1)
            .u64(sid::ADDRESS_PREFIX_LENGTH - sid::ADDRESS)
            .u64(64);
        payload
    };
    assert!(Change::decode(&mut Decoder::new(&encoded("2001:db8::1"))).is_ok());
    for spelling in ["2001:DB8::1", "2001:db8:0::1", "2001:0db8::1"] {
        assert!(
            Change::decode(&mut Decoder::new(&encoded(spelling))).is_err(),
            "{spelling}"
        );
    }
}

#[test]
fn vrf_binding_and_lookup_vrf_round_trip() {
    let changes = [
        Change::set(
            Key::Interface {
                name: "cust0".into(),
            },
            Value::Interface {
                enabled: true,
                mac: [2, 0, 0, 0, 0, 9],
                mtu: 1500,
                vrf: "customer".into(),
                vlan: None,
                tunnel: None,
                pppoe: None,
            },
        ),
        Change::set(
            Key::Route {
                vrf: "customer".into(),
                prefix: ip([0, 0, 0, 0]),
                len: 0,
            },
            Value::Route(RouteAction::LookupVrf("default".into())),
        ),
    ];
    for change in &changes {
        assert_eq!(&round_trip(change), change);
    }
    // The default VRF is left out on the wire and read back as "default".
    let default = Change::set(
        Key::Interface { name: "lan".into() },
        Value::Interface {
            enabled: true,
            mac: [2, 0, 0, 0, 0, 1],
            mtu: 1500,
            vrf: DEFAULT_VRF.into(),
            vlan: None,
            tunnel: None,
            pppoe: None,
        },
    );
    let mut payload = Vec::new();
    default.encode(&mut Encoder::new(&mut payload)).unwrap();
    assert!(!payload
        .windows(b"default".len())
        .any(|window| window == b"default"));
    assert_eq!(round_trip(&default), default);
    // An empty VRF name is refused.
    let empty = Change::set(
        Key::Route {
            vrf: "default".into(),
            prefix: ip([0, 0, 0, 0]),
            len: 0,
        },
        Value::Route(RouteAction::LookupVrf(String::new())),
    );
    assert!(empty.validate().is_err());
}

#[test]
fn vlan_sub_interfaces_round_trip_and_are_checked() {
    let sub = |parent: &str, id: u16| {
        Change::set(
            Key::Interface {
                name: "eth0.10".into(),
            },
            Value::Interface {
                enabled: true,
                mac: [2, 0, 0, 0, 0, 1],
                mtu: 1500,
                vrf: DEFAULT_VRF.into(),
                vlan: Some(Vlan {
                    parent: parent.into(),
                    id,
                }),
                tunnel: None,
                pppoe: None,
            },
        )
    };
    let good = sub("eth0", 10);
    assert_eq!(round_trip(&good), good);
    for bad in [
        sub("eth0", 0),
        sub("eth0", 4095),
        sub("", 10),
        sub("eth0.10", 10),
    ] {
        assert!(bad.validate().is_err(), "{bad:?}");
    }
}

#[test]
fn nat_and_firewall_entries_round_trip_and_are_checked() {
    use ruster_proto::table::{FirewallAction, FirewallRule, Nat, Protocol};
    let nat = |inside: &str, first: u16, last: u16| {
        Change::set(
            Key::Nat {
                vrf: "default".into(),
            },
            Value::Nat(Nat {
                inside: inside.into(),
                outside: "wan".into(),
                external: None,
                ports: ruster_proto::table::NatPorts::Range { first, last },
                filtering: ruster_proto::table::NatFiltering::AddressDependent,
                ipv4_id_rate_limit: true,
                ports_per_host: 0,
                state_per_host: 0,
            }),
        )
    };
    let rule = |source_ports: (u16, u16), ingress: Option<&str>| {
        Change::set(
            Key::FirewallRule {
                vrf: "default".into(),
                id: 10,
            },
            Value::FirewallRule(FirewallRule {
                ingress: ingress.map(Into::into),
                egress: Some("wan".into()),
                source: (Ipv4Addr::new(10, 0, 0, 0).into(), 8),
                destination: (Ipv4Addr::UNSPECIFIED.into(), 0),
                protocol: Protocol::Tcp,
                source_ports,
                destination_ports: (443, 443),
                action: FirewallAction::Accept,
            }),
        )
    };
    let mut with_external = nat("lan", 1024, 65535);
    if let Some(Value::Nat(n)) = &mut with_external.value {
        n.external = Some(Ipv4Addr::new(203, 0, 113, 10));
    }
    for change in [
        nat("lan", 1024, 65535),
        with_external,
        rule((1, 65535), Some("lan")),
        rule((0, 65535), None),
        Change::delete(Key::FirewallRule {
            vrf: "red".into(),
            id: 7,
        }),
    ] {
        assert_eq!(round_trip(&change), change);
    }
    for bad in [
        nat("wan", 1024, 65535),
        nat("lan", 0, 10),
        nat("lan", 20, 10),
        rule((10, 1), None),
    ] {
        assert!(bad.validate().is_err(), "{bad:?}");
    }
}

#[test]
fn tunnel_interfaces_round_trip_and_are_checked() {
    use ruster_proto::table::Tunnel;
    let tunnel = |local: &str, remote: &str, vlan: Option<Vlan>| {
        Change::set(
            Key::Interface {
                name: "dslite".into(),
            },
            Value::Interface {
                enabled: true,
                mac: [2, 0, 0, 0, 0, 1],
                mtu: 1460,
                vrf: DEFAULT_VRF.into(),
                vlan,
                tunnel: Some(Tunnel {
                    local: local.parse().unwrap(),
                    remote: remote.parse().unwrap(),
                }),
                pppoe: None,
            },
        )
    };
    let good = tunnel("2001:db8:1::2", "2001:db8:ff::1", None);
    assert!(good.validate().is_ok());
    assert_eq!(round_trip(&good), good);
    assert!(tunnel("fe80::1", "2001:db8:ff::1", None)
        .validate()
        .is_err());
    assert!(tunnel("2001:db8:1::2", "ff02::1", None).validate().is_err());
    let both = tunnel(
        "2001:db8:1::2",
        "2001:db8:ff::1",
        Some(Vlan {
            parent: "eth0".into(),
            id: 10,
        }),
    );
    assert!(both.validate().is_err());
}

#[test]
fn a_nat_with_a_psid_port_set_round_trips_and_is_checked() {
    use ruster_proto::table::{Nat, NatPorts};
    let nat = |ports: NatPorts| {
        Change::set(
            Key::Nat {
                vrf: "default".into(),
            },
            Value::Nat(Nat {
                inside: "lan".into(),
                outside: "map".into(),
                external: None,
                ports,
                filtering: Default::default(),
                ipv4_id_rate_limit: true,
                ports_per_host: 0,
                state_per_host: 0,
            }),
        )
    };
    let good = nat(NatPorts::Psid {
        offset: 6,
        length: 6,
        psid: 0x34,
    });
    assert!(good.validate().is_ok());
    assert_eq!(round_trip(&good), good);
    for bad in [
        NatPorts::Psid {
            offset: 6,
            length: 0,
            psid: 0,
        },
        NatPorts::Psid {
            offset: 8,
            length: 8,
            psid: 1,
        },
        NatPorts::Psid {
            offset: 6,
            length: 6,
            psid: 64,
        },
    ] {
        assert!(nat(bad).validate().is_err(), "{bad:?}");
    }
}

#[test]
fn a_pppoe_interface_round_trips_and_is_checked() {
    use ruster_proto::table::Pppoe;
    let ppp = |session: u16, peer: [u8; 6]| {
        Change::set(
            Key::Interface { name: "ppp".into() },
            Value::Interface {
                enabled: true,
                mac: [2, 0, 0, 0, 0, 8],
                mtu: 1492,
                vrf: DEFAULT_VRF.into(),
                vlan: None,
                tunnel: None,
                pppoe: Some(Pppoe {
                    parent: "wan".into(),
                    session,
                    peer,
                }),
            },
        )
    };
    let good = ppp(0x1234, [2, 0, 0, 0, 0, 0xac]);
    assert!(good.validate().is_ok());
    assert_eq!(round_trip(&good), good);
    assert!(ppp(0, [2, 0, 0, 0, 0, 0xac]).validate().is_err());
    assert!(ppp(0xffff, [2, 0, 0, 0, 0, 0xac]).validate().is_err());
    assert!(ppp(1, [0xff; 6]).validate().is_err());
    let Change {
        key,
        value:
            Some(Value::Interface {
                pppoe: Some(mut session),
                enabled,
                mac,
                mtu,
                vrf,
                ..
            }),
    } = good
    else {
        unreachable!()
    };
    session.parent = "ppp".into();
    let itself = Change::set(
        key,
        Value::Interface {
            enabled,
            mac,
            mtu,
            vrf,
            vlan: None,
            tunnel: None,
            pppoe: Some(session),
        },
    );
    assert_eq!(
        itself.validate(),
        Err(ModelError::Invalid("PPPoE parent (itself)"))
    );
}

#[test]
fn an_ipv6_firewall_rule_round_trips_and_a_mixed_one_is_refused() {
    use ruster_proto::table::{FirewallAction, FirewallRule, Protocol};
    let v6 = |text: &str| -> (IpAddr, u8) {
        let (address, len) = text.split_once('/').unwrap();
        (address.parse().unwrap(), len.parse().unwrap())
    };
    let rule = |source, destination, protocol| {
        Change::set(
            Key::FirewallRule {
                vrf: DEFAULT_VRF.into(),
                id: 1,
            },
            Value::FirewallRule(FirewallRule {
                ingress: Some("lan".into()),
                egress: None,
                source,
                destination,
                protocol,
                source_ports: (0, 65_535),
                destination_ports: (0, 65_535),
                action: FirewallAction::Accept,
            }),
        )
    };
    let icmpv6 = rule(v6("2001:db8:1::/48"), v6("::/0"), Protocol::Icmpv6);
    assert_eq!(round_trip(&icmpv6), icmpv6);
    for bad in [
        rule(v6("2001:db8:1::/48"), (ip([0, 0, 0, 0]), 0), Protocol::Tcp),
        rule(v6("::/0"), v6("::/0"), Protocol::Icmp),
        rule(
            (ip([0, 0, 0, 0]), 0),
            (ip([0, 0, 0, 0]), 0),
            Protocol::Icmpv6,
        ),
    ] {
        assert!(bad.validate().is_err(), "{bad:?}");
    }
}

/// A NAT entry without `filtering-type` (from an older writer) is
/// endpoint-independent, and the default is not written.
#[test]
fn a_nat_without_filtering_type_is_endpoint_independent() {
    use ruster_proto::table::{Nat, NatFiltering, NatPorts};
    let nat = Nat {
        inside: "lan".into(),
        outside: "wan".into(),
        external: None,
        ports: NatPorts::Range {
            first: 1_024,
            last: 32_767,
        },
        filtering: NatFiltering::EndpointIndependent,
        ipv4_id_rate_limit: true,
        ports_per_host: 0,
        state_per_host: 0,
    };
    let change = Change::set(
        Key::Nat {
            vrf: "default".into(),
        },
        Value::Nat(nat.clone()),
    );
    use ruster_proto::session::{decode_changes, encode_changes};
    let bytes = encode_changes(std::slice::from_ref(&change)).unwrap();
    assert_eq!(decode_changes(&bytes).unwrap(), vec![change]);
    let strict = Change::set(
        Key::Nat {
            vrf: "default".into(),
        },
        Value::Nat(Nat {
            filtering: NatFiltering::AddressAndPortDependent,
            ..nat
        }),
    );
    let longer = encode_changes(std::slice::from_ref(&strict)).unwrap();
    assert!(longer.len() > bytes.len(), "only a non-default is written");
    assert_eq!(decode_changes(&longer).unwrap(), vec![strict]);
}

#[test]
fn icmp_error_limits_round_trip_and_zero_or_a_missing_member_is_refused() {
    let limits = |ipv4_interval_ms| {
        Change::set(
            Key::IcmpErrors {
                vrf: DEFAULT_VRF.into(),
            },
            Value::IcmpErrors {
                ipv4_interval_ms,
                ipv6_burst: 10,
                ipv6_interval_ms: 10,
            },
        )
    };
    assert_eq!(round_trip(&limits(100)), limits(100));
    let mut zero = Vec::new();
    if limits(0).encode(&mut Encoder::new(&mut zero)).is_ok() {
        assert!(decode_bytes(&zero).is_err(), "an interval of 0");
    }
    // {[60150, "default"]: {1: 100, 2: 10}}: no ipv6-interval.
    let missing = encoded(|e| {
        e.map(1)
            .array(2)
            .u64(sid::ICMP_ERRORS)
            .text(DEFAULT_VRF)
            .map(2)
            .u64(1)
            .u64(100)
            .u64(2)
            .u64(10);
    });
    assert!(matches!(
        decode_bytes(&missing),
        Err(ModelError::Missing(_))
    ));
}

#[test]
fn the_wireguard_tables_are_gone() {
    // {[60100, "wg0"]: null}: WireGuard is not part of ruster.
    let old = encoded(|e| {
        e.map(1).array(2).u64(60_100).text("wg0").null();
    });
    assert!(matches!(
        decode_bytes(&old),
        Err(ModelError::UnknownTable(60_100))
    ));
}

#[test]
fn a_nat_without_the_ipv4_id_rate_limit_and_with_per_host_limits_round_trips() {
    let change = Change::set(
        Key::Nat {
            vrf: DEFAULT_VRF.into(),
        },
        Value::Nat(ruster_proto::table::Nat {
            inside: "lan".into(),
            outside: "wan".into(),
            external: None,
            ports: ruster_proto::table::NatPorts::Range {
                first: 1_024,
                last: 2_047,
            },
            filtering: Default::default(),
            ipv4_id_rate_limit: false,
            ports_per_host: 64,
            state_per_host: 512,
        }),
    );
    assert_eq!(round_trip(&change), change);
}

#[test]
fn a_per_host_limit_over_u16_is_refused_by_its_name() {
    let change = Change::set(
        Key::Nat {
            vrf: DEFAULT_VRF.into(),
        },
        Value::Nat(ruster_proto::table::Nat {
            inside: "lan".into(),
            outside: "wan".into(),
            external: None,
            ports: ruster_proto::table::NatPorts::Range {
                first: 1_024,
                last: 2_047,
            },
            filtering: Default::default(),
            ipv4_id_rate_limit: true,
            ports_per_host: 0,
            state_per_host: 512,
        }),
    );
    let mut out = Vec::new();
    change.encode(&mut Encoder::new(&mut out)).unwrap();
    // state-per-host (member 102) = 512, made 70000.
    let at = out
        .windows(5)
        .position(|w| w == [0x18, 102, 0x19, 0x02, 0x00])
        .expect("the member");
    out.splice(at + 2..at + 5, [0x1a, 0x00, 0x01, 0x11, 0x70]);
    assert_eq!(
        decode_bytes(&out),
        Err(ModelError::Invalid("state-per-host"))
    );
}

fn punt(class: &str, value: ruster_proto::table::PuntClass) -> Change {
    Change::set(
        Key::Punt {
            class: class.into(),
        },
        Value::Punt(value),
    )
}

#[test]
fn punt_classes_round_trip() {
    use ruster_proto::table::{PuntClass, PuntDestination, PuntKind, PuntMatch};
    let dhcp = punt(
        "dhcpv4",
        PuntClass {
            matches: PuntMatch::Ip {
                protocol: 17,
                ports: Some((67, 68)),
            },
            interface: Some("lan".into()),
            destination: PuntDestination::Control("ruster-kea".into()),
            rate: 100,
            burst: 20,
        },
    );
    let pppoe = punt(
        "pppoe-discovery",
        PuntClass {
            matches: PuntMatch::Kind(PuntKind::PppoeDiscovery),
            interface: None,
            destination: PuntDestination::Control("ruster-pppoed".into()),
            rate: 10,
            burst: 10,
        },
    );
    let icmp = punt(
        "icmp",
        PuntClass {
            matches: PuntMatch::Kind(PuntKind::Icmp),
            interface: None,
            destination: PuntDestination::Kernel,
            rate: 2_000,
            burst: 200,
        },
    );
    let ospf = punt(
        "ospf",
        PuntClass {
            matches: PuntMatch::Ip {
                protocol: 89,
                ports: None,
            },
            interface: None,
            destination: PuntDestination::Drop,
            rate: 1,
            burst: 1,
        },
    );
    let tap = punt(
        "ospf-wan",
        PuntClass {
            matches: PuntMatch::Kind(PuntKind::Ospf),
            interface: Some("wan".into()),
            destination: PuntDestination::Tap,
            rate: 100,
            burst: 50,
        },
    );
    let gone = Change::delete(Key::Punt { class: "x".into() });
    for change in [dhcp, pppoe, icmp, ospf, tap, gone] {
        assert_eq!(round_trip(&change), change);
    }
    for kind in PuntKind::ALL {
        assert_eq!(PuntKind::from_name(kind.name()), Some(kind));
    }
}

#[test]
fn a_bad_punt_class_is_refused() {
    use ruster_proto::table::{PuntClass, PuntDestination, PuntKind, PuntMatch};
    let class = |matches, destination| PuntClass {
        matches,
        interface: None,
        destination,
        rate: 10,
        burst: 10,
    };
    let control = |name: &str| PuntDestination::Control(name.into());
    let udp = PuntMatch::Ip {
        protocol: 17,
        ports: Some((67, 67)),
    };
    let refused = [
        class(PuntMatch::Kind(PuntKind::Arp), PuntDestination::Kernel),
        class(PuntMatch::Kind(PuntKind::Udp), control("kea")),
        class(
            PuntMatch::Ip {
                protocol: 1,
                ports: Some((1, 2)),
            },
            PuntDestination::Kernel,
        ),
        class(
            PuntMatch::Ip {
                protocol: 17,
                ports: Some((68, 67)),
            },
            PuntDestination::Kernel,
        ),
        class(udp, control("../etc")),
        class(udp, control("Kea")),
        class(udp, control("")),
        class(udp, control(&"a".repeat(33))),
        PuntClass {
            rate: 0,
            ..class(udp, PuntDestination::Drop)
        },
        PuntClass {
            burst: 0,
            ..class(udp, PuntDestination::Drop)
        },
        PuntClass {
            interface: Some(String::new()),
            ..class(udp, PuntDestination::Drop)
        },
        // IS-IS and OSPF go to an interface's TAP, and only they do.
        class(PuntMatch::Kind(PuntKind::Isis), PuntDestination::Tap),
        PuntClass {
            interface: Some("wan".into()),
            ..class(PuntMatch::Kind(PuntKind::Ospf), PuntDestination::Kernel)
        },
        PuntClass {
            interface: Some("wan".into()),
            ..class(udp, PuntDestination::Tap)
        },
    ];
    for value in refused {
        let change = punt("x", value.clone());
        assert!(change.validate().is_err(), "{value:?}");
    }
    assert!(punt("x", class(udp, control(&"a".repeat(32))))
        .validate()
        .is_ok());

    // {[60170, "x"]: {1: "arp", 2: 17, 6: "neighd", 9: 1, 10: 1}}: a kind and a
    // protocol both.
    let both = encoded(|e| {
        e.map(1)
            .array(2)
            .u64(sid::PUNT)
            .text("x")
            .map(5)
            .u64(1)
            .text("arp")
            .u64(2)
            .u64(17)
            .u64(6)
            .text("neighd")
            .u64(9)
            .u64(1)
            .u64(10)
            .u64(1);
    });
    assert!(decode_bytes(&both).is_err());
    // Two destinations.
    let two = encoded(|e| {
        e.map(1)
            .array(2)
            .u64(sid::PUNT)
            .text("x")
            .map(5)
            .u64(1)
            .text("udp")
            .u64(7)
            .bool(true)
            .u64(8)
            .bool(true)
            .u64(9)
            .u64(1)
            .u64(10)
            .u64(1);
    });
    assert!(decode_bytes(&two).is_err());
    // No burst.
    let no_burst = encoded(|e| {
        e.map(1)
            .array(2)
            .u64(sid::PUNT)
            .text("x")
            .map(3)
            .u64(1)
            .text("udp")
            .u64(7)
            .bool(true)
            .u64(9)
            .u64(1);
    });
    assert_eq!(decode_bytes(&no_burst), Err(ModelError::Missing("burst")));
}

#[test]
fn source_values_round_trip_and_are_checked() {
    let session = Change::set(
        Key::SourcePppoe {
            source: "pppoe-wan".into(),
        },
        Value::SourcePppoe {
            session: 4660,
            peer: [2, 0, 0, 0, 0, 0xac],
            mtu: 1492,
            lifetime: 60,
        },
    );
    let address = Change::set(
        Key::SourceIpv4 {
            source: "pppoe-wan".into(),
        },
        Value::SourceIpv4 {
            address: Ipv4Addr::new(198, 51, 100, 2),
            prefix_len: 32,
            lifetime: 60,
        },
    );
    for change in [&session, &address] {
        assert_eq!(&round_trip(change), change);
        assert_eq!(
            &round_trip(&Change::delete(change.key.clone())),
            &Change::delete(change.key.clone())
        );
    }
    let with = |value| Change::set(session.key.clone(), value);
    let bad = [
        with(Value::SourcePppoe {
            session: 0,
            peer: [2, 0, 0, 0, 0, 0xac],
            mtu: 1492,
            lifetime: 60,
        }),
        with(Value::SourcePppoe {
            session: 1,
            peer: [1, 0, 0, 0, 0, 0xac],
            mtu: 1492,
            lifetime: 60,
        }),
        with(Value::SourcePppoe {
            session: 1,
            peer: [2, 0, 0, 0, 0, 0xac],
            mtu: 1492,
            lifetime: 0,
        }),
        Change::set(
            address.key.clone(),
            Value::SourceIpv4 {
                address: Ipv4Addr::new(198, 51, 100, 2),
                prefix_len: 33,
                lifetime: 60,
            },
        ),
        // The value of another table.
        Change::set(
            address.key.clone(),
            Value::SourcePppoe {
                session: 1,
                peer: [2, 0, 0, 0, 0, 0xac],
                mtu: 1492,
                lifetime: 60,
            },
        ),
    ];
    for change in bad {
        assert!(change.validate().is_err(), "{change:?}");
    }
}

#[test]
fn dhcp_source_values_round_trip_and_are_checked() {
    let source = || "dhcp6-wan".to_owned();
    let prefix = |prefix: &str, len, preferred, valid| {
        Change::set(
            Key::SourcePrefix { source: source() },
            Value::SourcePrefix {
                prefix: prefix.parse().unwrap(),
                prefix_len: len,
                preferred,
                valid,
                lifetime: 60,
            },
        )
    };
    let address = |len, lifetime| {
        Change::set(
            Key::SourceIpv6 { source: source() },
            Value::SourceIpv6 {
                address: "2001:db8::2".parse().unwrap(),
                prefix_len: len,
                lifetime,
            },
        )
    };
    let dns = |servers: Vec<IpAddr>| {
        Change::set(
            Key::SourceDns { source: source() },
            Value::SourceDns {
                servers,
                lifetime: 60,
            },
        )
    };
    let good = [
        prefix("2001:db8:12:3400::", 56, 3600, 7200),
        address(128, 60),
        dns(vec![
            Ipv4Addr::new(192, 0, 2, 53).into(),
            "2001:db8::53".parse().unwrap(),
        ]),
    ];
    for change in &good {
        change.validate().unwrap();
        assert_eq!(&round_trip(change), change);
        let delete = Change::delete(change.key.clone());
        assert_eq!(round_trip(&delete), delete);
    }
    let bad = [
        // Bits after the prefix length.
        prefix("2001:db8:12:3401::", 56, 3600, 7200),
        prefix("2001:db8:12:3400::", 0, 3600, 7200),
        // Preferred above valid.
        prefix("2001:db8:12:3400::", 56, 7201, 7200),
        address(129, 60),
        address(128, 0),
        dns(Vec::new()),
        dns(vec![Ipv4Addr::new(192, 0, 2, 53).into(); 9]),
        // The value of another table.
        Change::set(
            Key::SourceDns { source: source() },
            Value::SourceIpv6 {
                address: "2001:db8::2".parse().unwrap(),
                prefix_len: 128,
                lifetime: 60,
            },
        ),
    ];
    for change in bad {
        assert!(change.validate().is_err(), "{change:?}");
    }
}

#[test]
fn gateway_routes_round_trip_and_do_not_mix_with_interface_hops() {
    let route = |prefix: IpAddr, len| Key::Route {
        vrf: DEFAULT_VRF.into(),
        prefix,
        len,
    };
    let change = Change::set(
        route(ip([203, 0, 113, 0]), 24),
        Value::Route(RouteAction::Gateways(vec![
            ip([10, 255, 0, 2]),
            ip([10, 255, 0, 3]),
        ])),
    );
    assert_eq!(round_trip(&change), change);
    let v6 = Change::set(
        route(ip6("2001:db8:203::"), 64),
        Value::Route(RouteAction::Gateways(vec![ip6("2001:db8:ff::2")])),
    );
    assert_eq!(round_trip(&v6), v6);

    // A gateway of the other family, a link-local one, and none at all.
    let v6_route = |gateways| {
        Change::set(
            route(ip6("2001:db8:203::"), 64),
            Value::Route(RouteAction::Gateways(gateways)),
        )
    };
    assert!(v6_route(vec![ip6("fe80::1")]).validate().is_err());
    for gateways in [vec![ip6("2001:db8::1")], vec![]] {
        let bad = Change::set(
            route(ip([203, 0, 113, 0]), 24),
            Value::Route(RouteAction::Gateways(gateways)),
        );
        assert!(bad.validate().is_err());
    }

    // One next hop with an interface and one without.
    let bytes = encoded(|e| {
        let d = |member: u64| member - sid::ROUTE_NEXT_HOP;
        e.map(1)
            .array(3)
            .u64(sid::ROUTE)
            .text("default")
            .text("203.0.113.0/24")
            .map(1)
            .u64(sid::ROUTE_NEXT_HOP - sid::ROUTE)
            .array(2)
            .map(2)
            .u64(d(sid::NEXT_HOP_INTERFACE))
            .text("wan")
            .u64(d(sid::NEXT_HOP_ADDRESS))
            .text("198.51.100.10")
            .map(1)
            .u64(d(sid::NEXT_HOP_ADDRESS))
            .text("10.255.0.2");
    });
    assert!(matches!(decode_bytes(&bytes), Err(ModelError::Invalid(_))));
}

#[test]
fn bridge_entries_round_trip_and_are_checked() {
    let entries = [
        Change::set(
            Key::Bridge { name: "br0".into() },
            Value::Bridge {
                aging_s: 300,
                max_learned: 4096,
            },
        ),
        Change::set(
            Key::BridgePort {
                interface: "p1".into(),
            },
            Value::BridgePort {
                bridge: "br0".into(),
            },
        ),
        Change::set(
            Key::BridgeMac {
                bridge: "br0".into(),
                mac: [2, 0, 0, 0, 0, 0x0a],
            },
            Value::BridgeMac {
                interface: "p1".into(),
            },
        ),
        Change::delete(Key::BridgeMac {
            bridge: "br0".into(),
            mac: [2, 0, 0, 0, 0, 0x0b],
        }),
    ];
    for change in &entries {
        assert_eq!(&round_trip(change), change);
    }
    assert_eq!(
        entry_line(&entries[2].key, entries[2].value.as_ref().unwrap()).unwrap(),
        "bridge-mac br0 02:00:00:00:00:0a p1"
    );
    let bad = [
        Change::set(
            Key::Bridge { name: "br0".into() },
            Value::Bridge {
                aging_s: 9,
                max_learned: 1,
            },
        ),
        Change::set(
            Key::Bridge { name: "br0".into() },
            Value::Bridge {
                aging_s: 300,
                max_learned: 0,
            },
        ),
        // A member cannot be the bridge's own interface.
        Change::set(
            Key::BridgePort {
                interface: "br0".into(),
            },
            Value::BridgePort {
                bridge: "br0".into(),
            },
        ),
        Change::set(
            Key::BridgeMac {
                bridge: "br0".into(),
                mac: [1, 0, 0, 0, 0, 1],
            },
            Value::BridgeMac {
                interface: "p1".into(),
            },
        ),
        Change::set(
            Key::BridgePort {
                interface: "p1".into(),
            },
            Value::BridgeMac {
                interface: "p1".into(),
            },
        ),
    ];
    for change in &bad {
        assert!(change.validate().is_err(), "{change:?}");
    }
}

#[test]
fn etherip_entries_round_trip_and_are_checked() {
    let ip = |a: &str| a.parse::<std::net::IpAddr>().unwrap();
    let entries = [
        Change::set(
            Key::EtherIp {
                interface: "eip0".into(),
            },
            Value::EtherIp {
                local: ip("192.0.2.1"),
                remote: ip("198.51.100.2"),
            },
        ),
        Change::set(
            Key::EtherIp {
                interface: "eip1".into(),
            },
            Value::EtherIp {
                local: ip("2001:db8::1"),
                remote: ip("2001:db8:1::2"),
            },
        ),
        Change::delete(Key::EtherIp {
            interface: "eip0".into(),
        }),
    ];
    for change in &entries {
        assert_eq!(&round_trip(change), change);
    }
    assert_eq!(
        entry_line(&entries[0].key, entries[0].value.as_ref().unwrap()).unwrap(),
        "etherip eip0 192.0.2.1 to 198.51.100.2"
    );
    let bad = [
        ("192.0.2.1", "2001:db8::2"),
        ("0.0.0.0", "192.0.2.2"),
        ("192.0.2.1", "224.0.0.1"),
        ("192.0.2.1", "192.0.2.1"),
        ("2001:db8::1", "::1"),
    ];
    for (local, remote) in bad {
        let change = Change::set(
            Key::EtherIp {
                interface: "eip0".into(),
            },
            Value::EtherIp {
                local: ip(local),
                remote: ip(remote),
            },
        );
        assert!(change.validate().is_err(), "{change:?}");
    }
}

#[test]
fn vxlan_entries_round_trip_and_are_checked() {
    let ip = |a: &str| a.parse::<std::net::IpAddr>().unwrap();
    let entry = |vni: u32, local: &str, remotes: &[&str]| {
        Change::set(
            Key::Vxlan {
                interface: "vx0".into(),
            },
            Value::Vxlan {
                vni,
                local: ip(local),
                remotes: remotes.iter().map(|r| ip(r)).collect(),
            },
        )
    };
    let good = entry(100, "192.0.2.1", &["198.51.100.2", "198.51.100.3"]);
    assert_eq!(round_trip(&good), good);
    let v6 = entry(16_777_215, "2001:db8::1", &["2001:db8:1::2"]);
    assert_eq!(round_trip(&v6), v6);
    assert_eq!(
        entry_line(&good.key, good.value.as_ref().unwrap()).unwrap(),
        "vxlan vx0 vni 100 192.0.2.1 to 198.51.100.2 198.51.100.3"
    );
    for bad in [
        entry(0, "192.0.2.1", &["198.51.100.2"]),
        entry(16_777_216, "192.0.2.1", &["198.51.100.2"]),
        entry(100, "192.0.2.1", &[]),
        entry(100, "192.0.2.1", &["2001:db8::2"]),
        entry(100, "192.0.2.1", &["192.0.2.1"]),
        entry(100, "192.0.2.1", &["198.51.100.2", "198.51.100.2"]),
        entry(100, "192.0.2.1", &["239.1.1.1"]),
    ] {
        assert!(bad.validate().is_err(), "{bad:?}");
    }
}
