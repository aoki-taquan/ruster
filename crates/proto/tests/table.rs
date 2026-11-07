//! Table entry encoding tests.

use std::net::{IpAddr, Ipv4Addr};

use ruster_proto::cbor::{Decoder, Encoder};
use ruster_proto::sid;
use ruster_proto::table::{
    format_mac, parse_mac, Change, Key, ModelError, NextHop, RouteAction, Value, DEFAULT_VRF,
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
    assert!(values.iter().all(|v| (60_000..100_000).contains(v)));
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
