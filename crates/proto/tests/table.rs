//! Table entry encoding tests.

use std::net::Ipv4Addr;

use ruster_proto::cbor::{Decoder, Encoder};
use ruster_proto::sid;
use ruster_proto::table::{
    format_mac, parse_mac, Change, Key, ModelError, NextHop, RouteAction, Value,
};

fn round_trip(change: &Change) -> Change {
    let mut out = Vec::new();
    change.encode(&mut Encoder::new(&mut out));
    let mut d = Decoder::new(&out);
    let back = Change::decode(&mut d).unwrap();
    assert!(d.is_empty());
    back
}

fn ip(a: [u8; 4]) -> Ipv4Addr {
    Ipv4Addr::from(a)
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
    change.encode(&mut Encoder::new(&mut out));
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
