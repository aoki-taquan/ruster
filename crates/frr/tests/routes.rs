//! zebra's routes as ribd's: the next hops' interfaces, the kinds, and what is left
//! out.

use std::net::IpAddr;

use ruster_config::Connected;
use ruster_frr::fpm::{Hop, Kind, Route};
use ruster_frr::routes::{Routes, MAIN_TABLE};
use ruster_proto::table::{Change, Key, NextHop, RouteAction, Value};

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn connected() -> Vec<Connected> {
    [
        ("wan", "198.51.100.0/24"),
        ("wan2", "198.51.100.128/25"),
        ("wan", "2001:db8:100::/64"),
        ("lan", "192.0.2.0/24"),
    ]
    .into_iter()
    .map(|(i, p)| Connected {
        interface: i.into(),
        prefix: p.into(),
    })
    .collect()
}

fn route(new: bool, prefix: &str, len: u8, kind: Kind, gateways: &[&str]) -> Route {
    Route {
        new,
        prefix: ip(prefix),
        len,
        table: MAIN_TABLE,
        kind,
        hops: gateways
            .iter()
            .map(|g| Hop {
                gateway: (!g.is_empty()).then(|| ip(g)),
                oif: Some(3),
            })
            .collect(),
    }
}

fn key(prefix: &str, len: u8) -> Key {
    Key::Route {
        vrf: "default".into(),
        prefix: ip(prefix),
        len,
    }
}

fn forward(hops: &[(&str, &str)]) -> Value {
    Value::Route(RouteAction::Forward(
        hops.iter()
            .map(|(i, a)| NextHop {
                interface: (*i).into(),
                address: Some(ip(a)),
            })
            .collect(),
    ))
}

#[test]
fn next_hops_take_the_interface_of_the_longest_prefix() {
    let mut routes = Routes::new();
    assert!(routes.set_connected(&connected()).is_empty());
    let got = routes.take(&route(
        true,
        "203.0.113.0",
        24,
        Kind::Unicast,
        &["198.51.100.10", "198.51.100.200", "198.51.100.10"],
    ));
    assert_eq!(
        got,
        Some(Change::set(
            key("203.0.113.0", 24),
            forward(&[("wan", "198.51.100.10"), ("wan2", "198.51.100.200")])
        )),
        "ECMP, the same next hop once"
    );
    let v6 = routes.take(&route(
        true,
        "2001:db8:203::",
        48,
        Kind::Unicast,
        &["2001:db8:100::10"],
    ));
    assert_eq!(
        v6,
        Some(Change::set(
            key("2001:db8:203::", 48),
            forward(&[("wan", "2001:db8:100::10")])
        ))
    );
    // A next hop on no interface, a link-local one and none at all are left out.
    let left_out = routes.take(&route(
        true,
        "2001:db8:204::",
        48,
        Kind::Unicast,
        &["fe80::1", "2001:db8:9::1", ""],
    ));
    assert_eq!(
        left_out,
        Some(Change::delete(key("2001:db8:204::", 48))),
        "held, but nothing for ribd"
    );
    assert_eq!(routes.hops_left_out, 1 + 2, "no gateway, then the two");
    let partly = routes.take(&route(
        true,
        "10.0.0.0",
        8,
        Kind::Unicast,
        &["10.9.9.9", "192.0.2.254"],
    ));
    assert_eq!(
        partly,
        Some(Change::set(
            key("10.0.0.0", 8),
            forward(&[("lan", "192.0.2.254")])
        ))
    );
    // A connected route (no gateway) is not ribd's from here.
    assert_eq!(
        routes.take(&route(true, "198.51.100.0", 24, Kind::Unicast, &[""])),
        None
    );
    assert_eq!(routes.len(), 4);
}

#[test]
fn kinds_tables_and_deletes() {
    let mut routes = Routes::new();
    routes.set_connected(&connected());
    let blackhole = routes.take(&route(true, "10.0.0.0", 8, Kind::Blackhole, &[]));
    assert_eq!(
        blackhole,
        Some(Change::set(
            key("10.0.0.0", 8),
            Value::Route(RouteAction::Discard)
        ))
    );
    let reject = routes.take(&route(true, "10.1.0.0", 16, Kind::Unreachable, &[]));
    assert_eq!(
        reject,
        Some(Change::set(
            key("10.1.0.0", 16),
            Value::Route(RouteAction::Reject)
        ))
    );
    assert_eq!(
        routes.take(&route(true, "10.2.0.0", 16, Kind::Other(2), &[])),
        None
    );
    let mut other_table = route(true, "10.3.0.0", 16, Kind::Unicast, &["198.51.100.10"]);
    other_table.table = 1_000;
    assert_eq!(routes.take(&other_table), None);
    assert_eq!(routes.passed_over, 2);
    // A delete of a held route, and of one not held.
    assert_eq!(
        routes.take(&route(false, "10.0.0.0", 8, Kind::Unicast, &[])),
        Some(Change::delete(key("10.0.0.0", 8)))
    );
    assert_eq!(
        routes.take(&route(false, "10.9.0.0", 16, Kind::Unicast, &[])),
        None
    );
    // A route that becomes one ribd cannot use is deleted.
    assert_eq!(
        routes.take(&route(true, "10.1.0.0", 16, Kind::Other(2), &[])),
        Some(Change::delete(key("10.1.0.0", 16)))
    );
    assert!(routes.is_empty());
}

#[test]
fn new_prefixes_remap_the_next_hops() {
    let mut routes = Routes::new();
    routes.set_connected(&connected());
    routes.take(&route(
        true,
        "203.0.113.0",
        24,
        Kind::Unicast,
        &["198.51.100.10"],
    ));
    let moved = vec![Connected {
        interface: "wan3".into(),
        prefix: "198.51.100.0/24".into(),
    }];
    assert_eq!(
        routes.set_connected(&moved),
        [Change::set(
            key("203.0.113.0", 24),
            forward(&[("wan3", "198.51.100.10")])
        )]
    );
    assert_eq!(
        routes.set_connected(&[]),
        [Change::delete(key("203.0.113.0", 24))]
    );
    assert_eq!(routes.len(), 1, "still held: back when the prefix is");
}

#[test]
fn routes_not_sent_again_are_swept() {
    let mut routes = Routes::new();
    routes.set_connected(&connected());
    for prefix in ["10.0.0.0", "10.1.0.0", "10.2.0.0"] {
        routes.take(&route(true, prefix, 16, Kind::Unicast, &["198.51.100.10"]));
    }
    routes.mark_stale();
    routes.take(&route(
        true,
        "10.0.0.0",
        16,
        Kind::Unicast,
        &["198.51.100.10"],
    ));
    routes.take(&route(false, "10.1.0.0", 16, Kind::Unicast, &[]));
    assert_eq!(routes.sweep(), [Change::delete(key("10.2.0.0", 16))]);
    assert!(routes.sweep().is_empty());
    assert_eq!(routes.clear(), [Change::delete(key("10.0.0.0", 16))]);
}

#[test]
fn an_update_in_one_frame_is_one_change() {
    let mut routes = Routes::new();
    routes.set_connected(&connected());
    routes.take(&route(
        true,
        "10.0.0.0",
        8,
        Kind::Unicast,
        &["198.51.100.10"],
    ));
    let update = [
        route(false, "10.0.0.0", 8, Kind::Unicast, &[]),
        route(true, "10.0.0.0", 8, Kind::Unicast, &["192.0.2.254"]),
        route(true, "10.1.0.0", 16, Kind::Blackhole, &[]),
    ];
    assert_eq!(
        routes.take_frame(&update),
        [
            Change::set(key("10.0.0.0", 8), forward(&[("lan", "192.0.2.254")])),
            Change::set(key("10.1.0.0", 16), Value::Route(RouteAction::Discard)),
        ]
    );
}

#[test]
fn new_prefixes_change_only_the_routes_they_move() {
    let mut routes = Routes::new();
    routes.set_connected(&connected());
    routes.take(&route(
        true,
        "10.0.0.0",
        8,
        Kind::Unicast,
        &["198.51.100.10"],
    ));
    routes.take(&route(
        true,
        "10.1.0.0",
        16,
        Kind::Unicast,
        &["192.0.2.254", "192.0.2.254"],
    ));
    let mut fewer = connected();
    fewer.retain(|c| c.interface != "wan");
    assert_eq!(
        routes.set_connected(&fewer),
        [Change::delete(key("10.0.0.0", 8))]
    );
    assert!(routes.set_connected(&fewer).is_empty());
    assert_eq!(
        routes.set_connected(&connected()),
        [Change::set(
            key("10.0.0.0", 8),
            forward(&[("wan", "198.51.100.10")])
        )]
    );
}
