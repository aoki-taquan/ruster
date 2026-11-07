//! The configuration file.

use std::net::Ipv4Addr;

use ruster_confd::file::parse;
use ruster_confd::{InterfaceConfig, StaticRoute};

const GOOD: &str = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"

[[interface]]
name = "wan"
mac = "02:00:00:00:00:02"
mtu = 1400
enabled = false

[[route]]
prefix = "0.0.0.0/0"
interface = "wan"
via = "198.51.100.1"

[[route]]
prefix = "10.0.0.0/8"
interface = "lan"
"#;

#[test]
fn a_file_becomes_the_configuration() {
    let config = parse(GOOD).unwrap();
    assert_eq!(
        config.interfaces,
        vec![
            InterfaceConfig {
                name: "lan".into(),
                mac: [2, 0, 0, 0, 0, 1],
                mtu: 1500,
                enabled: true,
                ipv4: Some((Ipv4Addr::new(192, 0, 2, 1), 24)),
                ipv6: Vec::new(),
            },
            InterfaceConfig {
                name: "wan".into(),
                mac: [2, 0, 0, 0, 0, 2],
                mtu: 1400,
                enabled: false,
                ipv4: None,
                ipv6: Vec::new(),
            },
        ]
    );
    assert_eq!(
        config.static_routes,
        vec![
            StaticRoute {
                prefix: Ipv4Addr::UNSPECIFIED.into(),
                len: 0,
                interface: "wan".into(),
                via: Some(Ipv4Addr::new(198, 51, 100, 1).into()),
            },
            StaticRoute {
                prefix: Ipv4Addr::new(10, 0, 0, 0).into(),
                len: 8,
                interface: "lan".into(),
                via: None,
            },
        ]
    );
}

#[test]
fn an_empty_file_is_an_empty_configuration() {
    let config = parse("").unwrap();
    assert!(config.interfaces.is_empty());
    assert!(config.static_routes.is_empty());
}

fn error(text: &str) -> String {
    parse(text).unwrap_err()
}

const LAN: &str = "[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:01\"\n";

#[test]
fn mistakes_are_refused_with_what_is_wrong() {
    for (text, expected) in [
        ("[[interfaces]]\n", "unknown field"),
        (&format!("{LAN}colour = \"red\"\n"), "unknown field"),
        (&format!("{LAN}{LAN}"), "given twice"),
        (
            "[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00\"\n",
            "mac is not like",
        ),
        (
            "[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:+1\"\n",
            "mac is not like",
        ),
        (
            "[[interface]]\nname = \"lan\"\nmac = \"01:00:5e:00:00:01\"\n",
            "unicast",
        ),
        (&format!("{LAN}mtu = 67\n"), "68 to 1500"),
        (&format!("{LAN}mtu = 9000\n"), "68 to 1500"),
        (&format!("{LAN}ipv4 = \"0.0.0.0/8\"\n"), "unicast"),
        (&format!("{LAN}ipv4 = \"127.0.0.1/8\"\n"), "unicast"),
        (&format!("{LAN}ipv4 = \"224.0.0.1/24\"\n"), "unicast"),
        (&format!("{LAN}ipv4 = \"255.255.255.255/32\"\n"), "unicast"),
        (
            &format!(
                "{LAN}ipv4 = \"192.0.2.1/24\"\n[[interface]]\nname = \"wan\"\n\
                 mac = \"02:00:00:00:00:02\"\nipv4 = \"192.0.2.1/30\"\n"
            ),
            "given twice",
        ),
        (
            &format!(
                "{LAN}ipv4 = \"192.0.2.1/24\"\n[[interface]]\nname = \"wan\"\n\
                 mac = \"02:00:00:00:00:02\"\nipv4 = \"192.0.2.2/24\"\n"
            ),
            "already on an interface",
        ),
        (
            &format!(
                "{LAN}ipv4 = \"192.0.2.1/24\"\n[[route]]\nprefix = \"10.0.0.0/8\"\n\
                 interface = \"lan\"\nvia = \"192.0.2.1\"\n"
            ),
            "via must be",
        ),
        (
            &format!(
                "{LAN}[[route]]\nprefix = \"10.0.0.0/8\"\ninterface = \"lan\"\n\
                 via = \"255.255.255.255\"\n"
            ),
            "via must be",
        ),
        (&format!("{LAN}ipv4 = \"192.0.2.1\"\n"), "ipv4 is not like"),
        (
            &format!("{LAN}ipv4 = \"192.0.2.1/33\"\n"),
            "ipv4 is not like",
        ),
        (&format!("{LAN}ipv4 = \"192.0.2.1/0\"\n"), "1 to 32"),
        (
            &format!("{LAN}[[route]]\nprefix = \"10.0.0.1/8\"\ninterface = \"lan\"\n"),
            "after the prefix length",
        ),
        (
            &format!("{LAN}[[route]]\nprefix = \"10.0.0.0/8\"\ninterface = \"wan\"\n"),
            "no interface",
        ),
        (
            &format!("{LAN}[[route]]\nprefix = \"10.0.0.0/8\"\ninterface = \"lan\"\nvia = \"x\"\n"),
            "via must be",
        ),
        (
            &format!(
                "{LAN}[[route]]\nprefix = \"10.0.0.0/8\"\ninterface = \"lan\"\n\
                 [[route]]\nprefix = \"10.0.0.0/8\"\ninterface = \"lan\"\n"
            ),
            "given twice",
        ),
    ] {
        let got = error(text);
        assert!(got.contains(expected), "{text:?}: {got}");
    }
}

#[test]
fn ipv6_addresses_and_routes_are_read() {
    let config = parse(
        r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv6 = ["2001:db8:1::1/64", "2001:db8:2::1/64"]

[[route]]
prefix = "::/0"
interface = "lan"
via = "fe80::1"

[[route]]
prefix = "2001:db8:99::/48"
interface = "lan"
"#,
    )
    .unwrap();
    let v6 = |text: &str| text.parse::<std::net::Ipv6Addr>().unwrap();
    assert_eq!(
        config.interfaces[0].ipv6,
        vec![(v6("2001:db8:1::1"), 64), (v6("2001:db8:2::1"), 64)]
    );
    assert_eq!(config.static_routes[0].prefix, v6("::"));
    assert_eq!(config.static_routes[0].via, Some(v6("fe80::1").into()));
    assert_eq!(config.static_routes[1].len, 48);
}

#[test]
fn ipv6_mistakes_are_refused() {
    let lan6 = |ipv6: &str| {
        format!("[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:01\"\nipv6 = [{ipv6}]\n")
    };
    for (text, expected) in [
        (lan6("\"2001:db8::1\""), "is not like"),
        (lan6("\"2001:db8::1/129\""), "is not like"),
        (lan6("\"192.0.2.1/24\""), "is not like"),
        (lan6("\"2001:db8::1/0\""), "1 to 128"),
        (lan6("\"ff02::1/64\""), "unicast"),
        (lan6("\"::1/128\""), "unicast"),
        (lan6("\"2001:db8::1/064\""), "is not like"),
        (
            lan6("\"2001:db8::1/64\", \"2001:db8::2/64\""),
            "already on an interface",
        ),
        (
            format!(
                "{}[[route]]\nprefix = \"::/0\"\ninterface = \"lan\"\nvia = \"192.0.2.1\"\n",
                lan6("\"2001:db8::1/64\"")
            ),
            "via must be",
        ),
        (
            format!(
                "{}[[route]]\nprefix = \"::/0\"\ninterface = \"lan\"\nvia = \"2001:db8::1\"\n",
                lan6("\"2001:db8::1/64\"")
            ),
            "via must be",
        ),
        (
            format!(
                "{}[[route]]\nprefix = \"2001:db8::1/64\"\ninterface = \"lan\"\n",
                lan6("\"2001:db8::1/64\"")
            ),
            "after the prefix length",
        ),
    ] {
        let got = error(&text);
        assert!(got.contains(expected), "{text:?}: {got}");
    }
}

#[test]
fn the_link_local_address_comes_from_the_mac_address() {
    // RFC 4291 appendix A: the universal/local bit flipped, ff:fe in the middle.
    // 00-00-5E-00-53-00 is the documentation MAC address of RFC 7042.
    assert_eq!(
        ruster_confd::link_local([0x00, 0x00, 0x5e, 0x00, 0x53, 0x00]),
        "fe80::200:5eff:fe00:5300"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
    );
    assert_eq!(
        ruster_confd::link_local([0x02, 0, 0, 0, 0, 1]),
        "fe80::ff:fe00:1".parse::<std::net::Ipv6Addr>().unwrap()
    );
}

#[test]
fn the_router_s_own_link_local_address_is_not_a_next_hop() {
    // lan's automatic link-local address is fe80::ff:fe00:1.
    let text = "[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:01\"\n\
                [[route]]\nprefix = \"::/0\"\ninterface = \"lan\"\nvia = \"fe80::ff:fe00:1\"\n";
    assert!(error(text).contains("via must be"));
    // The same link-local address on another link is another host.
    let two = "[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:01\"\n\
               [[interface]]\nname = \"wan\"\nmac = \"02:00:00:00:00:02\"\n\
               [[route]]\nprefix = \"::/0\"\ninterface = \"wan\"\nvia = \"fe80::ff:fe00:1\"\n";
    assert!(parse(two).is_ok());
    // A link-local address may be given on two interfaces.
    let shared = "[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:01\"\nipv6 = [\"fe80::1/64\"]\n\
                  [[interface]]\nname = \"wan\"\nmac = \"02:00:00:00:00:02\"\nipv6 = [\"fe80::1/64\"]\n";
    assert!(parse(shared).is_ok());
}
