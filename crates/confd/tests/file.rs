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
            },
            InterfaceConfig {
                name: "wan".into(),
                mac: [2, 0, 0, 0, 0, 2],
                mtu: 1400,
                enabled: false,
                ipv4: None,
            },
        ]
    );
    assert_eq!(
        config.static_routes,
        vec![
            StaticRoute {
                prefix: Ipv4Addr::UNSPECIFIED,
                len: 0,
                interface: "wan".into(),
                via: Some(Ipv4Addr::new(198, 51, 100, 1)),
            },
            StaticRoute {
                prefix: Ipv4Addr::new(10, 0, 0, 0),
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
        (&format!("{LAN}mtu = 67\n"), "at least 68"),
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
            "via is not",
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
