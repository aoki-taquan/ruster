//! The configuration file.

use std::net::Ipv4Addr;

use ruster_confd::file::parse;
use ruster_confd::{InterfaceConfig, RouteTarget, StaticRoute};

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
                vrf: "default".into(),
                vlan: None,
                tunnel: None,
            },
            InterfaceConfig {
                name: "wan".into(),
                mac: [2, 0, 0, 0, 0, 2],
                mtu: 1400,
                enabled: false,
                ipv4: None,
                ipv6: Vec::new(),
                vrf: "default".into(),
                vlan: None,
                tunnel: None,
            },
        ]
    );
    assert_eq!(
        config.static_routes,
        vec![
            StaticRoute {
                vrf: "default".into(),
                prefix: Ipv4Addr::UNSPECIFIED.into(),
                len: 0,
                target: RouteTarget::Next {
                    interface: "wan".into(),
                    via: Some(Ipv4Addr::new(198, 51, 100, 1).into()),
                },
            },
            StaticRoute {
                vrf: "default".into(),
                prefix: Ipv4Addr::new(10, 0, 0, 0).into(),
                len: 8,
                target: RouteTarget::Next {
                    interface: "lan".into(),
                    via: None,
                },
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
    assert_eq!(
        config.static_routes[0].target,
        RouteTarget::Next {
            interface: "lan".into(),
            via: Some(v6("fe80::1").into())
        }
    );
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

#[test]
fn vrfs_may_reuse_addresses_and_routes_may_look_up_another_vrf() {
    let config = parse(
        r#"
[[interface]]
name = "red0"
mac = "02:00:00:00:00:01"
ipv4 = "10.0.0.1/24"
vrf = "red"

[[interface]]
name = "blue0"
mac = "02:00:00:00:00:02"
ipv4 = "10.0.0.1/24"
vrf = "blue"

[[interface]]
name = "wan"
mac = "02:00:00:00:00:03"
ipv4 = "198.51.100.2/24"

[[route]]
prefix = "0.0.0.0/0"
interface = "wan"
via = "198.51.100.1"

[[route]]
vrf = "red"
prefix = "0.0.0.0/0"
lookup-vrf = "default"
"#,
    )
    .unwrap();
    assert_eq!(config.interfaces[0].vrf, "red");
    assert_eq!(config.interfaces[2].vrf, "default");
    assert_eq!(config.static_routes[1].vrf, "red");
    assert_eq!(
        config.static_routes[1].target,
        RouteTarget::LookupVrf("default".into())
    );
}

#[test]
fn vrf_mistakes_are_refused() {
    let one = |extra: &str| {
        format!(
            "[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:01\"\nipv4 = \"10.0.0.1/24\"\n{extra}"
        )
    };
    for (text, expected) in [
        (one("vrf = \"\"\n"), "must not be empty"),
        (
            one("[[route]]\nprefix = \"0.0.0.0/0\"\nlookup-vrf = \"default\"\n"),
            "another VRF",
        ),
        (
            one("[[route]]\nprefix = \"0.0.0.0/0\"\n"),
            "either interface or lookup-vrf",
        ),
        (
            one("[[route]]\nprefix = \"0.0.0.0/0\"\ninterface = \"lan\"\nlookup-vrf = \"red\"\n"),
            "either interface or lookup-vrf",
        ),
        (
            one("[[route]]\nvrf = \"red\"\nprefix = \"0.0.0.0/0\"\nlookup-vrf = \"default\"\nvia = \"10.0.0.9\"\n"),
            "has no via",
        ),
        (
            one("[[route]]\nvrf = \"red\"\nprefix = \"0.0.0.0/0\"\nlookup-vrf = \"defualt\"\n"),
            "no interface or route is in VRF",
        ),
        (
            one("[[route]]\nvrf = \"red\"\nprefix = \"0.0.0.0/0\"\nlookup-vrf = \"blue\"\n\
                 [[route]]\nvrf = \"blue\"\nprefix = \"0.0.0.0/0\"\nlookup-vrf = \"default\"\n"),
            "not followed",
        ),
    ] {
        let got = error(&text);
        assert!(got.contains(expected), "{text:?}: {got}");
    }
}

#[test]
fn the_kernel_side_has_a_tun_device_per_vrf_with_its_addresses() {
    let config = parse(
        r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"
ipv6 = ["2001:db8:1::1/64"]

[[interface]]
name = "red0"
mac = "02:00:00:00:00:02"
ipv4 = "10.0.0.1/24"
vrf = "red"
"#,
    )
    .unwrap();
    let commands: Vec<String> = ruster_confd::kernel::commands(&config)
        .iter()
        .map(|args| args.join(" "))
        .collect();
    for expected in [
        "tuntap add mode tun dev rt-default",
        "address replace 192.0.2.1/24 dev rt-default",
        "address replace 2001:db8:1::1/64 dev rt-default nodad",
        "-4 route replace default dev rt-default",
        "-6 route replace default dev rt-default",
        "tuntap add mode tun dev rt-red",
        "link add vrf-red type vrf table TABLE",
        "link set rt-red master vrf-red",
        "address replace 10.0.0.1/24 dev rt-red",
        "-4 route replace default dev rt-red table TABLE",
    ] {
        let expected = expected.replace("TABLE", &ruster_confd::kernel::table("red").to_string());
        assert!(commands.contains(&expected), "{expected}: {commands:#?}");
    }
    assert!(
        !commands.iter().any(|c| c.contains("fe80")),
        "no link-local addresses"
    );
}

#[test]
fn a_vrf_s_kernel_table_depends_only_on_its_name() {
    use ruster_confd::kernel::table;
    assert_eq!(table("red"), table("red"));
    assert_ne!(table("red"), table("blue"));
    assert!(table("red") >= 1_000);
}

#[test]
fn vlan_sub_interfaces_are_read_and_checked() {
    let lan = "[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:01\"\n";
    let config = parse(&format!(
        "{lan}[[interface]]\nname = \"lan.10\"\nparent = \"lan\"\nvlan = 10\nipv4 = \"10.10.0.1/24\"\n"
    ))
    .unwrap();
    assert_eq!(config.interfaces[1].vlan, Some(("lan".into(), 10)));
    assert_eq!(config.interfaces[1].mac, [2, 0, 0, 0, 0, 1], "the parent's");
    for (text, expected) in [
        (
            format!("{lan}[[interface]]\nname = \"x\"\nparent = \"lan\"\nvlan = 0\n"),
            "1 to 4094",
        ),
        (
            format!("{lan}[[interface]]\nname = \"x\"\nparent = \"nope\"\nvlan = 10\n"),
            "must be an interface given before it",
        ),
        (
            format!("{lan}[[interface]]\nname = \"x\"\nparent = \"lan\"\n"),
            "parent and vlan together",
        ),
        (
            format!(
                "{lan}[[interface]]\nname = \"a\"\nparent = \"lan\"\nvlan = 10\n\
                 [[interface]]\nname = \"b\"\nparent = \"lan\"\nvlan = 10\n"
            ),
            "given twice",
        ),
        (
            "[[interface]]\nname = \"lan\"\n".to_owned(),
            "mac is missing",
        ),
    ] {
        let got = error(&text);
        assert!(got.contains(expected), "{text:?}: {got}");
    }
}

#[test]
fn a_sub_interface_mtu_leaves_room_for_the_tag() {
    let lan = "[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:01\"\n";
    let config = parse(&format!(
        "{lan}[[interface]]\nname = \"lan.10\"\nparent = \"lan\"\nvlan = 10\n"
    ))
    .unwrap();
    assert_eq!(config.interfaces[1].mtu, 1496);
    let got = error(&format!(
        "{lan}[[interface]]\nname = \"lan.10\"\nparent = \"lan\"\nvlan = 10\nmtu = 1500\n"
    ));
    assert!(got.contains("68 to 1496"), "{got}");
}

#[test]
fn firewall_rules_keep_their_order_and_default_to_any() {
    let text = format!(
        "{LAN}[[firewall]]\naction = \"accept\"\nprotocol = \"udp\"\ningress = \"lan\"\n\
         destination = \"203.0.113.0/24\"\ndestination-ports = \"53\"\n\
         [[firewall]]\naction = \"drop\"\nprotocol = \"icmp\"\n\
         [[firewall]]\naction = \"accept\"\nprotocol = \"tcp\"\nsource-ports = \"1024-65535\"\n"
    );
    let config = parse(&text).unwrap();
    use ruster_proto::table::{FirewallAction, FirewallRule, Protocol};
    let any = (Ipv4Addr::UNSPECIFIED, 0);
    assert_eq!(
        config.firewall,
        vec![
            FirewallRule {
                ingress: Some("lan".into()),
                egress: None,
                source: any,
                destination: (Ipv4Addr::new(203, 0, 113, 0), 24),
                protocol: Protocol::Udp,
                source_ports: (0, 65_535),
                destination_ports: (53, 53),
                action: FirewallAction::Accept,
            },
            FirewallRule {
                ingress: None,
                egress: None,
                source: any,
                destination: any,
                protocol: Protocol::Icmp,
                source_ports: (0, 65_535),
                destination_ports: (0, 65_535),
                action: FirewallAction::Drop,
            },
            FirewallRule {
                ingress: None,
                egress: None,
                source: any,
                destination: any,
                protocol: Protocol::Tcp,
                source_ports: (1_024, 65_535),
                destination_ports: (0, 65_535),
                action: FirewallAction::Accept,
            },
        ]
    );
}

#[test]
fn firewall_mistakes_are_refused() {
    let rule = |extra: &str| {
        format!("{LAN}vrf = \"red\"\n[[interface]]\nname = \"wan\"\nmac = \"02:00:00:00:00:02\"\n[[firewall]]\n{extra}")
    };
    for (text, expected) in [
        (
            rule("action = \"allow\"\nprotocol = \"udp\"\n"),
            "action must be",
        ),
        (
            rule("action = \"accept\"\nprotocol = \"sctp\"\n"),
            "protocol must be",
        ),
        (
            rule("action = \"accept\"\nprotocol = \"udp\"\ningress = \"dmz\"\n"),
            "no interface \"dmz\"",
        ),
        (
            rule("action = \"accept\"\nprotocol = \"udp\"\ningress = \"lan\"\n"),
            "is in VRF \"red\"",
        ),
        (
            rule("action = \"accept\"\nprotocol = \"udp\"\nsource = \"10.0.0.1/8\"\n"),
            "no host bits",
        ),
        (
            rule("action = \"accept\"\nprotocol = \"udp\"\nsource = \"2001:db8::/32\"\n"),
            "IPv4 prefix",
        ),
        (
            rule("action = \"accept\"\nprotocol = \"icmp\"\ndestination-ports = \"53\"\n"),
            "tcp and udp only",
        ),
        (
            rule("action = \"accept\"\nprotocol = \"tcp\"\ndestination-ports = \"80-22\"\n"),
            "a port or a range",
        ),
        (
            rule("action = \"accept\"\nprotocol = \"tcp\"\ndestination-ports = \"+53\"\n"),
            "a port or a range",
        ),
    ] {
        let got = error(&text);
        assert!(got.contains(expected), "{text}: {got}");
    }
    assert!(parse(&rule(
        "action = \"accept\"\nprotocol = \"udp\"\negress = \"wan\"\n"
    ))
    .is_ok());
}

#[test]
fn nat_takes_the_outside_address_and_a_port_range() {
    let wan =
        "[[interface]]\nname = \"wan\"\nmac = \"02:00:00:00:00:02\"\nipv4 = \"198.51.100.2/24\"\n";
    let nat =
        |extra: &str| format!("{LAN}{wan}[nat]\ninside = \"lan\"\noutside = \"wan\"\n{extra}");
    assert_eq!(
        parse(&nat("")).unwrap().nat,
        Some(ruster_proto::table::Nat {
            inside: "lan".into(),
            outside: "wan".into(),
            external: None,
            first_port: 1_024,
            last_port: 32_767,
        })
    );
    let got = parse(&nat(
        "ports = \"40000-40999\"\nexternal = \"198.51.100.2\"\n",
    ))
    .unwrap()
    .nat
    .unwrap();
    assert_eq!((got.first_port, got.last_port), (40_000, 40_999));
    assert_eq!(got.external, Some(Ipv4Addr::new(198, 51, 100, 2)));
    for (text, expected) in [
        (nat("ports = \"0-100\"\n"), "not 0"),
        (nat("ports = \"9-1\"\n"), "a range"),
        (nat("external = \"203.0.113.1\"\n"), "external must be"),
        (
            format!("{LAN}{wan}[nat]\ninside = \"lan\"\noutside = \"lan\"\n"),
            "different",
        ),
        (
            format!("{LAN}{wan}[nat]\ninside = \"dmz\"\noutside = \"wan\"\n"),
            "no interface",
        ),
        (
            format!("{LAN}{wan}[nat]\ninside = \"wan\"\noutside = \"lan\"\n"),
            "has no ipv4 address",
        ),
    ] {
        let got = error(&text);
        assert!(got.contains(expected), "{text}: {got}");
    }
}

#[test]
fn an_interface_address_is_not_its_network_or_broadcast() {
    let with = |ipv4: &str| {
        format!("[[interface]]\nname = \"wan\"\nmac = \"02:00:00:00:00:02\"\nipv4 = \"{ipv4}\"\n")
    };
    for bad in [
        "198.51.100.0/24",
        "198.51.100.255/24",
        "10.0.0.4/30",
        "10.0.0.7/30",
    ] {
        assert!(error(&with(bad)).contains("network or broadcast"), "{bad}");
    }
    for good in [
        "198.51.100.1/24",
        "10.0.0.5/30",
        "10.0.0.0/31",
        "10.0.0.1/32",
    ] {
        assert!(parse(&with(good)).is_ok(), "{good}");
    }
}

#[test]
fn a_tunnel_interface_needs_no_mac_and_sends_from_a_router_address() {
    let wan = "[[interface]]\nname = \"wan\"\nmac = \"02:00:00:00:00:02\"\nipv6 = [\"2001:db8:1::2/64\"]\n";
    let dslite = |local: &str, extra: &str| {
        format!("{wan}[[interface]]\nname = \"dslite\"\ntunnel = {{ local = \"{local}\", remote = \"2001:db8:ff::1\" }}\n{extra}")
    };
    let config = parse(&dslite("2001:db8:1::2", "ipv4 = \"192.0.0.2/29\"\n")).unwrap();
    let tunnel = &config.interfaces[1];
    assert_eq!(tunnel.mtu, 1460);
    assert_eq!(
        tunnel.tunnel,
        Some((
            "2001:db8:1::2".parse().unwrap(),
            "2001:db8:ff::1".parse().unwrap()
        ))
    );
    for (text, expected) in [
        (
            dslite("2001:db8:9::9", ""),
            "must be an IPv6 address of an interface",
        ),
        (dslite("fe80::1", ""), "global unicast"),
        (dslite("192.0.2.1", ""), "IPv6 address"),
        (dslite("2001:db8:1::2", "mtu = 1500\n"), "mtu must be"),
        (
            dslite("2001:db8:1::2", "parent = \"wan\"\nvlan = 10\n"),
            "not both",
        ),
    ] {
        let got = error(&text);
        assert!(got.contains(expected), "{text}: {got}");
    }
}
