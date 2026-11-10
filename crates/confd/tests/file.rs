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
                pppoe: None,
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
                pppoe: None,
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
fn ipv6_addresses_that_are_close_to_the_refused_ones_are_read() {
    for ipv6 in [
        "2001:db8::/127",
        "2001:db8::/128",
        "fe80::1/64",
        "2001:db8::1/64",
    ] {
        let text = format!(
            "[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:01\"\nipv6 = [\"{ipv6}\"]\n"
        );
        assert!(parse(&text).is_ok(), "{ipv6}: {:?}", parse(&text).err());
    }
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
        (lan6("\"::ffff:192.0.2.1/128\""), "IPv4-mapped"),
        (lan6("\"::192.0.2.1/128\""), "IPv4-compatible"),
        (lan6("\"fec0::1/64\""), "site-local"),
        (lan6("\"fe80::1/10\""), "prefix length 64"),
        (lan6("\"2001:db8::/64\""), "Subnet-Router anycast"),
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
        (one("vrf = \"twelve-bytes\"\n"), "at most 11"),
        (one("vrf = \"a/b\"\n"), "at most 11"),
        (
            one("[[route]]\nprefix = \"0.0.0.0/0\"\nlookup-vrf = \"default\"\n"),
            "another VRF",
        ),
        (
            one("[[route]]\nprefix = \"0.0.0.0/0\"\n"),
            "one of interface, lookup-vrf and action",
        ),
        (
            one("[[route]]\nprefix = \"0.0.0.0/0\"\ninterface = \"lan\"\nlookup-vrf = \"red\"\n"),
            "one of interface, lookup-vrf and action",
        ),
        (
            one("[[route]]\nvrf = \"red\"\nprefix = \"0.0.0.0/0\"\nlookup-vrf = \"default\"\nvia = \"10.0.0.9\"\n"),
            "has no via",
        ),
        (
            one("[[route]]\nprefix = \"10.0.0.0/8\"\naction = \"drop\"\n"),
            "action must be",
        ),
        (
            one("[[route]]\nprefix = \"10.0.0.0/8\"\naction = \"discard\"\ninterface = \"lan\"\n"),
            "has no interface",
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
fn with_nat_the_router_s_own_ipv4_leaves_from_its_inside_address() {
    let text = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"

[[interface]]
name = "wan"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.1/24"

# A link that is neither NAT's inside nor its outside (a BGP peer).
[[interface]]
name = "peer"
mac = "02:00:00:00:00:03"
ipv4 = "10.9.0.1/30"
"#;
    let commands = |text: &str| -> Vec<String> {
        ruster_confd::kernel::commands(&parse(text).unwrap())
            .iter()
            .map(|args| args.join(" "))
            .collect()
    };
    let with_nat = commands(&format!(
        "{text}\n[nat]\ninside = \"lan\"\noutside = \"wan\"\nports = \"20000-20999\"\n"
    ));
    for expected in [
        "-4 route replace 198.51.100.0/24 dev rt-default src 192.0.2.1",
        "-4 route replace 192.0.2.0/24 dev rt-default src 192.0.2.1",
        "-4 route replace 10.9.0.0/30 dev rt-default src 10.9.0.1",
        "-4 route replace default dev rt-default src 192.0.2.1",
    ] {
        assert!(
            with_nat.contains(&expected.to_string()),
            "{expected}: {with_nat:#?}"
        );
    }

    // Without NAT (a reload that removed it), the WAN prefix leaves from its own
    // address again.
    let without = commands(text);
    let expected = "-4 route replace 198.51.100.0/24 dev rt-default src 198.51.100.1";
    assert!(without.contains(&expected.to_string()), "{without:#?}");
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
    let any: (std::net::IpAddr, u8) = (Ipv4Addr::UNSPECIFIED.into(), 0);
    let any6: (std::net::IpAddr, u8) = (std::net::Ipv6Addr::UNSPECIFIED.into(), 0);
    assert_eq!(
        config.firewall,
        vec![
            FirewallRule {
                ingress: Some("lan".into()),
                egress: None,
                source: any,
                destination: (Ipv4Addr::new(203, 0, 113, 0).into(), 24),
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
            // Neither addresses nor the protocol name a family: one rule each.
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
            FirewallRule {
                ingress: None,
                egress: None,
                source: any6,
                destination: any6,
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
            rule("action = \"accept\"\nprotocol = \"udp\"\nsource = \"2001:db8::/32\"\ndestination = \"10.0.0.0/8\"\n"),
            "one family",
        ),
        (
            rule("action = \"accept\"\nprotocol = \"icmp\"\nsource = \"2001:db8::/32\"\n"),
            "icmp is for IPv4",
        ),
        (
            rule("action = \"accept\"\nprotocol = \"icmpv6\"\ndestination = \"10.0.0.0/8\"\n"),
            "icmp is for IPv4",
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
            ports: ruster_proto::table::NatPorts::Range {
                first: 1_024,
                last: 32_767,
            },
            filtering: ruster_proto::table::NatFiltering::EndpointIndependent,
            ipv4_id_rate_limit: true,
            ports_per_host: 0,
            state_per_host: 0,
        })
    );
    let limited = parse(&nat("ports-per-host = 64\nstate-per-host = 512\n"))
        .unwrap()
        .nat
        .unwrap();
    assert_eq!((limited.ports_per_host, limited.state_per_host), (64, 512));
    assert!(
        !parse(&nat("ipv4-id-rate-limit = false\n"))
            .unwrap()
            .nat
            .unwrap()
            .ipv4_id_rate_limit
    );
    assert_eq!(
        parse(&nat("filtering = \"address-dependent\"\n"))
            .unwrap()
            .nat
            .unwrap()
            .filtering,
        ruster_proto::table::NatFiltering::AddressDependent
    );
    assert!(error(&nat("filtering = \"strict\"\n")).contains("filtering must be"));
    let got = parse(&nat(
        "ports = \"40000-40999\"\nexternal = \"198.51.100.2\"\n",
    ))
    .unwrap()
    .nat
    .unwrap();
    assert_eq!(
        got.ports,
        ruster_proto::table::NatPorts::Range {
            first: 40_000,
            last: 40_999
        }
    );
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
    // Without an address of its own it gets the B4's well-known one.
    let config = parse(&dslite("2001:db8:1::2", "")).unwrap();
    assert_eq!(
        config.interfaces[1].ipv4,
        Some((std::net::Ipv4Addr::new(192, 0, 0, 2), 29))
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
        (
            dslite("2001:db8:1::2", "ipv6 = [\"2001:db8:5::1/64\"]\n"),
            "IPv4 only",
        ),
        (
            dslite("2001:db8:1::2", "[[route]]\nprefix = \"2001:db8:9::/48\"\ninterface = \"dslite\"\n"),
            "carries IPv4 only",
        ),
        (
            dslite("2001:db8:1::2", "")
                .replace("ipv6 = [\"2001:db8:1::2/64\"]", "mtu = 1454\nipv6 = [\"2001:db8:1::2/64\"]"),
            "at most 1414",
        ),
        (
            format!(
                "{}[[interface]]\nname = \"other\"\ntunnel = {{ local = \"2001:db8:1::2\", remote = \"2001:db8:ff::1\" }}\n",
                dslite("2001:db8:1::2", "")
            ),
            "same local and remote",
        ),
        (
            format!(
                "{}[[interface]]\nname = \"d.10\"\nparent = \"dslite\"\nvlan = 10\n",
                dslite("2001:db8:1::2", "")
            ),
            "parent",
        ),
    ] {
        let got = error(&text);
        assert!(got.contains(expected), "{text}: {got}");
    }
}

/// RFC 7597 Appendix A, example 1.
#[test]
fn map_e_follows_rfc_7597_appendix_a() {
    let text = format!(
        "{LAN}[[interface]]\nname = \"wan\"\nmac = \"02:00:00:00:00:02\"\nipv6 = [\"2001:db8:ffff:1::2/64\"]\n\
         [map-e]\ninterface = \"map\"\ninside = \"lan\"\nprefix = \"2001:db8:12:3400::/56\"\n\
         rule-ipv6 = \"2001:db8::/40\"\nrule-ipv4 = \"192.0.2.0/24\"\nea-length = 16\npsid-offset = 6\n\
         br = \"2001:db8:ffff::1\"\n"
    );
    let config = parse(&text).unwrap();
    let map = config.interfaces.iter().find(|i| i.name == "map").unwrap();
    assert_eq!(map.ipv4, Some((Ipv4Addr::new(192, 0, 2, 18), 32)));
    assert_eq!(
        map.tunnel,
        Some((
            "2001:db8:12:3400:0:c000:212:34".parse().unwrap(),
            "2001:db8:ffff::1".parse().unwrap()
        ))
    );
    assert_eq!(map.mtu, 1460);
    let nat = config.nat.unwrap();
    assert_eq!((nat.inside.as_str(), nat.outside.as_str()), ("lan", "map"));
    assert_eq!(
        nat.ports,
        ruster_proto::table::NatPorts::Psid {
            offset: 6,
            length: 8,
            psid: 0x34
        }
    );
    assert!(config
        .static_routes
        .iter()
        .any(|r| r.len == 0 && r.prefix == std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    // The delegated prefix is discarded where no more specific route holds it
    // (RFC 7084 WPD-5).
    assert!(config.static_routes.iter().any(|r| r.len == 56
        && r.prefix == "2001:db8:12:3400::".parse::<std::net::IpAddr>().unwrap()
        && r.target == ruster_confd::RouteTarget::Discard));
    let rule =
        format!("{text}[[firewall]]\naction = \"accept\"\nprotocol = \"tcp\"\negress = \"map\"\n");
    assert!(
        parse(&rule).is_ok(),
        "a firewall rule may name the MAP-E tunnel"
    );

    for (bad, expected) in [
        (
            text.replace("2001:db8:12:3400::/56", "2001:db9:12:3400::/56"),
            "inside rule-ipv6",
        ),
        (
            text.replace("ea-length = 16", "ea-length = 4"),
            "ea-length must cover",
        ),
        (text.replace("192.0.2.0/24", "224.0.2.0/24"), "unicast"),
        (
            text.replace("rule-ipv6 = \"2001:db8::/40\"", "rule-ipv6 = \"2001:db8::1/40\""),
            "rule-ipv6 has bits set",
        ),
        (text.replace("ea-length = 16", "ea-length = 49"), "at most 48"),
        (
            text.replace("2001:db8:ffff:1::2/64", "2001:db8:12:3400::2/64"),
            "must not be an on-link prefix",
        ),
        (
            text.replace(
                "[map-e]",
                "[[interface]]\nname = \"dmz\"\nmac = \"02:00:00:00:00:03\"\nipv4 = \"192.0.2.18/24\"\n[map-e]",
            ),
            "given twice",
        ),
        (
            text.replace("2001:db8:12:3400::/56", "2001:db8:12::/48"),
            "hold the ea-length",
        ),
        (
            format!("{text}[nat]\ninside = \"lan\"\noutside = \"wan\"\n").replace(
                "ipv6 = [\"2001:db8:ffff:1::2/64\"]",
                "ipv4 = \"198.51.100.2/24\"\nipv6 = [\"2001:db8:ffff:1::2/64\"]",
            ),
            "give no [nat]",
        ),
    ] {
        let got = error(&bad);
        assert!(got.contains(expected), "{got}");
    }
}

#[test]
fn a_pppoe_interface_runs_on_its_parent_from_its_source() {
    let wan = "[[interface]]\nname = \"wan\"\nmac = \"02:00:00:00:00:02\"\n";
    let source = "[[source]]\nname = \"pppoe-wan\"\nkind = \"pppoe\"\n";
    let ppp = |extra: &str| {
        format!("{source}{wan}[[interface]]\nname = \"ppp\"\npppoe = {{ parent = \"wan\", source = \"pppoe-wan\" }}\n{extra}")
    };
    let config = parse(&ppp("")).unwrap();
    let session = &config.interfaces[1];
    assert_eq!((session.mtu, session.mac), (1492, [2, 0, 0, 0, 0, 2]));
    assert_eq!(session.pppoe, Some(("wan".into(), "pppoe-wan".into())));
    for (text, expected) in [
        (ppp("mtu = 1500\n"), "mtu must be"),
        (ppp("").replace("source = \"pppoe-wan\" }", "source = \"other\" }"), "kind pppoe"),
        (
            ppp("").replace("parent = \"wan\"", "parent = \"dmz\""),
            "port or VLAN",
        ),
        (
            ppp("[[interface]]\nname = \"ppp2\"\npppoe = { parent = \"wan\", source = \"pppoe-wan\" }\n"),
            "another interface",
        ),
        (
            ppp("[[interface]]\nname = \"v\"\nparent = \"ppp\"\nvlan = 10\n"),
            "not a VLAN",
        ),
    ] {
        let got = error(&text);
        assert!(got.contains(expected), "{text}: {got}");
    }
    // NAT may have the session as its outside: the address comes with it.
    let nat = ppp("[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:01\"\nipv4 = \"192.168.0.1/24\"\n\n[nat]\ninside = \"lan\"\noutside = \"ppp\"\n");
    assert!(parse(&nat).is_ok());
}

#[test]
fn wireguard_settings_are_refused() {
    // WireGuard is not part of ruster (docs/charter.md).
    let interface = "[[interface]]\nname = \"wg0\"\nwireguard = { listen-port = 51820, local = \"198.51.100.2\" }\n";
    assert!(
        error(interface).contains("wireguard"),
        "{}",
        error(interface)
    );
    let peer = "[[wireguard-peer]]\ninterface = \"wg0\"\nname = \"branch\"\nendpoint = \"203.0.113.9:51821\"\nallowed = [\"10.9.0.0/16\"]\n";
    assert!(error(peer).contains("wireguard-peer"), "{}", error(peer));
}

#[test]
fn a_firewall_rule_may_name_the_router_itself() {
    let text = format!(
        "{LAN}[[firewall]]\naction = \"accept\"\nprotocol = \"udp\"\ningress = \"rt-default\"\n"
    );
    let config = parse(&text).unwrap();
    assert_eq!(config.firewall.len(), 2, "IPv4 and IPv6");
    assert!(config
        .firewall
        .iter()
        .all(|rule| rule.ingress.as_deref() == Some("rt-default")));
}

/// RFC 8200 section 5: an interface with IPv6 addresses has an MTU of 1280 or more.
#[test]
fn an_ipv6_interface_needs_an_mtu_of_1280() {
    let iface = |mtu: u16| {
        format!(
            "[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:01\"\nmtu = {mtu}\nipv6 = [\"2001:db8:1::1/64\"]\n"
        )
    };
    assert!(parse(&iface(1_280)).is_ok());
    assert!(error(&iface(1_279)).contains("at least 1280"));
}

#[test]
fn the_firewall_filtering_is_endpoint_independent_unless_set() {
    use ruster_proto::table::NatFiltering;
    let rule = "[[firewall]]\naction = \"accept\"\nprotocol = \"udp\"\ningress = \"lan\"\n";
    let config = parse(&format!("{LAN}{rule}")).unwrap();
    assert_eq!(config.firewall_filtering, NatFiltering::EndpointIndependent);
    let config = parse(&format!(
        "firewall-filtering = \"address-dependent\"\n{LAN}{rule}"
    ))
    .unwrap();
    assert_eq!(config.firewall_filtering, NatFiltering::AddressDependent);
    assert!(
        error(&format!("firewall-filtering = \"none\"\n{LAN}{rule}")).contains("filtering must be")
    );
}

#[test]
fn the_firewall_outside_may_be_named() {
    let config = parse(&format!("firewall-outside = [\"lan\"]\n{LAN}")).unwrap();
    assert_eq!(config.firewall_outside, Some(vec!["lan".to_owned()]));
    assert_eq!(parse(LAN).unwrap().firewall_outside, None);
    assert!(error(&format!("firewall-outside = [\"wan\"]\n{LAN}")).contains("no interface"));
}

#[test]
fn the_icmp_error_limits_may_be_set() {
    let config = parse(&format!("{LAN}[icmp-errors]\nipv6-burst = 5\n")).unwrap();
    assert_eq!(config.icmp_errors, Some((100, 5, 10)));
    // Left out, the defaults, which confd now sets in the FE too.
    assert_eq!(parse(LAN).unwrap().icmp_errors, Some((100, 10, 10)));
    assert!(error(&format!("{LAN}[icmp-errors]\nipv4-interval-ms = 0\n")).contains("intervals"));
}

#[test]
fn the_lock_form_is_read_as_its_file() {
    let lock = ruster_config::resolve(GOOD).unwrap().to_text();
    assert_eq!(parse(&lock).unwrap(), parse(GOOD).unwrap());
    assert!(error(&lock.replacen("mtu = 1500\n", "", 1)).contains("missing"));
    assert!(error(&lock.replacen("version = 1", "version = 9", 1)).contains("version 9"));
    // A list of none or one takes no more.
    assert!(
        error(&lock.replacen("ipv4 = []", "ipv4 = [\"10.0.0.1/8\", \"10.0.0.2/8\"]", 1))
            .contains("at most one")
    );
}

#[test]
fn the_dns_section_is_kept_and_checked() {
    let text = format!("{GOOD}\n[dns]\nlisten = [\"lan\"]\nupstream = [\"192.0.2.53\"]\n");
    let dns = parse(&text).unwrap().dns.unwrap();
    assert_eq!(dns.listen, ["192.0.2.1"]);
    assert_eq!(dns.allow, ["192.0.2.0/24"]);
    assert_eq!(parse(GOOD).unwrap().dns, None);

    let lock = ruster_config::resolve(&text).unwrap().to_text();
    assert_eq!(parse(&lock).unwrap(), parse(&text).unwrap());
    for (from, to, expected) in [
        ("listen = [\"192.0.2.1\"]", "listen = []", "at least one"),
        (
            "listen = [\"192.0.2.1\"]",
            "listen = [\"192.0.2.9\"]",
            "address of an interface",
        ),
        (
            "allow = [\"192.0.2.0/24\"]",
            "allow = [\"192.0.2.1/24\"]",
            "no bits after",
        ),
        (
            "upstream = [\"192.0.2.53\"]",
            "upstream = [\"224.0.0.1\"]",
            "unicast",
        ),
        (
            "upstream-from = []",
            "upstream-from = [\"dhcp-wan\"]",
            "cannot name a source yet",
        ),
    ] {
        assert!(lock.contains(from), "{lock}");
        let e = error(&lock.replacen(from, to, 1));
        assert!(e.contains(expected), "{to}: {e}");
    }
}

#[test]
fn the_dhcp_section_is_kept_and_checked() {
    let text = format!(
        "{GOOD}\n[dns]\nlisten = [\"lan\"]\n\n[[dhcp]]\ninterface = \"lan\"\npool = \"192.0.2.100-192.0.2.199\"\n"
    );
    let dhcp = parse(&text).unwrap().dhcp;
    assert_eq!(dhcp.len(), 1);
    assert_eq!(dhcp[0].address, "192.0.2.1/24");
    assert_eq!(dhcp[0].router, ["192.0.2.1"]);
    assert_eq!(dhcp[0].dns, ["192.0.2.1"], "[dns] listens on lan");
    assert!(parse(GOOD).unwrap().dhcp.is_empty());

    for (entry, error) in [
        ("pool = \"192.0.2.0-192.0.2.9\"", "within the hosts"),
        ("pool = \"192.0.2.200-192.0.2.255\"", "within the hosts"),
        ("pool = \"192.0.3.10-192.0.3.20\"", "within the hosts"),
        ("pool = \"192.0.2.1-192.0.2.20\"", "router's address"),
        ("pool = \"192.0.2.20-192.0.2.10\"", "first not above"),
        ("pool = \"192.0.2.10\"", "pool must be like"),
        (
            "pool = \"192.0.2.10-192.0.2.20\"\nlease-time = 10",
            "lease-time",
        ),
        ("pool = \"192.0.2.10-192.0.2.20\"\ndns = [\"::1\"]", "dns"),
        (
            "pool = \"192.0.2.10-192.0.2.20\"\nrouter = [\"0.0.0.0\"]",
            "router",
        ),
    ] {
        let text = format!("{GOOD}\n[[dhcp]]\ninterface = \"lan\"\n{entry}\n");
        let got = parse(&text).unwrap_err();
        assert!(got.contains(error), "{entry}: {got}");
    }
    let twice = format!(
        "{GOOD}\n[[dhcp]]\ninterface = \"lan\"\npool = \"192.0.2.10-192.0.2.20\"\n\n[[dhcp]]\ninterface = \"lan\"\npool = \"192.0.2.30-192.0.2.40\"\n"
    );
    assert!(parse(&twice).unwrap_err().contains("given twice"));
}

#[test]
fn a_dhcp_lock_entry_must_agree_with_its_interface() {
    let text = format!("{GOOD}\n[[dhcp]]\ninterface = \"lan\"\npool = \"192.0.2.10-192.0.2.20\"\n");
    let lock = ruster_config::resolve(&text).unwrap();
    assert!(ruster_confd::file::config(lock.clone()).is_ok());
    for (change, error) in [
        (("mac", "02:00:00:00:00:09"), "mac must be the interface's"),
        (("address", "192.0.2.2/24"), "address must be"),
        (("interface", "nope"), "no such interface"),
    ] {
        let mut lock = lock.clone();
        let entry = &mut lock.dhcp[0];
        match change.0 {
            "mac" => entry.mac = change.1.into(),
            "address" => entry.address = change.1.into(),
            _ => entry.interface = change.1.into(),
        }
        let got = ruster_confd::file::config(lock).unwrap_err();
        assert!(got.contains(error), "{change:?}: {got}");
    }
}

#[test]
fn at_most_32_dhcp_are_taken() {
    let mut text = String::new();
    for n in 1..=33 {
        text.push_str(&format!(
            "[[interface]]\nname = \"l{n}\"\nmac = \"02:00:00:00:01:{n:02x}\"\nipv4 = \"10.0.{n}.1/24\"\n\n[[dhcp]]\ninterface = \"l{n}\"\npool = \"10.0.{n}.10-10.0.{n}.20\"\n\n"
        ));
    }
    assert!(parse(&text).unwrap_err().contains("at most 32 dhcp"));
}

#[test]
fn dhcp_subnets_do_not_overlap() {
    let text = r#"
[[interface]]
name = "a"
mac = "02:00:00:00:00:01"
ipv4 = "10.0.0.1/16"

[[interface]]
name = "b"
mac = "02:00:00:00:00:02"
ipv4 = "10.0.1.1/24"
vrf = "red"

[[interface]]
name = "c"
mac = "02:00:00:00:00:03"
ipv4 = "10.0.2.1/24"

[[dhcp]]
interface = "a"
pool = "10.0.0.10-10.0.0.20"

[[dhcp]]
interface = "c"
pool = "10.0.2.10-10.0.2.20"
"#;
    assert!(parse(text)
        .unwrap_err()
        .contains("overlaps that of dhcp \"a\""));
    let zero = "[[interface]]\nname = \"z\"\nmac = \"02:00:00:00:00:01\"\nipv4 = \"1.0.0.1/7\"\n\n[[dhcp]]\ninterface = \"z\"\npool = \"1.0.0.10-1.0.0.20\"\n";
    assert!(parse(zero).unwrap_err().contains("must not be 0.0.0.0"));
}
