//! `[srv6]` in the configuration and the routes confd hands ribd for it.

use ruster_confd::file::parse;
use ruster_confd::{Confd, Config};
use ruster_proto::table::{Key, RouteAction, Srv6Encap, Srv6Local, Value};

const INTERFACES: &str = r#"
[[interface]]
name = "wan"
mac = "02:00:00:00:01:01"
ipv6 = ["2001:db8::1/64"]

[[interface]]
name = "lan"
mac = "02:00:00:00:01:02"
vrf = "red"
ipv4 = "192.168.0.1/24"
"#;

const GOOD: &str = r#"
[srv6]
locator = "fc00:1::/48"
source = "2001:db8::1"

[[srv6.sid]]
sid = "fc00:1::4"
behavior = "End.DT4"
vrf = "red"

[[srv6.sid]]
sid = "fc00:1::2"
behavior = "End.X"
interface = "wan"
next-hop = "fe80::2"

[[srv6.sid]]
sid = "fc00:1::1"
behavior = "End"

[[srv6.policy]]
prefix = "10.2.0.0/16"
vrf = "red"
segments = ["fc00:2::1", "fc00:2::4"]
reduced = true
"#;

fn route(vrf: &str, prefix: &str, len: u8) -> Key {
    Key::Route {
        vrf: vrf.into(),
        prefix: prefix.parse().unwrap(),
        len,
    }
}

#[test]
fn sids_and_policies_become_routes_for_ribd() {
    let config = parse(&format!("{INTERFACES}{GOOD}")).unwrap();
    let mut confd = Confd::new(Config::default());
    let [_, [_, routes]] = confd.tables_now_and_with(&config);
    assert_eq!(
        routes.get(&route("default", "fc00:1::4", 128)),
        Some(&Value::Route(RouteAction::Srv6Local(Srv6Local::EndDt4 {
            vrf: "red".into()
        })))
    );
    assert_eq!(
        routes.get(&route("default", "fc00:1::2", 128)),
        Some(&Value::Route(RouteAction::Srv6Local(Srv6Local::EndX {
            interface: "wan".into(),
            next_hop: "fe80::2".parse().unwrap(),
            flavors: Default::default(),
        })))
    );
    assert_eq!(
        routes.get(&route("default", "fc00:1::1", 128)),
        Some(&Value::Route(RouteAction::Srv6Local(Srv6Local::End {
            flavors: Default::default()
        })))
    );
    assert_eq!(
        routes.get(&route("red", "10.2.0.0", 16)),
        Some(&Value::Route(RouteAction::Srv6Encap(Srv6Encap {
            source: "2001:db8::1".parse().unwrap(),
            segments: vec!["fc00:2::1".parse().unwrap(), "fc00:2::4".parse().unwrap()],
            reduced: true,
        })))
    );
}

#[test]
fn bad_srv6_settings_are_refused() {
    for (from, to, says) in [
        (
            "locator = \"fc00:1::/48\"",
            "locator = \"fc00:1::1/48\"",
            "locator",
        ),
        (
            "source = \"2001:db8::1\"",
            "source = \"2001:db8::9\"",
            "source",
        ),
        (
            "sid = \"fc00:1::4\"",
            "sid = \"fc00:9::4\"",
            "not in the locator",
        ),
        ("sid = \"fc00:1::2\"", "sid = \"fc00:1::4\"", "given twice"),
        (
            "vrf = \"red\"\n\n[[srv6.sid]]",
            "vrf = \"blue\"\n\n[[srv6.sid]]",
            "no interface is in VRF",
        ),
        (
            "behavior = \"End\"\n",
            "behavior = \"End.B6\"\n",
            "behavior is",
        ),
        (
            "interface = \"wan\"",
            "interface = \"lan\"",
            "not an interface of the default VRF",
        ),
        (
            "segments = [\"fc00:2::1\", \"fc00:2::4\"]",
            "segments = []",
            "segments",
        ),
        (
            "segments = [\"fc00:2::1\", \"fc00:2::4\"]",
            "segments = [\"ff02::1\"]",
            "not a unicast",
        ),
        (
            "prefix = \"10.2.0.0/16\"",
            "prefix = \"10.2.0.1/16\"",
            "bits are set",
        ),
    ] {
        let text = format!("{INTERFACES}{}", GOOD.replacen(from, to, 1));
        let error = parse(&text).expect_err(says);
        assert!(error.contains(says), "{says}: {error}");
    }
    // A policy for a prefix a static route has.
    let text = format!(
        "{INTERFACES}{GOOD}\n[[route]]\nprefix = \"10.2.0.0/16\"\nvrf = \"red\"\ninterface = \"lan\"\n"
    );
    let error = parse(&text).unwrap_err();
    assert!(error.contains("another route"), "{error}");
    // A SID a static route has, and a policy for a connected prefix.
    let text =
        format!("{INTERFACES}{GOOD}\n[[route]]\nprefix = \"fc00:1::4/128\"\ninterface = \"wan\"\n");
    let error = parse(&text).unwrap_err();
    assert!(error.contains("another route"), "{error}");
    let text = format!(
        "{INTERFACES}{}",
        GOOD.replacen("prefix = \"10.2.0.0/16\"", "prefix = \"192.168.0.0/24\"", 1)
    );
    let error = parse(&text).unwrap_err();
    assert!(error.contains("another route"), "{error}");
}

#[test]
fn cross_connect_and_dual_stack_sids_become_routes_for_ribd() {
    let sids = r#"
[[srv6.sid]]
sid = "fc00:1::d4"
behavior = "End.DX4"
interface = "lan"
next-hop = "192.168.0.2"

[[srv6.sid]]
sid = "fc00:1::d6"
behavior = "End.DX6"
interface = "lan"
next-hop = "fe80::2"

[[srv6.sid]]
sid = "fc00:1::46"
behavior = "End.DT46"
vrf = "red"
"#;
    let config = parse(&format!("{INTERFACES}{GOOD}{sids}")).unwrap();
    let mut confd = Confd::new(Config::default());
    let [_, [_, routes]] = confd.tables_now_and_with(&config);
    let local = |sid: &str| match routes.get(&route("default", sid, 128)) {
        Some(Value::Route(RouteAction::Srv6Local(local))) => local.clone(),
        other => panic!("{sid}: {other:?}"),
    };
    assert_eq!(
        local("fc00:1::d4"),
        Srv6Local::EndDx4 {
            interface: "lan".into(),
            next_hop: "192.168.0.2".parse().unwrap(),
        }
    );
    assert_eq!(
        local("fc00:1::d6"),
        Srv6Local::EndDx6 {
            interface: "lan".into(),
            next_hop: "fe80::2".parse().unwrap(),
        }
    );
    assert_eq!(
        local("fc00:1::46"),
        Srv6Local::EndDt46 { vrf: "red".into() }
    );

    for (from, to, says) in [
        (
            "next-hop = \"192.168.0.2\"",
            "next-hop = \"fe80::2\"",
            "IPv4",
        ),
        (
            "next-hop = \"fe80::2\"\n\n[[srv6.sid]]\nsid = \"fc00:1::46\"",
            "next-hop = \"192.168.0.2\"\n\n[[srv6.sid]]\nsid = \"fc00:1::46\"",
            "IPv6",
        ),
        (
            "interface = \"lan\"\nnext-hop = \"192.168.0.2\"",
            "interface = \"dmz\"\nnext-hop = \"192.168.0.2\"",
            "no interface",
        ),
        (
            "behavior = \"End.DT46\"\nvrf = \"red\"",
            "behavior = \"End.DT46\"\nvrf = \"blue\"",
            "no interface is in VRF",
        ),
    ] {
        let text = format!("{INTERFACES}{GOOD}{}", sids.replacen(from, to, 1));
        let error = parse(&text).expect_err(says);
        assert!(error.contains(says), "{says}: {error}");
    }
}

#[test]
fn flavors_of_end_and_end_x_become_routes_for_ribd() {
    use ruster_proto::table::Srv6Flavors;
    let text = GOOD.replacen(
        "behavior = \"End\"\n",
        "behavior = \"End\"\nflavors = [\"PSP\", \"USD\"]\n",
        1,
    );
    let config = parse(&format!("{INTERFACES}{text}")).unwrap();
    let mut confd = Confd::new(Config::default());
    let [_, [_, routes]] = confd.tables_now_and_with(&config);
    assert_eq!(
        routes.get(&route("default", "fc00:1::1", 128)),
        Some(&Value::Route(RouteAction::Srv6Local(Srv6Local::End {
            flavors: Srv6Flavors {
                psp: true,
                usp: false,
                usd: true,
                next_csid: None,
            }
        })))
    );
    for (flavors, behavior, says) in [
        ("[\"PSP\", \"PSP\"]", "End", "given twice"),
        ("[\"PSX\"]", "End", "flavors are"),
        ("[\"USD\"]", "End.DT4", "only End and End.X"),
    ] {
        let sid = format!(
            "\n[[srv6.sid]]\nsid = \"fc00:1::9\"\nbehavior = \"{behavior}\"\nflavors = {flavors}\n{}",
            if behavior == "End.DT4" { "vrf = \"red\"\n" } else { "" }
        );
        let error = parse(&format!("{INTERFACES}{GOOD}{sid}")).expect_err(says);
        assert!(error.contains(says), "{says}: {error}");
    }
}

const L2: &str = r#"
[[interface]]
name = "p2"
mac = "02:00:00:00:01:03"

[[interface]]
name = "sr0"
srv6-l2 = { sid = "fc00:1::d2", segments = ["fc00:2::1", "fc00:2::d2"] }

[[interface]]
name = "br0"
bridge = { members = ["p2", "sr0"] }
"#;

#[test]
fn an_srv6_l2_interface_becomes_the_fe_s_row() {
    let config = parse(&format!("{INTERFACES}{L2}{GOOD}")).unwrap();
    let mut confd = Confd::new(Config::default());
    let [[_, fe], _] = confd.tables_now_and_with(&config);
    assert_eq!(
        fe.get(&Key::Srv6L2 {
            interface: "sr0".into()
        }),
        Some(&Value::Srv6L2 {
            source: "2001:db8::1".parse().unwrap(),
            sid: "fc00:1::d2".parse().unwrap(),
            segments: vec!["fc00:2::1".parse().unwrap(), "fc00:2::d2".parse().unwrap()],
            reduced: false,
        })
    );
    // 1500 less the inner Ethernet header, IPv6 and an SRH of two segments.
    let sr0 = config.interfaces.iter().find(|i| i.name == "sr0").unwrap();
    assert_eq!(sr0.mtu, 1500 - 14 - 40 - 40);

    for (from, to, says) in [
        (
            "sid = \"fc00:1::d2\"",
            "sid = \"fc00:9::d2\"",
            "not in the locator",
        ),
        ("sid = \"fc00:1::d2\"", "sid = \"fc00:1::4\"", "another SID"),
        (
            "segments = [\"fc00:2::1\", \"fc00:2::d2\"]",
            "segments = []",
            "1 to 8",
        ),
        (
            "members = [\"p2\", \"sr0\"]",
            "members = [\"p2\"]",
            "member of a bridge",
        ),
    ] {
        let text = format!("{INTERFACES}{}{GOOD}", L2.replacen(from, to, 1));
        let error = parse(&text).expect_err(says);
        assert!(error.contains(says), "{says}: {error}");
    }
    let error = parse(&format!("{INTERFACES}{L2}")).expect_err("no [srv6]");
    assert!(error.contains("needs [srv6]"), "{error}");
}

const EVPN: &str = r#"
[[interface]]
name = "p2"
mac = "02:00:00:00:01:03"

[[interface]]
name = "se0"
srv6-evpn = { vni = 100, unicast-sid = "fc00:1::e", multicast-sid = "fc00:1::f" }

[[interface]]
name = "br0"
bridge = { members = ["p2", "se0"] }
"#;

#[test]
fn an_srv6_evpn_interface_becomes_the_fe_s_row() {
    let config = parse(&format!("{INTERFACES}{EVPN}{GOOD}")).unwrap();
    let mut confd = Confd::new(Config::default());
    let [[_, fe], _] = confd.tables_now_and_with(&config);
    assert_eq!(
        fe.get(&Key::Srv6Evpn {
            interface: "se0".into()
        }),
        Some(&Value::Srv6Evpn {
            source: "2001:db8::1".parse().unwrap(),
            vni: 100,
            unicast: "fc00:1::e".parse().unwrap(),
            multicast: "fc00:1::f".parse().unwrap(),
        })
    );
    // 1500 less the inner Ethernet header and IPv6: one SID, no SRH.
    let se0 = config.interfaces.iter().find(|i| i.name == "se0").unwrap();
    assert_eq!(se0.mtu, 1500 - 14 - 40);
    for (from, to, says) in [
        ("vni = 100", "vni = 0", "vni must be"),
        (
            "unicast-sid = \"fc00:1::e\"",
            "unicast-sid = \"fc00:9::e\"",
            "not in the locator",
        ),
        (
            "multicast-sid = \"fc00:1::f\"",
            "multicast-sid = \"fc00:1::e\"",
            "another SID",
        ),
        (
            "unicast-sid = \"fc00:1::e\"",
            "unicast-sid = \"fc00:1::4\"",
            "another SID",
        ),
        (
            "members = [\"p2\", \"se0\"]",
            "members = [\"p2\"]",
            "member of a bridge",
        ),
    ] {
        let text = format!("{INTERFACES}{}{GOOD}", EVPN.replacen(from, to, 1));
        let error = parse(&text).expect_err(says);
        assert!(error.contains(says), "{says}: {error}");
    }
    let error = parse(&format!("{INTERFACES}{EVPN}")).expect_err("no [srv6]");
    assert!(error.contains("needs [srv6]"), "{error}");
}

#[test]
fn a_next_csid_sid_is_a_route_of_its_block_and_csid() {
    use ruster_proto::table::{Srv6Csid, Srv6Flavors};
    let text = GOOD.replacen(
        "sid = \"fc00:1::1\"\nbehavior = \"End\"\n",
        "sid = \"fc00:1::\"\nbehavior = \"End\"\nflavors = [\"NEXT-CSID\"]\ncsid-structure = [32, 16]\n",
        1,
    );
    let config = parse(&format!("{INTERFACES}{text}")).unwrap();
    let mut confd = Confd::new(Config::default());
    let [_, [_, routes]] = confd.tables_now_and_with(&config);
    assert_eq!(
        routes.get(&route("default", "fc00:1::", 48)),
        Some(&Value::Route(RouteAction::Srv6Local(Srv6Local::End {
            flavors: Srv6Flavors {
                next_csid: Some(Srv6Csid {
                    block: 32,
                    csid: 16
                }),
                ..Srv6Flavors::default()
            }
        })))
    );
    for (from, to, says) in [
        ("csid-structure = [32, 16]\n", "", "needs csid-structure"),
        ("flavors = [\"NEXT-CSID\"]\n", "", "only for NEXT-CSID"),
        ("sid = \"fc00:1::\"", "sid = \"fc00:1::5\"", "bits are set"),
        (
            "csid-structure = [32, 16]",
            "csid-structure = [16, 16]",
            "fewer than the locator's",
        ),
    ] {
        let error = parse(&format!("{INTERFACES}{}", text.replacen(from, to, 1))).unwrap_err();
        assert!(error.contains(says), "{says}: {error}");
    }
}

#[test]
fn a_sid_interface_is_no_bridge_and_a_default_vrf_policy_holds_no_sid() {
    // End.X out of a bridge member.
    let bridged = format!(
        "{INTERFACES}\n[[interface]]\nname = \"p2\"\nmac = \"02:00:00:00:01:03\"\n\n[[interface]]\nname = \"br0\"\nbridge = {{ members = [\"p2\"] }}\n{}",
        GOOD.replacen("interface = \"wan\"", "interface = \"p2\"", 1)
    );
    let error = parse(&bridged).unwrap_err();
    assert!(error.contains("bridge member"), "{error}");
    // A default-VRF policy for fc00:1::/48: it holds the router's SIDs.
    let policy = format!(
        "{INTERFACES}{GOOD}\n[[srv6.policy]]\nprefix = \"fc00:1::/48\"\nsegments = [\"fc00:2::1\"]\n"
    );
    let error = parse(&policy).unwrap_err();
    assert!(error.contains("holds the SID"), "{error}");
}
