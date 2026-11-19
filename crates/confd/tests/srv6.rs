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
