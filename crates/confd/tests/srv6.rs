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
        })))
    );
    assert_eq!(
        routes.get(&route("default", "fc00:1::1", 128)),
        Some(&Value::Route(RouteAction::Srv6Local(Srv6Local::End)))
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
