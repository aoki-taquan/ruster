//! Bridges in the configuration and the FE's tables confd writes for them.

use ruster_confd::file::parse;
use ruster_confd::{Confd, Config};
use ruster_proto::table::{Key, Value};

const BRIDGE: &str = r#"
[[interface]]
name = "p1"
mac = "02:00:00:00:01:01"

[[interface]]
name = "p2"
mac = "02:00:00:00:01:02"

[[interface]]
name = "p2.10"
parent = "p2"
vlan = 10

[[interface]]
name = "br0"
bridge = { members = ["p1", "p2.10"], static-mac = [{ mac = "02:00:00:00:00:55", interface = "p1" }] }
ipv4 = "192.0.2.1/24"
"#;

#[test]
fn a_bridge_becomes_its_rows_and_its_own_interface() {
    let config = parse(BRIDGE).unwrap();
    let br0 = config.interfaces.iter().find(|i| i.name == "br0").unwrap();
    assert_eq!(br0.mac, [2, 0, 0, 0, 1, 1], "the first member's");
    assert_eq!(br0.mtu, 1496, "the smallest of the members'");
    let mut confd = Confd::new(Config::default());
    let [[_, tables], _] = confd.tables_now_and_with(&config);
    assert_eq!(
        tables.get(&Key::Bridge { name: "br0".into() }),
        Some(&Value::Bridge {
            aging_s: 300,
            max_learned: 4096
        })
    );
    for member in ["p1", "p2.10"] {
        assert_eq!(
            tables.get(&Key::BridgePort {
                interface: member.into()
            }),
            Some(&Value::BridgePort {
                bridge: "br0".into()
            })
        );
        // A member has no address, not even a link-local one.
        assert!(!tables
            .keys()
            .any(|k| matches!(k, Key::Address { interface, .. } if interface == member)));
    }
    assert_eq!(
        tables.get(&Key::BridgeMac {
            bridge: "br0".into(),
            mac: [2, 0, 0, 0, 0, 0x55]
        }),
        Some(&Value::BridgeMac {
            interface: "p1".into()
        })
    );
    assert!(tables.contains_key(&Key::Address {
        interface: "br0".into(),
        address: "192.0.2.1".parse().unwrap()
    }));
    // p2 is no member: it keeps its link-local address.
    assert!(tables
        .keys()
        .any(|k| matches!(k, Key::Address { interface, .. } if interface == "p2")));
}

#[test]
fn bad_bridges_are_refused() {
    let base = r#"
[[interface]]
name = "p1"
mac = "02:00:00:00:01:01"

[[interface]]
name = "p2"
mac = "02:00:00:00:01:02"
"#;
    for (bridge, why) in [
        (r#"bridge = { members = [] }"#, "member"),
        (r#"bridge = { members = ["p9"] }"#, "first member"),
        (r#"bridge = { members = ["p1", "p9"] }"#, "no interface"),
        (
            r#"bridge = { members = ["p1"], aging-time = 5 }"#,
            "aging-time",
        ),
        (
            r#"bridge = { members = ["p1"], max-learned = 0 }"#,
            "max-learned",
        ),
        (
            r#"bridge = { members = ["p1"], static-mac = [{ mac = "01:00:5e:00:00:01", interface = "p1" }] }"#,
            "unicast",
        ),
        (
            r#"bridge = { members = ["p1"], static-mac = [{ mac = "02:00:00:00:00:01", interface = "p2" }] }"#,
            "no member",
        ),
        (
            r#"bridge = { members = ["p1"] }
mtu = 9000"#,
            "mtu",
        ),
        (
            r#"bridge = { members = ["p1"] }
parent = "p1"
vlan = 3"#,
            "not also",
        ),
    ] {
        let text = format!("{base}\n[[interface]]\nname = \"br0\"\n{bridge}\n");
        let error = parse(&text).unwrap_err();
        assert!(error.contains(why), "{bridge}: {error}");
    }
    // A member with an address.
    let text = format!(
        "{}\n[[interface]]\nname = \"br0\"\nbridge = {{ members = [\"p1\"] }}\n",
        base.replace(
            "mac = \"02:00:00:00:01:01\"",
            "mac = \"02:00:00:00:01:01\"\nipv4 = \"10.0.0.1/24\""
        )
    );
    assert!(parse(&text).unwrap_err().contains("no address"));
    // A member of two bridges.
    let text = format!(
        "{base}\n[[interface]]\nname = \"br0\"\nbridge = {{ members = [\"p1\"] }}\n\
         \n[[interface]]\nname = \"br1\"\nbridge = {{ members = [\"p1\"] }}\n"
    );
    assert!(parse(&text).unwrap_err().contains("already in bridge"));
    // A member that is a PPPoE session's parent.
    let text = format!(
        "[[source]]\nname = \"pppoe-wan\"\nkind = \"pppoe\"\n{base}\n[[interface]]\nname = \"ppp\"\n\
         pppoe = {{ parent = \"p1\", source = \"pppoe-wan\" }}\n\n[[interface]]\nname = \"br0\"\n\
         bridge = {{ members = [\"p1\"] }}\n"
    );
    let error = parse(&text).unwrap_err();
    assert!(
        error.contains("is the parent of a PPPoE session"),
        "{error}"
    );
}
