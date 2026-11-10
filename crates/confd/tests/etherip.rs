//! EtherIP interfaces in the configuration and the FE's tables confd writes for them.

use ruster_confd::file::parse;
use ruster_confd::{Confd, Config};
use ruster_proto::table::{Key, Value};

const WAN: &str = r#"
[[interface]]
name = "wan"
mac = "02:00:00:00:01:01"
ipv4 = "192.0.2.1/24"
ipv6 = ["2001:db8::1/64"]

[[interface]]
name = "p1"
mac = "02:00:00:00:01:02"
"#;

fn with(etherip: &str, members: &str) -> String {
    format!(
        "{WAN}\n[[interface]]\nname = \"eip0\"\n{etherip}\n\n[[interface]]\nname = \"br0\"\nbridge = {{ members = [{members}] }}\n"
    )
}

#[test]
fn an_etherip_member_becomes_its_row() {
    let text = with(
        r#"etherip = { local = "192.0.2.1", remote = "198.51.100.2" }"#,
        r#""p1", "eip0""#,
    );
    let config = parse(&text).unwrap();
    let eip0 = config.interfaces.iter().find(|i| i.name == "eip0").unwrap();
    assert_eq!(eip0.mtu, 1464, "1500 less 36");
    let br0 = config.interfaces.iter().find(|i| i.name == "br0").unwrap();
    assert_eq!(br0.mtu, 1464, "the smallest of the members'");
    let mut confd = Confd::new(Config::default());
    let [[_, tables], _] = confd.tables_now_and_with(&config);
    assert_eq!(
        tables.get(&Key::EtherIp {
            interface: "eip0".into()
        }),
        Some(&Value::EtherIp {
            local: "192.0.2.1".parse().unwrap(),
            remote: "198.51.100.2".parse().unwrap(),
        })
    );
    assert_eq!(
        tables.get(&Key::BridgePort {
            interface: "eip0".into()
        }),
        Some(&Value::BridgePort {
            bridge: "br0".into()
        })
    );
    assert!(matches!(
        tables.get(&Key::Interface {
            name: "eip0".into()
        }),
        Some(Value::Interface {
            vlan: None,
            tunnel: None,
            pppoe: None,
            ..
        })
    ));
    // IPv6 leaves less room.
    let text = with(
        r#"etherip = { local = "2001:db8::1", remote = "2001:db8:1::2" }"#,
        r#""p1", "eip0""#,
    );
    let config = parse(&text).unwrap();
    let eip0 = config.interfaces.iter().find(|i| i.name == "eip0").unwrap();
    assert_eq!(eip0.mtu, 1444);
}

#[test]
fn bad_etherip_interfaces_are_refused() {
    let member = r#""p1", "eip0""#;
    for (etherip, members, says) in [
        (
            r#"etherip = { local = "192.0.2.1", remote = "198.51.100.2" }"#,
            r#""p1""#,
            "member of a bridge",
        ),
        (
            r#"etherip = { local = "192.0.2.9", remote = "198.51.100.2" }"#,
            member,
            "address given to an interface",
        ),
        (
            r#"etherip = { local = "192.0.2.1", remote = "2001:db8::2" }"#,
            member,
            "both be IPv4",
        ),
        (
            r#"etherip = { local = "192.0.2.1", remote = "224.0.0.1" }"#,
            member,
            "unicast",
        ),
        (
            "etherip = { local = \"192.0.2.1\", remote = \"198.51.100.2\" }\nmtu = 1500",
            member,
            "mtu must be at most 1464",
        ),
        (
            "etherip = { local = \"192.0.2.1\", remote = \"198.51.100.2\" }\nipv4 = \"10.0.0.1/24\"",
            member,
            "no address",
        ),
        (
            "etherip = { local = \"192.0.2.1\", remote = \"198.51.100.2\" }\nparent = \"p1\"\nvlan = 3",
            member,
            "not also a VLAN",
        ),
    ] {
        let error = parse(&with(etherip, members)).unwrap_err();
        assert!(error.contains(says), "{etherip}: {error}");
    }
}
