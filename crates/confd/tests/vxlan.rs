//! VXLAN interfaces in the configuration and the FE's tables confd writes for them.

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

fn with(vxlan: &str, bridge: &str) -> String {
    format!(
        "{WAN}\n[[interface]]\nname = \"vx0\"\n{vxlan}\n\n[[interface]]\nname = \"br0\"\nbridge = {{ {bridge} }}\n"
    )
}

const MEMBERS: &str = r#"members = ["vx0", "p1"]"#;

#[test]
fn a_vxlan_member_becomes_its_row() {
    let text = with(
        r#"vxlan = { vni = 100, local = "192.0.2.1", remote = ["198.51.100.2", "198.51.100.3"] }"#,
        MEMBERS,
    );
    let config = parse(&text).unwrap();
    let vx0 = config.interfaces.iter().find(|i| i.name == "vx0").unwrap();
    assert_eq!(vx0.mtu, 1450, "1500 less 50");
    let br0 = config.interfaces.iter().find(|i| i.name == "br0").unwrap();
    assert_eq!(br0.mtu, 1450, "the smallest of the members'");
    assert_eq!(
        br0.mac,
        [2, 0, 0, 0, 1, 2],
        "the first port's, not the tunnel's"
    );
    let mut confd = Confd::new(Config::default());
    let [[_, tables], _] = confd.tables_now_and_with(&config);
    assert_eq!(
        tables.get(&Key::Vxlan {
            interface: "vx0".into()
        }),
        Some(&Value::Vxlan {
            vni: 100,
            local: "192.0.2.1".parse().unwrap(),
            remotes: vec![
                "198.51.100.2".parse().unwrap(),
                "198.51.100.3".parse().unwrap()
            ],
        })
    );
    let text = with(
        r#"vxlan = { vni = 100, local = "2001:db8::1", remote = ["2001:db8:1::2"] }"#,
        MEMBERS,
    );
    let config = parse(&text).unwrap();
    let vx0 = config.interfaces.iter().find(|i| i.name == "vx0").unwrap();
    assert_eq!(vx0.mtu, 1430);
}

#[test]
fn bad_vxlan_interfaces_are_refused() {
    let good = r#"vxlan = { vni = 100, local = "192.0.2.1", remote = ["198.51.100.2"] }"#;
    for (vxlan, bridge, says) in [
        (
            r#"vxlan = { vni = 0, local = "192.0.2.1", remote = ["198.51.100.2"] }"#,
            MEMBERS,
            "vni must be",
        ),
        (
            r#"vxlan = { vni = 16777216, local = "192.0.2.1", remote = ["198.51.100.2"] }"#,
            MEMBERS,
            "vni must be",
        ),
        (
            r#"vxlan = { vni = 100, local = "192.0.2.1", remote = [] }"#,
            MEMBERS,
            "1 to 64",
        ),
        (
            r#"vxlan = { vni = 100, local = "192.0.2.1", remote = ["2001:db8::2"] }"#,
            MEMBERS,
            "all be IPv4",
        ),
        (
            r#"vxlan = { vni = 100, local = "192.0.2.1", remote = ["198.51.100.2", "198.51.100.2"] }"#,
            MEMBERS,
            "given twice",
        ),
        (
            r#"vxlan = { vni = 100, local = "192.0.2.9", remote = ["198.51.100.2"] }"#,
            MEMBERS,
            "address given to an interface",
        ),
        (good, r#"members = ["p1"]"#, "member of a bridge"),
        (
            good,
            r#"members = ["vx0", "p1"], static-mac = [{ mac = "02:00:00:00:00:55", interface = "vx0" }]"#,
            "static-mac",
        ),
        (
            "vxlan = { vni = 100, local = \"192.0.2.1\", remote = [\"198.51.100.2\"] }\nmtu = 1451",
            MEMBERS,
            "mtu must be at most 1450",
        ),
    ] {
        let error = parse(&with(vxlan, bridge)).unwrap_err();
        assert!(error.contains(says), "{vxlan}: {error}");
    }
    // Two in one bridge.
    let text = format!(
        "{}\n[[interface]]\nname = \"vx1\"\nvxlan = {{ vni = 200, local = \"192.0.2.1\", remote = [\"198.51.100.2\"] }}\n\n[[interface]]\nname = \"br0\"\nbridge = {{ members = [\"p1\", \"vx0\", \"vx1\"] }}\n",
        with(good, MEMBERS).split("\n[[interface]]\nname = \"br0\"").next().unwrap()
    );
    let error = parse(&text).unwrap_err();
    assert!(error.contains("already has VXLAN"), "{error}");
    // RFC 7348 section 5: the largest 24-bit VNI is taken.
    let top = r#"vxlan = { vni = 16777215, local = "192.0.2.1", remote = ["198.51.100.2"] }"#;
    assert!(parse(&with(top, MEMBERS)).is_ok());
}

#[test]
fn a_bridge_of_tunnels_only_needs_its_mac() {
    let vxlan = r#"vxlan = { vni = 100, local = "192.0.2.1", remote = ["198.51.100.2"] }"#;
    let error = parse(&with(vxlan, r#"members = ["vx0"]"#)).unwrap_err();
    assert!(error.contains("give its mac"), "{error}");
    let text = with(vxlan, r#"members = ["vx0"]"#) + "mac = \"02:00:00:00:00:77\"\n";
    let config = parse(&text).unwrap();
    let br0 = config.interfaces.iter().find(|i| i.name == "br0").unwrap();
    assert_eq!((br0.mac, br0.mtu), ([2, 0, 0, 0, 0, 0x77], 1450));
}
