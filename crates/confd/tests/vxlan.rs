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
            port: 4789,
        })
    );
    // Another UDP port.
    let config = parse(&with(
        r#"vxlan = { vni = 100, local = "192.0.2.1", remote = ["198.51.100.2"], port = 8472 }"#,
        MEMBERS,
    ))
    .unwrap();
    let [[_, tables], _] = confd.tables_now_and_with(&config);
    assert!(matches!(
        tables.get(&Key::Vxlan {
            interface: "vx0".into()
        }),
        Some(Value::Vxlan { port: 8472, .. })
    ));
    let error = parse(&with(
        r#"vxlan = { vni = 100, local = "192.0.2.1", remote = ["198.51.100.2"], port = 0 }"#,
        MEMBERS,
    ))
    .unwrap_err();
    assert!(error.contains("port must be 1 to 65535"), "{error}");
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
            "must give a vtep",
        ),
        (
            good,
            r#"members = ["vx0", "p1"], static-mac = [{ mac = "02:00:00:00:00:55", interface = "vx0", vtep = "198.51.100.9" }]"#,
            "must give a vtep",
        ),
        (
            good,
            r#"members = ["vx0", "p1"], static-mac = [{ mac = "02:00:00:00:00:55", interface = "p1", vtep = "198.51.100.2" }]"#,
            "no VXLAN interface",
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
    let text = format!(
        "{}\n[[interface]]\nname = \"vx1\"\nvxlan = {{ vni = 200, local = \"192.0.2.1\", remote = [\"198.51.100.3\"] }}\n\n[[interface]]\nname = \"br0\"\nbridge = {{ members = [\"p1\", \"vx0\", \"vx1\"] }}\n",
        with(good, MEMBERS).split("\n[[interface]]\nname = \"br0\"").next().unwrap()
    );
    // Two in one bridge (VNIs 100 and 200 joined): taken.
    assert!(parse(&text).is_ok(), "{:?}", parse(&text).err());
    // Two that share a remote VTEP are not: frames would loop between the routers.
    let shared = text.replacen(
        "vni = 200, local = \"192.0.2.1\", remote = [\"198.51.100.3\"]",
        "vni = 200, local = \"192.0.2.1\", remote = [\"198.51.100.2\"]",
        1,
    );
    let error = parse(&shared).unwrap_err();
    assert!(error.contains("also one of"), "{error}");
    // Two with the same local address and VNI are not.
    let same = text.replacen("vni = 200", "vni = 100", 1);
    let error = parse(&same).unwrap_err();
    assert!(error.contains("same local and vni"), "{error}");
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

#[test]
fn a_static_address_on_a_vxlan_member_is_behind_one_of_its_vteps() {
    let config = parse(&with(
        r#"vxlan = { vni = 100, local = "192.0.2.1", remote = ["198.51.100.2"] }"#,
        r#"members = ["vx0", "p1"], static-mac = [{ mac = "02:00:00:00:00:55", interface = "vx0", vtep = "198.51.100.2" }]"#,
    ))
    .unwrap();
    let mut confd = Confd::new(Config::default());
    let [[_, tables], _] = confd.tables_now_and_with(&config);
    assert_eq!(
        tables.get(&Key::BridgeMac {
            bridge: "br0".into(),
            mac: [2, 0, 0, 0, 0, 0x55]
        }),
        Some(&Value::BridgeMac {
            interface: "vx0".into(),
            vtep: Some("198.51.100.2".parse().unwrap()),
        })
    );
}

#[test]
fn the_mtu_leaves_room_for_the_outer_headers_on_the_largest_link() {
    // Both links at 1400: a VXLAN interface of the default MTU (1450) does not fit.
    let small = WAN
        .replace(
            "ipv6 = [\"2001:db8::1/64\"]\n",
            "ipv6 = [\"2001:db8::1/64\"]\nmtu = 1400\n",
        )
        .replace(
            "mac = \"02:00:00:00:01:02\"\n",
            "mac = \"02:00:00:00:01:02\"\nmtu = 1400\n",
        );
    let vxlan = r#"vxlan = { vni = 100, local = "192.0.2.1", remote = ["198.51.100.2"] }"#;
    let text = with(vxlan, MEMBERS).replacen(WAN, &small, 1);
    let error = parse(&text).unwrap_err();
    assert!(error.contains("at most 1350 (1400"), "{error}");
    // Given a fitting MTU, it is taken.
    let fitting = text.replacen(
        "remote = [\"198.51.100.2\"] }",
        "remote = [\"198.51.100.2\"] }\nmtu = 1350",
        1,
    );
    assert!(parse(&fitting).is_ok(), "{:?}", parse(&fitting).err());
}
