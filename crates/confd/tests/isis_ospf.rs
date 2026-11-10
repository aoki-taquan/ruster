//! `[isis]`, `[ospf]` and `[ospf6]`: what confd checks, and the `frr` part.

use ruster_confd::file;
use ruster_confd::part::Module;

const INTERFACES: &str = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"

[[interface]]
name = "lan.10"
parent = "lan"
vlan = 10

[[interface]]
name = "p2"
mac = "02:00:00:00:00:02"

[[interface]]
name = "br0"
bridge = { members = ["p2"] }
ipv4 = "10.2.0.1/24"

[[interface]]
name = "red"
mac = "02:00:00:00:00:04"
ipv4 = "10.4.0.1/24"
vrf = "red"

[[interface]]
name = "a b"
mac = "02:00:00:00:00:06"

[[interface]]
name = "verylongname1"
mac = "02:00:00:00:00:05"
ipv4 = "10.5.0.1/24"
"#;

fn with(text: &str) -> String {
    format!("{INTERFACES}\n{text}")
}

#[test]
fn isis_and_ospf_are_checked() {
    let good = with(
        "[isis]\nnet = \"49.0001.1921.6800.1001.00\"\n\
         [[isis.interface]]\nname = \"lan\"\n[[isis.interface]]\nname = \"lan.10\"\n\
         [[isis.interface]]\nname = \"br0\"\nmetric = 16777214\n\
         [ospf]\n[[ospf.interface]]\nname = \"lan\"\nnetwork = \"point-to-point\"\n\
         [ospf6]\n[[ospf6.interface]]\nname = \"lan.10\"\ncost = 65535\n",
    );
    let config = file::parse(&good).unwrap();
    assert_eq!(config.isis.as_ref().unwrap().interface.len(), 3);
    assert!(Module::Frr.configured(&config), "without bgp too");
    let part = ruster_config::parse_frr_part(&Module::Frr.part(&config)).unwrap();
    assert_eq!(part.isis, config.isis);
    assert_eq!(part.ospf, config.ospf);
    assert_eq!(part.ospf6, config.ospf6);

    let isis = |net: &str, interface: &str| {
        with(&format!(
            "[isis]\nnet = \"{net}\"\n[[isis.interface]]\nname = \"{interface}\"\n"
        ))
    };
    let ospf = |which: &str, interface: &str| {
        with(&format!(
            "[{which}]\n[[{which}.interface]]\nname = \"{interface}\"\n"
        ))
    };
    for (text, error) in [
        (isis("49.0001.1921.6800.1001.01", "lan"), "net"),
        (isis("49.0001.1921.6800.1001.00", "nowhere"), "no such interface"),
        (isis("49.0001.1921.6800.1001.00", "red"), "default VRF"),
        (isis("49.0001.1921.6800.1001.00", "p2"), "bridge member"),
        (isis("49.0001.1921.6800.1001.00", "verylongname1"), "at most 12"),
        (isis("49.0001.1921.6800.1001.00", "a b"), "without spaces"),
        (
            with("[isis]\nnet = \"49.0001.1921.6800.1001.00\"\nlevel = \"level-3\"\n"),
            "level",
        ),
        (
            with("[isis]\nnet = \"49.0001.1921.6800.1001.00\"\n[[isis.interface]]\nname = \"lan\"\nmetric = 16777215\n"),
            "metric",
        ),
        (
            with("[isis]\nnet = \"49.0001.1921.6800.1001.00\"\n[[isis.interface]]\nname = \"lan\"\n[[isis.interface]]\nname = \"lan\"\n"),
            "twice",
        ),
        (ospf("ospf", "lan.10"), "ipv4 address"),
        (
            with("[ospf]\nrouter-id = \"0.0.0.0\"\n"),
            "router-id",
        ),
        (
            with("[ospf]\n[[ospf.interface]]\nname = \"lan\"\narea = \"1\"\n"),
            "area",
        ),
        (
            with("[ospf]\n[[ospf.interface]]\nname = \"lan\"\ncost = 0\n"),
            "cost",
        ),
        (
            with("[ospf6]\n[[ospf6.interface]]\nname = \"lan\"\nnetwork = \"nbma\"\n"),
            "network",
        ),
    ] {
        let got = file::parse(&text).unwrap_err();
        assert!(got.contains(error), "{error}: {got}");
    }
    // OSPFv3 needs no IPv4 address.
    assert!(file::parse(&ospf("ospf6", "lan.10")).is_ok());
}

const ROUTING: &str = "[isis]\nnet = \"49.0001.1921.6800.1001.00\"\n\
    [[isis.interface]]\nname = \"lan\"\n[[isis.interface]]\nname = \"lan.10\"\n\
    [ospf6]\nrouter-id = \"10.0.0.1\"\n[[ospf6.interface]]\nname = \"lan.10\"\n";

#[test]
fn each_interface_s_is_is_and_ospf_go_to_its_tap() {
    use ruster_proto::table::{Key, PuntDestination, PuntKind, PuntMatch, Value};
    let config = file::parse(&with(ROUTING)).unwrap();
    let mut confd = ruster_confd::Confd::new(config.clone());
    let [[_, tables], _] = confd.tables_now_and_with(&config);
    let mut classes: Vec<(String, PuntKind, String)> = tables
        .iter()
        .filter_map(|(key, value)| match (key, value) {
            (Key::Punt { class }, Value::Punt(punt)) => {
                assert_eq!(punt.destination, PuntDestination::Tap);
                let PuntMatch::Kind(kind) = punt.matches else {
                    panic!("{punt:?}")
                };
                Some((class.clone(), kind, punt.interface.clone().unwrap()))
            }
            _ => None,
        })
        .collect();
    classes.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        classes,
        [
            ("isis-lan".into(), PuntKind::Isis, "lan".into()),
            ("isis-lan.10".into(), PuntKind::Isis, "lan.10".into()),
            ("ospf-lan.10".into(), PuntKind::Ospf, "lan.10".into()),
        ]
    );
}

#[test]
fn the_kernel_side_puts_the_interface_s_addresses_on_its_tap() {
    let config = file::parse(&with(ROUTING)).unwrap();
    let commands: Vec<String> = ruster_confd::kernel::commands(&config)
        .iter()
        .map(|args| args.join(" "))
        .collect();
    for expected in [
        "tuntap add mode tap dev rp-lan",
        "link set rp-lan address 02:00:00:00:00:01 mtu 1500 arp off addrgenmode none",
        "link set rp-lan up",
        "address replace 192.0.2.1/24 dev rp-lan",
        "address replace fe80::ff:fe00:1/64 dev rp-lan nodad",
        "tuntap add mode tap dev rp-lan.10",
        "link set rp-lan.10 address 02:00:00:00:00:01 mtu 1496 arp off addrgenmode none",
        "address replace 10.2.0.1/24 dev rt-default",
    ] {
        assert!(
            commands.iter().any(|c| c == expected),
            "{expected}: {commands:#?}"
        );
    }
    assert!(
        !commands
            .iter()
            .any(|c| c.contains("192.0.2.1/24 dev rt-default")
                || c.contains("192.0.2.0/24 dev rt-default")),
        "lan's address is on its TAP, not the TUN: {commands:#?}"
    );
}
