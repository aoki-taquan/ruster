//! `[bgp]`: what confd checks, and the `frr` part it hands `ruster-frr`.

use ruster_confd::file;
use ruster_confd::part::Module;

const WAN: &str = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"
ipv6 = ["2001:db8:1::1/64"]

[[interface]]
name = "wan"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.1/24"
ipv6 = ["2001:db8:100::1/64"]

[[interface]]
name = "off"
mac = "02:00:00:00:00:03"
ipv4 = "10.3.0.1/24"
enabled = false

[[interface]]
name = "red"
mac = "02:00:00:00:00:04"
ipv4 = "10.4.0.1/24"
vrf = "red"
"#;

fn bgp(top: &str, neighbor: &str) -> String {
    format!("{WAN}\n[bgp]\nas = 65001\n{top}\n[[bgp.neighbor]]\n{neighbor}")
}

const PEER: &str = "address = \"198.51.100.10\"\nremote-as = 65002\n";

#[test]
fn bgp_is_checked() {
    let good = bgp(
        "networks = [\"203.0.113.0/24\", \"2001:db8:5::/48\"]\ninclude = \"/etc/ruster/frr.conf\"\n",
        &format!("{PEER}description = \"the ISP\"\n\n[[bgp.neighbor]]\naddress = \"2001:db8:100::10\"\nremote-as = 65001\n"),
    );
    let config = file::parse(&good).unwrap();
    assert_eq!(config.bgp.as_ref().unwrap().neighbor.len(), 2);
    // Neighbors off the links (multihop) are taken.
    for address in ["203.0.113.9", "10.3.0.9", "2001:db8:5::9"] {
        let text = bgp("", &format!("address = \"{address}\"\nremote-as = 1\n"));
        assert!(file::parse(&text).is_ok(), "{address}");
    }
    for (top, neighbor, error) in [
        ("router-id = \"0.0.0.0\"\n", PEER, "router-id"),
        ("router-id = \"2001:db8::1\"\n", PEER, "router-id"),
        ("networks = [\"203.0.113.1/24\"]\n", PEER, "host bits"),
        ("networks = [\"203.0.113.0/33\"]\n", PEER, "host bits"),
        (
            "networks = [\"203.0.113.0/24\", \"203.0.113.0/24\"]\n",
            PEER,
            "twice",
        ),
        ("include = \"frr.conf\"\n", PEER, "absolute"),
        ("include = \"/etc/a\\nb\"\n", PEER, "control"),
        ("include = \"/etc/\"\n", PEER, "file path"),
        ("networks = [\"224.0.0.0/4\"]\n", PEER, "unicast"),
        ("networks = [\"fe80::/64\"]\n", PEER, "unicast"),
        ("", "address = \"198.51.100.0\"\nremote-as = 1\n", "subnet"),
        (
            "",
            "address = \"198.51.100.255\"\nremote-as = 1\n",
            "subnet",
        ),
        (
            "",
            "address = \"2001:db8:100::\"\nremote-as = 1\n",
            "subnet",
        ),
        (
            "",
            "address = \"198.51.100.10\"\nremote-as = 4294967295\n",
            "4294967295",
        ),
        ("", &format!("{PEER}description = \" \"\n"), "description"),
        (
            "",
            &format!("{PEER}description = \"caf\u{e9}\"\n"),
            "description",
        ),
        (
            "",
            "address = \"198.51.100.10\"\nremote-as = 0\n",
            "remote-as",
        ),
        (
            "",
            "address = \"198.51.100.10\"\nremote-as = 23456\n",
            "AS_TRANS",
        ),
        (
            "",
            "address = \"bad\"\nremote-as = 1\n",
            "not an IP address",
        ),
        (
            "",
            "address = \"198.51.100.1\"\nremote-as = 1\n",
            "router's addresses",
        ),
        ("", "address = \"fe80::9\"\nremote-as = 1\n", "link-local"),
        ("", "address = \"224.0.0.5\"\nremote-as = 1\n", "unicast"),
        ("", "address = \"127.0.0.1\"\nremote-as = 1\n", "unicast"),
        ("", "address = \"::\"\nremote-as = 1\n", "unicast"),
        ("", &format!("{PEER}description = \"\"\n"), "description"),
        (
            "",
            &format!("{PEER}description = \"a\\nb\"\n"),
            "description",
        ),
        (
            "",
            &format!("{PEER}description = \"{}\"\n", "x".repeat(81)),
            "description",
        ),
        ("", &format!("{PEER}\n[[bgp.neighbor]]\n{PEER}"), "twice"),
    ] {
        let text = bgp(top, neighbor);
        let got = file::parse(&text).err().unwrap_or_default();
        assert!(got.contains(error), "{top}{neighbor}: {got}");
    }
    let as_trans = format!("{WAN}\n[bgp]\nas = 23456\n");
    assert!(file::parse(&as_trans).unwrap_err().contains("AS_TRANS"));
}

#[test]
fn the_frr_part_has_the_default_vrf_s_prefixes() {
    let config = file::parse(&bgp("", PEER)).unwrap();
    assert!(Module::Frr.configured(&config));
    let part = ruster_config::parse_frr_part(&Module::Frr.part(&config)).unwrap();
    assert_eq!(part.bgp.as_ref(), config.bgp.as_ref());
    let connected = part.connected;
    let connected: Vec<(&str, &str)> = connected
        .iter()
        .map(|c| (c.interface.as_str(), c.prefix.as_str()))
        .collect();
    assert_eq!(
        connected,
        [
            ("lan", "192.0.2.0/24"),
            ("lan", "2001:db8:1::/64"),
            ("wan", "198.51.100.0/24"),
            ("wan", "2001:db8:100::/64"),
        ],
        "no disabled interface, no other VRF, no link-local"
    );
    let without = file::parse(WAN).unwrap();
    assert!(!Module::Frr.configured(&without));
    let none = ruster_config::parse_frr_part(&Module::Frr.part(&without)).unwrap();
    assert!(none.bgp.is_none());
    assert_eq!(Module::from_name("frr"), Some(Module::Frr));
}

#[test]
fn the_routing_part_goes_to_the_bridge_of_the_routing_daemon_chosen() {
    let frr = file::parse(&bgp("", PEER)).unwrap();
    assert!(Module::Frr.configured(&frr));
    assert!(!Module::Bird.configured(&frr));
    let bird = file::parse(&format!("routing-daemon = \"bird-rs\"\n{}", bgp("", PEER))).unwrap();
    assert!(!Module::Frr.configured(&bird));
    assert!(Module::Bird.configured(&bird));
    let part = ruster_config::parse_frr_part(&Module::Bird.part(&bird)).unwrap();
    assert_eq!(part.bgp.as_ref(), bird.bgp.as_ref());
    assert!(!part.connected.is_empty());
    let none = ruster_config::parse_frr_part(&Module::Frr.part(&bird)).unwrap();
    assert!(none.bgp.is_none() && none.connected.is_empty());
    assert_eq!(Module::from_name("bird"), Some(Module::Bird));
    let error = file::parse(&format!("routing-daemon = \"quagga\"\n{WAN}")).unwrap_err();
    assert!(error.contains("routing-daemon"), "{error}");
}

/// What only the lock form can hold: more than one of a none-or-one list.
#[test]
fn lists_of_none_or_one_take_no_more() {
    let lock = ruster_config::resolve(&bgp("", PEER)).unwrap().to_text();
    let parse = |text: &str| file::parse(text).err().unwrap_or_default();
    assert!(parse(&lock).is_empty(), "{}", parse(&lock));
    for (from, to, error) in [
        (
            "include = []",
            "include = [\"/a\", \"/b\"]",
            "at most one path",
        ),
        (
            "description = []",
            "description = [\"a\", \"b\"]",
            "at most one text",
        ),
    ] {
        assert!(parse(&lock.replacen(from, to, 1)).contains(error), "{to}");
    }
    let start = lock.find("[[bgp]]").unwrap();
    let twice = format!("{lock}\n{}", &lock[start..]);
    assert!(
        parse(&twice).contains("at most one bgp"),
        "{}",
        parse(&twice)
    );
}

#[test]
fn an_evpn_neighbor_needs_bird_rs_and_one_vni_and_the_bird_part_has_it() {
    let evpn = |daemon: &str, extra: &str, members: &str| {
        format!(
            "routing-daemon = \"{daemon}\"\n{WAN}\n[[interface]]\nname = \"p1\"\nmac = \"02:00:00:00:09:01\"\n\n\
             [[interface]]\nname = \"vx0\"\nvxlan = {{ vni = 100, local = \"198.51.100.1\" }}\n{extra}\n\
             [[interface]]\nname = \"br0\"\nbridge = {{ members = [{members}] }}\n\n\
             [bgp]\nas = 65001\n\n[[bgp.neighbor]]\naddress = \"198.51.100.10\"\nremote-as = 65002\nevpn = true\n"
        )
    };
    let one = evpn("bird-rs", "", "\"p1\", \"vx0\"");
    let config = file::parse(&one).unwrap();
    let part = ruster_config::parse_frr_part(&Module::Bird.part(&config)).unwrap();
    assert_eq!(part.evpn.len(), 1);
    assert_eq!(part.evpn[0].vni, 100);
    assert_eq!(part.evpn[0].bridge, "br0");
    assert_eq!(part.evpn[0].router_address, "198.51.100.1");
    let error = file::parse(&evpn("frr", "", "\"p1\", \"vx0\"")).unwrap_err();
    assert!(error.contains("bird-rs"), "{error}");
    // Two VNIs in one bridge: refused; in two bridges: both in the part.
    let vx1 = "\n[[interface]]\nname = \"vx1\"\nvxlan = { vni = 200, local = \"198.51.100.1\" }\n";
    let error = file::parse(&evpn("bird-rs", vx1, "\"p1\", \"vx0\", \"vx1\"")).unwrap_err();
    assert!(error.contains("one VNI per bridge"), "{error}");
    let br1 = format!(
        "{vx1}\n[[interface]]\nname = \"p2\"\nmac = \"02:00:00:00:09:02\"\n\n\
         [[interface]]\nname = \"br1\"\nbridge = {{ members = [\"p2\", \"vx1\"] }}\n"
    );
    let config = file::parse(&evpn("bird-rs", &br1, "\"p1\", \"vx0\"")).unwrap();
    let part = ruster_config::parse_frr_part(&Module::Bird.part(&config)).unwrap();
    let mut got: Vec<(u32, &str)> = part
        .evpn
        .iter()
        .map(|v| (v.vni, v.bridge.as_str()))
        .collect();
    got.sort_unstable();
    assert_eq!(got, [(100, "br0"), (200, "br1")]);
    let big = one.replace("vni = 100,", "vni = 70000,");
    let error = file::parse(&big).unwrap_err();
    assert!(error.contains("at most 65535"), "{error}");
}
