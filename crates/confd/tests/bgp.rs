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
        ("include = \"/etc/a\\nb\"\n", PEER, "absolute"),
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
        ("", "address = \"203.0.113.9\"\nremote-as = 1\n", "subnet"),
        ("", "address = \"10.3.0.9\"\nremote-as = 1\n", "subnet"),
        ("", "address = \"10.4.0.9\"\nremote-as = 1\n", "subnet"),
        ("", "address = \"2001:db8:5::9\"\nremote-as = 1\n", "subnet"),
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
    let (got, connected) = ruster_config::parse_frr_part(&Module::Frr.part(&config)).unwrap();
    assert_eq!(got.as_ref(), config.bgp.as_ref());
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
    let (none, _) = ruster_config::parse_frr_part(&Module::Frr.part(&without)).unwrap();
    assert!(none.is_none());
    assert_eq!(Module::from_name("frr"), Some(Module::Frr));
}
