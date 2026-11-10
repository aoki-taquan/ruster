//! `[bgp]`: the defaults, the lock form and `ruster-frr`'s part.

use ruster_config::{frr_part, parse_frr_part, parse_lock, resolve, Connected};

const WAN: &str = r#"
[[interface]]
name = "red"
mac = "02:00:00:00:00:09"
ipv4 = "10.9.0.1/24"
vrf = "red"

[[interface]]
name = "wan"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.1/24"
ipv6 = ["2001:db8:100::1/64"]
"#;

#[test]
fn bgp_takes_the_router_id_from_the_default_vrf() {
    let text = format!(
        "{WAN}\n[bgp]\nas = 65001\n\n[[bgp.neighbor]]\naddress = \"198.51.100.10\"\nremote-as = 65002\n"
    );
    let lock = resolve(&text).unwrap();
    let [bgp] = &lock.bgp[..] else {
        panic!("{:?}", lock.bgp)
    };
    assert_eq!(bgp.asn, 65001);
    assert_eq!(bgp.router_id, "198.51.100.1", "not red's address");
    assert!(bgp.networks.is_empty() && bgp.include.is_empty());
    assert_eq!(bgp.neighbor[0].remote_as, 65002);
    assert!(bgp.neighbor[0].description.is_empty());
    let written = lock.to_text();
    assert!(written.contains("[[bgp]]\nas = 65001\n"), "{written}");
    assert_eq!(parse_lock(&written).unwrap(), lock);
}

#[test]
fn bgp_keeps_what_is_given() {
    let text = format!(
        "{WAN}\n[bgp]\nas = 4200000000\nrouter-id = \"192.0.2.9\"\nnetworks = [\"203.0.113.0/24\"]\ninclude = \"/etc/ruster/frr-extra.conf\"\n\n[[bgp.neighbor]]\naddress = \"2001:db8:100::10\"\nremote-as = 65002\ndescription = \"upstream\"\n"
    );
    let lock = resolve(&text).unwrap();
    let bgp = &lock.bgp[0];
    assert_eq!(bgp.asn, 4_200_000_000);
    assert_eq!(bgp.router_id, "192.0.2.9");
    assert_eq!(bgp.networks, ["203.0.113.0/24"]);
    assert_eq!(bgp.include, ["/etc/ruster/frr-extra.conf"]);
    assert_eq!(bgp.neighbor[0].description, ["upstream"]);
    assert_eq!(parse_lock(&lock.to_text()).unwrap(), lock);
}

#[test]
fn bgp_without_an_ipv4_address_needs_a_router_id() {
    let text = "[[interface]]\nname = \"wan\"\nmac = \"02:00:00:00:00:02\"\nipv6 = [\"2001:db8::1/64\"]\n\n[bgp]\nas = 65001\n";
    assert!(resolve(text).unwrap_err().contains("router-id"));
    assert!(resolve(&format!("{text}router-id = \"192.0.2.9\"\n")).is_ok());
    assert!(
        resolve("[bgp]\nas = 65001\nasn = 1\n").is_err(),
        "unknown key"
    );
}

#[test]
fn the_frr_part_holds_bgp_and_the_connected_prefixes() {
    let lock = resolve(&format!("{WAN}\n[bgp]\nas = 65001\n")).unwrap();
    let connected = vec![Connected {
        interface: "wan".into(),
        prefix: "198.51.100.0/24".into(),
    }];
    let text = frr_part(lock.bgp.first(), &connected);
    assert!(text.starts_with("version = 1\n"), "{text}");
    assert_eq!(
        parse_frr_part(&text).unwrap(),
        (lock.bgp.first().cloned(), connected.clone())
    );
    let none = frr_part(None, &[]);
    assert_eq!(parse_frr_part(&none).unwrap(), (None, Vec::new()));
    let two = text.replacen("[[bgp]]", "[[bgp]]\nas = 1\nrouter-id = \"1.1.1.1\"\nnetworks = []\ninclude = []\nneighbor = []\n\n[[bgp]]", 1);
    assert!(parse_frr_part(&two).unwrap_err().contains("at most one"));
    assert!(parse_frr_part(&text.replacen("version = 1", "version = 2", 1)).is_err());
}
