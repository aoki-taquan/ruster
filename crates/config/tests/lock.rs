//! The lock form.

use ruster_config::{parse_lock, FirewallOutside, Kind, Target};

/// The lock form example in the crate's documentation.
fn example() -> String {
    let source = include_str!("../src/lib.rs");
    // The second block; the first is `ruster.toml`'s.
    let block = source.split("//! ```toml\n").nth(2).unwrap();
    block
        .lines()
        .take_while(|line| *line != "//! ```")
        .map(|line| line.strip_prefix("//!").unwrap().trim_start_matches(' '))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_documented_example_is_read() {
    let lock = parse_lock(&example()).unwrap();
    assert_eq!(lock.version, 1);
    assert_eq!(lock.firewall_outside, FirewallOutside::Derive);
    assert_eq!(
        lock.interface[1].kind,
        Kind::Vlan {
            parent: "lan".into(),
            id: 10
        }
    );
    assert_eq!(lock.route[0].target, Target::Discard);
    assert_eq!(
        lock.route[1].target,
        Target::Forward {
            interface: "lan".into(),
            via: vec!["192.0.2.254".into()]
        }
    );
    assert_eq!(lock.firewall[0].destination_ports, ["53"]);
    assert_eq!(lock.dns[0].listen, ["192.0.2.1"]);
    assert!(lock.dns[0].upstream_from.is_empty());
    assert_eq!(lock.dhcp[0].pool, "192.0.2.100-192.0.2.199");
    assert_eq!(lock.source[0].kind, "pppoe");
    assert_eq!(lock.source[0].sync_wait, 10);
}

#[test]
fn the_lock_form_reads_back_the_same() {
    let lock = parse_lock(&example()).unwrap();
    let text = lock.to_text();
    assert_eq!(parse_lock(&text).unwrap(), lock, "{text}");
    let mut other = lock.clone();
    other.firewall_outside = FirewallOutside::Interfaces(vec!["lan".into()]);
    other.route.push(ruster_config::Route {
        vrf: "red".into(),
        prefix: "0.0.0.0/0".into(),
        target: Target::LookupVrf("default".into()),
    });
    other.interface[0].kind = Kind::Tunnel {
        local: "2001:db8::1".into(),
        remote: "2001:db8::2".into(),
    };
    assert_eq!(parse_lock(&other.to_text()).unwrap(), other);
}

#[test]
fn a_lock_must_give_every_key() {
    let text = parse_lock(&example()).unwrap().to_text();
    for key in [
        "mtu = 1500\n",
        "firewall-outside = \"derive\"\n",
        "ipv6 = []\n",
        "map-e = []\n",
        "external = []\n",
        "ipv6-burst = 10\n",
    ] {
        assert!(text.contains(key), "{key} in {text}");
        let missing = text.replacen(key, "", 1);
        let error = parse_lock(&missing).unwrap_err();
        assert!(error.contains("missing"), "{key}: {error}");
    }
    let error =
        parse_lock(&text.replacen("mtu = 1500\n", "mtu = 1500\nspeed = 1\n", 1)).unwrap_err();
    assert!(error.contains("unknown field"), "{error}");
    let error = parse_lock(&text.replace("\"derive\"", "\"guess\"")).unwrap_err();
    assert!(error.contains("firewall-outside"), "{error}");
}

#[test]
fn another_version_is_refused() {
    let text = parse_lock(&example()).unwrap().to_text();
    let error = parse_lock(&text.replacen("version = 1", "version = 2", 1)).unwrap_err();
    assert!(
        error.contains("version 2") && error.contains("reads version 1"),
        "{error}"
    );
    let error = parse_lock(&text.replacen("version = 1\n", "", 1)).unwrap_err();
    assert!(error.contains("version is missing"), "{error}");
}

#[test]
fn the_dns_part_reads_back_the_same() {
    let lock = parse_lock(&example()).unwrap();
    let text = ruster_config::dns_part(lock.dns.first());
    assert!(text.starts_with("version = 1\n"), "{text}");
    assert_eq!(
        ruster_config::parse_dns_part(&text).unwrap().as_ref(),
        lock.dns.first()
    );
    let none = ruster_config::dns_part(None);
    assert_eq!(ruster_config::parse_dns_part(&none).unwrap(), None);
    assert!(ruster_config::parse_dns_part("version = 2\ndns = []\n").is_err());
    assert!(
        ruster_config::parse_dns_part(&example()).is_err(),
        "only dns"
    );
}

#[test]
fn the_dhcp_part_reads_back_the_same() {
    let lock = parse_lock(&example()).unwrap();
    let text = ruster_config::dhcp_part(&lock.dhcp);
    assert!(text.starts_with("version = 1\n"), "{text}");
    assert_eq!(ruster_config::parse_dhcp_part(&text).unwrap(), lock.dhcp);
    let none = ruster_config::dhcp_part(&[]);
    assert!(ruster_config::parse_dhcp_part(&none).unwrap().is_empty());
    assert!(ruster_config::parse_dhcp_part("version = 2\ndhcp = []\n").is_err());
    assert!(
        ruster_config::parse_dhcp_part(&example()).is_err(),
        "only dhcp"
    );
}
