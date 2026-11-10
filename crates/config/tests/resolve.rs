//! `ruster.toml` to the lock form.

use ruster_config::{parse_lock, resolve, FirewallOutside, Kind, Target, ICMP_ERRORS};

const FILE: &str = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"
ipv6 = ["2001:db8:1::1/64"]

[[interface]]
name = "wan"
mac = "02:00:00:00:00:02"
mtu = 1400
enabled = false

[[interface]]
name = "lan.10"
parent = "lan"
vlan = 10

[[interface]]
name = "ppp"
pppoe = { parent = "lan.10", session = 4660, peer = "02:00:00:00:00:ac" }

[[interface]]
name = "ds1"
tunnel = { local = "2001:db8:1::1", remote = "2001:db8:ff::1" }

[[interface]]
name = "ds2"
vrf = "red"
tunnel = { local = "2001:db8:1::1", remote = "2001:db8:ff::2" }

[[interface]]
name = "ds3"
tunnel = { local = "2001:db8:1::1", remote = "2001:db8:ff::3" }

[[route]]
prefix = "0.0.0.0/0"
interface = "wan"
via = "198.51.100.1"

[[route]]
vrf = "red"
prefix = "0.0.0.0/0"
lookup-vrf = "default"

[[route]]
prefix = "10.0.0.0/8"
action = "reject"

[[firewall]]
action = "accept"
protocol = "udp"
ingress = "lan"
destination-ports = "53"

[icmp-errors]
ipv6-burst = 5

[nat]
inside = "lan"
outside = "wan"

[map-e]
interface = "map"
inside = "lan"
prefix = "2001:db8:12:3400::/56"
rule-ipv6 = "2001:db8::/40"
rule-ipv4 = "192.0.2.0/24"
ea-length = 16
br = "2001:db8:ffff::1"
"#;

#[test]
fn the_defaults_are_filled() {
    let lock = resolve(FILE).unwrap();
    assert_eq!(lock.version, 1);
    let at = |name: &str| lock.interface.iter().find(|i| i.name == name).unwrap();
    assert_eq!(
        (at("lan").mtu, at("lan").enabled, at("lan").vrf.as_str()),
        (1500, true, "default")
    );
    assert_eq!(at("lan").kind, Kind::Port);
    assert_eq!(
        (at("lan.10").mac.as_str(), at("lan.10").mtu),
        ("02:00:00:00:00:01", 1496)
    );
    assert_eq!(
        (at("ppp").mac.as_str(), at("ppp").mtu),
        ("02:00:00:00:00:01", 1488)
    );
    assert_eq!(
        (at("ds1").mac.as_str(), at("ds1").mtu),
        ("02:00:00:00:00:fe", 1460)
    );
    // The B4's address: the first tunnel of each VRF only.
    assert_eq!(at("ds1").ipv4, ["192.0.0.2/29"]);
    assert_eq!(at("ds2").ipv4, ["192.0.0.2/29"]);
    assert!(at("ds3").ipv4.is_empty());
    assert!(at("wan").ipv4.is_empty());
    assert_eq!(lock.route[0].vrf, "default");
    assert_eq!(
        lock.route[0].target,
        Target::Forward {
            interface: "wan".into(),
            via: vec!["198.51.100.1".into()]
        }
    );
    assert_eq!(lock.route[1].target, Target::LookupVrf("default".into()));
    assert_eq!(lock.route[2].target, Target::Reject);
    assert_eq!(lock.firewall[0].ingress, ["lan"]);
    assert!(lock.firewall[0].source.is_empty());
    assert_eq!(lock.firewall_filtering, "endpoint-independent");
    assert_eq!(lock.firewall_outside, FirewallOutside::Derive);
    assert_eq!(lock.icmp_errors.ipv6_burst, 5);
    assert_eq!(
        lock.icmp_errors.ipv4_interval_ms,
        ICMP_ERRORS.ipv4_interval_ms
    );
    assert_eq!(lock.nat[0].ports, "1024-32767");
    assert!(lock.nat[0].external.is_empty());
    assert!(lock.nat[0].ipv4_id_rate_limit);
    assert_eq!((lock.map_e[0].psid_offset, lock.map_e[0].mtu), (6, 1460));
}

#[test]
fn a_resolved_file_reads_back_the_same() {
    let lock = resolve(FILE).unwrap();
    let text = lock.to_text();
    assert_eq!(parse_lock(&text).unwrap(), lock, "{text}");
    let bare = resolve("").unwrap();
    assert_eq!(parse_lock(&bare.to_text()).unwrap(), bare);
    // A resolved lock is its own resolution.
    assert_eq!(
        resolve(&text).map_err(|_| ()),
        Err(()),
        "version is not ruster.toml"
    );
}

#[test]
fn what_a_default_needs_is_checked() {
    for (text, want) in [
        ("[[interface]]\nname = \"a\"\n", "mac is missing"),
        ("[[interface]]\nname = \"a\"\nvlan = 1\n", "give parent and vlan together"),
        (
            "[[interface]]\nname = \"a\"\nparent = \"b\"\nvlan = 1\n",
            "parent \"b\" must be an interface given before it",
        ),
        (
            "[[interface]]\nname = \"a\"\npppoe = { parent = \"b\", session = 1, peer = \"02:00:00:00:00:01\" }\n",
            "PPPoE parent \"b\" must be a port or VLAN",
        ),
        ("[[route]]\nprefix = \"10.0.0.0/8\"\n", "give one of interface"),
        ("[[route]]\nprefix = \"10.0.0.0/8\"\naction = \"drop\"\n", "action must be"),
        (
            "[[route]]\nprefix = \"10.0.0.0/8\"\naction = \"discard\"\nvia = \"10.0.0.1\"\n",
            "a discard route has no",
        ),
    ] {
        let error = resolve(text).unwrap_err();
        assert!(error.contains(want), "{text}: {error}");
    }
}

/// The `ruster.toml` example in the crate's documentation.
#[test]
fn the_documented_example_is_resolved() {
    let source = include_str!("../src/lib.rs");
    let blocks: Vec<String> = source
        .split("//! ```toml\n")
        .skip(1)
        .map(|block| {
            block
                .lines()
                .take_while(|line| *line != "//! ```")
                .map(|line| line.strip_prefix("//!").unwrap().trim_start_matches(' '))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .collect();
    assert_eq!(blocks.len(), 2);
    resolve(&blocks[0]).unwrap();
}

const DNS_INTERFACES: &str = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"
ipv6 = ["fe80::1/64", "2001:db8:1::1/64"]

[[interface]]
name = "wan"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.2/24"

[[interface]]
name = "red"
mac = "02:00:00:00:00:03"
ipv4 = "10.0.0.1/24"
vrf = "red"
"#;

#[test]
fn dns_answers_on_nat_s_inside_when_listen_is_left_out() {
    let text = format!(
        "{DNS_INTERFACES}\n[nat]\ninside = \"lan\"\noutside = \"wan\"\n\n[dns]\nupstream = [\"192.0.2.53\"]\n"
    );
    let lock = resolve(&text).unwrap();
    let dns = &lock.dns[0];
    assert_eq!(dns.listen, ["192.0.2.1", "2001:db8:1::1"], "no link-local");
    assert_eq!(dns.allow, ["192.0.2.0/24", "2001:db8:1::/64"]);
    assert_eq!(dns.upstream, ["192.0.2.53"]);
    assert!(dns.upstream_from.is_empty());
    assert_eq!(parse_lock(&lock.to_text()).unwrap(), lock);
}

#[test]
fn dns_listens_where_it_is_told() {
    let text = format!("{DNS_INTERFACES}\n[dns]\nlisten = [\"lan\", \"wan\"]\n");
    let dns = resolve(&text).unwrap().dns.remove(0);
    assert_eq!(dns.listen, ["192.0.2.1", "2001:db8:1::1", "198.51.100.2"]);
    assert_eq!(
        dns.allow,
        ["192.0.2.0/24", "2001:db8:1::/64", "198.51.100.0/24"]
    );
    assert!(dns.upstream.is_empty(), "it resolves from the root");
    assert!(resolve(DNS_INTERFACES).unwrap().dns.is_empty());
}

#[test]
fn dns_needs_somewhere_to_listen() {
    for (dns, error) in [
        ("[dns]\n", "give listen"),
        ("[dns]\nlisten = [\"nope\"]\n", "no such interface"),
        ("[dns]\nlisten = [\"red\"]\n", "default VRF"),
    ] {
        let error_text = resolve(&format!("{DNS_INTERFACES}\n{dns}")).unwrap_err();
        assert!(error_text.contains(error), "{dns}: {error_text}");
    }
}
