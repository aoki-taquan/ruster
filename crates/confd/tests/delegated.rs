//! A LAN numbered from a delegated prefix (`ipv6-from`), and its Router
//! Advertisements following the prefix.

use std::net::Ipv6Addr;
use std::os::unix::net::UnixStream;

use ruster_confd::delegated::subnet;
use ruster_confd::part::{Client as PartClient, Module};
use ruster_confd::{file, Confd};
use ruster_proto::session::Client;
use ruster_proto::table::{Change, Key, Value};
use ruster_proto::task::Task;

const CONFIG: &str = r#"
[[source]]
name = "dhcp6-wan"
kind = "dhcpv6-client"

[[interface]]
name = "wan"
mac = "02:00:00:00:00:02"

[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.168.0.1/24"
ipv6-from = { source = "dhcp6-wan", subnet = 1 }

[[ra]]
interface = "lan"
"#;

fn prefix(lifetime: u32) -> Change {
    Change::set(
        Key::SourcePrefix {
            source: "dhcp6-wan".into(),
        },
        Value::SourcePrefix {
            prefix: "2001:db8:12:3400::".parse().unwrap(),
            prefix_len: 56,
            preferred: 3_600,
            valid: 7_200,
            lifetime,
        },
    )
}

#[test]
fn subnets_of_a_prefix() {
    let p: Ipv6Addr = "2001:db8:12:3400::".parse().unwrap();
    assert_eq!(
        subnet(p, 56, 1),
        Some("2001:db8:12:3401::".parse().unwrap())
    );
    assert_eq!(
        subnet(p, 56, 255),
        Some("2001:db8:12:34ff::".parse().unwrap())
    );
    assert_eq!(subnet(p, 56, 256), None, "no room");
    assert_eq!(subnet(p, 64, 0), Some(p));
    assert_eq!(subnet(p, 64, 1), None);
    assert_eq!(subnet(p, 65, 0), None);
}

#[test]
fn the_lan_takes_its_64_and_advertises_it_while_the_prefix_lasts() {
    let lock = ruster_config::resolve(CONFIG).unwrap();
    assert_eq!(lock.ra[0].prefix_from, ["dhcp6-wan"]);
    assert!(lock.ra[0].prefix.is_empty());
    let mut confd = Confd::new(file::config(lock).unwrap());
    let (a, b) = UnixStream::pair().unwrap();
    confd.attach_part(a).unwrap();
    let mut neighd = PartClient::new(b, Module::Ra).unwrap();
    let (a, b) = UnixStream::pair().unwrap();
    confd.attach_source("dhcp6-wan", a).unwrap();
    let mut source = Client::new(b).unwrap();
    let mut parts: Vec<String> = Vec::new();
    let run = |confd: &mut Confd,
               source: &mut Client,
               neighd: &mut PartClient,
               parts: &mut Vec<String>,
               now| {
        for _ in 0..50 {
            confd.step(now);
            source.poll();
            neighd
                .poll(&mut |text| {
                    parts.push(text.to_owned());
                    Ok(())
                })
                .unwrap();
        }
    };
    run(&mut confd, &mut source, &mut neighd, &mut parts, 0);
    let lan = |confd: &Confd| {
        confd
            .with_values()
            .interfaces
            .into_iter()
            .find(|i| i.name == "lan")
            .unwrap()
            .ipv6
    };
    assert!(lan(&confd).is_empty());
    source.patch(&[prefix(60)]).unwrap();
    run(&mut confd, &mut source, &mut neighd, &mut parts, 1);
    let address: Ipv6Addr = "2001:db8:12:3401::1".parse().unwrap();
    assert_eq!(lan(&confd), [(address, 64)]);
    let ra = ruster_config::parse_ra_part(parts.last().unwrap()).unwrap();
    let [advertised] = &ra[0].prefix[..] else {
        panic!("{:?}", ra[0].prefix)
    };
    assert_eq!(advertised.prefix, "2001:db8:12:3401::/64");
    assert!(advertised.on_link && advertised.autonomous);
    assert_eq!(
        (advertised.preferred_lifetime, advertised.valid_lifetime),
        (2_700, 5_400),
        "RFC 9096's caps"
    );
    // The value runs out: the address and the advertised prefix go.
    run(&mut confd, &mut source, &mut neighd, &mut parts, 70_000);
    assert!(lan(&confd).is_empty());
    let ra = ruster_config::parse_ra_part(parts.last().unwrap()).unwrap();
    assert!(ra[0].prefix.is_empty());
}

#[test]
fn ipv6_from_is_checked() {
    for (from, to) in [
        // Not a DHCPv6 client.
        ("source = \"dhcp6-wan\"", "source = \"nobody\""),
        ("subnet = 1", "subnet = 65536"),
        (
            "mac = \"02:00:00:00:00:01\"",
            "mac = \"02:00:00:00:00:01\"\nmtu = 1200",
        ),
    ] {
        let text = CONFIG.replace(from, to);
        assert!(file::parse(&text).is_err(), "{text}");
    }
    let twice = format!(
        "{CONFIG}\n[[interface]]\nname = \"lan2\"\nmac = \"02:00:00:00:00:03\"\nipv6-from = {{ source = \"dhcp6-wan\", subnet = 1 }}\n"
    );
    assert!(file::parse(&twice)
        .unwrap_err()
        .contains("another interface"));
    let mut lock = ruster_config::resolve(CONFIG).unwrap();
    lock.ra[0].prefix_from = vec!["other".into()];
    assert!(file::config(lock).unwrap_err().contains("prefix-from"));
}

const MAP_E: &str = r#"
[[source]]
name = "dhcp6-wan"
kind = "dhcpv6-client"

[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.168.0.1/24"
ipv6-from = { source = "dhcp6-wan", subnet = 1 }

[[interface]]
name = "wan"
mac = "02:00:00:00:00:02"

[map-e]
interface = "map"
inside = "lan"
prefix-from = "dhcp6-wan"
rule-ipv6 = "2001:db8::/40"
rule-ipv4 = "192.0.2.0/24"
ea-length = 16
br = "2001:db8:ffff::1"
"#;

#[test]
fn a_map_e_ce_follows_the_delegated_prefix() {
    let lock = ruster_config::resolve(MAP_E).unwrap();
    assert_eq!(lock.map_e[0].prefix_from, ["dhcp6-wan"]);
    assert!(lock.map_e[0].prefix.is_empty());
    let mut confd = Confd::new(file::config(lock).unwrap());
    let (a, b) = UnixStream::pair().unwrap();
    confd.attach_source("dhcp6-wan", a).unwrap();
    let mut source = Client::new(b).unwrap();
    let mut run = |confd: &mut Confd, now| {
        for _ in 0..50 {
            confd.step(now);
            source.poll();
        }
    };
    run(&mut confd, 0);
    assert!(confd.with_values().nat.is_none(), "no CE before the prefix");
    // RFC 7597 appendix A, example 1.
    let (a, b) = UnixStream::pair().unwrap();
    confd.attach_source("dhcp6-wan", a).unwrap();
    let mut source = Client::new(b).unwrap();
    source.patch(&[prefix(60)]).unwrap();
    for _ in 0..50 {
        confd.step(1);
        source.poll();
    }
    let now = confd.with_values();
    let map = now.interfaces.iter().find(|i| i.name == "map").unwrap();
    assert_eq!(map.ipv4, Some(("192.0.2.18".parse().unwrap(), 32)));
    assert_eq!(
        map.tunnel,
        Some((
            "2001:db8:12:3400:0:c000:212:34".parse().unwrap(),
            "2001:db8:ffff::1".parse().unwrap()
        ))
    );
    let nat = now.nat.as_ref().unwrap();
    assert_eq!(nat.outside, "map");
    assert!(matches!(
        nat.ports,
        ruster_proto::table::NatPorts::Psid {
            psid: 0x34,
            length: 8,
            offset: 6
        }
    ));
    assert!(now
        .static_routes
        .iter()
        .any(|r| r.len == 0 && r.prefix.is_ipv4()));
    // The LAN took subnet 1, the CE subnet 0.
    let lan = now.interfaces.iter().find(|i| i.name == "lan").unwrap();
    assert_eq!(lan.ipv6, [("2001:db8:12:3401::1".parse().unwrap(), 64)]);
    // The prefix runs out: the CE goes.
    for _ in 0..50 {
        confd.step(70_000);
        source.poll();
    }
    let now = confd.with_values();
    assert!(now.nat.is_none());
    assert!(now.interfaces.iter().all(|i| i.name != "map"));
}

#[test]
fn a_map_e_prefix_from_is_checked() {
    let both = MAP_E.replace(
        "prefix-from = \"dhcp6-wan\"",
        "prefix-from = \"dhcp6-wan\"\nprefix = \"2001:db8:12:3400::/56\"",
    );
    assert!(ruster_config::resolve(&both).is_err());
    let neither = MAP_E.replace("prefix-from = \"dhcp6-wan\"\n", "");
    assert!(ruster_config::resolve(&neither).is_err());
    let not_v6 = MAP_E.replace("kind = \"dhcpv6-client\"", "kind = \"dhcp-client\"");
    assert!(file::parse(&not_v6).is_err());
    let with_nat = format!("{MAP_E}\n[nat]\ninside = \"lan\"\noutside = \"wan\"\n");
    assert!(file::parse(&with_nat).is_err());
}

#[test]
fn the_delegated_lan_and_the_ce_have_their_routes() {
    use ruster_proto::session::{Hook, Server, Store};
    struct Accept;
    impl Hook for Accept {
        fn check(&mut self, _next: &Store) -> Result<(), String> {
            Ok(())
        }
        fn committed(&mut self, _store: &Store) {}
    }
    let mut confd = Confd::new(file::parse(MAP_E).unwrap());
    let (a, b) = UnixStream::pair().unwrap();
    let mut ribd = Server::new();
    ribd.attach(a, &[ruster_proto::sid::ROUTE]).unwrap();
    confd.connect_ribd(b).unwrap();
    let (a, b) = UnixStream::pair().unwrap();
    confd.attach_source("dhcp6-wan", a).unwrap();
    let mut source = Client::new(b).unwrap();
    source.patch(&[prefix(60)]).unwrap();
    for _ in 0..50 {
        confd.step(1);
        source.poll();
        ribd.step(&mut Accept);
    }
    let route = |prefix: &str, len| {
        ribd.store()
            .get(&Key::Route {
                vrf: "default".into(),
                prefix: prefix.parse().unwrap(),
                len,
            })
            .cloned()
    };
    assert!(route("2001:db8:12:3401::", 64).is_some(), "the LAN's /64");
    assert!(route("192.0.2.18", 32).is_some(), "the CE's address");
    assert_eq!(
        route("2001:db8:12:3400::", 56),
        Some(Value::Route(ruster_proto::table::RouteAction::Discard))
    );
}

#[test]
fn what_a_prefix_given_would_refuse_is_refused_with_prefix_from() {
    // Subnet 0 is the CE's.
    let subnet0 = MAP_E.replace("subnet = 1", "subnet = 0");
    assert!(file::parse(&subnet0).unwrap_err().contains("subnet 0"));
    // IPv6 into the tunnel.
    let v6 = format!("{MAP_E}\n[[route]]\nprefix = \"2001:db8:aaaa::/48\"\ninterface = \"map\"\n");
    assert!(file::parse(&v6).unwrap_err().contains("IPv4 only"));
    // Lengths that do not add up are refused, not a panic.
    let long = MAP_E
        .replace("2001:db8::/40", "2001:db8::/128")
        .replace("ea-length = 16", "ea-length = 200");
    assert!(file::parse(&long).is_err());
}

#[test]
fn the_dns_servers_of_the_sources_go_to_unbound_with_the_part() {
    let text = r#"
[[source]]
name = "dhcp-wan"
kind = "dhcp-client"

[[source]]
name = "pppoe-wan"
kind = "pppoe"

[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.168.0.1/24"

[dns]
listen = ["lan"]
upstream = ["192.0.2.53"]
upstream-from = ["dhcp-wan", "pppoe-wan"]
"#;
    let mut confd = Confd::new(file::parse(text).unwrap());
    let (a, b) = UnixStream::pair().unwrap();
    confd.attach_part(a).unwrap();
    let mut unbound = PartClient::new(b, Module::Dns).unwrap();
    let mut sources = Vec::new();
    for name in ["dhcp-wan", "pppoe-wan"] {
        let (a, b) = UnixStream::pair().unwrap();
        confd.attach_source(name, a).unwrap();
        sources.push(Client::new(b).unwrap());
    }
    let dns = |source: &str, servers: &[&str]| {
        Change::set(
            Key::SourceDns {
                source: source.into(),
            },
            Value::SourceDns {
                servers: servers.iter().map(|s| s.parse().unwrap()).collect(),
                lifetime: 60,
            },
        )
    };
    sources[0]
        .patch(&[dns("dhcp-wan", &["198.51.100.53", "198.51.100.54"])])
        .unwrap();
    sources[1]
        .patch(&[dns("pppoe-wan", &["198.51.100.54", "2001:db8::53"])])
        .unwrap();
    let mut parts = Vec::new();
    for _ in 0..50 {
        confd.step(0);
        for source in &mut sources {
            source.poll();
        }
        unbound
            .poll(&mut |text| {
                parts.push(text.to_owned());
                Ok(())
            })
            .unwrap();
    }
    let (dns, found) = ruster_config::parse_dns_part_with(parts.last().unwrap()).unwrap();
    assert_eq!(dns.unwrap().upstream, ["192.0.2.53"]);
    let found: Vec<String> = found.iter().map(ToString::to_string).collect();
    assert_eq!(found, ["198.51.100.53", "198.51.100.54", "2001:db8::53"]);
}
