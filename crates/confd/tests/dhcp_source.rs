//! The sources a DHCP client writes (kinds dhcp-client and dhcpv6-client), DNS
//! servers from any kind, and an interface whose IPv4 address comes from a source.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::net::UnixStream;

use ruster_confd::{file, Confd};
use ruster_proto::coap::Code;
use ruster_proto::session::{Client, Event};
use ruster_proto::table::{Change, Key, Value};
use ruster_proto::task::Task;

const CONFIG: &str = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"

[[interface]]
name = "wan"
mac = "02:00:00:00:00:02"
ipv4-from = "dhcp-wan"

[nat]
inside = "lan"
outside = "wan"

[[source]]
name = "dhcp-wan"
kind = "dhcp-client"

[[source]]
name = "dhcp6-wan"
kind = "dhcpv6-client"

[[source]]
name = "pppoe-wan"
kind = "pppoe"
"#;

fn connect(confd: &mut Confd, name: &str) -> Client {
    let (a, b) = UnixStream::pair().unwrap();
    confd.attach_source(name, a).unwrap();
    Client::new(b).unwrap()
}

/// Runs confd with the source; the codes of the source's answers by token.
fn run(confd: &mut Confd, source: &mut Client, now: u64) -> Vec<(u32, Code)> {
    let mut answers = Vec::new();
    for _ in 0..50 {
        confd.step(now);
        for event in source.poll().1 {
            if let Event::Response { token, code, .. } = event {
                answers.push((token, code));
            }
        }
    }
    answers
}

fn code(answers: &[(u32, Code)], token: u32) -> Code {
    answers
        .iter()
        .find(|(t, _)| *t == token)
        .map(|(_, c)| *c)
        .expect("an answer")
}

fn ipv4(source: &str, address: Ipv4Addr, prefix_len: u8) -> Change {
    Change::set(
        Key::SourceIpv4 {
            source: source.into(),
        },
        Value::SourceIpv4 {
            address,
            prefix_len,
            lifetime: 60,
        },
    )
}

fn dns(source: &str, servers: Vec<IpAddr>) -> Change {
    Change::set(
        Key::SourceDns {
            source: source.into(),
        },
        Value::SourceDns {
            servers,
            lifetime: 60,
        },
    )
}

fn prefix(source: &str, prefix: &str, len: u8) -> Change {
    Change::set(
        Key::SourcePrefix {
            source: source.into(),
        },
        Value::SourcePrefix {
            prefix: prefix.parse().unwrap(),
            prefix_len: len,
            preferred: 3_600,
            valid: 7_200,
            lifetime: 60,
        },
    )
}

#[test]
fn a_dhcp_client_gives_its_interface_the_leased_address() {
    let mut confd = Confd::new(file::parse(CONFIG).unwrap());
    let wan = |confd: &Confd| {
        confd
            .with_values()
            .interfaces
            .into_iter()
            .find(|i| i.name == "wan")
            .unwrap()
            .ipv4
    };
    assert_eq!(wan(&confd), None);
    let mut source = connect(&mut confd, "dhcp-wan");
    let good = source
        .patch(&[
            ipv4("dhcp-wan", Ipv4Addr::new(198, 51, 100, 20), 24),
            dns("dhcp-wan", vec![Ipv4Addr::new(198, 51, 100, 53).into()]),
        ])
        .unwrap();
    // A DHCPv4 client has no delegated prefix.
    let not_its_kind = source
        .patch(&[prefix("dhcp-wan", "2001:db8:1::", 48)])
        .unwrap();
    let answers = run(&mut confd, &mut source, 0);
    assert_eq!(code(&answers, good), Code::CHANGED);
    assert_ne!(code(&answers, not_its_kind).class(), 2);
    assert_eq!(wan(&confd), Some((Ipv4Addr::new(198, 51, 100, 20), 24)));
    assert_eq!(
        confd.source_dns("dhcp-wan"),
        [IpAddr::from(Ipv4Addr::new(198, 51, 100, 53))]
    );
    // The lease is gone when the source deletes it.
    let gone = source
        .patch(&[Change::delete(Key::SourceIpv4 {
            source: "dhcp-wan".into(),
        })])
        .unwrap();
    let answers = run(&mut confd, &mut source, 1);
    assert_eq!(code(&answers, gone), Code::CHANGED);
    assert_eq!(wan(&confd), None);
}

#[test]
fn a_leased_address_that_overlaps_another_interface_is_not_used() {
    let mut confd = Confd::new(file::parse(CONFIG).unwrap());
    let mut source = connect(&mut confd, "dhcp-wan");
    source
        .patch(&[ipv4("dhcp-wan", Ipv4Addr::new(192, 0, 2, 20), 24)])
        .unwrap();
    run(&mut confd, &mut source, 0);
    let wan = confd
        .with_values()
        .interfaces
        .into_iter()
        .find(|i| i.name == "wan")
        .unwrap();
    assert_eq!(wan.ipv4, None, "lan has 192.0.2.0/24");
}

#[test]
fn a_dhcpv6_client_writes_its_prefix_address_and_dns_servers() {
    let mut confd = Confd::new(file::parse(CONFIG).unwrap());
    let mut source = connect(&mut confd, "dhcp6-wan");
    let address: Ipv6Addr = "2001:db8:ff::20".parse().unwrap();
    let good = source
        .patch(&[
            prefix("dhcp6-wan", "2001:db8:12:3400::", 56),
            Change::set(
                Key::SourceIpv6 {
                    source: "dhcp6-wan".into(),
                },
                Value::SourceIpv6 {
                    address,
                    prefix_len: 128,
                    lifetime: 60,
                },
            ),
            dns("dhcp6-wan", vec!["2001:db8:ff::53".parse().unwrap()]),
        ])
        .unwrap();
    let not_its_kind = source
        .patch(&[ipv4("dhcp6-wan", Ipv4Addr::new(198, 51, 100, 20), 24)])
        .unwrap();
    let link_local = source.patch(&[prefix("dhcp6-wan", "fe80::", 64)]).unwrap();
    let multicast_dns = source
        .patch(&[dns("dhcp6-wan", vec!["ff02::1".parse().unwrap()])])
        .unwrap();
    let answers = run(&mut confd, &mut source, 0);
    assert_eq!(code(&answers, good), Code::CHANGED);
    for refused in [not_its_kind, link_local, multicast_dns] {
        assert_ne!(code(&answers, refused).class(), 2, "{answers:?}");
    }
    assert_eq!(
        confd.source_prefix("dhcp6-wan"),
        Some(("2001:db8:12:3400::".parse().unwrap(), 56, 3_600, 7_200))
    );
    assert_eq!(confd.source_ipv6("dhcp6-wan"), Some((address, 128)));
    assert_eq!(confd.source_dns("dhcp6-wan").len(), 1);
}

#[test]
fn a_pppoe_source_may_write_dns_servers() {
    let mut confd = Confd::new(file::parse(CONFIG).unwrap());
    let mut source = connect(&mut confd, "pppoe-wan");
    let servers: Vec<IpAddr> = vec![
        Ipv4Addr::new(192, 0, 2, 53).into(),
        Ipv4Addr::new(192, 0, 2, 54).into(),
    ];
    let token = source.patch(&[dns("pppoe-wan", servers.clone())]).unwrap();
    let answers = run(&mut confd, &mut source, 0);
    assert_eq!(code(&answers, token), Code::CHANGED);
    assert_eq!(confd.source_dns("pppoe-wan"), servers);
    // Their lifetime runs out.
    run(&mut confd, &mut source, 61_000);
    assert!(confd.source_dns("pppoe-wan").is_empty());
}

#[test]
fn ipv4_from_must_name_a_dhcp_client_source_of_its_own() {
    let refused = [
        // Both an address and a source.
        CONFIG.replace(
            "ipv4-from = \"dhcp-wan\"",
            "ipv4-from = \"dhcp-wan\"\nipv4 = \"198.51.100.1/24\"",
        ),
        // Not a DHCPv4 client.
        CONFIG.replace("ipv4-from = \"dhcp-wan\"", "ipv4-from = \"pppoe-wan\""),
        CONFIG.replace("ipv4-from = \"dhcp-wan\"", "ipv4-from = \"nobody\""),
        // Two interfaces from one source.
        format!(
            "{CONFIG}\n[[interface]]\nname = \"wan2\"\nmac = \"02:00:00:00:00:03\"\nipv4-from = \"dhcp-wan\"\n"
        ),
    ];
    for text in refused {
        assert!(file::parse(&text).is_err(), "{text}");
    }
    let lock = ruster_config::resolve(CONFIG).unwrap();
    let wan = lock.interface.iter().find(|i| i.name == "wan").unwrap();
    assert_eq!(wan.ipv4_from, ["dhcp-wan"]);
    assert!(wan.ipv4.is_empty());
    // The lock form says it.
    assert!(lock.to_text().contains("ipv4-from = [\"dhcp-wan\"]"));
}

#[test]
fn only_ipv4_waits_for_the_leased_address() {
    use ruster_proto::session::{Hook, Server, Store};
    struct Accept;
    impl Hook for Accept {
        fn check(&mut self, _next: &Store) -> Result<(), String> {
            Ok(())
        }
        fn committed(&mut self, _store: &Store) {}
    }
    let text = CONFIG.replace(
        "ipv4-from = \"dhcp-wan\"",
        "ipv4-from = \"dhcp-wan\"\nipv6 = [\"2001:db8:ff::2/64\"]",
    ) + "\n[[route]]\nprefix = \"0.0.0.0/0\"\ninterface = \"wan\"\nvia = \"198.51.100.1\"\n\n[[route]]\nprefix = \"::/0\"\ninterface = \"wan\"\nvia = \"fe80::1\"\n";
    let mut confd = Confd::new(file::parse(&text).unwrap());
    let (a, b) = UnixStream::pair().unwrap();
    let mut ribd = Server::new();
    ribd.attach(a, &[ruster_proto::sid::ROUTE]).unwrap();
    confd.connect_ribd(b).unwrap();
    let route = |prefix: IpAddr| Key::Route {
        vrf: "default".into(),
        prefix,
        len: 0,
    };
    let v4 = route(Ipv4Addr::UNSPECIFIED.into());
    let v6 = route(Ipv6Addr::UNSPECIFIED.into());
    let step = |confd: &mut Confd, ribd: &mut Server, now| {
        for _ in 0..50 {
            confd.step(now);
            ribd.step(&mut Accept);
        }
    };
    step(&mut confd, &mut ribd, 0);
    assert!(ribd.store().get(&v6).is_some());
    assert!(ribd.store().get(&v4).is_none());
    let mut source = connect(&mut confd, "dhcp-wan");
    source
        .patch(&[ipv4("dhcp-wan", Ipv4Addr::new(198, 51, 100, 20), 24)])
        .unwrap();
    for _ in 0..50 {
        confd.step(1);
        source.poll();
        ribd.step(&mut Accept);
    }
    assert!(ribd.store().get(&v4).is_some());
}
