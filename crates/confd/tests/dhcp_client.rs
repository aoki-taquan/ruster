//! `[[dhcp-client]]`: the part for ruster-dhcpc and the punt classes that hand it
//! DHCP and DHCPv6.

use std::os::unix::net::UnixStream;

use ruster_confd::{file, Confd};
use ruster_proto::session::{Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Key, PuntDestination, PuntMatch, Value};
use ruster_proto::task::Task;

struct Accept;

impl Hook for Accept {
    fn check(&mut self, _next: &Store) -> Result<(), String> {
        Ok(())
    }
    fn committed(&mut self, _store: &Store) {}
}

const CONFIG: &str = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"

[[interface]]
name = "wan"
mac = "02:00:00:00:00:02"
ipv4-from = "dhcp-wan"

[[source]]
name = "dhcp-wan"
kind = "dhcp-client"

[[source]]
name = "dhcp6-wan"
kind = "dhcpv6-client"

[[dhcp-client]]
interface = "wan"
ipv6-source = "dhcp6-wan"
"#;

#[test]
fn the_part_spells_out_the_client() {
    let lock = ruster_config::resolve(CONFIG).unwrap();
    let [client] = &lock.dhcp_client[..] else {
        panic!("{:?}", lock.dhcp_client)
    };
    assert_eq!(
        client.ipv4_source,
        ["dhcp-wan"],
        "the interface's ipv4-from"
    );
    assert_eq!(client.ipv6_source, ["dhcp6-wan"]);
    assert_eq!(client.link_local, "fe80::ff:fe00:2");
    assert_eq!(
        (client.vrf.as_str(), client.mac.as_str()),
        ("default", "02:00:00:00:00:02")
    );
    assert!(client.default_route && !client.ipv6_address);
    assert_eq!((client.punt_rate, client.punt_burst), (20, 20));
    let part = ruster_config::dhcp_client_part(&lock.dhcp_client);
    assert_eq!(
        ruster_config::parse_dhcp_client_part(&part).unwrap(),
        lock.dhcp_client
    );
    assert_eq!(
        file::config(lock.clone()).unwrap().dhcp_client,
        lock.dhcp_client
    );

    let refused = |change: &dyn Fn(&mut ruster_config::DhcpClient), why: &str| {
        let mut wrong = lock.clone();
        change(&mut wrong.dhcp_client[0]);
        let error = file::config(wrong).unwrap_err();
        assert!(error.contains(why), "{error}");
    };
    refused(
        &|c| c.link_local = "fe80::1".into(),
        "must be the interface's",
    );
    refused(
        &|c| c.ipv6_source = vec!["dhcp-wan".into()],
        "kind dhcpv6-client",
    );
    refused(
        &|c| c.ipv4_source = vec!["dhcp6-wan".into()],
        "kind dhcp-client",
    );
    refused(
        &|c| {
            c.interface = "lan".into();
            c.mac = "02:00:00:00:00:01".into();
            c.link_local = "fe80::ff:fe00:1".into();
        },
        "ipv4-from",
    );
    refused(
        &|c| {
            c.ipv4_source.clear();
            c.ipv6_source.clear();
        },
        "give ipv4-source or ipv6-source",
    );
    refused(&|c| c.punt_rate = 0, "punt-rate");
    let mut twice = lock.clone();
    twice.dhcp_client.push(twice.dhcp_client[0].clone());
    assert!(file::config(twice).unwrap_err().contains("given twice"));
}

#[test]
fn the_interface_s_dhcp_replies_go_to_dhcpc() {
    let mut confd = Confd::new(file::parse(CONFIG).unwrap());
    let mut fe = Server::new();
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(
        a,
        &[sid::INTERFACE, sid::ADDRESS, sid::ICMP_ERRORS, sid::PUNT],
    )
    .unwrap();
    confd.connect_fe(b).unwrap();
    for _ in 0..50 {
        fe.step(&mut Accept);
        confd.step(0);
    }
    for (class, port) in [("dhcpc-wan", 68), ("dhcpc6-wan", 546)] {
        let Some(Value::Punt(punt)) = fe.store().get(&Key::Punt {
            class: class.into(),
        }) else {
            panic!("no {class}");
        };
        assert_eq!(
            punt.matches,
            PuntMatch::Ip {
                protocol: 17,
                ports: Some((port, port))
            }
        );
        assert_eq!(punt.interface.as_deref(), Some("wan"));
        assert_eq!(punt.destination, PuntDestination::Control("dhcpc".into()));
    }
    // DHCPv4 only: no class for DHCPv6.
    let v4 = CONFIG.replace("ipv6-source = \"dhcp6-wan\"\n", "");
    let confd = Confd::new(file::parse(&v4).unwrap());
    assert!(confd.config().dhcp_client[0].ipv6_source.is_empty());
}
