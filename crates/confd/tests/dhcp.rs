//! DHCP: the punt classes confd writes to the FE, and the part ruster-kea takes.

use std::os::unix::net::UnixStream;

use ruster_confd::part::{Client, Module};
use ruster_confd::{file, Confd, DHCP_PUNT_BURST, DHCP_PUNT_RATE};
use ruster_proto::session::{Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Key, PuntClass, PuntDestination, PuntMatch, Value};
use ruster_proto::task::Task;

struct Accept;

impl Hook for Accept {
    fn check(&mut self, _next: &Store) -> Result<(), String> {
        Ok(())
    }
    fn committed(&mut self, _store: &Store) {}
}

const INTERFACES: &str = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"

[[interface]]
name = "lan.10"
parent = "lan"
vlan = 10
ipv4 = "10.10.0.1/24"
"#;

fn with_dhcp(interfaces: &[&str]) -> String {
    let mut text = INTERFACES.to_owned();
    for (name, pool) in [
        ("lan", "192.0.2.100-192.0.2.199"),
        ("lan.10", "10.10.0.100-10.10.0.199"),
    ] {
        if interfaces.contains(&name) {
            text.push_str(&format!(
                "\n[[dhcp]]\ninterface = \"{name}\"\npool = \"{pool}\"\n"
            ));
        }
    }
    text
}

fn run(fe: &mut Server, confd: &mut Confd, kea: &mut Client, parts: &mut Vec<String>) {
    for _ in 0..200 {
        fe.step(&mut Accept);
        confd.step(0);
        kea.poll(&mut |part| {
            parts.push(part.to_owned());
            Ok(())
        })
        .unwrap();
    }
}

fn punt_classes(fe: &Server) -> Vec<(String, PuntClass)> {
    fe.store()
        .iter()
        .filter_map(|(key, value)| match (key, value) {
            (Key::Punt { class }, Value::Punt(entry)) => Some((class.clone(), entry.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn each_dhcp_interface_hands_the_server_port_to_kea() {
    let mut fe = Server::new();
    let mut confd = Confd::new(file::parse(&with_dhcp(&["lan", "lan.10"])).unwrap());
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(
        a,
        &[sid::INTERFACE, sid::ADDRESS, sid::ICMP_ERRORS, sid::PUNT],
    )
    .unwrap();
    confd.connect_fe(b).unwrap();
    let (a, b) = UnixStream::pair().unwrap();
    confd.attach_part(a).unwrap();
    let mut kea = Client::new(b, Module::Dhcp).unwrap();
    let mut parts = Vec::new();
    run(&mut fe, &mut confd, &mut kea, &mut parts);

    let class = |interface: &str| PuntClass {
        matches: PuntMatch::Ip {
            protocol: 17,
            ports: Some((67, 67)),
        },
        interface: Some(interface.into()),
        destination: PuntDestination::Control("kea".into()),
        rate: DHCP_PUNT_RATE,
        burst: DHCP_PUNT_BURST,
    };
    assert_eq!(
        punt_classes(&fe),
        [
            ("dhcp-lan".to_owned(), class("lan")),
            ("dhcp-lan.10".to_owned(), class("lan.10")),
        ]
    );
    assert_eq!(parts.len(), 1);
    let dhcp = ruster_config::parse_dhcp_part(&parts[0]).unwrap();
    assert_eq!(dhcp.len(), 2);
    assert_eq!(dhcp[1].address, "10.10.0.1/24");

    // Removing one interface's dhcp removes its class, and the part changes.
    confd.set_config(file::parse(&with_dhcp(&["lan.10"])).unwrap());
    run(&mut fe, &mut confd, &mut kea, &mut parts);
    assert_eq!(
        punt_classes(&fe),
        [("dhcp-lan.10".to_owned(), class("lan.10"))]
    );
    assert_eq!(parts.len(), 2);
    assert_eq!(ruster_config::parse_dhcp_part(&parts[1]).unwrap().len(), 1);

    // Without dhcp there are no classes, and the part is empty.
    confd.set_config(file::parse(INTERFACES).unwrap());
    run(&mut fe, &mut confd, &mut kea, &mut parts);
    assert!(punt_classes(&fe).is_empty());
    assert!(ruster_config::parse_dhcp_part(&parts[2])
        .unwrap()
        .is_empty());
}
