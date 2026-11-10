//! `[[dhcp6]]`: what confd checks, the punt class it writes, and the part.

use std::os::unix::net::UnixStream;

use ruster_confd::part::{Client, Module};
use ruster_confd::{file, Confd};
use ruster_proto::session::{Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Key, PuntClass, PuntDestination, PuntMatch, Value};
use ruster_proto::task::Task;

const LAN: &str = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"
ipv6 = ["2001:db8:1::1/64"]

[[interface]]
name = "lan.10"
parent = "lan"
vlan = 10
ipv6 = ["2001:db8:1:10::1/64"]

[[interface]]
name = "lan.20"
parent = "lan"
vlan = 20
ipv6 = ["2001:db8:1::8000:1/120"]
"#;

fn entry(interface: &str, pool: &str, more: &str) -> String {
    format!("\n[[dhcp6]]\ninterface = \"{interface}\"\npool = \"{pool}\"\n{more}")
}

#[test]
fn dhcp6_is_checked() {
    let good = format!(
        "{LAN}{}",
        entry("lan", "2001:db8:1::1000-2001:db8:1::1fff", "")
    );
    assert_eq!(file::parse(&good).unwrap().dhcp6.len(), 1);
    for (pool, more, error) in [
        ("2001:db8:2::10-2001:db8:2::20", "", "within"),
        ("2001:db8:1::-2001:db8:1::20", "", "within"),
        ("2001:db8:1::20-2001:db8:1::10", "", "first not above"),
        ("2001:db8:1::1-2001:db8:1::20", "", "router's address"),
        ("2001:db8:1::10", "", "pool must be like"),
        (
            "2001:db8:1::10-2001:db8:1::20",
            "valid-lifetime = 10\n",
            "valid-lifetime",
        ),
        (
            "2001:db8:1::10-2001:db8:1::20",
            "preferred-lifetime = 9000\n",
            "preferred-lifetime",
        ),
        (
            "2001:db8:1::10-2001:db8:1::20",
            "dns = [\"ff02::1\"]\n",
            "dns",
        ),
        (
            "2001:db8:1::10-2001:db8:1::20",
            "punt-rate = 0\n",
            "punt-rate",
        ),
    ] {
        let text = format!("{LAN}{}", entry("lan", pool, more));
        let got = file::parse(&text).unwrap_err();
        assert!(got.contains(error), "{pool} {more}: {got}");
    }
    let twice = format!(
        "{good}{}",
        entry("lan", "2001:db8:1::2000-2001:db8:1::2fff", "")
    );
    assert!(file::parse(&twice).unwrap_err().contains("given twice"));
    // lan.20's /120 lies in lan's /64.
    let overlap = format!(
        "{good}{}",
        entry("lan.20", "2001:db8:1::8000:10-2001:db8:1::8000:20", "")
    );
    assert!(file::parse(&overlap).unwrap_err().contains("overlaps"));
}

#[test]
fn a_dhcp6_lock_entry_must_agree_with_its_interface() {
    let text = format!(
        "{LAN}{}",
        entry("lan", "2001:db8:1::1000-2001:db8:1::1fff", "")
    );
    let lock = ruster_config::resolve(&text).unwrap();
    for (change, error) in [
        (("mac", "02:00:00:00:00:09"), "mac"),
        (("link-local", "fe80::1"), "link-local"),
        (("address", "2001:db8:1::2/64"), "address"),
    ] {
        let mut lock = lock.clone();
        let d = &mut lock.dhcp6[0];
        match change.0 {
            "mac" => d.mac = change.1.into(),
            "link-local" => d.link_local = change.1.into(),
            _ => d.address = change.1.into(),
        }
        let got = file::parse(&lock.to_text()).unwrap_err();
        assert!(got.contains(error), "{change:?}: {got}");
    }
}

struct Accept;

impl Hook for Accept {
    fn check(&mut self, _next: &Store) -> Result<(), String> {
        Ok(())
    }
    fn committed(&mut self, _store: &Store) {}
}

#[test]
fn each_dhcp6_interface_hands_port_547_to_kea() {
    let text = format!(
        "{LAN}\n[[dhcp]]\ninterface = \"lan\"\npool = \"192.0.2.100-192.0.2.199\"\n{}",
        entry(
            "lan.10",
            "2001:db8:1:10::1000-2001:db8:1:10::1fff",
            "punt-rate = 7\npunt-burst = 8\n"
        )
    );
    let mut fe = Server::new();
    let mut confd = Confd::new(file::parse(&text).unwrap());
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
    for _ in 0..200 {
        fe.step(&mut Accept);
        confd.step(0);
        kea.poll(&mut |part| {
            parts.push(part.to_owned());
            Ok(())
        })
        .unwrap();
    }
    let classes: Vec<(String, PuntClass)> = fe
        .store()
        .iter()
        .filter_map(|(key, value)| match (key, value) {
            (Key::Punt { class }, Value::Punt(entry)) => Some((class.clone(), entry.clone())),
            _ => None,
        })
        .collect();
    let names: Vec<&str> = classes.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["dhcp-lan", "dhcp6-lan.10"]);
    assert_eq!(
        classes[1].1,
        PuntClass {
            matches: PuntMatch::Ip {
                protocol: 17,
                ports: Some((547, 547)),
            },
            interface: Some("lan.10".into()),
            destination: PuntDestination::Control("kea".into()),
            rate: 7,
            burst: 8,
        }
    );
    let (dhcp, dhcp6) = ruster_config::parse_dhcp_part(&parts[0]).unwrap();
    assert_eq!((dhcp.len(), dhcp6.len()), (1, 1));
    assert_eq!(dhcp6[0].address, "2001:db8:1:10::1/64");
}
