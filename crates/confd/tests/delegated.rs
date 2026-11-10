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
        (3_600, 7_200)
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
