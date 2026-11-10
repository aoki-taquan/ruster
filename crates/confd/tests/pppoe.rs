//! A PPPoE interface in the FE's tables, from its source's values.

use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::net::UnixStream;

use ruster_confd::{file, Confd};
use ruster_proto::session::{Client, Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Change, Key, Pppoe, PuntDestination, PuntKind, PuntMatch, Value};
use ruster_proto::task::Task;

struct Accept;

impl Hook for Accept {
    fn check(&mut self, _next: &Store) -> Result<(), String> {
        Ok(())
    }
    fn committed(&mut self, _store: &Store) {}
}

const CONFIG: &str = r#"
[[source]]
name = "pppoe-wan"
kind = "pppoe"
sync-wait = 0

[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.168.0.1/24"

[[interface]]
name = "wan"
mac = "02:00:00:00:00:02"

[[interface]]
name = "ppp"
pppoe = { parent = "wan", source = "pppoe-wan" }
mtu = 1454

[[route]]
prefix = "0.0.0.0/0"
interface = "ppp"

[nat]
inside = "lan"
outside = "ppp"
"#;

struct Rig {
    fe: Server,
    ribd: Server,
    confd: Confd,
    source: Client,
}

impl Rig {
    fn new() -> Self {
        let mut confd = Confd::new(file::parse(CONFIG).unwrap());
        let mut fe = Server::new();
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(
            a,
            &[
                sid::INTERFACE,
                sid::ADDRESS,
                sid::NAT,
                sid::ICMP_ERRORS,
                sid::PUNT,
                sid::FIREWALL_POLICY,
            ],
        )
        .unwrap();
        confd.connect_fe(b).unwrap();
        let mut ribd = Server::new();
        let (a, b) = UnixStream::pair().unwrap();
        ribd.attach(a, &[sid::ROUTE]).unwrap();
        confd.connect_ribd(b).unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        confd.attach_source("pppoe-wan", a).unwrap();
        Self {
            fe,
            ribd,
            confd,
            source: Client::new(b).unwrap(),
        }
    }

    fn run(&mut self, now: u64) {
        for _ in 0..50 {
            self.fe.step(&mut Accept);
            self.ribd.step(&mut Accept);
            self.confd.step(now);
            self.source.poll();
        }
    }

    fn fe(&self, key: &Key) -> Option<&Value> {
        self.fe.store().get(key)
    }
}

fn ppp() -> Key {
    Key::Interface { name: "ppp".into() }
}

fn session(lifetime: u32) -> Change {
    Change::set(
        Key::SourcePppoe {
            source: "pppoe-wan".into(),
        },
        Value::SourcePppoe {
            session: 4660,
            peer: [2, 0, 0, 0, 0, 0xac],
            mtu: 1492,
            lifetime,
        },
    )
}

fn address(lifetime: u32) -> Change {
    Change::set(
        Key::SourceIpv4 {
            source: "pppoe-wan".into(),
        },
        Value::SourceIpv4 {
            address: Ipv4Addr::new(198, 51, 100, 2),
            prefix_len: 32,
            lifetime,
        },
    )
}

fn default_route() -> Key {
    Key::Route {
        vrf: "default".into(),
        prefix: Ipv4Addr::UNSPECIFIED.into(),
        len: 0,
    }
}

fn ppp_address() -> Key {
    Key::Address {
        interface: "ppp".into(),
        address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
    }
}

#[test]
fn the_session_interface_is_there_while_the_session_is_up() {
    let mut rig = Rig::new();
    rig.run(0);
    assert_eq!(rig.fe(&ppp()), None);
    assert!(rig
        .fe(&Key::Nat {
            vrf: "default".into()
        })
        .is_none());
    assert!(rig.ribd.store().get(&default_route()).is_none());

    // The session without its address yet: the interface, but no NAT.
    rig.source.patch(&[session(30)]).unwrap();
    rig.run(1_000);
    assert_eq!(
        rig.fe(&ppp()),
        Some(&Value::Interface {
            enabled: true,
            mac: [2, 0, 0, 0, 0, 2],
            // The configured MTU, which is less than the session's.
            mtu: 1454,
            vrf: "default".into(),
            vlan: None,
            tunnel: None,
            pppoe: Some(Pppoe {
                parent: "wan".into(),
                session: 4660,
                peer: [2, 0, 0, 0, 0, 0xac],
            }),
        })
    );
    assert!(rig
        .fe(&Key::Nat {
            vrf: "default".into()
        })
        .is_none());
    assert!(
        rig.ribd.store().get(&default_route()).is_none(),
        "nothing leaves through NAT's outside before NAT is there"
    );

    rig.source.patch(&[address(10)]).unwrap();
    rig.run(2_000);
    assert!(rig.fe(&ppp_address()).is_some());
    assert!(rig.ribd.store().get(&default_route()).is_some());
    assert!(rig
        .fe(&Key::Nat {
            vrf: "default".into()
        })
        .is_some());
    let connected = Key::Route {
        vrf: "default".into(),
        prefix: Ipv4Addr::new(198, 51, 100, 2).into(),
        len: 32,
    };
    assert!(rig.ribd.store().get(&connected).is_some());
    let config = rig.confd.with_values();
    assert_eq!(
        config.interfaces[2].ipv4,
        Some((Ipv4Addr::new(198, 51, 100, 2), 32))
    );

    // The address runs out; then the session.
    rig.run(12_000);
    assert!(rig.fe(&ppp_address()).is_none());
    assert!(rig
        .fe(&Key::Nat {
            vrf: "default".into()
        })
        .is_none());
    assert!(rig.fe(&ppp()).is_some());
    rig.run(31_000);
    assert!(rig.fe(&ppp()).is_none());
    assert!(rig.ribd.store().get(&default_route()).is_none());
    assert_eq!(rig.confd.with_values().interfaces[2].ipv4, None);
}

#[test]
fn an_address_that_clashes_with_the_configuration_is_not_used() {
    let mut rig = Rig::new();
    rig.source
        .patch(&[
            session(30),
            Change::set(
                Key::SourceIpv4 {
                    source: "pppoe-wan".into(),
                },
                Value::SourceIpv4 {
                    address: Ipv4Addr::new(192, 168, 0, 9),
                    prefix_len: 32,
                    lifetime: 30,
                },
            ),
        ])
        .unwrap();
    rig.run(0);
    assert!(rig.fe(&ppp()).is_some());
    let clash = Key::Address {
        interface: "ppp".into(),
        address: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 9)),
    };
    assert!(rig.fe(&clash).is_none());
    assert!(rig
        .fe(&Key::Nat {
            vrf: "default".into()
        })
        .is_none());
    assert_eq!(rig.confd.with_values().interfaces[2].ipv4, None);
}

const CLIENT: &str = r#"
[[pppoe]]
source = "pppoe-wan"
user = "user@isp"
password = "secret"
ac-name = "isp-ac"
default-route = true
"#;

#[test]
fn the_client_s_part_spells_out_where_the_session_runs() {
    let lock = ruster_config::resolve(&format!("{CONFIG}{CLIENT}")).unwrap();
    let [client] = &lock.pppoe[..] else {
        panic!("{:?}", lock.pppoe)
    };
    assert_eq!(
        (
            client.interface.as_str(),
            client.vrf.as_str(),
            client.parent.as_str(),
            client.mac.as_str()
        ),
        ("ppp", "default", "wan", "02:00:00:00:00:02")
    );
    assert_eq!(client.ac_name, ["isp-ac"]);
    assert!(client.ipv6 && client.default_route && client.service.is_empty());
    assert_eq!((client.echo_interval, client.echo_failures), (10, 3));
    let part = ruster_config::pppoe_part(&lock.pppoe);
    assert_eq!(ruster_config::parse_pppoe_part(&part).unwrap(), lock.pppoe);
    // The lock form is checked against the interfaces.
    let config = file::config(lock.clone()).unwrap();
    assert_eq!(config.pppoe, lock.pppoe);
    let mut wrong = lock.clone();
    wrong.pppoe[0].parent = "lan".into();
    assert!(file::config(wrong)
        .unwrap_err()
        .contains("must be those of"));
    let mut wrong = lock.clone();
    wrong.pppoe[0].user = "u".repeat(256);
    assert!(file::config(wrong).unwrap_err().contains("longer than 255"));
    // An upper-case MAC in ruster.toml is the same MAC.
    let upper = format!("{CONFIG}{CLIENT}").replace("02:00:00:00:00:02", "02:00:00:00:00:0A");
    assert!(
        file::parse(&upper).is_ok(),
        "{:?}",
        file::parse(&upper).err()
    );
    let none = format!(
        "{CONFIG}{}",
        CLIENT.replace("source = \"pppoe-wan\"", "source = \"x\"")
    );
    assert!(ruster_config::resolve(&none)
        .unwrap_err()
        .contains("no PPPoE interface"));
}

#[test]
fn the_parent_s_pppoe_frames_go_to_pppoed() {
    let mut confd = Confd::new(file::parse(&format!("{CONFIG}{CLIENT}")).unwrap());
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
    for (class, kind) in [
        ("pppoe-discovery-wan", PuntKind::PppoeDiscovery),
        ("ppp-control-wan", PuntKind::PppControl),
    ] {
        let Some(Value::Punt(punt)) = fe.store().get(&Key::Punt {
            class: class.into(),
        }) else {
            panic!("no {class}");
        };
        assert_eq!(punt.matches, PuntMatch::Kind(kind));
        assert_eq!(punt.interface.as_deref(), Some("wan"));
        assert_eq!(punt.destination, PuntDestination::Control("pppoed".into()));
    }
    // Without a client, nothing goes to pppoed.
    let tables = Confd::new(file::parse(CONFIG).unwrap());
    assert!(tables.config().pppoe.is_empty());
}
