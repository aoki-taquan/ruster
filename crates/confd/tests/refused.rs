//! confd against a stand-in FE that refuses some tables.

use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;

use ruster_confd::{Confd, Config, InterfaceConfig};
use ruster_proto::session::{Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Key, Value};
use ruster_proto::task::Task;

/// Refuses any table with an interface MTU of `refuse_mtu`, or without an
/// interface named `keep`.
struct Check {
    refuse_mtu: Option<u16>,
    keep: Option<&'static str>,
}

impl Hook for Check {
    fn check(&mut self, next: &Store) -> Result<(), String> {
        let bad = next.iter().any(|(_, value)| {
            matches!(value, Value::Interface { mtu, .. } if Some(*mtu) == self.refuse_mtu)
        });
        let lost = self
            .keep
            .is_some_and(|name| next.get(&Key::Interface { name: name.into() }).is_none());
        if bad || lost {
            Err("refused".into())
        } else {
            Ok(())
        }
    }
    fn committed(&mut self, _store: &Store) {}
}

fn config(mtu: u16) -> Config {
    Config {
        wireguard: Vec::new(),
        interfaces: vec![InterfaceConfig {
            name: "lan".into(),
            mac: [2, 0, 0, 0, 0, 1],
            mtu,
            enabled: true,
            ipv4: Some((Ipv4Addr::new(192, 0, 2, 1), 24)),
            ipv6: Vec::new(),
            vrf: "default".into(),
            vlan: None,
            tunnel: None,
            pppoe: None,
        }],
        static_routes: Vec::new(),
        firewall: Vec::new(),
        firewall_filtering: Default::default(),
        icmp_errors: None,
        nat: None,
    }
}

fn settle(fe: &mut Server, confd: &mut Confd, check: &mut Check) {
    for _ in 0..1_000 {
        let busy = fe.step(check).busy | confd.step(0).busy;
        if !busy {
            // One more round lets messages queued by the last answers go out.
            fe.step(check);
            confd.step(0);
            fe.step(check);
            return;
        }
    }
    panic!("never settled");
}

fn mtu(fe: &Server) -> Option<u16> {
    match fe.store().get(&Key::Interface { name: "lan".into() }) {
        Some(Value::Interface { mtu, .. }) => Some(*mtu),
        _ => None,
    }
}

#[test]
fn a_refused_full_send_leaves_what_the_fe_holds() {
    let mut fe = Server::new();
    let mut check = Check {
        refuse_mtu: None,
        keep: None,
    };
    let mut confd = Confd::new(config(1500));
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, &[sid::INTERFACE, sid::ADDRESS]).unwrap();
    confd.connect_fe(b).unwrap();
    settle(&mut fe, &mut confd, &mut check);
    assert_eq!(mtu(&fe), Some(1500));
    assert_eq!(fe.store().len(), 3);

    // confd restarts with a configuration the FE refuses: the FE keeps the old one.
    check.refuse_mtu = Some(1400);
    let mut confd = Confd::new(config(1400));
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, &[sid::INTERFACE, sid::ADDRESS]).unwrap();
    confd.connect_fe(b).unwrap();
    settle(&mut fe, &mut confd, &mut check);
    assert_eq!(confd.counters().patches_refused, 1);
    assert_eq!(mtu(&fe), Some(1500), "the old interface stays");
    assert_eq!(fe.store().len(), 3, "and so does its address");

    // A configuration the FE accepts goes through.
    confd.set_config(config(1280));
    settle(&mut fe, &mut confd, &mut check);
    assert_eq!(mtu(&fe), Some(1280));
    assert_eq!(fe.store().len(), 3);
}

#[test]
fn a_refused_change_is_retried_with_the_next_one_and_leftovers_are_removed() {
    let mut fe = Server::new();
    let mut check = Check {
        refuse_mtu: Some(1400),
        keep: None,
    };
    let mut confd = Confd::new(config(1500));
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, &[sid::INTERFACE, sid::ADDRESS]).unwrap();
    confd.connect_fe(b).unwrap();
    settle(&mut fe, &mut confd, &mut check);

    let mut without_address = config(1400);
    without_address.interfaces[0].ipv4 = None;
    confd.set_config(without_address.clone());
    settle(&mut fe, &mut confd, &mut check);
    assert_eq!(mtu(&fe), Some(1500), "refused");

    without_address.interfaces[0].mtu = 1280;
    confd.set_config(without_address);
    settle(&mut fe, &mut confd, &mut check);
    assert_eq!(mtu(&fe), Some(1280));
    assert_eq!(
        fe.store().len(),
        2,
        "the IPv4 address removed in the refused change is gone too (the link-local stays)"
    );
}

#[test]
fn what_is_accepted_after_a_refused_send_is_cleaned_up_later() {
    let mut fe = Server::new();
    let mut check = Check {
        refuse_mtu: Some(1400),
        keep: None,
    };
    // The full send is refused; before its answer, a change adds "wan" and is accepted.
    let mut confd = Confd::new(config(1400));
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, &[sid::INTERFACE, sid::ADDRESS]).unwrap();
    confd.connect_fe(b).unwrap();
    let mut with_wan = config(1500);
    with_wan.interfaces.push(InterfaceConfig {
        name: "wan".into(),
        mac: [2, 0, 0, 0, 0, 2],
        mtu: 1500,
        enabled: true,
        ipv4: None,
        ipv6: Vec::new(),
        vrf: "default".into(),
        vlan: None,
        tunnel: None,
        pppoe: None,
    });
    confd.set_config(with_wan);
    settle(&mut fe, &mut confd, &mut check);
    assert_eq!(confd.counters().patches_refused, 1);

    // A later configuration without "wan" removes it.
    confd.set_config(config(1500));
    settle(&mut fe, &mut confd, &mut check);
    assert_eq!(mtu(&fe), Some(1500));
    assert!(fe
        .store()
        .get(&Key::Interface { name: "wan".into() })
        .is_none());
    assert_eq!(fe.store().len(), 3);
}

#[test]
fn a_refused_older_change_does_not_lose_the_newer_one() {
    let mut fe = Server::new();
    let mut check = Check {
        refuse_mtu: Some(1400),
        keep: None,
    };
    let mut confd = Confd::new(config(1500));
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, &[sid::INTERFACE, sid::ADDRESS]).unwrap();
    confd.connect_fe(b).unwrap();
    settle(&mut fe, &mut confd, &mut check);

    // Two changes in flight; the FE refuses the first, which drops the second too.
    // The second is sent as a difference from the first (the address already moved),
    // so on its own it would leave the old address in the FE.
    let moved = |mtu| {
        let mut config = config(mtu);
        config.interfaces[0].ipv4 = Some((Ipv4Addr::new(192, 0, 2, 2), 24));
        config
    };
    confd.set_config(moved(1400));
    confd.set_config(moved(1280));
    settle(&mut fe, &mut confd, &mut check);
    assert_eq!(mtu(&fe), Some(1280));
    let address = |last| Key::Address {
        interface: "lan".into(),
        address: Ipv4Addr::new(192, 0, 2, last).into(),
    };
    assert!(
        fe.store().get(&address(2)).is_some(),
        "the newer one is sent again"
    );
    assert!(fe.store().get(&address(1)).is_none());
    assert!(confd.settled());
}

#[test]
fn a_refused_resync_end_is_sent_again_after_the_next_change() {
    let mut fe = Server::new();
    let mut check = Check {
        refuse_mtu: None,
        keep: None,
    };
    let mut two = config(1500);
    let mut wan = two.interfaces[0].clone();
    wan.name = "wan".into();
    wan.mac = [2, 0, 0, 0, 0, 2];
    wan.ipv4 = None;
    two.interfaces.push(wan);
    let mut confd = Confd::new(two);
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, &[sid::INTERFACE, sid::ADDRESS]).unwrap();
    confd.connect_fe(b).unwrap();
    settle(&mut fe, &mut confd, &mut check);
    let wan = Key::Interface { name: "wan".into() };
    assert!(fe.store().get(&wan).is_some());

    // confd restarts without wan, and the FE refuses to delete it.
    check.keep = Some("wan");
    let mut confd = Confd::new(config(1500));
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, &[sid::INTERFACE, sid::ADDRESS]).unwrap();
    confd.connect_fe(b).unwrap();
    settle(&mut fe, &mut confd, &mut check);
    assert!(fe.store().get(&wan).is_some(), "refused, so kept");
    assert!(confd.settled());
    // Old entries that stay are not a refusal of the configuration just applied.
    assert!(confd.refused_since(confd.generation()).is_none());

    check.keep = None;
    confd.set_config(config(1400));
    settle(&mut fe, &mut confd, &mut check);
    assert_eq!(mtu(&fe), Some(1400));
    assert_eq!(fe.store().get(&wan), None, "the resync ended");
}
