//! confd against a stand-in FE that refuses some tables.

use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;

use ruster_confd::{Confd, Config, InterfaceConfig};
use ruster_proto::session::{Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Key, Value};
use ruster_proto::task::Task;

/// Refuses any table with an interface MTU of `refuse_mtu`.
struct Check {
    refuse_mtu: Option<u16>,
}

impl Hook for Check {
    fn check(&mut self, next: &Store) -> Result<(), String> {
        let bad = next.iter().any(|(_, value)| {
            matches!(value, Value::Interface { mtu, .. } if Some(*mtu) == self.refuse_mtu)
        });
        if bad {
            Err("refused".into())
        } else {
            Ok(())
        }
    }
    fn committed(&mut self, _store: &Store) {}
}

fn config(mtu: u16) -> Config {
    Config {
        interfaces: vec![InterfaceConfig {
            name: "lan".into(),
            mac: [2, 0, 0, 0, 0, 1],
            mtu,
            enabled: true,
            ipv4: Some((Ipv4Addr::new(192, 0, 2, 1), 24)),
            ipv6: Vec::new(),
            vrf: "default".into(),
            vlan: None,
        }],
        static_routes: Vec::new(),
        firewall: Vec::new(),
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
    let mut check = Check { refuse_mtu: None };
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
