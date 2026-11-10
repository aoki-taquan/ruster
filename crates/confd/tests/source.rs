//! Sources: the values they send, their lifetimes, and confd waiting for them after
//! it starts.

use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;

use ruster_confd::{file, Confd};
use ruster_proto::coap::Code;
use ruster_proto::session::{Client, Event, Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Change, Key, Value};
use ruster_proto::task::Task;

struct Accept;

impl Hook for Accept {
    fn check(&mut self, _next: &Store) -> Result<(), String> {
        Ok(())
    }
    fn committed(&mut self, _store: &Store) {}
}

const LAN: &str = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"
"#;

fn with_source(wait: u32) -> String {
    format!("{LAN}\n[[source]]\nname = \"pppoe-wan\"\nkind = \"pppoe\"\nsync-wait = {wait}\n")
}

fn session(source: &str, lifetime: u32) -> Change {
    Change::set(
        Key::SourcePppoe {
            source: source.into(),
        },
        Value::SourcePppoe {
            session: 4660,
            peer: [2, 0, 0, 0, 0, 0xac],
            mtu: 1492,
            lifetime,
        },
    )
}

fn ipv4(address: Ipv4Addr, lifetime: u32) -> Change {
    Change::set(
        Key::SourceIpv4 {
            source: "pppoe-wan".into(),
        },
        Value::SourceIpv4 {
            address,
            prefix_len: 32,
            lifetime,
        },
    )
}

/// A connection to the source's socket.
fn connect(confd: &mut Confd) -> Client {
    let (a, b) = UnixStream::pair().unwrap();
    confd.attach_source("pppoe-wan", a).unwrap();
    Client::new(b).unwrap()
}

/// Runs confd at `now` with the source; the source's answers.
fn run(confd: &mut Confd, source: &mut Client, now: u64) -> Vec<(u32, Code, String)> {
    let mut answers = Vec::new();
    for _ in 0..50 {
        confd.step(now);
        for event in source.poll().1 {
            if let Event::Response {
                token,
                code,
                payload,
            } = event
            {
                answers.push((token, code, String::from_utf8_lossy(&payload).into_owned()));
            }
        }
    }
    answers
}

fn code(answers: &[(u32, Code, String)], token: u32) -> Code {
    answers
        .iter()
        .find(|(t, _, _)| *t == token)
        .map(|(_, code, _)| *code)
        .expect("an answer")
}

#[test]
fn a_source_writes_only_its_own_values_of_its_kind() {
    let mut confd = Confd::new(file::parse(&with_source(10)).unwrap());
    let mut source = connect(&mut confd);
    let good = source
        .patch(&[
            session("pppoe-wan", 60),
            ipv4(Ipv4Addr::new(198, 51, 100, 2), 60),
        ])
        .unwrap();
    let other_name = source.patch(&[session("other", 60)]).unwrap();
    let route = source
        .patch(&[Change::set(
            Key::Route {
                vrf: "default".into(),
                prefix: Ipv4Addr::UNSPECIFIED.into(),
                len: 0,
            },
            Value::Route(ruster_proto::table::RouteAction::Discard),
        )])
        .unwrap();
    let multicast = source
        .patch(&[ipv4(Ipv4Addr::new(224, 0, 0, 1), 60)])
        .unwrap();
    let answers = run(&mut confd, &mut source, 0);
    assert_eq!(code(&answers, good), Code::CHANGED);
    for refused in [other_name, route, multicast] {
        assert_ne!(code(&answers, refused).class(), 2, "{answers:?}");
    }
    assert_eq!(
        confd.source_pppoe("pppoe-wan"),
        Some((4660, [2, 0, 0, 0, 0, 0xac], 1492))
    );
    assert_eq!(
        confd.source_ipv4("pppoe-wan"),
        Some((Ipv4Addr::new(198, 51, 100, 2), 32))
    );
    assert!(confd
        .attach_source("nobody", UnixStream::pair().unwrap().0)
        .is_err());
}

#[test]
fn a_value_lasts_its_lifetime_from_when_it_last_arrived() {
    let mut confd = Confd::new(file::parse(&with_source(10)).unwrap());
    let mut source = connect(&mut confd);
    source.patch(&[session("pppoe-wan", 10)]).unwrap();
    source
        .patch(&[ipv4(Ipv4Addr::new(198, 51, 100, 2), 10)])
        .unwrap();
    run(&mut confd, &mut source, 1_000);
    // The session is sent again at 8 s, the address is not.
    run(&mut confd, &mut source, 8_000);
    source.patch(&[session("pppoe-wan", 10)]).unwrap();
    run(&mut confd, &mut source, 8_000);
    run(&mut confd, &mut source, 11_000);
    assert!(confd.source_pppoe("pppoe-wan").is_some());
    assert_eq!(confd.source_ipv4("pppoe-wan"), None);
    run(&mut confd, &mut source, 18_000);
    assert_eq!(confd.source_pppoe("pppoe-wan"), None);
    // Sent again after it ran out, it is back.
    source
        .patch(&[ipv4(Ipv4Addr::new(198, 51, 100, 2), 10)])
        .unwrap();
    run(&mut confd, &mut source, 19_000);
    assert!(confd.source_ipv4("pppoe-wan").is_some());
    // Values stay while the source is away, and a resync drops what it did not
    // send again.
    drop(source);
    let mut idle = connect(&mut confd);
    run(&mut confd, &mut idle, 20_000);
    assert!(confd.source_ipv4("pppoe-wan").is_some());
    let mut again = connect(&mut confd);
    again.resync_begin();
    again.patch(&[session("pppoe-wan", 10)]).unwrap();
    again.resync_end();
    run(&mut confd, &mut again, 21_000);
    assert!(confd.source_pppoe("pppoe-wan").is_some());
    assert_eq!(confd.source_ipv4("pppoe-wan"), None);
}

/// An FE that holds an interface from the confd before.
fn fe_with_old_entry() -> Server {
    let mut fe = Server::new();
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, &[sid::INTERFACE, sid::ADDRESS, sid::ICMP_ERRORS])
        .unwrap();
    let mut old = Client::new(b).unwrap();
    old.patch(&[Change::set(
        Key::Interface { name: "ppp".into() },
        Value::Interface {
            enabled: true,
            mac: [2, 0, 0, 0, 0, 2],
            mtu: 1492,
            vrf: "default".into(),
            vlan: None,
            tunnel: None,
            pppoe: None,
        },
    )])
    .unwrap();
    for _ in 0..20 {
        fe.step(&mut Accept);
        old.poll();
    }
    fe
}

fn old_entry(fe: &Server) -> bool {
    fe.store()
        .get(&Key::Interface { name: "ppp".into() })
        .is_some()
}

fn run_with_fe(fe: &mut Server, confd: &mut Confd, source: &mut Client, now: u64) {
    for _ in 0..50 {
        fe.step(&mut Accept);
        confd.step(now);
        source.poll();
    }
}

#[test]
fn after_starting_confd_waits_for_the_sources_before_the_fe_drops_old_entries() {
    let mut fe = fe_with_old_entry();
    let mut confd = Confd::new(file::parse(&with_source(10)).unwrap());
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, &[sid::INTERFACE, sid::ADDRESS, sid::ICMP_ERRORS])
        .unwrap();
    confd.connect_fe(b).unwrap();
    let mut source = connect(&mut confd);
    run_with_fe(&mut fe, &mut confd, &mut source, 0);
    assert!(confd.waiting_for_sources());
    // confd's own entries are there, and the old one is kept.
    assert!(fe
        .store()
        .get(&Key::Interface { name: "lan".into() })
        .is_some());
    assert!(old_entry(&fe));
    run_with_fe(&mut fe, &mut confd, &mut source, 5_000);
    assert!(old_entry(&fe));
    source.sync_done();
    run_with_fe(&mut fe, &mut confd, &mut source, 5_000);
    assert!(!confd.waiting_for_sources());
    assert!(!old_entry(&fe));
}

#[test]
fn a_source_that_does_not_come_back_is_waited_for_its_sync_wait() {
    let mut fe = fe_with_old_entry();
    let mut confd = Confd::new(file::parse(&with_source(3)).unwrap());
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, &[sid::INTERFACE, sid::ADDRESS, sid::ICMP_ERRORS])
        .unwrap();
    confd.connect_fe(b).unwrap();
    let (_, mut nobody) = UnixStream::pair()
        .map(|(a, b)| (a, Client::new(b).unwrap()))
        .unwrap();
    run_with_fe(&mut fe, &mut confd, &mut nobody, 1_000);
    run_with_fe(&mut fe, &mut confd, &mut nobody, 3_999);
    assert!(old_entry(&fe));
    run_with_fe(&mut fe, &mut confd, &mut nobody, 4_000);
    assert!(!old_entry(&fe));

    // With no source declared, nothing is waited for.
    let mut fe = fe_with_old_entry();
    let mut confd = Confd::new(file::parse(LAN).unwrap());
    assert!(!confd.waiting_for_sources());
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, &[sid::INTERFACE, sid::ADDRESS, sid::ICMP_ERRORS])
        .unwrap();
    confd.connect_fe(b).unwrap();
    run_with_fe(&mut fe, &mut confd, &mut nobody, 0);
    assert!(!old_entry(&fe));
}

#[test]
fn sources_are_checked() {
    for (text, error) in [
        ("name = \"Wan\"\nkind = \"pppoe\"", "lower-case"),
        ("name = \"wan\"\nkind = \"dhcp\"", "kind"),
        (
            "name = \"wan\"\nkind = \"pppoe\"\nsync-wait = 601",
            "sync-wait",
        ),
    ] {
        let got = file::parse(&format!("{LAN}\n[[source]]\n{text}\n")).unwrap_err();
        assert!(got.contains(error), "{text}: {got}");
    }
    let twice = format!(
        "{}\n[[source]]\nname = \"pppoe-wan\"\nkind = \"pppoe\"\n",
        with_source(1)
    );
    assert!(file::parse(&twice).unwrap_err().contains("twice"));
    let config = file::parse(&format!(
        "{LAN}\n[[source]]\nname = \"pppoe-wan\"\nkind = \"pppoe\"\n"
    ))
    .unwrap();
    assert_eq!(config.sources[0].sync_wait_ms, 10_000);
}

#[test]
fn a_refused_send_while_waiting_does_not_end_the_resync() {
    struct Refuse;
    impl Hook for Refuse {
        fn check(&mut self, next: &Store) -> Result<(), String> {
            match next.get(&Key::Interface { name: "lan".into() }) {
                Some(_) => Err("no".into()),
                None => Ok(()),
            }
        }
        fn committed(&mut self, _store: &Store) {}
    }
    let mut fe = fe_with_old_entry();
    let mut confd = Confd::new(file::parse(&with_source(10)).unwrap());
    let (a, b) = UnixStream::pair().unwrap();
    fe.attach(a, &[sid::INTERFACE, sid::ADDRESS, sid::ICMP_ERRORS])
        .unwrap();
    confd.connect_fe(b).unwrap();
    let mut source = connect(&mut confd);
    let run = |fe: &mut Server, confd: &mut Confd, source: &mut Client| {
        for _ in 0..50 {
            fe.step(&mut Refuse);
            confd.step(1_000);
            source.poll();
        }
    };
    run(&mut fe, &mut confd, &mut source);
    assert!(confd.waiting_for_sources());
    source.sync_done();
    run(&mut fe, &mut confd, &mut source);
    assert!(!confd.waiting_for_sources());
    assert!(old_entry(&fe));
}
