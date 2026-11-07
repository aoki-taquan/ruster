//! ribd against a stand-in FE (a plain table server) over Unix sockets.

use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;

use ruster_proto::session::{Client, Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Change, Key, NextHop, RouteAction, Value};
use ruster_proto::task::Task;
use ruster_ribd::{Ribd, SourceSpec};

/// A stand-in FE check: refuses any table with a route through `refuse`.
struct Check<'a> {
    refuse: Option<&'a str>,
}

impl Hook for Check<'_> {
    fn check(&mut self, next: &Store) -> Result<(), String> {
        let bad = self.refuse.is_some_and(|refuse| {
            next.iter().any(|(_, value)| {
                matches!(value, Value::Route(RouteAction::Forward(hops))
                    if hops.iter().any(|hop| hop.interface == refuse))
            })
        });
        if bad {
            Err("refused".into())
        } else {
            Ok(())
        }
    }
    fn committed(&mut self, _store: &Store) {}
}

fn key(prefix: [u8; 4], len: u8) -> Key {
    Key::Route {
        vrf: "default".into(),
        prefix: Ipv4Addr::from(prefix).into(),
        len,
    }
}

fn via(interface: &str) -> Value {
    Value::Route(RouteAction::Forward(vec![NextHop {
        interface: interface.into(),
        address: None,
    }]))
}

fn route(prefix: [u8; 4], len: u8, interface: &str) -> Change {
    Change::set(key(prefix, len), via(interface))
}

fn spec(name: &str, preference: u32) -> SourceSpec {
    SourceSpec {
        name: name.into(),
        preference,
        hold_ms: 5_000,
    }
}

struct Lab {
    fe: Server,
    ribd: Ribd,
    sources: Vec<Client>,
    now: u64,
    refuse: Option<&'static str>,
}

impl Lab {
    fn new(fe: Server, specs: Vec<SourceSpec>) -> Self {
        let mut lab = Self {
            fe,
            ribd: Ribd::new(UnixStream::pair().unwrap().0, vec![]).unwrap(),
            sources: Vec::new(),
            now: 0,
            refuse: None,
        };
        lab.restart(specs);
        lab
    }

    /// Starts a fresh ribd connected to the FE, with a client per source.
    fn restart(&mut self, specs: Vec<SourceSpec>) {
        let (a, b) = UnixStream::pair().unwrap();
        self.fe.attach(a, &[sid::ROUTE]).unwrap();
        self.ribd = Ribd::new(b, specs.clone()).unwrap();
        self.sources.clear();
        for spec in &specs {
            let (a, b) = UnixStream::pair().unwrap();
            self.ribd.attach_source(&spec.name, a).unwrap();
            self.sources.push(Client::new(b).unwrap());
        }
        self.settle();
    }

    fn settle(&mut self) {
        for _ in 0..1_000 {
            let mut check = Check {
                refuse: self.refuse,
            };
            let mut busy = self.fe.step(&mut check).busy;
            busy |= self.ribd.step(self.now).busy;
            for source in &mut self.sources {
                busy |= source.poll().0.busy;
            }
            if !busy {
                return;
            }
        }
        panic!("never settled");
    }

    fn fe_route(&self, prefix: [u8; 4], len: u8) -> Option<&Value> {
        self.fe.store().get(&key(prefix, len))
    }
}

#[test]
fn routes_reach_the_fe_and_the_better_source_wins() {
    let mut lab = Lab::new(Server::new(), vec![spec("static", 1), spec("dhcp", 50)]);
    lab.sources[1]
        .patch(&[route([0, 0, 0, 0], 0, "wan-dhcp")])
        .unwrap();
    lab.settle();
    assert_eq!(lab.fe_route([0, 0, 0, 0], 0), Some(&via("wan-dhcp")));

    lab.sources[0]
        .patch(&[
            route([0, 0, 0, 0], 0, "wan-static"),
            route([10, 0, 0, 0], 8, "lan"),
        ])
        .unwrap();
    lab.settle();
    assert_eq!(lab.fe_route([0, 0, 0, 0], 0), Some(&via("wan-static")));
    assert_eq!(lab.fe_route([10, 0, 0, 0], 8), Some(&via("lan")));

    // Withdrawing the better route falls back to the other source.
    lab.sources[0]
        .patch(&[Change::delete(key([0, 0, 0, 0], 0))])
        .unwrap();
    lab.settle();
    assert_eq!(lab.fe_route([0, 0, 0, 0], 0), Some(&via("wan-dhcp")));

    // Withdrawn everywhere: deleted from the FE.
    lab.sources[0]
        .patch(&[Change::delete(key([10, 0, 0, 0], 8))])
        .unwrap();
    lab.settle();
    assert_eq!(lab.fe_route([10, 0, 0, 0], 8), None);
}

#[test]
fn a_restarted_ribd_keeps_fe_routes_until_its_sources_are_done() {
    let mut lab = Lab::new(Server::new(), vec![spec("static", 1)]);
    lab.sources[0]
        .patch(&[
            route([0, 0, 0, 0], 0, "wan"),
            route([10, 0, 0, 0], 8, "lan"),
        ])
        .unwrap();
    lab.sources[0].sync_done();
    lab.settle();
    assert!(lab.ribd.synced());

    lab.now = 100;
    lab.restart(vec![spec("static", 1)]);
    assert!(!lab.ribd.synced());
    assert_eq!(lab.fe.store().len(), 2, "kept while waiting");

    // The source sends only the default route this time, then says it is done.
    lab.sources[0]
        .patch(&[route([0, 0, 0, 0], 0, "wan")])
        .unwrap();
    lab.settle();
    assert_eq!(lab.fe.store().len(), 2, "still waiting for sync-done");
    lab.sources[0].sync_done();
    lab.settle();
    assert!(lab.ribd.synced());
    assert!(lab.fe_route([0, 0, 0, 0], 0).is_some());
    assert!(
        lab.fe_route([10, 0, 0, 0], 8).is_none(),
        "not sent again, removed"
    );
}

#[test]
fn a_silent_source_is_waited_for_only_until_its_hold_time() {
    let mut lab = Lab::new(Server::new(), vec![spec("static", 1)]);
    lab.sources[0]
        .patch(&[route([10, 0, 0, 0], 8, "lan")])
        .unwrap();
    lab.sources[0].sync_done();
    lab.settle();

    lab.restart(vec![spec("static", 1)]);
    lab.now = 4_999;
    lab.settle();
    assert_eq!(lab.fe.store().len(), 1);
    lab.now = 5_000;
    lab.settle();
    assert!(lab.ribd.synced());
    assert!(lab.fe.store().is_empty());
}

#[test]
fn a_refused_full_send_after_a_restart_does_not_delete_the_fe_routes() {
    let mut lab = Lab::new(Server::new(), vec![spec("static", 1)]);
    lab.sources[0]
        .patch(&[
            route([0, 0, 0, 0], 0, "wan"),
            route([10, 0, 0, 0], 8, "lan"),
            route([192, 168, 0, 0], 16, "old"),
        ])
        .unwrap();
    lab.sources[0].sync_done();
    lab.settle();
    assert_eq!(lab.fe.store().len(), 3);

    // The restarted ribd's source no longer has the old route, and has one the FE
    // refuses.
    lab.refuse = Some("bad");
    lab.restart(vec![spec("static", 1)]);
    lab.sources[0]
        .patch(&[
            route([0, 0, 0, 0], 0, "wan"),
            route([10, 0, 0, 0], 8, "lan"),
            route([172, 16, 0, 0], 12, "bad"),
        ])
        .unwrap();
    lab.sources[0].sync_done();
    lab.settle();
    lab.now = 10_000;
    lab.settle();
    assert_eq!(lab.ribd.counters().patches_refused, 1);
    assert_eq!(lab.fe_route([0, 0, 0, 0], 0), Some(&via("wan")), "kept");
    assert_eq!(lab.fe_route([10, 0, 0, 0], 8), Some(&via("lan")), "kept");
    assert!(
        lab.fe_route([192, 168, 0, 0], 16).is_some(),
        "kept until a full send is accepted"
    );

    // Once the source drops the bad route, ribd sends again and finishes the resync.
    lab.sources[0]
        .patch(&[Change::delete(key([172, 16, 0, 0], 12))])
        .unwrap();
    lab.settle();
    assert_eq!(lab.fe_route([0, 0, 0, 0], 0), Some(&via("wan")));
    assert_eq!(lab.fe_route([192, 168, 0, 0], 16), None, "the resync ended");
    assert_eq!(lab.fe.store().len(), 2);
}

#[test]
fn a_change_refused_in_steady_state_is_cleaned_up_by_the_next_one() {
    let mut lab = Lab::new(Server::new(), vec![spec("static", 1)]);
    lab.sources[0]
        .patch(&[
            route([10, 0, 0, 0], 8, "lan"),
            route([192, 168, 0, 0], 16, "lan"),
        ])
        .unwrap();
    lab.sources[0].sync_done();
    lab.settle();
    // Refused: adds a bad route and removes 192.168/16.
    lab.refuse = Some("bad");
    lab.sources[0]
        .patch(&[
            route([172, 16, 0, 0], 12, "bad"),
            Change::delete(key([192, 168, 0, 0], 16)),
        ])
        .unwrap();
    lab.settle();
    assert!(
        lab.fe_route([192, 168, 0, 0], 16).is_some(),
        "refused, so still there"
    );
    lab.refuse = None;
    lab.sources[0]
        .patch(&[Change::delete(key([172, 16, 0, 0], 12))])
        .unwrap();
    lab.settle();
    assert_eq!(lab.fe_route([192, 168, 0, 0], 16), None);
    assert_eq!(lab.fe.store().len(), 1);
}

#[test]
fn a_refused_change_is_sent_again_with_the_next_one() {
    let mut lab = Lab::new(Server::new(), vec![spec("static", 1)]);
    lab.sources[0].sync_done();
    lab.settle();
    lab.refuse = Some("bad");
    lab.sources[0]
        .patch(&[route([172, 16, 0, 0], 12, "bad")])
        .unwrap();
    lab.settle();
    assert!(lab.fe.store().is_empty());
    lab.refuse = None;
    lab.sources[0]
        .patch(&[route([10, 0, 0, 0], 8, "lan")])
        .unwrap();
    lab.settle();
    assert_eq!(
        lab.fe.store().len(),
        2,
        "the earlier route went with the next change"
    );
}
