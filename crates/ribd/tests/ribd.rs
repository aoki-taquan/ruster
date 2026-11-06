//! ribd against a stand-in FE (a plain table server) over Unix sockets.

use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;

use ruster_proto::session::{Client, Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Change, Key, NextHop, RouteAction, Value};
use ruster_proto::task::Task;
use ruster_ribd::{Ribd, SourceSpec};

struct Accept;

impl Hook for Accept {
    fn check(&mut self, _next: &Store) -> Result<(), String> {
        Ok(())
    }
    fn committed(&mut self, _store: &Store) {}
}

fn key(prefix: [u8; 4], len: u8) -> Key {
    Key::Route {
        vrf: "default".into(),
        prefix: Ipv4Addr::from(prefix),
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
}

impl Lab {
    fn new(fe: Server, specs: Vec<SourceSpec>) -> Self {
        let mut lab = Self {
            fe,
            ribd: Ribd::new(UnixStream::pair().unwrap().0, vec![]).unwrap(),
            sources: Vec::new(),
            now: 0,
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
            let mut busy = self.fe.step(&mut Accept).busy;
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
