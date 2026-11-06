//! Table server and client over real Unix socket pairs.

use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;

use ruster_proto::coap::Code;
use ruster_proto::session::{decode_changes, Client, Event, Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Change, Key, Value};

/// Refuses any store holding an interface named "bad"; records each commit.
#[derive(Default)]
struct TestHook {
    commits: usize,
}

impl Hook for TestHook {
    fn check(&mut self, next: &Store) -> Result<(), String> {
        if next.get(&iface_key("bad")).is_some() {
            return Err("bad interface".into());
        }
        Ok(())
    }

    fn committed(&mut self, _store: &Store) {
        self.commits += 1;
    }
}

fn iface_key(name: &str) -> Key {
    Key::Interface { name: name.into() }
}

fn iface(name: &str, last: u8) -> Change {
    Change::set(
        iface_key(name),
        Value::Interface {
            enabled: true,
            mac: [2, 0, 0, 0, 0, last],
            mtu: 1500,
        },
    )
}

fn neighbor(address: [u8; 4]) -> Change {
    Change::set(
        Key::Neighbor {
            interface: "eth0".into(),
            address: Ipv4Addr::from(address),
        },
        Value::Neighbor {
            mac: [2, 0, 0, 0, 1, 1],
        },
    )
}

struct Bench {
    server: Server,
    hook: TestHook,
}

impl Bench {
    fn new() -> Self {
        Self {
            server: Server::new(),
            hook: TestHook::default(),
        }
    }

    fn connect(&mut self, writes: &[u64]) -> Client {
        let (a, b) = UnixStream::pair().unwrap();
        self.server.attach(a, writes).unwrap();
        Client::new(b).unwrap()
    }

    /// Steps the server and client until quiet; returns the client's events.
    fn settle(&mut self, client: &mut Client) -> Vec<Event> {
        let mut events = Vec::new();
        for _ in 0..1_000 {
            let server = self.server.step(&mut self.hook);
            let (progress, mut got) = client.poll();
            events.append(&mut got);
            if !server.busy && !progress.busy {
                return events;
            }
        }
        panic!("never settled");
    }
}

fn response(events: &[Event], token: u32) -> (Code, Vec<u8>) {
    events
        .iter()
        .find_map(|event| match event {
            Event::Response {
                token: t,
                code,
                payload,
            } if *t == token => Some((*code, payload.clone())),
            _ => None,
        })
        .expect("response")
}

#[test]
fn patch_commits_and_get_returns_the_writers_entries() {
    let mut bench = Bench::new();
    let mut client = bench.connect(&[sid::INTERFACE]);
    let token = client.patch(&[iface("eth0", 1), iface("eth1", 2)]).unwrap();
    let events = bench.settle(&mut client);
    assert_eq!(response(&events, token).0, Code::CHANGED);
    assert_eq!(bench.server.store().len(), 2);
    assert_eq!(bench.hook.commits, 1);

    let token = client.get_all();
    let events = bench.settle(&mut client);
    let (code, payload) = response(&events, token);
    assert_eq!(code, Code::CONTENT);
    assert_eq!(decode_changes(&payload).unwrap().len(), 2);
}

#[test]
fn a_rejected_patch_changes_nothing() {
    let mut bench = Bench::new();
    let mut client = bench.connect(&[sid::INTERFACE]);
    let token = client.patch(&[iface("eth0", 1), iface("bad", 2)]).unwrap();
    let events = bench.settle(&mut client);
    let (code, payload) = response(&events, token);
    assert_eq!(code, Code::BAD_REQUEST);
    assert_eq!(payload, b"bad interface");
    assert!(bench.server.store().is_empty());
    assert_eq!(bench.hook.commits, 0);
}

#[test]
fn writing_another_writers_table_is_forbidden() {
    let mut bench = Bench::new();
    let mut client = bench.connect(&[sid::INTERFACE]);
    let token = client.patch(&[neighbor([10, 0, 0, 1])]).unwrap();
    let events = bench.settle(&mut client);
    assert_eq!(response(&events, token).0, Code::FORBIDDEN);
    assert!(bench.server.store().is_empty());
}

#[test]
fn resync_keeps_what_was_sent_again_and_only_this_writers_tables() {
    let mut bench = Bench::new();
    let mut ifaces = bench.connect(&[sid::INTERFACE]);
    let mut neighbors = bench.connect(&[sid::NEIGHBOR]);
    ifaces.patch(&[iface("eth0", 1), iface("old", 2)]).unwrap();
    bench.settle(&mut ifaces);
    neighbors.patch(&[neighbor([10, 0, 0, 1])]).unwrap();
    bench.settle(&mut neighbors);

    ifaces.resync_begin();
    ifaces.patch(&[iface("eth0", 1)]).unwrap();
    bench.settle(&mut ifaces);
    assert_eq!(
        bench.server.store().len(),
        3,
        "nothing is removed before the end"
    );
    let token = ifaces.resync_end();
    let events = bench.settle(&mut ifaces);
    assert_eq!(response(&events, token).0, Code::CHANGED);

    let store = bench.server.store();
    assert!(store.get(&iface_key("eth0")).is_some());
    assert!(store.get(&iface_key("old")).is_none());
    assert_eq!(store.len(), 2, "the neighbor writer's entry stays");
}

#[test]
fn tables_survive_a_writer_disconnecting() {
    let mut bench = Bench::new();
    let mut client = bench.connect(&[sid::INTERFACE]);
    client.patch(&[iface("eth0", 1)]).unwrap();
    bench.settle(&mut client);
    drop(client);
    for _ in 0..10 {
        bench.server.step(&mut bench.hook);
    }
    assert_eq!(bench.server.peers(), 0);
    assert_eq!(bench.server.store().len(), 1);
}

#[test]
fn observers_get_notifications() {
    let mut bench = Bench::new();
    let mut client = bench.connect(&[]);
    client.observe();
    bench.settle(&mut client);
    bench.server.notify(b"one");
    bench.server.notify(b"two");
    let events = bench.settle(&mut client);
    let got: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::Notification { payload } => Some(payload.as_slice()),
            Event::Response { .. } => None,
        })
        .collect();
    assert_eq!(got, [&b"one"[..], &b"two"[..]]);
}

#[test]
fn read_only_connections_cannot_write_or_resync() {
    let mut bench = Bench::new();
    let mut client = bench.connect(&[]);
    let patch = client.patch(&[iface("eth0", 1)]).unwrap();
    let resync = client.resync_begin();
    let events = bench.settle(&mut client);
    assert_eq!(response(&events, patch).0, Code::FORBIDDEN);
    assert_eq!(response(&events, resync).0, Code::NOT_FOUND);
}

#[test]
fn a_new_writer_for_the_same_tables_replaces_the_old_one() {
    let mut bench = Bench::new();
    let mut old = bench.connect(&[sid::INTERFACE]);
    old.patch(&[iface("eth0", 1)]).unwrap();
    bench.settle(&mut old);
    let mut new = bench.connect(&[sid::INTERFACE]);
    bench.settle(&mut new);
    assert_eq!(bench.server.peers(), 1, "the old writer is closed");
    for _ in 0..10 {
        old.poll();
    }
    assert!(old.is_closed());
    assert_eq!(bench.server.store().len(), 1, "its entries stay");
}

#[test]
fn empty_patch_from_a_read_only_connection_is_forbidden() {
    let mut bench = Bench::new();
    let mut client = bench.connect(&[]);
    let token = client.patch(&[]).unwrap();
    let events = bench.settle(&mut client);
    assert_eq!(response(&events, token).0, Code::FORBIDDEN);
    assert_eq!(bench.hook.commits, 0);
}

#[test]
fn a_peer_that_never_reads_does_not_grow_the_server_without_bound() {
    use ruster_proto::coap::{self, Code as C};
    use ruster_proto::conn::DEFAULT_LIMIT;
    use std::io::Write;

    let mut bench = Bench::new();
    let (server_end, raw) = UnixStream::pair().unwrap();
    bench.server.attach(server_end, &[]).unwrap();
    raw.set_nonblocking(true).unwrap();
    // Fill the store so every GET reply is large.
    let mut writer = bench.connect(&[sid::INTERFACE]);
    let many: Vec<Change> = (0..200)
        .map(|n| iface(&format!("if{n}"), n as u8))
        .collect();
    writer.patch(&many).unwrap();
    bench.settle(&mut writer);

    // Send many GETs and never read the replies.
    let mut get = Vec::new();
    coap::encode(&mut get, C::GET, &[1], &[(11, b"c")], &[]).unwrap();
    let mut requests = Vec::new();
    for _ in 0..20_000 {
        requests.extend_from_slice(&get);
    }
    let mut sent = 0;
    for _ in 0..2_000 {
        if sent < requests.len() {
            if let Ok(n) = (&raw).write(&requests[sent..]) {
                sent += n;
            }
        }
        bench.server.step(&mut bench.hook);
        // At most one reply is queued past the limit.
        assert!(bench.server.max_backlog() <= DEFAULT_LIMIT + 64 * 1024);
    }
    // Each queued reply is a few KiB; without backpressure 20 000 of them would be
    // tens of MiB. The test only checks the server stays alive and responsive.
    let token = writer.get_all();
    let events = bench.settle(&mut writer);
    assert_eq!(response(&events, token).0, Code::CONTENT);
}

#[test]
fn flooding_peer_is_read_no_further_than_the_message_limit() {
    use ruster_proto::conn::{Connection, DEFAULT_LIMIT};
    use std::io::Write;

    let (a, b) = UnixStream::pair().unwrap();
    let mut conn = Connection::new(a, DEFAULT_LIMIT).unwrap();
    b.set_nonblocking(true).unwrap();
    // 2-byte empty messages (code 0.00), about 40 MiB in total.
    let chunk = [0x00_u8, 0x00].repeat(32 * 1024);
    let mut written = 0_usize;
    for _ in 0..4_000 {
        if let Ok(n) = (&b).write(&chunk) {
            written += n;
        }
        let _ = conn.pump();
        assert!(conn.buffered_in() <= DEFAULT_LIMIT + 64 * 1024);
    }
    assert!(written > 0);
}

#[test]
fn a_replaced_writers_buffered_requests_are_not_handled() {
    let mut bench = Bench::new();
    let mut old = bench.connect(&[sid::INTERFACE]);
    old.patch(&[iface("eth0", 1)]).unwrap();
    bench.settle(&mut old);
    // The old writer sends a change but the server has not read it yet.
    old.patch(&[iface("stale", 9)]).unwrap();
    for _ in 0..5 {
        old.poll();
    }
    let mut new = bench.connect(&[sid::INTERFACE]);
    bench.settle(&mut new);
    for _ in 0..10 {
        bench.server.step(&mut bench.hook);
    }
    assert!(bench.server.store().get(&iface_key("stale")).is_none());
}

#[test]
fn sync_done_is_remembered() {
    let mut bench = Bench::new();
    let mut client = bench.connect(&[sid::ROUTE]);
    assert!(!bench.server.sync_done());
    let token = client.sync_done();
    let events = bench.settle(&mut client);
    assert_eq!(response(&events, token).0, Code::CHANGED);
    assert!(bench.server.sync_done());
}
