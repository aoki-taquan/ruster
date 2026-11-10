//! What the client writes to confd and ribd.

use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;

use ruster_pppoed::session::SessionUp;
use ruster_pppoed::writer::{default_route, source_values, Writer, LIFETIME, REFRESH_MS};
use ruster_proto::session::{Client, Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Change, Key, NextHop, RouteAction, Value};

#[derive(Default)]
struct Count(usize);

impl Hook for Count {
    fn check(&mut self, _next: &Store) -> Result<(), String> {
        Ok(())
    }
    fn committed(&mut self, _store: &Store) {}
    fn patched(&mut self, _changes: &[Change]) {
        self.0 += 1;
    }
}

fn up(ipv4: Option<Ipv4Addr>) -> SessionUp {
    SessionUp {
        session_id: 4660,
        ac: [2, 0, 0, 0, 0, 0xac],
        mtu: 1492,
        ipv4,
        peer_ipv4: None,
        dns: Vec::new(),
        ipv6_local_id: None,
        ipv6_peer_id: None,
    }
}

fn run(server: &mut Server, writer: &mut Writer, hook: &mut Count, now: u64) {
    for _ in 0..30 {
        server.step(hook);
        writer.step(now);
    }
}

#[test]
fn a_session_is_written_with_lifetimes_and_sent_again() {
    let mut server = Server::new();
    let (a, b) = UnixStream::pair().unwrap();
    server
        .attach(a, &[sid::SOURCE_PPPOE, sid::SOURCE_IPV4])
        .unwrap();
    let mut writer = Writer::new("/nonexistent".into(), Some(REFRESH_MS));
    let session = up(Some(Ipv4Addr::new(198, 51, 100, 2)));
    writer.set(source_values("pppoe-wan", Some(&session)));
    writer.attach(Client::new(b).unwrap(), 0);
    let mut hook = Count::default();
    run(&mut server, &mut writer, &mut hook, 0);
    assert!(server.sync_done());
    assert_eq!(
        server.store().get(&Key::SourcePppoe {
            source: "pppoe-wan".into()
        }),
        Some(&Value::SourcePppoe {
            session: 4660,
            peer: [2, 0, 0, 0, 0, 0xac],
            mtu: 1492,
            lifetime: LIFETIME,
        })
    );
    let first = hook.0;
    // The same values again change nothing; time does.
    writer.set(source_values("pppoe-wan", Some(&session)));
    run(&mut server, &mut writer, &mut hook, REFRESH_MS - 1);
    assert_eq!(hook.0, first);
    run(&mut server, &mut writer, &mut hook, REFRESH_MS);
    assert_eq!(hook.0, first + 1);
    // Down: both go.
    writer.set(source_values("pppoe-wan", None));
    run(&mut server, &mut writer, &mut hook, REFRESH_MS);
    assert!(server.store().is_empty());
    assert!(u64::from(LIFETIME) * 1_000 > 2 * REFRESH_MS);
}

#[test]
fn a_session_without_an_address_has_no_address_or_route() {
    let changes = source_values("s", Some(&up(None)));
    assert!(changes[1].value.is_none());
    assert!(default_route("default", "ppp", Some(&up(None)))
        .value
        .is_none());
    assert_eq!(
        default_route(
            "default",
            "ppp",
            Some(&up(Some(Ipv4Addr::new(198, 51, 100, 2))))
        )
        .value,
        Some(Value::Route(RouteAction::Forward(vec![NextHop {
            interface: "ppp".into(),
            address: None
        }])))
    );
}
