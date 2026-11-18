//! Connection tests over real Unix socket pairs.

use std::io::Write;
use std::os::unix::net::UnixStream;

use ruster_proto::coap::{self, Code};
use ruster_proto::conn::{
    ConnError, Connection, Incoming, Outgoing, DEFAULT_LIMIT, PROTOCOL_VERSION,
};
use ruster_proto::task::{run_until_idle, Progress, Task};

fn pair() -> (Connection, Connection) {
    let (a, b) = UnixStream::pair().unwrap();
    (
        Connection::new(a, DEFAULT_LIMIT).unwrap(),
        Connection::new(b, DEFAULT_LIMIT).unwrap(),
    )
}

/// Pumps both ends until nothing moves.
fn settle(a: &mut Connection, b: &mut Connection) {
    for _ in 0..1_000 {
        let moved = a.pump().unwrap() | b.pump().unwrap();
        if !moved {
            return;
        }
    }
    panic!("connections never settled");
}

fn receive(conn: &mut Connection) -> Option<Incoming> {
    conn.next_message().unwrap()
}

#[test]
fn csm_is_exchanged_and_requests_arrive_whole() {
    let (mut a, mut b) = pair();
    a.send(&Outgoing {
        code: Some(Code::IPATCH),
        token: &[7],
        path: &["c"],
        payload: b"body",
        ..Outgoing::default()
    })
    .unwrap();
    settle(&mut a, &mut b);
    let got = receive(&mut b).unwrap();
    assert_eq!(got.code, Code::IPATCH);
    assert_eq!(got.token, [7]);
    assert_eq!(got.path, ["c"]);
    assert_eq!(got.payload, b"body");
    assert_eq!(b.peer_limit(), Some(DEFAULT_LIMIT));
    assert_eq!(b.peer_version(), Some(PROTOCOL_VERSION));
    assert!(receive(&mut b).is_none());
}

/// Writes a CSM by hand to `raw`, with `version` when given.
fn raw_csm(raw: &mut UnixStream, version: Option<u32>) {
    let mut size = [0; 4];
    let size = coap::uint_option(1024, &mut size);
    let mut number = [0; 4];
    let mut options = vec![(coap::option::MAX_MESSAGE_SIZE, size)];
    if let Some(version) = version {
        options.push((
            coap::option::PROTOCOL_VERSION,
            coap::uint_option(version, &mut number),
        ));
    }
    let mut out = Vec::new();
    coap::encode(&mut out, Code::CSM, &[], &options, &[]).unwrap();
    raw.write_all(&out).unwrap();
}

/// Reads every message `raw` has been sent, in order.
fn raw_messages(raw: &mut UnixStream) -> Vec<(Code, Vec<u8>)> {
    use std::io::Read;
    raw.set_nonblocking(true).unwrap();
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        match raw.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    let mut out = Vec::new();
    let mut at = 0;
    while let Ok(coap::Decoded::Message(message, used)) = coap::decode(&bytes[at..], DEFAULT_LIMIT)
    {
        out.push((message.code, message.payload.to_vec()));
        at += used;
    }
    out
}

#[test]
fn a_peer_of_another_protocol_version_is_sent_an_abort_and_closed() {
    let (a, mut raw) = UnixStream::pair().unwrap();
    let mut conn = Connection::new(a, DEFAULT_LIMIT).unwrap();
    raw_csm(&mut raw, Some(PROTOCOL_VERSION + 1));
    conn.pump().unwrap();
    assert!(receive(&mut conn).is_none());
    assert!(conn.is_closed());
    assert_eq!(conn.peer_version(), Some(PROTOCOL_VERSION + 1));
    let got = raw_messages(&mut raw);
    assert_eq!(got[0].0, Code::CSM);
    let (code, payload) = got.last().unwrap();
    assert_eq!(*code, Code::ABORT);
    let reason = String::from_utf8_lossy(payload);
    assert!(
        reason.contains(&format!(
            "version {} from the peer, {PROTOCOL_VERSION} here",
            PROTOCOL_VERSION + 1
        )),
        "{reason}"
    );
}

#[test]
fn a_peer_without_a_protocol_version_is_taken() {
    let (a, mut raw) = UnixStream::pair().unwrap();
    let mut conn = Connection::new(a, DEFAULT_LIMIT).unwrap();
    raw_csm(&mut raw, None);
    conn.pump().unwrap();
    assert!(receive(&mut conn).is_none());
    assert!(!conn.is_closed());
    assert_eq!(conn.peer_version(), None);
    assert_eq!(conn.peer_limit(), Some(1024));
}

#[test]
fn an_abort_closes_the_connection() {
    let (mut a, mut b) = pair();
    settle(&mut a, &mut b);
    a.send(&Outgoing {
        code: Some(Code::ABORT),
        payload: b"why",
        ..Outgoing::default()
    })
    .unwrap();
    settle(&mut a, &mut b);
    assert!(receive(&mut b).is_none());
    assert!(b.is_closed());
}

#[test]
fn observe_option_and_several_messages_in_order() {
    let (mut a, mut b) = pair();
    for n in 0..5_u8 {
        a.send(&Outgoing {
            code: Some(Code::CONTENT),
            token: &[1],
            observe: Some(u32::from(n)),
            payload: &[n],
            ..Outgoing::default()
        })
        .unwrap();
    }
    settle(&mut a, &mut b);
    for n in 0..5_u8 {
        let got = receive(&mut b).unwrap();
        assert_eq!(got.observe, Some(u32::from(n)));
        assert_eq!(got.payload, [n]);
    }
}

#[test]
fn large_payload_crosses_several_pumps() {
    let (mut a, mut b) = pair();
    let payload = vec![0xa5; 1_000_000];
    a.send(&Outgoing {
        code: Some(Code::IPATCH),
        token: &[],
        payload: &payload,
        ..Outgoing::default()
    })
    .unwrap();
    settle(&mut a, &mut b);
    let got = receive(&mut b).unwrap();
    assert_eq!(got.payload.len(), payload.len());
    assert!(a.flushed());
}

#[test]
fn ping_is_answered_with_pong() {
    let (mut a, mut b) = pair();
    a.send(&Outgoing {
        code: Some(Code::PING),
        token: &[9],
        ..Outgoing::default()
    })
    .unwrap();
    settle(&mut a, &mut b);
    assert!(receive(&mut b).is_none(), "signaling is not handed out");
    settle(&mut a, &mut b);
    assert!(receive(&mut a).is_none(), "the Pong is handled too");
}

#[test]
fn peer_close_is_seen() {
    let (mut a, b) = pair();
    drop(b);
    for _ in 0..10 {
        let _ = a.pump();
    }
    assert!(a.is_closed());
}

#[test]
fn garbage_closes_the_connection() {
    let (raw, other) = UnixStream::pair().unwrap();
    let mut conn = Connection::new(other, DEFAULT_LIMIT).unwrap();
    // TKL 9 is reserved.
    (&raw).write_all(&[0x09, 0x01]).unwrap();
    conn.pump().unwrap();
    assert!(matches!(conn.next_message(), Err(ConnError::Frame(_))));
    assert!(conn.is_closed());
}

#[test]
fn oversized_message_is_refused() {
    let (raw, other) = UnixStream::pair().unwrap();
    let mut conn = Connection::new(other, 64).unwrap();
    let mut big = Vec::new();
    coap::encode(&mut big, Code::IPATCH, &[], &[], &[0; 100]).unwrap();
    (&raw).write_all(&big).unwrap();
    conn.pump().unwrap();
    assert!(matches!(conn.next_message(), Err(ConnError::Frame(_))));
}

struct Counter {
    left: u32,
}

impl Task for Counter {
    fn step(&mut self, _now_ms: u64) -> Progress {
        if self.left == 0 {
            return Progress::IDLE;
        }
        self.left -= 1;
        Progress::busy(true)
    }
}

#[test]
fn runner_steps_until_idle_or_gives_up() {
    let mut a = Counter { left: 3 };
    let mut b = Counter { left: 1 };
    assert_eq!(run_until_idle(&mut [&mut a, &mut b], 0, 10), Some(4));
    let mut c = Counter { left: 100 };
    assert_eq!(run_until_idle(&mut [&mut c], 0, 10), None);
    let merged = Progress {
        busy: false,
        wake_at: Some(5),
    }
    .and(Progress {
        busy: true,
        wake_at: Some(3),
    });
    assert_eq!(
        merged,
        Progress {
            busy: true,
            wake_at: Some(3)
        }
    );
}
