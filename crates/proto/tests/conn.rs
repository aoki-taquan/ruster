//! Connection tests over real Unix socket pairs.

use std::io::Write;
use std::os::unix::net::UnixStream;

use ruster_proto::coap::{self, Code};
use ruster_proto::conn::{ConnError, Connection, Incoming, Outgoing, DEFAULT_LIMIT};
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
    assert!(receive(&mut b).is_none());
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
