//! The FPM end over real TCP: routes in, the resync after zebra connects again, the
//! hold time, bad frames and the owner check.

use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream};

use ruster_config::Connected;
use ruster_frr::server::{owner_in, socket_owner, Fpm, HOLD_MS, QUIET_MS};
use ruster_proto::table::{Change, Key};

fn connected() -> Vec<Connected> {
    vec![Connected {
        interface: "wan".into(),
        prefix: "198.51.100.0/24".into(),
        link_local: "fe80::1".into(),
    }]
}

/// One frame with RTM_NEWROUTE (or RTM_DELROUTE) for 10.<n>.0.0/16 via
/// 198.51.100.10.
fn frame(n: u8, new: bool) -> Vec<u8> {
    let attr = |kind: u16, value: &[u8]| {
        let mut out = ((4 + value.len()) as u16).to_ne_bytes().to_vec();
        out.extend(kind.to_ne_bytes());
        out.extend(value);
        out
    };
    let mut body = vec![2, 16, 0, 0, 254, 186, 0, 1, 0, 0, 0, 0];
    body.extend(attr(1, &[10, n, 0, 0]));
    body.extend(attr(5, &[198, 51, 100, 10]));
    let mut message = ((16 + body.len()) as u32).to_ne_bytes().to_vec();
    message.extend(if new { 24u16 } else { 25 }.to_ne_bytes());
    message.extend([0; 10]);
    message.extend(body);
    let mut out = vec![1, 1];
    out.extend(((4 + message.len()) as u16).to_be_bytes());
    out.extend(message);
    out
}

fn key(n: u8) -> Key {
    Key::Route {
        vrf: "default".into(),
        prefix: IpAddr::from([10, n, 0, 0]),
        len: 16,
    }
}

/// Steps until a change comes or `tries` run out.
fn changes(fpm: &mut Fpm, now: u64) -> Vec<Change> {
    let mut out = Vec::new();
    for _ in 0..200 {
        let (more, _, _) = fpm.step(now);
        out.extend(more);
        if !out.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    out
}

fn connect(fpm: &Fpm) -> TcpStream {
    TcpStream::connect(fpm.local_addr().unwrap()).unwrap()
}

#[test]
fn routes_come_in_and_stale_ones_are_swept() {
    let mut fpm = Fpm::bind(0, None).unwrap();
    fpm.set_connected(&connected());
    assert!(!fpm.ready());
    let mut zebra = connect(&fpm);
    // Split across writes: the frame is taken once whole.
    let both = [frame(1, true), frame(2, true)].concat();
    zebra.write_all(&both[..10]).unwrap();
    zebra.write_all(&both[10..]).unwrap();
    let got = changes(&mut fpm, 0);
    let mut keys: Vec<Key> = got.iter().map(|c| c.key.clone()).collect();
    if keys.len() == 1 {
        keys.extend(changes(&mut fpm, 0).into_iter().map(|c| c.key));
    }
    assert_eq!(keys, [key(1), key(2)]);
    assert!(fpm.connected() && !fpm.ready());
    assert!(fpm.step(QUIET_MS).0.is_empty(), "nothing stale");
    assert!(fpm.ready());

    // zebra connects again and sends only 10.1/16: 10.2/16 goes once it is quiet.
    let mut again = connect(&fpm);
    again.write_all(&frame(1, true)).unwrap();
    for _ in 0..200 {
        fpm.step(QUIET_MS + 10);
        if fpm.connected() && fpm.routes().len() == 2 {
            break;
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(fpm.step(QUIET_MS + 20).0.is_empty());
    let swept = fpm.step(2 * QUIET_MS + 100).0;
    assert_eq!(swept, [Change::delete(key(2))]);
    drop(zebra);
    // A delete, then zebra goes away: the routes stay for the hold time.
    again.write_all(&frame(1, false)).unwrap();
    assert_eq!(changes(&mut fpm, 10_000), [Change::delete(key(1))]);
    again.write_all(&frame(3, true)).unwrap();
    assert_eq!(changes(&mut fpm, 10_000).len(), 1);
    drop(again);
    for _ in 0..200 {
        fpm.step(10_000);
        if !fpm.connected() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(!fpm.connected());
    assert!(fpm.step(10_000 + HOLD_MS - 1).0.is_empty());
    assert_eq!(fpm.step(10_000 + HOLD_MS).0, [Change::delete(key(3))]);
}

#[test]
fn a_bad_frame_ends_the_connection_and_bad_messages_are_passed_over() {
    let mut fpm = Fpm::bind(0, None).unwrap();
    fpm.set_connected(&connected());
    let mut zebra = connect(&fpm);
    // A message too short for a route, then a good one in the next frame.
    let mut short = vec![1, 1, 0, 24];
    short.extend(20u32.to_ne_bytes());
    short.extend([24, 0, 0, 0]);
    short.extend([0; 12]);
    zebra.write_all(&short).unwrap();
    zebra.write_all(&frame(1, true)).unwrap();
    assert_eq!(changes(&mut fpm, 0).len(), 1);
    zebra.write_all(&[2, 1, 0, 4]).unwrap();
    for _ in 0..200 {
        fpm.step(0);
        if !fpm.connected() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(!fpm.connected(), "version 2 ends it");
}

#[test]
fn without_zebra_it_is_ready_after_the_hold_time() {
    let mut fpm = Fpm::bind(0, None).unwrap();
    fpm.step(5);
    assert!(!fpm.ready());
    fpm.step(5 + HOLD_MS);
    assert!(fpm.ready());
}

fn own_uid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("Uid:")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[test]
fn the_owner_is_read_from_proc_net_tcp() {
    let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0A3C 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n   1: 0100007F:D4A3 0100007F:0A3C 01 00000000:00000000 00:00000000 00000000   999        0 2 1\n";
    let local: SocketAddr = "127.0.0.1:2620".parse().unwrap();
    let peer: SocketAddr = "127.0.0.1:54435".parse().unwrap();
    assert_eq!(owner_in(table, peer, local), Some(999));
    assert_eq!(owner_in(table, local, peer), None);
    // A real connection of this process.
    let mut fpm = Fpm::bind(0, Some(own_uid())).unwrap();
    let zebra = connect(&fpm);
    assert_eq!(
        socket_owner(zebra.local_addr().unwrap(), fpm.local_addr().unwrap()),
        Some(own_uid())
    );
    for _ in 0..200 {
        fpm.step(0);
        if fpm.connected() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(fpm.connected());
    let mut other = Fpm::bind(0, Some(own_uid() + 1)).unwrap();
    let _zebra = connect(&other);
    for _ in 0..50 {
        other.step(0);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(!other.connected(), "another user's socket is refused");
}
