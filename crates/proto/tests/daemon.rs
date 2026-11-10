//! Listening and connecting in the socket directory.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use ruster_proto::daemon;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ruster-daemon-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    dir
}

#[test]
fn a_listener_replaces_a_socket_left_by_an_earlier_run() {
    let dir = dir("stale");
    let path = dir.join("x.sock");
    drop(daemon::listen(&path).unwrap());
    assert!(path.exists(), "the file stays after the listener is gone");
    let listener = daemon::listen(&path).unwrap();
    let mut client = daemon::connect(&path, Duration::ZERO).unwrap();
    client.write_all(b"hi").unwrap();
    let mut accepted = daemon::accept(&listener);
    assert_eq!(accepted.len(), 1);
    let mut buf = [0_u8; 2];
    accepted[0].read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hi");
    assert!(daemon::accept(&listener).is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_listener_stops_while_another_process_holds_the_path() {
    let dir = dir("running");
    for name in ["confd.sock", "punt.sock"] {
        let path = dir.join(name);
        // Another process's lock: a separate open of the same file.
        let other = std::fs::File::create(dir.join(format!("{name}.lock"))).unwrap();
        other.lock().unwrap();
        let error = match name {
            "confd.sock" => daemon::listen(&path).map(drop).unwrap_err(),
            _ => daemon::bind_datagram(&path).map(drop).unwrap_err(),
        };
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        drop(other);
        drop(daemon::bind_datagram(&path).unwrap());
        // Binding again in the same process keeps the lock it holds.
        drop(daemon::bind_datagram(&path).unwrap());
    }
}

#[test]
fn a_listener_does_not_remove_a_file_that_is_not_a_socket() {
    let dir = dir("file");
    let path = dir.join("x.sock");
    std::fs::write(&path, b"keep").unwrap();
    assert!(daemon::listen(&path).is_err());
    assert!(daemon::bind_datagram(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"keep");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn connect_waits_for_a_listener_that_comes_up_later() {
    let dir = dir("later");
    let path = dir.join("x.sock");
    let late = path.clone();
    let server = thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        daemon::listen(&late).unwrap()
    });
    assert!(daemon::connect(&path, Duration::from_secs(5)).is_ok());
    drop(server.join().unwrap());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn connect_gives_up_after_the_wait() {
    let dir = dir("never");
    let error = daemon::connect(&dir.join("x.sock"), Duration::from_millis(100)).unwrap_err();
    assert!(error.to_string().contains("x.sock"), "{error}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn run_dir_is_taken_from_the_arguments() {
    let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let (dir, rest) = daemon::run_dir_and_rest(args(&["a", "--run-dir", "/tmp/x", "b"])).unwrap();
    assert_eq!(dir, PathBuf::from("/tmp/x"));
    assert_eq!(rest, args(&["a", "b"]));
    let (dir, _) = daemon::run_dir_and_rest(args(&[])).unwrap();
    assert_eq!(dir, PathBuf::from(daemon::DEFAULT_RUN_DIR));
    assert!(daemon::run_dir_and_rest(args(&["--run-dir"])).is_err());
}

#[test]
fn a_listener_creates_the_directories_above_its_socket() {
    let dir = dir("nested");
    let path = dir.join(daemon::socket::FE_PUNT);
    drop(daemon::bind_datagram(&path).unwrap());
    assert!(path.exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn notify_sends_the_state_to_the_notify_socket() {
    let dir = dir("notify");
    let path = dir.join("notify.sock");
    let systemd = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
    systemd.set_nonblocking(true).unwrap();
    // The only test that sets the variable; others never read it.
    std::env::set_var("NOTIFY_SOCKET", &path);
    daemon::notify("READY=1");
    std::env::remove_var("NOTIFY_SOCKET");
    let mut buf = [0_u8; 32];
    let n = systemd.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"READY=1");
    // Without the variable nothing is sent.
    daemon::notify("READY=1");
    assert!(systemd.recv(&mut buf).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn an_idle_process_sleeps_longer_until_it_has_work() {
    use ruster_proto::task::Progress;
    let mut idle = daemon::Idle::new();
    let quiet = Progress {
        busy: false,
        ..Progress::default()
    };
    let busy = Progress {
        busy: true,
        ..Progress::default()
    };
    let mut waits = Vec::new();
    for _ in 0..5 {
        waits.push(idle.next_ms());
        idle.wait(quiet);
    }
    assert_eq!(waits, [1, 2, 4, 8, 8]);
    idle.wait(busy);
    assert_eq!(idle.next_ms(), 1, "work starts over from 1 ms");

    let mut fe = daemon::Idle::up_to(4);
    let waits: Vec<_> = (0..4).map(|_| fe.after(false)).collect();
    assert_eq!(waits, [Some(1), Some(2), Some(4), Some(4)]);
    assert_eq!(fe.after(true), None);
    assert_eq!(fe.after(false), Some(1));
}

#[test]
fn sockets_and_the_directories_made_for_them_are_closed_to_others() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let dir = dir("modes");
    // The top directory carries the group for everything under it.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o2750)).unwrap();
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().mode() & 0o7777;
    let stream = dir.join("a/b/x.sock");
    let datagram = dir.join("a/punt.sock");
    let _listener = daemon::listen(&stream).unwrap();
    let _socket = daemon::bind_datagram(&datagram).unwrap();
    assert_eq!(mode(&dir.join("a")), 0o2750);
    assert_eq!(mode(&dir.join("a/b")), 0o2750);
    assert_eq!(mode(&stream), daemon::SOCKET_MODE);
    assert_eq!(mode(&datagram), daemon::SOCKET_MODE);
    assert_eq!(mode(&dir.join("a/b/x.sock.lock")), 0o600);
    let group = std::fs::metadata(&dir).unwrap().gid();
    assert_eq!(std::fs::metadata(&stream).unwrap().gid(), group);
    // Without the set-group-ID bit above, a new directory is plain 0750.
    let plain = dir.join("plain");
    std::fs::create_dir(&plain).unwrap();
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o700)).unwrap();
    let _other = daemon::listen(&plain.join("c/y.sock")).unwrap();
    assert_eq!(mode(&plain.join("c")), daemon::DIR_MODE);
    // A directory already there is left as it is.
    assert_eq!(mode(&plain), 0o700);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_directory_made_beforehand_gives_its_socket_its_own_group() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // A group of this process other than its own, as an operator's group for one
    // process (`docs/design/ce-processes.md`, "部分と送り手のsocket").
    // root may give any group: nogroup's.
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let me = std::fs::metadata("/proc/self").unwrap();
    let primary = me.gid();
    let other = if me.uid() == 0 {
        Some(65_534)
    } else {
        status
            .lines()
            .find_map(|l| l.strip_prefix("Groups:"))
            .and_then(|groups| {
                groups
                    .split_whitespace()
                    .filter_map(|g| g.parse::<u32>().ok())
                    .find(|&g| g != primary)
            })
    };
    let Some(other) = other else {
        eprintln!("skipped: this process is in no second group");
        return;
    };
    let dir = dir("own-group");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o2750)).unwrap();
    let pppoe = dir.join("confd/part/pppoe");
    std::fs::create_dir_all(&pppoe).unwrap();
    std::os::unix::fs::chown(&pppoe, None, Some(other)).unwrap();
    std::fs::set_permissions(&pppoe, std::fs::Permissions::from_mode(0o2750)).unwrap();
    let path = dir.join(ruster_proto::daemon::socket::confd_part("pppoe"));
    let dns = dir.join(ruster_proto::daemon::socket::confd_part("dns"));
    let _listener = daemon::listen(&path).unwrap();
    let _other = daemon::listen(&dns).unwrap();
    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(meta.gid(), other);
    assert_eq!(meta.mode() & 0o7777, daemon::SOCKET_MODE);
    // The directory made beforehand is left as it is.
    assert_eq!(std::fs::metadata(&pppoe).unwrap().mode() & 0o7777, 0o2750);
    assert_eq!(std::fs::metadata(&pppoe).unwrap().gid(), other);
    // A directory confd makes takes the group from above.
    assert_eq!(
        std::fs::metadata(&dns).unwrap().gid(),
        std::fs::metadata(&dir).unwrap().gid()
    );
    std::fs::remove_dir_all(dir).unwrap();
}
