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
