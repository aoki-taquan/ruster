//! Kea's settings file and reading it again.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::mpsc;

use ruster_kea::settings::{settings, Listen};
use ruster_kea::settings6::Listen6;
use ruster_kea::{Bridge, Server};

fn part(pool: &str) -> String {
    format!(
        "version = 1\ndhcp6 = []\n\n[[dhcp]]\ninterface = \"lan\"\nmac = \"02:00:00:00:00:01\"\naddress = \"192.0.2.1/24\"\npool = \"{pool}\"\nlease-time = 600\nrouter = [\"192.0.2.1\"]\ndns = [\"192.0.2.1\", \"192.0.2.2\"]\npunt-rate = 200\npunt-burst = 100\n"
    )
}

fn listen() -> Listen {
    Listen::parse("lo/127.0.0.1").unwrap()
}

#[test]
fn a_subnet_per_interface_with_its_options() {
    let (dhcp, _) = ruster_config::parse_dhcp_part(&part("192.0.2.100-192.0.2.199")).unwrap();
    let served = ruster_kea::settings::read(&dhcp).unwrap();
    assert_eq!(served[0].link.mac, [2, 0, 0, 0, 0, 1]);
    let text = settings(&listen(), &served);
    for want in [
        "\"interfaces\": [ \"lo/127.0.0.1\" ]",
        "\"dhcp-socket-type\": \"udp\"",
        // 192.0.2.0 as a number: the id stays with the subnet.
        "\"id\": 3221225984,",
        "\"subnet\": \"192.0.2.0/24\"",
        "\"valid-lifetime\": 600",
        "\"pool\": \"192.0.2.100 - 192.0.2.199\"",
        "{ \"name\": \"dhcp-server-identifier\", \"data\": \"192.0.2.1\" }",
        "{ \"name\": \"routers\", \"data\": \"192.0.2.1\" }",
        "{ \"name\": \"domain-name-servers\", \"data\": \"192.0.2.1, 192.0.2.2\" }",
    ] {
        assert!(text.contains(want), "{want} in {text}");
    }
    let none = settings(&listen(), &[]);
    assert!(none.contains("\"interfaces\": []"), "{none}");
    assert!(none.contains("\"subnet4\": []"), "{none}");
}

#[test]
fn only_addresses_reach_the_file() {
    for bad in ["192.0.2.100-x }, y: {", "192.0.2.100"] {
        let mut text = part("192.0.2.100-192.0.2.199");
        text = text.replace("192.0.2.100-192.0.2.199", bad);
        let (dhcp, _) = ruster_config::parse_dhcp_part(&text).unwrap();
        assert!(ruster_kea::settings::read(&dhcp).is_err(), "{bad}");
    }
    assert!(Listen::parse("lo\"/127.0.0.1").is_err());
    assert!(Listen::parse("lo/::1").is_err());
}

/// A Kea control socket that answers each `config-reload` with the next result.
fn kea(dir: &std::path::Path, results: Vec<i32>) -> (PathBuf, mpsc::Receiver<String>) {
    let path = dir.join("kea4-ctrl-socket");
    let listener = UnixListener::bind(&path).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for result in results {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0; 256];
            let n = stream.read(&mut buf).unwrap();
            tx.send(String::from_utf8_lossy(&buf[..n]).into_owned())
                .unwrap();
            let answer = format!("{{ \"result\": {result}, \"text\": \"said {result}\" }}");
            stream.write_all(answer.as_bytes()).unwrap();
        }
    });
    (path, rx)
}

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ruster-kea-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_file_kea_refuses_is_put_back() {
    let dir = dir("refuse");
    let (control, asked) = kea(&dir, vec![0, 1, 0]);
    let file = dir.join("ruster-dhcp4.json");
    let mut bridge = Bridge::new(file.clone(), Some(control), listen());
    let mut written = 0;
    let served = bridge
        .take(&part("192.0.2.100-192.0.2.199"), &mut || written += 1)
        .unwrap();
    assert_eq!(served.0.len(), 1);
    assert_eq!(written, 1);
    assert!(asked.recv().unwrap().contains("config-reload"));
    let before = std::fs::read_to_string(&file).unwrap();

    let error = bridge
        .take(&part("192.0.2.10-192.0.2.20"), &mut || {})
        .unwrap_err();
    assert!(error.contains("said 1"), "{error}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    asked.recv().unwrap();
    asked.recv().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn without_kea_running_the_part_is_taken() {
    let dir = dir("absent");
    let file = dir.join("ruster-dhcp4.json");
    let mut bridge = Bridge::new(file.clone(), Some(dir.join("no-socket")), listen());
    bridge
        .take(&part("192.0.2.100-192.0.2.199"), &mut || {})
        .unwrap();
    assert!(std::fs::read_to_string(&file)
        .unwrap()
        .contains("192.0.2.100 - 192.0.2.199"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A part with one dhcp6 entry, and the DHCPv4 entry of [`part`].
fn part6(pool: &str) -> String {
    part("192.0.2.100-192.0.2.199").replace(
        "dhcp6 = []\n",
        "",
    ) + &format!(
        "\n[[dhcp6]]\ninterface = \"lan\"\nmac = \"02:00:00:00:00:01\"\nlink-local = \"fe80::ff:fe00:1\"\naddress = \"2001:db8:1::1/64\"\npool = \"{pool}\"\npreferred-lifetime = 600\nvalid-lifetime = 1200\ndns = []\npunt-rate = 200\npunt-burst = 100\n"
    )
}

#[test]
fn dhcp6_needs_its_file_and_a_refusal_puts_both_back() {
    let dir = dir("six");
    let file = dir.join("ruster-dhcp4.json");
    let file6 = dir.join("ruster-dhcp6.json");
    let mut only4 = Bridge::new(file.clone(), None, listen());
    let error = only4
        .take(&part6("2001:db8:1::1000-2001:db8:1::1fff"), &mut || {})
        .unwrap_err();
    assert!(error.contains("--dhcp6"), "{error}");

    // Kea's DHCPv4 takes each file; its DHCPv6 takes the first and refuses the second.
    let (control, _asked) = kea(&dir, vec![0, 0, 0]);
    let six = dir.join("six");
    std::fs::create_dir_all(&six).unwrap();
    let (control6, _asked6) = kea(&six, vec![0, 1, 0]);
    let mut bridge = Bridge::new(file.clone(), Some(control), listen()).with_dhcp6(
        Server {
            path: file6.clone(),
            control: Some(control6),
        },
        Listen6::parse("lo/::1").unwrap(),
    );
    let (served, served6) = bridge
        .take(&part6("2001:db8:1::1000-2001:db8:1::1fff"), &mut || {})
        .unwrap();
    assert_eq!((served.len(), served6.len()), (1, 1));
    let before = std::fs::read_to_string(&file6).unwrap();
    assert!(
        before.contains("2001:db8:1::1000 - 2001:db8:1::1fff"),
        "{before}"
    );
    let before4 = std::fs::read_to_string(&file).unwrap();
    let error = bridge
        .take(&part6("2001:db8:1::2000-2001:db8:1::2fff"), &mut || {})
        .unwrap_err();
    assert!(error.contains("said 1"), "{error}");
    assert_eq!(std::fs::read_to_string(&file6).unwrap(), before);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), before4);
    let _ = std::fs::remove_dir_all(&dir);
}
