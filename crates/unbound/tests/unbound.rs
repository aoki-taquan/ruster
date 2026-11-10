//! Unbound's settings from the dns part, and taking parts.

use ruster_config::{dns_part, Dns};
use ruster_unbound::{settings, Bridge, HEADER};

fn dns() -> Dns {
    Dns {
        listen: vec!["192.0.2.1".into(), "2001:db8:1::1".into()],
        allow: vec!["192.0.2.0/24".into(), "2001:db8:1::/64".into()],
        upstream: vec!["198.51.100.53".into()],
        upstream_from: Vec::new(),
    }
}

#[test]
fn the_settings_listen_allow_and_forward() {
    let text = settings(Some(&dns())).unwrap();
    assert_eq!(
        text,
        format!(
            "{HEADER}
server:
    interface: 192.0.2.1
    interface: 2001:db8:1::1
    ip-freebind: yes
    access-control: 192.0.2.0/24 allow
    access-control: 2001:db8:1::/64 allow
forward-zone:
    name: \".\"
    forward-addr: 198.51.100.53
"
        )
    );
}

#[test]
fn without_upstream_or_dns_there_is_less() {
    let mut own = dns();
    own.upstream.clear();
    assert!(!settings(Some(&own)).unwrap().contains("forward-zone"));
    assert_eq!(settings(None).unwrap(), format!("{HEADER}\nserver:\n"));
}

#[test]
fn only_addresses_and_prefixes_reach_the_file() {
    let changes: [fn(&mut Dns); 4] = [
        |d| d.listen[0] = "192.0.2.1\n    do-ip4: no".into(),
        |d| d.allow[0] = "192.0.2.0/33".into(),
        |d| d.allow[0] = "192.0.2.0".into(),
        |d| d.upstream[0] = "example.net".into(),
    ];
    for change in changes {
        let mut bad = dns();
        change(&mut bad);
        assert!(settings(Some(&bad)).is_err(), "{bad:?}");
    }
}

fn dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ruster-unbound-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_part_is_written_and_reloaded() {
    let dir = dir("take");
    let file = dir.join("ruster.conf");
    let log = dir.join("reloads");
    let reload = vec![
        "sh".to_owned(),
        "-c".to_owned(),
        format!("echo x >> {}", log.display()),
    ];
    let mut bridge = Bridge::new(file.clone(), reload);
    bridge.take(&dns_part(Some(&dns()))).unwrap();
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        settings(Some(&dns())).unwrap()
    );
    // The same part again runs nothing.
    bridge.take(&dns_part(Some(&dns()))).unwrap();
    bridge.take(&dns_part(None)).unwrap();
    assert_eq!(std::fs::read_to_string(&log).unwrap(), "x\nx\n");
    assert!(bridge.take("version = 1\ndns = [1]\n").is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_failed_reload_puts_the_file_before_back_and_refuses() {
    let dir = dir("fail");
    let file = dir.join("ruster.conf");
    let mut bridge = Bridge::new(file.clone(), vec!["false".into()]);
    // The first part is kept: Unbound may not be running yet.
    bridge.take(&dns_part(None)).unwrap();
    let first = std::fs::read_to_string(&file).unwrap();
    let error = bridge.take(&dns_part(Some(&dns()))).unwrap_err();
    assert!(error.contains("false failed"), "{error}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), first);
    std::fs::remove_dir_all(&dir).unwrap();
}
