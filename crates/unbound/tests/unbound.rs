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
    bridge.take(&dns_part(Some(&dns())), &mut || {}).unwrap();
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        settings(Some(&dns())).unwrap()
    );
    // The same part again runs nothing.
    bridge.take(&dns_part(Some(&dns())), &mut || {}).unwrap();
    bridge.take(&dns_part(None), &mut || {}).unwrap();
    assert_eq!(std::fs::read_to_string(&log).unwrap(), "x\nx\n");
    assert!(bridge.take("version = 1\ndns = [1]\n", &mut || {}).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_failed_command_puts_the_file_before_back_and_refuses() {
    let dir = dir("fail");
    let file = dir.join("ruster.conf");
    let flag = dir.join("broken");
    let reload = vec![
        "sh".to_owned(),
        "-c".to_owned(),
        format!("! test -e {}", flag.display()),
    ];
    // The first part fails too, and then there is no file.
    std::fs::write(&flag, "").unwrap();
    let mut bridge = Bridge::new(file.clone(), reload);
    let mut written = 0;
    assert!(bridge.take(&dns_part(None), &mut || written += 1).is_err());
    assert_eq!(written, 1, "told before the command runs");
    assert!(!file.exists());

    std::fs::remove_file(&flag).unwrap();
    bridge.take(&dns_part(None), &mut || {}).unwrap();
    let first = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&flag, "").unwrap();
    let error = bridge
        .take(&dns_part(Some(&dns())), &mut || {})
        .unwrap_err();
    assert!(error.contains("failed"), "{error}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), first);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn after_a_start_the_command_runs_for_the_file_it_finds() {
    let dir = dir("again");
    let file = dir.join("ruster.conf");
    let log = dir.join("runs");
    let reload = vec![
        "sh".to_owned(),
        "-c".to_owned(),
        format!("echo x >> {}", log.display()),
    ];
    std::fs::write(&file, settings(None).unwrap()).unwrap();
    let mut bridge = Bridge::new(file.clone(), reload);
    bridge.take(&dns_part(None), &mut || {}).unwrap();
    bridge.take(&dns_part(None), &mut || {}).unwrap();
    assert_eq!(std::fs::read_to_string(&log).unwrap(), "x\n");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_servers_found_are_forwarded_to_after_those_given() {
    let found: Vec<std::net::IpAddr> = vec![
        "198.51.100.53".parse().unwrap(),
        "192.0.2.53".parse().unwrap(),
        "2001:db8::53".parse().unwrap(),
    ];
    let part = ruster_config::dns_part_with(Some(&dns()), &found);
    let (parsed, back) = ruster_config::parse_dns_part_with(&part).unwrap();
    assert_eq!(back, found);
    let text = ruster_unbound::settings_with(parsed.as_ref(), &back).unwrap();
    let forwards: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("forward-addr"))
        .collect();
    assert_eq!(forwards.len(), 3, "{text}");
    // The one given first, and the one found twice once.
    assert!(forwards[0].ends_with("198.51.100.53") && forwards[1].ends_with("192.0.2.53"));
    // With no servers given, those found are used.
    let own = Dns {
        upstream: Vec::new(),
        ..dns()
    };
    assert!(ruster_unbound::settings_with(Some(&own), &found[..1])
        .unwrap()
        .contains("forward-zone:\n    name: \".\"\n    forward-addr: 198.51.100.53\n"));
    // The part without servers found reads as before.
    assert_eq!(
        ruster_config::parse_dns_part_with(&dns_part(Some(&dns())))
            .unwrap()
            .1,
        Vec::<std::net::IpAddr>::new()
    );
}
