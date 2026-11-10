//! FRR's configuration from the `frr` part, and the command that applies it.

use std::path::{Path, PathBuf};

use ruster_config::{frr_part, Bgp, BgpNeighbor, Connected};
use ruster_frr::conf::{config, Bridge, HEADER};

fn bgp() -> Bgp {
    Bgp {
        asn: 65001,
        router_id: "198.51.100.1".into(),
        networks: vec!["203.0.113.0/24".into(), "2001:db8:5::/48".into()],
        include: Vec::new(),
        neighbor: vec![
            BgpNeighbor {
                address: "198.51.100.10".into(),
                remote_as: 65002,
                description: vec!["the ISP".into()],
            },
            BgpNeighbor {
                address: "2001:db8:100::10".into(),
                remote_as: 65002,
                description: Vec::new(),
            },
        ],
    }
}

fn connected() -> Vec<Connected> {
    [("198.51.100.0/24"), ("2001:db8:100::/64")]
        .into_iter()
        .map(|p| Connected {
            interface: "wan".into(),
            prefix: p.into(),
            link_local: "fe80::ff:fe00:2".into(),
        })
        .collect()
}

#[test]
fn the_configuration_has_fpm_the_policies_and_router_bgp() {
    let text = config(
        Some(&bgp()),
        &connected(),
        "route-map extra permit 10\n",
        2620,
    )
    .unwrap();
    let want = format!(
        "{HEADER}
fpm address 127.0.0.1
no fpm use-next-hop-groups
ip prefix-list ruster-out-v4 seq 5 permit 203.0.113.0/24
ipv6 prefix-list ruster-out-v6 seq 5 permit 2001:db8:5::/48
route-map ruster-in permit 10
 set ipv6 next-hop prefer-global
exit
route-map ruster-out permit 10
 match ip address prefix-list ruster-out-v4
exit
route-map ruster-out deny 100
exit
route-map ruster-out-v6-1 permit 10
 match ipv6 address prefix-list ruster-out-v6
 set ipv6 next-hop local fe80::ff:fe00:2
exit
route-map ruster-out-v6-1 deny 100
exit
router bgp 65001
 bgp router-id 198.51.100.1
 no bgp default ipv4-unicast
 no bgp network import-check
 neighbor 198.51.100.10 remote-as 65002
 neighbor 198.51.100.10 description the ISP
 neighbor 2001:db8:100::10 remote-as 65002
 address-family ipv4 unicast
  network 203.0.113.0/24
  neighbor 198.51.100.10 activate
  neighbor 198.51.100.10 route-map ruster-in in
  neighbor 198.51.100.10 route-map ruster-out out
 exit-address-family
 address-family ipv6 unicast
  network 2001:db8:5::/48
  neighbor 2001:db8:100::10 activate
  neighbor 2001:db8:100::10 route-map ruster-in in
  neighbor 2001:db8:100::10 route-map ruster-out-v6-1 out
 exit-address-family
exit
route-map extra permit 10
"
    );
    assert_eq!(text, want);
}

#[test]
fn without_bgp_only_fpm_is_set() {
    let text = config(None, &[], "", 9).unwrap();
    assert_eq!(
        text,
        format!("{HEADER}\nfpm address 127.0.0.1 port 9\nno fpm use-next-hop-groups\n")
    );
    // Without networks nothing is sent, and a family without either is left out.
    let mut quiet = bgp();
    quiet.networks.clear();
    quiet.neighbor.truncate(1);
    let text = config(Some(&quiet), &[], "log syslog", 9).unwrap();
    assert!(
        !text.contains("prefix-list") && !text.contains("ipv6 unicast"),
        "{text}"
    );
    assert!(text.contains("route-map ruster-out deny 100\n"));
    assert!(text.ends_with("exit\nlog syslog\n"), "{text}");
}

#[test]
fn values_that_would_break_the_file_are_refused() {
    for change in [
        |b: &mut Bgp| b.router_id = "1.2.3.4\nrouter bgp 1".into(),
        |b: &mut Bgp| b.networks = vec!["10.0.0.0/8 x".into()],
        |b: &mut Bgp| b.networks = vec!["10.0.0.0/33".into()],
        |b: &mut Bgp| b.neighbor[0].address = "10.0.0.1 remote-as 1".into(),
        |b: &mut Bgp| b.neighbor[0].description = vec!["a\nb".into()],
        |b: &mut Bgp| b.neighbor[0].description = vec![String::new()],
    ] {
        let mut b = bgp();
        change(&mut b);
        assert!(config(Some(&b), &connected(), "", 1).is_err(), "{b:?}");
    }
    // An IPv6 neighbor on no interface's prefix has no link-local for its next hop.
    assert!(config(Some(&bgp()), &connected()[..1], "", 1)
        .unwrap_err()
        .contains("no interface"));
    {}
}

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ruster-frr-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A command that records the file it was given, and fails while `broken` exists.
fn script(dir: &Path) -> Vec<String> {
    let path = dir.join("reload");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\necho \"$@\" >> {0}/ran\n[ -e {0}/broken ] && {{ echo broken on purpose; exit 1; }}\ncp \"$1\" {0}/applied\n",
            dir.display()
        ),
    )
    .unwrap();
    vec!["sh".into(), path.display().to_string()]
}

#[test]
fn the_bridge_writes_applies_and_puts_back() {
    let dir = dir("bridge");
    let file = dir.join("frr.conf");
    let include = dir.join("extra.conf");
    std::fs::write(&include, "hostname router\n").unwrap();
    let mut with_include = bgp();
    with_include.include = vec![include.display().to_string()];
    let connected = connected();
    let part = frr_part(Some(&with_include), &connected);
    let mut bridge = Bridge::new(file.clone(), script(&dir), 2620);
    assert_eq!(bridge.take(&part).unwrap(), connected);
    let written = std::fs::read_to_string(&file).unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o640, "the include may hold passwords");
    assert!(written.ends_with("exit\nhostname router\n"), "{written}");
    assert_eq!(
        std::fs::read_to_string(dir.join("applied")).unwrap(),
        written
    );
    let ran = |dir: &Path| {
        std::fs::read_to_string(dir.join("ran"))
            .unwrap()
            .lines()
            .count()
    };
    assert_eq!(ran(&dir), 1);
    // The same part again runs nothing.
    bridge.take(&part).unwrap();
    assert_eq!(ran(&dir), 1);
    // A failing command puts the file before back and refuses.
    std::fs::write(dir.join("broken"), "").unwrap();
    let error = bridge.take(&frr_part(None, &connected)).unwrap_err();
    assert!(
        error.contains("broken on purpose"),
        "said on stdout: {error}"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), written);
    assert_eq!(ran(&dir), 3, "the new file, and the one before again");
    std::fs::remove_file(dir.join("broken")).unwrap();
    // After a failure the same part runs the command again: FRR may be half done.
    bridge.take(&part).unwrap();
    assert_eq!(ran(&dir), 4);
    // An include that cannot be read refuses the part and changes nothing.
    std::fs::remove_file(&include).unwrap();
    let error = bridge.take(&part).unwrap_err();
    assert!(error.contains("include"), "{error}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), written);
    assert!(bridge.take("version = 1\n").is_err(), "not a whole part");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_new_bridge_runs_the_command_for_the_file_it_finds() {
    let dir = dir("start");
    let file = dir.join("frr.conf");
    let part = frr_part(None, &[]);
    Bridge::new(file.clone(), script(&dir), 1)
        .take(&part)
        .unwrap();
    Bridge::new(file.clone(), script(&dir), 1)
        .take(&part)
        .unwrap();
    let ran = std::fs::read_to_string(dir.join("ran")).unwrap();
    assert_eq!(ran.lines().count(), 2, "{ran}");
    assert!(ran.contains(&file.display().to_string()));
    // No command: the file is only written.
    let other = dir.join("other.conf");
    Bridge::new(other.clone(), Vec::new(), 1)
        .take(&part)
        .unwrap();
    assert!(other.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn with_no_file_before_a_failure_goes_back_to_no_bgp() {
    let dir = dir("none-before");
    let file = dir.join("frr.conf");
    std::fs::write(dir.join("broken"), "").unwrap();
    let mut bridge = Bridge::new(file.clone(), script(&dir), 2620);
    assert!(bridge.take(&frr_part(Some(&bgp()), &connected())).is_err());
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        config(None, &[], "", 2620).unwrap()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
