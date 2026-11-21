//! bird-rs's configuration from the `bird` part, and the `birdc` commands that apply it.

use std::path::{Path, PathBuf};

use ruster_bird::conf::{config, Bridge, HEADER};
use ruster_config::{frr_part, Bgp, BgpNeighbor, Connected, Frr};

fn routing(bgp: Option<Bgp>) -> Frr {
    Frr {
        bgp,
        connected: [("198.51.100.0/24"), ("2001:db8:100::/64")]
            .into_iter()
            .map(|p| Connected {
                interface: "wan".into(),
                prefix: p.into(),
                link_local: "fe80::ff:fe00:2".into(),
            })
            .collect(),
        ..Frr::default()
    }
}

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

#[test]
fn the_configuration_has_the_networks_the_neighbors_and_protocol_ruster() {
    let text = config(&routing(Some(bgp())), "# extra\n", "/run/ruster").unwrap();
    let expected = format!(
        "{HEADER}
router id 198.51.100.1;
protocol device {{}}
protocol static ruster_networks_ipv4 {{
  ipv4;
  route 203.0.113.0/24 unreachable;
}}
protocol static ruster_networks_ipv6 {{
  ipv6;
  route 2001:db8:5::/48 unreachable;
}}
protocol bgp ruster_neighbor_0 {{
  local as 65001;
  neighbor 198.51.100.10 as 65002;
  description \"the ISP\";
  ipv4 {{
    import all;
    export where proto = \"ruster_networks_ipv4\";
  }};
}}
protocol bgp ruster_neighbor_1 {{
  local as 65001;
  neighbor 2001:db8:100::10 as 65002;
  ipv6 {{
    import all;
    export where proto = \"ruster_networks_ipv6\";
    next hop prefer global;
    next hop link local fe80::ff:fe00:2;
  }};
}}
protocol ruster {{
  run dir \"/run/ruster\";
  source \"bird\";
  ipv4 {{ export where source = RTS_BGP; }};
  ipv6 {{ export where source = RTS_BGP; }};
}}
# extra
"
    );
    assert_eq!(text, expected);
}

#[test]
fn without_bgp_only_the_devices_are_read_and_without_networks_nothing_is_sent() {
    let text = config(&routing(None), "", "/run/ruster").unwrap();
    assert_eq!(text, format!("{HEADER}\nprotocol device {{}}\n"));
    let mut quiet = bgp();
    quiet.networks.clear();
    let text = config(&routing(Some(quiet)), "", "/run/ruster").unwrap();
    assert!(!text.contains("protocol static"), "{text}");
    assert_eq!(text.matches("export none;").count(), 2, "{text}");
}

#[test]
fn values_that_would_break_the_file_are_refused() {
    for change in [
        |b: &mut Bgp| b.neighbor[0].description = vec!["a\"b".into()],
        |b: &mut Bgp| b.neighbor[0].description = vec![String::new()],
        |b: &mut Bgp| b.neighbor[0].address = "x".into(),
        |b: &mut Bgp| b.router_id = "x".into(),
        |b: &mut Bgp| b.networks = vec!["203.0.113.0/33".into()],
    ] {
        let mut bad = bgp();
        change(&mut bad);
        assert!(config(&routing(Some(bad)), "", "/run/ruster").is_err());
    }
    assert!(config(&routing(Some(bgp())), "", "/run/\"x").is_err());
}

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ruster-bird-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A `birdc` that records its commands and fails a check while `broken` exists.
fn birdc(dir: &Path) -> Vec<String> {
    let path = dir.join("birdc");
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\necho \"$@\" >> {0}/ran\n\
             if [ \"$2\" = check ] && [ -e {0}/broken ]; then echo '8002 broken on purpose'; exit 1; fi\n\
             echo '0003 Reconfigured'\n",
            dir.display()
        ),
    )
    .unwrap();
    vec!["sh".into(), path.display().to_string()]
}

#[test]
fn the_bridge_checks_then_configures_and_a_refused_file_changes_nothing() {
    let dir = dir("take");
    let file = dir.join("bird.conf");
    let mut bridge = Bridge::new(file.clone(), birdc(&dir), "/run/ruster".into());
    let part = frr_part(&routing(Some(bgp())));
    bridge.take(&part).unwrap();
    let ran = std::fs::read_to_string(dir.join("ran")).unwrap();
    let f = file.display();
    assert_eq!(
        ran,
        format!("configure check \"{f}.next\"\nconfigure \"{f}\"\n")
    );
    let written = std::fs::read_to_string(&file).unwrap();
    assert!(written.contains("neighbor 198.51.100.10 as 65002;"));
    // The same part again: nothing to do.
    bridge.take(&part).unwrap();
    assert_eq!(std::fs::read_to_string(dir.join("ran")).unwrap(), ran);
    // A part bird-rs cannot read is refused, and the file stays as it was.
    std::fs::write(dir.join("broken"), "").unwrap();
    let error = bridge.take(&frr_part(&routing(None))).unwrap_err();
    assert!(error.contains("broken on purpose"), "{error}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), written);
    assert!(!dir.join("bird.conf.next").exists());
    // A check of a part shows the change and runs nothing.
    std::fs::remove_file(dir.join("broken")).unwrap();
    let before = std::fs::read_to_string(dir.join("ran")).unwrap();
    let diff = bridge.check(&frr_part(&routing(None))).unwrap();
    assert!(diff.contains("-protocol bgp ruster_neighbor_0 {"), "{diff}");
    assert_eq!(std::fs::read_to_string(dir.join("ran")).unwrap(), before);
    let _ = std::fs::remove_dir_all(&dir);
}
