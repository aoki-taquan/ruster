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
                evpn: false,
            },
            BgpNeighbor {
                address: "2001:db8:100::10".into(),
                remote_as: 65002,
                description: Vec::new(),
                evpn: false,
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
{}protocol static ruster_networks_ipv4 {{
  ipv4;
  route 203.0.113.0/24 unreachable;
}}
protocol static ruster_networks_ipv6 {{
  ipv6;
  route 2001:db8:5::/48 unreachable;
}}
protocol bgp ruster_neighbor_198_51_100_10 {{
  local as 65001;
  neighbor 198.51.100.10 as 65002;
  description \"the ISP\";
  ipv4 {{
    import all;
    export where proto = \"ruster_networks_ipv4\";
    igp table ruster_tun4;
  }};
}}
protocol bgp ruster_neighbor_2001_db8_100__10 {{
  local as 65001;
  neighbor 2001:db8:100::10 as 65002;
  ipv6 {{
    import all;
    export where proto = \"ruster_networks_ipv6\";
    igp table ruster_tun6;
    next hop prefer global;
    next hop link local fe80::ff:fe00:2;
  }};
}}
protocol ruster {{
  run dir \"/run/ruster\";
  source \"bird\";
  ipv4 {{ export where source ~ [RTS_BGP, RTS_ISIS, RTS_OSPF, RTS_OSPF_IA, RTS_OSPF_EXT1, RTS_OSPF_EXT2]; }};
  ipv6 {{ export where source ~ [RTS_BGP, RTS_ISIS, RTS_OSPF, RTS_OSPF_IA, RTS_OSPF_EXT1, RTS_OSPF_EXT2]; }};
}}
# extra
",
        ruster_bird::conf::NEXT_HOP_TABLES
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
        // On no interface's prefix: no link-local to give as the next hop's.
        |b: &mut Bgp| b.neighbor[1].address = "2001:db8:999::10".into(),
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
             if [ \"$2\" != check ] && [ -e {0}/stuck ]; then echo '8001 stuck on purpose'; exit 1; fi\n\
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
    assert!(
        diff.contains("-protocol bgp ruster_neighbor_198_51_100_10 {"),
        "{diff}"
    );
    assert_eq!(std::fs::read_to_string(dir.join("ran")).unwrap(), before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn when_bird_rs_does_not_take_the_file_the_one_before_is_put_back() {
    let dir = dir("putback");
    let file = dir.join("bird.conf");
    let mut bridge = Bridge::new(file.clone(), birdc(&dir), "/run/ruster".into());
    let part = frr_part(&routing(Some(bgp())));
    bridge.take(&part).unwrap();
    let written = std::fs::read_to_string(&file).unwrap();
    // The check passes, the configure fails: the file before is back.
    std::fs::write(dir.join("stuck"), "").unwrap();
    let error = bridge.take(&frr_part(&routing(None))).unwrap_err();
    assert!(error.contains("stuck on purpose"), "{error}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), written);
    assert!(!dir.join("bird.conf.next").exists());
    // The part it holds again is read again, though the file has it.
    std::fs::remove_file(dir.join("stuck")).unwrap();
    let before = std::fs::read_to_string(dir.join("ran")).unwrap();
    bridge.take(&part).unwrap();
    let ran = std::fs::read_to_string(dir.join("ran")).unwrap();
    assert!(ran.len() > before.len(), "{ran}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_check_hides_the_secrets_of_the_include() {
    let dir = dir("secrets");
    let file = dir.join("bird.conf");
    let include = dir.join("include.conf");
    std::fs::write(&include, "protocol bgp x { password \"hunter2\"; }\n").unwrap();
    let mut with_include = bgp();
    with_include.include = vec![include.display().to_string()];
    let bridge = Bridge::new(file, birdc(&dir), "/run/ruster".into());
    let diff = bridge
        .check(&frr_part(&routing(Some(with_include))))
        .unwrap();
    assert!(!diff.contains("hunter2"), "{diff}");
    assert!(diff.contains("password (hidden, changed)"), "{diff}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn evpn_vni(encapsulation: &str) -> ruster_config::EvpnVni {
    let srv6 = encapsulation == "srv6";
    ruster_config::EvpnVni {
        vni: 100,
        bridge: "br0".into(),
        encapsulation: encapsulation.into(),
        router_address: if srv6 { "2001:db8::1" } else { "10.0.0.1" }.into(),
        unicast_sid: if srv6 {
            vec!["fc00:1::e".into()]
        } else {
            Vec::new()
        },
        multicast_sid: if srv6 {
            vec!["fc00:1::f".into()]
        } else {
            Vec::new()
        },
    }
}

#[test]
fn an_evpn_neighbor_gets_the_vni_s_protocol_evpn_and_protocol_ruster_its_bridge() {
    let mut with_evpn = bgp();
    with_evpn.neighbor[0].evpn = true;
    let mut part = routing(Some(with_evpn.clone()));
    part.evpn = vec![evpn_vni("vxlan")];
    let text = config(&part, "", "/run/ruster").unwrap();
    for line in [
        "ipv4 table ruster_tun4;",
        "protocol direct ruster_tun { ipv4 { table ruster_tun4; }; ipv6 { table ruster_tun6; }; interface \"rt-default\"; }",
        "    igp table ruster_tun4;",
        "protocol evpn ruster_evpn_100 {",
        "  encapsulation vxlan { router address 10.0.0.1; };",
        "  rd 198.51.100.1:100;",
        "  route target (rt, 65001, 100);",
        "    export where proto = \"ruster_evpn_100\";",
        "  eth { table ruster_eth; export where net.vlan_id = 100; };",
        "  vid 100;",
        "  eth { table ruster_eth; export all; ruster bridge \"br0\" vid 100; };",
        "  evpn { table ruster_evpn; export where (rt, 65001, 100) ~ bgp_ext_community; };",
    ] {
        assert!(text.lines().any(|l| l == line), "{line}\n{text}");
    }
    // Only the EVPN neighbor carries EVPN.
    assert_eq!(text.matches("    table ruster_evpn;").count(), 1, "{text}");
    // Over SRv6: the SIDs, and the VNI not from the label.
    part.evpn = vec![evpn_vni("srv6")];
    let text = config(&part, "", "/run/ruster").unwrap();
    assert!(text.contains("encapsulation srv6 { unicast sid fc00:1::e; multicast sid fc00:1::f; router address 2001:db8::1; };"), "{text}");
    assert!(
        text.contains("~ bgp_ext_community; ruster vni 100; };"),
        "{text}"
    );
    // Without a VNI, or with a bridge name that would break the file: refused.
    part.evpn.clear();
    assert!(config(&part, "", "/run/ruster").is_err());
    let mut bad = evpn_vni("vxlan");
    bad.bridge = "br\"0".into();
    part.evpn = vec![bad];
    assert!(config(&part, "", "/run/ruster").is_err());
    // A VNI the RD's two-octet number does not take.
    let mut big = evpn_vni("vxlan");
    big.vni = 70_000;
    part.evpn = vec![big];
    assert!(config(&part, "", "/run/ruster").is_err());
}

#[test]
fn is_is_and_ospf_run_on_the_tap_devices_and_give_ribd_their_routes() {
    let mut part = routing(None);
    // Both IS-IS interfaces have IPv6.
    part.connected.push(Connected {
        interface: "lan".into(),
        prefix: "2001:db8:1::/64".into(),
        link_local: "fe80::ff:fe00:1".into(),
    });
    part.isis = Some(ruster_config::Isis {
        net: "49.0001.1921.6800.1001.00".into(),
        level: "level-2".into(),
        interface: vec![
            ruster_config::IsisInterface {
                name: "wan".into(),
                metric: 20,
                passive: false,
            },
            ruster_config::IsisInterface {
                name: "lan".into(),
                metric: 10,
                passive: true,
            },
        ],
    });
    let ospf = |passive: bool| ruster_config::Ospf {
        router_id: "198.51.100.1".into(),
        interface: vec![ruster_config::OspfInterface {
            name: "wan".into(),
            area: "0.0.0.1".into(),
            cost: 30,
            network: "point-to-point".into(),
            passive,
        }],
    };
    part.ospf = Some(ospf(false));
    part.ospf6 = Some(ospf(true));
    let text = config(&part, "", "/run/ruster").unwrap();
    let expected = format!(
        "{HEADER}
router id 198.51.100.1;
protocol device {{}}
protocol isis ruster_isis {{
  net \"49.0001.1921.6800.1001.00\";
  level 2;
  ipv4 {{ import all; export none; }};
  ipv6 {{ import all; export none; }};
  interface \"rp-wan\" {{ metric 20; }};
  interface \"rp-lan\" {{ metric 10; passive; }};
}}
protocol ospf v2 ruster_ospf {{
  router id 198.51.100.1;
  ipv4 {{ import all; export none; }};
  area 0.0.0.1 {{
    interface \"rp-wan\" {{ cost 30; type ptp; }};
  }};
}}
protocol ospf v3 ruster_ospf6 {{
  router id 198.51.100.1;
  ipv6 {{ import all; export none; }};
  area 0.0.0.1 {{
    interface \"rp-wan\" {{ cost 30; type ptp; stub; }};
  }};
}}
protocol ruster {{
  run dir \"/run/ruster\";
  source \"bird\";
  ipv4 {{ export where source ~ [RTS_BGP, RTS_ISIS, RTS_OSPF, RTS_OSPF_IA, RTS_OSPF_EXT1, RTS_OSPF_EXT2]; }};
  ipv6 {{ export where source ~ [RTS_BGP, RTS_ISIS, RTS_OSPF, RTS_OSPF_IA, RTS_OSPF_EXT1, RTS_OSPF_EXT2]; }};
}}
"
    );
    assert_eq!(text, expected);
    // A name that would break the file, a level or network of no kind: refused.
    let mut bad = part.clone();
    bad.isis.as_mut().unwrap().interface[0].name = "w\"an".into();
    assert!(config(&bad, "", "/run/ruster").is_err());
    let mut bad = part.clone();
    bad.isis.as_mut().unwrap().level = "level-3".into();
    assert!(config(&bad, "", "/run/ruster").is_err());
    let mut bad = part.clone();
    bad.ospf.as_mut().unwrap().interface[0].network = "nbma".into();
    assert!(config(&bad, "", "/run/ruster").is_err());
    let mut bad = part.clone();
    bad.isis.as_mut().unwrap().interface[0].name = "r*".into();
    assert!(config(&bad, "", "/run/ruster").is_err());
}

#[test]
fn is_is_carries_ipv6_on_the_interfaces_with_it_and_alone_takes_its_id_from_the_net() {
    let isis = |names: &[&str]| ruster_config::Isis {
        net: "49.0001.1921.6800.1001.00".into(),
        level: "level-1-2".into(),
        interface: names
            .iter()
            .map(|n| ruster_config::IsisInterface {
                name: (*n).into(),
                metric: 10,
                passive: false,
            })
            .collect(),
    };
    // wan has an IPv6 prefix (routing()'s connected), lan none: IPv6 off on lan.
    let mut part = routing(None);
    part.isis = Some(isis(&["wan", "lan"]));
    let text = config(&part, "", "/run/ruster").unwrap();
    assert!(
        text.contains("  ipv6 { import all; export none; };\n  interface"),
        "{text}"
    );
    assert!(
        text.contains("  interface \"rp-wan\" { metric 10; };"),
        "{text}"
    );
    assert!(
        text.contains("  interface \"rp-lan\" { metric 10; ipv6 off; };"),
        "{text}"
    );
    // The router ID from the system ID 1921.6800.1001: 0x68.0x00.0x10.0x01.
    assert!(text.contains("router id 104.0.16.1;"), "{text}");
    // An OSPF with no interface is not written.
    part.ospf = Some(ruster_config::Ospf {
        router_id: "198.51.100.1".into(),
        interface: Vec::new(),
    });
    let text = config(&part, "", "/run/ruster").unwrap();
    assert!(!text.contains("protocol ospf"), "{text}");
}

#[test]
fn two_vnis_get_a_protocol_evpn_and_a_vlan_id_each() {
    let mut with_evpn = bgp();
    with_evpn.neighbor[0].evpn = true;
    let mut part = routing(Some(with_evpn));
    let mut second = evpn_vni("vxlan");
    second.vni = 200;
    second.bridge = "br1".into();
    // VNIs up to 4094 are their own VLAN IDs; a larger one takes a free one.
    let mut third = evpn_vni("vxlan");
    third.vni = 5000;
    third.bridge = "br2".into();
    part.evpn = vec![second.clone(), third, evpn_vni("vxlan")];
    let text = config(&part, "", "/run/ruster").unwrap();
    for line in [
        "protocol evpn ruster_evpn_100 {",
        "protocol evpn ruster_evpn_200 {",
        "  eth { table ruster_eth; export where net.vlan_id = 200; };",
        "  eth { table ruster_eth; export where net.vlan_id = 1; };",
        "  route target (rt, 65001, 200);",
        "  eth { table ruster_eth; export all; ruster bridge \"br0\" vid 100; ruster bridge \"br1\" vid 200; ruster bridge \"br2\" vid 1; };",
        "  evpn { table ruster_evpn; export where (rt, 65001, 100) ~ bgp_ext_community || (rt, 65001, 200) ~ bgp_ext_community || (rt, 65001, 5000) ~ bgp_ext_community; };",
        "    export where proto = \"ruster_evpn_100\" || proto = \"ruster_evpn_200\" || proto = \"ruster_evpn_5000\";",
    ] {
        assert!(text.lines().any(|l| l == line), "{line}\n{text}");
    }
    assert_eq!(text.matches("ipv4 table ruster_tun4;").count(), 1, "{text}");
    // A bridge twice, or two VNIs over SRv6: refused.
    let mut same_bridge = second.clone();
    same_bridge.bridge = "br0".into();
    part.evpn = vec![evpn_vni("vxlan"), same_bridge];
    assert!(config(&part, "", "/run/ruster").is_err());
    let mut srv6 = evpn_vni("srv6");
    srv6.vni = 200;
    srv6.bridge = "br1".into();
    part.evpn = vec![evpn_vni("vxlan"), srv6];
    assert!(config(&part, "", "/run/ruster").is_err());
}
