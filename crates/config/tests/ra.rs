//! `[[ra]]`: the defaults of RFC 4861 section 6.2.1 and the prefixes and DNS servers
//! that follow from the interface.

use ruster_config::{parse_lock, parse_ra_part, ra_part, resolve};

const LAN: &str = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv6 = ["2001:db8:1::1/64", "2001:db8:1::2/64", "2001:db8:2::1/56", "fe80::5/64", "2001:db8:3::1/64"]
"#;

#[test]
fn ra_takes_the_defaults_and_the_interface_s_64s() {
    let text = format!("{LAN}\n[dns]\nlisten = [\"lan\"]\n\n[[ra]]\ninterface = \"lan\"\n");
    let lock = resolve(&text).unwrap();
    let [ra] = &lock.ra[..] else {
        panic!("{:?}", lock.ra)
    };
    assert_eq!((ra.min_interval, ra.max_interval), (198, 600));
    assert_eq!(ra.router_lifetime, 1_800);
    assert_eq!(ra.hop_limit, 64);
    assert!(!ra.managed && !ra.other);
    assert!(ra.mtu.is_empty());
    assert_eq!((ra.reachable_time, ra.retrans_timer), (0, 0));
    assert!(ra.prefix_from.is_empty());
    // One per /64, link-local and the /56 left out.
    let prefixes: Vec<_> = ra.prefix.iter().map(|p| p.prefix.as_str()).collect();
    assert_eq!(prefixes, ["2001:db8:1::/64", "2001:db8:3::/64"]);
    for p in &ra.prefix {
        assert!(p.on_link && p.autonomous);
        assert_eq!(
            (p.valid_lifetime, p.preferred_lifetime),
            (2_592_000, 604_800)
        );
    }
    // [dns] listens on every address but link-local.
    assert_eq!(
        ra.dns,
        [
            "2001:db8:1::1",
            "2001:db8:1::2",
            "2001:db8:2::1",
            "2001:db8:3::1"
        ]
    );
    assert_eq!(ra.dns_lifetime, 1_800);
    assert_eq!(parse_lock(&lock.to_text()).unwrap(), lock);
    assert_eq!(parse_ra_part(&ra_part(&lock.ra)).unwrap(), lock.ra);
}

#[test]
fn ra_keys_replace_the_defaults() {
    let text = format!(
        "{LAN}\n[[ra]]\ninterface = \"lan\"\nmax-interval = 8\nmanaged = true\nother = true\nmtu = 1480\nhop-limit = 0\nvalid-lifetime = 7200\npreferred-lifetime = 3600\ndns = [\"2001:db8::53\"]\n"
    );
    let lock = resolve(&text).unwrap();
    let ra = &lock.ra[0];
    // Below 9 s, 0.75 of max-interval.
    assert_eq!((ra.min_interval, ra.max_interval), (6, 8));
    assert_eq!((ra.router_lifetime, ra.dns_lifetime), (24, 24));
    assert!(ra.managed && ra.other);
    assert_eq!(ra.mtu, [1480]);
    assert_eq!(ra.hop_limit, 0);
    assert_eq!(ra.dns, ["2001:db8::53"]);
    assert_eq!(
        (ra.prefix[0].valid_lifetime, ra.prefix[0].preferred_lifetime),
        (7_200, 3_600)
    );
    // Without [dns] there is no DNS server.
    let lock = resolve(&format!("{LAN}\n[[ra]]\ninterface = \"lan\"\n")).unwrap();
    assert!(lock.ra[0].dns.is_empty());
    let got = resolve(&format!("{LAN}\n[[ra]]\ninterface = \"wan\"\n")).unwrap_err();
    assert!(got.contains("no such interface"), "{got}");
}
