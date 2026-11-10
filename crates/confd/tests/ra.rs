//! `[[ra]]`: what confd checks, and the part neighd takes.

use std::os::unix::net::UnixStream;

use ruster_confd::file::parse;
use ruster_confd::part::{Client, Module};
use ruster_confd::Confd;
use ruster_proto::task::Task;

const LAN: &str = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv6 = ["2001:db8:1::1/64", "2001:db8:2::1/56"]

[[interface]]
name = "lan.10"
parent = "lan"
vlan = 10

[[interface]]
name = "ds"
tunnel = { local = "2001:db8:1::1", remote = "2001:db8:ff::1" }
"#;

#[test]
fn ra_is_checked() {
    let good = format!("{LAN}\n[[ra]]\ninterface = \"lan\"\n");
    assert_eq!(parse(&good).unwrap().ra.len(), 1);
    // A VLAN without addresses still advertises itself as a router.
    let vlan = format!("{LAN}\n[[ra]]\ninterface = \"lan.10\"\n");
    assert!(parse(&vlan).unwrap().ra[0].prefix.is_empty());

    for (entry, error) in [
        ("interface = \"ds\"", "port or a VLAN"),
        ("interface = \"lan\"\nmax-interval = 3", "max-interval"),
        ("interface = \"lan\"\nmax-interval = 1801", "max-interval"),
        ("interface = \"lan\"\nmin-interval = 2", "min-interval"),
        ("interface = \"lan\"\nmin-interval = 451", "min-interval"),
        (
            "interface = \"lan\"\nrouter-lifetime = 599",
            "router-lifetime",
        ),
        (
            "interface = \"lan\"\nrouter-lifetime = 9001",
            "router-lifetime",
        ),
        ("interface = \"lan\"\nmtu = 1279", "mtu"),
        ("interface = \"lan\"\nmtu = 1501", "mtu"),
        (
            "interface = \"lan\"\nreachable-time = 3600001",
            "reachable-time",
        ),
        ("interface = \"lan\"\ndns = [\"ff02::1\"]", "dns"),
        ("interface = \"lan\"\ndns = [\"192.0.2.1\"]", "dns"),
        (
            "interface = \"lan\"\ndns = [\"2001:db8::53\"]\ndns-lifetime = 599",
            "dns-lifetime",
        ),
        (
            "interface = \"lan\"\nvalid-lifetime = 10\npreferred-lifetime = 20",
            "preferred-lifetime",
        ),
    ] {
        let text = format!("{LAN}\n[[ra]]\n{entry}\n");
        let got = parse(&text).unwrap_err();
        assert!(got.contains(error), "{entry}: {got}");
    }
    let small = LAN.replace("vlan = 10", "vlan = 10\nmtu = 1000");
    let got = parse(&format!("{small}\n[[ra]]\ninterface = \"lan.10\"\n")).unwrap_err();
    assert!(got.contains("at least 1280"), "{got}");
    assert!(parse(&format!("{good}\n[[ra]]\ninterface = \"lan\"\n"))
        .unwrap_err()
        .contains("given twice"));
    // router-lifetime 0: the router is not a default router.
    let zero = format!("{LAN}\n[[ra]]\ninterface = \"lan\"\nrouter-lifetime = 0\n");
    assert_eq!(parse(&zero).unwrap().ra[0].router_lifetime, 0);
}

#[test]
fn ra_lock_prefixes_must_be_the_interface_s() {
    let lock = ruster_config::resolve(&format!("{LAN}\n[[ra]]\ninterface = \"lan\"\n")).unwrap();
    let edit = |change: &dyn Fn(&mut ruster_config::Ra)| {
        let mut lock = lock.clone();
        change(&mut lock.ra[0]);
        parse(&lock.to_text())
    };
    assert!(edit(&|_| {}).is_ok());
    let prefix = |text: &str, autonomous: bool| ruster_config::RaPrefix {
        prefix: text.into(),
        on_link: true,
        autonomous,
        valid_lifetime: 100,
        preferred_lifetime: 50,
    };
    // The /56 may be advertised on-link, but not for SLAAC.
    assert!(edit(&|ra| ra.prefix.push(prefix("2001:db8:2::/56", false))).is_ok());
    for (bad, error) in [
        (prefix("2001:db8:2::/56", true), "a /64"),
        (prefix("2001:db8:9::/64", true), "interface's addresses"),
        (prefix("2001:db8:1::1/64", true), "no bits after"),
        (prefix("fe80::/64", true), "link-local"),
        (prefix("2001:db8:1::/64", true), "given twice"),
    ] {
        let got = edit(&|ra| ra.prefix.push(bad.clone())).unwrap_err();
        assert!(got.contains(error), "{bad:?}: {got}");
    }
    let got = edit(&|ra| ra.prefix_from.push("dhcpc-wan".into())).unwrap_err();
    assert!(got.contains("prefix-from"), "{got}");
}

#[test]
fn neighd_takes_the_ra_part() {
    let text = format!("{LAN}\n[[ra]]\ninterface = \"lan\"\n");
    let mut confd = Confd::new(parse(&text).unwrap());
    let (a, b) = UnixStream::pair().unwrap();
    confd.attach_part(Module::Ra, a).unwrap();
    let mut neighd = Client::new(b, Module::Ra).unwrap();
    let mut parts = Vec::new();
    let mut run = |confd: &mut Confd, parts: &mut Vec<String>| {
        for _ in 0..50 {
            confd.step(0);
            neighd
                .poll(&mut |part| {
                    parts.push(part.to_owned());
                    Ok(())
                })
                .unwrap();
        }
    };
    run(&mut confd, &mut parts);
    let ra = ruster_config::parse_ra_part(&parts[0]).unwrap();
    assert_eq!(ra[0].prefix[0].prefix, "2001:db8:1::/64");
    // Without [[ra]], the part is empty: neighd stops advertising.
    confd.set_config(parse(LAN).unwrap());
    run(&mut confd, &mut parts);
    assert!(ruster_config::parse_ra_part(parts.last().unwrap())
        .unwrap()
        .is_empty());
}
