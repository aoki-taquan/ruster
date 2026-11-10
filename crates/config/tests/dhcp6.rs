//! `[[dhcp6]]`: the values that follow from the interface, and the defaults.

use ruster_config::{dhcp_part, parse_dhcp_part, parse_lock, resolve};

const LAN: &str = r#"
[[interface]]
name = "lan"
mac = "02:00:00:00:00:01"
ipv6 = ["fe80::5/64", "2001:db8:1::1/64", "2001:db8:2::1/64"]
"#;

#[test]
fn dhcp6_takes_the_interface_s_first_global_address() {
    let text = format!(
        "{LAN}\n[dns]\nlisten = [\"lan\"]\n\n[[dhcp6]]\ninterface = \"lan\"\npool = \"2001:db8:1::1000-2001:db8:1::1fff\"\n"
    );
    let lock = resolve(&text).unwrap();
    let [d] = &lock.dhcp6[..] else {
        panic!("{:?}", lock.dhcp6)
    };
    assert_eq!(d.mac, "02:00:00:00:00:01");
    assert_eq!(d.link_local, "fe80::ff:fe00:1");
    assert_eq!(d.address, "2001:db8:1::1/64");
    assert_eq!((d.preferred_lifetime, d.valid_lifetime), (3_600, 7_200));
    assert_eq!(
        d.dns,
        ["2001:db8:1::1", "2001:db8:2::1"],
        "[dns] listens on lan"
    );
    assert_eq!((d.punt_rate, d.punt_burst), (200, 100));
    assert_eq!(parse_lock(&lock.to_text()).unwrap(), lock);
    let part = dhcp_part(&lock.dhcp, &lock.dhcp6);
    assert_eq!(
        parse_dhcp_part(&part).unwrap(),
        (Vec::new(), lock.dhcp6.clone())
    );

    let given = format!(
        "{LAN}\n[[dhcp6]]\ninterface = \"lan\"\npool = \"2001:db8:1::1000-2001:db8:1::1fff\"\npreferred-lifetime = 600\nvalid-lifetime = 1200\ndns = [\"2001:db8::53\"]\npunt-rate = 5\npunt-burst = 6\n"
    );
    let d = &resolve(&given).unwrap().dhcp6[0];
    assert_eq!((d.preferred_lifetime, d.valid_lifetime), (600, 1_200));
    assert_eq!(d.dns, ["2001:db8::53"]);
    assert_eq!((d.punt_rate, d.punt_burst), (5, 6));
}

#[test]
fn dhcp6_needs_an_interface_with_a_global_address() {
    let only_link_local = LAN.replace(", \"2001:db8:1::1/64\", \"2001:db8:2::1/64\"", "");
    for (text, error) in [
        (LAN.to_owned(), "no such interface"),
        (only_link_local, "no global ipv6 address"),
    ] {
        let interface = if error == "no such interface" {
            "wan"
        } else {
            "lan"
        };
        let text = format!("{text}\n[[dhcp6]]\ninterface = \"{interface}\"\npool = \"2001:db8:1::10-2001:db8:1::20\"\n");
        let got = resolve(&text).unwrap_err();
        assert!(got.contains(error), "{got}");
    }
}
