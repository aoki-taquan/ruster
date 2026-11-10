//! `[isis]`, `[ospf]` and `[ospf6]`: the defaults, the lock form and `ruster-frr`'s
//! part.

use ruster_config::{frr_part, parse_frr_part, parse_lock, resolve, Frr, IsisInterface};

const WAN: &str = r#"
[[interface]]
name = "red"
mac = "02:00:00:00:00:09"
ipv4 = "10.9.0.1/24"
vrf = "red"

[[interface]]
name = "wan"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.1/24"
"#;

#[test]
fn isis_and_ospf_take_their_defaults() {
    let text = format!(
        "{WAN}
[isis]
net = \"49.0001.1921.6800.1001.00\"

[[isis.interface]]
name = \"wan\"

[ospf]
area = \"0.0.0.1\"

[[ospf.interface]]
name = \"wan\"

[[ospf.interface]]
name = \"lan\"
area = \"0.0.0.0\"
cost = 20
network = \"point-to-point\"
passive = true

[ospf6]
router-id = \"10.0.0.1\"

[[ospf6.interface]]
name = \"wan\"
"
    );
    let lock = resolve(&text).unwrap();
    let [isis] = &lock.isis[..] else {
        panic!("{:?}", lock.isis)
    };
    assert_eq!(isis.level, "level-1-2");
    assert_eq!(
        isis.interface,
        [IsisInterface {
            name: "wan".into(),
            metric: 10,
            passive: false
        }]
    );
    let [ospf] = &lock.ospf[..] else {
        panic!("{:?}", lock.ospf)
    };
    assert_eq!(ospf.router_id, "198.51.100.1", "the default VRF's first");
    let wan = &ospf.interface[0];
    assert_eq!(
        (
            wan.area.as_str(),
            wan.cost,
            wan.network.as_str(),
            wan.passive
        ),
        ("0.0.0.1", 10, "broadcast", false),
        "the top's area"
    );
    let lan = &ospf.interface[1];
    assert_eq!(
        (
            lan.area.as_str(),
            lan.cost,
            lan.network.as_str(),
            lan.passive
        ),
        ("0.0.0.0", 20, "point-to-point", true)
    );
    assert_eq!(lock.ospf6[0].router_id, "10.0.0.1");
    assert_eq!(lock.ospf6[0].interface[0].area, "0.0.0.0");
    assert_eq!(parse_lock(&lock.to_text()).unwrap(), lock);

    let frr = Frr {
        isis: lock.isis.first().cloned(),
        ospf: lock.ospf.first().cloned(),
        ospf6: lock.ospf6.first().cloned(),
        ..Frr::default()
    };
    assert_eq!(parse_frr_part(&frr_part(&frr)).unwrap(), frr);
}

#[test]
fn ospf_needs_a_router_id_from_somewhere() {
    let text = "[[interface]]\nname = \"red\"\nmac = \"02:00:00:00:00:09\"\nvrf = \"red\"\nipv4 = \"10.9.0.1/24\"\n\n[ospf6]\n";
    let error = resolve(text).unwrap_err();
    assert!(error.contains("ospf6: give router-id"), "{error}");
}

#[test]
fn a_lock_form_from_before_isis_and_ospf_still_reads() {
    let lock = resolve(WAN).unwrap();
    let text = lock.to_text();
    assert!(text.contains("isis = []\n"), "{text}");
    let before = text
        .lines()
        .filter(|l| !l.starts_with("isis") && !l.starts_with("ospf"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(parse_lock(&before).unwrap(), lock);
}
