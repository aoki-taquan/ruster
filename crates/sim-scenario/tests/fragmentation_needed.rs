//! MTU1 (RFC 1812 §§4.2.2.7, 5.2.7.1, RFC 1191 §4): the egress MTU rule and
//! ICMP Fragmentation Needed end to end through `run_tick`, the validated
//! config (`[[interfaces]] mtu`, `[icmpv4-errors.generate]
//! fragmentation-needed`), and the publication. Every packet expectation is
//! in the scenario file (the ICMP bytes were computed separately); this
//! test also pins the final counters: no NAT mapping, query mapping, or
//! firewall state exists for a datagram that was not sent.

use std::path::Path;

use ruster_core::DropReason;
use ruster_sim_scenario::run_scenario_file;

#[test]
fn mtu1_scenario_answers_oversized_df_datagrams_with_fragmentation_needed() {
    let scenario = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/mtu1/scenario.toml");
    let mut out = Vec::new();
    let summary = run_scenario_file(&scenario, &mut out).expect("every expect step passes");
    assert_eq!(summary.generation.get(), 1);
    let drops = &summary.snapshot.drops;
    assert_eq!(drops.count(DropReason::Ipv4FragmentationNeeded), 4);
    assert_eq!(drops.count(DropReason::Ipv4FragmentationRequired), 1);
    assert_eq!(drops.count(DropReason::Nat44UdpNonAtomicIpv4Unsupported), 0);
    assert_eq!(drops.count(DropReason::Icmpv4EchoReplyExceedsMtu), 1);
    let output = String::from_utf8(out).expect("UTF-8");
    let start = output.lines().next().expect("start event");
    assert!(
        start.contains("\"mac\":\"02:00:00:00:00:01\",\"mtu\":120}")
            && start.contains("\"mac\":\"02:00:00:00:00:02\",\"mtu\":100}"),
        "{start}"
    );
    let last = output.lines().last().expect("final event");
    for (key, value) in [
        ("icmpv4_errors.queued_fragmentation_needed", 3),
        ("icmpv4_errors.dequeued_fragmentation_needed", 3),
        ("icmpv4_errors.rate_limited", 1),
        ("icmpv4_errors.disabled_fragmentation_needed", 0),
        ("nat44_udp.mappings_created", 1),
        ("nat44_icmp.mappings_created", 0),
        ("firewall.allowed_new", 1),
    ] {
        assert!(
            last.contains(&format!("\"{key}\":{value},")),
            "{key}={value} in {last}"
        );
    }
}
