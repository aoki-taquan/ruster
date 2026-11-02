//! N5 (RFC 5508 §3): ICMP query NAT end to end through `run_tick`, the
//! validated config (`[nat44.icmp]`, an `icmp` firewall rule), the
//! publication, a reloadable filtering change, and a restart-required
//! removal. Every packet expectation is in the scenario file; this test also
//! pins the final ICMP query counters and the flush of the reload.

use std::path::Path;

use ruster_core::DropReason;
use ruster_sim_scenario::run_scenario_file;

#[test]
fn n5_scenario_translates_answers_filters_and_reloads() {
    let scenario = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/n5/scenario.toml");
    let mut out = Vec::new();
    let summary = run_scenario_file(&scenario, &mut out).expect("every expect step passes");
    assert_eq!(summary.generation.get(), 2);
    let drops = &summary.snapshot.drops;
    assert_eq!(drops.count(DropReason::Nat44IcmpMappingMiss), 1);
    assert_eq!(drops.count(DropReason::Nat44IcmpFilterDenied), 1);
    assert_eq!(drops.count(DropReason::FirewallDefaultDenied), 1);
    let output = String::from_utf8(out).expect("UTF-8");
    assert!(
        output.contains("\"nat44_icmp\":{\"mappings\":8,\"peers\":16,\"identifier_owners\":16}")
    );
    let applied = output
        .lines()
        .find(|line| line.contains("\"outcome\":\"applied\""))
        .expect("apply event");
    assert!(
        applied.contains("\"nat44_icmp_mappings\":1,\"nat44_icmp_peers\":1,"),
        "{applied}"
    );
    let rejected = output
        .lines()
        .find(|line| line.contains("\"outcome\":\"rejected\""))
        .expect("rejected apply");
    assert!(
        rejected.contains("\"code\":\"STORAGE_SHAPE\""),
        "{rejected}"
    );
    let last = output.lines().last().expect("final event");
    for (key, value) in [
        ("nat44_icmp.outbound_translated", 2),
        ("nat44_icmp.inbound_translated", 1),
        ("nat44_icmp.mappings_created", 2),
        ("nat44_icmp.mapping_misses", 1),
        ("nat44_icmp.filter_denied", 1),
        ("nat44_icmp.reconciliations", 1),
    ] {
        assert!(
            last.contains(&format!("\"{key}\":{value},")),
            "{key}={value} in {last}"
        );
    }
}
