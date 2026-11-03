//! RELOAD-CARRY end to end through `run_tick`, the validated config, the
//! sequencer, and the publication: established UDP and TCP NAT44 flows and
//! the learned gateway survive a reload that changes the firewall rules
//! without affecting them, and a reload whose rules deny the DNS flow
//! revokes exactly that flow. Every packet expectation is in the scenario
//! file; this test pins the apply events.

use std::path::Path;

use ruster_sim_scenario::run_scenario_file;

#[test]
fn reload_carry_scenario_keeps_unaffected_flows_and_revokes_denied_ones() {
    let scenario =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/reload-carry/scenario.toml");
    let mut out = Vec::new();
    let summary = run_scenario_file(&scenario, &mut out).expect("every expect step passes");
    assert_eq!(summary.generation.get(), 3);
    let output = String::from_utf8(out).expect("UTF-8");
    let applied: Vec<&str> = output
        .lines()
        .filter(|line| line.contains("\"event\":\"apply\""))
        .collect();
    assert_eq!(applied.len(), 2, "{output}");
    let carried_everything = "\"carry\":{\"resolution\":\"carried\",\"nat44_udp\":\"carried\",\
         \"nat44_tcp\":\"carried\",\"nat44_icmp\":null,\"firewall\":\"carried\",";
    for line in &applied {
        assert!(line.contains(carried_everything), "{line}");
        // Nothing but pending resolution and ICMPv4 work is flushed.
        for flushed in [
            "\"dynamic_neighbors\":0,",
            "\"nat44_udp_mappings\":0,",
            "\"nat44_tcp_sessions\":0,",
            "\"firewall_flows\":0}",
        ] {
            assert!(line.contains(flushed), "{flushed} in {line}");
        }
    }
    // The unrelated rule keeps both flows; the DNS deny revokes one.
    assert!(
        applied[0].contains(
            "\"dynamic_neighbors\":1,\"nat44_udp_mappings\":1,\"nat44_udp_peers\":1,\
             \"nat44_tcp_mappings\":1,\"nat44_tcp_sessions\":1,\"nat44_icmp_mappings\":0,\
             \"nat44_icmp_peers\":0,\"firewall_flows\":2,\"firewall_flows_revoked\":0}"
        ),
        "{}",
        applied[0]
    );
    assert!(
        applied[1].contains("\"firewall_flows\":1,\"firewall_flows_revoked\":1}"),
        "{}",
        applied[1]
    );
    let last = output.lines().last().expect("final event");
    assert!(last.contains("\"firewall.states_revoked\":1"), "{last}");
    assert!(
        last.contains("\"carried.firewall_flows_revoked\":1"),
        "{last}"
    );
}
