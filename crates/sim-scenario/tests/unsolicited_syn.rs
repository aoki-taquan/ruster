//! B3 (RFC 5382 REQ-4, NAT44-038): the delayed ICMP Port Unreachable for
//! unsolicited inbound TCP SYNs end to end through `run_tick`, the
//! validated config, and a reloadable switch. Every expectation is in the
//! scenario file; this test also pins the final counters.

use std::path::Path;

use ruster_core::DropReason;
use ruster_sim_scenario::run_scenario_file;

#[test]
fn b3_scenario_holds_answers_cancels_and_switches_off() {
    let scenario = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/b3/scenario.toml");
    let mut out = Vec::new();
    let summary = run_scenario_file(&scenario, &mut out).expect("every expect step passes");
    assert_eq!(summary.generation.get(), 2);
    assert_eq!(
        summary
            .snapshot
            .drops
            .count(DropReason::Nat44TcpMappingMiss),
        3
    );
    let output = String::from_utf8(out).expect("UTF-8");
    let last = output.lines().last().expect("final event");
    for (key, value) in [
        ("nat44_tcp.unsolicited_syn_held", 2),
        ("nat44_tcp.unsolicited_syn_cancelled", 1),
        ("nat44_tcp.unsolicited_syn_icmp_queued", 1),
        ("nat44_tcp.unsolicited_syn_icmp_suppressed", 0),
        ("nat44_tcp.unsolicited_syn_superseded", 0),
        ("icmpv4_errors.dequeued_port_unreachable", 1),
    ] {
        assert!(
            last.contains(&format!("\"{key}\":{value},")),
            "{key}={value} in {last}"
        );
    }
    // Exactly one generated ICMPv4 frame in the whole run.
    assert_eq!(output.matches("\"generated_icmpv4\":1").count(), 1);
}
