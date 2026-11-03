//! ARP-HOLD (RFC 1122 §2.3.2.2, RFC 1812 §3.3.2): fixtures/arphold runs a
//! router with the default `[resolution.hold]` through the validated config,
//! the publication, and `run_tick` on SimIo. Every packet expectation is in
//! the scenario file (the first ping and the first TCP SYN replayed without
//! a retransmission, the latest three datagrams per next hop, Host
//! Unreachable for a silent next hop, a reload dropping a held datagram);
//! this test pins the final drop counts and `arp_hold` counters.

use std::path::Path;

use ruster_core::{ConsumeReason, DropReason};
use ruster_sim_scenario::run_scenario_file;

#[test]
fn arphold_scenario_holds_and_replays_first_datagrams() {
    let scenario =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/arphold/scenario.toml");
    let mut out = Vec::new();
    let summary = run_scenario_file(&scenario, &mut out).expect("every expect step passes");
    assert_eq!(summary.generation.get(), 2);
    assert_eq!(
        summary.snapshot.drops.count(DropReason::NeighborUnresolved),
        0
    );
    assert_eq!(summary.snapshot.drops.total(), 0);
    assert_eq!(summary.snapshot.consumes.count(ConsumeReason::ArpHeld), 8);
    let output = String::from_utf8(out).expect("UTF-8");
    let last = output.lines().last().expect("final event");
    for (key, value) in [
        ("arp_hold.held", 8),
        ("arp_hold.replaced", 1),
        ("arp_hold.replayed", 5),
        ("arp_hold.replay_sent", 5),
        ("arp_hold.replay_dropped", 0),
        ("arp_hold.expired", 1),
        ("arp_hold.failed", 0),
        ("arp_hold.flushed", 1),
        ("consume.ARP_HELD", 8),
    ] {
        let field = format!("\"{key}\":{value}");
        assert!(
            last.contains(&format!("{field},")) || last.contains(&format!("{field}}}")),
            "{key}={value} in {last}"
        );
    }
}
