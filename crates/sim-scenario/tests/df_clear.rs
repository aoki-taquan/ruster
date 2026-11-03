//! MTU2 part A (NAT44-008, NAT44-126, RFC 6864 §5.3.1): NAT44 translates
//! whole DF-clear datagrams of UDP, TCP and ICMP queries end to end through
//! `run_tick`, the validated config, and the publication
//! (`fixtures/mtu2a`). The scenario file pins every byte; this test checks
//! the ID policy on the transmitted frames independently of the pinned
//! values: two DF-clear datagrams of one translated tuple get consecutive
//! IDs although the host sent the same ID, an atomic datagram keeps the ID
//! the host sent, and a fragment stays refused.

use std::path::Path;

use ruster_core::DropReason;
use ruster_sim_scenario::run_scenario_file;

/// (step, interface, frame bytes) of every transmitted frame.
fn transmitted(output: &str) -> Vec<(u64, String, Vec<u8>)> {
    output
        .lines()
        .filter(|line| line.starts_with("{\"event\":\"tx\""))
        .map(|line| {
            let field = |name: &str| {
                let start = line.find(&format!("\"{name}\":")).unwrap() + name.len() + 3;
                let rest = &line[start..];
                let end = rest.find([',', '}']).unwrap();
                rest[..end].trim_matches('"').to_owned()
            };
            let hex = field("hex");
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            (field("step").parse().unwrap(), field("interface"), bytes)
        })
        .collect()
}

fn id(frame: &[u8]) -> u16 {
    u16::from_be_bytes([frame[18], frame[19]])
}

fn df(frame: &[u8]) -> bool {
    frame[20] & 0x40 != 0
}

#[test]
fn mtu2a_scenario_translates_df_clear_datagrams_with_generated_ids() {
    let scenario = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/mtu2a/scenario.toml");
    let mut out = Vec::new();
    let summary = run_scenario_file(&scenario, &mut out).expect("every expect step passes");
    let output = String::from_utf8(out).expect("UTF-8");
    let tx = transmitted(&output);
    let udp_out: Vec<_> = tx.iter().filter(|(step, ..)| *step == 8).collect();
    assert_eq!(udp_out.len(), 3);
    assert!(!df(&udp_out[0].2) && !df(&udp_out[1].2) && df(&udp_out[2].2));
    // Both DF-clear datagrams carried host ID 100.
    assert_eq!(id(&udp_out[1].2), id(&udp_out[0].2).wrapping_add(1));
    assert_eq!(id(&udp_out[2].2), 102, "atomic: the host's ID");
    // Every DF-clear datagram (UDP out twice and in, TCP and ICMP both ways)
    // was translated and left without DF.
    let df_clear = tx
        .iter()
        .filter(|(.., frame)| frame[12..14] == [8, 0] && !df(frame))
        .count();
    assert_eq!(df_clear, 7);
    let drops = &summary.snapshot.drops;
    assert_eq!(drops.count(DropReason::FirewallFragmentUnsupported), 1);
    assert_eq!(drops.count(DropReason::Nat44UdpNonAtomicIpv4Unsupported), 0);
    assert_eq!(drops.count(DropReason::Nat44TcpNonAtomicIpv4Unsupported), 0);
    let last = output.lines().last().expect("final event");
    for (key, value) in [
        ("nat44_udp.mappings_created", 1),
        ("nat44_tcp.mappings_created", 1),
        ("nat44_icmp.mappings_created", 1),
    ] {
        assert!(
            last.contains(&format!("\"{key}\":{value},")),
            "{key}={value} in {last}"
        );
    }
}
