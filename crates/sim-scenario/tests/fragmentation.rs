//! MTU2 part B (RFC 791 §3.2, RFC 1812 §4.2.2.7, NAT44-019L): DF-clear
//! datagrams above the WAN MTU leave as fragments after the NAT, end to end
//! through `run_tick`, the validated `[fragmentation]` config, and the
//! publication (`fixtures/mtu2b`). The scenario pins every fragment; this
//! test rebuilds each one here, independently of the router: the translated
//! datagram from the RFC 768/792 layouts with its own checksums (only the
//! generated ID is read from the first fragment), cut by this file's
//! RFC 791 procedure for a 576-byte MTU.

use std::path::Path;

use ruster_core::{ConsumeReason, DropReason};
use ruster_sim_scenario::run_scenario_file;

const PUBLIC: [u8; 4] = [203, 0, 113, 2];
const SERVER: [u8; 4] = [198, 51, 100, 20];
const GW_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];

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

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The scenario's payload pattern.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 13 + 7) as u8).collect()
}

/// The whole translated datagram as the router must send it before
/// fragmentation: TTL 63, DF clear, `id`.
fn translated(id: u16, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&GW_MAC);
    frame.extend_from_slice(&WAN_MAC);
    frame.extend_from_slice(&[0x08, 0x00]);
    let total = u16::try_from(20 + payload.len()).unwrap();
    let mut header = vec![0x45, 0];
    header.extend_from_slice(&total.to_be_bytes());
    header.extend_from_slice(&id.to_be_bytes());
    header.extend_from_slice(&[0, 0, 63, protocol, 0, 0]);
    header.extend_from_slice(&PUBLIC);
    header.extend_from_slice(&SERVER);
    let sum = checksum(&header);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    frame
}

fn udp(source_port: u16, data: &[u8]) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&source_port.to_be_bytes());
    segment.extend_from_slice(&53_u16.to_be_bytes());
    segment.extend_from_slice(&u16::try_from(8 + data.len()).unwrap().to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(data);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&PUBLIC);
    pseudo.extend_from_slice(&SERVER);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&u16::try_from(segment.len()).unwrap().to_be_bytes());
    pseudo.extend_from_slice(&segment);
    let sum = match checksum(&pseudo) {
        0 => 0xffff,
        sum => sum,
    };
    segment[6..8].copy_from_slice(&sum.to_be_bytes());
    segment
}

fn echo_request(identifier: u16, data: &[u8]) -> Vec<u8> {
    let mut message = vec![8, 0, 0, 0];
    message.extend_from_slice(&identifier.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    message.extend_from_slice(data);
    let sum = checksum(&message);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    message
}

/// RFC 791 §3.2 for a 20-byte header and `mtu`.
fn fragments(whole: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    let block = (mtu - 20) / 8 * 8;
    let data = &whole[34..];
    data.chunks(block)
        .enumerate()
        .map(|(index, chunk)| {
            let mut frame = whole[..34].to_vec();
            let last = (index + 1) * block >= data.len();
            let mut word = u16::try_from(index * block / 8).unwrap();
            if !last {
                word |= 0x2000;
            }
            frame[16..18].copy_from_slice(&u16::try_from(20 + chunk.len()).unwrap().to_be_bytes());
            frame[20..22].copy_from_slice(&word.to_be_bytes());
            frame[24..26].fill(0);
            let sum = checksum(&frame[14..34]);
            frame[24..26].copy_from_slice(&sum.to_be_bytes());
            frame.extend_from_slice(chunk);
            frame
        })
        .collect()
}

fn id(frame: &[u8]) -> u16 {
    u16::from_be_bytes([frame[18], frame[19]])
}

#[test]
fn mtu2b_scenario_fragments_df_clear_datagrams_after_the_nat() {
    let scenario = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/mtu2b/scenario.toml");
    let mut out = Vec::new();
    let summary = run_scenario_file(&scenario, &mut out).expect("every expect step passes");
    let output = String::from_utf8(out).expect("UTF-8");
    let tx = transmitted(&output);
    let at = |step: u64| -> Vec<Vec<u8>> {
        tx.iter()
            .filter(|(s, interface, _)| *s == step && interface == "wan")
            .map(|(.., frame)| frame.clone())
            .collect()
    };
    // Step 6: UDP from H:5000, translated to PUBLIC:40012 (the port the
    // seeded allocator picks; 5000 is outside the pool).
    let udp_fragments = at(6);
    let udp_id = id(&udp_fragments[0]);
    let expected = fragments(&translated(udp_id, 17, &udp(40_012, &pattern(972))), 576);
    assert_eq!(expected.len(), 2);
    assert_eq!(udp_fragments, expected);
    // Step 9: the Echo Request, identifier 40007 kept (identifier
    // preservation, N5).
    let icmp_fragments = at(9);
    let icmp_id = id(&icmp_fragments[0]);
    let expected = fragments(
        &translated(icmp_id, 1, &echo_request(40_007, &pattern(872))),
        576,
    );
    assert_eq!(icmp_fragments, expected);
    // Step 16: the next datagram of the UDP tuple: the next generated ID.
    let again = at(16);
    assert_eq!(id(&again[0]), udp_id.wrapping_add(1));
    assert_eq!(
        again,
        fragments(
            &translated(udp_id.wrapping_add(1), 17, &udp(40_012, &pattern(972))),
            576
        )
    );
    let drops = &summary.snapshot.drops;
    assert_eq!(
        drops.count(DropReason::Ipv4FragmentationTooManyFragments),
        1
    );
    assert_eq!(drops.count(DropReason::Ipv4FragmentationQueueFull), 1);
    assert_eq!(drops.count(DropReason::Ipv4FragmentationRequired), 0);
    assert_eq!(
        summary
            .snapshot
            .consumes
            .count(ConsumeReason::Ipv4Fragmented),
        3
    );
    let last = output.lines().last().expect("final event");
    for (key, value) in [
        // Only H:5000 got a mapping: the refused datagrams (5002, 5003)
        // committed none.
        ("nat44_udp.mappings_created", 1),
        ("nat44_icmp.mappings_created", 1),
        ("fragmentation.queued", 3),
        ("fragmentation.fragmented", 3),
        ("fragmentation.fragments", 6),
        ("fragmentation.dropped_unavailable", 0),
        ("generated_fragments.sessions", 3),
        ("generated_fragments.tx_accepted", 6),
    ] {
        assert!(
            last.contains(&format!("\"{key}\":{value},"))
                || last.contains(&format!("\"{key}\":{value}}}")),
            "{key}={value} in {last}"
        );
    }
}
