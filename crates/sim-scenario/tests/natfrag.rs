//! NAT-FRAG (RFC 4787 REQ-14, RFC 1858): fragments of one datagram through
//! the stateful firewall and the NAT, end to end through `run_tick`, the
//! validated `[fragment-tracking]` config, and the publication
//! (`fixtures/natfrag`). The scenario does not pin the forwarded fragments;
//! this test rebuilds each translated datagram here, independently of the
//! router (RFC 768/792 layouts with this file's own checksums; only the
//! generated ID and, for ICMP, the mapped identifier are read from the
//! output), checks every fragment against the sender's cut, and
//! reassembles them.

use std::path::Path;

use ruster_sim_scenario::run_scenario_file;

const H: [u8; 4] = [192, 168, 1, 10];
const PUBLIC: [u8; 4] = [203, 0, 113, 2];
const SERVER: [u8; 4] = [198, 51, 100, 20];
const H_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];
const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const GW_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
/// The public port of H:5000 (the NAT's keyed choice in this scenario).
const PUBLIC_PORT: u16 = 40_001;

struct Tx {
    step: u64,
    interface: String,
    origin: String,
    bytes: Vec<u8>,
}

fn transmitted(output: &str) -> Vec<Tx> {
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
            Tx {
                step: field("step").parse().unwrap(),
                interface: field("interface"),
                origin: field("origin"),
                bytes: (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect(),
            }
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

/// The scenario generator's data pattern.
fn pattern(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|i| (i * seed + 7) as u8).collect()
}

fn udp(source: [u8; 4], destination: [u8; 4], ports: (u16, u16), data: &[u8]) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&ports.0.to_be_bytes());
    segment.extend_from_slice(&ports.1.to_be_bytes());
    segment.extend_from_slice(&u16::try_from(8 + data.len()).unwrap().to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(data);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&source);
    pseudo.extend_from_slice(&destination);
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

/// The whole datagram as the router must forward it: `macs`, TTL `ttl`,
/// DF clear, `id`.
fn datagram(
    macs: ([u8; 6], [u8; 6]),
    addresses: ([u8; 4], [u8; 4]),
    id: u16,
    ttl: u8,
    protocol: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&macs.0);
    frame.extend_from_slice(&macs.1);
    frame.extend_from_slice(&[0x08, 0x00]);
    let total = u16::try_from(20 + payload.len()).unwrap();
    let mut header = vec![0x45, 0];
    header.extend_from_slice(&total.to_be_bytes());
    header.extend_from_slice(&id.to_be_bytes());
    header.extend_from_slice(&[0, 0, ttl, protocol, 0, 0]);
    header.extend_from_slice(&addresses.0);
    header.extend_from_slice(&addresses.1);
    let sum = checksum(&header);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    frame
}

/// RFC 791 §3.2 cut of `whole` at the sender's `sizes`.
fn cut(whole: &[u8], sizes: &[usize]) -> Vec<Vec<u8>> {
    let mut start = 0;
    sizes
        .iter()
        .enumerate()
        .map(|(index, &len)| {
            let more = index + 1 < sizes.len();
            let mut frame = whole[..34].to_vec();
            let word = u16::from(more) << 13 | u16::try_from(start / 8).unwrap();
            frame[16..18].copy_from_slice(&u16::try_from(20 + len).unwrap().to_be_bytes());
            frame[20..22].copy_from_slice(&word.to_be_bytes());
            frame[24..26].fill(0);
            let sum = checksum(&frame[14..34]);
            frame[24..26].copy_from_slice(&sum.to_be_bytes());
            frame.extend_from_slice(&whole[34 + start..34 + start + len]);
            start += len;
            frame
        })
        .collect()
}

fn id(frame: &[u8]) -> u16 {
    u16::from_be_bytes([frame[18], frame[19]])
}

/// The frames of `step`, sorted by fragment offset; every one on
/// `interface` with one ID and a valid header checksum.
fn step_frames(tx: &[Tx], step: u64, interface: &str) -> (Vec<Vec<u8>>, u16) {
    let mut frames: Vec<Vec<u8>> = tx
        .iter()
        .filter(|tx| tx.step == step)
        .inspect(|tx| assert_eq!(tx.interface, interface, "step {step}"))
        .map(|tx| tx.bytes.clone())
        .collect();
    frames.sort_by_key(|frame| u16::from_be_bytes([frame[20], frame[21]]) & 0x1fff);
    let first = id(&frames[0]);
    for frame in &frames {
        assert_eq!(id(frame), first, "step {step}: one ID per datagram");
        assert_eq!(checksum(&frame[14..34]), 0, "step {step}: header checksum");
    }
    (frames, first)
}

#[test]
fn natfrag_scenario_associates_fragments_in_and_out_of_order() {
    let scenario =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/natfrag/scenario.toml");
    let mut out = Vec::new();
    run_scenario_file(&scenario, &mut out).expect("every expect step passes");
    let output = String::from_utf8(out).expect("UTF-8");
    let tx = transmitted(&output);
    let sizes = [1480, 1480, 20];

    // Step 2 (inject steps 6-8, tick 8): in order, forwarded as received.
    let outbound = udp(PUBLIC, SERVER, (PUBLIC_PORT, 53), &pattern(2972, 13));
    let (frames, first_id) = step_frames(&tx, 8, "wan");
    let expected = datagram(
        (GW_MAC, WAN_MAC),
        (PUBLIC, SERVER),
        first_id,
        63,
        17,
        &outbound,
    );
    assert_eq!(frames, cut(&expected, &sizes));
    assert!(tx
        .iter()
        .filter(|tx| tx.step == 8)
        .all(|tx| tx.origin == "forwarded"));

    // Step 3 (tick 15): the first fragment forwarded, the two held ones
    // released through the generated fragment phase, the next ID.
    let (frames, second_id) = step_frames(&tx, 15, "wan");
    assert_eq!(second_id, first_id.wrapping_add(1));
    let expected = datagram(
        (GW_MAC, WAN_MAC),
        (PUBLIC, SERVER),
        second_id,
        63,
        17,
        &outbound,
    );
    assert_eq!(frames, cut(&expected, &sizes));
    let origins: Vec<&str> = tx
        .iter()
        .filter(|tx| tx.step == 15)
        .map(|tx| tx.origin.as_str())
        .collect();
    assert_eq!(origins, ["forwarded", "generated", "generated"]);

    // Step 4 (tick 21): inbound, translated to H:5000 with an inbound ID.
    let inbound = udp(SERVER, H, (53, 5000), &pattern(1972, 7));
    let (frames, inbound_id) = step_frames(&tx, 21, "lan");
    let expected = datagram((H_MAC, LAN_MAC), (SERVER, H), inbound_id, 59, 17, &inbound);
    assert_eq!(frames, cut(&expected, &[1480, 500]));

    // Steps 5 and 6 sent nothing; step 7 (tick 33): the Echo Request with
    // the mapping's identifier.
    assert!(tx
        .iter()
        .all(|tx| !(26..=33).contains(&tx.step) || tx.step == 33));
    let (frames, echo_id) = step_frames(&tx, 33, "wan");
    let identifier = u16::from_be_bytes([frames[0][38], frames[0][39]]);
    let expected = datagram(
        (GW_MAC, WAN_MAC),
        (PUBLIC, SERVER),
        echo_id,
        63,
        1,
        &echo_request(identifier, &pattern(3000, 5)),
    );
    assert_eq!(frames, cut(&expected, &[1480, 1480, 48]));
    // Nothing after the ping: the late fragments of step 8 are held.
    assert!(tx.iter().all(|tx| tx.step <= 33));

    let last = output.lines().last().unwrap();
    for counter in [
        "\"fragment_tracking.first_allowed\":4",
        "\"fragment_tracking.first_denied\":1",
        "\"fragment_tracking.followed\":4",
        "\"fragment_tracking.followed_denied\":1",
        "\"fragment_tracking.held\":5",
        "\"fragment_tracking.released\":3",
        "\"fragment_tracking.held_expired\":1",
        "\"fragment_tracking.entries_expired\":1",
        "\"fragmentation.whole\":3",
        "\"consume.IPV4_FRAGMENT_HELD\":5",
        "\"drop.FIREWALL_FRAGMENT_UNSUPPORTED\":0",
    ] {
        assert!(last.contains(counter), "{counter}");
    }
}
