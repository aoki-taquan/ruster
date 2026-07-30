use super::envelope::{
    CaseEnvelope, DropCode, Expected, ParserAccept, ResolutionSummary, Target, MAX_CORPUS_CASES,
};

pub struct NamedCase {
    pub name: &'static str,
    pub encoded: Vec<u8>,
}

pub fn past_regressions() -> Vec<NamedCase> {
    let cases = vec![
        parser_vlan(),
        parser_reserved_flag(),
        checksum_rfc1071(),
        checksum_odd_length(),
        admission_other_interface_mac(),
        admission_local_source_claim(),
        admission_arp_foreign_destination(),
        resolution_cancel_and_reuse(),
        resolution_zero_action_capacity(),
    ];
    assert!(
        cases.len() <= MAX_CORPUS_CASES,
        "static corpus exceeds {MAX_CORPUS_CASES}-case v1 bound"
    );
    cases
}

fn parser_vlan() -> NamedCase {
    let mut frame = vec![0_u8; 14];
    frame[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
    encoded(
        "vlan-inner-frame-not-parsed",
        Target::Parser,
        0,
        0,
        Expected::Drop(DropCode::new(2).unwrap()),
        frame,
    )
}

fn parser_reserved_flag() -> NamedCase {
    let frame = ipv4_frame(
        [0x02, 0, 0, 0, 0, 0x10],
        [0x02, 0, 0, 0, 0, 0x40],
        [192, 0, 2, 10],
        [198, 51, 100, 20],
        0x8000,
        64,
    );
    encoded(
        "reserved-ipv4-flag-parser-accept",
        Target::Parser,
        1,
        1,
        Expected::ParserAccept(ParserAccept {
            header_len: 20,
            total_len: 20,
            ttl: 64,
            protocol: 17,
            source: [192, 0, 2, 10],
            destination: [198, 51, 100, 20],
            checksum: read_be_u16(&frame, 24),
        }),
        frame,
    )
}

fn checksum_rfc1071() -> NamedCase {
    encoded(
        "rfc1071-known-vector",
        Target::Checksum,
        2,
        2,
        Expected::Checksum(0x220d),
        vec![0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7],
    )
}

fn checksum_odd_length() -> NamedCase {
    encoded(
        "odd-length-high-byte-padding",
        Target::Checksum,
        3,
        3,
        Expected::Checksum(0xfbfd),
        vec![0x01, 0x02, 0x03],
    )
}

fn admission_other_interface_mac() -> NamedCase {
    let frame = ipv4_frame(
        [0x02, 0, 0, 0, 0, 0x20],
        [0x02, 0, 0, 0, 0, 0x40],
        [192, 0, 2, 10],
        [198, 51, 100, 20],
        0x4000,
        64,
    );
    encoded(
        "cross-interface-router-mac",
        Target::Admission,
        4,
        4,
        Expected::Drop(DropCode::new(138).unwrap()),
        frame,
    )
}

fn admission_local_source_claim() -> NamedCase {
    let frame = ipv4_frame(
        [0x02, 0, 0, 0, 0, 0x10],
        [0x02, 0, 0, 0, 0, 0x40],
        [192, 0, 2, 1],
        [198, 51, 100, 20],
        0x4000,
        64,
    );
    encoded(
        "local-ipv4-source-claim",
        Target::Admission,
        5,
        5,
        Expected::Drop(DropCode::new(145).unwrap()),
        frame,
    )
}

fn admission_arp_foreign_destination() -> NamedCase {
    let mut frame = vec![0_u8; 60];
    frame[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x20]);
    frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x40]);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
    frame[22..28].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x41]);
    frame[28..32].copy_from_slice(&[192, 0, 2, 10]);
    frame[38..42].copy_from_slice(&[192, 0, 2, 1]);
    encoded(
        "arp-foreign-unicast-before-merge",
        Target::Admission,
        6,
        6,
        Expected::Drop(DropCode::new(138).unwrap()),
        frame,
    )
}

fn resolution_cancel_and_reuse() -> NamedCase {
    let payload = vec![
        2, 2, 2, 6, // capacities and operation count
        0, 0, // miss target 0
        0, 0, // duplicate miss target 0
        0, 1, // miss target 1
        1, 0, // learn target 0
        2, 7, // invalid future frame cannot poison time
        0, 2, // reuse the cancelled state/action capacity
    ];
    encoded(
        "resolution-cancel-reuse-and-invalid-future",
        Target::Resolution,
        7,
        7,
        Expected::Resolution(ResolutionSummary {
            pending_states: 2,
            pending_actions: 2,
            dynamic_neighbors: 1,
            queued: 3,
            suppressed: 1,
            state_full: 0,
            action_full: 0,
            clock_regressions: 0,
        }),
        payload,
    )
}

fn resolution_zero_action_capacity() -> NamedCase {
    let payload = vec![
        1, 0, 0, 2, // capacities and operation count
        0, 0, // miss has a state slot but no action slot
        1, 0, // cache full learning does not invent/cancel state
    ];
    encoded(
        "resolution-zero-action-and-cache-capacity",
        Target::Resolution,
        8,
        8,
        Expected::Resolution(ResolutionSummary {
            pending_states: 0,
            pending_actions: 0,
            dynamic_neighbors: 0,
            queued: 0,
            suppressed: 0,
            state_full: 0,
            action_full: 1,
            clock_regressions: 0,
        }),
        payload,
    )
}

fn encoded(
    name: &'static str,
    target: Target,
    seed: u64,
    case_index: u64,
    expected: Expected,
    payload: Vec<u8>,
) -> NamedCase {
    let encoded = CaseEnvelope {
        target,
        seed,
        case_index,
        now: 100,
        ingress: 1,
        expected,
        payload: &payload,
    }
    .encode()
    .unwrap();
    NamedCase { name, encoded }
}

fn ipv4_frame(
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    source: [u8; 4],
    destination: [u8; 4],
    flags_offset: u16,
    ttl: u8,
) -> Vec<u8> {
    let mut frame = vec![0_u8; 34];
    frame[0..6].copy_from_slice(&destination_mac);
    frame[6..12].copy_from_slice(&source_mac);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&20_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_offset.to_be_bytes());
    frame[22] = ttl;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&source);
    frame[30..34].copy_from_slice(&destination);
    let checksum = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u64;
    for chunk in bytes.chunks(2) {
        sum += if chunk.len() == 2 {
            u64::from(u16::from_be_bytes([chunk[0], chunk[1]]))
        } else {
            u64::from(chunk[0]) << 8
        };
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn read_be_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
