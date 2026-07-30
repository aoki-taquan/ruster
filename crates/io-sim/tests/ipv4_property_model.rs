use ruster_core::{
    forward_batch_with_resolution, validate_ipv4_frame, DropReason, DynamicNeighborSlot,
    ForwardingSnapshot, IfId, Interface, Ipv4Address, LocalIpv4Binding, MacAddress,
    MonotonicMillis, Neighbor, NoTrace, PacketIo, ResolutionActionSlot, ResolutionPolicy,
    ResolutionRuntime, ResolutionStateSlot, Route, ETHERNET_HEADER_LEN,
};
use ruster_io_sim::{RecycleCause, SimIo};

const MODEL_SEED: u64 = 0x6a09_e667_f3bc_c909;
const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const UNKNOWN: IfId = IfId(99);
const LAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x10]);
const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x20]);
const NEXT_HOP_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x30]);
const PEER_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x40]);
const ARP_SHA: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x41]);
const LOCAL_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const PEER_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 10]);
const DESTINATION: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const GATEWAY: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeaderModel {
    header_len: usize,
    total_len: usize,
    ttl: u8,
    protocol: u8,
    source: Ipv4Address,
    destination: Ipv4Address,
    checksum: u16,
}

#[derive(Clone, Copy)]
struct DeterministicRng(u64);

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u32(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        u32::try_from(self.0 >> 32).unwrap()
    }

    fn below(&mut self, exclusive_upper: usize) -> usize {
        assert!(exclusive_upper != 0);
        usize::try_from(self.next_u32()).unwrap() % exclusive_upper
    }

    fn byte(&mut self) -> u8 {
        self.next_u32().to_le_bytes()[0]
    }
}

fn read_be_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let word = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([word[0], word[1]]))
}

fn oracle_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u64;
    let mut pairs = bytes.chunks_exact(2);
    for pair in &mut pairs {
        sum += u64::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [last] = pairs.remainder() {
        sum += u64::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn model_ipv4(frame: &[u8]) -> Result<HeaderModel, DropReason> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return Err(DropReason::EthernetHeaderTruncated);
    }
    if read_be_u16(frame, 12) != Some(0x0800) {
        return Err(DropReason::UnsupportedEtherType);
    }
    let available = frame.len() - ETHERNET_HEADER_LEN;
    if available < 20 {
        return Err(DropReason::Ipv4HeaderTruncated);
    }
    let first = frame[ETHERNET_HEADER_LEN];
    if first >> 4 != 4 {
        return Err(DropReason::Ipv4VersionUnsupported);
    }
    let ihl_words = usize::from(first & 0x0f);
    if ihl_words < 5 {
        return Err(DropReason::Ipv4IhlTooSmall);
    }
    let header_len = ihl_words * 4;
    if header_len > available {
        return Err(DropReason::Ipv4HeaderLengthExceedsPacket);
    }
    let total_len = usize::from(read_be_u16(frame, ETHERNET_HEADER_LEN + 2).unwrap());
    if total_len < header_len {
        return Err(DropReason::Ipv4TotalLengthTooSmall);
    }
    if total_len > available {
        return Err(DropReason::Ipv4TotalLengthExceedsPacket);
    }
    let header = &frame[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + header_len];
    if oracle_checksum(header) != 0 {
        return Err(DropReason::Ipv4HeaderChecksumInvalid);
    }
    Ok(HeaderModel {
        header_len,
        total_len,
        ttl: frame[ETHERNET_HEADER_LEN + 8],
        protocol: frame[ETHERNET_HEADER_LEN + 9],
        source: Ipv4Address::from_octets(
            frame[ETHERNET_HEADER_LEN + 12..ETHERNET_HEADER_LEN + 16]
                .try_into()
                .unwrap(),
        ),
        destination: Ipv4Address::from_octets(
            frame[ETHERNET_HEADER_LEN + 16..ETHERNET_HEADER_LEN + 20]
                .try_into()
                .unwrap(),
        ),
        checksum: read_be_u16(frame, ETHERNET_HEADER_LEN + 10).unwrap(),
    })
}

fn production_model(frame: &[u8]) -> Result<HeaderModel, DropReason> {
    validate_ipv4_frame(frame).map(|header| HeaderModel {
        header_len: header.header_len,
        total_len: header.total_len,
        ttl: header.ttl,
        protocol: header.protocol,
        source: header.source,
        destination: header.destination,
        checksum: header.checksum,
    })
}

fn install_oracle_checksum(frame: &mut [u8]) {
    let header_len = usize::from(frame[ETHERNET_HEADER_LEN] & 0x0f) * 4;
    frame[ETHERNET_HEADER_LEN + 10..ETHERNET_HEADER_LEN + 12].fill(0);
    let checksum = oracle_checksum(&frame[ETHERNET_HEADER_LEN..ETHERNET_HEADER_LEN + header_len]);
    frame[ETHERNET_HEADER_LEN + 10..ETHERNET_HEADER_LEN + 12]
        .copy_from_slice(&checksum.to_be_bytes());
}

fn ipv4_frame(
    ihl_words: u8,
    payload_len: usize,
    padding_len: usize,
    flags_offset: u16,
    ttl: u8,
    source: Ipv4Address,
    destination: Ipv4Address,
) -> Vec<u8> {
    assert!((5..=15).contains(&ihl_words));
    let header_len = usize::from(ihl_words) * 4;
    let total_len = header_len + payload_len;
    let mut frame = vec![0_u8; ETHERNET_HEADER_LEN + total_len + padding_len];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&PEER_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x40 | ihl_words;
    frame[15] = 0x2e;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[18..20].copy_from_slice(&0x6d5a_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_offset.to_be_bytes());
    frame[22] = ttl;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    for (index, byte) in frame[34..ETHERNET_HEADER_LEN + header_len]
        .iter_mut()
        .enumerate()
    {
        *byte = u8::try_from((index * 29 + 7) & 0xff).unwrap();
    }
    for (index, byte) in frame[ETHERNET_HEADER_LEN + header_len..ETHERNET_HEADER_LEN + total_len]
        .iter_mut()
        .enumerate()
    {
        *byte = u8::try_from((index * 17 + 3) & 0xff).unwrap();
    }
    frame[ETHERNET_HEADER_LEN + total_len..].fill(0xa5);
    install_oracle_checksum(&mut frame);
    frame
}

fn random_valid_frame(rng: &mut DeterministicRng) -> Vec<u8> {
    let ihl_words = u8::try_from(5 + rng.below(11)).unwrap();
    let payload_len = rng.below(97);
    let padding_len = rng.below(33);
    let flags_offset = rng.next_u32().to_le_bytes()[0..2]
        .try_into()
        .map(u16::from_le_bytes)
        .unwrap();
    let ttl = rng.byte();
    let source = Ipv4Address::from_octets([192, 0, 2, 1 + (rng.byte() % 253)]);
    let destination = Ipv4Address::from_octets([198, 51, 100, 1 + (rng.byte() % 253)]);
    let mut frame = ipv4_frame(
        ihl_words,
        payload_len,
        padding_len,
        flags_offset,
        ttl,
        source,
        destination,
    );
    frame[15] = rng.byte();
    frame[18..20].copy_from_slice(&rng.next_u32().to_le_bytes()[0..2]);
    frame[23] = rng.byte();
    let header_len = usize::from(ihl_words) * 4;
    for byte in &mut frame[34..ETHERNET_HEADER_LEN + header_len] {
        *byte = rng.byte();
    }
    for byte in &mut frame[ETHERNET_HEADER_LEN + header_len..] {
        *byte = rng.byte();
    }
    install_oracle_checksum(&mut frame);
    frame
}

fn mutate_seeded(frame: &mut Vec<u8>, rng: &mut DeterministicRng) {
    let original_header_len = usize::from(frame[14] & 0x0f) * 4;
    let original_total_len = usize::from(read_be_u16(frame, 16).unwrap());
    match rng.below(12) {
        0 => frame.truncate(rng.below(frame.len() + 1)),
        1 => {
            let ether_type = [0x0800_u16, 0x0806, 0x8100, 0x88a8, 0x86dd][rng.below(5)];
            frame[12..14].copy_from_slice(&ether_type.to_be_bytes());
        }
        2 => frame[14] = rng.byte(),
        3 => frame[16..18].copy_from_slice(&rng.next_u32().to_le_bytes()[0..2]),
        4 => {
            let index = ETHERNET_HEADER_LEN + rng.below(original_header_len);
            frame[index] ^= 1 << rng.below(8);
        }
        5 if original_total_len > original_header_len => {
            let index = ETHERNET_HEADER_LEN
                + original_header_len
                + rng.below(original_total_len - original_header_len);
            frame[index] ^= rng.byte() | 1;
        }
        6 => frame[20..22].copy_from_slice(&rng.next_u32().to_le_bytes()[0..2]),
        7 => frame[22] = rng.byte(),
        8 => frame[24..26].copy_from_slice(&rng.next_u32().to_le_bytes()[0..2]),
        9 => frame.extend((0..rng.below(17)).map(|_| rng.byte())),
        10 if original_header_len > 20 => {
            let index = 34 + rng.below(original_header_len - 20);
            frame[index] ^= rng.byte() | 1;
        }
        _ => {}
    }
}

fn snapshot<'a>(
    routes: &'a [Route],
    interfaces: &'a [Interface],
    neighbors: &'a [Neighbor],
    bindings: &'a [LocalIpv4Binding],
) -> ForwardingSnapshot<'a> {
    ForwardingSnapshot::new(routes, interfaces, neighbors, bindings).unwrap()
}

fn topology() -> (
    [Route; 1],
    [Interface; 2],
    [Neighbor; 1],
    [LocalIpv4Binding; 1],
) {
    (
        [Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(GATEWAY)).unwrap()],
        [
            Interface {
                id: LAN,
                mac: LAN_MAC,
            },
            Interface {
                id: WAN,
                mac: WAN_MAC,
            },
        ],
        [Neighbor {
            interface: WAN,
            target: GATEWAY,
            mac: NEXT_HOP_MAC,
        }],
        [LocalIpv4Binding {
            interface: LAN,
            address: LOCAL_IP,
        }],
    )
}

fn arp_request(destination: MacAddress) -> Vec<u8> {
    let mut frame = vec![0_u8; 60];
    frame[0..6].copy_from_slice(&destination.0);
    frame[6..12].copy_from_slice(&PEER_MAC.0);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
    frame[22..28].copy_from_slice(&ARP_SHA.0);
    frame[28..32].copy_from_slice(&PEER_IP.octets());
    frame[38..42].copy_from_slice(&LOCAL_IP.octets());
    frame
}

fn assert_atomic_drop(
    context: &str,
    packet: Vec<u8>,
    ingress: IfId,
    expected: DropReason,
    snapshot: &ForwardingSnapshot<'_>,
    runtime: &mut ResolutionRuntime<'_>,
    now: u64,
) {
    let original = packet.clone();
    let counters = runtime.counters();
    let failure_counters = runtime.failure_counters();
    let pending_states = runtime.pending_states();
    let pending_actions = runtime.pending_actions();
    let dynamic_neighbors = runtime.dynamic_neighbor_count();
    let mut io = SimIo::new();
    io.inject(ingress, packet);
    let batch = io.receive(1).unwrap();
    let report =
        forward_batch_with_resolution(batch, snapshot, runtime, MonotonicMillis(now), &mut NoTrace);
    assert!(
        report.invariants_hold(),
        "{context}: invalid batch accounting"
    );
    assert_eq!(
        (
            report.received,
            report.tx_requested,
            report.dropped,
            report.consumed
        ),
        (1, 0, 1, 0),
        "{context}: unexpected disposition"
    );
    let recycled = io
        .pop_recycled()
        .unwrap_or_else(|| panic!("{context}: missing recycled frame"));
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(expected),
        "{context}: wrong drop reason"
    );
    assert_eq!(recycled.bytes, original, "{context}: drop mutated bytes");
    assert_eq!(runtime.counters(), counters, "{context}: counters mutated");
    assert_eq!(
        runtime.failure_counters(),
        failure_counters,
        "{context}: failure counters mutated"
    );
    assert_eq!(
        runtime.pending_states(),
        pending_states,
        "{context}: resolution states mutated"
    );
    assert_eq!(
        runtime.pending_actions(),
        pending_actions,
        "{context}: actions mutated"
    );
    assert_eq!(
        runtime.dynamic_neighbor_count(),
        dynamic_neighbors,
        "{context}: neighbor cache mutated"
    );
}

#[test]
fn seeded_ipv4_parser_mutations_match_independent_model() {
    let mut rng = DeterministicRng::new(MODEL_SEED);
    for case in 0..1_024 {
        let mut frame = random_valid_frame(&mut rng);
        mutate_seeded(&mut frame, &mut rng);
        let original = frame.clone();
        let expected = model_ipv4(&frame);
        let actual = production_model(&frame);
        let detail = format!(
            "seed={MODEL_SEED:#018x} case={case} len={} ethertype={:?} first={:?}",
            frame.len(),
            read_be_u16(&frame, 12),
            frame.get(14)
        );
        assert_eq!(actual, expected, "{detail}");
        assert_eq!(frame, original, "{detail}: parser mutated bytes");
    }
}

#[test]
fn ipv4_parser_boundary_matrix_has_exact_error_precedence() {
    let mut known_checksum_header = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00,
        0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];
    assert_eq!(
        oracle_checksum(&known_checksum_header),
        0xb861,
        "independent RFC-style checksum vector"
    );
    known_checksum_header[10..12].copy_from_slice(&0xb861_u16.to_be_bytes());
    assert_eq!(oracle_checksum(&known_checksum_header), 0);

    let base = ipv4_frame(5, 8, 7, 0x4000, 64, PEER_IP, DESTINATION);
    let mut cases: Vec<(&str, Vec<u8>, DropReason)> = Vec::new();

    for len in [0, 1, 11, 12, 13] {
        cases.push((
            "ethernet truncation",
            base[..len].to_vec(),
            DropReason::EthernetHeaderTruncated,
        ));
    }
    for len in [14, 15, 32, 33] {
        cases.push((
            "IPv4 minimum header truncation",
            base[..len].to_vec(),
            DropReason::Ipv4HeaderTruncated,
        ));
    }
    for ether_type in [0x0806_u16, 0x8100, 0x88a8, 0x86dd] {
        let mut packet = base.clone();
        packet[12..14].copy_from_slice(&ether_type.to_be_bytes());
        cases.push((
            "unsupported Ethernet type",
            packet,
            DropReason::UnsupportedEtherType,
        ));
    }
    for version in [0_u8, 3, 5, 15] {
        let mut packet = base.clone();
        packet[14] = (version << 4) | 5;
        cases.push((
            "unsupported IPv4 version",
            packet,
            DropReason::Ipv4VersionUnsupported,
        ));
    }
    for ihl in 0_u8..5 {
        let mut packet = base.clone();
        packet[14] = 0x40 | ihl;
        cases.push(("IHL below five words", packet, DropReason::Ipv4IhlTooSmall));
    }
    let mut header_exceeds = ipv4_frame(15, 0, 0, 0, 64, PEER_IP, DESTINATION);
    header_exceeds.truncate(ETHERNET_HEADER_LEN + 59);
    cases.push((
        "IHL exceeds available bytes",
        header_exceeds,
        DropReason::Ipv4HeaderLengthExceedsPacket,
    ));
    let mut total_too_small = base.clone();
    total_too_small[16..18].copy_from_slice(&19_u16.to_be_bytes());
    cases.push((
        "total length below header length",
        total_too_small,
        DropReason::Ipv4TotalLengthTooSmall,
    ));
    let mut total_exceeds = base.clone();
    let unavailable = u16::try_from(base.len() - ETHERNET_HEADER_LEN + 1).unwrap();
    total_exceeds[16..18].copy_from_slice(&unavailable.to_be_bytes());
    cases.push((
        "total length exceeds available bytes",
        total_exceeds,
        DropReason::Ipv4TotalLengthExceedsPacket,
    ));
    let mut bad_checksum = base.clone();
    bad_checksum[24] ^= 1;
    cases.push((
        "invalid independent checksum",
        bad_checksum,
        DropReason::Ipv4HeaderChecksumInvalid,
    ));

    for (case, (label, packet, expected)) in cases.into_iter().enumerate() {
        let detail = format!("boundary_case={case} label={label} len={}", packet.len());
        assert_eq!(model_ipv4(&packet), Err(expected), "{detail}: oracle");
        assert_eq!(
            production_model(&packet),
            Err(expected),
            "{detail}: production"
        );
    }

    for ihl_words in 5_u8..=15 {
        let packet = ipv4_frame(ihl_words, 0, 11, 0xe001, 0, PEER_IP, DESTINATION);
        let expected = HeaderModel {
            header_len: usize::from(ihl_words) * 4,
            total_len: usize::from(ihl_words) * 4,
            ttl: 0,
            protocol: 17,
            source: PEER_IP,
            destination: DESTINATION,
            checksum: read_be_u16(&packet, 24).unwrap(),
        };
        assert_eq!(model_ipv4(&packet), Ok(expected), "IHL={ihl_words}");
        assert_eq!(production_model(&packet), Ok(expected), "IHL={ihl_words}");
    }
}

#[test]
fn reserved_fragment_ttl_and_checksum_forwarding_match_wire_model() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = snapshot(&routes, &interfaces, &neighbors, &bindings);
    let offsets = [0_u16, 1, 0x1fff];

    for flags in 0_u16..8 {
        for offset in offsets {
            let flags_offset = (flags << 13) | offset;
            let original = ipv4_frame(5, 13, 9, flags_offset, 2, PEER_IP, DESTINATION);
            let mut expected = original.clone();
            expected[0..6].copy_from_slice(&NEXT_HOP_MAC.0);
            expected[6..12].copy_from_slice(&WAN_MAC.0);
            expected[22] = 1;
            install_oracle_checksum(&mut expected);

            let mut io = SimIo::new();
            io.inject(LAN, original);
            let report = io.run_once(1, &snapshot, &mut NoTrace).unwrap();
            let detail = format!("flags={flags:#05b} offset={offset:#06x}");
            assert!(
                report.invariants_hold(),
                "{detail}: invalid batch accounting"
            );
            assert_eq!(
                (report.tx_requested, report.dropped, report.consumed),
                (1, 0, 0),
                "{detail}"
            );
            let transmitted = io
                .pop_tx()
                .unwrap_or_else(|| panic!("{detail}: missing transmitted frame"));
            assert_eq!(transmitted.bytes, expected, "{detail}: wire mismatch");
            assert_eq!(
                read_be_u16(&transmitted.bytes, 20),
                Some(flags_offset),
                "{detail}: flags/offset changed"
            );
            assert_eq!(
                oracle_checksum(&transmitted.bytes[14..34]),
                0,
                "{detail}: invalid independent checksum"
            );
        }
    }
}

#[test]
fn parser_and_ingress_rejections_are_byte_and_resolution_state_atomic() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = snapshot(&routes, &interfaces, &neighbors, &bindings);
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 2];
    let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        &mut states,
        &mut actions,
        &mut dynamic,
    );

    let base = ipv4_frame(5, 8, 3, 0x4000, 64, PEER_IP, DESTINATION);
    let mut explicit_cases = Vec::new();
    explicit_cases.push((
        "Ethernet truncation",
        base[..13].to_vec(),
        LAN,
        DropReason::EthernetHeaderTruncated,
    ));
    let mut vlan = base.clone();
    vlan[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
    explicit_cases.push((
        "VLAN remains unsupported",
        vlan,
        LAN,
        DropReason::UnsupportedEtherType,
    ));
    let mut short_ihl = base.clone();
    short_ihl[14] = 0x44;
    explicit_cases.push(("short IHL", short_ihl, LAN, DropReason::Ipv4IhlTooSmall));
    let mut total_small = base.clone();
    total_small[16..18].copy_from_slice(&19_u16.to_be_bytes());
    explicit_cases.push((
        "small total length",
        total_small,
        LAN,
        DropReason::Ipv4TotalLengthTooSmall,
    ));
    let mut bad_checksum = base.clone();
    bad_checksum[24] ^= 1;
    explicit_cases.push((
        "bad checksum",
        bad_checksum,
        LAN,
        DropReason::Ipv4HeaderChecksumInvalid,
    ));
    let options = ipv4_frame(6, 0, 0, 0x4000, 64, PEER_IP, DESTINATION);
    explicit_cases.push((
        "validated options remain unsupported",
        options,
        LAN,
        DropReason::Ipv4OptionsUnsupported,
    ));
    for ttl in [0_u8, 1] {
        explicit_cases.push((
            "TTL expiry",
            ipv4_frame(5, 0, 0, 0x4000, ttl, PEER_IP, DESTINATION),
            LAN,
            DropReason::Ipv4TtlExpired,
        ));
    }
    let mut foreign_destination = base.clone();
    foreign_destination[0..6].copy_from_slice(&WAN_MAC.0);
    explicit_cases.push((
        "other router interface MAC",
        foreign_destination,
        LAN,
        DropReason::EthernetDestinationNotLocal,
    ));
    let local_source = ipv4_frame(5, 0, 0, 0x4000, 64, LOCAL_IP, DESTINATION);
    explicit_cases.push((
        "local IPv4 source claim",
        local_source,
        LAN,
        DropReason::Ipv4SourceLocalAddress,
    ));
    explicit_cases.push((
        "unknown IPv4 ingress",
        base.clone(),
        UNKNOWN,
        DropReason::Ipv4IngressInterfaceUnknown,
    ));
    let mut arp_foreign = arp_request(WAN_MAC);
    explicit_cases.push((
        "ARP foreign unicast",
        arp_foreign.clone(),
        LAN,
        DropReason::EthernetDestinationNotLocal,
    ));
    arp_foreign[0..6].copy_from_slice(&[0x01, 0, 0, 0, 0, 1]);
    explicit_cases.push((
        "ARP multicast destination",
        arp_foreign,
        LAN,
        DropReason::ArpEthernetDestinationMulticast,
    ));

    for (case, (label, packet, ingress, reason)) in explicit_cases.into_iter().enumerate() {
        assert_atomic_drop(
            &format!("explicit_case={case} label={label}"),
            packet,
            ingress,
            reason,
            &snapshot,
            &mut runtime,
            10_000 + u64::try_from(case).unwrap(),
        );
    }

    let mut rng = DeterministicRng::new(MODEL_SEED ^ 0xa5a5_5a5a_0123_4567);
    for case in 0..128 {
        let mut destination = [0_u8; 6];
        for byte in &mut destination {
            *byte = rng.byte();
        }
        destination[0] &= 0xfe;
        if destination == [0; 6] || destination == LAN_MAC.0 {
            destination[5] ^= 0x5a;
        }
        let mut packet = base.clone();
        packet[0..6].copy_from_slice(&destination);
        assert_atomic_drop(
            &format!(
                "seed={:#018x} foreign_mac_case={case} destination={destination:02x?}",
                MODEL_SEED ^ 0xa5a5_5a5a_0123_4567
            ),
            packet,
            LAN,
            DropReason::EthernetDestinationNotLocal,
            &snapshot,
            &mut runtime,
            20_000 + u64::try_from(case).unwrap(),
        );
    }

    let broadcast_request = arp_request(MacAddress([0xff; 6]));
    let mut io = SimIo::new();
    io.inject(LAN, broadcast_request);
    let batch = io.receive(1).unwrap();
    let report = forward_batch_with_resolution(
        batch,
        &snapshot,
        &mut runtime,
        MonotonicMillis(0),
        &mut NoTrace,
    );
    assert!(report.invariants_hold());
    assert_eq!(
        (report.tx_requested, report.dropped, report.consumed),
        (1, 0, 0),
        "valid older-time ARP broadcast must pass after future L2/parser drops"
    );
    assert_eq!(runtime.dynamic_neighbor_count(), 1);
    let reply = io.pop_tx().unwrap();
    assert_eq!(&reply.bytes[0..6], &ARP_SHA.0);
    assert_eq!(&reply.bytes[6..12], &LAN_MAC.0);
}

#[test]
fn exact_ingress_mac_accepts_individual_source_and_arp_broadcast_only_exception() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = snapshot(&routes, &interfaces, &neighbors, &bindings);

    let mut ipv4 = ipv4_frame(5, 0, 0, 0xc001, 2, PEER_IP, DESTINATION);
    ipv4[6..12].copy_from_slice(&WAN_MAC.0);
    let mut expected = ipv4.clone();
    expected[0..6].copy_from_slice(&NEXT_HOP_MAC.0);
    expected[6..12].copy_from_slice(&WAN_MAC.0);
    expected[22] = 1;
    install_oracle_checksum(&mut expected);
    let mut io = SimIo::new();
    io.inject(LAN, ipv4);
    let report = io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    assert_eq!(
        (report.tx_requested, report.dropped, report.consumed),
        (1, 0, 0),
        "an arbitrary individual Ethernet source, including a router MAC, is valid"
    );
    assert_eq!(io.pop_tx().unwrap().bytes, expected);

    for (case, destination) in [LAN_MAC, MacAddress([0xff; 6])].into_iter().enumerate() {
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            &mut states,
            &mut actions,
            &mut dynamic,
        );
        let mut io = SimIo::new();
        io.inject(LAN, arp_request(destination));
        let batch = io.receive(1).unwrap();
        let report = forward_batch_with_resolution(
            batch,
            &snapshot,
            &mut runtime,
            MonotonicMillis(u64::try_from(case).unwrap()),
            &mut NoTrace,
        );
        assert_eq!(
            (report.tx_requested, report.dropped, report.consumed),
            (1, 0, 0),
            "ARP destination={destination:?}"
        );
        assert_eq!(runtime.dynamic_neighbor_count(), 1);
        let reply = io.pop_tx().unwrap();
        assert_eq!(&reply.bytes[0..6], &ARP_SHA.0);
        assert_eq!(&reply.bytes[6..12], &LAN_MAC.0);
    }
}
