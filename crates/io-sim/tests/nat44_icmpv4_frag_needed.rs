use ruster_core::{
    internet_checksum, ipv4_header_checksum, rfc1624_update, ConsumeReason, DropReason,
    DynamicNeighborSlot, ForwardingSnapshot, IfId, Interface, Ipv4Address, LocalIpv4Binding,
    MacAddress, MonotonicMillis, Nat44Icmpv4Disposition, Nat44Icmpv4ErrorPolicy, Nat44TcpConfig,
    Nat44TcpMappingSlot, Nat44TcpPolicy, Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44UdpConfig,
    Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpRuntime, Neighbor, NoTrace,
    ResolutionActionSlot, ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route,
    TraceEvent,
};
use ruster_io_sim::{RecycleCause, SimIo, VecTrace};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const DMZ: IfId = IfId(3);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const HOST_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 10]);
const GW_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 20]);
const ROUTER_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 30]);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const OTHER_PUBLIC: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 10]);
const HOST: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
const LAN_LOCAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 1]);
const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const OTHER_REMOTE: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 30]);
const ROUTER: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
const GW: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);

fn topology() -> (
    [Route; 2],
    [Interface; 2],
    [Neighbor; 2],
    [LocalIpv4Binding; 2],
) {
    (
        [
            Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
            Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(GW)).unwrap(),
        ],
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
        [
            Neighbor {
                interface: LAN,
                target: HOST,
                mac: HOST_MAC,
            },
            Neighbor {
                interface: WAN,
                target: GW,
                mac: GW_MAC,
            },
        ],
        [
            LocalIpv4Binding {
                interface: LAN,
                address: LAN_LOCAL,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ],
    )
}

fn resolution<'a>(
    states: &'a mut [ResolutionStateSlot],
    actions: &'a mut [ResolutionActionSlot],
) -> ResolutionRuntime<'a> {
    ResolutionRuntime::new(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        states,
        actions,
    )
}

fn udp_config(snapshot: &ForwardingSnapshot<'_>, enabled: bool) -> Nat44UdpConfig {
    let policy = Nat44UdpPolicy::default().with_icmpv4_errors(if enabled {
        Nat44Icmpv4ErrorPolicy::ExternalOnly
    } else {
        Nat44Icmpv4ErrorPolicy::Disabled
    });
    Nat44UdpConfig::new(snapshot, LAN, WAN, PUBLIC, 40_000, 40_000, policy).unwrap()
}

fn tcp_config(snapshot: &ForwardingSnapshot<'_>, enabled: bool) -> Nat44TcpConfig {
    let policy = Nat44TcpPolicy::default().with_icmpv4_errors(if enabled {
        Nat44Icmpv4ErrorPolicy::ExternalOnly
    } else {
        Nat44Icmpv4ErrorPolicy::Disabled
    });
    Nat44TcpConfig::new(snapshot, LAN, WAN, PUBLIC, 40_000, 40_000, policy).unwrap()
}

fn udp_frame(remote: Ipv4Address, remote_port: u16, checksum: u16) -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 28 + 3];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&HOST_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = 0x7a;
    frame[16..18].copy_from_slice(&28_u16.to_be_bytes());
    frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&HOST.octets());
    frame[30..34].copy_from_slice(&remote.octets());
    frame[34..36].copy_from_slice(&12_345_u16.to_be_bytes());
    frame[36..38].copy_from_slice(&remote_port.to_be_bytes());
    frame[38..40].copy_from_slice(&8_u16.to_be_bytes());
    frame[40..42].copy_from_slice(&checksum.to_be_bytes());
    let ip_checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
    frame
}

fn tcp_frame(remote: Ipv4Address, remote_port: u16, _checksum: u16) -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 40 + 3];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&HOST_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = 0x7a;
    frame[16..18].copy_from_slice(&40_u16.to_be_bytes());
    frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&HOST.octets());
    frame[30..34].copy_from_slice(&remote.octets());
    frame[34..36].copy_from_slice(&12_345_u16.to_be_bytes());
    frame[36..38].copy_from_slice(&remote_port.to_be_bytes());
    frame[38..42].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
    frame[42..46].copy_from_slice(&0x0506_0708_u32.to_be_bytes());
    frame[46] = 5 << 4;
    frame[47] = 0x02;
    frame[48..50].copy_from_slice(&65_535_u16.to_be_bytes());
    let mut pseudo = Vec::with_capacity(52);
    pseudo.extend_from_slice(&HOST.octets());
    pseudo.extend_from_slice(&remote.octets());
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&20_u16.to_be_bytes());
    pseudo.extend_from_slice(&frame[34..54]);
    let tcp_checksum = internet_checksum(&pseudo);
    frame[50..52].copy_from_slice(&tcp_checksum.to_be_bytes());
    let ip_checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
    frame
}

fn refresh_inner_checksum(quote: &mut [u8]) {
    let ihl = usize::from(quote[0] & 0x0f) * 4;
    quote[10..12].fill(0);
    let checksum = ipv4_header_checksum(&quote[..ihl]);
    quote[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn refresh_icmp_and_outer_checksums(frame: &mut [u8]) {
    let outer_ihl = usize::from(frame[14] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes(frame[16..18].try_into().unwrap()));
    let icmp_offset = 14 + outer_ihl;
    frame[icmp_offset + 2..icmp_offset + 4].fill(0);
    let icmp_checksum = internet_checksum(&frame[icmp_offset..14 + total]);
    frame[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    frame[24..26].fill(0);
    let outer_checksum = ipv4_header_checksum(&frame[14..14 + outer_ihl]);
    frame[24..26].copy_from_slice(&outer_checksum.to_be_bytes());
}

fn assert_outer_icmp_checksum_valid(frame: &[u8]) {
    let outer_ihl = usize::from(frame[14] & 0x0f) * 4;
    let outer_total = usize::from(u16::from_be_bytes(frame[16..18].try_into().unwrap()));
    assert_eq!(
        internet_checksum(&frame[14 + outer_ihl..14 + outer_total]),
        0
    );
}

fn set_outer_source(frame: &mut [u8], source: Ipv4Address) {
    frame[26..30].copy_from_slice(&source.octets());
    let outer_ihl = usize::from(frame[14] & 0x0f) * 4;
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..14 + outer_ihl]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
}

fn set_frag_needed_mtu(frame: &mut [u8], mtu: u16) {
    frame[40..42].copy_from_slice(&mtu.to_be_bytes());
    refresh_icmp_and_outer_checksums(frame);
}

fn arp_reply(sender: Ipv4Address, sender_mac: MacAddress) -> Vec<u8> {
    let mut frame = vec![0_u8; 60];
    frame[0..6].copy_from_slice(&LAN_MAC.0);
    frame[6..12].copy_from_slice(&sender_mac.0);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18..22].copy_from_slice(&[6, 4, 0, 2]);
    frame[22..28].copy_from_slice(&sender_mac.0);
    frame[28..32].copy_from_slice(&sender.octets());
    frame[32..38].copy_from_slice(&LAN_MAC.0);
    frame[38..42].copy_from_slice(&LAN_LOCAL.octets());
    frame
}

fn frag_needed(quote: &[u8], ttl: u8, flags_fragment: u16, trailing: &[u8]) -> Vec<u8> {
    let icmp_len = 8 + quote.len() + trailing.len();
    let total_len = 20 + icmp_len;
    let mut frame = vec![0_u8; 14 + total_len + 5];
    frame[0..6].copy_from_slice(&WAN_MAC.0);
    frame[6..12].copy_from_slice(&ROUTER_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = 0xa4;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[18..20].copy_from_slice(&0x8888_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    frame[22] = ttl;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&ROUTER.octets());
    frame[30..34].copy_from_slice(&PUBLIC.octets());
    frame[34..36].copy_from_slice(&[3, 4]);
    frame[38..42].copy_from_slice(&[0, 0, 0x05, 0x78]);
    frame[42..42 + quote.len()].copy_from_slice(quote);
    frame[42 + quote.len()..42 + quote.len() + trailing.len()].copy_from_slice(trailing);
    let icmp_checksum = internet_checksum(&frame[34..34 + icmp_len]);
    frame[36..38].copy_from_slice(&icmp_checksum.to_be_bytes());
    let ip_checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
    frame[14 + total_len..].copy_from_slice(&[9, 8, 7, 6, 5]);
    frame
}

fn assert_drop(io: &mut SimIo, reason: DropReason, original: &[u8]) {
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(recycled.cause, RecycleCause::Forwarding(reason));
    assert_eq!(recycled.bytes, original);
}

fn updated_transport_checksum(
    checksum: u16,
    old_address: Ipv4Address,
    new_address: Ipv4Address,
    old_port: u16,
    new_port: u16,
) -> u16 {
    let old = old_address.octets();
    let new = new_address.octets();
    rfc1624_update(
        rfc1624_update(
            rfc1624_update(
                checksum,
                u16::from_be_bytes([old[0], old[1]]),
                u16::from_be_bytes([new[0], new[1]]),
            ),
            u16::from_be_bytes([old[2], old[3]]),
            u16::from_be_bytes([new[2], new[3]]),
        ),
        old_port,
        new_port,
    )
}

#[test]
fn udp_frag_needed_translates_cascade_and_keeps_nat_state_read_only() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = udp_config(&snapshot, true);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat = Nat44UdpRuntime::new(config, &mut mappings, &mut peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(LAN, udp_frame(REMOTE, 53, 0x2345));
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(100),
        &mut NoTrace,
    )
    .unwrap();
    let outbound = io.pop_tx().unwrap();
    let mut quote = outbound.bytes[14..42].to_vec();
    quote[6..8].copy_from_slice(&0xc000_u16.to_be_bytes());
    refresh_inner_checksum(&mut quote);
    let original_transport_checksum = u16::from_be_bytes(quote[26..28].try_into().unwrap());
    let error = frag_needed(&quote, 55, 0x4000, &[]);
    let original = error.clone();
    let before_mapping = nat.mappings()[0];
    let before_peer = nat.peers()[0];
    let before_counters = nat.counters();
    let mut trace = VecTrace::default();
    io.inject(WAN, error);
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(200),
            &mut trace,
        )
        .unwrap();
    assert_eq!((report.tx_requested, report.dropped), (1, 0));
    let translated = io.pop_tx().unwrap();
    assert_eq!(translated.egress, LAN);
    assert_eq!(&translated.bytes[0..6], &HOST_MAC.0);
    assert_eq!(&translated.bytes[6..12], &LAN_MAC.0);
    assert_eq!(translated.bytes[22], 54);
    assert_eq!(&translated.bytes[30..34], &HOST.octets());
    assert_eq!(&translated.bytes[54..58], &HOST.octets());
    assert_eq!(&translated.bytes[48..50], &0xc000_u16.to_be_bytes());
    assert_eq!(
        u16::from_be_bytes(translated.bytes[62..64].try_into().unwrap()),
        12_345
    );
    let expected_udp =
        updated_transport_checksum(original_transport_checksum, PUBLIC, HOST, 40_000, 12_345);
    assert_eq!(
        u16::from_be_bytes(translated.bytes[68..70].try_into().unwrap()),
        if expected_udp == 0 {
            0xffff
        } else {
            expected_udp
        }
    );
    assert_eq!(ipv4_header_checksum(&translated.bytes[14..34]), 0);
    assert_eq!(ipv4_header_checksum(&translated.bytes[42..62]), 0);
    let outer_total = usize::from(u16::from_be_bytes(
        translated.bytes[16..18].try_into().unwrap(),
    ));
    assert_eq!(
        internet_checksum(&translated.bytes[34..14 + outer_total]),
        0
    );
    assert_eq!(&translated.bytes[38..42], &[0, 0, 0x05, 0x78]);
    assert_eq!(&translated.bytes[14 + outer_total..], &[9, 8, 7, 6, 5]);
    assert_eq!(nat.mappings()[0], before_mapping);
    assert_eq!(nat.peers()[0], before_peer);
    assert_eq!(nat.counters(), before_counters);
    assert!(trace.events().contains(&TraceEvent::Nat44Icmpv4 {
        ingress: WAN,
        disposition: Nat44Icmpv4Disposition::Translated {
            quoted_protocol: 17,
            internal_address: HOST,
            internal_port: 12_345,
        },
    }));
    for flags_fragment in [0xe000_u16, 0xc001] {
        let mut fragmented_quote = quote.clone();
        fragmented_quote[6..8].copy_from_slice(&flags_fragment.to_be_bytes());
        refresh_inner_checksum(&mut fragmented_quote);
        let fragmented = frag_needed(&fragmented_quote, 64, 0, &[]);
        io.inject(WAN, fragmented.clone());
        io.run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(200),
            &mut NoTrace,
        )
        .unwrap();
        assert_drop(
            &mut io,
            DropReason::Nat44Icmpv4QuotedFragmentUnsupported,
            &fragmented,
        );
        assert_eq!(nat.mappings()[0], before_mapping);
        assert_eq!(nat.peers()[0], before_peer);
        assert_eq!(nat.counters(), before_counters);
    }

    let later = udp_frame(REMOTE, 53, 0);
    io.inject(LAN, later);
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(150),
        &mut NoTrace,
    )
    .unwrap();
    assert_eq!(io.pop_tx().unwrap().egress, WAN);
    assert_eq!(original[38..42], [0, 0, 0x05, 0x78]);
}

#[test]
fn udp_zero_checksum_and_remote_port_are_not_authority() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = udp_config(&snapshot, true);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat = Nat44UdpRuntime::new(config, &mut mappings, &mut peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(LAN, udp_frame(REMOTE, 53, 0));
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    let outbound = io.pop_tx().unwrap();
    let mut quote = outbound.bytes[14..42].to_vec();
    quote[22..24].copy_from_slice(&9999_u16.to_be_bytes());
    refresh_inner_checksum(&mut quote);
    io.inject(WAN, frag_needed(&quote, 64, 0, &[]));
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    let translated = io.pop_tx().unwrap();
    assert_eq!(&translated.bytes[68..70], &[0, 0]);

    let mut options_quote = outbound.bytes[14..42].to_vec();
    options_quote.splice(20..20, [1, 1, 0, 0]);
    options_quote[0] = 0x46;
    options_quote[2..4].copy_from_slice(&32_u16.to_be_bytes());
    refresh_inner_checksum(&mut options_quote);
    io.inject(WAN, frag_needed(&options_quote, 64, 0, &[]));
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    let translated_options = io.pop_tx().unwrap();
    assert_eq!(&translated_options.bytes[62..66], &[1, 1, 0, 0]);
    assert_eq!(
        u16::from_be_bytes(translated_options.bytes[66..68].try_into().unwrap()),
        12_345
    );
    assert_eq!(ipv4_header_checksum(&translated_options.bytes[42..66]), 0);

    let negative_zero_input = (0..=u16::MAX)
        .find(|checksum| updated_transport_checksum(*checksum, PUBLIC, HOST, 40_000, 12_345) == 0)
        .unwrap();
    let mut negative_zero_quote = outbound.bytes[14..42].to_vec();
    negative_zero_quote[26..28].copy_from_slice(&negative_zero_input.to_be_bytes());
    let negative_zero_error = frag_needed(&negative_zero_quote, 64, 0, &[]);
    io.inject(WAN, negative_zero_error);
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    let translated_negative_zero = io.pop_tx().unwrap();
    assert_eq!(&translated_negative_zero.bytes[68..70], &[0xff, 0xff]);
    assert_outer_icmp_checksum_valid(&translated_negative_zero.bytes);

    quote[16..20].copy_from_slice(&OTHER_REMOTE.octets());
    refresh_inner_checksum(&mut quote);
    let denied = frag_needed(&quote, 64, 0, &[]);
    io.inject(WAN, denied.clone());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(2),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpFilterDenied, &denied);
}

#[test]
fn tcp_quote_boundaries_and_exact_session_authority_are_enforced() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = tcp_config(&snapshot, true);
    let mut mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut nat = Nat44TcpRuntime::new(config, &mut mappings, &mut sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(LAN, tcp_frame(REMOTE, 443, 0x3456));
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(100),
        &mut NoTrace,
    )
    .unwrap();
    let outbound = io.pop_tx().unwrap();
    let mut complete_quote = outbound.bytes[14..54].to_vec();
    complete_quote[6..8].copy_from_slice(&0xc000_u16.to_be_bytes());
    refresh_inner_checksum(&mut complete_quote);
    let before_mapping = nat.mappings()[0];
    let before_session = nat.sessions()[0];
    let before_counters = nat.counters();

    let short = frag_needed(&complete_quote[..28], 64, 0, &[]);
    io.inject(WAN, short);
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(200),
        &mut NoTrace,
    )
    .unwrap();
    let translated_short = io.pop_tx().unwrap();
    assert_eq!(&translated_short.bytes[54..58], &HOST.octets());
    assert_eq!(&translated_short.bytes[48..50], &0xc000_u16.to_be_bytes());
    assert_eq!(
        u16::from_be_bytes(translated_short.bytes[62..64].try_into().unwrap()),
        12_345
    );

    let partial = frag_needed(&complete_quote[..37], 64, 0, &[]);
    io.inject(WAN, partial.clone());
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(201),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44Icmpv4TcpChecksumPartial, &partial);

    let with_checksum = frag_needed(&complete_quote[..38], 64, 0, &[]);
    let old_tcp = u16::from_be_bytes(complete_quote[36..38].try_into().unwrap());
    io.inject(WAN, with_checksum);
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(202),
        &mut NoTrace,
    )
    .unwrap();
    let translated = io.pop_tx().unwrap();
    assert_eq!(
        u16::from_be_bytes(translated.bytes[78..80].try_into().unwrap()),
        updated_transport_checksum(old_tcp, PUBLIC, HOST, 40_000, 12_345)
    );

    let zero_input = (0..=u16::MAX)
        .find(|checksum| updated_transport_checksum(*checksum, PUBLIC, HOST, 40_000, 12_345) == 0)
        .unwrap();
    let mut zero_checksum = complete_quote[..38].to_vec();
    zero_checksum[36..38].copy_from_slice(&zero_input.to_be_bytes());
    let zero_checksum = frag_needed(&zero_checksum, 64, 0, &[]);
    io.inject(WAN, zero_checksum);
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(202),
        &mut NoTrace,
    )
    .unwrap();
    let translated_zero = io.pop_tx().unwrap();
    assert_eq!(&translated_zero.bytes[78..80], &[0, 0]);
    assert_outer_icmp_checksum_valid(&translated_zero.bytes);

    let mut wrong_port = complete_quote[..28].to_vec();
    wrong_port[22..24].copy_from_slice(&444_u16.to_be_bytes());
    refresh_inner_checksum(&mut wrong_port);
    let denied = frag_needed(&wrong_port, 64, 0, &[]);
    io.inject(WAN, denied.clone());
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(203),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44TcpSessionMiss, &denied);
    assert_eq!(nat.mappings()[0], before_mapping);
    assert_eq!(nat.sessions()[0], before_session);
    assert_eq!(nat.counters(), before_counters);

    for flags_fragment in [0xe000_u16, 0xc001] {
        let mut fragmented_quote = complete_quote[..28].to_vec();
        fragmented_quote[6..8].copy_from_slice(&flags_fragment.to_be_bytes());
        refresh_inner_checksum(&mut fragmented_quote);
        let fragmented = frag_needed(&fragmented_quote, 64, 0, &[]);
        io.inject(WAN, fragmented.clone());
        io.run_nat44_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(203),
            &mut NoTrace,
        )
        .unwrap();
        assert_drop(
            &mut io,
            DropReason::Nat44Icmpv4QuotedFragmentUnsupported,
            &fragmented,
        );
        assert_eq!(nat.mappings()[0], before_mapping);
        assert_eq!(nat.sessions()[0], before_session);
        assert_eq!(nat.counters(), before_counters);
    }

    io.set_received_accept_budget(0);
    io.inject(WAN, frag_needed(&complete_quote[..28], 64, 0, &[]));
    let rejected = io
        .run_nat44_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(203),
            &mut NoTrace,
        )
        .unwrap();
    assert_eq!(rejected.completion.tx_rejected, 1);
    assert_eq!(io.pop_recycled().unwrap().cause, RecycleCause::TxRejected);
    assert_eq!(nat.mappings()[0], before_mapping);
    assert_eq!(nat.sessions()[0], before_session);
    assert_eq!(nat.counters(), before_counters);
}

#[test]
fn tcp_total_length_prevents_opaque_trailing_bytes_from_becoming_a_checksum() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = tcp_config(&snapshot, true);
    let mut mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut nat = Nat44TcpRuntime::new(config, &mut mappings, &mut sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(LAN, tcp_frame(REMOTE, 443, 0));
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    let outbound = io.pop_tx().unwrap();
    let mut quote = outbound.bytes[14..42].to_vec();
    quote[2..4].copy_from_slice(&28_u16.to_be_bytes());
    refresh_inner_checksum(&mut quote);
    let trailing = [0xaa; 20];
    let error = frag_needed(&quote, 64, 0, &trailing);
    io.inject(WAN, error);
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    let translated = io.pop_tx().unwrap();
    assert_eq!(&translated.bytes[70..90], &trailing);
}

#[test]
fn disabled_policy_preserves_local_consume_and_candidate_drops_are_atomic() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let enabled = udp_config(&snapshot, true);
    let disabled = udp_config(&snapshot, false);
    assert_eq!(
        Nat44UdpPolicy::default().icmpv4_errors(),
        Nat44Icmpv4ErrorPolicy::Disabled
    );
    assert_eq!(
        Nat44TcpPolicy::default().icmpv4_errors(),
        Nat44Icmpv4ErrorPolicy::Disabled
    );
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat = Nat44UdpRuntime::new(enabled, &mut mappings, &mut peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(LAN, udp_frame(REMOTE, 53, 0));
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &enabled,
        Some(&mut nat),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    let outbound = io.pop_tx().unwrap();
    let valid = frag_needed(&outbound.bytes[14..42], 64, 0, &[]);

    let mut disabled_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut disabled_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut disabled_nat =
        Nat44UdpRuntime::new(disabled, &mut disabled_mappings, &mut disabled_peers);
    io.inject(WAN, valid.clone());
    let report = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &disabled,
            Some(&mut disabled_nat),
            MonotonicMillis(1),
            &mut NoTrace,
        )
        .unwrap();
    assert_eq!((report.consumed, report.dropped), (1, 0));
    assert_eq!(
        io.pop_recycled().unwrap().cause,
        RecycleCause::Consumed(ruster_core::ConsumeReason::Ipv4LocalUnsupported)
    );

    let cases = [
        (1, 0, DropReason::Nat44Icmpv4OuterTtlExpired),
        (22, 0x2000, DropReason::Nat44Icmpv4OuterFragmentUnsupported),
    ];
    for (ttl, flags, reason) in cases {
        let malformed = frag_needed(&outbound.bytes[14..42], ttl, flags, &[]);
        io.inject(WAN, malformed.clone());
        io.run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &enabled,
            Some(&mut nat),
            MonotonicMillis(2),
            &mut NoTrace,
        )
        .unwrap();
        assert_drop(&mut io, reason, &malformed);
    }

    let mut bad_quote = outbound.bytes[14..42].to_vec();
    bad_quote[6..8].copy_from_slice(&0_u16.to_be_bytes());
    refresh_inner_checksum(&mut bad_quote);
    let malformed = frag_needed(&bad_quote, 64, 0, &[]);
    io.inject(WAN, malformed.clone());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &enabled,
        Some(&mut nat),
        MonotonicMillis(2),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(
        &mut io,
        DropReason::Nat44Icmpv4QuotedFragmentUnsupported,
        &malformed,
    );
}

#[test]
fn backend_reject_and_clock_regression_leave_icmp_lookup_state_unchanged() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = udp_config(&snapshot, true);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat = Nat44UdpRuntime::new(config, &mut mappings, &mut peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(LAN, udp_frame(REMOTE, 53, 0));
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(100),
        &mut NoTrace,
    )
    .unwrap();
    let outbound = io.pop_tx().unwrap();
    let error = frag_needed(&outbound.bytes[14..42], 64, 0, &[]);
    let before_mapping = nat.mappings()[0];
    let before_peer = nat.peers()[0];
    let before_counters = nat.counters();

    io.set_received_accept_budget(0);
    io.inject(WAN, error.clone());
    let rejected = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(101),
            &mut NoTrace,
        )
        .unwrap();
    assert_eq!(rejected.completion.tx_rejected, 1);
    assert_eq!(io.pop_recycled().unwrap().cause, RecycleCause::TxRejected);
    assert_eq!(nat.mappings()[0], before_mapping);
    assert_eq!(nat.peers()[0], before_peer);
    assert_eq!(nat.counters(), before_counters);

    io.set_received_accept_budget(1);
    io.inject(WAN, error.clone());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(99),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpClockRegression, &error);
    assert_eq!(nat.mappings()[0], before_mapping);
    assert_eq!(nat.peers()[0], before_peer);
    assert_eq!(nat.counters(), before_counters);

    io.inject(WAN, error);
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(100),
        &mut NoTrace,
    )
    .unwrap();
    assert_eq!(io.pop_tx().unwrap().egress, LAN);
}

#[test]
fn malformed_candidate_matrix_has_stable_atomic_reasons() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = udp_config(&snapshot, true);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat = Nat44UdpRuntime::new(config, &mut mappings, &mut peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(LAN, udp_frame(REMOTE, 53, 0));
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(10),
        &mut NoTrace,
    )
    .unwrap();
    let outbound = io.pop_tx().unwrap();
    let quote = outbound.bytes[14..42].to_vec();
    let valid = frag_needed(&quote, 64, 0, &[]);
    let before_mapping = nat.mappings()[0];
    let before_peer = nat.peers()[0];
    let before_counters = nat.counters();

    let mut cases = Vec::new();

    let mut outer_options = valid.clone();
    outer_options.splice(34..34, [1, 1, 0, 0]);
    outer_options[14] = 0x46;
    let total = u16::from_be_bytes(outer_options[16..18].try_into().unwrap()) + 4;
    outer_options[16..18].copy_from_slice(&total.to_be_bytes());
    refresh_icmp_and_outer_checksums(&mut outer_options);
    cases.push((
        outer_options,
        DropReason::Nat44Icmpv4OuterOptionsUnsupported,
    ));

    let mut short_icmp = valid.clone();
    short_icmp[16..18].copy_from_slice(&26_u16.to_be_bytes());
    refresh_icmp_and_outer_checksums(&mut short_icmp);
    cases.push((short_icmp, DropReason::Nat44Icmpv4HeaderTruncated));

    let no_quote = frag_needed(&[], 64, 0, &[]);
    cases.push((no_quote, DropReason::Nat44Icmpv4QuoteTruncated));

    let mut bad_icmp_checksum = valid.clone();
    bad_icmp_checksum[38] ^= 1;
    cases.push((bad_icmp_checksum, DropReason::Nat44Icmpv4ChecksumInvalid));

    let mut version = quote.clone();
    version[0] = 0x65;
    let frame = frag_needed(&version, 64, 0, &[]);
    cases.push((frame, DropReason::Nat44Icmpv4QuotedVersionUnsupported));

    let mut small_ihl = quote.clone();
    small_ihl[0] = 0x44;
    let frame = frag_needed(&small_ihl, 64, 0, &[]);
    cases.push((frame, DropReason::Nat44Icmpv4QuotedIhlTooSmall));

    let mut long_ihl = quote[..20].to_vec();
    long_ihl[0] = 0x46;
    let frame = frag_needed(&long_ihl, 64, 0, &[]);
    cases.push((frame, DropReason::Nat44Icmpv4QuotedHeaderTruncated));

    let mut short_total = quote.clone();
    short_total[2..4].copy_from_slice(&27_u16.to_be_bytes());
    refresh_inner_checksum(&mut short_total);
    let frame = frag_needed(&short_total, 64, 0, &[]);
    cases.push((frame, DropReason::Nat44Icmpv4QuotedTotalLengthTooSmall));

    let mut bad_inner_checksum = quote.clone();
    bad_inner_checksum[4] ^= 1;
    let frame = frag_needed(&bad_inner_checksum, 64, 0, &[]);
    cases.push((frame, DropReason::Nat44Icmpv4QuotedChecksumInvalid));

    let mut unsupported_protocol = quote.clone();
    unsupported_protocol[9] = 1;
    refresh_inner_checksum(&mut unsupported_protocol);
    let frame = frag_needed(&unsupported_protocol, 64, 0, &[]);
    cases.push((frame, DropReason::Nat44Icmpv4QuotedProtocolUnsupported));

    let mut wrong_public = quote.clone();
    wrong_public[12..16].copy_from_slice(&OTHER_REMOTE.octets());
    refresh_inner_checksum(&mut wrong_public);
    let frame = frag_needed(&wrong_public, 64, 0, &[]);
    cases.push((frame, DropReason::Nat44Icmpv4QuotedPublicSourceMismatch));

    for (packet, reason) in cases {
        io.inject(WAN, packet.clone());
        io.run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(10),
            &mut NoTrace,
        )
        .unwrap();
        assert_drop(&mut io, reason, &packet);
        assert_eq!(nat.mappings()[0], before_mapping);
        assert_eq!(nat.peers()[0], before_peer);
        assert_eq!(nat.counters(), before_counters);
    }

    io.inject(LAN, valid.clone());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(10),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44Icmpv4WrongIngress, &valid);

    let no_mapping_config = udp_config(&snapshot, true);
    let mut empty_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut empty_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut empty_nat =
        Nat44UdpRuntime::new(no_mapping_config, &mut empty_mappings, &mut empty_peers);
    io.inject(WAN, valid.clone());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &no_mapping_config,
        Some(&mut empty_nat),
        MonotonicMillis(10),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpMappingMiss, &valid);

    io.inject(WAN, valid.clone());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        None,
        MonotonicMillis(10),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpRuntimeUnavailable, &valid);
}

#[test]
fn combined_realm_mismatch_is_candidate_only_and_precedes_lookup_without_counters() {
    let routes = [
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
        Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(GW)).unwrap(),
    ];
    let interfaces = [
        Interface {
            id: LAN,
            mac: LAN_MAC,
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
        },
        Interface {
            id: DMZ,
            mac: MacAddress([2, 0, 0, 0, 0, 3]),
        },
    ];
    let neighbors = [
        Neighbor {
            interface: LAN,
            target: HOST,
            mac: HOST_MAC,
        },
        Neighbor {
            interface: WAN,
            target: GW,
            mac: GW_MAC,
        },
    ];
    let bindings = [
        LocalIpv4Binding {
            interface: LAN,
            address: LAN_LOCAL,
        },
        LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        },
        LocalIpv4Binding {
            interface: DMZ,
            address: OTHER_PUBLIC,
        },
    ];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let tcp_config = tcp_config(&snapshot, true);
    let udp_config = Nat44UdpConfig::new(
        &snapshot,
        LAN,
        DMZ,
        OTHER_PUBLIC,
        40_000,
        40_000,
        Nat44UdpPolicy::default().with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly),
    )
    .unwrap();
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut udp = Nat44UdpRuntime::new(udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut tcp = Nat44TcpRuntime::new(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let udp_counters = udp.counters();
    let tcp_counters = tcp.counters();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);

    let mut quote = tcp_frame(REMOTE, 443, 0)[14..42].to_vec();
    quote[12..16].copy_from_slice(&PUBLIC.octets());
    quote[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
    refresh_inner_checksum(&mut quote);
    let candidate = frag_needed(&quote, 64, 0, &[]);
    let mut io = SimIo::new();
    io.inject(WAN, candidate.clone());
    io.run_nat44_udp_and_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44CombinedRealmMismatch, &candidate);
    assert_eq!(udp.counters(), udp_counters);
    assert_eq!(tcp.counters(), tcp_counters);

    let ordinary = frag_needed(&quote, 64, 0, &[]);
    let mut non_candidate = ordinary.clone();
    non_candidate[35] = 3;
    refresh_icmp_and_outer_checksums(&mut non_candidate);
    io.inject(WAN, non_candidate);
    let report = io
        .run_nat44_udp_and_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &udp_config,
            Some(&mut udp),
            &tcp_config,
            Some(&mut tcp),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_eq!((report.consumed, report.dropped), (1, 0));
    assert_eq!(udp.counters(), udp_counters);
    assert_eq!(tcp.counters(), tcp_counters);
}

#[test]
fn outer_source_admission_rejects_non_hosts_local_and_inside_routes_atomically() {
    let routes = [
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
        Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, WAN, None).unwrap(),
        Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(GW)).unwrap(),
    ];
    let interfaces = [
        Interface {
            id: LAN,
            mac: LAN_MAC,
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
        },
    ];
    let neighbors = [
        Neighbor {
            interface: LAN,
            target: HOST,
            mac: HOST_MAC,
        },
        Neighbor {
            interface: WAN,
            target: GW,
            mac: GW_MAC,
        },
    ];
    let bindings = [
        LocalIpv4Binding {
            interface: LAN,
            address: LAN_LOCAL,
        },
        LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        },
    ];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = udp_config(&snapshot, true);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat = Nat44UdpRuntime::new(config, &mut mappings, &mut peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(LAN, udp_frame(REMOTE, 53, 0));
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    let outbound = io.pop_tx().unwrap();
    let valid = frag_needed(&outbound.bytes[14..42], 64, 0, &[]);
    let before_mapping = nat.mappings()[0];
    let before_peer = nat.peers()[0];
    let before_nat_counters = nat.counters();
    let before_resolution_counters = resolution.counters();

    let invalid_sources = [
        (
            Ipv4Address::from_octets([0, 1, 2, 3]),
            DropReason::Ipv4SourceUnspecifiedNetwork,
        ),
        (
            Ipv4Address::from_octets([127, 0, 0, 1]),
            DropReason::Ipv4SourceLoopback,
        ),
        (
            Ipv4Address::from_octets([224, 0, 0, 1]),
            DropReason::Ipv4SourceMulticast,
        ),
        (
            Ipv4Address::from_octets([240, 0, 0, 1]),
            DropReason::Ipv4SourceClassE,
        ),
        (
            Ipv4Address::from_octets([255; 4]),
            DropReason::Ipv4SourceLimitedBroadcast,
        ),
        (
            Ipv4Address::from_octets([192, 0, 2, 0]),
            DropReason::Ipv4SourceNetworkAddress,
        ),
        (
            Ipv4Address::from_octets([192, 0, 2, 255]),
            DropReason::Ipv4SourceDirectedBroadcast,
        ),
        (PUBLIC, DropReason::Nat44Icmpv4SourceForbidden),
        (LAN_LOCAL, DropReason::Nat44Icmpv4SourceForbidden),
        (HOST, DropReason::Nat44Icmpv4SourceForbidden),
    ];
    for (source, reason) in invalid_sources {
        let mut packet = valid.clone();
        set_outer_source(&mut packet, source);
        io.inject(WAN, packet.clone());
        io.run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
        assert_drop(&mut io, reason, &packet);
        assert_eq!(nat.mappings()[0], before_mapping);
        assert_eq!(nat.peers()[0], before_peer);
        assert_eq!(nat.counters(), before_nat_counters);
        assert_eq!(resolution.counters(), before_resolution_counters);
        assert_eq!(resolution.pending_actions(), 0);
    }

    let intermediate = Ipv4Address::from_octets([198, 18, 0, 1]);
    let mut packet = valid;
    set_outer_source(&mut packet, intermediate);
    io.inject(WAN, packet);
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    let translated = io.pop_tx().unwrap();
    assert_eq!(&translated.bytes[26..30], &intermediate.octets());
}

#[test]
fn mixed_protocol_policies_and_padding_peek_preserve_legacy_local_handling() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let mut udp_quote = udp_frame(REMOTE, 53, 0)[14..42].to_vec();
    udp_quote[12..16].copy_from_slice(&PUBLIC.octets());
    udp_quote[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
    refresh_inner_checksum(&mut udp_quote);
    let mut tcp_quote = tcp_frame(REMOTE, 443, 0)[14..42].to_vec();
    tcp_quote[12..16].copy_from_slice(&PUBLIC.octets());
    tcp_quote[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
    refresh_inner_checksum(&mut tcp_quote);

    for (udp_enabled, tcp_enabled, legacy, intercepted, intercepted_reason) in [
        (
            true,
            false,
            frag_needed(&tcp_quote, 64, 0, &[]),
            frag_needed(&udp_quote, 64, 0, &[]),
            DropReason::Nat44UdpMappingMiss,
        ),
        (
            false,
            true,
            frag_needed(&udp_quote, 64, 0, &[]),
            frag_needed(&tcp_quote, 64, 0, &[]),
            DropReason::Nat44TcpMappingMiss,
        ),
    ] {
        let udp_config = udp_config(&snapshot, udp_enabled);
        let tcp_config = tcp_config(&snapshot, tcp_enabled);
        let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
        let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
        let mut udp = Nat44UdpRuntime::new(udp_config, &mut udp_mappings, &mut udp_peers);
        let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
        let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
        let mut tcp = Nat44TcpRuntime::new(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution = resolution(&mut states, &mut actions);
        let mut io = SimIo::new();

        io.inject(WAN, legacy);
        let report = io
            .run_nat44_udp_and_tcp_once(
                1,
                &snapshot,
                &mut resolution,
                &udp_config,
                Some(&mut udp),
                &tcp_config,
                Some(&mut tcp),
                MonotonicMillis(0),
                &mut NoTrace,
            )
            .unwrap();
        assert_eq!((report.consumed, report.dropped), (1, 0));
        assert_eq!(
            io.pop_recycled().unwrap().cause,
            RecycleCause::Consumed(ConsumeReason::Ipv4LocalUnsupported)
        );

        io.inject(WAN, intercepted.clone());
        io.run_nat44_udp_and_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &udp_config,
            Some(&mut udp),
            &tcp_config,
            Some(&mut tcp),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
        assert_drop(&mut io, intercepted_reason, &intercepted);
    }

    let config = udp_config(&snapshot, true);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat = Nat44UdpRuntime::new(config, &mut mappings, &mut peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut padding_only = frag_needed(&udp_quote, 64, 0, &[]);
    padding_only[16..18].copy_from_slice(&20_u16.to_be_bytes());
    padding_only[24..26].fill(0);
    let checksum = ipv4_header_checksum(&padding_only[14..34]);
    padding_only[24..26].copy_from_slice(&checksum.to_be_bytes());
    let mut io = SimIo::new();
    io.inject(WAN, padding_only.clone());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Icmpv4HeaderTruncated, &padding_only);
    assert_eq!(nat.counters(), Default::default());
}

#[test]
fn same_batch_combined_dispatches_same_public_port_and_preserves_all_mtu_values() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let udp_config = udp_config(&snapshot, true);
    let tcp_config = tcp_config(&snapshot, true);
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut udp = Nat44UdpRuntime::new(udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut tcp = Nat44TcpRuntime::new(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);

    let mut udp_quote = udp_frame(REMOTE, 53, 0)[14..42].to_vec();
    udp_quote[12..16].copy_from_slice(&PUBLIC.octets());
    udp_quote[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
    refresh_inner_checksum(&mut udp_quote);
    let mut tcp_quote = tcp_frame(REMOTE, 443, 0)[14..42].to_vec();
    tcp_quote[12..16].copy_from_slice(&PUBLIC.octets());
    tcp_quote[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
    refresh_inner_checksum(&mut tcp_quote);
    let mut io = SimIo::new();
    io.inject(LAN, udp_frame(REMOTE, 53, 0));
    io.inject(LAN, tcp_frame(REMOTE, 443, 0));
    io.inject(WAN, frag_needed(&udp_quote, 64, 0, &[]));
    io.inject(WAN, frag_needed(&tcp_quote, 64, 0, &[]));
    let report = io
        .run_nat44_udp_and_tcp_once(
            4,
            &snapshot,
            &mut resolution,
            &udp_config,
            Some(&mut udp),
            &tcp_config,
            Some(&mut tcp),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_eq!((report.tx_requested, report.dropped), (4, 0));
    assert_eq!(io.pop_tx().unwrap().egress, WAN);
    assert_eq!(io.pop_tx().unwrap().egress, WAN);
    for protocol in [17, 6] {
        let translated = io.pop_tx().unwrap();
        assert_eq!(translated.egress, LAN);
        assert_eq!(translated.bytes[51], protocol);
        assert_eq!(
            u16::from_be_bytes(translated.bytes[62..64].try_into().unwrap()),
            12_345
        );
    }
    assert_eq!(udp.mappings()[0].public_port(), 40_000);
    assert_eq!(tcp.mappings()[0].public_port(), 40_000);

    for mtu in [0, 68, 1500, u16::MAX] {
        let mut error = frag_needed(&udp_quote, 64, 0, &[]);
        set_frag_needed_mtu(&mut error, mtu);
        io.inject(WAN, error);
        io.run_nat44_udp_and_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &udp_config,
            Some(&mut udp),
            &tcp_config,
            Some(&mut tcp),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
        let translated = io.pop_tx().unwrap();
        assert_eq!(
            u16::from_be_bytes(translated.bytes[40..42].try_into().unwrap()),
            mtu
        );
        assert_outer_icmp_checksum_valid(&translated.bytes);
    }
}

#[test]
fn udp_tcp_runtime_config_and_snapshot_mismatches_fail_before_read_only_lookup() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let udp_config = udp_config(&snapshot, true);
    let tcp_config = tcp_config(&snapshot, true);
    let mut udp_quote = udp_frame(REMOTE, 53, 0)[14..42].to_vec();
    udp_quote[12..16].copy_from_slice(&PUBLIC.octets());
    udp_quote[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
    refresh_inner_checksum(&mut udp_quote);
    let udp_error = frag_needed(&udp_quote, 64, 0, &[]);
    let mut tcp_quote = tcp_frame(REMOTE, 443, 0)[14..42].to_vec();
    tcp_quote[12..16].copy_from_slice(&PUBLIC.octets());
    tcp_quote[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
    refresh_inner_checksum(&mut tcp_quote);
    let tcp_error = frag_needed(&tcp_quote, 64, 0, &[]);

    let alternate_udp = Nat44UdpConfig::new(
        &snapshot,
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44UdpPolicy::new(Nat44UdpPolicy::default().idle_ttl_ms(), 1)
            .unwrap()
            .with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly),
    )
    .unwrap();
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut udp = Nat44UdpRuntime::new(alternate_udp, &mut udp_mappings, &mut udp_peers);
    let udp_counters = udp.counters();
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(WAN, udp_error.clone());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpConfigMismatch, &udp_error);
    assert_eq!(udp.counters(), udp_counters);

    let alternate_tcp = Nat44TcpConfig::new(
        &snapshot,
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44TcpPolicy::new(Nat44TcpPolicy::default().idle_ttl_ms(), 1)
            .unwrap()
            .with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly),
    )
    .unwrap();
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut tcp = Nat44TcpRuntime::new(alternate_tcp, &mut tcp_mappings, &mut tcp_sessions);
    let tcp_counters = tcp.counters();
    io.inject(WAN, tcp_error.clone());
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &tcp_config,
        Some(&mut tcp),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44TcpConfigMismatch, &tcp_error);
    assert_eq!(tcp.counters(), tcp_counters);

    let changed_neighbors = [
        neighbors[0],
        Neighbor {
            interface: WAN,
            target: GW,
            mac: MacAddress([2, 0, 0, 0, 0, 99]),
        },
    ];
    let changed_snapshot =
        ForwardingSnapshot::new(&routes, &interfaces, &changed_neighbors, &bindings).unwrap();
    let mut matching_udp_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut matching_udp_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut matching_udp = Nat44UdpRuntime::new(
        udp_config,
        &mut matching_udp_mappings,
        &mut matching_udp_peers,
    );
    io.inject(WAN, udp_error.clone());
    io.run_nat44_udp_once(
        1,
        &changed_snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut matching_udp),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpConfigMismatch, &udp_error);

    let mut matching_tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut matching_tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut matching_tcp = Nat44TcpRuntime::new(
        tcp_config,
        &mut matching_tcp_mappings,
        &mut matching_tcp_sessions,
    );
    io.inject(WAN, tcp_error.clone());
    io.run_nat44_tcp_once(
        1,
        &changed_snapshot,
        &mut resolution,
        &tcp_config,
        Some(&mut matching_tcp),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44TcpConfigMismatch, &tcp_error);

    io.inject(WAN, tcp_error.clone());
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &tcp_config,
        None,
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44TcpRuntimeUnavailable, &tcp_error);
}

#[test]
fn unresolved_inside_neighbor_schedules_arp_then_dynamic_learning_allows_translation() {
    let (routes, interfaces, _, bindings) = topology();
    let neighbors = [Neighbor {
        interface: WAN,
        target: GW,
        mac: GW_MAC,
    }];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = udp_config(&snapshot, true);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat = Nat44UdpRuntime::new(config, &mut mappings, &mut peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        &mut states,
        &mut actions,
        &mut dynamic,
    );
    let mut io = SimIo::new();
    io.inject(LAN, udp_frame(REMOTE, 53, 0));
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    let outbound = io.pop_tx().unwrap();
    let error = frag_needed(&outbound.bytes[14..42], 64, 0, &[]);
    let before_mapping = nat.mappings()[0];
    let before_peer = nat.peers()[0];
    let before_counters = nat.counters();
    io.inject(WAN, error.clone());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::NeighborUnresolved, &error);
    assert_eq!(resolution.pending_actions(), 1);
    assert_eq!(nat.mappings()[0], before_mapping);
    assert_eq!(nat.peers()[0], before_peer);
    assert_eq!(nat.counters(), before_counters);

    io.inject(LAN, arp_reply(HOST, HOST_MAC));
    let learned = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(2),
            &mut NoTrace,
        )
        .unwrap();
    assert_eq!(learned.consumed, 1);
    assert_eq!(resolution.dynamic_neighbor_count(), 1);
    io.pop_recycled();

    io.inject(WAN, error);
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(2),
        &mut NoTrace,
    )
    .unwrap();
    let translated = io.pop_tx().unwrap();
    assert_eq!(translated.egress, LAN);
    assert_eq!(&translated.bytes[0..6], &HOST_MAC.0);
}
