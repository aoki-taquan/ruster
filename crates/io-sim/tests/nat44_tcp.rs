mod support;

use ruster_core::{
    internet_checksum, ipv4_header_checksum, rfc1624_update, DropReason, ForwardingSnapshot, IfId,
    Interface, Ipv4Address, LocalIpv4Binding, MacAddress, MonotonicMillis, Nat44TcpConfig,
    Nat44TcpMappingSlot, Nat44TcpPolicy, Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44UdpConfig,
    Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy, Neighbor, NoTrace, ResolutionActionSlot,
    ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route, TraceEvent,
    NAT44_TCP_DEFAULT_IDLE_TTL_MS,
};
use ruster_io_sim::{RecycleCause, SimIo, VecTrace};
use support::UdpTestIndexes;

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const HOST_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 10]);
const GW_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 20]);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const HOST: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
const HOST2: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 11]);
const REMOTE1: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const REMOTE2: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 30]);
const GW: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);

fn topology() -> (
    [Route; 2],
    [Interface; 2],
    [Neighbor; 3],
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
                interface: LAN,
                target: HOST2,
                mac: MacAddress([2, 0, 0, 0, 0, 11]),
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
                address: Ipv4Address::from_octets([10, 0, 0, 1]),
            },
            LocalIpv4Binding {
                interface: WAN,
                address: PUBLIC,
            },
        ],
    )
}

fn config(snapshot: &ForwardingSnapshot<'_>, first: u16, last: u16) -> Nat44TcpConfig {
    Nat44TcpConfig::new(
        snapshot,
        LAN,
        WAN,
        PUBLIC,
        first,
        last,
        Nat44TcpPolicy::default(),
    )
    .unwrap()
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

fn checksum_for_tcp(source: Ipv4Address, destination: Ipv4Address, segment: &[u8]) -> u16 {
    let mut bytes = Vec::with_capacity(12 + segment.len());
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&destination.octets());
    bytes.extend_from_slice(&[0, 6]);
    bytes.extend_from_slice(&u16::try_from(segment.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(segment);
    internet_checksum(&bytes)
}

#[allow(clippy::too_many_arguments)]
fn tcp_frame(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    ttl: u8,
    flags_fragment: u16,
    flags: u8,
    options: &[u8],
    data: &[u8],
    ip_padding: &[u8],
) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0);
    let tcp_len = 20 + options.len() + data.len();
    let total_len = 20 + tcp_len + ip_padding.len();
    let mut frame = vec![0_u8; 14 + total_len + 3];
    let ingress_mac = if source == HOST { LAN_MAC } else { WAN_MAC };
    frame[0..6].copy_from_slice(&ingress_mac.0);
    frame[6..12].copy_from_slice(&HOST_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = 0xb8;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[18..20].copy_from_slice(&0x4242_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    frame[22] = ttl;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    frame[38..42].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
    frame[42..46].copy_from_slice(&0x0506_0708_u32.to_be_bytes());
    frame[46] = u8::try_from(5 + options.len() / 4).unwrap() << 4;
    frame[47] = flags;
    frame[48..50].copy_from_slice(&65_535_u16.to_be_bytes());
    frame[54..54 + options.len()].copy_from_slice(options);
    frame[54 + options.len()..54 + options.len() + data.len()].copy_from_slice(data);
    frame[54 + options.len() + data.len()..54 + options.len() + data.len() + ip_padding.len()]
        .copy_from_slice(ip_padding);
    let checksum = checksum_for_tcp(
        source,
        destination,
        &frame[34..34 + tcp_len + ip_padding.len()],
    );
    frame[50..52].copy_from_slice(&checksum.to_be_bytes());
    let ip_checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
    frame
}

fn tcp_checksum_valid(frame: &[u8]) -> bool {
    let source = Ipv4Address::from_octets(frame[26..30].try_into().unwrap());
    let destination = Ipv4Address::from_octets(frame[30..34].try_into().unwrap());
    let total = usize::from(u16::from_be_bytes(frame[16..18].try_into().unwrap()));
    checksum_for_tcp(source, destination, &frame[34..14 + total]) == 0
}

fn udp_frame(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 28];
    let ingress_mac = if source == HOST { LAN_MAC } else { WAN_MAC };
    frame[0..6].copy_from_slice(&ingress_mac.0);
    frame[6..12].copy_from_slice(&HOST_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&28_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    frame[38..40].copy_from_slice(&8_u16.to_be_bytes());
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn assert_drop(io: &mut SimIo, reason: DropReason, original: &[u8]) {
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(recycled.cause, RecycleCause::Forwarding(reason));
    assert_eq!(recycled.bytes, original);
}

fn refresh_ipv4_checksum(frame: &mut [u8]) {
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
}

fn non_transport_frame(source: Ipv4Address, destination: Ipv4Address, protocol: u8) -> Vec<u8> {
    let mut frame = tcp_frame(
        source,
        destination,
        40_000,
        443,
        64,
        0x4000,
        0x02,
        &[],
        &[],
        &[],
    );
    frame[23] = protocol;
    refresh_ipv4_checksum(&mut frame);
    frame
}

fn assert_external_non_transport_boundary_isolated(
    snapshot: &ForwardingSnapshot<'_>,
    udp_config: Nat44UdpConfig,
    tcp_config: Nat44TcpConfig,
) {
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut udp_indexes = UdpTestIndexes::new(udp_config, udp_mappings.len(), udp_peers.len());
    let mut udp = udp_indexes.runtime(udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut tcp = Nat44TcpRuntime::new(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut resolution = resolution(&mut states, &mut actions);
    let packets = [
        non_transport_frame(REMOTE1, HOST, 1),
        non_transport_frame(REMOTE1, HOST, 99),
    ];
    let mut io = SimIo::new();
    for packet in &packets {
        io.inject(WAN, packet.clone());
    }
    let mut trace = VecTrace::default();
    let report = io
        .run_nat44_udp_and_tcp_once(
            2,
            snapshot,
            &mut resolution,
            &udp_config,
            Some(&mut udp),
            &tcp_config,
            Some(&mut tcp),
            MonotonicMillis(100),
            &mut trace,
        )
        .unwrap();
    assert_eq!((report.tx_requested, report.dropped), (0, 2));
    for packet in &packets {
        assert_drop(&mut io, DropReason::Nat44ExternalToInternalBypass, packet);
    }
    assert!(!trace.events().iter().any(|event| {
        matches!(
            event,
            TraceEvent::Nat44Udp { .. }
                | TraceEvent::Nat44Tcp { .. }
                | TraceEvent::Routed { .. }
                | TraceEvent::NeighborResolution { .. }
        )
    }));
    assert_eq!(udp.counters(), Default::default());
    assert_eq!(tcp.counters(), Default::default());
    assert_eq!(resolution.counters(), Default::default());

    let udp_probe = udp_frame(REMOTE1, udp_config.public_address(), 53, 40_000);
    io.inject(udp_config.outside(), udp_probe.clone());
    io.run_nat44_udp_once(
        1,
        snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        MonotonicMillis(99),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpMappingMiss, &udp_probe);

    let (tcp_ingress, tcp_probe, tcp_reason) = if tcp_config.inside() == WAN {
        (
            WAN,
            tcp_frame(REMOTE1, HOST, 40_000, 443, 64, 0x4000, 0x02, &[], &[], &[]),
            DropReason::NeighborUnresolved,
        )
    } else {
        (
            tcp_config.outside(),
            tcp_frame(
                REMOTE1,
                tcp_config.public_address(),
                443,
                40_000,
                64,
                0x4000,
                0x12,
                &[],
                &[],
                &[],
            ),
            DropReason::Nat44TcpMappingMiss,
        )
    };
    io.inject(tcp_ingress, tcp_probe.clone());
    io.run_nat44_tcp_once(
        1,
        snapshot,
        &mut resolution,
        &tcp_config,
        Some(&mut tcp),
        MonotonicMillis(99),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, tcp_reason, &tcp_probe);
}

#[test]
fn syn_synack_and_data_translate_bidirectionally_in_one_batch() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_010);
    let mut mappings = [Nat44TcpMappingSlot::default(); 2];
    let mut sessions = [Nat44TcpSessionSlot::default(); 4];
    let mut nat = Nat44TcpRuntime::new(config, &mut mappings, &mut sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let outbound = tcp_frame(
        HOST,
        REMOTE1,
        40_000,
        443,
        64,
        0xc000,
        0xc2,
        &[2, 4, 5, 0xb4],
        &[1, 2, 3],
        &[0xaa],
    );
    let inbound = tcp_frame(
        REMOTE1,
        PUBLIC,
        443,
        40_000,
        50,
        0xc000,
        0x12,
        &[],
        &[],
        &[],
    );
    let mut io = SimIo::new();
    io.inject(LAN, outbound);
    io.inject(WAN, inbound);
    let report = io
        .run_nat44_tcp_once(
            2,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_eq!((report.tx_requested, report.dropped), (2, 0));
    let out = io.pop_tx().unwrap();
    assert_eq!(out.egress, WAN);
    assert_eq!(&out.bytes[0..6], &GW_MAC.0);
    assert_eq!(&out.bytes[26..30], &PUBLIC.octets());
    assert_eq!(out.bytes[22], 63);
    assert_eq!(&out.bytes[20..22], &0xc000_u16.to_be_bytes());
    assert_eq!(ipv4_header_checksum(&out.bytes[14..34]), 0);
    assert!(tcp_checksum_valid(&out.bytes));
    assert_eq!(&out.bytes[54..58], &[2, 4, 5, 0xb4]);
    assert_eq!(&out.bytes[58..61], &[1, 2, 3]);
    assert_eq!(out.bytes[61], 0xaa);
    let inbound = io.pop_tx().unwrap();
    assert_eq!(inbound.egress, LAN);
    assert_eq!(&inbound.bytes[30..34], &HOST.octets());
    assert_eq!(inbound.bytes[22], 49);
    assert_eq!(&inbound.bytes[20..22], &0xc000_u16.to_be_bytes());
    assert!(tcp_checksum_valid(&inbound.bytes));

    io.inject(
        LAN,
        tcp_frame(
            HOST,
            REMOTE1,
            40_000,
            443,
            64,
            0x4000,
            0x18,
            &[],
            &[7, 7, 7],
            &[],
        ),
    );
    io.inject(
        WAN,
        tcp_frame(
            REMOTE1,
            PUBLIC,
            443,
            40_000,
            64,
            0x4000,
            0x18,
            &[],
            &[8, 8, 8],
            &[],
        ),
    );
    io.run_nat44_tcp_once(
        2,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert!(tcp_checksum_valid(&io.pop_tx().unwrap().bytes));
    assert!(tcp_checksum_valid(&io.pop_tx().unwrap().bytes));
}

#[test]
fn eim_reuses_mapping_but_filter_is_exact_remote_endpoint() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_000);
    let mut mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut sessions = [Nat44TcpSessionSlot::default(); 2];
    let mut nat = Nat44TcpRuntime::new(config, &mut mappings, &mut sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    for (remote, port) in [(REMOTE1, 443), (REMOTE2, 8443)] {
        io.inject(
            LAN,
            tcp_frame(HOST, remote, 40_000, port, 64, 0x4000, 0x02, &[], &[], &[]),
        );
    }
    io.run_nat44_tcp_once(
        2,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_eq!(nat.counters().mappings_created, 1);
    assert_eq!(nat.counters().sessions_created, 2);
    io.pop_tx();
    io.pop_tx();

    let unknown = tcp_frame(
        REMOTE1,
        PUBLIC,
        444,
        40_000,
        64,
        0x4000,
        0x10,
        &[],
        &[],
        &[],
    );
    io.inject(WAN, unknown.clone());
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(2),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44TcpSessionMiss, &unknown);
}

#[test]
fn combined_udp_tcp_realms_keep_protocol_state_and_ports_independent() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let tcp_config = config(&snapshot, 40_000, 40_000);
    let udp_config = Nat44UdpConfig::new(
        &snapshot,
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44UdpPolicy::default(),
    )
    .unwrap();
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut tcp = Nat44TcpRuntime::new(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut udp_indexes = UdpTestIndexes::new(udp_config, udp_mappings.len(), udp_peers.len());
    let mut udp = udp_indexes.runtime(udp_config, &mut udp_mappings, &mut udp_peers);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(LAN, udp_frame(HOST, REMOTE1, 40_000, 53));
    io.inject(
        LAN,
        tcp_frame(HOST, REMOTE1, 40_000, 443, 64, 0x4000, 0x02, &[], &[], &[]),
    );
    io.run_nat44_udp_and_tcp_once(
        2,
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
    let udp_tx = io.pop_tx().unwrap();
    let tcp_tx = io.pop_tx().unwrap();
    assert_eq!(
        u16::from_be_bytes(udp_tx.bytes[34..36].try_into().unwrap()),
        40_000
    );
    assert_eq!(
        u16::from_be_bytes(tcp_tx.bytes[34..36].try_into().unwrap()),
        40_000
    );
    assert_eq!(udp.counters().outbound_translated, 1);
    assert_eq!(tcp.counters().outbound_translated, 1);
    assert_eq!(udp.counters().mapping_misses, 0);
    assert_eq!(tcp.counters().mapping_misses, 0);
}

#[test]
fn combined_realm_mismatch_fails_closed_without_cross_state() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let udp_config = Nat44UdpConfig::new(
        &snapshot,
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44UdpPolicy::default(),
    )
    .unwrap();
    let tcp_config = Nat44TcpConfig::new(
        &snapshot,
        WAN,
        LAN,
        Ipv4Address::from_octets([10, 0, 0, 1]),
        40_000,
        40_000,
        Nat44TcpPolicy::default(),
    )
    .unwrap();
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut udp_indexes = UdpTestIndexes::new(udp_config, udp_mappings.len(), udp_peers.len());
    let mut udp = udp_indexes.runtime(udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut tcp = Nat44TcpRuntime::new(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let packet = udp_frame(HOST, REMOTE1, 40_000, 53);
    let mut io = SimIo::new();
    io.inject(LAN, packet.clone());
    let mut trace = VecTrace::default();
    io.run_nat44_udp_and_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        MonotonicMillis(0),
        &mut trace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44CombinedRealmMismatch, &packet);
    assert!(udp.mappings().iter().all(|slot| !slot.is_occupied()));
    assert!(tcp.mappings().iter().all(|slot| !slot.is_occupied()));
    assert_eq!(udp.counters().config_mismatches, 1);
    assert_eq!(tcp.counters().config_mismatches, 1);
    assert!(matches!(
        trace.events(),
        [
            TraceEvent::Ipv4Validated { ingress: LAN, .. },
            TraceEvent::Nat44Udp {
                ingress: LAN,
                disposition: ruster_core::Nat44UdpDisposition::ConfigMismatch
            },
            TraceEvent::Nat44Tcp {
                ingress: LAN,
                disposition: ruster_core::Nat44TcpDisposition::ConfigMismatch
            },
            TraceEvent::Dropped {
                ingress: LAN,
                reason: DropReason::Nat44CombinedRealmMismatch
            },
            TraceEvent::BatchCompleted { .. }
        ]
    ));

    let tcp_packet = tcp_frame(HOST, REMOTE1, 40_000, 443, 64, 0x4000, 0x02, &[], &[], &[]);
    io.inject(LAN, tcp_packet.clone());
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
    assert_drop(&mut io, DropReason::Nat44CombinedRealmMismatch, &tcp_packet);
    assert_eq!(udp.counters().config_mismatches, 2);
    assert_eq!(tcp.counters().config_mismatches, 2);
}

#[test]
fn matching_and_mismatched_combined_external_boundary_is_protocol_independent() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot =
        ForwardingSnapshot::new(&routes, &interfaces, &neighbors[2..], &bindings).unwrap();
    let udp_config = Nat44UdpConfig::new(
        &snapshot,
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44UdpPolicy::default(),
    )
    .unwrap();
    let matching_tcp = config(&snapshot, 40_000, 40_000);
    assert_external_non_transport_boundary_isolated(&snapshot, udp_config, matching_tcp);

    let mismatched_tcp = Nat44TcpConfig::new(
        &snapshot,
        WAN,
        LAN,
        Ipv4Address::from_octets([10, 0, 0, 1]),
        40_000,
        40_000,
        Nat44TcpPolicy::default(),
    )
    .unwrap();
    assert_external_non_transport_boundary_isolated(&snapshot, udp_config, mismatched_tcp);
}

#[test]
fn combined_realm_mismatch_non_tcp_udp_outbound_is_isolated_and_fail_closed() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let udp_config = Nat44UdpConfig::new(
        &snapshot,
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44UdpPolicy::default(),
    )
    .unwrap();
    let tcp_config = Nat44TcpConfig::new(
        &snapshot,
        WAN,
        LAN,
        Ipv4Address::from_octets([10, 0, 0, 1]),
        40_000,
        40_000,
        Nat44TcpPolicy::default(),
    )
    .unwrap();
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut udp_indexes = UdpTestIndexes::new(udp_config, udp_mappings.len(), udp_peers.len());
    let mut udp = udp_indexes.runtime(udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut tcp = Nat44TcpRuntime::new(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut packets = Vec::new();
    for protocol in [1, 99] {
        let mut packet = tcp_frame(HOST, REMOTE1, 40_000, 443, 64, 0x4000, 0x02, &[], &[], &[]);
        packet[23] = protocol;
        refresh_ipv4_checksum(&mut packet);
        packets.push(packet);
    }

    let mut io = SimIo::new();
    for packet in &packets {
        io.inject(LAN, packet.clone());
    }
    let mut trace = VecTrace::default();
    let report = io
        .run_nat44_udp_and_tcp_once(
            2,
            &snapshot,
            &mut resolution,
            &udp_config,
            Some(&mut udp),
            &tcp_config,
            Some(&mut tcp),
            MonotonicMillis(100),
            &mut trace,
        )
        .unwrap();
    assert_eq!((report.tx_requested, report.dropped), (0, 2));
    for packet in &packets {
        assert_drop(&mut io, DropReason::Nat44ExternalToInternalBypass, packet);
    }
    assert!(!trace.events().iter().any(|event| {
        matches!(
            event,
            TraceEvent::Nat44Udp { .. }
                | TraceEvent::Nat44Tcp { .. }
                | TraceEvent::Routed { .. }
                | TraceEvent::NeighborResolution { .. }
        )
    }));
    assert_eq!(udp.counters(), Default::default());
    assert_eq!(tcp.counters(), Default::default());

    io.inject(LAN, udp_frame(HOST, REMOTE1, 40_000, 53));
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        MonotonicMillis(99),
        &mut NoTrace,
    )
    .unwrap();
    assert_eq!(io.pop_tx().unwrap().egress, WAN);

    io.inject(
        WAN,
        tcp_frame(REMOTE1, HOST, 40_000, 443, 64, 0x4000, 0x02, &[], &[], &[]),
    );
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &tcp_config,
        Some(&mut tcp),
        MonotonicMillis(99),
        &mut NoTrace,
    )
    .unwrap();
    assert_eq!(io.pop_tx().unwrap().egress, LAN);
}

#[test]
fn matching_combined_non_tcp_udp_outbound_fails_before_neighbor_without_nat_state() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot =
        ForwardingSnapshot::new(&routes, &interfaces, &neighbors[..2], &bindings).unwrap();
    let udp_config = Nat44UdpConfig::new(
        &snapshot,
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44UdpPolicy::default(),
    )
    .unwrap();
    let tcp_config = config(&snapshot, 40_000, 40_000);
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut udp_indexes = UdpTestIndexes::new(udp_config, udp_mappings.len(), udp_peers.len());
    let mut udp = udp_indexes.runtime(udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut tcp = Nat44TcpRuntime::new(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut resolution = resolution(&mut states, &mut actions);
    let packets = [
        non_transport_frame(HOST, REMOTE1, 1),
        non_transport_frame(HOST, REMOTE1, 99),
    ];
    let mut io = SimIo::new();
    for packet in &packets {
        io.inject(LAN, packet.clone());
    }
    let mut trace = VecTrace::default();
    let report = io
        .run_nat44_udp_and_tcp_once(
            2,
            &snapshot,
            &mut resolution,
            &udp_config,
            Some(&mut udp),
            &tcp_config,
            Some(&mut tcp),
            MonotonicMillis(100),
            &mut trace,
        )
        .unwrap();
    assert_eq!((report.tx_requested, report.dropped), (0, 2));
    for packet in &packets {
        assert_drop(&mut io, DropReason::Nat44UdpUnsupportedTransport, packet);
    }
    assert!(!trace.events().iter().any(|event| {
        matches!(
            event,
            TraceEvent::Nat44Udp { .. }
                | TraceEvent::Nat44Tcp { .. }
                | TraceEvent::Routed { .. }
                | TraceEvent::NeighborResolution { .. }
        )
    }));
    assert_eq!(udp.counters(), Default::default());
    assert_eq!(tcp.counters(), Default::default());
    assert_eq!(resolution.counters(), Default::default());

    let udp_probe = udp_frame(REMOTE1, PUBLIC, 53, 40_000);
    io.inject(WAN, udp_probe.clone());
    io.run_nat44_udp_and_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        MonotonicMillis(99),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpMappingMiss, &udp_probe);

    let tcp_probe = tcp_frame(HOST, REMOTE1, 40_000, 443, 64, 0x4000, 0x02, &[], &[], &[]);
    io.inject(LAN, tcp_probe.clone());
    io.run_nat44_udp_and_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        MonotonicMillis(99),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::NeighborUnresolved, &tcp_probe);
}

#[test]
fn only_initial_syn_creates_and_fin_rst_only_refresh_idle_lifetime() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_000);
    let mut mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut nat = Nat44TcpRuntime::new(config, &mut mappings, &mut sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    for flags in [0x10, 0x01, 0x04, 0x18] {
        let packet = tcp_frame(
            HOST,
            REMOTE1,
            40_000,
            443,
            64,
            0x4000,
            flags,
            &[],
            &[1],
            &[],
        );
        io.inject(LAN, packet.clone());
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
        assert_drop(&mut io, DropReason::Nat44TcpInvalidInitialFlags, &packet);
    }
    io.inject(
        LAN,
        tcp_frame(HOST, REMOTE1, 40_000, 443, 64, 0x4000, 0x02, &[], &[], &[]),
    );
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
    io.pop_tx();
    for (at, flags) in [(2, 0x02), (3, 0x11), (4, 0x14)] {
        io.inject(
            WAN,
            tcp_frame(
                REMOTE1,
                PUBLIC,
                443,
                40_000,
                64,
                0x4000,
                flags,
                &[],
                &[],
                &[],
            ),
        );
        io.run_nat44_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(at),
            &mut NoTrace,
        )
        .unwrap();
        io.pop_tx().unwrap();
    }
    assert_eq!(nat.sessions()[0].last_activity_ms(), 4);
}

#[test]
fn exact_idle_boundary_bidirectional_refresh_and_unmatched_no_refresh() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_000);
    assert_eq!(config.policy().idle_ttl_ms(), NAT44_TCP_DEFAULT_IDLE_TTL_MS);
    let mut mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut nat = Nat44TcpRuntime::new(config, &mut mappings, &mut sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(
        LAN,
        tcp_frame(HOST, REMOTE1, 40_000, 443, 64, 0x4000, 0x02, &[], &[], &[]),
    );
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
    io.pop_tx();
    let miss = tcp_frame(
        REMOTE2,
        PUBLIC,
        443,
        40_000,
        64,
        0x4000,
        0x10,
        &[],
        &[],
        &[],
    );
    io.inject(WAN, miss.clone());
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(NAT44_TCP_DEFAULT_IDLE_TTL_MS - 1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44TcpSessionMiss, &miss);
    let expired = tcp_frame(
        REMOTE1,
        PUBLIC,
        443,
        40_000,
        64,
        0x4000,
        0x10,
        &[],
        &[],
        &[],
    );
    io.inject(WAN, expired.clone());
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(NAT44_TCP_DEFAULT_IDLE_TTL_MS),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44TcpMappingMiss, &expired);
}

#[test]
fn malformed_checksum_fragment_source_zero_and_options_are_atomic() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_000);
    let mut mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut nat = Nat44TcpRuntime::new(config, &mut mappings, &mut sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    let mut cases = Vec::new();
    let mut checksum = tcp_frame(HOST, REMOTE1, 40_000, 443, 64, 0x4000, 0x02, &[], &[], &[]);
    checksum[50] ^= 1;
    cases.push((checksum, DropReason::Nat44TcpChecksumInvalid));
    cases.push((
        tcp_frame(HOST, REMOTE1, 40_000, 443, 64, 0, 0x02, &[], &[], &[]),
        DropReason::Nat44TcpNonAtomicIpv4Unsupported,
    ));
    cases.push((
        tcp_frame(HOST, REMOTE1, 40_000, 443, 64, 0xe000, 0x02, &[], &[], &[]),
        DropReason::Nat44TcpNonAtomicIpv4Unsupported,
    ));
    cases.push((
        tcp_frame(HOST, REMOTE1, 40_000, 443, 64, 0xc001, 0x02, &[], &[], &[]),
        DropReason::Nat44TcpNonAtomicIpv4Unsupported,
    ));
    cases.push((
        tcp_frame(HOST, REMOTE1, 0, 443, 64, 0x4000, 0x02, &[], &[], &[]),
        DropReason::Nat44TcpSourcePortZero,
    ));
    let mut offset = tcp_frame(HOST, REMOTE1, 40_000, 443, 64, 0x4000, 0x02, &[], &[], &[]);
    offset[46] = 0x40;
    cases.push((offset, DropReason::Nat44TcpDataOffsetTooSmall));
    for (packet, reason) in cases {
        io.inject(LAN, packet.clone());
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
        assert_drop(&mut io, reason, &packet);
        assert!(nat.mappings().iter().all(|slot| !slot.is_occupied()));
    }
}

#[test]
fn icmp_crossing_fails_closed_without_touching_tcp_clock_or_state() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_000);
    let mut mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut nat = Nat44TcpRuntime::new(config, &mut mappings, &mut sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut icmp = tcp_frame(HOST, REMOTE1, 40_000, 443, 64, 0x4000, 0x02, &[], &[], &[]);
    icmp[23] = 1;
    refresh_ipv4_checksum(&mut icmp);
    let mut io = SimIo::new();
    io.inject(LAN, icmp.clone());
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
    assert_drop(&mut io, DropReason::Nat44TcpUnsupportedTransport, &icmp);
    assert_eq!(nat.counters(), Default::default());

    io.inject(
        LAN,
        tcp_frame(HOST, REMOTE1, 40_000, 443, 64, 0x4000, 0x02, &[], &[], &[]),
    );
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(99),
        &mut NoTrace,
    )
    .unwrap();
    assert_eq!(io.pop_tx().unwrap().egress, WAN);
}

#[test]
fn backend_reject_retains_tx_requested_mapping_and_session() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_000);
    let mut mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut nat = Nat44TcpRuntime::new(config, &mut mappings, &mut sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.set_received_accept_budget(0);
    io.inject(
        LAN,
        tcp_frame(HOST, REMOTE1, 40_000, 443, 64, 0x4000, 0x02, &[], &[], &[]),
    );
    let report = io
        .run_nat44_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_eq!(report.tx_requested, 1);
    assert_eq!(report.completion.tx_rejected, 1);
    assert_eq!(io.pop_recycled().unwrap().cause, RecycleCause::TxRejected);
    assert_eq!(nat.counters().mappings_created, 1);
    assert_eq!(nat.counters().sessions_created, 1);

    io.inject(
        LAN,
        tcp_frame(HOST, REMOTE1, 40_000, 443, 64, 0x4000, 0x18, &[], &[1], &[]),
    );
    let refresh_ms = 10;
    let report = io
        .run_nat44_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(refresh_ms),
            &mut NoTrace,
        )
        .unwrap();
    assert_eq!(report.completion.tx_rejected, 1);
    assert_eq!(io.pop_recycled().unwrap().cause, RecycleCause::TxRejected);
    assert_eq!(nat.counters().mappings_reused, 1);
    assert_eq!(nat.counters().sessions_reused, 1);

    io.set_received_accept_budget(1);
    io.inject(
        WAN,
        tcp_frame(
            REMOTE1,
            PUBLIC,
            443,
            40_000,
            64,
            0x4000,
            0x12,
            &[],
            &[],
            &[],
        ),
    );
    io.run_nat44_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(refresh_ms + NAT44_TCP_DEFAULT_IDLE_TTL_MS - 1),
        &mut NoTrace,
    )
    .unwrap();
    assert_eq!(io.pop_tx().unwrap().egress, LAN);
}

#[test]
fn incremental_tcp_checksum_keeps_mathematical_zero_on_wire() {
    let old_address = HOST.octets();
    let new_address = PUBLIC.octets();
    let mut found = None;
    for checksum in 0..=u16::MAX {
        let updated = rfc1624_update(
            rfc1624_update(
                rfc1624_update(
                    checksum,
                    u16::from_be_bytes([old_address[0], old_address[1]]),
                    u16::from_be_bytes([new_address[0], new_address[1]]),
                ),
                u16::from_be_bytes([old_address[2], old_address[3]]),
                u16::from_be_bytes([new_address[2], new_address[3]]),
            ),
            40_000,
            40_001,
        );
        if updated == 0 {
            found = Some(checksum);
            break;
        }
    }
    let desired = found.expect("RFC 1624 zero-result boundary exists");
    let base = tcp_frame(
        HOST,
        REMOTE1,
        40_000,
        443,
        64,
        0x4000,
        0x02,
        &[],
        &[0, 0],
        &[],
    );
    let base_checksum = u16::from_be_bytes(base[50..52].try_into().unwrap());
    let payload_word = (0..=u16::MAX)
        .find(|word| rfc1624_update(base_checksum, 0, *word) == desired)
        .expect("a payload word reaches every checksum residue");
    let packet = tcp_frame(
        HOST,
        REMOTE1,
        40_000,
        443,
        64,
        0x4000,
        0x02,
        &[],
        &payload_word.to_be_bytes(),
        &[],
    );
    assert_eq!(
        u16::from_be_bytes(packet[50..52].try_into().unwrap()),
        desired
    );

    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_001, 40_001);
    let mut mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut nat = Nat44TcpRuntime::new(config, &mut mappings, &mut sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(LAN, packet);
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
    let translated = io.pop_tx().unwrap();
    assert_eq!(
        u16::from_be_bytes(translated.bytes[50..52].try_into().unwrap()),
        0
    );
    assert!(tcp_checksum_valid(&translated.bytes));
}

#[test]
fn a_deliberately_valid_zero_tcp_checksum_field_is_accepted() {
    let seed = tcp_frame(
        HOST,
        REMOTE1,
        40_000,
        443,
        64,
        0x4000,
        0x02,
        &[],
        &[0, 0],
        &[],
    );
    let adjustment = u16::from_be_bytes(seed[50..52].try_into().unwrap());
    let packet = tcp_frame(
        HOST,
        REMOTE1,
        40_000,
        443,
        64,
        0x4000,
        0x02,
        &[],
        &adjustment.to_be_bytes(),
        &[],
    );
    assert_eq!(u16::from_be_bytes(packet[50..52].try_into().unwrap()), 0);
    assert!(tcp_checksum_valid(&packet));

    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_000);
    let mut mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut nat = Nat44TcpRuntime::new(config, &mut mappings, &mut sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(LAN, packet);
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
    assert!(tcp_checksum_valid(&io.pop_tx().unwrap().bytes));
}
