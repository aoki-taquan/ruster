mod support;

use ruster_core::{
    internet_checksum, ipv4_header_checksum, rfc1624_update, DropReason, DynamicNeighborSlot,
    ForwardingSnapshot, IfId, Interface, Ipv4Address, LocalIpv4Binding, MacAddress,
    MonotonicMillis, Nat44UdpConfig, Nat44UdpConfigError, Nat44UdpDisposition, Nat44UdpMappingSlot,
    Nat44UdpPeerSlot, Nat44UdpPolicy, Neighbor, NoTrace, ResolutionActionSlot, ResolutionPolicy,
    ResolutionRuntime, ResolutionStateSlot, Route, TraceEvent, NAT44_UDP_MIN_IDLE_TTL_MS,
};
use ruster_io_sim::{RecycleCause, SimIo, VecTrace};
use support::UdpTestIndexes;

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const DMZ: IfId = IfId(3);
const LAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
const DMZ_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 3]);
const HOST_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 10]);
const GATEWAY_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 20]);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const LAN_LOCAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 1]);
const HOST: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
const HOST2: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 11]);
const REMOTE1: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const REMOTE2: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 30]);
const GATEWAY: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);

fn base() -> (
    [Route; 2],
    [Interface; 3],
    [Neighbor; 3],
    [LocalIpv4Binding; 2],
) {
    (
        [
            Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
            Route::new(
                Ipv4Address::from_octets([0, 0, 0, 0]),
                0,
                WAN,
                Some(GATEWAY),
            )
            .unwrap(),
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
            Interface {
                id: DMZ,
                mac: DMZ_MAC,
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
                mac: MacAddress([0x02, 0, 0, 0, 0, 11]),
            },
            Neighbor {
                interface: WAN,
                target: GATEWAY,
                mac: GATEWAY_MAC,
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

fn config(snapshot: &ForwardingSnapshot<'_>, first: u16, last: u16) -> Nat44UdpConfig {
    Nat44UdpConfig::new(
        snapshot,
        LAN,
        WAN,
        PUBLIC,
        first,
        last,
        Nat44UdpPolicy::default(),
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

#[derive(Clone, Copy)]
enum UdpChecksum {
    Zero,
    Valid,
    Raw(u16),
}

#[allow(clippy::too_many_arguments)]
fn udp_frame(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    ttl: u8,
    flags_fragment: u16,
    payload: &[u8],
    ip_padding: &[u8],
    checksum_mode: UdpChecksum,
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len + ip_padding.len();
    let mut frame = vec![0_u8; 14 + total_len + 3];
    let ingress_mac = if source.octets()[0] == 10 {
        LAN_MAC
    } else {
        WAN_MAC
    };
    frame[0..6].copy_from_slice(&ingress_mac.0);
    frame[6..12].copy_from_slice(&HOST_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = 0xb8;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[18..20].copy_from_slice(&0x4242_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    frame[22] = ttl;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    frame[38..40].copy_from_slice(&u16::try_from(udp_len).unwrap().to_be_bytes());
    frame[42..42 + payload.len()].copy_from_slice(payload);
    frame[42 + payload.len()..42 + payload.len() + ip_padding.len()].copy_from_slice(ip_padding);
    let udp_checksum = match checksum_mode {
        UdpChecksum::Zero => 0,
        UdpChecksum::Raw(value) => value,
        UdpChecksum::Valid => compute_udp_checksum(&frame, source, destination, udp_len),
    };
    frame[40..42].copy_from_slice(&udp_checksum.to_be_bytes());
    let ip_checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
    frame
}

fn compute_udp_checksum(
    frame: &[u8],
    source: Ipv4Address,
    destination: Ipv4Address,
    udp_len: usize,
) -> u16 {
    let mut bytes = Vec::with_capacity(12 + udp_len);
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&destination.octets());
    bytes.extend_from_slice(&[0, 17]);
    bytes.extend_from_slice(&u16::try_from(udp_len).unwrap().to_be_bytes());
    bytes.extend_from_slice(&frame[34..34 + udp_len]);
    bytes[18] = 0;
    bytes[19] = 0;
    let checksum = internet_checksum(&bytes);
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

fn udp_checksum_valid(frame: &[u8]) -> bool {
    let source = Ipv4Address::from_octets(frame[26..30].try_into().unwrap());
    let destination = Ipv4Address::from_octets(frame[30..34].try_into().unwrap());
    let udp_len = usize::from(u16::from_be_bytes(frame[38..40].try_into().unwrap()));
    let mut bytes = Vec::with_capacity(12 + udp_len);
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&destination.octets());
    bytes.extend_from_slice(&[0, 17]);
    bytes.extend_from_slice(&u16::try_from(udp_len).unwrap().to_be_bytes());
    bytes.extend_from_slice(&frame[34..34 + udp_len]);
    internet_checksum(&bytes) == 0
}

fn assert_drop(io: &mut SimIo, reason: DropReason, original: &[u8]) {
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(recycled.cause, RecycleCause::Forwarding(reason));
    assert_eq!(recycled.bytes, original);
}

fn refresh_ipv4_checksum(frame: &mut [u8]) {
    let header_len = usize::from(frame[14] & 0x0f) * 4;
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..14 + header_len]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
}

fn arp_reply(sender: Ipv4Address, target: Ipv4Address, sender_mac: MacAddress) -> Vec<u8> {
    let mut frame = vec![0_u8; 60];
    frame[0..6].copy_from_slice(&WAN_MAC.0);
    frame[6..12].copy_from_slice(&sender_mac.0);
    frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18..22].copy_from_slice(&[6, 4, 0, 2]);
    frame[22..28].copy_from_slice(&sender_mac.0);
    frame[28..32].copy_from_slice(&sender.octets());
    frame[32..38].copy_from_slice(&WAN_MAC.0);
    frame[38..42].copy_from_slice(&target.octets());
    frame
}

#[test]
fn nat_config_rejects_missing_or_ambiguous_authority_and_invalid_pool() {
    let (routes, interfaces, neighbors, bindings) = base();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let policy = Nat44UdpPolicy::default();
    assert_eq!(
        Nat44UdpConfig::new(&snapshot, LAN, LAN, PUBLIC, 40_000, 40_001, policy),
        Err(Nat44UdpConfigError::InterfacesEqual)
    );
    assert_eq!(
        Nat44UdpConfig::new(&snapshot, IfId(99), WAN, PUBLIC, 40_000, 40_001, policy),
        Err(Nat44UdpConfigError::InsideInterfaceMissing)
    );
    assert_eq!(
        Nat44UdpConfig::new(&snapshot, WAN, LAN, PUBLIC, 40_000, 40_001, policy),
        Err(Nat44UdpConfigError::PublicBindingWrongInterface)
    );
    assert_eq!(
        Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            Ipv4Address::from_octets([0; 4]),
            40_000,
            40_001,
            policy
        ),
        Err(Nat44UdpConfigError::PublicAddressNotHostUnicast)
    );
    assert_eq!(
        Nat44UdpConfig::new(&snapshot, LAN, WAN, PUBLIC, 0, 40_001, policy),
        Err(Nat44UdpConfigError::PortPoolIncludesZero)
    );
    assert_eq!(
        Nat44UdpConfig::new(&snapshot, LAN, WAN, PUBLIC, 40_001, 40_000, policy),
        Err(Nat44UdpConfigError::PortPoolReversed)
    );
}

#[test]
fn exact_bidirectional_wire_and_same_batch_visibility() {
    let (routes, interfaces, neighbors, bindings) = base();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_010);
    let mut mappings = [Nat44UdpMappingSlot::default(); 2];
    let mut peers = [Nat44UdpPeerSlot::default(); 4];
    let mut nat_indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = nat_indexes.runtime(config, &mut mappings, &mut peers);
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut rs, &mut ra);
    let outbound = udp_frame(
        HOST,
        REMOTE1,
        40_000,
        53,
        64,
        0xc000,
        &[1, 2, 3, 4, 5],
        &[0xaa, 0xbb],
        UdpChecksum::Valid,
    );
    let inbound = udp_frame(
        REMOTE1,
        PUBLIC,
        9_999,
        40_000,
        50,
        0xc000,
        &[9, 8, 7],
        &[],
        UdpChecksum::Valid,
    );
    let mut io = SimIo::new();
    io.inject(LAN, outbound);
    io.inject(WAN, inbound);
    let mut trace = VecTrace::default();
    let report = io
        .run_nat44_udp_once(
            2,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(0),
            &mut trace,
        )
        .unwrap();
    assert_eq!((report.tx_requested, report.dropped), (2, 0));

    let out = io.pop_tx().unwrap();
    assert_eq!(out.egress, WAN);
    assert_eq!(&out.bytes[0..6], &GATEWAY_MAC.0);
    assert_eq!(&out.bytes[6..12], &WAN_MAC.0);
    assert_eq!(&out.bytes[26..30], &PUBLIC.octets());
    assert_eq!(
        u16::from_be_bytes(out.bytes[34..36].try_into().unwrap()),
        40_000
    );
    assert_eq!(out.bytes[22], 63);
    assert_eq!(&out.bytes[20..22], &0xc000_u16.to_be_bytes());
    assert_eq!(ipv4_header_checksum(&out.bytes[14..34]), 0);
    assert!(udp_checksum_valid(&out.bytes));
    assert_eq!(&out.bytes[47..49], &[0xaa, 0xbb]);
    assert_eq!(&out.bytes[out.bytes.len() - 3..], &[0, 0, 0]);

    let inbound = io.pop_tx().unwrap();
    assert_eq!(inbound.egress, LAN);
    assert_eq!(&inbound.bytes[0..6], &HOST_MAC.0);
    assert_eq!(&inbound.bytes[6..12], &LAN_MAC.0);
    assert_eq!(&inbound.bytes[30..34], &HOST.octets());
    assert_eq!(
        u16::from_be_bytes(inbound.bytes[36..38].try_into().unwrap()),
        40_000
    );
    assert_eq!(inbound.bytes[22], 49);
    assert_eq!(&inbound.bytes[20..22], &0xc000_u16.to_be_bytes());
    assert_eq!(ipv4_header_checksum(&inbound.bytes[14..34]), 0);
    assert!(udp_checksum_valid(&inbound.bytes));
    assert_eq!(nat.counters().outbound_translated, 1);
    assert_eq!(nat.counters().inbound_translated, 1);
    assert!(matches!(
        trace.events(),
        [
            TraceEvent::Ipv4Validated { ingress: LAN, .. },
            TraceEvent::Routed { egress: WAN, .. },
            TraceEvent::Nat44Udp {
                ingress: LAN,
                disposition: Nat44UdpDisposition::OutboundTranslated { .. }
            },
            TraceEvent::TxRequested { egress: WAN },
            TraceEvent::Ipv4Validated { ingress: WAN, .. },
            TraceEvent::Routed { egress: LAN, .. },
            TraceEvent::Nat44Udp {
                ingress: WAN,
                disposition: Nat44UdpDisposition::InboundTranslated { .. }
            },
            TraceEvent::TxRequested { egress: LAN },
            TraceEvent::BatchCompleted {
                tx_accepted: 2,
                tx_rejected: 0
            }
        ]
    ));
}

#[test]
fn eim_reuses_public_tuple_and_adf_keys_only_remote_address() {
    let (routes, interfaces, neighbors, bindings) = base();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_010);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 2];
    let mut nat_indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = nat_indexes.runtime(config, &mut mappings, &mut peers);
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut rs, &mut ra);
    let mut io = SimIo::new();
    for (remote, port) in [(REMOTE1, 53), (REMOTE2, 4_444)] {
        io.inject(
            LAN,
            udp_frame(
                HOST,
                remote,
                40_000,
                port,
                64,
                0x4000,
                &[],
                &[],
                UdpChecksum::Zero,
            ),
        );
    }
    io.run_nat44_udp_once(
        2,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    for _ in 0..2 {
        let tx = io.pop_tx().unwrap();
        assert_eq!(
            u16::from_be_bytes(tx.bytes[34..36].try_into().unwrap()),
            40_000
        );
        assert_eq!(u16::from_be_bytes(tx.bytes[40..42].try_into().unwrap()), 0);
    }
    assert_eq!(nat.counters().mappings_created, 1);
    assert_eq!(nat.counters().mappings_reused, 1);
    assert_eq!(nat.counters().peers_created, 2);

    io.inject(
        WAN,
        udp_frame(
            REMOTE1,
            PUBLIC,
            65_000,
            40_000,
            64,
            0x4000,
            &[],
            &[],
            UdpChecksum::Zero,
        ),
    );
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
    assert_eq!(io.pop_tx().unwrap().egress, LAN);

    let denied = udp_frame(
        Ipv4Address::from_octets([198, 51, 100, 21]),
        PUBLIC,
        53,
        40_000,
        64,
        0x4000,
        &[],
        &[],
        UdpChecksum::Zero,
    );
    io.inject(WAN, denied.clone());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(3),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpFilterDenied, &denied);
}

#[test]
fn allocator_preserves_then_falls_back_without_overload_and_exhausts() {
    let (routes, interfaces, neighbors, bindings) = base();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_001);
    let mut mappings = [Nat44UdpMappingSlot::default(); 3];
    let mut peers = [Nat44UdpPeerSlot::default(); 3];
    let mut nat_indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = nat_indexes.runtime(config, &mut mappings, &mut peers);
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut rs, &mut ra);
    let mut io = SimIo::new();
    for host in [HOST, HOST2] {
        io.inject(
            LAN,
            udp_frame(
                host,
                REMOTE1,
                40_000,
                53,
                64,
                0x4000,
                &[],
                &[],
                UdpChecksum::Zero,
            ),
        );
    }
    io.run_nat44_udp_once(
        2,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    let first = u16::from_be_bytes(io.pop_tx().unwrap().bytes[34..36].try_into().unwrap());
    let second = u16::from_be_bytes(io.pop_tx().unwrap().bytes[34..36].try_into().unwrap());
    assert_eq!(first, 40_000);
    assert_eq!(second, 40_001);

    let third_host = Ipv4Address::from_octets([10, 0, 0, 12]);
    let packet = udp_frame(
        third_host,
        REMOTE1,
        50_000,
        53,
        64,
        0x4000,
        &[],
        &[],
        UdpChecksum::Zero,
    );
    io.inject(LAN, packet.clone());
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
    assert_drop(&mut io, DropReason::Nat44UdpPortExhausted, &packet);
}

#[test]
fn exact_idle_expiry_outbound_refresh_and_inbound_no_refresh() {
    let (routes, interfaces, neighbors, bindings) = base();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let policy = Nat44UdpPolicy::new(NAT44_UDP_MIN_IDLE_TTL_MS, 7).unwrap();
    let config = Nat44UdpConfig::new(&snapshot, LAN, WAN, PUBLIC, 40_000, 40_000, policy).unwrap();
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat_indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = nat_indexes.runtime(config, &mut mappings, &mut peers);
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut rs, &mut ra);
    let outbound = || {
        udp_frame(
            HOST,
            REMOTE1,
            40_000,
            53,
            64,
            0x4000,
            &[],
            &[],
            UdpChecksum::Zero,
        )
    };
    let inbound = || {
        udp_frame(
            REMOTE1,
            PUBLIC,
            53,
            40_000,
            64,
            0x4000,
            &[],
            &[],
            UdpChecksum::Zero,
        )
    };
    let mut io = SimIo::new();
    io.inject(LAN, outbound());
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
    io.pop_tx();
    io.inject(WAN, inbound());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(NAT44_UDP_MIN_IDLE_TTL_MS - 1),
        &mut NoTrace,
    )
    .unwrap();
    io.pop_tx();
    let expired = inbound();
    io.inject(WAN, expired.clone());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(NAT44_UDP_MIN_IDLE_TTL_MS),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpMappingMiss, &expired);

    io.inject(LAN, outbound());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(NAT44_UDP_MIN_IDLE_TTL_MS),
        &mut NoTrace,
    )
    .unwrap();
    io.pop_tx();
    io.inject(LAN, outbound());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(NAT44_UDP_MIN_IDLE_TTL_MS + 100),
        &mut NoTrace,
    )
    .unwrap();
    io.pop_tx();
    io.inject(WAN, inbound());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(2 * NAT44_UDP_MIN_IDLE_TTL_MS + 99),
        &mut NoTrace,
    )
    .unwrap();
    assert_eq!(io.pop_tx().unwrap().egress, LAN);
    let exact = inbound();
    io.inject(WAN, exact.clone());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(2 * NAT44_UDP_MIN_IDLE_TTL_MS + 100),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpMappingMiss, &exact);
}

#[test]
fn structural_and_policy_failures_are_byte_and_state_atomic() {
    let (routes, interfaces, neighbors, bindings) = base();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let base_config = config(&snapshot, 40_000, 40_000);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat_indexes = UdpTestIndexes::new(base_config, mappings.len(), peers.len());
    let mut nat = nat_indexes.runtime(base_config, &mut mappings, &mut peers);
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut rs, &mut ra);
    let cases = [
        (
            udp_frame(
                HOST,
                REMOTE1,
                40_000,
                53,
                64,
                0,
                &[],
                &[],
                UdpChecksum::Zero,
            ),
            DropReason::Nat44UdpNonAtomicIpv4Unsupported,
        ),
        (
            udp_frame(
                HOST,
                REMOTE1,
                40_000,
                53,
                64,
                0xc001,
                &[],
                &[],
                UdpChecksum::Zero,
            ),
            DropReason::Nat44UdpNonAtomicIpv4Unsupported,
        ),
        (
            udp_frame(
                HOST,
                REMOTE1,
                40_000,
                53,
                64,
                0xe000,
                &[],
                &[],
                UdpChecksum::Zero,
            ),
            DropReason::Nat44UdpNonAtomicIpv4Unsupported,
        ),
        (
            udp_frame(
                HOST,
                REMOTE1,
                0,
                53,
                64,
                0x4000,
                &[],
                &[],
                UdpChecksum::Zero,
            ),
            DropReason::Nat44UdpSourcePortZero,
        ),
        (
            udp_frame(
                HOST,
                PUBLIC,
                40_000,
                53,
                64,
                0x4000,
                &[],
                &[],
                UdpChecksum::Zero,
            ),
            DropReason::Nat44UdpHairpinUnsupported,
        ),
    ];
    let mut io = SimIo::new();
    for (packet, reason) in cases {
        io.inject(LAN, packet.clone());
        io.run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &base_config,
            Some(&mut nat),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
        assert_drop(&mut io, reason, &packet);
        assert_eq!(
            nat.mappings()
                .iter()
                .filter(|slot| slot.is_occupied())
                .count(),
            0
        );
    }
}

#[test]
fn checksum_zero_invalid_nonzero_and_odd_or_padded_udp_are_algebraic() {
    let (routes, interfaces, neighbors, bindings) = base();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_010);
    let mut mappings = [Nat44UdpMappingSlot::default(); 5];
    let mut peers = [Nat44UdpPeerSlot::default(); 5];
    let mut nat_indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = nat_indexes.runtime(config, &mut mappings, &mut peers);
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut rs, &mut ra);
    let mut io = SimIo::new();
    for (host, port, mode, payload, padding) in [
        (HOST, 40_000, UdpChecksum::Zero, &[1][..], &[9, 9][..]),
        (HOST2, 40_001, UdpChecksum::Valid, &[1, 2, 3][..], &[][..]),
        (
            Ipv4Address::from_octets([10, 0, 0, 12]),
            40_002,
            UdpChecksum::Raw(0x1234),
            &[1, 2, 3, 4][..],
            &[][..],
        ),
    ] {
        io.inject(
            LAN,
            udp_frame(host, REMOTE1, port, 53, 64, 0x4000, payload, padding, mode),
        );
    }
    let negative_zero_input = (1_u16..=u16::MAX)
        .find(|checksum| {
            let old = HOST.octets();
            let new = PUBLIC.octets();
            let updated = rfc1624_update(
                rfc1624_update(
                    rfc1624_update(
                        *checksum,
                        u16::from_be_bytes([old[0], old[1]]),
                        u16::from_be_bytes([new[0], new[1]]),
                    ),
                    u16::from_be_bytes([old[2], old[3]]),
                    u16::from_be_bytes([new[2], new[3]]),
                ),
                40_003,
                40_003,
            );
            updated == 0
        })
        .unwrap();
    io.inject(
        LAN,
        udp_frame(
            HOST,
            REMOTE2,
            40_003,
            53,
            64,
            0x4000,
            &[],
            &[],
            UdpChecksum::Raw(negative_zero_input),
        ),
    );
    io.inject(
        LAN,
        udp_frame(
            HOST2,
            REMOTE2,
            40_004,
            53,
            64,
            0x4000,
            &[],
            &[],
            UdpChecksum::Raw(0xffff),
        ),
    );
    io.run_nat44_udp_once(
        5,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    let zero = io.pop_tx().unwrap();
    assert_eq!(
        u16::from_be_bytes(zero.bytes[40..42].try_into().unwrap()),
        0
    );
    let valid = io.pop_tx().unwrap();
    assert!(udp_checksum_valid(&valid.bytes));
    let invalid = io.pop_tx().unwrap();
    assert!(!udp_checksum_valid(&invalid.bytes));
    assert_ne!(
        u16::from_be_bytes(invalid.bytes[40..42].try_into().unwrap()),
        0x1234
    );
    let negative_zero = io.pop_tx().unwrap();
    assert_eq!(
        u16::from_be_bytes(negative_zero.bytes[40..42].try_into().unwrap()),
        0xffff
    );
    let input_ffff = io.pop_tx().unwrap();
    assert_ne!(
        u16::from_be_bytes(input_ffff.bytes[40..42].try_into().unwrap()),
        0
    );
}

#[test]
fn absent_runtime_and_stale_snapshot_authority_fail_closed() {
    let (routes, interfaces, neighbors, bindings) = base();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_000);
    let packet = udp_frame(
        HOST,
        REMOTE1,
        40_000,
        53,
        64,
        0x4000,
        &[],
        &[],
        UdpChecksum::Zero,
    );
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut rs, &mut ra);
    let mut io = SimIo::new();
    io.inject(LAN, packet.clone());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        None,
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpRuntimeUnavailable, &packet);

    let mut changed_neighbors = neighbors;
    changed_neighbors[2].mac = MacAddress([2, 9, 9, 9, 9, 9]);
    let changed =
        ForwardingSnapshot::new(&routes, &interfaces, &changed_neighbors, &bindings).unwrap();
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat_indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = nat_indexes.runtime(config, &mut mappings, &mut peers);
    io.inject(LAN, packet.clone());
    io.run_nat44_udp_once(
        1,
        &changed,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpConfigMismatch, &packet);
}

#[test]
fn backend_reject_keeps_tx_request_mapping_and_filter_state() {
    let (routes, interfaces, neighbors, bindings) = base();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_000);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat_indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = nat_indexes.runtime(config, &mut mappings, &mut peers);
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut rs, &mut ra);
    let mut io = SimIo::new();
    io.set_received_accept_budget(0);
    io.inject(
        LAN,
        udp_frame(
            HOST,
            REMOTE1,
            40_000,
            53,
            64,
            0x4000,
            &[],
            &[],
            UdpChecksum::Zero,
        ),
    );
    let rejected = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_eq!(rejected.completion.tx_requested, 1);
    assert_eq!(rejected.completion.tx_rejected, 1);
    assert_eq!(io.pop_recycled().unwrap().cause, RecycleCause::TxRejected);
    assert_eq!(nat.counters().mappings_created, 1);

    io.set_received_accept_budget(1);
    io.inject(
        WAN,
        udp_frame(
            REMOTE1,
            PUBLIC,
            999,
            40_000,
            64,
            0x4000,
            &[],
            &[],
            UdpChecksum::Zero,
        ),
    );
    let inbound = io
        .run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(1),
            &mut NoTrace,
        )
        .unwrap();
    assert_eq!(inbound.tx_requested, 1);
    assert_eq!(io.pop_tx().unwrap().egress, LAN);
}

#[test]
fn malformed_udp_options_and_unsupported_transport_never_create_state() {
    let (routes, interfaces, neighbors, bindings) = base();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_010);
    let mut mappings = [Nat44UdpMappingSlot::default(); 2];
    let mut peers = [Nat44UdpPeerSlot::default(); 2];
    let mut nat_indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = nat_indexes.runtime(config, &mut mappings, &mut peers);
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut rs, &mut ra);
    let template = udp_frame(
        HOST,
        REMOTE1,
        40_000,
        53,
        64,
        0x4000,
        &[],
        &[],
        UdpChecksum::Zero,
    );
    let mut truncated = template.clone();
    truncated[16..18].copy_from_slice(&27_u16.to_be_bytes());
    refresh_ipv4_checksum(&mut truncated);
    let mut too_small = template.clone();
    too_small[38..40].copy_from_slice(&7_u16.to_be_bytes());
    let mut too_large = template.clone();
    too_large[38..40].copy_from_slice(&9_u16.to_be_bytes());
    let mut options = template.clone();
    options.splice(34..34, [1, 1, 1, 0]);
    options[14] = 0x46;
    let total = u16::from_be_bytes(options[16..18].try_into().unwrap()) + 4;
    options[16..18].copy_from_slice(&total.to_be_bytes());
    refresh_ipv4_checksum(&mut options);
    let mut tcp = template.clone();
    tcp[23] = 6;
    refresh_ipv4_checksum(&mut tcp);
    let cases = [
        (truncated, DropReason::Nat44UdpHeaderTruncated),
        (too_small, DropReason::Nat44UdpLengthTooSmall),
        (too_large, DropReason::Nat44UdpLengthExceedsIpv4Payload),
        (options, DropReason::Ipv4OptionsUnsupported),
        (tcp, DropReason::Nat44UdpUnsupportedTransport),
    ];
    let mut io = SimIo::new();
    for (packet, reason) in cases {
        io.inject(LAN, packet.clone());
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
        assert_eq!(nat.counters().mappings_created, 0);
    }
}

#[test]
fn wrong_ingress_unrelated_traffic_and_icmp_are_explicitly_non_nat() {
    let (routes, interfaces, neighbors, bindings) = base();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_000);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat_indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = nat_indexes.runtime(config, &mut mappings, &mut peers);
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut rs, &mut ra);
    let mut io = SimIo::new();
    let mut wrong = udp_frame(
        REMOTE1,
        PUBLIC,
        53,
        40_000,
        64,
        0x4000,
        &[],
        &[],
        UdpChecksum::Zero,
    );
    wrong[0..6].copy_from_slice(&DMZ_MAC.0);
    io.inject(DMZ, wrong.clone());
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
    assert_drop(&mut io, DropReason::Nat44UdpWrongIngress, &wrong);

    let unrelated = udp_frame(
        REMOTE1,
        REMOTE2,
        53,
        99,
        64,
        0x4000,
        &[],
        &[],
        UdpChecksum::Zero,
    );
    io.inject(WAN, unrelated);
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
    assert_eq!(io.pop_tx().unwrap().egress, WAN);
    assert_eq!(nat.counters().outbound_translated, 0);

    let mut icmp = udp_frame(
        REMOTE1,
        PUBLIC,
        8,
        0,
        64,
        0x4000,
        &[],
        &[],
        UdpChecksum::Zero,
    );
    icmp[23] = 1;
    refresh_ipv4_checksum(&mut icmp);
    io.inject(WAN, icmp.clone());
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
    assert_drop(&mut io, DropReason::Icmpv4ChecksumInvalid, &icmp);
    assert_eq!(nat.counters().outbound_translated, 0);
    assert_eq!(nat.counters().inbound_translated, 0);
}

#[test]
fn outside_to_inside_lpm_bypass_is_always_fail_closed_before_neighbor_work() {
    let (routes, interfaces, neighbors, bindings) = base();
    let snapshot =
        ForwardingSnapshot::new(&routes, &interfaces, &neighbors[2..], &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_000);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat_indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = nat_indexes.runtime(config, &mut mappings, &mut peers);
    let mut rs = [ResolutionStateSlot::EMPTY; 2];
    let mut ra = [ResolutionActionSlot::EMPTY; 2];
    let mut resolution = resolution(&mut rs, &mut ra);
    let mut io = SimIo::new();

    let empty_runtime = udp_frame(
        REMOTE1,
        HOST,
        53,
        40_000,
        64,
        0x4000,
        &[],
        &[],
        UdpChecksum::Zero,
    );
    io.inject(WAN, empty_runtime.clone());
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
    assert_drop(
        &mut io,
        DropReason::Nat44ExternalToInternalBypass,
        &empty_runtime,
    );
    assert!(nat.mappings().iter().all(|mapping| !mapping.is_occupied()));
    assert!(nat.peers().iter().all(|peer| !peer.is_occupied()));
    assert_eq!(nat.counters(), Default::default());
    assert_eq!(resolution.counters().queued, 0);

    io.inject(
        LAN,
        udp_frame(
            HOST,
            REMOTE1,
            40_000,
            53,
            64,
            0x4000,
            &[],
            &[],
            UdpChecksum::Zero,
        ),
    );
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
    io.pop_tx();
    let mapping_before = nat.mappings()[0];
    let peer_before = nat.peers()[0];
    let counters_before = nat.counters();
    let resolution_before = resolution.counters();

    let mut tcp = udp_frame(
        REMOTE1,
        HOST,
        53,
        40_000,
        64,
        0x4000,
        &[],
        &[],
        UdpChecksum::Zero,
    );
    tcp[23] = 6;
    refresh_ipv4_checksum(&mut tcp);
    let cases = [
        udp_frame(
            REMOTE1,
            HOST,
            53,
            40_000,
            64,
            0x4000,
            &[],
            &[],
            UdpChecksum::Zero,
        ),
        udp_frame(
            REMOTE2,
            HOST,
            53,
            40_000,
            64,
            0x4000,
            &[],
            &[],
            UdpChecksum::Zero,
        ),
        tcp,
    ];
    for packet in cases {
        io.inject(WAN, packet.clone());
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
        assert_drop(&mut io, DropReason::Nat44ExternalToInternalBypass, &packet);
        assert_eq!(nat.mappings()[0], mapping_before);
        assert_eq!(nat.peers()[0], peer_before);
        assert_eq!(nat.counters(), counters_before);
        assert_eq!(resolution.counters(), resolution_before);
    }

    let absent_runtime = udp_frame(
        REMOTE1,
        HOST,
        53,
        40_000,
        64,
        0x4000,
        &[],
        &[],
        UdpChecksum::Zero,
    );
    io.inject(WAN, absent_runtime.clone());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        None,
        MonotonicMillis(100),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(
        &mut io,
        DropReason::Nat44ExternalToInternalBypass,
        &absent_runtime,
    );
    assert_eq!(resolution.counters(), resolution_before);
}

#[test]
fn route_ttl_neighbor_and_reverse_authority_fail_before_nat_state() {
    let (routes, interfaces, neighbors, bindings) = base();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let base_config = config(&snapshot, 40_000, 40_000);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat_indexes = UdpTestIndexes::new(base_config, mappings.len(), peers.len());
    let mut nat = nat_indexes.runtime(base_config, &mut mappings, &mut peers);
    let mut rs = [ResolutionStateSlot::EMPTY; 1];
    let mut ra = [ResolutionActionSlot::EMPTY; 1];
    let mut cache = [DynamicNeighborSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        &mut rs,
        &mut ra,
        &mut cache,
    );
    let ttl = udp_frame(
        HOST,
        REMOTE1,
        40_000,
        53,
        1,
        0x4000,
        &[],
        &[],
        UdpChecksum::Zero,
    );
    let mut spoof = udp_frame(
        REMOTE2,
        REMOTE1,
        40_000,
        53,
        64,
        0x4000,
        &[],
        &[],
        UdpChecksum::Zero,
    );
    spoof[0..6].copy_from_slice(&LAN_MAC.0);
    let mut io = SimIo::new();
    for (packet, reason) in [
        (ttl, DropReason::Ipv4TtlExpired),
        (spoof, DropReason::Nat44UdpReverseAuthorityMismatch),
    ] {
        io.inject(LAN, packet.clone());
        io.run_nat44_udp_once(
            1,
            &snapshot,
            &mut resolution,
            &base_config,
            Some(&mut nat),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
        assert_drop(&mut io, reason, &packet);
        assert_eq!(nat.counters().mappings_created, 0);
    }

    let no_default = [routes[0]];
    let route_miss_snapshot =
        ForwardingSnapshot::new(&no_default, &interfaces, &neighbors[..2], &bindings).unwrap();
    let route_miss_config = config(&route_miss_snapshot, 40_000, 40_000);
    let mut miss_maps = [Nat44UdpMappingSlot::default(); 1];
    let mut miss_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut miss_nat_indexes =
        UdpTestIndexes::new(route_miss_config, miss_maps.len(), miss_peers.len());
    let mut miss_nat = miss_nat_indexes.runtime(route_miss_config, &mut miss_maps, &mut miss_peers);
    let packet = udp_frame(
        HOST,
        REMOTE1,
        40_000,
        53,
        64,
        0x4000,
        &[],
        &[],
        UdpChecksum::Zero,
    );
    io.inject(LAN, packet.clone());
    io.run_nat44_udp_once(
        1,
        &route_miss_snapshot,
        &mut resolution,
        &route_miss_config,
        Some(&mut miss_nat),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::RouteMiss, &packet);
    assert_eq!(miss_nat.counters().mappings_created, 0);

    let unresolved_snapshot =
        ForwardingSnapshot::new(&routes, &interfaces, &neighbors[..2], &bindings).unwrap();
    let unresolved_config = config(&unresolved_snapshot, 40_000, 40_000);
    let mut unresolved_maps = [Nat44UdpMappingSlot::default(); 1];
    let mut unresolved_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut unresolved_nat_indexes = UdpTestIndexes::new(
        unresolved_config,
        unresolved_maps.len(),
        unresolved_peers.len(),
    );
    let mut unresolved_nat = unresolved_nat_indexes.runtime(
        unresolved_config,
        &mut unresolved_maps,
        &mut unresolved_peers,
    );
    io.inject(LAN, packet.clone());
    io.run_nat44_udp_once(
        1,
        &unresolved_snapshot,
        &mut resolution,
        &unresolved_config,
        Some(&mut unresolved_nat),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::NeighborUnresolved, &packet);
    assert_eq!(unresolved_nat.counters().mappings_created, 0);
    assert_eq!(resolution.counters().queued, 1);

    io.inject(WAN, arp_reply(GATEWAY, PUBLIC, GATEWAY_MAC));
    io.run_nat44_udp_once(
        1,
        &unresolved_snapshot,
        &mut resolution,
        &unresolved_config,
        Some(&mut unresolved_nat),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    io.pop_recycled();
    io.inject(LAN, packet);
    io.run_nat44_udp_once(
        1,
        &unresolved_snapshot,
        &mut resolution,
        &unresolved_config,
        Some(&mut unresolved_nat),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_eq!(io.pop_tx().unwrap().egress, WAN);
    assert_eq!(unresolved_nat.counters().mappings_created, 1);
}

#[test]
fn later_forwarding_and_structural_failures_still_advance_nat_time() {
    let (routes, interfaces, neighbors, bindings) = base();
    let snapshot =
        ForwardingSnapshot::new(&routes, &interfaces, &neighbors[2..], &bindings).unwrap();
    let config = config(&snapshot, 40_000, 40_000);
    let mut mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut peers = [Nat44UdpPeerSlot::default(); 1];
    let mut nat_indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
    let mut nat = nat_indexes.runtime(config, &mut mappings, &mut peers);
    let mut rs = [ResolutionStateSlot::EMPTY; 2];
    let mut ra = [ResolutionActionSlot::EMPTY; 2];
    let mut resolution = resolution(&mut rs, &mut ra);
    let mut io = SimIo::new();
    let outbound = || {
        udp_frame(
            HOST,
            REMOTE1,
            40_000,
            53,
            64,
            0x4000,
            &[],
            &[],
            UdpChecksum::Zero,
        )
    };
    let inbound = || {
        udp_frame(
            REMOTE1,
            PUBLIC,
            53,
            40_000,
            64,
            0x4000,
            &[],
            &[],
            UdpChecksum::Zero,
        )
    };

    io.inject(LAN, outbound());
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
    io.pop_tx();

    let neighbor_failure = inbound();
    io.inject(WAN, neighbor_failure.clone());
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
    assert_drop(&mut io, DropReason::NeighborUnresolved, &neighbor_failure);
    assert_eq!(nat.mappings()[0].last_outbound_ms(), 0);
    assert_eq!(nat.counters().inbound_translated, 0);
    let resolution_after_failure = resolution.counters();

    let older = inbound();
    io.inject(WAN, older.clone());
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
    assert_drop(&mut io, DropReason::Nat44UdpClockRegression, &older);
    assert_eq!(resolution.counters(), resolution_after_failure);

    let equal = inbound();
    io.inject(WAN, equal.clone());
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
    assert_drop(&mut io, DropReason::NeighborUnresolved, &equal);

    let malformed = udp_frame(
        HOST,
        REMOTE1,
        40_000,
        53,
        64,
        0,
        &[],
        &[],
        UdpChecksum::Zero,
    );
    io.inject(LAN, malformed.clone());
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
        DropReason::Nat44UdpNonAtomicIpv4Unsupported,
        &malformed,
    );

    let older = outbound();
    io.inject(LAN, older.clone());
    io.run_nat44_udp_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(199),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpClockRegression, &older);

    io.inject(LAN, outbound());
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
    assert_eq!(io.pop_tx().unwrap().egress, WAN);
    assert_eq!(nat.mappings()[0].last_outbound_ms(), 200);
}
