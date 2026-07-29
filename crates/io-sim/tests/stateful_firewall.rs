use ruster_core::{
    internet_checksum, ipv4_header_checksum, DropReason, FirewallAction, FirewallAuditBuffer,
    FirewallAuditRecord, FirewallConfig, FirewallConnectionClass, FirewallDisposition,
    FirewallInterface, FirewallIpv4Prefix, FirewallPolicy, FirewallPolicySource, FirewallPortRange,
    FirewallProtocol, FirewallRule, FirewallRuleId, FirewallRuntime, FirewallStateSlot,
    FirewallTcpPhase, FirewallVerdict, ForwardingSnapshot, Icmpv4ErrorActionSlot,
    Icmpv4ErrorPolicy, Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address,
    LocalIpv4Binding, MacAddress, MonotonicMillis, Nat44Icmpv4ErrorPolicy, Nat44TcpConfig,
    Nat44TcpMappingSlot, Nat44TcpPolicy, Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44UdpConfig,
    Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpRuntime, Neighbor, NoTrace,
    ResolutionActionSlot, ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route,
};
use ruster_io_sim::{RecycleCause, SimIo};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const HOST_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 10]);
const GW_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 20]);
const HOST: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
const LAN_LOCAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 1]);
const WAN_LOCAL: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const OTHER_REMOTE: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 30]);
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
                address: WAN_LOCAL,
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

fn any_prefix() -> FirewallIpv4Prefix {
    FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap()
}

fn prefix(address: Ipv4Address, prefix_len: u8) -> FirewallIpv4Prefix {
    FirewallIpv4Prefix::new(address, prefix_len).unwrap()
}

fn ports(first: u16, last: u16) -> FirewallPortRange {
    FirewallPortRange::new(first, last).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn rule(
    id: u32,
    ingress: FirewallInterface,
    egress: FirewallInterface,
    source: FirewallIpv4Prefix,
    destination: FirewallIpv4Prefix,
    protocol: FirewallProtocol,
    source_ports: FirewallPortRange,
    destination_ports: FirewallPortRange,
    action: FirewallAction,
) -> FirewallRule {
    FirewallRule::new(
        FirewallRuleId(id),
        ingress,
        egress,
        source,
        destination,
        protocol,
        source_ports,
        destination_ports,
        action,
    )
}

fn allow(protocol: FirewallProtocol) -> FirewallRule {
    rule(
        if protocol == FirewallProtocol::Udp {
            10
        } else {
            20
        },
        FirewallInterface::Interface(LAN),
        FirewallInterface::Interface(WAN),
        prefix(Ipv4Address::from_octets([10, 0, 0, 0]), 24),
        any_prefix(),
        protocol,
        ports(0, u16::MAX),
        ports(1, u16::MAX),
        FirewallAction::AllowStateful,
    )
}

fn udp_frame(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    flags_fragment: u16,
    checksum: bool,
) -> Vec<u8> {
    let payload = [1_u8, 2, 3];
    let udp_len = 8 + payload.len();
    let mut frame = vec![0_u8; 14 + 20 + udp_len + 3];
    frame[0..6].copy_from_slice(&WAN_MAC.0);
    frame[6..12].copy_from_slice(&HOST_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&(u16::try_from(20 + udp_len).unwrap()).to_be_bytes());
    frame[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    frame[38..40].copy_from_slice(&(u16::try_from(udp_len).unwrap()).to_be_bytes());
    frame[42..45].copy_from_slice(&payload);
    if checksum {
        let checksum = transport_checksum(source, destination, 17, &frame[34..34 + udp_len]);
        frame[40..42].copy_from_slice(&checksum.to_be_bytes());
    }
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn tcp_frame(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    flags: u8,
    flags_fragment: u16,
) -> Vec<u8> {
    let mut frame = vec![0_u8; 14 + 40 + 3];
    frame[0..6].copy_from_slice(&WAN_MAC.0);
    frame[6..12].copy_from_slice(&HOST_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&40_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_fragment.to_be_bytes());
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    frame[38..42].copy_from_slice(&1_u32.to_be_bytes());
    frame[42..46].copy_from_slice(&2_u32.to_be_bytes());
    frame[46] = 5 << 4;
    frame[47] = flags;
    frame[48..50].copy_from_slice(&4096_u16.to_be_bytes());
    let checksum = transport_checksum(source, destination, 6, &frame[34..54]);
    frame[50..52].copy_from_slice(&checksum.to_be_bytes());
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn transport_checksum(
    source: Ipv4Address,
    destination: Ipv4Address,
    protocol: u8,
    segment: &[u8],
) -> u16 {
    let mut bytes = Vec::with_capacity(12 + segment.len());
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&destination.octets());
    bytes.extend_from_slice(&[0, protocol]);
    bytes.extend_from_slice(&(u16::try_from(segment.len()).unwrap()).to_be_bytes());
    bytes.extend_from_slice(segment);
    let checksum = internet_checksum(&bytes);
    if protocol == 17 && checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

fn assert_drop(io: &mut SimIo, reason: DropReason, original: &[u8]) {
    let dropped = io.pop_recycled().unwrap();
    assert_eq!(dropped.cause, RecycleCause::Forwarding(reason));
    assert_eq!(dropped.bytes, original);
}

fn rewrite_ipv4_header(frame: &mut [u8]) {
    let header_len = usize::from(frame[14] & 0x0f) * 4;
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..14 + header_len]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
}

fn set_ttl(frame: &mut [u8], ttl: u8) {
    frame[22] = ttl;
    rewrite_ipv4_header(frame);
}

fn set_protocol(frame: &mut [u8], protocol: u8) {
    frame[23] = protocol;
    rewrite_ipv4_header(frame);
}

fn frag_needed(quote: &[u8]) -> Vec<u8> {
    let total_len = 20 + 8 + quote.len();
    let mut frame = vec![0_u8; 14 + total_len];
    frame[0..6].copy_from_slice(&WAN_MAC.0);
    frame[6..12].copy_from_slice(&GW_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&(u16::try_from(total_len).unwrap()).to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&REMOTE.octets());
    frame[30..34].copy_from_slice(&WAN_LOCAL.octets());
    frame[34] = 3;
    frame[35] = 4;
    frame[38..42].copy_from_slice(&1500_u32.to_be_bytes());
    frame[42..].copy_from_slice(quote);
    let icmp_checksum = internet_checksum(&frame[34..]);
    frame[36..38].copy_from_slice(&icmp_checksum.to_be_bytes());
    let ipv4_checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ipv4_checksum.to_be_bytes());
    frame
}

#[test]
fn ordered_rules_cidr_ports_default_deny_and_runtime_authority_are_exact() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let rules = [
        rule(
            1,
            FirewallInterface::Interface(LAN),
            FirewallInterface::Interface(WAN),
            prefix(Ipv4Address::from_octets([10, 0, 0, 0]), 24),
            prefix(Ipv4Address::from_octets([198, 51, 100, 0]), 24),
            FirewallProtocol::Udp,
            ports(12_345, 12_345),
            ports(53, 53),
            FirewallAction::Deny,
        ),
        allow(FirewallProtocol::Udp),
    ];
    let config = FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
    let denied = udp_frame(HOST, REMOTE, 12_345, 53, 0, false);
    let allowed = udp_frame(HOST, REMOTE, 12_346, 53, 0x4000, false);
    let mut slots = [FirewallStateSlot::default(); 1];
    let mut firewall = FirewallRuntime::new(config, &mut slots);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(LAN, denied.clone());
    io.inject(LAN, allowed);
    let report = io
        .run_firewall_once(
            2,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut firewall),
            MonotonicMillis(0),
            &mut NoTrace,
        )
        .unwrap();
    assert_eq!((report.tx_requested, report.dropped), (1, 1));
    assert_drop(&mut io, DropReason::FirewallRuleDenied, &denied);
    assert_eq!(firewall.counters().denied_by_rule, 1);
    assert_eq!(firewall.counters().allowed_new, 1);

    let empty: [FirewallRule; 0] = [];
    let deny_config = FirewallConfig::new(&snapshot, &empty, FirewallPolicy::default(), 2).unwrap();
    let packet = udp_frame(HOST, OTHER_REMOTE, 12_347, 53, 0, false);
    io.inject(LAN, packet.clone());
    io.run_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &deny_config,
        None,
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallRuntimeUnavailable, &packet);
}

#[test]
fn firewall_runtime_config_and_snapshot_mismatches_fail_closed() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let rules = [allow(FirewallProtocol::Udp)];
    let copied_rules = rules;
    let config = FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
    let mismatched =
        FirewallConfig::new(&snapshot, &copied_rules, FirewallPolicy::default(), 2).unwrap();
    let mut slots = [FirewallStateSlot::default(); 1];
    let mut firewall = FirewallRuntime::new(config, &mut slots);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    let packet = udp_frame(HOST, REMOTE, 12_345, 53, 0, false);
    io.inject(LAN, packet.clone());
    io.run_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &mismatched,
        Some(&mut firewall),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallConfigMismatch, &packet);

    let changed_neighbors = [
        neighbors[0],
        Neighbor {
            interface: WAN,
            target: GW,
            mac: MacAddress([2, 0, 0, 0, 0, 99]),
        },
    ];
    let changed =
        ForwardingSnapshot::new(&routes, &interfaces, &changed_neighbors, &bindings).unwrap();
    io.inject(LAN, packet.clone());
    io.run_firewall_once(
        1,
        &changed,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallConfigMismatch, &packet);
    assert!(firewall.states().iter().all(|slot| !slot.is_occupied()));
    assert_eq!(firewall.counters().config_mismatches, 2);
}

#[test]
fn udp_pseudo_session_exact_reverse_checksum_df_and_padding_are_enforced() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let rules = [allow(FirewallProtocol::Udp)];
    let config = FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
    let mut slots = [FirewallStateSlot::default(); 2];
    let mut firewall = FirewallRuntime::new(config, &mut slots);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();

    let outbound = udp_frame(HOST, REMOTE, 12_345, 53, 0, true);
    let reverse = udp_frame(REMOTE, HOST, 53, 12_345, 0x4000, true);
    io.inject(LAN, outbound);
    io.inject(WAN, reverse.clone());
    io.run_firewall_once(
        2,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(10),
        &mut NoTrace,
    )
    .unwrap();
    assert_eq!(io.pop_tx().unwrap().egress, WAN);
    let translated_reverse = io.pop_tx().unwrap();
    assert_eq!(translated_reverse.egress, LAN);
    assert_eq!(&translated_reverse.bytes[45..], &[0, 0, 0]);
    assert_eq!(firewall.counters().allowed_established, 1);

    let wrong = udp_frame(OTHER_REMOTE, HOST, 53, 12_345, 0, false);
    io.inject(WAN, wrong.clone());
    io.run_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(11),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallDefaultDenied, &wrong);

    let wrong_interface = udp_frame(REMOTE, HOST, 53, 12_345, 0, false);
    io.inject(LAN, wrong_interface.clone());
    io.run_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(11),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallDefaultDenied, &wrong_interface);

    let mut bad_checksum = reverse;
    bad_checksum[42] ^= 1;
    io.inject(WAN, bad_checksum.clone());
    io.run_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(11),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(
        &mut io,
        DropReason::FirewallUdpChecksumInvalid,
        &bad_checksum,
    );

    let fragment = udp_frame(HOST, REMOTE, 12_346, 53, 0x2000, false);
    io.inject(LAN, fragment.clone());
    io.run_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(11),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallFragmentUnsupported, &fragment);
}

#[test]
fn tcp_initial_syn_same_batch_reverse_phase_fin_and_rst_refresh_are_exact() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let rules = [allow(FirewallProtocol::Tcp)];
    let config = FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
    let mut slots = [FirewallStateSlot::default(); 1];
    let mut firewall = FirewallRuntime::new(config, &mut slots);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();

    let syn = tcp_frame(HOST, REMOTE, 12_345, 443, 0x02, 0x4000);
    let simultaneous = tcp_frame(REMOTE, HOST, 443, 12_345, 0x02, 0);
    io.inject(LAN, syn);
    io.inject(WAN, simultaneous);
    io.run_firewall_once(
        2,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_eq!(io.pop_tx().unwrap().egress, WAN);
    assert_eq!(io.pop_tx().unwrap().egress, LAN);

    let syn_ack = tcp_frame(REMOTE, HOST, 443, 12_345, 0x12, 0x4000);
    let ack = tcp_frame(HOST, REMOTE, 12_345, 443, 0x10, 0x4000);
    io.inject(WAN, syn_ack);
    io.inject(LAN, ack);
    io.run_firewall_once(
        2,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(10),
        &mut NoTrace,
    )
    .unwrap();
    io.pop_tx().unwrap();
    io.pop_tx().unwrap();
    assert_eq!(firewall.states()[0].tcp_phase(), FirewallTcpPhase::Active);

    let fin = tcp_frame(HOST, REMOTE, 12_345, 443, 0x11, 0);
    io.inject(LAN, fin);
    io.run_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(20),
        &mut NoTrace,
    )
    .unwrap();
    io.pop_tx().unwrap();
    assert_eq!(firewall.states()[0].last_activity_ms(), 20);
    let rst = tcp_frame(HOST, REMOTE, 12_345, 443, 0x04, 0);
    io.inject(LAN, rst);
    io.run_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(30),
        &mut NoTrace,
    )
    .unwrap();
    io.pop_tx().unwrap();
    assert_eq!(firewall.states()[0].last_activity_ms(), 20);

    let invalid_new = tcp_frame(HOST, OTHER_REMOTE, 12_346, 443, 0x10, 0);
    io.inject(LAN, invalid_new.clone());
    io.run_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(30),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(
        &mut io,
        DropReason::FirewallTcpInvalidInitialFlags,
        &invalid_new,
    );
}

#[test]
fn firewall_transport_options_ports_checksums_and_ttl_fail_closed_before_state() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let rules = [allow(FirewallProtocol::Udp), allow(FirewallProtocol::Tcp)];
    let config = FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
    let mut slots = [FirewallStateSlot::default(); 2];
    let mut firewall = FirewallRuntime::new(config, &mut slots);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();

    let source_zero = udp_frame(HOST, REMOTE, 0, 53, 0, false);
    io.inject(LAN, source_zero);
    io.run_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_eq!(io.pop_tx().unwrap().egress, WAN);
    assert_eq!(firewall.states()[0].initiator_port(), 0);

    let destination_zero = udp_frame(HOST, REMOTE, 12_345, 0, 0, false);
    io.inject(LAN, destination_zero.clone());
    io.run_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(
        &mut io,
        DropReason::FirewallUdpDestinationPortZero,
        &destination_zero,
    );

    let mut bad_tcp = tcp_frame(HOST, REMOTE, 12_345, 443, 0x02, 0);
    bad_tcp[50] ^= 1;
    io.inject(LAN, bad_tcp.clone());
    io.run_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallTcpChecksumInvalid, &bad_tcp);

    let zero_tcp_port = tcp_frame(HOST, REMOTE, 0, 443, 0x02, 0);
    io.inject(LAN, zero_tcp_port.clone());
    io.run_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallTcpPortZero, &zero_tcp_port);

    let mut options = udp_frame(HOST, REMOTE, 12_346, 53, 0, false);
    options.splice(34..34, [1, 1, 0, 0]);
    options[14] = 0x46;
    options[16..18].copy_from_slice(&35_u16.to_be_bytes());
    options[24..26].fill(0);
    let checksum = ipv4_header_checksum(&options[14..38]);
    options[24..26].copy_from_slice(&checksum.to_be_bytes());
    io.inject(LAN, options.clone());
    io.run_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(
        &mut io,
        DropReason::FirewallIpv4OptionsUnsupported,
        &options,
    );

    let mut ttl = udp_frame(HOST, OTHER_REMOTE, 12_347, 53, 0, false);
    ttl[22] = 1;
    ttl[24..26].fill(0);
    let checksum = ipv4_header_checksum(&ttl[14..34]);
    ttl[24..26].copy_from_slice(&checksum.to_be_bytes());
    let before = firewall.states().to_vec();
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    io.inject(LAN, ttl.clone());
    io.run_firewall_with_icmpv4_errors_once(
        1,
        &snapshot,
        &mut resolution,
        &mut errors,
        &config,
        Some(&mut firewall),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Ipv4TtlExpired, &ttl);
    assert_eq!(firewall.states(), before);
    assert_eq!(errors.pending_actions(), 1);
}

#[test]
fn deny_is_silent_and_precedes_ttl_neighbor_and_resolution_mutation() {
    let (routes, interfaces, _neighbors, bindings) = topology();
    let no_neighbors = [];
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &no_neighbors, &bindings).unwrap();
    let rules = [rule(
        1,
        FirewallInterface::Any,
        FirewallInterface::Any,
        any_prefix(),
        any_prefix(),
        FirewallProtocol::Udp,
        ports(0, u16::MAX),
        ports(0, u16::MAX),
        FirewallAction::Deny,
    )];
    let config = FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
    let mut slots = [FirewallStateSlot::default(); 1];
    let mut firewall = FirewallRuntime::new(config, &mut slots);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut packet = udp_frame(HOST, REMOTE, 12_345, 53, 0, false);
    packet[22] = 1;
    packet[24..26].fill(0);
    let checksum = ipv4_header_checksum(&packet[14..34]);
    packet[24..26].copy_from_slice(&checksum.to_be_bytes());
    let mut io = SimIo::new();
    io.inject(LAN, packet.clone());
    io.run_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut firewall),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallRuleDenied, &packet);
    assert_eq!(resolution.pending_actions(), 0);
    assert_eq!(resolution.pending_states(), 0);
    assert!(firewall.states().iter().all(|slot| !slot.is_occupied()));
}

#[test]
fn legacy_forwarding_is_unchanged_when_firewall_api_is_not_selected() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let frame = udp_frame(HOST, REMOTE, 12_345, 0, 0x2000, false);
    let mut io = SimIo::new();
    io.inject(LAN, frame);
    let report = io.run_once(1, &snapshot, &mut NoTrace).unwrap();
    assert_eq!((report.tx_requested, report.dropped), (1, 0));
    assert_eq!(io.pop_tx().unwrap().egress, WAN);
}

#[test]
fn nat_uses_canonical_pre_and_post_translation_tuples_and_commits_atomically() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let udp_policy =
        Nat44UdpPolicy::default().with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly);
    let tcp_policy =
        Nat44TcpPolicy::default().with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly);
    let udp_config =
        Nat44UdpConfig::new(&snapshot, LAN, WAN, WAN_LOCAL, 40_000, 40_000, udp_policy).unwrap();
    let tcp_config =
        Nat44TcpConfig::new(&snapshot, LAN, WAN, WAN_LOCAL, 40_000, 40_000, tcp_policy).unwrap();
    let rules = [allow(FirewallProtocol::Udp), allow(FirewallProtocol::Tcp)];
    let firewall_config =
        FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
    let mut firewall_slots = [FirewallStateSlot::default(); 2];
    let mut firewall = FirewallRuntime::new(firewall_config, &mut firewall_slots);
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 2];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 2];
    let mut udp = Nat44UdpRuntime::new(udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 2];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 2];
    let mut tcp = Nat44TcpRuntime::new(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();

    let outbound_udp = udp_frame(HOST, REMOTE, 12_345, 53, 0x4000, false);
    io.inject(LAN, outbound_udp);
    io.inject(LAN, tcp_frame(HOST, REMOTE, 12_345, 443, 0x02, 0x4000));
    io.run_nat44_udp_and_tcp_with_firewall_once(
        2,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        &firewall_config,
        Some(&mut firewall),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    let udp_out = io.pop_tx().unwrap();
    let tcp_out = io.pop_tx().unwrap();
    assert_eq!(&udp_out.bytes[26..30], &WAN_LOCAL.octets());
    assert_eq!(&tcp_out.bytes[26..30], &WAN_LOCAL.octets());
    assert_eq!(firewall.states()[0].initiator_address(), HOST);
    assert_eq!(firewall.states()[0].responder_address(), REMOTE);
    assert_eq!(firewall.states()[0].initiator_port(), 12_345);
    assert_eq!(firewall.states()[1].protocol(), FirewallProtocol::Tcp);

    io.inject(WAN, udp_frame(REMOTE, WAN_LOCAL, 53, 40_000, 0x4000, false));
    io.inject(WAN, tcp_frame(REMOTE, WAN_LOCAL, 443, 40_000, 0x12, 0x4000));
    io.run_nat44_udp_and_tcp_with_firewall_once(
        2,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        &firewall_config,
        Some(&mut firewall),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    let udp_in = io.pop_tx().unwrap();
    let tcp_in = io.pop_tx().unwrap();
    assert_eq!(udp_in.egress, LAN);
    assert_eq!(tcp_in.egress, LAN);
    assert_eq!(&udp_in.bytes[30..34], &HOST.octets());
    assert_eq!(&tcp_in.bytes[30..34], &HOST.octets());

    let before_firewall = firewall.states().to_vec();
    let before_udp_counters = udp.counters();
    let before_udp_mappings = udp.mappings().to_vec();
    let before_udp_peers = udp.peers().to_vec();
    let before_tcp_counters = tcp.counters();
    let before_tcp_mappings = tcp.mappings().to_vec();
    let before_tcp_sessions = tcp.sessions().to_vec();
    let related = frag_needed(&udp_out.bytes[14..42]);
    io.inject(WAN, related.clone());
    io.run_nat44_udp_and_tcp_with_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        &firewall_config,
        Some(&mut firewall),
        MonotonicMillis(100),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(
        &mut io,
        DropReason::FirewallRelatedIcmpv4Unsupported,
        &related,
    );
    assert_eq!(firewall.states(), before_firewall);
    assert_eq!(udp.counters(), before_udp_counters);
    assert_eq!(udp.mappings(), before_udp_mappings);
    assert_eq!(udp.peers(), before_udp_peers);
    assert_eq!(tcp.counters(), before_tcp_counters);
    assert_eq!(tcp.mappings(), before_tcp_mappings);
    assert_eq!(tcp.sessions(), before_tcp_sessions);

    io.set_received_accept_budget(0);
    let existing = udp_frame(HOST, REMOTE, 12_345, 53, 0x4000, false);
    io.inject(LAN, existing);
    io.run_nat44_udp_and_tcp_with_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        &firewall_config,
        Some(&mut firewall),
        MonotonicMillis(3),
        &mut NoTrace,
    )
    .unwrap();
    assert_eq!(firewall.states()[0].last_activity_ms(), 3);
    assert_eq!(udp.mappings()[0].last_outbound_ms(), 3);
    assert_eq!(io.pop_recycled().unwrap().cause, RecycleCause::TxRejected);
}

#[test]
fn nat_and_firewall_capacity_failures_leave_the_other_state_uncommitted() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let udp_config = Nat44UdpConfig::new(
        &snapshot,
        LAN,
        WAN,
        WAN_LOCAL,
        40_000,
        40_001,
        Nat44UdpPolicy::default(),
    )
    .unwrap();
    let tcp_config = Nat44TcpConfig::new(
        &snapshot,
        LAN,
        WAN,
        WAN_LOCAL,
        40_000,
        40_001,
        Nat44TcpPolicy::default(),
    )
    .unwrap();
    let rules = [allow(FirewallProtocol::Udp), allow(FirewallProtocol::Tcp)];
    let firewall_config =
        FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
    let mut no_firewall_slots = [];
    let mut firewall = FirewallRuntime::new(firewall_config, &mut no_firewall_slots);
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
    let packet = udp_frame(HOST, REMOTE, 12_345, 53, 0x4000, false);
    io.inject(LAN, packet.clone());
    io.run_nat44_udp_and_tcp_with_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        &firewall_config,
        Some(&mut firewall),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallStateTableFull, &packet);
    assert!(udp.mappings().iter().all(|slot| !slot.is_occupied()));

    let mut firewall_slots = [FirewallStateSlot::default(); 1];
    let mut firewall = FirewallRuntime::new(firewall_config, &mut firewall_slots);
    let mut no_udp_mappings = [];
    let mut no_udp_peers = [];
    let mut udp = Nat44UdpRuntime::new(udp_config, &mut no_udp_mappings, &mut no_udp_peers);
    let packet = udp_frame(HOST, REMOTE, 12_345, 53, 0x4000, false);
    io.inject(LAN, packet.clone());
    io.run_nat44_udp_and_tcp_with_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        &firewall_config,
        Some(&mut firewall),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpMappingTableFull, &packet);
    assert!(firewall.states().iter().all(|slot| !slot.is_occupied()));
}

#[test]
fn nat_inbound_mapping_without_exact_firewall_reverse_state_is_denied() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let udp_config = Nat44UdpConfig::new(
        &snapshot,
        LAN,
        WAN,
        WAN_LOCAL,
        40_000,
        40_000,
        Nat44UdpPolicy::default(),
    )
    .unwrap();
    let tcp_config = Nat44TcpConfig::new(
        &snapshot,
        LAN,
        WAN,
        WAN_LOCAL,
        40_000,
        40_000,
        Nat44TcpPolicy::default(),
    )
    .unwrap();
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
    let outbound = udp_frame(HOST, REMOTE, 12_345, 53, 0x4000, false);
    io.inject(LAN, outbound);
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
    io.pop_tx().unwrap();
    let outbound_tcp = tcp_frame(HOST, REMOTE, 12_346, 443, 0x02, 0x4000);
    io.inject(LAN, outbound_tcp);
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
    io.pop_tx().unwrap();
    let before_nat = udp.counters();

    let rules = [allow(FirewallProtocol::Udp)];
    let firewall_config =
        FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
    let mut firewall_slots = [FirewallStateSlot::default(); 1];
    let mut firewall = FirewallRuntime::new(firewall_config, &mut firewall_slots);
    let mut inbound = udp_frame(REMOTE, WAN_LOCAL, 53, 40_000, 0x4000, false);
    set_ttl(&mut inbound, 1);
    io.inject(WAN, inbound.clone());
    io.run_nat44_udp_and_tcp_with_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        &firewall_config,
        Some(&mut firewall),
        MonotonicMillis(100),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallDefaultDenied, &inbound);
    assert_eq!(udp.counters(), before_nat);
    assert!(firewall.states().iter().all(|slot| !slot.is_occupied()));
    assert_eq!(resolution.pending_actions(), 0);

    let mut inbound_tcp = tcp_frame(REMOTE, WAN_LOCAL, 443, 40_000, 0x12, 0x4000);
    set_ttl(&mut inbound_tcp, 1);
    io.inject(WAN, inbound_tcp.clone());
    io.run_nat44_udp_and_tcp_with_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        &firewall_config,
        Some(&mut firewall),
        MonotonicMillis(100),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallDefaultDenied, &inbound_tcp);
    assert!(firewall.states().iter().all(|slot| !slot.is_occupied()));

    let old_time = udp_frame(HOST, REMOTE, 12_345, 53, 0x4000, false);
    io.inject(LAN, old_time.clone());
    io.run_nat44_udp_and_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44UdpClockRegression, &old_time);
}

#[test]
fn typed_audit_preserves_first_match_rule_default_and_established_identity() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let rules = [
        rule(
            1,
            FirewallInterface::Interface(LAN),
            FirewallInterface::Interface(WAN),
            prefix(HOST, 32),
            any_prefix(),
            FirewallProtocol::Udp,
            ports(12_345, 12_345),
            ports(53, 53),
            FirewallAction::Deny,
        ),
        rule(
            2,
            FirewallInterface::Interface(LAN),
            FirewallInterface::Interface(WAN),
            prefix(HOST, 32),
            any_prefix(),
            FirewallProtocol::Udp,
            ports(12_346, 12_346),
            ports(53, 53),
            FirewallAction::AllowStateful,
        ),
    ];
    let config = FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
    let mut firewall_slots = [FirewallStateSlot::default(); 1];
    let mut firewall = FirewallRuntime::new(config, &mut firewall_slots);
    let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
    let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut resolution_states, &mut resolution_actions);
    let mut audit_storage = [FirewallAuditRecord::default(); 4];
    let mut audit = FirewallAuditBuffer::new(&mut audit_storage);
    let mut io = SimIo::new();
    io.set_received_accept_budget(0);
    io.inject(LAN, udp_frame(HOST, REMOTE, 12_345, 53, 0, false));
    io.inject(LAN, udp_frame(HOST, REMOTE, 12_346, 53, 0, false));
    io.inject(WAN, udp_frame(REMOTE, HOST, 53, 12_346, 0, false));
    io.inject(LAN, udp_frame(HOST, REMOTE, 12_347, 53, 0, false));
    let report = io
        .run_firewall_audited_once(
            4,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut firewall),
            &mut audit,
            MonotonicMillis(10),
            &mut NoTrace,
        )
        .unwrap();
    assert_eq!(report.dropped, 2);
    assert_eq!(report.completion.tx_rejected, 2);
    assert_eq!(audit.dropped_records(), 0);
    assert_eq!(
        audit
            .records()
            .iter()
            .map(|record| record.disposition)
            .collect::<Vec<_>>(),
        vec![
            FirewallDisposition {
                verdict: FirewallVerdict::Drop,
                class: FirewallConnectionClass::New,
                source: FirewallPolicySource::Rule(FirewallRuleId(1)),
            },
            FirewallDisposition {
                verdict: FirewallVerdict::Allow,
                class: FirewallConnectionClass::New,
                source: FirewallPolicySource::Rule(FirewallRuleId(2)),
            },
            FirewallDisposition {
                verdict: FirewallVerdict::Allow,
                class: FirewallConnectionClass::Established,
                source: FirewallPolicySource::Rule(FirewallRuleId(2)),
            },
            FirewallDisposition {
                verdict: FirewallVerdict::Drop,
                class: FirewallConnectionClass::New,
                source: FirewallPolicySource::Default,
            },
        ]
    );
    assert!(firewall.states()[0].is_occupied());
    assert_eq!(firewall.states()[0].origin_rule_id(), FirewallRuleId(2));
    assert_eq!(firewall.counters().rule_evaluations, 5);
}

#[test]
fn future_denies_make_plain_udp_and_tcp_old_time_fail_closed_without_state_changes() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let rules = [
        rule(
            1,
            FirewallInterface::Any,
            FirewallInterface::Any,
            any_prefix(),
            any_prefix(),
            FirewallProtocol::Udp,
            ports(0, u16::MAX),
            ports(0, u16::MAX),
            FirewallAction::Deny,
        ),
        rule(
            2,
            FirewallInterface::Any,
            FirewallInterface::Any,
            any_prefix(),
            any_prefix(),
            FirewallProtocol::Tcp,
            ports(0, u16::MAX),
            ports(0, u16::MAX),
            FirewallAction::Deny,
        ),
    ];
    let config = FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
    let mut firewall_slots = [FirewallStateSlot::default(); 2];
    let mut firewall = FirewallRuntime::new(config, &mut firewall_slots);
    let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
    let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut resolution_states, &mut resolution_actions);
    let mut io = SimIo::new();

    for (frame, now, reason) in [
        (
            udp_frame(HOST, REMOTE, 12_345, 53, 0, false),
            100,
            DropReason::FirewallRuleDenied,
        ),
        (
            udp_frame(HOST, REMOTE, 12_345, 53, 0, false),
            99,
            DropReason::FirewallClockRegression,
        ),
        (
            tcp_frame(HOST, REMOTE, 12_345, 443, 0x02, 0),
            200,
            DropReason::FirewallRuleDenied,
        ),
        (
            tcp_frame(HOST, REMOTE, 12_345, 443, 0x02, 0),
            199,
            DropReason::FirewallClockRegression,
        ),
    ] {
        io.inject(LAN, frame.clone());
        io.run_firewall_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut firewall),
            MonotonicMillis(now),
            &mut NoTrace,
        )
        .unwrap();
        assert_drop(&mut io, reason, &frame);
        assert!(firewall.states().iter().all(|slot| !slot.is_occupied()));
    }
    assert_eq!(firewall.counters().clock_regressions, 2);
}

#[test]
fn future_combined_denies_advance_udp_and_tcp_nat_security_watermarks_only() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let udp_config = Nat44UdpConfig::new(
        &snapshot,
        LAN,
        WAN,
        WAN_LOCAL,
        40_000,
        40_000,
        Nat44UdpPolicy::default(),
    )
    .unwrap();
    let tcp_config = Nat44TcpConfig::new(
        &snapshot,
        LAN,
        WAN,
        WAN_LOCAL,
        40_000,
        40_000,
        Nat44TcpPolicy::default(),
    )
    .unwrap();
    let rules = [
        rule(
            1,
            FirewallInterface::Any,
            FirewallInterface::Any,
            any_prefix(),
            any_prefix(),
            FirewallProtocol::Udp,
            ports(0, u16::MAX),
            ports(0, u16::MAX),
            FirewallAction::Deny,
        ),
        rule(
            2,
            FirewallInterface::Any,
            FirewallInterface::Any,
            any_prefix(),
            any_prefix(),
            FirewallProtocol::Tcp,
            ports(0, u16::MAX),
            ports(0, u16::MAX),
            FirewallAction::Deny,
        ),
    ];
    let firewall_config =
        FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
    let mut firewall_slots = [];
    let mut firewall = FirewallRuntime::new(firewall_config, &mut firewall_slots);
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut udp = Nat44UdpRuntime::new(udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut tcp = Nat44TcpRuntime::new(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
    let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut resolution_states, &mut resolution_actions);
    let mut io = SimIo::new();

    let future_udp = udp_frame(HOST, REMOTE, 12_345, 53, 0x4000, false);
    io.inject(LAN, future_udp.clone());
    io.run_nat44_udp_and_tcp_with_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        &firewall_config,
        Some(&mut firewall),
        MonotonicMillis(100),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallRuleDenied, &future_udp);
    let old_udp = udp_frame(HOST, REMOTE, 12_345, 53, 0x4000, false);
    io.inject(LAN, old_udp.clone());
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
    assert_drop(&mut io, DropReason::Nat44UdpClockRegression, &old_udp);

    let future_tcp = tcp_frame(HOST, REMOTE, 12_345, 443, 0x02, 0x4000);
    io.inject(LAN, future_tcp.clone());
    io.run_nat44_udp_and_tcp_with_firewall_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        &firewall_config,
        Some(&mut firewall),
        MonotonicMillis(200),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallRuleDenied, &future_tcp);
    let old_tcp = tcp_frame(HOST, REMOTE, 12_345, 443, 0x02, 0x4000);
    io.inject(LAN, old_tcp.clone());
    io.run_nat44_udp_and_tcp_once(
        1,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        MonotonicMillis(199),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::Nat44TcpClockRegression, &old_tcp);
    assert!(udp.mappings().iter().all(|slot| !slot.is_occupied()));
    assert!(tcp.mappings().iter().all(|slot| !slot.is_occupied()));
    assert!(tcp.sessions().iter().all(|slot| !slot.is_occupied()));
}

#[test]
fn firewall_preflight_hides_route_oracles_and_never_queues_icmp_or_arp_on_failures() {
    let (all_routes, interfaces, neighbors, bindings) = topology();
    let no_remote_routes = [all_routes[0]];
    let snapshot =
        ForwardingSnapshot::new(&no_remote_routes, &interfaces, &neighbors, &bindings).unwrap();
    let rules = [allow(FirewallProtocol::Udp)];
    let config = FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
    let config2 = FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 2).unwrap();
    let mut firewall_slots = [FirewallStateSlot::default(); 1];
    let mut firewall = FirewallRuntime::new(config, &mut firewall_slots);
    let mut resolution_states = [ResolutionStateSlot::EMPTY; 2];
    let mut resolution_actions = [ResolutionActionSlot::EMPTY; 2];
    let mut resolution = resolution(&mut resolution_states, &mut resolution_actions);
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 2];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 2];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let mut io = SimIo::new();

    let valid_no_route = udp_frame(HOST, REMOTE, 12_345, 53, 0, false);
    io.inject(LAN, valid_no_route.clone());
    io.run_firewall_with_icmpv4_errors_once(
        1,
        &snapshot,
        &mut resolution,
        &mut errors,
        &config,
        Some(&mut firewall),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(
        &mut io,
        DropReason::FirewallRouteUnavailable,
        &valid_no_route,
    );

    let absent = udp_frame(HOST, REMOTE, 12_345, 53, 0, false);
    io.inject(LAN, absent.clone());
    io.run_firewall_with_icmpv4_errors_once(
        1,
        &snapshot,
        &mut resolution,
        &mut errors,
        &config,
        None,
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallRuntimeUnavailable, &absent);

    let mismatch = udp_frame(HOST, REMOTE, 12_345, 53, 0, false);
    io.inject(LAN, mismatch.clone());
    io.run_firewall_with_icmpv4_errors_once(
        1,
        &snapshot,
        &mut resolution,
        &mut errors,
        &config2,
        Some(&mut firewall),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallConfigMismatch, &mismatch);

    let mut unsupported = udp_frame(HOST, REMOTE, 12_345, 53, 0, false);
    set_protocol(&mut unsupported, 99);
    io.inject(LAN, unsupported.clone());
    io.run_firewall_with_icmpv4_errors_once(
        1,
        &snapshot,
        &mut resolution,
        &mut errors,
        &config,
        Some(&mut firewall),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(
        &mut io,
        DropReason::FirewallUnsupportedProtocol,
        &unsupported,
    );

    let mut malformed = udp_frame(HOST, REMOTE, 12_345, 53, 0, true);
    malformed[42] ^= 1;
    io.inject(LAN, malformed.clone());
    io.run_firewall_with_icmpv4_errors_once(
        1,
        &snapshot,
        &mut resolution,
        &mut errors,
        &config,
        Some(&mut firewall),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallUdpChecksumInvalid, &malformed);

    let fragment = udp_frame(HOST, REMOTE, 12_345, 53, 0x2000, false);
    io.inject(LAN, fragment.clone());
    io.run_firewall_with_icmpv4_errors_once(
        1,
        &snapshot,
        &mut resolution,
        &mut errors,
        &config,
        Some(&mut firewall),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallFragmentUnsupported, &fragment);
    assert_eq!(errors.pending_actions(), 0);
    assert_eq!(resolution.pending_actions(), 0);
    assert!(firewall.states().iter().all(|slot| !slot.is_occupied()));

    let snapshot =
        ForwardingSnapshot::new(&all_routes, &interfaces, &neighbors, &bindings).unwrap();
    let deny_rules = [rule(
        7,
        FirewallInterface::Any,
        FirewallInterface::Any,
        any_prefix(),
        any_prefix(),
        FirewallProtocol::Udp,
        ports(12_345, 12_345),
        ports(53, 53),
        FirewallAction::Deny,
    )];
    let deny_config =
        FirewallConfig::new(&snapshot, &deny_rules, FirewallPolicy::default(), 1).unwrap();
    let mut deny_slots = [FirewallStateSlot::default(); 1];
    let mut deny_runtime = FirewallRuntime::new(deny_config, &mut deny_slots);
    let explicit = udp_frame(HOST, REMOTE, 12_345, 53, 0, false);
    let default = udp_frame(HOST, REMOTE, 12_346, 53, 0, false);
    io.inject(LAN, explicit.clone());
    io.inject(LAN, default.clone());
    io.run_firewall_with_icmpv4_errors_once(
        2,
        &snapshot,
        &mut resolution,
        &mut errors,
        &deny_config,
        Some(&mut deny_runtime),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_drop(&mut io, DropReason::FirewallRuleDenied, &explicit);
    assert_drop(&mut io, DropReason::FirewallDefaultDenied, &default);
    assert_eq!(errors.pending_actions(), 0);
    assert_eq!(resolution.pending_actions(), 0);
}

#[test]
fn unfragmented_transport_boundary_matrix_is_typed_and_byte_atomic() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let rules = [allow(FirewallProtocol::Udp), allow(FirewallProtocol::Tcp)];
    let config = FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
    let mut firewall_slots = [FirewallStateSlot::default(); 1];
    let mut firewall = FirewallRuntime::new(config, &mut firewall_slots);
    let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
    let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut resolution_states, &mut resolution_actions);
    let mut io = SimIo::new();

    let mut udp_len_seven = udp_frame(HOST, REMOTE, 12_345, 53, 0, false);
    udp_len_seven[38..40].copy_from_slice(&7_u16.to_be_bytes());
    let mut udp_len_exceeds = udp_frame(HOST, REMOTE, 12_345, 53, 0, false);
    udp_len_exceeds[38..40].copy_from_slice(&12_u16.to_be_bytes());
    let mut udp_truncated = udp_frame(HOST, REMOTE, 12_345, 53, 0, false);
    udp_truncated[16..18].copy_from_slice(&27_u16.to_be_bytes());
    rewrite_ipv4_header(&mut udp_truncated);
    let reserved = udp_frame(HOST, REMOTE, 12_345, 53, 0x8000, false);
    let more_fragments = udp_frame(HOST, REMOTE, 12_345, 53, 0x2000, false);
    let fragment_offset = udp_frame(HOST, REMOTE, 12_345, 53, 1, false);
    let mut tcp_offset_small = tcp_frame(HOST, REMOTE, 12_345, 443, 0x02, 0);
    tcp_offset_small[46] = 4 << 4;
    let mut tcp_offset_exceeds = tcp_frame(HOST, REMOTE, 12_345, 443, 0x02, 0);
    tcp_offset_exceeds[46] = 6 << 4;
    let mut tcp_truncated = tcp_frame(HOST, REMOTE, 12_345, 443, 0x02, 0);
    tcp_truncated[16..18].copy_from_slice(&39_u16.to_be_bytes());
    rewrite_ipv4_header(&mut tcp_truncated);

    for (frame, reason) in [
        (udp_len_seven, DropReason::FirewallUdpLengthTooSmall),
        (
            udp_len_exceeds,
            DropReason::FirewallUdpLengthExceedsIpv4Payload,
        ),
        (udp_truncated, DropReason::FirewallUdpHeaderTruncated),
        (reserved, DropReason::FirewallFragmentUnsupported),
        (more_fragments, DropReason::FirewallFragmentUnsupported),
        (fragment_offset, DropReason::FirewallFragmentUnsupported),
        (tcp_offset_small, DropReason::FirewallTcpDataOffsetTooSmall),
        (
            tcp_offset_exceeds,
            DropReason::FirewallTcpDataOffsetExceedsIpv4Payload,
        ),
        (tcp_truncated, DropReason::FirewallTcpHeaderTruncated),
    ] {
        io.inject(LAN, frame.clone());
        io.run_firewall_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut firewall),
            MonotonicMillis(1),
            &mut NoTrace,
        )
        .unwrap();
        assert_drop(&mut io, reason, &frame);
        assert!(firewall.states().iter().all(|slot| !slot.is_occupied()));
    }
}

#[test]
fn nat_outbound_and_exact_reverse_are_visible_in_the_same_batch() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let udp_config = Nat44UdpConfig::new(
        &snapshot,
        LAN,
        WAN,
        WAN_LOCAL,
        40_000,
        40_000,
        Nat44UdpPolicy::default(),
    )
    .unwrap();
    let tcp_config = Nat44TcpConfig::new(
        &snapshot,
        LAN,
        WAN,
        WAN_LOCAL,
        41_000,
        41_000,
        Nat44TcpPolicy::default(),
    )
    .unwrap();
    let rules = [allow(FirewallProtocol::Udp)];
    let firewall_config =
        FirewallConfig::new(&snapshot, &rules, FirewallPolicy::default(), 1).unwrap();
    let mut firewall_slots = [FirewallStateSlot::default(); 1];
    let mut firewall = FirewallRuntime::new(firewall_config, &mut firewall_slots);
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut udp = Nat44UdpRuntime::new(udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut tcp = Nat44TcpRuntime::new(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
    let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut resolution_states, &mut resolution_actions);
    let mut io = SimIo::new();
    io.inject(LAN, udp_frame(HOST, REMOTE, 12_345, 53, 0x4000, false));
    io.inject(WAN, udp_frame(REMOTE, WAN_LOCAL, 53, 40_000, 0x4000, false));
    io.run_nat44_udp_and_tcp_with_firewall_once(
        2,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp),
        &tcp_config,
        Some(&mut tcp),
        &firewall_config,
        Some(&mut firewall),
        MonotonicMillis(1),
        &mut NoTrace,
    )
    .unwrap();
    assert_eq!(io.pop_tx().unwrap().egress, WAN);
    assert_eq!(io.pop_tx().unwrap().egress, LAN);
    assert_eq!(udp.counters().outbound_translated, 1);
    assert_eq!(udp.counters().inbound_translated, 1);
    assert_eq!(firewall.counters().allowed_new, 1);
    assert_eq!(firewall.counters().allowed_established, 1);
}
