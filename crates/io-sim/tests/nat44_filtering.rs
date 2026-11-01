//! NAT44 inbound filtering modes (RFC 4787 §5, REQ-8; RFC 5382 §4.3, REQ-3)
//! through the full packet path, including the firewall that runs after NAT.

mod support;

use ruster_core::{
    internet_checksum, ipv4_header_checksum, DropReason, FirewallAction, FirewallConfig,
    FirewallHashKey, FirewallInterface, FirewallIpv4Prefix, FirewallPolicy, FirewallPortRange,
    FirewallProtocol, FirewallRule, FirewallRuleId, FirewallRuntime, FirewallStateSlot,
    ForwardingSnapshot, Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy, Icmpv4ErrorRuntime,
    Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address, LocalIpv4Binding, MacAddress,
    MonotonicMillis, Nat44Filtering, Nat44TcpConfig, Nat44TcpMappingSlot, Nat44TcpPolicy,
    Nat44TcpSessionSlot, Nat44UdpConfig, Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy,
    Neighbor, NoTrace, ResolutionActionSlot, ResolutionPolicy, ResolutionRuntime,
    ResolutionStateSlot, Route,
};
use ruster_io_sim::{RecycleCause, SimIo};
use support::UdpTestIndexes;

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const HOST_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 10]);
const GW_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 20]);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const HOST: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
const REMOTE1: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const REMOTE2: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 30]);
const GW: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);
const PORT: u16 = 40_000;
const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;
const MODES: [Nat44Filtering; 3] = [
    Nat44Filtering::EndpointIndependent,
    Nat44Filtering::AddressDependent,
    Nat44Filtering::AddressAndPortDependent,
];

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
                address: Ipv4Address::from_octets([10, 0, 0, 1]),
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

fn udp_config(snapshot: &ForwardingSnapshot<'_>, filtering: Nat44Filtering) -> Nat44UdpConfig {
    Nat44UdpConfig::new(
        snapshot,
        LAN,
        WAN,
        PUBLIC,
        PORT,
        PORT,
        Nat44UdpPolicy::default().with_filtering(filtering),
    )
    .unwrap()
}

fn tcp_config(snapshot: &ForwardingSnapshot<'_>, filtering: Nat44Filtering) -> Nat44TcpConfig {
    Nat44TcpConfig::new(
        snapshot,
        LAN,
        WAN,
        PUBLIC,
        PORT,
        PORT,
        Nat44TcpPolicy::default().with_filtering(filtering),
    )
    .unwrap()
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
    bytes.extend_from_slice(&u16::try_from(segment.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(segment);
    let checksum = internet_checksum(&bytes);
    if protocol == 17 && checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

/// Atomic (DF=1) IPv4 frame addressed to the ingress interface MAC. `flags`
/// is `None` for UDP and the TCP flags byte otherwise.
fn frame(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    flags: Option<u8>,
) -> Vec<u8> {
    let transport_len = if flags.is_some() { 20 } else { 8 };
    let total_len = 20 + transport_len;
    let mut frame = vec![0_u8; 14 + total_len];
    let ingress_mac = if source.octets()[0] == 10 {
        LAN_MAC
    } else {
        WAN_MAC
    };
    frame[0..6].copy_from_slice(&ingress_mac.0);
    frame[6..12].copy_from_slice(&HOST_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = if flags.is_some() { 6 } else { 17 };
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    if let Some(flags) = flags {
        frame[38..42].copy_from_slice(&1_u32.to_be_bytes());
        frame[42..46].copy_from_slice(&2_u32.to_be_bytes());
        frame[46] = 5 << 4;
        frame[47] = flags;
        frame[48..50].copy_from_slice(&4096_u16.to_be_bytes());
        let checksum = transport_checksum(source, destination, 6, &frame[34..54]);
        frame[50..52].copy_from_slice(&checksum.to_be_bytes());
    } else {
        frame[38..40].copy_from_slice(&8_u16.to_be_bytes());
        let checksum = transport_checksum(source, destination, 17, &frame[34..42]);
        frame[40..42].copy_from_slice(&checksum.to_be_bytes());
    }
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn udp(source: Ipv4Address, destination: Ipv4Address, sport: u16, dport: u16) -> Vec<u8> {
    frame(source, destination, sport, dport, None)
}

fn tcp(source: Ipv4Address, destination: Ipv4Address, sport: u16, dport: u16, f: u8) -> Vec<u8> {
    frame(source, destination, sport, dport, Some(f))
}

fn assert_drop(io: &mut SimIo, reason: DropReason, original: &[u8]) {
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(recycled.cause, RecycleCause::Forwarding(reason));
    assert_eq!(recycled.bytes, original);
    assert!(io.pop_tx().is_none());
}

/// Asserts one translated TX toward `egress` with the given IPv4/transport
/// addresses.
fn assert_tx(
    io: &mut SimIo,
    egress: IfId,
    (source, source_port): (Ipv4Address, u16),
    (destination, destination_port): (Ipv4Address, u16),
) {
    let tx = io.pop_tx().expect("translated packet");
    assert_eq!(tx.egress, egress);
    assert_eq!(&tx.bytes[26..30], &source.octets());
    assert_eq!(&tx.bytes[30..34], &destination.octets());
    assert_eq!(&tx.bytes[34..36], &source_port.to_be_bytes());
    assert_eq!(&tx.bytes[36..38], &destination_port.to_be_bytes());
    assert!(io.pop_recycled().is_none());
}

#[test]
fn default_filtering_is_address_dependent_for_udp_and_tcp() {
    assert_eq!(Nat44Filtering::default(), Nat44Filtering::AddressDependent);
    assert_eq!(
        Nat44UdpPolicy::default().filtering(),
        Nat44Filtering::AddressDependent
    );
    assert_eq!(
        Nat44TcpPolicy::default().filtering(),
        Nat44Filtering::AddressDependent
    );
    assert_eq!(
        Nat44UdpPolicy::new(ruster_core::NAT44_UDP_DEFAULT_IDLE_TTL_MS, 7)
            .unwrap()
            .filtering(),
        Nat44Filtering::AddressDependent
    );
    assert_eq!(
        Nat44TcpPolicy::new(ruster_core::NAT44_TCP_DEFAULT_IDLE_TTL_MS, 7)
            .unwrap()
            .filtering(),
        Nat44Filtering::AddressDependent
    );
}

/// RFC 4787 §5 taxonomy for UDP. After HOST:40000 sent to REMOTE1:53, the
/// same remote endpoint is admitted in every mode, another port of the same
/// remote address only without port dependence, and another remote address
/// only under endpoint-independent filtering. Rejections are byte-unchanged
/// `NAT44_UDP_FILTER_DENIED` drops that create no state.
#[test]
fn udp_filtering_modes_admit_and_reject_inbound_per_rfc4787() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    for filtering in MODES {
        let config = udp_config(&snapshot, filtering);
        let mut mappings = [Nat44UdpMappingSlot::default(); 1];
        let mut peers = [Nat44UdpPeerSlot::default(); 4];
        let mut indexes = UdpTestIndexes::new(config, mappings.len(), peers.len());
        let mut nat = indexes.runtime(config, &mut mappings, &mut peers);
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution = resolution(&mut states, &mut actions);
        let mut io = SimIo::new();
        let mut run = |io: &mut SimIo, nat: &mut _, packet: Vec<u8>, ingress: IfId, now: u64| {
            io.inject(ingress, packet);
            io.run_nat44_udp_once(
                1,
                &snapshot,
                &mut resolution,
                &config,
                Some(nat),
                MonotonicMillis(now),
                &mut NoTrace,
            )
            .unwrap();
        };

        run(&mut io, &mut nat, udp(HOST, REMOTE1, PORT, 53), LAN, 0);
        assert_tx(&mut io, WAN, (PUBLIC, PORT), (REMOTE1, 53));
        assert_eq!(nat.counters().peers_created, 1);

        let cases = [
            (REMOTE1, 53, true, true, true),
            (REMOTE1, 5353, true, true, false),
            (REMOTE2, 53, true, false, false),
        ];
        for (remote, remote_port, eif, adf, apdf) in cases {
            let admitted = match filtering {
                Nat44Filtering::EndpointIndependent => eif,
                Nat44Filtering::AddressDependent => adf,
                Nat44Filtering::AddressAndPortDependent => apdf,
                _ => unreachable!(),
            };
            let before = nat.counters();
            let inbound = udp(remote, PUBLIC, remote_port, PORT);
            run(&mut io, &mut nat, inbound.clone(), WAN, 1);
            if admitted {
                assert_tx(&mut io, LAN, (remote, remote_port), (HOST, PORT));
                assert_eq!(
                    nat.counters().inbound_translated,
                    before.inbound_translated + 1
                );
            } else {
                assert_drop(&mut io, DropReason::Nat44UdpFilterDenied, &inbound);
                assert_eq!(nat.counters().filter_denied, before.filter_denied + 1);
            }
            // Inbound packets never create filter state in any mode.
            assert_eq!(nat.counters().peers_created, before.peers_created);
        }

        // A peer key carries the remote port only under port-dependent
        // filtering: a second destination port of REMOTE1 is a new peer
        // there and the existing one elsewhere.
        run(&mut io, &mut nat, udp(HOST, REMOTE1, PORT, 5353), LAN, 2);
        assert_tx(&mut io, WAN, (PUBLIC, PORT), (REMOTE1, 5353));
        let expected_peers = if filtering == Nat44Filtering::AddressAndPortDependent {
            2
        } else {
            1
        };
        assert_eq!(nat.counters().peers_created, expected_peers);
        let inbound = udp(REMOTE1, PUBLIC, 5353, PORT);
        run(&mut io, &mut nat, inbound, WAN, 3);
        assert_tx(&mut io, LAN, (REMOTE1, 5353), (HOST, PORT));

        // No mode admits a public port without a live mapping.
        let unmapped = udp(REMOTE1, PUBLIC, 53, PORT);
        run(&mut io, &mut nat, unmapped.clone(), WAN, 300_000 + 2);
        assert_drop(&mut io, DropReason::Nat44UdpMappingMiss, &unmapped);
    }
}

/// RFC 5382 §4.3 for TCP. Packets of an exact live session are translated
/// in every mode. Without one, only an initial SYN may initiate a session,
/// from any endpoint (EIF), from a remote address with another live session
/// of the mapping (ADF), or never (APDF). Everything else is a silent
/// byte-unchanged `NAT44_TCP_SESSION_MISS` (RFC 5382 REQ-4 a).
#[test]
fn tcp_filtering_modes_gate_inbound_initial_syn_per_rfc5382() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    for filtering in MODES {
        let config = tcp_config(&snapshot, filtering);
        let mut mappings = [Nat44TcpMappingSlot::default(); 1];
        let mut sessions = [Nat44TcpSessionSlot::default(); 4];
        let mut nat = support::tcp_runtime(config, &mut mappings, &mut sessions);
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution = resolution(&mut states, &mut actions);
        let mut io = SimIo::new();
        let mut run = |io: &mut SimIo, nat: &mut _, packet: Vec<u8>, ingress: IfId, now: u64| {
            io.inject(ingress, packet);
            io.run_nat44_tcp_once(
                1,
                &snapshot,
                &mut resolution,
                &config,
                Some(nat),
                MonotonicMillis(now),
                &mut NoTrace,
            )
            .unwrap();
        };

        run(
            &mut io,
            &mut nat,
            tcp(HOST, REMOTE1, PORT, 443, SYN),
            LAN,
            0,
        );
        assert_tx(&mut io, WAN, (PUBLIC, PORT), (REMOTE1, 443));
        run(
            &mut io,
            &mut nat,
            tcp(REMOTE1, PUBLIC, 443, PORT, SYN_ACK),
            WAN,
            1,
        );
        assert_tx(&mut io, LAN, (REMOTE1, 443), (HOST, PORT));

        // Non-SYN packets never initiate, whatever the filter.
        for (remote, remote_port) in [(REMOTE1, 8443), (REMOTE2, 443)] {
            let ack = tcp(remote, PUBLIC, remote_port, PORT, ACK);
            run(&mut io, &mut nat, ack.clone(), WAN, 2);
            assert_drop(&mut io, DropReason::Nat44TcpSessionMiss, &ack);
        }
        // SYN+ACK, SYN+RST, and SYN+FIN are not initial SYNs either.
        for flags in [SYN_ACK, 0x06, 0x03] {
            let packet = tcp(REMOTE1, PUBLIC, 8443, PORT, flags);
            run(&mut io, &mut nat, packet.clone(), WAN, 2);
            assert_drop(&mut io, DropReason::Nat44TcpSessionMiss, &packet);
        }
        assert_eq!(nat.counters().sessions_created, 1);

        let cases = [
            (REMOTE1, 8443, true, true, false),
            (REMOTE2, 443, true, false, false),
        ];
        let mut inbound_created = 0;
        for (now, (remote, remote_port, eif, adf, apdf)) in (3..).step_by(3).zip(cases) {
            let admitted = match filtering {
                Nat44Filtering::EndpointIndependent => eif,
                Nat44Filtering::AddressDependent => adf,
                Nat44Filtering::AddressAndPortDependent => apdf,
                _ => unreachable!(),
            };
            let before = nat.counters();
            let syn = tcp(remote, PUBLIC, remote_port, PORT, SYN);
            run(&mut io, &mut nat, syn.clone(), WAN, now);
            if !admitted {
                assert_drop(&mut io, DropReason::Nat44TcpSessionMiss, &syn);
                assert_eq!(nat.counters().session_misses, before.session_misses + 1);
                assert_eq!(nat.counters().sessions_created, before.sessions_created);
                continue;
            }
            inbound_created += 1;
            assert_tx(&mut io, LAN, (remote, remote_port), (HOST, PORT));
            assert_eq!(nat.counters().inbound_sessions_created, inbound_created);
            assert_eq!(nat.counters().sessions_created, before.sessions_created + 1);
            // The internal answer reuses the existing mapping (EIM) and the
            // new session; the connection then runs in both directions.
            run(
                &mut io,
                &mut nat,
                tcp(HOST, remote, PORT, remote_port, SYN_ACK),
                LAN,
                now + 1,
            );
            assert_tx(&mut io, WAN, (PUBLIC, PORT), (remote, remote_port));
            run(
                &mut io,
                &mut nat,
                tcp(remote, PUBLIC, remote_port, PORT, ACK),
                WAN,
                now + 2,
            );
            assert_tx(&mut io, LAN, (remote, remote_port), (HOST, PORT));
            assert_eq!(nat.counters().mappings_created, 1);
            assert_eq!(nat.counters().sessions_created, before.sessions_created + 1);
        }
        let expected = match filtering {
            Nat44Filtering::EndpointIndependent => 2,
            Nat44Filtering::AddressDependent => 1,
            _ => 0,
        };
        assert_eq!(nat.counters().inbound_sessions_created, expected);
    }
}

/// Address-dependent TCP admission needs a *live* session with the remote
/// address: an expired one does not count, even while the mapping is kept
/// alive by a session with another remote.
#[test]
fn tcp_address_dependent_admission_requires_a_live_session_with_the_address() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = tcp_config(&snapshot, Nat44Filtering::AddressDependent);
    let ttl = config.policy().idle_ttl_ms();
    let mut mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut sessions = [Nat44TcpSessionSlot::default(); 4];
    let mut nat = support::tcp_runtime(config, &mut mappings, &mut sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    let mut run = |io: &mut SimIo, packet: Vec<u8>, ingress: IfId, now: u64| {
        io.inject(ingress, packet);
        io.run_nat44_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &config,
            Some(&mut nat),
            MonotonicMillis(now),
            &mut NoTrace,
        )
        .unwrap();
    };
    run(&mut io, tcp(HOST, REMOTE1, PORT, 443, SYN), LAN, 0);
    assert_tx(&mut io, WAN, (PUBLIC, PORT), (REMOTE1, 443));
    run(&mut io, tcp(HOST, REMOTE2, PORT, 443, SYN), LAN, ttl - 1);
    assert_tx(&mut io, WAN, (PUBLIC, PORT), (REMOTE2, 443));

    // The REMOTE1 session expires exactly at `ttl`; the mapping stays live.
    let late = tcp(REMOTE1, PUBLIC, 8443, PORT, SYN);
    run(&mut io, late.clone(), WAN, ttl);
    assert_drop(&mut io, DropReason::Nat44TcpSessionMiss, &late);
    run(&mut io, tcp(REMOTE2, PUBLIC, 8443, PORT, SYN), WAN, ttl);
    assert_tx(&mut io, LAN, (REMOTE2, 8443), (HOST, PORT));
}

/// An admitted inbound SYN needs a free session slot like an outbound one;
/// a full table drops it as `NAT44_TCP_SESSION_TABLE_FULL` without evicting.
#[test]
fn tcp_inbound_initiation_respects_session_capacity_without_eviction() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let config = tcp_config(&snapshot, Nat44Filtering::EndpointIndependent);
    let mut mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut nat = support::tcp_runtime(config, &mut mappings, &mut sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    io.inject(LAN, tcp(HOST, REMOTE1, PORT, 443, SYN));
    let syn = tcp(REMOTE2, PUBLIC, 443, PORT, SYN);
    io.inject(WAN, syn.clone());
    io.run_nat44_tcp_once(
        2,
        &snapshot,
        &mut resolution,
        &config,
        Some(&mut nat),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    assert_eq!(io.pop_tx().unwrap().egress, WAN);
    assert_drop(&mut io, DropReason::Nat44TcpSessionTableFull, &syn);
    assert_eq!(nat.counters().session_full, 1);
    assert_eq!(nat.counters().inbound_sessions_created, 0);
    assert_eq!(nat.sessions()[0].remote_address(), REMOTE1);
}

fn firewall_config<'rules>(
    snapshot: &ForwardingSnapshot<'_>,
    rules: &'rules [FirewallRule],
) -> FirewallConfig<'rules> {
    FirewallConfig::new(
        snapshot,
        rules,
        FirewallPolicy::default(),
        1,
        FirewallHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap(),
    )
    .unwrap()
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
    ingress: IfId,
    egress: IfId,
    source: FirewallIpv4Prefix,
    destination: FirewallIpv4Prefix,
    protocol: FirewallProtocol,
    destination_ports: FirewallPortRange,
) -> FirewallRule {
    FirewallRule::new(
        FirewallRuleId(id),
        FirewallInterface::Interface(ingress),
        FirewallInterface::Interface(egress),
        source,
        destination,
        protocol,
        ports(0, u16::MAX),
        destination_ports,
        FirewallAction::AllowStateful,
    )
}

/// The firewall still evaluates the post-DNAT packet: a looser NAT filter
/// admits an inbound endpoint only where the firewall policy also admits
/// it, and a firewall deny commits no NAT state. A permissive firewall rule
/// does not loosen a stricter NAT filter either.
#[test]
fn looser_nat_filtering_never_bypasses_the_firewall() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let any = prefix(Ipv4Address::from_octets([0; 4]), 0);
    let lan = prefix(Ipv4Address::from_octets([10, 0, 0, 0]), 24);
    let outbound_rules = [
        rule(
            10,
            LAN,
            WAN,
            lan,
            any,
            FirewallProtocol::Udp,
            ports(1, u16::MAX),
        ),
        rule(
            20,
            LAN,
            WAN,
            lan,
            any,
            FirewallProtocol::Tcp,
            ports(1, u16::MAX),
        ),
    ];
    let inbound_rules = [
        outbound_rules[0],
        outbound_rules[1],
        rule(
            30,
            WAN,
            LAN,
            any,
            prefix(HOST, 32),
            FirewallProtocol::Udp,
            ports(PORT, PORT),
        ),
        rule(
            40,
            WAN,
            LAN,
            any,
            prefix(HOST, 32),
            FirewallProtocol::Tcp,
            ports(PORT, PORT),
        ),
    ];
    for filtering in [
        Nat44Filtering::EndpointIndependent,
        Nat44Filtering::AddressAndPortDependent,
    ] {
        for rules in [&outbound_rules[..], &inbound_rules[..]] {
            let udp_config = udp_config(&snapshot, filtering);
            let tcp_config = tcp_config(&snapshot, filtering);
            let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut udp_peers = [Nat44UdpPeerSlot::default(); 2];
            let mut udp_indexes =
                UdpTestIndexes::new(udp_config, udp_mappings.len(), udp_peers.len());
            let mut udp_nat = udp_indexes.runtime(udp_config, &mut udp_mappings, &mut udp_peers);
            let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
            let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 2];
            let mut tcp_nat =
                support::tcp_runtime(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
            let firewall_config = firewall_config(&snapshot, rules);
            let mut firewall_slots = [FirewallStateSlot::default(); 8];
            let mut firewall = FirewallRuntime::new(firewall_config, &mut firewall_slots);
            let mut states = [ResolutionStateSlot::EMPTY; 1];
            let mut actions = [ResolutionActionSlot::EMPTY; 1];
            let mut resolution = resolution(&mut states, &mut actions);
            let mut io = SimIo::new();
            let mut run = |io: &mut SimIo,
                           udp_nat: &mut _,
                           tcp_nat: &mut _,
                           firewall: &mut _,
                           packet: Vec<u8>,
                           ingress: IfId| {
                io.inject(ingress, packet);
                io.run_nat44_udp_and_tcp_with_firewall_once(
                    1,
                    &snapshot,
                    &mut resolution,
                    &udp_config,
                    Some(udp_nat),
                    &tcp_config,
                    Some(tcp_nat),
                    &firewall_config,
                    Some(firewall),
                    MonotonicMillis(0),
                    &mut NoTrace,
                )
                .unwrap();
            };
            let outbound = [
                udp(HOST, REMOTE1, PORT, 53),
                tcp(HOST, REMOTE1, PORT, 443, SYN),
            ];
            for packet in outbound {
                run(
                    &mut io,
                    &mut udp_nat,
                    &mut tcp_nat,
                    &mut firewall,
                    packet,
                    LAN,
                );
                assert_eq!(io.pop_tx().unwrap().egress, WAN);
            }
            let inbound_permitted = rules.len() == inbound_rules.len();
            let nat_admits = filtering == Nat44Filtering::EndpointIndependent;
            for inbound in [
                udp(REMOTE2, PUBLIC, 53, PORT),
                tcp(REMOTE2, PUBLIC, 443, PORT, SYN),
            ] {
                let before_udp = udp_nat.counters();
                let before_tcp = tcp_nat.counters();
                let before_sessions = tcp_nat.sessions().to_vec();
                let before_firewall = firewall.counters();
                let is_tcp = inbound[23] == 6;
                run(
                    &mut io,
                    &mut udp_nat,
                    &mut tcp_nat,
                    &mut firewall,
                    inbound.clone(),
                    WAN,
                );
                match (nat_admits, inbound_permitted) {
                    (true, true) => {
                        assert_tx(
                            &mut io,
                            LAN,
                            (REMOTE2, if is_tcp { 443 } else { 53 }),
                            (HOST, PORT),
                        );
                        assert_eq!(
                            firewall.counters().allowed_new,
                            before_firewall.allowed_new + 1
                        );
                        if is_tcp {
                            assert_eq!(tcp_nat.counters().inbound_sessions_created, 1);
                        }
                    }
                    (true, false) => {
                        // NAT admits, the firewall denies: nothing commits.
                        assert_drop(&mut io, DropReason::FirewallDefaultDenied, &inbound);
                        assert_eq!(udp_nat.counters(), before_udp);
                        assert_eq!(tcp_nat.counters(), before_tcp);
                        assert_eq!(tcp_nat.sessions(), &before_sessions[..]);
                        assert_eq!(firewall.counters().allowed_new, before_firewall.allowed_new);
                    }
                    (false, _) => {
                        // The stricter NAT filter holds even when the
                        // firewall would allow the flow.
                        let reason = if is_tcp {
                            DropReason::Nat44TcpSessionMiss
                        } else {
                            DropReason::Nat44UdpFilterDenied
                        };
                        assert_drop(&mut io, reason, &inbound);
                        assert_eq!(tcp_nat.sessions(), &before_sessions[..]);
                        assert_eq!(firewall.counters().allowed_new, before_firewall.allowed_new);
                    }
                }
            }
        }
    }
}

/// NAT44-021 is independent of the filter: outside traffic routed straight
/// at an inside address, not at the public address, is still dropped
/// before neighbor work under the loosest filter.
#[test]
fn endpoint_independent_filtering_keeps_the_external_to_internal_bypass_closed() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let udp_config = udp_config(&snapshot, Nat44Filtering::EndpointIndependent);
    let tcp_config = tcp_config(&snapshot, Nat44Filtering::EndpointIndependent);
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut udp_indexes = UdpTestIndexes::new(udp_config, udp_mappings.len(), udp_peers.len());
    let mut udp_nat = udp_indexes.runtime(udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut tcp_nat = support::tcp_runtime(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut io = SimIo::new();
    for outbound in [
        udp(HOST, REMOTE1, PORT, 53),
        tcp(HOST, REMOTE1, PORT, 443, SYN),
    ] {
        io.inject(LAN, outbound);
    }
    io.run_nat44_udp_and_tcp_once(
        2,
        &snapshot,
        &mut resolution,
        &udp_config,
        Some(&mut udp_nat),
        &tcp_config,
        Some(&mut tcp_nat),
        MonotonicMillis(0),
        &mut NoTrace,
    )
    .unwrap();
    io.pop_tx().unwrap();
    io.pop_tx().unwrap();
    for direct in [
        udp(REMOTE2, HOST, 53, PORT),
        tcp(REMOTE2, HOST, 443, PORT, SYN),
    ] {
        io.inject(WAN, direct.clone());
        io.run_nat44_udp_and_tcp_once(
            1,
            &snapshot,
            &mut resolution,
            &udp_config,
            Some(&mut udp_nat),
            &tcp_config,
            Some(&mut tcp_nat),
            MonotonicMillis(1),
            &mut NoTrace,
        )
        .unwrap();
        assert_drop(&mut io, DropReason::Nat44ExternalToInternalBypass, &direct);
    }
    assert_eq!(resolution.pending_actions(), 0);
    assert_eq!(tcp_nat.counters().inbound_sessions_created, 0);
}

/// RFC 5382 REQ-4 with every responder bound: an unsolicited inbound SYN
/// (no mapping, or refused by the filter) gets no TCP RST and no ICMP from
/// the full NAT + firewall + ICMPv4 error worker, now or later (REQ-4 a
/// silent drop), and an outbound SYN for the same connection afterwards
/// still opens it.
#[test]
fn unsolicited_inbound_syn_is_silently_dropped_by_the_full_worker() {
    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    let udp_config = udp_config(&snapshot, Nat44Filtering::AddressDependent);
    let tcp_config = tcp_config(&snapshot, Nat44Filtering::AddressDependent);
    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut udp_indexes = UdpTestIndexes::new(udp_config, udp_mappings.len(), udp_peers.len());
    let mut udp_nat = udp_indexes.runtime(udp_config, &mut udp_mappings, &mut udp_peers);
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 2];
    let mut tcp_nat = support::tcp_runtime(tcp_config, &mut tcp_mappings, &mut tcp_sessions);
    let any = prefix(Ipv4Address::from_octets([0; 4]), 0);
    let lan = prefix(Ipv4Address::from_octets([10, 0, 0, 0]), 24);
    // Rule 40 would admit the inbound flow, so only NAT decides here.
    let rules = [
        rule(
            20,
            LAN,
            WAN,
            lan,
            any,
            FirewallProtocol::Tcp,
            ports(1, u16::MAX),
        ),
        rule(
            40,
            WAN,
            LAN,
            any,
            prefix(HOST, 32),
            FirewallProtocol::Tcp,
            ports(PORT, PORT),
        ),
    ];
    let firewall_config = firewall_config(&snapshot, &rules);
    let mut firewall_slots = [FirewallStateSlot::default(); 4];
    let mut firewall = FirewallRuntime::new(firewall_config, &mut firewall_slots);
    let mut states = [ResolutionStateSlot::EMPTY; 1];
    let mut actions = [ResolutionActionSlot::EMPTY; 1];
    let mut resolution = resolution(&mut states, &mut actions);
    let mut error_states = [Icmpv4ErrorStateSlot::EMPTY; 4];
    let mut error_actions = [Icmpv4ErrorActionSlot::EMPTY; 4];
    let mut errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut error_states,
        &mut error_actions,
    );
    let mut io = SimIo::new();
    let mut run = |io: &mut SimIo,
                   errors: &mut Icmpv4ErrorRuntime<'_>,
                   tcp_nat: &mut _,
                   packet: Vec<u8>,
                   ingress: IfId,
                   now: u64| {
        io.inject(ingress, packet);
        io.run_nat44_udp_and_tcp_with_firewall_and_icmpv4_errors_once(
            1,
            &snapshot,
            &mut resolution,
            errors,
            &udp_config,
            Some(&mut udp_nat),
            &tcp_config,
            Some(tcp_nat),
            &firewall_config,
            Some(&mut firewall),
            MonotonicMillis(now),
            &mut NoTrace,
        )
        .unwrap();
    };

    // No mapping yet.
    let unsolicited = tcp(REMOTE1, PUBLIC, 443, PORT, SYN);
    run(
        &mut io,
        &mut errors,
        &mut tcp_nat,
        unsolicited.clone(),
        WAN,
        0,
    );
    assert_drop(&mut io, DropReason::Nat44TcpMappingMiss, &unsolicited);
    // The internal side then opens the connection (simultaneous open).
    run(
        &mut io,
        &mut errors,
        &mut tcp_nat,
        tcp(HOST, REMOTE1, PORT, 443, SYN),
        LAN,
        1,
    );
    assert_tx(&mut io, WAN, (PUBLIC, PORT), (REMOTE1, 443));
    // Filter-refused: REMOTE2 has no session with this mapping.
    let refused = tcp(REMOTE2, PUBLIC, 443, PORT, SYN);
    run(&mut io, &mut errors, &mut tcp_nat, refused.clone(), WAN, 2);
    assert_drop(&mut io, DropReason::Nat44TcpSessionMiss, &refused);
    // Nothing is queued or emitted, even well after the 6 s window.
    assert_eq!(errors.pending_actions(), 0);
    run(
        &mut io,
        &mut errors,
        &mut tcp_nat,
        tcp(HOST, REMOTE1, PORT, 443, ACK),
        LAN,
        10_000,
    );
    assert_tx(&mut io, WAN, (PUBLIC, PORT), (REMOTE1, 443));
    assert_eq!(errors.pending_actions(), 0);
    assert_eq!(resolution.pending_actions(), 0);
    assert!(io.pop_tx().is_none());
    assert_eq!(tcp_nat.counters().inbound_sessions_created, 0);
}

/// NAT44-041: an off-path sender spoofing a remote address the mapping
/// already talks to gets at most the default per-remote limit of sessions;
/// every further SYN is a byte-unchanged typed drop that creates nothing, and
/// the inside host keeps the remaining session capacity.
#[test]
fn spoofed_syns_are_capped_per_remote_and_inside_hosts_keep_capacity() {
    use ruster_core::NAT44_TCP_DEFAULT_INBOUND_SESSIONS_PER_REMOTE as LIMIT;

    let (routes, interfaces, neighbors, bindings) = topology();
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
    for filtering in [
        Nat44Filtering::EndpointIndependent,
        Nat44Filtering::AddressDependent,
    ] {
        let config = tcp_config(&snapshot, filtering);
        assert_eq!(config.policy().inbound_sessions_per_remote(), LIMIT);
        let mut mappings = [Nat44TcpMappingSlot::default(); 1];
        let mut sessions = [Nat44TcpSessionSlot::default(); 16];
        let mut nat = support::tcp_runtime(config, &mut mappings, &mut sessions);
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution = resolution(&mut states, &mut actions);
        let mut io = SimIo::new();
        let mut run = |io: &mut SimIo, nat: &mut _, packet: Vec<u8>, ingress: IfId, now: u64| {
            io.inject(ingress, packet);
            io.run_nat44_tcp_once(
                1,
                &snapshot,
                &mut resolution,
                &config,
                Some(nat),
                MonotonicMillis(now),
                &mut NoTrace,
            )
            .unwrap();
        };
        run(
            &mut io,
            &mut nat,
            tcp(HOST, REMOTE1, PORT, 443, SYN),
            LAN,
            0,
        );
        assert_tx(&mut io, WAN, (PUBLIC, PORT), (REMOTE1, 443));

        // The spoofed flood: many source ports, one claimed remote address.
        for spoofed_port in 1_000..1_040 {
            let syn = tcp(REMOTE1, PUBLIC, spoofed_port, PORT, SYN);
            let before = (nat.mappings().to_vec(), nat.sessions().to_vec());
            run(&mut io, &mut nat, syn.clone(), WAN, 1);
            if spoofed_port < 1_000 + u16::from(LIMIT) {
                assert_tx(&mut io, LAN, (REMOTE1, spoofed_port), (HOST, PORT));
            } else {
                assert_drop(
                    &mut io,
                    DropReason::Nat44TcpInboundRemoteQuotaExceeded,
                    &syn,
                );
                assert_eq!(nat.mappings(), before.0.as_slice());
                assert_eq!(nat.sessions(), before.1.as_slice());
            }
        }
        let counters = nat.counters();
        assert_eq!(counters.inbound_sessions_created, u64::from(LIMIT));
        assert_eq!(
            counters.inbound_remote_quota_exceeded,
            40 - u64::from(LIMIT)
        );
        assert_eq!(counters.session_full, 0);

        // The inside host still opens new connections into the rest.
        let free = 16 - 1 - usize::from(LIMIT);
        for remote_port in 0..free {
            let port = 2_000 + u16::try_from(remote_port).unwrap();
            run(
                &mut io,
                &mut nat,
                tcp(HOST, REMOTE1, PORT, port, SYN),
                LAN,
                2,
            );
            assert_tx(&mut io, WAN, (PUBLIC, PORT), (REMOTE1, port));
        }
        assert!(nat.sessions().iter().all(|session| session.is_occupied()));
        assert_eq!(
            nat.sessions()
                .iter()
                .filter(|session| session.is_external_inbound())
                .count(),
            usize::from(LIMIT)
        );
    }
}
