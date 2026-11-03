//! ICMP query NAT (RFC 5508 §3, N5) through the full packet path, with and
//! without the firewall.
//!
//! Every translated frame is compared byte for byte with a frame built from
//! scratch with fully recomputed IPv4 and ICMP checksums, so the RFC 1624
//! incremental updates are checked against a full recomputation.

mod support;

use ruster_core::{
    forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors,
    forward_batch_with_nat44_udp_and_tcp_and_icmp_and_icmpv4_errors, internet_checksum,
    ipv4_header_checksum, DropReason, FirewallAction, FirewallConfig, FirewallHashKey,
    FirewallInterface, FirewallIpv4Prefix, FirewallPolicy, FirewallPortRange, FirewallProtocol,
    FirewallRule, FirewallRuleId, FirewallRuntime, FirewallStateSlot, ForwardingSnapshot,
    Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy, Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId,
    Interface, Ipv4Address, LocalIpv4Binding, MacAddress, MonotonicMillis, Nat44Filtering,
    Nat44IcmpConfig, Nat44IcmpDisposition, Nat44IcmpPolicy, Nat44IcmpRuntime,
    Nat44Icmpv4Disposition, Nat44Icmpv4ErrorPolicy, Nat44TcpConfig, Nat44TcpMappingSlot,
    Nat44TcpPolicy, Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44UdpConfig, Nat44UdpMappingSlot,
    Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpRuntime, Neighbor, PacketIo, ResolutionActionSlot,
    ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route, TraceEvent,
};
use ruster_io_sim::{RecycleCause, SimIo, VecTrace};
use support::UdpTestIndexes;

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
const H1_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 10]);
const H2_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 11]);
const GW_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 20]);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
const LAN_LOCAL: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 1]);
const H1: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 10]);
const H2: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 11]);
const REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const OTHER_REMOTE: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 21]);
/// A router on the outside path that reports Time Exceeded.
const ROUTER: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);
const GW: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);
const FIRST: u16 = 40_000;
const LAST: u16 = 40_015;
const ECHO_REQUEST: u8 = 8;
const ECHO_REPLY: u8 = 0;
const TIMESTAMP_REQUEST: u8 = 13;
const TIMESTAMP_REPLY: u8 = 14;

fn leak<T>(value: T) -> &'static mut T {
    Box::leak(Box::new(value))
}

fn snapshot() -> ForwardingSnapshot<'static> {
    let routes = leak([
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
        Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(GW)).unwrap(),
    ]);
    let interfaces = leak([
        Interface {
            id: LAN,
            mac: LAN_MAC,
        },
        Interface {
            id: WAN,
            mac: WAN_MAC,
        },
    ]);
    let neighbors = leak([
        Neighbor {
            interface: LAN,
            target: H1,
            mac: H1_MAC,
        },
        Neighbor {
            interface: LAN,
            target: H2,
            mac: H2_MAC,
        },
        Neighbor {
            interface: WAN,
            target: GW,
            mac: GW_MAC,
        },
    ]);
    let bindings = leak([
        LocalIpv4Binding {
            interface: LAN,
            address: LAN_LOCAL,
        },
        LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        },
    ]);
    ForwardingSnapshot::new(&routes[..], &interfaces[..], &neighbors[..], &bindings[..]).unwrap()
}

fn any() -> FirewallIpv4Prefix {
    FirewallIpv4Prefix::new(Ipv4Address::from_octets([0; 4]), 0).unwrap()
}

fn inside() -> FirewallIpv4Prefix {
    FirewallIpv4Prefix::new(Ipv4Address::from_octets([10, 0, 0, 0]), 8).unwrap()
}

fn full() -> FirewallPortRange {
    FirewallPortRange::new(0, u16::MAX).unwrap()
}

fn rule(id: u32, ingress: IfId, egress: IfId, protocol: FirewallProtocol) -> FirewallRule {
    let (source, destination) = if ingress == LAN {
        (inside(), any())
    } else {
        (any(), inside())
    };
    FirewallRule::new(
        FirewallRuleId(id),
        FirewallInterface::Interface(ingress),
        FirewallInterface::Interface(egress),
        source,
        destination,
        protocol,
        full(),
        full(),
        FirewallAction::AllowStateful,
    )
}

#[derive(Clone, Copy, PartialEq)]
enum Firewall {
    None,
    /// LAN->WAN UDP/TCP only: the M1 rule set, without an ICMP rule.
    WithoutIcmpRule,
    /// LAN->WAN UDP/TCP/ICMP.
    WithIcmpRule,
}

struct World {
    snapshot: ForwardingSnapshot<'static>,
    udp_config: Nat44UdpConfig,
    tcp_config: Nat44TcpConfig,
    icmp_config: Nat44IcmpConfig,
    udp: Nat44UdpRuntime<'static>,
    tcp: Nat44TcpRuntime<'static>,
    icmp: Nat44IcmpRuntime<'static>,
    /// Runs the firewall composition without an ICMP config (feature off).
    icmp_enabled: bool,
    firewall_config: Option<FirewallConfig<'static>>,
    firewall: Option<FirewallRuntime<'static>>,
    resolution: ResolutionRuntime<'static>,
    errors: Icmpv4ErrorRuntime<'static>,
    io: SimIo,
    trace: VecTrace,
    now: u64,
}

impl World {
    fn new(firewall: Firewall, policy: Nat44IcmpPolicy) -> Self {
        Self::with_identifiers(firewall, policy, FIRST, LAST)
    }

    fn with_identifiers(
        firewall: Firewall,
        policy: Nat44IcmpPolicy,
        first: u16,
        last: u16,
    ) -> Self {
        let snapshot = snapshot();
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            FIRST,
            LAST,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            PUBLIC,
            FIRST,
            LAST,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let icmp_config =
            Nat44IcmpConfig::new(&snapshot, LAN, WAN, PUBLIC, first, last, policy).unwrap();
        let indexes = leak(UdpTestIndexes::new(udp_config, 4, 8));
        let udp = indexes.runtime(
            udp_config,
            leak([Nat44UdpMappingSlot::default(); 4]),
            leak([Nat44UdpPeerSlot::default(); 8]),
        );
        let tcp = support::tcp_runtime(
            tcp_config,
            leak([Nat44TcpMappingSlot::default(); 4]),
            leak([Nat44TcpSessionSlot::default(); 8]),
        );
        let icmp = support::icmp_runtime(icmp_config, 4, 8);
        let (firewall_config, firewall) = match firewall {
            Firewall::None => (None, None),
            Firewall::WithoutIcmpRule | Firewall::WithIcmpRule => {
                let mut rules = vec![
                    rule(20, LAN, WAN, FirewallProtocol::Udp),
                    rule(30, LAN, WAN, FirewallProtocol::Tcp),
                ];
                if firewall == Firewall::WithIcmpRule {
                    rules.push(rule(40, LAN, WAN, FirewallProtocol::Icmp));
                }
                let config = FirewallConfig::new(
                    &snapshot,
                    Vec::leak(rules),
                    FirewallPolicy::default(),
                    1,
                    FirewallHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap(),
                )
                .unwrap();
                let runtime =
                    FirewallRuntime::new(config, leak([FirewallStateSlot::default(); 16]));
                (Some(config), Some(runtime))
            }
        };
        let resolution = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            leak([ResolutionStateSlot::EMPTY; 2]),
            leak([ResolutionActionSlot::EMPTY; 2]),
        );
        let errors = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::default(),
            leak([Icmpv4ErrorStateSlot::EMPTY; 4]),
            leak([Icmpv4ErrorActionSlot::EMPTY; 4]),
        );
        Self {
            snapshot,
            udp_config,
            tcp_config,
            icmp_config,
            udp,
            tcp,
            icmp,
            icmp_enabled: true,
            firewall_config,
            firewall,
            resolution,
            errors,
            io: SimIo::new(),
            trace: VecTrace::default(),
            now: 1_000,
        }
    }

    /// Runs one frame; returns the transmitted frame or the drop reason.
    fn run(&mut self, ingress: IfId, frame: Vec<u8>) -> Result<(IfId, Vec<u8>), DropReason> {
        self.io.inject(ingress, frame);
        let now = MonotonicMillis(self.now);
        self.trace.clear();
        let batch = self.io.receive(1).unwrap();
        let report = if let Some(firewall_config) = &self.firewall_config {
            forward_batch_with_nat44_udp_and_tcp_and_icmp_and_firewall_and_icmpv4_errors(
                batch,
                &self.snapshot,
                &mut self.resolution,
                &mut self.errors,
                &self.udp_config,
                Some(&mut self.udp),
                &self.tcp_config,
                Some(&mut self.tcp),
                self.icmp_enabled
                    .then_some((&self.icmp_config, Some(&mut self.icmp))),
                firewall_config,
                self.firewall.as_mut(),
                None,
                now,
                &mut self.trace,
            )
        } else {
            forward_batch_with_nat44_udp_and_tcp_and_icmp_and_icmpv4_errors(
                batch,
                &self.snapshot,
                &mut self.resolution,
                &mut self.errors,
                &self.udp_config,
                Some(&mut self.udp),
                &self.tcp_config,
                Some(&mut self.tcp),
                &self.icmp_config,
                Some(&mut self.icmp),
                now,
                &mut self.trace,
            )
        };
        assert!(report.invariants_hold());
        if let Some(tx) = self.io.pop_tx() {
            return Ok((tx.egress, tx.bytes));
        }
        match self.io.pop_recycled().expect("dropped or consumed").cause {
            RecycleCause::Forwarding(reason) => Err(reason),
            other => panic!("unexpected recycle {other:?}"),
        }
    }

    fn run_consumed(&mut self, ingress: IfId, frame: Vec<u8>) {
        self.io.inject(ingress, frame);
        let batch = self.io.receive(1).unwrap();
        let report = forward_batch_with_nat44_udp_and_tcp_and_icmp_and_icmpv4_errors(
            batch,
            &self.snapshot,
            &mut self.resolution,
            &mut self.errors,
            &self.udp_config,
            Some(&mut self.udp),
            &self.tcp_config,
            Some(&mut self.tcp),
            &self.icmp_config,
            Some(&mut self.icmp),
            MonotonicMillis(self.now),
            &mut self.trace,
        );
        assert_eq!(report.consumed, 1);
        assert!(matches!(
            self.io.pop_recycled().unwrap().cause,
            RecycleCause::Consumed(_)
        ));
    }

    fn icmp_dispositions(&self) -> Vec<Nat44IcmpDisposition> {
        self.trace
            .events()
            .iter()
            .filter_map(|event| match event {
                TraceEvent::Nat44Icmp { disposition, .. } => Some(*disposition),
                _ => None,
            })
            .collect()
    }

    fn icmp_state(&self) -> (usize, usize) {
        let occupancy = self.icmp.occupancy();
        (occupancy.mappings.occupied(), occupancy.peers.occupied())
    }
}

fn mac_pair(ingress: IfId, source: Ipv4Address) -> (MacAddress, MacAddress) {
    match ingress {
        LAN => (LAN_MAC, if source == H2 { H2_MAC } else { H1_MAC }),
        _ => (WAN_MAC, GW_MAC),
    }
}

/// An Ethernet/IPv4/ICMP query frame with every checksum computed from
/// scratch. `body` follows the identifier and sequence number.
#[allow(clippy::too_many_arguments)]
fn query_frame(
    destination_mac: MacAddress,
    source_mac: MacAddress,
    source: Ipv4Address,
    destination: Ipv4Address,
    ttl: u8,
    icmp_type: u8,
    identifier: u16,
    sequence: u16,
) -> Vec<u8> {
    let body: &[u8] = if matches!(icmp_type, TIMESTAMP_REQUEST | TIMESTAMP_REPLY) {
        &[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]
    } else {
        b"ping-payload"
    };
    let icmp_len = 8 + body.len();
    let total_len = 20 + icmp_len;
    let mut frame = vec![0_u8; 14 + total_len];
    frame[0..6].copy_from_slice(&destination_mac.0);
    frame[6..12].copy_from_slice(&source_mac.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[18..20].copy_from_slice(&0x4242_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = ttl;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34] = icmp_type;
    frame[38..40].copy_from_slice(&identifier.to_be_bytes());
    frame[40..42].copy_from_slice(&sequence.to_be_bytes());
    frame[42..].copy_from_slice(body);
    refresh(&mut frame);
    frame
}

fn refresh(frame: &mut [u8]) {
    frame[36..38].fill(0);
    let checksum = internet_checksum(&frame[34..]);
    frame[36..38].copy_from_slice(&checksum.to_be_bytes());
    frame[24..26].fill(0);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
}

/// A query as received on `ingress` from `source`.
fn received(
    ingress: IfId,
    source: Ipv4Address,
    destination: Ipv4Address,
    icmp_type: u8,
    identifier: u16,
) -> Vec<u8> {
    let (destination_mac, source_mac) = mac_pair(ingress, source);
    query_frame(
        destination_mac,
        source_mac,
        source,
        destination,
        64,
        icmp_type,
        identifier,
        7,
    )
}

/// An ICMP error from `source` to `destination` quoting the IPv4 datagram
/// of `quoted` (an Ethernet frame), received on `ingress`.
fn icmp_error(
    ingress: IfId,
    source: Ipv4Address,
    destination: Ipv4Address,
    icmp_type: u8,
    code: u8,
    quoted: &[u8],
) -> Vec<u8> {
    let quote = &quoted[14..];
    let total_len = 20 + 8 + quote.len();
    let mut frame = vec![0_u8; 14 + total_len];
    let (destination_mac, source_mac) = mac_pair(ingress, source);
    frame[0..6].copy_from_slice(&destination_mac.0);
    frame[6..12].copy_from_slice(&source_mac.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[18..20].copy_from_slice(&0x7777_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34] = icmp_type;
    frame[35] = code;
    frame[42..].copy_from_slice(quote);
    refresh(&mut frame);
    frame
}

fn identifier(frame: &[u8]) -> u16 {
    u16::from_be_bytes([frame[38], frame[39]])
}

/// Echo and Timestamp: the request leaves with the public address and the
/// preserved identifier, the reply returns to the host with the internal
/// identifier, and both match a full checksum recomputation.
#[test]
fn lan_queries_translate_both_ways_with_exact_checksums() {
    for firewall in [Firewall::None, Firewall::WithIcmpRule] {
        for (request, reply) in [
            (ECHO_REQUEST, ECHO_REPLY),
            (TIMESTAMP_REQUEST, TIMESTAMP_REPLY),
        ] {
            let mut world = World::new(firewall, Nat44IcmpPolicy::default());
            let id = FIRST + 3;
            let (egress, out) = world
                .run(LAN, received(LAN, H1, REMOTE, request, id))
                .unwrap();
            assert_eq!(egress, WAN);
            assert_eq!(
                out,
                query_frame(GW_MAC, WAN_MAC, PUBLIC, REMOTE, 63, request, id, 7)
            );
            assert_eq!(
                world.icmp_dispositions(),
                [Nat44IcmpDisposition::OutboundTranslated {
                    public_identifier: id,
                    mapping_created: true,
                    peer_created: true,
                }]
            );
            let (egress, back) = world
                .run(WAN, received(WAN, REMOTE, PUBLIC, reply, id))
                .unwrap();
            assert_eq!(egress, LAN);
            assert_eq!(
                back,
                query_frame(H1_MAC, LAN_MAC, REMOTE, H1, 63, reply, id, 7)
            );
            let counters = world.icmp.counters();
            assert_eq!(counters.outbound_translated, 1);
            assert_eq!(counters.inbound_translated, 1);
            assert_eq!(world.icmp_state(), (1, 1));
            // UDP and TCP state are untouched.
            assert_eq!(world.udp.occupancy().mappings.occupied(), 0);
            assert_eq!(world.tcp.occupancy().mappings.occupied(), 0);
        }
    }
}

/// Two hosts using the same identifier get distinct public identifiers and
/// each reply reaches its own host (the identifier is the NAPT "port").
#[test]
fn colliding_identifiers_are_translated_apart() {
    let mut world = World::new(Firewall::None, Nat44IcmpPolicy::default());
    let id = FIRST;
    let (_, first) = world
        .run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, id))
        .unwrap();
    let (_, second) = world
        .run(LAN, received(LAN, H2, REMOTE, ECHO_REQUEST, id))
        .unwrap();
    assert_eq!(identifier(&first), id);
    let public = identifier(&second);
    assert_ne!(public, id);
    assert!((FIRST..=LAST).contains(&public));
    assert_eq!(
        second,
        query_frame(GW_MAC, WAN_MAC, PUBLIC, REMOTE, 63, ECHO_REQUEST, public, 7)
    );
    let (_, back) = world
        .run(WAN, received(WAN, REMOTE, PUBLIC, ECHO_REPLY, public))
        .unwrap();
    assert_eq!(
        back,
        query_frame(H2_MAC, LAN_MAC, REMOTE, H2, 63, ECHO_REPLY, id, 7)
    );
    let (_, back) = world
        .run(WAN, received(WAN, REMOTE, PUBLIC, ECHO_REPLY, id))
        .unwrap();
    assert_eq!(
        back,
        query_frame(H1_MAC, LAN_MAC, REMOTE, H1, 63, ECHO_REPLY, id, 7)
    );
}

/// An unsolicited Echo Request to the public address is answered by the
/// router itself and creates no NAT state; an unsolicited or foreign reply
/// is refused (mapping miss, address-dependent filter).
#[test]
fn inbound_requests_reach_the_router_and_unsolicited_replies_are_refused() {
    for firewall in [Firewall::None, Firewall::WithIcmpRule] {
        let mut world = World::new(firewall, Nat44IcmpPolicy::default());
        let (egress, answer) = world
            .run(WAN, received(WAN, REMOTE, PUBLIC, ECHO_REQUEST, 0x77))
            .unwrap();
        assert_eq!(egress, WAN);
        assert_eq!(answer[34], ECHO_REPLY);
        assert_eq!(&answer[26..30], &PUBLIC.octets());
        assert_eq!(&answer[30..34], &REMOTE.octets());
        assert_eq!(identifier(&answer), 0x77);
        assert_eq!(world.icmp_state(), (0, 0));
        assert_eq!(
            world.run(WAN, received(WAN, REMOTE, PUBLIC, ECHO_REPLY, FIRST)),
            Err(DropReason::Nat44IcmpMappingMiss)
        );
        world
            .run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST))
            .unwrap();
        assert_eq!(
            world.run(WAN, received(WAN, OTHER_REMOTE, PUBLIC, ECHO_REPLY, FIRST)),
            Err(DropReason::Nat44IcmpFilterDenied)
        );
        // A Timestamp Request to the router is local, unsupported control.
        world.run_consumed(WAN, received(WAN, REMOTE, PUBLIC, TIMESTAMP_REQUEST, 1));
        assert_eq!(world.icmp_state(), (1, 1));
    }
}

/// Endpoint-independent filtering admits a reply from any remote to a live
/// mapping, but the firewall still requires its own flow.
#[test]
fn endpoint_independent_filtering_is_still_gated_by_the_firewall() {
    let policy = Nat44IcmpPolicy::default()
        .with_filtering(Nat44Filtering::EndpointIndependent)
        .unwrap();
    let mut world = World::new(Firewall::None, policy);
    world
        .run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST))
        .unwrap();
    let (egress, _) = world
        .run(WAN, received(WAN, OTHER_REMOTE, PUBLIC, ECHO_REPLY, FIRST))
        .unwrap();
    assert_eq!(egress, LAN);

    let mut world = World::new(Firewall::WithIcmpRule, policy);
    world
        .run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST))
        .unwrap();
    assert_eq!(
        world.run(WAN, received(WAN, OTHER_REMOTE, PUBLIC, ECHO_REPLY, FIRST)),
        Err(DropReason::FirewallDefaultDenied)
    );
    // A Timestamp Reply is not the reply of an Echo flow.
    assert_eq!(
        world.run(WAN, received(WAN, REMOTE, PUBLIC, TIMESTAMP_REPLY, FIRST)),
        Err(DropReason::FirewallDefaultDenied)
    );
}

/// The firewall evaluates ICMP queries: without an ICMP rule the default
/// denies them before any NAT state, and with ICMP query NAT off the
/// crossing fails closed as before (unsupported transport).
#[test]
fn firewall_without_an_icmp_rule_and_disabled_query_nat_fail_closed() {
    let mut world = World::new(Firewall::WithoutIcmpRule, Nat44IcmpPolicy::default());
    assert_eq!(
        world.run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST)),
        Err(DropReason::FirewallDefaultDenied)
    );
    assert_eq!(world.icmp_state(), (0, 0));
    assert_eq!(world.icmp.counters().outbound_translated, 0);

    let mut world = World::new(Firewall::WithIcmpRule, Nat44IcmpPolicy::default());
    world.icmp_enabled = false;
    assert_eq!(
        world.run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST)),
        Err(DropReason::Nat44UdpUnsupportedTransport)
    );
    assert!(world
        .run(WAN, received(WAN, REMOTE, PUBLIC, ECHO_REQUEST, 1))
        .is_ok());
}

/// Malformed or untranslated messages are refused before any state change.
#[test]
fn malformed_and_untranslated_queries_are_refused_without_state() {
    for firewall in [Firewall::None, Firewall::WithIcmpRule] {
        let mut world = World::new(firewall, Nat44IcmpPolicy::default());
        let mut bad_checksum = received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST);
        bad_checksum[36] ^= 0xff;
        let mut bad_code = received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST);
        bad_code[35] = 1;
        refresh(&mut bad_code);
        // MF set: a fragment (DF clear alone is translated, see below).
        let mut fragment = received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST);
        fragment[20] = 0x20;
        refresh(&mut fragment);
        // A Timestamp Request with only the 8-byte echo-sized header.
        let mut short_timestamp = received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST);
        short_timestamp.truncate(14 + 20 + 8);
        short_timestamp[16..18].copy_from_slice(&28_u16.to_be_bytes());
        short_timestamp[34] = TIMESTAMP_REQUEST;
        refresh(&mut short_timestamp);
        let inside_reply = received(LAN, H1, REMOTE, ECHO_REPLY, FIRST);
        let mut information = received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST);
        information[34] = 15;
        refresh(&mut information);
        let (checksum, code, header, unsupported, fragmented) = if firewall == Firewall::None {
            (
                DropReason::Nat44IcmpChecksumInvalid,
                DropReason::Nat44IcmpCodeInvalid,
                DropReason::Nat44IcmpHeaderTruncated,
                DropReason::Nat44IcmpTypeUnsupported,
                DropReason::Nat44IcmpFragmentUnsupported,
            )
        } else {
            (
                DropReason::FirewallIcmpQueryInvalid,
                DropReason::FirewallIcmpQueryInvalid,
                DropReason::FirewallIcmpQueryInvalid,
                DropReason::FirewallUnsupportedProtocol,
                DropReason::FirewallFragmentUnsupported,
            )
        };
        assert_eq!(world.run(LAN, bad_checksum), Err(checksum));
        assert_eq!(world.run(LAN, bad_code), Err(code));
        assert_eq!(world.run(LAN, short_timestamp), Err(header));
        assert_eq!(world.run(LAN, information), Err(unsupported));
        assert_eq!(world.run(LAN, fragment), Err(fragmented));
        // A reply from the inside answers nothing the NAT delivered. With
        // the firewall, the LAN->WAN ICMP rule matches it but a reply never
        // opens a flow; without it, the NAT refuses it.
        let inside_reply_reason = if firewall == Firewall::None {
            DropReason::Nat44IcmpTypeUnsupported
        } else {
            DropReason::FirewallIcmpReplyWithoutRequest
        };
        assert_eq!(world.run(LAN, inside_reply), Err(inside_reply_reason));
        assert_eq!(world.icmp_state(), (0, 0));
    }
}

/// An inside host pinging the public address is answered by the router on
/// the inside interface; the query creates no NAT state. A reply addressed
/// to the public address from the inside cannot name a query session.
#[test]
fn pinging_the_public_address_from_inside_is_answered_by_the_router() {
    for firewall in [Firewall::None, Firewall::WithoutIcmpRule] {
        let mut world = World::new(firewall, Nat44IcmpPolicy::default());
        let (egress, answer) = world
            .run(LAN, received(LAN, H1, PUBLIC, ECHO_REQUEST, 0x99))
            .unwrap();
        assert_eq!(egress, LAN);
        assert_eq!(answer[34], ECHO_REPLY);
        assert_eq!(&answer[0..6], &H1_MAC.0);
        assert_eq!(&answer[26..30], &PUBLIC.octets());
        assert_eq!(&answer[30..34], &H1.octets());
        assert_eq!(internet_checksum(&answer[34..]), 0);
        assert_eq!(ipv4_header_checksum(&answer[14..34]), 0);
        assert_eq!(world.icmp_state(), (0, 0));
        assert_eq!(
            world.run(LAN, received(LAN, H1, PUBLIC, ECHO_REPLY, FIRST)),
            Err(DropReason::Nat44IcmpWrongIngress)
        );
    }
}

/// RFC 5508 REQ-4: a Time Exceeded about the translated Echo Request (TTL
/// expiring upstream, as traceroute does) reaches the inside host with the
/// quote reverted to what the host sent: its address, its identifier, and
/// its ICMP checksum. The lookup is read-only.
#[test]
fn external_errors_quoting_a_query_reach_the_host_with_the_quote_reverted() {
    for firewall in [Firewall::None, Firewall::WithIcmpRule] {
        let mut world = World::new(firewall, Nat44IcmpPolicy::default());
        let sent = received(LAN, H2, REMOTE, ECHO_REQUEST, FIRST);
        world
            .run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST))
            .unwrap();
        let (_, translated) = world.run(LAN, sent.clone()).unwrap();
        let public = identifier(&translated);
        assert_ne!(public, FIRST);
        let counters = world.icmp.counters();
        let error = icmp_error(WAN, ROUTER, PUBLIC, 11, 0, &translated);
        let (egress, delivered) = world.run(WAN, error).unwrap();
        assert_eq!(egress, LAN);
        // Outer: from ROUTER to H2; quote: what H2 sent (TTL 64 as it left
        // H2, minus the router's own hop: the quote is the translated
        // datagram, whose TTL the router decremented once).
        let mut expected_quote = sent.clone();
        expected_quote[22] -= 1;
        refresh(&mut expected_quote);
        let expected = {
            let mut frame = icmp_error(WAN, ROUTER, H2, 11, 0, &expected_quote);
            frame[0..6].copy_from_slice(&H2_MAC.0);
            frame[6..12].copy_from_slice(&LAN_MAC.0);
            frame[22] -= 1;
            refresh(&mut frame);
            frame
        };
        assert_eq!(delivered, expected);
        assert_eq!(
            world.trace.events().iter().find_map(|event| match event {
                TraceEvent::Nat44Icmpv4 { disposition, .. } => Some(*disposition),
                _ => None,
            }),
            Some(Nat44Icmpv4Disposition::Translated {
                quoted_protocol: 1,
                internal_address: H2,
                internal_port: FIRST,
            })
        );
        assert_eq!(world.icmp.counters(), counters);
        // Only the queried remote's path may report: an error quoting a
        // query to another remote is refused.
        let mut other = translated.clone();
        other[30..34].copy_from_slice(&OTHER_REMOTE.octets());
        refresh(&mut other);
        assert_eq!(
            world.run(WAN, icmp_error(WAN, ROUTER, PUBLIC, 11, 0, &other)),
            Err(DropReason::Nat44IcmpFilterDenied)
        );
        // A quoted reply was never sent by the NAT.
        let mut quoted_reply = translated.clone();
        quoted_reply[34] = ECHO_REPLY;
        refresh(&mut quoted_reply);
        assert_eq!(
            world.run(WAN, icmp_error(WAN, ROUTER, PUBLIC, 11, 0, &quoted_reply)),
            Err(DropReason::Nat44Icmpv4QuotedProtocolUnsupported)
        );
    }
}

/// RFC 5508 REQ-5: an inside host's error about a reply it received goes to
/// the remote with the quote reverted to the external view (public address
/// and public identifier) and the public address as outer source.
#[test]
fn inside_errors_quoting_a_reply_reach_the_remote_with_the_external_view() {
    for firewall in [Firewall::None, Firewall::WithIcmpRule] {
        let mut world = World::new(firewall, Nat44IcmpPolicy::default());
        world
            .run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST))
            .unwrap();
        let (_, translated) = world
            .run(LAN, received(LAN, H2, REMOTE, ECHO_REQUEST, FIRST))
            .unwrap();
        let public = identifier(&translated);
        let arrived = received(WAN, REMOTE, PUBLIC, ECHO_REPLY, public);
        let (_, delivered) = world.run(WAN, arrived.clone()).unwrap();
        // H2 reports Parameter Problem about the reply it received.
        let error = icmp_error(LAN, H2, REMOTE, 12, 0, &delivered);
        let (egress, out) = world.run(LAN, error).unwrap();
        assert_eq!(egress, WAN);
        let mut external_quote = arrived;
        external_quote[22] -= 1;
        refresh(&mut external_quote);
        let expected = {
            let mut frame = icmp_error(WAN, PUBLIC, REMOTE, 12, 0, &external_quote);
            frame[0..6].copy_from_slice(&GW_MAC.0);
            frame[6..12].copy_from_slice(&WAN_MAC.0);
            frame[22] -= 1;
            refresh(&mut frame);
            frame
        };
        assert_eq!(out, expected);
        // Only a reply can have reached H2 through the NAT: an error quoting
        // a request is refused.
        let mut quoted_request = delivered.clone();
        quoted_request[34] = ECHO_REQUEST;
        refresh(&mut quoted_request);
        assert_eq!(
            world.run(LAN, icmp_error(LAN, H2, REMOTE, 12, 0, &quoted_request)),
            Err(DropReason::Nat44Icmpv4QuotedProtocolUnsupported)
        );
        // Policy: off for queries leaves the error untranslated.
        let policy =
            Nat44IcmpPolicy::default().with_icmpv4_errors(Nat44Icmpv4ErrorPolicy::ExternalOnly);
        let mut world = World::new(firewall, policy);
        world
            .run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST))
            .unwrap();
        let (_, delivered) = world
            .run(WAN, received(WAN, REMOTE, PUBLIC, ECHO_REPLY, FIRST))
            .unwrap();
        assert!(world
            .run(LAN, icmp_error(LAN, H1, REMOTE, 12, 0, &delivered))
            .is_err());
    }
}

/// The router's own Time Exceeded for an inside ping whose TTL expires at
/// the router quotes the untranslated packet and creates no mapping.
#[test]
fn ttl_expiry_at_the_router_is_reported_before_translation() {
    let mut world = World::new(Firewall::None, Nat44IcmpPolicy::default());
    let mut frame = received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST);
    frame[22] = 1;
    refresh(&mut frame);
    assert_eq!(world.run(LAN, frame), Err(DropReason::Ipv4TtlExpired));
    assert_eq!(world.icmp_state(), (0, 0));
    assert_eq!(world.errors.pending_actions(), 1);
}

/// Capacity: the mapping table and identifier pool fail closed without
/// eviction; an expired mapping is reused.
#[test]
fn full_tables_fail_closed_and_expired_mappings_are_reused() {
    let mut world = World::new(Firewall::None, Nat44IcmpPolicy::default());
    for id in 0..4 {
        world
            .run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST + id))
            .unwrap();
    }
    assert_eq!(
        world.run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST + 4)),
        Err(DropReason::Nat44IcmpMappingTableFull)
    );
    assert_eq!(world.icmp.counters().mapping_full, 1);
    world.now += Nat44IcmpPolicy::default().idle_ttl_ms();
    world
        .run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST + 4))
        .unwrap();
    assert_eq!(world.icmp.counters().mappings_expired, 1);
}

/// N6: with `peers-per-host = 1` a host that already queries one remote
/// on a live mapping is refused a second remote (on the same identifier or
/// a new one) as `NAT44_ICMP_HOST_PEER_QUOTA_EXCEEDED` without state, while
/// another host is served; the host recovers when its mapping expires.
#[test]
fn a_host_at_its_query_peer_limit_is_refused_while_another_is_served() {
    let mut world = World::new(
        Firewall::None,
        Nat44IcmpPolicy::default().with_peers_per_host(1),
    );
    let other = Ipv4Address::from_octets([198, 51, 100, 21]);
    world
        .run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST))
        .unwrap();
    let state = world.icmp_state();
    for id in [FIRST, FIRST + 1] {
        assert_eq!(
            world.run(LAN, received(LAN, H1, other, ECHO_REQUEST, id)),
            Err(DropReason::Nat44IcmpHostPeerQuotaExceeded)
        );
    }
    assert_eq!(world.icmp_state(), state);
    assert_eq!(world.icmp.counters().host_peer_quota_exceeded, 2);
    world
        .run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST))
        .unwrap();
    world
        .run(LAN, received(LAN, H2, other, ECHO_REQUEST, FIRST))
        .unwrap();
    world.now += Nat44IcmpPolicy::default().idle_ttl_ms();
    world
        .run(LAN, received(LAN, H1, other, ECHO_REQUEST, FIRST + 1))
        .unwrap();
}

/// N4 gates apply to errors quoting a query exactly as to UDP/TCP quotes:
/// the per-(inside host, quoted remote) translated-error limit (NAT44-065,
/// default burst 100) and the Frag Needed Next-Hop MTU sanity check.
#[test]
fn errors_quoting_a_query_share_the_translated_limit_and_mtu_check() {
    let mut world = World::new(Firewall::None, Nat44IcmpPolicy::default());
    let (_, translated) = world
        .run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST))
        .unwrap();
    let mut bad_mtu = icmp_error(WAN, ROUTER, PUBLIC, 3, 4, &translated);
    bad_mtu[40..42].copy_from_slice(&67_u16.to_be_bytes());
    refresh(&mut bad_mtu);
    assert_eq!(
        world.run(WAN, bad_mtu),
        Err(DropReason::Nat44Icmpv4FragNeededMtuInvalid)
    );
    let error = icmp_error(WAN, ROUTER, PUBLIC, 11, 0, &translated);
    for _ in 0..ruster_core::ICMPV4_DEFAULT_TRANSLATED_BURST {
        assert!(world.run(WAN, error.clone()).is_ok());
    }
    assert_eq!(
        world.run(WAN, error),
        Err(DropReason::Nat44Icmpv4TranslatedRateLimited)
    );
}

/// NAT44-116: an unfragmented query with DF clear (Windows Echo Requests,
/// Linux Echo Replies) is translated both ways with its flags and IPv4 ID
/// preserved, and an error quoting such a query is translated too.
#[test]
fn unfragmented_queries_with_df_clear_translate_both_ways() {
    for firewall in [Firewall::None, Firewall::WithIcmpRule] {
        let mut world = World::new(firewall, Nat44IcmpPolicy::default());
        let clear_df = |mut frame: Vec<u8>| {
            frame[20] = 0;
            refresh(&mut frame);
            frame
        };
        let (_, out) = world
            .run(
                LAN,
                clear_df(received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST)),
            )
            .unwrap();
        assert_eq!(
            out,
            clear_df(query_frame(
                GW_MAC,
                WAN_MAC,
                PUBLIC,
                REMOTE,
                63,
                ECHO_REQUEST,
                FIRST,
                7
            ))
        );
        let (_, back) = world
            .run(
                WAN,
                clear_df(received(WAN, REMOTE, PUBLIC, ECHO_REPLY, FIRST)),
            )
            .unwrap();
        assert_eq!(
            back,
            clear_df(query_frame(
                H1_MAC, LAN_MAC, REMOTE, H1, 63, ECHO_REPLY, FIRST, 7
            ))
        );
        let (egress, _) = world
            .run(WAN, icmp_error(WAN, ROUTER, PUBLIC, 11, 0, &out))
            .unwrap();
        assert_eq!(egress, LAN);
    }
}

/// Routed (non-NAT) ICMP queries through the firewall alone, LAN <-> WAN.
struct Routed {
    snapshot: ForwardingSnapshot<'static>,
    config: FirewallConfig<'static>,
    firewall: FirewallRuntime<'static>,
    resolution: ResolutionRuntime<'static>,
    io: SimIo,
    now: u64,
}

impl Routed {
    /// LAN -> WAN ICMP allow-stateful, plus WAN -> LAN when `inbound_rule`.
    fn new(inbound_rule: bool) -> Self {
        let snapshot = snapshot();
        let mut rules = vec![rule(40, LAN, WAN, FirewallProtocol::Icmp)];
        if inbound_rule {
            rules.push(rule(41, WAN, LAN, FirewallProtocol::Icmp));
        }
        let config = FirewallConfig::new(
            &snapshot,
            Vec::leak(rules),
            FirewallPolicy::default(),
            1,
            FirewallHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap(),
        )
        .unwrap();
        Self {
            snapshot,
            config,
            firewall: FirewallRuntime::new(config, leak([FirewallStateSlot::default(); 16])),
            resolution: ResolutionRuntime::new(
                ResolutionPolicy::new(1_000, 2_000).unwrap(),
                leak([ResolutionStateSlot::EMPTY; 2]),
                leak([ResolutionActionSlot::EMPTY; 2]),
            ),
            io: SimIo::new(),
            now: 1_000,
        }
    }

    fn run(&mut self, ingress: IfId, frame: Vec<u8>) -> Result<IfId, DropReason> {
        self.io.inject(ingress, frame);
        self.now += 1;
        self.io
            .run_firewall_once(
                1,
                &self.snapshot,
                &mut self.resolution,
                &self.config,
                Some(&mut self.firewall),
                MonotonicMillis(self.now),
                &mut VecTrace::default(),
            )
            .unwrap();
        if let Some(tx) = self.io.pop_tx() {
            return Ok(tx.egress);
        }
        match self.io.pop_recycled().expect("dropped").cause {
            RecycleCause::Forwarding(reason) => Err(reason),
            other => panic!("unexpected recycle {other:?}"),
        }
    }
}

/// Review M1: with identifiers 8 and 13 a request's pseudo-port tuple equals
/// the reverse of another query's tuple as numbers. The direction flag keeps
/// the three counterexamples out: a remote's request never matches an inside
/// host's flow as its reply, while the real replies still pass.
#[test]
fn routed_queries_with_identifiers_8_and_13_never_admit_a_reverse_request() {
    // (inside request type, id), (remote request type, id) that collides.
    for ((host_type, host_id), (remote_type, remote_id), reply_type) in [
        ((ECHO_REQUEST, 8), (ECHO_REQUEST, 8), ECHO_REPLY),
        ((TIMESTAMP_REQUEST, 8), (ECHO_REQUEST, 13), TIMESTAMP_REPLY),
        ((ECHO_REQUEST, 13), (TIMESTAMP_REQUEST, 8), ECHO_REPLY),
    ] {
        let mut routed = Routed::new(false);
        assert_eq!(
            routed.run(LAN, received(LAN, H1, REMOTE, host_type, host_id)),
            Ok(WAN)
        );
        assert_eq!(
            routed.run(WAN, received(WAN, REMOTE, H1, remote_type, remote_id)),
            Err(DropReason::FirewallDefaultDenied),
            "{host_type}/{host_id} vs {remote_type}/{remote_id}"
        );
        assert_eq!(
            routed.run(WAN, received(WAN, REMOTE, H1, reply_type, host_id)),
            Ok(LAN)
        );
        // A repeated request from the inside is the same flow, not a reply.
        assert_eq!(
            routed.run(LAN, received(LAN, H1, REMOTE, host_type, host_id)),
            Ok(WAN)
        );
        assert_eq!(routed.firewall.counters().allowed_new, 1);
    }
    // A reply without a request never opens a flow, even under an
    // allow-stateful rule for the reverse direction.
    let mut routed = Routed::new(true);
    assert_eq!(
        routed.run(WAN, received(WAN, REMOTE, H1, ECHO_REPLY, 8)),
        Err(DropReason::FirewallIcmpReplyWithoutRequest)
    );
    // A request under that rule opens a flow whose reply goes back out.
    assert_eq!(
        routed.run(WAN, received(WAN, REMOTE, H1, ECHO_REQUEST, 8)),
        Ok(LAN)
    );
    assert_eq!(
        routed.run(LAN, received(LAN, H1, REMOTE, ECHO_REPLY, 8)),
        Ok(WAN)
    );
}

/// The same identifiers through the NAT: Echo and Timestamp replies with
/// public identifiers 8 and 13 return to the host, and an error quoting a
/// query with those identifiers is still RELATED (identifier pool 1..65535
/// so the identifiers are preserved).
#[test]
fn nat_queries_with_identifiers_8_and_13_keep_their_flows_apart() {
    let mut world = World::with_identifiers(
        Firewall::WithIcmpRule,
        Nat44IcmpPolicy::default(),
        1,
        65_535,
    );
    let (_, echo) = world
        .run(LAN, received(LAN, H1, REMOTE, ECHO_REQUEST, 8))
        .unwrap();
    assert_eq!(identifier(&echo), 8);
    let (_, timestamp) = world
        .run(LAN, received(LAN, H2, REMOTE, TIMESTAMP_REQUEST, 13))
        .unwrap();
    assert_eq!(identifier(&timestamp), 13);
    // A Timestamp Reply with H1's identifier is not the reply of H1's Echo.
    assert_eq!(
        world.run(WAN, received(WAN, REMOTE, PUBLIC, TIMESTAMP_REPLY, 8)),
        Err(DropReason::FirewallDefaultDenied)
    );
    assert_eq!(
        world
            .run(WAN, received(WAN, REMOTE, PUBLIC, ECHO_REPLY, 8))
            .map(|(e, _)| e),
        Ok(LAN)
    );
    assert_eq!(
        world
            .run(WAN, received(WAN, REMOTE, PUBLIC, TIMESTAMP_REPLY, 13))
            .map(|(e, _)| e),
        Ok(LAN)
    );
    // REQ-4 error about the Echo, and a REQ-5 error about the delivered
    // Timestamp Reply, are RELATED to their own flows.
    assert!(world
        .run(WAN, icmp_error(WAN, ROUTER, PUBLIC, 11, 0, &echo))
        .is_ok());
    let (_, delivered) = world
        .run(WAN, received(WAN, REMOTE, PUBLIC, TIMESTAMP_REPLY, 13))
        .unwrap();
    assert!(world
        .run(LAN, icmp_error(LAN, H2, REMOTE, 12, 0, &delivered))
        .is_ok());
}

/// The reserved flag is handled as for UDP/TCP (NAT44-008, RFC 1812
/// §4.2.2.3): ignored by both the firewall pre-validation and the NAT's
/// fragment check, and preserved on the wire.
#[test]
fn the_reserved_flag_is_ignored_and_preserved_by_firewall_and_nat_alike() {
    for firewall in [Firewall::None, Firewall::WithIcmpRule] {
        let mut world = World::new(firewall, Nat44IcmpPolicy::default());
        let reserved = |mut frame: Vec<u8>| {
            frame[20] |= 0x80;
            refresh(&mut frame);
            frame
        };
        let (_, out) = world
            .run(
                LAN,
                reserved(received(LAN, H1, REMOTE, ECHO_REQUEST, FIRST)),
            )
            .unwrap();
        assert_eq!(
            out,
            reserved(query_frame(
                GW_MAC,
                WAN_MAC,
                PUBLIC,
                REMOTE,
                63,
                ECHO_REQUEST,
                FIRST,
                7
            ))
        );
    }
}
