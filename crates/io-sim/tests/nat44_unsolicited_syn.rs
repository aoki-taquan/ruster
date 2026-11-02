//! RFC 5382 §5 REQ-4 through the full NAT + firewall + ICMPv4 error worker:
//! an unsolicited inbound SYN is dropped silently, held for at least 6 s,
//! dropped silently for good if an outbound SYN for the same connection is
//! translated meanwhile (simultaneous open), and otherwise answered with
//! exactly one ICMP Destination Unreachable, Port Unreachable (Type 3,
//! Code 3) quoting the original SYN (NAT44-038, NAT44-069..NAT44-073).

mod support;

use ruster_core::{
    dispatch_nat44_tcp_unsolicited_syns, execute_one_icmpv4_error, internet_checksum,
    ipv4_header_checksum, DropReason, FirewallAction, FirewallConfig, FirewallHashKey,
    FirewallInterface, FirewallIpv4Prefix, FirewallPolicy, FirewallPortRange, FirewallProtocol,
    FirewallRule, FirewallRuleId, FirewallRuntime, FirewallStateSlot, ForwardingSnapshot,
    Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy, Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId,
    Interface, Ipv4Address, LocalIpv4Binding, MacAddress, MonotonicMillis, Nat44Filtering,
    Nat44TcpConfig, Nat44TcpCounters, Nat44TcpHashKey, Nat44TcpMappingSlot, Nat44TcpPolicy,
    Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44TcpSynHoldSlot, Nat44TcpUnsolicitedSynDisposition,
    Nat44UdpConfig, Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpRuntime,
    Neighbor, NoGeneratedIcmpv4Trace, NoTrace, ResolutionActionSlot, ResolutionPolicy,
    ResolutionRuntime, ResolutionStateSlot, Route, TraceEvent, TraceSink,
    NAT44_TCP_UNSOLICITED_SYN_HOLD_MS,
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
const HOLD: u64 = NAT44_TCP_UNSOLICITED_SYN_HOLD_MS;
const MODES: [Nat44Filtering; 3] = [
    Nat44Filtering::EndpointIndependent,
    Nat44Filtering::AddressDependent,
    Nat44Filtering::AddressAndPortDependent,
];

fn leak<T>(value: T) -> &'static mut T {
    Box::leak(Box::new(value))
}

fn leak_slice<T: Clone>(value: T, len: usize) -> &'static mut [T] {
    Box::leak(vec![value; len].into_boxed_slice())
}

fn snapshot(static_gateway: bool) -> &'static ForwardingSnapshot<'static> {
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
    let neighbors: &'static [Neighbor] = if static_gateway {
        leak([
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
        ])
    } else {
        leak([Neighbor {
            interface: LAN,
            target: HOST,
            mac: HOST_MAC,
        }])
    };
    let bindings = leak([
        LocalIpv4Binding {
            interface: LAN,
            address: Ipv4Address::from_octets([10, 0, 0, 1]),
        },
        LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        },
    ]);
    leak(ForwardingSnapshot::new(routes, interfaces, neighbors, bindings).unwrap())
}

fn prefix(address: Ipv4Address, prefix_len: u8) -> FirewallIpv4Prefix {
    FirewallIpv4Prefix::new(address, prefix_len).unwrap()
}

fn rule(id: u32, ingress: IfId, egress: IfId, destination: FirewallIpv4Prefix) -> FirewallRule {
    FirewallRule::new(
        FirewallRuleId(id),
        FirewallInterface::Interface(ingress),
        FirewallInterface::Interface(egress),
        prefix(Ipv4Address::from_octets([0; 4]), 0),
        destination,
        FirewallProtocol::Tcp,
        FirewallPortRange::new(0, u16::MAX).unwrap(),
        FirewallPortRange::new(1, u16::MAX).unwrap(),
        FirewallAction::AllowStateful,
    )
}

/// How a test world is built.
#[derive(Clone, Copy)]
struct Setup {
    filtering: Nat44Filtering,
    unsolicited_syn_icmp: bool,
    holds: usize,
    sessions: usize,
    /// Whether the firewall admits new outside -> inside TCP flows.
    firewall_admits_inbound: bool,
    static_gateway: bool,
    inbound_sessions_per_remote: u8,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            filtering: Nat44Filtering::AddressDependent,
            unsolicited_syn_icmp: true,
            holds: 8,
            sessions: 8,
            firewall_admits_inbound: true,
            static_gateway: true,
            inbound_sessions_per_remote: 0,
        }
    }
}

struct World {
    snapshot: &'static ForwardingSnapshot<'static>,
    resolution: ResolutionRuntime<'static>,
    errors: Icmpv4ErrorRuntime<'static>,
    udp_config: Nat44UdpConfig,
    udp: Nat44UdpRuntime<'static>,
    tcp_config: Nat44TcpConfig,
    tcp: Nat44TcpRuntime<'static>,
    firewall_config: FirewallConfig<'static>,
    firewall: FirewallRuntime<'static>,
    io: SimIo,
}

impl World {
    fn new(setup: Setup) -> Self {
        let snapshot = snapshot(setup.static_gateway);
        let udp_config = Nat44UdpConfig::new(
            snapshot,
            LAN,
            WAN,
            PUBLIC,
            PORT,
            PORT,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        let udp_indexes = leak(UdpTestIndexes::new(udp_config, 1, 1));
        let udp = udp_indexes.runtime(
            udp_config,
            leak_slice(Nat44UdpMappingSlot::default(), 1),
            leak_slice(Nat44UdpPeerSlot::default(), 1),
        );
        let tcp_policy = Nat44TcpPolicy::default()
            .with_filtering(setup.filtering)
            .with_unsolicited_syn_icmp(setup.unsolicited_syn_icmp)
            .with_inbound_sessions_per_remote(setup.inbound_sessions_per_remote)
            .unwrap();
        let tcp_config =
            Nat44TcpConfig::new(snapshot, LAN, WAN, PUBLIC, PORT, PORT, tcp_policy).unwrap();
        let tcp = support::tcp_runtime(
            tcp_config,
            leak_slice(Nat44TcpMappingSlot::default(), 1),
            leak_slice(Nat44TcpSessionSlot::default(), setup.sessions),
        )
        .with_unsolicited_syn_holds(leak_slice(Nat44TcpSynHoldSlot::EMPTY, setup.holds))
        .unwrap();
        let mut rules = vec![rule(
            20,
            LAN,
            WAN,
            prefix(Ipv4Address::from_octets([0; 4]), 0),
        )];
        if setup.firewall_admits_inbound {
            rules.push(rule(40, WAN, LAN, prefix(HOST, 32)));
        }
        let rules: &'static [FirewallRule] = Box::leak(rules.into_boxed_slice());
        let firewall_config = FirewallConfig::new(
            snapshot,
            rules,
            FirewallPolicy::default(),
            1,
            FirewallHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap(),
        )
        .unwrap();
        let firewall = FirewallRuntime::new(
            firewall_config,
            leak_slice(FirewallStateSlot::default(), 16),
        );
        let resolution = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            leak_slice(ResolutionStateSlot::EMPTY, 4),
            leak_slice(ResolutionActionSlot::EMPTY, 4),
        );
        let errors = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::default(),
            leak_slice(Icmpv4ErrorStateSlot::EMPTY, 4),
            leak_slice(Icmpv4ErrorActionSlot::EMPTY, 4),
        );
        Self {
            snapshot,
            resolution,
            errors,
            udp_config,
            udp,
            tcp_config,
            tcp,
            firewall_config,
            firewall,
            io: SimIo::new(),
        }
    }

    /// One packet through the full worker at `now`.
    fn packet(&mut self, ingress: IfId, frame: Vec<u8>, now: u64) {
        self.packet_traced(ingress, frame, now, &mut NoTrace);
    }

    fn packet_traced<T: TraceSink>(
        &mut self,
        ingress: IfId,
        frame: Vec<u8>,
        now: u64,
        trace: &mut T,
    ) {
        self.io.inject(ingress, frame);
        self.io
            .run_nat44_udp_and_tcp_with_firewall_and_icmpv4_errors_once(
                1,
                self.snapshot,
                &mut self.resolution,
                &mut self.errors,
                &self.udp_config,
                Some(&mut self.udp),
                &self.tcp_config,
                Some(&mut self.tcp),
                &self.firewall_config,
                Some(&mut self.firewall),
                MonotonicMillis(now),
                trace,
            )
            .unwrap();
    }

    /// The tick-loop part: dispatch matured holds with `budget`, then emit
    /// every queued generated ICMPv4 error. Returns the emitted frames.
    fn tick(&mut self, now: u64, budget: usize) -> Vec<(IfId, Vec<u8>)> {
        self.tick_traced(now, budget, &mut NoTrace)
    }

    fn tick_traced<T: TraceSink>(
        &mut self,
        now: u64,
        budget: usize,
        trace: &mut T,
    ) -> Vec<(IfId, Vec<u8>)> {
        dispatch_nat44_tcp_unsolicited_syns(
            &mut self.tcp,
            &mut self.errors,
            &mut self.resolution,
            self.snapshot,
            MonotonicMillis(now),
            budget,
            trace,
        )
        .unwrap();
        while execute_one_icmpv4_error(
            &mut self.io,
            &mut self.errors,
            MonotonicMillis(now),
            &mut NoGeneratedIcmpv4Trace,
        )
        .unwrap()
        .is_some()
        {}
        let mut emitted = Vec::new();
        while let Some(tx) = self.io.pop_tx() {
            emitted.push((tx.egress, tx.bytes));
        }
        emitted
    }

    fn counters(&self) -> Nat44TcpCounters {
        self.tcp.counters()
    }

    fn expect_drop(&mut self, reason: DropReason, original: &[u8]) {
        let recycled = self.io.pop_recycled().expect("dropped");
        assert_eq!(recycled.cause, RecycleCause::Forwarding(reason));
        assert_eq!(recycled.bytes, original);
        assert!(self.io.pop_tx().is_none(), "nothing is sent at once");
    }

    fn expect_tx(&mut self, egress: IfId) -> Vec<u8> {
        let tx = self.io.pop_tx().expect("forwarded");
        assert_eq!(tx.egress, egress);
        assert!(self.io.pop_recycled().is_none());
        tx.bytes
    }
}

#[derive(Default)]
struct Recorder(Vec<Nat44TcpUnsolicitedSynDisposition>);

impl TraceSink for Recorder {
    fn record(&mut self, event: TraceEvent) {
        if let TraceEvent::Nat44TcpUnsolicitedSyn { disposition } = event {
            self.0.push(disposition);
        }
    }
}

fn tcp_checksum(source: Ipv4Address, destination: Ipv4Address, segment: &[u8]) -> u16 {
    let mut bytes = Vec::with_capacity(12 + segment.len());
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&destination.octets());
    bytes.extend_from_slice(&[0, 6]);
    bytes.extend_from_slice(&u16::try_from(segment.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(segment);
    internet_checksum(&bytes)
}

/// Atomic (DF=1) TCP frame with IPv4 identification `id` and TOS `tos`,
/// addressed to the ingress interface MAC.
fn tcp_with(
    source: Ipv4Address,
    destination: Ipv4Address,
    ports: (u16, u16),
    flags: u8,
    id: u16,
    tos: u8,
) -> Vec<u8> {
    let mut frame = vec![0_u8; 54];
    let (ingress_mac, source_mac) = if source.octets()[0] == 10 {
        (LAN_MAC, HOST_MAC)
    } else {
        (WAN_MAC, GW_MAC)
    };
    frame[0..6].copy_from_slice(&ingress_mac.0);
    frame[6..12].copy_from_slice(&source_mac.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = tos;
    frame[16..18].copy_from_slice(&40_u16.to_be_bytes());
    frame[18..20].copy_from_slice(&id.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&source.octets());
    frame[30..34].copy_from_slice(&destination.octets());
    frame[34..36].copy_from_slice(&ports.0.to_be_bytes());
    frame[36..38].copy_from_slice(&ports.1.to_be_bytes());
    frame[38..42].copy_from_slice(&0x1000_0000_u32.to_be_bytes());
    frame[46] = 5 << 4;
    frame[47] = flags;
    frame[48..50].copy_from_slice(&65_535_u16.to_be_bytes());
    let checksum = tcp_checksum(source, destination, &frame[34..54]);
    frame[50..52].copy_from_slice(&checksum.to_be_bytes());
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn tcp(source: Ipv4Address, destination: Ipv4Address, sport: u16, dport: u16, f: u8) -> Vec<u8> {
    tcp_with(source, destination, (sport, dport), f, 1, 0)
}

/// The exact ICMP Port Unreachable the router must send for `original`
/// (an Ethernet frame received on WAN from `remote`): from the WAN address
/// to the remote through the gateway, TOS 0xc0 | (original & 0x1e), TTL
/// 64, ID 0, DF, quoting the whole original IPv4 datagram.
fn port_unreachable(remote: Ipv4Address, original: &[u8]) -> Vec<u8> {
    let quote = &original[14..];
    let mut frame = vec![0_u8; 14 + 28 + quote.len()];
    frame[0..6].copy_from_slice(&GW_MAC.0);
    frame[6..12].copy_from_slice(&WAN_MAC.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = 0xc0 | (quote[1] & 0x1e);
    frame[16..18].copy_from_slice(&u16::try_from(28 + quote.len()).unwrap().to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&PUBLIC.octets());
    frame[30..34].copy_from_slice(&remote.octets());
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame[34] = 3;
    frame[35] = 3;
    frame[42..].copy_from_slice(quote);
    let checksum = internet_checksum(&frame[34..]);
    frame[36..38].copy_from_slice(&checksum.to_be_bytes());
    frame
}

/// Mapping miss and filter refusal in every filtering mode: silent at
/// once, still silent 1 ms before the 6 s hold ends, then exactly one ICMP
/// Port Unreachable quoting the original SYN; never a second one.
#[test]
fn unsolicited_syn_gets_one_port_unreachable_after_six_seconds_and_not_before() {
    for filtering in MODES {
        let mut world = World::new(Setup {
            filtering,
            ..Setup::default()
        });
        // Mapping miss: nothing has used the public port yet.
        let unsolicited = tcp_with(REMOTE1, PUBLIC, (443, PORT), SYN, 0x1234, 0x2d);
        let mut trace = Recorder::default();
        world.packet_traced(WAN, unsolicited.clone(), 100, &mut trace);
        world.expect_drop(DropReason::Nat44TcpMappingMiss, &unsolicited);
        assert_eq!(
            trace.0,
            [Nat44TcpUnsolicitedSynDisposition::Held {
                public_port: PORT,
                deadline_ms: 100 + HOLD
            }]
        );
        assert_eq!(world.counters().unsolicited_syn_held, 1);
        assert_eq!(world.errors.pending_actions(), 0);
        assert!(world.tick(100, 16).is_empty());
        assert!(world.tick(100 + HOLD - 1, 16).is_empty(), "{filtering:?}");
        assert_eq!(world.tcp.unsolicited_syn_holds(), 1);
        let emitted = world.tick(100 + HOLD, 16);
        assert_eq!(emitted, [(WAN, port_unreachable(REMOTE1, &unsolicited))]);
        assert_eq!(world.counters().unsolicited_syn_icmp_queued, 1);
        assert_eq!(world.errors.counters().dequeued_port_unreachable, 1);
        assert_eq!(world.tcp.unsolicited_syn_holds(), 0);
        assert!(world.tick(100 + 10 * HOLD, 16).is_empty(), "never twice");

        // Filter refusal: the host's mapping talks to REMOTE1:443 only.
        world.packet(LAN, tcp(HOST, REMOTE1, PORT, 443, SYN), 20_000);
        world.expect_tx(WAN);
        let refused = tcp(REMOTE2, PUBLIC, 443, PORT, SYN);
        world.packet(WAN, refused.clone(), 20_001);
        if filtering == Nat44Filtering::EndpointIndependent {
            // EIF admits it: a session is created, nothing is held.
            world.expect_tx(LAN);
            assert_eq!(world.counters().unsolicited_syn_held, 1);
            assert!(world.tick(20_001 + HOLD, 16).is_empty());
        } else {
            world.expect_drop(DropReason::Nat44TcpSessionMiss, &refused);
            assert_eq!(world.counters().unsolicited_syn_held, 2);
            assert!(world.tick(20_000 + HOLD, 16).is_empty());
            let emitted = world.tick(20_001 + HOLD, 16);
            assert_eq!(emitted, [(WAN, port_unreachable(REMOTE2, &refused))]);
        }
        // A non-SYN unsolicited segment is never held.
        let ack = tcp(REMOTE2, PUBLIC, 444, PORT, 0x10);
        world.packet(WAN, ack.clone(), 30_000);
        world.expect_drop(DropReason::Nat44TcpSessionMiss, &ack);
        assert!(world.tick(30_000 + HOLD, 16).is_empty());
        assert_eq!(world.tcp.unsolicited_syn_holds(), 0);
    }
}

/// REQ-4 MUST: an outbound SYN for the same connection (translated source
/// `PUBLIC:PORT`, destination the held SYN's remote endpoint) translated
/// during the hold silently drops the held SYN, and the simultaneous open
/// completes. An outbound SYN to another remote port is another
/// connection: the hold survives, and at maturity it is answered only if
/// the filtering still refuses the remote endpoint.
#[test]
fn outbound_syn_for_the_connection_cancels_the_hold_and_opens_it() {
    for filtering in MODES {
        let mut world = World::new(Setup {
            filtering,
            ..Setup::default()
        });
        let unsolicited = tcp(REMOTE1, PUBLIC, 443, PORT, SYN);
        world.packet(WAN, unsolicited.clone(), 0);
        world.expect_drop(DropReason::Nat44TcpMappingMiss, &unsolicited);
        world.packet(LAN, tcp(HOST, REMOTE1, PORT, 443, SYN), 5_999);
        let outbound = world.expect_tx(WAN);
        assert_eq!(&outbound[34..36], &PORT.to_be_bytes());
        assert_eq!(world.counters().unsolicited_syn_cancelled, 1);
        assert_eq!(world.tcp.unsolicited_syn_holds(), 0);
        assert!(world.tick(HOLD, 16).is_empty());
        assert!(world.tick(10 * HOLD, 16).is_empty());
        // The retransmitted inbound SYN now opens the connection.
        world.packet(WAN, tcp(REMOTE1, PUBLIC, 443, PORT, SYN), 7_000);
        world.expect_tx(LAN);
        assert_eq!(world.counters().unsolicited_syn_icmp_queued, 0);
    }

    for filtering in MODES {
        let mut world = World::new(Setup {
            filtering,
            ..Setup::default()
        });
        let unsolicited = tcp(REMOTE1, PUBLIC, 443, PORT, SYN);
        world.packet(WAN, unsolicited.clone(), 0);
        world.expect_drop(DropReason::Nat44TcpMappingMiss, &unsolicited);
        // Same remote address, other remote port: another connection.
        world.packet(LAN, tcp(HOST, REMOTE1, PORT, 444, SYN), 1);
        world.expect_tx(WAN);
        assert_eq!(world.counters().unsolicited_syn_cancelled, 0);
        assert_eq!(world.tcp.unsolicited_syn_holds(), 1);
        let emitted = world.tick(HOLD, 16);
        if filtering == Nat44Filtering::AddressAndPortDependent {
            assert_eq!(emitted, [(WAN, port_unreachable(REMOTE1, &unsolicited))]);
        } else {
            // EIF and ADF would now admit a retransmission: silent.
            assert!(emitted.is_empty(), "{filtering:?}");
            assert_eq!(world.counters().unsolicited_syn_superseded, 1);
        }
    }
}

/// A retransmitted SYN of a held connection is not held again: it restarts
/// the hold (REQ-4 forbids answering any unsolicited SYN within 6 s of its
/// reception), and the one ICMP still quotes the original SYN.
#[test]
fn retransmissions_restart_the_hold_and_yield_one_icmp_for_the_original() {
    let mut world = World::new(Setup::default());
    let original = tcp_with(REMOTE1, PUBLIC, (443, PORT), SYN, 1, 0);
    let retransmitted = tcp_with(REMOTE1, PUBLIC, (443, PORT), SYN, 2, 0);
    world.packet(WAN, original.clone(), 0);
    world.expect_drop(DropReason::Nat44TcpMappingMiss, &original);
    world.packet(WAN, retransmitted.clone(), 3_000);
    world.expect_drop(DropReason::Nat44TcpMappingMiss, &retransmitted);
    assert_eq!(
        (
            world.counters().unsolicited_syn_held,
            world.counters().unsolicited_syn_refreshed
        ),
        (1, 1)
    );
    assert_eq!(world.tcp.unsolicited_syn_holds(), 1);
    assert!(world.tick(HOLD, 16).is_empty());
    assert!(world.tick(3_000 + HOLD - 1, 16).is_empty());
    let emitted = world.tick(3_000 + HOLD, 16);
    assert_eq!(emitted, [(WAN, port_unreachable(REMOTE1, &original))]);
    assert!(world.tick(100_000, 16).is_empty());
}

/// The hold table is bounded: when it is full, further unsolicited SYNs are
/// only dropped silently (REQ-4 a), counted, and nothing is evicted.
#[test]
fn a_full_hold_table_drops_silently_without_eviction() {
    let mut world = World::new(Setup {
        holds: 2,
        ..Setup::default()
    });
    for (index, remote_port) in [1001_u16, 1002, 1003].into_iter().enumerate() {
        let syn = tcp(REMOTE1, PUBLIC, remote_port, PORT, SYN);
        world.packet(WAN, syn.clone(), index as u64);
        world.expect_drop(DropReason::Nat44TcpMappingMiss, &syn);
    }
    let counters = world.counters();
    assert_eq!(
        (
            counters.unsolicited_syn_held,
            counters.unsolicited_syn_hold_full
        ),
        (2, 1)
    );
    let occupancy = world.tcp.occupancy().unsolicited_syn_holds;
    assert_eq!((occupancy.occupied(), occupancy.capacity()), (2, 2));
    // The two held SYNs are answered (100 ms apart: the per-egress
    // limiter), the refused one never.
    assert_eq!(world.tick(HOLD, 1).len(), 1);
    assert_eq!(world.tick(HOLD + 100, 1).len(), 1);
    assert!(world.tick(HOLD + 10_000, 16).is_empty());
    assert_eq!(world.counters().unsolicited_syn_icmp_queued, 2);
}

/// Rate limit and anti-amplification: SYNs that mature together share the
/// generated-ICMPv4 per-egress limiter (one queued error per egress, then
/// 100 ms). A hold the limiter refuses is retired, never retried, so a hold
/// produces at most one ICMP and a flood of N SYNs at most N.
#[test]
fn matured_holds_share_the_icmp_limiter_and_are_never_retried() {
    let mut world = World::new(Setup {
        holds: 16,
        ..Setup::default()
    });
    for remote_port in 2000..2010_u16 {
        world.packet(WAN, tcp(REMOTE1, PUBLIC, remote_port, PORT, SYN), 0);
        assert!(world.io.pop_recycled().is_some());
    }
    let emitted = world.tick(HOLD, 16);
    assert_eq!(emitted.len(), 1);
    let counters = world.counters();
    assert_eq!(
        (
            counters.unsolicited_syn_icmp_queued,
            counters.unsolicited_syn_icmp_suppressed
        ),
        (1, 9)
    );
    assert_eq!(world.errors.counters().pending, 9);
    assert_eq!(world.tcp.unsolicited_syn_holds(), 0);
    assert!(world.tick(HOLD + 1_000, 16).is_empty());
}

/// The tick budget bounds the work per call: holds mature in deadline
/// order, so a call never touches more than `budget` holds and never scans
/// the ones still held.
#[test]
fn dispatch_work_is_bounded_by_the_budget_at_the_production_cap() {
    const CAP: usize = 4096;
    let mut world = World::new(Setup {
        holds: CAP,
        ..Setup::default()
    });
    for n in 0..CAP + 100 {
        let remote =
            Ipv4Address::from_octets([198, 51, 100 + (n / 60_000) as u8, 1 + (n % 200) as u8]);
        let syn = tcp(remote, PUBLIC, 1024 + (n / 200) as u16, PORT, SYN);
        world.packet(WAN, syn, n as u64 / 64);
        assert!(world.io.pop_recycled().is_some());
    }
    let counters = world.counters();
    assert_eq!(
        (
            counters.unsolicited_syn_held,
            counters.unsolicited_syn_hold_full
        ),
        (CAP as u64, 100)
    );
    let mut trace = Recorder::default();
    let emitted = world.tick_traced(HOLD + 1_000, 16, &mut trace);
    assert_eq!(emitted.len(), 1, "one ICMP per egress at a time");
    assert_eq!(trace.0.len(), 16);
    assert_eq!(world.tcp.unsolicited_syn_holds(), CAP - 16);
    // Nothing matures before its time even with a huge budget.
    let mut world = World::new(Setup {
        holds: CAP,
        ..Setup::default()
    });
    for n in 0..CAP {
        let remote = Ipv4Address::from_octets([198, 51, 100, 1 + (n % 200) as u8]);
        world.packet(
            WAN,
            tcp(remote, PUBLIC, 1024 + (n / 200) as u16, PORT, SYN),
            n as u64,
        );
        assert!(world.io.pop_recycled().is_some());
    }
    let mut trace = Recorder::default();
    assert_eq!(
        world.tick_traced(HOLD + 99, usize::MAX, &mut trace).len(),
        1
    );
    assert_eq!(
        trace.0.len(),
        100,
        "exactly the holds received at 0..=99 ms"
    );
    assert_eq!(world.tcp.unsolicited_syn_holds(), CAP - 100);
}

/// Switch off (or no hold storage) is the REQ-4 a policy: silent drop only.
#[test]
fn switch_off_or_no_storage_keeps_the_silent_drop() {
    for (switch, holds) in [(false, 8), (true, 0)] {
        let mut world = World::new(Setup {
            unsolicited_syn_icmp: switch,
            holds,
            ..Setup::default()
        });
        let syn = tcp(REMOTE1, PUBLIC, 443, PORT, SYN);
        let mut trace = Recorder::default();
        world.packet_traced(WAN, syn.clone(), 0, &mut trace);
        world.expect_drop(DropReason::Nat44TcpMappingMiss, &syn);
        assert!(trace.0.is_empty());
        assert!(world.tick(HOLD, 16).is_empty());
        assert!(world.tick(10 * HOLD, 16).is_empty());
        let counters = world.counters();
        assert_eq!(counters.mapping_misses, 1);
        assert_eq!(
            counters.unsolicited_syn_held + counters.unsolicited_syn_hold_full,
            0
        );
        assert_eq!(world.errors.counters().queued, 0);
    }
}

/// Reflection guard: a SYN whose source is not routed back out of the
/// outside interface (here a spoofed inside address arriving on WAN) is
/// never held, so no ICMP can be steered into the inside realm.
#[test]
fn spoofed_inside_sources_are_never_held() {
    let mut world = World::new(Setup::default());
    let spoofed = tcp_with(
        Ipv4Address::from_octets([10, 0, 0, 99]),
        PUBLIC,
        (443, PORT),
        SYN,
        1,
        0,
    );
    // Arrives on WAN with a WAN-side MAC.
    let mut spoofed = spoofed;
    spoofed[0..6].copy_from_slice(&WAN_MAC.0);
    spoofed[6..12].copy_from_slice(&GW_MAC.0);
    let mut trace = Recorder::default();
    world.packet_traced(WAN, spoofed.clone(), 0, &mut trace);
    world.expect_drop(DropReason::Nat44TcpMappingMiss, &spoofed);
    assert_eq!(
        trace.0,
        [Nat44TcpUnsolicitedSynDisposition::Ineligible { public_port: PORT }]
    );
    assert_eq!(world.counters().unsolicited_syn_ineligible, 1);
    assert!(world.tick(HOLD, 16).is_empty());
}

/// Hairpin and quota: a hairpinned SYN that the destination mapping
/// refuses keeps the hole-punching silent drop (it is never held), and a
/// SYN refused by the per-remote inbound quota (NAT44-041) is not an
/// unsolicited SYN in the REQ-4 sense and stays a silent drop.
#[test]
fn hairpin_and_quota_refusals_are_not_held() {
    let mut world = World::new(Setup::default());
    // No mapping owns PUBLIC:PORT+1: the inbound half is a mapping miss.
    let hairpin = tcp(HOST, PUBLIC, 5555, PORT + 1, SYN);
    world.packet(LAN, hairpin, 0);
    assert!(world.io.pop_recycled().is_some());
    assert_eq!(world.counters().unsolicited_syn_held, 0);
    assert!(world.tick(HOLD, 16).is_empty());

    let mut world = World::new(Setup {
        filtering: Nat44Filtering::EndpointIndependent,
        inbound_sessions_per_remote: 1,
        ..Setup::default()
    });
    world.packet(LAN, tcp(HOST, REMOTE1, PORT, 443, SYN), 0);
    world.expect_tx(WAN);
    world.packet(WAN, tcp(REMOTE2, PUBLIC, 1000, PORT, SYN), 1);
    world.expect_tx(LAN);
    let over = tcp(REMOTE2, PUBLIC, 1001, PORT, SYN);
    world.packet(WAN, over.clone(), 2);
    world.expect_drop(DropReason::Nat44TcpInboundRemoteQuotaExceeded, &over);
    assert_eq!(world.counters().unsolicited_syn_held, 0);
    assert!(world.tick(HOLD + 2, 16).is_empty());
}

/// Firewall order: the NAT decides first. A mapping miss is held whatever
/// the firewall's inbound policy (there is no inside tuple to judge), while
/// a SYN the NAT filter admits but the firewall denies is the firewall's
/// silent `FIREWALL_DEFAULT_DENIED` and is not held.
#[test]
fn nat_refusals_are_held_but_firewall_denials_are_not() {
    let mut world = World::new(Setup {
        filtering: Nat44Filtering::EndpointIndependent,
        firewall_admits_inbound: false,
        ..Setup::default()
    });
    let miss = tcp(REMOTE1, PUBLIC, 443, PORT, SYN);
    world.packet(WAN, miss.clone(), 0);
    world.expect_drop(DropReason::Nat44TcpMappingMiss, &miss);
    world.packet(LAN, tcp(HOST, REMOTE1, PORT, 80, SYN), 1);
    world.expect_tx(WAN);
    let denied = tcp(REMOTE2, PUBLIC, 443, PORT, SYN);
    world.packet(WAN, denied.clone(), 2);
    world.expect_drop(DropReason::FirewallDefaultDenied, &denied);
    assert_eq!(world.counters().unsolicited_syn_held, 1);
    // The mapping exists now and EIF admits REMOTE1 again: superseded.
    assert!(world.tick(HOLD + 2, 16).is_empty());
    assert_eq!(world.counters().unsolicited_syn_superseded, 1);
}

/// An unresolved reverse neighbor queues only an ARP Request; the hold is
/// retired without an ICMP (it is not retried).
#[test]
fn unresolved_reverse_neighbor_retires_the_hold_after_arp() {
    let mut world = World::new(Setup {
        static_gateway: false,
        ..Setup::default()
    });
    let syn = tcp(REMOTE1, PUBLIC, 443, PORT, SYN);
    world.packet(WAN, syn.clone(), 0);
    world.expect_drop(DropReason::Nat44TcpMappingMiss, &syn);
    assert!(world.tick(HOLD, 16).is_empty());
    assert_eq!(world.resolution.pending_actions(), 1, "one ARP Request");
    assert_eq!(world.counters().unsolicited_syn_icmp_suppressed, 1);
    assert_eq!(world.tcp.unsolicited_syn_holds(), 0);
}

/// A reconcile (every publication) flushes the holds with the rest of the
/// TCP NAT state.
#[test]
fn reconcile_flushes_every_hold() {
    let mut world = World::new(Setup::default());
    world.packet(WAN, tcp(REMOTE1, PUBLIC, 443, PORT, SYN), 0);
    assert!(world.io.pop_recycled().is_some());
    assert_eq!(world.tcp.unsolicited_syn_holds(), 1);
    world
        .tcp
        .reconcile(
            world.tcp_config,
            Nat44TcpHashKey::new(0x1111_2222_3333_4444, 0x5555_6666_7777_8888).unwrap(),
        )
        .unwrap();
    assert_eq!(world.tcp.unsolicited_syn_holds(), 0);
    assert_eq!(world.tcp.storage_shape().unsolicited_syn_hold_slots(), 8);
    assert!(world.tick(HOLD, 16).is_empty());
}

/// Defaults: the switch is on (the RFC SHOULD) and a runtime gets its hold
/// storage only from the caller.
#[test]
fn delayed_icmp_is_on_by_default_and_needs_caller_storage() {
    assert!(Nat44TcpPolicy::default().unsolicited_syn_icmp());
    assert!(
        Nat44TcpPolicy::new(ruster_core::NAT44_TCP_DEFAULT_IDLE_TTL_MS, 1)
            .unwrap()
            .unsolicited_syn_icmp()
    );
    assert_eq!(HOLD, 6_000);
    let world = World::new(Setup {
        holds: 0,
        ..Setup::default()
    });
    assert_eq!(world.tcp.storage_shape().unsolicited_syn_hold_slots(), 0);
}
