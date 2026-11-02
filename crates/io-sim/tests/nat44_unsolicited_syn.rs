//! RFC 5382 §5 REQ-4 through the full NAT + firewall + ICMPv4 error worker:
//! an unsolicited inbound SYN is dropped silently, held for at least 6 s,
//! dropped silently for good if an outbound SYN for the same connection is
//! translated meanwhile (simultaneous open), and otherwise answered with
//! exactly one ICMP Destination Unreachable, Port Unreachable (Type 3,
//! Code 3) quoting the held SYN (NAT44-038, NAT44-069..NAT44-079). With a
//! firewall bound, only SYNs it would admit as new flows to every inside
//! destination are held and answered (REQ-4 a).

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
    NAT44_TCP_UNSOLICITED_SYN_CLOCK_MARGIN_MS, NAT44_TCP_UNSOLICITED_SYN_HOLD_MS,
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
/// Ticks after the capture tick at which a hold matures: the 6 s REQ-4
/// minimum plus the clock-granularity margin (nothing at `HOLD - 1`, the
/// ICMP at `HOLD`).
const HOLD: u64 = NAT44_TCP_UNSOLICITED_SYN_HOLD_MS + NAT44_TCP_UNSOLICITED_SYN_CLOCK_MARGIN_MS;
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
    rule_with(
        id,
        ingress,
        FirewallInterface::Interface(egress),
        prefix(Ipv4Address::from_octets([0; 4]), 0),
        destination,
        FirewallAction::AllowStateful,
    )
}

fn rule_with(
    id: u32,
    ingress: IfId,
    egress: FirewallInterface,
    source: FirewallIpv4Prefix,
    destination: FirewallIpv4Prefix,
    action: FirewallAction,
) -> FirewallRule {
    FirewallRule::new(
        FirewallRuleId(id),
        FirewallInterface::Interface(ingress),
        egress,
        source,
        destination,
        FirewallProtocol::Tcp,
        FirewallPortRange::new(0, u16::MAX).unwrap(),
        FirewallPortRange::new(1, u16::MAX).unwrap(),
        action,
    )
}

/// The firewall's policy for new outside -> inside TCP flows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Inbound {
    /// Default deny: no inbound rule.
    Denied,
    /// Allow WAN -> LAN to every inside address and port.
    AllowAll,
    /// Allow WAN -> any egress to every inside address and port.
    AllowAnyEgress,
    /// Allow WAN -> LAN to `HOST` only (narrower than every destination).
    AllowHostOnly,
    /// Deny everything from `REMOTE1`, then allow WAN -> LAN to all.
    DenyRemote1,
}

fn firewall_rules(inbound: Inbound) -> &'static [FirewallRule] {
    let any = prefix(Ipv4Address::from_octets([0; 4]), 0);
    let mut rules = vec![rule(20, LAN, WAN, any)];
    match inbound {
        Inbound::Denied => {}
        Inbound::AllowAll => rules.push(rule(40, WAN, LAN, any)),
        Inbound::AllowAnyEgress => rules.push(rule_with(
            40,
            WAN,
            FirewallInterface::Any,
            any,
            any,
            FirewallAction::AllowStateful,
        )),
        Inbound::AllowHostOnly => rules.push(rule(40, WAN, LAN, prefix(HOST, 32))),
        Inbound::DenyRemote1 => {
            rules.push(rule_with(
                30,
                WAN,
                FirewallInterface::Any,
                prefix(REMOTE1, 32),
                any,
                FirewallAction::Deny,
            ));
            rules.push(rule(40, WAN, LAN, any));
        }
    }
    Box::leak(rules.into_boxed_slice())
}

/// How a test world is built.
#[derive(Clone, Copy)]
struct Setup {
    filtering: Nat44Filtering,
    unsolicited_syn_icmp: bool,
    holds: usize,
    sessions: usize,
    /// The firewall's policy for new outside -> inside TCP flows.
    inbound: Inbound,
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
            inbound: Inbound::AllowAll,
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

fn firewall_config(
    snapshot: &'static ForwardingSnapshot<'static>,
    inbound: Inbound,
    generation: u64,
) -> FirewallConfig<'static> {
    FirewallConfig::new(
        snapshot,
        firewall_rules(inbound),
        FirewallPolicy::default(),
        generation,
        FirewallHashKey::new(0x0123_4567_89ab_cdef ^ generation, 0xfedc_ba98_7654_3210).unwrap(),
    )
    .unwrap()
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
        let firewall_config = firewall_config(snapshot, setup.inbound, 1);
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

    /// Replaces the firewall rules in place (a firewall-only reconcile that
    /// keeps every TCP NAT hold), as a reload that changed only the rules
    /// would if holds survived it.
    fn set_inbound(&mut self, inbound: Inbound, generation: u64) {
        self.firewall_config = firewall_config(self.snapshot, inbound, generation);
        self.firewall.reconcile(self.firewall_config).unwrap();
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
            Some(&self.firewall_config),
            Some(&mut self.firewall),
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
/// once, still silent 1 ms before the hold (6 s plus the clock margin)
/// ends, then exactly one ICMP Port Unreachable quoting the original SYN;
/// never a second one.
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
        world.packet(LAN, tcp(HOST, REMOTE1, PORT, 443, SYN), HOLD - 1);
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
/// reception), and the one ICMP still quotes the original SYN (same
/// sequence number). A SYN with a new sequence number from the same remote
/// port (a reconnect) also restarts the hold but replaces the quote, so the
/// ICMP quotes the SYN the peer is now waiting on.
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

    let mut world = World::new(Setup::default());
    let first = tcp_with(REMOTE1, PUBLIC, (443, PORT), SYN, 1, 0);
    let reconnect = with_sequence(
        tcp_with(REMOTE1, PUBLIC, (443, PORT), SYN, 2, 0x08),
        0x2000_0000,
    );
    world.packet(WAN, first.clone(), 0);
    world.expect_drop(DropReason::Nat44TcpMappingMiss, &first);
    world.packet(WAN, reconnect.clone(), 1_000);
    world.expect_drop(DropReason::Nat44TcpMappingMiss, &reconnect);
    assert_eq!(world.counters().unsolicited_syn_refreshed, 1);
    assert!(world.tick(1_000 + HOLD - 1, 16).is_empty());
    let emitted = world.tick(1_000 + HOLD, 16);
    assert_eq!(emitted, [(WAN, port_unreachable(REMOTE1, &reconnect))]);
}

/// `frame` with TCP sequence number `sequence` (checksum recomputed).
fn with_sequence(mut frame: Vec<u8>, sequence: u32) -> Vec<u8> {
    frame[38..42].copy_from_slice(&sequence.to_be_bytes());
    frame[50..52].copy_from_slice(&[0, 0]);
    let source = Ipv4Address::from_octets(frame[26..30].try_into().unwrap());
    let destination = Ipv4Address::from_octets(frame[30..34].try_into().unwrap());
    let checksum = tcp_checksum(source, destination, &frame[34..54]);
    frame[50..52].copy_from_slice(&checksum.to_be_bytes());
    frame
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
    // The two held SYNs are answered (1 s apart: the Port Unreachable
    // limiter), the refused one never.
    assert_eq!(world.tick(HOLD, 1).len(), 1);
    assert_eq!(world.tick(HOLD + 1_000, 1).len(), 1);
    assert!(world.tick(HOLD + 10_000, 16).is_empty());
    assert_eq!(world.counters().unsolicited_syn_icmp_queued, 2);
}

/// Rate limit and anti-amplification: matured holds go through the Port
/// Unreachable limiter class (one queued error per egress, then
/// `port-unreachable-interval-ms`, default 1 s). A hold the limiter refuses
/// is retired, never retried, so a hold produces at most one ICMP and a
/// flood of N SYNs at most N, and at most one per second per egress.
#[test]
fn matured_holds_are_rate_limited_and_never_retried() {
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
    // The last Port Unreachable left at HOLD: the next ones are refused
    // until 1 s after the last one that left.
    for (received, remote_port) in [(7_000, 3000), (7_500, 3001), (8_000, 3002)] {
        world.packet(WAN, tcp(REMOTE2, PUBLIC, remote_port, PORT, SYN), received);
        assert!(world.io.pop_recycled().is_some());
    }
    for (matured, answered) in [
        (7_000 + HOLD, true),
        (7_500 + HOLD, false),
        (8_000 + HOLD, true),
    ] {
        assert_eq!(
            world.tick(matured, 16).len(),
            usize::from(answered),
            "{matured}"
        );
    }
    assert_eq!(world.errors.counters().rate_limited, 1);
}

/// The Port Unreachable class never uses up the limiter of the other
/// kinds: right after a Port Unreachable on WAN, a Time Exceeded for a
/// packet from the WAN still goes out on WAN.
#[test]
fn port_unreachable_does_not_starve_other_icmp_errors_on_the_same_egress() {
    let mut world = World::new(Setup {
        filtering: Nat44Filtering::EndpointIndependent,
        inbound: Inbound::AllowAnyEgress,
        ..Setup::default()
    });
    world.packet(LAN, tcp(HOST, REMOTE1, PORT, 443, SYN), 0);
    world.expect_tx(WAN);
    let syn = tcp(REMOTE2, PUBLIC, 443, PORT + 1, SYN);
    world.packet(WAN, syn.clone(), 0);
    world.expect_drop(DropReason::Nat44TcpMappingMiss, &syn);
    assert_eq!(
        world.tick(HOLD, 16),
        [(WAN, port_unreachable(REMOTE2, &syn))]
    );
    // A transit SYN from the WAN back out of the WAN with TTL 1 (the
    // firewall admits WAN -> any egress) expires at the router: its Time
    // Exceeded leaves on WAN at once.
    let transit = Ipv4Address::from_octets([192, 0, 2, 99]);
    let mut expiring = tcp(REMOTE1, transit, 443, 80, SYN);
    expiring[22] = 1;
    expiring[24..26].copy_from_slice(&[0, 0]);
    let checksum = ipv4_header_checksum(&expiring[14..34]);
    expiring[24..26].copy_from_slice(&checksum.to_be_bytes());
    world.packet(WAN, expiring, HOLD);
    let recycled = world.io.pop_recycled().expect("dropped");
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::Ipv4TtlExpired)
    );
    let emitted = world.tick(HOLD, 16);
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0].0, WAN);
    assert_eq!(emitted[0].1[34], 11, "Time Exceeded");
    let errors = world.errors.counters();
    assert_eq!(
        (
            errors.dequeued_port_unreachable,
            errors.dequeued_time_exceeded
        ),
        (1, 1)
    );
    assert_eq!(errors.rate_limited, 0);
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

/// REQ-4 a and the firewall: a NAT refusal is held, and answered, only if
/// the bound firewall would admit the SYN as a new connection to every
/// inside destination. Default deny, an explicit deny for the source, and
/// an allow narrower than every inside destination all keep the silent
/// drop, so the ICMP never answers what the policy would refuse (and never
/// depends on whether a mapping exists). An allow to every destination,
/// toward the inside egress or any egress, admits it.
#[test]
fn the_firewall_policy_decides_whether_a_nat_refusal_is_answered() {
    for (inbound, remote, answered) in [
        (Inbound::Denied, REMOTE1, false),
        (Inbound::AllowHostOnly, REMOTE1, false),
        (Inbound::DenyRemote1, REMOTE1, false),
        (Inbound::DenyRemote1, REMOTE2, true),
        (Inbound::AllowAll, REMOTE1, true),
        (Inbound::AllowAnyEgress, REMOTE1, true),
    ] {
        // A mapping miss in every filtering mode, and a filter refusal
        // (the mapping talks to OTHER only) where the filtering refuses: the
        // outcome never depends on whether a mapping exists.
        let refusals = MODES
            .into_iter()
            .map(|filtering| (filtering, false))
            .chain([
                (Nat44Filtering::AddressDependent, true),
                (Nat44Filtering::AddressAndPortDependent, true),
            ]);
        for (filtering, mapped) in refusals {
            let mut world = World::new(Setup {
                filtering,
                inbound,
                ..Setup::default()
            });
            let reason = if mapped {
                let other = Ipv4Address::from_octets([203, 0, 113, 77]);
                world.packet(LAN, tcp(HOST, other, PORT, 9, SYN), 0);
                world.expect_tx(WAN);
                DropReason::Nat44TcpSessionMiss
            } else {
                DropReason::Nat44TcpMappingMiss
            };
            let miss = tcp(remote, PUBLIC, 443, PORT, SYN);
            let mut trace = Recorder::default();
            world.packet_traced(WAN, miss.clone(), 1, &mut trace);
            world.expect_drop(reason, &miss);
            let emitted = world.tick(1 + HOLD, 16);
            let counters = world.counters();
            if answered {
                assert_eq!(
                    emitted,
                    [(WAN, port_unreachable(remote, &miss))],
                    "{inbound:?} {filtering:?}"
                );
                assert_eq!(counters.unsolicited_syn_firewall_denied, 0);
            } else {
                assert!(emitted.is_empty(), "{inbound:?} {filtering:?}");
                assert_eq!(
                    trace.0,
                    [Nat44TcpUnsolicitedSynDisposition::FirewallDenied { public_port: PORT }]
                );
                assert_eq!(counters.unsolicited_syn_held, 0);
                assert_eq!(counters.unsolicited_syn_firewall_denied, 1);
                assert_eq!(world.errors.counters().queued, 0);
            }
        }
    }
}

/// A bound firewall config without its runtime, or with a runtime that
/// belongs to another config, fails closed at maturity: no ICMP.
#[test]
fn an_unusable_firewall_fails_closed_at_maturity() {
    for runtime_present in [false, true] {
        let mut world = World::new(Setup::default());
        let syn = tcp(REMOTE1, PUBLIC, 443, PORT, SYN);
        world.packet(WAN, syn.clone(), 0);
        world.expect_drop(DropReason::Nat44TcpMappingMiss, &syn);
        // A newer config (generation 2) the runtime was never reconciled to.
        let other = firewall_config(world.snapshot, Inbound::AllowAll, 2);
        let report = dispatch_nat44_tcp_unsolicited_syns(
            &mut world.tcp,
            &mut world.errors,
            &mut world.resolution,
            world.snapshot,
            Some(&other),
            runtime_present.then_some(&mut world.firewall),
            MonotonicMillis(HOLD),
            16,
            &mut NoTrace,
        )
        .unwrap();
        assert_eq!(report.firewall_denied, 1, "{runtime_present}");
        assert_eq!(report.queued, 0);
        assert_eq!(world.errors.pending_actions(), 0);
        assert_eq!(world.counters().unsolicited_syn_firewall_denied, 1);
    }
}

/// Firewall order: the NAT decides first. A SYN the NAT filter admits but
/// the firewall denies is the firewall's silent `FIREWALL_DEFAULT_DENIED`
/// and is never held.
#[test]
fn firewall_denials_of_admitted_syns_are_not_held() {
    let mut world = World::new(Setup {
        filtering: Nat44Filtering::EndpointIndependent,
        inbound: Inbound::Denied,
        ..Setup::default()
    });
    world.packet(LAN, tcp(HOST, REMOTE1, PORT, 80, SYN), 1);
    world.expect_tx(WAN);
    let denied = tcp(REMOTE2, PUBLIC, 443, PORT, SYN);
    world.packet(WAN, denied.clone(), 2);
    world.expect_drop(DropReason::FirewallDefaultDenied, &denied);
    let counters = world.counters();
    assert_eq!(
        (
            counters.unsolicited_syn_held,
            counters.unsolicited_syn_firewall_denied
        ),
        (0, 0)
    );
    assert!(world.tick(HOLD + 2, 16).is_empty());
}

/// The firewall is re-checked when a hold matures: rules that deny the SYN
/// by then silence it, and rules that still admit it let it through.
#[test]
fn a_firewall_change_during_the_hold_is_honoured_at_maturity() {
    for (later, answered) in [
        (Inbound::Denied, false),
        (Inbound::DenyRemote1, false),
        (Inbound::AllowHostOnly, false),
        (Inbound::AllowAnyEgress, true),
    ] {
        let mut world = World::new(Setup::default());
        let syn = tcp(REMOTE1, PUBLIC, 443, PORT, SYN);
        world.packet(WAN, syn.clone(), 0);
        world.expect_drop(DropReason::Nat44TcpMappingMiss, &syn);
        assert_eq!(world.tcp.unsolicited_syn_holds(), 1);
        world.set_inbound(later, 2);
        assert_eq!(world.tcp.unsolicited_syn_holds(), 1, "the NAT keeps it");
        let mut trace = Recorder::default();
        let emitted = world.tick_traced(HOLD, 16, &mut trace);
        if answered {
            assert_eq!(emitted, [(WAN, port_unreachable(REMOTE1, &syn))]);
        } else {
            assert!(emitted.is_empty(), "{later:?}");
            assert_eq!(
                trace.0,
                [Nat44TcpUnsolicitedSynDisposition::FirewallDenied { public_port: PORT }]
            );
            assert_eq!(world.counters().unsolicited_syn_firewall_denied, 1);
            assert_eq!(world.tcp.unsolicited_syn_holds(), 0, "retired, not retried");
            assert!(world.tick(10 * HOLD, 16).is_empty());
        }
    }
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
    assert_eq!(NAT44_TCP_UNSOLICITED_SYN_HOLD_MS, 6_000);
    assert_eq!(NAT44_TCP_UNSOLICITED_SYN_CLOCK_MARGIN_MS, 2);
    assert_eq!(HOLD, 6_002);
    let world = World::new(Setup {
        holds: 0,
        ..Setup::default()
    });
    assert_eq!(world.tcp.storage_shape().unsolicited_syn_hold_slots(), 0);
}
