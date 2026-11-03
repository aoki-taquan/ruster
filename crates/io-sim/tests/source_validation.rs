//! URPF: per-interface IPv4 source address validation (RFC 1812 §5.3.8,
//! RFC 3704, RFC 2827) through the validated config, the publication,
//! `run_tick`, and SimIo (fixtures/urpf/router.toml: LAN 192.168.1.0/24
//! with H 192.168.1.10, 10.0.0.0/8 behind the LAN gateway 192.168.1.254,
//! UDP/TCP/ICMP NAPT on WAN 203.0.113.2, a default route via the WAN
//! gateway G 203.0.113.1, a stateful firewall).
//!
//! Every frame is built here from RFC 791/768/792 with this file's own
//! checksum, independently of the router.

use ruster_config::{parse, validate, ValidatedConfig, PRODUCTION_VALIDATION_LIMITS};
use ruster_control::{
    ActivePublication, FullServiceStorage, PublicationSequencer, SimDeterministicKeySource,
};
use ruster_core::{
    forward_batch, forward_batch_with_resolution_and_icmpv4_errors, ConsumeReason, DropReason,
    ForwardingSnapshot, Icmpv4ErrorActionSlot, Icmpv4ErrorCounters, Icmpv4ErrorPolicy,
    Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address, Ipv4OriginPolicy,
    LocalIpv4Binding, MacAddress, MonotonicMillis, Neighbor, PacketIo, ResolutionActionSlot,
    ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, Route, SnapshotError,
    SourceValidation, SourceValidationBinding, TraceEvent, ValidatedForwardingOwner,
    ValidatedForwardingOwnerError,
};
use ruster_io_sim::{RecycleCause, SimIo, TxFrame, VecTrace};
use ruster_runtime::{run_tick, PublicationOutcome, TickBudgets, TickObserver};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const H_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];
const G_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
const BROADCAST: [u8; 6] = [0xff; 6];
const LAN_IP: [u8; 4] = [192, 168, 1, 1];
const PUBLIC: [u8; 4] = [203, 0, 113, 2];
const H: [u8; 4] = [192, 168, 1, 10];
const G: [u8; 4] = [203, 0, 113, 1];
/// An Internet host: only the default route covers it.
const X: [u8; 4] = [192, 0, 2, 77];
/// A host behind the LAN gateway (10.0.0.0/8 via LAN).
const BEHIND_LAN: [u8; 4] = [10, 1, 2, 3];
const DF: u16 = 0x4000;
const MF: u16 = 0x2000;
const ROUTER: &str = include_str!("../../../fixtures/urpf/router.toml");

// ------------------------------------------------------------ builders ----

/// RFC 1071 one's-complement checksum, independent of the router's.
fn sum16(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ethernet(destination: [u8; 6], source: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// RFC 791 header (IHL 5) and `payload`.
fn ipv4(
    source: [u8; 4],
    destination: [u8; 4],
    id: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(&u16::try_from(20 + payload.len()).unwrap().to_be_bytes());
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&flags_fragment.to_be_bytes());
    packet.extend_from_slice(&[ttl, protocol, 0, 0]);
    packet.extend_from_slice(&source);
    packet.extend_from_slice(&destination);
    let checksum = sum16(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// RFC 768 datagram with its checksum.
fn udp(source: [u8; 4], destination: [u8; 4], ports: (u16, u16), payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&ports.0.to_be_bytes());
    segment.extend_from_slice(&ports.1.to_be_bytes());
    segment.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&source);
    pseudo.extend_from_slice(&destination);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&u16::try_from(segment.len()).unwrap().to_be_bytes());
    pseudo.extend_from_slice(&segment);
    let checksum = match sum16(&pseudo) {
        0 => 0xffff,
        sum => sum,
    };
    segment[6..8].copy_from_slice(&checksum.to_be_bytes());
    segment
}

/// RFC 792 Echo (type 8) or Echo Reply (type 0).
fn icmp_echo(kind: u8, identifier: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut message = vec![kind, 0, 0, 0];
    message.extend_from_slice(&identifier.to_be_bytes());
    message.extend_from_slice(&sequence.to_be_bytes());
    message.extend_from_slice(data);
    let checksum = sum16(&message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    message
}

/// An IPv4 frame received on the WAN from G's MAC with any `source`.
fn on_wan(source: [u8; 4], destination: [u8; 4], ttl: u8, protocol: u8, l4: &[u8]) -> Vec<u8> {
    ethernet(
        WAN_MAC,
        G_MAC,
        0x0800,
        &ipv4(source, destination, 0x0505, DF, ttl, protocol, l4),
    )
}

/// An IPv4 frame received on the LAN from H's MAC with any `source`.
fn on_lan(source: [u8; 4], destination: [u8; 4], ttl: u8, protocol: u8, l4: &[u8]) -> Vec<u8> {
    ethernet(
        LAN_MAC,
        H_MAC,
        0x0800,
        &ipv4(source, destination, 0x0606, DF, ttl, protocol, l4),
    )
}

/// The Echo Request `source` -> the router's WAN address, on the WAN.
fn ping_wan(source: [u8; 4]) -> Vec<u8> {
    on_wan(source, PUBLIC, 64, 1, &icmp_echo(8, 0x77, 1, b"urpf"))
}

/// The router's Echo Reply to `source`: an in-place answer out of the WAN
/// (the ingress) to the sender's MAC, G's (ICMP4-001).
fn pong(source: [u8; 4]) -> Vec<u8> {
    ethernet(
        G_MAC,
        WAN_MAC,
        0x0800,
        &ipv4(
            PUBLIC,
            source,
            0,
            DF,
            64,
            1,
            &icmp_echo(0, 0x77, 1, b"urpf"),
        ),
    )
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

// --------------------------------------------------------------- world ----

/// The fixture with `lan`/`wan` modes (`None` keeps the fixture's `off`)
/// and the optional allow-default switch on the WAN.
fn router(lan: &str, wan: &str, wan_allow_default: bool) -> String {
    let lan_line = format!("mac = \"02:00:00:00:00:01\"\nsource-validation = \"{lan}\"\n");
    let mut wan_line = format!("mac = \"02:00:00:00:00:02\"\nsource-validation = \"{wan}\"\n");
    if wan_allow_default {
        wan_line.push_str("source-validation-allow-default = true\n");
    }
    ROUTER
        .replacen(
            "mac = \"02:00:00:00:00:01\"\nsource-validation = \"off\"\n",
            &lan_line,
            1,
        )
        .replacen(
            "mac = \"02:00:00:00:00:02\"\nsource-validation = \"off\"\n",
            &wan_line,
            1,
        )
}

fn validated(text: &str) -> ruster_config::ValidatedConfigV1 {
    let ValidatedConfig::V1(config) = validate(
        parse(text.as_bytes()).expect("parse"),
        PRODUCTION_VALIDATION_LIMITS,
    )
    .expect("valid") else {
        unreachable!("schema V1");
    };
    config
}

fn budgets() -> TickBudgets {
    TickBudgets {
        rx: 32,
        resolution_timer_scans: 16,
        failure_dispatch_scans: 16,
        generated_arp: 8,
        generated_icmpv4: 8,
        generated_fragments: 64,
    }
}

struct World {
    active: ActivePublication<'static, SimIo>,
    sequencer: PublicationSequencer<SimDeterministicKeySource>,
    io: SimIo,
    observer: TickObserver,
    now: u64,
}

impl World {
    fn new(text: &str) -> Self {
        let config = validated(text);
        let mut sequencer = PublicationSequencer::new(SimDeterministicKeySource::new(7));
        let candidate = sequencer.candidate(&config).expect("candidate");
        let storage = Box::leak(Box::new(
            FullServiceStorage::new(candidate.storage_shape()).expect("storage"),
        ));
        let active = ActivePublication::<SimIo>::new(storage, candidate).expect("activates");
        Self {
            active,
            sequencer,
            io: SimIo::new(),
            observer: TickObserver::default(),
            now: 0,
        }
    }

    /// Injects `frames` and runs one tick at `now`; returns the frames sent.
    fn tick(&mut self, now: u64, frames: &[(IfId, Vec<u8>)]) -> Vec<TxFrame> {
        self.now = now;
        for (ingress, frame) in frames {
            self.io.inject(*ingress, frame.clone());
        }
        let report = run_tick(
            &mut self.active,
            None,
            &mut self.io,
            MonotonicMillis(now),
            budgets(),
            &mut self.observer,
        );
        self.observer.observe_tick(
            MonotonicMillis(now),
            Some(self.active.generation()),
            &report,
        );
        while self.io.pop_recycled().is_some() {}
        std::iter::from_fn(|| self.io.pop_tx()).collect()
    }

    /// Applies `text` as a new generation (a reload) in a tick at `now`.
    fn apply(&mut self, now: u64, text: &str) {
        self.now = now;
        let candidate = self
            .sequencer
            .candidate(&validated(text))
            .expect("candidate");
        let report = run_tick(
            &mut self.active,
            Some(candidate),
            &mut self.io,
            MonotonicMillis(now),
            budgets(),
            &mut self.observer,
        );
        assert!(
            matches!(report.publication, PublicationOutcome::Applied),
            "{:?}",
            report.publication
        );
        self.observer.observe_tick(
            MonotonicMillis(now),
            Some(self.active.generation()),
            &report,
        );
    }

    fn drops(&self, reason: DropReason) -> u64 {
        self.observer
            .snapshot(MonotonicMillis(self.now))
            .drops
            .count(reason)
    }

    fn consumed(&self, reason: ConsumeReason) -> u64 {
        self.observer
            .snapshot(MonotonicMillis(self.now))
            .consumes
            .count(reason)
    }

    fn urpf_drops(&self) -> u64 {
        self.drops(DropReason::Ipv4SourceValidationFailed)
    }
}

fn bytes(frames: &[TxFrame]) -> Vec<(IfId, Vec<u8>)> {
    frames
        .iter()
        .map(|frame| (frame.egress, frame.bytes.clone()))
        .collect()
}

// --------------------------------------------------------------- tests ----

/// RFC 1812 §5.3.8 "If this feature is implemented, it MUST be disabled by
/// default": without the key (and with `off`) nothing is validated, so a
/// datagram claiming an inside source on the WAN is answered as before.
#[test]
fn source_validation_is_off_by_default() {
    let absent = ROUTER.replace("source-validation = \"off\"\n", "");
    assert!(!absent.contains("\nsource-validation"));
    for text in [absent.as_str(), ROUTER] {
        let config = validated(text);
        assert!(config.source_validation().is_empty());
        let mut world = World::new(text);
        let sent = world.tick(0, &[(WAN, ping_wan(H))]);
        assert_eq!(bytes(&sent), [(WAN, pong(H))]);
        assert_eq!(world.urpf_drops(), 0);
    }
}

/// Strict on the WAN (RFC 1812 §5.3.8, RFC 3704 §2.2): an inside source
/// arriving on the WAN is silently discarded, with no reply and no ICMP
/// error, while an Internet source whose only route is the default route
/// out of the WAN passes.
#[test]
fn strict_drops_a_spoofed_inside_source_and_passes_the_default_route() {
    let mut world = World::new(&router("off", "strict", false));
    let sent = world.tick(0, &[(WAN, ping_wan(H))]);
    assert!(sent.is_empty(), "{sent:?}");
    assert_eq!(world.urpf_drops(), 1);

    let sent = world.tick(10, &[(WAN, ping_wan(X))]);
    assert_eq!(bytes(&sent), [(WAN, pong(X))]);
    assert_eq!(world.urpf_drops(), 1);
}

/// Asymmetric routing: 10.0.0.0/8 is routed out of the LAN, so a source in
/// it arriving on the WAN fails strict (the best route back is not the
/// ingress) but passes loose (it has a route other than the default).
#[test]
fn asymmetric_routing_fails_strict_and_passes_loose() {
    let mut strict = World::new(&router("off", "strict", false));
    let sent = strict.tick(0, &[(WAN, ping_wan(BEHIND_LAN))]);
    assert!(sent.is_empty(), "{sent:?}");
    assert_eq!(strict.urpf_drops(), 1);

    for allow_default in [false, true] {
        let mut loose = World::new(&router("off", "loose", allow_default));
        let sent = loose.tick(0, &[(WAN, ping_wan(BEHIND_LAN))]);
        assert_eq!(bytes(&sent), [(WAN, pong(BEHIND_LAN))]);
        assert_eq!(loose.urpf_drops(), 0);
    }
}

/// Loose ignores default routes (RFC 3704 §2.5), so on a WAN whose only
/// route back to the Internet is the default route it drops every Internet
/// source; `source-validation-allow-default` restores RFC 3704 §2.4.
#[test]
fn loose_ignores_the_default_route_unless_allowed() {
    let mut loose = World::new(&router("off", "loose", false));
    assert!(loose.tick(0, &[(WAN, ping_wan(X))]).is_empty());
    assert_eq!(loose.urpf_drops(), 1);

    let mut allowed = World::new(&router("off", "loose", true));
    let sent = allowed.tick(0, &[(WAN, ping_wan(X))]);
    assert_eq!(bytes(&sent), [(WAN, pong(X))]);
    assert_eq!(allowed.urpf_drops(), 0);
}

/// Strict on the LAN is RFC 2827 ingress filtering of the inside network:
/// H (connected) passes, a LAN datagram claiming an Internet source does
/// not leave.
#[test]
fn strict_on_the_lan_filters_spoofed_outbound_sources() {
    let mut world = World::new(&router("strict", "off", false));
    let query = |source| on_lan(source, X, 64, 17, &udp(source, X, (5000, 53), b"q"));
    let sent = world.tick(0, &[(LAN, query(X))]);
    assert!(sent.is_empty(), "{sent:?}");
    assert_eq!(world.urpf_drops(), 1);
    assert_eq!(
        world.active.nat44_udp().occupancy().mappings.occupied(),
        0,
        "nothing commits before the check"
    );
    let sent = world.tick(10, &[(LAN, query(H))]);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].egress, WAN);
    assert_eq!(world.urpf_drops(), 1);
}

/// NAT: with strict on both sides, the outbound query is translated and the
/// Internet host's answer to the public address passes the WAN check (its
/// best route back is the default route out of the WAN) and reaches H.
#[test]
fn nat_answers_to_the_public_address_pass_strict_on_the_wan() {
    let mut world = World::new(&router("strict", "strict", false));
    let query = on_lan(H, X, 64, 17, &udp(H, X, (5000, 53), b"query"));
    let sent = world.tick(0, &[(LAN, query)]);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let port = u16_at(&sent[0].bytes, 34);
    assert!((40_000..=40_015).contains(&port));

    let answer = on_wan(X, PUBLIC, 60, 17, &udp(X, PUBLIC, (53, port), b"answer"));
    let sent = world.tick(10, &[(WAN, answer)]);
    assert_eq!(
        bytes(&sent),
        [(
            LAN,
            ethernet(
                H_MAC,
                LAN_MAC,
                0x0800,
                &ipv4(X, H, 0x0505, DF, 59, 17, &udp(X, H, (53, 5000), b"answer"))
            )
        )]
    );
    // A spoofed inside source sending to the public address is dropped
    // before the NAT lookup.
    let spoofed = on_wan(H, PUBLIC, 60, 17, &udp(H, PUBLIC, (53, port), b"spoof"));
    assert!(world.tick(20, &[(WAN, spoofed)]).is_empty());
    assert_eq!(world.urpf_drops(), 1);
}

/// A reload switches the mode in place (reloadable, no restart): off, then
/// strict, then off again, with the same frame.
#[test]
fn a_reload_changes_the_mode_in_place() {
    let mut world = World::new(ROUTER);
    assert_eq!(world.tick(0, &[(WAN, ping_wan(H))]).len(), 1);
    world.apply(10, &router("off", "strict", false));
    assert!(world.tick(20, &[(WAN, ping_wan(H))]).is_empty());
    assert_eq!(world.urpf_drops(), 1);
    world.apply(30, &router("off", "loose", false));
    assert_eq!(world.tick(40, &[(WAN, ping_wan(H))]).len(), 1);
    world.apply(50, ROUTER);
    assert_eq!(world.tick(60, &[(WAN, ping_wan(BEHIND_LAN))]).len(), 1);
    assert_eq!(world.urpf_drops(), 1);
}

/// NAT-FRAG: every fragment is checked on its own (they share the source),
/// so a spoofed later fragment that arrives first is dropped before it can
/// take a held slot, and a spoofed first fragment leaves no association.
#[test]
fn spoofed_fragments_are_dropped_before_the_association_table() {
    let mut world = World::new(&router("off", "strict", false));
    let later = ethernet(
        WAN_MAC,
        G_MAC,
        0x0800,
        &ipv4(H, PUBLIC, 0x0909, 185, 64, 17, &[0; 16]),
    );
    let first = ethernet(
        WAN_MAC,
        G_MAC,
        0x0800,
        &ipv4(H, PUBLIC, 0x0909, MF, 64, 17, &[0; 24]),
    );
    assert!(world.tick(0, &[(WAN, later), (WAN, first)]).is_empty());
    assert_eq!(world.urpf_drops(), 2);
    assert_eq!(world.consumed(ConsumeReason::Ipv4FragmentHeld), 0);
    assert_eq!(
        world
            .active
            .fragment_tracking()
            .map_or((0, 0), |tracker| (tracker.entries(), tracker.held())),
        (0, 0)
    );
}

/// The martian checks keep their own reasons ahead of URPF: a directed
/// broadcast source is IPV4_SOURCE_DIRECTED_BROADCAST, and a valid source
/// sending to a directed broadcast passes URPF and is refused as
/// IPV4_DESTINATION_DIRECTED_BROADCAST.
#[test]
fn martian_and_directed_broadcast_reasons_precede_urpf() {
    let mut world = World::new(&router("strict", "strict", false));
    let directed = [192, 168, 1, 255];
    world.tick(
        0,
        &[
            (
                WAN,
                on_wan(directed, PUBLIC, 64, 1, &icmp_echo(8, 1, 1, b"")),
            ),
            (WAN, on_wan(X, directed, 64, 1, &icmp_echo(8, 1, 1, b""))),
        ],
    );
    assert_eq!(world.drops(DropReason::Ipv4SourceDirectedBroadcast), 1);
    assert_eq!(world.drops(DropReason::Ipv4DestinationDirectedBroadcast), 1);
    assert_eq!(world.urpf_drops(), 0);
}

/// ARP-HOLD: the check runs when the datagram is received. A replay
/// decides the held datagram again against the same snapshot (a
/// publication apply drops every hold), so it passes again: H's datagram
/// to an unresolved LAN next hop is held and sent with strict on the LAN,
/// and a spoofed one is never held.
#[test]
fn arp_hold_replays_pass_and_spoofed_datagrams_are_never_held() {
    let text = router("strict", "off", false).replacen(
        "[[neighbors]]\ninterface = \"wan\"\naddress = \"203.0.113.1\"\nmac = \"02:00:00:00:00:fe\"\n",
        "",
        1,
    );
    let mut world = World::new(&text);
    let echo = icmp_echo(8, 0x1234, 1, b"held");
    let sent = world.tick(
        0,
        &[
            (LAN, on_lan(X, [198, 51, 100, 20], 64, 1, &echo)),
            (LAN, on_lan(H, X, 64, 1, &echo)),
        ],
    );
    let request = {
        let mut body = vec![0, 1, 8, 0, 6, 4, 0, 1];
        body.extend_from_slice(&WAN_MAC);
        body.extend_from_slice(&PUBLIC);
        body.extend_from_slice(&[0; 6]);
        body.extend_from_slice(&G);
        body.resize(46, 0);
        ethernet(BROADCAST, WAN_MAC, 0x0806, &body)
    };
    assert_eq!(bytes(&sent), [(WAN, request)]);
    assert_eq!(world.urpf_drops(), 1, "an Internet source on the LAN");
    assert_eq!(world.consumed(ConsumeReason::ArpHeld), 1);

    let reply = {
        let mut body = vec![0, 1, 8, 0, 6, 4, 0, 2];
        body.extend_from_slice(&G_MAC);
        body.extend_from_slice(&G);
        body.extend_from_slice(&WAN_MAC);
        body.extend_from_slice(&PUBLIC);
        body.resize(46, 0);
        ethernet(WAN_MAC, G_MAC, 0x0806, &body)
    };
    let sent = world.tick(10, &[(WAN, reply)]);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].egress, WAN);
    let counters = world.active.arp_hold().expect("holding is on").counters();
    assert_eq!(
        (counters.held, counters.replay_sent, counters.replay_dropped),
        (1, 1, 0)
    );
    assert_eq!(world.urpf_drops(), 1);
}

// ------------------------------------------------- core-level contracts ----

fn core_interfaces() -> [Interface; 2] {
    [
        Interface {
            id: LAN,
            mac: MacAddress(LAN_MAC),
            mtu: 1500,
        },
        Interface {
            id: WAN,
            mac: MacAddress(WAN_MAC),
            mtu: 1500,
        },
    ]
}

fn core_routes() -> [Route; 3] {
    [
        Route::new(Ipv4Address::from_octets([192, 168, 1, 0]), 24, LAN, None).unwrap(),
        Route::new(Ipv4Address::from_octets([203, 0, 113, 0]), 24, WAN, None).unwrap(),
        Route::new(
            Ipv4Address::from_octets([0, 0, 0, 0]),
            0,
            WAN,
            Some(Ipv4Address::from_octets(G)),
        )
        .unwrap(),
    ]
}

fn core_bindings() -> [LocalIpv4Binding; 2] {
    [
        LocalIpv4Binding {
            interface: LAN,
            address: Ipv4Address::from_octets(LAN_IP),
        },
        LocalIpv4Binding {
            interface: WAN,
            address: Ipv4Address::from_octets(PUBLIC),
        },
    ]
}

/// The drop is traced with its ingress, source, and mode, the frame is
/// recycled unchanged, and off costs nothing (an empty binding slice).
#[test]
fn the_drop_is_traced_with_its_source_and_mode() {
    let routes = core_routes();
    let interfaces = core_interfaces();
    let locals = core_bindings();
    let strict = [SourceValidationBinding {
        interface: WAN,
        mode: SourceValidation::Strict,
    }];
    let plain = ForwardingSnapshot::new(&routes, &interfaces, &[], &locals).unwrap();
    assert!(plain.source_validation_bindings().is_empty());
    let snapshot = plain.with_source_validation(&strict).unwrap();
    assert_eq!(snapshot.source_validation(WAN), SourceValidation::Strict);
    assert_eq!(snapshot.source_validation(LAN), SourceValidation::Off);

    let mut io = SimIo::new();
    let frame = ping_wan(H);
    io.inject(WAN, frame.clone());
    let mut trace = VecTrace::default();
    let report = forward_batch(io.receive(1).unwrap(), &snapshot, &mut trace);
    assert_eq!((report.dropped, report.tx_requested), (1, 0));
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::Ipv4SourceValidationFailed)
    );
    assert_eq!(recycled.bytes, frame);
    assert!(trace
        .events()
        .contains(&TraceEvent::Ipv4SourceValidationFailed {
            ingress: WAN,
            source: Ipv4Address::from_octets(H),
            mode: SourceValidation::Strict,
        }));
    assert!(trace.events().contains(&TraceEvent::Dropped {
        ingress: WAN,
        reason: DropReason::Ipv4SourceValidationFailed,
    }));
    assert_eq!(DropReason::Ipv4SourceValidationFailed as u16, 209);
    assert_eq!(
        DropReason::Ipv4SourceValidationFailed.code(),
        "IPV4_SOURCE_VALIDATION_FAILED"
    );
}

/// RFC 1812 §5.3.8 "silently discard", and the ICMP4-023/ICMP4-029 class 0
/// vector: without a NAT on the WAN address, a datagram on the WAN claiming
/// the inside host H as its source makes the router queue an error toward
/// H through the LAN egress's class 0 limiter: a Port Unreachable for UDP
/// to the router, a Parameter Problem for a truncated datagram, a Time
/// Exceeded for TTL 1. Strict on the WAN discards each silently, so none
/// is queued and the inside egress's class 0 stays free.
#[test]
fn strict_on_the_wan_closes_the_class_zero_vector() {
    let routes = core_routes();
    let interfaces = core_interfaces();
    let locals = core_bindings();
    let neighbors = [Neighbor {
        interface: LAN,
        target: Ipv4Address::from_octets(H),
        mac: MacAddress(H_MAC),
    }];
    let strict = [SourceValidationBinding {
        interface: WAN,
        mode: SourceValidation::Strict,
    }];
    let port_unreachable = on_wan(H, PUBLIC, 64, 17, &udp(H, PUBLIC, (1, 9), b"u"));
    let mut truncated = port_unreachable.clone();
    let claimed = u16_at(&truncated, 16) + 8;
    truncated[16..18].copy_from_slice(&claimed.to_be_bytes());
    truncated[24..26].fill(0);
    let checksum = sum16(&truncated[14..34]);
    truncated[24..26].copy_from_slice(&checksum.to_be_bytes());
    let elsewhere = [192, 168, 1, 20];
    let expiring = on_wan(H, elsewhere, 1, 17, &udp(H, elsewhere, (1, 9), b""));
    // Each frame alone: they would share the LAN egress's class 0 limiter.
    // A truncated datagram is still discarded as truncated: the check only
    // silences its Parameter Problem.
    for (frame, failing) in [
        (port_unreachable, DropReason::Ipv4SourceValidationFailed),
        (truncated, DropReason::Ipv4TotalLengthExceedsPacket),
        (expiring, DropReason::Ipv4SourceValidationFailed),
    ] {
        for (bindings, expected) in [(&[][..], 1), (&strict[..], 0)] {
            let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &locals)
                .unwrap()
                .with_source_validation(bindings)
                .unwrap();
            let mut rs = [ResolutionStateSlot::EMPTY; 2];
            let mut ra = [ResolutionActionSlot::EMPTY; 2];
            let mut resolution = ResolutionRuntime::new(
                ResolutionPolicy::new(1_000, 60_000).unwrap(),
                &mut rs,
                &mut ra,
            );
            let mut es = [Icmpv4ErrorStateSlot::EMPTY; 2];
            let mut ea = [Icmpv4ErrorActionSlot::EMPTY; 2];
            let mut errors =
                Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), &mut es, &mut ea);
            let mut io = SimIo::new();
            io.inject(WAN, frame.clone());
            let mut trace = VecTrace::default();
            let report = forward_batch_with_resolution_and_icmpv4_errors(
                io.receive(1).unwrap(),
                &snapshot,
                &mut resolution,
                &mut errors,
                MonotonicMillis(10),
                &mut trace,
            );
            assert_eq!(report.dropped, 1);
            let counters = errors.counters();
            let queued = counters.queued_udp_port_unreachable
                + counters.queued_parameter_problem
                + counters.queued_time_exceeded;
            assert_eq!(queued, expected, "{bindings:?}");
            if expected == 0 {
                assert_eq!(counters, Icmpv4ErrorCounters::default());
                assert_eq!(
                    io.pop_recycled().unwrap().cause,
                    RecycleCause::Forwarding(failing)
                );
            }
        }
    }
}

/// Owner bindings come in any order and drop `off`; the borrowed form must
/// be sorted. Unknown or repeated interfaces are refused either way.
#[test]
fn bindings_are_validated_and_normalized() {
    let routes = core_routes();
    let interfaces = core_interfaces();
    let locals = core_bindings();
    let binding = |interface, mode| SourceValidationBinding { interface, mode };
    let owner = ValidatedForwardingOwner::new(
        routes.into(),
        interfaces.into(),
        Box::default(),
        locals.into(),
        Ipv4OriginPolicy::default(),
    )
    .unwrap()
    .with_source_validation(&[
        binding(WAN, SourceValidation::Loose),
        binding(LAN, SourceValidation::Off),
    ])
    .unwrap();
    assert_eq!(
        owner.source_validation(),
        [binding(WAN, SourceValidation::Loose)]
    );
    let snapshot = owner.snapshot();
    assert_eq!(snapshot.source_validation(WAN), SourceValidation::Loose);
    assert_eq!(snapshot.source_validation(LAN), SourceValidation::Off);

    for (bindings, error) in [
        (
            vec![binding(IfId(9), SourceValidation::Strict)],
            SnapshotError::SourceValidationUnknownInterface,
        ),
        (
            vec![
                binding(LAN, SourceValidation::Strict),
                binding(LAN, SourceValidation::Loose),
            ],
            SnapshotError::DuplicateSourceValidation,
        ),
    ] {
        let owner = ValidatedForwardingOwner::new(
            routes.into(),
            interfaces.into(),
            Box::default(),
            locals.into(),
            Ipv4OriginPolicy::default(),
        )
        .unwrap();
        assert_eq!(
            owner.with_source_validation(&bindings).unwrap_err(),
            ValidatedForwardingOwnerError::Snapshot(error)
        );
        let borrowed = ForwardingSnapshot::new(&routes, &interfaces, &[], &locals).unwrap();
        assert_eq!(
            borrowed.with_source_validation(&bindings).unwrap_err(),
            error
        );
    }
    let unsorted = [
        binding(WAN, SourceValidation::Strict),
        binding(LAN, SourceValidation::Strict),
    ];
    let borrowed = ForwardingSnapshot::new(&routes, &interfaces, &[], &locals).unwrap();
    assert_eq!(
        borrowed.with_source_validation(&unsorted).unwrap_err(),
        SnapshotError::SourceValidationUnsorted
    );
}
