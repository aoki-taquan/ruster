//! ARP-HOLD (RFC 1122 §2.3.2.2, RFC 1812 §3.3.2): a datagram whose next
//! hop is being resolved is held, not dropped, and is decided anew and sent
//! when the next hop resolves, through the validated config, the
//! publication, `run_tick`, and SimIo (fixtures/arphold/router.toml: LAN
//! 192.168.1.0/24 with H 192.168.1.10 a static neighbor, UDP/TCP/ICMP NAPT
//! on WAN 203.0.113.2, gateway G 203.0.113.1 resolved by ARP, a stateful
//! firewall).
//!
//! Every expected frame is built here from RFC 791/768/793/792/826 with
//! this file's own checksum, independently of the router. The NAT's keyed
//! choices (the public port or ICMP identifier, and the generated IPv4 ID of
//! a translated DF-clear datagram, NAT44-126) are read from the output;
//! everything else, checksums included, must match exactly.

use ruster_config::{parse, validate, ValidatedConfig, PRODUCTION_VALIDATION_LIMITS};
use ruster_control::{
    ActivePublication, FullServiceStorage, PublicationSequencer, SimDeterministicKeySource,
};
use ruster_core::{ArpHoldCounters, ConsumeReason, DropReason, IfId, MonotonicMillis};
use ruster_io_sim::{FrameOrigin, SimIo, TxFrame};
use ruster_runtime::{run_tick, TickBudgets, TickObserver};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const H_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];
const J_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x20];
const G_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0xfe];
const BROADCAST: [u8; 6] = [0xff; 6];
const LAN_IP: [u8; 4] = [192, 168, 1, 1];
const PUBLIC: [u8; 4] = [203, 0, 113, 2];
const H: [u8; 4] = [192, 168, 1, 10];
/// A LAN host that is not a static neighbor.
const J: [u8; 4] = [192, 168, 1, 20];
const G: [u8; 4] = [203, 0, 113, 1];
const S: [u8; 4] = [198, 51, 100, 20];
const DF: u16 = 0x4000;
const MF: u16 = 0x2000;
const ROUTER: &str = include_str!("../../../fixtures/arphold/router.toml");

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

fn pseudo_sum(source: [u8; 4], destination: [u8; 4], protocol: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&source);
    pseudo.extend_from_slice(&destination);
    pseudo.extend_from_slice(&[0, protocol]);
    pseudo.extend_from_slice(&u16::try_from(segment.len()).unwrap().to_be_bytes());
    pseudo.extend_from_slice(segment);
    sum16(&pseudo)
}

/// RFC 768 datagram with its checksum.
fn udp(source: [u8; 4], destination: [u8; 4], ports: (u16, u16), payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&ports.0.to_be_bytes());
    segment.extend_from_slice(&ports.1.to_be_bytes());
    segment.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);
    let checksum = match pseudo_sum(source, destination, 17, &segment) {
        0 => 0xffff,
        sum => sum,
    };
    segment[6..8].copy_from_slice(&checksum.to_be_bytes());
    segment
}

/// RFC 793 SYN with no options.
fn tcp_syn(source: [u8; 4], destination: [u8; 4], ports: (u16, u16), seq: u32) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&ports.0.to_be_bytes());
    segment.extend_from_slice(&ports.1.to_be_bytes());
    segment.extend_from_slice(&seq.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 0, 0x50, 0x02, 0x10, 0x00, 0, 0, 0, 0]);
    let checksum = pseudo_sum(source, destination, 6, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
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

/// RFC 826 Ethernet/IPv4 ARP, padded to the 60-byte minimum.
fn arp(
    destination: [u8; 6],
    op: u16,
    sender: ([u8; 6], [u8; 4]),
    target: ([u8; 6], [u8; 4]),
) -> Vec<u8> {
    let mut body = vec![0, 1, 8, 0, 6, 4];
    body.extend_from_slice(&op.to_be_bytes());
    body.extend_from_slice(&sender.0);
    body.extend_from_slice(&sender.1);
    body.extend_from_slice(&target.0);
    body.extend_from_slice(&target.1);
    body.resize(46, 0);
    ethernet(destination, sender.0, 0x0806, &body)
}

/// The router's ARP Request for `target` out of `(mac, ip)`.
fn arp_request(mac: [u8; 6], ip: [u8; 4], target: [u8; 4]) -> Vec<u8> {
    arp(BROADCAST, 1, (mac, ip), ([0; 6], target))
}

/// G's ARP Reply to the router's WAN address.
fn g_reply() -> Vec<u8> {
    arp(WAN_MAC, 2, (G_MAC, G), (WAN_MAC, PUBLIC))
}

/// An IPv4 frame from H on the LAN.
fn from_h(destination: [u8; 4], id: u16, flags: u16, ttl: u8, protocol: u8, l4: &[u8]) -> Vec<u8> {
    ethernet(
        LAN_MAC,
        H_MAC,
        0x0800,
        &ipv4(H, destination, id, flags, ttl, protocol, l4),
    )
}

/// The outbound frame on the WAN to G after NAT.
fn to_g(id: u16, flags: u16, protocol: u8, l4: &[u8]) -> Vec<u8> {
    ethernet(
        G_MAC,
        WAN_MAC,
        0x0800,
        &ipv4(PUBLIC, S, id, flags, 63, protocol, l4),
    )
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

/// RFC 791 §3.2 cut of the Ethernet+IPv4 `frame` for an MTU of `mtu`.
fn cut(frame: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    let header = &frame[14..34];
    let data = &frame[34..];
    let block = (mtu - 20) / 8 * 8;
    let base = u16_at(header, 6);
    data.chunks(block)
        .enumerate()
        .map(|(index, piece)| {
            let last = (index + 1) * block >= data.len();
            let offset = u16::try_from(index * block / 8).unwrap();
            let more = if last { base & MF } else { MF };
            let mut fragment = header.to_vec();
            fragment[2..4].copy_from_slice(&u16::try_from(20 + piece.len()).unwrap().to_be_bytes());
            fragment[6..8].copy_from_slice(&((base & 0x8000) | more | offset).to_be_bytes());
            fragment[10..12].copy_from_slice(&[0, 0]);
            let checksum = sum16(&fragment);
            fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
            fragment.extend_from_slice(piece);
            let mut out = frame[..14].to_vec();
            out.extend_from_slice(&fragment);
            out
        })
        .collect()
}

// --------------------------------------------------------------- world ----

struct World {
    active: ActivePublication<'static, SimIo>,
    sequencer: PublicationSequencer<SimDeterministicKeySource>,
    config: ruster_config::ValidatedConfigV1,
    io: SimIo,
    observer: TickObserver,
    now: u64,
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
            config,
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

    /// Applies the same document as a new generation in a tick at `now`.
    fn reapply(&mut self, now: u64) -> Vec<TxFrame> {
        let candidate = self.sequencer.candidate(&self.config).expect("candidate");
        let report = run_tick(
            &mut self.active,
            Some(candidate),
            &mut self.io,
            MonotonicMillis(now),
            budgets(),
            &mut self.observer,
        );
        assert!(
            matches!(
                report.publication,
                ruster_runtime::PublicationOutcome::Applied
            ),
            "{:?}",
            report.publication
        );
        std::iter::from_fn(|| self.io.pop_tx()).collect()
    }

    fn hold(&self) -> ArpHoldCounters {
        self.active.arp_hold().expect("holding is on").counters()
    }

    fn live(&self) -> usize {
        self.active.arp_hold().expect("holding is on").live()
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

    /// UDP mappings, TCP sessions, ICMP mappings, firewall states.
    fn state(&self) -> [usize; 4] {
        [
            self.active.nat44_udp().occupancy().mappings.occupied(),
            self.active.nat44_tcp().occupancy().sessions.occupied(),
            self.active
                .nat44_icmp()
                .map_or(0, |icmp| icmp.occupancy().mappings.occupied()),
            self.active.firewall().occupancy().occupied(),
        ]
    }
}

fn bytes(frames: &[TxFrame]) -> Vec<(IfId, Vec<u8>)> {
    frames
        .iter()
        .map(|frame| (frame.egress, frame.bytes.clone()))
        .collect()
}

// --------------------------------------------------------------- tests ----

/// The first Echo Request of a ping towards an unresolved gateway is held
/// (nothing committed: no NAT mapping, no firewall state), and is sent,
/// translated, the tick G's ARP Reply arrives: `ping -c1` succeeds on the
/// first try. Its reply comes back through the state the replay created.
#[test]
fn the_first_echo_request_is_held_and_sent_when_the_gateway_answers() {
    let mut world = World::new(ROUTER);
    let echo = icmp_echo(8, 0x1234, 1, b"first ping");
    let sent = world.tick(0, &[(LAN, from_h(S, 0x0101, DF, 64, 1, &echo))]);
    assert_eq!(bytes(&sent), [(WAN, arp_request(WAN_MAC, PUBLIC, G))]);
    assert_eq!(world.consumed(ConsumeReason::ArpHeld), 1);
    assert_eq!(world.drops(DropReason::NeighborUnresolved), 0);
    assert_eq!(world.live(), 1);
    assert_eq!(world.state(), [0, 0, 0, 0], "nothing commits for a hold");

    let sent = world.tick(10, &[(WAN, g_reply())]);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(
        (sent[0].egress, sent[0].origin),
        (WAN, FrameOrigin::Generated)
    );
    let identifier = u16_at(&sent[0].bytes, 38);
    assert_eq!(
        sent[0].bytes,
        to_g(0x0101, DF, 1, &icmp_echo(8, identifier, 1, b"first ping"))
    );
    assert_eq!(world.live(), 0);
    assert_eq!(world.state(), [0, 0, 1, 1], "the replay committed");
    let counters = world.hold();
    assert_eq!(
        (
            counters.held,
            counters.replayed,
            counters.replay_sent,
            counters.replay_dropped
        ),
        (1, 1, 1, 0)
    );

    // S's Echo Reply goes back to H through the replay's mapping.
    let reply = ethernet(
        WAN_MAC,
        G_MAC,
        0x0800,
        &ipv4(
            S,
            PUBLIC,
            0x0202,
            DF,
            60,
            1,
            &icmp_echo(0, identifier, 1, b"first ping"),
        ),
    );
    let sent = world.tick(20, &[(WAN, reply)]);
    assert_eq!(
        bytes(&sent),
        [(
            LAN,
            ethernet(
                H_MAC,
                LAN_MAC,
                0x0800,
                &ipv4(
                    S,
                    H,
                    0x0202,
                    DF,
                    59,
                    1,
                    &icmp_echo(0, 0x1234, 1, b"first ping")
                )
            )
        )]
    );
}

/// The first TCP SYN of a connection is held and sent when the gateway
/// resolves, so the client pays no retransmission timeout.
#[test]
fn a_tcp_syn_is_held_and_sent_without_a_retransmission() {
    let mut world = World::new(ROUTER);
    let syn = tcp_syn(H, S, (5001, 443), 1000);
    let sent = world.tick(0, &[(LAN, from_h(S, 7, DF, 64, 6, &syn))]);
    assert_eq!(bytes(&sent), [(WAN, arp_request(WAN_MAC, PUBLIC, G))]);
    let sent = world.tick(900, &[(WAN, g_reply())]);
    assert_eq!(sent.len(), 1);
    let port = u16_at(&sent[0].bytes, 34);
    assert!((40_000..=40_015).contains(&port));
    assert_eq!(
        sent[0].bytes,
        to_g(7, DF, 6, &tcp_syn(PUBLIC, S, (port, 443), 1000))
    );
    assert_eq!(world.state(), [0, 1, 0, 1]);
}

/// RFC 1122 §2.3.2.2 keeps the latest datagram: with three per next hop,
/// five datagrams to the unresolved gateway leave the last three, sent in
/// the order they arrived.
#[test]
fn the_latest_datagrams_are_kept_and_sent_in_order() {
    let mut world = World::new(ROUTER);
    let frames: Vec<_> = (1..=5_u16)
        .map(|id| {
            let l4 = udp(H, S, (5000, 53), format!("q{id}").as_bytes());
            (LAN, from_h(S, id, DF, 64, 17, &l4))
        })
        .collect();
    let sent = world.tick(0, &frames);
    assert_eq!(bytes(&sent), [(WAN, arp_request(WAN_MAC, PUBLIC, G))]);
    assert_eq!(world.consumed(ConsumeReason::ArpHeld), 5);
    assert_eq!(world.live(), 3);
    assert_eq!(world.hold().replaced, 2);

    let sent = world.tick(10, &[(WAN, g_reply())]);
    assert_eq!(sent.len(), 3);
    let port = u16_at(&sent[0].bytes, 34);
    for (frame, id) in sent.iter().zip(3..=5_u16) {
        assert_eq!(
            frame.bytes,
            to_g(
                id,
                DF,
                17,
                &udp(PUBLIC, S, (port, 53), format!("q{id}").as_bytes())
            )
        );
    }
}

/// Per-host and total bounds refuse with typed drops; the ARP request for
/// a refused datagram's next hop still goes out.
#[test]
fn the_per_host_and_total_bounds_refuse_with_typed_drops() {
    let text = ROUTER
        .replacen("per-host = 16", "per-host = 2", 1)
        .replacen("packets = 64", "packets = 3", 1);
    let mut world = World::new(&text);
    let datagram = |source: [u8; 4], mac: [u8; 6], last: u8| {
        let destination = [203, 0, 113, last];
        let l4 = udp(source, destination, (5000, 7), b"x");
        (
            LAN,
            ethernet(
                LAN_MAC,
                mac,
                0x0800,
                &ipv4(source, destination, 1, DF, 64, 17, &l4),
            ),
        )
    };
    let sent = world.tick(
        0,
        &[
            datagram(H, H_MAC, 50),
            datagram(H, H_MAC, 51),
            datagram(H, H_MAC, 52),
            datagram(J, J_MAC, 53),
            datagram([192, 168, 1, 30], J_MAC, 54),
        ],
    );
    assert_eq!(sent.len(), 5, "an ARP request per next hop");
    assert_eq!(world.drops(DropReason::ArpHoldHostLimit), 1);
    assert_eq!(world.drops(DropReason::ArpHoldFull), 1);
    assert_eq!(world.consumed(ConsumeReason::ArpHeld), 3);
    let counters = world.hold();
    assert_eq!(
        (
            counters.held,
            counters.refused_host_limit,
            counters.refused_full
        ),
        (3, 1, 1)
    );
}

/// A directly connected next hop that never answers: three ARP Requests,
/// then the resolution's Host Unreachable (ICMP4-012H) to H quoting the
/// datagram as received, and the held datagram is discarded. A late reply
/// replays nothing.
#[test]
fn an_unanswered_next_hop_gets_host_unreachable_and_the_hold_is_freed() {
    let mut world = World::new(ROUTER);
    let silent = [203, 0, 113, 50];
    let l4 = udp(H, silent, (5005, 7), b"hello?");
    let original = ipv4(H, silent, 10, DF, 64, 17, &l4);
    let request = arp_request(WAN_MAC, PUBLIC, silent);
    let mut sent = bytes(&world.tick(0, &[(LAN, ethernet(LAN_MAC, H_MAC, 0x0800, &original))]));
    for now in [1_000, 2_000] {
        sent.extend(bytes(&world.tick(now, &[])));
        assert_eq!(world.live(), 1, "still resolving at {now}");
    }
    assert_eq!(sent, vec![(WAN, request.clone()); 3]);
    let sent = world.tick(3_000, &[]);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let error = &sent[0].bytes;
    assert_eq!(sent[0].egress, LAN);
    assert_eq!(&error[..12], &[H_MAC, LAN_MAC].concat()[..]);
    assert_eq!(&error[26..34], &[LAN_IP, H].concat()[..]);
    assert_eq!(&error[34..36], &[3, 1], "Destination Unreachable, Host");
    assert_eq!(sum16(&error[34..]), 0, "ICMP checksum");
    assert_eq!(&error[42..], &original[..], "the datagram as received");
    assert_eq!(world.live(), 0);
    let counters = world.hold();
    assert_eq!(counters.expired + counters.failed, 1);
    assert_eq!(counters.replayed, 0);
    let late = arp(
        WAN_MAC,
        2,
        ([2, 0, 0, 0, 0, 0x50], silent),
        (WAN_MAC, PUBLIC),
    );
    assert!(world.tick(3_500, &[(WAN, late)]).is_empty());
}

/// The replay is sent in the tick's last, generated fragment phase: after
/// the router's own ARP Requests and ICMPv4 errors of the same tick.
#[test]
fn the_replay_follows_the_routers_own_arp_and_icmp_in_its_tick() {
    let mut world = World::new(ROUTER);
    let held = udp(H, S, (5000, 53), b"held");
    world.tick(0, &[(LAN, from_h(S, 1, DF, 64, 17, &held))]);
    let expired = udp(H, S, (5003, 33434), b"trace");
    let unresolved = [203, 0, 113, 60];
    let fresh = udp(H, unresolved, (5004, 9), b"new");
    let sent = world.tick(
        10,
        &[
            (WAN, g_reply()),
            (LAN, from_h(S, 2, DF, 1, 17, &expired)),
            (LAN, from_h(unresolved, 3, DF, 64, 17, &fresh)),
        ],
    );
    assert_eq!(sent.len(), 3, "{sent:?}");
    assert!(sent
        .iter()
        .all(|frame| frame.origin == FrameOrigin::Generated));
    assert_eq!(
        (sent[0].egress, sent[0].bytes.clone()),
        (WAN, arp_request(WAN_MAC, PUBLIC, unresolved))
    );
    assert_eq!(
        (sent[1].egress, sent[1].bytes[34]),
        (LAN, 11),
        "Time Exceeded"
    );
    let port = u16_at(&sent[2].bytes, 34);
    assert_eq!(
        (sent[2].egress, sent[2].bytes.clone()),
        (WAN, to_g(1, DF, 17, &udp(PUBLIC, S, (port, 53), b"held")))
    );
    assert_eq!(world.live(), 1, "the fresh datagram waits");
}

/// A tick replays at most as many datagrams as there are free
/// fragmentation slots; the rest go out in the next tick.
#[test]
fn replays_wait_for_free_fragmentation_slots() {
    let text = ROUTER.replacen("[tick]", "[fragmentation]\ndatagrams = 1\n\n[tick]", 1);
    let mut world = World::new(&text);
    let frames: Vec<_> = (1..=2_u16)
        .map(|id| (LAN, from_h(S, id, DF, 64, 17, &udp(H, S, (5000, 53), b"q"))))
        .collect();
    world.tick(0, &frames);
    let first = world.tick(10, &[(WAN, g_reply())]);
    assert_eq!(first.len(), 1);
    assert_eq!(u16_at(&first[0].bytes, 18), 1);
    assert_eq!(world.hold().deferred, 1);
    let second = world.tick(20, &[]);
    assert_eq!(second.len(), 1);
    assert_eq!(u16_at(&second[0].bytes, 18), 2);
    let counters = world.hold();
    assert_eq!((counters.replay_sent, world.live()), (2, 0));
}

/// A publication apply drops what is held (the datagram would be decided
/// under the successor's rules): nothing is sent when the gateway answers.
#[test]
fn a_publication_apply_drops_the_held_datagrams() {
    let mut world = World::new(ROUTER);
    world.tick(
        0,
        &[(LAN, from_h(S, 1, DF, 64, 17, &udp(H, S, (5000, 53), b"q")))],
    );
    assert_eq!(world.live(), 1);
    world.reapply(5);
    assert_eq!(world.live(), 0);
    assert_eq!(world.hold().flushed, 1);
    assert!(world.tick(10, &[(WAN, g_reply())]).is_empty());
    assert_eq!(world.hold().replayed, 0);
}

/// The firewall decides before the next hop: a denied datagram is dropped
/// with its own reason and never held.
#[test]
fn a_firewall_denied_datagram_is_never_held() {
    let mut world = World::new(ROUTER);
    let telnet = tcp_syn(H, S, (5002, 23), 7);
    let sent = world.tick(0, &[(LAN, from_h(S, 6, DF, 64, 6, &telnet))]);
    assert!(sent.is_empty());
    assert_eq!(world.drops(DropReason::FirewallRuleDenied), 1);
    assert_eq!(world.consumed(ConsumeReason::ArpHeld), 0);
    assert_eq!(world.hold().held, 0);
}

/// An inbound answer de-translated towards a LAN host the router has not
/// resolved yet is held too, and sent when the host answers the router's
/// ARP Request on the LAN.
#[test]
fn an_inbound_answer_to_an_unresolved_lan_host_is_held() {
    let mut world = World::new(ROUTER);
    let query = udp(J, S, (5000, 53), b"query");
    let from_j = ethernet(LAN_MAC, J_MAC, 0x0800, &ipv4(J, S, 1, DF, 64, 17, &query));
    world.tick(0, &[(LAN, from_j)]);
    let sent = world.tick(10, &[(WAN, g_reply())]);
    let port = u16_at(&sent[0].bytes, 34);
    let answer = ethernet(
        WAN_MAC,
        G_MAC,
        0x0800,
        &ipv4(
            S,
            PUBLIC,
            9,
            DF,
            60,
            17,
            &udp(S, PUBLIC, (53, port), b"answer"),
        ),
    );
    let sent = world.tick(20, &[(WAN, answer)]);
    assert_eq!(bytes(&sent), [(LAN, arp_request(LAN_MAC, LAN_IP, J))]);
    assert_eq!(world.live(), 1);
    let j_reply = arp(LAN_MAC, 2, (J_MAC, J), (LAN_MAC, LAN_IP));
    let sent = world.tick(30, &[(LAN, j_reply)]);
    assert_eq!(
        bytes(&sent),
        [(
            LAN,
            ethernet(
                J_MAC,
                LAN_MAC,
                0x0800,
                &ipv4(S, J, 9, DF, 59, 17, &udp(S, J, (53, 5000), b"answer"))
            )
        )]
    );
}

/// NAT-FRAG: a held first fragment stays undecided, so its later fragments
/// are held by the association table; when the replay allows the first
/// fragment they are released, and every fragment leaves with one
/// generated ID and the translated header.
#[test]
fn a_held_first_fragment_releases_its_later_fragments() {
    let mut world = World::new(ROUTER);
    let payload: Vec<u8> = (0..2972_u32).map(|i| (i % 251) as u8).collect();
    let datagram = from_h(S, 0x4242, 0, 64, 17, &udp(H, S, (5000, 4789), &payload));
    let fragments = cut(&datagram, 1500);
    assert_eq!(fragments.len(), 3);
    let frames: Vec<_> = fragments.iter().map(|f| (LAN, f.clone())).collect();
    let sent = world.tick(0, &frames);
    assert_eq!(bytes(&sent), [(WAN, arp_request(WAN_MAC, PUBLIC, G))]);
    assert_eq!(world.consumed(ConsumeReason::ArpHeld), 1);
    assert_eq!(world.consumed(ConsumeReason::Ipv4FragmentHeld), 2);

    let mut sent = bytes(&world.tick(10, &[(WAN, g_reply())]));
    assert_eq!(sent.len(), 3, "{sent:?}");
    sent.sort_by_key(|(_, bytes)| u16_at(bytes, 20) & 0x1fff);
    let first = &sent[0].1;
    let id = u16_at(first, 18);
    let port = u16_at(first, 34);
    let translated = to_g(id, 0, 17, &udp(PUBLIC, S, (port, 4789), &payload));
    let expected: Vec<_> = cut(&translated, 1500)
        .into_iter()
        .map(|f| (WAN, f))
        .collect();
    assert_eq!(sent, expected);
}

/// MTU2: a held DF-clear datagram above the egress MTU is fragmented when it
/// is replayed (RFC 791 §3.2, at MTU 576: 552 + 428 data bytes).
#[test]
fn a_held_df_clear_datagram_above_the_egress_mtu_is_fragmented_at_replay() {
    let text = ROUTER.replacen(
        "mac = \"02:00:00:00:00:02\"",
        "mac = \"02:00:00:00:00:02\"\nmtu = 576",
        1,
    );
    let mut world = World::new(&text);
    let payload = vec![0x5a; 972];
    world.tick(
        0,
        &[(
            LAN,
            from_h(S, 0x0900, 0, 64, 17, &udp(H, S, (5000, 53), &payload)),
        )],
    );
    let sent = bytes(&world.tick(10, &[(WAN, g_reply())]));
    assert_eq!(sent.len(), 2, "{sent:?}");
    let id = u16_at(&sent[0].1, 18);
    let port = u16_at(&sent[0].1, 34);
    let translated = to_g(id, 0, 17, &udp(PUBLIC, S, (port, 53), &payload));
    let expected: Vec<_> = cut(&translated, 576)
        .into_iter()
        .map(|f| (WAN, f))
        .collect();
    assert_eq!(
        expected
            .iter()
            .map(|(_, f)| f.len() - 34)
            .collect::<Vec<_>>(),
        [552, 428]
    );
    assert_eq!(sent, expected);
    assert_eq!(world.hold().replay_fragmented, 1);
}

/// A held DF-set datagram above the egress MTU gets Fragmentation Needed
/// (RFC 1191 §4, Next-Hop MTU 576) at replay, in the same tick.
#[test]
fn a_held_df_set_datagram_above_the_egress_mtu_gets_fragmentation_needed() {
    let text = ROUTER.replacen(
        "mac = \"02:00:00:00:00:02\"",
        "mac = \"02:00:00:00:00:02\"\nmtu = 576",
        1,
    );
    let mut world = World::new(&text);
    world.tick(
        0,
        &[(
            LAN,
            from_h(S, 0x0900, DF, 64, 17, &udp(H, S, (5000, 53), &[0; 972])),
        )],
    );
    let sent = world.tick(10, &[(WAN, g_reply())]);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let error = &sent[0].bytes;
    assert_eq!((sent[0].egress, &error[34..36]), (LAN, &[3, 4][..]));
    assert_eq!(u16_at(error, 40), 576);
    assert_eq!(world.drops(DropReason::Ipv4FragmentationNeeded), 1);
    assert_eq!(world.hold().replay_dropped, 1);
}

/// `enabled = false` is the switch: the datagram is dropped as before
/// ARP-HOLD and never sent, and there is no hold storage.
#[test]
fn holding_off_drops_as_before() {
    let mut world = World::new(&ROUTER.replacen("enabled = true", "enabled = false", 1));
    assert!(world.active.arp_hold().is_none());
    world.tick(
        0,
        &[(LAN, from_h(S, 1, DF, 64, 17, &udp(H, S, (5000, 53), b"q")))],
    );
    assert_eq!(world.drops(DropReason::NeighborUnresolved), 1);
    assert!(world.tick(10, &[(WAN, g_reply())]).is_empty());
}

/// Hairpin (RFC 4787 REQ-9): H's datagram to J's public mapping turns back
/// into the LAN towards J, which the router has not resolved: it is held,
/// and sent with H's external source when J answers the ARP Request.
#[test]
fn a_hairpinned_datagram_to_an_unresolved_lan_host_is_held() {
    // Endpoint-independent filtering, and a rule for the inbound half
    // (outside -> inside from the public address).
    let text = ROUTER
        .replacen(
            "filtering = \"address-dependent\"",
            "filtering = \"endpoint-independent\"",
            1,
        )
        .replacen(
            "[tick]",
            "[[firewall.rules]]\nid = 60\ningress = \"wan\"\negress = \"lan\"\n\
             source = \"203.0.113.2/32\"\ndestination = \"192.168.1.0/24\"\n\
             protocol = \"udp\"\naction = \"allow-stateful\"\n\n\
             [firewall.rules.source-ports]\nfirst = 1\nlast = 65535\n\n\
             [firewall.rules.destination-ports]\nfirst = 1\nlast = 65535\n\n[tick]",
            1,
        );
    let mut world = World::new(&text);
    let from_j = |id: u16, l4: &[u8], destination: [u8; 4]| {
        ethernet(
            LAN_MAC,
            J_MAC,
            0x0800,
            &ipv4(J, destination, id, DF, 64, 17, l4),
        )
    };
    world.tick(0, &[(LAN, from_j(1, &udp(J, S, (5000, 53), b"j"), S))]);
    let sent = world.tick(10, &[(WAN, g_reply())]);
    let j_port = u16_at(&sent[0].bytes, 34);

    let hairpin = udp(H, PUBLIC, (6000, j_port), b"to j");
    let sent = world.tick(20, &[(LAN, from_h(PUBLIC, 0x0707, DF, 64, 17, &hairpin))]);
    assert_eq!(bytes(&sent), [(LAN, arp_request(LAN_MAC, LAN_IP, J))]);
    assert_eq!(world.live(), 1);
    let j_reply = arp(LAN_MAC, 2, (J_MAC, J), (LAN_MAC, LAN_IP));
    let sent = world.tick(30, &[(LAN, j_reply)]);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let h_port = u16_at(&sent[0].bytes, 34);
    assert_eq!(
        bytes(&sent),
        [(
            LAN,
            ethernet(
                J_MAC,
                LAN_MAC,
                0x0800,
                &ipv4(
                    PUBLIC,
                    J,
                    0x0707,
                    DF,
                    63,
                    17,
                    &udp(PUBLIC, J, (h_port, 5000), b"to j")
                )
            )
        )]
    );
}

/// RFC 5508: S's ICMP error about J's flow is translated towards J, which
/// the router has not resolved: the translated error is held and sent when
/// J answers the ARP Request.
#[test]
fn a_translated_icmp_error_to_an_unresolved_lan_host_is_held() {
    let text = ROUTER.replacen(
        "icmpv4-errors = \"disabled\"",
        "icmpv4-errors = \"bidirectional\"",
        1,
    );
    let mut world = World::new(&text);
    let query = udp(J, S, (5000, 53), b"j");
    let from_j = ethernet(LAN_MAC, J_MAC, 0x0800, &ipv4(J, S, 1, DF, 64, 17, &query));
    world.tick(0, &[(LAN, from_j)]);
    let sent = world.tick(10, &[(WAN, g_reply())]);
    let port = u16_at(&sent[0].bytes, 34);
    // S answers with Port Unreachable quoting what it received.
    let quoted = ipv4(PUBLIC, S, 1, DF, 63, 17, &udp(PUBLIC, S, (port, 53), b"j"));
    let mut error = vec![3, 3, 0, 0, 0, 0, 0, 0];
    error.extend_from_slice(&quoted);
    let checksum = sum16(&error);
    error[2..4].copy_from_slice(&checksum.to_be_bytes());
    let from_s = ethernet(
        WAN_MAC,
        G_MAC,
        0x0800,
        &ipv4(S, PUBLIC, 77, 0, 60, 1, &error),
    );
    let sent = world.tick(20, &[(WAN, from_s)]);
    assert_eq!(bytes(&sent), [(LAN, arp_request(LAN_MAC, LAN_IP, J))]);
    assert_eq!(world.live(), 1);
    let j_reply = arp(LAN_MAC, 2, (J_MAC, J), (LAN_MAC, LAN_IP));
    let sent = world.tick(30, &[(LAN, j_reply)]);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let out = &sent[0].bytes;
    assert_eq!(sent[0].egress, LAN);
    assert_eq!(&out[..12], &[J_MAC, LAN_MAC].concat()[..]);
    assert_eq!(sum16(&out[14..34]), 0, "outer IPv4 checksum");
    assert_eq!((&out[26..30], &out[30..34]), (&S[..], &J[..]));
    assert_eq!(out[22], 59, "outer TTL decremented once");
    assert_eq!(&out[34..36], &[3, 3]);
    assert_eq!(sum16(&out[34..]), 0, "ICMP checksum");
    let inner = &out[42..];
    assert_eq!(sum16(&inner[..20]), 0, "quoted IPv4 checksum");
    assert_eq!(&inner[12..16], &J[..], "quoted source translated back");
    assert_eq!(
        u16_at(inner, 20),
        5000,
        "quoted source port translated back"
    );
}
