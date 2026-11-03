//! RFC 5227 ARP Announcements of the router's own addresses and address
//! conflict detection/defense (ARP-033..ARP-039), through the validated
//! config, the publication, `run_tick`, and SimIo
//! (fixtures/arphold/router.toml: LAN 192.168.1.1/24 on if1, WAN
//! 203.0.113.2/24 on if2).
//!
//! Every expected frame is built here from RFC 826/5227 independently of
//! the router: an Announcement is an ARP Request, broadcast, with sender IP
//! = target IP = the interface's address and target MAC zero (§2.3), padded
//! to 60 bytes.

use ruster_config::{parse, validate, ValidatedConfig, PRODUCTION_VALIDATION_LIMITS};
use ruster_control::{
    ActivePublication, FullServiceStorage, PublicationSequencer, SimDeterministicKeySource,
};
use ruster_core::{ArpAnnounceCounters, IfId, MonotonicMillis};
use ruster_io_sim::{FrameOrigin, SimIo, TxFrame};
use ruster_runtime::{run_tick, PublicationOutcome, TickBudgets, TickObserver};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const OTHER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x66];
const H_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];
const BROADCAST: [u8; 6] = [0xff; 6];
const LAN_IP: [u8; 4] = [192, 168, 1, 1];
const NEW_LAN_IP: [u8; 4] = [192, 168, 1, 254];
const PUBLIC: [u8; 4] = [203, 0, 113, 2];
const H: [u8; 4] = [192, 168, 1, 10];
const ROUTER: &str = include_str!("../../../fixtures/arphold/router.toml");

/// RFC 826 Ethernet/IPv4 ARP, padded to the 60-byte minimum.
fn arp(
    destination: [u8; 6],
    source: [u8; 6],
    op: u16,
    sender: ([u8; 6], [u8; 4]),
    target: ([u8; 6], [u8; 4]),
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&0x0806_u16.to_be_bytes());
    frame.extend_from_slice(&[0, 1, 8, 0, 6, 4]);
    frame.extend_from_slice(&op.to_be_bytes());
    frame.extend_from_slice(&sender.0);
    frame.extend_from_slice(&sender.1);
    frame.extend_from_slice(&target.0);
    frame.extend_from_slice(&target.1);
    frame.resize(60, 0);
    frame
}

/// RFC 5227 §2.3 ARP Announcement of `(mac, ip)`.
fn announcement(mac: [u8; 6], ip: [u8; 4]) -> Vec<u8> {
    arp(BROADCAST, mac, 1, (mac, ip), ([0; 6], ip))
}

fn lan() -> (IfId, Vec<u8>) {
    (LAN, announcement(LAN_MAC, LAN_IP))
}

fn wan() -> (IfId, Vec<u8>) {
    (WAN, announcement(WAN_MAC, PUBLIC))
}

/// `ROUTER` with `[arp]` set to `arp` and the LAN address `lan`.
fn router(arp: &str, lan: [u8; 4]) -> String {
    let lan = format!("ipv4 = \"{}.{}.{}.{}/24\"", lan[0], lan[1], lan[2], lan[3]);
    let text = ROUTER.replacen("ipv4 = \"192.168.1.1/24\"", &lan, 1);
    if arp.is_empty() {
        text
    } else {
        text.replacen(
            "[ipv4-origin]",
            &format!("[arp]\n{arp}\n\n[ipv4-origin]"),
            1,
        )
    }
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
        }
    }

    /// `ruster run` once the ports are open: every interface announces.
    fn started(text: &str) -> Self {
        let mut world = Self::new(text);
        world.active.request_arp_announcements(None);
        world
    }

    fn sent(&mut self) -> Vec<(IfId, Vec<u8>)> {
        while self.io.pop_recycled().is_some() {}
        std::iter::from_fn(|| self.io.pop_tx())
            .map(|frame: TxFrame| {
                assert_eq!(frame.origin, FrameOrigin::Generated, "{frame:?}");
                (frame.egress, frame.bytes)
            })
            .collect()
    }

    /// Injects `frames` and runs one tick at `now`; returns the frames sent.
    fn tick(&mut self, now: u64, frames: &[(IfId, Vec<u8>)]) -> Vec<(IfId, Vec<u8>)> {
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
        self.sent()
    }

    /// Applies `text` as a new generation in a tick at `now`.
    fn reload(&mut self, now: u64, text: &str) -> Vec<(IfId, Vec<u8>)> {
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
        self.sent()
    }

    fn counters(&self) -> ArpAnnounceCounters {
        self.active.resolution().announce_counters()
    }

    fn conflicts(&self) -> Vec<(IfId, u64)> {
        self.active.resolution().address_conflicts().collect()
    }
}

/// Runs idle ticks every 100 ms over `from..=to` and returns what they
/// sent with the tick time.
fn idle(world: &mut World, from: u64, to: u64) -> Vec<(u64, (IfId, Vec<u8>))> {
    let mut sent = Vec::new();
    let mut now = from;
    while now <= to {
        sent.extend(world.tick(now, &[]).into_iter().map(|frame| (now, frame)));
        now += 100;
    }
    sent
}

/// Startup (ARP-033, ARP-036): with the RFC 5227 defaults every interface
/// sends ANNOUNCE_NUM = 2 Announcements ANNOUNCE_INTERVAL = 2 s apart, the
/// first at once (no Probe, so no ANNOUNCE_WAIT), and nothing after.
#[test]
fn startup_announces_every_address_twice_two_seconds_apart() {
    let mut world = World::started(ROUTER);
    assert_eq!(world.active.resolution().pending_announcements(), 2);
    assert_eq!(world.tick(0, &[]), [lan(), wan()]);
    assert_eq!(
        idle(&mut world, 100, 6_000),
        [(2_000, lan()), (2_000, wan())]
    );
    assert_eq!(world.active.resolution().pending_announcements(), 0);
    let counters = world.counters();
    assert_eq!(
        (counters.requested, counters.sequences, counters.committed),
        (2, 2, 4)
    );
    // The generated ARP accounting carries them (shared frame budget).
    let snapshot = world.observer.snapshot(MonotonicMillis(6_000));
    assert_eq!(snapshot.totals.generated_arp.tx_requested, 4);
}

/// Announcements share the generated ARP budget: with a budget of one
/// frame per tick the second interface waits for the next tick.
#[test]
fn announcements_stay_within_the_generated_arp_budget() {
    let mut world = World::started(ROUTER);
    let budgets = TickBudgets {
        generated_arp: 1,
        ..budgets()
    };
    for (now, expected) in [(0, vec![lan()]), (1, vec![wan()]), (2, vec![])] {
        let _report = run_tick(
            &mut world.active,
            None,
            &mut world.io,
            MonotonicMillis(now),
            budgets,
            &mut world.observer,
        );
        assert_eq!(world.sent(), expected, "tick {now}");
    }
}

/// A reload announces only an address that is new or changed (ARP-037):
/// the same document announces nothing, a changed LAN address announces
/// the new address twice on the LAN only.
#[test]
fn reload_announces_only_a_changed_address() {
    let mut world = World::new(ROUTER);
    assert!(world.tick(0, &[]).is_empty(), "nothing without a trigger");
    assert!(world.reload(1_000, ROUTER).is_empty(), "unchanged document");
    assert!(idle(&mut world, 1_100, 4_000).is_empty());

    let changed = router("", NEW_LAN_IP);
    assert_eq!(
        world.reload(5_000, &changed),
        [(LAN, announcement(LAN_MAC, NEW_LAN_IP))],
        "announced in the applying tick"
    );
    assert_eq!(
        idle(&mut world, 5_100, 9_000),
        [(7_000, (LAN, announcement(LAN_MAC, NEW_LAN_IP)))]
    );
    // Back to the old address: a change again, after the minimum interval.
    assert!(world.reload(9_100, ROUTER).is_empty(), "rate-limited");
    assert_eq!(
        idle(&mut world, 9_200, 20_000),
        [(15_000, lan()), (17_000, lan())]
    );
}

/// A link-up (ARP-033, RFC 5227 §2.1 "inactive to active") announces on
/// that port only.
#[test]
fn link_up_announces_on_that_port_only() {
    let mut world = World::new(ROUTER);
    assert_eq!(world.active.request_arp_announcements(Some(WAN)), 1);
    assert_eq!(world.tick(0, &[]), [wan()]);
    assert_eq!(idle(&mut world, 100, 3_000), [(2_000, wan())]);
}

/// A link flap storm (ARP-035): link-ups within the minimum interval
/// (default 10 s) are folded into one later sequence, so the port sends at
/// most ANNOUNCE_NUM frames per minimum interval, and the last trigger is
/// not lost.
#[test]
fn a_link_flap_storm_is_bounded_by_the_minimum_interval() {
    let mut world = World::new(ROUTER);
    world.active.request_arp_announcements(Some(LAN));
    let mut sent = Vec::new();
    let mut now = 0;
    while now <= 25_000 {
        // A link-up every 300 ms for the first 15 s.
        if now <= 15_000 && now % 300 == 0 {
            world.active.request_arp_announcements(Some(LAN));
        }
        sent.extend(world.tick(now, &[]).into_iter().map(|frame| (now, frame)));
        now += 100;
    }
    assert_eq!(
        sent,
        [
            (0, lan()),
            (2_000, lan()),
            (10_000, lan()),
            (12_000, lan()),
            (20_000, lan()),
            (22_000, lan()),
        ]
    );
    let counters = world.counters();
    assert_eq!((counters.sequences, counters.rate_limited), (3, 2));
    assert!(counters.coalesced > 40, "{counters:?}");
}

/// Conflict detection and defense (ARP-038, ARP-039, RFC 5227 §2.4 (c)):
/// an ARP Request or Reply from another MAC claiming the LAN address is
/// counted on the LAN, defended by one Announcement in the same tick, and
/// not defended again within DEFEND_INTERVAL (10 s). The router's own MAC
/// as sender is not a conflict.
#[test]
fn a_conflicting_arp_packet_is_counted_and_defended_once_per_defend_interval() {
    let mut world = World::new(ROUTER);
    let request = arp(BROADCAST, OTHER_MAC, 1, (OTHER_MAC, LAN_IP), ([0; 6], H));
    let reply = arp(
        LAN_MAC,
        OTHER_MAC,
        2,
        (OTHER_MAC, LAN_IP),
        (LAN_MAC, LAN_IP),
    );
    assert_eq!(world.tick(0, &[(LAN, request.clone())]), [lan()]);
    assert_eq!(world.conflicts(), [(LAN, 1), (WAN, 0)]);
    assert!(world.tick(5_000, &[(LAN, reply)]).is_empty(), "within 10 s");
    assert!(world.tick(9_999, &[(LAN, request.clone())]).is_empty());
    assert_eq!(world.tick(10_000, &[(LAN, request)]), [lan()]);
    assert_eq!(world.conflicts(), [(LAN, 4), (WAN, 0)]);
    let counters = world.counters();
    assert_eq!(
        (
            counters.conflicts,
            counters.defended,
            counters.defense_suppressed,
            counters.committed
        ),
        (4, 2, 2, 2)
    );

    // Our own MAC (a reflected Announcement) and another interface's
    // address on the LAN (ARP-021B) are not conflicts.
    let reflected = arp(BROADCAST, LAN_MAC, 2, (LAN_MAC, LAN_IP), (H_MAC, H));
    let other_link = arp(BROADCAST, H_MAC, 1, (H_MAC, PUBLIC), ([0; 6], H));
    assert!(world
        .tick(30_000, &[(LAN, reflected), (LAN, other_link)])
        .is_empty());
    assert_eq!(world.conflicts(), [(LAN, 4), (WAN, 0)]);
}

/// With `conflict-defense = false` a conflict is still counted (ARP-039)
/// but nothing is sent.
#[test]
fn defense_off_counts_without_sending() {
    let mut world = World::new(&router("conflict-defense = false", LAN_IP));
    // A Reply (a Request for our address would also be answered, ARP-008).
    let request = arp(
        BROADCAST,
        OTHER_MAC,
        2,
        (OTHER_MAC, PUBLIC),
        (H_MAC, [203, 0, 113, 9]),
    );
    assert!(world.tick(0, &[(WAN, request)]).is_empty());
    assert_eq!(world.conflicts(), [(LAN, 0), (WAN, 1)]);
    let counters = world.counters();
    assert_eq!(
        (
            counters.conflicts,
            counters.defended,
            counters.defense_suppressed
        ),
        (1, 0, 1)
    );
}

/// `announce = false` (ARP-034): no trigger announces, at startup, link-up,
/// or reload; switching it back on by reload announces the next trigger.
#[test]
fn announce_off_sends_nothing_and_is_reloadable() {
    let off = router("announce = false", LAN_IP);
    let mut world = World::started(&off);
    assert_eq!(world.active.request_arp_announcements(Some(LAN)), 0);
    assert!(idle(&mut world, 0, 3_000).is_empty());
    assert!(world
        .reload(3_100, &router("announce = false", NEW_LAN_IP))
        .is_empty());
    assert!(idle(&mut world, 3_200, 6_000).is_empty());
    assert_eq!(world.counters().disabled, 4);

    assert!(world.reload(6_100, &router("", NEW_LAN_IP)).is_empty());
    assert_eq!(world.active.request_arp_announcements(Some(LAN)), 1);
    assert_eq!(
        world.tick(6_200, &[]),
        [(LAN, announcement(LAN_MAC, NEW_LAN_IP))]
    );
}

/// Configured count and interval (ARP-034): three Announcements one
/// second apart.
#[test]
fn configured_count_and_interval_are_used() {
    let text = router(
        "announce-count = 3\nannounce-interval-ms = 1000\nannounce-min-interval-ms = 5000",
        LAN_IP,
    );
    let mut world = World::new(&text);
    world.active.request_arp_announcements(Some(LAN));
    assert_eq!(
        idle(&mut world, 0, 4_000),
        [(0, lan()), (1_000, lan()), (2_000, lan())]
    );
}

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

/// An RFC 768 datagram from H to `destination` in an RFC 791 header, on
/// the LAN.
fn udp_from_h(destination: [u8; 4], source_port: u16) -> Vec<u8> {
    let payload = b"announce";
    let mut segment = Vec::new();
    segment.extend_from_slice(&source_port.to_be_bytes());
    segment.extend_from_slice(&9_000_u16.to_be_bytes());
    segment.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&H);
    pseudo.extend_from_slice(&destination);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&u16::try_from(segment.len()).unwrap().to_be_bytes());
    pseudo.extend_from_slice(&segment);
    let checksum = match sum16(&pseudo) {
        0 => 0xffff,
        sum => sum,
    };
    segment[6..8].copy_from_slice(&checksum.to_be_bytes());
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(&u16::try_from(20 + segment.len()).unwrap().to_be_bytes());
    packet.extend_from_slice(&[0, 1, 0x40, 0, 64, 17, 0, 0]);
    packet.extend_from_slice(&H);
    packet.extend_from_slice(&destination);
    let checksum = sum16(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(&segment);
    let mut frame = Vec::new();
    frame.extend_from_slice(&LAN_MAC);
    frame.extend_from_slice(&H_MAC);
    frame.extend_from_slice(&0x0800_u16.to_be_bytes());
    frame.extend_from_slice(&packet);
    frame
}

/// The first frame of each tick's generated ARP budget goes to a due
/// Announcement (#351 review L-b): with a budget of one frame and a
/// resolution Request queued every tick, the announcements still leave,
/// one per tick, and the Requests after them.
#[test]
fn resolution_requests_cannot_starve_the_announcements() {
    let mut world = World::started(ROUTER);
    let budgets = TickBudgets {
        generated_arp: 1,
        ..budgets()
    };
    let mut sent = Vec::new();
    for now in 0..4_u8 {
        // A datagram to another unresolved WAN host every tick.
        let target = [203, 0, 113, 10 + now];
        world
            .io
            .inject(LAN, udp_from_h(target, 40_000 + u16::from(now)));
        let _report = run_tick(
            &mut world.active,
            None,
            &mut world.io,
            MonotonicMillis(u64::from(now)),
            budgets,
            &mut world.observer,
        );
        sent.push(world.sent());
    }
    let request = |last: u8| {
        (
            WAN,
            arp(
                BROADCAST,
                WAN_MAC,
                1,
                (WAN_MAC, PUBLIC),
                ([0; 6], [203, 0, 113, last]),
            ),
        )
    };
    assert_eq!(
        sent,
        [
            vec![lan()],
            vec![wan()],
            vec![request(10)],
            vec![request(11)]
        ]
    );
}

/// A conflicting ARP Request for the router's own address (RFC 5227
/// §2.4): the router answers it as before (RFC 826, ARP-008, a unicast
/// Reply in place) and also defends with the broadcast Announcement, in
/// the same tick.
#[test]
fn a_conflicting_request_for_our_address_is_answered_and_defended() {
    let mut world = World::new(ROUTER);
    let probe_like = arp(
        BROADCAST,
        OTHER_MAC,
        1,
        (OTHER_MAC, LAN_IP),
        ([0; 6], LAN_IP),
    );
    world.io.inject(LAN, probe_like);
    let _report = run_tick(
        &mut world.active,
        None,
        &mut world.io,
        MonotonicMillis(0),
        budgets(),
        &mut world.observer,
    );
    while world.io.pop_recycled().is_some() {}
    let sent: Vec<(FrameOrigin, IfId, Vec<u8>)> = std::iter::from_fn(|| world.io.pop_tx())
        .map(|frame| (frame.origin, frame.egress, frame.bytes))
        .collect();
    let reply = arp(
        OTHER_MAC,
        LAN_MAC,
        2,
        (LAN_MAC, LAN_IP),
        (OTHER_MAC, LAN_IP),
    );
    assert_eq!(
        sent,
        [
            (FrameOrigin::Received { ingress: LAN }, LAN, reply),
            (FrameOrigin::Generated, LAN, announcement(LAN_MAC, LAN_IP)),
        ]
    );
    assert_eq!(world.conflicts(), [(LAN, 1), (WAN, 0)]);
}
