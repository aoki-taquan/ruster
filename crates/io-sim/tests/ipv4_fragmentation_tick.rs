//! MTU2 part B: the generated fragment phase of `run_tick` (the last phase,
//! after generated ARP and ICMPv4) through the validated config, the
//! publication, and SimIo: it sends the staged datagrams in the tick they
//! arrived in within its frame budget; a backend failure of its own or of
//! an earlier generated phase flushes them, so no staged datagram outlives
//! its tick.

use ruster_config::{parse, validate, ValidatedConfig, PRODUCTION_VALIDATION_LIMITS};
use ruster_control::{
    ActivePublication, FullServiceStorage, PublicationSequencer, SimDeterministicKeySource,
};
use ruster_core::{internet_checksum, IfId, MonotonicMillis};
use ruster_io_sim::{FrameOrigin, SimIo};
use ruster_runtime::{
    run_tick, GeneratedAccounting, GeneratedFragmentsStop, GeneratedPhaseReport, PhaseReport,
    TickBudgets, TickObserver, TickPhaseSkip,
};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);

/// fixtures/mtu2b (WAN MTU 576, at most 2 fragments) with two slots and the
/// gateway as a static neighbor, so nothing waits for ARP.
fn config_text() -> String {
    include_str!("../../../fixtures/mtu2b/router.toml")
        .replacen("datagrams = 1", "datagrams = 2", 1)
        .replacen(
            "[ipv4-origin]",
            "[[neighbors]]\ninterface = \"wan\"\naddress = \"203.0.113.1\"\nmac = \"02:00:00:00:00:fe\"\n\n[ipv4-origin]",
            1,
        )
}

/// A DF-clear UDP datagram of `total` bytes from H 192.168.1.10:`port` to
/// S 198.51.100.20:53, as received on the LAN.
fn datagram(port: u16, total: usize) -> Vec<u8> {
    udp_to([198, 51, 100, 20], 64, port, total)
}

/// A DF-clear UDP datagram from H 192.168.1.10:`port` to `destination`:53.
fn udp_to(destination: [u8; 4], ttl: u8, port: u16, total: usize) -> Vec<u8> {
    let mut frame = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0x10, 0x08, 0x00];
    let mut header = vec![0x45, 0];
    header.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    header.extend_from_slice(&[0x12, 0x34, 0, 0, ttl, 17, 0, 0]);
    header.extend_from_slice(&[192, 168, 1, 10]);
    header.extend_from_slice(&destination);
    let sum = internet_checksum(&header);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    frame.extend_from_slice(&header);
    let len = total - 20;
    let mut udp = Vec::new();
    udp.extend_from_slice(&port.to_be_bytes());
    udp.extend_from_slice(&53_u16.to_be_bytes());
    udp.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend((0..len - 8).map(|i| i as u8));
    let mut pseudo = vec![192, 168, 1, 10];
    pseudo.extend_from_slice(&destination);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    pseudo.extend_from_slice(&udp);
    let sum = match internet_checksum(&pseudo) {
        0 => 0xffff,
        sum => sum,
    };
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    frame.extend_from_slice(&udp);
    frame
}

fn budgets() -> TickBudgets {
    TickBudgets {
        rx: 8,
        resolution_timer_scans: 8,
        failure_dispatch_scans: 8,
        generated_arp: 8,
        generated_icmpv4: 8,
        generated_fragments: 8,
    }
}

#[test]
fn the_fragment_phase_sends_in_the_tick_and_a_finish_error_flushes_the_rest() {
    let ValidatedConfig::V1(config) = validate(
        parse(config_text().as_bytes()).unwrap(),
        PRODUCTION_VALIDATION_LIMITS,
    )
    .unwrap() else {
        unreachable!("schema V1");
    };
    let mut sequencer = PublicationSequencer::new(SimDeterministicKeySource::new(7));
    let candidate = sequencer.candidate(&config).unwrap();
    let mut storage = FullServiceStorage::new(candidate.storage_shape()).unwrap();
    let mut active = ActivePublication::<SimIo>::new(&mut storage, candidate).unwrap();
    let mut io = SimIo::new();
    let mut observer = TickObserver::default();

    // Two datagrams of 1000 bytes: two fragments each, in the same tick.
    io.inject(LAN, datagram(5000, 1000));
    io.inject(LAN, datagram(5001, 1000));
    let report = run_tick(
        &mut active,
        None,
        &mut io,
        MonotonicMillis(1),
        budgets(),
        &mut observer,
    );
    observer.observe_tick(MonotonicMillis(1), Some(active.generation()), &report);
    assert!(matches!(
        report.generated_fragments,
        PhaseReport::Completed(GeneratedPhaseReport {
            accounting: GeneratedAccounting {
                sessions: 2,
                allocation_attempts: 4,
                allocated: 4,
                tx_requested: 4,
                tx_accepted: 4,
                tx_rejected: 0,
                ..
            },
            stop: GeneratedFragmentsStop::QueueEmpty,
        })
    ));
    let mut sent = Vec::new();
    while let Some(frame) = io.pop_tx() {
        assert_eq!((frame.egress, frame.origin), (WAN, FrameOrigin::Generated));
        sent.push(frame.bytes);
    }
    assert_eq!(sent.len(), 4);
    assert!(sent.iter().all(|bytes| bytes.len() <= 14 + 576));
    let counters = active.fragmentation().unwrap().counters();
    assert_eq!(
        (counters.queued, counters.fragmented, counters.fragments),
        (2, 2, 4)
    );
    assert_eq!(active.fragmentation().unwrap().pending(), 0);

    // The first fragment session's finish fails: its fragments were
    // committed and the second datagram is flushed. The fragment phase is
    // the last of the tick, so the ARP and ICMPv4 phases already ran.
    io.inject(LAN, datagram(5000, 1000));
    io.inject(LAN, datagram(5001, 1000));
    io.fail_next_generated_finish();
    let report = run_tick(
        &mut active,
        None,
        &mut io,
        MonotonicMillis(2),
        budgets(),
        &mut observer,
    );
    observer.observe_tick(MonotonicMillis(2), Some(active.generation()), &report);
    assert!(
        matches!(
            report.generated_fragments,
            PhaseReport::Completed(GeneratedPhaseReport {
                accounting: GeneratedAccounting { sessions: 1, .. },
                stop: GeneratedFragmentsStop::Failed { flushed: 1, .. },
            })
        ),
        "{:?}",
        report.generated_fragments
    );
    assert!(matches!(report.generated_arp, PhaseReport::Completed(_)));
    assert!(matches!(report.generated_icmpv4, PhaseReport::Completed(_)));
    let fragmentation = active.fragmentation().unwrap();
    assert_eq!(fragmentation.pending(), 0, "nothing outlives the tick");
    let counters = fragmentation.counters();
    assert_eq!(
        (counters.queued, counters.fragmented, counters.flushed),
        (4, 3, 1)
    );

    // The next tick starts empty and works again.
    io.inject(LAN, datagram(5000, 1000));
    let report = run_tick(
        &mut active,
        None,
        &mut io,
        MonotonicMillis(3),
        budgets(),
        &mut observer,
    );
    observer.observe_tick(MonotonicMillis(3), Some(active.generation()), &report);
    assert!(matches!(
        report.generated_fragments,
        PhaseReport::Completed(GeneratedPhaseReport {
            stop: GeneratedFragmentsStop::QueueEmpty,
            ..
        })
    ));
    let totals = observer.snapshot(MonotonicMillis(3)).totals;
    assert_eq!(totals.generated_fragments.sessions, 4);
    assert_eq!(totals.generated_fragments.failures, 1);
}

/// The interface MTU is not enforced on received frames: with every
/// interface configured below 1500 (LAN 1280, WAN 1400) a 1500-byte DF-clear
/// datagram from a 1500-byte LAN device still fits a slot (sized for the
/// larger of the MTUs and the longest AF_XDP datagram, 3826 bytes) and is
/// fragmented for the WAN, never dropped for its size.
#[test]
fn a_datagram_above_every_configured_mtu_is_still_fragmented() {
    let text = config_text()
        .replacen("mtu = 576", "mtu = 1400", 1)
        .replacen(
            "mac = \"02:00:00:00:00:01\"",
            "mac = \"02:00:00:00:00:01\"\nmtu = 1280",
            1,
        )
        .replacen(
            "max-fragments-per-datagram = 2",
            "max-fragments-per-datagram = 4",
            1,
        );
    let ValidatedConfig::V1(config) = validate(
        parse(text.as_bytes()).unwrap(),
        PRODUCTION_VALIDATION_LIMITS,
    )
    .unwrap() else {
        unreachable!("schema V1");
    };
    assert_eq!(
        config
            .storage_shape()
            .fragmentation
            .map(|shape| shape.slot_bytes),
        Some(14 + 3826)
    );
    let mut sequencer = PublicationSequencer::new(SimDeterministicKeySource::new(7));
    let candidate = sequencer.candidate(&config).unwrap();
    let mut storage = FullServiceStorage::new(candidate.storage_shape()).unwrap();
    let mut active = ActivePublication::<SimIo>::new(&mut storage, candidate).unwrap();
    let mut io = SimIo::new();
    let mut observer = TickObserver::default();
    io.inject(LAN, datagram(5000, 1500));
    let report = run_tick(
        &mut active,
        None,
        &mut io,
        MonotonicMillis(1),
        budgets(),
        &mut observer,
    );
    assert!(matches!(
        report.generated_fragments,
        PhaseReport::Completed(GeneratedPhaseReport {
            accounting: GeneratedAccounting { tx_accepted: 2, .. },
            stop: GeneratedFragmentsStop::QueueEmpty,
        })
    ));
    let lengths: Vec<usize> = std::iter::from_fn(|| io.pop_tx())
        .map(|frame| frame.bytes.len() - 14)
        .collect();
    // 1480 data bytes at MTU 1400: 1376 + 104.
    assert_eq!(lengths, [1396, 124]);
}

fn activate(text: &str) -> (FullServiceStorage, ruster_control::ValidatedCandidate) {
    let ValidatedConfig::V1(config) = validate(
        parse(text.as_bytes()).unwrap(),
        PRODUCTION_VALIDATION_LIMITS,
    )
    .unwrap() else {
        unreachable!("schema V1");
    };
    let mut sequencer = PublicationSequencer::new(SimDeterministicKeySource::new(7));
    let candidate = sequencer.candidate(&config).unwrap();
    let storage = FullServiceStorage::new(candidate.storage_shape()).unwrap();
    (storage, candidate)
}

/// Review (MTU2 part B): the fragment phase runs last, after generated ARP
/// and ICMPv4, so a fragment set larger than the room the backend has left
/// never starves the router's own frames: an ARP request for an unresolved
/// next hop and a Time Exceeded queued in the same RX batch are still sent,
/// and the set is refused whole (`dropped_unavailable`), nothing partial.
#[test]
fn router_frames_go_first_and_a_set_beyond_the_room_is_refused_whole() {
    let (mut storage, candidate) = activate(&config_text());
    let mut active = ActivePublication::<SimIo>::new(&mut storage, candidate).unwrap();
    let mut io = SimIo::new();
    // One frame of room per generated session: enough for one ARP request
    // or one ICMP error, not for a two-fragment set.
    io.set_generated_budget(1);
    let mut observer = TickObserver::default();
    io.inject(LAN, udp_to([203, 0, 113, 50], 64, 5000, 100));
    io.inject(LAN, udp_to([198, 51, 100, 20], 1, 5001, 100));
    io.inject(LAN, datagram(5002, 1000));
    let report = run_tick(
        &mut active,
        None,
        &mut io,
        MonotonicMillis(1),
        budgets(),
        &mut observer,
    );
    let mut sent = Vec::new();
    while let Some(frame) = io.pop_tx() {
        sent.push((frame.egress, frame.bytes));
    }
    // The ARP request (WAN, EtherType 0x0806) and the Time Exceeded (LAN,
    // ICMP type 11) went out; no fragment did.
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!((sent[0].0, &sent[0].1[12..14]), (WAN, &[0x08, 0x06][..]));
    assert_eq!((sent[1].0, sent[1].1[23], sent[1].1[34]), (LAN, 1, 11));
    assert!(matches!(
        report.generated_fragments,
        PhaseReport::Completed(GeneratedPhaseReport {
            accounting: GeneratedAccounting {
                sessions: 1,
                allocated: 0,
                tx_requested: 0,
                ..
            },
            stop: GeneratedFragmentsStop::QueueEmpty,
        })
    ));
    let counters = active.fragmentation().unwrap().counters();
    assert_eq!((counters.queued, counters.dropped_unavailable), (1, 1));
    assert_eq!(counters.fragments, 0);
}

/// `[tick] generated-fragments` bounds the fragment frames of one tick: a
/// set that does not fit what is left is dropped whole without a session
/// (`dropped_budget`), and the budget is fresh in the next tick.
#[test]
fn the_tick_fragment_budget_refuses_whole_sets() {
    let (mut storage, candidate) = activate(&config_text());
    let mut active = ActivePublication::<SimIo>::new(&mut storage, candidate).unwrap();
    let mut io = SimIo::new();
    let mut observer = TickObserver::default();
    let tight = TickBudgets {
        generated_fragments: 3,
        ..budgets()
    };
    io.inject(LAN, datagram(5000, 1000));
    io.inject(LAN, datagram(5001, 1000));
    let report = run_tick(
        &mut active,
        None,
        &mut io,
        MonotonicMillis(1),
        tight,
        &mut observer,
    );
    assert!(matches!(
        report.generated_fragments,
        PhaseReport::Completed(GeneratedPhaseReport {
            accounting: GeneratedAccounting {
                sessions: 1,
                tx_accepted: 2,
                ..
            },
            stop: GeneratedFragmentsStop::QueueEmpty,
        })
    ));
    assert_eq!(std::iter::from_fn(|| io.pop_tx()).count(), 2);
    let counters = active.fragmentation().unwrap().counters();
    assert_eq!((counters.fragmented, counters.dropped_budget), (1, 1));
    io.inject(LAN, datagram(5001, 1000));
    run_tick(
        &mut active,
        None,
        &mut io,
        MonotonicMillis(2),
        tight,
        &mut observer,
    );
    assert_eq!(std::iter::from_fn(|| io.pop_tx()).count(), 2);
    assert_eq!(active.fragmentation().unwrap().counters().fragmented, 2);
}

/// Re-review M1: a backend failure in the generated ICMPv4 phase (here its
/// finish error) skips the fragment phase that follows and flushes the
/// staged datagrams; nothing is sent for them and nothing stays staged.
#[test]
fn an_icmpv4_phase_failure_skips_the_fragment_phase_and_flushes() {
    let (mut storage, candidate) = activate(&config_text());
    let mut active = ActivePublication::<SimIo>::new(&mut storage, candidate).unwrap();
    let mut io = SimIo::new();
    let mut observer = TickObserver::default();
    // A TTL=1 datagram queues a Time Exceeded (the tick's first generated
    // session, whose finish fails); the DF-clear datagram is staged.
    io.inject(LAN, udp_to([198, 51, 100, 20], 1, 5001, 100));
    io.inject(LAN, datagram(5002, 1000));
    io.fail_next_generated_finish();
    let report = run_tick(
        &mut active,
        None,
        &mut io,
        MonotonicMillis(1),
        budgets(),
        &mut observer,
    );
    assert!(matches!(report.generated_icmpv4, PhaseReport::Completed(_)));
    assert_eq!(
        report.generated_fragments,
        PhaseReport::Skipped(TickPhaseSkip::BackendIoFailure)
    );
    let fragmentation = active.fragmentation().unwrap();
    assert_eq!(fragmentation.pending(), 0);
    let counters = fragmentation.counters();
    assert_eq!(
        (counters.queued, counters.flushed, counters.fragments),
        (1, 1, 0)
    );
    // Only the Time Exceeded left (its finish error does not reject it).
    let sent: Vec<_> = std::iter::from_fn(|| io.pop_tx()).collect();
    assert!(sent.iter().all(|frame| frame.egress == LAN), "{sent:?}");
}

/// Re-review L1: a datagram that needs more fragments than the tick's
/// fragment budget can never be sent, so it is refused at admission
/// (IPV4_FRAGMENTATION_TOO_MANY_FRAGMENTS) before its NAT mapping commits.
#[test]
fn a_set_above_the_tick_budget_is_refused_before_commit() {
    let (mut storage, candidate) = activate(&config_text());
    let mut active = ActivePublication::<SimIo>::new(&mut storage, candidate).unwrap();
    let mut io = SimIo::new();
    let mut observer = TickObserver::default();
    let one = TickBudgets {
        generated_fragments: 1,
        ..budgets()
    };
    io.inject(LAN, datagram(5000, 1000));
    run_tick(
        &mut active,
        None,
        &mut io,
        MonotonicMillis(1),
        one,
        &mut observer,
    );
    assert_eq!(io.pop_tx().map(|frame| frame.egress), None);
    let recycled = io.pop_recycled().expect("dropped");
    assert_eq!(
        recycled.cause,
        ruster_io_sim::RecycleCause::Forwarding(
            ruster_core::DropReason::Ipv4FragmentationTooManyFragments
        )
    );
    assert_eq!(active.nat44_udp().counters().mappings_created, 0);
    assert_eq!(active.fragmentation().unwrap().counters().queued, 0);
}
