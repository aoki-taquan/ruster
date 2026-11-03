//! MTU2 part B: the generated fragment phase of `run_tick` (right after RX)
//! through the validated config, the publication, and SimIo: it sends the
//! staged datagrams in the tick they arrived in, and a backend finish error
//! flushes the rest of them and skips the later generated phases, so no
//! staged datagram outlives its tick.

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
    let mut frame = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0x10, 0x08, 0x00];
    let mut header = vec![0x45, 0];
    header.extend_from_slice(&u16::try_from(total).unwrap().to_be_bytes());
    header.extend_from_slice(&[0x12, 0x34, 0, 0, 64, 17, 0, 0]);
    header.extend_from_slice(&[192, 168, 1, 10, 198, 51, 100, 20]);
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
    let mut pseudo = vec![192, 168, 1, 10, 198, 51, 100, 20, 0, 17];
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

    // The first session's finish fails: its fragments were committed, the
    // second datagram is flushed, and the later generated phases skip.
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
    assert_eq!(
        report.generated_arp,
        PhaseReport::Skipped(TickPhaseSkip::BackendIoFailure)
    );
    assert_eq!(
        report.generated_icmpv4,
        PhaseReport::Skipped(TickPhaseSkip::BackendIoFailure)
    );
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
