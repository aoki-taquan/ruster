//! Reusable conformance cases for RX-to-distinct-TX copy backends.
//!
//! Unlike the in-place [`crate::rx`] contract, this capability assigns
//! different identity domains to the source RX packet and the submitted TX
//! frame. This is required for copy backends such as AF_PACKET: completing a
//! source packet is a logical lifecycle event, while a TPACKET_V3 RX block can
//! return to the kernel only after every packet in that block is terminal.
//! Accepted TX storage remains independently in flight until completion.
//!
//! Payload snapshots and scan counters in this module are cold test
//! observations. They do not require a production backend to clone packets or
//! expose packet-path telemetry.

use ruster_core::{ConsumeReason, DropReason, IfId, PacketBatch, PacketIo};

use crate::{
    RxReclaim, TxEndpoint, CONFORMANCE_LAN, CONFORMANCE_LAN_ENDPOINT, CONFORMANCE_UNKNOWN,
    CONFORMANCE_WAN, CONFORMANCE_WAN_ENDPOINT,
};

/// Physical TPACKET_V3-style RX block identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CopyRxBlockToken {
    pub block_id: u64,
    pub generation: u64,
}

/// One logical packet within a physical RX block.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CopyRxPacketToken {
    pub block: CopyRxBlockToken,
    pub packet_index: u32,
}

/// Physical TX storage identity in a domain distinct from RX block identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CopyTxToken {
    pub frame_id: u64,
    pub generation: u64,
}

/// Source identity bound while an RX lease is live.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveCopyRxPacket {
    pub token: CopyRxPacketToken,
    pub visible_address: usize,
    pub requested_len: usize,
}

/// Destination identity bound when a backend-owned TX frame is reserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveCopyTxFrame {
    pub token: CopyTxToken,
    pub visible_address: usize,
    pub requested_len: usize,
}

/// Cold description returned by block injection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InjectedCopyRxBlock {
    pub block: CopyRxBlockToken,
    pub packets: Vec<LiveCopyRxPacket>,
}

/// Independent source observer used while the I/O object is borrowed.
pub trait CopyLeaseObserver {
    fn observe_source(&self, bytes: &[u8]) -> LiveCopyRxPacket;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopySourceDisposition {
    TxAccepted {
        tx: LiveCopyTxFrame,
        endpoint: TxEndpoint,
    },
    TxRejected {
        tx: Option<LiveCopyTxFrame>,
        attempted_egress: IfId,
        endpoint: Option<TxEndpoint>,
    },
    Reclaimed(RxReclaim),
}

/// Logical terminal event for one source packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopySourceEvent {
    pub source: LiveCopyRxPacket,
    pub ingress: IfId,
    pub disposition: CopySourceDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyTxDisposition {
    Submitted,
    Rejected,
}

/// Physical TX event plus a cold, test-only payload snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyTxEvent {
    pub source: LiveCopyRxPacket,
    pub tx: LiveCopyTxFrame,
    pub endpoint: TxEndpoint,
    pub descriptor_len: usize,
    pub disposition: CopyTxDisposition,
    pub observed_payload: Vec<u8>,
}

/// Return of one complete physical RX block to the kernel-facing pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyRxBlockReturn {
    pub block: CopyRxBlockToken,
    pub packet_count: usize,
}

/// TX completion for the distinct copied destination frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyTxCompletion {
    pub tx: LiveCopyTxFrame,
    pub endpoint: TxEndpoint,
}

/// Cold proof that block validation was not repeated across partial batches.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CopyRxScanObservation {
    pub block_acquisitions: usize,
    pub descriptor_validations: usize,
}

/// Reusable capability for a backend that copies RX bytes into distinct TX
/// storage.
pub trait RxCopyHarness: Sized {
    type Io: PacketIo;
    type Observer: CopyLeaseObserver;

    fn new() -> Self;
    fn io_and_observer(&mut self) -> (&mut Self::Io, &mut Self::Observer);

    /// Injects one physical RX block. Every packet identity belongs to that
    /// block and becomes logically terminal independently.
    fn inject_rx_block(&mut self, ingress: IfId, packets: Vec<Vec<u8>>) -> InjectedCopyRxBlock;

    fn set_copy_tx_accept_budget(&mut self, budget: usize);
    fn pending_copy_rx_packets(&self) -> usize;
    fn free_copy_tx_frames(&self) -> usize;
    fn copy_rx_scan_observation(&self, block: CopyRxBlockToken) -> CopyRxScanObservation;
    fn drain_copy_source_events(&mut self) -> Vec<CopySourceEvent>;
    fn drain_copy_tx_events(&mut self) -> Vec<CopyTxEvent>;
    fn drain_copy_rx_block_returns(&mut self) -> Vec<CopyRxBlockReturn>;
    fn drain_copy_tx_kicks(&mut self) -> Vec<TxEndpoint>;
}

pub trait RxCopyFinishErrorHarness: RxCopyHarness {
    fn fail_next_copy_finish(&mut self);
}

pub trait RxCopyUnknownEgressHarness: RxCopyHarness {}

pub trait RxCopyCompletionHarness: RxCopyHarness {
    fn complete_copy_submissions(&mut self) -> Vec<CopyTxCompletion>;
    fn prefer_copy_tx_frame(&mut self, frame_id: u64);
}

fn expected_endpoint(egress: IfId) -> TxEndpoint {
    match egress {
        CONFORMANCE_LAN => CONFORMANCE_LAN_ENDPOINT,
        CONFORMANCE_WAN => CONFORMANCE_WAN_ENDPOINT,
        _ => panic!("unknown conformance endpoint"),
    }
}

fn assert_source_bindings(expected: &[LiveCopyRxPacket], events: &[CopySourceEvent]) {
    assert_eq!(events.len(), expected.len());
    for source in expected {
        assert_eq!(
            events
                .iter()
                .filter(|event| event.source.token == source.token)
                .count(),
            1,
            "source packet did not reach exactly one logical terminal"
        );
        assert!(
            events.iter().any(|event| event.source == *source),
            "source terminal changed its lease-time binding"
        );
    }
}

/// Zero budget cannot acquire or validate a block.
pub fn zero_budget_does_not_scan_or_advance<H: RxCopyHarness>() {
    let mut harness = H::new();
    let injected = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![1], vec![2]]);
    let completion = {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(0)
            .unwrap_or_else(|_| panic!("zero-budget receive failed"));
        assert!(batch.next_packet().is_none());
        batch.finish()
    };
    assert_eq!(
        (
            completion.tx_requested,
            completion.tx_accepted,
            completion.tx_rejected,
            completion.recycled,
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(harness.pending_copy_rx_packets(), 2);
    assert_eq!(
        harness.copy_rx_scan_observation(injected.block),
        CopyRxScanObservation::default()
    );
    assert!(harness.drain_copy_source_events().is_empty());
    assert!(harness.drain_copy_rx_block_returns().is_empty());
}

/// A partial budget resumes the saved block cursor and never validates the
/// same descriptor chain twice.
pub fn split_budgets_resume_without_rescan_or_early_block_return<H: RxCopyHarness>() {
    let mut harness = H::new();
    let injected = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![1], vec![2], vec![3]]);
    let mut observed = Vec::new();
    for index in 0..3 {
        {
            let (io, observer) = harness.io_and_observer();
            let mut batch = io
                .receive(1)
                .unwrap_or_else(|_| panic!("RX receive failed"));
            let mut packet = batch.next_packet().expect("saved-cursor packet");
            observed.push(observer.observe_source(packet.bytes_mut()));
            packet.recycle(DropReason::RouteMiss);
            assert!(batch.next_packet().is_none());
            assert_eq!(batch.finish().recycled, 1);
        }
        assert_eq!(
            harness.copy_rx_scan_observation(injected.block),
            CopyRxScanObservation {
                block_acquisitions: 1,
                descriptor_validations: 3,
            }
        );
        let returned = harness.drain_copy_rx_block_returns();
        if index < 2 {
            assert!(returned.is_empty(), "partial block returned early");
        } else {
            assert_eq!(
                returned,
                [CopyRxBlockReturn {
                    block: injected.block,
                    packet_count: 3,
                }]
            );
        }
    }
    assert_eq!(observed, injected.packets);
    assert_source_bindings(&injected.packets, &harness.drain_copy_source_events());
}

/// Dropping a batch cannot advance packets that were never leased.
pub fn dropped_batch_preserves_unleased_cursor<H: RxCopyHarness>() {
    let mut harness = H::new();
    let injected = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![1], vec![2], vec![3]]);
    {
        let (io, observer) = harness.io_and_observer();
        let mut batch = io
            .receive(3)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        let mut packet = batch.next_packet().expect("first packet");
        assert_eq!(
            observer.observe_source(packet.bytes_mut()),
            injected.packets[0]
        );
        packet.recycle(DropReason::RouteMiss);
        drop(batch);
    }
    assert_eq!(harness.pending_copy_rx_packets(), 2);
    assert!(harness.drain_copy_rx_block_returns().is_empty());

    let mut resumed = Vec::new();
    {
        let (io, observer) = harness.io_and_observer();
        let mut batch = io.receive(2).unwrap_or_else(|_| panic!("RX resume failed"));
        while let Some(mut packet) = batch.next_packet() {
            resumed.push(observer.observe_source(packet.bytes_mut()));
            packet.recycle(DropReason::RouteMiss);
        }
        assert_eq!(batch.finish().recycled, 2);
    }
    assert_eq!(resumed, injected.packets[1..]);
    assert_eq!(
        harness.copy_rx_scan_observation(injected.block),
        CopyRxScanObservation {
            block_acquisitions: 1,
            descriptor_validations: 3,
        }
    );
    assert_eq!(
        harness.drain_copy_rx_block_returns(),
        [CopyRxBlockReturn {
            block: injected.block,
            packet_count: 3,
        }]
    );
}

/// Accepted transmit uses separate TX storage and copies the final mutated
/// source bytes with an exact descriptor length.
pub fn transmit_uses_distinct_tx_storage_and_exact_payload<H: RxCopyHarness>() {
    let mut harness = H::new();
    let injected = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![0x10, 0x20, 0x30]]);
    let completion = {
        let (io, observer) = harness.io_and_observer();
        let mut batch = io
            .receive(1)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        let mut packet = batch.next_packet().expect("source packet");
        assert_eq!(
            observer.observe_source(packet.bytes_mut()),
            injected.packets[0]
        );
        packet.bytes_mut()[1] = 0x99;
        packet.commit(CONFORMANCE_WAN);
        batch.finish()
    };
    assert_eq!(
        (
            completion.tx_requested,
            completion.tx_accepted,
            completion.tx_rejected,
            completion.recycled,
        ),
        (1, 1, 0, 0)
    );
    let source_events = harness.drain_copy_source_events();
    assert_source_bindings(&injected.packets, &source_events);
    let CopySourceDisposition::TxAccepted { tx, endpoint } = source_events[0].disposition else {
        panic!("copy transmit was not accepted");
    };
    assert_eq!(endpoint, expected_endpoint(CONFORMANCE_WAN));
    assert_ne!(
        injected.packets[0].visible_address, tx.visible_address,
        "copy backend submitted source storage in place"
    );
    let tx_events = harness.drain_copy_tx_events();
    assert_eq!(tx_events.len(), 1);
    assert_eq!(tx_events[0].source, injected.packets[0]);
    assert_eq!(tx_events[0].tx, tx);
    assert_eq!(tx_events[0].descriptor_len, 3);
    assert_eq!(tx_events[0].observed_payload, [0x10, 0x99, 0x30]);
    assert_eq!(tx_events[0].disposition, CopyTxDisposition::Submitted);
}

/// Partial acceptance terminally consumes every source packet, immediately
/// reclaims rejected TX frames, and leaves only accepted TX frames in flight.
pub fn partial_reject_reclaims_tx_and_terminals_source<H: RxCopyHarness>() {
    let mut harness = H::new();
    harness.set_copy_tx_accept_budget(1);
    let baseline = harness.free_copy_tx_frames();
    let injected = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![1], vec![2], vec![3]]);
    let completion = {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(3)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        while let Some(packet) = batch.next_packet() {
            packet.commit(CONFORMANCE_WAN);
        }
        batch.finish()
    };
    assert_eq!(
        (
            completion.tx_requested,
            completion.tx_accepted,
            completion.tx_rejected,
            completion.recycled,
        ),
        (3, 1, 2, 0)
    );
    let source_events = harness.drain_copy_source_events();
    assert_source_bindings(&injected.packets, &source_events);
    assert_eq!(
        source_events
            .iter()
            .filter(|event| matches!(event.disposition, CopySourceDisposition::TxAccepted { .. }))
            .count(),
        1
    );
    assert_eq!(
        source_events
            .iter()
            .filter(|event| matches!(
                event.disposition,
                CopySourceDisposition::TxRejected { tx: Some(_), .. }
            ))
            .count(),
        2
    );
    let tx_events = harness.drain_copy_tx_events();
    assert_eq!(
        tx_events
            .iter()
            .filter(|event| event.disposition == CopyTxDisposition::Submitted)
            .count(),
        1
    );
    assert_eq!(
        tx_events
            .iter()
            .filter(|event| event.disposition == CopyTxDisposition::Rejected)
            .count(),
        2
    );
    assert_eq!(harness.free_copy_tx_frames() + 1, baseline);
    assert_eq!(
        harness.drain_copy_rx_block_returns(),
        [CopyRxBlockReturn {
            block: injected.block,
            packet_count: 3,
        }]
    );
}

/// Non-TX terminals remain logically distinct, while physical block return is
/// delayed until the final sibling is terminal.
pub fn recycle_consume_abandon_delay_block_return<H: RxCopyHarness>() {
    let mut harness = H::new();
    let injected = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![1], vec![2], vec![3]]);
    for marker in 1_u8..=3 {
        {
            let (io, _) = harness.io_and_observer();
            let mut batch = io
                .receive(1)
                .unwrap_or_else(|_| panic!("RX receive failed"));
            let mut packet = batch.next_packet().expect("source packet");
            assert_eq!(packet.bytes_mut()[0], marker);
            match marker {
                1 => packet.recycle(DropReason::NeighborUnresolved),
                2 => packet.consume(ConsumeReason::ArpControl),
                3 => drop(packet),
                _ => unreachable!(),
            }
            assert_eq!(batch.finish().recycled, 1);
        }
        let returned = harness.drain_copy_rx_block_returns();
        if marker < 3 {
            assert!(returned.is_empty());
        } else {
            assert_eq!(
                returned,
                [CopyRxBlockReturn {
                    block: injected.block,
                    packet_count: 3,
                }]
            );
        }
    }
    let events = harness.drain_copy_source_events();
    assert_source_bindings(&injected.packets, &events);
    assert!(matches!(
        events[0].disposition,
        CopySourceDisposition::Reclaimed(RxReclaim::Recycled(DropReason::NeighborUnresolved))
    ));
    assert!(matches!(
        events[1].disposition,
        CopySourceDisposition::Reclaimed(RxReclaim::Consumed(ConsumeReason::ArpControl))
    ));
    assert!(matches!(
        events[2].disposition,
        CopySourceDisposition::Reclaimed(RxReclaim::Abandoned)
    ));
}

/// Unknown egress terminally rejects the source without reserving TX storage.
pub fn unknown_egress_touches_no_tx_or_kick<H: RxCopyUnknownEgressHarness>() {
    let mut harness = H::new();
    let baseline = harness.free_copy_tx_frames();
    let injected = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![0x71]]);
    let completion = {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(1)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        batch
            .next_packet()
            .expect("source packet")
            .commit(CONFORMANCE_UNKNOWN);
        batch.finish()
    };
    assert_eq!((completion.tx_accepted, completion.tx_rejected), (0, 1));
    assert_eq!(harness.free_copy_tx_frames(), baseline);
    assert!(harness.drain_copy_tx_events().is_empty());
    assert!(harness.drain_copy_tx_kicks().is_empty());
    let source_events = harness.drain_copy_source_events();
    assert_source_bindings(&injected.packets, &source_events);
    assert_eq!(
        source_events[0].disposition,
        CopySourceDisposition::TxRejected {
            tx: None,
            attempted_egress: CONFORMANCE_UNKNOWN,
            endpoint: None,
        }
    );
}

/// Finish errors preserve exact accounting and never cause duplicate kicks.
pub fn finish_error_preserves_accounting_and_single_kick<H: RxCopyFinishErrorHarness>() {
    let mut harness = H::new();
    harness.fail_next_copy_finish();
    let injected = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![1], vec![2], vec![3]]);
    let completion = {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(3)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        while let Some(packet) = batch.next_packet() {
            packet.commit(CONFORMANCE_WAN);
        }
        batch.finish()
    };
    assert_eq!(
        (
            completion.tx_requested,
            completion.tx_accepted,
            completion.tx_rejected,
            completion.recycled,
        ),
        (3, 3, 0, 0)
    );
    assert!(completion.error.is_some());
    assert_source_bindings(&injected.packets, &harness.drain_copy_source_events());
    assert_eq!(
        harness.drain_copy_tx_kicks(),
        [expected_endpoint(CONFORMANCE_WAN)]
    );
}

/// RX block return follows source logical completion and does not wait for TX
/// completion.
pub fn source_block_returns_before_independent_tx_completion<H: RxCopyCompletionHarness>() {
    let mut harness = H::new();
    let baseline = harness.free_copy_tx_frames();
    let injected = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![0x81]]);
    let tx = {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(1)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        batch
            .next_packet()
            .expect("source packet")
            .commit(CONFORMANCE_WAN);
        assert_eq!(batch.finish().tx_accepted, 1);
        let source = harness.drain_copy_source_events();
        let CopySourceDisposition::TxAccepted { tx, .. } = source[0].disposition else {
            panic!("submitted TX frame");
        };
        tx
    };
    assert_eq!(
        harness.drain_copy_rx_block_returns(),
        [CopyRxBlockReturn {
            block: injected.block,
            packet_count: 1,
        }]
    );
    assert_eq!(harness.free_copy_tx_frames() + 1, baseline);
    assert_eq!(
        harness.complete_copy_submissions(),
        [CopyTxCompletion {
            tx,
            endpoint: expected_endpoint(CONFORMANCE_WAN),
        }]
    );
    assert_eq!(harness.free_copy_tx_frames(), baseline);
}

/// Reuse after completion keeps physical identity but advances generation.
pub fn completed_tx_reuse_advances_generation<H: RxCopyCompletionHarness>() {
    let mut harness = H::new();
    let first_block = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![0x91]]);
    let first = {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(1)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        batch
            .next_packet()
            .expect("source packet")
            .commit(CONFORMANCE_WAN);
        assert_eq!(batch.finish().tx_accepted, 1);
        let events = harness.drain_copy_source_events();
        let CopySourceDisposition::TxAccepted { tx, .. } = events[0].disposition else {
            panic!("submitted TX frame");
        };
        tx
    };
    assert_eq!(
        harness.complete_copy_submissions(),
        [CopyTxCompletion {
            tx: first,
            endpoint: expected_endpoint(CONFORMANCE_WAN),
        }]
    );
    harness.prefer_copy_tx_frame(first.token.frame_id);

    let second_block = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![0x92]]);
    let second = {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(1)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        batch
            .next_packet()
            .expect("source packet")
            .commit(CONFORMANCE_WAN);
        assert_eq!(batch.finish().tx_accepted, 1);
        let events = harness.drain_copy_source_events();
        let CopySourceDisposition::TxAccepted { tx, .. } = events[0].disposition else {
            panic!("submitted TX frame");
        };
        tx
    };
    assert_ne!(first_block.block, second_block.block);
    assert_eq!(second.token.frame_id, first.token.frame_id);
    assert!(
        second.token.generation > first.token.generation,
        "completed TX frame reused a stale generation"
    );
}

/// One batch may touch multiple endpoints, but each endpoint is kicked at most
/// once.
pub fn one_batch_kicks_each_endpoint_at_most_once<H: RxCopyHarness>() {
    let mut harness = H::new();
    let injected =
        harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![1], vec![2], vec![3], vec![4]]);
    let completion = {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(4)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        for index in 0_usize..4 {
            let egress = if index.is_multiple_of(2) {
                CONFORMANCE_LAN
            } else {
                CONFORMANCE_WAN
            };
            batch.next_packet().expect("source packet").commit(egress);
        }
        batch.finish()
    };
    assert_eq!((completion.tx_accepted, completion.tx_rejected), (4, 0));
    assert_source_bindings(&injected.packets, &harness.drain_copy_source_events());
    let mut kicks = harness.drain_copy_tx_kicks();
    kicks.sort_by_key(|endpoint| endpoint.interface);
    assert_eq!(
        kicks,
        [
            expected_endpoint(CONFORMANCE_LAN),
            expected_endpoint(CONFORMANCE_WAN),
        ]
    );
}

/// Exhausting the physical TX pool rejects the overflow packet without
/// replaying or retaining any source packet.
pub fn tx_pool_exhaustion_is_partial_and_source_terminal<H: RxCopyHarness>() {
    let mut harness = H::new();
    let capacity = harness.free_copy_tx_frames();
    assert!(capacity > 0);
    let packets = (0..=capacity)
        .map(|index| vec![u8::try_from(index + 1).expect("small conformance pool")])
        .collect();
    let injected = harness.inject_rx_block(CONFORMANCE_LAN, packets);
    let completion = {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(usize::MAX)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        while let Some(packet) = batch.next_packet() {
            packet.commit(CONFORMANCE_WAN);
        }
        batch.finish()
    };
    assert_eq!(completion.tx_requested, capacity + 1);
    assert_eq!(completion.tx_accepted, capacity);
    assert_eq!(completion.tx_rejected, 1);
    assert_eq!(completion.recycled, 0);
    assert_eq!(harness.pending_copy_rx_packets(), 0);
    assert_source_bindings(&injected.packets, &harness.drain_copy_source_events());
    assert_eq!(
        harness.drain_copy_rx_block_returns(),
        [CopyRxBlockReturn {
            block: injected.block,
            packet_count: capacity + 1,
        }]
    );
    assert_eq!(
        harness.drain_copy_tx_kicks(),
        [expected_endpoint(CONFORMANCE_WAN)]
    );
}
