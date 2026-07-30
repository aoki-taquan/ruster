//! Reusable conformance cases for RX-to-distinct-TX copy backends.
//!
//! Unlike the in-place [`crate::rx`] contract, this capability assigns
//! different identity domains to the source RX packet and the submitted TX
//! frame. This is required for copy backends such as AF_PACKET: completing a
//! source packet is a logical lifecycle event, while a TPACKET_V3 RX block can
//! return to the kernel only after every packet in that block is terminal.
//! Accepted TX storage remains independently in flight until completion.
//!
//! Base events are metadata-only. Optional payload snapshots and all scan
//! counters are cold test observations; production adapters keep the payload
//! hook disabled and must not clone packets for conformance.

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
    RxInvalid(CopyRxDescriptorFault),
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

/// Metadata-only physical TX event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyTxEvent {
    pub source: LiveCopyRxPacket,
    pub tx: LiveCopyTxFrame,
    pub endpoint: TxEndpoint,
    pub descriptor_len: usize,
    pub disposition: CopyTxDisposition,
    /// Bytes copied by the production copy primitive. Rejection is always
    /// zero; submission is exactly `descriptor_len`.
    pub copied_bytes: usize,
}

/// Optional cold payload observation implemented by a mock or external wire
/// capture, never by the production packet-path hook.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyPayloadObservation {
    pub source: LiveCopyRxPacket,
    pub tx: LiveCopyTxFrame,
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
    pub block_status_reads: usize,
    pub block_acquisitions: usize,
    pub descriptor_validations: usize,
}

/// Independent per-call budgets for kernel-visible status/descriptor work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyOperationBudgets {
    pub rx_block_status_reads: usize,
    pub rx_descriptor_visits: usize,
    pub tx_submit_status_reads: usize,
    pub tx_completion_status_reads: usize,
}

impl Default for CopyOperationBudgets {
    fn default() -> Self {
        Self {
            rx_block_status_reads: usize::MAX,
            rx_descriptor_visits: usize::MAX,
            tx_submit_status_reads: usize::MAX,
            tx_completion_status_reads: usize::MAX,
        }
    }
}

/// Exact production-operation observations. Test payload capture is excluded.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CopyOperationCounters {
    pub rx_block_status_reads: usize,
    pub rx_descriptor_visits: usize,
    pub tx_submit_status_reads: usize,
    pub tx_completion_status_reads: usize,
    pub copy_invocations: usize,
    pub copied_bytes: usize,
    pub kick_syscalls: usize,
    pub steady_allocations: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyRxDescriptorFault {
    /// The descriptor is locally invalid, but its checked next pointer permits
    /// one safe advance.
    SafePacket,
    /// The chain itself is unsafe. The whole block is released without walking
    /// any later descriptor.
    UnsafeChain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyRxFaultEvent {
    pub block: CopyRxBlockToken,
    pub packet_index: usize,
    pub fault: CopyRxDescriptorFault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyErrno(pub i32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyKickEvent {
    pub endpoint: TxEndpoint,
    pub result: Result<(), CopyErrno>,
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
    fn set_copy_operation_budgets(&mut self, budgets: CopyOperationBudgets);
    fn pending_copy_rx_packets(&self) -> usize;
    fn free_copy_tx_frames(&self) -> usize;
    fn inflight_copy_tx_frames(&self) -> usize;
    fn copy_operation_counters(&self) -> CopyOperationCounters;
    /// Must remain false for a production adapter. Payload inspection belongs
    /// to [`RxCopyPayloadHarness`] or an external wire capture.
    fn production_payload_hook_enabled(&self) -> bool;
    fn copy_rx_scan_observation(&self, block: CopyRxBlockToken) -> CopyRxScanObservation;
    fn drain_copy_source_events(&mut self) -> Vec<CopySourceEvent>;
    fn drain_copy_tx_events(&mut self) -> Vec<CopyTxEvent>;
    fn drain_copy_rx_block_returns(&mut self) -> Vec<CopyRxBlockReturn>;
    fn drain_copy_tx_kicks(&mut self) -> Vec<CopyKickEvent>;
}

pub trait RxCopyFinishErrorHarness: RxCopyHarness {
    fn fail_next_copy_finish(&mut self);
}

pub trait RxCopyKickErrorHarness: RxCopyHarness {
    fn fail_next_copy_kick(&mut self, errno: CopyErrno);
}

pub trait RxCopyUnknownEgressHarness: RxCopyHarness {}

pub trait RxCopyCompletionHarness: RxCopyHarness {
    fn complete_copy_submissions(&mut self) -> Vec<CopyTxCompletion>;
    fn prefer_copy_tx_frame(&mut self, frame_id: u64);
    fn prefer_copy_rx_block(&mut self, block_id: u64);
    fn set_copy_completion_head_sending(&mut self, sending: bool);
}

pub trait RxCopyPayloadHarness: RxCopyHarness {
    fn drain_copy_payload_observations(&mut self) -> Vec<CopyPayloadObservation>;
}

pub trait RxCopyAdversarialHarness: RxCopyCompletionHarness {
    fn inject_rx_block_with_fault(
        &mut self,
        ingress: IfId,
        packets: Vec<Vec<u8>>,
        packet_index: usize,
        fault: CopyRxDescriptorFault,
    ) -> InjectedCopyRxBlock;
    fn drain_copy_rx_faults(&mut self) -> Vec<CopyRxFaultEvent>;
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
                block_status_reads: 1,
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
            block_status_reads: 1,
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
pub fn transmit_uses_distinct_tx_storage_and_exact_payload<H: RxCopyPayloadHarness>() {
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
    assert_eq!(tx_events[0].copied_bytes, 3);
    assert_eq!(tx_events[0].disposition, CopyTxDisposition::Submitted);
    let payloads = harness.drain_copy_payload_observations();
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0].source, injected.packets[0]);
    assert_eq!(payloads[0].tx, tx);
    assert_eq!(payloads[0].observed_payload, [0x10, 0x99, 0x30]);
    assert!(!harness.production_payload_hook_enabled());
    let counters = harness.copy_operation_counters();
    assert_eq!(counters.copy_invocations, 1);
    assert_eq!(counters.copied_bytes, 3);
    assert_eq!(counters.steady_allocations, 0);
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
    for event in &tx_events {
        assert_eq!(
            tx_events
                .iter()
                .filter(|candidate| candidate.tx.token == event.tx.token)
                .count(),
            1,
            "finish error duplicated a TX ownership token"
        );
    }
    assert!(tx_events.iter().all(|event| {
        match event.disposition {
            CopyTxDisposition::Submitted => event.copied_bytes == event.descriptor_len,
            CopyTxDisposition::Rejected => event.copied_bytes == 0 && event.descriptor_len == 0,
        }
    }));
    let counters = harness.copy_operation_counters();
    assert_eq!(counters.copy_invocations, 1);
    assert_eq!(counters.copied_bytes, 1);
    assert_eq!(counters.steady_allocations, 0);
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
pub fn finish_error_preserves_accounting_and_single_kick<H>()
where
    H: RxCopyFinishErrorHarness + RxCopyCompletionHarness,
{
    let mut harness = H::new();
    harness.set_copy_tx_accept_budget(1);
    harness.fail_next_copy_finish();
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
    assert!(completion.error.is_some());
    let sources = harness.drain_copy_source_events();
    assert_source_bindings(&injected.packets, &sources);
    let accepted = sources
        .iter()
        .find_map(|event| match event.disposition {
            CopySourceDisposition::TxAccepted { tx, endpoint } => Some((tx, endpoint)),
            _ => None,
        })
        .expect("one accepted TX");
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
            .filter(|event| {
                event.disposition == CopyTxDisposition::Rejected
                    && event.copied_bytes == 0
                    && event.descriptor_len == 0
            })
            .count(),
        2
    );
    assert_eq!(
        harness.drain_copy_rx_block_returns(),
        [CopyRxBlockReturn {
            block: injected.block,
            packet_count: 3,
        }]
    );
    assert_eq!(harness.free_copy_tx_frames() + 1, baseline);
    assert_eq!(harness.inflight_copy_tx_frames(), 1);
    assert_eq!(
        harness.drain_copy_tx_kicks(),
        [CopyKickEvent {
            endpoint: expected_endpoint(CONFORMANCE_WAN),
            result: Ok(()),
        }]
    );
    assert_eq!(
        harness.complete_copy_submissions(),
        [CopyTxCompletion {
            tx: accepted.0,
            endpoint: accepted.1,
        }]
    );
    assert!(harness.complete_copy_submissions().is_empty());
    assert_eq!(harness.free_copy_tx_frames(), baseline);
    assert_eq!(harness.inflight_copy_tx_frames(), 0);
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
    kicks.sort_by_key(|event| event.endpoint.interface);
    assert_eq!(
        kicks,
        [
            CopyKickEvent {
                endpoint: expected_endpoint(CONFORMANCE_LAN),
                result: Ok(()),
            },
            CopyKickEvent {
                endpoint: expected_endpoint(CONFORMANCE_WAN),
                result: Ok(()),
            },
        ]
    );
    let counters = harness.copy_operation_counters();
    assert_eq!(counters.kick_syscalls, 2);
    assert_eq!(counters.copy_invocations, 4);
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
        [CopyKickEvent {
            endpoint: expected_endpoint(CONFORMANCE_WAN),
            result: Ok(()),
        }]
    );
}

/// Descriptor/status budgets are independent, persist validation progress, and
/// stop an unsafe chain without walking a declared huge suffix.
pub fn validation_budgets_and_fault_advance_are_bounded<H: RxCopyAdversarialHarness>() {
    let mut harness = H::new();
    harness.set_copy_operation_budgets(CopyOperationBudgets {
        rx_block_status_reads: 0,
        rx_descriptor_visits: usize::MAX,
        ..CopyOperationBudgets::default()
    });
    let safe = harness.inject_rx_block_with_fault(
        CONFORMANCE_LAN,
        vec![vec![1], vec![2], vec![3]],
        1,
        CopyRxDescriptorFault::SafePacket,
    );
    {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(3)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        assert!(batch.next_packet().is_none());
        batch.finish();
    }
    assert_eq!(
        harness.copy_rx_scan_observation(safe.block),
        CopyRxScanObservation::default()
    );
    harness.set_copy_operation_budgets(CopyOperationBudgets {
        rx_block_status_reads: 1,
        rx_descriptor_visits: 1,
        ..CopyOperationBudgets::default()
    });
    for _ in 0..2 {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(3)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        assert!(batch.next_packet().is_none());
        batch.finish();
    }
    {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(3)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        while let Some(packet) = batch.next_packet() {
            packet.recycle(DropReason::RouteMiss);
        }
        assert_eq!(batch.finish().recycled, 2);
    }
    assert_eq!(
        harness.copy_rx_scan_observation(safe.block),
        CopyRxScanObservation {
            block_status_reads: 1,
            block_acquisitions: 1,
            descriptor_validations: 3,
        }
    );
    assert_eq!(
        harness.drain_copy_rx_faults(),
        [CopyRxFaultEvent {
            block: safe.block,
            packet_index: 1,
            fault: CopyRxDescriptorFault::SafePacket,
        }]
    );
    assert_eq!(
        harness.drain_copy_rx_block_returns(),
        [CopyRxBlockReturn {
            block: safe.block,
            packet_count: 3,
        }]
    );

    harness.set_copy_operation_budgets(CopyOperationBudgets {
        rx_block_status_reads: 1,
        rx_descriptor_visits: usize::MAX,
        ..CopyOperationBudgets::default()
    });
    let huge_packets = (0..4_096).map(|_| vec![0xa5]).collect();
    let unsafe_block = harness.inject_rx_block_with_fault(
        CONFORMANCE_LAN,
        huge_packets,
        1,
        CopyRxDescriptorFault::UnsafeChain,
    );
    let before = harness.copy_operation_counters();
    {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(usize::MAX)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        assert!(batch.next_packet().is_none());
        batch.finish();
    }
    let after = harness.copy_operation_counters();
    assert_eq!(
        after.rx_block_status_reads - before.rx_block_status_reads,
        1
    );
    assert_eq!(after.rx_descriptor_visits - before.rx_descriptor_visits, 2);
    assert_eq!(
        harness.copy_rx_scan_observation(unsafe_block.block),
        CopyRxScanObservation {
            block_status_reads: 1,
            block_acquisitions: 1,
            descriptor_validations: 2,
        }
    );
    assert_eq!(
        harness.drain_copy_rx_faults(),
        [CopyRxFaultEvent {
            block: unsafe_block.block,
            packet_index: 1,
            fault: CopyRxDescriptorFault::UnsafeChain,
        }]
    );
}

/// A locally invalid packet is terminal exactly once at every boundary
/// position. Its hole is skipped by the persistent lease cursor without
/// rescanning descriptors or delaying the physical block return.
pub fn safe_packet_fault_positions_are_terminal_exactly_once<H: RxCopyAdversarialHarness>() {
    for (packet_count, fault_index) in [(3, 0), (3, 2), (1, 0)] {
        let mut harness = H::new();
        harness.set_copy_operation_budgets(CopyOperationBudgets {
            rx_block_status_reads: 1,
            rx_descriptor_visits: packet_count,
            ..CopyOperationBudgets::default()
        });
        let payloads = (0..packet_count)
            .map(|index| vec![u8::try_from(index + 1).expect("small fixture")])
            .collect();
        let injected = harness.inject_rx_block_with_fault(
            CONFORMANCE_LAN,
            payloads,
            fault_index,
            CopyRxDescriptorFault::SafePacket,
        );
        {
            let (io, _) = harness.io_and_observer();
            let mut batch = io
                .receive(packet_count)
                .unwrap_or_else(|_| panic!("RX receive failed"));
            while let Some(packet) = batch.next_packet() {
                packet.recycle(DropReason::RouteMiss);
            }
            assert_eq!(batch.finish().recycled, packet_count - 1);
        }
        assert_eq!(harness.pending_copy_rx_packets(), 0);
        assert_eq!(
            harness.copy_rx_scan_observation(injected.block),
            CopyRxScanObservation {
                block_status_reads: 1,
                block_acquisitions: 1,
                descriptor_validations: packet_count,
            }
        );
        assert_eq!(
            harness.drain_copy_rx_faults(),
            [CopyRxFaultEvent {
                block: injected.block,
                packet_index: fault_index,
                fault: CopyRxDescriptorFault::SafePacket,
            }]
        );
        let source_events = harness.drain_copy_source_events();
        assert_source_bindings(&injected.packets, &source_events);
        for (index, source) in injected.packets.iter().enumerate() {
            let event = source_events
                .iter()
                .find(|event| event.source == *source)
                .expect("source terminal");
            let expected = if index == fault_index {
                CopySourceDisposition::RxInvalid(CopyRxDescriptorFault::SafePacket)
            } else {
                CopySourceDisposition::Reclaimed(RxReclaim::Recycled(DropReason::RouteMiss))
            };
            assert_eq!(event.disposition, expected);
        }
        assert_eq!(
            harness.drain_copy_rx_block_returns(),
            [CopyRxBlockReturn {
                block: injected.block,
                packet_count,
            }]
        );
    }
}

/// TX status-read exhaustion rejects without copying; accepted bytes have one
/// and only one copy invocation.
pub fn submit_status_budget_precedes_copy<H: RxCopyHarness>() {
    let mut harness = H::new();
    harness.set_copy_operation_budgets(CopyOperationBudgets {
        tx_submit_status_reads: 1,
        ..CopyOperationBudgets::default()
    });
    let injected = harness.inject_rx_block(
        CONFORMANCE_LAN,
        vec![vec![1, 1], vec![2, 2, 2], vec![3, 3, 3, 3]],
    );
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
    let counters = harness.copy_operation_counters();
    assert_eq!(counters.tx_submit_status_reads, 1);
    assert_eq!(counters.copy_invocations, 1);
    assert_eq!(counters.copied_bytes, 2);
    assert_eq!(counters.steady_allocations, 0);
    assert_source_bindings(&injected.packets, &harness.drain_copy_source_events());
    assert!(harness
        .drain_copy_tx_events()
        .iter()
        .all(|event| event.disposition == CopyTxDisposition::Submitted && event.copied_bytes == 2));
    assert_eq!(
        harness.drain_copy_tx_kicks(),
        [CopyKickEvent {
            endpoint: expected_endpoint(CONFORMANCE_WAN),
            result: Ok(()),
        }]
    );
}

/// Completion reads are bounded and a SENDING head prevents skipping to later
/// AVAILABLE entries.
pub fn completion_budget_and_sending_head_are_bounded<H: RxCopyCompletionHarness>() {
    let mut harness = H::new();
    let injected = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![1], vec![2], vec![3]]);
    {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(3)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        while let Some(packet) = batch.next_packet() {
            packet.commit(CONFORMANCE_WAN);
        }
        assert_eq!(batch.finish().tx_accepted, 3);
    }
    assert_source_bindings(&injected.packets, &harness.drain_copy_source_events());
    harness.set_copy_operation_budgets(CopyOperationBudgets {
        tx_completion_status_reads: 0,
        ..CopyOperationBudgets::default()
    });
    assert!(harness.complete_copy_submissions().is_empty());
    assert_eq!(
        harness.copy_operation_counters().tx_completion_status_reads,
        0
    );
    harness.set_copy_operation_budgets(CopyOperationBudgets {
        tx_completion_status_reads: 1,
        ..CopyOperationBudgets::default()
    });
    harness.set_copy_completion_head_sending(true);
    assert!(harness.complete_copy_submissions().is_empty());
    assert_eq!(
        harness.copy_operation_counters().tx_completion_status_reads,
        1
    );
    harness.set_copy_completion_head_sending(false);
    let mut completions = Vec::new();
    for expected_len in 1..=3 {
        let completed = harness.complete_copy_submissions();
        assert_eq!(completed.len(), 1);
        completions.extend(completed);
        assert_eq!(completions.len(), expected_len);
    }
    assert!(harness.complete_copy_submissions().is_empty());
    assert_eq!(
        harness.copy_operation_counters().tx_completion_status_reads,
        4
    );
}

/// Dropping a completion-capable batch still publishes and kicks an accepted
/// packet while preserving unleased siblings and exact CQ ownership.
pub fn completion_capable_batch_drop_is_exact<H: RxCopyCompletionHarness>() {
    let mut harness = H::new();
    let baseline = harness.free_copy_tx_frames();
    let injected = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![1], vec![2], vec![3]]);
    {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(3)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        batch
            .next_packet()
            .expect("first source")
            .commit(CONFORMANCE_WAN);
        drop(batch);
    }
    assert_eq!(harness.pending_copy_rx_packets(), 2);
    assert!(
        harness.drain_copy_rx_block_returns().is_empty(),
        "source block returned before its unleased siblings became terminal"
    );
    let events = harness.drain_copy_source_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].source, injected.packets[0]);
    assert_eq!(events[0].ingress, CONFORMANCE_LAN);
    let CopySourceDisposition::TxAccepted { tx, endpoint } = events[0].disposition else {
        panic!("dropped batch lost accepted TX");
    };
    let tx_events = harness.drain_copy_tx_events();
    assert_eq!(
        tx_events,
        [CopyTxEvent {
            source: injected.packets[0],
            tx,
            endpoint,
            descriptor_len: 1,
            disposition: CopyTxDisposition::Submitted,
            copied_bytes: 1,
        }]
    );
    assert_eq!(harness.free_copy_tx_frames() + 1, baseline);
    assert_eq!(
        harness.drain_copy_tx_kicks(),
        [CopyKickEvent {
            endpoint,
            result: Ok(()),
        }]
    );
    assert_eq!(
        harness.complete_copy_submissions(),
        [CopyTxCompletion { tx, endpoint }]
    );
    assert_eq!(harness.free_copy_tx_frames(), baseline);
    {
        let (io, _) = harness.io_and_observer();
        let mut batch = io.receive(2).unwrap_or_else(|_| panic!("RX resume failed"));
        while let Some(packet) = batch.next_packet() {
            packet.recycle(DropReason::RouteMiss);
        }
        assert_eq!(batch.finish().recycled, 2);
    }
    assert_eq!(
        harness.drain_copy_rx_block_returns(),
        [CopyRxBlockReturn {
            block: injected.block,
            packet_count: 3,
        }]
    );
}

/// A kick errno is reported once without retry; already published descriptors
/// remain accepted and complete normally.
pub fn kick_errno_has_no_retry_or_reclassification<H>()
where
    H: RxCopyKickErrorHarness + RxCopyCompletionHarness,
{
    let mut harness = H::new();
    harness.fail_next_copy_kick(CopyErrno(11));
    let baseline = harness.free_copy_tx_frames();
    harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![1], vec![2]]);
    let completion = {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(2)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        while let Some(packet) = batch.next_packet() {
            packet.commit(CONFORMANCE_WAN);
        }
        batch.finish()
    };
    assert_eq!((completion.tx_accepted, completion.tx_rejected), (2, 0));
    assert!(completion.error.is_some());
    assert_eq!(
        harness.drain_copy_tx_kicks(),
        [CopyKickEvent {
            endpoint: expected_endpoint(CONFORMANCE_WAN),
            result: Err(CopyErrno(11)),
        }]
    );
    assert_eq!(harness.copy_operation_counters().kick_syscalls, 1);
    assert_eq!(harness.complete_copy_submissions().len(), 2);
    assert_eq!(harness.free_copy_tx_frames(), baseline);
}

/// Immediate reject returns the same physical TX frame, but the next
/// reservation must use a strictly newer generation.
pub fn rejected_tx_reuse_advances_generation<H: RxCopyCompletionHarness>() {
    let mut harness = H::new();
    harness.set_copy_tx_accept_budget(0);
    let first_block = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![1]]);
    let first = {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(1)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        batch.next_packet().expect("source").commit(CONFORMANCE_WAN);
        assert_eq!(batch.finish().tx_rejected, 1);
        let events = harness.drain_copy_source_events();
        let CopySourceDisposition::TxRejected { tx: Some(tx), .. } = events[0].disposition else {
            panic!("rejected physical TX token");
        };
        tx
    };
    harness.prefer_copy_tx_frame(first.token.frame_id);
    let second_block = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![2]]);
    let second = {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(1)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        batch.next_packet().expect("source").commit(CONFORMANCE_WAN);
        assert_eq!(batch.finish().tx_rejected, 1);
        let events = harness.drain_copy_source_events();
        let CopySourceDisposition::TxRejected { tx: Some(tx), .. } = events[0].disposition else {
            panic!("rejected physical TX token");
        };
        tx
    };
    assert_ne!(first_block.block, second_block.block);
    assert_eq!(second.token.frame_id, first.token.frame_id);
    assert!(second.token.generation > first.token.generation);
    assert!(harness
        .drain_copy_tx_events()
        .iter()
        .all(|event| event.copied_bytes == 0 && event.descriptor_len == 0));
    assert_eq!(harness.copy_operation_counters().copy_invocations, 0);
}

/// A returned physical RX block keeps its block id but advances a nonzero
/// generation before reuse.
pub fn returned_rx_block_reuse_advances_generation<H: RxCopyCompletionHarness>() {
    let mut harness = H::new();
    let first = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![1]]);
    {
        let (io, _) = harness.io_and_observer();
        let mut batch = io
            .receive(1)
            .unwrap_or_else(|_| panic!("RX receive failed"));
        batch
            .next_packet()
            .expect("source")
            .recycle(DropReason::RouteMiss);
        batch.finish();
    }
    harness.drain_copy_rx_block_returns();
    harness.prefer_copy_rx_block(first.block.block_id);
    let second = harness.inject_rx_block(CONFORMANCE_LAN, vec![vec![2]]);
    assert_eq!(second.block.block_id, first.block.block_id);
    assert_ne!(second.block, first.block);
    assert_ne!(first.block.generation, 0);
    assert!(second.block.generation > first.block.generation);
    assert_ne!(first.packets[0].token, second.packets[0].token);
}
