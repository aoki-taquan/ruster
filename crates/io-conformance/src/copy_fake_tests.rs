use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    rc::Rc,
};

use ruster_core::{
    BatchCompletion, PacketBatch, PacketIo, PacketLease, PacketSlot, SlotCompletion,
};

use super::{
    rx_copy::{
        self, CopyLeaseObserver, CopyRxBlockReturn, CopyRxBlockToken, CopyRxPacketToken,
        CopyRxScanObservation, CopySourceDisposition, CopySourceEvent, CopyTxCompletion,
        CopyTxDisposition, CopyTxEvent, CopyTxToken, InjectedCopyRxBlock, LiveCopyRxPacket,
        LiveCopyTxFrame, RxCopyCompletionHarness, RxCopyFinishErrorHarness, RxCopyHarness,
        RxCopyUnknownEgressHarness,
    },
    RxReclaim, TxEndpoint, CONFORMANCE_LAN_ENDPOINT, CONFORMANCE_WAN_ENDPOINT,
};

const TX_FRAME_CAPACITY: usize = 128;
const TX_FRAME_COUNT: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CopyFakeError {
    InjectedFinish,
}

struct SourcePacket {
    live: LiveCopyRxPacket,
    ingress: ruster_core::IfId,
    storage: Box<[u8]>,
}

impl SourcePacket {
    fn bytes(&self) -> &[u8] {
        &self.storage
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.storage
    }
}

struct SourceBlock {
    token: CopyRxBlockToken,
    packets: Vec<Option<SourcePacket>>,
    cursor: usize,
    terminals: usize,
    validated: bool,
}

struct TxFrame {
    id: u64,
    storage: Box<[u8; TX_FRAME_CAPACITY]>,
    len: usize,
}

impl TxFrame {
    fn new(id: u64) -> Self {
        Self {
            id,
            storage: Box::new([0; TX_FRAME_CAPACITY]),
            len: 0,
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.storage[..self.len]
    }

    fn copy_from(&mut self, bytes: &[u8]) {
        assert!(bytes.len() <= TX_FRAME_CAPACITY);
        self.len = bytes.len();
        self.storage[..self.len].copy_from_slice(bytes);
    }
}

struct SubmittedTx {
    frame: TxFrame,
    live: LiveCopyTxFrame,
    endpoint: TxEndpoint,
}

struct CopyState {
    blocks: VecDeque<SourceBlock>,
    source_live: BTreeMap<usize, LiveCopyRxPacket>,
    free_tx: Vec<TxFrame>,
    submitted_tx: Vec<SubmittedTx>,
    tx_generations: BTreeMap<u64, u64>,
    preferred_tx: Option<u64>,
    next_block_id: u64,
    scans: BTreeMap<CopyRxBlockToken, CopyRxScanObservation>,
    source_events: Vec<CopySourceEvent>,
    tx_events: Vec<CopyTxEvent>,
    block_returns: Vec<CopyRxBlockReturn>,
    kicks: Vec<TxEndpoint>,
    tx_accept_budget: usize,
    fail_next_finish: bool,
}

impl CopyState {
    fn new() -> Self {
        Self {
            blocks: VecDeque::new(),
            source_live: BTreeMap::new(),
            free_tx: (0..TX_FRAME_COUNT)
                .map(|index| TxFrame::new(index as u64 + 1))
                .collect(),
            submitted_tx: Vec::new(),
            tx_generations: BTreeMap::new(),
            preferred_tx: None,
            next_block_id: 1,
            scans: BTreeMap::new(),
            source_events: Vec::new(),
            tx_events: Vec::new(),
            block_returns: Vec::new(),
            kicks: Vec::new(),
            tx_accept_budget: usize::MAX,
            fail_next_finish: false,
        }
    }

    fn endpoint(egress: ruster_core::IfId) -> Option<TxEndpoint> {
        match egress {
            interface if interface == CONFORMANCE_LAN_ENDPOINT.interface => {
                Some(CONFORMANCE_LAN_ENDPOINT)
            }
            interface if interface == CONFORMANCE_WAN_ENDPOINT.interface => {
                Some(CONFORMANCE_WAN_ENDPOINT)
            }
            _ => None,
        }
    }

    fn take_tx(&mut self) -> Option<TxFrame> {
        if let Some(preferred) = self.preferred_tx.take() {
            if let Some(index) = self.free_tx.iter().position(|frame| frame.id == preferred) {
                return Some(self.free_tx.swap_remove(index));
            }
        }
        self.free_tx.pop()
    }

    fn bind_tx(&mut self, frame: &TxFrame) -> LiveCopyTxFrame {
        let generation = self.tx_generations.entry(frame.id).or_default();
        *generation = generation
            .checked_add(1)
            .expect("fake TX generation overflow");
        LiveCopyTxFrame {
            token: CopyTxToken {
                frame_id: frame.id,
                generation: *generation,
            },
            visible_address: frame.bytes().as_ptr() as usize,
            requested_len: frame.len,
        }
    }

    fn terminal_source(&mut self, packet: SourcePacket, disposition: CopySourceDisposition) {
        assert_eq!(
            self.source_live.remove(&packet.live.visible_address),
            Some(packet.live)
        );
        self.source_events.push(CopySourceEvent {
            source: packet.live,
            ingress: packet.ingress,
            disposition,
        });
        let block = self
            .blocks
            .iter_mut()
            .find(|block| block.token == packet.live.token.block)
            .expect("source block remains until every packet is terminal");
        block.terminals += 1;
        if block.terminals == block.packets.len() {
            assert_eq!(
                block.cursor,
                block.packets.len(),
                "block returned with an unleased packet"
            );
            let packet_count = block.packets.len();
            let token = block.token;
            let index = self
                .blocks
                .iter()
                .position(|candidate| candidate.token == token)
                .expect("terminal block");
            self.blocks.remove(index);
            self.block_returns.push(CopyRxBlockReturn {
                block: token,
                packet_count,
            });
        }
    }
}

#[derive(Default)]
struct CopyBatchState {
    tx_requested: usize,
    tx_accepted: usize,
    tx_rejected: usize,
    recycled: usize,
    remaining_accepts: usize,
    touched: Vec<TxEndpoint>,
}

impl CopyBatchState {
    fn touch(&mut self, endpoint: TxEndpoint) {
        if !self.touched.contains(&endpoint) {
            self.touched.push(endpoint);
        }
    }
}

struct CopyFakeIo(Rc<RefCell<CopyState>>);

struct CopyFakeObserver(Rc<RefCell<CopyState>>);

impl CopyLeaseObserver for CopyFakeObserver {
    fn observe_source(&self, bytes: &[u8]) -> LiveCopyRxPacket {
        let address = bytes.as_ptr() as usize;
        let state = self.0.borrow();
        let live = *state
            .source_live
            .get(&address)
            .expect("source bytes have no live identity");
        assert_eq!(bytes.len(), live.requested_len);
        live
    }
}

struct CopyFakeBatch {
    state: Rc<RefCell<CopyState>>,
    counters: Rc<RefCell<CopyBatchState>>,
    remaining: usize,
    fail_finish: bool,
    finished: bool,
}

impl CopyFakeBatch {
    fn finish_inner(&mut self) -> BatchCompletion<CopyFakeError> {
        assert!(!self.finished, "copy batch finished twice");
        self.finished = true;
        let counters = self.counters.borrow();
        let mut state = self.state.borrow_mut();
        state.kicks.extend(counters.touched.iter().copied());
        BatchCompletion {
            tx_requested: counters.tx_requested,
            tx_accepted: counters.tx_accepted,
            tx_rejected: counters.tx_rejected,
            recycled: counters.recycled,
            error: self.fail_finish.then_some(CopyFakeError::InjectedFinish),
        }
    }
}

impl Drop for CopyFakeBatch {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish_inner();
        }
    }
}

struct CopyFakeSlot {
    state: Rc<RefCell<CopyState>>,
    counters: Rc<RefCell<CopyBatchState>>,
    packet: Option<SourcePacket>,
}

impl PacketSlot for CopyFakeSlot {
    fn ingress(&self) -> ruster_core::IfId {
        self.packet.as_ref().expect("live source slot").ingress
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.packet.as_mut().expect("live source slot").bytes_mut()
    }

    fn complete(mut self, completion: SlotCompletion) {
        let packet = self.packet.take().expect("source slot completed once");
        let mut state = self.state.borrow_mut();
        let mut counters = self.counters.borrow_mut();
        let disposition = match completion {
            SlotCompletion::Transmit(egress) => {
                counters.tx_requested += 1;
                let Some(endpoint) = CopyState::endpoint(egress) else {
                    counters.tx_rejected += 1;
                    state.terminal_source(
                        packet,
                        CopySourceDisposition::TxRejected {
                            tx: None,
                            attempted_egress: egress,
                            endpoint: None,
                        },
                    );
                    return;
                };
                let Some(mut tx_frame) = state.take_tx() else {
                    counters.tx_rejected += 1;
                    state.terminal_source(
                        packet,
                        CopySourceDisposition::TxRejected {
                            tx: None,
                            attempted_egress: egress,
                            endpoint: Some(endpoint),
                        },
                    );
                    return;
                };
                tx_frame.copy_from(packet.bytes());
                let tx = state.bind_tx(&tx_frame);
                let accepted = counters.remaining_accepts != 0;
                if accepted {
                    counters.remaining_accepts -= 1;
                    counters.tx_accepted += 1;
                    counters.touch(endpoint);
                    state.tx_events.push(CopyTxEvent {
                        source: packet.live,
                        tx,
                        endpoint,
                        descriptor_len: packet.bytes().len(),
                        disposition: CopyTxDisposition::Submitted,
                        observed_payload: tx_frame.bytes().to_vec(),
                    });
                    state.submitted_tx.push(SubmittedTx {
                        frame: tx_frame,
                        live: tx,
                        endpoint,
                    });
                    CopySourceDisposition::TxAccepted { tx, endpoint }
                } else {
                    counters.tx_rejected += 1;
                    state.tx_events.push(CopyTxEvent {
                        source: packet.live,
                        tx,
                        endpoint,
                        descriptor_len: packet.bytes().len(),
                        disposition: CopyTxDisposition::Rejected,
                        observed_payload: tx_frame.bytes().to_vec(),
                    });
                    state.free_tx.push(tx_frame);
                    CopySourceDisposition::TxRejected {
                        tx: Some(tx),
                        attempted_egress: egress,
                        endpoint: Some(endpoint),
                    }
                }
            }
            SlotCompletion::Recycle(reason) => {
                counters.recycled += 1;
                CopySourceDisposition::Reclaimed(RxReclaim::Recycled(reason))
            }
            SlotCompletion::Consume(reason) => {
                counters.recycled += 1;
                CopySourceDisposition::Reclaimed(RxReclaim::Consumed(reason))
            }
            SlotCompletion::LeaseAbandoned => {
                counters.recycled += 1;
                CopySourceDisposition::Reclaimed(RxReclaim::Abandoned)
            }
        };
        state.terminal_source(packet, disposition);
    }
}

impl PacketBatch for CopyFakeBatch {
    type Error = CopyFakeError;
    type Slot<'a>
        = CopyFakeSlot
    where
        Self: 'a;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        if self.remaining == 0 {
            return None;
        }
        let packet = {
            let mut state = self.state.borrow_mut();
            let block = state.blocks.front_mut()?;
            let index = block.cursor;
            let packet = block.packets.get_mut(index)?.take()?;
            block.cursor += 1;
            packet
        };
        self.remaining -= 1;
        Some(PacketLease::new(CopyFakeSlot {
            state: Rc::clone(&self.state),
            counters: Rc::clone(&self.counters),
            packet: Some(packet),
        }))
    }

    fn finish(mut self) -> BatchCompletion<Self::Error> {
        self.finish_inner()
    }
}

impl PacketIo for CopyFakeIo {
    type Error = CopyFakeError;
    type Batch<'a> = CopyFakeBatch;

    fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
        let (remaining, accept_budget, fail_finish) = {
            let mut state = self.0.borrow_mut();
            let fail_finish = std::mem::take(&mut state.fail_next_finish);
            let accept_budget = state.tx_accept_budget;
            let remaining = if budget == 0 {
                0
            } else if !state.blocks.is_empty() {
                let (remaining, scan) = {
                    let block = state.blocks.front_mut().expect("checked nonempty");
                    let scan = if block.validated {
                        None
                    } else {
                        block.validated = true;
                        Some((block.token, block.packets.len()))
                    };
                    (budget.min(block.packets.len() - block.cursor), scan)
                };
                if let Some((token, descriptor_validations)) = scan {
                    state.scans.insert(
                        token,
                        CopyRxScanObservation {
                            block_acquisitions: 1,
                            descriptor_validations,
                        },
                    );
                }
                remaining
            } else {
                0
            };
            (remaining, accept_budget, fail_finish)
        };
        Ok(CopyFakeBatch {
            state: Rc::clone(&self.0),
            counters: Rc::new(RefCell::new(CopyBatchState {
                remaining_accepts: accept_budget,
                ..CopyBatchState::default()
            })),
            remaining,
            fail_finish,
            finished: false,
        })
    }
}

struct CopyFakeHarness {
    io: CopyFakeIo,
    observer: CopyFakeObserver,
}

impl RxCopyHarness for CopyFakeHarness {
    type Io = CopyFakeIo;
    type Observer = CopyFakeObserver;

    fn new() -> Self {
        let state = Rc::new(RefCell::new(CopyState::new()));
        Self {
            io: CopyFakeIo(Rc::clone(&state)),
            observer: CopyFakeObserver(state),
        }
    }

    fn io_and_observer(&mut self) -> (&mut Self::Io, &mut Self::Observer) {
        (&mut self.io, &mut self.observer)
    }

    fn inject_rx_block(
        &mut self,
        ingress: ruster_core::IfId,
        packets: Vec<Vec<u8>>,
    ) -> InjectedCopyRxBlock {
        assert!(!packets.is_empty());
        let mut state = self.io.0.borrow_mut();
        let token = CopyRxBlockToken {
            block_id: state.next_block_id,
            generation: 1,
        };
        state.next_block_id += 1;
        let mut source_packets = Vec::with_capacity(packets.len());
        let mut live_packets = Vec::with_capacity(packets.len());
        for (packet_index, bytes) in packets.into_iter().enumerate() {
            let storage = bytes.into_boxed_slice();
            let live = LiveCopyRxPacket {
                token: CopyRxPacketToken {
                    block: token,
                    packet_index: u32::try_from(packet_index).expect("small fake block"),
                },
                visible_address: storage.as_ptr() as usize,
                requested_len: storage.len(),
            };
            assert!(state
                .source_live
                .insert(live.visible_address, live)
                .is_none());
            live_packets.push(live);
            source_packets.push(Some(SourcePacket {
                live,
                ingress,
                storage,
            }));
        }
        state.blocks.push_back(SourceBlock {
            token,
            packets: source_packets,
            cursor: 0,
            terminals: 0,
            validated: false,
        });
        InjectedCopyRxBlock {
            block: token,
            packets: live_packets,
        }
    }

    fn set_copy_tx_accept_budget(&mut self, budget: usize) {
        self.io.0.borrow_mut().tx_accept_budget = budget;
    }

    fn pending_copy_rx_packets(&self) -> usize {
        self.io
            .0
            .borrow()
            .blocks
            .iter()
            .map(|block| {
                block
                    .packets
                    .iter()
                    .filter(|packet| packet.is_some())
                    .count()
            })
            .sum()
    }

    fn free_copy_tx_frames(&self) -> usize {
        self.io.0.borrow().free_tx.len()
    }

    fn copy_rx_scan_observation(&self, block: CopyRxBlockToken) -> CopyRxScanObservation {
        self.io
            .0
            .borrow()
            .scans
            .get(&block)
            .copied()
            .unwrap_or_default()
    }

    fn drain_copy_source_events(&mut self) -> Vec<CopySourceEvent> {
        std::mem::take(&mut self.io.0.borrow_mut().source_events)
    }

    fn drain_copy_tx_events(&mut self) -> Vec<CopyTxEvent> {
        std::mem::take(&mut self.io.0.borrow_mut().tx_events)
    }

    fn drain_copy_rx_block_returns(&mut self) -> Vec<CopyRxBlockReturn> {
        std::mem::take(&mut self.io.0.borrow_mut().block_returns)
    }

    fn drain_copy_tx_kicks(&mut self) -> Vec<TxEndpoint> {
        std::mem::take(&mut self.io.0.borrow_mut().kicks)
    }
}

impl RxCopyFinishErrorHarness for CopyFakeHarness {
    fn fail_next_copy_finish(&mut self) {
        self.io.0.borrow_mut().fail_next_finish = true;
    }
}

impl RxCopyUnknownEgressHarness for CopyFakeHarness {}

impl RxCopyCompletionHarness for CopyFakeHarness {
    fn complete_copy_submissions(&mut self) -> Vec<CopyTxCompletion> {
        let mut state = self.io.0.borrow_mut();
        let submitted = std::mem::take(&mut state.submitted_tx);
        submitted
            .into_iter()
            .map(|submission| {
                let completion = CopyTxCompletion {
                    tx: submission.live,
                    endpoint: submission.endpoint,
                };
                state.free_tx.push(submission.frame);
                completion
            })
            .collect()
    }

    fn prefer_copy_tx_frame(&mut self, frame_id: u64) {
        self.io.0.borrow_mut().preferred_tx = Some(frame_id);
    }
}

#[test]
fn copy_acceptance_01_zero_budget() {
    rx_copy::zero_budget_does_not_scan_or_advance::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_02_persistent_cursor() {
    rx_copy::split_budgets_resume_without_rescan_or_early_block_return::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_03_batch_drop() {
    rx_copy::dropped_batch_preserves_unleased_cursor::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_04_distinct_exact_copy() {
    rx_copy::transmit_uses_distinct_tx_storage_and_exact_payload::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_05_partial_reject() {
    rx_copy::partial_reject_reclaims_tx_and_terminals_source::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_06_block_terminal_partition() {
    rx_copy::recycle_consume_abandon_delay_block_return::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_07_unknown_egress() {
    rx_copy::unknown_egress_touches_no_tx_or_kick::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_08_finish_error_and_kick_bound() {
    rx_copy::finish_error_preserves_accounting_and_single_kick::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_09_independent_completion() {
    rx_copy::source_block_returns_before_independent_tx_completion::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_10_tx_generation() {
    rx_copy::completed_tx_reuse_advances_generation::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_11_kick_deduplication() {
    rx_copy::one_batch_kicks_each_endpoint_at_most_once::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_12_tx_pool_exhaustion() {
    rx_copy::tx_pool_exhaustion_is_partial_and_source_terminal::<CopyFakeHarness>();
}
