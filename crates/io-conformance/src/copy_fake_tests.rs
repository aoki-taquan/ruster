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
        self, CopyErrno, CopyKickEvent, CopyLeaseObserver, CopyOperationBudgets,
        CopyOperationCounters, CopyPayloadObservation, CopyRxBlockReturn, CopyRxBlockToken,
        CopyRxDescriptorFault, CopyRxFaultEvent, CopyRxPacketToken, CopyRxScanObservation,
        CopySourceDisposition, CopySourceEvent, CopyTxCompletion, CopyTxDisposition, CopyTxEvent,
        CopyTxToken, InjectedCopyRxBlock, LiveCopyRxPacket, LiveCopyTxFrame,
        RxCopyAdversarialHarness, RxCopyCompletionHarness, RxCopyFinishErrorHarness, RxCopyHarness,
        RxCopyKickErrorHarness, RxCopyPayloadHarness, RxCopyUnknownEgressHarness,
    },
    RxReclaim, TxEndpoint, CONFORMANCE_LAN_ENDPOINT, CONFORMANCE_WAN_ENDPOINT,
};

const TX_FRAME_CAPACITY: usize = 128;
const TX_FRAME_COUNT: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CopyFakeError {
    InjectedFinish,
    Kick(CopyErrno),
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
    status_read: bool,
    validation_cursor: usize,
    validated: bool,
    fault: Option<(usize, CopyRxDescriptorFault)>,
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
    sending: bool,
}

struct CopyState {
    blocks: VecDeque<SourceBlock>,
    source_live: BTreeMap<usize, LiveCopyRxPacket>,
    free_tx: Vec<TxFrame>,
    submitted_tx: VecDeque<SubmittedTx>,
    tx_generations: BTreeMap<u64, u64>,
    preferred_tx: Option<u64>,
    preferred_rx_block: Option<u64>,
    next_block_id: u64,
    free_rx_block_ids: Vec<u64>,
    rx_block_generations: BTreeMap<u64, u64>,
    scans: BTreeMap<CopyRxBlockToken, CopyRxScanObservation>,
    operation_budgets: CopyOperationBudgets,
    operation_counters: CopyOperationCounters,
    source_events: Vec<CopySourceEvent>,
    tx_events: Vec<CopyTxEvent>,
    payload_observations: Vec<CopyPayloadObservation>,
    rx_faults: Vec<CopyRxFaultEvent>,
    block_returns: Vec<CopyRxBlockReturn>,
    kicks: Vec<CopyKickEvent>,
    tx_accept_budget: usize,
    fail_next_finish: bool,
    fail_next_kick: Option<CopyErrno>,
}

impl CopyState {
    fn new() -> Self {
        Self {
            blocks: VecDeque::new(),
            source_live: BTreeMap::new(),
            free_tx: (0..TX_FRAME_COUNT)
                .map(|index| TxFrame::new(index as u64 + 1))
                .collect(),
            submitted_tx: VecDeque::new(),
            tx_generations: BTreeMap::new(),
            preferred_tx: None,
            preferred_rx_block: None,
            next_block_id: 1,
            free_rx_block_ids: Vec::new(),
            rx_block_generations: BTreeMap::new(),
            scans: BTreeMap::new(),
            operation_budgets: CopyOperationBudgets::default(),
            operation_counters: CopyOperationCounters::default(),
            source_events: Vec::new(),
            tx_events: Vec::new(),
            payload_observations: Vec::new(),
            rx_faults: Vec::new(),
            block_returns: Vec::new(),
            kicks: Vec::new(),
            tx_accept_budget: usize::MAX,
            fail_next_finish: false,
            fail_next_kick: None,
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

    fn prepare_receive(&mut self, packet_budget: usize) -> usize {
        if packet_budget == 0 || self.blocks.is_empty() {
            return 0;
        }
        let budgets = self.operation_budgets;
        let mut status_read = false;
        let mut descriptor_visits = 0;
        let mut safe_fault = None;
        let mut unsafe_fault = None;
        let token;
        {
            let block = self.blocks.front_mut().expect("checked nonempty");
            token = block.token;
            if !block.status_read {
                if budgets.rx_block_status_reads == 0 {
                    return 0;
                }
                block.status_read = true;
                status_read = true;
            }
            let visit_budget = budgets.rx_descriptor_visits;
            while !block.validated
                && descriptor_visits < visit_budget
                && block.validation_cursor < block.packets.len()
            {
                let index = block.validation_cursor;
                descriptor_visits += 1;
                if block
                    .fault
                    .is_some_and(|(fault_index, _)| fault_index == index)
                {
                    let fault = block.fault.expect("matched fault").1;
                    match fault {
                        CopyRxDescriptorFault::SafePacket => {
                            safe_fault = block.packets[index].take().map(|packet| (index, packet));
                            block.validation_cursor += 1;
                            block.fault = None;
                            continue;
                        }
                        CopyRxDescriptorFault::UnsafeChain => {
                            unsafe_fault = Some(index);
                            break;
                        }
                    }
                }
                block.validation_cursor += 1;
            }
            if unsafe_fault.is_none() && block.validation_cursor == block.packets.len() {
                block.validated = true;
            }
        }
        if status_read {
            self.operation_counters.rx_block_status_reads += 1;
            self.scans.entry(token).or_default().block_status_reads += 1;
            self.scans.entry(token).or_default().block_acquisitions += 1;
        }
        self.operation_counters.rx_descriptor_visits += descriptor_visits;
        self.scans.entry(token).or_default().descriptor_validations += descriptor_visits;

        if let Some(index) = unsafe_fault {
            self.terminal_unsafe_block(token, index);
            return 0;
        }
        if let Some((index, packet)) = safe_fault {
            self.rx_faults.push(CopyRxFaultEvent {
                block: token,
                packet_index: index,
                fault: CopyRxDescriptorFault::SafePacket,
            });
            self.terminal_source(
                packet,
                CopySourceDisposition::RxInvalid(CopyRxDescriptorFault::SafePacket),
            );
        }
        let Some(block) = self.blocks.front() else {
            return 0;
        };
        if !block.validated {
            return 0;
        }
        packet_budget.min(
            block.packets[block.cursor..]
                .iter()
                .filter(|packet| packet.is_some())
                .count(),
        )
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
        while block.cursor < block.packets.len() && block.packets[block.cursor].is_none() {
            block.cursor += 1;
        }
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
            self.free_rx_block_ids.push(token.block_id);
            self.block_returns.push(CopyRxBlockReturn {
                block: token,
                packet_count,
            });
        }
    }

    fn terminal_unsafe_block(&mut self, token: CopyRxBlockToken, packet_index: usize) {
        let index = self
            .blocks
            .iter()
            .position(|block| block.token == token)
            .expect("unsafe block");
        let mut block = self.blocks.remove(index).expect("unsafe block removal");
        for packet in block.packets.iter_mut().filter_map(Option::take) {
            assert_eq!(
                self.source_live.remove(&packet.live.visible_address),
                Some(packet.live)
            );
            self.source_events.push(CopySourceEvent {
                source: packet.live,
                ingress: packet.ingress,
                disposition: CopySourceDisposition::RxInvalid(CopyRxDescriptorFault::UnsafeChain),
            });
        }
        self.rx_faults.push(CopyRxFaultEvent {
            block: token,
            packet_index,
            fault: CopyRxDescriptorFault::UnsafeChain,
        });
        self.free_rx_block_ids.push(token.block_id);
        self.block_returns.push(CopyRxBlockReturn {
            block: token,
            packet_count: block.packets.len(),
        });
    }
}

#[derive(Default)]
struct CopyBatchState {
    tx_requested: usize,
    tx_accepted: usize,
    tx_rejected: usize,
    recycled: usize,
    remaining_accepts: usize,
    remaining_tx_status_reads: usize,
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
        let mut kick_error = None;
        for endpoint in counters.touched.iter().copied() {
            let result = if let Some(errno) = state.fail_next_kick.take() {
                kick_error = Some(CopyFakeError::Kick(errno));
                Err(errno)
            } else {
                Ok(())
            };
            state.operation_counters.kick_syscalls += 1;
            state.kicks.push(CopyKickEvent { endpoint, result });
        }
        BatchCompletion {
            tx_requested: counters.tx_requested,
            tx_accepted: counters.tx_accepted,
            tx_rejected: counters.tx_rejected,
            recycled: counters.recycled,
            error: self
                .fail_finish
                .then_some(CopyFakeError::InjectedFinish)
                .or(kick_error),
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
                if counters.remaining_tx_status_reads == 0 {
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
                }
                counters.remaining_tx_status_reads -= 1;
                state.operation_counters.tx_submit_status_reads += 1;
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
                tx_frame.len = packet.bytes().len();
                let tx = state.bind_tx(&tx_frame);
                let accepted = counters.remaining_accepts != 0;
                if accepted {
                    counters.remaining_accepts -= 1;
                    counters.tx_accepted += 1;
                    counters.touch(endpoint);
                    tx_frame.copy_from(packet.bytes());
                    state.operation_counters.copy_invocations += 1;
                    state.operation_counters.copied_bytes += packet.bytes().len();
                    state.tx_events.push(CopyTxEvent {
                        source: packet.live,
                        tx,
                        endpoint,
                        descriptor_len: packet.bytes().len(),
                        disposition: CopyTxDisposition::Submitted,
                        copied_bytes: packet.bytes().len(),
                    });
                    state.payload_observations.push(CopyPayloadObservation {
                        source: packet.live,
                        tx,
                        observed_payload: tx_frame.bytes().to_vec(),
                    });
                    state.submitted_tx.push_back(SubmittedTx {
                        frame: tx_frame,
                        live: tx,
                        endpoint,
                        sending: false,
                    });
                    CopySourceDisposition::TxAccepted { tx, endpoint }
                } else {
                    counters.tx_rejected += 1;
                    state.tx_events.push(CopyTxEvent {
                        source: packet.live,
                        tx,
                        endpoint,
                        descriptor_len: 0,
                        disposition: CopyTxDisposition::Rejected,
                        copied_bytes: 0,
                    });
                    tx_frame.len = 0;
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
            loop {
                let index = block.cursor;
                block.cursor += 1;
                if let Some(packet) = block.packets.get_mut(index)?.take() {
                    break packet;
                }
            }
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
        let (remaining, accept_budget, tx_status_budget, fail_finish) = {
            let mut state = self.0.borrow_mut();
            let fail_finish = std::mem::take(&mut state.fail_next_finish);
            let accept_budget = state.tx_accept_budget;
            let tx_status_budget = state.operation_budgets.tx_submit_status_reads;
            let remaining = state.prepare_receive(budget);
            (remaining, accept_budget, tx_status_budget, fail_finish)
        };
        Ok(CopyFakeBatch {
            state: Rc::clone(&self.0),
            counters: Rc::new(RefCell::new(CopyBatchState {
                remaining_accepts: accept_budget,
                remaining_tx_status_reads: tx_status_budget,
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

impl CopyFakeHarness {
    fn shared() -> Self {
        let state = Rc::new(RefCell::new(CopyState::new()));
        Self {
            io: CopyFakeIo(Rc::clone(&state)),
            observer: CopyFakeObserver(state),
        }
    }

    fn inject_with_fault(
        &mut self,
        ingress: ruster_core::IfId,
        packets: Vec<Vec<u8>>,
        fault: Option<(usize, CopyRxDescriptorFault)>,
    ) -> InjectedCopyRxBlock {
        assert!(!packets.is_empty());
        if let Some((index, _)) = fault {
            assert!(index < packets.len());
        }
        let mut state = self.io.0.borrow_mut();
        let block_id = if let Some(preferred) = state.preferred_rx_block.take() {
            let index = state
                .free_rx_block_ids
                .iter()
                .position(|candidate| *candidate == preferred)
                .expect("preferred RX block is physically free");
            state.free_rx_block_ids.swap_remove(index)
        } else if let Some(block_id) = state.free_rx_block_ids.pop() {
            block_id
        } else {
            let block_id = state.next_block_id;
            state.next_block_id += 1;
            block_id
        };
        let generation = state.rx_block_generations.entry(block_id).or_default();
        *generation = generation
            .checked_add(1)
            .expect("fake RX block generation overflow");
        let token = CopyRxBlockToken {
            block_id,
            generation: *generation,
        };
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
            status_read: false,
            validation_cursor: 0,
            validated: false,
            fault,
        });
        InjectedCopyRxBlock {
            block: token,
            packets: live_packets,
        }
    }
}

impl RxCopyHarness for CopyFakeHarness {
    type Io = CopyFakeIo;
    type Observer = CopyFakeObserver;

    fn new() -> Self {
        Self::shared()
    }

    fn io_and_observer(&mut self) -> (&mut Self::Io, &mut Self::Observer) {
        (&mut self.io, &mut self.observer)
    }

    fn inject_rx_block(
        &mut self,
        ingress: ruster_core::IfId,
        packets: Vec<Vec<u8>>,
    ) -> InjectedCopyRxBlock {
        self.inject_with_fault(ingress, packets, None)
    }

    fn set_copy_tx_accept_budget(&mut self, budget: usize) {
        self.io.0.borrow_mut().tx_accept_budget = budget;
    }

    fn set_copy_operation_budgets(&mut self, budgets: CopyOperationBudgets) {
        self.io.0.borrow_mut().operation_budgets = budgets;
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

    fn inflight_copy_tx_frames(&self) -> usize {
        self.io.0.borrow().submitted_tx.len()
    }

    fn copy_operation_counters(&self) -> CopyOperationCounters {
        self.io.0.borrow().operation_counters
    }

    fn production_payload_hook_enabled(&self) -> bool {
        false
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

    fn drain_copy_tx_kicks(&mut self) -> Vec<CopyKickEvent> {
        std::mem::take(&mut self.io.0.borrow_mut().kicks)
    }
}

impl RxCopyFinishErrorHarness for CopyFakeHarness {
    fn fail_next_copy_finish(&mut self) {
        self.io.0.borrow_mut().fail_next_finish = true;
    }
}

impl RxCopyKickErrorHarness for CopyFakeHarness {
    fn fail_next_copy_kick(&mut self, errno: CopyErrno) {
        self.io.0.borrow_mut().fail_next_kick = Some(errno);
    }
}

impl RxCopyUnknownEgressHarness for CopyFakeHarness {}

impl RxCopyCompletionHarness for CopyFakeHarness {
    fn complete_copy_submissions(&mut self) -> Vec<CopyTxCompletion> {
        let mut state = self.io.0.borrow_mut();
        let mut completed = Vec::new();
        let budget = state.operation_budgets.tx_completion_status_reads;
        for _ in 0..budget {
            let Some(sending) = state.submitted_tx.front().map(|head| head.sending) else {
                break;
            };
            state.operation_counters.tx_completion_status_reads += 1;
            if sending {
                break;
            }
            let submission = state.submitted_tx.pop_front().expect("observed head");
            completed.push(CopyTxCompletion {
                tx: submission.live,
                endpoint: submission.endpoint,
            });
            state.free_tx.push(submission.frame);
        }
        completed
    }

    fn prefer_copy_tx_frame(&mut self, frame_id: u64) {
        self.io.0.borrow_mut().preferred_tx = Some(frame_id);
    }

    fn prefer_copy_rx_block(&mut self, block_id: u64) {
        self.io.0.borrow_mut().preferred_rx_block = Some(block_id);
    }

    fn set_copy_completion_head_sending(&mut self, sending: bool) {
        self.io
            .0
            .borrow_mut()
            .submitted_tx
            .front_mut()
            .expect("submitted TX head")
            .sending = sending;
    }
}

impl RxCopyPayloadHarness for CopyFakeHarness {
    fn drain_copy_payload_observations(&mut self) -> Vec<CopyPayloadObservation> {
        std::mem::take(&mut self.io.0.borrow_mut().payload_observations)
    }
}

impl RxCopyAdversarialHarness for CopyFakeHarness {
    fn inject_rx_block_with_fault(
        &mut self,
        ingress: ruster_core::IfId,
        packets: Vec<Vec<u8>>,
        packet_index: usize,
        fault: CopyRxDescriptorFault,
    ) -> InjectedCopyRxBlock {
        self.inject_with_fault(ingress, packets, Some((packet_index, fault)))
    }

    fn drain_copy_rx_faults(&mut self) -> Vec<CopyRxFaultEvent> {
        std::mem::take(&mut self.io.0.borrow_mut().rx_faults)
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

#[test]
fn copy_acceptance_13_validation_budgets_and_faults() {
    rx_copy::validation_budgets_and_fault_advance_are_bounded::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_20_safe_fault_terminal_positions() {
    rx_copy::safe_packet_fault_positions_are_terminal_exactly_once::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_14_submit_budget_precedes_copy() {
    rx_copy::submit_status_budget_precedes_copy::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_15_completion_budget_and_head_stop() {
    rx_copy::completion_budget_and_sending_head_are_bounded::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_16_completion_capable_batch_drop() {
    rx_copy::completion_capable_batch_drop_is_exact::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_17_kick_errno() {
    rx_copy::kick_errno_has_no_retry_or_reclassification::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_18_reject_aba() {
    rx_copy::rejected_tx_reuse_advances_generation::<CopyFakeHarness>();
}

#[test]
fn copy_acceptance_19_rx_block_aba() {
    rx_copy::returned_rx_block_reuse_advances_generation::<CopyFakeHarness>();
}
