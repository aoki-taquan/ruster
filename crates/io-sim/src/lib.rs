#![forbid(unsafe_code)]
#![doc = "Deterministic, in-memory packet I/O for ruster-core."]

use std::{collections::VecDeque, convert::Infallible};

use ruster_core::{
    forward_batch, forward_batch_with_nat44_tcp, forward_batch_with_nat44_udp,
    forward_batch_with_nat44_udp_and_tcp, BatchCompletion, BatchReport, ConsumeReason, DropReason,
    ForwardingSnapshot, GeneratedAllocationError, GeneratedArpTrace, GeneratedBatchCompletion,
    GeneratedIcmpv4Trace, GeneratedIcmpv4TraceSink, GeneratedPacketBatch, GeneratedPacketIo,
    GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion, GeneratedTraceSink, IfId,
    MonotonicMillis, Nat44TcpConfig, Nat44TcpRuntime, Nat44UdpConfig, Nat44UdpRuntime, PacketBatch,
    PacketIo, PacketLease, PacketSlot, ResolutionRuntime, SlotCompletion, TraceEvent, TraceSink,
};

#[derive(Debug, Eq, PartialEq)]
struct Slot {
    sequence: u64,
    ingress: IfId,
    bytes: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TxFrame {
    pub sequence: u64,
    pub ingress: IfId,
    pub egress: IfId,
    pub origin: FrameOrigin,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameOrigin {
    Received { ingress: IfId },
    Generated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecycleCause {
    Forwarding(DropReason),
    Consumed(ConsumeReason),
    TxRejected,
    LeaseAbandoned,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RecycledFrame {
    pub sequence: u64,
    pub ingress: IfId,
    pub cause: RecycleCause,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedRecycleCause {
    Cancelled,
    Abandoned,
    TxRejected,
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedRecycledFrame {
    pub sequence: u64,
    pub egress: IfId,
    pub cause: GeneratedRecycleCause,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimGeneratedError {
    Injected,
}

#[derive(Debug)]
pub struct SimIo {
    next_sequence: u64,
    rx: VecDeque<Slot>,
    tx: VecDeque<TxFrame>,
    recycled: VecDeque<RecycledFrame>,
    generated_recycled: VecDeque<GeneratedRecycledFrame>,
    generated_budget: usize,
    generated_max_frame: usize,
    generated_accept_budget: usize,
    fail_generated_finish: bool,
    received_accept_budget: usize,
}

impl Default for SimIo {
    fn default() -> Self {
        Self {
            next_sequence: 0,
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            recycled: VecDeque::new(),
            generated_recycled: VecDeque::new(),
            generated_budget: usize::MAX,
            generated_max_frame: 1_514,
            generated_accept_budget: usize::MAX,
            fail_generated_finish: false,
            received_accept_budget: usize::MAX,
        }
    }
}

impl SimIo {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inject(&mut self, ingress: IfId, bytes: Vec<u8>) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.rx.push_back(Slot {
            sequence,
            ingress,
            bytes,
        });
        sequence
    }

    #[must_use]
    pub fn pending_rx(&self) -> usize {
        self.rx.len()
    }

    #[must_use]
    pub fn pending_tx(&self) -> usize {
        self.tx.len()
    }

    #[must_use]
    pub fn pending_recycled(&self) -> usize {
        self.recycled.len()
    }

    pub fn pop_tx(&mut self) -> Option<TxFrame> {
        self.tx.pop_front()
    }

    pub fn pop_recycled(&mut self) -> Option<RecycledFrame> {
        self.recycled.pop_front()
    }

    pub fn pop_generated_recycled(&mut self) -> Option<GeneratedRecycledFrame> {
        self.generated_recycled.pop_front()
    }

    pub fn set_generated_budget(&mut self, budget: usize) {
        self.generated_budget = budget;
    }

    pub fn set_generated_max_frame(&mut self, max_frame: usize) {
        self.generated_max_frame = max_frame;
    }

    pub fn set_generated_accept_budget(&mut self, budget: usize) {
        self.generated_accept_budget = budget;
    }

    pub fn fail_next_generated_finish(&mut self) {
        self.fail_generated_finish = true;
    }

    pub fn set_received_accept_budget(&mut self, budget: usize) {
        self.received_accept_budget = budget;
    }

    pub fn run_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(forward_batch(batch, snapshot, trace))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_nat44_udp_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        resolution: &mut ResolutionRuntime<'_>,
        config: &Nat44UdpConfig,
        nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
        now: MonotonicMillis,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(forward_batch_with_nat44_udp(
            batch, snapshot, resolution, config, nat44_udp, now, trace,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_nat44_tcp_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        resolution: &mut ResolutionRuntime<'_>,
        config: &Nat44TcpConfig,
        nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
        now: MonotonicMillis,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(forward_batch_with_nat44_tcp(
            batch, snapshot, resolution, config, nat44_tcp, now, trace,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_nat44_udp_and_tcp_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        resolution: &mut ResolutionRuntime<'_>,
        udp_config: &Nat44UdpConfig,
        nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
        tcp_config: &Nat44TcpConfig,
        nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
        now: MonotonicMillis,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(forward_batch_with_nat44_udp_and_tcp(
            batch, snapshot, resolution, udp_config, nat44_udp, tcp_config, nat44_tcp, now, trace,
        ))
    }
}

impl PacketIo for SimIo {
    type Error = Infallible;
    type Batch<'a> = SimBatch<'a>;

    fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
        let remaining = budget.min(self.rx.len());
        Ok(SimBatch {
            rx: &mut self.rx,
            tx: &mut self.tx,
            recycled: &mut self.recycled,
            accept_budget: &mut self.received_accept_budget,
            remaining,
            counters: BatchCounters::default(),
        })
    }
}

pub struct SimBatch<'a> {
    rx: &'a mut VecDeque<Slot>,
    tx: &'a mut VecDeque<TxFrame>,
    recycled: &'a mut VecDeque<RecycledFrame>,
    accept_budget: &'a mut usize,
    remaining: usize,
    counters: BatchCounters,
}

#[derive(Debug, Default)]
struct BatchCounters {
    tx_requested: usize,
    tx_accepted: usize,
    tx_rejected: usize,
    recycled: usize,
}

impl PacketBatch for SimBatch<'_> {
    type Error = Infallible;
    type Slot<'a>
        = SimSlot<'a>
    where
        Self: 'a;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        if self.remaining == 0 {
            return None;
        }
        let slot = self.rx.pop_front()?;
        self.remaining -= 1;
        Some(PacketLease::new(SimSlot {
            slot: Some(slot),
            tx: self.tx,
            recycled: self.recycled,
            accept_budget: self.accept_budget,
            counters: &mut self.counters,
        }))
    }

    fn finish(self) -> BatchCompletion<Self::Error> {
        BatchCompletion {
            tx_requested: self.counters.tx_requested,
            tx_accepted: self.counters.tx_accepted,
            tx_rejected: self.counters.tx_rejected,
            recycled: self.counters.recycled,
            error: None,
        }
    }
}

pub struct SimSlot<'a> {
    slot: Option<Slot>,
    tx: &'a mut VecDeque<TxFrame>,
    recycled: &'a mut VecDeque<RecycledFrame>,
    accept_budget: &'a mut usize,
    counters: &'a mut BatchCounters,
}

impl PacketSlot for SimSlot<'_> {
    fn ingress(&self) -> IfId {
        self.slot.as_ref().expect("live sim slot").ingress
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.slot.as_mut().expect("live sim slot").bytes
    }

    fn complete(mut self, completion: SlotCompletion) {
        let slot = self.slot.take().expect("sim slot completed exactly once");
        match completion {
            SlotCompletion::Transmit(egress) => {
                self.counters.tx_requested += 1;
                if *self.accept_budget == 0 {
                    self.counters.tx_rejected += 1;
                    self.recycled.push_back(RecycledFrame {
                        sequence: slot.sequence,
                        ingress: slot.ingress,
                        cause: RecycleCause::TxRejected,
                        bytes: slot.bytes,
                    });
                } else {
                    *self.accept_budget -= 1;
                    self.tx.push_back(TxFrame {
                        sequence: slot.sequence,
                        ingress: slot.ingress,
                        egress,
                        origin: FrameOrigin::Received {
                            ingress: slot.ingress,
                        },
                        bytes: slot.bytes,
                    });
                    self.counters.tx_accepted += 1;
                }
            }
            SlotCompletion::Recycle(reason) => {
                self.recycle(slot, RecycleCause::Forwarding(reason));
            }
            SlotCompletion::Consume(reason) => {
                self.recycle(slot, RecycleCause::Consumed(reason));
            }
            SlotCompletion::LeaseAbandoned => {
                self.recycle(slot, RecycleCause::LeaseAbandoned);
            }
        }
    }
}

impl GeneratedPacketIo for SimIo {
    type Error = SimGeneratedError;
    type Batch<'a> = SimGeneratedBatch<'a>;

    fn begin_generated(&mut self, egress: IfId) -> Self::Batch<'_> {
        let fail_finish = self.fail_generated_finish;
        self.fail_generated_finish = false;
        SimGeneratedBatch {
            next_sequence: &mut self.next_sequence,
            tx: &mut self.tx,
            recycled: &mut self.generated_recycled,
            egress,
            remaining_allocations: self.generated_budget,
            max_frame: self.generated_max_frame,
            accept_budget: self.generated_accept_budget,
            fail_finish,
            pending: VecDeque::new(),
            counters: GeneratedCounters::default(),
        }
    }
}

#[derive(Debug)]
struct GeneratedSlot {
    sequence: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
struct GeneratedCounters {
    attempts: usize,
    allocated: usize,
    failed: usize,
    requested: usize,
    cancelled: usize,
    abandoned: usize,
}

pub struct SimGeneratedBatch<'a> {
    next_sequence: &'a mut u64,
    tx: &'a mut VecDeque<TxFrame>,
    recycled: &'a mut VecDeque<GeneratedRecycledFrame>,
    egress: IfId,
    remaining_allocations: usize,
    max_frame: usize,
    accept_budget: usize,
    fail_finish: bool,
    pending: VecDeque<GeneratedSlot>,
    counters: GeneratedCounters,
}

impl GeneratedPacketBatch for SimGeneratedBatch<'_> {
    type Error = SimGeneratedError;
    type Slot<'a>
        = SimGeneratedSlot<'a>
    where
        Self: 'a;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        self.counters.attempts += 1;
        let error = if frame_len == 0 {
            Some(GeneratedAllocationError::ZeroLength)
        } else if frame_len > self.max_frame {
            Some(GeneratedAllocationError::FrameTooLarge)
        } else if self.remaining_allocations == 0 {
            Some(GeneratedAllocationError::Unavailable)
        } else {
            None
        };
        if let Some(error) = error {
            self.counters.failed += 1;
            return Err(error);
        }
        self.remaining_allocations -= 1;
        self.counters.allocated += 1;
        let sequence = *self.next_sequence;
        *self.next_sequence = self.next_sequence.wrapping_add(1);
        Ok(GeneratedPacketLease::new(SimGeneratedSlot {
            slot: Some(GeneratedSlot {
                sequence,
                bytes: vec![0xa5; frame_len],
            }),
            pending: &mut self.pending,
            recycled: self.recycled,
            counters: &mut self.counters,
            egress: self.egress,
        }))
    }

    fn finish(mut self) -> GeneratedBatchCompletion<Self::Error> {
        let accepted = self.accept_budget.min(self.pending.len());
        for _ in 0..accepted {
            let slot = self.pending.pop_front().expect("accepted generated slot");
            self.tx.push_back(TxFrame {
                sequence: slot.sequence,
                ingress: self.egress,
                egress: self.egress,
                origin: FrameOrigin::Generated,
                bytes: slot.bytes,
            });
        }
        let rejected = self.pending.len();
        while let Some(slot) = self.pending.pop_front() {
            self.recycled.push_back(GeneratedRecycledFrame {
                sequence: slot.sequence,
                egress: self.egress,
                cause: GeneratedRecycleCause::TxRejected,
                bytes: slot.bytes,
            });
        }
        GeneratedBatchCompletion {
            attempts: self.counters.attempts,
            allocated: self.counters.allocated,
            failed: self.counters.failed,
            requested: self.counters.requested,
            cancelled: self.counters.cancelled,
            abandoned: self.counters.abandoned,
            accepted,
            rejected,
            error: self.fail_finish.then_some(SimGeneratedError::Injected),
        }
    }
}

pub struct SimGeneratedSlot<'a> {
    slot: Option<GeneratedSlot>,
    pending: &'a mut VecDeque<GeneratedSlot>,
    recycled: &'a mut VecDeque<GeneratedRecycledFrame>,
    counters: &'a mut GeneratedCounters,
    egress: IfId,
}

impl GeneratedPacketSlot for SimGeneratedSlot<'_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.slot.as_mut().expect("live generated sim slot").bytes
    }

    fn complete(mut self, completion: GeneratedSlotCompletion) {
        let slot = self
            .slot
            .take()
            .expect("generated sim slot completed exactly once");
        match completion {
            GeneratedSlotCompletion::Transmit => {
                self.counters.requested += 1;
                self.pending.push_back(slot);
            }
            GeneratedSlotCompletion::Cancelled => {
                self.counters.cancelled += 1;
                self.recycle(slot, GeneratedRecycleCause::Cancelled);
            }
            GeneratedSlotCompletion::Abandoned => {
                self.counters.abandoned += 1;
                self.recycle(slot, GeneratedRecycleCause::Abandoned);
            }
        }
    }
}

impl SimGeneratedSlot<'_> {
    fn recycle(&mut self, slot: GeneratedSlot, cause: GeneratedRecycleCause) {
        self.recycled.push_back(GeneratedRecycledFrame {
            sequence: slot.sequence,
            egress: self.egress,
            cause,
            bytes: slot.bytes,
        });
    }
}

impl SimSlot<'_> {
    fn recycle(&mut self, slot: Slot, cause: RecycleCause) {
        self.recycled.push_back(RecycledFrame {
            sequence: slot.sequence,
            ingress: slot.ingress,
            cause,
            bytes: slot.bytes,
        });
        self.counters.recycled += 1;
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct VecTrace {
    events: Vec<TraceEvent>,
}

impl VecTrace {
    #[must_use]
    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl TraceSink for VecTrace {
    fn record(&mut self, event: TraceEvent) {
        self.events.push(event);
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct VecGeneratedTrace {
    events: Vec<GeneratedArpTrace>,
}

impl VecGeneratedTrace {
    #[must_use]
    pub fn events(&self) -> &[GeneratedArpTrace] {
        &self.events
    }
}

impl GeneratedTraceSink for VecGeneratedTrace {
    fn record_generated(&mut self, event: GeneratedArpTrace) {
        self.events.push(event);
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct VecGeneratedIcmpv4Trace {
    events: Vec<GeneratedIcmpv4Trace>,
}

impl VecGeneratedIcmpv4Trace {
    #[must_use]
    pub fn events(&self) -> &[GeneratedIcmpv4Trace] {
        &self.events
    }
}

impl GeneratedIcmpv4TraceSink for VecGeneratedIcmpv4Trace {
    fn record_generated_icmpv4(&mut self, event: GeneratedIcmpv4Trace) {
        self.events.push(event);
    }
}
