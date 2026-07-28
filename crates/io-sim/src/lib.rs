#![forbid(unsafe_code)]
#![doc = "Deterministic, in-memory packet I/O for ruster-core."]

use std::{collections::VecDeque, convert::Infallible};

use ruster_core::{
    forward_batch, BatchCompletion, BatchReport, DropReason, ForwardingSnapshot, IfId, PacketBatch,
    PacketIo, PacketLease, PacketSlot, SlotCompletion, TraceEvent, TraceSink,
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
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecycleCause {
    Forwarding(DropReason),
    LeaseAbandoned,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RecycledFrame {
    pub sequence: u64,
    pub ingress: IfId,
    pub cause: RecycleCause,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct SimIo {
    next_sequence: u64,
    rx: VecDeque<Slot>,
    tx: VecDeque<TxFrame>,
    recycled: VecDeque<RecycledFrame>,
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

    pub fn run_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(forward_batch(batch, snapshot, trace))
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
            remaining,
            counters: BatchCounters::default(),
        })
    }
}

pub struct SimBatch<'a> {
    rx: &'a mut VecDeque<Slot>,
    tx: &'a mut VecDeque<TxFrame>,
    recycled: &'a mut VecDeque<RecycledFrame>,
    remaining: usize,
    counters: BatchCounters,
}

#[derive(Debug, Default)]
struct BatchCounters {
    tx_requested: usize,
    tx_accepted: usize,
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
            counters: &mut self.counters,
        }))
    }

    fn finish(self) -> BatchCompletion<Self::Error> {
        BatchCompletion {
            tx_requested: self.counters.tx_requested,
            tx_accepted: self.counters.tx_accepted,
            tx_rejected: 0,
            recycled: self.counters.recycled,
            error: None,
        }
    }
}

pub struct SimSlot<'a> {
    slot: Option<Slot>,
    tx: &'a mut VecDeque<TxFrame>,
    recycled: &'a mut VecDeque<RecycledFrame>,
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
                self.tx.push_back(TxFrame {
                    sequence: slot.sequence,
                    ingress: slot.ingress,
                    egress,
                    bytes: slot.bytes,
                });
                self.counters.tx_accepted += 1;
            }
            SlotCompletion::Recycle(reason) => {
                self.recycle(slot, RecycleCause::Forwarding(reason));
            }
            SlotCompletion::LeaseAbandoned => {
                self.recycle(slot, RecycleCause::LeaseAbandoned);
            }
        }
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
