use std::convert::Infallible;

use ruster_core::{
    BatchCompletion, ConsumeReason, DropReason, IfId, PacketBatch, PacketIo, PacketLease,
    PacketSlot, SlotCompletion,
};

/// Terminal state retained in a preallocated benchmark slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchCompletion {
    Transmitted(IfId),
    Recycled(DropReason),
    Consumed(ConsumeReason),
    LeaseAbandoned,
}

#[derive(Debug)]
struct BenchSlot {
    ingress: IfId,
    bytes: Box<[u8]>,
    completion: Option<BenchCompletion>,
}

/// A NIC-free packet backend whose buffers and slot metadata are allocated
/// before measurement.
///
/// Unlike the simulation backend this backend does not capture or move packet
/// buffers at completion. Core borrows each backend-owned buffer, and
/// completion only updates fixed slot metadata.
#[derive(Debug)]
pub struct BenchBackend {
    slots: Vec<BenchSlot>,
}

impl BenchBackend {
    /// Allocates `slot_count` backend-owned buffers initialized from
    /// `template`. This is cold setup and must not run in a timed region.
    #[must_use]
    pub fn new(slot_count: usize, ingress: IfId, template: &[u8]) -> Self {
        let slots = (0..slot_count)
            .map(|_| BenchSlot {
                ingress,
                bytes: template.to_vec().into_boxed_slice(),
                completion: None,
            })
            .collect();
        Self { slots }
    }

    #[must_use]
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Restores packet bytes and clears terminal metadata outside measurement.
    ///
    /// The length must match the buffers chosen during construction.
    pub fn reset(&mut self, template: &[u8]) {
        for slot in &mut self.slots {
            assert_eq!(
                slot.bytes.len(),
                template.len(),
                "benchmark reset template length changed"
            );
            slot.bytes.copy_from_slice(template);
            slot.completion = None;
        }
    }

    #[must_use]
    pub fn bytes(&self, index: usize) -> Option<&[u8]> {
        self.slots.get(index).map(|slot| slot.bytes.as_ref())
    }

    #[must_use]
    pub fn completion(&self, index: usize) -> Option<BenchCompletion> {
        self.slots.get(index).and_then(|slot| slot.completion)
    }
}

#[derive(Debug, Default)]
struct BenchCounters {
    tx_requested: usize,
    tx_accepted: usize,
    recycled: usize,
}

pub struct BenchBatch<'a> {
    slots: &'a mut [BenchSlot],
    next: usize,
    counters: BenchCounters,
}

impl PacketIo for BenchBackend {
    type Error = Infallible;
    type Batch<'a> = BenchBatch<'a>;

    fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
        let count = budget.min(self.slots.len());
        Ok(BenchBatch {
            slots: &mut self.slots[..count],
            next: 0,
            counters: BenchCounters::default(),
        })
    }
}

impl PacketBatch for BenchBatch<'_> {
    type Error = Infallible;
    type Slot<'a>
        = BenchPacketSlot<'a>
    where
        Self: 'a;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        let slot = self.slots.get_mut(self.next)?;
        self.next += 1;
        Some(PacketLease::new(BenchPacketSlot {
            slot,
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

pub struct BenchPacketSlot<'a> {
    slot: &'a mut BenchSlot,
    counters: &'a mut BenchCounters,
}

impl PacketSlot for BenchPacketSlot<'_> {
    fn ingress(&self) -> IfId {
        self.slot.ingress
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.slot.bytes.as_mut()
    }

    fn complete(self, completion: SlotCompletion) {
        assert!(
            self.slot.completion.is_none(),
            "benchmark slot completed more than once"
        );
        self.slot.completion = Some(match completion {
            SlotCompletion::Transmit(egress) => {
                self.counters.tx_requested += 1;
                self.counters.tx_accepted += 1;
                BenchCompletion::Transmitted(egress)
            }
            SlotCompletion::Recycle(reason) => {
                self.counters.recycled += 1;
                BenchCompletion::Recycled(reason)
            }
            SlotCompletion::Consume(reason) => {
                self.counters.recycled += 1;
                BenchCompletion::Consumed(reason)
            }
            SlotCompletion::LeaseAbandoned => {
                self.counters.recycled += 1;
                BenchCompletion::LeaseAbandoned
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use ruster_core::{DropReason, PacketBatch, PacketIo};

    use super::*;

    #[test]
    fn budget_and_exactly_once_terminal_states_are_accounted() {
        let mut backend = BenchBackend::new(3, IfId(1), &[0; 64]);
        let mut batch = backend.receive(2).unwrap();
        batch.next_packet().unwrap().commit(IfId(2));
        batch.next_packet().unwrap().recycle(DropReason::RouteMiss);
        assert!(batch.next_packet().is_none());
        assert_eq!(
            batch.finish(),
            BatchCompletion {
                tx_requested: 1,
                tx_accepted: 1,
                tx_rejected: 0,
                recycled: 1,
                error: None,
            }
        );
        assert_eq!(
            backend.completion(0),
            Some(BenchCompletion::Transmitted(IfId(2)))
        );
        assert_eq!(
            backend.completion(1),
            Some(BenchCompletion::Recycled(DropReason::RouteMiss))
        );
        assert_eq!(backend.completion(2), None);
    }

    #[test]
    fn abandoned_lease_is_recycled_and_reset_restores_storage() {
        let template = [7_u8; 60];
        let mut backend = BenchBackend::new(1, IfId(1), &template);
        let mut batch = backend.receive(1).unwrap();
        {
            let mut packet = batch.next_packet().unwrap();
            packet.bytes_mut()[0] = 9;
        }
        assert_eq!(batch.finish().recycled, 1);
        assert_eq!(backend.completion(0), Some(BenchCompletion::LeaseAbandoned));
        assert_eq!(backend.bytes(0).unwrap()[0], 9);
        backend.reset(&template);
        assert_eq!(backend.completion(0), None);
        assert_eq!(backend.bytes(0), Some(template.as_slice()));
    }

    #[test]
    fn consumed_slot_is_a_typed_recycled_completion() {
        let mut backend = BenchBackend::new(1, IfId(1), &[0; 60]);
        let mut batch = backend.receive(1).unwrap();
        batch
            .next_packet()
            .unwrap()
            .consume(ConsumeReason::ArpControl);
        assert_eq!(batch.finish().recycled, 1);
        assert_eq!(
            backend.completion(0),
            Some(BenchCompletion::Consumed(ConsumeReason::ArpControl))
        );
    }
}
