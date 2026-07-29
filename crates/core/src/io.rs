use std::{marker::PhantomData, rc::Rc};

use crate::{DropReason, IfId};

pub trait PacketIo {
    type Error;
    type Batch<'a>: PacketBatch<Error = Self::Error>
    where
        Self: 'a;

    fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error>;
}

pub trait PacketBatch {
    type Error;
    type Slot<'a>: PacketSlot
    where
        Self: 'a;

    /// Returns a core-owned lease, never a backend's raw slot.
    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>>;

    /// Flushes requested transmissions and always returns their accounting.
    ///
    /// `tx_accepted + tx_rejected == tx_requested` must hold, including when
    /// `error` is present. The backend must recycle or free every rejected
    /// slot before returning.
    fn finish(self) -> BatchCompletion<Self::Error>;
}

/// Backend hook used only behind [`PacketLease`].
pub trait PacketSlot {
    fn ingress(&self) -> IfId;
    fn bytes_mut(&mut self) -> &mut [u8];
    fn complete(self, completion: SlotCompletion);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotCompletion {
    Transmit(IfId),
    Recycle(DropReason),
    Consume(ConsumeReason),
    LeaseAbandoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumeReason {
    ArpControl,
}

/// A core-owned, worker-local RAII lease.
///
/// The `Rc` marker makes this type `!Send + !Sync`; moving a live backend slot
/// across workers is therefore rejected at compile time.
pub struct PacketLease<S: PacketSlot> {
    slot: Option<S>,
    _worker_local: PhantomData<Rc<()>>,
}

impl<S: PacketSlot> PacketLease<S> {
    #[must_use]
    pub fn new(slot: S) -> Self {
        Self {
            slot: Some(slot),
            _worker_local: PhantomData,
        }
    }

    #[must_use]
    pub fn ingress(&self) -> IfId {
        self.slot.as_ref().expect("live packet lease").ingress()
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        self.slot.as_mut().expect("live packet lease").bytes_mut()
    }

    pub fn commit(mut self, egress: IfId) {
        self.complete(SlotCompletion::Transmit(egress));
    }

    pub fn recycle(mut self, reason: DropReason) {
        self.complete(SlotCompletion::Recycle(reason));
    }

    pub fn consume(mut self, reason: ConsumeReason) {
        self.complete(SlotCompletion::Consume(reason));
    }

    fn complete(&mut self, completion: SlotCompletion) {
        self.slot
            .take()
            .expect("packet lease completed exactly once")
            .complete(completion);
    }
}

impl<S: PacketSlot> Drop for PacketLease<S> {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            slot.complete(SlotCompletion::LeaseAbandoned);
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct BatchCompletion<E> {
    pub tx_requested: usize,
    pub tx_accepted: usize,
    pub tx_rejected: usize,
    pub recycled: usize,
    pub error: Option<E>,
}
