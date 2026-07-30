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
    /// [`BatchCompletion::invariants_hold`] must return `true`, including when
    /// `error` is present. The backend must recycle or free every rejected
    /// slot before returning. Rejected TX slots are accounted in
    /// [`BatchCompletion::tx_rejected`], not
    /// [`BatchCompletion::recycled`].
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
#[non_exhaustive]
pub enum ConsumeReason {
    ArpControl,
    /// Valid local IPv4 traffic that this deliberately small control plane
    /// does not implement. It must not fall through to router forwarding.
    Ipv4LocalUnsupported,
}

/// A core-owned, worker-local RAII lease.
///
/// The `Rc` marker makes this type `!Send + !Sync`; moving a live backend slot
/// across workers is therefore rejected at compile time.
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<ruster_core::PacketLease<MySlot>>();
/// # struct MySlot;
/// # impl ruster_core::PacketSlot for MySlot {
/// #   fn ingress(&self) -> ruster_core::IfId { ruster_core::IfId(1) }
/// #   fn bytes_mut(&mut self) -> &mut [u8] { &mut [] }
/// #   fn complete(self, _: ruster_core::SlotCompletion) {}
/// # }
/// ```
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<ruster_core::PacketLease<MySlot>>();
/// # struct MySlot;
/// # impl ruster_core::PacketSlot for MySlot {
/// #   fn ingress(&self) -> ruster_core::IfId { ruster_core::IfId(1) }
/// #   fn bytes_mut(&mut self) -> &mut [u8] { &mut [] }
/// #   fn complete(self, _: ruster_core::SlotCompletion) {}
/// # }
/// ```
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
    /// Slots completed with [`SlotCompletion::Transmit`].
    pub tx_requested: usize,
    /// Requested TX slots accepted by the backend.
    pub tx_accepted: usize,
    /// Requested TX slots rejected and reclaimed by the backend.
    pub tx_rejected: usize,
    /// RX slots completed with [`SlotCompletion::Recycle`],
    /// [`SlotCompletion::Consume`], or [`SlotCompletion::LeaseAbandoned`].
    ///
    /// This excludes rejected TX slots and slots that were never leased from
    /// the batch.
    pub recycled: usize,
    /// A backend error that occurred while preserving all accounting above.
    pub error: Option<E>,
}

impl<E> BatchCompletion<E> {
    /// Returns whether requested TX slots are partitioned exactly into
    /// accepted and rejected slots.
    ///
    /// The invariant is independent of `error`: backends must preserve it on
    /// both successful and failed finishes.
    #[must_use]
    pub const fn invariants_hold(&self) -> bool {
        let Some(accounted) = self.tx_accepted.checked_add(self.tx_rejected) else {
            return false;
        };
        accounted == self.tx_requested
    }
}

#[cfg(test)]
mod tests {
    use super::BatchCompletion;

    #[test]
    fn batch_completion_invariant_is_exact_even_with_error() {
        let completion = BatchCompletion {
            tx_requested: 3,
            tx_accepted: 1,
            tx_rejected: 2,
            recycled: 4,
            error: Some("injected"),
        };
        assert!(completion.invariants_hold());

        let invalid = BatchCompletion {
            tx_requested: 3,
            tx_accepted: 1,
            tx_rejected: 1,
            recycled: 4,
            error: None::<&str>,
        };
        assert!(!invalid.invariants_hold());
    }

    #[test]
    fn batch_completion_invariant_rejects_counter_overflow() {
        let completion = BatchCompletion {
            tx_requested: 0,
            tx_accepted: usize::MAX,
            tx_rejected: 1,
            recycled: 0,
            error: None::<()>,
        };
        assert!(!completion.invariants_hold());
    }
}
