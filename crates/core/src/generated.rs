use std::{marker::PhantomData, rc::Rc};

use crate::IfId;

pub trait GeneratedPacketIo {
    type Error;
    type Batch<'a>: GeneratedPacketBatch<Error = Self::Error>
    where
        Self: 'a;

    /// Starts an independent generated-packet session for one egress.
    fn begin_generated(&mut self, egress: IfId) -> Self::Batch<'_>;
}

pub trait GeneratedPacketBatch {
    type Error;
    type Slot<'a>: GeneratedPacketSlot
    where
        Self: 'a;

    /// Allocates a backend-owned frame with exactly `frame_len` visible bytes.
    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError>;

    /// Flushes requested transmissions and always returns accounting.
    ///
    /// Backends must preserve the three invariants checked by
    /// [`GeneratedBatchCompletion::invariants_hold`] even when `error` is
    /// present, and recycle every rejected frame before returning.
    fn finish(self) -> GeneratedBatchCompletion<Self::Error>;
}

/// Backend hook hidden behind [`GeneratedPacketLease`].
pub trait GeneratedPacketSlot {
    fn bytes_mut(&mut self) -> &mut [u8];
    fn complete(self, completion: GeneratedSlotCompletion);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedAllocationError {
    ZeroLength,
    FrameTooLarge,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedSlotCompletion {
    Transmit,
    Cancelled,
    Abandoned,
}

/// Worker-local ownership of one exact-length generated frame.
///
/// A live lease cannot cross a worker boundary:
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<ruster_core::GeneratedPacketLease<MySlot>>();
/// # struct MySlot;
/// # impl ruster_core::GeneratedPacketSlot for MySlot {
/// #   fn bytes_mut(&mut self) -> &mut [u8] { &mut [] }
/// #   fn complete(self, _: ruster_core::GeneratedSlotCompletion) {}
/// # }
/// ```
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<ruster_core::GeneratedPacketLease<MySlot>>();
/// # struct MySlot;
/// # impl ruster_core::GeneratedPacketSlot for MySlot {
/// #   fn bytes_mut(&mut self) -> &mut [u8] { &mut [] }
/// #   fn complete(self, _: ruster_core::GeneratedSlotCompletion) {}
/// # }
/// ```
pub struct GeneratedPacketLease<S: GeneratedPacketSlot> {
    slot: Option<S>,
    _worker_local: PhantomData<Rc<()>>,
}

impl<S: GeneratedPacketSlot> GeneratedPacketLease<S> {
    #[must_use]
    pub fn new(slot: S) -> Self {
        Self {
            slot: Some(slot),
            _worker_local: PhantomData,
        }
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        self.slot
            .as_mut()
            .expect("live generated lease")
            .bytes_mut()
    }

    pub fn commit(mut self) {
        self.complete(GeneratedSlotCompletion::Transmit);
    }

    pub fn cancel(mut self) {
        self.complete(GeneratedSlotCompletion::Cancelled);
    }

    fn complete(&mut self, completion: GeneratedSlotCompletion) {
        self.slot
            .take()
            .expect("generated lease completed exactly once")
            .complete(completion);
    }
}

impl<S: GeneratedPacketSlot> Drop for GeneratedPacketLease<S> {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            slot.complete(GeneratedSlotCompletion::Abandoned);
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedBatchCompletion<E> {
    pub attempts: usize,
    pub allocated: usize,
    pub failed: usize,
    pub requested: usize,
    pub cancelled: usize,
    pub abandoned: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub error: Option<E>,
}

impl<E> GeneratedBatchCompletion<E> {
    #[must_use]
    pub const fn invariants_hold(&self) -> bool {
        self.attempts == self.allocated + self.failed
            && self.allocated == self.requested + self.cancelled + self.abandoned
            && self.accepted + self.rejected == self.requested
    }
}
