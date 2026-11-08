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

    /// Checks, without allocating anything or changing the session
    /// accounting, that this session can take `frames` more frames of at
    /// most `frame_len` visible bytes each.
    ///
    /// `Ok(())` promises that, if nothing else is allocated in this session
    /// in between, the next `frames` calls to [`Self::allocate`] with a
    /// length of at most `frame_len` succeed, and that committing all of
    /// them is not rejected for lack of room (free frames, TX ring slots,
    /// or an in-flight bound). Only a backend fault, which the session then
    /// reports from [`Self::finish`], may still fail one of them. A caller
    /// that must send a set of frames all or nothing (the fragments of one
    /// IPv4 datagram, RFC 791 §3.2) checks the whole set first, because a
    /// committed frame cannot be taken back. A backend may withhold a small
    /// reserve it keeps for the router's own single frames (ARP, ICMP errors)
    /// from the room it offers here, so a frame set never takes the last of
    /// its pool (the AF_XDP adapter keeps `max(2, pool / 8)`, MTU2 part B).
    ///
    /// `frames == 0` is `Ok(())`. Otherwise the error is the one
    /// [`Self::allocate`] would return first: [`GeneratedAllocationError::ZeroLength`]
    /// for `frame_len == 0`, [`GeneratedAllocationError::FrameTooLarge`]
    /// when `allocate` refuses `frame_len` for its length, and
    /// [`GeneratedAllocationError::Unavailable`] when fewer than `frames`
    /// frames (or less TX room) are available now, the egress is unknown,
    /// or the backend is stopped. Bounded and allocation-free.
    fn check_capacity(
        &mut self,
        frames: usize,
        frame_len: usize,
    ) -> Result<(), GeneratedAllocationError>;

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

    /// The same lease over `f(slot)`, for a backend that wraps another's slots.
    #[must_use]
    pub fn map_slot<T: GeneratedPacketSlot>(
        mut self,
        f: impl FnOnce(S) -> T,
    ) -> GeneratedPacketLease<T> {
        let slot = self.slot.take().expect("live generated lease");
        GeneratedPacketLease::new(f(slot))
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
