use std::{marker::PhantomData, rc::Rc};

use crate::{DropReason, IfId};

mod quiescence_guard_sealed {
    pub trait Sealed {}
}

/// Sealed witness implemented only by core's exact backend-borrowing guard.
///
/// This bound prevents a [`PublicationQuiescence`] implementation from using
/// a boolean, counter, or unrelated token as its publication proof.
#[doc(hidden)]
pub trait PublicationQuiescenceWitness: quiescence_guard_sealed::Sealed {
    type Backend;
}

/// Whether packet I/O may continue after a publication-quiescence failure.
///
/// Backends must select `ContinueOldIo` only when the failure prevents an
/// authority change but cannot conflict with another operation using the
/// current publication. Unknown failures are conservatively treated as
/// [`Self::SkipIo`] by [`PublicationQuiescence`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationQuiescenceDisposition {
    ContinueOldIo,
    SkipIo,
    Stop,
}

/// Exclusive, worker-local proof that one exact backend is quiescent.
///
/// The guard deliberately exposes no backend operations. Holding it only
/// preserves the exclusive borrow until a publication attempt returns.
/// `Rc` in the marker keeps the proof `!Send + !Sync`, and the type is neither
/// `Copy`, `Clone`, nor `Debug`.
///
/// ```compile_fail
/// use ruster_core::PublicationQuiescenceGuard;
///
/// fn require_send<T: Send>() {}
/// require_send::<PublicationQuiescenceGuard<'static, Backend>>();
/// # struct Backend;
/// ```
///
/// ```compile_fail
/// use ruster_core::PublicationQuiescenceGuard;
///
/// fn require_sync<T: Sync>() {}
/// require_sync::<PublicationQuiescenceGuard<'static, Backend>>();
/// # struct Backend;
/// ```
///
/// ```compile_fail
/// use ruster_core::PublicationQuiescenceGuard;
///
/// fn clone_guard(guard: PublicationQuiescenceGuard<'_, Backend>) {
///     let _copy = guard.clone();
/// }
/// # struct Backend;
/// ```
///
/// ```compile_fail
/// use std::fmt::Debug;
/// use ruster_core::PublicationQuiescenceGuard;
///
/// fn require_debug<T: Debug>() {}
/// require_debug::<PublicationQuiescenceGuard<'static, Backend>>();
/// # struct Backend;
/// ```
#[must_use = "dropping the guard releases the backend for packet I/O"]
pub struct PublicationQuiescenceGuard<'backend, Backend> {
    _backend: &'backend mut Backend,
    _worker_local: PhantomData<Rc<()>>,
}

impl<'backend, Backend> PublicationQuiescenceGuard<'backend, Backend> {
    /// Constructs a guard after the backend has checked all of its
    /// authoritative outstanding-ownership state.
    ///
    /// This constructor does not perform the check itself. It is intended for
    /// [`PublicationQuiescence::try_publication_quiescence`]
    /// implementations after their bounded check succeeds.
    pub fn new(backend: &'backend mut Backend) -> Self {
        Self {
            _backend: backend,
            _worker_local: PhantomData,
        }
    }
}

impl<Backend> quiescence_guard_sealed::Sealed for PublicationQuiescenceGuard<'_, Backend> {}

impl<Backend> PublicationQuiescenceWitness for PublicationQuiescenceGuard<'_, Backend> {
    type Backend = Backend;
}

/// Backend-authoritative publication quiescence boundary.
///
/// Implementations must inspect only bounded backend-owned state and return a
/// typed error while an RX/generated batch is unfinished, a leased slot has
/// not reached a terminal action, or accepted TX still embeds authority from
/// the active publication. Success returns core's sealed guard, which borrows
/// that exact backend exclusively. Implementing this trait does not by itself
/// claim an AF_XDP completion-queue drain; each backend must define and prove
/// its own authoritative completion boundary.
/// [`Self::quiescence_error_disposition`] classifies one failed publication
/// attempt. [`Self::current_io_disposition`] is the steady, backend-owned
/// re-entry seam: runtimes call it on candidate-free ticks instead of
/// requesting another guard. It must keep returning [`PublicationQuiescenceDisposition::SkipIo`]
/// until an explicit backend recovery has made packet I/O re-entrant.
/// [`PublicationQuiescenceDisposition::Stop`] is terminal for that backend
/// value and must never transition back to another disposition.
///
/// Both checks must inspect only bounded backend-owned state. The error
/// classifier defaults to `SkipIo`, so adding a new error cannot accidentally
/// make the tick containing that error re-entrant.
///
/// A scalar cannot be substituted for the exact borrow:
///
/// ```compile_fail
/// use ruster_core::PublicationQuiescence;
///
/// struct Backend;
///
/// impl PublicationQuiescence for Backend {
///     type Error = ();
///     type Guard<'a> = bool;
///
///     fn try_publication_quiescence(&mut self) -> Result<Self::Guard<'_>, ()> {
///         Ok(true)
///     }
/// }
/// ```
///
/// A guard for another backend is rejected too:
///
/// ```compile_fail
/// use ruster_core::{PublicationQuiescence, PublicationQuiescenceGuard};
///
/// struct Backend;
/// struct OtherBackend;
///
/// impl PublicationQuiescence for Backend {
///     type Error = ();
///     type Guard<'a> = PublicationQuiescenceGuard<'a, OtherBackend>;
///
///     fn try_publication_quiescence(&mut self) -> Result<Self::Guard<'_>, ()> {
///         unreachable!()
///     }
/// }
/// ```
pub trait PublicationQuiescence: Sized {
    type Error;
    type Guard<'backend>: PublicationQuiescenceWitness<Backend = Self>
    where
        Self: 'backend;

    fn try_publication_quiescence(&mut self) -> Result<Self::Guard<'_>, Self::Error>;

    /// Reports whether the backend can safely enter packet I/O now.
    ///
    /// This bounded, read-only check is distinct from acquiring a publication
    /// guard. It is required so a candidate-free tick cannot re-enter a
    /// backend after an earlier `SkipIo` or `Stop` result. `SkipIo` may recover
    /// only after the backend has explicitly reclaimed all conflicting local
    /// ownership. `Stop` is terminal for the lifetime of this backend value.
    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition;

    /// Classifies whether the current publication may continue packet I/O.
    ///
    /// The default is fail-closed for backends whose error taxonomy has not
    /// proved that an error is compatible with another local operation.
    fn quiescence_error_disposition(_error: &Self::Error) -> PublicationQuiescenceDisposition {
        PublicationQuiescenceDisposition::SkipIo
    }
}

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

    /// Flushes requested transmissions and returns accounting for the entire
    /// batch lifetime, starting when the backend created the batch.
    ///
    /// [`BatchCompletion::invariants_hold`] must return `true`, including when
    /// `error` is present. The backend must recycle or free every rejected
    /// slot before returning. Rejected TX slots are accounted in
    /// [`BatchCompletion::tx_rejected`], not
    /// [`BatchCompletion::recycled`].
    ///
    /// For an AF_XDP backend, `tx_accepted` means that a descriptor was
    /// published to the TX producer before this method returned. It does not
    /// mean that the frame reached the wire or appeared on the completion
    /// queue. An error from a wakeup after publication leaves that descriptor
    /// accepted and in flight. `tx_rejected` means the descriptor was not
    /// published and its frame was reclaimed before return. Published frames
    /// remain backend-owned until completion and are not counted as
    /// `recycled`.
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
    ///
    /// For AF_XDP this is the number of descriptors published to the TX
    /// producer, not wire delivery or completion-queue ownership return.
    pub tx_accepted: usize,
    /// Requested TX slots rejected and reclaimed by the backend.
    pub tx_rejected: usize,
    /// RX slots completed with [`SlotCompletion::Recycle`],
    /// [`SlotCompletion::Consume`], or [`SlotCompletion::LeaseAbandoned`].
    ///
    /// This excludes rejected TX slots and slots that were never leased from
    /// the batch. For AF_XDP it also excludes published TX frames waiting for
    /// completion; those remain backend-owned.
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
    use super::{
        BatchCompletion, PublicationQuiescence, PublicationQuiescenceDisposition,
        PublicationQuiescenceGuard,
    };

    struct UnclassifiedBackend;

    impl PublicationQuiescence for UnclassifiedBackend {
        type Error = ();
        type Guard<'backend> = PublicationQuiescenceGuard<'backend, Self>;

        fn try_publication_quiescence(&mut self) -> Result<Self::Guard<'_>, Self::Error> {
            Err(())
        }

        fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
            PublicationQuiescenceDisposition::SkipIo
        }
    }

    #[test]
    fn unclassified_quiescence_error_skips_io_by_default() {
        assert_eq!(
            UnclassifiedBackend::quiescence_error_disposition(&()),
            PublicationQuiescenceDisposition::SkipIo
        );
    }

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
