use std::{
    marker::PhantomData,
    num::NonZeroU64,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{DropReason, GeneratedPacketIo, IfId};

static NEXT_PUBLICATION_BINDING_IDENTITY: AtomicU64 = AtomicU64::new(1);

/// Typed failure returned after all publication-binding identities are spent.
///
/// Exhaustion is terminal for the process-global allocator. Identities never
/// wrap or recover, so an old owner/backend pair cannot become equal again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationBindingIdentityExhausted;

/// Move-only capability reserved for the publication owner of one bound backend.
///
/// The backend type is part of the capability, and the private monotonic
/// identity ties it to one exact [`BoundPublicationBackend`] value. The
/// capability is neither `Copy`, `Clone`, nor `Debug`.
pub struct PublicationOwnerBinding<Backend> {
    identity: NonZeroU64,
    _backend: PhantomData<fn(Backend) -> Backend>,
}

impl<I> PublicationOwnerBinding<BoundPublicationBackend<I>> {
    /// Returns whether `backend` is the exact wrapper paired with this owner.
    ///
    /// This borrow-only precheck compares private immutable identities without
    /// acquiring quiescence or exposing either scalar value.
    #[must_use]
    pub fn matches_backend(&self, backend: &BoundPublicationBackend<I>) -> bool {
        self.identity == backend.identity
    }
}

impl<Backend> PublicationOwnerBinding<Backend> {
    /// Consumes a raw checked guard and authorizes it for this exact owner.
    ///
    /// A guard acquired from another same-type backend is returned unchanged so
    /// the caller can fail closed without losing the exclusive backend borrow.
    pub fn match_quiescence_guard<'backend>(
        &self,
        guard: PublicationQuiescenceGuard<'backend, Backend>,
    ) -> Result<
        MatchedPublicationQuiescenceGuard<'backend, Backend>,
        PublicationQuiescenceGuard<'backend, Backend>,
    > {
        if self.identity == guard.identity {
            Ok(MatchedPublicationQuiescenceGuard { _guard: guard })
        } else {
            Err(guard)
        }
    }
}

/// Core-owned packet-I/O backend carrying one immutable publication identity.
///
/// The wrapper consumes the inner backend and is the logical backend instance
/// used by runtime publication. Its identity has no accessor or replacement
/// seam. Operational traits are delegated directly. Immutable inspection and
/// typed backend-specific commands remain available without exposing a generic
/// mutable borrow that could move out or replace the authoritative backend.
///
/// Even a cloneable, debuggable inner backend does not make the wrapper
/// cloneable or debuggable:
///
/// ```compile_fail
/// use ruster_core::{
///     bind_publication_backend, BoundPublicationBackend, PublicationBackendAuthority,
/// };
///
/// #[derive(Clone, Debug)]
/// struct Backend;
/// // SAFETY: this zero-state fixture exposes no operational backend surface.
/// #[allow(unsafe_code)]
/// unsafe impl PublicationBackendAuthority for Backend {}
/// let (_owner, backend) = bind_publication_backend(Backend).unwrap();
/// let _copy = backend.clone();
/// # let _: BoundPublicationBackend<Backend> = backend;
/// ```
///
/// ```compile_fail
/// use std::fmt::Debug;
/// use ruster_core::{
///     bind_publication_backend, BoundPublicationBackend, PublicationBackendAuthority,
/// };
///
/// #[derive(Clone, Debug)]
/// struct Backend;
/// // SAFETY: this zero-state fixture exposes no operational backend surface.
/// #[allow(unsafe_code)]
/// unsafe impl PublicationBackendAuthority for Backend {}
/// fn require_debug<T: Debug>() {}
/// let (_owner, _backend) = bind_publication_backend(Backend).unwrap();
/// require_debug::<BoundPublicationBackend<Backend>>();
/// ```
///
/// The inner backend can be inspected immutably, but the wrapper provides
/// neither a consuming extraction seam nor a generic mutable borrow. Both
/// negative fixtures satisfy every backend trait bound so a future bound on
/// either accessor cannot make the compile failure a false positive:
///
/// ```compile_fail,E0599
/// use ruster_core::{
///     bind_publication_backend, PublicationBackendAuthority, PublicationBackendControl,
///     PublicationQuiescenceBackend, PublicationQuiescenceDisposition,
/// };
///
/// #[derive(Debug, Default)]
/// struct Backend;
///
/// impl PublicationQuiescenceBackend for Backend {
///     type Error = ();
///
///     fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {
///         Ok(())
///     }
///
///     fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
///         PublicationQuiescenceDisposition::ContinueOldIo
///     }
///
///     fn quiescence_error_disposition(
///         _error: &Self::Error,
///     ) -> PublicationQuiescenceDisposition {
///         PublicationQuiescenceDisposition::SkipIo
///     }
/// }
///
/// // SAFETY: the unit command leaves this zero-state fixture unchanged and the
/// // unit response cannot contain the backend or an authoritative alias.
/// #[allow(unsafe_code)]
/// unsafe impl PublicationBackendControl for Backend {
///     type Command = ();
///     type Response = ();
///
///     fn execute_publication_backend_command(
///         &mut self,
///         _command: Self::Command,
///     ) -> Self::Response {}
/// }
///
/// // SAFETY: every associated output is unit and no operation can detach state.
/// #[allow(unsafe_code)]
/// unsafe impl PublicationBackendAuthority for Backend {}
///
/// let (_owner, backend) = bind_publication_backend(Backend).unwrap();
/// let _detached = backend.into_inner();
/// ```
///
/// ```compile_fail,E0599
/// use std::mem;
/// use ruster_core::{
///     bind_publication_backend, PublicationBackendAuthority, PublicationBackendControl,
///     PublicationQuiescenceBackend, PublicationQuiescenceDisposition,
/// };
///
/// #[derive(Debug, Default)]
/// struct Backend;
///
/// impl PublicationQuiescenceBackend for Backend {
///     type Error = ();
///
///     fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {
///         Ok(())
///     }
///
///     fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
///         PublicationQuiescenceDisposition::ContinueOldIo
///     }
///
///     fn quiescence_error_disposition(
///         _error: &Self::Error,
///     ) -> PublicationQuiescenceDisposition {
///         PublicationQuiescenceDisposition::SkipIo
///     }
/// }
///
/// // SAFETY: the unit command leaves this zero-state fixture unchanged and the
/// // unit response cannot contain the backend or an authoritative alias.
/// #[allow(unsafe_code)]
/// unsafe impl PublicationBackendControl for Backend {
///     type Command = ();
///     type Response = ();
///
///     fn execute_publication_backend_command(
///         &mut self,
///         _command: Self::Command,
///     ) -> Self::Response {}
/// }
///
/// // SAFETY: every associated output is unit and no operation can detach state.
/// #[allow(unsafe_code)]
/// unsafe impl PublicationBackendAuthority for Backend {}
///
/// let (_owner, mut backend) = bind_publication_backend(Backend).unwrap();
/// let _detached = mem::take(backend.inner_mut());
/// ```
pub struct BoundPublicationBackend<I> {
    inner: I,
    identity: NonZeroU64,
}

impl<I> BoundPublicationBackend<I> {
    /// Borrows the inner backend for immutable inspection.
    ///
    /// [`PublicationBackendAuthority`] implementors must audit every safe method
    /// reachable through this shared borrow, including interior-mutability
    /// surfaces. The wrapper deliberately provides no generic mutable borrow
    /// because such a borrow would let safe callers replace or move out the
    /// authoritative backend while retaining this wrapper's publication identity.
    #[must_use]
    pub const fn inner(&self) -> &I {
        &self.inner
    }
}

/// Audited authority boundary for a backend used by publication.
///
/// Safe operational traits cannot express that their associated outputs leave
/// the exact backend value in place. For example, an otherwise safe
/// [`PacketIo`] or [`PublicationQuiescenceBackend`] implementation could use
/// `Self` as an associated output and return `mem::take(self)`. Binding therefore
/// requires this explicit unsafe marker in addition to the individual safe trait
/// implementations.
///
/// A safe external implementation is rejected:
///
/// ```compile_fail,E0200
/// use ruster_core::PublicationBackendAuthority;
///
/// struct Backend;
/// impl PublicationBackendAuthority for Backend {}
/// ```
///
/// # Safety
///
/// Every operation reachable through the backend while it is wrapped by
/// [`BoundPublicationBackend`] must preserve the same logical backend as the
/// authority covered by its immutable binding identity on normal, error, and
/// unwind paths. This includes safe methods reached through
/// [`BoundPublicationBackend::inner`]. In particular:
///
/// - [`PacketIo::receive`], [`GeneratedPacketIo::begin_generated`],
///   [`PublicationQuiescenceBackend::check_publication_quiescence`], and every
///   associated error, batch, slot, or completion path must not move out,
///   replace, swap, or return the backend as a whole;
/// - returned values may hold lifetime-bounded exclusive borrows, but must not
///   contain an independently mutable alias or detached owned state that can
///   change what the wrapper's later quiescence check observes; and
/// - hidden, shared, or interior-mutable authoritative state must remain covered
///   by quiescence for the entire lifetime of the bound backend.
///
/// These are publication-authority invariants rather than memory-safety
/// invariants. Adding or changing any operational trait implementation for a
/// marked type requires re-auditing this contract.
#[allow(unsafe_code)]
pub unsafe trait PublicationBackendAuthority: Sized {}

/// Typed backend-specific control surface delegated by [`BoundPublicationBackend`].
///
/// Unlike a generic `&mut I` accessor, a command exposes only operations chosen
/// by the backend implementation. The trait is unsafe to implement because the
/// wrapper exposes [`BoundPublicationBackend::execute_backend_command`] as a safe
/// method and relies on each implementation to preserve publication authority.
/// Safe external code must therefore make that trust decision explicit:
///
/// ```compile_fail,E0200
/// use std::mem;
/// use ruster_core::{
///     PublicationBackendControl, PublicationQuiescenceBackend,
///     PublicationQuiescenceDisposition,
/// };
///
/// #[derive(Debug, Default)]
/// struct Backend {
///     pending: bool,
/// }
///
/// impl PublicationQuiescenceBackend for Backend {
///     type Error = ();
///
///     fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {
///         if self.pending { Err(()) } else { Ok(()) }
///     }
///
///     fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
///         PublicationQuiescenceDisposition::ContinueOldIo
///     }
///
///     fn quiescence_error_disposition(
///         _error: &Self::Error,
///     ) -> PublicationQuiescenceDisposition {
///         PublicationQuiescenceDisposition::ContinueOldIo
///     }
/// }
///
/// // Rejected: an implementation that can move out the whole backend must be an
/// // explicit unsafe trust boundary.
/// impl PublicationBackendControl for Backend {
///     type Command = ();
///     type Response = Self;
///
///     fn execute_publication_backend_command(
///         &mut self,
///         _command: Self::Command,
///     ) -> Self::Response {
///         mem::take(self)
///     }
/// }
/// ```
///
/// # Safety
///
/// Every command execution must preserve this exact value as the authoritative
/// backend associated with its bound publication identity. In particular, an
/// implementation must not:
///
/// - move out, replace, swap, or return the backend as a whole;
/// - return or otherwise create an independently mutable alias to any state
///   covered by [`PublicationQuiescenceBackend`], including hidden or shared
///   state reachable through interior mutability; or
/// - detach authoritative state from the quiescence check, misclassify its I/O
///   disposition, or make a [`PublicationQuiescenceDisposition::Stop`] state
///   silently reusable.
///
/// These are publication-authority invariants rather than memory-safety
/// invariants. An incorrect unsafe implementation can let safe callers obtain a
/// publication proof for the wrong logical backend.
#[allow(unsafe_code)]
pub unsafe trait PublicationBackendControl: PublicationQuiescenceBackend {
    type Command;
    type Response;

    fn execute_publication_backend_command(&mut self, command: Self::Command) -> Self::Response;
}

impl<I: PublicationBackendAuthority + PublicationBackendControl> BoundPublicationBackend<I> {
    /// Executes one typed backend-specific command without exposing `&mut I`.
    ///
    /// This method is safe because [`PublicationBackendControl`] requires an
    /// audited unsafe implementation that preserves the bound backend's
    /// publication-authority invariants.
    pub fn execute_backend_command(&mut self, command: I::Command) -> I::Response {
        self.inner.execute_publication_backend_command(command)
    }
}

/// Wraps one backend in a core-owned immutable publication identity.
///
/// Identity allocation is monotonic, checked, and allocation-free. After the
/// last nonzero `u64` identity is issued, every later call returns
/// [`PublicationBindingIdentityExhausted`]; identities never wrap or recover.
/// The returned owner capability and backend wrapper are both move-only and do
/// not expose or format the identity. `I` must cross the audited
/// [`PublicationBackendAuthority`] boundary before it can be bound.
///
/// ```compile_fail
/// use ruster_core::{bind_publication_backend, PublicationBackendAuthority};
///
/// #[derive(Clone, Debug)]
/// struct Backend;
/// // SAFETY: this zero-state fixture exposes no operational backend surface.
/// #[allow(unsafe_code)]
/// unsafe impl PublicationBackendAuthority for Backend {}
/// let (owner, _backend) = bind_publication_backend(Backend).unwrap();
/// let _copy = owner.clone();
/// ```
///
/// ```compile_fail
/// use std::fmt::Debug;
/// use ruster_core::{
///     bind_publication_backend, BoundPublicationBackend, PublicationBackendAuthority,
///     PublicationOwnerBinding,
/// };
///
/// #[derive(Clone, Debug)]
/// struct Backend;
/// // SAFETY: this zero-state fixture exposes no operational backend surface.
/// #[allow(unsafe_code)]
/// unsafe impl PublicationBackendAuthority for Backend {}
/// fn require_debug<T: Debug>() {}
/// let (_owner, _backend) = bind_publication_backend(Backend).unwrap();
/// require_debug::<PublicationOwnerBinding<BoundPublicationBackend<Backend>>>();
/// ```
#[must_use = "binding identity exhaustion must be handled"]
pub fn bind_publication_backend<I: PublicationBackendAuthority>(
    inner: I,
) -> Result<
    (
        PublicationOwnerBinding<BoundPublicationBackend<I>>,
        BoundPublicationBackend<I>,
    ),
    PublicationBindingIdentityExhausted,
> {
    bind_publication_backend_from(&NEXT_PUBLICATION_BINDING_IDENTITY, inner)
}

fn bind_publication_backend_from<I: PublicationBackendAuthority>(
    identities: &AtomicU64,
    inner: I,
) -> Result<
    (
        PublicationOwnerBinding<BoundPublicationBackend<I>>,
        BoundPublicationBackend<I>,
    ),
    PublicationBindingIdentityExhausted,
> {
    let identity = identities
        .fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| match current {
                0 => None,
                u64::MAX => Some(0),
                _ => current.checked_add(1),
            },
        )
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or(PublicationBindingIdentityExhausted)?;
    Ok((
        PublicationOwnerBinding {
            identity,
            _backend: PhantomData,
        },
        BoundPublicationBackend { inner, identity },
    ))
}

impl<I: PacketIo + PublicationBackendAuthority> PacketIo for BoundPublicationBackend<I> {
    type Error = I::Error;
    type Batch<'a>
        = I::Batch<'a>
    where
        Self: 'a;

    fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
        self.inner.receive(budget)
    }
}

impl<I: GeneratedPacketIo + PublicationBackendAuthority> GeneratedPacketIo
    for BoundPublicationBackend<I>
{
    type Error = I::Error;
    type Batch<'a>
        = I::Batch<'a>
    where
        Self: 'a;

    fn begin_generated(&mut self, egress: IfId) -> Self::Batch<'_> {
        self.inner.begin_generated(egress)
    }
}

/// Whether packet I/O may continue after a publication-quiescence failure.
///
/// Backends must select `ContinueOldIo` only when the failure prevents an
/// authority change but cannot conflict with another operation using the
/// current publication. Unknown failures are conservatively treated as
/// [`Self::SkipIo`] by [`PublicationQuiescenceBackend`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationQuiescenceDisposition {
    ContinueOldIo,
    SkipIo,
    Stop,
}

/// Backend-specific hooks used by [`BoundPublicationBackend`].
///
/// This public trait deliberately contains no publication identity, guard
/// constructor, or binding accessor. Implementors report only authoritative
/// quiescence state and its I/O disposition. Core seals the runtime-facing
/// [`PublicationQuiescence`] trait so only the immutable wrapper can mint a
/// publication proof.
///
/// Implementors must include every authoritative alias and outstanding owner in
/// the check. In particular, pre-existing aliases, shared resources, clone or
/// interior-mutability surfaces, and [`PublicationBackendControl`] commands must
/// not let safe callers hide live state from this method. Implementors must also
/// classify current and failed states accurately, and a state classified as
/// [`PublicationQuiescenceDisposition::Stop`] must not silently become usable
/// again. Those backend-specific semantic guarantees cannot be inferred by the
/// wrapper; core mechanically enforces identity non-reuse, wrapper ownership,
/// and guard matching around them.
pub trait PublicationQuiescenceBackend: Sized {
    type Error;

    /// Checks all authoritative outstanding-ownership state without creating a
    /// publication proof.
    fn check_publication_quiescence(&mut self) -> Result<(), Self::Error>;

    /// Reports whether the backend can safely enter packet I/O now.
    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition;

    /// Classifies whether the current publication may continue packet I/O.
    ///
    /// The default is fail-closed for backends whose error taxonomy has not
    /// proved that an error is compatible with another local operation.
    fn quiescence_error_disposition(_error: &Self::Error) -> PublicationQuiescenceDisposition {
        PublicationQuiescenceDisposition::SkipIo
    }
}

mod publication_quiescence_sealed {
    pub trait Sealed {}
}

impl<I> publication_quiescence_sealed::Sealed for BoundPublicationBackend<I> {}

/// Runtime-facing backend-authoritative publication quiescence boundary.
///
/// This trait is sealed: external backend types implement
/// [`PublicationQuiescenceBackend`] and are then consumed by
/// [`bind_publication_backend`]. Only [`BoundPublicationBackend`] can acquire a
/// raw guard, and its private identity is snapshotted after the inner backend's
/// check succeeds.
///
/// Direct external implementations are rejected even when every visible method
/// is provided:
///
/// ```compile_fail
/// use ruster_core::{
///     PublicationQuiescence, PublicationQuiescenceDisposition,
///     PublicationQuiescenceGuard,
/// };
///
/// struct Backend;
/// impl PublicationQuiescence for Backend {
///     type Error = ();
///
///     fn try_publication_quiescence(
///         &mut self,
///     ) -> Result<PublicationQuiescenceGuard<'_, Self>, Self::Error> {
///         todo!()
///     }
///
///     fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
///         PublicationQuiescenceDisposition::SkipIo
///     }
///
///     fn quiescence_error_disposition(
///         _error: &Self::Error,
///     ) -> PublicationQuiescenceDisposition {
///         PublicationQuiescenceDisposition::SkipIo
///     }
/// }
/// ```
pub trait PublicationQuiescence: publication_quiescence_sealed::Sealed + Sized {
    type Error;

    /// Checks this exact wrapper and exclusively borrows it in a raw core guard.
    fn try_publication_quiescence(
        &mut self,
    ) -> Result<PublicationQuiescenceGuard<'_, Self>, Self::Error>;

    /// Reports whether the backend can safely enter packet I/O now.
    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition;

    /// Classifies whether the current publication may continue packet I/O.
    fn quiescence_error_disposition(error: &Self::Error) -> PublicationQuiescenceDisposition;
}

impl<I: PublicationBackendAuthority + PublicationQuiescenceBackend> PublicationQuiescence
    for BoundPublicationBackend<I>
{
    type Error = I::Error;

    fn try_publication_quiescence(
        &mut self,
    ) -> Result<PublicationQuiescenceGuard<'_, Self>, Self::Error> {
        self.inner.check_publication_quiescence()?;
        let identity = self.identity;
        Ok(PublicationQuiescenceGuard {
            _backend: self,
            identity,
            _worker_local: PhantomData,
        })
    }

    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
        self.inner.current_io_disposition()
    }

    fn quiescence_error_disposition(error: &Self::Error) -> PublicationQuiescenceDisposition {
        I::quiescence_error_disposition(error)
    }
}

/// Exclusive, worker-local proof that one bound backend is quiescent.
///
/// This raw guard must be consumed by
/// [`PublicationOwnerBinding::match_quiescence_guard`] before publication. The
/// guard deliberately exposes no backend operations and is neither `Copy`,
/// `Clone`, nor `Debug`. Safe external code cannot construct it.
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
/// # #[derive(Debug)]
/// # struct Backend;
/// ```
///
/// ```compile_fail
/// use ruster_core::PublicationQuiescenceGuard;
///
/// struct Backend;
/// let mut backend = Backend;
/// let _forged = PublicationQuiescenceGuard::new(&mut backend);
/// ```
#[must_use = "the raw guard must be matched or explicitly dropped"]
pub struct PublicationQuiescenceGuard<'backend, Backend> {
    _backend: &'backend mut Backend,
    identity: NonZeroU64,
    _worker_local: PhantomData<Rc<()>>,
}

/// Owner-authorized proof that one exact bound backend is quiescent.
///
/// Core creates this capability only by consuming a raw guard whose immutable
/// identity matches the borrowed owner binding. It exposes no constructor or
/// backend operations and is neither `Copy`, `Clone`, nor `Debug`.
///
/// ```compile_fail
/// use ruster_core::{MatchedPublicationQuiescenceGuard, PublicationQuiescenceGuard};
///
/// fn forge(raw: PublicationQuiescenceGuard<'_, Backend>) {
///     let _matched = MatchedPublicationQuiescenceGuard::new(raw);
/// }
/// # struct Backend;
/// ```
///
/// ```compile_fail
/// use ruster_core::MatchedPublicationQuiescenceGuard;
///
/// fn clone_guard(guard: MatchedPublicationQuiescenceGuard<'_, Backend>) {
///     let _copy = guard.clone();
/// }
/// # struct Backend;
/// ```
///
/// ```compile_fail
/// use std::fmt::Debug;
/// use ruster_core::MatchedPublicationQuiescenceGuard;
///
/// fn require_debug<T: Debug>() {}
/// require_debug::<MatchedPublicationQuiescenceGuard<'static, Backend>>();
/// # #[derive(Debug)]
/// # struct Backend;
/// ```
#[must_use = "dropping the guard releases the backend for packet I/O"]
pub struct MatchedPublicationQuiescenceGuard<'backend, Backend> {
    _guard: PublicationQuiescenceGuard<'backend, Backend>,
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
    /// A datagram copied into the hold queue to be split (RFC 791 §3.2). It
    /// leaves as several frames from the generated path, so the received frame
    /// is consumed rather than forwarded or dropped.
    Ipv4Fragmented,
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
    use std::{
        cell::Cell,
        rc::Rc,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{
        bind_publication_backend, bind_publication_backend_from, BatchCompletion, ConsumeReason,
        PacketLease, PacketSlot, PublicationBackendAuthority, PublicationBindingIdentityExhausted,
        PublicationQuiescence, PublicationQuiescenceBackend, PublicationQuiescenceDisposition,
        SlotCompletion,
    };

    struct RecordingSlot {
        completion: Rc<Cell<Option<SlotCompletion>>>,
    }

    impl PacketSlot for RecordingSlot {
        fn ingress(&self) -> crate::IfId {
            crate::IfId(0)
        }

        fn bytes_mut(&mut self) -> &mut [u8] {
            &mut []
        }

        fn complete(self, completion: SlotCompletion) {
            self.completion.set(Some(completion));
        }
    }

    struct TestBackend {
        quiescent: bool,
        checks: usize,
    }

    impl PublicationQuiescenceBackend for TestBackend {
        type Error = ();

        fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {
            self.checks += 1;
            self.quiescent.then_some(()).ok_or(())
        }

        fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
            PublicationQuiescenceDisposition::SkipIo
        }
    }

    // SAFETY: this fixture exposes only the quiescence hook above; it neither
    // replaces itself nor returns the backend or an authoritative alias.
    #[allow(unsafe_code)]
    unsafe impl PublicationBackendAuthority for TestBackend {}

    fn backend(quiescent: bool) -> TestBackend {
        TestBackend {
            quiescent,
            checks: 0,
        }
    }

    #[test]
    fn raw_guard_matches_only_its_exact_owner() {
        let (owner_a, mut backend_a) = bind_publication_backend(backend(true)).unwrap();
        let (owner_b, mut backend_b) = bind_publication_backend(backend(true)).unwrap();

        assert!(owner_a.matches_backend(&backend_a));
        assert!(owner_b.matches_backend(&backend_b));
        assert!(!owner_a.matches_backend(&backend_b));
        assert!(!owner_b.matches_backend(&backend_a));

        let raw_a = backend_a
            .try_publication_quiescence()
            .expect("first backend is quiescent");
        let Ok(matched_a) = owner_a.match_quiescence_guard(raw_a) else {
            panic!("paired owner must accept first guard");
        };
        drop(matched_a);

        let raw_b = backend_b
            .try_publication_quiescence()
            .expect("second backend is quiescent");
        let raw_b = match owner_a.match_quiescence_guard(raw_b) {
            Ok(_) => panic!("foreign same-type owner must reject the guard"),
            Err(raw_b) => raw_b,
        };
        let Ok(matched_b) = owner_b.match_quiescence_guard(raw_b) else {
            panic!("rejected raw guard must remain usable by its paired owner");
        };
        drop(matched_b);
    }

    #[test]
    fn binding_identity_survives_a_wrapper_move() {
        let (owner, backend) = bind_publication_backend(backend(true)).unwrap();
        let mut moved_backend = backend;

        assert!(owner.matches_backend(&moved_backend));
        let raw = moved_backend
            .try_publication_quiescence()
            .expect("moved backend remains quiescent");
        let Ok(matched) = owner.match_quiescence_guard(raw) else {
            panic!("wrapper move must preserve identity");
        };
        drop(matched);
    }

    #[test]
    fn failed_quiescence_check_creates_no_guard() {
        let (_owner, mut backend) = bind_publication_backend(backend(false)).unwrap();

        assert!(backend.try_publication_quiescence().is_err());
    }

    #[test]
    fn binding_identity_allocator_is_monotonic_and_never_recovers() {
        let identities = AtomicU64::new(1);
        let (first, _first_backend) =
            bind_publication_backend_from(&identities, backend(true)).unwrap();
        let (second, _second_backend) =
            bind_publication_backend_from(&identities, backend(true)).unwrap();
        assert_eq!(first.identity.get(), 1);
        assert_eq!(second.identity.get(), 2);

        let identities = AtomicU64::new(u64::MAX - 1);
        let (penultimate, _penultimate_backend) =
            bind_publication_backend_from(&identities, backend(true)).unwrap();
        let (last, _last_backend) =
            bind_publication_backend_from(&identities, backend(true)).unwrap();
        assert_eq!(penultimate.identity.get(), u64::MAX - 1);
        assert_eq!(last.identity.get(), u64::MAX);
        assert_eq!(identities.load(Ordering::Relaxed), 0);
        assert!(matches!(
            bind_publication_backend_from(&identities, backend(true)),
            Err(PublicationBindingIdentityExhausted)
        ));
        assert!(matches!(
            bind_publication_backend_from(&identities, backend(true)),
            Err(PublicationBindingIdentityExhausted)
        ));
        assert_eq!(identities.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unclassified_quiescence_error_skips_io_by_default() {
        assert_eq!(
            TestBackend::quiescence_error_disposition(&()),
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

    #[test]
    fn consuming_a_packet_lease_reports_the_consume_reason() {
        // Protects PacketLease::consume from becoming a no-op and verifies the
        // requested ConsumeReason reaches the backend slot.
        let completion = Rc::new(Cell::new(None));
        let slot = RecordingSlot {
            completion: Rc::clone(&completion),
        };

        PacketLease::new(slot).consume(ConsumeReason::ArpControl);

        assert_eq!(
            completion.get(),
            Some(SlotCompletion::Consume(ConsumeReason::ArpControl))
        );
    }

    #[test]
    fn dropping_a_live_packet_lease_reports_abandonment() {
        // Protects PacketLease's Drop implementation from becoming a no-op and
        // verifies an unfinished lease is returned as LeaseAbandoned.
        let completion = Rc::new(Cell::new(None));
        let slot = RecordingSlot {
            completion: Rc::clone(&completion),
        };
        let lease = PacketLease::new(slot);

        drop(lease);

        assert_eq!(completion.get(), Some(SlotCompletion::LeaseAbandoned));
    }
}
