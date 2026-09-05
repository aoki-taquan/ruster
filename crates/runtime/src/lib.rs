#![deny(unsafe_code)]
#![doc = "Allocation-free, bounded single-worker tick orchestration for ruster."]

use ruster_core::{
    dispatch_host_unreachable_failures, execute_one_arp_request, execute_one_icmpv4_error,
    forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors_and_timestamp,
    poll_resolution_timers, ArpRequestBuildError, BatchReport, BoundPublicationBackend,
    ExecuteArpRequestError, ExecuteIcmpv4Error, FirewallConfig, FirewallCounters, FirewallRuntime,
    ForwardingSnapshot, GeneratedAllocationError, GeneratedIcmpv4TraceSink, GeneratedPacketIo,
    GeneratedTraceSink, Icmpv4ErrorBuildError, Icmpv4ErrorRuntime, Icmpv4TimestampClock,
    MatchedPublicationQuiescenceGuard, MonotonicMillis, Nat44TcpConfig, Nat44TcpCounters,
    Nat44TcpRuntime, Nat44UdpConfig, Nat44UdpCounters, Nat44UdpRuntime, PacketIo,
    PublicationBackendAuthority, PublicationOwnerBinding, PublicationQuiescence,
    PublicationQuiescenceBackend, PublicationQuiescenceDisposition, PublicationQuiescenceGuard,
    ResolutionFailureDispatchError, ResolutionFailureDispatchReport, ResolutionFailureTraceSink,
    ResolutionRuntime, ResolutionTimerError, ResolutionTimerReport, ResolutionTimerTraceSink,
    TraceSink,
};
use std::{fmt, num::NonZeroU64};

pub mod observability;

/// Tick-local UDP NAT44 authority and its optional worker-local runtime.
///
/// The fields are private so downstream callers cannot reconcile the runtime
/// behind the generation-tagged publication. Publication adapters can construct
/// the paired view, while only this crate's tick engine can consume the mutable
/// runtime borrow.
pub struct Nat44UdpServiceView<'view, 'storage> {
    config: Nat44UdpConfig,
    runtime: Option<&'view mut Nat44UdpRuntime<'storage>>,
}

impl<'view, 'storage> Nat44UdpServiceView<'view, 'storage> {
    /// Pairs validated UDP authority with its worker-local runtime.
    #[must_use]
    pub const fn new(
        config: Nat44UdpConfig,
        runtime: Option<&'view mut Nat44UdpRuntime<'storage>>,
    ) -> Self {
        Self { config, runtime }
    }

    /// Returns the copied UDP authority without exposing mutable runtime state.
    #[must_use]
    pub const fn config(&self) -> Nat44UdpConfig {
        self.config
    }

    /// Reports whether this publication supplied UDP runtime state.
    #[must_use]
    pub const fn has_runtime(&self) -> bool {
        self.runtime.is_some()
    }

    /// Returns a copy of the cumulative saturating UDP NAT44 counters, or
    /// `None` when this tick has no runtime state. Read-only: the runtime
    /// borrow behind it remains sealed to this crate.
    #[must_use]
    pub fn counters(&self) -> Option<Nat44UdpCounters> {
        self.runtime.as_deref().map(Nat44UdpRuntime::counters)
    }
}

/// Tick-local TCP NAT44 authority and its optional worker-local runtime.
///
/// The optional runtime preserves the existing fail-closed packet semantics
/// when a configured service cannot supply mutable state for a tick. Its borrow
/// remains private so callers cannot rotate its key outside publication.
pub struct Nat44TcpServiceView<'view, 'storage> {
    config: Nat44TcpConfig,
    runtime: Option<&'view mut Nat44TcpRuntime<'storage>>,
}

impl<'view, 'storage> Nat44TcpServiceView<'view, 'storage> {
    /// Pairs validated TCP authority with its worker-local runtime.
    #[must_use]
    pub const fn new(
        config: Nat44TcpConfig,
        runtime: Option<&'view mut Nat44TcpRuntime<'storage>>,
    ) -> Self {
        Self { config, runtime }
    }

    /// Returns the copied TCP authority without exposing mutable runtime state.
    #[must_use]
    pub const fn config(&self) -> Nat44TcpConfig {
        self.config
    }

    /// Reports whether this publication supplied TCP runtime state.
    #[must_use]
    pub const fn has_runtime(&self) -> bool {
        self.runtime.is_some()
    }

    /// Returns a copy of the cumulative saturating TCP NAT44 counters, or
    /// `None` when this tick has no runtime state. Read-only: the runtime
    /// borrow behind it remains sealed to this crate.
    #[must_use]
    pub fn counters(&self) -> Option<Nat44TcpCounters> {
        self.runtime.as_deref().map(Nat44TcpRuntime::counters)
    }
}

/// Tick-local firewall authority and its optional worker-local runtime.
///
/// The config's borrowed rules and the runtime borrow are both shortened to
/// the lifetime of the active publication view. The runtime remains private to
/// the tick engine so the pair cannot be separated by downstream code.
pub struct FirewallServiceView<'view, 'storage> {
    config: FirewallConfig<'view>,
    runtime: Option<&'view mut FirewallRuntime<'storage>>,
}

impl<'view, 'storage> FirewallServiceView<'view, 'storage> {
    /// Pairs validated firewall authority with its worker-local runtime.
    #[must_use]
    pub const fn new(
        config: FirewallConfig<'view>,
        runtime: Option<&'view mut FirewallRuntime<'storage>>,
    ) -> Self {
        Self { config, runtime }
    }

    /// Returns the copied firewall authority without exposing mutable state.
    #[must_use]
    pub const fn config(&self) -> FirewallConfig<'view> {
        self.config
    }

    /// Reports whether this publication supplied firewall runtime state.
    #[must_use]
    pub const fn has_runtime(&self) -> bool {
        self.runtime.is_some()
    }

    /// Returns a copy of the cumulative saturating firewall counters, or
    /// `None` when this tick has no runtime state. Read-only: the runtime
    /// borrow behind it remains sealed to this crate.
    #[must_use]
    pub fn counters(&self) -> Option<FirewallCounters> {
        self.runtime.as_deref().map(FirewallRuntime::counters)
    }
}

/// All immutable authority and mutable worker-local state required by the
/// full UDP/TCP NAT44, firewall, resolution, and generated ICMP composition.
///
/// The immutable snapshot, generation-bound tick budgets, and validated
/// configs are copied into each tick-local view. Each NAT/firewall config is paired with its runtime in a
/// service-specific nested view, and every borrowed slice is shortened to
/// `'view`, so neither immutable authority nor mutable runtime state can
/// escape the borrow of the publication adapter. `FullServiceView`
/// deliberately remains move-only:
///
/// ```compile_fail
/// use ruster_runtime::FullServiceView;
///
/// fn move_twice(view: FullServiceView<'_, '_>) {
///     let first = view;
///     let second = view;
///     drop((first, second));
/// }
/// ```
///
/// It is not clonable either:
///
/// ```compile_fail
/// use ruster_runtime::FullServiceView;
///
/// fn clone_view(view: FullServiceView<'_, '_>) {
///     let _copy = view.clone();
/// }
/// ```
///
/// Extracting copied authority does not release the adapter borrow. A
/// candidate cannot be published while that authority is still live:
///
/// ```compile_fail
/// use ruster_core::{
///     BoundPublicationBackend, PublicationBackendAuthority, PublicationQuiescence,
///     PublicationQuiescenceBackend,
/// };
/// use ruster_runtime::{
///     try_publish_candidate, FullServicePublication, FullServiceView,
/// };
///
/// fn publish_while_authority_is_live<'storage, I, P>(
///     publication: &mut P,
///     io: &mut BoundPublicationBackend<I>,
///     candidate: P::Candidate,
/// )
/// where
///     I: PublicationBackendAuthority + PublicationQuiescenceBackend,
///     P: FullServicePublication<'storage, BoundPublicationBackend<I>>,
/// {
///     let view: FullServiceView<'_, 'storage> = publication.active();
///     let snapshot = view.snapshot();
///     let firewall_config = view.firewall_config();
///     let Ok(guard) = io.try_publication_quiescence() else {
///         return;
///     };
///     let _result = try_publish_candidate(publication, candidate, guard);
///     drop((snapshot, firewall_config));
/// }
/// ```
///
/// The complete old view likewise cannot remain live across a publication
/// attempt:
///
/// ```compile_fail
/// use ruster_core::{
///     BoundPublicationBackend, PublicationBackendAuthority, PublicationQuiescence,
///     PublicationQuiescenceBackend,
/// };
/// use ruster_runtime::{try_publish_candidate, FullServicePublication};
///
/// fn publish_while_old_view_is_live<'storage, I, P>(
///     publication: &mut P,
///     io: &mut BoundPublicationBackend<I>,
///     candidate: P::Candidate,
/// )
/// where
///     I: PublicationBackendAuthority + PublicationQuiescenceBackend,
///     P: FullServicePublication<'storage, BoundPublicationBackend<I>>,
/// {
///     let old_view = publication.active();
///     let Ok(guard) = io.try_publication_quiescence() else {
///         return;
///     };
///     let _result = try_publish_candidate(publication, candidate, guard);
///     drop(old_view);
/// }
/// ```
///
/// This paired, generation-tagged by-value layout is a pre-1.0 source break
/// from the earlier flat config/runtime fields and the older
/// `&ForwardingSnapshot` field. Downstream adapters construct the view with a
/// copied `ForwardingSnapshot`, a nonzero generation, generation-bound tick
/// budgets, and the three nested service views.
///
/// Existing code that extracts the removed flat fields no longer compiles:
///
/// ```compile_fail
/// use ruster_runtime::FullServiceView;
///
/// fn use_old_flat_fields(view: FullServiceView<'_, '_>) {
///     let FullServiceView {
///         udp_config,
///         tcp_config,
///         firewall_config,
///         ..
///     } = view;
///     drop((udp_config, tcp_config, firewall_config));
/// }
/// ```
pub struct FullServiceView<'view, 'storage> {
    tick_authority: &'view ActiveTickAuthority,
    snapshot: ForwardingSnapshot<'view>,
    resolution: &'view mut ResolutionRuntime<'storage>,
    icmpv4_errors: &'view mut Icmpv4ErrorRuntime<'storage>,
    nat44_udp: Nat44UdpServiceView<'view, 'storage>,
    nat44_tcp: Nat44TcpServiceView<'view, 'storage>,
    firewall: FirewallServiceView<'view, 'storage>,
}

impl<'view, 'storage> FullServiceView<'view, 'storage> {
    /// Constructs one coherent tick-local view for a publication adapter.
    ///
    /// Mutable runtime fields remain private after construction. This prevents
    /// downstream code from reconciling a NAT runtime without also replacing
    /// the generation-tagged candidate that supplied its authority.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "one constructor binds all generation-local authority and runtime state"
    )]
    pub const fn new(
        tick_authority: &'view ActiveTickAuthority,
        snapshot: ForwardingSnapshot<'view>,
        resolution: &'view mut ResolutionRuntime<'storage>,
        icmpv4_errors: &'view mut Icmpv4ErrorRuntime<'storage>,
        nat44_udp: Nat44UdpServiceView<'view, 'storage>,
        nat44_tcp: Nat44TcpServiceView<'view, 'storage>,
        firewall: FirewallServiceView<'view, 'storage>,
    ) -> Self {
        Self {
            tick_authority,
            snapshot,
            resolution,
            icmpv4_errors,
            nat44_udp,
            nat44_tcp,
            firewall,
        }
    }

    /// Returns the generation of all authority and state in this view.
    #[must_use]
    pub const fn generation(&self) -> NonZeroU64 {
        self.tick_authority.generation()
    }

    /// Returns the budgets paired with this active generation.
    #[must_use]
    pub const fn tick_budgets(&self) -> TickBudgets {
        self.tick_authority.tick_budgets()
    }

    /// Returns the copied forwarding authority.
    #[must_use]
    pub const fn snapshot(&self) -> ForwardingSnapshot<'view> {
        self.snapshot
    }

    /// Returns the copied UDP NAT authority.
    #[must_use]
    pub const fn nat44_udp_config(&self) -> Nat44UdpConfig {
        self.nat44_udp.config()
    }

    /// Returns the copied TCP NAT authority.
    #[must_use]
    pub const fn nat44_tcp_config(&self) -> Nat44TcpConfig {
        self.nat44_tcp.config()
    }

    /// Returns the copied firewall authority.
    #[must_use]
    pub const fn firewall_config(&self) -> FirewallConfig<'view> {
        self.firewall.config()
    }

    /// Reports whether this publication supplied UDP runtime state.
    #[must_use]
    pub const fn has_nat44_udp_runtime(&self) -> bool {
        self.nat44_udp.has_runtime()
    }

    /// Reports whether this publication supplied TCP runtime state.
    #[must_use]
    pub const fn has_nat44_tcp_runtime(&self) -> bool {
        self.nat44_tcp.has_runtime()
    }

    /// Reports whether this publication supplied firewall runtime state.
    #[must_use]
    pub const fn has_firewall_runtime(&self) -> bool {
        self.firewall.has_runtime()
    }

    /// Returns a copy of the cumulative saturating UDP NAT44 counters, or
    /// `None` when this tick has no UDP runtime state.
    #[must_use]
    pub fn nat44_udp_counters(&self) -> Option<Nat44UdpCounters> {
        self.nat44_udp.counters()
    }

    /// Returns a copy of the cumulative saturating TCP NAT44 counters, or
    /// `None` when this tick has no TCP runtime state.
    #[must_use]
    pub fn nat44_tcp_counters(&self) -> Option<Nat44TcpCounters> {
        self.nat44_tcp.counters()
    }

    /// Returns a copy of the cumulative saturating firewall counters, or
    /// `None` when this tick has no firewall runtime state.
    #[must_use]
    pub fn firewall_counters(&self) -> Option<FirewallCounters> {
        self.firewall.counters()
    }
}

/// A publication rejection that preserves ownership of the exact candidate.
///
/// This wrapper only guarantees ownership preservation; the error taxonomy
/// decides whether the operation is retryable or terminal. A publication adapter
/// must return the same candidate ownership it received. The caller can inspect
/// the error through [`Self::error`] and recover both values through
/// [`Self::into_parts`] before deciding whether to retry, revise, or discard the
/// candidate.
///
/// Candidate authority can contain allocator seeds or other secrets, so this
/// wrapper deliberately provides neither `Debug` nor `Clone`. Its fields remain
/// private to prevent accidental partial extraction or logging.
///
/// ```compile_fail
/// use ruster_runtime::PublicationRejection;
///
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<PublicationRejection<u8, ()>>();
/// ```
///
/// ```compile_fail
/// use ruster_runtime::PublicationRejection;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<PublicationRejection<u8, ()>>();
/// ```
#[must_use = "a rejected candidate retains caller-owned authority"]
#[derive(Eq, PartialEq)]
pub struct PublicationRejection<C, E> {
    candidate: C,
    error: E,
}

impl<C, E> PublicationRejection<C, E> {
    /// Creates a rejection from the exact candidate that was not published.
    ///
    /// Publication adapters use this constructor whenever a failed cold
    /// boundary must return the exact candidate to a caller outside this crate.
    pub const fn new(candidate: C, error: E) -> Self {
        Self { candidate, error }
    }

    /// Returns the publication error without exposing the candidate.
    #[must_use]
    pub const fn error(&self) -> &E {
        &self.error
    }

    /// Recovers the rejected candidate and its error without cloning either.
    #[must_use]
    pub fn into_parts(self) -> (C, E) {
        (self.candidate, self.error)
    }
}

/// Immutable status of the publication owner's active authority.
///
/// This is independent of [`PublicationQuiescenceDisposition`], which describes
/// one packet backend. `StopOldPublication` asserts that an active publication
/// still exists but has latched an authority invariant failure, so it must never
/// be borrowed for data phases. There is deliberately no default: every adapter
/// must classify absence, executable authority, and terminal authority explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivePublicationStatus {
    Absent,
    ContinueOldIo,
    StopOldPublication,
}

impl ActivePublicationStatus {
    /// Reports whether the owner still contains an active publication.
    #[must_use]
    pub const fn is_present(self) -> bool {
        !matches!(self, Self::Absent)
    }
}

/// Failure returned by [`try_publish_candidate`] before a candidate is applied.
///
/// Both variants preserve ownership of the exact candidate. Candidate authority
/// may contain allocator seeds or other secrets, so `Debug` redacts it.
#[must_use = "a failed publication attempt retains caller-owned authority"]
#[derive(Eq, PartialEq)]
pub enum PublicationAttemptError<C, E> {
    /// The raw quiescence guard belongs to another same-type backend instance.
    BackendMismatch { candidate: C },
    /// The authorized adapter rejected the candidate unchanged.
    Rejected(PublicationRejection<C, E>),
}

impl<C, E> fmt::Debug for PublicationAttemptError<C, E>
where
    E: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendMismatch { .. } => formatter
                .debug_struct("BackendMismatch")
                .field("candidate", &"<redacted>")
                .finish(),
            Self::Rejected(rejection) => formatter
                .debug_struct("Rejected")
                .field("candidate", &"<redacted>")
                .field("error", rejection.error())
                .finish(),
        }
    }
}

/// Atomic publication seam used by [`run_tick`] and [`try_publish_candidate`].
///
/// The authorized hook receives a move-only guard that core matched to this
/// owner's exact bound backend. Safe callers use [`try_publish_candidate`], which
/// performs the owner match and preserves the candidate on mismatch. The guard
/// cannot coexist with packet I/O and is dropped when the publication call
/// returns.
///
/// # Safety
///
/// Implementing this trait accepts the publication-adapter authority boundary.
/// Every implementation must uphold all of the following invariants:
///
/// - [`Self::publication_owner_binding`] is stable and belongs to the exact bound
///   backend whose quiescence governs every active service runtime;
/// - [`Self::active_status`] is immutable, O(1), and coherent: `Absent` means no
///   active authority exists, `ContinueOldIo` means [`Self::active`] can borrow one
///   complete coherent generation, and `StopOldPublication` means an authority
///   still exists but may never be borrowed or executed;
/// - `StopOldPublication` is terminal for this owner and retains the same typed
///   cause returned by [`Self::reject_candidate_if_active_stopped`];
/// - both rejection paths return the exact candidate value they received. They
///   must never substitute, clone, reconstruct, or retain candidate authority;
/// - a rejected publication leaves the previous active candidate, all service
///   runtimes, and their backing storage unchanged, except that a detected active
///   invariant failure may atomically latch `StopOldPublication` and its cause;
/// - a successful publication installs the entire candidate and all associated
///   runtime transitions atomically before reporting success; and
/// - [`Self::active`] is allocation-free and O(1), performs no validation, scan,
///   hash, or reconciliation work, and returns a view that remains one coherent
///   generation until dropped.
///
/// Violating these semantic requirements can let safe runtime code publish or
/// execute authority that was not covered by the matched backend proof.
/// The validated snapshot and NAT/firewall configs are copied into the view by
/// value so an adapter never has to return references to temporary values. A full
/// view currently contains all three configured service pairs; representing a
/// service as wholly absent requires a future core composition seam that accepts
/// optional configs as well as optional runtimes.
///
/// Direct raw-guard publication is an intentional pre-1.0 source break:
///
/// ```compile_fail
/// use ruster_core::{PublicationQuiescence, PublicationQuiescenceGuard};
/// use ruster_runtime::FullServicePublication;
///
/// fn old_direct_call<'storage, I, P>(
///     publication: &mut P,
///     candidate: P::Candidate,
///     raw: PublicationQuiescenceGuard<'_, I>,
/// ) where
///     I: PublicationQuiescence,
///     P: FullServicePublication<'storage, I>,
/// {
///     publication.publish_candidate(candidate, raw);
/// }
/// ```
///
/// The typed apply report is an intentional pre-1.0 source break for
/// publication adapters. An otherwise complete adapter must declare it:
///
/// ```compile_fail
/// use ruster_core::{
///     BoundPublicationBackend, MatchedPublicationQuiescenceGuard,
///     PublicationOwnerBinding,
/// };
/// use ruster_io_sim::SimIo;
///
/// type Backend = BoundPublicationBackend<SimIo>;
/// use ruster_runtime::{
///     ActivePublicationStatus, FullServicePublication, FullServiceView,
///     PublicationRejection,
/// };
///
/// struct MissingApplyReport {
///     owner_binding: PublicationOwnerBinding<Backend>,
/// }
///
/// unsafe impl<'storage> FullServicePublication<'storage, Backend> for MissingApplyReport {
///     type Candidate = ();
///     type Reject = ();
///
///     fn publication_owner_binding(&self) -> &PublicationOwnerBinding<Backend> {
///         &self.owner_binding
///     }
///
///     unsafe fn publish_candidate_authorized(
///         &mut self,
///         _candidate: Self::Candidate,
///         _quiescence: MatchedPublicationQuiescenceGuard<'_, Backend>,
///     ) -> Result<
///         Self::ApplyReport,
///         PublicationRejection<Self::Candidate, Self::Reject>,
///     > {
///         unreachable!()
///     }
///
///     fn reject_candidate_if_active_stopped(
///         &self,
///         candidate: Self::Candidate,
///     ) -> Result<Self::Candidate, PublicationRejection<Self::Candidate, Self::Reject>> {
///         Ok(candidate)
///     }
///
///     fn active_status(&self) -> ActivePublicationStatus {
///         ActivePublicationStatus::Absent
///     }
///
///     fn active(&mut self) -> FullServiceView<'_, 'storage> {
///         unreachable!()
///     }
/// }
/// ```
///
/// Declaring an apply report while retaining the former unit success result is
/// a separate source error:
///
/// ```compile_fail
/// use ruster_core::{
///     BoundPublicationBackend, MatchedPublicationQuiescenceGuard,
///     PublicationOwnerBinding,
/// };
/// use ruster_io_sim::SimIo;
///
/// type Backend = BoundPublicationBackend<SimIo>;
/// use ruster_runtime::{
///     ActivePublicationStatus, FullServicePublication, FullServiceView,
///     PublicationRejection,
/// };
///
/// struct UnitResultAdapter {
///     owner_binding: PublicationOwnerBinding<Backend>,
/// }
///
/// unsafe impl<'storage> FullServicePublication<'storage, Backend> for UnitResultAdapter {
///     type Candidate = ();
///     type Reject = ();
///     type ApplyReport = u8;
///
///     fn publication_owner_binding(&self) -> &PublicationOwnerBinding<Backend> {
///         &self.owner_binding
///     }
///
///     unsafe fn publish_candidate_authorized(
///         &mut self,
///         _candidate: Self::Candidate,
///         _quiescence: MatchedPublicationQuiescenceGuard<'_, Backend>,
///     ) -> Result<(), PublicationRejection<Self::Candidate, Self::Reject>> {
///         Ok(())
///     }
///
///     fn reject_candidate_if_active_stopped(
///         &self,
///         candidate: Self::Candidate,
///     ) -> Result<Self::Candidate, PublicationRejection<Self::Candidate, Self::Reject>> {
///         Ok(candidate)
///     }
///
///     fn active_status(&self) -> ActivePublicationStatus {
///         ActivePublicationStatus::Absent
///     }
///
///     fn active(&mut self) -> FullServiceView<'_, 'storage> {
///         unreachable!()
///     }
/// }
/// ```
#[allow(unsafe_code)]
pub unsafe trait FullServicePublication<'storage, I: PublicationQuiescence> {
    type Candidate;
    type Reject;
    type ApplyReport;

    /// Returns the move-only owner capability paired with the exact backend
    /// instance allowed to drive this publication owner.
    fn publication_owner_binding(&self) -> &PublicationOwnerBinding<I>;

    /// Applies one candidate after the caller authorizes exact-backend quiescence.
    ///
    /// # Safety
    ///
    /// The matched guard must have been produced for this exact publication
    /// owner's binding and must retain the exclusive backend borrow for the whole
    /// call. Safe code must call [`try_publish_candidate`] instead.
    #[allow(unsafe_code)]
    unsafe fn publish_candidate_authorized(
        &mut self,
        candidate: Self::Candidate,
        quiescence: MatchedPublicationQuiescenceGuard<'_, I>,
    ) -> Result<Self::ApplyReport, PublicationRejection<Self::Candidate, Self::Reject>>;

    /// Rejects a candidate from an already stopped publication before backend
    /// quiescence is requested.
    ///
    /// This check must be O(1), mutation-free, and preserve the exact candidate.
    /// When [`Self::active_status`] is `StopOldPublication`, it must return the
    /// same latched typed cause that the owner would return from
    /// [`Self::publish_candidate_authorized`]. Otherwise it must return the
    /// candidate unchanged. [`run_tick`] calls this only after exact backend
    /// identity matching, and [`try_publish_candidate`] repeats it after raw guard
    /// matching so neither safe entry can reach the adapter hook under a latch.
    fn reject_candidate_if_active_stopped(
        &self,
        candidate: Self::Candidate,
    ) -> Result<Self::Candidate, PublicationRejection<Self::Candidate, Self::Reject>>;

    /// Returns the immutable, coherent active-authority status.
    ///
    /// This method must be O(1), mutation-free, and must not borrow any mutable
    /// service runtime. [`run_tick`] uses it for backend mismatch and skip
    /// decisions without calling [`Self::active`].
    fn active_status(&self) -> ActivePublicationStatus;

    /// Borrows the complete active generation.
    ///
    /// [`run_tick`] calls this method only after observing
    /// [`ActivePublicationStatus::ContinueOldIo`] and a backend disposition that
    /// permits data phases.
    fn active(&mut self) -> FullServiceView<'_, 'storage>;
}

/// Safely authorizes and applies one candidate against a checked raw guard.
///
/// A guard from another same-type bound backend is rejected before the active
/// latch is inspected. After an exact match, an already stopped publication
/// rejects with its latched cause before the adapter hook runs. Both paths
/// preserve the exact candidate and old active publication.
#[allow(unsafe_code)]
pub fn try_publish_candidate<'storage, P, I>(
    publication: &mut P,
    candidate: P::Candidate,
    quiescence: PublicationQuiescenceGuard<'_, BoundPublicationBackend<I>>,
) -> Result<P::ApplyReport, PublicationAttemptError<P::Candidate, P::Reject>>
where
    P: FullServicePublication<'storage, BoundPublicationBackend<I>>,
    I: PublicationBackendAuthority + PublicationQuiescenceBackend,
{
    let quiescence = match publication
        .publication_owner_binding()
        .match_quiescence_guard(quiescence)
    {
        Ok(quiescence) => quiescence,
        Err(quiescence) => {
            drop(quiescence);
            return Err(PublicationAttemptError::BackendMismatch { candidate });
        }
    };
    let candidate = match publication.reject_candidate_if_active_stopped(candidate) {
        Ok(candidate) => candidate,
        Err(rejection) => {
            drop(quiescence);
            return Err(PublicationAttemptError::Rejected(rejection));
        }
    };

    // SAFETY: the only safe entry point consumed the raw guard and matched its
    // immutable core-owned identity against this exact publication owner. The
    // mutation-free latch check also confirmed this candidate may reach the hook.
    unsafe { publication.publish_candidate_authorized(candidate, quiescence) }
        .map_err(PublicationAttemptError::Rejected)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TickBudgets {
    pub rx: usize,
    pub resolution_timer_scans: usize,
    pub failure_dispatch_scans: usize,
    pub generated_arp: usize,
    pub generated_icmpv4: usize,
}

/// One generation's identity paired with its tick budgets.
///
/// [`FullServiceView`] borrows this instead of embedding both values by
/// value, so a coherent update of the pair is a single write at the owner
/// and every view stays a plain reference. A publication adapter must keep
/// exactly one instance of this type per active generation and update it
/// atomically with the generation it identifies; it must never expose two
/// different generations' budgets as members of the same instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveTickAuthority {
    generation: NonZeroU64,
    tick_budgets: TickBudgets,
}

impl ActiveTickAuthority {
    /// Pairs one generation identity with its tick budgets.
    #[must_use]
    pub const fn new(generation: NonZeroU64, tick_budgets: TickBudgets) -> Self {
        Self {
            generation,
            tick_budgets,
        }
    }

    /// Returns the paired generation identity.
    #[must_use]
    pub const fn generation(&self) -> NonZeroU64 {
        self.generation
    }

    /// Returns the paired tick budgets.
    #[must_use]
    pub const fn tick_budgets(&self) -> TickBudgets {
        self.tick_budgets
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TickPhase {
    Publication,
    Rx,
    ResolutionTimers,
    FailureDispatch,
    GeneratedArp,
    GeneratedIcmpv4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TickPhaseSkip {
    NoActivePublication,
    BackendInstanceMismatch,
    ActivePublicationInvalid,
    BackendIoNotReentrant,
    BackendStopped,
    BackendIoFailure,
    BackendContractViolation,
    ClockRegression,
    GeneratedArpFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TickPhaseTrace {
    TickStarted,
    PhaseStarted(TickPhase),
    PhaseFinished(TickPhase),
    PhaseSkipped {
        phase: TickPhase,
        reason: TickPhaseSkip,
    },
    TickFinished,
}

pub trait TickPhaseTraceSink {
    fn record_tick_phase(&mut self, event: TickPhaseTrace);
}

#[derive(Default)]
pub struct NoTickPhaseTrace;

impl TickPhaseTraceSink for NoTickPhaseTrace {
    fn record_tick_phase(&mut self, _event: TickPhaseTrace) {}
}

/// Result of the publication phase, including any unconsumed candidate.
///
/// `Rejected`, `Deferred`, and candidate-bearing `BackendMismatch` preserve the
/// exact candidate ownership supplied to [`run_tick`]. Rejection reports whether
/// the old publication remains executable; the adapter's `E` taxonomy decides
/// whether the candidate should be retried, revised, or discarded. A deferred
/// candidate can be retried after the backend condition changes or with a replacement backend;
/// `Stop` remains terminal for the backend value that reported it. The deferred
/// disposition controls whether old-publication I/O may continue in the current
/// tick and never consumes the candidate. `Applied` carries the adapter's typed
/// report for the completed transaction.
///
/// `Debug` deliberately redacts candidates while retaining the error and
/// disposition needed for operational diagnosis.
///
/// Ignoring an outcome can silently discard the exact rejected or deferred
/// candidate, so the type is `must_use`:
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use ruster_runtime::PublicationOutcome;
///
/// fn discard(outcome: PublicationOutcome<(), (), ()>) {
///     outcome;
/// }
/// ```
///
/// `Applied` now always carries the adapter's typed report. The former unit
/// pattern is an intentional pre-1.0 source break:
///
/// ```compile_fail
/// use ruster_runtime::PublicationOutcome;
///
/// fn use_old_unit_pattern(outcome: PublicationOutcome<(), (), (), u8>) {
///     if let PublicationOutcome::Applied = outcome {}
/// }
/// ```
#[must_use = "the publication outcome may retain an unconsumed candidate"]
#[derive(Eq, PartialEq)]
pub enum PublicationOutcome<C, E, Q, A = ()> {
    Unchanged,
    Applied(A),
    /// The supplied backend is not the instance paired with this publication.
    BackendMismatch {
        candidate: Option<C>,
    },
    /// The backend refused quiescence before the adapter saw the candidate.
    Deferred {
        candidate: C,
        error: Q,
        disposition: PublicationQuiescenceDisposition,
    },
    /// The adapter rejected publication and returned the candidate unchanged.
    Rejected {
        rejection: PublicationRejection<C, E>,
        status: ActivePublicationStatus,
    },
}

impl<C, E, Q, A> fmt::Debug for PublicationOutcome<C, E, Q, A>
where
    E: fmt::Debug,
    Q: fmt::Debug,
    A: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unchanged => formatter.write_str("Unchanged"),
            Self::Applied(report) => formatter.debug_tuple("Applied").field(report).finish(),
            Self::BackendMismatch { candidate } => formatter
                .debug_struct("BackendMismatch")
                .field("candidate", &candidate.as_ref().map(|_| "<redacted>"))
                .finish(),
            Self::Rejected { rejection, status } => formatter
                .debug_struct("Rejected")
                .field("candidate", &"<redacted>")
                .field("error", rejection.error())
                .field("status", status)
                .finish(),
            Self::Deferred {
                error, disposition, ..
            } => formatter
                .debug_struct("Deferred")
                .field("candidate", &"<redacted>")
                .field("error", error)
                .field("disposition", disposition)
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseReport<T, E> {
    Skipped(TickPhaseSkip),
    Completed(T),
    Failed(E),
}

#[derive(Debug, Eq, PartialEq)]
pub enum RxPhaseReport<E> {
    Skipped(TickPhaseSkip),
    ReceiveFailed(E),
    Completed(BatchReport<E>),
    AccountingInvariantViolation(BatchReport<E>),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GeneratedAccounting {
    pub sessions: usize,
    pub allocation_attempts: usize,
    pub allocated: usize,
    pub allocation_failed: usize,
    pub tx_requested: usize,
    pub cancelled: usize,
    pub abandoned: usize,
    /// Backend-accepted TX requests. This is descriptor publication, not wire
    /// delivery and not completion-queue ownership return.
    pub tx_accepted: usize,
    pub tx_rejected: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedCompletion<E> {
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

impl<E> GeneratedCompletion<E> {
    fn from_core(completion: ruster_core::GeneratedBatchCompletion<E>) -> Self {
        Self {
            attempts: completion.attempts,
            allocated: completion.allocated,
            failed: completion.failed,
            requested: completion.requested,
            cancelled: completion.cancelled,
            abandoned: completion.abandoned,
            accepted: completion.accepted,
            rejected: completion.rejected,
            error: completion.error,
        }
    }

    #[must_use]
    pub const fn invariants_hold(&self) -> bool {
        let Some(attempts) = self.allocated.checked_add(self.failed) else {
            return false;
        };
        let Some(allocated) = self.requested.checked_add(self.cancelled) else {
            return false;
        };
        let Some(allocated) = allocated.checked_add(self.abandoned) else {
            return false;
        };
        let Some(requested) = self.accepted.checked_add(self.rejected) else {
            return false;
        };
        self.attempts == attempts && self.allocated == allocated && self.requested == requested
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedAccountingViolation<E, B> {
    pub completion: GeneratedCompletion<E>,
    pub allocation: Option<GeneratedAllocationError>,
    pub build: Option<B>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedArpFailure<E> {
    pub allocation: Option<GeneratedAllocationError>,
    pub build: Option<ArpRequestBuildError>,
    pub finish: Option<E>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum GeneratedArpStop<E> {
    QueueEmpty,
    BudgetExhausted { pending: usize },
    ClockRegression,
    Failed(GeneratedArpFailure<E>),
    AccountingInvariantViolation(GeneratedAccountingViolation<E, ArpRequestBuildError>),
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedIcmpv4Failure<E> {
    pub allocation: Option<GeneratedAllocationError>,
    pub build: Option<Icmpv4ErrorBuildError>,
    pub finish: Option<E>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum GeneratedIcmpv4Stop<E> {
    QueueEmpty,
    BudgetExhausted { pending: usize },
    ClockRegression,
    Failed(GeneratedIcmpv4Failure<E>),
    AccountingInvariantViolation(GeneratedAccountingViolation<E, Icmpv4ErrorBuildError>),
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedPhaseReport<S> {
    pub accounting: GeneratedAccounting,
    pub stop: S,
}

/// Complete bounded tick report.
///
/// Its `Debug` implementation inherits candidate redaction from
/// [`PublicationOutcome`] and therefore does not require `Candidate: Debug`.
/// The publication outcome may own an unconsumed candidate, so callers must
/// inspect or deliberately bind the report rather than discard it implicitly.
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use ruster_runtime::TickReport;
///
/// fn discard<RxError, GeneratedError>(
///     report: TickReport<(), (), (), RxError, GeneratedError>,
/// ) {
///     report;
/// }
/// ```
#[must_use = "the tick report may retain an unconsumed publication candidate"]
#[derive(Eq, PartialEq)]
pub struct TickReport<
    Candidate,
    PublicationError,
    QuiescenceError,
    RxError,
    GeneratedError,
    ApplyReport = (),
> {
    pub publication: PublicationOutcome<Candidate, PublicationError, QuiescenceError, ApplyReport>,
    pub active: bool,
    pub rx: RxPhaseReport<RxError>,
    pub resolution_timers: PhaseReport<ResolutionTimerReport, ResolutionTimerError>,
    pub failure_dispatch:
        PhaseReport<ResolutionFailureDispatchReport, ResolutionFailureDispatchError>,
    pub generated_arp: PhaseReport<
        GeneratedPhaseReport<GeneratedArpStop<GeneratedError>>,
        core::convert::Infallible,
    >,
    pub generated_icmpv4: PhaseReport<
        GeneratedPhaseReport<GeneratedIcmpv4Stop<GeneratedError>>,
        core::convert::Infallible,
    >,
}

impl<C, E, Q, R, G, A> fmt::Debug for TickReport<C, E, Q, R, G, A>
where
    E: fmt::Debug,
    Q: fmt::Debug,
    R: fmt::Debug,
    G: fmt::Debug,
    A: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TickReport")
            .field("publication", &self.publication)
            .field("active", &self.active)
            .field("rx", &self.rx)
            .field("resolution_timers", &self.resolution_timers)
            .field("failure_dispatch", &self.failure_dispatch)
            .field("generated_arp", &self.generated_arp)
            .field("generated_icmpv4", &self.generated_icmpv4)
            .finish()
    }
}

fn add_generated_accounting<E>(
    total: &mut GeneratedAccounting,
    completion: &GeneratedCompletion<E>,
) -> bool {
    let Some(sessions) = total.sessions.checked_add(1) else {
        return false;
    };
    total.sessions = sessions;
    if !completion.invariants_hold() {
        return false;
    }
    let Some(allocation_attempts) = total.allocation_attempts.checked_add(completion.attempts)
    else {
        return false;
    };
    let Some(allocated) = total.allocated.checked_add(completion.allocated) else {
        return false;
    };
    let Some(allocation_failed) = total.allocation_failed.checked_add(completion.failed) else {
        return false;
    };
    let Some(tx_requested) = total.tx_requested.checked_add(completion.requested) else {
        return false;
    };
    let Some(cancelled) = total.cancelled.checked_add(completion.cancelled) else {
        return false;
    };
    let Some(abandoned) = total.abandoned.checked_add(completion.abandoned) else {
        return false;
    };
    let Some(tx_accepted) = total.tx_accepted.checked_add(completion.accepted) else {
        return false;
    };
    let Some(tx_rejected) = total.tx_rejected.checked_add(completion.rejected) else {
        return false;
    };
    *total = GeneratedAccounting {
        sessions,
        allocation_attempts,
        allocated,
        allocation_failed,
        tx_requested,
        cancelled,
        abandoned,
        tx_accepted,
        tx_rejected,
    };
    true
}

fn run_generated_arp<I, T>(
    io: &mut I,
    runtime: &mut ResolutionRuntime<'_>,
    now: MonotonicMillis,
    budget: usize,
    trace: &mut T,
) -> (
    GeneratedPhaseReport<GeneratedArpStop<I::Error>>,
    Option<TickPhaseSkip>,
)
where
    I: GeneratedPacketIo,
    T: GeneratedTraceSink,
{
    let mut accounting = GeneratedAccounting::default();
    for _ in 0..budget {
        let result = match execute_one_arp_request(io, runtime, now, trace) {
            Ok(Some(result)) => result,
            Ok(None) => {
                return (
                    GeneratedPhaseReport {
                        accounting,
                        stop: GeneratedArpStop::QueueEmpty,
                    },
                    None,
                );
            }
            Err(ExecuteArpRequestError::ClockRegression) => {
                return (
                    GeneratedPhaseReport {
                        accounting,
                        stop: GeneratedArpStop::ClockRegression,
                    },
                    Some(TickPhaseSkip::ClockRegression),
                );
            }
        };
        let completion = GeneratedCompletion::from_core(result.completion);
        let accounting_valid = add_generated_accounting(&mut accounting, &completion);
        if !accounting_valid {
            return (
                GeneratedPhaseReport {
                    accounting,
                    stop: GeneratedArpStop::AccountingInvariantViolation(
                        GeneratedAccountingViolation {
                            completion,
                            allocation: result.allocation_error,
                            build: result.build_error,
                        },
                    ),
                },
                Some(TickPhaseSkip::BackendContractViolation),
            );
        }
        let failure = GeneratedArpFailure {
            allocation: result.allocation_error,
            build: result.build_error,
            finish: completion.error,
        };
        if failure.allocation.is_some() || failure.build.is_some() || failure.finish.is_some() {
            let downstream_skip = if failure.finish.is_some() {
                Some(TickPhaseSkip::BackendIoFailure)
            } else if failure.build.is_some()
                || failure
                    .allocation
                    .is_some_and(|error| error != GeneratedAllocationError::Unavailable)
            {
                Some(TickPhaseSkip::GeneratedArpFailure)
            } else {
                None
            };
            return (
                GeneratedPhaseReport {
                    accounting,
                    stop: GeneratedArpStop::Failed(failure),
                },
                downstream_skip,
            );
        }
    }
    let pending = runtime.pending_actions();
    (
        GeneratedPhaseReport {
            accounting,
            stop: if pending == 0 {
                GeneratedArpStop::QueueEmpty
            } else {
                GeneratedArpStop::BudgetExhausted { pending }
            },
        },
        None,
    )
}

fn run_generated_icmpv4<I, T>(
    io: &mut I,
    runtime: &mut Icmpv4ErrorRuntime<'_>,
    now: MonotonicMillis,
    budget: usize,
    trace: &mut T,
) -> (
    GeneratedPhaseReport<GeneratedIcmpv4Stop<I::Error>>,
    Option<TickPhaseSkip>,
)
where
    I: GeneratedPacketIo,
    T: GeneratedIcmpv4TraceSink,
{
    let mut accounting = GeneratedAccounting::default();
    for _ in 0..budget {
        let result = match execute_one_icmpv4_error(io, runtime, now, trace) {
            Ok(Some(result)) => result,
            Ok(None) => {
                return (
                    GeneratedPhaseReport {
                        accounting,
                        stop: GeneratedIcmpv4Stop::QueueEmpty,
                    },
                    None,
                );
            }
            Err(ExecuteIcmpv4Error::ClockRegression) => {
                return (
                    GeneratedPhaseReport {
                        accounting,
                        stop: GeneratedIcmpv4Stop::ClockRegression,
                    },
                    Some(TickPhaseSkip::ClockRegression),
                );
            }
        };
        let completion = GeneratedCompletion::from_core(result.completion);
        let accounting_valid = add_generated_accounting(&mut accounting, &completion);
        if !accounting_valid {
            return (
                GeneratedPhaseReport {
                    accounting,
                    stop: GeneratedIcmpv4Stop::AccountingInvariantViolation(
                        GeneratedAccountingViolation {
                            completion,
                            allocation: result.allocation_error,
                            build: result.build_error,
                        },
                    ),
                },
                Some(TickPhaseSkip::BackendContractViolation),
            );
        }
        let failure = GeneratedIcmpv4Failure {
            allocation: result.allocation_error,
            build: result.build_error,
            finish: completion.error,
        };
        if failure.allocation.is_some() || failure.build.is_some() || failure.finish.is_some() {
            return (
                GeneratedPhaseReport {
                    accounting,
                    stop: GeneratedIcmpv4Stop::Failed(failure),
                },
                None,
            );
        }
    }
    let pending = runtime.pending_actions();
    (
        GeneratedPhaseReport {
            accounting,
            stop: if pending == 0 {
                GeneratedIcmpv4Stop::QueueEmpty
            } else {
                GeneratedIcmpv4Stop::BudgetExhausted { pending }
            },
        },
        None,
    )
}

fn skip_phase<T: TickPhaseTraceSink>(trace: &mut T, phase: TickPhase, reason: TickPhaseSkip) {
    trace.record_tick_phase(TickPhaseTrace::PhaseSkipped { phase, reason });
}

/// Skips every post-publication phase for the same `reason` and finishes the
/// tick trace, building the resulting all-`Skipped` [`TickReport`].
fn skip_remaining_phases<T, C, E, Q, R, G, A>(
    trace: &mut T,
    reason: TickPhaseSkip,
    publication: PublicationOutcome<C, E, Q, A>,
    active: bool,
) -> TickReport<C, E, Q, R, G, A>
where
    T: TickPhaseTraceSink,
{
    for phase in [
        TickPhase::Rx,
        TickPhase::ResolutionTimers,
        TickPhase::FailureDispatch,
        TickPhase::GeneratedArp,
        TickPhase::GeneratedIcmpv4,
    ] {
        skip_phase(trace, phase, reason);
    }
    trace.record_tick_phase(TickPhaseTrace::TickFinished);
    TickReport {
        publication,
        active,
        rx: RxPhaseReport::Skipped(reason),
        resolution_timers: PhaseReport::Skipped(reason),
        failure_dispatch: PhaseReport::Skipped(reason),
        generated_arp: PhaseReport::Skipped(reason),
        generated_icmpv4: PhaseReport::Skipped(reason),
    }
}

/// Runs one bounded, single-worker service tick.
///
/// After exact backend identity matching, an already stopped active publication
/// rejects a candidate with its latched typed cause before backend quiescence is
/// requested. Otherwise a candidate requires backend-authoritative quiescence.
/// Its successful guard is released before `active` or packet I/O, then the
/// backend's bounded current-I/O disposition is re-read after an applied or
/// rejected attempt. A quiescence failure is classified by the backend:
/// `ContinueOldIo` may run the old publication, while `SkipIo` and `Stop` suppress
/// every data phase. Unknown backend failures default to `SkipIo`. Candidate-free
/// ticks perform the same bounded disposition read, so a sticky `SkipIo` or
/// terminal `Stop` cannot be bypassed. This steady check does not request a
/// quiescence guard.
///
/// The phase order is publication, RX, resolution timers, failure dispatch,
/// generated ARP, and generated ICMPv4. The RX batch is moved into the full
/// composition wrapper in a lexical scope and is therefore finished before
/// either generated session can borrow `io`.
///
/// A backend accounting violation suppresses all later generated I/O in the
/// tick. A valid finish error, allocation error, or build error stops that
/// generated phase after one attempt while retaining any uncommitted action.
/// RX receive/finish errors still permit the non-I/O timer and failure phases,
/// but suppress generated I/O for the tick. Clock regression suppresses every
/// downstream phase. ARP allocation `Unavailable` is the only ARP failure that
/// still permits the independent ICMPv4 generated phase.
///
/// The backend contracts also prevent a caller from overlapping an RX batch
/// with a generated session:
///
/// ```compile_fail
/// use ruster_core::{GeneratedPacketIo, IfId, PacketIo};
///
/// fn overlap<I>(io: &mut I)
/// where
///     I: PacketIo + GeneratedPacketIo,
/// {
///     let Ok(rx) = io.receive(1) else { return };
///     let generated = io.begin_generated(IfId(1));
///     drop((rx, generated));
/// }
/// ```
///
/// Tick budgets now come from the post-publication active view. Supplying the
/// former independent budget argument is an intentional pre-1.0 source break:
///
/// ```compile_fail
/// use ruster_core::{
///     BoundPublicationBackend, GeneratedIcmpv4TraceSink, GeneratedPacketIo,
///     PublicationBackendAuthority,
///     GeneratedTraceSink, MonotonicMillis, PacketIo,
///     PublicationQuiescenceBackend, ResolutionFailureTraceSink,
///     ResolutionTimerTraceSink, TraceSink,
/// };
/// use ruster_runtime::{
///     run_tick, FullServicePublication, TickBudgets, TickPhaseTraceSink,
/// };
///
/// fn old_external_budgets<'storage, P, I, T>(
///     publication: &mut P,
///     candidate: Option<P::Candidate>,
///     io: &mut BoundPublicationBackend<I>,
///     trace: &mut T,
/// ) where
///     P: FullServicePublication<'storage, BoundPublicationBackend<I>>,
///     I: PacketIo + GeneratedPacketIo + PublicationBackendAuthority + PublicationQuiescenceBackend,
///     T: TickPhaseTraceSink
///         + TraceSink
///         + ResolutionTimerTraceSink
///         + ResolutionFailureTraceSink
///         + GeneratedTraceSink
///         + GeneratedIcmpv4TraceSink,
/// {
///     let _report = run_tick(
///         publication,
///         candidate,
///         io,
///         MonotonicMillis(0),
///         TickBudgets::default(),
///         trace,
///     );
/// }
/// ```
///
/// The returned report can retain the exact rejected or deferred candidate and
/// therefore cannot be discarded without an `unused_must_use` diagnostic:
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use ruster_core::{
///     BoundPublicationBackend, GeneratedIcmpv4TraceSink, GeneratedPacketIo,
///     PublicationBackendAuthority,
///     GeneratedTraceSink, MonotonicMillis, PacketIo,
///     PublicationQuiescenceBackend, ResolutionFailureTraceSink,
///     ResolutionTimerTraceSink, TraceSink,
/// };
/// use ruster_runtime::{run_tick, FullServicePublication, TickPhaseTraceSink};
///
/// fn discard<'storage, P, I, T>(
///     publication: &mut P,
///     candidate: Option<P::Candidate>,
///     io: &mut BoundPublicationBackend<I>,
///     trace: &mut T,
/// ) where
///     P: FullServicePublication<'storage, BoundPublicationBackend<I>>,
///     I: PacketIo + GeneratedPacketIo + PublicationBackendAuthority + PublicationQuiescenceBackend,
///     T: TickPhaseTraceSink
///         + TraceSink
///         + ResolutionTimerTraceSink
///         + ResolutionFailureTraceSink
///         + GeneratedTraceSink
///         + GeneratedIcmpv4TraceSink,
/// {
///     run_tick(
///         publication,
///         candidate,
///         io,
///         MonotonicMillis(0),
///         trace,
///     );
/// }
/// ```
#[must_use = "the tick report may retain an unconsumed publication candidate"]
#[allow(clippy::type_complexity)]
pub fn run_tick<'storage, P, I, T>(
    publication: &mut P,
    candidate: Option<P::Candidate>,
    io: &mut BoundPublicationBackend<I>,
    now: MonotonicMillis,
    timestamp_clock: Icmpv4TimestampClock,
    trace: &mut T,
) -> TickReport<
    P::Candidate,
    P::Reject,
    <I as PublicationQuiescenceBackend>::Error,
    <I as PacketIo>::Error,
    <I as GeneratedPacketIo>::Error,
    P::ApplyReport,
>
where
    P: FullServicePublication<'storage, BoundPublicationBackend<I>>,
    I: PacketIo + GeneratedPacketIo + PublicationBackendAuthority + PublicationQuiescenceBackend,
    T: TickPhaseTraceSink
        + TraceSink
        + ResolutionTimerTraceSink
        + ResolutionFailureTraceSink
        + GeneratedTraceSink
        + GeneratedIcmpv4TraceSink,
{
    trace.record_tick_phase(TickPhaseTrace::TickStarted);
    trace.record_tick_phase(TickPhaseTrace::PhaseStarted(TickPhase::Publication));
    if !publication.publication_owner_binding().matches_backend(io) {
        trace.record_tick_phase(TickPhaseTrace::PhaseFinished(TickPhase::Publication));
        let active = publication.active_status().is_present();
        return skip_remaining_phases(
            trace,
            TickPhaseSkip::BackendInstanceMismatch,
            PublicationOutcome::BackendMismatch { candidate },
            active,
        );
    }

    let mut io_disposition = None;
    let publication_report = match candidate {
        Some(candidate) => match publication.reject_candidate_if_active_stopped(candidate) {
            Err(rejection) => PublicationOutcome::Rejected {
                rejection,
                status: publication.active_status(),
            },
            Ok(candidate) => match io.try_publication_quiescence() {
                Ok(quiescence) => match try_publish_candidate(publication, candidate, quiescence) {
                    Ok(report) => PublicationOutcome::Applied(report),
                    Err(PublicationAttemptError::Rejected(rejection)) => {
                        PublicationOutcome::Rejected {
                            rejection,
                            status: publication.active_status(),
                        }
                    }
                    Err(PublicationAttemptError::BackendMismatch { candidate }) => {
                        trace.record_tick_phase(TickPhaseTrace::PhaseFinished(
                            TickPhase::Publication,
                        ));
                        let active = publication.active_status().is_present();
                        return skip_remaining_phases(
                            trace,
                            TickPhaseSkip::BackendInstanceMismatch,
                            PublicationOutcome::BackendMismatch {
                                candidate: Some(candidate),
                            },
                            active,
                        );
                    }
                },
                Err(error) => {
                    let disposition = I::quiescence_error_disposition(&error);
                    io_disposition = Some(disposition);
                    PublicationOutcome::Deferred {
                        candidate,
                        error,
                        disposition,
                    }
                }
            },
        },
        None => PublicationOutcome::Unchanged,
    };
    trace.record_tick_phase(TickPhaseTrace::PhaseFinished(TickPhase::Publication));

    match publication.active_status() {
        ActivePublicationStatus::StopOldPublication => {
            return skip_remaining_phases(
                trace,
                TickPhaseSkip::ActivePublicationInvalid,
                publication_report,
                true,
            );
        }
        ActivePublicationStatus::Absent => {
            return skip_remaining_phases(
                trace,
                TickPhaseSkip::NoActivePublication,
                publication_report,
                false,
            );
        }
        ActivePublicationStatus::ContinueOldIo => {}
    }

    if io_disposition.is_none() {
        io_disposition = Some(io.current_io_disposition());
    }

    if matches!(
        io_disposition,
        Some(PublicationQuiescenceDisposition::SkipIo | PublicationQuiescenceDisposition::Stop)
    ) {
        let reason = if io_disposition == Some(PublicationQuiescenceDisposition::Stop) {
            TickPhaseSkip::BackendStopped
        } else {
            TickPhaseSkip::BackendIoNotReentrant
        };
        return skip_remaining_phases(trace, reason, publication_report, true);
    }

    let view = publication.active();
    let FullServiceView {
        tick_authority,
        snapshot,
        resolution,
        icmpv4_errors,
        nat44_udp,
        nat44_tcp,
        firewall,
    } = view;
    let Nat44UdpServiceView {
        config: udp_config,
        runtime: nat44_udp,
    } = nat44_udp;
    let Nat44TcpServiceView {
        config: tcp_config,
        runtime: nat44_tcp,
    } = nat44_tcp;
    let FirewallServiceView {
        config: firewall_config,
        runtime: firewall,
    } = firewall;
    let budgets = tick_authority.tick_budgets();

    trace.record_tick_phase(TickPhaseTrace::PhaseStarted(TickPhase::Rx));
    let rx = match io.receive(budgets.rx) {
        Ok(batch) => {
            let report =
                forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors_and_timestamp(
                    batch,
                    &snapshot,
                    resolution,
                    icmpv4_errors,
                    &udp_config,
                    nat44_udp,
                    &tcp_config,
                    nat44_tcp,
                    &firewall_config,
                    firewall,
                    now,
                    timestamp_clock,
                    trace,
                );
            if report.invariants_hold() {
                RxPhaseReport::Completed(report)
            } else {
                RxPhaseReport::AccountingInvariantViolation(report)
            }
        }
        Err(error) => RxPhaseReport::ReceiveFailed(error),
    };
    trace.record_tick_phase(TickPhaseTrace::PhaseFinished(TickPhase::Rx));
    let mut generated_skip = match &rx {
        RxPhaseReport::AccountingInvariantViolation(_) => {
            Some(TickPhaseSkip::BackendContractViolation)
        }
        RxPhaseReport::ReceiveFailed(_) => Some(TickPhaseSkip::BackendIoFailure),
        RxPhaseReport::Completed(report) if report.completion.error.is_some() => {
            Some(TickPhaseSkip::BackendIoFailure)
        }
        RxPhaseReport::Skipped(_) | RxPhaseReport::Completed(_) => None,
    };

    trace.record_tick_phase(TickPhaseTrace::PhaseStarted(TickPhase::ResolutionTimers));
    let resolution_timers =
        match poll_resolution_timers(resolution, now, budgets.resolution_timer_scans, trace) {
            Ok(report) => PhaseReport::Completed(report),
            Err(error) => PhaseReport::Failed(error),
        };
    trace.record_tick_phase(TickPhaseTrace::PhaseFinished(TickPhase::ResolutionTimers));

    let failure_dispatch = if matches!(
        resolution_timers,
        PhaseReport::Failed(ResolutionTimerError::ClockRegression)
    ) {
        skip_phase(
            trace,
            TickPhase::FailureDispatch,
            TickPhaseSkip::ClockRegression,
        );
        if generated_skip.is_none() {
            generated_skip = Some(TickPhaseSkip::ClockRegression);
        }
        PhaseReport::Skipped(TickPhaseSkip::ClockRegression)
    } else {
        trace.record_tick_phase(TickPhaseTrace::PhaseStarted(TickPhase::FailureDispatch));
        let report = match dispatch_host_unreachable_failures(
            resolution,
            icmpv4_errors,
            &snapshot,
            now,
            budgets.failure_dispatch_scans,
            trace,
        ) {
            Ok(report) => PhaseReport::Completed(report),
            Err(error) => PhaseReport::Failed(error),
        };
        trace.record_tick_phase(TickPhaseTrace::PhaseFinished(TickPhase::FailureDispatch));
        if matches!(
            report,
            PhaseReport::Failed(ResolutionFailureDispatchError::ClockRegression)
        ) && generated_skip.is_none()
        {
            generated_skip = Some(TickPhaseSkip::ClockRegression);
        }
        report
    };

    let (generated_arp, arp_skip) = if let Some(reason) = generated_skip {
        skip_phase(trace, TickPhase::GeneratedArp, reason);
        (PhaseReport::Skipped(reason), Some(reason))
    } else {
        trace.record_tick_phase(TickPhaseTrace::PhaseStarted(TickPhase::GeneratedArp));
        let (report, downstream_skip) =
            run_generated_arp(io, resolution, now, budgets.generated_arp, trace);
        trace.record_tick_phase(TickPhaseTrace::PhaseFinished(TickPhase::GeneratedArp));
        (PhaseReport::Completed(report), downstream_skip)
    };

    let generated_icmpv4 = if let Some(reason) = arp_skip {
        skip_phase(trace, TickPhase::GeneratedIcmpv4, reason);
        PhaseReport::Skipped(reason)
    } else {
        trace.record_tick_phase(TickPhaseTrace::PhaseStarted(TickPhase::GeneratedIcmpv4));
        let (report, _) =
            run_generated_icmpv4(io, icmpv4_errors, now, budgets.generated_icmpv4, trace);
        trace.record_tick_phase(TickPhaseTrace::PhaseFinished(TickPhase::GeneratedIcmpv4));
        PhaseReport::Completed(report)
    };

    trace.record_tick_phase(TickPhaseTrace::TickFinished);
    TickReport {
        publication: publication_report,
        active: true,
        rx,
        resolution_timers,
        failure_dispatch,
        generated_arp,
        generated_icmpv4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruster_core::{
        bind_publication_backend, forward_batch_with_resolution,
        forward_batch_with_resolution_and_icmpv4_errors, internet_checksum, ipv4_header_checksum,
        BatchCompletion, BoundPublicationBackend, DirectoryBucket, DirectoryNode, FirewallHashKey,
        FirewallPolicy, FirewallRuntime, FirewallStateSlot, GeneratedBatchCompletion,
        GeneratedPacketBatch, GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion,
        GeneratedTraceSink, Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy, Icmpv4ErrorStateSlot, IfId,
        Interface, Ipv4Address, Ipv4Mtu, LocalIpv4Binding, MacAddress,
        MatchedPublicationQuiescenceGuard, Nat44TcpHashKey, Nat44TcpIndexStorage,
        Nat44TcpMappingSlot, Nat44TcpPolicy, Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44UdpHashKey,
        Nat44UdpIndexStorage, Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy,
        Nat44UdpRuntime, Neighbor, NoTrace, PacketBatch, PacketLease, PacketSlot, PortOwnerSlot,
        PublicationBackendAuthority, PublicationBackendControl, PublicationOwnerBinding,
        PublicationQuiescenceBackend, ResolutionActionSlot, ResolutionFailureHoldSlot,
        ResolutionFailureTrace, ResolutionPolicy, ResolutionStateSlot, ResolutionTimerTrace, Route,
        SlotCompletion, TraceEvent,
    };
    use ruster_io_sim::{
        BoundSimIoControl, FrameOrigin, SimBatch, SimGeneratedBatch, SimGeneratedError, SimIo,
        SimPublicationQuiescenceError,
    };

    const LAN: IfId = IfId(1);
    const WAN: IfId = IfId(2);
    const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
    const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
    const HOST_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 50]);
    const LAN_IP: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 1]);
    const HOST_IP: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 50]);
    const WAN_IP: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
    const GATEWAY: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);

    type BoundTestIo = BoundPublicationBackend<TestIo>;
    type BoundSimIo = BoundPublicationBackend<SimIo>;
    type BoundCountingSimIo = BoundPublicationBackend<CountingSimIo>;

    #[derive(Debug, Eq, PartialEq)]
    enum Candidate {
        Apply,
        ApplyOwned(Box<usize>),
        ApplyWithBudgets(TickBudgets),
        Reject(Box<usize>),
        RejectActivePublication(Box<usize>),
    }

    struct TestPublication<'view, 'storage, I> {
        owner_binding: PublicationOwnerBinding<I>,
        active_status: ActivePublicationStatus,
        applied: usize,
        active_calls: usize,
        tick_authority: ActiveTickAuthority,
        steady_validation_scans: usize,
        snapshot: &'view ForwardingSnapshot<'storage>,
        resolution: &'view mut ResolutionRuntime<'storage>,
        icmpv4_errors: &'view mut Icmpv4ErrorRuntime<'storage>,
        udp_config: Nat44UdpConfig,
        tcp_config: Nat44TcpConfig,
        firewall_config: FirewallConfig<'storage>,
    }

    #[allow(unsafe_code)]
    unsafe impl<'view, 'storage, I> FullServicePublication<'storage, I>
        for TestPublication<'view, 'storage, I>
    where
        I: PublicationQuiescence,
    {
        type Candidate = Candidate;
        type Reject = &'static str;
        type ApplyReport = usize;

        fn publication_owner_binding(&self) -> &PublicationOwnerBinding<I> {
            &self.owner_binding
        }

        fn reject_candidate_if_active_stopped(
            &self,
            candidate: Self::Candidate,
        ) -> Result<Self::Candidate, PublicationRejection<Self::Candidate, Self::Reject>> {
            if self.active_status == ActivePublicationStatus::StopOldPublication {
                Err(PublicationRejection::new(
                    candidate,
                    "active publication invalid",
                ))
            } else {
                Ok(candidate)
            }
        }

        #[allow(unsafe_code)]
        unsafe fn publish_candidate_authorized(
            &mut self,
            candidate: Self::Candidate,
            _quiescence: MatchedPublicationQuiescenceGuard<'_, I>,
        ) -> Result<Self::ApplyReport, PublicationRejection<Self::Candidate, Self::Reject>>
        {
            match candidate {
                Candidate::Apply | Candidate::ApplyOwned(_) => {
                    self.applied += 1;
                    Ok(self.applied)
                }
                Candidate::ApplyWithBudgets(tick_budgets) => {
                    self.tick_authority =
                        ActiveTickAuthority::new(self.tick_authority.generation(), tick_budgets);
                    self.applied += 1;
                    Ok(self.applied)
                }
                Candidate::Reject(_) => Err(PublicationRejection::new(candidate, "rejected")),
                Candidate::RejectActivePublication(_) => {
                    self.active_status = ActivePublicationStatus::StopOldPublication;
                    Err(PublicationRejection::new(
                        candidate,
                        "active publication invalid",
                    ))
                }
            }
        }

        fn active_status(&self) -> ActivePublicationStatus {
            self.active_status
        }

        fn active(&mut self) -> FullServiceView<'_, 'storage> {
            self.active_calls += 1;
            FullServiceView::new(
                &self.tick_authority,
                *self.snapshot,
                self.resolution,
                self.icmpv4_errors,
                Nat44UdpServiceView::new(self.udp_config, None),
                Nat44TcpServiceView::new(self.tcp_config, None),
                FirewallServiceView::new(self.firewall_config, None),
            )
        }
    }

    fn with_fixture(
        run: impl FnOnce(&mut TestPublication<'_, '_, BoundTestIo>, &mut BoundTestIo, &mut TestTrace),
    ) {
        let (owner_binding, io) =
            bind_publication_backend(TestIo::default()).expect("test publication binding identity");
        with_backend_fixture(owner_binding, io, run);
    }

    fn with_sim_fixture(
        run: impl FnOnce(&mut TestPublication<'_, '_, BoundSimIo>, &mut BoundSimIo, &mut TestTrace),
    ) {
        let (owner_binding, io) =
            bind_publication_backend(SimIo::new()).expect("test publication binding identity");
        with_backend_fixture(owner_binding, io, run);
    }

    fn with_counting_sim_fixture(
        run: impl FnOnce(
            &mut TestPublication<'_, '_, BoundCountingSimIo>,
            &mut BoundCountingSimIo,
            &mut TestTrace,
        ),
    ) {
        let (owner_binding, io) = bind_publication_backend(CountingSimIo::default())
            .expect("test publication binding identity");
        with_backend_fixture(owner_binding, io, run);
    }

    fn with_backend_fixture<I>(
        owner_binding: PublicationOwnerBinding<BoundPublicationBackend<I>>,
        mut io: BoundPublicationBackend<I>,
        run: impl FnOnce(
            &mut TestPublication<'_, '_, BoundPublicationBackend<I>>,
            &mut BoundPublicationBackend<I>,
            &mut TestTrace,
        ),
    ) {
        let routes = [
            Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
            Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(GATEWAY)).unwrap(),
        ];
        let interfaces = [
            Interface {
                id: LAN,
                mac: LAN_MAC,
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: WAN_MAC,
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: LAN_IP,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: WAN_IP,
            },
        ];
        let neighbors = [Neighbor {
            interface: LAN,
            target: HOST_IP,
            mac: HOST_MAC,
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            WAN_IP,
            40_000,
            40_003,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            WAN_IP,
            40_000,
            40_003,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let firewall_config = FirewallConfig::new(
            &snapshot,
            &[],
            FirewallPolicy::default(),
            1,
            FirewallHashKey::new(1, 2).unwrap(),
        )
        .unwrap();
        let mut resolution_states = [ResolutionStateSlot::EMPTY; 4];
        let mut resolution_actions = [ResolutionActionSlot::EMPTY; 4];
        let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 4];
        let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            &mut resolution_states,
            &mut resolution_actions,
            &mut [],
            &mut failure_holds,
        );
        let mut icmp_states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut icmp_actions = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut icmpv4_errors = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::default(),
            &mut icmp_states,
            &mut icmp_actions,
        );
        let mut publication = TestPublication {
            owner_binding,
            active_status: ActivePublicationStatus::ContinueOldIo,
            applied: 0,
            active_calls: 0,
            tick_authority: ActiveTickAuthority::new(NonZeroU64::MIN, TickBudgets::default()),
            steady_validation_scans: 0,
            snapshot: &snapshot,
            resolution: &mut resolution,
            icmpv4_errors: &mut icmpv4_errors,
            udp_config,
            tcp_config,
            firewall_config,
        };
        let mut trace = TestTrace::default();
        run(&mut publication, &mut io, &mut trace);
    }

    #[allow(clippy::type_complexity)]
    fn run_test_tick<'storage, I, T>(
        publication: &mut TestPublication<'_, 'storage, BoundPublicationBackend<I>>,
        candidate: Option<Candidate>,
        io: &mut BoundPublicationBackend<I>,
        now: MonotonicMillis,
        tick_budgets: TickBudgets,
        trace: &mut T,
    ) -> TickReport<
        Candidate,
        &'static str,
        <I as PublicationQuiescenceBackend>::Error,
        <I as PacketIo>::Error,
        <I as GeneratedPacketIo>::Error,
        usize,
    >
    where
        I: PacketIo
            + GeneratedPacketIo
            + PublicationBackendAuthority
            + PublicationQuiescenceBackend,
        T: TickPhaseTraceSink
            + TraceSink
            + ResolutionTimerTraceSink
            + ResolutionFailureTraceSink
            + GeneratedTraceSink
            + GeneratedIcmpv4TraceSink,
    {
        publication.tick_authority =
            ActiveTickAuthority::new(publication.tick_authority.generation(), tick_budgets);
        // Deterministic tests have no wall clock of their own; this derives
        // one straight from `now` so a Timestamp Reply in a test is exact
        // and reproducible without adding a second clock to this helper's
        // signature (and every one of its many call sites).
        let timestamp_clock =
            Icmpv4TimestampClock(u32::try_from(now.0 % 86_400_000).expect("bounded by modulus"));
        super::run_tick(publication, candidate, io, now, timestamp_clock, trace)
    }

    fn seed_resolution<I>(publication: &mut TestPublication<'_, '_, I>, last: u8, now: u64) {
        let mut frame = [0_u8; 34];
        frame[0..6].copy_from_slice(&WAN_MAC.0);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 99]);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&20_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
        frame[22] = 64;
        frame[23] = 17;
        frame[26..30].copy_from_slice(&[198, 51, 100, 99]);
        frame[30..34].copy_from_slice(&[10, 0, 0, last]);
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        let mut io = SimIo::new();
        io.inject(WAN, frame.to_vec());
        let batch = io.receive(1).unwrap();
        let report = forward_batch_with_resolution(
            batch,
            publication.snapshot,
            publication.resolution,
            MonotonicMillis(now),
            &mut NoTrace,
        );
        assert!(report.invariants_hold());
    }

    fn seed_icmpv4<I>(publication: &mut TestPublication<'_, '_, I>, now: u64) {
        let mut frame = [0_u8; 34];
        frame[0..6].copy_from_slice(&LAN_MAC.0);
        frame[6..12].copy_from_slice(&HOST_MAC.0);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&20_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
        frame[22] = 1;
        frame[23] = 17;
        frame[26..30].copy_from_slice(&HOST_IP.octets());
        frame[30..34].copy_from_slice(&[198, 51, 100, 99]);
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        let mut io = SimIo::new();
        io.inject(LAN, frame.to_vec());
        let batch = io.receive(1).unwrap();
        let report = forward_batch_with_resolution_and_icmpv4_errors(
            batch,
            publication.snapshot,
            publication.resolution,
            publication.icmpv4_errors,
            MonotonicMillis(now),
            &mut NoTrace,
        );
        assert!(report.invariants_hold());
        assert_eq!(publication.icmpv4_errors.pending_actions(), 1);
    }

    fn arp_request() -> [u8; 60] {
        let mut frame = [0_u8; 60];
        frame[0..6].fill(0xff);
        frame[6..12].copy_from_slice(&HOST_MAC.0);
        frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
        frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[18] = 6;
        frame[19] = 4;
        frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
        frame[22..28].copy_from_slice(&HOST_MAC.0);
        frame[28..32].copy_from_slice(&HOST_IP.octets());
        frame[38..42].copy_from_slice(&LAN_IP.octets());
        frame
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RxError {
        Injected,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum GeneratedError {
        Finish,
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum RxMode {
        #[default]
        Empty,
        Fail,
        FinishError,
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum GeneratedMode {
        #[default]
        Exact,
        AllocationFailure,
        WrongLength,
        FinishError,
        InvalidAccounting,
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum TestBatchState {
        #[default]
        Idle,
        Rx,
        Generated,
    }

    struct TestIo {
        rx_mode: RxMode,
        generated_mode: GeneratedMode,
        batch_state: TestBatchState,
        quiescence_override: Option<TestPublicationQuiescenceError>,
        current_disposition_override: Option<PublicationQuiescenceDisposition>,
        pending_tx: usize,
        generated_leases_live: usize,
        quiescence_calls: usize,
        receive_calls: usize,
        last_receive_budget: Option<usize>,
        generated_calls: usize,
        frame: [u8; 590],
    }

    impl Default for TestIo {
        fn default() -> Self {
            Self {
                rx_mode: RxMode::Empty,
                generated_mode: GeneratedMode::Exact,
                batch_state: TestBatchState::Idle,
                quiescence_override: None,
                current_disposition_override: None,
                pending_tx: 0,
                generated_leases_live: 0,
                quiescence_calls: 0,
                receive_calls: 0,
                last_receive_budget: None,
                generated_calls: 0,
                frame: [0; 590],
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestPublicationQuiescenceError {
        RxBatchNotFinished,
        GeneratedBatchNotFinished,
        GeneratedLeaseNotCompleted,
        TxCompletionPending,
        OwnershipFault,
        Closing,
    }

    impl PublicationQuiescenceBackend for TestIo {
        type Error = TestPublicationQuiescenceError;

        fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {
            self.quiescence_calls += 1;
            if let Some(error) = self.quiescence_override {
                return Err(error);
            }
            match self.batch_state {
                TestBatchState::Rx => {
                    return Err(TestPublicationQuiescenceError::RxBatchNotFinished);
                }
                TestBatchState::Generated => {
                    return Err(TestPublicationQuiescenceError::GeneratedBatchNotFinished);
                }
                TestBatchState::Idle => {}
            }
            if self.generated_leases_live != 0 {
                return Err(TestPublicationQuiescenceError::GeneratedLeaseNotCompleted);
            }
            if self.pending_tx != 0 {
                return Err(TestPublicationQuiescenceError::TxCompletionPending);
            }
            Ok(())
        }

        fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
            if matches!(
                self.quiescence_override,
                Some(
                    TestPublicationQuiescenceError::OwnershipFault
                        | TestPublicationQuiescenceError::Closing
                )
            ) {
                return PublicationQuiescenceDisposition::Stop;
            }
            if let Some(disposition) = self.current_disposition_override {
                return disposition;
            }
            match self.quiescence_override {
                Some(
                    TestPublicationQuiescenceError::OwnershipFault
                    | TestPublicationQuiescenceError::Closing,
                ) => PublicationQuiescenceDisposition::Stop,
                Some(
                    TestPublicationQuiescenceError::RxBatchNotFinished
                    | TestPublicationQuiescenceError::GeneratedBatchNotFinished
                    | TestPublicationQuiescenceError::GeneratedLeaseNotCompleted,
                ) => PublicationQuiescenceDisposition::SkipIo,
                Some(TestPublicationQuiescenceError::TxCompletionPending) | None => {
                    if self.batch_state != TestBatchState::Idle || self.generated_leases_live != 0 {
                        PublicationQuiescenceDisposition::SkipIo
                    } else {
                        PublicationQuiescenceDisposition::ContinueOldIo
                    }
                }
            }
        }

        fn quiescence_error_disposition(error: &Self::Error) -> PublicationQuiescenceDisposition {
            match error {
                TestPublicationQuiescenceError::TxCompletionPending => {
                    PublicationQuiescenceDisposition::ContinueOldIo
                }
                TestPublicationQuiescenceError::RxBatchNotFinished
                | TestPublicationQuiescenceError::GeneratedBatchNotFinished
                | TestPublicationQuiescenceError::GeneratedLeaseNotCompleted => {
                    PublicationQuiescenceDisposition::SkipIo
                }
                TestPublicationQuiescenceError::OwnershipFault
                | TestPublicationQuiescenceError::Closing => PublicationQuiescenceDisposition::Stop,
            }
        }
    }

    enum TestIoCommand {
        SetPendingTx(usize),
        SetQuiescenceOverride(Option<TestPublicationQuiescenceError>),
        SetCurrentDisposition(PublicationQuiescenceDisposition),
        CompletePendingTx,
        SetGeneratedMode(GeneratedMode),
        SetRxMode(RxMode),
    }

    // SAFETY: every command mutates only fields of this exact `TestIo`, and the
    // unit response cannot detach the backend or expose an authoritative alias.
    // Once a quiescence override or current disposition is classified as `Stop`,
    // later requests cannot make that terminal state reusable.
    #[allow(unsafe_code)]
    unsafe impl PublicationBackendControl for TestIo {
        type Command = TestIoCommand;
        type Response = ();

        fn execute_publication_backend_command(
            &mut self,
            command: Self::Command,
        ) -> Self::Response {
            match command {
                TestIoCommand::SetPendingTx(pending) => self.pending_tx = pending,
                TestIoCommand::SetQuiescenceOverride(error) => {
                    if !matches!(
                        self.quiescence_override,
                        Some(
                            TestPublicationQuiescenceError::OwnershipFault
                                | TestPublicationQuiescenceError::Closing
                        )
                    ) {
                        self.quiescence_override = error;
                    }
                }
                TestIoCommand::SetCurrentDisposition(disposition) => {
                    if self.current_disposition_override
                        != Some(PublicationQuiescenceDisposition::Stop)
                    {
                        self.current_disposition_override = Some(disposition);
                    }
                }
                TestIoCommand::CompletePendingTx => self.pending_tx = 0,
                TestIoCommand::SetGeneratedMode(mode) => self.generated_mode = mode,
                TestIoCommand::SetRxMode(mode) => self.rx_mode = mode,
            }
        }
    }

    struct CountingSimIo {
        inner: SimIo,
        quiescence_calls: usize,
        receive_calls: usize,
        generated_calls: usize,
    }

    impl Default for CountingSimIo {
        fn default() -> Self {
            Self {
                inner: SimIo::new(),
                quiescence_calls: 0,
                receive_calls: 0,
                generated_calls: 0,
            }
        }
    }

    #[derive(Clone, Copy)]
    enum CountingSimIoCommand {
        ResetCalls,
        ForgetRxBatch,
        ForgetGeneratedBatch,
        ForgetRxLease,
        ForgetGeneratedLease,
    }

    // SAFETY: commands retain this exact wrapper and return only `()`; forgotten
    // batch/lease state remains recorded by the inner quiescence implementation.
    #[allow(unsafe_code)]
    unsafe impl PublicationBackendControl for CountingSimIo {
        type Command = CountingSimIoCommand;
        type Response = ();

        fn execute_publication_backend_command(
            &mut self,
            command: Self::Command,
        ) -> Self::Response {
            match command {
                CountingSimIoCommand::ResetCalls => {
                    self.receive_calls = 0;
                    self.generated_calls = 0;
                }
                CountingSimIoCommand::ForgetRxBatch => {
                    let batch = self.receive(0).expect("empty RX batch");
                    core::mem::forget(batch);
                }
                CountingSimIoCommand::ForgetGeneratedBatch => {
                    let batch = self.begin_generated(WAN);
                    core::mem::forget(batch);
                }
                CountingSimIoCommand::ForgetRxLease => {
                    self.inner.inject(LAN, vec![0; 64]);
                    let mut batch = self.receive(1).expect("infallible simulated RX");
                    let lease = batch.next_packet().expect("one injected frame");
                    core::mem::forget(lease);
                    assert!(batch.finish().invariants_hold());
                }
                CountingSimIoCommand::ForgetGeneratedLease => {
                    let mut batch = self.begin_generated(WAN);
                    let lease = batch.allocate(64).expect("one generated frame");
                    core::mem::forget(lease);
                    assert!(!batch.finish().invariants_hold());
                }
            }
        }
    }

    impl PublicationQuiescenceBackend for CountingSimIo {
        type Error = SimPublicationQuiescenceError;

        fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {
            self.quiescence_calls += 1;
            self.inner.check_publication_quiescence()
        }

        fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
            self.inner.current_io_disposition()
        }

        fn quiescence_error_disposition(error: &Self::Error) -> PublicationQuiescenceDisposition {
            SimIo::quiescence_error_disposition(error)
        }
    }

    impl PacketIo for CountingSimIo {
        type Error = core::convert::Infallible;
        type Batch<'a> = SimBatch<'a>;

        fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
            self.receive_calls += 1;
            self.inner.receive(budget)
        }
    }

    impl GeneratedPacketIo for CountingSimIo {
        type Error = SimGeneratedError;
        type Batch<'a> = SimGeneratedBatch<'a>;

        fn begin_generated(&mut self, egress: IfId) -> Self::Batch<'_> {
            self.generated_calls += 1;
            self.inner.begin_generated(egress)
        }
    }

    // SAFETY: both batch types retain exclusive borrows into the embedded SimIo,
    // errors contain no backend state, and the audited control implementation
    // cannot detach or independently alias the inner backend.
    #[allow(unsafe_code)]
    unsafe impl PublicationBackendAuthority for CountingSimIo {}

    struct EmptyRxSlot;

    impl PacketSlot for EmptyRxSlot {
        fn ingress(&self) -> IfId {
            unreachable!("empty RX batch has no slot")
        }

        fn bytes_mut(&mut self) -> &mut [u8] {
            unreachable!("empty RX batch has no slot")
        }

        fn complete(self, _completion: SlotCompletion) {
            unreachable!("empty RX batch has no slot")
        }
    }

    struct EmptyRxBatch<'a> {
        state: &'a mut TestBatchState,
        finish_error: bool,
    }

    impl PacketBatch for EmptyRxBatch<'_> {
        type Error = RxError;
        type Slot<'a>
            = EmptyRxSlot
        where
            Self: 'a;

        fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
            None
        }

        fn finish(self) -> BatchCompletion<Self::Error> {
            *self.state = TestBatchState::Idle;
            BatchCompletion {
                tx_requested: 0,
                tx_accepted: 0,
                tx_rejected: 0,
                recycled: 0,
                error: self.finish_error.then_some(RxError::Injected),
            }
        }
    }

    impl Drop for EmptyRxBatch<'_> {
        fn drop(&mut self) {
            *self.state = TestBatchState::Idle;
        }
    }

    impl PacketIo for TestIo {
        type Error = RxError;
        type Batch<'a> = EmptyRxBatch<'a>;

        fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
            self.receive_calls += 1;
            self.last_receive_budget = Some(budget);
            if self.rx_mode == RxMode::Fail {
                return Err(RxError::Injected);
            }
            assert_eq!(
                self.batch_state,
                TestBatchState::Idle,
                "packet I/O batches cannot overlap"
            );
            assert_eq!(
                self.generated_leases_live, 0,
                "nonterminal generated leases prevent another batch"
            );
            self.batch_state = TestBatchState::Rx;
            Ok(EmptyRxBatch {
                state: &mut self.batch_state,
                finish_error: self.rx_mode == RxMode::FinishError,
            })
        }
    }

    struct TestGeneratedSlot<'a> {
        bytes: &'a mut [u8],
        completion: &'a mut Option<GeneratedSlotCompletion>,
        leases_live: &'a mut usize,
    }

    impl GeneratedPacketSlot for TestGeneratedSlot<'_> {
        fn bytes_mut(&mut self) -> &mut [u8] {
            self.bytes
        }

        fn complete(self, completion: GeneratedSlotCompletion) {
            *self.completion = Some(completion);
            *self.leases_live = self
                .leases_live
                .checked_sub(1)
                .expect("generated lease completed exactly once");
        }
    }

    struct TestGeneratedBatch<'a> {
        mode: GeneratedMode,
        frame: &'a mut [u8; 590],
        state: &'a mut TestBatchState,
        pending_tx: &'a mut usize,
        leases_live: &'a mut usize,
        attempted: bool,
        allocated: bool,
        completion: Option<GeneratedSlotCompletion>,
    }

    impl GeneratedPacketBatch for TestGeneratedBatch<'_> {
        type Error = GeneratedError;
        type Slot<'a>
            = TestGeneratedSlot<'a>
        where
            Self: 'a;

        fn allocate(
            &mut self,
            frame_len: usize,
        ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
            assert!(!self.attempted, "one action performs one allocation");
            self.attempted = true;
            if self.mode == GeneratedMode::AllocationFailure {
                return Err(GeneratedAllocationError::Unavailable);
            }
            *self.leases_live = self
                .leases_live
                .checked_add(1)
                .expect("generated lease count cannot overflow");
            self.allocated = true;
            let visible_len = if self.mode == GeneratedMode::WrongLength {
                frame_len - 1
            } else {
                frame_len
            };
            Ok(GeneratedPacketLease::new(TestGeneratedSlot {
                bytes: &mut self.frame[..visible_len],
                completion: &mut self.completion,
                leases_live: self.leases_live,
            }))
        }

        fn finish(self) -> GeneratedBatchCompletion<Self::Error> {
            let (requested, cancelled, abandoned) = match self.completion {
                Some(GeneratedSlotCompletion::Transmit) => (1, 0, 0),
                Some(GeneratedSlotCompletion::Cancelled) => (0, 1, 0),
                Some(GeneratedSlotCompletion::Abandoned) => (0, 0, 1),
                None => (0, 0, 0),
            };
            let allocated = usize::from(self.allocated);
            let failed = usize::from(self.attempted && !self.allocated);
            let invalid = self.mode == GeneratedMode::InvalidAccounting;
            let accepted = if invalid { 0 } else { requested };
            *self.state = TestBatchState::Idle;
            *self.pending_tx += accepted;
            GeneratedBatchCompletion {
                attempts: usize::from(self.attempted),
                allocated,
                failed,
                requested,
                cancelled,
                abandoned,
                accepted,
                rejected: 0,
                error: (self.mode == GeneratedMode::FinishError).then_some(GeneratedError::Finish),
            }
        }
    }

    impl Drop for TestGeneratedBatch<'_> {
        fn drop(&mut self) {
            *self.state = TestBatchState::Idle;
        }
    }

    impl GeneratedPacketIo for TestIo {
        type Error = GeneratedError;
        type Batch<'a> = TestGeneratedBatch<'a>;

        fn begin_generated(&mut self, _egress: IfId) -> Self::Batch<'_> {
            assert_eq!(
                self.batch_state,
                TestBatchState::Idle,
                "packet I/O batches cannot overlap"
            );
            assert_eq!(
                self.generated_leases_live, 0,
                "nonterminal generated leases prevent another batch"
            );
            self.batch_state = TestBatchState::Generated;
            self.generated_calls += 1;
            TestGeneratedBatch {
                mode: self.generated_mode,
                frame: &mut self.frame,
                state: &mut self.batch_state,
                pending_tx: &mut self.pending_tx,
                leases_live: &mut self.generated_leases_live,
                attempted: false,
                allocated: false,
                completion: None,
            }
        }
    }

    // SAFETY: RX and generated batches retain lifetime-bounded exclusive borrows
    // into this exact value; all error types are detached enums, and the audited
    // control implementation neither replaces the backend nor exposes an alias.
    #[allow(unsafe_code)]
    unsafe impl PublicationBackendAuthority for TestIo {}

    #[derive(Default)]
    struct TestTrace {
        phases: [Option<TickPhaseTrace>; 16],
        phase_len: usize,
    }

    impl TickPhaseTraceSink for TestTrace {
        fn record_tick_phase(&mut self, event: TickPhaseTrace) {
            self.phases[self.phase_len] = Some(event);
            self.phase_len += 1;
        }
    }

    impl TraceSink for TestTrace {
        fn record(&mut self, _event: TraceEvent) {}
    }

    impl ResolutionTimerTraceSink for TestTrace {
        fn record_resolution_timer(&mut self, _event: ResolutionTimerTrace) {}
    }

    impl ResolutionFailureTraceSink for TestTrace {
        fn record_resolution_failure(&mut self, _event: ResolutionFailureTrace) {}
    }

    impl GeneratedTraceSink for TestTrace {
        fn record_generated(&mut self, _event: ruster_core::GeneratedArpTrace) {}
    }

    impl GeneratedIcmpv4TraceSink for TestTrace {
        fn record_generated_icmpv4(&mut self, _event: ruster_core::GeneratedIcmpv4Trace) {}
    }

    fn assert_all_data_phases_skipped<C, E, Q, R, G, A>(
        report: &TickReport<C, E, Q, R, G, A>,
        reason: TickPhaseSkip,
    ) {
        assert!(matches!(
            &report.rx,
            RxPhaseReport::Skipped(actual) if *actual == reason
        ));
        assert!(matches!(
            &report.resolution_timers,
            PhaseReport::Skipped(actual) if *actual == reason
        ));
        assert!(matches!(
            &report.failure_dispatch,
            PhaseReport::Skipped(actual) if *actual == reason
        ));
        assert!(matches!(
            &report.generated_arp,
            PhaseReport::Skipped(actual) if *actual == reason
        ));
        assert!(matches!(
            &report.generated_icmpv4,
            PhaseReport::Skipped(actual) if *actual == reason
        ));
    }

    #[test]
    fn publication_outcome_debug_redacts_unconsumed_candidates() {
        struct OpaqueCandidate;
        fn require_debug<T: fmt::Debug>() {}
        require_debug::<PublicationOutcome<OpaqueCandidate, (), ()>>();
        require_debug::<PublicationAttemptError<OpaqueCandidate, ()>>();
        require_debug::<TickReport<OpaqueCandidate, (), (), (), ()>>();
        require_debug::<TickReport<OpaqueCandidate, (), (), (), (), usize>>();

        let attempt_mismatched: PublicationAttemptError<String, &'static str> =
            PublicationAttemptError::BackendMismatch {
                candidate: String::from("attempt-mismatch-secret"),
            };
        let attempt_rejected: PublicationAttemptError<String, &'static str> =
            PublicationAttemptError::Rejected(PublicationRejection::new(
                String::from("attempt-rejected-secret"),
                "attempt rejected",
            ));
        let applied: PublicationOutcome<OpaqueCandidate, (), (), usize> =
            PublicationOutcome::Applied(47);
        let rejected: PublicationOutcome<String, _, TestPublicationQuiescenceError> =
            PublicationOutcome::Rejected {
                rejection: PublicationRejection::new(String::from("rejected-secret"), "rejected"),
                status: ActivePublicationStatus::StopOldPublication,
            };
        let mismatched: PublicationOutcome<String, &'static str, TestPublicationQuiescenceError> =
            PublicationOutcome::BackendMismatch {
                candidate: Some(String::from("mismatch-secret")),
            };
        let mismatch_without_candidate: PublicationOutcome<
            String,
            &'static str,
            TestPublicationQuiescenceError,
        > = PublicationOutcome::BackendMismatch { candidate: None };
        let deferred: PublicationOutcome<String, &'static str, _> = PublicationOutcome::Deferred {
            candidate: String::from("deferred-secret"),
            error: TestPublicationQuiescenceError::Closing,
            disposition: PublicationQuiescenceDisposition::Stop,
        };

        let attempt_mismatched_debug = format!("{attempt_mismatched:?}");
        let attempt_rejected_debug = format!("{attempt_rejected:?}");
        let applied_debug = format!("{applied:?}");
        let rejected_debug = format!("{rejected:?}");
        let mismatched_debug = format!("{mismatched:?}");
        let mismatch_without_candidate_debug = format!("{mismatch_without_candidate:?}");
        let deferred_debug = format!("{deferred:?}");
        assert_eq!(
            attempt_mismatched_debug,
            "BackendMismatch { candidate: \"<redacted>\" }"
        );
        assert_eq!(
            attempt_rejected_debug,
            "Rejected { candidate: \"<redacted>\", error: \"attempt rejected\" }"
        );
        assert_eq!(applied_debug, "Applied(47)");
        assert_eq!(
            rejected_debug,
            "Rejected { candidate: \"<redacted>\", error: \"rejected\", status: StopOldPublication }"
        );
        assert_eq!(
            mismatched_debug,
            "BackendMismatch { candidate: Some(\"<redacted>\") }"
        );
        assert_eq!(
            mismatch_without_candidate_debug,
            "BackendMismatch { candidate: None }"
        );
        assert_eq!(
            deferred_debug,
            "Deferred { candidate: \"<redacted>\", error: Closing, disposition: Stop }"
        );
        assert!(!attempt_mismatched_debug.contains("attempt-mismatch-secret"));
        assert!(!attempt_rejected_debug.contains("attempt-rejected-secret"));
        assert!(!rejected_debug.contains("rejected-secret"));
        assert!(!mismatched_debug.contains("mismatch-secret"));
        assert!(!deferred_debug.contains("deferred-secret"));
    }

    #[test]
    fn backend_instance_mismatch_precedes_quiescence_failure_and_preserves_candidate() {
        with_fixture(|publication, paired_io, trace| {
            let (_wrong_owner, mut wrong_io) = bind_publication_backend(TestIo {
                pending_tx: 1,
                ..TestIo::default()
            })
            .expect("wrong test backend binding identity");
            let candidate = Box::new(48);
            let candidate_pointer = core::ptr::from_ref(candidate.as_ref());
            let report = run_test_tick(
                publication,
                Some(Candidate::ApplyOwned(candidate)),
                &mut wrong_io,
                MonotonicMillis(0),
                TickBudgets {
                    rx: usize::MAX,
                    resolution_timer_scans: usize::MAX,
                    failure_dispatch_scans: usize::MAX,
                    generated_arp: usize::MAX,
                    generated_icmpv4: usize::MAX,
                },
                trace,
            );
            let PublicationOutcome::BackendMismatch {
                candidate: Some(Candidate::ApplyOwned(ref candidate)),
            } = report.publication
            else {
                panic!("wrong backend must preserve the unconsumed candidate");
            };
            assert_eq!(candidate.as_ref(), &48);
            assert_eq!(core::ptr::from_ref(candidate.as_ref()), candidate_pointer);
            assert!(report.active);
            assert_all_data_phases_skipped(&report, TickPhaseSkip::BackendInstanceMismatch);
            assert_eq!(publication.applied, 0);
            assert_eq!(publication.active_calls, 0);
            assert_eq!(wrong_io.inner().quiescence_calls, 0);
            assert_eq!(
                (
                    wrong_io.inner().receive_calls,
                    wrong_io.inner().generated_calls
                ),
                (0, 0)
            );
            assert_eq!(paired_io.inner().quiescence_calls, 0);
            assert_eq!(
                (
                    paired_io.inner().receive_calls,
                    paired_io.inner().generated_calls
                ),
                (0, 0)
            );
            assert_eq!(trace.phase_len, 9);

            *trace = TestTrace::default();
            let report = run_test_tick(
                publication,
                None,
                &mut wrong_io,
                MonotonicMillis(1),
                TickBudgets::default(),
                trace,
            );
            assert_eq!(
                report.publication,
                PublicationOutcome::BackendMismatch { candidate: None }
            );
            assert!(report.active);
            assert_all_data_phases_skipped(&report, TickPhaseSkip::BackendInstanceMismatch);
            assert_eq!(publication.active_calls, 0);
            assert_eq!(wrong_io.inner().quiescence_calls, 0);
            assert_eq!(
                (
                    wrong_io.inner().receive_calls,
                    wrong_io.inner().generated_calls
                ),
                (0, 0)
            );
            assert_eq!(trace.phase_len, 9);
        });
    }

    #[test]
    fn safe_gate_rejects_wrong_raw_guard_before_authorized_hook() {
        with_fixture(|publication, paired_io, _trace| {
            let (_wrong_owner, mut wrong_io) = bind_publication_backend(TestIo::default())
                .expect("wrong raw-guard backend binding identity");
            let raw = wrong_io
                .try_publication_quiescence()
                .expect("wrong test backend is locally quiescent");
            let candidate = Box::new(50);
            let candidate_pointer = core::ptr::from_ref(candidate.as_ref());

            let error = try_publish_candidate(publication, Candidate::ApplyOwned(candidate), raw)
                .expect_err("wrong raw guard must not reach the authorized hook");
            let PublicationAttemptError::BackendMismatch {
                candidate: Candidate::ApplyOwned(candidate),
            } = error
            else {
                panic!("wrong raw guard must preserve the exact candidate");
            };

            assert_eq!(candidate.as_ref(), &50);
            assert_eq!(core::ptr::from_ref(candidate.as_ref()), candidate_pointer);
            assert_eq!(publication.applied, 0);
            assert_eq!(wrong_io.inner().quiescence_calls, 1);
            assert_eq!(paired_io.inner().quiescence_calls, 0);
        });
    }

    #[test]
    fn active_invariant_rejection_latches_fail_closed_across_candidate_free_ticks() {
        with_fixture(|publication, io, trace| {
            let candidate = Box::new(49);
            let candidate_pointer = core::ptr::from_ref(candidate.as_ref());
            let report = run_test_tick(
                publication,
                Some(Candidate::RejectActivePublication(candidate)),
                io,
                MonotonicMillis(0),
                TickBudgets {
                    rx: usize::MAX,
                    resolution_timer_scans: usize::MAX,
                    failure_dispatch_scans: usize::MAX,
                    generated_arp: usize::MAX,
                    generated_icmpv4: usize::MAX,
                },
                trace,
            );
            assert_all_data_phases_skipped(&report, TickPhaseSkip::ActivePublicationInvalid);
            let PublicationOutcome::Rejected {
                rejection,
                status: ActivePublicationStatus::StopOldPublication,
            } = report.publication
            else {
                panic!("active invariant failure must reject and stop the old publication");
            };
            assert_eq!(rejection.error(), &"active publication invalid");
            let (candidate, error) = rejection.into_parts();
            assert_eq!(error, "active publication invalid");
            let Candidate::RejectActivePublication(candidate) = candidate else {
                panic!("rejected candidate identity must be preserved");
            };
            assert_eq!(candidate.as_ref(), &49);
            assert_eq!(core::ptr::from_ref(candidate.as_ref()), candidate_pointer);
            assert!(report.active);
            assert_eq!(publication.active_calls, 0);
            assert_eq!(io.inner().quiescence_calls, 1);
            assert_eq!(
                (io.inner().receive_calls, io.inner().generated_calls),
                (0, 0)
            );
            assert_eq!(trace.phase_len, 9);

            io.execute_backend_command(TestIoCommand::SetPendingTx(1));
            *trace = TestTrace::default();
            let report = run_test_tick(
                publication,
                None,
                io,
                MonotonicMillis(1),
                TickBudgets::default(),
                trace,
            );
            assert_eq!(report.publication, PublicationOutcome::Unchanged);
            assert!(report.active);
            assert_all_data_phases_skipped(&report, TickPhaseSkip::ActivePublicationInvalid);
            assert_eq!(publication.active_calls, 0);
            assert_eq!(io.inner().quiescence_calls, 1);
            assert_eq!(
                (io.inner().receive_calls, io.inner().generated_calls),
                (0, 0)
            );
            assert_eq!(trace.phase_len, 9);

            let candidate = Box::new(51);
            let candidate_pointer = core::ptr::from_ref(candidate.as_ref());
            *trace = TestTrace::default();
            let report = run_test_tick(
                publication,
                Some(Candidate::ApplyOwned(candidate)),
                io,
                MonotonicMillis(2),
                TickBudgets::default(),
                trace,
            );
            assert!(report.active);
            assert_all_data_phases_skipped(&report, TickPhaseSkip::ActivePublicationInvalid);
            let PublicationOutcome::Rejected {
                rejection,
                status: ActivePublicationStatus::StopOldPublication,
            } = report.publication
            else {
                panic!("active stop latch must outrank backend quiescence");
            };
            assert_eq!(rejection.error(), &"active publication invalid");
            let (candidate, error) = rejection.into_parts();
            assert_eq!(error, "active publication invalid");
            let Candidate::ApplyOwned(candidate) = candidate else {
                panic!("latched rejection must retain the exact candidate");
            };
            assert_eq!(candidate.as_ref(), &51);
            assert_eq!(core::ptr::from_ref(candidate.as_ref()), candidate_pointer);
            assert_eq!(publication.active_calls, 0);
            assert_eq!(
                io.inner().quiescence_calls,
                1,
                "latched rejection must not request backend quiescence"
            );
            assert_eq!(
                (io.inner().receive_calls, io.inner().generated_calls),
                (0, 0)
            );
            assert_eq!(trace.phase_len, 9);
        });
    }

    #[test]
    fn safe_publication_gate_rejects_latched_candidate_before_adapter_hook() {
        with_fixture(|publication, io, trace| {
            let report = run_test_tick(
                publication,
                Some(Candidate::RejectActivePublication(Box::new(54))),
                io,
                MonotonicMillis(0),
                TickBudgets::default(),
                trace,
            );
            assert!(matches!(
                report.publication,
                PublicationOutcome::Rejected {
                    status: ActivePublicationStatus::StopOldPublication,
                    ..
                }
            ));
            assert_eq!(publication.applied, 0);

            let raw = io
                .try_publication_quiescence()
                .expect("test backend remains locally quiescent");
            let candidate = Box::new(55);
            let candidate_pointer = core::ptr::from_ref(candidate.as_ref());
            let error = try_publish_candidate(publication, Candidate::ApplyOwned(candidate), raw)
                .expect_err("latched candidate must not reach the adapter hook");
            let PublicationAttemptError::Rejected(rejection) = error else {
                panic!("exact matched guard must retain the active rejection");
            };
            assert_eq!(rejection.error(), &"active publication invalid");
            let (candidate, rejected_error) = rejection.into_parts();
            assert_eq!(rejected_error, "active publication invalid");
            let Candidate::ApplyOwned(candidate) = candidate else {
                panic!("safe gate must preserve the exact candidate");
            };
            assert_eq!(candidate.as_ref(), &55);
            assert_eq!(core::ptr::from_ref(candidate.as_ref()), candidate_pointer);
            assert_eq!(publication.applied, 0);
            assert_eq!(io.inner().quiescence_calls, 2);
        });
    }

    #[test]
    fn active_stop_latch_outranks_backend_skip_and_stop_without_quiescence() {
        for error in [
            TestPublicationQuiescenceError::RxBatchNotFinished,
            TestPublicationQuiescenceError::GeneratedBatchNotFinished,
            TestPublicationQuiescenceError::GeneratedLeaseNotCompleted,
            TestPublicationQuiescenceError::OwnershipFault,
            TestPublicationQuiescenceError::Closing,
        ] {
            with_fixture(|publication, io, trace| {
                let report = run_test_tick(
                    publication,
                    Some(Candidate::RejectActivePublication(Box::new(52))),
                    io,
                    MonotonicMillis(0),
                    TickBudgets::default(),
                    trace,
                );
                assert_all_data_phases_skipped(&report, TickPhaseSkip::ActivePublicationInvalid);
                assert!(matches!(
                    report.publication,
                    PublicationOutcome::Rejected {
                        status: ActivePublicationStatus::StopOldPublication,
                        ..
                    }
                ));
                assert_eq!(io.inner().quiescence_calls, 1);

                io.execute_backend_command(TestIoCommand::SetQuiescenceOverride(Some(error)));
                let candidate = Box::new(53);
                let candidate_pointer = core::ptr::from_ref(candidate.as_ref());
                *trace = TestTrace::default();
                let report = run_test_tick(
                    publication,
                    Some(Candidate::ApplyOwned(candidate)),
                    io,
                    MonotonicMillis(1),
                    TickBudgets::default(),
                    trace,
                );
                assert_all_data_phases_skipped(&report, TickPhaseSkip::ActivePublicationInvalid);
                let PublicationOutcome::Rejected {
                    rejection,
                    status: ActivePublicationStatus::StopOldPublication,
                } = report.publication
                else {
                    panic!("latched active failure must outrank backend error {error:?}");
                };
                assert_eq!(rejection.error(), &"active publication invalid");
                let (candidate, rejected_error) = rejection.into_parts();
                assert_eq!(rejected_error, "active publication invalid");
                let Candidate::ApplyOwned(candidate) = candidate else {
                    panic!("latched rejection must retain the exact candidate");
                };
                assert_eq!(candidate.as_ref(), &53);
                assert_eq!(core::ptr::from_ref(candidate.as_ref()), candidate_pointer);
                assert!(report.active);
                assert_eq!(publication.active_calls, 0);
                assert_eq!(
                    io.inner().quiescence_calls,
                    1,
                    "latched rejection must not observe backend error {error:?}"
                );
                assert_eq!(
                    (io.inner().receive_calls, io.inner().generated_calls),
                    (0, 0)
                );
                assert_eq!(trace.phase_len, 9);
            });
        }
    }

    #[test]
    fn applied_candidate_rechecks_terminal_backend_before_data_phases() {
        with_fixture(|publication, io, trace| {
            io.execute_backend_command(TestIoCommand::SetCurrentDisposition(
                PublicationQuiescenceDisposition::Stop,
            ));

            let report = run_test_tick(
                publication,
                Some(Candidate::Apply),
                io,
                MonotonicMillis(0),
                TickBudgets {
                    rx: usize::MAX,
                    resolution_timer_scans: usize::MAX,
                    failure_dispatch_scans: usize::MAX,
                    generated_arp: usize::MAX,
                    generated_icmpv4: usize::MAX,
                },
                trace,
            );

            assert_eq!(report.publication, PublicationOutcome::Applied(1));
            assert!(report.active);
            assert_all_data_phases_skipped(&report, TickPhaseSkip::BackendStopped);
            assert_eq!(publication.applied, 1);
            assert_eq!(publication.active_calls, 0);
            assert_eq!(io.inner().quiescence_calls, 1);
            assert_eq!(
                (io.inner().receive_calls, io.inner().generated_calls),
                (0, 0)
            );
            assert_eq!(trace.phase_len, 9);
        });
    }

    #[test]
    fn rejected_candidate_rechecks_terminal_backend_before_data_phases() {
        with_fixture(|publication, io, trace| {
            io.execute_backend_command(TestIoCommand::SetCurrentDisposition(
                PublicationQuiescenceDisposition::Stop,
            ));
            let candidate = Box::new(56);
            let candidate_pointer = core::ptr::from_ref(candidate.as_ref());

            let report = run_test_tick(
                publication,
                Some(Candidate::Reject(candidate)),
                io,
                MonotonicMillis(0),
                TickBudgets {
                    rx: usize::MAX,
                    resolution_timer_scans: usize::MAX,
                    failure_dispatch_scans: usize::MAX,
                    generated_arp: usize::MAX,
                    generated_icmpv4: usize::MAX,
                },
                trace,
            );

            assert!(report.active);
            assert_all_data_phases_skipped(&report, TickPhaseSkip::BackendStopped);
            let PublicationOutcome::Rejected {
                rejection,
                status: ActivePublicationStatus::ContinueOldIo,
            } = report.publication
            else {
                panic!("candidate rejection must survive terminal backend recheck");
            };
            assert_eq!(rejection.error(), &"rejected");
            let (candidate, error) = rejection.into_parts();
            assert_eq!(error, "rejected");
            let Candidate::Reject(candidate) = candidate else {
                panic!("terminal backend recheck must preserve the exact candidate");
            };
            assert_eq!(candidate.as_ref(), &56);
            assert_eq!(core::ptr::from_ref(candidate.as_ref()), candidate_pointer);
            assert_eq!(publication.applied, 0);
            assert_eq!(publication.active_calls, 0);
            assert_eq!(io.inner().quiescence_calls, 1);
            assert_eq!(
                (io.inner().receive_calls, io.inner().generated_calls),
                (0, 0)
            );
            assert_eq!(trace.phase_len, 9);
        });
    }

    #[test]
    fn publication_result_selects_the_active_generations_budget_in_the_same_tick() {
        with_fixture(|publication, io, trace| {
            let next_budgets = TickBudgets {
                rx: 7,
                ..TickBudgets::default()
            };
            let report = super::run_tick(
                publication,
                Some(Candidate::ApplyWithBudgets(next_budgets)),
                io,
                MonotonicMillis(0),
                Icmpv4TimestampClock(1),
                trace,
            );
            assert_eq!(report.publication, PublicationOutcome::Applied(1));
            assert_eq!(io.inner().last_receive_budget, Some(next_budgets.rx));
            assert_eq!(publication.tick_authority.tick_budgets(), next_budgets);

            *trace = TestTrace::default();
            let report = super::run_tick(
                publication,
                Some(Candidate::Reject(Box::new(1))),
                io,
                MonotonicMillis(1),
                Icmpv4TimestampClock(1),
                trace,
            );
            assert!(matches!(
                report.publication,
                PublicationOutcome::Rejected {
                    status: ActivePublicationStatus::ContinueOldIo,
                    ..
                }
            ));
            assert_eq!(io.inner().last_receive_budget, Some(next_budgets.rx));
            assert_eq!(publication.tick_authority.tick_budgets(), next_budgets);

            *trace = TestTrace::default();
            io.execute_backend_command(TestIoCommand::SetQuiescenceOverride(Some(
                TestPublicationQuiescenceError::TxCompletionPending,
            )));
            let deferred_budgets = TickBudgets {
                rx: 11,
                ..TickBudgets::default()
            };
            let report = super::run_tick(
                publication,
                Some(Candidate::ApplyWithBudgets(deferred_budgets)),
                io,
                MonotonicMillis(2),
                Icmpv4TimestampClock(1),
                trace,
            );
            assert!(matches!(
                report.publication,
                PublicationOutcome::Deferred {
                    candidate: Candidate::ApplyWithBudgets(budgets),
                    disposition: PublicationQuiescenceDisposition::ContinueOldIo,
                    ..
                } if budgets == deferred_budgets
            ));
            assert_eq!(io.inner().last_receive_budget, Some(next_budgets.rx));
            assert_eq!(publication.tick_authority.tick_budgets(), next_budgets);
        });
    }

    #[test]
    fn rejected_candidate_keeps_old_view_and_phase_sentinels_are_exact() {
        with_fixture(|publication, io, trace| {
            seed_resolution(publication, 2, 0);
            let candidate = Box::new(41);
            let candidate_pointer = core::ptr::from_ref(candidate.as_ref());
            let report = run_test_tick(
                publication,
                Some(Candidate::Reject(candidate)),
                io,
                MonotonicMillis(0),
                TickBudgets {
                    rx: 0,
                    resolution_timer_scans: 0,
                    failure_dispatch_scans: 0,
                    generated_arp: 1,
                    generated_icmpv4: 0,
                },
                trace,
            );
            let PublicationOutcome::Rejected {
                rejection,
                status: disposition,
            } = report.publication
            else {
                panic!("candidate must be rejected");
            };
            assert_eq!(disposition, ActivePublicationStatus::ContinueOldIo);
            assert_eq!(rejection.error(), &"rejected");
            let (candidate, error) = rejection.into_parts();
            assert_eq!(error, "rejected");
            let Candidate::Reject(candidate) = candidate else {
                panic!("rejected candidate identity must be preserved");
            };
            assert_eq!(candidate.as_ref(), &41);
            assert_eq!(core::ptr::from_ref(candidate.as_ref()), candidate_pointer);
            assert!(report.active);
            assert_eq!(io.inner().receive_calls, 1);
            assert_eq!(io.inner().generated_calls, 1);
            assert_eq!(io.inner().batch_state, TestBatchState::Idle);
            assert!(matches!(
                report.resolution_timers,
                PhaseReport::Completed(ResolutionTimerReport {
                    scanned: 0,
                    pending: 1,
                    ..
                })
            ));
            assert!(matches!(
                report.failure_dispatch,
                PhaseReport::Completed(ResolutionFailureDispatchReport { scanned: 0, .. })
            ));
            assert!(matches!(
                report.generated_arp,
                PhaseReport::Completed(GeneratedPhaseReport {
                    accounting: GeneratedAccounting {
                        sessions: 1,
                        tx_requested: 1,
                        tx_accepted: 1,
                        ..
                    },
                    stop: GeneratedArpStop::QueueEmpty,
                })
            ));
            assert_eq!(
                &trace.phases[..trace.phase_len],
                &[
                    Some(TickPhaseTrace::TickStarted),
                    Some(TickPhaseTrace::PhaseStarted(TickPhase::Publication)),
                    Some(TickPhaseTrace::PhaseFinished(TickPhase::Publication)),
                    Some(TickPhaseTrace::PhaseStarted(TickPhase::Rx)),
                    Some(TickPhaseTrace::PhaseFinished(TickPhase::Rx)),
                    Some(TickPhaseTrace::PhaseStarted(TickPhase::ResolutionTimers)),
                    Some(TickPhaseTrace::PhaseFinished(TickPhase::ResolutionTimers)),
                    Some(TickPhaseTrace::PhaseStarted(TickPhase::FailureDispatch)),
                    Some(TickPhaseTrace::PhaseFinished(TickPhase::FailureDispatch)),
                    Some(TickPhaseTrace::PhaseStarted(TickPhase::GeneratedArp)),
                    Some(TickPhaseTrace::PhaseFinished(TickPhase::GeneratedArp)),
                    Some(TickPhaseTrace::PhaseStarted(TickPhase::GeneratedIcmpv4)),
                    Some(TickPhaseTrace::PhaseFinished(TickPhase::GeneratedIcmpv4)),
                    Some(TickPhaseTrace::TickFinished),
                ]
            );
        });
    }

    #[test]
    fn sim_full_composition_orders_rx_before_arp_and_icmp_generated_tx() {
        with_sim_fixture(|publication, io, trace| {
            seed_resolution(publication, 2, 0);
            seed_icmpv4(publication, 0);
            io.inject(LAN, arp_request().into());
            let report = run_test_tick(
                publication,
                None,
                io,
                MonotonicMillis(0),
                TickBudgets {
                    rx: 1,
                    generated_arp: 1,
                    generated_icmpv4: 1,
                    ..TickBudgets::default()
                },
                trace,
            );
            assert!(matches!(
                report.rx,
                RxPhaseReport::Completed(BatchReport {
                    received: 1,
                    tx_requested: 1,
                    ..
                })
            ));
            assert_eq!(io.inner().pending_tx(), 3);
            assert!(matches!(
                io.pop_tx().unwrap().origin,
                FrameOrigin::Received { ingress: LAN }
            ));
            assert_eq!(io.pop_tx().unwrap().origin, FrameOrigin::Generated);
            assert_eq!(io.pop_tx().unwrap().origin, FrameOrigin::Generated);
        });
    }

    fn timestamp_request() -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + 20 + 20];
        frame[0..6].copy_from_slice(&LAN_MAC.0);
        frame[6..12].copy_from_slice(&HOST_MAC.0);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&40_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
        frame[22] = 64;
        frame[23] = 1;
        frame[26..30].copy_from_slice(&HOST_IP.octets());
        frame[30..34].copy_from_slice(&LAN_IP.octets());
        frame[34] = 13;
        let checksum = internet_checksum(&frame[34..54]);
        frame[36..38].copy_from_slice(&checksum.to_be_bytes());
        let ipv4_checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&ipv4_checksum.to_be_bytes());
        frame
    }

    /// RFC 792 / RFC 1812 §4.3.2.9, wired end to end through `run_tick`: a
    /// Timestamp request addressed to the router's own LAN address draws a
    /// Timestamp Reply carrying `run_test_tick`'s clock, proving the whole
    /// assembled router (not just the core forwarding function) answers one.
    #[test]
    fn assembled_router_answers_a_timestamp_request_with_the_tick_clock() {
        with_sim_fixture(|publication, io, trace| {
            io.inject(LAN, timestamp_request());
            let report = run_test_tick(
                publication,
                None,
                io,
                MonotonicMillis(5_000),
                TickBudgets {
                    rx: 1,
                    ..TickBudgets::default()
                },
                trace,
            );
            assert!(matches!(
                report.rx,
                RxPhaseReport::Completed(BatchReport {
                    received: 1,
                    tx_requested: 1,
                    ..
                })
            ));
            let reply = io.pop_tx().unwrap();
            assert_eq!(reply.origin, FrameOrigin::Received { ingress: LAN });
            assert_eq!(&reply.bytes[0..6], &HOST_MAC.0);
            assert_eq!(&reply.bytes[6..12], &LAN_MAC.0);
            assert_eq!(&reply.bytes[26..30], &LAN_IP.octets());
            assert_eq!(&reply.bytes[30..34], &HOST_IP.octets());
            assert_eq!(reply.bytes[34], 14, "Timestamp Reply");
            assert_eq!(reply.bytes[35], 0);
            // `run_test_tick` derives its clock as `now % 86_400_000`, and
            // 5_000 is already inside that range.
            assert_eq!(&reply.bytes[46..50], &5_000_u32.to_be_bytes());
            assert_eq!(&reply.bytes[50..54], &5_000_u32.to_be_bytes());
            assert_eq!(internet_checksum(&reply.bytes[34..54]), 0);
        });
    }

    #[test]
    fn no_active_publication_is_a_typed_skip_without_backend_access() {
        with_fixture(|publication, io, trace| {
            publication.active_status = ActivePublicationStatus::Absent;
            let report = run_test_tick(
                publication,
                Some(Candidate::Apply),
                io,
                MonotonicMillis(0),
                TickBudgets {
                    rx: usize::MAX,
                    resolution_timer_scans: usize::MAX,
                    failure_dispatch_scans: usize::MAX,
                    generated_arp: usize::MAX,
                    generated_icmpv4: usize::MAX,
                },
                trace,
            );
            assert_eq!(report.publication, PublicationOutcome::Applied(1));
            assert!(!report.active);
            assert_eq!(
                (io.inner().receive_calls, io.inner().generated_calls),
                (0, 0)
            );
            assert_eq!(
                report.rx,
                RxPhaseReport::Skipped(TickPhaseSkip::NoActivePublication)
            );
            assert!(matches!(
                report.generated_icmpv4,
                PhaseReport::Skipped(TickPhaseSkip::NoActivePublication)
            ));
            assert_eq!(trace.phase_len, 9);
            assert_eq!(
                trace.phases[trace.phase_len - 1],
                Some(TickPhaseTrace::TickFinished)
            );
        });
    }

    #[test]
    fn fake_quiescence_reports_each_unfinished_batch_state_exactly() {
        let (_rx_owner, mut rx_io) =
            bind_publication_backend(TestIo::default()).expect("RX-state test binding identity");
        let rx = rx_io.receive(0).expect("empty RX batch");
        core::mem::forget(rx);
        assert!(matches!(
            rx_io.try_publication_quiescence(),
            Err(TestPublicationQuiescenceError::RxBatchNotFinished)
        ));

        let (_generated_owner, mut generated_io) = bind_publication_backend(TestIo::default())
            .expect("generated-state test binding identity");
        let generated = generated_io.begin_generated(WAN);
        core::mem::forget(generated);
        assert!(matches!(
            generated_io.try_publication_quiescence(),
            Err(TestPublicationQuiescenceError::GeneratedBatchNotFinished)
        ));

        let (_lease_owner, mut lease_io) =
            bind_publication_backend(TestIo::default()).expect("lease-state test binding identity");
        let mut generated = lease_io.begin_generated(WAN);
        let lease = generated.allocate(64).expect("generated frame");
        core::mem::forget(lease);
        let completion = generated.finish();
        assert!(!completion.invariants_hold());
        assert!(matches!(
            lease_io.try_publication_quiescence(),
            Err(TestPublicationQuiescenceError::GeneratedLeaseNotCompleted)
        ));
    }

    #[test]
    fn candidate_quiescence_deferral_preserves_old_active_without_publication() {
        with_fixture(|publication, io, trace| {
            let mut generated = io.begin_generated(WAN);
            generated.allocate(64).expect("generated frame").commit();
            let completion = generated.finish();
            assert_eq!(completion.accepted, 1);
            assert_eq!(io.inner().pending_tx, 1);

            let candidate = Box::new(42);
            let candidate_pointer = core::ptr::from_ref(candidate.as_ref());
            let report = run_test_tick(
                publication,
                Some(Candidate::ApplyOwned(candidate)),
                io,
                MonotonicMillis(0),
                TickBudgets::default(),
                trace,
            );
            let PublicationOutcome::Deferred {
                candidate,
                error,
                disposition,
            } = report.publication
            else {
                panic!("candidate must be deferred");
            };
            assert_eq!(error, TestPublicationQuiescenceError::TxCompletionPending);
            assert_eq!(disposition, PublicationQuiescenceDisposition::ContinueOldIo);
            let Candidate::ApplyOwned(candidate) = candidate else {
                panic!("deferred candidate identity must be preserved");
            };
            assert_eq!(candidate.as_ref(), &42);
            assert_eq!(core::ptr::from_ref(candidate.as_ref()), candidate_pointer);
            assert!(report.active);
            assert_eq!(publication.applied, 0);
            assert_eq!(publication.active_calls, 1);
            assert_eq!(io.inner().quiescence_calls, 1);
            assert_eq!(io.inner().receive_calls, 1);
            assert_eq!(io.inner().pending_tx, 1);

            io.execute_backend_command(TestIoCommand::CompletePendingTx);
            *trace = TestTrace::default();
            let report = run_test_tick(
                publication,
                Some(Candidate::Apply),
                io,
                MonotonicMillis(1),
                TickBudgets::default(),
                trace,
            );
            assert_eq!(report.publication, PublicationOutcome::Applied(1));
            assert_eq!(publication.applied, 1);
            assert_eq!(publication.active_calls, 2);
            assert_eq!(io.inner().quiescence_calls, 2);
            assert_eq!(io.inner().receive_calls, 2);
        });
    }

    fn assert_forgotten_sim_state_skips_every_data_phase(
        setup: CountingSimIoCommand,
        expected_error: SimPublicationQuiescenceError,
    ) {
        with_counting_sim_fixture(|publication, io, trace| {
            io.execute_backend_command(setup);
            io.execute_backend_command(CountingSimIoCommand::ResetCalls);
            let candidate = Box::new(43);
            let candidate_pointer = core::ptr::from_ref(candidate.as_ref());
            let report = run_test_tick(
                publication,
                Some(Candidate::ApplyOwned(candidate)),
                io,
                MonotonicMillis(0),
                TickBudgets {
                    rx: usize::MAX,
                    resolution_timer_scans: usize::MAX,
                    failure_dispatch_scans: usize::MAX,
                    generated_arp: usize::MAX,
                    generated_icmpv4: usize::MAX,
                },
                trace,
            );
            let PublicationOutcome::Deferred {
                candidate,
                error,
                disposition,
            } = report.publication
            else {
                panic!("candidate must be deferred");
            };
            assert_eq!(error, expected_error);
            assert_eq!(disposition, PublicationQuiescenceDisposition::SkipIo);
            let Candidate::ApplyOwned(candidate) = candidate else {
                panic!("deferred candidate identity must be preserved");
            };
            assert_eq!(candidate.as_ref(), &43);
            assert_eq!(core::ptr::from_ref(candidate.as_ref()), candidate_pointer);
            assert!(report.active);
            assert_eq!(
                report.rx,
                RxPhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
            );
            assert!(matches!(
                report.resolution_timers,
                PhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
            ));
            assert!(matches!(
                report.failure_dispatch,
                PhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
            ));
            assert!(matches!(
                report.generated_arp,
                PhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
            ));
            assert!(matches!(
                report.generated_icmpv4,
                PhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
            ));
            assert_eq!(trace.phase_len, 9);
            assert_eq!(
                (io.inner().receive_calls, io.inner().generated_calls),
                (0, 0)
            );

            *trace = TestTrace::default();
            let report = run_test_tick(
                publication,
                None,
                io,
                MonotonicMillis(1),
                TickBudgets {
                    rx: usize::MAX,
                    resolution_timer_scans: usize::MAX,
                    failure_dispatch_scans: usize::MAX,
                    generated_arp: usize::MAX,
                    generated_icmpv4: usize::MAX,
                },
                trace,
            );
            assert_eq!(report.publication, PublicationOutcome::Unchanged);
            assert!(report.active);
            assert_eq!(
                report.rx,
                RxPhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
            );
            assert!(matches!(
                report.resolution_timers,
                PhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
            ));
            assert!(matches!(
                report.failure_dispatch,
                PhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
            ));
            assert!(matches!(
                report.generated_arp,
                PhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
            ));
            assert!(matches!(
                report.generated_icmpv4,
                PhaseReport::Skipped(TickPhaseSkip::BackendIoNotReentrant)
            ));
            assert_eq!(trace.phase_len, 9);
            assert_eq!(
                (io.inner().receive_calls, io.inner().generated_calls),
                (0, 0)
            );
            assert_eq!(io.inner().quiescence_calls, 1);
            assert_eq!(publication.applied, 0);
            assert_eq!(publication.active_calls, 0);
        });
    }

    #[test]
    fn candidate_with_forgotten_sim_batch_or_lease_skips_every_data_phase() {
        assert_forgotten_sim_state_skips_every_data_phase(
            CountingSimIoCommand::ForgetRxBatch,
            SimPublicationQuiescenceError::RxBatchNotFinished,
        );
        assert_forgotten_sim_state_skips_every_data_phase(
            CountingSimIoCommand::ForgetGeneratedBatch,
            SimPublicationQuiescenceError::GeneratedBatchNotFinished,
        );
        assert_forgotten_sim_state_skips_every_data_phase(
            CountingSimIoCommand::ForgetRxLease,
            SimPublicationQuiescenceError::RxLeaseNotCompleted,
        );
        assert_forgotten_sim_state_skips_every_data_phase(
            CountingSimIoCommand::ForgetGeneratedLease,
            SimPublicationQuiescenceError::GeneratedLeaseNotCompleted,
        );
    }

    #[test]
    fn sim_pending_tx_defers_candidate_but_continues_old_io() {
        with_sim_fixture(|publication, io, trace| {
            let mut generated = io.begin_generated(WAN);
            generated.allocate(64).expect("generated frame").commit();
            assert_eq!(generated.finish().accepted, 1);

            let report = run_test_tick(
                publication,
                Some(Candidate::Apply),
                io,
                MonotonicMillis(0),
                TickBudgets::default(),
                trace,
            );
            assert_eq!(
                report.publication,
                PublicationOutcome::Deferred {
                    candidate: Candidate::Apply,
                    error: SimPublicationQuiescenceError::TxCompletionPending,
                    disposition: PublicationQuiescenceDisposition::ContinueOldIo,
                }
            );
            assert_eq!(publication.applied, 0);
            assert!(matches!(
                report.rx,
                RxPhaseReport::Completed(BatchReport { received: 0, .. })
            ));
            assert!(matches!(
                report.resolution_timers,
                PhaseReport::Completed(_)
            ));
            assert!(matches!(report.failure_dispatch, PhaseReport::Completed(_)));
            assert!(matches!(report.generated_arp, PhaseReport::Completed(_)));
            assert!(matches!(report.generated_icmpv4, PhaseReport::Completed(_)));
            assert_eq!(io.inner().pending_tx(), 1);
        });
    }

    #[test]
    fn test_io_control_keeps_stop_terminal_after_clear_or_continue_requests() {
        for terminal_error in [
            TestPublicationQuiescenceError::OwnershipFault,
            TestPublicationQuiescenceError::Closing,
        ] {
            let (_owner, mut io) = bind_publication_backend(TestIo::default())
                .expect("test publication binding identity");

            io.execute_backend_command(TestIoCommand::SetQuiescenceOverride(Some(terminal_error)));
            assert_test_io_terminal_stop(&mut io, terminal_error);

            io.execute_backend_command(TestIoCommand::SetQuiescenceOverride(None));
            assert_test_io_terminal_stop(&mut io, terminal_error);

            io.execute_backend_command(TestIoCommand::SetQuiescenceOverride(Some(
                TestPublicationQuiescenceError::TxCompletionPending,
            )));
            assert_test_io_terminal_stop(&mut io, terminal_error);
        }
    }

    fn assert_test_io_terminal_stop(
        io: &mut BoundTestIo,
        expected: TestPublicationQuiescenceError,
    ) {
        assert_eq!(
            <BoundTestIo as PublicationQuiescence>::current_io_disposition(io),
            PublicationQuiescenceDisposition::Stop
        );
        assert_eq!(
            <BoundTestIo as PublicationQuiescence>::quiescence_error_disposition(&expected),
            PublicationQuiescenceDisposition::Stop
        );
        match io.try_publication_quiescence() {
            Err(error) => assert_eq!(error, expected),
            Ok(_guard) => panic!("terminal test backend must not mint a quiescence guard"),
        }
    }

    #[test]
    fn ownership_fault_or_closing_stops_every_data_phase() {
        for error in [
            TestPublicationQuiescenceError::OwnershipFault,
            TestPublicationQuiescenceError::Closing,
        ] {
            with_fixture(|publication, io, trace| {
                io.execute_backend_command(TestIoCommand::SetQuiescenceOverride(Some(error)));
                let candidate = Box::new(44);
                let candidate_pointer = core::ptr::from_ref(candidate.as_ref());
                let report = run_test_tick(
                    publication,
                    Some(Candidate::ApplyOwned(candidate)),
                    io,
                    MonotonicMillis(0),
                    TickBudgets {
                        rx: usize::MAX,
                        resolution_timer_scans: usize::MAX,
                        failure_dispatch_scans: usize::MAX,
                        generated_arp: usize::MAX,
                        generated_icmpv4: usize::MAX,
                    },
                    trace,
                );
                let PublicationOutcome::Deferred {
                    candidate,
                    error: deferred_error,
                    disposition,
                } = report.publication
                else {
                    panic!("candidate must be deferred");
                };
                assert_eq!(deferred_error, error);
                assert_eq!(disposition, PublicationQuiescenceDisposition::Stop);
                let Candidate::ApplyOwned(candidate) = candidate else {
                    panic!("deferred candidate identity must be preserved");
                };
                assert_eq!(candidate.as_ref(), &44);
                assert_eq!(core::ptr::from_ref(candidate.as_ref()), candidate_pointer);
                assert!(report.active);
                assert_eq!(publication.applied, 0);
                assert_eq!(
                    (io.inner().receive_calls, io.inner().generated_calls),
                    (0, 0)
                );
                assert_eq!(
                    report.rx,
                    RxPhaseReport::Skipped(TickPhaseSkip::BackendStopped)
                );
                assert!(matches!(
                    report.resolution_timers,
                    PhaseReport::Skipped(TickPhaseSkip::BackendStopped)
                ));
                assert!(matches!(
                    report.failure_dispatch,
                    PhaseReport::Skipped(TickPhaseSkip::BackendStopped)
                ));
                assert!(matches!(
                    report.generated_arp,
                    PhaseReport::Skipped(TickPhaseSkip::BackendStopped)
                ));
                assert!(matches!(
                    report.generated_icmpv4,
                    PhaseReport::Skipped(TickPhaseSkip::BackendStopped)
                ));

                *trace = TestTrace::default();
                let report = run_test_tick(
                    publication,
                    None,
                    io,
                    MonotonicMillis(1),
                    TickBudgets {
                        rx: usize::MAX,
                        resolution_timer_scans: usize::MAX,
                        failure_dispatch_scans: usize::MAX,
                        generated_arp: usize::MAX,
                        generated_icmpv4: usize::MAX,
                    },
                    trace,
                );
                assert_eq!(report.publication, PublicationOutcome::Unchanged);
                assert_eq!(publication.active_calls, 0);
                assert_eq!(io.inner().quiescence_calls, 1);
                assert_eq!(
                    (io.inner().receive_calls, io.inner().generated_calls),
                    (0, 0)
                );
                assert_eq!(
                    report.rx,
                    RxPhaseReport::Skipped(TickPhaseSkip::BackendStopped)
                );
                assert!(matches!(
                    report.resolution_timers,
                    PhaseReport::Skipped(TickPhaseSkip::BackendStopped)
                ));
                assert!(matches!(
                    report.failure_dispatch,
                    PhaseReport::Skipped(TickPhaseSkip::BackendStopped)
                ));
                assert!(matches!(
                    report.generated_arp,
                    PhaseReport::Skipped(TickPhaseSkip::BackendStopped)
                ));
                assert!(matches!(
                    report.generated_icmpv4,
                    PhaseReport::Skipped(TickPhaseSkip::BackendStopped)
                ));
            });
        }
    }

    #[test]
    fn unchanged_tick_never_requests_a_quiescence_guard() {
        with_fixture(|publication, io, trace| {
            let mut generated = io.begin_generated(WAN);
            generated.allocate(64).expect("generated frame").commit();
            let completion = generated.finish();
            assert_eq!(completion.accepted, 1);

            let report = run_test_tick(
                publication,
                None,
                io,
                MonotonicMillis(0),
                TickBudgets::default(),
                trace,
            );
            assert_eq!(report.publication, PublicationOutcome::Unchanged);
            assert_eq!(io.inner().quiescence_calls, 0);
            assert_eq!(publication.active_calls, 1);
            assert_eq!(io.inner().receive_calls, 1);
        });
    }

    #[test]
    fn active_view_is_one_o1_borrow_without_revalidation_scans() {
        with_fixture(|publication, io, trace| {
            let report = run_test_tick(
                publication,
                None,
                io,
                MonotonicMillis(0),
                TickBudgets::default(),
                trace,
            );
            assert!(report.active);
            assert_eq!(publication.active_calls, 1);
            assert_eq!(publication.steady_validation_scans, 0);
        });
    }

    #[test]
    fn active_view_pairs_one_generation_with_config_and_runtime_values() {
        with_fixture(|publication, _io, _trace| {
            let udp = publication.udp_config;
            let tcp = publication.tcp_config;
            let firewall = publication.firewall_config;
            let view = <TestPublication<'_, '_, BoundTestIo> as FullServicePublication<
                '_,
                BoundTestIo,
            >>::active(publication);
            assert_eq!(view.tick_authority.generation(), NonZeroU64::MIN);
            assert_eq!(view.tick_authority.tick_budgets(), TickBudgets::default());
            assert_eq!(view.tick_budgets(), TickBudgets::default());
            assert_eq!(view.nat44_udp.config, udp);
            assert!(view.nat44_udp.runtime.is_none());
            assert_eq!(view.nat44_tcp.config, tcp);
            assert!(view.nat44_tcp.runtime.is_none());
            assert_eq!(view.firewall.config, firewall);
            assert!(view.firewall.runtime.is_none());
        });
    }

    #[test]
    fn generated_budget_is_exact_and_failures_stop_after_one_session() {
        for (mode, expected_pending) in [
            (GeneratedMode::AllocationFailure, 2),
            (GeneratedMode::WrongLength, 2),
            (GeneratedMode::FinishError, 1),
        ] {
            with_fixture(|publication, io, trace| {
                for last in [2, 3] {
                    seed_resolution(publication, last, 0);
                }
                seed_icmpv4(publication, 0);
                io.execute_backend_command(TestIoCommand::SetGeneratedMode(mode));
                let report = run_test_tick(
                    publication,
                    None,
                    io,
                    MonotonicMillis(0),
                    TickBudgets {
                        generated_arp: 4,
                        generated_icmpv4: 1,
                        ..TickBudgets::default()
                    },
                    trace,
                );
                assert_eq!(
                    publication.resolution.pending_actions(),
                    expected_pending,
                    "mode {mode:?}"
                );
                let PhaseReport::Completed(arp) = report.generated_arp else {
                    panic!("generated ARP phase must run");
                };
                assert_eq!(arp.accounting.sessions, 1);
                assert!(matches!(arp.stop, GeneratedArpStop::Failed(_)));
                match mode {
                    GeneratedMode::AllocationFailure => {
                        assert_eq!(io.inner().generated_calls, 2);
                        assert_eq!(publication.icmpv4_errors.pending_actions(), 1);
                        assert!(matches!(
                            report.generated_icmpv4,
                            PhaseReport::Completed(GeneratedPhaseReport {
                                stop: GeneratedIcmpv4Stop::Failed(GeneratedIcmpv4Failure {
                                    allocation: Some(GeneratedAllocationError::Unavailable),
                                    ..
                                }),
                                ..
                            })
                        ));
                    }
                    GeneratedMode::WrongLength => {
                        assert_eq!(io.inner().generated_calls, 1);
                        assert_eq!(publication.icmpv4_errors.pending_actions(), 1);
                        assert!(matches!(
                            report.generated_icmpv4,
                            PhaseReport::Skipped(TickPhaseSkip::GeneratedArpFailure)
                        ));
                    }
                    GeneratedMode::FinishError => {
                        assert_eq!(io.inner().generated_calls, 1);
                        assert_eq!(publication.icmpv4_errors.pending_actions(), 1);
                        assert!(matches!(
                            report.generated_icmpv4,
                            PhaseReport::Skipped(TickPhaseSkip::BackendIoFailure)
                        ));
                    }
                    GeneratedMode::Exact | GeneratedMode::InvalidAccounting => unreachable!(),
                }
            });
        }

        with_fixture(|publication, io, trace| {
            for last in [2, 3, 4] {
                seed_resolution(publication, last, 0);
            }
            let report = run_test_tick(
                publication,
                None,
                io,
                MonotonicMillis(0),
                TickBudgets {
                    resolution_timer_scans: 2,
                    failure_dispatch_scans: 1,
                    generated_arp: 2,
                    ..TickBudgets::default()
                },
                trace,
            );
            assert_eq!(io.inner().generated_calls, 2);
            assert_eq!(publication.resolution.pending_actions(), 1);
            assert!(matches!(
                report.resolution_timers,
                PhaseReport::Completed(ResolutionTimerReport { scanned: 2, .. })
            ));
            assert!(matches!(
                report.failure_dispatch,
                PhaseReport::Completed(ResolutionFailureDispatchReport { scanned: 1, .. })
            ));
            assert!(matches!(
                report.generated_arp,
                PhaseReport::Completed(GeneratedPhaseReport {
                    accounting: GeneratedAccounting { sessions: 2, .. },
                    stop: GeneratedArpStop::BudgetExhausted { pending: 1 },
                })
            ));
        });
    }

    #[test]
    fn receive_error_runs_non_io_phases_but_skips_all_generated_io() {
        for mode in [RxMode::Fail, RxMode::FinishError] {
            with_fixture(|publication, io, trace| {
                seed_resolution(publication, 2, 10);
                io.execute_backend_command(TestIoCommand::SetRxMode(mode));
                let report = run_test_tick(
                    publication,
                    None,
                    io,
                    MonotonicMillis(10),
                    TickBudgets {
                        generated_arp: 1,
                        ..TickBudgets::default()
                    },
                    trace,
                );
                match mode {
                    RxMode::Fail => {
                        assert_eq!(report.rx, RxPhaseReport::ReceiveFailed(RxError::Injected));
                    }
                    RxMode::FinishError => assert!(matches!(
                        report.rx,
                        RxPhaseReport::Completed(BatchReport {
                            completion: BatchCompletion {
                                error: Some(RxError::Injected),
                                ..
                            },
                            ..
                        })
                    )),
                    RxMode::Empty => unreachable!(),
                }
                assert!(matches!(
                    report.resolution_timers,
                    PhaseReport::Completed(ResolutionTimerReport { scanned: 0, .. })
                ));
                assert!(matches!(
                    report.failure_dispatch,
                    PhaseReport::Completed(ResolutionFailureDispatchReport { scanned: 0, .. })
                ));
                assert!(matches!(
                    report.generated_arp,
                    PhaseReport::Skipped(TickPhaseSkip::BackendIoFailure)
                ));
                assert!(matches!(
                    report.generated_icmpv4,
                    PhaseReport::Skipped(TickPhaseSkip::BackendIoFailure)
                ));
                assert_eq!(publication.resolution.pending_actions(), 1);
                assert_eq!(io.inner().generated_calls, 0);
            });
        }
    }

    #[test]
    fn timer_clock_regression_skips_failure_and_both_generated_phases_atomically() {
        with_fixture(|publication, io, trace| {
            seed_resolution(publication, 2, 10);
            seed_icmpv4(publication, 10);
            let report = run_test_tick(
                publication,
                None,
                io,
                MonotonicMillis(9),
                TickBudgets {
                    failure_dispatch_scans: 1,
                    generated_arp: 1,
                    generated_icmpv4: 1,
                    ..TickBudgets::default()
                },
                trace,
            );
            assert!(matches!(
                report.resolution_timers,
                PhaseReport::Failed(ResolutionTimerError::ClockRegression)
            ));
            assert!(matches!(
                report.failure_dispatch,
                PhaseReport::Skipped(TickPhaseSkip::ClockRegression)
            ));
            assert!(matches!(
                report.generated_arp,
                PhaseReport::Skipped(TickPhaseSkip::ClockRegression)
            ));
            assert!(matches!(
                report.generated_icmpv4,
                PhaseReport::Skipped(TickPhaseSkip::ClockRegression)
            ));
            assert_eq!(publication.resolution.pending_actions(), 1);
            assert_eq!(publication.icmpv4_errors.pending_actions(), 1);
            assert_eq!(io.inner().generated_calls, 0);
        });
    }

    #[test]
    fn generated_accounting_violation_stops_later_backend_phases() {
        with_fixture(|publication, io, trace| {
            for last in [2, 3] {
                seed_resolution(publication, last, 0);
            }
            io.execute_backend_command(TestIoCommand::SetGeneratedMode(
                GeneratedMode::InvalidAccounting,
            ));
            let report = run_test_tick(
                publication,
                None,
                io,
                MonotonicMillis(0),
                TickBudgets {
                    generated_arp: 2,
                    generated_icmpv4: 1,
                    ..TickBudgets::default()
                },
                trace,
            );
            assert_eq!(io.inner().generated_calls, 1);
            assert_eq!(publication.resolution.pending_actions(), 1);
            let PhaseReport::Completed(GeneratedPhaseReport {
                accounting,
                stop: GeneratedArpStop::AccountingInvariantViolation(violation),
            }) = report.generated_arp
            else {
                panic!("raw invalid completion must be reported");
            };
            assert_eq!(accounting.sessions, 1);
            assert_eq!(
                (
                    violation.completion.attempts,
                    violation.completion.allocated,
                    violation.completion.requested,
                    violation.completion.accepted,
                    violation.completion.rejected,
                ),
                (1, 1, 1, 0, 0)
            );
            assert!(!violation.completion.invariants_hold());
            assert!(matches!(
                report.generated_icmpv4,
                PhaseReport::Skipped(TickPhaseSkip::BackendContractViolation)
            ));
        });
    }

    #[test]
    fn generated_icmpv4_build_failure_is_single_attempt_and_preserves_pending() {
        with_fixture(|publication, io, trace| {
            seed_icmpv4(publication, 0);
            io.execute_backend_command(TestIoCommand::SetGeneratedMode(GeneratedMode::WrongLength));
            let report = run_test_tick(
                publication,
                None,
                io,
                MonotonicMillis(0),
                TickBudgets {
                    generated_icmpv4: 4,
                    ..TickBudgets::default()
                },
                trace,
            );
            assert_eq!(io.inner().generated_calls, 1);
            assert_eq!(publication.icmpv4_errors.pending_actions(), 1);
            assert!(matches!(
                report.generated_icmpv4,
                PhaseReport::Completed(GeneratedPhaseReport {
                    accounting: GeneratedAccounting {
                        sessions: 1,
                        cancelled: 1,
                        ..
                    },
                    stop: GeneratedIcmpv4Stop::Failed(GeneratedIcmpv4Failure {
                        build: Some(Icmpv4ErrorBuildError::ExactLengthRequired),
                        ..
                    }),
                })
            ));
        });
    }

    #[test]
    fn optional_service_views_distinguish_absent_runtime_from_absent_counters() {
        // Protects every optional service-view presence and counter accessor
        // from manufacturing a runtime or counters when the publication
        // supplied neither, including the nested view implementations.
        with_fixture(|publication, _io, _trace| {
            let view = <TestPublication<'_, '_, BoundTestIo> as FullServicePublication<
                '_,
                BoundTestIo,
            >>::active(publication);

            assert!(!view.has_nat44_udp_runtime());
            assert!(!view.has_nat44_tcp_runtime());
            assert!(!view.has_firewall_runtime());
            assert_eq!(view.nat44_udp_counters(), None);
            assert_eq!(view.nat44_tcp_counters(), None);
            assert_eq!(view.firewall_counters(), None);
        });
    }

    #[test]
    fn optional_service_views_preserve_present_runtime_and_live_counters() {
        // Protects every optional service-view accessor from replacing a
        // present runtime with a constant result and from replacing its live
        // non-default counters with `None` or `Default`.
        let routes = [
            Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
            Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(GATEWAY)).unwrap(),
        ];
        let interfaces = [
            Interface {
                id: LAN,
                mac: LAN_MAC,
                mtu: Ipv4Mtu::ETHERNET,
            },
            Interface {
                id: WAN,
                mac: WAN_MAC,
                mtu: Ipv4Mtu::ETHERNET,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: LAN_IP,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: WAN_IP,
            },
        ];
        let neighbors = [Neighbor {
            interface: LAN,
            target: HOST_IP,
            mac: HOST_MAC,
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            WAN_IP,
            40_000,
            40_003,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            WAN_IP,
            40_000,
            40_003,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let firewall_rules = [];
        let firewall_config = FirewallConfig::new(
            &snapshot,
            &firewall_rules,
            FirewallPolicy::default(),
            1,
            FirewallHashKey::new(1, 2).unwrap(),
        )
        .unwrap();
        let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
        let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
        let mut resolution = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            &mut resolution_states,
            &mut resolution_actions,
        );
        let mut icmp_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut icmp_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut icmpv4_errors = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::default(),
            &mut icmp_states,
            &mut icmp_actions,
        );
        let tick_authority = ActiveTickAuthority::new(NonZeroU64::MIN, TickBudgets::default());

        {
            let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
            let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
            let mut udp_mapping_buckets = [DirectoryBucket::default(); 1];
            let mut udp_mapping_nodes = [DirectoryNode::default(); 1];
            let mut udp_peer_buckets = [DirectoryBucket::default(); 1];
            let mut udp_peer_nodes = [DirectoryNode::default(); 1];
            let mut udp_port_owners = [PortOwnerSlot::default(); 4];
            let udp_hash_key = Nat44UdpHashKey::new(1, 2).unwrap();
            let mut udp_runtime = Nat44UdpRuntime::new(
                udp_config,
                &mut udp_mappings,
                &mut udp_peers,
                Nat44UdpIndexStorage::new(
                    &mut udp_mapping_buckets,
                    &mut udp_mapping_nodes,
                    &mut udp_peer_buckets,
                    &mut udp_peer_nodes,
                    &mut udp_port_owners,
                ),
                udp_hash_key,
            )
            .unwrap();
            udp_runtime
                .reconcile(udp_config, Nat44UdpHashKey::new(3, 4).unwrap())
                .unwrap();
            let udp_counters = udp_runtime.counters();
            assert!(udp_counters.reconciliations > 0);

            let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
            let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
            let mut tcp_mapping_buckets = [DirectoryBucket::default(); 1];
            let mut tcp_mapping_nodes = [DirectoryNode::default(); 1];
            let mut tcp_session_buckets = [DirectoryBucket::default(); 1];
            let mut tcp_session_nodes = [DirectoryNode::default(); 1];
            let mut tcp_port_owners = [PortOwnerSlot::default(); 4];
            let tcp_hash_key = Nat44TcpHashKey::new(5, 6).unwrap();
            let mut tcp_runtime = Nat44TcpRuntime::new(
                tcp_config,
                &mut tcp_mappings,
                &mut tcp_sessions,
                Nat44TcpIndexStorage::new(
                    &mut tcp_mapping_buckets,
                    &mut tcp_mapping_nodes,
                    &mut tcp_session_buckets,
                    &mut tcp_session_nodes,
                    &mut tcp_port_owners,
                ),
                tcp_hash_key,
            )
            .unwrap();
            tcp_runtime
                .reconcile(tcp_config, Nat44TcpHashKey::new(7, 8).unwrap())
                .unwrap();
            let tcp_counters = tcp_runtime.counters();
            assert!(tcp_counters.reconciliations > 0);

            let mut firewall_states = [FirewallStateSlot::default(); 1];
            let mut firewall_runtime = FirewallRuntime::new(firewall_config, &mut firewall_states);
            let next_firewall_config = FirewallConfig::new(
                &snapshot,
                firewall_config.rules(),
                firewall_config.policy(),
                firewall_config.generation() + 1,
                FirewallHashKey::new(9, 10).unwrap(),
            )
            .unwrap();
            firewall_runtime.reconcile(next_firewall_config).unwrap();
            let firewall_counters = firewall_runtime.counters();
            assert!(firewall_counters.reconciliations > 0);

            let view = FullServiceView::new(
                &tick_authority,
                snapshot,
                &mut resolution,
                &mut icmpv4_errors,
                Nat44UdpServiceView::new(udp_config, Some(&mut udp_runtime)),
                Nat44TcpServiceView::new(tcp_config, Some(&mut tcp_runtime)),
                FirewallServiceView::new(next_firewall_config, Some(&mut firewall_runtime)),
            );

            assert!(view.has_nat44_udp_runtime());
            assert!(view.has_nat44_tcp_runtime());
            assert!(view.has_firewall_runtime());
            assert_eq!(view.nat44_udp_counters(), Some(udp_counters));
            assert_eq!(view.nat44_tcp_counters(), Some(tcp_counters));
            assert_eq!(view.firewall_counters(), Some(firewall_counters));
        }
    }

    #[test]
    fn active_publication_status_presence_is_false_only_when_absent() {
        // Protects the publication-presence predicate from treating an absent
        // owner as present; the two active states must remain present.
        assert!(!ActivePublicationStatus::Absent.is_present());
        assert!(ActivePublicationStatus::ContinueOldIo.is_present());
        assert!(ActivePublicationStatus::StopOldPublication.is_present());
    }

    #[test]
    fn tick_report_debug_includes_the_report_fields() {
        // Protects TickReport's structured Debug implementation from silently
        // returning success without writing any report representation.
        let report: TickReport<(), (), (), (), (), ()> = TickReport {
            publication: PublicationOutcome::Unchanged,
            active: false,
            rx: RxPhaseReport::Skipped(TickPhaseSkip::NoActivePublication),
            resolution_timers: PhaseReport::Skipped(TickPhaseSkip::NoActivePublication),
            failure_dispatch: PhaseReport::Skipped(TickPhaseSkip::NoActivePublication),
            generated_arp: PhaseReport::Skipped(TickPhaseSkip::NoActivePublication),
            generated_icmpv4: PhaseReport::Skipped(TickPhaseSkip::NoActivePublication),
        };

        let debug = format!("{report:?}");
        assert!(debug.starts_with("TickReport {"));
        assert!(debug.contains("active: false"));
        assert!(debug.contains("rx: Skipped(NoActivePublication)"));
    }

    #[test]
    fn generated_icmpv4_distinguishes_empty_queue_from_budget_exhaustion() {
        // Protects the generated-ICMPv4 terminal boundary: zero pending
        // actions is QueueEmpty, while a zero budget with pending work is
        // BudgetExhausted and must retain the pending count.
        with_fixture(|publication, io, trace| {
            let report = run_test_tick(
                publication,
                None,
                io,
                MonotonicMillis(0),
                TickBudgets::default(),
                trace,
            );
            assert!(matches!(
                report.generated_icmpv4,
                PhaseReport::Completed(GeneratedPhaseReport {
                    stop: GeneratedIcmpv4Stop::QueueEmpty,
                    ..
                })
            ));
        });

        with_fixture(|publication, io, trace| {
            seed_icmpv4(publication, 0);
            let report = run_test_tick(
                publication,
                None,
                io,
                MonotonicMillis(0),
                TickBudgets::default(),
                trace,
            );
            assert!(matches!(
                report.generated_icmpv4,
                PhaseReport::Completed(GeneratedPhaseReport {
                    stop: GeneratedIcmpv4Stop::BudgetExhausted { pending: 1 },
                    ..
                })
            ));
        });
    }

    #[test]
    fn production_tick_source_keeps_heap_and_shared_fast_path_types_out() {
        let source = include_str!("lib.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        for forbidden in [
            "V\u{65}c",
            "B\u{6f}x",
            "Str\u{69}ng",
            "A\u{72}c",
            "Mut\u{65}x",
            "dyn Pack\u{65}tIo",
        ] {
            assert!(
                !source.contains(forbidden),
                "production tick source contains forbidden token {forbidden}"
            );
        }
    }
}
