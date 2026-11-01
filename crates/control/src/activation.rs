//! Live activation of validated full-service publications.
//!
//! [`FullServiceStorage`] owns every caller-backed runtime slot array. It is
//! allocated once on the cold path from a [`FullServiceStorageShape`] and is
//! exclusively borrowed for `'storage` by one [`ActivePublication`]. The
//! storage therefore outlives every runtime and every tick-local view without
//! self-reference, leaking, or pointer-identity tricks.
//!
//! [`ActivePublication`] owns the current [`ValidatedCandidate`] and the five
//! worker-local runtimes bound to that storage. It is bound to exactly one
//! packet backend type `I` and implements [`FullServicePublication`] only for
//! that backend, so [`ruster_runtime::run_tick`] drives it directly. Both
//! seam methods require a [`PublicationTick`] that only `run_tick` can mint,
//! so they are reachable only from code that `run_tick` calls.
//!
//! Precise guarantee: `FullServicePublication` implementations (adapters,
//! including wrappers around this type) are trusted code, because they
//! receive the token and may forward it. Backend binding is by type only:
//! driving the publication with the same backend instance on every tick is
//! the caller's responsibility, and core's `PublicationQuiescenceGuard::new`
//! is not sealed, so a guard is type discipline, not proof of quiescence.
//! Only `run_tick` itself obtains the guard from the backend's real check.
//!
//! The compile_fail error codes below were verified manually; stable rustdoc
//! (and therefore CI) only enforces that each example fails to compile.
//!
//! The transaction is:
//!
//! 1. [`ValidatedCandidate::validate_successor`] (generation, key rotation,
//!    and the restart-required storage shape, fixed policies, and interface
//!    identities);
//! 2. preflight of all five runtimes, holding all five exclusive permits at
//!    once (resolution, ICMPv4 errors, NAT44 UDP, NAT44 TCP, firewall);
//! 3. one commit point: the five permit commits and the candidate swap. Each
//!    of these is infallible in the core API (slot fills, scalar stores, and
//!    saturating counters only), so no partial application can be observed.
//!
//! A failure at any stage before the commit point drops the already-acquired
//! permits, which leaves every runtime byte unchanged, and keeps the old
//! candidate, snapshot, and generation active.
//!
//! [`ActivePublication::check_successor`] runs stages 1 and 2 without a
//! guard or tick and drops the permits instead of committing them, so a plan
//! can dry-run a successor without changing anything. [`FullServiceStorage`]
//! remembers the highest generation it served, and a re-activation on it must
//! use a strictly higher generation.
//!
//! Outside `run_tick`, neither seam method can be called, because the tick
//! token is a required argument:
//!
//! ```compile_fail,E0061
//! use ruster_control::ActivePublication;
//! use ruster_io_sim::SimIo;
//! use ruster_runtime::FullServicePublication;
//!
//! fn view_outside_tick(active: &mut ActivePublication<'_, SimIo>) {
//!     let _ = FullServicePublication::<SimIo>::active(active);
//! }
//! ```
//!
//! ```compile_fail,E0061
//! use ruster_control::{ActivePublication, ValidatedCandidate};
//! use ruster_core::PublicationQuiescence;
//! use ruster_io_sim::SimIo;
//! use ruster_runtime::FullServicePublication;
//!
//! fn publish_outside_tick(
//!     active: &mut ActivePublication<'_, SimIo>,
//!     io: &mut SimIo,
//!     next: ValidatedCandidate,
//! ) {
//!     let guard = io.try_publication_quiescence().unwrap();
//!     let _ = FullServicePublication::<SimIo>::publish_candidate(active, next, guard);
//! }
//! ```
//!
//! and the token cannot be forged:
//!
//! ```compile_fail,E0451
//! use ruster_control::ActivePublication;
//! use ruster_io_sim::SimIo;
//! use ruster_runtime::{FullServicePublication, PublicationTick};
//!
//! fn forge(active: &mut ActivePublication<'_, SimIo>) {
//!     let tick = PublicationTick { _tick: std::marker::PhantomData };
//!     let _ = FullServicePublication::<SimIo>::active(active, &tick);
//! }
//! ```
//!
//! A publication bound to one backend type cannot be driven through the seam
//! of another backend type:
//!
//! ```compile_fail,E0277
//! use ruster_control::ActivePublication;
//! use ruster_core::{
//!     PublicationQuiescence, PublicationQuiescenceDisposition, PublicationQuiescenceGuard,
//! };
//! use ruster_io_sim::SimIo;
//! use ruster_runtime::FullServicePublication;
//!
//! struct AlwaysQuiet;
//!
//! impl PublicationQuiescence for AlwaysQuiet {
//!     type Error = ();
//!     type Guard<'backend> = PublicationQuiescenceGuard<'backend, Self>;
//!
//!     fn try_publication_quiescence(&mut self) -> Result<Self::Guard<'_>, ()> {
//!         Ok(PublicationQuiescenceGuard::new(self))
//!     }
//!
//!     fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
//!         PublicationQuiescenceDisposition::ContinueOldIo
//!     }
//! }
//!
//! fn require_seam<P: FullServicePublication<'static, AlwaysQuiet>>() {}
//! require_seam::<ActivePublication<'static, SimIo>>();
//! ```
//!
//! The storage cannot be touched, moved, or dropped while a publication
//! borrows it:
//!
//! ```compile_fail,E0505
//! use ruster_control::{ActivePublication, FullServiceStorage, ValidatedCandidate};
//! use ruster_io_sim::SimIo;
//!
//! fn reuse_live_storage(candidate: ValidatedCandidate) {
//!     let mut storage = FullServiceStorage::new(candidate.storage_shape()).unwrap();
//!     let active = ActivePublication::<SimIo>::new(&mut storage, candidate).unwrap();
//!     drop(storage);
//!     drop(active);
//! }
//! ```
//!
//! Neither type can be formatted or cloned, so owned hash keys and runtime
//! state cannot leak or be duplicated through them:
//!
//! ```compile_fail,E0277
//! use ruster_control::ActivePublication;
//! use ruster_io_sim::SimIo;
//!
//! fn require_debug<T: std::fmt::Debug>() {}
//! require_debug::<ActivePublication<'static, SimIo>>();
//! ```
//!
//! ```compile_fail,E0277
//! use ruster_control::ActivePublication;
//! use ruster_io_sim::SimIo;
//!
//! fn require_clone<T: Clone>() {}
//! require_clone::<ActivePublication<'static, SimIo>>();
//! ```
//!
//! ```compile_fail,E0277
//! use ruster_control::FullServiceStorage;
//!
//! fn require_debug<T: std::fmt::Debug>() {}
//! require_debug::<FullServiceStorage>();
//! ```
//!
//! ```compile_fail,E0277
//! use ruster_control::FullServiceStorage;
//!
//! fn require_clone<T: Clone>() {}
//! require_clone::<FullServiceStorage>();
//! ```

use std::{marker::PhantomData, num::NonZeroU64};

use ruster_core::{
    DirectoryBucket, DirectoryNode, DynamicNeighborSlot, FirewallReconcileError,
    FirewallReconcileReport, FirewallRuntime, FirewallStateSlot, Icmpv4ErrorActionSlot,
    Icmpv4ErrorPublicationError, Icmpv4ErrorPublicationReport, Icmpv4ErrorRuntime,
    Icmpv4ErrorStateSlot, Nat44TcpIndexStorage, Nat44TcpMappingSlot, Nat44TcpReconcileError,
    Nat44TcpReconcileReport, Nat44TcpRuntime, Nat44TcpRuntimeConfigError, Nat44TcpSessionSlot,
    Nat44UdpIndexStorage, Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpReconcileError,
    Nat44UdpReconcileReport, Nat44UdpRuntime, Nat44UdpRuntimeConfigError, PortOwnerSlot,
    PublicationQuiescence, ResolutionActionSlot, ResolutionFailureHoldSlot,
    ResolutionPublicationError, ResolutionPublicationReport, ResolutionRuntime,
    ResolutionStateSlot,
};
use ruster_core::{
    FirewallReconcilePermit, Icmpv4ErrorPublicationPermit, Nat44TcpReconcilePermit,
    Nat44UdpReconcilePermit, ResolutionPublicationPermit,
};
use ruster_runtime::{
    FirewallServiceView, FullServicePublication, FullServiceView, Nat44TcpServiceView,
    Nat44UdpServiceView, PublicationTick,
};

use crate::{
    plan::{FlushCount, StateFlush, SuccessorCheck},
    FullServiceStorageShape, RuntimeService, SuccessorError, ValidatedCandidate,
};

/// Typed, value-free failure to allocate one runtime table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct StorageAllocationError {
    pub service: RuntimeService,
}

/// Owned caller-backed slot arrays for all five full-service runtimes.
///
/// Every array is sized exactly from one [`FullServiceStorageShape`] and is
/// allocated once on the cold path. Capacity is fixed for the lifetime of the
/// storage: a successor with another shape is restart-required, never
/// resized.
pub struct FullServiceStorage {
    shape: FullServiceStorageShape,
    /// Highest generation ever activated or applied on this storage.
    generation_floor: Option<NonZeroU64>,
    resolution_states: Box<[ResolutionStateSlot]>,
    resolution_actions: Box<[ResolutionActionSlot]>,
    dynamic_neighbors: Box<[DynamicNeighborSlot]>,
    failure_holds: Box<[ResolutionFailureHoldSlot]>,
    icmpv4_states: Box<[Icmpv4ErrorStateSlot]>,
    icmpv4_actions: Box<[Icmpv4ErrorActionSlot]>,
    udp: NatTables<Nat44UdpMappingSlot, Nat44UdpPeerSlot>,
    tcp: NatTables<Nat44TcpMappingSlot, Nat44TcpSessionSlot>,
    /// TCP session remote-address directory, sized like the session
    /// directory (address-dependent filtering).
    tcp_session_address_buckets: Box<[DirectoryBucket]>,
    tcp_session_address_nodes: Box<[DirectoryNode]>,
    firewall_states: Box<[FirewallStateSlot]>,
}

/// Mapping, secondary-state, directory, and port-owner arrays of one NAT
/// runtime. UDP secondary state is peers; TCP secondary state is sessions.
struct NatTables<M, S> {
    mappings: Box<[M]>,
    secondary: Box<[S]>,
    mapping_buckets: Box<[DirectoryBucket]>,
    mapping_nodes: Box<[DirectoryNode]>,
    secondary_buckets: Box<[DirectoryBucket]>,
    secondary_nodes: Box<[DirectoryNode]>,
    port_owners: Box<[PortOwnerSlot]>,
}

impl FullServiceStorage {
    /// Allocates every runtime table exactly once for `shape`.
    ///
    /// Allocation failure is reported per service instead of aborting.
    pub fn new(shape: FullServiceStorageShape) -> Result<Self, StorageAllocationError> {
        use RuntimeService::{Firewall, Icmpv4Errors, Nat44Tcp, Nat44Udp, Resolution};
        let resolution = shape.resolution();
        let icmpv4 = shape.icmpv4_errors();
        let udp = shape.nat44_udp();
        let tcp = shape.nat44_tcp();
        Ok(Self {
            shape,
            generation_floor: None,
            resolution_states: slots(
                resolution.state_slots(),
                ResolutionStateSlot::EMPTY,
                Resolution,
            )?,
            resolution_actions: slots(
                resolution.action_slots(),
                ResolutionActionSlot::EMPTY,
                Resolution,
            )?,
            dynamic_neighbors: slots(
                resolution.dynamic_neighbor_slots(),
                DynamicNeighborSlot::EMPTY,
                Resolution,
            )?,
            failure_holds: slots(
                resolution.failure_hold_slots(),
                ResolutionFailureHoldSlot::EMPTY,
                Resolution,
            )?,
            icmpv4_states: slots(
                icmpv4.state_slots(),
                Icmpv4ErrorStateSlot::EMPTY,
                Icmpv4Errors,
            )?,
            icmpv4_actions: slots(
                icmpv4.action_slots(),
                Icmpv4ErrorActionSlot::EMPTY,
                Icmpv4Errors,
            )?,
            udp: NatTables::new(
                [
                    udp.mapping_slots(),
                    udp.peer_slots(),
                    udp.mapping_buckets(),
                    udp.mapping_nodes(),
                    udp.peer_buckets(),
                    udp.peer_nodes(),
                    udp.port_owner_slots(),
                ],
                Nat44Udp,
            )?,
            tcp: NatTables::new(
                [
                    tcp.mapping_slots(),
                    tcp.session_slots(),
                    tcp.mapping_buckets(),
                    tcp.mapping_nodes(),
                    tcp.session_buckets(),
                    tcp.session_nodes(),
                    tcp.port_owner_slots(),
                ],
                Nat44Tcp,
            )?,
            tcp_session_address_buckets: slots(
                tcp.session_buckets(),
                DirectoryBucket::default(),
                Nat44Tcp,
            )?,
            tcp_session_address_nodes: slots(
                tcp.session_nodes(),
                DirectoryNode::default(),
                Nat44Tcp,
            )?,
            firewall_states: slots(
                shape.firewall_state_slots(),
                FirewallStateSlot::default(),
                Firewall,
            )?,
        })
    }

    #[must_use]
    pub const fn shape(&self) -> FullServiceStorageShape {
        self.shape
    }

    /// Highest generation ever activated or applied on this storage. A new
    /// [`ActivePublication`] on this storage must use a strictly higher one.
    #[must_use]
    pub const fn generation_floor(&self) -> Option<NonZeroU64> {
        self.generation_floor
    }
}

impl<M: Copy + Default, S: Copy + Default> NatTables<M, S> {
    fn new(counts: [u32; 7], service: RuntimeService) -> Result<Self, StorageAllocationError> {
        let [mappings, secondary, mapping_buckets, mapping_nodes, secondary_buckets, secondary_nodes, port_owners] =
            counts;
        Ok(Self {
            mappings: slots(mappings, M::default(), service)?,
            secondary: slots(secondary, S::default(), service)?,
            mapping_buckets: slots(mapping_buckets, DirectoryBucket::default(), service)?,
            mapping_nodes: slots(mapping_nodes, DirectoryNode::default(), service)?,
            secondary_buckets: slots(secondary_buckets, DirectoryBucket::default(), service)?,
            secondary_nodes: slots(secondary_nodes, DirectoryNode::default(), service)?,
            port_owners: slots(port_owners, PortOwnerSlot::default(), service)?,
        })
    }
}

fn slots<T: Copy>(
    count: u32,
    empty: T,
    service: RuntimeService,
) -> Result<Box<[T]>, StorageAllocationError> {
    let error = StorageAllocationError { service };
    let count = usize::try_from(count).map_err(|_| error)?;
    let mut table = Vec::new();
    table.try_reserve_exact(count).map_err(|_| error)?;
    table.resize(count, empty);
    Ok(table.into_boxed_slice())
}

/// Typed, value-free failure to activate the first publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ActivationError {
    /// The storage was allocated for a different shape than the candidate.
    StorageShapeMismatch,
    /// The candidate generation is not above every generation this storage
    /// has already served, so a drop and re-activation cannot go back.
    GenerationNotAboveFloor,
    Nat44Udp(Nat44UdpRuntimeConfigError),
    Nat44Tcp(Nat44TcpRuntimeConfigError),
}

/// Successor change that live activation cannot apply in place.
///
/// The fixed runtime storage and the fixed resolution/ICMPv4 policies are
/// bound when storage and runtimes are created. Changing them requires
/// dropping the active publication and activating new storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RestartRequired {
    StorageShape,
    ResolutionPolicy,
    Icmpv4ErrorPolicy,
    /// An interface IfId was added/removed or its MAC address changed.
    Interfaces,
}

impl RestartRequired {
    /// Stable SCREAMING_SNAKE_CASE code for machine-readable output.
    ///
    /// Exhaustive, so a new variant fails to compile until it has a code.
    /// Nested detail is collapsed to the outer variant.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StorageShape => "STORAGE_SHAPE",
            Self::ResolutionPolicy => "RESOLUTION_POLICY",
            Self::Icmpv4ErrorPolicy => "ICMPV4_ERROR_POLICY",
            Self::Interfaces => "INTERFACES",
        }
    }
}

/// Typed, value-free reason a successor was rejected.
///
/// Every variant guarantees that the old candidate, snapshot, generation, and
/// all five runtimes are unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ApplyError {
    RestartRequired(RestartRequired),
    Successor(SuccessorError),
    Resolution(ResolutionPublicationError),
    Icmpv4Errors(Icmpv4ErrorPublicationError),
    Nat44Udp(Nat44UdpReconcileError),
    Nat44Tcp(Nat44TcpReconcileError),
    Firewall(FirewallReconcileError),
}

impl From<SuccessorError> for ApplyError {
    fn from(error: SuccessorError) -> Self {
        match error {
            SuccessorError::StorageShapeChanged => {
                Self::RestartRequired(RestartRequired::StorageShape)
            }
            SuccessorError::ResolutionPolicyChanged => {
                Self::RestartRequired(RestartRequired::ResolutionPolicy)
            }
            SuccessorError::Icmpv4ErrorPolicyChanged => {
                Self::RestartRequired(RestartRequired::Icmpv4ErrorPolicy)
            }
            SuccessorError::InterfacesChanged => Self::RestartRequired(RestartRequired::Interfaces),
            SuccessorError::GenerationExhausted
            | SuccessorError::GenerationNotIncreasing
            | SuccessorError::Nat44UdpHashKeyReused
            | SuccessorError::Nat44TcpHashKeyReused
            | SuccessorError::FirewallHashKeyReused => Self::Successor(error),
        }
    }
}

/// What one committed successor flushed in each runtime.
///
/// Every runtime flushes publication-bound state on a new generation:
/// resolution states/actions/learned neighbors/failure holds, the ICMPv4
/// error limiter and queue, and all NAT44 UDP/TCP and firewall flow state
/// (their hash keys rotate). Cumulative counters are preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ApplyReport {
    pub previous_generation: NonZeroU64,
    pub generation: NonZeroU64,
    pub resolution: ResolutionPublicationReport,
    pub icmpv4_errors: Icmpv4ErrorPublicationReport,
    pub nat44_udp: Nat44UdpReconcileReport,
    pub nat44_tcp: Nat44TcpReconcileReport,
    pub firewall: FirewallReconcileReport,
}

/// Transaction stage, used only to inject failures in tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
enum ApplyStage {
    Successor,
    Resolution,
    Icmpv4Errors,
    Nat44Udp,
    Nat44Tcp,
    Firewall,
}

/// The current validated candidate and its five live runtimes.
///
/// The steady [`FullServicePublication::active`] borrow is O(1): it copies the
/// candidate's precomputed snapshot and configs and reborrows the runtimes,
/// without validation, hashing, scans, or allocation.
///
/// Runtimes are reachable mutably only through that tick-local view, whose
/// runtime borrows are private to `run_tick`. The read-only accessors serve
/// observability and tests. `I` is the one packet backend whose quiescence
/// guards may publish a successor.
pub struct ActivePublication<'storage, I> {
    candidate: ValidatedCandidate,
    runtimes: LiveRuntimes<'storage>,
    generation_floor: &'storage mut Option<NonZeroU64>,
    last_apply: Option<ApplyReport>,
    backend: PhantomData<fn(I) -> I>,
}

/// The five runtimes bound to one storage.
struct LiveRuntimes<'storage> {
    resolution: ResolutionRuntime<'storage>,
    icmpv4_errors: Icmpv4ErrorRuntime<'storage>,
    nat44_udp: Nat44UdpRuntime<'storage>,
    nat44_tcp: Nat44TcpRuntime<'storage>,
    firewall: FirewallRuntime<'storage>,
}

/// All five exclusive permits of one successor, held at once.
struct Permits<'runtime, 'storage> {
    resolution: ResolutionPublicationPermit<'runtime, 'storage>,
    icmpv4_errors: Icmpv4ErrorPublicationPermit<'runtime, 'storage>,
    nat44_udp: Nat44UdpReconcilePermit<'runtime, 'storage>,
    nat44_tcp: Nat44TcpReconcilePermit<'runtime, 'storage>,
    firewall: FirewallReconcilePermit<'runtime, 'storage>,
}

impl<'storage> LiveRuntimes<'storage> {
    /// Validates `successor` against `current` and preflights all five
    /// runtimes. Preflight never mutates; dropping the permits leaves every
    /// runtime unchanged.
    ///
    /// `fault` is a test seam evaluated after each stage succeeded and while
    /// that stage's permit (and every earlier one) is still held.
    fn preflight<'runtime, F>(
        &'runtime mut self,
        current: &ValidatedCandidate,
        successor: &ValidatedCandidate,
        fault: &mut F,
    ) -> Result<Permits<'runtime, 'storage>, ApplyError>
    where
        F: FnMut(ApplyStage) -> Option<ApplyError>,
    {
        current.validate_successor(successor)?;
        if let Some(error) = fault(ApplyStage::Successor) {
            return Err(error);
        }
        let authority = successor.authority();
        let resolution = self
            .resolution
            .preflight_publication()
            .map_err(ApplyError::Resolution)?;
        if let Some(error) = fault(ApplyStage::Resolution) {
            return Err(error);
        }
        let icmpv4_errors = self
            .icmpv4_errors
            .preflight_publication()
            .map_err(ApplyError::Icmpv4Errors)?;
        if let Some(error) = fault(ApplyStage::Icmpv4Errors) {
            return Err(error);
        }
        let nat44_udp = self
            .nat44_udp
            .preflight_reconcile(authority.nat44_udp_config(), authority.nat44_udp_hash_key())
            .map_err(ApplyError::Nat44Udp)?;
        if let Some(error) = fault(ApplyStage::Nat44Udp) {
            return Err(error);
        }
        let nat44_tcp = self
            .nat44_tcp
            .preflight_reconcile(authority.nat44_tcp_config(), authority.nat44_tcp_hash_key())
            .map_err(ApplyError::Nat44Tcp)?;
        if let Some(error) = fault(ApplyStage::Nat44Tcp) {
            return Err(error);
        }
        let firewall = self
            .firewall
            .preflight_reconcile(authority.firewall_config())
            .map_err(ApplyError::Firewall)?;
        if let Some(error) = fault(ApplyStage::Firewall) {
            return Err(error);
        }
        Ok(Permits {
            resolution,
            icmpv4_errors,
            nat44_udp,
            nat44_tcp,
            firewall,
        })
    }

    /// Live counts of the state a commit would flush, read without mutation.
    /// The ICMPv4 limiter state count has no read accessor in core.
    fn flush_counts(&self) -> StateFlush {
        let count = |occupied: usize| FlushCount::Exact(occupied);
        let resolution = &self.resolution;
        StateFlush {
            resolution_states: count(resolution.pending_states()),
            resolution_actions: count(resolution.pending_actions()),
            dynamic_neighbors: count(resolution.dynamic_neighbor_count()),
            failure_holds: count(resolution.pending_failure_holds()),
            icmpv4_error_states: FlushCount::All,
            icmpv4_error_actions: count(self.icmpv4_errors.pending_actions()),
            nat44_udp_mappings: count(occupied(self.nat44_udp.mappings(), |slot| {
                slot.is_occupied()
            })),
            nat44_udp_peers: count(occupied(self.nat44_udp.peers(), |slot| slot.is_occupied())),
            nat44_tcp_mappings: count(occupied(self.nat44_tcp.mappings(), |slot| {
                slot.is_occupied()
            })),
            nat44_tcp_sessions: count(occupied(self.nat44_tcp.sessions(), |slot| {
                slot.is_occupied()
            })),
            firewall_flows: count(occupied(self.firewall.states(), |slot| slot.is_occupied())),
        }
    }
}

fn occupied<T: Copy>(slots: &[T], is_occupied: impl Fn(T) -> bool) -> usize {
    slots.iter().filter(|slot| is_occupied(**slot)).count()
}

impl<'storage, I: PublicationQuiescence> ActivePublication<'storage, I> {
    /// Builds pristine runtimes in `storage` and activates `candidate`.
    ///
    /// The storage must have been allocated for exactly the candidate's
    /// storage shape. Runtime constructors clear every borrowed slot.
    pub fn new(
        storage: &'storage mut FullServiceStorage,
        candidate: ValidatedCandidate,
    ) -> Result<Self, ActivationError> {
        if storage.shape != candidate.storage_shape() {
            return Err(ActivationError::StorageShapeMismatch);
        }
        if storage
            .generation_floor
            .is_some_and(|floor| candidate.generation() <= floor)
        {
            return Err(ActivationError::GenerationNotAboveFloor);
        }
        let FullServiceStorage {
            shape: _,
            generation_floor,
            resolution_states,
            resolution_actions,
            dynamic_neighbors,
            failure_holds,
            icmpv4_states,
            icmpv4_actions,
            udp,
            tcp,
            tcp_session_address_buckets,
            tcp_session_address_nodes,
            firewall_states,
        } = storage;
        let authority = candidate.authority();
        let nat44_udp = Nat44UdpRuntime::new(
            authority.nat44_udp_config(),
            &mut udp.mappings,
            &mut udp.secondary,
            Nat44UdpIndexStorage::new(
                &mut udp.mapping_buckets,
                &mut udp.mapping_nodes,
                &mut udp.secondary_buckets,
                &mut udp.secondary_nodes,
                &mut udp.port_owners,
            ),
            authority.nat44_udp_hash_key(),
        )
        .map_err(ActivationError::Nat44Udp)?;
        let nat44_tcp = Nat44TcpRuntime::new(
            authority.nat44_tcp_config(),
            &mut tcp.mappings,
            &mut tcp.secondary,
            Nat44TcpIndexStorage::new(
                &mut tcp.mapping_buckets,
                &mut tcp.mapping_nodes,
                &mut tcp.secondary_buckets,
                &mut tcp.secondary_nodes,
                tcp_session_address_buckets,
                tcp_session_address_nodes,
                &mut tcp.port_owners,
            ),
            authority.nat44_tcp_hash_key(),
        )
        .map_err(ActivationError::Nat44Tcp)?;
        let resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            authority.resolution_policy(),
            resolution_states,
            resolution_actions,
            dynamic_neighbors,
            failure_holds,
        );
        let icmpv4_errors = Icmpv4ErrorRuntime::new(
            authority.icmpv4_error_policy(),
            icmpv4_states,
            icmpv4_actions,
        );
        let firewall = FirewallRuntime::new(authority.firewall_config(), firewall_states);
        *generation_floor = Some(candidate.generation());
        Ok(Self {
            candidate,
            runtimes: LiveRuntimes {
                resolution,
                icmpv4_errors,
                nat44_udp,
                nat44_tcp,
                firewall,
            },
            generation_floor,
            last_apply: None,
            backend: PhantomData,
        })
    }

    #[must_use]
    pub const fn generation(&self) -> NonZeroU64 {
        self.candidate.generation()
    }

    #[must_use]
    pub const fn storage_shape(&self) -> FullServiceStorageShape {
        self.candidate.storage_shape()
    }

    /// Report of the most recent committed successor, if any.
    #[must_use]
    pub const fn last_apply(&self) -> Option<ApplyReport> {
        self.last_apply
    }

    #[must_use]
    pub const fn resolution(&self) -> &ResolutionRuntime<'storage> {
        &self.runtimes.resolution
    }

    #[must_use]
    pub const fn icmpv4_errors(&self) -> &Icmpv4ErrorRuntime<'storage> {
        &self.runtimes.icmpv4_errors
    }

    #[must_use]
    pub const fn nat44_udp(&self) -> &Nat44UdpRuntime<'storage> {
        &self.runtimes.nat44_udp
    }

    #[must_use]
    pub const fn nat44_tcp(&self) -> &Nat44TcpRuntime<'storage> {
        &self.runtimes.nat44_tcp
    }

    #[must_use]
    pub const fn firewall(&self) -> &FirewallRuntime<'storage> {
        &self.runtimes.firewall
    }

    /// Guard-free dry-run of `successor` against this publication.
    ///
    /// Runs exactly the checks of an apply (successor validation, including
    /// the restart-required classification, and all five runtime preflights)
    /// and then drops the permits, so nothing is committed: generation,
    /// candidate, slots, counters, and bindings are unchanged. It takes no
    /// quiescence guard or tick because it publishes nothing; the exclusive
    /// borrow only reflects that core preflight hands out exclusive permits.
    pub fn check_successor(
        &mut self,
        successor: &ValidatedCandidate,
    ) -> Result<SuccessorCheck, ApplyError> {
        let flush = self.runtimes.flush_counts();
        // The permits are discarded at the end of this statement without a
        // commit, which leaves every runtime unchanged.
        let preview = self
            .runtimes
            .preflight(&self.candidate, successor, &mut |_| None)?
            .resolution
            .preview();
        Ok(SuccessorCheck {
            previous_generation: self.candidate.generation(),
            generation: successor.generation(),
            flush: StateFlush {
                resolution_states: FlushCount::Exact(preview.states_flushed),
                resolution_actions: FlushCount::Exact(preview.actions_flushed),
                dynamic_neighbors: FlushCount::Exact(preview.dynamic_neighbors_flushed),
                failure_holds: FlushCount::Exact(preview.failure_holds_flushed),
                ..flush
            },
        })
    }

    /// Validates, preflights all five runtimes, then commits at one point.
    ///
    /// `fault` is a test seam (see [`LiveRuntimes::preflight`]). Production
    /// passes a closure that never fails, which is inlined away.
    fn apply_with<F>(
        &mut self,
        successor: ValidatedCandidate,
        mut fault: F,
    ) -> Result<ApplyReport, ApplyError>
    where
        F: FnMut(ApplyStage) -> Option<ApplyError>,
    {
        let Permits {
            resolution,
            icmpv4_errors,
            nat44_udp,
            nat44_tcp,
            firewall,
        } = self
            .runtimes
            .preflight(&self.candidate, &successor, &mut fault)?;

        // Commit point. Nothing below can fail: every permit commit is a
        // total core operation, the permits retain no borrow of `successor`,
        // and the boxed forwarding/firewall owners keep their addresses when
        // the candidate is moved into place, so the firewall binding stays
        // equal to the moved candidate's config.
        let report = ApplyReport {
            previous_generation: self.candidate.generation(),
            generation: successor.generation(),
            resolution: resolution.commit(),
            icmpv4_errors: icmpv4_errors.commit(),
            nat44_udp: nat44_udp.commit(),
            nat44_tcp: nat44_tcp.commit(),
            firewall: firewall.commit(),
        };
        // No permit borrows `successor`, so it can move into place.
        let previous = std::mem::replace(&mut self.candidate, successor);
        *self.generation_floor = Some(report.generation);
        self.last_apply = Some(report);
        drop(previous);
        Ok(report)
    }
}

impl<'storage, I: PublicationQuiescence> FullServicePublication<'storage, I>
    for ActivePublication<'storage, I>
{
    type Candidate = ValidatedCandidate;
    type Reject = ApplyError;

    fn publish_candidate(
        &mut self,
        candidate: Self::Candidate,
        _quiescence: I::Guard<'_>,
        _tick: &PublicationTick<'_>,
    ) -> Result<(), Self::Reject> {
        self.apply_with(candidate, |_| None).map(|_| ())
    }

    fn active(&mut self, _tick: &PublicationTick<'_>) -> Option<FullServiceView<'_, 'storage>> {
        let authority = self.candidate.authority();
        Some(FullServiceView::new(
            authority.generation(),
            authority.snapshot(),
            &mut self.runtimes.resolution,
            &mut self.runtimes.icmpv4_errors,
            Nat44UdpServiceView::new(
                authority.nat44_udp_config(),
                Some(&mut self.runtimes.nat44_udp),
            ),
            Nat44TcpServiceView::new(
                authority.nat44_tcp_config(),
                Some(&mut self.runtimes.nat44_tcp),
            ),
            FirewallServiceView::new(
                authority.firewall_config(),
                Some(&mut self.runtimes.firewall),
            ),
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests;
