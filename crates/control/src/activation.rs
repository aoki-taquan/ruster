//! Live activation of validated full-service publications.
//!
//! [`FullServiceStorage`] owns every caller-backed runtime slot array. It is
//! allocated once on the cold path from a [`FullServiceStorageShape`] and is
//! exclusively borrowed for `'storage` by one [`ActivePublication`]. The
//! storage therefore outlives every runtime and every tick-local view without
//! self-reference, leaking, or pointer-identity tricks.
//!
//! [`ActivePublication`] owns the current [`ValidatedCandidate`] and the five
//! worker-local runtimes bound to that storage. It implements
//! [`FullServicePublication`], so [`ruster_runtime::run_tick`] drives it
//! directly. A successor is installed only through
//! [`FullServicePublication::publish_candidate`], which requires the packet
//! backend's quiescence guard. The transaction is:
//!
//! 1. [`ValidatedCandidate::validate_successor`] (generation, key rotation,
//!    and the restart-required storage shape and fixed policies);
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
//! A successor cannot be applied without a backend quiescence guard:
//!
//! ```compile_fail
//! use ruster_control::{ActivePublication, ValidatedCandidate};
//!
//! fn apply_without_guard(active: &mut ActivePublication<'_>, next: ValidatedCandidate) {
//!     let _ = active.apply(next);
//! }
//! ```
//!
//! The storage cannot be touched, moved, or dropped while a publication
//! borrows it:
//!
//! ```compile_fail
//! use ruster_control::{ActivePublication, FullServiceStorage, ValidatedCandidate};
//!
//! fn reuse_live_storage(candidate: ValidatedCandidate) {
//!     let mut storage = FullServiceStorage::new(candidate.storage_shape()).unwrap();
//!     let active = ActivePublication::new(&mut storage, candidate).unwrap();
//!     drop(storage);
//!     drop(active);
//! }
//! ```
//!
//! Neither type can be cloned or formatted, so the owned hash keys cannot
//! leak through them:
//!
//! ```compile_fail
//! use ruster_control::ActivePublication;
//!
//! fn require_debug<T: std::fmt::Debug>() {}
//! require_debug::<ActivePublication<'static>>();
//! ```
//!
//! ```compile_fail
//! use ruster_control::FullServiceStorage;
//!
//! fn require_clone<T: Clone>() {}
//! require_clone::<FullServiceStorage>();
//! ```

use std::num::NonZeroU64;

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
use ruster_runtime::{
    FirewallServiceView, FullServicePublication, FullServiceView, Nat44TcpServiceView,
    Nat44UdpServiceView,
};

use crate::{FullServiceStorageShape, RuntimeService, SuccessorError, ValidatedCandidate};

/// Typed, value-free failure to allocate one runtime table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    resolution_states: Box<[ResolutionStateSlot]>,
    resolution_actions: Box<[ResolutionActionSlot]>,
    dynamic_neighbors: Box<[DynamicNeighborSlot]>,
    failure_holds: Box<[ResolutionFailureHoldSlot]>,
    icmpv4_states: Box<[Icmpv4ErrorStateSlot]>,
    icmpv4_actions: Box<[Icmpv4ErrorActionSlot]>,
    udp: NatTables<Nat44UdpMappingSlot, Nat44UdpPeerSlot>,
    tcp: NatTables<Nat44TcpMappingSlot, Nat44TcpSessionSlot>,
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
/// Runtimes are reachable mutably only through that tick-local view. The
/// read-only accessors serve observability and tests.
pub struct ActivePublication<'storage> {
    candidate: ValidatedCandidate,
    resolution: ResolutionRuntime<'storage>,
    icmpv4_errors: Icmpv4ErrorRuntime<'storage>,
    nat44_udp: Nat44UdpRuntime<'storage>,
    nat44_tcp: Nat44TcpRuntime<'storage>,
    firewall: FirewallRuntime<'storage>,
    last_apply: Option<ApplyReport>,
}

impl<'storage> ActivePublication<'storage> {
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
        let FullServiceStorage {
            shape: _,
            resolution_states,
            resolution_actions,
            dynamic_neighbors,
            failure_holds,
            icmpv4_states,
            icmpv4_actions,
            udp,
            tcp,
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
        Ok(Self {
            candidate,
            resolution,
            icmpv4_errors,
            nat44_udp,
            nat44_tcp,
            firewall,
            last_apply: None,
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
        &self.resolution
    }

    #[must_use]
    pub const fn icmpv4_errors(&self) -> &Icmpv4ErrorRuntime<'storage> {
        &self.icmpv4_errors
    }

    #[must_use]
    pub const fn nat44_udp(&self) -> &Nat44UdpRuntime<'storage> {
        &self.nat44_udp
    }

    #[must_use]
    pub const fn nat44_tcp(&self) -> &Nat44TcpRuntime<'storage> {
        &self.nat44_tcp
    }

    #[must_use]
    pub const fn firewall(&self) -> &FirewallRuntime<'storage> {
        &self.firewall
    }

    /// Validates, preflights all five runtimes, then commits at one point.
    ///
    /// `fault` is a test seam evaluated after each stage succeeded and while
    /// that stage's permit (and every earlier one) is still held. Production
    /// passes a closure that never fails, which is inlined away.
    fn apply_with<F>(
        &mut self,
        successor: ValidatedCandidate,
        mut fault: F,
    ) -> Result<ApplyReport, ApplyError>
    where
        F: FnMut(ApplyStage) -> Option<ApplyError>,
    {
        self.candidate.validate_successor(&successor)?;
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
        // `authority` is dead here; moving `successor` ends its borrow.
        let previous = std::mem::replace(&mut self.candidate, successor);
        self.last_apply = Some(report);
        drop(previous);
        Ok(report)
    }
}

impl<'storage, I: PublicationQuiescence> FullServicePublication<'storage, I>
    for ActivePublication<'storage>
{
    type Candidate = ValidatedCandidate;
    type Reject = ApplyError;

    fn publish_candidate(
        &mut self,
        candidate: Self::Candidate,
        _quiescence: I::Guard<'_>,
    ) -> Result<(), Self::Reject> {
        self.apply_with(candidate, |_| None).map(|_| ())
    }

    fn active(&mut self) -> Option<FullServiceView<'_, 'storage>> {
        let authority = self.candidate.authority();
        Some(FullServiceView {
            generation: authority.generation(),
            snapshot: authority.snapshot(),
            resolution: &mut self.resolution,
            icmpv4_errors: &mut self.icmpv4_errors,
            nat44_udp: Nat44UdpServiceView {
                config: authority.nat44_udp_config(),
                runtime: Some(&mut self.nat44_udp),
            },
            nat44_tcp: Nat44TcpServiceView {
                config: authority.nat44_tcp_config(),
                runtime: Some(&mut self.nat44_tcp),
            },
            firewall: FirewallServiceView {
                config: authority.firewall_config(),
                runtime: Some(&mut self.firewall),
            },
        })
    }
}

#[cfg(test)]
mod tests;
