use std::mem::size_of;

use ruster_control::{FullServiceCandidateV1, FullServiceStorageShape};
use ruster_core::{
    DirectoryBucket, DirectoryNode, DynamicNeighborSlot, FirewallStateSlot, Icmpv4ErrorActionSlot,
    Icmpv4ErrorStateSlot, Nat44TcpMappingSlot, Nat44TcpSessionSlot, Nat44UdpMappingSlot,
    Nat44UdpPeerSlot, PortOwnerSlot, ResolutionActionSlot, ResolutionFailureHoldSlot,
    ResolutionStateSlot,
};

/// Cold-path fixed runtime storage could not be allocated coherently.
///
/// This error is deliberately value-free: allocation diagnostics must not echo
/// topology-derived capacities or any authority carried by a candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RuntimeStorageAllocationError {
    /// The allocator could not reserve one of the fixed backing arrays.
    Unavailable,
    /// Exact reservation returned excess capacity, so boxing could reallocate.
    AllocatorCapacityMismatch,
    /// The checked byte total for the 21 backing arrays overflowed `usize`.
    ByteCountOverflow,
    /// Candidate byte metadata does not match its concrete 21-array shape.
    RequiredBytesMismatch,
}

/// Externally owned fixed backing for all five full-service runtimes.
///
/// Every backing array is private so it can only be lent to an activation owner
/// as one coherent set. The storage must outlive the returned publication owner.
/// Public construction is candidate-bound through [`Self::try_for_candidate`],
/// which checks the concrete 21-array byte total before allocating.
///
/// ```compile_fail
/// use ruster_integration::FullServiceRuntimeStorage;
///
/// fn expose(storage: FullServiceRuntimeStorage) {
///     let _ = storage.resolution_states;
/// }
/// ```
///
/// The storage is intentionally not clonable; duplicating empty backing would
/// not duplicate active worker-local state.
///
/// ```compile_fail
/// use ruster_integration::FullServiceRuntimeStorage;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<FullServiceRuntimeStorage>();
/// ```
pub struct FullServiceRuntimeStorage {
    shape: FullServiceStorageShape,
    required_runtime_bytes: usize,
    resolution_states: Box<[ResolutionStateSlot]>,
    resolution_actions: Box<[ResolutionActionSlot]>,
    resolution_dynamic_neighbors: Box<[DynamicNeighborSlot]>,
    resolution_failure_holds: Box<[ResolutionFailureHoldSlot]>,
    icmpv4_error_states: Box<[Icmpv4ErrorStateSlot]>,
    icmpv4_error_actions: Box<[Icmpv4ErrorActionSlot]>,
    nat44_udp_mappings: Box<[Nat44UdpMappingSlot]>,
    nat44_udp_peers: Box<[Nat44UdpPeerSlot]>,
    nat44_udp_mapping_buckets: Box<[DirectoryBucket]>,
    nat44_udp_mapping_nodes: Box<[DirectoryNode]>,
    nat44_udp_peer_buckets: Box<[DirectoryBucket]>,
    nat44_udp_peer_nodes: Box<[DirectoryNode]>,
    nat44_udp_port_owners: Box<[PortOwnerSlot]>,
    nat44_tcp_mappings: Box<[Nat44TcpMappingSlot]>,
    nat44_tcp_sessions: Box<[Nat44TcpSessionSlot]>,
    nat44_tcp_mapping_buckets: Box<[DirectoryBucket]>,
    nat44_tcp_mapping_nodes: Box<[DirectoryNode]>,
    nat44_tcp_session_buckets: Box<[DirectoryBucket]>,
    nat44_tcp_session_nodes: Box<[DirectoryNode]>,
    nat44_tcp_port_owners: Box<[PortOwnerSlot]>,
    firewall_states: Box<[FirewallStateSlot]>,
}

impl FullServiceRuntimeStorage {
    /// Fallibly allocates all backing for one exact full-service candidate.
    ///
    /// The candidate's shape is independently converted into the concrete byte
    /// total of all 21 backing arrays. A mismatch with validated metadata fails
    /// before allocation. Each array is boxed only when its reserved capacity is
    /// exactly its requested length, preventing an infallible shrink/reallocation
    /// from hiding an allocation failure.
    pub fn try_for_candidate(
        candidate: &FullServiceCandidateV1,
    ) -> Result<Self, RuntimeStorageAllocationError> {
        Self::try_for_metadata(
            candidate.storage_shape(),
            candidate.required_runtime_bytes(),
        )
    }

    fn try_for_metadata(
        shape: FullServiceStorageShape,
        reported_required_runtime_bytes: usize,
    ) -> Result<Self, RuntimeStorageAllocationError> {
        let required_runtime_bytes =
            validate_required_runtime_bytes(shape, reported_required_runtime_bytes)?;
        Self::allocate(shape, required_runtime_bytes)
    }

    #[cfg(test)]
    pub(crate) fn try_for_shape(
        shape: FullServiceStorageShape,
    ) -> Result<Self, RuntimeStorageAllocationError> {
        let required_runtime_bytes = checked_required_runtime_bytes(shape)?;
        Self::try_for_metadata(shape, required_runtime_bytes)
    }

    #[cfg(test)]
    fn try_for_reported_bytes(
        shape: FullServiceStorageShape,
        reported_required_runtime_bytes: usize,
    ) -> Result<Self, RuntimeStorageAllocationError> {
        Self::try_for_metadata(shape, reported_required_runtime_bytes)
    }

    fn allocate(
        shape: FullServiceStorageShape,
        required_runtime_bytes: usize,
    ) -> Result<Self, RuntimeStorageAllocationError> {
        let resolution = shape.resolution();
        let icmpv4_errors = shape.icmpv4_errors();
        let nat44_udp = shape.nat44_udp();
        let nat44_tcp = shape.nat44_tcp();

        Ok(Self {
            shape,
            required_runtime_bytes,
            resolution_states: fixed_storage(resolution.state_slots(), ResolutionStateSlot::EMPTY)?,
            resolution_actions: fixed_storage(
                resolution.action_slots(),
                ResolutionActionSlot::EMPTY,
            )?,
            resolution_dynamic_neighbors: fixed_storage(
                resolution.dynamic_neighbor_slots(),
                DynamicNeighborSlot::EMPTY,
            )?,
            resolution_failure_holds: fixed_storage(
                resolution.failure_hold_slots(),
                ResolutionFailureHoldSlot::EMPTY,
            )?,
            icmpv4_error_states: fixed_storage(
                icmpv4_errors.state_slots(),
                Icmpv4ErrorStateSlot::EMPTY,
            )?,
            icmpv4_error_actions: fixed_storage(
                icmpv4_errors.action_slots(),
                Icmpv4ErrorActionSlot::EMPTY,
            )?,
            nat44_udp_mappings: fixed_storage(
                nat44_udp.mapping_slots(),
                Nat44UdpMappingSlot::default(),
            )?,
            nat44_udp_peers: fixed_storage(nat44_udp.peer_slots(), Nat44UdpPeerSlot::default())?,
            nat44_udp_mapping_buckets: fixed_storage(
                nat44_udp.mapping_buckets(),
                DirectoryBucket::default(),
            )?,
            nat44_udp_mapping_nodes: fixed_storage(
                nat44_udp.mapping_nodes(),
                DirectoryNode::default(),
            )?,
            nat44_udp_peer_buckets: fixed_storage(
                nat44_udp.peer_buckets(),
                DirectoryBucket::default(),
            )?,
            nat44_udp_peer_nodes: fixed_storage(nat44_udp.peer_nodes(), DirectoryNode::default())?,
            nat44_udp_port_owners: fixed_storage(
                nat44_udp.port_owner_slots(),
                PortOwnerSlot::default(),
            )?,
            nat44_tcp_mappings: fixed_storage(
                nat44_tcp.mapping_slots(),
                Nat44TcpMappingSlot::default(),
            )?,
            nat44_tcp_sessions: fixed_storage(
                nat44_tcp.session_slots(),
                Nat44TcpSessionSlot::default(),
            )?,
            nat44_tcp_mapping_buckets: fixed_storage(
                nat44_tcp.mapping_buckets(),
                DirectoryBucket::default(),
            )?,
            nat44_tcp_mapping_nodes: fixed_storage(
                nat44_tcp.mapping_nodes(),
                DirectoryNode::default(),
            )?,
            nat44_tcp_session_buckets: fixed_storage(
                nat44_tcp.session_buckets(),
                DirectoryBucket::default(),
            )?,
            nat44_tcp_session_nodes: fixed_storage(
                nat44_tcp.session_nodes(),
                DirectoryNode::default(),
            )?,
            nat44_tcp_port_owners: fixed_storage(
                nat44_tcp.port_owner_slots(),
                PortOwnerSlot::default(),
            )?,
            firewall_states: fixed_storage(
                shape.firewall_state_slots(),
                FirewallStateSlot::default(),
            )?,
        })
    }

    /// Returns the exact candidate shape used for allocation.
    #[must_use]
    pub const fn shape(&self) -> FullServiceStorageShape {
        self.shape
    }

    /// Returns the checked concrete byte total of all backing arrays.
    #[must_use]
    pub const fn required_runtime_bytes(&self) -> usize {
        self.required_runtime_bytes
    }
}

fn checked_required_runtime_bytes(
    shape: FullServiceStorageShape,
) -> Result<usize, RuntimeStorageAllocationError> {
    let resolution = shape.resolution();
    let icmpv4_errors = shape.icmpv4_errors();
    let nat44_udp = shape.nat44_udp();
    let nat44_tcp = shape.nat44_tcp();
    let mut bytes = 0usize;

    add_array_bytes::<ResolutionStateSlot>(&mut bytes, resolution.state_slots())?;
    add_array_bytes::<ResolutionActionSlot>(&mut bytes, resolution.action_slots())?;
    add_array_bytes::<DynamicNeighborSlot>(&mut bytes, resolution.dynamic_neighbor_slots())?;
    add_array_bytes::<ResolutionFailureHoldSlot>(&mut bytes, resolution.failure_hold_slots())?;
    add_array_bytes::<Icmpv4ErrorStateSlot>(&mut bytes, icmpv4_errors.state_slots())?;
    add_array_bytes::<Icmpv4ErrorActionSlot>(&mut bytes, icmpv4_errors.action_slots())?;
    add_array_bytes::<Nat44UdpMappingSlot>(&mut bytes, nat44_udp.mapping_slots())?;
    add_array_bytes::<Nat44UdpPeerSlot>(&mut bytes, nat44_udp.peer_slots())?;
    add_array_bytes::<DirectoryBucket>(&mut bytes, nat44_udp.mapping_buckets())?;
    add_array_bytes::<DirectoryNode>(&mut bytes, nat44_udp.mapping_nodes())?;
    add_array_bytes::<DirectoryBucket>(&mut bytes, nat44_udp.peer_buckets())?;
    add_array_bytes::<DirectoryNode>(&mut bytes, nat44_udp.peer_nodes())?;
    add_array_bytes::<PortOwnerSlot>(&mut bytes, nat44_udp.port_owner_slots())?;
    add_array_bytes::<Nat44TcpMappingSlot>(&mut bytes, nat44_tcp.mapping_slots())?;
    add_array_bytes::<Nat44TcpSessionSlot>(&mut bytes, nat44_tcp.session_slots())?;
    add_array_bytes::<DirectoryBucket>(&mut bytes, nat44_tcp.mapping_buckets())?;
    add_array_bytes::<DirectoryNode>(&mut bytes, nat44_tcp.mapping_nodes())?;
    add_array_bytes::<DirectoryBucket>(&mut bytes, nat44_tcp.session_buckets())?;
    add_array_bytes::<DirectoryNode>(&mut bytes, nat44_tcp.session_nodes())?;
    add_array_bytes::<PortOwnerSlot>(&mut bytes, nat44_tcp.port_owner_slots())?;
    add_array_bytes::<FirewallStateSlot>(&mut bytes, shape.firewall_state_slots())?;

    Ok(bytes)
}

fn validate_required_runtime_bytes(
    shape: FullServiceStorageShape,
    reported: usize,
) -> Result<usize, RuntimeStorageAllocationError> {
    let actual = checked_required_runtime_bytes(shape)?;
    if actual != reported {
        return Err(RuntimeStorageAllocationError::RequiredBytesMismatch);
    }
    Ok(actual)
}

fn add_array_bytes<T>(total: &mut usize, count: u32) -> Result<(), RuntimeStorageAllocationError> {
    let count =
        usize::try_from(count).map_err(|_| RuntimeStorageAllocationError::ByteCountOverflow)?;
    add_bytes(total, size_of::<T>(), count)
}

fn add_bytes(
    total: &mut usize,
    element_size: usize,
    count: usize,
) -> Result<(), RuntimeStorageAllocationError> {
    let bytes = element_size
        .checked_mul(count)
        .ok_or(RuntimeStorageAllocationError::ByteCountOverflow)?;
    *total = total
        .checked_add(bytes)
        .ok_or(RuntimeStorageAllocationError::ByteCountOverflow)?;
    Ok(())
}

fn ensure_exact_capacity(
    capacity: usize,
    count: usize,
) -> Result<(), RuntimeStorageAllocationError> {
    if capacity != count {
        return Err(RuntimeStorageAllocationError::AllocatorCapacityMismatch);
    }
    Ok(())
}

fn fixed_storage<T: Copy>(count: u32, value: T) -> Result<Box<[T]>, RuntimeStorageAllocationError> {
    fixed_storage_with_reservation(count, value, |storage, count| {
        storage
            .try_reserve_exact(count)
            .map_err(|_| RuntimeStorageAllocationError::Unavailable)
    })
}

fn fixed_storage_with_reservation<T: Copy>(
    count: u32,
    value: T,
    reserve: impl FnOnce(&mut Vec<T>, usize) -> Result<(), RuntimeStorageAllocationError>,
) -> Result<Box<[T]>, RuntimeStorageAllocationError> {
    let count = usize::try_from(count).map_err(|_| RuntimeStorageAllocationError::Unavailable)?;
    let mut storage = Vec::new();
    reserve(&mut storage, count)?;
    ensure_exact_capacity(storage.capacity(), count)?;
    storage.resize(count, value);
    Ok(storage.into_boxed_slice())
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NatBackingOccupancy {
    pub(super) udp_mappings: usize,
    pub(super) udp_peers: usize,
    pub(super) udp_mapping_buckets: usize,
    pub(super) udp_mapping_nodes: usize,
    pub(super) udp_peer_buckets: usize,
    pub(super) udp_peer_nodes: usize,
    pub(super) udp_port_owners: usize,
    pub(super) tcp_mappings: usize,
    pub(super) tcp_sessions: usize,
    pub(super) tcp_mapping_buckets: usize,
    pub(super) tcp_mapping_nodes: usize,
    pub(super) tcp_session_buckets: usize,
    pub(super) tcp_session_nodes: usize,
    pub(super) tcp_port_owners: usize,
}

#[cfg(test)]
impl NatBackingOccupancy {
    pub(super) const EMPTY: Self = Self {
        udp_mappings: 0,
        udp_peers: 0,
        udp_mapping_buckets: 0,
        udp_mapping_nodes: 0,
        udp_peer_buckets: 0,
        udp_peer_nodes: 0,
        udp_port_owners: 0,
        tcp_mappings: 0,
        tcp_sessions: 0,
        tcp_mapping_buckets: 0,
        tcp_mapping_nodes: 0,
        tcp_session_buckets: 0,
        tcp_session_nodes: 0,
        tcp_port_owners: 0,
    };
}

#[cfg(test)]
fn non_default_count<T: Default + PartialEq>(storage: &[T]) -> usize {
    let default = T::default();
    storage.iter().filter(|slot| *slot != &default).count()
}

#[cfg(test)]
impl FullServiceRuntimeStorage {
    pub(super) fn pointer_identities(&self) -> [usize; 21] {
        [
            self.resolution_states.as_ptr() as usize,
            self.resolution_actions.as_ptr() as usize,
            self.resolution_dynamic_neighbors.as_ptr() as usize,
            self.resolution_failure_holds.as_ptr() as usize,
            self.icmpv4_error_states.as_ptr() as usize,
            self.icmpv4_error_actions.as_ptr() as usize,
            self.nat44_udp_mappings.as_ptr() as usize,
            self.nat44_udp_peers.as_ptr() as usize,
            self.nat44_udp_mapping_buckets.as_ptr() as usize,
            self.nat44_udp_mapping_nodes.as_ptr() as usize,
            self.nat44_udp_peer_buckets.as_ptr() as usize,
            self.nat44_udp_peer_nodes.as_ptr() as usize,
            self.nat44_udp_port_owners.as_ptr() as usize,
            self.nat44_tcp_mappings.as_ptr() as usize,
            self.nat44_tcp_sessions.as_ptr() as usize,
            self.nat44_tcp_mapping_buckets.as_ptr() as usize,
            self.nat44_tcp_mapping_nodes.as_ptr() as usize,
            self.nat44_tcp_session_buckets.as_ptr() as usize,
            self.nat44_tcp_session_nodes.as_ptr() as usize,
            self.nat44_tcp_port_owners.as_ptr() as usize,
            self.firewall_states.as_ptr() as usize,
        ]
    }

    pub(super) fn nat_backing_occupancy(&self) -> NatBackingOccupancy {
        NatBackingOccupancy {
            udp_mappings: non_default_count(&self.nat44_udp_mappings),
            udp_peers: non_default_count(&self.nat44_udp_peers),
            udp_mapping_buckets: non_default_count(&self.nat44_udp_mapping_buckets),
            udp_mapping_nodes: non_default_count(&self.nat44_udp_mapping_nodes),
            udp_peer_buckets: non_default_count(&self.nat44_udp_peer_buckets),
            udp_peer_nodes: non_default_count(&self.nat44_udp_peer_nodes),
            udp_port_owners: non_default_count(&self.nat44_udp_port_owners),
            tcp_mappings: non_default_count(&self.nat44_tcp_mappings),
            tcp_sessions: non_default_count(&self.nat44_tcp_sessions),
            tcp_mapping_buckets: non_default_count(&self.nat44_tcp_mapping_buckets),
            tcp_mapping_nodes: non_default_count(&self.nat44_tcp_mapping_nodes),
            tcp_session_buckets: non_default_count(&self.nat44_tcp_session_buckets),
            tcp_session_nodes: non_default_count(&self.nat44_tcp_session_nodes),
            tcp_port_owners: non_default_count(&self.nat44_tcp_port_owners),
        }
    }

    pub(super) fn lengths(&self) -> [usize; 21] {
        [
            self.resolution_states.len(),
            self.resolution_actions.len(),
            self.resolution_dynamic_neighbors.len(),
            self.resolution_failure_holds.len(),
            self.icmpv4_error_states.len(),
            self.icmpv4_error_actions.len(),
            self.nat44_udp_mappings.len(),
            self.nat44_udp_peers.len(),
            self.nat44_udp_mapping_buckets.len(),
            self.nat44_udp_mapping_nodes.len(),
            self.nat44_udp_peer_buckets.len(),
            self.nat44_udp_peer_nodes.len(),
            self.nat44_udp_port_owners.len(),
            self.nat44_tcp_mappings.len(),
            self.nat44_tcp_sessions.len(),
            self.nat44_tcp_mapping_buckets.len(),
            self.nat44_tcp_mapping_nodes.len(),
            self.nat44_tcp_session_buckets.len(),
            self.nat44_tcp_session_nodes.len(),
            self.nat44_tcp_port_owners.len(),
            self.firewall_states.len(),
        ]
    }

    pub(super) fn set_required_runtime_bytes_for_test(&mut self, bytes: usize) {
        self.required_runtime_bytes = bytes;
    }
}

pub(super) struct RuntimeStorageSlices<'storage> {
    pub(super) resolution_states: &'storage mut [ResolutionStateSlot],
    pub(super) resolution_actions: &'storage mut [ResolutionActionSlot],
    pub(super) resolution_dynamic_neighbors: &'storage mut [DynamicNeighborSlot],
    pub(super) resolution_failure_holds: &'storage mut [ResolutionFailureHoldSlot],
    pub(super) icmpv4_error_states: &'storage mut [Icmpv4ErrorStateSlot],
    pub(super) icmpv4_error_actions: &'storage mut [Icmpv4ErrorActionSlot],
    pub(super) nat44_udp_mappings: &'storage mut [Nat44UdpMappingSlot],
    pub(super) nat44_udp_peers: &'storage mut [Nat44UdpPeerSlot],
    pub(super) nat44_udp_mapping_buckets: &'storage mut [DirectoryBucket],
    pub(super) nat44_udp_mapping_nodes: &'storage mut [DirectoryNode],
    pub(super) nat44_udp_peer_buckets: &'storage mut [DirectoryBucket],
    pub(super) nat44_udp_peer_nodes: &'storage mut [DirectoryNode],
    pub(super) nat44_udp_port_owners: &'storage mut [PortOwnerSlot],
    pub(super) nat44_tcp_mappings: &'storage mut [Nat44TcpMappingSlot],
    pub(super) nat44_tcp_sessions: &'storage mut [Nat44TcpSessionSlot],
    pub(super) nat44_tcp_mapping_buckets: &'storage mut [DirectoryBucket],
    pub(super) nat44_tcp_mapping_nodes: &'storage mut [DirectoryNode],
    pub(super) nat44_tcp_session_buckets: &'storage mut [DirectoryBucket],
    pub(super) nat44_tcp_session_nodes: &'storage mut [DirectoryNode],
    pub(super) nat44_tcp_port_owners: &'storage mut [PortOwnerSlot],
    pub(super) firewall_states: &'storage mut [FirewallStateSlot],
}

impl FullServiceRuntimeStorage {
    pub(super) fn slices(&mut self) -> RuntimeStorageSlices<'_> {
        RuntimeStorageSlices {
            resolution_states: &mut self.resolution_states,
            resolution_actions: &mut self.resolution_actions,
            resolution_dynamic_neighbors: &mut self.resolution_dynamic_neighbors,
            resolution_failure_holds: &mut self.resolution_failure_holds,
            icmpv4_error_states: &mut self.icmpv4_error_states,
            icmpv4_error_actions: &mut self.icmpv4_error_actions,
            nat44_udp_mappings: &mut self.nat44_udp_mappings,
            nat44_udp_peers: &mut self.nat44_udp_peers,
            nat44_udp_mapping_buckets: &mut self.nat44_udp_mapping_buckets,
            nat44_udp_mapping_nodes: &mut self.nat44_udp_mapping_nodes,
            nat44_udp_peer_buckets: &mut self.nat44_udp_peer_buckets,
            nat44_udp_peer_nodes: &mut self.nat44_udp_peer_nodes,
            nat44_udp_port_owners: &mut self.nat44_udp_port_owners,
            nat44_tcp_mappings: &mut self.nat44_tcp_mappings,
            nat44_tcp_sessions: &mut self.nat44_tcp_sessions,
            nat44_tcp_mapping_buckets: &mut self.nat44_tcp_mapping_buckets,
            nat44_tcp_mapping_nodes: &mut self.nat44_tcp_mapping_nodes,
            nat44_tcp_session_buckets: &mut self.nat44_tcp_session_buckets,
            nat44_tcp_session_nodes: &mut self.nat44_tcp_session_nodes,
            nat44_tcp_port_owners: &mut self.nat44_tcp_port_owners,
            firewall_states: &mut self.firewall_states,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruster_control::{
        Icmpv4ErrorStorageShape, Nat44TcpStoragePlan, Nat44UdpStoragePlan, ResolutionStorageShape,
    };

    fn shape() -> FullServiceStorageShape {
        FullServiceStorageShape::new(
            ResolutionStorageShape::new(2, 3, 4, 5),
            Icmpv4ErrorStorageShape::new(6, 7),
            Nat44UdpStoragePlan::new(3, 9, 4, 3, 16, 9, 13),
            Nat44TcpStoragePlan::new(5, 17, 8, 5, 32, 17, 13),
            11,
        )
    }

    #[test]
    fn candidate_allocation_path_rejects_required_byte_metadata_drift() {
        let shape = shape();
        let actual = checked_required_runtime_bytes(shape).expect("small shape byte total");
        assert!(matches!(
            FullServiceRuntimeStorage::try_for_reported_bytes(shape, actual + 1),
            Err(RuntimeStorageAllocationError::RequiredBytesMismatch)
        ));
    }

    #[test]
    fn checked_byte_accounting_reports_overflow() {
        let mut bytes = usize::MAX;
        assert_eq!(
            add_bytes(&mut bytes, 1, 1),
            Err(RuntimeStorageAllocationError::ByteCountOverflow)
        );
    }

    #[test]
    fn production_boxing_path_rejects_excess_allocator_capacity() {
        let result = fixed_storage_with_reservation(16, 0u8, |storage, count| {
            storage
                .try_reserve_exact(count + 1)
                .map_err(|_| RuntimeStorageAllocationError::Unavailable)
        });
        assert!(matches!(
            result,
            Err(RuntimeStorageAllocationError::AllocatorCapacityMismatch)
        ));
    }

    #[test]
    fn production_boxing_path_accepts_exact_allocator_capacity() {
        let storage = fixed_storage_with_reservation(16, 7u8, |storage, count| {
            storage
                .try_reserve_exact(count)
                .map_err(|_| RuntimeStorageAllocationError::Unavailable)
        })
        .expect("small exact reservation");
        assert_eq!(&*storage, &[7u8; 16]);
    }
}
