//! Publication-time lookup indexes over one forwarding snapshot (PERF-002).
//!
//! [`ForwardingIndex`] is built by [`crate::ValidatedForwardingOwner`] on the
//! cold publication path (allocation allowed there) and is never mutated
//! afterwards. The routes come as a [`crate::Ipv4Routes`], which a new owner
//! may share with the one before it; the indexes of the other tables are
//! built from the boxed tables the owner validates.
//!
//! - Route LPM: the route tree read one byte of the destination at a time,
//!   at most four nodes whatever the number of routes.
//! - What is asked of the routes as a whole (connected network and
//!   directed-broadcast addresses, gateway next hops, on-link senders for
//!   ARP learning, ARP-031): ordered sets that [`crate::Ipv4Routes`] keeps
//!   up to date as routes are set and taken out.
//! - Exact keys of the other tables (interface by id, local address by
//!   address and by interface, static neighbor by `(interface, target)`):
//!   sorted arrays searched by binary search. Keys come from validated
//!   configuration, not from packets, so a hash table would gain nothing
//!   against an attacker and would need a secret to stay bounded; a sorted
//!   array is deterministic, has no worst case beyond `ceil(log2(n + 1))`
//!   probes, and needs no per-publication key.
//!
//! The linear functions at the bottom of this file are the reference
//! semantics. They remain the implementation for snapshots borrowed with
//! [`crate::ForwardingSnapshot::new`] (no owner to hold an index), and the
//! differential tests compare both on random tables.
//!
//! Equivalence with the linear reference, including ties: the reference
//! LPM is `filter(matches).max_by_key(prefix_len)`, and `max_by_key`
//! returns the *last* maximal element. Snapshot validation rejects two
//! routes with the same prefix and length, and two matching routes of the
//! same length necessarily have the same prefix (`address & mask`), so a
//! validated table never has a tie. The builder still reproduces the
//! last-wins rule for unvalidated input: it sets the routes in slice order,
//! and a route set again takes the place of the one before. Exact-key
//! lookups return the first element in slice order, like the reference
//! `find`.

use crate::{IfId, Interface, Ipv4Address, LocalIpv4Binding, Neighbor, Route};

/// Immutable lookup indexes for one validated forwarding owner.
pub(crate) struct ForwardingIndex {
    /// The routes, and what the packet path asks of them as a whole.
    routes: crate::Ipv4Routes,
    /// `(interface id, slice index)` sorted by id.
    interfaces: Box<[(u16, u32)]>,
    /// `(address, slice index)` sorted by address.
    locals_by_address: Box<[(u32, u32)]>,
    /// `(interface id, slice index)` sorted by interface.
    locals_by_interface: Box<[(u16, u32)]>,
    /// `(interface << 32 | target, slice index)` sorted by key.
    neighbors: Box<[(u64, u32)]>,
    /// The input firewall rules split by ingress and protocol class
    /// (INPUT-FW), set by [`crate::ValidatedForwardingOwner::with_input_firewall`].
    input_firewall: crate::firewall::InputFirewallIndex,
}

impl std::fmt::Debug for ForwardingIndex {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ForwardingIndex")
            .field("routes", &self.routes.len())
            .field("heap_bytes", &self.heap_bytes())
            .finish_non_exhaustive()
    }
}

const fn key(interface: IfId, address: Ipv4Address) -> u64 {
    ((interface.0 as u64) << 32) | address_bits(address) as u64
}

const fn address_bits(address: Ipv4Address) -> u32 {
    u32::from_be_bytes(address.octets())
}

fn slot(index: usize) -> u32 {
    u32::try_from(index).expect("forwarding tables are far below u32::MAX entries")
}

/// Index of the first element for which `before` is false, and the number
/// of elements compared. At most `ceil(log2(items.len() + 1))` probes.
#[inline]
fn partition<T>(items: &[T], mut before: impl FnMut(&T) -> bool) -> (usize, u32) {
    let mut low = 0;
    let mut len = items.len();
    let mut probes = 0;
    while len > 0 {
        let half = len / 2;
        probes += 1;
        if before(&items[low + half]) {
            low += half + 1;
            len -= half + 1;
        } else {
            len = half;
        }
    }
    (low, probes)
}

#[inline]
fn exact<K: Ord + Copy>(items: &[(K, u32)], wanted: K) -> (Option<usize>, u32) {
    let (position, probes) = partition(items, |(candidate, _)| *candidate < wanted);
    let found = items
        .get(position)
        .filter(|(candidate, _)| *candidate == wanted)
        .map(|(_, index)| *index as usize);
    (found, probes)
}

impl ForwardingIndex {
    /// Builds every index from a list of routes. Of two routes with the same
    /// prefix and length the later one stays, like the reference
    /// `max_by_key`. Cold path: allocates and sorts, `O(n log n)`.
    pub(crate) fn build(
        routes: &[Route],
        interfaces: &[Interface],
        neighbors: &[Neighbor],
        local_ipv4: &[LocalIpv4Binding],
    ) -> Self {
        let routes = routes.iter().copied().collect();
        Self::with_routes(routes, interfaces, neighbors, local_ipv4)
    }

    /// Builds the indexes of the other tables around `routes`, which is
    /// taken as it is: nothing here grows with the number of routes.
    pub(crate) fn with_routes(
        routes: crate::Ipv4Routes,
        interfaces: &[Interface],
        neighbors: &[Neighbor],
        local_ipv4: &[LocalIpv4Binding],
    ) -> Self {
        let mut interface_keys: Vec<(u16, u32)> = interfaces
            .iter()
            .enumerate()
            .map(|(index, interface)| (interface.id.0, slot(index)))
            .collect();
        interface_keys.sort_by_key(|(id, _)| *id);
        let mut locals_by_address: Vec<(u32, u32)> = local_ipv4
            .iter()
            .enumerate()
            .map(|(index, binding)| (address_bits(binding.address), slot(index)))
            .collect();
        locals_by_address.sort_by_key(|(address, _)| *address);
        let mut locals_by_interface: Vec<(u16, u32)> = local_ipv4
            .iter()
            .enumerate()
            .map(|(index, binding)| (binding.interface.0, slot(index)))
            .collect();
        locals_by_interface.sort_by_key(|(id, _)| *id);
        let mut neighbor_keys: Vec<(u64, u32)> = neighbors
            .iter()
            .enumerate()
            .map(|(index, neighbor)| (key(neighbor.interface, neighbor.target), slot(index)))
            .collect();
        neighbor_keys.sort_by_key(|(key, _)| *key);

        Self {
            routes,
            interfaces: interface_keys.into_boxed_slice(),
            locals_by_address: locals_by_address.into_boxed_slice(),
            locals_by_interface: locals_by_interface.into_boxed_slice(),
            neighbors: neighbor_keys.into_boxed_slice(),
            input_firewall: crate::firewall::InputFirewallIndex::default(),
        }
    }

    /// Replaces the input firewall lists (INPUT-FW, cold).
    pub(crate) fn set_input_firewall(&mut self, index: crate::firewall::InputFirewallIndex) {
        self.input_firewall = index;
    }

    /// The input firewall lists (INPUT-FW).
    #[inline]
    pub(crate) const fn input_firewall(&self) -> &crate::firewall::InputFirewallIndex {
        &self.input_firewall
    }

    /// Heap bytes held by the index (snapshot memory, freed with the owner).
    pub(crate) fn heap_bytes(&self) -> usize {
        use std::mem::size_of_val;
        self.routes.heap_bytes()
            + size_of_val(&*self.interfaces)
            + size_of_val(&*self.locals_by_address)
            + size_of_val(&*self.locals_by_interface)
            + size_of_val(&*self.neighbors)
            + self.input_firewall.heap_bytes()
    }

    /// The routes.
    #[inline]
    pub(crate) const fn routes(&self) -> &crate::Ipv4Routes {
        &self.routes
    }

    /// The longest-prefix route for `destination`, and the number of tree
    /// nodes read.
    #[inline]
    pub(crate) fn route(&self, destination: Ipv4Address) -> (Option<Route>, u32) {
        self.routes.route_counted(destination)
    }

    #[inline]
    pub(crate) fn interface(&self, id: IfId) -> (Option<usize>, u32) {
        exact(&self.interfaces, id.0)
    }

    #[inline]
    pub(crate) fn local_by_address(&self, address: Ipv4Address) -> (Option<usize>, u32) {
        exact(&self.locals_by_address, address_bits(address))
    }

    #[inline]
    pub(crate) fn local_by_interface(&self, interface: IfId) -> (Option<usize>, u32) {
        exact(&self.locals_by_interface, interface.0)
    }

    #[inline]
    pub(crate) fn static_neighbor(
        &self,
        interface: IfId,
        target: Ipv4Address,
    ) -> (Option<usize>, u32) {
        exact(&self.neighbors, key(interface, target))
    }

    #[inline]
    pub(crate) fn connected_boundary(&self, interface: IfId, address: Ipv4Address) -> bool {
        self.routes.is_connected_boundary(interface, address)
    }

    #[inline]
    #[cfg(test)]
    pub(crate) fn gateway(&self, interface: IfId, next_hop: Ipv4Address) -> bool {
        self.routes.is_gateway(interface, next_hop)
    }

    #[inline]
    pub(crate) fn sender_on_link(&self, interface: IfId, sender: Ipv4Address) -> bool {
        self.routes.is_sender_on_link(interface, sender)
    }
}

/// Linear reference semantics, the pre-H4c per-packet code. Used for
/// snapshots without an owner index and as the differential oracle.
pub(crate) mod linear {
    use crate::{IfId, Interface, Ipv4Address, LocalIpv4Binding, Neighbor, Route};

    pub(crate) fn route(routes: &[Route], destination: Ipv4Address) -> Option<Route> {
        crate::route::lookup_linear(routes, destination)
    }

    pub(crate) fn interface(interfaces: &[Interface], id: IfId) -> Option<&Interface> {
        interfaces.iter().find(|interface| interface.id == id)
    }

    pub(crate) fn local_by_address(
        local_ipv4: &[LocalIpv4Binding],
        address: Ipv4Address,
    ) -> Option<&LocalIpv4Binding> {
        local_ipv4.iter().find(|binding| binding.address == address)
    }

    pub(crate) fn local_by_interface(
        local_ipv4: &[LocalIpv4Binding],
        interface: IfId,
    ) -> Option<&LocalIpv4Binding> {
        local_ipv4
            .iter()
            .find(|binding| binding.interface == interface)
    }

    pub(crate) fn static_neighbor(
        neighbors: &[Neighbor],
        interface: IfId,
        target: Ipv4Address,
    ) -> Option<&Neighbor> {
        neighbors
            .iter()
            .find(|neighbor| neighbor.interface == interface && neighbor.target == target)
    }

    pub(crate) fn connected_boundary(
        routes: &[Route],
        interface: IfId,
        address: Ipv4Address,
    ) -> bool {
        routes.iter().any(|route| {
            route.egress() == interface
                && (route.is_connected_directed_broadcast(address)
                    || route.is_connected_network_address(address))
        })
    }

    #[cfg(test)]
    pub(crate) fn gateway(routes: &[Route], interface: IfId, next_hop: Ipv4Address) -> bool {
        routes
            .iter()
            .any(|route| route.egress() == interface && route.next_hop() == Some(next_hop))
    }

    pub(crate) fn sender_on_link(routes: &[Route], interface: IfId, sender: Ipv4Address) -> bool {
        routes.iter().any(|route| {
            route.egress() == interface
                && match route.next_hop() {
                    None => route.matches(sender),
                    Some(next_hop) => next_hop == sender,
                }
        })
    }
}
