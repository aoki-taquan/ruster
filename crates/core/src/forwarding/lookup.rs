//! Publication-time lookup indexes over one forwarding snapshot (PERF-002).
//!
//! [`ForwardingIndex`] is built once by [`crate::ValidatedForwardingOwner::new`]
//! on the cold publication path (allocation allowed there) from the same
//! boxed tables it validates, and is never mutated afterwards. Every packet
//! path lookup then costs a bounded number of comparisons that depends only
//! on the configured list lengths logarithmically, never linearly:
//!
//! - Route LPM: the routes are flattened into disjoint address intervals
//!   ("binary search on ranges"). Every route is a prefix, so the routes
//!   form a laminar family (two prefixes are disjoint or nested) and the
//!   longest match is constant between consecutive prefix boundaries. The
//!   boundaries (at most `2 * routes + 1`, fewer after merging neighbouring
//!   intervals with the same answer) are sorted and searched with one
//!   binary search: at most 14 probes at the 4096-route config limit.
//! - Exact keys (interface by id, local address by address and by
//!   interface, static neighbor by `(interface, target)`, connected network
//!   and directed-broadcast boundaries, gateway next hops): sorted arrays
//!   searched by binary search. Keys come from validated configuration, not
//!   from packets, so a hash table would gain nothing against an attacker
//!   and would need a secret to stay bounded; a sorted array is
//!   deterministic, has no worst case beyond `ceil(log2(n + 1))` probes,
//!   and needs no per-publication key.
//! - On-link senders (ARP learning, ARP-031): the direct (no next hop)
//!   routes of every interface merged into disjoint `(interface, address)`
//!   intervals, plus the gateway set.
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
//! last-wins rule for unvalidated input: it sorts with a stable sort, so
//! equal prefixes stay in slice order and the later one is pushed last and
//! ends on top of the nesting stack. Exact-key lookups return the first
//! element in slice order, like the reference `find`.

use crate::{IfId, Interface, Ipv4Address, LocalIpv4Binding, Neighbor, Route};

/// No route covers the interval.
const NO_ROUTE: u32 = u32::MAX;

/// Immutable lookup indexes for one validated forwarding owner.
pub(crate) struct ForwardingIndex {
    /// Sorted interval starts; `lpm_starts[0] == 0` always (with or without
    /// routes), so every address falls in exactly one interval.
    lpm_starts: Box<[u32]>,
    /// Route index per interval, or [`NO_ROUTE`].
    lpm_routes: Box<[u32]>,
    /// `(interface id, slice index)` sorted by id.
    interfaces: Box<[(u16, u32)]>,
    /// `(address, slice index)` sorted by address.
    locals_by_address: Box<[(u32, u32)]>,
    /// `(interface id, slice index)` sorted by interface.
    locals_by_interface: Box<[(u16, u32)]>,
    /// `(interface << 32 | target, slice index)` sorted by key.
    neighbors: Box<[(u64, u32)]>,
    /// `interface << 32 | address` of every network and directed-broadcast
    /// address of a connected (no next hop) route of length at most 30.
    connected_boundaries: Box<[u64]>,
    /// `interface << 32 | next hop` of every gateway route.
    gateways: Box<[u64]>,
    /// Disjoint, sorted, inclusive `(interface << 32 | first, interface <<
    /// 32 | last)` ranges covered by direct routes.
    on_link: Box<[(u64, u64)]>,
    /// The input firewall rules split by ingress and protocol class
    /// (INPUT-FW), set by [`crate::ValidatedForwardingOwner::with_input_firewall`].
    input_firewall: crate::firewall::InputFirewallIndex,
}

impl std::fmt::Debug for ForwardingIndex {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ForwardingIndex")
            .field("lpm_intervals", &self.lpm_starts.len())
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

fn prefix_last(route: Route) -> u32 {
    // `checked_shr` is `None` for `/32` (shift by 32): no host bits.
    address_bits(route.prefix())
        | u32::MAX
            .checked_shr(u32::from(route.prefix_len()))
            .unwrap_or(0)
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

#[inline]
fn member(items: &[u64], wanted: u64) -> (bool, u32) {
    let (position, probes) = partition(items, |candidate| *candidate < wanted);
    (items.get(position) == Some(&wanted), probes)
}

impl ForwardingIndex {
    /// Builds every index. Cold path: allocates and sorts, `O(n log n)`.
    pub(crate) fn build(
        routes: &[Route],
        interfaces: &[Interface],
        neighbors: &[Neighbor],
        local_ipv4: &[LocalIpv4Binding],
    ) -> Self {
        let (lpm_starts, lpm_routes) = build_lpm(routes);
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

        let mut connected_boundaries = Vec::new();
        let mut gateways = Vec::new();
        let mut direct: Vec<(u64, u64)> = Vec::new();
        for route in routes {
            if let Some(next_hop) = route.next_hop() {
                gateways.push(key(route.egress(), next_hop));
                continue;
            }
            let base = u64::from(route.egress().0) << 32;
            let first = address_bits(route.prefix());
            let last = prefix_last(*route);
            direct.push((base | u64::from(first), base | u64::from(last)));
            if route.prefix_len() <= 30 {
                connected_boundaries.push(base | u64::from(first));
                connected_boundaries.push(base | u64::from(last));
            }
        }
        connected_boundaries.sort_unstable();
        connected_boundaries.dedup();
        gateways.sort_unstable();
        gateways.dedup();
        direct.sort_unstable();
        let mut on_link: Vec<(u64, u64)> = Vec::with_capacity(direct.len());
        for (first, last) in direct {
            match on_link.last_mut() {
                // Merge overlapping and touching ranges. Ranges of two
                // interfaces can only touch at an interface boundary of
                // the 48-bit key space, where merging keeps the exact same
                // covered set.
                Some((_, previous_last)) if first <= previous_last.saturating_add(1) => {
                    *previous_last = (*previous_last).max(last);
                }
                _ => on_link.push((first, last)),
            }
        }

        Self {
            lpm_starts,
            lpm_routes,
            interfaces: interface_keys.into_boxed_slice(),
            locals_by_address: locals_by_address.into_boxed_slice(),
            locals_by_interface: locals_by_interface.into_boxed_slice(),
            neighbors: neighbor_keys.into_boxed_slice(),
            connected_boundaries: connected_boundaries.into_boxed_slice(),
            gateways: gateways.into_boxed_slice(),
            on_link: on_link.into_boxed_slice(),
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
        size_of_val(&*self.lpm_starts)
            + size_of_val(&*self.lpm_routes)
            + size_of_val(&*self.interfaces)
            + size_of_val(&*self.locals_by_address)
            + size_of_val(&*self.locals_by_interface)
            + size_of_val(&*self.neighbors)
            + size_of_val(&*self.connected_boundaries)
            + size_of_val(&*self.gateways)
            + size_of_val(&*self.on_link)
            + self.input_firewall.heap_bytes()
    }

    /// Slice index of the longest-prefix route for `destination`.
    #[inline]
    pub(crate) fn route(&self, destination: Ipv4Address) -> (Option<usize>, u32) {
        let address = address_bits(destination);
        let (after, probes) = partition(&self.lpm_starts, |start| *start <= address);
        // `lpm_starts[0] == 0`, so `after >= 1`.
        let route = self.lpm_routes[after - 1];
        ((route != NO_ROUTE).then_some(route as usize), probes)
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
    pub(crate) fn connected_boundary(&self, interface: IfId, address: Ipv4Address) -> (bool, u32) {
        member(&self.connected_boundaries, key(interface, address))
    }

    #[inline]
    pub(crate) fn gateway(&self, interface: IfId, next_hop: Ipv4Address) -> (bool, u32) {
        member(&self.gateways, key(interface, next_hop))
    }

    #[inline]
    pub(crate) fn sender_on_link(&self, interface: IfId, sender: Ipv4Address) -> (bool, u32) {
        let wanted = key(interface, sender);
        let (after, range_probes) = partition(&self.on_link, |(first, _)| *first <= wanted);
        let covered = after
            .checked_sub(1)
            .is_some_and(|position| self.on_link[position].1 >= wanted);
        if covered {
            return (true, range_probes);
        }
        let (gateway, gateway_probes) = self.gateway(interface, sender);
        (gateway, range_probes + gateway_probes)
    }
}

/// Flattens the routes into disjoint intervals with their longest match.
fn build_lpm(routes: &[Route]) -> (Box<[u32]>, Box<[u32]>) {
    let mut order: Vec<usize> = (0..routes.len()).collect();
    // Stable: equal (prefix, length) keep slice order, so the later route
    // ends on top of the stack, like the reference `max_by_key`.
    order.sort_by_key(|&index| {
        (
            address_bits(routes[index].prefix()),
            routes[index].prefix_len(),
        )
    });
    let mut points: Vec<u32> = Vec::with_capacity(routes.len() * 2 + 1);
    points.push(0);
    for route in routes {
        points.push(address_bits(route.prefix()));
        if let Some(after) = prefix_last(*route).checked_add(1) {
            points.push(after);
        }
    }
    points.sort_unstable();
    points.dedup();

    let mut starts = Vec::with_capacity(points.len());
    let mut values = Vec::with_capacity(points.len());
    let mut stack: Vec<usize> = Vec::new();
    let mut next = 0;
    for point in points {
        // Nested prefixes: the innermost (top) ends first.
        while stack
            .last()
            .is_some_and(|&top| prefix_last(routes[top]) < point)
        {
            stack.pop();
        }
        while let Some(&index) = order.get(next) {
            if address_bits(routes[index].prefix()) != point {
                break;
            }
            stack.push(index);
            next += 1;
        }
        let value = stack.last().map_or(NO_ROUTE, |&index| slot(index));
        if values.last() != Some(&value) {
            starts.push(point);
            values.push(value);
        }
    }
    (starts.into_boxed_slice(), values.into_boxed_slice())
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
