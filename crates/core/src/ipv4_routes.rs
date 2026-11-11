//! The IPv4 routes of one table, kept so that a new version shares what did
//! not change with the one before it.
//!
//! Beside the routes by prefix ([`crate::Ipv4RouteTree`]) this keeps what
//! the packet path asks of the routes as a whole: the network and
//! directed-broadcast addresses of connected routes, the gateways, the
//! routes without a gateway by interface, and the interfaces routes leave
//! by. Each is brought up to date as a route is set or taken out, so a
//! change costs the same whatever the number of routes.
//!
//! [`Ipv4Routes::clone`] copies two pointers. The sets beside the tree are
//! one block, copied whole by the first change after a clone: they are as
//! large as the number of gateways and of routes without one, which is
//! small beside the routes a routing protocol brings.
//!
//! The forwarding path does not use this yet.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::{IfId, Ipv4Address, Ipv4RouteTree, Route};

/// An interface and an address as one number, interface first.
fn key(interface: IfId, address: u32) -> u64 {
    u64::from(interface.0) << 32 | u64::from(address)
}

fn bits(address: Ipv4Address) -> u32 {
    u32::from_be_bytes(address.octets())
}

fn mask(len: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0)
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Sets {
    /// Interface and next hop of the routes with a gateway, and how many
    /// routes name each.
    gateways: BTreeMap<u64, u32>,
    /// Interface and address of the first and the last address of the
    /// routes without a gateway of at most 30 bits, and how many have each.
    boundaries: BTreeMap<u64, u32>,
    /// The routes without a gateway: interface, length, prefix.
    direct: BTreeSet<(u16, u8, u32)>,
    /// The interfaces routes leave by, and how many routes each has.
    egresses: BTreeMap<IfId, u32>,
}

fn count<K: Ord>(counts: &mut BTreeMap<K, u32>, key: K, add: bool) {
    if add {
        *counts.entry(key).or_insert(0) += 1;
    } else if let Some(left) = counts.get_mut(&key) {
        *left -= 1;
        if *left == 0 {
            counts.remove(&key);
        }
    }
}

impl Sets {
    fn account(&mut self, route: Route, add: bool) {
        count(&mut self.egresses, route.egress(), add);
        if let Some(next_hop) = route.next_hop() {
            count(&mut self.gateways, key(route.egress(), bits(next_hop)), add);
            return;
        }
        let (first, len) = (bits(route.prefix()), route.prefix_len());
        let entry = (route.egress().0, len, first);
        if add {
            self.direct.insert(entry);
        } else {
            self.direct.remove(&entry);
        }
        if len <= 30 {
            count(&mut self.boundaries, key(route.egress(), first), add);
            count(
                &mut self.boundaries,
                key(route.egress(), first | !mask(len)),
                add,
            );
        }
    }
}

/// The IPv4 routes of one table.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ipv4Routes {
    tree: Ipv4RouteTree<Route>,
    sets: Arc<Sets>,
}

impl Ipv4Routes {
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of routes.
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Sets `route` and returns the route its prefix had.
    pub fn set(&mut self, route: Route) -> Option<Route> {
        let prefix = route.prefix().octets();
        if self.tree.get(&prefix, route.prefix_len()) == Some(&route) {
            // Nothing changes, and nothing is copied.
            return Some(route);
        }
        let before = self.tree.insert(&prefix, route.prefix_len(), route);
        let sets = Arc::make_mut(&mut self.sets);
        if let Some(before) = before {
            sets.account(before, false);
        }
        sets.account(route, true);
        before
    }

    /// Takes the route of `prefix/len` out and returns it.
    pub fn remove(&mut self, prefix: Ipv4Address, len: u8) -> Option<Route> {
        let removed = self.tree.remove(&prefix.octets(), len)?;
        Arc::make_mut(&mut self.sets).account(removed, false);
        Some(removed)
    }

    /// The route of `prefix/len` itself.
    pub fn get(&self, prefix: Ipv4Address, len: u8) -> Option<Route> {
        self.tree.get(&prefix.octets(), len).copied()
    }

    /// The longest route that has `destination`.
    #[inline]
    pub fn route(&self, destination: Ipv4Address) -> Option<Route> {
        self.tree.lookup(&destination.octets()).copied()
    }

    /// Whether `address` is the first or the last address of a route of at
    /// most 30 bits that leaves by `interface` without a gateway.
    #[inline]
    pub fn is_connected_boundary(&self, interface: IfId, address: Ipv4Address) -> bool {
        self.sets
            .boundaries
            .contains_key(&key(interface, bits(address)))
    }

    /// Whether some route out of `interface` names `next_hop` as gateway.
    #[inline]
    pub fn is_gateway(&self, interface: IfId, next_hop: Ipv4Address) -> bool {
        self.sets
            .gateways
            .contains_key(&key(interface, bits(next_hop)))
    }

    /// Whether `sender` is on the link of `interface`: inside a route out of
    /// it without a gateway, or a gateway out of it.
    pub fn is_sender_on_link(&self, interface: IfId, sender: Ipv4Address) -> bool {
        let address = bits(sender);
        (0..=32).any(|len| {
            self.sets
                .direct
                .contains(&(interface.0, len, address & mask(len)))
        }) || self.is_gateway(interface, sender)
    }

    /// The interfaces the routes leave by, each once, in order.
    pub fn egresses(&self) -> impl Iterator<Item = IfId> + '_ {
        self.sets.egresses.keys().copied()
    }

    /// Calls `visit` with every route.
    pub fn each(&self, mut visit: impl FnMut(Route)) {
        self.tree.each(|_, _, route| visit(*route));
    }

    /// Whether this and `other` are one and the same, as a clone and what it
    /// was made from are until one of them changes. Equal routes that were
    /// built apart are not.
    pub fn shares_all_with(&self, other: &Self) -> bool {
        self.tree.shares_all_with(&other.tree) && Arc::ptr_eq(&self.sets, &other.sets)
    }

    /// About the heap bytes held. Goes through every node of the tree.
    pub fn heap_bytes(&self) -> usize {
        use std::mem::size_of;
        let sets = &*self.sets;
        self.tree.heap_bytes()
            + (sets.gateways.len() + sets.boundaries.len()) * size_of::<(u64, u32)>()
            + sets.direct.len() * size_of::<(u16, u8, u32)>()
            + sets.egresses.len() * size_of::<(IfId, u32)>()
    }
}

impl FromIterator<Route> for Ipv4Routes {
    /// Of two routes with the same prefix the later one stays.
    fn from_iter<T: IntoIterator<Item = Route>>(routes: T) -> Self {
        let mut table = Self::new();
        for route in routes {
            table.set(route);
        }
        table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Interface, Ipv4OriginPolicy, MacAddress, ValidatedForwardingOwner};

    struct Rng(u64);

    impl Rng {
        fn below(&mut self, bound: u64) -> u64 {
            // SplitMix64.
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value = self.0;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (value ^ (value >> 31)) % bound
        }
    }

    fn ip(address: u32) -> Ipv4Address {
        Ipv4Address::from_octets(address.to_be_bytes())
    }

    /// An address out of few, so that prefixes lie inside one another and
    /// first and last addresses fall together.
    fn some_address(rng: &mut Rng) -> u32 {
        [0x0a01_0000u32, 0x0a01_0100, 0xc0a8_0000][rng.below(3) as usize]
            | [0u32, 0x80, 0xff, 0x01, 0xfe][rng.below(5) as usize]
    }

    fn some_route(rng: &mut Rng) -> Route {
        let len = [0u8, 8, 16, 23, 24, 25, 30, 31, 32][rng.below(9) as usize];
        let egress = IfId(rng.below(3) as u16);
        let next_hop = (rng.below(3) == 0).then(|| ip(some_address(rng)));
        Route::new(ip(some_address(rng) & mask(len)), len, egress, next_hop).unwrap()
    }

    /// What the forwarding snapshot answers for the same routes, built from
    /// nothing as it is today.
    fn assert_answers_as_the_snapshot(table: &Ipv4Routes, routes: &[Route], rng: &mut Rng) {
        let interfaces: Vec<Interface> = (0..3)
            .map(|id| Interface {
                id: IfId(id),
                mac: MacAddress([2, 0, 0, 0, 0, id as u8]),
                mtu: 1500,
            })
            .collect();
        let owner = ValidatedForwardingOwner::new(
            routes.into(),
            interfaces.into(),
            Box::default(),
            Box::default(),
            Ipv4OriginPolicy::default(),
        )
        .unwrap();
        let snapshot = owner.snapshot();
        assert_eq!(table.len(), routes.len());
        for _ in 0..200 {
            let address = ip(some_address(rng) ^ rng.below(4) as u32);
            assert_eq!(table.route(address), snapshot.route_lookup(address));
            for interface in (0..4).map(IfId) {
                assert_eq!(
                    table.is_connected_boundary(interface, address),
                    snapshot.is_connected_boundary(interface, address),
                    "{interface:?} {address:?}"
                );
                assert_eq!(
                    table.is_gateway(interface, address),
                    snapshot.is_gateway(interface, address)
                );
                assert_eq!(
                    table.is_sender_on_link(interface, address),
                    snapshot.sender_on_link(interface, address),
                    "{interface:?} {address:?}"
                );
            }
        }
        let mut egresses: Vec<IfId> = routes.iter().map(|route| route.egress()).collect();
        egresses.sort_unstable();
        egresses.dedup();
        assert_eq!(table.egresses().collect::<Vec<_>>(), egresses);
        // Built from the same routes anew, the table is equal though apart.
        let mut seen = Vec::new();
        table.each(|route| seen.push(route));
        assert_eq!(seen.len(), routes.len());
        let anew: Ipv4Routes = seen.into_iter().collect();
        assert!(anew == *table);
        assert!(routes.is_empty() || !anew.shares_all_with(table));
    }

    #[test]
    fn any_run_of_changes_answers_as_the_snapshot_built_from_the_routes_does() {
        let mut rng = Rng(0x7461_626c);
        let mut table = Ipv4Routes::new();
        let mut model: BTreeMap<(u32, u8), Route> = BTreeMap::new();
        let mut kept = Vec::new();
        for round in 0..1500 {
            let route = some_route(&mut rng);
            let at = (bits(route.prefix()), route.prefix_len());
            if rng.below(3) == 0 {
                assert_eq!(
                    table.remove(route.prefix(), route.prefix_len()),
                    model.remove(&at)
                );
            } else {
                assert_eq!(table.set(route), model.insert(at, route));
            }
            assert_eq!(
                table.get(route.prefix(), route.prefix_len()),
                model.get(&at).copied()
            );
            if round % 25 == 0 {
                let routes: Vec<Route> = model.values().copied().collect();
                assert_answers_as_the_snapshot(&table, &routes, &mut rng);
            }
            if round % 300 == 0 {
                kept.push((table.clone(), model.clone()));
            }
        }
        // The versions kept on the way are as they were.
        for (table, model) in &kept {
            let routes: Vec<Route> = model.values().copied().collect();
            assert_answers_as_the_snapshot(table, &routes, &mut rng);
        }
        for (prefix, len) in model.keys().copied().collect::<Vec<_>>() {
            assert!(table.remove(ip(prefix), len).is_some());
        }
        assert!(table == Ipv4Routes::new());
    }

    #[test]
    fn setting_a_route_as_it_is_copies_nothing() {
        let route = Route::new(ip(0x0a00_0000), 8, IfId(1), None).unwrap();
        let mut table = Ipv4Routes::new();
        assert_eq!(table.set(route), None);
        let copy = table.clone();
        assert_eq!(table.set(route), Some(route));
        assert_eq!(table.remove(ip(0x0b00_0000), 8), None);
        assert!(table.shares_all_with(&copy));
        let other = Route::new(ip(0x0a00_0000), 8, IfId(2), None).unwrap();
        assert_eq!(table.set(other), Some(route));
        assert!(!table.shares_all_with(&copy));
        assert_eq!(copy.route(ip(0x0a00_0001)), Some(route));
        assert!(copy.is_sender_on_link(IfId(1), ip(0x0a00_0001)));
        assert!(!table.is_sender_on_link(IfId(1), ip(0x0a00_0001)));
    }
}
