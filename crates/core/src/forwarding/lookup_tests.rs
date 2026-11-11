//! Differential and cost tests for the publication-time forwarding indexes
//! (PERF-002). The oracle is `lookup::linear`, the pre-H4c per-packet code.

use super::lookup::{linear, ForwardingIndex};
use super::*;
use crate::{Ipv4Address, MacAddress};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // SplitMix64: deterministic, seedable, no dependency.
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn address(&mut self) -> u32 {
        self.next() as u32
    }
}

fn ip(bits: u32) -> Ipv4Address {
    Ipv4Address::from_octets(bits.to_be_bytes())
}

fn bits(address: Ipv4Address) -> u32 {
    u32::from_be_bytes(address.octets())
}

fn mask(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(len))
    }
}

struct Tables {
    routes: Vec<Route>,
    interfaces: Vec<Interface>,
    neighbors: Vec<Neighbor>,
    local_ipv4: Vec<LocalIpv4Binding>,
}

/// Random tables that pass snapshot validation: overlapping prefixes drawn
/// from a few bases (so nesting is common), `/0` and `/32` included, a few
/// interfaces, unique neighbors and one address per interface.
fn random_tables(rng: &mut Rng, max_routes: u64) -> Tables {
    let interface_count = 1 + rng.below(6) as u16;
    let interfaces: Vec<Interface> = (0..interface_count)
        .map(|id| Interface {
            id: IfId(id * 3 + 1),
            mac: MacAddress([2, 0, 0, 0, 0, id as u8]),
            mtu: 1500,
        })
        .collect();
    let bases: Vec<u32> = (0..4).map(|_| rng.address()).collect();
    let mut routes: Vec<Route> = Vec::new();
    let wanted = rng.below(max_routes + 1);
    while (routes.len() as u64) < wanted {
        let len = match rng.below(8) {
            0 => 0,
            1 => 32,
            2 => 31,
            _ => rng.below(33) as u8,
        };
        let base = if rng.below(4) == 0 {
            rng.address()
        } else {
            bases[rng.below(bases.len() as u64) as usize] ^ (rng.address() & 0xff)
        };
        let prefix = ip(base & mask(len));
        let egress = interfaces[rng.below(interfaces.len() as u64) as usize].id;
        let next_hop = (rng.below(3) == 0).then(|| ip(rng.address()));
        if routes
            .iter()
            .any(|route| route.prefix() == prefix && route.prefix_len() == len)
        {
            continue;
        }
        routes.push(Route::new(prefix, len, egress, next_hop).unwrap());
    }
    let mut neighbors: Vec<Neighbor> = Vec::new();
    for _ in 0..rng.below(40) {
        let interface = interfaces[rng.below(interfaces.len() as u64) as usize].id;
        let target = if rng.below(2) == 0 && !routes.is_empty() {
            let route = routes[rng.below(routes.len() as u64) as usize];
            ip(bits(route.prefix()) | (rng.address() & !mask(route.prefix_len())))
        } else {
            ip(rng.address())
        };
        if !neighbors
            .iter()
            .any(|neighbor| neighbor.interface == interface && neighbor.target == target)
        {
            neighbors.push(Neighbor {
                interface,
                target,
                mac: MacAddress([2, 1, 0, 0, 0, neighbors.len() as u8]),
            });
        }
    }
    let mut local_ipv4: Vec<LocalIpv4Binding> = Vec::new();
    for interface in &interfaces {
        if rng.below(4) == 0 {
            continue;
        }
        let address = ip(rng.address() | 1);
        if !local_ipv4.iter().any(|binding| binding.address == address) {
            local_ipv4.push(LocalIpv4Binding {
                interface: interface.id,
                address,
            });
        }
    }
    Tables {
        routes,
        interfaces,
        neighbors,
        local_ipv4,
    }
}

/// Addresses that hit every interval boundary of the table plus random ones.
fn probe_addresses(rng: &mut Rng, tables: &Tables) -> Vec<Ipv4Address> {
    let mut addresses = vec![ip(0), ip(1), ip(u32::MAX), ip(u32::MAX - 1)];
    for route in &tables.routes {
        let first = bits(route.prefix());
        let last = first | !mask(route.prefix_len());
        for candidate in [
            first,
            last,
            first.wrapping_sub(1),
            last.wrapping_add(1),
            first.wrapping_add(1),
        ] {
            addresses.push(ip(candidate));
        }
        if let Some(next_hop) = route.next_hop() {
            addresses.push(next_hop);
        }
    }
    for neighbor in &tables.neighbors {
        addresses.push(neighbor.target);
    }
    for binding in &tables.local_ipv4 {
        addresses.push(binding.address);
    }
    for _ in 0..64 {
        addresses.push(ip(rng.address()));
    }
    addresses
}

fn interface_ids(tables: &Tables) -> Vec<IfId> {
    let mut ids: Vec<IfId> = tables
        .interfaces
        .iter()
        .map(|interface| interface.id)
        .collect();
    ids.push(IfId(0));
    ids.push(IfId(u16::MAX));
    ids
}

fn owner(tables: &Tables) -> ValidatedForwardingOwner {
    ValidatedForwardingOwner::new(
        tables.routes.clone().into_boxed_slice(),
        tables.interfaces.clone().into_boxed_slice(),
        tables.neighbors.clone().into_boxed_slice(),
        tables.local_ipv4.clone().into_boxed_slice(),
        Ipv4OriginPolicy::default(),
    )
    .unwrap()
}

fn assert_snapshot_matches_linear(
    snapshot: &ForwardingSnapshot<'_>,
    tables: &Tables,
    rng: &mut Rng,
) {
    assert!(snapshot.index.is_some(), "owner snapshots are indexed");
    let addresses = probe_addresses(rng, tables);
    let ids = interface_ids(tables);
    for id in &ids {
        assert_eq!(
            snapshot.interface(*id),
            linear::interface(&tables.interfaces, *id)
        );
        assert_eq!(
            snapshot.local_binding_on(*id),
            linear::local_by_interface(&tables.local_ipv4, *id)
        );
    }
    for address in &addresses {
        assert_eq!(
            snapshot.route_lookup(*address),
            linear::route(&tables.routes, *address),
            "route for {address:?}"
        );
        assert_eq!(
            snapshot.local_binding_for(*address),
            linear::local_by_address(&tables.local_ipv4, *address)
        );
        for id in &ids {
            assert_eq!(
                snapshot.static_neighbor(*id, *address),
                linear::static_neighbor(&tables.neighbors, *id, *address)
            );
            assert_eq!(
                snapshot.is_connected_boundary(*id, *address),
                linear::connected_boundary(&tables.routes, *id, *address),
                "connected boundary {id:?} {address:?}"
            );
            assert_eq!(
                snapshot.is_gateway(*id, *address),
                linear::gateway(&tables.routes, *id, *address)
            );
            assert_eq!(
                snapshot.sender_on_link(*id, *address),
                linear::sender_on_link(&tables.routes, *id, *address),
                "on-link {id:?} {address:?}"
            );
        }
    }
}

#[test]
fn indexed_lookups_match_the_linear_reference_on_random_tables() {
    let mut rng = Rng(0x5eed_4c00);
    for _ in 0..400 {
        let tables = random_tables(&mut rng, 80);
        let owner = owner(&tables);
        assert_snapshot_matches_linear(&owner.snapshot(), &tables, &mut rng);
    }
}

#[test]
fn indexed_route_lookup_matches_the_linear_reference_on_large_tables() {
    let mut rng = Rng(0x0004_0960);
    for _ in 0..8 {
        let tables = random_tables(&mut rng, 4096);
        let owner = owner(&tables);
        let snapshot = owner.snapshot();
        for address in probe_addresses(&mut rng, &tables) {
            assert_eq!(
                snapshot.route_lookup(address),
                linear::route(&tables.routes, address)
            );
        }
    }
}

/// Duplicate `(prefix, length)` pairs never pass validation, but the
/// builder must still reproduce `max_by_key`'s last-maximum rule.
#[test]
fn unvalidated_duplicate_prefixes_resolve_to_the_last_like_max_by_key() {
    let mut rng = Rng(0xd0b1_e000);
    for _ in 0..300 {
        let mut routes = Vec::new();
        for _ in 0..rng.below(24) {
            let len = rng.below(33) as u8;
            let prefix = ip((0x0a00_0000 | (rng.address() & 0x00ff_ffff)) & mask(len));
            let egress = IfId(rng.below(4) as u16);
            routes.push(Route::new(prefix, len, egress, None).unwrap());
            if rng.below(2) == 0 {
                // An exact duplicate prefix with a different egress.
                routes.push(Route::new(prefix, len, IfId(9), None).unwrap());
            }
        }
        let index = ForwardingIndex::build(&routes, &[], &[], &[]);
        for route in &routes {
            for address in [
                route.prefix(),
                ip(bits(route.prefix()) | !mask(route.prefix_len())),
                ip(rng.address()),
            ] {
                assert_eq!(
                    index.route(address).0.map(|slot| routes[slot]),
                    linear::route(&routes, address)
                );
            }
        }
    }
}

#[test]
fn edge_tables_default_host_and_empty() {
    let default = Route::new(ip(0), 0, IfId(1), Some(ip(0x0a00_0001))).unwrap();
    let host_low = Route::new(ip(0), 32, IfId(2), None).unwrap();
    let host_high = Route::new(ip(u32::MAX), 32, IfId(3), None).unwrap();
    let empty = ForwardingIndex::build(&[], &[], &[], &[]);
    assert_eq!(empty.route(ip(0)).0, None);
    assert_eq!(empty.route(ip(u32::MAX)).0, None);
    assert!(!empty.sender_on_link(IfId(1), ip(1)).0);

    let routes = [default, host_low, host_high];
    let index = ForwardingIndex::build(&routes, &[], &[], &[]);
    assert_eq!(index.route(ip(0)).0, Some(1));
    assert_eq!(index.route(ip(1)).0, Some(0));
    assert_eq!(index.route(ip(u32::MAX - 1)).0, Some(0));
    assert_eq!(index.route(ip(u32::MAX)).0, Some(2));
    // `/0` and `/32` are never connected boundaries (length > 30 or a
    // gateway), but a direct `/32` is on-link for its own address only.
    assert!(index.sender_on_link(IfId(3), ip(u32::MAX)).0);
    assert!(!index.sender_on_link(IfId(3), ip(u32::MAX - 1)).0);
    assert!(index.sender_on_link(IfId(1), ip(0x0a00_0001)).0);
    assert!(!index.sender_on_link(IfId(1), ip(0x0a00_0002)).0);

    let connected = [Route::new(ip(0), 0, IfId(4), None).unwrap()];
    let index = ForwardingIndex::build(&connected, &[], &[], &[]);
    assert!(index.connected_boundary(IfId(4), ip(0)).0);
    assert!(index.connected_boundary(IfId(4), ip(u32::MAX)).0);
    assert!(!index.connected_boundary(IfId(5), ip(u32::MAX)).0);
    assert!(index.sender_on_link(IfId(4), ip(0x1234_5678)).0);
}

fn limit_tables() -> Tables {
    let mut rng = Rng(0x1_0000);
    let interfaces: Vec<Interface> = (0..256u16)
        .map(|id| Interface {
            id: IfId(id),
            mac: MacAddress([2, 0, 0, 0, (id >> 8) as u8, id as u8]),
            mtu: 1500,
        })
        .collect();
    // 4096 /24 routes, the shape the review measured, half of them direct.
    let routes: Vec<Route> = (0..4096u32)
        .map(|index| {
            let prefix = ip(0x0a00_0000 | (index << 8));
            let egress = IfId((index % 256) as u16);
            let next_hop = (index % 2 == 1).then(|| ip(0x0a00_0000 | ((index - 1) << 8) | 1));
            Route::new(prefix, 24, egress, next_hop).unwrap()
        })
        .collect();
    let neighbors: Vec<Neighbor> = (0..4096u32)
        .map(|index| Neighbor {
            interface: IfId((index % 256) as u16),
            target: ip(0x0a00_0000 | (index << 8) | 2),
            mac: MacAddress([2, 2, 0, 0, (index >> 8) as u8, index as u8]),
        })
        .collect();
    // One address per interface is the snapshot (and config validation)
    // rule, so at most 256 here although `[[addresses]]` parses up to
    // 1024. The bound below is computed for 1024 regardless.
    let local_ipv4: Vec<LocalIpv4Binding> = (0..256u32)
        .map(|index| LocalIpv4Binding {
            interface: IfId(index as u16),
            address: ip(0x0a00_0000 | (index << 8) | 1),
        })
        .collect();
    let _ = rng.next();
    Tables {
        routes,
        interfaces,
        neighbors,
        local_ipv4,
    }
}

fn log2_ceil(entries: usize) -> u32 {
    usize::BITS - entries.leading_zeros()
}

#[test]
fn lookup_probes_are_bounded_at_the_config_limits() {
    let tables = limit_tables();
    let index = ForwardingIndex::build(
        &tables.routes,
        &tables.interfaces,
        &tables.neighbors,
        &tables.local_ipv4,
    );
    // ceil(log2(n + 1)) probes for n sorted entries.
    // The route tree reads at most one node per 8 bits of the address.
    let tree_bound = 4;
    let route_bound = log2_ceil(2 * 4096 + 1); // 14
    let neighbor_bound = log2_ceil(4096); // 13
    let local_bound = log2_ceil(1024); // 11
    let interface_bound = log2_ceil(256); // 9
    assert_eq!(route_bound, 14);
    let mut rng = Rng(0xc057);
    let mut addresses = probe_addresses(&mut rng, &tables);
    addresses.extend((0..4096).map(|_| ip(rng.address())));
    let mut worst = [0u32; 7];
    for address in &addresses {
        worst[0] = worst[0].max(index.route(*address).1);
        worst[1] = worst[1].max(index.local_by_address(*address).1);
        for id in [IfId(0), IfId(17), IfId(255)] {
            worst[2] = worst[2].max(index.static_neighbor(id, *address).1);
            worst[3] = worst[3].max(index.connected_boundary(id, *address).1);
            worst[4] = worst[4].max(index.gateway(id, *address).1);
            worst[5] = worst[5].max(index.sender_on_link(id, *address).1);
        }
    }
    for id in 0..=u16::MAX {
        worst[6] = worst[6].max(index.interface(IfId(id)).1);
        worst[6] = worst[6].max(index.local_by_interface(IfId(id)).1);
    }
    assert!(worst[0] <= tree_bound, "route tree nodes {}", worst[0]);
    assert!(worst[1] <= local_bound, "local probes {}", worst[1]);
    assert!(worst[2] <= neighbor_bound, "neighbor probes {}", worst[2]);
    assert!(worst[3] <= route_bound, "connected probes {}", worst[3]);
    assert!(worst[4] <= neighbor_bound, "gateway probes {}", worst[4]);
    assert!(
        worst[5] <= route_bound + neighbor_bound,
        "on-link probes {}",
        worst[5]
    );
    assert!(worst[6] <= interface_bound, "interface probes {}", worst[6]);
    // Memory at the limits stays small and is reported.
    assert!(index.heap_bytes() < 256 * 1024, "{}", index.heap_bytes());
}

#[test]
fn owner_snapshot_is_indexed_and_borrowed_snapshot_is_linear() {
    let tables = limit_tables();
    let owner = owner(&tables);
    let snapshot = owner.snapshot();
    assert!(snapshot.index.is_some());
    assert_eq!(owner.index_heap_bytes(), owner.index.heap_bytes());
    let borrowed = ForwardingSnapshot::new(
        &tables.routes,
        &tables.interfaces,
        &tables.neighbors,
        &tables.local_ipv4,
    )
    .unwrap();
    assert!(borrowed.index.is_none());
}

/// Release timing, run on demand:
/// `cargo test --release -p ruster-core lookup_timing -- --ignored --nocapture`
#[test]
#[ignore = "timing report, not a pass/fail test"]
fn lookup_timing_at_4096_routes() {
    use std::hint::black_box;
    use std::time::Instant;

    let tables = limit_tables();
    let owner = owner(&tables);
    let snapshot = owner.snapshot();
    let mut rng = Rng(0x7177);
    let addresses: Vec<Ipv4Address> = (0..4096)
        .map(|_| ip(0x0a00_0000 | (rng.address() & 0x00ff_ffff)))
        .collect();
    let rounds = 200;
    let started = Instant::now();
    for _ in 0..rounds {
        for address in &addresses {
            black_box(linear::route(&tables.routes, black_box(*address)));
        }
    }
    let linear_ns = started.elapsed().as_nanos() as f64 / f64::from(rounds * 4096);
    let rounds = 20_000;
    let started = Instant::now();
    for _ in 0..rounds {
        for address in &addresses {
            black_box(snapshot.route_lookup(black_box(*address)));
        }
    }
    let indexed_ns = started.elapsed().as_nanos() as f64 / f64::from(rounds * 4096);
    let started = Instant::now();
    for _ in 0..rounds {
        for address in &addresses {
            black_box(snapshot.static_neighbor(IfId(7), black_box(*address)));
            black_box(snapshot.is_local_ipv4(black_box(*address)));
        }
    }
    let exact_ns = started.elapsed().as_nanos() as f64 / f64::from(rounds * 4096);
    println!(
        "4096 /24 routes: linear LPM {linear_ns:.1} ns, indexed LPM {indexed_ns:.1} ns, \
         static neighbor + local address {exact_ns:.1} ns, index {} bytes",
        owner.index_heap_bytes()
    );
}

/// Duplicate ids, addresses, and neighbor keys never pass validation, but
/// the exact-key indexes still return the first in slice order, like the
/// reference `find`.
#[test]
fn unvalidated_duplicate_keys_resolve_to_the_first_like_find() {
    let interfaces = [
        Interface {
            id: IfId(4),
            mac: MacAddress([2, 0, 0, 0, 0, 1]),
            mtu: 1500,
        },
        Interface {
            id: IfId(4),
            mac: MacAddress([2, 0, 0, 0, 0, 2]),
            mtu: 1500,
        },
    ];
    let local_ipv4 = [
        LocalIpv4Binding {
            interface: IfId(4),
            address: ip(0x0a00_0001),
        },
        LocalIpv4Binding {
            interface: IfId(4),
            address: ip(0x0a00_0001),
        },
    ];
    let neighbors = [
        Neighbor {
            interface: IfId(4),
            target: ip(0x0a00_0002),
            mac: MacAddress([2, 0, 0, 0, 0, 3]),
        },
        Neighbor {
            interface: IfId(4),
            target: ip(0x0a00_0002),
            mac: MacAddress([2, 0, 0, 0, 0, 4]),
        },
    ];
    let index = ForwardingIndex::build(&[], &interfaces, &neighbors, &local_ipv4);
    assert_eq!(index.interface(IfId(4)).0, Some(0));
    assert_eq!(index.local_by_interface(IfId(4)).0, Some(0));
    assert_eq!(index.local_by_address(ip(0x0a00_0001)).0, Some(0));
    assert_eq!(index.static_neighbor(IfId(4), ip(0x0a00_0002)).0, Some(0));
}

/// The largest index the config limits allow: 4096 non-adjacent direct
/// routes (every route adds two connected boundaries and its own on-link
/// range, and they fill the route tree's nodes of 32 /16s), 4096 static
/// neighbors, and 256 interfaces with one address each, and 256 input
/// firewall rules (INPUT-FW) in the shape with the most per-ingress list
/// entries: 128 for any interface and protocol, 128 naming distinct
/// interfaces. About 415 KiB (snapshot memory; two owners coexist during a
/// reload, about 830 KiB).
#[test]
fn index_heap_at_the_worst_config_shape_is_about_415_kib() {
    let interfaces: Vec<Interface> = (0..256u16)
        .map(|id| Interface {
            id: IfId(id),
            mac: MacAddress([2, 0, 0, 0, (id >> 8) as u8, id as u8]),
            mtu: 1500,
        })
        .collect();
    // /24s spaced one /24 apart: no two ranges touch, nothing merges.
    let routes: Vec<Route> = (0..4096u32)
        .map(|index| {
            Route::new(
                ip(0x0a00_0000 | (index << 9)),
                24,
                IfId((index % 256) as u16),
                None,
            )
            .unwrap()
        })
        .collect();
    let neighbors: Vec<Neighbor> = (0..4096u32)
        .map(|index| Neighbor {
            interface: IfId((index % 256) as u16),
            target: ip(0x0a00_0000 | (index << 9) | 2),
            mac: MacAddress([2, 2, 0, 0, (index >> 8) as u8, index as u8]),
        })
        .collect();
    let local_ipv4: Vec<LocalIpv4Binding> = (0..256u32)
        .map(|index| LocalIpv4Binding {
            interface: IfId(index as u16),
            address: ip(0x0a00_0000 | (index << 9) | 1),
        })
        .collect();
    let mut index = ForwardingIndex::build(&routes, &interfaces, &neighbors, &local_ipv4);
    let tables = index.heap_bytes();
    // 8192 boundaries x 8 + 4096 on-link ranges x 16 + 4096 neighbors x 16
    // + 256 interfaces x 8 + 2 x 256 locals x 8, and the route tree.
    let sorted = 8192 * 8 + 4096 * 16 + 4096 * 16 + 256 * 8 + 2 * 256 * 8;
    let tree = tables - sorted;
    // 32 nodes of a /16 with 128 routes each, and the two nodes above them.
    assert!((64 * 1024..=96 * 1024).contains(&tree), "{tree}");

    // Input rules: with `a` rules for any interface and protocol and `b`
    // naming distinct interfaces, the lists hold 4a + 4b(a + 1) entries,
    // most at a = b = 128.
    let any = crate::FirewallIpv4Prefix::new(ip(0), 0).unwrap();
    let rules: Vec<crate::InputFirewallRule> = (0..crate::INPUT_FIREWALL_MAX_RULES as u32)
        .map(|slot| {
            let ingress = if slot < 128 {
                crate::FirewallInterface::Any
            } else {
                crate::FirewallInterface::Interface(IfId((slot - 128) as u16))
            };
            crate::InputFirewallRule::new(
                crate::FirewallRuleId(slot + 1),
                ingress,
                any,
                any,
                crate::InputFirewallProtocol::Any,
                crate::InputFirewallAction::Accept,
            )
        })
        .collect();
    index.set_input_firewall(crate::firewall::InputFirewallIndex::build(&rules));
    let bytes = index.heap_bytes();
    let entries = 4 * 128 + 4 * 128 * 129;
    let lists = 128 * std::mem::size_of::<(u16, [u32; 5])>();
    assert_eq!(bytes - tables, entries * 2 + lists);
    assert!(bytes <= 420 * 1024, "{bytes}");
}

/// What validation answered when it compared every entry with every earlier one:
/// the entries in slice order, and for each a repeat before an unknown interface.
fn validation_by_pairs(tables: &Tables) -> Result<(), SnapshotError> {
    let Tables {
        routes,
        interfaces,
        neighbors,
        local_ipv4,
    } = tables;
    let known = |id: IfId| interfaces.iter().any(|interface| interface.id == id);
    for (index, route) in routes.iter().enumerate() {
        if routes[..index]
            .iter()
            .any(|c| c.prefix() == route.prefix() && c.prefix_len() == route.prefix_len())
        {
            return Err(SnapshotError::DuplicateRoute);
        }
        if !known(route.egress()) && !matches!(route.egress(), IfId::DISCARD | IfId::REJECT) {
            return Err(SnapshotError::RouteUnknownInterface);
        }
    }
    for (index, interface) in interfaces.iter().enumerate() {
        if interfaces[..index].iter().any(|c| c.id == interface.id) {
            return Err(SnapshotError::DuplicateInterface);
        }
        if interface.mtu < crate::IPV4_MIN_MTU {
            return Err(SnapshotError::InterfaceMtuBelowMinimum);
        }
    }
    for (index, neighbor) in neighbors.iter().enumerate() {
        if neighbors[..index]
            .iter()
            .any(|c| c.interface == neighbor.interface && c.target == neighbor.target)
        {
            return Err(SnapshotError::DuplicateNeighbor);
        }
        if !known(neighbor.interface) {
            return Err(SnapshotError::NeighborUnknownInterface);
        }
    }
    for (index, binding) in local_ipv4.iter().enumerate() {
        if binding.address.is_unspecified() {
            return Err(SnapshotError::LocalIpv4BindingUnspecified);
        }
        if local_ipv4[..index]
            .iter()
            .any(|c| c.interface == binding.interface || c.address == binding.address)
        {
            return Err(SnapshotError::DuplicateLocalIpv4Binding);
        }
        if !known(binding.interface) {
            return Err(SnapshotError::LocalIpv4BindingUnknownInterface);
        }
    }
    Ok(())
}

/// Valid tables with a few entries spoiled: repeated, moved to an interface the
/// tables do not have, an MTU too small, an unspecified address.
fn spoiled_tables(rng: &mut Rng) -> Tables {
    let mut tables = random_tables(rng, 24);
    let missing = IfId(900 + rng.below(3) as u16);
    for _ in 0..rng.below(4) {
        match rng.below(9) {
            0 if !tables.routes.is_empty() => {
                let from = tables.routes[rng.below(tables.routes.len() as u64) as usize];
                let at = rng.below(tables.routes.len() as u64 + 1) as usize;
                tables.routes.insert(at, from);
            }
            1 if !tables.routes.is_empty() => {
                let at = rng.below(tables.routes.len() as u64) as usize;
                let route = tables.routes[at];
                let egress = [missing, IfId::DISCARD, IfId::REJECT][rng.below(3) as usize];
                tables.routes[at] =
                    Route::new(route.prefix(), route.prefix_len(), egress, route.next_hop())
                        .unwrap();
            }
            2 => {
                let from = tables.interfaces[rng.below(tables.interfaces.len() as u64) as usize];
                let at = rng.below(tables.interfaces.len() as u64 + 1) as usize;
                tables.interfaces.insert(at, from);
            }
            3 => {
                let at = rng.below(tables.interfaces.len() as u64) as usize;
                tables.interfaces[at].mtu = crate::IPV4_MIN_MTU - 1;
            }
            4 if !tables.neighbors.is_empty() => {
                let from = tables.neighbors[rng.below(tables.neighbors.len() as u64) as usize];
                let at = rng.below(tables.neighbors.len() as u64 + 1) as usize;
                tables.neighbors.insert(at, from);
            }
            5 if !tables.neighbors.is_empty() => {
                let at = rng.below(tables.neighbors.len() as u64) as usize;
                tables.neighbors[at].interface = missing;
            }
            6 if !tables.local_ipv4.is_empty() => {
                let mut from =
                    tables.local_ipv4[rng.below(tables.local_ipv4.len() as u64) as usize];
                // The same interface, the same address, or both.
                match rng.below(3) {
                    0 => from.address = ip(rng.address() | 1),
                    1 => from.interface = missing,
                    _ => {}
                }
                let at = rng.below(tables.local_ipv4.len() as u64 + 1) as usize;
                tables.local_ipv4.insert(at, from);
            }
            7 if !tables.local_ipv4.is_empty() => {
                let at = rng.below(tables.local_ipv4.len() as u64) as usize;
                tables.local_ipv4[at].interface = missing;
            }
            8 if !tables.local_ipv4.is_empty() => {
                let at = rng.below(tables.local_ipv4.len() as u64) as usize;
                tables.local_ipv4[at].address = ip(0);
            }
            _ => {}
        }
    }
    tables
}

#[test]
fn validation_answers_as_comparing_every_pair_did() {
    let mut rng = Rng(0x7461_626c_6573);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..20_000 {
        let tables = spoiled_tables(&mut rng);
        let expected = validation_by_pairs(&tables);
        let got = ForwardingSnapshot::new(
            &tables.routes,
            &tables.interfaces,
            &tables.neighbors,
            &tables.local_ipv4,
        )
        .map(|_| ());
        assert_eq!(got, expected);
        seen.insert(format!("{expected:?}"));
    }
    // Every answer came up: valid tables and each of the nine errors.
    assert_eq!(seen.len(), 10, "{seen:?}");
}

#[test]
fn a_repeat_among_many_routes_is_found() {
    // 200,000 routes. Comparing every pair (2 * 10^10 comparisons) would still pass,
    // but take minutes.
    let interfaces = [Interface {
        id: IfId(1),
        mac: MacAddress([2, 0, 0, 0, 0, 1]),
        mtu: 1500,
    }];
    let mut routes: Vec<Route> = (0..200_000u32)
        .map(|i| Route::new(ip(i << 8), 24, IfId(1), None).unwrap())
        .collect();
    assert!(ForwardingSnapshot::new(&routes, &interfaces, &[], &[]).is_ok());
    routes.push(routes[7]);
    assert_eq!(
        ForwardingSnapshot::new(&routes, &interfaces, &[], &[]).err(),
        Some(SnapshotError::DuplicateRoute)
    );
}

/// The same at the sizes of a BGP table. The destinations are spread over all
/// the routes, so the index does not stay in the CPU's cache:
/// `cargo test --release -p ruster-core lookup_timing -- --ignored --nocapture`
#[test]
#[ignore = "timing report, not a pass/fail test"]
fn lookup_timing_up_to_a_full_table() {
    use std::hint::black_box;
    use std::time::Instant;

    for count in [4096u32, 131_072, 1_048_576] {
        let mut tables = limit_tables();
        tables.routes = (0..count)
            .map(|index| {
                let prefix = ip(0x1000_0000 + (index << 8));
                let egress = IfId((index % 256) as u16);
                let next_hop = (index % 2 == 1).then(|| ip(0x1000_0000 + ((index - 1) << 8) + 1));
                Route::new(prefix, 24, egress, next_hop).unwrap()
            })
            .collect();
        let started = Instant::now();
        let owner = owner(&tables);
        let built = started.elapsed();
        let snapshot = owner.snapshot();
        let mut rng = Rng(0x7177);
        let addresses: Vec<Ipv4Address> = (0..65_536)
            .map(|_| ip(0x1000_0000 + (rng.address() % (count << 8))))
            .collect();
        let rounds = 200;
        let started = Instant::now();
        for _ in 0..rounds {
            for address in &addresses {
                black_box(snapshot.route_lookup(black_box(*address)));
            }
        }
        let lookup_ns = started.elapsed().as_nanos() as f64 / f64::from(rounds * 65_536);
        println!(
            "{count} /24 routes: validation and index {built:?}, LPM {lookup_ns:.1} ns, \
             index {} bytes",
            owner.index_heap_bytes()
        );
    }
}
