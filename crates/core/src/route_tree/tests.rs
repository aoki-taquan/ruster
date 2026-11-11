use std::collections::BTreeMap;

use super::*;

fn ip(address: u32) -> [u8; 4] {
    address.to_be_bytes()
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// `address` with the bits after `len` cleared.
fn masked<const N: usize>(mut address: [u8; N], len: u8) -> [u8; N] {
    for (index, byte) in address.iter_mut().enumerate() {
        let before = index as u32 * 8;
        let keep = u32::from(len).saturating_sub(before).min(8);
        *byte &= (0xff00u16 >> keep) as u8;
    }
    address
}

/// The last address of `prefix/len`.
fn last<const N: usize>(mut prefix: [u8; N], len: u8) -> [u8; N] {
    for (index, byte) in prefix.iter_mut().enumerate() {
        let before = index as u32 * 8;
        let keep = u32::from(len).saturating_sub(before).min(8);
        *byte |= !((0xff00u16 >> keep) as u8);
    }
    prefix
}

/// The address after (or before) `address`, wrapping.
fn step<const N: usize>(mut address: [u8; N], up: bool) -> [u8; N] {
    for byte in address.iter_mut().rev() {
        let (next, carried) = if up {
            byte.overflowing_add(1)
        } else {
            byte.overflowing_sub(1)
        };
        *byte = next;
        if !carried {
            break;
        }
    }
    address
}

/// The routes as a plain map, searched by comparing every one.
type Model<const N: usize> = BTreeMap<([u8; N], u8), u32>;

fn longest<const N: usize>(model: &Model<N>, address: [u8; N]) -> Option<u32> {
    model
        .iter()
        .filter(|((prefix, len), _)| masked(address, *len) == *prefix)
        .max_by_key(|((_, len), _)| *len)
        .map(|(_, value)| *value)
}

#[test]
fn the_longest_route_that_has_the_address_answers() {
    let mut tree = Ipv4RouteTree::new();
    assert_eq!(tree.lookup(&ip(0x0a01_0203)), None);
    for (prefix, len, value) in [
        (0, 0, 0),
        (0x0a00_0000, 8, 8),
        (0x0a01_0000, 16, 16),
        (0x0a01_8000, 17, 17),
        (0x0a01_0200, 24, 24),
        (0x0a01_0280, 25, 25),
        (0x0a01_0203, 32, 32),
    ] {
        assert_eq!(tree.insert(&ip(prefix), len, value), None);
    }
    assert_eq!(tree.len(), 7);
    for (address, value) in [
        (0x0b00_0000, 0),
        (0x0a02_0000, 8),
        (0x0a01_0100, 16),
        (0x0a01_7fff, 16),
        (0x0a01_8000, 17),
        (0x0a01_ffff, 17),
        (0x0a01_0200, 24),
        (0x0a01_0203, 32),
        (0x0a01_0204, 24),
        (0x0a01_027f, 24),
        (0x0a01_0280, 25),
        (0x0a01_02ff, 25),
        (0x0a01_0300, 16),
    ] {
        assert_eq!(tree.lookup(&ip(address)), Some(&value), "{address:#x}");
    }
    // A route set again gives back the value it had, and the count stays.
    assert_eq!(tree.insert(&ip(0x0a01_0200), 24, 240), Some(24));
    assert_eq!(tree.len(), 7);
    assert_eq!(tree.lookup(&ip(0x0a01_0204)), Some(&240));
    // Taken out, the shorter route under it answers again.
    assert_eq!(tree.remove(&ip(0x0a01_0200), 24), Some(240));
    assert_eq!(tree.remove(&ip(0x0a01_0200), 24), None);
    assert_eq!(tree.lookup(&ip(0x0a01_0204)), Some(&16));
    assert_eq!(tree.lookup(&ip(0x0a01_0203)), Some(&32));
    assert_eq!(tree.lookup(&ip(0x0a01_0280)), Some(&25));
    assert_eq!(tree.get(&ip(0x0a01_0000), 16), Some(&16));
    assert_eq!(tree.get(&ip(0x0a01_0000), 17), None);
}

/// A route out of few places, so that routes lie inside one another and are
/// set and taken out again: two starts, two continuations after each, and a
/// few bits free in every byte after that.
fn some_route<const N: usize>(rng: &mut Rng) -> ([u8; N], u8) {
    let len = rng.below(N as u64 * 8 + 1) as u8;
    let mut address = [0u8; N];
    for (index, byte) in address.iter_mut().enumerate() {
        *byte = match index {
            0 => [0x0a, 0xc0][rng.below(2) as usize],
            1 => [0x01, 0xa8][rng.below(2) as usize],
            _ => [0x00, 0x81][rng.below(2) as usize] | (rng.below(256) as u8 & 0x42),
        };
    }
    (masked(address, len), len)
}

fn assert_answers_as<const N: usize>(tree: &RouteTree<N, u32>, model: &Model<N>, rng: &mut Rng) {
    assert_eq!(tree.len(), model.len());
    let mut addresses: Vec<[u8; N]> = (0..16)
        .map(|_| std::array::from_fn(|_| rng.next() as u8))
        .collect();
    for (&(prefix, len), value) in model {
        assert_eq!(tree.get(&prefix, len), Some(value));
        let last = last(prefix, len);
        addresses.extend([prefix, last, step(prefix, false), step(last, true)]);
    }
    for address in addresses {
        assert_eq!(
            tree.lookup(&address).copied(),
            longest(model, address),
            "{address:?}"
        );
    }
    // Every route is gone through once, and a tree built from them anew is
    // equal though it shares no node.
    let mut seen = Model::new();
    let mut anew = RouteTree::new();
    tree.each(|prefix, len, value| {
        assert_eq!(seen.insert((prefix, len), *value), None);
        anew.insert(&prefix, len, *value);
    });
    assert_eq!(&seen, model);
    assert!(anew == *tree);
    assert!(model.is_empty() || !anew.shares_all_with(tree));
}

fn any_run_of_changes<const N: usize>(seed: u64, rounds: u32, every: u32) {
    let mut rng = Rng(seed);
    let mut tree = RouteTree::<N, u32>::new();
    let mut model = Model::<N>::new();
    // Versions kept from earlier on: later changes must not reach them.
    let mut kept: Vec<(RouteTree<N, u32>, Model<N>)> = Vec::new();
    for round in 0..rounds {
        let (prefix, len) = some_route(&mut rng);
        if rng.below(3) == 0 {
            assert_eq!(tree.remove(&prefix, len), model.remove(&(prefix, len)));
        } else {
            assert_eq!(
                tree.insert(&prefix, len, round),
                model.insert((prefix, len), round)
            );
        }
        if round % every == 0 {
            assert_answers_as(&tree, &model, &mut rng);
        }
        if round % (rounds / 6) == 0 {
            kept.push((tree.clone(), model.clone()));
        }
    }
    assert_answers_as(&tree, &model, &mut rng);
    for (old, model) in &kept {
        assert_answers_as(old, model, &mut rng);
        assert!(old != &tree);
    }
    // Every route taken out again leaves no node but the first.
    for (prefix, len) in model.keys().copied().collect::<Vec<_>>() {
        assert!(tree.remove(&prefix, len).is_some());
    }
    assert!(tree.is_empty());
    assert!(tree.root.is_empty());
    assert!(tree.root.children.is_none());
    assert!(tree.root.places.iter().all(|place| *place == 0));
    assert!(tree == RouteTree::new());
}

#[test]
fn any_run_of_ipv4_changes_answers_as_comparing_every_route_does() {
    any_run_of_changes::<4>(0x7472_6565, 3000, 17);
}

#[test]
fn any_run_of_ipv6_changes_answers_as_comparing_every_route_does() {
    any_run_of_changes::<16>(0x7472_6566, 900, 60);
}

/// The node reached by reading `bytes` of an address.
fn node_at<'a, V>(tree: &'a Ipv4RouteTree<V>, bytes: &[usize]) -> &'a Arc<Node<V>> {
    let mut node = &tree.root;
    for byte in bytes {
        node = node.children.as_ref().unwrap()[*byte].as_ref().unwrap();
    }
    node
}

#[test]
fn a_changed_copy_shares_the_nodes_off_the_way_to_the_change() {
    let mut before = Ipv4RouteTree::new();
    before.insert(&ip(0x0a01_0200), 24, 1);
    before.insert(&ip(0x0a01_0300), 25, 2);
    before.insert(&ip(0x0a02_0000), 24, 3);
    let mut after = before.clone();
    assert!(after.shares_all_with(&before));
    // Taking out a route that is not there copies nothing.
    assert_eq!(after.remove(&ip(0x0a01_0400), 24), None);
    assert!(after.shares_all_with(&before));

    after.insert(&ip(0x0a01_0200), 24, 10);
    assert!(!after.shares_all_with(&before));
    assert!(after != before);
    assert_eq!(before.lookup(&ip(0x0a01_0201)), Some(&1));
    assert_eq!(after.lookup(&ip(0x0a01_0201)), Some(&10));
    // 10.2/16 is off the way: one node, used by both.
    assert!(Arc::ptr_eq(
        node_at(&before, &[10, 2]),
        node_at(&after, &[10, 2])
    ));
    // 10.1/16 is on the way and was copied; 10.1.3/24 below it was not.
    assert!(!Arc::ptr_eq(
        node_at(&before, &[10, 1]),
        node_at(&after, &[10, 1])
    ));
    assert!(Arc::ptr_eq(
        node_at(&before, &[10, 1, 3]),
        node_at(&after, &[10, 1, 3])
    ));
    // Set back, the copy is equal again though its nodes are its own.
    after.insert(&ip(0x0a01_0200), 24, 1);
    assert!(after == before);
    // A change to a tree no other uses is made in place.
    let node = Arc::as_ptr(node_at(&after, &[10, 1]));
    after.insert(&ip(0x0a01_0500), 24, 11);
    assert_eq!(Arc::as_ptr(node_at(&after, &[10, 1])), node);
}

/// Release timing, run on demand:
/// `cargo test --release -p ruster-core route_tree_timing -- --ignored --nocapture`
#[test]
#[ignore = "timing report, not a pass/fail test"]
fn route_tree_timing_up_to_a_full_table() {
    use std::hint::black_box;
    use std::time::Instant;

    for count in [4096u32, 131_072, 1_048_576] {
        let started = Instant::now();
        let mut tree = Ipv4RouteTree::new();
        for index in 0..count {
            tree.insert(&ip(0x1000_0000 + (index << 8)), 24, index);
        }
        let built = started.elapsed();
        let mut rng = Rng(0x7177);
        let addresses: Vec<[u8; 4]> = (0..65_536)
            .map(|_| ip(0x1000_0000 + (rng.next() as u32 % (count << 8))))
            .collect();
        let rounds = 200;
        let started = Instant::now();
        for _ in 0..rounds {
            for address in &addresses {
                black_box(tree.lookup(black_box(address)));
            }
        }
        let lookup_ns = started.elapsed().as_nanos() as f64 / f64::from(rounds * 65_536);
        // One route changes in a copy while the tree before it is still used.
        let rounds = 200;
        let started = Instant::now();
        for round in 0..rounds {
            let mut next = tree.clone();
            next.insert(&ip(0x1000_0000 + ((count / 2) << 8)), 24, round);
            black_box(&next);
        }
        let change = started.elapsed() / rounds;
        println!(
            "{count} /24 routes: all set in {built:?}, LPM {lookup_ns:.1} ns, \
             one route changed in a copy in {change:?}, {} bytes",
            tree.heap_bytes()
        );
    }
    // IPv6: /48s under 2001:db8::/32 and beside it, 262,144 of them.
    let v6 = |index: u32| {
        let mut address = [0u8; 16];
        address[..2].copy_from_slice(&[0x20, 0x01]);
        address[2..6].copy_from_slice(&(0x0db8_0000 + index).to_be_bytes());
        address
    };
    let mut tree = Ipv6RouteTree::new();
    for index in 0..262_144u32 {
        tree.insert(&v6(index), 48, index);
    }
    let mut rng = Rng(0x7177);
    let addresses: Vec<[u8; 16]> = (0..65_536)
        .map(|_| {
            let mut address = v6(rng.next() as u32 % 262_144);
            address[8..].copy_from_slice(&rng.next().to_be_bytes());
            address
        })
        .collect();
    let rounds = 200;
    let started = Instant::now();
    for _ in 0..rounds {
        for address in &addresses {
            black_box(tree.lookup(black_box(address)));
        }
    }
    let lookup_ns = started.elapsed().as_nanos() as f64 / f64::from(rounds * 65_536);
    println!(
        "262144 IPv6 /48 routes: LPM {lookup_ns:.1} ns, {} bytes",
        tree.heap_bytes()
    );
}
