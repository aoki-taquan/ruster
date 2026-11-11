use std::collections::BTreeMap;

use super::*;

fn ip(address: u32) -> Ipv4Address {
    Ipv4Address::from_octets(address.to_be_bytes())
}

fn mask(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - len)
    }
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

/// The routes as a plain map, searched by comparing every one.
type Model = BTreeMap<(u32, u8), u32>;

fn longest(model: &Model, address: u32) -> Option<u32> {
    model
        .iter()
        .filter(|((prefix, len), _)| address & mask(*len) == *prefix)
        .max_by_key(|((_, len), _)| *len)
        .map(|(_, value)| *value)
}

#[test]
fn the_longest_route_that_has_the_address_answers() {
    let mut tree = Ipv4RouteTree::new();
    assert_eq!(tree.lookup(ip(0x0a01_0203)), None);
    for (prefix, len, value) in [
        (0, 0, 0),
        (0x0a00_0000, 8, 8),
        (0x0a01_0000, 16, 16),
        (0x0a01_8000, 17, 17),
        (0x0a01_0200, 24, 24),
        (0x0a01_0280, 25, 25),
        (0x0a01_0203, 32, 32),
    ] {
        assert_eq!(tree.insert(ip(prefix), len, value), None);
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
        assert_eq!(tree.lookup(ip(address)), Some(value), "{address:#x}");
    }
    // A route set again gives back the value it had, and the count stays.
    assert_eq!(tree.insert(ip(0x0a01_0200), 24, 240), Some(24));
    assert_eq!(tree.len(), 7);
    assert_eq!(tree.lookup(ip(0x0a01_0204)), Some(240));
    // Taken out, the shorter route under it answers again.
    assert_eq!(tree.remove(ip(0x0a01_0200), 24), Some(240));
    assert_eq!(tree.remove(ip(0x0a01_0200), 24), None);
    assert_eq!(tree.lookup(ip(0x0a01_0204)), Some(16));
    assert_eq!(tree.lookup(ip(0x0a01_0203)), Some(32));
    assert_eq!(tree.lookup(ip(0x0a01_0280)), Some(25));
    assert_eq!(tree.get(ip(0x0a01_0000), 16), Some(16));
    assert_eq!(tree.get(ip(0x0a01_0000), 17), None);
}

/// A route out of few places, so that routes lie inside one another and are
/// set and taken out again.
fn some_route(rng: &mut Rng) -> (u32, u8) {
    let len = match rng.below(10) {
        0 => rng.below(9) as u8,
        1..=2 => 9 + rng.below(8) as u8,
        3..=6 => 17 + rng.below(8) as u8,
        _ => 25 + rng.below(8) as u8,
    };
    // Two /16s, two /24s in each, and a few bits free at the end.
    let address = [0x0a01_0000u32, 0xc0a8_0000][rng.below(2) as usize]
        | [0x0000u32, 0x8100][rng.below(2) as usize]
        | (rng.below(256) as u32 & 0xc7);
    (address & mask(len), len)
}

fn assert_answers_as(tree: &Ipv4RouteTree<u32>, model: &Model, rng: &mut Rng) {
    assert_eq!(tree.len(), model.len());
    let mut addresses: Vec<u32> = (0..16).map(|_| rng.next() as u32).collect();
    for (&(prefix, len), value) in model {
        assert_eq!(tree.get(ip(prefix), len), Some(*value));
        let last = prefix | !mask(len);
        addresses.extend([prefix, last, prefix.wrapping_sub(1), last.wrapping_add(1)]);
    }
    for address in addresses {
        assert_eq!(
            tree.lookup(ip(address)),
            longest(model, address),
            "{address:#x}"
        );
    }
}

#[test]
fn any_run_of_changes_answers_as_comparing_every_route_does() {
    let mut rng = Rng(0x7472_6565);
    let mut tree = Ipv4RouteTree::new();
    let mut model = Model::new();
    // Versions kept from earlier on: later changes must not reach them.
    let mut kept: Vec<(Ipv4RouteTree<u32>, Model)> = Vec::new();
    for round in 0..4000u32 {
        let (prefix, len) = some_route(&mut rng);
        if rng.below(3) == 0 {
            assert_eq!(tree.remove(ip(prefix), len), model.remove(&(prefix, len)));
        } else {
            assert_eq!(
                tree.insert(ip(prefix), len, round),
                model.insert((prefix, len), round)
            );
        }
        if round % 7 == 0 {
            assert_answers_as(&tree, &model, &mut rng);
        }
        if round % 500 == 0 {
            kept.push((tree.clone(), model.clone()));
        }
    }
    assert_answers_as(&tree, &model, &mut rng);
    for (tree, model) in &kept {
        assert_answers_as(tree, model, &mut rng);
    }
    // Every route taken out again leaves no node but the first.
    for (prefix, len) in model.keys().copied().collect::<Vec<_>>() {
        assert!(tree.remove(ip(prefix), len).is_some());
    }
    assert!(tree.is_empty());
    assert!(tree.root.is_empty());
    assert!(tree.root.children.is_none());
    assert!(tree.root.places.iter().all(Option::is_none));
}

fn child<V>(node: &Node<V>, index: usize) -> &Arc<Node<V>> {
    node.children.as_ref().unwrap()[index].as_ref().unwrap()
}

#[test]
fn a_changed_copy_shares_the_nodes_off_the_way_to_the_change() {
    let mut before = Ipv4RouteTree::new();
    before.insert(ip(0x0a01_0200), 24, 1);
    before.insert(ip(0x0a01_0300), 25, 2);
    before.insert(ip(0x0a02_0000), 24, 3);
    let mut after = before.clone();
    assert!(after.shares_all_with(&before));
    // Taking out a route that is not there copies nothing.
    assert_eq!(after.remove(ip(0x0a01_0400), 24), None);
    assert!(after.shares_all_with(&before));

    after.insert(ip(0x0a01_0200), 24, 10);
    assert!(!after.shares_all_with(&before));
    assert_eq!(before.lookup(ip(0x0a01_0201)), Some(1));
    assert_eq!(after.lookup(ip(0x0a01_0201)), Some(10));
    // 10.2/16 is off the way: one node, used by both.
    assert!(Arc::ptr_eq(
        child(&before.root, 0x0a02),
        child(&after.root, 0x0a02)
    ));
    // 10.1/16 is on the way and was copied; 10.1.3/24 below it was not.
    let (old, new) = (child(&before.root, 0x0a01), child(&after.root, 0x0a01));
    assert!(!Arc::ptr_eq(old, new));
    assert!(Arc::ptr_eq(child(old, 3), child(new, 3)));
    // A change to a tree no other uses is made in place.
    let node = Arc::as_ptr(child(&after.root, 0x0a01));
    after.insert(ip(0x0a01_0500), 24, 11);
    assert_eq!(Arc::as_ptr(child(&after.root, 0x0a01)), node);
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
            tree.insert(ip(0x1000_0000 + (index << 8)), 24, index);
        }
        let built = started.elapsed();
        let mut rng = Rng(0x7177);
        let addresses: Vec<Ipv4Address> = (0..65_536)
            .map(|_| ip(0x1000_0000 + (rng.next() as u32 % (count << 8))))
            .collect();
        let rounds = 200;
        let started = Instant::now();
        for _ in 0..rounds {
            for address in &addresses {
                black_box(tree.lookup(black_box(*address)));
            }
        }
        let lookup_ns = started.elapsed().as_nanos() as f64 / f64::from(rounds * 65_536);
        // One route changes in a copy while the tree before it is still used.
        let rounds = 200;
        let started = Instant::now();
        for round in 0..rounds {
            let mut next = tree.clone();
            next.insert(ip(0x1000_0000 + ((count / 2) << 8)), 24, round);
            black_box(&next);
        }
        let change = started.elapsed() / rounds;
        println!(
            "{count} /24 routes: all set in {built:?}, LPM {lookup_ns:.1} ns, \
             one route changed in a copy in {change:?}"
        );
    }
}
