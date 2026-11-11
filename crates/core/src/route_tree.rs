//! IPv4 routes as a tree that a new version shares with the one before it.
//!
//! The tree reads the destination 8 bits at a time: at most four nodes for
//! the longest match, whatever the number of routes. A node holds
//! one answer per value of its bits, so a route shorter than the node's last
//! bit fills every place it covers. The routes a node was filled from are
//! kept beside the places, and a change fills the places it covers again
//! from them.
//!
//! [`Ipv4RouteTree::clone`] copies nothing but the pointer to the first node.
//! A change to a tree whose nodes another tree still uses copies the nodes on
//! the way to the change and leaves the rest shared, so a table of a million
//! routes takes one route's change in the time of copying four nodes. The
//! packet path only reads: no lock, no counter is written.
//!
//! The forwarding path does not use this yet.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::Ipv4Address;

/// The bits each level reads. With 16 bits first the longest match is a fifth
/// faster on a million routes (25 ns for 31 ns), but the first node is 256 KiB
/// in every table, however small, and is copied for every version.
const STRIDES: [u8; 4] = [8, 8, 8, 8];

/// A route inside a node: how many of the node's bits it has, and those bits.
type Own = (u8, u32);

/// The node of the longer routes under one value of a node's bits.
type Child<V> = Option<Arc<Node<V>>>;

#[derive(Clone, Debug)]
struct Node<V> {
    /// The routes that end in this node.
    own: Arc<BTreeMap<Own, V>>,
    /// The longest of `own` that covers each value of the node's bits.
    places: Box<[Option<V>]>,
    /// The nodes of longer routes, one per value of the node's bits. `None`
    /// while there is no longer route at all.
    children: Option<Box<[Child<V>]>>,
    child_count: u32,
}

impl<V: Copy> Node<V> {
    fn new(stride: u8) -> Self {
        Self {
            own: Arc::new(BTreeMap::new()),
            places: vec![None; 1 << stride].into_boxed_slice(),
            children: None,
            child_count: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.own.is_empty() && self.child_count == 0
    }

    /// Fills the places a route of `len` bits at `bits` covers from `own`.
    fn fill(&mut self, stride: u8, (len, bits): Own) {
        // What covers all of them: the longest route no longer than `len`.
        let under = (0..=len)
            .rev()
            .find_map(|shorter| self.own.get(&(shorter, bits >> (len - shorter))));
        let first = (bits as usize) << (stride - len);
        let span = 1usize << (stride - len);
        self.places[first..first + span].fill(under.copied());
        // Then the longer routes inside, shorter ones first.
        for longer in len + 1..=stride {
            let low = bits << (longer - len);
            let high = low + (1 << (longer - len)) - 1;
            for (&(_, inside), value) in self.own.range((longer, low)..=(longer, high)) {
                let first = (inside as usize) << (stride - longer);
                let span = 1usize << (stride - longer);
                self.places[first..first + span].fill(Some(*value));
            }
        }
    }
}

/// IPv4 routes by prefix, answering the longest match.
#[derive(Clone, Debug)]
pub struct Ipv4RouteTree<V> {
    root: Arc<Node<V>>,
    len: usize,
}

impl<V: Copy> Default for Ipv4RouteTree<V> {
    fn default() -> Self {
        Self::new()
    }
}

/// The level a prefix of `len` bits ends in, and the bits read before it.
fn level_of(len: u8) -> (usize, u8) {
    let mut before = 0;
    for (level, stride) in STRIDES.iter().enumerate() {
        if len <= before + stride {
            return (level, before);
        }
        before += stride;
    }
    unreachable!("a prefix is at most 32 bits")
}

/// The `stride` bits of `address` after the first `used`.
fn bits_at(address: u32, used: u8, stride: u8) -> usize {
    ((address << used) >> (32 - stride)) as usize
}

impl<V: Copy> Ipv4RouteTree<V> {
    pub fn new() -> Self {
        Self {
            root: Arc::new(Node::new(STRIDES[0])),
            len: 0,
        }
    }

    /// The number of routes.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The value of the longest route that has `address`.
    #[inline]
    pub fn lookup(&self, address: Ipv4Address) -> Option<V> {
        let address = u32::from_be_bytes(address.octets());
        let mut node = &*self.root;
        let mut used = 0;
        let mut best = None;
        for stride in STRIDES {
            let index = bits_at(address, used, stride);
            if let Some(value) = node.places[index] {
                best = Some(value);
            }
            match node.children.as_ref().and_then(|c| c[index].as_deref()) {
                Some(child) => node = child,
                None => break,
            }
            used += stride;
        }
        best
    }

    /// The value of the route `prefix/len` itself. The bits of `prefix` after
    /// `len` are not looked at. `len` is at most 32.
    pub fn get(&self, prefix: Ipv4Address, len: u8) -> Option<V> {
        let prefix = u32::from_be_bytes(prefix.octets());
        let (level, before) = level_of(len);
        let mut node = &*self.root;
        let mut used = 0;
        for stride in &STRIDES[..level] {
            let index = bits_at(prefix, used, *stride);
            node = node.children.as_ref()?[index].as_deref()?;
            used += stride;
        }
        node.own.get(&own_of(prefix, len, before)).copied()
    }

    /// Sets the route `prefix/len` and returns the value it had. The bits of
    /// `prefix` after `len` are not looked at. `len` is at most 32.
    pub fn insert(&mut self, prefix: Ipv4Address, len: u8, value: V) -> Option<V> {
        let prefix = u32::from_be_bytes(prefix.octets());
        let (level, before) = level_of(len);
        let mut node = Arc::make_mut(&mut self.root);
        let mut used = 0;
        for (at, stride) in STRIDES[..level].iter().enumerate() {
            let index = bits_at(prefix, used, *stride);
            let children = node
                .children
                .get_or_insert_with(|| vec![None; 1 << stride].into_boxed_slice());
            if children[index].is_none() {
                children[index] = Some(Arc::new(Node::new(STRIDES[at + 1])));
                node.child_count += 1;
            }
            let Some(child) = &mut children[index] else {
                unreachable!("the child was just set")
            };
            node = Arc::make_mut(child);
            used += stride;
        }
        let own = own_of(prefix, len, before);
        let had = Arc::make_mut(&mut node.own).insert(own, value);
        node.fill(STRIDES[level], own);
        if had.is_none() {
            self.len += 1;
        }
        had
    }

    /// Takes the route `prefix/len` out and returns the value it had.
    pub fn remove(&mut self, prefix: Ipv4Address, len: u8) -> Option<V> {
        // Looked up first, so that taking out a route that is not there
        // copies no node.
        self.get(prefix, len)?;
        let prefix = u32::from_be_bytes(prefix.octets());
        let (level, before) = level_of(len);
        let own = own_of(prefix, len, before);
        let removed = remove_in(Arc::make_mut(&mut self.root), prefix, 0, level, own);
        self.len -= 1;
        removed
    }

    /// Whether the two trees are one and the same nodes, as a clone and the
    /// tree it was made from are until one of them changes.
    #[cfg(test)]
    fn shares_all_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.root, &other.root)
    }
}

fn own_of(prefix: u32, len: u8, before: u8) -> Own {
    let inside = len - before;
    let bits = if inside == 0 {
        0
    } else {
        (prefix << before) >> (32 - inside)
    };
    (inside, bits)
}

fn remove_in<V: Copy>(
    node: &mut Node<V>,
    prefix: u32,
    at: usize,
    level: usize,
    own: Own,
) -> Option<V> {
    if at == level {
        let removed = Arc::make_mut(&mut node.own).remove(&own);
        node.fill(STRIDES[at], own);
        return removed;
    }
    let used: u8 = STRIDES[..at].iter().sum();
    let index = bits_at(prefix, used, STRIDES[at]);
    let children = node.children.as_mut()?;
    let child = children[index].as_mut()?;
    let removed = remove_in(Arc::make_mut(child), prefix, at + 1, level, own);
    if child.is_empty() {
        children[index] = None;
        node.child_count -= 1;
        if node.child_count == 0 {
            node.children = None;
        }
    }
    removed
}

#[cfg(test)]
mod tests;
