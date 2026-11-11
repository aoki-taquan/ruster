//! Routes by prefix as a tree that a new version shares with the one before
//! it, for IPv4 (4 bytes) and IPv6 (16 bytes).
//!
//! The tree reads the destination one byte at a time: at most one node per
//! byte for the longest match, whatever the number of routes. A node keeps
//! the routes that end in it, at most 511 (the prefixes of one to eight bits
//! of its byte; the first node has the route of no bits too), and for each of
//! the byte's 256 values the place of the longest of them in that list. A
//! change to the list fills the 256 places again.
//!
//! [`RouteTree::clone`] copies nothing but the pointer to the first node. A
//! change to a tree whose nodes another tree still uses copies the nodes on
//! the way to the change and leaves the rest shared, so a table of a million
//! routes takes one route's change in the time of copying four nodes. The
//! packet path only reads: no lock, no counter is written.
//!
//! [`crate::ValidatedForwardingOwner`] and [`crate::Ipv6Fib`] build one from
//! their routes for the longest match. They build the whole tree for every
//! version still.

use std::sync::Arc;

/// IPv4 routes by prefix.
pub type Ipv4RouteTree<V> = RouteTree<4, V>;

/// IPv6 routes by prefix.
pub type Ipv6RouteTree<V> = RouteTree<16, V>;

/// The node of the longer routes under one value of a node's byte.
type Child<V> = Option<Arc<Node<V>>>;

/// A route inside a node: how many bits of the node's byte it has, in the
/// high byte, and those bits, in the low one. Shorter routes sort first.
type Own = u16;

#[derive(Clone, Debug)]
struct Node<V> {
    /// The routes that end in this node, sorted.
    own: Vec<(Own, V)>,
    /// For each value of the node's byte, one more than the index in `own`
    /// of the longest route that covers it, or 0.
    places: [u16; 256],
    /// The nodes of longer routes. `None` while there is no longer route.
    children: Option<Box<[Child<V>]>>,
    child_count: u32,
}

impl<V> Node<V> {
    fn new() -> Self {
        Self {
            own: Vec::new(),
            places: [0; 256],
            children: None,
            child_count: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.own.is_empty() && self.child_count == 0
    }

    fn child(&self, byte: u8) -> Option<&Node<V>> {
        self.children.as_ref()?[usize::from(byte)].as_deref()
    }

    /// Fills the places from `own`: the shorter routes first, so that a
    /// longer one ends on top.
    fn fill(&mut self) {
        self.places = [0; 256];
        for (index, (own, _)) in self.own.iter().enumerate() {
            let (len, bits) = (own >> 8, usize::from(own & 0xff));
            let first = bits << (8 - len);
            let span = 1usize << (8 - len);
            self.places[first..first + span].fill(index as u16 + 1);
        }
    }

    /// Puts `value` into `own` at index `at` and brings the places up to
    /// date. The routes at lower indexes are shorter or beside the new one,
    /// so the new one goes on top of those; the ones after it move up by one.
    fn insert_own(&mut self, at: usize, own: Own, value: V) {
        self.own.insert(at, (own, value));
        let at = at as u16;
        for place in &mut self.places {
            *place += u16::from(*place > at);
        }
        let (len, bits) = (own >> 8, usize::from(own & 0xff));
        let first = bits << (8 - len);
        for place in &mut self.places[first..first + (1usize << (8 - len))] {
            if *place <= at {
                *place = at + 1;
            }
        }
    }

    fn heap_bytes(&self) -> usize {
        use std::mem::{size_of, size_of_val};
        let below: usize = self
            .children
            .iter()
            .flat_map(|children| children.iter().flatten())
            .map(|child| child.heap_bytes())
            .sum();
        size_of::<Self>()
            + self.own.capacity() * size_of::<(Own, V)>()
            + self.children.as_deref().map_or(0, size_of_val)
            + below
    }

    fn each<const N: usize>(
        &self,
        prefix: &mut [u8; N],
        level: usize,
        visit: &mut impl FnMut([u8; N], u8, &V),
    ) {
        for (own, value) in &self.own {
            let (len, bits) = ((own >> 8) as u8, (own & 0xff) as u8);
            prefix[level] = if len == 0 { 0 } else { bits << (8 - len) };
            visit(*prefix, level as u8 * 8 + len, value);
        }
        for (byte, child) in self.children.iter().flat_map(|c| c.iter().enumerate()) {
            if let Some(child) = child {
                prefix[level] = byte as u8;
                child.each(prefix, level + 1, visit);
            }
        }
        if level < N {
            prefix[level] = 0;
        }
    }
}

/// Two nodes hold the same routes. Nodes that are one and the same are not
/// gone through, so a tree and a changed copy of it compare in the time of
/// the change.
impl<V: PartialEq> PartialEq for Node<V> {
    fn eq(&self, other: &Self) -> bool {
        self.own == other.own
            && self.child_count == other.child_count
            && match (&self.children, &other.children) {
                (None, None) => true,
                (Some(a), Some(b)) => a.iter().zip(b.iter()).all(|pair| match pair {
                    (None, None) => true,
                    (Some(a), Some(b)) => Arc::ptr_eq(a, b) || a == b,
                    _ => false,
                }),
                _ => false,
            }
    }
}

/// Routes by prefix of `N` bytes, answering the longest match.
#[derive(Clone, Debug)]
pub struct RouteTree<const N: usize, V> {
    root: Arc<Node<V>>,
    len: usize,
}

impl<const N: usize, V> Default for RouteTree<N, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, V: PartialEq> PartialEq for RouteTree<N, V> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && (Arc::ptr_eq(&self.root, &other.root) || self.root == other.root)
    }
}

impl<const N: usize, V: Eq> Eq for RouteTree<N, V> {}

/// The node a prefix of `len` bits ends in, counted from the first, and the
/// prefix inside that node.
fn place_of<const N: usize>(prefix: &[u8; N], len: u8) -> (usize, Own) {
    assert!(usize::from(len) <= N * 8, "a prefix of {len} bits");
    if len == 0 {
        return (0, 0);
    }
    let level = usize::from(len - 1) / 8;
    let inside = len - level as u8 * 8;
    let bits = prefix[level] >> (8 - inside);
    (level, u16::from(inside) << 8 | u16::from(bits))
}

impl<const N: usize, V> RouteTree<N, V> {
    pub fn new() -> Self {
        Self {
            root: Arc::new(Node::new()),
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
    pub fn lookup(&self, address: &[u8; N]) -> Option<&V> {
        self.lookup_counted(address).0
    }

    /// [`Self::lookup`], and the number of nodes read for it.
    #[inline]
    pub(crate) fn lookup_counted(&self, address: &[u8; N]) -> (Option<&V>, u32) {
        let mut node = &*self.root;
        let mut best: Option<(&Node<V>, u16)> = None;
        let mut read = 0;
        for byte in address {
            read += 1;
            let place = node.places[usize::from(*byte)];
            if place != 0 {
                best = Some((node, place));
            }
            match node.child(*byte) {
                Some(child) => node = child,
                None => break,
            }
        }
        let value = best.map(|(node, place)| &node.own[usize::from(place) - 1].1);
        (value, read)
    }

    /// The value of the route `prefix/len` itself. The bits of `prefix` after
    /// `len` are not looked at.
    ///
    /// # Panics
    ///
    /// When `len` is more than the bits of `N` bytes.
    pub fn get(&self, prefix: &[u8; N], len: u8) -> Option<&V> {
        let (level, own) = place_of(prefix, len);
        let mut node = &*self.root;
        for byte in &prefix[..level] {
            node = node.child(*byte)?;
        }
        let at = node.own.binary_search_by_key(&own, |(own, _)| *own).ok()?;
        Some(&node.own[at].1)
    }

    /// Calls `visit` with every route: its prefix, its length and its value.
    pub fn each(&self, mut visit: impl FnMut([u8; N], u8, &V)) {
        self.root.each(&mut [0; N], 0, &mut visit);
    }

    /// About the heap bytes the tree holds, counting a node other trees share
    /// too in full. Goes through every node.
    pub fn heap_bytes(&self) -> usize {
        self.root.heap_bytes()
    }

    /// Whether the two trees are one and the same nodes, as a clone and the
    /// tree it was made from are until one of them changes.
    pub fn shares_all_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.root, &other.root)
    }
}

impl<const N: usize, V: Clone> RouteTree<N, V> {
    /// Sets the route `prefix/len` and returns the value it had. The bits of
    /// `prefix` after `len` are not looked at.
    ///
    /// # Panics
    ///
    /// When `len` is more than the bits of `N` bytes.
    pub fn insert(&mut self, prefix: &[u8; N], len: u8, value: V) -> Option<V> {
        let (level, own) = place_of(prefix, len);
        let mut node = Arc::make_mut(&mut self.root);
        for byte in &prefix[..level] {
            let children = node
                .children
                .get_or_insert_with(|| vec![None; 256].into_boxed_slice());
            let child = &mut children[usize::from(*byte)];
            if child.is_none() {
                node.child_count += 1;
            }
            node = Arc::make_mut(child.get_or_insert_with(|| Arc::new(Node::new())));
        }
        match node.own.binary_search_by_key(&own, |(own, _)| *own) {
            Ok(at) => Some(std::mem::replace(&mut node.own[at].1, value)),
            Err(at) => {
                node.insert_own(at, own, value);
                self.len += 1;
                None
            }
        }
    }

    /// Takes the route `prefix/len` out and returns the value it had.
    ///
    /// # Panics
    ///
    /// When `len` is more than the bits of `N` bytes.
    pub fn remove(&mut self, prefix: &[u8; N], len: u8) -> Option<V> {
        // Looked up first, so that taking out a route that is not there
        // copies no node.
        self.get(prefix, len)?;
        let (level, own) = place_of(prefix, len);
        let removed = remove_in(Arc::make_mut(&mut self.root), &prefix[..level], own);
        self.len -= 1;
        removed
    }
}

fn remove_in<V: Clone>(node: &mut Node<V>, path: &[u8], own: Own) -> Option<V> {
    let Some((byte, rest)) = path.split_first() else {
        let at = node.own.binary_search_by_key(&own, |(own, _)| *own).ok()?;
        let (_, removed) = node.own.remove(at);
        node.fill();
        return Some(removed);
    };
    let children = node.children.as_mut()?;
    let child = children[usize::from(*byte)].as_mut()?;
    let removed = remove_in(Arc::make_mut(child), rest, own);
    if child.is_empty() {
        children[usize::from(*byte)] = None;
        node.child_count -= 1;
        if node.child_count == 0 {
            node.children = None;
        }
    }
    removed
}

#[cfg(test)]
mod tests;
