//! Keyed hash chains and lowest-free-slot bitmaps embedded in caller-backed
//! slot arrays (H4b, PERF-001).
//!
//! The resolution tables keep the constructor signatures that take one slot
//! slice per table, so their indexes live inside those slices:
//!
//! - **Chains.** A table of `n` slots has `n` buckets. Slot `i` stores the
//!   head of bucket `i` (a table word) and, as a chain node, the bucket it is
//!   linked in plus previous/next links. A key's bucket is the keyed SipHash
//!   of the key reduced to `0..n` by a multiply-high, so the bucket count need
//!   not be a power of two. Link and unlink touch at most three slots. A walk
//!   visits at most `n` nodes even when the links are corrupt.
//! - **Bitmaps.** A two-level "used" bitmap answers "lowest slot that is not
//!   used" with at most `ceil(n / 4096)` summary words and one leaf word.
//!   Leaf word `w` is stored at slot `w` and summary word `s` at slot
//!   `leaf_words(n) + s`; both counts together never exceed `n`. A set leaf
//!   bit means the slot is used; a set summary bit means its leaf word is
//!   full. All-zero words therefore mean "all free", which is the `EMPTY`
//!   value of every slot type: a table whose entries are all gone is
//!   bit-for-bit back to `EMPTY`.
//!
//! Nothing here allocates. Every walk is bounded by the slot count.

use crate::fixed_directory::{DirectoryHashDomain, DirectoryHashKey};

pub(crate) const INDEX_NONE: u32 = u32::MAX;

/// Chain links of one slot (`bucket == INDEX_NONE` when unlinked).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChainNode {
    bucket: u32,
    prev: u32,
    next: u32,
}

impl ChainNode {
    pub(crate) const UNLINKED: Self = Self {
        bucket: INDEX_NONE,
        prev: INDEX_NONE,
        next: INDEX_NONE,
    };

    pub(crate) const fn is_linked(self) -> bool {
        self.bucket != INDEX_NONE
    }
}

/// An index structure is inconsistent. Callers fail closed before any
/// mutation that depends on the inconsistent part.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IndexCorrupt;

/// Access to one embedded chain of a slot type. A slot type with two chains
/// implements this through two marker types.
pub(crate) trait Chain {
    type Slot;
    fn node(slot: &Self::Slot) -> ChainNode;
    fn node_mut(slot: &mut Self::Slot) -> &mut ChainNode;
    fn head(slot: &Self::Slot) -> u32;
    fn head_mut(slot: &mut Self::Slot) -> &mut u32;
}

/// Outcome of a chain walk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChainWalk {
    /// The first node `visit` accepted.
    pub found: Option<usize>,
    /// Nodes visited (each one slot read).
    pub visited: usize,
}

/// Bucket of `hash` among `slots` buckets (`slots > 0`).
pub(crate) fn bucket_of(hash: u64, slots: usize) -> usize {
    debug_assert!(slots > 0);
    ((u128::from(hash) * slots as u128) >> 64) as usize
}

/// Bucket of a key among `slots` buckets, or `None` for an empty table.
pub(crate) fn key_bucket(
    hash_key: DirectoryHashKey,
    domain: DirectoryHashDomain,
    words: &[u64],
    slots: usize,
) -> Option<usize> {
    (slots != 0).then(|| bucket_of(hash_key.hash_words(domain, words), slots))
}

fn link_index(index: usize) -> u32 {
    let link = u32::try_from(index).expect("validated slot capacity fits u32");
    debug_assert!(link != INDEX_NONE);
    link
}

fn decode(link: u32, slots: usize) -> Option<usize> {
    let index = link as usize;
    (link != INDEX_NONE && index < slots).then_some(index)
}

/// Walks the chain of `bucket` from its head, calling `visit` on every node
/// until it returns true. Visits at most `limit` nodes (and never more than
/// the slot count). A chain longer than `limit`, a link outside the table,
/// or a node of another bucket is `IndexCorrupt`.
pub(crate) fn walk<C: Chain>(
    slots: &[C::Slot],
    bucket: usize,
    limit: usize,
    mut visit: impl FnMut(usize) -> bool,
) -> Result<ChainWalk, IndexCorrupt> {
    let Some(head_slot) = slots.get(bucket) else {
        return Err(IndexCorrupt);
    };
    let mut current = C::head(head_slot);
    let mut previous = INDEX_NONE;
    let mut visited = 0;
    let limit = limit.min(slots.len());
    while current != INDEX_NONE {
        if visited == limit {
            return Err(IndexCorrupt);
        }
        let index = decode(current, slots.len()).ok_or(IndexCorrupt)?;
        let node = C::node(&slots[index]);
        if node.bucket as usize != bucket || node.prev != previous {
            return Err(IndexCorrupt);
        }
        visited += 1;
        if visit(index) {
            return Ok(ChainWalk {
                found: Some(index),
                visited,
            });
        }
        previous = current;
        current = node.next;
    }
    Ok(ChainWalk {
        found: None,
        visited,
    })
}

/// Links the unlinked slot `index` at the head of `bucket`. The current head
/// is checked first; on `IndexCorrupt` nothing changes.
pub(crate) fn link<C: Chain>(
    slots: &mut [C::Slot],
    index: usize,
    bucket: usize,
) -> Result<(), IndexCorrupt> {
    if index >= slots.len() || bucket >= slots.len() || C::node(&slots[index]).is_linked() {
        return Err(IndexCorrupt);
    }
    let head = C::head(&slots[bucket]);
    if head != INDEX_NONE {
        let head_index = decode(head, slots.len()).ok_or(IndexCorrupt)?;
        let node = C::node(&slots[head_index]);
        if node.bucket as usize != bucket || node.prev != INDEX_NONE || head_index == index {
            return Err(IndexCorrupt);
        }
        C::node_mut(&mut slots[head_index]).prev = link_index(index);
    }
    *C::node_mut(&mut slots[index]) = ChainNode {
        bucket: link_index(bucket),
        prev: INDEX_NONE,
        next: head,
    };
    *C::head_mut(&mut slots[bucket]) = link_index(index);
    Ok(())
}

/// Unlinks slot `index` from its chain. Its neighbours are checked first; on
/// `IndexCorrupt` nothing changes. Unlinking an unlinked slot is a no-op.
pub(crate) fn unlink<C: Chain>(slots: &mut [C::Slot], index: usize) -> Result<(), IndexCorrupt> {
    let Some(slot) = slots.get(index) else {
        return Err(IndexCorrupt);
    };
    let node = C::node(slot);
    if !node.is_linked() {
        return Ok(());
    }
    let this = link_index(index);
    let bucket = decode(node.bucket, slots.len()).ok_or(IndexCorrupt)?;
    let prev = match node.prev {
        INDEX_NONE => {
            if C::head(&slots[bucket]) != this {
                return Err(IndexCorrupt);
            }
            None
        }
        link => {
            let prev = decode(link, slots.len()).ok_or(IndexCorrupt)?;
            let prev_node = C::node(&slots[prev]);
            if prev == index || prev_node.next != this || prev_node.bucket != node.bucket {
                return Err(IndexCorrupt);
            }
            Some(prev)
        }
    };
    let next = match node.next {
        INDEX_NONE => None,
        link => {
            let next = decode(link, slots.len()).ok_or(IndexCorrupt)?;
            let next_node = C::node(&slots[next]);
            if next == index || next_node.prev != this || next_node.bucket != node.bucket {
                return Err(IndexCorrupt);
            }
            Some(next)
        }
    };
    match prev {
        Some(prev) => C::node_mut(&mut slots[prev]).next = node.next,
        None => *C::head_mut(&mut slots[bucket]) = node.next,
    }
    if let Some(next) = next {
        C::node_mut(&mut slots[next]).prev = node.prev;
    }
    *C::node_mut(&mut slots[index]) = ChainNode::UNLINKED;
    Ok(())
}

#[cfg(test)]
/// Puts the unlinked slot `new` in the chain position of the linked slot
/// `old`, which becomes unlinked. Every neighbour is checked first; on
/// `IndexCorrupt` nothing changes.
pub(crate) fn replace<C: Chain>(
    slots: &mut [C::Slot],
    old: usize,
    new: usize,
) -> Result<(), IndexCorrupt> {
    if old >= slots.len() || new >= slots.len() || old == new || C::node(&slots[new]).is_linked() {
        return Err(IndexCorrupt);
    }
    let node = C::node(&slots[old]);
    if !node.is_linked() {
        return Err(IndexCorrupt);
    }
    let this = link_index(old);
    let bucket = decode(node.bucket, slots.len()).ok_or(IndexCorrupt)?;
    let prev = match node.prev {
        INDEX_NONE => {
            if C::head(&slots[bucket]) != this {
                return Err(IndexCorrupt);
            }
            None
        }
        link => {
            let prev = decode(link, slots.len()).ok_or(IndexCorrupt)?;
            if prev == old || prev == new || C::node(&slots[prev]).next != this {
                return Err(IndexCorrupt);
            }
            Some(prev)
        }
    };
    let next = match node.next {
        INDEX_NONE => None,
        link => {
            let next = decode(link, slots.len()).ok_or(IndexCorrupt)?;
            if next == old || next == new || C::node(&slots[next]).prev != this {
                return Err(IndexCorrupt);
            }
            Some(next)
        }
    };
    let new_link = link_index(new);
    match prev {
        Some(prev) => C::node_mut(&mut slots[prev]).next = new_link,
        None => *C::head_mut(&mut slots[bucket]) = new_link,
    }
    if let Some(next) = next {
        C::node_mut(&mut slots[next]).prev = new_link;
    }
    *C::node_mut(&mut slots[new]) = node;
    *C::node_mut(&mut slots[old]) = ChainNode::UNLINKED;
    Ok(())
}

#[cfg(test)]
/// Checks every chain of the table: each bucket head walks a well-formed
/// chain of its own bucket, every linked node is reached exactly once, and
/// `expected_bucket(i)` (the bucket slot `i` must be linked in, or `None`)
/// matches. O(n); validation only.
pub(crate) fn validate<C: Chain>(
    slots: &[C::Slot],
    mut expected_bucket: impl FnMut(usize) -> Option<usize>,
) -> bool {
    let mut reached = 0usize;
    for bucket in 0..slots.len() {
        let Ok(walked) = walk::<C>(slots, bucket, slots.len(), |_| false) else {
            return false;
        };
        reached += walked.visited;
    }
    let mut linked = 0usize;
    for (index, slot) in slots.iter().enumerate() {
        let node = C::node(slot);
        let actual = node.is_linked().then_some(node.bucket as usize);
        if actual != expected_bucket(index) {
            return false;
        }
        linked += usize::from(node.is_linked());
    }
    reached == linked
}

#[cfg(test)]
/// Access to the one bitmap word stored in each slot.
pub(crate) trait UsedBits {
    type Slot;
    fn word(slot: &Self::Slot) -> u64;
    fn word_mut(slot: &mut Self::Slot) -> &mut u64;
}

#[cfg(test)]
pub(crate) const fn leaf_words(slots: usize) -> usize {
    slots.div_ceil(64)
}

#[cfg(test)]
pub(crate) const fn summary_words(slots: usize) -> usize {
    let leaves = leaf_words(slots);
    if leaves <= 1 {
        0
    } else {
        leaves.div_ceil(64)
    }
}

#[cfg(test)]
/// Valid bits of leaf word `word`.
fn leaf_mask(slots: usize, word: usize) -> u64 {
    let remaining = slots - word * 64;
    if remaining >= 64 {
        u64::MAX
    } else {
        (1u64 << remaining) - 1
    }
}

#[cfg(test)]
/// Valid bits of summary word `word`.
fn summary_mask(slots: usize, word: usize) -> u64 {
    let remaining = leaf_words(slots) - word * 64;
    if remaining >= 64 {
        u64::MAX
    } else {
        (1u64 << remaining) - 1
    }
}

#[cfg(test)]
/// Marks slot `index` used or unused and keeps the summary in step.
pub(crate) fn set_used<B: UsedBits>(slots: &mut [B::Slot], index: usize, used: bool) {
    let word = index / 64;
    let bit = 1u64 << (index % 64);
    let leaf = B::word_mut(&mut slots[word]);
    if used {
        *leaf |= bit;
    } else {
        *leaf &= !bit;
    }
    let full = *leaf & leaf_mask(slots.len(), word) == leaf_mask(slots.len(), word);
    if summary_words(slots.len()) != 0 {
        let summary_slot = leaf_words(slots.len()) + word / 64;
        let summary_bit = 1u64 << (word % 64);
        let summary = B::word_mut(&mut slots[summary_slot]);
        if full {
            *summary |= summary_bit;
        } else {
            *summary &= !summary_bit;
        }
    }
}

#[cfg(test)]
/// Lowest unused slot and the number of bitmap words read, or `None` when
/// every slot is used. A summary that claims a free leaf word whose bits are
/// all set is `IndexCorrupt`.
pub(crate) fn first_unused<B: UsedBits>(
    slots: &[B::Slot],
) -> Result<(Option<usize>, usize), IndexCorrupt> {
    let n = slots.len();
    if n == 0 {
        return Ok((None, 0));
    }
    let leaf_with_free = if summary_words(n) == 0 {
        Some(0)
    } else {
        let base = leaf_words(n);
        let mut found = None;
        let mut reads = 0;
        for word in 0..summary_words(n) {
            reads += 1;
            let free = !B::word(&slots[base + word]) & summary_mask(n, word);
            if free != 0 {
                found = Some(word * 64 + free.trailing_zeros() as usize);
                break;
            }
        }
        let Some(leaf) = found else {
            return Ok((None, reads));
        };
        let free = !B::word(&slots[leaf]) & leaf_mask(n, leaf);
        if free == 0 {
            return Err(IndexCorrupt);
        }
        return Ok((Some(leaf * 64 + free.trailing_zeros() as usize), reads + 1));
    };
    let leaf = leaf_with_free.expect("single leaf word");
    let free = !B::word(&slots[leaf]) & leaf_mask(n, leaf);
    Ok(((free != 0).then(|| free.trailing_zeros() as usize), 1))
}

#[cfg(test)]
/// Checks that the bitmap marks exactly the slots `used(i)` says are used,
/// that every summary bit matches its leaf word, and that no bit past the
/// table is set. O(n); validation only.
pub(crate) fn validate_bits<B: UsedBits>(
    slots: &[B::Slot],
    mut used: impl FnMut(usize) -> bool,
) -> bool {
    let n = slots.len();
    for (word, slot) in slots.iter().enumerate().take(leaf_words(n)) {
        let mut expected = 0u64;
        for bit in 0..64 {
            let index = word * 64 + bit;
            if index < n && used(index) {
                expected |= 1u64 << bit;
            }
        }
        if B::word(slot) != expected {
            return false;
        }
    }
    let base = leaf_words(n);
    for word in 0..summary_words(n) {
        let mut expected = 0u64;
        for bit in 0..64 {
            let leaf = word * 64 + bit;
            if leaf < leaf_words(n) {
                let mask = leaf_mask(n, leaf);
                if B::word(&slots[leaf]) & mask == mask {
                    expected |= 1u64 << bit;
                }
            }
        }
        if B::word(&slots[base + word]) != expected {
            return false;
        }
    }
    for (index, slot) in slots.iter().enumerate() {
        if index >= base + summary_words(n) && B::word(slot) != 0 {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Slot {
        node: ChainNode,
        head: u32,
        word: u64,
    }

    const EMPTY: Slot = Slot {
        node: ChainNode::UNLINKED,
        head: INDEX_NONE,
        word: 0,
    };

    struct C;
    impl Chain for C {
        type Slot = Slot;
        fn node(slot: &Slot) -> ChainNode {
            slot.node
        }
        fn node_mut(slot: &mut Slot) -> &mut ChainNode {
            &mut slot.node
        }
        fn head(slot: &Slot) -> u32 {
            slot.head
        }
        fn head_mut(slot: &mut Slot) -> &mut u32 {
            &mut slot.head
        }
    }

    struct B;
    impl UsedBits for B {
        type Slot = Slot;
        fn word(slot: &Slot) -> u64 {
            slot.word
        }
        fn word_mut(slot: &mut Slot) -> &mut u64 {
            &mut slot.word
        }
    }

    fn chain(slots: &[Slot], bucket: usize) -> Vec<usize> {
        let mut seen = Vec::new();
        walk::<C>(slots, bucket, slots.len(), |index| {
            seen.push(index);
            false
        })
        .unwrap();
        seen
    }

    #[test]
    fn chains_link_unlink_and_return_to_empty() {
        let mut slots = [EMPTY; 4];
        for index in [0, 1, 2] {
            link::<C>(&mut slots, index, 3).unwrap();
        }
        link::<C>(&mut slots, 3, 0).unwrap();
        assert_eq!(chain(&slots, 3), [2, 1, 0]);
        assert_eq!(chain(&slots, 0), [3]);
        assert!(validate::<C>(&slots, |index| Some(if index == 3 {
            0
        } else {
            3
        })));
        assert_eq!(link::<C>(&mut slots, 1, 0), Err(IndexCorrupt));
        unlink::<C>(&mut slots, 1).unwrap();
        assert_eq!(chain(&slots, 3), [2, 0]);
        unlink::<C>(&mut slots, 2).unwrap();
        unlink::<C>(&mut slots, 0).unwrap();
        unlink::<C>(&mut slots, 3).unwrap();
        unlink::<C>(&mut slots, 3).unwrap();
        assert_eq!(slots, [EMPTY; 4]);
        // Replacing keeps the chain position.
        for index in [0, 1, 2] {
            link::<C>(&mut slots, index, 3).unwrap();
        }
        replace::<C>(&mut slots, 1, 3).unwrap();
        assert_eq!(chain(&slots, 3), [2, 3, 0]);
        replace::<C>(&mut slots, 2, 1).unwrap();
        assert_eq!(chain(&slots, 3), [1, 3, 0]);
        assert_eq!(replace::<C>(&mut slots, 0, 3), Err(IndexCorrupt));
        assert_eq!(replace::<C>(&mut slots, 2, 0), Err(IndexCorrupt));
        for index in [1, 3, 0] {
            unlink::<C>(&mut slots, index).unwrap();
        }
        assert_eq!(slots, [EMPTY; 4]);
        let found = walk::<C>(&slots, 2, 4, |_| true).unwrap();
        assert_eq!(
            found,
            ChainWalk {
                found: None,
                visited: 0
            }
        );
    }

    #[test]
    fn corrupt_chains_fail_closed_without_mutation() {
        let mut slots = [EMPTY; 3];
        link::<C>(&mut slots, 0, 1).unwrap();
        link::<C>(&mut slots, 1, 1).unwrap();
        // A cycle: the tail points back to the head.
        slots[0].node.next = 1;
        assert_eq!(walk::<C>(&slots, 1, 3, |_| false), Err(IndexCorrupt));
        let before = slots;
        assert_eq!(unlink::<C>(&mut slots, 0), Err(IndexCorrupt));
        assert_eq!(slots, before);
        // The limit bounds a well-formed chain too.
        let mut slots = [EMPTY; 3];
        link::<C>(&mut slots, 0, 0).unwrap();
        link::<C>(&mut slots, 1, 0).unwrap();
        assert_eq!(walk::<C>(&slots, 0, 1, |_| false), Err(IndexCorrupt));
        assert_eq!(walk::<C>(&slots, 0, 2, |_| false).unwrap().visited, 2);
        // A head pointing at a node of another bucket.
        slots[2].head = 0;
        let before = slots;
        assert_eq!(link::<C>(&mut slots, 2, 2), Err(IndexCorrupt));
        assert_eq!(slots, before);
        assert!(!validate::<C>(&slots, |index| (index < 2).then_some(0)));
    }

    #[test]
    fn bitmap_finds_the_lowest_unused_slot_like_a_scan() {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        for n in [1, 2, 63, 64, 65, 127, 128, 129, 4095, 4096, 4097, 9000] {
            let mut slots = vec![EMPTY; n];
            let mut used = vec![false; n];
            assert!(validate_bits::<B>(&slots, |index| used[index]));
            for step in 0..(4 * n).min(20_000) {
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let index = (seed >> 33) as usize % n;
                // Fill up mostly, then churn.
                let value = step < n || seed & 1 == 0;
                set_used::<B>(&mut slots, index, value);
                used[index] = value;
                let (found, reads) = first_unused::<B>(&slots).unwrap();
                assert_eq!(found, used.iter().position(|used| !used));
                assert!(reads <= summary_words(n).max(1) + 1);
            }
            assert!(validate_bits::<B>(&slots, |index| used[index]));
            for index in 0..n {
                set_used::<B>(&mut slots, index, true);
            }
            assert_eq!(first_unused::<B>(&slots).unwrap().0, None);
            for index in 0..n {
                set_used::<B>(&mut slots, index, false);
            }
            assert!(slots.iter().all(|slot| *slot == EMPTY));
        }
        assert!(leaf_words(65_536) + summary_words(65_536) <= 65_536);
        assert_eq!(first_unused::<B>(&[]).unwrap(), (None, 0));
    }

    #[test]
    fn bitmap_corruption_is_detected() {
        let mut slots = vec![EMPTY; 200];
        set_used::<B>(&mut slots, 3, true);
        assert!(validate_bits::<B>(&slots, |index| index == 3));
        assert!(!validate_bits::<B>(&slots, |_| false));
        // A summary bit claiming leaf 1 is not full while it is.
        for index in 64..128 {
            set_used::<B>(&mut slots, index, true);
        }
        for index in 0..64 {
            set_used::<B>(&mut slots, index, true);
        }
        let summary = leaf_words(200);
        slots[summary].word &= !0b11;
        assert!(!validate_bits::<B>(&slots, |index| index < 128));
        assert_eq!(first_unused::<B>(&slots), Err(IndexCorrupt));
    }

    #[test]
    fn buckets_cover_the_table() {
        assert_eq!(bucket_of(0, 7), 0);
        assert_eq!(bucket_of(u64::MAX, 7), 6);
        assert_eq!(bucket_of(u64::MAX / 2, 2), 0);
        assert_eq!(bucket_of(u64::MAX / 2 + 1, 2), 1);
    }
}
