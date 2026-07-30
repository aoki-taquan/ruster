//! Caller-backed fixed-capacity lookup primitives.
//!
//! The directory owns no keys or state. Each node index is the corresponding
//! caller state-slot index, while the caller supplies key matching as a
//! monomorphized closure. Buckets and links are caller-owned fixed slices.

const NONE: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryBucket {
    head: u32,
}

impl Default for DirectoryBucket {
    fn default() -> Self {
        Self { head: NONE }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryNode {
    bucket: u32,
    previous: u32,
    next: u32,
}

impl Default for DirectoryNode {
    fn default() -> Self {
        Self {
            bucket: NONE,
            previous: NONE,
            next: NONE,
        }
    }
}

impl DirectoryNode {
    const fn is_linked(self) -> bool {
        self.bucket != NONE
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryConfigError {
    BucketsWithoutNodes,
    NodesWithoutBuckets,
    BucketCountNotPowerOfTwo,
    BucketCountTooSmall,
    CapacityTooLarge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryMutationError {
    StateIndexOutOfRange,
    AlreadyLinked,
    NotLinked,
    Corrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryLookupError {
    InvalidNodeIndex { probes: usize },
    BucketMismatch { probes: usize },
    Cycle { probes: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryProbe {
    pub state_index: Option<usize>,
    pub probes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DirectoryConservation {
    pub linked_nodes: usize,
    pub nonempty_buckets: usize,
    pub max_chain_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryInvariantError {
    InvalidNodeIndex,
    BucketMismatch,
    PreviousMismatch,
    Cycle,
    UnreachableLinkedNode,
}

/// A fixed-capacity chained directory with state-slot-indexed nodes.
///
/// Link and unlink touch a constant number of entries. Lookup visits at most
/// `node_capacity()` nodes, including under collision or corruption.
pub(crate) struct FixedDirectory<'a> {
    buckets: &'a mut [DirectoryBucket],
    nodes: &'a mut [DirectoryNode],
    hash_seed: u64,
}

impl<'a> FixedDirectory<'a> {
    pub(crate) fn new(
        buckets: &'a mut [DirectoryBucket],
        nodes: &'a mut [DirectoryNode],
        hash_seed: u64,
    ) -> Result<Self, DirectoryConfigError> {
        validate_dimensions(buckets.len(), nodes.len())?;
        buckets.fill(DirectoryBucket::default());
        nodes.fill(DirectoryNode::default());
        Ok(Self {
            buckets,
            nodes,
            hash_seed,
        })
    }

    pub(crate) const fn node_capacity(&self) -> usize {
        self.nodes.len()
    }

    pub(crate) const fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    pub(crate) fn clear(&mut self) {
        self.buckets.fill(DirectoryBucket::default());
        self.nodes.fill(DirectoryNode::default());
    }

    pub(crate) fn is_linked(&self, state_index: usize) -> Option<bool> {
        self.nodes.get(state_index).map(|node| node.is_linked())
    }

    pub(crate) fn hash_words(&self, words: &[u64]) -> u64 {
        keyed_hash_words(self.hash_seed, words)
    }

    pub(crate) fn bucket_for_words(&self, words: &[u64]) -> Option<usize> {
        self.bucket_for_hash(self.hash_words(words))
    }

    pub(crate) fn link(
        &mut self,
        state_index: usize,
        words: &[u64],
    ) -> Result<(), DirectoryMutationError> {
        let state = index_to_link(state_index, self.nodes.len())?;
        if self.nodes[state_index].is_linked() {
            return Err(DirectoryMutationError::AlreadyLinked);
        }
        let bucket_index = self
            .bucket_for_words(words)
            .ok_or(DirectoryMutationError::StateIndexOutOfRange)?;
        let bucket = u32::try_from(bucket_index)
            .map_err(|_| DirectoryMutationError::StateIndexOutOfRange)?;
        let old_head = self.buckets[bucket_index].head;
        let old_head_index = if old_head == NONE {
            None
        } else {
            let old_head_index =
                link_to_index(old_head, self.nodes.len()).ok_or(DirectoryMutationError::Corrupt)?;
            let old_head_node = self.nodes[old_head_index];
            if old_head_node.bucket != bucket || old_head_node.previous != NONE {
                return Err(DirectoryMutationError::Corrupt);
            }
            Some(old_head_index)
        };

        self.nodes[state_index] = DirectoryNode {
            bucket,
            previous: NONE,
            next: old_head,
        };
        if let Some(old_head_index) = old_head_index {
            self.nodes[old_head_index].previous = state;
        }
        self.buckets[bucket_index].head = state;
        Ok(())
    }

    pub(crate) fn unlink(&mut self, state_index: usize) -> Result<(), DirectoryMutationError> {
        let state = index_to_link(state_index, self.nodes.len())?;
        let node = self.nodes[state_index];
        if !node.is_linked() {
            return Err(DirectoryMutationError::NotLinked);
        }
        let bucket_index = link_to_index(node.bucket, self.buckets.len())
            .ok_or(DirectoryMutationError::Corrupt)?;
        let previous_index = if node.previous == NONE {
            if self.buckets[bucket_index].head != state {
                return Err(DirectoryMutationError::Corrupt);
            }
            None
        } else {
            let index = link_to_index(node.previous, self.nodes.len())
                .ok_or(DirectoryMutationError::Corrupt)?;
            let previous = self.nodes[index];
            if previous.bucket != node.bucket || previous.next != state {
                return Err(DirectoryMutationError::Corrupt);
            }
            Some(index)
        };
        let next_index = if node.next == NONE {
            None
        } else {
            let index = link_to_index(node.next, self.nodes.len())
                .ok_or(DirectoryMutationError::Corrupt)?;
            let next = self.nodes[index];
            if next.bucket != node.bucket || next.previous != state {
                return Err(DirectoryMutationError::Corrupt);
            }
            Some(index)
        };

        if let Some(index) = previous_index {
            self.nodes[index].next = node.next;
        } else {
            self.buckets[bucket_index].head = node.next;
        }
        if let Some(index) = next_index {
            self.nodes[index].previous = node.previous;
        }
        self.nodes[state_index] = DirectoryNode::default();
        Ok(())
    }

    pub(crate) fn lookup(
        &self,
        words: &[u64],
        mut key_matches: impl FnMut(usize) -> bool,
    ) -> Result<DirectoryProbe, DirectoryLookupError> {
        let Some(bucket_index) = self.bucket_for_words(words) else {
            return Ok(DirectoryProbe {
                state_index: None,
                probes: 0,
            });
        };
        let bucket =
            u32::try_from(bucket_index).expect("validated directory bucket count fits u32");
        let mut current = self.buckets[bucket_index].head;
        let mut probes = 0;
        for _ in 0..self.nodes.len() {
            if current == NONE {
                return Ok(DirectoryProbe {
                    state_index: None,
                    probes,
                });
            }
            let Some(index) = link_to_index(current, self.nodes.len()) else {
                return Err(DirectoryLookupError::InvalidNodeIndex { probes });
            };
            let node = self.nodes[index];
            if node.bucket != bucket {
                return Err(DirectoryLookupError::BucketMismatch { probes });
            }
            probes += 1;
            if key_matches(index) {
                return Ok(DirectoryProbe {
                    state_index: Some(index),
                    probes,
                });
            }
            current = node.next;
        }
        if current == NONE {
            Ok(DirectoryProbe {
                state_index: None,
                probes,
            })
        } else {
            Err(DirectoryLookupError::Cycle { probes })
        }
    }

    pub(crate) fn validate(&self) -> Result<DirectoryConservation, DirectoryInvariantError> {
        let mut report = DirectoryConservation::default();
        for (bucket_index, bucket) in self.buckets.iter().enumerate() {
            if bucket.head == NONE {
                continue;
            }
            report.nonempty_buckets += 1;
            let expected_bucket = u32::try_from(bucket_index)
                .map_err(|_| DirectoryInvariantError::InvalidNodeIndex)?;
            let mut current = bucket.head;
            let mut previous = NONE;
            let mut chain_len = 0;
            for _ in 0..self.nodes.len() {
                if current == NONE {
                    break;
                }
                let index = link_to_index(current, self.nodes.len())
                    .ok_or(DirectoryInvariantError::InvalidNodeIndex)?;
                let node = self.nodes[index];
                if node.bucket != expected_bucket {
                    return Err(DirectoryInvariantError::BucketMismatch);
                }
                if node.previous != previous {
                    return Err(DirectoryInvariantError::PreviousMismatch);
                }
                report.linked_nodes += 1;
                chain_len += 1;
                previous = current;
                current = node.next;
            }
            if current != NONE {
                return Err(DirectoryInvariantError::Cycle);
            }
            report.max_chain_len = report.max_chain_len.max(chain_len);
        }
        let linked_nodes = self.nodes.iter().filter(|node| node.is_linked()).count();
        if linked_nodes != report.linked_nodes {
            return Err(DirectoryInvariantError::UnreachableLinkedNode);
        }
        Ok(report)
    }

    fn bucket_for_hash(&self, hash: u64) -> Option<usize> {
        if self.buckets.is_empty() {
            return None;
        }
        let mask = self.buckets.len() - 1;
        Some((hash as usize) & mask)
    }
}

fn validate_dimensions(bucket_count: usize, node_count: usize) -> Result<(), DirectoryConfigError> {
    if node_count == 0 {
        return if bucket_count == 0 {
            Ok(())
        } else {
            Err(DirectoryConfigError::BucketsWithoutNodes)
        };
    }
    if bucket_count == 0 {
        return Err(DirectoryConfigError::NodesWithoutBuckets);
    }
    if bucket_count > u32::MAX as usize || node_count > u32::MAX as usize {
        return Err(DirectoryConfigError::CapacityTooLarge);
    }
    if !bucket_count.is_power_of_two() {
        return Err(DirectoryConfigError::BucketCountNotPowerOfTwo);
    }
    let minimum = node_count
        .checked_next_power_of_two()
        .ok_or(DirectoryConfigError::CapacityTooLarge)?;
    if bucket_count < minimum {
        return Err(DirectoryConfigError::BucketCountTooSmall);
    }
    Ok(())
}

fn index_to_link(index: usize, capacity: usize) -> Result<u32, DirectoryMutationError> {
    if index >= capacity {
        return Err(DirectoryMutationError::StateIndexOutOfRange);
    }
    u32::try_from(index).map_err(|_| DirectoryMutationError::StateIndexOutOfRange)
}

fn link_to_index(link: u32, capacity: usize) -> Option<usize> {
    let index = usize::try_from(link).ok()?;
    (index < capacity).then_some(index)
}

fn keyed_hash_words(seed: u64, words: &[u64]) -> u64 {
    let key0 = avalanche(seed ^ 0x736f_6d65_7073_6575);
    let key1 = avalanche(seed ^ 0x646f_7261_6e64_6f6d);
    let mut v0 = key0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = key1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = key0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = key1 ^ 0x7465_6462_7974_6573;
    for &word in words {
        v3 ^= word;
        sip_rounds(&mut v0, &mut v1, &mut v2, &mut v3, 2);
        v0 ^= word;
    }
    let final_word = (words.len() as u64).wrapping_mul(8) << 56;
    v3 ^= final_word;
    sip_rounds(&mut v0, &mut v1, &mut v2, &mut v3, 2);
    v0 ^= final_word;
    v2 ^= 0xff;
    sip_rounds(&mut v0, &mut v1, &mut v2, &mut v3, 4);
    v0 ^ v1 ^ v2 ^ v3
}

const fn avalanche(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn sip_rounds(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64, rounds: usize) {
    for _ in 0..rounds {
        *v0 = v0.wrapping_add(*v1);
        *v1 = v1.rotate_left(13);
        *v1 ^= *v0;
        *v0 = v0.rotate_left(32);
        *v2 = v2.wrapping_add(*v3);
        *v3 = v3.rotate_left(16);
        *v3 ^= *v2;
        *v0 = v0.wrapping_add(*v3);
        *v3 = v3.rotate_left(21);
        *v3 ^= *v0;
        *v2 = v2.wrapping_add(*v1);
        *v1 = v1.rotate_left(17);
        *v1 ^= *v2;
        *v2 = v2.rotate_left(32);
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PortOwnerSlot {
    state_index_plus_one: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PortOwnerConfigError {
    ZeroPort,
    InvalidRange,
    SlotCountMismatch,
    StateCapacityTooLarge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PortOwnerError {
    PortOutOfRange,
    StateIndexOutOfRange,
    CorruptOwner,
}

pub(crate) struct PortOwnerTable<'a> {
    slots: &'a mut [PortOwnerSlot],
    first_port: u16,
    last_port: u16,
    state_capacity: usize,
}

impl<'a> PortOwnerTable<'a> {
    pub(crate) fn new(
        slots: &'a mut [PortOwnerSlot],
        first_port: u16,
        last_port: u16,
        state_capacity: usize,
    ) -> Result<Self, PortOwnerConfigError> {
        if first_port == 0 {
            return Err(PortOwnerConfigError::ZeroPort);
        }
        if first_port > last_port {
            return Err(PortOwnerConfigError::InvalidRange);
        }
        let required = (u32::from(last_port) - u32::from(first_port) + 1) as usize;
        if slots.len() != required {
            return Err(PortOwnerConfigError::SlotCountMismatch);
        }
        if state_capacity > u32::MAX as usize {
            return Err(PortOwnerConfigError::StateCapacityTooLarge);
        }
        slots.fill(PortOwnerSlot::default());
        Ok(Self {
            slots,
            first_port,
            last_port,
            state_capacity,
        })
    }

    pub(crate) fn clear(&mut self) {
        self.slots.fill(PortOwnerSlot::default());
    }

    pub(crate) fn owner(&self, port: u16) -> Result<Option<usize>, PortOwnerError> {
        let offset = self.offset(port)?;
        let encoded = self.slots[offset].state_index_plus_one;
        if encoded == 0 {
            return Ok(None);
        }
        let state_index =
            usize::try_from(encoded - 1).map_err(|_| PortOwnerError::StateIndexOutOfRange)?;
        if state_index >= self.state_capacity {
            return Err(PortOwnerError::CorruptOwner);
        }
        Ok(Some(state_index))
    }

    pub(crate) fn assign(&mut self, port: u16, state_index: usize) -> Result<(), PortOwnerError> {
        let offset = self.offset(port)?;
        if state_index >= self.state_capacity {
            return Err(PortOwnerError::StateIndexOutOfRange);
        }
        let encoded = u32::try_from(state_index)
            .map_err(|_| PortOwnerError::StateIndexOutOfRange)?
            .checked_add(1)
            .ok_or(PortOwnerError::StateIndexOutOfRange)?;
        self.slots[offset].state_index_plus_one = encoded;
        Ok(())
    }

    pub(crate) fn clear_if(
        &mut self,
        port: u16,
        state_index: usize,
    ) -> Result<bool, PortOwnerError> {
        let offset = self.offset(port)?;
        if state_index >= self.state_capacity {
            return Err(PortOwnerError::StateIndexOutOfRange);
        }
        let encoded = u32::try_from(state_index)
            .map_err(|_| PortOwnerError::StateIndexOutOfRange)?
            .checked_add(1)
            .ok_or(PortOwnerError::StateIndexOutOfRange)?;
        if self.slots[offset].state_index_plus_one != encoded {
            return Ok(false);
        }
        self.slots[offset] = PortOwnerSlot::default();
        Ok(true)
    }

    fn offset(&self, port: u16) -> Result<usize, PortOwnerError> {
        if !(self.first_port..=self.last_port).contains(&port) {
            return Err(PortOwnerError::PortOutOfRange);
        }
        Ok(usize::from(port - self.first_port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_capacity_is_valid_and_every_operation_is_bounded() {
        let mut buckets = [];
        let mut nodes = [];
        let mut directory = FixedDirectory::new(&mut buckets, &mut nodes, 7).unwrap();
        assert_eq!(directory.node_capacity(), 0);
        assert_eq!(directory.bucket_count(), 0);
        assert_eq!(directory.bucket_for_words(&[1, 2]), None);
        assert_eq!(
            directory.lookup(&[1, 2], |_| true).unwrap(),
            DirectoryProbe {
                state_index: None,
                probes: 0
            }
        );
        assert_eq!(
            directory.link(0, &[1]),
            Err(DirectoryMutationError::StateIndexOutOfRange)
        );
        assert_eq!(
            directory.unlink(0),
            Err(DirectoryMutationError::StateIndexOutOfRange)
        );
        assert_eq!(directory.validate(), Ok(DirectoryConservation::default()));
        directory.clear();
    }

    #[test]
    fn invalid_dimensions_do_not_mutate_caller_storage() {
        let occupied_bucket = DirectoryBucket { head: 9 };
        let occupied_node = DirectoryNode {
            bucket: 1,
            previous: 2,
            next: 3,
        };

        let mut buckets = [occupied_bucket; 1];
        let mut no_nodes = [];
        assert!(matches!(
            FixedDirectory::new(&mut buckets, &mut no_nodes, 0),
            Err(DirectoryConfigError::BucketsWithoutNodes)
        ));
        assert_eq!(buckets, [occupied_bucket; 1]);

        let mut no_buckets = [];
        let mut nodes = [occupied_node; 1];
        assert!(matches!(
            FixedDirectory::new(&mut no_buckets, &mut nodes, 0),
            Err(DirectoryConfigError::NodesWithoutBuckets)
        ));
        assert_eq!(nodes, [occupied_node; 1]);

        let mut non_power = [occupied_bucket; 3];
        let mut nodes = [occupied_node; 2];
        assert!(matches!(
            FixedDirectory::new(&mut non_power, &mut nodes, 0),
            Err(DirectoryConfigError::BucketCountNotPowerOfTwo)
        ));
        assert_eq!(non_power, [occupied_bucket; 3]);
        assert_eq!(nodes, [occupied_node; 2]);

        let mut too_small = [occupied_bucket; 2];
        let mut nodes = [occupied_node; 3];
        assert!(matches!(
            FixedDirectory::new(&mut too_small, &mut nodes, 0),
            Err(DirectoryConfigError::BucketCountTooSmall)
        ));
        assert_eq!(too_small, [occupied_bucket; 2]);
        assert_eq!(nodes, [occupied_node; 3]);
    }

    #[test]
    fn keyed_hash_is_deterministic_seeded_and_tuple_ordered() {
        let words = [0x0102_0304_0506_0708, 0x1112_1314_1516_1718];
        let first = keyed_hash_words(7, &words);
        assert_eq!(first, keyed_hash_words(7, &words));
        assert_ne!(first, keyed_hash_words(8, &words));
        assert_ne!(first, keyed_hash_words(7, &[words[1], words[0]]));
        assert_ne!(first, keyed_hash_words(7, &words[..1]));
    }

    #[test]
    fn collisions_lookup_with_exact_probe_counts_and_no_tombstones() {
        let mut buckets = [DirectoryBucket::default(); 4];
        let mut nodes = [DirectoryNode::default(); 3];
        let mut directory = FixedDirectory::new(&mut buckets, &mut nodes, 11).unwrap();
        let mut keys = [0_u64; 3];
        let target_bucket = directory.bucket_for_words(&[0]).unwrap();
        let mut found = 0;
        for candidate in 0..100 {
            if directory.bucket_for_words(&[candidate]) == Some(target_bucket) {
                keys[found] = candidate;
                found += 1;
                if found == keys.len() {
                    break;
                }
            }
        }
        assert_eq!(found, keys.len());
        for (state_index, key) in keys.into_iter().enumerate() {
            directory.link(state_index, &[key]).unwrap();
        }

        assert_eq!(
            directory.lookup(&[keys[2]], |index| index == 2).unwrap(),
            DirectoryProbe {
                state_index: Some(2),
                probes: 1
            }
        );
        assert_eq!(
            directory.lookup(&[keys[0]], |index| index == 0).unwrap(),
            DirectoryProbe {
                state_index: Some(0),
                probes: 3
            }
        );
        assert_eq!(
            directory.lookup(&[keys[0]], |_| false).unwrap(),
            DirectoryProbe {
                state_index: None,
                probes: 3
            }
        );
        assert_eq!(
            directory.validate().unwrap(),
            DirectoryConservation {
                linked_nodes: 3,
                nonempty_buckets: 1,
                max_chain_len: 3,
            }
        );
    }

    #[test]
    fn unlink_head_middle_tail_is_constant_and_conserves_every_link() {
        let mut buckets = [DirectoryBucket::default(); 4];
        let mut nodes = [DirectoryNode::default(); 3];
        let mut directory = FixedDirectory::new(&mut buckets, &mut nodes, 1).unwrap();
        let key = [9];
        for state_index in 0..3 {
            directory.link(state_index, &key).unwrap();
        }
        assert_eq!(
            directory.link(1, &key),
            Err(DirectoryMutationError::AlreadyLinked)
        );

        directory.unlink(1).unwrap();
        assert_eq!(
            directory.lookup(&key, |index| index == 0).unwrap().probes,
            2
        );
        assert_eq!(directory.validate().unwrap().linked_nodes, 2);

        directory.unlink(2).unwrap();
        assert_eq!(
            directory.lookup(&key, |index| index == 0).unwrap().probes,
            1
        );
        assert_eq!(directory.validate().unwrap().linked_nodes, 1);

        directory.link(1, &key).unwrap();
        directory.link(2, &key).unwrap();
        directory.unlink(0).unwrap();
        assert_eq!(directory.lookup(&key, |_| false).unwrap().probes, 2);
        assert_eq!(directory.validate().unwrap().linked_nodes, 2);
        assert_eq!(directory.unlink(0), Err(DirectoryMutationError::NotLinked));

        directory.unlink(2).unwrap();
        directory.unlink(1).unwrap();
        assert_eq!(directory.validate(), Ok(DirectoryConservation::default()));
        assert!(directory.nodes.iter().all(|node| !node.is_linked()));
        assert!(directory.buckets.iter().all(|bucket| bucket.head == NONE));
    }

    #[test]
    fn corrupt_cycle_and_links_terminate_without_mutating() {
        let mut buckets = [DirectoryBucket::default(); 2];
        let mut nodes = [DirectoryNode::default(); 2];
        let mut directory = FixedDirectory::new(&mut buckets, &mut nodes, 3).unwrap();
        let key = [4];
        directory.link(0, &key).unwrap();
        directory.link(1, &key).unwrap();
        directory.nodes[0].next = 1;
        let before_buckets = [directory.buckets[0], directory.buckets[1]];
        let before_nodes = [directory.nodes[0], directory.nodes[1]];
        assert_eq!(
            directory.lookup(&key, |_| false),
            Err(DirectoryLookupError::Cycle { probes: 2 })
        );
        assert!(matches!(
            directory.validate(),
            Err(DirectoryInvariantError::Cycle | DirectoryInvariantError::PreviousMismatch)
        ));
        assert_eq!(directory.buckets, &before_buckets);
        assert_eq!(directory.nodes, &before_nodes);
    }

    #[test]
    fn mutation_corruption_checks_are_atomic() {
        let mut buckets = [DirectoryBucket::default(); 2];
        let mut nodes = [DirectoryNode::default(); 2];
        let mut directory = FixedDirectory::new(&mut buckets, &mut nodes, 5).unwrap();
        let key = [6];
        directory.link(0, &key).unwrap();
        let bucket = directory.nodes[0].bucket as usize;
        directory.buckets[bucket].head = 1;
        let before_buckets = [directory.buckets[0], directory.buckets[1]];
        let before_nodes = [directory.nodes[0], directory.nodes[1]];
        assert_eq!(directory.unlink(0), Err(DirectoryMutationError::Corrupt));
        assert_eq!(directory.buckets, &before_buckets);
        assert_eq!(directory.nodes, &before_nodes);
    }

    #[test]
    fn port_owner_range_assignment_conditional_clear_and_validation_are_exact() {
        let mut slots = [PortOwnerSlot::default(); 3];
        let mut owners = PortOwnerTable::new(&mut slots, 40_000, 40_002, 2).unwrap();
        assert_eq!(owners.owner(40_000), Ok(None));
        owners.assign(40_000, 1).unwrap();
        assert_eq!(owners.owner(40_000), Ok(Some(1)));
        assert_eq!(owners.clear_if(40_000, 0), Ok(false));
        assert_eq!(owners.owner(40_000), Ok(Some(1)));
        assert_eq!(owners.clear_if(40_000, 1), Ok(true));
        assert_eq!(owners.owner(40_000), Ok(None));
        assert_eq!(
            owners.assign(40_001, 2),
            Err(PortOwnerError::StateIndexOutOfRange)
        );
        assert_eq!(owners.owner(39_999), Err(PortOwnerError::PortOutOfRange));
        owners.assign(40_002, 0).unwrap();
        owners.clear();
        assert_eq!(owners.owner(40_002), Ok(None));
    }

    #[test]
    fn invalid_port_owner_configuration_is_atomic() {
        let occupied = PortOwnerSlot {
            state_index_plus_one: 7,
        };
        let mut zero = [occupied; 1];
        assert!(matches!(
            PortOwnerTable::new(&mut zero, 0, 0, 1),
            Err(PortOwnerConfigError::ZeroPort)
        ));
        assert_eq!(zero, [occupied; 1]);

        let mut reversed = [occupied; 1];
        assert!(matches!(
            PortOwnerTable::new(&mut reversed, 40_001, 40_000, 1),
            Err(PortOwnerConfigError::InvalidRange)
        ));
        assert_eq!(reversed, [occupied; 1]);

        let mut wrong_len = [occupied; 1];
        assert!(matches!(
            PortOwnerTable::new(&mut wrong_len, 40_000, 40_001, 1),
            Err(PortOwnerConfigError::SlotCountMismatch)
        ));
        assert_eq!(wrong_len, [occupied; 1]);
    }

    #[test]
    fn corrupt_port_owner_is_reported_without_mutation() {
        let mut slots = [PortOwnerSlot::default(); 1];
        let owners = PortOwnerTable::new(&mut slots, 40_000, 40_000, 1).unwrap();
        owners.slots[0].state_index_plus_one = 2;
        let before = owners.slots[0];
        assert_eq!(owners.owner(40_000), Err(PortOwnerError::CorruptOwner));
        assert_eq!(owners.slots[0], before);
    }
}
