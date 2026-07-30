//! Caller-backed fixed-capacity lookup primitives.
//!
//! The directory owns no keys or state. Each node index is the corresponding
//! caller state-slot index, while the caller supplies key matching as a
//! monomorphized closure. Buckets and links are caller-owned fixed slices.
//! Hash inputs are fixed-width `u64` fields in their documented tuple order;
//! callers must include a state generation as its own field when it is part of
//! identity.

const NONE: u32 = u32::MAX;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct DirectoryHashKey {
    first: u64,
    second: u64,
}

impl std::fmt::Debug for DirectoryHashKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DirectoryHashKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryHashKeyError {
    AllZero,
}

impl DirectoryHashKey {
    /// Builds an independently generated keyed-hash secret.
    ///
    /// This key must come from an unpredictable runtime source. In particular,
    /// callers must not derive it from an allocator seed or a public counter.
    pub(crate) const fn new(first: u64, second: u64) -> Result<Self, DirectoryHashKeyError> {
        if first == 0 && second == 0 {
            return Err(DirectoryHashKeyError::AllZero);
        }
        Ok(Self { first, second })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub(crate) enum DirectoryHashDomain {
    UdpMapping = 0x4e41_5434_554d_4150,
    UdpPeer = 0x4e41_5434_5550_4545,
    TcpMapping = 0x4e41_5434_544d_4150,
    TcpSession = 0x4e41_5434_5453_4553,
}

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
    hash: u64,
    bucket: u32,
    previous: u32,
    next: u32,
}

impl Default for DirectoryNode {
    fn default() -> Self {
        Self {
            hash: 0,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectorySemanticError {
    Structural(DirectoryInvariantError),
    DeadStateLinked { state_index: usize },
    LiveStateUnlinked { state_index: usize },
    KeyHashMismatch { state_index: usize },
    KeyBucketMismatch { state_index: usize },
}

/// A fixed-capacity chained directory with state-slot-indexed nodes.
///
/// Link and unlink touch a constant number of entries. Lookup visits at most
/// `node_capacity()` nodes, including under collision or corruption.
pub(crate) struct FixedDirectory<'a> {
    buckets: &'a mut [DirectoryBucket],
    nodes: &'a mut [DirectoryNode],
    hash_key: DirectoryHashKey,
}

impl<'a> FixedDirectory<'a> {
    pub(crate) fn new(
        buckets: &'a mut [DirectoryBucket],
        nodes: &'a mut [DirectoryNode],
        hash_key: DirectoryHashKey,
    ) -> Result<Self, DirectoryConfigError> {
        validate_dimensions(buckets.len(), nodes.len())?;
        buckets.fill(DirectoryBucket::default());
        nodes.fill(DirectoryNode::default());
        Ok(Self {
            buckets,
            nodes,
            hash_key,
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

    pub(crate) fn hash_words(&self, domain: DirectoryHashDomain, words: &[u64]) -> u64 {
        keyed_hash_words(self.hash_key, domain, words)
    }

    pub(crate) fn bucket_for_words(
        &self,
        domain: DirectoryHashDomain,
        words: &[u64],
    ) -> Option<usize> {
        self.bucket_for_hash(self.hash_words(domain, words))
    }

    pub(crate) fn link(
        &mut self,
        state_index: usize,
        domain: DirectoryHashDomain,
        words: &[u64],
    ) -> Result<(), DirectoryMutationError> {
        let state = index_to_link(state_index, self.nodes.len())?;
        if self.nodes[state_index].is_linked() {
            return Err(DirectoryMutationError::AlreadyLinked);
        }
        let hash = self.hash_words(domain, words);
        let bucket_index = self
            .bucket_for_hash(hash)
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
            hash,
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
        if node.previous == state
            || node.next == state
            || (node.previous != NONE && node.previous == node.next)
        {
            return Err(DirectoryMutationError::Corrupt);
        }
        let previous_index = if node.previous == NONE {
            if self.buckets[bucket_index].head != state {
                return Err(DirectoryMutationError::Corrupt);
            }
            None
        } else {
            let index = link_to_index(node.previous, self.nodes.len())
                .ok_or(DirectoryMutationError::Corrupt)?;
            let previous = self.nodes[index];
            if index == state_index
                || previous.bucket != node.bucket
                || previous.next != state
                || previous.previous == state
                || (previous.previous != NONE
                    && (previous.previous == node.previous || previous.previous == node.next))
            {
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
            if index == state_index
                || next.bucket != node.bucket
                || next.previous != state
                || next.next == state
                || (next.next != NONE && (next.next == node.previous || next.next == node.next))
            {
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
        domain: DirectoryHashDomain,
        words: &[u64],
        mut key_matches: impl FnMut(usize) -> bool,
    ) -> Result<DirectoryProbe, DirectoryLookupError> {
        let hash = self.hash_words(domain, words);
        let Some(bucket_index) = self.bucket_for_hash(hash) else {
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
            if node.hash == hash && key_matches(index) {
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

    /// Checks structural conservation plus the caller's live/dead and key view.
    ///
    /// The callback is invoked exactly once for every state slot. A returned
    /// hash declares that slot live and must be computed with `hash_words`.
    pub(crate) fn validate_semantics(
        &self,
        mut expected_hash: impl FnMut(usize) -> Option<u64>,
    ) -> Result<DirectoryConservation, DirectorySemanticError> {
        let report = self
            .validate()
            .map_err(DirectorySemanticError::Structural)?;
        for (state_index, node) in self.nodes.iter().copied().enumerate() {
            match (expected_hash(state_index), node.is_linked()) {
                (None, false) => {}
                (None, true) => {
                    return Err(DirectorySemanticError::DeadStateLinked { state_index });
                }
                (Some(_), false) => {
                    return Err(DirectorySemanticError::LiveStateUnlinked { state_index });
                }
                (Some(hash), true) => {
                    if node.hash != hash {
                        return Err(DirectorySemanticError::KeyHashMismatch { state_index });
                    }
                    if self.bucket_for_hash(hash) != Some(node.bucket as usize) {
                        return Err(DirectorySemanticError::KeyBucketMismatch { state_index });
                    }
                }
            }
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

fn keyed_hash_words(key: DirectoryHashKey, domain: DirectoryHashDomain, words: &[u64]) -> u64 {
    let mut v0 = key.first ^ 0x736f_6d65_7073_6575;
    let mut v1 = key.second ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = key.first ^ 0x6c79_6765_6e65_7261;
    let mut v3 = key.second ^ 0x7465_6462_7974_6573;
    for word in core::iter::once(domain as u64).chain(words.iter().copied()) {
        v3 ^= word;
        sip_rounds(&mut v0, &mut v1, &mut v2, &mut v3, 2);
        v0 ^= word;
    }
    // The domain is the first canonical word and the exact tuple length is the
    // final canonical word. This prevents cross-domain and prefix ambiguity.
    let final_word = 0x8000_0000_0000_0000 ^ (words.len() as u64);
    v3 ^= final_word;
    sip_rounds(&mut v0, &mut v1, &mut v2, &mut v3, 2);
    v0 ^= final_word;
    v2 ^= 0xff;
    sip_rounds(&mut v0, &mut v1, &mut v2, &mut v3, 4);
    v0 ^ v1 ^ v2 ^ v3
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
    state_generation: u64,
    runtime_epoch: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PortOwnerToken {
    state_index: u32,
    state_generation: u64,
    runtime_epoch: u128,
}

impl PortOwnerToken {
    pub(crate) fn new(
        state_index: usize,
        state_generation: u64,
        runtime_epoch: u128,
    ) -> Result<Self, PortOwnerError> {
        let state_index =
            u32::try_from(state_index).map_err(|_| PortOwnerError::StateIndexOutOfRange)?;
        Ok(Self {
            state_index,
            state_generation,
            runtime_epoch,
        })
    }

    pub(crate) const fn state_index(self) -> usize {
        self.state_index as usize
    }

    pub(crate) const fn state_generation(self) -> u64 {
        self.state_generation
    }

    pub(crate) const fn runtime_epoch(self) -> u128 {
        self.runtime_epoch
    }
}

impl PortOwnerSlot {
    fn from_token(token: PortOwnerToken) -> Result<Self, PortOwnerError> {
        let state_index_plus_one = token
            .state_index
            .checked_add(1)
            .ok_or(PortOwnerError::StateIndexOutOfRange)?;
        Ok(Self {
            state_index_plus_one,
            state_generation: token.state_generation,
            runtime_epoch: token.runtime_epoch,
        })
    }

    fn token(self) -> Result<Option<PortOwnerToken>, PortOwnerError> {
        if self.state_index_plus_one == 0 {
            return if self.state_generation == 0 && self.runtime_epoch == 0 {
                Ok(None)
            } else {
                Err(PortOwnerError::CorruptOwner)
            };
        }
        Ok(Some(PortOwnerToken {
            state_index: self.state_index_plus_one - 1,
            state_generation: self.state_generation,
            runtime_epoch: self.runtime_epoch,
        }))
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PortOwnerExpectation {
    pub port: u16,
    pub state_generation: u64,
    pub runtime_epoch: u128,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PortOwnerConservation {
    pub assigned_ports: usize,
    pub live_states: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PortOwnerSemanticError {
    Structural(PortOwnerError),
    OwnerForDeadState { port: u16, state_index: usize },
    OwnerMismatch { port: u16, state_index: usize },
    ExpectedPortOutOfRange { state_index: usize },
    MissingOwner { state_index: usize },
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

    pub(crate) fn owner(&self, port: u16) -> Result<Option<PortOwnerToken>, PortOwnerError> {
        let offset = self.offset(port)?;
        let token = self.slots[offset].token()?;
        if token.is_some_and(|owner| owner.state_index() >= self.state_capacity) {
            return Err(PortOwnerError::CorruptOwner);
        }
        Ok(token)
    }

    pub(crate) fn assign(
        &mut self,
        port: u16,
        owner: PortOwnerToken,
    ) -> Result<(), PortOwnerError> {
        let offset = self.offset(port)?;
        if owner.state_index() >= self.state_capacity {
            return Err(PortOwnerError::StateIndexOutOfRange);
        }
        self.slots[offset] = PortOwnerSlot::from_token(owner)?;
        Ok(())
    }

    pub(crate) fn claim(
        &mut self,
        port: u16,
        expected: Option<PortOwnerToken>,
        replacement: PortOwnerToken,
    ) -> Result<bool, PortOwnerError> {
        let offset = self.offset(port)?;
        if replacement.state_index() >= self.state_capacity {
            return Err(PortOwnerError::StateIndexOutOfRange);
        }
        let current = self.slots[offset].token()?;
        if current.is_some_and(|owner| owner.state_index() >= self.state_capacity) {
            return Err(PortOwnerError::CorruptOwner);
        }
        if current != expected {
            return Ok(false);
        }
        self.slots[offset] = PortOwnerSlot::from_token(replacement)?;
        Ok(true)
    }

    pub(crate) fn clear_if(
        &mut self,
        port: u16,
        expected: PortOwnerToken,
    ) -> Result<bool, PortOwnerError> {
        let offset = self.offset(port)?;
        if expected.state_index() >= self.state_capacity {
            return Err(PortOwnerError::StateIndexOutOfRange);
        }
        let current = self.slots[offset].token()?;
        if current.is_some_and(|owner| owner.state_index() >= self.state_capacity) {
            return Err(PortOwnerError::CorruptOwner);
        }
        if current != Some(expected) {
            return Ok(false);
        }
        self.slots[offset] = PortOwnerSlot::default();
        Ok(true)
    }

    /// Verifies that every live state owns exactly its declared port and that
    /// every assigned port points to a live state with the exact lifecycle
    /// token. The callback must be pure because it can be called twice.
    pub(crate) fn validate_semantics(
        &self,
        mut expected_owner: impl FnMut(usize) -> Option<PortOwnerExpectation>,
    ) -> Result<PortOwnerConservation, PortOwnerSemanticError> {
        let mut report = PortOwnerConservation::default();
        for (offset, slot) in self.slots.iter().copied().enumerate() {
            let Some(owner) = slot.token().map_err(PortOwnerSemanticError::Structural)? else {
                continue;
            };
            if owner.state_index() >= self.state_capacity {
                return Err(PortOwnerSemanticError::Structural(
                    PortOwnerError::CorruptOwner,
                ));
            }
            report.assigned_ports += 1;
            let port = self.first_port + offset as u16;
            let Some(expected) = expected_owner(owner.state_index()) else {
                return Err(PortOwnerSemanticError::OwnerForDeadState {
                    port,
                    state_index: owner.state_index(),
                });
            };
            if expected.port != port
                || expected.state_generation != owner.state_generation()
                || expected.runtime_epoch != owner.runtime_epoch()
            {
                return Err(PortOwnerSemanticError::OwnerMismatch {
                    port,
                    state_index: owner.state_index(),
                });
            }
        }

        for state_index in 0..self.state_capacity {
            let Some(expected) = expected_owner(state_index) else {
                continue;
            };
            report.live_states += 1;
            let expected_token = PortOwnerToken::new(
                state_index,
                expected.state_generation,
                expected.runtime_epoch,
            )
            .map_err(PortOwnerSemanticError::Structural)?;
            let owner = match self.owner(expected.port) {
                Ok(owner) => owner,
                Err(PortOwnerError::PortOutOfRange) => {
                    return Err(PortOwnerSemanticError::ExpectedPortOutOfRange { state_index });
                }
                Err(error) => return Err(PortOwnerSemanticError::Structural(error)),
            };
            match owner {
                None => return Err(PortOwnerSemanticError::MissingOwner { state_index }),
                Some(owner) if owner != expected_token => {
                    return Err(PortOwnerSemanticError::OwnerMismatch {
                        port: expected.port,
                        state_index,
                    });
                }
                Some(_) => {}
            }
        }
        Ok(report)
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

    const DOMAIN: DirectoryHashDomain = DirectoryHashDomain::UdpMapping;

    fn key(first: u64) -> DirectoryHashKey {
        DirectoryHashKey::new(first, first ^ 0xa5a5_a5a5_a5a5_a5a5).unwrap()
    }

    #[test]
    fn zero_capacity_is_valid_and_every_operation_is_bounded() {
        let mut buckets = [];
        let mut nodes = [];
        let mut directory = FixedDirectory::new(&mut buckets, &mut nodes, key(7)).unwrap();
        assert_eq!(directory.node_capacity(), 0);
        assert_eq!(directory.bucket_count(), 0);
        assert_eq!(directory.bucket_for_words(DOMAIN, &[1, 2]), None);
        assert_eq!(
            directory.lookup(DOMAIN, &[1, 2], |_| true).unwrap(),
            DirectoryProbe {
                state_index: None,
                probes: 0
            }
        );
        assert_eq!(
            directory.link(0, DOMAIN, &[1]),
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
            hash: 4,
            bucket: 1,
            previous: 2,
            next: 3,
        };

        let mut buckets = [occupied_bucket; 1];
        let mut no_nodes = [];
        assert!(matches!(
            FixedDirectory::new(&mut buckets, &mut no_nodes, key(1)),
            Err(DirectoryConfigError::BucketsWithoutNodes)
        ));
        assert_eq!(buckets, [occupied_bucket; 1]);

        let mut no_buckets = [];
        let mut nodes = [occupied_node; 1];
        assert!(matches!(
            FixedDirectory::new(&mut no_buckets, &mut nodes, key(1)),
            Err(DirectoryConfigError::NodesWithoutBuckets)
        ));
        assert_eq!(nodes, [occupied_node; 1]);

        let mut non_power = [occupied_bucket; 3];
        let mut nodes = [occupied_node; 2];
        assert!(matches!(
            FixedDirectory::new(&mut non_power, &mut nodes, key(1)),
            Err(DirectoryConfigError::BucketCountNotPowerOfTwo)
        ));
        assert_eq!(non_power, [occupied_bucket; 3]);
        assert_eq!(nodes, [occupied_node; 2]);

        let mut too_small = [occupied_bucket; 2];
        let mut nodes = [occupied_node; 3];
        assert!(matches!(
            FixedDirectory::new(&mut too_small, &mut nodes, key(1)),
            Err(DirectoryConfigError::BucketCountTooSmall)
        ));
        assert_eq!(too_small, [occupied_bucket; 2]);
        assert_eq!(nodes, [occupied_node; 3]);
    }

    #[test]
    fn keyed_hash_has_stable_vectors_and_domain_separation() {
        let words = [0x0102_0304_0506_0708, 0x1112_1314_1516_1718];
        let first_key =
            DirectoryHashKey::new(0x0011_2233_4455_6677, 0x8899_aabb_ccdd_eeff).unwrap();
        let second_key =
            DirectoryHashKey::new(0xfedc_ba98_7654_3210, 0x0123_4567_89ab_cdef).unwrap();
        let actual = [
            keyed_hash_words(first_key, DirectoryHashDomain::UdpMapping, &words),
            keyed_hash_words(first_key, DirectoryHashDomain::UdpPeer, &words),
            keyed_hash_words(first_key, DirectoryHashDomain::TcpMapping, &words),
            keyed_hash_words(first_key, DirectoryHashDomain::TcpSession, &words),
            keyed_hash_words(second_key, DirectoryHashDomain::UdpMapping, &words),
            keyed_hash_words(
                first_key,
                DirectoryHashDomain::UdpMapping,
                &[words[1], words[0]],
            ),
            keyed_hash_words(first_key, DirectoryHashDomain::UdpMapping, &words[..1]),
        ];
        assert_eq!(
            actual,
            [
                0xc3ea_f0ab_19ce_22db,
                0xe786_0c6e_b788_481d,
                0xb01f_db4a_b49f_82ab,
                0x3144_9180_cf24_5993,
                0x93ae_426d_24d0_8996,
                0x8ae6_31df_69a8_d41e,
                0x1b8c_d0ec_f3d3_c46a,
            ]
        );
        for left in 0..4 {
            for right in (left + 1)..4 {
                assert_ne!(actual[left], actual[right]);
            }
        }
        assert_eq!(
            DirectoryHashKey::new(0, 0),
            Err(DirectoryHashKeyError::AllZero)
        );
        assert_eq!(format!("{first_key:?}"), "DirectoryHashKey([REDACTED])");
        assert_eq!(format!("{first_key:#?}"), "DirectoryHashKey([REDACTED])");
        assert_eq!(format!("{first_key:?}"), format!("{second_key:?}"));
    }

    #[test]
    fn collisions_lookup_with_exact_probe_counts_and_no_tombstones() {
        let mut buckets = [DirectoryBucket::default(); 4];
        let mut nodes = [DirectoryNode::default(); 3];
        let mut directory = FixedDirectory::new(&mut buckets, &mut nodes, key(11)).unwrap();
        let mut keys = [0_u64; 3];
        let target_bucket = directory.bucket_for_words(DOMAIN, &[0]).unwrap();
        let mut found = 0;
        for candidate in 0..100 {
            if directory.bucket_for_words(DOMAIN, &[candidate]) == Some(target_bucket) {
                keys[found] = candidate;
                found += 1;
                if found == keys.len() {
                    break;
                }
            }
        }
        assert_eq!(found, keys.len());
        for (state_index, key) in keys.into_iter().enumerate() {
            directory.link(state_index, DOMAIN, &[key]).unwrap();
        }

        assert_eq!(
            directory
                .lookup(DOMAIN, &[keys[2]], |index| index == 2)
                .unwrap(),
            DirectoryProbe {
                state_index: Some(2),
                probes: 1
            }
        );
        assert_eq!(
            directory
                .lookup(DOMAIN, &[keys[0]], |index| index == 0)
                .unwrap(),
            DirectoryProbe {
                state_index: Some(0),
                probes: 3
            }
        );
        assert_eq!(
            directory.lookup(DOMAIN, &[keys[0]], |_| false).unwrap(),
            DirectoryProbe {
                state_index: None,
                probes: 3
            }
        );
        let absent = (100..1_000)
            .find(|candidate| {
                directory.bucket_for_words(DOMAIN, &[*candidate]) == Some(target_bucket)
            })
            .unwrap();
        let mut key_match_calls = 0;
        assert_eq!(
            directory
                .lookup(DOMAIN, &[absent], |_| {
                    key_match_calls += 1;
                    true
                })
                .unwrap(),
            DirectoryProbe {
                state_index: None,
                probes: 3,
            }
        );
        assert_eq!(key_match_calls, 0);
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
        let mut directory = FixedDirectory::new(&mut buckets, &mut nodes, key(1)).unwrap();
        let key = [9];
        for state_index in 0..3 {
            directory.link(state_index, DOMAIN, &key).unwrap();
        }
        assert_eq!(
            directory.link(1, DOMAIN, &key),
            Err(DirectoryMutationError::AlreadyLinked)
        );

        directory.unlink(1).unwrap();
        assert_eq!(
            directory
                .lookup(DOMAIN, &key, |index| index == 0)
                .unwrap()
                .probes,
            2
        );
        assert_eq!(directory.validate().unwrap().linked_nodes, 2);

        directory.unlink(2).unwrap();
        assert_eq!(
            directory
                .lookup(DOMAIN, &key, |index| index == 0)
                .unwrap()
                .probes,
            1
        );
        assert_eq!(directory.validate().unwrap().linked_nodes, 1);

        directory.link(1, DOMAIN, &key).unwrap();
        directory.link(2, DOMAIN, &key).unwrap();
        directory.unlink(0).unwrap();
        assert_eq!(directory.lookup(DOMAIN, &key, |_| false).unwrap().probes, 2);
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
        let mut directory = FixedDirectory::new(&mut buckets, &mut nodes, key(3)).unwrap();
        let key = [4];
        directory.link(0, DOMAIN, &key).unwrap();
        directory.link(1, DOMAIN, &key).unwrap();
        directory.nodes[0].next = 1;
        let before_buckets = [directory.buckets[0], directory.buckets[1]];
        let before_nodes = [directory.nodes[0], directory.nodes[1]];
        assert_eq!(
            directory.lookup(DOMAIN, &key, |_| false),
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
        let mut directory = FixedDirectory::new(&mut buckets, &mut nodes, key(5)).unwrap();
        let key = [6];
        directory.link(0, DOMAIN, &key).unwrap();
        let bucket = directory.nodes[0].bucket as usize;
        directory.buckets[bucket].head = 1;
        let before_buckets = [directory.buckets[0], directory.buckets[1]];
        let before_nodes = [directory.nodes[0], directory.nodes[1]];
        assert_eq!(directory.unlink(0), Err(DirectoryMutationError::Corrupt));
        assert_eq!(directory.buckets, &before_buckets);
        assert_eq!(directory.nodes, &before_nodes);
    }

    fn assert_alias_corruption_is_atomic(corrupt: impl FnOnce(&mut FixedDirectory<'_>)) {
        let mut buckets = [DirectoryBucket::default(); 4];
        let mut nodes = [DirectoryNode::default(); 3];
        let mut directory = FixedDirectory::new(&mut buckets, &mut nodes, key(17)).unwrap();
        for state_index in 0..3 {
            directory.link(state_index, DOMAIN, &[5]).unwrap();
        }
        corrupt(&mut directory);
        let before_buckets = [
            directory.buckets[0],
            directory.buckets[1],
            directory.buckets[2],
            directory.buckets[3],
        ];
        let before_nodes = [directory.nodes[0], directory.nodes[1], directory.nodes[2]];
        assert_eq!(directory.unlink(1), Err(DirectoryMutationError::Corrupt));
        assert_eq!(directory.buckets, &before_buckets);
        assert_eq!(directory.nodes, &before_nodes);
    }

    #[test]
    fn unlink_rejects_self_and_neighbor_aliases_atomically() {
        assert_alias_corruption_is_atomic(|directory| {
            directory.nodes[1].previous = 1;
        });
        assert_alias_corruption_is_atomic(|directory| {
            directory.nodes[1].next = 1;
        });
        assert_alias_corruption_is_atomic(|directory| {
            directory.nodes[1].next = directory.nodes[1].previous;
        });
        assert_alias_corruption_is_atomic(|directory| {
            let previous = directory.nodes[1].previous as usize;
            directory.nodes[previous].previous = 1;
        });
        assert_alias_corruption_is_atomic(|directory| {
            let previous = directory.nodes[1].previous as usize;
            directory.nodes[previous].previous = directory.nodes[1].previous;
        });
        assert_alias_corruption_is_atomic(|directory| {
            let previous = directory.nodes[1].previous as usize;
            directory.nodes[previous].previous = directory.nodes[1].next;
        });
        assert_alias_corruption_is_atomic(|directory| {
            let next = directory.nodes[1].next as usize;
            directory.nodes[next].next = 1;
        });
        assert_alias_corruption_is_atomic(|directory| {
            let next = directory.nodes[1].next as usize;
            directory.nodes[next].next = directory.nodes[1].previous;
        });
        assert_alias_corruption_is_atomic(|directory| {
            let next = directory.nodes[1].next as usize;
            directory.nodes[next].next = directory.nodes[1].next;
        });
    }

    #[test]
    fn directory_semantics_cover_every_live_dead_key_and_generation() {
        let mut buckets = [DirectoryBucket::default(); 4];
        let mut nodes = [DirectoryNode::default(); 3];
        let mut directory = FixedDirectory::new(&mut buckets, &mut nodes, key(23)).unwrap();
        let state_keys = [[10, 1], [20, 1], [30, 7]];
        directory.link(0, DOMAIN, &state_keys[0]).unwrap();
        directory.link(2, DOMAIN, &state_keys[2]).unwrap();
        let expected = [
            Some(directory.hash_words(DOMAIN, &state_keys[0])),
            None,
            Some(directory.hash_words(DOMAIN, &state_keys[2])),
        ];
        let structural = directory.validate().unwrap();
        assert_eq!(
            directory.validate_semantics(|index| expected[index]),
            Ok(structural)
        );

        let wrong_generation = directory.hash_words(DOMAIN, &[state_keys[2][0], 8]);
        assert_eq!(
            directory.validate_semantics(|index| match index {
                0 => expected[0],
                2 => Some(wrong_generation),
                _ => None,
            }),
            Err(DirectorySemanticError::KeyHashMismatch { state_index: 2 })
        );
        assert_eq!(
            directory.validate_semantics(|index| (index == 0).then_some(expected[0].unwrap())),
            Err(DirectorySemanticError::DeadStateLinked { state_index: 2 })
        );

        directory.unlink(2).unwrap();
        assert_eq!(
            directory.validate_semantics(|index| expected[index]),
            Err(DirectorySemanticError::LiveStateUnlinked { state_index: 2 })
        );
    }

    #[test]
    fn port_owner_range_assignment_conditional_clear_and_validation_are_exact() {
        let mut slots = [PortOwnerSlot::default(); 3];
        let mut owners = PortOwnerTable::new(&mut slots, 40_000, 40_002, 2).unwrap();
        let owner0 = PortOwnerToken::new(0, 7, 11).unwrap();
        let owner1 = PortOwnerToken::new(1, 8, 11).unwrap();
        assert_eq!(owners.owner(40_000), Ok(None));
        owners.assign(40_000, owner1).unwrap();
        assert_eq!(owners.owner(40_000), Ok(Some(owner1)));
        assert_eq!(owners.clear_if(40_000, owner0), Ok(false));
        assert_eq!(owners.owner(40_000), Ok(Some(owner1)));
        assert_eq!(owners.clear_if(40_000, owner1), Ok(true));
        assert_eq!(owners.owner(40_000), Ok(None));
        let out_of_range = PortOwnerToken::new(2, 9, 11).unwrap();
        assert_eq!(
            owners.assign(40_001, out_of_range),
            Err(PortOwnerError::StateIndexOutOfRange)
        );
        assert_eq!(owners.owner(39_999), Err(PortOwnerError::PortOutOfRange));
        owners.assign(40_002, owner0).unwrap();
        owners.clear();
        assert_eq!(owners.owner(40_002), Ok(None));
    }

    #[test]
    fn stale_port_owner_tokens_cannot_clear_or_claim_reused_state_index() {
        let mut slots = [PortOwnerSlot::default(); 1];
        let mut owners = PortOwnerTable::new(&mut slots, 40_000, 40_000, 1).unwrap();
        let generation_a = PortOwnerToken::new(0, 1, 100).unwrap();
        let generation_b = PortOwnerToken::new(0, 2, 100).unwrap();
        let epoch_b = PortOwnerToken::new(0, 2, 101).unwrap();

        owners.assign(40_000, generation_a).unwrap();
        assert_eq!(
            owners.claim(40_000, Some(generation_a), generation_b),
            Ok(true)
        );
        assert_eq!(owners.clear_if(40_000, generation_a), Ok(false));
        assert_eq!(owners.claim(40_000, Some(generation_a), epoch_b), Ok(false));
        assert_eq!(owners.owner(40_000), Ok(Some(generation_b)));
        assert_eq!(owners.claim(40_000, Some(generation_b), epoch_b), Ok(true));
        assert_eq!(owners.clear_if(40_000, generation_b), Ok(false));
        assert_eq!(owners.owner(40_000), Ok(Some(epoch_b)));
    }

    #[test]
    fn port_owner_semantics_cover_live_dead_missing_and_mismatched_owners() {
        let mut slots = [PortOwnerSlot::default(); 2];
        let mut owners = PortOwnerTable::new(&mut slots, 40_000, 40_001, 2).unwrap();
        let owner = PortOwnerToken::new(0, 7, 31).unwrap();
        let expected = PortOwnerExpectation {
            port: 40_000,
            state_generation: 7,
            runtime_epoch: 31,
        };
        owners.assign(40_000, owner).unwrap();
        assert_eq!(
            owners.validate_semantics(|index| (index == 0).then_some(expected)),
            Ok(PortOwnerConservation {
                assigned_ports: 1,
                live_states: 1,
            })
        );
        assert_eq!(
            owners.validate_semantics(|_| None),
            Err(PortOwnerSemanticError::OwnerForDeadState {
                port: 40_000,
                state_index: 0,
            })
        );

        let stale = PortOwnerToken::new(0, 6, 31).unwrap();
        owners.assign(40_000, stale).unwrap();
        assert_eq!(
            owners.validate_semantics(|index| (index == 0).then_some(expected)),
            Err(PortOwnerSemanticError::OwnerMismatch {
                port: 40_000,
                state_index: 0,
            })
        );

        owners.clear();
        assert_eq!(
            owners.validate_semantics(|index| (index == 0).then_some(expected)),
            Err(PortOwnerSemanticError::MissingOwner { state_index: 0 })
        );
        let outside = PortOwnerExpectation {
            port: 39_999,
            ..expected
        };
        assert_eq!(
            owners.validate_semantics(|index| (index == 0).then_some(outside)),
            Err(PortOwnerSemanticError::ExpectedPortOutOfRange { state_index: 0 })
        );
    }

    #[test]
    fn invalid_port_owner_configuration_is_atomic() {
        let occupied = PortOwnerSlot {
            state_index_plus_one: 7,
            state_generation: 8,
            runtime_epoch: 9,
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
