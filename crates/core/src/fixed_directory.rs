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

    pub(crate) fn hash_words(self, domain: DirectoryHashDomain, words: &[u64]) -> u64 {
        keyed_hash_words(self, domain, words)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
#[allow(dead_code)] // TCP domains are reserved for the separately reviewed N4 integration.
pub(crate) enum DirectoryHashDomain {
    UdpMapping = 0x4e41_5434_554d_4150,
    UdpPeer = 0x4e41_5434_5550_4545,
    TcpMapping = 0x4e41_5434_544d_4150,
    TcpSession = 0x4e41_5434_5453_4553,
    TcpSessionAddress = 0x4e41_5434_5453_4144,
    TcpInboundSlot = 0x4e41_5434_5449_534c,
    ResolutionState = 0x5253_4c56_5354_4154,
    ResolutionDynamicNeighbor = 0x5253_4c56_444e_4248,
    ResolutionHoldForward = 0x5253_4c56_4846_5744,
    ResolutionHoldReverse = 0x5253_4c56_4852_4556,
    TcpSynHold = 0x4e41_5434_5453_5948,
    /// Start of the public-port search of a new UDP mapping (N2, NAT44-020).
    UdpPortStart = 0x4e41_5434_5550_5354,
    /// Takeover probes of a new UDP mapping when every port has an owner.
    UdpPortTakeover = 0x4e41_5434_5550_544b,
    /// Start of the public-port search of a new TCP mapping (N2, NAT44-020).
    TcpPortStart = 0x4e41_5434_5450_5354,
    /// Takeover probes of a new TCP mapping when every port has an owner.
    TcpPortTakeover = 0x4e41_5434_5450_544b,
    /// Internal-host directory of the UDP per-host mapping quota (N3).
    UdpHost = 0x4e41_5434_5548_4f53,
    /// Internal-host directory of the TCP per-host mapping quota (N3).
    TcpHost = 0x4e41_5434_5448_4f53,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DirectoryBucket {
    head: u32,
}

impl std::fmt::Debug for DirectoryBucket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DirectoryBucket([REDACTED])")
    }
}

impl Default for DirectoryBucket {
    fn default() -> Self {
        Self { head: NONE }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DirectoryNode {
    hash: u64,
    bucket: u32,
    previous: u32,
    next: u32,
}

impl std::fmt::Debug for DirectoryNode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DirectoryNode([REDACTED])")
    }
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

#[derive(Clone, Copy)]
pub(crate) struct PreparedDirectoryLink {
    state: u32,
    hash: u64,
    bucket: u32,
    expected_head: u32,
}

#[derive(Clone, Copy)]
pub(crate) struct PreparedDirectoryUnlink {
    state: u32,
    node: DirectoryNode,
}

#[derive(Clone, Copy)]
pub(crate) struct PreparedDirectoryRelink {
    state: u32,
    hash: u64,
    bucket: u32,
    expected_head: u32,
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

/// Outcome of [`FixedDirectory::walk_bounded`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryWalk {
    pub probes: usize,
    /// The visitor stopped the walk.
    pub stopped: bool,
    /// The walk reached the end of the chain without being stopped.
    pub complete: bool,
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
    pub(crate) fn validate_config(
        bucket_count: usize,
        node_count: usize,
    ) -> Result<(), DirectoryConfigError> {
        validate_dimensions(bucket_count, node_count)
    }

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

    #[allow(dead_code)] // Kept for bounded-complexity assertions and the N2 primitive API.
    pub(crate) const fn node_capacity(&self) -> usize {
        self.nodes.len()
    }

    #[allow(dead_code)] // Kept for bounded-complexity assertions and the N2 primitive API.
    pub(crate) const fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    #[cfg(test)]
    pub(crate) fn backing_snapshot(&self) -> (Vec<DirectoryBucket>, Vec<DirectoryNode>) {
        (self.buckets.to_vec(), self.nodes.to_vec())
    }

    pub(crate) fn clear(&mut self) {
        self.buckets.fill(DirectoryBucket::default());
        self.nodes.fill(DirectoryNode::default());
    }

    pub(crate) fn clear_with_key(&mut self, hash_key: DirectoryHashKey) {
        self.clear();
        self.hash_key = hash_key;
    }

    #[allow(dead_code)] // Used by fault-model tests and the N2 primitive API.
    pub(crate) fn is_linked(&self, state_index: usize) -> Option<bool> {
        self.nodes.get(state_index).map(|node| node.is_linked())
    }

    pub(crate) fn hash_words(&self, domain: DirectoryHashDomain, words: &[u64]) -> u64 {
        self.hash_key.hash_words(domain, words)
    }

    #[allow(dead_code)] // Used by collision-model tests and the N2 primitive API.
    pub(crate) fn bucket_for_words(
        &self,
        domain: DirectoryHashDomain,
        words: &[u64],
    ) -> Option<usize> {
        self.bucket_for_hash(self.hash_words(domain, words))
    }

    #[allow(dead_code)] // Compatibility wrapper around prepare/apply.
    pub(crate) fn link(
        &mut self,
        state_index: usize,
        domain: DirectoryHashDomain,
        words: &[u64],
    ) -> Result<(), DirectoryMutationError> {
        let prepared = self.prepare_link(state_index, domain, words)?;
        self.apply_prepared_link(prepared);
        Ok(())
    }

    #[allow(dead_code)] // Compatibility wrapper around prepare/apply.
    pub(crate) fn unlink(&mut self, state_index: usize) -> Result<(), DirectoryMutationError> {
        let prepared = self.prepare_unlink(state_index)?;
        self.apply_prepared_unlink(prepared);
        Ok(())
    }

    pub(crate) fn prepare_link(
        &self,
        state_index: usize,
        domain: DirectoryHashDomain,
        words: &[u64],
    ) -> Result<PreparedDirectoryLink, DirectoryMutationError> {
        self.prepare_link_hashed(state_index, self.hash_words(domain, words))
    }

    /// [`Self::prepare_link`] with the key's hash already computed by
    /// [`Self::hash_words`] (N3: a host assignment carries the hash from
    /// plan to commit instead of a prepared link).
    pub(crate) fn prepare_link_hashed(
        &self,
        state_index: usize,
        hash: u64,
    ) -> Result<PreparedDirectoryLink, DirectoryMutationError> {
        let state = index_to_link(state_index, self.nodes.len())?;
        if self.nodes[state_index].is_linked() {
            return Err(DirectoryMutationError::AlreadyLinked);
        }
        let bucket_index = self
            .bucket_for_hash(hash)
            .ok_or(DirectoryMutationError::StateIndexOutOfRange)?;
        let bucket = u32::try_from(bucket_index)
            .map_err(|_| DirectoryMutationError::StateIndexOutOfRange)?;
        let expected_head = self.buckets[bucket_index].head;
        self.validate_head(bucket, expected_head)?;
        Ok(PreparedDirectoryLink {
            state,
            hash,
            bucket,
            expected_head,
        })
    }

    pub(crate) fn prepared_link_matches(&self, prepared: PreparedDirectoryLink) -> bool {
        let state_index = prepared.state as usize;
        self.nodes.get(state_index) == Some(&DirectoryNode::default())
            && self
                .buckets
                .get(prepared.bucket as usize)
                .map(|bucket| bucket.head)
                == Some(prepared.expected_head)
            && self
                .validate_head(prepared.bucket, prepared.expected_head)
                .is_ok()
    }

    pub(crate) fn apply_prepared_link(&mut self, prepared: PreparedDirectoryLink) {
        debug_assert!(self.prepared_link_matches(prepared));
        let state_index = prepared.state as usize;
        self.nodes[state_index] = DirectoryNode {
            hash: prepared.hash,
            bucket: prepared.bucket,
            previous: NONE,
            next: prepared.expected_head,
        };
        if prepared.expected_head != NONE {
            let index = prepared.expected_head as usize;
            self.nodes[index].previous = prepared.state;
        }
        self.buckets[prepared.bucket as usize].head = prepared.state;
    }

    pub(crate) fn prepare_unlink(
        &self,
        state_index: usize,
    ) -> Result<PreparedDirectoryUnlink, DirectoryMutationError> {
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
        let expected_bucket_head = self.buckets[bucket_index].head;
        if node.previous == NONE {
            if expected_bucket_head != state {
                return Err(DirectoryMutationError::Corrupt);
            }
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
        }
        if node.next != NONE {
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
        }
        Ok(PreparedDirectoryUnlink { state, node })
    }

    pub(crate) fn prepared_unlink_matches(&self, prepared: PreparedDirectoryUnlink) -> bool {
        let state_index = prepared.state as usize;
        if self.nodes.get(state_index) != Some(&prepared.node) {
            return false;
        }
        let Some(bucket) = self.buckets.get(prepared.node.bucket as usize) else {
            return false;
        };
        if prepared.node.previous == NONE {
            if bucket.head != prepared.state {
                return false;
            }
        } else {
            let Some(previous) = self.nodes.get(prepared.node.previous as usize).copied() else {
                return false;
            };
            if previous.bucket != prepared.node.bucket || previous.next != prepared.state {
                return false;
            }
        }
        if prepared.node.next != NONE {
            let Some(next) = self.nodes.get(prepared.node.next as usize).copied() else {
                return false;
            };
            if next.bucket != prepared.node.bucket || next.previous != prepared.state {
                return false;
            }
        }
        true
    }

    pub(crate) fn apply_prepared_unlink(&mut self, prepared: PreparedDirectoryUnlink) {
        debug_assert!(self.prepared_unlink_matches(prepared));
        if prepared.node.previous != NONE {
            self.nodes[prepared.node.previous as usize].next = prepared.node.next;
        } else {
            self.buckets[prepared.node.bucket as usize].head = prepared.node.next;
        }
        if prepared.node.next != NONE {
            self.nodes[prepared.node.next as usize].previous = prepared.node.previous;
        }
        self.nodes[prepared.state as usize] = DirectoryNode::default();
    }

    pub(crate) fn prepare_relink(
        &self,
        state_index: usize,
        domain: DirectoryHashDomain,
        words: &[u64],
    ) -> Result<PreparedDirectoryRelink, DirectoryMutationError> {
        self.prepare_relink_hashed(state_index, self.hash_words(domain, words))
    }

    /// [`Self::prepare_relink`] with the key's hash already computed.
    pub(crate) fn prepare_relink_hashed(
        &self,
        state_index: usize,
        hash: u64,
    ) -> Result<PreparedDirectoryRelink, DirectoryMutationError> {
        let unlink = self.prepare_unlink(state_index)?;
        let bucket_index = self
            .bucket_for_hash(hash)
            .ok_or(DirectoryMutationError::StateIndexOutOfRange)?;
        let bucket = u32::try_from(bucket_index)
            .map_err(|_| DirectoryMutationError::StateIndexOutOfRange)?;
        let expected_head = if bucket == unlink.node.bucket && unlink.node.previous == NONE {
            unlink.node.next
        } else {
            let head = self.buckets[bucket_index].head;
            self.validate_head(bucket, head)?;
            head
        };
        Ok(PreparedDirectoryRelink {
            state: unlink.state,
            hash,
            bucket,
            expected_head,
        })
    }

    pub(crate) fn prepared_relink_matches(&self, prepared: PreparedDirectoryRelink) -> bool {
        let Ok(unlink) = self.prepare_unlink(prepared.state as usize) else {
            return false;
        };
        if prepared.bucket == unlink.node.bucket && unlink.node.previous == NONE {
            prepared.expected_head == unlink.node.next
        } else {
            self.buckets
                .get(prepared.bucket as usize)
                .is_some_and(|bucket| bucket.head == prepared.expected_head)
                && self
                    .validate_head(prepared.bucket, prepared.expected_head)
                    .is_ok()
        }
    }

    pub(crate) fn apply_prepared_relink(&mut self, prepared: PreparedDirectoryRelink) {
        debug_assert!(self.prepared_relink_matches(prepared));
        let node = self.nodes[prepared.state as usize];
        if node.previous != NONE {
            self.nodes[node.previous as usize].next = node.next;
        } else {
            self.buckets[node.bucket as usize].head = node.next;
        }
        if node.next != NONE {
            self.nodes[node.next as usize].previous = node.previous;
        }
        self.nodes[prepared.state as usize] = DirectoryNode {
            hash: prepared.hash,
            bucket: prepared.bucket,
            previous: NONE,
            next: prepared.expected_head,
        };
        if prepared.expected_head != NONE {
            self.nodes[prepared.expected_head as usize].previous = prepared.state;
        }
        self.buckets[prepared.bucket as usize].head = prepared.state;
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

    /// Visits the chain of `words` in order, at most `max_probes` nodes,
    /// calling `visit` for each node whose hash matches. `visit` returns
    /// `true` to stop early. The result says how many nodes were visited,
    /// whether `visit` stopped the walk, and whether the walk reached the
    /// end of the chain (`complete`). A chain longer than the budget is
    /// reported as incomplete, never as an error, so callers that count
    /// matches for an admission decision can fail closed.
    pub(crate) fn walk_bounded(
        &self,
        domain: DirectoryHashDomain,
        words: &[u64],
        max_probes: usize,
        mut visit: impl FnMut(usize) -> bool,
    ) -> Result<DirectoryWalk, DirectoryLookupError> {
        let hash = self.hash_words(domain, words);
        let Some(bucket_index) = self.bucket_for_hash(hash) else {
            return Ok(DirectoryWalk {
                probes: 0,
                stopped: false,
                complete: true,
            });
        };
        let bucket =
            u32::try_from(bucket_index).expect("validated directory bucket count fits u32");
        let mut current = self.buckets[bucket_index].head;
        let mut probes = 0;
        for _ in 0..self.nodes.len().min(max_probes) {
            if current == NONE {
                break;
            }
            let Some(index) = link_to_index(current, self.nodes.len()) else {
                return Err(DirectoryLookupError::InvalidNodeIndex { probes });
            };
            let node = self.nodes[index];
            if node.bucket != bucket {
                return Err(DirectoryLookupError::BucketMismatch { probes });
            }
            probes += 1;
            if node.hash == hash && visit(index) {
                return Ok(DirectoryWalk {
                    probes,
                    stopped: true,
                    complete: false,
                });
            }
            current = node.next;
        }
        Ok(DirectoryWalk {
            probes,
            stopped: false,
            complete: current == NONE,
        })
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

    fn validate_head(
        &self,
        bucket: u32,
        head: u32,
    ) -> Result<Option<DirectoryNode>, DirectoryMutationError> {
        if head == NONE {
            return Ok(None);
        }
        let index = link_to_index(head, self.nodes.len()).ok_or(DirectoryMutationError::Corrupt)?;
        let node = self.nodes[index];
        if node.bucket != bucket || node.previous != NONE {
            return Err(DirectoryMutationError::Corrupt);
        }
        Ok(Some(node))
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

/// Number of `u64` words of caller-backed free-port bitmap storage for a
/// NAT44 port pool of `port_count` ports: one leaf bit per port plus one
/// summary bit per leaf word (1040 words, 8320 bytes, for the widest pool of
/// 65535 ports). A free port is then found by reading at most two leaf words
/// and two passes over the summary words (34 words for the widest pool)
/// instead of walking the pool.
#[must_use]
pub const fn port_free_bitmap_words(port_count: usize) -> usize {
    if port_count == 0 {
        return 0;
    }
    let leaf_words = port_count.div_ceil(64);
    leaf_words + leaf_words.div_ceil(64)
}

/// Free-port bitmap over caller-backed words: leaf bit `offset` is set iff
/// pool offset `offset` has no owner, and summary bit `w` is set iff leaf
/// word `w` has a set bit. Bits past the pool are always clear.
struct PortFreeBitmap<'a> {
    words: &'a mut [u64],
    port_count: usize,
    leaf_words: usize,
    #[cfg(test)]
    word_reads: std::cell::Cell<usize>,
}

impl<'a> PortFreeBitmap<'a> {
    fn new(words: &'a mut [u64], port_count: usize) -> Self {
        debug_assert!(words.len() == port_free_bitmap_words(port_count));
        let mut bitmap = Self {
            words,
            port_count,
            leaf_words: port_count.div_ceil(64),
            #[cfg(test)]
            word_reads: std::cell::Cell::new(0),
        };
        bitmap.reset_all_free();
        bitmap
    }

    /// Marks every pool offset free. O(pool / 64), cold path only.
    fn reset_all_free(&mut self) {
        self.words.fill(0);
        let (leaf, summary) = self.words.split_at_mut(self.leaf_words);
        for (word_index, word) in leaf.iter_mut().enumerate() {
            let bits = (self.port_count - word_index * 64).min(64);
            *word = if bits == 64 {
                u64::MAX
            } else {
                (1_u64 << bits) - 1
            };
            summary[word_index / 64] |= 1_u64 << (word_index % 64);
        }
    }

    fn set(&mut self, offset: usize, free: bool) {
        debug_assert!(offset < self.port_count);
        let word_index = offset / 64;
        let bit = 1_u64 << (offset % 64);
        if free {
            self.words[word_index] |= bit;
        } else {
            self.words[word_index] &= !bit;
        }
        let nonempty = self.words[word_index] != 0;
        let summary_bit = 1_u64 << (word_index % 64);
        let summary = &mut self.words[self.leaf_words + word_index / 64];
        if nonempty {
            *summary |= summary_bit;
        } else {
            *summary &= !summary_bit;
        }
    }

    fn read(&self, word_index: usize) -> u64 {
        #[cfg(test)]
        self.word_reads.set(self.word_reads.get() + 1);
        self.words[word_index]
    }

    /// First leaf word at or after `from` with a free bit, found through the
    /// summary words (at most one read per summary word).
    fn next_nonempty_leaf_word(&self, from: usize) -> Option<usize> {
        if from >= self.leaf_words {
            return None;
        }
        let summary_words = self.words.len() - self.leaf_words;
        let mut summary_index = from / 64;
        let mut mask = u64::MAX << (from % 64);
        while summary_index < summary_words {
            let bits = self.read(self.leaf_words + summary_index) & mask;
            if bits != 0 {
                let word_index = summary_index * 64 + bits.trailing_zeros() as usize;
                return (word_index < self.leaf_words).then_some(word_index);
            }
            summary_index += 1;
            mask = u64::MAX;
        }
        None
    }

    /// The first free offset at or after `start`, wrapping once around the
    /// pool: the same port a walk of the pool from `start` would reach first
    /// among unowned ports. Bounded by two leaf-word reads plus two passes
    /// over the summary words, independent of how many ports are owned.
    fn first_free_from(&self, start: usize) -> Option<usize> {
        if self.port_count == 0 {
            return None;
        }
        let start = start % self.port_count;
        let start_word = start / 64;
        let tail = self.read(start_word) & (u64::MAX << (start % 64));
        if tail != 0 {
            return Some(start_word * 64 + tail.trailing_zeros() as usize);
        }
        // Later words, then wrap to the beginning: the second search may
        // return `start_word` itself, whose set bits are all below `start`.
        let word_index = self
            .next_nonempty_leaf_word(start_word + 1)
            .or_else(|| self.next_nonempty_leaf_word(0))?;
        let bits = self.read(word_index);
        (bits != 0).then(|| word_index * 64 + bits.trailing_zeros() as usize)
    }

    /// Exact consistency with the owner slots (validation only, O(pool)).
    fn matches(&self, slots: &[PortOwnerSlot]) -> bool {
        if slots.len() != self.port_count || self.words.len() != port_free_bitmap_words(slots.len())
        {
            return false;
        }
        let summary_words = self.words.len() - self.leaf_words;
        let mut expected_summary = [0_u64; 16];
        if summary_words > expected_summary.len() {
            return false;
        }
        for word_index in 0..self.leaf_words {
            let mut expected = 0_u64;
            for bit in 0..64 {
                if slots
                    .get(word_index * 64 + bit)
                    .is_some_and(|slot| *slot == PortOwnerSlot::default())
                {
                    expected |= 1_u64 << bit;
                }
            }
            if self.words[word_index] != expected {
                return false;
            }
            if expected != 0 {
                expected_summary[word_index / 64] |= 1_u64 << (word_index % 64);
            }
        }
        self.words[self.leaf_words..] == expected_summary[..summary_words]
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct PortOwnerSlot {
    state_index_plus_one: u32,
    state_generation: u64,
    runtime_epoch: u128,
}

impl std::fmt::Debug for PortOwnerSlot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PortOwnerSlot([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct PortOwnerToken {
    state_index: u32,
    state_generation: u64,
    runtime_epoch: u128,
}

impl std::fmt::Debug for PortOwnerToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PortOwnerToken([REDACTED])")
    }
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

    pub(crate) const fn from_prevalidated_index(
        state_index: u32,
        state_generation: u64,
        runtime_epoch: u128,
    ) -> Self {
        Self {
            state_index,
            state_generation,
            runtime_epoch,
        }
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
    BitmapSizeMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PortOwnerError {
    PortOutOfRange,
    StateIndexOutOfRange,
    CorruptOwner,
}

#[derive(Clone, Copy)]
#[allow(dead_code)] // N3 uses prepare_move; claim remains the single-port primitive.
pub(crate) struct PreparedPortOwnerClaim {
    offset: usize,
    expected: PortOwnerSlot,
    replacement: PortOwnerSlot,
}

#[derive(Clone, Copy)]
#[allow(dead_code)] // Exact snapshot form remains covered by primitive tests.
pub(crate) struct PreparedPortOwnerMove {
    old_offset: Option<usize>,
    old_expected: Option<PortOwnerSlot>,
    new_offset: usize,
    new_expected: PortOwnerSlot,
    replacement: PortOwnerSlot,
}

#[derive(Clone, Copy)]
pub(crate) struct PreparedPortOwnerMoveTopology {
    old_offset: u32,
    new_offset: u32,
}

impl PreparedPortOwnerMove {
    pub(crate) fn topology(self) -> PreparedPortOwnerMoveTopology {
        PreparedPortOwnerMoveTopology {
            old_offset: self.old_offset.map_or(NONE, |offset| {
                u32::try_from(offset).expect("validated offset fits u32")
            }),
            new_offset: u32::try_from(self.new_offset).expect("validated offset fits u32"),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct PortOwnerExpectation {
    pub port: u16,
    pub state_generation: u64,
    pub runtime_epoch: u128,
}

impl std::fmt::Debug for PortOwnerExpectation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PortOwnerExpectation([REDACTED])")
    }
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
    FreeBitmapMismatch,
}

/// Public-port owner index of one NAT44 protocol: one owner slot per pool
/// port and a free-port bitmap kept exactly in step with the slots by every
/// mutation, so a free port is found without walking the pool.
pub(crate) struct PortOwnerTable<'a> {
    slots: &'a mut [PortOwnerSlot],
    free: PortFreeBitmap<'a>,
    first_port: u16,
    last_port: u16,
    state_capacity: usize,
}

impl<'a> PortOwnerTable<'a> {
    pub(crate) fn validate_config(
        slot_count: usize,
        bitmap_words: usize,
        first_port: u16,
        last_port: u16,
        state_capacity: usize,
    ) -> Result<(), PortOwnerConfigError> {
        validate_port_owner_dimensions(slot_count, first_port, last_port, state_capacity)?;
        if bitmap_words != port_free_bitmap_words(slot_count) {
            return Err(PortOwnerConfigError::BitmapSizeMismatch);
        }
        Ok(())
    }

    pub(crate) fn new(
        slots: &'a mut [PortOwnerSlot],
        free_words: &'a mut [u64],
        first_port: u16,
        last_port: u16,
        state_capacity: usize,
    ) -> Result<Self, PortOwnerConfigError> {
        Self::validate_config(
            slots.len(),
            free_words.len(),
            first_port,
            last_port,
            state_capacity,
        )?;
        slots.fill(PortOwnerSlot::default());
        let free = PortFreeBitmap::new(free_words, slots.len());
        Ok(Self {
            slots,
            free,
            first_port,
            last_port,
            state_capacity,
        })
    }

    pub(crate) fn clear(&mut self) {
        self.slots.fill(PortOwnerSlot::default());
        self.free.reset_all_free();
    }

    /// Writes one owner slot and its free bit together.
    fn write_slot(&mut self, offset: usize, slot: PortOwnerSlot) {
        self.slots[offset] = slot;
        self.free.set(offset, slot == PortOwnerSlot::default());
    }

    /// The first unowned port at or after `start_offset` (a pool offset,
    /// reduced modulo the pool size), wrapping once: exactly the first
    /// unowned port of a walk of the pool from that offset, found in a
    /// bounded number of bitmap word reads.
    pub(crate) fn first_unowned_port_from(&self, start_offset: usize) -> Option<u16> {
        let offset = self.free.first_free_from(start_offset)?;
        debug_assert!(self.slots[offset] == PortOwnerSlot::default());
        u16::try_from(offset)
            .ok()
            .and_then(|offset| self.first_port.checked_add(offset))
    }

    /// Bitmap words read by [`Self::first_unowned_port_from`] since the last
    /// reset (cost tests).
    #[cfg(test)]
    pub(crate) fn take_bitmap_word_reads(&self) -> usize {
        self.free.word_reads.replace(0)
    }

    /// Whether the free-port bitmap agrees with every owner slot (O(pool),
    /// validation only).
    pub(crate) fn bitmap_matches_slots(&self) -> bool {
        self.free.matches(self.slots)
    }

    pub(crate) const fn slot_count(&self) -> usize {
        self.slots.len()
    }

    #[cfg(test)]
    pub(crate) fn backing_snapshot(&self) -> Vec<PortOwnerSlot> {
        self.slots.to_vec()
    }

    pub(crate) fn reconfigure_prevalidated_and_clear(
        &mut self,
        first_port: u16,
        last_port: u16,
        state_capacity: usize,
    ) {
        self.clear();
        self.first_port = first_port;
        self.last_port = last_port;
        self.state_capacity = state_capacity;
    }

    pub(crate) fn owner(&self, port: u16) -> Result<Option<PortOwnerToken>, PortOwnerError> {
        let offset = self.offset(port)?;
        let token = self.slots[offset].token()?;
        if token.is_some_and(|owner| owner.state_index() >= self.state_capacity) {
            return Err(PortOwnerError::CorruptOwner);
        }
        Ok(token)
    }

    #[allow(dead_code)] // Compatibility primitive; N3 commits through prepared moves.
    pub(crate) fn assign(
        &mut self,
        port: u16,
        owner: PortOwnerToken,
    ) -> Result<(), PortOwnerError> {
        let offset = self.offset(port)?;
        if owner.state_index() >= self.state_capacity {
            return Err(PortOwnerError::StateIndexOutOfRange);
        }
        let slot = PortOwnerSlot::from_token(owner)?;
        self.write_slot(offset, slot);
        Ok(())
    }

    #[allow(dead_code)] // Compatibility primitive; N3 commits through prepared moves.
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
        let slot = PortOwnerSlot::from_token(replacement)?;
        self.write_slot(offset, slot);
        Ok(true)
    }

    #[allow(dead_code)] // Retained for single-port integrations and fault tests.
    pub(crate) fn prepare_claim(
        &self,
        port: u16,
        expected: Option<PortOwnerToken>,
        replacement: PortOwnerToken,
    ) -> Result<PreparedPortOwnerClaim, PortOwnerError> {
        let offset = self.offset(port)?;
        if replacement.state_index() >= self.state_capacity {
            return Err(PortOwnerError::StateIndexOutOfRange);
        }
        let current = self.slots[offset].token()?;
        if current.is_some_and(|owner| owner.state_index() >= self.state_capacity) {
            return Err(PortOwnerError::CorruptOwner);
        }
        if current != expected {
            return Err(PortOwnerError::CorruptOwner);
        }
        Ok(PreparedPortOwnerClaim {
            offset,
            expected: self.slots[offset],
            replacement: PortOwnerSlot::from_token(replacement)?,
        })
    }

    #[allow(dead_code)] // Retained for single-port integrations and fault tests.
    pub(crate) fn prepared_claim_matches(&self, prepared: PreparedPortOwnerClaim) -> bool {
        self.slots.get(prepared.offset) == Some(&prepared.expected)
    }

    #[allow(dead_code)] // Retained for single-port integrations and fault tests.
    pub(crate) fn apply_prepared_claim(&mut self, prepared: PreparedPortOwnerClaim) {
        debug_assert!(self.prepared_claim_matches(prepared));
        self.write_slot(prepared.offset, prepared.replacement);
    }

    pub(crate) fn prepare_move(
        &self,
        old: Option<(u16, PortOwnerToken)>,
        new_port: u16,
        new_expected: Option<PortOwnerToken>,
        replacement: PortOwnerToken,
    ) -> Result<PreparedPortOwnerMove, PortOwnerError> {
        if replacement.state_index() >= self.state_capacity {
            return Err(PortOwnerError::StateIndexOutOfRange);
        }
        let new_offset = self.offset(new_port)?;
        let new_current = self.slots[new_offset].token()?;
        if new_current.is_some_and(|owner| owner.state_index() >= self.state_capacity) {
            return Err(PortOwnerError::CorruptOwner);
        }
        if new_current != new_expected {
            return Err(PortOwnerError::CorruptOwner);
        }
        let (old_offset, old_expected) = if let Some((old_port, old_token)) = old {
            let offset = self.offset(old_port)?;
            let current = self.slots[offset].token()?;
            if current.is_some_and(|owner| owner.state_index() >= self.state_capacity) {
                return Err(PortOwnerError::CorruptOwner);
            }
            if current != Some(old_token) {
                return Err(PortOwnerError::CorruptOwner);
            }
            if offset == new_offset {
                if new_expected != Some(old_token) {
                    return Err(PortOwnerError::CorruptOwner);
                }
                (None, None)
            } else {
                (Some(offset), Some(self.slots[offset]))
            }
        } else {
            (None, None)
        };
        Ok(PreparedPortOwnerMove {
            old_offset,
            old_expected,
            new_offset,
            new_expected: self.slots[new_offset],
            replacement: PortOwnerSlot::from_token(replacement)?,
        })
    }

    #[allow(dead_code)] // Exact snapshot form remains covered by primitive tests.
    pub(crate) fn prepared_move_matches(&self, prepared: PreparedPortOwnerMove) -> bool {
        self.slots.get(prepared.new_offset) == Some(&prepared.new_expected)
            && match (prepared.old_offset, prepared.old_expected) {
                (Some(offset), Some(expected)) => self.slots.get(offset) == Some(&expected),
                (None, None) => true,
                _ => false,
            }
    }

    #[allow(dead_code)] // Exact snapshot form remains covered by primitive tests.
    pub(crate) fn apply_prepared_move(&mut self, prepared: PreparedPortOwnerMove) {
        debug_assert!(self.prepared_move_matches(prepared));
        if let Some(offset) = prepared.old_offset {
            self.write_slot(offset, PortOwnerSlot::default());
        }
        self.write_slot(prepared.new_offset, prepared.replacement);
    }

    pub(crate) fn apply_prepared_move_topology(
        &mut self,
        prepared: PreparedPortOwnerMoveTopology,
        replacement: PortOwnerToken,
    ) {
        debug_assert!((prepared.new_offset as usize) < self.slots.len());
        if prepared.old_offset != NONE {
            self.write_slot(prepared.old_offset as usize, PortOwnerSlot::default());
        }
        self.write_slot(
            prepared.new_offset as usize,
            PortOwnerSlot::from_token(replacement).expect("prepared owner token fits storage"),
        );
    }

    #[allow(dead_code)] // Compatibility primitive; N3 commits through prepared moves.
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
        self.write_slot(offset, PortOwnerSlot::default());
        Ok(true)
    }

    /// Verifies that every live state owns exactly its declared port, that
    /// every assigned port points to a live state with the exact lifecycle
    /// token, and that the free-port bitmap marks exactly the unowned ports.
    /// The callback must be pure because it can be called twice.
    pub(crate) fn validate_semantics(
        &self,
        mut expected_owner: impl FnMut(usize) -> Option<PortOwnerExpectation>,
    ) -> Result<PortOwnerConservation, PortOwnerSemanticError> {
        if !self.bitmap_matches_slots() {
            return Err(PortOwnerSemanticError::FreeBitmapMismatch);
        }
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

fn validate_port_owner_dimensions(
    slot_count: usize,
    first_port: u16,
    last_port: u16,
    state_capacity: usize,
) -> Result<(), PortOwnerConfigError> {
    if first_port == 0 {
        return Err(PortOwnerConfigError::ZeroPort);
    }
    if first_port > last_port {
        return Err(PortOwnerConfigError::InvalidRange);
    }
    let required = (u32::from(last_port) - u32::from(first_port) + 1) as usize;
    if slot_count != required {
        return Err(PortOwnerConfigError::SlotCountMismatch);
    }
    if state_capacity > u32::MAX as usize {
        return Err(PortOwnerConfigError::StateCapacityTooLarge);
    }
    Ok(())
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
    fn directory_and_port_owner_debug_are_topology_independent() {
        const POISON_U64: u64 = 18_446_744_073_709_551_613;
        const POISON_U128: u128 = 0xfedc_ba98_7654_3210_0123_4567_89ab_cdef;

        let buckets_a = [
            DirectoryBucket::default(),
            DirectoryBucket { head: u32::MAX - 2 },
        ];
        let buckets_b = [DirectoryBucket { head: 7 }, DirectoryBucket::default()];
        assert_eq!(
            format!("{buckets_a:?}"),
            "[DirectoryBucket([REDACTED]), DirectoryBucket([REDACTED])]"
        );
        assert_eq!(format!("{buckets_a:#?}"), format!("{buckets_b:#?}"));

        let nodes_a = [
            DirectoryNode::default(),
            DirectoryNode {
                hash: POISON_U64,
                bucket: u32::MAX - 3,
                previous: u32::MAX - 4,
                next: u32::MAX - 5,
            },
        ];
        let nodes_b = [nodes_a[1], nodes_a[0]];
        assert_eq!(
            format!("{nodes_a:?}"),
            "[DirectoryNode([REDACTED]), DirectoryNode([REDACTED])]"
        );
        assert_eq!(format!("{nodes_a:#?}"), format!("{nodes_b:#?}"));

        let owner_slots_a = [
            PortOwnerSlot::default(),
            PortOwnerSlot {
                state_index_plus_one: u32::MAX - 6,
                state_generation: POISON_U64,
                runtime_epoch: POISON_U128,
            },
        ];
        let owner_slots_b = [owner_slots_a[1], owner_slots_a[0]];
        assert_eq!(
            format!("{owner_slots_a:?}"),
            "[PortOwnerSlot([REDACTED]), PortOwnerSlot([REDACTED])]"
        );
        assert_eq!(format!("{owner_slots_a:#?}"), format!("{owner_slots_b:#?}"));

        let token_a = PortOwnerToken::new(0, 1, 2).unwrap();
        let token_b = PortOwnerToken::new(u32::MAX as usize - 1, POISON_U64, POISON_U128).unwrap();
        assert_eq!(format!("{token_a:?}"), "PortOwnerToken([REDACTED])");
        assert_eq!(format!("{token_a:#?}"), "PortOwnerToken([REDACTED])");
        assert_eq!(format!("{token_a:?}"), format!("{token_b:?}"));

        let expectation_a = PortOwnerExpectation {
            port: 1,
            state_generation: 2,
            runtime_epoch: 3,
        };
        let expectation_b = PortOwnerExpectation {
            port: u16::MAX,
            state_generation: POISON_U64,
            runtime_epoch: POISON_U128,
        };
        assert_eq!(
            format!("{expectation_a:?}"),
            "PortOwnerExpectation([REDACTED])"
        );
        assert_eq!(
            format!("{expectation_a:#?}"),
            "PortOwnerExpectation([REDACTED])"
        );
        assert_eq!(format!("{expectation_a:?}"), format!("{expectation_b:?}"));

        let combined =
            format!("{buckets_a:?}{nodes_a:?}{owner_slots_a:?}{token_b:?}{expectation_b:?}");
        assert!(!combined.contains(&POISON_U64.to_string()));
        assert!(!combined.contains(&format!("{POISON_U64:x}")));
        assert!(!combined.contains(&POISON_U128.to_string()));
        assert!(!combined.contains(&format!("{POISON_U128:x}")));
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
    fn bounded_walk_visits_hash_matches_in_order_and_reports_completion() {
        let mut buckets = [DirectoryBucket::default(); 4];
        let mut nodes = [DirectoryNode::default(); 4];
        let mut directory = FixedDirectory::new(&mut buckets, &mut nodes, key(5)).unwrap();
        let same = [7];
        for state_index in 0..4 {
            directory.link(state_index, DOMAIN, &same).unwrap();
        }
        // Links are pushed at the head: the walk sees 3, 2, 1, 0.
        let mut seen = Vec::new();
        let walk = directory
            .walk_bounded(DOMAIN, &same, 16, |index| {
                seen.push(index);
                false
            })
            .unwrap();
        assert_eq!(seen, [3, 2, 1, 0]);
        assert_eq!(
            walk,
            DirectoryWalk {
                probes: 4,
                stopped: false,
                complete: true,
            }
        );
        // The visitor can stop; that is neither complete nor an error.
        let walk = directory
            .walk_bounded(DOMAIN, &same, 16, |index| index == 2)
            .unwrap();
        assert_eq!(
            walk,
            DirectoryWalk {
                probes: 2,
                stopped: true,
                complete: false,
            }
        );
        // The budget cuts the chain: incomplete, never an error.
        let mut calls = 0;
        let walk = directory
            .walk_bounded(DOMAIN, &same, 3, |_| {
                calls += 1;
                false
            })
            .unwrap();
        assert_eq!(calls, 3);
        assert_eq!(
            walk,
            DirectoryWalk {
                probes: 3,
                stopped: false,
                complete: false,
            }
        );
        // Exactly the chain length is complete.
        assert!(
            directory
                .walk_bounded(DOMAIN, &same, 4, |_| false)
                .unwrap()
                .complete
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
    fn prepared_directory_mutations_recheck_snapshots_and_apply_without_failure() {
        let mut buckets = [DirectoryBucket::default(); 2];
        let mut nodes = [DirectoryNode::default(); 2];
        let mut directory = FixedDirectory::new(&mut buckets, &mut nodes, key(29)).unwrap();

        let link = directory.prepare_link(0, DOMAIN, &[10, 1]).unwrap();
        assert!(directory.prepared_link_matches(link));
        directory.apply_prepared_link(link);
        let stale_link = directory.prepare_link(1, DOMAIN, &[20, 1]).unwrap();
        let current_link = directory.prepare_link(1, DOMAIN, &[21, 1]).unwrap();
        directory.apply_prepared_link(current_link);
        assert!(!directory.prepared_link_matches(stale_link));

        let relink = directory.prepare_relink(0, DOMAIN, &[10, 2]).unwrap();
        assert!(directory.prepared_relink_matches(relink));
        directory.apply_prepared_relink(relink);
        let expected_hash = directory.hash_words(DOMAIN, &[10, 2]);
        let other_hash = directory.hash_words(DOMAIN, &[21, 1]);
        assert_eq!(
            directory.validate_semantics(|index| match index {
                0 => Some(expected_hash),
                1 => Some(other_hash),
                _ => None,
            }),
            directory
                .validate()
                .map_err(DirectorySemanticError::Structural)
        );

        let unlink = directory.prepare_unlink(1).unwrap();
        assert!(directory.prepared_unlink_matches(unlink));
        directory.apply_prepared_unlink(unlink);
        assert_eq!(directory.is_linked(1), Some(false));
    }

    #[test]
    fn port_owner_range_assignment_conditional_clear_and_validation_are_exact() {
        let mut slots = [PortOwnerSlot::default(); 3];
        let mut words = [0_u64; 2];
        let mut owners = PortOwnerTable::new(&mut slots, &mut words, 40_000, 40_002, 2).unwrap();
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
        let mut words = [0_u64; 2];
        let mut owners = PortOwnerTable::new(&mut slots, &mut words, 40_000, 40_000, 1).unwrap();
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
    fn prepared_port_claim_and_move_are_exact_and_nofail_after_recheck() {
        let mut slots = [PortOwnerSlot::default(); 2];
        let mut words = [0_u64; 2];
        let mut owners = PortOwnerTable::new(&mut slots, &mut words, 40_000, 40_001, 2).unwrap();
        let first = PortOwnerToken::new(0, 1, 10).unwrap();
        let second = PortOwnerToken::new(1, 1, 10).unwrap();
        let replacement = PortOwnerToken::new(0, 2, 10).unwrap();

        let claim = owners.prepare_claim(40_000, None, first).unwrap();
        assert!(owners.prepared_claim_matches(claim));
        owners.apply_prepared_claim(claim);
        owners.assign(40_001, second).unwrap();
        let movement = owners
            .prepare_move(Some((40_000, first)), 40_001, Some(second), replacement)
            .unwrap();
        assert!(owners.prepared_move_matches(movement));
        owners.apply_prepared_move(movement);
        assert_eq!(owners.owner(40_000), Ok(None));
        assert_eq!(owners.owner(40_001), Ok(Some(replacement)));

        let stale = owners
            .prepare_move(Some((40_001, replacement)), 40_000, None, first)
            .unwrap();
        owners.assign(40_000, second).unwrap();
        assert!(!owners.prepared_move_matches(stale));
        assert_eq!(owners.owner(40_000), Ok(Some(second)));
        assert_eq!(owners.owner(40_001), Ok(Some(replacement)));
    }

    #[test]
    fn port_owner_semantics_cover_live_dead_missing_and_mismatched_owners() {
        let mut slots = [PortOwnerSlot::default(); 2];
        let mut words = [0_u64; 2];
        let mut owners = PortOwnerTable::new(&mut slots, &mut words, 40_000, 40_001, 2).unwrap();
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
            PortOwnerTable::new(&mut zero, &mut [0_u64; 2], 0, 0, 1),
            Err(PortOwnerConfigError::ZeroPort)
        ));
        assert_eq!(zero, [occupied; 1]);

        let mut reversed = [occupied; 1];
        assert!(matches!(
            PortOwnerTable::new(&mut reversed, &mut [0_u64; 2], 40_001, 40_000, 1),
            Err(PortOwnerConfigError::InvalidRange)
        ));
        assert_eq!(reversed, [occupied; 1]);

        let mut wrong_len = [occupied; 1];
        assert!(matches!(
            PortOwnerTable::new(&mut wrong_len, &mut [0_u64; 2], 40_000, 40_001, 1),
            Err(PortOwnerConfigError::SlotCountMismatch)
        ));
        assert_eq!(wrong_len, [occupied; 1]);
    }

    #[test]
    fn corrupt_port_owner_is_reported_without_mutation() {
        let mut slots = [PortOwnerSlot::default(); 1];
        let mut words = [0_u64; 2];
        let owners = PortOwnerTable::new(&mut slots, &mut words, 40_000, 40_000, 1).unwrap();
        owners.slots[0].state_index_plus_one = 2;
        let before = owners.slots[0];
        assert_eq!(owners.owner(40_000), Err(PortOwnerError::CorruptOwner));
        assert_eq!(owners.slots[0], before);
    }

    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = *state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    /// The first unowned port a walk of the pool from `start` reaches: the
    /// walk the bitmap search must reproduce, as the reference.
    fn walk_first_unowned(owners: &PortOwnerTable<'_>, start: usize) -> Option<u16> {
        let count = owners.slot_count();
        (0..count)
            .map(|step| (start + step) % count)
            .find(|offset| owners.slots[*offset] == PortOwnerSlot::default())
            .map(|offset| owners.first_port + offset as u16)
    }

    #[test]
    fn bitmap_words_cover_every_pool_size_exactly() {
        assert_eq!(port_free_bitmap_words(0), 0);
        assert_eq!(port_free_bitmap_words(1), 2);
        assert_eq!(port_free_bitmap_words(64), 2);
        assert_eq!(port_free_bitmap_words(65), 3);
        assert_eq!(port_free_bitmap_words(4096), 65);
        assert_eq!(port_free_bitmap_words(4097), 67);
        // The widest pool (1..=65535): 1024 leaf and 16 summary words.
        assert_eq!(port_free_bitmap_words(65_535), 1040);
        let mut slots = [PortOwnerSlot::default(); 2];
        let mut words = [0_u64; 3];
        assert!(matches!(
            PortOwnerTable::new(&mut slots, &mut words, 40_000, 40_001, 2),
            Err(PortOwnerConfigError::BitmapSizeMismatch)
        ));
        assert_eq!(words, [0; 3]);
    }

    /// Bitmap search returns exactly the port a linear walk would, for
    /// every start, under random ownership and every mutation primitive,
    /// with a bounded number of word reads; exhaustion is `None`.
    #[test]
    fn bitmap_search_matches_a_pool_walk_with_bounded_reads() {
        let mut rng = 0x5eed_u64;
        for (first, last) in [
            (40_000, 40_000),
            (40_000, 40_062),
            (40_000, 40_063),
            (40_000, 40_064),
            (1_000, 5_096),
            (1, 65_535),
        ] {
            let count = usize::from(last - first) + 1;
            let mut slots = vec![PortOwnerSlot::default(); count];
            let mut words = vec![0_u64; port_free_bitmap_words(count)];
            let mut owners =
                PortOwnerTable::new(&mut slots, &mut words, first, last, count).unwrap();
            let summary_words = port_free_bitmap_words(count) - count.div_ceil(64);
            let read_bound = 2 + 2 * summary_words;
            for round in 0..64 {
                // Own or free a random batch of ports through the public
                // mutators (assign, conditional clear, and moves).
                for _ in 0..(1 + count / 8).min(512) {
                    let offset = (splitmix(&mut rng) as usize) % count;
                    let port = first + offset as u16;
                    let token = PortOwnerToken::new(offset, round + 1, 7).unwrap();
                    match splitmix(&mut rng) % 3 {
                        0 => owners.assign(port, token).unwrap(),
                        1 => {
                            if let Some(owner) = owners.owner(port).unwrap() {
                                assert!(owners.clear_if(port, owner).unwrap());
                            }
                        }
                        _ => {
                            let target = first + ((splitmix(&mut rng) as usize) % count) as u16;
                            let old = owners.owner(port).unwrap().map(|owner| (port, owner));
                            let expected = owners.owner(target).unwrap();
                            let replacement = PortOwnerToken::new(offset, round + 2, 7).unwrap();
                            let movement = owners
                                .prepare_move(old, target, expected, replacement)
                                .unwrap();
                            owners.apply_prepared_move_topology(movement.topology(), replacement);
                        }
                    }
                }
                if round == 40 {
                    // Fill the pool: exhaustion is found without a walk.
                    for offset in 0..count {
                        let token = PortOwnerToken::new(offset, 99, 7).unwrap();
                        owners.assign(first + offset as u16, token).unwrap();
                    }
                }
                assert!(owners.bitmap_matches_slots());
                for _ in 0..32 {
                    let start = splitmix(&mut rng) as usize;
                    owners.take_bitmap_word_reads();
                    assert_eq!(
                        owners.first_unowned_port_from(start),
                        walk_first_unowned(&owners, start % count)
                    );
                    assert!(owners.take_bitmap_word_reads() <= read_bound);
                }
            }
            owners.clear();
            assert!(owners.bitmap_matches_slots());
            assert_eq!(owners.first_unowned_port_from(count - 1), Some(last));
            assert_eq!(owners.first_unowned_port_from(count), Some(first));
        }
    }

    #[test]
    fn bitmap_mismatch_is_reported_by_semantic_validation() {
        let mut slots = [PortOwnerSlot::default(); 2];
        let mut words = [0_u64; 2];
        let owners = PortOwnerTable::new(&mut slots, &mut words, 40_000, 40_001, 2).unwrap();
        assert_eq!(
            owners.validate_semantics(|_| None),
            Ok(PortOwnerConservation::default())
        );
        owners.free.words[0] = 0b01;
        assert_eq!(
            owners.validate_semantics(|_| None),
            Err(PortOwnerSemanticError::FreeBitmapMismatch)
        );
        owners.free.words[0] = 0b11;
        owners.free.words[1] = 0;
        assert_eq!(
            owners.validate_semantics(|_| None),
            Err(PortOwnerSemanticError::FreeBitmapMismatch)
        );
    }
}
