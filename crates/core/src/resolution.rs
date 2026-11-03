#[cfg(test)]
use std::cell::Cell;
use std::{marker::PhantomData, rc::Rc};

use crate::{
    arp_hold::{ArpHoldMiss, ArpHoldNextHop},
    fixed_directory::{DirectoryHashDomain, DirectoryHashKey},
    slot_index::{
        bucket_of, chain_bucket, chain_head, chain_next, first_unused, key_bucket, link, replace,
        set_used, unlink, validate, validate_bits, walk, Chain, ChainNode, IndexCorrupt, UsedBits,
        INDEX_NONE,
    },
    slot_list::{Linked, SlotLinks, SlotList},
    GeneratedAllocationError, GeneratedBatchCompletion, GeneratedPacketBatch, GeneratedPacketIo,
    HighWaterMark, Icmpv4ErrorAction, Icmpv4ErrorDisposition, Icmpv4ErrorKind, Icmpv4ErrorRuntime,
    IfId, Ipv4Address, MacAddress, TableOccupancy, ARP_ETHERTYPE, ICMPV4_ERROR_MAX_QUOTE_LEN,
    IPV4_ETHERTYPE,
};

// RFC 5227 announcements of the router's own addresses and address
// conflict detection (ARP-033..ARP-039).
mod announce;
pub use announce::{
    execute_one_arp_announcement, ArpAnnounceCounters, ArpAnnouncePolicy, ArpAnnouncePolicyError,
    ArpAnnounceSlot, ARP_ANNOUNCE_DEFAULT_MIN_INTERVAL_MS, ARP_ANNOUNCE_INTERVAL_MS,
    ARP_ANNOUNCE_MAX_COUNT, ARP_ANNOUNCE_MAX_INTERVAL_MS, ARP_ANNOUNCE_MIN_INTERVAL_MS,
    ARP_ANNOUNCE_NUM, ARP_ANNOUNCE_RETRY_MAX_MS, ARP_ANNOUNCE_RETRY_MS, ARP_DEFEND_INTERVAL_MS,
};

pub const ARP_REQUEST_FRAME_LEN: usize = 60;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicMillis(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionPolicyError {
    IntervalTooShort,
    StateTtlTooShort,
    DynamicNeighborTtlZero,
    MaxAttemptsZero,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionPolicy {
    interval_ms: u64,
    state_ttl_ms: u64,
    dynamic_neighbor_ttl_ms: u64,
    max_attempts: u16,
}

impl ResolutionPolicy {
    pub fn new(interval_ms: u64, state_ttl_ms: u64) -> Result<Self, ResolutionPolicyError> {
        if interval_ms < 1_000 {
            return Err(ResolutionPolicyError::IntervalTooShort);
        }
        if state_ttl_ms < interval_ms {
            return Err(ResolutionPolicyError::StateTtlTooShort);
        }
        Ok(Self {
            interval_ms,
            state_ttl_ms,
            dynamic_neighbor_ttl_ms: 60_000,
            max_attempts: 3,
        })
    }

    pub fn with_retry(
        interval_ms: u64,
        state_ttl_ms: u64,
        max_attempts: u16,
    ) -> Result<Self, ResolutionPolicyError> {
        if max_attempts == 0 {
            return Err(ResolutionPolicyError::MaxAttemptsZero);
        }
        let mut policy = Self::new(interval_ms, state_ttl_ms)?;
        policy.max_attempts = max_attempts;
        Ok(policy)
    }

    pub fn with_dynamic_neighbor_ttl(
        interval_ms: u64,
        state_ttl_ms: u64,
        dynamic_neighbor_ttl_ms: u64,
    ) -> Result<Self, ResolutionPolicyError> {
        let mut policy = Self::new(interval_ms, state_ttl_ms)?;
        if dynamic_neighbor_ttl_ms == 0 {
            return Err(ResolutionPolicyError::DynamicNeighborTtlZero);
        }
        policy.dynamic_neighbor_ttl_ms = dynamic_neighbor_ttl_ms;
        Ok(policy)
    }

    pub fn with_retry_and_dynamic_neighbor_ttl(
        interval_ms: u64,
        state_ttl_ms: u64,
        max_attempts: u16,
        dynamic_neighbor_ttl_ms: u64,
    ) -> Result<Self, ResolutionPolicyError> {
        let mut policy = Self::with_retry(interval_ms, state_ttl_ms, max_attempts)?;
        if dynamic_neighbor_ttl_ms == 0 {
            return Err(ResolutionPolicyError::DynamicNeighborTtlZero);
        }
        policy.dynamic_neighbor_ttl_ms = dynamic_neighbor_ttl_ms;
        Ok(policy)
    }

    #[must_use]
    pub const fn interval_ms(self) -> u64 {
        self.interval_ms
    }

    #[must_use]
    pub const fn failed_hold_ms(self) -> u64 {
        self.state_ttl_ms
    }

    #[must_use]
    pub const fn max_attempts(self) -> u16 {
        self.max_attempts
    }

    #[must_use]
    pub const fn dynamic_neighbor_ttl_ms(self) -> u64 {
        self.dynamic_neighbor_ttl_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpRequestAction {
    pub egress: IfId,
    pub source_mac: MacAddress,
    pub source_ip: Ipv4Address,
    pub target_ip: Ipv4Address,
}

/// Longest key chain the state, dynamic-neighbor, and failure-hold forward
/// indexes admit (H4b, PERF-001).
///
/// Each of those tables has one bucket per slot and a secret keyed SipHash,
/// so a chain this long is astronomically unlikely by chance, and it cannot
/// be aimed at as long as the key stays secret. An insert into
/// a chain that already holds this many entries fails closed with the
/// table's existing full result (`StateFull`, `CacheFull`, or
/// `CapacityFull`) and a `*_probe_exhausted` count in
/// [`ResolutionIndexCounters`]. Because inserts never grow a chain past this
/// limit, every lookup in these tables visits at most this many slots.
pub const RESOLUTION_INDEX_CHAIN_LIMIT: usize = 16;

/// Secret key of the resolution runtime's hashed indexes.
///
/// The control plane must generate a fresh unpredictable key for every
/// runtime construction and successful publication
/// ([`ResolutionRuntime::with_hash_key`],
/// [`ResolutionPublicationPermit::commit_with_hash_key`]).
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ResolutionHashKey(DirectoryHashKey);

impl std::fmt::Debug for ResolutionHashKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResolutionHashKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResolutionHashKeyError {
    AllZero,
}

impl ResolutionHashKey {
    /// Constructs a control-plane supplied resolution index key.
    pub const fn new(first: u64, second: u64) -> Result<Self, ResolutionHashKeyError> {
        match DirectoryHashKey::new(first, second) {
            Ok(key) => Ok(Self(key)),
            Err(_) => Err(ResolutionHashKeyError::AllZero),
        }
    }

    /// The secret, for other per-publication uses in their own hash domain.
    pub(crate) const fn directory_key(self) -> DirectoryHashKey {
        self.0
    }
}

/// Public fixed key of the constructors that take no key (tests and benches).
/// Chains stay capped at insert, so a known key can only make inserts fail
/// closed, except in the uncapped reverse failure-hold index.
const FIXED_HASH_KEY: DirectoryHashKey =
    match DirectoryHashKey::new(0x7275_7374_6572_7273, 0x6c76_2d66_6978_6564) {
        Ok(key) => key,
        Err(_) => panic!("nonzero fixed key"),
    };

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResolutionKey {
    egress: IfId,
    target: Ipv4Address,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QueuedAction {
    action: ArpRequestAction,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionPhase {
    InitialQueued,
    Waiting,
    RetryQueued,
    Failed,
    Cooldown,
}

/// One slot of the ARP request queue.
///
/// Queued slots form a FIFO list; slot `i` also stores word `i` of the
/// queue's free-slot bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionActionSlot {
    queued: Option<QueuedAction>,
    state: u32,
    links: SlotLinks,
    used_word: u64,
}

impl ResolutionActionSlot {
    pub const EMPTY: Self = Self {
        queued: None,
        state: INDEX_NONE,
        links: SlotLinks::UNLINKED,
        used_word: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StateEntry {
    key: ResolutionKey,
    action: ArpRequestAction,
    generation: u64,
    attempts: u16,
    accepted_attempts: u16,
    requested_at: MonotonicMillis,
    failed_at: MonotonicMillis,
    occupied: bool,
    phase: ResolutionPhase,
    failure_notified: bool,
}

impl StateEntry {
    const EMPTY: Self = Self {
        key: ResolutionKey {
            egress: IfId(0),
            target: Ipv4Address::from_octets([0; 4]),
        },
        action: ArpRequestAction {
            egress: IfId(0),
            source_mac: MacAddress([0; 6]),
            source_ip: Ipv4Address::from_octets([0; 4]),
            target_ip: Ipv4Address::from_octets([0; 4]),
        },
        generation: 0,
        attempts: 0,
        accepted_attempts: 0,
        requested_at: MonotonicMillis(0),
        failed_at: MonotonicMillis(0),
        occupied: false,
        phase: ResolutionPhase::InitialQueued,
        failure_notified: false,
    };
}

/// One resolution state slot.
///
/// Besides the state, the slot is a node of the key chain (key: egress
/// interface and target IPv4) and of the request-order list, and stores
/// table word `i`: the head of key bucket `i` and word `i` of the
/// reusable-slot bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionStateSlot {
    entry: StateEntry,
    chain: ChainNode,
    order: SlotLinks,
    in_order: bool,
    action_slot: u32,
    bucket_head: u32,
    used_word: u64,
}

impl ResolutionStateSlot {
    pub const EMPTY: Self = Self {
        entry: StateEntry::EMPTY,
        chain: ChainNode::UNLINKED,
        order: SlotLinks::UNLINKED,
        in_order: false,
        action_slot: INDEX_NONE,
        bucket_head: INDEX_NONE,
        used_word: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DynamicEntry {
    interface: IfId,
    target: Ipv4Address,
    mac: MacAddress,
    refreshed_at: MonotonicMillis,
    occupied: bool,
}

impl DynamicEntry {
    const EMPTY: Self = Self {
        interface: IfId(0),
        target: Ipv4Address::from_octets([0; 4]),
        mac: MacAddress([0; 6]),
        refreshed_at: MonotonicMillis(0),
        occupied: false,
    };
}

/// One dynamic ARP cache slot.
///
/// Besides the entry, the slot is a node of the key chain (key: interface
/// and IPv4) and of the refresh-order list, and stores table word `i`: the
/// head of key bucket `i` and word `i` of the reusable-slot bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicNeighborSlot {
    entry: DynamicEntry,
    chain: ChainNode,
    lru: SlotLinks,
    in_lru: bool,
    bucket_head: u32,
    used_word: u64,
}

impl DynamicNeighborSlot {
    pub const EMPTY: Self = Self {
        entry: DynamicEntry::EMPTY,
        chain: ChainNode::UNLINKED,
        lru: SlotLinks::UNLINKED,
        in_lru: false,
        bucket_head: INDEX_NONE,
        used_word: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicLookup {
    Hit(MacAddress),
    Miss,
    ClockRegression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlDisposition {
    Inserted,
    Updated,
    Ignored,
    StaticPreserved,
    CacheFull,
    Probe,
    SenderNotHost,
    LocalAddressPreserved,
    ClockRegression,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StaticReconcileReport {
    pub dynamic_removed: usize,
    pub states_removed: usize,
    pub actions_removed: usize,
    pub invalid_states_removed: usize,
    pub invalid_actions_removed: usize,
    pub cooldowns_retained: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResolutionPublicationError {
    ActionQueueCapacity,
    ActionQueueHead,
    ActionQueueWindow,
    PendingStateCount,
    PendingFailureHoldCount,
    RuntimeEpochExhausted,
    /// A key chain, reuse bitmap, or order list disagrees with the slots.
    IndexCorrupt,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionPublicationReport {
    pub states_flushed: usize,
    pub actions_flushed: usize,
    pub dynamic_neighbors_flushed: usize,
    pub failure_holds_flushed: usize,
    /// Learned neighbors kept by a carrying commit (RELOAD-CARRY).
    pub dynamic_neighbors_carried: usize,
    /// `Carried` for a carrying commit, which still flushes pending
    /// resolution states, actions, and failure holds.
    pub outcome: crate::StateCarryOutcome,
}

/// Exclusive proof that old resolution authority can be flushed totally.
///
/// A fresh publication conservatively flushes all learned and queued
/// resolution authority. The permit therefore retains no target-owner borrow
/// and cannot become self-referential when that owner moves into its active
/// slot.
///
/// ```compile_fail
/// use ruster_core::ResolutionRuntime;
///
/// fn reborrow<'storage>(runtime: &mut ResolutionRuntime<'storage>) {
///     let permit = runtime.preflight_publication().unwrap();
///     let _ = runtime.pending_actions();
///     permit.commit();
/// }
/// ```
#[must_use]
pub struct ResolutionPublicationPermit<'runtime, 'storage> {
    runtime: &'runtime mut ResolutionRuntime<'storage>,
    next_runtime_epoch: u128,
    preview: ResolutionPublicationReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionResult {
    Queued,
    RetryQueued,
    Suppressed,
    TimedOut,
    Failed,
    StateFull,
    ActionFull,
    ClockRegression,
    ForbiddenTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionStatus {
    pub phase: ResolutionPhase,
    pub attempts: u16,
    pub accepted_attempts: u16,
    pub generation: u64,
    pub requested_at: Option<MonotonicMillis>,
    pub failed_at: Option<MonotonicMillis>,
    pub terminal_notified: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionCounters {
    pub queued: usize,
    pub suppressed: usize,
    pub state_full: usize,
    pub action_full: usize,
    pub clock_regressions: usize,
    pub forbidden_target: usize,
    pub dequeued: usize,
    pub retry_queued: usize,
    pub attempts_committed: usize,
    pub attempts_accepted: usize,
    pub timed_out: usize,
    pub failed_hits: usize,
    pub failures_expired: usize,
}

/// Occupancy of the bounded resolution tables (OBS-017); see
/// [`ResolutionRuntime::occupancy`].
///
/// - `states`: state slots a new resolution cannot take: queued, waiting
///   for a reply, failed hold-downs, and cooldowns whose request interval
///   has not elapsed yet (still on the request order). An elapsed cooldown
///   is reusable and not counted. This is the same "used" bit that slot
///   admission reads, so `state_full` happens only at `capacity`.
/// - `actions`: the generated ARP request queue.
/// - `dynamic_neighbors`: learned neighbors, expired ones included until
///   their slot is reused or removed.
/// - `failure_holds`: datagrams held for a Host Unreachable error.
///
/// `high_water` is the largest count since construction or the last
/// publication commit. Every commit flushes the states, actions, and
/// failure holds, so their marks restart at zero. A flushing commit also
/// empties the learned neighbors and restarts their mark; a carrying commit
/// keeps the mark (as OBS-015 keeps it across a reconcile that keeps state).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionOccupancy {
    pub states: TableOccupancy,
    pub actions: TableOccupancy,
    pub dynamic_neighbors: TableOccupancy,
    pub failure_holds: TableOccupancy,
}

/// High-water marks behind [`ResolutionOccupancy`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ResolutionHighWater {
    states: HighWaterMark,
    actions: HighWaterMark,
    dynamic_neighbors: HighWaterMark,
    failure_holds: HighWaterMark,
}

/// Fail-closed outcomes of the hashed indexes (H4b).
///
/// Each probe-exhausted insert is also counted by the table's existing full
/// counter (`state_full`, `capture_full`) or reported as `CacheFull`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionIndexCounters {
    /// New resolution states refused because their key chain already held
    /// [`RESOLUTION_INDEX_CHAIN_LIMIT`] states.
    pub state_probe_exhausted: usize,
    /// Dynamic neighbors not learned for the same reason.
    pub dynamic_probe_exhausted: usize,
    /// Failure holds not captured for the same reason.
    pub failure_hold_probe_exhausted: usize,
    /// Index inconsistencies found on a packet path. Each one failed closed
    /// (a full result, a miss, or a skipped update) instead of mutating
    /// through the inconsistent part.
    pub index_corrupt: usize,
}

impl crate::ObservableFields for ResolutionIndexCounters {
    /// Section `resolution_index`. `ruster run` renders it in its stats
    /// blocks; the run-sim schema does not include it.
    fn visit_fields<V: crate::FieldVisitor>(&self, visitor: &mut V) {
        let Self {
            state_probe_exhausted,
            dynamic_probe_exhausted,
            failure_hold_probe_exhausted,
            index_corrupt,
        } = *self;
        for (key, value) in [
            ("state_probe_exhausted", state_probe_exhausted),
            ("dynamic_probe_exhausted", dynamic_probe_exhausted),
            ("failure_hold_probe_exhausted", failure_hold_probe_exhausted),
            ("index_corrupt", index_corrupt),
        ] {
            visitor.field(
                "resolution_index",
                key,
                crate::FieldValue::Count(value as u64),
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionGenerationToken {
    pub egress: IfId,
    pub target: Ipv4Address,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionFailureHoldPhase {
    Empty,
    WaitingForward,
    TerminalReady,
    WaitingReverse,
}

/// A bounded quote-only candidate for a future ICMPv4 Host Unreachable.
///
/// This is deliberately separate from [`ResolutionStateSlot`]. It never owns
/// an RX/TX lease and is not a packet queue: only validated metadata and at
/// most 548 original IPv4 bytes are copied before the original RX is recycled.
///
/// Besides the hold, the slot is a node of the forward chain (key: forward
/// egress and target) and, while waiting for reverse resolution, of the
/// group of holds waiting on the same reverse generation token; the first
/// hold of each group stands for it on the reverse chain. The slot also
/// stores table word `i`: the heads of both chains' bucket `i` and word `i`
/// of the free-slot bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionFailureHoldSlot {
    phase: ResolutionFailureHoldPhase,
    forward: ResolutionGenerationToken,
    reverse: ResolutionGenerationToken,
    original_source: Ipv4Address,
    original_destination: Ipv4Address,
    forward_source_mac: MacAddress,
    forward_source_ip: Ipv4Address,
    forward_prefix: Ipv4Address,
    forward_prefix_len: u8,
    original_tos: u8,
    quote_len: u16,
    quote: [u8; ICMPV4_ERROR_MAX_QUOTE_LEN],
    forward_chain: ChainNode,
    reverse_chain: ChainNode,
    /// Previous/next hold waiting on the same reverse token (the group
    /// leader, the only one on the reverse chain, has no previous).
    reverse_group_prev: u32,
    reverse_group_next: u32,
    forward_head: u32,
    reverse_head: u32,
    used_word: u64,
}

impl ResolutionFailureHoldSlot {
    pub const EMPTY: Self = Self {
        phase: ResolutionFailureHoldPhase::Empty,
        forward: ResolutionGenerationToken {
            egress: IfId(0),
            target: Ipv4Address::from_octets([0; 4]),
            generation: 0,
        },
        reverse: ResolutionGenerationToken {
            egress: IfId(0),
            target: Ipv4Address::from_octets([0; 4]),
            generation: 0,
        },
        original_source: Ipv4Address::from_octets([0; 4]),
        original_destination: Ipv4Address::from_octets([0; 4]),
        forward_source_mac: MacAddress([0; 6]),
        forward_source_ip: Ipv4Address::from_octets([0; 4]),
        forward_prefix: Ipv4Address::from_octets([0; 4]),
        forward_prefix_len: 0,
        original_tos: 0,
        quote_len: 0,
        quote: [0; ICMPV4_ERROR_MAX_QUOTE_LEN],
        forward_chain: ChainNode::UNLINKED,
        reverse_chain: ChainNode::UNLINKED,
        reverse_group_prev: INDEX_NONE,
        reverse_group_next: INDEX_NONE,
        forward_head: INDEX_NONE,
        reverse_head: INDEX_NONE,
        used_word: 0,
    };

    #[must_use]
    pub const fn phase(&self) -> ResolutionFailureHoldPhase {
        self.phase
    }

    #[must_use]
    pub const fn forward_token(&self) -> Option<ResolutionGenerationToken> {
        if matches!(self.phase, ResolutionFailureHoldPhase::Empty) {
            None
        } else {
            Some(self.forward)
        }
    }

    #[must_use]
    pub const fn quote_len(&self) -> usize {
        self.quote_len as usize
    }

    /// Resets the hold to empty, keeping the table words stored here.
    fn clear_entry(&mut self) {
        let (forward_head, reverse_head, used_word) =
            (self.forward_head, self.reverse_head, self.used_word);
        *self = Self::EMPTY;
        self.forward_head = forward_head;
        self.reverse_head = reverse_head;
        self.used_word = used_word;
    }
}

struct StateChain;

impl Chain for StateChain {
    type Slot = ResolutionStateSlot;
    fn node(slot: &Self::Slot) -> ChainNode {
        slot.chain
    }
    fn node_mut(slot: &mut Self::Slot) -> &mut ChainNode {
        &mut slot.chain
    }
    fn head(slot: &Self::Slot) -> u32 {
        slot.bucket_head
    }
    fn head_mut(slot: &mut Self::Slot) -> &mut u32 {
        &mut slot.bucket_head
    }
}

struct StateBits;

impl UsedBits for StateBits {
    type Slot = ResolutionStateSlot;
    fn word(slot: &Self::Slot) -> u64 {
        slot.used_word
    }
    fn word_mut(slot: &mut Self::Slot) -> &mut u64 {
        &mut slot.used_word
    }
}

impl Linked for ResolutionStateSlot {
    fn links(&self) -> SlotLinks {
        self.order
    }
    fn links_mut(&mut self) -> &mut SlotLinks {
        &mut self.order
    }
}

struct ActionBits;

impl UsedBits for ActionBits {
    type Slot = ResolutionActionSlot;
    fn word(slot: &Self::Slot) -> u64 {
        slot.used_word
    }
    fn word_mut(slot: &mut Self::Slot) -> &mut u64 {
        &mut slot.used_word
    }
}

impl Linked for ResolutionActionSlot {
    fn links(&self) -> SlotLinks {
        self.links
    }
    fn links_mut(&mut self) -> &mut SlotLinks {
        &mut self.links
    }
}

struct DynamicChain;

impl Chain for DynamicChain {
    type Slot = DynamicNeighborSlot;
    fn node(slot: &Self::Slot) -> ChainNode {
        slot.chain
    }
    fn node_mut(slot: &mut Self::Slot) -> &mut ChainNode {
        &mut slot.chain
    }
    fn head(slot: &Self::Slot) -> u32 {
        slot.bucket_head
    }
    fn head_mut(slot: &mut Self::Slot) -> &mut u32 {
        &mut slot.bucket_head
    }
}

struct DynamicBits;

impl UsedBits for DynamicBits {
    type Slot = DynamicNeighborSlot;
    fn word(slot: &Self::Slot) -> u64 {
        slot.used_word
    }
    fn word_mut(slot: &mut Self::Slot) -> &mut u64 {
        &mut slot.used_word
    }
}

impl Linked for DynamicNeighborSlot {
    fn links(&self) -> SlotLinks {
        self.lru
    }
    fn links_mut(&mut self) -> &mut SlotLinks {
        &mut self.lru
    }
}

struct HoldForwardChain;

impl Chain for HoldForwardChain {
    type Slot = ResolutionFailureHoldSlot;
    fn node(slot: &Self::Slot) -> ChainNode {
        slot.forward_chain
    }
    fn node_mut(slot: &mut Self::Slot) -> &mut ChainNode {
        &mut slot.forward_chain
    }
    fn head(slot: &Self::Slot) -> u32 {
        slot.forward_head
    }
    fn head_mut(slot: &mut Self::Slot) -> &mut u32 {
        &mut slot.forward_head
    }
}

struct HoldReverseChain;

impl Chain for HoldReverseChain {
    type Slot = ResolutionFailureHoldSlot;
    fn node(slot: &Self::Slot) -> ChainNode {
        slot.reverse_chain
    }
    fn node_mut(slot: &mut Self::Slot) -> &mut ChainNode {
        &mut slot.reverse_chain
    }
    fn head(slot: &Self::Slot) -> u32 {
        slot.reverse_head
    }
    fn head_mut(slot: &mut Self::Slot) -> &mut u32 {
        &mut slot.reverse_head
    }
}

struct HoldBits;

impl UsedBits for HoldBits {
    type Slot = ResolutionFailureHoldSlot;
    fn word(slot: &Self::Slot) -> u64 {
        slot.used_word
    }
    fn word_mut(slot: &mut Self::Slot) -> &mut u64 {
        &mut slot.used_word
    }
}

const fn ipv4_word(address: Ipv4Address) -> u64 {
    u32::from_be_bytes(address.octets()) as u64
}

const fn key_words(egress: IfId, target: Ipv4Address) -> [u64; 2] {
    [egress.0 as u64, ipv4_word(target)]
}

const fn token_words(token: ResolutionGenerationToken) -> [u64; 3] {
    [
        token.egress.0 as u64,
        ipv4_word(token.target),
        token.generation,
    ]
}

/// A state slot is used (not reusable) unless it is free or an elapsed
/// cooldown. A cooldown is known to be elapsed once it left the request
/// order list (see [`ResolutionRuntime::mature_states`]).
const fn state_used(slot: &ResolutionStateSlot) -> bool {
    slot.entry.occupied
        && !(matches!(slot.entry.phase, ResolutionPhase::Cooldown) && !slot.in_order)
}

/// A dynamic neighbor slot is used unless it is free or expired. An entry is
/// known to be expired once it left the refresh-order list.
const fn dynamic_used(slot: &DynamicNeighborSlot) -> bool {
    slot.entry.occupied && slot.in_lru
}

#[derive(Clone, Copy, Debug)]
struct KeyLookup {
    bucket: usize,
    found: Option<usize>,
    /// Length of the whole chain when `found` is `None`.
    chain_len: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionFailureCounters {
    pub captured: usize,
    pub capture_full: usize,
    pub promoted: usize,
    pub no_accepted_arp_request: usize,
    pub cancelled: usize,
    pub reverse_arp_scheduled: usize,
    pub reverse_arp_pending: usize,
    pub reverse_resolution_failed: usize,
    pub same_failed_key: usize,
    pub queued: usize,
    pub retained_transient: usize,
    pub retired_permanent: usize,
    /// Holds retired because the ICMPv4 error policy disables Host
    /// Unreachable generation; no reverse ARP or action was attempted.
    pub generation_disabled: usize,
    /// Holds retired because the reverse egress MTU leaves less room than
    /// the RFC 792 minimum quote of the held datagram (its header with
    /// options and 8 data bytes; MTU1). Retired, not retained: the hold
    /// could never be answered and would otherwise be re-suppressed on
    /// every scan.
    pub quote_below_minimum: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionFailureDispatchReport {
    pub scanned: usize,
    pub queued: usize,
    pub retained: usize,
    pub retired: usize,
    pub reverse_arp_scheduled: usize,
    pub reverse_arp_pending: usize,
    pub pending: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionFailureDispatchError {
    ClockRegression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionFailureCapture {
    Captured(ResolutionGenerationToken),
    Existing(ResolutionGenerationToken),
    Inactive,
    CapacityFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionFailureTrace {
    Queued {
        forward: ResolutionGenerationToken,
        reverse_egress: IfId,
    },
    ReverseArpScheduled {
        forward: ResolutionGenerationToken,
        reverse: ResolutionGenerationToken,
    },
    ReverseArpPending {
        forward: ResolutionGenerationToken,
        reverse: ResolutionGenerationToken,
    },
    Retained {
        forward: ResolutionGenerationToken,
        disposition: Icmpv4ErrorDisposition,
    },
    ReverseResolutionFailed {
        forward: ResolutionGenerationToken,
        reverse: ResolutionGenerationToken,
    },
    SameFailedKey {
        forward: ResolutionGenerationToken,
    },
    ForwardAuthorityLost {
        forward: ResolutionGenerationToken,
    },
    GenerationDisabled {
        forward: ResolutionGenerationToken,
    },
    /// The hold retired as [`ResolutionFailureCounters::quote_below_minimum`].
    QuoteBelowMinimum {
        forward: ResolutionGenerationToken,
    },
    ClockRegression,
}

pub trait ResolutionFailureTraceSink {
    fn record_resolution_failure(&mut self, event: ResolutionFailureTrace);
}

#[derive(Default)]
pub struct NoResolutionFailureTrace;

impl ResolutionFailureTraceSink for NoResolutionFailureTrace {
    fn record_resolution_failure(&mut self, _event: ResolutionFailureTrace) {}
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionTimerReport {
    pub scanned: usize,
    pub retries_queued: usize,
    pub timed_out: usize,
    pub no_accepted_arp_request: usize,
    pub failures_expired: usize,
    pub action_full: usize,
    pub deferred_due: usize,
    pub pending: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionTimerError {
    ClockRegression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionTimerTrace {
    RetryQueued {
        egress: IfId,
        target: Ipv4Address,
        attempts: u16,
        generation: u64,
    },
    TimedOut {
        egress: IfId,
        target: Ipv4Address,
        attempts: u16,
        generation: u64,
    },
    NoAcceptedArpRequest {
        egress: IfId,
        target: Ipv4Address,
        generation: u64,
    },
    FailureExpired {
        egress: IfId,
        target: Ipv4Address,
        generation: u64,
    },
    ActionFull {
        egress: IfId,
        target: Ipv4Address,
        attempts: u16,
        generation: u64,
    },
    ClockRegression,
}

pub trait ResolutionTimerTraceSink {
    fn record_resolution_timer(&mut self, event: ResolutionTimerTrace);
}

#[derive(Default)]
pub struct NoResolutionTimerTrace;

impl ResolutionTimerTraceSink for NoResolutionTimerTrace {
    #[inline]
    fn record_resolution_timer(&mut self, _event: ResolutionTimerTrace) {}
}

/// Caller-backed worker-local resolution state.
///
/// Every per-packet operation finds its state, dynamic neighbor, failure
/// hold, or free slot through indexes embedded in the caller's slots (keyed
/// chains, reusable-slot bitmaps, and time-ordered lists; H4b, PERF-001), so
/// its cost does not grow with the table capacity.
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<ruster_core::ResolutionRuntime<'static>>();
/// ```
///
/// ```compile_fail
/// fn require_sync<T: Sync>() {}
/// require_sync::<ruster_core::ResolutionRuntime<'static>>();
/// ```
pub struct ResolutionRuntime<'a> {
    policy: ResolutionPolicy,
    states: &'a mut [ResolutionStateSlot],
    actions: &'a mut [ResolutionActionSlot],
    dynamic_neighbors: &'a mut [DynamicNeighborSlot],
    failure_holds: &'a mut [ResolutionFailureHoldSlot],
    hash_key: DirectoryHashKey,
    /// Queued ARP request slots, oldest first.
    action_queue: SlotList,
    /// States with at least one committed request whose interval had not
    /// elapsed when last checked, in commit (`requested_at`) order.
    request_order: SlotList,
    /// Dynamic neighbors not known to be expired, in refresh order.
    dynamic_order: SlotList,
    dynamic_count: usize,
    pending_state_count: usize,
    /// State slots marked used in the reusable bitmap (OBS-017), kept at
    /// [`Self::refresh_state_bit`], the only place the bit changes.
    used_state_count: usize,
    pending_failure_hold_count: usize,
    poll_cursor: usize,
    failure_cursor: usize,
    last_now: Option<MonotonicMillis>,
    publication_epoch: u128,
    counters: ResolutionCounters,
    failure_counters: ResolutionFailureCounters,
    index_counters: ResolutionIndexCounters,
    high_water: ResolutionHighWater,
    /// The neighbour miss of the datagram being decided that started or
    /// joined an ARP resolution (ARP-HOLD): set at a forwarding miss,
    /// cleared before each datagram when holding is on.
    forward_miss: Option<ResolutionKey>,
    /// One RFC 5227 announcement slot per snapshot interface (ARP-033);
    /// empty when not attached ([`Self::with_announce_slots`]).
    announce: &'a mut [ArpAnnounceSlot],
    /// Slots with a trigger waiting or a sequence running.
    announce_busy: usize,
    /// Round-robin start of the next announcement scan.
    announce_cursor: usize,
    announce_counters: ArpAnnounceCounters,
    /// Index slots visited (chain nodes, list heads, bitmap words). Cost
    /// tests read it; it never affects behavior. Test builds only.
    #[cfg(test)]
    visits: Cell<u64>,
    _worker_local: PhantomData<Rc<()>>,
}

impl<'a> ResolutionRuntime<'a> {
    /// Test and bench constructor with a public fixed index key; production
    /// code uses [`Self::with_hash_key`].
    #[doc(hidden)]
    #[must_use]
    pub fn new(
        policy: ResolutionPolicy,
        states: &'a mut [ResolutionStateSlot],
        action_storage: &'a mut [ResolutionActionSlot],
    ) -> Self {
        Self::with_dynamic_neighbors(policy, states, action_storage, &mut [])
    }

    /// Test and bench constructor with a public fixed index key; production
    /// code uses [`Self::with_hash_key`].
    #[doc(hidden)]
    #[must_use]
    pub fn with_dynamic_neighbors(
        policy: ResolutionPolicy,
        states: &'a mut [ResolutionStateSlot],
        action_storage: &'a mut [ResolutionActionSlot],
        dynamic_neighbors: &'a mut [DynamicNeighborSlot],
    ) -> Self {
        Self::with_dynamic_neighbors_and_failure_holds(
            policy,
            states,
            action_storage,
            dynamic_neighbors,
            &mut [],
        )
    }

    /// Test and bench constructor with a public fixed index key; production
    /// code uses [`Self::with_hash_key`].
    #[doc(hidden)]
    #[must_use]
    pub fn with_dynamic_neighbors_and_failure_holds(
        policy: ResolutionPolicy,
        states: &'a mut [ResolutionStateSlot],
        action_storage: &'a mut [ResolutionActionSlot],
        dynamic_neighbors: &'a mut [DynamicNeighborSlot],
        failure_holds: &'a mut [ResolutionFailureHoldSlot],
    ) -> Self {
        Self::build(
            policy,
            states,
            action_storage,
            dynamic_neighbors,
            failure_holds,
            FIXED_HASH_KEY,
        )
    }

    /// Builds a runtime whose hashed indexes use the secret `hash_key`.
    ///
    /// Every slice is cleared. Each table must have fewer than `u32::MAX`
    /// slots.
    #[must_use]
    pub fn with_hash_key(
        policy: ResolutionPolicy,
        states: &'a mut [ResolutionStateSlot],
        action_storage: &'a mut [ResolutionActionSlot],
        dynamic_neighbors: &'a mut [DynamicNeighborSlot],
        failure_holds: &'a mut [ResolutionFailureHoldSlot],
        hash_key: ResolutionHashKey,
    ) -> Self {
        Self::build(
            policy,
            states,
            action_storage,
            dynamic_neighbors,
            failure_holds,
            hash_key.0,
        )
    }

    fn build(
        policy: ResolutionPolicy,
        states: &'a mut [ResolutionStateSlot],
        action_storage: &'a mut [ResolutionActionSlot],
        dynamic_neighbors: &'a mut [DynamicNeighborSlot],
        failure_holds: &'a mut [ResolutionFailureHoldSlot],
        hash_key: DirectoryHashKey,
    ) -> Self {
        for len in [
            states.len(),
            action_storage.len(),
            dynamic_neighbors.len(),
            failure_holds.len(),
        ] {
            assert!(
                u32::try_from(len).is_ok_and(|len| len != INDEX_NONE),
                "resolution table capacity must be below u32::MAX"
            );
        }
        states.fill(ResolutionStateSlot::EMPTY);
        action_storage.fill(ResolutionActionSlot::EMPTY);
        dynamic_neighbors.fill(DynamicNeighborSlot::EMPTY);
        failure_holds.fill(ResolutionFailureHoldSlot::EMPTY);
        Self {
            policy,
            states,
            actions: action_storage,
            dynamic_neighbors,
            failure_holds,
            hash_key,
            action_queue: SlotList::EMPTY,
            request_order: SlotList::EMPTY,
            dynamic_order: SlotList::EMPTY,
            dynamic_count: 0,
            pending_state_count: 0,
            used_state_count: 0,
            pending_failure_hold_count: 0,
            poll_cursor: 0,
            failure_cursor: 0,
            last_now: None,
            publication_epoch: 1,
            counters: ResolutionCounters::default(),
            failure_counters: ResolutionFailureCounters::default(),
            index_counters: ResolutionIndexCounters::default(),
            high_water: ResolutionHighWater::default(),
            forward_miss: None,
            announce: &mut [],
            announce_busy: 0,
            announce_cursor: 0,
            announce_counters: ArpAnnounceCounters {
                requested: 0,
                coalesced: 0,
                disabled: 0,
                sequences: 0,
                rate_limited: 0,
                committed: 0,
                accepted: 0,
                rejected: 0,
                unavailable: 0,
                cancelled: 0,
                conflicts: 0,
                defended: 0,
                defense_suppressed: 0,
            },
            #[cfg(test)]
            visits: Cell::new(0),
            _worker_local: PhantomData,
        }
    }

    /// Occupied dynamic neighbor slots, expired ones included, in O(1).
    #[must_use]
    pub const fn dynamic_neighbor_count(&self) -> usize {
        self.dynamic_count
    }

    #[must_use]
    pub const fn policy(&self) -> ResolutionPolicy {
        self.policy
    }

    #[must_use]
    pub const fn state_capacity(&self) -> usize {
        self.states.len()
    }

    #[must_use]
    pub const fn action_capacity(&self) -> usize {
        self.actions.len()
    }

    #[must_use]
    pub const fn dynamic_neighbor_capacity(&self) -> usize {
        self.dynamic_neighbors.len()
    }

    #[must_use]
    pub const fn failure_hold_capacity(&self) -> usize {
        self.failure_holds.len()
    }

    /// Occupancy and high-water marks of the bounded tables (OBS-017), in
    /// O(1): every count is maintained at its slot transitions.
    #[must_use]
    pub const fn occupancy(&self) -> ResolutionOccupancy {
        let high_water = self.high_water;
        ResolutionOccupancy {
            states: high_water
                .states
                .snapshot(self.used_state_count, self.states.len()),
            actions: high_water
                .actions
                .snapshot(self.action_queue.len(), self.actions.len()),
            dynamic_neighbors: high_water
                .dynamic_neighbors
                .snapshot(self.dynamic_count, self.dynamic_neighbors.len()),
            failure_holds: high_water
                .failure_holds
                .snapshot(self.pending_failure_hold_count, self.failure_holds.len()),
        }
    }

    /// Fail-closed outcomes of the hashed indexes.
    #[must_use]
    pub const fn index_counters(&self) -> ResolutionIndexCounters {
        self.index_counters
    }

    /// Returns whether this runtime is still in its exact constructor state.
    #[must_use]
    pub fn is_pristine(&self) -> bool {
        self.states
            .iter()
            .all(|slot| *slot == ResolutionStateSlot::EMPTY)
            && self
                .actions
                .iter()
                .all(|slot| *slot == ResolutionActionSlot::EMPTY)
            && self
                .dynamic_neighbors
                .iter()
                .all(|slot| *slot == DynamicNeighborSlot::EMPTY)
            && self
                .failure_holds
                .iter()
                .all(|slot| *slot == ResolutionFailureHoldSlot::EMPTY)
            && self.action_queue == SlotList::EMPTY
            && self.request_order == SlotList::EMPTY
            && self.dynamic_order == SlotList::EMPTY
            && self.dynamic_count == 0
            && self.pending_state_count == 0
            && self.used_state_count == 0
            && self.pending_failure_hold_count == 0
            && self.poll_cursor == 0
            && self.failure_cursor == 0
            && self.last_now.is_none()
            && self.publication_epoch == 1
            && self.counters == ResolutionCounters::default()
            && self.failure_counters == ResolutionFailureCounters::default()
            && self.index_counters == ResolutionIndexCounters::default()
            && self.high_water == ResolutionHighWater::default()
    }

    /// Validates queue/accounting/index invariants and previews one
    /// publication.
    ///
    /// Preflight never mutates runtime state. The returned permit retains the
    /// exact runtime exclusively until it is committed or dropped.
    pub fn preflight_publication<'runtime>(
        &'runtime mut self,
    ) -> Result<ResolutionPublicationPermit<'runtime, 'a>, ResolutionPublicationError> {
        self.validate_publication_invariants()?;
        let next_runtime_epoch = self
            .publication_epoch
            .checked_add(1)
            .ok_or(ResolutionPublicationError::RuntimeEpochExhausted)?;
        let preview = ResolutionPublicationReport {
            states_flushed: self
                .states
                .iter()
                .filter(|state| state.entry.occupied)
                .count(),
            actions_flushed: self.action_queue.len(),
            dynamic_neighbors_flushed: self.dynamic_count,
            failure_holds_flushed: self.pending_failure_hold_count,
            dynamic_neighbors_carried: 0,
            outcome: crate::StateCarryOutcome::FlushRequested,
        };
        Ok(ResolutionPublicationPermit {
            runtime: self,
            next_runtime_epoch,
            preview,
        })
    }

    /// Removes worker-local state shadowed by a newly published static set.
    ///
    /// The owner must call this on the same worker tick that publishes the
    /// corresponding immutable forwarding snapshot, before processing another
    /// packet with that snapshot.
    pub fn reconcile_static(&mut self, neighbors: &[crate::Neighbor]) -> StaticReconcileReport {
        let mut report = StaticReconcileReport::default();
        for neighbor in neighbors {
            let key = ResolutionKey {
                egress: neighbor.interface,
                target: neighbor.target,
            };
            if let Some(index) = self.find_dynamic(key) {
                self.remove_dynamic(index);
                report.dynamic_removed += 1;
            }
        }
        for neighbor in neighbors {
            let key = ResolutionKey {
                egress: neighbor.interface,
                target: neighbor.target,
            };
            let Some(index) = self.find_state(key) else {
                continue;
            };
            if self.states[index].entry.phase == ResolutionPhase::Cooldown {
                continue;
            }
            if self.states[index].entry.attempts != 0 {
                report.cooldowns_retained += 1;
            }
            report.actions_removed += usize::from(self.cancel_state_at(index));
            report.states_removed += 1;
        }
        for neighbor in neighbors {
            self.cancel_forward_holds(neighbor.interface, neighbor.target);
        }
        report
    }

    /// Reconciles resolution authority with a newly published snapshot.
    ///
    /// The owner must publish the snapshot and call this method on the same
    /// worker tick, before timer polling or packet processing. Static
    /// resolution and changed/removed interface, binding, route, or target
    /// authority cancel matching states and actions atomically.
    pub fn reconcile_publication(
        &mut self,
        snapshot: &crate::ForwardingSnapshot<'_>,
    ) -> StaticReconcileReport {
        self.commit_publication(snapshot)
    }

    fn validate_publication_invariants(&self) -> Result<(), ResolutionPublicationError> {
        if self.action_queue.len() > self.actions.len() {
            return Err(ResolutionPublicationError::ActionQueueCapacity);
        }
        if self
            .action_queue
            .head()
            .is_some_and(|head| head >= self.actions.len())
        {
            return Err(ResolutionPublicationError::ActionQueueHead);
        }
        let actions = &*self.actions;
        let states = &*self.states;
        let queue_valid = self.action_queue.validate(actions, |index| {
            let slot = actions[index];
            slot.queued.is_some()
                && states.get(slot.state as usize).is_some_and(|state| {
                    state.action_slot as usize == index && state.entry.occupied
                })
        });
        let queued = actions.iter().filter(|slot| slot.queued.is_some()).count();
        if !queue_valid || queued != self.action_queue.len() {
            return Err(ResolutionPublicationError::ActionQueueWindow);
        }
        let pending_states = self
            .states
            .iter()
            .filter(|state| state_is_pending(state.entry))
            .count();
        if pending_states != self.pending_state_count {
            return Err(ResolutionPublicationError::PendingStateCount);
        }
        let pending_holds = self
            .failure_holds
            .iter()
            .filter(|hold| hold.phase != ResolutionFailureHoldPhase::Empty)
            .count();
        if pending_holds != self.pending_failure_hold_count {
            return Err(ResolutionPublicationError::PendingFailureHoldCount);
        }
        if !self.indexes_valid() {
            return Err(ResolutionPublicationError::IndexCorrupt);
        }
        Ok(())
    }

    /// Checks every embedded index against the slots. O(capacity); control
    /// path and tests only.
    fn indexes_valid(&self) -> bool {
        let states = &*self.states;
        let actions = &*self.actions;
        let dynamic = &*self.dynamic_neighbors;
        let holds = &*self.failure_holds;
        let state_bucket = |index: usize| {
            let entry = states[index].entry;
            entry.occupied.then(|| {
                bucket_of(
                    self.hash_key.hash_words(
                        DirectoryHashDomain::ResolutionState,
                        &key_words(entry.key.egress, entry.key.target),
                    ),
                    states.len(),
                )
            })
        };
        let mut last = 0;
        let mut ordered = 0;
        let order_valid = self.request_order.validate(states, |index| {
            let slot = states[index];
            let valid = slot.in_order
                && slot.entry.occupied
                && slot.entry.attempts != 0
                && slot.entry.requested_at.0 >= last;
            last = slot.entry.requested_at.0;
            ordered += 1;
            valid
        });
        let states_valid = validate::<StateChain>(states, state_bucket)
            && validate_bits::<StateBits>(states, |index| state_used(&states[index]))
            && order_valid
            && states.iter().filter(|slot| slot.in_order).count() == ordered
            && states.iter().enumerate().all(|(index, slot)| {
                let queued = slot.entry.occupied
                    && matches!(
                        slot.entry.phase,
                        ResolutionPhase::InitialQueued | ResolutionPhase::RetryQueued
                    );
                if slot.action_slot == INDEX_NONE {
                    !queued
                } else {
                    queued
                        && actions
                            .get(slot.action_slot as usize)
                            .is_some_and(|action| {
                                action.state as usize == index
                                    && action.queued.is_some_and(|queued| {
                                        queued.generation == slot.entry.generation
                                            && queued.action == slot.entry.action
                                    })
                            })
                }
            });
        let actions_valid =
            validate_bits::<ActionBits>(actions, |index| actions[index].queued.is_some());
        let dynamic_bucket = |index: usize| {
            let entry = dynamic[index].entry;
            entry.occupied.then(|| {
                bucket_of(
                    self.hash_key.hash_words(
                        DirectoryHashDomain::ResolutionDynamicNeighbor,
                        &key_words(entry.interface, entry.target),
                    ),
                    dynamic.len(),
                )
            })
        };
        let mut last = 0;
        let mut ordered = 0;
        let lru_valid = self.dynamic_order.validate(dynamic, |index| {
            let slot = dynamic[index];
            let valid = slot.in_lru && slot.entry.occupied && slot.entry.refreshed_at.0 >= last;
            last = slot.entry.refreshed_at.0;
            ordered += 1;
            valid
        });
        let dynamic_valid = validate::<DynamicChain>(dynamic, dynamic_bucket)
            && validate_bits::<DynamicBits>(dynamic, |index| dynamic_used(&dynamic[index]))
            && lru_valid
            && dynamic.iter().filter(|slot| slot.in_lru).count() == ordered
            && dynamic.iter().filter(|slot| slot.entry.occupied).count() == self.dynamic_count;
        let forward_bucket = |index: usize| {
            let hold = holds[index];
            (hold.phase != ResolutionFailureHoldPhase::Empty).then(|| {
                bucket_of(
                    self.hash_key.hash_words(
                        DirectoryHashDomain::ResolutionHoldForward,
                        &key_words(hold.forward.egress, hold.forward.target),
                    ),
                    holds.len(),
                )
            })
        };
        let reverse_bucket = |index: usize| {
            let hold = holds[index];
            (hold.phase == ResolutionFailureHoldPhase::WaitingReverse
                && hold.reverse_group_prev == INDEX_NONE)
                .then(|| {
                    bucket_of(
                        self.hash_key.hash_words(
                            DirectoryHashDomain::ResolutionHoldReverse,
                            &token_words(hold.reverse),
                        ),
                        holds.len(),
                    )
                })
        };
        let holds_valid = validate::<HoldForwardChain>(holds, forward_bucket)
            && validate::<HoldReverseChain>(holds, reverse_bucket)
            && reverse_groups_valid(holds, |token| {
                bucket_of(
                    self.hash_key.hash_words(
                        DirectoryHashDomain::ResolutionHoldReverse,
                        &token_words(token),
                    ),
                    holds.len(),
                )
            })
            && validate_bits::<HoldBits>(holds, |index| {
                holds[index].phase != ResolutionFailureHoldPhase::Empty
            });
        states_valid && actions_valid && dynamic_valid && holds_valid
    }

    fn commit_publication(
        &mut self,
        snapshot: &crate::ForwardingSnapshot<'_>,
    ) -> StaticReconcileReport {
        let mut report = StaticReconcileReport::default();
        for neighbor in snapshot.neighbors {
            let key = ResolutionKey {
                egress: neighbor.interface,
                target: neighbor.target,
            };
            if let Some(index) = self.find_dynamic(key) {
                self.remove_dynamic(index);
                report.dynamic_removed = report.dynamic_removed.saturating_add(1);
            }
        }
        for index in 0..self.states.len() {
            let state = self.states[index].entry;
            if !state_is_pending(state) {
                continue;
            }
            let authority = snapshot.resolution_action_authority(state.action);
            if authority == crate::forwarding::ResolutionActionAuthority::Valid {
                continue;
            }
            if state.attempts != 0 {
                report.cooldowns_retained = report.cooldowns_retained.saturating_add(1);
            }
            // A queued state owns exactly one queued action with the same
            // ARP request, so the action has the state's authority.
            let action_removed = usize::from(self.cancel_state_at(index));
            match authority {
                crate::forwarding::ResolutionActionAuthority::StaticResolved => {
                    report.states_removed = report.states_removed.saturating_add(1);
                    report.actions_removed = report.actions_removed.saturating_add(action_removed);
                }
                crate::forwarding::ResolutionActionAuthority::Invalid => {
                    report.invalid_states_removed = report.invalid_states_removed.saturating_add(1);
                    report.invalid_actions_removed = report
                        .invalid_actions_removed
                        .saturating_add(action_removed);
                }
                crate::forwarding::ResolutionActionAuthority::Valid => {}
            }
        }
        for index in 0..self.failure_holds.len() {
            let hold = self.failure_holds[index];
            if hold.phase == ResolutionFailureHoldPhase::Empty
                || publication_hold_valid(snapshot, &hold)
            {
                continue;
            }
            self.clear_failure_hold(index);
            self.failure_counters.cancelled = self.failure_counters.cancelled.saturating_add(1);
        }
        report
    }

    #[must_use]
    pub const fn counters(&self) -> ResolutionCounters {
        self.counters
    }

    #[must_use]
    pub const fn failure_counters(&self) -> ResolutionFailureCounters {
        self.failure_counters
    }

    #[must_use]
    pub const fn pending_failure_holds(&self) -> usize {
        self.pending_failure_hold_count
    }

    #[must_use]
    pub const fn pending_actions(&self) -> usize {
        self.action_queue.len()
    }

    #[must_use]
    pub const fn pending_states(&self) -> usize {
        self.pending_state_count
    }

    #[must_use]
    pub fn cooldown_count(&self) -> usize {
        self.states
            .iter()
            .filter(|state| state.entry.occupied && state.entry.phase == ResolutionPhase::Cooldown)
            .count()
    }

    #[must_use]
    pub fn status(&self, egress: IfId, target: Ipv4Address) -> Option<ResolutionStatus> {
        let index = self.find_state(ResolutionKey { egress, target })?;
        let state = self.states[index].entry;
        Some(ResolutionStatus {
            phase: state.phase,
            attempts: state.attempts,
            accepted_attempts: state.accepted_attempts,
            generation: state.generation,
            requested_at: (state.attempts != 0).then_some(state.requested_at),
            failed_at: (state.phase == ResolutionPhase::Failed).then_some(state.failed_at),
            terminal_notified: state.failure_notified,
        })
    }

    /// Counts index slot visits for the cost tests; compiled out otherwise.
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    #[inline(always)]
    fn count_visits(&self, visits: usize) {
        #[cfg(test)]
        self.visits
            .set(self.visits.get().wrapping_add(visits as u64));
        #[cfg(not(test))]
        let _ = visits;
    }

    /// Records an index inconsistency met while mutating; the caller has
    /// already left the inconsistent part unchanged.
    fn index_result(&mut self, result: Result<(), IndexCorrupt>) {
        if result.is_err() {
            debug_assert!(false, "resolution index corrupt");
            self.index_counters.index_corrupt = self.index_counters.index_corrupt.saturating_add(1);
        }
    }

    fn state_bucket(&self, key: ResolutionKey) -> Option<usize> {
        key_bucket(
            self.hash_key,
            DirectoryHashDomain::ResolutionState,
            &key_words(key.egress, key.target),
            self.states.len(),
        )
    }

    /// Looks `key` up among the occupied states (at most
    /// [`RESOLUTION_INDEX_CHAIN_LIMIT`] slots). `Ok(None)` for an empty table.
    fn lookup_state(&self, key: ResolutionKey) -> Result<Option<KeyLookup>, IndexCorrupt> {
        let Some(bucket) = self.state_bucket(key) else {
            return Ok(None);
        };
        let states = &*self.states;
        let walked = walk::<StateChain>(states, bucket, RESOLUTION_INDEX_CHAIN_LIMIT, |index| {
            let entry = states[index].entry;
            entry.occupied && entry.key == key
        });
        let walked = walked?;
        self.count_visits(walked.visited.max(1));
        Ok(Some(KeyLookup {
            bucket,
            found: walked.found,
            chain_len: walked.visited,
        }))
    }

    /// The occupied state of `key`, or `None` (also when the index is
    /// inconsistent: callers then behave as on a miss).
    fn find_state(&self, key: ResolutionKey) -> Option<usize> {
        self.lookup_state(key)
            .ok()
            .flatten()
            .and_then(|lookup| lookup.found)
    }

    fn dynamic_bucket(&self, key: ResolutionKey) -> Option<usize> {
        key_bucket(
            self.hash_key,
            DirectoryHashDomain::ResolutionDynamicNeighbor,
            &key_words(key.egress, key.target),
            self.dynamic_neighbors.len(),
        )
    }

    fn lookup_dynamic_key(&self, key: ResolutionKey) -> Result<Option<KeyLookup>, IndexCorrupt> {
        let Some(bucket) = self.dynamic_bucket(key) else {
            return Ok(None);
        };
        let slots = &*self.dynamic_neighbors;
        let walked = walk::<DynamicChain>(slots, bucket, RESOLUTION_INDEX_CHAIN_LIMIT, |index| {
            let entry = slots[index].entry;
            entry.occupied && entry.interface == key.egress && entry.target == key.target
        })?;
        self.count_visits(walked.visited.max(1));
        Ok(Some(KeyLookup {
            bucket,
            found: walked.found,
            chain_len: walked.visited,
        }))
    }

    fn find_dynamic(&self, key: ResolutionKey) -> Option<usize> {
        self.lookup_dynamic_key(key)
            .ok()
            .flatten()
            .and_then(|lookup| lookup.found)
    }

    /// Length of a dynamic key chain, or `None` when it is inconsistent.
    fn dynamic_chain_len(&self, bucket: usize) -> Option<usize> {
        walk::<DynamicChain>(
            self.dynamic_neighbors,
            bucket,
            RESOLUTION_INDEX_CHAIN_LIMIT,
            |_| false,
        )
        .ok()
        .map(|walked| {
            self.count_visits(walked.visited);
            walked.visited
        })
    }

    fn forward_bucket(&self, egress: IfId, target: Ipv4Address) -> Option<usize> {
        key_bucket(
            self.hash_key,
            DirectoryHashDomain::ResolutionHoldForward,
            &key_words(egress, target),
            self.failure_holds.len(),
        )
    }

    fn reverse_bucket(&self, token: ResolutionGenerationToken) -> Option<usize> {
        key_bucket(
            self.hash_key,
            DirectoryHashDomain::ResolutionHoldReverse,
            &token_words(token),
            self.failure_holds.len(),
        )
    }

    /// Whether a live hold has forward token `token`, plus the length of the
    /// forward chain of its key (complete only when not found).
    fn forward_hold_exists(
        &self,
        token: ResolutionGenerationToken,
    ) -> Result<(bool, usize), IndexCorrupt> {
        let Some(bucket) = self.forward_bucket(token.egress, token.target) else {
            return Ok((false, 0));
        };
        let holds = &*self.failure_holds;
        let walked =
            walk::<HoldForwardChain>(holds, bucket, RESOLUTION_INDEX_CHAIN_LIMIT, |index| {
                holds[index].phase != ResolutionFailureHoldPhase::Empty
                    && holds[index].forward == token
            })?;
        self.count_visits(walked.visited.max(1));
        Ok((walked.found.is_some(), walked.visited))
    }

    /// The group leader of the holds waiting for reverse resolution
    /// `token`, if any. The reverse chain holds one leader per distinct
    /// waiting token, so this walk does not grow with the number of holds
    /// that wait on one token (H4b review L1).
    fn reverse_leader(
        &self,
        token: ResolutionGenerationToken,
    ) -> Result<Option<usize>, IndexCorrupt> {
        let Some(bucket) = self.reverse_bucket(token) else {
            return Ok(None);
        };
        let holds = &*self.failure_holds;
        let walked = walk::<HoldReverseChain>(holds, bucket, holds.len(), |index| {
            holds[index].reverse == token
        })?;
        self.count_visits(walked.visited.max(1));
        Ok(walked.found)
    }

    /// Whether a hold waits for reverse resolution with token `token`.
    fn reverse_hold_exists(&self, token: ResolutionGenerationToken) -> Result<bool, IndexCorrupt> {
        self.reverse_leader(token).map(|leader| leader.is_some())
    }

    /// Adds hold `index` (already `WaitingReverse` with its token set) to
    /// the group of its reverse token: right behind the leader, or as a new
    /// leader on the reverse chain.
    fn reverse_join(&mut self, index: usize) {
        let token = self.failure_holds[index].reverse;
        match self.reverse_leader(token) {
            Ok(Some(leader)) => {
                let next = self.failure_holds[leader].reverse_group_next;
                let link = u32::try_from(index).expect("validated capacity");
                self.failure_holds[index].reverse_group_prev =
                    u32::try_from(leader).expect("validated capacity");
                self.failure_holds[index].reverse_group_next = next;
                if next != INDEX_NONE {
                    self.failure_holds[next as usize].reverse_group_prev = link;
                }
                self.failure_holds[leader].reverse_group_next = link;
            }
            Ok(None) => {
                let bucket = self.reverse_bucket(token).expect("nonempty hold table");
                let linked = link::<HoldReverseChain>(self.failure_holds, index, bucket);
                self.index_result(linked);
            }
            Err(IndexCorrupt) => self.index_result(Err(IndexCorrupt)),
        }
    }

    /// Takes hold `index` out of its reverse group. A leader hands its
    /// chain position to the next hold of the group, in O(1).
    fn reverse_leave(&mut self, index: usize) {
        let hold = self.failure_holds[index];
        let (prev, next) = (hold.reverse_group_prev, hold.reverse_group_next);
        if hold.reverse_chain.is_linked() {
            let result = if next == INDEX_NONE {
                unlink::<HoldReverseChain>(self.failure_holds, index)
            } else {
                replace::<HoldReverseChain>(self.failure_holds, index, next as usize)
            };
            self.index_result(result);
            if next != INDEX_NONE {
                self.failure_holds[next as usize].reverse_group_prev = INDEX_NONE;
            }
        } else if prev != INDEX_NONE {
            self.failure_holds[prev as usize].reverse_group_next = next;
            if next != INDEX_NONE {
                self.failure_holds[next as usize].reverse_group_prev = prev;
            }
        }
        self.failure_holds[index].reverse_group_prev = INDEX_NONE;
        self.failure_holds[index].reverse_group_next = INDEX_NONE;
    }

    /// Visits every hold of the forward chain of `(egress, target)` (all
    /// generations) or of the reverse chain of a token, in chain order, and
    /// lets `act` clear or change it. The successor is read before `act`, so
    /// clearing the visited hold is safe. Stops at the slot count or at a
    /// node of another bucket.
    fn for_each_hold<C: Chain<Slot = ResolutionFailureHoldSlot>>(
        &mut self,
        bucket: usize,
        mut act: impl FnMut(&mut Self, usize),
    ) {
        let mut current = chain_head::<C>(self.failure_holds, bucket);
        let mut steps = 0;
        while let Some(index) = current {
            if steps == self.failure_holds.len() {
                self.index_result(Err(IndexCorrupt));
                return;
            }
            steps += 1;
            self.count_visits(1);
            let node = C::node(&self.failure_holds[index]);
            if !node.is_linked() || chain_bucket(node) != Some(bucket) {
                self.index_result(Err(IndexCorrupt));
                return;
            }
            current = chain_next::<C>(self.failure_holds, index);
            act(self, index);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture_failure_candidate(
        &mut self,
        egress: IfId,
        target: Ipv4Address,
        source: Ipv4Address,
        destination: Ipv4Address,
        forward_source_mac: MacAddress,
        forward_source_ip: Ipv4Address,
        forward_prefix: Ipv4Address,
        forward_prefix_len: u8,
        original_tos: u8,
        original_ipv4: &[u8],
    ) -> ResolutionFailureCapture {
        let Some(state) = self
            .find_state(ResolutionKey { egress, target })
            .map(|index| self.states[index].entry)
            .filter(|state| {
                matches!(
                    state.phase,
                    ResolutionPhase::InitialQueued
                        | ResolutionPhase::Waiting
                        | ResolutionPhase::RetryQueued
                )
            })
        else {
            return ResolutionFailureCapture::Inactive;
        };
        let token = ResolutionGenerationToken {
            egress,
            target,
            generation: state.generation,
        };
        let chain_len = match self.forward_hold_exists(token) {
            Ok((true, _)) => return ResolutionFailureCapture::Existing(token),
            Ok((false, chain_len)) => chain_len,
            Err(IndexCorrupt) => {
                self.index_counters.index_corrupt =
                    self.index_counters.index_corrupt.saturating_add(1);
                self.failure_counters.capture_full += 1;
                return ResolutionFailureCapture::CapacityFull;
            }
        };
        let free = first_unused::<HoldBits>(self.failure_holds);
        let index = match free {
            Ok((Some(index), reads)) => {
                self.count_visits(reads);
                index
            }
            Ok((None, reads)) => {
                self.count_visits(reads);
                self.failure_counters.capture_full += 1;
                return ResolutionFailureCapture::CapacityFull;
            }
            Err(IndexCorrupt) => {
                self.index_counters.index_corrupt =
                    self.index_counters.index_corrupt.saturating_add(1);
                self.failure_counters.capture_full += 1;
                return ResolutionFailureCapture::CapacityFull;
            }
        };
        if chain_len >= RESOLUTION_INDEX_CHAIN_LIMIT {
            self.index_counters.failure_hold_probe_exhausted = self
                .index_counters
                .failure_hold_probe_exhausted
                .saturating_add(1);
            self.failure_counters.capture_full += 1;
            return ResolutionFailureCapture::CapacityFull;
        }
        let bucket = self
            .forward_bucket(egress, target)
            .expect("a free hold slot exists");
        let quote_len = original_ipv4.len().min(ICMPV4_ERROR_MAX_QUOTE_LEN);
        let slot = &mut self.failure_holds[index];
        slot.clear_entry();
        slot.phase = ResolutionFailureHoldPhase::WaitingForward;
        slot.forward = token;
        slot.original_source = source;
        slot.original_destination = destination;
        slot.forward_source_mac = forward_source_mac;
        slot.forward_source_ip = forward_source_ip;
        slot.forward_prefix = forward_prefix;
        slot.forward_prefix_len = forward_prefix_len;
        slot.original_tos = original_tos;
        slot.quote_len = quote_len as u16;
        slot.quote[..quote_len].copy_from_slice(&original_ipv4[..quote_len]);
        let linked = link::<HoldForwardChain>(self.failure_holds, index, bucket);
        self.index_result(linked);
        set_used::<HoldBits>(self.failure_holds, index, true);
        debug_assert!(self.pending_failure_hold_count < self.failure_holds.len());
        self.pending_failure_hold_count += 1;
        self.high_water
            .failure_holds
            .observe(self.pending_failure_hold_count);
        self.failure_counters.captured += 1;
        ResolutionFailureCapture::Captured(token)
    }

    /// Reserves the lowest free action slot, or reports why none can be used.
    fn reserve_action_slot(&mut self) -> Option<usize> {
        if self.action_queue.len() == self.actions.len() {
            return None;
        }
        match first_unused::<ActionBits>(self.actions) {
            Ok((found, reads)) => {
                self.count_visits(reads);
                debug_assert!(found.is_some(), "a non-full queue has a free slot");
                if found.is_none() {
                    self.index_counters.index_corrupt =
                        self.index_counters.index_corrupt.saturating_add(1);
                }
                found
            }
            Err(IndexCorrupt) => {
                self.index_counters.index_corrupt =
                    self.index_counters.index_corrupt.saturating_add(1);
                None
            }
        }
    }

    pub(crate) fn schedule(
        &mut self,
        action: ArpRequestAction,
        now: MonotonicMillis,
        forbidden_by_snapshot: bool,
    ) -> ResolutionResult {
        if !self.observe_now(now) {
            return ResolutionResult::ClockRegression;
        }
        if forbidden_by_snapshot
            || action.target_ip == action.source_ip
            || forbidden_target(action.target_ip)
        {
            self.counters.forbidden_target += 1;
            return ResolutionResult::ForbiddenTarget;
        }
        let key = ResolutionKey {
            egress: action.egress,
            target: action.target_ip,
        };
        let lookup = match self.lookup_state(key) {
            Ok(lookup) => lookup,
            Err(IndexCorrupt) => {
                self.index_counters.index_corrupt =
                    self.index_counters.index_corrupt.saturating_add(1);
                self.counters.state_full += 1;
                return ResolutionResult::StateFull;
            }
        };
        if let Some(index) = lookup.and_then(|lookup| lookup.found) {
            let state = self.states[index].entry;
            match state.phase {
                ResolutionPhase::InitialQueued | ResolutionPhase::RetryQueued => {
                    self.counters.suppressed += 1;
                    return ResolutionResult::Suppressed;
                }
                ResolutionPhase::Waiting => {
                    if now.0 - state.requested_at.0 < self.policy.interval_ms {
                        self.counters.suppressed += 1;
                        return ResolutionResult::Suppressed;
                    }
                    if state.attempts >= self.policy.max_attempts {
                        return self.mark_failed(index, now);
                    }
                    let Some(action_slot) = self.reserve_action_slot() else {
                        self.counters.action_full += 1;
                        return ResolutionResult::ActionFull;
                    };
                    self.states[index].entry.action = action;
                    return self.enqueue_retry(index, action_slot);
                }
                ResolutionPhase::Failed => {
                    if now.0 - state.failed_at.0 < self.policy.state_ttl_ms {
                        self.counters.failed_hits += 1;
                        return ResolutionResult::Failed;
                    }
                    let Some(action_slot) = self.reserve_action_slot() else {
                        self.counters.action_full += 1;
                        return ResolutionResult::ActionFull;
                    };
                    self.counters.failures_expired += 1;
                    self.cancel_holds_of_token(ResolutionGenerationToken {
                        egress: state.key.egress,
                        target: state.key.target,
                        generation: state.generation,
                    });
                    self.start_cycle(index, action);
                    return self.enqueue_initial(index, action_slot);
                }
                ResolutionPhase::Cooldown => {
                    if now.0 - state.requested_at.0 < self.policy.interval_ms {
                        self.counters.suppressed += 1;
                        return ResolutionResult::Suppressed;
                    }
                    let Some(action_slot) = self.reserve_action_slot() else {
                        self.counters.action_full += 1;
                        return ResolutionResult::ActionFull;
                    };
                    self.start_cycle(index, action);
                    return self.enqueue_initial(index, action_slot);
                }
            }
        }
        // A new key takes the lowest slot that is free or an elapsed
        // cooldown, exactly the slot a scan from slot 0 would take.
        self.mature_states(now);
        let reusable = match first_unused::<StateBits>(self.states) {
            Ok((found, reads)) => {
                self.count_visits(reads);
                found
            }
            Err(IndexCorrupt) => {
                self.index_counters.index_corrupt =
                    self.index_counters.index_corrupt.saturating_add(1);
                None
            }
        };
        let (Some(index), Some(lookup)) = (reusable, lookup) else {
            self.counters.state_full += 1;
            return ResolutionResult::StateFull;
        };
        let reused_in_chain = self.states[index].chain.is_linked()
            && chain_bucket(self.states[index].chain) == Some(lookup.bucket);
        if lookup.chain_len - usize::from(reused_in_chain) >= RESOLUTION_INDEX_CHAIN_LIMIT {
            self.index_counters.state_probe_exhausted =
                self.index_counters.state_probe_exhausted.saturating_add(1);
            self.counters.state_full += 1;
            return ResolutionResult::StateFull;
        }
        let Some(action_slot) = self.reserve_action_slot() else {
            self.counters.action_full += 1;
            return ResolutionResult::ActionFull;
        };
        self.start_cycle(index, action);
        debug_assert_eq!(self.states[index].entry.key, key);
        self.enqueue_initial(index, action_slot)
    }

    /// Records the forwarding miss of the datagram being decided when its
    /// request is queued, retried, or already pending (ARP-HOLD): only then
    /// can holding it end in a replay.
    pub(crate) fn note_forward_miss(
        &mut self,
        egress: IfId,
        target: Ipv4Address,
        result: ResolutionResult,
    ) {
        // `Suppressed` also covers a Cooldown tombstone (a request was
        // committed and the key then learned or cancelled): nothing will
        // resolve it, so only a pending generation counts.
        let pending = match result {
            ResolutionResult::Queued | ResolutionResult::RetryQueued => true,
            ResolutionResult::Suppressed => matches!(
                self.status(egress, target).map(|status| status.phase),
                Some(
                    ResolutionPhase::InitialQueued
                        | ResolutionPhase::Waiting
                        | ResolutionPhase::RetryQueued
                )
            ),
            _ => false,
        };
        if pending {
            self.forward_miss = Some(ResolutionKey { egress, target });
        }
    }

    /// Forgets the previous datagram's miss (ARP-HOLD).
    #[inline]
    pub(crate) fn clear_forward_miss(&mut self) {
        self.forward_miss = None;
    }

    /// The current datagram's resolving miss, with the time after which its
    /// resolution can no longer succeed: `interval × max-attempts` from now
    /// (the last request goes out at most `(max-attempts - 1) × interval`
    /// after the first and fails a full interval later).
    pub(crate) fn take_forward_miss(&mut self, now: MonotonicMillis) -> Option<ArpHoldMiss> {
        let key = self.forward_miss.take()?;
        Some(ArpHoldMiss {
            egress: key.egress,
            target: key.target,
            deadline_ms: now.0.saturating_add(
                self.policy
                    .interval_ms
                    .saturating_mul(u64::from(self.policy.max_attempts)),
            ),
        })
    }

    /// What a held datagram's next hop is now (ARP-HOLD): known when a live
    /// dynamic neighbour exists, resolving while its request generation is
    /// queued or waiting, over otherwise (failed, cancelled, gone, or a
    /// clock regression).
    pub(crate) fn arp_hold_next_hop(
        &mut self,
        egress: IfId,
        target: Ipv4Address,
        now: MonotonicMillis,
    ) -> ArpHoldNextHop {
        match self.lookup_dynamic(egress, target, now) {
            DynamicLookup::Hit(_) => ArpHoldNextHop::Known,
            DynamicLookup::ClockRegression => ArpHoldNextHop::Resolving,
            DynamicLookup::Miss => match self.status(egress, target).map(|status| status.phase) {
                Some(
                    ResolutionPhase::InitialQueued
                    | ResolutionPhase::Waiting
                    | ResolutionPhase::RetryQueued,
                ) => ArpHoldNextHop::Resolving,
                Some(ResolutionPhase::Failed) => ArpHoldNextHop::Failed,
                Some(ResolutionPhase::Cooldown) | None => ArpHoldNextHop::Gone,
            },
        }
    }

    pub(crate) fn lookup_dynamic(
        &mut self,
        interface: IfId,
        target: Ipv4Address,
        now: MonotonicMillis,
    ) -> DynamicLookup {
        if !self.observe_now(now) {
            return DynamicLookup::ClockRegression;
        }
        let key = ResolutionKey {
            egress: interface,
            target,
        };
        let found = match self.lookup_dynamic_key(key) {
            Ok(lookup) => lookup.and_then(|lookup| lookup.found),
            Err(IndexCorrupt) => {
                self.index_counters.index_corrupt =
                    self.index_counters.index_corrupt.saturating_add(1);
                None
            }
        };
        let Some(index) = found else {
            return DynamicLookup::Miss;
        };
        let entry = self.dynamic_neighbors[index].entry;
        if now.0 - entry.refreshed_at.0 >= self.policy.dynamic_neighbor_ttl_ms {
            self.remove_dynamic(index);
            DynamicLookup::Miss
        } else {
            DynamicLookup::Hit(entry.mac)
        }
    }

    pub(crate) fn merge_dynamic(
        &mut self,
        interface: IfId,
        sender: Ipv4Address,
        mac: MacAddress,
        allow_insert: bool,
        static_key: bool,
        now: MonotonicMillis,
    ) -> ControlDisposition {
        if !self.observe_now(now) {
            return ControlDisposition::ClockRegression;
        }
        if static_key {
            self.reconcile_static_key(interface, sender);
            return ControlDisposition::StaticPreserved;
        }
        let key = ResolutionKey {
            egress: interface,
            target: sender,
        };
        let lookup = match self.lookup_dynamic_key(key) {
            Ok(lookup) => lookup,
            Err(IndexCorrupt) => {
                self.index_counters.index_corrupt =
                    self.index_counters.index_corrupt.saturating_add(1);
                return if allow_insert {
                    ControlDisposition::CacheFull
                } else {
                    ControlDisposition::Ignored
                };
            }
        };
        let mut chain_len = lookup.map_or(0, |lookup| lookup.chain_len);
        if let Some(index) = lookup.and_then(|lookup| lookup.found) {
            let entry = self.dynamic_neighbors[index].entry;
            if now.0 - entry.refreshed_at.0 < self.policy.dynamic_neighbor_ttl_ms {
                self.dynamic_neighbors[index].entry.mac = mac;
                self.dynamic_neighbors[index].entry.refreshed_at = now;
                self.touch_dynamic(index);
                self.clear_resolution(interface, sender);
                return ControlDisposition::Updated;
            }
            self.remove_dynamic(index);
            if allow_insert {
                let bucket = lookup.expect("found in a nonempty table").bucket;
                let Some(len) = self.dynamic_chain_len(bucket) else {
                    self.index_counters.index_corrupt =
                        self.index_counters.index_corrupt.saturating_add(1);
                    return ControlDisposition::CacheFull;
                };
                chain_len = len;
            }
        }
        if !allow_insert {
            return ControlDisposition::Ignored;
        }
        // The lowest slot that is free or expired, as a scan would find.
        self.mature_dynamic(now);
        let reusable = match first_unused::<DynamicBits>(self.dynamic_neighbors) {
            Ok((found, reads)) => {
                self.count_visits(reads);
                found
            }
            Err(IndexCorrupt) => {
                self.index_counters.index_corrupt =
                    self.index_counters.index_corrupt.saturating_add(1);
                None
            }
        };
        let (Some(index), Some(lookup)) = (reusable, lookup) else {
            return ControlDisposition::CacheFull;
        };
        let reused_in_chain = self.dynamic_neighbors[index].chain.is_linked()
            && chain_bucket(self.dynamic_neighbors[index].chain) == Some(lookup.bucket);
        if chain_len - usize::from(reused_in_chain) >= RESOLUTION_INDEX_CHAIN_LIMIT {
            self.index_counters.dynamic_probe_exhausted = self
                .index_counters
                .dynamic_probe_exhausted
                .saturating_add(1);
            return ControlDisposition::CacheFull;
        }
        if self.dynamic_neighbors[index].entry.occupied {
            self.remove_dynamic(index);
        }
        self.dynamic_neighbors[index].entry = DynamicEntry {
            interface,
            target: sender,
            mac,
            refreshed_at: now,
            occupied: true,
        };
        let linked = link::<DynamicChain>(self.dynamic_neighbors, index, lookup.bucket);
        self.index_result(linked);
        self.dynamic_count += 1;
        self.high_water
            .dynamic_neighbors
            .observe(self.dynamic_count);
        self.touch_dynamic(index);
        self.clear_resolution(interface, sender);
        ControlDisposition::Inserted
    }

    /// Moves a just refreshed dynamic neighbor to the tail of the refresh
    /// order. Refresh times are monotonic, so the order stays sorted.
    fn touch_dynamic(&mut self, index: usize) {
        if self.dynamic_neighbors[index].in_lru {
            self.dynamic_order.unlink(self.dynamic_neighbors, index);
        }
        self.dynamic_order.push_back(self.dynamic_neighbors, index);
        self.dynamic_neighbors[index].in_lru = true;
        set_used::<DynamicBits>(self.dynamic_neighbors, index, true);
    }

    /// Takes every expired entry off the head of the refresh order and marks
    /// its slot reusable. Each refresh enters the order once, so the work is
    /// amortized O(1) per learned or refreshed entry. Taking an entry off is
    /// only bookkeeping (an expired entry stays expired), so it may run at
    /// any time; the timer poll drains a bounded number each tick so an
    /// insert rarely finds many waiting. It cannot be bounded per insert
    /// without losing the lowest-reusable-slot choice: the next expired
    /// entry may be the lowest slot.
    fn mature_dynamic(&mut self, now: MonotonicMillis) {
        self.mature_dynamic_at_most(now, usize::MAX);
    }

    fn mature_dynamic_at_most(&mut self, now: MonotonicMillis, budget: usize) {
        for _ in 0..budget {
            let Some(head) = self.dynamic_order.head() else {
                return;
            };
            self.count_visits(1);
            let refreshed_at = self.dynamic_neighbors[head].entry.refreshed_at;
            if now.0.saturating_sub(refreshed_at.0) < self.policy.dynamic_neighbor_ttl_ms {
                return;
            }
            self.dynamic_order.unlink(self.dynamic_neighbors, head);
            self.dynamic_neighbors[head].in_lru = false;
            set_used::<DynamicBits>(self.dynamic_neighbors, head, false);
        }
    }

    fn remove_dynamic(&mut self, index: usize) {
        debug_assert!(self.dynamic_neighbors[index].entry.occupied);
        let unlinked = unlink::<DynamicChain>(self.dynamic_neighbors, index);
        self.index_result(unlinked);
        if self.dynamic_neighbors[index].in_lru {
            self.dynamic_order.unlink(self.dynamic_neighbors, index);
            self.dynamic_neighbors[index].in_lru = false;
        }
        self.dynamic_neighbors[index].entry = DynamicEntry::EMPTY;
        set_used::<DynamicBits>(self.dynamic_neighbors, index, false);
        self.dynamic_count -= 1;
    }

    /// Takes every state whose last request is at least one interval old off
    /// the head of the request order. Such a state that is (or later
    /// becomes) a cooldown is reusable. Each commit enters the order once,
    /// so the work is amortized O(1) per committed ARP request; the timer
    /// poll also drains a bounded number each tick (see
    /// [`Self::mature_dynamic`]).
    fn mature_states(&mut self, now: MonotonicMillis) {
        self.mature_states_at_most(now, usize::MAX);
    }

    fn mature_states_at_most(&mut self, now: MonotonicMillis, budget: usize) {
        for _ in 0..budget {
            let Some(head) = self.request_order.head() else {
                return;
            };
            self.count_visits(1);
            let requested_at = self.states[head].entry.requested_at;
            if now.0.saturating_sub(requested_at.0) < self.policy.interval_ms {
                return;
            }
            self.request_order.unlink(self.states, head);
            self.states[head].in_order = false;
            self.refresh_state_bit(head);
        }
    }

    fn refresh_state_bit(&mut self, index: usize) {
        let used = state_used(&self.states[index]);
        let word = StateBits::word(&self.states[index / 64]);
        let was_used = word & (1u64 << (index % 64)) != 0;
        match (was_used, used) {
            (false, true) => {
                self.used_state_count += 1;
                self.high_water.states.observe(self.used_state_count);
            }
            (true, false) => {
                self.used_state_count = self.used_state_count.saturating_sub(1);
            }
            (false, false) | (true, true) => {}
        }
        set_used::<StateBits>(self.states, index, used);
    }

    /// Replaces the state entry of slot `index` and keeps the key chain, the
    /// request order, and the reusable bitmap in step. The request time of
    /// an entry that stays on the order list must not change here.
    fn replace_state_entry(&mut self, index: usize, new: StateEntry) {
        let old = self.states[index].entry;
        let relink = old.occupied != new.occupied || (new.occupied && old.key != new.key);
        if relink && old.occupied {
            let unlinked = unlink::<StateChain>(self.states, index);
            self.index_result(unlinked);
        }
        if relink && new.occupied {
            let bucket = self.state_bucket(new.key).expect("nonempty state table");
            let linked = link::<StateChain>(self.states, index, bucket);
            self.index_result(linked);
        }
        debug_assert!(
            !(self.states[index].in_order && new.occupied && new.attempts != 0)
                || new.requested_at == old.requested_at,
            "an entry staying on the request order keeps its request time"
        );
        if self.states[index].in_order && (!new.occupied || new.attempts == 0) {
            self.request_order.unlink(self.states, index);
            self.states[index].in_order = false;
        }
        self.states[index].entry = new;
        self.refresh_state_bit(index);
    }

    fn observe_now(&mut self, now: MonotonicMillis) -> bool {
        if self.last_now.is_some_and(|last| now < last) {
            self.counters.clock_regressions += 1;
            return false;
        }
        self.last_now = Some(now);
        true
    }

    pub(crate) fn observe_control(&mut self, now: MonotonicMillis) -> bool {
        self.observe_now(now)
    }

    fn clear_resolution(&mut self, interface: IfId, target: Ipv4Address) {
        if let Some(index) = self.find_state(ResolutionKey {
            egress: interface,
            target,
        }) {
            self.cancel_state_at(index);
        }
        self.cancel_forward_holds(interface, target);
    }

    fn reconcile_static_key(&mut self, interface: IfId, target: Ipv4Address) {
        if let Some(index) = self.find_dynamic(ResolutionKey {
            egress: interface,
            target,
        }) {
            self.remove_dynamic(index);
        }
        self.clear_resolution(interface, target);
    }

    /// Removes the queued action of state `index`, if any, keeping the order
    /// of the other queued actions.
    fn remove_queued_action(&mut self, index: usize) -> bool {
        let slot = self.states[index].action_slot;
        if slot == INDEX_NONE {
            return false;
        }
        let slot = slot as usize;
        self.states[index].action_slot = INDEX_NONE;
        self.action_queue.unlink(self.actions, slot);
        self.actions[slot].queued = None;
        self.actions[slot].state = INDEX_NONE;
        set_used::<ActionBits>(self.actions, slot, false);
        true
    }

    /// Cancels state `index` (cooldown if it ever committed a request, else
    /// free) together with its queued action. Returns whether an action was
    /// removed.
    fn cancel_state_at(&mut self, index: usize) -> bool {
        let action_removed = self.remove_queued_action(index);
        let old = self.states[index].entry;
        let was_pending = state_is_pending(old);
        self.replace_state_entry(index, cancelled_entry(old));
        if was_pending {
            debug_assert!(self.pending_state_count != 0);
            self.pending_state_count -= 1;
        }
        action_removed
    }

    fn vacate_state_at(&mut self, index: usize) {
        debug_assert_eq!(self.states[index].action_slot, INDEX_NONE);
        self.remove_queued_action(index);
        let old = self.states[index].entry;
        let was_pending = state_is_pending(old);
        self.replace_state_entry(index, vacated_entry(old));
        if was_pending {
            debug_assert!(self.pending_state_count != 0);
            self.pending_state_count -= 1;
        }
    }

    fn clear_failure_hold(&mut self, index: usize) {
        debug_assert!(
            self.failure_holds[index].phase != ResolutionFailureHoldPhase::Empty,
            "only a live failure hold can be cleared"
        );
        let forward = unlink::<HoldForwardChain>(self.failure_holds, index);
        self.index_result(forward);
        if self.failure_holds[index].phase == ResolutionFailureHoldPhase::WaitingReverse {
            self.reverse_leave(index);
        }
        self.failure_holds[index].clear_entry();
        set_used::<HoldBits>(self.failure_holds, index, false);
        debug_assert!(self.pending_failure_hold_count != 0);
        self.pending_failure_hold_count -= 1;
    }

    /// Moves hold `index` to waiting for reverse resolution `reverse`.
    pub(crate) fn wait_reverse(&mut self, index: usize, reverse: ResolutionGenerationToken) {
        let hold = self.failure_holds[index];
        if hold.phase == ResolutionFailureHoldPhase::WaitingReverse {
            if hold.reverse == reverse {
                return;
            }
            self.reverse_leave(index);
        }
        self.failure_holds[index].phase = ResolutionFailureHoldPhase::WaitingReverse;
        self.failure_holds[index].reverse = reverse;
        self.reverse_join(index);
    }

    /// Clears every live hold whose forward token, or whose reverse token
    /// while waiting for reverse resolution, is `token`. Cost: the forward
    /// chain of the key, the reverse chain of the bucket (one leader per
    /// distinct token), and the group of the token, every hold of which is
    /// cleared (each was captured once).
    fn cancel_holds_of_token(&mut self, token: ResolutionGenerationToken) {
        if let Some(bucket) = self.forward_bucket(token.egress, token.target) {
            self.for_each_hold::<HoldForwardChain>(bucket, |runtime, index| {
                let hold = runtime.failure_holds[index];
                if hold.phase != ResolutionFailureHoldPhase::Empty && hold.forward == token {
                    runtime.clear_failure_hold(index);
                    runtime.failure_counters.cancelled += 1;
                }
            });
        }
        let mut current = match self.reverse_leader(token) {
            Ok(leader) => leader,
            Err(IndexCorrupt) => {
                self.index_result(Err(IndexCorrupt));
                None
            }
        };
        let mut steps = 0;
        while let Some(index) = current {
            let hold = self.failure_holds[index];
            if steps == self.failure_holds.len()
                || hold.phase != ResolutionFailureHoldPhase::WaitingReverse
                || hold.reverse != token
            {
                self.index_result(Err(IndexCorrupt));
                return;
            }
            steps += 1;
            self.count_visits(1);
            let next = hold.reverse_group_next;
            current = (next != INDEX_NONE).then_some(next as usize);
            self.clear_failure_hold(index);
            self.failure_counters.cancelled += 1;
        }
    }

    fn start_cycle(&mut self, index: usize, action: ArpRequestAction) {
        let was_pending = state_is_pending(self.states[index].entry);
        let generation = self.next_generation(
            action.egress,
            action.target_ip,
            self.states[index].entry.generation,
        );
        self.replace_state_entry(
            index,
            StateEntry {
                key: ResolutionKey {
                    egress: action.egress,
                    target: action.target_ip,
                },
                action,
                generation,
                attempts: 0,
                accepted_attempts: 0,
                requested_at: MonotonicMillis(0),
                failed_at: MonotonicMillis(0),
                occupied: true,
                phase: ResolutionPhase::InitialQueued,
                failure_notified: false,
            },
        );
        if !was_pending {
            debug_assert!(self.pending_state_count < self.states.len());
            self.pending_state_count += 1;
        }
    }

    fn enqueue_initial(&mut self, index: usize, action_slot: usize) -> ResolutionResult {
        debug_assert_eq!(self.states[index].entry.attempts, 0);
        debug_assert_eq!(
            self.states[index].entry.phase,
            ResolutionPhase::InitialQueued
        );
        self.enqueue_state_action(index, action_slot);
        self.counters.queued += 1;
        ResolutionResult::Queued
    }

    fn enqueue_retry(&mut self, index: usize, action_slot: usize) -> ResolutionResult {
        self.states[index].entry.phase = ResolutionPhase::RetryQueued;
        self.enqueue_state_action(index, action_slot);
        self.counters.queued += 1;
        self.counters.retry_queued += 1;
        ResolutionResult::RetryQueued
    }

    fn enqueue_state_action(&mut self, index: usize, action_slot: usize) {
        debug_assert!(self.action_queue.len() < self.actions.len());
        debug_assert!(self.actions[action_slot].queued.is_none());
        let entry = self.states[index].entry;
        self.actions[action_slot].queued = Some(QueuedAction {
            action: entry.action,
            generation: entry.generation,
        });
        self.actions[action_slot].state = u32::try_from(index).expect("validated capacity");
        set_used::<ActionBits>(self.actions, action_slot, true);
        self.action_queue.push_back(self.actions, action_slot);
        self.high_water.actions.observe(self.action_queue.len());
        self.states[index].action_slot = u32::try_from(action_slot).expect("validated capacity");
    }

    fn mark_failed(&mut self, index: usize, now: MonotonicMillis) -> ResolutionResult {
        debug_assert_eq!(self.states[index].entry.phase, ResolutionPhase::Waiting);
        debug_assert!(self.states[index].entry.attempts >= self.policy.max_attempts);
        self.states[index].entry.phase = ResolutionPhase::Failed;
        self.states[index].entry.failed_at = now;
        self.states[index].entry.failure_notified = true;
        self.counters.timed_out += 1;
        let state = self.states[index].entry;
        let token = ResolutionGenerationToken {
            egress: state.key.egress,
            target: state.key.target,
            generation: state.generation,
        };
        let Some(bucket) = self.forward_bucket(token.egress, token.target) else {
            return ResolutionResult::TimedOut;
        };
        if state.accepted_attempts == 0 {
            self.for_each_hold::<HoldForwardChain>(bucket, |runtime, hold_index| {
                let hold = runtime.failure_holds[hold_index];
                if hold.phase == ResolutionFailureHoldPhase::WaitingForward && hold.forward == token
                {
                    runtime.clear_failure_hold(hold_index);
                    runtime.failure_counters.no_accepted_arp_request += 1;
                }
            });
        } else {
            self.for_each_hold::<HoldForwardChain>(bucket, |runtime, hold_index| {
                let hold = &mut runtime.failure_holds[hold_index];
                if hold.phase == ResolutionFailureHoldPhase::WaitingForward && hold.forward == token
                {
                    hold.phase = ResolutionFailureHoldPhase::TerminalReady;
                    runtime.failure_counters.promoted += 1;
                }
            });
        }
        ResolutionResult::TimedOut
    }

    fn front(&self) -> Option<QueuedAction> {
        self.action_queue
            .head()
            .and_then(|head| self.actions.get(head))
            .and_then(|slot| slot.queued)
    }

    fn execution_time_valid(&mut self, now: MonotonicMillis) -> bool {
        self.observe_now(now)
    }

    fn committed(&mut self, queued: QueuedAction, now: MonotonicMillis) {
        let head = self
            .action_queue
            .head()
            .expect("committed action is queue front");
        let item = self.actions[head]
            .queued
            .take()
            .expect("committed action is queue front");
        debug_assert_eq!(item, queued);
        let owner = self.actions[head].state as usize;
        self.actions[head].state = INDEX_NONE;
        self.action_queue.unlink(self.actions, head);
        set_used::<ActionBits>(self.actions, head, false);
        if self
            .states
            .get(owner)
            .is_some_and(|state| state.action_slot as usize == head)
        {
            self.states[owner].action_slot = INDEX_NONE;
        }
        self.counters.dequeued += 1;
        let Some(index) = self
            .find_state(ResolutionKey {
                egress: queued.action.egress,
                target: queued.action.target_ip,
            })
            .filter(|&index| self.states[index].entry.generation == queued.generation)
        else {
            return;
        };
        debug_assert!(matches!(
            self.states[index].entry.phase,
            ResolutionPhase::InitialQueued | ResolutionPhase::RetryQueued
        ));
        debug_assert!(self.states[index].entry.attempts < self.policy.max_attempts);
        let entry = &mut self.states[index].entry;
        entry.attempts += 1;
        entry.phase = ResolutionPhase::Waiting;
        entry.requested_at = now;
        if self.states[index].in_order {
            self.request_order.unlink(self.states, index);
        }
        self.request_order.push_back(self.states, index);
        self.states[index].in_order = true;
        self.refresh_state_bit(index);
        self.counters.attempts_committed += 1;
    }

    fn accepted(&mut self, queued: QueuedAction, accepted: usize) {
        if accepted == 0 {
            return;
        }
        if let Some(index) = self
            .find_state(ResolutionKey {
                egress: queued.action.egress,
                target: queued.action.target_ip,
            })
            .filter(|&index| self.states[index].entry.generation == queued.generation)
        {
            let state = &mut self.states[index].entry;
            state.accepted_attempts = state.accepted_attempts.saturating_add(accepted as u16);
            self.counters.attempts_accepted += accepted;
        }
    }

    /// Whether a live hold still carries `token`: as its forward token, or
    /// as its reverse token while waiting for reverse resolution.
    fn token_in_use(&mut self, token: ResolutionGenerationToken) -> bool {
        let forward = self.forward_hold_exists(token).map(|(found, _)| found);
        let reverse = self.reverse_hold_exists(token);
        match (forward, reverse) {
            (Ok(forward), Ok(reverse)) => forward || reverse,
            _ => {
                self.index_result(Err(IndexCorrupt));
                false
            }
        }
    }

    fn next_generation(&mut self, egress: IfId, target: Ipv4Address, previous: u64) -> u64 {
        let mut candidate = previous.wrapping_add(1);
        for _ in 0..=self.failure_holds.len() {
            if !self.token_in_use(ResolutionGenerationToken {
                egress,
                target,
                generation: candidate,
            }) {
                return candidate;
            }
            candidate = candidate.wrapping_add(1);
        }
        unreachable!("more live tokens than caller-backed hold slots")
    }

    fn cancel_forward_holds(&mut self, egress: IfId, target: Ipv4Address) {
        let Some(bucket) = self.forward_bucket(egress, target) else {
            return;
        };
        self.for_each_hold::<HoldForwardChain>(bucket, |runtime, index| {
            let hold = runtime.failure_holds[index];
            if hold.phase != ResolutionFailureHoldPhase::Empty
                && hold.forward.egress == egress
                && hold.forward.target == target
            {
                runtime.clear_failure_hold(index);
                runtime.failure_counters.cancelled += 1;
            }
        });
    }

    /// Whether a hold is still waiting for forward resolution `token`.
    fn waiting_forward_hold_exists(&mut self, token: ResolutionGenerationToken) -> bool {
        let Some(bucket) = self.forward_bucket(token.egress, token.target) else {
            return false;
        };
        let holds = &*self.failure_holds;
        match walk::<HoldForwardChain>(holds, bucket, RESOLUTION_INDEX_CHAIN_LIMIT, |index| {
            holds[index].phase == ResolutionFailureHoldPhase::WaitingForward
                && holds[index].forward == token
        }) {
            Ok(walked) => {
                self.count_visits(walked.visited.max(1));
                walked.found.is_some()
            }
            Err(IndexCorrupt) => {
                self.index_result(Err(IndexCorrupt));
                false
            }
        }
    }

    fn poll_timers<T: ResolutionTimerTraceSink>(
        &mut self,
        now: MonotonicMillis,
        scan_budget: usize,
        trace: &mut T,
    ) -> Result<ResolutionTimerReport, ResolutionTimerError> {
        if !self.observe_now(now) {
            trace.record_resolution_timer(ResolutionTimerTrace::ClockRegression);
            return Err(ResolutionTimerError::ClockRegression);
        }
        let mut report = ResolutionTimerReport::default();
        // Background bookkeeping, invisible in behaviour: take up to one
        // scan budget of elapsed requests and expired dynamic neighbors off
        // their time-ordered lists, so a later insert has less to do.
        self.mature_states_at_most(now, scan_budget);
        self.mature_dynamic_at_most(now, scan_budget);
        if self.states.is_empty() || scan_budget == 0 {
            report.pending = self.pending_states();
            return Ok(report);
        }
        let scans = scan_budget.min(self.states.len());
        for _ in 0..scans {
            let index = self.poll_cursor;
            self.poll_cursor = (self.poll_cursor + 1) % self.states.len();
            report.scanned += 1;
            let state = self.states[index].entry;
            if !state.occupied {
                continue;
            }
            match state.phase {
                ResolutionPhase::InitialQueued | ResolutionPhase::RetryQueued => {}
                ResolutionPhase::Waiting => {
                    if now.0 - state.requested_at.0 < self.policy.interval_ms {
                        continue;
                    }
                    if state.attempts >= self.policy.max_attempts {
                        let token = ResolutionGenerationToken {
                            egress: state.key.egress,
                            target: state.key.target,
                            generation: state.generation,
                        };
                        let no_accepted_candidate =
                            state.accepted_attempts == 0 && self.waiting_forward_hold_exists(token);
                        self.mark_failed(index, now);
                        report.timed_out += 1;
                        trace.record_resolution_timer(ResolutionTimerTrace::TimedOut {
                            egress: state.key.egress,
                            target: state.key.target,
                            attempts: state.attempts,
                            generation: state.generation,
                        });
                        if no_accepted_candidate {
                            report.no_accepted_arp_request += 1;
                            trace.record_resolution_timer(
                                ResolutionTimerTrace::NoAcceptedArpRequest {
                                    egress: state.key.egress,
                                    target: state.key.target,
                                    generation: state.generation,
                                },
                            );
                        }
                    } else if let Some(action_slot) = self.reserve_action_slot() {
                        let result = self.enqueue_retry(index, action_slot);
                        debug_assert_eq!(result, ResolutionResult::RetryQueued);
                        report.retries_queued += 1;
                        trace.record_resolution_timer(ResolutionTimerTrace::RetryQueued {
                            egress: state.key.egress,
                            target: state.key.target,
                            attempts: state.attempts,
                            generation: state.generation,
                        });
                    } else {
                        self.counters.action_full += 1;
                        report.action_full += 1;
                        report.deferred_due += 1;
                        trace.record_resolution_timer(ResolutionTimerTrace::ActionFull {
                            egress: state.key.egress,
                            target: state.key.target,
                            attempts: state.attempts,
                            generation: state.generation,
                        });
                    }
                }
                ResolutionPhase::Failed => {
                    if now.0 - state.failed_at.0 >= self.policy.state_ttl_ms {
                        self.cancel_holds_of_token(ResolutionGenerationToken {
                            egress: state.key.egress,
                            target: state.key.target,
                            generation: state.generation,
                        });
                        self.vacate_state_at(index);
                        self.counters.failures_expired += 1;
                        report.failures_expired += 1;
                        trace.record_resolution_timer(ResolutionTimerTrace::FailureExpired {
                            egress: state.key.egress,
                            target: state.key.target,
                            generation: state.generation,
                        });
                    }
                }
                ResolutionPhase::Cooldown => {}
            }
        }
        report.pending = self.pending_states();
        Ok(report)
    }
}

#[cfg(test)]
impl ResolutionRuntime<'_> {
    /// Installs a live hold through the indexes, as capture and dispatch
    /// would.
    pub(crate) fn install_hold_for_test(
        &mut self,
        index: usize,
        phase: ResolutionFailureHoldPhase,
        forward: ResolutionGenerationToken,
        reverse: ResolutionGenerationToken,
    ) {
        assert_eq!(
            self.failure_holds[index].phase,
            ResolutionFailureHoldPhase::Empty
        );
        self.failure_holds[index].phase = ResolutionFailureHoldPhase::WaitingForward;
        self.failure_holds[index].forward = forward;
        let bucket = self.forward_bucket(forward.egress, forward.target).unwrap();
        link::<HoldForwardChain>(self.failure_holds, index, bucket).unwrap();
        set_used::<HoldBits>(self.failure_holds, index, true);
        self.pending_failure_hold_count += 1;
        if phase == ResolutionFailureHoldPhase::WaitingReverse {
            self.wait_reverse(index, reverse);
        } else {
            self.failure_holds[index].phase = phase;
        }
    }

    pub(crate) fn take_visits(&self) -> u64 {
        self.visits.replace(0)
    }
}

impl ResolutionPublicationPermit<'_, '_> {
    #[must_use]
    pub const fn preview(&self) -> ResolutionPublicationReport {
        self.preview
    }

    /// Flushes all old publication authority without failure, keeping the
    /// index key. Tests only; production code rotates the key with
    /// [`Self::commit_with_hash_key`].
    #[doc(hidden)]
    pub fn commit(self) -> ResolutionPublicationReport {
        let key = self.runtime.hash_key;
        self.commit_keyed(key)
    }

    /// Flushes all old publication authority without failure and switches
    /// the hashed indexes to the fresh secret `hash_key`.
    pub fn commit_with_hash_key(self, hash_key: ResolutionHashKey) -> ResolutionPublicationReport {
        self.commit_keyed(hash_key.0)
    }

    fn commit_keyed(self, hash_key: DirectoryHashKey) -> ResolutionPublicationReport {
        let runtime = self.runtime;
        runtime.flush_pending(self.next_runtime_epoch);
        runtime.dynamic_neighbors.fill(DynamicNeighborSlot::EMPTY);
        runtime.hash_key = hash_key;
        runtime.dynamic_order = SlotList::EMPTY;
        runtime.dynamic_count = 0;
        runtime.high_water.dynamic_neighbors.reset(0);
        self.preview
    }

    /// The report [`Self::commit_carrying`] would return for the same
    /// snapshots, computed without mutation.
    #[must_use]
    pub fn preview_carrying(
        &self,
        current: &crate::ForwardingSnapshot<'_>,
        next: &crate::ForwardingSnapshot<'_>,
    ) -> ResolutionPublicationReport {
        let runtime = &*self.runtime;
        let dropped = runtime
            .dynamic_neighbors
            .iter()
            .filter(|slot| {
                slot.entry.occupied && !dynamic_neighbor_carries(current, next, slot.entry)
            })
            .count();
        ResolutionPublicationReport {
            dynamic_neighbors_flushed: dropped,
            dynamic_neighbors_carried: runtime.dynamic_count - dropped,
            outcome: crate::StateCarryOutcome::Carried,
            ..self.preview
        }
    }

    /// Flushes pending resolution work like [`Self::commit_with_hash_key`]
    /// but keeps the learned neighbors that `next` still binds the same way
    /// as `current` (RELOAD-CARRY), with the index key.
    ///
    /// Pending states, queued ARP actions, and failure holds always flush:
    /// they carry the old snapshot's authority and restart from the next
    /// packet. A learned neighbor `(interface, target)` is kept only when
    ///
    /// - the interface's local IPv4 binding (the address ARP is answered
    ///   and learned for) is the same in both snapshots,
    /// - `next` has no static neighbor for it (static wins, as on
    ///   [`ResolutionRuntime::reconcile_static`]), and
    /// - when `next` enables the ARP-031 on-link sender hardening, the
    ///   target is on the interface's link in `next` (an entry learned
    ///   under the RFC 826 default does not outlive the switch).
    ///
    /// The MAC address cannot change (an interface MAC change is restart
    /// required). O(learned neighbors) with O(1) snapshot lookups and index
    /// removals; no allocation.
    pub fn commit_carrying(
        self,
        current: &crate::ForwardingSnapshot<'_>,
        next: &crate::ForwardingSnapshot<'_>,
    ) -> ResolutionPublicationReport {
        let runtime = self.runtime;
        runtime.flush_pending(self.next_runtime_epoch);
        let mut dropped = 0usize;
        for index in 0..runtime.dynamic_neighbors.len() {
            let entry = runtime.dynamic_neighbors[index].entry;
            if entry.occupied && !dynamic_neighbor_carries(current, next, entry) {
                runtime.remove_dynamic(index);
                dropped += 1;
            }
        }
        ResolutionPublicationReport {
            dynamic_neighbors_flushed: dropped,
            dynamic_neighbors_carried: runtime.dynamic_count,
            outcome: crate::StateCarryOutcome::Carried,
            ..self.preview
        }
    }
}

/// Whether the learned neighbor `entry` keeps its meaning from `current`
/// to `next`; see [`ResolutionPublicationPermit::commit_carrying`].
fn dynamic_neighbor_carries(
    current: &crate::ForwardingSnapshot<'_>,
    next: &crate::ForwardingSnapshot<'_>,
    entry: DynamicEntry,
) -> bool {
    let binding = |snapshot: &crate::ForwardingSnapshot<'_>| {
        snapshot
            .local_binding_on(entry.interface)
            .map(|binding| binding.address)
    };
    let bound = binding(current);
    bound.is_some()
        && bound == binding(next)
        && next
            .static_neighbor(entry.interface, entry.target)
            .is_none()
        && (!next.arp.require_on_link_sender()
            || next.sender_on_link(entry.interface, entry.target))
}

impl ResolutionRuntime<'_> {
    /// Empties every pending state, queued action, and failure hold and
    /// their lists; learned neighbors and the index key are untouched.
    fn flush_pending(&mut self, next_runtime_epoch: u128) {
        self.states.fill(ResolutionStateSlot::EMPTY);
        self.actions.fill(ResolutionActionSlot::EMPTY);
        self.failure_holds.fill(ResolutionFailureHoldSlot::EMPTY);
        self.action_queue = SlotList::EMPTY;
        self.request_order = SlotList::EMPTY;
        self.pending_state_count = 0;
        self.used_state_count = 0;
        self.pending_failure_hold_count = 0;
        self.high_water.states.reset(0);
        self.high_water.actions.reset(0);
        self.high_water.failure_holds.reset(0);
        self.poll_cursor = 0;
        self.failure_cursor = 0;
        self.publication_epoch = next_runtime_epoch;
    }
}

fn publication_hold_valid(
    snapshot: &crate::ForwardingSnapshot<'_>,
    hold: &ResolutionFailureHoldSlot,
) -> bool {
    snapshot
        .route_lookup(hold.original_destination)
        .is_some_and(|route| {
            route.egress() == hold.forward.egress
                && route.next_hop().is_none()
                && hold.forward.target == hold.original_destination
                && route.prefix() == hold.forward_prefix
                && route.prefix_len() == hold.forward_prefix_len
        })
        && snapshot
            .interface(hold.forward.egress)
            .is_some_and(|interface| interface.mac == hold.forward_source_mac)
        && snapshot.is_local_ipv4_on(hold.forward.egress, hold.forward_source_ip)
        && snapshot
            .static_neighbor(hold.forward.egress, hold.forward.target)
            .is_none()
        && !host_failure_target_forbidden(
            snapshot,
            hold.forward.egress,
            hold.forward.target,
            hold.forward_source_ip,
        )
}

/// Every waiting-reverse hold is in exactly one group: a leader (on the
/// reverse chain, in the bucket of its token, the only leader of that token
/// in the bucket) followed by holds of the same token with consistent back
/// links. O(capacity); validation only.
fn reverse_groups_valid(
    holds: &[ResolutionFailureHoldSlot],
    bucket_of_token: impl Fn(ResolutionGenerationToken) -> usize,
) -> bool {
    let waiting = holds
        .iter()
        .filter(|hold| hold.phase == ResolutionFailureHoldPhase::WaitingReverse)
        .count();
    let mut reached = 0usize;
    for (leader, hold) in holds.iter().enumerate() {
        if !hold.reverse_chain.is_linked() {
            if hold.phase != ResolutionFailureHoldPhase::WaitingReverse
                && (hold.reverse_group_prev != INDEX_NONE || hold.reverse_group_next != INDEX_NONE)
            {
                return false;
            }
            continue;
        }
        if hold.phase != ResolutionFailureHoldPhase::WaitingReverse
            || hold.reverse_group_prev != INDEX_NONE
        {
            return false;
        }
        let bucket = bucket_of_token(hold.reverse);
        if chain_bucket(hold.reverse_chain) != Some(bucket) {
            return false;
        }
        // No second leader of the same token in this bucket.
        let mut current = chain_head::<HoldReverseChain>(holds, bucket);
        let mut seen = 0;
        while let Some(other) = current {
            if other != leader && holds[other].reverse == hold.reverse {
                return false;
            }
            seen += 1;
            if seen > holds.len() {
                return false;
            }
            current = chain_next::<HoldReverseChain>(holds, other);
        }
        let mut previous = leader;
        let mut current = hold.reverse_group_next;
        reached += 1;
        while current != INDEX_NONE {
            let Some(member) = holds.get(current as usize) else {
                return false;
            };
            if member.phase != ResolutionFailureHoldPhase::WaitingReverse
                || member.reverse != hold.reverse
                || member.reverse_chain.is_linked()
                || member.reverse_group_prev as usize != previous
            {
                return false;
            }
            reached += 1;
            if reached > waiting {
                return false;
            }
            previous = current as usize;
            current = member.reverse_group_next;
        }
    }
    reached == waiting
}

const fn state_is_pending(state: StateEntry) -> bool {
    state.occupied && !matches!(state.phase, ResolutionPhase::Cooldown)
}

/// A free state that keeps its generation counter.
const fn vacated_entry(state: StateEntry) -> StateEntry {
    let mut vacated = StateEntry::EMPTY;
    vacated.generation = state.generation;
    vacated
}

/// The entry a cancelled state becomes: free if it never committed a
/// request, else a cooldown that remembers the last request time.
const fn cancelled_entry(state: StateEntry) -> StateEntry {
    if state.attempts == 0 {
        return vacated_entry(state);
    }
    let mut cooldown = StateEntry::EMPTY;
    cooldown.key = state.key;
    cooldown.generation = state.generation;
    cooldown.attempts = state.attempts;
    cooldown.requested_at = state.requested_at;
    cooldown.occupied = true;
    cooldown.phase = ResolutionPhase::Cooldown;
    cooldown
}

/// Advances bounded ARP retry/timeout state without performing packet I/O.
pub fn poll_resolution_timers<T: ResolutionTimerTraceSink>(
    runtime: &mut ResolutionRuntime<'_>,
    now: MonotonicMillis,
    scan_budget: usize,
    trace: &mut T,
) -> Result<ResolutionTimerReport, ResolutionTimerError> {
    runtime.poll_timers(now, scan_budget, trace)
}

/// Boundedly promotes fruitless directly-connected ARP generations into
/// ICMPv4 Destination Unreachable, Host Unreachable actions.
///
/// Call after publication reconciliation, RX processing, and resolution timer
/// polling, but before generated ARP and ICMP execution.
pub fn dispatch_host_unreachable_failures<T: ResolutionFailureTraceSink>(
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    snapshot: &crate::ForwardingSnapshot<'_>,
    now: MonotonicMillis,
    scan_budget: usize,
    trace: &mut T,
) -> Result<ResolutionFailureDispatchReport, ResolutionFailureDispatchError> {
    if !resolution.observe_now(now) {
        trace.record_resolution_failure(ResolutionFailureTrace::ClockRegression);
        return Err(ResolutionFailureDispatchError::ClockRegression);
    }
    let mut report = ResolutionFailureDispatchReport::default();
    if resolution.failure_holds.is_empty() || scan_budget == 0 {
        report.pending = resolution.pending_failure_holds();
        return Ok(report);
    }
    let scans = scan_budget.min(resolution.failure_holds.len());
    for _ in 0..scans {
        let index = resolution.failure_cursor;
        resolution.failure_cursor =
            (resolution.failure_cursor + 1) % resolution.failure_holds.len();
        report.scanned += 1;
        let hold = resolution.failure_holds[index];
        if !matches!(
            hold.phase,
            ResolutionFailureHoldPhase::TerminalReady | ResolutionFailureHoldPhase::WaitingReverse
        ) {
            continue;
        }
        match dispatch_one_failure(resolution, icmpv4_errors, snapshot, now, hold) {
            FailureDispatch::Queued(reverse_egress) => {
                resolution.clear_failure_hold(index);
                resolution.failure_counters.queued += 1;
                report.queued += 1;
                trace.record_resolution_failure(ResolutionFailureTrace::Queued {
                    forward: hold.forward,
                    reverse_egress,
                });
            }
            FailureDispatch::WaitReverse {
                reverse,
                newly_scheduled,
            } => {
                resolution.wait_reverse(index, reverse);
                report.retained += 1;
                if newly_scheduled {
                    resolution.failure_counters.reverse_arp_scheduled += 1;
                    report.reverse_arp_scheduled += 1;
                    trace.record_resolution_failure(ResolutionFailureTrace::ReverseArpScheduled {
                        forward: hold.forward,
                        reverse,
                    });
                } else {
                    resolution.failure_counters.reverse_arp_pending += 1;
                    report.reverse_arp_pending += 1;
                    trace.record_resolution_failure(ResolutionFailureTrace::ReverseArpPending {
                        forward: hold.forward,
                        reverse,
                    });
                }
            }
            FailureDispatch::Retain(disposition) => {
                resolution.failure_counters.retained_transient += 1;
                report.retained += 1;
                trace.record_resolution_failure(ResolutionFailureTrace::Retained {
                    forward: hold.forward,
                    disposition,
                });
            }
            FailureDispatch::ReverseFailed(reverse) => {
                resolution.clear_failure_hold(index);
                resolution.failure_counters.reverse_resolution_failed += 1;
                report.retired += 1;
                trace.record_resolution_failure(ResolutionFailureTrace::ReverseResolutionFailed {
                    forward: hold.forward,
                    reverse,
                });
            }
            FailureDispatch::SameFailedKey => {
                resolution.clear_failure_hold(index);
                resolution.failure_counters.same_failed_key += 1;
                report.retired += 1;
                trace.record_resolution_failure(ResolutionFailureTrace::SameFailedKey {
                    forward: hold.forward,
                });
            }
            FailureDispatch::GenerationDisabled => {
                resolution.clear_failure_hold(index);
                resolution.failure_counters.generation_disabled += 1;
                report.retired += 1;
                trace.record_resolution_failure(ResolutionFailureTrace::GenerationDisabled {
                    forward: hold.forward,
                });
            }
            FailureDispatch::QuoteBelowMinimum => {
                resolution.clear_failure_hold(index);
                resolution.failure_counters.quote_below_minimum += 1;
                report.retired += 1;
                trace.record_resolution_failure(ResolutionFailureTrace::QuoteBelowMinimum {
                    forward: hold.forward,
                });
            }
            FailureDispatch::AuthorityLost => {
                resolution.clear_failure_hold(index);
                resolution.failure_counters.retired_permanent += 1;
                report.retired += 1;
                trace.record_resolution_failure(ResolutionFailureTrace::ForwardAuthorityLost {
                    forward: hold.forward,
                });
            }
        }
    }
    report.pending = resolution.pending_failure_holds();
    Ok(report)
}

enum FailureDispatch {
    Queued(IfId),
    WaitReverse {
        reverse: ResolutionGenerationToken,
        newly_scheduled: bool,
    },
    Retain(Icmpv4ErrorDisposition),
    ReverseFailed(ResolutionGenerationToken),
    SameFailedKey,
    GenerationDisabled,
    /// The reverse egress MTU cannot carry the RFC 792 minimum quote of the
    /// held datagram (MTU1 review); permanent for the hold, so it retires.
    QuoteBelowMinimum,
    AuthorityLost,
}

fn dispatch_one_failure(
    resolution: &mut ResolutionRuntime<'_>,
    icmpv4_errors: &mut Icmpv4ErrorRuntime<'_>,
    snapshot: &crate::ForwardingSnapshot<'_>,
    now: MonotonicMillis,
    hold: ResolutionFailureHoldSlot,
) -> FailureDispatch {
    let forward_status = resolution.status(hold.forward.egress, hold.forward.target);
    if !forward_status.is_some_and(|status| {
        status.generation == hold.forward.generation
            && status.phase == ResolutionPhase::Failed
            && status.accepted_attempts != 0
    }) {
        return FailureDispatch::AuthorityLost;
    }
    let forward_route = snapshot.route_lookup(hold.original_destination);
    if !forward_route.is_some_and(|route| {
        route.egress() == hold.forward.egress
            && route.next_hop().is_none()
            && hold.forward.target == hold.original_destination
            && route.prefix() == hold.forward_prefix
            && route.prefix_len() == hold.forward_prefix_len
    }) || !snapshot
        .interface(hold.forward.egress)
        .is_some_and(|interface| interface.mac == hold.forward_source_mac)
        || !snapshot.is_local_ipv4_on(hold.forward.egress, hold.forward_source_ip)
        || snapshot
            .static_neighbor(hold.forward.egress, hold.forward.target)
            .is_some()
        || host_failure_target_forbidden(
            snapshot,
            hold.forward.egress,
            hold.forward.target,
            hold.forward_source_ip,
        )
    {
        return FailureDispatch::AuthorityLost;
    }
    match resolution.lookup_dynamic(hold.forward.egress, hold.forward.target, now) {
        DynamicLookup::Hit(_) | DynamicLookup::ClockRegression => {
            return FailureDispatch::AuthorityLost;
        }
        DynamicLookup::Miss => {}
    }
    if !current_icmp_error_eligible(snapshot, hold) {
        return FailureDispatch::AuthorityLost;
    }
    if !icmpv4_errors
        .policy()
        .generates(Icmpv4ErrorKind::DestinationUnreachableHost)
    {
        // Retire before the reverse route or reverse ARP: a disabled kind
        // emits nothing on the wire.
        icmpv4_errors.record_suppression(Icmpv4ErrorDisposition::GenerationDisabled {
            kind: Icmpv4ErrorKind::DestinationUnreachableHost,
        });
        return FailureDispatch::GenerationDisabled;
    }

    let Some(reverse_route) = snapshot.route_lookup(hold.original_source) else {
        return FailureDispatch::AuthorityLost;
    };
    let reverse_egress = reverse_route.egress();
    let Some(interface) = snapshot.interface(reverse_egress) else {
        return FailureDispatch::AuthorityLost;
    };
    let Some(binding) = snapshot.local_binding_on(reverse_egress) else {
        return FailureDispatch::AuthorityLost;
    };
    let target = reverse_route.next_hop().unwrap_or(hold.original_source);
    if host_failure_target_forbidden(snapshot, reverse_egress, target, binding.address) {
        return FailureDispatch::AuthorityLost;
    }
    let reverse_key = ResolutionKey {
        egress: reverse_egress,
        target,
    };
    if reverse_key
        == (ResolutionKey {
            egress: hold.forward.egress,
            target: hold.forward.target,
        })
    {
        return FailureDispatch::SameFailedKey;
    }

    let destination_mac = if let Some(neighbor) = snapshot.static_neighbor(reverse_egress, target) {
        neighbor.mac
    } else {
        match resolution.lookup_dynamic(reverse_egress, target, now) {
            DynamicLookup::Hit(mac) => mac,
            DynamicLookup::ClockRegression => {
                return FailureDispatch::Retain(Icmpv4ErrorDisposition::ClockRegression);
            }
            DynamicLookup::Miss => {
                if hold.phase == ResolutionFailureHoldPhase::WaitingReverse
                    && hold.reverse.egress == reverse_egress
                    && hold.reverse.target == target
                    && resolution
                        .status(hold.reverse.egress, hold.reverse.target)
                        .is_some_and(|status| {
                            status.generation == hold.reverse.generation
                                && status.phase == ResolutionPhase::Failed
                        })
                {
                    return FailureDispatch::ReverseFailed(hold.reverse);
                }
                let result = resolution.schedule(
                    ArpRequestAction {
                        egress: reverse_egress,
                        source_mac: interface.mac,
                        source_ip: binding.address,
                        target_ip: target,
                    },
                    now,
                    false,
                );
                if matches!(
                    result,
                    ResolutionResult::Failed | ResolutionResult::TimedOut
                ) {
                    if let Some(status) = resolution.status(reverse_egress, target) {
                        return FailureDispatch::ReverseFailed(ResolutionGenerationToken {
                            egress: reverse_egress,
                            target,
                            generation: status.generation,
                        });
                    }
                }
                if resolution
                    .status(reverse_egress, target)
                    .is_some_and(|status| {
                        matches!(
                            status.phase,
                            ResolutionPhase::InitialQueued
                                | ResolutionPhase::RetryQueued
                                | ResolutionPhase::Waiting
                        )
                    })
                {
                    let status = resolution
                        .status(reverse_egress, target)
                        .expect("active status was just observed");
                    return FailureDispatch::WaitReverse {
                        reverse: ResolutionGenerationToken {
                            egress: reverse_egress,
                            target,
                            generation: status.generation,
                        },
                        newly_scheduled: matches!(
                            result,
                            ResolutionResult::Queued | ResolutionResult::RetryQueued
                        ),
                    };
                }
                return FailureDispatch::Retain(
                    Icmpv4ErrorDisposition::ReverseNeighborUnresolved {
                        egress: reverse_egress,
                        target,
                        resolution: result,
                    },
                );
            }
        }
    };

    let disposition = icmpv4_errors.schedule(
        Icmpv4ErrorAction::new_with_kind(
            Icmpv4ErrorKind::DestinationUnreachableHost,
            reverse_egress,
            interface.mac,
            destination_mac,
            binding.address,
            hold.original_source,
            hold.original_tos,
            snapshot.ipv4_origin.default_ttl(),
            &hold.quote[..usize::from(hold.quote_len)],
        )
        .fit_egress_mtu(interface.mtu),
        now,
    );
    match disposition {
        Icmpv4ErrorDisposition::HostUnreachableQueued { .. } => {
            FailureDispatch::Queued(reverse_egress)
        }
        Icmpv4ErrorDisposition::QuoteBelowMinimum { .. } => FailureDispatch::QuoteBelowMinimum,
        _ => FailureDispatch::Retain(disposition),
    }
}

fn current_icmp_error_eligible(
    snapshot: &crate::ForwardingSnapshot<'_>,
    hold: ResolutionFailureHoldSlot,
) -> bool {
    let source = hold.original_source.octets();
    source[0] != 0
        && source[0] != 127
        && source[0] < 224
        && !snapshot.is_local_ipv4(hold.original_source)
        && !snapshot
            .route_lookup(hold.original_source)
            .is_some_and(|route| {
                route.is_prefix_network_address(hold.original_source)
                    || route.is_prefix_directed_broadcast(hold.original_source)
            })
}

fn host_failure_target_forbidden(
    snapshot: &crate::ForwardingSnapshot<'_>,
    egress: IfId,
    target: Ipv4Address,
    local: Ipv4Address,
) -> bool {
    let octets = target.octets();
    octets[0] == 0
        || octets[0] == 127
        || octets[0] >= 224
        || octets == [255; 4]
        || target == local
        || snapshot.is_local_ipv4(target)
        || snapshot.is_connected_boundary(egress, target)
}

fn forbidden_target(target: Ipv4Address) -> bool {
    let octets = target.octets();
    octets[0] == 0 || octets[0] == 127 || octets[0] >= 224 || octets == [255; 4]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedArpTrace {
    AllocationFailed(GeneratedAllocationError),
    BuildFailed(ArpRequestBuildError),
    ClockRegression,
    TxRequested { egress: IfId, target: Ipv4Address },
    BatchCompleted { accepted: usize, rejected: usize },
}

pub trait GeneratedTraceSink {
    fn record_generated(&mut self, event: GeneratedArpTrace);
}

#[derive(Default)]
pub struct NoGeneratedTrace;

impl GeneratedTraceSink for NoGeneratedTrace {
    #[inline]
    fn record_generated(&mut self, _event: GeneratedArpTrace) {}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArpRequestBuildError {
    ExactLengthRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecuteArpRequestError {
    ClockRegression,
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedArpReport<E> {
    pub action: ArpRequestAction,
    pub allocation_error: Option<GeneratedAllocationError>,
    pub build_error: Option<ArpRequestBuildError>,
    pub completion: GeneratedBatchCompletion<E>,
}

/// Executes at most one queued action. Allocation failure retains the action.
pub fn execute_one_arp_request<I, T>(
    io: &mut I,
    runtime: &mut ResolutionRuntime<'_>,
    now: MonotonicMillis,
    trace: &mut T,
) -> Result<Option<GeneratedArpReport<I::Error>>, ExecuteArpRequestError>
where
    I: GeneratedPacketIo,
    T: GeneratedTraceSink,
{
    let Some(queued) = runtime.front() else {
        return Ok(None);
    };
    if !runtime.execution_time_valid(now) {
        trace.record_generated(GeneratedArpTrace::ClockRegression);
        return Err(ExecuteArpRequestError::ClockRegression);
    }
    let mut batch = io.begin_generated(queued.action.egress);
    let (allocation_error, build_error, committed) =
        match allocate_arp_request(&mut batch, queued.action) {
            Ok(()) => {
                runtime.committed(queued, now);
                trace.record_generated(GeneratedArpTrace::TxRequested {
                    egress: queued.action.egress,
                    target: queued.action.target_ip,
                });
                (None, None, true)
            }
            Err(ArpRequestGenerationError::Allocation(error)) => {
                trace.record_generated(GeneratedArpTrace::AllocationFailed(error));
                (Some(error), None, false)
            }
            Err(ArpRequestGenerationError::Build(error)) => {
                trace.record_generated(GeneratedArpTrace::BuildFailed(error));
                (None, Some(error), false)
            }
        };
    let completion = batch.finish();
    if committed {
        runtime.accepted(queued, completion.accepted);
    }
    trace.record_generated(GeneratedArpTrace::BatchCompleted {
        accepted: completion.accepted,
        rejected: completion.rejected,
    });
    Ok(Some(GeneratedArpReport {
        action: queued.action,
        allocation_error,
        build_error,
        completion,
    }))
}

enum ArpRequestGenerationError {
    Allocation(GeneratedAllocationError),
    Build(ArpRequestBuildError),
}

fn allocate_arp_request<B: GeneratedPacketBatch>(
    batch: &mut B,
    action: ArpRequestAction,
) -> Result<(), ArpRequestGenerationError> {
    let mut lease = batch
        .allocate(ARP_REQUEST_FRAME_LEN)
        .map_err(ArpRequestGenerationError::Allocation)?;
    if lease.bytes_mut().len() != ARP_REQUEST_FRAME_LEN {
        lease.cancel();
        return Err(ArpRequestGenerationError::Build(
            ArpRequestBuildError::ExactLengthRequired,
        ));
    }
    build_arp_request(lease.bytes_mut(), action);
    lease.commit();
    Ok(())
}

fn build_arp_request(frame: &mut [u8], action: ArpRequestAction) {
    debug_assert_eq!(frame.len(), ARP_REQUEST_FRAME_LEN);
    frame.fill(0);
    frame[0..6].fill(0xff);
    frame[6..12].copy_from_slice(&action.source_mac.0);
    frame[12..14].copy_from_slice(&ARP_ETHERTYPE.to_be_bytes());
    frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&IPV4_ETHERTYPE.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
    frame[22..28].copy_from_slice(&action.source_mac.0);
    frame[28..32].copy_from_slice(&action.source_ip.octets());
    frame[38..42].copy_from_slice(&action.target_ip.octets());
}

#[cfg(test)]
#[path = "resolution_index_tests.rs"]
mod index_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ForwardingSnapshot, Interface, LocalIpv4Binding, Neighbor, Route};

    // `resolution/tests/carry.rs`: learned neighbors carried across a
    // publication (RELOAD-CARRY).
    mod carry;
    // `resolution/tests/occupancy.rs`: table high-water marks (OBS-017).
    mod occupancy;

    const WAN: IfId = IfId(2);
    const SOURCE_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
    const SOURCE_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);

    fn target(last: u8) -> Ipv4Address {
        Ipv4Address::from_octets([192, 0, 2, last])
    }

    fn action(last: u8) -> ArpRequestAction {
        ArpRequestAction {
            egress: WAN,
            source_mac: SOURCE_MAC,
            source_ip: SOURCE_IP,
            target_ip: target(last),
        }
    }

    fn commit_front(runtime: &mut ResolutionRuntime<'_>, now: u64) {
        let queued = runtime.front().expect("queued action");
        runtime.committed(queued, MonotonicMillis(now));
    }

    fn commit_front_accepted(runtime: &mut ResolutionRuntime<'_>, now: u64) {
        let queued = runtime.front().expect("queued action");
        runtime.committed(queued, MonotonicMillis(now));
        runtime.accepted(queued, 1);
    }

    fn assert_pending_accounting(runtime: &ResolutionRuntime<'_>) {
        assert_eq!(
            runtime.pending_states(),
            runtime
                .states
                .iter()
                .copied()
                .filter(|state| state_is_pending(state.entry))
                .count()
        );
        assert!(runtime.indexes_valid(), "indexes match the slots");
        assert_eq!(
            runtime.pending_failure_holds(),
            runtime
                .failure_holds
                .iter()
                .filter(|hold| hold.phase != ResolutionFailureHoldPhase::Empty)
                .count()
        );
    }

    #[derive(Debug, Eq, PartialEq)]
    struct RuntimeImage {
        policy: ResolutionPolicy,
        states: Vec<ResolutionStateSlot>,
        actions: Vec<ResolutionActionSlot>,
        dynamic_neighbors: Vec<DynamicNeighborSlot>,
        failure_holds: Vec<ResolutionFailureHoldSlot>,
        action_queue: SlotList,
        request_order: SlotList,
        dynamic_order: SlotList,
        dynamic_count: usize,
        index_counters: ResolutionIndexCounters,
        pending_state_count: usize,
        pending_failure_hold_count: usize,
        poll_cursor: usize,
        failure_cursor: usize,
        last_now: Option<MonotonicMillis>,
        publication_epoch: u128,
        counters: ResolutionCounters,
        failure_counters: ResolutionFailureCounters,
    }

    fn runtime_image(runtime: &ResolutionRuntime<'_>) -> RuntimeImage {
        RuntimeImage {
            policy: runtime.policy,
            states: runtime.states.to_vec(),
            actions: runtime.actions.to_vec(),
            dynamic_neighbors: runtime.dynamic_neighbors.to_vec(),
            failure_holds: runtime.failure_holds.to_vec(),
            action_queue: runtime.action_queue,
            request_order: runtime.request_order,
            dynamic_order: runtime.dynamic_order,
            dynamic_count: runtime.dynamic_count,
            index_counters: runtime.index_counters,
            pending_state_count: runtime.pending_state_count,
            pending_failure_hold_count: runtime.pending_failure_hold_count,
            poll_cursor: runtime.poll_cursor,
            failure_cursor: runtime.failure_cursor,
            last_now: runtime.last_now,
            publication_epoch: runtime.publication_epoch,
            counters: runtime.counters,
            failure_counters: runtime.failure_counters,
        }
    }

    fn assert_publication_error_is_atomic(
        runtime: &mut ResolutionRuntime<'_>,
        expected: ResolutionPublicationError,
    ) {
        let before = runtime_image(runtime);
        assert_eq!(runtime.preflight_publication().err(), Some(expected));
        assert_eq!(runtime_image(runtime), before);
    }

    #[derive(Default)]
    struct TimerTrace {
        events: [Option<ResolutionTimerTrace>; 16],
        len: usize,
    }

    #[test]
    fn publication_preflight_errors_leave_runtime_exactly_unchanged() {
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let mut states = [];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.action_queue = SlotList::from_raw_for_test(INDEX_NONE, INDEX_NONE, 1);
        assert_publication_error_is_atomic(
            &mut runtime,
            ResolutionPublicationError::ActionQueueCapacity,
        );

        let mut states = [];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.action_queue = SlotList::from_raw_for_test(1, 1, 1);
        assert_publication_error_is_atomic(
            &mut runtime,
            ResolutionPublicationError::ActionQueueHead,
        );

        let mut states = [];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.action_queue = SlotList::from_raw_for_test(0, 0, 1);
        assert_publication_error_is_atomic(
            &mut runtime,
            ResolutionPublicationError::ActionQueueWindow,
        );

        // A reusable-slot bit that disagrees with its state.
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.states[0].used_word = 1;
        assert_publication_error_is_atomic(&mut runtime, ResolutionPublicationError::IndexCorrupt);

        // A dynamic neighbor that is not on its key chain.
        let mut dynamic = [DynamicNeighborSlot::EMPTY; 2];
        let mut runtime =
            ResolutionRuntime::with_dynamic_neighbors(policy, &mut [], &mut [], &mut dynamic);
        assert_eq!(
            runtime.merge_dynamic(
                WAN,
                target(9),
                MacAddress([2, 0, 0, 0, 0, 9]),
                true,
                false,
                MonotonicMillis(0)
            ),
            ControlDisposition::Inserted
        );
        let linked = runtime.find_dynamic(ResolutionKey {
            egress: WAN,
            target: target(9),
        });
        let index = linked.unwrap();
        runtime.dynamic_neighbors[index].entry.target = target(10);
        assert_publication_error_is_atomic(&mut runtime, ResolutionPublicationError::IndexCorrupt);

        let mut states = [];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.pending_state_count = 1;
        assert_publication_error_is_atomic(
            &mut runtime,
            ResolutionPublicationError::PendingStateCount,
        );

        let mut states = [];
        let mut actions = [];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        runtime.pending_failure_hold_count = 1;
        assert_publication_error_is_atomic(
            &mut runtime,
            ResolutionPublicationError::PendingFailureHoldCount,
        );

        let mut states = [];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.publication_epoch = u128::MAX;
        assert_publication_error_is_atomic(
            &mut runtime,
            ResolutionPublicationError::RuntimeEpochExhausted,
        );
    }

    #[test]
    fn publication_permit_drop_and_commit_flush_all_authority_without_overflow() {
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 2];
        let mut actions = [ResolutionActionSlot::EMPTY; 2];
        let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut dynamic,
            &mut holds,
        );
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
        assert_eq!(
            runtime.schedule(action(3), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
        commit_front(&mut runtime, 0);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(1_000),
                usize::MAX,
                &mut NoResolutionTimerTrace,
            )
            .unwrap()
            .retries_queued,
            1
        );
        assert_eq!(runtime.pending_actions(), 2);
        assert_eq!(runtime.front().unwrap().action, action(3));
        assert_eq!(
            runtime.merge_dynamic(
                WAN,
                target(9),
                MacAddress([2, 0, 0, 0, 0, 9]),
                true,
                false,
                MonotonicMillis(1_000)
            ),
            ControlDisposition::Inserted
        );
        assert!(matches!(
            runtime.capture_failure_candidate(
                WAN,
                target(2),
                target(50),
                target(2),
                SOURCE_MAC,
                SOURCE_IP,
                Ipv4Address::from_octets([192, 0, 2, 0]),
                24,
                0,
                &[0x45; 20],
            ),
            ResolutionFailureCapture::Captured(_)
        ));
        runtime.counters.queued = usize::MAX;
        runtime.failure_counters.cancelled = usize::MAX;

        let before = runtime_image(&runtime);
        let permit = runtime.preflight_publication().unwrap();
        assert_eq!(
            permit.preview(),
            ResolutionPublicationReport {
                states_flushed: 2,
                actions_flushed: 2,
                dynamic_neighbors_flushed: 1,
                failure_holds_flushed: 1,
                ..ResolutionPublicationReport::default()
            }
        );
        drop(permit);
        assert_eq!(runtime_image(&runtime), before);

        let counters = runtime.counters;
        let failure_counters = runtime.failure_counters;
        let report = runtime.preflight_publication().unwrap().commit();
        assert_eq!(
            report,
            ResolutionPublicationReport {
                states_flushed: 2,
                actions_flushed: 2,
                dynamic_neighbors_flushed: 1,
                failure_holds_flushed: 1,
                ..ResolutionPublicationReport::default()
            }
        );
        assert!(runtime
            .states
            .iter()
            .all(|slot| *slot == ResolutionStateSlot::EMPTY));
        assert!(runtime
            .actions
            .iter()
            .all(|slot| *slot == ResolutionActionSlot::EMPTY));
        assert!(runtime
            .dynamic_neighbors
            .iter()
            .all(|slot| *slot == DynamicNeighborSlot::EMPTY));
        assert!(runtime
            .failure_holds
            .iter()
            .all(|slot| *slot == ResolutionFailureHoldSlot::EMPTY));
        assert_eq!(
            (
                runtime.action_queue.len(),
                runtime.dynamic_count,
                runtime.pending_state_count,
                runtime.pending_failure_hold_count,
                runtime.poll_cursor,
                runtime.failure_cursor,
                runtime.publication_epoch,
            ),
            (0, 0, 0, 0, 0, 0, 2)
        );
        assert_eq!(runtime.counters, counters);
        assert_eq!(runtime.failure_counters, failure_counters);
    }

    #[test]
    fn publication_zero_capacity_is_total_and_pristine_is_exact() {
        let mut states = [];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 1_000).unwrap(),
            &mut states,
            &mut actions,
        );
        assert!(runtime.is_pristine());
        assert_eq!(
            runtime.preflight_publication().unwrap().commit(),
            ResolutionPublicationReport::default()
        );
        assert!(!runtime.is_pristine());

        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [];
        let runtime = ResolutionRuntime::new(
            ResolutionPolicy::new(1_000, 1_000).unwrap(),
            &mut states,
            &mut actions,
        );
        runtime.states[0].entry.generation = 9;
        assert!(!runtime.is_pristine());
    }

    impl ResolutionTimerTraceSink for TimerTrace {
        fn record_resolution_timer(&mut self, event: ResolutionTimerTrace) {
            self.events[self.len] = Some(event);
            self.len += 1;
        }
    }

    #[test]
    fn exact_three_attempt_timeline_and_max_one_wait_full_interval() {
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        assert_eq!(policy.interval_ms(), 1_000);
        assert_eq!(policy.failed_hold_ms(), 1_000);
        assert_eq!(policy.max_attempts(), 3);
        assert_eq!(policy.dynamic_neighbor_ttl_ms(), 60_000);
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
        commit_front(&mut runtime, 0);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(999),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .retries_queued,
            0
        );
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(1_000),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .retries_queued,
            1
        );
        commit_front(&mut runtime, 1_000);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(2_000),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .retries_queued,
            1
        );
        commit_front(&mut runtime, 2_000);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(2_999),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .timed_out,
            0
        );
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(3_000),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .timed_out,
            1
        );
        assert_eq!(
            runtime.status(WAN, target(2)).unwrap().phase,
            ResolutionPhase::Failed
        );
        assert_eq!(runtime.counters().attempts_committed, 3);

        let policy = ResolutionPolicy::with_retry(1_000, 1_000, 1).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        assert_eq!(
            runtime.schedule(action(3), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
        commit_front(&mut runtime, 0);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(999),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .timed_out,
            0
        );
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(1_000),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .timed_out,
            1
        );
    }

    #[test]
    fn late_poll_queues_only_one_retry_and_rx_timer_order_is_idempotent() {
        for rx_first in [false, true] {
            let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
            let mut states = [ResolutionStateSlot::EMPTY; 1];
            let mut actions = [ResolutionActionSlot::EMPTY; 1];
            let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
            assert_eq!(
                runtime.schedule(action(2), MonotonicMillis(0), false),
                ResolutionResult::Queued
            );
            commit_front(&mut runtime, 0);
            if rx_first {
                assert_eq!(
                    runtime.schedule(action(2), MonotonicMillis(5_000), false),
                    ResolutionResult::RetryQueued
                );
                assert_eq!(
                    poll_resolution_timers(
                        &mut runtime,
                        MonotonicMillis(5_000),
                        1,
                        &mut NoResolutionTimerTrace
                    )
                    .unwrap()
                    .retries_queued,
                    0
                );
            } else {
                assert_eq!(
                    poll_resolution_timers(
                        &mut runtime,
                        MonotonicMillis(5_000),
                        1,
                        &mut NoResolutionTimerTrace
                    )
                    .unwrap()
                    .retries_queued,
                    1
                );
                assert_eq!(
                    runtime.schedule(action(2), MonotonicMillis(5_000), false),
                    ResolutionResult::Suppressed
                );
            }
            assert_eq!(runtime.pending_actions(), 1);
            assert_eq!(runtime.status(WAN, target(2)).unwrap().attempts, 1);
        }
    }

    #[test]
    fn failed_hold_has_one_terminal_transition_and_exact_expiry_new_generation() {
        let policy = ResolutionPolicy::with_retry(1_000, 2_000, 1).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.schedule(action(2), MonotonicMillis(0), false);
        let first_generation = runtime.status(WAN, target(2)).unwrap().generation;
        commit_front(&mut runtime, 0);
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(1_000), false),
            ResolutionResult::TimedOut
        );
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(2_999), false),
            ResolutionResult::Failed
        );
        assert_eq!(runtime.counters().timed_out, 1);
        assert_eq!(runtime.counters().failed_hits, 1);
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(3_000), false),
            ResolutionResult::Queued
        );
        let status = runtime.status(WAN, target(2)).unwrap();
        assert_eq!(status.phase, ResolutionPhase::InitialQueued);
        assert_eq!(status.attempts, 0);
        assert_eq!(status.generation, first_generation.wrapping_add(1));
        assert_eq!(runtime.counters().failures_expired, 1);
    }

    #[test]
    fn bounded_round_robin_makes_progress_under_action_pressure() {
        let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 2];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.schedule(action(2), MonotonicMillis(0), false);
        commit_front(&mut runtime, 0);
        runtime.schedule(action(3), MonotonicMillis(0), false);
        commit_front(&mut runtime, 0);

        let first = poll_resolution_timers(
            &mut runtime,
            MonotonicMillis(1_000),
            1,
            &mut NoResolutionTimerTrace,
        )
        .unwrap();
        assert_eq!((first.scanned, first.retries_queued), (1, 1));
        let mut trace = TimerTrace::default();
        let second =
            poll_resolution_timers(&mut runtime, MonotonicMillis(1_000), 1, &mut trace).unwrap();
        assert_eq!(
            (
                second.scanned,
                second.retries_queued,
                second.action_full,
                second.deferred_due
            ),
            (1, 0, 1, 1)
        );
        assert!(matches!(
            trace.events[0],
            Some(ResolutionTimerTrace::ActionFull { target: value, .. }) if value == target(3)
        ));
        commit_front(&mut runtime, 1_000);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(1_000),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .retries_queued,
            0,
            "persistent cursor first scans the other state"
        );
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(1_000),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .retries_queued,
            1
        );
        assert_eq!(runtime.front().unwrap().action.target_ip, target(3));
    }

    #[test]
    fn clock_regression_is_atomic_for_poll_and_equal_time_recovers() {
        let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.schedule(action(2), MonotonicMillis(u64::MAX - 2_000), false);
        commit_front(&mut runtime, u64::MAX - 2_000);
        let before = runtime.status(WAN, target(2));
        let mut trace = TimerTrace::default();
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(u64::MAX - 2_001),
                1,
                &mut trace
            ),
            Err(ResolutionTimerError::ClockRegression)
        );
        assert_eq!(runtime.status(WAN, target(2)), before);
        assert_eq!(runtime.pending_actions(), 0);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(u64::MAX - 1_000),
                1,
                &mut trace
            )
            .unwrap()
            .retries_queued,
            1
        );
        assert!(matches!(
            trace.events[0],
            Some(ResolutionTimerTrace::ClockRegression)
        ));
    }

    #[test]
    fn successful_merge_cancels_queued_waiting_and_failed_cycles() {
        for cancellation_point in 0..4 {
            let policy = ResolutionPolicy::with_retry(1_000, 2_000, 1).unwrap();
            let mut states = [ResolutionStateSlot::EMPTY; 1];
            let mut actions = [ResolutionActionSlot::EMPTY; 1];
            let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
            let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
                policy,
                &mut states,
                &mut actions,
                &mut dynamic,
            );
            runtime.schedule(action(2), MonotonicMillis(0), false);
            if cancellation_point >= 1 {
                commit_front(&mut runtime, 0);
            }
            if cancellation_point == 2 {
                runtime.policy.max_attempts = 2;
                poll_resolution_timers(
                    &mut runtime,
                    MonotonicMillis(1_000),
                    1,
                    &mut NoResolutionTimerTrace,
                )
                .unwrap();
            }
            if cancellation_point == 3 {
                poll_resolution_timers(
                    &mut runtime,
                    MonotonicMillis(1_000),
                    1,
                    &mut NoResolutionTimerTrace,
                )
                .unwrap();
            }
            assert_eq!(
                runtime.merge_dynamic(
                    WAN,
                    target(2),
                    MacAddress([3; 6]),
                    true,
                    false,
                    MonotonicMillis(1_000),
                ),
                ControlDisposition::Inserted
            );
            if cancellation_point == 0 {
                assert_eq!(runtime.status(WAN, target(2)), None);
            } else {
                assert_eq!(
                    runtime.status(WAN, target(2)).unwrap().phase,
                    ResolutionPhase::Cooldown
                );
            }
            assert_eq!(runtime.pending_actions(), 0);
        }
    }

    #[test]
    fn publication_reconciliation_removes_static_and_invalid_authority_only() {
        let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 3];
        let mut actions = [ResolutionActionSlot::EMPTY; 3];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        for last in [2, 3, 4] {
            runtime.schedule(action(last), MonotonicMillis(0), false);
        }
        let routes = [Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, WAN, None).unwrap()];
        let interfaces = [Interface {
            id: WAN,
            mac: SOURCE_MAC,
            mtu: 1500,
        }];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: SOURCE_IP,
        }];
        let neighbors = [Neighbor {
            interface: WAN,
            target: target(3),
            mac: MacAddress([9; 6]),
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let report = runtime.reconcile_publication(&snapshot);
        assert_eq!(report.states_removed, 1);
        assert_eq!(report.actions_removed, 1);
        assert_eq!(runtime.pending_actions(), 2);
        assert_eq!(runtime.front().unwrap().action.target_ip, target(2));
        commit_front(&mut runtime, 0);
        assert_eq!(runtime.front().unwrap().action.target_ip, target(4));

        let changed_interfaces = [Interface {
            id: WAN,
            mac: MacAddress([7; 6]),
            mtu: 1500,
        }];
        let changed =
            ForwardingSnapshot::new(&routes, &changed_interfaces, &[], &bindings).unwrap();
        let report = runtime.reconcile_publication(&changed);
        assert_eq!(report.invalid_states_removed, 2);
        assert_eq!(report.invalid_actions_removed, 1);
        assert_eq!(runtime.pending_actions(), 0);
    }

    #[test]
    fn zero_storage_and_policy_validation_are_safe() {
        assert_eq!(
            ResolutionPolicy::with_retry(1_000, 1_000, 0),
            Err(ResolutionPolicyError::MaxAttemptsZero)
        );
        let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
        let mut states = [];
        let mut actions = [];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(0), false),
            ResolutionResult::StateFull
        );
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(0),
                usize::MAX,
                &mut NoResolutionTimerTrace
            )
            .unwrap(),
            ResolutionTimerReport::default()
        );
    }

    #[test]
    fn generation_wrap_and_due_action_full_are_lifecycle_safe_and_atomic() {
        let policy = ResolutionPolicy::with_retry(1_000, 1_000, 2).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 2];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.states[0].entry.generation = u64::MAX;
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
        assert_eq!(runtime.status(WAN, target(2)).unwrap().generation, 0);
        commit_front(&mut runtime, 0);

        assert_eq!(
            runtime.schedule(action(3), MonotonicMillis(1_000), false),
            ResolutionResult::Queued
        );
        let authoritative = runtime
            .states
            .iter()
            .find(|state| state.entry.occupied && state.entry.key.target == target(2))
            .unwrap()
            .entry
            .action;
        let mut changed = action(2);
        changed.source_mac = MacAddress([9; 6]);
        assert_eq!(
            runtime.schedule(changed, MonotonicMillis(1_000), false),
            ResolutionResult::ActionFull
        );
        assert_eq!(
            runtime
                .states
                .iter()
                .find(|state| state.entry.occupied && state.entry.key.target == target(2))
                .unwrap()
                .entry
                .action,
            authoritative
        );
        assert_eq!(runtime.status(WAN, target(2)).unwrap().attempts, 1);
    }

    #[test]
    fn learned_mapping_with_short_ttl_cannot_reset_committed_cooldown() {
        let policy =
            ResolutionPolicy::with_retry_and_dynamic_neighbor_ttl(1_000, 2_000, 3, 1).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
            policy,
            &mut states,
            &mut actions,
            &mut dynamic,
        );
        runtime.schedule(action(2), MonotonicMillis(0), false);
        commit_front(&mut runtime, 0);
        assert_eq!(
            runtime.merge_dynamic(
                WAN,
                target(2),
                MacAddress([3; 6]),
                true,
                false,
                MonotonicMillis(1),
            ),
            ControlDisposition::Inserted
        );
        assert_eq!(
            runtime.status(WAN, target(2)).unwrap().phase,
            ResolutionPhase::Cooldown
        );
        assert_eq!(
            runtime.lookup_dynamic(WAN, target(2), MonotonicMillis(2)),
            DynamicLookup::Miss
        );
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(2), false),
            ResolutionResult::Suppressed
        );
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(999),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .retries_queued,
            0
        );
        assert_eq!(runtime.pending_actions(), 0);
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(1_000), false),
            ResolutionResult::Queued
        );
    }

    #[test]
    fn static_publication_removal_cannot_reset_committed_cooldown() {
        let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.schedule(action(2), MonotonicMillis(0), false);
        commit_front(&mut runtime, 0);

        let routes = [Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, WAN, None).unwrap()];
        let interfaces = [Interface {
            id: WAN,
            mac: SOURCE_MAC,
            mtu: 1500,
        }];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: SOURCE_IP,
        }];
        let neighbors = [Neighbor {
            interface: WAN,
            target: target(2),
            mac: MacAddress([4; 6]),
        }];
        let with_static =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let report = runtime.reconcile_publication(&with_static);
        assert_eq!(report.cooldowns_retained, 1);
        assert_eq!(
            runtime.status(WAN, target(2)).unwrap().phase,
            ResolutionPhase::Cooldown
        );

        let without_static = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        assert_eq!(
            runtime.reconcile_publication(&without_static),
            StaticReconcileReport::default()
        );
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(999), false),
            ResolutionResult::Suppressed
        );
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(1_000), false),
            ResolutionResult::Queued
        );
    }

    #[test]
    fn uncommitted_cancel_has_no_cooldown_and_expired_tombstone_is_reusable() {
        let policy =
            ResolutionPolicy::with_retry_and_dynamic_neighbor_ttl(1_000, 2_000, 3, 1).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut dynamic = [DynamicNeighborSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors(
            policy,
            &mut states,
            &mut actions,
            &mut dynamic,
        );
        runtime.schedule(action(2), MonotonicMillis(0), false);
        runtime.merge_dynamic(
            WAN,
            target(2),
            MacAddress([3; 6]),
            true,
            false,
            MonotonicMillis(1),
        );
        assert_eq!(runtime.status(WAN, target(2)), None);
        assert_eq!(
            runtime.lookup_dynamic(WAN, target(2), MonotonicMillis(2)),
            DynamicLookup::Miss
        );
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(2), false),
            ResolutionResult::Queued
        );
        commit_front(&mut runtime, 2);
        runtime.clear_resolution(WAN, target(2));
        assert_eq!(
            runtime.schedule(action(3), MonotonicMillis(1_001), false),
            ResolutionResult::StateFull
        );
        assert_eq!(
            runtime.schedule(action(3), MonotonicMillis(1_002), false),
            ResolutionResult::Queued,
            "expired cooldown slot is reusable by a different key"
        );
    }

    #[test]
    fn authority_change_scrubs_retry_but_preserves_cooldown_and_clock_atomicity() {
        let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        runtime.schedule(action(2), MonotonicMillis(0), false);
        commit_front(&mut runtime, 0);

        let routes = [Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, WAN, None).unwrap()];
        let new_mac = MacAddress([8; 6]);
        let interfaces = [Interface {
            id: WAN,
            mac: new_mac,
            mtu: 1500,
        }];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: SOURCE_IP,
        }];
        let changed = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
        let report = runtime.reconcile_publication(&changed);
        assert_eq!(
            (report.invalid_states_removed, report.cooldowns_retained),
            (1, 1)
        );
        assert_eq!(runtime.pending_actions(), 0);
        let mut fresh = action(2);
        fresh.source_mac = new_mac;
        assert_eq!(
            runtime.schedule(fresh, MonotonicMillis(500), false),
            ResolutionResult::Suppressed
        );
        let before = runtime.status(WAN, target(2));
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(499),
                1,
                &mut NoResolutionTimerTrace
            ),
            Err(ResolutionTimerError::ClockRegression)
        );
        assert_eq!(runtime.status(WAN, target(2)), before);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(500),
                1,
                &mut NoResolutionTimerTrace
            )
            .unwrap()
            .retries_queued,
            0
        );
        assert_eq!(runtime.status(WAN, target(2)), before);
        assert_eq!(
            runtime.schedule(fresh, MonotonicMillis(1_000), false),
            ResolutionResult::Queued
        );
        assert_eq!(runtime.front().unwrap().action.source_mac, new_mac);
    }

    #[test]
    fn pending_state_accounting_survives_rollback_reconcile_regression_and_cursor_wrap() {
        let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 4];
        let mut actions = [ResolutionActionSlot::EMPTY; 3];
        let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
        for last in [2, 3, 4] {
            assert_eq!(
                runtime.schedule(action(last), MonotonicMillis(100), false),
                ResolutionResult::Queued
            );
        }
        assert_pending_accounting(&runtime);
        assert_eq!(runtime.pending_states(), 3);

        assert_eq!(
            runtime.schedule(action(5), MonotonicMillis(100), false),
            ResolutionResult::ActionFull
        );
        assert_pending_accounting(&runtime);
        assert_eq!(runtime.pending_states(), 3);
        assert_eq!(
            poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(99),
                usize::MAX,
                &mut NoResolutionTimerTrace
            ),
            Err(ResolutionTimerError::ClockRegression)
        );
        assert_pending_accounting(&runtime);
        let zero_budget = poll_resolution_timers(
            &mut runtime,
            MonotonicMillis(100),
            0,
            &mut NoResolutionTimerTrace,
        )
        .unwrap();
        assert_eq!((zero_budget.scanned, zero_budget.pending), (0, 3));

        commit_front(&mut runtime, 100);
        let routes = [Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, WAN, None).unwrap()];
        let interfaces = [Interface {
            id: WAN,
            mac: SOURCE_MAC,
            mtu: 1500,
        }];
        let bindings = [LocalIpv4Binding {
            interface: WAN,
            address: SOURCE_IP,
        }];
        let neighbors = [
            Neighbor {
                interface: WAN,
                target: target(2),
                mac: MacAddress([8; 6]),
            },
            Neighbor {
                interface: WAN,
                target: target(3),
                mac: MacAddress([9; 6]),
            },
        ];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let reconciled = runtime.reconcile_publication(&snapshot);
        assert_eq!(
            (
                reconciled.states_removed,
                reconciled.cooldowns_retained,
                reconciled.actions_removed
            ),
            (2, 1, 1)
        );
        assert_pending_accounting(&runtime);
        assert_eq!(runtime.pending_states(), 1);

        for _ in 0..=runtime.states.len() {
            let report = poll_resolution_timers(
                &mut runtime,
                MonotonicMillis(100),
                1,
                &mut NoResolutionTimerTrace,
            )
            .unwrap();
            assert_eq!((report.scanned, report.pending), (1, 1));
            assert_pending_accounting(&runtime);
        }
    }

    /// MTU1 review: a hold whose quote cannot fit the RFC 792 minimum on
    /// the reverse egress (IHL 15 = 60-byte header + 8 bytes, MTU 70 leaves
    /// 42) retires as `quote_below_minimum` on the first dispatch instead of
    /// being retained and re-suppressed on every scan.
    #[test]
    fn a_hold_below_the_quote_minimum_retires() {
        const LAN: IfId = IfId(1);
        let host = Ipv4Address::from_octets([198, 51, 100, 10]);
        let routes = [
            Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, WAN, None).unwrap(),
            Route::new(Ipv4Address::from_octets([198, 51, 100, 0]), 24, LAN, None).unwrap(),
        ];
        let interfaces = [
            Interface {
                id: LAN,
                mac: MacAddress([2, 0, 0, 0, 0, 9]),
                mtu: 70,
            },
            Interface {
                id: WAN,
                mac: SOURCE_MAC,
                mtu: 1500,
            },
        ];
        let neighbors = [Neighbor {
            interface: LAN,
            target: host,
            mac: MacAddress([2, 0, 0, 0, 0, 0x10]),
        }];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: Ipv4Address::from_octets([198, 51, 100, 1]),
            },
            LocalIpv4Binding {
                interface: WAN,
                address: SOURCE_IP,
            },
        ];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let policy = ResolutionPolicy::with_retry(1_000, 1_000, 1).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        assert_eq!(
            runtime.schedule(action(5), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
        commit_front_accepted(&mut runtime, 0);
        let mut quote = [0_u8; 68];
        quote[0] = 0x4f;
        assert!(matches!(
            runtime.capture_failure_candidate(
                WAN,
                target(5),
                host,
                target(5),
                SOURCE_MAC,
                SOURCE_IP,
                Ipv4Address::from_octets([192, 0, 2, 0]),
                24,
                0,
                &quote,
            ),
            ResolutionFailureCapture::Captured(_)
        ));
        poll_resolution_timers(
            &mut runtime,
            MonotonicMillis(1_000),
            usize::MAX,
            &mut NoResolutionTimerTrace,
        )
        .unwrap();
        let mut icmp_states = [crate::Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut icmp_actions = [crate::Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut icmpv4_errors = Icmpv4ErrorRuntime::new(
            crate::Icmpv4ErrorPolicy::default(),
            &mut icmp_states,
            &mut icmp_actions,
        );
        let report = dispatch_host_unreachable_failures(
            &mut runtime,
            &mut icmpv4_errors,
            &snapshot,
            MonotonicMillis(1_000),
            usize::MAX,
            &mut NoResolutionFailureTrace,
        )
        .unwrap();
        assert_eq!(
            (
                report.scanned,
                report.retired,
                report.retained,
                report.pending
            ),
            (1, 1, 0, 0)
        );
        assert_eq!(runtime.failure_counters().quote_below_minimum, 1);
        assert_eq!(runtime.failure_counters().retained_transient, 0);
        assert_eq!(icmpv4_errors.counters().quote_below_minimum, 1);
        assert_eq!(icmpv4_errors.pending_actions(), 0);
        assert_pending_accounting(&runtime);
        let again = dispatch_host_unreachable_failures(
            &mut runtime,
            &mut icmpv4_errors,
            &snapshot,
            MonotonicMillis(2_000),
            usize::MAX,
            &mut NoResolutionFailureTrace,
        )
        .unwrap();
        assert_eq!((again.retired, again.retained, again.pending), (0, 0, 0));
        assert_eq!(icmpv4_errors.counters().quote_below_minimum, 1);
    }

    #[test]
    fn pending_failure_accounting_survives_capacity_regression_dispatch_wrap_and_expiry() {
        let policy = ResolutionPolicy::with_retry(1_000, 1_000, 1).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 3];
        let mut actions = [ResolutionActionSlot::EMPTY; 3];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 2];
        let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            policy,
            &mut states,
            &mut actions,
            &mut [],
            &mut holds,
        );
        for last in [2, 3, 4] {
            assert_eq!(
                runtime.schedule(action(last), MonotonicMillis(0), false),
                ResolutionResult::Queued
            );
            commit_front_accepted(&mut runtime, 0);
            let capture = runtime.capture_failure_candidate(
                WAN,
                target(last),
                target(100 + last),
                target(last),
                SOURCE_MAC,
                SOURCE_IP,
                Ipv4Address::from_octets([192, 0, 2, 0]),
                24,
                0,
                &[0x45; 28],
            );
            if last == 4 {
                assert_eq!(capture, ResolutionFailureCapture::CapacityFull);
            } else {
                assert!(matches!(capture, ResolutionFailureCapture::Captured(_)));
            }
            assert_pending_accounting(&runtime);
        }
        assert_eq!(
            (runtime.pending_states(), runtime.pending_failure_holds()),
            (3, 2)
        );

        let timed_out = poll_resolution_timers(
            &mut runtime,
            MonotonicMillis(1_000),
            usize::MAX,
            &mut NoResolutionTimerTrace,
        )
        .unwrap();
        assert_eq!((timed_out.timed_out, timed_out.pending), (3, 3));
        assert_pending_accounting(&runtime);
        assert_eq!(runtime.pending_failure_holds(), 2);

        let snapshot = ForwardingSnapshot::new(&[], &[], &[], &[]).unwrap();
        let mut icmp_states = [crate::Icmpv4ErrorStateSlot::EMPTY; 1];
        let mut icmp_actions = [crate::Icmpv4ErrorActionSlot::EMPTY; 1];
        let mut icmpv4_errors = Icmpv4ErrorRuntime::new(
            crate::Icmpv4ErrorPolicy::default(),
            &mut icmp_states,
            &mut icmp_actions,
        );
        assert_eq!(
            dispatch_host_unreachable_failures(
                &mut runtime,
                &mut icmpv4_errors,
                &snapshot,
                MonotonicMillis(999),
                usize::MAX,
                &mut NoResolutionFailureTrace
            ),
            Err(ResolutionFailureDispatchError::ClockRegression)
        );
        assert_pending_accounting(&runtime);

        for expected_pending in [1, 0] {
            let report = dispatch_host_unreachable_failures(
                &mut runtime,
                &mut icmpv4_errors,
                &snapshot,
                MonotonicMillis(1_000),
                1,
                &mut NoResolutionFailureTrace,
            )
            .unwrap();
            assert_eq!(
                (report.scanned, report.retired, report.pending),
                (1, 1, expected_pending)
            );
            assert_pending_accounting(&runtime);
        }
        let wrapped = dispatch_host_unreachable_failures(
            &mut runtime,
            &mut icmpv4_errors,
            &snapshot,
            MonotonicMillis(1_000),
            1,
            &mut NoResolutionFailureTrace,
        )
        .unwrap();
        assert_eq!((wrapped.scanned, wrapped.pending), (1, 0));
        assert_pending_accounting(&runtime);

        let expired = poll_resolution_timers(
            &mut runtime,
            MonotonicMillis(2_000),
            usize::MAX,
            &mut NoResolutionTimerTrace,
        )
        .unwrap();
        assert_eq!((expired.failures_expired, expired.pending), (3, 0));
        assert_pending_accounting(&runtime);
    }

    #[test]
    fn generation_wrap_skips_live_failure_token_and_recreation_zeroes_quote() {
        let policy = ResolutionPolicy::new(1_000, 2_000).unwrap();
        let mut states = [ResolutionStateSlot::EMPTY; 1];
        let mut actions = [ResolutionActionSlot::EMPTY; 1];
        let mut holds = [ResolutionFailureHoldSlot::EMPTY; 1];
        {
            let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
                policy,
                &mut states,
                &mut actions,
                &mut [],
                &mut holds,
            );
            runtime.states[0].entry.generation = u64::MAX;
            runtime.install_hold_for_test(
                0,
                ResolutionFailureHoldPhase::TerminalReady,
                ResolutionGenerationToken {
                    egress: WAN,
                    target: target(2),
                    generation: 0,
                },
                ResolutionGenerationToken {
                    egress: WAN,
                    target: target(2),
                    generation: 0,
                },
            );
            runtime.failure_holds[0].quote_len = 1;
            runtime.failure_holds[0].quote[0] = 0xa5;
            assert_eq!(
                runtime.schedule(action(2), MonotonicMillis(0), false),
                ResolutionResult::Queued
            );
            assert_eq!(runtime.status(WAN, target(2)).unwrap().generation, 1);
        }
        {
            let runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
                policy,
                &mut states,
                &mut actions,
                &mut [],
                &mut holds,
            );
            assert_eq!(runtime.pending_failure_holds(), 0);
        }
        assert_eq!(holds[0].quote_len, 0);
        assert!(holds[0].quote.iter().all(|byte| *byte == 0));
    }
}
