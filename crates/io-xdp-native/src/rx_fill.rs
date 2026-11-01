//! RX/Fill half of the AF_XDP datapath engine (M2 S3, X01).
//!
//! One worker owns one [`RxFillEngine`]: the Fill producer, the RX
//! consumer, the TX producer, the Completion consumer, the socket's kick
//! handle, the UMEM, and the authoritative frame ledger. The TX/Completion
//! half (M2 S4, X02) lives in the `tx_completion` child module and shares
//! this one ledger. Nothing here
//! locks, allocates after construction, clones packets, or formats a
//! string. The engine is generic over ring memory only through the
//! [`DatapathRings`] bundle it consumes: a live [`crate::NativeSession`]
//! lends it once over the kernel mappings, and tests lend it once over heap
//! memory. Taking the whole bundle once is what makes the ledger the only
//! record of Fill publications for this UMEM.
//!
//! Frame ownership follows the [`FrameLedger`]: a free RX-pool frame is
//! reserved and published to Fill (`FillOwnedByKernel`); the kernel returns
//! it on an RX descriptor, which is validated before anything else looks at
//! it (`RxAvailable`); the engine lends it to the caller as an [`RxFrame`]
//! (`Leased`), which ends by recycling it to the free list (`Free`, next
//! refill republishes it) or by handing it to TX (`PendingTx`, see
//! [`TxHandoff`]). An invalid descriptor never reaches the caller.
//!
//! The generated pool (`rx_frames..frame_count`, M2 S5, X03) lives in the
//! `generated` child module on the same ledger: a free generated frame is
//! leased directly (`Free` → `Leased`, never published to Fill), lent as a
//! [`GeneratedFrame`] of exactly the requested visible length, and either
//! cancelled or abandoned back to the generated free list or staged into
//! the same TX path as forwarded frames. Every frame that becomes `Free`
//! returns to the free list of its own pool, decided by its frame index
//! alone, so Fill never sees a generated frame and generation never takes
//! an RX frame.

#[path = "generated.rs"]
mod generated;
#[path = "tx_completion.rs"]
mod tx_completion;

use std::{fmt, num::NonZeroU32};

use generated::GeneratedPool;
pub(crate) use generated::ZeroFill;
pub use generated::{
    GeneratedAccounting, GeneratedAllocError, GeneratedCounters, GeneratedFrame,
    GeneratedRejectReason,
};
use tx_completion::InflightFifo;
pub use tx_completion::{
    CompletionInvalidReason, CompletionLag, CompletionReport, DrainOutcome, DrainReport,
    FrameAccounting, TxBlocked, TxCounters, TxRejected, TxRejection, TxSubmitError, TxSubmitReport,
};

use ruster_io_xdp::{
    AuditError, FrameId, FrameLedger, FrameStateKind, FrameToken, LayoutError, LedgerError,
    RawDescriptor, UmemDomainId, UmemLayout, ValidatedDescriptor,
};

use crate::{
    abi::XdpDescriptor,
    datapath::{DatapathParts, DatapathRings},
    native_unsafe::{
        kick::SocketKick,
        umem::{UmemFrames, UmemPairingError},
    },
    CompletionConsumer, FillProducer, NativeRingError, NeedWakeup, RxConsumer, TxProducer,
    XDP_PACKET_HEADROOM,
};

/// Smallest accepted RX length: one Ethernet II header.
///
/// Software devices such as veth deliver frames without link padding (an
/// ARP request arrives as 42 bytes), so the 60-byte padded minimum is not
/// required. Core validates every protocol header after this check.
pub const ETHERNET_HEADER_LEN: u32 = 14;

/// Why an RX descriptor was refused before reaching the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxInvalidReason {
    /// The address lies outside the registered UMEM. Nothing is mutated.
    AddressOutsideUmem,
    /// The addressed frame is not currently published to the kernel through
    /// Fill: a duplicate, a generated-pool frame, or a frame already owned
    /// by user space or TX. Nothing is mutated.
    NotKernelOwned,
    /// Option bits other than zero (for example `XDP_PKT_CONTD`). The
    /// kernel-owned frame is quarantined.
    UnsupportedOptions,
    /// The packet starts inside the configured plus kernel headroom. The
    /// kernel-owned frame is quarantined.
    DataBeforeHeadroom,
    /// Shorter than [`ETHERNET_HEADER_LEN`], including zero. The kernel
    /// returned the frame correctly (address, headroom, and chunk bound in
    /// profile) with an unusable packet, so the frame is recycled, not
    /// quarantined.
    ShorterThanEthernetHeader,
    /// The visible range ends beyond the frame (chunk), whatever its
    /// length. Checked before the runt check, so out-of-profile geometry is
    /// always quarantined. The kernel-owned frame is quarantined.
    ExceedsFrame,
}

impl RxInvalidReason {
    /// Number of reasons.
    pub const COUNT: usize = 6;

    /// Every reason in declaration order; `ALL[reason.index()] == reason`.
    pub const ALL: [Self; Self::COUNT] = [
        Self::AddressOutsideUmem,
        Self::NotKernelOwned,
        Self::UnsupportedOptions,
        Self::DataBeforeHeadroom,
        Self::ShorterThanEthernetHeader,
        Self::ExceedsFrame,
    ];

    /// Dense index into [`Self::ALL`].
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::AddressOutsideUmem => 0,
            Self::NotKernelOwned => 1,
            Self::UnsupportedOptions => 2,
            Self::DataBeforeHeadroom => 3,
            Self::ShorterThanEthernetHeader => 4,
            Self::ExceedsFrame => 5,
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AddressOutsideUmem => "ADDRESS_OUTSIDE_UMEM",
            Self::NotKernelOwned => "NOT_KERNEL_OWNED",
            Self::UnsupportedOptions => "UNSUPPORTED_OPTIONS",
            Self::DataBeforeHeadroom => "DATA_BEFORE_HEADROOM",
            Self::ShorterThanEthernetHeader => "SHORTER_THAN_ETHERNET_HEADER",
            Self::ExceedsFrame => "EXCEEDS_FRAME",
        }
    }
}

/// Saturating, allocation-free RX/Fill counters (OBS-018, RX/Fill half).
///
/// Every field only grows. A poll updates a handful of integers and never
/// scans the ledger.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct RxFillCounters {
    /// Calls to [`RxFillEngine::poll`].
    pub polls: u64,
    /// RX descriptors that passed validation.
    pub rx_packets: u64,
    /// Valid frames lent to the caller.
    pub rx_leased: u64,
    /// Lent frames recycled explicitly.
    pub rx_recycled: u64,
    /// Lent frames dropped without an explicit completion (recycled).
    pub rx_abandoned: u64,
    /// Lent frames handed to TX.
    pub rx_tx_handoffs: u64,
    /// TX handoffs cancelled back to the free list.
    pub tx_handoffs_cancelled: u64,
    /// Refills that published nothing because a drain started.
    pub fill_suppressed_draining: u64,
    /// Polls that wanted RX descriptors, had none pending, and found the RX
    /// ring empty.
    pub rx_ring_empty: u64,
    /// Polls that left RX descriptors in the ring because the budget (or
    /// the pending capacity) was smaller than what the kernel produced.
    pub rx_backlogged: u64,
    /// Frames published to the Fill ring.
    pub fill_published: u64,
    /// Refills that found the Fill ring with room and the free list empty.
    pub fill_starved: u64,
    /// Refills that found free frames and a full Fill ring.
    pub fill_ring_full: u64,
    /// Refills that observed the kernel requesting a Fill wakeup.
    pub fill_need_wakeup: u64,
    /// Refills whose Fill flags word had unknown bits.
    pub fill_flag_errors: u64,
    /// Frames permanently removed from reuse (out-of-profile kernel return
    /// on RX or Completion, or generation exhaustion) in either pool: the
    /// RX pool and the generated pool both count here, and
    /// [`GeneratedAccounting::quarantined`] is the generated share. This,
    /// not starvation, is where pool shrinkage is observed.
    pub frames_quarantined: u64,
    /// Runt frames (shorter than an Ethernet header) recycled to the pool.
    pub rx_runts_recycled: u64,
    rx_invalid: [u64; RxInvalidReason::COUNT],
}

impl RxFillCounters {
    /// Refused RX descriptors of one reason.
    #[must_use]
    pub const fn rx_invalid(&self, reason: RxInvalidReason) -> u64 {
        self.rx_invalid[reason.index()]
    }

    /// Refused RX descriptors of every reason.
    #[must_use]
    pub fn rx_invalid_total(&self) -> u64 {
        self.rx_invalid
            .iter()
            .fold(0_u64, |total, value| total.saturating_add(*value))
    }
}

pub(super) fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

pub(super) fn add(counter: &mut u64, value: u32) {
    *counter = counter.saturating_add(u64::from(value));
}

/// Source of process-unique engine identities (cold path: one increment
/// per engine construction, never on the datapath).
static NEXT_ENGINE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_engine_id() -> u64 {
    let id = NEXT_ENGINE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    assert_ne!(id, 0, "engine identities exhausted");
    id
}

/// Checked engine parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RxFillConfig {
    fill_batch: NonZeroU32,
}

impl RxFillConfig {
    /// `fill_batch` bounds the frames published to Fill by one refill. It
    /// must not exceed the Fill ring capacity.
    #[must_use]
    pub const fn new(fill_batch: NonZeroU32) -> Self {
        Self { fill_batch }
    }

    /// Returns the per-refill publication bound.
    #[must_use]
    pub const fn fill_batch(self) -> NonZeroU32 {
        self.fill_batch
    }
}

/// Engine construction failure. Nothing was published to any ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxFillSetupError {
    /// The UMEM geometry could not form a ledger layout.
    Layout(LayoutError),
    /// The ledger could not be created.
    Ledger(LedgerError),
    /// The UMEM borrow is shorter than its configured geometry.
    UmemTooShort,
    /// `fill_batch` exceeds the Fill ring capacity.
    FillBatchExceedsRing {
        /// Requested bound.
        fill_batch: u32,
        /// Fill ring capacity.
        capacity: u32,
    },
    /// The Fill ring already holds entries that no ledger tracks.
    FillRingNotEmpty,
    /// The RX ring already holds descriptors that no ledger tracks.
    RxRingNotEmpty,
    /// The TX ring already holds descriptors that no ledger tracks.
    TxRingNotEmpty,
    /// The Completion ring already holds entries that no ledger tracks.
    CompletionRingNotEmpty,
    /// The Completion ring is smaller than the TX ring, so in-flight TX
    /// (bounded by the TX capacity) could outgrow the completion slots.
    CompletionSmallerThanTx {
        /// TX ring capacity.
        tx: u32,
        /// Completion ring capacity.
        completion: u32,
    },
    /// A ring cursor was corrupt, or the initial refill failed.
    Ring(NativeRingError),
}

impl fmt::Display for RxFillSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RxFillSetupError {}

/// Datapath failure. Ledger and rings are unchanged by the failing step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxFillError {
    /// A kernel-shared ring cursor was corrupt (producer and consumer more
    /// than one capacity apart), or a ring operation was refused.
    Ring(NativeRingError),
    /// A ledger transition was refused (for example a foreign or stale
    /// [`TxHandoff`]).
    Ledger(LedgerError),
}

impl fmt::Display for RxFillError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RxFillError {}

/// Cold-audit failure of [`RxFillEngine::audit`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxFillAuditError {
    /// The ledger's own full scan failed.
    Ledger(AuditError),
    /// A free-list entry is outside the RX pool, duplicated, or not `Free`.
    FreeListEntry {
        /// Offending frame index.
        frame: u32,
    },
    /// The free list does not hold exactly the `Free` RX-pool frames.
    FreeListCount {
        /// Entries in the free list.
        listed: u32,
        /// `Free` frames in the RX pool.
        free: u32,
    },
    /// A pending-RX entry is duplicated or not `RxAvailable`.
    PendingEntry {
        /// Offending frame index.
        frame: u32,
    },
    /// The pending-RX list does not hold exactly the `RxAvailable` frames.
    PendingCount {
        /// Entries in the pending list.
        listed: u32,
        /// `RxAvailable` frames in the ledger.
        available: u32,
    },
    /// A frame is in a state this engine never leaves at rest.
    UnexpectedState {
        /// Offending frame index.
        frame: u32,
        /// Observed state.
        state: FrameStateKind,
    },
    /// An in-flight entry is duplicated, listed in another engine list, or
    /// not the exact `TxOwnedByKernel` owner of its frame.
    InflightEntry {
        /// Offending frame index.
        frame: u32,
    },
    /// The in-flight list does not hold exactly the `TxOwnedByKernel`
    /// frames, or the in-flight gauge disagrees with it.
    InflightCount {
        /// Entries in the in-flight list.
        listed: u32,
        /// `TxOwnedByKernel` frames in the ledger.
        in_flight: u32,
    },
    /// In-flight TX exceeds the TX ring capacity (BACKEND-004).
    InflightExceedsLimit {
        /// Frames in flight.
        in_flight: u32,
        /// TX ring capacity.
        limit: u32,
    },
    /// The owner partition of the RX pool does not sum to the pool size.
    Accounting {
        /// Sum over all owners.
        accounted: u32,
        /// RX pool size.
        rx_frames: u32,
    },
    /// A generated free-list entry is outside the generated pool,
    /// duplicated, or not `Free`.
    GeneratedFreeListEntry {
        /// Offending frame index.
        frame: u32,
    },
    /// The engine's record of one generated-pool state disagrees with a
    /// full scan of the generated pool (free list length for `Free`,
    /// outstanding generated handoffs for `PendingTx`, the
    /// `generated_inflight` gauge for `TxOwnedByKernel`, generated
    /// quarantine for `Quarantined`, zero for every other state).
    GeneratedCount {
        /// Generated-pool state whose count disagrees.
        state: FrameStateKind,
        /// What the engine records.
        recorded: u32,
        /// What the scan found.
        actual: u32,
    },
    /// The owner partition of the generated pool does not sum to its size.
    GeneratedAccounting {
        /// Sum over all owners.
        accounted: u32,
        /// Generated pool size.
        generated_frames: u32,
    },
}

/// Fill outcome of one refill.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct RefillReport {
    published: u32,
    starved: bool,
    need_wakeup: Result<NeedWakeup, NativeRingError>,
}

impl RefillReport {
    /// Frames published to Fill.
    #[must_use]
    pub const fn published(self) -> u32 {
        self.published
    }

    /// Whether the free list was empty while Fill had room.
    #[must_use]
    pub const fn starved(self) -> bool {
        self.starved
    }

    /// The Fill need-wakeup flag observed at the end of this refill (after
    /// the Release publication, if one happened), also when nothing was
    /// published. The kick itself (poll/recvfrom on the socket) belongs to
    /// the caller.
    pub const fn need_wakeup(self) -> Result<NeedWakeup, NativeRingError> {
        self.need_wakeup
    }
}

/// Fixed-capacity FIFO of free frame indices of one pool.
struct IndexFifo {
    slots: Box<[u32]>,
    head: usize,
    len: usize,
}

impl IndexFifo {
    fn full(count: u32) -> Self {
        Self::range(0, count)
    }

    /// Holds every index of `start..end` (cold: one allocation).
    fn range(start: u32, end: u32) -> Self {
        Self {
            slots: (start..end).collect(),
            head: 0,
            len: end.saturating_sub(start) as usize,
        }
    }

    const fn len(&self) -> usize {
        self.len
    }

    fn pop(&mut self) -> Option<u32> {
        if self.len == 0 {
            return None;
        }
        let value = self.slots[self.head];
        self.head = (self.head + 1) % self.slots.len();
        self.len -= 1;
        Some(value)
    }

    /// Returns `false` (and drops the index) only if the FIFO is full,
    /// which the ledger's exactly-once `Free` transition rules out.
    fn push(&mut self, value: u32) -> bool {
        if self.len == self.slots.len() {
            return false;
        }
        let tail = (self.head + self.len) % self.slots.len();
        self.slots[tail] = value;
        self.len += 1;
        true
    }

    fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.len).map(|offset| self.slots[(self.head + offset) % self.slots.len()])
    }
}

/// Fixed-capacity FIFO of validated, not yet lent RX tokens.
struct TokenFifo {
    slots: Box<[Option<FrameToken>]>,
    head: usize,
    len: usize,
}

impl TokenFifo {
    fn new(capacity: u32) -> Self {
        Self {
            slots: vec![None; capacity as usize].into_boxed_slice(),
            head: 0,
            len: 0,
        }
    }

    const fn len(&self) -> usize {
        self.len
    }

    fn free(&self) -> usize {
        self.slots.len() - self.len
    }

    fn pop(&mut self) -> Option<FrameToken> {
        if self.len == 0 {
            return None;
        }
        let value = self.slots[self.head].take();
        self.head = (self.head + 1) % self.slots.len();
        self.len -= 1;
        value
    }

    fn push(&mut self, token: FrameToken) -> bool {
        if self.len == self.slots.len() {
            return false;
        }
        let tail = (self.head + self.len) % self.slots.len();
        self.slots[tail] = Some(token);
        self.len += 1;
        true
    }

    fn iter(&self) -> impl Iterator<Item = FrameToken> + '_ {
        (0..self.len).filter_map(|offset| self.slots[(self.head + offset) % self.slots.len()])
    }
}

/// Everything except the two ring views, so ring borrows and state updates
/// can coexist inside one operation.
struct EngineState<'memory> {
    /// Process-unique identity stamped into every `TxHandoff`.
    engine_id: u64,
    frames: UmemFrames<'memory>,
    /// Free RX-pool frames (`0..rx_frames`), the only source of Fill.
    free: IndexFifo,
    /// Free generated-pool frames (`rx_frames..frame_count`), the only
    /// source of generated allocation.
    generated_free: IndexFifo,
    /// Generated-pool owners other than the free list and the in-flight
    /// gauge (which is `generated_counters.generated_inflight`).
    generated: GeneratedPool,
    generated_counters: GeneratedCounters,
    pending: TokenFifo,
    scratch: Box<[Option<FrameToken>]>,
    counters: RxFillCounters,
    /// Published, not yet completed TX frames, in submission order.
    inflight: InflightFifo,
    tx_counters: TxCounters,
    /// Set by `drain`: no new TX or Fill publication, ever again.
    draining: bool,
    fill_batch: u32,
    rx_frames: u32,
    frame_size: u64,
    headroom: u64,
    umem_len: u64,
}

/// What happens to the frame of a refused descriptor.
#[derive(Clone, Copy)]
enum Refusal {
    /// The kernel did not return a frame this engine owns: touch nothing.
    Untouched,
    /// Out-of-profile kernel return: remove the frame from reuse.
    Quarantine(FrameToken),
    /// Correct kernel return with an unusable packet: recycle the frame.
    Recycle(FrameToken),
}

type Classified = Result<(FrameToken, ValidatedDescriptor), (RxInvalidReason, Refusal)>;

impl EngineState<'_> {
    /// Validates one kernel RX descriptor against the profile and ledger.
    ///
    /// On failure the [`Refusal`] says what happens to the frame.
    fn classify(&self, raw: XdpDescriptor) -> Classified {
        if raw.address >= self.umem_len {
            return Err((RxInvalidReason::AddressOutsideUmem, Refusal::Untouched));
        }
        let frame_base = raw.address & !(self.frame_size - 1);
        let Ok(index) = u32::try_from(raw.address / self.frame_size) else {
            return Err((RxInvalidReason::AddressOutsideUmem, Refusal::Untouched));
        };
        let ledger = self.frames.ledger();
        let Ok(state) = ledger.state(index) else {
            return Err((RxInvalidReason::AddressOutsideUmem, Refusal::Untouched));
        };
        let (FrameStateKind::FillOwnedByKernel, Some(token)) = (state.kind(), state.token()) else {
            return Err((RxInvalidReason::NotKernelOwned, Refusal::Untouched));
        };
        let quarantine = |reason| Err((reason, Refusal::Quarantine(token)));
        if raw.options != 0 {
            return quarantine(RxInvalidReason::UnsupportedOptions);
        }
        let offset = raw.address - frame_base;
        if offset < self.headroom {
            return quarantine(RxInvalidReason::DataBeforeHeadroom);
        }
        // Chunk overflow before the runt check: an out-of-profile range is
        // quarantined even when it is also short.
        if offset + u64::from(raw.len) > self.frame_size {
            return quarantine(RxInvalidReason::ExceedsFrame);
        }
        if raw.len < ETHERNET_HEADER_LEN {
            return Err((
                RxInvalidReason::ShorterThanEthernetHeader,
                Refusal::Recycle(token),
            ));
        }
        match ledger.layout().validate_descriptor(RawDescriptor {
            addr: raw.address,
            len: raw.len,
            options: raw.options,
        }) {
            Ok(descriptor) => Ok((token, descriptor)),
            // The checks above are a superset of the layout's; keep the
            // layout as a second, independent gate.
            Err(_) => quarantine(RxInvalidReason::ExceedsFrame),
        }
    }

    fn accept(&mut self, raw: XdpDescriptor) {
        match self.classify(raw) {
            Ok((token, descriptor)) => {
                self.frames
                    .ledger_mut()
                    .receive(token, descriptor)
                    .expect("classification proved FillOwnedByKernel and frame identity");
                let pushed = self.pending.push(token);
                debug_assert!(pushed, "acquisition is bounded by pending capacity");
                bump(&mut self.counters.rx_packets);
            }
            Err((reason, refusal)) => {
                bump(&mut self.counters.rx_invalid[reason.index()]);
                match refusal {
                    Refusal::Untouched => {}
                    Refusal::Quarantine(token) => {
                        self.frames
                            .ledger_mut()
                            .quarantine_kernel_fill(token)
                            .expect("classification proved FillOwnedByKernel");
                        bump(&mut self.counters.frames_quarantined);
                    }
                    Refusal::Recycle(token) => {
                        self.frames
                            .ledger_mut()
                            .release_kernel_fill(token)
                            .expect("classification proved FillOwnedByKernel");
                        self.push_free(token.frame().index());
                        bump(&mut self.counters.rx_runts_recycled);
                    }
                }
            }
        }
    }

    /// Whether `frame` belongs to the generated pool (`rx_frames..`).
    const fn is_generated(&self, frame: u32) -> bool {
        frame >= self.rx_frames
    }

    /// Lists a frame that just became `Free` in the free list of its own
    /// pool, chosen by frame index alone.
    fn push_free(&mut self, frame: u32) {
        let pushed = if self.is_generated(frame) {
            self.generated_free.push(frame)
        } else {
            self.free.push(frame)
        };
        debug_assert!(pushed, "each Free transition enters the free list once");
    }

    /// Ends a `Leased` cycle (either pool) and frees the frame to its pool.
    fn recycle(&mut self, token: FrameToken) {
        self.frames
            .ledger_mut()
            .recycle_lease(token)
            .expect("only a live lease recycles, and it is Leased");
        self.push_free(token.frame().index());
    }

    fn rollback_reserved(&mut self, reserved: usize) {
        for slot in 0..reserved {
            if let Some(token) = self.scratch[slot].take() {
                self.frames
                    .ledger_mut()
                    .cancel_fill(token)
                    .expect("scratch holds FillReserved tokens");
                self.push_free(token.frame().index());
            }
        }
    }
}

/// RX/Fill engine of one AF_XDP socket.
///
/// `'memory` is the borrow of the ring and UMEM memory, either a live
/// session's mappings or caller-owned heap memory.
///
/// The engine is `!Send` and `!Sync` because the ledger is worker-local:
///
/// ```compile_fail,E0277
/// fn send<T: Send>() {}
/// send::<ruster_io_xdp_native::RxFillEngine<'static>>();
/// ```
pub struct RxFillEngine<'memory> {
    fill: FillProducer<'memory>,
    rx: RxConsumer<'memory>,
    /// Owned by the engine alone: no one else can submit a TX descriptor
    /// naming a frame of this ledger.
    tx: TxProducer<'memory>,
    completion: CompletionConsumer<'memory>,
    kick: SocketKick<'memory>,
    /// Identity of the session (or test kernel) the bundle came from.
    origin: u64,
    state: EngineState<'memory>,
    initial_refill: RefillReport,
}

impl<'memory> RxFillEngine<'memory> {
    /// Consumes the session's datapath bundle, creates the ledger for
    /// `domain`, and performs the first bounded refill (see
    /// [`Self::initial_refill`]).
    ///
    /// Frames `0..rx_frames` form the RX pool, the only frames published to
    /// Fill. The generated pool `rx_frames..frame_count` is never published
    /// to Fill; it is lent only by [`Self::allocate_generated`].
    /// All four rings must be empty, a defensive check on top of the
    /// once-per-session bundle, and the Completion ring must be at least as
    /// large as the TX ring, which bounds in-flight TX.
    pub fn new(
        datapath: DatapathRings<'memory>,
        domain: UmemDomainId,
        config: RxFillConfig,
    ) -> Result<Self, RxFillSetupError> {
        let DatapathParts {
            fill,
            completion,
            rx,
            tx,
            umem,
            umem_config: geometry,
            kick,
            origin,
        } = datapath.into_parts();
        let fill_batch = config.fill_batch().get();
        if fill_batch > fill.capacity() {
            return Err(RxFillSetupError::FillBatchExceedsRing {
                fill_batch,
                capacity: fill.capacity(),
            });
        }
        if fill.free_slots().map_err(RxFillSetupError::Ring)? != fill.capacity() {
            return Err(RxFillSetupError::FillRingNotEmpty);
        }
        if rx.available().map_err(RxFillSetupError::Ring)? != 0 {
            return Err(RxFillSetupError::RxRingNotEmpty);
        }
        if completion.capacity() < tx.capacity() {
            return Err(RxFillSetupError::CompletionSmallerThanTx {
                tx: tx.capacity(),
                completion: completion.capacity(),
            });
        }
        if tx.free_slots().map_err(RxFillSetupError::Ring)? != tx.capacity() {
            return Err(RxFillSetupError::TxRingNotEmpty);
        }
        if completion.available().map_err(RxFillSetupError::Ring)? != 0 {
            return Err(RxFillSetupError::CompletionRingNotEmpty);
        }
        let headroom = geometry.headroom() + XDP_PACKET_HEADROOM;
        let layout = UmemLayout::new(
            domain,
            geometry.frame_count(),
            geometry.frame_size(),
            headroom,
        )
        .map_err(RxFillSetupError::Layout)?;
        let ledger = FrameLedger::new(layout).map_err(RxFillSetupError::Ledger)?;
        let frames = UmemFrames::new(umem, ledger).map_err(|error| match error {
            UmemPairingError::MappingTooShort => RxFillSetupError::UmemTooShort,
            UmemPairingError::LedgerNotFresh => {
                unreachable!("a newly created ledger is fresh")
            }
        })?;
        let state = EngineState {
            engine_id: next_engine_id(),
            frames,
            free: IndexFifo::full(geometry.rx_frames()),
            generated_free: IndexFifo::range(geometry.rx_frames(), geometry.frame_count()),
            generated: GeneratedPool::default(),
            generated_counters: GeneratedCounters::default(),
            pending: TokenFifo::new(rx.capacity()),
            scratch: vec![None; fill.capacity() as usize].into_boxed_slice(),
            counters: RxFillCounters::default(),
            inflight: InflightFifo::new(tx.capacity()),
            tx_counters: TxCounters::default(),
            draining: false,
            fill_batch,
            rx_frames: geometry.rx_frames(),
            frame_size: u64::from(geometry.frame_size()),
            headroom: u64::from(headroom),
            umem_len: geometry.byte_len(),
        };
        let mut engine = Self {
            fill,
            rx,
            tx,
            completion,
            kick,
            origin,
            state,
            initial_refill: RefillReport {
                published: 0,
                starved: false,
                need_wakeup: Ok(NeedWakeup::NotRequired),
            },
        };
        engine.initial_refill = engine.refill().map_err(|error| match error {
            RxFillError::Ring(error) => RxFillSetupError::Ring(error),
            RxFillError::Ledger(error) => RxFillSetupError::Ledger(error),
        })?;
        Ok(engine)
    }

    /// The refill performed by [`Self::new`], including its need-wakeup
    /// observation: in zero-copy mode the first kick may be due at once.
    pub const fn initial_refill(&self) -> RefillReport {
        self.initial_refill
    }

    /// Acquire-loads the Fill need-wakeup flag without publishing (one
    /// atomic load), for the libxdp pattern of kicking whenever the kernel
    /// asks, also while the free list is empty or Fill is full.
    pub fn fill_needs_wakeup(&self) -> Result<NeedWakeup, NativeRingError> {
        self.fill.need_wakeup()
    }

    /// Identity of the session (or test kernel) whose datapath bundle this
    /// engine consumed; the core adapter pairs it with the port config.
    pub(crate) const fn origin(&self) -> u64 {
        self.origin
    }

    /// TX descriptors published and not yet consumed by the kernel (one
    /// atomic load). A corrupt cursor reads as the full capacity.
    pub(crate) fn tx_unconsumed(&self) -> u32 {
        self.tx
            .free_slots()
            .map_or(self.tx.capacity(), |free| self.tx.capacity() - free)
    }

    /// Fill entries published and not yet taken by the kernel (one atomic
    /// load; a corrupt cursor reads as the full capacity).
    pub(crate) fn fill_occupancy(&self) -> u32 {
        self.fill
            .free_slots()
            .map_or(self.fill.capacity(), |free| self.fill.capacity() - free)
    }

    /// RX descriptors produced by the kernel and not yet consumed (one
    /// atomic load; a corrupt cursor reads as the full capacity).
    pub(crate) fn rx_occupancy(&self) -> u32 {
        self.rx.available().unwrap_or(self.rx.capacity())
    }

    /// The kernel's `XDP_STATISTICS` for this socket (one `getsockopt`,
    /// cold path only), or `None` if the kernel refused or returned another
    /// structure size than Linux v6.8's 48 bytes.
    pub(crate) fn kernel_statistics(&self) -> Option<crate::abi::XdpStatistics> {
        self.kick.statistics()
    }

    /// Frames handed to TX and neither submitted nor cancelled: the
    /// ledger's `PendingTx` count, both pools (received and generated). A
    /// `TxHandoff` dropped without either stays counted here forever.
    #[must_use]
    pub fn tx_handoffs_outstanding(&self) -> u32 {
        u32::try_from(
            self.state
                .frames
                .ledger()
                .counts()
                .get(FrameStateKind::PendingTx),
        )
        .expect("bounded by the u32 frame count")
    }

    /// Publishes up to `fill_batch` free RX-pool frames to Fill, bounded by
    /// the ring's room.
    ///
    /// An empty free list with room in Fill is counted as starvation and
    /// returns immediately; it never blocks other work. After
    /// [`Self::drain`] nothing is published.
    pub fn refill(&mut self) -> Result<RefillReport, RxFillError> {
        let (published, starved) = self.publish_fill()?;
        let need_wakeup = self.fill.need_wakeup();
        let counters = &mut self.state.counters;
        match need_wakeup {
            Ok(NeedWakeup::Required) => bump(&mut counters.fill_need_wakeup),
            Ok(NeedWakeup::NotRequired) => {}
            Err(_) => bump(&mut counters.fill_flag_errors),
        }
        Ok(RefillReport {
            published,
            starved,
            need_wakeup,
        })
    }

    /// Returns `(published, starved)`.
    fn publish_fill(&mut self) -> Result<(u32, bool), RxFillError> {
        if self.state.draining {
            bump(&mut self.state.counters.fill_suppressed_draining);
            return Ok((0, false));
        }
        let room = self.fill.free_slots().map_err(RxFillError::Ring)?;
        let state = &mut self.state;
        if room == 0 {
            if state.free.len() > 0 {
                bump(&mut state.counters.fill_ring_full);
            }
            return Ok((0, false));
        }
        let target = (room as usize).min(state.fill_batch as usize);
        let mut reserved = 0;
        while reserved < target {
            let Some(index) = state.free.pop() else {
                break;
            };
            match state.frames.ledger_mut().reserve_fill(index) {
                Ok(token) => {
                    state.scratch[reserved] = Some(token);
                    reserved += 1;
                }
                Err(LedgerError::GenerationExhausted { .. }) => {
                    // The ledger quarantined the frame; it leaves the pool.
                    bump(&mut state.counters.frames_quarantined);
                }
                Err(error) => {
                    state.rollback_reserved(reserved);
                    return Err(RxFillError::Ledger(error));
                }
            }
        }
        if reserved == 0 {
            bump(&mut state.counters.fill_starved);
            return Ok((0, true));
        }
        let count = u32::try_from(reserved).expect("bounded by the u32 ring room");
        let mut reservation = match self.fill.reserve(count) {
            Ok(reservation) => reservation,
            Err(error) => {
                state.rollback_reserved(reserved);
                return Err(RxFillError::Ring(error));
            }
        };
        for slot in &state.scratch[..reserved] {
            let token = slot.expect("reserved prefix");
            let address = u64::from(token.frame().index()) * state.frame_size;
            if let Err(error) = reservation.write(address) {
                reservation.release_cancel();
                state.rollback_reserved(reserved);
                return Err(RxFillError::Ring(error));
            }
        }
        // The publication's own flag observation is superseded by the one
        // `refill` takes after this returns.
        if let Err(error) = reservation.release_submit() {
            state.rollback_reserved(reserved);
            return Err(RxFillError::Ring(error));
        }
        for slot in &mut state.scratch[..reserved] {
            let token = slot.take().expect("reserved prefix");
            state
                .frames
                .ledger_mut()
                .publish_fill(token)
                .expect("scratch holds FillReserved tokens");
        }
        add(&mut state.counters.fill_published, count);
        Ok((count, false))
    }

    /// Reaps completions, refills Fill, then consumes at most `budget` RX
    /// descriptors and returns a batch that lends at most `budget` valid
    /// frames.
    ///
    /// The reap comes first and is bounded by the TX capacity (the most
    /// frames that can be in flight), so completed TX frames are back in
    /// the free list before this refill (BACKEND-004). Valid frames left
    /// unlent when the batch drops stay pending and are lent by the next
    /// poll before any new descriptor is consumed, so one poll never does
    /// more than `budget` RX descriptor work. A zero budget reaps and
    /// refills only and never observes the RX ring.
    pub fn poll(&mut self, budget: u32) -> Result<RxBatch<'_, 'memory>, RxFillError> {
        bump(&mut self.state.counters.polls);
        let completions = self.reap_completions(self.tx.capacity())?;
        let refill = self.refill()?;
        let pending = self.state.pending.len();
        let budget_len = budget as usize;
        let fetch = budget_len
            .saturating_sub(pending)
            .min(self.state.pending.free());
        if fetch > 0 {
            let available = self.rx.available().map_err(RxFillError::Ring)? as usize;
            if available == 0 {
                if pending == 0 {
                    bump(&mut self.state.counters.rx_ring_empty);
                }
            } else {
                let take = fetch.min(available);
                if available > take {
                    bump(&mut self.state.counters.rx_backlogged);
                }
                self.consume_rx(u32::try_from(take).expect("bounded by u32 budget"))?;
            }
        } else if budget_len > 0 && self.rx.available().map_err(RxFillError::Ring)? > 0 {
            bump(&mut self.state.counters.rx_backlogged);
        }
        let remaining = budget_len.min(self.state.pending.len());
        Ok(RxBatch {
            engine: self,
            remaining,
            refill,
            completions,
        })
    }

    fn consume_rx(&mut self, take: u32) -> Result<(), RxFillError> {
        let mut acquisition = self.rx.acquire(take).map_err(RxFillError::Ring)?;
        for _ in 0..take {
            // Reads cannot fail within the acquired length; if one did, the
            // descriptors already accepted stay pending and the consumer
            // cursor is not released, so the error is reported instead.
            let raw = acquisition.read().map_err(RxFillError::Ring)?;
            self.state.accept(raw);
        }
        acquisition.release_consume().map_err(RxFillError::Ring)
    }

    /// Returns a TX handoff that will not be transmitted to the free list
    /// of its pool: a received frame to the RX free list (the next refill
    /// republishes it to Fill, counted as `tx_handoffs_cancelled`), a
    /// generated frame to the generated free list (counted as
    /// `generated_cancelled`).
    ///
    /// The handoff is verified against the ledger before it is consumed: a
    /// handoff of another engine (or one whose geometry this ledger does
    /// not validate) comes back unchanged with the error.
    // Boxing the refusal would allocate; the handoff must come back intact.
    #[allow(clippy::result_large_err)]
    pub fn cancel_tx_handoff(
        &mut self,
        handoff: TxHandoff,
    ) -> Result<(), (RxFillError, TxHandoff)> {
        if let Err(error) = self.state.verify_handoff(&handoff) {
            return Err((RxFillError::Ledger(error), handoff));
        }
        let token = handoff.defuse();
        let state = &mut self.state;
        state
            .frames
            .ledger_mut()
            .cancel_pending_tx(token)
            .expect("verified PendingTx with this token");
        state.recycle(token);
        if state.is_generated(token.frame().index()) {
            state.generated.handoffs -= 1;
            bump(&mut state.generated_counters.generated_cancelled);
        } else {
            bump(&mut state.counters.tx_handoffs_cancelled);
        }
        Ok(())
    }

    /// Returns the counter snapshot.
    #[must_use]
    pub const fn counters(&self) -> RxFillCounters {
        self.state.counters
    }

    /// Returns the authoritative ledger, read-only.
    #[must_use]
    pub const fn ledger(&self) -> &FrameLedger {
        self.state.frames.ledger()
    }

    /// Free RX-pool frames waiting for the next refill.
    #[must_use]
    pub fn free_frames(&self) -> u32 {
        u32::try_from(self.state.free.len()).expect("bounded by rx_frames")
    }

    /// Validated frames waiting to be lent.
    #[must_use]
    pub fn pending_rx(&self) -> u32 {
        u32::try_from(self.state.pending.len()).expect("bounded by the RX ring")
    }

    /// Number of frames in the RX pool (`0..rx_frames`).
    #[must_use]
    pub const fn rx_frames(&self) -> u32 {
        self.state.rx_frames
    }

    /// Cold full consistency check of the ledger and every engine list.
    ///
    /// Every frame must be accounted for exactly once: each listed frame
    /// appears in exactly one of the RX free, generated free, pending-RX,
    /// and in-flight lists, in the matching ledger state with the exact
    /// token; RX free-list entries lie in the RX pool and generated
    /// free-list entries in the generated pool; RX-only states (Fill, RX)
    /// never appear in the generated pool; each ledger state that has a
    /// list or gauge matches it exactly, per pool; and both owner
    /// partitions ([`Self::frame_accounting`],
    /// [`Self::generated_accounting`]) sum to their pool size. In-flight TX
    /// (both pools) must not exceed the TX capacity. It runs only between
    /// batches (it borrows the engine shared, so no frame can be lent) and
    /// allocates one bitmap.
    pub fn audit(&self) -> Result<(), RxFillAuditError> {
        let ledger = self.state.frames.ledger();
        ledger.deep_audit().map_err(RxFillAuditError::Ledger)?;
        let mut seen = vec![false; ledger.frame_count()];
        let is_free = |frame| {
            ledger
                .state(frame)
                .is_ok_and(|state| state.kind() == FrameStateKind::Free)
        };
        for frame in self.state.free.iter() {
            match seen.get_mut(frame as usize) {
                Some(seen) if !*seen && frame < self.state.rx_frames && is_free(frame) => {
                    *seen = true;
                }
                _ => return Err(RxFillAuditError::FreeListEntry { frame }),
            }
        }
        for frame in self.state.generated_free.iter() {
            match seen.get_mut(frame as usize) {
                Some(seen) if !*seen && self.state.is_generated(frame) && is_free(frame) => {
                    *seen = true;
                }
                _ => return Err(RxFillAuditError::GeneratedFreeListEntry { frame }),
            }
        }
        for token in self.state.pending.iter() {
            let frame = token.frame().index();
            let entry = seen.get_mut(frame as usize);
            let is_available = ledger.state(frame).is_ok_and(|state| {
                state.kind() == FrameStateKind::RxAvailable && state.token() == Some(token)
            });
            match entry {
                Some(seen) if !*seen && is_available => *seen = true,
                _ => return Err(RxFillAuditError::PendingEntry { frame }),
            }
        }
        for entry in self.state.inflight.iter() {
            let frame = entry.token.frame().index();
            let entry_slot = seen.get_mut(frame as usize);
            let in_flight = ledger.state(frame).is_ok_and(|state| {
                state.kind() == FrameStateKind::TxOwnedByKernel
                    && state.token() == Some(entry.token)
            });
            match entry_slot {
                Some(seen) if !*seen && in_flight => *seen = true,
                _ => return Err(RxFillAuditError::InflightEntry { frame }),
            }
        }
        let mut free = 0_u32;
        let mut available = 0_u32;
        let mut in_flight = 0_u32;
        let mut generated = [0_u32; STATE_KINDS.len()];
        for frame in 0..ledger.layout().frame_count() {
            let kind = ledger
                .state(frame)
                .map_err(|_| RxFillAuditError::FreeListEntry { frame })?
                .kind();
            let in_pool = !self.state.is_generated(frame);
            let allowed = match kind {
                FrameStateKind::Free
                | FrameStateKind::PendingTx
                | FrameStateKind::TxOwnedByKernel
                | FrameStateKind::Quarantined => true,
                FrameStateKind::FillOwnedByKernel | FrameStateKind::RxAvailable => in_pool,
                _ => false,
            };
            if !allowed {
                return Err(RxFillAuditError::UnexpectedState { frame, state: kind });
            }
            if in_pool && kind == FrameStateKind::Free {
                free += 1;
            }
            if !in_pool {
                generated[kind as usize] += 1;
            }
            if kind == FrameStateKind::RxAvailable {
                available += 1;
            }
            if kind == FrameStateKind::TxOwnedByKernel {
                in_flight += 1;
            }
        }
        let listed = self.free_frames();
        if listed != free {
            return Err(RxFillAuditError::FreeListCount { listed, free });
        }
        let listed = self.pending_rx();
        if listed != available {
            return Err(RxFillAuditError::PendingCount { listed, available });
        }
        let listed = self.tx_inflight();
        if listed != in_flight || self.state.tx_counters.tx_inflight != listed {
            return Err(RxFillAuditError::InflightCount { listed, in_flight });
        }
        let limit = self.tx_inflight_limit();
        if in_flight > limit {
            return Err(RxFillAuditError::InflightExceedsLimit { in_flight, limit });
        }
        let recorded = self.generated_accounting();
        for kind in STATE_KINDS {
            let expected = match kind {
                FrameStateKind::Free => recorded.free,
                FrameStateKind::PendingTx => recorded.tx_handoffs,
                FrameStateKind::TxOwnedByKernel => recorded.tx_in_flight,
                FrameStateKind::Quarantined => recorded.quarantined,
                // A generated lease borrows the engine mutably, so none is
                // live while this shared borrow is.
                _ => 0,
            };
            let actual = generated[kind as usize];
            if expected != actual {
                return Err(RxFillAuditError::GeneratedCount {
                    state: kind,
                    recorded: expected,
                    actual,
                });
            }
        }
        if recorded.total() != recorded.generated_frames {
            return Err(RxFillAuditError::GeneratedAccounting {
                accounted: recorded.total(),
                generated_frames: recorded.generated_frames,
            });
        }
        let accounting = self.state.accounting();
        if accounting.total() != self.state.rx_frames {
            return Err(RxFillAuditError::Accounting {
                accounted: accounting.total(),
                rx_frames: self.state.rx_frames,
            });
        }
        Ok(())
    }
}

/// Every ledger state, in declaration order (the ledger's own list is
/// private to `ruster-io-xdp`).
const STATE_KINDS: [FrameStateKind; 10] = [
    FrameStateKind::Free,
    FrameStateKind::FillReserved,
    FrameStateKind::FillOwnedByKernel,
    FrameStateKind::RxAvailable,
    FrameStateKind::Leased,
    FrameStateKind::PendingTx,
    FrameStateKind::TxReserved,
    FrameStateKind::TxOwnedByKernel,
    FrameStateKind::CompletionAvailable,
    FrameStateKind::Quarantined,
];

impl fmt::Debug for RxFillEngine<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RxFillEngine")
            .field("frames", &self.state.frames)
            .field("free", &self.state.free.len())
            .field("generated_free", &self.state.generated_free.len())
            .field("pending", &self.state.pending.len())
            .field("inflight", &self.state.inflight.len())
            .field("draining", &self.state.draining)
            .field("counters", &self.state.counters)
            .field("tx_counters", &self.state.tx_counters)
            .field("generated_counters", &self.state.generated_counters)
            .finish_non_exhaustive()
    }
}

/// Valid RX frames of one poll, lent one at a time.
pub struct RxBatch<'engine, 'memory> {
    engine: &'engine mut RxFillEngine<'memory>,
    remaining: usize,
    refill: RefillReport,
    completions: CompletionReport,
}

impl<'memory> RxBatch<'_, 'memory> {
    /// Lends the next valid frame. Only one frame can be lent at a time.
    pub fn next_frame(&mut self) -> Option<RxFrame<'_, 'memory>> {
        if self.remaining == 0 {
            return None;
        }
        let lease = self.engine.lease_pending()?;
        self.remaining -= 1;
        Some(self.engine.resume_rx(lease))
    }

    /// Valid frames this batch can still lend.
    #[must_use]
    pub fn remaining(&self) -> u32 {
        u32::try_from(self.remaining).expect("bounded by u32 budget")
    }

    /// The refill that preceded this batch.
    pub const fn refill(&self) -> RefillReport {
        self.refill
    }

    /// The completion reap that preceded the refill.
    pub const fn completions(&self) -> CompletionReport {
        self.completions
    }
}

/// One lent frame (received or generated) recorded by value.
///
/// The core adapter (`packet_io`) keeps a lease across borrows of other
/// ports' engines, which a borrowing [`RxFrame`] or [`GeneratedFrame`]
/// cannot do. The value is move-only and has no public constructor: only
/// [`RxFillEngine::lease_pending`] and `allocate_generated_raw` create it,
/// [`RxFillEngine::resume_rx`] and `resume_generated` consume it into the
/// borrowing view whose end (recycle, stage, cancel, or drop) frees it
/// through the same accounting as a directly lent frame. Byte access goes
/// through the same ledger-gated view and panics if the lease does not
/// name a `Leased` frame of that engine (a lease is never used on another
/// engine: the adapter stores it with its port index).
#[derive(Debug)]
pub(crate) struct RawLease {
    /// The issuing engine (`EngineState::engine_id`), checked on every use.
    engine: u64,
    token: FrameToken,
    descriptor: ValidatedDescriptor,
}

impl RawLease {
    /// Visible length.
    pub(crate) const fn len(&self) -> u32 {
        self.descriptor.len()
    }

    /// The issuing engine identity (tests).
    #[cfg(test)]
    pub(crate) const fn engine(&self) -> u64 {
        self.engine
    }

    /// Ledger ownership cycle.
    #[cfg(test)]
    pub(crate) const fn token(&self) -> FrameToken {
        self.token
    }
}

impl<'memory> RxFillEngine<'memory> {
    /// Leases the next pending (validated, unlent) RX frame by value.
    ///
    /// Not bounded by a batch budget: the caller ([`RxBatch::next_frame`]
    /// or the core adapter) bounds the number of calls by what one
    /// [`Self::poll`] made lendable.
    pub(crate) fn lease_pending(&mut self) -> Option<RawLease> {
        let state = &mut self.state;
        let token = state.pending.pop()?;
        let descriptor = state
            .frames
            .ledger_mut()
            .lease_rx(token)
            .expect("pending holds RxAvailable tokens");
        bump(&mut state.counters.rx_leased);
        Some(RawLease {
            engine: state.engine_id,
            token,
            descriptor,
        })
    }

    /// Always-on check that `lease` was issued by this engine: a lease of
    /// another engine never touches this ledger or UMEM, even when the two
    /// ledgers share a `UmemDomainId` and issue identical tokens.
    pub(crate) fn check_lease(&self, lease: &RawLease) {
        assert_eq!(
            lease.engine, self.state.engine_id,
            "a raw lease is used only on the engine that issued it"
        );
    }

    /// The visible bytes of a lease of this engine.
    pub(crate) fn lease_bytes(&self, lease: &RawLease) -> &[u8] {
        self.check_lease(lease);
        self.state
            .frames
            .leased_bytes(lease.token, lease.descriptor)
            .expect("a live lease of this engine owns its Leased frame")
    }

    /// The visible bytes of a lease of this engine, for writing.
    pub(crate) fn lease_bytes_mut(&mut self, lease: &RawLease) -> &mut [u8] {
        self.check_lease(lease);
        self.state
            .frames
            .leased_bytes_mut(lease.token, lease.descriptor)
            .expect("a live lease of this engine owns its Leased frame")
    }

    /// Turns an RX lease back into the borrowing view that ends it.
    pub(crate) fn resume_rx(&mut self, lease: RawLease) -> RxFrame<'_, 'memory> {
        self.check_lease(&lease);
        assert!(
            !self.state.is_generated(lease.token.frame().index()),
            "an RX lease names an RX-pool frame"
        );
        RxFrame {
            engine: self,
            token: lease.token,
            descriptor: lease.descriptor,
            resolved: false,
        }
    }
}

/// One valid received frame, lent by the engine.
///
/// The frame bytes are reachable only through this value, which mutably
/// borrows the engine; ending it ([`Self::recycle`], [`Self::stage_tx`], or
/// drop) consumes it, so a frame cannot be recycled while its bytes are
/// borrowed:
///
/// ```compile_fail,E0505
/// fn recycle_while_borrowed(mut frame: ruster_io_xdp_native::RxFrame<'_, '_>) {
///     let bytes = frame.bytes_mut();
///     frame.recycle();
///     bytes[0] = 0;
/// }
/// ```
///
/// Dropping it without an explicit end recycles it and is counted as
/// `rx_abandoned`.
pub struct RxFrame<'engine, 'memory> {
    engine: &'engine mut RxFillEngine<'memory>,
    token: FrameToken,
    descriptor: ValidatedDescriptor,
    resolved: bool,
}

impl RxFrame<'_, '_> {
    /// The canonical UMEM frame.
    #[must_use]
    pub const fn frame(&self) -> FrameId {
        self.descriptor.frame()
    }

    /// The validated RX descriptor geometry.
    #[must_use]
    pub const fn descriptor(&self) -> ValidatedDescriptor {
        self.descriptor
    }

    /// Visible packet length.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.descriptor.len()
    }

    /// Always `false`: a valid frame holds at least an Ethernet header.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.descriptor.is_empty()
    }

    /// The received bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.engine
            .state
            .frames
            .leased_bytes(self.token, self.descriptor)
            .expect("a live RxFrame owns its Leased frame")
    }

    /// The received bytes, for in-place rewrite.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        self.engine
            .state
            .frames
            .leased_bytes_mut(self.token, self.descriptor)
            .expect("a live RxFrame owns its Leased frame")
    }

    /// Returns the frame to the free list; the next refill republishes it.
    pub fn recycle(mut self) {
        self.resolved = true;
        self.engine.state.recycle(self.token);
        bump(&mut self.engine.state.counters.rx_recycled);
    }

    /// Hands the frame to TX (`PendingTx`) with the bytes as rewritten in
    /// place and the received length. [`RxFillEngine::submit_tx`] (or
    /// [`RxFillEngine::submit_tx_batch`]) publishes it;
    /// [`RxFillEngine::cancel_tx_handoff`] returns it to the free list.
    pub fn stage_tx(mut self) -> TxHandoff {
        self.resolved = true;
        self.engine
            .state
            .frames
            .ledger_mut()
            .stage_tx(self.token)
            .expect("a live RxFrame owns its Leased frame");
        bump(&mut self.engine.state.counters.rx_tx_handoffs);
        TxHandoff {
            engine: self.engine.state.engine_id,
            token: self.token,
            descriptor: self.descriptor,
        }
    }
}

impl Drop for RxFrame<'_, '_> {
    fn drop(&mut self) {
        if !self.resolved {
            self.engine.state.recycle(self.token);
            bump(&mut self.engine.state.counters.rx_abandoned);
        }
    }
}

impl fmt::Debug for RxFrame<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RxFrame")
            .field("frame", &self.descriptor.frame())
            .field("len", &self.descriptor.len())
            .finish_non_exhaustive()
    }
}

/// A received frame staged for TX.
///
/// Move-only and without a public constructor. The frame stays
/// `PendingTx` in the ledger until [`RxFillEngine::submit_tx`] publishes it
/// or [`RxFillEngine::cancel_tx_handoff`] returns it; a refused submission
/// or cancel hands the value back. Dropping the value strands the frame
/// (it never becomes reusable): it is `must_use`, a debug build asserts on
/// such a drop, and [`RxFillEngine::tx_handoffs_outstanding`] keeps
/// counting it.
#[must_use = "a dropped TX handoff strands its frame in PendingTx"]
#[derive(Debug)]
pub struct TxHandoff {
    /// The issuing engine; see `EngineState::verify_handoff`.
    engine: u64,
    token: FrameToken,
    descriptor: ValidatedDescriptor,
}

impl Drop for TxHandoff {
    fn drop(&mut self) {
        debug_assert!(
            std::thread::panicking(),
            "TxHandoff dropped without TX or cancel: frame stranded in PendingTx"
        );
    }
}

impl TxHandoff {
    /// Consumes the handoff inside an engine method, without the drop check.
    fn defuse(self) -> FrameToken {
        let token = self.token;
        std::mem::forget(self);
        token
    }

    /// The canonical UMEM frame.
    #[must_use]
    pub const fn frame(&self) -> FrameId {
        self.descriptor.frame()
    }

    /// The RX geometry the frame arrived with.
    #[must_use]
    pub const fn descriptor(&self) -> ValidatedDescriptor {
        self.descriptor
    }

    /// The exact ledger ownership cycle.
    #[must_use]
    pub const fn token(&self) -> FrameToken {
        self.token
    }
}

#[cfg(test)]
impl TxHandoff {
    /// A second handle to the same ownership cycle, which no public API can
    /// produce: used to prove the ledger refuses a duplicate completion.
    pub(crate) const fn forged_copy_for_test(&self) -> Self {
        Self {
            engine: self.engine,
            token: self.token,
            descriptor: self.descriptor,
        }
    }

    /// A forged copy that claims other descriptor geometry.
    pub(crate) const fn with_descriptor_for_test(&self, descriptor: ValidatedDescriptor) -> Self {
        Self {
            engine: self.engine,
            token: self.token,
            descriptor,
        }
    }
}

#[cfg(test)]
impl RxFillEngine<'_> {
    /// Attempts the raw ledger recycle a lent frame performs, for a token
    /// the caller does not own. Only refusals keep the engine consistent.
    pub(crate) fn raw_recycle_for_test(&mut self, token: FrameToken) -> Result<(), LedgerError> {
        self.state.frames.ledger_mut().recycle_lease(token)
    }
}

#[cfg(test)]
impl RxFillEngine<'_> {
    /// Loses one free-list entry behind the ledger's back.
    pub(crate) fn drop_free_entry_for_test(&mut self) -> Option<u32> {
        self.state.free.pop()
    }

    /// Lists a frame in the free list a second time.
    pub(crate) fn push_free_entry_for_test(&mut self, frame: u32) -> bool {
        self.state.free.push(frame)
    }
}

#[cfg(test)]
impl RxFillEngine<'_> {
    /// Moves a free frame's generation to `u64::MAX`, so its next refill
    /// exhausts the generation.
    pub(crate) fn exhaust_generation_for_test(&mut self, frame: u32) {
        self.state
            .frames
            .ledger_mut()
            .set_free_generation_for_test(frame, u64::MAX);
    }
}
