//! RX/Fill half of the AF_XDP datapath engine (M2 S3, X01).
//!
//! One worker owns one [`RxFillEngine`]: the Fill producer, the RX
//! consumer, the UMEM, and the authoritative frame ledger. Nothing here
//! locks, allocates after construction, clones packets, or formats a
//! string. The engine is generic over ring memory only through the
//! borrowed role views it consumes: a live [`crate::NativeSession`] lends
//! them over the kernel mappings, and tests lend them over heap memory.
//!
//! Frame ownership follows the [`FrameLedger`]: a free RX-pool frame is
//! reserved and published to Fill (`FillOwnedByKernel`); the kernel returns
//! it on an RX descriptor, which is validated before anything else looks at
//! it (`RxAvailable`); the engine lends it to the caller as an [`RxFrame`]
//! (`Leased`), which ends by recycling it to the free list (`Free`, next
//! refill republishes it) or by handing it to TX (`PendingTx`, see
//! [`TxHandoff`]). An invalid descriptor never reaches the caller.

use std::{fmt, num::NonZeroU32};

use ruster_io_xdp::{
    AuditError, FrameId, FrameLedger, FrameStateKind, FrameToken, LayoutError, LedgerError,
    RawDescriptor, UmemDomainId, UmemLayout, ValidatedDescriptor,
};

use crate::{
    abi::XdpDescriptor,
    native_unsafe::umem::{UmemFrames, UmemPairingError},
    FillProducer, NativeRingError, NeedWakeup, RxConsumer, UmemRegion, XDP_PACKET_HEADROOM,
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
    /// Shorter than [`ETHERNET_HEADER_LEN`], including zero. The
    /// kernel-owned frame is quarantined.
    ShorterThanEthernetHeader,
    /// The visible range ends beyond the frame (chunk). The kernel-owned
    /// frame is quarantined.
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
    /// Fill publications after which the kernel requested a wakeup.
    pub fill_need_wakeup: u64,
    /// Fill publications whose flags word had unknown bits.
    pub fill_flag_errors: u64,
    /// Frames permanently removed from reuse (invalid kernel return or
    /// generation exhaustion).
    pub frames_quarantined: u64,
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

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

fn add(counter: &mut u64, value: u32) {
    *counter = counter.saturating_add(u64::from(value));
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
}

/// Fill outcome of one refill.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct RefillReport {
    published: u32,
    starved: bool,
    need_wakeup: Option<Result<NeedWakeup, NativeRingError>>,
}

impl RefillReport {
    const fn idle(starved: bool) -> Self {
        Self {
            published: 0,
            starved,
            need_wakeup: None,
        }
    }

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

    /// The need-wakeup observation after a publication, if one happened.
    /// The kick itself (poll/recvfrom on the socket) belongs to the caller.
    #[must_use]
    pub const fn need_wakeup(self) -> Option<Result<NeedWakeup, NativeRingError>> {
        self.need_wakeup
    }
}

/// Fixed-capacity FIFO of free RX-pool frame indices.
struct IndexFifo {
    slots: Box<[u32]>,
    head: usize,
    len: usize,
}

impl IndexFifo {
    fn full(count: u32) -> Self {
        Self {
            slots: (0..count).collect(),
            head: 0,
            len: count as usize,
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
    frames: UmemFrames<'memory>,
    free: IndexFifo,
    pending: TokenFifo,
    scratch: Box<[Option<FrameToken>]>,
    counters: RxFillCounters,
    fill_batch: u32,
    rx_frames: u32,
    frame_size: u64,
    headroom: u64,
    umem_len: u64,
}

type Classified = Result<(FrameToken, ValidatedDescriptor), (RxInvalidReason, Option<FrameToken>)>;

impl EngineState<'_> {
    /// Validates one kernel RX descriptor against the profile and ledger.
    ///
    /// The returned token, on failure, names a kernel-owned frame that must
    /// be quarantined; `None` means nothing may be touched.
    fn classify(&self, raw: XdpDescriptor) -> Classified {
        if raw.address >= self.umem_len {
            return Err((RxInvalidReason::AddressOutsideUmem, None));
        }
        let frame_base = raw.address & !(self.frame_size - 1);
        let Ok(index) = u32::try_from(raw.address / self.frame_size) else {
            return Err((RxInvalidReason::AddressOutsideUmem, None));
        };
        let ledger = self.frames.ledger();
        let Ok(state) = ledger.state(index) else {
            return Err((RxInvalidReason::AddressOutsideUmem, None));
        };
        let (FrameStateKind::FillOwnedByKernel, Some(token)) = (state.kind(), state.token()) else {
            return Err((RxInvalidReason::NotKernelOwned, None));
        };
        let quarantine = |reason| Err((reason, Some(token)));
        if raw.options != 0 {
            return quarantine(RxInvalidReason::UnsupportedOptions);
        }
        let offset = raw.address - frame_base;
        if offset < self.headroom {
            return quarantine(RxInvalidReason::DataBeforeHeadroom);
        }
        if raw.len < ETHERNET_HEADER_LEN {
            return quarantine(RxInvalidReason::ShorterThanEthernetHeader);
        }
        if offset + u64::from(raw.len) > self.frame_size {
            return quarantine(RxInvalidReason::ExceedsFrame);
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
            Err((reason, quarantine)) => {
                bump(&mut self.counters.rx_invalid[reason.index()]);
                if let Some(token) = quarantine {
                    self.frames
                        .ledger_mut()
                        .quarantine_kernel_fill(token)
                        .expect("classification proved FillOwnedByKernel");
                    bump(&mut self.counters.frames_quarantined);
                }
            }
        }
    }

    fn recycle(&mut self, token: FrameToken) {
        self.frames
            .ledger_mut()
            .recycle_lease(token)
            .expect("only a live RxFrame recycles, and it is Leased");
        let pushed = self.free.push(token.frame().index());
        debug_assert!(pushed, "each Free transition enters the free list once");
    }

    fn rollback_reserved(&mut self, reserved: usize) {
        for slot in 0..reserved {
            if let Some(token) = self.scratch[slot].take() {
                self.frames
                    .ledger_mut()
                    .cancel_fill(token)
                    .expect("scratch holds FillReserved tokens");
                let pushed = self.free.push(token.frame().index());
                debug_assert!(pushed);
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
    state: EngineState<'memory>,
}

impl<'memory> RxFillEngine<'memory> {
    /// Binds the engine to the Fill and RX views and the UMEM, creates the
    /// ledger for `domain`, and performs the first bounded refill.
    ///
    /// Frames `0..rx_frames` form the RX pool. The generated pool
    /// `rx_frames..frame_count` is never published or lent by this engine.
    /// Both rings must be empty: entries that no ledger tracks are refused.
    pub fn new(
        fill: FillProducer<'memory>,
        rx: RxConsumer<'memory>,
        umem: UmemRegion<'memory>,
        domain: UmemDomainId,
        config: RxFillConfig,
    ) -> Result<Self, RxFillSetupError> {
        let geometry = umem.config();
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
        let headroom = geometry.headroom() + XDP_PACKET_HEADROOM;
        let layout = UmemLayout::new(
            domain,
            geometry.frame_count(),
            geometry.frame_size(),
            headroom,
        )
        .map_err(RxFillSetupError::Layout)?;
        let ledger = FrameLedger::new(layout).map_err(RxFillSetupError::Ledger)?;
        let frames = UmemFrames::new(umem.into_mapping(), ledger).map_err(|error| match error {
            UmemPairingError::MappingTooShort => RxFillSetupError::UmemTooShort,
            UmemPairingError::LedgerNotFresh => {
                unreachable!("a newly created ledger is fresh")
            }
        })?;
        let state = EngineState {
            frames,
            free: IndexFifo::full(geometry.rx_frames()),
            pending: TokenFifo::new(rx.capacity()),
            scratch: vec![None; fill.capacity() as usize].into_boxed_slice(),
            counters: RxFillCounters::default(),
            fill_batch,
            rx_frames: geometry.rx_frames(),
            frame_size: u64::from(geometry.frame_size()),
            headroom: u64::from(headroom),
            umem_len: geometry.byte_len(),
        };
        let mut engine = Self { fill, rx, state };
        let _initial = engine.refill().map_err(|error| match error {
            RxFillError::Ring(error) => RxFillSetupError::Ring(error),
            RxFillError::Ledger(error) => RxFillSetupError::Ledger(error),
        })?;
        Ok(engine)
    }

    /// Publishes up to `fill_batch` free RX-pool frames to Fill, bounded by
    /// the ring's room.
    ///
    /// An empty free list with room in Fill is counted as starvation and
    /// returns immediately; it never blocks other work.
    pub fn refill(&mut self) -> Result<RefillReport, RxFillError> {
        let room = self.fill.free_slots().map_err(RxFillError::Ring)?;
        let state = &mut self.state;
        if room == 0 {
            if state.free.len() > 0 {
                bump(&mut state.counters.fill_ring_full);
            }
            return Ok(RefillReport::idle(false));
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
            return Ok(RefillReport::idle(true));
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
        let publication = match reservation.release_submit() {
            Ok(publication) => publication,
            Err(error) => {
                state.rollback_reserved(reserved);
                return Err(RxFillError::Ring(error));
            }
        };
        for slot in &mut state.scratch[..reserved] {
            let token = slot.take().expect("reserved prefix");
            state
                .frames
                .ledger_mut()
                .publish_fill(token)
                .expect("scratch holds FillReserved tokens");
        }
        add(&mut state.counters.fill_published, count);
        let need_wakeup = publication.need_wakeup();
        match need_wakeup {
            Ok(NeedWakeup::Required) => bump(&mut state.counters.fill_need_wakeup),
            Ok(NeedWakeup::NotRequired) => {}
            Err(_) => bump(&mut state.counters.fill_flag_errors),
        }
        Ok(RefillReport {
            published: count,
            starved: false,
            need_wakeup: Some(need_wakeup),
        })
    }

    /// Refills Fill, then consumes at most `budget` RX descriptors and
    /// returns a batch that lends at most `budget` valid frames.
    ///
    /// Valid frames left unlent when the batch drops stay pending and are
    /// lent by the next poll before any new descriptor is consumed, so one
    /// poll never does more than `budget` descriptor work. A zero budget
    /// only refills and never observes the RX ring.
    pub fn poll(&mut self, budget: u32) -> Result<RxBatch<'_, 'memory>, RxFillError> {
        bump(&mut self.state.counters.polls);
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

    /// Returns a TX handoff that will not be transmitted to the free list.
    pub fn cancel_tx_handoff(&mut self, handoff: TxHandoff) -> Result<(), RxFillError> {
        let ledger = self.state.frames.ledger_mut();
        ledger
            .cancel_pending_tx(handoff.token)
            .map_err(RxFillError::Ledger)?;
        self.state.recycle(handoff.token);
        bump(&mut self.state.counters.tx_handoffs_cancelled);
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

    /// Cold full consistency check of ledger, free list, and pending list.
    ///
    /// It runs only between batches (it borrows the engine shared, so no
    /// frame can be lent) and allocates one bitmap.
    pub fn audit(&self) -> Result<(), RxFillAuditError> {
        let ledger = self.state.frames.ledger();
        ledger.deep_audit().map_err(RxFillAuditError::Ledger)?;
        let mut seen = vec![false; ledger.frame_count()];
        for frame in self.state.free.iter() {
            let entry = seen.get_mut(frame as usize);
            let is_free = ledger
                .state(frame)
                .is_ok_and(|state| state.kind() == FrameStateKind::Free);
            match entry {
                Some(seen) if !*seen && frame < self.state.rx_frames && is_free => *seen = true,
                _ => return Err(RxFillAuditError::FreeListEntry { frame }),
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
        let mut free = 0_u32;
        let mut available = 0_u32;
        for frame in 0..ledger.layout().frame_count() {
            let kind = ledger
                .state(frame)
                .map_err(|_| RxFillAuditError::FreeListEntry { frame })?
                .kind();
            let in_pool = frame < self.state.rx_frames;
            let allowed = match kind {
                FrameStateKind::Free => true,
                FrameStateKind::FillOwnedByKernel
                | FrameStateKind::RxAvailable
                | FrameStateKind::PendingTx
                | FrameStateKind::Quarantined => in_pool,
                _ => false,
            };
            if !allowed {
                return Err(RxFillAuditError::UnexpectedState { frame, state: kind });
            }
            if in_pool && kind == FrameStateKind::Free {
                free += 1;
            }
            if kind == FrameStateKind::RxAvailable {
                available += 1;
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
        Ok(())
    }
}

impl fmt::Debug for RxFillEngine<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RxFillEngine")
            .field("frames", &self.state.frames)
            .field("free", &self.state.free.len())
            .field("pending", &self.state.pending.len())
            .field("counters", &self.state.counters)
            .finish_non_exhaustive()
    }
}

/// Valid RX frames of one poll, lent one at a time.
pub struct RxBatch<'engine, 'memory> {
    engine: &'engine mut RxFillEngine<'memory>,
    remaining: usize,
    refill: RefillReport,
}

impl<'memory> RxBatch<'_, 'memory> {
    /// Lends the next valid frame. Only one frame can be lent at a time.
    pub fn next_frame(&mut self) -> Option<RxFrame<'_, 'memory>> {
        if self.remaining == 0 {
            return None;
        }
        let state = &mut self.engine.state;
        let token = state.pending.pop()?;
        let descriptor = state
            .frames
            .ledger_mut()
            .lease_rx(token)
            .expect("pending holds RxAvailable tokens");
        self.remaining -= 1;
        bump(&mut state.counters.rx_leased);
        Some(RxFrame {
            engine: &mut *self.engine,
            token,
            descriptor,
            resolved: false,
        })
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

    /// Hands the frame to TX (`PendingTx`). The TX/Completion half (S4)
    /// publishes it; until then [`RxFillEngine::cancel_tx_handoff`] returns
    /// it to the free list.
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

/// A received frame staged for TX: the hook point of the TX half (S4).
///
/// Move-only and without a public constructor. The frame stays
/// `PendingTx` in the ledger until TX publishes it or
/// [`RxFillEngine::cancel_tx_handoff`] returns it; dropping the value
/// strands the frame (it never becomes reusable), so it is `must_use`.
#[must_use = "a dropped TX handoff strands its frame in PendingTx"]
#[derive(Debug)]
pub struct TxHandoff {
    token: FrameToken,
    descriptor: ValidatedDescriptor,
}

impl TxHandoff {
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
            token: self.token,
            descriptor: self.descriptor,
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
