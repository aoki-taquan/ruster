//! Generated-frame half of the AF_XDP datapath engine (M2 S5, X03).
//!
//! The UMEM frames `rx_frames..frame_count` (`generated-frames` in the
//! backend config) form the generated pool. They are never published to
//! Fill. The same [`RxFillEngine`] and the same authoritative ledger own
//! them, so one audit covers both pools. A generated frame moves:
//!
//! ```text
//!                 allocate_generated(len)
//!   Free (generated free list) ───────────────► Leased(Generated)  = GeneratedFrame
//!       ▲   ▲   ▲                                 │   │   │
//!       │   │   └──────── cancel ─────────────────┘   │   │
//!       │   └──────────── drop (abandoned) ───────────┘   │
//!       │                                                 │ stage_tx / commit
//!       │                                                 ▼
//!       ├──── cancel_tx_handoff ──────────────── PendingTx  = TxHandoff
//!       │                                                 │ submit (shared TX cap)
//!       │                                                 ▼
//!       └──── validated completion ──────────── TxOwnedByKernel (in flight)
//!                                                         │ address mismatch
//!                                                         ▼
//!                                                    Quarantined
//! ```
//!
//! A [`GeneratedFrame`] lends exactly the requested visible bytes: the
//! descriptor is `frame base + headroom` with the requested length, and
//! byte access goes through the same ledger-gated UMEM view as RX frames,
//! so bytes beyond the requested length (and the headroom before it) are
//! never reachable. The visible bytes are zeroed at allocation, so no byte
//! of an earlier packet can reach the wire through a field the caller did
//! not write.
//!
//! Refusals never block and never touch the pool: draining, a zero or
//! shorter-than-Ethernet length, a length above the frame minus headroom
//! (all [`GeneratedAllocError::Rejected`]), or an empty generated free list
//! ([`GeneratedAllocError::Unavailable`]).

use std::fmt;

use ruster_io_xdp::{FrameId, FrameToken, LedgerError, RawDescriptor, ValidatedDescriptor};

use super::{bump, EngineState, RawLease, RxFillEngine, TxHandoff, ETHERNET_HEADER_LEN};
use crate::{TxRejected, TxSubmitReport};

/// Why a generated allocation was refused for its arguments or the engine
/// state (as opposed to an empty pool, [`GeneratedAllocError::Unavailable`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedRejectReason {
    /// The requested length was zero.
    ZeroLength,
    /// Shorter than one Ethernet header ([`ETHERNET_HEADER_LEN`]), the same
    /// floor as RX.
    BelowMinimum,
    /// Longer than the frame minus the configured and kernel headroom
    /// ([`RxFillEngine::generated_max_len`]).
    TooLarge,
    /// [`RxFillEngine::drain`] started; no new frame is generated.
    Draining,
}

impl GeneratedRejectReason {
    /// Number of reasons.
    pub const COUNT: usize = 4;

    /// Every reason in declaration order; `ALL[reason.index()] == reason`.
    pub const ALL: [Self; Self::COUNT] = [
        Self::ZeroLength,
        Self::BelowMinimum,
        Self::TooLarge,
        Self::Draining,
    ];

    /// Dense index into [`Self::ALL`].
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::ZeroLength => 0,
            Self::BelowMinimum => 1,
            Self::TooLarge => 2,
            Self::Draining => 3,
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ZeroLength => "ZERO_LENGTH",
            Self::BelowMinimum => "BELOW_MINIMUM",
            Self::TooLarge => "TOO_LARGE",
            Self::Draining => "DRAINING",
        }
    }
}

/// A refused generated allocation. Nothing was allocated, nothing blocked,
/// and the generated free list is unchanged (except that a frame whose
/// ownership generation was exhausted on the way was quarantined).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedAllocError {
    /// The generated free list is empty: every generated frame is lent,
    /// staged, in flight, or quarantined. Recoverable: reap completions
    /// ([`RxFillEngine::poll`] or [`RxFillEngine::reap_completions`]) and
    /// retry. Counted as `generated_unavailable`.
    Unavailable,
    /// Refused for the request itself or because the engine drains.
    /// Counted per reason.
    Rejected(GeneratedRejectReason),
    /// A generated free-list entry was not a `Free` frame of this ledger:
    /// an engine invariant failure, which [`RxFillEngine::audit`] also
    /// reports. The entry was dropped from the list.
    Ledger(LedgerError),
}

impl fmt::Display for GeneratedAllocError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for GeneratedAllocError {}

/// Saturating, allocation-free generated-pool counters (OBS-018, generated
/// half).
///
/// Monotonic fields only grow; [`Self::generated_inflight`] is a gauge.
/// With `L` live generated leases (0 or 1) and `H` outstanding generated
/// handoffs ([`GeneratedAccounting::tx_handoffs`]):
///
/// - `generated_allocated == generated_committed + generated_cancelled +
///   generated_abandoned + H + L`
/// - `generated_committed == generated_completed + generated_inflight +
///   generated_quarantined_after_tx`
///
/// `RxFillCounters::frames_quarantined` counts quarantined frames of both
/// pools (an out-of-profile RX or completion return, or an exhausted
/// generation, in either pool); [`GeneratedAccounting::quarantined`] is
/// the generated pool's current share, and `generated_quarantined_after_tx`
/// the part that a completion with a mismatched address removed after a
/// commit.
///
/// Refusals (`generated_unavailable`, `generated_rejected`) never allocate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct GeneratedCounters {
    /// Successful allocations: generated frames lent as [`GeneratedFrame`].
    pub generated_allocated: u64,
    /// Allocations refused because the generated free list was empty.
    pub generated_unavailable: u64,
    /// Generated frames published to the TX ring.
    pub generated_committed: u64,
    /// Generated frames returned to the generated free list by an explicit
    /// cancel: [`GeneratedFrame::cancel`], or
    /// [`RxFillEngine::cancel_tx_handoff`] of a generated handoff.
    pub generated_cancelled: u64,
    /// Generated frames dropped without an explicit end (recycled to the
    /// generated free list).
    pub generated_abandoned: u64,
    /// Valid completions of generated frames (returned to the generated
    /// free list).
    pub generated_completed: u64,
    /// Generated frames currently published to TX and not completed. Part
    /// of, never in addition to, `TxCounters::tx_inflight`.
    pub generated_inflight: u32,
    /// Committed generated frames whose completion named an address other
    /// than the submitted one, so the frame was quarantined instead of
    /// freed. Also counted in `RxFillCounters::frames_quarantined`.
    pub generated_quarantined_after_tx: u64,
    generated_rejected: [u64; GeneratedRejectReason::COUNT],
}

impl GeneratedCounters {
    /// Refused allocations of one reason.
    #[must_use]
    pub const fn generated_rejected(&self, reason: GeneratedRejectReason) -> u64 {
        self.generated_rejected[reason.index()]
    }

    /// Refused allocations of every reason (excluding `Unavailable`).
    #[must_use]
    pub fn generated_rejected_total(&self) -> u64 {
        self.generated_rejected
            .iter()
            .fold(0_u64, |total, value| total.saturating_add(*value))
    }
}

/// Every generated-pool frame by owner, in O(1).
///
/// The fields partition `rx_frames..frame_count`, so [`Self::total`]
/// always equals [`Self::generated_frames`]; [`RxFillEngine::audit`]
/// checks each field against a full scan of the generated pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct GeneratedAccounting {
    /// Size of the generated pool.
    pub generated_frames: u32,
    /// In the generated free list.
    pub free: u32,
    /// Lent as a [`GeneratedFrame`] right now (zero whenever the engine is
    /// not borrowed by one).
    pub leased: u32,
    /// Held by the caller as generated [`TxHandoff`]s.
    pub tx_handoffs: u32,
    /// Published to TX and not completed: the kernel holds them.
    pub tx_in_flight: u32,
    /// Permanently removed from reuse.
    pub quarantined: u32,
}

impl GeneratedAccounting {
    /// Sum over all owners.
    #[must_use]
    pub const fn total(self) -> u32 {
        self.free + self.leased + self.tx_handoffs + self.tx_in_flight + self.quarantined
    }
}

/// Whether a generated allocation zeroes its visible bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ZeroFill {
    /// Zero them (every public allocation).
    Zero,
    /// The caller overwrites every visible byte at once.
    Overwritten,
}

/// Generated-pool owners the free list and the in-flight gauge do not
/// already record.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct GeneratedPool {
    pub(super) leased: u32,
    pub(super) handoffs: u32,
    pub(super) quarantined: u32,
}

impl EngineState<'_> {
    pub(super) fn generated_accounting(&self) -> GeneratedAccounting {
        GeneratedAccounting {
            generated_frames: self.frames.ledger().layout().frame_count() - self.rx_frames,
            free: u32::try_from(self.generated_free.len()).expect("bounded by u32 frames"),
            leased: self.generated.leased,
            tx_handoffs: self.generated.handoffs,
            tx_in_flight: self.generated_counters.generated_inflight,
            quarantined: self.generated.quarantined,
        }
    }

    fn reject(&mut self, reason: GeneratedRejectReason) -> GeneratedAllocError {
        bump(&mut self.generated_counters.generated_rejected[reason.index()]);
        GeneratedAllocError::Rejected(reason)
    }

    /// The largest visible length a generated frame can carry.
    fn generated_max_len(&self) -> u64 {
        self.frame_size - self.headroom
    }

    /// Ends a live generated lease into the generated free list.
    fn release_generated(&mut self, token: FrameToken) {
        self.recycle(token);
        self.generated.leased -= 1;
    }
}

impl<'memory> RxFillEngine<'memory> {
    /// Allocates one generated-pool frame and lends exactly `len` visible
    /// bytes of it, zeroed, starting after the configured and kernel
    /// headroom.
    ///
    /// Never blocks. Refusals, checked in this order, change nothing: a
    /// started drain, a zero length, a length below one Ethernet header, a
    /// length above [`Self::generated_max_len`] (each
    /// [`GeneratedAllocError::Rejected`]), then an empty generated free
    /// list ([`GeneratedAllocError::Unavailable`]). The frame is end-ed by
    /// [`GeneratedFrame::commit`], [`GeneratedFrame::stage_tx`],
    /// [`GeneratedFrame::cancel`], or drop (abandoned). Only one frame
    /// (received or generated) can be lent at a time, because the lease
    /// borrows the engine.
    pub fn allocate_generated(
        &mut self,
        len: usize,
    ) -> Result<GeneratedFrame<'_, 'memory>, GeneratedAllocError> {
        let lease = self.allocate_generated_raw(len, ZeroFill::Zero)?;
        Ok(self.resume_generated(lease))
    }

    /// [`Self::allocate_generated`] by value, for the core adapter.
    ///
    /// [`ZeroFill::Overwritten`] skips zeroing the visible bytes. It is
    /// only for a caller that overwrites every visible byte before the
    /// lease can end or be observed (the adapter's cross-port copy, which
    /// copies exactly `len` bytes right after allocation): otherwise bytes
    /// of an earlier packet could reach the wire.
    pub(crate) fn allocate_generated_raw(
        &mut self,
        len: usize,
        zero: ZeroFill,
    ) -> Result<RawLease, GeneratedAllocError> {
        let state = &mut self.state;
        if state.draining {
            return Err(state.reject(GeneratedRejectReason::Draining));
        }
        if len == 0 {
            return Err(state.reject(GeneratedRejectReason::ZeroLength));
        }
        if len < ETHERNET_HEADER_LEN as usize {
            return Err(state.reject(GeneratedRejectReason::BelowMinimum));
        }
        let Ok(visible) = u32::try_from(len) else {
            return Err(state.reject(GeneratedRejectReason::TooLarge));
        };
        if u64::from(visible) > state.generated_max_len() {
            return Err(state.reject(GeneratedRejectReason::TooLarge));
        }
        let (token, descriptor) = loop {
            let Some(frame) = state.generated_free.pop() else {
                bump(&mut state.generated_counters.generated_unavailable);
                return Err(GeneratedAllocError::Unavailable);
            };
            let address = u64::from(frame) * state.frame_size + state.headroom;
            let raw = RawDescriptor {
                addr: address,
                len: visible,
                options: 0,
            };
            // The layout is a second, independent gate on the geometry.
            let Ok(descriptor) = state.frames.ledger().layout().validate_descriptor(raw) else {
                let pushed = state.generated_free.push(frame);
                debug_assert!(pushed, "the entry was just popped");
                return Err(state.reject(GeneratedRejectReason::TooLarge));
            };
            match state.frames.ledger_mut().lease_generated(frame) {
                Ok(token) => break (token, descriptor),
                Err(LedgerError::GenerationExhausted { .. }) => {
                    // The ledger quarantined the frame; it leaves the pool.
                    bump(&mut state.counters.frames_quarantined);
                    state.generated.quarantined += 1;
                }
                Err(error) => return Err(GeneratedAllocError::Ledger(error)),
            }
        };
        state.generated.leased += 1;
        bump(&mut state.generated_counters.generated_allocated);
        if zero == ZeroFill::Zero {
            state
                .frames
                .leased_bytes_mut(token, descriptor)
                .expect("a just-leased generated frame")
                .fill(0);
        }
        Ok(RawLease { token, descriptor })
    }

    /// Turns a generated lease back into the borrowing view that ends it.
    pub(crate) fn resume_generated(&mut self, lease: RawLease) -> GeneratedFrame<'_, 'memory> {
        debug_assert!(self.state.is_generated(lease.token.frame().index()));
        GeneratedFrame {
            engine: self,
            token: lease.token,
            descriptor: lease.descriptor,
            resolved: false,
        }
    }

    /// Generated-pool counter snapshot.
    #[must_use]
    pub const fn generated_counters(&self) -> GeneratedCounters {
        self.state.generated_counters
    }

    /// Owner of every generated-pool frame, in O(1).
    #[must_use]
    pub fn generated_accounting(&self) -> GeneratedAccounting {
        self.state.generated_accounting()
    }

    /// Free generated-pool frames.
    #[must_use]
    pub fn generated_free_frames(&self) -> u32 {
        u32::try_from(self.state.generated_free.len()).expect("bounded by u32 frames")
    }

    /// Number of frames in the generated pool (`rx_frames..frame_count`).
    #[must_use]
    pub fn generated_frames(&self) -> u32 {
        self.state.frames.ledger().layout().frame_count() - self.state.rx_frames
    }

    /// The largest length [`Self::allocate_generated`] accepts: the frame
    /// size minus the configured headroom and the kernel's
    /// `XDP_PACKET_HEADROOM`.
    #[must_use]
    pub fn generated_max_len(&self) -> u32 {
        u32::try_from(self.state.generated_max_len()).expect("bounded by the u32 frame size")
    }
}

/// One generated-pool frame lent with exactly the requested visible length.
///
/// The bytes are reachable only through this value, which mutably borrows
/// the engine; ending it consumes it, so a frame cannot be cancelled or
/// committed while its bytes are borrowed:
///
/// ```compile_fail,E0505
/// fn cancel_while_borrowed(mut frame: ruster_io_xdp_native::GeneratedFrame<'_, '_>) {
///     let bytes = frame.bytes_mut();
///     frame.cancel();
///     bytes[0] = 0;
/// }
/// ```
///
/// Dropping it without an explicit end returns it to the generated free
/// list and is counted as `generated_abandoned`.
pub struct GeneratedFrame<'engine, 'memory> {
    engine: &'engine mut RxFillEngine<'memory>,
    token: FrameToken,
    descriptor: ValidatedDescriptor,
    resolved: bool,
}

impl GeneratedFrame<'_, '_> {
    /// The canonical UMEM frame (in the generated pool).
    #[must_use]
    pub const fn frame(&self) -> FrameId {
        self.descriptor.frame()
    }

    /// The exact ledger ownership cycle (frame and generation).
    #[must_use]
    pub const fn token(&self) -> FrameToken {
        self.token
    }

    /// The TX geometry: frame base plus headroom, the requested length.
    #[must_use]
    pub const fn descriptor(&self) -> ValidatedDescriptor {
        self.descriptor
    }

    /// Visible length: exactly the requested length.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.descriptor.len()
    }

    /// Always `false`: a zero length is refused.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.descriptor.is_empty()
    }

    /// The visible bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.engine
            .state
            .frames
            .leased_bytes(self.token, self.descriptor)
            .expect("a live GeneratedFrame owns its Leased frame")
    }

    /// The visible bytes, for writing the packet.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        self.engine
            .state
            .frames
            .leased_bytes_mut(self.token, self.descriptor)
            .expect("a live GeneratedFrame owns its Leased frame")
    }

    /// Returns the frame to the generated free list without transmitting.
    pub fn cancel(mut self) {
        self.resolved = true;
        let state = &mut self.engine.state;
        state.release_generated(self.token);
        bump(&mut state.generated_counters.generated_cancelled);
    }

    /// Hands the frame to TX (`PendingTx`) with the written bytes and the
    /// requested length, for [`RxFillEngine::submit_tx`] or
    /// [`RxFillEngine::submit_tx_batch`] next to forwarded frames.
    /// [`RxFillEngine::cancel_tx_handoff`] returns it to the generated free
    /// list.
    pub fn stage_tx(mut self) -> TxHandoff {
        self.stage()
    }

    /// Stages the frame and submits it at once through the same TX path,
    /// in-flight bound, and back-pressure as forwarded frames. A refused
    /// submission ([`crate::TxBlocked`] or a ring error) hands the generated
    /// handoff back in [`TxRejected`] for a retry or a cancel.
    // Boxing the refusal would allocate on the back-pressure path.
    #[allow(clippy::result_large_err)]
    pub fn commit(mut self) -> Result<TxSubmitReport, TxRejected> {
        let handoff = self.stage();
        self.engine.submit_tx(handoff)
    }

    fn stage(&mut self) -> TxHandoff {
        self.resolved = true;
        let state = &mut self.engine.state;
        state
            .frames
            .ledger_mut()
            .stage_tx(self.token)
            .expect("a live GeneratedFrame owns its Leased frame");
        state.generated.leased -= 1;
        state.generated.handoffs += 1;
        TxHandoff {
            engine: state.engine_id,
            token: self.token,
            descriptor: self.descriptor,
        }
    }
}

impl Drop for GeneratedFrame<'_, '_> {
    fn drop(&mut self) {
        if !self.resolved {
            let state = &mut self.engine.state;
            state.release_generated(self.token);
            bump(&mut state.generated_counters.generated_abandoned);
        }
    }
}

impl fmt::Debug for GeneratedFrame<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedFrame")
            .field("frame", &self.descriptor.frame())
            .field("len", &self.descriptor.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl RxFillEngine<'_> {
    /// Moves a free generated frame's generation to `u64::MAX`, so its next
    /// allocation exhausts the generation.
    pub(crate) fn exhaust_generated_generation_for_test(&mut self, frame: u32) {
        self.state
            .frames
            .ledger_mut()
            .set_free_generation_for_test(frame, u64::MAX);
    }

    /// Loses one generated free-list entry behind the ledger's back.
    pub(crate) fn drop_generated_free_entry_for_test(&mut self) -> Option<u32> {
        self.state.generated_free.pop()
    }

    /// Lists a frame in the generated free list behind the ledger's back.
    pub(crate) fn push_generated_free_entry_for_test(&mut self, frame: u32) -> bool {
        self.state.generated_free.push(frame)
    }

    /// Moves `frame` to the head of the generated free list (a rotation of
    /// the FIFO; the ledger is untouched), so the next allocation selects
    /// it. Returns whether the frame was free.
    pub(crate) fn prefer_generated_free_for_test(&mut self, frame: u32) -> bool {
        let free = &mut self.state.generated_free;
        let len = free.len();
        if !free.iter().any(|entry| entry == frame) {
            return false;
        }
        for _ in 0..len {
            let head = free.pop().expect("nonempty");
            if head == frame {
                // Put it back at the head by rotating the rest behind it.
                let pushed = free.push(head);
                debug_assert!(pushed);
                for _ in 1..len {
                    let next = free.pop().expect("nonempty");
                    let pushed = free.push(next);
                    debug_assert!(pushed);
                }
                return true;
            }
            let pushed = free.push(head);
            debug_assert!(pushed);
        }
        false
    }

    /// Skews the generated handoff record behind the ledger's back.
    pub(crate) fn skew_generated_handoffs_for_test(&mut self, delta: i32) {
        let handoffs = &mut self.state.generated.handoffs;
        *handoffs = handoffs.wrapping_add_signed(delta);
    }
}
