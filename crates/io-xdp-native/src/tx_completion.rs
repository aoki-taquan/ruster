//! TX/Completion half of the AF_XDP datapath engine (M2 S4, X02).
//!
//! The same [`RxFillEngine`] that owns the Fill and RX rings owns the TX
//! producer, the Completion consumer, and the socket's kick handle, so one
//! ledger records every frame of the UMEM. A frame forwarded without copy
//! moves `Leased` (an [`crate::RxFrame`], rewritten in place by core) →
//! `PendingTx` ([`TxHandoff`], held by the caller) → `TxReserved` →
//! `TxOwnedByKernel` (descriptor published to TX, in flight) →
//! `CompletionAvailable` → `Free` (back in the free list, republished to
//! Fill by the next refill). A handoff that cannot be submitted stays a
//! handoff: the caller retries it or cancels it (`PendingTx` → `Leased` →
//! `Free`).
//!
//! In-flight TX (published and not yet completed) never exceeds the TX ring
//! capacity, which engine setup requires to be at most the Completion ring
//! capacity, so every in-flight frame always has a Completion slot.
//! Completions are reaped in bounded batches and validated against the
//! ledger and the exact submitted address before a frame is freed.

use std::fmt;

use ruster_io_xdp::{FrameStateKind, FrameToken, LedgerError, RawDescriptor};

use super::{add, bump, EngineState, RxFillEngine, RxFillError, TxHandoff};
use crate::{
    abi::XdpDescriptor,
    native_unsafe::kick::{KickError, KickOutcome, KickRing},
    NativeRingError, NeedWakeup,
};

/// Why a TX submission left handoffs unsubmitted. Every such handoff is
/// unchanged and recoverable: retry it later, or cancel it with
/// [`RxFillEngine::cancel_tx_handoff`] (which recycles its frame to the
/// free list and from there to Fill).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxBlocked {
    /// The TX ring had no free slot: the kernel has not consumed earlier
    /// descriptors yet. Kick ([`RxFillEngine::wake_tx`]) and retry.
    RingFull,
    /// In-flight TX reached the TX ring capacity (BACKEND-004): completions
    /// lag. Reap them ([`RxFillEngine::poll`] or
    /// [`RxFillEngine::reap_completions`]) and retry.
    InflightLimit,
    /// [`RxFillEngine::drain`] started; no new TX is accepted.
    Draining,
}

/// Outcome of a TX submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct TxSubmitReport {
    submitted: u32,
    blocked: Option<TxBlocked>,
    need_wakeup: Result<NeedWakeup, NativeRingError>,
}

impl TxSubmitReport {
    /// Handoffs published to the TX ring by this call.
    #[must_use]
    pub const fn submitted(self) -> u32 {
        self.submitted
    }

    /// Why handoffs were left unsubmitted, if any were.
    #[must_use]
    pub const fn blocked(self) -> Option<TxBlocked> {
        self.blocked
    }

    /// The TX need-wakeup flag observed at the end of the call (after the
    /// Release publication, if one happened). In copy mode Linux transmits
    /// only from `sendto`, and keeps this flag set; answer `Required` with
    /// [`RxFillEngine::wake_tx`].
    pub const fn need_wakeup(self) -> Result<NeedWakeup, NativeRingError> {
        self.need_wakeup
    }
}

/// A batch submission refused before anything was submitted. Every handoff
/// is still in its slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxSubmitError {
    /// The handoff at `index` is not the current `PendingTx` owner of a
    /// frame in this engine's ledger (another engine's handoff), or its
    /// geometry does not match this ledger's layout.
    Handoff {
        /// Slot index of the refused handoff.
        index: usize,
        /// Ledger refusal.
        error: LedgerError,
    },
    /// A TX ring cursor was corrupt.
    Ring(NativeRingError),
}

impl fmt::Display for TxSubmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for TxSubmitError {}

/// Why [`RxFillEngine::submit_tx`] refused one handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxRejection {
    /// Recoverable back-pressure; see [`TxBlocked`].
    Blocked(TxBlocked),
    /// The handoff does not belong to this engine's ledger (see
    /// [`TxSubmitError::Handoff`]).
    Invalid(LedgerError),
    /// A TX ring cursor was corrupt.
    Ring(NativeRingError),
}

/// A handoff returned unsubmitted, with the reason.
///
/// Dropping it drops the handoff, which strands the frame (debug builds
/// assert): take it back with [`Self::into_handoff`].
#[must_use = "the refused handoff must be retried or cancelled"]
#[derive(Debug)]
pub struct TxRejected {
    reason: TxRejection,
    handoff: TxHandoff,
}

impl TxRejected {
    /// Why the handoff was not submitted.
    #[must_use]
    pub const fn reason(&self) -> TxRejection {
        self.reason
    }

    /// The unchanged handoff, for a retry or a cancel.
    pub fn into_handoff(self) -> TxHandoff {
        self.handoff
    }
}

/// Why a completion entry was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionInvalidReason {
    /// The address lies outside the registered UMEM. Nothing is mutated.
    AddressOutsideUmem,
    /// The addressed frame is not in flight on TX: a duplicate completion,
    /// or a frame owned by Fill, RX, the caller, or quarantine. Nothing is
    /// mutated, so a kernel completion can never free a frame that someone
    /// else owns.
    NotInFlight,
    /// The frame is in flight, but the address is not the exact descriptor
    /// address that was submitted (Linux returns `desc.addr` verbatim).
    /// Whether the kernel is done with the frame is unknown, so it is
    /// quarantined (fail closed): never recycled, never lent again.
    AddressMismatch,
}

impl CompletionInvalidReason {
    /// Number of reasons.
    pub const COUNT: usize = 3;

    /// Every reason in declaration order; `ALL[reason.index()] == reason`.
    pub const ALL: [Self; Self::COUNT] = [
        Self::AddressOutsideUmem,
        Self::NotInFlight,
        Self::AddressMismatch,
    ];

    /// Dense index into [`Self::ALL`].
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::AddressOutsideUmem => 0,
            Self::NotInFlight => 1,
            Self::AddressMismatch => 2,
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AddressOutsideUmem => "ADDRESS_OUTSIDE_UMEM",
            Self::NotInFlight => "NOT_IN_FLIGHT",
            Self::AddressMismatch => "ADDRESS_MISMATCH",
        }
    }
}

/// Outcome of one bounded completion reap.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[must_use]
pub struct CompletionReport {
    reaped: u32,
    invalid: u32,
    backlogged: bool,
}

impl CompletionReport {
    /// Valid completions whose frames returned to the free list.
    #[must_use]
    pub const fn reaped(self) -> u32 {
        self.reaped
    }

    /// Refused completion entries consumed by this reap.
    #[must_use]
    pub const fn invalid(self) -> u32 {
        self.invalid
    }

    /// Whether entries were left in the Completion ring by the bound.
    #[must_use]
    pub const fn backlogged(self) -> bool {
        self.backlogged
    }
}

/// Completion lag, in O(1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionLag {
    in_flight: u32,
    oldest_age_polls: Option<u64>,
}

impl CompletionLag {
    /// Frames published to TX and not yet completed.
    #[must_use]
    pub const fn in_flight(self) -> u32 {
        self.in_flight
    }

    /// Engine polls since the oldest in-flight frame was submitted, or
    /// `None` with nothing in flight. The engine has no clock; the caller
    /// converts polls to time with its own tick period.
    #[must_use]
    pub const fn oldest_age_polls(self) -> Option<u64> {
        self.oldest_age_polls
    }
}

/// Saturating TX/Completion counters (OBS-018, TX/Completion half).
///
/// Monotonic fields only grow; [`Self::tx_inflight`] is the current gauge
/// and [`Self::tx_inflight_highwater`] its peak. Updating them is a handful
/// of integer operations per call; nothing scans the ledger.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct TxCounters {
    /// Frames published to the TX ring.
    pub tx_submitted: u64,
    /// Submissions that left handoffs behind because the TX ring was full.
    pub tx_ring_full: u64,
    /// Submissions that left handoffs behind at the in-flight limit.
    pub tx_inflight_limited: u64,
    /// Submissions refused because a drain started.
    pub tx_refused_draining: u64,
    /// Valid completions; their frames returned to the free list.
    pub tx_completed: u64,
    /// Valid completions that were not for the oldest in-flight frame.
    pub tx_completions_reordered: u64,
    /// Reaps that left entries in the Completion ring.
    pub completion_backlogged: u64,
    /// Submissions that observed the kernel requesting a TX wakeup.
    pub tx_need_wakeup: u64,
    /// Submissions whose TX flags word had unknown bits.
    pub tx_flag_errors: u64,
    /// TX kicks (`sendto`) performed.
    pub tx_kicks: u64,
    /// Fill kicks (`poll`) performed.
    pub fill_kicks: u64,
    /// Kicks the kernel deferred (`EAGAIN`, `EBUSY`, `ENOBUFS`, `EINTR`).
    pub kicks_deferred: u64,
    /// Kicks that failed with a typed [`KickError`].
    pub kick_errors: u64,
    /// Calls to [`RxFillEngine::drain`].
    pub drains: u64,
    /// Frames currently published to TX and not completed.
    pub tx_inflight: u32,
    /// Peak of [`Self::tx_inflight`] over the engine lifetime.
    pub tx_inflight_highwater: u32,
    tx_invalid_completion: [u64; CompletionInvalidReason::COUNT],
}

impl TxCounters {
    /// Refused completion entries of one reason.
    #[must_use]
    pub const fn tx_invalid_completion(&self, reason: CompletionInvalidReason) -> u64 {
        self.tx_invalid_completion[reason.index()]
    }

    /// Refused completion entries of every reason.
    #[must_use]
    pub fn tx_invalid_completion_total(&self) -> u64 {
        self.tx_invalid_completion
            .iter()
            .fold(0_u64, |total, value| total.saturating_add(*value))
    }
}

/// One published, not yet completed TX frame.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InflightEntry {
    pub(super) token: FrameToken,
    /// The exact descriptor address submitted (`desc.addr`).
    pub(super) address: u64,
    /// `polls` at submission.
    pub(super) stamp: u64,
}

/// Fixed-capacity, submission-ordered list of in-flight TX frames.
///
/// Linux completes in submission order, so the matching entry is normally
/// the head (O(1)). A reordered completion removes from the middle,
/// bounded by the TX ring capacity, and is counted.
pub(super) struct InflightFifo {
    slots: Box<[Option<InflightEntry>]>,
    head: usize,
    len: usize,
}

impl InflightFifo {
    pub(super) fn new(capacity: u32) -> Self {
        Self {
            slots: vec![None; capacity as usize].into_boxed_slice(),
            head: 0,
            len: 0,
        }
    }

    pub(super) const fn len(&self) -> usize {
        self.len
    }

    pub(super) fn free(&self) -> usize {
        self.slots.len() - self.len
    }

    fn slot(&self, offset: usize) -> usize {
        (self.head + offset) % self.slots.len()
    }

    fn push(&mut self, entry: InflightEntry) -> bool {
        if self.len == self.slots.len() {
            return false;
        }
        let tail = self.slot(self.len);
        self.slots[tail] = Some(entry);
        self.len += 1;
        true
    }

    pub(super) fn oldest(&self) -> Option<InflightEntry> {
        if self.len == 0 {
            None
        } else {
            self.slots[self.head]
        }
    }

    /// Removes the entry of `token`; returns it and its offset from head.
    fn remove(&mut self, token: FrameToken) -> Option<(InflightEntry, usize)> {
        let offset = (0..self.len).find(|offset| {
            self.slots[self.slot(*offset)].is_some_and(|entry| entry.token == token)
        })?;
        let entry = self.slots[self.slot(offset)].take()?;
        if offset == 0 {
            self.head = self.slot(1);
        } else {
            // Close the gap: shift the younger entries one slot toward head.
            for later in offset..self.len - 1 {
                let from = self.slot(later + 1);
                let to = self.slot(later);
                self.slots[to] = self.slots[from].take();
            }
        }
        self.len -= 1;
        Some((entry, offset))
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = InflightEntry> + '_ {
        (0..self.len).filter_map(|offset| self.slots[self.slot(offset)])
    }
}

/// Every frame of the RX pool by owner, from O(1) ledger counts.
///
/// The fields partition `0..rx_frames`, so [`Self::total`] always equals
/// [`Self::rx_frames`]; [`RxFillEngine::audit`] checks that and that each
/// frame sits in exactly one engine list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct FrameAccounting {
    /// Size of the RX pool.
    pub rx_frames: u32,
    /// In the free list (user space, reusable).
    pub free: u32,
    /// Published to Fill: the kernel holds them until it returns them on
    /// RX, or the socket closes.
    pub fill_in_kernel: u32,
    /// Validated RX frames waiting to be lent.
    pub rx_pending: u32,
    /// Lent as an [`crate::RxFrame`] right now (zero whenever the engine
    /// is not borrowed by a frame).
    pub leased: u32,
    /// Held by the caller as [`TxHandoff`]s.
    pub tx_handoffs: u32,
    /// Published to TX and not completed: the kernel holds them.
    pub tx_in_flight: u32,
    /// Permanently removed from reuse.
    pub quarantined: u32,
}

impl FrameAccounting {
    /// Sum over all owners.
    #[must_use]
    pub const fn total(self) -> u32 {
        self.free
            + self.fill_in_kernel
            + self.rx_pending
            + self.leased
            + self.tx_handoffs
            + self.tx_in_flight
            + self.quarantined
    }

    /// Frames the kernel holds (Fill or TX).
    #[must_use]
    pub const fn in_kernel(self) -> u32 {
        self.fill_in_kernel + self.tx_in_flight
    }
}

/// Whether a drain returned every TX frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainOutcome {
    /// No frame is in flight on TX. Frames still published to Fill
    /// ([`FrameAccounting::fill_in_kernel`]) stay with the kernel until it
    /// returns them on RX or the socket closes; that is expected at
    /// shutdown and not reported as a failure.
    Drained,
    /// Frames are still in flight on TX: the kernel has not completed them
    /// within the caller's bound. They are not counted as returned; drain
    /// again, or close the socket (which ends kernel use of the UMEM).
    TxInFlight {
        /// Frames still published to TX.
        frames: u32,
    },
}

/// Result of one [`RxFillEngine::drain`] call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct DrainReport {
    outcome: DrainOutcome,
    rounds: u32,
    completed: u32,
    rx_pending_released: u32,
    last_kick_error: Option<KickError>,
    accounting: FrameAccounting,
}

impl DrainReport {
    /// Whether every TX frame came back.
    #[must_use]
    pub const fn outcome(self) -> DrainOutcome {
        self.outcome
    }

    /// Reap rounds used (at most the caller's bound).
    #[must_use]
    pub const fn rounds(self) -> u32 {
        self.rounds
    }

    /// Valid completions reaped by this call.
    #[must_use]
    pub const fn completed(self) -> u32 {
        self.completed
    }

    /// Validated, unlent RX frames returned to the free list by this call.
    #[must_use]
    pub const fn rx_pending_released(self) -> u32 {
        self.rx_pending_released
    }

    /// The last typed kick failure seen while draining, if any.
    #[must_use]
    pub const fn last_kick_error(self) -> Option<KickError> {
        self.last_kick_error
    }

    /// Owner of every RX-pool frame after the drain.
    #[must_use]
    pub const fn accounting(self) -> FrameAccounting {
        self.accounting
    }
}

impl EngineState<'_> {
    /// Checks, without mutation, that `handoff` is the current `PendingTx`
    /// owner of its frame in this ledger and that its geometry is exactly
    /// what this ledger's layout validates.
    pub(super) fn verify_handoff(&self, handoff: &TxHandoff) -> Result<(), LedgerError> {
        let ledger = self.frames.ledger();
        ledger.check(handoff.token, FrameStateKind::PendingTx)?;
        let descriptor = handoff.descriptor;
        if descriptor.frame() != handoff.token.frame() {
            return Err(LedgerError::DescriptorFrameAlias {
                token_frame: handoff.token.frame(),
                descriptor_frame: descriptor.frame(),
            });
        }
        let revalidated = ledger.layout().validate_descriptor(RawDescriptor {
            addr: descriptor.frame_base() + u64::from(descriptor.data_offset()),
            len: descriptor.len(),
            options: 0,
        });
        // Equality includes the hidden domain binding.
        if revalidated != Ok(descriptor) {
            return Err(LedgerError::ForeignDescriptorDomain);
        }
        Ok(())
    }

    fn tx_descriptor(handoff: &TxHandoff) -> XdpDescriptor {
        let descriptor = handoff.descriptor;
        XdpDescriptor {
            address: descriptor.frame_base() + u64::from(descriptor.data_offset()),
            len: descriptor.len(),
            options: 0,
        }
    }

    /// Validates and applies one completion address.
    fn complete(&mut self, address: u64) -> Result<(), CompletionInvalidReason> {
        if address >= self.umem_len {
            return Err(CompletionInvalidReason::AddressOutsideUmem);
        }
        let Ok(index) = u32::try_from(address / self.frame_size) else {
            return Err(CompletionInvalidReason::AddressOutsideUmem);
        };
        let ledger = self.frames.ledger();
        let Ok(view) = ledger.state(index) else {
            return Err(CompletionInvalidReason::AddressOutsideUmem);
        };
        let (FrameStateKind::TxOwnedByKernel, Some(token)) = (view.kind(), view.token()) else {
            return Err(CompletionInvalidReason::NotInFlight);
        };
        let (entry, offset) = self
            .inflight
            .remove(token)
            .expect("every TxOwnedByKernel frame is listed in flight");
        self.tx_counters.tx_inflight = self.tx_counters.tx_inflight.saturating_sub(1);
        if entry.address != address {
            self.frames
                .ledger_mut()
                .quarantine_kernel_tx(token)
                .expect("checked TxOwnedByKernel with this token");
            bump(&mut self.counters.frames_quarantined);
            return Err(CompletionInvalidReason::AddressMismatch);
        }
        if offset != 0 {
            bump(&mut self.tx_counters.tx_completions_reordered);
        }
        let ledger = self.frames.ledger_mut();
        ledger
            .complete_tx(token)
            .expect("checked TxOwnedByKernel with this token");
        ledger
            .recycle_completion(token)
            .expect("completed under the same borrow");
        let pushed = self.free.push(index);
        debug_assert!(pushed, "each Free transition enters the free list once");
        bump(&mut self.tx_counters.tx_completed);
        Ok(())
    }

    /// Returns validated, unlent RX frames to the free list.
    fn release_pending_rx(&mut self) -> u32 {
        let mut released = 0;
        while let Some(token) = self.pending.pop() {
            let ledger = self.frames.ledger_mut();
            ledger
                .lease_rx(token)
                .expect("pending holds RxAvailable tokens");
            ledger
                .recycle_lease(token)
                .expect("leased under the same borrow");
            let pushed = self.free.push(token.frame().index());
            debug_assert!(pushed, "each Free transition enters the free list once");
            released += 1;
        }
        released
    }

    fn note_kick(&mut self, ring: KickRing, result: Result<KickOutcome, KickError>) {
        let counters = &mut self.tx_counters;
        match ring {
            KickRing::Tx => bump(&mut counters.tx_kicks),
            KickRing::Fill => bump(&mut counters.fill_kicks),
        }
        match result {
            Ok(KickOutcome::Woken) => {}
            Ok(KickOutcome::Deferred(_)) => bump(&mut counters.kicks_deferred),
            Err(_) => bump(&mut counters.kick_errors),
        }
    }

    pub(super) fn accounting(&self) -> FrameAccounting {
        let counts = self.frames.ledger().counts();
        let count = |kind| u32::try_from(counts.get(kind)).expect("bounded by u32 frames");
        let generated = self.frames.ledger().layout().frame_count() - self.rx_frames;
        FrameAccounting {
            rx_frames: self.rx_frames,
            // Generated-pool frames are never used by this engine, so they
            // are the only Free frames outside the RX pool.
            free: count(FrameStateKind::Free).saturating_sub(generated),
            fill_in_kernel: count(FrameStateKind::FillOwnedByKernel)
                + count(FrameStateKind::FillReserved),
            rx_pending: count(FrameStateKind::RxAvailable),
            leased: count(FrameStateKind::Leased),
            tx_handoffs: count(FrameStateKind::PendingTx),
            tx_in_flight: count(FrameStateKind::TxOwnedByKernel)
                + count(FrameStateKind::TxReserved)
                + count(FrameStateKind::CompletionAvailable),
            quarantined: count(FrameStateKind::Quarantined),
        }
    }
}

impl RxFillEngine<'_> {
    /// Submits one handoff to the TX ring without copying: the descriptor
    /// is the frame's validated RX geometry (core rewrote the bytes in
    /// place and kept the length).
    ///
    /// On refusal the unchanged handoff comes back in [`TxRejected`] for a
    /// retry or [`Self::cancel_tx_handoff`]. Call [`Self::wake_tx`] when
    /// the report asks for a wakeup.
    // Boxing the refusal would allocate on the back-pressure path.
    #[allow(clippy::result_large_err)]
    pub fn submit_tx(&mut self, handoff: TxHandoff) -> Result<TxSubmitReport, TxRejected> {
        let mut slot = [Some(handoff)];
        let result = self.submit_tx_batch(&mut slot);
        let [slot] = slot;
        match (result, slot) {
            (Ok(report), None) => Ok(report),
            (Ok(report), Some(handoff)) => Err(TxRejected {
                reason: TxRejection::Blocked(
                    report.blocked.expect("an unsubmitted handoff was blocked"),
                ),
                handoff,
            }),
            (Err(TxSubmitError::Handoff { error, .. }), Some(handoff)) => Err(TxRejected {
                reason: TxRejection::Invalid(error),
                handoff,
            }),
            (Err(TxSubmitError::Ring(error)), Some(handoff)) => Err(TxRejected {
                reason: TxRejection::Ring(error),
                handoff,
            }),
            (Err(_), None) => unreachable!("a refused batch keeps every handoff"),
        }
    }

    /// Submits the handoffs of `handoffs` in slot order with one TX
    /// reservation and one Release publication, taking each submitted one
    /// out of its slot.
    ///
    /// At most `min(TX ring room, TX capacity - in flight)` handoffs are
    /// submitted (BACKEND-004). The rest stay in their slots, unchanged,
    /// and [`TxSubmitReport::blocked`] says why; a partial submission is
    /// normal back-pressure, not an error. Before anything is submitted,
    /// every handoff that would be submitted is checked against the ledger
    /// (and geometry); one refusal returns [`TxSubmitError`] with nothing
    /// submitted and every slot unchanged.
    pub fn submit_tx_batch(
        &mut self,
        handoffs: &mut [Option<TxHandoff>],
    ) -> Result<TxSubmitReport, TxSubmitError> {
        let candidates = handoffs.iter().filter(|slot| slot.is_some()).count();
        let state = &mut self.state;
        let mut report = TxSubmitReport {
            submitted: 0,
            blocked: None,
            need_wakeup: Ok(NeedWakeup::NotRequired),
        };
        if candidates > 0 && state.draining {
            bump(&mut state.tx_counters.tx_refused_draining);
            report.blocked = Some(TxBlocked::Draining);
        } else if candidates > 0 {
            let room = self.tx.free_slots().map_err(TxSubmitError::Ring)? as usize;
            let allowance = room.min(state.inflight.free());
            let take = allowance.min(candidates);
            if take < candidates {
                if room <= state.inflight.free() {
                    bump(&mut state.tx_counters.tx_ring_full);
                    report.blocked = Some(TxBlocked::RingFull);
                } else {
                    bump(&mut state.tx_counters.tx_inflight_limited);
                    report.blocked = Some(TxBlocked::InflightLimit);
                }
            }
            if take > 0 {
                Self::publish_tx(&mut self.tx, state, handoffs, take)?;
                report.submitted = u32::try_from(take).expect("bounded by the u32 ring");
            }
        }
        report.need_wakeup = self.tx.need_wakeup();
        let counters = &mut self.state.tx_counters;
        match report.need_wakeup {
            Ok(NeedWakeup::Required) => bump(&mut counters.tx_need_wakeup),
            Ok(NeedWakeup::NotRequired) => {}
            Err(_) => bump(&mut counters.tx_flag_errors),
        }
        Ok(report)
    }

    /// Verifies, reserves, writes, publishes, and records the first `take`
    /// handoffs. Nothing is changed unless all of it succeeds.
    fn publish_tx(
        tx: &mut crate::TxProducer<'_>,
        state: &mut EngineState<'_>,
        handoffs: &mut [Option<TxHandoff>],
        take: usize,
    ) -> Result<(), TxSubmitError> {
        let chosen = || {
            handoffs
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| slot.as_ref().map(|handoff| (index, handoff)))
                .take(take)
        };
        for (index, handoff) in chosen() {
            state
                .verify_handoff(handoff)
                .map_err(|error| TxSubmitError::Handoff { index, error })?;
        }
        let count = u32::try_from(take).expect("bounded by the u32 ring");
        let mut reservation = tx.reserve(count).map_err(TxSubmitError::Ring)?;
        for (_, handoff) in chosen() {
            state
                .frames
                .ledger_mut()
                .reserve_tx(handoff.token)
                .expect("verified PendingTx");
            reservation
                .write(EngineState::tx_descriptor(handoff))
                .expect("writes stay within the reservation");
        }
        if let Err(error) = reservation.release_submit() {
            for (_, handoff) in chosen() {
                state
                    .frames
                    .ledger_mut()
                    .cancel_tx_reservation(handoff.token)
                    .expect("reserved above");
            }
            return Err(TxSubmitError::Ring(error));
        }
        let stamp = state.counters.polls;
        let mut published = 0;
        for slot in handoffs.iter_mut() {
            if published == take {
                break;
            }
            let Some(handoff) = slot.take() else {
                continue;
            };
            let address = EngineState::tx_descriptor(&handoff).address;
            let token = handoff.defuse();
            state
                .frames
                .ledger_mut()
                .publish_tx(token)
                .expect("reserved above");
            let pushed = state.inflight.push(InflightEntry {
                token,
                address,
                stamp,
            });
            debug_assert!(pushed, "bounded by the in-flight allowance");
            published += 1;
        }
        let counters = &mut state.tx_counters;
        add(&mut counters.tx_submitted, count);
        counters.tx_inflight = u32::try_from(state.inflight.len()).expect("bounded by u32 ring");
        counters.tx_inflight_highwater = counters.tx_inflight_highwater.max(counters.tx_inflight);
        Ok(())
    }

    /// Consumes at most `budget` Completion entries, validates each, and
    /// returns completed frames to the free list (the next refill
    /// republishes them to Fill).
    ///
    /// [`Self::poll`] calls this first with a budget of the TX capacity,
    /// so frames return to Fill before RX needs them (BACKEND-004).
    pub fn reap_completions(&mut self, budget: u32) -> Result<CompletionReport, RxFillError> {
        let available = self.completion.available().map_err(RxFillError::Ring)?;
        let take = available.min(budget);
        let mut report = CompletionReport {
            backlogged: available > take,
            ..CompletionReport::default()
        };
        if report.backlogged {
            bump(&mut self.state.tx_counters.completion_backlogged);
        }
        if take == 0 {
            return Ok(report);
        }
        let mut acquisition = self.completion.acquire(take).map_err(RxFillError::Ring)?;
        for _ in 0..take {
            let address = acquisition.read().map_err(RxFillError::Ring)?;
            match self.state.complete(address) {
                Ok(()) => report.reaped += 1,
                Err(reason) => {
                    bump(&mut self.state.tx_counters.tx_invalid_completion[reason.index()]);
                    report.invalid += 1;
                }
            }
        }
        acquisition.release_consume().map_err(RxFillError::Ring)?;
        Ok(report)
    }

    /// Acquire-loads the TX need-wakeup flag (one atomic load).
    pub fn tx_needs_wakeup(&self) -> Result<NeedWakeup, NativeRingError> {
        self.tx.need_wakeup()
    }

    /// Kicks TX: `sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0)` on the
    /// bundle's socket. Copy mode transmits only from this call; zero-copy
    /// drivers need it when [`Self::tx_needs_wakeup`] is `Required`.
    pub fn wake_tx(&mut self) -> Result<KickOutcome, KickError> {
        let result = self.kick.kick(KickRing::Tx);
        self.state.note_kick(KickRing::Tx, result);
        result
    }

    /// Kicks Fill: `poll(fd, POLLIN, 0)` on the bundle's socket, for
    /// zero-copy drivers when [`Self::fill_needs_wakeup`] is `Required`.
    /// It never sleeps.
    pub fn wake_fill(&mut self) -> Result<KickOutcome, KickError> {
        let result = self.kick.kick(KickRing::Fill);
        self.state.note_kick(KickRing::Fill, result);
        result
    }

    /// TX/Completion counter snapshot.
    #[must_use]
    pub const fn tx_counters(&self) -> TxCounters {
        self.state.tx_counters
    }

    /// Frames published to TX and not yet completed.
    #[must_use]
    pub fn tx_inflight(&self) -> u32 {
        u32::try_from(self.state.inflight.len()).expect("bounded by the u32 ring")
    }

    /// The in-flight bound: the TX ring capacity.
    #[must_use]
    pub const fn tx_inflight_limit(&self) -> u32 {
        self.tx.capacity()
    }

    /// In-flight count and the age of the oldest in-flight frame.
    #[must_use]
    pub fn completion_lag(&self) -> CompletionLag {
        CompletionLag {
            in_flight: self.tx_inflight(),
            oldest_age_polls: self
                .state
                .inflight
                .oldest()
                .map(|entry| self.state.counters.polls.saturating_sub(entry.stamp)),
        }
    }

    /// Owner of every RX-pool frame, from O(1) ledger counts.
    #[must_use]
    pub fn frame_accounting(&self) -> FrameAccounting {
        self.state.accounting()
    }

    /// Whether [`Self::drain`] was called. Draining is permanent.
    #[must_use]
    pub const fn is_draining(&self) -> bool {
        self.state.draining
    }

    /// Shutdown drain: stops new TX and Fill publication (permanently),
    /// returns validated unlent RX frames to the free list, then runs at
    /// most `rounds` rounds of "kick TX if the kernel asks, reap up to the
    /// TX capacity of completions" until nothing is in flight.
    ///
    /// Every frame returns to the ledger's free list exactly once, through
    /// the same validated completion path as [`Self::reap_completions`].
    /// Frames the kernel still holds are reported, never assumed returned:
    /// [`DrainOutcome::TxInFlight`] for TX, and
    /// [`FrameAccounting::fill_in_kernel`] for Fill (released only when the
    /// kernel returns them on RX, which [`Self::poll`] still processes, or
    /// when the socket closes). The engine has no clock: the caller bounds
    /// the work with `rounds` and may call again, for example after a
    /// sleep, until the outcome is [`DrainOutcome::Drained`] or its own
    /// timeout expires.
    pub fn drain(&mut self, rounds: u32) -> Result<DrainReport, RxFillError> {
        self.state.draining = true;
        bump(&mut self.state.tx_counters.drains);
        let rx_pending_released = self.state.release_pending_rx();
        let mut used = 0;
        let mut completed = 0;
        let mut last_kick_error = None;
        while used < rounds && self.state.inflight.len() != 0 {
            used += 1;
            if self.tx_needs_wakeup() == Ok(NeedWakeup::Required) {
                if let Err(error) = self.wake_tx() {
                    last_kick_error = Some(error);
                }
            }
            let budget = self.tx.capacity();
            completed += self.reap_completions(budget)?.reaped();
        }
        let accounting = self.state.accounting();
        let outcome = match self.tx_inflight() {
            0 => DrainOutcome::Drained,
            frames => DrainOutcome::TxInFlight { frames },
        };
        Ok(DrainReport {
            outcome,
            rounds: used,
            completed,
            rx_pending_released,
            last_kick_error,
            accounting,
        })
    }
}

#[cfg(test)]
impl RxFillEngine<'_> {
    /// Loses the oldest in-flight entry behind the ledger's back.
    pub(crate) fn drop_inflight_entry_for_test(&mut self) -> Option<InflightEntry> {
        let entry = self.state.inflight.oldest()?;
        self.state
            .inflight
            .remove(entry.token)
            .map(|(entry, _)| entry)
    }

    /// Lists an in-flight entry (again).
    pub(crate) fn push_inflight_entry_for_test(&mut self, entry: InflightEntry) {
        assert!(self.state.inflight.push(entry), "test list has room");
    }
}
