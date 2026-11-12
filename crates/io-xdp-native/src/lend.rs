//! Sending a received frame out through another socket of the same UMEM.
//!
//! Sockets that share one registered UMEM can name each other's frames on
//! their rings. A frame received by one engine (its home) is then
//! transmitted by another engine's socket without a copy: the home engine's
//! ledger moves the frame to `TxOwnedByKernel` exactly as for its own TX
//! ring, the descriptor is written to the other engine's TX ring, and the
//! other engine lists it in flight under the home engine's id.
//!
//! The completion arrives on the other socket's Completion ring. That
//! engine matches it by its exact address against the frames it sent for
//! others, and keeps it as a [`LentCompletion`] until the caller (the core
//! adapter, which owns every engine of the UMEM) takes it with
//! [`RxFillEngine::take_lent_completion`] and gives it to the home engine's
//! [`RxFillEngine::complete_lent`]. Only then is the frame `Free` again and
//! back in its home RX free list: a frame never changes its pool.
//!
//! Byte access stays sound for the reason `native_unsafe/umem.rs` gives:
//! the home ledger records the frame as `TxOwnedByKernel` from before the
//! descriptor is published until its validated completion came back, so no
//! reference into it is formed while the kernel reads it.

use ruster_io_xdp::{FrameStateKind, FrameToken, LedgerError};

use super::{
    add, bump,
    tx_completion::{InflightEntry, TxRejected, TxRejection, TxSubmitReport},
    CompletionInvalidReason, EngineState, RxFillEngine, TxBlocked, TxHandoff,
};
use crate::{abi::XdpDescriptor, NeedWakeup};

/// The completion of a frame that was sent out through another engine's TX
/// ring, on its way back to the frame's home engine.
///
/// Dropping it strands the frame in `TxOwnedByKernel` for good (it is never
/// reused, which is safe); give it to [`RxFillEngine::complete_lent`].
#[must_use = "a lent frame returns to its pool only through complete_lent"]
#[derive(Debug)]
pub struct LentCompletion {
    home: u64,
    token: FrameToken,
}

impl EngineState<'_> {
    /// A completion whose address is outside this engine's part: the oldest
    /// frame this engine sent for another one at exactly that address.
    pub(super) fn complete_for_another(
        &mut self,
        address: u64,
    ) -> Result<(), CompletionInvalidReason> {
        let own = self.engine_id;
        let Some((entry, offset)) = self
            .inflight
            .remove(|entry| entry.home != own && entry.address == address)
        else {
            return Err(CompletionInvalidReason::AddressOutsideUmem);
        };
        self.tx_counters.tx_inflight = self.tx_counters.tx_inflight.saturating_sub(1);
        if offset != 0 {
            bump(&mut self.tx_counters.tx_completions_reordered);
        }
        bump(&mut self.tx_counters.tx_completed);
        self.lent_completions.push(LentCompletion {
            home: entry.home,
            token: entry.token,
        });
        Ok(())
    }
}

impl RxFillEngine<'_> {
    /// Whether this engine's frames and `other`'s are parts of one
    /// registered UMEM, so each can transmit the other's frames.
    #[must_use]
    pub fn shares_umem_with(&self, other: &RxFillEngine<'_>) -> bool {
        self.state.umem_id == other.state.umem_id
    }

    /// Frames of this engine in flight on other sockets' TX rings.
    #[must_use]
    pub const fn tx_lent(&self) -> u32 {
        self.state.lent
    }

    /// The most frames this engine has in flight on other sockets at once:
    /// what its RX pool has beyond one full Fill ring, so a peer that stops
    /// completing (a link that went down) cannot take the frames this
    /// socket needs to keep receiving.
    #[must_use]
    pub fn tx_lent_limit(&self) -> u32 {
        self.state.rx_frames.saturating_sub(self.fill.capacity())
    }

    /// Submits a handoff of this engine's received frame to the TX ring of
    /// `out`, without copying.
    ///
    /// Refused unchanged, like [`Self::submit_tx`]: when the two engines do
    /// not share a UMEM or the frame is a generated one
    /// ([`TxRejection::Invalid`]), when either engine is draining, when
    /// `out`'s TX ring or in-flight bound is full, or when this engine is
    /// at [`Self::tx_lent_limit`] ([`TxBlocked::InflightLimit`]; the caller
    /// can still copy the bytes into a frame of `out`).
    // Boxing the refusal would allocate on the back-pressure path.
    #[allow(clippy::result_large_err)]
    pub fn submit_tx_through(
        &mut self,
        out: &mut RxFillEngine<'_>,
        handoff: TxHandoff,
    ) -> Result<TxSubmitReport, TxRejected> {
        let refuse = |reason, handoff| Err(TxRejected::new(reason, handoff));
        let home = &mut self.state;
        if home.umem_id != out.state.umem_id {
            return refuse(
                TxRejection::Invalid(LedgerError::ForeignDescriptorDomain),
                handoff,
            );
        }
        if let Err(error) = home.verify_handoff(&handoff) {
            return refuse(TxRejection::Invalid(error), handoff);
        }
        if home.is_generated(handoff.frame().index()) {
            // Generated frames are for their own socket; their accounting
            // has no place for one in flight elsewhere.
            return refuse(
                TxRejection::Invalid(LedgerError::ForeignDescriptorDomain),
                handoff,
            );
        }
        if home.draining || out.state.draining {
            bump(&mut out.state.tx_counters.tx_refused_draining);
            return refuse(TxRejection::Blocked(TxBlocked::Draining), handoff);
        }
        if home.lent >= home.rx_frames.saturating_sub(self.fill.capacity()) {
            bump(&mut home.tx_counters.tx_lent_limited);
            return refuse(TxRejection::Blocked(TxBlocked::InflightLimit), handoff);
        }
        let room = match out.tx.free_slots() {
            Ok(room) => room as usize,
            Err(error) => return refuse(TxRejection::Ring(error), handoff),
        };
        // Completions not yet taken keep their place, so the list of them
        // never outgrows the TX capacity it was allocated for.
        let unlisted = out
            .state
            .inflight
            .free()
            .saturating_sub(out.state.lent_completions.len());
        if room == 0 {
            bump(&mut out.state.tx_counters.tx_ring_full);
            return refuse(TxRejection::Blocked(TxBlocked::RingFull), handoff);
        }
        if unlisted == 0 {
            bump(&mut out.state.tx_counters.tx_inflight_limited);
            return refuse(TxRejection::Blocked(TxBlocked::InflightLimit), handoff);
        }

        let token = handoff.token();
        if let Err(error) = home.frames.ledger_mut().reserve_tx(token) {
            return refuse(TxRejection::Invalid(error), handoff);
        }
        let descriptor = EngineState::tx_descriptor(&handoff, home.address_base);
        if let Err(error) = write_one(&mut out.tx, descriptor) {
            home.frames
                .ledger_mut()
                .cancel_tx_reservation(token)
                .expect("reserved above");
            return refuse(TxRejection::Ring(error), handoff);
        }
        let token = handoff.defuse();
        home.frames
            .ledger_mut()
            .publish_tx(token)
            .expect("reserved above");
        home.lent += 1;
        bump(&mut home.tx_counters.tx_lent);

        let state = &mut out.state;
        let pushed = state.inflight.push(InflightEntry {
            token,
            address: descriptor.address,
            stamp: state.counters.polls,
            home: home.engine_id,
        });
        debug_assert!(pushed, "room was checked above");
        let counters = &mut state.tx_counters;
        add(&mut counters.tx_submitted, 1);
        counters.tx_inflight = u32::try_from(state.inflight.len()).expect("bounded by u32 ring");
        counters.tx_inflight_highwater = counters.tx_inflight_highwater.max(counters.tx_inflight);
        let need_wakeup = out.tx.need_wakeup();
        match need_wakeup {
            Ok(NeedWakeup::Required) => bump(&mut counters.tx_need_wakeup),
            Ok(NeedWakeup::NotRequired) => {}
            Err(_) => bump(&mut counters.tx_flag_errors),
        }
        Ok(TxSubmitReport::of_one(need_wakeup))
    }

    /// Takes one completion of a frame this engine sent for another one,
    /// for that engine's [`Self::complete_lent`].
    pub fn take_lent_completion(&mut self) -> Option<LentCompletion> {
        self.state.lent_completions.pop()
    }

    /// Ends the TX of a frame this engine sent out through another socket:
    /// the frame is `Free` and back in the RX free list. A completion of
    /// another engine's frame comes back unchanged.
    pub fn complete_lent(&mut self, completion: LentCompletion) -> Result<(), LentCompletion> {
        let state = &mut self.state;
        if completion.home != state.engine_id {
            return Err(completion);
        }
        let token = completion.token;
        let ledger = state.frames.ledger_mut();
        ledger
            .check(token, FrameStateKind::TxOwnedByKernel)
            .expect("a lent frame stays TxOwnedByKernel until its completion returns");
        ledger.complete_tx(token).expect("checked above");
        ledger
            .recycle_completion(token)
            .expect("completed under the same borrow");
        state.push_free(token.frame().index());
        state.lent -= 1;
        bump(&mut state.tx_counters.tx_lent_completed);
        Ok(())
    }
}

/// Reserves, writes, and publishes one TX descriptor, or changes nothing.
fn write_one(
    tx: &mut crate::TxProducer<'_>,
    descriptor: XdpDescriptor,
) -> Result<(), crate::NativeRingError> {
    let mut reservation = tx.reserve(1)?;
    if let Err(error) = reservation.write(descriptor) {
        reservation.release_cancel();
        return Err(error);
    }
    reservation.release_submit().map(|_| ())
}
