use std::num::NonZeroU64;

use crate::{FrameId, FrameToken, OwnershipGeneration, ValidatedDescriptor};

#[derive(Debug)]
pub(crate) struct TokenAuthority(());

impl TokenAuthority {
    const fn new() -> Self {
        Self(())
    }
}

/// A stable partition of all frame ownership states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameStateKind {
    /// Available for a new ownership cycle.
    Free = 0,
    /// Reserved locally for a future fill-ring publication.
    FillReserved = 1,
    /// Published to the kernel through the fill ring.
    FillOwnedByKernel = 2,
    /// Returned by the kernel on an RX ring.
    RxAvailable = 3,
    /// Borrowed by packet processing.
    Leased = 4,
    /// Packet processing requested TX.
    PendingTx = 5,
    /// Locally reserved for a future TX-ring publication.
    TxReserved = 6,
    /// Published to the kernel through a TX ring.
    TxOwnedByKernel = 7,
    /// Returned by the kernel on a completion ring.
    CompletionAvailable = 8,
    /// Permanently excluded from normal reuse.
    Quarantined = 9,
}

const STATE_KIND_COUNT: usize = 10;

impl FrameStateKind {
    const ALL: [Self; STATE_KIND_COUNT] = [
        Self::Free,
        Self::FillReserved,
        Self::FillOwnedByKernel,
        Self::RxAvailable,
        Self::Leased,
        Self::PendingTx,
        Self::TxReserved,
        Self::TxOwnedByKernel,
        Self::CompletionAvailable,
        Self::Quarantined,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

/// Origin of a frame borrowed by packet processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseKind {
    /// Frame arrived from the RX path.
    Received,
    /// Frame was allocated for a locally generated packet.
    Generated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameState {
    Free,
    FillReserved(FrameToken),
    FillOwnedByKernel(FrameToken),
    RxAvailable {
        token: FrameToken,
        descriptor: ValidatedDescriptor,
    },
    Leased {
        token: FrameToken,
        kind: LeaseKind,
    },
    PendingTx {
        token: FrameToken,
        kind: LeaseKind,
    },
    TxReserved {
        token: FrameToken,
        kind: LeaseKind,
    },
    TxOwnedByKernel(FrameToken),
    CompletionAvailable(FrameToken),
    Quarantined(Option<FrameToken>),
}

impl FrameState {
    const fn kind(self) -> FrameStateKind {
        match self {
            Self::Free => FrameStateKind::Free,
            Self::FillReserved(_) => FrameStateKind::FillReserved,
            Self::FillOwnedByKernel(_) => FrameStateKind::FillOwnedByKernel,
            Self::RxAvailable { .. } => FrameStateKind::RxAvailable,
            Self::Leased { .. } => FrameStateKind::Leased,
            Self::PendingTx { .. } => FrameStateKind::PendingTx,
            Self::TxReserved { .. } => FrameStateKind::TxReserved,
            Self::TxOwnedByKernel(_) => FrameStateKind::TxOwnedByKernel,
            Self::CompletionAvailable(_) => FrameStateKind::CompletionAvailable,
            Self::Quarantined(_) => FrameStateKind::Quarantined,
        }
    }

    const fn token(self) -> Option<FrameToken> {
        match self {
            Self::Free => None,
            Self::FillReserved(token)
            | Self::FillOwnedByKernel(token)
            | Self::TxOwnedByKernel(token)
            | Self::CompletionAvailable(token) => Some(token),
            Self::RxAvailable { token, .. }
            | Self::Leased { token, .. }
            | Self::PendingTx { token, .. }
            | Self::TxReserved { token, .. } => Some(token),
            Self::Quarantined(token) => token,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrameEntry {
    generation: u64,
    state: FrameState,
}

/// Constant-time counters for the complete state partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateCounts {
    values: [usize; STATE_KIND_COUNT],
}

impl StateCounts {
    fn new(frame_count: usize) -> Self {
        let mut values = [0; STATE_KIND_COUNT];
        values[FrameStateKind::Free.index()] = frame_count;
        Self { values }
    }

    /// Returns the number of frames in one state.
    #[must_use]
    pub const fn get(self, kind: FrameStateKind) -> usize {
        self.values[kind.index()]
    }

    /// Returns the sum across the state partition.
    #[must_use]
    pub fn total(self) -> usize {
        self.values.iter().sum()
    }

    fn transition(&mut self, from: FrameStateKind, to: FrameStateKind) {
        debug_assert!(self.values[from.index()] > 0);
        self.values[from.index()] -= 1;
        self.values[to.index()] += 1;
    }
}

/// Read-only projection of a frame entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameStateView {
    kind: FrameStateKind,
    token: Option<FrameToken>,
}

impl FrameStateView {
    /// Returns the current ownership state.
    #[must_use]
    pub const fn kind(self) -> FrameStateKind {
        self.kind
    }

    /// Returns the current or last token, when the state has one.
    #[must_use]
    pub const fn token(self) -> Option<FrameToken> {
        self.token
    }
}

/// Fixed-size ownership ledger for one UMEM frame set.
///
/// Hot transitions index one entry and update two counters. [`Self::deep_audit`]
/// is the explicit cold path that scans the complete ledger.
#[derive(Debug)]
pub struct FrameLedger {
    entries: Box<[FrameEntry]>,
    counts: StateCounts,
    authority: TokenAuthority,
}

impl FrameLedger {
    /// Creates a ledger with every frame in [`FrameStateKind::Free`].
    pub fn new(frame_count: u32) -> Result<Self, LedgerError> {
        if frame_count == 0 {
            return Err(LedgerError::ZeroFrameCount);
        }
        let count = usize::try_from(frame_count).map_err(|_| LedgerError::FrameCountUnsupported)?;
        let entries = vec![
            FrameEntry {
                generation: 0,
                state: FrameState::Free,
            };
            count
        ]
        .into_boxed_slice();

        Ok(Self {
            entries,
            counts: StateCounts::new(count),
            authority: TokenAuthority::new(),
        })
    }

    /// Returns the number of tracked frames.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns constant-time state partition counters.
    #[must_use]
    pub const fn counts(&self) -> StateCounts {
        self.counts
    }

    /// Returns a read-only state projection.
    pub fn state(&self, frame_index: u32) -> Result<FrameStateView, LedgerError> {
        let entry = self.entry(frame_index)?;
        Ok(FrameStateView {
            kind: entry.state.kind(),
            token: entry.state.token(),
        })
    }

    /// Starts an RX ownership cycle and reserves the frame for fill publication.
    pub fn reserve_fill(&mut self, frame_index: u32) -> Result<FrameToken, LedgerError> {
        self.begin_cycle(frame_index, FrameState::FillReserved)
    }

    /// Publishes a locally reserved frame to the fill ring.
    pub fn publish_fill(&mut self, token: FrameToken) -> Result<(), LedgerError> {
        self.transition(
            token,
            FrameStateKind::FillReserved,
            FrameState::FillOwnedByKernel(token),
        )
    }

    /// Records an RX descriptor returned for a kernel-owned fill frame.
    pub fn receive(
        &mut self,
        token: FrameToken,
        descriptor: ValidatedDescriptor,
    ) -> Result<(), LedgerError> {
        self.verify(token, FrameStateKind::FillOwnedByKernel)?;
        if descriptor.frame() != token.frame() {
            return Err(LedgerError::DescriptorFrameAlias {
                token_frame: token.frame(),
                descriptor_frame: descriptor.frame(),
            });
        }
        self.transition(
            token,
            FrameStateKind::FillOwnedByKernel,
            FrameState::RxAvailable { token, descriptor },
        )
    }

    /// Borrows a received frame for packet processing.
    pub fn lease_rx(&mut self, token: FrameToken) -> Result<ValidatedDescriptor, LedgerError> {
        let index = self.verify(token, FrameStateKind::RxAvailable)?;
        let FrameState::RxAvailable { descriptor, .. } = self.entries[index].state else {
            unreachable!("verified RX state");
        };
        self.transition(
            token,
            FrameStateKind::RxAvailable,
            FrameState::Leased {
                token,
                kind: LeaseKind::Received,
            },
        )?;
        Ok(descriptor)
    }

    /// Starts an ownership cycle already leased for generated packet bytes.
    pub fn lease_generated(&mut self, frame_index: u32) -> Result<FrameToken, LedgerError> {
        self.begin_cycle(frame_index, |token| FrameState::Leased {
            token,
            kind: LeaseKind::Generated,
        })
    }

    /// Converts a processing lease into a pending TX request.
    pub fn stage_tx(&mut self, token: FrameToken) -> Result<(), LedgerError> {
        let kind = self.tx_lease_kind(token, FrameStateKind::Leased)?;
        self.transition(
            token,
            FrameStateKind::Leased,
            FrameState::PendingTx { token, kind },
        )
    }

    /// Reserves a pending TX frame for ring publication.
    pub fn reserve_tx(&mut self, token: FrameToken) -> Result<(), LedgerError> {
        let kind = self.tx_lease_kind(token, FrameStateKind::PendingTx)?;
        self.transition(
            token,
            FrameStateKind::PendingTx,
            FrameState::TxReserved { token, kind },
        )
    }

    /// Publishes a reserved frame to the TX ring.
    pub fn publish_tx(&mut self, token: FrameToken) -> Result<(), LedgerError> {
        self.transition(
            token,
            FrameStateKind::TxReserved,
            FrameState::TxOwnedByKernel(token),
        )
    }

    /// Records a completion descriptor returned for a kernel-owned TX frame.
    pub fn complete_tx(&mut self, token: FrameToken) -> Result<(), LedgerError> {
        self.transition(
            token,
            FrameStateKind::TxOwnedByKernel,
            FrameState::CompletionAvailable(token),
        )
    }

    /// Recycles a completed TX frame.
    pub fn recycle_completion(&mut self, token: FrameToken) -> Result<(), LedgerError> {
        self.transition(token, FrameStateKind::CompletionAvailable, FrameState::Free)
    }

    /// Recycles a processing lease without requesting TX.
    pub fn recycle_lease(&mut self, token: FrameToken) -> Result<(), LedgerError> {
        self.transition(token, FrameStateKind::Leased, FrameState::Free)
    }

    /// Cancels a local fill reservation before publication.
    pub fn cancel_fill(&mut self, token: FrameToken) -> Result<(), LedgerError> {
        self.transition(token, FrameStateKind::FillReserved, FrameState::Free)
    }

    /// Rolls a pending TX request back into its processing lease.
    pub fn cancel_pending_tx(&mut self, token: FrameToken) -> Result<(), LedgerError> {
        let kind = self.tx_lease_kind(token, FrameStateKind::PendingTx)?;
        self.transition(
            token,
            FrameStateKind::PendingTx,
            FrameState::Leased { token, kind },
        )
    }

    /// Rolls a local TX reservation back into the pending queue.
    pub fn cancel_tx_reservation(&mut self, token: FrameToken) -> Result<(), LedgerError> {
        let kind = self.tx_lease_kind(token, FrameStateKind::TxReserved)?;
        self.transition(
            token,
            FrameStateKind::TxReserved,
            FrameState::PendingTx { token, kind },
        )
    }

    /// Performs a cold full-ledger consistency check.
    pub fn deep_audit(&self) -> Result<(), AuditError> {
        let mut observed = [0_usize; STATE_KIND_COUNT];
        for (index, entry) in self.entries.iter().enumerate() {
            observed[entry.state.kind().index()] += 1;
            if let Some(token) = entry.state.token() {
                let token_index =
                    usize::try_from(token.frame().index()).map_err(|_| AuditError::TokenFrame {
                        entry: index,
                        token: token.frame(),
                    })?;
                if token_index != index {
                    return Err(AuditError::TokenFrame {
                        entry: index,
                        token: token.frame(),
                    });
                }
                if token.generation().get() != entry.generation {
                    return Err(AuditError::TokenGeneration {
                        frame: token.frame(),
                        entry_generation: entry.generation,
                        token_generation: token.generation(),
                    });
                }
            } else if entry.generation != 0 && entry.state.kind() != FrameStateKind::Free {
                return Err(AuditError::MissingToken {
                    frame: FrameId::from_index(
                        u32::try_from(index).expect("entry index originated from u32"),
                    ),
                    state: entry.state.kind(),
                });
            }
        }

        for kind in FrameStateKind::ALL {
            let expected = self.counts.get(kind);
            let actual = observed[kind.index()];
            if expected != actual {
                return Err(AuditError::CountMismatch {
                    state: kind,
                    expected,
                    actual,
                });
            }
        }
        Ok(())
    }

    fn begin_cycle(
        &mut self,
        frame_index: u32,
        next_state: impl FnOnce(FrameToken) -> FrameState,
    ) -> Result<FrameToken, LedgerError> {
        let index = self.index(frame_index)?;
        let entry = self.entries[index];
        if entry.state.kind() != FrameStateKind::Free {
            return Err(LedgerError::WrongState {
                frame: FrameId::from_index(frame_index),
                expected: FrameStateKind::Free,
                actual: entry.state.kind(),
            });
        }

        let Some(next_generation) = entry.generation.checked_add(1) else {
            let generation =
                OwnershipGeneration::new(NonZeroU64::new(entry.generation).expect("u64::MAX"));
            let last = FrameToken::from_ledger(
                FrameId::from_index(frame_index),
                generation,
                &self.authority,
            );
            self.entries[index].state = FrameState::Quarantined(Some(last));
            self.counts
                .transition(FrameStateKind::Free, FrameStateKind::Quarantined);
            return Err(LedgerError::GenerationExhausted {
                frame: FrameId::from_index(frame_index),
            });
        };
        let generation =
            OwnershipGeneration::new(NonZeroU64::new(next_generation).expect("one added to u64"));
        let token = FrameToken::from_ledger(
            FrameId::from_index(frame_index),
            generation,
            &self.authority,
        );
        self.entries[index] = FrameEntry {
            generation: next_generation,
            state: next_state(token),
        };
        self.counts
            .transition(FrameStateKind::Free, self.entries[index].state.kind());
        Ok(token)
    }

    fn transition(
        &mut self,
        token: FrameToken,
        expected: FrameStateKind,
        next: FrameState,
    ) -> Result<(), LedgerError> {
        let index = self.verify(token, expected)?;
        self.entries[index].state = next;
        self.counts.transition(expected, next.kind());
        Ok(())
    }

    fn verify(&self, token: FrameToken, expected: FrameStateKind) -> Result<usize, LedgerError> {
        let index = self.index(token.frame().index())?;
        let entry = self.entries[index];
        if entry.generation != token.generation().get() {
            return Err(LedgerError::StaleToken {
                token,
                current_generation: entry.generation,
            });
        }
        if entry.state.kind() != expected || entry.state.token() != Some(token) {
            return Err(LedgerError::WrongState {
                frame: token.frame(),
                expected,
                actual: entry.state.kind(),
            });
        }
        Ok(index)
    }

    fn tx_lease_kind(
        &self,
        token: FrameToken,
        expected: FrameStateKind,
    ) -> Result<LeaseKind, LedgerError> {
        let index = self.verify(token, expected)?;
        match self.entries[index].state {
            FrameState::Leased { kind, .. }
            | FrameState::PendingTx { kind, .. }
            | FrameState::TxReserved { kind, .. } => Ok(kind),
            _ => unreachable!("verified TX staging state"),
        }
    }

    fn entry(&self, frame_index: u32) -> Result<&FrameEntry, LedgerError> {
        let index = self.index(frame_index)?;
        Ok(&self.entries[index])
    }

    fn index(&self, frame_index: u32) -> Result<usize, LedgerError> {
        let index =
            usize::try_from(frame_index).map_err(|_| LedgerError::FrameIndexOutsideLedger)?;
        if index >= self.entries.len() {
            return Err(LedgerError::FrameIndexOutsideLedger);
        }
        Ok(index)
    }

    #[cfg(test)]
    pub(crate) fn set_free_generation_for_test(&mut self, frame_index: u32, generation: u64) {
        let index = self.index(frame_index).expect("test frame");
        assert_eq!(self.entries[index].state, FrameState::Free);
        self.entries[index].generation = generation;
    }
}

/// Rejected ledger operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerError {
    /// At least one frame is required.
    ZeroFrameCount,
    /// The requested frame count cannot be indexed on this target.
    FrameCountUnsupported,
    /// The requested index does not name a ledger entry.
    FrameIndexOutsideLedger,
    /// The ownership epoch reached `u64::MAX`; the frame was quarantined.
    GenerationExhausted {
        /// Frame permanently removed from reuse.
        frame: FrameId,
    },
    /// The token belongs to an earlier ownership cycle.
    StaleToken {
        /// Rejected capability.
        token: FrameToken,
        /// Ledger epoch at rejection time.
        current_generation: u64,
    },
    /// The operation is not valid from the current state.
    WrongState {
        /// Affected frame.
        frame: FrameId,
        /// Required state.
        expected: FrameStateKind,
        /// Observed state.
        actual: FrameStateKind,
    },
    /// Descriptor and token resolve to different canonical frames.
    DescriptorFrameAlias {
        /// Frame authorized by the token.
        token_frame: FrameId,
        /// Frame resolved from descriptor geometry.
        descriptor_frame: FrameId,
    },
}

/// Cold-audit invariant failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditError {
    /// A stored token identifies a different entry.
    TokenFrame {
        /// Entry position being audited.
        entry: usize,
        /// Frame identity stored in the token.
        token: FrameId,
    },
    /// A stored token does not match the entry ownership epoch.
    TokenGeneration {
        /// Frame being audited.
        frame: FrameId,
        /// Epoch stored by the entry.
        entry_generation: u64,
        /// Epoch stored by the token.
        token_generation: OwnershipGeneration,
    },
    /// A non-free ownership state did not carry its token.
    MissingToken {
        /// Frame being audited.
        frame: FrameId,
        /// State missing the token.
        state: FrameStateKind,
    },
    /// O(1) counter and full-scan count disagree.
    CountMismatch {
        /// State whose count disagrees.
        state: FrameStateKind,
        /// O(1) counter value.
        expected: usize,
        /// Full-scan value.
        actual: usize,
    },
}
