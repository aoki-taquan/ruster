use std::num::NonZeroU64;

use crate::{domain::DomainIdentity, ledger::TokenAuthority};

/// Canonical identity of one fixed-size frame in a UMEM region.
///
/// The numeric value is the frame index, not a packet data offset or virtual
/// address. Values are produced by [`crate::UmemLayout`] or [`crate::FrameLedger`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FrameId(u32);

impl FrameId {
    pub(crate) const fn from_index(index: u32) -> Self {
        Self(index)
    }

    /// Returns the zero-based frame index.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }
}

/// Nonzero ownership epoch for a frame.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OwnershipGeneration(NonZeroU64);

impl OwnershipGeneration {
    pub(crate) const fn new(value: NonZeroU64) -> Self {
        Self(value)
    }

    /// Returns the nonzero epoch value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Capability identifying one particular ownership cycle of a frame.
///
/// There is intentionally no public constructor. Only a ledger holding its
/// private issuance authority can create a token. Tokens are `Copy` so they can
/// cross ring-model state boundaries without allocation; copying one does not
/// duplicate ownership. After the first valid transition, another copy is
/// rejected by the exact state/generation check.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FrameToken {
    domain: DomainIdentity,
    frame: FrameId,
    generation: OwnershipGeneration,
}

impl FrameToken {
    pub(crate) const fn from_ledger(
        frame: FrameId,
        generation: OwnershipGeneration,
        authority: &TokenAuthority,
    ) -> Self {
        Self {
            domain: authority.domain(),
            frame,
            generation,
        }
    }

    /// Returns the canonical UMEM frame identity.
    #[must_use]
    pub const fn frame(self) -> FrameId {
        self.frame
    }

    /// Returns the ownership epoch captured by this token.
    #[must_use]
    pub const fn generation(self) -> OwnershipGeneration {
        self.generation
    }

    pub(crate) fn belongs_to(self, domain: DomainIdentity) -> bool {
        self.domain == domain
    }
}
