use std::{fmt, num::NonZeroU128};

/// Caller-provided identity for one UMEM ownership lifetime.
///
/// The value must be unique across every live ledger and must never be reused
/// when a UMEM or ledger is recreated. This crate intentionally does not derive
/// identity from pointers, process-local counters, or global mutable state.
///
/// This type is move-only so one identity cannot accidentally initialize two
/// layouts. A caller can still repeat the numeric input, so persistence and
/// uniqueness across restarts remain a control-plane responsibility.
pub struct UmemDomainId(DomainIdentity);

impl UmemDomainId {
    /// Wraps a caller-generated nonzero unique value.
    #[must_use]
    pub const fn new(unique: NonZeroU128) -> Self {
        Self(DomainIdentity(unique))
    }

    pub(crate) const fn into_inner(self) -> DomainIdentity {
        self.0
    }
}

impl fmt::Debug for UmemDomainId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UmemDomainId(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct DomainIdentity(NonZeroU128);

impl fmt::Debug for DomainIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}
