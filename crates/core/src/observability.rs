//! Backend-facing observability vocabulary.
//!
//! Packet backends depend only on this crate, so the fixed-field visiting
//! contract and the backend stats extension point live here. Aggregation,
//! health, and rendering live in `ruster-runtime`.

use core::fmt;
use core::num::NonZeroU64;

use crate::MonotonicMillis;

/// A field value visited by [`ObservableFields::visit_fields`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldValue {
    Count(u64),
    Flag(bool),
    /// Injected monotonic time; `None` when the event has not happened.
    Millis(Option<MonotonicMillis>),
    Generation(Option<NonZeroU64>),
    Label(&'static str),
}

/// Receives `(section, key, value)` triples in a fixed order.
pub trait FieldVisitor {
    fn field(&mut self, section: &'static str, key: &'static str, value: FieldValue);
}

/// A fixed-shape value that can be serialized deterministically.
///
/// Implementations must visit the same fields in the same order on every
/// call, must not allocate, and must not depend on map iteration order.
pub trait ObservableFields {
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V);
}

/// How a backend moves packet bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendMode {
    Simulated,
    Copy,
    ZeroCopy,
}

impl BackendMode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Simulated => "simulated",
            Self::Copy => "copy",
            Self::ZeroCopy => "zero_copy",
        }
    }
}

/// Static-dispatch extension point for backend-owned fixed stats.
///
/// `backend_stats` is called by the cold side between ticks. It must be O(1)
/// or bounded by fixed backend geometry, must not allocate, and must not
/// mutate backend state. The stats type renders through
/// [`ObservableFields`] with a fixed field order.
pub trait BackendStats {
    type Stats: Copy + fmt::Debug + Eq + ObservableFields;

    const NAME: &'static str;
    const MODE: BackendMode;

    fn backend_stats(&self) -> Self::Stats;
}
