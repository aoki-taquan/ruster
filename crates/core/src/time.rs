//! Time as the forwarding path counts it.

/// Milliseconds on a monotonic clock, as the worker reads it once per batch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicMillis(pub u64);
