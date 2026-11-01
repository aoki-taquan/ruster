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

/// Exact slot occupancy of one fixed-capacity state table (OBS-015).
///
/// `occupied` counts the slots that currently hold state which no operation
/// has reclaimed, deleted, or flushed yet ("allocated slots"). Expiry in the
/// NAT44, firewall, and ICMPv4 error tables is lazy: a slot whose idle TTL
/// has passed stays counted until a later operation reuses or deletes it or
/// a publication flush clears the table. `occupied` is therefore an exact
/// count of allocated slots and an upper bound on state that is still live
/// at the runtime's watermark; it never undercounts live state.
///
/// `high_water` is the largest `occupied` value reached since the runtime
/// was created or last flushed by a publication. It never decreases in
/// between; a flushing publication resets both values to zero together with
/// the table, and a same-generation reconcile that keeps state keeps both.
///
/// `capacity` is the number of slots the runtime may fill, so `occupied`
/// and `high_water` never exceed it.
///
/// The counters are maintained in O(1) at every slot transition, so reading
/// them never scans a table.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TableOccupancy {
    occupied: usize,
    high_water: usize,
    capacity: usize,
}

impl TableOccupancy {
    /// A value satisfying `occupied <= high_water <= capacity`, for callers
    /// that render or aggregate occupancy without a core runtime. `None`
    /// otherwise.
    #[must_use]
    pub const fn new(occupied: usize, high_water: usize, capacity: usize) -> Option<Self> {
        if occupied <= high_water && high_water <= capacity {
            Some(Self {
                occupied,
                high_water,
                capacity,
            })
        } else {
            None
        }
    }

    #[must_use]
    pub const fn occupied(self) -> usize {
        self.occupied
    }

    #[must_use]
    pub const fn high_water(self) -> usize {
        self.high_water
    }

    #[must_use]
    pub const fn capacity(self) -> usize {
        self.capacity
    }
}

/// Worker-local O(1) occupancy counter behind a [`TableOccupancy`].
///
/// Only runtime commit, reclaim, and flush paths mutate it, so it cannot
/// drift from the slots it counts. Tests compare it against a full scan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OccupancyCounter {
    occupied: usize,
    high_water: usize,
}

impl OccupancyCounter {
    /// Records one slot overwrite: `before` and `after` are whether the slot
    /// held state before and after the write.
    #[inline]
    pub(crate) fn transition(&mut self, before: bool, after: bool) {
        match (before, after) {
            (false, true) => self.insert(),
            (true, false) => self.remove(),
            (false, false) | (true, true) => {}
        }
    }

    #[inline]
    pub(crate) fn insert(&mut self) {
        self.occupied = self.occupied.saturating_add(1);
        if self.occupied > self.high_water {
            self.high_water = self.occupied;
        }
    }

    #[inline]
    pub(crate) fn remove(&mut self) {
        debug_assert!(self.occupied > 0, "occupancy underflow");
        self.occupied = self.occupied.saturating_sub(1);
    }

    /// The table was cleared by a publication flush: a new generation of
    /// state starts with a zero high-water mark.
    #[inline]
    pub(crate) fn flush(&mut self) {
        *self = Self::default();
    }

    #[must_use]
    pub(crate) const fn occupied(self) -> usize {
        self.occupied
    }

    #[must_use]
    pub(crate) const fn snapshot(self, capacity: usize) -> TableOccupancy {
        TableOccupancy {
            occupied: self.occupied,
            high_water: self.high_water,
            capacity,
        }
    }
}

#[cfg(test)]
mod occupancy_tests {
    use super::*;

    #[test]
    fn occupancy_counter_tracks_transitions_high_water_and_flush() {
        let mut counter = OccupancyCounter::default();
        counter.transition(false, true);
        counter.transition(false, true);
        counter.transition(true, true);
        assert_eq!(
            counter.snapshot(4),
            TableOccupancy {
                occupied: 2,
                high_water: 2,
                capacity: 4,
            }
        );
        counter.transition(true, false);
        counter.transition(false, false);
        let after_remove = counter.snapshot(4);
        assert_eq!((after_remove.occupied(), after_remove.high_water()), (1, 2));
        counter.insert();
        assert_eq!(counter.snapshot(4).high_water(), 2, "refill below peak");
        counter.insert();
        assert_eq!(counter.snapshot(4).high_water(), 3);
        counter.flush();
        assert_eq!(counter.snapshot(4), TableOccupancy::new(0, 0, 4).unwrap());
    }

    #[test]
    fn table_occupancy_constructor_enforces_its_ordering() {
        assert_eq!(
            TableOccupancy::new(1, 2, 3).map(|t| t.high_water()),
            Some(2)
        );
        assert_eq!(
            TableOccupancy::new(0, 0, 0),
            Some(TableOccupancy::default())
        );
        assert_eq!(TableOccupancy::new(2, 1, 3), None);
        assert_eq!(TableOccupancy::new(1, 4, 3), None);
    }
}
