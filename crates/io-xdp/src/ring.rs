use crate::{ObservedSubmission, RingObservation};

/// Published producer and consumer cursors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingIndices {
    /// Next logical slot after all submitted producer entries.
    pub producer: u32,
    /// Next logical slot not yet consumed.
    pub consumer: u32,
}

/// Fixed-storage, power-of-two SPSC ring model.
///
/// This pure model is single-threaded and uses `&mut` exclusion instead of
/// atomics. Its API fixes the native ordering contract: descriptor writes occur
/// before producer release-submit; producer observation occurs before consumer
/// peek; reads complete before consumer release-consume. A native ring must map
/// those publication points to Release/Acquire cursor operations.
#[derive(Debug)]
pub struct SpscRing<T: Copy, const N: usize> {
    observation: RingObservation,
    slots: [Option<ObservedSubmission<T>>; N],
    producer: u32,
    consumer: u32,
}

impl<T: Copy, const N: usize> SpscRing<T, N> {
    /// Creates an empty ring using inline storage.
    pub fn new(observation: RingObservation) -> Result<Self, RingError> {
        if N == 0 || !N.is_power_of_two() || u32::try_from(N).is_err() {
            return Err(RingError::InvalidCapacity);
        }
        Ok(Self {
            observation,
            slots: [None; N],
            producer: 0,
            consumer: 0,
        })
    }

    /// Returns the physical ring fact used at construction.
    #[must_use]
    pub const fn observation(&self) -> RingObservation {
        self.observation
    }

    /// Returns published cursors.
    #[must_use]
    pub const fn indices(&self) -> RingIndices {
        RingIndices {
            producer: self.producer,
            consumer: self.consumer,
        }
    }

    /// Returns the fixed capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns submitted entries not yet consumed.
    pub fn occupied(&self) -> Result<usize, RingError> {
        let occupied = self.producer.wrapping_sub(self.consumer);
        let occupied = usize::try_from(occupied).map_err(|_| RingError::CorruptCursor)?;
        if occupied > N {
            return Err(RingError::CorruptCursor);
        }
        Ok(occupied)
    }

    /// Reserves exactly `len` unpublished producer slots.
    pub fn reserve(&mut self, len: usize) -> Result<ProducerReservation<'_, T, N>, RingError> {
        self.validate_len(len)?;
        let occupied = self.occupied()?;
        if len > N - occupied {
            return Err(RingError::RingFull);
        }
        let start = self.producer;
        Ok(ProducerReservation {
            ring: self,
            start,
            len,
            written: 0,
            released: false,
        })
    }

    /// Acquires exactly `len` published consumer slots.
    pub fn acquire(&mut self, len: usize) -> Result<ConsumerAcquisition<'_, T, N>, RingError> {
        self.validate_len(len)?;
        if len > self.occupied()? {
            return Err(RingError::RingEmpty);
        }
        let start = self.consumer;
        Ok(ConsumerAcquisition {
            ring: self,
            start,
            len,
        })
    }

    fn validate_len(&self, len: usize) -> Result<(), RingError> {
        if len == 0 {
            return Err(RingError::ZeroLength);
        }
        if len > N {
            return Err(RingError::LengthExceedsCapacity);
        }
        Ok(())
    }

    const fn physical_index(logical: u32) -> usize {
        (logical as usize) & (N - 1)
    }

    #[cfg(test)]
    pub(crate) fn set_empty_cursor_for_test(&mut self, cursor: u32) {
        assert_eq!(self.occupied(), Ok(0));
        self.producer = cursor;
        self.consumer = cursor;
    }
}

/// Unpublished producer range.
///
/// Dropping this value before release-submit clears every write and publishes
/// nothing.
pub struct ProducerReservation<'ring, T: Copy, const N: usize> {
    ring: &'ring mut SpscRing<T, N>,
    start: u32,
    len: usize,
    written: usize,
    released: bool,
}

impl<T: Copy, const N: usize> ProducerReservation<'_, T, N> {
    /// Writes one offset in the reserved logical range.
    pub fn write(
        &mut self,
        offset: usize,
        submission: ObservedSubmission<T>,
    ) -> Result<(), RingError> {
        if offset >= self.len {
            return Err(RingError::OffsetOutsideRange);
        }
        if submission.observation() != self.ring.observation {
            return Err(RingError::WrongRing);
        }
        let logical = self.start.wrapping_add(
            u32::try_from(offset).expect("reservation length was bounded by u32 capacity"),
        );
        let index = SpscRing::<T, N>::physical_index(logical);
        if self.ring.slots[index].is_some() {
            return Err(RingError::DuplicateWrite);
        }
        self.ring.slots[index] = Some(submission);
        self.written += 1;
        Ok(())
    }

    /// Publishes the complete range after every descriptor write.
    pub fn release_submit(mut self) -> Result<(), RingError> {
        if self.written != self.len {
            return Err(RingError::IncompleteReservation);
        }
        self.ring.producer = self.start.wrapping_add(
            u32::try_from(self.len).expect("reservation length was bounded by u32 capacity"),
        );
        self.released = true;
        Ok(())
    }

    /// Explicitly cancels the unpublished range.
    pub fn release_cancel(mut self) {
        self.clear();
        self.released = true;
    }

    fn clear(&mut self) {
        for offset in 0..self.len {
            let logical = self.start.wrapping_add(
                u32::try_from(offset).expect("reservation length was bounded by u32 capacity"),
            );
            let index = SpscRing::<T, N>::physical_index(logical);
            self.ring.slots[index] = None;
        }
    }
}

impl<T: Copy, const N: usize> Drop for ProducerReservation<'_, T, N> {
    fn drop(&mut self) {
        if !self.released {
            self.clear();
        }
    }
}

/// Published consumer range.
///
/// Drop has cancel semantics: entries remain published until explicit
/// release-consume.
pub struct ConsumerAcquisition<'ring, T: Copy, const N: usize> {
    ring: &'ring mut SpscRing<T, N>,
    start: u32,
    len: usize,
}

impl<T: Copy, const N: usize> ConsumerAcquisition<'_, T, N> {
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// Peeks one published value without advancing the consumer cursor.
    pub fn peek(&self, offset: usize) -> Result<T, RingError> {
        if offset >= self.len {
            return Err(RingError::OffsetOutsideRange);
        }
        let logical = self.start.wrapping_add(
            u32::try_from(offset).expect("acquisition length was bounded by u32 capacity"),
        );
        let index = SpscRing::<T, N>::physical_index(logical);
        self.ring.slots[index]
            .map(ObservedSubmission::into_value)
            .ok_or(RingError::CorruptSlot)
    }

    /// Consumes the complete acquired range and release-publishes its cursor.
    pub fn release_consume(self) -> Result<(), RingError> {
        for offset in 0..self.len {
            let logical = self.start.wrapping_add(
                u32::try_from(offset).expect("acquisition length was bounded by u32 capacity"),
            );
            let index = SpscRing::<T, N>::physical_index(logical);
            if self.ring.slots[index].is_none() {
                return Err(RingError::CorruptSlot);
            }
        }
        for offset in 0..self.len {
            let logical = self.start.wrapping_add(
                u32::try_from(offset).expect("acquisition length was bounded by u32 capacity"),
            );
            let index = SpscRing::<T, N>::physical_index(logical);
            self.ring.slots[index] = None;
        }
        self.ring.consumer = self.start.wrapping_add(
            u32::try_from(self.len).expect("acquisition length was bounded by u32 capacity"),
        );
        Ok(())
    }

    /// Cancels the acquisition without changing slots or cursors.
    pub fn release_cancel(self) {}
}

/// Ring construction or operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingError {
    /// Capacity must be a nonzero power of two representable by `u32`.
    InvalidCapacity,
    /// A reservation or acquisition must include at least one entry.
    ZeroLength,
    /// The requested range exceeds the compile-time capacity.
    LengthExceedsCapacity,
    /// The producer has insufficient free slots.
    RingFull,
    /// The consumer has insufficient published slots.
    RingEmpty,
    /// The submission was observed from another endpoint or ring.
    WrongRing,
    /// The same reserved offset was written more than once.
    DuplicateWrite,
    /// An offset lies outside the reserved or acquired range.
    OffsetOutsideRange,
    /// Release-submit was attempted before every slot was written.
    IncompleteReservation,
    /// Published cursor distance exceeds capacity.
    CorruptCursor,
    /// A published logical slot did not contain a value.
    CorruptSlot,
}
