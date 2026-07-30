#![allow(unsafe_code)]
//! Private atomic and volatile access to one checked borrowed ring mapping.
//!
//! No reference into kernel-mutated memory escapes this module. Cursor
//! publication follows the AF_XDP SPSC contract: descriptors precede a Release
//! producer store, an Acquire producer load precedes descriptor reads, and
//! descriptor reads precede a Release consumer store.

use std::{
    marker::PhantomData,
    ptr::NonNull,
    sync::atomic::{AtomicU32, Ordering},
};

use crate::{
    abi::{RingElement, RingMmapLayout, XdpDescriptor, XdpRingOffset, XDP_RING_NEED_WAKEUP},
    NativeRingError, RingEntries, RingField, RingMapError,
};

use super::mmap::BorrowedMmap;

pub(crate) trait RingValue: Copy {
    const ELEMENT: RingElement;
}

impl RingValue for u64 {
    const ELEMENT: RingElement = RingElement::UmemAddress;
}

impl RingValue for XdpDescriptor {
    const ELEMENT: RingElement = RingElement::PacketDescriptor;
}

pub(crate) struct RingMemory<'memory, T: RingValue> {
    producer: NonNull<AtomicU32>,
    consumer: NonNull<AtomicU32>,
    flags: NonNull<AtomicU32>,
    descriptors: NonNull<T>,
    capacity: u32,
    mask: u32,
    _mapping: BorrowedMmap<'memory>,
    _value: PhantomData<T>,
}

impl<'memory, T: RingValue> RingMemory<'memory, T> {
    pub(crate) fn new(
        memory: &'memory mut [u8],
        raw: XdpRingOffset,
        entries: RingEntries,
    ) -> Result<Self, RingMapError> {
        let layout = RingMmapLayout::new(raw, entries, T::ELEMENT)?;
        let mapping = BorrowedMmap::new(memory, layout)?;
        let producer = mapping.field(RingField::Producer, layout.producer())?;
        let consumer = mapping.field(RingField::Consumer, layout.consumer())?;
        let flags = mapping.field(RingField::Flags, layout.flags())?;
        let descriptors = mapping.field(RingField::Descriptors, layout.descriptors())?;
        let capacity = entries.get();
        Ok(Self {
            producer,
            consumer,
            flags,
            descriptors,
            capacity,
            mask: capacity - 1,
            _mapping: mapping,
            _value: PhantomData,
        })
    }

    pub(crate) const fn capacity(&self) -> u32 {
        self.capacity
    }

    pub(crate) fn producer_relaxed(&self) -> u32 {
        self.atomic_load(self.producer, Ordering::Relaxed)
    }

    pub(crate) fn producer_acquire(&self) -> u32 {
        self.atomic_load(self.producer, Ordering::Acquire)
    }

    pub(crate) fn consumer_relaxed(&self) -> u32 {
        self.atomic_load(self.consumer, Ordering::Relaxed)
    }

    pub(crate) fn consumer_acquire(&self) -> u32 {
        self.atomic_load(self.consumer, Ordering::Acquire)
    }

    pub(crate) fn publish_producer(&mut self, value: u32) {
        self.atomic_store(self.producer, value, Ordering::Release);
    }

    pub(crate) fn publish_consumer(&mut self, value: u32) {
        self.atomic_store(self.consumer, value, Ordering::Release);
    }

    pub(crate) fn write(&mut self, logical: u32, value: T) {
        let physical = (logical & self.mask) as usize;
        let pointer = self.descriptors.as_ptr().wrapping_add(physical);
        // SAFETY: construction validated the complete descriptor-array extent
        // and its alignment. `physical < capacity`, `T` is sealed to integer
        // UAPI layouts with every bit pattern valid, and the exclusive mapping
        // borrow prevents competing Rust access. Volatile access represents the
        // independently kernel-observed mapping.
        unsafe {
            pointer.write_volatile(value);
        }
    }

    pub(crate) fn read(&self, logical: u32) -> T {
        let physical = (logical & self.mask) as usize;
        let pointer = self.descriptors.as_ptr().wrapping_add(physical);
        // SAFETY: the same checked extent, alignment, sealed-value, and
        // exclusive-borrow invariants as `write` apply. Callers perform an
        // Acquire producer load before reaching this read.
        unsafe { pointer.read_volatile() }
    }

    pub(crate) fn need_wakeup(&self) -> Result<bool, NativeRingError> {
        let raw = self.atomic_load(self.flags, Ordering::Acquire);
        let unsupported = raw & !XDP_RING_NEED_WAKEUP;
        if unsupported != 0 {
            Err(NativeRingError::UnsupportedRingFlags(unsupported))
        } else {
            Ok(raw & XDP_RING_NEED_WAKEUP != 0)
        }
    }

    fn atomic_load(&self, pointer: NonNull<AtomicU32>, ordering: Ordering) -> u32 {
        // SAFETY: construction checked the mapped field extent and actual
        // address alignment. `AtomicU32` accepts every `u32` bit pattern; the
        // returned reference is temporary and never escapes this operation.
        unsafe { pointer.as_ref().load(ordering) }
    }

    fn atomic_store(&mut self, pointer: NonNull<AtomicU32>, value: u32, ordering: Ordering) {
        // SAFETY: the cursor pointer has the checked lifetime, extent, and
        // alignment described in `atomic_load`. SPSC role ownership guarantees
        // this process is the sole writer for the selected cursor.
        unsafe {
            pointer.as_ref().store(value, ordering);
        }
    }
}
