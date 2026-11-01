#![allow(unsafe_code)]
//! Test-only scripted kernel over heap memory.
//!
//! The memory stands in for the kernel-shared Fill ring, RX ring, and UMEM
//! mappings. The engine borrows it through the same role views a live
//! session lends; the script plays the kernel side through raw pointers
//! only (atomic cursors, volatile descriptors, raw byte copies), exactly as
//! the kernel accesses the real mappings concurrently. No Rust reference
//! into the memory is formed here except temporary `&AtomicU32` to cursor
//! words, which the ring views also use.

use std::{
    alloc::{alloc_zeroed, dealloc, Layout},
    ptr::NonNull,
    sync::atomic::{AtomicU32, Ordering},
};

use crate::{
    abi::{XdpDescriptor, XdpRingOffset},
    FillProducer, RingEntries, RxConsumer, UmemConfig, UmemRegion,
};

use super::{mmap::BorrowedMmap, umem::UmemMapping};

/// Allocation counter for hot-path tests; delegates to the system allocator.
struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn count_allocation(pointer: *mut u8) {
    if !pointer.is_null() {
        ALLOCATIONS.with(|count| count.set(count.get().saturating_add(1)));
    }
}

// SAFETY: every operation forwards its unchanged contract to `System`. The
// const thread-local counter never allocates and keeps concurrent test
// threads out of one test's measurement.
unsafe impl std::alloc::GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract.
        let pointer = unsafe { std::alloc::System.alloc(layout) };
        count_allocation(pointer);
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc_zeroed` contract.
        let pointer = unsafe { std::alloc::System.alloc_zeroed(layout) };
        count_allocation(pointer);
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` and `layout` came from this allocator.
        unsafe { std::alloc::System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::realloc` contract.
        let pointer = unsafe { std::alloc::System.realloc(pointer, layout, new_size) };
        count_allocation(pointer);
        pointer
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

/// Allocations made by the current thread so far.
pub(crate) fn allocation_count() -> u64 {
    ALLOCATIONS.with(std::cell::Cell::get)
}

/// Ring layout used for both heap rings: cursors on separate cache lines,
/// descriptors after them.
pub(crate) const HEAP_RING_OFFSETS: XdpRingOffset = XdpRingOffset {
    producer: 0,
    consumer: 64,
    flags: 128,
    descriptors: 192,
};

const PRODUCER: usize = 0;
const CONSUMER: usize = 64;
const FLAGS: usize = 128;
const DESCRIPTORS: usize = 192;

struct HeapRegion {
    base: NonNull<u8>,
    layout: Layout,
}

impl HeapRegion {
    fn new(len: usize) -> Self {
        let layout = Layout::from_size_align(len, 4_096).expect("test region layout");
        // SAFETY: `layout` has a nonzero size (every caller passes at least
        // the ring header) and a valid power-of-two alignment.
        let base = unsafe { alloc_zeroed(layout) };
        Self {
            base: NonNull::new(base).expect("test allocation"),
            layout,
        }
    }

    const fn len(&self) -> usize {
        self.layout.size()
    }

    fn cursor(&self, offset: usize) -> &AtomicU32 {
        assert!(offset + 4 <= self.len() && offset.is_multiple_of(4));
        // SAFETY: the word lies inside the live allocation and is 4-byte
        // aligned (the base is page aligned). `AtomicU32` accepts every bit
        // pattern, and all accesses to cursor words, from the script and
        // from the ring views, are atomic.
        unsafe { AtomicU32::from_ptr(self.base.as_ptr().add(offset).cast::<u32>()) }
    }
}

impl Drop for HeapRegion {
    fn drop(&mut self) {
        // SAFETY: `base` came from `alloc_zeroed` with exactly `layout`.
        unsafe { dealloc(self.base.as_ptr(), self.layout) };
    }
}

/// Heap stand-in for one socket's Fill ring, RX ring, and UMEM.
pub(crate) struct ScriptedKernel {
    fill: HeapRegion,
    rx: HeapRegion,
    umem: HeapRegion,
    fill_entries: RingEntries,
    rx_entries: RingEntries,
    umem_config: UmemConfig,
}

impl ScriptedKernel {
    pub(crate) fn new(fill: RingEntries, rx: RingEntries, umem: UmemConfig) -> Self {
        let umem_len = usize::try_from(umem.byte_len()).expect("test UMEM fits usize");
        Self {
            fill: HeapRegion::new(DESCRIPTORS + fill.get() as usize * 8),
            rx: HeapRegion::new(DESCRIPTORS + rx.get() as usize * 16),
            umem: HeapRegion::new(umem_len),
            fill_entries: fill,
            rx_entries: rx,
            umem_config: umem,
        }
    }

    /// Lends the application-side views, as `NativeSession::rings` does.
    ///
    /// The test must not hold two sets of views at once.
    pub(crate) fn views(&self) -> (FillProducer<'_>, RxConsumer<'_>, UmemRegion<'_>) {
        // SAFETY (all three): each region is one live zeroed heap
        // allocation that outlives the `&self` borrow and is freed only by
        // Drop. The script touches it only through raw pointers: atomic
        // cursor words and volatile descriptor or raw byte copies, never
        // inside a frame the engine has leased. That is the contract
        // `from_raw_parts` states for kernel-shared mappings.
        let fill = unsafe { BorrowedMmap::from_raw_parts(self.fill.base, self.fill.len()) };
        let rx = unsafe { BorrowedMmap::from_raw_parts(self.rx.base, self.rx.len()) };
        let umem = unsafe { UmemMapping::from_raw_parts(self.umem.base, self.umem.len()) };
        (
            FillProducer::with_mapping(fill, HEAP_RING_OFFSETS, self.fill_entries)
                .expect("heap Fill view"),
            RxConsumer::with_mapping(rx, HEAP_RING_OFFSETS, self.rx_entries).expect("heap RX view"),
            UmemRegion::new(self.umem_config, umem),
        )
    }

    pub(crate) fn fill_producer(&self) -> u32 {
        self.fill.cursor(PRODUCER).load(Ordering::Acquire)
    }

    pub(crate) fn fill_consumer(&self) -> u32 {
        self.fill.cursor(CONSUMER).load(Ordering::Relaxed)
    }

    /// Entries the application published and the kernel has not consumed.
    pub(crate) fn fill_pending(&self) -> u32 {
        self.fill_producer().wrapping_sub(self.fill_consumer())
    }

    /// Reads one published Fill entry by logical cursor, without consuming.
    pub(crate) fn fill_entry(&self, logical: u32) -> u64 {
        let slot = (logical & (self.fill_entries.get() - 1)) as usize;
        let pointer = self
            .fill
            .base
            .as_ptr()
            .wrapping_add(DESCRIPTORS + slot * 8)
            .cast::<u64>();
        // SAFETY: the slot lies inside the allocation, is 8-byte aligned,
        // and is read volatile like the kernel reads the mapping.
        unsafe { pointer.read_volatile() }
    }

    /// Kernel-consumes the oldest Fill entry.
    pub(crate) fn consume_fill(&self) -> Option<u64> {
        let consumer = self.fill_consumer();
        if self.fill_producer() == consumer {
            return None;
        }
        let address = self.fill_entry(consumer);
        self.fill
            .cursor(CONSUMER)
            .store(consumer.wrapping_add(1), Ordering::Release);
        Some(address)
    }

    pub(crate) fn rx_consumer(&self) -> u32 {
        self.rx.cursor(CONSUMER).load(Ordering::Acquire)
    }

    pub(crate) fn rx_producer(&self) -> u32 {
        self.rx.cursor(PRODUCER).load(Ordering::Relaxed)
    }

    /// Kernel-produces one RX descriptor; `false` if the RX ring is full.
    pub(crate) fn produce_rx(&self, descriptor: XdpDescriptor) -> bool {
        let producer = self.rx_producer();
        if producer.wrapping_sub(self.rx_consumer()) >= self.rx_entries.get() {
            return false;
        }
        let slot = (producer & (self.rx_entries.get() - 1)) as usize;
        let pointer = self
            .rx
            .base
            .as_ptr()
            .wrapping_add(DESCRIPTORS + slot * 16)
            .cast::<XdpDescriptor>();
        // SAFETY: the slot lies inside the allocation and is 8-byte aligned;
        // `XdpDescriptor` is plain integers. The Release store below
        // publishes it after the write.
        unsafe { pointer.write_volatile(descriptor) };
        self.rx
            .cursor(PRODUCER)
            .store(producer.wrapping_add(1), Ordering::Release);
        true
    }

    /// Overwrites the RX producer cursor (corruption tests).
    pub(crate) fn set_rx_producer(&self, value: u32) {
        self.rx.cursor(PRODUCER).store(value, Ordering::Release);
    }

    /// Overwrites the Fill consumer cursor (corruption tests).
    pub(crate) fn set_fill_consumer(&self, value: u32) {
        self.fill.cursor(CONSUMER).store(value, Ordering::Release);
    }

    /// Sets the Fill flags word the kernel exposes after publication.
    pub(crate) fn set_fill_flags(&self, value: u32) {
        self.fill.cursor(FLAGS).store(value, Ordering::Release);
    }

    /// Kernel-writes packet bytes into a frame it owns.
    pub(crate) fn write_umem(&self, offset: u64, bytes: &[u8]) {
        let offset = usize::try_from(offset).expect("test offset");
        assert!(offset + bytes.len() <= self.umem.len());
        // SAFETY: the range lies inside the allocation, and tests write only
        // frames the ledger records as kernel-owned (never a leased one).
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.umem.base.as_ptr().add(offset),
                bytes.len(),
            );
        }
    }

    /// Kernel-reads bytes back (for example after an in-place rewrite).
    pub(crate) fn read_umem(&self, offset: u64, out: &mut [u8]) {
        let offset = usize::try_from(offset).expect("test offset");
        assert!(offset + out.len() <= self.umem.len());
        // SAFETY: the range lies inside the allocation, and tests read only
        // frames that no live lease borrows mutably.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.umem.base.as_ptr().add(offset),
                out.as_mut_ptr(),
                out.len(),
            );
        }
    }
}
