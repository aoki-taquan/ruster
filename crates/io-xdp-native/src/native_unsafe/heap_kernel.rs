#![allow(unsafe_code)]
//! Test-only scripted kernel over heap memory.
//!
//! The memory stands in for the kernel-shared Fill, RX, TX, and Completion
//! rings and the UMEM mapping. The engine borrows it through the same role views a live
//! session lends; the script plays the kernel side through raw pointers
//! only (atomic cursors, volatile descriptors, raw byte copies), exactly as
//! the kernel accesses the real mappings concurrently. No Rust reference
//! into the memory is formed here except temporary `&AtomicU32` to cursor
//! words, which the ring views also use.

use std::{
    alloc::{alloc_zeroed, dealloc, Layout},
    cell::{Cell, RefCell},
    ptr::NonNull,
    sync::atomic::{AtomicU32, Ordering},
};

use crate::{
    abi::{XdpDescriptor, XdpRingOffset},
    datapath::{DatapathError, DatapathParts, DatapathRings},
    CompletionConsumer, FillProducer, RingEntries, RingName, RxConsumer, TxProducer, UmemConfig,
};

/// Default TX and Completion capacity of the heap bundle.
fn default_tx_entries() -> RingEntries {
    RingEntries::new(RingName::Tx, 8).expect("valid capacity")
}

use super::{
    kick::{KickRing, KickTarget, ScriptedKicks, SocketKick},
    mmap::BorrowedMmap,
    umem::UmemMapping,
};

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

/// Heap stand-in for all datapath mappings of one socket.
///
/// The script tracks which frames it holds as "kernel": taken from Fill and
/// not yet returned on RX (`held`), or taken from TX and not yet returned
/// on Completion (`tx_held`). It writes packet bytes only inside Fill-held
/// frames and reads them only inside held frames, so it never touches a
/// frame the engine may have lent.
pub(crate) struct ScriptedKernel {
    fill: HeapRegion,
    rx: HeapRegion,
    tx: HeapRegion,
    completion: HeapRegion,
    umem: HeapRegion,
    fill_entries: RingEntries,
    rx_entries: RingEntries,
    tx_entries: RingEntries,
    completion_entries: RingEntries,
    umem_config: UmemConfig,
    taken: Cell<bool>,
    held: RefCell<Vec<bool>>,
    tx_held: RefCell<Vec<bool>>,
    kicks: ScriptedKicks,
}

impl ScriptedKernel {
    pub(crate) fn new(fill: RingEntries, rx: RingEntries, umem: UmemConfig) -> Self {
        Self::with_tx(fill, rx, default_tx_entries(), default_tx_entries(), umem)
    }

    /// A kernel with explicit TX and Completion capacities.
    pub(crate) fn with_tx(
        fill: RingEntries,
        rx: RingEntries,
        tx: RingEntries,
        completion: RingEntries,
        umem: UmemConfig,
    ) -> Self {
        let umem_len = usize::try_from(umem.byte_len()).expect("test UMEM fits usize");
        Self {
            fill: HeapRegion::new(DESCRIPTORS + fill.get() as usize * 8),
            rx: HeapRegion::new(DESCRIPTORS + rx.get() as usize * 16),
            tx: HeapRegion::new(DESCRIPTORS + tx.get() as usize * 16),
            completion: HeapRegion::new(DESCRIPTORS + completion.get() as usize * 8),
            umem: HeapRegion::new(umem_len),
            fill_entries: fill,
            rx_entries: rx,
            tx_entries: tx,
            completion_entries: completion,
            umem_config: umem,
            taken: Cell::new(false),
            held: RefCell::new(vec![false; umem.frame_count() as usize]),
            tx_held: RefCell::new(vec![false; umem.frame_count() as usize]),
            kicks: ScriptedKicks::default(),
        }
    }

    /// Lends the application side as one bundle, at most once, exactly as
    /// `NativeSession::take_datapath` does.
    pub(crate) fn take_datapath(&self) -> Result<DatapathRings<'_>, DatapathError> {
        if self.taken.replace(true) {
            return Err(DatapathError::AlreadyTaken);
        }
        // SAFETY (all five): each region is one live zeroed heap allocation
        // that outlives the `&self` borrow and is freed only by Drop. The
        // once-only flag means at most one set of views ever exists. The
        // script touches the memory only through raw pointers: atomic
        // cursor words, volatile descriptors, and raw byte copies inside
        // frames it holds as kernel (never a frame the engine can lend).
        // That is the contract `from_raw_parts` states for kernel-shared
        // mappings.
        let fill = unsafe { BorrowedMmap::from_raw_parts(self.fill.base, self.fill.len()) };
        let rx = unsafe { BorrowedMmap::from_raw_parts(self.rx.base, self.rx.len()) };
        let tx = unsafe { BorrowedMmap::from_raw_parts(self.tx.base, self.tx.len()) };
        let completion =
            unsafe { BorrowedMmap::from_raw_parts(self.completion.base, self.completion.len()) };
        let umem = unsafe { UmemMapping::from_raw_parts(self.umem.base, self.umem.len()) };
        Ok(DatapathRings::new(DatapathParts {
            fill: FillProducer::with_mapping(fill, HEAP_RING_OFFSETS, self.fill_entries)
                .expect("heap Fill view"),
            completion: CompletionConsumer::with_mapping(
                completion,
                HEAP_RING_OFFSETS,
                self.completion_entries,
            )
            .expect("heap Completion view"),
            rx: RxConsumer::with_mapping(rx, HEAP_RING_OFFSETS, self.rx_entries)
                .expect("heap RX view"),
            tx: TxProducer::with_mapping(tx, HEAP_RING_OFFSETS, self.tx_entries)
                .expect("heap TX view"),
            umem,
            umem_config: self.umem_config,
            kick: SocketKick::new(KickTarget::Scripted(&self.kicks)),
        }))
    }

    fn frame_of(&self, address: u64) -> Option<usize> {
        let frame = address / u64::from(self.umem_config.frame_size());
        usize::try_from(frame)
            .ok()
            .filter(|frame| *frame < self.umem_config.frame_count() as usize)
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

    /// Kernel-consumes the oldest Fill entry; the frame is now held.
    ///
    /// Panics if the frame is already held: that would be a double
    /// publication of one frame, which the engine must never produce.
    pub(crate) fn consume_fill(&self) -> Option<u64> {
        let consumer = self.fill_consumer();
        if self.fill_producer() == consumer {
            return None;
        }
        let address = self.fill_entry(consumer);
        if let Some(frame) = self.frame_of(address) {
            let mut held = self.held.borrow_mut();
            assert!(!held[frame], "frame {frame} published to Fill twice");
            held[frame] = true;
        }
        self.fill
            .cursor(CONSUMER)
            .store(consumer.wrapping_add(1), Ordering::Release);
        Some(address)
    }

    /// Whether the script holds `frame` (taken from Fill, not returned).
    pub(crate) fn holds(&self, frame: u32) -> bool {
        self.held
            .borrow()
            .get(frame as usize)
            .copied()
            .unwrap_or(false)
    }

    pub(crate) fn rx_consumer(&self) -> u32 {
        self.rx.cursor(CONSUMER).load(Ordering::Acquire)
    }

    pub(crate) fn rx_producer(&self) -> u32 {
        self.rx.cursor(PRODUCER).load(Ordering::Relaxed)
    }

    /// Kernel-produces one RX descriptor; `false` if the RX ring is full.
    ///
    /// A descriptor naming a held frame returns that frame to the
    /// application; any other descriptor (invalid or duplicate) returns
    /// nothing.
    pub(crate) fn produce_rx(&self, descriptor: XdpDescriptor) -> bool {
        let producer = self.rx_producer();
        if producer.wrapping_sub(self.rx_consumer()) >= self.rx_entries.get() {
            return false;
        }
        if let Some(frame) = self.frame_of(descriptor.address) {
            self.held.borrow_mut()[frame] = false;
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

    /// Overwrites the Fill producer cursor, as a stale application would
    /// have left it (setup tests).
    pub(crate) fn set_fill_producer(&self, value: u32) {
        self.fill.cursor(PRODUCER).store(value, Ordering::Release);
    }

    /// Overwrites the Fill consumer cursor (corruption tests).
    pub(crate) fn set_fill_consumer(&self, value: u32) {
        self.fill.cursor(CONSUMER).store(value, Ordering::Release);
    }

    /// Sets the Fill flags word the kernel exposes.
    pub(crate) fn set_fill_flags(&self, value: u32) {
        self.fill.cursor(FLAGS).store(value, Ordering::Release);
    }

    /// Checks that `offset..offset + len` lies inside one held frame:
    /// Fill-held, or also TX-held when `tx_ok` (the kernel reads a frame
    /// it transmits but never writes it).
    fn held_range(&self, offset: u64, len: usize, tx_ok: bool) -> usize {
        let frame = self.frame_of(offset).expect("offset inside UMEM");
        let frame_size = u64::from(self.umem_config.frame_size());
        let end = offset + len as u64;
        assert!(
            end <= (frame as u64 + 1) * frame_size,
            "range crosses its frame"
        );
        assert!(
            self.held.borrow()[frame] || (tx_ok && self.tx_held.borrow()[frame]),
            "the script may touch only frames it holds as kernel"
        );
        usize::try_from(offset).expect("test offset")
    }

    /// Kernel-writes packet bytes into a frame it holds.
    pub(crate) fn write_umem(&self, offset: u64, bytes: &[u8]) {
        let offset = self.held_range(offset, bytes.len(), false);
        // SAFETY: `held_range` proved the range lies inside the allocation
        // and inside one frame the script holds as kernel: taken from Fill
        // and not returned on RX, so the engine's ledger records it as
        // `FillOwnedByKernel` and never lends it.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.umem.base.as_ptr().add(offset),
                bytes.len(),
            );
        }
    }

    /// Kernel-reads bytes back from a frame it holds (for example a frame
    /// recycled and republished after an in-place rewrite).
    pub(crate) fn read_umem(&self, offset: u64, out: &mut [u8]) {
        let offset = self.held_range(offset, out.len(), true);
        // SAFETY: as in `write_umem`; the engine holds no reference into a
        // frame the script holds.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.umem.base.as_ptr().add(offset),
                out.as_mut_ptr(),
                out.len(),
            );
        }
    }

    pub(crate) fn tx_producer(&self) -> u32 {
        self.tx.cursor(PRODUCER).load(Ordering::Acquire)
    }

    pub(crate) fn tx_consumer(&self) -> u32 {
        self.tx.cursor(CONSUMER).load(Ordering::Relaxed)
    }

    /// TX descriptors the application published and the kernel has not
    /// consumed.
    pub(crate) fn tx_pending(&self) -> u32 {
        self.tx_producer().wrapping_sub(self.tx_consumer())
    }

    /// Reads one published TX descriptor by logical cursor, without
    /// consuming.
    pub(crate) fn tx_entry(&self, logical: u32) -> XdpDescriptor {
        let slot = (logical & (self.tx_entries.get() - 1)) as usize;
        let pointer = self
            .tx
            .base
            .as_ptr()
            .wrapping_add(DESCRIPTORS + slot * 16)
            .cast::<XdpDescriptor>();
        // SAFETY: the slot lies inside the allocation, is 8-byte aligned,
        // and is read volatile like the kernel reads the mapping.
        unsafe { pointer.read_volatile() }
    }

    /// Kernel-consumes the oldest TX descriptor; its frame is now TX-held
    /// until a completion names it.
    ///
    /// Panics if the frame is already held as kernel (Fill or TX): that
    /// would be a double publication, which the engine must never produce.
    pub(crate) fn consume_tx(&self) -> Option<XdpDescriptor> {
        let consumer = self.tx_consumer();
        if self.tx_producer() == consumer {
            return None;
        }
        // The producer's Release store (Acquire-loaded above) published it.
        let descriptor = self.tx_entry(consumer);
        if let Some(frame) = self.frame_of(descriptor.address) {
            let mut tx_held = self.tx_held.borrow_mut();
            assert!(!tx_held[frame], "frame {frame} submitted to TX twice");
            assert!(
                !self.held.borrow()[frame],
                "frame {frame} submitted to TX while published to Fill"
            );
            tx_held[frame] = true;
        }
        self.tx
            .cursor(CONSUMER)
            .store(consumer.wrapping_add(1), Ordering::Release);
        Some(descriptor)
    }

    pub(crate) fn completion_producer(&self) -> u32 {
        self.completion.cursor(PRODUCER).load(Ordering::Relaxed)
    }

    pub(crate) fn completion_consumer(&self) -> u32 {
        self.completion.cursor(CONSUMER).load(Ordering::Acquire)
    }

    /// Kernel-produces one completion address; `false` if the Completion
    /// ring is full.
    ///
    /// An address inside a TX-held frame returns that frame; any other
    /// address (invalid or duplicate) returns nothing.
    pub(crate) fn produce_completion(&self, address: u64) -> bool {
        let producer = self.completion_producer();
        if producer.wrapping_sub(self.completion_consumer()) >= self.completion_entries.get() {
            return false;
        }
        if let Some(frame) = self.frame_of(address) {
            self.tx_held.borrow_mut()[frame] = false;
        }
        let slot = (producer & (self.completion_entries.get() - 1)) as usize;
        let pointer = self
            .completion
            .base
            .as_ptr()
            .wrapping_add(DESCRIPTORS + slot * 8)
            .cast::<u64>();
        // SAFETY: the slot lies inside the allocation and is 8-byte aligned.
        // The Release store below publishes it after the write.
        unsafe { pointer.write_volatile(address) };
        self.completion
            .cursor(PRODUCER)
            .store(producer.wrapping_add(1), Ordering::Release);
        true
    }

    /// Whether the script holds `frame` for TX (consumed, not completed).
    pub(crate) fn tx_holds(&self, frame: u32) -> bool {
        self.tx_held
            .borrow()
            .get(frame as usize)
            .copied()
            .unwrap_or(false)
    }

    /// Sets the TX flags word the kernel exposes.
    pub(crate) fn set_tx_flags(&self, value: u32) {
        self.tx.cursor(FLAGS).store(value, Ordering::Release);
    }

    /// Overwrites the TX producer cursor, as a stale application would
    /// have left it (setup tests).
    pub(crate) fn set_tx_producer(&self, value: u32) {
        self.tx.cursor(PRODUCER).store(value, Ordering::Release);
    }

    /// Overwrites the TX consumer cursor (corruption tests).
    pub(crate) fn set_tx_consumer(&self, value: u32) {
        self.tx.cursor(CONSUMER).store(value, Ordering::Release);
    }

    /// Overwrites the Completion producer cursor (corruption tests).
    pub(crate) fn set_completion_producer(&self, value: u32) {
        self.completion
            .cursor(PRODUCER)
            .store(value, Ordering::Release);
    }

    /// Kicks the engine performed on `ring`.
    pub(crate) fn kicks(&self, ring: KickRing) -> u32 {
        self.kicks.count(ring)
    }

    /// Makes the next kick fail with `errno` (`None`: refused before the
    /// kernel).
    pub(crate) fn fail_next_kick(&self, errno: Option<u16>) {
        self.kicks.fail_next(errno);
    }
}
