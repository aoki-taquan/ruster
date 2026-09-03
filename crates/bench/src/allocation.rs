use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

/// Allocator used by the `ruster-bench` binary to count successful allocation
/// and reallocation calls in timed regions.
///
/// The library does not install this allocator globally. Keeping the
/// declaration in the binary lets a downstream identity-only consumer choose
/// its own allocator without a linker-level global allocator conflict.
pub struct CountingAllocator;

thread_local! {
    static ALLOCATION_COUNT: Cell<u64> = const { Cell::new(0) };
}

// SAFETY: every operation delegates unchanged pointers and layouts to the
// standard system allocator. The counter is independent of allocation
// ownership. A const thread-local Cell keeps concurrent test and runner
// allocations from contaminating the measured worker.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies the GlobalAlloc layout contract.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            increment_count();
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies the GlobalAlloc layout contract.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            increment_count();
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the caller guarantees that pointer and layout came from this
        // allocator; this implementation delegates all allocations to System.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller supplies the GlobalAlloc reallocation contract.
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if !new_pointer.is_null() {
            increment_count();
        }
        new_pointer
    }
}

#[cfg(test)]
#[global_allocator]
static TEST_GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

fn increment_count() {
    ALLOCATION_COUNT.with(|count| count.set(count.get().saturating_add(1)));
}

/// Returns this thread's count of successful allocation or reallocation calls.
///
/// Benchmark timed regions run on the packet worker thread and compare
/// snapshots, so unrelated test or process threads cannot contaminate a row.
#[must_use]
pub fn allocation_count() -> u64 {
    ALLOCATION_COUNT.with(Cell::get)
}

/// Checks that the process selected this crate's counting allocator before a
/// run starts measuring. A library consumer is otherwise allowed to select a
/// different global allocator, in which case `allocation_count` would remain
/// at zero and an allocation-free result would be unverifiable.
pub(crate) fn allocation_instrumentation_available() -> bool {
    let before = allocation_count();
    let probe = Vec::<u8>::with_capacity(1);
    std::hint::black_box(&probe);
    let after = allocation_count();
    drop(probe);
    after != before
}
