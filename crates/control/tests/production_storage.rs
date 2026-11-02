//! H3: the maximal production config builds its runtime storage within the
//! documented memory bound. Its own test binary, so the counting allocator
//! sees only this test.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    mem::size_of,
    num::NonZeroU64,
    sync::atomic::{AtomicUsize, Ordering},
};

use ruster_config::{parse, validate, ValidatedConfig, PRODUCTION_VALIDATION_LIMITS};
use ruster_control::{candidate_from_config, FullServiceStorage, SimDeterministicKeySource};
use ruster_core::{
    port_free_bitmap_words, DirectoryBucket, DirectoryNode, DynamicNeighborSlot, FirewallStateSlot,
    Icmpv4ErrorActionSlot, Icmpv4ErrorStateSlot, Nat44TcpMappingSlot, Nat44TcpSessionSlot,
    Nat44UdpMappingSlot, Nat44UdpPeerSlot, PortOwnerSlot, ResolutionActionSlot,
    ResolutionFailureHoldSlot, ResolutionStateSlot,
};

/// Bytes currently allocated through the global allocator.
static LIVE: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

// SAFETY: every method forwards to `System` with the caller's arguments and
// only adjusts a counter.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc_zeroed` contract.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: `pointer` and `layout` came from this allocator.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::realloc` contract.
        let moved = unsafe { System.realloc(pointer, layout, size) };
        if !moved.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            LIVE.fetch_add(size, Ordering::Relaxed);
        }
        moved
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

const MAXIMAL: &str = include_str!("../../../fixtures/limits/router-production-max.toml");

/// Every table at its production limit, the port pool at its
/// widest, computed from the slot types `FullServiceStorage` allocates.
fn worst_case_bytes() -> usize {
    let slots = PRODUCTION_VALIDATION_LIMITS.max_slots_per_table as usize;
    let quote = PRODUCTION_VALIDATION_LIMITS.max_quote_slots_per_table as usize;
    let ports = 65_535;
    let directory = size_of::<DirectoryBucket>() + size_of::<DirectoryNode>();
    // One owner slot per pool port plus the free-port bitmap.
    let port_index = ports * size_of::<PortOwnerSlot>() + port_free_bitmap_words(ports) * 8;
    // Failure holds and ICMPv4 error actions hold a quoted datagram.
    let resolution = slots
        * (size_of::<ResolutionStateSlot>()
            + size_of::<ResolutionActionSlot>()
            + size_of::<DynamicNeighborSlot>())
        + quote * size_of::<ResolutionFailureHoldSlot>();
    let icmpv4 =
        slots * size_of::<Icmpv4ErrorStateSlot>() + quote * size_of::<Icmpv4ErrorActionSlot>();
    let udp = slots * (size_of::<Nat44UdpMappingSlot>() + size_of::<Nat44UdpPeerSlot>())
        + 2 * slots * directory
        + port_index;
    // Mapping, session, and session remote-address directories.
    let tcp = slots * (size_of::<Nat44TcpMappingSlot>() + size_of::<Nat44TcpSessionSlot>())
        + 3 * slots * directory
        + port_index;
    let firewall = slots * size_of::<FirewallStateSlot>();
    resolution + icmpv4 + udp + tcp + firewall
}

#[test]
fn the_maximal_production_config_allocates_within_the_documented_bound() {
    // Documented in the runbook ("Validation limits and memory").
    const WORST_CASE: usize = 53_592_256;
    assert_eq!(worst_case_bytes(), WORST_CASE);
    const { assert!(WORST_CASE <= PRODUCTION_VALIDATION_LIMITS.max_runtime_bytes) };

    let parsed = parse(MAXIMAL.as_bytes()).expect("parse");
    let Ok(ValidatedConfig::V1(config)) = validate(parsed, PRODUCTION_VALIDATION_LIMITS) else {
        panic!("the maximal config is within the production limits");
    };
    assert_eq!(config.storage_shape().required_bytes, WORST_CASE);
    let mut keys = SimDeterministicKeySource::new(0);
    let candidate =
        candidate_from_config(&config, NonZeroU64::MIN, &mut keys).expect("bridge accepts");

    let before = LIVE.load(Ordering::Relaxed);
    let storage = FullServiceStorage::new(candidate.storage_shape()).expect("allocates");
    let allocated = LIVE.load(Ordering::Relaxed) - before;
    // The arrays exactly; `Box<[T]>` has no spare capacity.
    assert_eq!(allocated, WORST_CASE);
    assert!(allocated <= PRODUCTION_VALIDATION_LIMITS.max_runtime_bytes);
    drop(storage);
    assert_eq!(LIVE.load(Ordering::Relaxed), before);
}
