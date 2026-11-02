//! H3: the maximal production config builds its runtime storage within the
//! documented memory bound. Its own test binary, so the counting allocator
//! sees only this test.

use std::{mem::size_of, num::NonZeroU64};

use ruster_config::{parse, validate, ValidatedConfig, PRODUCTION_VALIDATION_LIMITS};
use ruster_control::{candidate_from_config, FullServiceStorage, SimDeterministicKeySource};
use ruster_core::{
    port_free_bitmap_words, DirectoryBucket, DirectoryNode, DynamicNeighborSlot, FirewallStateSlot,
    Icmpv4ErrorActionSlot, Icmpv4ErrorStateSlot, Nat44HostCounter, Nat44HostLink, Nat44TcpHostSlot,
    Nat44TcpMappingSlot, Nat44TcpSessionSlot, Nat44TcpSynHoldSlot, Nat44UdpHostSlot,
    Nat44UdpMappingSlot, Nat44UdpPeerSlot, PortOwnerSlot, ResolutionActionSlot,
    ResolutionFailureHoldSlot, ResolutionStateSlot,
};

/// Net bytes the measuring thread allocated while armed.
///
/// Process-wide accounting also saw other threads (the libtest harness
/// thread) allocate or free concurrently, which could break the exact
/// comparison. Only this thread builds the storage, so only it counts;
/// [`live::self_check`] proves the counter is live.
#[allow(unsafe_code)]
mod live {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static ARMED: Cell<bool> = const { Cell::new(false) };
        static NET: Cell<isize> = const { Cell::new(0) };
    }

    fn note(delta: isize) {
        if ARMED.try_with(Cell::get).unwrap_or(false) {
            let _ = NET.try_with(|net| net.set(net.get().wrapping_add(delta)));
        }
    }

    fn signed(size: usize) -> isize {
        isize::try_from(size).expect("allocation sizes fit isize")
    }

    pub struct Counting;

    // SAFETY: every method forwards the caller's arguments unchanged to
    // `System` and only adjusts a const thread-local counter.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract.
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() {
                note(signed(layout.size()));
            }
            pointer
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller upholds the `GlobalAlloc::alloc_zeroed` contract.
            let pointer = unsafe { System.alloc_zeroed(layout) };
            if !pointer.is_null() {
                note(signed(layout.size()));
            }
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            note(-signed(layout.size()));
            // SAFETY: `pointer` and `layout` came from this allocator.
            unsafe { System.dealloc(pointer, layout) }
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            // SAFETY: the caller upholds the `GlobalAlloc::realloc` contract.
            let moved = unsafe { System.realloc(pointer, layout, size) };
            if !moved.is_null() {
                note(signed(size) - signed(layout.size()));
            }
            moved
        }
    }

    /// Resets this thread's net bytes and starts counting.
    pub fn start() {
        NET.with(|net| net.set(0));
        ARMED.with(|armed| armed.set(true));
    }

    /// This thread's net bytes since `start` (still counting).
    pub fn net() -> isize {
        NET.with(Cell::get)
    }

    pub fn stop() {
        ARMED.with(|armed| armed.set(false));
    }

    /// The counter sees this thread's allocation and its release.
    pub fn self_check() {
        start();
        let probe = std::hint::black_box(Vec::<u8>::with_capacity(24));
        let allocated = net();
        drop(probe);
        let released = net();
        stop();
        assert_eq!(
            (allocated, released),
            (24, 0),
            "the counting allocator is live"
        );
    }
}

#[global_allocator]
static GLOBAL: live::Counting = live::Counting;

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
    // Mapping, session, and session remote-address directories, and the
    // unsolicited-SYN holds (each with a quoted datagram).
    let tcp = slots * (size_of::<Nat44TcpMappingSlot>() + size_of::<Nat44TcpSessionSlot>())
        + 3 * slots * directory
        + port_index
        + quote * size_of::<Nat44TcpSynHoldSlot>();
    let firewall = slots * size_of::<FirewallStateSlot>();
    resolution + icmpv4 + udp + tcp + firewall
}

#[test]
fn the_maximal_production_config_allocates_within_the_documented_bound() {
    // Documented in the runbook ("Validation limits and memory").
    const WORST_CASE: usize = 57_065_664;
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

    live::self_check();
    live::start();
    let storage = FullServiceStorage::new(candidate.storage_shape()).expect("allocates");
    let allocated = usize::try_from(live::net()).expect("storage allocates");
    // The arrays exactly; `Box<[T]>` has no spare capacity.
    assert_eq!(allocated, WORST_CASE);
    assert!(allocated <= PRODUCTION_VALIDATION_LIMITS.max_runtime_bytes);
    drop(storage);
    assert_eq!(live::net(), 0);
    live::stop();
}

/// N3: per-host mapping accounting on both protocols adds, per mapping
/// slot, one host link, one host slot, and one host directory node and
/// bucket. The maximal config with `mappings-per-host` set on both still
/// fits the production byte bound, and the storage allocates exactly what
/// `required_bytes` counts.
#[test]
fn the_maximal_config_with_per_host_limits_still_fits_the_bound() {
    let slots = PRODUCTION_VALIDATION_LIMITS.max_slots_per_table as usize;
    let directory = size_of::<DirectoryBucket>() + size_of::<DirectoryNode>();
    let host_bytes = slots
        * (2 * (size_of::<Nat44HostLink>() + directory)
            + size_of::<Nat44UdpHostSlot>()
            + size_of::<Nat44TcpHostSlot>()
            + size_of::<u32>()
            + size_of::<Nat44HostCounter>());
    // 12-byte links, 24- and 36-byte host slots (one and two host lists),
    // and the UDP table's 4-byte link word and 8-byte peer counter (N6).
    assert_eq!(host_bytes, 9_961_472);
    let worst_case = worst_case_bytes() + host_bytes;
    assert_eq!(worst_case, 67_027_136);
    assert!(worst_case <= PRODUCTION_VALIDATION_LIMITS.max_runtime_bytes);

    let text = MAXIMAL
        .replacen(
            "[nat44.udp.capacity]",
            "mappings-per-host = 256\n\n[nat44.udp.capacity]",
            1,
        )
        .replacen(
            "[nat44.tcp.capacity]",
            "mappings-per-host = 256\n\n[nat44.tcp.capacity]",
            1,
        );
    let parsed = parse(text.as_bytes()).expect("parse");
    let Ok(ValidatedConfig::V1(config)) = validate(parsed, PRODUCTION_VALIDATION_LIMITS) else {
        panic!("per-host limits keep the maximal config within the production limits");
    };
    assert_eq!(config.storage_shape().required_bytes, worst_case);
    let mut keys = SimDeterministicKeySource::new(0);
    let candidate =
        candidate_from_config(&config, NonZeroU64::MIN, &mut keys).expect("bridge accepts");
    assert_eq!(candidate.storage_shape().nat44_udp().host_slots(), 65_536);
    assert_eq!(candidate.storage_shape().nat44_tcp().host_slots(), 65_536);

    live::self_check();
    live::start();
    let storage = FullServiceStorage::new(candidate.storage_shape()).expect("allocates");
    assert_eq!(
        usize::try_from(live::net()).expect("storage allocates"),
        worst_case
    );
    drop(storage);
    assert_eq!(live::net(), 0);
    live::stop();
}
