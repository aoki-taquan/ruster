//! Steady-state allocation check for the observability sink. Kept in its own
//! test binary so no concurrently running test perturbs the counter.

mod observability_support;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    num::NonZeroU64,
    sync::atomic::{AtomicUsize, Ordering},
};

use observability_support::*;
use ruster_core::{
    ConsumeReason, DropReason, ForwardingSnapshot, Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy,
    Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, MonotonicMillis, ResolutionActionSlot,
    ResolutionFailureHoldSlot, ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot,
};
use ruster_io_sim::SimIo;
use ruster_runtime::{run_tick, BackendStats, HealthState, TickBudgets, TickObserver};

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `layout` is the allocator contract supplied by the caller.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` and `layout` came from this allocator.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `layout` is the allocator contract supplied by the caller.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `pointer` and `layout` came from this allocator.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

const TICKS: u64 = 256;

fn frames() -> [Vec<u8>; 4] {
    [
        truncated_ethernet(),
        unsupported_ethertype(),
        bad_ipv4_checksum(),
        local_udp(),
    ]
}

#[test]
fn observability_sink_is_allocation_free_in_steady_state() {
    let routes = routes();
    let snapshot = ForwardingSnapshot::new(&routes, &INTERFACES, &[], &BINDINGS).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut holds = [ResolutionFailureHoldSlot::EMPTY; 2];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        &mut states,
        &mut actions,
        &mut [],
        &mut holds,
    );
    let mut icmp_states = [Icmpv4ErrorStateSlot::EMPTY; 2];
    let mut icmp_actions = [Icmpv4ErrorActionSlot::EMPTY; 2];
    let mut icmpv4_errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut icmp_states,
        &mut icmp_actions,
    );
    let mut publication = Publication {
        generation: NonZeroU64::MIN,
        snapshot: &snapshot,
        resolution: &mut resolution,
        icmpv4_errors: &mut icmpv4_errors,
        udp_config: udp_config(&snapshot),
        tcp_config: tcp_config(&snapshot),
        firewall_config: firewall_config(&snapshot),
    };
    let mut io = SimIo::new();
    let mut observer = TickObserver::default();
    let budgets = TickBudgets {
        rx: 8,
        resolution_timer_scans: 4,
        failure_dispatch_scans: 4,
        generated_arp: 4,
        generated_icmpv4: 4,
    };

    // Warm-up grows the simulated backend's queues once.
    for frame in frames() {
        io.inject(LAN, frame);
    }
    let report = run_tick(
        &mut publication,
        None,
        &mut io,
        MonotonicMillis(0),
        budgets,
        &mut observer,
    );
    observer.observe_tick(MonotonicMillis(0), Some(publication.generation), &report);
    while io.pop_recycled().is_some() {}

    // The sim backend's injected frames are cold-side Vecs; build them first.
    let mut pending: Vec<Vec<u8>> = (0..TICKS).flat_map(|_| frames()).collect();

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut last = None;
    for tick in 1..=TICKS {
        for _ in 0..4 {
            io.inject(LAN, pending.pop().unwrap());
        }
        let now = MonotonicMillis(tick);
        let report = run_tick(&mut publication, None, &mut io, now, budgets, &mut observer);
        observer.observe_tick(now, Some(publication.generation), &report);
        last = Some((observer.snapshot(now), io.backend_stats()));
        while io.pop_recycled().is_some() {}
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    assert_eq!(
        after - before,
        0,
        "sink, aggregation, and snapshots allocate nothing"
    );

    let (snapshot, backend) = last.unwrap();
    let ticks = TICKS + 1;
    assert_eq!(snapshot.state, HealthState::Healthy);
    assert_eq!(snapshot.totals.ticks, ticks);
    assert_eq!(snapshot.totals.successful_ticks, ticks);
    assert_eq!(
        snapshot.drops.count(DropReason::EthernetHeaderTruncated),
        ticks
    );
    assert_eq!(
        snapshot.drops.count(DropReason::UnsupportedEtherType),
        ticks
    );
    assert_eq!(
        snapshot.drops.count(DropReason::Ipv4HeaderChecksumInvalid),
        ticks
    );
    assert_eq!(
        snapshot.consumes.count(ConsumeReason::Ipv4LocalUnsupported),
        ticks
    );
    assert_eq!(snapshot.totals.rx.received, 4 * ticks);
    assert_eq!(backend.injected, 4 * ticks);
}
