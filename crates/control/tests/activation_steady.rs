#![cfg(feature = "validation-test-hooks")]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    num::NonZeroU64,
    sync::atomic::{AtomicUsize, Ordering},
};

use ruster_control::{
    ActivePublication, FirewallPublicationInput, FullServiceStorage, FullServiceStorageShape,
    Icmpv4ErrorStorageShape, Nat44TcpPublicationInput, Nat44TcpStoragePlan,
    Nat44UdpPublicationInput, Nat44UdpStoragePlan, PublicationPlan, ResolutionStorageShape,
    ValidatedCandidate,
};
use ruster_core::{
    take_full_firewall_validation_count, take_full_forwarding_validation_count, FirewallHashKey,
    FirewallPolicy, GeneratedArpTrace, GeneratedIcmpv4Trace, GeneratedIcmpv4TraceSink,
    GeneratedTraceSink, Icmpv4ErrorPolicy, IfId, Interface, Ipv4Address, Ipv4OriginPolicy,
    LocalIpv4Binding, MacAddress, MonotonicMillis, Nat44TcpHashKey, Nat44TcpPolicy,
    Nat44UdpHashKey, Nat44UdpPolicy, ResolutionFailureTrace, ResolutionFailureTraceSink,
    ResolutionPolicy, ResolutionTimerTrace, ResolutionTimerTraceSink, Route, TraceEvent, TraceSink,
};
use ruster_io_sim::SimIo;
use ruster_runtime::{
    run_tick, PublicationOutcome, TickBudgets, TickPhaseTrace, TickPhaseTraceSink,
};

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `layout` is supplied by the allocator contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` and `layout` came from this allocator.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `layout` is supplied by the allocator contract.
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

struct Quiet;

impl TickPhaseTraceSink for Quiet {
    fn record_tick_phase(&mut self, _: TickPhaseTrace) {}
}
impl TraceSink for Quiet {
    fn record(&mut self, _: TraceEvent) {}
}
impl ResolutionTimerTraceSink for Quiet {
    fn record_resolution_timer(&mut self, _: ResolutionTimerTrace) {}
}
impl ResolutionFailureTraceSink for Quiet {
    fn record_resolution_failure(&mut self, _: ResolutionFailureTrace) {}
}
impl GeneratedTraceSink for Quiet {
    fn record_generated(&mut self, _: GeneratedArpTrace) {}
}
impl GeneratedIcmpv4TraceSink for Quiet {
    fn record_generated_icmpv4(&mut self, _: GeneratedIcmpv4Trace) {}
}

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);

fn candidate(generation: u64) -> ValidatedCandidate {
    let key = generation * 8;
    let routes = [
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
        Route::new(
            Ipv4Address::from_octets([0; 4]),
            0,
            WAN,
            Some(Ipv4Address::from_octets([203, 0, 113, 1])),
        )
        .unwrap(),
    ];
    let interfaces = [
        Interface {
            id: LAN,
            mac: MacAddress([2, 0, 0, 0, 0, 1]),
        },
        Interface {
            id: WAN,
            mac: MacAddress([2, 0, 0, 0, 0, 2]),
        },
    ];
    let bindings = [
        LocalIpv4Binding {
            interface: LAN,
            address: Ipv4Address::from_octets([10, 0, 0, 1]),
        },
        LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        },
    ];
    let shape = FullServiceStorageShape::new(
        ResolutionStorageShape::new(4, 4, 4, 4),
        Icmpv4ErrorStorageShape::new(4, 4),
        Nat44UdpStoragePlan::new(4, 8, 4, 4, 8, 8, 8),
        Nat44TcpStoragePlan::new(4, 8, 4, 4, 8, 8, 8),
        16,
    );
    let plan = PublicationPlan::new(
        NonZeroU64::new(generation).unwrap(),
        shape,
        routes.into(),
        interfaces.into(),
        Vec::new().into_boxed_slice(),
        bindings.into(),
        Ipv4OriginPolicy::default(),
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        Icmpv4ErrorPolicy::default(),
    )
    .with_nat44_udp(Nat44UdpPublicationInput::new(
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_007,
        Nat44UdpPolicy::default(),
        Nat44UdpHashKey::new(key + 1, key + 2).unwrap(),
    ))
    .with_nat44_tcp(Nat44TcpPublicationInput::new(
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_007,
        Nat44TcpPolicy::default(),
        Nat44TcpHashKey::new(key + 3, key + 4).unwrap(),
    ))
    .with_firewall(FirewallPublicationInput::new(
        Vec::new().into_boxed_slice(),
        FirewallPolicy::default(),
        FirewallHashKey::new(key + 5, key + 6).unwrap(),
    ));
    ValidatedCandidate::new(plan).unwrap()
}

fn allocations_during(run: impl FnOnce()) -> usize {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    run();
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

#[test]
fn activated_publication_ticks_and_applies_without_allocation_or_revalidation() {
    let first = candidate(1);
    let successor = candidate(2);
    let mut storage = FullServiceStorage::new(first.storage_shape()).unwrap();
    let mut active = ActivePublication::new(&mut storage, first).unwrap();
    let mut io = SimIo::new();
    let mut trace = Quiet;
    let budgets = TickBudgets {
        rx: 32,
        resolution_timer_scans: 8,
        failure_dispatch_scans: 8,
        generated_arp: 8,
        generated_icmpv4: 8,
    };
    take_full_forwarding_validation_count();
    take_full_firewall_validation_count();

    let steady = allocations_during(|| {
        for now in 0..1_024 {
            let report = run_tick(
                &mut active,
                None,
                &mut io,
                MonotonicMillis(now),
                budgets,
                &mut trace,
            );
            assert!(report.active);
        }
    });
    assert_eq!(steady, 0, "steady active ticks allocate");

    let mut successor = Some(successor);
    let apply = allocations_during(|| {
        let report = run_tick(
            &mut active,
            successor.take(),
            &mut io,
            MonotonicMillis(1_024),
            budgets,
            &mut trace,
        );
        assert_eq!(report.publication, PublicationOutcome::Applied);
    });
    assert_eq!(apply, 0, "applying a prebuilt successor allocates");
    assert_eq!(active.generation().get(), 2);

    let after_apply = allocations_during(|| {
        for now in 1_025..2_048 {
            let report = run_tick(
                &mut active,
                None,
                &mut io,
                MonotonicMillis(now),
                budgets,
                &mut trace,
            );
            assert!(report.active);
        }
    });
    assert_eq!(after_apply, 0);
    assert_eq!(take_full_forwarding_validation_count(), 0);
    assert_eq!(take_full_firewall_validation_count(), 0);
}
