use std::{
    alloc::{GlobalAlloc, Layout, System},
    num::NonZeroU64,
    sync::atomic::{AtomicUsize, Ordering},
};

#[cfg(target_pointer_width = "64")]
use std::mem::size_of;

use ruster_core::{
    FirewallConfig, FirewallHashKey, FirewallPolicy, ForwardingSnapshot, GeneratedIcmpv4Trace,
    GeneratedIcmpv4TraceSink, GeneratedTraceSink, Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy,
    Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address, LocalIpv4Binding,
    MacAddress, MonotonicMillis, Nat44TcpConfig, Nat44TcpPolicy, Nat44UdpConfig, Nat44UdpPolicy,
    ResolutionActionSlot, ResolutionFailureHoldSlot, ResolutionFailureTrace,
    ResolutionFailureTraceSink, ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot,
    ResolutionTimerTrace, ResolutionTimerTraceSink, TraceEvent, TraceSink,
};
use ruster_io_sim::SimIo;
use ruster_runtime::{
    run_tick, FirewallServiceView, FullServicePublication, FullServiceView, Nat44TcpServiceView,
    Nat44UdpServiceView, TickBudgets, TickPhaseTrace, TickPhaseTraceSink,
};

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

struct Publication<'view, 'storage> {
    generation: NonZeroU64,
    active_calls: usize,
    semantic_validation_calls: usize,
    fingerprint_calls: usize,
    hash_calls: usize,
    slice_scan_calls: usize,
    snapshot: &'view ForwardingSnapshot<'storage>,
    resolution: &'view mut ResolutionRuntime<'storage>,
    icmpv4_errors: &'view mut Icmpv4ErrorRuntime<'storage>,
    udp_config: Nat44UdpConfig,
    tcp_config: Nat44TcpConfig,
    firewall_config: FirewallConfig<'storage>,
}

impl<'view, 'storage> FullServicePublication<'storage> for Publication<'view, 'storage> {
    type Candidate = ();
    type Reject = ();

    fn publish_candidate(&mut self, _candidate: Self::Candidate) -> Result<(), Self::Reject> {
        self.semantic_validation_calls += 1;
        self.fingerprint_calls += 1;
        self.hash_calls += 1;
        self.slice_scan_calls += 1;
        Ok(())
    }

    fn active(&mut self) -> Option<FullServiceView<'_, 'storage>> {
        self.active_calls += 1;
        Some(FullServiceView {
            generation: self.generation,
            snapshot: *self.snapshot,
            resolution: self.resolution,
            icmpv4_errors: self.icmpv4_errors,
            nat44_udp: Nat44UdpServiceView {
                config: self.udp_config,
                runtime: None,
            },
            nat44_tcp: Nat44TcpServiceView {
                config: self.tcp_config,
                runtime: None,
            },
            firewall: FirewallServiceView {
                config: self.firewall_config,
                runtime: None,
            },
        })
    }
}

struct NoTrace;

impl TickPhaseTraceSink for NoTrace {
    fn record_tick_phase(&mut self, _event: TickPhaseTrace) {}
}

impl TraceSink for NoTrace {
    fn record(&mut self, _event: TraceEvent) {}
}

impl ResolutionTimerTraceSink for NoTrace {
    fn record_resolution_timer(&mut self, _event: ResolutionTimerTrace) {}
}

impl ResolutionFailureTraceSink for NoTrace {
    fn record_resolution_failure(&mut self, _event: ResolutionFailureTrace) {}
}

impl GeneratedTraceSink for NoTrace {
    fn record_generated(&mut self, _event: ruster_core::GeneratedArpTrace) {}
}

impl GeneratedIcmpv4TraceSink for NoTrace {
    fn record_generated_icmpv4(&mut self, _event: GeneratedIcmpv4Trace) {}
}

#[test]
fn by_value_active_view_is_bounded_tick_local_and_steady_o1() {
    const LAN: IfId = IfId(1);
    const WAN: IfId = IfId(2);
    const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
    let routes = [
        ruster_core::Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
        ruster_core::Route::new(
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
    let snapshot = ForwardingSnapshot::new(&routes, &interfaces, &[], &bindings).unwrap();
    let udp_config = Nat44UdpConfig::new(
        &snapshot,
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44UdpPolicy::default(),
    )
    .unwrap();
    let tcp_config = Nat44TcpConfig::new(
        &snapshot,
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44TcpPolicy::default(),
    )
    .unwrap();
    let firewall_config = FirewallConfig::new(
        &snapshot,
        &[],
        FirewallPolicy::default(),
        1,
        FirewallHashKey::new(1, 2).unwrap(),
    )
    .unwrap();
    let mut resolution_states = [ResolutionStateSlot::EMPTY; 1];
    let mut resolution_actions = [ResolutionActionSlot::EMPTY; 1];
    let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 1];
    let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        &mut resolution_states,
        &mut resolution_actions,
        &mut [],
        &mut failure_holds,
    );
    let mut icmp_states = [Icmpv4ErrorStateSlot::EMPTY; 1];
    let mut icmp_actions = [Icmpv4ErrorActionSlot::EMPTY; 1];
    let mut icmpv4_errors = Icmpv4ErrorRuntime::new(
        Icmpv4ErrorPolicy::default(),
        &mut icmp_states,
        &mut icmp_actions,
    );
    let mut publication = Publication {
        generation: NonZeroU64::MIN,
        active_calls: 0,
        semantic_validation_calls: 0,
        fingerprint_calls: 0,
        hash_calls: 0,
        slice_scan_calls: 0,
        snapshot: &snapshot,
        resolution: &mut resolution,
        icmpv4_errors: &mut icmpv4_errors,
        udp_config,
        tcp_config,
        firewall_config,
    };
    let mut io = SimIo::new();
    let mut trace = NoTrace;

    #[cfg(target_pointer_width = "64")]
    {
        assert_eq!(size_of::<ForwardingSnapshot<'static>>(), 144);
        assert_eq!(size_of::<FirewallConfig<'static>>(), 160);
        assert_eq!(size_of::<Nat44UdpConfig>(), 112);
        assert_eq!(size_of::<Nat44TcpConfig>(), 112);
        assert_eq!(size_of::<Nat44UdpServiceView<'static, 'static>>(), 120);
        assert_eq!(size_of::<Nat44TcpServiceView<'static, 'static>>(), 120);
        assert_eq!(size_of::<FirewallServiceView<'static, 'static>>(), 168);
        assert!(size_of::<FullServiceView<'static, 'static>>() <= 576);
    }

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for tick in 0..1_024 {
        let report = run_tick(
            &mut publication,
            None,
            &mut io,
            MonotonicMillis(tick),
            TickBudgets::default(),
            &mut trace,
        );
        assert!(report.active);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);

    assert_eq!(publication.active_calls, 1_024);
    assert_eq!(publication.semantic_validation_calls, 0);
    assert_eq!(publication.fingerprint_calls, 0);
    assert_eq!(publication.hash_calls, 0);
    assert_eq!(publication.slice_scan_calls, 0);
    assert_eq!(after - before, 0);
}
