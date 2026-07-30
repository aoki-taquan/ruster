use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
};

use ruster_core::{
    FirewallConfig, FirewallHashKey, FirewallPolicy, FirewallRuntime, ForwardingSnapshot,
    GeneratedIcmpv4Trace, GeneratedIcmpv4TraceSink, GeneratedTraceSink, Icmpv4ErrorActionSlot,
    Icmpv4ErrorPolicy, Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address,
    LocalIpv4Binding, MacAddress, MonotonicMillis, Nat44TcpConfig, Nat44TcpPolicy, Nat44TcpRuntime,
    Nat44UdpConfig, Nat44UdpPolicy, Nat44UdpRuntime, ResolutionActionSlot,
    ResolutionFailureHoldSlot, ResolutionFailureTrace, ResolutionFailureTraceSink,
    ResolutionPolicy, ResolutionRuntime, ResolutionStateSlot, ResolutionTimerTrace,
    ResolutionTimerTraceSink, TraceEvent, TraceSink,
};
use ruster_io_sim::SimIo;
use ruster_runtime::{
    run_tick, FullServicePublication, FullServiceView, TickBudgets, TickPhaseTrace,
    TickPhaseTraceSink,
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
        Ok(())
    }

    fn active(&mut self) -> Option<FullServiceView<'_, 'storage>> {
        Some(FullServiceView {
            snapshot: self.snapshot,
            resolution: self.resolution,
            icmpv4_errors: self.icmpv4_errors,
            udp_config: self.udp_config,
            nat44_udp: None::<&mut Nat44UdpRuntime<'_>>,
            tcp_config: self.tcp_config,
            nat44_tcp: None::<&mut Nat44TcpRuntime<'_>>,
            firewall_config: self.firewall_config,
            firewall: None::<&mut FirewallRuntime<'_>>,
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
fn active_zero_budget_steady_tick_allocates_nothing() {
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
        snapshot: &snapshot,
        resolution: &mut resolution,
        icmpv4_errors: &mut icmpv4_errors,
        udp_config,
        tcp_config,
        firewall_config,
    };
    let mut io = SimIo::new();
    let mut trace = NoTrace;

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let report = run_tick(
        &mut publication,
        None,
        &mut io,
        MonotonicMillis(0),
        TickBudgets::default(),
        &mut trace,
    );
    let after = ALLOCATIONS.load(Ordering::Relaxed);

    assert!(report.active);
    assert_eq!(after - before, 0);
}
