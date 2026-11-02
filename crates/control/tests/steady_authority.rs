#![cfg(feature = "validation-test-hooks")]

use std::num::NonZeroU64;

use ruster_control::{
    FirewallPublicationInput, FullServiceStorageShape, Icmpv4ErrorStorageShape,
    Nat44TcpPublicationInput, Nat44TcpStoragePlan, Nat44UdpPublicationInput, Nat44UdpStoragePlan,
    PublicationPlan, ResolutionStorageShape, ValidatedCandidate,
};
use ruster_core::{
    take_full_firewall_validation_count, take_full_forwarding_validation_count, FirewallHashKey,
    FirewallPolicy, Icmpv4ErrorPolicy, IfId, Interface, Ipv4Address, Ipv4OriginPolicy,
    LocalIpv4Binding, MacAddress, Nat44TcpHashKey, Nat44TcpPolicy, Nat44UdpHashKey, Nat44UdpPolicy,
    ResolutionPolicy, Route,
};

/// Counts the allocations of the measuring thread while it is armed.
///
/// A process-wide counter also saw allocations of other threads (the
/// libtest harness thread, which reports results concurrently) and flaked.
/// Only this thread's work is measured, so only this thread counts;
/// [`counting::self_check`] proves the counter is live.
#[allow(unsafe_code)]
mod counting {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static ARMED: Cell<bool> = const { Cell::new(false) };
        static COUNT: Cell<usize> = const { Cell::new(0) };
    }

    fn note() {
        if ARMED.try_with(Cell::get).unwrap_or(false) {
            let _ = COUNT.try_with(|count| count.set(count.get() + 1));
        }
    }

    pub struct Counting;

    // SAFETY: every method forwards the caller's arguments unchanged to
    // `System`; the const thread-local counters never allocate.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            note();
            // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: `pointer` and `layout` came from this allocator.
            unsafe { System.dealloc(pointer, layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            note();
            // SAFETY: the caller upholds the `GlobalAlloc::alloc_zeroed` contract.
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            note();
            // SAFETY: `pointer` and `layout` came from this allocator.
            unsafe { System.realloc(pointer, layout, size) }
        }
    }

    /// Resets this thread's count and starts counting.
    pub fn start() {
        COUNT.with(|count| count.set(0));
        ARMED.with(|armed| armed.set(true));
    }

    /// Stops counting and returns this thread's allocations since `start`.
    pub fn stop() -> usize {
        ARMED.with(|armed| armed.set(false));
        COUNT.with(Cell::get)
    }

    /// The counter sees an allocation made on this thread while armed.
    pub fn self_check() {
        start();
        let probe = std::hint::black_box(Vec::<u8>::with_capacity(1));
        let counted = stop();
        drop(probe);
        assert_eq!(counted, 1, "the counting allocator is live");
    }
}

#[global_allocator]
static GLOBAL: counting::Counting = counting::Counting;

#[test]
fn validated_candidate_builds_1024_static_authority_views_without_work() {
    const LAN: IfId = IfId(1);
    const WAN: IfId = IfId(2);
    const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);

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
        ResolutionStorageShape::new(1, 1, 1, 1),
        Icmpv4ErrorStorageShape::new(1, 1),
        Nat44UdpStoragePlan::new(1, 1, 1, 1, 1, 1, 1),
        Nat44TcpStoragePlan::new(1, 1, 1, 1, 1, 1, 1),
        1,
    );
    let plan = PublicationPlan::new(
        NonZeroU64::MIN,
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
        40_000,
        Nat44UdpPolicy::default(),
        Nat44UdpHashKey::new(1, 2).unwrap(),
    ))
    .with_nat44_tcp(Nat44TcpPublicationInput::new(
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44TcpPolicy::default(),
        Nat44TcpHashKey::new(3, 4).unwrap(),
    ))
    .with_firewall(FirewallPublicationInput::new(
        Vec::new().into_boxed_slice(),
        FirewallPolicy::default(),
        FirewallHashKey::new(5, 6).unwrap(),
    ))
    .with_resolution_hash_key(ruster_core::ResolutionHashKey::new(7, 8).unwrap());
    let candidate = ValidatedCandidate::new(plan).unwrap();

    assert_eq!(take_full_forwarding_validation_count(), 1);
    assert_eq!(take_full_firewall_validation_count(), 1);
    counting::self_check();
    counting::start();
    for _ in 0..1_024 {
        let authority = candidate.authority();
        assert_eq!(authority.generation(), NonZeroU64::MIN);
        assert_eq!(authority.nat44_udp_config().inside(), LAN);
        assert_eq!(authority.nat44_tcp_config().outside(), WAN);
        assert_eq!(authority.firewall_config().generation(), 1);
    }
    assert_eq!(counting::stop(), 0);
    assert_eq!(take_full_forwarding_validation_count(), 0);
    assert_eq!(take_full_firewall_validation_count(), 0);
}
