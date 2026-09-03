mod common;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use common::{inputs, validated, Services};
use ruster_control::{plan_full_service_v1, FullServicePlanningError, RuntimeService};

struct CountingAllocator;

thread_local! {
    static ALLOCATION_COUNT: Cell<u64> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout`はallocator contractから渡されます。
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            increment_count();
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer`と`layout`はこのallocatorから取得されています。
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout`はallocator contractから渡されます。
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            increment_count();
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: `pointer`と`layout`はこのallocatorから取得されています。
        let new_pointer = unsafe { System.realloc(pointer, layout, size) };
        if !new_pointer.is_null() {
            increment_count();
        }
        new_pointer
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn increment_count() {
    ALLOCATION_COUNT.with(|count| count.set(count.get().saturating_add(1)));
}

fn reset_allocation_count() {
    ALLOCATION_COUNT.with(|count| count.set(0));
}

fn allocation_count() -> u64 {
    ALLOCATION_COUNT.with(Cell::get)
}

#[test]
fn full_service_planning_success_and_missing_failures_are_allocation_free() {
    let config = validated(Services::ALL);
    let plan_inputs = inputs(1, 10);
    reset_allocation_count();
    let plan = match plan_full_service_v1(config, plan_inputs) {
        Ok(plan) => plan,
        Err(failure) => panic!("full fixture must plan: {:?}", failure.error()),
    };
    assert_eq!(allocation_count(), 0);
    drop(plan);

    let cases = [
        (
            Services {
                resolution: false,
                icmpv4_errors: false,
                nat44_udp: false,
                nat44_tcp: false,
                firewall: false,
            },
            RuntimeService::Resolution,
        ),
        (
            Services {
                resolution: true,
                icmpv4_errors: false,
                nat44_udp: false,
                nat44_tcp: false,
                firewall: false,
            },
            RuntimeService::Icmpv4Errors,
        ),
        (
            Services {
                resolution: true,
                icmpv4_errors: true,
                nat44_udp: false,
                nat44_tcp: false,
                firewall: false,
            },
            RuntimeService::Nat44Udp,
        ),
        (
            Services {
                resolution: true,
                icmpv4_errors: true,
                nat44_udp: true,
                nat44_tcp: false,
                firewall: false,
            },
            RuntimeService::Nat44Tcp,
        ),
        (
            Services {
                firewall: false,
                ..Services::ALL
            },
            RuntimeService::Firewall,
        ),
    ];

    for (index, (services, service)) in cases.into_iter().enumerate() {
        let config = validated(services);
        let plan_inputs = inputs(1, 100 + index as u64 * 10);
        reset_allocation_count();
        let failure = match plan_full_service_v1(config, plan_inputs) {
            Ok(_) => panic!("missing service must reject planning"),
            Err(failure) => failure,
        };
        let (error, config, inputs) = failure.into_parts();
        assert_eq!(allocation_count(), 0);
        assert_eq!(error, FullServicePlanningError::MissingService(service));
        drop((config, inputs));
    }
}
