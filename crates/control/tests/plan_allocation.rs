mod common;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use common::{inputs, validated, Services};
use ruster_config::{parse, validate, ValidatedConfig, ValidationLimits, VersionedConfig};
use ruster_control::{
    plan_full_service_v1, plan_successor, PlanOutcome, PlanRestartRequired, SuccessorError,
};

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

fn assert_allocation_free(label: &str, run: impl FnOnce() -> PlanOutcome) -> PlanOutcome {
    reset_allocation_count();
    let outcome = run();
    assert_eq!(
        allocation_count(),
        0,
        "{label} plan_successor call must not allocate"
    );
    outcome
}

fn candidate(generation: u64, seed: u64) -> ruster_control::FullServiceCandidateV1 {
    let plan = match plan_full_service_v1(validated(Services::ALL), inputs(generation, seed)) {
        Ok(plan) => plan,
        Err(failure) => panic!("fixture must plan: {:?}", failure.error()),
    };
    plan.into_candidate().expect("fixture must validate")
}

fn parsed_fixture() -> VersionedConfig {
    parse(include_bytes!("full-service.toml")).expect("fixture must parse")
}

fn mutated_candidate(
    generation: u64,
    seed: u64,
    mutate: impl FnOnce(&mut VersionedConfig),
) -> ruster_control::FullServiceCandidateV1 {
    let mut config = parsed_fixture();
    mutate(&mut config);
    let config = match validate(
        config,
        ValidationLimits {
            max_slots_per_table: 1_048_576,
            max_runtime_bytes: 1 << 30,
        },
    )
    .expect("fixture must validate")
    {
        ValidatedConfig::V1(config) => config,
        _ => unreachable!("fixture selects schema V1"),
    };
    let plan = plan_full_service_v1(config, inputs(generation, seed))
        .unwrap_or_else(|failure| panic!("fixture must plan: {:?}", failure.error()));
    plan.into_candidate().expect("fixture must validate")
}

#[test]
fn plan_successor_all_outcome_classes_are_allocation_free() {
    let current = candidate(1, 0);
    let in_place_eligible = candidate(2, 100);
    let interface_restart = mutated_candidate(2, 100, |config| {
        let VersionedConfig::V1(config) = config else {
            unreachable!("fixture selects schema V1")
        };
        config.interfaces[0].mac = "02:00:00:00:00:09".to_owned();
    });
    let storage_restart = mutated_candidate(2, 100, |config| {
        let VersionedConfig::V1(config) = config else {
            unreachable!("fixture selects schema V1")
        };
        config
            .nat44
            .as_mut()
            .unwrap()
            .udp
            .as_mut()
            .unwrap()
            .capacity
            .mappings += 1;
    });
    let generation_rejected = candidate(1, 100);
    let hash_rejected = candidate(2, 0);
    let policy_restart = mutated_candidate(2, 100, |config| {
        let VersionedConfig::V1(config) = config else {
            unreachable!("fixture selects schema V1")
        };
        config.resolution.as_mut().unwrap().policy.interval_ms += 1;
    });

    let outcome = assert_allocation_free("initial", || plan_successor(None, &in_place_eligible));
    assert!(matches!(outcome, PlanOutcome::InitialActivation { .. }));

    let outcome = assert_allocation_free("in-place eligible", || {
        plan_successor(Some(&current), &in_place_eligible)
    });
    assert!(matches!(outcome, PlanOutcome::InPlaceEligible { .. }));

    let outcome = assert_allocation_free("interface restart", || {
        plan_successor(Some(&current), &interface_restart)
    });
    assert!(matches!(
        outcome,
        PlanOutcome::RestartRequired {
            reason: PlanRestartRequired::InterfaceBindingsChanged,
            ..
        }
    ));

    let outcome = assert_allocation_free("storage restart", || {
        plan_successor(Some(&current), &storage_restart)
    });
    assert!(matches!(
        outcome,
        PlanOutcome::RestartRequired {
            reason: PlanRestartRequired::RuntimeStorageShapeChanged,
            ..
        }
    ));

    let outcome = assert_allocation_free("generation rejection", || {
        plan_successor(Some(&current), &generation_rejected)
    });
    assert_eq!(
        outcome.rejection_error(),
        Some(SuccessorError::GenerationNotIncreasing)
    );
    assert!(outcome.section_diff().is_some());

    let outcome = assert_allocation_free("hash-key rejection", || {
        plan_successor(Some(&current), &hash_rejected)
    });
    assert_eq!(
        outcome.rejection_error(),
        Some(SuccessorError::Nat44UdpHashKeyReused)
    );
    assert!(outcome.section_diff().is_some());

    let outcome = assert_allocation_free("resolution policy restart", || {
        plan_successor(Some(&current), &policy_restart)
    });
    assert!(matches!(
        outcome,
        PlanOutcome::RestartRequired {
            reason: PlanRestartRequired::ResolutionPolicyChanged,
            ..
        }
    ));
    assert!(outcome
        .section_diff()
        .expect("restart diff is operator-visible")
        .resolution_policy_changed());
}

#[test]
fn policy_restart_and_successor_error_precedence_is_table_driven() {
    let current = candidate(1, 0);
    let resolution_only = mutated_candidate(2, 100, |config| {
        let VersionedConfig::V1(config) = config else {
            unreachable!("fixture selects schema V1")
        };
        config.resolution.as_mut().unwrap().policy.interval_ms += 1;
    });
    let icmp_only = mutated_candidate(2, 100, |config| {
        let VersionedConfig::V1(config) = config else {
            unreachable!("fixture selects schema V1")
        };
        config.icmpv4_errors.as_mut().unwrap().policy.interval_ms += 1;
    });
    let both_policies = mutated_candidate(2, 100, |config| {
        let VersionedConfig::V1(config) = config else {
            unreachable!("fixture selects schema V1")
        };
        config.resolution.as_mut().unwrap().policy.interval_ms += 1;
        config.icmpv4_errors.as_mut().unwrap().policy.interval_ms += 1;
    });
    let storage_and_policy = mutated_candidate(2, 100, |config| {
        let VersionedConfig::V1(config) = config else {
            unreachable!("fixture selects schema V1")
        };
        config.resolution.as_mut().unwrap().policy.interval_ms += 1;
        config
            .nat44
            .as_mut()
            .unwrap()
            .udp
            .as_mut()
            .unwrap()
            .capacity
            .mappings += 1;
    });

    for (label, next, expected, resolution_changed, icmp_changed, storage_changed) in [
        (
            "resolution policy only",
            resolution_only,
            PlanRestartRequired::ResolutionPolicyChanged,
            true,
            false,
            false,
        ),
        (
            "icmp policy only",
            icmp_only,
            PlanRestartRequired::Icmpv4ErrorPolicyChanged,
            false,
            true,
            false,
        ),
        (
            "both policies; resolution first",
            both_policies,
            PlanRestartRequired::ResolutionPolicyChanged,
            true,
            true,
            false,
        ),
        (
            "storage before policy",
            storage_and_policy,
            PlanRestartRequired::RuntimeStorageShapeChanged,
            true,
            false,
            true,
        ),
    ] {
        let outcome = assert_allocation_free(label, || plan_successor(Some(&current), &next));
        assert!(matches!(
            outcome,
            PlanOutcome::RestartRequired { reason, .. } if reason == expected
        ));
        let diff = outcome
            .section_diff()
            .expect("restart retains semantic diff");
        assert_eq!(
            diff.resolution_policy_changed(),
            resolution_changed,
            "{label}"
        );
        assert_eq!(diff.icmpv4_error_policy_changed(), icmp_changed, "{label}");
        assert_eq!(diff.storage_shape_changed(), storage_changed, "{label}");
        assert_eq!(
            outcome.previous_generation(),
            Some(current.generation()),
            "{label}"
        );
        assert_eq!(outcome.next_generation(), next.generation(), "{label}");
    }

    let key_reuse_and_policy = mutated_candidate(2, 0, |config| {
        let VersionedConfig::V1(config) = config else {
            unreachable!("fixture selects schema V1")
        };
        config.resolution.as_mut().unwrap().policy.interval_ms += 1;
    });
    let generation_failure_and_policy = mutated_candidate(1, 100, |config| {
        let VersionedConfig::V1(config) = config else {
            unreachable!("fixture selects schema V1")
        };
        config.resolution.as_mut().unwrap().policy.interval_ms += 1;
    });
    for (label, next, expected) in [
        (
            "key reuse before policy",
            key_reuse_and_policy,
            SuccessorError::Nat44UdpHashKeyReused,
        ),
        (
            "generation failure before policy",
            generation_failure_and_policy,
            SuccessorError::GenerationNotIncreasing,
        ),
    ] {
        let outcome = assert_allocation_free(label, || plan_successor(Some(&current), &next));
        assert_eq!(outcome.rejection_error(), Some(expected), "{label}");
        let diff = outcome
            .section_diff()
            .expect("rejection retains semantic diff");
        assert!(diff.resolution_policy_changed(), "{label}");
        assert_eq!(
            outcome.previous_generation(),
            Some(current.generation()),
            "{label}"
        );
        assert_eq!(outcome.next_generation(), next.generation(), "{label}");
    }

    let exhausted_current = candidate(u64::MAX, 10);
    let exhausted_next = mutated_candidate(u64::MAX, 100, |config| {
        let VersionedConfig::V1(config) = config else {
            unreachable!("fixture selects schema V1")
        };
        config.resolution.as_mut().unwrap().policy.interval_ms += 1;
    });
    let outcome = assert_allocation_free("generation exhaustion before policy", || {
        plan_successor(Some(&exhausted_current), &exhausted_next)
    });
    assert_eq!(
        outcome.rejection_error(),
        Some(SuccessorError::GenerationExhausted)
    );
    assert!(outcome
        .section_diff()
        .expect("rejection retains semantic diff")
        .resolution_policy_changed());
}
