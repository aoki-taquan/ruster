use std::alloc::System;

use ruster_bench::{r17_benchmark_spec_sha256, RunConfig, RunError, Suite};

#[global_allocator]
static CONSUMER_ALLOCATOR: System = System;

#[test]
fn identity_only_consumer_can_choose_its_own_global_allocator() {
    let digest = r17_benchmark_spec_sha256();
    assert_eq!(digest.as_bytes().len(), 32);
}

#[test]
fn runner_fails_closed_without_counting_allocator_instrumentation() {
    let mut config = RunConfig::smoke();
    config.suite = Suite::DeterministicSmoke;
    assert_eq!(
        ruster_bench::run(&config),
        Err(RunError::AllocationInstrumentationUnavailable)
    );
}
