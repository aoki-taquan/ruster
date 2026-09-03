// Keep the existing publication fixture and assertions as the single source
// of truth, but place its items inside a const block. Rust does not register
// `#[test]` inner items in the test harness, so this adapter can call only the
// fixed R16 matrix without registering a second set of runnable tests in the
// binary.
#[allow(dead_code, unused_imports, unnameable_test_items)]
const R16_PUBLICATION_CASE_RUNNER: fn(bool) = {
    #[allow(dead_code, unused_imports, unnameable_test_items)]
    mod included {
        include!("publication_tick.rs");

        const MAX_PUBLICATION_CASES: usize = 8;
        const SHORT_PUBLICATION_CASES: usize = 4;

        pub fn run(full: bool) {
            let cases: [(&str, fn()); MAX_PUBLICATION_CASES] = [
                (
                    "same-shape-successor-and-same-tick-authority",
                    run_tick_applies_same_interface_same_shape_successor_and_uses_new_authority_same_tick,
                ),
                (
                    "invalid-successor-candidate-preservation",
                    run_tick_invalid_successor_keeps_exact_candidate_old_budget_and_live_state,
                ),
                (
                    "restart-required-candidate-preservation",
                    run_tick_restart_required_table_keeps_exact_candidate_old_budget_and_live_state,
                ),
                (
                    "rx-defer-quiescence-ordering",
                    run_tick_skip_io_defer_preserves_exact_candidate_and_skips_data_phases,
                ),
                (
                    "rollback-and-generation-regression",
                    run_tick_rollback_to_prior_generation_source_restores_behavior_and_rejects_regression,
                ),
                (
                    "foreign-guard-candidate-preservation",
                    direct_safe_gate_rejects_foreign_guard_with_exact_candidate_and_unchanged_active_state,
                ),
                (
                    "foreign-backend-queue-preservation",
                    run_tick_foreign_backend_some_and_none_preserve_queues_and_skip_data_phases,
                ),
                (
                    "tx-defer-and-candidate-last-retry",
                    run_tick_continue_old_io_defer_uses_old_budget_then_retries_same_candidate_applied,
                ),
            ];
            let case_count = if full {
                cases.len()
            } else {
                SHORT_PUBLICATION_CASES
            };
            assert!(
                case_count <= MAX_PUBLICATION_CASES,
                "publication case count exceeds fixed upper bound"
            );
            for (case_index, &(name, case)) in cases.iter().take(case_count).enumerate() {
                assert!(
                    case_index < MAX_PUBLICATION_CASES,
                    "publication case index exceeds fixed upper bound"
                );
                case_name_guard(name, case_index);
                case();
            }
        }

        fn case_name_guard(name: &str, case_index: usize) {
            assert!(
                !name.is_empty(),
                "publication case {case_index} has no name"
            );
        }
    }

    included::run
};

#[test]
fn r16_publication_property_contract_smoke() {
    R16_PUBLICATION_CASE_RUNNER(false);
}

#[test]
#[ignore = "fixed publication property smoke; invoke explicitly with the documented exact command"]
fn r16_publication_property_smoke() {
    R16_PUBLICATION_CASE_RUNNER(true);
}
