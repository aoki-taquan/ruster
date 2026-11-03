//! OBS-017: the resolution tables' occupancy. Each count equals the
//! runtime's own counter (and a scan), the high-water marks keep the peak
//! through dequeues, cancels, and removals, a flushing commit restarts the
//! marks at zero, and a carrying commit restarts the learned neighbors' mark
//! at the carried count.

use super::*;

fn table(occupancy: TableOccupancy) -> (usize, usize, usize) {
    (
        occupancy.occupied(),
        occupancy.high_water(),
        occupancy.capacity(),
    )
}

fn assert_counts_match_a_scan(runtime: &ResolutionRuntime<'_>) {
    let occupancy = runtime.occupancy();
    assert_eq!(occupancy.states.occupied(), runtime.pending_states());
    assert_eq!(
        occupancy.states.occupied(),
        runtime
            .states
            .iter()
            .filter(|state| state_is_pending(state.entry))
            .count()
    );
    assert_eq!(occupancy.actions.occupied(), runtime.pending_actions());
    assert_eq!(
        occupancy.actions.occupied(),
        runtime
            .actions
            .iter()
            .filter(|slot| slot.queued.is_some())
            .count()
    );
    assert_eq!(
        occupancy.dynamic_neighbors.occupied(),
        runtime
            .dynamic_neighbors
            .iter()
            .filter(|slot| slot.entry.occupied)
            .count()
    );
    assert_eq!(
        occupancy.failure_holds.occupied(),
        runtime.pending_failure_holds()
    );
}

fn learn(runtime: &mut ResolutionRuntime<'_>, last: u8) {
    assert_eq!(
        runtime.merge_dynamic(
            WAN,
            target(last),
            MacAddress([2, 0, 0, 0, 1, last]),
            true,
            false,
            MonotonicMillis(10),
        ),
        ControlDisposition::Inserted
    );
}

#[test]
fn state_and_action_high_water_marks_keep_the_peak_until_a_commit() {
    let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 3];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut runtime = ResolutionRuntime::new(policy, &mut states, &mut actions);
    let empty = ResolutionOccupancy {
        states: TableOccupancy::new(0, 0, 3).unwrap(),
        actions: TableOccupancy::new(0, 0, 2).unwrap(),
        dynamic_neighbors: TableOccupancy::default(),
        failure_holds: TableOccupancy::default(),
    };
    assert_eq!(runtime.occupancy(), empty);
    for last in [5, 6] {
        assert_eq!(
            runtime.schedule(action(last), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
    }
    assert_counts_match_a_scan(&runtime);
    assert_eq!(table(runtime.occupancy().states), (2, 2, 3));
    assert_eq!(table(runtime.occupancy().actions), (2, 2, 2));
    // A full action queue refuses a third resolution without a count change.
    assert_ne!(
        runtime.schedule(action(7), MonotonicMillis(0), false),
        ResolutionResult::Queued
    );
    assert_eq!(table(runtime.occupancy().actions), (2, 2, 2));
    // Committing the queued requests empties the queue; the states wait.
    commit_front(&mut runtime, 0);
    commit_front(&mut runtime, 0);
    assert_counts_match_a_scan(&runtime);
    assert_eq!(table(runtime.occupancy().actions), (0, 2, 2));
    assert_eq!(table(runtime.occupancy().states).1, 2);
    // A dropped permit changes nothing; a commit flushes and restarts.
    drop(runtime.preflight_publication().unwrap());
    assert_eq!(table(runtime.occupancy().actions), (0, 2, 2));
    runtime.preflight_publication().unwrap().commit();
    assert_eq!(runtime.occupancy(), empty);
    assert_eq!(
        runtime.schedule(action(5), MonotonicMillis(10), false),
        ResolutionResult::Queued
    );
    assert_eq!(table(runtime.occupancy().states), (1, 1, 3));
    assert_eq!(table(runtime.occupancy().actions), (1, 1, 2));
    assert_counts_match_a_scan(&runtime);
}

#[test]
fn learned_neighbor_high_water_restarts_at_a_flush_or_the_carried_count() {
    let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 4];
    let mut runtime =
        ResolutionRuntime::with_dynamic_neighbors(policy, &mut states, &mut actions, &mut dynamic);
    for last in [7, 8, 9] {
        learn(&mut runtime, last);
    }
    assert_counts_match_a_scan(&runtime);
    assert_eq!(table(runtime.occupancy().dynamic_neighbors), (3, 3, 4));
    // A carrying commit over the same snapshot keeps all three.
    let tables = carry::Tables::new(SOURCE_IP, Vec::new());
    let snapshot = tables.snapshot();
    runtime
        .preflight_publication()
        .unwrap()
        .commit_carrying(&snapshot, &snapshot);
    assert_eq!(table(runtime.occupancy().dynamic_neighbors), (3, 3, 4));
    // A renumbered WAN drops them: the mark restarts at the carried zero.
    let renumbered = carry::Tables::new(target(3), Vec::new());
    runtime
        .preflight_publication()
        .unwrap()
        .commit_carrying(&snapshot, &renumbered.snapshot());
    assert_eq!(table(runtime.occupancy().dynamic_neighbors), (0, 0, 4));
    learn(&mut runtime, 7);
    learn(&mut runtime, 8);
    assert_eq!(table(runtime.occupancy().dynamic_neighbors), (2, 2, 4));
    runtime.preflight_publication().unwrap().commit();
    assert_eq!(table(runtime.occupancy().dynamic_neighbors), (0, 0, 4));
    assert_counts_match_a_scan(&runtime);
}

#[test]
fn failure_hold_high_water_keeps_the_peak_until_a_commit() {
    let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 2];
    let mut actions = [ResolutionActionSlot::EMPTY; 2];
    let mut holds = [ResolutionFailureHoldSlot::EMPTY; 2];
    let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        policy,
        &mut states,
        &mut actions,
        &mut [],
        &mut holds,
    );
    let mut quote = [0_u8; 68];
    quote[0] = 0x4f;
    // One hold per resolution: capture behind two of them.
    for last in [5, 6] {
        assert_eq!(
            runtime.schedule(action(last), MonotonicMillis(0), false),
            ResolutionResult::Queued
        );
        assert!(matches!(
            runtime.capture_failure_candidate(
                WAN,
                target(last),
                Ipv4Address::from_octets([198, 51, 100, 10]),
                target(last),
                SOURCE_MAC,
                SOURCE_IP,
                Ipv4Address::from_octets([192, 0, 2, 0]),
                24,
                0,
                &quote,
            ),
            ResolutionFailureCapture::Captured(_)
        ));
    }
    assert_counts_match_a_scan(&runtime);
    assert_eq!(table(runtime.occupancy().failure_holds), (2, 2, 2));
    // Clearing a resolution cancels its hold; the mark stays.
    runtime.clear_resolution(WAN, target(5));
    assert_counts_match_a_scan(&runtime);
    assert_eq!(table(runtime.occupancy().failure_holds), (1, 2, 2));
    runtime.preflight_publication().unwrap().commit();
    assert_eq!(table(runtime.occupancy().failure_holds), (0, 0, 2));
}
