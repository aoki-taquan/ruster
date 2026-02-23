//! E2E startup tests for ruster.
//!
//! These tests verify the full init pipeline:
//! config load -> control validate/apply -> dataplane init.

use std::path::PathBuf;

/// Path to the example config at the project root.
fn example_config_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates
    path.pop(); // project root
    path.push("router.toml.example");
    path
}

/// Helper: read the example toml as a string.
fn example_toml_str() -> String {
    std::fs::read_to_string(example_config_path())
        .unwrap_or_else(|e| panic!("failed to read example config: {e}"))
}

// ── Config loading tests ──────────────────────────────────────────────

#[test]
fn load_valid_config_succeeds() {
    let path = example_config_path();
    let config = ruster_config::load_from_file(path.to_str().unwrap());
    assert!(config.is_ok(), "loading example config should succeed");
}

#[test]
fn load_nonexistent_config_fails() {
    let result = ruster_config::load_from_file("/tmp/ruster-nonexistent-config-42.toml");
    assert!(result.is_err(), "loading nonexistent config should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("read config file") || err.contains("No such file"),
        "error should mention file read failure: {err}"
    );
}

#[test]
fn load_invalid_toml_content_fails() {
    let tmp_path = "/tmp/ruster-test-invalid.toml";
    std::fs::write(tmp_path, "this is not valid toml {{{{").unwrap();
    let result = ruster_config::load_from_file(tmp_path);
    assert!(result.is_err(), "loading invalid toml should fail");
    let _ = std::fs::remove_file(tmp_path);
}

// ── Control plane tests ───────────────────────────────────────────────

#[test]
fn control_validate_and_apply_succeeds() {
    let config =
        ruster_config::load_from_str(&example_toml_str()).expect("example config should be valid");

    // Validate
    ruster_control::validate(&config).expect("validation should succeed");

    // Apply via store
    let mut store = ruster_control::ConfigStore::new();
    let plan = store
        .apply(config.clone())
        .expect("apply should succeed for valid config");
    assert!(plan.has_changes, "initial apply should have changes");

    store.commit().expect("commit should succeed");
    assert!(
        !store.has_pending_changes(),
        "no pending changes after commit"
    );
}

// ── Dataplane init tests ──────────────────────────────────────────────

#[test]
fn dataplane_init_creates_all_engines() {
    let config =
        ruster_config::load_from_str(&example_toml_str()).expect("example config should be valid");

    let dp = ruster_dataplane::Dataplane::init(&config).expect("dataplane init should succeed");

    // Verify engines are created from config values.
    // The example config has NAT enabled.
    assert!(dp.nat.is_enabled(), "NAT should be enabled per config");

    // L3 engine should have the static routes loaded.
    assert_eq!(
        dp.l3.route_table().len(),
        config.routing.ipv4_static_routes.len(),
        "route table should have all static routes"
    );

    // Conntrack should start with zero sessions.
    assert_eq!(
        dp.conntrack.session_count(),
        0,
        "conntrack should start empty"
    );
}

#[test]
fn dataplane_init_returns_result_type() {
    // This test primarily verifies the API contract: init returns Result.
    let config =
        ruster_config::load_from_str(&example_toml_str()).expect("example config should be valid");

    let result: Result<ruster_dataplane::Dataplane, ruster_dataplane::DataplaneError> =
        ruster_dataplane::Dataplane::init(&config);
    assert!(result.is_ok());
}

// ── Full pipeline E2E ─────────────────────────────────────────────────

#[test]
fn full_startup_pipeline_succeeds() {
    // Simulate the full main() flow without process::exit.
    let config_path = example_config_path();
    let config = ruster_config::load_from_file(config_path.to_str().unwrap())
        .expect("config load should succeed");

    ruster_control::validate(&config).expect("validation should succeed");

    let mut store = ruster_control::ConfigStore::new();
    store.apply(config.clone()).expect("apply should succeed");
    store.commit().expect("commit should succeed");

    let dp = ruster_dataplane::Dataplane::init(&config).expect("dataplane init should succeed");

    // Verify the dataplane is properly initialized.
    assert!(dp.nat.is_enabled());
    assert_eq!(dp.conntrack.session_count(), 0);
}

// ── Run loop tests ──────────────────────────────────────────────────

#[test]
fn dataplane_run_exits_on_shutdown_signal() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let config =
        ruster_config::load_from_str(&example_toml_str()).expect("example config should be valid");
    let dp = ruster_dataplane::Dataplane::init(&config).expect("dataplane init should succeed");

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_trigger = Arc::clone(&shutdown);

    // Signal shutdown after a short delay.
    let handle = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        shutdown_trigger.store(true, Ordering::Relaxed);
    });

    let result = dp.run(shutdown);
    assert!(result.is_ok(), "run should return Ok on clean shutdown");

    handle.join().expect("trigger thread should join cleanly");
}

#[test]
fn dataplane_run_immediate_shutdown() {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Duration;

    let config =
        ruster_config::load_from_str(&example_toml_str()).expect("example config should be valid");
    let dp = ruster_dataplane::Dataplane::init(&config).expect("dataplane init should succeed");

    // Pre-set shutdown before calling run.
    let shutdown = Arc::new(AtomicBool::new(true));

    let start = std::time::Instant::now();
    let result = dp.run(shutdown);
    let elapsed = start.elapsed();

    assert!(result.is_ok(), "run should return Ok");
    assert!(
        elapsed < Duration::from_millis(50),
        "run should return immediately when shutdown is pre-set, took {:?}",
        elapsed
    );
}

#[test]
fn full_startup_run_shutdown_pipeline() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    // Full E2E: config load -> control -> dataplane init -> run -> shutdown
    let config_path = example_config_path();
    let config = ruster_config::load_from_file(config_path.to_str().unwrap())
        .expect("config load should succeed");

    ruster_control::validate(&config).expect("validation should succeed");

    let mut store = ruster_control::ConfigStore::new();
    store.apply(config.clone()).expect("apply should succeed");
    store.commit().expect("commit should succeed");

    let dp = ruster_dataplane::Dataplane::init(&config).expect("dataplane init should succeed");

    // Verify engines.
    assert!(dp.nat.is_enabled());
    assert_eq!(dp.conntrack.session_count(), 0);

    // Run and shutdown.
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_trigger = Arc::clone(&shutdown);

    let handle = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        shutdown_trigger.store(true, Ordering::Relaxed);
    });

    let result = dp.run(shutdown);
    assert!(result.is_ok(), "full pipeline run should succeed");

    handle.join().expect("trigger thread should join");
}
