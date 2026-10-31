//! Deterministic driver and M1 golden fixture tests.
//!
//! Regenerate the golden output after an intentional change with
//!
//! ```text
//! RUSTER_UPDATE_GOLDEN=1 cargo test -p ruster-sim-scenario --test driver
//! ```
//!
//! and review the diff. The variable is refused when `CI` is set, so CI
//! always compares.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ruster_config::ValidationCode;
use ruster_core::DropReason;
use ruster_sim_scenario::{
    parse_scenario, run_scenario_file, ApplyClass, ApplyOutcome, ConfigRejection, DriverError,
    ExpectMismatch, FileRole, Progress, RejectReason, SimSession, RUN_SIM_SCHEMA_V1,
};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/m1")
}

fn scenario_text() -> String {
    fs::read_to_string(fixtures().join("scenario.toml")).expect("golden scenario")
}

fn run_file(path: &Path) -> (Result<ruster_sim_scenario::RunSummary, DriverError>, String) {
    let mut out = Vec::new();
    let result = run_scenario_file(path, &mut out);
    (result, String::from_utf8(out).expect("UTF-8 output"))
}

/// Runs scenario text with config paths resolved in the fixture directory.
fn run_text(source: &str) -> (Result<(), DriverError>, String) {
    let mut out = Vec::new();
    let result = (|| {
        let scenario =
            parse_scenario(source.as_bytes(), &fixtures()).map_err(DriverError::Scenario)?;
        let mut session = SimSession::new(scenario)?;
        let mut run = session.start(&mut out)?;
        run.run(&mut out)?;
        run.finish(&mut out).map(|_| ())
    })();
    (result, String::from_utf8(out).expect("UTF-8 output"))
}

fn replace_once(source: &str, from: &str, to: &str) -> String {
    assert_eq!(source.matches(from).count(), 1, "fixture anchor {from:?}");
    source.replacen(from, to, 1)
}

#[test]
fn m1_golden_scenario_passes_and_matches_golden_output() {
    let (result, output) = run_file(&fixtures().join("scenario.toml"));
    let summary = result.expect("every expect step passes");
    assert_eq!(summary.generation.get(), 5);
    assert_eq!(summary.snapshot.totals.publications_applied, 2);
    assert_eq!(summary.snapshot.totals.publications_rejected, 2);
    assert_eq!(summary.snapshot.totals.apply_flushes_recorded, 2);
    assert_eq!(summary.snapshot.drops.count(DropReason::Ipv4TtlExpired), 1);

    let golden = fixtures().join("expected.jsonl");
    if std::env::var_os("RUSTER_UPDATE_GOLDEN").is_some_and(|value| value == "1") {
        assert!(
            std::env::var_os("CI").is_none(),
            "RUSTER_UPDATE_GOLDEN must not be used in CI"
        );
        fs::write(&golden, &output).expect("write golden");
    }
    let expected = fs::read_to_string(&golden).expect("golden output");
    assert!(
        output == expected,
        "run-sim output differs from {}; regenerate with RUSTER_UPDATE_GOLDEN=1 after review",
        golden.display()
    );
}

#[test]
fn run_sim_output_is_byte_identical_across_runs_and_canonical() {
    let path = fixtures().join("scenario.toml");
    let (first, a) = run_file(&path);
    let (second, b) = run_file(&path);
    first.unwrap();
    second.unwrap();
    assert_eq!(a, b);

    let lines: Vec<&str> = a.lines().collect();
    assert!(lines[0].starts_with(&format!(
        "{{\"event\":\"start\",\"schema\":\"{RUN_SIM_SCHEMA_V1}\",\"backend\":\"sim\""
    )));
    assert!(lines.last().unwrap().starts_with("{\"event\":\"final\""));
    for line in &lines {
        assert!(line.starts_with("{\"event\":\"") && line.ends_with('}'));
    }
    // Every apply reports its flush counts or an explicit null.
    let applies: Vec<&&str> = lines
        .iter()
        .filter(|l| l.contains("\"event\":\"apply\""))
        .collect();
    assert_eq!(applies.len(), 5);
    assert!(
        applies[0].contains("\"outcome\":\"applied\"")
            && applies[0].contains("\"flush\":{\"resolution_states\":2")
    );
    assert!(applies[1].contains("\"reason\":\"invalid\"") && applies[1].contains("\"flush\":null"));
    assert!(applies[2].contains("\"code\":\"storage_shape\""));
    assert!(applies[3].contains("\"code\":\"interfaces\""));
    // R15: counters, health, and generation are in the final event.
    let last = lines.last().unwrap();
    for field in [
        "\"generation\":5",
        "\"observer.state\":\"healthy\"",
        "\"observer.generation\":5",
        "\"health.last_successful_tick\":4030",
        "\"drop.FIREWALL_RULE_DENIED\":1",
        "\"consume.ARP_CONTROL\":2",
        "\"nat44_tcp.inbound_translated\":1",
        "\"backend.sim.pending_tx\":0",
    ] {
        assert!(last.contains(field), "final event lacks {field}");
    }
}

#[test]
fn run_sim_output_never_contains_the_seed() {
    let (result, output) = run_file(&fixtures().join("scenario.toml"));
    result.unwrap();
    let seed: u64 = 20_261_101;
    assert!(scenario_text().contains(&format!("seed = {seed}")));
    for form in [format!("{seed}"), format!("{seed:x}"), format!("{seed:X}")] {
        assert!(!output.contains(&form), "output leaks the seed");
    }
    assert!(!output.contains("seed"));
    assert!(!output.to_ascii_lowercase().contains("key"));
}

#[test]
fn wrong_expectations_fail_with_typed_mismatches() {
    let source = scenario_text();

    // A wrong NAT port in the first translated UDP frame.
    let wrong_port = replace_once(
        &source,
        "src-port = 40011, dst-port = 53",
        "src-port = 40012, dst-port = 53",
    );
    let (result, output) = run_text(&wrong_port);
    match result {
        Err(DriverError::Expect {
            step: 6,
            mismatch:
                ExpectMismatch::Tx {
                    index: 0,
                    expected_count: 1,
                    actual_count: 1,
                    expected: Some(expected),
                    actual: Some(actual),
                },
        }) => {
            assert_eq!(expected.interface, actual.interface);
            assert_ne!(expected.bytes, actual.bytes);
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(output
        .lines()
        .last()
        .unwrap()
        .contains("\"result\":\"fail\",\"mismatch\":\"tx\""));
    assert!(!output.contains("\"event\":\"final\""));

    // A missing TX frame is reported at the first absent index.
    let missing = replace_once(
        &source,
        "generation = 2\ntx = []",
        "generation = 2\ntx = [{ interface = \"lan\", frame = { kind = \"raw\", hex = \"00\" } }]",
    );
    let (result, _) = run_text(&missing);
    assert!(matches!(
        result,
        Err(DriverError::Expect {
            mismatch: ExpectMismatch::Tx {
                index: 0,
                expected_count: 1,
                actual_count: 0,
                actual: None,
                ..
            },
            ..
        })
    ));

    let wrong_drop = replace_once(
        &source,
        "drops = [{ reason = \"NEIGHBOR_UNRESOLVED\", count = 1 }]",
        "drops = [{ reason = \"NEIGHBOR_UNRESOLVED\", count = 2 }]",
    );
    let (result, _) = run_text(&wrong_drop);
    assert_eq!(
        result,
        Err(DriverError::Expect {
            step: 2,
            mismatch: ExpectMismatch::Drop {
                reason: DropReason::NeighborUnresolved,
                expected: 2,
                actual: 1,
            },
        })
    );

    let wrong_generation = replace_once(&source, "generation = 5", "generation = 4");
    let (result, _) = run_text(&wrong_generation);
    assert!(matches!(
        result,
        Err(DriverError::Expect {
            mismatch: ExpectMismatch::Generation { .. },
            ..
        })
    ));

    // An apply whose observed class differs from the expectation.
    let wrong_apply = replace_once(
        &source,
        "config = \"router-capacity.toml\"\noutcome = \"rejected\"\nreason = \"restart-required\"",
        "config = \"router-capacity.toml\"\noutcome = \"rejected\"\nreason = \"invalid\"",
    );
    let (result, _) = run_text(&wrong_apply);
    assert_eq!(
        result,
        Err(DriverError::ApplyMismatch {
            step: 38,
            expected: ApplyOutcome::Rejected {
                reason: Some(RejectReason::Invalid)
            },
            observed: ApplyClass::RestartRequired,
        })
    );
    let applied_invalid = replace_once(
        &source,
        "config = \"router-invalid.toml\"\noutcome = \"rejected\"\nreason = \"invalid\"",
        "config = \"router-invalid.toml\"\noutcome = \"applied\"",
    );
    let (result, _) = run_text(&applied_invalid);
    assert!(matches!(
        result,
        Err(DriverError::ApplyMismatch {
            observed: ApplyClass::Invalid,
            ..
        })
    ));
}

#[test]
fn invalid_paths_and_inputs_fail_typed() {
    let (result, output) = run_file(&fixtures().join("does-not-exist.toml"));
    assert_eq!(
        result.unwrap_err(),
        DriverError::Read {
            file: FileRole::Scenario,
            step: None,
            kind: io::ErrorKind::NotFound,
        }
    );
    assert!(output.is_empty());

    let source = scenario_text();
    let missing_initial = replace_once(
        &source,
        "config = \"router-v1.toml\"\n\n#",
        "config = \"absent.toml\"\n\n#",
    );
    assert_eq!(
        run_text(&missing_initial).0,
        Err(DriverError::Read {
            file: FileRole::Config,
            step: None,
            kind: io::ErrorKind::NotFound,
        })
    );

    let invalid_initial = replace_once(
        &source,
        "config = \"router-v1.toml\"\n\n#",
        "config = \"router-invalid.toml\"\n\n#",
    );
    match run_text(&invalid_initial).0 {
        Err(DriverError::InitialConfig(ConfigRejection::Validate(error))) => {
            assert_eq!(error.code(), ValidationCode::GatewayNotOnLink);
        }
        other => panic!("unexpected {other:?}"),
    }

    let missing_apply = replace_once(
        &source,
        "config = \"router-v2.toml\"",
        "config = \"v9.toml\"",
    );
    let (result, output) = run_text(&missing_apply);
    assert_eq!(
        result,
        Err(DriverError::Read {
            file: FileRole::Config,
            step: Some(28),
            kind: io::ErrorKind::NotFound,
        })
    );
    assert!(!output.contains("v9.toml"));

    let unknown_interface = replace_once(
        &source,
        "interface = \"lan\"\nframe = { kind = \"udp\", eth = { src = \"02:00:00:00:00:10\", dst = \"02:00:00:00:00:01\" }, ip = { src = \"192.168.1.10\", dst = \"198.51.100.20\", id = 1 }",
        "interface = \"dmz\"\nframe = { kind = \"udp\", eth = { src = \"02:00:00:00:00:10\", dst = \"02:00:00:00:00:01\" }, ip = { src = \"192.168.1.10\", dst = \"198.51.100.20\", id = 1 }",
    );
    assert_eq!(
        run_text(&unknown_interface).0,
        Err(DriverError::UnknownInterface {
            step: 0,
            name: "dmz".to_owned(),
        })
    );

    let escaping = replace_once(
        &source,
        "config = \"router-v2.toml\"",
        "config = \"../m1/router-v2.toml\"",
    );
    assert!(matches!(
        run_text(&escaping).0,
        Err(DriverError::Scenario(_))
    ));
}

#[test]
fn step_api_yields_between_ticks_and_stops_at_hold() {
    let source = r#"
schema = "ruster-scenario/v1"
seed = 3
config = "router-v1.toml"

[[step]]
kind = "tick"
advance-ms = 5
ticks = 3

[[step]]
kind = "expect"
generation = 1
tx = []

[[step]]
kind = "hold"
"#;
    let scenario = parse_scenario(source.as_bytes(), &fixtures()).unwrap();
    let mut session = SimSession::new(scenario).unwrap();
    assert!(session.scenario().holds());
    let mut out = Vec::new();
    let mut run = session.start(&mut out).unwrap();
    let mut progress = Vec::new();
    loop {
        let step = run.step(&mut out).unwrap();
        progress.push(step);
        if step != Progress::Running {
            break;
        }
    }
    // Three single ticks, the expect, then the hold marker.
    assert_eq!(
        progress,
        [
            Progress::Running,
            Progress::Running,
            Progress::Running,
            Progress::Running,
            Progress::Hold
        ]
    );
    assert_eq!(run.step(&mut out).unwrap(), Progress::Finished);
    assert_eq!(run.now_ms(), 5);
    assert_eq!(run.snapshot().totals.ticks, 3);
    let summary = run.finish(&mut out).unwrap();
    assert_eq!(summary.generation.get(), 1);
    let text = String::from_utf8(out).unwrap();
    assert_eq!(text.matches("\"event\":\"tick\"").count(), 3);
    assert_eq!(text.lines().count(), 6);
}
