use ruster_bench::{
    deterministic_smoke, r17_benchmark_spec_sha256, validate_deterministic_smoke_artifact,
    CountingAllocator, RunConfig, Suite, R17_BENCHMARK_SPEC_SHA256_HEX,
    R17_DETERMINISTIC_SMOKE_CASE_COUNT, R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS,
    R17_DETERMINISTIC_SMOKE_SEED, R17_DETERMINISTIC_SMOKE_WORKLOAD_FINGERPRINT,
};

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn public_compiled_identity_has_stable_lowercase_content_form() {
    assert_eq!(
        r17_benchmark_spec_sha256().to_lower_hex(),
        R17_BENCHMARK_SPEC_SHA256_HEX
    );
    assert_eq!(R17_BENCHMARK_SPEC_SHA256_HEX.len(), 64);
    assert!(R17_BENCHMARK_SPEC_SHA256_HEX
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    assert_eq!(
        R17_DETERMINISTIC_SMOKE_WORKLOAD_FINGERPRINT,
        0x6920_d887_2e7e_5c38
    );
}

#[test]
fn public_runner_dispatches_deterministic_suite_without_timed_path() {
    let mut config = RunConfig::smoke();
    config.suite = Suite::DeterministicSmoke;
    config.samples = 0;
    config.sample_time = std::time::Duration::ZERO;
    config.warmup_time = std::time::Duration::ZERO;
    config.batches = vec![0];

    let rows = ruster_bench::run(&config).unwrap();
    assert_eq!(rows.len(), R17_DETERMINISTIC_SMOKE_CASE_COUNT);
    assert!(rows.iter().all(|row| row.timed_allocations == 0));
}

#[test]
fn public_artifact_validator_rejects_identity_and_case_drift() {
    let artifact = deterministic_smoke(
        R17_DETERMINISTIC_SMOKE_SEED,
        R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS,
    )
    .unwrap();
    assert_eq!(
        artifact.lines().count(),
        R17_DETERMINISTIC_SMOKE_CASE_COUNT + 1
    );
    validate_deterministic_smoke_artifact(&artifact).unwrap();

    let lines = artifact.split_terminator('\n').collect::<Vec<_>>();
    assert_eq!(
        json_keys(lines[0]),
        ruster_bench::R17_DETERMINISTIC_SMOKE_HEADER_FIELDS.to_vec()
    );
    assert_eq!(
        json_keys(lines[1]),
        ruster_bench::R17_DETERMINISTIC_SMOKE_CASE_FIELDS.to_vec()
    );

    let wrong_identity = artifact.replace(
        R17_BENCHMARK_SPEC_SHA256_HEX,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert!(validate_deterministic_smoke_artifact(&wrong_identity).is_err());

    let mut lines = artifact.split_terminator('\n').collect::<Vec<_>>();
    lines.swap(1, 2);
    let reordered = format!("{}\n", lines.join("\n"));
    assert!(validate_deterministic_smoke_artifact(&reordered).is_err());

    let mut lines = artifact.split_terminator('\n').collect::<Vec<_>>();
    let first_case = lines[1];
    lines[2] = first_case;
    let duplicated = format!("{}\n", lines.join("\n"));
    assert!(validate_deterministic_smoke_artifact(&duplicated).is_err());

    let unknown_hardware_field = artifact.replace(
        "\"counter_allocations\":0,",
        "\"counter_allocations\":0,\"cycles_per_packet\":0,",
    );
    assert!(validate_deterministic_smoke_artifact(&unknown_hardware_field).is_err());

    let unknown_privacy_field = artifact.replace(
        "\"counter_allocations\":0,",
        "\"counter_allocations\":0,\"hostname\":\"runner\",",
    );
    assert!(validate_deterministic_smoke_artifact(&unknown_privacy_field).is_err());

    for (field, replacement) in [
        (
            "\"artifact_schema\":\"ruster.benchmark-smoke/v1\"",
            "\"artifact_schema\":\"ruster.benchmark-smoke/other\"",
        ),
        ("\"case_count\":24", "\"case_count\":23"),
        ("\"kind\":\"deterministic-smoke\"", "\"kind\":\"other\""),
    ] {
        let mutated = artifact.replacen(field, replacement, 1);
        assert!(
            validate_deterministic_smoke_artifact(&mutated).is_err(),
            "header mutation should be rejected: {field}"
        );
    }

    let mut case_schema_lines = artifact.split_terminator('\n').collect::<Vec<_>>();
    let case_schema = case_schema_lines[1].replace(
        "\"artifact_schema\":\"ruster.benchmark-smoke/v1\"",
        "\"artifact_schema\":\"ruster.benchmark-smoke/other\"",
    );
    case_schema_lines[1] = &case_schema;
    let case_schema_mutation = format!("{}\n", case_schema_lines.join("\n"));
    assert!(validate_deterministic_smoke_artifact(&case_schema_mutation).is_err());

    for (field, replacement) in [
        ("\"counter_allocations\":0", "\"counter_allocations\":1"),
        ("\"counter_consumed\":0", "\"counter_consumed\":1"),
        ("\"counter_dropped\":0", "\"counter_dropped\":1"),
        ("\"counter_received\":1", "\"counter_received\":0"),
        ("\"counter_recycled\":0", "\"counter_recycled\":1"),
        ("\"counter_tx_accepted\":1", "\"counter_tx_accepted\":0"),
        ("\"counter_tx_rejected\":0", "\"counter_tx_rejected\":1"),
        ("\"counter_tx_requested\":1", "\"counter_tx_requested\":0"),
        (
            "\"completion\":\"transmitted\"",
            "\"completion\":\"rejected\"",
        ),
        ("\"egress\":\"wan\"", "\"egress\":\"lan\""),
        ("\"frame\":\"wire64\"", "\"frame\":\"ip-mtu1500\""),
        (
            "\"oracle\":\"forwarded-wire-exact\"",
            "\"oracle\":\"not-forwarded\"",
        ),
        ("\"checksum_passes\":0", "\"checksum_passes\":1"),
        ("\"logical_time_ms\":1000", "\"logical_time_ms\":1001"),
        (
            &format!("\"seed\":{R17_DETERMINISTIC_SMOKE_SEED}"),
            "\"seed\":7",
        ),
        (
            &format!("\"spec_sha256\":\"{R17_BENCHMARK_SPEC_SHA256_HEX}\""),
            "\"spec_sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\"",
        ),
        (
            &format!(
                "\"workload_fingerprint\":\"{R17_DETERMINISTIC_SMOKE_WORKLOAD_FINGERPRINT:016x}\""
            ),
            "\"workload_fingerprint\":\"0000000000000000\"",
        ),
        ("\"ordinal\":0", "\"ordinal\":1"),
    ] {
        let mutated = artifact.replacen(field, replacement, 1);
        assert!(
            validate_deterministic_smoke_artifact(&mutated).is_err(),
            "mutation should be rejected: {field}"
        );
    }

    let inbound_egress = artifact.replacen("\"egress\":\"lan\"", "\"egress\":\"wan\"", 1);
    assert!(validate_deterministic_smoke_artifact(&inbound_egress).is_err());
}

#[test]
fn public_deterministic_replay_is_byte_identical() {
    let first = deterministic_smoke(
        R17_DETERMINISTIC_SMOKE_SEED,
        R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS,
    )
    .unwrap();
    let second = deterministic_smoke(
        R17_DETERMINISTIC_SMOKE_SEED,
        R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS,
    )
    .unwrap();
    assert_eq!(first, second);
    assert!(!first.contains("\"latency\""));
    assert!(!first.contains("\"hostname\""));
    assert!(!first.contains("\"elapsed\""));
}

fn json_keys(line: &str) -> Vec<&str> {
    let mut keys = Vec::new();
    let mut cursor = 0;
    while let Some(relative_end) = line[cursor..].find("\":") {
        let end = cursor + relative_end;
        let start = line[..end].rfind('"').unwrap() + 1;
        keys.push(&line[start..end]);
        cursor = end + 2;
    }
    keys
}
