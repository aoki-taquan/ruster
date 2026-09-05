#[path = "r16a_support/mod.rs"]
mod r16a;

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};

use r16a::{
    artifact::{load_replay, ArtifactWriter},
    envelope::{
        parse, CaseEnvelope, EnvelopeError, Expected, Target, MAX_CASES_PER_RUN, MAX_CORPUS_CASES,
        MAX_ENVELOPE_LEN, MAX_PAYLOAD_LEN, MAX_RESOLUTION_NOW,
    },
    targets::{
        generate_encoded, ADMISSION_SMOKE_CASES, CHECKSUM_SMOKE_CASES, PARSER_SMOKE_CASES,
        RESOLUTION_SMOKE_CASES, V1_SEEDS,
    },
};

#[test]
fn r16a_envelope_parser_is_typed_canonical_and_bounded() {
    let payload = [1_u8, 2, 3];
    let encoded = CaseEnvelope {
        target: Target::Checksum,
        seed: V1_SEEDS[0],
        case_index: 7,
        now: 11,
        ingress: 1,
        expected: Expected::Checksum(0xfbfd),
        payload: &payload,
    }
    .encode()
    .unwrap();
    let parsed = parse(&encoded).unwrap();
    assert_eq!(parsed.target, Target::Checksum);
    assert_eq!(parsed.seed, V1_SEEDS[0]);
    assert_eq!(parsed.case_index, 7);
    assert_eq!(parsed.payload, payload);
    assert_eq!(parsed.encode().unwrap(), encoded);

    let mut cases = Vec::new();
    cases.push((
        "header truncation",
        encoded[..71].to_vec(),
        EnvelopeError::HeaderTruncated,
    ));
    let mut bad_magic = encoded.clone();
    bad_magic[0] ^= 1;
    cases.push(("bad magic", bad_magic, EnvelopeError::BadMagic));
    let mut bad_version = encoded.clone();
    bad_version[4] = 2;
    cases.push((
        "unsupported version",
        bad_version,
        EnvelopeError::UnsupportedVersion,
    ));
    let mut bad_target = encoded.clone();
    bad_target[5] = 99;
    cases.push((
        "unknown target",
        bad_target,
        EnvelopeError::UnknownTargetTag,
    ));
    let mut bad_expected = encoded.clone();
    bad_expected[6] = 99;
    cases.push((
        "unknown expected",
        bad_expected,
        EnvelopeError::UnknownExpectedTag,
    ));
    let mut bad_reserved = encoded.clone();
    bad_reserved[7] = 1;
    cases.push((
        "nonzero reserved",
        bad_reserved,
        EnvelopeError::ReservedNotZero,
    ));
    let mut bad_reserved_word = encoded.clone();
    bad_reserved_word[35] = 1;
    cases.push((
        "nonzero reserved word",
        bad_reserved_word,
        EnvelopeError::ReservedNotZero,
    ));
    let mut noncanonical = encoded.clone();
    noncanonical[42] = 1;
    cases.push((
        "noncanonical expected tail",
        noncanonical,
        EnvelopeError::NonCanonicalExpected,
    ));
    let mut target_mismatch = encoded.clone();
    target_mismatch[5] = Target::Parser as u8;
    cases.push((
        "expected target mismatch",
        target_mismatch,
        EnvelopeError::ExpectedTargetMismatch,
    ));
    let mut unknown_drop = encoded.clone();
    unknown_drop[6] = 2;
    unknown_drop[40..72].fill(0);
    cases.push((
        "unknown drop code",
        unknown_drop,
        EnvelopeError::UnknownDropCode,
    ));
    let mut length_mismatch = encoded.clone();
    length_mismatch[36..40].copy_from_slice(&4_u32.to_le_bytes());
    cases.push((
        "length mismatch",
        length_mismatch,
        EnvelopeError::LengthMismatch,
    ));
    cases.push((
        "envelope too large",
        vec![0; MAX_ENVELOPE_LEN + 1],
        EnvelopeError::EnvelopeTooLarge,
    ));
    let mut case_out_of_range = encoded.clone();
    case_out_of_range[16..24].copy_from_slice(&MAX_CASES_PER_RUN.to_le_bytes());
    cases.push((
        "case index out of range",
        case_out_of_range,
        EnvelopeError::CaseIndexOutOfRange,
    ));
    let mut resolution_time = generate_encoded(Target::Resolution, V1_SEEDS[0], 0).unwrap();
    resolution_time[24..32].copy_from_slice(&(MAX_RESOLUTION_NOW + 1).to_le_bytes());
    cases.push((
        "resolution time out of range",
        resolution_time,
        EnvelopeError::ResolutionTimeOutOfRange,
    ));

    for (case, (label, bytes, expected)) in cases.into_iter().enumerate() {
        assert_eq!(
            parse(&bytes),
            Err(expected),
            "envelope_case={case} label={label}"
        );
    }

    assert_eq!(MAX_PAYLOAD_LEN + 72, MAX_ENVELOPE_LEN);
    assert_eq!(MAX_CORPUS_CASES, 512);
    assert_eq!(MAX_CASES_PER_RUN, 65_536);
    assert_eq!(
        CaseEnvelope {
            target: Target::Checksum,
            seed: V1_SEEDS[0],
            case_index: MAX_CASES_PER_RUN,
            now: 0,
            ingress: 0,
            expected: Expected::Checksum(0),
            payload: &[],
        }
        .encode(),
        Err(EnvelopeError::CaseIndexOutOfRange)
    );
    assert_eq!(
        CaseEnvelope {
            target: Target::Resolution,
            seed: V1_SEEDS[0],
            case_index: 0,
            now: MAX_RESOLUTION_NOW + 1,
            ingress: 1,
            expected: Expected::Resolution(Default::default()),
            payload: &[0, 0, 0, 0],
        }
        .encode(),
        Err(EnvelopeError::ResolutionTimeOutOfRange)
    );
}

#[test]
fn r16a_v1_generation_is_exact_case_replayable() {
    assert_eq!(
        V1_SEEDS,
        [
            0x6a09_e667_f3bc_c909,
            0x243f_6a88_85a3_08d3,
            0x9e37_79b9_7f4a_7c15,
            0xd1b5_4a32_d192_ed03,
        ]
    );
    assert_eq!(
        (
            PARSER_SMOKE_CASES,
            CHECKSUM_SMOKE_CASES,
            ADMISSION_SMOKE_CASES,
            RESOLUTION_SMOKE_CASES,
        ),
        (4_096, 4_096, 2_048, 2_048)
    );
    for target in Target::ALL {
        let first = generate_encoded(target, V1_SEEDS[2], 317).unwrap();
        let replay = generate_encoded(target, V1_SEEDS[2], 317).unwrap();
        let neighbor = generate_encoded(target, V1_SEEDS[2], 318).unwrap();
        assert_eq!(first, replay, "target={} exact replay", target.name());
        assert_ne!(first, neighbor, "target={} case domain", target.name());
    }
    let goldens = [
        (Target::Parser, V1_SEEDS[0], 0, 147, 0xf086_57a1_48f7_7bc4),
        (Target::Parser, V1_SEEDS[1], 31, 193, 0xadcd_b78a_dfc3_5aed),
        (Target::Parser, V1_SEEDS[2], 317, 311, 0x9cda_284c_932e_fffb),
        (
            Target::Parser,
            V1_SEEDS[3],
            2_047,
            266,
            0xad1a_028b_c440_b06e,
        ),
        (Target::Checksum, V1_SEEDS[0], 0, 72, 0x0baf_8351_091e_9bca),
        (
            Target::Checksum,
            V1_SEEDS[1],
            31,
            1_459,
            0xa713_e4ed_2446_83ff,
        ),
        (
            Target::Checksum,
            V1_SEEDS[2],
            317,
            2_179,
            0x1707_ca7f_ffab_9c64,
        ),
        (
            Target::Checksum,
            V1_SEEDS[3],
            2_047,
            1_737,
            0x36db_e3c3_9e59_0213,
        ),
        (
            Target::Admission,
            V1_SEEDS[0],
            0,
            106,
            0x951c_87e6_2dd0_9014,
        ),
        (
            Target::Admission,
            V1_SEEDS[1],
            31,
            132,
            0x58c9_29b6_d9ac_c237,
        ),
        (
            Target::Admission,
            V1_SEEDS[2],
            317,
            132,
            0x0a67_7a18_e227_eea2,
        ),
        (
            Target::Admission,
            V1_SEEDS[3],
            2_047,
            110,
            0x55df_50e5_9d5a_352a,
        ),
        (
            Target::Resolution,
            V1_SEEDS[0],
            0,
            102,
            0x0c5b_eb89_8c53_254d,
        ),
        (
            Target::Resolution,
            V1_SEEDS[1],
            31,
            124,
            0x9570_677b_4bd6_d210,
        ),
        (
            Target::Resolution,
            V1_SEEDS[2],
            317,
            104,
            0x3309_ecf4_7e34_7954,
        ),
        (
            Target::Resolution,
            V1_SEEDS[3],
            2_047,
            118,
            0x8afa_4b2c_93dd_039d,
        ),
    ];
    for (target, seed, case_index, length, digest) in goldens {
        let encoded = generate_encoded(target, seed, case_index).unwrap();
        assert_eq!(encoded.len(), length, "target={} length", target.name());
        assert_eq!(
            stable_digest(&encoded),
            digest,
            "target={} seed={seed:#018x} case={case_index}",
            target.name()
        );
    }
}

#[test]
fn r16a_past_regression_corpus_is_exact() {
    let expected = [
        ("vlan-inner-frame-not-parsed", 86, 0x2420_c338_87fc_b585),
        (
            "reserved-ipv4-flag-parser-accept",
            106,
            0xa4de_8a67_8db7_a30c,
        ),
        ("rfc1071-known-vector", 80, 0x7512_5b58_810b_98c3),
        ("odd-length-high-byte-padding", 75, 0xb28f_cd8b_78e4_45c1),
        ("cross-interface-router-mac", 106, 0xe937_4ca6_6a3b_a610),
        ("local-ipv4-source-claim", 106, 0xb45a_4469_a391_e2ff),
        (
            "arp-foreign-unicast-before-merge",
            132,
            0x8573_b747_d761_1914,
        ),
        (
            "resolution-cancel-reuse-and-invalid-future",
            88,
            0x9651_3a3b_31a7_d660,
        ),
        (
            "resolution-zero-action-and-cache-capacity",
            80,
            0x8257_75e7_732e_ef57,
        ),
    ];
    let corpus = r16a::corpus::past_regressions();
    assert_eq!(corpus.len(), expected.len());
    for (case, (name, length, digest)) in corpus.iter().zip(expected) {
        assert_eq!(case.name, name);
        assert_eq!(case.encoded.len(), length, "corpus={name}");
        assert_eq!(stable_digest(&case.encoded), digest, "corpus={name}");
    }
    r16a::run_past_corpus();
}

#[test]
fn r16a_resolution_fixed_identity_fifo_invalid_future_regression() {
    let case = r16a::corpus::past_regressions()
        .into_iter()
        .find(|case| case.name == "resolution-cancel-reuse-and-invalid-future")
        .expect("fixed resolution regression");
    assert_eq!(case.encoded[16..24], 7_u64.to_le_bytes());
    assert_eq!(case.encoded[24..32], 100_u64.to_le_bytes());
    assert_eq!(
        &case.encoded[72..],
        &[2, 2, 2, 6, 0, 0, 0, 0, 0, 1, 1, 0, 2, 7, 0, 2]
    );
    match r16a::envelope::parse(&case.encoded).unwrap().expected {
        Expected::Resolution(summary) => assert_eq!(
            summary,
            r16a::envelope::ResolutionSummary {
                pending_states: 2,
                pending_actions: 2,
                dynamic_neighbors: 1,
                queued: 3,
                suppressed: 1,
                state_full: 0,
                action_full: 0,
                clock_regressions: 0,
            }
        ),
        expected => panic!("fixed resolution expected value changed: {expected:?}"),
    }
    r16a::targets::run_resolution_fixed_identity_fifo_regression().unwrap();
}

#[test]
fn r16a_short_seed_matrix_is_deterministic() {
    r16a::run_short_matrix();
}

#[test]
fn r16a_state_property_contract_smoke() {
    r16a::state::run_short_state_smoke();
}

#[test]
fn r16a_combined_nat_firewall_fixed_transaction_regression() {
    r16a::state::run_combined_nat_firewall_fixed_regression();
}

#[test]
fn r16a_failure_artifact_is_binary_jsonl_and_exactly_replayable() {
    let encoded = generate_encoded(Target::Parser, V1_SEEDS[1], 19).unwrap();
    let parsed = parse(&encoded).unwrap();
    let directory = missing_temp_path("artifact-meta");
    let writer = ArtifactWriter::new(directory.clone()).unwrap();
    let record = writer
        .write(&encoded, &parsed, "synthetic \"failure\"\nline")
        .unwrap();
    let replay = fs::read(&record.case_path).unwrap();
    assert_eq!(replay, encoded);
    assert_eq!(parse(&replay).unwrap(), parsed);
    r16a::targets::run_encoded(&replay).unwrap();
    let metadata = fs::read_to_string(&record.jsonl_path).unwrap();
    assert_eq!(metadata.lines().count(), 1);
    assert!(metadata.contains("\"schema\":1"));
    assert!(metadata.contains("\"target\":\"parser\""));
    assert!(metadata.contains("synthetic \\\"failure\\\"\\nline"));
    assert!(metadata.contains("RUSTER_R16A_REPLAY=/tmp/"));
    assert!(record.repro.contains("--locked"));
    assert!(record.repro.contains("--ignored --exact"));
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&record.case_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&record.jsonl_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let bounded = writer
        .write(&encoded, &parsed, &"x".repeat(10_000))
        .unwrap();
    let bounded_metadata = fs::read_to_string(&bounded.jsonl_path).unwrap();
    assert!(bounded_metadata.len() <= 65_536);
    assert!(bounded_metadata.contains("...[truncated]"));
    fs::remove_file(record.case_path).unwrap();
    fs::remove_file(record.jsonl_path).unwrap();
    fs::remove_file(bounded.case_path).unwrap();
    fs::remove_file(bounded.jsonl_path).unwrap();
    fs::remove_dir(directory).unwrap();
}

#[test]
fn r16a_artifact_paths_and_replay_reads_are_bounded() {
    assert!(ArtifactWriter::new(PathBuf::from("relative")).is_err());
    assert!(ArtifactWriter::new(PathBuf::from("/tmp/../tmp/r16a")).is_err());
    assert!(ArtifactWriter::new(PathBuf::from("/")).is_err());
    assert!(ArtifactWriter::new(PathBuf::from(format!("/tmp/{}", "a".repeat(4_096)))).is_err());

    let directory = private_temp_dir("replay-bounds");
    let oversized = directory.join("oversized.case");
    let mut oversized_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&oversized)
        .unwrap();
    oversized_file
        .write_all(&vec![0_u8; MAX_ENVELOPE_LEN + 1])
        .unwrap();
    drop(oversized_file);
    let error = load_replay(oversized.clone()).unwrap_err();
    assert!(error.contains("exceeds"));
    fs::remove_file(oversized).unwrap();

    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    let encoded = generate_encoded(Target::Parser, V1_SEEDS[0], 0).unwrap();
    let parsed = parse(&encoded).unwrap();
    let writer = ArtifactWriter::new(directory.clone()).unwrap();
    assert!(writer
        .write(&encoded, &parsed, "private mode required")
        .is_err());
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir(directory).unwrap();
}

#[test]
fn r16a_artifact_and_replay_paths_reject_symlinks_directly() {
    let directory = private_temp_dir("symlink-boundary");
    let real_component = directory.join("real");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&real_component)
        .unwrap();
    let linked_component = directory.join("linked");
    symlink(&real_component, &linked_component).unwrap();

    let encoded = generate_encoded(Target::Parser, V1_SEEDS[0], 0).unwrap();
    let parsed = parse(&encoded).unwrap();
    let writer = ArtifactWriter::new(linked_component.join("artifacts")).unwrap();
    let error = match writer.write(&encoded, &parsed, "symlink component must fail") {
        Err(error) => error,
        Ok(_) => panic!("artifact symlink component was accepted"),
    };
    assert!(error.contains("cannot traverse symlinks"));
    assert!(fs::read_dir(&real_component).unwrap().next().is_none());

    let replay = directory.join("replay.case");
    let mut replay_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&replay)
        .unwrap();
    replay_file.write_all(&encoded).unwrap();
    drop(replay_file);
    let linked_replay = directory.join("linked-replay.case");
    symlink(&replay, &linked_replay).unwrap();
    let error = load_replay(linked_replay.clone()).unwrap_err();
    assert!(error.contains("cannot traverse symlinks"));

    fs::remove_file(linked_replay).unwrap();
    fs::remove_file(replay).unwrap();
    fs::remove_file(linked_component).unwrap();
    fs::remove_dir(real_component).unwrap();
    fs::remove_dir(directory).unwrap();
}

#[test]
fn r16a_environment_surface_is_fixed_and_cold_only() {
    assert_eq!(
        r16a::env_names(),
        [
            "RUSTER_R16A_TARGET",
            "RUSTER_R16A_SEED",
            "RUSTER_R16A_CASE_START",
            "RUSTER_R16A_CASES",
            "RUSTER_R16A_REPLAY",
            "RUSTER_R16A_ARTIFACT_DIR",
        ]
    );
}

#[test]
#[ignore = "bounded R16A full smoke; invoke explicitly with the documented exact command"]
fn r16a_bounded_smoke() {
    r16a::run_bounded_smoke();
}

#[test]
#[ignore = "fixed-seed NAT/FW state property smoke; invoke explicitly with the documented exact command"]
fn r16a_state_property_smoke() {
    r16a::state::run_full_state_smoke();
}

fn stable_digest(bytes: &[u8]) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        digest ^= u64::from(*byte);
        digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
    }
    digest
}

fn missing_temp_path(label: &str) -> PathBuf {
    for suffix in 0_u8..16 {
        let path = PathBuf::from(format!(
            "/tmp/ruster-r16a-{label}-{}-{suffix}",
            std::process::id()
        ));
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return path,
            Ok(_) => {}
            Err(error) => panic!("inspect temporary artifact path: {error}"),
        }
    }
    panic!("all bounded temporary artifact paths already exist");
}

fn private_temp_dir(label: &str) -> PathBuf {
    for suffix in 0_u8..16 {
        let path = PathBuf::from(format!(
            "/tmp/ruster-r16a-{label}-{}-{suffix}",
            std::process::id()
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create private temporary directory: {error}"),
        }
    }
    panic!("all bounded private temporary directories already exist");
}
