pub mod artifact;
pub mod corpus;
pub mod envelope;
pub mod state;
#[path = "../support/mod.rs"]
pub mod support;
pub mod targets;

use std::{
    env,
    panic::{self, AssertUnwindSafe},
};

use artifact::{
    load_replay_from_env, replay_repro, seed_repro, ArtifactWriter, ARTIFACT_DIR_ENV, REPLAY_ENV,
};
use envelope::{parse, Target, MAX_CASES_PER_RUN};
use targets::{generate_encoded, run_encoded, smoke_budget, SHORT_CASES, V1_SEEDS};

const TARGET_ENV: &str = "RUSTER_R16A_TARGET";
const SEED_ENV: &str = "RUSTER_R16A_SEED";
const CASE_START_ENV: &str = "RUSTER_R16A_CASE_START";
const CASES_ENV: &str = "RUSTER_R16A_CASES";

pub fn run_short_matrix() {
    let writer = ArtifactWriter::from_env().unwrap_or_else(|error| panic!("{error}"));
    for target in Target::ALL {
        for case_index in 0..SHORT_CASES {
            let encoded = generate_encoded(target, V1_SEEDS[0], case_index)
                .unwrap_or_else(|failure| panic!("{}", failure.detail));
            let repro = seed_repro(target.name(), V1_SEEDS[0], case_index);
            run_one(&encoded, writer.as_ref(), &repro);
        }
    }
}

pub fn run_past_corpus() {
    let writer = ArtifactWriter::from_env().unwrap_or_else(|error| panic!("{error}"));
    for case in corpus::past_regressions() {
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            run_one(&case.encoded, writer.as_ref(), corpus_repro())
        }));
        if let Err(payload) = result {
            panic!(
                "past regression corpus={} failed: {}",
                case.name,
                panic_detail(payload)
            );
        }
    }
}

pub fn run_bounded_smoke() {
    let writer = ArtifactWriter::from_env().unwrap_or_else(|error| panic!("{error}"));
    if let Some((path, encoded)) =
        load_replay_from_env().unwrap_or_else(|error| panic!("replay configuration: {error}"))
    {
        reject_seed_selection_with_replay();
        parse(&encoded).unwrap_or_else(|error| {
            panic!("replay={} typed parse failed: {error}", path.display())
        });
        let repro =
            replay_repro(&path).unwrap_or_else(|error| panic!("replay configuration: {error}"));
        run_one(&encoded, writer.as_ref(), &repro);
        return;
    }

    match explicit_selection() {
        Some(selection) => {
            for case_index in selection.start..selection.start + selection.cases {
                let encoded = generate_encoded(selection.target, selection.seed, case_index)
                    .unwrap_or_else(|failure| panic!("{}", failure.detail));
                let repro = seed_repro(selection.target.name(), selection.seed, case_index);
                run_one(&encoded, writer.as_ref(), &repro);
            }
        }
        None => {
            for target in Target::ALL {
                for seed in V1_SEEDS {
                    for case_index in 0..smoke_budget(target) {
                        let encoded = generate_encoded(target, seed, case_index)
                            .unwrap_or_else(|failure| panic!("{}", failure.detail));
                        let repro = seed_repro(target.name(), seed, case_index);
                        run_one(&encoded, writer.as_ref(), &repro);
                    }
                }
            }
        }
    }
}

fn run_one(encoded: &[u8], writer: Option<&ArtifactWriter>, fallback_repro: &str) {
    let parsed = parse(encoded).unwrap_or_else(|error| panic!("typed envelope parse: {error}"));
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| run_encoded(encoded)));
    let detail = match outcome {
        Ok(Ok(())) => return,
        Ok(Err(failure)) => failure.detail,
        Err(payload) => format!("target panicked: {}", panic_detail(payload)),
    };
    let (artifact, repro) = if let Some(writer) = writer {
        match writer.write(encoded, &parsed, &detail) {
            Ok(record) => (
                format!(
                    "case={} metadata={}",
                    record.case_path.display(),
                    record.jsonl_path.display()
                ),
                record.repro,
            ),
            Err(error) => (format!("artifact_error={error}"), fallback_repro.to_owned()),
        }
    } else {
        ("artifact=disabled".to_owned(), fallback_repro.to_owned())
    };
    panic!(
        "R16A_FAILURE schema=1 target={} seed=0x{:016x} case={} {} detail={} repro={}",
        parsed.target.name(),
        parsed.seed,
        parsed.case_index,
        artifact,
        detail,
        repro
    );
}

fn corpus_repro() -> &'static str {
    "cargo test --locked -p ruster-io-sim --test security_property_smoke \
     r16a_past_regression_corpus_is_exact -- --exact --nocapture --test-threads=1"
}

struct ExplicitSelection {
    target: Target,
    seed: u64,
    start: u64,
    cases: u64,
}

fn explicit_selection() -> Option<ExplicitSelection> {
    let values = [
        env_value(TARGET_ENV),
        env_value(SEED_ENV),
        env_value(CASE_START_ENV),
        env_value(CASES_ENV),
    ];
    if values.iter().all(Option::is_none) {
        return None;
    }
    if values.iter().any(Option::is_none) {
        panic!("{TARGET_ENV}, {SEED_ENV}, {CASE_START_ENV}, and {CASES_ENV} must be set together");
    }
    let target = Target::from_name(values[0].as_deref().unwrap())
        .unwrap_or_else(|error| panic!("{TARGET_ENV}: {error}"));
    let seed = parse_u64(values[1].as_deref().unwrap())
        .unwrap_or_else(|error| panic!("{SEED_ENV}: {error}"));
    let start = parse_u64(values[2].as_deref().unwrap())
        .unwrap_or_else(|error| panic!("{CASE_START_ENV}: {error}"));
    let cases = parse_u64(values[3].as_deref().unwrap())
        .unwrap_or_else(|error| panic!("{CASES_ENV}: {error}"));
    if cases == 0 || cases > MAX_CASES_PER_RUN {
        panic!("{CASES_ENV} must be in 1..={MAX_CASES_PER_RUN}");
    }
    let end = start
        .checked_add(cases)
        .unwrap_or_else(|| panic!("case range overflow"));
    if end > MAX_CASES_PER_RUN {
        panic!("case range end {end} exceeds {MAX_CASES_PER_RUN}");
    }
    Some(ExplicitSelection {
        target,
        seed,
        start,
        cases,
    })
}

fn reject_seed_selection_with_replay() {
    for name in [TARGET_ENV, SEED_ENV, CASE_START_ENV, CASES_ENV] {
        if env_value(name).is_some() {
            panic!("{REPLAY_ENV} cannot be combined with {name}");
        }
    }
}

fn env_value(name: &str) -> Option<String> {
    match env::var(name) {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => panic!("{name} must be valid UTF-8"),
    }
}

fn parse_u64(value: &str) -> Result<u64, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid hexadecimal u64".to_owned());
        }
        u64::from_str_radix(hex, 16).map_err(|error| error.to_string())
    } else {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("invalid decimal u64".to_owned());
        }
        value.parse::<u64>().map_err(|error| error.to_string())
    }
}

fn panic_detail(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

pub fn env_names() -> [&'static str; 6] {
    [
        TARGET_ENV,
        SEED_ENV,
        CASE_START_ENV,
        CASES_ENV,
        REPLAY_ENV,
        ARTIFACT_DIR_ENV,
    ]
}
