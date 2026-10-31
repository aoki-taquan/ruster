//! `ruster validate` and `ruster plan`.
//!
//! Both read at most [`MAX_CONFIG_BYTES`] + 1 bytes per file, parse and
//! validate with the same [`SIM_VALIDATION_LIMITS`] that `run-sim` uses, and
//! print only counts, stable codes, schema field paths, and plan structure.
//! Secrets (allocator seeds, hash keys, scenario seeds) are never printed:
//! they are not part of any rendered value.

use std::fs::File;
use std::io::{self, Read, Write};
use std::num::NonZeroU64;
use std::path::Path;

use ruster_config::{
    parse, validate, PathSegment, SourcePath, ValidatedConfig, ValidatedConfigV1, MAX_CONFIG_BYTES,
};
use ruster_control::{
    candidate_from_config, ApplyPlan, ConfigBridgeError, PlanError, PlanSide,
    SimDeterministicKeySource,
};
use ruster_sim_scenario::SIM_VALIDATION_LIMITS;

use crate::{plan_text, EXIT_INVALID, EXIT_RUNTIME};

/// Why a configuration file could not be used.
pub enum LoadError {
    /// The file could not be opened or read (exit 1).
    Read(io::ErrorKind),
    /// The content was rejected (exit 2). Value-free.
    Rejected(Rejection),
}

pub struct Rejection {
    pub stage: &'static str,
    pub code: &'static str,
    pub path: Option<String>,
    pub bounds: Option<(u64, u64)>,
}

impl Rejection {
    fn render(&self) -> String {
        let mut text = format!("stage={} code={}", self.stage, self.code);
        if let Some(path) = &self.path {
            text.push_str(" path=");
            text.push_str(path);
        }
        if let Some((limit, actual)) = self.bounds {
            text.push_str(&format!(" limit={limit} actual={actual}"));
        }
        text
    }
}

fn wide(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Renders a value-free schema path such as `routes[0].via`.
fn render_path(path: &SourcePath) -> Option<String> {
    let mut text = String::new();
    for segment in path.segments() {
        match segment {
            PathSegment::Field(field) => {
                if !text.is_empty() {
                    text.push('.');
                }
                text.push_str(field);
            }
            PathSegment::Index(index) => text.push_str(&format!("[{index}]")),
            _ => text.push_str("[?]"),
        }
    }
    (!text.is_empty()).then_some(text)
}

/// Reads, parses, and validates one configuration document, including the
/// M1 service bridge, so `validate` and both sides of `plan` accept exactly
/// what `run-sim` accepts.
pub fn load(path: &Path) -> Result<ValidatedConfigV1, LoadError> {
    let mut bytes = Vec::new();
    let take = wide(MAX_CONFIG_BYTES).saturating_add(1);
    File::open(path)
        .and_then(|file| file.take(take).read_to_end(&mut bytes))
        .map_err(|error| LoadError::Read(error.kind()))?;
    let parsed = parse(&bytes).map_err(|diagnostic| {
        LoadError::Rejected(Rejection {
            stage: "parse",
            code: diagnostic.code().code(),
            path: render_path(diagnostic.path()),
            bounds: diagnostic
                .limit()
                .zip(diagnostic.actual())
                .map(|(l, a)| (wide(l), wide(a))),
        })
    })?;
    match validate(parsed, SIM_VALIDATION_LIMITS) {
        Ok(ValidatedConfig::V1(config)) => Ok(config),
        Ok(_) => Err(LoadError::Rejected(Rejection {
            stage: "version",
            code: "UNSUPPORTED_VERSION",
            path: None,
            bounds: None,
        })),
        Err(error) => Err(LoadError::Rejected(Rejection {
            stage: "validate",
            code: error.code().code(),
            path: render_path(error.path()),
            bounds: error.limit().zip(error.actual()),
        })),
    }
    .and_then(|config| {
        bridge_check(&config).map_err(LoadError::Rejected)?;
        Ok(config)
    })
}

/// The M1 service bridge that `run-sim` applies: every service present and
/// candidate validation passing. It builds a throw-away generation-1
/// candidate with the simulation key source; the keys stay in memory and
/// are dropped unprinted.
fn bridge_check(config: &ValidatedConfigV1) -> Result<(), Rejection> {
    let mut keys = SimDeterministicKeySource::new(0);
    candidate_from_config(config, NonZeroU64::MIN, &mut keys)
        .map(drop)
        .map_err(bridge_rejection)
}

/// Stable label of an I/O error kind (never an OS message or a path).
pub fn io_code(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::NotFound => "NOT_FOUND",
        io::ErrorKind::PermissionDenied => "PERMISSION_DENIED",
        io::ErrorKind::IsADirectory => "IS_A_DIRECTORY",
        io::ErrorKind::InvalidData => "INVALID_DATA",
        io::ErrorKind::Interrupted => "INTERRUPTED",
        io::ErrorKind::BrokenPipe => "BROKEN_PIPE",
        io::ErrorKind::OutOfMemory => "OUT_OF_MEMORY",
        _ => "IO_ERROR",
    }
}

fn bridge_rejection(error: ConfigBridgeError) -> Rejection {
    Rejection {
        stage: "bridge",
        code: error.code(),
        path: None,
        bounds: None,
    }
}

/// Reports a load failure on stderr and returns the exit status.
fn report_load(err: &mut impl Write, label: &str, error: &LoadError) -> u8 {
    match error {
        LoadError::Read(kind) => {
            let _ = writeln!(err, "ruster: cannot read {label}config: {}", io_code(*kind));
            EXIT_RUNTIME
        }
        LoadError::Rejected(rejection) => {
            let _ = writeln!(err, "ruster: invalid {label}config: {}", rejection.render());
            EXIT_INVALID
        }
    }
}

/// `ruster validate <config>`: summary on stdout, diagnostics on stderr.
pub fn run_validate(path: &Path, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let config = match load(path) {
        Ok(config) => config,
        Err(error) => return report_load(err, "", &error),
    };
    let rules = config
        .firewall()
        .map_or(0, |firewall| firewall.rules().len());
    let summary = format!(
        "valid: schema-version=1 interfaces={} routes={} neighbors={} local-ipv4={} \
         firewall-rules={} services=resolution,icmpv4-errors,nat44-udp,nat44-tcp,firewall \
         storage-bytes={}\n",
        config.interfaces().len(),
        config.routes().len(),
        config.neighbors().len(),
        config.local_ipv4().len(),
        rules,
        config.storage_shape().required_bytes,
    );
    if out.write_all(summary.as_bytes()).is_err() {
        return EXIT_RUNTIME;
    }
    0
}

/// `ruster plan <current> <next>`: the plan on stdout, exit 0 whenever a
/// plan is produced, including a restart-required one.
pub fn run_plan(current: &Path, next: &Path, out: &mut impl Write, err: &mut impl Write) -> u8 {
    let current = match load(current) {
        Ok(config) => config,
        Err(error) => return report_load(err, "current ", &error),
    };
    let next = match load(next) {
        Ok(config) => config,
        Err(error) => return report_load(err, "next ", &error),
    };
    match ApplyPlan::between(&current, &next) {
        Ok(plan) => {
            if out.write_all(plan_text::render(&plan).as_bytes()).is_err() {
                return EXIT_RUNTIME;
            }
            0
        }
        Err(PlanError::MissingService { side, service }) => {
            let label = match side {
                PlanSide::Current => "current",
                PlanSide::Next => "next",
            };
            let rejection = bridge_rejection(ConfigBridgeError::MissingService(service));
            let _ = writeln!(
                err,
                "ruster: invalid {label} config: {}",
                rejection.render()
            );
            EXIT_INVALID
        }
        Err(_) => {
            let _ = writeln!(err, "ruster: plan rejected");
            EXIT_INVALID
        }
    }
}
