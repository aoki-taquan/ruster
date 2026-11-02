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
    /// The reload path is not a regular file
    /// ([`load_validated_regular`]).
    NotAFile,
    /// `--strict-config-perms` refused the file (exit 1). Value-free code.
    Insecure(&'static str),
}

impl LoadError {
    /// Value-free `stage=... code=...` text of the failure.
    pub fn render(&self) -> String {
        match self {
            Self::Read(kind) => format!("stage=read code={}", io_code(*kind)),
            Self::Rejected(rejection) => rejection.render(),
            Self::NotAFile => "stage=read code=NOT_A_FILE".to_owned(),
            Self::Insecure(code) => format!("stage=permissions code={code}"),
        }
    }
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
/// what `run-sim` accepts, except that any validated `[backend]` is
/// accepted here: `run-sim` additionally refuses a non-`sim` backend
/// (`stage=backend code=UNSUPPORTED_BACKEND`).
pub fn load(path: &Path) -> Result<ValidatedConfigV1, LoadError> {
    load_validated(path).and_then(|config| {
        bridge_check(&config).map_err(LoadError::Rejected)?;
        Ok(config)
    })
}

/// Reads, parses, and validates one configuration document without the
/// service bridge. `ruster run` uses this and then builds its one
/// candidate with the production key source, so no simulation key source
/// is ever constructed on the live path; the bridge errors are the same.
pub fn load_validated(path: &Path) -> Result<ValidatedConfigV1, LoadError> {
    let file = File::open(path).map_err(|error| LoadError::Read(error.kind()))?;
    validate_file(file)
}

/// [`load_validated`] for `ruster run` (startup and the reload, which runs
/// on the router thread): the path is opened with `O_NONBLOCK | O_NOCTTY`
/// and must be a regular file (`NOT_A_FILE` otherwise), so a FIFO or
/// device node in its place can neither block the datapath nor become
/// the controlling terminal. A regular file's reads never block on the
/// writer.
///
/// With `strict` (`--strict-config-perms`) the opened file (`fstat`, so
/// the checked file is the read one) must not be writable by group or
/// other (`code=WRITABLE_BY_OTHERS`) and must be owned by root or the
/// effective user (`code=UNTRUSTED_OWNER`; an unreadable effective uid is
/// `code=OWNER_UNVERIFIABLE`).
pub fn load_validated_regular(path: &Path, strict: bool) -> Result<ValidatedConfigV1, LoadError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        /// Linux `O_NONBLOCK` and `O_NOCTTY` (the same values on every
        /// Linux architecture this binary supports for `run`).
        const O_NONBLOCK: i32 = 0o4000;
        const O_NOCTTY: i32 = 0o400;
        options.custom_flags(O_NONBLOCK | O_NOCTTY);
    }
    let file = options
        .open(path)
        .map_err(|error| LoadError::Read(error.kind()))?;
    let metadata = file
        .metadata()
        .map_err(|error| LoadError::Read(error.kind()))?;
    if !metadata.is_file() {
        return Err(LoadError::NotAFile);
    }
    #[cfg(unix)]
    if strict {
        use std::os::unix::fs::MetadataExt;
        let euid = effective_uid().ok_or(LoadError::Insecure("OWNER_UNVERIFIABLE"))?;
        check_permissions(metadata.mode(), metadata.uid(), euid).map_err(LoadError::Insecure)?;
        check_directories(path, euid).map_err(LoadError::Insecure)?;
    }
    #[cfg(not(unix))]
    let _ = strict;
    validate_file(file)
}

/// The strict-permission rule of [`load_validated_regular`].
pub fn check_permissions(mode: u32, owner: u32, euid: u32) -> Result<(), &'static str> {
    if mode & 0o022 != 0 {
        return Err("WRITABLE_BY_OTHERS");
    }
    if owner != 0 && owner != euid {
        return Err("UNTRUSTED_OWNER");
    }
    Ok(())
}

/// The strict-permission rule for each directory on the way to the file:
/// owned by root or the effective user, and not writable by group or
/// other unless it is a root-owned sticky directory (like `/tmp`, where
/// nobody else may rename or replace an entry they do not own).
pub fn check_directory(mode: u32, owner: u32, euid: u32) -> Result<(), &'static str> {
    if owner != 0 && owner != euid {
        return Err("UNTRUSTED_DIRECTORY");
    }
    let sticky_root = mode & 0o1000 != 0 && owner == 0;
    if mode & 0o022 != 0 && !sticky_root {
        return Err("WRITABLE_DIRECTORY");
    }
    Ok(())
}

/// Applies [`check_directory`] to every directory from the canonical
/// path's parent up to `/` (symlinks resolved, so a link elsewhere is
/// checked where it points). Cold path; `canonicalize` failing is
/// `OWNER_UNVERIFIABLE`.
#[cfg(unix)]
fn check_directories(path: &Path, euid: u32) -> Result<(), &'static str> {
    use std::os::unix::fs::MetadataExt;
    let canonical = std::fs::canonicalize(path).map_err(|_| "OWNER_UNVERIFIABLE")?;
    for directory in canonical.ancestors().skip(1) {
        let metadata = std::fs::metadata(directory).map_err(|_| "OWNER_UNVERIFIABLE")?;
        check_directory(metadata.mode(), metadata.uid(), euid)?;
    }
    Ok(())
}

/// The effective uid (second field of `Uid:` in `/proc/self/status`).
fn effective_uid() -> Option<u32> {
    parse_effective_uid(&std::fs::read_to_string("/proc/self/status").ok()?)
}

/// `Uid:\t<real>\t<effective>\t<saved>\t<fs>`.
pub fn parse_effective_uid(status: &str) -> Option<u32> {
    let row = status.lines().find_map(|line| line.strip_prefix("Uid:"))?;
    row.split_whitespace().nth(1)?.parse().ok()
}

fn validate_file(file: File) -> Result<ValidatedConfigV1, LoadError> {
    let mut bytes = Vec::new();
    let take = wide(MAX_CONFIG_BYTES).saturating_add(1);
    file.take(take)
        .read_to_end(&mut bytes)
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
pub fn report_load(err: &mut impl Write, label: &str, error: &LoadError) -> u8 {
    match error {
        LoadError::Read(kind) => {
            let _ = writeln!(err, "ruster: cannot read {label}config: {}", io_code(*kind));
            EXIT_RUNTIME
        }
        LoadError::NotAFile => {
            let _ = writeln!(err, "ruster: cannot read {label}config: NOT_A_FILE");
            EXIT_RUNTIME
        }
        LoadError::Insecure(code) => {
            let _ = writeln!(
                err,
                "ruster: refused {label}config: stage=permissions code={code}"
            );
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
    let backend = match config.backend().af_xdp() {
        None => format!("backend={}", config.backend().kind().config_name()),
        Some(af_xdp) => format!(
            "backend={} ports={} umem-bytes={}",
            config.backend().kind().config_name(),
            af_xdp.ports().len(),
            af_xdp.umem_bytes()
        ),
    };
    let summary = format!(
        "valid: schema-version=1 interfaces={} routes={} neighbors={} local-ipv4={} \
         firewall-rules={} services=resolution,icmpv4-errors,nat44-udp,nat44-tcp,firewall \
         storage-bytes={} {backend}\n",
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

#[cfg(test)]
#[path = "config_cmd_tests.rs"]
mod tests;
