//! `ruster validate` and `ruster plan`.
//!
//! Both read at most [`MAX_CONFIG_BYTES`] + 1 bytes per file, parse, and
//! validate with the limits of the backend the document selects
//! ([`limits_for`]): [`PRODUCTION_VALIDATION_LIMITS`] for `af-xdp`, the
//! limits `ruster run` uses, and [`SIM_VALIDATION_LIMITS`] for `sim`, the
//! limits `run-sim` uses. They print only counts, stable codes, schema
//! field paths, and plan structure.
//! Secrets (allocator seeds, hash keys, scenario seeds) are never printed:
//! they are not part of any rendered value.

use std::fs::File;
use std::io::{self, Read, Write};
use std::num::NonZeroU64;
use std::path::Path;

use ruster_config::{
    parse, validate, BackendKindV1, PathSegment, SourcePath, ValidatedConfig, ValidatedConfigV1,
    ValidationLimits, VersionedConfig, MAX_CONFIG_BYTES, PRODUCTION_VALIDATION_LIMITS,
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
/// what the command for the document's backend accepts ([`limits_for`]):
/// a `sim` document what `run-sim` accepts, an `af-xdp` one what `ruster
/// run` accepts. Any validated `[backend]` is accepted here: `run-sim`
/// additionally refuses a non-`sim` backend (`stage=backend
/// code=UNSUPPORTED_BACKEND`) and `run` a `sim` one (`code=SIM_BACKEND`).
pub fn load(path: &Path) -> Result<ValidatedConfigV1, LoadError> {
    load_validated(path).and_then(with_bridge)
}

/// [`load`] of a document already in memory.
#[cfg(test)]
pub fn load_bytes(bytes: &[u8]) -> Result<ValidatedConfigV1, LoadError> {
    validate_bytes(bytes).and_then(with_bridge)
}

fn with_bridge(config: ValidatedConfigV1) -> Result<ValidatedConfigV1, LoadError> {
    bridge_check(&config).map_err(LoadError::Rejected)?;
    Ok(config)
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
/// `code=OWNER_UNVERIFIABLE`), the path must contain no symbolic link
/// (`code=SYMLINK_IN_PATH`), and every directory of the opened file's
/// chain must pass [`check_directory`].
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
        check_no_symlinks(path).map_err(LoadError::Insecure)?;
        check_permissions(metadata.mode(), metadata.uid(), euid).map_err(LoadError::Insecure)?;
        #[cfg(target_os = "linux")]
        check_directories(&file, euid).map_err(LoadError::Insecure)?;
        #[cfg(not(target_os = "linux"))]
        return Err(LoadError::Insecure("OWNER_UNVERIFIABLE"));
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

/// Applies [`check_directory`] to every directory from the opened file's
/// parent up to `/`. The chain comes from the open descriptor
/// (`readlink /proc/self/fd/<fd>`), so it is the directory chain of the
/// file actually read, not of whatever the path names now. Any error (a
/// deleted file's `(deleted)` target, an unreadable directory) fails closed
/// as `OWNER_UNVERIFIABLE`.
#[cfg(target_os = "linux")]
fn check_directories(file: &File, euid: u32) -> Result<(), &'static str> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let opened = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|_| "OWNER_UNVERIFIABLE")?;
    if !opened.is_absolute() {
        return Err("OWNER_UNVERIFIABLE");
    }
    for directory in opened.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(directory).map_err(|_| "OWNER_UNVERIFIABLE")?;
        if !metadata.is_dir() {
            return Err("OWNER_UNVERIFIABLE");
        }
        check_directory(metadata.mode(), metadata.uid(), euid)?;
    }
    Ok(())
}

/// Refuses a path with a symbolic link in any component (`lstat` of every
/// lexical prefix, the file itself included), so the strict checks cannot
/// be pointed elsewhere by a link. Errors fail closed.
#[cfg(unix)]
pub fn check_no_symlinks(path: &Path) -> Result<(), &'static str> {
    let mut prefix = std::path::PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        if matches!(
            component,
            std::path::Component::RootDir | std::path::Component::CurDir
        ) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&prefix).map_err(|_| "OWNER_UNVERIFIABLE")?;
        if metadata.file_type().is_symlink() {
            return Err("SYMLINK_IN_PATH");
        }
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

/// Validation limits of a parsed document, chosen by the backend it
/// selects, so `validate` and `plan` accept exactly what the command that
/// runs that backend accepts: `af-xdp` and `af-packet` (only `ruster run`
/// drives them)
/// gets [`PRODUCTION_VALIDATION_LIMITS`]; `sim`, or no `[backend]` (only
/// `run-sim` drives it), gets [`SIM_VALIDATION_LIMITS`]. A document for
/// another schema version gets the simulator's (smaller) limits; the
/// validator refuses it anyway.
pub fn limits_for(parsed: &VersionedConfig) -> ValidationLimits {
    match parsed {
        VersionedConfig::V1(config) => match config.backend.as_ref().map(|backend| backend.kind) {
            Some(BackendKindV1::AfXdp | BackendKindV1::AfPacket) => PRODUCTION_VALIDATION_LIMITS,
            Some(BackendKindV1::Sim) | None => SIM_VALIDATION_LIMITS,
        },
        _ => SIM_VALIDATION_LIMITS,
    }
}

fn validate_file(file: File) -> Result<ValidatedConfigV1, LoadError> {
    let mut bytes = Vec::new();
    let take = wide(MAX_CONFIG_BYTES).saturating_add(1);
    file.take(take)
        .read_to_end(&mut bytes)
        .map_err(|error| LoadError::Read(error.kind()))?;
    validate_bytes(&bytes)
}

/// Parses and validates one document (at most [`MAX_CONFIG_BYTES`] + 1
/// bytes already read) with the limits of [`limits_for`]. Every loader
/// of `validate`, `plan`, and `ruster run` (startup and reload) ends here.
pub fn validate_bytes(bytes: &[u8]) -> Result<ValidatedConfigV1, LoadError> {
    let parsed = parse(bytes).map_err(|diagnostic| {
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
    let limits = limits_for(&parsed);
    match validate(parsed, limits) {
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

/// Ticks above which one round-robin sweep of a resolution table is
/// reported as slow: about 1 s when `ruster run` sleeps 1 ms between idle
/// ticks (H4b review).
pub const SWEEP_SLOW_TICKS: u64 = 1_000;

/// A resolution table whose tick-budgeted round-robin sweep (retry and
/// timeout timers, Host Unreachable dispatch) takes more than
/// [`SWEEP_SLOW_TICKS`] ticks. Value-free: the table and the tick count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SweepSlow {
    pub table: &'static str,
    /// `None`: the table is never swept (a zero scan budget).
    pub ticks: Option<u64>,
}

impl std::fmt::Display for SweepSlow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "RESOLUTION_SWEEP_SLOW table={} ticks=",
            self.table
        )?;
        match self.ticks {
            Some(ticks) => write!(formatter, "{ticks}"),
            None => formatter.write_str("never"),
        }
    }
}

/// The slow sweeps of `config`: resolution states against
/// `tick.resolution-timer-scans` and failure holds against
/// `tick.failure-dispatch-scans`, as `ceil(capacity / scans)` ticks.
#[must_use]
pub fn sweep_warnings(config: &ValidatedConfigV1) -> [Option<SweepSlow>; 2] {
    let tick = config.tick();
    let Some(storage) = config.resolution().map(|resolution| resolution.storage()) else {
        return [None, None];
    };
    let slow = |table: &'static str, capacity: u32, scans: u32| {
        if capacity == 0 {
            return None;
        }
        let ticks = (scans != 0).then(|| u64::from(capacity).div_ceil(u64::from(scans)));
        ticks
            .is_none_or(|ticks| ticks > SWEEP_SLOW_TICKS)
            .then_some(SweepSlow { table, ticks })
    };
    [
        slow("states", storage.states, tick.resolution_timer_scans),
        slow(
            "failure-holds",
            storage.failure_holds,
            tick.failure_dispatch_scans,
        ),
    ]
}

/// `[fragment-tracking] ingress-share-percent` is a cap, not a
/// reservation, on the entries and on the held fragments alike: each
/// ingress may take `floor(slots × share / 100)` of either (at least one),
/// so when that times `interfaces − 1` reaches the table's size, the other
/// ingresses can take every slot and leave none to the last (a share of at
/// most 100/N leaves each an equal part, up to rounding on a small table).
/// `held` is 0 without held slots (no fragmentation). Value-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentShareOvercommitted {
    pub share_percent: u8,
    pub interfaces: usize,
    pub entries: u32,
    pub held: u32,
}

impl std::fmt::Display for FragmentShareOvercommitted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "FRAGMENT_INGRESS_SHARE_OVERCOMMITTED share-percent={} interfaces={} entries={} \
             held={}",
            self.share_percent, self.interfaces, self.entries, self.held
        )
    }
}

/// The fragment share warning of `config` (associate mode with a share
/// below 100: 100 does not partition the tables), computed on the shares
/// the table enforces (`ipv4_fragment_tracking_ingress_cap`, rounded down,
/// at least one) for the entries and for the held slots.
#[must_use]
pub fn fragment_share_warning(config: &ValidatedConfigV1) -> Option<FragmentShareOvercommitted> {
    let tracking = config.fragment_tracking();
    let share = tracking.policy()?.ingress_share_percent();
    let storage = tracking.storage()?;
    let interfaces = config.interfaces().len();
    if share >= 100 || interfaces < 2 {
        return None;
    }
    let overcommitted = |slots: u32| {
        let slots = usize::try_from(slots).unwrap_or(usize::MAX);
        slots != 0
            && ruster_core::ipv4_fragment_tracking_ingress_cap(slots, share)
                .saturating_mul(interfaces - 1)
                >= slots
    };
    (overcommitted(storage.entries) || overcommitted(storage.held)).then_some(
        FragmentShareOvercommitted {
            share_percent: share,
            interfaces,
            entries: storage.entries,
            held: storage.held,
        },
    )
}

/// `ruster validate <config>`: summary on stdout, diagnostics on stderr.
pub fn run_validate(path: &Path, out: &mut impl Write, err: &mut impl Write) -> u8 {
    validate_loaded(load(path), out, err)
}

/// The `validate` report of one [`load`] result.
pub fn validate_loaded(
    loaded: Result<ValidatedConfigV1, LoadError>,
    out: &mut impl Write,
    err: &mut impl Write,
) -> u8 {
    let config = match loaded {
        Ok(config) => config,
        Err(error) => return report_load(err, "", &error),
    };
    let rules = config
        .firewall()
        .map_or(0, |firewall| firewall.rules().len());
    let backend = match (config.backend().af_xdp(), config.backend().af_packet()) {
        (Some(af_xdp), _) => format!(
            "backend={} ports={} umem-bytes={}",
            config.backend().kind().config_name(),
            af_xdp.ports().len(),
            af_xdp.umem_bytes()
        ),
        (None, Some(af_packet)) => format!(
            "backend={} ports={} max-frame-len={} ring-bytes={}",
            config.backend().kind().config_name(),
            af_packet.ports().len(),
            af_packet.max_frame_len(),
            af_packet.ring_bytes()
        ),
        (None, None) => format!("backend={}", config.backend().kind().config_name()),
    };
    // ICMP query NAT (N5) is the one optional service.
    let icmp = if config.nat44().and_then(|nat44| nat44.icmp()).is_some() {
        "nat44-icmp,"
    } else {
        ""
    };
    let summary = format!(
        "valid: schema-version=1 interfaces={} routes={} neighbors={} local-ipv4={} \
         firewall-rules={} services=resolution,icmpv4-errors,nat44-udp,nat44-tcp,{icmp}firewall \
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
    // The sweep latency of `ruster run` (af-xdp and af-packet only: the
    // simulator has no idle backoff).
    if config.backend().kind() != BackendKindV1::Sim {
        for warning in sweep_warnings(&config).into_iter().flatten() {
            let _ = writeln!(err, "ruster: warning: {warning}");
        }
    }
    if let Some(warning) = fragment_share_warning(&config) {
        let _ = writeln!(err, "ruster: warning: {warning}");
    }
    0
}

/// `ruster plan <current> <next>`: the plan on stdout, exit 0 whenever a
/// plan is produced, including a restart-required one.
pub fn run_plan(current: &Path, next: &Path, out: &mut impl Write, err: &mut impl Write) -> u8 {
    plan_with(load, current, next, out, err)
}

/// `plan` over two documents read by `load` (next only after current).
pub fn plan_with<T: ?Sized>(
    load: impl Fn(&T) -> Result<ValidatedConfigV1, LoadError>,
    current: &T,
    next: &T,
    out: &mut impl Write,
    err: &mut impl Write,
) -> u8 {
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
