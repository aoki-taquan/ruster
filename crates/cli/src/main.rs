use std::{
    collections::VecDeque,
    env, fs,
    io::{self, Read},
    num::NonZeroU64,
    process::ExitCode,
};

use ruster_config::{
    parse, validate, Diagnostic, ValidatedBackendV1, ValidatedConfig, ValidatedConfigV1,
    ValidationCode, ValidationError, ValidationLimits, MAX_CONFIG_BYTES,
};
use ruster_control::{
    plan_full_service_v1, plan_successor, FullServicePlanInputs, PlanOutcome, PlanRestartRequired,
    SuccessorError,
};
use ruster_core::{FirewallHashKey, Nat44TcpHashKey, Nat44UdpHashKey, IPV4_MINIMUM_MTU};

#[cfg(target_os = "linux")]
use std::sync::mpsc::{self, TryRecvError};

#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(target_os = "linux")]
use std::panic::{self, AssertUnwindSafe};

#[cfg(target_os = "linux")]
mod sd_notify;

#[cfg(target_os = "linux")]
mod control_socket;

#[cfg(target_os = "linux")]
use ruster_core::{
    bind_publication_backend, GeneratedArpTrace, GeneratedIcmpv4Trace, GeneratedIcmpv4TraceSink,
    GeneratedPacketIo, GeneratedTraceSink, MonotonicMillis, PacketIo, PublicationBackendAuthority,
    PublicationBackendControl, PublicationQuiescence, PublicationQuiescenceBackend,
    PublicationQuiescenceDisposition, ResolutionFailureTrace, ResolutionFailureTraceSink,
    ResolutionTimerTrace, ResolutionTimerTraceSink, TraceEvent, TraceSink,
};
#[cfg(target_os = "linux")]
use ruster_integration::{
    activate_initial, BoundFullServicePublicationOwner, FullServiceApplyReport,
    FullServicePublicationOwner, FullServicePublishError, FullServiceRuntimeStorage,
};
#[cfg(all(target_os = "linux", test))]
use ruster_io_afpacket::AfPacketError;
#[cfg(target_os = "linux")]
use ruster_io_afpacket::{
    AfPacketIo, AfPacketPlatform, PlatformError, PortConfig, RingGeometry,
    ValidatedConfig as AfPacketValidatedConfig,
};
#[cfg(target_os = "linux")]
use ruster_io_sim::{BoundSimIoControl, BoundSimIoObservabilityControl, SimIo};
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
use ruster_io_xdp_native::{PageAlignedUmem, XdpResourcePair};
#[cfg(target_os = "linux")]
use ruster_io_xdp_native::{
    XdpAttachError, XdpAttachment, XdpRedirectProgram, XdpResource, XdpResourceBuilder, XskMap,
};
#[cfg(target_os = "linux")]
use ruster_runtime::{
    observability::{
        ObservabilityActivitySnapshot, ObservabilityRecorder, ObservabilitySnapshot, Readiness,
        DROP_REASON_SLOTS,
    },
    run_tick, PublicationOutcome, RxPhaseReport, TickBudgets, TickPhaseTrace, TickPhaseTraceSink,
};

const VALIDATION_LIMITS: ValidationLimits = ValidationLimits {
    max_slots_per_table: 1_048_576,
    max_runtime_bytes: 1 << 30,
};

// Four finite ticks cover the ingress tick and the next few logical timer
// boundaries while keeping the simulator a quick config-checking command.
const DEFAULT_SIM_TICKS: usize = 4;
const SIM_TICK_INTERVAL_MS: u64 = 1_000;

#[cfg(target_os = "linux")]
const RX_BLOCK_RETIRE_TIMEOUT_MS: u32 = 20;
#[cfg(target_os = "linux")]
const MAX_FRAME_LEN: usize = 1_514;
#[cfg(target_os = "linux")]
const RUN_TICK_IDLE_WAIT_MAX_MS: u64 = 25;
#[cfg(target_os = "linux")]
const RUN_TICK_IDLE_WAIT_MIN_MS: u64 = 1;
#[cfg(target_os = "linux")]
const OBSERVABILITY_INTERVAL_ENV: &str = "RUSTER_OBSERVABILITY_INTERVAL_SECS";
#[cfg(target_os = "linux")]
const DEFAULT_OBSERVABILITY_INTERVAL_SECS: u64 = 10;
#[cfg(target_os = "linux")]
const SHUTDOWN_RETRY_SLEEP_MS: u64 = 1;
#[cfg(target_os = "linux")]
const SHUTDOWN_RX_BUDGET: usize = 64;
#[cfg(target_os = "linux")]
// A bounded shutdown prevents a stuck kernel ring or failed completion from
// keeping the daemon alive forever without a quiescence proof.
const SHUTDOWN_QUIESCENCE_TIMEOUT_SECS: u64 = 5;

#[cfg(target_os = "linux")]
const SIGINT: std::ffi::c_int = 2;
#[cfg(target_os = "linux")]
const SIGTERM: std::ffi::c_int = 15;
#[cfg(target_os = "linux")]
const SIGHUP: std::ffi::c_int = 1;
#[cfg(target_os = "linux")]
const SIG_ERR: usize = usize::MAX;
#[cfg(target_os = "linux")]
const SC_PAGESIZE: std::ffi::c_int = 30;
#[cfg(target_os = "linux")]
const EPERM: i32 = 1;
#[cfg(target_os = "linux")]
const EACCES: i32 = 13;

#[cfg(target_os = "linux")]
static STOP_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(target_os = "linux")]
static RELOAD_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ruster: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    if let [command, path, options @ ..] = args.as_slice() {
        if command == "run-sim" {
            let ticks = parse_run_sim_options(options)?;
            return run_sim_path(path, ticks);
        }
    }

    if let [command] = args.as_slice() {
        if command == "status" {
            #[cfg(target_os = "linux")]
            {
                return control_socket::request_status();
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err("ruster status requires the Linux control socket".to_owned());
            }
        }
    }

    let (command, path) = match args.as_slice() {
        [command, path] if matches!(command.as_str(), "validate" | "plan" | "run") => {
            (command.as_str(), path.as_str())
        }
        [command] if command == "--help" || command == "-h" => {
            print_help();
            return Ok(());
        }
        _ => {
            return Err(
                "usage: ruster <validate|plan|run> <config-path> | ruster status | ruster run-sim <config-path> [--ticks <N>]"
                    .to_owned(),
            );
        }
    };

    match command {
        "validate" => validate_path(path),
        "plan" => plan_path(path),
        "run" => run_path(path),
        _ => unreachable!("argument parser admits only known commands"),
    }
}

fn validate_path(path: &str) -> Result<(), String> {
    let config = load_and_validate(path)?;
    println!(
        "configuration valid: schema=v1 interfaces={} routes={} neighbors={} runtime_bytes={}",
        config.interfaces().len(),
        config.routes().len(),
        config.neighbors().len(),
        config.storage_shape().required_bytes,
    );
    Ok(())
}

fn plan_path(path: &str) -> Result<(), String> {
    let config = load_and_validate(path)?;
    let inputs = full_service_plan_inputs()?;
    let plan = plan_full_service_v1(config, inputs)
        .map_err(|failure| format!("full-service planning failed: {:?}", failure.error()))?;
    let candidate = plan
        .into_candidate()
        .map_err(|error| format!("candidate creation failed: {error:?}"))?;
    let outcome = plan_successor(None, &candidate);
    println!(
        "cold plan: outcome={outcome:?} initial={} generation={} runtime_bytes={} interfaces={} routes={} neighbors={}",
        outcome.generation_transition().is_initial(),
        candidate.generation(),
        candidate.required_runtime_bytes(),
        candidate.interfaces().len(),
        candidate.authority().snapshot().routes().len(),
        candidate.authority().snapshot().neighbors().len(),
    );
    Ok(())
}

fn full_service_plan_inputs() -> Result<FullServicePlanInputs, String> {
    Ok(FullServicePlanInputs::new(
        NonZeroU64::new(1).expect("literal one is nonzero"),
        Nat44UdpHashKey::new(0x10, 0x11).map_err(|error| format!("UDP hash key: {error:?}"))?,
        Nat44TcpHashKey::new(0x20, 0x21).map_err(|error| format!("TCP hash key: {error:?}"))?,
        FirewallHashKey::new(0x30, 0x31)
            .map_err(|error| format!("firewall hash key: {error:?}"))?,
    ))
}

#[cfg(target_os = "linux")]
const URANDOM_PATH: &str = "/dev/urandom";

#[cfg(target_os = "linux")]
const FRESH_KEY_ATTEMPTS: usize = 16;

#[cfg(target_os = "linux")]
type HashKeyWords = (u64, u64);

#[cfg(target_os = "linux")]
const HASH_KEYS_PER_GENERATION: usize = 3;

// The generator retains the active generation and one in-flight successor while
// the successor is being planned. Once publication succeeds, the old
// generation is retired, so this remains a fixed workspace rather than a
// process-lifetime history.
#[cfg(target_os = "linux")]
const MAX_ISSUED_KEYS: usize = HASH_KEYS_PER_GENERATION * 2;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct IssuedKey {
    generation: NonZeroU64,
    words: HashKeyWords,
}

/// Mints process-local publication identities for the daemon.
///
/// The control-plane inputs are intentionally move-only, so the generator keeps
/// only the raw words it issued. This lets it reject a random collision before
/// handing a key to the planner without inspecting or copying candidate
/// authority. Only the active generation and an unpublished candidate are
/// retained. A failed candidate is removed, and a successful activation
/// retires every older generation. `/dev/urandom` is read only on the
/// reload/control path; packet processing never generates randomness.
#[cfg(target_os = "linux")]
struct PlanInputGenerator {
    entropy: fs::File,
    issued_keys: VecDeque<IssuedKey>,
    active_generation: Option<NonZeroU64>,
}

#[cfg(target_os = "linux")]
impl PlanInputGenerator {
    fn open() -> Result<Self, String> {
        let entropy = fs::File::open(URANDOM_PATH)
            .map_err(|error| format!("cannot open {URANDOM_PATH}: {error}"))?;
        Ok(Self {
            entropy,
            issued_keys: VecDeque::with_capacity(MAX_ISSUED_KEYS),
            active_generation: None,
        })
    }

    fn initial_inputs(&mut self) -> Result<FullServicePlanInputs, String> {
        self.inputs_for_generation(NonZeroU64::new(1).expect("literal one is nonzero"))
    }

    fn successor_inputs(
        &mut self,
        generation: NonZeroU64,
    ) -> Result<FullServicePlanInputs, String> {
        self.inputs_for_generation(generation)
    }

    fn inputs_for_generation(
        &mut self,
        generation: NonZeroU64,
    ) -> Result<FullServicePlanInputs, String> {
        if let Some(previous) = self
            .issued_keys
            .iter()
            .map(|issued| issued.generation)
            .max()
        {
            if generation <= previous {
                return Err(format!(
                    "publication generation {generation} is not strictly greater than issued generation {previous}"
                ));
            }
        }
        let result = (|| {
            let udp = self.fresh_key("UDP", generation)?;
            let tcp = self.fresh_key("TCP", generation)?;
            let firewall = self.fresh_key("firewall", generation)?;
            let udp = Nat44UdpHashKey::new(udp.0, udp.1)
                .map_err(|_| "generated UDP hash key was all zero".to_owned())?;
            let tcp = Nat44TcpHashKey::new(tcp.0, tcp.1)
                .map_err(|_| "generated TCP hash key was all zero".to_owned())?;
            let firewall = FirewallHashKey::new(firewall.0, firewall.1)
                .map_err(|_| "generated firewall hash key was all zero".to_owned())?;
            Ok(FullServicePlanInputs::new(generation, udp, tcp, firewall))
        })();
        if result.is_err() {
            // A failed attempt never creates a live candidate. Remove any
            // keys minted before the failure so a partial transaction cannot
            // consume the bounded active/candidate workspace.
            self.discard_generation(generation);
        }
        result
    }

    fn fresh_key(&mut self, service: &str, generation: NonZeroU64) -> Result<HashKeyWords, String> {
        if self.issued_keys.len() >= MAX_ISSUED_KEYS {
            return Err(format!(
                "cannot issue fresh {service} hash key for generation {generation}: active/candidate hash-key workspace limit {MAX_ISSUED_KEYS} reached"
            ));
        }
        for _ in 0..FRESH_KEY_ATTEMPTS {
            let mut bytes = [0_u8; 16];
            self.entropy.read_exact(&mut bytes).map_err(|error| {
                format!("cannot read fresh {service} hash key from {URANDOM_PATH}: {error}")
            })?;
            let words = (
                u64::from_le_bytes(bytes[..8].try_into().expect("first key word is 8 bytes")),
                u64::from_le_bytes(bytes[8..].try_into().expect("second key word is 8 bytes")),
            );
            if words == (0, 0) || self.issued_keys.iter().any(|issued| issued.words == words) {
                continue;
            }
            self.issued_keys.push_back(IssuedKey { generation, words });
            return Ok(words);
        }
        Err(format!(
            "could not mint a fresh {service} hash key after {FRESH_KEY_ATTEMPTS} attempts"
        ))
    }

    fn activate_generation(&mut self, generation: NonZeroU64) -> Result<(), String> {
        if let Some(active) = self.active_generation {
            if generation <= active {
                return Err(format!(
                    "cannot activate publication generation {generation} after active generation {active}"
                ));
            }
        }
        let generation_key_count = self
            .issued_keys
            .iter()
            .filter(|issued| issued.generation == generation)
            .count();
        if generation_key_count != HASH_KEYS_PER_GENERATION {
            return Err(format!(
                "cannot activate publication generation {generation}: expected {HASH_KEYS_PER_GENERATION} issued service keys, found {generation_key_count}"
            ));
        }
        if self
            .issued_keys
            .iter()
            .any(|issued| issued.generation > generation)
        {
            return Err(format!(
                "cannot activate publication generation {generation}: key workspace contains a newer generation"
            ));
        }
        // Publication has passed every activation check. The previous
        // generation can no longer be accepted as a successor because
        // publication generations are strictly increasing, so retire its
        // keys only now. During minting the old active keys stayed in the
        // workspace and prevented immediate reuse; after this point the
        // newly active generation is the only published key set retained.
        self.active_generation = Some(generation);
        self.issued_keys
            .retain(|issued| issued.generation == generation);
        Ok(())
    }

    fn discard_generation(&mut self, generation: NonZeroU64) {
        if self
            .active_generation
            .is_some_and(|active| generation.get() <= active.get())
        {
            debug_assert!(
                false,
                "active key workspace must not discard an active or older generation"
            );
            return;
        }
        self.issued_keys
            .retain(|issued| issued.generation != generation);
    }

    #[cfg(test)]
    fn from_entropy(entropy: fs::File) -> Self {
        Self {
            entropy,
            issued_keys: VecDeque::with_capacity(MAX_ISSUED_KEYS),
            active_generation: None,
        }
    }
}

#[cfg(target_os = "linux")]
fn successor_generation(current: NonZeroU64) -> Result<NonZeroU64, String> {
    current
        .get()
        .checked_add(1)
        .and_then(NonZeroU64::new)
        .ok_or_else(|| "publication generation is exhausted".to_owned())
}

/// A validated reload input kept until the active identity comparison finishes.
///
/// The source bytes are retained only on the cold reload path. They are read
/// and validated before the identity comparison, so an invalid file can never
/// be treated as an unchanged reload.
#[cfg(target_os = "linux")]
struct LoadedReloadConfig {
    source: Vec<u8>,
    config: ValidatedConfigV1,
}

/// The active configuration identity used by the daemon reload boundary.
///
/// Identity is deliberately exact source bytes, after successful parse and
/// semantic validation. This conservative rule treats formatting/comments or
/// source-order changes as a changed reload; it avoids claiming equivalence
/// that this layer cannot prove and keeps the active identity independent of
/// publication keys and runtime storage. The bytes are compared only on the
/// cold control path, never in packet processing.
#[cfg(target_os = "linux")]
struct ActiveConfigIdentity {
    source: Box<[u8]>,
}

#[cfg(target_os = "linux")]
impl ActiveConfigIdentity {
    fn from_source(source: Vec<u8>) -> Self {
        Self {
            source: source.into_boxed_slice(),
        }
    }

    fn matches(&self, source: &[u8]) -> bool {
        self.source.as_ref() == source
    }
}

/// A validated config comparison result. `Unchanged` is the reload equivalent
/// of the runtime's candidate-free `PublicationOutcome::Unchanged`: it carries
/// no candidate, key input, or storage allocation.
#[cfg(target_os = "linux")]
enum ReloadConfigPlan {
    Unchanged,
    Changed(Box<LoadedReloadConfig>),
}

#[cfg(target_os = "linux")]
fn classify_reload_config(
    active: &ActiveConfigIdentity,
    loaded: LoadedReloadConfig,
) -> ReloadConfigPlan {
    if active.matches(&loaded.source) {
        ReloadConfigPlan::Unchanged
    } else {
        ReloadConfigPlan::Changed(Box::new(loaded))
    }
}

/// Test-only wrapper that derives fresh successor inputs before planning.
///
/// Production reloads compare a validated source identity before entering this
/// helper. Tests for the changed path use it directly to retain coverage of
/// the derive-then-plan sequence.
#[cfg(all(target_os = "linux", test))]
fn prepare_successor_candidate(
    path: &str,
    generation: NonZeroU64,
    inputs: &mut PlanInputGenerator,
) -> Result<ruster_control::FullServiceCandidateV1, String> {
    let config = load_and_validate(path)?;
    let plan_inputs = inputs.successor_inputs(generation)?;
    prepare_successor_candidate_from_config(config, plan_inputs)
}

#[cfg(target_os = "linux")]
fn prepare_successor_candidate_from_config(
    config: ValidatedConfigV1,
    plan_inputs: FullServicePlanInputs,
) -> Result<ruster_control::FullServiceCandidateV1, String> {
    let plan = plan_full_service_v1(config, plan_inputs)
        .map_err(|failure| format!("full-service planning failed: {:?}", failure.error()))?;
    plan.into_candidate()
        .map_err(|error| format!("candidate creation failed: {error:?}"))
}

#[cfg(target_os = "linux")]
fn start_reload_preparation(path: &str) -> Result<ReloadPreparation, String> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let path = path.to_owned();
    std::thread::Builder::new()
        .name("ruster-reload".to_owned())
        .spawn(move || {
            let result = load_reload_config(&path);
            let _ = sender.send(result);
        })
        .map_err(|error| format!("cannot start reload worker: {error}"))?;
    Ok(ReloadPreparation::Config { result: receiver })
}

#[cfg(target_os = "linux")]
fn start_reload_candidate_preparation(
    config: ValidatedConfigV1,
    generation: NonZeroU64,
    plan_inputs: FullServicePlanInputs,
) -> Result<std::sync::mpsc::Receiver<Result<ruster_control::FullServiceCandidateV1, String>>, String>
{
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("ruster-reload-plan".to_owned())
        .spawn(move || {
            let result = prepare_successor_candidate_from_config(config, plan_inputs);
            let result = result.and_then(|candidate| {
                if candidate.generation() != generation {
                    return Err(format!(
                        "reload candidate generation {} did not match requested generation {generation}",
                        candidate.generation()
                    ));
                }
                Ok(candidate)
            });
            let _ = sender.send(result);
        })
        .map_err(|error| format!("cannot start reload planner: {error}"))?;
    Ok(receiver)
}

/// Maps the static successor plan into the reload decisions handled by the
/// daemon. The active publication is always present when this runs, so
/// `InitialActivation` and future unsupported variants are fail-closed as a
/// rejected reload rather than being sent to `run_tick` without a proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(target_os = "linux")]
enum ReloadPlanClassification {
    InPlaceEligible,
    RestartRequired(PlanRestartRequired),
    Rejected(SuccessorError),
    InitialActivation,
    Unsupported,
}

#[cfg(target_os = "linux")]
fn classify_reload_plan(outcome: &PlanOutcome) -> ReloadPlanClassification {
    match outcome {
        PlanOutcome::InitialActivation { .. } => ReloadPlanClassification::InitialActivation,
        PlanOutcome::InPlaceEligible { .. } => ReloadPlanClassification::InPlaceEligible,
        PlanOutcome::RestartRequired { reason, .. } => {
            ReloadPlanClassification::RestartRequired(*reason)
        }
        PlanOutcome::Rejected { error, .. } => ReloadPlanClassification::Rejected(*error),
        _ => ReloadPlanClassification::Unsupported,
    }
}

#[cfg(target_os = "linux")]
fn handle_reload_plan(
    candidate: ruster_control::FullServiceCandidateV1,
    outcome: PlanOutcome,
    current_generation: NonZeroU64,
    reload_observability: &mut ReloadObservability,
) -> Option<ruster_control::FullServiceCandidateV1> {
    let candidate_generation = candidate.generation();
    match classify_reload_plan(&outcome) {
        ReloadPlanClassification::InPlaceEligible => Some(candidate),
        ReloadPlanClassification::RestartRequired(reason) => {
            reload_observability.record_result(ReloadResultKind::RestartRequired);
            drop(candidate);
            println!(
                "ruster: reload result=restart-required generation={candidate_generation} reason={reason:?} action=continue-old"
            );
            None
        }
        ReloadPlanClassification::Rejected(error) => {
            reload_observability.record_result(ReloadResultKind::Rejected);
            drop(candidate);
            eprintln!(
                "ruster: reload rejected before publication generation={candidate_generation} reason={error:?}"
            );
            println!(
                "ruster: reload result=rejected generation={candidate_generation} reason={error:?} action=continue-old"
            );
            None
        }
        ReloadPlanClassification::InitialActivation | ReloadPlanClassification::Unsupported => {
            reload_observability.record_result(ReloadResultKind::Rejected);
            drop(candidate);
            eprintln!(
                "ruster: reload plan was not a supported successor of generation {current_generation}"
            );
            println!(
                "ruster: reload result=rejected generation={candidate_generation} reason=unsupported-successor-plan action=continue-old"
            );
            None
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReloadPublicationClassification {
    Applied,
    Rejected,
    RestartRequired,
    Unchanged,
    Deferred,
    BackendMismatch,
}

#[cfg(target_os = "linux")]
impl ReloadPublicationClassification {
    const fn as_result_kind(self) -> ReloadResultKind {
        match self {
            Self::Applied => ReloadResultKind::Applied,
            Self::Rejected => ReloadResultKind::Rejected,
            Self::RestartRequired => ReloadResultKind::RestartRequired,
            Self::Unchanged => ReloadResultKind::Unchanged,
            Self::Deferred => ReloadResultKind::Deferred,
            Self::BackendMismatch => ReloadResultKind::BackendMismatch,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReloadResultKind {
    Applied,
    Rejected,
    RestartRequired,
    Unchanged,
    Deferred,
    BackendMismatch,
}

#[cfg(target_os = "linux")]
impl ReloadResultKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::RestartRequired => "restart-required",
            Self::Unchanged => "unchanged",
            Self::Deferred => "deferred",
            Self::BackendMismatch => "backend-mismatch",
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ReloadObservability {
    requests: u64,
    results: u64,
    applied: u64,
    rejected: u64,
    restart_required: u64,
    unchanged: u64,
    deferred: u64,
    backend_mismatch: u64,
    last_result: Option<ReloadResultKind>,
}

#[cfg(target_os = "linux")]
impl ReloadObservability {
    fn record_request(&mut self) {
        self.requests = self.requests.saturating_add(1);
    }

    fn record_result(&mut self, result: ReloadResultKind) {
        self.results = self.results.saturating_add(1);
        self.last_result = Some(result);
        match result {
            ReloadResultKind::Applied => self.applied = self.applied.saturating_add(1),
            ReloadResultKind::Rejected => self.rejected = self.rejected.saturating_add(1),
            ReloadResultKind::RestartRequired => {
                self.restart_required = self.restart_required.saturating_add(1)
            }
            ReloadResultKind::Unchanged => self.unchanged = self.unchanged.saturating_add(1),
            ReloadResultKind::Deferred => self.deferred = self.deferred.saturating_add(1),
            ReloadResultKind::BackendMismatch => {
                self.backend_mismatch = self.backend_mismatch.saturating_add(1)
            }
        }
    }
}

#[cfg(target_os = "linux")]
enum ReloadPreparation {
    Config {
        result: std::sync::mpsc::Receiver<Result<LoadedReloadConfig, String>>,
    },
    Candidate {
        generation: NonZeroU64,
        identity: ActiveConfigIdentity,
        result: std::sync::mpsc::Receiver<Result<ruster_control::FullServiceCandidateV1, String>>,
    },
}

#[cfg(target_os = "linux")]
fn classify_reload_publication<C, Q, A>(
    outcome: &PublicationOutcome<C, FullServicePublishError, Q, A>,
) -> ReloadPublicationClassification {
    match outcome {
        PublicationOutcome::Unchanged => ReloadPublicationClassification::Unchanged,
        PublicationOutcome::Applied(_) => ReloadPublicationClassification::Applied,
        PublicationOutcome::BackendMismatch { .. } => {
            ReloadPublicationClassification::BackendMismatch
        }
        PublicationOutcome::Deferred { .. } => ReloadPublicationClassification::Deferred,
        PublicationOutcome::Rejected { rejection, .. } => {
            if matches!(
                rejection.error(),
                FullServicePublishError::RestartRequired(_)
            ) {
                ReloadPublicationClassification::RestartRequired
            } else {
                ReloadPublicationClassification::Rejected
            }
        }
    }
}

fn validate_config_source(source: &[u8]) -> Result<ValidatedConfigV1, String> {
    let parsed = parse(source).map_err(|error| format_config_diagnostic(&error))?;
    let validated =
        validate(parsed, VALIDATION_LIMITS).map_err(|error| format_validation_error(&error))?;
    match validated {
        ValidatedConfig::V1(config) => Ok(config),
        _ => Err("configuration schema is not supported by this binary".to_owned()),
    }
}

fn load_and_validate(path: &str) -> Result<ValidatedConfigV1, String> {
    let bytes = read_config_bytes(path)?;
    validate_config_source(&bytes)
}

#[cfg(target_os = "linux")]
fn load_reload_config(path: &str) -> Result<LoadedReloadConfig, String> {
    let source = read_config_bytes(path)?;
    let config = validate_config_source(&source)?;
    Ok(LoadedReloadConfig { source, config })
}

fn read_config_bytes(path: &str) -> Result<Vec<u8>, String> {
    let read_limit = MAX_CONFIG_BYTES
        .checked_add(1)
        .ok_or_else(|| "configuration size limit cannot be represented".to_owned())?;
    let read_limit_u64 = u64::try_from(read_limit)
        .map_err(|_| "configuration size limit cannot be represented".to_owned())?;
    let mut file =
        open_config_file(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    let mut bytes = Vec::with_capacity(read_limit);
    let mut chunk = [0_u8; 16 * 1024];
    #[cfg(target_os = "linux")]
    let mut blocked_since = None;

    loop {
        let remaining = read_limit - bytes.len();
        if remaining == 0 {
            break;
        }
        let chunk_len = remaining.min(chunk.len());
        match file.read(&mut chunk[..chunk_len]) {
            Ok(0) => break,
            Ok(read) => {
                bytes.extend_from_slice(&chunk[..read]);
                #[cfg(target_os = "linux")]
                {
                    blocked_since = None;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                #[cfg(target_os = "linux")]
                {
                    let blocked_at = blocked_since.get_or_insert_with(std::time::Instant::now);
                    if blocked_at.elapsed() >= CONFIG_READ_IDLE_TIMEOUT {
                        return Err(format!(
                            "configuration input stalled before EOF or size limit: {error}"
                        ));
                    }
                    std::thread::sleep(CONFIG_READ_RETRY_DELAY);
                }
                #[cfg(not(target_os = "linux"))]
                {
                    return Err(format!("configuration input is not readable: {error}"));
                }
            }
            Err(error) => return Err(format!("cannot read {path}: {error}")),
        }
    }
    debug_assert!(u64::try_from(bytes.len()).expect("buffer length fits u64") <= read_limit_u64);
    Ok(bytes)
}

#[cfg(target_os = "linux")]
const CONFIG_OPEN_NONBLOCK: i32 = 0o4000;
#[cfg(target_os = "linux")]
const CONFIG_READ_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);
#[cfg(target_os = "linux")]
const CONFIG_READ_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(1);

fn open_config_file(path: &str) -> std::io::Result<fs::File> {
    #[cfg(target_os = "linux")]
    {
        // O_NONBLOCK is passed as an open flag; the standard library performs
        // the path handling without exposing an unsafe operation here.
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(CONFIG_OPEN_NONBLOCK)
            .open(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        fs::File::open(path)
    }
}

fn format_config_diagnostic(error: &Diagnostic) -> String {
    error.to_string()
}

fn format_validation_error(error: &ValidationError) -> String {
    let path = match error.code() {
        ValidationCode::AfXdpUmem(ruster_io_xdp_native::ConfigError::InvalidFrameSize(_)) => {
            format!("{}.frame-size", error.path())
        }
        _ => error.path().to_string(),
    };
    format!(
        "configuration invalid at {path}: {}",
        validation_reason(error)
    )
}

fn validation_reason(error: &ValidationError) -> String {
    match error.code() {
        ValidationCode::InvalidSchemaVersion => "schema-version is invalid".to_owned(),
        ValidationCode::AfXdpUmem(ruster_io_xdp_native::ConfigError::InvalidFrameSize(
            frame_size,
        )) => format!("frame size {frame_size} must be a power of two"),
        ValidationCode::AfXdpUmem(_) => "AF_XDP UMEM configuration is invalid".to_owned(),
        ValidationCode::AfXdpRings(_) => "AF_XDP ring configuration is invalid".to_owned(),
        ValidationCode::AfXdpBindFlags(_) => "AF_XDP bind flags are invalid".to_owned(),
        ValidationCode::AfXdpSharedUmemUnsupported => {
            "shared AF_XDP UMEM is not supported".to_owned()
        }
        ValidationCode::AfXdpXskMapMaxEntriesZero => {
            "XSKMAP must have at least one entry".to_owned()
        }
        ValidationCode::AfXdpQueueIdOutOfRange {
            queue_id,
            max_entries,
        } => format!("queue id {queue_id} is outside XSKMAP entries 0..{max_entries}"),
        ValidationCode::AfXdpUmemLengthNotRepresentable => {
            "AF_XDP UMEM length is not representable".to_owned()
        }
        ValidationCode::AfXdpRequiresTwoResources { actual } => {
            format!("AF_XDP requires exactly two resources, got {actual}")
        }
        ValidationCode::AfXdpDuplicateResourceInterface => {
            "AF_XDP resources must use distinct interfaces".to_owned()
        }
        ValidationCode::AfXdpInterfaceNotCovered => {
            "AF_XDP resources must cover every interface".to_owned()
        }
        ValidationCode::ListTooLong => {
            bounded_reason(error, "list is too long", |limit, actual| {
                format!("list has {actual} entries; maximum is {limit}")
            })
        }
        ValidationCode::TextTooLarge => {
            bounded_reason(error, "text is too large", |limit, actual| {
                format!("text has {actual} bytes; maximum is {limit}")
            })
        }
        ValidationCode::EmptyInterfaceName => "interface name must not be empty".to_owned(),
        ValidationCode::EmptyDeviceName => "device name must not be empty".to_owned(),
        ValidationCode::DuplicateInterfaceId => "interface ids must be unique".to_owned(),
        ValidationCode::DuplicateInterfaceName => "interface names must be unique".to_owned(),
        ValidationCode::DuplicateDeviceName => "device names must be unique".to_owned(),
        ValidationCode::InvalidMac => "MAC address is invalid".to_owned(),
        ValidationCode::NonCanonicalMac => "MAC address is not canonical".to_owned(),
        ValidationCode::MacNotUnicast => "MAC address must be unicast".to_owned(),
        ValidationCode::MtuBelowIpv4Minimum => {
            format!("interface MTU must be at least {IPV4_MINIMUM_MTU} bytes")
        }
        ValidationCode::InvalidIpv4 => "IPv4 address is invalid".to_owned(),
        ValidationCode::NonCanonicalIpv4 => "IPv4 address is not canonical".to_owned(),
        ValidationCode::InvalidIpv4Prefix => "IPv4 prefix is invalid".to_owned(),
        ValidationCode::NonCanonicalIpv4Prefix => "IPv4 prefix is not canonical".to_owned(),
        ValidationCode::AddressNotHost => "IPv4 address must be a host address".to_owned(),
        ValidationCode::UnknownInterface => "interface is not declared".to_owned(),
        ValidationCode::DuplicateLocalAddress => "local IPv4 addresses must be unique".to_owned(),
        ValidationCode::DuplicateInterfaceAddress => {
            "an interface cannot have duplicate addresses".to_owned()
        }
        ValidationCode::Route(_) => "route is invalid".to_owned(),
        ValidationCode::DuplicateRoute => "routes must be unique".to_owned(),
        ValidationCode::GatewayNotHost => "route gateway must be a host address".to_owned(),
        ValidationCode::GatewayNotOnLink => "route gateway is not on the egress link".to_owned(),
        ValidationCode::DuplicateNeighbor => "neighbors must be unique".to_owned(),
        ValidationCode::NeighborNotHost => "neighbor address must be a host address".to_owned(),
        ValidationCode::NeighborNotOnLink => "neighbor is not on the interface link".to_owned(),
        ValidationCode::Forwarding(_) => "forwarding configuration is invalid".to_owned(),
        ValidationCode::Ipv4Origin(_) => "IPv4 origin policy is invalid".to_owned(),
        ValidationCode::ResolutionPolicy(_) => "resolution policy is invalid".to_owned(),
        ValidationCode::Icmpv4ErrorPolicy(_) => "ICMPv4 error policy is invalid".to_owned(),
        ValidationCode::InvalidAllocatorSeed => "allocator seed is invalid".to_owned(),
        ValidationCode::NonCanonicalAllocatorSeed => "allocator seed is not canonical".to_owned(),
        ValidationCode::Nat44RealmWithoutProtocol => "NAT44 realm requires a protocol".to_owned(),
        ValidationCode::Nat44UdpPolicy(_) => "NAT44 UDP policy is invalid".to_owned(),
        ValidationCode::Nat44UdpConfig(_) => "NAT44 UDP configuration is invalid".to_owned(),
        ValidationCode::Nat44TcpPolicy(_) => "NAT44 TCP policy is invalid".to_owned(),
        ValidationCode::Nat44TcpConfig(_) => "NAT44 TCP configuration is invalid".to_owned(),
        ValidationCode::FirewallPrefix(_) => "firewall prefix is invalid".to_owned(),
        ValidationCode::FirewallPortRange(_) => "firewall port range is invalid".to_owned(),
        ValidationCode::FirewallPolicy(_) => "firewall policy is invalid".to_owned(),
        ValidationCode::FirewallRules(_) => "firewall rules are invalid".to_owned(),
        ValidationCode::CapacityLimitExceeded => "capacity exceeds the configured limit".to_owned(),
        ValidationCode::CapacityNotRepresentable => "capacity is not representable".to_owned(),
        ValidationCode::CapacityArithmeticOverflow => "capacity arithmetic overflowed".to_owned(),
        ValidationCode::RuntimeStorageBytesExceeded => bounded_reason(
            error,
            "runtime storage exceeds the configured limit",
            |limit, actual| format!("runtime storage requires {actual} bytes; maximum is {limit}"),
        ),
        _ => "configuration value is invalid".to_owned(),
    }
}

fn bounded_reason(
    error: &ValidationError,
    fallback: &str,
    render: impl FnOnce(u64, u64) -> String,
) -> String {
    match (error.limit(), error.actual()) {
        (Some(limit), Some(actual)) => render(limit, actual),
        _ => fallback.to_owned(),
    }
}

fn print_help() {
    println!(
        "usage: ruster <validate|plan|run> <config-path> | ruster status | ruster run-sim <config-path> [--ticks <N>]"
    );
}

fn parse_run_sim_options(options: &[String]) -> Result<usize, String> {
    let mut ticks = DEFAULT_SIM_TICKS;
    let mut index = 0;
    while index < options.len() {
        if options[index] != "--ticks" {
            return Err(format!(
                "unknown run-sim option {:?}; expected --ticks <N>",
                options[index]
            ));
        }
        if index + 1 >= options.len() {
            return Err("run-sim option --ticks requires a value".to_owned());
        }
        ticks = options[index + 1]
            .parse::<usize>()
            .map_err(|error| format!("run-sim --ticks must be a positive integer: {error}"))?;
        if ticks == 0 {
            return Err("run-sim --ticks must be greater than zero".to_owned());
        }
        index += 2;
    }
    Ok(ticks)
}

#[cfg(target_os = "linux")]
fn run_path(path: &str) -> Result<(), String> {
    let observability_interval = observability_interval()?;
    let loaded = load_reload_config(path)?;
    let active_config_identity = ActiveConfigIdentity::from_source(loaded.source);
    let config = loaded.config;
    let mut input_generator = PlanInputGenerator::open()?;
    let inputs = input_generator.initial_inputs()?;
    let plan = plan_full_service_v1(config, inputs)
        .map_err(|failure| format!("full-service planning failed: {:?}", failure.error()))?;
    let candidate = plan
        .into_candidate()
        .map_err(|error| format!("candidate creation failed: {error:?}"))?;
    let backend = candidate.backend().clone();
    let (resolution_interval_ms, icmpv4_interval_ms) = {
        let authority = candidate.authority();
        (
            authority.resolution_policy().interval_ms(),
            authority.icmpv4_error_policy().interval_ms(),
        )
    };
    let mut storage = FullServiceRuntimeStorage::try_for_candidate(&candidate)
        .map_err(|error| format!("runtime storage allocation failed: {error:?}"))?;
    let publication = activate_initial(&mut storage, candidate)
        .map_err(|failure| format!("initial activation failed: {:?}", failure.error()))?;
    input_generator
        .activate_generation(publication.generation())
        .map_err(|error| format!("initial key history activation failed: {error}"))?;

    let result = match backend {
        ValidatedBackendV1::AfPacket => {
            let afpacket_config = afpacket_config(publication.interfaces())?;
            AfPacketPlatform::ensure_supported()
                .map_err(|error| format!("AF_PACKET platform validation failed: {error}"))?;
            install_signal_handlers()?;
            let io = AfPacketIo::open(afpacket_config).map_err(format_open_error)?;
            let (owner_binding, mut io) = bind_publication_backend(io)
                .map_err(|_| "publication backend binding identity exhausted".to_owned())?;
            let mut quiescence = ShutdownQuiescenceState::default();
            let mut publication =
                publication
                    .bind_backend(owner_binding, &mut io)
                    .map_err(|failure| {
                        format!("initial backend binding failed: {:?}", failure.error())
                    })?;
            let result = run_backend(
                path,
                observability_interval,
                resolution_interval_ms,
                icmpv4_interval_ms,
                input_generator,
                active_config_identity,
                &mut publication,
                &mut io,
                &mut quiescence,
                ObservabilityBackend::AfPacket,
            );
            drop(publication);
            drop(io);
            match result {
                Ok(activity) => {
                    print_shutdown_complete(activity);
                    Ok(())
                }
                Err(error) => Err(error),
            }
        }
        ValidatedBackendV1::AfXdp(backend) => {
            match panic::catch_unwind(AssertUnwindSafe(|| {
                run_xdp_backend(
                    path,
                    observability_interval,
                    resolution_interval_ms,
                    icmpv4_interval_ms,
                    input_generator,
                    active_config_identity,
                    publication,
                    backend,
                )
            })) {
                Ok(result) => result,
                Err(_) => {
                    let error =
                        "AF_XDP setup or run loop panicked; shutdown is being attempted".to_owned();
                    eprintln!("ruster: {error}");
                    Err(error)
                }
            }
        }
    };
    drop(storage);
    result
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
#[allow(
    clippy::too_many_arguments,
    reason = "the AF_XDP wrapper passes explicit lifecycle state to the shared runner"
)]
fn run_xdp_backend<'storage>(
    path: &str,
    observability_interval: std::time::Duration,
    resolution_interval_ms: u64,
    icmpv4_interval_ms: u64,
    input_generator: PlanInputGenerator,
    active_config_identity: ActiveConfigIdentity,
    publication: FullServicePublicationOwner<'storage>,
    backend: ruster_config::ValidatedAfXdpBackendV1,
) -> Result<(), String> {
    let umem_config = backend.umem();
    let umem_len = usize::try_from(umem_config.byte_len())
        .map_err(|_| "AF_XDP UMEM length does not fit usize".to_owned())?;
    let page_size = system_page_size()?;
    if umem_len % page_size != 0 {
        return Err(format!(
            "AF_XDP UMEM length {umem_len} is not a multiple of the system page size {page_size}"
        ));
    }
    let mut first_umem = PageAlignedUmem::for_umem(umem_config)
        .map_err(|error| format!("AF_XDP first page-aligned UMEM allocation failed: {error:?}"))?;
    let mut second_umem = PageAlignedUmem::for_umem(umem_config)
        .map_err(|error| format!("AF_XDP second page-aligned UMEM allocation failed: {error:?}"))?;
    let setup = match build_xdp_setup(
        first_umem.as_mut_slice(),
        second_umem.as_mut_slice(),
        umem_len,
        backend.resources(),
        &backend,
    ) {
        Ok(setup) => setup,
        Err(error) => {
            eprintln!("ruster: {error}");
            // The setup guard has already detached/closed every partial cold
            // owner before these page-aligned UMEM mappings are dropped.
            return Err(error);
        }
    };
    let (pair, mut xdp_owner) = setup.into_parts();
    let mut quiescence = ShutdownQuiescenceState::default();
    let (owner_binding, mut io) = match bind_publication_backend(pair) {
        Ok(bound) => bound,
        Err(_) => {
            let error = "publication backend binding identity exhausted".to_owned();
            let cleanup_result =
                catch_shutdown_result("AF_XDP setup cleanup", || xdp_owner.cleanup_all());
            return match cleanup_result {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(format!("{error}; cleanup failed: {cleanup_error}")),
            };
        }
    };
    let mut publication = match publication.bind_backend(owner_binding, &mut io) {
        Ok(publication) => publication,
        Err(failure) => {
            let error = format!("initial backend binding failed: {:?}", failure.error());
            let quiescence_result =
                catch_shutdown_result("AF_XDP initial-binding publication quiescence", || {
                    wait_for_quiescence_once(&mut quiescence, &mut io)
                });
            let publication_drop_result =
                catch_shutdown_result("AF_XDP initial-binding publication drop", || {
                    drop(failure);
                    Ok(())
                });
            let io_drop_result = catch_shutdown_result("AF_XDP backend drop", || {
                drop(io);
                Ok(())
            });
            let cold_cleanup_result =
                catch_shutdown_result("AF_XDP initial-binding cold cleanup", || {
                    xdp_owner.cleanup_all()
                });
            let cleanup_result = merge_unit_results(
                quiescence_result,
                merge_unit_results(
                    publication_drop_result,
                    merge_unit_results(io_drop_result, cold_cleanup_result),
                ),
            );
            return match cleanup_result {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(format!("{error}; cleanup failed: {cleanup_error}")),
            };
        }
    };

    // Keep both the publication and the bound backend alive outside this
    // catch. If control-socket setup or any loop-adjacent code panics, the
    // common cleanup below can still drain the authoritative pair before
    // detaching the links.
    let run_result = match panic::catch_unwind(AssertUnwindSafe(|| {
        run_backend(
            path,
            observability_interval,
            resolution_interval_ms,
            icmpv4_interval_ms,
            input_generator,
            active_config_identity,
            &mut publication,
            &mut io,
            &mut quiescence,
            ObservabilityBackend::Xdp,
        )
    })) {
        Ok(result) => result,
        Err(_) => {
            let error = "AF_XDP setup or run loop panicked; shutdown is being attempted".to_owned();
            eprintln!("ruster: {error}");
            Err(error)
        }
    };

    // `run_backend` owns the normal shutdown wait. This fallback only performs
    // it when the common runner panicked before entering its ordered shutdown
    // section. The shared state reuses the same deadline and records an
    // attempted wait, so this block cannot extend the shutdown timeout.
    let quiescence_result = catch_shutdown_result("AF_XDP publication quiescence", || {
        wait_for_quiescence_once(&mut quiescence, &mut io)
    });
    let publication_drop_result = catch_shutdown_result("AF_XDP publication drop", || {
        drop(publication);
        Ok(())
    });
    let io_drop_result = catch_shutdown_result("AF_XDP backend drop", || {
        drop(io);
        Ok(())
    });
    let cold_cleanup_result =
        catch_shutdown_result("AF_XDP cold cleanup", || xdp_owner.cleanup_all());
    let result = match merge_backend_result(
        run_result,
        merge_unit_results(
            quiescence_result,
            merge_unit_results(
                publication_drop_result,
                merge_unit_results(io_drop_result, cold_cleanup_result),
            ),
        ),
    ) {
        Ok(activity) => catch_shutdown_result("shutdown completion message", || {
            print_shutdown_complete(activity);
            Ok(())
        }),
        Err(error) => Err(error),
    };
    // Both resources have been dropped with `io` before the borrowed UMEM
    // owners leave scope. Their mappings are backend-owned and page-aligned;
    // PageAlignedUmem's Drop is the final fallback after explicit cold cleanup.
    let first_umem_result = catch_shutdown_result("first AF_XDP UMEM unmap", || {
        drop(first_umem);
        Ok(())
    });
    let second_umem_result = catch_shutdown_result("second AF_XDP UMEM unmap", || {
        drop(second_umem);
        Ok(())
    });
    merge_unit_results(
        result,
        merge_unit_results(first_umem_result, second_umem_result),
    )
}

#[cfg(all(
    target_os = "linux",
    not(all(target_arch = "x86_64", target_pointer_width = "64"))
))]
#[allow(
    clippy::too_many_arguments,
    reason = "the unsupported AF_XDP wrapper mirrors the shared runner signature"
)]
fn run_xdp_backend<'storage>(
    _path: &str,
    _observability_interval: std::time::Duration,
    _resolution_interval_ms: u64,
    _icmpv4_interval_ms: u64,
    _input_generator: PlanInputGenerator,
    _active_config_identity: ActiveConfigIdentity,
    _publication: FullServicePublicationOwner<'storage>,
    _backend: ruster_config::ValidatedAfXdpBackendV1,
) -> Result<(), String> {
    Err("AF_XDP live backend requires 64-bit x86 Linux".to_owned())
}

#[cfg(target_os = "linux")]
struct XdpColdOwner {
    attachments: Vec<XdpAttachment>,
    programs: Vec<XdpRedirectProgram>,
    maps: Vec<XskMap>,
}

#[cfg(target_os = "linux")]
impl XdpColdOwner {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            attachments: Vec::with_capacity(capacity),
            programs: Vec::with_capacity(capacity),
            maps: Vec::with_capacity(capacity),
        }
    }

    fn push(&mut self, map: XskMap, program: XdpRedirectProgram, attachment: XdpAttachment) {
        self.maps.push(map);
        self.programs.push(program);
        self.attachments.push(attachment);
    }

    fn detach(&mut self) -> Result<(), String> {
        let mut first_error = None;
        for attachment in &mut self.attachments {
            let result = catch_shutdown_result("AF_XDP program detach", || {
                attachment.detach().map_err(|error| format!("{error:?}"))
            });
            if let Err(error) = result {
                let message = format!("AF_XDP program detach failed: {error}");
                eprintln!("ruster: {message}");
                if first_error.is_none() {
                    first_error = Some(message);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn close_program_and_map(&mut self) -> Result<(), String> {
        let mut first_error = None;
        for program in self.programs.drain(..) {
            let result = catch_shutdown_result("AF_XDP redirect program close", || {
                program.close().map_err(|error| format!("{error:?}"))
            });
            if let Err(error) = result {
                let message = format!("AF_XDP redirect program close failed: {error}");
                eprintln!("ruster: {message}");
                if first_error.is_none() {
                    first_error = Some(message);
                }
            }
        }
        for map in self.maps.drain(..) {
            let result = catch_shutdown_result("AF_XDP XSKMAP close", || {
                map.close().map_err(|error| format!("{error:?}"))
            });
            if let Err(error) = result {
                let message = format!("AF_XDP XSKMAP close failed: {error}");
                eprintln!("ruster: {message}");
                if first_error.is_none() {
                    first_error = Some(message);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn cleanup_all(&mut self) -> Result<(), String> {
        merge_unit_results(self.detach(), self.close_program_and_map())
    }
}

#[cfg(target_os = "linux")]
impl Drop for XdpColdOwner {
    fn drop(&mut self) {
        // Explicit callers use `cleanup_all` and observe its errors. This
        // fallback is still an explicit retry for unwind/setup-failure paths;
        // it is not the only detach attempt.
        if let Err(error) =
            catch_shutdown_result("AF_XDP cleanup detach during Drop", || self.detach())
        {
            eprintln!("ruster: AF_XDP cleanup detach failed during Drop: {error}");
        }
        if let Err(error) = catch_shutdown_result("AF_XDP cleanup close during Drop", || {
            self.close_program_and_map()
        }) {
            eprintln!("ruster: AF_XDP cleanup close failed during Drop: {error}");
        }
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
struct XdpSetupGuard<'umem> {
    resources: Option<Vec<XdpResource<'umem>>>,
    pair: Option<XdpResourcePair<'umem>>,
    cold: Option<XdpColdOwner>,
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
impl<'umem> XdpSetupGuard<'umem> {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            resources: Some(Vec::with_capacity(capacity)),
            pair: None,
            cold: Some(XdpColdOwner::with_capacity(capacity)),
        }
    }

    fn push(
        &mut self,
        resource: XdpResource<'umem>,
        map: XskMap,
        program: XdpRedirectProgram,
        attachment: XdpAttachment,
    ) {
        self.resources
            .as_mut()
            .expect("live AF_XDP setup resources")
            .push(resource);
        self.cold
            .as_mut()
            .expect("live AF_XDP setup owner")
            .push(map, program, attachment);
    }

    fn into_parts(mut self) -> (XdpResourcePair<'umem>, XdpColdOwner) {
        (
            self.pair
                .take()
                .expect("AF_XDP setup pair is present on success"),
            self.cold
                .take()
                .expect("AF_XDP setup owner is present on success"),
        )
    }

    fn fail(mut self, error: String) -> String {
        let cleanup_result = self.cleanup();
        match cleanup_result {
            Ok(()) => error,
            Err(cleanup_error) => format!("{error}; cleanup failed: {cleanup_error}"),
        }
    }

    fn cleanup(&mut self) -> Result<(), String> {
        let detach_result = catch_shutdown_result("AF_XDP setup detach", || {
            self.cold.as_mut().map_or(Ok(()), XdpColdOwner::detach)
        });
        let pair_drop_result = catch_shutdown_result("AF_XDP setup pair drop", || {
            drop(self.pair.take());
            Ok(())
        });
        let resource_drop_result = catch_shutdown_result("AF_XDP setup resource drop", || {
            drop(self.resources.take());
            Ok(())
        });
        let close_result = catch_shutdown_result("AF_XDP setup program/map close", || {
            self.cold
                .as_mut()
                .map_or(Ok(()), XdpColdOwner::close_program_and_map)
        });
        merge_unit_results(
            detach_result,
            merge_unit_results(
                pair_drop_result,
                merge_unit_results(resource_drop_result, close_result),
            ),
        )
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
impl Drop for XdpSetupGuard<'_> {
    fn drop(&mut self) {
        if let Err(error) =
            catch_shutdown_result("AF_XDP setup cleanup during Drop", || self.cleanup())
        {
            eprintln!("ruster: AF_XDP setup cleanup failed during unwind: {error}");
        }
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn build_xdp_setup<'umem>(
    first_memory: &'umem mut [u8],
    second_memory: &'umem mut [u8],
    umem_len: usize,
    resource_specs: &[ruster_config::ValidatedAfXdpResourceV1],
    backend: &ruster_config::ValidatedAfXdpBackendV1,
) -> Result<XdpSetupGuard<'umem>, String> {
    let mut setup = XdpSetupGuard::with_capacity(resource_specs.len());
    let result = build_xdp_setup_transaction(
        &mut setup,
        first_memory,
        second_memory,
        umem_len,
        resource_specs,
        backend,
    );
    match result {
        Ok(()) => Ok(setup),
        Err(error) => Err(setup.fail(error)),
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn build_xdp_setup_transaction<'umem>(
    setup: &mut XdpSetupGuard<'umem>,
    first_memory: &'umem mut [u8],
    second_memory: &'umem mut [u8],
    umem_len: usize,
    resource_specs: &[ruster_config::ValidatedAfXdpResourceV1],
    backend: &ruster_config::ValidatedAfXdpBackendV1,
) -> Result<(), String> {
    install_signal_handlers()?;
    if resource_specs.len() != 2 {
        return Err(format!(
            "AF_XDP resource pair requires exactly two resources, got {}",
            resource_specs.len()
        ));
    }

    if first_memory.len() != umem_len || second_memory.len() != umem_len {
        return Err(format!(
            "AF_XDP page-aligned UMEM length mismatch: first={} second={} expected={umem_len}",
            first_memory.len(),
            second_memory.len(),
        ));
    }

    let first = build_xdp_resource(first_memory, &resource_specs[0], backend)?;
    let first_map = XskMap::new(backend.xskmap_max_entries())
        .map_err(|error| format!("AF_XDP first XSKMAP creation failed: {error:?}"))?;
    first_map
        .register(&first)
        .map_err(|error| format!("AF_XDP first XSKMAP registration failed: {error:?}"))?;
    let first_program = first_map
        .load_redirect_program()
        .map_err(|error| format!("AF_XDP first redirect program load failed: {error:?}"))?;
    let first_attachment = first_program
        .attach_with_mode(first.ifindex(), backend.attach_mode())
        .map_err(|error: XdpAttachError| {
            format!("AF_XDP first program attachment failed: {error:?}")
        })?;
    setup.push(first, first_map, first_program, first_attachment);

    let second = build_xdp_resource(second_memory, &resource_specs[1], backend)?;
    let second_map = XskMap::new(backend.xskmap_max_entries())
        .map_err(|error| format!("AF_XDP second XSKMAP creation failed: {error:?}"))?;
    second_map
        .register(&second)
        .map_err(|error| format!("AF_XDP second XSKMAP registration failed: {error:?}"))?;
    let second_program = second_map
        .load_redirect_program()
        .map_err(|error| format!("AF_XDP second redirect program load failed: {error:?}"))?;
    let second_attachment = second_program
        .attach_with_mode(second.ifindex(), backend.attach_mode())
        .map_err(|error: XdpAttachError| {
            format!("AF_XDP second program attachment failed: {error:?}")
        })?;
    setup.push(second, second_map, second_program, second_attachment);

    let mut resources = setup
        .resources
        .take()
        .expect("AF_XDP setup resources are present before pair assembly");
    let second = resources
        .pop()
        .expect("AF_XDP pair second resource is present");
    let first = resources
        .pop()
        .expect("AF_XDP pair first resource is present");
    drop(resources);
    setup.pair = Some(
        XdpResourcePair::new(first, second)
            .map_err(|error| format!("AF_XDP resource pair creation failed: {error:?}"))?,
    );
    Ok(())
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn build_xdp_resource<'umem>(
    memory: &'umem mut [u8],
    resource_spec: &ruster_config::ValidatedAfXdpResourceV1,
    backend: &ruster_config::ValidatedAfXdpBackendV1,
) -> Result<XdpResource<'umem>, String> {
    let if_index = interface_index(resource_spec.device())?;
    let resource_builder = XdpResourceBuilder::new(
        backend.umem(),
        backend.rings(),
        if_index,
        resource_spec.queue_id(),
    )
    .map_err(|error| format!("AF_XDP resource builder failed: {error:?}"))?
    .with_bind_flags(backend.bind_flags())
    .with_interface_id(resource_spec.interface());
    resource_builder
        .build(memory)
        .map_err(|error| format!("AF_XDP resource setup failed: {error:?}"))
}

#[cfg(target_os = "linux")]
fn merge_unit_results(first: Result<(), String>, second: Result<(), String>) -> Result<(), String> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(format!("{first}; {second}")),
    }
}

#[cfg(target_os = "linux")]
fn merge_backend_result(
    run_result: Result<ObservabilityActivitySnapshot, String>,
    cleanup_result: Result<(), String>,
) -> Result<ObservabilityActivitySnapshot, String> {
    match (run_result, cleanup_result) {
        (Ok(activity), Ok(())) => Ok(activity),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(run_error), Err(cleanup_error)) => {
            Err(format!("{run_error}; cleanup failed: {cleanup_error}"))
        }
    }
}

#[cfg(target_os = "linux")]
fn catch_shutdown_phase<T>(phase: &str, operation: impl FnOnce() -> T) -> Result<T, String> {
    match panic::catch_unwind(AssertUnwindSafe(operation)) {
        Ok(value) => Ok(value),
        Err(_) => {
            let error = format!("{phase} panicked; continuing ordered shutdown");
            eprintln!("ruster: {error}");
            Err(error)
        }
    }
}

#[cfg(target_os = "linux")]
fn catch_shutdown_result(
    phase: &str,
    operation: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    match catch_shutdown_phase(phase, operation) {
        Ok(result) => result,
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn print_shutdown_complete(activity: ObservabilityActivitySnapshot) {
    println!(
        "ruster: shutdown complete: ticks={} active_ticks={}",
        activity.ticks.get(),
        activity.active_ticks.get()
    );
}

#[cfg(target_os = "linux")]
#[allow(
    clippy::too_many_arguments,
    reason = "the backend loop keeps its lifecycle inputs explicit across static dispatch"
)]
fn run_backend<'storage, I, E>(
    path: &str,
    observability_interval: std::time::Duration,
    resolution_interval_ms: u64,
    icmpv4_interval_ms: u64,
    mut input_generator: PlanInputGenerator,
    mut active_config_identity: ActiveConfigIdentity,
    publication: &mut BoundFullServicePublicationOwner<'storage, I>,
    io: &mut ruster_core::BoundPublicationBackend<I>,
    quiescence: &mut ShutdownQuiescenceState,
    observability_backend: ObservabilityBackend,
) -> Result<ObservabilityActivitySnapshot, String>
where
    I: PacketIo<Error = E>
        + GeneratedPacketIo
        + PublicationBackendAuthority
        + PublicationQuiescenceBackend<Error = E>
        + PublicationBackendControl<Command = std::time::Duration, Response = Result<bool, E>>,
    E: std::fmt::Debug,
{
    let mut notifier = sd_notify::Notifier::from_env();
    let policy_idle_wait_max = policy_idle_wait_maximum(resolution_interval_ms, icmpv4_interval_ms);

    for interface in publication.interfaces() {
        println!(
            "ruster: bound interface name={} device={} generation={}",
            interface.name(),
            interface.device(),
            publication.generation()
        );
    }

    let start = std::time::Instant::now();
    let mut recorder: ObservabilityRecorder = ObservabilityRecorder::new();
    let mut next_observability = std::time::Instant::now() + observability_interval;
    let mut pending_candidate: Option<ruster_control::FullServiceCandidateV1> = None;
    let mut pending_identity: Option<ActiveConfigIdentity> = None;
    let mut reload_preparation: Option<ReloadPreparation> = None;
    let mut reload_observability = ReloadObservability::default();
    let loop_result = panic::catch_unwind(AssertUnwindSafe(|| -> Result<Health, String> {
        let mut control_listener = control_socket::ControlListener::open()?;
        // READY is announced only after the control socket is bound and secured,
        // so an operator never observes a ready daemon without its control plane.
        report_notify_result("READY", notifier.ready(), false);
        // Start with one quarter of the active candidate's ICMP and resolution
        // policy intervals. Their usual defaults are 100 ms and 1 s,
        // respectively. ResolutionPolicy validates intervals of at least 1 s,
        // while Icmpv4ErrorPolicy rejects only zero, so a valid custom ICMP
        // interval down to 1 ms is also honored. The notifier further clamps it
        // to one quarter of its half-WATCHDOG_USEC heartbeat cadence, while the
        // observability interval gets the same quarter bound. Those bounds are
        // combined below so idle polling remains short enough for timer work,
        // watchdog heartbeats, and output.
        let idle_wait_timeout =
            notifier.idle_wait_timeout(observability_interval, policy_idle_wait_max);
        let last_health = loop {
            let now = MonotonicMillis(
                u64::try_from(start.elapsed().as_millis())
                    .map_err(|_| "monotonic elapsed time exceeded u64 milliseconds".to_owned())?,
            );
            let configured_tick = publication.tick();
            recorder.observe_tick_budgets(TickBudgets {
                rx: usize_from_u32(configured_tick.rx),
                resolution_timer_scans: usize_from_u32(configured_tick.resolution_timer_scans),
                failure_dispatch_scans: usize_from_u32(configured_tick.failure_dispatch_scans),
                generated_arp: usize_from_u32(configured_tick.generated_arp),
                generated_icmpv4: usize_from_u32(configured_tick.generated_icmpv4),
            });
            let submitted_generation = pending_candidate
                .as_ref()
                .map(ruster_control::FullServiceCandidateV1::generation);
            let submitted_identity = pending_identity.take();
            let candidate_for_tick = pending_candidate.take();
            let reload_candidate_submitted = candidate_for_tick.is_some();
            debug_assert_eq!(
                reload_candidate_submitted,
                submitted_identity.is_some(),
                "a pending reload candidate must carry its source identity"
            );
            let report = {
                let mut trace = DaemonTrace::new(&mut recorder);
                run_tick(publication, candidate_for_tick, io, now, &mut trace)
            };
            let tick_finished_at = std::time::Instant::now();

            // This call is deliberately reachable only after run_tick has returned.
            // If the tick loop hangs inside run_tick, it never reaches a completed
            // tick and therefore cannot keep the systemd watchdog alive.
            if !stop_requested() {
                if let Some(result) = notifier.watchdog_after_tick(tick_finished_at) {
                    report_notify_result("WATCHDOG", result, true);
                }
            }
            recorder.record_tick_report(&report);
            let snapshot = publication.observability_snapshot(&mut recorder, ());
            let health = health_for_tick(snapshot.readiness, &report);
            let tick_observed_at = std::time::Instant::now();

            // Control processing is non-blocking and bounded.  status gets the
            // snapshot produced by this completed tick; reload only raises the
            // existing SIGHUP flag and is consumed by the reload path below.
            let control_result = control_listener.process(|| {
                format_observability_line(
                    &snapshot,
                    recorder.activity_snapshot(),
                    health,
                    reload_observability,
                    observability_backend,
                )
            });
            if control_result.reload_requested {
                RELOAD_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
                println!("ruster: reload requested via control socket");
            }

            if tick_observed_at >= next_observability {
                println!(
                    "{}",
                    format_observability_line(
                        &snapshot,
                        recorder.activity_snapshot(),
                        health,
                        reload_observability,
                        observability_backend,
                    )
                );
                next_observability = tick_observed_at + observability_interval;
            }

            let tick_has_work = tick_report_has_work(&report);
            if reload_candidate_submitted {
                let applied_generation = match &report.publication {
                    PublicationOutcome::Applied(applied) => Some(applied.generation()),
                    PublicationOutcome::Unchanged
                    | PublicationOutcome::Rejected { .. }
                    | PublicationOutcome::Deferred { .. }
                    | PublicationOutcome::BackendMismatch { .. } => None,
                };
                pending_candidate = handle_reload_publication(
                    report.publication,
                    publication.generation(),
                    &mut reload_observability,
                );
                if let Some(generation) = applied_generation {
                    let identity = submitted_identity.ok_or_else(|| {
                        "applied reload candidate was missing its config identity".to_owned()
                    })?;
                    input_generator
                        .activate_generation(generation)
                        .map_err(|error| {
                            format!("applied generation key history activation failed: {error}")
                        })?;
                    // The source identity advances only after publication and
                    // key-history activation both succeed. A deferred or
                    // rejected candidate therefore cannot change this value.
                    active_config_identity = identity;
                } else if pending_candidate.is_some() {
                    // Deferred and backend-mismatch outcomes return the exact
                    // candidate. Keep its identity paired with it for retry.
                    pending_identity = submitted_identity;
                } else if pending_candidate.is_none() {
                    if let Some(generation) = submitted_generation {
                        input_generator.discard_generation(generation);
                    }
                    drop(submitted_identity);
                }
            }

            if let Some(preparation) = reload_preparation.take() {
                match preparation {
                    ReloadPreparation::Config { result } => match result.try_recv() {
                        Ok(Ok(loaded)) => {
                            match classify_reload_config(&active_config_identity, loaded) {
                                ReloadConfigPlan::Unchanged => {
                                    record_reload_unchanged(
                                        &mut reload_observability,
                                        publication.generation(),
                                    );
                                }
                                ReloadConfigPlan::Changed(loaded) => {
                                    let current_generation = publication.generation();
                                    match successor_generation(current_generation) {
                                        Err(error) => record_reload_failure(
                                            &mut reload_observability,
                                            current_generation,
                                            &error,
                                        ),
                                        Ok(generation) => {
                                            let LoadedReloadConfig { source, config } = *loaded;
                                            match input_generator.successor_inputs(generation) {
                                                Err(error) => record_reload_failure(
                                                    &mut reload_observability,
                                                    current_generation,
                                                    &error,
                                                ),
                                                Ok(inputs) => {
                                                    match start_reload_candidate_preparation(
                                                        config, generation, inputs,
                                                    ) {
                                                        Ok(result) => {
                                                            reload_preparation = Some(
                                                        ReloadPreparation::Candidate {
                                                            generation,
                                                            identity:
                                                                ActiveConfigIdentity::from_source(
                                                                    source,
                                                                ),
                                                            result,
                                                        },
                                                    );
                                                        }
                                                        Err(error) => {
                                                            input_generator
                                                                .discard_generation(generation);
                                                            record_reload_failure(
                                                                &mut reload_observability,
                                                                current_generation,
                                                                &error,
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Ok(Err(error)) => record_reload_failure(
                            &mut reload_observability,
                            publication.generation(),
                            &error,
                        ),
                        Err(TryRecvError::Empty) => {
                            reload_preparation = Some(ReloadPreparation::Config { result });
                        }
                        Err(TryRecvError::Disconnected) => record_reload_failure(
                            &mut reload_observability,
                            publication.generation(),
                            "reload worker exited before returning a result",
                        ),
                    },
                    ReloadPreparation::Candidate {
                        generation,
                        identity,
                        result,
                    } => match result.try_recv() {
                        Ok(Ok(candidate)) => {
                            let candidate_generation = candidate.generation();
                            let static_outcome = publication.plan_successor(&candidate);
                            pending_candidate = handle_reload_plan(
                                candidate,
                                static_outcome,
                                publication.generation(),
                                &mut reload_observability,
                            );
                            if pending_candidate.is_none() {
                                input_generator.discard_generation(candidate_generation);
                            } else {
                                pending_identity = Some(identity);
                            }
                        }
                        Ok(Err(error)) => {
                            input_generator.discard_generation(generation);
                            record_reload_failure(
                                &mut reload_observability,
                                publication.generation(),
                                &error,
                            );
                        }
                        Err(TryRecvError::Empty) => {
                            reload_preparation = Some(ReloadPreparation::Candidate {
                                generation,
                                identity,
                                result,
                            });
                        }
                        Err(TryRecvError::Disconnected) => {
                            input_generator.discard_generation(generation);
                            record_reload_failure(
                                &mut reload_observability,
                                publication.generation(),
                                "reload worker exited before returning a result",
                            );
                        }
                    },
                }
            }

            // The request is consumed only after a completed tick. Config I/O,
            // validation, and full-service planning run on workers, while this thread continues
            // to call run_tick and send watchdog heartbeats.
            if !stop_requested()
                && pending_candidate.is_none()
                && reload_preparation.is_none()
                && take_reload_request()
            {
                reload_observability.record_request();
                println!("ruster: reload requested");
                if let Some(result) = notifier.watchdog_after_tick(std::time::Instant::now()) {
                    report_notify_result("WATCHDOG", result, true);
                }
                let current_generation = publication.generation();
                match start_reload_preparation(path) {
                    Ok(preparation) => reload_preparation = Some(preparation),
                    Err(error) => {
                        record_reload_failure(&mut reload_observability, current_generation, &error)
                    }
                }
                // If preparation involved enough work to reach a watchdog
                // deadline, give systemd a heartbeat before the next tick.
                if let Some(result) = notifier.watchdog_after_tick(std::time::Instant::now()) {
                    report_notify_result("WATCHDOG", result, true);
                }
            }

            // Work-producing ticks stay hot; only an idle tick enters the backend's
            // bounded RX readiness wait.
            if stop_requested() {
                break health;
            }
            if pending_candidate.is_some() || tick_has_work {
                continue;
            }

            // The command bridge keeps the descriptors and readiness state owned
            // by the bound backend. An interrupted wait returns false, then this
            // stop check immediately selects the ordered shutdown path.
            let wait_result = io.execute_backend_command(idle_wait_timeout);
            if stop_requested() {
                break health;
            }
            let _woken_by_readiness = wait_result
                .map_err(|error| format!("backend RX readiness wait failed: {error:?}"))?;
        };
        Ok(last_health)
    }));
    let (loop_result, last_health) = match loop_result {
        Ok(Ok(health)) => (Ok(()), health),
        Ok(Err(error)) => (Err(error), Health::Unavailable),
        Err(_) => {
            let error = "ruster: backend run loop panicked; shutdown is being attempted".to_owned();
            eprintln!("{error}");
            (Err(error), Health::Unavailable)
        }
    };

    // `control_listener` is scoped inside the caught loop body, so it is
    // dropped here (before this ordered shutdown section) on success, an open
    // error, or an unwind. Its Drop implementation closes clients and unlinks
    // only the pathname socket inode it originally bound.
    // Signal handlers only set the stop flag. The main thread performs the
    // protocol write after observing that flag, where it is safe to use the
    // normal socket implementation and formatting code.
    // Each shutdown phase is independently panic-contained. This keeps a
    // notification/formatting failure, a quiescence implementation panic, or
    // a retired-candidate destructor panic from bypassing the later phases.
    let stopping_result = catch_shutdown_result("systemd STOPPING notification", || {
        report_notify_result("STOPPING", notifier.stopping(), false);
        Ok(())
    });
    let stop_message_result = catch_shutdown_result("shutdown progress message", || {
        println!("ruster: stop requested; waiting for publication quiescence");
        Ok(())
    });
    // This is the single normal shutdown wait for the whole backend lifetime.
    // The AF_XDP wrapper receives the same state and can therefore fall back
    // only when this ordered section was never reached.
    let quiescence_result = catch_shutdown_result("backend publication quiescence", || {
        wait_for_quiescence_once(quiescence, io)
    });
    let final_observability_result =
        catch_shutdown_result("final observability publication", || {
            let final_snapshot = publication.observability_snapshot(&mut recorder, ());
            println!(
                "{}",
                format_observability_line(
                    &final_snapshot,
                    recorder.activity_snapshot(),
                    last_health,
                    reload_observability,
                    observability_backend,
                )
            );
            Ok(())
        });
    // `wait_for_quiescence` has completed the backend-authoritative check.
    // Release any candidate or worker receiver before tearing down the active
    // publication, backend, and its external runtime storage.
    let retired_values_result = catch_shutdown_result("retired publication values", || {
        drop(pending_candidate.take());
        drop(pending_identity.take());
        drop(reload_preparation.take());
        Ok(())
    });
    let activity = recorder.activity_snapshot();
    let shutdown_result = merge_unit_results(
        stopping_result,
        merge_unit_results(
            stop_message_result,
            merge_unit_results(
                quiescence_result,
                merge_unit_results(final_observability_result, retired_values_result),
            ),
        ),
    );
    merge_backend_result(loop_result.map(|()| activity), shutdown_result)
}

#[cfg(not(target_os = "linux"))]
fn run_path(_path: &str) -> Result<(), String> {
    Err("ruster run requires Linux AF_PACKET support".to_owned())
}

#[cfg(target_os = "linux")]
struct SimIngress {
    interface: ruster_core::IfId,
    bytes: Vec<u8>,
}

#[cfg(target_os = "linux")]
struct SimScenario {
    ingress: Vec<SimIngress>,
}

#[derive(Clone, Copy)]
#[cfg(target_os = "linux")]
struct SimPath {
    destination: ruster_core::Ipv4Address,
}

#[derive(Clone, Copy)]
#[cfg(target_os = "linux")]
struct SimTransport {
    protocol: u8,
    source_port: u16,
    destination_port: u16,
    source: ruster_core::Ipv4Address,
}

#[derive(Clone, Copy)]
#[cfg(target_os = "linux")]
struct SimForwardingPlan {
    ingress: ruster_core::IfId,
    router_mac: [u8; 6],
    source_mac: [u8; 6],
    source: ruster_core::Ipv4Address,
    destination: ruster_core::Ipv4Address,
    protocol: u8,
    source_port: u16,
    destination_port: u16,
}

#[cfg(target_os = "linux")]
fn run_sim_path(path: &str, ticks: usize) -> Result<(), String> {
    let config = load_and_validate(path)?;
    let inputs = full_service_plan_inputs()?;
    let plan = plan_full_service_v1(config, inputs)
        .map_err(|failure| format!("full-service planning failed: {:?}", failure.error()))?;
    let candidate = plan
        .into_candidate()
        .map_err(|error| format!("candidate creation failed: {error:?}"))?;
    let scenario = build_sim_scenario(&candidate);
    let mut storage = FullServiceRuntimeStorage::try_for_candidate(&candidate)
        .map_err(|error| format!("runtime storage allocation failed: {error:?}"))?;
    let publication = activate_initial(&mut storage, candidate)
        .map_err(|failure| format!("initial activation failed: {:?}", failure.error()))?;
    let (owner_binding, mut io) = bind_publication_backend(SimIo::new())
        .map_err(|_| "publication backend binding identity exhausted".to_owned())?;
    let mut publication = publication
        .bind_backend(owner_binding, &mut io)
        .map_err(|failure| format!("initial backend binding failed: {:?}", failure.error()))?;

    install_signal_handlers()?;
    println!(
        "ruster: run-sim started generation={} ticks={} ingress_frames={}",
        publication.generation(),
        ticks,
        scenario.ingress.len()
    );

    let mut recorder: ObservabilityRecorder = ObservabilityRecorder::new();
    let mut last_health = Health::Healthy;
    let mut internal_error = None;
    let mut scenario = scenario;

    for tick_index in 0..ticks {
        if stop_requested() {
            break;
        }
        let now = sim_tick_time(tick_index)?;
        let configured_tick = publication.tick();
        recorder.observe_tick_budgets(TickBudgets {
            rx: usize_from_u32(configured_tick.rx),
            resolution_timer_scans: usize_from_u32(configured_tick.resolution_timer_scans),
            failure_dispatch_scans: usize_from_u32(configured_tick.failure_dispatch_scans),
            generated_arp: usize_from_u32(configured_tick.generated_arp),
            generated_icmpv4: usize_from_u32(configured_tick.generated_icmpv4),
        });

        if tick_index == 0 {
            for ingress in scenario.ingress.drain(..) {
                io.inject(ingress.interface, ingress.bytes);
            }
        }

        let report = {
            let mut trace = DaemonTrace::new(&mut recorder);
            run_tick(&mut publication, None, &mut io, now, &mut trace)
        };
        let tick_failed = sim_tick_has_internal_error(&report);
        recorder.record_tick_report(&report);
        let snapshot = publication.observability_snapshot(&mut recorder, ());
        last_health = health_for_tick(snapshot.readiness, &report);
        drain_sim_backend(&mut io);

        if tick_failed {
            internal_error = Some("simulation tick encountered an internal runtime error");
            break;
        }
    }

    if stop_requested() {
        println!("ruster: stop requested; finishing simulated publication");
    }

    let mut shutdown_error = io
        .retire_pending_rx()
        .err()
        .map(|error| format!("simulator could not retire pending RX ownership: {error:?}"));
    if shutdown_error.is_none() {
        shutdown_error = match io.try_publication_quiescence() {
            Ok(guard) => {
                drop(guard);
                None
            }
            Err(error) => Some(format!("simulator quiescence check failed: {error:?}")),
        };
    }

    let final_snapshot = publication.observability_snapshot(&mut recorder, ());
    println!(
        "{}",
        format_observability_line(
            &final_snapshot,
            recorder.activity_snapshot(),
            last_health,
            ReloadObservability::default(),
            ObservabilityBackend::Sim,
        )
    );
    let activity = recorder.activity_snapshot();

    drop(publication);
    drop(io);
    drop(storage);

    if let Some(error) = internal_error {
        return Err(error.to_owned());
    }
    if let Some(error) = shutdown_error {
        return Err(error);
    }

    println!(
        "ruster: shutdown complete: ticks={} active_ticks={}",
        activity.ticks.get(),
        activity.active_ticks.get()
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_sim_path(_path: &str, _ticks: usize) -> Result<(), String> {
    Err("ruster run-sim requires the Linux build in this binary".to_owned())
}

#[cfg(target_os = "linux")]
fn sim_tick_time(index: usize) -> Result<MonotonicMillis, String> {
    let index = u64::try_from(index)
        .map_err(|_| "run-sim tick index exceeded the logical clock range".to_owned())?;
    let millis = index
        .checked_mul(SIM_TICK_INTERVAL_MS)
        .ok_or_else(|| "run-sim logical clock overflowed".to_owned())?;
    Ok(MonotonicMillis(millis))
}

#[cfg(target_os = "linux")]
fn build_sim_scenario(candidate: &ruster_control::FullServiceCandidateV1) -> SimScenario {
    let authority = candidate.authority();
    let snapshot = authority.snapshot();
    let fallback_interface = candidate
        .interfaces()
        .first()
        .map(|interface| interface.id())
        .unwrap_or(ruster_core::IfId(0));
    let fallback_mac = candidate
        .interfaces()
        .first()
        .map(|interface| interface.mac().0)
        .unwrap_or([0; 6]);
    let forwarding = sim_forwarding_plan(candidate, &authority, &snapshot);
    let (ingress_interface, router_mac) = forwarding
        .map(|plan| (plan.ingress, plan.router_mac))
        .unwrap_or((fallback_interface, fallback_mac));

    let mut ingress = Vec::with_capacity(2);
    if let Some(plan) = forwarding {
        ingress.push(SimIngress {
            interface: plan.ingress,
            bytes: build_sim_transport_frame(plan),
        });
    }
    ingress.push(SimIngress {
        interface: ingress_interface,
        bytes: build_sim_unsupported_frame(router_mac),
    });
    SimScenario { ingress }
}

#[cfg(target_os = "linux")]
fn sim_forwarding_plan(
    candidate: &ruster_control::FullServiceCandidateV1,
    authority: &ruster_control::ValidatedAuthority<'_>,
    snapshot: &ruster_core::ForwardingSnapshot<'_>,
) -> Option<SimForwardingPlan> {
    let inside = authority.nat44_tcp_config().inside();
    let outside = authority.nat44_tcp_config().outside();
    if inside == outside {
        return None;
    }
    let ingress_interface = candidate
        .interfaces()
        .iter()
        .find(|interface| interface.id() == inside)?;
    let source_neighbor = snapshot
        .neighbors()
        .iter()
        .find(|neighbor| neighbor.interface == inside && sim_usable_ipv4(neighbor.target));
    let source = sim_source_address(source_neighbor, inside, snapshot.local_ipv4())?;
    let source_mac = source_neighbor
        .map(|neighbor| neighbor.mac.0)
        .unwrap_or_else(|| ingress_interface.mac().0);
    let paths = sim_paths(
        snapshot.routes(),
        snapshot.neighbors(),
        outside,
        snapshot.local_ipv4(),
    );
    if paths.is_empty() {
        return None;
    }

    let rules = authority.firewall_config().rules();
    for path in paths.iter().copied() {
        if let Some(transport) =
            sim_allowed_transport(rules, inside, outside, source, path.destination)
        {
            return Some(SimForwardingPlan {
                ingress: inside,
                router_mac: ingress_interface.mac().0,
                source_mac,
                source: transport.source,
                destination: path.destination,
                protocol: transport.protocol,
                source_port: transport.source_port,
                destination_port: transport.destination_port,
            });
        }
    }

    let path = paths[0];
    Some(SimForwardingPlan {
        ingress: inside,
        router_mac: ingress_interface.mac().0,
        source_mac,
        source,
        destination: path.destination,
        protocol: 6,
        source_port: 51_000,
        destination_port: 443,
    })
}

#[cfg(target_os = "linux")]
fn sim_source_address(
    source_neighbor: Option<&ruster_core::Neighbor>,
    ingress: ruster_core::IfId,
    local_ipv4: &[ruster_core::LocalIpv4Binding],
) -> Option<ruster_core::Ipv4Address> {
    if let Some(neighbor) = source_neighbor {
        if !local_ipv4
            .iter()
            .any(|binding| binding.address == neighbor.target)
        {
            return Some(neighbor.target);
        }
    }
    for binding in local_ipv4
        .iter()
        .filter(|binding| binding.interface == ingress)
    {
        let base = u32::from_be_bytes(binding.address.octets());
        for offset in [1_u32, 2, 3] {
            let Some(value) = base.checked_add(offset) else {
                continue;
            };
            let candidate = ruster_core::Ipv4Address::from_octets(value.to_be_bytes());
            if sim_usable_ipv4(candidate)
                && !local_ipv4.iter().any(|other| other.address == candidate)
            {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn sim_paths(
    routes: &[ruster_core::Route],
    neighbors: &[ruster_core::Neighbor],
    egress: ruster_core::IfId,
    local_ipv4: &[ruster_core::LocalIpv4Binding],
) -> Vec<SimPath> {
    let mut paths = Vec::with_capacity(routes.len());
    for route in routes.iter().copied() {
        if route.egress() != egress {
            continue;
        }
        let target = route.next_hop();
        for destination in sim_destination_candidates(route) {
            if !sim_usable_ipv4(destination)
                || local_ipv4
                    .iter()
                    .any(|binding| binding.address == destination)
                || !sim_route_matches(route, destination)
            {
                continue;
            }
            let neighbor_target = target.unwrap_or(destination);
            if !neighbors
                .iter()
                .any(|neighbor| neighbor.interface == egress && neighbor.target == neighbor_target)
            {
                continue;
            }
            let Some(selected) = sim_selected_route(routes, destination) else {
                continue;
            };
            if selected.prefix() != route.prefix()
                || selected.prefix_len() != route.prefix_len()
                || selected.egress() != route.egress()
                || selected.next_hop() != route.next_hop()
            {
                continue;
            }
            if paths
                .iter()
                .any(|path: &SimPath| path.destination == destination)
            {
                continue;
            }
            paths.push(SimPath { destination });
            break;
        }
    }
    paths
}

#[cfg(target_os = "linux")]
fn sim_destination_candidates(route: ruster_core::Route) -> [ruster_core::Ipv4Address; 3] {
    let prefix = u32::from_be_bytes(route.prefix().octets());
    let first = ruster_core::Ipv4Address::from_octets(
        (prefix | sim_host_mask(route.prefix_len())).to_be_bytes(),
    );
    let second = ruster_core::Ipv4Address::from_octets(
        (prefix | sim_host_mask(route.prefix_len()).min(2)).to_be_bytes(),
    );
    [
        first,
        second,
        ruster_core::Ipv4Address::from_octets([203, 0, 113, 5]),
    ]
}

#[cfg(target_os = "linux")]
fn sim_selected_route(
    routes: &[ruster_core::Route],
    destination: ruster_core::Ipv4Address,
) -> Option<ruster_core::Route> {
    routes
        .iter()
        .copied()
        .filter(|route| sim_route_matches(*route, destination))
        .max_by_key(|route| route.prefix_len())
}

#[cfg(target_os = "linux")]
fn sim_route_matches(route: ruster_core::Route, address: ruster_core::Ipv4Address) -> bool {
    let mask = sim_prefix_mask(route.prefix_len());
    let prefix = u32::from_be_bytes(route.prefix().octets());
    let address = u32::from_be_bytes(address.octets());
    address & mask == prefix
}

#[cfg(target_os = "linux")]
fn sim_prefix_mask(prefix_len: u8) -> u32 {
    match prefix_len {
        0 => 0,
        1..=32 => u32::MAX << (32 - u32::from(prefix_len)),
        _ => 0,
    }
}

#[cfg(target_os = "linux")]
fn sim_host_mask(prefix_len: u8) -> u32 {
    !sim_prefix_mask(prefix_len)
}

#[cfg(target_os = "linux")]
fn sim_usable_ipv4(address: ruster_core::Ipv4Address) -> bool {
    let octets = address.octets();
    address != ruster_core::Ipv4Address::from_octets([0; 4])
        && octets[0] != 0
        && octets[0] != 127
        && octets[0] < 224
        && octets != [255; 4]
}

#[cfg(target_os = "linux")]
fn sim_allowed_transport(
    rules: &[ruster_core::FirewallRule],
    ingress: ruster_core::IfId,
    egress: ruster_core::IfId,
    source: ruster_core::Ipv4Address,
    destination: ruster_core::Ipv4Address,
) -> Option<SimTransport> {
    for (protocol, protocol_number) in [
        (ruster_core::FirewallProtocol::Tcp, 6_u8),
        (ruster_core::FirewallProtocol::Udp, 17_u8),
    ] {
        for rule in rules.iter().copied() {
            if rule.action() != ruster_core::FirewallAction::AllowStateful
                || rule.protocol() != protocol
                || !sim_firewall_interface_matches(rule.ingress(), ingress)
                || !sim_firewall_interface_matches(rule.egress(), egress)
                || !sim_firewall_prefix_matches(rule.destination(), destination)
            {
                continue;
            }
            let rule_source = if sim_firewall_prefix_matches(rule.source(), source) {
                source
            } else {
                let Some(candidate) = sim_firewall_prefix_representative(rule.source()) else {
                    continue;
                };
                candidate
            };
            if !sim_usable_ipv4(rule_source) {
                continue;
            }
            return Some(SimTransport {
                protocol: protocol_number,
                source_port: sim_port(rule.source_ports(), 51_000),
                destination_port: sim_port(rule.destination_ports(), 443),
                source: rule_source,
            });
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn sim_firewall_interface_matches(
    interface: ruster_core::FirewallInterface,
    expected: ruster_core::IfId,
) -> bool {
    match interface {
        ruster_core::FirewallInterface::Any => true,
        ruster_core::FirewallInterface::Interface(id) => id == expected,
    }
}

#[cfg(target_os = "linux")]
fn sim_firewall_prefix_matches(
    prefix: ruster_core::FirewallIpv4Prefix,
    address: ruster_core::Ipv4Address,
) -> bool {
    let mask = sim_prefix_mask(prefix.prefix_len());
    let prefix = u32::from_be_bytes(prefix.address().octets());
    let address = u32::from_be_bytes(address.octets());
    address & mask == prefix
}

#[cfg(target_os = "linux")]
fn sim_firewall_prefix_representative(
    prefix: ruster_core::FirewallIpv4Prefix,
) -> Option<ruster_core::Ipv4Address> {
    let base = u32::from_be_bytes(prefix.address().octets());
    let host_mask = sim_host_mask(prefix.prefix_len());
    [
        base | host_mask.min(1),
        base | host_mask.min(2),
        u32::from_be_bytes([203, 0, 113, 5]),
    ]
    .into_iter()
    .map(|value| ruster_core::Ipv4Address::from_octets(value.to_be_bytes()))
    .find(|candidate| {
        sim_usable_ipv4(*candidate) && sim_firewall_prefix_matches(prefix, *candidate)
    })
}

#[cfg(target_os = "linux")]
fn sim_port(range: ruster_core::FirewallPortRange, preferred: u16) -> u16 {
    if range.first() <= preferred && preferred <= range.last() {
        preferred
    } else {
        range.first()
    }
}

#[cfg(target_os = "linux")]
fn build_sim_transport_frame(plan: SimForwardingPlan) -> Vec<u8> {
    let payload = b"ruster-sim";
    let transport_len = if plan.protocol == 6 {
        20
    } else {
        8 + payload.len()
    };
    let total_length = 20 + transport_len;
    let total_length = u16::try_from(total_length).expect("built-in simulation frame fits u16");
    let mut frame = Vec::with_capacity(14 + usize::from(total_length));
    frame.extend_from_slice(&plan.router_mac);
    frame.extend_from_slice(&plan.source_mac);
    frame.extend_from_slice(&ruster_core::IPV4_ETHERTYPE.to_be_bytes());

    let mut ip = [0_u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&total_length.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = plan.protocol;
    ip[12..16].copy_from_slice(&plan.source.octets());
    ip[16..20].copy_from_slice(&plan.destination.octets());
    let checksum = ruster_core::ipv4_header_checksum(&ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&ip);

    let mut transport = if plan.protocol == 6 {
        let mut segment = [0_u8; 20];
        segment[0..2].copy_from_slice(&plan.source_port.to_be_bytes());
        segment[2..4].copy_from_slice(&plan.destination_port.to_be_bytes());
        segment[4..8].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
        segment[12] = 5 << 4;
        segment[13] = 0x02;
        segment[14..16].copy_from_slice(&64_240_u16.to_be_bytes());
        segment.to_vec()
    } else {
        let length = u16::try_from(8 + payload.len()).expect("built-in UDP frame fits u16");
        let mut segment = Vec::with_capacity(usize::from(length));
        segment.extend_from_slice(&plan.source_port.to_be_bytes());
        segment.extend_from_slice(&plan.destination_port.to_be_bytes());
        segment.extend_from_slice(&length.to_be_bytes());
        segment.extend_from_slice(&0_u16.to_be_bytes());
        segment.extend_from_slice(payload);
        segment
    };
    let transport_length = u16::try_from(transport.len()).expect("transport fits u16");
    let mut pseudo = Vec::with_capacity(12 + transport.len());
    pseudo.extend_from_slice(&plan.source.octets());
    pseudo.extend_from_slice(&plan.destination.octets());
    pseudo.push(0);
    pseudo.push(plan.protocol);
    pseudo.extend_from_slice(&transport_length.to_be_bytes());
    pseudo.extend_from_slice(&transport);
    let checksum = ruster_core::internet_checksum(&pseudo);
    let checksum = if checksum == 0 { 0xffff } else { checksum };
    if plan.protocol == 6 {
        transport[16..18].copy_from_slice(&checksum.to_be_bytes());
    } else {
        transport[6..8].copy_from_slice(&checksum.to_be_bytes());
    }
    frame.extend_from_slice(&transport);
    frame
}

#[cfg(target_os = "linux")]
fn build_sim_unsupported_frame(router_mac: [u8; 6]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14);
    frame.extend_from_slice(&router_mac);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0xfe]);
    frame.extend_from_slice(&0x88b5_u16.to_be_bytes());
    frame
}

#[cfg(target_os = "linux")]
fn drain_sim_backend(io: &mut ruster_core::BoundPublicationBackend<SimIo>) {
    while io.pop_tx().is_some() {}
    while io.pop_recycled().is_some() {}
}

#[cfg(target_os = "linux")]
fn sim_tick_has_internal_error<C, E, Q, R, G, A>(
    report: &ruster_runtime::TickReport<C, E, Q, R, G, A>,
) -> bool {
    let generated_arp_failed = matches!(
        &report.generated_arp,
        ruster_runtime::PhaseReport::Failed(_)
    ) || matches!(
        &report.generated_arp,
        ruster_runtime::PhaseReport::Completed(generated)
            if matches!(
                &generated.stop,
                ruster_runtime::GeneratedArpStop::ClockRegression
                    | ruster_runtime::GeneratedArpStop::Failed(_)
                    | ruster_runtime::GeneratedArpStop::AccountingInvariantViolation(_)
            )
    );
    let generated_icmpv4_failed = matches!(
        &report.generated_icmpv4,
        ruster_runtime::PhaseReport::Failed(_)
    ) || matches!(
        &report.generated_icmpv4,
        ruster_runtime::PhaseReport::Completed(generated)
            if matches!(
                &generated.stop,
                ruster_runtime::GeneratedIcmpv4Stop::ClockRegression
                    | ruster_runtime::GeneratedIcmpv4Stop::Failed(_)
                    | ruster_runtime::GeneratedIcmpv4Stop::AccountingInvariantViolation(_)
            )
    );

    !report.active
        || !matches!(
            &report.publication,
            ruster_runtime::PublicationOutcome::Unchanged
        )
        || matches!(
            &report.rx,
            RxPhaseReport::ReceiveFailed(_) | RxPhaseReport::AccountingInvariantViolation(_)
        )
        || matches!(
            &report.resolution_timers,
            ruster_runtime::PhaseReport::Failed(_)
        )
        || matches!(
            &report.failure_dispatch,
            ruster_runtime::PhaseReport::Failed(_)
        )
        || generated_arp_failed
        || generated_icmpv4_failed
}

#[cfg(target_os = "linux")]
fn afpacket_config(
    interfaces: &[ruster_config::InterfaceBindingV1],
) -> Result<AfPacketValidatedConfig, String> {
    let page_size = system_page_size()?;
    let rx = RingGeometry {
        block_size: 4_096,
        block_count: 2,
        frame_size: 2_048,
        frame_count: 4,
        retire_timeout_ms: RX_BLOCK_RETIRE_TIMEOUT_MS,
        private_size: 0,
        feature_flags: 0,
    };
    let tx = RingGeometry {
        retire_timeout_ms: 0,
        private_size: 0,
        feature_flags: 0,
        ..rx
    };
    let mut ports = Vec::with_capacity(interfaces.len());
    for interface in interfaces {
        ports.push(PortConfig {
            interface: interface.id(),
            if_index: interface_index(interface.device())?,
            rx,
            tx,
        });
    }
    AfPacketValidatedConfig::new(&ports, page_size, MAX_FRAME_LEN)
        .map_err(|error| format!("AF_PACKET port configuration failed: {error:?}"))
}

#[cfg(target_os = "linux")]
fn interface_index(interface_name: &str) -> Result<u32, String> {
    let c_name = std::ffi::CString::new(interface_name)
        .map_err(|_| format!("interface name {interface_name:?} contains an embedded NUL"))?;
    // SAFETY: `c_name` is a live, NUL-terminated interface name and the libc
    // call only reads that string and returns its numeric ifindex.
    let if_index = unsafe { if_nametoindex(c_name.as_ptr()) };
    if if_index == 0 {
        return Err(format!(
            "cannot resolve interface {interface_name:?}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(if_index)
}

#[cfg(target_os = "linux")]
fn system_page_size() -> Result<usize, String> {
    // SAFETY: `sysconf` receives a constant and has no borrowed pointer or
    // ownership arguments.
    let page_size = unsafe { sysconf(SC_PAGESIZE) };
    if page_size <= 0 {
        return Err(format!(
            "sysconf(_SC_PAGESIZE) returned invalid value {page_size}"
        ));
    }
    usize::try_from(page_size)
        .map_err(|_| format!("sysconf(_SC_PAGESIZE) returned invalid value {page_size}"))
}

#[cfg(target_os = "linux")]
fn format_open_error(error: PlatformError) -> String {
    match error {
        PlatformError::Syscall { stage, errno }
            if matches!(errno.get(), EPERM | EACCES) => format!(
                "AF_PACKET backend open/bind failed at {stage:?}: permission denied (errno {}); root or CAP_NET_RAW is required",
                errno.get()
            ),
        error => format!("AF_PACKET backend open/bind failed: {error}"),
    }
}

#[cfg(target_os = "linux")]
fn observability_interval() -> Result<std::time::Duration, String> {
    let value = match env::var(OBSERVABILITY_INTERVAL_ENV) {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => DEFAULT_OBSERVABILITY_INTERVAL_SECS.to_string(),
        Err(error) => {
            return Err(format!("cannot read {OBSERVABILITY_INTERVAL_ENV}: {error}"));
        }
    };
    let seconds = value.parse::<u64>().map_err(|error| {
        format!("{OBSERVABILITY_INTERVAL_ENV} must be a positive integer seconds value: {error}")
    })?;
    if seconds == 0 {
        return Err(format!(
            "{OBSERVABILITY_INTERVAL_ENV} must be greater than zero"
        ));
    }
    Ok(std::time::Duration::from_secs(seconds))
}

#[cfg(target_os = "linux")]
fn usize_from_u32(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Health {
    Healthy,
    Degraded,
    Unavailable,
}

#[cfg(target_os = "linux")]
impl Health {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        }
    }
}

#[cfg(target_os = "linux")]
fn health_for_tick<C, E, Q, R, G, A>(
    readiness: Readiness,
    report: &ruster_runtime::TickReport<C, E, Q, R, G, A>,
) -> Health {
    if readiness == Readiness::Cold {
        return Health::Unavailable;
    }
    if readiness == Readiness::Degraded || !report.active {
        return Health::Degraded;
    }

    let rx_healthy = matches!(
        &report.rx,
        RxPhaseReport::Completed(batch)
            if batch.invariants_hold() && batch.completion.error.is_none()
    );
    let timers_healthy = matches!(
        &report.resolution_timers,
        ruster_runtime::PhaseReport::Completed(_)
    );
    let failure_dispatch_healthy = matches!(
        &report.failure_dispatch,
        ruster_runtime::PhaseReport::Completed(_)
    );
    let arp_healthy = matches!(
        &report.generated_arp,
        ruster_runtime::PhaseReport::Completed(generated)
            if matches!(
                &generated.stop,
                ruster_runtime::GeneratedArpStop::QueueEmpty
                    | ruster_runtime::GeneratedArpStop::BudgetExhausted { .. }
            )
    );
    let icmp_healthy = matches!(
        &report.generated_icmpv4,
        ruster_runtime::PhaseReport::Completed(generated)
            if matches!(
                &generated.stop,
                ruster_runtime::GeneratedIcmpv4Stop::QueueEmpty
                    | ruster_runtime::GeneratedIcmpv4Stop::BudgetExhausted { .. }
            )
    );

    if rx_healthy && timers_healthy && failure_dispatch_healthy && arp_healthy && icmp_healthy {
        Health::Healthy
    } else {
        Health::Degraded
    }
}

#[cfg(target_os = "linux")]
fn tick_report_has_work<C, E, Q, R, G, A>(
    report: &ruster_runtime::TickReport<C, E, Q, R, G, A>,
) -> bool {
    if !report.active
        || !matches!(
            &report.publication,
            ruster_runtime::PublicationOutcome::Unchanged
        )
    {
        return true;
    }

    let rx_work = match &report.rx {
        RxPhaseReport::Completed(batch) => {
            batch.received != 0
                || batch.tx_requested != 0
                || batch.dropped != 0
                || batch.consumed != 0
                || batch.completion.tx_requested != 0
                || batch.completion.tx_accepted != 0
                || batch.completion.tx_rejected != 0
                || batch.completion.recycled != 0
                || batch.completion.error.is_some()
        }
        RxPhaseReport::AccountingInvariantViolation(_) | RxPhaseReport::ReceiveFailed(_) => true,
        RxPhaseReport::Skipped(_) => false,
    };

    let resolution_timer_work = match &report.resolution_timers {
        ruster_runtime::PhaseReport::Completed(timer) => {
            timer.retries_queued != 0
                || timer.timed_out != 0
                || timer.no_accepted_arp_request != 0
                || timer.failures_expired != 0
        }
        ruster_runtime::PhaseReport::Failed(_) => true,
        ruster_runtime::PhaseReport::Skipped(_) => false,
    };

    let failure_dispatch_work = match &report.failure_dispatch {
        ruster_runtime::PhaseReport::Completed(dispatch) => {
            dispatch.queued != 0 || dispatch.retired != 0 || dispatch.reverse_arp_scheduled != 0
        }
        ruster_runtime::PhaseReport::Failed(_) => true,
        ruster_runtime::PhaseReport::Skipped(_) => false,
    };

    let generated_arp_work = match &report.generated_arp {
        ruster_runtime::PhaseReport::Completed(generated) => match &generated.stop {
            ruster_runtime::GeneratedArpStop::QueueEmpty => {
                generated_accounting_has_progress(&generated.accounting)
            }
            ruster_runtime::GeneratedArpStop::BudgetExhausted { pending } => {
                *pending > 0 && generated_accounting_has_progress(&generated.accounting)
            }
            ruster_runtime::GeneratedArpStop::ClockRegression
            | ruster_runtime::GeneratedArpStop::Failed(_)
            | ruster_runtime::GeneratedArpStop::AccountingInvariantViolation(_) => false,
        },
        ruster_runtime::PhaseReport::Failed(_) => true,
        ruster_runtime::PhaseReport::Skipped(_) => false,
    };

    let generated_icmpv4_work = match &report.generated_icmpv4 {
        ruster_runtime::PhaseReport::Completed(generated) => match &generated.stop {
            ruster_runtime::GeneratedIcmpv4Stop::QueueEmpty => {
                generated_accounting_has_progress(&generated.accounting)
            }
            ruster_runtime::GeneratedIcmpv4Stop::BudgetExhausted { pending } => {
                *pending > 0 && generated_accounting_has_progress(&generated.accounting)
            }
            ruster_runtime::GeneratedIcmpv4Stop::ClockRegression
            | ruster_runtime::GeneratedIcmpv4Stop::Failed(_)
            | ruster_runtime::GeneratedIcmpv4Stop::AccountingInvariantViolation(_) => false,
        },
        ruster_runtime::PhaseReport::Failed(_) => true,
        ruster_runtime::PhaseReport::Skipped(_) => false,
    };

    rx_work
        || resolution_timer_work
        || failure_dispatch_work
        || generated_arp_work
        || generated_icmpv4_work
}

#[cfg(target_os = "linux")]
fn generated_accounting_has_progress(accounting: &ruster_runtime::GeneratedAccounting) -> bool {
    accounting.allocated != 0
        || accounting.tx_requested != 0
        || accounting.cancelled != 0
        || accounting.abandoned != 0
        || accounting.tx_accepted != 0
        || accounting.tx_rejected != 0
}

#[cfg(target_os = "linux")]
fn policy_idle_wait_maximum(
    resolution_interval_ms: u64,
    icmpv4_interval_ms: u64,
) -> std::time::Duration {
    let resolution = std::time::Duration::from_millis(resolution_interval_ms);
    let icmpv4 = std::time::Duration::from_millis(icmpv4_interval_ms);
    let quarter_of_shortest_policy = resolution.min(icmpv4) / 4;
    // Waiting for at most one quarter of the shortest policy interval leaves
    // several timer opportunities before its deadline when that quarter is at
    // least 1 ms. Keep a 1 ms floor for a shorter, valid ICMP interval:
    // poll(2) accepts millisecond timeouts, and a sub-millisecond result would
    // become a zero-timeout busy poll rather than a useful bounded wait. This
    // is the smallest blocking wait and is at most one such policy interval.
    std::time::Duration::from_millis(RUN_TICK_IDLE_WAIT_MIN_MS).max(
        std::time::Duration::from_millis(RUN_TICK_IDLE_WAIT_MAX_MS).min(quarter_of_shortest_policy),
    )
}

#[cfg(target_os = "linux")]
const fn readiness_name(readiness: Readiness) -> &'static str {
    match readiness {
        Readiness::Cold => "cold",
        Readiness::Ready => "ready",
        Readiness::Degraded => "degraded",
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum ObservabilityBackend {
    AfPacket,
    Xdp,
    Sim,
}

#[cfg(target_os = "linux")]
impl ObservabilityBackend {
    const fn mode(self) -> &'static str {
        match self {
            Self::AfPacket => "af_packet_copy",
            Self::Xdp => "af_xdp",
            Self::Sim => "sim",
        }
    }

    const fn copy(self) -> bool {
        match self {
            Self::AfPacket => true,
            Self::Xdp | Self::Sim => false,
        }
    }
}

#[cfg(target_os = "linux")]
fn format_observability_line(
    snapshot: &ObservabilitySnapshot,
    activity: ObservabilityActivitySnapshot,
    health: Health,
    reload: ReloadObservability,
    backend: ObservabilityBackend,
) -> String {
    use std::fmt::Write;

    let mut line = String::with_capacity(2_048);
    write!(
        line,
        "record_type=observability config_generation={} readiness={} health={} reload_requests={} reload_results={} reload_applied={} reload_rejected={} reload_restart_required={} reload_unchanged={} reload_deferred={} reload_backend_mismatch={} reload_last_result={} ticks={} active_ticks={} forwarded={} dropped={} consumed={} tx_accepted={} tx_rejected={} firewall_processed={} firewall_denied={} firewall_processed_per_tick_high_watermark={} firewall_denied_per_tick_high_watermark={} nat44_udp_processed={} nat44_udp_denied={} nat44_udp_processed_per_tick_high_watermark={} nat44_udp_denied_per_tick_high_watermark={} nat44_tcp_processed={} nat44_tcp_denied={} nat44_tcp_processed_per_tick_high_watermark={} nat44_tcp_denied_per_tick_high_watermark={} queue_high_watermark={} queue_rx_batch_high_watermark={} queue_resolution_high_watermark={} queue_failure_high_watermark={} queue_generated_arp_high_watermark={} queue_generated_icmpv4_high_watermark={} capacity_high_watermark={} capacity_rx_high_watermark={} capacity_resolution_timer_high_watermark={} capacity_failure_dispatch_high_watermark={} capacity_generated_arp_high_watermark={} capacity_generated_icmpv4_high_watermark={} capacity_source=tick_budget backend_mode={} backend_copy={} backend_ring_capacity_high_watermark=unavailable drop_reason_total={}",
        snapshot.generation,
        readiness_name(snapshot.readiness),
        health.as_str(),
        reload.requests,
        reload.results,
        reload.applied,
        reload.rejected,
        reload.restart_required,
        reload.unchanged,
        reload.deferred,
        reload.backend_mismatch,
        reload
            .last_result
            .map(ReloadResultKind::as_str)
            .unwrap_or("none"),
        activity.ticks.get(),
        activity.active_ticks.get(),
        activity.forwarded.get(),
        activity.dropped.get(),
        activity.consumed.get(),
        activity.tx_accepted.get(),
        activity.tx_rejected.get(),
        snapshot.core.firewall.processed.get(),
        snapshot.core.firewall.denied.get(),
        snapshot
            .core
            .firewall
            .processed_per_tick_high_watermark
            .get(),
        snapshot
            .core
            .firewall
            .denied_per_tick_high_watermark
            .get(),
        snapshot.core.nat44_udp.processed.get(),
        snapshot.core.nat44_udp.denied.get(),
        snapshot
            .core
            .nat44_udp
            .processed_per_tick_high_watermark
            .get(),
        snapshot
            .core
            .nat44_udp
            .denied_per_tick_high_watermark
            .get(),
        snapshot.core.nat44_tcp.processed.get(),
        snapshot.core.nat44_tcp.denied.get(),
        snapshot
            .core
            .nat44_tcp
            .processed_per_tick_high_watermark
            .get(),
        snapshot
            .core
            .nat44_tcp
            .denied_per_tick_high_watermark
            .get(),
        activity.queue_high_watermark.get(),
        activity.rx_batch_high_watermark.get(),
        activity.resolution_queue_high_watermark.get(),
        activity.failure_queue_high_watermark.get(),
        activity.generated_arp_queue_high_watermark.get(),
        activity.generated_icmpv4_queue_high_watermark.get(),
        activity.capacity_high_watermark.get(),
        activity.capacity_rx_high_watermark.get(),
        activity.capacity_resolution_timer_high_watermark.get(),
        activity.capacity_failure_dispatch_high_watermark.get(),
        activity.capacity_generated_arp_high_watermark.get(),
        activity.capacity_generated_icmpv4_high_watermark.get(),
        backend.mode(),
        backend.copy(),
        activity.drop_reasons.total(),
    )
    .expect("writing an observability record to String cannot fail");

    for index in 0..DROP_REASON_SLOTS {
        if let Some((reason, count)) = activity.drop_reasons.entry(index) {
            write!(line, " drop_reason_{}={count}", reason.code())
                .expect("writing a drop reason to String cannot fail");
        }
    }
    line
}

#[cfg(target_os = "linux")]
fn record_reload_unchanged(
    reload_observability: &mut ReloadObservability,
    current_generation: NonZeroU64,
) {
    // This is the no-candidate reload form of
    // `PublicationOutcome::Unchanged`: use the same typed classification and
    // operator spelling while retaining the active publication untouched.
    reload_observability.record_result(ReloadResultKind::Unchanged);
    println!("ruster: reload result=unchanged generation={current_generation} action=continue-old");
}

#[cfg(target_os = "linux")]
fn record_reload_failure(
    reload_observability: &mut ReloadObservability,
    current_generation: NonZeroU64,
    error: &str,
) {
    reload_observability.record_result(ReloadResultKind::Rejected);
    eprintln!("ruster: reload failed: {error}");
    println!(
        "ruster: reload result=rejected generation={current_generation} reason={error} action=continue-old"
    );
}

#[cfg(target_os = "linux")]
fn report_notify_result(field: &str, result: sd_notify::NotifySendResult, watchdog_retry: bool) {
    let action = if watchdog_retry {
        "watchdog will retry on the next completed tick"
    } else {
        "daemon continues because systemd notification is advisory"
    };
    match result {
        sd_notify::NotifySendResult::Disabled | sd_notify::NotifySendResult::Sent => {}
        sd_notify::NotifySendResult::WouldBlock => eprintln!(
            "ruster: systemd {field} notification was not sent because the notify queue is full; {action}"
        ),
        sd_notify::NotifySendResult::Failed { errno } => eprintln!(
            "ruster: systemd {field} notification failed with errno={errno}; {action}"
        ),
    }
}

#[cfg(target_os = "linux")]
fn handle_reload_publication<Q>(
    outcome: PublicationOutcome<
        ruster_control::FullServiceCandidateV1,
        FullServicePublishError,
        Q,
        FullServiceApplyReport,
    >,
    current_generation: NonZeroU64,
    reload_observability: &mut ReloadObservability,
) -> Option<ruster_control::FullServiceCandidateV1>
where
    Q: std::fmt::Debug,
{
    let classification = classify_reload_publication(&outcome);
    reload_observability.record_result(classification.as_result_kind());
    match outcome {
        PublicationOutcome::Unchanged => {
            println!(
                "ruster: reload result=unchanged generation={current_generation} action=continue-old"
            );
            None
        }
        PublicationOutcome::Applied(report) => {
            println!(
                "ruster: reload result=applied generation={}",
                report.generation()
            );
            None
        }
        PublicationOutcome::Rejected { rejection, status } => {
            let (candidate, error) = rejection.into_parts();
            let generation = candidate.generation();
            let action = if status == ruster_runtime::ActivePublicationStatus::ContinueOldIo {
                "continue-old"
            } else {
                "old-publication-not-runnable"
            };
            if classification == ReloadPublicationClassification::RestartRequired {
                if let FullServicePublishError::RestartRequired(reason) = error {
                    println!(
                        "ruster: reload result=restart-required generation={generation} reason={reason:?} action={action}"
                    );
                } else {
                    println!(
                        "ruster: reload result=rejected generation={generation} reason={error:?} action={action}"
                    );
                }
            } else {
                println!(
                    "ruster: reload result=rejected generation={generation} reason={error:?} action={action}"
                );
            }
            if status != ruster_runtime::ActivePublicationStatus::ContinueOldIo {
                eprintln!("ruster: reload rejection left old publication status={status:?}");
            }
            // `PublicationRejection` returns the exact candidate. This
            // reload attempt is terminal for it, so dispose of it explicitly
            // after preserving the active publication.
            drop(candidate);
            None
        }
        PublicationOutcome::Deferred {
            candidate,
            error,
            disposition,
        } => {
            let generation = candidate.generation();
            eprintln!(
                "ruster: reload deferred generation={generation} error={error:?} disposition={disposition:?}"
            );
            println!(
                "ruster: reload result=deferred generation={generation} disposition={disposition:?} action={}",
                if disposition == PublicationQuiescenceDisposition::Stop {
                    "drop-candidate"
                } else {
                    "retry"
                }
            );
            if disposition == PublicationQuiescenceDisposition::Stop {
                // A terminal backend disposition cannot recover in this
                // owner/backend pair. Do not retry it forever or starve a
                // later reload; the active publication remains untouched.
                drop(candidate);
                None
            } else {
                Some(candidate)
            }
        }
        PublicationOutcome::BackendMismatch { candidate } => match candidate {
            Some(candidate) => {
                let generation = candidate.generation();
                eprintln!(
                    "ruster: reload backend mismatch; retaining candidate generation={generation}"
                );
                println!("ruster: reload result=backend-mismatch generation={generation}");
                // Keep the exact candidate so the caller can recover if the
                // bound backend is repaired or replaced by the surrounding
                // lifecycle. The daemon has no replacement seam here.
                Some(candidate)
            }
            None => {
                eprintln!("ruster: reload backend mismatch returned no candidate");
                println!("ruster: reload result=backend-mismatch");
                None
            }
        },
    }
}

#[cfg(target_os = "linux")]
fn stop_requested() -> bool {
    STOP_REQUESTED.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(target_os = "linux")]
fn take_reload_request() -> bool {
    RELOAD_REQUESTED.swap(false, std::sync::atomic::Ordering::Relaxed)
}

#[cfg(target_os = "linux")]
fn install_signal_handlers() -> Result<(), String> {
    STOP_REQUESTED.store(false, std::sync::atomic::Ordering::Relaxed);
    RELOAD_REQUESTED.store(false, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: all signal numbers are valid Linux signals and `signal_handler`
    // has the C ABI and performs only lock-free AtomicBool stores.
    let term_previous = unsafe { signal(SIGTERM, signal_handler) };
    if term_previous as usize == SIG_ERR {
        return Err(format!(
            "cannot install SIGTERM handler: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: see the SIGTERM call above; the SIGINT handler has the same
    // async-signal-safe implementation and no captured state.
    let int_previous = unsafe { signal(SIGINT, signal_handler) };
    if int_previous as usize == SIG_ERR {
        return Err(format!(
            "cannot install SIGINT handler: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: see the SIGTERM call above; SIGHUP only sets the reload flag.
    let hup_previous = unsafe { signal(SIGHUP, signal_handler) };
    if hup_previous as usize == SIG_ERR {
        return Err(format!(
            "cannot install SIGHUP handler: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
extern "C" fn signal_handler(signal: std::ffi::c_int) {
    match signal {
        SIGINT | SIGTERM => {
            STOP_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        SIGHUP => {
            RELOAD_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        _ => {}
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct ShutdownQuiescenceState {
    deadline: Option<std::time::Instant>,
    attempted: bool,
}

#[cfg(target_os = "linux")]
impl ShutdownQuiescenceState {
    // The common runner calls this when its ordered shutdown begins. A caller
    // that has to recover from a panic before then gets the same one-shot
    // state and creates the fallback deadline at that recovery point.
    fn begin_wait(&mut self) -> Option<std::time::Instant> {
        if self.attempted {
            return None;
        }
        self.attempted = true;
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(SHUTDOWN_QUIESCENCE_TIMEOUT_SECS);
        self.deadline = Some(deadline);
        Some(deadline)
    }
}

#[cfg(target_os = "linux")]
fn wait_for_quiescence_once<I, E>(
    state: &mut ShutdownQuiescenceState,
    io: &mut ruster_core::BoundPublicationBackend<I>,
) -> Result<(), String>
where
    I: PacketIo<Error = E> + PublicationBackendAuthority + PublicationQuiescenceBackend<Error = E>,
    E: std::fmt::Debug,
{
    let Some(deadline) = state.begin_wait() else {
        return Ok(());
    };
    wait_for_quiescence(io, deadline)
}

#[cfg(target_os = "linux")]
fn wait_for_quiescence<I, E>(
    io: &mut ruster_core::BoundPublicationBackend<I>,
    deadline: std::time::Instant,
) -> Result<(), String>
where
    I: PacketIo<Error = E> + PublicationBackendAuthority + PublicationQuiescenceBackend<Error = E>,
    E: std::fmt::Debug,
{
    loop {
        match io.try_publication_quiescence() {
            Ok(guard) => {
                drop(guard);
                let disposition = io.current_io_disposition();
                if disposition == PublicationQuiescenceDisposition::ContinueOldIo {
                    return Ok(());
                }
                return Err(format!(
                    "backend reported non-reusable I/O disposition during shutdown: {disposition:?}"
                ));
            }
            Err(error) => {
                let current_disposition = io.current_io_disposition();
                let error_disposition =
                    <ruster_core::BoundPublicationBackend<I> as PublicationQuiescence>::
                        quiescence_error_disposition(&error);
                if current_disposition != PublicationQuiescenceDisposition::ContinueOldIo
                    || error_disposition != PublicationQuiescenceDisposition::ContinueOldIo
                {
                    return Err(format!(
                        "backend reported non-reusable I/O disposition during shutdown: current={current_disposition:?} error={error_disposition:?}"
                    ));
                }
            }
        }

        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out after {SHUTDOWN_QUIESCENCE_TIMEOUT_SECS}s waiting for backend publication quiescence"
            ));
        }

        let current_before_receive = io.current_io_disposition();
        let completion = match PacketIo::receive(io, SHUTDOWN_RX_BUDGET) {
            Ok(batch) => ruster_core::PacketBatch::finish(batch),
            Err(error) => {
                let error_disposition =
                    <ruster_core::BoundPublicationBackend<I> as PublicationQuiescence>::
                        quiescence_error_disposition(&error);
                return Err(format!(
                    "backend shutdown drain failed while scanning completions: {error:?} (current={current_before_receive:?} error={error_disposition:?})"
                ));
            }
        };
        if !completion.invariants_hold() {
            return Err("backend shutdown drain violated batch accounting invariants".to_owned());
        }
        if let Some(error) = completion.error {
            let current_disposition = io.current_io_disposition();
            let error_disposition =
                <ruster_core::BoundPublicationBackend<I> as PublicationQuiescence>::
                    quiescence_error_disposition(&error);
            if current_disposition != PublicationQuiescenceDisposition::ContinueOldIo
                || error_disposition != PublicationQuiescenceDisposition::ContinueOldIo
            {
                return Err(format!(
                    "backend shutdown drain failed after returning ownership: {error:?} (current={current_disposition:?} error={error_disposition:?})"
                ));
            }
        }

        // `receive` performs the backend's completion/ownership housekeeping
        // before creating this batch. Its finish path then returns every
        // selected RX slot, so retrying preserves the backend's ring protocol
        // while asynchronous ownership completes.
        std::thread::sleep(std::time::Duration::from_millis(SHUTDOWN_RETRY_SLEEP_MS));
    }
}

#[cfg(target_os = "linux")]
struct DaemonTrace<'recorder> {
    recorder: &'recorder mut ObservabilityRecorder,
}

#[cfg(target_os = "linux")]
impl<'recorder> DaemonTrace<'recorder> {
    fn new(recorder: &'recorder mut ObservabilityRecorder) -> Self {
        Self { recorder }
    }
}

#[cfg(target_os = "linux")]
impl TickPhaseTraceSink for DaemonTrace<'_> {
    fn record_tick_phase(&mut self, _event: TickPhaseTrace) {}
}

#[cfg(target_os = "linux")]
impl TraceSink for DaemonTrace<'_> {
    fn record(&mut self, event: TraceEvent) {
        if let TraceEvent::Dropped { reason, .. } = event {
            self.recorder.record_drop_reason(reason);
        }
    }
}

#[cfg(target_os = "linux")]
impl ResolutionTimerTraceSink for DaemonTrace<'_> {
    fn record_resolution_timer(&mut self, _event: ResolutionTimerTrace) {}
}

#[cfg(target_os = "linux")]
impl ResolutionFailureTraceSink for DaemonTrace<'_> {
    fn record_resolution_failure(&mut self, _event: ResolutionFailureTrace) {}
}

#[cfg(target_os = "linux")]
impl GeneratedTraceSink for DaemonTrace<'_> {
    fn record_generated(&mut self, _event: GeneratedArpTrace) {}
}

#[cfg(target_os = "linux")]
impl GeneratedIcmpv4TraceSink for DaemonTrace<'_> {
    fn record_generated_icmpv4(&mut self, _event: GeneratedIcmpv4Trace) {}
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn if_nametoindex(ifname: *const std::ffi::c_char) -> u32;
    fn signal(
        signum: std::ffi::c_int,
        handler: extern "C" fn(std::ffi::c_int),
    ) -> extern "C" fn(std::ffi::c_int);
    fn sysconf(name: std::ffi::c_int) -> isize;
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::*;
    #[cfg(target_os = "linux")]
    use ruster_io_afpacket::{Errno, SyscallStage};
    #[cfg(target_os = "linux")]
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(target_os = "linux")]
    static NEXT_RELOAD_TEST_ID: AtomicU64 = AtomicU64::new(0);

    #[cfg(target_os = "linux")]
    const FULL_SERVICE_CONFIG: &str = include_str!("../../control/tests/full-service.toml");

    #[cfg(target_os = "linux")]
    fn write_reload_test_config(source: &str) -> std::path::PathBuf {
        let id = NEXT_RELOAD_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ruster-cli-reload-{}-{id}.toml",
            std::process::id()
        ));
        fs::write(&path, source).expect("reload test config must be writable");
        path
    }

    #[cfg(target_os = "linux")]
    fn write_key_entropy(words: &[HashKeyWords]) -> (fs::File, std::path::PathBuf) {
        let id = NEXT_RELOAD_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ruster-cli-key-entropy-{}-{id}.bin",
            std::process::id()
        ));
        let mut bytes = Vec::with_capacity(words.len() * 16);
        for (first, second) in words {
            bytes.extend_from_slice(&first.to_le_bytes());
            bytes.extend_from_slice(&second.to_le_bytes());
        }
        fs::write(&path, bytes).expect("key entropy fixture must be writable");
        let entropy = fs::File::open(&path).expect("key entropy fixture must be readable");
        (entropy, path)
    }

    #[cfg(target_os = "linux")]
    fn planned_test_candidate(
        source: &str,
        generation: u64,
        seed: u64,
    ) -> ruster_control::FullServiceCandidateV1 {
        let parsed = parse(source.as_bytes()).expect("reload test config must parse");
        let config =
            match validate(parsed, VALIDATION_LIMITS).expect("reload test config validates") {
                ValidatedConfig::V1(config) => config,
                _ => unreachable!("reload tests use schema V1"),
            };
        let inputs = FullServicePlanInputs::new(
            NonZeroU64::new(generation).expect("reload generation is nonzero"),
            Nat44UdpHashKey::new(seed, seed + 1).expect("reload UDP key is nonzero"),
            Nat44TcpHashKey::new(seed + 2, seed + 3).expect("reload TCP key is nonzero"),
            FirewallHashKey::new(seed + 4, seed + 5).expect("reload firewall key is nonzero"),
        );
        let plan = plan_full_service_v1(config, inputs).unwrap_or_else(|failure| {
            panic!("reload test config must plan: {:?}", failure.error())
        });
        plan.into_candidate()
            .unwrap_or_else(|error| panic!("reload test candidate must be creatable: {error:?}"))
    }

    #[cfg(target_os = "linux")]
    fn af_xdp_reload_test_source() -> String {
        let mut source = FULL_SERVICE_CONFIG.to_owned();
        source.push_str(
            r#"
[backend]
kind = "af-xdp"
xskmap-max-entries = 2
bind-flags = 8
attach-mode = "skb"

[[backend.resources]]
interface = "wan"
queue-id = 0

[[backend.resources]]
interface = "lan"
queue-id = 1

[backend.umem]
frame-count = 2
frame-size = 2048
headroom = 256
rx-frames = 1
generated-frames = 1
raw-flags = 0

[backend.rings]
fill = 4
rx = 4
tx = 4
completion = 4
"#,
        );
        source
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn af_xdp_wrapper_does_not_repeat_common_shutdown_quiescence_wait() {
        let source = include_str!("../src/main.rs");
        let wrapper = source
            .split_once("fn run_xdp_backend<'storage>(")
            .expect("the native AF_XDP wrapper must exist")
            .1;
        let common_call = wrapper
            .split_once("let run_result =")
            .expect("the AF_XDP wrapper must call the common backend runner")
            .1
            .split_once("}))")
            .expect("the common backend runner call must be panic-contained")
            .0;
        let fallback = wrapper
            .split_once("let run_result =")
            .expect("the AF_XDP wrapper must call the common backend runner")
            .1
            .split_once("let publication_drop_result")
            .expect("the AF_XDP wrapper must retain ordered cleanup")
            .0;

        assert!(
            fallback.contains("wait_for_quiescence_once"),
            "AF_XDP wrapper fallback must use the shared one-shot quiescence state"
        );
        assert!(
            common_call.contains("&mut quiescence"),
            "the common backend runner must receive the shared quiescence state"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shutdown_quiescence_state_creates_only_one_deadline() {
        let mut state = ShutdownQuiescenceState::default();
        let deadline = state
            .begin_wait()
            .expect("the first quiescence wait must create a deadline");

        assert_eq!(state.deadline, Some(deadline));
        assert!(
            state.begin_wait().is_none(),
            "a wrapper fallback must not start a second quiescence wait"
        );
        assert_eq!(state.deadline, Some(deadline));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn permission_errors_explain_raw_socket_requirement() {
        let message = format_open_error(PlatformError::Syscall {
            stage: SyscallStage::Socket,
            errno: Errno::new(EPERM),
        });
        assert!(message.contains("root or CAP_NET_RAW is required"));
        assert!(message.contains("permission denied"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_afpacket_open_reports_permission_failure_when_unprivileged() {
        let rx = RingGeometry {
            block_size: 4_096,
            block_count: 2,
            frame_size: 2_048,
            frame_count: 4,
            retire_timeout_ms: RX_BLOCK_RETIRE_TIMEOUT_MS,
            private_size: 0,
            feature_flags: 0,
        };
        let tx = RingGeometry {
            retire_timeout_ms: 0,
            private_size: 0,
            feature_flags: 0,
            ..rx
        };
        let config = AfPacketValidatedConfig::new(
            &[PortConfig {
                interface: ruster_core::IfId(1),
                if_index: 1,
                rx,
                tx,
            }],
            system_page_size().expect("Linux test page size must be available"),
            MAX_FRAME_LEN,
        )
        .expect("loopback AF_PACKET test configuration must validate");

        match AfPacketIo::open(config) {
            Ok(io) => {
                drop(io);
                println!("AF_PACKET permission test observed a privileged environment");
            }
            Err(error) => {
                assert!(
                    matches!(
                        error,
                        PlatformError::Syscall { errno, .. }
                            if matches!(errno.get(), EPERM | EACCES)
                    ),
                    "unprivileged AF_PACKET open must fail with EPERM/EACCES: {error:?}"
                );
                let message = format_open_error(error);
                assert!(message.contains("root or CAP_NET_RAW is required"));
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn observability_line_is_a_stable_key_value_record() {
        let generation = NonZeroU64::new(7).expect("literal is nonzero");
        let mut recorder: ObservabilityRecorder = ObservabilityRecorder::new();
        let snapshot = recorder.record_tick(
            generation,
            ruster_runtime::ActivePublicationStatus::ContinueOldIo,
            None,
            None,
            None,
            (),
        );
        recorder.record_drop_reason(ruster_core::DropReason::UnsupportedEtherType);

        let line = format_observability_line(
            &snapshot,
            recorder.activity_snapshot(),
            Health::Healthy,
            ReloadObservability::default(),
            ObservabilityBackend::AfPacket,
        );
        assert!(!line.contains('\n'));

        let mut fields = std::collections::BTreeMap::new();
        for field in line.split_whitespace() {
            let (key, value) = field
                .split_once('=')
                .expect("structured observability fields use key=value");
            assert!(
                fields.insert(key, value).is_none(),
                "structured record contains duplicate key {key:?}"
            );
        }

        for key in [
            "record_type",
            "config_generation",
            "readiness",
            "health",
            "reload_requests",
            "reload_results",
            "reload_applied",
            "reload_rejected",
            "reload_restart_required",
            "reload_unchanged",
            "reload_deferred",
            "reload_backend_mismatch",
            "reload_last_result",
            "ticks",
            "active_ticks",
            "forwarded",
            "dropped",
            "consumed",
            "tx_accepted",
            "tx_rejected",
            "firewall_processed",
            "firewall_denied",
            "firewall_processed_per_tick_high_watermark",
            "firewall_denied_per_tick_high_watermark",
            "nat44_udp_processed",
            "nat44_udp_denied",
            "nat44_udp_processed_per_tick_high_watermark",
            "nat44_udp_denied_per_tick_high_watermark",
            "nat44_tcp_processed",
            "nat44_tcp_denied",
            "nat44_tcp_processed_per_tick_high_watermark",
            "nat44_tcp_denied_per_tick_high_watermark",
            "queue_high_watermark",
            "capacity_high_watermark",
            "backend_mode",
            "backend_copy",
            "backend_ring_capacity_high_watermark",
            "drop_reason_total",
            "drop_reason_UNSUPPORTED_ETHERTYPE",
        ] {
            assert!(fields.contains_key(key), "missing structured key {key:?}");
        }
        assert_eq!(fields.get("record_type"), Some(&"observability"));
        assert_eq!(fields.get("config_generation"), Some(&"7"));
        assert_eq!(fields.get("reload_requests"), Some(&"0"));
        assert_eq!(fields.get("reload_results"), Some(&"0"));
        assert_eq!(fields.get("reload_applied"), Some(&"0"));
        assert_eq!(fields.get("reload_rejected"), Some(&"0"));
        assert_eq!(fields.get("reload_restart_required"), Some(&"0"));
        assert_eq!(fields.get("reload_unchanged"), Some(&"0"));
        assert_eq!(fields.get("reload_deferred"), Some(&"0"));
        assert_eq!(fields.get("reload_backend_mismatch"), Some(&"0"));
        assert_eq!(fields.get("reload_last_result"), Some(&"none"));
        assert_eq!(fields.get("drop_reason_UNSUPPORTED_ETHERTYPE"), Some(&"1"));
        assert_eq!(fields.get("backend_mode"), Some(&"af_packet_copy"));
    }

    #[cfg(target_os = "linux")]
    fn idle_tick_report() -> ruster_runtime::TickReport<(), (), (), (), (), ()> {
        ruster_runtime::TickReport {
            publication: ruster_runtime::PublicationOutcome::Unchanged,
            active: true,
            rx: RxPhaseReport::Completed(ruster_core::BatchReport {
                received: 0,
                tx_requested: 0,
                dropped: 0,
                consumed: 0,
                completion: ruster_core::BatchCompletion {
                    tx_requested: 0,
                    tx_accepted: 0,
                    tx_rejected: 0,
                    recycled: 0,
                    error: None,
                },
            }),
            resolution_timers: ruster_runtime::PhaseReport::Completed(
                ruster_core::ResolutionTimerReport::default(),
            ),
            failure_dispatch: ruster_runtime::PhaseReport::Completed(
                ruster_core::ResolutionFailureDispatchReport::default(),
            ),
            generated_arp: ruster_runtime::PhaseReport::Completed(
                ruster_runtime::GeneratedPhaseReport {
                    accounting: ruster_runtime::GeneratedAccounting::default(),
                    stop: ruster_runtime::GeneratedArpStop::QueueEmpty,
                },
            ),
            generated_icmpv4: ruster_runtime::PhaseReport::Completed(
                ruster_runtime::GeneratedPhaseReport {
                    accounting: ruster_runtime::GeneratedAccounting::default(),
                    stop: ruster_runtime::GeneratedIcmpv4Stop::QueueEmpty,
                },
            ),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn idle_tick_classifier_ignores_scan_and_pending_without_progress() {
        let mut report = idle_tick_report();
        report.resolution_timers =
            ruster_runtime::PhaseReport::Completed(ruster_core::ResolutionTimerReport {
                scanned: 4,
                pending: 2,
                ..Default::default()
            });
        report.failure_dispatch =
            ruster_runtime::PhaseReport::Completed(ruster_core::ResolutionFailureDispatchReport {
                scanned: 4,
                pending: 2,
                ..Default::default()
            });
        report.generated_arp =
            ruster_runtime::PhaseReport::Completed(ruster_runtime::GeneratedPhaseReport {
                accounting: ruster_runtime::GeneratedAccounting::default(),
                stop: ruster_runtime::GeneratedArpStop::BudgetExhausted { pending: 1 },
            });
        assert!(!tick_report_has_work(&report));

        report.resolution_timers =
            ruster_runtime::PhaseReport::Completed(ruster_core::ResolutionTimerReport {
                retries_queued: 1,
                ..Default::default()
            });
        assert!(tick_report_has_work(&report));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn idle_tick_classifier_requires_generated_progress_for_pending_budget() {
        let mut report = idle_tick_report();
        report.generated_arp =
            ruster_runtime::PhaseReport::Completed(ruster_runtime::GeneratedPhaseReport {
                accounting: ruster_runtime::GeneratedAccounting {
                    allocated: 1,
                    ..Default::default()
                },
                stop: ruster_runtime::GeneratedArpStop::BudgetExhausted { pending: 1 },
            });
        assert!(tick_report_has_work(&report));

        report.generated_arp =
            ruster_runtime::PhaseReport::Completed(ruster_runtime::GeneratedPhaseReport {
                accounting: ruster_runtime::GeneratedAccounting {
                    allocation_failed: 1,
                    ..Default::default()
                },
                stop: ruster_runtime::GeneratedArpStop::BudgetExhausted { pending: 1 },
            });
        assert!(!tick_report_has_work(&report));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn policy_idle_wait_uses_default_and_short_custom_intervals() {
        assert_eq!(
            policy_idle_wait_maximum(1_000, 100),
            std::time::Duration::from_millis(25)
        );
        assert_eq!(
            policy_idle_wait_maximum(1_000, 1),
            std::time::Duration::from_millis(1)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    // The public candidate-free Unchanged tick path leaves active runtime state and session untouched.
    fn same_config_reload_preflight_does_not_issue_fresh_keys() {
        const RELOAD_COUNT: usize = 101;
        let (entropy, entropy_path) = write_key_entropy(&[(1, 2), (3, 4), (5, 6)]);
        let mut inputs = PlanInputGenerator::from_entropy(entropy);
        inputs.initial_inputs().expect("initial generation inputs");
        let active_generation = NonZeroU64::new(1).expect("initial generation");
        inputs
            .activate_generation(active_generation)
            .expect("initial generation must activate");

        let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../control/tests/full-service.toml");
        let active_identity =
            ActiveConfigIdentity::from_source(FULL_SERVICE_CONFIG.as_bytes().to_vec());
        let mut reload_observability = ReloadObservability::default();
        for _ in 0..RELOAD_COUNT {
            reload_observability.record_request();
            let loaded =
                load_reload_config(config_path.to_str().expect("fixture path must be UTF-8"))
                    .expect("same configuration must be valid");
            assert!(matches!(
                classify_reload_config(&active_identity, loaded),
                ReloadConfigPlan::Unchanged
            ));
            record_reload_unchanged(&mut reload_observability, active_generation);
            assert_eq!(inputs.issued_keys.len(), HASH_KEYS_PER_GENERATION);
            assert_eq!(inputs.active_generation, Some(active_generation));
        }

        assert_eq!(reload_observability.requests, RELOAD_COUNT as u64);
        assert_eq!(reload_observability.results, RELOAD_COUNT as u64);
        assert_eq!(reload_observability.unchanged, RELOAD_COUNT as u64);
        assert_eq!(reload_observability.applied, 0);
        assert_eq!(reload_observability.rejected, 0);
        assert_eq!(
            reload_observability.last_result,
            Some(ReloadResultKind::Unchanged)
        );
        assert_eq!(
            inputs.issued_keys.len(),
            HASH_KEYS_PER_GENERATION,
            "unchanged reload must not mint a candidate generation"
        );
        assert_eq!(inputs.active_generation, Some(active_generation));
        fs::remove_file(entropy_path).expect("key entropy fixture must be removable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn same_config_reload_candidate_free_tick_preserves_active_nat_firewall_state() {
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../control/tests/full-service.toml");
        let LoadedReloadConfig { source, config } =
            load_reload_config(fixture_path.to_str().expect("fixture path must be UTF-8"))
                .expect("initial configuration must be valid");
        let active_identity = ActiveConfigIdentity::from_source(source);
        let candidate = prepare_successor_candidate_from_config(
            config,
            full_service_plan_inputs().expect("fixed plan inputs must be constructible"),
        )
        .expect("initial candidate must be plannable");

        // The simulation fixture's first frame is a stateful TCP flow. Build
        // two independent fixture buffers so the second packet must use the
        // state created by the first one; production packet handling remains
        // backend-buffered and is not changed by this test.
        let first_frame = build_sim_scenario(&candidate)
            .ingress
            .into_iter()
            .next()
            .expect("full-service fixture must produce a TCP ingress frame");
        let second_frame = build_sim_scenario(&candidate)
            .ingress
            .into_iter()
            .next()
            .expect("full-service fixture must produce a second TCP ingress frame");

        let mut storage = FullServiceRuntimeStorage::try_for_candidate(&candidate)
            .expect("fixture runtime storage must be allocatable");
        let owner = match activate_initial(&mut storage, candidate) {
            Ok(owner) => owner,
            Err(_) => panic!("fixture candidate must activate"),
        };
        let (owner_binding, mut io) =
            bind_publication_backend(SimIo::new()).expect("simulator binding must be available");
        let mut publication = match owner.bind_backend(owner_binding, &mut io) {
            Ok(publication) => publication,
            Err(_) => panic!("simulator must bind to the activated publication"),
        };
        let generation_before_reload = publication.generation();
        let publication_identity_before_reload = (
            publication.generation(),
            publication.interfaces().as_ptr() as usize,
            publication.interfaces().len(),
            publication.tick(),
            publication.required_runtime_bytes(),
            publication.storage_shape(),
        );
        let firewall_key_before_reload = {
            let view = publication.active_view();
            view.firewall_config().hash_key()
        };

        io.inject(first_frame.interface, first_frame.bytes);
        let mut recorder: ObservabilityRecorder = ObservabilityRecorder::new();
        let first_report = {
            let mut trace = DaemonTrace::new(&mut recorder);
            run_tick(
                &mut publication,
                None,
                &mut io,
                MonotonicMillis(1),
                &mut trace,
            )
        };
        assert!(matches!(
            &first_report.publication,
            PublicationOutcome::Unchanged
        ));
        let RxPhaseReport::Completed(first_rx) = first_report.rx else {
            panic!("state-seeding frame must complete: {:?}", first_report.rx);
        };
        assert_eq!(first_rx.completion.tx_accepted, 1);
        assert!(
            io.pop_tx().is_some(),
            "state-seeding frame must be forwarded"
        );

        let seeded_state = {
            let view = publication.active_view();
            assert!(view.has_nat44_udp_runtime());
            assert!(view.has_nat44_tcp_runtime());
            assert!(view.has_firewall_runtime());
            (
                view.nat44_udp_counters()
                    .expect("fixture must provide UDP runtime"),
                view.nat44_tcp_counters()
                    .expect("fixture must provide TCP runtime"),
                view.firewall_counters()
                    .expect("fixture must provide firewall runtime"),
            )
        };
        assert!(seeded_state.1.mappings_created > 0);
        assert!(seeded_state.1.sessions_created > 0);
        assert!(seeded_state.2.allowed_new > 0);

        // This test shares the reload boundary's cold steps: load one source
        // snapshot, parse/validate it, and compare its exact bytes with the
        // active identity. `Unchanged` carries no candidate, so the following
        // run_tick(None) exercises the matching candidate-free publication
        // outcome for that preflight result.
        let reloaded =
            load_reload_config(fixture_path.to_str().expect("fixture path must be UTF-8"))
                .expect("same configuration must remain valid");
        assert!(matches!(
            classify_reload_config(&active_identity, reloaded),
            ReloadConfigPlan::Unchanged
        ));
        let mut reload_observability = ReloadObservability::default();
        record_reload_unchanged(&mut reload_observability, publication.generation());

        io.inject(second_frame.interface, second_frame.bytes);
        let second_report = {
            let mut trace = DaemonTrace::new(&mut recorder);
            run_tick(
                &mut publication,
                None,
                &mut io,
                MonotonicMillis(2),
                &mut trace,
            )
        };
        assert!(matches!(
            &second_report.publication,
            PublicationOutcome::Unchanged
        ));
        let RxPhaseReport::Completed(second_rx) = second_report.rx else {
            panic!(
                "repeated stateful frame must complete: {:?}",
                second_report.rx
            );
        };
        assert_eq!(second_rx.completion.tx_accepted, 1);
        assert!(
            io.pop_tx().is_some(),
            "repeated stateful frame must still be forwarded"
        );

        let retained_state = {
            let view = publication.active_view();
            assert_eq!(view.generation(), generation_before_reload);
            assert!(view.has_nat44_udp_runtime());
            assert!(view.has_nat44_tcp_runtime());
            assert!(view.has_firewall_runtime());
            (
                view.nat44_udp_counters()
                    .expect("fixture must retain UDP runtime"),
                view.nat44_tcp_counters()
                    .expect("fixture must retain TCP runtime"),
                view.firewall_counters()
                    .expect("fixture must retain firewall runtime"),
            )
        };
        let publication_identity_after_reload = (
            publication.generation(),
            publication.interfaces().as_ptr() as usize,
            publication.interfaces().len(),
            publication.tick(),
            publication.required_runtime_bytes(),
            publication.storage_shape(),
        );
        let firewall_key_after_reload = {
            let view = publication.active_view();
            view.firewall_config().hash_key()
        };
        assert_eq!(publication.generation(), generation_before_reload);
        assert_eq!(
            publication_identity_after_reload,
            publication_identity_before_reload
        );
        // The public FullServiceView exposes the firewall hash identity. NAT
        // hash keys remain intentionally sealed there; their identity is
        // proven below by reusing the existing mapping/session state.
        assert_eq!(firewall_key_after_reload, firewall_key_before_reload);
        assert_eq!(retained_state.0, seeded_state.0);
        assert_eq!(
            retained_state.1.mappings_created,
            seeded_state.1.mappings_created
        );
        assert_eq!(
            retained_state.1.sessions_created,
            seeded_state.1.sessions_created
        );
        assert!(retained_state.1.mappings_reused > seeded_state.1.mappings_reused);
        assert!(retained_state.1.sessions_reused > seeded_state.1.sessions_reused);
        assert_eq!(retained_state.2.allowed_new, seeded_state.2.allowed_new);
        assert!(retained_state.2.allowed_established > seeded_state.2.allowed_established);
        assert_eq!(reload_observability.results, 1);
        assert_eq!(reload_observability.unchanged, 1);
        assert_eq!(
            reload_observability.last_result,
            Some(ReloadResultKind::Unchanged)
        );

        drop(publication);
        drop(io);
        drop(storage);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn changed_config_reload_rotates_fresh_keys_before_candidate_planning() {
        let (entropy, entropy_path) =
            write_key_entropy(&[(1, 2), (3, 4), (5, 6), (7, 8), (9, 10), (11, 12)]);
        let mut inputs = PlanInputGenerator::from_entropy(entropy);
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../control/tests/full-service.toml");
        let initial_loaded =
            load_reload_config(fixture_path.to_str().expect("fixture path must be UTF-8"))
                .expect("initial configuration must be valid");
        let initial_inputs = inputs.initial_inputs().expect("initial keys");
        let initial_candidate =
            prepare_successor_candidate_from_config(initial_loaded.config, initial_inputs)
                .expect("initial candidate must be plannable");
        let initial_generation = initial_candidate.generation();
        inputs
            .activate_generation(initial_generation)
            .expect("initial generation must activate");

        let changed_source = format!("# source identity changed\n{FULL_SERVICE_CONFIG}");
        let changed_path = write_reload_test_config(&changed_source);
        let loaded = load_reload_config(
            changed_path
                .to_str()
                .expect("changed config path must be UTF-8"),
        )
        .expect("changed configuration must be valid");
        let active_identity =
            ActiveConfigIdentity::from_source(FULL_SERVICE_CONFIG.as_bytes().to_vec());
        let loaded = match classify_reload_config(&active_identity, loaded) {
            ReloadConfigPlan::Changed(loaded) => loaded,
            ReloadConfigPlan::Unchanged => panic!("source-byte change must require reload"),
        };
        let generation = successor_generation(initial_generation).expect("successor generation");
        let LoadedReloadConfig { source, config } = *loaded;
        let plan_inputs = inputs
            .successor_inputs(generation)
            .expect("changed reload must mint fresh keys");
        let candidate = prepare_successor_candidate_from_config(config, plan_inputs)
            .expect("changed reload candidate must be plannable");
        assert_eq!(candidate.generation(), generation);
        assert_ne!(source.as_slice(), FULL_SERVICE_CONFIG.as_bytes());
        assert_eq!(inputs.issued_keys.len(), MAX_ISSUED_KEYS);
        assert_eq!(inputs.active_generation, Some(initial_generation));

        let outcome = plan_successor(Some(&initial_candidate), &candidate);
        assert_eq!(
            classify_reload_plan(&outcome),
            ReloadPlanClassification::InPlaceEligible
        );
        let mut reload_observability = ReloadObservability::default();
        let pending = handle_reload_plan(
            candidate,
            outcome,
            initial_generation,
            &mut reload_observability,
        );
        assert!(
            pending.is_some(),
            "eligible changed candidate must be queued"
        );
        drop(pending);
        inputs
            .activate_generation(generation)
            .expect("successful publication may activate the fresh generation");
        assert_eq!(inputs.active_generation, Some(generation));
        assert_eq!(inputs.issued_keys.len(), HASH_KEYS_PER_GENERATION);

        fs::remove_file(changed_path).expect("changed config fixture must be removable");
        fs::remove_file(entropy_path).expect("key entropy fixture must be removable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reload_reproduction_can_reclaim_a_retired_generation_key() {
        let (entropy, path) = write_key_entropy(&[
            (1, 2),
            (3, 4),
            (5, 6),
            (7, 8),
            (9, 10),
            (11, 12),
            (1, 2),
            (3, 4),
            (5, 6),
        ]);
        let mut inputs = PlanInputGenerator::from_entropy(entropy);
        inputs.initial_inputs().expect("initial generation inputs");
        inputs
            .activate_generation(NonZeroU64::new(1).expect("initial generation"))
            .expect("initial generation must activate");
        inputs
            .successor_inputs(NonZeroU64::new(2).expect("successor generation"))
            .expect("second generation inputs");
        inputs
            .activate_generation(NonZeroU64::new(2).expect("successor generation"))
            .expect("successor generation must activate");

        inputs
            .successor_inputs(NonZeroU64::new(3).expect("successor generation"))
            .expect("keys retired after generation 2 may be reused by generation 3");
        assert_eq!(inputs.issued_keys.len(), MAX_ISSUED_KEYS);
        inputs
            .activate_generation(NonZeroU64::new(3).expect("successor generation"))
            .expect("third generation must activate");
        assert_eq!(inputs.issued_keys.len(), HASH_KEYS_PER_GENERATION);
        assert!(inputs
            .issued_keys
            .iter()
            .all(|issued| issued.generation == NonZeroU64::new(3).unwrap()));
        fs::remove_file(path).expect("key entropy fixture must be removable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issued_key_history_is_bounded_across_reload_generations() {
        const EXPECTED_MAX_ISSUED_KEYS: usize = HASH_KEYS_PER_GENERATION * 2;
        let (entropy, path) = write_key_entropy(&[
            (1, 2),
            (3, 4),
            (5, 6),
            (7, 8),
            (9, 10),
            (11, 12),
            (13, 14),
            (15, 16),
            (17, 18),
        ]);
        let mut inputs = PlanInputGenerator::from_entropy(entropy);
        inputs.initial_inputs().expect("initial generation inputs");
        inputs
            .activate_generation(NonZeroU64::new(1).expect("initial generation"))
            .expect("initial generation must activate");
        inputs
            .successor_inputs(NonZeroU64::new(2).expect("nonzero generation"))
            .expect("second generation inputs");
        inputs
            .activate_generation(NonZeroU64::new(2).expect("successor generation"))
            .expect("successor generation must activate");

        assert_eq!(inputs.issued_keys.len(), HASH_KEYS_PER_GENERATION);
        assert!(inputs.issued_keys.capacity() >= EXPECTED_MAX_ISSUED_KEYS);
        assert_eq!(
            inputs
                .issued_keys
                .iter()
                .filter(|issued| issued.generation == NonZeroU64::new(2).unwrap())
                .count(),
            HASH_KEYS_PER_GENERATION
        );

        inputs
            .successor_inputs(NonZeroU64::new(3).expect("nonzero generation"))
            .expect("retired generations must not block a later reload");
        assert_eq!(inputs.issued_keys.len(), EXPECTED_MAX_ISSUED_KEYS);
        assert_eq!(
            inputs
                .issued_keys
                .iter()
                .filter(|issued| issued.generation == NonZeroU64::new(3).unwrap())
                .count(),
            HASH_KEYS_PER_GENERATION
        );
        for (index, issued) in inputs.issued_keys.iter().enumerate() {
            assert!(
                inputs
                    .issued_keys
                    .iter()
                    .skip(index + 1)
                    .all(|other| other.words != issued.words),
                "issued hash-key words must never be reused"
            );
        }
        inputs
            .activate_generation(NonZeroU64::new(3).expect("successor generation"))
            .expect("third generation must activate");
        assert_eq!(inputs.issued_keys.len(), HASH_KEYS_PER_GENERATION);
        assert!(inputs
            .issued_keys
            .iter()
            .all(|issued| issued.generation == NonZeroU64::new(3).unwrap()));
        fs::remove_file(path).expect("key entropy fixture must be removable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reloads_through_generation_101_keep_issued_key_history_bounded() {
        let words: Vec<HashKeyWords> = (0..(HASH_KEYS_PER_GENERATION * 101))
            .map(|index| {
                let value = index as u64 + 1;
                (value, value.wrapping_add(0x1000))
            })
            .collect();
        let (entropy, path) = write_key_entropy(&words);
        let mut inputs = PlanInputGenerator::from_entropy(entropy);

        let initial_generation = NonZeroU64::new(1).expect("initial generation");
        inputs
            .initial_inputs()
            .expect("initial generation inputs must be issued");
        inputs
            .activate_generation(initial_generation)
            .expect("initial generation must activate");
        assert!(inputs.issued_keys.len() <= MAX_ISSUED_KEYS);
        assert!(inputs.issued_keys.capacity() <= MAX_ISSUED_KEYS);

        for generation in 2..=101 {
            let generation = NonZeroU64::new(generation).expect("reload generation");
            inputs
                .successor_inputs(generation)
                .unwrap_or_else(|error| panic!("generation {generation} must issue: {error}"));
            assert!(inputs.issued_keys.len() <= MAX_ISSUED_KEYS);
            assert!(inputs.issued_keys.capacity() <= MAX_ISSUED_KEYS);
            inputs
                .activate_generation(generation)
                .unwrap_or_else(|error| panic!("generation {generation} must activate: {error}"));
            assert_eq!(inputs.active_generation, Some(generation));
            assert!(inputs.issued_keys.len() <= MAX_ISSUED_KEYS);
            assert!(inputs.issued_keys.capacity() <= MAX_ISSUED_KEYS);
        }

        fs::remove_file(path).expect("key entropy fixture must be removable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_reload_key_mint_discards_partial_generation() {
        let (entropy, path) = write_key_entropy(&[(1, 2), (3, 4), (5, 6), (7, 8)]);
        let mut inputs = PlanInputGenerator::from_entropy(entropy);
        inputs.initial_inputs().expect("initial keys");
        inputs
            .activate_generation(NonZeroU64::new(1).expect("initial generation"))
            .expect("initial generation must activate");

        assert!(inputs
            .successor_inputs(NonZeroU64::new(2).expect("successor generation"))
            .is_err());
        assert_eq!(inputs.issued_keys.len(), HASH_KEYS_PER_GENERATION);
        assert!(inputs
            .issued_keys
            .iter()
            .all(|issued| issued.generation == NonZeroU64::new(1).unwrap()));
        fs::remove_file(path).expect("key entropy fixture must be removable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collision_retry_mints_a_unique_successor_and_exhaustion_preserves_active_keys() {
        let (entropy, path) =
            write_key_entropy(&[(1, 2), (3, 4), (5, 6), (1, 2), (7, 8), (9, 10), (11, 12)]);
        let mut inputs = PlanInputGenerator::from_entropy(entropy);
        inputs.initial_inputs().expect("initial keys");
        inputs
            .activate_generation(NonZeroU64::new(1).expect("initial generation"))
            .expect("initial generation must activate");
        inputs
            .successor_inputs(NonZeroU64::new(2).expect("successor generation"))
            .expect("collision retry must find a fresh key");
        assert_eq!(inputs.issued_keys.len(), MAX_ISSUED_KEYS);
        assert_eq!(inputs.issued_keys[3].words, (7, 8));
        assert_eq!(
            inputs
                .issued_keys
                .iter()
                .filter(|issued| issued.words == (1, 2))
                .count(),
            1
        );
        inputs
            .activate_generation(NonZeroU64::new(2).expect("successor generation"))
            .expect("successor generation must activate");
        assert_eq!(inputs.issued_keys.len(), HASH_KEYS_PER_GENERATION);
        assert!(inputs
            .issued_keys
            .iter()
            .all(|issued| issued.generation == NonZeroU64::new(2).unwrap()));
        fs::remove_file(path).expect("key entropy fixture must be removable");

        let mut collision_words = vec![(21, 22), (23, 24), (25, 26)];
        collision_words.extend(std::iter::repeat_n((21, 22), FRESH_KEY_ATTEMPTS));
        let (entropy, path) = write_key_entropy(&collision_words);
        let mut inputs = PlanInputGenerator::from_entropy(entropy);
        inputs.initial_inputs().expect("initial keys");
        inputs
            .activate_generation(NonZeroU64::new(1).expect("initial generation"))
            .expect("initial generation must activate");
        assert!(inputs
            .successor_inputs(NonZeroU64::new(2).expect("successor generation"))
            .is_err());
        assert_eq!(inputs.issued_keys.len(), HASH_KEYS_PER_GENERATION);
        assert!(inputs
            .issued_keys
            .iter()
            .all(|issued| issued.generation == NonZeroU64::new(1).unwrap()));
        fs::remove_file(path).expect("key entropy fixture must be removable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn successor_generation_fails_closed_at_u64_max() {
        let exhausted = NonZeroU64::new(u64::MAX).expect("maximum is nonzero");
        assert_eq!(
            successor_generation(exhausted),
            Err("publication generation is exhausted".to_owned())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn successor_generation_is_strict_and_candidate_key_reuse_is_rejected() {
        let current = planned_test_candidate(FULL_SERVICE_CONFIG, 1, 10);
        assert_eq!(
            successor_generation(current.generation()),
            Ok(NonZeroU64::new(2).expect("successor generation is nonzero"))
        );

        let reused_key = planned_test_candidate(FULL_SERVICE_CONFIG, 2, 10);
        let outcome = plan_successor(Some(&current), &reused_key);
        assert_eq!(
            outcome.rejection_error(),
            Some(SuccessorError::Nat44UdpHashKeyReused)
        );
        assert_eq!(outcome.next_generation(), NonZeroU64::new(2).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sighup_flag_causes_the_validated_config_to_be_reloaded() {
        RELOAD_REQUESTED.store(false, Ordering::Relaxed);
        signal_handler(SIGHUP);
        assert!(take_reload_request());
        assert!(!take_reload_request());

        let source = FULL_SERVICE_CONFIG.replace("rx = 64", "rx = 32");
        let path = write_reload_test_config(&source);
        let mut inputs = PlanInputGenerator::open().expect("system entropy must be available");
        let candidate = prepare_successor_candidate(
            path.to_str().expect("reload test path must be UTF-8"),
            NonZeroU64::new(2).expect("reload generation is nonzero"),
            &mut inputs,
        )
        .expect("valid reload config must produce a successor candidate");
        assert_eq!(candidate.generation(), NonZeroU64::new(2).unwrap());
        assert_eq!(candidate.tick().rx, 32);
        drop(candidate);
        fs::remove_file(path).expect("reload test config must be removable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn invalid_reload_config_continues_old_generation_and_records_rejection() {
        let path = write_reload_test_config("schema-version = 1\n[[interfaces]]\n");
        let mut inputs = PlanInputGenerator::open().expect("system entropy must be available");
        let old_generation = NonZeroU64::new(1).expect("old generation is nonzero");
        let result = prepare_successor_candidate(
            path.to_str().expect("reload test path must be UTF-8"),
            successor_generation(old_generation).expect("successor generation must be available"),
            &mut inputs,
        );
        assert!(result.is_err(), "invalid reload config must be rejected");
        assert_eq!(old_generation, NonZeroU64::new(1).unwrap());

        let mut reload_observability = ReloadObservability::default();
        reload_observability.record_request();
        record_reload_failure(
            &mut reload_observability,
            old_generation,
            "configuration validation failed",
        );
        assert_eq!(reload_observability.requests, 1);
        assert_eq!(reload_observability.results, 1);
        assert_eq!(reload_observability.rejected, 1);
        assert_eq!(reload_observability.applied, 0);
        assert_eq!(reload_observability.restart_required, 0);
        assert_eq!(
            reload_observability.last_result,
            Some(ReloadResultKind::Rejected)
        );
        assert_eq!(old_generation, NonZeroU64::new(1).unwrap());
        fs::remove_file(path).expect("reload test config must be removable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn successor_plan_classifier_covers_apply_reject_and_restart() {
        let current = planned_test_candidate(FULL_SERVICE_CONFIG, 1, 10);
        let eligible = planned_test_candidate(FULL_SERVICE_CONFIG, 2, 20);
        assert_eq!(
            classify_reload_plan(&plan_successor(Some(&current), &eligible)),
            ReloadPlanClassification::InPlaceEligible
        );

        let reused_key = planned_test_candidate(FULL_SERVICE_CONFIG, 2, 10);
        assert!(matches!(
            classify_reload_plan(&plan_successor(Some(&current), &reused_key)),
            ReloadPlanClassification::Rejected(SuccessorError::Nat44UdpHashKeyReused)
        ));

        let changed_interface =
            FULL_SERVICE_CONFIG.replace("device = \"eth1\"", "device = \"eth9\"");
        let restart = planned_test_candidate(&changed_interface, 2, 30);
        assert!(matches!(
            classify_reload_plan(&plan_successor(Some(&current), &restart)),
            ReloadPlanClassification::RestartRequired(
                PlanRestartRequired::InterfaceBindingsChanged
            )
        ));

        let backend_changed = planned_test_candidate(&af_xdp_reload_test_source(), 2, 30);
        assert!(matches!(
            classify_reload_plan(&plan_successor(Some(&current), &backend_changed)),
            ReloadPlanClassification::RestartRequired(PlanRestartRequired::BackendChanged)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn static_reload_plan_rejects_or_reports_restart_without_queuing_candidate() {
        let current = planned_test_candidate(FULL_SERVICE_CONFIG, 1, 10);
        let eligible = planned_test_candidate(FULL_SERVICE_CONFIG, 2, 20);
        let eligible_outcome = plan_successor(Some(&current), &eligible);
        let eligible_diff = eligible_outcome
            .section_diff()
            .expect("successor plan must include its semantic diff");
        assert!(!eligible_diff.interfaces_changed());
        assert!(eligible_diff.nat44_udp_hash_key_changed());
        assert!(eligible_diff.nat44_tcp_hash_key_changed());
        assert!(eligible_diff.firewall_hash_key_changed());
        let mut reload_observability = ReloadObservability::default();
        let pending = handle_reload_plan(
            eligible,
            eligible_outcome,
            current.generation(),
            &mut reload_observability,
        );
        assert_eq!(
            pending.as_ref().map(|candidate| candidate.generation()),
            NonZeroU64::new(2)
        );
        drop(pending);
        assert_eq!(reload_observability.results, 0);

        let restart_source = FULL_SERVICE_CONFIG.replace("device = \"eth1\"", "device = \"eth9\"");
        let restart = planned_test_candidate(&restart_source, 2, 30);
        let restart_outcome = plan_successor(Some(&current), &restart);
        let pending = handle_reload_plan(
            restart,
            restart_outcome,
            current.generation(),
            &mut reload_observability,
        );
        assert!(pending.is_none());
        assert_eq!(reload_observability.results, 1);
        assert_eq!(reload_observability.restart_required, 1);
        assert_eq!(reload_observability.rejected, 0);

        let rejected = planned_test_candidate(FULL_SERVICE_CONFIG, 2, 10);
        let rejected_outcome = plan_successor(Some(&current), &rejected);
        let pending = handle_reload_plan(
            rejected,
            rejected_outcome,
            current.generation(),
            &mut reload_observability,
        );
        assert!(pending.is_none());
        assert_eq!(reload_observability.results, 2);
        assert_eq!(reload_observability.restart_required, 1);
        assert_eq!(reload_observability.rejected, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn publication_classifier_covers_all_candidate_outcomes() {
        type Outcome = PublicationOutcome<(), FullServicePublishError, (), ()>;
        let applied = Outcome::Applied(());
        assert_eq!(
            classify_reload_publication(&applied),
            ReloadPublicationClassification::Applied
        );
        assert_eq!(
            classify_reload_publication(&Outcome::Unchanged),
            ReloadPublicationClassification::Unchanged
        );
        assert_eq!(
            classify_reload_publication(&Outcome::Deferred {
                candidate: (),
                error: (),
                disposition: PublicationQuiescenceDisposition::ContinueOldIo,
            }),
            ReloadPublicationClassification::Deferred
        );
        assert_eq!(
            classify_reload_publication(&Outcome::BackendMismatch {
                candidate: Some(())
            }),
            ReloadPublicationClassification::BackendMismatch
        );
        assert_eq!(
            classify_reload_publication(&Outcome::Rejected {
                rejection: ruster_runtime::PublicationRejection::new(
                    (),
                    FullServicePublishError::InvalidSuccessor(
                        SuccessorError::GenerationNotIncreasing,
                    ),
                ),
                status: ruster_runtime::ActivePublicationStatus::ContinueOldIo,
            }),
            ReloadPublicationClassification::Rejected
        );
        assert_eq!(
            classify_reload_publication(&Outcome::Rejected {
                rejection: ruster_runtime::PublicationRejection::new(
                    (),
                    FullServicePublishError::RestartRequired(
                        ruster_integration::FullServiceRestartRequired::InterfaceBindingsChanged,
                    ),
                ),
                status: ruster_runtime::ActivePublicationStatus::ContinueOldIo,
            }),
            ReloadPublicationClassification::RestartRequired
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn publication_handler_retains_deferred_candidate_and_safely_discards_rejection() {
        let deferred_candidate = planned_test_candidate(FULL_SERVICE_CONFIG, 2, 20);
        let deferred = PublicationOutcome::Deferred {
            candidate: deferred_candidate,
            error: AfPacketError::Wait(PlatformError::UnsupportedPlatform),
            disposition: PublicationQuiescenceDisposition::SkipIo,
        };
        let mut reload_observability = ReloadObservability::default();
        let pending = handle_reload_publication::<AfPacketError>(
            deferred,
            NonZeroU64::new(1).expect("old generation is nonzero"),
            &mut reload_observability,
        );
        assert_eq!(
            pending.as_ref().map(|candidate| candidate.generation()),
            NonZeroU64::new(2)
        );
        assert_eq!(reload_observability.results, 1);
        assert_eq!(reload_observability.deferred, 1);
        drop(pending);

        let terminal_candidate = planned_test_candidate(FULL_SERVICE_CONFIG, 2, 21);
        let terminal_deferred = PublicationOutcome::Deferred {
            candidate: terminal_candidate,
            error: AfPacketError::Wait(PlatformError::UnsupportedPlatform),
            disposition: PublicationQuiescenceDisposition::Stop,
        };
        let pending = handle_reload_publication(
            terminal_deferred,
            NonZeroU64::new(1).expect("old generation is nonzero"),
            &mut reload_observability,
        );
        assert!(pending.is_none());
        assert_eq!(reload_observability.results, 2);
        assert_eq!(reload_observability.deferred, 2);

        let rejected_candidate = planned_test_candidate(FULL_SERVICE_CONFIG, 2, 30);
        let rejected = PublicationOutcome::Rejected {
            rejection: ruster_runtime::PublicationRejection::new(
                rejected_candidate,
                FullServicePublishError::InvalidSuccessor(SuccessorError::GenerationNotIncreasing),
            ),
            status: ruster_runtime::ActivePublicationStatus::ContinueOldIo,
        };
        let pending = handle_reload_publication::<AfPacketError>(
            rejected,
            NonZeroU64::new(1).expect("old generation is nonzero"),
            &mut reload_observability,
        );
        assert!(pending.is_none());
        assert_eq!(reload_observability.results, 3);
        assert_eq!(reload_observability.deferred, 2);
        assert_eq!(reload_observability.rejected, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reload_result_strings_and_initial_activation_are_fail_closed() {
        // Protects the operator-visible spelling of every reload result and
        // ensures a cold-start plan is never treated as a successor apply.
        let cases = [
            (ReloadResultKind::Applied, "applied"),
            (ReloadResultKind::Rejected, "rejected"),
            (ReloadResultKind::RestartRequired, "restart-required"),
            (ReloadResultKind::Unchanged, "unchanged"),
            (ReloadResultKind::Deferred, "deferred"),
            (ReloadResultKind::BackendMismatch, "backend-mismatch"),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.as_str(), expected);
        }

        let candidate = planned_test_candidate(FULL_SERVICE_CONFIG, 1, 10);
        let outcome = plan_successor(None, &candidate);
        assert_eq!(
            classify_reload_plan(&outcome),
            ReloadPlanClassification::InitialActivation
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_sim_options_reject_invalid_or_zero_ticks() {
        // Protects the CLI boundary from accepting malformed, missing, or
        // zero simulation budgets that would otherwise silently do no work.
        assert_eq!(
            parse_run_sim_options(&[]).expect("default simulation budget"),
            DEFAULT_SIM_TICKS
        );
        assert_eq!(
            parse_run_sim_options(&["--ticks".to_owned(), "7".to_owned()])
                .expect("positive simulation budget"),
            7
        );
        assert!(parse_run_sim_options(&["--ticks".to_owned()]).is_err());
        assert!(parse_run_sim_options(&["--ticks".to_owned(), "0".to_owned()]).is_err());
        assert!(parse_run_sim_options(&["--other".to_owned(), "1".to_owned()]).is_err());
    }

    #[cfg(target_os = "linux")]
    fn healthy_tick_report() -> ruster_runtime::TickReport<(), (), (), (), (), ()> {
        idle_tick_report()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn health_classifier_distinguishes_readiness_and_active_state() {
        // Protects the fail-closed health contract: cold is unavailable and
        // either degraded readiness or an inactive publication is degraded.
        let report = healthy_tick_report();
        assert_eq!(
            health_for_tick(Readiness::Cold, &report),
            Health::Unavailable
        );
        assert_eq!(
            health_for_tick(Readiness::Degraded, &report),
            Health::Degraded
        );

        let mut inactive = healthy_tick_report();
        inactive.active = false;
        assert_eq!(
            health_for_tick(Readiness::Ready, &inactive),
            Health::Degraded
        );
        assert_eq!(health_for_tick(Readiness::Ready, &report), Health::Healthy);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn health_classifier_requires_every_tick_phase_to_be_healthy() {
        // Protects each independent health prerequisite; one failed phase
        // must never be hidden by the other four successful phases.
        let mut report = healthy_tick_report();
        report.rx = RxPhaseReport::Completed(ruster_core::BatchReport {
            received: 1,
            tx_requested: 0,
            dropped: 0,
            consumed: 0,
            completion: ruster_core::BatchCompletion {
                tx_requested: 0,
                tx_accepted: 0,
                tx_rejected: 0,
                recycled: 0,
                error: None,
            },
        });
        assert_eq!(health_for_tick(Readiness::Ready, &report), Health::Degraded);

        let mut report = healthy_tick_report();
        report.rx = RxPhaseReport::Completed(ruster_core::BatchReport {
            received: 0,
            tx_requested: 0,
            dropped: 0,
            consumed: 0,
            completion: ruster_core::BatchCompletion {
                tx_requested: 0,
                tx_accepted: 0,
                tx_rejected: 0,
                recycled: 0,
                error: Some(()),
            },
        });
        assert_eq!(health_for_tick(Readiness::Ready, &report), Health::Degraded);

        let mut report = healthy_tick_report();
        report.resolution_timers =
            ruster_runtime::PhaseReport::Failed(ruster_core::ResolutionTimerError::ClockRegression);
        assert_eq!(health_for_tick(Readiness::Ready, &report), Health::Degraded);

        let mut report = healthy_tick_report();
        report.failure_dispatch = ruster_runtime::PhaseReport::Failed(
            ruster_core::ResolutionFailureDispatchError::ClockRegression,
        );
        assert_eq!(health_for_tick(Readiness::Ready, &report), Health::Degraded);

        let mut report = healthy_tick_report();
        report.generated_arp =
            ruster_runtime::PhaseReport::Completed(ruster_runtime::GeneratedPhaseReport {
                accounting: ruster_runtime::GeneratedAccounting::default(),
                stop: ruster_runtime::GeneratedArpStop::ClockRegression,
            });
        assert_eq!(health_for_tick(Readiness::Ready, &report), Health::Degraded);

        let mut report = healthy_tick_report();
        report.generated_icmpv4 =
            ruster_runtime::PhaseReport::Completed(ruster_runtime::GeneratedPhaseReport {
                accounting: ruster_runtime::GeneratedAccounting::default(),
                stop: ruster_runtime::GeneratedIcmpv4Stop::ClockRegression,
            });
        assert_eq!(health_for_tick(Readiness::Ready, &report), Health::Degraded);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tick_work_classifier_reports_each_rx_counter() {
        // Protects every RX activity counter from being ignored by the idle
        // watchdog decision.
        let mut reports: Vec<_> = (0..9).map(|_| healthy_tick_report()).collect();
        reports[0].rx = RxPhaseReport::Completed(ruster_core::BatchReport {
            received: 1,
            ..idle_tick_batch_report()
        });
        reports[1].rx = RxPhaseReport::Completed(ruster_core::BatchReport {
            tx_requested: 1,
            ..idle_tick_batch_report()
        });
        reports[2].rx = RxPhaseReport::Completed(ruster_core::BatchReport {
            dropped: 1,
            ..idle_tick_batch_report()
        });
        reports[3].rx = RxPhaseReport::Completed(ruster_core::BatchReport {
            consumed: 1,
            ..idle_tick_batch_report()
        });
        reports[4].rx = RxPhaseReport::Completed(ruster_core::BatchReport {
            completion: ruster_core::BatchCompletion {
                tx_requested: 1,
                tx_accepted: 0,
                tx_rejected: 0,
                recycled: 0,
                error: None,
            },
            ..idle_tick_batch_report()
        });
        reports[5].rx = RxPhaseReport::Completed(ruster_core::BatchReport {
            completion: ruster_core::BatchCompletion {
                tx_requested: 0,
                tx_accepted: 1,
                tx_rejected: 0,
                recycled: 0,
                error: None,
            },
            ..idle_tick_batch_report()
        });
        reports[6].rx = RxPhaseReport::Completed(ruster_core::BatchReport {
            completion: ruster_core::BatchCompletion {
                tx_requested: 0,
                tx_accepted: 0,
                tx_rejected: 1,
                recycled: 0,
                error: None,
            },
            ..idle_tick_batch_report()
        });
        reports[7].rx = RxPhaseReport::Completed(ruster_core::BatchReport {
            completion: ruster_core::BatchCompletion {
                tx_requested: 0,
                tx_accepted: 0,
                tx_rejected: 0,
                recycled: 1,
                error: None,
            },
            ..idle_tick_batch_report()
        });
        reports[8].rx = RxPhaseReport::Completed(ruster_core::BatchReport {
            completion: ruster_core::BatchCompletion {
                tx_requested: 0,
                tx_accepted: 0,
                tx_rejected: 0,
                recycled: 0,
                error: Some(()),
            },
            ..idle_tick_batch_report()
        });
        for report in reports {
            assert!(tick_report_has_work(&report));
        }
    }

    #[cfg(target_os = "linux")]
    fn idle_tick_batch_report() -> ruster_core::BatchReport<()> {
        ruster_core::BatchReport {
            received: 0,
            tx_requested: 0,
            dropped: 0,
            consumed: 0,
            completion: idle_batch_completion(),
        }
    }

    #[cfg(target_os = "linux")]
    fn idle_batch_completion() -> ruster_core::BatchCompletion<()> {
        ruster_core::BatchCompletion {
            tx_requested: 0,
            tx_accepted: 0,
            tx_rejected: 0,
            recycled: 0,
            error: None,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tick_work_classifier_reports_timer_dispatch_and_phase_failures() {
        // Protects timer, failure-dispatch, and terminal phase outcomes from
        // being mistaken for an idle tick.
        let mut report = healthy_tick_report();
        for timer in [
            ruster_core::ResolutionTimerReport {
                retries_queued: 1,
                ..Default::default()
            },
            ruster_core::ResolutionTimerReport {
                timed_out: 1,
                ..Default::default()
            },
            ruster_core::ResolutionTimerReport {
                no_accepted_arp_request: 1,
                ..Default::default()
            },
            ruster_core::ResolutionTimerReport {
                failures_expired: 1,
                ..Default::default()
            },
        ] {
            report.resolution_timers = ruster_runtime::PhaseReport::Completed(timer);
            assert!(tick_report_has_work(&report));
        }
        for dispatch in [
            ruster_core::ResolutionFailureDispatchReport {
                queued: 1,
                ..Default::default()
            },
            ruster_core::ResolutionFailureDispatchReport {
                retired: 1,
                ..Default::default()
            },
            ruster_core::ResolutionFailureDispatchReport {
                reverse_arp_scheduled: 1,
                ..Default::default()
            },
        ] {
            report.failure_dispatch = ruster_runtime::PhaseReport::Completed(dispatch);
            assert!(tick_report_has_work(&report));
        }
        report.resolution_timers =
            ruster_runtime::PhaseReport::Failed(ruster_core::ResolutionTimerError::ClockRegression);
        assert!(tick_report_has_work(&report));
        report.failure_dispatch = ruster_runtime::PhaseReport::Failed(
            ruster_core::ResolutionFailureDispatchError::ClockRegression,
        );
        assert!(tick_report_has_work(&report));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn generated_work_requires_progress_and_positive_pending_budget() {
        // Protects generated watchdog work from counting a pending queue when
        // no frame progressed, and covers the zero/one/multiple pending cases.
        let fields = [
            (
                "allocated",
                ruster_runtime::GeneratedAccounting {
                    allocated: 1,
                    ..Default::default()
                },
            ),
            (
                "tx_requested",
                ruster_runtime::GeneratedAccounting {
                    tx_requested: 1,
                    ..Default::default()
                },
            ),
            (
                "cancelled",
                ruster_runtime::GeneratedAccounting {
                    cancelled: 1,
                    ..Default::default()
                },
            ),
            (
                "abandoned",
                ruster_runtime::GeneratedAccounting {
                    abandoned: 1,
                    ..Default::default()
                },
            ),
            (
                "tx_accepted",
                ruster_runtime::GeneratedAccounting {
                    tx_accepted: 1,
                    ..Default::default()
                },
            ),
            (
                "tx_rejected",
                ruster_runtime::GeneratedAccounting {
                    tx_rejected: 1,
                    ..Default::default()
                },
            ),
        ];
        for (name, accounting) in fields {
            assert!(
                generated_accounting_has_progress(&accounting),
                "{name} is progress"
            );
            let mut report = healthy_tick_report();
            report.generated_arp =
                ruster_runtime::PhaseReport::Completed(ruster_runtime::GeneratedPhaseReport {
                    accounting,
                    stop: ruster_runtime::GeneratedArpStop::QueueEmpty,
                });
            assert!(tick_report_has_work(&report));
        }

        let mut report = healthy_tick_report();
        report.generated_arp =
            ruster_runtime::PhaseReport::Completed(ruster_runtime::GeneratedPhaseReport {
                accounting: fields[0].1,
                stop: ruster_runtime::GeneratedArpStop::BudgetExhausted { pending: 0 },
            });
        assert!(!tick_report_has_work(&report));
        for pending in [1, 2] {
            report.generated_arp =
                ruster_runtime::PhaseReport::Completed(ruster_runtime::GeneratedPhaseReport {
                    accounting: fields[0].1,
                    stop: ruster_runtime::GeneratedArpStop::BudgetExhausted { pending },
                });
            assert!(tick_report_has_work(&report));
        }
        report.generated_arp =
            ruster_runtime::PhaseReport::Completed(ruster_runtime::GeneratedPhaseReport {
                accounting: ruster_runtime::GeneratedAccounting::default(),
                stop: ruster_runtime::GeneratedArpStop::QueueEmpty,
            });
        for (pending, expected) in [(0, false), (1, true), (2, true)] {
            report.generated_icmpv4 =
                ruster_runtime::PhaseReport::Completed(ruster_runtime::GeneratedPhaseReport {
                    accounting: fields[0].1,
                    stop: ruster_runtime::GeneratedIcmpv4Stop::BudgetExhausted { pending },
                });
            assert_eq!(tick_report_has_work(&report), expected);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tick_work_classifier_marks_inactive_and_non_unchanged_publication_busy() {
        // Protects the top-level watchdog short circuit for inactive or
        // publication-changing ticks, even when all phase counters are zero.
        let mut report = healthy_tick_report();
        report.active = false;
        assert!(tick_report_has_work(&report));
        report.active = true;
        report.publication = ruster_runtime::PublicationOutcome::Applied(());
        assert!(tick_report_has_work(&report));
    }

    #[cfg(target_os = "linux")]
    fn ip(octets: [u8; 4]) -> ruster_core::Ipv4Address {
        ruster_core::Ipv4Address::from_octets(octets)
    }

    #[cfg(target_os = "linux")]
    fn prefix(octets: [u8; 4], length: u8) -> ruster_core::FirewallIpv4Prefix {
        ruster_core::FirewallIpv4Prefix::new(ip(octets), length).expect("valid test prefix")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn simulation_ipv4_masks_and_usable_boundaries_are_explicit() {
        // Protects route-mask arithmetic and excludes unspecified, loopback,
        // multicast, and limited-broadcast addresses from generated traffic.
        assert_eq!(sim_prefix_mask(0), 0);
        assert_eq!(sim_prefix_mask(1), 0x8000_0000);
        assert_eq!(sim_prefix_mask(24), 0xffff_ff00);
        assert_eq!(sim_prefix_mask(32), u32::MAX);
        assert_eq!(sim_prefix_mask(33), 0);
        assert_eq!(sim_host_mask(24), 0x0000_00ff);

        for address in [
            [0, 0, 0, 0],
            [0, 1, 2, 3],
            [127, 0, 0, 1],
            [224, 0, 0, 1],
            [255, 255, 255, 255],
        ] {
            assert!(
                !sim_usable_ipv4(ip(address)),
                "{address:?} must be unusable"
            );
        }
        for address in [
            [1, 0, 0, 1],
            [126, 1, 2, 3],
            [128, 0, 0, 1],
            [223, 255, 255, 254],
        ] {
            assert!(sim_usable_ipv4(ip(address)), "{address:?} must be usable");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn simulation_firewall_matching_and_port_selection_are_fail_closed() {
        // Protects firewall interface/prefix matching, representative source
        // selection, and preferred-port fallback used by run-sim.
        let ingress = ruster_core::IfId(1);
        let egress = ruster_core::IfId(2);
        assert!(sim_firewall_interface_matches(
            ruster_core::FirewallInterface::Any,
            ingress
        ));
        assert!(sim_firewall_interface_matches(
            ruster_core::FirewallInterface::Interface(ingress),
            ingress
        ));
        assert!(!sim_firewall_interface_matches(
            ruster_core::FirewallInterface::Interface(egress),
            ingress
        ));
        let network = prefix([192, 0, 2, 0], 24);
        assert!(sim_firewall_prefix_matches(network, ip([192, 0, 2, 7])));
        assert!(!sim_firewall_prefix_matches(network, ip([192, 0, 3, 7])));
        assert_eq!(
            sim_firewall_prefix_representative(network),
            Some(ip([192, 0, 2, 1]))
        );
        assert_eq!(
            sim_firewall_prefix_representative(prefix([127, 0, 0, 0], 8)),
            None
        );

        let inside = ruster_core::FirewallPortRange::new(50_000, 52_000).unwrap();
        let outside = ruster_core::FirewallPortRange::new(80, 90).unwrap();
        assert_eq!(sim_port(inside, 51_000), 51_000);
        assert_eq!(sim_port(outside, 443), 80);

        let rule = ruster_core::FirewallRule::new(
            ruster_core::FirewallRuleId(1),
            ruster_core::FirewallInterface::Interface(ingress),
            ruster_core::FirewallInterface::Interface(egress),
            prefix([192, 0, 2, 0], 24),
            prefix([203, 0, 113, 0], 24),
            ruster_core::FirewallProtocol::Tcp,
            inside,
            ruster_core::FirewallPortRange::new(443, 443).unwrap(),
            ruster_core::FirewallAction::AllowStateful,
        );
        let allowed = sim_allowed_transport(
            &[rule],
            ingress,
            egress,
            ip([192, 0, 2, 7]),
            ip([203, 0, 113, 5]),
        )
        .expect("matching TCP rule must allow");
        assert_eq!(allowed.protocol, 6);
        assert_eq!(allowed.source, ip([192, 0, 2, 7]));
        assert_eq!(allowed.source_port, 51_000);
        assert_eq!(allowed.destination_port, 443);
        assert!(sim_allowed_transport(
            &[ruster_core::FirewallRule::new(
                ruster_core::FirewallRuleId(2),
                ruster_core::FirewallInterface::Any,
                ruster_core::FirewallInterface::Any,
                prefix([192, 0, 2, 0], 24),
                prefix([203, 0, 113, 0], 24),
                ruster_core::FirewallProtocol::Udp,
                inside,
                outside,
                ruster_core::FirewallAction::AllowStateful,
            )],
            ingress,
            egress,
            ip([192, 0, 2, 7]),
            ip([203, 0, 113, 5]),
        )
        .is_some());
        assert!(sim_allowed_transport(
            &[ruster_core::FirewallRule::new(
                ruster_core::FirewallRuleId(3),
                ruster_core::FirewallInterface::Any,
                ruster_core::FirewallInterface::Any,
                prefix([127, 0, 0, 0], 8),
                prefix([203, 0, 113, 0], 24),
                ruster_core::FirewallProtocol::Tcp,
                inside,
                outside,
                ruster_core::FirewallAction::AllowStateful,
            )],
            ingress,
            egress,
            ip([192, 0, 2, 7]),
            ip([203, 0, 113, 5]),
        )
        .is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn simulation_source_and_path_selection_reject_local_or_foreign_values() {
        // Protects simulation source selection from using local addresses,
        // wrong interfaces, missing neighbors, or a less-specific route.
        let ingress = ruster_core::IfId(1);
        let neighbor = ruster_core::Neighbor {
            interface: ingress,
            target: ip([192, 0, 2, 9]),
            mac: ruster_core::MacAddress([2, 0, 0, 0, 0, 1]),
        };
        let local = [ruster_core::LocalIpv4Binding {
            interface: ingress,
            address: ip([192, 0, 2, 1]),
        }];
        assert_eq!(
            sim_source_address(Some(&neighbor), ingress, &local),
            Some(ip([192, 0, 2, 9]))
        );
        let local_neighbor = ruster_core::Neighbor {
            target: ip([192, 0, 2, 1]),
            ..neighbor
        };
        assert_eq!(
            sim_source_address(Some(&local_neighbor), ingress, &local),
            Some(ip([192, 0, 2, 2]))
        );
        assert_eq!(
            sim_source_address(
                None,
                ingress,
                &[ruster_core::LocalIpv4Binding {
                    interface: ruster_core::IfId(9),
                    address: ip([192, 0, 2, 1]),
                }]
            ),
            None
        );

        let egress = ruster_core::IfId(2);
        let route = ruster_core::Route::new(ip([203, 0, 113, 0]), 24, egress, None)
            .expect("valid direct test route");
        let route_neighbor = ruster_core::Neighbor {
            interface: egress,
            target: ip([203, 0, 113, 5]),
            mac: ruster_core::MacAddress([2, 0, 0, 0, 0, 2]),
        };
        let paths = sim_paths(&[route], &[route_neighbor], egress, &[]);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].destination, ip([203, 0, 113, 5]));
        assert!(sim_paths(&[route], &[], egress, &[]).is_empty());
        assert!(sim_paths(&[route], &[route_neighbor], ingress, &[]).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[derive(Clone, Copy, Debug)]
    enum QuiescenceTestError {
        Continue,
        Completion,
    }

    #[cfg(target_os = "linux")]
    #[derive(Clone, Copy)]
    enum QuiescenceCheck {
        AlwaysContinue,
        ContinueOnce,
        Ready,
    }

    #[cfg(target_os = "linux")]
    struct EmptyShutdownBatch {
        completion: ruster_core::BatchCompletion<QuiescenceTestError>,
    }

    #[cfg(target_os = "linux")]
    struct EmptyShutdownSlot;

    #[cfg(target_os = "linux")]
    impl ruster_core::PacketSlot for EmptyShutdownSlot {
        fn ingress(&self) -> ruster_core::IfId {
            ruster_core::IfId(0)
        }

        fn bytes_mut(&mut self) -> &mut [u8] {
            &mut []
        }

        fn complete(self, _completion: ruster_core::SlotCompletion) {}
    }

    #[cfg(target_os = "linux")]
    impl ruster_core::PacketBatch for EmptyShutdownBatch {
        type Error = QuiescenceTestError;
        type Slot<'a> = EmptyShutdownSlot;

        fn next_packet(&mut self) -> Option<ruster_core::PacketLease<Self::Slot<'_>>> {
            None
        }

        fn finish(self) -> ruster_core::BatchCompletion<Self::Error> {
            self.completion
        }
    }

    #[cfg(target_os = "linux")]
    struct ShutdownTestIo {
        check: QuiescenceCheck,
        checks: usize,
        invalid_completion: bool,
        completion_error: Option<QuiescenceTestError>,
    }

    #[cfg(target_os = "linux")]
    unsafe impl PublicationBackendAuthority for ShutdownTestIo {}

    #[cfg(target_os = "linux")]
    impl PublicationQuiescenceBackend for ShutdownTestIo {
        type Error = QuiescenceTestError;

        fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {
            match self.check {
                QuiescenceCheck::AlwaysContinue => Err(QuiescenceTestError::Continue),
                QuiescenceCheck::ContinueOnce if self.checks == 0 => {
                    self.checks += 1;
                    Err(QuiescenceTestError::Continue)
                }
                QuiescenceCheck::ContinueOnce | QuiescenceCheck::Ready => Ok(()),
            }
        }

        fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
            PublicationQuiescenceDisposition::ContinueOldIo
        }

        fn quiescence_error_disposition(_error: &Self::Error) -> PublicationQuiescenceDisposition {
            PublicationQuiescenceDisposition::ContinueOldIo
        }
    }

    #[cfg(target_os = "linux")]
    impl PacketIo for ShutdownTestIo {
        type Error = QuiescenceTestError;
        type Batch<'a> = EmptyShutdownBatch;

        fn receive(&mut self, _budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
            Ok(EmptyShutdownBatch {
                completion: ruster_core::BatchCompletion {
                    tx_requested: usize::from(self.invalid_completion),
                    tx_accepted: 0,
                    tx_rejected: 0,
                    recycled: 0,
                    error: self.completion_error,
                },
            })
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shutdown_quiescence_accepts_only_continue_old_io_and_deadline_is_enforced() {
        // Protects shutdown from entering a non-reusable backend state and
        // from treating a completed quiescence check as a timeout.
        let (_owner, mut io) = bind_publication_backend(ShutdownTestIo {
            check: QuiescenceCheck::Ready,
            checks: 0,
            invalid_completion: false,
            completion_error: None,
        })
        .expect("shutdown test binding");
        assert_eq!(
            wait_for_quiescence(&mut io, std::time::Instant::now()),
            Ok(())
        );

        let (_owner, mut io) = bind_publication_backend(ShutdownTestIo {
            check: QuiescenceCheck::AlwaysContinue,
            checks: 0,
            invalid_completion: false,
            completion_error: None,
        })
        .expect("shutdown test binding");
        let error = wait_for_quiescence(&mut io, std::time::Instant::now())
            .expect_err("expired retry must report timeout");
        assert!(error.contains("timed out"));

        let (_owner, mut io) = bind_publication_backend(ShutdownTestIo {
            check: QuiescenceCheck::ContinueOnce,
            checks: 0,
            invalid_completion: true,
            completion_error: None,
        })
        .expect("shutdown test binding");
        let error = wait_for_quiescence(
            &mut io,
            std::time::Instant::now() + std::time::Duration::from_millis(20),
        )
        .expect_err("invalid shutdown accounting must be rejected");
        assert!(error.contains("violated batch accounting invariants"));

        let (_owner, mut io) = bind_publication_backend(ShutdownTestIo {
            check: QuiescenceCheck::ContinueOnce,
            checks: 0,
            invalid_completion: false,
            completion_error: Some(QuiescenceTestError::Completion),
        })
        .expect("shutdown test binding");
        assert_eq!(
            wait_for_quiescence(
                &mut io,
                std::time::Instant::now() + std::time::Duration::from_secs(1)
            ),
            Ok(())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shutdown_quiescence_deadline_is_in_the_future() {
        // Protects the bounded shutdown wait: the first attempt must create a
        // deadline after the configured timeout, never before the wait starts.
        let before = std::time::Instant::now();
        let mut state = ShutdownQuiescenceState::default();
        let deadline = state.begin_wait().expect("first wait creates deadline");
        assert!(
            deadline >= before + std::time::Duration::from_secs(SHUTDOWN_QUIESCENCE_TIMEOUT_SECS)
        );
    }
}
