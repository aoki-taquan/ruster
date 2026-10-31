//! R16 `publication` target: candidate build, dry-run, apply, rollback, and
//! restart sequences through `PublicationSequencer` and `ActivePublication`.
//!
//! A bounded random program builds candidates from reloadable,
//! restart-required, and invalid router variants, dry-runs and applies them
//! (also stale ones, out of order), rolls back to the previous document, and
//! restarts on the same or new storage, with UDP traffic between steps so
//! every apply has live state to keep or flush. The key source either is the
//! simulation source or deliberately repeats the previous generation's keys.
//! Checked properties:
//!
//! - every `candidate` call consumes exactly the next generation, success or
//!   not, and an issued key set never repeats any earlier issued key;
//! - the active generation strictly increases over the whole process, and
//!   an apply or activation commits only a higher generation;
//! - a rejected apply (stale generation, restart-required change) returns
//!   the oracle's typed error and leaves generation, last apply report, every
//!   NAT/firewall slot, and the forwarding behavior unchanged;
//! - `check_successor` mutates nothing, agrees with the following apply, and
//!   reports exact live flush counts; `ApplyPlan::between` lists exactly the
//!   oracle's restart-required reasons;
//! - an applied successor (including a rollback, which is a new generation)
//!   flushes all NAT/firewall state, and its routes, firewall rules, and NAT
//!   port range govern the next packets;
//! - re-activation on the same storage refuses a different storage shape
//!   and a generation that is not above the storage floor.

use std::num::NonZeroU64;

use ruster_config::ValidatedConfigV1;
use ruster_control::{
    ActivationError, ActivePublication, ApplyError, ApplyPlan, FlushCount, FullServiceStorage,
    FullServiceStorageShape, KeySourceError, KeySourceKind, PublicationKeySource, PublicationKeys,
    PublicationSequencer, RestartRequired, SequencerError, SimDeterministicKeySource,
    SuccessorError, ValidatedCandidate,
};
use ruster_core::{
    FirewallHashKey, IfId, Ipv4Address, MonotonicMillis, Nat44TcpHashKey, Nat44UdpHashKey,
};
use ruster_io_sim::{FrameOrigin, SimIo};
use ruster_runtime::{run_tick, PublicationOutcome, RxPhaseReport, TickBudgets, TickObserver};

use super::envelope::{CaseEnvelope, Expected, InvariantFlags, Target};
use super::packets::{source_port, Proto, Segment, SYN};
use super::router::{
    host, host_mac, remote, RouterParams, GATEWAY_MAC, LAN_MAC, PORT_FIRST, PUBLIC,
};
use super::targets::{CaseFailure, V1Rng};

pub const HEADER_LEN: usize = 12;
pub const OP_LEN: usize = 2;
pub const MAX_OPS: usize = 64;
pub const MAX_PENDING: usize = 4;
pub const VARIANTS: u8 = 12;
const TICK_MS: u64 = 10;
type Forwarded = Vec<(IfId, Vec<u8>)>;
type TickOutcome = PublicationOutcome<ApplyError, ruster_io_sim::SimPublicationQuiescenceError>;

/// Start times above this could overflow the bounded time advances.
pub const MAX_START_MS: u64 = 1 << 40;
const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);

mod op {
    pub const BUILD: u8 = 0;
    pub const APPLY: u8 = 1;
    pub const DRY_RUN: u8 = 2;
    pub const PROBE: u8 = 3;
    pub const REPLY: u8 = 4;
    pub const ROLLBACK: u8 = 5;
    pub const RESTART: u8 = 6;
    pub const COUNT: u8 = 7;
}

/// Router variant `index`, or `None` for the unparsable document.
fn variant(index: u8) -> Option<RouterParams> {
    let base = RouterParams::BASE;
    Some(match index {
        0 => base,
        1 => RouterParams {
            alternate_route: true,
            ..base
        },
        2 => RouterParams {
            deny_dns: true,
            ..base
        },
        3 => RouterParams { ports: 8, ..base },
        4 => RouterParams {
            alternate_route: true,
            deny_dns: true,
            ..base
        },
        5 => RouterParams {
            udp_mappings: 16,
            ..base
        },
        6 => RouterParams {
            resolution_interval_ms: 2_000,
            ..base
        },
        7 => RouterParams {
            icmpv4_interval_ms: 200,
            ..base
        },
        8 => RouterParams {
            wan_mac_last: 0x03,
            ..base
        },
        9 => RouterParams {
            offlink_route: true,
            ..base
        },
        10 => RouterParams {
            include_nat: false,
            ..base
        },
        _ => return None,
    })
}

pub fn generate(seed: u64, case_index: u64) -> Result<Vec<u8>, CaseFailure> {
    let mut rng = V1Rng::for_case(Target::Publication, seed, case_index);
    let mut payload = vec![0_u8; HEADER_LEN];
    // Byte 0: key-source mode; for mode 1, byte 2 is the repeat distance
    // (1-3 generations back) and bytes 4..12 the repeat mask.
    payload[0] = u8::from(rng.below(4) == 0);
    if payload[0] == 1 {
        payload[2] = 1 + u8::try_from(rng.below(3)).unwrap();
        payload[4..12].copy_from_slice(&rng.next_u64().to_le_bytes());
    }
    let ops = 4 + rng.below(MAX_OPS - 3);
    payload[1] = u8::try_from(ops).unwrap();
    for _ in 0..ops {
        let kind = match rng.below(32) {
            0..=8 => op::BUILD,
            9..=14 => op::APPLY,
            15..=17 => op::DRY_RUN,
            18..=22 => op::PROBE,
            23..=26 => op::REPLY,
            27..=29 => op::ROLLBACK,
            _ => op::RESTART,
        };
        payload.extend_from_slice(&[kind, rng.byte()]);
    }
    CaseEnvelope {
        target: Target::Publication,
        seed,
        case_index,
        now: 1_000,
        ingress: 0,
        expected: Expected::Invariants(InvariantFlags::default()),
        payload: &payload,
    }
    .encode()
    .map_err(|error| CaseFailure::new(format!("encode publication case: {error}")))
}

/// Simulation key source that, in repeat mode, hands out the keys of the
/// generation `distance` (1-3) back whenever the generation's mask bit is
/// set, so a guard that only compares against the previous key is caught.
#[derive(Clone, Copy)]
struct ScriptedKeys {
    seed: u64,
    repeat: Option<(u64, u64)>,
}

impl ScriptedKeys {
    fn source_generation(&self, generation: NonZeroU64) -> NonZeroU64 {
        match self.repeat {
            Some((mask, distance))
                if generation.get() > distance && mask >> (generation.get() % 64) & 1 == 1 =>
            {
                NonZeroU64::new(generation.get() - distance).unwrap()
            }
            _ => generation,
        }
    }

    fn keys(&self, generation: NonZeroU64) -> Result<KeySet, KeySourceError> {
        let keys = SimDeterministicKeySource::new(self.seed)
            .publication_keys(self.source_generation(generation))?;
        Ok(KeySet::of(&keys))
    }
}

impl PublicationKeySource for ScriptedKeys {
    const KIND: KeySourceKind = KeySourceKind::DeterministicSimulation;

    fn publication_keys(
        &mut self,
        generation: NonZeroU64,
    ) -> Result<PublicationKeys, KeySourceError> {
        SimDeterministicKeySource::new(self.seed)
            .publication_keys(self.source_generation(generation))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KeySet {
    udp: Nat44UdpHashKey,
    tcp: Nat44TcpHashKey,
    firewall: FirewallHashKey,
}

impl KeySet {
    fn of(keys: &PublicationKeys) -> Self {
        Self {
            udp: keys.nat44_udp(),
            tcp: keys.nat44_tcp(),
            firewall: keys.firewall(),
        }
    }

    fn of_candidate(candidate: &ValidatedCandidate) -> Self {
        let authority = candidate.authority();
        Self {
            udp: authority.nat44_udp_hash_key(),
            tcp: authority.nat44_tcp_hash_key(),
            firewall: authority.firewall_config().hash_key(),
        }
    }

    fn shares_any(&self, other: &Self) -> bool {
        self.udp == other.udp || self.tcp == other.tcp || self.firewall == other.firewall
    }
}

struct Built {
    variant: u8,
    params: RouterParams,
    config: ValidatedConfigV1,
    candidate: ValidatedCandidate,
}

#[derive(Clone, Copy, Debug)]
struct ProbeFlow {
    host: usize,
    internal_port: u16,
    remote: Ipv4Address,
    remote_port: u16,
    public_port: u16,
}

struct World<'ops> {
    ops: &'ops [u8],
    cursor: usize,
    sequencer: PublicationSequencer<ScriptedKeys>,
    oracle_keys: ScriptedKeys,
    issued: Vec<KeySet>,
    last_issued: Option<NonZeroU64>,
    pending: Vec<Built>,
    /// Variants of every activated or applied generation, in order.
    history: Vec<u8>,
    activated: Vec<NonZeroU64>,
    active_params: RouterParams,
    /// The validated document of the active generation (plan input).
    active_config: Option<ValidatedConfigV1>,
    flows: Vec<ProbeFlow>,
    flushed: Vec<ProbeFlow>,
    now: u64,
    budgets: TickBudgets,
    coverage: PublicationCoverage,
}

struct Restart {
    candidate: Built,
    stale: Option<Built>,
}

/// How often each checked property was actually exercised.
#[derive(Clone, Copy, Debug, Default)]
pub struct PublicationCoverage {
    pub applied: u64,
    pub rollbacks: u64,
    pub stale_rejected: u64,
    pub restart_rejected: u64,
    pub dry_run_ok: u64,
    pub dry_run_rejected: u64,
    pub restarts: u64,
    pub reactivation_refused: u64,
    pub key_reuse_refused: u64,
    /// Key reuse from two or three generations back was refused.
    pub far_key_reuse_refused: u64,
    pub bridge_refused: u64,
    pub invalid_refused: u64,
    pub replies_translated: u64,
    pub flushed_replies_refused: u64,
    pub probes_filtered: u64,
}

impl PublicationCoverage {
    pub fn add(&mut self, other: Self) {
        let pairs = [
            (&mut self.applied, other.applied),
            (&mut self.rollbacks, other.rollbacks),
            (&mut self.stale_rejected, other.stale_rejected),
            (&mut self.restart_rejected, other.restart_rejected),
            (&mut self.dry_run_ok, other.dry_run_ok),
            (&mut self.dry_run_rejected, other.dry_run_rejected),
            (&mut self.restarts, other.restarts),
            (&mut self.reactivation_refused, other.reactivation_refused),
            (&mut self.key_reuse_refused, other.key_reuse_refused),
            (&mut self.far_key_reuse_refused, other.far_key_reuse_refused),
            (&mut self.bridge_refused, other.bridge_refused),
            (&mut self.invalid_refused, other.invalid_refused),
            (&mut self.replies_translated, other.replies_translated),
            (
                &mut self.flushed_replies_refused,
                other.flushed_replies_refused,
            ),
            (&mut self.probes_filtered, other.probes_filtered),
        ];
        for (total, value) in pairs {
            *total += value;
        }
    }
}

pub fn run(case: &CaseEnvelope<'_>) -> Result<(), CaseFailure> {
    run_with_coverage(case).map(|_| ())
}

pub fn run_with_coverage(case: &CaseEnvelope<'_>) -> Result<PublicationCoverage, CaseFailure> {
    if case.now > MAX_START_MS {
        return Err(CaseFailure::new("publication start time is out of range"));
    }
    let Expected::Invariants(flags) = case.expected else {
        return Err(CaseFailure::new(
            "publication target has a non-invariant expected value",
        ));
    };
    if flags.bits() != 0 {
        return Err(CaseFailure::new(
            "publication target accepts no invariant flags",
        ));
    }
    let payload = case.payload;
    if payload.len() < HEADER_LEN
        || payload[0] > 1
        || payload[3] != 0
        || (payload[0] == 0 && (payload[2] != 0 || payload[4..12] != [0; 8]))
        || (payload[0] == 1 && !(1..=3).contains(&payload[2]))
    {
        return Err(CaseFailure::new("publication payload header is malformed"));
    }
    let ops = usize::from(payload[1]);
    if ops > MAX_OPS || payload.len() != HEADER_LEN + ops * OP_LEN {
        return Err(CaseFailure::new(
            "publication op count does not match payload",
        ));
    }
    let ops = &payload[HEADER_LEN..];
    if ops.chunks_exact(OP_LEN).any(|chunk| chunk[0] >= op::COUNT) {
        return Err(CaseFailure::new("publication op kind is unknown"));
    }
    let repeat = (payload[0] == 1).then(|| {
        (
            u64::from_le_bytes(payload[4..12].try_into().unwrap()),
            u64::from(payload[2]),
        )
    });
    let base = RouterParams::BASE.validated()?;
    let tick = base.tick();
    let mut world = World {
        ops,
        cursor: 0,
        sequencer: PublicationSequencer::new(ScriptedKeys {
            seed: case.seed,
            repeat,
        }),
        oracle_keys: ScriptedKeys {
            seed: case.seed,
            repeat,
        },
        issued: Vec::new(),
        last_issued: None,
        pending: Vec::new(),
        history: Vec::new(),
        activated: Vec::new(),
        active_params: RouterParams::BASE,
        active_config: None,
        flows: Vec::new(),
        flushed: Vec::new(),
        now: case.now,
        budgets: TickBudgets {
            rx: usize::try_from(tick.rx).unwrap(),
            resolution_timer_scans: usize::try_from(tick.resolution_timer_scans).unwrap(),
            failure_dispatch_scans: usize::try_from(tick.failure_dispatch_scans).unwrap(),
            generated_arp: usize::try_from(tick.generated_arp).unwrap(),
            generated_icmpv4: usize::try_from(tick.generated_icmpv4).unwrap(),
        },
        coverage: PublicationCoverage::default(),
    };
    let first = world
        .build(0)?
        .ok_or_else(|| CaseFailure::new("generation 1 of the base router was not issued"))?;
    let mut shape = first.candidate.storage_shape();
    let mut storage = FullServiceStorage::new(shape)
        .map_err(|error| CaseFailure::new(format!("publication storage: {error:?}")))?;
    let mut next = first;
    loop {
        let restart = world.segment(&mut storage, next)?;
        let Some(Restart { candidate, stale }) = restart else {
            return Ok(world.coverage);
        };
        world.coverage.restarts += 1;
        let new_shape = candidate.candidate.storage_shape();
        if new_shape == shape {
            if let Some(stale) = stale {
                world.reactivate_refused(&mut storage, shape, stale)?;
            }
        } else {
            shape = new_shape;
            storage = FullServiceStorage::new(shape)
                .map_err(|error| CaseFailure::new(format!("publication storage: {error:?}")))?;
        }
        next = candidate;
    }
}

impl World<'_> {
    fn fail(&self, detail: impl std::fmt::Display) -> CaseFailure {
        CaseFailure::new(format!(
            "op={} generation={:?} {detail}",
            self.cursor.saturating_sub(1),
            self.activated.last().map(|generation| generation.get())
        ))
    }

    /// Builds `variant` through the sequencer and checks the issuance
    /// properties. Returns `None` when the build is (correctly) refused.
    fn build(&mut self, variant_index: u8) -> Result<Option<Built>, CaseFailure> {
        let Some(params) = variant(variant_index) else {
            // Unparsable document: never reaches the sequencer.
            let parsed = ruster_config::parse(b"schema-version = 1\n[[interfaces]\n");
            if parsed.is_ok() {
                return Err(self.fail("unparsable router document was accepted"));
            }
            self.coverage.invalid_refused += 1;
            return Ok(None);
        };
        let config = match params.validated() {
            Ok(config) => config,
            Err(_) if params.offlink_route => {
                self.coverage.invalid_refused += 1;
                return Ok(None);
            }
            Err(failure) => return Err(failure),
        };
        if params.offlink_route {
            return Err(self.fail("off-link route variant passed validation"));
        }
        let generation = match self.last_issued {
            None => NonZeroU64::MIN,
            Some(last) => last.checked_add(1).unwrap(),
        };
        if self.sequencer.next_generation() != Ok(generation) {
            return Err(self.fail("sequencer next generation is not last issued + 1"));
        }
        let predicted = self
            .oracle_keys
            .keys(generation)
            .map_err(|error| self.fail(format!("oracle keys: {error:?}")))?;
        let result = self.sequencer.candidate(&config);
        if self.sequencer.last_issued() != Some(generation) {
            return Err(self.fail("candidate did not consume exactly one generation"));
        }
        self.last_issued = Some(generation);
        let reused = self
            .issued
            .iter()
            .any(|issued| issued.shares_any(&predicted));
        match result {
            Err(SequencerError::Bridge(_)) if !params.include_nat => {
                self.coverage.bridge_refused += 1;
                Ok(None)
            }
            Err(SequencerError::KeyReused(_)) if params.include_nat && reused => {
                self.coverage.key_reuse_refused += 1;
                if self
                    .oracle_keys
                    .repeat
                    .is_some_and(|(_, distance)| distance > 1)
                {
                    self.coverage.far_key_reuse_refused += 1;
                }
                Ok(None)
            }
            Err(error) => Err(self.fail(format!("unexpected sequencer error {error:?}"))),
            Ok(_) if !params.include_nat => {
                Err(self.fail("candidate without NAT services was issued"))
            }
            Ok(_) if reused => Err(self.fail("candidate reusing an issued key was issued")),
            Ok(candidate) => {
                if candidate.generation() != generation {
                    return Err(self.fail("candidate generation is not the consumed generation"));
                }
                let keys = KeySet::of_candidate(&candidate);
                if keys != predicted {
                    return Err(self.fail("candidate keys differ from the key source"));
                }
                if self.issued.iter().any(|issued| issued.shares_any(&keys)) {
                    return Err(self.fail("issued key repeated"));
                }
                self.issued.push(keys);
                Ok(Some(Built {
                    variant: variant_index,
                    params,
                    config,
                    candidate,
                }))
            }
        }
    }

    fn record_activation(
        &mut self,
        generation: NonZeroU64,
        variant: u8,
    ) -> Result<(), CaseFailure> {
        if self
            .activated
            .last()
            .is_some_and(|last| generation <= *last)
        {
            return Err(self.fail("active generation did not strictly increase"));
        }
        self.activated.push(generation);
        self.history.push(variant);
        self.flushed.append(&mut self.flows);
        Ok(())
    }

    /// Restart-required reasons of `next` against the active document, in
    /// `validate_successor` order.
    fn restart_reasons(
        &self,
        active_shape: FullServiceStorageShape,
        next: &Built,
    ) -> Vec<RestartRequired> {
        let current = self.active_params;
        let mut reasons = Vec::new();
        if next.candidate.storage_shape() != active_shape {
            reasons.push(RestartRequired::StorageShape);
        }
        if next.params.resolution_interval_ms != current.resolution_interval_ms {
            reasons.push(RestartRequired::ResolutionPolicy);
        }
        if next.params.icmpv4_interval_ms != current.icmpv4_interval_ms {
            reasons.push(RestartRequired::Icmpv4ErrorPolicy);
        }
        if next.params.wan_mac_last != current.wan_mac_last {
            reasons.push(RestartRequired::Interfaces);
        }
        reasons
    }

    fn expected_apply(
        &self,
        active: &ActivePublication<'_, SimIo>,
        next: &Built,
    ) -> Result<(), ApplyError> {
        if next.candidate.generation() <= active.generation() {
            return Err(ApplyError::Successor(
                SuccessorError::GenerationNotIncreasing,
            ));
        }
        match self.restart_reasons(active.storage_shape(), next).first() {
            Some(reason) => Err(ApplyError::RestartRequired(*reason)),
            None => Ok(()),
        }
    }

    fn segment(
        &mut self,
        storage: &mut FullServiceStorage,
        initial: Built,
    ) -> Result<Option<Restart>, CaseFailure> {
        let generation = initial.candidate.generation();
        let variant_index = initial.variant;
        let params = initial.params;
        self.active_config = Some(initial.config);
        let mut active = ActivePublication::<SimIo>::new(storage, initial.candidate)
            .map_err(|error| self.fail(format!("activation refused: {error:?}")))?;
        if active.generation() != generation || active.last_apply().is_some() {
            return Err(self.fail("activation did not install the candidate"));
        }
        self.active_params = params;
        self.record_activation(generation, variant_index)?;
        let mut io = SimIo::new();
        let mut observer = TickObserver::default();
        while self.cursor < self.ops.len() / OP_LEN {
            let index = self.cursor * OP_LEN;
            let (kind, arg) = (self.ops[index], self.ops[index + 1]);
            self.cursor += 1;
            match kind {
                op::BUILD => {
                    if let Some(built) = self.build(arg % VARIANTS)? {
                        if self.pending.len() == MAX_PENDING {
                            self.pending.remove(0);
                        }
                        self.pending.push(built);
                    }
                }
                op::APPLY => {
                    if !self.pending.is_empty() {
                        let built = self.pending.remove(usize::from(arg) % self.pending.len());
                        self.apply(&mut active, &mut io, &mut observer, built)?;
                    }
                }
                op::DRY_RUN => {
                    if !self.pending.is_empty() {
                        let index = usize::from(arg) % self.pending.len();
                        self.dry_run(&mut active, index)?;
                        if arg & 0x80 != 0 {
                            let built = self.pending.remove(index);
                            self.apply(&mut active, &mut io, &mut observer, built)?;
                        }
                    }
                }
                op::PROBE => self.probe(&mut active, &mut io, &mut observer, arg)?,
                op::REPLY => self.reply(&mut active, &mut io, &mut observer, arg)?,
                op::ROLLBACK => {
                    if self.history.len() >= 2 {
                        let previous = self.history[self.history.len() - 2];
                        if let Some(built) = self.build(previous)? {
                            self.apply(&mut active, &mut io, &mut observer, built)?;
                            self.coverage.rollbacks += 1;
                        }
                    }
                }
                op::RESTART => {
                    let Some(candidate) = self.build(arg % VARIANTS)? else {
                        continue;
                    };
                    let floor = active.generation();
                    let stale = self
                        .pending
                        .iter()
                        .position(|built| built.candidate.generation() <= floor)
                        .map(|index| self.pending.remove(index));
                    drop(active);
                    return Ok(Some(Restart { candidate, stale }));
                }
                _ => return Err(self.fail("unknown publication op")),
            }
            if active.generation() != *self.activated.last().unwrap() {
                return Err(self.fail("active generation drifted"));
            }
        }
        Ok(None)
    }

    fn reactivate_refused(
        &mut self,
        storage: &mut FullServiceStorage,
        shape: FullServiceStorageShape,
        stale: Built,
    ) -> Result<(), CaseFailure> {
        let expected = if stale.candidate.storage_shape() != shape {
            ActivationError::StorageShapeMismatch
        } else {
            ActivationError::GenerationNotAboveFloor
        };
        match ActivePublication::<SimIo>::new(storage, stale.candidate) {
            Err(error) if error == expected => {
                self.coverage.reactivation_refused += 1;
                Ok(())
            }
            Err(error) => Err(self.fail(format!(
                "stale re-activation refused with {error:?}, expected {expected:?}"
            ))),
            Ok(_) => Err(self.fail("stale candidate re-activated on the same storage")),
        }
    }

    fn snapshot(active: &ActivePublication<'_, SimIo>) -> Observed {
        Observed {
            generation: active.generation(),
            last_apply: active.last_apply(),
            udp_mappings: active.nat44_udp().mappings().to_vec(),
            udp_peers: active.nat44_udp().peers().to_vec(),
            tcp_mappings: active.nat44_tcp().mappings().to_vec(),
            tcp_sessions: active.nat44_tcp().sessions().to_vec(),
            firewall: active.firewall().states().to_vec(),
            resolution: [
                active.resolution().pending_states(),
                active.resolution().pending_actions(),
                active.resolution().dynamic_neighbor_count(),
                active.resolution().pending_failure_holds(),
            ],
            icmpv4_actions: active.icmpv4_errors().pending_actions(),
            counters: Counters {
                resolution: active.resolution().counters(),
                resolution_failures: active.resolution().failure_counters(),
                icmpv4_errors: active.icmpv4_errors().counters(),
                nat44_udp: active.nat44_udp().counters(),
                nat44_tcp: active.nat44_tcp().counters(),
                firewall: active.firewall().counters(),
            },
            bindings: Bindings {
                storage_shape: active.storage_shape(),
                nat44_udp: active.nat44_udp().config(),
                nat44_tcp: active.nat44_tcp().config(),
                resolution_policy: active.resolution().policy(),
                icmpv4_error_policy: active.icmpv4_errors().policy(),
                firewall_pristine: active.firewall().is_pristine(),
            },
        }
    }

    fn check_plan(
        &self,
        next: &Built,
        active: &ActivePublication<'_, SimIo>,
    ) -> Result<(), CaseFailure> {
        let current = self
            .active_config
            .as_ref()
            .ok_or_else(|| self.fail("no active document"))?;
        let plan = ApplyPlan::between(current, &next.config)
            .map_err(|error| self.fail(format!("plan failed: {error:?}")))?;
        let expected = self.restart_reasons(active.storage_shape(), next);
        if plan.restart_required() != expected.as_slice() {
            return Err(self.fail(format!(
                "plan restart reasons {:?} differ from oracle {expected:?}",
                plan.restart_required()
            )));
        }
        Ok(())
    }

    fn dry_run(
        &mut self,
        active: &mut ActivePublication<'_, SimIo>,
        index: usize,
    ) -> Result<(), CaseFailure> {
        let before = Self::snapshot(active);
        let built = &self.pending[index];
        self.check_plan(built, active)?;
        let expected = self.expected_apply(active, built);
        let result = active.check_successor(&built.candidate);
        let after = Self::snapshot(active);
        if before != after {
            return Err(self.fail("check_successor changed the live publication"));
        }
        match (&result, expected) {
            (Ok(check), Ok(())) => {
                if check.generation != built.candidate.generation()
                    || check.previous_generation != active.generation()
                {
                    return Err(self.fail("dry-run generations are wrong"));
                }
                fn exact<T: Copy>(slots: &[T], occupied: impl Fn(T) -> bool) -> FlushCount {
                    FlushCount::Exact(slots.iter().filter(|slot| occupied(**slot)).count())
                }
                let flush = check.flush;
                if flush.nat44_udp_mappings
                    != exact(&before.udp_mappings, |slot| slot.is_occupied())
                    || flush.nat44_udp_peers != exact(&before.udp_peers, |slot| slot.is_occupied())
                    || flush.nat44_tcp_mappings
                        != exact(&before.tcp_mappings, |slot| slot.is_occupied())
                    || flush.nat44_tcp_sessions
                        != exact(&before.tcp_sessions, |slot| slot.is_occupied())
                    || flush.firewall_flows != exact(&before.firewall, |slot| slot.is_occupied())
                {
                    return Err(self.fail("dry-run flush counts are not the live counts"));
                }
                self.coverage.dry_run_ok += 1;
                Ok(())
            }
            (Err(error), Err(expected)) if *error == expected => {
                self.coverage.dry_run_rejected += 1;
                Ok(())
            }
            (result, expected) => Err(self.fail(format!(
                "dry-run returned {result:?}, oracle expected {expected:?}"
            ))),
        }
    }

    fn tick(
        &mut self,
        active: &mut ActivePublication<'_, SimIo>,
        io: &mut SimIo,
        observer: &mut TickObserver,
        candidate: Option<ValidatedCandidate>,
        injected: usize,
    ) -> Result<(TickOutcome, Forwarded), CaseFailure> {
        self.now += TICK_MS;
        let report = run_tick(
            active,
            candidate,
            io,
            MonotonicMillis(self.now),
            self.budgets,
            observer,
        );
        match &report.rx {
            RxPhaseReport::Completed(rx) if rx.received == injected => {}
            RxPhaseReport::Skipped(_) if injected == 0 => {}
            RxPhaseReport::Completed(rx) if injected == 0 && rx.received == 0 => {}
            other => return Err(self.fail(format!("rx phase {other:?} for {injected} frames"))),
        }
        let mut forwarded = Vec::new();
        while let Some(frame) = io.pop_tx() {
            if frame.origin != FrameOrigin::Generated {
                forwarded.push((frame.egress, frame.bytes));
            }
        }
        while io.pop_recycled().is_some() {}
        while io.pop_generated_recycled().is_some() {}
        Ok((report.publication, forwarded))
    }

    fn apply(
        &mut self,
        active: &mut ActivePublication<'_, SimIo>,
        io: &mut SimIo,
        observer: &mut TickObserver,
        built: Built,
    ) -> Result<(), CaseFailure> {
        self.check_plan(&built, active)?;
        let expected = self.expected_apply(active, &built);
        let before = Self::snapshot(active);
        let generation = built.candidate.generation();
        let (outcome, forwarded) = self.tick(active, io, observer, Some(built.candidate), 0)?;
        if !forwarded.is_empty() {
            return Err(self.fail("apply tick forwarded frames without input"));
        }
        let after = Self::snapshot(active);
        match (outcome, expected) {
            (PublicationOutcome::Rejected(error), Err(expected)) if error == expected => {
                if before != after {
                    return Err(self.fail(format!(
                        "rejected apply ({error:?}) changed the live publication"
                    )));
                }
                if matches!(error, ApplyError::RestartRequired(_)) {
                    self.coverage.restart_rejected += 1;
                } else {
                    self.coverage.stale_rejected += 1;
                }
                Ok(())
            }
            (PublicationOutcome::Applied, Ok(())) => {
                let report = active
                    .last_apply()
                    .ok_or_else(|| self.fail("applied without a report"))?;
                if active.generation() != generation
                    || report.generation != generation
                    || report.previous_generation != before.generation
                {
                    return Err(self.fail("applied generation/report mismatch"));
                }
                if after.udp_mappings.iter().any(|slot| slot.is_occupied())
                    || after.udp_peers.iter().any(|slot| slot.is_occupied())
                    || after.tcp_mappings.iter().any(|slot| slot.is_occupied())
                    || after.tcp_sessions.iter().any(|slot| slot.is_occupied())
                    || after.firewall.iter().any(|slot| slot.is_occupied())
                {
                    return Err(self.fail("applied successor kept NAT/firewall state"));
                }
                self.active_params = built.params;
                self.active_config = Some(built.config);
                self.coverage.applied += 1;
                self.record_activation(generation, built.variant)
            }
            (outcome, expected) => Err(self.fail(format!(
                "apply of variant {} produced {outcome:?}, oracle expected {expected:?}",
                built.variant
            ))),
        }
    }

    fn probe(
        &mut self,
        active: &mut ActivePublication<'_, SimIo>,
        io: &mut SimIo,
        observer: &mut TickObserver,
        arg: u8,
    ) -> Result<(), CaseFailure> {
        let params = self.active_params;
        let host_index = usize::from(arg) % 2;
        let internal_port = 6_000 + u16::from(arg) % 2;
        let (remote_ip, remote_port, allowed) = match (arg >> 1) % 3 {
            0 => (remote(0, false), 123, true),
            1 => (remote(1, false), 53, !params.deny_dns),
            _ => (remote(2, true), 123, params.alternate_route),
        };
        let id = u16::from(arg) | 0x100;
        let bytes = Segment {
            proto: Proto::Udp,
            eth_source: host_mac(host_index),
            eth_destination: LAN_MAC,
            source: host(host_index),
            destination: remote_ip,
            source_port: internal_port,
            destination_port: remote_port,
            identification: id,
            ttl: 64,
            flags: SYN,
        }
        .build()?;
        io.inject(LAN, bytes);
        let (_, forwarded) = self.tick(active, io, observer, None, 1)?;
        match (forwarded.as_slice(), allowed) {
            ([], false) => {
                self.coverage.probes_filtered += 1;
                Ok(())
            }
            ([(egress, bytes)], true) => {
                let public_port = source_port(bytes).unwrap_or(0);
                if *egress != WAN
                    || bytes[26..30] != PUBLIC.octets()
                    || bytes[30..34] != remote_ip.octets()
                    || bytes[0..6] != GATEWAY_MAC.0
                    || bytes[6..12] != params.wan_mac().0
                    || !(PORT_FIRST..=params.port_last()).contains(&public_port)
                {
                    return Err(self.fail(format!(
                        "probe is not translated by the active document (port {public_port})"
                    )));
                }
                let flow = ProbeFlow {
                    host: host_index,
                    internal_port,
                    remote: remote_ip,
                    remote_port,
                    public_port,
                };
                if !self.flows.iter().any(|known| {
                    known.host == flow.host
                        && known.internal_port == flow.internal_port
                        && known.remote == flow.remote
                }) {
                    self.flows.push(flow);
                }
                Ok(())
            }
            (forwarded, allowed) => Err(self.fail(format!(
                "probe forwarded {} frames, active document allows={allowed}",
                forwarded.len()
            ))),
        }
    }

    fn reply(
        &mut self,
        active: &mut ActivePublication<'_, SimIo>,
        io: &mut SimIo,
        observer: &mut TickObserver,
        arg: u8,
    ) -> Result<(), CaseFailure> {
        let (flow, live) = if !self.flows.is_empty() {
            (self.flows[usize::from(arg) % self.flows.len()], true)
        } else if !self.flushed.is_empty() {
            (self.flushed[usize::from(arg) % self.flushed.len()], false)
        } else {
            return Ok(());
        };
        let id = u16::from(arg) | 0x200;
        let bytes = Segment {
            proto: Proto::Udp,
            eth_source: GATEWAY_MAC,
            eth_destination: self.active_params.wan_mac(),
            source: flow.remote,
            destination: PUBLIC,
            source_port: flow.remote_port,
            destination_port: flow.public_port,
            identification: id,
            ttl: 64,
            flags: SYN,
        }
        .build()?;
        io.inject(WAN, bytes);
        let (_, forwarded) = self.tick(active, io, observer, None, 1)?;
        match (forwarded.as_slice(), live) {
            ([], false) => {
                self.coverage.flushed_replies_refused += 1;
                Ok(())
            }
            ([(egress, bytes)], true) => {
                if *egress != LAN
                    || bytes[30..34] != host(flow.host).octets()
                    || bytes[36..38] != flow.internal_port.to_be_bytes()
                    || bytes[0..6] != host_mac(flow.host).0
                {
                    return Err(self.fail("reply is not de-translated to the probe endpoint"));
                }
                self.coverage.replies_translated += 1;
                Ok(())
            }
            (forwarded, live) => Err(self.fail(format!(
                "reply forwarded {} frames, state live={live} (flushed state must not admit)",
                forwarded.len()
            ))),
        }
    }
}

/// Cumulative runtime counters; a rejected apply or a dry-run must not
/// change them.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Counters {
    resolution: ruster_core::ResolutionCounters,
    resolution_failures: ruster_core::ResolutionFailureCounters,
    icmpv4_errors: ruster_core::Icmpv4ErrorCounters,
    nat44_udp: ruster_core::Nat44UdpCounters,
    nat44_tcp: ruster_core::Nat44TcpCounters,
    firewall: ruster_core::FirewallCounters,
}

/// Publication-bound runtime configuration readable through public
/// accessors (the firewall binding itself is private; its pristine flag
/// and the counters stand in for it).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Bindings {
    storage_shape: FullServiceStorageShape,
    nat44_udp: ruster_core::Nat44UdpConfig,
    nat44_tcp: ruster_core::Nat44TcpConfig,
    resolution_policy: ruster_core::ResolutionPolicy,
    icmpv4_error_policy: ruster_core::Icmpv4ErrorPolicy,
    firewall_pristine: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct Observed {
    generation: NonZeroU64,
    last_apply: Option<ruster_control::ApplyReport>,
    udp_mappings: Vec<ruster_core::Nat44UdpMappingSlot>,
    udp_peers: Vec<ruster_core::Nat44UdpPeerSlot>,
    tcp_mappings: Vec<ruster_core::Nat44TcpMappingSlot>,
    tcp_sessions: Vec<ruster_core::Nat44TcpSessionSlot>,
    firewall: Vec<ruster_core::FirewallStateSlot>,
    resolution: [usize; 4],
    icmpv4_actions: usize,
    counters: Counters,
    bindings: Bindings,
}
