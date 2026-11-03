//! SIGHUP reload of `ruster run` (M2 S10b).
//!
//! The SIGHUP handler only stores a flag ([`crate::signal`]); the run loop
//! takes it at a tick boundary when no reload is in flight (so SIGHUPs
//! that arrive meanwhile coalesce into one later reload) and hands it to
//! the reload worker thread `ruster-reload` ([`ReloadWorker`], H7), which
//! runs the production config path and the document plan off the router
//! thread, before anything changes ([`Preparer::prepare`]):
//!
//! 1. re-read and validate the `--config` file exactly like startup
//!    ([`crate::config_cmd::load_validated_regular`]: the same limits, and
//!    a non-regular file is refused so a FIFO cannot block the worker);
//! 2. build the successor candidate with the production sequencer (a
//!    fresh generation and fresh keys; a refused or failed reload still
//!    consumes that generation, as in `run-sim`);
//! 3. [`ApplyPlan::between`] the active generation's document and the
//!    new one: any restart-required reason (backend, device, port set,
//!    UMEM or ring shape: [`RestartRequired::Backend`]; interface ids or
//!    MACs; storage shape; resolution or ICMPv4 error policy) refuses the
//!    reload.
//!
//! The router thread keeps ticking (RX included) meanwhile and only takes
//! the answer with a non-blocking `try_recv` ([`Reloader::poll`]). A ready
//! successor then gets the live part of the dry run on the router thread,
//! [`ActivePublication::check_successor`] (successor validation and the
//! runtime preflights: a few comparisons, no I/O, no mutation; the same
//! check [`ApplyPlan::for_active`] makes), whose failure fails the reload
//! (`stage=dry-run`).
//!
//! The sequencer and the documents live on the worker thread for the
//! whole run ([`Preparer`]): one owner, no lock. The router thread keeps
//! only the active document's tick budgets and sweep warnings, and tells
//! the worker when a successor was applied so its document becomes the
//! base of the next plan.
//!
//! A reload that passes is pending. The loop then applies it at the next
//! tick boundary at which the backend is quiescent (no lease, no staged
//! handoff, no TX in flight: completions of frames rewritten under the old
//! generation are awaited), by handing the candidate to `run_tick`'s
//! publication phase, which runs before RX: no batch or lease is open
//! across the switch. While a reload waits, the loop holds RX back (the
//! quiescence probe itself reaps and kicks), at most
//! [`RELOAD_QUIESCE_MS`]; then the reload fails and normal ticks resume.
//!
//! Every outcome is failure atomic: on a refusal or failure the old
//! generation, its runtimes, and its state keep running unchanged. An
//! applied reload follows the control-plane contract (PUB-006,
//! RELOAD-CARRY): the new generation flushes pending resolution and ICMPv4
//! errors, carries NAT44 mappings and sessions, firewall flows (re-evaluated
//! against changed rules), and learned ARP neighbors that the new document
//! does not invalidate (`[reload] state = "carry"`, the default), or flushes
//! all of them with fresh hash keys (`state = "flush"`), and keeps
//! cumulative counters; the flushed and carried counts and each family's
//! outcome are printed. The tick budgets of the new document apply from the
//! next tick.
//!
//! A reload still preparing when the run ends is not waited for: it fails
//! as `stage=prepare code=STOPPED` (`stage=quiesce code=STOPPED` while
//! pending), so `requested == applied + refused + failed` at every exit.
//! A preparation has no time bound of its own (the worker cannot be
//! interrupted); further SIGHUPs wait for it.

use std::fmt;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};

use ruster_config::ValidatedConfigV1;
use ruster_control::{
    ActivePublication, ApplyError, ApplyPlan, ProductionKeySource, ProductionSequencer,
    RestartRequired, SequencerError, ValidatedCandidate,
};
use ruster_core::{
    FieldValue, FieldVisitor, MonotonicMillis, ObservableFields, PublicationQuiescence,
};
use ruster_runtime::{ApplyCarryCounts, ApplyFlushCounts, TickBudgets};

use crate::config_cmd::{self, LoadError, SweepSlow};

use super::ops::{Fallback, Ops};
use super::output::SpawnError;
use super::privileges::DropFailure;
use super::startup::token;
#[cfg(test)]
use super::workers::lockstep_wait;
use super::workers::{spawn, Worker};

/// Longest wait for backend quiescence before a pending reload fails.
pub const RELOAD_QUIESCE_MS: u64 = 200;

/// A preparation running this long gets one warning line (the worker
/// cannot be interrupted, and later SIGHUPs wait for it).
pub const RELOAD_PREPARE_WARN_MS: u64 = 10_000;

/// Where a reload reads the next document.
pub trait ConfigSource {
    fn load(&mut self) -> Result<ValidatedConfigV1, LoadError>;
}

/// The `--config` file.
pub struct ConfigFile {
    pub path: PathBuf,
    /// `--strict-config-perms`.
    pub strict: bool,
}

impl ConfigSource for ConfigFile {
    fn load(&mut self) -> Result<ValidatedConfigV1, LoadError> {
        config_cmd::load_validated_regular(&self.path, self.strict)
    }
}

/// Cumulative reload counters (`reload.*`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReloadCounters {
    pub requested: u64,
    pub applied: u64,
    pub refused: u64,
    pub failed: u64,
    /// How long the reload in preparation has run, as of the last loop
    /// iteration (0 when none is preparing): a gauge.
    pub preparing_ms: u64,
}

impl ObservableFields for ReloadCounters {
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        const SECTION: &str = "reload";
        visitor.field(SECTION, "requested", FieldValue::Count(self.requested));
        visitor.field(SECTION, "applied", FieldValue::Count(self.applied));
        visitor.field(SECTION, "refused", FieldValue::Count(self.refused));
        visitor.field(SECTION, "failed", FieldValue::Count(self.failed));
        visitor.field(
            SECTION,
            "preparing_ms",
            FieldValue::Count(self.preparing_ms),
        );
    }
}

/// How one reload ended. Value-free.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReloadOutcome {
    Applied {
        /// `None` if the commit's report was missing (an invariant
        /// violation: the run then ends with exit 1).
        previous: Option<NonZeroU64>,
        generation: NonZeroU64,
        flush: Option<ApplyFlushCounts>,
        /// Boxed (cold path, once per applied reload) to keep the enum small.
        carry: Option<Box<ApplyCarryCounts>>,
        counts: DocumentCounts,
    },
    /// Restart-required reasons, in plan order.
    Refused {
        reasons: Box<[RestartRequired]>,
        generation: NonZeroU64,
    },
    Failed {
        /// `stage=<stage> code=<code>[ path=<schema path>...]`.
        detail: String,
        generation: NonZeroU64,
    },
    /// The live dry run passed; the successor waits for quiescence. Not an
    /// end of the reload: `Applied`, `Refused`, or `Failed` follows.
    Checked {
        generation: NonZeroU64,
        carried: ruster_control::CarriedCounts,
    },
}

impl fmt::Display for ReloadOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Applied {
                previous,
                generation,
                flush,
                carry,
                counts,
            } => {
                write!(
                    formatter,
                    "reload applied: generation={generation} previous="
                )?;
                match previous {
                    Some(previous) => write!(formatter, "{previous}")?,
                    None => formatter.write_str("unknown")?,
                }
                write!(
                    formatter,
                    "; interfaces={} addresses={} routes={} neighbors={} firewall-rules={} \
                     nat44-ports={}; ",
                    counts.interfaces,
                    counts.addresses,
                    counts.routes,
                    counts.neighbors,
                    counts.firewall_rules,
                    counts.nat44_ports,
                )?;
                match flush.zip(carry.as_deref().copied()) {
                    Some((flush, carry)) => {
                        write!(
                            formatter,
                            "flushed dynamic-neighbors={} resolution-states={} \
                             nat44-udp-mappings={} nat44-tcp-sessions={} firewall-flows={}; ",
                            flush.dynamic_neighbors,
                            flush.resolution_states,
                            flush.nat44_udp_mappings,
                            flush.nat44_tcp_sessions,
                            flush.firewall_flows,
                        )?;
                        let outcomes = carry.outcomes;
                        write!(
                            formatter,
                            "carried dynamic-neighbors={} nat44-udp-mappings={} \
                             nat44-tcp-sessions={} nat44-icmp-mappings={} firewall-flows={} \
                             firewall-revoked={}; state arp={} nat44-udp={} nat44-tcp={} \
                             nat44-icmp={} firewall={}",
                            carry.dynamic_neighbors,
                            carry.nat44_udp_mappings,
                            carry.nat44_tcp_sessions,
                            carry.nat44_icmp_mappings,
                            carry.firewall_flows,
                            carry.firewall_flows_revoked,
                            outcomes.resolution.label(),
                            outcomes.nat44_udp.label(),
                            outcomes.nat44_tcp.label(),
                            outcomes
                                .nat44_icmp
                                .map_or("none", ruster_core::StateCarryOutcome::label),
                            outcomes.firewall.label(),
                        )
                    }
                    None => formatter.write_str("code=APPLY_REPORT_MISSING"),
                }
            }
            Self::Refused {
                reasons,
                generation,
            } => {
                formatter.write_str("reload refused: code=RESTART_REQUIRED reasons=")?;
                for (index, reason) in reasons.iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(",")?;
                    }
                    formatter.write_str(reason.code())?;
                }
                write!(formatter, "; generation {generation} keeps running")
            }
            Self::Failed { detail, generation } => write!(
                formatter,
                "reload failed: {detail}; generation {generation} keeps running"
            ),
            Self::Checked {
                generation,
                carried,
            } => {
                // `<=` when the commit re-evaluates the firewall flows and
                // may revoke some (the dry run does not repeat that pass).
                write!(
                    formatter,
                    "reload checked: generation {generation} keeps running until the switch; \
                     would carry dynamic-neighbors={} nat44-udp-mappings={} nat44-tcp-sessions={} \
                     nat44-icmp-mappings={} firewall-flows{}{}",
                    carried.dynamic_neighbors,
                    carried.nat44_udp_mappings,
                    carried.nat44_tcp_sessions,
                    carried.nat44_icmp_mappings,
                    if carried.firewall_flows_upper_bound {
                        "<="
                    } else {
                        "="
                    },
                    carried.firewall_flows,
                )
            }
        }
    }
}

/// The publication result of the tick that carried a reload candidate.
#[derive(Clone, Copy, Debug)]
pub enum TickApply {
    /// Committed; the commit's report (previous generation, flush, carry),
    /// if it matched the new generation.
    Applied(Option<(NonZeroU64, ApplyFlushCounts, ApplyCarryCounts)>),
    Rejected(ApplyError),
    /// Neither (the backend deferred it).
    NotApplied,
}

/// Value-free size of an applied document, so a truncated or wrong file
/// shows in the `reload applied` line.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DocumentCounts {
    pub interfaces: usize,
    pub addresses: usize,
    pub routes: usize,
    pub neighbors: usize,
    pub firewall_rules: usize,
    /// NAT44 public port pool size (0 without NAT).
    pub nat44_ports: u32,
}

impl DocumentCounts {
    pub fn of(config: &ValidatedConfigV1) -> Self {
        Self {
            interfaces: config.interfaces().len(),
            addresses: config.local_ipv4().len(),
            routes: config.routes().len(),
            neighbors: config.neighbors().len(),
            firewall_rules: config
                .firewall()
                .map_or(0, |firewall| firewall.rules().len()),
            nat44_ports: nat44_ports(config),
        }
    }
}

/// The NAT44 UDP public port pool size (the TCP pool shares the realm).
fn nat44_ports(config: &ValidatedConfigV1) -> u32 {
    config
        .nat44()
        .and_then(|nat44| nat44.udp())
        .map_or(0, |udp| {
            u32::from(udp.last_port()).saturating_sub(u32::from(udp.first_port())) + 1
        })
}

/// A successor that passed the preparer, waiting for its dry run and
/// publication on the router thread.
pub struct Ready {
    /// `None` once handed to a tick.
    candidate: Option<ValidatedCandidate>,
    /// Tick budgets of its document.
    budgets: TickBudgets,
    counts: DocumentCounts,
    /// The slow-sweep warnings of its document, printed once applied.
    sweep: [Option<SweepSlow>; 2],
    /// The watch settings of its document (OPS-LOG), applied with it.
    ops: Ops,
}

/// The preparer's answer to one request (formatted on the worker thread,
/// value-free).
pub enum Prepared {
    Ready(Box<Ready>),
    /// Restart-required reasons, in plan order.
    Refused(Box<[RestartRequired]>),
    /// `stage=<stage> code=<code>[ path=...]`.
    Failed(String),
}

/// Requests to the reload worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Request {
    /// Steps 1 to 3 of the module documentation for the current file.
    Prepare,
    /// The last [`Prepared::Ready`] successor was applied: its document is
    /// current now.
    Applied,
}

/// The reload worker's state (H7): the production sequencer, the active
/// generation's document, and the source. It lives on the reload worker
/// thread for the whole run, so the sequencer (generation and key
/// uniqueness) is used by one thread only and is never shared.
pub struct Preparer<K: ProductionKeySource, C> {
    sequencer: ProductionSequencer<K>,
    current: ValidatedConfigV1,
    source: C,
    /// The document of the last `Ready` answer, until it is applied or the
    /// next request.
    next: Option<(ValidatedConfigV1, Ops)>,
    /// What a `[health]`/`[watch]` key falls back to (OPS-LOG).
    fallback: Fallback,
    /// The watch settings of the current document.
    ops: Ops,
}

impl<K: ProductionKeySource, C: ConfigSource> Preparer<K, C> {
    pub fn new(sequencer: ProductionSequencer<K>, current: ValidatedConfigV1, source: C) -> Self {
        Self {
            sequencer,
            current,
            source,
            next: None,
            fallback: Fallback::default(),
            ops: Ops::default(),
        }
    }

    /// The flag fallback of the `[health]`/`[watch]` keys and the resolved
    /// settings of the current document ([`super::ops`]).
    #[must_use]
    pub fn with_ops(mut self, fallback: Fallback, ops: Ops) -> Self {
        self.fallback = fallback;
        self.ops = ops;
        self
    }

    /// The watch settings of the current document.
    pub const fn ops(&self) -> Ops {
        self.ops
    }

    /// The active generation's document.
    pub const fn current(&self) -> &ValidatedConfigV1 {
        &self.current
    }

    /// Steps 1 to 3 of the module documentation, without the live dry run
    /// (which needs the active publication: the router thread runs it on
    /// the answer, [`Reloader::poll`]).
    pub fn prepare(&mut self) -> Prepared {
        self.next = None;
        let next = match self.source.load() {
            Ok(next) => next,
            Err(error) => return Prepared::Failed(error.render()),
        };
        // The merged watch settings first (the document validator bounded
        // each key): a disagreement with a flag fails the reload before a
        // generation is drawn.
        let ops = match Ops::resolve(&next, self.fallback) {
            Ok(ops) => ops,
            Err(error) => return Prepared::Failed(error.to_string()),
        };
        let candidate = match self.sequencer.candidate(&next) {
            Ok(candidate) => candidate,
            Err(SequencerError::Bridge(error)) => {
                return failed("candidate", error.code().to_owned());
            }
            Err(error) => return failed("candidate", token(&error)),
        };
        let plan = match ApplyPlan::between(&self.current, &next) {
            Ok(plan) => plan,
            Err(error) => return failed("plan", token(&error)),
        };
        if plan.requires_restart() {
            return Prepared::Refused(plan.restart_required().into());
        }
        let ready = Ready {
            ops,
            candidate: Some(candidate),
            budgets: super::budgets(&next),
            counts: DocumentCounts::of(&next),
            sweep: config_cmd::sweep_warnings(&next),
        };
        self.next = Some((next, ops));
        Prepared::Ready(Box::new(ready))
    }

    /// The last prepared document was applied.
    pub fn applied(&mut self) {
        if let Some((next, ops)) = self.next.take() {
            self.ops = ops;
            self.current = next;
        }
    }
}

fn failed(stage: &'static str, code: String) -> Prepared {
    Prepared::Failed(format!("stage={stage} code={code}"))
}

/// The router thread's end of the reload worker thread `ruster-reload`.
pub struct ReloadWorker {
    requests: SyncSender<Request>,
    replies: Receiver<Prepared>,
    /// A reply taken early by a lockstep request (tests).
    #[cfg(test)]
    early: Option<Prepared>,
    worker: Option<Worker>,
    #[cfg(test)]
    lockstep: bool,
}

/// The reload worker thread is gone (it panicked).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerGone;

impl ReloadWorker {
    /// Spawns `ruster-reload` owning `preparer`; it runs `prologue` first.
    pub fn spawn<K, C, P>(
        mut preparer: Preparer<K, C>,
        prologue: P,
    ) -> Result<Self, SpawnError<DropFailure>>
    where
        K: ProductionKeySource + Send + 'static,
        C: ConfigSource + Send + 'static,
        P: FnOnce() -> Result<(), DropFailure> + Send + 'static,
    {
        // Capacity 2: an `Applied` and the next `Prepare` may both wait.
        let (requests, jobs) = mpsc::sync_channel::<Request>(2);
        let (done, replies) = mpsc::sync_channel::<Prepared>(1);
        let worker = spawn("ruster-reload", prologue, move || {
            for request in jobs {
                match request {
                    Request::Prepare => {
                        if done.send(preparer.prepare()).is_err() {
                            return;
                        }
                    }
                    Request::Applied => preparer.applied(),
                }
            }
        })?;
        Ok(Self {
            requests,
            replies,
            #[cfg(test)]
            early: None,
            worker: Some(worker),
            #[cfg(test)]
            lockstep: false,
        })
    }

    /// Tests: every request waits (bounded) for its answer.
    #[cfg(test)]
    #[must_use]
    pub fn lockstep(mut self, on: bool) -> Self {
        self.lockstep = on;
        self
    }

    /// `Full` is unreachable: a `Prepare` is sent only while no reload is
    /// in flight, so the queue holds at most the previous `Applied` and
    /// this `Prepare` (capacity 2); only `Disconnected` (a dead worker)
    /// fails here.
    fn request(&mut self) -> Result<(), WorkerGone> {
        self.requests.try_send(Request::Prepare).map_err(|error| {
            debug_assert!(
                matches!(error, TrySendError::Disconnected(_)),
                "the reload request queue is never full"
            );
            WorkerGone
        })?;
        #[cfg(test)]
        if self.lockstep {
            self.early = lockstep_wait(&self.replies);
        }
        Ok(())
    }

    fn applied(&mut self) {
        // A gone worker fails the next request instead. Never full: the
        // worker took the `Prepare` of this reload before answering it.
        let _ = self.requests.try_send(Request::Applied);
    }

    fn poll(&mut self) -> Result<Option<Prepared>, WorkerGone> {
        #[cfg(test)]
        if let Some(reply) = self.early.take() {
            return Ok(Some(reply));
        }
        match self.replies.try_recv() {
            Ok(reply) => Ok(Some(reply)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(WorkerGone),
        }
    }

    /// Ends the worker: drops the channel ends (a waiting worker ends at
    /// once, one preparing ends after that) and hands back the thread for
    /// a bounded [`Worker::finish`].
    fn stop(mut self) -> Option<Worker> {
        self.worker.take()
    }
}

/// Where one reload is on the router thread.
enum Phase {
    Idle,
    /// Requested from the worker at `since`; RX goes on meanwhile.
    /// `warned` once the slow-preparation warning was given.
    Preparing {
        since: MonotonicMillis,
        warned: bool,
    },
    /// Passed the dry run; waits for quiescence since `since`.
    Pending {
        ready: Box<Ready>,
        since: MonotonicMillis,
    },
}

/// The reload state of the router thread: at most one reload in flight
/// (preparing on the worker or pending here), the active document's tick
/// budgets and sweep warnings, and the counters. The documents and the
/// sequencer live on the worker ([`Preparer`]).
pub struct Reloader {
    worker: Option<ReloadWorker>,
    phase: Phase,
    budgets: TickBudgets,
    sweep: [Option<SweepSlow>; 2],
    counters: ReloadCounters,
    /// The watch settings of the active generation's document (OPS-LOG).
    ops: Ops,
}

impl Reloader {
    /// Over `worker`, with the active document's tick budgets.
    pub fn new(worker: ReloadWorker, budgets: TickBudgets) -> Self {
        Self {
            worker: Some(worker),
            phase: Phase::Idle,
            budgets,
            sweep: [None, None],
            counters: ReloadCounters::default(),
            ops: Ops::default(),
        }
    }

    /// With the active document's watch settings (OPS-LOG).
    #[must_use]
    pub const fn with_ops(mut self, ops: Ops) -> Self {
        self.ops = ops;
        self
    }

    /// The watch settings of the active generation's document: an applied
    /// reload switches them with its budgets.
    pub const fn ops(&self) -> Ops {
        self.ops
    }

    /// A reloader without a worker (tests of `finish`).
    #[cfg(test)]
    pub fn without_worker(budgets: TickBudgets) -> Self {
        Self {
            worker: None,
            phase: Phase::Idle,
            budgets,
            sweep: [None, None],
            counters: ReloadCounters::default(),
            ops: Ops::default(),
        }
    }

    pub const fn counters(&self) -> ReloadCounters {
        self.counters
    }

    /// Tick budgets of the active generation's document.
    pub const fn budgets(&self) -> TickBudgets {
        self.budgets
    }

    /// The slow-sweep warnings of the last applied document.
    pub const fn sweep(&self) -> [Option<SweepSlow>; 2] {
        self.sweep
    }

    /// Whether a reload is in flight (preparing or pending): further
    /// requests wait (coalesce) in the signal flag until it ends.
    pub const fn busy(&self) -> bool {
        !matches!(self.phase, Phase::Idle)
    }

    /// Since when a successor waits for quiescence, if one does.
    pub fn pending_since(&self) -> Option<MonotonicMillis> {
        match &self.phase {
            Phase::Pending { since, .. } => Some(*since),
            _ => None,
        }
    }

    /// Hands a reload request to the worker at `now` (never blocks).
    /// `Some` if it ended at once (the worker is gone).
    pub fn request(
        &mut self,
        generation: NonZeroU64,
        now: MonotonicMillis,
    ) -> Option<ReloadOutcome> {
        self.counters.requested = self.counters.requested.saturating_add(1);
        let sent = self
            .worker
            .as_mut()
            .map_or(Err(WorkerGone), ReloadWorker::request);
        match sent {
            Ok(()) => {
                self.phase = Phase::Preparing {
                    since: now,
                    warned: false,
                };
                None
            }
            Err(WorkerGone) => {
                Some(self.failed("prepare", "WORKER_STOPPED".to_owned(), generation))
            }
        }
    }

    /// Takes the worker's answer, if it came (never blocks): a refused or
    /// failed reload ends here; a ready successor gets the live dry run
    /// ([`ActivePublication::check_successor`]: no lock, no I/O, no
    /// mutation) and then waits for quiescence from `now`.
    pub fn poll<I: PublicationQuiescence>(
        &mut self,
        active: &mut ActivePublication<'_, I>,
        now: MonotonicMillis,
    ) -> Option<ReloadOutcome> {
        if !matches!(self.phase, Phase::Preparing { .. }) {
            return None;
        }
        let generation = active.generation();
        let reply = match self
            .worker
            .as_mut()
            .map_or(Err(WorkerGone), ReloadWorker::poll)
        {
            Ok(None) => return None,
            Ok(Some(reply)) => reply,
            Err(WorkerGone) => {
                self.phase = Phase::Idle;
                self.counters.preparing_ms = 0;
                return Some(self.failed("prepare", "WORKER_STOPPED".to_owned(), generation));
            }
        };
        self.phase = Phase::Idle;
        self.counters.preparing_ms = 0;
        match reply {
            Prepared::Failed(detail) => Some(self.failed_with(detail, generation)),
            Prepared::Refused(reasons) => {
                self.counters.refused = self.counters.refused.saturating_add(1);
                Some(ReloadOutcome::Refused {
                    reasons,
                    generation,
                })
            }
            Prepared::Ready(ready) => {
                let check = ready
                    .candidate
                    .as_ref()
                    .map(|candidate| active.check_successor(candidate));
                let checked = match check {
                    Some(Err(error)) => {
                        return Some(self.failed("dry-run", apply_code(error), generation));
                    }
                    Some(Ok(check)) => Some(ReloadOutcome::Checked {
                        generation,
                        carried: check.carried,
                    }),
                    None => None,
                };
                self.phase = Phase::Pending { ready, since: now };
                checked
            }
        }
    }

    /// Makes a successor with `budgets` pending without a candidate (tests
    /// of `finish`).
    #[cfg(test)]
    pub fn set_pending_for_test(&mut self, budgets: TickBudgets) {
        self.counters.requested = self.counters.requested.saturating_add(1);
        self.phase = Phase::Pending {
            ready: Box::new(Ready {
                candidate: None,
                budgets,
                counts: DocumentCounts::default(),
                sweep: [None, None],
                ops: self.ops,
            }),
            since: MonotonicMillis(0),
        };
    }

    /// Takes the pending candidate for the publication phase of this tick;
    /// the rest stays until [`Self::finish`].
    pub fn take_candidate(&mut self) -> Option<ValidatedCandidate> {
        match &mut self.phase {
            Phase::Pending { ready, .. } => ready.candidate.take(),
            _ => None,
        }
    }

    /// Ends the pending reload with the publication result of the tick
    /// that carried its candidate. `PublicationOutcome::Applied` is
    /// authoritative: the new document becomes current (here: its budgets
    /// and sweep warnings; on the worker: the document) even if the
    /// commit's report is missing (`TickApply::Applied(None)`, an invariant
    /// violation the caller ends the run on), so it is never reported as
    /// "keeps running".
    pub fn finish(&mut self, generation: NonZeroU64, result: TickApply) -> Option<ReloadOutcome> {
        let Phase::Pending { ready, .. } = std::mem::replace(&mut self.phase, Phase::Idle) else {
            return None;
        };
        Some(match result {
            TickApply::Applied(report) => {
                self.budgets = ready.budgets;
                self.sweep = ready.sweep;
                self.ops = ready.ops;
                if let Some(worker) = self.worker.as_mut() {
                    worker.applied();
                }
                self.counters.applied = self.counters.applied.saturating_add(1);
                ReloadOutcome::Applied {
                    previous: report.map(|(previous, _, _)| previous),
                    generation,
                    flush: report.map(|(_, flush, _)| flush),
                    carry: report.map(|(_, _, carry)| Box::new(carry)),
                    counts: ready.counts,
                }
            }
            TickApply::Rejected(error) => self.failed("apply", apply_code(error), generation),
            TickApply::NotApplied => self.failed("apply", "NOT_QUIESCENT".to_owned(), generation),
        })
    }

    /// Abandons the reload in flight (quiescence timeout, a stopping
    /// backend, or the end of the run: `STOPPED`, also while the worker
    /// still prepares it, which is then not waited for), so `requested`
    /// always equals `applied + refused + failed` at the end.
    pub fn abandon(&mut self, code: &'static str, generation: NonZeroU64) -> Option<ReloadOutcome> {
        let stage = match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Idle => return None,
            Phase::Preparing { .. } => "prepare",
            Phase::Pending { .. } => "quiesce",
        };
        self.counters.preparing_ms = 0;
        Some(self.failed(stage, code.to_owned(), generation))
    }

    /// Updates `reload.preparing_ms` at `now` (no allocation, no I/O) and
    /// returns the whole seconds the preparation has run, once, when it
    /// first reaches `warn_ms` ([`RELOAD_PREPARE_WARN_MS`]).
    pub fn observe_preparation(&mut self, now: MonotonicMillis, warn_ms: u64) -> Option<u64> {
        let Phase::Preparing { since, warned } = &mut self.phase else {
            return None;
        };
        let running = now.0.saturating_sub(since.0);
        self.counters.preparing_ms = running;
        if *warned || running < warn_ms {
            return None;
        }
        *warned = true;
        Some(running / 1_000)
    }

    /// Ends the worker (see [`ReloadWorker::stop`]).
    pub fn stop_worker(&mut self) -> Option<Worker> {
        self.worker.take().and_then(ReloadWorker::stop)
    }

    fn failed(
        &mut self,
        stage: &'static str,
        code: String,
        generation: NonZeroU64,
    ) -> ReloadOutcome {
        self.failed_with(format!("stage={stage} code={code}"), generation)
    }

    fn failed_with(&mut self, detail: String, generation: NonZeroU64) -> ReloadOutcome {
        self.counters.failed = self.counters.failed.saturating_add(1);
        ReloadOutcome::Failed { detail, generation }
    }
}

/// Value-free code of a rejected successor.
pub fn apply_code(error: ApplyError) -> String {
    match error {
        ApplyError::RestartRequired(reason) => format!("RESTART_REQUIRED.{}", reason.code()),
        other => token(&other),
    }
}

#[cfg(test)]
mod checked_tests {
    use std::num::NonZeroU64;

    use super::ReloadOutcome;

    /// Sec Nit: a re-evaluating dry run shows the firewall count as a bound.
    #[test]
    fn a_reevaluating_dry_run_prints_the_firewall_count_as_a_bound() {
        let mut carried = ruster_control::CarriedCounts::default();
        carried.firewall_flows = 7;
        carried.firewall_flows_upper_bound = true;
        let line = ReloadOutcome::Checked {
            generation: NonZeroU64::new(3).unwrap(),
            carried,
        }
        .to_string();
        assert!(line.ends_with(" firewall-flows<=7"), "{line}");
        carried.firewall_flows_upper_bound = false;
        let line = ReloadOutcome::Checked {
            generation: NonZeroU64::new(3).unwrap(),
            carried,
        }
        .to_string();
        assert!(line.ends_with(" firewall-flows=7"), "{line}");
    }
}
