//! SIGHUP reload of `ruster run` (M2 S10b).
//!
//! The SIGHUP handler only stores a flag ([`crate::signal`]); the run loop
//! takes it at a tick boundary and calls [`Reloader::prepare`], which runs
//! the production config path and the control plane's plan, all on the
//! cold path, before anything changes:
//!
//! 1. re-read and validate the `--config` file exactly like startup
//!    ([`crate::config_cmd::load_validated_regular`]: the same limits, and
//!    a non-regular file is refused so a FIFO cannot block the router);
//! 2. build the successor candidate with the production sequencer (a
//!    fresh generation and fresh keys; a refused or failed reload still
//!    consumes that generation, as in `run-sim`);
//! 3. [`ApplyPlan::for_active`] against the active generation's document:
//!    any restart-required reason (backend, device, port set, UMEM or ring
//!    shape: [`RestartRequired::Backend`]; interface ids or MACs; storage
//!    shape; resolution or ICMPv4 error policy) refuses the reload, and a
//!    failing dry run (successor validation or a runtime preflight) fails
//!    it.
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
//! applied reload follows the control-plane contract (PUB-006): the new
//! generation flushes publication-bound state (ARP learning, pending
//! resolution and ICMPv4 errors, every NAT44 mapping and firewall flow,
//! because their hash keys rotate) and keeps cumulative counters; the
//! flush counts are printed. The tick budgets of the new document apply
//! from the next tick.

use std::fmt;
use std::num::NonZeroU64;
use std::path::PathBuf;

use ruster_config::ValidatedConfigV1;
use ruster_control::{
    ActivePublication, ApplyError, ApplyPlan, ProductionKeySource, ProductionSequencer,
    RestartRequired, SequencerError, ValidatedCandidate,
};
use ruster_core::{
    FieldValue, FieldVisitor, MonotonicMillis, ObservableFields, PublicationQuiescence,
};
use ruster_runtime::{ApplyFlushCounts, TickBudgets};

use crate::config_cmd::{self, LoadError};

use super::startup::token;

/// Longest wait for backend quiescence before a pending reload fails.
pub const RELOAD_QUIESCE_MS: u64 = 200;

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
}

impl ObservableFields for ReloadCounters {
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        const SECTION: &str = "reload";
        visitor.field(SECTION, "requested", FieldValue::Count(self.requested));
        visitor.field(SECTION, "applied", FieldValue::Count(self.applied));
        visitor.field(SECTION, "refused", FieldValue::Count(self.refused));
        visitor.field(SECTION, "failed", FieldValue::Count(self.failed));
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
}

impl fmt::Display for ReloadOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Applied {
                previous,
                generation,
                flush,
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
                match flush {
                    Some(flush) => write!(
                        formatter,
                        "flushed dynamic-neighbors={} resolution-states={} \
                         nat44-udp-mappings={} nat44-tcp-sessions={} firewall-flows={}",
                        flush.dynamic_neighbors,
                        flush.resolution_states,
                        flush.nat44_udp_mappings,
                        flush.nat44_tcp_sessions,
                        flush.firewall_flows,
                    ),
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
        }
    }
}

/// The publication result of the tick that carried a reload candidate.
#[derive(Clone, Copy, Debug)]
pub enum TickApply {
    /// Committed; the commit's report (previous generation, flush), if it
    /// matched the new generation.
    Applied(Option<(NonZeroU64, ApplyFlushCounts)>),
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

struct Pending {
    /// `None` once handed to a tick.
    candidate: Option<ValidatedCandidate>,
    next: ValidatedConfigV1,
    since: MonotonicMillis,
}

/// The reload state of one run: the production sequencer, the active
/// generation's document, and at most one pending successor.
pub struct Reloader<K: ProductionKeySource, C> {
    sequencer: ProductionSequencer<K>,
    current: ValidatedConfigV1,
    source: C,
    pending: Option<Pending>,
    counters: ReloadCounters,
}

impl<K: ProductionKeySource, C: ConfigSource> Reloader<K, C> {
    pub fn new(sequencer: ProductionSequencer<K>, current: ValidatedConfigV1, source: C) -> Self {
        Self {
            sequencer,
            current,
            source,
            pending: None,
            counters: ReloadCounters::default(),
        }
    }

    pub const fn counters(&self) -> ReloadCounters {
        self.counters
    }

    /// The active generation's document.
    pub const fn current(&self) -> &ValidatedConfigV1 {
        &self.current
    }

    /// Tick budgets of the active generation's document.
    pub fn budgets(&self) -> TickBudgets {
        super::budgets(&self.current)
    }

    /// Since when a successor waits for quiescence, if one does.
    pub fn pending_since(&self) -> Option<MonotonicMillis> {
        self.pending.as_ref().map(|pending| pending.since)
    }

    /// Steps 1-3 of the module documentation. `None`: the successor is
    /// pending; `Some`: the reload ended (refused or failed) and nothing
    /// changed.
    pub fn prepare<I: PublicationQuiescence>(
        &mut self,
        active: &mut ActivePublication<'_, I>,
        now: MonotonicMillis,
    ) -> Option<ReloadOutcome> {
        self.counters.requested = self.counters.requested.saturating_add(1);
        let generation = active.generation();
        let next = match self.source.load() {
            Ok(next) => next,
            Err(error) => {
                return Some(self.failed_with(error.render(), generation));
            }
        };
        let candidate = match self.sequencer.candidate(&next) {
            Ok(candidate) => candidate,
            Err(SequencerError::Bridge(error)) => {
                return Some(self.failed("candidate", error.code().to_owned(), generation))
            }
            Err(error) => return Some(self.failed("candidate", token(&error), generation)),
        };
        let plan = match ApplyPlan::for_active(active, &self.current, &next, &candidate) {
            Ok(plan) => plan,
            Err(error) => return Some(self.failed("plan", token(&error), generation)),
        };
        if plan.requires_restart() {
            self.counters.refused = self.counters.refused.saturating_add(1);
            return Some(ReloadOutcome::Refused {
                reasons: plan.restart_required().into(),
                generation,
            });
        }
        if let Some(Err(error)) = plan.dry_run() {
            return Some(self.failed("dry-run", apply_code(error), generation));
        }
        self.pending = Some(Pending {
            candidate: Some(candidate),
            next,
            since: now,
        });
        None
    }

    /// Makes `next` pending without a candidate (tests of `finish`).
    #[cfg(test)]
    pub fn set_pending_for_test(&mut self, next: ValidatedConfigV1) {
        self.counters.requested = self.counters.requested.saturating_add(1);
        self.pending = Some(Pending {
            candidate: None,
            next,
            since: MonotonicMillis(0),
        });
    }

    /// Takes the pending candidate for the publication phase of this tick;
    /// its document stays until [`Self::finish`].
    pub fn take_candidate(&mut self) -> Option<ValidatedCandidate> {
        self.pending.as_mut()?.candidate.take()
    }

    /// Ends the pending reload with the publication result of the tick
    /// that carried its candidate. `PublicationOutcome::Applied` is
    /// authoritative: the new document becomes current even if the
    /// commit's report is missing (`TickApply::Applied(None)`, an invariant
    /// violation the caller ends the run on), so it is never reported as
    /// "keeps running".
    pub fn finish(&mut self, generation: NonZeroU64, result: TickApply) -> Option<ReloadOutcome> {
        let pending = self.pending.take()?;
        Some(match result {
            TickApply::Applied(report) => {
                let counts = DocumentCounts::of(&pending.next);
                self.current = pending.next;
                self.counters.applied = self.counters.applied.saturating_add(1);
                ReloadOutcome::Applied {
                    previous: report.map(|(previous, _)| previous),
                    generation,
                    flush: report.map(|(_, flush)| flush),
                    counts,
                }
            }
            TickApply::Rejected(error) => self.failed("apply", apply_code(error), generation),
            TickApply::NotApplied => self.failed("apply", "NOT_QUIESCENT".to_owned(), generation),
        })
    }

    /// Abandons the pending reload (quiescence timeout, a stopping
    /// backend, or the end of the run: `STOPPED`), so `requested` always
    /// equals `applied + refused + failed` at the end.
    pub fn abandon(&mut self, code: &'static str, generation: NonZeroU64) -> Option<ReloadOutcome> {
        self.pending.take()?;
        Some(self.failed("quiesce", code.to_owned(), generation))
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
