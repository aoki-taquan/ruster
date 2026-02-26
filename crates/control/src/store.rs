//! Configuration store implementing the **validate -> plan -> apply** pipeline.
//!
//! # The `validate -> plan -> apply` Contract
//!
//! Every configuration change flows through a strict three-phase pipeline.
//! Each phase is a gate: if it fails, no state is mutated and the error is
//! returned to the caller.
//!
//! 1. **`validate(candidate)`** -- Runs the full semantic validation suite from
//!    [`ruster_config::validate::validate`] against the candidate configuration.
//!    This includes checks for duplicate interface names/port-IDs, bridge-domain
//!    member existence, static-route `out_if` references, NAT/firewall
//!    cross-constraints, and more.  The store state is never modified by this
//!    method.
//!
//! 2. **`plan(candidate)`** -- Calls `validate` first, then diffs the candidate
//!    against the current running config to produce a [`PlanResult`] with the
//!    list of changes.  If there is no running config yet the entire candidate
//!    is reported as an addition.  The store state is not modified.
//!
//! 3. **`apply(candidate)`** -- Calls `plan` (which internally calls `validate`),
//!    and only if both succeed does it promote the candidate to the new running
//!    config.  The change remains "pending" (uncommitted) until [`ConfigStore::commit`]
//!    is called.
//!
//! Because `plan` gates on `validate`, and `apply` gates on `plan`, **any
//! semantic error detected by the config crate will prevent a state change
//! at every level of the pipeline**.

use ruster_config::RouterConfig;

use crate::diff;
use crate::diff::ConfigChange;
use crate::error::ControlError;
use crate::transaction::{self, ConfigDiff, ConfigTransaction, TransactionState};

/// Result of a `plan` operation.
#[derive(Debug)]
pub struct PlanResult {
    pub has_changes: bool,
    pub changes: Vec<ConfigChange>,
}

impl std::fmt::Display for PlanResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.has_changes {
            return write!(f, "No changes.");
        }
        writeln!(f, "{} change(s):", self.changes.len())?;
        for c in &self.changes {
            writeln!(f, "  {c}")?;
        }
        Ok(())
    }
}

/// Holds running / candidate configuration state.
///
/// # Workflow
///
/// ```text
/// validate(candidate)
///     |
///     v
/// plan(candidate)     -- calls validate, then diffs
///     |
///     v
/// apply(candidate)    -- calls plan, then updates running
///     |
///     v
/// commit()            -- snapshots running as committed
/// ```
///
/// If any earlier phase fails, later phases are never reached and the store
/// state remains unchanged.  See the [module-level documentation](self) for
/// the full contract description.
#[derive(Debug)]
pub struct ConfigStore {
    /// The currently active configuration (after `apply`).
    running: Option<RouterConfig>,
    /// The last committed (saved) configuration.
    committed: Option<RouterConfig>,
    /// Snapshot of the previous running config, used for rollback.
    rollback_snapshot: Option<RouterConfig>,
}

impl ConfigStore {
    /// Create a new store with no running config.
    pub fn new() -> Self {
        Self {
            running: None,
            committed: None,
            rollback_snapshot: None,
        }
    }

    /// Create a store with an initial running config (e.g. loaded at startup).
    pub fn with_running(config: RouterConfig) -> Self {
        Self {
            running: Some(config.clone()),
            committed: Some(config),
            rollback_snapshot: None,
        }
    }

    /// Reference to the current running config, if any.
    pub fn running(&self) -> Option<&RouterConfig> {
        self.running.as_ref()
    }

    /// Reference to the last committed config, if any.
    pub fn committed(&self) -> Option<&RouterConfig> {
        self.committed.as_ref()
    }

    /// Returns true if there are uncommitted changes (running differs from committed).
    pub fn has_pending_changes(&self) -> bool {
        match (&self.running, &self.committed) {
            (Some(r), Some(c)) => r != c,
            (Some(_), None) | (None, Some(_)) => true,
            (None, None) => false,
        }
    }

    /// Validate a candidate configuration using the full `ruster-config` validation suite.
    ///
    /// This delegates to [`ruster_config::validate::validate`] so that the same semantic
    /// checks applied at config-load time (duplicate interface names, bridge-domain member
    /// existence, NAT/firewall cross-references, etc.) are also enforced on every runtime
    /// config change through the `validate -> plan -> apply` pipeline.
    ///
    /// This does **not** modify store state; it is purely a read-only check.
    pub fn validate(&self, candidate: &RouterConfig) -> Result<(), ControlError> {
        // Empty hostname is caught by the config-crate validation as well,
        // but we keep the explicit check for a clearer error message.
        if candidate.meta.hostname.trim().is_empty() {
            return Err(ControlError::Validation(
                "meta.hostname must not be empty".to_string(),
            ));
        }

        // Full semantic validation via ruster-config.
        ruster_config::validate::validate(candidate).map_err(|errors| {
            let msgs: Vec<String> = errors
                .iter()
                .map(|e| format!("{}: {}", e.field, e.reason))
                .collect();
            ControlError::Validation(msgs.join("; "))
        })?;

        Ok(())
    }

    /// Plan: compare current running config against candidate.
    ///
    /// Returns the list of changes. If there is no running config, every field
    /// in the candidate is treated as an addition.
    pub fn plan(&self, candidate: &RouterConfig) -> Result<PlanResult, ControlError> {
        self.validate(candidate)?;

        match &self.running {
            Some(running) => {
                let changes = diff::diff_configs(running, candidate);
                Ok(PlanResult {
                    has_changes: !changes.is_empty(),
                    changes,
                })
            }
            None => {
                // First-time apply: treat the whole config as new.
                // We use a synthetic empty-like diff by reporting "initial load".
                Ok(PlanResult {
                    has_changes: true,
                    changes: vec![ConfigChange {
                        path: "<root>".to_string(),
                        kind: crate::diff::ChangeKind::Added {
                            new: "initial configuration".to_string(),
                        },
                    }],
                })
            }
        }
    }

    /// Apply a candidate config as the new running config.
    ///
    /// Validates and plans first; rejects if validation fails.
    /// The change becomes "pending" until `commit()` is called.
    pub fn apply(&mut self, candidate: RouterConfig) -> Result<PlanResult, ControlError> {
        let plan = self.plan(&candidate)?;
        self.running = Some(candidate);
        Ok(plan)
    }

    /// Commit the current running config as the new baseline.
    ///
    /// After commit, `has_pending_changes()` returns false.
    pub fn commit(&mut self) -> Result<(), ControlError> {
        match &self.running {
            Some(r) => {
                self.committed = Some(r.clone());
                Ok(())
            }
            None => Err(ControlError::NothingToCommit),
        }
    }

    // ── Transaction-based apply ──────────────────────────────────────

    /// Begin a new configuration transaction.
    ///
    /// Creates a [`ConfigTransaction`] that captures the current running config
    /// as a rollback snapshot. If there is no running config, a
    /// [`ControlError::NothingToCommit`] error is returned (there must be a
    /// baseline config to roll back to).
    pub fn begin_transaction(&self) -> Result<ConfigTransaction, ControlError> {
        match &self.running {
            Some(running) => Ok(ConfigTransaction::new(running.clone())),
            None => Err(ControlError::NothingToCommit),
        }
    }

    /// Prepare a transaction: validate the candidate config and compute a diff.
    ///
    /// The transaction transitions from `Preparing` to `Validated` on success.
    /// If validation fails, the transaction remains in `Preparing` and the
    /// error is returned.
    pub fn prepare(
        &self,
        txn: &mut ConfigTransaction,
        new_config: RouterConfig,
    ) -> Result<ConfigDiff, ControlError> {
        if txn.is_consumed() {
            return Err(ControlError::TransactionAlreadyConsumed);
        }

        // Validate the candidate through the full validation pipeline.
        self.validate(&new_config)?;

        // Compute the high-level diff.
        let diff = transaction::compute_diff(txn.rollback_snapshot(), &new_config);

        // Store the candidate and advance the state.
        txn.set_candidate(new_config);
        txn.mark_validated();

        Ok(diff)
    }

    /// Commit a transaction: atomically apply the candidate as the new running config.
    ///
    /// The transaction must be in the `Validated` state. On success, the running
    /// config is updated and the previous running config is stored as the
    /// rollback snapshot.
    pub fn commit_transaction(&mut self, txn: ConfigTransaction) -> Result<(), ControlError> {
        if txn.is_consumed() {
            return Err(ControlError::TransactionAlreadyConsumed);
        }
        if txn.state() != TransactionState::Validated {
            return Err(ControlError::TransactionNotValidated);
        }

        // Save the rollback snapshot before replacing running.
        self.rollback_snapshot = self.running.clone();

        // Extract the candidate and set as new running.
        let candidate = txn
            .take_candidate()
            .expect("Validated transaction must have a candidate");
        self.running = Some(candidate);

        Ok(())
    }

    /// Abort a transaction: discard the candidate without applying any changes.
    ///
    /// The running config is left completely unchanged.
    pub fn abort(&self, mut txn: ConfigTransaction) -> Result<(), ControlError> {
        if txn.is_consumed() {
            return Err(ControlError::TransactionAlreadyConsumed);
        }
        txn.mark_aborted();
        Ok(())
    }

    /// Rollback the running config to the previous snapshot.
    ///
    /// This reverts the running config to the state it was in before the last
    /// `commit_transaction`. Returns an error if there is no rollback snapshot.
    pub fn rollback(&mut self) -> Result<(), ControlError> {
        match self.rollback_snapshot.take() {
            Some(snapshot) => {
                self.running = Some(snapshot);
                Ok(())
            }
            None => Err(ControlError::NothingToRollback),
        }
    }

    /// Dry-run: validate and compute a diff without modifying any state.
    ///
    /// This is a convenience method that validates the candidate and returns a
    /// [`ConfigDiff`] showing what *would* change, without creating a transaction
    /// or modifying the store.
    pub fn dry_run(&self, new_config: &RouterConfig) -> Result<ConfigDiff, ControlError> {
        self.validate(new_config)?;

        match &self.running {
            Some(running) => Ok(transaction::compute_diff(running, new_config)),
            None => {
                // No running config -- everything in the candidate is "new".
                // Report all interfaces and routes as added.
                Ok(ConfigDiff {
                    added_routes: new_config
                        .routing
                        .ipv4_static_routes
                        .iter()
                        .map(|r| r.prefix.clone())
                        .collect(),
                    removed_routes: vec![],
                    changed_interfaces: new_config
                        .interfaces
                        .iter()
                        .map(|i| i.name.clone())
                        .collect(),
                    nat_changed: true,
                    firewall_changed: true,
                })
            }
        }
    }
}

impl Default for ConfigStore {
    fn default() -> Self {
        Self::new()
    }
}
