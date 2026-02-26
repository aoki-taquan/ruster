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
//!
//! # Atomic Transactions
//!
//! For multi-step configuration changes that need all-or-nothing semantics,
//! the store supports an explicit transaction protocol:
//!
//! ```text
//! begin_transaction()   -- snapshot running as pre-transaction baseline
//!     |
//!     v
//! apply(candidate)      -- one or more apply calls within the transaction
//!     |
//!     v
//! prepare_transaction() -- validate the final state, freeze changes
//!     |
//!     v
//! commit_transaction()  -- promote to committed; transaction ends
//!     OR
//! abort_transaction()   -- revert running to pre-transaction snapshot
//! ```
//!
//! If validation fails during `prepare`, the caller should `abort_transaction()`
//! to roll back.  The `rollback()` method provides a shorthand for reverting the
//! running config to the last committed config outside of a transaction.

use ruster_config::RouterConfig;

use crate::diff;
use crate::diff::ConfigChange;
use crate::error::ControlError;

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

/// The lifecycle state of an atomic configuration transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    /// The transaction is open and accepting `apply()` calls.
    Pending,
    /// The transaction has been prepared (validated) and is ready for commit.
    Prepared,
}

impl std::fmt::Display for TransactionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionState::Pending => write!(f, "Pending"),
            TransactionState::Prepared => write!(f, "Prepared"),
        }
    }
}

/// An in-flight atomic transaction.
///
/// Holds the snapshot of the running config taken at `begin_transaction()` time
/// so that `abort_transaction()` can restore it.
#[derive(Debug)]
pub struct Transaction {
    /// State machine: Pending -> Prepared -> (committed or aborted).
    pub state: TransactionState,
    /// Snapshot of running config taken when the transaction began.
    snapshot: Option<RouterConfig>,
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
    /// Active transaction, if any.
    transaction: Option<Transaction>,
}

impl ConfigStore {
    /// Create a new store with no running config.
    pub fn new() -> Self {
        Self {
            running: None,
            committed: None,
            transaction: None,
        }
    }

    /// Create a store with an initial running config (e.g. loaded at startup).
    pub fn with_running(config: RouterConfig) -> Self {
        Self {
            running: Some(config.clone()),
            committed: Some(config),
            transaction: None,
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

    /// Returns true if there is an active transaction.
    pub fn has_active_transaction(&self) -> bool {
        self.transaction.is_some()
    }

    /// Returns the current transaction state, if a transaction is active.
    pub fn transaction_state(&self) -> Option<TransactionState> {
        self.transaction.as_ref().map(|t| t.state)
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
        // If in a transaction that has already been prepared, reject further applies.
        if let Some(ref txn) = self.transaction {
            if txn.state == TransactionState::Prepared {
                return Err(ControlError::InvalidTransactionState {
                    expected: "Pending".to_string(),
                    actual: "Prepared".to_string(),
                });
            }
        }

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

    // ── Atomic Transaction Protocol ──

    /// Begin an atomic transaction.
    ///
    /// Snapshots the current running config so that `abort_transaction()` can
    /// restore it.  Only one transaction may be active at a time.
    ///
    /// # Errors
    ///
    /// - [`ControlError::TransactionInProgress`] if a transaction is already active.
    /// - [`ControlError::NoRunningConfig`] if there is no running config to snapshot.
    pub fn begin_transaction(&mut self) -> Result<(), ControlError> {
        if self.transaction.is_some() {
            return Err(ControlError::TransactionInProgress);
        }

        let snapshot = self
            .running
            .as_ref()
            .ok_or(ControlError::NoRunningConfig)?
            .clone();

        self.transaction = Some(Transaction {
            state: TransactionState::Pending,
            snapshot: Some(snapshot),
        });

        Ok(())
    }

    /// Prepare (validate) the transaction.
    ///
    /// Validates the current running config to ensure all changes applied within
    /// the transaction are collectively valid.  Transitions the transaction state
    /// from `Pending` to `Prepared`.
    ///
    /// # Errors
    ///
    /// - [`ControlError::NoTransaction`] if no transaction is active.
    /// - [`ControlError::InvalidTransactionState`] if not in `Pending` state.
    /// - [`ControlError::Validation`] if the current running config is invalid.
    pub fn prepare_transaction(&mut self) -> Result<PlanResult, ControlError> {
        // Check transaction state with an immutable borrow first, then release it.
        {
            let txn = self
                .transaction
                .as_ref()
                .ok_or(ControlError::NoTransaction)?;

            if txn.state != TransactionState::Pending {
                return Err(ControlError::InvalidTransactionState {
                    expected: "Pending".to_string(),
                    actual: txn.state.to_string(),
                });
            }
        }

        // Validate the current running config.
        let running = self
            .running
            .as_ref()
            .ok_or(ControlError::NoRunningConfig)?
            .clone();
        self.validate(&running)?;

        // Diff against the pre-transaction snapshot to show what the transaction changed.
        let txn = self.transaction.as_ref().expect("transaction exists");
        let snapshot = txn.snapshot.as_ref().expect("snapshot set at begin");
        let changes = diff::diff_configs(snapshot, &running);
        let plan = PlanResult {
            has_changes: !changes.is_empty(),
            changes,
        };

        // Transition to Prepared state.
        self.transaction.as_mut().expect("transaction exists").state = TransactionState::Prepared;

        Ok(plan)
    }

    /// Commit the prepared transaction.
    ///
    /// Promotes the current running config to committed and ends the transaction.
    ///
    /// # Errors
    ///
    /// - [`ControlError::NoTransaction`] if no transaction is active.
    /// - [`ControlError::InvalidTransactionState`] if not in `Prepared` state.
    pub fn commit_transaction(&mut self) -> Result<(), ControlError> {
        let txn = self
            .transaction
            .as_ref()
            .ok_or(ControlError::NoTransaction)?;

        if txn.state != TransactionState::Prepared {
            return Err(ControlError::InvalidTransactionState {
                expected: "Prepared".to_string(),
                actual: txn.state.to_string(),
            });
        }

        // Promote running to committed.
        self.committed = self.running.clone();
        self.transaction = None;
        Ok(())
    }

    /// Abort the active transaction, restoring the pre-transaction running config.
    ///
    /// This reverts the running config to the snapshot taken at `begin_transaction()`
    /// time.  Works in both `Pending` and `Prepared` states.
    ///
    /// # Errors
    ///
    /// - [`ControlError::NoTransaction`] if no transaction is active.
    pub fn abort_transaction(&mut self) -> Result<(), ControlError> {
        let txn = self.transaction.take().ok_or(ControlError::NoTransaction)?;

        // Restore the snapshot.
        self.running = txn.snapshot;
        Ok(())
    }

    /// Rollback the running config to the last committed config (outside of a transaction).
    ///
    /// This is a convenience method for reverting uncommitted changes without
    /// the full transaction protocol.
    ///
    /// # Errors
    ///
    /// - [`ControlError::TransactionInProgress`] if a transaction is active (use
    ///   `abort_transaction()` instead).
    /// - [`ControlError::NoCommittedConfig`] if there is no committed config to
    ///   rollback to.
    pub fn rollback(&mut self) -> Result<(), ControlError> {
        if self.transaction.is_some() {
            return Err(ControlError::TransactionInProgress);
        }

        let committed = self
            .committed
            .as_ref()
            .ok_or(ControlError::NoCommittedConfig)?
            .clone();

        self.running = Some(committed);
        Ok(())
    }
}

impl Default for ConfigStore {
    fn default() -> Self {
        Self::new()
    }
}
