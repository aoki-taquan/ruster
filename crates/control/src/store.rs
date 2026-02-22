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

/// Holds running / candidate configuration state.
///
/// Workflow: `validate` → `plan` → `apply` → (optional) `commit`.
#[derive(Debug)]
pub struct ConfigStore {
    /// The currently active configuration (after `apply`).
    running: Option<RouterConfig>,
    /// The last committed (saved) configuration.
    committed: Option<RouterConfig>,
}

impl ConfigStore {
    /// Create a new store with no running config.
    pub fn new() -> Self {
        Self {
            running: None,
            committed: None,
        }
    }

    /// Create a store with an initial running config (e.g. loaded at startup).
    pub fn with_running(config: RouterConfig) -> Self {
        Self {
            running: Some(config.clone()),
            committed: Some(config),
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

    /// Validate a candidate configuration (parse + semantic checks).
    ///
    /// This does NOT modify store state.
    pub fn validate(&self, candidate: &RouterConfig) -> Result<(), ControlError> {
        if candidate.meta.hostname.trim().is_empty() {
            return Err(ControlError::Validation(
                "meta.hostname must not be empty".to_string(),
            ));
        }
        // Config-crate level validation is assumed to have passed at load time.
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
}

impl Default for ConfigStore {
    fn default() -> Self {
        Self::new()
    }
}
