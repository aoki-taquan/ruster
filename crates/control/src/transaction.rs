//! Transaction-based configuration apply with rollback.
//!
//! This module provides [`ConfigTransaction`] for safe, atomic runtime
//! configuration changes. A transaction captures the candidate config and
//! a rollback snapshot, ensuring that failed or aborted changes never
//! corrupt the running state.
//!
//! # Lifecycle
//!
//! ```text
//! begin_transaction()  -> ConfigTransaction (Preparing)
//!        |
//! prepare(txn, cfg)    -> ConfigDiff        (Validated)
//!        |
//! commit(txn)          -> running updated   (Applied)
//!   or abort(txn)      -> discarded         (Aborted)
//!
//! rollback()           -> revert to snapshot (RolledBack)
//! ```

use ruster_config::RouterConfig;

/// State machine for a configuration transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    /// Transaction created, candidate not yet set.
    Preparing,
    /// Candidate validated and diff computed; ready to commit.
    Validated,
    /// Candidate has been applied as the new running config.
    Applied,
    /// Running config has been reverted to the rollback snapshot.
    RolledBack,
    /// Transaction was explicitly discarded without applying.
    Aborted,
}

impl std::fmt::Display for TransactionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preparing => write!(f, "Preparing"),
            Self::Validated => write!(f, "Validated"),
            Self::Applied => write!(f, "Applied"),
            Self::RolledBack => write!(f, "RolledBack"),
            Self::Aborted => write!(f, "Aborted"),
        }
    }
}

/// A configuration transaction capturing candidate and rollback state.
#[derive(Debug, Clone)]
pub struct ConfigTransaction {
    /// The candidate config being prepared.
    candidate: Option<RouterConfig>,
    /// Snapshot of the current running config for rollback.
    rollback_snapshot: RouterConfig,
    /// Current transaction state.
    state: TransactionState,
}

impl ConfigTransaction {
    /// Create a new transaction from the current running config.
    ///
    /// The `running` config is cloned as the rollback snapshot.
    pub(crate) fn new(running: RouterConfig) -> Self {
        Self {
            candidate: None,
            rollback_snapshot: running,
            state: TransactionState::Preparing,
        }
    }

    /// The candidate configuration, if one has been set via `prepare`.
    pub fn candidate(&self) -> Option<&RouterConfig> {
        self.candidate.as_ref()
    }

    /// The rollback snapshot (the running config when the transaction began).
    pub fn rollback_snapshot(&self) -> &RouterConfig {
        &self.rollback_snapshot
    }

    /// Current state of this transaction.
    pub fn state(&self) -> TransactionState {
        self.state
    }

    /// Set the candidate config (called by `ConfigStore::prepare`).
    pub(crate) fn set_candidate(&mut self, config: RouterConfig) {
        self.candidate = Some(config);
    }

    /// Transition to the Validated state.
    pub(crate) fn mark_validated(&mut self) {
        self.state = TransactionState::Validated;
    }

    /// Transition to the Aborted state.
    pub(crate) fn mark_aborted(&mut self) {
        self.state = TransactionState::Aborted;
    }

    /// Consume this transaction and return the candidate config.
    ///
    /// Returns `None` if no candidate was set.
    pub(crate) fn take_candidate(self) -> Option<RouterConfig> {
        self.candidate
    }

    /// Check whether this transaction is in a terminal state (Applied / Aborted / RolledBack).
    pub fn is_consumed(&self) -> bool {
        matches!(
            self.state,
            TransactionState::Applied | TransactionState::Aborted | TransactionState::RolledBack
        )
    }
}

/// Summary of what changed between the running config and the candidate.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigDiff {
    /// Static routes added (prefix strings).
    pub added_routes: Vec<String>,
    /// Static routes removed (prefix strings).
    pub removed_routes: Vec<String>,
    /// Interface names whose config changed.
    pub changed_interfaces: Vec<String>,
    /// Whether NAT configuration changed.
    pub nat_changed: bool,
    /// Whether firewall configuration changed.
    pub firewall_changed: bool,
}

impl ConfigDiff {
    /// Returns true if there are no changes at all.
    pub fn is_empty(&self) -> bool {
        self.added_routes.is_empty()
            && self.removed_routes.is_empty()
            && self.changed_interfaces.is_empty()
            && !self.nat_changed
            && !self.firewall_changed
    }
}

impl std::fmt::Display for ConfigDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            return write!(f, "No changes.");
        }
        let mut parts = Vec::new();
        if !self.added_routes.is_empty() {
            parts.push(format!("routes added: {}", self.added_routes.join(", ")));
        }
        if !self.removed_routes.is_empty() {
            parts.push(format!(
                "routes removed: {}",
                self.removed_routes.join(", ")
            ));
        }
        if !self.changed_interfaces.is_empty() {
            parts.push(format!(
                "interfaces changed: {}",
                self.changed_interfaces.join(", ")
            ));
        }
        if self.nat_changed {
            parts.push("NAT changed".to_string());
        }
        if self.firewall_changed {
            parts.push("firewall changed".to_string());
        }
        write!(f, "{}", parts.join("; "))
    }
}

/// Compute a high-level diff between running and candidate configs.
pub fn compute_diff(running: &RouterConfig, candidate: &RouterConfig) -> ConfigDiff {
    let running_routes: std::collections::HashSet<&str> = running
        .routing
        .ipv4_static_routes
        .iter()
        .map(|r| r.prefix.as_str())
        .collect();
    let candidate_routes: std::collections::HashSet<&str> = candidate
        .routing
        .ipv4_static_routes
        .iter()
        .map(|r| r.prefix.as_str())
        .collect();

    let added_routes: Vec<String> = candidate_routes
        .difference(&running_routes)
        .map(|s| s.to_string())
        .collect();
    let removed_routes: Vec<String> = running_routes
        .difference(&candidate_routes)
        .map(|s| s.to_string())
        .collect();

    // Detect changed interfaces by comparing each interface by name.
    let mut changed_interfaces = Vec::new();
    let running_ifaces: std::collections::HashMap<&str, &ruster_config::model::InterfaceConfig> =
        running
            .interfaces
            .iter()
            .map(|i| (i.name.as_str(), i))
            .collect();
    let candidate_ifaces: std::collections::HashMap<&str, &ruster_config::model::InterfaceConfig> =
        candidate
            .interfaces
            .iter()
            .map(|i| (i.name.as_str(), i))
            .collect();

    // Check interfaces present in both or only in one side.
    let mut all_names: std::collections::HashSet<&str> = std::collections::HashSet::new();
    all_names.extend(running_ifaces.keys());
    all_names.extend(candidate_ifaces.keys());

    for name in all_names {
        match (running_ifaces.get(name), candidate_ifaces.get(name)) {
            (Some(r), Some(c)) => {
                if r != c {
                    changed_interfaces.push(name.to_string());
                }
            }
            _ => {
                // Added or removed interface.
                changed_interfaces.push(name.to_string());
            }
        }
    }
    changed_interfaces.sort();

    let nat_changed = running.nat != candidate.nat;
    let firewall_changed = running.firewall != candidate.firewall;

    ConfigDiff {
        added_routes,
        removed_routes,
        changed_interfaces,
        nat_changed,
        firewall_changed,
    }
}
