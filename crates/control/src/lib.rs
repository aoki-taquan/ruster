pub mod diff;
pub mod error;
pub mod store;

pub use diff::{ChangeKind, ConfigChange};
pub use error::ControlError;
pub use store::{ConfigStore, PlanResult};

use ruster_config::RouterConfig;

/// Convenience: validate a config without a store (backwards-compatible).
pub fn validate(config: &RouterConfig) -> Result<(), ControlError> {
    let store = ConfigStore::new();
    store.validate(config)
}

/// Convenience: plan changes from `running` to `candidate`.
pub fn plan(
    running: Option<&RouterConfig>,
    candidate: &RouterConfig,
) -> Result<PlanResult, ControlError> {
    match running {
        Some(r) => {
            let store = ConfigStore::with_running(r.clone());
            store.plan(candidate)
        }
        None => {
            let store = ConfigStore::new();
            store.plan(candidate)
        }
    }
}

/// Convenience: validate then apply (returns the plan).
pub fn apply(
    running: Option<&RouterConfig>,
    candidate: RouterConfig,
) -> Result<(RouterConfig, PlanResult), ControlError> {
    let mut store = match running {
        Some(r) => ConfigStore::with_running(r.clone()),
        None => ConfigStore::new(),
    };
    let plan = store.apply(candidate)?;
    let new_running = store.running().expect("apply succeeded").clone();
    Ok((new_running, plan))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn example_toml() -> String {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.push("router.toml.example");
        std::fs::read_to_string(&path).expect("example toml")
    }

    fn load_example() -> RouterConfig {
        ruster_config::load_from_str(&example_toml()).expect("valid config")
    }

    // ── validate ──

    #[test]
    fn validate_valid_config_succeeds() {
        let cfg = load_example();
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn validate_empty_hostname_fails() {
        let mut cfg = load_example();
        cfg.meta.hostname = "  ".to_string();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("hostname"));
    }

    // ── plan ──

    #[test]
    fn plan_no_op_returns_no_changes() {
        let cfg = load_example();
        let result = plan(Some(&cfg), &cfg).unwrap();
        assert!(!result.has_changes);
        assert!(result.changes.is_empty());
    }

    #[test]
    fn plan_initial_load_has_changes() {
        let cfg = load_example();
        let result = plan(None, &cfg).unwrap();
        assert!(result.has_changes);
    }

    #[test]
    fn plan_detects_hostname_change() {
        let cfg1 = load_example();
        let mut cfg2 = cfg1.clone();
        cfg2.meta.hostname = "new-host".to_string();
        let result = plan(Some(&cfg1), &cfg2).unwrap();
        assert!(result.has_changes);
        assert!(result.changes.iter().any(|c| c.path == "meta.hostname"));
    }

    #[test]
    fn plan_detects_mtu_change() {
        let cfg1 = load_example();
        let mut cfg2 = cfg1.clone();
        cfg2.interfaces[0].mtu = 9000;
        let result = plan(Some(&cfg1), &cfg2).unwrap();
        assert!(result.has_changes);
        assert!(result.changes.iter().any(|c| c.path.contains("mtu")));
    }

    #[test]
    fn plan_detects_nat_toggle() {
        let cfg1 = load_example();
        let mut cfg2 = cfg1.clone();
        cfg2.nat.enabled = false;
        cfg2.firewall.enabled = false;
        let result = plan(Some(&cfg1), &cfg2).unwrap();
        assert!(result.has_changes);
        assert!(result
            .changes
            .iter()
            .any(|c| c.path.contains("nat") && c.path.contains("enabled")));
    }

    #[test]
    fn plan_display_format() {
        let cfg1 = load_example();
        let mut cfg2 = cfg1.clone();
        cfg2.meta.hostname = "changed".to_string();
        let result = plan(Some(&cfg1), &cfg2).unwrap();
        let display = result.to_string();
        assert!(display.contains("change(s)"));
        assert!(display.contains("meta.hostname"));
    }

    // ── apply ──

    #[test]
    fn apply_sets_new_running() {
        let cfg = load_example();
        let (new_running, plan_result) = apply(None, cfg.clone()).unwrap();
        assert!(plan_result.has_changes);
        assert_eq!(new_running.meta.hostname, cfg.meta.hostname);
    }

    #[test]
    fn apply_rejects_invalid_config() {
        let mut cfg = load_example();
        cfg.meta.hostname = "".to_string();
        let err = apply(None, cfg).unwrap_err();
        assert!(err.to_string().contains("hostname"));
    }

    // ── ConfigStore full flow ──

    #[test]
    fn store_full_validate_plan_apply_commit_flow() {
        let cfg1 = load_example();
        let mut store = ConfigStore::new();

        // Initial apply (no committed baseline yet → pending)
        store.validate(&cfg1).unwrap();
        let p = store.apply(cfg1.clone()).unwrap();
        assert!(p.has_changes);
        assert!(store.has_pending_changes());

        // Commit
        store.commit().unwrap();
        assert!(!store.has_pending_changes());

        // No-op apply
        let p2 = store.plan(&cfg1).unwrap();
        assert!(!p2.has_changes);

        // Modify and apply
        let mut cfg2 = cfg1.clone();
        cfg2.meta.hostname = "updated".to_string();
        let p3 = store.apply(cfg2).unwrap();
        assert!(p3.has_changes);
        assert!(store.has_pending_changes());
        assert_eq!(store.running().unwrap().meta.hostname, "updated");
        assert_eq!(store.committed().unwrap().meta.hostname, "ruster-lab");

        // Commit again
        store.commit().unwrap();
        assert!(!store.has_pending_changes());
        assert_eq!(store.committed().unwrap().meta.hostname, "updated");
    }

    #[test]
    fn store_commit_without_running_fails() {
        let mut store = ConfigStore::new();
        let err = store.commit().unwrap_err();
        assert!(matches!(err, ControlError::NothingToCommit));
    }

    #[test]
    fn store_with_running_has_no_pending() {
        let cfg = load_example();
        let store = ConfigStore::with_running(cfg);
        assert!(!store.has_pending_changes());
    }
}
