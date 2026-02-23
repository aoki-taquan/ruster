//! `ruster-control` -- validate, plan, and apply configuration changes.
//!
//! This crate provides the [`ConfigStore`] type that implements the
//! **validate -> plan -> apply** pipeline for the ruster software router.
//! All configuration mutations are gated by the full semantic validation
//! from [`ruster_config::validate`], ensuring that runtime config changes
//! are held to the same standard as initial config loading.
//!
//! See [`store`] module documentation for the detailed contract.

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

    // ── validate rejects non-hostname invalid configs ──

    #[test]
    fn validate_rejects_duplicate_interface_names() {
        let mut cfg = load_example();
        // Set lan1's name to "lan0" (duplicate of the second interface).
        cfg.interfaces[2].name = "lan0".to_string();
        let err = validate(&cfg).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("duplicate"), "expected 'duplicate' in: {msg}");
        assert!(
            msg.contains("interfaces.name"),
            "expected 'interfaces.name' in: {msg}"
        );
    }

    #[test]
    fn validate_rejects_duplicate_port_ids() {
        let mut cfg = load_example();
        // Set lan1's port_id to 1 (duplicate of lan0).
        cfg.interfaces[2].port_id = 1;
        let err = validate(&cfg).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("port_id"), "expected 'port_id' in: {msg}");
        assert!(msg.contains("duplicate"), "expected 'duplicate' in: {msg}");
    }

    #[test]
    fn validate_rejects_bridge_domain_unknown_member() {
        let mut cfg = load_example();
        cfg.l2.bridge_domains[1].members = vec!["lan0".to_string(), "nonexistent".to_string()];
        let err = validate(&cfg).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("nonexistent"),
            "expected 'nonexistent' in: {msg}"
        );
        assert!(
            msg.contains("bridge_domains"),
            "expected 'bridge_domains' in: {msg}"
        );
    }

    #[test]
    fn validate_rejects_static_route_unknown_out_if() {
        let mut cfg = load_example();
        cfg.routing.ipv4_static_routes[0].out_if = "noexist".to_string();
        let err = validate(&cfg).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("noexist"), "expected 'noexist' in: {msg}");
        assert!(
            msg.contains("static_routes"),
            "expected 'static_routes' in: {msg}"
        );
    }

    #[test]
    fn validate_rejects_nat_external_if_not_wan() {
        let mut cfg = load_example();
        cfg.nat.external_if = "lan0".to_string();
        let err = validate(&cfg).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("nat.external_if"),
            "expected 'nat.external_if' in: {msg}"
        );
    }

    #[test]
    fn validate_rejects_nat_enabled_without_firewall() {
        let mut cfg = load_example();
        cfg.nat.enabled = true;
        cfg.firewall.enabled = false;
        let err = validate(&cfg).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("nat.enabled"),
            "expected 'nat.enabled' in: {msg}"
        );
        assert!(msg.contains("firewall"), "expected 'firewall' in: {msg}");
    }

    #[test]
    fn validate_rejects_firewall_rule_empty_state() {
        let mut cfg = load_example();
        cfg.firewall.rules[0].state = vec![];
        let err = validate(&cfg).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("state"), "expected 'state' in: {msg}");
        assert!(msg.contains("empty"), "expected 'empty' in: {msg}");
    }

    // ── plan/apply reject non-hostname invalid configs ──

    #[test]
    fn plan_rejects_duplicate_interface_names() {
        let valid = load_example();
        let mut invalid = valid.clone();
        invalid.interfaces[2].name = "lan0".to_string();
        let err = plan(Some(&valid), &invalid).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("duplicate"), "expected 'duplicate' in: {msg}");
    }

    #[test]
    fn apply_rejects_duplicate_interface_names() {
        let valid = load_example();
        let mut invalid = valid.clone();
        invalid.interfaces[2].name = "lan0".to_string();
        let err = apply(Some(&valid), invalid).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("duplicate"), "expected 'duplicate' in: {msg}");
    }

    #[test]
    fn apply_rejects_bridge_domain_unknown_member() {
        let valid = load_example();
        let mut invalid = valid.clone();
        invalid.l2.bridge_domains[1].members = vec!["lan0".to_string(), "ghost".to_string()];
        let err = apply(Some(&valid), invalid).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ghost"), "expected 'ghost' in: {msg}");
    }

    // ── state unchanged on validation failure ──

    #[test]
    fn store_apply_validation_failure_preserves_state() {
        let valid = load_example();
        let mut store = ConfigStore::with_running(valid.clone());
        store.commit().unwrap();

        // Build an invalid candidate: duplicate interface names.
        let mut invalid = valid.clone();
        invalid.interfaces[2].name = "lan0".to_string();

        // apply() must fail.
        let err = store.apply(invalid);
        assert!(err.is_err(), "apply should have failed");

        // Running config must be unchanged.
        assert_eq!(
            store.running().unwrap().interfaces[2].name,
            "lan1",
            "running config should be unchanged after failed apply"
        );

        // No pending changes should exist.
        assert!(
            !store.has_pending_changes(),
            "no pending changes after failed apply"
        );
    }

    #[test]
    fn store_plan_validation_failure_preserves_state() {
        let valid = load_example();
        let store = ConfigStore::with_running(valid.clone());

        // Invalid: NAT external_if points to a lan interface.
        let mut invalid = valid.clone();
        invalid.nat.external_if = "lan0".to_string();

        let err = store.plan(&invalid);
        assert!(err.is_err(), "plan should have failed");

        // Running config unchanged.
        assert_eq!(
            store.running().unwrap().nat.external_if,
            "wan0",
            "running config should be unchanged after failed plan"
        );
    }
}
