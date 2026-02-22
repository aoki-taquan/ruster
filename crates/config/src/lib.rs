pub mod model;
pub mod validate;

pub use model::RouterConfig;
pub use validate::ValidationError;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),

    #[error("validation failed:\n{}", .0.iter().map(|e| format!("  - {e}")).collect::<Vec<_>>().join("\n"))]
    Validation(Vec<ValidationError>),
}

pub fn load_from_str(input: &str) -> Result<RouterConfig, ConfigError> {
    let config: RouterConfig = toml::from_str(input)?;
    validate::validate(&config).map_err(ConfigError::Validation)?;
    Ok(config)
}

pub fn load_from_file(path: &str) -> Result<RouterConfig, ConfigError> {
    let content = std::fs::read_to_string(path)?;
    load_from_str(&content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn example_toml() -> String {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop(); // crates
        path.pop(); // project root
        path.push("router.toml.example");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
    }

    fn make_valid_toml() -> String {
        example_toml()
    }

    #[test]
    fn load_example_toml_succeeds() {
        let cfg = load_from_str(&example_toml()).expect("example config should be valid");
        assert_eq!(cfg.meta.hostname, "ruster-lab");
        assert_eq!(cfg.interfaces.len(), 3);
        assert_eq!(cfg.l2.bridge_domains.len(), 2);
    }

    #[test]
    fn reject_unknown_field() {
        let toml = format!("{}\n[extra]\nfoo = 1\n", make_valid_toml());
        let err = load_from_str(&toml).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn reject_duplicate_interface_name() {
        let toml = make_valid_toml().replace("name = \"lan1\"", "name = \"lan0\"");
        let err = load_from_str(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("interfaces.name"),
            "error should mention field: {msg}"
        );
        assert!(
            msg.contains("duplicate"),
            "error should mention reason: {msg}"
        );
    }

    #[test]
    fn reject_duplicate_port_id() {
        let toml = make_valid_toml().replace("port_id = 2", "port_id = 1");
        let err = load_from_str(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("port_id"), "error should mention field: {msg}");
        assert!(
            msg.contains("duplicate"),
            "error should mention reason: {msg}"
        );
    }

    #[test]
    fn reject_bridge_domain_unknown_member() {
        let toml = make_valid_toml().replace(
            r#"members = ["lan0", "lan1"]"#,
            r#"members = ["lan0", "nonexistent"]"#,
        );
        let err = load_from_str(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("bridge_domains"),
            "error should mention field: {msg}"
        );
        assert!(
            msg.contains("nonexistent"),
            "error should mention reason: {msg}"
        );
    }

    #[test]
    fn reject_static_route_unknown_out_if() {
        let toml = make_valid_toml().replace(r#"out_if = "wan0""#, r#"out_if = "noexist""#);
        let err = load_from_str(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("static_routes"),
            "error should mention field: {msg}"
        );
        assert!(
            msg.contains("noexist"),
            "error should mention reason: {msg}"
        );
    }

    #[test]
    fn reject_nat_external_if_not_wan() {
        let toml = make_valid_toml().replace(r#"external_if = "wan0""#, r#"external_if = "lan0""#);
        let err = load_from_str(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("nat.external_if"),
            "error should mention field: {msg}"
        );
    }

    #[test]
    fn reject_nat_enabled_without_firewall() {
        let toml =
            make_valid_toml().replace("[firewall]\nenabled = true", "[firewall]\nenabled = false");
        let err = load_from_str(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("nat.enabled"),
            "error should mention field: {msg}"
        );
        assert!(
            msg.contains("firewall"),
            "error should mention reason: {msg}"
        );
    }

    #[test]
    fn reject_firewall_rule_empty_state() {
        let toml = make_valid_toml().replace(r#"state = ["new"]"#, r#"state = []"#);
        let err = load_from_str(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("state"), "error should mention field: {msg}");
        assert!(msg.contains("empty"), "error should mention reason: {msg}");
    }
}
