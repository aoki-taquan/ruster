use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    pub hostname: String,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
}

pub fn load_from_str(input: &str) -> Result<RouterConfig, ConfigError> {
    toml::from_str(input).map_err(ConfigError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let cfg = load_from_str("hostname = \"ruster-lab\"").expect("valid config");
        assert_eq!(cfg.hostname, "ruster-lab");
    }
}
