//! Configuration management
//!
//! Handles config.toml (user-defined) and config.lock (generated with all defaults).

mod types;
mod validation;

pub use types::*;
pub use validation::{validate, ValidationResult};

use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Load configuration from a TOML file
pub fn load<P: AsRef<Path>>(path: P) -> Result<Config> {
    let content = std::fs::read_to_string(path).map_err(Error::Io)?;
    let config: Config = toml::from_str(&content).map_err(|e| Error::Config(e.to_string()))?;
    Ok(config)
}

/// Generate a lock file from config, filling in all defaults
pub fn generate_lock(config: &Config, source_content: &str) -> ConfigLock {
    let source_hash = compute_hash(source_content);
    ConfigLock::from_config(config, source_hash)
}

fn compute_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}
