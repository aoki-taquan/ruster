//! Configuration management
//!
//! Handles config.toml (user-defined) and config.lock (generated with all defaults).

mod types;

pub use types::*;

use crate::{Error, Result};
use std::path::Path;

/// Load configuration from a TOML file
pub fn load<P: AsRef<Path>>(path: P) -> Result<Config> {
    let content = std::fs::read_to_string(path).map_err(Error::Io)?;
    let config: Config = toml::from_str(&content).map_err(|e| Error::Config(e.to_string()))?;
    Ok(config)
}

/// Generate a lock file from config, filling in all defaults
pub fn generate_lock(config: &Config) -> ConfigLock {
    ConfigLock::from_config(config)
}
