use anyhow::{bail, Result};
use ruster_config::RouterConfig;

#[derive(Debug, Clone, Copy)]
pub struct PlanResult {
    pub has_changes: bool,
}

pub fn validate(config: &RouterConfig) -> Result<()> {
    if config.hostname.trim().is_empty() {
        bail!("hostname must not be empty");
    }
    Ok(())
}

pub fn plan(_running: Option<&RouterConfig>, _candidate: &RouterConfig) -> PlanResult {
    PlanResult { has_changes: true }
}

pub fn apply(candidate: RouterConfig) -> Result<RouterConfig> {
    validate(&candidate)?;
    Ok(candidate)
}
