//! SRv6 configuration types.
//!
//! These types correspond to the `[srv6]` section of `router.toml`.
//! They are used internally by the SRv6 engine and are constructed
//! from the config model types in `ruster-config`.

use super::usid::{DEFAULT_BLOCK_LEN, DEFAULT_USID_LEN};

/// Top-level SRv6 configuration.
///
/// Corresponds to the `[srv6]` section in `router.toml`.
///
/// ```toml
/// [srv6]
/// locator_block = "fd00::"
/// block_len = 32
/// usid_len = 16
///
/// [[srv6.local_sids]]
/// sid = "fd00:1::"
/// action = "end"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv6Config {
    /// Locator block address (e.g., "fd00::").
    pub locator_block: String,
    /// Block prefix length in bits.
    pub block_len: u8,
    /// uSID length in bits.
    pub usid_len: u8,
    /// Local SID entries.
    pub local_sids: Vec<LocalSidConfig>,
}

impl Default for Srv6Config {
    fn default() -> Self {
        Self {
            locator_block: "fd00::".to_string(),
            block_len: DEFAULT_BLOCK_LEN,
            usid_len: DEFAULT_USID_LEN,
            local_sids: Vec::new(),
        }
    }
}

/// A single local SID configuration entry.
///
/// ```toml
/// [[srv6.local_sids]]
/// sid = "fd00:1::"
/// action = "end"
/// table = "default"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSidConfig {
    /// SID address string, optionally with prefix (e.g., "fd00:1::" or "fd00::/32").
    pub sid: String,
    /// Action name (e.g., "end", "end_dt4", "end_dt6", "un").
    pub action: String,
    /// Optional VRF table name for decap actions.
    pub table: Option<String>,
}

impl Srv6Config {
    /// Validate the SRv6 configuration.
    ///
    /// Returns a list of validation error messages, or an empty vec if valid.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Block length must be a multiple of 8 and > 0.
        if self.block_len == 0 || !self.block_len.is_multiple_of(8) {
            errors.push(format!(
                "block_len must be a positive multiple of 8, got {}",
                self.block_len
            ));
        }

        // uSID length must be a multiple of 8 and > 0.
        if self.usid_len == 0 || !self.usid_len.is_multiple_of(8) {
            errors.push(format!(
                "usid_len must be a positive multiple of 8, got {}",
                self.usid_len
            ));
        }

        // Block + at least one uSID must fit in 128 bits.
        if self.block_len as u32 + self.usid_len as u32 > 128 {
            errors.push(format!(
                "block_len ({}) + usid_len ({}) exceeds 128 bits",
                self.block_len, self.usid_len
            ));
        }

        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = Srv6Config::default();
        assert_eq!(config.block_len, 32);
        assert_eq!(config.usid_len, 16);
        assert!(config.local_sids.is_empty());
    }

    #[test]
    fn validate_default_config() {
        let config = Srv6Config::default();
        assert!(config.validate().is_empty());
    }

    #[test]
    fn validate_invalid_block_len() {
        let config = Srv6Config {
            block_len: 0,
            ..Srv6Config::default()
        };
        let errors = config.validate();
        assert!(!errors.is_empty());
        assert!(errors[0].contains("block_len"));
    }

    #[test]
    fn validate_non_byte_aligned_usid() {
        let config = Srv6Config {
            usid_len: 13,
            ..Srv6Config::default()
        };
        let errors = config.validate();
        assert!(!errors.is_empty());
    }

    #[test]
    fn validate_exceeds_128_bits() {
        let config = Srv6Config {
            block_len: 120,
            usid_len: 16,
            ..Srv6Config::default()
        };
        let errors = config.validate();
        assert!(!errors.is_empty());
        assert!(errors[0].contains("exceeds 128 bits"));
    }
}
