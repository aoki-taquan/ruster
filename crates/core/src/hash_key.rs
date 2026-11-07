//! The secret key of the per-publication hashed tables (fragment tracking, the
//! limiter of translated ICMP errors), each in its own hash domain.

use crate::fixed_directory::DirectoryHashKey;

/// Secret key of a publication's hashed tables. The control plane generates a
/// fresh unpredictable key for every publication.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ResolutionHashKey(DirectoryHashKey);

impl std::fmt::Debug for ResolutionHashKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResolutionHashKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResolutionHashKeyError {
    AllZero,
}

impl ResolutionHashKey {
    /// Constructs a control-plane supplied resolution index key.
    pub const fn new(first: u64, second: u64) -> Result<Self, ResolutionHashKeyError> {
        match DirectoryHashKey::new(first, second) {
            Ok(key) => Ok(Self(key)),
            Err(_) => Err(ResolutionHashKeyError::AllZero),
        }
    }

    /// The secret, for other per-publication uses in their own hash domain.
    pub(crate) const fn directory_key(self) -> DirectoryHashKey {
        self.0
    }
}
