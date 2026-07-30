#![deny(unsafe_code)]
#![doc = "Checked configuration and Linux UAPI ABI facts for a future native AF_XDP backend."]
#![doc = ""]
#![doc = "This crate does not open sockets, map memory, access native rings, implement packet I/O,"]
#![doc = "or link libxdp. Its first slice is cold-path validation only."]

mod config;
mod error;
mod platform;

#[path = "native_unsafe/abi.rs"]
pub mod abi;

pub use config::{
    validate_descriptor_options, BindMode, RingConfig, RingEntries, RingName, UmemConfig,
    ValidatedBindFlags,
};
pub use error::{AbiLayoutError, ConfigError, PlatformError, RingField};
pub use platform::ensure_supported;

#[cfg(test)]
mod tests;
