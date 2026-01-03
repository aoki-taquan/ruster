//! Ruster - Software Router
//!
//! A software router implementation in Rust for learning network protocols.
//! L2+ protocols are implemented from scratch in userspace.

pub mod capture;
pub mod config;
pub mod dataplane;
pub mod error;
pub mod protocol;

pub use error::{Error, Result};
