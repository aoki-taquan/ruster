//! Telemetry module for logging and metrics.
//!
//! Provides:
//! - Logging configuration and initialization
//! - Metrics collection for packet statistics

mod logging;
mod metrics;

pub use logging::{init_logging, LogConfig};
pub use metrics::{Counter, InterfaceStats, MetricsRegistry};
