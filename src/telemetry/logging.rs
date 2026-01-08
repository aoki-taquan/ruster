//! Logging configuration and initialization.
//!
//! Provides flexible logging setup with support for:
//! - Environment variable (RUST_LOG) configuration
//! - config.toml configuration file
//! - Multiple output formats (pretty, compact, json)

use tracing::Level;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

/// Logging configuration from config.toml.
#[derive(Debug, Clone, Default)]
pub struct LogConfig {
    /// Log level: error, warn, info, debug, trace
    pub level: String,
    /// Output format: pretty, compact, json
    pub format: String,
}

impl LogConfig {
    /// Creates a new LogConfig with default values.
    pub fn new() -> Self {
        Self {
            level: "info".to_string(),
            format: "pretty".to_string(),
        }
    }
}

/// Initializes the logging system.
///
/// Priority:
/// 1. RUST_LOG environment variable (if set)
/// 2. config parameter (if provided)
/// 3. Default: info level, pretty format
///
/// # Examples
///
/// ```ignore
/// // Use environment variable
/// std::env::set_var("RUST_LOG", "debug");
/// init_logging(None);
///
/// // Use config file settings
/// let config = LogConfig { level: "debug".into(), format: "json".into() };
/// init_logging(Some(&config));
/// ```
pub fn init_logging(config: Option<&LogConfig>) {
    // Determine log level filter
    let env_filter = if std::env::var("RUST_LOG").is_ok() {
        // RUST_LOG takes priority
        EnvFilter::from_default_env()
    } else if let Some(cfg) = config {
        // Use config file setting
        let level = parse_level(&cfg.level);
        EnvFilter::new(level.as_str())
    } else {
        // Default to info
        EnvFilter::new("info")
    };

    // Get format from config or default
    let format = config.map(|c| c.format.as_str()).unwrap_or("pretty");

    // Build and set subscriber based on format
    match format {
        "json" => {
            let subscriber = tracing_subscriber::registry().with(env_filter).with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_span_events(FmtSpan::CLOSE),
            );
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
        "compact" => {
            let subscriber = tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer().compact());
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
        _ => {
            // "pretty" or default
            let subscriber = tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer());
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
    }
}

/// Parses a log level string into a Level.
fn parse_level(level: &str) -> Level {
    match level.to_lowercase().as_str() {
        "error" => Level::ERROR,
        "warn" => Level::WARN,
        "info" => Level::INFO,
        "debug" => Level::DEBUG,
        "trace" => Level::TRACE,
        _ => Level::INFO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_level() {
        assert_eq!(parse_level("error"), Level::ERROR);
        assert_eq!(parse_level("warn"), Level::WARN);
        assert_eq!(parse_level("info"), Level::INFO);
        assert_eq!(parse_level("debug"), Level::DEBUG);
        assert_eq!(parse_level("trace"), Level::TRACE);
        assert_eq!(parse_level("INFO"), Level::INFO);
        assert_eq!(parse_level("unknown"), Level::INFO);
    }

    #[test]
    fn test_log_config_default() {
        let config = LogConfig::new();
        assert_eq!(config.level, "info");
        assert_eq!(config.format, "pretty");
    }
}
