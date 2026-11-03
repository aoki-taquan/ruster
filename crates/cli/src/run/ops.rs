//! The watch settings of `ruster run` from `[health]` and `[watch]`
//! (OPS-LOG).
//!
//! Every health threshold and watch interval is a config key. Each key
//! resolves on its own, in this order:
//!
//! 1. the key in the document (startup: the `--config` file; reload: the
//!    re-read file);
//! 2. the matching `ruster run` flag, for the four keys that have one
//!    (`--tx-stall-warn-secs`, `--tx-stall-fatal-secs`,
//!    `--kick-errors-fatal-secs`, `--link-stale-secs`; deprecated, kept
//!    for compatibility);
//! 3. the built-in default (the behaviour before OPS-LOG).
//!
//! A flag therefore acts as the default for a key the document does not
//! set, at startup and at every reload. A flag given with a value other
//! than its default under a document that sets the key is overridden; the
//! startup warns once per such flag ([`overridden_flags`]).
//!
//! The document validator bounds every key ([`ruster_config`]); the
//! merged values are checked again here, because a document key and a flag
//! can disagree (`tx-stall-fatal-ms` below `tx-stall-warn-ms`). A merge
//! that fails is an invalid configuration: exit 2 at startup, `reload
//! failed: stage=health ...` (the old settings stay) at a reload.
//!
//! Every key is reloadable: the watch decides on cold samples between
//! ticks, so new thresholds and intervals apply from the next sample
//! after an applied reload ([`super::engine::run_loop`]). A failed or
//! refused reload changes none of them.

use std::fmt;

use ruster_config::ValidatedConfigV1;

use super::watch::{Limits, Thresholds, HEALTH_INTERVAL_MS, LINK_INTERVAL_MS};
use super::Settings;

/// The resolved watch settings of one document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ops {
    pub thresholds: Thresholds,
    pub limits: Limits,
    pub health_interval_ms: u64,
    pub link_interval_ms: u64,
    pub link_stale_ms: u64,
}

impl Default for Ops {
    /// The built-in defaults.
    fn default() -> Self {
        Self {
            thresholds: Thresholds::default(),
            limits: Limits::default(),
            health_interval_ms: HEALTH_INTERVAL_MS,
            link_interval_ms: LINK_INTERVAL_MS,
            link_stale_ms: super::watch::DEFAULT_LINK_STALE_MS,
        }
    }
}

/// What a key falls back to when the document does not set it: the flags
/// (and, in tests, the intervals) of the run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fallback {
    pub thresholds: Thresholds,
    pub health_interval_ms: u64,
    pub link_interval_ms: u64,
    pub link_stale_ms: u64,
}

impl Default for Fallback {
    fn default() -> Self {
        Self::from(&Ops::default())
    }
}

impl From<&Ops> for Fallback {
    fn from(ops: &Ops) -> Self {
        Self {
            thresholds: ops.thresholds,
            health_interval_ms: ops.health_interval_ms,
            link_interval_ms: ops.link_interval_ms,
            link_stale_ms: ops.link_stale_ms,
        }
    }
}

impl From<&Settings> for Fallback {
    fn from(settings: &Settings) -> Self {
        Self {
            thresholds: settings.thresholds,
            health_interval_ms: settings.health_interval_ms,
            link_interval_ms: settings.link_interval_ms,
            link_stale_ms: settings.link_stale_ms,
        }
    }
}

/// The merged values disagree. Value-free apart from the two bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpsError {
    /// The effective `tx-stall-fatal-ms` is neither 0 nor at least the
    /// effective `tx-stall-warn-ms` (one of them from a flag).
    FatalBelowWarning { warn_ms: u64, fatal_ms: u64 },
}

impl fmt::Display for OpsError {
    /// `stage=health code=... path=... limit=... actual=...`, like a
    /// document rejection.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FatalBelowWarning { warn_ms, fatal_ms } => write!(
                formatter,
                "stage=health code=HEALTH_FATAL_BELOW_WARNING path=health.tx-stall-fatal-ms \
                 limit={warn_ms} actual={fatal_ms}"
            ),
        }
    }
}

/// A count of `[health]` as a `u32` threshold (validated to fit).
fn count(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// 0 disables a fatal exit.
fn fatal(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

impl Ops {
    /// The settings of `config`, each key falling back to `fallback`, then
    /// to the default (module documentation).
    pub fn resolve(config: &ValidatedConfigV1, fallback: Fallback) -> Result<Self, OpsError> {
        let health = config.health();
        let watch = config.watch();
        let limits = Limits::default();
        let flags = fallback.thresholds;
        let thresholds = Thresholds {
            tx_stall_warn_ms: health.tx_stall_warn_ms.unwrap_or(flags.tx_stall_warn_ms),
            tx_stall_fatal_ms: health
                .tx_stall_fatal_ms
                .map_or(flags.tx_stall_fatal_ms, fatal),
            kick_errors_fatal_ms: health
                .kick_errors_fatal_ms
                .map_or(flags.kick_errors_fatal_ms, fatal),
        };
        if let Some(fatal_ms) = thresholds.tx_stall_fatal_ms {
            if fatal_ms < thresholds.tx_stall_warn_ms {
                return Err(OpsError::FatalBelowWarning {
                    warn_ms: thresholds.tx_stall_warn_ms,
                    fatal_ms,
                });
            }
        }
        Ok(Self {
            thresholds,
            limits: Limits {
                fill_starved_warn_ms: health
                    .fill_starved_warn_ms
                    .unwrap_or(limits.fill_starved_warn_ms),
                link_probe_failures_fatal: health
                    .link_probe_failures_fatal
                    .map_or(limits.link_probe_failures_fatal, count),
                link_dump_interrupted_fatal: health
                    .link_dump_interrupted_fatal
                    .map_or(limits.link_dump_interrupted_fatal, count),
                frames_quarantined_fatal: health
                    .frames_quarantined_fatal
                    .map_or(limits.frames_quarantined_fatal, fatal),
                tx_invalid_descs_fatal: health
                    .tx_invalid_descs_fatal
                    .map_or(limits.tx_invalid_descs_fatal, fatal),
            },
            health_interval_ms: watch
                .health_interval_ms
                .unwrap_or(fallback.health_interval_ms),
            link_interval_ms: watch.link_interval_ms.unwrap_or(fallback.link_interval_ms),
            link_stale_ms: watch.link_stale_ms.unwrap_or(fallback.link_stale_ms),
        })
    }
}

impl fmt::Display for Ops {
    /// Every effective value as `key=value` in milliseconds or counts, 0
    /// for a disabled fatal exit (the `watch settings applied` line).
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let off = |value: Option<u64>| value.unwrap_or(0);
        write!(
            formatter,
            "tx-stall-warn-ms={} tx-stall-fatal-ms={} kick-errors-fatal-ms={} \
             fill-starved-warn-ms={} link-probe-failures-fatal={} \
             link-dump-interrupted-fatal={} frames-quarantined-fatal={} \
             tx-invalid-descs-fatal={} health-interval-ms={} link-interval-ms={} \
             link-stale-ms={}",
            self.thresholds.tx_stall_warn_ms,
            off(self.thresholds.tx_stall_fatal_ms),
            off(self.thresholds.kick_errors_fatal_ms),
            self.limits.fill_starved_warn_ms,
            self.limits.link_probe_failures_fatal,
            self.limits.link_dump_interrupted_fatal,
            off(self.limits.frames_quarantined_fatal),
            off(self.limits.tx_invalid_descs_fatal),
            self.health_interval_ms,
            self.link_interval_ms,
            self.link_stale_ms,
        )
    }
}

/// The flags given with a non-default value whose key `config` sets (the
/// document wins; the startup warns once per flag).
pub fn overridden_flags(config: &ValidatedConfigV1, fallback: Fallback) -> Vec<&'static str> {
    let health = config.health();
    let defaults = Fallback::default();
    let flags = fallback.thresholds;
    let mut overridden = Vec::new();
    for (set, differs, flag) in [
        (
            health.tx_stall_warn_ms.is_some(),
            flags.tx_stall_warn_ms != defaults.thresholds.tx_stall_warn_ms,
            "--tx-stall-warn-secs",
        ),
        (
            health.tx_stall_fatal_ms.is_some(),
            flags.tx_stall_fatal_ms != defaults.thresholds.tx_stall_fatal_ms,
            "--tx-stall-fatal-secs",
        ),
        (
            health.kick_errors_fatal_ms.is_some(),
            flags.kick_errors_fatal_ms != defaults.thresholds.kick_errors_fatal_ms,
            "--kick-errors-fatal-secs",
        ),
        (
            config.watch().link_stale_ms.is_some(),
            fallback.link_stale_ms != defaults.link_stale_ms,
            "--link-stale-secs",
        ),
    ] {
        if set && differs {
            overridden.push(flag);
        }
    }
    overridden
}

/// The `[health]` or `[watch]` key a flag stands for.
pub const fn key_of(flag: &str) -> &'static str {
    match flag.as_bytes() {
        b"--tx-stall-warn-secs" => "[health] tx-stall-warn-ms",
        b"--tx-stall-fatal-secs" => "[health] tx-stall-fatal-ms",
        b"--kick-errors-fatal-secs" => "[health] kick-errors-fatal-ms",
        _ => "[watch] link-stale-ms",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str) -> ValidatedConfigV1 {
        let base = include_str!("../../../../fixtures/m1/router-v1.toml");
        let text = format!("{base}\n{extra}\n");
        match crate::config_cmd::validate_bytes(text.as_bytes()) {
            Ok(config) => config,
            Err(error) => panic!("valid config: {}", error.render()),
        }
    }

    /// Defaults equal the behaviour before OPS-LOG.
    #[test]
    fn the_defaults_are_the_old_constants() {
        let ops = Ops::resolve(&config(""), Fallback::default()).expect("resolves");
        assert_eq!(ops, Ops::default());
        assert_eq!(ops.thresholds, Thresholds::from_secs(1, 10, 5));
        assert_eq!(
            (
                ops.health_interval_ms,
                ops.link_interval_ms,
                ops.link_stale_ms
            ),
            (500, 1_000, 5_000)
        );
        assert_eq!(
            ops.limits,
            Limits {
                fill_starved_warn_ms: 1_000,
                link_probe_failures_fatal: 3,
                link_dump_interrupted_fatal: 10,
                frames_quarantined_fatal: Some(64),
                tx_invalid_descs_fatal: Some(64),
            }
        );
        assert_eq!(
            ops.to_string(),
            "tx-stall-warn-ms=1000 tx-stall-fatal-ms=10000 kick-errors-fatal-ms=5000 \
             fill-starved-warn-ms=1000 link-probe-failures-fatal=3 \
             link-dump-interrupted-fatal=10 frames-quarantined-fatal=64 \
             tx-invalid-descs-fatal=64 health-interval-ms=500 link-interval-ms=1000 \
             link-stale-ms=5000"
        );
    }

    /// The document wins over a flag, a flag over the default; 0 disables
    /// a fatal exit; every key resolves on its own.
    #[test]
    fn a_document_key_wins_over_its_flag_which_wins_over_the_default() {
        let flags = Fallback {
            thresholds: Thresholds::from_secs(2, 20, 0),
            link_stale_ms: 9_000,
            ..Fallback::default()
        };
        let plain = Ops::resolve(&config(""), flags).expect("resolves");
        assert_eq!(plain.thresholds, Thresholds::from_secs(2, 20, 0));
        assert_eq!(plain.link_stale_ms, 9_000);
        assert!(overridden_flags(&config(""), flags).is_empty());

        let keyed = config(
            "[health]\ntx-stall-warn-ms = 3000\nkick-errors-fatal-ms = 700\n\
             frames-quarantined-fatal = 0\ntx-invalid-descs-fatal = 5\n\
             fill-starved-warn-ms = 200\nlink-probe-failures-fatal = 7\n\
             link-dump-interrupted-fatal = 11\n\n\
             [watch]\nhealth-interval-ms = 150\nlink-interval-ms = 250\nlink-stale-ms = 1000",
        );
        let ops = Ops::resolve(&keyed, flags).expect("resolves");
        assert_eq!(
            ops,
            Ops {
                thresholds: Thresholds {
                    tx_stall_warn_ms: 3_000,
                    // Not in the document: the flag.
                    tx_stall_fatal_ms: Some(20_000),
                    kick_errors_fatal_ms: Some(700),
                },
                limits: Limits {
                    fill_starved_warn_ms: 200,
                    link_probe_failures_fatal: 7,
                    link_dump_interrupted_fatal: 11,
                    frames_quarantined_fatal: None,
                    tx_invalid_descs_fatal: Some(5),
                },
                health_interval_ms: 150,
                link_interval_ms: 250,
                link_stale_ms: 1_000,
            }
        );
        // Three flags differ from their default and their key is set; the
        // fatal TX stall flag's key is not set.
        assert_eq!(
            overridden_flags(&keyed, flags),
            [
                "--tx-stall-warn-secs",
                "--kick-errors-fatal-secs",
                "--link-stale-secs"
            ]
        );
        assert_eq!(key_of("--link-stale-secs"), "[watch] link-stale-ms");
        assert_eq!(key_of("--tx-stall-warn-secs"), "[health] tx-stall-warn-ms");
        // Default-valued flags are never reported.
        assert!(overridden_flags(&keyed, Fallback::default()).is_empty());
    }

    /// A merge of a document key and a flag that disagree fails closed.
    #[test]
    fn a_merged_fatal_below_the_warning_fails_closed() {
        let warn_only_doc = config("[health]\ntx-stall-warn-ms = 20000");
        let error = Ops::resolve(&warn_only_doc, Fallback::default()).expect_err("10 s < 20 s");
        assert_eq!(
            error,
            OpsError::FatalBelowWarning {
                warn_ms: 20_000,
                fatal_ms: 10_000
            }
        );
        assert_eq!(
            error.to_string(),
            "stage=health code=HEALTH_FATAL_BELOW_WARNING path=health.tx-stall-fatal-ms \
             limit=20000 actual=10000"
        );
        // With the fatal exit off, or a key above, it resolves.
        let flags = Fallback {
            thresholds: Thresholds::from_secs(1, 0, 5),
            ..Fallback::default()
        };
        assert!(Ops::resolve(&warn_only_doc, flags).is_ok());
        let both = config("[health]\ntx-stall-warn-ms = 20000\ntx-stall-fatal-ms = 20000");
        assert!(Ops::resolve(&both, Fallback::default()).is_ok());
    }
}
