//! Hand-written argument parsing (no external parser).
//!
//! Options are matched on their UTF-8 spelling; operands stay `OsString` so
//! non-UTF-8 paths work. `--` ends option parsing for the remaining operands.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::PathBuf;

pub const USAGE: &str = "\
usage:
  ruster validate <config.toml>
  ruster plan <current.toml> <next.toml>
  ruster run-sim [--hold] --scenario <scenario.toml>
  ruster run-sim [--hold] -- <scenario.toml>
  ruster run [--allow-multi-queue] [--stats-interval <seconds>]
             [--startup-attempts <n>] --config <config.toml>
  ruster run [options] -- <config.toml>
  ruster --help | --version

`run`: SIGINT/SIGTERM stop (a second one forces), SIGHUP reloads the config.

exit status: 0 success or signal shutdown, 1 runtime/I/O/expectation failure
(including unreadable files, and `run` stopped by a fatal health or device
event), 2 usage error or invalid config/scenario;
`run` also: 3 shutdown deadline passed with TX frames still in the kernel,
4 missing privilege or too small RLIMIT_MEMLOCK (nothing was acquired)
";

/// Default `ruster run --stats-interval` in seconds.
pub const DEFAULT_STATS_INTERVAL_SECS: u64 = 60;
/// Largest accepted `--stats-interval` (one day).
pub const MAX_STATS_INTERVAL_SECS: u64 = 86_400;
/// Default `ruster run --startup-attempts` (XDP-045).
pub const DEFAULT_STARTUP_ATTEMPTS: u32 = 3;
/// Largest accepted `--startup-attempts`.
pub const MAX_STARTUP_ATTEMPTS: u32 = 10;

/// `ruster run` options.
#[derive(Debug, Eq, PartialEq)]
pub struct RunArgs {
    pub config: PathBuf,
    /// Accept a port device with more than one RX queue (XDP-063): the
    /// operator asserts that RSS/ntuple steers every frame to the bound
    /// queue; frames on other queues are dropped by the XDP program.
    pub allow_multi_queue: bool,
    /// Seconds between periodic stats blocks on stdout; 0 disables them
    /// (the final block is always printed).
    pub stats_interval_secs: u64,
    /// Whole startups tried when a port open fails transiently (XDP-045:
    /// `BIND/BUSY`, `REGISTER_UMEM/MEMLOCK_LIMIT`, ...), each after a full
    /// rollback; `1..=MAX_STARTUP_ATTEMPTS`, 1 disables the retry.
    pub startup_attempts: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Help,
    Version,
    Validate { config: PathBuf },
    Plan { current: PathBuf, next: PathBuf },
    RunSim { scenario: PathBuf, hold: bool },
    Run(RunArgs),
}

/// A usage error. Holds only fixed labels and, for an unrecognised word,
/// its lossy text so the operator can see what was rejected.
#[derive(Debug, Eq, PartialEq)]
pub enum UsageError {
    MissingCommand,
    UnknownCommand(String),
    UnknownOption(String),
    UnexpectedOperand(String),
    MissingOperand(&'static str),
    MissingValue(&'static str),
    DuplicateOption(&'static str),
    InvalidValue(&'static str),
}

impl fmt::Display for UsageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCommand => formatter.write_str("missing command"),
            Self::UnknownCommand(word) => write!(formatter, "unknown command {word:?}"),
            Self::UnknownOption(word) => write!(formatter, "unknown option {word:?}"),
            Self::UnexpectedOperand(word) => write!(formatter, "unexpected operand {word:?}"),
            Self::MissingOperand(name) => write!(formatter, "missing operand <{name}>"),
            Self::MissingValue(option) => write!(formatter, "option {option} requires a value"),
            Self::DuplicateOption(option) => write!(formatter, "option {option} given twice"),
            Self::InvalidValue(option @ "--startup-attempts") => write!(
                formatter,
                "option {option} needs a whole number from 1 to {MAX_STARTUP_ATTEMPTS}"
            ),
            Self::InvalidValue(option) => write!(
                formatter,
                "option {option} needs a whole number of seconds from 0 to {MAX_STATS_INTERVAL_SECS}"
            ),
        }
    }
}

/// Parses the arguments after the program name.
pub fn parse<I: IntoIterator<Item = OsString>>(args: I) -> Result<Command, UsageError> {
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Err(UsageError::MissingCommand);
    };
    let rest: Vec<OsString> = args.collect();
    match first.to_str() {
        Some("-h" | "--help" | "help") => Ok(Command::Help),
        Some("-V" | "--version") => Ok(Command::Version),
        Some("validate") => {
            let words = split(&rest)?;
            if words.help {
                return Ok(Command::Help);
            }
            let [config] = operands(words.operands, ["config.toml"])?;
            Ok(Command::Validate { config })
        }
        Some("plan") => {
            let words = split(&rest)?;
            if words.help {
                return Ok(Command::Help);
            }
            let [current, next] = operands(words.operands, ["current.toml", "next.toml"])?;
            Ok(Command::Plan { current, next })
        }
        Some("run-sim") => parse_run_sim(&rest),
        Some("run") => parse_run(&rest),
        _ if is_option(&first) => Err(UsageError::UnknownOption(lossy(&first))),
        _ => Err(UsageError::UnknownCommand(lossy(&first))),
    }
}

fn parse_run_sim(rest: &[OsString]) -> Result<Command, UsageError> {
    let mut scenario = None;
    let mut hold = false;
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        if let Some(value) = equals_value(word, "--scenario=") {
            if value.is_empty() {
                return Err(UsageError::MissingValue("--scenario"));
            }
            set_once(&mut scenario, value.into(), "--scenario")?;
            continue;
        }
        match word.to_str() {
            Some("--") => {
                // `run-sim [--hold] -- <scenario.toml>`: the one operand
                // after `--` is the scenario, even if it starts with `-`.
                let value = words.next().ok_or(UsageError::MissingValue("--scenario"))?;
                set_once(&mut scenario, value.into(), "--scenario")?;
                if let Some(extra) = words.next() {
                    return Err(UsageError::UnexpectedOperand(lossy(extra)));
                }
            }
            Some("-h" | "--help") => return Ok(Command::Help),
            Some("--hold") if hold => return Err(UsageError::DuplicateOption("--hold")),
            Some("--hold") => hold = true,
            Some("--scenario") => {
                // A flag-like word is not taken as the value; use
                // `--scenario=<path>` or `--` for such paths.
                let value = words
                    .next()
                    .filter(|value| !is_option(value))
                    .ok_or(UsageError::MissingValue("--scenario"))?;
                set_once(&mut scenario, value.into(), "--scenario")?;
            }
            _ if is_option(word) => return Err(UsageError::UnknownOption(lossy(word))),
            _ => return Err(UsageError::UnexpectedOperand(lossy(word))),
        }
    }
    let scenario = scenario.ok_or(UsageError::MissingValue("--scenario"))?;
    Ok(Command::RunSim { scenario, hold })
}

/// The value of `<prefix><value>`, split on the raw bytes on Unix so a
/// non-UTF-8 value is preserved.
fn equals_value(word: &OsStr, prefix: &str) -> Option<OsString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let value = word.as_bytes().strip_prefix(prefix.as_bytes())?;
        Some(OsStr::from_bytes(value).to_owned())
    }
    #[cfg(not(unix))]
    {
        word.to_str()?.strip_prefix(prefix).map(OsString::from)
    }
}

fn parse_run(rest: &[OsString]) -> Result<Command, UsageError> {
    let mut config = None;
    let mut allow_multi_queue = false;
    let mut interval = None;
    let mut attempts = None;
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        if let Some(value) = equals_value(word, "--config=") {
            if value.is_empty() {
                return Err(UsageError::MissingValue("--config"));
            }
            set_once(&mut config, value.into(), "--config")?;
            continue;
        }
        if let Some(value) = equals_value(word, "--stats-interval=") {
            set_interval(&mut interval, &value)?;
            continue;
        }
        if let Some(value) = equals_value(word, "--startup-attempts=") {
            set_attempts(&mut attempts, &value)?;
            continue;
        }
        match word.to_str() {
            Some("--") => {
                // `run [options] -- <config.toml>`: the one operand after
                // `--` is the config, even if it starts with `-`.
                let value = words.next().ok_or(UsageError::MissingValue("--config"))?;
                set_once(&mut config, value.into(), "--config")?;
                if let Some(extra) = words.next() {
                    return Err(UsageError::UnexpectedOperand(lossy(extra)));
                }
            }
            Some("-h" | "--help") => return Ok(Command::Help),
            Some("--allow-multi-queue") if allow_multi_queue => {
                return Err(UsageError::DuplicateOption("--allow-multi-queue"))
            }
            Some("--allow-multi-queue") => allow_multi_queue = true,
            Some("--config") => {
                let value = words
                    .next()
                    .filter(|value| !is_option(value))
                    .ok_or(UsageError::MissingValue("--config"))?;
                set_once(&mut config, value.into(), "--config")?;
            }
            Some("--stats-interval") => {
                let value = words
                    .next()
                    .filter(|value| !is_option(value))
                    .ok_or(UsageError::MissingValue("--stats-interval"))?;
                set_interval(&mut interval, value)?;
            }
            Some("--startup-attempts") => {
                let value = words
                    .next()
                    .filter(|value| !is_option(value))
                    .ok_or(UsageError::MissingValue("--startup-attempts"))?;
                set_attempts(&mut attempts, value)?;
            }
            _ if is_option(word) => return Err(UsageError::UnknownOption(lossy(word))),
            _ => return Err(UsageError::UnexpectedOperand(lossy(word))),
        }
    }
    let config = config.ok_or(UsageError::MissingValue("--config"))?;
    Ok(Command::Run(RunArgs {
        config,
        allow_multi_queue,
        stats_interval_secs: interval.unwrap_or(DEFAULT_STATS_INTERVAL_SECS),
        startup_attempts: attempts.unwrap_or(DEFAULT_STARTUP_ATTEMPTS),
    }))
}

/// A decimal attempt count, `1..=MAX_STARTUP_ATTEMPTS`, ASCII digits only.
fn set_attempts(slot: &mut Option<u32>, value: &OsStr) -> Result<(), UsageError> {
    const OPTION: &str = "--startup-attempts";
    let attempts = value
        .to_str()
        .filter(|text| {
            !text.is_empty() && text.len() <= 2 && text.bytes().all(|b| b.is_ascii_digit())
        })
        .and_then(|text| text.parse::<u32>().ok())
        .filter(|attempts| (1..=MAX_STARTUP_ATTEMPTS).contains(attempts))
        .ok_or(UsageError::InvalidValue(OPTION))?;
    if slot.replace(attempts).is_some() {
        return Err(UsageError::DuplicateOption(OPTION));
    }
    Ok(())
}

/// A decimal number of seconds, `0..=MAX_STATS_INTERVAL_SECS`, ASCII digits
/// only (no sign, no whitespace).
fn set_interval(slot: &mut Option<u64>, value: &OsStr) -> Result<(), UsageError> {
    const OPTION: &str = "--stats-interval";
    let seconds = value
        .to_str()
        .filter(|text| {
            !text.is_empty() && text.len() <= 6 && text.bytes().all(|b| b.is_ascii_digit())
        })
        .and_then(|text| text.parse::<u64>().ok())
        .filter(|seconds| *seconds <= MAX_STATS_INTERVAL_SECS)
        .ok_or(UsageError::InvalidValue(OPTION))?;
    if slot.replace(seconds).is_some() {
        return Err(UsageError::DuplicateOption(OPTION));
    }
    Ok(())
}

fn set_once(
    slot: &mut Option<PathBuf>,
    value: PathBuf,
    option: &'static str,
) -> Result<(), UsageError> {
    if slot.replace(value).is_some() {
        return Err(UsageError::DuplicateOption(option));
    }
    Ok(())
}

struct Words {
    help: bool,
    operands: Vec<OsString>,
}

/// Splits operands from options; `validate` and `plan` accept only `--help`.
fn split(rest: &[OsString]) -> Result<Words, UsageError> {
    let mut words = Words {
        help: false,
        operands: Vec::new(),
    };
    let mut options_done = false;
    for word in rest {
        if options_done || !is_option(word) {
            words.operands.push(word.clone());
            continue;
        }
        match word.to_str() {
            Some("--") => options_done = true,
            Some("-h" | "--help") => words.help = true,
            _ => return Err(UsageError::UnknownOption(lossy(word))),
        }
    }
    Ok(words)
}

fn operands<const N: usize>(
    words: Vec<OsString>,
    names: [&'static str; N],
) -> Result<[PathBuf; N], UsageError> {
    if let Some(extra) = words.get(N) {
        return Err(UsageError::UnexpectedOperand(lossy(extra)));
    }
    let mut words = words.into_iter();
    let mut paths = names.map(|_| PathBuf::new());
    for (path, name) in paths.iter_mut().zip(names) {
        *path = words.next().ok_or(UsageError::MissingOperand(name))?.into();
    }
    Ok(paths)
}

fn is_option(word: &OsStr) -> bool {
    word.as_encoded_bytes().first() == Some(&b'-') && word.len() > 1
}

fn lossy(word: &OsStr) -> String {
    word.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(words: &[&str]) -> Result<Command, UsageError> {
        parse(words.iter().map(OsString::from))
    }

    #[test]
    fn commands_parse_with_operands_and_options() {
        assert_eq!(run(&["--help"]), Ok(Command::Help));
        assert_eq!(run(&["-h"]), Ok(Command::Help));
        assert_eq!(run(&["--version"]), Ok(Command::Version));
        assert_eq!(run(&["-V"]), Ok(Command::Version));
        assert_eq!(
            run(&["validate", "a.toml"]),
            Ok(Command::Validate {
                config: "a.toml".into()
            })
        );
        assert_eq!(run(&["validate", "--help"]), Ok(Command::Help));
        assert_eq!(
            run(&["validate", "--", "-odd.toml"]),
            Ok(Command::Validate {
                config: "-odd.toml".into()
            })
        );
        assert_eq!(
            run(&["plan", "a.toml", "b.toml"]),
            Ok(Command::Plan {
                current: "a.toml".into(),
                next: "b.toml".into()
            })
        );
        assert_eq!(
            run(&["run-sim", "--scenario", "s.toml"]),
            Ok(Command::RunSim {
                scenario: "s.toml".into(),
                hold: false
            })
        );
        assert_eq!(
            run(&["run-sim", "--hold", "--scenario=s.toml"]),
            Ok(Command::RunSim {
                scenario: "s.toml".into(),
                hold: true
            })
        );
        assert_eq!(run(&["run-sim", "--help"]), Ok(Command::Help));
    }

    #[test]
    fn usage_errors_are_typed() {
        assert_eq!(run(&[]), Err(UsageError::MissingCommand));
        assert_eq!(
            run(&["frobnicate"]),
            Err(UsageError::UnknownCommand("frobnicate".into()))
        );
        assert_eq!(
            run(&["--verbose"]),
            Err(UsageError::UnknownOption("--verbose".into()))
        );
        assert_eq!(
            run(&["validate"]),
            Err(UsageError::MissingOperand("config.toml"))
        );
        assert_eq!(
            run(&["validate", "a", "b"]),
            Err(UsageError::UnexpectedOperand("b".into()))
        );
        assert_eq!(
            run(&["validate", "-x", "a"]),
            Err(UsageError::UnknownOption("-x".into()))
        );
        assert_eq!(
            run(&["plan", "a"]),
            Err(UsageError::MissingOperand("next.toml"))
        );
        assert_eq!(
            run(&["run-sim"]),
            Err(UsageError::MissingValue("--scenario"))
        );
        assert_eq!(
            run(&["run-sim", "--scenario"]),
            Err(UsageError::MissingValue("--scenario"))
        );
        assert_eq!(
            run(&["run-sim", "--scenario="]),
            Err(UsageError::MissingValue("--scenario"))
        );
        assert_eq!(
            run(&["run-sim", "--scenario", "a", "--scenario", "b"]),
            Err(UsageError::DuplicateOption("--scenario"))
        );
        assert_eq!(
            run(&["run-sim", "--scenario", "a", "--hold", "--hold"]),
            Err(UsageError::DuplicateOption("--hold"))
        );
        assert_eq!(
            run(&["run-sim", "--scenario", "a", "extra"]),
            Err(UsageError::UnexpectedOperand("extra".into()))
        );
        assert_eq!(
            run(&["run-sim", "--scenario", "a", "--fast"]),
            Err(UsageError::UnknownOption("--fast".into()))
        );
    }

    #[test]
    fn run_sim_accepts_double_dash_and_rejects_flag_like_values() {
        assert_eq!(
            run(&["run-sim", "--hold", "--", "-s.toml"]),
            Ok(Command::RunSim {
                scenario: "-s.toml".into(),
                hold: true
            })
        );
        assert_eq!(
            run(&["run-sim", "--scenario=-s.toml"]),
            Ok(Command::RunSim {
                scenario: "-s.toml".into(),
                hold: false
            })
        );
        assert_eq!(
            run(&["run-sim", "--"]),
            Err(UsageError::MissingValue("--scenario"))
        );
        assert_eq!(
            run(&["run-sim", "--", "a", "b"]),
            Err(UsageError::UnexpectedOperand("b".into()))
        );
        assert_eq!(
            run(&["run-sim", "--scenario", "a", "--", "b"]),
            Err(UsageError::DuplicateOption("--scenario"))
        );
        for value in ["--hold", "--help", "-x"] {
            assert_eq!(
                run(&["run-sim", "--scenario", value]),
                Err(UsageError::MissingValue("--scenario")),
                "{value}"
            );
        }
    }

    fn run_args(config: &str, allow_multi_queue: bool, stats_interval_secs: u64) -> Command {
        Command::Run(RunArgs {
            config: config.into(),
            allow_multi_queue,
            stats_interval_secs,
            startup_attempts: DEFAULT_STARTUP_ATTEMPTS,
        })
    }

    #[test]
    fn run_parses_startup_attempts() {
        let with = |attempts| {
            Ok(Command::Run(RunArgs {
                config: "r.toml".into(),
                allow_multi_queue: false,
                stats_interval_secs: DEFAULT_STATS_INTERVAL_SECS,
                startup_attempts: attempts,
            }))
        };
        assert_eq!(
            run(&["run", "--startup-attempts", "1", "--config", "r.toml"]),
            with(1)
        );
        assert_eq!(
            run(&["run", "--startup-attempts=10", "--config", "r.toml"]),
            with(MAX_STARTUP_ATTEMPTS)
        );
        for bad in ["", "0", "11", "-1", "+3", " 3", "3.0", "x", "100"] {
            let word = format!("--startup-attempts={bad}");
            assert_eq!(
                run(&["run", "--config", "a", &word]),
                Err(UsageError::InvalidValue("--startup-attempts")),
                "{bad:?}"
            );
        }
        assert_eq!(
            run(&["run", "--config", "a", "--startup-attempts"]),
            Err(UsageError::MissingValue("--startup-attempts"))
        );
        assert_eq!(
            run(&[
                "run",
                "--config",
                "a",
                "--startup-attempts=2",
                "--startup-attempts",
                "3"
            ]),
            Err(UsageError::DuplicateOption("--startup-attempts"))
        );
        assert_eq!(
            UsageError::InvalidValue("--startup-attempts").to_string(),
            "option --startup-attempts needs a whole number from 1 to 10"
        );
    }

    #[test]
    fn run_parses_config_and_options() {
        assert_eq!(
            run(&["run", "--config", "r.toml"]),
            Ok(run_args("r.toml", false, DEFAULT_STATS_INTERVAL_SECS))
        );
        assert_eq!(
            run(&["run", "--config=r.toml", "--allow-multi-queue"]),
            Ok(run_args("r.toml", true, DEFAULT_STATS_INTERVAL_SECS))
        );
        assert_eq!(
            run(&["run", "--stats-interval", "0", "--config", "r.toml"]),
            Ok(run_args("r.toml", false, 0))
        );
        assert_eq!(
            run(&["run", "--stats-interval=86400", "--", "-r.toml"]),
            Ok(run_args("-r.toml", false, 86_400))
        );
        assert_eq!(run(&["run", "--help"]), Ok(Command::Help));
    }

    #[test]
    fn run_usage_errors_are_typed() {
        assert_eq!(run(&["run"]), Err(UsageError::MissingValue("--config")));
        assert_eq!(
            run(&["run", "--config"]),
            Err(UsageError::MissingValue("--config"))
        );
        assert_eq!(
            run(&["run", "--config="]),
            Err(UsageError::MissingValue("--config"))
        );
        assert_eq!(
            run(&["run", "--config", "--allow-multi-queue"]),
            Err(UsageError::MissingValue("--config"))
        );
        assert_eq!(
            run(&["run", "--config", "a", "--config=b"]),
            Err(UsageError::DuplicateOption("--config"))
        );
        assert_eq!(
            run(&["run", "--config", "a", "--", "b"]),
            Err(UsageError::DuplicateOption("--config"))
        );
        assert_eq!(
            run(&["run", "--", "a", "b"]),
            Err(UsageError::UnexpectedOperand("b".into()))
        );
        assert_eq!(
            run(&[
                "run",
                "--config",
                "a",
                "--allow-multi-queue",
                "--allow-multi-queue"
            ]),
            Err(UsageError::DuplicateOption("--allow-multi-queue"))
        );
        assert_eq!(
            run(&["run", "--config", "a", "extra"]),
            Err(UsageError::UnexpectedOperand("extra".into()))
        );
        assert_eq!(
            run(&["run", "--config", "a", "--hold"]),
            Err(UsageError::UnknownOption("--hold".into()))
        );
        assert_eq!(
            run(&["run", "--config", "a", "--stats-interval"]),
            Err(UsageError::MissingValue("--stats-interval"))
        );
        for bad in ["", "-1", "+5", " 5", "1.5", "86401", "9999999", "x"] {
            let word = format!("--stats-interval={bad}");
            assert_eq!(
                run(&["run", "--config", "a", &word]),
                Err(UsageError::InvalidValue("--stats-interval")),
                "{bad:?}"
            );
        }
        assert_eq!(
            run(&[
                "run",
                "--config",
                "a",
                "--stats-interval=1",
                "--stats-interval",
                "2"
            ]),
            Err(UsageError::DuplicateOption("--stats-interval"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_scenario_values_are_kept_as_paths() {
        use std::os::unix::ffi::OsStringExt;
        let mut word = b"--scenario=".to_vec();
        word.extend_from_slice(&[b's', 0xfe, b'.', b't']);
        let parsed = parse([OsString::from("run-sim"), OsString::from_vec(word)]);
        assert_eq!(
            parsed,
            Ok(Command::RunSim {
                scenario: PathBuf::from(OsString::from_vec(vec![b's', 0xfe, b'.', b't'])),
                hold: false
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_operands_are_kept_as_paths() {
        use std::os::unix::ffi::OsStringExt;
        let name = OsString::from_vec(vec![b'c', 0xff, b'.', b't']);
        let parsed = parse([OsString::from("validate"), name.clone()]);
        assert_eq!(
            parsed,
            Ok(Command::Validate {
                config: PathBuf::from(name)
            })
        );
    }
}
