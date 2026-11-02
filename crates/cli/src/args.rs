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
  ruster run [--allow-multi-queue] [--allow-kernel-forwarding]
             [--allow-kernel-ipv6] [--allow-ipv4-weak-host]
             [--strict-config-perms] [--stats-interval <seconds>]
             [--startup-attempts <n>] [--tx-stall-warn-secs <s>]
             [--tx-stall-fatal-secs <s>] [--kick-errors-fatal-secs <s>]
             [--link-stale-secs <s>] [--idle-wait-ms <ms>]
             [--keep-privileges | --user <uid> --group <gid>]
             [--seccomp kill|log|off]
             --config <config.toml>
  ruster run [options] -- <config.toml>
  ruster --help | --version

`run`: SIGINT/SIGTERM stop (a second one forces), SIGHUP reloads the config.
A fatal threshold of 0 disables that fatal exit (warn only).
After startup `run` drops every capability (and with --user/--group switches
to that numeric uid/gid); --keep-privileges keeps them for the whole run.
It then confines every thread to a syscall allowlist (seccomp): a syscall
outside it kills the process (--seccomp kill, the default), is logged and
allowed (--seccomp log), or the filter is not installed (--seccomp off).
When idle, `run` blocks in poll() on the port sockets for at most
--idle-wait-ms (default 10, 1 to 100; at most 1 while timers or TX are
pending); an arriving frame ends the wait at once.

exit status: 0 success or signal shutdown, 1 runtime/I/O/expectation failure
(including unreadable files, and `run` stopped by a fatal health or device
event), 2 usage error or invalid config/scenario;
`run` also: 3 shutdown deadline passed with TX frames still in the kernel,
4 missing privilege or too small RLIMIT_MEMLOCK, or a privilege drop that
cannot work (nothing was acquired)
";

/// Default `ruster run --stats-interval` in seconds.
pub const DEFAULT_STATS_INTERVAL_SECS: u64 = 60;
/// Largest accepted `--stats-interval` (one day).
pub const MAX_STATS_INTERVAL_SECS: u64 = 86_400;
/// Default `ruster run --startup-attempts` (XDP-045).
pub const DEFAULT_STARTUP_ATTEMPTS: u32 = 3;
/// Largest accepted `--startup-attempts`.
pub const MAX_STARTUP_ATTEMPTS: u32 = 10;
/// Default `--tx-stall-warn-secs`.
pub const DEFAULT_TX_STALL_WARN_SECS: u64 = 1;
/// Default `--tx-stall-fatal-secs` (0 disables the fatal exit).
pub const DEFAULT_TX_STALL_FATAL_SECS: u64 = 10;
/// Default `--kick-errors-fatal-secs` (0 disables the fatal exit).
pub const DEFAULT_KICK_ERRORS_FATAL_SECS: u64 = 5;
/// Default `--link-stale-secs`: a link round outstanding this long makes
/// every further due round a failed link query (H7).
pub const DEFAULT_LINK_STALE_SECS: u64 = 5;
/// Largest accepted health threshold (one hour).
pub const MAX_HEALTH_SECS: u64 = 3_600;
/// Default `ruster run --idle-wait-ms` (H9): the longest idle `poll`.
pub const DEFAULT_IDLE_WAIT_MS: u64 = 10;
/// Largest accepted `--idle-wait-ms`.
pub const MAX_IDLE_WAIT_MS: u64 = 100;

/// Largest `--user`/`--group` id (`u32::MAX` means "unchanged" to the
/// kernel's set-id calls).
pub const MAX_ID: u32 = u32::MAX - 1;

/// What `ruster run` does about syscalls outside its allowlist after
/// startup (`--seccomp`, H8).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SeccompMode {
    /// `kill` (the default): the kernel kills the whole process
    /// (`SECCOMP_RET_KILL_PROCESS`).
    #[default]
    Kill,
    /// `log`: the kernel logs the syscall and lets it run
    /// (`SECCOMP_RET_LOG`); for diagnosing a kill.
    Log,
    /// `off`: no filter is installed.
    Off,
}

impl SeccompMode {
    /// The option value (and the stats label).
    pub const fn label(self) -> &'static str {
        match self {
            Self::Kill => "kill",
            Self::Log => "log",
            Self::Off => "off",
        }
    }

    fn parse(value: &OsStr) -> Option<Self> {
        match value.to_str()? {
            "kill" => Some(Self::Kill),
            "log" => Some(Self::Log),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

/// A numeric `run` option: name and accepted range.
struct Numeric {
    name: &'static str,
    min: u64,
    max: u64,
}

const NUMERIC: [Numeric; 7] = [
    Numeric {
        name: "--stats-interval",
        min: 0,
        max: MAX_STATS_INTERVAL_SECS,
    },
    Numeric {
        name: "--startup-attempts",
        min: 1,
        max: MAX_STARTUP_ATTEMPTS as u64,
    },
    Numeric {
        name: "--tx-stall-warn-secs",
        min: 1,
        max: MAX_HEALTH_SECS,
    },
    Numeric {
        name: "--tx-stall-fatal-secs",
        min: 0,
        max: MAX_HEALTH_SECS,
    },
    Numeric {
        name: "--kick-errors-fatal-secs",
        min: 0,
        max: MAX_HEALTH_SECS,
    },
    Numeric {
        name: "--link-stale-secs",
        min: 1,
        max: MAX_HEALTH_SECS,
    },
    Numeric {
        name: "--idle-wait-ms",
        min: 1,
        max: MAX_IDLE_WAIT_MS,
    },
];

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
    /// Start although kernel IPv4 forwarding is on (or unreadable) in the
    /// namespace or on a port: warned instead of refused (XDP-063).
    pub allow_kernel_forwarding: bool,
    /// Start although the kernel IPv6 stack is exposed on a port with IPv6
    /// enabled (addresses outside `fe80::/10`, routes out of the port,
    /// IPv6 forwarding, or an unreadable IPv6 fact): warned instead of
    /// refused (XDP-063).
    pub allow_kernel_ipv6: bool,
    /// Start although a port's effective IPv4 `rp_filter` is 0 (or
    /// unreadable), which exposes every local IPv4 address of the host
    /// through the address-less port while the router is detached (weak
    /// host model): warned (`IPV4_WEAK_HOST_EXPOSURE`) instead of refused
    /// (`KERNEL_IPV4_WEAK_HOST`, CLI-079).
    pub allow_ipv4_weak_host: bool,
    /// Refuse a config file that group or other may write or that is
    /// owned by neither root nor the effective user (startup and reload).
    pub strict_config_perms: bool,
    /// Health thresholds of the watch, in seconds (0 fatal: warn only).
    pub tx_stall_warn_secs: u64,
    pub tx_stall_fatal_secs: u64,
    pub kick_errors_fatal_secs: u64,
    /// Age in seconds of an outstanding link watcher round from which
    /// every due round counts as a failed link query (1 to 3600; no 0:
    /// losing observability always ends the run eventually).
    pub link_stale_secs: u64,
    /// Keep every capability after startup instead of dropping them all
    /// (the default drop is security relevant; this is the opt-out).
    pub keep_privileges: bool,
    /// Numeric uid and gid to switch to with the drop (`--user` and
    /// `--group`, only together, never with `--keep-privileges`).
    pub user: Option<u32>,
    pub group: Option<u32>,
    /// The syscall filter after startup (`--seccomp`, default kill).
    pub seccomp: SeccompMode,
    /// The longest idle wait in milliseconds (`--idle-wait-ms`, 1 to
    /// [`MAX_IDLE_WAIT_MS`], H9).
    pub idle_wait_ms: u64,
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
    /// `--tx-stall-fatal-secs` is neither 0 nor at least
    /// `--tx-stall-warn-secs`.
    FatalBelowWarning,
    /// `--user` without `--group` or the other way round.
    IdentityIncomplete,
    /// `--keep-privileges` with `--user`/`--group`.
    KeepWithIdentity,
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
            Self::InvalidValue("--seccomp") => {
                formatter.write_str("option --seccomp needs kill, log, or off")
            }
            Self::InvalidValue(option @ ("--user" | "--group")) => write!(
                formatter,
                "option {option} needs a numeric id from 1 to {MAX_ID}"
            ),
            Self::InvalidValue(option) => match NUMERIC.iter().find(|n| n.name == *option) {
                Some(n) if n.name == "--idle-wait-ms" => write!(
                    formatter,
                    "option {option} needs a whole number of milliseconds from {} to {}",
                    n.min, n.max
                ),
                Some(n) if n.name == "--startup-attempts" => write!(
                    formatter,
                    "option {option} needs a whole number from {} to {}",
                    n.min, n.max
                ),
                Some(n) => write!(
                    formatter,
                    "option {option} needs a whole number of seconds from {} to {}",
                    n.min, n.max
                ),
                None => write!(formatter, "option {option} has an invalid value"),
            },
            Self::FatalBelowWarning => formatter.write_str(
                "option --tx-stall-fatal-secs must be 0 or at least --tx-stall-warn-secs",
            ),
            Self::IdentityIncomplete => {
                formatter.write_str("options --user and --group must be given together")
            }
            Self::KeepWithIdentity => formatter
                .write_str("option --keep-privileges cannot be combined with --user/--group"),
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
    let mut allow_kernel_forwarding = false;
    let mut allow_kernel_ipv6 = false;
    let mut allow_ipv4_weak_host = false;
    let mut strict_config_perms = false;
    let mut keep_privileges = false;
    let mut ids: [Option<u32>; 2] = [None; 2];
    let mut seccomp = None;
    let mut numbers: [Option<u64>; NUMERIC.len()] = [None; NUMERIC.len()];
    let mut words = rest.iter();
    'words: while let Some(word) = words.next() {
        if let Some(value) = equals_value(word, "--config=") {
            if value.is_empty() {
                return Err(UsageError::MissingValue("--config"));
            }
            set_once(&mut config, value.into(), "--config")?;
            continue;
        }
        if let Some(value) = equals_value(word, "--seccomp=") {
            set_seccomp(&mut seccomp, &value)?;
            continue;
        }
        if word.to_str() == Some("--seccomp") {
            let value = words
                .next()
                .filter(|value| !is_option(value))
                .ok_or(UsageError::MissingValue("--seccomp"))?;
            set_seccomp(&mut seccomp, value)?;
            continue;
        }
        for (index, &name) in ID_OPTIONS.iter().enumerate() {
            if let Some(value) = equals_value(word, &format!("{name}=")) {
                set_id(&mut ids[index], name, &value)?;
                continue 'words;
            }
            if word.to_str() == Some(name) {
                let value = words
                    .next()
                    .filter(|value| !is_option(value))
                    .ok_or(UsageError::MissingValue(name))?;
                set_id(&mut ids[index], name, value)?;
                continue 'words;
            }
        }
        for (index, numeric) in NUMERIC.iter().enumerate() {
            let prefix = format!("{}=", numeric.name);
            if let Some(value) = equals_value(word, &prefix) {
                set_number(&mut numbers[index], numeric, &value)?;
                continue 'words;
            }
            if word.to_str() == Some(numeric.name) {
                let value = words
                    .next()
                    .filter(|value| !is_option(value))
                    .ok_or(UsageError::MissingValue(numeric.name))?;
                set_number(&mut numbers[index], numeric, value)?;
                continue 'words;
            }
        }
        let flag = |slot: &mut bool, name: &'static str| {
            if std::mem::replace(slot, true) {
                Err(UsageError::DuplicateOption(name))
            } else {
                Ok(())
            }
        };
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
            Some("--allow-multi-queue") => flag(&mut allow_multi_queue, "--allow-multi-queue")?,
            Some("--allow-kernel-forwarding") => {
                flag(&mut allow_kernel_forwarding, "--allow-kernel-forwarding")?;
            }
            Some("--allow-kernel-ipv6") => flag(&mut allow_kernel_ipv6, "--allow-kernel-ipv6")?,
            Some("--allow-ipv4-weak-host") => {
                flag(&mut allow_ipv4_weak_host, "--allow-ipv4-weak-host")?;
            }
            Some("--strict-config-perms") => {
                flag(&mut strict_config_perms, "--strict-config-perms")?
            }
            Some("--keep-privileges") => flag(&mut keep_privileges, "--keep-privileges")?,
            Some("--config") => {
                let value = words
                    .next()
                    .filter(|value| !is_option(value))
                    .ok_or(UsageError::MissingValue("--config"))?;
                set_once(&mut config, value.into(), "--config")?;
            }
            _ if is_option(word) => return Err(UsageError::UnknownOption(lossy(word))),
            _ => return Err(UsageError::UnexpectedOperand(lossy(word))),
        }
    }
    let config = config.ok_or(UsageError::MissingValue("--config"))?;
    let [interval, attempts, warn, fatal, kicks, stale, idle_wait] = numbers;
    let tx_stall_warn_secs = warn.unwrap_or(DEFAULT_TX_STALL_WARN_SECS);
    let tx_stall_fatal_secs = fatal.unwrap_or(DEFAULT_TX_STALL_FATAL_SECS);
    if tx_stall_fatal_secs != 0 && tx_stall_fatal_secs < tx_stall_warn_secs {
        return Err(UsageError::FatalBelowWarning);
    }
    let [user, group] = ids;
    if user.is_some() != group.is_some() {
        return Err(UsageError::IdentityIncomplete);
    }
    if keep_privileges && user.is_some() {
        return Err(UsageError::KeepWithIdentity);
    }
    Ok(Command::Run(RunArgs {
        config,
        allow_multi_queue,
        stats_interval_secs: interval.unwrap_or(DEFAULT_STATS_INTERVAL_SECS),
        startup_attempts: attempts
            .and_then(|attempts| u32::try_from(attempts).ok())
            .unwrap_or(DEFAULT_STARTUP_ATTEMPTS),
        allow_kernel_forwarding,
        allow_kernel_ipv6,
        allow_ipv4_weak_host,
        strict_config_perms,
        tx_stall_warn_secs,
        tx_stall_fatal_secs,
        kick_errors_fatal_secs: kicks.unwrap_or(DEFAULT_KICK_ERRORS_FATAL_SECS),
        link_stale_secs: stale.unwrap_or(DEFAULT_LINK_STALE_SECS),
        keep_privileges,
        user,
        group,
        seccomp: seccomp.unwrap_or_default(),
        idle_wait_ms: idle_wait.unwrap_or(DEFAULT_IDLE_WAIT_MS),
    }))
}

/// `--seccomp kill|log|off`, at most once.
fn set_seccomp(slot: &mut Option<SeccompMode>, value: &OsStr) -> Result<(), UsageError> {
    let mode = SeccompMode::parse(value).ok_or(UsageError::InvalidValue("--seccomp"))?;
    if slot.replace(mode).is_some() {
        return Err(UsageError::DuplicateOption("--seccomp"));
    }
    Ok(())
}

/// The identity options of `run`, in `ids` order.
const ID_OPTIONS: [&str; 2] = ["--user", "--group"];

/// A numeric uid/gid from 1 to [`MAX_ID`], ASCII digits only (no sign, no
/// whitespace, at most 10 digits). Names are not resolved: a name lookup
/// would need the C library's NSS.
fn set_id(slot: &mut Option<u32>, name: &'static str, value: &OsStr) -> Result<(), UsageError> {
    let id = value
        .to_str()
        .filter(|text| {
            !text.is_empty() && text.len() <= 10 && text.bytes().all(|b| b.is_ascii_digit())
        })
        .and_then(|text| text.parse::<u64>().ok())
        .filter(|id| (1..=u64::from(MAX_ID)).contains(id))
        .and_then(|id| u32::try_from(id).ok())
        .ok_or(UsageError::InvalidValue(name))?;
    if slot.replace(id).is_some() {
        return Err(UsageError::DuplicateOption(name));
    }
    Ok(())
}

/// A decimal number in the option's range, ASCII digits only (no sign,
/// no whitespace, at most 6 digits).
fn set_number(slot: &mut Option<u64>, numeric: &Numeric, value: &OsStr) -> Result<(), UsageError> {
    let number = value
        .to_str()
        .filter(|text| {
            !text.is_empty() && text.len() <= 6 && text.bytes().all(|b| b.is_ascii_digit())
        })
        .and_then(|text| text.parse::<u64>().ok())
        .filter(|number| (numeric.min..=numeric.max).contains(number))
        .ok_or(UsageError::InvalidValue(numeric.name))?;
    if slot.replace(number).is_some() {
        return Err(UsageError::DuplicateOption(numeric.name));
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
            allow_kernel_forwarding: false,
            allow_kernel_ipv6: false,
            allow_ipv4_weak_host: false,
            strict_config_perms: false,
            tx_stall_warn_secs: DEFAULT_TX_STALL_WARN_SECS,
            tx_stall_fatal_secs: DEFAULT_TX_STALL_FATAL_SECS,
            kick_errors_fatal_secs: DEFAULT_KICK_ERRORS_FATAL_SECS,
            link_stale_secs: DEFAULT_LINK_STALE_SECS,
            keep_privileges: false,
            user: None,
            group: None,
            seccomp: SeccompMode::Kill,
            idle_wait_ms: DEFAULT_IDLE_WAIT_MS,
        })
    }

    #[test]
    fn run_parses_the_privilege_options() {
        let parsed = |words: &[&str]| match run(words) {
            Ok(Command::Run(args)) => (args.keep_privileges, args.user, args.group),
            other => panic!("{other:?}"),
        };
        assert_eq!(parsed(&["run", "--config", "a"]), (false, None, None));
        assert_eq!(
            parsed(&["run", "--keep-privileges", "--config", "a"]),
            (true, None, None)
        );
        assert_eq!(
            parsed(&["run", "--user", "990", "--group=991", "--config", "a"]),
            (false, Some(990), Some(991))
        );
        assert_eq!(
            parsed(&["run", "--user=4294967294", "--group", "1", "--config", "a"]),
            (false, Some(MAX_ID), Some(1))
        );
        assert_eq!(
            run(&["run", "--config", "a", "--user", "990"]),
            Err(UsageError::IdentityIncomplete)
        );
        assert_eq!(
            run(&["run", "--config", "a", "--group", "990"]),
            Err(UsageError::IdentityIncomplete)
        );
        assert_eq!(
            run(&[
                "run",
                "--config",
                "a",
                "--keep-privileges",
                "--user=1",
                "--group=1"
            ]),
            Err(UsageError::KeepWithIdentity)
        );
        assert_eq!(
            run(&[
                "run",
                "--config",
                "a",
                "--keep-privileges",
                "--keep-privileges"
            ]),
            Err(UsageError::DuplicateOption("--keep-privileges"))
        );
        assert_eq!(
            run(&["run", "--config", "a", "--user=1", "--user=2", "--group=1"]),
            Err(UsageError::DuplicateOption("--user"))
        );
        for bad in [
            "",
            "0",
            "-1",
            "+1",
            " 1",
            "1 ",
            "x",
            "root",
            "4294967295",
            "99999999999",
            "1.0",
        ] {
            for option in ["--user", "--group"] {
                assert_eq!(
                    run(&["run", "--config", "a", &format!("{option}={bad}")]),
                    Err(UsageError::InvalidValue(option)),
                    "{option}={bad}"
                );
            }
        }
        assert_eq!(
            run(&["run", "--config", "a", "--user", "--group", "1"]),
            Err(UsageError::MissingValue("--user"))
        );
        assert_eq!(
            UsageError::InvalidValue("--user").to_string(),
            "option --user needs a numeric id from 1 to 4294967294"
        );
        assert!(USAGE.contains("[--keep-privileges | --user <uid> --group <gid>]"));
    }

    #[test]
    fn run_parses_the_idle_wait_option() {
        let parsed = |words: &[&str]| match run(words) {
            Ok(Command::Run(args)) => args.idle_wait_ms,
            other => panic!("{other:?}"),
        };
        assert_eq!(parsed(&["run", "--config", "a"]), DEFAULT_IDLE_WAIT_MS);
        assert_eq!(DEFAULT_IDLE_WAIT_MS, 10);
        assert_eq!(parsed(&["run", "--idle-wait-ms", "1", "--config", "a"]), 1);
        assert_eq!(parsed(&["run", "--idle-wait-ms=100", "--config", "a"]), 100);
        for bad in ["0", "101", "-1", "1.5", "", "ten"] {
            let error = run(&["run", &format!("--idle-wait-ms={bad}"), "--config", "a"]);
            assert_eq!(
                error,
                Err(UsageError::InvalidValue("--idle-wait-ms")),
                "{bad}"
            );
        }
        assert_eq!(
            UsageError::InvalidValue("--idle-wait-ms").to_string(),
            "option --idle-wait-ms needs a whole number of milliseconds from 1 to 100"
        );
        assert_eq!(
            run(&[
                "run",
                "--idle-wait-ms",
                "5",
                "--idle-wait-ms=6",
                "--config",
                "a"
            ]),
            Err(UsageError::DuplicateOption("--idle-wait-ms"))
        );
    }

    #[test]
    fn run_parses_the_seccomp_option() {
        let parsed = |words: &[&str]| match run(words) {
            Ok(Command::Run(args)) => args.seccomp,
            other => panic!("{other:?}"),
        };
        assert_eq!(parsed(&["run", "--config", "a"]), SeccompMode::Kill);
        assert_eq!(SeccompMode::default(), SeccompMode::Kill);
        for (value, mode) in [
            ("kill", SeccompMode::Kill),
            ("log", SeccompMode::Log),
            ("off", SeccompMode::Off),
        ] {
            assert_eq!(parsed(&["run", "--seccomp", value, "--config", "a"]), mode);
            assert_eq!(
                parsed(&["run", &format!("--seccomp={value}"), "--config", "a"]),
                mode
            );
            assert_eq!(mode.label(), value);
        }
        // Every mode combines with every privilege policy.
        assert_eq!(
            parsed(&["run", "--keep-privileges", "--seccomp=log", "--config", "a"]),
            SeccompMode::Log
        );
        assert_eq!(
            parsed(&[
                "run",
                "--user=1",
                "--group=1",
                "--seccomp=off",
                "--config",
                "a"
            ]),
            SeccompMode::Off
        );
        for bad in ["", "KILL", "Kill", "errno", "trap", "0", " kill", "kill "] {
            assert_eq!(
                run(&["run", "--config", "a", &format!("--seccomp={bad}")]),
                Err(UsageError::InvalidValue("--seccomp")),
                "{bad:?}"
            );
        }
        assert_eq!(
            run(&["run", "--config", "a", "--seccomp"]),
            Err(UsageError::MissingValue("--seccomp"))
        );
        assert_eq!(
            run(&["run", "--seccomp", "--config", "a"]),
            Err(UsageError::MissingValue("--seccomp"))
        );
        assert_eq!(
            run(&["run", "--config", "a", "--seccomp=log", "--seccomp", "log"]),
            Err(UsageError::DuplicateOption("--seccomp"))
        );
        assert_eq!(
            UsageError::InvalidValue("--seccomp").to_string(),
            "option --seccomp needs kill, log, or off"
        );
        assert!(USAGE.contains("[--seccomp kill|log|off]"));
    }

    #[test]
    fn run_parses_security_and_health_options() {
        let Ok(Command::Run(args)) = run(&[
            "run",
            "--allow-kernel-forwarding",
            "--allow-kernel-ipv6",
            "--allow-ipv4-weak-host",
            "--strict-config-perms",
            "--tx-stall-warn-secs=2",
            "--tx-stall-fatal-secs",
            "0",
            "--kick-errors-fatal-secs=0",
            "--link-stale-secs",
            "9",
            "--config",
            "r.toml",
        ]) else {
            panic!("parsed");
        };
        assert!(args.allow_kernel_forwarding && args.strict_config_perms);
        assert!(args.allow_kernel_ipv6);
        assert!(args.allow_ipv4_weak_host);
        assert_eq!(
            (
                args.tx_stall_warn_secs,
                args.tx_stall_fatal_secs,
                args.kick_errors_fatal_secs
            ),
            (2, 0, 0)
        );
        assert_eq!(args.link_stale_secs, 9);
        let Ok(Command::Run(defaults)) = run(&["run", "--config", "r.toml"]) else {
            panic!("parsed");
        };
        assert!(!defaults.allow_kernel_forwarding && !defaults.strict_config_perms);
        assert!(!defaults.allow_kernel_ipv6);
        assert!(!defaults.allow_ipv4_weak_host);
        assert_eq!(
            (
                defaults.tx_stall_warn_secs,
                defaults.tx_stall_fatal_secs,
                defaults.kick_errors_fatal_secs
            ),
            (1, 10, 5)
        );
        assert_eq!(defaults.link_stale_secs, 5);
        for flag in [
            "--allow-kernel-forwarding",
            "--allow-kernel-ipv6",
            "--allow-ipv4-weak-host",
            "--strict-config-perms",
        ] {
            assert_eq!(
                run(&["run", "--config", "a", flag, flag]),
                Err(UsageError::DuplicateOption(flag))
            );
        }
        for (word, option) in [
            ("--tx-stall-warn-secs=0", "--tx-stall-warn-secs"),
            ("--tx-stall-warn-secs=3601", "--tx-stall-warn-secs"),
            ("--tx-stall-fatal-secs=3601", "--tx-stall-fatal-secs"),
            ("--kick-errors-fatal-secs=-1", "--kick-errors-fatal-secs"),
            ("--link-stale-secs=0", "--link-stale-secs"),
            ("--link-stale-secs=3601", "--link-stale-secs"),
        ] {
            assert_eq!(
                run(&["run", "--config", "a", word]),
                Err(UsageError::InvalidValue(option)),
                "{word}"
            );
        }
        assert_eq!(
            run(&[
                "run",
                "--config",
                "a",
                "--tx-stall-warn-secs=20",
                "--tx-stall-fatal-secs=10"
            ]),
            Err(UsageError::FatalBelowWarning)
        );
        assert!(run(&[
            "run",
            "--config",
            "a",
            "--tx-stall-warn-secs=20",
            "--tx-stall-fatal-secs=20"
        ])
        .is_ok());
        assert_eq!(
            UsageError::InvalidValue("--tx-stall-fatal-secs").to_string(),
            "option --tx-stall-fatal-secs needs a whole number of seconds from 0 to 3600"
        );
    }

    #[test]
    fn run_parses_startup_attempts() {
        let with = |attempts| {
            Ok(Command::Run(RunArgs {
                config: "r.toml".into(),
                allow_multi_queue: false,
                stats_interval_secs: DEFAULT_STATS_INTERVAL_SECS,
                startup_attempts: attempts,
                allow_kernel_forwarding: false,
                allow_kernel_ipv6: false,
                allow_ipv4_weak_host: false,
                strict_config_perms: false,
                tx_stall_warn_secs: DEFAULT_TX_STALL_WARN_SECS,
                tx_stall_fatal_secs: DEFAULT_TX_STALL_FATAL_SECS,
                kick_errors_fatal_secs: DEFAULT_KICK_ERRORS_FATAL_SECS,
                link_stale_secs: DEFAULT_LINK_STALE_SECS,
                keep_privileges: false,
                user: None,
                group: None,
                seccomp: SeccompMode::Kill,
                idle_wait_ms: DEFAULT_IDLE_WAIT_MS,
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
