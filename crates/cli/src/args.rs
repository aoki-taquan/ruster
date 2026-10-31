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
  ruster run-sim --scenario <scenario.toml> [--hold]
  ruster --help | --version

exit status: 0 success or signal shutdown, 1 runtime/I/O/expectation failure,
2 usage error or invalid config/scenario
";

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Help,
    Version,
    Validate { config: PathBuf },
    Plan { current: PathBuf, next: PathBuf },
    RunSim { scenario: PathBuf, hold: bool },
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
        _ if is_option(&first) => Err(UsageError::UnknownOption(lossy(&first))),
        _ => Err(UsageError::UnknownCommand(lossy(&first))),
    }
}

fn parse_run_sim(rest: &[OsString]) -> Result<Command, UsageError> {
    let mut scenario = None;
    let mut hold = false;
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        let text = word.to_str();
        match text {
            Some("-h" | "--help") => return Ok(Command::Help),
            Some("--hold") if hold => return Err(UsageError::DuplicateOption("--hold")),
            Some("--hold") => hold = true,
            Some("--scenario") => {
                let value = words.next().ok_or(UsageError::MissingValue("--scenario"))?;
                set_once(&mut scenario, PathBuf::from(value))?;
            }
            Some(text) if text.starts_with("--scenario=") => {
                let value = &text["--scenario=".len()..];
                if value.is_empty() {
                    return Err(UsageError::MissingValue("--scenario"));
                }
                set_once(&mut scenario, PathBuf::from(value))?;
            }
            _ if is_option(word) => return Err(UsageError::UnknownOption(lossy(word))),
            _ => return Err(UsageError::UnexpectedOperand(lossy(word))),
        }
    }
    let scenario = scenario.ok_or(UsageError::MissingValue("--scenario"))?;
    Ok(Command::RunSim { scenario, hold })
}

fn set_once(slot: &mut Option<PathBuf>, value: PathBuf) -> Result<(), UsageError> {
    if slot.replace(value).is_some() {
        return Err(UsageError::DuplicateOption("--scenario"));
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
