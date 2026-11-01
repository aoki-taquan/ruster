#![deny(unsafe_code)]
//! `ruster`: M1 command-line entry point.
//!
//! - `ruster validate <config.toml>`: parse, validate, and check the M1
//!   service bridge. Summary on stdout, value-free diagnostics on stderr.
//! - `ruster plan <current.toml> <next.toml>`: deterministic text apply plan
//!   on stdout, including restart-required reasons and the expected flush.
//! - `ruster run-sim --scenario <scenario.toml> [--hold]`: canonical
//!   `ruster-run-sim/v1` JSONL on stdout, human summary on stderr.
//! - `ruster run --config <config.toml>`: the AF_XDP static router (x86_64
//!   Linux); stats blocks on stdout, progress and diagnostics on stderr.
//!
//! Exit status: 0 success (also a restart-required plan, and an ordered
//! shutdown after SIGINT/SIGTERM), 1 runtime, I/O, invariant, or scenario
//! expectation failure, 2 usage error or invalid configuration/scenario;
//! `run` adds 3 (shutdown deadline with TX frames still in the kernel) and
//! 4 (missing privilege or memlock).
//!
//! The only `unsafe` code is FFI in two private modules: the signal
//! handlers (`signal`) and the rtnetlink address dump of `ruster run`'s
//! startup check (`run::netlink`).

mod args;
mod config_cmd;
mod plan_text;
mod run;
mod run_sim;
mod signal;

use std::io::{self, Write};
use std::process::ExitCode;

use args::Command;

/// Runtime, I/O, invariant, or expectation failure.
pub const EXIT_RUNTIME: u8 = 1;
/// Usage error or invalid configuration/scenario.
pub const EXIT_INVALID: u8 = 2;

/// Whether `main` flushes stdout after the command. `run` never touches
/// the global stdout from this thread: its output thread may still hold
/// the stdout lock, blocked on a pipe nobody drains, after the bounded
/// exit wait, and a flush here would then block forever (#301 LN1).
fn flushes_stdout(command: &Result<Command, args::UsageError>) -> bool {
    !matches!(command, Ok(Command::Run(_)))
}

fn main() -> ExitCode {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let command = args::parse(std::env::args_os().skip(1));
    let flush = flushes_stdout(&command);
    let status = match command {
        Err(error) => {
            let _ = write!(stderr, "ruster: {error}\n{}", args::USAGE);
            EXIT_INVALID
        }
        Ok(Command::Help) => {
            let _ = stdout.write_all(args::USAGE.as_bytes());
            0
        }
        Ok(Command::Version) => {
            let _ = writeln!(stdout, "ruster {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Ok(Command::Validate { config }) => {
            config_cmd::run_validate(&config, &mut stdout.lock(), &mut stderr)
        }
        Ok(Command::Plan { current, next }) => {
            config_cmd::run_plan(&current, &next, &mut stdout.lock(), &mut stderr)
        }
        Ok(Command::RunSim { scenario, hold }) => run_sim::run(&scenario, hold, &mut stderr),
        Ok(Command::Run(run)) => run::run(&run, &mut stderr),
    };
    if flush {
        let _ = stdout.flush();
    }
    ExitCode::from(status)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{args, flushes_stdout};

    fn parsed(words: &[&str]) -> Result<args::Command, args::UsageError> {
        args::parse(words.iter().map(OsString::from))
    }

    #[test]
    fn only_run_skips_the_final_stdout_flush() {
        assert!(!flushes_stdout(&parsed(&["run", "--config", "r.toml"])));
        for words in [
            &["run-sim", "--scenario", "s.toml"][..],
            &["validate", "a.toml"][..],
            &["plan", "a.toml", "b.toml"][..],
            &["--help"][..],
            &["frobnicate"][..],
        ] {
            assert!(flushes_stdout(&parsed(words)), "{words:?}");
        }
    }
}
