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

fn main() -> ExitCode {
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let status = match args::parse(std::env::args_os().skip(1)) {
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
    let _ = stdout.flush();
    ExitCode::from(status)
}
