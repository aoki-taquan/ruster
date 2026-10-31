//! `ruster run-sim --scenario <path> [--hold]`.
//!
//! stdout carries exactly the canonical `ruster-run-sim/v1` JSON lines of the
//! driver; stderr carries the human summary and diagnostics. Without
//! `--hold` (and without a signal) stdout is byte-identical to
//! [`ruster_sim_scenario::run_scenario_file`] for the same scenario.
//!
//! The scenario is executed one [`SimRun::step`] at a time and the stop flag
//! is read before every step, so SIGINT/SIGTERM take effect at a tick
//! boundary. A scenario's `hold` step without `--hold` simply ends the run.
//!
//! With `--hold`, after the last step the run keeps calling
//! [`SimRun::idle_tick`] with injected time advancing by [`IDLE_STEP_MS`]
//! per tick. Injected time never reads a clock; a real
//! [`IDLE_PACING`] sleep between idle ticks only keeps the process from
//! spinning, so the number of idle ticks before a signal is not
//! deterministic but every tick's content is. The readiness line
//! [`HOLD_READY`] is written to stderr after stdout is flushed, and stdout
//! is flushed again after every idle tick.
//!
//! Ordered shutdown: stop stepping (no more injection), require backend
//! publication quiescence (no unfinished batch, live lease, or uncompleted
//! TX; injected-but-unreceived frames are reported as `pending_rx`), write the
//! `final` event with counters and the active generation, flush, exit 0.

use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use ruster_io_sim::SimPublicationQuiescenceError;
use ruster_sim_scenario::{DriverError, Progress, SimRun, SimSession};

use crate::{signal, EXIT_INVALID, EXIT_RUNTIME};

/// Injected time added per idle tick in hold mode.
pub const IDLE_STEP_MS: u64 = 100;
/// Real sleep between idle ticks in hold mode (pacing only).
pub const IDLE_PACING: Duration = Duration::from_millis(100);
/// Readiness marker written to stderr when hold mode starts.
pub const HOLD_READY: &str = "ruster run-sim: holding";

/// Exit status of a driver failure: invalid scenario or initial config, or
/// a scenario naming an unknown interface, is 2; everything else (I/O,
/// expectation or apply mismatch, invariant, output) is 1.
pub fn exit_status(error: &DriverError) -> u8 {
    match error {
        DriverError::Scenario(_)
        | DriverError::InitialConfig(_)
        | DriverError::UnknownInterface { .. } => EXIT_INVALID,
        _ => EXIT_RUNTIME,
    }
}

fn label(error: &DriverError) -> &'static str {
    match error {
        DriverError::Scenario(_) => "invalid scenario",
        DriverError::InitialConfig(_) => "invalid initial config",
        DriverError::UnknownInterface { .. } => "invalid scenario",
        DriverError::Expect { .. } => "expectation failed",
        DriverError::ApplyMismatch { .. } => "expectation failed",
        DriverError::Read { .. } => "read failed",
        DriverError::Output(_) => "output failed",
        _ => "runtime failure",
    }
}

const fn quiescence_label(error: SimPublicationQuiescenceError) -> &'static str {
    match error {
        SimPublicationQuiescenceError::RxBatchNotFinished => "RX batch not finished",
        SimPublicationQuiescenceError::GeneratedBatchNotFinished => "generated batch not finished",
        SimPublicationQuiescenceError::RxLeaseNotCompleted => "RX lease still live",
        SimPublicationQuiescenceError::GeneratedLeaseNotCompleted => "generated lease still live",
        SimPublicationQuiescenceError::TxCompletionPending => "TX completion pending",
    }
}

enum Failure {
    Driver(DriverError),
    NotQuiescent(SimPublicationQuiescenceError),
    TimeOverflow,
}

impl From<DriverError> for Failure {
    fn from(error: DriverError) -> Self {
        Self::Driver(error)
    }
}

/// Runs the command and returns the exit status.
pub fn run(scenario: &Path, hold: bool, err: &mut impl Write) -> u8 {
    if let Err(name) = signal::install() {
        let _ = writeln!(err, "ruster run-sim: cannot install {name} handler");
        return EXIT_RUNTIME;
    }
    let mut out = BufWriter::new(io::stdout().lock());
    let result = execute(scenario, hold, &mut out, err);
    let flushed = out.flush();
    let status = match result {
        Ok(()) => 0,
        Err(Failure::Driver(error)) => {
            let _ = writeln!(err, "ruster run-sim: {}: {error}", label(&error));
            exit_status(&error)
        }
        Err(Failure::NotQuiescent(error)) => {
            let _ = writeln!(
                err,
                "ruster run-sim: shutdown invariant violated: {}",
                quiescence_label(error)
            );
            EXIT_RUNTIME
        }
        Err(Failure::TimeOverflow) => {
            let _ = writeln!(err, "ruster run-sim: injected time overflow in hold mode");
            EXIT_RUNTIME
        }
    };
    if status == 0 && flushed.is_err() {
        let _ = writeln!(err, "ruster run-sim: output failed");
        return EXIT_RUNTIME;
    }
    status
}

fn execute<W: Write>(
    scenario: &Path,
    hold: bool,
    out: &mut W,
    err: &mut impl Write,
) -> Result<(), Failure> {
    let mut session = SimSession::load(scenario)?;
    let mut run = session.start(out)?;
    let mut stopped = false;
    loop {
        if signal::stop_requested() {
            stopped = true;
            break;
        }
        match run.step(out)? {
            Progress::Running => {}
            Progress::Hold | Progress::Finished => break,
        }
    }
    if hold && !stopped {
        out.flush().map_err(|e| DriverError::Output(e.kind()))?;
        let _ = writeln!(
            err,
            "{HOLD_READY} at generation {} ({} ms); send SIGINT or SIGTERM to stop",
            run.generation(),
            run.now_ms()
        );
        let _ = err.flush();
        stopped = idle(&mut run, out)?;
    }
    shutdown(&mut run, stopped, out, err)
}

/// Idle-ticks until a signal arrives. Returns `true` (stopped by signal).
fn idle<W: Write>(run: &mut SimRun<'_>, out: &mut W) -> Result<bool, Failure> {
    loop {
        if signal::stop_requested() {
            return Ok(true);
        }
        thread::sleep(IDLE_PACING);
        if signal::stop_requested() {
            return Ok(true);
        }
        let at = run
            .now_ms()
            .checked_add(IDLE_STEP_MS)
            .ok_or(Failure::TimeOverflow)?;
        run.idle_tick(at, out)?;
        // Live output for operators; the scenario part was flushed before
        // the readiness line.
        out.flush().map_err(|e| DriverError::Output(e.kind()))?;
    }
}

fn shutdown<W: Write>(
    run: &mut SimRun<'_>,
    stopped: bool,
    out: &mut W,
    err: &mut impl Write,
) -> Result<(), Failure> {
    run.check_quiescence().map_err(Failure::NotQuiescent)?;
    let summary = run.finish(out)?;
    let totals = summary.snapshot.totals;
    let _ = writeln!(
        err,
        "ruster run-sim: {} at {} ms; generation {}, ticks {}, publications applied {} \
         rejected {}, health {}",
        if stopped {
            "stopped by signal"
        } else {
            "finished"
        },
        run.now_ms(),
        summary.generation,
        totals.ticks,
        totals.publications_applied,
        totals.publications_rejected,
        summary.snapshot.state.label(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use ruster_sim_scenario::FileRole;

    use super::*;

    #[test]
    fn driver_failures_map_to_documented_exit_statuses() {
        let read = DriverError::Read {
            file: FileRole::Scenario,
            step: None,
            kind: ErrorKind::NotFound,
        };
        assert_eq!(exit_status(&read), EXIT_RUNTIME);
        assert_eq!(exit_status(&DriverError::Output(ErrorKind::BrokenPipe)), 1);
        assert_eq!(exit_status(&DriverError::ApplyDeferred { step: 1 }), 1);
        assert_eq!(
            exit_status(&DriverError::UnknownInterface {
                step: 0,
                name: "x".into()
            }),
            EXIT_INVALID
        );
        let scenario = ruster_sim_scenario::parse_scenario(b"schema = 1", Path::new(""))
            .expect_err("invalid scenario");
        assert_eq!(exit_status(&DriverError::Scenario(scenario)), 2);
    }
}
