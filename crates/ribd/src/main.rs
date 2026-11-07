//! `ruster-ribd [--run-dir DIR] [NAME:PREFERENCE[:HOLD_MS]]...`: route selection.
//!
//! ribd writes the FE's route table and listens on one socket per route source
//! (`ribd/source/NAME.sock`). With no sources given, the only source is `confd` with
//! preference 1. Lower preference wins; HOLD_MS (default 5000) is how long ribd waits
//! for a source to finish sending after start-up before it tells the FE it is done.

use std::process::ExitCode;
use std::time::Duration;

use ruster_proto::daemon::{self, socket, Clock};
use ruster_proto::task::Task;
use ruster_ribd::{Ribd, SourceSpec};

/// How long to wait for the FE at start-up.
const FE_WAIT: Duration = Duration::from_secs(10);

fn source(text: &str) -> Result<SourceSpec, String> {
    let bad = || format!("{text}: a source is NAME:PREFERENCE[:HOLD_MS]");
    let mut parts = text.split(':');
    let name = parts
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(bad)?;
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(bad());
    }
    let preference = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let hold_ms = match parts.next() {
        Some(hold) => hold.parse().map_err(|_| bad())?,
        None => 5_000,
    };
    if parts.next().is_some() {
        return Err(bad());
    }
    Ok(SourceSpec {
        name: name.to_owned(),
        preference,
        hold_ms,
    })
}

fn run() -> Result<(), String> {
    let (run_dir, rest) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    let mut sources = rest
        .iter()
        .map(|text| source(text))
        .collect::<Result<Vec<_>, _>>()?;
    if sources.is_empty() {
        sources.push(source("confd:1")?);
    }
    let mut listeners = Vec::new();
    for spec in &sources {
        let name = socket::ribd_source(&spec.name);
        let listener =
            daemon::listen(&run_dir.join(&name)).map_err(|error| format!("{name}: {error}"))?;
        listeners.push((listener, spec.name.clone()));
    }
    let fe = daemon::connect(&run_dir.join(socket::FE_ROUTE), FE_WAIT)
        .map_err(|error| format!("connecting to the FE: {error}"))?;
    let mut ribd = Ribd::new(fe, sources).map_err(|error| error.to_string())?;
    eprintln!("ruster-ribd: connected to the FE");

    let clock = Clock::new();
    let mut synced = false;
    loop {
        let now = clock.now_ms();
        for (listener, name) in &listeners {
            for stream in daemon::accept(listener) {
                ribd.attach_source(name, stream)
                    .map_err(|error| error.to_string())?;
            }
        }
        let progress = ribd.step(now);
        if ribd.synced() && !synced {
            synced = true;
            eprintln!("ruster-ribd: routes sent to the FE");
        }
        daemon::idle(progress);
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ruster-ribd: {error}");
            ExitCode::FAILURE
        }
    }
}
