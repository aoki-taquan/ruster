//! `ruster-neighd [--run-dir DIR]`: ARP for the FE.
//!
//! neighd writes the FE's neighbor table, takes ARP from the FE on `neighd/punt.sock`
//! and sends frames back to `fe/punt/arp-nd.sock`. confd gives it the interfaces and addresses
//! on `neighd/config.sock`.

use std::process::ExitCode;
use std::time::Duration;

use ruster_neighd::Neighd;
use ruster_proto::daemon::{self, socket, Clock};
use ruster_proto::task::Task;

/// How long to wait for the FE at start-up.
const FE_WAIT: Duration = Duration::from_secs(10);

fn run() -> Result<(), String> {
    let (run_dir, rest) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    if let Some(extra) = rest.first() {
        return Err(format!("unexpected argument {extra}"));
    }
    let path = |name: &str| run_dir.join(name);
    let config = daemon::listen(&path(socket::NEIGHD_CONFIG))
        .map_err(|error| format!("{}: {error}", socket::NEIGHD_CONFIG))?;
    let punt = daemon::bind_datagram(&path(socket::NEIGHD_PUNT))
        .map_err(|error| format!("{}: {error}", socket::NEIGHD_PUNT))?;
    daemon::connect_datagram(&punt, &path(socket::FE_PUNT), FE_WAIT)
        .map_err(|error| format!("connecting to the FE: {error}"))?;
    let fe = daemon::connect(&path(socket::FE_NEIGHBOR), FE_WAIT)
        .map_err(|error| format!("connecting to the FE: {error}"))?;
    let mut neighd = Neighd::new(fe, punt).map_err(|error| error.to_string())?;
    eprintln!("ruster-neighd: connected to the FE");

    let clock = Clock::new();
    let mut last_report = 0;
    let mut reported = neighd.counters();
    let mut retry = daemon::Retry::default();
    loop {
        let now = clock.now_ms();
        for stream in daemon::accept(&config) {
            neighd
                .attach_config(stream)
                .map_err(|error| error.to_string())?;
        }
        if neighd.fe_closed() && retry.due(now) {
            if let Some(stream) = daemon::try_connect(&path(socket::FE_NEIGHBOR)) {
                let punt = daemon::bind_datagram(&path(socket::NEIGHD_PUNT))
                    .map_err(|error| format!("{}: {error}", socket::NEIGHD_PUNT))?;
                if punt.connect(path(socket::FE_PUNT)).is_ok() {
                    neighd
                        .reconnect_fe(stream, punt)
                        .map_err(|error| error.to_string())?;
                    eprintln!("ruster-neighd: connected to the FE again");
                }
            }
        }
        let progress = neighd.step(now);
        if now.saturating_sub(last_report) >= 5_000 && neighd.counters() != reported {
            reported = neighd.counters();
            last_report = now;
            eprintln!("ruster-neighd: {reported:?}");
        }
        daemon::idle(progress);
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ruster-neighd: {error}");
            ExitCode::FAILURE
        }
    }
}
