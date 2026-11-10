//! `ruster-neighd [--run-dir DIR]`: ARP, Neighbor Discovery and Router
//! Advertisements for the FE.
//!
//! neighd writes the FE's neighbor table, takes ARP and ND from the FE on
//! `neighd/punt.sock` and sends frames back to `fe/punt/arp-nd.sock`. confd gives it
//! the interfaces and addresses on `neighd/config.sock`, and the Router
//! Advertisements as the `ra` part on `confd/part.sock`, which neighd connects to
//! once confd is there, and again every second when confd goes away.

use std::process::ExitCode;
use std::time::Duration;

use ruster_confd::part::{Client, Module};
use ruster_neighd::Neighd;
use ruster_proto::daemon::{self, socket, Clock};
use ruster_proto::task::{Progress, Task};

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
    daemon::notify("READY=1");

    let clock = Clock::new();
    let mut last_report = 0;
    let mut reported = neighd.counters();
    let mut retry = daemon::Retry::default();
    let mut part: Option<Client> = None;
    let mut part_retry = daemon::Retry::default();
    let mut idle = daemon::Idle::new();
    loop {
        let now = clock.now_ms();
        for stream in daemon::accept(&config) {
            // A connection that fails to set up is dropped; confd connects again.
            if let Err(error) = neighd.attach_config(stream) {
                eprintln!("ruster-neighd: confd's connection: {error}");
            }
        }
        // A failure while connecting again is tried again at the next turn.
        if neighd.fe_closed() && retry.due(now) {
            if let Some(stream) = daemon::try_connect(&path(socket::FE_NEIGHBOR)) {
                match daemon::bind_datagram(&path(socket::NEIGHD_PUNT)) {
                    Ok(punt) if punt.connect(path(socket::FE_PUNT)).is_ok() => {
                        match neighd.reconnect_fe(stream, punt) {
                            Ok(()) => eprintln!("ruster-neighd: connected to the FE again"),
                            Err(error) => eprintln!("ruster-neighd: connecting to the FE: {error}"),
                        }
                    }
                    Ok(_) => {}
                    Err(error) => eprintln!("ruster-neighd: {}: {error}", socket::NEIGHD_PUNT),
                }
            }
        }
        if part.as_ref().is_none_or(Client::is_closed) && part_retry.due(now) {
            part = daemon::try_connect(&path(socket::CONFD_PART))
                .and_then(|stream| Client::new(stream, Module::Ra).ok());
        }
        let mut taken = Progress::IDLE;
        if let Some(client) = &mut part {
            let polled = client.poll(&mut |text| {
                let result = neighd.take_ra(text);
                match &result {
                    Ok(()) => eprintln!("ruster-neighd: took the ra part"),
                    Err(error) => eprintln!("ruster-neighd: refused the ra part: {error}"),
                }
                result
            });
            match polled {
                Ok(progress) => taken = progress,
                Err(error) => {
                    eprintln!("ruster-neighd: {error}");
                    part = None;
                }
            }
        }
        let progress = neighd.step(now).and(taken);
        if now.saturating_sub(last_report) >= 5_000 && neighd.counters() != reported {
            reported = neighd.counters();
            last_report = now;
            eprintln!("ruster-neighd: {reported:?}");
        }
        idle.wait(progress);
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
