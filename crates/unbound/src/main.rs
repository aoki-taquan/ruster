//! `ruster-unbound [--run-dir DIR] [--reload COMMAND] FILE`: takes the `dns` part of
//! the configuration from confd and writes Unbound's settings to FILE
//! ([`ruster_unbound`]). After each change it runs COMMAND, split at spaces
//! (`systemctl restart unbound` when not given; an empty one runs nothing). It tells
//! systemd it is ready once FILE is written, so Unbound can be started after it.
//! When confd goes away it connects again every second.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use ruster_confd::part::{Client, Module};
use ruster_proto::daemon::{self, socket, Clock};
use ruster_unbound::Bridge;

/// How long to wait for confd at start-up.
const CONFD_WAIT: Duration = Duration::from_secs(10);

fn run() -> Result<(), String> {
    let (run_dir, rest) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    let mut reload = "systemctl restart unbound".to_owned();
    let mut file = None;
    let mut args = rest.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--reload" {
            reload = args.next().ok_or("--reload needs a command")?;
        } else if file.is_none() {
            file = Some(PathBuf::from(arg));
        } else {
            return Err("give one file".into());
        }
    }
    let file = file.ok_or("give the file to write Unbound's settings to")?;
    let reload = reload.split_whitespace().map(str::to_owned).collect();
    let mut bridge = Bridge::new(file, reload);

    let path = run_dir.join(socket::CONFD_PART);
    let stream = daemon::connect(&path, CONFD_WAIT).map_err(|e| format!("connecting: {e}"))?;
    let mut client = Client::new(stream, Module::Dns).map_err(|e| e.to_string())?;
    let clock = Clock::new();
    let mut retry = daemon::Retry::default();
    let mut idle = daemon::Idle::new();
    let mut ready = false;
    loop {
        if client.is_closed() && retry.due(clock.now_ms()) {
            if let Some(stream) = daemon::try_connect(&path) {
                match Client::new(stream, Module::Dns) {
                    Ok(again) => {
                        client = again;
                        eprintln!("ruster-unbound: connected to confd again");
                    }
                    Err(error) => eprintln!("ruster-unbound: connecting: {error}"),
                }
            }
        }
        let mut took = false;
        let progress = client.poll(&mut |part| {
            let result = bridge.take(part);
            if let Err(error) = &result {
                eprintln!("ruster-unbound: refused a part: {error}");
            }
            took |= result.is_ok();
            result
        })?;
        if took && !ready {
            ready = true;
            eprintln!("ruster-unbound: wrote the settings");
            daemon::notify("READY=1");
        }
        idle.wait(progress);
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ruster-unbound: {error}");
            ExitCode::FAILURE
        }
    }
}
