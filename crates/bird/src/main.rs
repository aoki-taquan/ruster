//! `ruster-bird [--run-dir DIR] [--birdc COMMAND] FILE`: the bridge between confd and
//! bird-rs ([`ruster_bird`]).
//!
//! It takes the `bird` part of the configuration from confd, writes bird-rs's
//! configuration to FILE, and has bird-rs check and read it with COMMAND
//! (`birdc-rs -s /run/bird-rs.ctl` when not given; an empty one runs nothing), split at
//! spaces, followed by `configure check "FILE"` and `configure "FILE"`. bird-rs gives
//! its routes to ribd itself, as the route source `bird`
//! (`ribd/source/bird/source.sock`; start ribd with `bird:PREFERENCE:HOLD_MS`). Run it
//! in the router's kernel namespace, where bird-rs runs. It tells systemd it is ready
//! once FILE is first written. When confd goes away it connects again every second.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use ruster_bird::conf::Bridge;
use ruster_confd::part::{Asked, Client, Module};
use ruster_proto::daemon::{self, socket, Clock};

/// How long to wait for confd at start-up.
const CONFD_WAIT: Duration = Duration::from_secs(10);

fn run() -> Result<(), String> {
    let (run_dir, rest) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    let mut birdc = "birdc-rs -s /run/bird-rs.ctl".to_owned();
    let mut file = None;
    let mut args = rest.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--birdc" => birdc = args.next().ok_or("--birdc needs a command")?,
            _ if file.is_none() => file = Some(PathBuf::from(arg)),
            _ => return Err("give one file".into()),
        }
    }
    let file = file.ok_or("give the file to write bird-rs's configuration to")?;
    let birdc = birdc.split_whitespace().map(str::to_owned).collect();
    let absolute = std::path::absolute(&run_dir).map_err(|e| format!("run dir: {e}"))?;
    let mut bridge = Bridge::new(file, birdc, absolute.display().to_string());

    let path = run_dir.join(socket::confd_part(Module::Bird.name()));
    let stream = daemon::connect(&path, CONFD_WAIT).map_err(|e| format!("connecting: {e}"))?;
    let mut client = Client::new(stream, Module::Bird).map_err(|e| e.to_string())?;
    let clock = Clock::new();
    let mut retry = daemon::Retry::default();
    let mut idle = daemon::Idle::new();
    let mut written = false;
    loop {
        let now = clock.now_ms();
        if client.is_closed() && retry.due(now) {
            if let Some(stream) = daemon::try_connect(&path) {
                match Client::new(stream, Module::Bird) {
                    Ok(again) => {
                        client = again;
                        eprintln!("ruster-bird: connected to confd again");
                    }
                    Err(error) => eprintln!("ruster-bird: connecting: {error}"),
                }
            }
        }
        let progress = client.poll(&mut |asked| {
            let part = match asked {
                Asked::Check(part) => return bridge.check(part),
                Asked::Take(part) => part,
            };
            match bridge.take(part) {
                Ok(()) => {
                    if !written {
                        written = true;
                        eprintln!("ruster-bird: wrote bird-rs's configuration");
                        daemon::notify("READY=1");
                    }
                    Ok(String::new())
                }
                Err(error) => {
                    eprintln!("ruster-bird: refused a part: {error}");
                    Err(error)
                }
            }
        })?;
        idle.wait(progress);
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ruster-bird: {error}");
            ExitCode::FAILURE
        }
    }
}
