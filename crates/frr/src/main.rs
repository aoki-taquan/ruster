//! `ruster-frr [--run-dir DIR] [--reload COMMAND] [--fpm-port PORT] [--fpm-owner UID]
//! FILE`: the bridge between confd, ribd and FRR ([`ruster_frr`]).
//!
//! It takes the `frr` part of the configuration from confd, writes FRR's
//! configuration to FILE and runs COMMAND with FILE as its last argument
//! (`/usr/lib/frr/frr-reload.py --reload` when not given; an empty one runs
//! nothing), split at spaces. It listens for zebra's FPM connection on
//! 127.0.0.1:PORT (2620 when not given), taking it only from a socket of user ID
//! UID when one is given, and gives the routes to ribd as the route source `frr`
//! (`ribd/source/frr.sock`; start ribd with `frr:PREFERENCE`). Run it in the
//! router's kernel namespace, where zebra runs. It tells systemd it is ready once
//! FILE is first written. When confd or ribd goes away it connects again every
//! second.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use ruster_confd::part::{Client, Module};
use ruster_frr::conf::Bridge;
use ruster_frr::server::Fpm;
use ruster_proto::daemon::{self, socket, Clock};
use ruster_proto::task::Progress;
use ruster_proto::writer::Writer;

/// How long to wait for confd at start-up.
const CONFD_WAIT: Duration = Duration::from_secs(10);
/// The route source's name at ribd.
const SOURCE: &str = "frr";

fn run() -> Result<(), String> {
    let (run_dir, rest) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    let mut reload = "/usr/lib/frr/frr-reload.py --reload".to_owned();
    let mut port: u16 = 2620;
    let mut owner = None;
    let mut file = None;
    let mut args = rest.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--reload" => reload = args.next().ok_or("--reload needs a command")?,
            "--fpm-port" => {
                port = args
                    .next()
                    .and_then(|p| p.parse().ok())
                    .ok_or("--fpm-port needs a port")?;
            }
            "--fpm-owner" => {
                owner = Some(
                    args.next()
                        .and_then(|u| u.parse().ok())
                        .ok_or("--fpm-owner needs a user ID")?,
                );
            }
            _ if file.is_none() => file = Some(PathBuf::from(arg)),
            _ => return Err("give one file".into()),
        }
    }
    let file = file.ok_or("give the file to write FRR's configuration to")?;
    let reload = reload.split_whitespace().map(str::to_owned).collect();
    let mut bridge = Bridge::new(file, reload, port);
    let mut fpm = Fpm::bind(port, owner).map_err(|e| format!("FPM port {port}: {e}"))?;
    let mut ribd = Writer::new(run_dir.join(socket::ribd_source(SOURCE)), None);

    let path = run_dir.join(socket::CONFD_PART);
    let stream = daemon::connect(&path, CONFD_WAIT).map_err(|e| format!("connecting: {e}"))?;
    let mut client = Client::new(stream, Module::Frr).map_err(|e| e.to_string())?;
    let clock = Clock::new();
    let mut retry = daemon::Retry::default();
    let mut idle = daemon::Idle::new();
    let mut written = false;
    let mut announced = false;
    loop {
        let now = clock.now_ms();
        if client.is_closed() && retry.due(now) {
            if let Some(stream) = daemon::try_connect(&path) {
                match Client::new(stream, Module::Frr) {
                    Ok(again) => {
                        client = again;
                        eprintln!("ruster-frr: connected to confd again");
                    }
                    Err(error) => eprintln!("ruster-frr: connecting: {error}"),
                }
            }
        }
        let mut changes = Vec::new();
        let mut progress = client.poll(&mut |part| match bridge.take(part) {
            Ok(connected) => {
                if !written {
                    written = true;
                    eprintln!("ruster-frr: wrote FRR's configuration");
                    daemon::notify("READY=1");
                }
                changes.extend(fpm.set_connected(&connected));
                Ok(())
            }
            Err(error) => {
                eprintln!("ruster-frr: refused a part: {error}");
                Err(error)
            }
        })?;
        let (more, busy, wake) = fpm.step(now);
        changes.extend(more);
        ribd.set(changes);
        progress = progress.and(Progress {
            busy,
            wake_at: wake,
        });
        // Until zebra's routes are all in, ribd is not told the routes are sent.
        if fpm.ready() {
            if !announced {
                announced = true;
                eprintln!(
                    "ruster-frr: {} routes from zebra, giving them to ribd",
                    fpm.routes().len()
                );
            }
            let (moved, at) = ribd.step(now);
            progress = progress.and(Progress {
                busy: moved,
                wake_at: at,
            });
            if let Some(reason) = ribd.refused.take() {
                eprintln!("ruster-frr: ribd refused routes: {reason}");
            }
        }
        idle.wait(progress);
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ruster-frr: {error}");
            ExitCode::FAILURE
        }
    }
}
