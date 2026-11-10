//! `ruster-frr [--run-dir DIR] [--reload COMMAND] [--fpm-port PORT] [--fpm-owner UID]
//! FILE`: the bridge between confd, ribd and FRR ([`ruster_frr`]).
//!
//! It takes the `frr` part of the configuration from confd, writes FRR's
//! configuration to FILE and runs COMMAND with FILE as its last argument
//! (`/usr/lib/frr/frr-reload.py --reload` when not given; an empty one runs
//! nothing), split at spaces. It listens for zebra's FPM connection on
//! 127.0.0.1:PORT (2620 when not given), taking it only from a socket of user ID
//! UID (the `frr` user's when not given; `any` takes every one), and gives the
//! routes to ribd as the route source `frr` (`ribd/source/frr/source.sock`; start ribd
//! with `frr:PREFERENCE:65000`: ruster-frr says it has sent everything only once
//! zebra's routes are in, which may take up to 60 s after it starts). Run it in the
//! router's kernel namespace, where zebra runs. It tells systemd it is ready once
//! FILE is first written. When confd or ribd goes away it connects again every
//! second.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use ruster_confd::part::{Asked, Client, Module};
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
    let mut owner = Some(None);
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
                owner = match args.next().as_deref() {
                    Some("any") => None,
                    Some(uid) => Some(Some(
                        uid.parse()
                            .map_err(|_| "--fpm-owner needs a user ID or any")?,
                    )),
                    None => return Err("--fpm-owner needs a user ID or any".into()),
                };
            }
            _ if file.is_none() => file = Some(PathBuf::from(arg)),
            _ => return Err("give one file".into()),
        }
    }
    let file = file.ok_or("give the file to write FRR's configuration to")?;
    let reload = reload.split_whitespace().map(str::to_owned).collect();
    let mut bridge = Bridge::new(file, reload, port);
    let owner = match owner {
        Some(None) => Some(
            user_id("frr")
                .ok_or("there is no user frr in /etc/passwd; give --fpm-owner UID (or any)")?,
        ),
        Some(Some(uid)) => Some(uid),
        None => None,
    };
    let mut fpm = Fpm::bind(port, owner).map_err(|e| format!("FPM port {port}: {e}"))?;
    let mut ribd = Writer::new(run_dir.join(socket::ribd_source(SOURCE)), None);

    let path = run_dir.join(socket::confd_part(Module::Frr.name()));
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
        let mut progress = client.poll(&mut |asked| {
            let part = match asked {
                Asked::Check(part) => return bridge.check(part),
                Asked::Take(part) => part,
            };
            match bridge.take(part) {
                Ok(connected) => {
                    if !written {
                        written = true;
                        eprintln!("ruster-frr: wrote FRR's configuration");
                        daemon::notify("READY=1");
                    }
                    changes.extend(fpm.set_connected(&connected));
                    Ok(String::new())
                }
                Err(error) => {
                    eprintln!("ruster-frr: refused a part: {error}");
                    Err(error)
                }
            }
        })?;
        let (more, busy, wake) = fpm.step(now);
        changes.extend(more);
        ribd.set(changes);
        progress = progress.and(Progress {
            busy,
            wake_at: wake,
        });
        // Until zebra's routes are all in and their interfaces known, ribd is not
        // told the routes are sent.
        if fpm.ready() && written {
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

/// A user's ID, from `/etc/passwd`.
fn user_id(name: &str) -> Option<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then(|| fields.nth(1)?.parse().ok())?
    })
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
