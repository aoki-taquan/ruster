//! `ruster-kea [--run-dir DIR] [--control SOCKET] [--kea IFACE/ADDRESS] [--dhcp6 FILE6]
//! [--control6 SOCKET] [--kea6 IFACE/ADDRESS] FILE`: takes the `dhcp` part of the
//! configuration from confd, writes Kea's DHCPv4 subnets to FILE (and its DHCPv6
//! subnets to FILE6) and relays DHCP and DHCPv6 between the FE and Kea
//! ([`ruster_kea`]).
//!
//! - `--control`: Kea's DHCPv4 control socket, `/run/kea/kea4-ctrl-socket` when not
//!   given; an empty one asks Kea nothing.
//! - `--kea`: where Kea's DHCPv4 listens, `lo/127.0.0.1` when not given.
//! - `--dhcp6`: the file for Kea's DHCPv6; without it, a part with `dhcp6` is
//!   refused.
//! - `--control6`, `--kea6`: as `--control` and `--kea` for Kea's DHCPv6,
//!   `/run/kea/kea6-ctrl-socket` and `lo/::1` when not given.
//!
//! It tells systemd it is ready once FILE is first written, before Kea is asked to
//! read it, so Kea can be started after it. When confd goes away it connects again
//! every second. It needs to bind UDP ports 67 and 547 (`CAP_NET_BIND_SERVICE`).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use ruster_confd::part::{Client, Module};
use ruster_kea::agent::Agent;
use ruster_kea::settings::Listen;
use ruster_kea::settings6::Listen6;
use ruster_kea::{Bridge, Server};
use ruster_proto::daemon::{self, socket, Clock};
use ruster_proto::task::Progress;

/// How long to wait for confd at start-up.
const CONFD_WAIT: Duration = Duration::from_secs(10);
/// The control process name the FE's punt classes give.
const NAME: &str = "kea";

fn run() -> Result<(), String> {
    let (run_dir, rest) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    let mut control = "/run/kea/kea4-ctrl-socket".to_owned();
    let mut listen = "lo/127.0.0.1".to_owned();
    let mut control6 = "/run/kea/kea6-ctrl-socket".to_owned();
    let mut listen6 = "lo/::1".to_owned();
    let mut file6 = None;
    let mut file = None;
    let mut args = rest.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--control" => control = args.next().ok_or("--control needs a socket")?,
            "--kea" => listen = args.next().ok_or("--kea needs IFACE/ADDRESS")?,
            "--dhcp6" => file6 = Some(PathBuf::from(args.next().ok_or("--dhcp6 needs a file")?)),
            "--control6" => control6 = args.next().ok_or("--control6 needs a socket")?,
            "--kea6" => listen6 = args.next().ok_or("--kea6 needs IFACE/ADDRESS")?,
            _ if file.is_none() => file = Some(PathBuf::from(arg)),
            _ => return Err("give one file".into()),
        }
    }
    let file = file.ok_or("give the file to write Kea's subnets to")?;
    let listen = Listen::parse(&listen).map_err(|e| format!("--kea: {e}"))?;
    let control = (!control.is_empty()).then(|| PathBuf::from(control));
    let listen6 = Listen6::parse(&listen6).map_err(|e| format!("--kea6: {e}"))?;
    let control6 = (!control6.is_empty()).then(|| PathBuf::from(control6));
    let mut agent = Agent::new(
        daemon::bind_datagram(&run_dir.join(socket::control_punt(NAME)))
            .map_err(|e| format!("{}: {e}", socket::control_punt(NAME)))?,
        run_dir.join(socket::fe_punt(NAME)),
        listen.address,
        listen6.address,
    );
    let mut bridge = Bridge::new(file, control, listen);
    if let Some(path) = file6 {
        let server = Server {
            path,
            control: control6,
        };
        bridge = bridge.with_dhcp6(server, listen6);
    }

    let path = run_dir.join(socket::confd_part(Module::Dhcp.name()));
    let stream = daemon::connect(&path, CONFD_WAIT).map_err(|e| format!("connecting: {e}"))?;
    let mut client = Client::new(stream, Module::Dhcp).map_err(|e| e.to_string())?;
    let clock = Clock::new();
    let mut retry = daemon::Retry::default();
    let mut idle = daemon::Idle::new();
    let mut ready = false;
    let mut counters = agent.counters;
    let mut logged_at = 0;
    loop {
        if client.is_closed() && retry.due(clock.now_ms()) {
            if let Some(stream) = daemon::try_connect(&path) {
                match Client::new(stream, Module::Dhcp) {
                    Ok(again) => {
                        client = again;
                        eprintln!("ruster-kea: connected to confd again");
                    }
                    Err(error) => eprintln!("ruster-kea: connecting: {error}"),
                }
            }
        }
        let polled = client.poll(&mut |part| {
            let result = bridge.take(part, &mut || {
                if !ready {
                    ready = true;
                    eprintln!("ruster-kea: wrote the settings");
                    daemon::notify("READY=1");
                }
            });
            match result {
                Ok((served, served6)) => {
                    agent.set_links(
                        served.into_iter().map(|s| s.link).collect(),
                        served6.into_iter().map(|s| s.link).collect(),
                    );
                    eprintln!("ruster-kea: took a part");
                    Ok(())
                }
                Err(error) => {
                    eprintln!("ruster-kea: refused a part: {error}");
                    Err(error)
                }
            }
        })?;
        let progress = polled.and(agent.step(clock.now_ms()));
        // The counts, at most once a second.
        if agent.counters != counters && clock.now_ms() >= logged_at + 1_000 {
            logged_at = clock.now_ms();
            counters = agent.counters;
            eprintln!(
                "ruster-kea: {} requests, {} replies, {} dropped",
                counters.requests, counters.replies, counters.dropped
            );
        }
        idle.wait(Progress {
            busy: progress.busy,
            wake_at: None,
        });
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ruster-kea: {error}");
            ExitCode::FAILURE
        }
    }
}
