//! `ruster-confd [--run-dir DIR] [--kernel] FILE`: reads the configuration file and
//! sends it to the FE, ribd (as route source `confd`) and neighd. With `--kernel` it
//! also sets up the kernel side of traffic to the router ([`ruster_confd::kernel`]).
//! `ruster apply` gives it a new file later ([`ruster_confd::apply`]).

use std::process::ExitCode;
use std::time::Duration;

use ruster_confd::apply::Apply;
use ruster_confd::{file, Confd, Config, PeerKind};
use ruster_proto::daemon::{self, socket, Clock};
use ruster_proto::task::Task;

/// How long to wait for each process at start-up.
const PEER_WAIT: Duration = Duration::from_secs(10);

fn run() -> Result<(), String> {
    let (run_dir, rest) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    let kernel = rest.iter().any(|a| a == "--kernel");
    let rest: Vec<&String> = rest.iter().filter(|a| *a != "--kernel").collect();
    let [path] = rest.as_slice() else {
        return Err("give one configuration file".into());
    };
    let text = std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
    let config = file::parse(&text).map_err(|error| format!("{path}: {error}"))?;
    // Sets up the kernel side before a configuration is sent; the errors are also
    // reported to `ruster apply`.
    let mut prepare = |config: &Config| -> Vec<String> {
        if !kernel {
            return Vec::new();
        }
        let errors: Vec<String> = ruster_confd::kernel::apply(config)
            .into_iter()
            .map(|error| format!("kernel: {error}"))
            .collect();
        for error in &errors {
            eprintln!("ruster-confd: {error}");
        }
        errors
    };
    prepare(&config);
    let listener = daemon::listen(&run_dir.join(socket::CONFD_CONFIG))
        .map_err(|error| format!("{}: {error}", socket::CONFD_CONFIG))?;
    let mut apply = Apply::new();
    let mut confd = Confd::new(config);
    let connect = |name: &str| {
        daemon::connect(&run_dir.join(name), PEER_WAIT)
            .map_err(|error| format!("connecting: {error}"))
    };
    confd
        .connect_fe(connect(socket::FE_CONFIG)?)
        .map_err(|error| error.to_string())?;
    confd
        .connect_ribd(connect(&socket::ribd_source("confd"))?)
        .map_err(|error| error.to_string())?;
    confd
        .connect_neighd(connect(socket::NEIGHD_CONFIG)?)
        .map_err(|error| error.to_string())?;
    eprintln!("ruster-confd: sent {path}");
    daemon::notify("READY=1");

    let clock = Clock::new();
    let mut refused = 0;
    let mut apply_seen = apply.counters();
    let mut retry = daemon::Retry::default();
    loop {
        let now = clock.now_ms();
        let closed = confd.closed();
        if !closed.is_empty() && retry.due(now) {
            for kind in closed {
                let name = match kind {
                    PeerKind::Fe => socket::FE_CONFIG.to_owned(),
                    PeerKind::Ribd => socket::ribd_source("confd"),
                    PeerKind::Neighd => socket::NEIGHD_CONFIG.to_owned(),
                };
                let Some(stream) = daemon::try_connect(&run_dir.join(&name)) else {
                    continue;
                };
                // A failure is tried again at the next turn.
                let connected = match kind {
                    PeerKind::Fe => confd.connect_fe(stream),
                    PeerKind::Ribd => confd.connect_ribd(stream),
                    PeerKind::Neighd => confd.connect_neighd(stream),
                };
                match connected {
                    Ok(()) => eprintln!("ruster-confd: connected to {name} again"),
                    Err(error) => eprintln!("ruster-confd: connecting to {name}: {error}"),
                }
            }
        }
        for stream in daemon::accept(&listener) {
            if let Err(error) = apply.attach(stream) {
                eprintln!("ruster-confd: {}: {error}", socket::CONFD_CONFIG);
            }
        }
        let progress = confd
            .step(now)
            .and(apply.step(&mut confd, now, &mut prepare));
        if apply.counters() != apply_seen {
            let (now, was) = (apply.counters(), apply_seen);
            if now.late_rollbacks != was.late_rollbacks {
                eprintln!("ruster-confd: a late refusal put the configuration before back");
            }
            if now.gave_up != was.gave_up {
                eprintln!("ruster-confd: stopped waiting for answers to a new configuration");
            }
            apply_seen = now;
        }
        for request in confd.take_key_exchange_requests() {
            eprintln!(
                "ruster-confd: WireGuard {} of {} needs a key exchange",
                request.peer, request.interface
            );
        }
        if confd.counters().patches_refused != refused {
            refused = confd.counters().patches_refused;
            eprintln!("ruster-confd: a process refused a change ({refused} so far)");
        }
        daemon::idle(progress);
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ruster-confd: {error}");
            ExitCode::FAILURE
        }
    }
}
