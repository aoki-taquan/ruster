//! `ruster-confd [--run-dir DIR] [--state-dir DIR] [--kernel] FILE`: sends the
//! configuration to the FE, ribd (as route source `confd`) and neighd. With `--kernel`
//! it also sets up the kernel side of traffic to the router ([`ruster_confd::kernel`]).
//!
//! The configuration is the latest version confd has kept. FILE is read only when there
//! is none yet, and becomes version 1. With `--state-dir` the versions are files there
//! and outlive confd; without it they are only in memory, so confd started again reads
//! FILE again ([`ruster_confd::versions`]).
//!
//! `ruster apply` gives it a new file later ([`ruster_confd::apply`]), and processes
//! such as `ruster-unbound` take their part of it on `confd/part/<module>/part.sock`
//! ([`ruster_confd::part`]). Each source of the configuration gets
//! `confd/source/<name>/source.sock` ([`ruster_confd::source`]).

use std::collections::BTreeMap;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use ruster_confd::apply::Apply;
use ruster_confd::part::Module;
use ruster_confd::versions::Versions;
use ruster_confd::{Confd, Config, PeerKind};
use ruster_proto::daemon::{self, socket, Clock};
use ruster_proto::task::Task;

/// How long to wait for each process at start-up.
const PEER_WAIT: Duration = Duration::from_secs(10);

/// Listens on the socket of each source of the configuration, and stops listening
/// for those it no longer has.
fn source_sockets(run_dir: &Path, confd: &Confd, listening: &mut BTreeMap<String, UnixListener>) {
    let names = confd.source_names();
    listening.retain(|name, _| {
        let keep = names.contains(name);
        if !keep {
            let _ = std::fs::remove_file(run_dir.join(socket::confd_source(name)));
        }
        keep
    });
    for name in names {
        if listening.contains_key(&name) {
            continue;
        }
        let path = socket::confd_source(&name);
        match daemon::listen(&run_dir.join(&path)) {
            Ok(listener) => {
                listening.insert(name, listener);
            }
            Err(error) => eprintln!("ruster-confd: {path}: {error}"),
        }
    }
}

fn run() -> Result<(), String> {
    let (run_dir, rest) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    let mut kernel = false;
    let mut state_dir = None;
    let mut files = Vec::new();
    let mut args = rest.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--kernel" => kernel = true,
            "--state-dir" => {
                state_dir = Some(args.next().ok_or("--state-dir needs a directory")?);
            }
            _ => files.push(arg),
        }
    }
    let [path] = files.as_slice() else {
        return Err("give one configuration file".into());
    };
    let mut versions = match &state_dir {
        Some(dir) => Versions::open(Path::new(dir))?,
        None => Versions::in_memory(),
    };
    let start = versions.starting_config(path)?;
    if let Some(warning) = &start.warning {
        eprintln!("ruster-confd: WARNING: {warning}");
    }
    let (config, from) = (start.config, start.from);
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
    let mut parts = Vec::new();
    for module in Module::ALL {
        let path = socket::confd_part(module.name());
        let listener =
            daemon::listen(&run_dir.join(&path)).map_err(|error| format!("{path}: {error}"))?;
        parts.push((module, listener));
    }
    let mut apply = Apply::new(versions);
    let mut confd = Confd::new(config);
    let mut sources = BTreeMap::new();
    source_sockets(&run_dir, &confd, &mut sources);
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
    eprintln!("ruster-confd: sent {from}");
    daemon::notify("READY=1");

    let clock = Clock::new();
    let mut refused = 0;
    let mut generation = confd.generation();
    let mut retry_sockets = daemon::Retry::default();
    let mut values_seen = confd.values_changed();
    let mut kernel_config = None;
    let mut waiting = confd.waiting_for_sources();
    let mut apply_seen = apply.counters();
    let mut retry = daemon::Retry::default();
    let mut idle = daemon::Idle::new();
    loop {
        let now = clock.now_ms();
        let closed = confd.closed();
        if !closed.is_empty() && retry.due(now) {
            for kind in closed {
                let name = match kind {
                    // It connects to confd again by itself.
                    PeerKind::Part(_) => continue,
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
                    PeerKind::Part(_) => continue,
                };
                match connected {
                    Ok(()) => eprintln!("ruster-confd: connected to {name} again"),
                    Err(error) => eprintln!("ruster-confd: connecting to {name}: {error}"),
                }
            }
        }
        // A socket that could not be made is tried again at the next turn.
        let missing = confd.source_names().len() != sources.len();
        let new_values = confd.values_changed() != values_seen;
        if confd.generation() != generation || new_values || (missing && retry_sockets.due(now)) {
            generation = confd.generation();
            values_seen = confd.values_changed();
            source_sockets(&run_dir, &confd, &mut sources);
            // A PPPoE session's address comes and goes with the session.
            // A value sent again unchanged changes nothing there.
            let now_config = confd.with_values();
            if kernel && kernel_config.as_ref() != Some(&now_config) {
                for error in ruster_confd::kernel::apply(&now_config) {
                    eprintln!("ruster-confd: kernel: {error}");
                }
                kernel_config = Some(now_config);
            }
        }
        for (name, listener) in &sources {
            for stream in daemon::accept(listener) {
                if let Err(error) = confd.attach_source(name, stream) {
                    eprintln!("ruster-confd: source {name}: {error}");
                }
            }
        }
        for (module, listener) in &parts {
            for stream in daemon::accept(listener) {
                if let Err(error) = confd.attach_part(*module, stream) {
                    eprintln!("ruster-confd: part {module}: {error}");
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
        for line in apply.take_log() {
            eprintln!("ruster-confd: {line}");
        }
        if waiting && !confd.waiting_for_sources() {
            waiting = false;
            eprintln!(
                "ruster-confd: the sources sent everything again (or their sync-wait passed)"
            );
        }
        if confd.counters().patches_refused != refused {
            refused = confd.counters().patches_refused;
            eprintln!("ruster-confd: a process refused a change ({refused} so far)");
        }
        idle.wait(progress);
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
