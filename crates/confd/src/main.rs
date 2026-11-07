//! `ruster-confd [--run-dir DIR] FILE`: reads the configuration file and sends it to
//! the FE, ribd (as route source `confd`) and neighd.

use std::process::ExitCode;
use std::time::Duration;

use ruster_confd::{file, Confd};
use ruster_proto::daemon::{self, socket, Clock};
use ruster_proto::task::Task;

/// How long to wait for each process at start-up.
const PEER_WAIT: Duration = Duration::from_secs(10);

fn run() -> Result<(), String> {
    let (run_dir, rest) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    let [path] = rest.as_slice() else {
        return Err("give one configuration file".into());
    };
    let text = std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
    let config = file::parse(&text).map_err(|error| format!("{path}: {error}"))?;
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

    let clock = Clock::new();
    let mut refused = 0;
    loop {
        let now = clock.now_ms();
        let progress = confd.step(now);
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
