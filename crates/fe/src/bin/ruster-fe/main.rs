//! `ruster-fe [--run-dir DIR] [--backend af-xdp|af-packet] [--xdp-attach native|generic]
//! [--zero-copy] DEVICE...`: the FE on Linux.
//!
//! Each DEVICE is a Linux network device and becomes the port of the same name: the
//! interface names in the tables are the device names. The FE listens on the table
//! sockets in the socket directory and forwards by what the writers send.
//!
//! - `af-xdp` (the default) attaches an XDP program to queue 0 of each device and
//!   takes the frames away from the kernel. Copy mode unless `--zero-copy`.
//! - `af-packet` receives copies: the kernel still sees every frame, so the devices
//!   must carry no kernel address or route, and the kernel must not forward on them.

mod af_packet;
mod af_xdp;

use std::os::unix::net::UnixListener;
use std::process::ExitCode;

use ruster_core::{GeneratedPacketIo, MonotonicMillis, PacketIo};
use ruster_fe::{writers, Fe};
use ruster_io_xdp_native::XdpAttachMode;
use ruster_proto::daemon::{self, socket, Clock};
use ruster_proto::task::Task;

/// What the loop needs from a backend beyond packet I/O.
pub trait Backend<B> {
    fn set_clock(&mut self, io: &mut B, now: MonotonicMillis);
    /// Waits for input when the step found nothing to do; fails when the backend stopped.
    fn after_step(&mut self, io: &mut B, busy: bool) -> Result<(), String>;
}

/// The interface index of `device` in this network namespace.
pub fn if_index(device: &str) -> Result<u32, String> {
    let path = format!("/sys/class/net/{device}/ifindex");
    let text = std::fs::read_to_string(&path).map_err(|error| format!("{path}: {error}"))?;
    text.trim()
        .parse()
        .map_err(|_| format!("{path}: not a number"))
}

struct Args {
    run_dir: std::path::PathBuf,
    af_packet: bool,
    xdp: af_xdp::Options,
    devices: Vec<String>,
}

fn args() -> Result<Args, String> {
    let (run_dir, rest) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    let mut args = Args {
        run_dir,
        af_packet: false,
        xdp: af_xdp::Options {
            attach: XdpAttachMode::Native,
            zero_copy: false,
        },
        devices: Vec::new(),
    };
    let mut rest = rest.into_iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--backend" => match rest.next().as_deref() {
                Some("af-xdp") => args.af_packet = false,
                Some("af-packet") => args.af_packet = true,
                _ => return Err("--backend is af-xdp or af-packet".into()),
            },
            "--xdp-attach" => match rest.next().as_deref() {
                Some("native") => args.xdp.attach = XdpAttachMode::Native,
                Some("generic") => args.xdp.attach = XdpAttachMode::Generic,
                _ => return Err("--xdp-attach is native or generic".into()),
            },
            "--zero-copy" => args.xdp.zero_copy = true,
            flag if flag.starts_with("--") => return Err(format!("unknown option {flag}")),
            _ => args.devices.push(arg),
        }
    }
    if args.devices.is_empty() {
        return Err("give at least one device".into());
    }
    Ok(args)
}

fn run() -> Result<(), String> {
    let args = args()?;
    if args.af_packet {
        let io = af_packet::open(&args.devices)?;
        serve(io, af_packet::Waiter::default(), &args)
    } else {
        let mut sessions = af_xdp::open_sessions(&args.devices, args.xdp)?;
        let io = af_xdp::packet_io(&mut sessions)?;
        serve(io, af_xdp::Waiter::default(), &args)
    }
}

fn serve<B, W>(io: B, mut waiter: W, args: &Args) -> Result<(), String>
where
    B: PacketIo + GeneratedPacketIo,
    W: Backend<B>,
{
    let mut fe = Fe::new(io, args.devices.clone());
    let path = |name: &str| args.run_dir.join(name);
    let mut listeners: Vec<(UnixListener, &[u64])> = Vec::new();
    for (name, writes) in [
        (socket::FE_CONFIG, writers::CONFIG),
        (socket::FE_ROUTE, writers::ROUTE),
        (socket::FE_NEIGHBOR, writers::NEIGHBOR),
    ] {
        let listener = daemon::listen(&path(name)).map_err(|error| format!("{name}: {error}"))?;
        listeners.push((listener, writes));
    }
    let punt = daemon::bind_datagram(&path(socket::FE_PUNT))
        .map_err(|error| format!("{}: {error}", socket::FE_PUNT))?;
    fe.attach_punt_to(punt, path(socket::NEIGHD_PUNT))
        .map_err(|error| error.to_string())?;
    let backend = if args.af_packet {
        "AF_PACKET"
    } else {
        "AF_XDP"
    };
    eprintln!(
        "ruster-fe: forwarding on {} ({backend})",
        args.devices.join(", ")
    );
    run_loop(&mut fe, &mut waiter, &listeners)
}

fn run_loop<B, W>(
    fe: &mut Fe<B>,
    waiter: &mut W,
    listeners: &[(UnixListener, &[u64])],
) -> Result<(), String>
where
    B: PacketIo + GeneratedPacketIo,
    W: Backend<B>,
{
    let clock = Clock::new();
    let mut last_report = 0;
    let mut reported = fe.counters();
    loop {
        let now = clock.now_ms();
        waiter.set_clock(fe.io_mut(), MonotonicMillis(now));
        for (listener, writes) in listeners {
            for stream in daemon::accept(listener) {
                fe.attach(stream, writes)
                    .map_err(|error| error.to_string())?;
            }
        }
        let progress = fe.step(now);
        if now.saturating_sub(last_report) >= 5_000 && fe.counters() != reported {
            reported = fe.counters();
            last_report = now;
            eprintln!("ruster-fe: {reported:?}");
        }
        waiter.after_step(fe.io_mut(), progress.busy)?;
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ruster-fe: {error}");
            ExitCode::FAILURE
        }
    }
}
