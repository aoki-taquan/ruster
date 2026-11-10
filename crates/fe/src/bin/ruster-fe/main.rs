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
mod promisc;
mod signal;
mod tun;

use std::os::unix::net::UnixListener;
use std::process::ExitCode;

use ruster_core::{GeneratedPacketIo, MonotonicMillis, PacketIo};
use ruster_fe::{writers, Fe};
use ruster_io_xdp_native::XdpAttachMode;
use ruster_proto::daemon::{self, socket, Clock};
use ruster_proto::task::Task;

/// The longest the FE waits for frames while idle. A frame wakes it at once; the
/// control sockets and the kernel's frames are seen at the end of the wait.
const IDLE_LONGEST_MS: u32 = 4;

/// What the loop needs from a backend beyond packet I/O.
pub trait Backend<B> {
    fn set_clock(&mut self, io: &mut B, now: MonotonicMillis);
    /// Waits for input when the step found nothing to do; fails when the backend stopped.
    fn after_step(&mut self, io: &mut B, busy: bool) -> Result<(), String>;
    /// One round of the shutdown drain: stops I/O for good, and returns whether every
    /// frame handed to the kernel came back.
    fn drain(&mut self, io: &mut B) -> bool;
}

/// How long a stopping FE waits for frames still in the kernel.
const DRAIN_MS: u64 = 1_000;

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
    signal::install().map_err(|name| format!("installing the {name} handler"))?;
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
        (socket::FE_STATE, writers::READ_ONLY),
    ] {
        let listener = daemon::listen(&path(name)).map_err(|error| format!("{name}: {error}"))?;
        listeners.push((listener, writes));
    }
    let punt = daemon::bind_datagram(&path(socket::FE_PUNT))
        .map_err(|error| format!("{}: {error}", socket::FE_PUNT))?;
    fe.attach_punt_to(punt, path(socket::NEIGHD_PUNT))
        .map_err(|error| error.to_string())?;
    fe.set_punt_dir(args.run_dir.clone());
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
    let mut tuns = Tuns::default();
    let mut promiscuous = promisc::Promiscuous::default();
    let mut last_tun_check = 0;
    // A stop asked for while starting: the loop stops at once, without READY=1.
    if !signal::stop_requested() {
        daemon::notify("READY=1");
    }
    loop {
        let now = clock.now_ms();
        if signal::stop_requested() {
            daemon::notify("STOPPING=1");
            let until = now.saturating_add(DRAIN_MS);
            let mut drained = waiter.drain(fe.io_mut());
            while !drained && clock.now_ms() < until && !signal::force_requested() {
                std::thread::sleep(daemon::IDLE_MAX);
                drained = waiter.drain(fe.io_mut());
            }
            let how = if drained { "drained" } else { "not drained" };
            eprintln!("ruster-fe: stopped, {how} ({:?})", fe.counters());
            promiscuous.keep(&[]);
            return Ok(());
        }
        waiter.set_clock(fe.io_mut(), MonotonicMillis(now));
        for (listener, writes) in listeners {
            for stream in daemon::accept(listener) {
                fe.attach(stream, writes)
                    .map_err(|error| error.to_string())?;
            }
        }
        if now.saturating_sub(last_tun_check) >= TUN_CHECK_MS {
            last_tun_check = now;
            tuns.check(fe);
            promiscuous.keep(&fe.promiscuous_ports());
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

/// How often the FE looks at the TUN devices of its VRFs.
const TUN_CHECK_MS: u64 = 1_000;

/// The TUN devices the FE's VRFs are attached to.
#[derive(Default)]
struct Tuns {
    /// For each attached VRF, the interface index of its device when it was opened.
    attached: std::collections::BTreeMap<String, u32>,
    /// For each interface whose TAP device is attached, its index when opened.
    taps: std::collections::BTreeMap<String, u32>,
    /// The last error for each device, written once until it changes.
    errors: std::collections::BTreeMap<String, String>,
}

impl Tuns {
    /// Attaches each VRF to its TUN device once confd has created it, and again when
    /// the device was made again (another index) or the VRF went away and came back.
    fn check<B>(&mut self, fe: &mut Fe<B>)
    where
        B: PacketIo + GeneratedPacketIo,
    {
        let vrfs = fe.vrfs().to_vec();
        let gone: Vec<String> = self
            .attached
            .iter()
            .filter(|(vrf, &index)| {
                !vrfs.contains(vrf) || tun::device(vrf).and_then(|d| tun::index(&d)) != Some(index)
            })
            .map(|(vrf, _)| vrf.clone())
            .collect();
        for vrf in gone {
            self.attached.remove(&vrf);
            fe.detach_local(&vrf);
            eprintln!("ruster-fe: the TUN device of VRF {vrf:?} is gone or was made again");
        }
        self.check_taps(fe);
        for vrf in vrfs {
            if self.attached.contains_key(&vrf) {
                continue;
            }
            let Some(device) = tun::device(&vrf) else {
                continue;
            };
            let Some(index) = tun::index(&device) else {
                continue;
            };
            match tun::open(&device, false) {
                Ok(file) => {
                    fe.attach_local(&vrf, Box::new(file));
                    eprintln!("ruster-fe: traffic to the router in VRF {vrf:?} goes to {device}");
                    self.attached.insert(vrf, index);
                    self.errors.remove(&device);
                }
                Err(error) => {
                    let text = error.to_string();
                    if self.errors.get(&device) != Some(&text) {
                        eprintln!("ruster-fe: {device}: {text}");
                        self.errors.insert(device, text);
                    }
                }
            }
        }
    }
}

impl Tuns {
    /// Attaches each interface whose IS-IS and OSPF go to a TAP device to it once
    /// confd has created it, and again when it was made again; detaches it when the
    /// tables no longer send anything there.
    fn check_taps<B>(&mut self, fe: &mut Fe<B>)
    where
        B: PacketIo + GeneratedPacketIo,
    {
        let wanted = fe.tap_interfaces();
        let gone: Vec<String> = self
            .taps
            .iter()
            .filter(|(name, &index)| {
                !wanted.contains(name)
                    || tun::tap_device(name).and_then(|d| tun::index(&d)) != Some(index)
            })
            .map(|(name, _)| name.clone())
            .collect();
        for name in gone {
            self.taps.remove(&name);
            fe.detach_tap(&name);
            eprintln!("ruster-fe: the TAP device of {name:?} is gone, made again or not used");
        }
        for name in wanted {
            if self.taps.contains_key(&name) {
                continue;
            }
            let Some(device) = tun::tap_device(&name) else {
                continue;
            };
            let Some(index) = tun::index(&device) else {
                continue;
            };
            match tun::open(&device, true) {
                Ok(file) => {
                    fe.attach_tap(&name, Box::new(file));
                    eprintln!("ruster-fe: IS-IS and OSPF of {name:?} go to {device}");
                    self.taps.insert(name, index);
                    self.errors.remove(&device);
                }
                Err(error) => {
                    let text = error.to_string();
                    if self.errors.get(&device) != Some(&text) {
                        eprintln!("ruster-fe: {device}: {text}");
                        self.errors.insert(device, text);
                    }
                }
            }
        }
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
