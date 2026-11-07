//! `ruster-fe [--run-dir DIR] DEVICE...`: the FE on Linux AF_PACKET sockets.
//!
//! Each DEVICE is a Linux network device and becomes the port of the same name: the
//! interface names in the tables are the device names. The FE listens on the table
//! sockets in the socket directory and forwards by what the writers send.
//!
//! AF_PACKET does not take frames away from the kernel, so the devices must carry no
//! kernel address or route, and the kernel must not forward on them.

use std::process::ExitCode;

use ruster_core::MonotonicMillis;
use ruster_fe::{writers, Fe};
use ruster_io_afpacket::{
    AfPacketIo, AfPacketPlatform, PortConfig, RingGeometry, ValidatedConfig, DEFAULT_MAX_FRAME_LEN,
};
use ruster_proto::daemon::{self, socket, Clock};
use ruster_proto::task::Task;

/// Room for the kernel's per-frame header and the largest frame.
const FRAME_SIZE: u32 = 2_048;
const BLOCK_SIZE: u32 = 65_536;

fn ring(block_count: u32, retire_timeout_ms: u32) -> RingGeometry {
    RingGeometry {
        block_size: BLOCK_SIZE,
        block_count,
        frame_size: FRAME_SIZE,
        frame_count: BLOCK_SIZE / FRAME_SIZE * block_count,
        retire_timeout_ms,
        private_size: 0,
        feature_flags: 0,
    }
}

fn if_index(device: &str) -> Result<u32, String> {
    let path = format!("/sys/class/net/{device}/ifindex");
    let text = std::fs::read_to_string(&path).map_err(|error| format!("{path}: {error}"))?;
    text.trim()
        .parse()
        .map_err(|_| format!("{path}: not a number"))
}

fn open(devices: &[String]) -> Result<AfPacketIo, String> {
    if devices.is_empty() {
        return Err("give at least one device".into());
    }
    let mut ports = Vec::with_capacity(devices.len());
    for (index, device) in devices.iter().enumerate() {
        let interface = u16::try_from(index)
            .map(ruster_core::IfId)
            .map_err(|_| "too many devices".to_owned())?;
        ports.push(PortConfig {
            interface,
            if_index: if_index(device)?,
            rx: ring(8, 4),
            tx: ring(4, 0),
        });
    }
    let page = AfPacketPlatform::page_size().map_err(|error| format!("{error:?}"))?;
    let config = ValidatedConfig::new(&ports, page, DEFAULT_MAX_FRAME_LEN)
        .map_err(|error| format!("{error:?}"))?;
    AfPacketIo::open(config).map_err(|error| format!("opening the devices: {error:?}"))
}

fn run() -> Result<(), String> {
    let (run_dir, devices) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    let io = open(&devices)?;
    let mut fe = Fe::new(io, devices.clone());
    let path = |name: &str| run_dir.join(name);
    let mut listeners = Vec::new();
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
    eprintln!("ruster-fe: forwarding on {}", devices.join(", "));

    let clock = Clock::new();
    let mut last_report = 0;
    let mut reported = fe.counters();
    loop {
        let now = clock.now_ms();
        fe.io_mut().set_clock(MonotonicMillis(now));
        for (listener, writes) in &listeners {
            for stream in daemon::accept(listener).map_err(|error| error.to_string())? {
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
        if !progress.busy {
            let wait = u32::try_from(daemon::IDLE_MAX.as_millis()).unwrap_or(1);
            fe.io_mut()
                .wait_rx(wait)
                .map_err(|error| format!("waiting for packets: {error:?}"))?;
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
