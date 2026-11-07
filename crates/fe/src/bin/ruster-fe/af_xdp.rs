//! The AF_XDP backend: an XDP program hands each port's frames to the FE.

use std::num::{NonZeroU128, NonZeroU32};
use std::thread;

use ruster_core::{IfId, MonotonicMillis};
use ruster_io_xdp::native_profile::{
    RingConfig, UmemConfig, ValidatedBindFlags, XDP_COPY, XDP_USE_NEED_WAKEUP, XDP_ZEROCOPY,
};
use ruster_io_xdp_native::{
    NativeSession, RxFillConfig, RxFillEngine, RxWait, SessionConfig, UmemDomainId, XdpAttachMode,
    XdpPacketIo, XdpPort, XdpPortConfig,
};
use ruster_proto::daemon;

use crate::Backend;

/// Ring and UMEM sizes of every port.
const RING_ENTRIES: u32 = 2_048;
const FRAME_SIZE: u32 = 4_096;
const GENERATED_FRAMES: u32 = 512;
const FRAME_COUNT: u32 = RING_ENTRIES * 2 + GENERATED_FRAMES;
/// Kick-and-reap rounds per drain call.
const DRAIN_ROUNDS: u32 = 8;

/// How the XDP program is attached and the sockets bound.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub attach: XdpAttachMode,
    pub zero_copy: bool,
}

/// Opens one socket on queue 0 of each device and attaches the XDP program.
pub fn open_sessions(devices: &[String], options: Options) -> Result<Vec<NativeSession>, String> {
    let mode = if options.zero_copy {
        XDP_ZEROCOPY
    } else {
        XDP_COPY
    };
    let bad = |error| format!("{error:?}");
    let bind_flags = ValidatedBindFlags::new(XDP_USE_NEED_WAKEUP | mode).map_err(bad)?;
    let rings =
        RingConfig::new(RING_ENTRIES, RING_ENTRIES, RING_ENTRIES, RING_ENTRIES).map_err(bad)?;
    let umem = UmemConfig::new(
        FRAME_COUNT,
        FRAME_SIZE,
        0,
        FRAME_COUNT - GENERATED_FRAMES,
        GENERATED_FRAMES,
        0,
    )
    .map_err(bad)?;
    let mut sessions = Vec::with_capacity(devices.len());
    for device in devices {
        let config = SessionConfig::new(device, 0, bind_flags, rings, umem)
            .map_err(|error| format!("{device}: {error:?}"))?;
        let mut session =
            NativeSession::open(&config).map_err(|error| format!("{device}: {error:?}"))?;
        session
            .attach_xdp(options.attach)
            .map_err(|error| format!("{device}: attaching XDP: {error:?}"))?;
        sessions.push(session);
    }
    Ok(sessions)
}

fn domain(interface: IfId) -> UmemDomainId {
    // A tag keeps these apart from domains other code may make.
    const TAG: u128 = 0x7275_7374_6572_2d66_6500_0000_0000_0000;
    let id = TAG | u128::from(interface.0);
    UmemDomainId::new(NonZeroU128::new(id).unwrap_or(NonZeroU128::MIN))
}

/// The packet I/O over the opened sessions; port `i` is `IfId(i)`.
pub fn packet_io(sessions: &mut [NativeSession]) -> Result<XdpPacketIo<'_>, String> {
    let mut ports = Vec::with_capacity(sessions.len());
    for (index, session) in sessions.iter_mut().enumerate() {
        let interface = u16::try_from(index)
            .map(IfId)
            .map_err(|_| "too many devices".to_owned())?;
        let config = XdpPortConfig::from_session(interface, session);
        let datapath = session
            .take_datapath()
            .map_err(|error| format!("{error:?}"))?;
        let fill_batch = datapath.capacities()[0];
        let engine = RxFillEngine::new(
            datapath,
            domain(interface),
            RxFillConfig::new(NonZeroU32::new(fill_batch).unwrap_or(NonZeroU32::MIN)),
        )
        .map_err(|error| format!("{error:?}"))?;
        ports.push(XdpPort::new(config, engine));
    }
    XdpPacketIo::new(ports).map_err(|error| format!("{error:?}"))
}

/// Waiting for AF_XDP input between steps.
#[derive(Default)]
pub struct Waiter {
    ready_unused: bool,
}

impl Backend<XdpPacketIo<'_>> for Waiter {
    fn set_clock(&mut self, io: &mut XdpPacketIo<'_>, now: MonotonicMillis) {
        io.set_clock(now);
    }

    fn after_step(&mut self, io: &mut XdpPacketIo<'_>, busy: bool) -> Result<(), String> {
        if busy {
            self.ready_unused = false;
            return Ok(());
        }
        // Reap completions, retry owed kicks and refill Fill while idle.
        io.service()
            .map_err(|error| format!("the packet backend stopped: {error:?}"))?;
        if self.ready_unused || !io.can_wait() {
            self.ready_unused = false;
            thread::sleep(daemon::IDLE_MAX);
        } else {
            let woke = io
                .wait_rx(daemon::IDLE_MAX_MS)
                .map_err(|error| format!("waiting for packets: {error:?}"))?;
            self.ready_unused = woke == RxWait::Ready;
        }
        Ok(())
    }

    fn drain(&mut self, io: &mut XdpPacketIo<'_>) -> bool {
        // An error means the adapter already stopped: nothing more can come back.
        io.drain(DRAIN_ROUNDS)
            .map_or(true, |report| report.is_drained())
    }
}
