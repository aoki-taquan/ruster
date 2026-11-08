//! The AF_PACKET backend: copies of the frames the kernel receives.

use std::thread;

use ruster_core::{IfId, MonotonicMillis};
use ruster_io_afpacket::{
    AfPacketIo, AfPacketPlatform, PortConfig, RingGeometry, RxWait, ValidatedConfig,
    DEFAULT_MAX_FRAME_LEN,
};
use ruster_proto::daemon;

use crate::{if_index, Backend};

/// Room for the kernel's per-frame header and the largest frame.
const FRAME_SIZE: u32 = 2_048;
const BLOCK_SIZE: u32 = 65_536;
/// Kick-and-reap rounds per drain call.
const DRAIN_ROUNDS: u32 = 8;

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

pub fn open(devices: &[String]) -> Result<AfPacketIo, String> {
    let mut ports = Vec::with_capacity(devices.len());
    for (index, device) in devices.iter().enumerate() {
        let interface = u16::try_from(index)
            .map(IfId)
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

/// Waiting for AF_PACKET input between steps.
pub struct Waiter {
    /// How long to wait for input while idle, up to [`crate::IDLE_LONGEST_MS`].
    idle: daemon::Idle,
    /// The last wait said ready, and the step after it found nothing.
    ready_unused: bool,
}

impl Default for Waiter {
    fn default() -> Self {
        Self {
            idle: daemon::Idle::up_to(crate::IDLE_LONGEST_MS),
            ready_unused: false,
        }
    }
}

impl Backend<AfPacketIo> for Waiter {
    fn set_clock(&mut self, io: &mut AfPacketIo, now: MonotonicMillis) {
        io.set_clock(now);
    }

    fn after_step(&mut self, io: &mut AfPacketIo, busy: bool) -> Result<(), String> {
        if io.is_stopped() {
            return Err("the packet backend stopped".into());
        }
        if busy {
            self.ready_unused = false;
            self.idle.after(true);
        } else if self.ready_unused {
            // A readiness RX cannot consume (a socket condition): sleep, do not spin.
            self.ready_unused = false;
            thread::sleep(daemon::IDLE_MAX);
        } else {
            let woke = io
                .wait_rx(self.idle.after(false).unwrap_or(1))
                .map_err(|error| format!("waiting for packets: {error:?}"))?;
            self.ready_unused = woke == RxWait::Ready;
        }
        Ok(())
    }

    fn drain(&mut self, io: &mut AfPacketIo) -> bool {
        io.drain(DRAIN_ROUNDS).is_drained()
    }
}
