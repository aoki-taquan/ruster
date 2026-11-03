//! AP3 live scheduling of the AF_PACKET engine: TX completion reaping and
//! kick retry, the idle `poll` wait, kernel statistics, live stats, the
//! publication quiescence check, and the shutdown drain.
//!
//! # TX completion scheduling
//!
//! The AP2 `PacketIo` of the engine never reaps TX completions. The live
//! entry points (`live_receive`, `live_begin_generated`, `quiescence_check`,
//! `drain`) first *settle* ports: a bounded FIFO completion scan of every
//! in-flight frame (at most `tx_frame_count` status reads per port, each an
//! Acquire load, O(1) per reclaimed frame), then the owed kick.
//!
//! A port owes a kick when its last kick failed, or when a settle finds the
//! oldest in-flight frame still SEND_REQUEST: the kernel has not taken it.
//! Linux `tpacket_snd` sets a frame back to SEND_REQUEST and returns success
//! when it cannot allocate an skb under `MSG_DONTWAIT` after sending earlier
//! frames, and it leaves frames SEND_REQUEST on `ENOBUFS`, `EAGAIN`, or a
//! down link. The first kick of a batch (`finish`) is always attempted. An
//! owed *retry* is attempted at a settle only once the loop's clock (handed
//! in with `set_clock`, never read here) has reached the port's retry time;
//! each retry pushes that time out by a backoff that starts at 1 ms and
//! doubles up to [`KICK_BACKOFF_MAX_MS`], and any reclaimed frame resets the
//! backoff and makes the next retry due at once. A down link is therefore
//! kicked at most about 16 times per second instead of at every tick. Until
//! the first `set_clock` there is no clock to pace by, so every settle
//! retries an owed kick (the AF_XDP adapter behaves the same way). The
//! drain ignores the backoff.
//!
//! Kick errnos are classified once: `EAGAIN`, `ENOBUFS`, `EINTR`, `EBUSY`
//! defer and `ENETDOWN` means the link is down; neither is a batch error,
//! both leave the kick owed. `ENXIO` means the bound device was unregistered
//! (`tpacket_snd` finds no device for the bound ifindex): that is permanent,
//! so it is a batch error, the port is marked `unbound`, and its owed kick
//! is never retried (a restart must reopen the port). Any other errno is a
//! fault: the first one of a batch is its `error`, and it is owed and
//! retried with the backoff. Published frames stay in flight in every
//! case.
//!
//! A completion scan that finds an impossible status or ownership is an
//! invariant violation: the engine stops for good (fail closed), the call
//! that found it reports it once, and every later call reports `Stopped`.
//!
//! # Idle wait
//!
//! `wait_rx` returns at once when any port has RX work the cursor can take
//! (a block in validation or delivery, or a USER head block: one Acquire
//! load per port, no budget accounting); otherwise it blocks in one
//! `poll(2)` with `POLLIN` over every port's socket, kept in a fixed
//! `pollfd` array allocated at open. TPACKET_V3 makes a block visible only
//! when it is full or its retire timer fires, so an idle router sees a lone
//! frame up to the RX `retire_timeout_ms` after it arrived. A `POLLERR`
//! (the kernel's pending socket error after the bound device went down or
//! away) is read and cleared with `getsockopt(SO_ERROR)` before the wait
//! returns `Ready`; otherwise it would stay set, every later wait would
//! return at once, and the idle wait would degrade to a sleep.
//!
//! Nothing here allocates, locks, or uses a trait object.

use ruster_core::{IfId, MonotonicMillis, PublicationQuiescenceDisposition};

use super::{
    bump, AfPacketEngine, PacketOps, PacketRingResources, TxCompletionError, POLLERR, POLLNVAL,
};
use crate::{
    io_stats::add_faults, AfPacketBackendStats, AfPacketCounters, AfPacketPortStats,
    BackendStatsSnapshot, Errno, PlatformError, RxWait, SyscallStage, TP_STATUS_SEND_REQUEST,
};

/// Upper bound of the owed-kick retry backoff.
pub(crate) const KICK_BACKOFF_MAX_MS: u64 = 64;

const EINTR: i32 = 4;
const ENXIO: i32 = 6;
const EBADF: i32 = 9;
const EAGAIN: i32 = 11;
const EBUSY: i32 = 16;
const ENETDOWN: i32 = 100;
const ENOBUFS: i32 = 105;

/// How a failed kick is treated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KickClass {
    /// The kernel could not take the frames now; retry later.
    Deferred,
    /// The device is down; retry later, link state is not an error.
    LinkDown,
    /// The bound device is gone (`ENXIO`): a batch error, never retried.
    Unbound,
    /// Anything else: reported as the batch error, and retried.
    Fault,
}

impl KickClass {
    pub(crate) const fn of(error: PlatformError) -> Self {
        match error {
            PlatformError::Syscall { errno, .. } => match errno.get() {
                EAGAIN | ENOBUFS | EINTR | EBUSY => Self::Deferred,
                ENETDOWN => Self::LinkDown,
                ENXIO => Self::Unbound,
                _ => Self::Fault,
            },
            _ => Self::Fault,
        }
    }

    /// Whether the failure is reported as a batch error.
    pub(crate) const fn is_error(self) -> bool {
        matches!(self, Self::Unbound | Self::Fault)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KickFailure {
    pub(crate) error: PlatformError,
    pub(crate) class: KickClass,
}

/// Owed-kick state of one port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KickState {
    pub(crate) owed: bool,
    pub(crate) link_down: bool,
    /// The bound device is gone; no retry is attempted any more.
    pub(crate) unbound: bool,
    pub(crate) retry_at_ms: u64,
    pub(crate) backoff_ms: u64,
}

impl KickState {
    pub(crate) const fn new() -> Self {
        Self {
            owed: false,
            link_down: false,
            unbound: false,
            retry_at_ms: 0,
            backoff_ms: 1,
        }
    }
}

/// Why the engine performs no more packet I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StopCause {
    /// A completion scan found an invariant violation on `interface`.
    Completion {
        interface: IfId,
        error: TxCompletionError,
    },
}

/// Outcome of one bounded shutdown drain call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AfPacketDrain {
    /// Frames the kernel still holds (published, not handed back).
    pub tx_in_flight: u64,
    /// Ports that still owe a kick.
    pub kick_owed_ports: u32,
}

impl AfPacketDrain {
    /// Whether every published frame came back.
    #[must_use]
    pub const fn is_drained(&self) -> bool {
        self.tx_in_flight == 0
    }
}

/// Why a publication cannot be applied now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AfPacketQuiescenceError {
    /// Published frames still embed the current publication's authority.
    /// Packet I/O may continue under the current publication.
    TxInFlight { frames: u64 },
    /// The backend was drained or stopped by a fault.
    Stopped,
}

impl AfPacketQuiescenceError {
    /// The core disposition of this error.
    #[must_use]
    pub const fn disposition(self) -> PublicationQuiescenceDisposition {
        match self {
            Self::TxInFlight { .. } => PublicationQuiescenceDisposition::ContinueOldIo,
            Self::Stopped => PublicationQuiescenceDisposition::Stop,
        }
    }
}

impl<O: PacketOps> PacketRingResources<O> {
    /// One nonblocking kick with errno classification and kick state.
    pub(super) fn kick_classified(&mut self, now: u64, retry: bool) -> Result<(), KickFailure> {
        if retry {
            bump(&mut self.counters.kick_retries);
        }
        match self.kick_tx() {
            Ok(()) => {
                bump(&mut self.counters.kicks);
                self.kick.owed = false;
                self.kick.link_down = false;
                Ok(())
            }
            Err(error) => {
                let class = KickClass::of(error);
                // Only `ENETDOWN` means the link is down (OPS-EXIT).
                self.kick.link_down = class == KickClass::LinkDown;
                match class {
                    KickClass::Deferred => bump(&mut self.counters.kicks_deferred),
                    KickClass::LinkDown => {
                        bump(&mut self.counters.kicks_link_down);
                        self.kick.link_down = true;
                    }
                    KickClass::Unbound => {
                        bump(&mut self.counters.kicks_unbound);
                        bump(&mut self.counters.kick_errors);
                        self.kick.unbound = true;
                    }
                    KickClass::Fault => bump(&mut self.counters.kick_errors),
                }
                self.kick.owed = true;
                self.kick.retry_at_ms = now.saturating_add(self.kick.backoff_ms);
                Err(KickFailure { error, class })
            }
        }
    }

    /// Reaps completions, detects frames the kernel has not taken, and
    /// retries an owed kick when due (or `force`). An unbound port is never
    /// retried.
    fn settle(&mut self, now: u64, force: bool) -> Result<(), TxCompletionError> {
        if self.tx_state.in_flight == 0 {
            self.kick.owed = false;
            self.kick.backoff_ms = 1;
            return Ok(());
        }
        let frames = self.tx_frame_count();
        let report = self.tx_scan_completions(frames)?;
        if report.reclaimed != 0 {
            // Progress: the kernel is taking frames again (so the link is
            // not down).
            self.kick.backoff_ms = 1;
            self.kick.retry_at_ms = now;
            self.kick.link_down = false;
        }
        if self.tx_state.in_flight == 0 {
            self.kick.owed = false;
            return Ok(());
        }
        let head = self
            .load_tx_status(self.tx_state.completion_head)
            .map_err(TxCompletionError::Mapping)?;
        if head == TP_STATUS_SEND_REQUEST {
            self.kick.owed = true;
        }
        if self.kick.owed && !self.kick.unbound {
            if force || now >= self.kick.retry_at_ms {
                let _ = self.kick_classified(now, true);
                self.kick.retry_at_ms = now.saturating_add(self.kick.backoff_ms);
                self.kick.backoff_ms = (self.kick.backoff_ms * 2).min(KICK_BACKOFF_MAX_MS);
            } else {
                bump(&mut self.counters.kick_retries_suppressed);
            }
        }
        Ok(())
    }

    fn port_stats(&self) -> AfPacketPortStats {
        AfPacketPortStats {
            interface: self.interface,
            if_index: self.if_index,
            max_frame: u32::try_from(self.max_frame_len).unwrap_or(u32::MAX),
            rx_blocks: u32::try_from(self.rx.block_count()).unwrap_or(u32::MAX),
            tx_frames: u32::try_from(self.tx_frame_count()).unwrap_or(u32::MAX),
            tx_inflight: u32::try_from(self.tx_state.in_flight).unwrap_or(u32::MAX),
            rx_halted: self.rx_sticky_halt().is_some(),
            kick_owed: self.kick.owed,
            link_down: self.kick.link_down,
            tx_held_on_down_link: if self.kick.link_down {
                u32::try_from(self.tx_state.in_flight).unwrap_or(u32::MAX)
            } else {
                0
            },
            unbound: self.kick.unbound,
            faults: self.rx_stats(),
            counters: self.counters,
        }
    }
}

impl<O: PacketOps> AfPacketEngine<O> {
    /// Hands the engine the loop's clock reading (cold boundary).
    pub(crate) fn set_clock(&mut self, now: MonotonicMillis) {
        self.now_ms = now.0;
        self.clock_set = true;
    }

    /// Whether the engine stopped for good (drained or faulted).
    pub(crate) const fn is_stopped(&self) -> bool {
        self.draining || self.stopped.is_some()
    }

    fn stop_on(
        &mut self,
        port: usize,
        error: TxCompletionError,
    ) -> super::packet_io::AfPacketIoError {
        let interface = self.ports[port].interface;
        if self.stopped.is_none() {
            self.stopped = Some(StopCause::Completion { interface, error });
        }
        super::packet_io::AfPacketIoError::Completion { interface, error }
    }

    /// Settles one port; a completion fault stops the engine.
    pub(crate) fn settle_port(
        &mut self,
        port: usize,
        force: bool,
    ) -> Result<(), super::packet_io::AfPacketIoError> {
        let now = self.now_ms;
        // Without a clock there is nothing to pace retries by: every settle
        // retries an owed kick.
        let force = force || !self.clock_set;
        match self.ports[port].settle(now, force) {
            Ok(()) => Ok(()),
            Err(error) => Err(self.stop_on(port, error)),
        }
    }

    /// Settles every port in order; stops at the first completion fault.
    pub(crate) fn settle_all(
        &mut self,
        force: bool,
    ) -> Result<(), super::packet_io::AfPacketIoError> {
        for port in 0..self.ports.len() {
            self.settle_port(port, force)?;
        }
        Ok(())
    }

    /// `receive` behind the live adapter: refuses I/O once stopped, settles
    /// every port, then opens the AP2 batch.
    pub(crate) fn live_receive(
        &mut self,
        budget: usize,
    ) -> Result<super::packet_io::AfPacketBatch<'_, O>, super::packet_io::AfPacketIoError> {
        if self.is_stopped() {
            return Err(super::packet_io::AfPacketIoError::Stopped);
        }
        self.settle_all(false)?;
        ruster_core::PacketIo::receive(self, budget)
    }

    /// Frames published and not yet handed back, over every port.
    pub(crate) fn tx_in_flight(&self) -> u64 {
        self.ports
            .iter()
            .map(|port| port.tx_state.in_flight as u64)
            .sum()
    }

    /// Whether TX is in flight or a kick is owed: work only a later settle
    /// completes.
    pub(crate) fn tx_outstanding(&self) -> bool {
        self.ports
            .iter()
            .any(|port| port.tx_state.in_flight != 0 || port.kick.owed)
    }

    /// The publication quiescence check: no batch or lease can be open
    /// (`&mut self`), so after settling every port only in-flight TX can
    /// still carry the current publication's authority. A port whose link
    /// is down does not block (OPS-EXIT): `tpacket_snd` leaves every frame
    /// SEND_REQUEST while the device is down, so waiting would block every
    /// publication for as long as the link stays down. A port the last
    /// kick saw down is confirmed with one fresh kick (outside the
    /// backoff): only `ENETDOWN` lets its frames pass; any other outcome
    /// clears `link_down` and they block. The frames stay in flight (sent
    /// or reported by the drain as before; gauge `tx_held_on_down_link`).
    pub(crate) fn quiescence_check(&mut self) -> Result<(), AfPacketQuiescenceError> {
        if self.is_stopped() {
            return Err(AfPacketQuiescenceError::Stopped);
        }
        if self.settle_all(false).is_err() {
            return Err(AfPacketQuiescenceError::Stopped);
        }
        let now = self.now_ms;
        let mut frames: u64 = 0;
        for port in self.ports.iter_mut() {
            if port.tx_state.in_flight == 0 {
                continue;
            }
            let held = port.kick.link_down
                && !port.kick.unbound
                && matches!(
                    port.kick_classified(now, true),
                    Err(KickFailure {
                        class: KickClass::LinkDown,
                        ..
                    })
                );
            if !held {
                frames += port.tx_state.in_flight as u64;
            }
        }
        if frames != 0 {
            return Err(AfPacketQuiescenceError::TxInFlight { frames });
        }
        Ok(())
    }

    pub(crate) const fn io_disposition(&self) -> PublicationQuiescenceDisposition {
        if self.is_stopped() {
            PublicationQuiescenceDisposition::Stop
        } else {
            PublicationQuiescenceDisposition::ContinueOldIo
        }
    }

    /// One bounded shutdown drain call: stops RX and new TX for good, then
    /// settles every port at most `rounds` times, kicking owed ports without
    /// backoff, until no frame is in flight. A port stopped by a completion
    /// fault is not scanned again.
    pub(crate) fn drain(&mut self, rounds: u32) -> AfPacketDrain {
        self.draining = true;
        for _ in 0..rounds {
            if self.tx_in_flight() == 0 {
                break;
            }
            if self.stopped.is_some() {
                break;
            }
            let _ = self.settle_all(true);
        }
        AfPacketDrain {
            tx_in_flight: self.tx_in_flight(),
            kick_owed_ports: u32::try_from(self.ports.iter().filter(|port| port.kick.owed).count())
                .unwrap_or(u32::MAX),
        }
    }

    /// The idle wait: `Ready` at once while any port has RX work, otherwise
    /// one `poll(2)` over every port's socket.
    pub(crate) fn wait_rx(&mut self, timeout_ms: u32) -> Result<RxWait, PlatformError> {
        if self.is_stopped() {
            return Ok(RxWait::Ready);
        }
        for port in self.ports.iter_mut() {
            if port.rx_ready() {
                return Ok(RxWait::Ready);
            }
        }
        for entry in self.poll_fds.iter_mut() {
            entry.revents = 0;
        }
        let timeout = i32::try_from(timeout_ms).unwrap_or(i32::MAX);
        let ops = &mut self.ports[0].socket.ops;
        match ops.poll(&mut self.poll_fds, timeout) {
            Ok(0) => Ok(RxWait::TimedOut),
            Ok(_) => {
                if self
                    .poll_fds
                    .iter()
                    .any(|entry| entry.revents & POLLNVAL != 0)
                {
                    return Err(PlatformError::Syscall {
                        stage: SyscallStage::Poll,
                        errno: Errno::new(EBADF),
                    });
                }
                // A pending socket error (`sk_err`: the kernel sets it when
                // the bound device goes down or is unregistered) keeps
                // `POLLERR` set until it is read, since the ring is never
                // `recv`ed: read and clear it here (cold, at most one
                // `getsockopt` per port and wait), so the next wait can
                // block again instead of degrading to a sleep.
                for (port, entry) in self.ports.iter_mut().zip(self.poll_fds.iter()) {
                    if entry.revents & POLLERR != 0 {
                        let fd = port.socket.fd;
                        match port.socket.ops.take_socket_error(fd) {
                            Ok(_) => bump(&mut port.counters.socket_errors),
                            Err(_) => bump(&mut port.counters.socket_error_reads_failed),
                        }
                    }
                }
                // POLLERR/POLLHUP also end the wait; the next tick observes
                // the socket. A readiness that RX cannot consume is turned
                // into a plain sleep by the caller.
                Ok(RxWait::Ready)
            }
            Err(PlatformError::Syscall {
                stage: SyscallStage::Poll,
                errno,
            }) if errno.get() == EINTR => Ok(RxWait::Interrupted),
            Err(error) => Err(error),
        }
    }

    /// Reads (and thereby resets) the kernel's `PACKET_STATISTICS` of every
    /// port and folds them into the cumulative counters. Cold path only.
    pub(crate) fn refresh_kernel_stats(&mut self) -> Result<(), PlatformError> {
        let mut first = None;
        for port in self.ports.iter_mut() {
            let fd = port.socket.fd;
            match port.socket.ops.packet_statistics(fd) {
                Ok(stats) => {
                    let counters = &mut port.counters;
                    counters.kernel_packets = counters
                        .kernel_packets
                        .saturating_add(u64::from(stats.tp_packets));
                    counters.kernel_drops = counters
                        .kernel_drops
                        .saturating_add(u64::from(stats.tp_drops));
                    counters.kernel_freeze_q = counters
                        .kernel_freeze_q
                        .saturating_add(u64::from(stats.tp_freeze_q_cnt));
                }
                Err(error) => {
                    bump(&mut port.counters.kernel_stats_errors);
                    first.get_or_insert(error);
                }
            }
        }
        first.map_or(Ok(()), Err)
    }

    pub(crate) fn port_stats(&self, interface: IfId) -> Option<AfPacketPortStats> {
        let index = self.table.lookup(interface)?.get();
        Some(self.ports[index].port_stats())
    }

    pub(crate) fn backend_stats(&self) -> AfPacketBackendStats {
        let mut stats = AfPacketBackendStats {
            ports: u32::try_from(self.ports.len()).unwrap_or(u32::MAX),
            tx_inflight: 0,
            rx_halted_ports: 0,
            kick_owed_ports: 0,
            link_down_ports: 0,
            tx_held_on_down_link: 0,
            unbound_ports: 0,
            generated_unknown_egress: self.generated_unknown_egress,
            stopped: self.is_stopped(),
            faults: BackendStatsSnapshot {
                geometry_rejected: 0,
                descriptor_rejected: 0,
                status_rejected: 0,
                ownership_rejected: 0,
                syscall_errors: 0,
                mmap_errors: 0,
            },
            counters: AfPacketCounters::default(),
        };
        for port in self.ports.iter() {
            let port = port.port_stats();
            stats.tx_inflight += u64::from(port.tx_inflight);
            stats.rx_halted_ports += u32::from(port.rx_halted);
            stats.kick_owed_ports += u32::from(port.kick_owed);
            stats.link_down_ports += u32::from(port.link_down);
            stats.tx_held_on_down_link += u64::from(port.tx_held_on_down_link);
            stats.unbound_ports += u32::from(port.unbound);
            stats.faults = add_faults(stats.faults, port.faults);
            stats.counters.accumulate(&port.counters);
        }
        stats
    }
}

#[cfg(test)]
mod tests;
