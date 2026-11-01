//! Core-facing AF_XDP adapter (M2 S6, X04a).
//!
//! [`XdpPacketIo`] implements `ruster-core`'s [`PacketIo`],
//! [`GeneratedPacketIo`], [`PublicationQuiescence`], and [`BackendStats`]
//! over one [`RxFillEngine`] per interface with static dispatch only: the
//! adapter, its batches, and its slots are concrete types, and nothing on
//! the packet path locks, allocates, clones a packet, formats a string, or
//! calls through a trait object.
//!
//! # Multi-port mapping
//!
//! M2 binds one AF_XDP socket (one engine, one UMEM) per interface and
//! queue. The ports are passed once to [`XdpPacketIo::new`], which refuses
//! an empty set and a duplicate `IfId` and sorts them by `IfId` into a
//! boxed slice that never changes afterwards. TX egress selection is a
//! binary search of that fixed slice (`O(log ports)`, no map, no string).
//!
//! # RX merge
//!
//! [`PacketIo::receive`] polls every port once, starting from a port that
//! rotates by one per batch so no port is always served last. Each poll
//! reaps that port's completions, refills its Fill ring, and validates at
//! most the budget left by the ports before it; ports after the budget is
//! used up are still polled with a zero budget, which reaps and refills
//! only. The batch then lends the validated frames port by port in the
//! same order. Frames left unlent when a batch ends stay pending in their
//! engine and are lent by a later batch before new descriptors are read.
//!
//! # TX
//!
//! A forwarded frame committed to its ingress port is transmitted in place
//! from the same UMEM frame (same-frame TX, no copy). A frame committed to
//! another port cannot be: each port has its own UMEM, and a descriptor can
//! only name a frame of the socket's own UMEM (shared-UMEM zero copy across
//! interfaces is deferred, XDP-136). The adapter therefore copies it: it
//! allocates a generated frame of the egress engine, copies the exact
//! visible bytes once (`len` bytes, no zeroing first, because every byte is
//! overwritten at once), commits that frame on the egress TX ring, and
//! recycles the RX frame on the ingress port. The cost is one
//! `memcpy` of the frame per cross-port packet plus one generated frame of
//! the egress pool while it is in flight; it is counted as
//! `cross_port_copies` on the egress port. An empty egress generated pool
//! refuses the commit (`cross_port_copy_unavailable`), never blocks.
//!
//! Every TX (forwarded or generated) is bounded by the egress port's MTU
//! plus the 14-byte Ethernet header ([`XdpPortConfig::max_frame_len`]): a
//! longer frame is refused before any descriptor is written
//! (`tx_over_mtu`, `generated_over_mtu`). Linux copy-mode transmit may
//! otherwise consume an over-MTU descriptor without completing it (#299
//! review), leaving the frame `TxOwnedByKernel` forever. The MTU is read
//! once at session open; a later MTU change is not seen (X04b).
//!
//! # Error mapping
//!
//! - `TxBlocked` (`RingFull`, `InflightLimit`, `Draining`) is core
//!   back-pressure: the slot counts as `tx_rejected` (generated:
//!   `rejected`), the handoff is cancelled back to its pool, and `finish`
//!   reports no error. It is counted per port (`tx_blocked`,
//!   `generated_tx_blocked`).
//! - An unknown egress, an over-MTU frame, and an empty egress pool for a
//!   cross-port copy are rejections without an error, like back-pressure.
//! - [`GeneratedAllocError`] maps to [`GeneratedAllocationError`]:
//!   `Unavailable` → `Unavailable`; `Rejected(ZeroLength)` → `ZeroLength`;
//!   `Rejected(TooLarge)` and a length above the egress MTU bound →
//!   `FrameTooLarge`; `Rejected(BelowMinimum)` (1 to 13 bytes) →
//!   `FrameTooLarge`, the nearest core variant: core has no "too short"
//!   variant, its generators never ask for less than an Ethernet header,
//!   and the runtime treats both as the same fatal build failure, so no
//!   core change is needed to keep the outcome exact;
//!   `Rejected(Draining)` → `Unavailable` plus [`XdpIoError::Stopped`] at
//!   `finish` (a drained adapter also reports
//!   [`PublicationQuiescenceDisposition::Stop`], so the runtime never
//!   reaches it); `Ledger` → `Unavailable` plus
//!   [`XdpIoError::GeneratedLedger`] at `finish`.
//! - A corrupt ring cursor or a ledger refusal of the adapter's own
//!   handoff is a fault: it is reported once as the batch error and makes
//!   the adapter stop ([`PublicationQuiescenceDisposition::Stop`]) for
//!   good. A failed wakeup kick is reported as the batch error and is not
//!   sticky: the published descriptors stay in flight.
//!
//! # Kicks
//!
//! `finish` (or dropping a batch) kicks TX once per port that accepted a
//! frame in that batch, unless the kernel's need-wakeup flag says it is not
//! needed (copy mode keeps it set: Linux transmits only from `sendto`).
//! `receive` answers a Fill need-wakeup request with a non-sleeping `poll`
//! kick on that port.
//!
//! # Quiescence
//!
//! Batches borrow the adapter mutably, so no batch is open whenever
//! [`PublicationQuiescence::try_publication_quiescence`] can be called. It
//! first reaps every port's completions (bounded by the TX capacity), then
//! requires, for every port: no lent frame of either pool (a forgotten
//! lease is reclaimed by the batch that lent it, so this is defensive), no
//! staged handoff, and no TX in flight. In-flight TX still carries bytes
//! rewritten under the active publication, so it defers the publication
//! but lets old I/O continue ([`PublicationQuiescenceDisposition::ContinueOldIo`]);
//! the next batch reaps it. RX frames validated but not yet lent carry no
//! publication authority and do not block. A drained or faulted adapter
//! is [`PublicationQuiescenceDisposition::Stop`].

use std::fmt;

use ruster_core::{
    BackendMode, BackendStats, BatchCompletion, FieldValue, FieldVisitor, GeneratedAllocationError,
    GeneratedBatchCompletion, GeneratedPacketBatch, GeneratedPacketIo, GeneratedPacketLease,
    GeneratedPacketSlot, GeneratedSlotCompletion, IfId, ObservableFields, PacketBatch, PacketIo,
    PacketLease, PacketSlot, PublicationQuiescence, PublicationQuiescenceDisposition,
    PublicationQuiescenceGuard, SlotCompletion,
};
use ruster_io_xdp::LedgerError;

use crate::{
    rx_fill::{RawLease, ZeroFill},
    DrainOutcome, GeneratedAllocError, GeneratedRejectReason, KickError, NeedWakeup,
    NegotiatedMode, RxFillEngine, RxFillError, RxInvalidReason, TxRejection, ETHERNET_HEADER_LEN,
};

/// Static facts of one port: its interface, its socket's queue and
/// negotiated mode, and the device MTU.
///
/// Build it from the session before taking its datapath:
/// `XdpPortConfig::new(interface, session.queue(), session.mode(),
/// session.mtu())`. The MTU is read once by `NativeSession::open` from
/// sysfs and bounds every TX on this port to `mtu + 14` bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XdpPortConfig {
    interface: IfId,
    queue: u32,
    mode: NegotiatedMode,
    mtu: u32,
}

impl XdpPortConfig {
    #[must_use]
    pub const fn new(interface: IfId, queue: u32, mode: NegotiatedMode, mtu: u32) -> Self {
        Self {
            interface,
            queue,
            mode,
            mtu,
        }
    }

    #[must_use]
    pub const fn interface(self) -> IfId {
        self.interface
    }

    #[must_use]
    pub const fn queue(self) -> u32 {
        self.queue
    }

    #[must_use]
    pub const fn mode(self) -> NegotiatedMode {
        self.mode
    }

    #[must_use]
    pub const fn mtu(self) -> u32 {
        self.mtu
    }

    /// The longest frame this port transmits: `mtu` plus the 14-byte
    /// Ethernet header (no VLAN tag: VLAN is out of the M2 profile).
    #[must_use]
    pub const fn max_frame_len(self) -> u32 {
        self.mtu.saturating_add(ETHERNET_HEADER_LEN)
    }
}

/// One port handed to [`XdpPacketIo::new`]: its static facts and its
/// engine.
pub struct XdpPort<'memory> {
    config: XdpPortConfig,
    engine: RxFillEngine<'memory>,
}

impl<'memory> XdpPort<'memory> {
    #[must_use]
    pub const fn new(config: XdpPortConfig, engine: RxFillEngine<'memory>) -> Self {
        Self { config, engine }
    }
}

impl fmt::Debug for XdpPort<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XdpPort")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Why [`XdpPacketIo::new`] refused its ports. The engines are dropped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpPacketIoSetupError {
    /// No port was given.
    NoPorts,
    /// Two ports name the same interface.
    DuplicateInterface(IfId),
    /// A port's engine already started draining.
    EngineDraining(IfId),
    /// A port's MTU leaves no room for an Ethernet payload (zero).
    ZeroMtu(IfId),
}

impl fmt::Display for XdpPacketIoSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for XdpPacketIoSetupError {}

/// The first failure of one batch, or why `receive` refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpIoError {
    /// The adapter was drained or stopped by an earlier fault: no I/O.
    Stopped,
    /// A ring cursor was corrupt or the ledger refused an engine operation
    /// on `interface`. The adapter stops.
    Datapath { interface: IfId, error: RxFillError },
    /// The engine of `interface` refused the adapter's own TX handoff for a
    /// reason other than back-pressure (a corrupt TX ring or a ledger
    /// refusal). The frame was reclaimed. The adapter stops.
    Submit {
        interface: IfId,
        rejection: TxRejection,
    },
    /// A generated free-list entry of `interface` was not a free frame of
    /// its ledger (an engine invariant failure that `audit` also reports).
    /// The allocation failed as `Unavailable`.
    GeneratedLedger { interface: IfId, error: LedgerError },
    /// A TX or Fill wakeup failed. Published descriptors stay in flight.
    Kick { interface: IfId, error: KickError },
    /// A generated session named an interface without a port.
    UnknownEgress(IfId),
}

impl fmt::Display for XdpIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for XdpIoError {}

/// Why a publication cannot be applied now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpQuiescenceError {
    /// The adapter was drained or stopped by a fault.
    Stopped,
    /// Reaping completions of `interface` failed; the adapter stops.
    Datapath { interface: IfId, error: RxFillError },
    /// A frame of `interface` is still lent.
    LeaseOutstanding { interface: IfId, frames: u32 },
    /// A TX handoff of `interface` is staged but neither submitted nor
    /// cancelled.
    HandoffOutstanding { interface: IfId, frames: u32 },
    /// `frames` published TX frames of `interface` are not completed yet.
    TxInFlight { interface: IfId, frames: u32 },
}

impl fmt::Display for XdpQuiescenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for XdpQuiescenceError {}

/// Adapter-level per-port counters (the engine counts the rest).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct XdpAdapterCounters {
    /// Forwarded frames transmitted in place from their RX frame (egress
    /// is the ingress port).
    pub forwarded_in_place: u64,
    /// Forwarded frames from another port copied into a generated frame of
    /// this (egress) port and transmitted.
    pub cross_port_copies: u64,
    /// Cross-port commits refused because this port's generated pool was
    /// empty.
    pub cross_port_copy_unavailable: u64,
    /// Forwarded frames refused for this egress because they exceed
    /// `mtu + 14`.
    pub tx_over_mtu: u64,
    /// Forwarded frames refused for this egress by TX back-pressure.
    pub tx_blocked: u64,
    /// Frames received on this port and committed to an interface without
    /// a port.
    pub tx_unknown_egress: u64,
    /// Generated allocations refused for exceeding `mtu + 14`.
    pub generated_over_mtu: u64,
    /// Generated commits refused by TX back-pressure.
    pub generated_tx_blocked: u64,
    /// Lent frames whose lease was forgotten (`mem::forget`) and that the
    /// batch reclaimed.
    pub leases_reclaimed: u64,
}

struct PortState<'memory> {
    config: XdpPortConfig,
    /// `min(config.max_frame_len(), engine frame capacity)`.
    max_frame: u32,
    engine: RxFillEngine<'memory>,
    /// Frames the current RX batch may still lend from this port.
    lendable: u32,
    /// Whether the current batch published TX on this port.
    tx_touched: bool,
    counters: XdpAdapterCounters,
}

impl PortState<'_> {
    /// Kicks TX once if this batch published here and the kernel did not
    /// say a kick is unnecessary.
    fn kick_tx(&mut self, error: &mut Option<XdpIoError>) {
        if !std::mem::take(&mut self.tx_touched) {
            return;
        }
        if self.engine.tx_needs_wakeup() == Ok(NeedWakeup::NotRequired) {
            return;
        }
        if let Err(kick) = self.engine.wake_tx() {
            error.get_or_insert(XdpIoError::Kick {
                interface: self.config.interface,
                error: kick,
            });
        }
    }
}

/// Why the adapter stopped for good.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stop {
    Drained,
    Fault,
}

/// AF_XDP backend for `ruster-core` over one engine per interface.
///
/// `!Send` and `!Sync` like its engines: one worker owns every port.
///
/// ```compile_fail,E0277
/// fn send<T: Send>() {}
/// send::<ruster_io_xdp_native::XdpPacketIo<'static>>();
/// ```
pub struct XdpPacketIo<'memory> {
    ports: Box<[PortState<'memory>]>,
    rx_start: usize,
    stop: Option<Stop>,
    #[cfg(test)]
    test: test_hooks::TestHooks,
}

impl<'memory> XdpPacketIo<'memory> {
    /// Fixes the `IfId` → port mapping for the adapter's lifetime.
    ///
    /// The ports are sorted by `IfId`; RX visits them in that order (with a
    /// rotating start) and TX finds the egress by binary search. Cold: one
    /// allocation of the port slice.
    pub fn new(
        ports: impl IntoIterator<Item = XdpPort<'memory>>,
    ) -> Result<Self, XdpPacketIoSetupError> {
        let mut states: Vec<PortState<'memory>> = Vec::new();
        for port in ports {
            let interface = port.config.interface;
            if port.config.mtu == 0 {
                return Err(XdpPacketIoSetupError::ZeroMtu(interface));
            }
            if port.engine.is_draining() {
                return Err(XdpPacketIoSetupError::EngineDraining(interface));
            }
            let max_frame = port
                .config
                .max_frame_len()
                .min(port.engine.generated_max_len());
            states.push(PortState {
                config: port.config,
                max_frame,
                engine: port.engine,
                lendable: 0,
                tx_touched: false,
                counters: XdpAdapterCounters::default(),
            });
        }
        if states.is_empty() {
            return Err(XdpPacketIoSetupError::NoPorts);
        }
        states.sort_by_key(|port| port.config.interface);
        if let Some(pair) = states
            .windows(2)
            .find(|pair| pair[0].config.interface == pair[1].config.interface)
        {
            return Err(XdpPacketIoSetupError::DuplicateInterface(
                pair[0].config.interface,
            ));
        }
        Ok(Self {
            ports: states.into_boxed_slice(),
            rx_start: 0,
            stop: None,
            #[cfg(test)]
            test: test_hooks::TestHooks::default(),
        })
    }

    /// Number of ports.
    #[must_use]
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// The interface of every port, in the fixed (sorted) order.
    pub fn interfaces(&self) -> impl Iterator<Item = IfId> + '_ {
        self.ports.iter().map(|port| port.config.interface)
    }

    /// The engine of `interface`, read-only (audit, accounting).
    #[must_use]
    pub fn engine(&self, interface: IfId) -> Option<&RxFillEngine<'memory>> {
        self.port_index(interface)
            .map(|index| &self.ports[index].engine)
    }

    /// The static facts of `interface`'s port.
    #[must_use]
    pub fn port_config(&self, interface: IfId) -> Option<XdpPortConfig> {
        self.port_index(interface)
            .map(|index| self.ports[index].config)
    }

    fn port_index(&self, interface: IfId) -> Option<usize> {
        self.ports
            .binary_search_by_key(&interface, |port| port.config.interface)
            .ok()
    }

    fn running(&self) -> Result<(), XdpIoError> {
        match self.stop {
            None => Ok(()),
            Some(_) => Err(XdpIoError::Stopped),
        }
    }

    /// Records a fault and stops the adapter for good.
    fn fault(&mut self, error: XdpIoError) -> XdpIoError {
        if self.stop.is_none() {
            self.stop = Some(Stop::Fault);
        }
        error
    }

    /// Reaps completions (up to the TX capacity) and refills Fill on every
    /// port, outside a batch: for idle ticks, before a drain, and in tests.
    /// Returns the frames reaped.
    pub fn service(&mut self) -> Result<u32, XdpIoError> {
        self.running()?;
        let mut reaped = 0_u32;
        for index in 0..self.ports.len() {
            let port = &mut self.ports[index];
            let interface = port.config.interface;
            let budget = port.engine.tx_inflight_limit();
            let result = port
                .engine
                .reap_completions(budget)
                .and_then(|report| port.engine.refill().map(|_| report.reaped()));
            match result {
                Ok(count) => reaped = reaped.saturating_add(count),
                Err(error) => return Err(self.fault(XdpIoError::Datapath { interface, error })),
            }
        }
        Ok(reaped)
    }

    /// Shutdown drain of every port (see [`RxFillEngine::drain`]): no new
    /// TX or Fill, ever again; unlent RX frames return to their pool; up to
    /// `rounds` rounds of kick-and-reap per port. The adapter stops
    /// ([`PublicationQuiescenceDisposition::Stop`]). Call again until
    /// [`XdpDrainReport::is_drained`] or the caller's own timeout.
    pub fn drain(&mut self, rounds: u32) -> Result<XdpDrainReport, XdpIoError> {
        self.stop = Some(self.stop.unwrap_or(Stop::Drained));
        let mut report = XdpDrainReport::default();
        for port in self.ports.iter_mut() {
            let interface = port.config.interface;
            let drained = port
                .engine
                .drain(rounds)
                .map_err(|error| XdpIoError::Datapath { interface, error })?;
            report.completed = report.completed.saturating_add(drained.completed());
            report.rx_pending_released = report
                .rx_pending_released
                .saturating_add(drained.rx_pending_released());
            if let DrainOutcome::TxInFlight { frames } = drained.outcome() {
                report.tx_in_flight = report.tx_in_flight.saturating_add(frames);
            }
            let accounting = drained.accounting();
            report.fill_in_kernel = report
                .fill_in_kernel
                .saturating_add(accounting.fill_in_kernel);
            if let Some(error) = drained.last_kick_error() {
                report.last_kick_error = Some((interface, error));
            }
        }
        Ok(report)
    }

    /// Per-port stats of `interface` (bounded, allocation-free).
    #[must_use]
    pub fn port_stats(&self, interface: IfId) -> Option<XdpPortStats> {
        self.port_index(interface)
            .map(|index| port_stats(&self.ports[index]))
    }

    /// Ends a forgotten RX lease (its `PacketLease` was leaked): the frame
    /// returns to its pool and is counted, not reported as recycled.
    fn reclaim_rx(&mut self, port: usize, lease: RawLease) {
        let state = &mut self.ports[port];
        bump(&mut state.counters.leases_reclaimed);
        drop(state.engine.resume_rx(lease));
    }

    /// Ends one RX lease without TX.
    fn recycle_rx(&mut self, port: usize, lease: RawLease) {
        self.ports[port].engine.resume_rx(lease).recycle();
    }

    /// Transmits one forwarded frame of port `ingress` on `egress`.
    /// Returns whether a descriptor was published; on refusal every frame
    /// involved is back in its pool.
    fn transmit(
        &mut self,
        ingress: usize,
        lease: RawLease,
        egress: IfId,
        error: &mut Option<XdpIoError>,
    ) -> bool {
        let Some(out) = self.port_index(egress) else {
            bump(&mut self.ports[ingress].counters.tx_unknown_egress);
            #[cfg(test)]
            self.test_rx_event(ingress, &lease, test_hooks::RxEnd::Rejected(egress, None));
            self.recycle_rx(ingress, lease);
            return false;
        };
        if lease.len() > self.ports[out].max_frame {
            bump(&mut self.ports[out].counters.tx_over_mtu);
            #[cfg(test)]
            self.test_rx_event(
                ingress,
                &lease,
                test_hooks::RxEnd::Rejected(egress, Some(out)),
            );
            self.recycle_rx(ingress, lease);
            return false;
        }
        if out == ingress {
            self.transmit_in_place(out, lease, error)
        } else {
            self.transmit_copy(ingress, out, lease, error)
        }
    }

    fn transmit_in_place(
        &mut self,
        port: usize,
        lease: RawLease,
        error: &mut Option<XdpIoError>,
    ) -> bool {
        #[cfg(test)]
        let snapshot = self.test_rx_snapshot(port, &lease);
        let state = &mut self.ports[port];
        let interface = state.config.interface;
        let handoff = state.engine.resume_rx(lease).stage_tx();
        match state.engine.submit_tx(handoff) {
            Ok(_) => {
                state.tx_touched = true;
                bump(&mut state.counters.forwarded_in_place);
                true
            }
            Err(rejected) => {
                let reason = rejected.reason();
                let cancelled = state.engine.cancel_tx_handoff(rejected.into_handoff());
                assert!(cancelled.is_ok(), "the adapter's own handoff cancels");
                if let TxRejection::Blocked(_) = reason {
                    bump(&mut state.counters.tx_blocked);
                } else {
                    let failure = self.fault(XdpIoError::Submit {
                        interface,
                        rejection: reason,
                    });
                    error.get_or_insert(failure);
                }
                #[cfg(test)]
                self.test_rx_rejected(port, snapshot, interface, Some(port));
                false
            }
        }
    }

    fn transmit_copy(
        &mut self,
        ingress: usize,
        out: usize,
        lease: RawLease,
        error: &mut Option<XdpIoError>,
    ) -> bool {
        #[cfg(test)]
        let snapshot = self.test_rx_snapshot(ingress, &lease);
        let [source, target] = self
            .ports
            .get_disjoint_mut([ingress, out])
            .expect("distinct ports in range");
        let interface = target.config.interface;
        let len = lease.len() as usize;
        let mut failure = None;
        let accepted = match target
            .engine
            .allocate_generated_raw(len, ZeroFill::Overwritten)
        {
            Ok(copy) => {
                // Every visible byte is overwritten here, before the lease
                // can end or be observed (the engine skipped zeroing).
                target
                    .engine
                    .lease_bytes_mut(&copy)
                    .copy_from_slice(source.engine.lease_bytes(&lease));
                match target.engine.resume_generated(copy).commit() {
                    Ok(_) => {
                        target.tx_touched = true;
                        bump(&mut target.counters.cross_port_copies);
                        true
                    }
                    Err(rejected) => {
                        let reason = rejected.reason();
                        let cancelled = target.engine.cancel_tx_handoff(rejected.into_handoff());
                        assert!(cancelled.is_ok(), "the adapter's own handoff cancels");
                        if let TxRejection::Blocked(_) = reason {
                            bump(&mut target.counters.tx_blocked);
                        } else {
                            failure = Some(XdpIoError::Submit {
                                interface,
                                rejection: reason,
                            });
                        }
                        false
                    }
                }
            }
            Err(GeneratedAllocError::Unavailable) => {
                bump(&mut target.counters.cross_port_copy_unavailable);
                false
            }
            Err(GeneratedAllocError::Rejected(_)) => {
                // Only `Draining` is reachable (the length is within the MTU
                // bound, itself capped by the frame capacity), and a
                // draining engine belongs to a stopped adapter.
                bump(&mut target.counters.tx_blocked);
                false
            }
            Err(GeneratedAllocError::Ledger(ledger)) => {
                failure = Some(XdpIoError::GeneratedLedger {
                    interface,
                    error: ledger,
                });
                false
            }
        };
        // The source frame's job ended with the copy (or the refusal).
        source.engine.resume_rx(lease).recycle();
        if let Some(failure) = failure {
            let failure = if matches!(failure, XdpIoError::Submit { .. }) {
                self.fault(failure)
            } else {
                failure
            };
            error.get_or_insert(failure);
        }
        #[cfg(test)]
        if !accepted {
            self.test_rx_rejected(ingress, snapshot, interface, Some(out));
        }
        accepted
    }
}

impl fmt::Debug for XdpPacketIo<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XdpPacketIo")
            .field("ports", &self.ports.len())
            .field("stop", &self.stop)
            .finish_non_exhaustive()
    }
}

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

/// Outcome of [`XdpPacketIo::drain`], summed over ports.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpDrainReport {
    /// Completions reaped by this call.
    pub completed: u32,
    /// Validated, unlent RX frames returned to their pools.
    pub rx_pending_released: u32,
    /// Frames the kernel still holds for TX.
    pub tx_in_flight: u32,
    /// Frames the kernel still holds from Fill (released when the socket
    /// closes).
    pub fill_in_kernel: u32,
    /// The last failed kick of this call.
    pub last_kick_error: Option<(IfId, KickError)>,
}

impl XdpDrainReport {
    /// Whether no TX is in flight on any port.
    #[must_use]
    pub const fn is_drained(&self) -> bool {
        self.tx_in_flight == 0
    }
}

// ---------------------------------------------------------------- RX ----

impl<'memory> PacketIo for XdpPacketIo<'memory> {
    type Error = XdpIoError;
    type Batch<'a>
        = XdpRxBatch<'a, 'memory>
    where
        Self: 'a;

    fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
        self.running()?;
        let count = self.ports.len();
        let start = self.rx_start;
        self.rx_start = (start + 1) % count;
        let mut remaining = u32::try_from(budget).unwrap_or(u32::MAX);
        let mut error = None;
        for step in 0..count {
            let port = &mut self.ports[(start + step) % count];
            port.tx_touched = false;
            let interface = port.config.interface;
            let polled = port
                .engine
                .poll(remaining)
                .map(|batch| (batch.remaining(), batch.refill()));
            let (lendable, refill) = match polled {
                Ok(polled) => polled,
                Err(failure) => {
                    for port in self.ports.iter_mut() {
                        port.lendable = 0;
                    }
                    return Err(self.fault(XdpIoError::Datapath {
                        interface,
                        error: failure,
                    }));
                }
            };
            port.lendable = lendable;
            remaining -= lendable;
            if refill.need_wakeup() != Ok(NeedWakeup::NotRequired) {
                if let Err(kick) = port.engine.wake_fill() {
                    error.get_or_insert(XdpIoError::Kick {
                        interface,
                        error: kick,
                    });
                }
            }
        }
        Ok(XdpRxBatch {
            io: self,
            start,
            step: 0,
            outstanding: None,
            tx_requested: 0,
            tx_accepted: 0,
            tx_rejected: 0,
            recycled: 0,
            error,
        })
    }
}

/// One RX batch over every port. Lends one frame at a time.
pub struct XdpRxBatch<'a, 'memory> {
    io: &'a mut XdpPacketIo<'memory>,
    start: usize,
    step: usize,
    /// The lent frame and its port, while a slot is live (or forgotten).
    outstanding: Option<(usize, RawLease)>,
    tx_requested: usize,
    tx_accepted: usize,
    tx_rejected: usize,
    recycled: usize,
    error: Option<XdpIoError>,
}

impl XdpRxBatch<'_, '_> {
    /// Reclaims a lease whose `PacketLease` was forgotten.
    fn reclaim(&mut self) {
        if let Some((port, lease)) = self.outstanding.take() {
            self.io.reclaim_rx(port, lease);
        }
    }

    /// Reclaims, kicks each port that published TX, and returns the error.
    fn settle(&mut self) {
        self.reclaim();
        let count = self.io.ports.len();
        for step in 0..count {
            let port = (self.start + step) % count;
            self.io.ports[port].lendable = 0;
            self.io.ports[port].kick_tx(&mut self.error);
        }
    }

    fn complete(&mut self, port: usize, lease: RawLease, completion: SlotCompletion) {
        match completion {
            SlotCompletion::Transmit(egress) => {
                self.tx_requested += 1;
                if self.io.transmit(port, lease, egress, &mut self.error) {
                    self.tx_accepted += 1;
                } else {
                    self.tx_rejected += 1;
                }
            }
            SlotCompletion::Recycle(_) | SlotCompletion::Consume(_) => {
                #[cfg(test)]
                self.io
                    .test_rx_event(port, &lease, test_hooks::RxEnd::Reclaimed(completion));
                self.recycled += 1;
                self.io.recycle_rx(port, lease);
            }
            SlotCompletion::LeaseAbandoned => {
                #[cfg(test)]
                self.io
                    .test_rx_event(port, &lease, test_hooks::RxEnd::Reclaimed(completion));
                self.recycled += 1;
                drop(self.io.ports[port].engine.resume_rx(lease));
            }
        }
    }
}

impl<'a, 'memory> PacketBatch for XdpRxBatch<'a, 'memory> {
    type Error = XdpIoError;
    type Slot<'s>
        = XdpRxSlot<'s, 'a, 'memory>
    where
        Self: 's;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        self.reclaim();
        let count = self.io.ports.len();
        while self.step < count {
            let port = (self.start + self.step) % count;
            let state = &mut self.io.ports[port];
            if state.lendable > 0 {
                state.lendable -= 1;
                if let Some(lease) = state.engine.lease_pending() {
                    self.outstanding = Some((port, lease));
                    return Some(PacketLease::new(XdpRxSlot { batch: self }));
                }
                state.lendable = 0;
            }
            self.step += 1;
        }
        None
    }

    fn finish(mut self) -> BatchCompletion<Self::Error> {
        self.settle();
        BatchCompletion {
            tx_requested: self.tx_requested,
            tx_accepted: self.tx_accepted,
            tx_rejected: self.tx_rejected,
            recycled: self.recycled,
            error: self.error.take(),
        }
    }
}

impl Drop for XdpRxBatch<'_, '_> {
    fn drop(&mut self) {
        // Idempotent after `finish`: nothing outstanding, nothing touched.
        self.settle();
    }
}

impl fmt::Debug for XdpRxBatch<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XdpRxBatch")
            .field("tx_requested", &self.tx_requested)
            .field("tx_accepted", &self.tx_accepted)
            .field("tx_rejected", &self.tx_rejected)
            .field("recycled", &self.recycled)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// Core's view of one lent RX frame.
pub struct XdpRxSlot<'s, 'a, 'memory> {
    batch: &'s mut XdpRxBatch<'a, 'memory>,
}

impl PacketSlot for XdpRxSlot<'_, '_, '_> {
    fn ingress(&self) -> IfId {
        let (port, _) = self.batch.outstanding.as_ref().expect("live RX slot");
        self.batch.io.ports[*port].config.interface
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        let batch = &mut *self.batch;
        let (port, lease) = batch.outstanding.as_ref().expect("live RX slot");
        batch.io.ports[*port].engine.lease_bytes_mut(lease)
    }

    fn complete(self, completion: SlotCompletion) {
        let (port, lease) = self.batch.outstanding.take().expect("live RX slot");
        self.batch.complete(port, lease, completion);
    }
}

// --------------------------------------------------------- generated ----

impl<'memory> GeneratedPacketIo for XdpPacketIo<'memory> {
    type Error = XdpIoError;
    type Batch<'a>
        = XdpGeneratedBatch<'a, 'memory>
    where
        Self: 'a;

    fn begin_generated(&mut self, egress: IfId) -> Self::Batch<'_> {
        let port = self.port_index(egress);
        let error = match (self.running(), port) {
            (Err(stopped), _) => Some(stopped),
            (Ok(()), None) => Some(XdpIoError::UnknownEgress(egress)),
            (Ok(()), Some(port)) => {
                self.ports[port].tx_touched = false;
                None
            }
        };
        let usable = if error.is_none() { port } else { None };
        #[cfg(test)]
        let allocation_budget = self.test.generated_allocation_budget;
        XdpGeneratedBatch {
            io: self,
            port: usable,
            outstanding: None,
            completion: GeneratedBatchCompletion {
                attempts: 0,
                allocated: 0,
                failed: 0,
                requested: 0,
                cancelled: 0,
                abandoned: 0,
                accepted: 0,
                rejected: 0,
                error,
            },
            #[cfg(test)]
            allocation_budget,
        }
    }
}

/// One generated session for one egress port.
pub struct XdpGeneratedBatch<'a, 'memory> {
    io: &'a mut XdpPacketIo<'memory>,
    /// The egress port; `None` for an unknown egress or a stopped adapter.
    port: Option<usize>,
    outstanding: Option<RawLease>,
    completion: GeneratedBatchCompletion<XdpIoError>,
    #[cfg(test)]
    allocation_budget: Option<usize>,
}

impl XdpGeneratedBatch<'_, '_> {
    fn reclaim(&mut self) {
        if let (Some(port), Some(lease)) = (self.port, self.outstanding.take()) {
            let state = &mut self.io.ports[port];
            bump(&mut state.counters.leases_reclaimed);
            self.completion.abandoned += 1;
            drop(state.engine.resume_generated(lease));
        }
    }

    fn settle(&mut self) {
        self.reclaim();
        if let Some(port) = self.port {
            self.io.ports[port].kick_tx(&mut self.completion.error);
        }
    }

    fn fail(&mut self, error: GeneratedAllocationError) -> GeneratedAllocationError {
        self.completion.failed += 1;
        error
    }

    fn complete(&mut self, lease: RawLease, completion: GeneratedSlotCompletion) {
        let port = self.port.expect("a lease implies a port");
        #[cfg(test)]
        let snapshot = self.io.test_generated_snapshot(port, &lease);
        let state = &mut self.io.ports[port];
        match completion {
            GeneratedSlotCompletion::Transmit => {
                self.completion.requested += 1;
                let interface = state.config.interface;
                match state.engine.resume_generated(lease).commit() {
                    Ok(_) => {
                        state.tx_touched = true;
                        self.completion.accepted += 1;
                    }
                    Err(rejected) => {
                        self.completion.rejected += 1;
                        let reason = rejected.reason();
                        let cancelled = state.engine.cancel_tx_handoff(rejected.into_handoff());
                        assert!(cancelled.is_ok(), "the adapter's own handoff cancels");
                        if let TxRejection::Blocked(_) = reason {
                            bump(&mut state.counters.generated_tx_blocked);
                        } else {
                            let failure = self.io.fault(XdpIoError::Submit {
                                interface,
                                rejection: reason,
                            });
                            self.completion.error.get_or_insert(failure);
                        }
                        #[cfg(test)]
                        self.io.test_generated_rejected(snapshot);
                    }
                }
            }
            GeneratedSlotCompletion::Cancelled => {
                self.completion.cancelled += 1;
                state.engine.resume_generated(lease).cancel();
                #[cfg(test)]
                self.io.test_generated_ended(snapshot, completion);
            }
            GeneratedSlotCompletion::Abandoned => {
                self.completion.abandoned += 1;
                drop(state.engine.resume_generated(lease));
                #[cfg(test)]
                self.io.test_generated_ended(snapshot, completion);
            }
        }
    }
}

impl<'a, 'memory> GeneratedPacketBatch for XdpGeneratedBatch<'a, 'memory> {
    type Error = XdpIoError;
    type Slot<'s>
        = XdpGeneratedSlot<'s, 'a, 'memory>
    where
        Self: 's;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        self.reclaim();
        self.completion.attempts += 1;
        let Some(port) = self.port else {
            return Err(self.fail(GeneratedAllocationError::Unavailable));
        };
        #[cfg(test)]
        if let Some(budget) = self.allocation_budget.as_mut() {
            if frame_len != 0 && frame_len <= self.io.ports[port].max_frame as usize {
                if *budget == 0 {
                    return Err(self.fail(GeneratedAllocationError::Unavailable));
                }
                *budget -= 1;
            }
        }
        let state = &mut self.io.ports[port];
        if frame_len > state.max_frame as usize {
            bump(&mut state.counters.generated_over_mtu);
            return Err(self.fail(GeneratedAllocationError::FrameTooLarge));
        }
        let interface = state.config.interface;
        match state
            .engine
            .allocate_generated_raw(frame_len, ZeroFill::Zero)
        {
            Ok(lease) => {
                self.completion.allocated += 1;
                #[cfg(test)]
                self.io.test_generated_allocated(port, &lease);
                self.outstanding = Some(lease);
                Ok(GeneratedPacketLease::new(XdpGeneratedSlot { batch: self }))
            }
            Err(GeneratedAllocError::Unavailable) => {
                Err(self.fail(GeneratedAllocationError::Unavailable))
            }
            Err(GeneratedAllocError::Rejected(reason)) => Err(match reason {
                GeneratedRejectReason::ZeroLength => {
                    self.fail(GeneratedAllocationError::ZeroLength)
                }
                GeneratedRejectReason::BelowMinimum | GeneratedRejectReason::TooLarge => {
                    self.fail(GeneratedAllocationError::FrameTooLarge)
                }
                GeneratedRejectReason::Draining => {
                    self.completion.error.get_or_insert(XdpIoError::Stopped);
                    self.fail(GeneratedAllocationError::Unavailable)
                }
            }),
            Err(GeneratedAllocError::Ledger(error)) => {
                self.completion
                    .error
                    .get_or_insert(XdpIoError::GeneratedLedger { interface, error });
                Err(self.fail(GeneratedAllocationError::Unavailable))
            }
        }
    }

    fn finish(mut self) -> GeneratedBatchCompletion<Self::Error> {
        self.settle();
        GeneratedBatchCompletion {
            attempts: self.completion.attempts,
            allocated: self.completion.allocated,
            failed: self.completion.failed,
            requested: self.completion.requested,
            cancelled: self.completion.cancelled,
            abandoned: self.completion.abandoned,
            accepted: self.completion.accepted,
            rejected: self.completion.rejected,
            error: self.completion.error.take(),
        }
    }
}

impl Drop for XdpGeneratedBatch<'_, '_> {
    fn drop(&mut self) {
        self.settle();
    }
}

impl fmt::Debug for XdpGeneratedBatch<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XdpGeneratedBatch")
            .field("completion", &self.completion)
            .finish_non_exhaustive()
    }
}

/// Core's view of one generated frame.
pub struct XdpGeneratedSlot<'s, 'a, 'memory> {
    batch: &'s mut XdpGeneratedBatch<'a, 'memory>,
}

impl GeneratedPacketSlot for XdpGeneratedSlot<'_, '_, '_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        let batch = &mut *self.batch;
        let port = batch.port.expect("a lease implies a port");
        let lease = batch.outstanding.as_ref().expect("live generated slot");
        batch.io.ports[port].engine.lease_bytes_mut(lease)
    }

    fn complete(self, completion: GeneratedSlotCompletion) {
        let lease = self.batch.outstanding.take().expect("live generated slot");
        self.batch.complete(lease, completion);
    }
}

// -------------------------------------------------------- quiescence ----

impl PublicationQuiescence for XdpPacketIo<'_> {
    type Error = XdpQuiescenceError;
    type Guard<'backend>
        = PublicationQuiescenceGuard<'backend, Self>
    where
        Self: 'backend;

    fn try_publication_quiescence(&mut self) -> Result<Self::Guard<'_>, Self::Error> {
        if self.stop.is_some() {
            return Err(XdpQuiescenceError::Stopped);
        }
        for index in 0..self.ports.len() {
            let port = &mut self.ports[index];
            let interface = port.config.interface;
            let budget = port.engine.tx_inflight_limit();
            if let Err(error) = port.engine.reap_completions(budget) {
                self.fault(XdpIoError::Datapath { interface, error });
                return Err(XdpQuiescenceError::Datapath { interface, error });
            }
        }
        for port in self.ports.iter() {
            let interface = port.config.interface;
            let leased =
                port.engine.frame_accounting().leased + port.engine.generated_accounting().leased;
            if leased != 0 {
                return Err(XdpQuiescenceError::LeaseOutstanding {
                    interface,
                    frames: leased,
                });
            }
            let handoffs = port.engine.tx_handoffs_outstanding();
            if handoffs != 0 {
                return Err(XdpQuiescenceError::HandoffOutstanding {
                    interface,
                    frames: handoffs,
                });
            }
            let in_flight = port.engine.tx_inflight();
            if in_flight != 0 {
                return Err(XdpQuiescenceError::TxInFlight {
                    interface,
                    frames: in_flight,
                });
            }
        }
        Ok(PublicationQuiescenceGuard::new(self))
    }

    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
        if self.stop.is_some() {
            return PublicationQuiescenceDisposition::Stop;
        }
        let stranded = self.ports.iter().any(|port| {
            port.engine.frame_accounting().leased != 0
                || port.engine.generated_accounting().leased != 0
                || port.engine.tx_handoffs_outstanding() != 0
        });
        if stranded {
            PublicationQuiescenceDisposition::SkipIo
        } else {
            PublicationQuiescenceDisposition::ContinueOldIo
        }
    }

    fn quiescence_error_disposition(error: &Self::Error) -> PublicationQuiescenceDisposition {
        match error {
            XdpQuiescenceError::Stopped | XdpQuiescenceError::Datapath { .. } => {
                PublicationQuiescenceDisposition::Stop
            }
            XdpQuiescenceError::LeaseOutstanding { .. }
            | XdpQuiescenceError::HandoffOutstanding { .. } => {
                PublicationQuiescenceDisposition::SkipIo
            }
            XdpQuiescenceError::TxInFlight { .. } => {
                PublicationQuiescenceDisposition::ContinueOldIo
            }
        }
    }
}

// ------------------------------------------------------------- stats ----

/// Counters and gauges of one port, or summed over every port (OBS-018).
///
/// Sums saturate; `tx_inflight_highwater` and
/// `completion_lag_oldest_polls` are maxima, not sums.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct XdpCounters {
    // RX/Fill (engine).
    pub polls: u64,
    pub rx_packets: u64,
    pub rx_leased: u64,
    pub rx_recycled: u64,
    pub rx_abandoned: u64,
    pub rx_ring_empty: u64,
    pub rx_backlogged: u64,
    pub rx_runts_recycled: u64,
    /// Refused RX descriptors, every reason.
    pub rx_invalid: u64,
    /// Refused RX descriptors per reason, in [`RxInvalidReason::ALL`] order.
    pub rx_invalid_by_reason: [u64; RxInvalidReason::COUNT],
    pub fill_published: u64,
    pub fill_starved: u64,
    pub fill_ring_full: u64,
    pub fill_need_wakeup: u64,
    pub fill_flag_errors: u64,
    pub fill_suppressed_draining: u64,
    // TX/Completion (engine).
    pub tx_submitted: u64,
    pub tx_ring_full: u64,
    pub tx_inflight_limited: u64,
    pub tx_refused_draining: u64,
    pub tx_completed: u64,
    pub tx_completions_reordered: u64,
    pub completion_backlogged: u64,
    /// Refused completion entries, every reason.
    pub tx_invalid_completions: u64,
    pub tx_need_wakeup: u64,
    pub tx_flag_errors: u64,
    pub tx_kicks: u64,
    pub fill_kicks: u64,
    pub kicks_deferred: u64,
    pub kick_errors: u64,
    pub drains: u64,
    /// Gauge: frames published to TX and not completed.
    pub tx_inflight: u64,
    /// Highest `tx_inflight` (maximum over ports).
    pub tx_inflight_highwater: u64,
    /// Poll age of the oldest in-flight frame (maximum over ports; zero
    /// when nothing is in flight).
    pub completion_lag_oldest_polls: u64,
    // Quarantine (both pools).
    pub frames_quarantined: u64,
    /// Gauge: generated-pool frames currently quarantined.
    pub generated_quarantined: u64,
    pub generated_quarantined_after_tx: u64,
    // Generated pool (engine; includes cross-port copies).
    pub generated_allocated: u64,
    pub generated_unavailable: u64,
    pub generated_committed: u64,
    pub generated_cancelled: u64,
    pub generated_abandoned: u64,
    pub generated_completed: u64,
    pub generated_rejected: u64,
    /// Gauge: generated frames in flight.
    pub generated_inflight: u64,
    // Adapter.
    pub forwarded_in_place: u64,
    pub cross_port_copies: u64,
    pub cross_port_copy_unavailable: u64,
    pub tx_over_mtu: u64,
    pub tx_blocked: u64,
    pub tx_unknown_egress: u64,
    pub generated_over_mtu: u64,
    pub generated_tx_blocked: u64,
    pub leases_reclaimed: u64,
}

impl XdpCounters {
    fn of(port: &PortState<'_>) -> Self {
        let engine = &port.engine;
        let rx = engine.counters();
        let tx = engine.tx_counters();
        let generated = engine.generated_counters();
        let accounting = engine.generated_accounting();
        let adapter = port.counters;
        let mut rx_invalid_by_reason = [0; RxInvalidReason::COUNT];
        for reason in RxInvalidReason::ALL {
            rx_invalid_by_reason[reason.index()] = rx.rx_invalid(reason);
        }
        Self {
            polls: rx.polls,
            rx_packets: rx.rx_packets,
            rx_leased: rx.rx_leased,
            rx_recycled: rx.rx_recycled,
            rx_abandoned: rx.rx_abandoned,
            rx_ring_empty: rx.rx_ring_empty,
            rx_backlogged: rx.rx_backlogged,
            rx_runts_recycled: rx.rx_runts_recycled,
            rx_invalid: rx.rx_invalid_total(),
            rx_invalid_by_reason,
            fill_published: rx.fill_published,
            fill_starved: rx.fill_starved,
            fill_ring_full: rx.fill_ring_full,
            fill_need_wakeup: rx.fill_need_wakeup,
            fill_flag_errors: rx.fill_flag_errors,
            fill_suppressed_draining: rx.fill_suppressed_draining,
            tx_submitted: tx.tx_submitted,
            tx_ring_full: tx.tx_ring_full,
            tx_inflight_limited: tx.tx_inflight_limited,
            tx_refused_draining: tx.tx_refused_draining,
            tx_completed: tx.tx_completed,
            tx_completions_reordered: tx.tx_completions_reordered,
            completion_backlogged: tx.completion_backlogged,
            tx_invalid_completions: tx.tx_invalid_completion_total(),
            tx_need_wakeup: tx.tx_need_wakeup,
            tx_flag_errors: tx.tx_flag_errors,
            tx_kicks: tx.tx_kicks,
            fill_kicks: tx.fill_kicks,
            kicks_deferred: tx.kicks_deferred,
            kick_errors: tx.kick_errors,
            drains: tx.drains,
            tx_inflight: u64::from(tx.tx_inflight),
            tx_inflight_highwater: u64::from(tx.tx_inflight_highwater),
            completion_lag_oldest_polls: engine.completion_lag().oldest_age_polls().unwrap_or(0),
            frames_quarantined: rx.frames_quarantined,
            generated_quarantined: u64::from(accounting.quarantined),
            generated_quarantined_after_tx: generated.generated_quarantined_after_tx,
            generated_allocated: generated.generated_allocated,
            generated_unavailable: generated.generated_unavailable,
            generated_committed: generated.generated_committed,
            generated_cancelled: generated.generated_cancelled,
            generated_abandoned: generated.generated_abandoned,
            generated_completed: generated.generated_completed,
            generated_rejected: generated.generated_rejected_total(),
            generated_inflight: u64::from(generated.generated_inflight),
            forwarded_in_place: adapter.forwarded_in_place,
            cross_port_copies: adapter.cross_port_copies,
            cross_port_copy_unavailable: adapter.cross_port_copy_unavailable,
            tx_over_mtu: adapter.tx_over_mtu,
            tx_blocked: adapter.tx_blocked,
            tx_unknown_egress: adapter.tx_unknown_egress,
            generated_over_mtu: adapter.generated_over_mtu,
            generated_tx_blocked: adapter.generated_tx_blocked,
            leases_reclaimed: adapter.leases_reclaimed,
        }
    }

    /// Adds `other` (sums saturate; maxima for the high-water and lag).
    fn accumulate(&mut self, other: &Self) {
        macro_rules! sum {
            ($($field:ident),* $(,)?) => {
                $(self.$field = self.$field.saturating_add(other.$field);)*
            };
        }
        sum!(
            polls,
            rx_packets,
            rx_leased,
            rx_recycled,
            rx_abandoned,
            rx_ring_empty,
            rx_backlogged,
            rx_runts_recycled,
            rx_invalid,
            fill_published,
            fill_starved,
            fill_ring_full,
            fill_need_wakeup,
            fill_flag_errors,
            fill_suppressed_draining,
            tx_submitted,
            tx_ring_full,
            tx_inflight_limited,
            tx_refused_draining,
            tx_completed,
            tx_completions_reordered,
            completion_backlogged,
            tx_invalid_completions,
            tx_need_wakeup,
            tx_flag_errors,
            tx_kicks,
            fill_kicks,
            kicks_deferred,
            kick_errors,
            drains,
            tx_inflight,
            frames_quarantined,
            generated_quarantined,
            generated_quarantined_after_tx,
            generated_allocated,
            generated_unavailable,
            generated_committed,
            generated_cancelled,
            generated_abandoned,
            generated_completed,
            generated_rejected,
            generated_inflight,
            forwarded_in_place,
            cross_port_copies,
            cross_port_copy_unavailable,
            tx_over_mtu,
            tx_blocked,
            tx_unknown_egress,
            generated_over_mtu,
            generated_tx_blocked,
            leases_reclaimed,
        );
        for (total, value) in self
            .rx_invalid_by_reason
            .iter_mut()
            .zip(other.rx_invalid_by_reason)
        {
            *total = total.saturating_add(value);
        }
        self.tx_inflight_highwater = self.tx_inflight_highwater.max(other.tx_inflight_highwater);
        self.completion_lag_oldest_polls = self
            .completion_lag_oldest_polls
            .max(other.completion_lag_oldest_polls);
    }

    fn visit<V: FieldVisitor>(&self, section: &'static str, visitor: &mut V) {
        let mut count = |key: &'static str, value: u64| {
            visitor.field(section, key, FieldValue::Count(value));
        };
        count("polls", self.polls);
        count("rx_packets", self.rx_packets);
        count("rx_leased", self.rx_leased);
        count("rx_recycled", self.rx_recycled);
        count("rx_abandoned", self.rx_abandoned);
        count("rx_ring_empty", self.rx_ring_empty);
        count("rx_backlogged", self.rx_backlogged);
        count("rx_runts_recycled", self.rx_runts_recycled);
        count("rx_invalid", self.rx_invalid);
        for (key, value) in RX_INVALID_KEYS.iter().zip(self.rx_invalid_by_reason) {
            count(key, value);
        }
        count("fill_published", self.fill_published);
        count("fill_starved", self.fill_starved);
        count("fill_ring_full", self.fill_ring_full);
        count("fill_need_wakeup", self.fill_need_wakeup);
        count("fill_flag_errors", self.fill_flag_errors);
        count("fill_suppressed_draining", self.fill_suppressed_draining);
        count("tx_submitted", self.tx_submitted);
        count("tx_ring_full", self.tx_ring_full);
        count("tx_inflight_limited", self.tx_inflight_limited);
        count("tx_refused_draining", self.tx_refused_draining);
        count("tx_completed", self.tx_completed);
        count("tx_completions_reordered", self.tx_completions_reordered);
        count("completion_backlogged", self.completion_backlogged);
        count("tx_invalid_completions", self.tx_invalid_completions);
        count("tx_need_wakeup", self.tx_need_wakeup);
        count("tx_flag_errors", self.tx_flag_errors);
        count("tx_kicks", self.tx_kicks);
        count("fill_kicks", self.fill_kicks);
        count("kicks_deferred", self.kicks_deferred);
        count("kick_errors", self.kick_errors);
        count("drains", self.drains);
        count("tx_inflight", self.tx_inflight);
        count("tx_inflight_highwater", self.tx_inflight_highwater);
        count(
            "completion_lag_oldest_polls",
            self.completion_lag_oldest_polls,
        );
        count("frames_quarantined", self.frames_quarantined);
        count("generated_quarantined", self.generated_quarantined);
        count(
            "generated_quarantined_after_tx",
            self.generated_quarantined_after_tx,
        );
        count("generated_allocated", self.generated_allocated);
        count("generated_unavailable", self.generated_unavailable);
        count("generated_committed", self.generated_committed);
        count("generated_cancelled", self.generated_cancelled);
        count("generated_abandoned", self.generated_abandoned);
        count("generated_completed", self.generated_completed);
        count("generated_rejected", self.generated_rejected);
        count("generated_inflight", self.generated_inflight);
        count("forwarded_in_place", self.forwarded_in_place);
        count("cross_port_copies", self.cross_port_copies);
        count(
            "cross_port_copy_unavailable",
            self.cross_port_copy_unavailable,
        );
        count("tx_over_mtu", self.tx_over_mtu);
        count("tx_blocked", self.tx_blocked);
        count("tx_unknown_egress", self.tx_unknown_egress);
        count("generated_over_mtu", self.generated_over_mtu);
        count("generated_tx_blocked", self.generated_tx_blocked);
        count("leases_reclaimed", self.leases_reclaimed);
    }
}

/// Stats keys of [`XdpCounters::rx_invalid_by_reason`], in
/// [`RxInvalidReason::ALL`] order.
const RX_INVALID_KEYS: [&str; RxInvalidReason::COUNT] = [
    "rx_invalid_address_outside_umem",
    "rx_invalid_not_kernel_owned",
    "rx_invalid_unsupported_options",
    "rx_invalid_data_before_headroom",
    "rx_invalid_shorter_than_ethernet_header",
    "rx_invalid_exceeds_frame",
];

const fn mode_label(mode: NegotiatedMode) -> &'static str {
    match mode {
        NegotiatedMode::Copy => BackendMode::Copy.label(),
        NegotiatedMode::ZeroCopy => BackendMode::ZeroCopy.label(),
    }
}

/// Stats of one port (OBS-018).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XdpPortStats {
    pub interface: IfId,
    pub queue: u32,
    pub mode: NegotiatedMode,
    pub mtu: u32,
    /// The TX length bound actually enforced.
    pub max_frame: u32,
    /// The Fill need-wakeup flag right now (`true` also when the flags
    /// word is unreadable).
    pub fill_need_wakeup: bool,
    /// The TX need-wakeup flag right now (copy mode keeps it set).
    pub tx_need_wakeup: bool,
    pub draining: bool,
    pub counters: XdpCounters,
}

fn port_stats(port: &PortState<'_>) -> XdpPortStats {
    XdpPortStats {
        interface: port.config.interface,
        queue: port.config.queue,
        mode: port.config.mode,
        mtu: port.config.mtu,
        max_frame: port.max_frame,
        fill_need_wakeup: port.engine.fill_needs_wakeup() != Ok(NeedWakeup::NotRequired),
        tx_need_wakeup: port.engine.tx_needs_wakeup() != Ok(NeedWakeup::NotRequired),
        draining: port.engine.is_draining(),
        counters: XdpCounters::of(port),
    }
}

impl ObservableFields for XdpPortStats {
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        const SECTION: &str = "af_xdp_port";
        visitor.field(
            SECTION,
            "interface",
            FieldValue::Count(u64::from(self.interface.0)),
        );
        visitor.field(SECTION, "queue", FieldValue::Count(u64::from(self.queue)));
        visitor.field(SECTION, "mode", FieldValue::Label(mode_label(self.mode)));
        visitor.field(SECTION, "mtu", FieldValue::Count(u64::from(self.mtu)));
        visitor.field(
            SECTION,
            "max_frame",
            FieldValue::Count(u64::from(self.max_frame)),
        );
        visitor.field(
            SECTION,
            "fill_need_wakeup_now",
            FieldValue::Flag(self.fill_need_wakeup),
        );
        visitor.field(
            SECTION,
            "tx_need_wakeup_now",
            FieldValue::Flag(self.tx_need_wakeup),
        );
        visitor.field(SECTION, "draining", FieldValue::Flag(self.draining));
        self.counters.visit(SECTION, visitor);
    }
}

/// Backend stats summed over every port (OBS-018). Per-port detail is
/// [`XdpPacketIo::port_stats`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XdpBackendStats {
    pub ports: u32,
    pub copy_ports: u32,
    pub zero_copy_ports: u32,
    /// Ports whose Fill need-wakeup flag is set right now.
    pub fill_need_wakeup_ports: u32,
    /// Ports whose TX need-wakeup flag is set right now.
    pub tx_need_wakeup_ports: u32,
    /// Drained or stopped by a fault: no more I/O.
    pub stopped: bool,
    pub counters: XdpCounters,
}

impl XdpBackendStats {
    /// `"copy"`, `"zero_copy"`, or `"mixed"`.
    #[must_use]
    pub const fn mode_label(&self) -> &'static str {
        match (self.copy_ports, self.zero_copy_ports) {
            (_, 0) => BackendMode::Copy.label(),
            (0, _) => BackendMode::ZeroCopy.label(),
            _ => "mixed",
        }
    }
}

impl ObservableFields for XdpBackendStats {
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        const SECTION: &str = "af_xdp";
        visitor.field(SECTION, "mode", FieldValue::Label(self.mode_label()));
        visitor.field(SECTION, "ports", FieldValue::Count(u64::from(self.ports)));
        visitor.field(
            SECTION,
            "copy_ports",
            FieldValue::Count(u64::from(self.copy_ports)),
        );
        visitor.field(
            SECTION,
            "zero_copy_ports",
            FieldValue::Count(u64::from(self.zero_copy_ports)),
        );
        visitor.field(
            SECTION,
            "fill_need_wakeup_ports",
            FieldValue::Count(u64::from(self.fill_need_wakeup_ports)),
        );
        visitor.field(
            SECTION,
            "tx_need_wakeup_ports",
            FieldValue::Count(u64::from(self.tx_need_wakeup_ports)),
        );
        visitor.field(SECTION, "stopped", FieldValue::Flag(self.stopped));
        self.counters.visit(SECTION, visitor);
    }
}

impl BackendStats for XdpPacketIo<'_> {
    type Stats = XdpBackendStats;

    const NAME: &'static str = "af_xdp";
    /// The mode every port guarantees: the bind mode is negotiated per
    /// port at open (`auto` may fall back to copy), so the static claim is
    /// copy. The negotiated mode of each port is in the stats
    /// (`copy_ports`, `zero_copy_ports`, [`XdpPortStats::mode`]).
    const MODE: BackendMode = BackendMode::Copy;

    fn backend_stats(&self) -> Self::Stats {
        let mut stats = XdpBackendStats {
            ports: 0,
            copy_ports: 0,
            zero_copy_ports: 0,
            fill_need_wakeup_ports: 0,
            tx_need_wakeup_ports: 0,
            stopped: self.stop.is_some(),
            counters: XdpCounters::default(),
        };
        for port in self.ports.iter() {
            let port = port_stats(port);
            stats.ports += 1;
            match port.mode {
                NegotiatedMode::Copy => stats.copy_ports += 1,
                NegotiatedMode::ZeroCopy => stats.zero_copy_ports += 1,
            }
            stats.fill_need_wakeup_ports += u32::from(port.fill_need_wakeup);
            stats.tx_need_wakeup_ports += u32::from(port.tx_need_wakeup);
            stats.counters.accumulate(&port.counters);
        }
        stats
    }
}

#[cfg(test)]
#[path = "packet_io_hooks.rs"]
pub(crate) mod test_hooks;
