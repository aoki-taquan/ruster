//! Private AF_PACKET copy backend for [`ruster_core::PacketIo`] (AP2).
//!
//! [`AfPacketEngine`] owns RX and TX state of every port. `receive` returns a
//! batch that exclusively borrows the whole engine and walks the ports'
//! persistent RX cursors round-robin under one packet budget plus the
//! per-port RX and per-batch TX [`WorkLimits`]. Each lease is a zero-copy view
//! of one validated RX packet in a USER-owned block of the ingress port's
//! mapping. The mapping is `PROT_READ | PROT_WRITE` and `MAP_SHARED`, and a
//! USER block belongs to userspace until its status is stored back as
//! TP_STATUS_KERNEL, so core may rewrite the packet in place through
//! `bytes_mut`.
//!
//! Completion of a lease:
//!
//! - `commit(egress)`: O(1) `IfId` lookup, size check, the batch's TX
//!   status-read budget, one Acquire load of the egress producer-head status,
//!   and frame ownership are all checked before any byte moves. Only an
//!   accepted submission copies, exactly once, from the RX packet directly into
//!   the TX frame of the egress port and publishes SEND_REQUEST. The egress
//!   may be any configured port, including the ingress port itself.
//! - `recycle`, `consume`, and an abandoned `PacketLease` complete the RX
//!   packet without touching TX.
//!
//! In every case the RX packet becomes terminal exactly once after any copy,
//! and its block returns to the kernel when its last packet is terminal. TX
//! completion of the copied frame is independent and is reclaimed later by
//! the bounded FIFO completion scan.
//!
//! # Hairpin borrow and aliasing argument
//!
//! A lease (`AfPacketSlot`) borrows the batch, which borrows the engine, so
//! while a lease is live no other lease of any port exists and no other code
//! can reach any port's metadata or mapping. Core gets a `&mut [u8]` only
//! through `bytes_mut(&mut self)`, and `complete(self)` consumes the slot, so
//! that borrow has ended before the copy starts. The copy source is kept as a
//! raw `(NonNull<u8>, len)` (`TxPayload::from_raw`), never as a `&[u8]` held
//! across the `&mut` engine call, so selecting the TX frame of the same port
//! does not need a shared and an exclusive borrow of that port at once.
//! The source range was proved by `ring_address` to lie inside the ingress
//! port's RX extent, and the destination range inside the egress port's TX
//! extent. Within one port the checked combined layout places RX at
//! `[0, rx_len)` and TX at `[rx_len, combined_len)` (`CombinedRingExtents`
//! rejects overlap and gaps, and `MmapRegion::validate_extents` rechecks the
//! live mapping), and distinct ports own distinct mappings. Hence source and
//! destination never overlap and `copy_nonoverlapping` is sound for hairpin
//! and cross-port commits alike. The block containing the source stays USER
//! (kernel does not write it) until the packet completes after the copy.
//!
//! # `BatchCompletion` mapping
//!
//! - `tx_requested`: every `Transmit` completion.
//! - `tx_accepted`: SEND_REQUEST published before `finish` returned. A kick
//!   failure does not demote it; the frame stays in flight.
//! - `tx_rejected`: unknown egress, oversize, exhausted TX status-read
//!   budget, a non-AVAILABLE producer head (ring full), and backend faults
//!   (unknown status, generation exhaustion, mapping/ownership violations).
//!   Rejection never reserves or copies; the RX packet is still completed.
//! - `recycled`: `Recycle`, `Consume`, and `LeaseAbandoned` completions.
//!   RX packets that fail validation are never leased and are not counted;
//!   they appear only in the per-port `BackendStats`. A `mem::forget`-ten
//!   lease is finalized by a later cursor step and is not counted either.
//! - `error`: the first backend fault of the batch: a newly observed halting
//!   RX fault of any port, a TX fault-class rejection, or the first failed
//!   kick. Routine rejections are not errors. Accounting is complete in every
//!   case.
//!
//! RX halts are edge-triggered. A halt becomes `error` only in the batch that
//! first observes that halt event, using the same sticky event identity that
//! counts it once in `BackendStats`. While the same condition persists, later
//! batches skip the halted port without an error; a different halt, or the
//! same condition recurring after the port made progress, is a new event and
//! is reported again. The runtime treats any finish error as a backend I/O
//! failure and skips generated ARP/ICMP for every port in that tick, so a
//! level-triggered report would let one halted port starve healthy ports
//! indefinitely. The halted state stays visible through `BackendStats`;
//! health reporting and escalation are deferred (R15/AP3).
//!
//! PacketIo alone never reaps TX completions. Accepted frames are returned
//! only by the engine's bounded `scan_completions`, which today only tests
//! call. Without it each egress TX ring is exhausted after `frame_count`
//! accepted commits, and later commits are routinely rejected as ring full
//! with `error == None`. A public constructor must not be exposed before AP3
//! adds completion scheduling.
//!
//! `finish` and `Drop` both try `send(MSG_DONTWAIT)` at most once per egress
//! port that accepted a frame in this batch and never retry.
//!
//! Steady operation allocates nothing, takes no lock, uses no trait object,
//! and does O(1) work per packet plus bounded per-port status/descriptor work.
//! Poll integration, TX completion scheduling, live telemetry, and the public
//! constructor are deferred to AP3.

use std::ptr::NonNull;

use ruster_core::{
    BatchCompletion, IfId, PacketBatch, PacketIo, PacketLease, PacketSlot, SlotCompletion,
};

use super::{
    rx::{Completion, RxBatchReport, RxBudget, RxFault, RxPacketToken, RxStop, Step},
    AfPacketEngine, LinuxOps, PacketOps, TxPayload, TxSubmitError,
};
use crate::PlatformError;

/// First backend fault observed during one batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum AfPacketIoError {
    /// A halting RX fault (or a failed packet completion) on `interface`.
    Rx { interface: IfId, fault: RxFault },
    /// A fault-class TX rejection; the RX packet was still completed.
    Tx { egress: IfId, error: TxSubmitError },
    /// The first failed nonblocking kick. Published frames stay in flight.
    Kick {
        interface: IfId,
        error: PlatformError,
    },
}

impl<O: PacketOps> PacketIo for AfPacketEngine<O> {
    type Error = AfPacketIoError;
    type Batch<'a>
        = AfPacketBatch<'a, O>
    where
        Self: 'a;

    fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
        let epoch = self.begin_epoch();
        let limits = self.limits;
        let port_count = self.ports.len();
        let port = self.rx_start % port_count;
        Ok(AfPacketBatch {
            engine: self,
            epoch,
            touched_len: 0,
            start: port,
            port,
            ports_left: port_count,
            rx: RxBudget {
                packets: budget,
                block_status_reads: limits.rx_block_status_reads_per_port,
                descriptor_visits: limits.rx_descriptor_visits_per_port,
            },
            rx_report: RxBatchReport::default(),
            tx_status_reads: limits.tx_submit_status_reads,
            tx_requested: 0,
            tx_accepted: 0,
            tx_rejected: 0,
            recycled: 0,
            error: None,
            packet_budget_port: None,
            finished: false,
        })
    }
}

/// One RX pass over every port plus the TX submissions it requests.
#[must_use]
pub(crate) struct AfPacketBatch<'a, O: PacketOps = LinuxOps> {
    engine: &'a mut AfPacketEngine<O>,
    epoch: u64,
    touched_len: usize,
    start: usize,
    port: usize,
    ports_left: usize,
    rx: RxBudget,
    rx_report: RxBatchReport,
    tx_status_reads: usize,
    tx_requested: usize,
    tx_accepted: usize,
    tx_rejected: usize,
    recycled: usize,
    error: Option<AfPacketIoError>,
    packet_budget_port: Option<usize>,
    finished: bool,
}

struct LeasedRx {
    port: usize,
    token: RxPacketToken,
    data: NonNull<u8>,
    len: usize,
}

#[allow(dead_code)]
impl<O: PacketOps> AfPacketBatch<'_, O> {
    /// Aggregated RX work and lifecycle counters of this batch.
    pub(crate) const fn rx_report(&self) -> RxBatchReport {
        self.rx_report
    }

    fn record(&mut self, error: AfPacketIoError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    fn next_port(&mut self) {
        self.ports_left -= 1;
        self.port = (self.port + 1) % self.engine.ports.len();
        self.rx.block_status_reads = self.engine.limits.rx_block_status_reads_per_port;
        self.rx.descriptor_visits = self.engine.limits.rx_descriptor_visits_per_port;
    }

    fn next_rx(&mut self) -> Option<LeasedRx> {
        while self.ports_left != 0 {
            let port = self.port;
            let already_reported = self.engine.ports[port].rx_sticky_halt();
            match self.engine.ports[port].rx_step(&mut self.rx, &mut self.rx_report) {
                // A packet-local or whole-block fault is already terminal and
                // counted in the port's BackendStats; delivery continues.
                Step::Continue | Step::Fault(_) => {}
                Step::Lease { token, data, len } => {
                    return Some(LeasedRx {
                        port,
                        token,
                        data,
                        len,
                    })
                }
                Step::Stop(RxStop::PacketBudget) => {
                    self.packet_budget_port = Some(port);
                    self.ports_left = 0;
                }
                Step::Stop(_) => self.next_port(),
                Step::Halt(fault) => {
                    // Edge-triggered: a halt is an error only in the batch
                    // that first observes it (the same event identity that
                    // `BackendStats` counts once), so one persistently
                    // halted port does not fail every later batch.
                    if already_reported != Some(fault) {
                        let interface = self.engine.ports[port].interface;
                        self.record(AfPacketIoError::Rx { interface, fault });
                    }
                    self.next_port();
                }
            }
        }
        None
    }

    /// Reject-before-copy submission of one RX packet to `egress`.
    fn transmit(&mut self, egress: IfId, data: NonNull<u8>, len: usize) {
        self.tx_requested += 1;
        // SAFETY: `data..data + len` was proved by `ring_address` to lie in
        // the RX extent of the ingress port's live mapping, inside the
        // validated data range of a packet whose block stays USER-owned until
        // `complete_rx` runs after this call. The slot that produced it was
        // consumed by `complete`, so no `&mut [u8]` view of it is live. An RX
        // extent never overlaps any TX extent (module docs), and the payload
        // does not outlive this function.
        let payload = unsafe { TxPayload::from_raw(data, len) };
        match self
            .engine
            .submit(egress, payload, &mut self.tx_status_reads)
        {
            Ok((port_index, _)) => {
                self.tx_accepted += 1;
                self.engine
                    .touch(self.epoch, &mut self.touched_len, port_index);
            }
            Err(error) => {
                self.tx_rejected += 1;
                if error.is_fault() {
                    self.record(AfPacketIoError::Tx { egress, error });
                }
            }
        }
    }

    fn complete_rx(&mut self, port: usize, token: RxPacketToken, end: Completion) {
        let resources = &mut self.engine.ports[port];
        let already_reported = resources.rx_sticky_halt();
        if let Err(error) = resources.rx_complete(token, end, &mut self.rx_report) {
            let fault = RxFault::Release(error);
            resources.rx_note_halt(fault);
            let interface = resources.interface;
            if already_reported != Some(fault) {
                self.record(AfPacketIoError::Rx { interface, fault });
            }
        }
    }

    fn finish_inner(&mut self) -> BatchCompletion<AfPacketIoError> {
        self.finished = true;
        let kicks = self.engine.kick_touched(self.touched_len, self.tx_accepted);
        if let (Some(error), Some(interface)) = (kicks.first_kick_error, kicks.first_kick_interface)
        {
            self.record(AfPacketIoError::Kick { interface, error });
        }
        let port_count = self.engine.ports.len();
        // Round-robin fairness: the next batch starts after the port that
        // exhausted the packet budget, or one port later than this batch.
        self.engine.rx_start = match self.packet_budget_port {
            Some(port) => (port + 1) % port_count,
            None => (self.start + 1) % port_count,
        };
        BatchCompletion {
            tx_requested: self.tx_requested,
            tx_accepted: self.tx_accepted,
            tx_rejected: self.tx_rejected,
            recycled: self.recycled,
            error: self.error.take(),
        }
    }
}

impl<'a, O: PacketOps> PacketBatch for AfPacketBatch<'a, O> {
    type Error = AfPacketIoError;
    type Slot<'b>
        = AfPacketSlot<'b, 'a, O>
    where
        Self: 'b;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        let leased = self.next_rx()?;
        Some(PacketLease::new(AfPacketSlot {
            batch: self,
            port: leased.port,
            token: leased.token,
            data: leased.data,
            len: leased.len,
            completed: false,
        }))
    }

    fn finish(mut self) -> BatchCompletion<Self::Error> {
        self.finish_inner()
    }
}

impl<O: PacketOps> Drop for AfPacketBatch<'_, O> {
    fn drop(&mut self) {
        if !self.finished {
            // Accepted frames are already published; kick them once.
            let _ = self.finish_inner();
        }
    }
}

/// Backend slot behind one core [`PacketLease`].
pub(crate) struct AfPacketSlot<'b, 'a, O: PacketOps = LinuxOps> {
    batch: &'b mut AfPacketBatch<'a, O>,
    port: usize,
    token: RxPacketToken,
    data: NonNull<u8>,
    len: usize,
    completed: bool,
}

impl<O: PacketOps> PacketSlot for AfPacketSlot<'_, '_, O> {
    fn ingress(&self) -> IfId {
        self.batch.engine.ports[self.port].interface
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: `data..data + len` was proved by `ring_address` to lie in
        // the RX extent of the live mapping and inside this packet's validated
        // data range. The block stays USER-owned, so the kernel does not write
        // it, until this packet completes. The slot exclusively borrows the
        // batch and therefore the engine, so no other lease or engine access
        // exists, sibling packet ranges are disjoint, and `&mut self` makes
        // this the only live view. The mapping is writable (`PROT_WRITE`).
        unsafe { std::slice::from_raw_parts_mut(self.data.as_ptr(), self.len) }
    }

    fn complete(mut self, completion: SlotCompletion) {
        self.completed = true;
        let end = match completion {
            SlotCompletion::Transmit(egress) => {
                // The copy happens before the RX packet becomes terminal.
                self.batch.transmit(egress, self.data, self.len);
                Completion::Released
            }
            SlotCompletion::Recycle(_) | SlotCompletion::Consume(_) => {
                self.batch.recycled += 1;
                Completion::Released
            }
            SlotCompletion::LeaseAbandoned => {
                self.batch.recycled += 1;
                Completion::Dropped
            }
        };
        self.batch.complete_rx(self.port, self.token, end);
    }
}

impl<O: PacketOps> Drop for AfPacketSlot<'_, '_, O> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        // Reached only if a slot is dropped without `complete`, for example
        // while unwinding; the packet is reclaimed like an abandoned lease.
        self.completed = true;
        self.batch.recycled += 1;
        self.batch
            .complete_rx(self.port, self.token, Completion::Dropped);
    }
}

#[cfg(test)]
mod conformance;
#[cfg(test)]
mod tests;
