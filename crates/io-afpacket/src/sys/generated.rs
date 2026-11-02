//! Router-generated frames written directly into a TX frame (AP3).
//!
//! A generated session targets one egress port. `allocate(len)` checks the
//! length (`14..=max_frame_len`, below the Ethernet header is refused like an
//! oversize frame), then reserves the egress producer-head frame exactly like
//! a copy commit does (one Acquire status load, ownership Available ->
//! Prepared, every address checked) and lends core its `len` data bytes,
//! zeroed. The status word stays AVAILABLE while the lease is live, so the
//! kernel never reads the frame. `commit` writes the V3 header and publishes
//! SEND_REQUEST with a Release store; `cancel` and an abandoned lease return
//! the frame to Available without writing the ring. There is no packet copy:
//! the backend-owned TX frame *is* the generated buffer.
//!
//! The lease exclusively borrows the session, which exclusively borrows the
//! engine, so at most one TX frame of any port is lent at a time and no RX
//! lease or other TX submission can coexist with it. A full ring, an
//! unknown egress, or a stopped engine makes `allocate` return
//! `Unavailable` (counted, no error); a fault-class reservation or
//! publication failure is the session error. `finish` kicks the egress at
//! most once when it published a frame, with the same errno classification
//! as the RX batch. A lease forgotten with `mem::forget` leaves its frame
//! Prepared and unpublished; the session's `finish` (or, if the session was
//! forgotten too, the port's next reservation) returns it to Available and
//! counts it abandoned / `tx_orphans_reclaimed`. Nothing allocates.

use ruster_core::{
    GeneratedAllocationError, GeneratedBatchCompletion, GeneratedPacketBatch, GeneratedPacketLease,
    GeneratedPacketSlot, GeneratedSlotCompletion, IfId,
};

use super::{bump, packet_io::AfPacketIoError, AfPacketEngine, LinuxOps, PacketOps, TxReservation};

/// Shortest frame the kernel's `SOCK_RAW` Ethernet TX accepts.
const ETHERNET_HEADER_LEN: usize = 14;

impl<O: PacketOps> AfPacketEngine<O> {
    /// A generated session on `egress` without settling (scripted tests).
    pub(crate) fn begin_generated_batch(&mut self, egress: IfId) -> AfPacketGenBatch<'_, O> {
        let port = if self.is_stopped() {
            None
        } else {
            let port = self.table.lookup(egress).map(|index| index.get());
            if port.is_none() {
                bump(&mut self.generated_unknown_egress);
            }
            port
        };
        AfPacketGenBatch::new(self, egress, port, None)
    }

    /// `begin_generated` behind the live adapter: settles the egress port
    /// (reap and owed kick) first so the session sees reclaimed frames.
    pub(crate) fn live_begin_generated(&mut self, egress: IfId) -> AfPacketGenBatch<'_, O> {
        if !self.is_stopped() {
            if let Some(index) = self.table.lookup(egress) {
                if let Err(error) = self.settle_port(index.get(), false) {
                    return AfPacketGenBatch::new(self, egress, None, Some(error));
                }
            }
        }
        self.begin_generated_batch(egress)
    }
}

/// One generated session on one egress port.
#[must_use]
pub(crate) struct AfPacketGenBatch<'a, O: PacketOps = LinuxOps> {
    engine: &'a mut AfPacketEngine<O>,
    egress: IfId,
    port: Option<usize>,
    attempts: usize,
    allocated: usize,
    failed: usize,
    requested: usize,
    cancelled: usize,
    abandoned: usize,
    accepted: usize,
    rejected: usize,
    error: Option<AfPacketIoError>,
    finished: bool,
}

impl<'a, O: PacketOps> AfPacketGenBatch<'a, O> {
    const fn new(
        engine: &'a mut AfPacketEngine<O>,
        egress: IfId,
        port: Option<usize>,
        error: Option<AfPacketIoError>,
    ) -> Self {
        Self {
            engine,
            egress,
            port,
            attempts: 0,
            allocated: 0,
            failed: 0,
            requested: 0,
            cancelled: 0,
            abandoned: 0,
            accepted: 0,
            rejected: 0,
            error,
            finished: false,
        }
    }

    fn record(&mut self, error: AfPacketIoError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    /// The next generated frame's backend slot (the public adapter wraps it).
    pub(crate) fn allocate_slot(
        &mut self,
        len: usize,
    ) -> Result<AfPacketGenSlot<'_, 'a, O>, GeneratedAllocationError> {
        self.attempts += 1;
        if len == 0 {
            self.failed += 1;
            return Err(GeneratedAllocationError::ZeroLength);
        }
        let Some(port) = self.port else {
            self.failed += 1;
            return Err(GeneratedAllocationError::Unavailable);
        };
        let resources = &mut self.engine.ports[port];
        if !(ETHERNET_HEADER_LEN..=resources.max_frame_len).contains(&len) {
            self.failed += 1;
            bump(&mut resources.counters.generated_rejected);
            return Err(GeneratedAllocationError::FrameTooLarge);
        }
        let mut status_reads = usize::MAX;
        match resources.tx_reserve(len, &mut status_reads) {
            Ok(reservation) => {
                // SAFETY: `tx_prepare` proved (through ring_address) that
                // `data..+len` lies inside this port's TX frame of the live
                // mapping. The frame is Prepared and its status AVAILABLE, so
                // the kernel does not access it, and the engine is
                // exclusively borrowed, so no other userspace access exists.
                unsafe { std::ptr::write_bytes(reservation.data().as_ptr(), 0, len) };
                bump(&mut resources.counters.generated_allocated);
                self.allocated += 1;
                Ok(AfPacketGenSlot {
                    batch: self,
                    port,
                    reservation: Some(reservation),
                })
            }
            Err(error) => {
                self.failed += 1;
                if error.is_fault() {
                    let egress = self.egress;
                    self.record(AfPacketIoError::Tx { egress, error });
                } else {
                    bump(&mut self.engine.ports[port].counters.generated_unavailable);
                }
                Err(GeneratedAllocationError::Unavailable)
            }
        }
    }

    fn finish_inner(&mut self) -> GeneratedBatchCompletion<AfPacketIoError> {
        self.finished = true;
        // A lease forgotten with `mem::forget` never ran its completion. Its
        // borrow of this session is over now, so its frame (still Prepared,
        // never visible to the kernel) is returned and the lease is counted
        // as abandoned, which keeps the completion invariants exact.
        let ended = self.requested + self.cancelled + self.abandoned;
        let forgotten = self.allocated.saturating_sub(ended);
        if forgotten != 0 {
            if let Some(port) = self.port {
                let resources = &mut self.engine.ports[port];
                let head = resources.tx_state.producer_head;
                resources.tx_reclaim_orphan(head);
                for _ in 0..forgotten {
                    bump(&mut resources.counters.generated_abandoned);
                }
            }
            self.abandoned += forgotten;
        }
        if self.accepted != 0 {
            if let Some(port) = self.port {
                let now = self.engine.now_ms;
                let resources = &mut self.engine.ports[port];
                if let Err(failure) = resources.kick_classified(now, false) {
                    if failure.class.is_error() {
                        let interface = resources.interface;
                        self.record(AfPacketIoError::Kick {
                            interface,
                            error: failure.error,
                        });
                    }
                }
            }
        }
        GeneratedBatchCompletion {
            attempts: self.attempts,
            allocated: self.allocated,
            failed: self.failed,
            requested: self.requested,
            cancelled: self.cancelled,
            abandoned: self.abandoned,
            accepted: self.accepted,
            rejected: self.rejected,
            error: self.error.take(),
        }
    }

    /// `finish` that the public adapter calls through its wrapper.
    pub(crate) fn finish_batch(mut self) -> GeneratedBatchCompletion<AfPacketIoError> {
        self.finish_inner()
    }
}

impl<'a, O: PacketOps> GeneratedPacketBatch for AfPacketGenBatch<'a, O> {
    type Error = AfPacketIoError;
    type Slot<'b>
        = AfPacketGenSlot<'b, 'a, O>
    where
        Self: 'b;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        self.allocate_slot(frame_len).map(GeneratedPacketLease::new)
    }

    fn finish(mut self) -> GeneratedBatchCompletion<Self::Error> {
        self.finish_inner()
    }
}

impl<O: PacketOps> Drop for AfPacketGenBatch<'_, O> {
    fn drop(&mut self) {
        if !self.finished {
            // Published frames are already in the ring; kick them once.
            let _ = self.finish_inner();
        }
    }
}

/// Backend slot behind one core [`GeneratedPacketLease`].
pub(crate) struct AfPacketGenSlot<'b, 'a, O: PacketOps = LinuxOps> {
    batch: &'b mut AfPacketGenBatch<'a, O>,
    port: usize,
    reservation: Option<TxReservation>,
}

impl<O: PacketOps> AfPacketGenSlot<'_, '_, O> {
    fn end(&mut self, completion: GeneratedSlotCompletion) {
        let Some(reservation) = self.reservation.take() else {
            return;
        };
        let batch = &mut *self.batch;
        let resources = &mut batch.engine.ports[self.port];
        match completion {
            GeneratedSlotCompletion::Transmit => {
                batch.requested += 1;
                match resources.tx_commit(reservation) {
                    Ok(_) => {
                        bump(&mut resources.counters.generated_committed);
                        batch.accepted += 1;
                    }
                    Err(error) => {
                        batch.rejected += 1;
                        let egress = batch.egress;
                        batch.record(AfPacketIoError::Tx { egress, error });
                    }
                }
            }
            GeneratedSlotCompletion::Cancelled => {
                resources.tx_cancel(reservation);
                bump(&mut resources.counters.generated_cancelled);
                batch.cancelled += 1;
            }
            GeneratedSlotCompletion::Abandoned => {
                resources.tx_cancel(reservation);
                bump(&mut resources.counters.generated_abandoned);
                batch.abandoned += 1;
            }
        }
    }
}

impl<O: PacketOps> GeneratedPacketSlot for AfPacketGenSlot<'_, '_, O> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        let reservation = self
            .reservation
            .as_ref()
            .expect("live generated slot holds its reservation");
        // SAFETY: `tx_prepare` proved (through ring_address) that
        // `data..data + len` lies inside the egress port's TX frame of the
        // live mapping, which outlives the engine borrow this slot holds.
        // The frame is Prepared with status AVAILABLE, so the kernel neither
        // reads nor writes it; the slot exclusively borrows the session and
        // so the engine, and `&mut self` makes this the only live view.
        unsafe { std::slice::from_raw_parts_mut(reservation.data().as_ptr(), reservation.len()) }
    }

    fn complete(mut self, completion: GeneratedSlotCompletion) {
        self.end(completion);
    }
}

impl<O: PacketOps> Drop for AfPacketGenSlot<'_, '_, O> {
    fn drop(&mut self) {
        // Reached when the slot ends without `complete`, for example while
        // unwinding: the frame was never published, so return it.
        self.end(GeneratedSlotCompletion::Abandoned);
    }
}
