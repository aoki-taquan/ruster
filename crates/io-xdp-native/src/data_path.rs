//! AF_XDP packet I/O over the checked native ring views.
//!
//! The cold setup layer owns the socket, mmap regions, UMEM borrow, and the
//! fixed ownership ledger. This module only adds the worker-local operations
//! over those resources. It deliberately keeps all pointer access in
//! `native_unsafe`; packet bytes are borrowed from the original UMEM slice and
//! ring entries are accessed through the safe role-typed views.

use std::time::Duration;

use ruster_core::{
    BatchCompletion, GeneratedAllocationError, GeneratedBatchCompletion, GeneratedPacketBatch,
    GeneratedPacketIo, GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion, IfId,
    PacketBatch, PacketIo, PacketLease, PacketSlot, PublicationBackendAuthority,
    PublicationBackendControl, PublicationQuiescenceBackend, PublicationQuiescenceDisposition,
    SlotCompletion,
};

use crate::{
    abi::XdpDescriptor,
    native_unsafe::syscall::{
        LinuxSyscalls, OwnedXdpFd, ResourceError, SyscallArgumentError, SyscallStage, Syscalls,
    },
    CompletionConsumer, FillProducer, NativeRingError, NeedWakeup, RingName, RxConsumer,
    TxProducer, XdpChunkState, XdpIoError, XdpResource, XdpRingViews,
};

use super::config::UmemConfig;

/// Internal marker used while one resource is borrowed by a packet batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BatchState {
    Idle,
    Rx,
    Generated,
    Maintenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChunkState {
    Free,
    FillReserved,
    FillOwnedByKernel,
    Leased,
    PendingTx,
    TxReserved,
    TxOwnedByKernel { address: u64 },
    CompletionAvailable,
    Quarantined,
}

impl ChunkState {
    const fn kind(self) -> XdpChunkState {
        match self {
            Self::Free => XdpChunkState::Free,
            Self::FillReserved => XdpChunkState::FillReserved,
            Self::FillOwnedByKernel => XdpChunkState::FillOwnedByKernel,
            Self::Leased => XdpChunkState::Leased,
            Self::PendingTx => XdpChunkState::PendingTx,
            Self::TxReserved => XdpChunkState::TxReserved,
            Self::TxOwnedByKernel { .. } => XdpChunkState::TxOwnedByKernel,
            Self::CompletionAvailable => XdpChunkState::CompletionAvailable,
            Self::Quarantined => XdpChunkState::Quarantined,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChunkEntry {
    state: ChunkState,
}

/// Fixed-capacity ownership authority for one AF_XDP UMEM.
///
/// Every transition is performed before the corresponding producer/consumer
/// cursor is released, except for a producer's post-publication need-wakeup
/// observation. That observation can report an error after publication, so
/// callers retain the published state and surface the error separately.
#[derive(Debug)]
pub(crate) struct XdpOwnership {
    frame_count: u32,
    rx_frames: u32,
    frame_size: u32,
    data_offset: u32,
    byte_len: u64,
    entries: Box<[ChunkEntry]>,
    counts: [usize; 10],
}

impl XdpOwnership {
    pub(crate) fn new(config: UmemConfig) -> Self {
        let frame_count = usize::try_from(config.frame_count())
            .expect("configured frame count fits the native target");
        let mut counts = [0_usize; 10];
        counts[XdpChunkState::Free as usize] = frame_count;
        Self {
            frame_count: config.frame_count(),
            rx_frames: config.rx_frames(),
            frame_size: config.frame_size(),
            data_offset: config
                .headroom()
                .checked_add(crate::XDP_PACKET_HEADROOM)
                .expect("validated UMEM headroom cannot overflow"),
            byte_len: config.byte_len(),
            entries: vec![
                ChunkEntry {
                    state: ChunkState::Free,
                };
                frame_count
            ]
            .into_boxed_slice(),
            counts,
        }
    }

    fn state(&self, frame_index: u32) -> ChunkState {
        self.entries[usize::try_from(frame_index).expect("frame index fits usize")].state
    }

    fn state_kind(&self, frame_index: u32) -> XdpChunkState {
        self.state(frame_index).kind()
    }

    fn transition(
        &mut self,
        frame_index: u32,
        expected: XdpChunkState,
        next: ChunkState,
    ) -> Result<(), XdpIoError> {
        let index = usize::try_from(frame_index).expect("frame index fits usize");
        let actual = self.entries[index].state.kind();
        if actual != expected {
            return Err(XdpIoError::Ownership {
                frame_index,
                expected,
                actual,
            });
        }
        self.entries[index].state = next;
        self.counts[expected as usize] -= 1;
        self.counts[next.kind() as usize] += 1;
        Ok(())
    }

    fn frame_base(&self, frame_index: u32) -> u64 {
        u64::from(frame_index) * u64::from(self.frame_size)
    }

    fn data_address(&self, frame_index: u32) -> u64 {
        self.frame_base(frame_index) + u64::from(self.data_offset)
    }

    fn next_free_rx(&self) -> Option<u32> {
        (0..self.rx_frames).find(|&index| self.state_kind(index) == XdpChunkState::Free)
    }

    fn next_free_generated(&self) -> Option<u32> {
        (self.rx_frames..self.frame_count)
            .find(|&index| self.state_kind(index) == XdpChunkState::Free)
    }

    fn reserve_fill(&mut self, frame_index: u32) -> Result<(), XdpIoError> {
        self.transition(frame_index, XdpChunkState::Free, ChunkState::FillReserved)
    }

    fn cancel_fill(&mut self, frame_index: u32) -> Result<(), XdpIoError> {
        self.transition(frame_index, XdpChunkState::FillReserved, ChunkState::Free)
    }

    fn publish_fill(&mut self, frame_index: u32) -> Result<(), XdpIoError> {
        self.transition(
            frame_index,
            XdpChunkState::FillReserved,
            ChunkState::FillOwnedByKernel,
        )
    }

    fn lease_generated(&mut self, frame_index: u32) -> Result<(), XdpIoError> {
        if frame_index < self.rx_frames {
            return Err(XdpIoError::Ownership {
                frame_index,
                expected: XdpChunkState::Free,
                actual: self.state_kind(frame_index),
            });
        }
        self.transition(frame_index, XdpChunkState::Free, ChunkState::Leased)
    }

    fn validate_packet_descriptor(&self, descriptor: XdpDescriptor) -> Result<u32, XdpIoError> {
        if descriptor.options != 0 || descriptor.len == 0 {
            return Err(XdpIoError::InvalidDescriptor {
                address: descriptor.address,
                len: descriptor.len,
                options: descriptor.options,
            });
        }
        if descriptor.address >= self.byte_len {
            return Err(XdpIoError::InvalidDescriptor {
                address: descriptor.address,
                len: descriptor.len,
                options: descriptor.options,
            });
        }
        let frame_size = u64::from(self.frame_size);
        let frame_index = u32::try_from(descriptor.address / frame_size).map_err(|_| {
            XdpIoError::InvalidDescriptor {
                address: descriptor.address,
                len: descriptor.len,
                options: descriptor.options,
            }
        })?;
        let frame_base = self.frame_base(frame_index);
        let offset = descriptor.address - frame_base;
        let end = descriptor
            .address
            .checked_add(u64::from(descriptor.len))
            .ok_or(XdpIoError::InvalidDescriptor {
                address: descriptor.address,
                len: descriptor.len,
                options: descriptor.options,
            })?;
        let frame_end = frame_base + frame_size;
        if offset < u64::from(self.data_offset) || end > frame_end {
            return Err(XdpIoError::InvalidDescriptor {
                address: descriptor.address,
                len: descriptor.len,
                options: descriptor.options,
            });
        }
        Ok(frame_index)
    }

    fn lease_rx(&mut self, descriptor: XdpDescriptor) -> Result<u32, XdpIoError> {
        let frame_index = self.validate_packet_descriptor(descriptor)?;
        self.transition(
            frame_index,
            XdpChunkState::FillOwnedByKernel,
            ChunkState::Leased,
        )?;
        Ok(frame_index)
    }

    fn recycle_lease(&mut self, frame_index: u32) -> Result<(), XdpIoError> {
        self.transition(frame_index, XdpChunkState::Leased, ChunkState::Free)
    }

    fn stage_tx(&mut self, frame_index: u32) -> Result<(), XdpIoError> {
        self.transition(frame_index, XdpChunkState::Leased, ChunkState::PendingTx)
    }

    fn cancel_pending_tx(&mut self, frame_index: u32) -> Result<(), XdpIoError> {
        self.transition(frame_index, XdpChunkState::PendingTx, ChunkState::Leased)
    }

    fn reserve_tx(&mut self, frame_index: u32) -> Result<(), XdpIoError> {
        self.transition(
            frame_index,
            XdpChunkState::PendingTx,
            ChunkState::TxReserved,
        )
    }

    fn cancel_tx_reservation(&mut self, frame_index: u32) -> Result<(), XdpIoError> {
        self.transition(
            frame_index,
            XdpChunkState::TxReserved,
            ChunkState::PendingTx,
        )
    }

    fn publish_tx(&mut self, frame_index: u32, address: u64) -> Result<(), XdpIoError> {
        self.transition(
            frame_index,
            XdpChunkState::TxReserved,
            ChunkState::TxOwnedByKernel { address },
        )
    }

    fn completion_frame(&self, address: u64) -> Option<u32> {
        if address >= self.byte_len {
            return None;
        }
        u32::try_from(address / u64::from(self.frame_size)).ok()
    }

    fn complete_tx(&mut self, address: u64) -> Result<u32, XdpIoError> {
        let Some(frame_index) = self.completion_frame(address) else {
            return Err(XdpIoError::InvalidCompletionAddress { address });
        };
        let expected = self.state(frame_index);
        if !matches!(expected, ChunkState::TxOwnedByKernel { address: tx_address } if tx_address == address)
        {
            if matches!(expected, ChunkState::TxOwnedByKernel { .. }) {
                self.quarantine(frame_index);
            }
            return Err(XdpIoError::Ownership {
                frame_index,
                expected: XdpChunkState::TxOwnedByKernel,
                actual: expected.kind(),
            });
        }
        self.transition(
            frame_index,
            XdpChunkState::TxOwnedByKernel,
            ChunkState::CompletionAvailable,
        )?;
        Ok(frame_index)
    }

    fn recycle_completion(&mut self, frame_index: u32) -> Result<(), XdpIoError> {
        self.transition(
            frame_index,
            XdpChunkState::CompletionAvailable,
            ChunkState::Free,
        )
    }

    fn quarantine(&mut self, frame_index: u32) {
        let index = usize::try_from(frame_index).expect("frame index fits usize");
        let current = self.entries[index].state.kind();
        if current == XdpChunkState::Quarantined || current == XdpChunkState::Free {
            return;
        }
        self.entries[index].state = ChunkState::Quarantined;
        self.counts[current as usize] -= 1;
        self.counts[XdpChunkState::Quarantined as usize] += 1;
    }

    fn recover_rx_descriptor(&mut self, descriptor: XdpDescriptor) {
        if let Some(frame_index) = self.completion_frame(descriptor.address) {
            if frame_index < self.rx_frames {
                let frame_base = self.frame_base(frame_index);
                let frame_end = frame_base + u64::from(self.frame_size);
                let address_is_in_visible_chunk = descriptor.address
                    >= frame_base + u64::from(self.data_offset)
                    && descriptor.address < frame_end;
                if address_is_in_visible_chunk
                    && self.state_kind(frame_index) == XdpChunkState::FillOwnedByKernel
                {
                    // The malformed descriptor has already been consumed
                    // from RX. Returning its identified RX chunk is safe and
                    // keeps a processing error from permanently starving the
                    // Fill pool. Addresses that cannot be tied to one RX
                    // chunk remain quarantined below.
                    let _ = self.transition(
                        frame_index,
                        XdpChunkState::FillOwnedByKernel,
                        ChunkState::Free,
                    );
                    return;
                }
            }
        }
        self.quarantine_descriptor(descriptor);
    }

    fn quarantine_descriptor(&mut self, descriptor: XdpDescriptor) {
        if let Some(frame_index) = self.completion_frame(descriptor.address) {
            if frame_index < self.rx_frames
                && self.state_kind(frame_index) == XdpChunkState::FillOwnedByKernel
            {
                self.quarantine(frame_index);
            }
        }
    }

    pub(crate) fn has_nonquiescent_owner(&self) -> Option<(u32, XdpChunkState)> {
        for (index, entry) in self.entries.iter().enumerate() {
            let state = entry.state.kind();
            if matches!(
                state,
                XdpChunkState::FillReserved
                    | XdpChunkState::RxAvailable
                    | XdpChunkState::Leased
                    | XdpChunkState::PendingTx
                    | XdpChunkState::TxReserved
                    | XdpChunkState::TxOwnedByKernel
                    | XdpChunkState::CompletionAvailable
            ) {
                return Some((
                    u32::try_from(index).expect("entry index originated from u32"),
                    state,
                ));
            }
        }
        None
    }

    #[cfg(test)]
    pub(crate) fn count(&self, state: XdpChunkState) -> usize {
        self.counts[state as usize]
    }
}

/// The shared operational part of RX and generated batches.
pub(crate) struct XdpBatchCore<'batch, 'syscalls, S: Syscalls> {
    pub(crate) fill: FillProducer<'batch>,
    pub(crate) completion: CompletionConsumer<'batch>,
    pub(crate) rx: RxConsumer<'batch>,
    pub(crate) tx: TxProducer<'batch>,
    pub(crate) socket: Option<&'batch OwnedXdpFd<'syscalls, S>>,
    pub(crate) umem: &'batch mut [u8],
    pub(crate) ownership: &'batch mut XdpOwnership,
    batch_state: &'batch mut BatchState,
    interface: IfId,
    fill_wakeup_pending: &'batch mut bool,
    tx_wakeup_pending: &'batch mut bool,
}

/// One descriptor consumed from a resource's RX ring and leased from its
/// ownership ledger.  The pair backend uses this small value instead of
/// wrapping a single-resource packet lease so it can submit a copy to the
/// other resource's TX ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct XdpReceivedPacket {
    pub(crate) frame_index: u32,
    pub(crate) descriptor: XdpDescriptor,
}

/// One generated-pool frame reserved by the pair's cross-interface path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct XdpGeneratedFrame {
    pub(crate) frame_index: u32,
    pub(crate) address: u64,
}

impl<'batch, 'syscalls, S: Syscalls> XdpBatchCore<'batch, 'syscalls, S> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        views: XdpRingViews<'batch>,
        socket: &'batch OwnedXdpFd<'syscalls, S>,
        umem: &'batch mut [u8],
        ownership: &'batch mut XdpOwnership,
        batch_state: &'batch mut BatchState,
        interface: IfId,
        fill_wakeup_pending: &'batch mut bool,
        tx_wakeup_pending: &'batch mut bool,
        kind: BatchState,
    ) -> Self {
        *batch_state = kind;
        let XdpRingViews {
            fill,
            completion,
            rx,
            tx,
        } = views;
        Self {
            fill,
            completion,
            rx,
            tx,
            socket: Some(socket),
            umem,
            ownership,
            batch_state,
            interface,
            fill_wakeup_pending,
            tx_wakeup_pending,
        }
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_without_socket(
        views: XdpRingViews<'batch>,
        umem: &'batch mut [u8],
        ownership: &'batch mut XdpOwnership,
        batch_state: &'batch mut BatchState,
        interface: IfId,
        fill_wakeup_pending: &'batch mut bool,
        tx_wakeup_pending: &'batch mut bool,
        kind: BatchState,
    ) -> Self {
        *batch_state = kind;
        let XdpRingViews {
            fill,
            completion,
            rx,
            tx,
        } = views;
        Self {
            fill,
            completion,
            rx,
            tx,
            socket: None,
            umem,
            ownership,
            batch_state,
            interface,
            fill_wakeup_pending,
            tx_wakeup_pending,
        }
    }

    pub(crate) fn release_state(&mut self) {
        *self.batch_state = BatchState::Idle;
    }

    pub(crate) const fn interface(&self) -> IfId {
        self.interface
    }

    fn record_first(error: &mut Option<XdpIoError>, source: XdpIoError) {
        if error.is_none() {
            *error = Some(source);
        }
    }

    pub(crate) fn refill_fill(&mut self) -> Result<(), XdpIoError> {
        let mut first_error = None;
        while let Some(frame_index) = self.ownership.next_free_rx() {
            let mut reservation = match self.fill.reserve(1) {
                Ok(reservation) => reservation,
                Err(NativeRingError::RingFull) => break,
                Err(source) => {
                    first_error = Some(XdpIoError::Ring {
                        ring: RingName::Fill,
                        source,
                    });
                    break;
                }
            };
            if let Err(source) = self.ownership.reserve_fill(frame_index) {
                reservation.release_cancel();
                Self::record_first(&mut first_error, source);
                break;
            }
            if let Err(source) = reservation.write(self.ownership.frame_base(frame_index)) {
                reservation.release_cancel();
                let _ = self.ownership.cancel_fill(frame_index);
                Self::record_first(
                    &mut first_error,
                    XdpIoError::Ring {
                        ring: RingName::Fill,
                        source,
                    },
                );
                break;
            }
            if let Err(source) = self.ownership.publish_fill(frame_index) {
                reservation.release_cancel();
                let _ = self.ownership.cancel_fill(frame_index);
                Self::record_first(&mut first_error, source);
                break;
            }
            match reservation.release_submit() {
                Ok(publication) => {
                    if let Err(source) =
                        self.observe_publication(RingName::Fill, publication.need_wakeup())
                    {
                        Self::record_first(&mut first_error, source);
                        break;
                    }
                }
                // With a complete one-entry reservation, the only native
                // error after the descriptor write is the post-publication
                // ring-flag observation. The chunk therefore remains kernel
                // owned even when this result is an error.
                Err(source) => {
                    Self::record_first(
                        &mut first_error,
                        XdpIoError::Ring {
                            ring: RingName::Fill,
                            source,
                        },
                    );
                    break;
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn observe_publication(
        &mut self,
        ring: RingName,
        observation: Result<NeedWakeup, NativeRingError>,
    ) -> Result<(), XdpIoError> {
        match observation {
            Ok(NeedWakeup::Required) => {
                match ring {
                    RingName::Fill => *self.fill_wakeup_pending = true,
                    RingName::Tx => *self.tx_wakeup_pending = true,
                    RingName::Rx | RingName::Completion => {}
                }
                Ok(())
            }
            Ok(NeedWakeup::NotRequired) => Ok(()),
            Err(source) => Err(XdpIoError::Ring { ring, source }),
        }
    }

    pub(crate) fn reclaim_completions(&mut self) -> Result<(), XdpIoError> {
        let mut first_error = None;
        loop {
            let mut acquisition = match self.completion.acquire(1) {
                Ok(acquisition) => acquisition,
                Err(NativeRingError::RingEmpty) => break,
                Err(source) => {
                    first_error = Some(XdpIoError::Ring {
                        ring: RingName::Completion,
                        source,
                    });
                    break;
                }
            };
            let address = match acquisition.read() {
                Ok(address) => address,
                Err(source) => {
                    acquisition.release_cancel();
                    first_error.get_or_insert(XdpIoError::Ring {
                        ring: RingName::Completion,
                        source,
                    });
                    break;
                }
            };
            if let Err(source) = acquisition.release_consume() {
                first_error.get_or_insert(XdpIoError::Ring {
                    ring: RingName::Completion,
                    source,
                });
                break;
            }
            match self.ownership.complete_tx(address) {
                Ok(frame_index) => {
                    if let Err(source) = self.ownership.recycle_completion(frame_index) {
                        Self::record_first(&mut first_error, source);
                    }
                }
                Err(source) => {
                    Self::record_first(&mut first_error, source);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Consumes at most one RX descriptor and leases its frame.
    ///
    /// `Ok(None)` is the normal empty-ring result.  The caller owns the
    /// returned lease until it recycles or submits it.  This is deliberately a
    /// lower-level primitive than [`XdpPacketBatch`]: the fixed pair uses the
    /// same resource core to submit a bounded copy to the other member's TX
    /// ring while preserving both ownership ledgers.
    pub(crate) fn receive_one(&mut self) -> Result<Option<XdpReceivedPacket>, XdpIoError> {
        let mut acquisition = match self.rx.acquire(1) {
            Ok(acquisition) => acquisition,
            Err(NativeRingError::RingEmpty) => return Ok(None),
            Err(source) => {
                return Err(XdpIoError::Ring {
                    ring: RingName::Rx,
                    source,
                });
            }
        };
        let descriptor = match acquisition.read() {
            Ok(descriptor) => descriptor,
            Err(source) => {
                acquisition.release_cancel();
                return Err(XdpIoError::Ring {
                    ring: RingName::Rx,
                    source,
                });
            }
        };
        if let Err(source) = acquisition.release_consume() {
            return Err(XdpIoError::Ring {
                ring: RingName::Rx,
                source,
            });
        }
        let frame_index = match self.ownership.lease_rx(descriptor) {
            Ok(frame_index) => frame_index,
            Err(source) => {
                self.ownership.recover_rx_descriptor(descriptor);
                return Err(source);
            }
        };
        Ok(Some(XdpReceivedPacket {
            frame_index,
            descriptor,
        }))
    }

    /// Reserves one frame from this resource's generated pool.
    ///
    /// A missing generated frame is a normal bounded TX rejection and is
    /// returned as `Ok(None)`.  Geometry that cannot hold the requested
    /// visible length is treated the same way; both cases leave the ownership
    /// ledger unchanged.
    pub(crate) fn reserve_generated_frame(
        &mut self,
        frame_len: usize,
    ) -> Result<Option<XdpGeneratedFrame>, XdpIoError> {
        let visible_capacity = usize::try_from(
            self.ownership
                .frame_size
                .checked_sub(self.ownership.data_offset)
                .expect("validated UMEM data offset fits the frame size"),
        )
        .expect("validated visible frame capacity fits usize");
        if frame_len == 0 || frame_len > visible_capacity {
            return Ok(None);
        }
        let Some(frame_index) = self.ownership.next_free_generated() else {
            return Ok(None);
        };
        self.ownership.lease_generated(frame_index)?;
        Ok(Some(XdpGeneratedFrame {
            frame_index,
            address: self.ownership.data_address(frame_index),
        }))
    }

    /// Borrows the visible bytes of a descriptor already validated by
    /// `receive_one`.
    pub(crate) fn packet_bytes(&self, descriptor: XdpDescriptor) -> &[u8] {
        let start =
            usize::try_from(descriptor.address).expect("validated AF_XDP address fits usize");
        let len = usize::try_from(descriptor.len).expect("validated AF_XDP length fits");
        let end = start
            .checked_add(len)
            .expect("validated AF_XDP packet range cannot overflow");
        &self.umem[start..end]
    }

    /// Mutably borrows the visible bytes of a descriptor already validated by
    /// `receive_one`.
    pub(crate) fn packet_bytes_mut(&mut self, descriptor: XdpDescriptor) -> &mut [u8] {
        let start =
            usize::try_from(descriptor.address).expect("validated AF_XDP address fits usize");
        let len = usize::try_from(descriptor.len).expect("validated AF_XDP length fits");
        let end = start
            .checked_add(len)
            .expect("validated AF_XDP packet range cannot overflow");
        &mut self.umem[start..end]
    }

    /// Borrows the visible bytes of a generated frame reserved by
    /// `reserve_generated_frame`.
    pub(crate) fn generated_bytes_mut(&mut self, address: u64, frame_len: usize) -> &mut [u8] {
        let start = usize::try_from(address).expect("validated AF_XDP address fits usize");
        let end = start
            .checked_add(frame_len)
            .expect("validated AF_XDP generated range cannot overflow");
        &mut self.umem[start..end]
    }

    fn rollback_to_lease(&mut self, frame_index: u32, tx_state: XdpChunkState) {
        match tx_state {
            XdpChunkState::TxReserved => {
                let _ = self.ownership.cancel_tx_reservation(frame_index);
                let _ = self.ownership.cancel_pending_tx(frame_index);
            }
            XdpChunkState::PendingTx => {
                let _ = self.ownership.cancel_pending_tx(frame_index);
            }
            _ => {}
        }
    }

    /// Attempts one TX publication. `Ok(Some(error))` means that the
    /// descriptor was published and only the post-publication observation
    /// failed; the caller must count that case as accepted.
    pub(crate) fn submit_tx(
        &mut self,
        frame_index: u32,
        address: u64,
        len: u32,
        egress: IfId,
    ) -> Result<Option<XdpIoError>, XdpIoError> {
        if egress != self.interface {
            return Err(XdpIoError::InterfaceMismatch {
                expected: self.interface,
                actual: egress,
            });
        }
        self.ownership.stage_tx(frame_index)?;
        let mut reservation = match self.tx.reserve(1) {
            Ok(reservation) => reservation,
            Err(source) => {
                let _ = self.ownership.cancel_pending_tx(frame_index);
                return Err(XdpIoError::Ring {
                    ring: RingName::Tx,
                    source,
                });
            }
        };
        if let Err(source) = self.ownership.reserve_tx(frame_index) {
            reservation.release_cancel();
            let _ = self.ownership.cancel_pending_tx(frame_index);
            return Err(source);
        }
        let descriptor = XdpDescriptor {
            address,
            len,
            options: 0,
        };
        if let Err(source) = reservation.write(descriptor) {
            reservation.release_cancel();
            let _ = self.ownership.cancel_tx_reservation(frame_index);
            let _ = self.ownership.cancel_pending_tx(frame_index);
            return Err(XdpIoError::Ring {
                ring: RingName::Tx,
                source,
            });
        }
        if let Err(source) = self.ownership.publish_tx(frame_index, address) {
            reservation.release_cancel();
            self.rollback_to_lease(frame_index, XdpChunkState::TxReserved);
            return Err(source);
        }
        match reservation.release_submit() {
            Ok(publication) => {
                match self.observe_publication(RingName::Tx, publication.need_wakeup()) {
                    Ok(()) => Ok(None),
                    Err(source) => Ok(Some(source)),
                }
            }
            // See the matching Fill path: the reservation is complete, so a
            // native error here is observed after publication.
            Err(source) => Ok(Some(XdpIoError::Ring {
                ring: RingName::Tx,
                source,
            })),
        }
    }

    pub(crate) fn recycle_frame(&mut self, frame_index: u32) -> Result<(), XdpIoError> {
        self.ownership.recycle_lease(frame_index)
    }

    pub(crate) fn wake_if_needed(&mut self) -> Result<(), XdpIoError> {
        if !*self.fill_wakeup_pending && !*self.tx_wakeup_pending {
            return Ok(());
        }
        let Some(socket) = self.socket else {
            *self.fill_wakeup_pending = false;
            *self.tx_wakeup_pending = false;
            return Ok(());
        };
        let mut first_error = None;
        if *self.fill_wakeup_pending {
            // With XDP_USE_NEED_WAKEUP, publishing new Fill entries requires
            // a zero-timeout poll to kick the RX path. A timeout is harmless:
            // the publication is already visible and the next tick retries
            // if the syscall itself fails.
            match socket.poll(1, 0) {
                Ok(_) => *self.fill_wakeup_pending = false,
                Err(error) => first_error = Some(map_poll_error(error)),
            }
        }
        if *self.tx_wakeup_pending {
            match socket.send_to_wakeup() {
                Ok(()) => *self.tx_wakeup_pending = false,
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(map_wakeup_error(error));
                    }
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl<S: Syscalls> Drop for XdpBatchCore<'_, '_, S> {
    fn drop(&mut self) {
        if *self.batch_state != BatchState::Idle {
            let _ = self.reclaim_completions();
            let _ = self.refill_fill();
            let _ = self.wake_if_needed();
            *self.batch_state = BatchState::Idle;
        }
    }
}

#[derive(Default)]
struct PacketCounters {
    tx_requested: usize,
    tx_accepted: usize,
    tx_rejected: usize,
    recycled: usize,
}

struct XdpPacketBatchWithOps<'batch, 'syscalls, S: Syscalls> {
    core: XdpBatchCore<'batch, 'syscalls, S>,
    remaining: usize,
    counters: PacketCounters,
    error: Option<XdpIoError>,
    finished: bool,
}

impl<'batch, 'syscalls, S: Syscalls> XdpPacketBatchWithOps<'batch, 'syscalls, S> {
    fn new(core: XdpBatchCore<'batch, 'syscalls, S>, budget: usize) -> Self {
        Self {
            core,
            remaining: budget,
            counters: PacketCounters::default(),
            error: None,
            finished: false,
        }
    }

    fn record_error(&mut self, source: XdpIoError) {
        if self.error.is_none() {
            self.error = Some(source);
        }
    }

    fn start_housekeeping(&mut self) {
        if let Err(source) = self.core.reclaim_completions() {
            self.record_error(source);
        }
        if let Err(source) = self.core.refill_fill() {
            self.record_error(source);
        }
    }

    fn next_slot(&mut self) -> Option<XdpPacketSlotWithOps<'_, 'batch, 'syscalls, S>> {
        if self.remaining == 0 || self.error.is_some() {
            return None;
        }
        let mut acquisition = match self.core.rx.acquire(1) {
            Ok(acquisition) => acquisition,
            Err(NativeRingError::RingEmpty) => {
                self.remaining = 0;
                return None;
            }
            Err(source) => {
                self.record_error(XdpIoError::Ring {
                    ring: RingName::Rx,
                    source,
                });
                self.remaining = 0;
                return None;
            }
        };
        let descriptor = match acquisition.read() {
            Ok(descriptor) => descriptor,
            Err(source) => {
                acquisition.release_cancel();
                self.record_error(XdpIoError::Ring {
                    ring: RingName::Rx,
                    source,
                });
                self.remaining = 0;
                return None;
            }
        };
        if let Err(source) = acquisition.release_consume() {
            self.record_error(XdpIoError::Ring {
                ring: RingName::Rx,
                source,
            });
            self.remaining = 0;
            return None;
        }
        self.remaining -= 1;
        let frame_index = match self.core.ownership.lease_rx(descriptor) {
            Ok(frame_index) => frame_index,
            Err(source) => {
                self.core.ownership.recover_rx_descriptor(descriptor);
                self.record_error(source);
                if let Err(fill_error) = self.core.refill_fill() {
                    self.record_error(fill_error);
                }
                return None;
            }
        };
        Some(XdpPacketSlotWithOps {
            batch: self,
            frame_index,
            descriptor,
        })
    }

    fn complete_slot(
        &mut self,
        frame_index: u32,
        descriptor: XdpDescriptor,
        completion: SlotCompletion,
    ) {
        match completion {
            SlotCompletion::Transmit(egress) => {
                self.counters.tx_requested = self
                    .counters
                    .tx_requested
                    .checked_add(1)
                    .expect("AF_XDP TX request count cannot overflow");
                match self
                    .core
                    .submit_tx(frame_index, descriptor.address, descriptor.len, egress)
                {
                    Ok(post_error) => {
                        self.counters.tx_accepted = self
                            .counters
                            .tx_accepted
                            .checked_add(1)
                            .expect("AF_XDP TX accepted count cannot overflow");
                        if let Some(source) = post_error {
                            self.record_error(source);
                        }
                    }
                    Err(source) => {
                        self.counters.tx_rejected = self
                            .counters
                            .tx_rejected
                            .checked_add(1)
                            .expect("AF_XDP TX rejected count cannot overflow");
                        if !is_expected_tx_rejection(source) {
                            self.record_error(source);
                        }
                        if let Err(recycle_error) = self.core.recycle_frame(frame_index) {
                            self.record_error(recycle_error);
                        }
                        if let Err(fill_error) = self.core.refill_fill() {
                            self.record_error(fill_error);
                        }
                    }
                }
            }
            SlotCompletion::Recycle(_)
            | SlotCompletion::Consume(_)
            | SlotCompletion::LeaseAbandoned => {
                if let Err(source) = self.core.recycle_frame(frame_index) {
                    self.record_error(source);
                } else {
                    self.counters.recycled = self
                        .counters
                        .recycled
                        .checked_add(1)
                        .expect("AF_XDP recycled count cannot overflow");
                }
                if let Err(source) = self.core.refill_fill() {
                    self.record_error(source);
                }
            }
        }
    }

    fn finish_inner(&mut self) -> BatchCompletion<XdpIoError> {
        if let Err(source) = self.core.reclaim_completions() {
            self.record_error(source);
        }
        if let Err(source) = self.core.refill_fill() {
            self.record_error(source);
        }
        if let Err(source) = self.core.wake_if_needed() {
            self.record_error(source);
        }
        self.core.release_state();
        self.finished = true;
        BatchCompletion {
            tx_requested: self.counters.tx_requested,
            tx_accepted: self.counters.tx_accepted,
            tx_rejected: self.counters.tx_rejected,
            recycled: self.counters.recycled,
            error: self.error,
        }
    }
}

impl<S: Syscalls> Drop for XdpPacketBatchWithOps<'_, '_, S> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = self.core.reclaim_completions();
        let _ = self.core.refill_fill();
        let _ = self.core.wake_if_needed();
        self.core.release_state();
        self.finished = true;
    }
}

struct XdpPacketSlotWithOps<'slot, 'batch, 'syscalls, S: Syscalls> {
    batch: &'slot mut XdpPacketBatchWithOps<'batch, 'syscalls, S>,
    frame_index: u32,
    descriptor: XdpDescriptor,
}

impl<S: Syscalls> PacketSlot for XdpPacketSlotWithOps<'_, '_, '_, S> {
    fn ingress(&self) -> IfId {
        self.batch.core.interface
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        let start =
            usize::try_from(self.descriptor.address).expect("validated AF_XDP address fits usize");
        let len = usize::try_from(self.descriptor.len).expect("validated AF_XDP length fits");
        let end = start
            .checked_add(len)
            .expect("validated AF_XDP packet range cannot overflow");
        &mut self.batch.core.umem[start..end]
    }

    fn complete(self, completion: SlotCompletion) {
        let Self {
            batch,
            frame_index,
            descriptor,
        } = self;
        batch.complete_slot(frame_index, descriptor, completion);
    }
}

/// Core-facing RX batch for the live Linux AF_XDP resource.
pub struct XdpPacketBatch<'batch> {
    inner: XdpPacketBatchWithOps<'batch, 'static, LinuxSyscalls>,
}

impl<'batch> PacketBatch for XdpPacketBatch<'batch> {
    type Error = XdpIoError;
    type Slot<'slot>
        = XdpPacketSlot<'slot, 'batch>
    where
        Self: 'slot;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        self.inner
            .next_slot()
            .map(|slot| PacketLease::new(XdpPacketSlot { inner: slot }))
    }

    fn finish(mut self) -> BatchCompletion<Self::Error> {
        self.inner.finish_inner()
    }
}

/// Core-facing RX slot for the live Linux AF_XDP resource.
pub struct XdpPacketSlot<'slot, 'batch> {
    inner: XdpPacketSlotWithOps<'slot, 'batch, 'static, LinuxSyscalls>,
}

impl PacketSlot for XdpPacketSlot<'_, '_> {
    fn ingress(&self) -> IfId {
        self.inner.ingress()
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.inner.bytes_mut()
    }

    fn complete(self, completion: SlotCompletion) {
        self.inner.complete(completion);
    }
}

#[derive(Default)]
struct GeneratedCounters {
    attempts: usize,
    allocated: usize,
    failed: usize,
    requested: usize,
    cancelled: usize,
    abandoned: usize,
    accepted: usize,
    rejected: usize,
}

struct XdpGeneratedBatchWithOps<'batch, 'syscalls, S: Syscalls> {
    core: XdpBatchCore<'batch, 'syscalls, S>,
    egress: IfId,
    pending: Option<u32>,
    counters: GeneratedCounters,
    error: Option<XdpIoError>,
    finished: bool,
    disabled: bool,
}

impl<'batch, 'syscalls, S: Syscalls> XdpGeneratedBatchWithOps<'batch, 'syscalls, S> {
    fn new(core: XdpBatchCore<'batch, 'syscalls, S>, egress: IfId) -> Self {
        Self {
            core,
            egress,
            pending: None,
            counters: GeneratedCounters::default(),
            error: None,
            finished: false,
            disabled: false,
        }
    }

    fn record_error(&mut self, source: XdpIoError) {
        if self.error.is_none() {
            self.error = Some(source);
        }
    }

    fn allocate_slot(
        &mut self,
        frame_len: usize,
    ) -> Result<XdpGeneratedSlotWithOps<'_, 'batch, 'syscalls, S>, GeneratedAllocationError> {
        self.counters.attempts = self
            .counters
            .attempts
            .checked_add(1)
            .expect("AF_XDP generated allocation count cannot overflow");
        if self.disabled {
            self.counters.failed += 1;
            return Err(GeneratedAllocationError::Unavailable);
        }
        if frame_len == 0 {
            self.counters.failed += 1;
            return Err(GeneratedAllocationError::ZeroLength);
        }
        let visible_capacity =
            usize::try_from(self.core.ownership.frame_size - self.core.ownership.data_offset)
                .expect("visible frame size fits");
        if frame_len > visible_capacity {
            self.counters.failed += 1;
            return Err(GeneratedAllocationError::FrameTooLarge);
        }
        if self.egress != self.core.interface {
            self.counters.failed += 1;
            self.record_error(XdpIoError::InterfaceMismatch {
                expected: self.core.interface,
                actual: self.egress,
            });
            return Err(GeneratedAllocationError::Unavailable);
        }
        if self.pending.is_some() {
            self.counters.failed += 1;
            return Err(GeneratedAllocationError::Unavailable);
        }
        let Some(frame_index) = self.core.ownership.next_free_generated() else {
            self.counters.failed += 1;
            return Err(GeneratedAllocationError::Unavailable);
        };
        if let Err(source) = self.core.ownership.lease_generated(frame_index) {
            self.counters.failed += 1;
            self.record_error(source);
            return Err(GeneratedAllocationError::Unavailable);
        }
        self.pending = Some(frame_index);
        let address = self.core.ownership.data_address(frame_index);
        self.counters.allocated = self
            .counters
            .allocated
            .checked_add(1)
            .expect("AF_XDP generated allocation count cannot overflow");
        Ok(XdpGeneratedSlotWithOps {
            batch: self,
            frame_index,
            address,
            frame_len,
        })
    }

    fn complete_slot(
        &mut self,
        frame_index: u32,
        address: u64,
        frame_len: usize,
        completion: GeneratedSlotCompletion,
    ) {
        match completion {
            GeneratedSlotCompletion::Transmit => {
                self.counters.requested = self
                    .counters
                    .requested
                    .checked_add(1)
                    .expect("AF_XDP generated request count cannot overflow");
                let len = match u32::try_from(frame_len) {
                    Ok(len) => len,
                    Err(_) => {
                        self.counters.rejected += 1;
                        self.record_error(XdpIoError::InvalidDescriptor {
                            address,
                            len: u32::MAX,
                            options: 0,
                        });
                        let _ = self.core.recycle_frame(frame_index);
                        self.pending = None;
                        return;
                    }
                };
                match self.core.submit_tx(frame_index, address, len, self.egress) {
                    Ok(post_error) => {
                        self.counters.accepted += 1;
                        if let Some(source) = post_error {
                            self.record_error(source);
                        }
                    }
                    Err(source) => {
                        self.counters.rejected += 1;
                        if !is_expected_tx_rejection(source) {
                            self.record_error(source);
                        }
                        if let Err(recycle_error) = self.core.recycle_frame(frame_index) {
                            self.record_error(recycle_error);
                        }
                    }
                }
            }
            GeneratedSlotCompletion::Cancelled => {
                self.counters.cancelled += 1;
                if let Err(source) = self.core.recycle_frame(frame_index) {
                    self.record_error(source);
                }
            }
            GeneratedSlotCompletion::Abandoned => {
                self.counters.abandoned += 1;
                if let Err(source) = self.core.recycle_frame(frame_index) {
                    self.record_error(source);
                }
            }
        }
        self.pending = None;
    }

    fn recycle_pending(&mut self) {
        let Some(frame_index) = self.pending.take() else {
            return;
        };
        self.counters.abandoned += 1;
        if let Err(source) = self.core.recycle_frame(frame_index) {
            self.record_error(source);
        }
    }

    fn finish_inner(&mut self) -> GeneratedBatchCompletion<XdpIoError> {
        if self.disabled {
            self.core.release_state();
            self.finished = true;
            return GeneratedBatchCompletion {
                attempts: self.counters.attempts,
                allocated: self.counters.allocated,
                failed: self.counters.failed,
                requested: self.counters.requested,
                cancelled: self.counters.cancelled,
                abandoned: self.counters.abandoned,
                accepted: self.counters.accepted,
                rejected: self.counters.rejected,
                error: self.error,
            };
        }
        self.recycle_pending();
        if let Err(source) = self.core.reclaim_completions() {
            self.record_error(source);
        }
        if let Err(source) = self.core.refill_fill() {
            self.record_error(source);
        }
        if let Err(source) = self.core.wake_if_needed() {
            self.record_error(source);
        }
        self.core.release_state();
        self.finished = true;
        GeneratedBatchCompletion {
            attempts: self.counters.attempts,
            allocated: self.counters.allocated,
            failed: self.counters.failed,
            requested: self.counters.requested,
            cancelled: self.counters.cancelled,
            abandoned: self.counters.abandoned,
            accepted: self.counters.accepted,
            rejected: self.counters.rejected,
            error: self.error,
        }
    }
}

impl<S: Syscalls> Drop for XdpGeneratedBatchWithOps<'_, '_, S> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.recycle_pending();
        if self.disabled {
            self.core.release_state();
            self.finished = true;
            return;
        }
        let _ = self.core.reclaim_completions();
        let _ = self.core.refill_fill();
        let _ = self.core.wake_if_needed();
        self.core.release_state();
        self.finished = true;
    }
}

struct XdpGeneratedSlotWithOps<'slot, 'batch, 'syscalls, S: Syscalls> {
    batch: &'slot mut XdpGeneratedBatchWithOps<'batch, 'syscalls, S>,
    frame_index: u32,
    address: u64,
    frame_len: usize,
}

impl<S: Syscalls> GeneratedPacketSlot for XdpGeneratedSlotWithOps<'_, '_, '_, S> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        let start = usize::try_from(self.address).expect("validated AF_XDP address fits usize");
        let end = start
            .checked_add(self.frame_len)
            .expect("validated AF_XDP generated range cannot overflow");
        &mut self.batch.core.umem[start..end]
    }

    fn complete(self, completion: GeneratedSlotCompletion) {
        let Self {
            batch,
            frame_index,
            address,
            frame_len,
        } = self;
        batch.complete_slot(frame_index, address, frame_len, completion);
    }
}

/// Core-facing generated batch for the live Linux AF_XDP resource.
pub struct XdpGeneratedBatch<'batch> {
    inner: XdpGeneratedBatchWithOps<'batch, 'static, LinuxSyscalls>,
}

impl<'batch> GeneratedPacketBatch for XdpGeneratedBatch<'batch> {
    type Error = XdpIoError;
    type Slot<'slot>
        = XdpGeneratedSlot<'slot, 'batch>
    where
        Self: 'slot;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        let slot = self.inner.allocate_slot(frame_len)?;
        Ok(GeneratedPacketLease::new(XdpGeneratedSlot { inner: slot }))
    }

    fn finish(mut self) -> GeneratedBatchCompletion<Self::Error> {
        self.inner.finish_inner()
    }
}

/// Core-facing generated slot for the live Linux AF_XDP resource.
pub struct XdpGeneratedSlot<'slot, 'batch> {
    inner: XdpGeneratedSlotWithOps<'slot, 'batch, 'static, LinuxSyscalls>,
}

impl GeneratedPacketSlot for XdpGeneratedSlot<'_, '_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        self.inner.bytes_mut()
    }

    fn complete(self, completion: GeneratedSlotCompletion) {
        self.inner.complete(completion);
    }
}

impl XdpResource<'_> {
    pub(crate) fn start_packet_batch(
        &mut self,
        budget: usize,
    ) -> Result<XdpPacketBatch<'_>, XdpIoError> {
        if self.data_path_raw_views_exposed() {
            return Err(XdpIoError::RawRingViewsExposed);
        }
        if !self.data_path_is_idle() {
            return Err(XdpIoError::BatchActive);
        }
        let core = self.make_data_path_core(BatchState::Rx)?;
        let mut batch = XdpPacketBatchWithOps::new(core, budget);
        batch.start_housekeeping();
        Ok(XdpPacketBatch { inner: batch })
    }

    pub(crate) fn start_generated_batch(&mut self, egress: IfId) -> XdpGeneratedBatch<'_> {
        let raw_views_exposed = self.data_path_raw_views_exposed();
        if !self.data_path_is_idle() || raw_views_exposed {
            let core = self
                .make_data_path_core(BatchState::Generated)
                .expect("checked native ring mappings remain available");
            let mut batch = XdpGeneratedBatchWithOps::new(core, egress);
            batch.disabled = true;
            batch.record_error(if raw_views_exposed {
                XdpIoError::RawRingViewsExposed
            } else {
                XdpIoError::BatchActive
            });
            return XdpGeneratedBatch { inner: batch };
        }
        let mut core = self
            .make_data_path_core(BatchState::Generated)
            .expect("checked native ring mappings remain available");
        if let Err(source) = core.reclaim_completions() {
            let mut batch = XdpGeneratedBatchWithOps::new(core, egress);
            batch.record_error(source);
            return XdpGeneratedBatch { inner: batch };
        }
        if let Err(source) = core.refill_fill() {
            let mut batch = XdpGeneratedBatchWithOps::new(core, egress);
            batch.record_error(source);
            return XdpGeneratedBatch { inner: batch };
        }
        XdpGeneratedBatch {
            inner: XdpGeneratedBatchWithOps::new(core, egress),
        }
    }

    /// Waits for an RX ring producer event without making packet I/O block in
    /// `receive`. The socket is nonblocking; this helper is the explicit poll
    /// boundary for callers that want to sleep between ticks.
    pub fn wait_for_rx(&mut self, timeout: Duration) -> Result<bool, XdpIoError> {
        let timeout_millis = poll_timeout_ms(timeout);
        let result = self
            .bound_socket()
            .poll(1, timeout_millis)
            .map_err(map_poll_error)?;
        Ok(result.ready != 0 && result.events & 1 != 0)
    }
}

fn poll_timeout_ms(timeout: Duration) -> i32 {
    let millis = timeout.as_millis().min(i32::MAX as u128);
    // Preserve an explicit zero timeout for nonblocking probes, but do not
    // let a positive sub-millisecond wait turn into the same probe.
    let millis = if timeout.is_zero() {
        millis
    } else {
        millis.max(1)
    };
    millis.try_into().expect("bounded timeout fits i32")
}

impl PacketIo for XdpResource<'_> {
    type Error = XdpIoError;
    type Batch<'a>
        = XdpPacketBatch<'a>
    where
        Self: 'a;

    fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
        self.start_packet_batch(budget)
    }
}

impl GeneratedPacketIo for XdpResource<'_> {
    type Error = XdpIoError;
    type Batch<'a>
        = XdpGeneratedBatch<'a>
    where
        Self: 'a;

    fn begin_generated(&mut self, egress: IfId) -> Self::Batch<'_> {
        self.start_generated_batch(egress)
    }
}

impl PublicationQuiescenceBackend for XdpResource<'_> {
    type Error = XdpIoError;

    fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {
        if self.data_path_raw_views_exposed() {
            return Err(XdpIoError::RawRingViewsExposed);
        }
        if !self.data_path_is_idle() {
            return Err(XdpIoError::Quiescence {
                frame_index: None,
                state: XdpChunkState::Leased,
            });
        }
        if let Some((frame_index, state)) = self.data_path_nonquiescent_owner() {
            return Err(XdpIoError::Quiescence {
                frame_index: Some(frame_index),
                state,
            });
        }
        Ok(())
    }

    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
        if !self.data_path_is_idle() || self.data_path_raw_views_exposed() {
            PublicationQuiescenceDisposition::SkipIo
        } else {
            PublicationQuiescenceDisposition::ContinueOldIo
        }
    }

    fn quiescence_error_disposition(error: &Self::Error) -> PublicationQuiescenceDisposition {
        match error {
            XdpIoError::Quiescence {
                state: XdpChunkState::TxOwnedByKernel | XdpChunkState::CompletionAvailable,
                ..
            } => PublicationQuiescenceDisposition::ContinueOldIo,
            _ => PublicationQuiescenceDisposition::SkipIo,
        }
    }
}

// SAFETY: the resource owns the socket, all mmap regions, the UMEM borrow,
// ownership ledger, cursors, and wakeup state in one non-detachable value.
// Every batch and slot is lifetime-bounded to that exact value. `ring_views`
// exposes the same mappings only through a mutable borrow of the resource, so
// it cannot coexist with this data path or mutate the ledger behind a live
// batch; it therefore cannot detach or replace authoritative state.
#[allow(unsafe_code)]
unsafe impl PublicationBackendAuthority for XdpResource<'_> {}

// SAFETY: this command only waits on the exact resource's private AF_XDP fd;
// it returns no backend or authoritative alias and cannot replace ownership
// state.
#[allow(unsafe_code)]
unsafe impl PublicationBackendControl for XdpResource<'_> {
    type Command = Duration;
    type Response = Result<bool, XdpIoError>;

    fn execute_publication_backend_command(&mut self, command: Self::Command) -> Self::Response {
        self.wait_for_rx(command)
    }
}

fn is_expected_tx_rejection(error: XdpIoError) -> bool {
    matches!(
        error,
        XdpIoError::Ring {
            source: NativeRingError::RingFull,
            ..
        } | XdpIoError::InterfaceMismatch { .. }
    )
}

fn map_poll_error(error: ResourceError) -> XdpIoError {
    match error {
        ResourceError::Platform(error) => XdpIoError::Platform(error),
        ResourceError::Argument(error) => XdpIoError::Syscall {
            stage: map_syscall_stage(argument_stage(error)),
            errno: None,
        },
        ResourceError::Syscall(error) => XdpIoError::Syscall {
            stage: map_syscall_stage(error.stage),
            errno: error.errno.raw(),
        },
    }
}

fn map_wakeup_error(error: ResourceError) -> XdpIoError {
    match error {
        ResourceError::Platform(error) => XdpIoError::Platform(error),
        ResourceError::Argument(_) => XdpIoError::Wakeup { errno: None },
        ResourceError::Syscall(error) => XdpIoError::Wakeup {
            errno: error.errno.raw(),
        },
    }
}

const fn argument_stage(error: SyscallArgumentError) -> SyscallStage {
    match error {
        SyscallArgumentError::InvalidFileDescriptor => SyscallStage::PollSocket,
        SyscallArgumentError::ZeroLength { stage }
        | SyscallArgumentError::LengthDoesNotFitSockLen { stage, .. }
        | SyscallArgumentError::LengthDoesNotFitAddressSpace { stage, .. } => stage,
        SyscallArgumentError::OffsetDoesNotFitOffT { .. }
        | SyscallArgumentError::KernelLengthOutOfBounds { .. } => SyscallStage::PollSocket,
    }
}

const fn map_syscall_stage(stage: SyscallStage) -> crate::XdpSetupStage {
    match stage {
        SyscallStage::OpenSocket => crate::XdpSetupStage::OpenSocket,
        SyscallStage::SetSocketOption => crate::XdpSetupStage::SetSocketOption,
        SyscallStage::GetSocketOption => crate::XdpSetupStage::GetSocketOption,
        SyscallStage::MapMemory => crate::XdpSetupStage::MapMemory,
        SyscallStage::UnmapMemory => crate::XdpSetupStage::UnmapMemory,
        SyscallStage::BindSocket => crate::XdpSetupStage::BindSocket,
        SyscallStage::PollSocket => crate::XdpSetupStage::PollSocket,
        SyscallStage::SendToSocket => crate::XdpSetupStage::SendToSocket,
        SyscallStage::CloseSocket => crate::XdpSetupStage::CloseSocket,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruster_core::{ConsumeReason, DropReason};

    // The model tests below use the same native role-typed ring views as the
    // live path. Kernel-side producer/consumer cursor changes are performed by
    // the finite byte-array seam, never by an alternate packet implementation.
    const OFFSETS: crate::abi::XdpRingOffset = crate::abi::XdpRingOffset {
        producer: 0,
        consumer: 64,
        descriptors: 192,
        flags: 128,
    };
    const RING_ENTRIES: u32 = 8;
    const FRAME_SIZE: usize = 2_048;
    const HEADROOM: usize = 256;
    const DATA_OFFSET: usize = HEADROOM + crate::XDP_PACKET_HEADROOM as usize;
    const FRAME_COUNT: usize = 8;
    const RX_FRAMES: usize = 6;

    #[test]
    fn positive_submillisecond_wait_rounds_up_to_one_poll_millisecond() {
        assert_eq!(poll_timeout_ms(Duration::from_nanos(500)), 1);
    }

    #[test]
    fn watchdog_quarter_never_becomes_zero_xdp_poll_timeout() {
        let raw_watchdog_quarter = Duration::from_micros(2) / 4;

        assert_eq!(raw_watchdog_quarter, Duration::from_nanos(500));
        assert_eq!(poll_timeout_ms(raw_watchdog_quarter), 1);
    }

    #[repr(align(64))]
    struct RingMemory([u8; 384]);

    impl RingMemory {
        fn new() -> Self {
            Self([0; 384])
        }

        fn write_u32(&mut self, offset: usize, value: u32) {
            self.0[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }

        fn read_u32(&self, offset: usize) -> u32 {
            u32::from_ne_bytes(self.0[offset..offset + 4].try_into().expect("u32"))
        }

        fn write_descriptor(&mut self, offset: usize, descriptor: XdpDescriptor) {
            self.0[offset..offset + 8].copy_from_slice(&descriptor.address.to_ne_bytes());
            self.0[offset + 8..offset + 12].copy_from_slice(&descriptor.len.to_ne_bytes());
            self.0[offset + 12..offset + 16].copy_from_slice(&descriptor.options.to_ne_bytes());
        }

        fn read_descriptor(&self, offset: usize) -> XdpDescriptor {
            XdpDescriptor {
                address: u64::from_ne_bytes(
                    self.0[offset..offset + 8].try_into().expect("address"),
                ),
                len: u32::from_ne_bytes(self.0[offset + 8..offset + 12].try_into().expect("len")),
                options: u32::from_ne_bytes(
                    self.0[offset + 12..offset + 16]
                        .try_into()
                        .expect("options"),
                ),
            }
        }

        fn write_u64(&mut self, offset: usize, value: u64) {
            self.0[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
        }
    }

    struct Harness {
        umem: Box<[u8]>,
        fill: RingMemory,
        completion: RingMemory,
        rx: RingMemory,
        tx: RingMemory,
        ownership: XdpOwnership,
        state: BatchState,
        fill_wakeup_pending: bool,
        tx_wakeup_pending: bool,
        interface: IfId,
    }

    impl Harness {
        fn new() -> Self {
            let config = UmemConfig::new(
                FRAME_COUNT as u32,
                FRAME_SIZE as u32,
                HEADROOM as u32,
                RX_FRAMES as u32,
                (FRAME_COUNT - RX_FRAMES) as u32,
                0,
            )
            .expect("test UMEM");
            Self {
                umem: vec![0; FRAME_COUNT * FRAME_SIZE].into_boxed_slice(),
                fill: RingMemory::new(),
                completion: RingMemory::new(),
                rx: RingMemory::new(),
                tx: RingMemory::new(),
                ownership: XdpOwnership::new(config),
                state: BatchState::Idle,
                fill_wakeup_pending: false,
                tx_wakeup_pending: false,
                interface: IfId(7),
            }
        }

        fn core(&mut self, kind: BatchState) -> XdpBatchCore<'_, 'static, LinuxSyscalls> {
            let interface = self.interface;
            let Harness {
                umem,
                fill,
                completion,
                rx,
                tx,
                ownership,
                state,
                fill_wakeup_pending,
                tx_wakeup_pending,
                ..
            } = self;
            XdpBatchCore::new_without_socket(
                XdpRingViews {
                    fill: FillProducer::new(
                        &mut fill.0,
                        OFFSETS,
                        crate::RingEntries::new(RingName::Fill, RING_ENTRIES)
                            .expect("fill capacity"),
                    )
                    .expect("fill view"),
                    completion: CompletionConsumer::new(
                        &mut completion.0,
                        OFFSETS,
                        crate::RingEntries::new(RingName::Completion, RING_ENTRIES)
                            .expect("completion capacity"),
                    )
                    .expect("completion view"),
                    rx: RxConsumer::new(
                        &mut rx.0,
                        OFFSETS,
                        crate::RingEntries::new(RingName::Rx, RING_ENTRIES).expect("rx capacity"),
                    )
                    .expect("rx view"),
                    tx: TxProducer::new(
                        &mut tx.0,
                        OFFSETS,
                        crate::RingEntries::new(RingName::Tx, RING_ENTRIES).expect("tx capacity"),
                    )
                    .expect("tx view"),
                },
                umem,
                ownership,
                state,
                interface,
                fill_wakeup_pending,
                tx_wakeup_pending,
                kind,
            )
        }

        fn kernel_publish_rx(&mut self, frame_index: u32, len: u32) {
            // A kernel-produced RX descriptor consumes one address from the
            // application-published Fill queue. Keep the fake cursors in the
            // same state transition as the live kernel so refill tests can
            // distinguish available ring space from ledger ownership.
            let fill_consumer = self.fill.read_u32(64);
            self.fill.write_u32(64, fill_consumer.wrapping_add(1));
            let producer = self.rx.read_u32(0);
            let offset = 192 + (usize::try_from(producer).expect("cursor") & 7) * 16;
            self.rx.write_descriptor(
                offset,
                XdpDescriptor {
                    address: u64::from(frame_index) * FRAME_SIZE as u64 + DATA_OFFSET as u64,
                    len,
                    options: 0,
                },
            );
            self.rx.write_u32(0, producer.wrapping_add(1));
        }

        fn kernel_publish_completion(&mut self, address: u64) {
            let producer = self.completion.read_u32(0);
            let offset = 192 + (usize::try_from(producer).expect("cursor") & 7) * 8;
            self.completion.write_u64(offset, address);
            self.completion.write_u32(0, producer.wrapping_add(1));
        }

        fn ring_occupied(&self, ring: &RingMemory) -> u32 {
            ring.read_u32(0).wrapping_sub(ring.read_u32(64))
        }
    }

    fn initialize(harness: &mut Harness) {
        {
            let mut core = harness.core(BatchState::Maintenance);
            core.refill_fill().expect("initial fill");
            core.release_state();
        }
        assert_eq!(
            harness.ownership.count(XdpChunkState::FillOwnedByKernel),
            RX_FRAMES
        );
        assert_eq!(harness.ring_occupied(&harness.fill), RX_FRAMES as u32);
    }

    #[test]
    fn a_budget_limits_packets_and_zero_is_empty() {
        let mut harness = Harness::new();
        initialize(&mut harness);
        harness.kernel_publish_rx(0, 64);
        harness.kernel_publish_rx(1, 64);
        let completion = {
            let core = harness.core(BatchState::Rx);
            let mut batch = XdpPacketBatch {
                inner: XdpPacketBatchWithOps::new(core, 1),
            };
            let mut lease = batch.next_packet().expect("one packet within budget");
            assert_eq!(lease.bytes_mut().len(), 64);
            drop(lease);
            assert!(batch.next_packet().is_none());
            batch.finish()
        };
        assert_eq!(completion.tx_requested, 0);
        assert_eq!(harness.ring_occupied(&harness.rx), 1);

        let completion = {
            let core = harness.core(BatchState::Rx);
            let mut empty = XdpPacketBatch {
                inner: XdpPacketBatchWithOps::new(core, 0),
            };
            assert!(empty.next_packet().is_none());
            empty.finish()
        };
        assert!(completion.invariants_hold());
    }

    #[test]
    fn b_recycling_every_slot_returns_fill_and_preserves_invariant() {
        let mut harness = Harness::new();
        initialize(&mut harness);
        harness.kernel_publish_rx(0, 64);
        harness.kernel_publish_rx(1, 64);
        let completion = {
            let core = harness.core(BatchState::Rx);
            let mut batch = XdpPacketBatch {
                inner: XdpPacketBatchWithOps::new(core, 2),
            };
            let first = batch.next_packet().expect("first");
            first.recycle(DropReason::RouteMiss);
            let second = batch.next_packet().expect("second");
            second.consume(ConsumeReason::ArpControl);
            batch.finish()
        };
        assert_eq!(completion.recycled, 2);
        assert!(completion.invariants_hold());
        // The two generated-packet chunks remain free; both RX chunks were
        // recycled and immediately returned to Fill.
        assert_eq!(
            harness.ownership.count(XdpChunkState::Free),
            FRAME_COUNT - RX_FRAMES
        );
        assert_eq!(
            harness.ownership.count(XdpChunkState::FillOwnedByKernel),
            RX_FRAMES
        );
        assert_eq!(harness.ring_occupied(&harness.fill), RX_FRAMES as u32);
    }

    #[test]
    fn c_transmit_publishes_tx_and_preserves_accounting() {
        let mut harness = Harness::new();
        initialize(&mut harness);
        harness.kernel_publish_rx(0, 64);
        let interface = harness.interface;
        let completion = {
            let core = harness.core(BatchState::Rx);
            let mut batch = XdpPacketBatch {
                inner: XdpPacketBatchWithOps::new(core, 1),
            };
            let slot = batch.next_packet().expect("RX slot");
            slot.commit(interface);
            batch.finish()
        };
        assert_eq!(
            (
                completion.tx_requested,
                completion.tx_accepted,
                completion.tx_rejected
            ),
            (1, 1, 0)
        );
        assert!(completion.invariants_hold());
        assert_eq!(harness.ring_occupied(&harness.tx), 1);
        assert_eq!(harness.ownership.count(XdpChunkState::TxOwnedByKernel), 1);
        assert_eq!(
            harness.tx.read_descriptor(192),
            XdpDescriptor {
                address: DATA_OFFSET as u64,
                len: 64,
                options: 0,
            }
        );
    }

    #[test]
    fn d_full_tx_ring_rejects_and_reclaims_the_frame() {
        let mut harness = Harness::new();
        initialize(&mut harness);
        harness.kernel_publish_rx(0, 64);
        // Make the application-visible TX ring full without changing the
        // ledger; the submission then rolls the leased frame back and frees it.
        harness.tx.write_u32(0, RING_ENTRIES);
        harness.tx.write_u32(64, 0);
        let interface = harness.interface;
        let completion = {
            let core = harness.core(BatchState::Rx);
            let mut batch = XdpPacketBatch {
                inner: XdpPacketBatchWithOps::new(core, 1),
            };
            let slot = batch.next_packet().expect("RX slot");
            slot.commit(interface);
            batch.finish()
        };
        assert_eq!(
            (
                completion.tx_requested,
                completion.tx_accepted,
                completion.tx_rejected
            ),
            (1, 0, 1)
        );
        assert!(completion.invariants_hold());
        assert_eq!(
            harness.ownership.count(XdpChunkState::Free),
            FRAME_COUNT - RX_FRAMES
        );
        assert_eq!(harness.ring_occupied(&harness.tx), RING_ENTRIES);
    }

    #[test]
    fn e_drop_returns_recycled_chunks_to_fill() {
        let mut harness = Harness::new();
        initialize(&mut harness);
        harness.kernel_publish_rx(0, 64);
        {
            let core = harness.core(BatchState::Rx);
            let mut batch = XdpPacketBatch {
                inner: XdpPacketBatchWithOps::new(core, 1),
            };
            let slot = batch.next_packet().expect("RX slot");
            slot.recycle(DropReason::RouteMiss);
            drop(batch);
        }
        assert_eq!(
            harness.ownership.count(XdpChunkState::FillOwnedByKernel),
            RX_FRAMES
        );
        assert_eq!(harness.ring_occupied(&harness.fill), RX_FRAMES as u32);
    }

    #[test]
    fn f_processing_error_keeps_fill_recovery_and_invariant() {
        let mut harness = Harness::new();
        initialize(&mut harness);
        harness.kernel_publish_rx(0, 64);
        harness.kernel_publish_rx(1, 0);
        let completion = {
            let core = harness.core(BatchState::Rx);
            let mut batch = XdpPacketBatch {
                inner: XdpPacketBatchWithOps::new(core, 2),
            };
            let first = batch.next_packet().expect("valid slot");
            first.recycle(DropReason::RouteMiss);
            assert!(batch.next_packet().is_none());
            batch.finish()
        };
        assert!(completion.error.is_some());
        assert!(completion.invariants_hold());
        assert_eq!(
            harness.ownership.count(XdpChunkState::FillOwnedByKernel),
            RX_FRAMES
        );
    }

    #[test]
    fn g_completion_drain_makes_tx_chunk_reusable() {
        let mut harness = Harness::new();
        initialize(&mut harness);
        harness.kernel_publish_rx(0, 64);
        let interface = harness.interface;
        let address = {
            let core = harness.core(BatchState::Rx);
            let mut batch = XdpPacketBatch {
                inner: XdpPacketBatchWithOps::new(core, 1),
            };
            let slot = batch.next_packet().expect("RX slot");
            slot.commit(interface);
            let completion = batch.finish();
            assert!(completion.invariants_hold());
            DATA_OFFSET as u64
        };
        harness.kernel_publish_completion(address);
        {
            let mut core = harness.core(BatchState::Maintenance);
            core.reclaim_completions().expect("completion drain");
            core.release_state();
        }
        assert_eq!(harness.ownership.count(XdpChunkState::Free), 3);
        // The returned frame can now be filled again without an ownership
        // collision.
        {
            let mut core = harness.core(BatchState::Maintenance);
            core.refill_fill().expect("re-use completed frame");
            core.release_state();
        }
        assert_eq!(
            harness.ownership.count(XdpChunkState::FillOwnedByKernel),
            RX_FRAMES
        );
        assert_eq!(
            harness.ownership.count(XdpChunkState::Free),
            FRAME_COUNT - RX_FRAMES
        );
    }

    #[test]
    fn h_empty_fill_and_rx_finish_normally_with_zero_packets() {
        let mut harness = Harness::new();
        initialize(&mut harness);
        // Kernel consumes every published Fill address; no RX descriptor is
        // produced, leaving the application with no available packet.
        harness.fill.write_u32(64, harness.fill.read_u32(0));
        let completion = {
            let core = harness.core(BatchState::Rx);
            let mut batch = XdpPacketBatch {
                inner: XdpPacketBatchWithOps::new(core, 64),
            };
            assert!(batch.next_packet().is_none());
            batch.finish()
        };
        assert_eq!(completion.tx_requested, 0);
        assert!(completion.invariants_hold());
        assert_eq!(harness.ring_occupied(&harness.fill), 0);
    }
}
