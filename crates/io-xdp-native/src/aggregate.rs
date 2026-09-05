//! Fixed two-resource AF_XDP composition for a full-service LAN/WAN worker.
//!
//! Each member retains its own socket, UMEM borrow, four rings, and ownership
//! ledger.  A cross-link packet is copied into a fixed generated frame owned
//! by the destination resource before that resource's TX descriptor is
//! published.  This keeps the aggregate statically dispatched while allowing
//! an ingress packet from either link to be transmitted on the other link
//! without pretending that two UMEMs share addresses.

use std::time::Duration;

use ruster_core::{
    BatchCompletion, GeneratedAllocationError, GeneratedBatchCompletion, GeneratedPacketBatch,
    GeneratedPacketIo, GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion, IfId,
    PacketBatch, PacketIo, PacketLease, PacketSlot, PublicationBackendAuthority,
    PublicationBackendControl, PublicationQuiescenceBackend, PublicationQuiescenceDisposition,
    SlotCompletion,
};

use crate::{
    data_path::{BatchState, XdpBatchCore, XdpReceivedPacket},
    native_unsafe::syscall::LinuxSyscalls,
    XdpGeneratedBatch, XdpGeneratedSlot, XdpIoError, XdpPairIoError, XdpResource,
    XdpResourcePairError, XdpResourcePairIndex,
};

/// A fixed aggregate containing exactly two independently configured AF_XDP
/// resources.
///
/// The pair is intended for a full-service candidate with two logical links,
/// such as LAN and WAN.  A separate `XskMap`, redirect program, and attachment
/// may be created for each member.  Consequently equal queue ids on different
/// interfaces are valid: queue-map keys are local to each map and each XDP
/// program is attached to only one link.
pub struct XdpResourcePair<'umem> {
    first: XdpResource<'umem>,
    second: XdpResource<'umem>,
}

impl<'umem> XdpResourcePair<'umem> {
    /// Creates a pair after checking that its logical and Linux interfaces are
    /// distinct.  The two resources retain their original UMEM borrows.
    pub fn new(
        first: XdpResource<'umem>,
        second: XdpResource<'umem>,
    ) -> Result<Self, XdpResourcePairError> {
        if first.interface_id() == second.interface_id() {
            return Err(XdpResourcePairError::DuplicateInterface {
                interface: first.interface_id(),
            });
        }
        if first.ifindex() == second.ifindex() {
            return Err(XdpResourcePairError::DuplicateIfindex {
                ifindex: first.ifindex(),
            });
        }
        Ok(Self { first, second })
    }

    /// Returns the first resource for cold setup of its map/program.
    ///
    /// The borrow is immutable and cannot expose the packet-path owner.  Use
    /// [`XskMap::register`](crate::XskMap::register) with this view before the
    /// pair is handed to the worker.
    #[must_use]
    pub const fn first(&self) -> &XdpResource<'umem> {
        &self.first
    }

    /// Returns the second resource for cold setup of its map/program.
    #[must_use]
    pub const fn second(&self) -> &XdpResource<'umem> {
        &self.second
    }

    /// Returns the resource at a fixed pair position.
    #[must_use]
    pub const fn resource(&self, index: XdpResourcePairIndex) -> &XdpResource<'umem> {
        match index {
            XdpResourcePairIndex::First => &self.first,
            XdpResourcePairIndex::Second => &self.second,
        }
    }

    /// Returns both logical interface identifiers in pair order.
    #[must_use]
    pub const fn interface_ids(&self) -> (IfId, IfId) {
        (self.first.interface_id(), self.second.interface_id())
    }

    /// Waits for either member's RX ring.  Both sockets are polled; once the
    /// first socket is ready, the second receives a zero timeout so a command
    /// never adds a second full sleep interval.  A failure from either member
    /// is returned after both polls have been attempted.
    pub fn wait_for_rx(&mut self, timeout: Duration) -> Result<bool, XdpPairIoError> {
        let first = self.first.wait_for_rx(timeout);
        let second_timeout = if matches!(first, Ok(true)) {
            Duration::ZERO
        } else {
            timeout
        };
        let second = self.second.wait_for_rx(second_timeout);

        match (first, second) {
            (Err(error), _) => Err(pair_error(XdpResourcePairIndex::First, error)),
            (_, Err(error)) => Err(pair_error(XdpResourcePairIndex::Second, error)),
            (Ok(first_ready), Ok(second_ready)) => Ok(first_ready || second_ready),
        }
    }
}

impl PacketIo for XdpResourcePair<'_> {
    type Error = XdpPairIoError;
    type Batch<'a>
        = XdpPairPacketBatch<'a>
    where
        Self: 'a;

    fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
        if self.first.data_path_raw_views_exposed() {
            return Err(pair_error(
                XdpResourcePairIndex::First,
                XdpIoError::RawRingViewsExposed,
            ));
        }
        if self.second.data_path_raw_views_exposed() {
            return Err(pair_error(
                XdpResourcePairIndex::Second,
                XdpIoError::RawRingViewsExposed,
            ));
        }
        if !self.first.data_path_is_idle() {
            return Err(pair_error(
                XdpResourcePairIndex::First,
                XdpIoError::BatchActive,
            ));
        }
        if !self.second.data_path_is_idle() {
            return Err(pair_error(
                XdpResourcePairIndex::Second,
                XdpIoError::BatchActive,
            ));
        }
        // Keep one authoritative data-path core per member.  Unlike wrapping
        // two single-resource leases, these cores expose both RX and TX rings
        // to the pair slot, so a cross-interface transmit can reserve a
        // destination generated frame without borrowing the source frame as
        // the destination descriptor.
        let first_core = self
            .first
            .make_data_path_core(BatchState::Rx)
            .map_err(|error| pair_error(XdpResourcePairIndex::First, error))?;
        let first = XdpPairMemberBatch::new(first_core, budget);
        let second_core = self
            .second
            .make_data_path_core(BatchState::Rx)
            .map_err(|error| pair_error(XdpResourcePairIndex::Second, error))?;
        let second = XdpPairMemberBatch::new(second_core, budget);
        Ok(XdpPairPacketBatch {
            first,
            second,
            next_resource: 0,
            remaining: budget,
            first_exhausted: false,
            second_exhausted: false,
            counters: PairPacketCounters::default(),
            error: None,
        })
    }
}

/// One pair member's RX/TX/CQ core and ownership-preserving batch state.
struct XdpPairMemberBatch<'batch> {
    core: XdpBatchCore<'batch, 'static, LinuxSyscalls>,
    remaining: usize,
    error: Option<XdpIoError>,
}

impl<'batch> XdpPairMemberBatch<'batch> {
    fn new(mut core: XdpBatchCore<'batch, 'static, LinuxSyscalls>, budget: usize) -> Self {
        let mut error = None;
        if let Err(source) = core.reclaim_completions() {
            error = Some(source);
        }
        if let Err(source) = core.refill_fill() {
            if error.is_none() {
                error = Some(source);
            }
        }
        Self {
            core,
            remaining: budget,
            error,
        }
    }

    fn record_error(&mut self, source: XdpIoError) {
        if self.error.is_none() {
            self.error = Some(source);
        }
    }

    fn next_packet(&mut self) -> Option<XdpReceivedPacket> {
        if self.remaining == 0 || self.error.is_some() {
            return None;
        }
        match self.core.receive_one() {
            Ok(Some(packet)) => {
                self.remaining -= 1;
                Some(packet)
            }
            Ok(None) => None,
            Err(source) => {
                self.record_error(source);
                if let Err(fill_error) = self.core.refill_fill() {
                    self.record_error(fill_error);
                }
                None
            }
        }
    }

    /// Recycles an ingress lease and restores its RX/FILL availability.  The
    /// boolean reports whether the lease transition itself succeeded; a later
    /// refill observation may still be recorded as a batch error.
    fn recycle_input(&mut self, frame_index: u32) -> bool {
        if let Err(source) = self.core.recycle_frame(frame_index) {
            self.record_error(source);
            return false;
        }
        if let Err(source) = self.core.refill_fill() {
            self.record_error(source);
        }
        true
    }

    fn finish(mut self) -> Option<XdpIoError> {
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
        self.error
    }
}

#[derive(Default)]
struct PairPacketCounters {
    tx_requested: usize,
    tx_accepted: usize,
    tx_rejected: usize,
    recycled: usize,
}

/// RX batch that keeps a member active until its ring is empty, then visits
/// the other member.  Both member budgets are initialized from the pair
/// budget, while `remaining` is the single pair-level cap.
pub struct XdpPairPacketBatch<'batch> {
    first: XdpPairMemberBatch<'batch>,
    second: XdpPairMemberBatch<'batch>,
    next_resource: u8,
    remaining: usize,
    first_exhausted: bool,
    second_exhausted: bool,
    counters: PairPacketCounters,
    error: Option<XdpPairIoError>,
}

impl<'batch> PacketBatch for XdpPairPacketBatch<'batch> {
    type Error = XdpPairIoError;
    type Slot<'slot>
        = XdpPairPacketSlot<'slot, 'batch>
    where
        Self: 'slot;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        loop {
            if self.remaining == 0 || (self.first_exhausted && self.second_exhausted) {
                return None;
            }

            if self.next_resource == 0 {
                if !self.first_exhausted {
                    if let Some(packet) = self.first.next_packet() {
                        self.remaining -= 1;
                        return Some(PacketLease::new(XdpPairPacketSlot {
                            batch: self,
                            resource: XdpResourcePairIndex::First,
                            packet,
                        }));
                    }
                    self.first_exhausted = true;
                }
                self.next_resource = 1;
            } else {
                if !self.second_exhausted {
                    if let Some(packet) = self.second.next_packet() {
                        self.remaining -= 1;
                        return Some(PacketLease::new(XdpPairPacketSlot {
                            batch: self,
                            resource: XdpResourcePairIndex::Second,
                            packet,
                        }));
                    }
                    self.second_exhausted = true;
                }
                self.next_resource = 0;
            }
        }
    }

    fn finish(self) -> BatchCompletion<Self::Error> {
        let Self {
            first,
            second,
            counters,
            error,
            ..
        } = self;
        let first_error = first.finish();
        let second_error = second.finish();
        let member_error = first_error
            .map(|source| pair_error(XdpResourcePairIndex::First, source))
            .or_else(|| {
                second_error.map(|source| pair_error(XdpResourcePairIndex::Second, source))
            });
        BatchCompletion {
            tx_requested: counters.tx_requested,
            tx_accepted: counters.tx_accepted,
            tx_rejected: counters.tx_rejected,
            recycled: counters.recycled,
            error: error.or(member_error),
        }
    }
}

/// Packet slot that retains the ingress member and delegates completion to the
/// pair.  Cross-interface transmit allocates a destination generated frame,
/// copies the bounded packet bytes, submits that destination frame, and then
/// recycles the ingress frame.
pub struct XdpPairPacketSlot<'slot, 'batch> {
    batch: &'slot mut XdpPairPacketBatch<'batch>,
    resource: XdpResourcePairIndex,
    packet: XdpReceivedPacket,
}

impl PacketSlot for XdpPairPacketSlot<'_, '_> {
    fn ingress(&self) -> IfId {
        self.batch.member(self.resource).core.interface()
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.batch
            .member_mut(self.resource)
            .core
            .packet_bytes_mut(self.packet.descriptor)
    }

    fn complete(self, completion: SlotCompletion) {
        let Self {
            batch,
            resource,
            packet,
        } = self;
        batch.complete_slot(resource, packet, completion);
    }
}

impl<'batch> XdpPairPacketBatch<'batch> {
    fn member(&self, resource: XdpResourcePairIndex) -> &XdpPairMemberBatch<'batch> {
        match resource {
            XdpResourcePairIndex::First => &self.first,
            XdpResourcePairIndex::Second => &self.second,
        }
    }

    fn member_mut(&mut self, resource: XdpResourcePairIndex) -> &mut XdpPairMemberBatch<'batch> {
        match resource {
            XdpResourcePairIndex::First => &mut self.first,
            XdpResourcePairIndex::Second => &mut self.second,
        }
    }

    fn egress_resource(&self, egress: IfId) -> Option<XdpResourcePairIndex> {
        if self.first.core.interface() == egress {
            Some(XdpResourcePairIndex::First)
        } else if self.second.core.interface() == egress {
            Some(XdpResourcePairIndex::Second)
        } else {
            None
        }
    }

    fn complete_slot(
        &mut self,
        ingress: XdpResourcePairIndex,
        packet: XdpReceivedPacket,
        completion: SlotCompletion,
    ) {
        match completion {
            SlotCompletion::Transmit(egress) => {
                self.counters.tx_requested = self
                    .counters
                    .tx_requested
                    .checked_add(1)
                    .expect("AF_XDP pair TX request count cannot overflow");
                match self.egress_resource(egress) {
                    Some(egress_resource) if egress_resource == ingress => {
                        self.submit_same(ingress, packet, egress);
                    }
                    Some(egress_resource) => {
                        self.submit_cross(ingress, egress_resource, packet, egress);
                    }
                    None => {
                        self.counters.tx_rejected = self
                            .counters
                            .tx_rejected
                            .checked_add(1)
                            .expect("AF_XDP pair TX rejection count cannot overflow");
                        if self.error.is_none() {
                            self.error = Some(XdpPairIoError::EgressNotFound { egress });
                        }
                        let _ = self.member_mut(ingress).recycle_input(packet.frame_index);
                    }
                }
            }
            SlotCompletion::Recycle(_)
            | SlotCompletion::Consume(_)
            | SlotCompletion::LeaseAbandoned => {
                if self.member_mut(ingress).recycle_input(packet.frame_index) {
                    self.counters.recycled = self
                        .counters
                        .recycled
                        .checked_add(1)
                        .expect("AF_XDP pair recycled count cannot overflow");
                }
            }
        }
    }

    fn submit_same(
        &mut self,
        ingress: XdpResourcePairIndex,
        packet: XdpReceivedPacket,
        egress: IfId,
    ) {
        let outcome = {
            let member = self.member_mut(ingress);
            match member.core.submit_tx(
                packet.frame_index,
                packet.descriptor.address,
                packet.descriptor.len,
                egress,
            ) {
                Ok(post_error) => {
                    if let Some(source) = post_error {
                        member.record_error(source);
                    }
                    Ok(())
                }
                Err(source) => {
                    if !is_expected_tx_rejection(source) {
                        member.record_error(source);
                    }
                    let _ = member.recycle_input(packet.frame_index);
                    Err(source)
                }
            }
        };
        match outcome {
            Ok(()) => {
                self.counters.tx_accepted = self
                    .counters
                    .tx_accepted
                    .checked_add(1)
                    .expect("AF_XDP pair TX accepted count cannot overflow");
            }
            Err(_) => {
                self.counters.tx_rejected = self
                    .counters
                    .tx_rejected
                    .checked_add(1)
                    .expect("AF_XDP pair TX rejection count cannot overflow");
            }
        }
    }

    fn submit_cross(
        &mut self,
        ingress: XdpResourcePairIndex,
        egress_resource: XdpResourcePairIndex,
        packet: XdpReceivedPacket,
        egress: IfId,
    ) {
        let outcome = {
            let (source, destination) = self.members_mut_pair(ingress, egress_resource);
            let Some(destination_frame) = destination
                .core
                .reserve_generated_frame(
                    usize::try_from(packet.descriptor.len)
                        .expect("AF_XDP descriptor length fits usize"),
                )
                .inspect_err(|&source_error| {
                    destination.record_error(source_error);
                })
                .ok()
                .flatten()
            else {
                let _ = source.recycle_input(packet.frame_index);
                return self.record_cross_rejected();
            };
            let source_bytes = source.core.packet_bytes(packet.descriptor);
            let destination_bytes = destination
                .core
                .generated_bytes_mut(destination_frame.address, source_bytes.len());
            destination_bytes.copy_from_slice(source_bytes);
            match destination.core.submit_tx(
                destination_frame.frame_index,
                destination_frame.address,
                packet.descriptor.len,
                egress,
            ) {
                Ok(post_error) => {
                    if let Some(source_error) = post_error {
                        destination.record_error(source_error);
                    }
                    let _ = source.recycle_input(packet.frame_index);
                    Ok(())
                }
                Err(source_error) => {
                    if !is_expected_tx_rejection(source_error) {
                        destination.record_error(source_error);
                    }
                    if let Err(recycle_error) = destination
                        .core
                        .recycle_frame(destination_frame.frame_index)
                    {
                        destination.record_error(recycle_error);
                    }
                    let _ = source.recycle_input(packet.frame_index);
                    Err(source_error)
                }
            }
        };
        match outcome {
            Ok(()) => {
                self.counters.tx_accepted = self
                    .counters
                    .tx_accepted
                    .checked_add(1)
                    .expect("AF_XDP pair cross-TX accepted count cannot overflow");
            }
            Err(_) => {
                self.counters.tx_rejected = self
                    .counters
                    .tx_rejected
                    .checked_add(1)
                    .expect("AF_XDP pair cross-TX rejection count cannot overflow");
            }
        }
    }

    fn members_mut_pair(
        &mut self,
        source: XdpResourcePairIndex,
        destination: XdpResourcePairIndex,
    ) -> (
        &mut XdpPairMemberBatch<'batch>,
        &mut XdpPairMemberBatch<'batch>,
    ) {
        match (source, destination) {
            (XdpResourcePairIndex::First, XdpResourcePairIndex::Second) => {
                (&mut self.first, &mut self.second)
            }
            (XdpResourcePairIndex::Second, XdpResourcePairIndex::First) => {
                (&mut self.second, &mut self.first)
            }
            _ => unreachable!("cross-interface destination differs from ingress"),
        }
    }

    fn record_cross_rejected(&mut self) {
        self.counters.tx_rejected = self
            .counters
            .tx_rejected
            .checked_add(1)
            .expect("AF_XDP pair cross-TX rejection count cannot overflow");
    }
}

fn is_expected_tx_rejection(error: XdpIoError) -> bool {
    matches!(
        error,
        XdpIoError::Ring {
            source: crate::NativeRingError::RingFull,
            ..
        } | XdpIoError::InterfaceMismatch { .. }
    )
}

impl GeneratedPacketIo for XdpResourcePair<'_> {
    type Error = XdpPairIoError;
    type Batch<'a>
        = XdpPairGeneratedBatch<'a>
    where
        Self: 'a;

    fn begin_generated(&mut self, egress: IfId) -> Self::Batch<'_> {
        if self.first.interface_id() == egress {
            return XdpPairGeneratedBatch::member(
                XdpResourcePairIndex::First,
                self.first.start_generated_batch(egress),
            );
        }
        if self.second.interface_id() == egress {
            return XdpPairGeneratedBatch::member(
                XdpResourcePairIndex::Second,
                self.second.start_generated_batch(egress),
            );
        }
        XdpPairGeneratedBatch::missing(egress)
    }
}

/// Generated-packet batch routed to one selected pair member.
pub struct XdpPairGeneratedBatch<'batch> {
    inner: Option<XdpGeneratedBatch<'batch>>,
    resource: Option<XdpResourcePairIndex>,
    attempts: usize,
    failed: usize,
    error: Option<XdpPairIoError>,
}

impl<'batch> XdpPairGeneratedBatch<'batch> {
    fn member(resource: XdpResourcePairIndex, inner: XdpGeneratedBatch<'batch>) -> Self {
        Self {
            inner: Some(inner),
            resource: Some(resource),
            attempts: 0,
            failed: 0,
            error: None,
        }
    }

    fn missing(egress: IfId) -> Self {
        Self {
            inner: None,
            resource: None,
            attempts: 0,
            failed: 0,
            error: Some(XdpPairIoError::EgressNotFound { egress }),
        }
    }
}

impl<'batch> GeneratedPacketBatch for XdpPairGeneratedBatch<'batch> {
    type Error = XdpPairIoError;
    type Slot<'a>
        = XdpPairGeneratedSlot<'a, 'batch>
    where
        Self: 'a;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        let Some(inner) = self.inner.as_mut() else {
            self.attempts = self.attempts.saturating_add(1);
            self.failed = self.failed.saturating_add(1);
            return Err(GeneratedAllocationError::Unavailable);
        };
        let slot = inner.allocate(frame_len)?;
        Ok(GeneratedPacketLease::new(XdpPairGeneratedSlot {
            inner: slot,
        }))
    }

    fn finish(self) -> GeneratedBatchCompletion<Self::Error> {
        let Self {
            inner,
            resource,
            attempts,
            failed,
            error,
        } = self;
        let Some(inner) = inner else {
            return GeneratedBatchCompletion {
                attempts,
                allocated: 0,
                failed,
                requested: 0,
                cancelled: 0,
                abandoned: 0,
                accepted: 0,
                rejected: 0,
                error,
            };
        };
        let completion = inner.finish();
        let inner_error = completion.error.map(|inner_error| {
            pair_error(
                resource.expect("a member batch always has a pair position"),
                inner_error,
            )
        });
        GeneratedBatchCompletion {
            attempts: completion.attempts,
            allocated: completion.allocated,
            failed: completion.failed,
            requested: completion.requested,
            cancelled: completion.cancelled,
            abandoned: completion.abandoned,
            accepted: completion.accepted,
            rejected: completion.rejected,
            error: error.or(inner_error),
        }
    }
}

/// Generated slot that delegates its UMEM borrow to one selected resource.
pub struct XdpPairGeneratedSlot<'slot, 'batch> {
    inner: GeneratedPacketLease<XdpGeneratedSlot<'slot, 'batch>>,
}

impl GeneratedPacketSlot for XdpPairGeneratedSlot<'_, '_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        self.inner.bytes_mut()
    }

    fn complete(self, completion: GeneratedSlotCompletion) {
        match completion {
            GeneratedSlotCompletion::Transmit => self.inner.commit(),
            GeneratedSlotCompletion::Cancelled => self.inner.cancel(),
            GeneratedSlotCompletion::Abandoned => drop(self.inner),
        }
    }
}

impl PublicationQuiescenceBackend for XdpResourcePair<'_> {
    type Error = XdpPairIoError;

    fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {
        let first = self.first.check_publication_quiescence();
        let second = self.second.check_publication_quiescence();
        if let Err(error) = first {
            return Err(pair_error(XdpResourcePairIndex::First, error));
        }
        if let Err(error) = second {
            return Err(pair_error(XdpResourcePairIndex::Second, error));
        }
        Ok(())
    }

    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
        combine_disposition(
            self.first.current_io_disposition(),
            self.second.current_io_disposition(),
        )
    }

    fn quiescence_error_disposition(error: &Self::Error) -> PublicationQuiescenceDisposition {
        match error {
            XdpPairIoError::Resource { resource, error } => match resource {
                XdpResourcePairIndex::First => {
                    <XdpResource<'static> as PublicationQuiescenceBackend>::
                        quiescence_error_disposition(error)
                }
                XdpResourcePairIndex::Second => {
                    <XdpResource<'static> as PublicationQuiescenceBackend>::
                        quiescence_error_disposition(error)
                }
            },
            XdpPairIoError::EgressNotFound { .. } => PublicationQuiescenceDisposition::SkipIo,
        }
    }
}

// SAFETY: the pair has immutable resource accessors only.  Every packet or
// generated batch borrows exactly one member, while quiescence checks both
// ownership ledgers.  No operation can replace, detach, or hide either member.
#[allow(unsafe_code)]
unsafe impl PublicationBackendAuthority for XdpResourcePair<'_> {}

// SAFETY: the only command is a pair-local poll.  It returns no resource,
// mutable alias, or publication state and polls both private sockets.
#[allow(unsafe_code)]
unsafe impl PublicationBackendControl for XdpResourcePair<'_> {
    type Command = Duration;
    type Response = Result<bool, XdpPairIoError>;

    fn execute_publication_backend_command(&mut self, command: Self::Command) -> Self::Response {
        self.wait_for_rx(command)
    }
}

fn pair_error(resource: XdpResourcePairIndex, error: XdpIoError) -> XdpPairIoError {
    XdpPairIoError::Resource { resource, error }
}

const fn combine_disposition(
    first: PublicationQuiescenceDisposition,
    second: PublicationQuiescenceDisposition,
) -> PublicationQuiescenceDisposition {
    match (first, second) {
        (PublicationQuiescenceDisposition::Stop, _)
        | (_, PublicationQuiescenceDisposition::Stop) => PublicationQuiescenceDisposition::Stop,
        (PublicationQuiescenceDisposition::SkipIo, _)
        | (_, PublicationQuiescenceDisposition::SkipIo) => PublicationQuiescenceDisposition::SkipIo,
        _ => PublicationQuiescenceDisposition::ContinueOldIo,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        abi::XdpDescriptor, data_path::XdpOwnership, CompletionConsumer, FillProducer, RingEntries,
        RingName, RxConsumer, TxProducer, XdpRingViews,
    };
    use ruster_core::{
        internet_checksum, ipv4_header_checksum, validate_ipv4_frame, DropReason, PacketBatch,
    };
    use std::{
        cell::RefCell,
        fmt,
        os::fd::{IntoRawFd, RawFd},
        os::unix::net::UnixStream,
    };

    use crate::native_unsafe::syscall::{sealed, Errno, MapRequest, PollDescriptor, Syscalls};

    const OFFSETS: crate::abi::XdpRingOffset = crate::abi::XdpRingOffset {
        producer: 0,
        consumer: 64,
        descriptors: 192,
        flags: 128,
    };
    const RING_ENTRIES: u32 = 8;
    const FRAME_SIZE: usize = 2_048;
    const DATA_OFFSET: usize = crate::XDP_PACKET_HEADROOM as usize;
    const FRAME_COUNT: usize = 8;
    const RX_FRAMES: usize = 4;

    #[repr(align(64))]
    struct RingMemory([u8; 384]);

    impl RingMemory {
        fn new() -> Self {
            Self([0; 384])
        }

        fn read_u32(&self, offset: usize) -> u32 {
            u32::from_ne_bytes(self.0[offset..offset + 4].try_into().expect("u32"))
        }

        fn write_u32(&mut self, offset: usize, value: u32) {
            self.0[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }

        fn write_u64(&mut self, offset: usize, value: u64) {
            self.0[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
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
                len: u32::from_ne_bytes(
                    self.0[offset + 8..offset + 12].try_into().expect("length"),
                ),
                options: u32::from_ne_bytes(
                    self.0[offset + 12..offset + 16]
                        .try_into()
                        .expect("options"),
                ),
            }
        }
    }

    struct MemberHarness {
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

    impl MemberHarness {
        fn new(interface: IfId) -> Self {
            let config = crate::UmemConfig::new(
                FRAME_COUNT as u32,
                FRAME_SIZE as u32,
                0,
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
                interface,
            }
        }

        fn core(&mut self, kind: BatchState) -> XdpBatchCore<'_, 'static, LinuxSyscalls> {
            let interface = self.interface;
            let Self {
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
                        RingEntries::new(RingName::Fill, RING_ENTRIES).expect("fill entries"),
                    )
                    .expect("fill view"),
                    completion: CompletionConsumer::new(
                        &mut completion.0,
                        OFFSETS,
                        RingEntries::new(RingName::Completion, RING_ENTRIES)
                            .expect("completion entries"),
                    )
                    .expect("completion view"),
                    rx: RxConsumer::new(
                        &mut rx.0,
                        OFFSETS,
                        RingEntries::new(RingName::Rx, RING_ENTRIES).expect("rx entries"),
                    )
                    .expect("rx view"),
                    tx: TxProducer::new(
                        &mut tx.0,
                        OFFSETS,
                        RingEntries::new(RingName::Tx, RING_ENTRIES).expect("tx entries"),
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

        fn initialize(&mut self) {
            let mut core = self.core(BatchState::Maintenance);
            core.refill_fill().expect("initial fill");
            core.release_state();
        }

        fn kernel_publish_rx(&mut self, frame_index: u32, len: u32) {
            let fill_consumer = self.fill.read_u32(64);
            self.fill.write_u32(64, fill_consumer.wrapping_add(1));
            let producer = self.rx.read_u32(0);
            let offset = 192 + (producer as usize & (RING_ENTRIES as usize - 1)) * 16;
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
            let offset = 192 + (producer as usize & (RING_ENTRIES as usize - 1)) * 8;
            self.completion.write_u64(offset, address);
            self.completion.write_u32(0, producer.wrapping_add(1));
        }

        fn ring_occupied(&self, ring: &RingMemory) -> u32 {
            ring.read_u32(0).wrapping_sub(ring.read_u32(64))
        }
    }

    struct PairHarness {
        first: MemberHarness,
        second: MemberHarness,
    }

    impl PairHarness {
        fn new() -> Self {
            Self {
                first: MemberHarness::new(IfId(1)),
                second: MemberHarness::new(IfId(2)),
            }
        }

        fn initialize(&mut self) {
            self.first.initialize();
            self.second.initialize();
        }

        fn batch(&mut self, budget: usize) -> XdpPairPacketBatch<'_> {
            let first = XdpPairMemberBatch::new(self.first.core(BatchState::Rx), budget);
            let second = XdpPairMemberBatch::new(self.second.core(BatchState::Rx), budget);
            XdpPairPacketBatch {
                first,
                second,
                next_resource: 0,
                remaining: budget,
                first_exhausted: false,
                second_exhausted: false,
                counters: PairPacketCounters::default(),
                error: None,
            }
        }
    }

    /// Syscall fixture for aggregate tests that need a concrete
    /// `XdpResource`. The resource's operational methods are exercised over
    /// fake ring mappings, while the returned socket fd is a real Unix stream
    /// fd so the production Linux poll implementation remains in the path.
    struct AggregateSyscalls {
        socket_fd: RawFd,
        _peer: Option<UnixStream>,
        mappings: RefCell<Vec<Box<[u8]>>>,
    }

    impl AggregateSyscalls {
        fn new(ready: bool) -> Self {
            let (reader, peer) = UnixStream::pair().expect("test poll socket pair");
            let (socket_fd, peer) = if ready {
                // `/dev/zero` is readable immediately and avoids depending on
                // a write through the test socket under restricted runners.
                let ready_file = std::fs::File::open("/dev/zero").expect("test ready fd");
                (ready_file.into_raw_fd(), None)
            } else {
                (reader.into_raw_fd(), Some(peer))
            };
            Self {
                socket_fd,
                _peer: peer,
                mappings: RefCell::new(Vec::new()),
            }
        }
    }

    impl sealed::Sealed for AggregateSyscalls {}

    impl Syscalls for AggregateSyscalls {
        fn socket(
            &self,
            _domain: std::ffi::c_int,
            _kind: std::ffi::c_int,
            _protocol: std::ffi::c_int,
        ) -> Result<RawFd, Errno> {
            Ok(self.socket_fd)
        }

        fn set_socket_option(
            &self,
            _fd: RawFd,
            _level: std::ffi::c_int,
            _name: std::ffi::c_int,
            _value: &[u8],
            _length: u32,
        ) -> Result<(), Errno> {
            Ok(())
        }

        fn get_socket_option(
            &self,
            _fd: RawFd,
            _level: std::ffi::c_int,
            _name: std::ffi::c_int,
            value: &mut [u8],
            length: &mut u32,
        ) -> Result<(), Errno> {
            let encoded = crate::abi::encode_xdp_mmap_offsets(TEST_MMAP_OFFSETS);
            value[..encoded.len()].copy_from_slice(&encoded);
            *length = u32::try_from(encoded.len()).expect("test offsets length fits");
            Ok(())
        }

        fn mmap(&self, request: MapRequest) -> Result<*mut std::ffi::c_void, Errno> {
            let byte_len = match request {
                MapRequest::Anonymous { byte_len } | MapRequest::Shared { byte_len, .. } => {
                    byte_len
                }
            };
            let mut mapping = vec![0_u8; byte_len].into_boxed_slice();
            let address = mapping.as_mut_ptr().cast::<std::ffi::c_void>();
            self.mappings.borrow_mut().push(mapping);
            Ok(address)
        }

        fn munmap(&self, _address: *mut std::ffi::c_void, _byte_len: usize) -> Result<(), Errno> {
            Ok(())
        }

        fn bind(&self, _fd: RawFd, _address: &[u8], _length: u32) -> Result<(), Errno> {
            Ok(())
        }

        fn poll(
            &self,
            _descriptor: &mut PollDescriptor,
            _timeout_millis: std::ffi::c_int,
        ) -> Result<u32, Errno> {
            Ok(0)
        }

        fn send_to_wakeup(&self, _fd: RawFd) -> Result<(), Errno> {
            Ok(())
        }

        fn bpf(&self, _command: u32, _attr: &mut [u8]) -> Result<std::ffi::c_long, Errno> {
            Ok(0)
        }

        fn close(&self, _fd: RawFd) -> Result<(), Errno> {
            Ok(())
        }
    }

    const TEST_MMAP_OFFSETS: crate::abi::XdpMmapOffsets = crate::abi::XdpMmapOffsets {
        rx: OFFSETS,
        tx: OFFSETS,
        fill: OFFSETS,
        completion: OFFSETS,
    };

    #[allow(unsafe_code)]
    fn aggregate_resource(interface: IfId, ifindex: u32, ready: bool) -> XdpResource<'static> {
        let config = crate::UmemConfig::new(
            FRAME_COUNT as u32,
            FRAME_SIZE as u32,
            0,
            RX_FRAMES as u32,
            (FRAME_COUNT - RX_FRAMES) as u32,
            0,
        )
        .expect("test UMEM");
        let rings = crate::RingConfig::new(RING_ENTRIES, RING_ENTRIES, RING_ENTRIES, RING_ENTRIES)
            .expect("test rings");
        let syscalls: &'static AggregateSyscalls =
            Box::leak(Box::new(AggregateSyscalls::new(ready)));
        let memory: &'static mut [u8] =
            Box::leak(vec![0_u8; config.byte_len() as usize].into_boxed_slice());
        let owner = crate::XdpResourceBuilder::new(config, rings, ifindex, 0)
            .expect("test builder")
            .with_interface_id(interface)
            .build_with_syscalls(memory, syscalls)
            .expect("test resource");

        // SAFETY: `ResourceOwner` is structurally identical for the two
        // syscall marker types: every syscall-dependent field stores only a
        // reference, and this fixture never drops the retyped resource. Ring
        // operations use the fake mappings; the only production syscall kept
        // live for these tests is Linux poll over the real Unix fd above.
        unsafe { std::mem::transmute(owner) }
    }

    fn aggregate_pair(
        first_ready: bool,
        second_ready: bool,
    ) -> &'static mut XdpResourcePair<'static> {
        let first = aggregate_resource(IfId(1), 1, first_ready);
        let second = aggregate_resource(IfId(2), 2, second_ready);
        Box::leak(Box::new(
            XdpResourcePair::new(first, second).expect("test pair interfaces are distinct"),
        ))
    }

    struct HexBytes<'a>(&'a [u8]);

    impl fmt::Display for HexBytes<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            for (index, byte) in self.0.iter().copied().enumerate() {
                if index != 0 {
                    formatter.write_str(" ")?;
                }
                formatter.write_fmt(format_args!("{byte:02x}"))?;
            }
            Ok(())
        }
    }

    fn wire_valid_tcp_frame() -> [u8; 60] {
        let mut frame = [0_u8; 60];
        frame[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());

        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&40_u16.to_be_bytes());
        frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
        frame[22] = 64;
        frame[23] = 6;
        frame[26..30].copy_from_slice(&[192, 0, 2, 20]);
        frame[30..34].copy_from_slice(&[198, 51, 100, 1]);
        let ipv4_checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&ipv4_checksum.to_be_bytes());

        frame[34..36].copy_from_slice(&42_000_u16.to_be_bytes());
        frame[36..38].copy_from_slice(&443_u16.to_be_bytes());
        frame[38..42].copy_from_slice(&0x1122_3344_u32.to_be_bytes());
        frame[46] = 5 << 4;
        frame[47] = 0x02;
        frame[48..50].copy_from_slice(&65_535_u16.to_be_bytes());

        let mut pseudo_and_tcp = [0_u8; 32];
        pseudo_and_tcp[0..4].copy_from_slice(&[192, 0, 2, 20]);
        pseudo_and_tcp[4..8].copy_from_slice(&[198, 51, 100, 1]);
        pseudo_and_tcp[9] = 6;
        pseudo_and_tcp[10..12].copy_from_slice(&20_u16.to_be_bytes());
        pseudo_and_tcp[12..32].copy_from_slice(&frame[34..54]);
        let tcp_checksum = internet_checksum(&pseudo_and_tcp);
        frame[50..52].copy_from_slice(&tcp_checksum.to_be_bytes());

        // The bytes after IPv4 Total Length model Ethernet minimum-frame
        // padding. They must not be included in the TCP checksum range.
        frame[54..].fill(0xa5);
        frame
    }

    fn tcp_wire_residual(frame: &[u8]) -> u16 {
        let ipv4 = validate_ipv4_frame(frame).expect("wire-valid Ethernet/IPv4 header");
        let tcp_start = ipv4.header_offset + ipv4.header_len;
        let tcp_end = ipv4.header_offset + ipv4.total_len;
        let segment = &frame[tcp_start..tcp_end];
        assert_eq!(segment.len(), 20, "known fixture has a TCP header only");

        let mut pseudo_and_tcp = [0_u8; 32];
        pseudo_and_tcp[0..4].copy_from_slice(&ipv4.source.octets());
        pseudo_and_tcp[4..8].copy_from_slice(&ipv4.destination.octets());
        pseudo_and_tcp[9] = ipv4.protocol;
        pseudo_and_tcp[10..12].copy_from_slice(
            &u16::try_from(segment.len())
                .expect("segment length fits")
                .to_be_bytes(),
        );
        pseudo_and_tcp[12..].copy_from_slice(segment);
        internet_checksum(&pseudo_and_tcp)
    }

    fn tcp_pseudo_header_only_checksum(frame: &[u8]) -> u16 {
        let ipv4 = validate_ipv4_frame(frame).expect("wire-valid Ethernet/IPv4 header");
        let tcp_len = ipv4.total_len - ipv4.header_len;
        let mut pseudo_header = [0_u8; 12];
        pseudo_header[0..4].copy_from_slice(&ipv4.source.octets());
        pseudo_header[4..8].copy_from_slice(&ipv4.destination.octets());
        pseudo_header[9] = ipv4.protocol;
        pseudo_header[10..12].copy_from_slice(
            &u16::try_from(tcp_len)
                .expect("segment length fits")
                .to_be_bytes(),
        );
        internet_checksum(&pseudo_header)
    }

    fn tcp_checksum_valid_model(frame: &[u8]) -> bool {
        // This is the same wire contract as forwarding's private
        // `tcp_checksum_valid`: the pseudo-header plus the complete TCP
        // segment must have a zero Internet-checksum residual.
        tcp_wire_residual(frame) == 0
    }

    #[test]
    fn budget_one_reaches_a_packet_only_on_the_second_resource() {
        let mut harness = PairHarness::new();
        harness.initialize();
        harness.second.kernel_publish_rx(0, 64);

        let completion = {
            let mut batch = harness.batch(1);
            let packet = batch.next_packet().expect("second resource packet");
            assert_eq!(packet.ingress(), IfId(2));
            packet.recycle(DropReason::RouteMiss);
            assert!(batch.next_packet().is_none());
            batch.finish()
        };

        assert_eq!(completion.recycled, 1);
        assert_eq!(completion.tx_requested, 0);
        assert!(completion.invariants_hold());
    }

    #[test]
    fn a_member_is_drained_before_the_pair_advances_to_the_other_member() {
        let mut harness = PairHarness::new();
        harness.initialize();
        harness.first.kernel_publish_rx(0, 64);
        harness.first.kernel_publish_rx(1, 64);

        let completion = {
            let mut batch = harness.batch(4);
            for _ in 0..2 {
                let packet = batch.next_packet().expect("first resource packet");
                assert_eq!(packet.ingress(), IfId(1));
                packet.recycle(DropReason::RouteMiss);
            }
            assert!(batch.next_packet().is_none());
            batch.finish()
        };

        assert_eq!(completion.recycled, 2);
        assert!(completion.invariants_hold());
    }

    #[test]
    fn pair_budget_caps_packets_across_both_resources() {
        let mut harness = PairHarness::new();
        harness.initialize();
        for frame_index in 0..2 {
            harness.first.kernel_publish_rx(frame_index, 64);
            harness.second.kernel_publish_rx(frame_index, 64);
        }

        let completion = {
            let mut batch = harness.batch(3);
            for _ in 0..3 {
                let packet = batch.next_packet().expect("packet within pair budget");
                packet.recycle(DropReason::RouteMiss);
            }
            assert!(batch.next_packet().is_none());
            batch.finish()
        };

        assert_eq!(completion.recycled, 3);
        assert!(completion.invariants_hold());
    }

    #[test]
    fn a_zero_member_budget_does_not_consume_an_rx_packet() {
        let mut harness = PairHarness::new();
        harness.initialize();
        harness.first.kernel_publish_rx(0, 64);

        let mut member = XdpPairMemberBatch::new(harness.first.core(BatchState::Rx), 0);
        assert!(member.next_packet().is_none());
        assert!(member.finish().is_none());
        assert_eq!(harness.first.ring_occupied(&harness.first.rx), 1);
    }

    #[test]
    fn member_remaining_decrements_and_stops_at_its_budget() {
        let mut harness = PairHarness::new();
        harness.initialize();
        harness.first.kernel_publish_rx(0, 64);
        harness.first.kernel_publish_rx(1, 64);

        let completion = {
            let mut member = XdpPairMemberBatch::new(harness.first.core(BatchState::Rx), 1);
            let packet = member.next_packet().expect("packet within member budget");
            assert_eq!(packet.frame_index, 0);
            assert!(member.next_packet().is_none());
            assert!(member.recycle_input(packet.frame_index));
            member.finish()
        };

        assert!(completion.is_none());
        assert_eq!(harness.first.ring_occupied(&harness.first.rx), 1);
    }

    #[test]
    fn member_remaining_decrements_by_one_after_one_packet_from_non_unit_budget() {
        let mut harness = PairHarness::new();
        harness.initialize();
        harness.first.kernel_publish_rx(0, 64);

        let completion = {
            let mut member = XdpPairMemberBatch::new(harness.first.core(BatchState::Rx), 3);
            let packet = member.next_packet().expect("packet within member budget");
            assert_eq!(packet.frame_index, 0);
            assert_eq!(member.remaining, 2);
            assert!(member.recycle_input(packet.frame_index));
            member.finish()
        };

        assert!(completion.is_none());
    }

    #[test]
    fn rx_model_preserves_wire_tcp_frame_at_descriptor_address() {
        let mut harness = PairHarness::new();
        harness.initialize();
        let expected = wire_valid_tcp_frame();
        let source_address = DATA_OFFSET as u64;
        harness.first.umem[..DATA_OFFSET].fill(0xc3);
        harness.first.umem[DATA_OFFSET..DATA_OFFSET + expected.len()].copy_from_slice(&expected);
        harness
            .first
            .kernel_publish_rx(0, u32::try_from(expected.len()).expect("frame length fits"));
        assert_eq!(
            harness.first.rx.read_descriptor(192),
            XdpDescriptor {
                address: source_address,
                len: expected.len() as u32,
                options: 0,
            }
        );

        let completion = {
            let mut batch = harness.batch(1);
            let mut packet = batch.next_packet().expect("one RX packet");
            let observed = packet.bytes_mut();
            assert_eq!(observed, &expected);
            assert_eq!(observed.len(), expected.len());
            assert_eq!(observed[0..14], expected[0..14]);
            assert_eq!(observed[14..34], expected[14..34]);
            assert_eq!(observed[34..54], expected[34..54]);

            let ipv4 = validate_ipv4_frame(observed).expect("wire-valid Ethernet/IPv4 header");
            assert_eq!(ipv4.total_len, 40);
            assert_eq!(ipv4.protocol, 6);
            let mut pseudo_and_tcp = [0_u8; 32];
            pseudo_and_tcp[0..4].copy_from_slice(&ipv4.source.octets());
            pseudo_and_tcp[4..8].copy_from_slice(&ipv4.destination.octets());
            pseudo_and_tcp[9] = ipv4.protocol;
            pseudo_and_tcp[10..12].copy_from_slice(&20_u16.to_be_bytes());
            pseudo_and_tcp[12..32].copy_from_slice(&observed[34..54]);
            let tcp_residual = internet_checksum(&pseudo_and_tcp);
            eprintln!(
                "af_xdp_rx_model descriptor address={} frame_base=0 configured_headroom=0 kernel_headroom={} offset={} len={} ether_type=0x{:04x} ipv4_version_ihl=0x{:02x} ip_total_len={} tcp_source_port={} tcp_destination_port={} tcp_checksum_field=0x{:04x} tcp_checksum_residual=0x{:04x} bytes[0..54]={}",
                source_address,
                crate::XDP_PACKET_HEADROOM,
                DATA_OFFSET,
                observed.len(),
                u16::from_be_bytes([observed[12], observed[13]]),
                observed[14],
                ipv4.total_len,
                u16::from_be_bytes([observed[34], observed[35]]),
                u16::from_be_bytes([observed[36], observed[37]]),
                u16::from_be_bytes([observed[50], observed[51]]),
                tcp_residual,
                HexBytes(&observed[..54]),
            );
            assert_eq!(tcp_residual, 0);
            packet.commit(IfId(2));
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
        let destination_address = RX_FRAMES as u64 * FRAME_SIZE as u64 + DATA_OFFSET as u64;
        assert_eq!(
            harness.second.tx.read_descriptor(192),
            XdpDescriptor {
                address: destination_address,
                len: expected.len() as u32,
                options: 0,
            }
        );
        let destination_start = destination_address as usize;
        assert_eq!(
            &harness.second.umem[destination_start..destination_start + expected.len()],
            &expected
        );
    }

    #[test]
    fn rx_model_rejects_partial_tcp_checksum_without_wire_bytes() {
        let mut harness = PairHarness::new();
        harness.initialize();

        let mut expected = wire_valid_tcp_frame();
        let pseudo_header_checksum = tcp_pseudo_header_only_checksum(&expected);
        expected[50..52].copy_from_slice(&pseudo_header_checksum.to_be_bytes());
        let expected_residual = tcp_wire_residual(&expected);
        assert_ne!(expected_residual, 0);
        assert!(!tcp_checksum_valid_model(&expected));

        let source_address = DATA_OFFSET as u64;
        harness.first.umem[..DATA_OFFSET].fill(0xc3);
        harness.first.umem[DATA_OFFSET..DATA_OFFSET + expected.len()].copy_from_slice(&expected);
        harness
            .first
            .kernel_publish_rx(0, u32::try_from(expected.len()).expect("frame length fits"));
        assert_eq!(
            harness.first.rx.read_descriptor(192),
            XdpDescriptor {
                address: source_address,
                len: expected.len() as u32,
                options: 0,
            }
        );

        let completion = {
            let mut batch = harness.batch(1);
            let mut packet = batch.next_packet().expect("one RX packet");
            let observed = packet.bytes_mut();
            assert_eq!(observed, &expected);
            assert_eq!(observed.len(), expected.len());
            assert_eq!(observed[0..14], expected[0..14]);
            assert_eq!(observed[14..34], expected[14..34]);
            let ipv4 = validate_ipv4_frame(observed).expect("IPv4 header remains valid");
            assert_eq!(ipv4.protocol, 6);
            let observed_residual = tcp_wire_residual(observed);
            eprintln!(
                "af_xdp_rx_model_partial descriptor address={} frame_base=0 configured_headroom=0 kernel_headroom={} offset={} len={} ether_type=0x{:04x} ipv4_version_ihl=0x{:02x} ip_total_len={} tcp_checksum_field=0x{:04x} pseudo_header_only=0x{:04x} tcp_checksum_residual=0x{:04x} validator_accepts={} bytes[0..54]={}",
                source_address,
                crate::XDP_PACKET_HEADROOM,
                DATA_OFFSET,
                observed.len(),
                u16::from_be_bytes([observed[12], observed[13]]),
                observed[14],
                ipv4.total_len,
                u16::from_be_bytes([observed[50], observed[51]]),
                pseudo_header_checksum,
                observed_residual,
                tcp_checksum_valid_model(observed),
                HexBytes(&observed[..54]),
            );
            assert_ne!(observed_residual, 0);
            assert!(!tcp_checksum_valid_model(observed));
            packet.recycle(DropReason::FirewallTcpChecksumInvalid);
            batch.finish()
        };

        assert_eq!(completion.recycled, 1);
        assert!(completion.invariants_hold());
    }

    #[test]
    fn cross_interface_commit_copies_into_destination_umem_and_reclaims_cq() {
        let mut harness = PairHarness::new();
        harness.initialize();
        harness.first.kernel_publish_rx(0, 8);
        let payload = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

        let completion = {
            let mut batch = harness.batch(1);
            let mut packet = batch.next_packet().expect("first resource packet");
            packet.bytes_mut().copy_from_slice(&payload);
            packet.commit(IfId(2));
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
        let descriptor = harness.second.tx.read_descriptor(192);
        let expected_address = RX_FRAMES as u64 * FRAME_SIZE as u64 + DATA_OFFSET as u64;
        assert_eq!(
            descriptor,
            XdpDescriptor {
                address: expected_address,
                len: payload.len() as u32,
                options: 0,
            }
        );
        let start = expected_address as usize;
        assert_eq!(&harness.second.umem[start..start + payload.len()], &payload);
        assert_eq!(
            harness.first.ring_occupied(&harness.first.fill),
            RX_FRAMES as u32
        );

        harness.second.kernel_publish_completion(expected_address);
        {
            let mut core = harness.second.core(BatchState::Maintenance);
            core.reclaim_completions().expect("destination completion");
            core.refill_fill().expect("destination refill");
            core.release_state();
        }
        assert_eq!(
            harness.second.ownership.count(crate::XdpChunkState::Free),
            FRAME_COUNT - RX_FRAMES
        );
    }

    #[test]
    fn same_interface_commit_uses_ingress_tx_without_copying() {
        // Protect same-interface routing: an ingress frame is submitted on
        // its own TX ring and is not mistaken for a cross-interface copy.
        let mut harness = PairHarness::new();
        harness.initialize();
        harness.first.kernel_publish_rx(0, 8);
        let completion = {
            let mut batch = harness.batch(1);
            let packet = batch.next_packet().expect("first packet");
            packet.commit(IfId(1));
            batch.finish()
        };
        assert_eq!((completion.tx_accepted, completion.tx_rejected), (1, 0));
        assert_eq!(harness.first.ring_occupied(&harness.first.tx), 1);
        assert_eq!(harness.second.ring_occupied(&harness.second.tx), 0);
        assert_eq!(
            harness.first.tx.read_descriptor(192),
            XdpDescriptor {
                address: DATA_OFFSET as u64,
                len: 8,
                options: 0,
            }
        );
    }

    #[test]
    fn reverse_cross_interface_commit_uses_the_other_member_pair() {
        // Protect the reverse members_mut_pair arm: second-to-first traffic
        // copies into the first member's generated UMEM and TX ring.
        let mut harness = PairHarness::new();
        harness.initialize();
        harness.second.kernel_publish_rx(0, 4);
        let payload = [9, 8, 7, 6];
        let completion = {
            let mut batch = harness.batch(1);
            let mut packet = batch.next_packet().expect("second packet");
            packet.bytes_mut().copy_from_slice(&payload);
            packet.commit(IfId(1));
            batch.finish()
        };
        assert_eq!((completion.tx_accepted, completion.tx_rejected), (1, 0));
        let address = RX_FRAMES as u64 * FRAME_SIZE as u64 + DATA_OFFSET as u64;
        assert_eq!(
            harness.first.tx.read_descriptor(192),
            XdpDescriptor {
                address,
                len: payload.len() as u32,
                options: 0,
            }
        );
        assert_eq!(
            &harness.first.umem[address as usize..address as usize + payload.len()],
            &payload
        );
    }

    #[test]
    fn expected_full_ring_rejections_do_not_poison_same_or_cross_batches() {
        // Protect expected TX rejection handling: both same- and
        // cross-interface RingFull outcomes are counted and recycled without
        // becoming a batch error.
        let mut harness = PairHarness::new();
        harness.initialize();
        harness.first.kernel_publish_rx(0, 8);
        harness.first.tx.write_u32(0, RING_ENTRIES);
        let completion = {
            let mut batch = harness.batch(1);
            let packet = batch.next_packet().expect("same packet");
            packet.commit(IfId(1));
            batch.finish()
        };
        assert_eq!((completion.tx_accepted, completion.tx_rejected), (0, 1));
        assert!(completion.error.is_none());

        let mut harness = PairHarness::new();
        harness.initialize();
        harness.first.kernel_publish_rx(0, 8);
        harness.second.tx.write_u32(0, RING_ENTRIES);
        let completion = {
            let mut batch = harness.batch(1);
            let packet = batch.next_packet().expect("cross packet");
            packet.commit(IfId(2));
            batch.finish()
        };
        assert_eq!((completion.tx_accepted, completion.tx_rejected), (0, 1));
        assert!(completion.error.is_none());
        assert!(completion.invariants_hold());
    }

    #[test]
    fn cross_rejection_when_generated_pool_is_empty_is_counted_once() {
        // Protect cross rejection accounting: an exhausted destination pool
        // recycles the source and increments rejection exactly once.
        let mut harness = PairHarness::new();
        harness.initialize();
        {
            let mut core = harness.second.core(BatchState::Maintenance);
            for _ in RX_FRAMES..FRAME_COUNT {
                core.reserve_generated_frame(8)
                    .expect("reserve destination pool")
                    .expect("generated frame");
            }
            core.release_state();
        }
        harness.first.kernel_publish_rx(0, 8);
        let completion = {
            let mut batch = harness.batch(1);
            let packet = batch.next_packet().expect("source packet");
            packet.commit(IfId(2));
            batch.finish()
        };
        assert_eq!((completion.tx_accepted, completion.tx_rejected), (0, 1));
        assert!(completion.error.is_none());
        assert!(completion.invariants_hold());
    }

    #[test]
    fn member_processing_error_is_retained_until_pair_finish() {
        // Protect pair member error propagation: a malformed descriptor stops
        // that member and is reported with its fixed pair position.
        let mut harness = PairHarness::new();
        harness.initialize();
        harness.first.kernel_publish_rx(0, 0);
        let completion = {
            let mut batch = harness.batch(1);
            assert!(batch.next_packet().is_none());
            batch.finish()
        };
        assert!(matches!(
            completion.error,
            Some(XdpPairIoError::Resource {
                resource: XdpResourcePairIndex::First,
                ..
            })
        ));
        assert!(completion.invariants_hold());
    }

    #[test]
    fn missing_generated_egress_reports_attempt_and_failure() {
        // Protect missing-egress generated state: allocation is unavailable,
        // and both attempt and failure counters are observable at finish.
        let mut batch = XdpPairGeneratedBatch::missing(IfId(99));
        assert!(matches!(
            batch.allocate(8),
            Err(GeneratedAllocationError::Unavailable)
        ));
        let completion = batch.finish();
        assert_eq!((completion.attempts, completion.failed), (1, 1));
        assert!(matches!(
            completion.error,
            Some(XdpPairIoError::EgressNotFound { egress: IfId(99) })
        ));
    }

    #[test]
    fn pair_wait_for_rx_reports_second_member_readiness_and_timeout() {
        let ready_pair = aggregate_pair(false, true);
        assert_eq!(ready_pair.wait_for_rx(Duration::ZERO), Ok(true));

        let idle_pair = aggregate_pair(false, false);
        assert_eq!(idle_pair.wait_for_rx(Duration::ZERO), Ok(false));
    }

    #[test]
    fn pair_receive_rejects_an_active_first_member() {
        let pair = aggregate_pair(false, false);
        let generated = pair.first.start_generated_batch(IfId(1));
        std::mem::forget(generated);

        let result = PacketIo::receive(pair, 1);
        assert!(matches!(
            result
                .err()
                .expect("active first member must reject receive"),
            XdpPairIoError::Resource {
                resource: XdpResourcePairIndex::First,
                error: XdpIoError::BatchActive,
            }
        ));
    }

    #[test]
    fn pair_receive_rejects_an_active_second_member() {
        let pair = aggregate_pair(false, false);
        let generated = pair.second.start_generated_batch(IfId(2));
        std::mem::forget(generated);

        let result = PacketIo::receive(pair, 1);
        assert!(matches!(
            result
                .err()
                .expect("active second member must reject receive"),
            XdpPairIoError::Resource {
                resource: XdpResourcePairIndex::Second,
                error: XdpIoError::BatchActive,
            }
        ));
    }

    #[test]
    fn pair_generated_batches_route_each_selected_egress() {
        let pair = aggregate_pair(false, false);

        let first = GeneratedPacketIo::begin_generated(pair, IfId(1));
        assert_eq!(first.resource, Some(XdpResourcePairIndex::First));
        assert!(first.finish().error.is_none());

        let second = GeneratedPacketIo::begin_generated(pair, IfId(2));
        assert_eq!(second.resource, Some(XdpResourcePairIndex::Second));
        assert!(second.finish().error.is_none());
    }

    #[test]
    fn pair_generated_slot_exposes_exact_bytes_and_commits_transmit() {
        let pair = aggregate_pair(false, false);
        let mut batch = GeneratedPacketIo::begin_generated(pair, IfId(1));
        let mut slot = batch.allocate(8).expect("generated slot");
        assert_eq!(slot.bytes_mut().len(), 8);
        slot.bytes_mut().copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        slot.commit();

        let completion = batch.finish();
        assert_eq!(
            (
                completion.attempts,
                completion.allocated,
                completion.requested,
                completion.accepted,
                completion.rejected,
                completion.cancelled,
                completion.abandoned,
            ),
            (1, 1, 1, 1, 0, 0, 0)
        );
        assert!(completion.error.is_none());
        assert!(completion.invariants_hold());
    }

    #[test]
    fn pair_generated_slot_cancellation_recycles_the_inner_slot() {
        let pair = aggregate_pair(false, false);
        let mut batch = GeneratedPacketIo::begin_generated(pair, IfId(1));
        let slot = batch.allocate(8).expect("generated slot");
        slot.cancel();

        let completion = batch.finish();
        assert_eq!(
            (
                completion.attempts,
                completion.allocated,
                completion.requested,
                completion.accepted,
                completion.rejected,
                completion.cancelled,
                completion.abandoned,
            ),
            (1, 1, 0, 0, 0, 1, 0)
        );
        assert!(completion.error.is_none());
        assert!(completion.invariants_hold());
    }

    #[test]
    fn pair_publication_quiescence_reports_a_live_member_owner() {
        let pair = aggregate_pair(false, false);
        let generated = pair.first.start_generated_batch(IfId(1));
        std::mem::forget(generated);

        let result = PublicationQuiescenceBackend::check_publication_quiescence(pair);
        assert!(matches!(
            result.expect_err("live member must block quiescence"),
            XdpPairIoError::Resource {
                resource: XdpResourcePairIndex::First,
                error: XdpIoError::Quiescence {
                    frame_index: None,
                    state: crate::XdpChunkState::Leased,
                },
            }
        ));
    }

    #[test]
    fn expected_rejection_classifier_accepts_only_bounded_tx_failures() {
        // Protect the rejection classifier: RingFull and interface mismatch
        // are bounded routing outcomes; unrelated errors remain visible.
        assert!(is_expected_tx_rejection(XdpIoError::Ring {
            ring: crate::RingName::Tx,
            source: crate::NativeRingError::RingFull,
        }));
        assert!(is_expected_tx_rejection(XdpIoError::InterfaceMismatch {
            expected: IfId(1),
            actual: IfId(2),
        }));
        assert!(!is_expected_tx_rejection(XdpIoError::BatchActive));
    }

    #[test]
    fn disposition_combination_preserves_stop_then_skip_precedence() {
        // Protect publication disposition precedence: Stop dominates every
        // pair, SkipIo dominates ContinueOldIo, and Continue combines cleanly.
        use PublicationQuiescenceDisposition::{ContinueOldIo, SkipIo, Stop};
        assert_eq!(combine_disposition(Stop, ContinueOldIo), Stop);
        assert_eq!(combine_disposition(ContinueOldIo, Stop), Stop);
        assert_eq!(combine_disposition(SkipIo, ContinueOldIo), SkipIo);
        assert_eq!(combine_disposition(ContinueOldIo, SkipIo), SkipIo);
        assert_eq!(combine_disposition(SkipIo, Stop), Stop);
        assert_eq!(
            combine_disposition(ContinueOldIo, ContinueOldIo),
            ContinueOldIo
        );
    }
}
