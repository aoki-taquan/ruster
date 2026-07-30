use crate::{
    DescriptorError, EndpointHandle, EndpointLocation, FakeEndpointId, FrameLedger, FrameStateKind,
    FrameToken, LedgerError, RawDescriptor, RingError, RingKind, SpscRing, UmemLayout,
    ValidatedDescriptor,
};

/// Shadow descriptor observed on one of the finite fake rings.
///
/// Descriptor constructors are intentionally private to this crate. Callers
/// publish Fill and TX work through the typed fake APIs instead of injecting a
/// raw [`FrameToken`] into a ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingDescriptor {
    token: FrameToken,
    packet: Option<ValidatedDescriptor>,
}

impl RingDescriptor {
    const fn frame(token: FrameToken) -> Self {
        Self {
            token,
            packet: None,
        }
    }

    const fn packet(token: FrameToken, descriptor: ValidatedDescriptor) -> Self {
        Self {
            token,
            packet: Some(descriptor),
        }
    }

    /// Returns the shadow ownership capability.
    #[must_use]
    pub const fn token(self) -> FrameToken {
        self.token
    }

    /// Returns packet geometry when this is an RX/TX descriptor.
    #[must_use]
    pub const fn packet_descriptor(self) -> Option<ValidatedDescriptor> {
        self.packet
    }
}

/// Ledger-authorized frame reserved only for Fill publication.
///
/// This capability is move-only, has no public constructor, and cannot be used
/// with the TX publication API.
pub struct FillReservation<'fake, const RING_SIZE: usize, const FRAME_COUNT: usize> {
    fake: &'fake mut FakeKernel<RING_SIZE, FRAME_COUNT>,
    token: FrameToken,
    resolved: bool,
}

impl<const RING_SIZE: usize, const FRAME_COUNT: usize> FillReservation<'_, RING_SIZE, FRAME_COUNT> {
    /// Returns the exact ownership generation represented by this reservation.
    #[must_use]
    pub const fn token(&self) -> FrameToken {
        self.token
    }

    /// Publishes this exact reservation to the Fill ring.
    pub fn publish(mut self) -> Result<(), FakeFault> {
        self.fake.publish_fill_token(self.token)?;
        self.resolved = true;
        Ok(())
    }

    /// Explicitly cancels the reservation and frees the frame.
    pub fn release_cancel(mut self) {
        self.fake
            .ledger
            .cancel_fill(self.token)
            .expect("reservation owns the exact FillReserved state");
        self.resolved = true;
    }
}

impl<const RING_SIZE: usize, const FRAME_COUNT: usize> Drop
    for FillReservation<'_, RING_SIZE, FRAME_COUNT>
{
    fn drop(&mut self) {
        if !self.resolved {
            self.fake
                .ledger
                .cancel_fill(self.token)
                .expect("unresolved reservation owns the exact FillReserved state");
        }
    }
}

/// Ledger-authorized frame reserved only for TX publication.
///
/// This capability is move-only, has no public constructor, and cannot be used
/// with the Fill publication API.
pub struct TxReservation<'fake, const RING_SIZE: usize, const FRAME_COUNT: usize> {
    fake: &'fake mut FakeKernel<RING_SIZE, FRAME_COUNT>,
    token: FrameToken,
    resolved: bool,
}

impl<const RING_SIZE: usize, const FRAME_COUNT: usize> TxReservation<'_, RING_SIZE, FRAME_COUNT> {
    /// Returns the exact ownership generation represented by this reservation.
    #[must_use]
    pub const fn token(&self) -> FrameToken {
        self.token
    }

    /// Publishes this exact reservation and descriptor to the TX ring.
    pub fn publish(mut self, packet: ValidatedDescriptor) -> Result<(), FakeFault> {
        self.fake.publish_tx_token(self.token, packet)?;
        self.resolved = true;
        Ok(())
    }

    /// Explicitly cancels the reservation back to pending TX.
    pub fn release_cancel(mut self) {
        self.fake
            .ledger
            .cancel_tx_reservation(self.token)
            .expect("reservation owns the exact TxReserved state");
        self.resolved = true;
    }
}

impl<const RING_SIZE: usize, const FRAME_COUNT: usize> Drop
    for TxReservation<'_, RING_SIZE, FRAME_COUNT>
{
    fn drop(&mut self) {
        if !self.resolved {
            self.fake
                .ledger
                .cancel_tx_reservation(self.token)
                .expect("unresolved reservation owns the exact TxReserved state");
        }
    }
}

/// Proof that the fake kernel consumed one published Fill entry.
pub struct ConsumedFill<'fake, const RING_SIZE: usize> {
    acquisition: Option<crate::ConsumerAcquisition<'fake, RingDescriptor, RING_SIZE>>,
    ledger: &'fake mut FrameLedger,
    rx: &'fake mut SpscRing<RingDescriptor, RING_SIZE>,
    endpoint: &'fake crate::endpoint::PhysicalEndpoint,
    descriptor: RingDescriptor,
}

impl<const RING_SIZE: usize> ConsumedFill<'_, RING_SIZE> {
    /// Returns the exact consumed ownership generation.
    #[must_use]
    pub const fn token(&self) -> FrameToken {
        self.descriptor.token
    }

    /// Publishes RX for this consumed Fill entry.
    ///
    /// If validation or RX capacity rejects the operation, Drop cancels the
    /// in-place acquisition so the same head remains next.
    pub fn produce_rx(mut self, raw: RawDescriptor) -> Result<ValidatedDescriptor, FakeFault> {
        let token = self.descriptor.token;
        self.ledger
            .verify_state(token, FrameStateKind::FillOwnedByKernel)
            .map_err(FakeFault::Ledger)?;
        let descriptor = self
            .ledger
            .layout()
            .validate_descriptor(raw)
            .map_err(FakeFault::Descriptor)?;
        if descriptor.frame() != token.frame() {
            return Err(FakeFault::Ledger(LedgerError::DescriptorFrameAlias {
                token_frame: token.frame(),
                descriptor_frame: descriptor.frame(),
            }));
        }
        let observation = self.endpoint.handle().observe(RingKind::Rx);
        let mut output = self.rx.reserve(1).map_err(FakeFault::Ring)?;
        output
            .write(
                0,
                observation.bind(RingDescriptor::packet(token, descriptor)),
            )
            .map_err(FakeFault::Ring)?;
        self.ledger
            .receive(token, descriptor)
            .expect("Fill ownership and descriptor were prevalidated");
        self.acquisition
            .take()
            .expect("live consumed Fill acquisition")
            .release_consume()
            .expect("the acquired input slot was already peeked");
        output
            .release_submit()
            .expect("the exact one-slot output reservation was written");
        Ok(descriptor)
    }
}

impl<const RING_SIZE: usize> Drop for ConsumedFill<'_, RING_SIZE> {
    fn drop(&mut self) {
        // The still-present acquisition field drops after this method and
        // cancels in place. A successful resolution takes it first.
    }
}

/// Proof that the fake kernel consumed one published TX entry.
pub struct ConsumedTx<'fake, const RING_SIZE: usize> {
    acquisition: Option<crate::ConsumerAcquisition<'fake, RingDescriptor, RING_SIZE>>,
    ledger: &'fake mut FrameLedger,
    completion: &'fake mut SpscRing<RingDescriptor, RING_SIZE>,
    endpoint: &'fake crate::endpoint::PhysicalEndpoint,
    descriptor: RingDescriptor,
}

impl<const RING_SIZE: usize> ConsumedTx<'_, RING_SIZE> {
    /// Returns the exact consumed ownership generation.
    #[must_use]
    pub const fn token(&self) -> FrameToken {
        self.descriptor.token
    }

    /// Publishes completion for this consumed TX entry.
    pub fn produce_completion(mut self) -> Result<(), FakeFault> {
        let token = self.descriptor.token;
        self.ledger
            .verify_state(token, FrameStateKind::TxOwnedByKernel)
            .map_err(FakeFault::Ledger)?;
        let observation = self.endpoint.handle().observe(RingKind::Completion);
        let mut output = self.completion.reserve(1).map_err(FakeFault::Ring)?;
        output
            .write(0, observation.bind(RingDescriptor::frame(token)))
            .map_err(FakeFault::Ring)?;
        self.ledger
            .complete_tx(token)
            .expect("TX ownership was prevalidated under the same mutable borrow");
        self.acquisition
            .take()
            .expect("live consumed TX acquisition")
            .release_consume()
            .expect("the acquired input slot was already peeked");
        output
            .release_submit()
            .expect("the exact one-slot output reservation was written");
        Ok(())
    }
}

impl<const RING_SIZE: usize> Drop for ConsumedTx<'_, RING_SIZE> {
    fn drop(&mut self) {
        // The still-present acquisition field drops after this method and
        // cancels in place. A successful resolution takes it first.
    }
}

/// Finite deterministic producer/consumer for all four AF_XDP rings.
///
/// One authoritative [`FrameLedger`] is consumed at construction. Ring
/// publication and consumption never accept caller-built descriptors, and each
/// ownership transition is coupled to the matching ledger transition. Ring
/// storage is fixed; the ledger performs its one allocation only during cold
/// construction.
#[derive(Debug)]
pub struct FakeKernel<const RING_SIZE: usize, const FRAME_COUNT: usize> {
    endpoint: crate::endpoint::PhysicalEndpoint,
    ledger: FrameLedger,
    fill: SpscRing<RingDescriptor, RING_SIZE>,
    rx: SpscRing<RingDescriptor, RING_SIZE>,
    tx: SpscRing<RingDescriptor, RING_SIZE>,
    completion: SpscRing<RingDescriptor, RING_SIZE>,
}

impl<const RING_SIZE: usize, const FRAME_COUNT: usize> FakeKernel<RING_SIZE, FRAME_COUNT> {
    /// Creates four rings bound to the consumed ledger's single UMEM domain.
    pub fn new(
        identity: FakeEndpointId,
        location: EndpointLocation,
        ledger: FrameLedger,
    ) -> Result<Self, FakeFault> {
        if ledger.frame_count() != FRAME_COUNT {
            return Err(FakeFault::FrameCountMismatch {
                expected: FRAME_COUNT,
                actual: ledger.frame_count(),
            });
        }
        let endpoint = crate::endpoint::PhysicalEndpoint::new(identity, location);
        let handle = endpoint.handle();
        let fill = SpscRing::new(handle.observe(RingKind::Fill)).map_err(FakeFault::Ring)?;
        let rx = SpscRing::new(handle.observe(RingKind::Rx)).map_err(FakeFault::Ring)?;
        let tx = SpscRing::new(handle.observe(RingKind::Tx)).map_err(FakeFault::Ring)?;
        let completion =
            SpscRing::new(handle.observe(RingKind::Completion)).map_err(FakeFault::Ring)?;
        Ok(Self {
            endpoint,
            ledger,
            fill,
            rx,
            tx,
            completion,
        })
    }

    /// Returns the only source of physical ring observations.
    #[must_use]
    pub const fn endpoint_handle(&self) -> EndpointHandle<'_> {
        self.endpoint.handle()
    }

    /// Returns the authoritative ownership ledger.
    #[must_use]
    pub const fn ledger(&self) -> &FrameLedger {
        &self.ledger
    }

    /// Returns the immutable UMEM layout bound to every fake ring.
    #[must_use]
    pub const fn layout(&self) -> &UmemLayout {
        self.ledger.layout()
    }

    /// Returns the number of published entries in one fake ring.
    pub fn ring_occupied(&self, kind: RingKind) -> Result<usize, RingError> {
        match kind {
            RingKind::Fill => self.fill.occupied(),
            RingKind::Rx => self.rx.occupied(),
            RingKind::Tx => self.tx.occupied(),
            RingKind::Completion => self.completion.occupied(),
        }
    }

    /// Reserves one free frame in the ledger for Fill publication.
    pub fn reserve_fill(
        &mut self,
        frame_index: u32,
    ) -> Result<FillReservation<'_, RING_SIZE, FRAME_COUNT>, FakeFault> {
        let token = self
            .ledger
            .reserve_fill(frame_index)
            .map_err(FakeFault::Ledger)?;
        Ok(FillReservation {
            fake: self,
            token,
            resolved: false,
        })
    }

    /// Validates a token as an existing Fill reservation without mutation.
    ///
    /// This is useful at a control-plane handoff boundary. Generated leases,
    /// TX reservations, stale generations, and foreign domains are rejected
    /// before any ring cursor or ledger state changes.
    pub fn authorize_fill(
        &mut self,
        token: FrameToken,
    ) -> Result<FillReservation<'_, RING_SIZE, FRAME_COUNT>, FakeFault> {
        self.ledger
            .verify_state(token, FrameStateKind::FillReserved)
            .map_err(FakeFault::Ledger)?;
        Ok(FillReservation {
            fake: self,
            token,
            resolved: false,
        })
    }

    fn publish_fill_token(&mut self, token: FrameToken) -> Result<(), FakeFault> {
        self.ledger
            .verify_state(token, FrameStateKind::FillReserved)
            .map_err(FakeFault::Ledger)?;
        let observation = self.endpoint.handle().observe(RingKind::Fill);
        let mut ring = self.fill.reserve(1).map_err(FakeFault::Ring)?;
        ring.write(0, observation.bind(RingDescriptor::frame(token)))
            .map_err(FakeFault::Ring)?;
        self.ledger
            .publish_fill(token)
            .expect("Fill state was prevalidated under the same mutable borrow");
        ring.release_submit()
            .expect("the exact one-slot reservation was written");
        Ok(())
    }

    /// Starts a generated-packet processing lease.
    pub fn lease_generated(&mut self, frame_index: u32) -> Result<FrameToken, FakeFault> {
        self.ledger
            .lease_generated(frame_index)
            .map_err(FakeFault::Ledger)
    }

    /// Stages a received or generated processing lease for TX.
    pub fn stage_tx(&mut self, token: FrameToken) -> Result<(), FakeFault> {
        self.ledger.stage_tx(token).map_err(FakeFault::Ledger)
    }

    /// Recycles a processing lease that will not be transmitted.
    pub fn recycle_lease(&mut self, token: FrameToken) -> Result<(), FakeFault> {
        self.ledger.recycle_lease(token).map_err(FakeFault::Ledger)
    }

    /// Cancels pending TX back to its processing lease.
    pub fn cancel_pending_tx(&mut self, token: FrameToken) -> Result<(), FakeFault> {
        self.ledger
            .cancel_pending_tx(token)
            .map_err(FakeFault::Ledger)
    }

    /// Reserves a staged token only for TX ring publication.
    pub fn reserve_tx(
        &mut self,
        token: FrameToken,
    ) -> Result<TxReservation<'_, RING_SIZE, FRAME_COUNT>, FakeFault> {
        self.ledger.reserve_tx(token).map_err(FakeFault::Ledger)?;
        Ok(TxReservation {
            fake: self,
            token,
            resolved: false,
        })
    }

    fn publish_tx_token(
        &mut self,
        token: FrameToken,
        packet: ValidatedDescriptor,
    ) -> Result<(), FakeFault> {
        self.ledger
            .verify_state(token, FrameStateKind::TxReserved)
            .map_err(FakeFault::Ledger)?;
        if !packet.belongs_to(self.ledger.layout().domain()) {
            return Err(FakeFault::Ledger(LedgerError::ForeignDescriptorDomain));
        }
        if packet.frame() != token.frame() {
            return Err(FakeFault::Ledger(LedgerError::DescriptorFrameAlias {
                token_frame: token.frame(),
                descriptor_frame: packet.frame(),
            }));
        }
        let observation = self.endpoint.handle().observe(RingKind::Tx);
        let mut ring = self.tx.reserve(1).map_err(FakeFault::Ring)?;
        ring.write(0, observation.bind(RingDescriptor::packet(token, packet)))
            .map_err(FakeFault::Ring)?;
        self.ledger
            .publish_tx(token)
            .expect("TX state was prevalidated under the same mutable borrow");
        ring.release_submit()
            .expect("the exact one-slot reservation was written");
        Ok(())
    }

    /// Acquires application-consumer RX slots.
    pub fn acquire_rx(
        &mut self,
        len: usize,
    ) -> Result<FakeConsumerAcquisition<'_, RING_SIZE>, FakeFault> {
        let acquisition = self.rx.acquire(len).map_err(FakeFault::Ring)?;
        Ok(FakeConsumerAcquisition {
            acquisition,
            ledger: &mut self.ledger,
            kind: RingKind::Rx,
        })
    }

    /// Acquires application-consumer completion slots.
    pub fn acquire_completion(
        &mut self,
        len: usize,
    ) -> Result<FakeConsumerAcquisition<'_, RING_SIZE>, FakeFault> {
        let acquisition = self.completion.acquire(len).map_err(FakeFault::Ring)?;
        Ok(FakeConsumerAcquisition {
            acquisition,
            ledger: &mut self.ledger,
            kind: RingKind::Completion,
        })
    }

    /// Consumes one application-published Fill descriptor.
    pub fn kernel_consume_fill(&mut self) -> Result<ConsumedFill<'_, RING_SIZE>, FakeFault> {
        let acquisition = self.fill.acquire(1).map_err(FakeFault::Ring)?;
        let descriptor = acquisition.peek(0).map_err(FakeFault::Ring)?;
        if descriptor.packet.is_some() {
            return Err(FakeFault::WrongDescriptorShape {
                ring: RingKind::Fill,
            });
        }
        self.ledger
            .verify_state(descriptor.token, FrameStateKind::FillOwnedByKernel)
            .map_err(FakeFault::Ledger)?;
        Ok(ConsumedFill {
            acquisition: Some(acquisition),
            ledger: &mut self.ledger,
            rx: &mut self.rx,
            endpoint: &self.endpoint,
            descriptor,
        })
    }

    /// Consumes one application-published TX descriptor.
    pub fn kernel_consume_tx(&mut self) -> Result<ConsumedTx<'_, RING_SIZE>, FakeFault> {
        let acquisition = self.tx.acquire(1).map_err(FakeFault::Ring)?;
        let descriptor = acquisition.peek(0).map_err(FakeFault::Ring)?;
        let Some(packet) = descriptor.packet else {
            return Err(FakeFault::WrongDescriptorShape { ring: RingKind::Tx });
        };
        self.ledger
            .verify_state(descriptor.token, FrameStateKind::TxOwnedByKernel)
            .map_err(FakeFault::Ledger)?;
        if !packet.belongs_to(self.ledger.layout().domain()) {
            return Err(FakeFault::Ledger(LedgerError::ForeignDescriptorDomain));
        }
        if packet.frame() != descriptor.token.frame() {
            return Err(FakeFault::Ledger(LedgerError::DescriptorFrameAlias {
                token_frame: descriptor.token.frame(),
                descriptor_frame: packet.frame(),
            }));
        }
        Ok(ConsumedTx {
            acquisition: Some(acquisition),
            ledger: &mut self.ledger,
            completion: &mut self.completion,
            endpoint: &self.endpoint,
            descriptor,
        })
    }
}

/// Application-side RX or completion acquisition tied to the authoritative
/// ledger.
pub struct FakeConsumerAcquisition<'fake, const RING_SIZE: usize> {
    acquisition: crate::ConsumerAcquisition<'fake, RingDescriptor, RING_SIZE>,
    ledger: &'fake mut FrameLedger,
    kind: RingKind,
}

impl<const RING_SIZE: usize> FakeConsumerAcquisition<'_, RING_SIZE> {
    /// Peeks without changing ring cursors or ledger ownership.
    pub fn peek(&self, offset: usize) -> Result<RingDescriptor, RingError> {
        self.acquisition.peek(offset)
    }

    /// Consumes the complete range and advances every authoritative state.
    pub fn release_consume(self) -> Result<(), FakeFault> {
        let mut updates = [None; RING_SIZE];
        for offset in 0..self.acquisition.len() {
            let descriptor = self.acquisition.peek(offset).map_err(FakeFault::Ring)?;
            let expected = match self.kind {
                RingKind::Rx => {
                    if descriptor.packet.is_none() {
                        return Err(FakeFault::WrongDescriptorShape { ring: RingKind::Rx });
                    }
                    FrameStateKind::RxAvailable
                }
                RingKind::Completion => {
                    if descriptor.packet.is_some() {
                        return Err(FakeFault::WrongDescriptorShape {
                            ring: RingKind::Completion,
                        });
                    }
                    FrameStateKind::CompletionAvailable
                }
                RingKind::Fill | RingKind::Tx => return Err(FakeFault::WrongOrder),
            };
            self.ledger
                .verify_state(descriptor.token, expected)
                .map_err(FakeFault::Ledger)?;
            if updates[..offset]
                .iter()
                .flatten()
                .any(|token| *token == descriptor.token)
            {
                return Err(FakeFault::DuplicateToken);
            }
            updates[offset] = Some(descriptor.token);
        }
        self.acquisition
            .release_consume()
            .map_err(FakeFault::Ring)?;
        for token in updates.into_iter().flatten() {
            match self.kind {
                RingKind::Rx => {
                    self.ledger
                        .lease_rx(token)
                        .expect("RX state was batch-prevalidated");
                }
                RingKind::Completion => {
                    self.ledger
                        .recycle_completion(token)
                        .expect("completion state was batch-prevalidated");
                }
                RingKind::Fill | RingKind::Tx => unreachable!("constructor limits fake consumer"),
            }
        }
        Ok(())
    }

    /// Cancels without changing ring cursors or ledger ownership.
    pub fn release_cancel(self) {
        self.acquisition.release_cancel();
    }
}

/// Finite fake fault detected without partially mutating ring and ledger state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeFault {
    /// Ring construction or operation failed.
    Ring(RingError),
    /// Authoritative ownership transition failed.
    Ledger(LedgerError),
    /// Packet descriptor geometry is invalid.
    Descriptor(DescriptorError),
    /// Const fake capacity did not match the consumed ledger.
    FrameCountMismatch {
        /// Compile-time capacity expected by the fake.
        expected: usize,
        /// Frames tracked by the supplied ledger.
        actual: usize,
    },
    /// The descriptor shape is not valid for this ring.
    WrongDescriptorShape {
        /// Ring whose descriptor was rejected.
        ring: RingKind,
    },
    /// One ownership generation appeared more than once in a consumer batch.
    DuplicateToken,
    /// A dependent operation was attempted through the wrong ring direction.
    WrongOrder,
}
