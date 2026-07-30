use crate::{
    DescriptorError, EndpointHandle, EndpointLocation, FakeEndpointId, FrameToken,
    ProducerReservation, RawDescriptor, RingError, RingKind, SpscRing, UmemLayout,
    ValidatedDescriptor,
};

/// Shadow descriptor used by the finite fake rings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingDescriptor {
    token: FrameToken,
    packet: Option<ValidatedDescriptor>,
}

impl RingDescriptor {
    /// Creates an address-only fill or completion descriptor.
    #[must_use]
    pub const fn frame(token: FrameToken) -> Self {
        Self {
            token,
            packet: None,
        }
    }

    /// Creates an RX or TX packet descriptor.
    #[must_use]
    pub const fn packet(token: FrameToken, descriptor: ValidatedDescriptor) -> Self {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeFrameState {
    Idle,
    FillOwned(FrameToken),
    RxPublished(FrameToken),
    AppOwned(FrameToken),
    TxOwned(FrameToken),
    CompletionPublished(FrameToken),
    Retired(FrameToken),
}

/// Finite deterministic producer/consumer for all four AF_XDP rings.
///
/// It owns only fixed arrays and pure ring state. It does not implement a
/// packet-I/O engine, socket, FFI, or native XDP lifecycle.
#[derive(Debug)]
pub struct FakeKernel<const RING_SIZE: usize, const FRAME_COUNT: usize> {
    endpoint: crate::endpoint::PhysicalEndpoint,
    fill: SpscRing<RingDescriptor, RING_SIZE>,
    rx: SpscRing<RingDescriptor, RING_SIZE>,
    tx: SpscRing<RingDescriptor, RING_SIZE>,
    completion: SpscRing<RingDescriptor, RING_SIZE>,
    frames: [FakeFrameState; FRAME_COUNT],
}

impl<const RING_SIZE: usize, const FRAME_COUNT: usize> FakeKernel<RING_SIZE, FRAME_COUNT> {
    /// Creates four rings attached to one finite fake physical endpoint.
    pub fn new(identity: FakeEndpointId, location: EndpointLocation) -> Result<Self, RingError> {
        let endpoint = crate::endpoint::PhysicalEndpoint::new(identity, location);
        let handle = endpoint.handle();
        let fill = SpscRing::new(handle.observe(RingKind::Fill))?;
        let rx = SpscRing::new(handle.observe(RingKind::Rx))?;
        let tx = SpscRing::new(handle.observe(RingKind::Tx))?;
        let completion = SpscRing::new(handle.observe(RingKind::Completion))?;
        Ok(Self {
            endpoint,
            fill,
            rx,
            tx,
            completion,
            frames: [FakeFrameState::Idle; FRAME_COUNT],
        })
    }

    /// Returns the only source of physical ring observations.
    #[must_use]
    pub const fn endpoint_handle(&self) -> EndpointHandle<'_> {
        self.endpoint.handle()
    }

    /// Reserves application-producer fill slots.
    pub fn reserve_fill(
        &mut self,
        len: usize,
    ) -> Result<ProducerReservation<'_, RingDescriptor, RING_SIZE>, RingError> {
        self.fill.reserve(len)
    }

    /// Reserves application-producer TX slots.
    pub fn reserve_tx(
        &mut self,
        len: usize,
    ) -> Result<ProducerReservation<'_, RingDescriptor, RING_SIZE>, RingError> {
        self.tx.reserve(len)
    }

    /// Acquires application-consumer RX slots.
    pub fn acquire_rx(
        &mut self,
        len: usize,
    ) -> Result<FakeConsumerAcquisition<'_, RING_SIZE, FRAME_COUNT>, RingError> {
        let acquisition = self.rx.acquire(len)?;
        Ok(FakeConsumerAcquisition {
            acquisition,
            frames: &mut self.frames,
            kind: RingKind::Rx,
        })
    }

    /// Acquires application-consumer completion slots.
    pub fn acquire_completion(
        &mut self,
        len: usize,
    ) -> Result<FakeConsumerAcquisition<'_, RING_SIZE, FRAME_COUNT>, RingError> {
        let acquisition = self.completion.acquire(len)?;
        Ok(FakeConsumerAcquisition {
            acquisition,
            frames: &mut self.frames,
            kind: RingKind::Completion,
        })
    }

    /// Consumes one application-submitted fill descriptor.
    pub fn kernel_consume_fill(&mut self) -> Result<FrameToken, FakeFault> {
        let acquisition = self.fill.acquire(1).map_err(FakeFault::Ring)?;
        let descriptor = acquisition.peek(0).map_err(FakeFault::Ring)?;
        if descriptor.packet.is_some() {
            return Err(FakeFault::WrongDescriptorShape {
                ring: RingKind::Fill,
            });
        }
        let index = frame_index::<FRAME_COUNT>(descriptor.token)?;
        match self.frames[index] {
            FakeFrameState::Idle => {}
            FakeFrameState::Retired(previous) if previous != descriptor.token => {}
            state if state.token() == Some(descriptor.token) => {
                return Err(FakeFault::DuplicateToken);
            }
            _ => return Err(FakeFault::WrongOrder),
        }
        acquisition.release_consume().map_err(FakeFault::Ring)?;
        self.frames[index] = FakeFrameState::FillOwned(descriptor.token);
        Ok(descriptor.token)
    }

    /// Produces one kernel RX descriptor after consuming its fill token.
    pub fn kernel_produce_rx(
        &mut self,
        token: FrameToken,
        raw: RawDescriptor,
        layout: &UmemLayout,
    ) -> Result<ValidatedDescriptor, FakeFault> {
        let index = frame_index::<FRAME_COUNT>(token)?;
        if self.frames[index] != FakeFrameState::FillOwned(token) {
            return Err(FakeFault::WrongOrder);
        }
        if !token.belongs_to(layout.domain()) {
            return Err(FakeFault::ForeignDomain);
        }
        let descriptor = layout
            .validate_descriptor(raw)
            .map_err(FakeFault::Descriptor)?;
        if descriptor.frame() != token.frame() {
            return Err(FakeFault::DescriptorFrameAlias);
        }
        let observation = self.endpoint.handle().observe(RingKind::Rx);
        let mut reservation = self.rx.reserve(1).map_err(FakeFault::Ring)?;
        reservation
            .write(
                0,
                observation.bind(RingDescriptor::packet(token, descriptor)),
            )
            .map_err(FakeFault::Ring)?;
        reservation.release_submit().map_err(FakeFault::Ring)?;
        self.frames[index] = FakeFrameState::RxPublished(token);
        Ok(descriptor)
    }

    /// Consumes one application-submitted TX packet descriptor.
    pub fn kernel_consume_tx(&mut self, layout: &UmemLayout) -> Result<RingDescriptor, FakeFault> {
        let acquisition = self.tx.acquire(1).map_err(FakeFault::Ring)?;
        let descriptor = acquisition.peek(0).map_err(FakeFault::Ring)?;
        let Some(packet) = descriptor.packet else {
            return Err(FakeFault::WrongDescriptorShape { ring: RingKind::Tx });
        };
        if !descriptor.token.belongs_to(layout.domain()) || !packet.belongs_to(layout.domain()) {
            return Err(FakeFault::ForeignDomain);
        }
        if packet.frame() != descriptor.token.frame() {
            return Err(FakeFault::DescriptorFrameAlias);
        }
        let index = frame_index::<FRAME_COUNT>(descriptor.token)?;
        match self.frames[index] {
            FakeFrameState::Idle => {}
            FakeFrameState::AppOwned(owned) if owned == descriptor.token => {}
            FakeFrameState::Retired(previous) if previous != descriptor.token => {}
            state if state.token() == Some(descriptor.token) => {
                return Err(FakeFault::DuplicateToken);
            }
            _ => return Err(FakeFault::WrongOrder),
        }
        acquisition.release_consume().map_err(FakeFault::Ring)?;
        self.frames[index] = FakeFrameState::TxOwned(descriptor.token);
        Ok(descriptor)
    }

    /// Produces one completion after the exact TX token was consumed.
    pub fn kernel_produce_completion(&mut self, token: FrameToken) -> Result<(), FakeFault> {
        let index = frame_index::<FRAME_COUNT>(token)?;
        if self.frames[index] != FakeFrameState::TxOwned(token) {
            return Err(FakeFault::WrongOrder);
        }
        let observation = self.endpoint.handle().observe(RingKind::Completion);
        let mut reservation = self.completion.reserve(1).map_err(FakeFault::Ring)?;
        reservation
            .write(0, observation.bind(RingDescriptor::frame(token)))
            .map_err(FakeFault::Ring)?;
        reservation.release_submit().map_err(FakeFault::Ring)?;
        self.frames[index] = FakeFrameState::CompletionPublished(token);
        Ok(())
    }
}

impl FakeFrameState {
    const fn token(self) -> Option<FrameToken> {
        match self {
            Self::Idle => None,
            Self::FillOwned(token)
            | Self::RxPublished(token)
            | Self::AppOwned(token)
            | Self::TxOwned(token)
            | Self::CompletionPublished(token)
            | Self::Retired(token) => Some(token),
        }
    }
}

/// Application-side RX or completion acquisition tied to fake ownership state.
pub struct FakeConsumerAcquisition<'fake, const RING_SIZE: usize, const FRAME_COUNT: usize> {
    acquisition: crate::ConsumerAcquisition<'fake, RingDescriptor, RING_SIZE>,
    frames: &'fake mut [FakeFrameState; FRAME_COUNT],
    kind: RingKind,
}

impl<const RING_SIZE: usize, const FRAME_COUNT: usize>
    FakeConsumerAcquisition<'_, RING_SIZE, FRAME_COUNT>
{
    /// Peeks without changing ring cursors or fake ownership.
    pub fn peek(&self, offset: usize) -> Result<RingDescriptor, RingError> {
        self.acquisition.peek(offset)
    }

    /// Consumes the complete range and advances each exact token state.
    pub fn release_consume(self) -> Result<(), FakeFault> {
        let mut updates = [None; RING_SIZE];
        for (offset, update) in updates.iter_mut().enumerate().take(self.acquisition.len()) {
            let descriptor = self.acquisition.peek(offset).map_err(FakeFault::Ring)?;
            let index = frame_index::<FRAME_COUNT>(descriptor.token)?;
            let expected = match self.kind {
                RingKind::Rx => {
                    if descriptor.packet.is_none() {
                        return Err(FakeFault::WrongDescriptorShape { ring: RingKind::Rx });
                    }
                    FakeFrameState::RxPublished(descriptor.token)
                }
                RingKind::Completion => {
                    if descriptor.packet.is_some() {
                        return Err(FakeFault::WrongDescriptorShape {
                            ring: RingKind::Completion,
                        });
                    }
                    FakeFrameState::CompletionPublished(descriptor.token)
                }
                RingKind::Fill | RingKind::Tx => return Err(FakeFault::WrongOrder),
            };
            if self.frames[index] != expected {
                return Err(FakeFault::WrongOrder);
            }
            *update = Some((index, descriptor.token));
        }
        self.acquisition
            .release_consume()
            .map_err(FakeFault::Ring)?;
        for update in updates.into_iter().flatten() {
            let (index, token) = update;
            self.frames[index] = match self.kind {
                RingKind::Rx => FakeFrameState::AppOwned(token),
                RingKind::Completion => FakeFrameState::Retired(token),
                RingKind::Fill | RingKind::Tx => unreachable!("constructor limits fake consumer"),
            };
        }
        Ok(())
    }

    /// Cancels without changing ring cursors or fake ownership.
    pub fn release_cancel(self) {
        self.acquisition.release_cancel();
    }
}

fn frame_index<const FRAME_COUNT: usize>(token: FrameToken) -> Result<usize, FakeFault> {
    let index = usize::try_from(token.frame().index()).map_err(|_| FakeFault::FrameOutsideFake)?;
    if index >= FRAME_COUNT {
        return Err(FakeFault::FrameOutsideFake);
    }
    Ok(index)
}

/// Finite fake fault detected without mutating ring or ownership state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeFault {
    /// Ring construction or operation failed.
    Ring(RingError),
    /// Packet descriptor geometry is invalid.
    Descriptor(DescriptorError),
    /// Token frame index exceeds the fake tracking array.
    FrameOutsideFake,
    /// The descriptor shape is not valid for this ring.
    WrongDescriptorShape {
        /// Ring whose descriptor was rejected.
        ring: RingKind,
    },
    /// The token is already owned by a kernel-side operation.
    DuplicateToken,
    /// A dependent kernel operation was attempted before its predecessor.
    WrongOrder,
    /// Token or descriptor belongs to another UMEM domain.
    ForeignDomain,
    /// Packet descriptor canonicalized to a different frame.
    DescriptorFrameAlias,
}
