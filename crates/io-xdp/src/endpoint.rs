use std::{fmt, num::NonZeroU128};

/// Caller-generated unique identity for one finite fake physical endpoint.
///
/// The value is consumed when the fake endpoint is created. As with
/// [`crate::UmemDomainId`], callers must not reuse it across endpoint
/// lifetimes.
pub struct FakeEndpointId(EndpointIdentity);

impl FakeEndpointId {
    /// Wraps a nonzero value generated on the cold control-plane path.
    #[must_use]
    pub const fn new(unique: NonZeroU128) -> Self {
        Self(EndpointIdentity(unique))
    }

    const fn into_inner(self) -> EndpointIdentity {
        self.0
    }
}

impl fmt::Debug for FakeEndpointId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FakeEndpointId(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct EndpointIdentity(NonZeroU128);

impl fmt::Debug for EndpointIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Physical interface and queue selected for an endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointLocation {
    interface_index: u32,
    queue_id: u32,
}

impl EndpointLocation {
    /// Creates observable physical location metadata.
    #[must_use]
    pub const fn new(interface_index: u32, queue_id: u32) -> Self {
        Self {
            interface_index,
            queue_id,
        }
    }

    /// Returns the OS interface index represented by the fake endpoint.
    #[must_use]
    pub const fn interface_index(self) -> u32 {
        self.interface_index
    }

    /// Returns the selected queue.
    #[must_use]
    pub const fn queue_id(self) -> u32 {
        self.queue_id
    }
}

/// One of the four AF_XDP queue rings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingKind {
    /// Application producer, kernel consumer.
    Fill,
    /// Kernel producer, application consumer.
    Rx,
    /// Application producer, kernel consumer.
    Tx,
    /// Kernel producer, application consumer.
    Completion,
}

#[derive(Debug)]
pub(crate) struct PhysicalEndpoint {
    identity: EndpointIdentity,
    location: EndpointLocation,
}

impl PhysicalEndpoint {
    pub(crate) const fn new(identity: FakeEndpointId, location: EndpointLocation) -> Self {
        Self {
            identity: identity.into_inner(),
            location,
        }
    }

    pub(crate) const fn handle(&self) -> EndpointHandle<'_> {
        EndpointHandle { endpoint: self }
    }
}

/// Borrowed proof that an endpoint observation came from an actual handle.
#[derive(Clone, Copy, Debug)]
pub struct EndpointHandle<'endpoint> {
    endpoint: &'endpoint PhysicalEndpoint,
}

impl EndpointHandle<'_> {
    /// Observes one ring on this physical endpoint.
    ///
    /// [`RingObservation`] has no public constructor; adapters cannot replace
    /// this handle-derived fact with self-reported interface or queue values.
    #[must_use]
    pub const fn observe(self, kind: RingKind) -> RingObservation {
        RingObservation {
            endpoint: self.endpoint.identity,
            location: self.endpoint.location,
            kind,
        }
    }
}

/// Opaque identity and visible location of one observed physical ring.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RingObservation {
    endpoint: EndpointIdentity,
    location: EndpointLocation,
    kind: RingKind,
}

impl RingObservation {
    /// Returns the observed physical location.
    #[must_use]
    pub const fn location(self) -> EndpointLocation {
        self.location
    }

    /// Returns the observed ring kind.
    #[must_use]
    pub const fn kind(self) -> RingKind {
        self.kind
    }

    /// Binds a value to this handle-derived observation.
    #[must_use]
    pub const fn bind<T>(self, value: T) -> ObservedSubmission<T> {
        ObservedSubmission {
            observation: self,
            value,
        }
    }
}

impl fmt::Debug for RingObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RingObservation")
            .field("endpoint", &"<redacted>")
            .field("location", &self.location)
            .field("kind", &self.kind)
            .finish()
    }
}

/// Value sealed to the physical ring from which it was observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedSubmission<T> {
    observation: RingObservation,
    value: T,
}

impl<T> ObservedSubmission<T> {
    pub(crate) const fn observation(&self) -> RingObservation {
        self.observation
    }

    pub(crate) fn into_value(self) -> T {
        self.value
    }
}
