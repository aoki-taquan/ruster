#![forbid(unsafe_code)]
#![doc = "Pure-Rust AF_XDP ownership, descriptor, and ring model."]
#![doc = ""]
#![doc = "This crate deliberately contains no socket, native ring, FFI, or packet-I/O"]
#![doc = "integration. It defines the checked model that a native backend must obey before"]
#![doc = "those layers are connected."]

mod descriptor;
mod domain;
mod endpoint;
mod fake;
mod layout;
mod ledger;
mod ring;
mod token;

pub use descriptor::{DescriptorError, RawDescriptor, ValidatedDescriptor};
pub use domain::UmemDomainId;
pub use endpoint::{
    EndpointHandle, EndpointLocation, FakeEndpointId, ObservedSubmission, RingKind, RingObservation,
};
pub use fake::{
    ConsumedFill, ConsumedTx, FakeConsumerAcquisition, FakeFault, FakeKernel, FillReservation,
    RingDescriptor, TxReservation,
};
pub use layout::{LayoutError, UmemLayout};
pub use ledger::{
    AuditError, FrameLedger, FrameStateKind, FrameStateView, LeaseKind, LedgerError, StateCounts,
};
pub use ring::{ConsumerAcquisition, ProducerReservation, RingError, RingIndices, SpscRing};
pub use token::{FrameId, FrameToken, OwnershipGeneration};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod x00b_tests;
