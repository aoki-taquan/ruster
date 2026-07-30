#![forbid(unsafe_code)]
#![doc = "Pure-Rust AF_XDP ownership and descriptor model."]
#![doc = ""]
#![doc = "This crate deliberately contains no socket, ring, FFI, or packet-I/O integration."]
#![doc = "It defines the checked model that a native backend must obey before those layers"]
#![doc = "are connected."]

mod descriptor;
mod layout;
mod ledger;
mod token;

pub use descriptor::{DescriptorError, RawDescriptor, ValidatedDescriptor};
pub use layout::{LayoutError, UmemLayout};
pub use ledger::{
    AuditError, FrameLedger, FrameStateKind, FrameStateView, LeaseKind, LedgerError, StateCounts,
};
pub use token::{FrameId, FrameToken, OwnershipGeneration};

#[cfg(test)]
mod tests;
