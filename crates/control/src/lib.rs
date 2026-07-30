#![forbid(unsafe_code)]
//! Owned, validated cold-path publications for ruster.
//!
//! Runtime activation is intentionally sealed until the follow-on worker can
//! mint an all-five-runtime publication proof:
//!
//! ```compile_fail
//! use ruster_control::{ActivePublication, FullServiceRuntimeSet};
//! ```

mod publication;

pub use publication::{
    FirewallPublicationInput, FullServiceStorageShape, Icmpv4ErrorStorageShape,
    Nat44TcpPublicationInput, Nat44TcpStoragePlan, Nat44UdpPublicationInput, Nat44UdpStoragePlan,
    PublicationCandidateError, PublicationPlan, ResolutionStorageShape, RuntimeService,
    StorageShapeError, SuccessorError, ValidatedAuthority, ValidatedCandidate,
};
