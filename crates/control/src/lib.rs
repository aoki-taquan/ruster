#![forbid(unsafe_code)]
//! Owned, validated cold-path publications for ruster.
//!
//! Live activation is exposed only as [`FullServiceStorage`] plus
//! [`ActivePublication`]: runtimes are always constructed from owned storage,
//! never adopted, and a successor is installed only through the
//! guard-taking [`ruster_runtime::FullServicePublication`] seam. No separate
//! runtime set can be assembled or adopted:
//!
//! ```compile_fail
//! use ruster_control::FullServiceRuntimeSet;
//! ```

mod activation;
mod config_bridge;
mod publication;

pub use activation::{
    ActivationError, ActivePublication, ApplyError, ApplyReport, FullServiceStorage,
    RestartRequired, StorageAllocationError,
};

pub use config_bridge::{
    candidate_from_config, ConfigBridgeError, KeySourceError, KeySourceKind, PublicationKeySource,
    PublicationKeys, SimDeterministicKeySource,
};

pub use publication::{
    FirewallPublicationInput, FullServiceStorageShape, Icmpv4ErrorStorageShape,
    Nat44TcpPublicationInput, Nat44TcpStoragePlan, Nat44UdpPublicationInput, Nat44UdpStoragePlan,
    PublicationCandidateError, PublicationPlan, ResolutionStorageShape, RuntimeService,
    StorageShapeError, SuccessorError, ValidatedAuthority, ValidatedCandidate,
};
