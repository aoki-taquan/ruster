#![forbid(unsafe_code)]
//! Owned, validated cold-path publications for ruster.
//!
//! Runtime activation is intentionally sealed until the follow-on worker can
//! mint an all-five-runtime publication proof:
//!
//! ```compile_fail
//! use ruster_control::{ActivePublication, FullServiceRuntimeSet};
//! ```

mod plan;
mod planning;
mod publication;

pub use plan::{
    classify_successor, plan_successor, FullServiceSuccessorClassification,
    PlanGenerationTransition, PlanOutcome, PlanRestartRequired, PlanSectionDiff,
};
pub use planning::{
    plan_full_service_v1, FullServiceCandidateError, FullServiceCandidateV1, FullServicePlanInputs,
    FullServicePlanV1, FullServicePlanningError, FullServicePlanningFailure,
};
pub use publication::{
    FirewallPublicationInput, FullServiceStorageShape, Icmpv4ErrorStorageShape,
    Nat44TcpPublicationInput, Nat44TcpStoragePlan, Nat44UdpPublicationInput, Nat44UdpStoragePlan,
    PublicationCandidateError, PublicationPlan, ResolutionStorageShape, RuntimeService,
    StorageShapeError, SuccessorError, ValidatedAuthority, ValidatedCandidate,
};
pub use ruster_config::{InterfaceBindingV1, TickBudgetsV1};
