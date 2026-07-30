//! Versioned declarative configuration parsing and cold semantic validation.
//!
//! Parsing preserves the exact V1 source schema. Semantic validation resolves
//! names, canonicalizes order-independent tables, synthesizes connected routes,
//! and owns canonical core tables without minting a publication identity.
//! Publication generations, fresh hash-key generation, planning, and apply
//! belong to later control-plane stages.

mod diagnostic;
mod model;
mod parse;
mod validate;

pub use diagnostic::{Diagnostic, DiagnosticCode, PathSegment, SourcePath};
pub use model::{
    AddressV1, AllocatorSeedV1, ConfigV1, FirewallActionV1, FirewallCapacityV1, FirewallPolicyV1,
    FirewallProtocolV1, FirewallRuleV1, FirewallV1, Icmpv4ErrorCapacityV1, Icmpv4ErrorPolicyV1,
    Icmpv4ErrorV1, InterfaceV1, Ipv4OriginV1, Nat44Icmpv4ErrorsV1, Nat44PortRangeV1, Nat44RealmV1,
    Nat44TcpCapacityV1, Nat44TcpV1, Nat44UdpCapacityV1, Nat44UdpV1, Nat44V1, NeighborV1,
    ResolutionCapacityV1, ResolutionPolicyV1, ResolutionV1, RouteV1, TickBudgetV1, VersionedConfig,
};
pub use parse::{
    parse, MAX_ADDRESSES, MAX_CONFIG_BYTES, MAX_FIREWALL_RULES, MAX_INTERFACES, MAX_NEIGHBORS,
    MAX_ROUTES, SCHEMA_VERSION_V1,
};
pub use validate::{
    validate, Icmpv4ErrorStorageShapeV1, InterfaceBindingV1, Nat44TcpStorageShapeV1,
    Nat44UdpStorageShapeV1, ResolutionStorageShapeV1, RuntimeStorageShapeV1, TickBudgetsV1,
    ValidatedConfig, ValidatedConfigV1, ValidatedFirewallV1, ValidatedIcmpv4ErrorV1,
    ValidatedNat44TcpV1, ValidatedNat44UdpV1, ValidatedNat44V1, ValidatedResolutionV1,
    ValidationCode, ValidationError, ValidationLimits,
};
