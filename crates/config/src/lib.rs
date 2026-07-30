//! Versioned declarative configuration data transfer objects and exact parser.
//!
//! This crate deliberately stops at syntax. Semantic validation, normalization,
//! publication generations, secret generation, planning, and apply belong to
//! later control-plane stages.

mod diagnostic;
mod model;
mod parse;

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
