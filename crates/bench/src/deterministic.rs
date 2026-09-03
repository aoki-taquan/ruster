//! R17 deterministic smoke execution and canonical artifact support.
//!
//! The smoke path uses the existing matrix's deterministic execution mode. It
//! has no `Instant`, host metadata, packet timing, or runtime specification
//! I/O; all output fields are stable counters and fixed logical inputs.

use ruster_core::MonotonicMillis;
use std::fmt;

use crate::{
    r17_benchmark_spec_sha256, FrameSize, ResultRow, RunConfig, RunError, Sha256Digest, Suite,
};

/// The value-only recipe for the deterministic workload. Runtime construction
/// and identity serialization both consume this descriptor; it contains no
/// packet or secret-key output representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct R17WorkloadDescriptor {
    pub(crate) seed: u64,
    pub(crate) logical_time_ms: u64,
    pub(crate) topology: R17TopologyDescriptor,
    pub(crate) frame: R17FrameRecipe,
    pub(crate) resolution: R17ResolutionDescriptor,
    pub(crate) nat: R17NatDescriptor,
    pub(crate) firewall: R17FirewallDescriptor,
    pub(crate) capacities: R17CapacityDescriptor,
    pub(crate) hash_roles: R17HashRolesDescriptor,
    pub(crate) setup: R17SetupDescriptor,
    pub(crate) cases: [R17CaseDescriptor; 24],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct R17TopologyDescriptor {
    pub(crate) lan_if: u16,
    pub(crate) wan_if: u16,
    pub(crate) lan_mac: [u8; 6],
    pub(crate) wan_mac: [u8; 6],
    pub(crate) host_mac: [u8; 6],
    pub(crate) gateway_mac: [u8; 6],
    pub(crate) host: [u8; 4],
    pub(crate) lan_local: [u8; 4],
    pub(crate) public: [u8; 4],
    pub(crate) remote: [u8; 4],
    pub(crate) gateway: [u8; 4],
    pub(crate) host_port: u16,
    pub(crate) remote_port: u16,
    pub(crate) lan_route_prefix: [u8; 4],
    pub(crate) lan_route_prefix_len: u8,
    pub(crate) default_route_prefix: [u8; 4],
    pub(crate) default_route_prefix_len: u8,
    pub(crate) default_route_next_hop: [u8; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct R17FrameRecipe {
    pub(crate) deterministic_size: FrameSize,
    pub(crate) ethertype: u16,
    pub(crate) ipv4_version_ihl: u8,
    pub(crate) ipv4_flags: u16,
    pub(crate) ttl: u8,
    pub(crate) udp_zero_checksum: bool,
    pub(crate) udp_transport_checksum: bool,
    pub(crate) tcp_transport_checksum: bool,
    pub(crate) payload_xorshift: [u32; 3],
    pub(crate) tcp_sequence: u32,
    pub(crate) tcp_acknowledgement: u32,
    pub(crate) tcp_window: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct R17ResolutionDescriptor {
    pub(crate) interval_ms: u64,
    pub(crate) state_ttl_ms: u64,
    pub(crate) max_attempts: u16,
    pub(crate) dynamic_neighbor_ttl_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct R17NatDescriptor {
    pub(crate) udp_idle_ttl_ms: u64,
    pub(crate) tcp_idle_ttl_ms: u64,
    pub(crate) allocator_seed: u64,
    pub(crate) public_port_first: u16,
    pub(crate) public_port_last: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct R17FirewallRuleDescriptor {
    pub(crate) id: u16,
    pub(crate) protocol: u8,
    pub(crate) source_prefix: [u8; 4],
    pub(crate) source_prefix_len: u8,
    pub(crate) destination_prefix: [u8; 4],
    pub(crate) destination_prefix_len: u8,
    pub(crate) source_port_first: u16,
    pub(crate) source_port_last: u16,
    pub(crate) destination_port_first: u16,
    pub(crate) destination_port_last: u16,
    pub(crate) allow_stateful: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct R17FirewallDescriptor {
    pub(crate) udp_idle_ttl_ms: u64,
    pub(crate) tcp_opening_idle_ttl_ms: u64,
    pub(crate) tcp_active_idle_ttl_ms: u64,
    pub(crate) generation: u64,
    pub(crate) rules: [R17FirewallRuleDescriptor; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct R17CapacityDescriptor {
    pub(crate) nat_mapping_slots: usize,
    pub(crate) nat_peer_slots: usize,
    pub(crate) nat_session_slots: usize,
    pub(crate) directory_buckets: usize,
    pub(crate) directory_nodes: usize,
    pub(crate) port_owner_slots: usize,
    pub(crate) firewall_state_slots: usize,
    pub(crate) resolution_state_slots: usize,
    pub(crate) resolution_action_slots: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct R17HashRoleDescriptor {
    pub(crate) role: &'static str,
    pub(crate) service: &'static str,
    pub(crate) domain: &'static str,
    pub(crate) wiring: &'static str,
    pub(crate) first: u64,
    pub(crate) second: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum R17HashRole {
    NatUdpMappingPeer,
    NatTcpMappingSession,
    FirewallStatefulFlow,
}

impl R17HashRole {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::NatUdpMappingPeer => "nat-udp-mapping-peer",
            Self::NatTcpMappingSession => "nat-tcp-mapping-session",
            Self::FirewallStatefulFlow => "firewall-stateful-flow",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct R17HashRolesDescriptor {
    pub(crate) nat_udp: R17HashRoleDescriptor,
    pub(crate) nat_tcp: R17HashRoleDescriptor,
    pub(crate) firewall: R17HashRoleDescriptor,
}

impl R17HashRolesDescriptor {
    pub(crate) const fn role(self, role: R17HashRole) -> R17HashRoleDescriptor {
        match role {
            R17HashRole::NatUdpMappingPeer => self.nat_udp,
            R17HashRole::NatTcpMappingSession => self.nat_tcp,
            R17HashRole::FirewallStatefulFlow => self.firewall,
        }
    }
}

/// Safe observations produced by the actual stateful-runtime constructors.
///
/// Each value is a bounded digest of fixed semantic probes after the runtime
/// has accepted state. It contains no key bytes, packet bytes, or publication
/// identity. The fixed answers are kept in the test module independently from
/// descriptor and artifact fingerprint serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct R17HashConstructorProbe {
    pub(crate) nat_udp_mapping_peer: u64,
    pub(crate) nat_tcp_mapping_session: u64,
    pub(crate) firewall_stateful_flow: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum R17SetupTransport {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum R17SetupDirection {
    Outbound,
    Inbound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum R17SeedTransform {
    Base,
    Xor(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct R17SetupStep {
    pub(crate) label: &'static str,
    pub(crate) transport: R17SetupTransport,
    pub(crate) direction: R17SetupDirection,
    pub(crate) seed: R17SeedTransform,
    pub(crate) tcp_flags: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct R17SetupDescriptor {
    /// Ordered setup events. The first UDP event and the following TCP
    /// handshake events are consumed by both runtime setup and identity
    /// serialization; no second hand-written order is permitted.
    pub(crate) steps: [R17SetupStep; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum R17Profile {
    Plain,
    Nat,
    Firewall,
    Combined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum R17Transport {
    UdpZero,
    UdpChecksum,
    Tcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum R17Direction {
    Outbound,
    Inbound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct R17CaseDescriptor {
    pub(crate) label: &'static str,
    pub(crate) profile: R17Profile,
    pub(crate) transport: R17Transport,
    pub(crate) direction: R17Direction,
}

/// One canonical value-only workload descriptor for all R17 deterministic
/// setup, measured fixture, policy, topology, capacity, and hash-role inputs.
pub(crate) const R17_WORKLOAD_DESCRIPTOR: R17WorkloadDescriptor = R17WorkloadDescriptor {
    seed: 0x5eed_0200_0000_0001,
    logical_time_ms: 1_000,
    topology: R17TopologyDescriptor {
        lan_if: 1,
        wan_if: 2,
        lan_mac: [0x02, 0, 0, 0, 0, 1],
        wan_mac: [0x02, 0, 0, 0, 0, 2],
        host_mac: [0x02, 0, 0, 0, 0, 10],
        gateway_mac: [0x02, 0, 0, 0, 0, 20],
        host: [10, 0, 0, 10],
        lan_local: [10, 0, 0, 1],
        public: [203, 0, 113, 10],
        remote: [198, 51, 100, 20],
        gateway: [203, 0, 113, 1],
        host_port: 40_000,
        remote_port: 443,
        lan_route_prefix: [10, 0, 0, 0],
        lan_route_prefix_len: 24,
        default_route_prefix: [0; 4],
        default_route_prefix_len: 0,
        default_route_next_hop: [203, 0, 113, 1],
    },
    frame: R17FrameRecipe {
        deterministic_size: FrameSize::Wire64,
        ethertype: 0x0800,
        ipv4_version_ihl: 0x45,
        ipv4_flags: 0x4000,
        ttl: 64,
        udp_zero_checksum: false,
        udp_transport_checksum: true,
        tcp_transport_checksum: true,
        payload_xorshift: [13, 7, 17],
        tcp_sequence: 1,
        tcp_acknowledgement: 2,
        tcp_window: 4_096,
    },
    resolution: R17ResolutionDescriptor {
        interval_ms: 1_000,
        state_ttl_ms: 2_000,
        max_attempts: 3,
        dynamic_neighbor_ttl_ms: 60_000,
    },
    nat: R17NatDescriptor {
        udp_idle_ttl_ms: 300_000,
        tcp_idle_ttl_ms: 7_440_000,
        allocator_seed: 0,
        public_port_first: 40_000,
        public_port_last: 40_000,
    },
    firewall: R17FirewallDescriptor {
        udp_idle_ttl_ms: 300_000,
        tcp_opening_idle_ttl_ms: 240_000,
        tcp_active_idle_ttl_ms: 7_440_000,
        generation: 1,
        rules: [
            R17FirewallRuleDescriptor {
                id: 1,
                protocol: 17,
                source_prefix: [10, 0, 0, 0],
                source_prefix_len: 24,
                destination_prefix: [0; 4],
                destination_prefix_len: 0,
                source_port_first: 0,
                source_port_last: u16::MAX,
                destination_port_first: 0,
                destination_port_last: u16::MAX,
                allow_stateful: true,
            },
            R17FirewallRuleDescriptor {
                id: 2,
                protocol: 6,
                source_prefix: [10, 0, 0, 0],
                source_prefix_len: 24,
                destination_prefix: [0; 4],
                destination_prefix_len: 0,
                source_port_first: 0,
                source_port_last: u16::MAX,
                destination_port_first: 0,
                destination_port_last: u16::MAX,
                allow_stateful: true,
            },
        ],
    },
    capacities: R17CapacityDescriptor {
        nat_mapping_slots: 4,
        nat_peer_slots: 4,
        nat_session_slots: 4,
        directory_buckets: 4,
        directory_nodes: 4,
        port_owner_slots: 1,
        firewall_state_slots: 4,
        resolution_state_slots: 0,
        resolution_action_slots: 0,
    },
    hash_roles: R17HashRolesDescriptor {
        nat_udp: R17HashRoleDescriptor {
            role: "nat44-udp",
            service: "nat44",
            domain: "udp-mapping-and-peer",
            wiring: "Nat44UdpHashKey::new(mapping,peer)",
            first: 0x1357_9bdf_2468_ace0,
            second: 0xfdb9_7531_eca8_6420,
        },
        nat_tcp: R17HashRoleDescriptor {
            role: "nat44-tcp",
            service: "nat44",
            domain: "tcp-mapping-and-session",
            wiring: "Nat44TcpHashKey::new(mapping,session)",
            first: 0xc001_d00d_f00d_beef,
            second: 0x1234_5678_9abc_def0,
        },
        firewall: R17HashRoleDescriptor {
            role: "firewall-flow",
            service: "firewall",
            domain: "stateful-flow",
            wiring: "FirewallHashKey::new(flow)",
            first: 0x0f1e_2d3c_4b5a_6978,
            second: 0x8877_6655_4433_2211,
        },
    },
    setup: R17SetupDescriptor {
        steps: [
            R17SetupStep {
                label: "udp-setup",
                transport: R17SetupTransport::Udp,
                direction: R17SetupDirection::Outbound,
                seed: R17SeedTransform::Base,
                tcp_flags: 0,
            },
            R17SetupStep {
                label: "tcp-syn",
                transport: R17SetupTransport::Tcp,
                direction: R17SetupDirection::Outbound,
                seed: R17SeedTransform::Base,
                tcp_flags: 0x02,
            },
            R17SetupStep {
                label: "tcp-syn-ack",
                transport: R17SetupTransport::Tcp,
                direction: R17SetupDirection::Inbound,
                seed: R17SeedTransform::Xor(1),
                tcp_flags: 0x12,
            },
            R17SetupStep {
                label: "tcp-ack",
                transport: R17SetupTransport::Tcp,
                direction: R17SetupDirection::Outbound,
                seed: R17SeedTransform::Xor(2),
                tcp_flags: 0x10,
            },
        ],
    },
    cases: [
        R17CaseDescriptor {
            label: "ctl-udp0-out",
            profile: R17Profile::Plain,
            transport: R17Transport::UdpZero,
            direction: R17Direction::Outbound,
        },
        R17CaseDescriptor {
            label: "nat-udp0-out-est",
            profile: R17Profile::Nat,
            transport: R17Transport::UdpZero,
            direction: R17Direction::Outbound,
        },
        R17CaseDescriptor {
            label: "fw-udp0-out-est",
            profile: R17Profile::Firewall,
            transport: R17Transport::UdpZero,
            direction: R17Direction::Outbound,
        },
        R17CaseDescriptor {
            label: "both-udp0-out-est",
            profile: R17Profile::Combined,
            transport: R17Transport::UdpZero,
            direction: R17Direction::Outbound,
        },
        R17CaseDescriptor {
            label: "ctl-udp0-in",
            profile: R17Profile::Plain,
            transport: R17Transport::UdpZero,
            direction: R17Direction::Inbound,
        },
        R17CaseDescriptor {
            label: "nat-udp0-in-est",
            profile: R17Profile::Nat,
            transport: R17Transport::UdpZero,
            direction: R17Direction::Inbound,
        },
        R17CaseDescriptor {
            label: "fw-udp0-in-est",
            profile: R17Profile::Firewall,
            transport: R17Transport::UdpZero,
            direction: R17Direction::Inbound,
        },
        R17CaseDescriptor {
            label: "both-udp0-in-est",
            profile: R17Profile::Combined,
            transport: R17Transport::UdpZero,
            direction: R17Direction::Inbound,
        },
        R17CaseDescriptor {
            label: "ctl-udpc-out",
            profile: R17Profile::Plain,
            transport: R17Transport::UdpChecksum,
            direction: R17Direction::Outbound,
        },
        R17CaseDescriptor {
            label: "nat-udpc-out-est",
            profile: R17Profile::Nat,
            transport: R17Transport::UdpChecksum,
            direction: R17Direction::Outbound,
        },
        R17CaseDescriptor {
            label: "fw-udpc-out-est",
            profile: R17Profile::Firewall,
            transport: R17Transport::UdpChecksum,
            direction: R17Direction::Outbound,
        },
        R17CaseDescriptor {
            label: "both-udpc-out-est",
            profile: R17Profile::Combined,
            transport: R17Transport::UdpChecksum,
            direction: R17Direction::Outbound,
        },
        R17CaseDescriptor {
            label: "ctl-udpc-in",
            profile: R17Profile::Plain,
            transport: R17Transport::UdpChecksum,
            direction: R17Direction::Inbound,
        },
        R17CaseDescriptor {
            label: "nat-udpc-in-est",
            profile: R17Profile::Nat,
            transport: R17Transport::UdpChecksum,
            direction: R17Direction::Inbound,
        },
        R17CaseDescriptor {
            label: "fw-udpc-in-est",
            profile: R17Profile::Firewall,
            transport: R17Transport::UdpChecksum,
            direction: R17Direction::Inbound,
        },
        R17CaseDescriptor {
            label: "both-udpc-in-est",
            profile: R17Profile::Combined,
            transport: R17Transport::UdpChecksum,
            direction: R17Direction::Inbound,
        },
        R17CaseDescriptor {
            label: "ctl-tcp-out",
            profile: R17Profile::Plain,
            transport: R17Transport::Tcp,
            direction: R17Direction::Outbound,
        },
        R17CaseDescriptor {
            label: "nat-tcp-out-est",
            profile: R17Profile::Nat,
            transport: R17Transport::Tcp,
            direction: R17Direction::Outbound,
        },
        R17CaseDescriptor {
            label: "fw-tcp-out-est",
            profile: R17Profile::Firewall,
            transport: R17Transport::Tcp,
            direction: R17Direction::Outbound,
        },
        R17CaseDescriptor {
            label: "both-tcp-out-est",
            profile: R17Profile::Combined,
            transport: R17Transport::Tcp,
            direction: R17Direction::Outbound,
        },
        R17CaseDescriptor {
            label: "ctl-tcp-in",
            profile: R17Profile::Plain,
            transport: R17Transport::Tcp,
            direction: R17Direction::Inbound,
        },
        R17CaseDescriptor {
            label: "nat-tcp-in-est",
            profile: R17Profile::Nat,
            transport: R17Transport::Tcp,
            direction: R17Direction::Inbound,
        },
        R17CaseDescriptor {
            label: "fw-tcp-in-est",
            profile: R17Profile::Firewall,
            transport: R17Transport::Tcp,
            direction: R17Direction::Inbound,
        },
        R17CaseDescriptor {
            label: "both-tcp-in-est",
            profile: R17Profile::Combined,
            transport: R17Transport::Tcp,
            direction: R17Direction::Inbound,
        },
    ],
};

const ROLE_DIGEST_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const ROLE_DIGEST_PRIME: u64 = 0x0000_0100_0000_01b3;

fn role_digest_byte(hash: u64, byte: u8) -> u64 {
    (hash ^ u64::from(byte)).wrapping_mul(ROLE_DIGEST_PRIME)
}

fn role_digest_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash = role_digest_byte(hash, byte);
    }
    hash
}

fn role_digest_u64(hash: u64, value: u64) -> u64 {
    role_digest_bytes(hash, &value.to_be_bytes())
}

fn role_digest_string(mut hash: u64, value: &str) -> u64 {
    hash = role_digest_u64(hash, value.len() as u64);
    role_digest_bytes(hash, value.as_bytes())
}

fn r17_hash_key_digest(role: R17HashRoleDescriptor) -> u64 {
    let mut hash = role_digest_string(ROLE_DIGEST_OFFSET, "ruster.r17.siphash-key/v1");
    hash = role_digest_u64(hash, role.first);
    role_digest_u64(hash, role.second)
}

/// Safe role-mapping identity. It binds role, service, domain, constructor
/// wiring, and a one-way key-material digest without exposing either raw key.
pub(crate) fn r17_hash_role_mapping_digest_for(roles: R17HashRolesDescriptor) -> u64 {
    let mut hash = role_digest_string(ROLE_DIGEST_OFFSET, "ruster.r17.hash-role-map/v2");
    for kind in [
        R17HashRole::NatUdpMappingPeer,
        R17HashRole::NatTcpMappingSession,
        R17HashRole::FirewallStatefulFlow,
    ] {
        let role = roles.role(kind);
        hash = role_digest_string(hash, kind.label());
        hash = role_digest_string(hash, role.role);
        hash = role_digest_string(hash, role.service);
        hash = role_digest_string(hash, role.domain);
        hash = role_digest_string(hash, role.wiring);
        hash = role_digest_u64(hash, r17_hash_key_digest(role));
    }
    hash
}

#[cfg(test)]
pub(crate) fn r17_hash_role_mapping_digest() -> u64 {
    r17_hash_role_mapping_digest_for(R17_WORKLOAD_DESCRIPTOR.hash_roles)
}

/// Independent known answer for the role mapping used by all stateful
/// constructors. This is intentionally not derived from the value above.
#[cfg(test)]
pub(crate) const R17_HASH_ROLE_MAPPING_KNOWN_ANSWER: u64 = 0x2b07_c91e_57d3_1ca7;

/// Schema identifier for the canonical deterministic smoke artifact.
pub const R17_DETERMINISTIC_SMOKE_SCHEMA: &str = "ruster.benchmark-smoke/v1";
/// Alias with the conventional schema-ID suffix for downstream callers.
pub const R17_DETERMINISTIC_SMOKE_SCHEMA_ID: &str = R17_DETERMINISTIC_SMOKE_SCHEMA;
/// Fixed seed used by the R17 CI smoke command.
pub const R17_DETERMINISTIC_SMOKE_SEED: u64 = R17_WORKLOAD_DESCRIPTOR.seed;
/// Fixed logical time used by the forwarding state machines.
pub const R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS: u64 = R17_WORKLOAD_DESCRIPTOR.logical_time_ms;
/// Typed logical time shared by the deterministic matrix and artifact.
pub(crate) const R17_DETERMINISTIC_SMOKE_LOGICAL_TIME: MonotonicMillis =
    MonotonicMillis(R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS);
/// Golden non-secret identity for the complete deterministic workload.
///
/// The live value is derived independently from the matrix topology, packet
/// fixtures, policies, setup sequence, and flow-hash configuration. Keeping
/// this known answer separate prevents the writer and validator from
/// accepting a self-consistent but different workload.
pub const R17_DETERMINISTIC_SMOKE_WORKLOAD_FINGERPRINT: u64 = 0x6920_d887_2e7e_5c38;
/// Number of ordered matrix cases in the R17 deterministic smoke.
pub const R17_DETERMINISTIC_SMOKE_CASE_COUNT: usize = R17_WORKLOAD_DESCRIPTOR.cases.len();
/// Maximum canonical artifact size accepted by the validator and CLI.
pub const R17_DETERMINISTIC_SMOKE_ARTIFACT_MAX_BYTES: usize = 64 * 1024;

// These validator answers intentionally do not reuse the writer-facing
// vocabulary or formatting constants below. The validator is the boundary
// that must reject a writer and validator changing in lockstep.
const VALIDATOR_SCHEMA: &str = "ruster.benchmark-smoke/v1";
const VALIDATOR_CASE_COUNT: usize = 24;
const VALIDATOR_SEED: u64 = 0x5eed_0200_0000_0001;
const VALIDATOR_LOGICAL_TIME_MS: u64 = 1_000;
const VALIDATOR_WORKLOAD_FINGERPRINT: u64 = 0x6920_d887_2e7e_5c38;
const VALIDATOR_CASES: [&str; VALIDATOR_CASE_COUNT] = [
    "ctl-udp0-out",
    "nat-udp0-out-est",
    "fw-udp0-out-est",
    "both-udp0-out-est",
    "ctl-udp0-in",
    "nat-udp0-in-est",
    "fw-udp0-in-est",
    "both-udp0-in-est",
    "ctl-udpc-out",
    "nat-udpc-out-est",
    "fw-udpc-out-est",
    "both-udpc-out-est",
    "ctl-udpc-in",
    "nat-udpc-in-est",
    "fw-udpc-in-est",
    "both-udpc-in-est",
    "ctl-tcp-out",
    "nat-tcp-out-est",
    "fw-tcp-out-est",
    "both-tcp-out-est",
    "ctl-tcp-in",
    "nat-tcp-in-est",
    "fw-tcp-in-est",
    "both-tcp-in-est",
];

/// Exact header key order for the canonical deterministic artifact.
pub const R17_DETERMINISTIC_SMOKE_HEADER_FIELDS: [&str; 7] = [
    "artifact_schema",
    "case_count",
    "kind",
    "logical_time_ms",
    "seed",
    "spec_sha256",
    "workload_fingerprint",
];
/// Exact case key order and allowlist for the canonical deterministic artifact.
pub const R17_DETERMINISTIC_SMOKE_CASE_FIELDS: [&str; 19] = [
    "artifact_schema",
    "case",
    "checksum_passes",
    "completion",
    "counter_allocations",
    "counter_consumed",
    "counter_dropped",
    "counter_received",
    "counter_recycled",
    "counter_tx_accepted",
    "counter_tx_rejected",
    "counter_tx_requested",
    "egress",
    "frame",
    "logical_time_ms",
    "oracle",
    "ordinal",
    "seed",
    "spec_sha256",
];

/// Canonical case vocabulary and order, copied from the existing matrix test
/// contract and kept in one public artifact-facing list.
pub const R17_DETERMINISTIC_SMOKE_CASES: [&str; R17_DETERMINISTIC_SMOKE_CASE_COUNT] = [
    R17_WORKLOAD_DESCRIPTOR.cases[0].label,
    R17_WORKLOAD_DESCRIPTOR.cases[1].label,
    R17_WORKLOAD_DESCRIPTOR.cases[2].label,
    R17_WORKLOAD_DESCRIPTOR.cases[3].label,
    R17_WORKLOAD_DESCRIPTOR.cases[4].label,
    R17_WORKLOAD_DESCRIPTOR.cases[5].label,
    R17_WORKLOAD_DESCRIPTOR.cases[6].label,
    R17_WORKLOAD_DESCRIPTOR.cases[7].label,
    R17_WORKLOAD_DESCRIPTOR.cases[8].label,
    R17_WORKLOAD_DESCRIPTOR.cases[9].label,
    R17_WORKLOAD_DESCRIPTOR.cases[10].label,
    R17_WORKLOAD_DESCRIPTOR.cases[11].label,
    R17_WORKLOAD_DESCRIPTOR.cases[12].label,
    R17_WORKLOAD_DESCRIPTOR.cases[13].label,
    R17_WORKLOAD_DESCRIPTOR.cases[14].label,
    R17_WORKLOAD_DESCRIPTOR.cases[15].label,
    R17_WORKLOAD_DESCRIPTOR.cases[16].label,
    R17_WORKLOAD_DESCRIPTOR.cases[17].label,
    R17_WORKLOAD_DESCRIPTOR.cases[18].label,
    R17_WORKLOAD_DESCRIPTOR.cases[19].label,
    R17_WORKLOAD_DESCRIPTOR.cases[20].label,
    R17_WORKLOAD_DESCRIPTOR.cases[21].label,
    R17_WORKLOAD_DESCRIPTOR.cases[22].label,
    R17_WORKLOAD_DESCRIPTOR.cases[23].label,
];

const WRITER_CHECKSUM_PASSES: [u8; R17_DETERMINISTIC_SMOKE_CASE_COUNT] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 2, 0, 1, 1, 2,
];

// Keep the validator's checksum answers independent from the writer's row
// validation. A drift in the writer-side matrix metadata must not make a
// self-consistent artifact acceptable at this boundary.
const VALIDATOR_CHECKSUM_PASSES: [u8; VALIDATOR_CASE_COUNT] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 2, 0, 1, 1, 2,
];

/// Errors raised by deterministic smoke generation or artifact validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeterministicSmokeError {
    InvalidSeed { expected: u64, actual: u64 },
    InvalidLogicalTime { expected: u64, actual: u64 },
    WorkloadFingerprintMismatch { expected: u64, actual: u64 },
    Run(RunError),
    WrongCaseCount { expected: usize, actual: usize },
    CaseMismatch { ordinal: usize },
    InvalidHeader,
    SpecShaMismatch,
    ArtifactTooLarge { maximum: usize, actual: usize },
    NonCanonicalArtifact(&'static str),
}

impl fmt::Display for DeterministicSmokeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSeed { expected, actual } => write!(
                formatter,
                "R17 deterministic smoke seed must be {expected}, got {actual}"
            ),
            Self::InvalidLogicalTime { expected, actual } => write!(
                formatter,
                "R17 deterministic smoke logical time must be {expected} ms, got {actual} ms"
            ),
            Self::WorkloadFingerprintMismatch { expected, actual } => write!(
                formatter,
                "R17 deterministic smoke workload fingerprint mismatch: expected {expected:016x}, got {actual:016x}"
            ),
            Self::Run(error) => write!(formatter, "deterministic smoke execution failed: {error}"),
            Self::WrongCaseCount { expected, actual } => write!(
                formatter,
                "deterministic smoke case count: expected {expected}, got {actual}"
            ),
            Self::CaseMismatch { ordinal } => {
                write!(
                    formatter,
                    "deterministic smoke case record mismatch at ordinal {ordinal}"
                )
            }
            Self::InvalidHeader => {
                formatter.write_str("invalid deterministic smoke artifact header")
            }
            Self::SpecShaMismatch => {
                formatter.write_str("deterministic smoke artifact is bound to the wrong spec SHA")
            }
            Self::ArtifactTooLarge { maximum, actual } => write!(
                formatter,
                "deterministic smoke artifact exceeds {maximum} bytes (got {actual})"
            ),
            Self::NonCanonicalArtifact(reason) => {
                write!(
                    formatter,
                    "non-canonical deterministic smoke artifact: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for DeterministicSmokeError {}

impl From<RunError> for DeterministicSmokeError {
    fn from(error: RunError) -> Self {
        Self::Run(error)
    }
}

/// Runs the fixed R17 forwarding matrix and returns canonical JSONL bytes
/// represented as a `String`.
pub fn deterministic_smoke(
    seed: u64,
    logical_time_ms: u64,
) -> Result<String, DeterministicSmokeError> {
    crate::runner::require_allocation_instrumentation()?;
    if seed != R17_DETERMINISTIC_SMOKE_SEED {
        return Err(DeterministicSmokeError::InvalidSeed {
            expected: R17_DETERMINISTIC_SMOKE_SEED,
            actual: seed,
        });
    }
    if logical_time_ms != R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS {
        return Err(DeterministicSmokeError::InvalidLogicalTime {
            expected: R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS,
            actual: logical_time_ms,
        });
    }
    let workload_fingerprint = crate::matrix::r17_deterministic_workload_fingerprint();
    if workload_fingerprint != R17_DETERMINISTIC_SMOKE_WORKLOAD_FINGERPRINT {
        return Err(DeterministicSmokeError::WorkloadFingerprintMismatch {
            expected: R17_DETERMINISTIC_SMOKE_WORKLOAD_FINGERPRINT,
            actual: workload_fingerprint,
        });
    }

    let mut config = RunConfig::smoke();
    config.suite = Suite::Smoke;
    config.seed = seed;
    let rows = crate::matrix::run_deterministic_matrix(&config)?;
    if rows.len() != R17_DETERMINISTIC_SMOKE_CASE_COUNT {
        return Err(DeterministicSmokeError::WrongCaseCount {
            expected: R17_DETERMINISTIC_SMOKE_CASE_COUNT,
            actual: rows.len(),
        });
    }

    let spec_sha256 = r17_benchmark_spec_sha256();
    let mut artifact = String::new();
    write_header(
        &mut artifact,
        seed,
        R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
        spec_sha256,
        workload_fingerprint,
    );
    for (ordinal, (row, expected_case)) in
        rows.iter().zip(R17_DETERMINISTIC_SMOKE_CASES).enumerate()
    {
        validate_row(row, ordinal, expected_case, seed)?;
        write_case(
            &mut artifact,
            row,
            ordinal,
            seed,
            R17_DETERMINISTIC_SMOKE_LOGICAL_TIME,
            spec_sha256,
        );
    }
    validate_deterministic_smoke_artifact(&artifact)?;
    Ok(artifact)
}

/// Runs the fixed-seed, fixed-logical-time R17 smoke configuration.
pub fn r17_deterministic_smoke() -> Result<String, DeterministicSmokeError> {
    deterministic_smoke(
        R17_DETERMINISTIC_SMOKE_SEED,
        R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS,
    )
}

/// Validates the complete canonical artifact, including its compiled spec
/// identity, exact case set/order, counters, and line-ending contract.
pub fn validate_deterministic_smoke_artifact(
    artifact: &str,
) -> Result<(), DeterministicSmokeError> {
    if artifact.len() > R17_DETERMINISTIC_SMOKE_ARTIFACT_MAX_BYTES {
        return Err(DeterministicSmokeError::ArtifactTooLarge {
            maximum: R17_DETERMINISTIC_SMOKE_ARTIFACT_MAX_BYTES,
            actual: artifact.len(),
        });
    }
    let live_workload_fingerprint = crate::matrix::r17_deterministic_workload_fingerprint();
    if live_workload_fingerprint != VALIDATOR_WORKLOAD_FINGERPRINT {
        return Err(DeterministicSmokeError::WorkloadFingerprintMismatch {
            expected: VALIDATOR_WORKLOAD_FINGERPRINT,
            actual: live_workload_fingerprint,
        });
    }
    if !artifact.ends_with('\n') {
        return Err(DeterministicSmokeError::NonCanonicalArtifact(
            "artifact must end with exactly one LF",
        ));
    }
    if artifact.ends_with("\n\n") {
        return Err(DeterministicSmokeError::NonCanonicalArtifact(
            "artifact has more than one final LF",
        ));
    }
    if artifact.contains('\r') {
        return Err(DeterministicSmokeError::NonCanonicalArtifact(
            "artifact must use LF-only line endings",
        ));
    }

    let lines = artifact.split_terminator('\n').collect::<Vec<_>>();
    let expected_lines = VALIDATOR_CASE_COUNT + 1;
    if lines.len() != expected_lines {
        return Err(DeterministicSmokeError::WrongCaseCount {
            expected: expected_lines,
            actual: lines.len(),
        });
    }

    let (seed, spec_sha256) = parse_header(lines[0])?;
    for (ordinal, expected_case) in VALIDATOR_CASES.into_iter().enumerate() {
        validate_case_line(
            lines[ordinal + 1],
            ordinal,
            expected_case,
            seed,
            spec_sha256,
        )?;
    }
    Ok(())
}

fn parse_header(line: &str) -> Result<(u64, Sha256Digest), DeterministicSmokeError> {
    let mut cursor = line;
    take_exact(&mut cursor, "{")?;
    if take_string_field(&mut cursor, "artifact_schema", true)? != VALIDATOR_SCHEMA {
        return Err(DeterministicSmokeError::InvalidHeader);
    }
    if take_decimal_field(&mut cursor, "case_count", false)? != VALIDATOR_CASE_COUNT as u64 {
        return Err(DeterministicSmokeError::InvalidHeader);
    }
    if take_string_field(&mut cursor, "kind", false)? != "deterministic-smoke" {
        return Err(DeterministicSmokeError::InvalidHeader);
    }
    let logical_time = take_decimal_field(&mut cursor, "logical_time_ms", false)?;
    if logical_time != VALIDATOR_LOGICAL_TIME_MS {
        return Err(DeterministicSmokeError::InvalidLogicalTime {
            expected: VALIDATOR_LOGICAL_TIME_MS,
            actual: logical_time,
        });
    }
    let seed = take_decimal_field(&mut cursor, "seed", false)?;
    if seed != VALIDATOR_SEED {
        return Err(DeterministicSmokeError::InvalidSeed {
            expected: VALIDATOR_SEED,
            actual: seed,
        });
    }
    let digest_text = take_string_field(&mut cursor, "spec_sha256", false)?;
    if digest_text != crate::R17_BENCHMARK_SPEC_SHA256_HEX {
        return Err(DeterministicSmokeError::SpecShaMismatch);
    }
    let fingerprint_text = take_string_field(&mut cursor, "workload_fingerprint", false)?;
    let fingerprint = parse_workload_fingerprint(fingerprint_text)
        .ok_or(DeterministicSmokeError::InvalidHeader)?;
    if fingerprint != VALIDATOR_WORKLOAD_FINGERPRINT {
        return Err(DeterministicSmokeError::WorkloadFingerprintMismatch {
            expected: VALIDATOR_WORKLOAD_FINGERPRINT,
            actual: fingerprint,
        });
    }
    take_exact(&mut cursor, "}")?;
    if !cursor.is_empty() {
        return Err(DeterministicSmokeError::InvalidHeader);
    }
    Ok((seed, r17_benchmark_spec_sha256()))
}

fn validate_case_line(
    line: &str,
    ordinal: usize,
    expected_case: &str,
    seed: u64,
    spec_sha256: Sha256Digest,
) -> Result<(), DeterministicSmokeError> {
    let mut cursor = line;
    take_exact(&mut cursor, "{")?;
    if take_string_field(&mut cursor, "artifact_schema", true)? != VALIDATOR_SCHEMA {
        return Err(DeterministicSmokeError::CaseMismatch { ordinal });
    }
    if take_string_field(&mut cursor, "case", false)? != expected_case {
        return Err(DeterministicSmokeError::CaseMismatch { ordinal });
    }
    if take_decimal_field(&mut cursor, "checksum_passes", false)?
        != u64::from(VALIDATOR_CHECKSUM_PASSES[ordinal])
    {
        return Err(DeterministicSmokeError::CaseMismatch { ordinal });
    }
    if take_string_field(&mut cursor, "completion", false)? != "transmitted" {
        return Err(DeterministicSmokeError::CaseMismatch { ordinal });
    }
    if take_decimal_field(&mut cursor, "counter_allocations", false)? != 0
        || take_decimal_field(&mut cursor, "counter_consumed", false)? != 0
        || take_decimal_field(&mut cursor, "counter_dropped", false)? != 0
        || take_decimal_field(&mut cursor, "counter_received", false)? != 1
        || take_decimal_field(&mut cursor, "counter_recycled", false)? != 0
        || take_decimal_field(&mut cursor, "counter_tx_accepted", false)? != 1
        || take_decimal_field(&mut cursor, "counter_tx_rejected", false)? != 0
        || take_decimal_field(&mut cursor, "counter_tx_requested", false)? != 1
    {
        return Err(DeterministicSmokeError::CaseMismatch { ordinal });
    }
    if take_string_field(&mut cursor, "egress", false)? != validator_egress(ordinal)
        || take_string_field(&mut cursor, "frame", false)? != "wire64"
    {
        return Err(DeterministicSmokeError::CaseMismatch { ordinal });
    }
    if take_decimal_field(&mut cursor, "logical_time_ms", false)? != VALIDATOR_LOGICAL_TIME_MS
        || take_string_field(&mut cursor, "oracle", false)? != "forwarded-wire-exact"
        || take_decimal_field(&mut cursor, "ordinal", false)? != ordinal as u64
        || take_decimal_field(&mut cursor, "seed", false)? != seed
    {
        return Err(DeterministicSmokeError::CaseMismatch { ordinal });
    }
    if take_string_field(&mut cursor, "spec_sha256", false)? != spec_sha256.to_lower_hex() {
        return Err(DeterministicSmokeError::SpecShaMismatch);
    }
    take_exact(&mut cursor, "}")?;
    if !cursor.is_empty() {
        return Err(DeterministicSmokeError::CaseMismatch { ordinal });
    }
    Ok(())
}

fn take_exact(cursor: &mut &str, expected: &str) -> Result<(), DeterministicSmokeError> {
    if let Some(remainder) = cursor.strip_prefix(expected) {
        *cursor = remainder;
        Ok(())
    } else {
        Err(DeterministicSmokeError::InvalidHeader)
    }
}

fn take_field_prefix(
    cursor: &mut &str,
    field: &str,
    first: bool,
) -> Result<(), DeterministicSmokeError> {
    if !first {
        take_exact(cursor, ",")?;
    }
    let mut prefix = String::with_capacity(field.len() + 3);
    prefix.push('"');
    prefix.push_str(field);
    prefix.push_str("\":");
    take_exact(cursor, &prefix)
}

fn take_string_field<'a>(
    cursor: &mut &'a str,
    field: &str,
    first: bool,
) -> Result<&'a str, DeterministicSmokeError> {
    take_field_prefix(cursor, field, first)?;
    let remainder = cursor
        .strip_prefix('"')
        .ok_or(DeterministicSmokeError::InvalidHeader)?;
    let end = remainder
        .find('"')
        .ok_or(DeterministicSmokeError::InvalidHeader)?;
    let value = &remainder[..end];
    if value.bytes().any(|byte| byte == b'\\' || byte < 0x20) {
        return Err(DeterministicSmokeError::InvalidHeader);
    }
    *cursor = &remainder[end + 1..];
    Ok(value)
}

fn take_decimal_field(
    cursor: &mut &str,
    field: &str,
    first: bool,
) -> Result<u64, DeterministicSmokeError> {
    take_field_prefix(cursor, field, first)?;
    let end = cursor
        .find([',', '}'])
        .ok_or(DeterministicSmokeError::InvalidHeader)?;
    let value = &cursor[..end];
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(DeterministicSmokeError::InvalidHeader);
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DeterministicSmokeError::InvalidHeader);
    }
    let parsed = value
        .parse()
        .map_err(|_| DeterministicSmokeError::InvalidHeader)?;
    *cursor = &cursor[end..];
    Ok(parsed)
}

fn parse_workload_fingerprint(value: &str) -> Option<u64> {
    if value.len() != 16 {
        return None;
    }
    let mut parsed = 0_u64;
    for byte in value.bytes() {
        let nibble = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a' + 10),
            _ => return None,
        };
        parsed = (parsed << 4) | nibble;
    }
    Some(parsed)
}

fn header_line(
    seed: u64,
    logical_time: MonotonicMillis,
    spec_sha256: Sha256Digest,
    workload_fingerprint: u64,
) -> String {
    format!(
        "{{\"artifact_schema\":\"{R17_DETERMINISTIC_SMOKE_SCHEMA}\",\"case_count\":{R17_DETERMINISTIC_SMOKE_CASE_COUNT},\"kind\":\"deterministic-smoke\",\"logical_time_ms\":{},\"seed\":{seed},\"spec_sha256\":\"{}\",\"workload_fingerprint\":\"{workload_fingerprint:016x}\"}}",
        logical_time.0,
        spec_sha256.to_lower_hex()
    )
}

fn write_header(
    output: &mut String,
    seed: u64,
    logical_time: MonotonicMillis,
    spec_sha256: Sha256Digest,
    workload_fingerprint: u64,
) {
    output.push_str(&header_line(
        seed,
        logical_time,
        spec_sha256,
        workload_fingerprint,
    ));
    output.push('\n');
}

fn write_case(
    output: &mut String,
    row: &ResultRow,
    ordinal: usize,
    seed: u64,
    logical_time: MonotonicMillis,
    spec_sha256: Sha256Digest,
) {
    let spec_sha256_hex = spec_sha256.to_lower_hex();
    output.push_str(&case_line(CaseLine {
        case: row.case,
        checksum_passes: row.checksum_passes,
        counter_allocations: row.timed_allocations,
        counter_tx_requested: row.digest,
        egress: egress(row.case),
        logical_time,
        ordinal,
        seed,
        spec_sha256: &spec_sha256_hex,
    }));
    output.push('\n');
}

struct CaseLine<'a> {
    case: &'a str,
    checksum_passes: u8,
    counter_allocations: u64,
    counter_tx_requested: u16,
    egress: &'a str,
    logical_time: MonotonicMillis,
    ordinal: usize,
    seed: u64,
    spec_sha256: &'a str,
}

fn case_line(line: CaseLine<'_>) -> String {
    format!(
        "{{\"artifact_schema\":\"{R17_DETERMINISTIC_SMOKE_SCHEMA}\",\"case\":\"{}\",\"checksum_passes\":{},\"completion\":\"transmitted\",\"counter_allocations\":{},\"counter_consumed\":0,\"counter_dropped\":0,\"counter_received\":1,\"counter_recycled\":0,\"counter_tx_accepted\":1,\"counter_tx_rejected\":0,\"counter_tx_requested\":{},\"egress\":\"{}\",\"frame\":\"wire64\",\"logical_time_ms\":{},\"oracle\":\"forwarded-wire-exact\",\"ordinal\":{},\"seed\":{},\"spec_sha256\":\"{}\"}}",
        line.case,
        line.checksum_passes,
        line.counter_allocations,
        line.counter_tx_requested,
        line.egress,
        line.logical_time.0,
        line.ordinal,
        line.seed,
        line.spec_sha256,
    )
}

fn validate_row(
    row: &ResultRow,
    ordinal: usize,
    expected_case: &str,
    seed: u64,
) -> Result<(), DeterministicSmokeError> {
    if row.case != expected_case
        || row.size != FrameSize::Wire64
        || row.batch != 1
        || row.checksum_passes != WRITER_CHECKSUM_PASSES[ordinal]
        || row.seed != seed
        || row.repetitions_per_sample != 1
        || row.timed_allocations != 0
        || row.digest != 1
        || row.stats.samples != 1
        || row.stats.min_ns != 1.0
        || row.stats.p50_ns != 1.0
        || row.stats.p95_ns != 1.0
        || row.stats.mad_ns != 0.0
    {
        return Err(DeterministicSmokeError::CaseMismatch { ordinal });
    }
    Ok(())
}

fn egress(case: &str) -> &'static str {
    if case.contains("-out") {
        "wan"
    } else {
        "lan"
    }
}

fn validator_egress(ordinal: usize) -> &'static str {
    match ordinal {
        0..=3 | 8..=11 | 16..=19 => "wan",
        4..=7 | 12..=15 | 20..=23 => "lan",
        _ => "invalid",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_smoke_artifact_binds_exact_case_set_and_spec_identity() {
        let artifact = r17_deterministic_smoke().unwrap();
        validate_deterministic_smoke_artifact(&artifact).unwrap();
        assert!(artifact
            .starts_with("{\"artifact_schema\":\"ruster.benchmark-smoke/v1\",\"case_count\":24"));
        assert!(artifact.contains(crate::R17_BENCHMARK_SPEC_SHA256_HEX));

        let wrong_spec = artifact.replace(
            crate::R17_BENCHMARK_SPEC_SHA256_HEX,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(
            validate_deterministic_smoke_artifact(&wrong_spec),
            Err(DeterministicSmokeError::SpecShaMismatch)
        );
    }

    #[test]
    fn canonical_field_order_and_allowlist_are_frozen() {
        let artifact = r17_deterministic_smoke().unwrap();
        let lines = artifact.split_terminator('\n').collect::<Vec<_>>();
        assert_eq!(
            json_keys(lines[0]),
            R17_DETERMINISTIC_SMOKE_HEADER_FIELDS.to_vec()
        );
        assert_eq!(
            json_keys(lines[1]),
            R17_DETERMINISTIC_SMOKE_CASE_FIELDS.to_vec()
        );

        let extra = artifact.replace(
            "\"counter_allocations\":0,",
            "\"counter_allocations\":0,\"cycles_per_packet\":0,",
        );
        assert!(validate_deterministic_smoke_artifact(&extra).is_err());

        let reordered_case = lines[1].replace(
            "\"case\":\"ctl-udp0-out\",\"checksum_passes\":0",
            "\"checksum_passes\":0,\"case\":\"ctl-udp0-out\"",
        );
        let mut reordered_lines = lines[..].to_vec();
        reordered_lines[1] = &reordered_case;
        let reordered = format!("{}\n", reordered_lines.join("\n"));
        assert!(validate_deterministic_smoke_artifact(&reordered).is_err());
    }

    #[test]
    fn case_set_order_and_duplicates_are_rejected() {
        let artifact = r17_deterministic_smoke().unwrap();
        let wrong_case =
            artifact.replace("\"case\":\"ctl-udp0-out\"", "\"case\":\"unexpected-case\"");
        assert!(matches!(
            validate_deterministic_smoke_artifact(&wrong_case),
            Err(DeterministicSmokeError::CaseMismatch { ordinal: 0 })
        ));

        let artifact = r17_deterministic_smoke().unwrap();
        let mut lines = artifact.split_terminator('\n').collect::<Vec<_>>();
        lines.swap(1, 2);
        let reordered = format!("{}\n", lines.join("\n"));
        assert!(matches!(
            validate_deterministic_smoke_artifact(&reordered),
            Err(DeterministicSmokeError::CaseMismatch { ordinal: 0 })
        ));

        let artifact = r17_deterministic_smoke().unwrap();
        let mut lines = artifact.split_terminator('\n').collect::<Vec<_>>();
        lines[2] = lines[1];
        let duplicate = format!("{}\n", lines.join("\n"));
        assert!(matches!(
            validate_deterministic_smoke_artifact(&duplicate),
            Err(DeterministicSmokeError::CaseMismatch { ordinal: 1 })
        ));

        let artifact = r17_deterministic_smoke().unwrap();
        let mut lines = artifact.split_terminator('\n').collect::<Vec<_>>();
        lines.pop();
        let missing = format!("{}\n", lines.join("\n"));
        assert_eq!(
            validate_deterministic_smoke_artifact(&missing),
            Err(DeterministicSmokeError::WrongCaseCount {
                expected: R17_DETERMINISTIC_SMOKE_CASE_COUNT + 1,
                actual: R17_DETERMINISTIC_SMOKE_CASE_COUNT,
            })
        );

        let artifact = r17_deterministic_smoke().unwrap();
        let wrong_counter =
            artifact.replace("\"counter_tx_accepted\":1", "\"counter_tx_accepted\":0");
        assert!(matches!(
            validate_deterministic_smoke_artifact(&wrong_counter),
            Err(DeterministicSmokeError::CaseMismatch { ordinal: 0 })
        ));
    }

    #[test]
    fn replay_is_byte_identical_and_wall_clock_free() {
        let first = r17_deterministic_smoke().unwrap();
        let second = r17_deterministic_smoke().unwrap();
        assert_eq!(first, second);
        assert!(!first.contains("latency"));
        assert!(!first.contains("ns_per_op"));
        assert!(!first.contains("hostname"));
    }

    #[test]
    fn noncanonical_artifact_shapes_are_rejected() {
        let artifact = r17_deterministic_smoke().unwrap();
        assert!(matches!(
            validate_deterministic_smoke_artifact(&format!("{artifact}\n")),
            Err(DeterministicSmokeError::NonCanonicalArtifact(_))
        ));
        assert_eq!(
            deterministic_smoke(
                R17_DETERMINISTIC_SMOKE_SEED - 1,
                R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS
            ),
            Err(DeterministicSmokeError::InvalidSeed {
                expected: R17_DETERMINISTIC_SMOKE_SEED,
                actual: R17_DETERMINISTIC_SMOKE_SEED - 1,
            })
        );
        assert_eq!(
            deterministic_smoke(
                R17_DETERMINISTIC_SMOKE_SEED,
                R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS + 1
            ),
            Err(DeterministicSmokeError::InvalidLogicalTime {
                expected: R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS,
                actual: R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS + 1,
            })
        );

        let wrong_seed = artifact.replace(
            &format!("\"seed\":{}", R17_DETERMINISTIC_SMOKE_SEED),
            "\"seed\":7",
        );
        assert_eq!(
            validate_deterministic_smoke_artifact(&wrong_seed),
            Err(DeterministicSmokeError::InvalidSeed {
                expected: R17_DETERMINISTIC_SMOKE_SEED,
                actual: 7,
            })
        );
    }

    #[test]
    fn r17_f07_hash_role_mapping_has_an_independent_known_answer() {
        let roles = R17_WORKLOAD_DESCRIPTOR.hash_roles;
        assert_eq!(
            r17_hash_role_mapping_digest(),
            R17_HASH_ROLE_MAPPING_KNOWN_ANSWER
        );

        let mut key_mutation = roles;
        key_mutation.nat_udp.first ^= 1;
        assert_ne!(
            r17_hash_role_mapping_digest_for(key_mutation),
            r17_hash_role_mapping_digest()
        );

        let mut wiring_mutation = roles;
        wiring_mutation.nat_tcp.wiring = "Nat44TcpHashKey::new(session,mapping)";
        assert_ne!(
            r17_hash_role_mapping_digest_for(wiring_mutation),
            r17_hash_role_mapping_digest()
        );

        let mut role_swap = roles;
        role_swap.nat_udp = role_swap.nat_tcp;
        assert_ne!(
            r17_hash_role_mapping_digest_for(role_swap),
            r17_hash_role_mapping_digest()
        );
    }

    fn json_keys(line: &str) -> Vec<&str> {
        let mut keys = Vec::new();
        let mut cursor = 0;
        while let Some(relative_end) = line[cursor..].find("\":") {
            let end = cursor + relative_end;
            let start = line[..end].rfind('"').unwrap() + 1;
            keys.push(&line[start..end]);
            cursor = end + 2;
        }
        keys
    }
}
