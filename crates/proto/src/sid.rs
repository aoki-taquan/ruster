//! SIDs (RFC 9595) of the skeleton's tables and notifications.
//!
//! All of them are in the experimental range 60000 to 99999. IANA has given
//! `ietf-interfaces` and `ietf-ip` ranges, but no per-item `.sid` files are published,
//! so the items used here are numbered locally for now. The source of truth is
//! `crates/proto/sid/ruster-fe.sid`; a test checks that it matches these constants.
//!
//! # Standards
//!
//! - RFC 9595: SIDs and the `.sid` file format.
//!
//! Deviations: items of standard modules use local numbers in the experimental range
//! until per-item `.sid` files are published.

pub const INTERFACE: u64 = 60010;
pub const INTERFACE_ENABLED: u64 = 60011;
pub const INTERFACE_PHYS_ADDRESS: u64 = 60012;
pub const INTERFACE_MTU: u64 = 60013;
/// `ietf-network-instance` (RFC 8529) `bind-ni-name`: the interface's VRF.
pub const INTERFACE_BIND_NI_NAME: u64 = 60014;

pub const ADDRESS: u64 = 60020;
pub const ADDRESS_PREFIX_LENGTH: u64 = 60021;

pub const ROUTE: u64 = 60030;
pub const ROUTE_NEXT_HOP: u64 = 60031;
pub const NEXT_HOP_INTERFACE: u64 = 60032;
pub const NEXT_HOP_ADDRESS: u64 = 60033;
pub const ROUTE_LOCAL: u64 = 60035;
pub const ROUTE_DISCARD: u64 = 60036;
pub const ROUTE_REJECT: u64 = 60037;
pub const ROUTE_LOOKUP_VRF: u64 = 60038;

pub const NEIGHBOR: u64 = 60040;
pub const NEIGHBOR_LINK_LAYER_ADDRESS: u64 = 60041;

/// Notification: the FE has a packet for a next hop that is not in the neighbor table.
pub const RESOLVE_REQUEST: u64 = 60050;
pub const RESOLVE_REQUEST_INTERFACE: u64 = 60051;
pub const RESOLVE_REQUEST_ADDRESS: u64 = 60052;

/// Every SID above with its schema path, in the order of the `.sid` file.
pub const ALL: &[(&str, u64)] = &[
    ("/ietf-interfaces:interfaces/interface", INTERFACE),
    (
        "/ietf-interfaces:interfaces/interface/enabled",
        INTERFACE_ENABLED,
    ),
    (
        "/ietf-interfaces:interfaces/interface/phys-address",
        INTERFACE_PHYS_ADDRESS,
    ),
    (
        "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/mtu",
        INTERFACE_MTU,
    ),
    (
        "/ietf-interfaces:interfaces/interface/ietf-network-instance:bind-ni-name",
        INTERFACE_BIND_NI_NAME,
    ),
    (
        "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/address",
        ADDRESS,
    ),
    (
        "/ietf-interfaces:interfaces/interface/ietf-ip:ipv4/address/prefix-length",
        ADDRESS_PREFIX_LENGTH,
    ),
    ("/ruster-fib:fib/vrf/route", ROUTE),
    ("/ruster-fib:fib/vrf/route/next-hop", ROUTE_NEXT_HOP),
    (
        "/ruster-fib:fib/vrf/route/next-hop/outgoing-interface",
        NEXT_HOP_INTERFACE,
    ),
    (
        "/ruster-fib:fib/vrf/route/next-hop/address",
        NEXT_HOP_ADDRESS,
    ),
    ("/ruster-fib:fib/vrf/route/local", ROUTE_LOCAL),
    ("/ruster-fib:fib/vrf/route/discard", ROUTE_DISCARD),
    ("/ruster-fib:fib/vrf/route/reject", ROUTE_REJECT),
    ("/ruster-fib:fib/vrf/route/lookup-vrf", ROUTE_LOOKUP_VRF),
    ("/ruster-neighbor:neighbors/neighbor", NEIGHBOR),
    (
        "/ruster-neighbor:neighbors/neighbor/link-layer-address",
        NEIGHBOR_LINK_LAYER_ADDRESS,
    ),
    ("/ruster-neighbor:resolve-request", RESOLVE_REQUEST),
    (
        "/ruster-neighbor:resolve-request/interface",
        RESOLVE_REQUEST_INTERFACE,
    ),
    (
        "/ruster-neighbor:resolve-request/address",
        RESOLVE_REQUEST_ADDRESS,
    ),
];
