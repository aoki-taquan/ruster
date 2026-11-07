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
/// `ietf-if-extensions` `parent-interface`, of a VLAN sub-interface.
pub const INTERFACE_PARENT: u64 = 60015;
/// `ietf-if-vlan-encapsulation` `dot1q-vlan/outer-tag/vlan-id`.
pub const INTERFACE_VLAN_ID: u64 = 60016;

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

/// `ietf-nat` instance of a VRF (`napt44`).
pub const NAT: u64 = 60060;
pub const NAT_INSIDE: u64 = 60061;
pub const NAT_OUTSIDE: u64 = 60062;
pub const NAT_EXTERNAL: u64 = 60063;
pub const NAT_FIRST_PORT: u64 = 60064;
pub const NAT_LAST_PORT: u64 = 60065;

/// One forward firewall rule (`ietf-access-control-list` ace, `ruster-firewall`).
pub const FIREWALL_RULE: u64 = 60070;
pub const FIREWALL_INGRESS: u64 = 60071;
pub const FIREWALL_EGRESS: u64 = 60072;
pub const FIREWALL_SOURCE: u64 = 60073;
pub const FIREWALL_DESTINATION: u64 = 60074;
pub const FIREWALL_PROTOCOL: u64 = 60075;
pub const FIREWALL_SOURCE_PORT_LOW: u64 = 60076;
pub const FIREWALL_SOURCE_PORT_HIGH: u64 = 60077;
pub const FIREWALL_DESTINATION_PORT_LOW: u64 = 60078;
pub const FIREWALL_DESTINATION_PORT_HIGH: u64 = 60079;
pub const FIREWALL_ACTION: u64 = 60080;

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
        "/ietf-interfaces:interfaces/interface/ietf-if-extensions:parent-interface",
        INTERFACE_PARENT,
    ),
    (
        "/ietf-interfaces:interfaces/interface/ietf-if-extensions:encapsulation/ietf-if-vlan-encapsulation:dot1q-vlan/outer-tag/vlan-id",
        INTERFACE_VLAN_ID,
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
    ("/ietf-nat:nat/instances/instance", NAT),
    ("/ietf-nat:nat/instances/instance/ruster-nat:inside-interface", NAT_INSIDE),
    ("/ietf-nat:nat/instances/instance/ruster-nat:outside-interface", NAT_OUTSIDE),
    ("/ietf-nat:nat/instances/instance/policy/external-ip-address-pool/external-ip-pool", NAT_EXTERNAL),
    ("/ietf-nat:nat/instances/instance/policy/port-set-restrict/port-range/start-port-number", NAT_FIRST_PORT),
    ("/ietf-nat:nat/instances/instance/policy/port-set-restrict/port-range/end-port-number", NAT_LAST_PORT),
    ("/ietf-access-control-list:acls/acl/aces/ace", FIREWALL_RULE),
    ("/ietf-access-control-list:acls/acl/aces/ace/matches/ingress-interface", FIREWALL_INGRESS),
    ("/ietf-access-control-list:acls/acl/aces/ace/matches/egress-interface", FIREWALL_EGRESS),
    ("/ietf-access-control-list:acls/acl/aces/ace/matches/ipv4/source-ipv4-network", FIREWALL_SOURCE),
    ("/ietf-access-control-list:acls/acl/aces/ace/matches/ipv4/destination-ipv4-network", FIREWALL_DESTINATION),
    ("/ietf-access-control-list:acls/acl/aces/ace/matches/ipv4/protocol", FIREWALL_PROTOCOL),
    ("/ietf-access-control-list:acls/acl/aces/ace/matches/l4/source-port/lower-port", FIREWALL_SOURCE_PORT_LOW),
    ("/ietf-access-control-list:acls/acl/aces/ace/matches/l4/source-port/upper-port", FIREWALL_SOURCE_PORT_HIGH),
    ("/ietf-access-control-list:acls/acl/aces/ace/matches/l4/destination-port/lower-port", FIREWALL_DESTINATION_PORT_LOW),
    ("/ietf-access-control-list:acls/acl/aces/ace/matches/l4/destination-port/upper-port", FIREWALL_DESTINATION_PORT_HIGH),
    ("/ietf-access-control-list:acls/acl/aces/ace/actions/forwarding", FIREWALL_ACTION),
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
