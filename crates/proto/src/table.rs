//! The four tables of the skeleton and how their entries look on the wire.
//!
//! See `docs/design/tables.md` and `docs/design/control-protocol.md`. A change is one
//! CBOR map with one pair: the instance identifier and the new value, or `null` to
//! delete. An iPATCH body is a sequence of such maps.
//!
//! ```text
//! { [SID, key...]: { delta-SID: leaf, ... } }      add or replace
//! { [SID, key...]: null }                          delete
//! ```
//!
//! Inside a value, members are keyed by their SID minus the SID of the entry, as in
//! RFC 9254. Addresses, prefixes and MAC addresses are text, as YANG types them. An
//! address is IPv4 or IPv6 (`inet:ip-address`); a prefix length is checked against its
//! family, and a next hop must be of the route's family. A route's next hops all name
//! their outgoing interface, or all give only an address (a gateway that ribd
//! resolves, as RFC 8349's `next-hop-address` without `outgoing-interface`).
//!
//! # Standards
//!
//! - RFC 9254: the YANG-to-CBOR encoding (SID keys, delta SIDs inside an entry,
//!   instance identifiers as an array of the SID and the keys).
//! - draft-ietf-core-comi-21: a change maps an instance identifier to the
//!   new value, or to `null` to delete.
//! - RFC 8343 (`ietf-interfaces`) and RFC 8344 (`ietf-ip`): the interface and address
//!   entries follow their leaves (enabled, phys-address, mtu, prefix-length).
//! - RFC 8529 (`ietf-network-instance`): an interface names its VRF with
//!   `bind-ni-name`; `default` when left out.
//! - `draft-ietf-netmod-sub-intf-vlan-model`: a sub-interface names its
//!   `parent-interface` and the VLAN ID of its outer 802.1Q tag.
//! - IEEE 802.1Qcp (`ieee802-dot1q-bridge`): a bridge's ageing time (10 to 1000000
//!   seconds), an interface's `bridge-port/bridge-name`, and the static entries of the
//!   filtering database; here in the tables of `ruster-bridge`.
//! - RFC 5952 section 4: an IPv6 address is accepted only in its canonical text, so
//!   one address is one key.
//!
//! Deviations: the route, neighbor, punt and bridge tables and the source values (what a
//! daemon writes to confd, each with a lifetime) are ruster's own models, and the SIDs are
//! local (see [`crate::sid`]).

use std::fmt;
use std::net::IpAddr;

use crate::cbor::{DecodeError, Decoder, Encoder, Kind};
use crate::sid;

/// The smallest IPv4 MTU (RFC 791, the `ietf-ip` range).
pub const MIN_MTU: u16 = 68;

/// The key of one entry: which table, and which row.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Key {
    Interface {
        name: String,
    },
    Address {
        interface: String,
        address: IpAddr,
    },
    Route {
        vrf: String,
        prefix: IpAddr,
        len: u8,
    },
    Neighbor {
        interface: String,
        address: IpAddr,
    },
    /// The NAT of a VRF (one per VRF).
    Nat {
        vrf: String,
    },
    /// How the forward firewall of a VRF filters (one per VRF).
    FirewallPolicy {
        vrf: String,
    },
    /// The rate limits of the ICMP errors the FE generates (one, `default`).
    IcmpErrors {
        vrf: String,
    },
    /// One forward firewall rule of a VRF; lower ids are matched first.
    FirewallRule {
        vrf: String,
        id: u32,
    },
    /// One class of traffic to the router or to the control side (`ruster-punt`,
    /// one table for the whole FE).
    Punt {
        class: String,
    },
    /// The PPPoE session a source of kind `pppoe` found (`ruster-source`, written
    /// to confd); one per source, keyed by the source's name.
    SourcePppoe {
        source: String,
    },
    /// The IPv4 address a source found (by IPCP or DHCP); one per source.
    SourceIpv4 {
        source: String,
    },
    /// The IPv6 prefix delegated to a source (DHCPv6 IA_PD); one per source.
    SourcePrefix {
        source: String,
    },
    /// The IPv6 address a source found (DHCPv6 IA_NA); one per source.
    SourceIpv6 {
        source: String,
    },
    /// The DNS servers a source found (DHCP, DHCPv6 or IPCP); one list per source.
    SourceDns {
        source: String,
    },
    /// A bridge (`ruster-bridge`). The interface of the same name, when there is
    /// one, is the bridge's own interface (its IRB).
    Bridge {
        name: String,
    },
    /// The bridge an interface is a member of; one per interface.
    BridgePort {
        interface: String,
    },
    /// A static entry of a bridge's MAC address table.
    BridgeMac {
        bridge: String,
        mac: [u8; 6],
    },
}

/// The value of one entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Interface {
        enabled: bool,
        mac: [u8; 6],
        mtu: u16,
        /// The VRF (`ietf-network-instance` `bind-ni-name`) the interface belongs to;
        /// [`DEFAULT_VRF`] when not given.
        vrf: String,
        /// For a VLAN sub-interface, its parent and VLAN ID.
        vlan: Option<Vlan>,
        /// For an IPv4 in IPv6 tunnel, its outer addresses.
        tunnel: Option<Tunnel>,
        /// For a PPPoE session, where it runs.
        pppoe: Option<Pppoe>,
    },
    Address {
        prefix_len: u8,
    },
    Route(RouteAction),
    Neighbor {
        mac: [u8; 6],
    },
    Nat(Nat),
    /// ICMPv4 errors at most one per `ipv4_interval_ms` per egress and kind; ICMPv6
    /// errors `ipv6_burst` at once and one more every `ipv6_interval_ms`.
    IcmpErrors {
        ipv4_interval_ms: u32,
        ipv6_burst: u32,
        ipv6_interval_ms: u32,
    },
    /// Which outside endpoints may reach an inside endpoint with a flow out, where
    /// no rule decides. Left out of the message when it is the default.
    FirewallPolicy {
        filtering: NatFiltering,
        /// The interfaces outside the network the firewall guards (RFC 6092's
        /// exterior), by name.
        outside: Vec<String>,
    },
    FirewallRule(FirewallRule),
    Punt(PuntClass),
    /// A PPPoE session: its ID, the access concentrator's MAC address and the most
    /// the peer takes in one PPP frame; valid for `lifetime` seconds from when it
    /// arrives.
    SourcePppoe {
        session: u16,
        peer: [u8; 6],
        mtu: u16,
        lifetime: u32,
    },
    /// An IPv4 address and prefix length, valid for `lifetime` seconds from when it
    /// arrives.
    SourceIpv4 {
        address: std::net::Ipv4Addr,
        prefix_len: u8,
        lifetime: u32,
    },
    /// A delegated prefix (no bits set after its length) and the preferred and
    /// valid lifetimes the delegating router gave it, in seconds (RFC 8415 section
    /// 21.22); valid for `lifetime` seconds from when it arrives.
    SourcePrefix {
        prefix: std::net::Ipv6Addr,
        prefix_len: u8,
        preferred: u32,
        valid: u32,
        lifetime: u32,
    },
    /// An IPv6 address and prefix length, valid for `lifetime` seconds from when it
    /// arrives.
    SourceIpv6 {
        address: std::net::Ipv6Addr,
        prefix_len: u8,
        lifetime: u32,
    },
    /// 1 to [`SOURCE_DNS_MAX`] DNS servers, IPv4 or IPv6, valid for `lifetime`
    /// seconds from when they arrive.
    SourceDns {
        servers: Vec<IpAddr>,
        lifetime: u32,
    },
    /// A bridge: a learned address not seen for `aging_s` seconds is no longer used
    /// (IEEE 802.1Q 8.8.3: 10 to 1000000, 300 recommended), and at most
    /// `max_learned` addresses are learned.
    Bridge {
        aging_s: u32,
        max_learned: u32,
    },
    /// The interface is a member of bridge `bridge`.
    BridgePort {
        bridge: String,
    },
    /// The address is on member `interface`.
    BridgeMac {
        interface: String,
    },
}

/// The range of a bridge's ageing time, in seconds (IEEE 802.1Q 8.8.3).
pub const BRIDGE_AGING_RANGE: std::ops::RangeInclusive<u32> = 10..=1_000_000;

/// The most DNS servers one source sends.
pub const SOURCE_DNS_MAX: usize = 8;

/// One class of `ruster-punt`: frames that match go to `destination`, at most
/// `rate` per second and `burst` at once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PuntClass {
    pub matches: PuntMatch,
    /// Only frames that came in on this interface; any interface when `None`.
    pub interface: Option<String>,
    pub destination: PuntDestination,
    /// Packets per second, at least 1.
    pub rate: u32,
    /// Packets that may go at once, at least 1.
    pub burst: u32,
}

/// What a punt class matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PuntMatch {
    /// A fixed kind of traffic.
    Kind(PuntKind),
    /// IP packets of `protocol` (either family), and for TCP and UDP only the
    /// destination ports `first..=last` when given.
    Ip {
        protocol: u8,
        ports: Option<(u16, u16)>,
    },
}

/// The fixed kinds of traffic a punt class can match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PuntKind {
    /// ARP (RFC 826).
    Arp,
    /// IPv6 Neighbor Discovery (RFC 4861).
    Nd,
    /// PPPoE Discovery frames (RFC 2516 section 5, Ethernet type 0x8863).
    PppoeDiscovery,
    /// PPP control protocols in PPPoE session frames (RFC 1661 section 2: protocol
    /// numbers from 0x8000, such as LCP, PAP, CHAP, IPCP and IPv6CP).
    PppControl,
    /// To the kernel: ICMP and ICMPv6 errors.
    IcmpError,
    /// Other ICMP and ICMPv6.
    Icmp,
    /// TCP SYNs that open a connection.
    TcpSyn,
    /// Other TCP.
    Tcp,
    Udp,
    /// Anything else.
    Other,
}

impl PuntKind {
    pub const ALL: [Self; 10] = [
        Self::Arp,
        Self::Nd,
        Self::PppoeDiscovery,
        Self::PppControl,
        Self::IcmpError,
        Self::Icmp,
        Self::TcpSyn,
        Self::Tcp,
        Self::Udp,
        Self::Other,
    ];

    /// The name on the wire.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Arp => "arp",
            Self::Nd => "nd",
            Self::PppoeDiscovery => "pppoe-discovery",
            Self::PppControl => "ppp-control",
            Self::IcmpError => "icmp-error",
            Self::Icmp => "icmp",
            Self::TcpSyn => "tcp-syn",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Other => "other",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }

    /// Whether the kind is a frame for a control process rather than an IP packet
    /// for the kernel.
    #[must_use]
    pub const fn is_frame(self) -> bool {
        matches!(
            self,
            Self::Arp | Self::Nd | Self::PppoeDiscovery | Self::PppControl
        )
    }
}

/// Where the frames of a punt class go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PuntDestination {
    /// The control process with this socket name, as a whole frame.
    Control(String),
    /// The kernel of the VRF the packet came in on (its TUN).
    Kernel,
    /// Nowhere: dropped and counted.
    Drop,
}

/// The longest socket name of a control process.
pub const PUNT_CONTROL_NAME_MAX: usize = 32;

/// Whether `name` can name a control process's socket: 1 to
/// [`PUNT_CONTROL_NAME_MAX`] lower-case letters, digits and `-`, starting with a
/// letter, so that it is one safe path component.
#[must_use]
pub fn is_control_name(name: &str) -> bool {
    name.len() <= PUNT_CONTROL_NAME_MAX
        && name.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The most entries a list member of a value has.
const MEMBER_LIST_MAX: u64 = 64;

/// Source NAPT44 (`ietf-nat` type `napt44`): traffic from `inside` leaving through
/// `outside` gets the `external` address (the outside interface's IPv4 address when
/// `None`) and a port from `ports`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nat {
    pub inside: String,
    pub outside: String,
    pub external: Option<std::net::Ipv4Addr>,
    pub ports: NatPorts,
    pub filtering: NatFiltering,
    /// Whether the rate of translated datagrams that may be fragmented is limited
    /// so that their IPv4 IDs do not repeat within the maximum datagram lifetime
    /// (RFC 6864 section 5.2). Left out of the message when it is the default,
    /// `true`.
    pub ipv4_id_rate_limit: bool,
    /// The most public ports one inside host may hold, for each of UDP, TCP and
    /// ICMP (RFC 6888 REQ-4); 0 for no limit. Left out of the message when 0.
    pub ports_per_host: u16,
    /// The most state one inside host may hold: TCP sessions, and the outside
    /// endpoints its UDP and ICMP mappings have sent to (RFC 6888 REQ-5); 0 for
    /// no limit. Left out of the message when 0.
    pub state_per_host: u16,
}

/// Which outside endpoints may reach a mapping (`ietf-nat` `filtering-type`).
/// Left out of the message when it is the default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NatFiltering {
    /// Any.
    #[default]
    EndpointIndependent,
    /// Only addresses the mapping has sent to.
    AddressDependent,
    /// Only the address and port the mapping has sent to.
    AddressAndPortDependent,
}

impl NatFiltering {
    /// The `ietf-nat` identity's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EndpointIndependent => "endpoint-independent-filtering",
            Self::AddressDependent => "address-dependent-filtering",
            Self::AddressAndPortDependent => "address-and-port-dependent-filtering",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        [
            Self::EndpointIndependent,
            Self::AddressDependent,
            Self::AddressAndPortDependent,
        ]
        .into_iter()
        .find(|f| f.name() == name)
    }
}

/// The public ports of a NAT (`ietf-nat` `port-set-restrict`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatPorts {
    /// `first..=last`.
    Range { first: u16, last: u16 },
    /// A MAP-E port set (RFC 7597 section 5.1): PSID offset `offset` (`a`), PSID
    /// length `length` (`k`), and the PSID.
    Psid { offset: u8, length: u8, psid: u16 },
}

/// The protocols a firewall rule matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    /// ICMPv4 queries; IPv4 rules only.
    Icmp,
    /// ICMPv6 Echo; IPv6 rules only.
    Icmpv6,
}

/// What a firewall rule does: let the flow through and track it (its replies pass
/// too), or drop it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirewallAction {
    Accept,
    Drop,
}

/// One forward rule (`ietf-access-control-list` matches, stateful by `ruster-firewall`).
/// A VRF with any rule drops what no rule accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirewallRule {
    /// `None` for any interface.
    pub ingress: Option<String>,
    pub egress: Option<String>,
    /// IPv4 or IPv6, both of one family.
    pub source: (IpAddr, u8),
    pub destination: (IpAddr, u8),
    pub protocol: Protocol,
    pub source_ports: (u16, u16),
    pub destination_ports: (u16, u16),
    pub action: FirewallAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteAction {
    Forward(Vec<NextHop>),
    /// Next hops given only as gateway addresses, not necessarily on a link (a BGP
    /// NEXT_HOP). Only a route source writes these; ribd resolves them to
    /// [`RouteAction::Forward`] before the FE sees the route.
    Gateways(Vec<IpAddr>),
    /// Addressed to the router.
    Local,
    /// Dropped silently.
    Discard,
    /// Dropped with an ICMP Destination Unreachable.
    Reject,
    /// Looked up again in another VRF.
    LookupVrf(String),
}

/// A VLAN sub-interface: frames on `parent` tagged `id` (802.1Q outer tag).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vlan {
    pub parent: String,
    /// 1 to 4094.
    pub id: u16,
}

/// An IPv4 in IPv6 tunnel (`ruster-if-tunnel`, a DS-Lite softwire): its packets
/// leave in IPv6 from `local` to `remote`, routed in the default VRF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tunnel {
    pub local: std::net::Ipv6Addr,
    pub remote: std::net::Ipv6Addr,
}

/// A PPPoE session (`ruster-if-pppoe`, RFC 2516) on `parent`, with the session ID
/// and the peer's MAC address the session's daemon found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pppoe {
    pub parent: String,
    /// 1 to 0xfffe (RFC 2516 section 4: 0xffff is reserved, 0 is Discovery's).
    pub session: u16,
    pub peer: [u8; 6],
}

/// The VRF of an interface that names none.
pub const DEFAULT_VRF: &str = "default";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NextHop {
    pub interface: String,
    /// `None` for an on-link route, where the destination itself is the next hop.
    pub address: Option<IpAddr>,
}

/// One change to a table: set `value`, or delete the entry when it is `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub key: Key,
    pub value: Option<Value>,
}

impl Key {
    /// The SID of the table this key belongs to.
    pub fn table(&self) -> u64 {
        match self {
            Self::Interface { .. } => sid::INTERFACE,
            Self::Address { .. } => sid::ADDRESS,
            Self::Route { .. } => sid::ROUTE,
            Self::Neighbor { .. } => sid::NEIGHBOR,
            Self::Nat { .. } => sid::NAT,
            Self::FirewallPolicy { .. } => sid::FIREWALL_POLICY,
            Self::IcmpErrors { .. } => sid::ICMP_ERRORS,
            Self::FirewallRule { .. } => sid::FIREWALL_RULE,
            Self::Punt { .. } => sid::PUNT,
            Self::SourcePppoe { .. } => sid::SOURCE_PPPOE,
            Self::SourceIpv4 { .. } => sid::SOURCE_IPV4,
            Self::SourcePrefix { .. } => sid::SOURCE_PREFIX,
            Self::SourceIpv6 { .. } => sid::SOURCE_IPV6,
            Self::SourceDns { .. } => sid::SOURCE_DNS,
            Self::Bridge { .. } => sid::BRIDGE,
            Self::BridgePort { .. } => sid::BRIDGE_PORT,
            Self::BridgeMac { .. } => sid::BRIDGE_MAC,
        }
    }
}

/// Why a change could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelError {
    Cbor(DecodeError),
    /// The instance identifier names a table this model does not have.
    UnknownTable(u64),
    /// A member SID that does not belong to the entry.
    UnknownMember(u64),
    /// A key or member has the wrong shape or an invalid value.
    Invalid(&'static str),
    /// A mandatory member is missing.
    Missing(&'static str),
    /// The value does not match the table of the key.
    WrongTable,
}

impl From<DecodeError> for ModelError {
    fn from(error: DecodeError) -> Self {
        Self::Cbor(error)
    }
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => write!(f, "{error}"),
            Self::UnknownTable(sid) => write!(f, "unknown table SID {sid}"),
            Self::UnknownMember(sid) => write!(f, "unknown member SID {sid}"),
            Self::Invalid(what) => write!(f, "invalid {what}"),
            Self::Missing(what) => write!(f, "missing {what}"),
            Self::WrongTable => write!(f, "value does not match the table of the key"),
        }
    }
}

impl std::error::Error for ModelError {}

impl Change {
    pub fn set(key: Key, value: Value) -> Self {
        Self {
            key,
            value: Some(value),
        }
    }

    pub fn delete(key: Key) -> Self {
        Self { key, value: None }
    }

    /// Checks what [`Change::decode`] checks, so that everything encoded can be decoded.
    pub fn validate(&self) -> Result<(), ModelError> {
        let name = |text: &str| {
            if text.is_empty() {
                Err(ModelError::Invalid("empty name"))
            } else {
                Ok(())
            }
        };
        match &self.key {
            Key::Interface { name: n } => name(n)?,
            Key::Nat { vrf }
            | Key::FirewallPolicy { vrf }
            | Key::IcmpErrors { vrf }
            | Key::FirewallRule { vrf, .. } => name(vrf)?,
            Key::Address { interface, .. } | Key::Neighbor { interface, .. } => name(interface)?,
            Key::Punt { class } => name(class)?,
            Key::SourcePppoe { source }
            | Key::SourceIpv4 { source }
            | Key::SourcePrefix { source }
            | Key::SourceIpv6 { source }
            | Key::SourceDns { source } => name(source)?,
            Key::Bridge { name: n } | Key::BridgeMac { bridge: n, .. } => name(n)?,
            Key::BridgePort { interface } => name(interface)?,
            Key::Route { vrf, prefix, len } => {
                name(vrf)?;
                parse_prefix(&format!("{prefix}/{len}"))?;
            }
        }
        match &self.value {
            None => {}
            Some(value) => {
                let table_matches = matches!(
                    (&self.key, value),
                    (Key::Interface { .. }, Value::Interface { .. })
                        | (Key::Address { .. }, Value::Address { .. })
                        | (Key::Route { .. }, Value::Route(_))
                        | (Key::Neighbor { .. }, Value::Neighbor { .. })
                        | (Key::Nat { .. }, Value::Nat(_))
                        | (Key::FirewallPolicy { .. }, Value::FirewallPolicy { .. })
                        | (Key::IcmpErrors { .. }, Value::IcmpErrors { .. })
                        | (Key::FirewallRule { .. }, Value::FirewallRule(_))
                        | (Key::Punt { .. }, Value::Punt(_))
                        | (Key::SourcePppoe { .. }, Value::SourcePppoe { .. })
                        | (Key::SourceIpv4 { .. }, Value::SourceIpv4 { .. })
                        | (Key::SourcePrefix { .. }, Value::SourcePrefix { .. })
                        | (Key::SourceIpv6 { .. }, Value::SourceIpv6 { .. })
                        | (Key::SourceDns { .. }, Value::SourceDns { .. })
                        | (Key::Bridge { .. }, Value::Bridge { .. })
                        | (Key::BridgePort { .. }, Value::BridgePort { .. })
                        | (Key::BridgeMac { .. }, Value::BridgeMac { .. })
                );
                if !table_matches {
                    return Err(ModelError::WrongTable);
                }
                match value {
                    Value::Interface { mtu, .. } if *mtu < MIN_MTU => {
                        return Err(ModelError::Invalid("mtu"));
                    }
                    Value::Interface {
                        vlan,
                        tunnel,
                        pppoe,
                        ..
                    } if u8::from(vlan.is_some())
                        + u8::from(tunnel.is_some())
                        + u8::from(pppoe.is_some())
                        > 1 =>
                    {
                        return Err(ModelError::Invalid("more than one of VLAN, tunnel, PPPoE"));
                    }
                    Value::Interface {
                        pppoe: Some(pppoe), ..
                    } if pppoe.session == 0
                        || pppoe.session == 0xffff
                        || pppoe.peer[0] & 1 != 0
                        || pppoe.peer == [0; 6]
                        || name(&pppoe.parent).is_err() =>
                    {
                        return Err(ModelError::Invalid("PPPoE session, peer or parent"));
                    }
                    Value::Interface {
                        tunnel: Some(tunnel),
                        ..
                    } if [tunnel.local, tunnel.remote].iter().any(|a| {
                        a.is_unspecified()
                            || a.is_loopback()
                            || a.is_multicast()
                            || a.is_unicast_link_local()
                    }) =>
                    {
                        return Err(ModelError::Invalid("tunnel address"));
                    }
                    Value::Interface {
                        vrf, vlan, pppoe, ..
                    } => {
                        name(vrf)?;
                        if let (Some(pppoe), Key::Interface { name: own }) = (pppoe, &self.key) {
                            if *own == pppoe.parent {
                                return Err(ModelError::Invalid("PPPoE parent (itself)"));
                            }
                        }
                        if let Some(vlan) = vlan {
                            name(&vlan.parent)?;
                            if !(1..=4094).contains(&vlan.id) {
                                return Err(ModelError::Invalid("VLAN ID"));
                            }
                            if let Key::Interface { name: own } = &self.key {
                                if *own == vlan.parent {
                                    return Err(ModelError::Invalid("VLAN parent (itself)"));
                                }
                            }
                        }
                    }
                    Value::Route(RouteAction::LookupVrf(vrf)) => name(vrf)?,
                    Value::Nat(nat) => {
                        name(&nat.inside)?;
                        name(&nat.outside)?;
                        if nat.inside == nat.outside {
                            return Err(ModelError::Invalid("NAT inside equals outside"));
                        }
                        match nat.ports {
                            NatPorts::Range { first, last } if first == 0 || first > last => {
                                return Err(ModelError::Invalid("NAT port range"));
                            }
                            NatPorts::Psid {
                                offset,
                                length,
                                psid,
                            } if offset == 0
                                || length == 0
                                || u16::from(offset) + u16::from(length) >= 16
                                || psid >> length != 0 =>
                            {
                                return Err(ModelError::Invalid("NAT PSID"));
                            }
                            _ => {}
                        }
                    }
                    Value::FirewallRule(rule) => {
                        for interface in [&rule.ingress, &rule.egress].into_iter().flatten() {
                            name(interface)?;
                        }
                        for (address, len) in [rule.source, rule.destination] {
                            parse_prefix(&format!("{address}/{len}"))?;
                        }
                        let ipv6 = rule.source.0.is_ipv6();
                        if rule.destination.0.is_ipv6() != ipv6
                            || (rule.protocol == Protocol::Icmp && ipv6)
                            || (rule.protocol == Protocol::Icmpv6 && !ipv6)
                        {
                            return Err(ModelError::Invalid("firewall rule families"));
                        }
                        for (first, last) in [rule.source_ports, rule.destination_ports] {
                            if first > last {
                                return Err(ModelError::Invalid("firewall port range"));
                            }
                        }
                    }
                    Value::Punt(class) => validate_punt(class)?,
                    Value::Bridge {
                        aging_s,
                        max_learned,
                    } => {
                        if !BRIDGE_AGING_RANGE.contains(aging_s) {
                            return Err(ModelError::Invalid("aging-time"));
                        }
                        if *max_learned == 0 {
                            return Err(ModelError::Invalid("max-learned"));
                        }
                    }
                    Value::BridgePort { bridge } => {
                        name(bridge)?;
                        if let Key::BridgePort { interface } = &self.key {
                            if interface == bridge {
                                return Err(ModelError::Invalid("bridge port (the bridge itself)"));
                            }
                        }
                    }
                    Value::BridgeMac { interface } => {
                        name(interface)?;
                        if let Key::BridgeMac { mac, .. } = &self.key {
                            if mac[0] & 1 != 0 || *mac == [0; 6] {
                                return Err(ModelError::Invalid("static MAC address"));
                            }
                        }
                    }
                    Value::SourcePppoe {
                        session,
                        peer,
                        mtu,
                        lifetime,
                    } => {
                        if *session == 0 || *session == 0xffff {
                            return Err(ModelError::Invalid("PPPoE session"));
                        }
                        if peer[0] & 1 != 0 || *peer == [0; 6] {
                            return Err(ModelError::Invalid("PPPoE peer"));
                        }
                        if *mtu < MIN_MTU {
                            return Err(ModelError::Invalid("mtu"));
                        }
                        if *lifetime == 0 {
                            return Err(ModelError::Invalid("lifetime"));
                        }
                    }
                    Value::SourceIpv4 {
                        prefix_len,
                        lifetime,
                        ..
                    } => {
                        if *prefix_len == 0 || *prefix_len > 32 {
                            return Err(ModelError::Invalid("prefix length"));
                        }
                        if *lifetime == 0 {
                            return Err(ModelError::Invalid("lifetime"));
                        }
                    }
                    Value::SourcePrefix {
                        prefix,
                        prefix_len,
                        preferred,
                        valid,
                        lifetime,
                    } => {
                        let address = IpAddr::V6(*prefix);
                        if *prefix_len == 0
                            || *prefix_len > 128
                            || network(address, *prefix_len) != address
                        {
                            return Err(ModelError::Invalid("prefix"));
                        }
                        if preferred > valid || *valid == 0 {
                            return Err(ModelError::Invalid("prefix lifetimes"));
                        }
                        if *lifetime == 0 {
                            return Err(ModelError::Invalid("lifetime"));
                        }
                    }
                    Value::SourceIpv6 {
                        prefix_len,
                        lifetime,
                        ..
                    } => {
                        if *prefix_len == 0 || *prefix_len > 128 {
                            return Err(ModelError::Invalid("prefix length"));
                        }
                        if *lifetime == 0 {
                            return Err(ModelError::Invalid("lifetime"));
                        }
                    }
                    Value::SourceDns { servers, lifetime } => {
                        if servers.is_empty() || servers.len() > SOURCE_DNS_MAX {
                            return Err(ModelError::Invalid("number of DNS servers"));
                        }
                        if *lifetime == 0 {
                            return Err(ModelError::Invalid("lifetime"));
                        }
                    }
                    Value::Address { prefix_len } => {
                        let Key::Address { address, .. } = &self.key else {
                            unreachable!("checked above");
                        };
                        if *prefix_len > max_len(address) {
                            return Err(ModelError::Invalid("prefix length"));
                        }
                    }
                    Value::Route(RouteAction::Forward(hops)) => {
                        if hops.is_empty() {
                            return Err(ModelError::Missing("next-hop"));
                        }
                        let Key::Route { prefix, .. } = &self.key else {
                            unreachable!("checked above");
                        };
                        for hop in hops {
                            name(&hop.interface)?;
                            if hop.address.is_some_and(|a| a.is_ipv4() != prefix.is_ipv4()) {
                                return Err(ModelError::Invalid("next hop address family"));
                            }
                        }
                    }
                    Value::Route(RouteAction::Gateways(gateways)) => {
                        if gateways.is_empty() {
                            return Err(ModelError::Missing("next-hop"));
                        }
                        let Key::Route { prefix, .. } = &self.key else {
                            unreachable!("checked above");
                        };
                        if gateways.iter().any(|a| a.is_ipv4() != prefix.is_ipv4()) {
                            return Err(ModelError::Invalid("next hop address family"));
                        }
                        // A link-local address says nothing of its link.
                        if gateways
                            .iter()
                            .any(|a| matches!(a, IpAddr::V6(a) if a.is_unicast_link_local()))
                        {
                            return Err(ModelError::Invalid("link-local gateway"));
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Writes the change after [`Change::validate`]; nothing is written on error.
    pub fn encode(&self, e: &mut Encoder<'_>) -> Result<(), ModelError> {
        self.validate()?;
        e.map(1);
        encode_key(&self.key, e);
        match &self.value {
            None => {
                e.null();
            }
            Some(value) => encode_value(value, e),
        }
        Ok(())
    }

    pub fn decode(d: &mut Decoder<'_>) -> Result<Self, ModelError> {
        if d.map()? != 1 {
            return Err(ModelError::Invalid("change (expected one pair)"));
        }
        let key = decode_key(d)?;
        let value = if d.peek_kind()? == Kind::Null {
            d.null()?;
            None
        } else {
            Some(decode_value(key.table(), d)?)
        };
        let change = Self { key, value };
        change.validate()?;
        Ok(change)
    }
}

/// Encodes a key as an instance identifier: `[table SID, key...]`.
pub fn encode_key(key: &Key, e: &mut Encoder<'_>) {
    match key {
        Key::Interface { name } => {
            e.array(2).u64(sid::INTERFACE).text(name);
        }
        Key::Address { interface, address } => {
            e.array(3)
                .u64(sid::ADDRESS)
                .text(interface)
                .text(&address.to_string());
        }
        Key::Route { vrf, prefix, len } => {
            e.array(3)
                .u64(sid::ROUTE)
                .text(vrf)
                .text(&format!("{prefix}/{len}"));
        }
        Key::Neighbor { interface, address } => {
            e.array(3)
                .u64(sid::NEIGHBOR)
                .text(interface)
                .text(&address.to_string());
        }
        Key::Nat { vrf } => {
            e.array(2).u64(sid::NAT).text(vrf);
        }
        Key::FirewallPolicy { vrf } => {
            e.array(2).u64(sid::FIREWALL_POLICY).text(vrf);
        }
        Key::IcmpErrors { vrf } => {
            e.array(2).u64(sid::ICMP_ERRORS).text(vrf);
        }
        Key::Punt { class } => {
            e.array(2).u64(sid::PUNT).text(class);
        }
        Key::SourcePppoe { source } => {
            e.array(2).u64(sid::SOURCE_PPPOE).text(source);
        }
        Key::SourceIpv4 { source } => {
            e.array(2).u64(sid::SOURCE_IPV4).text(source);
        }
        Key::SourcePrefix { source } => {
            e.array(2).u64(sid::SOURCE_PREFIX).text(source);
        }
        Key::SourceIpv6 { source } => {
            e.array(2).u64(sid::SOURCE_IPV6).text(source);
        }
        Key::SourceDns { source } => {
            e.array(2).u64(sid::SOURCE_DNS).text(source);
        }
        Key::Bridge { name } => {
            e.array(2).u64(sid::BRIDGE).text(name);
        }
        Key::BridgePort { interface } => {
            e.array(2).u64(sid::BRIDGE_PORT).text(interface);
        }
        Key::BridgeMac { bridge, mac } => {
            e.array(3)
                .u64(sid::BRIDGE_MAC)
                .text(bridge)
                .text(&format_mac(mac));
        }
        Key::FirewallRule { vrf, id } => {
            e.array(3)
                .u64(sid::FIREWALL_RULE)
                .text(vrf)
                .u64(u64::from(*id));
        }
    }
}

pub fn decode_key(d: &mut Decoder<'_>) -> Result<Key, ModelError> {
    let len = d.array()?;
    let table = d.u64()?;
    let expected = match table {
        sid::INTERFACE
        | sid::NAT
        | sid::FIREWALL_POLICY
        | sid::ICMP_ERRORS
        | sid::PUNT
        | sid::SOURCE_PPPOE
        | sid::SOURCE_IPV4
        | sid::SOURCE_PREFIX
        | sid::SOURCE_IPV6
        | sid::SOURCE_DNS
        | sid::BRIDGE
        | sid::BRIDGE_PORT => 2,
        sid::ADDRESS | sid::ROUTE | sid::NEIGHBOR | sid::FIREWALL_RULE | sid::BRIDGE_MAC => 3,
        other => return Err(ModelError::UnknownTable(other)),
    };
    if len != expected {
        return Err(ModelError::Invalid("instance identifier length"));
    }
    let first = d.text()?.to_owned();
    if first.is_empty() {
        return Err(ModelError::Invalid("empty name"));
    }
    Ok(match table {
        sid::INTERFACE => Key::Interface { name: first },
        sid::NAT => Key::Nat { vrf: first },
        sid::FIREWALL_POLICY => Key::FirewallPolicy { vrf: first },
        sid::ICMP_ERRORS => Key::IcmpErrors { vrf: first },
        sid::PUNT => Key::Punt { class: first },
        sid::SOURCE_PPPOE => Key::SourcePppoe { source: first },
        sid::SOURCE_IPV4 => Key::SourceIpv4 { source: first },
        sid::SOURCE_PREFIX => Key::SourcePrefix { source: first },
        sid::SOURCE_IPV6 => Key::SourceIpv6 { source: first },
        sid::SOURCE_DNS => Key::SourceDns { source: first },
        sid::BRIDGE => Key::Bridge { name: first },
        sid::BRIDGE_PORT => Key::BridgePort { interface: first },
        sid::BRIDGE_MAC => Key::BridgeMac {
            bridge: first,
            mac: parse_mac(d.text()?)?,
        },
        sid::FIREWALL_RULE => Key::FirewallRule {
            vrf: first,
            id: u32::try_from(d.u64()?).map_err(|_| ModelError::Invalid("rule id"))?,
        },
        sid::ADDRESS => Key::Address {
            interface: first,
            address: parse_ip(d.text()?)?,
        },
        sid::ROUTE => {
            let (prefix, len) = parse_prefix(d.text()?)?;
            Key::Route {
                vrf: first,
                prefix,
                len,
            }
        }
        _ => Key::Neighbor {
            interface: first,
            address: parse_ip(d.text()?)?,
        },
    })
}

fn encode_value(value: &Value, e: &mut Encoder<'_>) {
    match value {
        Value::Interface {
            enabled,
            mac,
            mtu,
            vrf,
            vlan,
            tunnel,
            pppoe,
        } => {
            let named = vrf != DEFAULT_VRF;
            let members = 3
                + u64::from(named)
                + if vlan.is_some() { 2 } else { 0 }
                + if tunnel.is_some() { 2 } else { 0 }
                + if pppoe.is_some() { 3 } else { 0 };
            e.map(members)
                .u64(sid::INTERFACE_ENABLED - sid::INTERFACE)
                .bool(*enabled)
                .u64(sid::INTERFACE_PHYS_ADDRESS - sid::INTERFACE)
                .text(&format_mac(mac))
                .u64(sid::INTERFACE_MTU - sid::INTERFACE)
                .u64(u64::from(*mtu));
            if named {
                e.u64(sid::INTERFACE_BIND_NI_NAME - sid::INTERFACE)
                    .text(vrf);
            }
            if let Some(vlan) = vlan {
                e.u64(sid::INTERFACE_PARENT - sid::INTERFACE)
                    .text(&vlan.parent)
                    .u64(sid::INTERFACE_VLAN_ID - sid::INTERFACE)
                    .u64(u64::from(vlan.id));
            }
            if let Some(tunnel) = tunnel {
                e.u64(sid::INTERFACE_TUNNEL_LOCAL - sid::INTERFACE)
                    .text(&tunnel.local.to_string())
                    .u64(sid::INTERFACE_TUNNEL_REMOTE - sid::INTERFACE)
                    .text(&tunnel.remote.to_string());
            }
            if let Some(pppoe) = pppoe {
                e.u64(sid::INTERFACE_PPPOE_PARENT - sid::INTERFACE)
                    .text(&pppoe.parent)
                    .u64(sid::INTERFACE_PPPOE_SESSION - sid::INTERFACE)
                    .u64(u64::from(pppoe.session))
                    .u64(sid::INTERFACE_PPPOE_PEER - sid::INTERFACE)
                    .text(&format_mac(&pppoe.peer));
            }
        }
        Value::Address { prefix_len } => {
            e.map(1)
                .u64(sid::ADDRESS_PREFIX_LENGTH - sid::ADDRESS)
                .u64(u64::from(*prefix_len));
        }
        Value::Route(action) => {
            e.map(1);
            match action {
                RouteAction::Forward(hops) => {
                    e.u64(sid::ROUTE_NEXT_HOP - sid::ROUTE)
                        .array(hops.len() as u64);
                    for hop in hops {
                        let delta = |member: u64| member - sid::ROUTE_NEXT_HOP;
                        e.map(if hop.address.is_some() { 2 } else { 1 })
                            .u64(delta(sid::NEXT_HOP_INTERFACE))
                            .text(&hop.interface);
                        if let Some(address) = hop.address {
                            e.u64(delta(sid::NEXT_HOP_ADDRESS))
                                .text(&address.to_string());
                        }
                    }
                }
                RouteAction::Gateways(gateways) => {
                    e.u64(sid::ROUTE_NEXT_HOP - sid::ROUTE)
                        .array(gateways.len() as u64);
                    for gateway in gateways {
                        e.map(1)
                            .u64(sid::NEXT_HOP_ADDRESS - sid::ROUTE_NEXT_HOP)
                            .text(&gateway.to_string());
                    }
                }
                RouteAction::Local => {
                    e.u64(sid::ROUTE_LOCAL - sid::ROUTE).bool(true);
                }
                RouteAction::Discard => {
                    e.u64(sid::ROUTE_DISCARD - sid::ROUTE).bool(true);
                }
                RouteAction::Reject => {
                    e.u64(sid::ROUTE_REJECT - sid::ROUTE).bool(true);
                }
                RouteAction::LookupVrf(vrf) => {
                    e.u64(sid::ROUTE_LOOKUP_VRF - sid::ROUTE).text(vrf);
                }
            }
        }
        Value::Neighbor { mac } => {
            e.map(1)
                .u64(sid::NEIGHBOR_LINK_LAYER_ADDRESS - sid::NEIGHBOR)
                .text(&format_mac(mac));
        }
        Value::SourcePppoe {
            session,
            peer,
            mtu,
            lifetime,
        } => {
            let d = |member: u64| member - sid::SOURCE_PPPOE;
            e.map(4)
                .u64(d(sid::SOURCE_PPPOE_SESSION))
                .u64(u64::from(*session))
                .u64(d(sid::SOURCE_PPPOE_PEER))
                .text(&format_mac(peer))
                .u64(d(sid::SOURCE_PPPOE_MTU))
                .u64(u64::from(*mtu))
                .u64(d(sid::SOURCE_PPPOE_LIFETIME))
                .u64(u64::from(*lifetime));
        }
        Value::SourceIpv4 {
            address,
            prefix_len,
            lifetime,
        } => {
            let d = |member: u64| member - sid::SOURCE_IPV4;
            e.map(3)
                .u64(d(sid::SOURCE_IPV4_ADDRESS))
                .text(&address.to_string())
                .u64(d(sid::SOURCE_IPV4_PREFIX_LENGTH))
                .u64(u64::from(*prefix_len))
                .u64(d(sid::SOURCE_IPV4_LIFETIME))
                .u64(u64::from(*lifetime));
        }
        Value::SourcePrefix {
            prefix,
            prefix_len,
            preferred,
            valid,
            lifetime,
        } => {
            let d = |member: u64| member - sid::SOURCE_PREFIX;
            e.map(5)
                .u64(d(sid::SOURCE_PREFIX_PREFIX))
                .text(&prefix.to_string())
                .u64(d(sid::SOURCE_PREFIX_PREFIX_LENGTH))
                .u64(u64::from(*prefix_len))
                .u64(d(sid::SOURCE_PREFIX_PREFERRED))
                .u64(u64::from(*preferred))
                .u64(d(sid::SOURCE_PREFIX_VALID))
                .u64(u64::from(*valid))
                .u64(d(sid::SOURCE_PREFIX_LIFETIME))
                .u64(u64::from(*lifetime));
        }
        Value::SourceIpv6 {
            address,
            prefix_len,
            lifetime,
        } => {
            let d = |member: u64| member - sid::SOURCE_IPV6;
            e.map(3)
                .u64(d(sid::SOURCE_IPV6_ADDRESS))
                .text(&address.to_string())
                .u64(d(sid::SOURCE_IPV6_PREFIX_LENGTH))
                .u64(u64::from(*prefix_len))
                .u64(d(sid::SOURCE_IPV6_LIFETIME))
                .u64(u64::from(*lifetime));
        }
        Value::SourceDns { servers, lifetime } => {
            let d = |member: u64| member - sid::SOURCE_DNS;
            e.map(2)
                .u64(d(sid::SOURCE_DNS_ADDRESS))
                .array(servers.len() as u64);
            for server in servers {
                e.text(&server.to_string());
            }
            e.u64(d(sid::SOURCE_DNS_LIFETIME)).u64(u64::from(*lifetime));
        }
        Value::IcmpErrors {
            ipv4_interval_ms,
            ipv6_burst,
            ipv6_interval_ms,
        } => {
            let d = |member: u64| member - sid::ICMP_ERRORS;
            e.map(3)
                .u64(d(sid::ICMP_ERRORS_IPV4_INTERVAL))
                .u64(u64::from(*ipv4_interval_ms))
                .u64(d(sid::ICMP_ERRORS_IPV6_BURST))
                .u64(u64::from(*ipv6_burst))
                .u64(d(sid::ICMP_ERRORS_IPV6_INTERVAL))
                .u64(u64::from(*ipv6_interval_ms));
        }
        Value::FirewallPolicy { filtering, outside } => {
            let default = *filtering == NatFiltering::default();
            e.map(u64::from(!default) + u64::from(!outside.is_empty()));
            if !default {
                e.u64(sid::FIREWALL_POLICY_FILTERING - sid::FIREWALL_POLICY)
                    .text(filtering.name());
            }
            if !outside.is_empty() {
                e.u64(sid::FIREWALL_POLICY_OUTSIDE - sid::FIREWALL_POLICY)
                    .array(outside.len() as u64);
                for name in outside {
                    e.text(name);
                }
            }
        }
        Value::Nat(nat) => {
            let d = |member: u64| member - sid::NAT;
            let ports = match nat.ports {
                NatPorts::Range { .. } => 2,
                NatPorts::Psid { .. } => 3,
            };
            let filtering = nat.filtering != NatFiltering::default();
            let no_id_limit = !nat.ipv4_id_rate_limit;
            e.map(
                2 + ports
                    + u64::from(nat.external.is_some())
                    + u64::from(filtering)
                    + u64::from(no_id_limit)
                    + u64::from(nat.ports_per_host != 0)
                    + u64::from(nat.state_per_host != 0),
            );
            if filtering {
                e.u64(d(sid::NAT_FILTERING)).text(nat.filtering.name());
            }
            if no_id_limit {
                e.u64(d(sid::NAT_IPV4_ID_RATE_LIMIT)).bool(false);
            }
            if nat.ports_per_host != 0 {
                e.u64(d(sid::NAT_PORTS_PER_HOST))
                    .u64(u64::from(nat.ports_per_host));
            }
            if nat.state_per_host != 0 {
                e.u64(d(sid::NAT_STATE_PER_HOST))
                    .u64(u64::from(nat.state_per_host));
            }
            e.u64(d(sid::NAT_INSIDE))
                .text(&nat.inside)
                .u64(d(sid::NAT_OUTSIDE))
                .text(&nat.outside);
            match nat.ports {
                NatPorts::Range { first, last } => {
                    e.u64(d(sid::NAT_FIRST_PORT))
                        .u64(u64::from(first))
                        .u64(d(sid::NAT_LAST_PORT))
                        .u64(u64::from(last));
                }
                NatPorts::Psid {
                    offset,
                    length,
                    psid,
                } => {
                    e.u64(d(sid::NAT_PSID_OFFSET))
                        .u64(u64::from(offset))
                        .u64(d(sid::NAT_PSID_LENGTH))
                        .u64(u64::from(length))
                        .u64(d(sid::NAT_PSID))
                        .u64(u64::from(psid));
                }
            }
            if let Some(external) = nat.external {
                e.u64(d(sid::NAT_EXTERNAL)).text(&external.to_string());
            }
        }
        Value::Punt(class) => encode_punt(class, e),
        Value::Bridge {
            aging_s,
            max_learned,
        } => {
            e.map(2)
                .u64(sid::BRIDGE_AGING_TIME - sid::BRIDGE)
                .u64(u64::from(*aging_s))
                .u64(sid::BRIDGE_MAX_LEARNED - sid::BRIDGE)
                .u64(u64::from(*max_learned));
        }
        Value::BridgePort { bridge } => {
            e.map(1)
                .u64(sid::BRIDGE_PORT_BRIDGE - sid::BRIDGE_PORT)
                .text(bridge);
        }
        Value::BridgeMac { interface } => {
            e.map(1)
                .u64(sid::BRIDGE_MAC_PORT - sid::BRIDGE_MAC)
                .text(interface);
        }
        Value::FirewallRule(rule) => {
            let d = |member: u64| member - sid::FIREWALL_RULE;
            let members = 8 + u64::from(rule.ingress.is_some()) + u64::from(rule.egress.is_some());
            e.map(members)
                .u64(d(sid::FIREWALL_SOURCE))
                .text(&format!("{}/{}", rule.source.0, rule.source.1))
                .u64(d(sid::FIREWALL_DESTINATION))
                .text(&format!("{}/{}", rule.destination.0, rule.destination.1))
                .u64(d(sid::FIREWALL_PROTOCOL))
                .text(match rule.protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                    Protocol::Icmp => "icmp",
                    Protocol::Icmpv6 => "icmpv6",
                })
                .u64(d(sid::FIREWALL_SOURCE_PORT_LOW))
                .u64(u64::from(rule.source_ports.0))
                .u64(d(sid::FIREWALL_SOURCE_PORT_HIGH))
                .u64(u64::from(rule.source_ports.1))
                .u64(d(sid::FIREWALL_DESTINATION_PORT_LOW))
                .u64(u64::from(rule.destination_ports.0))
                .u64(d(sid::FIREWALL_DESTINATION_PORT_HIGH))
                .u64(u64::from(rule.destination_ports.1))
                .u64(d(sid::FIREWALL_ACTION))
                .text(match rule.action {
                    FirewallAction::Accept => "accept",
                    FirewallAction::Drop => "drop",
                });
            if let Some(ingress) = &rule.ingress {
                e.u64(d(sid::FIREWALL_INGRESS)).text(ingress);
            }
            if let Some(egress) = &rule.egress {
                e.u64(d(sid::FIREWALL_EGRESS)).text(egress);
            }
        }
    }
}

fn decode_value(table: u64, d: &mut Decoder<'_>) -> Result<Value, ModelError> {
    if matches!(
        table,
        sid::NAT
            | sid::FIREWALL_POLICY
            | sid::ICMP_ERRORS
            | sid::FIREWALL_RULE
            | sid::PUNT
            | sid::SOURCE_PPPOE
            | sid::SOURCE_IPV4
            | sid::SOURCE_PREFIX
            | sid::SOURCE_IPV6
            | sid::SOURCE_DNS
            | sid::BRIDGE
            | sid::BRIDGE_PORT
            | sid::BRIDGE_MAC
    ) {
        return decode_policy_value(table, d);
    }
    let members = d.map()?;
    let mut enabled = None;
    let mut mac = None;
    let mut mtu = None;
    let mut vrf = None;
    let mut parent = None;
    let mut vlan_id = None;
    let mut tunnel_local = None;
    let mut pppoe_parent = None;
    let mut pppoe_session = None;
    let mut pppoe_peer = None;
    let mut tunnel_remote = None;
    let mut prefix_len = None;
    let mut action = None;
    for _ in 0..members {
        let member = table
            .checked_add(d.u64()?)
            .ok_or(ModelError::Invalid("member SID"))?;
        match member {
            sid::INTERFACE_ENABLED if table == sid::INTERFACE => put(&mut enabled, d.bool()?)?,
            sid::INTERFACE_PHYS_ADDRESS if table == sid::INTERFACE => {
                put(&mut mac, parse_mac(d.text()?)?)?;
            }
            sid::INTERFACE_MTU if table == sid::INTERFACE => {
                put(
                    &mut mtu,
                    u16::try_from(d.u64()?).map_err(|_| ModelError::Invalid("mtu"))?,
                )?;
            }
            sid::INTERFACE_BIND_NI_NAME if table == sid::INTERFACE => {
                put(&mut vrf, d.text()?.to_owned())?;
            }
            sid::INTERFACE_PARENT if table == sid::INTERFACE => {
                put(&mut parent, d.text()?.to_owned())?;
            }
            sid::INTERFACE_VLAN_ID if table == sid::INTERFACE => {
                put(
                    &mut vlan_id,
                    u16::try_from(d.u64()?).map_err(|_| ModelError::Invalid("VLAN ID"))?,
                )?;
            }
            sid::INTERFACE_PPPOE_PARENT if table == sid::INTERFACE => {
                put(&mut pppoe_parent, d.text()?.to_owned())?;
            }
            sid::INTERFACE_PPPOE_SESSION if table == sid::INTERFACE => {
                put(
                    &mut pppoe_session,
                    u16::try_from(d.u64()?).map_err(|_| ModelError::Invalid("PPPoE session"))?,
                )?;
            }
            sid::INTERFACE_PPPOE_PEER if table == sid::INTERFACE => {
                put(&mut pppoe_peer, parse_mac(d.text()?)?)?;
            }
            sid::INTERFACE_TUNNEL_LOCAL if table == sid::INTERFACE => {
                put(&mut tunnel_local, parse_ipv6(d.text()?)?)?;
            }
            sid::INTERFACE_TUNNEL_REMOTE if table == sid::INTERFACE => {
                put(&mut tunnel_remote, parse_ipv6(d.text()?)?)?;
            }
            sid::ROUTE_LOOKUP_VRF if table == sid::ROUTE => {
                put(&mut action, RouteAction::LookupVrf(d.text()?.to_owned()))?;
            }
            sid::ADDRESS_PREFIX_LENGTH if table == sid::ADDRESS => {
                put(
                    &mut prefix_len,
                    u8::try_from(d.u64()?)
                        .ok()
                        .filter(|&len| len <= 128)
                        .ok_or(ModelError::Invalid("prefix length"))?,
                )?;
            }
            sid::ROUTE_NEXT_HOP if table == sid::ROUTE => {
                put(&mut action, decode_next_hops(d)?)?;
            }
            sid::ROUTE_LOCAL | sid::ROUTE_DISCARD | sid::ROUTE_REJECT if table == sid::ROUTE => {
                if !d.bool()? {
                    return Err(ModelError::Invalid("route action flag"));
                }
                put(
                    &mut action,
                    match member {
                        sid::ROUTE_LOCAL => RouteAction::Local,
                        sid::ROUTE_DISCARD => RouteAction::Discard,
                        _ => RouteAction::Reject,
                    },
                )?;
            }
            sid::NEIGHBOR_LINK_LAYER_ADDRESS if table == sid::NEIGHBOR => {
                put(&mut mac, parse_mac(d.text()?)?)?;
            }
            other => return Err(ModelError::UnknownMember(other)),
        }
    }
    match table {
        sid::INTERFACE => Ok(Value::Interface {
            enabled: enabled.unwrap_or(true),
            mac: mac.ok_or(ModelError::Missing("phys-address"))?,
            mtu: mtu.unwrap_or(1500),
            vrf: vrf.unwrap_or_else(|| DEFAULT_VRF.to_owned()),
            vlan: match (parent, vlan_id) {
                (Some(parent), Some(id)) => Some(Vlan { parent, id }),
                (None, None) => None,
                _ => return Err(ModelError::Missing("VLAN parent and ID together")),
            },
            tunnel: match (tunnel_local, tunnel_remote) {
                (Some(local), Some(remote)) => Some(Tunnel { local, remote }),
                (None, None) => None,
                _ => return Err(ModelError::Missing("tunnel local and remote together")),
            },
            pppoe: match (pppoe_parent, pppoe_session, pppoe_peer) {
                (Some(parent), Some(session), Some(peer)) => Some(Pppoe {
                    parent,
                    session,
                    peer,
                }),
                (None, None, None) => None,
                _ => {
                    return Err(ModelError::Missing(
                        "PPPoE parent, session and peer together",
                    ))
                }
            },
        }),
        sid::ADDRESS => Ok(Value::Address {
            prefix_len: prefix_len.ok_or(ModelError::Missing("prefix-length"))?,
        }),
        sid::ROUTE => Ok(Value::Route(
            action.ok_or(ModelError::Missing("route action"))?,
        )),
        sid::NEIGHBOR => Ok(Value::Neighbor {
            mac: mac.ok_or(ModelError::Missing("link-layer-address"))?,
        }),
        _ => Err(ModelError::WrongTable),
    }
}

/// Next hops that all name their interface ([`RouteAction::Forward`]), or that all
/// give only an address ([`RouteAction::Gateways`]).
fn decode_next_hops(d: &mut Decoder<'_>) -> Result<RouteAction, ModelError> {
    let count = d.array()?;
    if count == 0 {
        return Err(ModelError::Missing("next-hop"));
    }
    let mut hops = Vec::new();
    let mut gateways = Vec::new();
    for _ in 0..count {
        let members = d.map()?;
        let mut interface = None;
        let mut address = None;
        for _ in 0..members {
            let member = sid::ROUTE_NEXT_HOP
                .checked_add(d.u64()?)
                .ok_or(ModelError::Invalid("member SID"))?;
            match member {
                sid::NEXT_HOP_INTERFACE => put(&mut interface, d.text()?.to_owned())?,
                sid::NEXT_HOP_ADDRESS => put(&mut address, parse_ip(d.text()?)?)?,
                other => return Err(ModelError::UnknownMember(other)),
            }
        }
        match (interface, address) {
            (Some(interface), address) => hops.push(NextHop { interface, address }),
            (None, Some(address)) => gateways.push(address),
            (None, None) => return Err(ModelError::Missing("outgoing-interface")),
        }
    }
    match (hops.is_empty(), gateways.is_empty()) {
        (false, true) => Ok(RouteAction::Forward(hops)),
        (true, false) => Ok(RouteAction::Gateways(gateways)),
        _ => Err(ModelError::Invalid(
            "next hops with and without an outgoing interface",
        )),
    }
}

/// Stores a member, refusing a second value for the same member (RFC 8949
/// section 5.6: duplicate map keys) or a second route action.
fn put<T>(slot: &mut Option<T>, value: T) -> Result<(), ModelError> {
    if slot.is_some() {
        return Err(ModelError::Invalid("duplicate member"));
    }
    *slot = Some(value);
    Ok(())
}

/// The longest prefix of the address's family.
pub fn max_len(address: &IpAddr) -> u8 {
    if address.is_ipv4() {
        32
    } else {
        128
    }
}

/// `address` with the bits after the first `len` cleared.
pub fn network(address: IpAddr, len: u8) -> IpAddr {
    match address {
        IpAddr::V4(a) => {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(len.min(32)))
                .unwrap_or(0);
            IpAddr::V4((u32::from(a) & mask).into())
        }
        IpAddr::V6(a) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(len.min(128)))
                .unwrap_or(0);
            IpAddr::V6((u128::from(a) & mask).into())
        }
    }
}

/// An IP address in the canonical text of RFC 5952 (for IPv6) or dotted decimal.
fn parse_ip(text: &str) -> Result<IpAddr, ModelError> {
    let address: IpAddr = text
        .parse()
        .map_err(|_| ModelError::Invalid("IP address"))?;
    // One spelling per address, so that keys compare equal (RFC 5952 section 4).
    if address.to_string() != text {
        return Err(ModelError::Invalid("IP address (not canonical)"));
    }
    Ok(address)
}

fn parse_ipv6(text: &str) -> Result<std::net::Ipv6Addr, ModelError> {
    match parse_ip(text)? {
        IpAddr::V6(address) => Ok(address),
        IpAddr::V4(_) => Err(ModelError::Invalid("IPv6 address")),
    }
}

fn parse_prefix(text: &str) -> Result<(IpAddr, u8), ModelError> {
    let (address, len) = text.split_once('/').ok_or(ModelError::Invalid("prefix"))?;
    let address = parse_ip(address)?;
    let canonical = !len.is_empty()
        && len.bytes().all(|b| b.is_ascii_digit())
        && (len == "0" || !len.starts_with('0'));
    if !canonical {
        return Err(ModelError::Invalid("prefix length"));
    }
    let len: u8 = len
        .parse()
        .ok()
        .filter(|&len| len <= max_len(&address))
        .ok_or(ModelError::Invalid("prefix length"))?;
    if network(address, len) != address {
        return Err(ModelError::Invalid("prefix (host bits set)"));
    }
    Ok((address, len))
}

/// Formats a MAC address as YANG `phys-address`: lower-case hex pairs and colons.
pub fn format_mac(mac: &[u8; 6]) -> String {
    let parts: Vec<String> = mac.iter().map(|b| format!("{b:02x}")).collect();
    parts.join(":")
}

/// An interface, address, route, neighbor or bridge entry as a line of text for a person
/// (`ruster show`); `None` for the other tables.
pub fn entry_line(key: &Key, value: &Value) -> Option<String> {
    let line = match (key, value) {
        (
            Key::Interface { name },
            Value::Interface {
                enabled,
                mac,
                mtu,
                vrf,
                vlan,
                tunnel,
                pppoe,
            },
        ) => format!(
            "interface {name} {} mac {} mtu {mtu} vrf {vrf}{}{}{}",
            if *enabled { "up" } else { "down" },
            format_mac(mac),
            vlan.as_ref()
                .map(|v| format!(" vlan {} on {}", v.id, v.parent))
                .unwrap_or_default(),
            tunnel
                .as_ref()
                .map(|t| format!(" tunnel {} to {}", t.local, t.remote))
                .unwrap_or_default(),
            pppoe
                .as_ref()
                .map(|p| format!(
                    " pppoe session {} on {} to {}",
                    p.session,
                    p.parent,
                    format_mac(&p.peer)
                ))
                .unwrap_or_default()
        ),
        (Key::Address { interface, address }, Value::Address { prefix_len }) => {
            format!("address {interface} {address}/{prefix_len}")
        }
        (Key::Route { vrf, prefix, len }, Value::Route(action)) => {
            let action = match action {
                RouteAction::Forward(hops) => hops
                    .iter()
                    .map(|hop| match hop.address {
                        Some(via) => format!("via {via} dev {}", hop.interface),
                        None => format!("dev {}", hop.interface),
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
                RouteAction::Gateways(gateways) => gateways
                    .iter()
                    .map(|via| format!("via {via}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                RouteAction::Local => "local".into(),
                RouteAction::Discard => "discard".into(),
                RouteAction::Reject => "reject".into(),
                RouteAction::LookupVrf(other) => format!("lookup-vrf {other}"),
            };
            format!("route {vrf} {prefix}/{len} {action}")
        }
        (Key::Neighbor { interface, address }, Value::Neighbor { mac }) => {
            format!("neighbor {interface} {address} {}", format_mac(mac))
        }
        (
            Key::Bridge { name },
            Value::Bridge {
                aging_s,
                max_learned,
            },
        ) => format!("bridge {name} aging {aging_s} max-learned {max_learned}"),
        (Key::BridgePort { interface }, Value::BridgePort { bridge }) => {
            format!("bridge-port {interface} bridge {bridge}")
        }
        (Key::BridgeMac { bridge, mac }, Value::BridgeMac { interface }) => {
            format!("bridge-mac {bridge} {} {interface}", format_mac(mac))
        }
        _ => return None,
    };
    Some(line)
}

pub fn parse_mac(text: &str) -> Result<[u8; 6], ModelError> {
    let invalid = ModelError::Invalid("MAC address");
    let mut mac = [0; 6];
    let mut parts = text.split(':');
    for byte in &mut mac {
        let part = parts.next().ok_or(invalid)?;
        if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid);
        }
        *byte = u8::from_str_radix(part, 16).map_err(|_| invalid)?;
    }
    if parts.next().is_some() {
        return Err(invalid);
    }
    Ok(mac)
}

/// The notification the FE sends when a packet's next hop is not in the neighbor
/// table: `{RESOLVE_REQUEST: {1: interface, 2: address}}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolveRequest {
    pub interface: String,
    pub address: IpAddr,
}

impl ResolveRequest {
    pub fn encode(&self, e: &mut Encoder<'_>) {
        e.map(1)
            .u64(sid::RESOLVE_REQUEST)
            .map(2)
            .u64(sid::RESOLVE_REQUEST_INTERFACE - sid::RESOLVE_REQUEST)
            .text(&self.interface)
            .u64(sid::RESOLVE_REQUEST_ADDRESS - sid::RESOLVE_REQUEST)
            .text(&self.address.to_string());
    }

    pub fn decode(d: &mut Decoder<'_>) -> Result<Self, ModelError> {
        if d.map()? != 1 || d.u64()? != sid::RESOLVE_REQUEST {
            return Err(ModelError::Invalid("resolve request"));
        }
        let members = d.map()?;
        let mut interface = None;
        let mut address = None;
        for _ in 0..members {
            match sid::RESOLVE_REQUEST.checked_add(d.u64()?) {
                Some(sid::RESOLVE_REQUEST_INTERFACE) => {
                    put(&mut interface, d.text()?.to_owned())?;
                }
                Some(sid::RESOLVE_REQUEST_ADDRESS) => put(&mut address, parse_ip(d.text()?)?)?,
                Some(other) => return Err(ModelError::UnknownMember(other)),
                None => return Err(ModelError::Invalid("member SID")),
            }
        }
        Ok(Self {
            interface: interface.ok_or(ModelError::Missing("interface"))?,
            address: address.ok_or(ModelError::Missing("address"))?,
        })
    }
}

/// A member of a NAT or firewall value: text or an unsigned integer.
enum Member {
    Text(String),
    Uint(u64),
    Bool(bool),
    List(Vec<String>),
}

fn decode_policy_value(table: u64, d: &mut Decoder<'_>) -> Result<Value, ModelError> {
    let members = d.map()?;
    let mut got: std::collections::BTreeMap<u64, Member> = std::collections::BTreeMap::new();
    for _ in 0..members {
        let member = table
            .checked_add(d.u64()?)
            .ok_or(ModelError::Invalid("member SID"))?;
        let value = match d.peek_kind()? {
            Kind::Text => Member::Text(d.text()?.to_owned()),
            Kind::Unsigned => Member::Uint(d.u64()?),
            Kind::Bool => Member::Bool(d.bool()?),
            Kind::Array => {
                let len = d.array()?;
                if len > MEMBER_LIST_MAX {
                    return Err(ModelError::Invalid("member list"));
                }
                let mut list = Vec::new();
                for _ in 0..len {
                    list.push(d.text()?.to_owned());
                }
                Member::List(list)
            }
            _ => return Err(ModelError::Invalid("member value")),
        };
        if got.insert(member, value).is_some() {
            return Err(ModelError::Invalid("duplicate member"));
        }
    }
    let mut text = |sid: u64, what: &'static str| match got.remove(&sid) {
        Some(Member::Text(t)) => Ok(Some(t)),
        Some(_) => Err(ModelError::Invalid(what)),
        None => Ok(None),
    };
    let value = if table == sid::PUNT {
        decode_punt(&mut got)?
    } else if table == sid::BRIDGE {
        let mut number = |member: u64, what: &'static str| match got.remove(&member) {
            Some(Member::Uint(n)) => u32::try_from(n).map_err(|_| ModelError::Invalid(what)),
            Some(_) => Err(ModelError::Invalid(what)),
            None => Err(ModelError::Missing(what)),
        };
        Value::Bridge {
            aging_s: number(sid::BRIDGE_AGING_TIME, "aging-time")?,
            max_learned: number(sid::BRIDGE_MAX_LEARNED, "max-learned")?,
        }
    } else if table == sid::BRIDGE_PORT {
        Value::BridgePort {
            bridge: text(sid::BRIDGE_PORT_BRIDGE, "bridge-name")?
                .ok_or(ModelError::Missing("bridge-name"))?,
        }
    } else if table == sid::BRIDGE_MAC {
        Value::BridgeMac {
            interface: text(sid::BRIDGE_MAC_PORT, "port")?.ok_or(ModelError::Missing("port"))?,
        }
    } else if matches!(
        table,
        sid::SOURCE_PPPOE
            | sid::SOURCE_IPV4
            | sid::SOURCE_PREFIX
            | sid::SOURCE_IPV6
            | sid::SOURCE_DNS
    ) {
        decode_source(table, &mut got)?
    } else if table == sid::ICMP_ERRORS {
        let mut number = |member: u64, what: &'static str| match got.remove(&member) {
            Some(Member::Uint(n)) => u32::try_from(n)
                .ok()
                .filter(|&n| n > 0)
                .ok_or(ModelError::Invalid(what)),
            Some(_) => Err(ModelError::Invalid(what)),
            None => Err(ModelError::Missing(what)),
        };
        Value::IcmpErrors {
            ipv4_interval_ms: number(sid::ICMP_ERRORS_IPV4_INTERVAL, "ipv4-interval")?,
            ipv6_burst: number(sid::ICMP_ERRORS_IPV6_BURST, "ipv6-burst")?,
            ipv6_interval_ms: number(sid::ICMP_ERRORS_IPV6_INTERVAL, "ipv6-interval")?,
        }
    } else if table == sid::FIREWALL_POLICY {
        let filtering = match text(sid::FIREWALL_POLICY_FILTERING, "filtering-type")? {
            Some(name) => {
                NatFiltering::from_name(&name).ok_or(ModelError::Invalid("filtering-type"))?
            }
            None => NatFiltering::default(),
        };
        let outside = match got.remove(&sid::FIREWALL_POLICY_OUTSIDE) {
            Some(Member::List(list)) => list,
            Some(_) => return Err(ModelError::Invalid("outside")),
            None => Vec::new(),
        };
        Value::FirewallPolicy { filtering, outside }
    } else if table == sid::NAT {
        let inside = text(sid::NAT_INSIDE, "inside")?.ok_or(ModelError::Missing("inside"))?;
        let outside = text(sid::NAT_OUTSIDE, "outside")?.ok_or(ModelError::Missing("outside"))?;
        let external = match text(sid::NAT_EXTERNAL, "external")? {
            Some(t) => Some(
                t.parse()
                    .map_err(|_| ModelError::Invalid("external address"))?,
            ),
            None => None,
        };
        // Left out: endpoint-independent, the default.
        let filtering = match text(sid::NAT_FILTERING, "filtering-type")? {
            Some(name) => {
                NatFiltering::from_name(&name).ok_or(ModelError::Invalid("filtering-type"))?
            }
            None => NatFiltering::default(),
        };
        // Left out: on, the default.
        let ipv4_id_rate_limit = match got.remove(&sid::NAT_IPV4_ID_RATE_LIMIT) {
            None => true,
            Some(Member::Bool(on)) => on,
            Some(_) => return Err(ModelError::Invalid("ipv4-id-rate-limit")),
        };
        // Left out: 0, no limit.
        let limit = |got: &mut std::collections::BTreeMap<u64, Member>,
                     member: u64,
                     what: &'static str| match got.remove(&member) {
            Some(Member::Uint(n)) => u16::try_from(n).map_err(|_| ModelError::Invalid(what)),
            Some(_) => Err(ModelError::Invalid(what)),
            None => Ok(0),
        };
        let ports_per_host = limit(&mut got, sid::NAT_PORTS_PER_HOST, "ports-per-host")?;
        let state_per_host = limit(&mut got, sid::NAT_STATE_PER_HOST, "state-per-host")?;
        let range = (
            port(&mut got, sid::NAT_FIRST_PORT)?,
            port(&mut got, sid::NAT_LAST_PORT)?,
        );
        let set = (
            port(&mut got, sid::NAT_PSID_OFFSET)?,
            port(&mut got, sid::NAT_PSID_LENGTH)?,
            port(&mut got, sid::NAT_PSID)?,
        );
        let ports = match (range, set) {
            ((Some(first), Some(last)), (None, None, None)) => NatPorts::Range { first, last },
            ((None, None), (Some(offset), Some(length), Some(psid))) => NatPorts::Psid {
                offset: u8::try_from(offset).map_err(|_| ModelError::Invalid("PSID offset"))?,
                length: u8::try_from(length).map_err(|_| ModelError::Invalid("PSID length"))?,
                psid,
            },
            _ => return Err(ModelError::Missing("a port range or a PSID")),
        };
        Value::Nat(Nat {
            inside,
            outside,
            external,
            ports,
            filtering,
            ipv4_id_rate_limit,
            ports_per_host,
            state_per_host,
        })
    } else {
        let ingress = text(sid::FIREWALL_INGRESS, "ingress")?;
        let egress = text(sid::FIREWALL_EGRESS, "egress")?;
        let prefix = |t: Option<String>, what: &'static str| -> Result<(IpAddr, u8), ModelError> {
            parse_prefix(&t.ok_or(ModelError::Missing(what))?)
        };
        let source = prefix(text(sid::FIREWALL_SOURCE, "source")?, "source")?;
        let destination = prefix(
            text(sid::FIREWALL_DESTINATION, "destination")?,
            "destination",
        )?;
        let protocol = match text(sid::FIREWALL_PROTOCOL, "protocol")?.as_deref() {
            Some("tcp") => Protocol::Tcp,
            Some("udp") => Protocol::Udp,
            Some("icmp") => Protocol::Icmp,
            Some("icmpv6") => Protocol::Icmpv6,
            _ => return Err(ModelError::Invalid("protocol")),
        };
        let action = match text(sid::FIREWALL_ACTION, "action")?.as_deref() {
            Some("accept") => FirewallAction::Accept,
            Some("drop") => FirewallAction::Drop,
            _ => return Err(ModelError::Invalid("action")),
        };
        let range = |got: &mut std::collections::BTreeMap<u64, Member>,
                     low,
                     high|
         -> Result<(u16, u16), ModelError> {
            Ok((
                port(got, low)?.ok_or(ModelError::Missing("port"))?,
                port(got, high)?.ok_or(ModelError::Missing("port"))?,
            ))
        };
        let source_ports = range(
            &mut got,
            sid::FIREWALL_SOURCE_PORT_LOW,
            sid::FIREWALL_SOURCE_PORT_HIGH,
        )?;
        let destination_ports = range(
            &mut got,
            sid::FIREWALL_DESTINATION_PORT_LOW,
            sid::FIREWALL_DESTINATION_PORT_HIGH,
        )?;
        Value::FirewallRule(FirewallRule {
            ingress,
            egress,
            source,
            destination,
            protocol,
            source_ports,
            destination_ports,
            action,
        })
    };
    if let Some((&unknown, _)) = got.iter().next() {
        return Err(ModelError::UnknownMember(unknown));
    }
    Ok(value)
}

/// A source's value: every member must be there.
fn decode_source(
    table: u64,
    got: &mut std::collections::BTreeMap<u64, Member>,
) -> Result<Value, ModelError> {
    let mut number = |member: u64, what: &'static str| match got.remove(&member) {
        Some(Member::Uint(n)) => Ok(n),
        Some(_) => Err(ModelError::Invalid(what)),
        None => Err(ModelError::Missing(what)),
    };
    let lifetime_sid = match table {
        sid::SOURCE_PPPOE => sid::SOURCE_PPPOE_LIFETIME,
        sid::SOURCE_PREFIX => sid::SOURCE_PREFIX_LIFETIME,
        sid::SOURCE_IPV6 => sid::SOURCE_IPV6_LIFETIME,
        sid::SOURCE_DNS => sid::SOURCE_DNS_LIFETIME,
        _ => sid::SOURCE_IPV4_LIFETIME,
    };
    let lifetime = u32::try_from(number(lifetime_sid, "lifetime")?)
        .map_err(|_| ModelError::Invalid("lifetime"))?;
    if table == sid::SOURCE_PPPOE {
        let session = u16::try_from(number(sid::SOURCE_PPPOE_SESSION, "session-id")?)
            .map_err(|_| ModelError::Invalid("session-id"))?;
        let mtu = u16::try_from(number(sid::SOURCE_PPPOE_MTU, "mtu")?)
            .map_err(|_| ModelError::Invalid("mtu"))?;
        let peer = match got.remove(&sid::SOURCE_PPPOE_PEER) {
            Some(Member::Text(text)) => parse_mac(&text)?,
            Some(_) => return Err(ModelError::Invalid("peer-address")),
            None => return Err(ModelError::Missing("peer-address")),
        };
        return Ok(Value::SourcePppoe {
            session,
            peer,
            mtu,
            lifetime,
        });
    }
    if table == sid::SOURCE_DNS {
        let servers = match got.remove(&sid::SOURCE_DNS_ADDRESS) {
            Some(Member::List(list)) => list
                .iter()
                .map(|text| parse_ip(text))
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err(ModelError::Invalid("address")),
            None => return Err(ModelError::Missing("address")),
        };
        return Ok(Value::SourceDns { servers, lifetime });
    }
    if table == sid::SOURCE_PREFIX || table == sid::SOURCE_IPV6 {
        let (address_sid, len_sid) = if table == sid::SOURCE_PREFIX {
            (sid::SOURCE_PREFIX_PREFIX, sid::SOURCE_PREFIX_PREFIX_LENGTH)
        } else {
            (sid::SOURCE_IPV6_ADDRESS, sid::SOURCE_IPV6_PREFIX_LENGTH)
        };
        let prefix_len = u8::try_from(number(len_sid, "prefix-length")?)
            .map_err(|_| ModelError::Invalid("prefix length"))?;
        let lifetimes = if table == sid::SOURCE_PREFIX {
            let mut seconds = |member: u64, what: &'static str| {
                u32::try_from(number(member, what)?).map_err(|_| ModelError::Invalid(what))
            };
            Some((
                seconds(sid::SOURCE_PREFIX_PREFERRED, "preferred-lifetime")?,
                seconds(sid::SOURCE_PREFIX_VALID, "valid-lifetime")?,
            ))
        } else {
            None
        };
        let address = match got.remove(&address_sid) {
            Some(Member::Text(text)) => match parse_ip(&text)? {
                IpAddr::V6(address) => address,
                IpAddr::V4(_) => return Err(ModelError::Invalid("IPv6 address")),
            },
            Some(_) => return Err(ModelError::Invalid("address")),
            None => return Err(ModelError::Missing("address")),
        };
        return Ok(match lifetimes {
            Some((preferred, valid)) => Value::SourcePrefix {
                prefix: address,
                prefix_len,
                preferred,
                valid,
                lifetime,
            },
            None => Value::SourceIpv6 {
                address,
                prefix_len,
                lifetime,
            },
        });
    }
    let prefix_len = u8::try_from(number(sid::SOURCE_IPV4_PREFIX_LENGTH, "prefix-length")?)
        .map_err(|_| ModelError::Invalid("prefix length"))?;
    let address = match got.remove(&sid::SOURCE_IPV4_ADDRESS) {
        Some(Member::Text(text)) => match parse_ip(&text)? {
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => return Err(ModelError::Invalid("IPv4 address")),
        },
        Some(_) => return Err(ModelError::Invalid("address")),
        None => return Err(ModelError::Missing("address")),
    };
    Ok(Value::SourceIpv4 {
        address,
        prefix_len,
        lifetime,
    })
}

fn port(
    got: &mut std::collections::BTreeMap<u64, Member>,
    sid: u64,
) -> Result<Option<u16>, ModelError> {
    match got.remove(&sid) {
        Some(Member::Uint(n)) => u16::try_from(n)
            .map(Some)
            .map_err(|_| ModelError::Invalid("port")),
        Some(_) => Err(ModelError::Invalid("port")),
        None => Ok(None),
    }
}

/// The checks of a punt class that do not depend on the other classes.
fn validate_punt(class: &PuntClass) -> Result<(), ModelError> {
    if class.rate == 0 || class.burst == 0 {
        return Err(ModelError::Invalid("punt rate or burst"));
    }
    if class.interface.as_deref() == Some("") {
        return Err(ModelError::Invalid("empty name"));
    }
    if let PuntDestination::Control(name) = &class.destination {
        if !is_control_name(name) {
            return Err(ModelError::Invalid("punt control socket name"));
        }
    }
    match class.matches {
        // A frame has no IP packet to give the kernel.
        PuntMatch::Kind(kind) if kind.is_frame() => {
            if class.destination == PuntDestination::Kernel {
                return Err(ModelError::Invalid(
                    "punt destination (a frame to the kernel)",
                ));
            }
        }
        // The kernel's kinds are what is left of the traffic to the router.
        PuntMatch::Kind(_) => {
            if matches!(class.destination, PuntDestination::Control(_)) {
                return Err(ModelError::Invalid("punt destination (a kernel kind)"));
            }
        }
        PuntMatch::Ip { protocol, ports } => {
            if let Some((first, last)) = ports {
                if !matches!(protocol, 6 | 17) || first > last {
                    return Err(ModelError::Invalid("punt ports"));
                }
            }
        }
    }
    Ok(())
}

fn encode_punt(class: &PuntClass, e: &mut Encoder<'_>) {
    let d = |member: u64| member - sid::PUNT;
    let matches = match class.matches {
        PuntMatch::Kind(_) | PuntMatch::Ip { ports: None, .. } => 1,
        PuntMatch::Ip { ports: Some(_), .. } => 3,
    };
    e.map(3 + matches + u64::from(class.interface.is_some()));
    match class.matches {
        PuntMatch::Kind(kind) => {
            e.u64(d(sid::PUNT_KIND)).text(kind.name());
        }
        PuntMatch::Ip { protocol, ports } => {
            e.u64(d(sid::PUNT_PROTOCOL)).u64(u64::from(protocol));
            if let Some((first, last)) = ports {
                e.u64(d(sid::PUNT_FIRST_PORT))
                    .u64(u64::from(first))
                    .u64(d(sid::PUNT_LAST_PORT))
                    .u64(u64::from(last));
            }
        }
    }
    if let Some(interface) = &class.interface {
        e.u64(d(sid::PUNT_INTERFACE)).text(interface);
    }
    match &class.destination {
        PuntDestination::Control(name) => {
            e.u64(d(sid::PUNT_CONTROL)).text(name);
        }
        PuntDestination::Kernel => {
            e.u64(d(sid::PUNT_KERNEL)).bool(true);
        }
        PuntDestination::Drop => {
            e.u64(d(sid::PUNT_DROP)).bool(true);
        }
    }
    e.u64(d(sid::PUNT_RATE))
        .u64(u64::from(class.rate))
        .u64(d(sid::PUNT_BURST))
        .u64(u64::from(class.burst));
}

type Members = std::collections::BTreeMap<u64, Member>;

fn decode_punt(got: &mut Members) -> Result<Value, ModelError> {
    let text = |got: &mut Members, member: u64, what: &'static str| match got.remove(&member) {
        Some(Member::Text(t)) => Ok(Some(t)),
        Some(_) => Err(ModelError::Invalid(what)),
        None => Ok(None),
    };
    let kind = match text(got, sid::PUNT_KIND, "punt kind")? {
        Some(name) => Some(PuntKind::from_name(&name).ok_or(ModelError::Invalid("punt kind"))?),
        None => None,
    };
    let protocol = match got.remove(&sid::PUNT_PROTOCOL) {
        Some(Member::Uint(n)) => {
            Some(u8::try_from(n).map_err(|_| ModelError::Invalid("punt protocol"))?)
        }
        Some(_) => return Err(ModelError::Invalid("punt protocol")),
        None => None,
    };
    let ports = match (
        port(got, sid::PUNT_FIRST_PORT)?,
        port(got, sid::PUNT_LAST_PORT)?,
    ) {
        (Some(first), Some(last)) => Some((first, last)),
        (None, None) => None,
        _ => return Err(ModelError::Missing("first-port and last-port together")),
    };
    let matches = match (kind, protocol) {
        (Some(kind), None) if ports.is_none() => PuntMatch::Kind(kind),
        (None, Some(protocol)) => PuntMatch::Ip { protocol, ports },
        _ => return Err(ModelError::Invalid("punt match (a kind or a protocol)")),
    };
    let interface = text(got, sid::PUNT_INTERFACE, "punt interface")?;
    let control = text(got, sid::PUNT_CONTROL, "punt control")?;
    let flag = |got: &mut Members, member: u64| match got.remove(&member) {
        Some(Member::Bool(true)) => Ok(true),
        Some(_) => Err(ModelError::Invalid("punt destination flag")),
        None => Ok(false),
    };
    let kernel = flag(got, sid::PUNT_KERNEL)?;
    let drop = flag(got, sid::PUNT_DROP)?;
    let destination = match (control, kernel, drop) {
        (Some(name), false, false) => PuntDestination::Control(name),
        (None, true, false) => PuntDestination::Kernel,
        (None, false, true) => PuntDestination::Drop,
        _ => return Err(ModelError::Invalid("punt destination (exactly one)")),
    };
    let number = |got: &mut Members, member: u64, what: &'static str| match got.remove(&member) {
        Some(Member::Uint(n)) => u32::try_from(n).map_err(|_| ModelError::Invalid(what)),
        Some(_) => Err(ModelError::Invalid(what)),
        None => Err(ModelError::Missing(what)),
    };
    Ok(Value::Punt(PuntClass {
        matches,
        interface,
        destination,
        rate: number(got, sid::PUNT_RATE, "rate")?,
        burst: number(got, sid::PUNT_BURST, "burst")?,
    }))
}
