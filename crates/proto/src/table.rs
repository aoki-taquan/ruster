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
//! family, and a next hop must be of the route's family.
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
//! - RFC 5952 section 4: an IPv6 address is accepted only in its canonical text, so
//!   one address is one key.
//!
//! Deviations: the route and neighbor tables are ruster's own models, and the SIDs are
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
    /// One forward firewall rule of a VRF; lower ids are matched first.
    FirewallRule {
        vrf: String,
        id: u32,
    },
    /// The WireGuard settings of an interface (one per interface).
    Wireguard {
        interface: String,
    },
    /// One peer of a WireGuard interface.
    WireguardPeer {
        interface: String,
        peer: String,
    },
    /// The session keys of a peer, as the key exchange left them.
    WireguardSession {
        interface: String,
        peer: String,
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
    /// Which outside endpoints may reach an inside endpoint with a flow out, where
    /// no rule decides. Left out of the message when it is the default.
    FirewallPolicy {
        filtering: NatFiltering,
        /// The interfaces outside the network the firewall guards (RFC 6092's
        /// exterior), by name.
        outside: Vec<String>,
    },
    FirewallRule(FirewallRule),
    Wireguard(Wireguard),
    WireguardPeer(WireguardPeer),
    WireguardSession(WireguardSession),
}

/// An interface that is a WireGuard interface (`ruster-if-wireguard`): the UDP port
/// it listens on and the IPv4 address its packets leave from. The interface entry
/// of the same name gives its MAC address and MTU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wireguard {
    pub listen_port: u16,
    pub local: std::net::Ipv4Addr,
}

/// A peer: where its packets go, and the addresses it may send from and be sent to
/// (cryptokey routing).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireguardPeer {
    pub endpoint: std::net::Ipv4Addr,
    pub port: u16,
    pub allowed: Vec<(std::net::Ipv4Addr, u8)>,
}

/// The keys and indexes of a peer's current session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireguardSession {
    /// Seals what the router sends.
    pub send: [u8; 32],
    /// Opens what the router receives.
    pub receive: [u8; 32],
    /// The receiver index of what the router sends (the peer's own index).
    pub peer_index: u32,
    /// The receiver index of what the router receives (the router's own index).
    pub local_index: u32,
}

/// The most allowed prefixes a peer has.
pub const WIREGUARD_MAX_ALLOWED: usize = 64;

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
            Self::FirewallRule { .. } => sid::FIREWALL_RULE,
            Self::Wireguard { .. } => sid::WIREGUARD,
            Self::WireguardPeer { .. } => sid::WIREGUARD_PEER,
            Self::WireguardSession { .. } => sid::WIREGUARD_SESSION,
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
            Key::Nat { vrf } | Key::FirewallPolicy { vrf } | Key::FirewallRule { vrf, .. } => {
                name(vrf)?
            }
            Key::Address { interface, .. } | Key::Neighbor { interface, .. } => name(interface)?,
            Key::Wireguard { interface } => name(interface)?,
            Key::WireguardPeer { interface, peer } | Key::WireguardSession { interface, peer } => {
                name(interface)?;
                name(peer)?;
            }
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
                        | (Key::FirewallRule { .. }, Value::FirewallRule(_))
                        | (Key::Wireguard { .. }, Value::Wireguard(_))
                        | (Key::WireguardPeer { .. }, Value::WireguardPeer(_))
                        | (Key::WireguardSession { .. }, Value::WireguardSession(_))
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
                    Value::Interface { vrf, vlan, .. } => {
                        name(vrf)?;
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
                    Value::Wireguard(wireguard) => {
                        if wireguard.listen_port == 0 || !usable_ipv4(wireguard.local) {
                            return Err(ModelError::Invalid("WireGuard port or address"));
                        }
                    }
                    Value::WireguardPeer(peer) => {
                        if peer.port == 0 || !usable_ipv4(peer.endpoint) {
                            return Err(ModelError::Invalid("WireGuard endpoint"));
                        }
                        if peer.allowed.is_empty() || peer.allowed.len() > WIREGUARD_MAX_ALLOWED {
                            return Err(ModelError::Invalid("WireGuard allowed addresses"));
                        }
                        for (address, len) in &peer.allowed {
                            parse_prefix(&format!("{address}/{len}"))?;
                        }
                    }
                    Value::WireguardSession(session) => {
                        if session.send == [0; 32] || session.receive == [0; 32] {
                            return Err(ModelError::Invalid("WireGuard session key"));
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
        Key::Wireguard { interface } => {
            e.array(2).u64(sid::WIREGUARD).text(interface);
        }
        Key::WireguardPeer { interface, peer } => {
            e.array(3)
                .u64(sid::WIREGUARD_PEER)
                .text(interface)
                .text(peer);
        }
        Key::WireguardSession { interface, peer } => {
            e.array(3)
                .u64(sid::WIREGUARD_SESSION)
                .text(interface)
                .text(peer);
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
        sid::INTERFACE | sid::NAT | sid::FIREWALL_POLICY | sid::WIREGUARD => 2,
        sid::ADDRESS
        | sid::ROUTE
        | sid::NEIGHBOR
        | sid::FIREWALL_RULE
        | sid::WIREGUARD_PEER
        | sid::WIREGUARD_SESSION => 3,
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
        sid::WIREGUARD => Key::Wireguard { interface: first },
        sid::WIREGUARD_PEER | sid::WIREGUARD_SESSION => {
            let peer = d.text()?.to_owned();
            if table == sid::WIREGUARD_PEER {
                Key::WireguardPeer {
                    interface: first,
                    peer,
                }
            } else {
                Key::WireguardSession {
                    interface: first,
                    peer,
                }
            }
        }
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
        Value::Wireguard(wireguard) => {
            e.map(2)
                .u64(sid::WIREGUARD_LISTEN_PORT - sid::WIREGUARD)
                .u64(u64::from(wireguard.listen_port))
                .u64(sid::WIREGUARD_LOCAL - sid::WIREGUARD)
                .text(&wireguard.local.to_string());
        }
        Value::WireguardPeer(peer) => {
            e.map(3)
                .u64(sid::WIREGUARD_PEER_ENDPOINT - sid::WIREGUARD_PEER)
                .text(&peer.endpoint.to_string())
                .u64(sid::WIREGUARD_PEER_PORT - sid::WIREGUARD_PEER)
                .u64(u64::from(peer.port))
                .u64(sid::WIREGUARD_PEER_ALLOWED - sid::WIREGUARD_PEER)
                .array(peer.allowed.len() as u64);
            for (address, len) in &peer.allowed {
                e.text(&format!("{address}/{len}"));
            }
        }
        Value::WireguardSession(session) => {
            e.map(4)
                .u64(sid::WIREGUARD_SESSION_SEND - sid::WIREGUARD_SESSION)
                .bytes(&session.send)
                .u64(sid::WIREGUARD_SESSION_RECEIVE - sid::WIREGUARD_SESSION)
                .bytes(&session.receive)
                .u64(sid::WIREGUARD_SESSION_PEER_INDEX - sid::WIREGUARD_SESSION)
                .u64(u64::from(session.peer_index))
                .u64(sid::WIREGUARD_SESSION_LOCAL_INDEX - sid::WIREGUARD_SESSION)
                .u64(u64::from(session.local_index));
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
            e.map(2 + ports + u64::from(nat.external.is_some()) + u64::from(filtering));
            if filtering {
                e.u64(d(sid::NAT_FILTERING)).text(nat.filtering.name());
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
            | sid::FIREWALL_RULE
            | sid::WIREGUARD
            | sid::WIREGUARD_PEER
            | sid::WIREGUARD_SESSION
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
                put(&mut action, RouteAction::Forward(decode_next_hops(d)?))?;
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

fn decode_next_hops(d: &mut Decoder<'_>) -> Result<Vec<NextHop>, ModelError> {
    let count = d.array()?;
    if count == 0 {
        return Err(ModelError::Missing("next-hop"));
    }
    let mut hops = Vec::new();
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
        hops.push(NextHop {
            interface: interface.ok_or(ModelError::Missing("outgoing-interface"))?,
            address,
        });
    }
    Ok(hops)
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
/// An IPv4 address a WireGuard endpoint or local address may be.
fn usable_ipv4(address: std::net::Ipv4Addr) -> bool {
    !(address.is_unspecified() || address.is_loopback() || address.is_multicast())
}

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

/// The notification the FE sends when a packet is for a WireGuard peer that has no
/// session: `{KEY_REQUEST: {1: interface, 2: peer}}`. The key exchange for that
/// peer is due.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyExchangeRequest {
    pub interface: String,
    pub peer: String,
}

impl KeyExchangeRequest {
    pub fn encode(&self, e: &mut Encoder<'_>) {
        e.map(1)
            .u64(sid::WIREGUARD_KEY_REQUEST)
            .map(2)
            .u64(sid::WIREGUARD_KEY_REQUEST_INTERFACE - sid::WIREGUARD_KEY_REQUEST)
            .text(&self.interface)
            .u64(sid::WIREGUARD_KEY_REQUEST_PEER - sid::WIREGUARD_KEY_REQUEST)
            .text(&self.peer);
    }

    pub fn decode(d: &mut Decoder<'_>) -> Result<Self, ModelError> {
        if d.map()? != 1 || d.u64()? != sid::WIREGUARD_KEY_REQUEST {
            return Err(ModelError::Invalid("key exchange request"));
        }
        let members = d.map()?;
        let mut interface = None;
        let mut peer = None;
        for _ in 0..members {
            match sid::WIREGUARD_KEY_REQUEST.checked_add(d.u64()?) {
                Some(sid::WIREGUARD_KEY_REQUEST_INTERFACE) => {
                    put(&mut interface, d.text()?.to_owned())?;
                }
                Some(sid::WIREGUARD_KEY_REQUEST_PEER) => put(&mut peer, d.text()?.to_owned())?,
                Some(other) => return Err(ModelError::UnknownMember(other)),
                None => return Err(ModelError::Invalid("member SID")),
            }
        }
        Ok(Self {
            interface: interface.ok_or(ModelError::Missing("interface"))?,
            peer: peer.ok_or(ModelError::Missing("peer"))?,
        })
    }
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
    Bytes(Vec<u8>),
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
            Kind::Bytes => Member::Bytes(d.bytes()?.to_vec()),
            Kind::Array => {
                let len = d.array()?;
                if len > WIREGUARD_MAX_ALLOWED as u64 {
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
    let value = if table == sid::WIREGUARD {
        let local = text(sid::WIREGUARD_LOCAL, "local-address")?
            .ok_or(ModelError::Missing("local-address"))?
            .parse()
            .map_err(|_| ModelError::Invalid("local-address"))?;
        let listen_port = port(&mut got, sid::WIREGUARD_LISTEN_PORT)?
            .ok_or(ModelError::Missing("listen-port"))?;
        Value::Wireguard(Wireguard { listen_port, local })
    } else if table == sid::WIREGUARD_PEER {
        let endpoint = text(sid::WIREGUARD_PEER_ENDPOINT, "endpoint-address")?
            .ok_or(ModelError::Missing("endpoint-address"))?
            .parse()
            .map_err(|_| ModelError::Invalid("endpoint-address"))?;
        let port = port(&mut got, sid::WIREGUARD_PEER_PORT)?
            .ok_or(ModelError::Missing("endpoint-port"))?;
        let Some(Member::List(list)) = got.remove(&sid::WIREGUARD_PEER_ALLOWED) else {
            return Err(ModelError::Missing("allowed-ips"));
        };
        let mut allowed = Vec::new();
        for prefix in list {
            match parse_prefix(&prefix)? {
                (IpAddr::V4(address), len) => allowed.push((address, len)),
                _ => return Err(ModelError::Invalid("allowed-ips")),
            }
        }
        Value::WireguardPeer(WireguardPeer {
            endpoint,
            port,
            allowed,
        })
    } else if table == sid::WIREGUARD_SESSION {
        let mut key = |member: u64, what: &'static str| match got.remove(&member) {
            Some(Member::Bytes(bytes)) => {
                <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| ModelError::Invalid(what))
            }
            Some(_) => Err(ModelError::Invalid(what)),
            None => Err(ModelError::Missing(what)),
        };
        let send = key(sid::WIREGUARD_SESSION_SEND, "send-key")?;
        let receive = key(sid::WIREGUARD_SESSION_RECEIVE, "receive-key")?;
        let mut index = |member: u64, what: &'static str| match got.remove(&member) {
            Some(Member::Uint(n)) => u32::try_from(n).map_err(|_| ModelError::Invalid(what)),
            Some(_) => Err(ModelError::Invalid(what)),
            None => Err(ModelError::Missing(what)),
        };
        let peer_index = index(sid::WIREGUARD_SESSION_PEER_INDEX, "peer-index")?;
        let local_index = index(sid::WIREGUARD_SESSION_LOCAL_INDEX, "local-index")?;
        Value::WireguardSession(WireguardSession {
            send,
            receive,
            peer_index,
            local_index,
        })
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
