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
//! RFC 9254. Addresses, prefixes and MAC addresses are text, as YANG types them.
//! Only IPv4 is here; IPv6 comes after the skeleton.

use std::fmt;
use std::net::Ipv4Addr;

use crate::cbor::{DecodeError, Decoder, Encoder, Kind};
use crate::sid;

/// The key of one entry: which table, and which row.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Key {
    Interface {
        name: String,
    },
    Address {
        interface: String,
        address: Ipv4Addr,
    },
    Route {
        vrf: String,
        prefix: Ipv4Addr,
        len: u8,
    },
    Neighbor {
        interface: String,
        address: Ipv4Addr,
    },
}

/// The value of one entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Interface {
        enabled: bool,
        mac: [u8; 6],
        mtu: u16,
    },
    Address {
        prefix_len: u8,
    },
    Route(RouteAction),
    Neighbor {
        mac: [u8; 6],
    },
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NextHop {
    pub interface: String,
    /// `None` for an on-link route, where the destination itself is the next hop.
    pub address: Option<Ipv4Addr>,
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

    pub fn encode(&self, e: &mut Encoder<'_>) {
        e.map(1);
        encode_key(&self.key, e);
        match &self.value {
            None => {
                e.null();
            }
            Some(value) => encode_value(value, e),
        }
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
        Ok(Self { key, value })
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
    }
}

pub fn decode_key(d: &mut Decoder<'_>) -> Result<Key, ModelError> {
    let len = d.array()?;
    let table = d.u64()?;
    let expected = match table {
        sid::INTERFACE => 2,
        sid::ADDRESS | sid::ROUTE | sid::NEIGHBOR => 3,
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
        sid::ADDRESS => Key::Address {
            interface: first,
            address: parse_ipv4(d.text()?)?,
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
            address: parse_ipv4(d.text()?)?,
        },
    })
}

fn encode_value(value: &Value, e: &mut Encoder<'_>) {
    match value {
        Value::Interface { enabled, mac, mtu } => {
            e.map(3)
                .u64(sid::INTERFACE_ENABLED - sid::INTERFACE)
                .bool(*enabled)
                .u64(sid::INTERFACE_PHYS_ADDRESS - sid::INTERFACE)
                .text(&format_mac(mac))
                .u64(sid::INTERFACE_MTU - sid::INTERFACE)
                .u64(u64::from(*mtu));
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
            }
        }
        Value::Neighbor { mac } => {
            e.map(1)
                .u64(sid::NEIGHBOR_LINK_LAYER_ADDRESS - sid::NEIGHBOR)
                .text(&format_mac(mac));
        }
    }
}

fn decode_value(table: u64, d: &mut Decoder<'_>) -> Result<Value, ModelError> {
    let members = d.map()?;
    let mut enabled = None;
    let mut mac = None;
    let mut mtu = None;
    let mut prefix_len = None;
    let mut action = None;
    for _ in 0..members {
        let member = table
            .checked_add(d.u64()?)
            .ok_or(ModelError::Invalid("member SID"))?;
        match member {
            sid::INTERFACE_ENABLED if table == sid::INTERFACE => enabled = Some(d.bool()?),
            sid::INTERFACE_PHYS_ADDRESS if table == sid::INTERFACE => {
                mac = Some(parse_mac(d.text()?)?);
            }
            sid::INTERFACE_MTU if table == sid::INTERFACE => {
                mtu = Some(u16::try_from(d.u64()?).map_err(|_| ModelError::Invalid("mtu"))?);
            }
            sid::ADDRESS_PREFIX_LENGTH if table == sid::ADDRESS => {
                prefix_len = Some(
                    u8::try_from(d.u64()?)
                        .ok()
                        .filter(|&len| len <= 32)
                        .ok_or(ModelError::Invalid("prefix length"))?,
                );
            }
            sid::ROUTE_NEXT_HOP if table == sid::ROUTE => {
                action = Some(RouteAction::Forward(decode_next_hops(d)?));
            }
            sid::ROUTE_LOCAL | sid::ROUTE_DISCARD | sid::ROUTE_REJECT if table == sid::ROUTE => {
                if !d.bool()? {
                    return Err(ModelError::Invalid("route action flag"));
                }
                action = Some(match member {
                    sid::ROUTE_LOCAL => RouteAction::Local,
                    sid::ROUTE_DISCARD => RouteAction::Discard,
                    _ => RouteAction::Reject,
                });
            }
            sid::NEIGHBOR_LINK_LAYER_ADDRESS if table == sid::NEIGHBOR => {
                mac = Some(parse_mac(d.text()?)?);
            }
            other => return Err(ModelError::UnknownMember(other)),
        }
    }
    match table {
        sid::INTERFACE => Ok(Value::Interface {
            enabled: enabled.unwrap_or(true),
            mac: mac.ok_or(ModelError::Missing("phys-address"))?,
            mtu: mtu.unwrap_or(1500),
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
                sid::NEXT_HOP_INTERFACE => interface = Some(d.text()?.to_owned()),
                sid::NEXT_HOP_ADDRESS => address = Some(parse_ipv4(d.text()?)?),
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

fn parse_ipv4(text: &str) -> Result<Ipv4Addr, ModelError> {
    text.parse()
        .map_err(|_| ModelError::Invalid("IPv4 address"))
}

fn parse_prefix(text: &str) -> Result<(Ipv4Addr, u8), ModelError> {
    let (address, len) = text.split_once('/').ok_or(ModelError::Invalid("prefix"))?;
    let address = parse_ipv4(address)?;
    let len: u8 = len
        .parse()
        .ok()
        .filter(|&len| len <= 32)
        .ok_or(ModelError::Invalid("prefix length"))?;
    let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
    if u32::from(address) & !mask != 0 {
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
        if part.len() != 2 {
            return Err(invalid);
        }
        *byte = u8::from_str_radix(part, 16).map_err(|_| invalid)?;
    }
    if parts.next().is_some() {
        return Err(invalid);
    }
    Ok(mac)
}
