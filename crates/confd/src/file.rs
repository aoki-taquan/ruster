//! The configuration file, in TOML.
//!
//! ```toml
//! [[interface]]
//! name = "lan"                 # the FE port (the Linux device name)
//! mac = "02:00:00:00:00:01"
//! mtu = 1500                   # optional, 1500 when left out
//! enabled = true               # optional, true when left out
//! ipv4 = "192.0.2.1/24"        # optional
//! ipv6 = ["2001:db8:1::1/64"]  # optional; a link-local address is added by itself
//!
//! [[route]]
//! prefix = "0.0.0.0/0"         # or an IPv6 prefix such as "::/0"
//! interface = "wan"
//! via = "198.51.100.1"         # optional; left out for an on-link route
//! ```
//!
//! # Standards
//!
//! - RFC 791: the smallest MTU is 68.
//! - RFC 6890 and RFC 1122 section 3.2.1.3: IPv4 interface addresses and next hops
//!   must be usable unicast addresses (not 0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/4 or
//!   240.0.0.0/4).
//! - RFC 4291 section 2.5: IPv6 interface addresses and next hops must not be
//!   unspecified, loopback or multicast. A link-local next hop is allowed: it is on
//!   the route's interface.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Deserialize;

use crate::{Config, InterfaceConfig, StaticRoute};

/// The smallest MTU an IPv4 interface may have (RFC 791).
const MIN_MTU: u16 = ruster_proto::table::MIN_MTU;
/// The FE takes Ethernet frames of up to 1514 bytes.
const MAX_MTU: u16 = 1_500;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    interface: Vec<InterfaceEntry>,
    #[serde(default)]
    route: Vec<RouteEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InterfaceEntry {
    name: String,
    mac: String,
    #[serde(default = "default_mtu")]
    mtu: u16,
    #[serde(default = "default_enabled")]
    enabled: bool,
    ipv4: Option<String>,
    #[serde(default)]
    ipv6: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteEntry {
    prefix: String,
    interface: String,
    via: Option<String>,
}

fn default_mtu() -> u16 {
    1_500
}

fn default_enabled() -> bool {
    true
}

/// What the interfaces of a file have, to check addresses and routes against.
#[derive(Default)]
struct Seen {
    names: BTreeSet<String>,
    addresses: BTreeSet<IpAddr>,
    /// Connected prefixes (link-local ones are on every interface and not counted).
    connected: BTreeSet<(IpAddr, u8)>,
}

impl Seen {
    fn address(&mut self, at: &str, address: IpAddr, len: u8) -> Result<(), String> {
        if !self.addresses.insert(address) {
            return Err(format!("{at}: {address} is on another interface too"));
        }
        let link_local = matches!(address, IpAddr::V6(a) if a.is_unicast_link_local());
        if !link_local && !self.connected.insert((network(address, len), len)) {
            return Err(format!("{at}: another interface has the same prefix"));
        }
        Ok(())
    }
}

/// Reads a configuration from the text of a configuration file.
pub fn parse(text: &str) -> Result<Config, String> {
    let file: File = toml::from_str(text).map_err(|error| error.to_string())?;
    let mut seen = Seen::default();
    let mut interfaces = Vec::with_capacity(file.interface.len());
    for entry in file.interface {
        let at = format!("interface {:?}", entry.name);
        if entry.name.is_empty() || entry.name.len() > 255 {
            return Err(format!("{at}: the name must be 1 to 255 bytes"));
        }
        if !seen.names.insert(entry.name.clone()) {
            return Err(format!("{at}: given twice"));
        }
        let mac =
            mac(&entry.mac).ok_or_else(|| format!("{at}: mac is not like 02:00:00:00:00:01"))?;
        if mac[0] & 1 != 0 || mac == [0; 6] {
            return Err(format!("{at}: mac must be a unicast address"));
        }
        if !(MIN_MTU..=MAX_MTU).contains(&entry.mtu) {
            return Err(format!("{at}: mtu must be {MIN_MTU} to {MAX_MTU}"));
        }
        let ipv4 = match &entry.ipv4 {
            Some(text) => {
                let Some((IpAddr::V4(address), len)) = prefix(text) else {
                    return Err(format!("{at}: ipv4 is not like 192.0.2.1/24"));
                };
                if len == 0 {
                    return Err(format!("{at}: ipv4 needs a prefix length of 1 to 32"));
                }
                if !unicast_v4(address) {
                    return Err(format!("{at}: ipv4 must be a unicast address"));
                }
                seen.address(&at, address.into(), len)?;
                Some((address, len))
            }
            None => None,
        };
        let mut ipv6 = Vec::with_capacity(entry.ipv6.len());
        for text in &entry.ipv6 {
            let Some((IpAddr::V6(address), len)) = prefix(text) else {
                return Err(format!("{at}: ipv6 {text:?} is not like 2001:db8::1/64"));
            };
            if len == 0 {
                return Err(format!(
                    "{at}: ipv6 {text:?} needs a prefix length of 1 to 128"
                ));
            }
            if !unicast_v6(address) {
                return Err(format!("{at}: ipv6 {text:?} must be a unicast address"));
            }
            seen.address(&at, address.into(), len)?;
            ipv6.push((address, len));
        }
        interfaces.push(InterfaceConfig {
            name: entry.name,
            mac,
            mtu: entry.mtu,
            enabled: entry.enabled,
            ipv4,
            ipv6,
        });
    }
    let mut static_routes = Vec::with_capacity(file.route.len());
    let mut prefixes = BTreeSet::new();
    for entry in file.route {
        let at = format!("route {:?}", entry.prefix);
        let (address, len) = prefix(&entry.prefix)
            .ok_or_else(|| format!("{at}: prefix is not like 10.0.0.0/8 or 2001:db8::/32"))?;
        if network(address, len) != address {
            return Err(format!("{at}: bits are set after the prefix length"));
        }
        if !prefixes.insert((address, len)) {
            return Err(format!("{at}: given twice"));
        }
        if !seen.names.contains(&entry.interface) {
            return Err(format!("{at}: no interface {:?}", entry.interface));
        }
        let via = match &entry.via {
            Some(text) => {
                let via = text
                    .parse::<IpAddr>()
                    .ok()
                    .filter(|via| via.is_ipv4() == address.is_ipv4())
                    .filter(|via| match via {
                        IpAddr::V4(v) => unicast_v4(*v),
                        IpAddr::V6(v) => unicast_v6(*v),
                    })
                    .filter(|via| !seen.addresses.contains(via));
                Some(via.ok_or_else(|| {
                    format!("{at}: via must be a unicast address of another host, of the prefix's family")
                })?)
            }
            None => None,
        };
        static_routes.push(StaticRoute {
            prefix: address,
            len,
            interface: entry.interface,
            via,
        });
    }
    Ok(Config {
        interfaces,
        static_routes,
    })
}

fn mac(text: &str) -> Option<[u8; 6]> {
    let mut out = [0_u8; 6];
    let mut parts = text.split(':');
    for byte in &mut out {
        let part = parts.next()?;
        if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

fn prefix(text: &str) -> Option<(IpAddr, u8)> {
    let (address, len) = text.split_once('/')?;
    if len.is_empty() || len.len() > 3 || !len.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let len: u8 = len.parse().ok()?;
    let address: IpAddr = address.parse().ok()?;
    (len <= ruster_proto::table::max_len(&address)).then_some((address, len))
}

fn network(address: IpAddr, len: u8) -> IpAddr {
    ruster_proto::table::network(address, len)
}

/// An address a host can have: not unspecified, loopback, multicast, broadcast or
/// reserved (240.0.0.0/4).
fn unicast_v4(address: Ipv4Addr) -> bool {
    let first = address.octets()[0];
    first != 0 && !address.is_loopback() && first < 224
}

fn unicast_v6(address: Ipv6Addr) -> bool {
    !address.is_unspecified() && !address.is_loopback() && !address.is_multicast()
}
