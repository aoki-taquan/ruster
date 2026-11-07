//! The configuration file, in TOML.
//!
//! ```toml
//! [[interface]]
//! name = "lan"                 # the FE port (the Linux device name)
//! mac = "02:00:00:00:00:01"
//! mtu = 1500                   # optional, 1500 when left out
//! enabled = true               # optional, true when left out
//! ipv4 = "192.0.2.1/24"        # optional
//!
//! [[route]]
//! prefix = "0.0.0.0/0"
//! interface = "wan"
//! via = "198.51.100.1"         # optional; left out for an on-link route
//! ```

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use serde::Deserialize;

use crate::{Config, InterfaceConfig, StaticRoute};

/// The smallest MTU an IPv4 interface may have (RFC 791).
const MIN_MTU: u16 = ruster_proto::table::MIN_MTU;

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

/// Reads a configuration from the text of a configuration file.
pub fn parse(text: &str) -> Result<Config, String> {
    let file: File = toml::from_str(text).map_err(|error| error.to_string())?;
    let mut names = BTreeSet::new();
    let mut interfaces = Vec::with_capacity(file.interface.len());
    for entry in file.interface {
        let at = format!("interface {:?}", entry.name);
        if entry.name.is_empty() || entry.name.len() > 255 {
            return Err(format!("{at}: the name must be 1 to 255 bytes"));
        }
        if !names.insert(entry.name.clone()) {
            return Err(format!("{at}: given twice"));
        }
        let mac =
            mac(&entry.mac).ok_or_else(|| format!("{at}: mac is not like 02:00:00:00:00:01"))?;
        if mac[0] & 1 != 0 || mac == [0; 6] {
            return Err(format!("{at}: mac must be a unicast address"));
        }
        if entry.mtu < MIN_MTU {
            return Err(format!("{at}: mtu must be at least {MIN_MTU}"));
        }
        let ipv4 = match &entry.ipv4 {
            Some(text) => {
                let (address, len) =
                    prefix(text).ok_or_else(|| format!("{at}: ipv4 is not like 192.0.2.1/24"))?;
                if len == 0 {
                    return Err(format!("{at}: ipv4 needs a prefix length of 1 to 32"));
                }
                Some((address, len))
            }
            None => None,
        };
        interfaces.push(InterfaceConfig {
            name: entry.name,
            mac,
            mtu: entry.mtu,
            enabled: entry.enabled,
            ipv4,
        });
    }
    let mut static_routes = Vec::with_capacity(file.route.len());
    let mut prefixes = BTreeSet::new();
    for entry in file.route {
        let at = format!("route {:?}", entry.prefix);
        let (address, len) =
            prefix(&entry.prefix).ok_or_else(|| format!("{at}: prefix is not like 10.0.0.0/8"))?;
        let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
        if u32::from(address) & !mask != 0 {
            return Err(format!("{at}: bits are set after the prefix length"));
        }
        if !prefixes.insert((address, len)) {
            return Err(format!("{at}: given twice"));
        }
        if !names.contains(&entry.interface) {
            return Err(format!("{at}: no interface {:?}", entry.interface));
        }
        let via = match &entry.via {
            Some(text) => Some(
                text.parse::<Ipv4Addr>()
                    .map_err(|_| format!("{at}: via is not an IPv4 address"))?,
            ),
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

fn prefix(text: &str) -> Option<(Ipv4Addr, u8)> {
    let (address, len) = text.split_once('/')?;
    if len.is_empty() || len.len() > 2 || !len.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let len: u8 = len.parse().ok()?;
    (len <= 32).then_some(())?;
    Some((address.parse().ok()?, len))
}
