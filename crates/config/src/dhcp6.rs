//! `[[dhcp6]]`: a DHCPv6 server (Kea, through `ruster-kea`) for one interface.

use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};

use crate::{Dns, Interface, DHCP_PUNT_BURST, DHCP_PUNT_RATE};

/// The preferred and valid lifetimes of a leased address, in seconds (Kea's own
/// defaults).
pub const DHCP6_PREFERRED_LIFETIME: u32 = 3_600;
pub const DHCP6_VALID_LIFETIME: u32 = 7_200;

/// The DHCPv6 server for one interface: Kea, which `ruster-kea` configures and
/// relays to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Dhcp6 {
    pub interface: String,
    /// The interface's MAC address and its link-local address (from the MAC): the
    /// source of the replies to clients.
    pub mac: String,
    pub link_local: String,
    /// One of the interface's global IPv6 addresses and its prefix length: the
    /// relay's link-address, and the subnet.
    pub address: String,
    /// The first and last address leased, as `first-last`.
    pub pool: String,
    /// In seconds.
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    /// The DNS Recursive Name Server option.
    pub dns: Vec<String>,
    /// The FE's rate limit on the DHCPv6 it hands over from the interface.
    pub punt_rate: u32,
    pub punt_burst: u32,
}

/// `[[dhcp6]]` of `ruster.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct Dhcp6Entry {
    interface: String,
    pool: String,
    preferred_lifetime: Option<u32>,
    valid_lifetime: Option<u32>,
    dns: Option<Vec<String>>,
    punt_rate: Option<u32>,
    punt_burst: Option<u32>,
}

/// The link-local address of a MAC address: fe80::/64 and its modified EUI-64
/// interface identifier (RFC 4291 section 2.5.1, RFC 2464 section 4).
pub fn link_local(mac: [u8; 6]) -> Ipv6Addr {
    Ipv6Addr::from([
        0xfe,
        0x80,
        0,
        0,
        0,
        0,
        0,
        0,
        mac[0] ^ 0x02,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ])
}

/// `aa:bb:cc:dd:ee:ff` as bytes.
fn mac(text: &str) -> Option<[u8; 6]> {
    let mut out = [0; 6];
    let mut parts = text.split(':');
    for byte in &mut out {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// `[[dhcp6]]`: the interface's MAC, link-local and first global address, and the
/// defaults.
pub(crate) fn resolve(
    entry: Dhcp6Entry,
    interfaces: &[Interface],
    dns: Option<&Dns>,
) -> Result<Dhcp6, String> {
    let at = format!("dhcp6 {:?}", entry.interface);
    let interface = interfaces
        .iter()
        .find(|i| i.name == entry.interface)
        .ok_or_else(|| format!("{at}: no such interface"))?;
    let bytes = mac(&interface.mac).ok_or_else(|| format!("{at}: the interface's mac"))?;
    let global: Vec<(&String, Ipv6Addr)> = interface
        .ipv6
        .iter()
        .filter_map(|text| {
            let address: Ipv6Addr = text.split_once('/')?.0.parse().ok()?;
            (!address.is_unicast_link_local()).then_some((text, address))
        })
        .collect();
    let (address, _) = global
        .first()
        .ok_or_else(|| format!("{at}: the interface has no global ipv6 address"))?;
    let listened: Vec<String> = dns.map_or_else(Vec::new, |dns| {
        global
            .iter()
            .map(|(_, a)| a.to_string())
            .filter(|a| dns.listen.contains(a))
            .collect()
    });
    Ok(Dhcp6 {
        interface: entry.interface,
        mac: interface.mac.clone(),
        link_local: link_local(bytes).to_string(),
        address: (*address).clone(),
        pool: entry.pool,
        preferred_lifetime: entry.preferred_lifetime.unwrap_or(DHCP6_PREFERRED_LIFETIME),
        valid_lifetime: entry.valid_lifetime.unwrap_or(DHCP6_VALID_LIFETIME),
        dns: entry.dns.unwrap_or(listened),
        punt_rate: entry.punt_rate.unwrap_or(DHCP_PUNT_RATE),
        punt_burst: entry.punt_burst.unwrap_or(DHCP_PUNT_BURST),
    })
}
