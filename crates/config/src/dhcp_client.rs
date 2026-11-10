//! `[[dhcp-client]]`: the WAN side's DHCP client (`ruster-dhcpc`) on one interface.

use serde::{Deserialize, Serialize};

use crate::{Interface, Kind, VERSION};

/// How many DHCP packets per second, and at once, the FE hands the client from one
/// interface: a client exchanges a few per lease, and a flood is kept short.
pub const DHCP_CLIENT_PUNT_RATE: u32 = 20;
pub const DHCP_CLIENT_PUNT_BURST: u32 = 20;

/// The DHCP client on one interface, every value given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct DhcpClient {
    /// A port or VLAN.
    pub interface: String,
    pub vrf: String,
    /// The interface's MAC address and its link-local address (from the MAC).
    pub mac: String,
    pub link_local: String,
    /// None or one: run DHCPv4 and write to this source (of kind dhcp-client).
    pub ipv4_source: Vec<String>,
    /// None or one: run DHCPv6 with prefix delegation and write to this source (of
    /// kind dhcpv6-client).
    pub ipv6_source: Vec<String>,
    /// Whether DHCPv6 also asks for an address (IA_NA).
    pub ipv6_address: bool,
    /// Whether to send ribd the default routes: IPv4's to the router option's
    /// address, IPv6's to the address the DHCPv6 replies come from.
    pub default_route: bool,
    /// The FE's rate limit on the DHCP it hands over from the interface.
    pub punt_rate: u32,
    pub punt_burst: u32,
}

/// `[[dhcp-client]]` of `ruster.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct DhcpClientEntry {
    interface: String,
    ipv4_source: Option<String>,
    ipv6_source: Option<String>,
    ipv6_address: Option<bool>,
    default_route: Option<bool>,
    punt_rate: Option<u32>,
    punt_burst: Option<u32>,
}

/// `[[dhcp-client]]`: the interface's VRF, MAC and link-local address; DHCPv4's
/// source is the interface's `ipv4-from` when not given.
pub(crate) fn resolve(
    entry: DhcpClientEntry,
    interfaces: &[Interface],
) -> Result<DhcpClient, String> {
    let at = format!("dhcp-client {:?}", entry.interface);
    let interface = interfaces
        .iter()
        .find(|i| i.name == entry.interface)
        .ok_or_else(|| format!("{at}: no such interface"))?;
    if !matches!(interface.kind, Kind::Port | Kind::Vlan { .. }) {
        return Err(format!("{at}: the interface must be a port or a VLAN"));
    }
    let bytes =
        crate::dhcp6::mac(&interface.mac).ok_or_else(|| format!("{at}: the interface's mac"))?;
    let ipv4_source = match entry.ipv4_source {
        Some(source) => vec![source],
        None => interface.ipv4_from.clone(),
    };
    let ipv6_source: Vec<String> = entry.ipv6_source.into_iter().collect();
    if ipv4_source.is_empty() && ipv6_source.is_empty() {
        return Err(format!(
            "{at}: give ipv4-source or ipv6-source (or ipv4-from on the interface)"
        ));
    }
    Ok(DhcpClient {
        interface: entry.interface,
        vrf: interface.vrf.clone(),
        mac: interface.mac.clone(),
        link_local: crate::link_local(bytes).to_string(),
        ipv4_source,
        ipv6_source,
        ipv6_address: entry.ipv6_address.unwrap_or(false),
        default_route: entry.default_route.unwrap_or(true),
        punt_rate: entry.punt_rate.unwrap_or(DHCP_CLIENT_PUNT_RATE),
        punt_burst: entry.punt_burst.unwrap_or(DHCP_CLIENT_PUNT_BURST),
    })
}

/// The part of the lock form that `ruster-dhcpc` takes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct DhcpClientPart {
    version: u32,
    dhcp_client: Vec<DhcpClient>,
}

/// `ruster-dhcpc`'s part of the lock form as TOML text: `version = 1` and
/// `dhcp-client`.
pub fn dhcp_client_part(entries: &[DhcpClient]) -> String {
    let part = DhcpClientPart {
        version: VERSION,
        dhcp_client: entries.to_vec(),
    };
    toml::to_string(&part).expect("the lock form is plain TOML")
}

/// Reads `ruster-dhcpc`'s part of the lock form ([`dhcp_client_part`]).
pub fn parse_dhcp_client_part(text: &str) -> Result<Vec<DhcpClient>, String> {
    crate::check_version(text)?;
    let part: DhcpClientPart = toml::from_str(text).map_err(|e| e.to_string())?;
    Ok(part.dhcp_client)
}
