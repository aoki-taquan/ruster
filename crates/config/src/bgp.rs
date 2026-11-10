//! `[bgp]`: BGP, which FRR's bgpd speaks and `ruster-frr` configures.

use serde::{Deserialize, Serialize};

use ruster_proto::table::DEFAULT_VRF;

use crate::{Interface, VERSION};

/// BGP in the default VRF, every value given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Bgp {
    /// The router's AS number.
    #[serde(rename = "as")]
    pub asn: u32,
    /// The BGP Identifier, an IPv4 address.
    pub router_id: String,
    /// The prefixes it announces, IPv4 or IPv6.
    pub networks: Vec<String>,
    /// None or one: a file of FRR settings that ruster-frr adds to FRR's
    /// configuration as it is (route-maps and the like).
    pub include: Vec<String>,
    pub neighbor: Vec<BgpNeighbor>,
}

/// One BGP neighbor. The session carries the unicast routes of its address's
/// family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct BgpNeighbor {
    pub address: String,
    pub remote_as: u32,
    /// None or one.
    pub description: Vec<String>,
}

/// A prefix of one of the default VRF's interfaces, which `ruster-frr` uses to find
/// the interface of a next hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Connected {
    pub interface: String,
    /// `network/len`.
    pub prefix: String,
    /// The interface's link-local address (from its MAC address), which the
    /// router gives an IPv6 neighbor on the link as its next hop.
    pub link_local: String,
}

/// `[bgp]` of `ruster.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct BgpEntry {
    #[serde(rename = "as")]
    asn: u32,
    router_id: Option<String>,
    #[serde(default)]
    networks: Vec<String>,
    include: Option<String>,
    #[serde(default)]
    neighbor: Vec<NeighborEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct NeighborEntry {
    address: String,
    remote_as: u32,
    description: Option<String>,
}

/// `[bgp]`: the router ID is the first IPv4 address of the default VRF's interfaces
/// when not given.
pub(crate) fn resolve(entry: BgpEntry, interfaces: &[Interface]) -> Result<Bgp, String> {
    let router_id = match entry.router_id {
        Some(id) => id,
        None => interfaces
            .iter()
            .filter(|i| i.vrf == DEFAULT_VRF && i.enabled)
            .flat_map(|i| &i.ipv4)
            .find_map(|a| a.split_once('/').map(|(a, _)| a.to_owned()))
            .ok_or("bgp: give router-id; no interface of the default VRF has an ipv4 address")?,
    };
    Ok(Bgp {
        asn: entry.asn,
        router_id,
        networks: entry.networks,
        include: entry.include.into_iter().collect(),
        neighbor: entry
            .neighbor
            .into_iter()
            .map(|n| BgpNeighbor {
                address: n.address,
                remote_as: n.remote_as,
                description: n.description.into_iter().collect(),
            })
            .collect(),
    })
}

/// The part of the lock form that `ruster-frr` takes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrrPart {
    version: u32,
    bgp: Vec<Bgp>,
    connected: Vec<Connected>,
}

/// `ruster-frr`'s part of the lock form as TOML text: `version = 1`, `bgp` (none or
/// one) and `connected`, the prefixes of the default VRF's interfaces that confd
/// worked out from them.
pub fn frr_part(bgp: Option<&Bgp>, connected: &[Connected]) -> String {
    let part = FrrPart {
        version: VERSION,
        bgp: bgp.into_iter().cloned().collect(),
        connected: connected.to_vec(),
    };
    toml::to_string(&part).expect("the lock form is plain TOML")
}

/// Reads `ruster-frr`'s part of the lock form ([`frr_part`]).
pub fn parse_frr_part(text: &str) -> Result<(Option<Bgp>, Vec<Connected>), String> {
    crate::check_version(text)?;
    let part: FrrPart = toml::from_str(text).map_err(|e| crate::toml_error(text, &e))?;
    match <[Bgp; 1]>::try_from(part.bgp) {
        Ok([bgp]) => Ok((Some(bgp), part.connected)),
        Err(none) if none.is_empty() => Ok((None, part.connected)),
        Err(_) => Err("bgp takes at most one value".into()),
    }
}
