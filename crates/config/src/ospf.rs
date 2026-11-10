//! `[ospf]` and `[ospf6]`: OSPFv2 and OSPFv3, which FRR's ospfd and ospf6d speak on
//! the TAP devices of their interfaces (`docs/design/overlay.md` section 6) and
//! `ruster-frr` configures.

use serde::{Deserialize, Serialize};

use crate::Interface;

/// The area of an interface when not told: the backbone (RFC 2328 section 3).
pub const OSPF_AREA: &str = "0.0.0.0";
/// An interface's cost when not told.
pub const OSPF_COST: u32 = 10;
/// An interface's network type when not told: an Ethernet is a broadcast network
/// (RFC 2328 section 1.2).
pub const OSPF_NETWORK: &str = "broadcast";
/// The network types taken.
pub const OSPF_NETWORKS: [&str; 2] = ["broadcast", "point-to-point"];

/// OSPFv2 or OSPFv3 in the default VRF, every value given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Ospf {
    /// The router ID, a 32-bit number written as an IPv4 address.
    pub router_id: String,
    pub interface: Vec<OspfInterface>,
}

/// One interface OSPF runs on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct OspfInterface {
    pub name: String,
    /// The area ID, written as an IPv4 address.
    pub area: String,
    pub cost: u32,
    /// One of [`OSPF_NETWORKS`].
    pub network: String,
    /// Its prefixes are announced, but no adjacency is formed on it.
    pub passive: bool,
}

/// `[ospf]` or `[ospf6]` of `ruster.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct OspfEntry {
    router_id: Option<String>,
    /// The area of the interfaces that name none.
    area: Option<String>,
    #[serde(default)]
    interface: Vec<OspfInterfaceEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct OspfInterfaceEntry {
    name: String,
    area: Option<String>,
    cost: Option<u32>,
    network: Option<String>,
    passive: Option<bool>,
}

/// `[ospf]` or `[ospf6]` (`at`): the router ID is the first IPv4 address of the
/// default VRF's interfaces when not given.
pub(crate) fn resolve(
    at: &str,
    entry: OspfEntry,
    interfaces: &[Interface],
) -> Result<Ospf, String> {
    let router_id = match entry.router_id {
        Some(id) => id,
        None => crate::bgp::first_ipv4(interfaces).ok_or_else(|| {
            format!("{at}: give router-id; no interface of the default VRF has an ipv4 address")
        })?,
    };
    let area = entry.area.unwrap_or_else(|| OSPF_AREA.to_owned());
    Ok(Ospf {
        router_id,
        interface: entry
            .interface
            .into_iter()
            .map(|i| OspfInterface {
                name: i.name,
                area: i.area.unwrap_or_else(|| area.clone()),
                cost: i.cost.unwrap_or(OSPF_COST),
                network: i.network.unwrap_or_else(|| OSPF_NETWORK.to_owned()),
                passive: i.passive.unwrap_or(false),
            })
            .collect(),
    })
}
