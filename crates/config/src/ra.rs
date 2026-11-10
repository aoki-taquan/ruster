//! `[[ra]]`: the Router Advertisements neighd sends on one interface, and their
//! defaults (RFC 4861 section 6.2.1).

use std::net::{IpAddr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::{Dns, Interface, VERSION};

/// MaxRtrAdvInterval, in seconds.
pub const RA_MAX_INTERVAL: u32 = 600;
/// AdvCurHopLimit: the value the IANA registry gives for IPv6, 64.
pub const RA_HOP_LIMIT: u8 = 64;
/// AdvValidLifetime and AdvPreferredLifetime of each prefix, in seconds.
pub const RA_VALID_LIFETIME: u32 = 2_592_000;
pub const RA_PREFERRED_LIFETIME: u32 = 604_800;

/// MinRtrAdvInterval for a MaxRtrAdvInterval: 0.33 of it from 9 s, and at least
/// the 3 s the same section allows. Below 9 s RFC 4861 gives MaxRtrAdvInterval
/// itself, which is above the 0.75 of it that the section allows, so 0.75 of it is
/// used.
pub fn ra_min_interval(max: u32) -> u32 {
    if max >= 9 {
        (max * 33 / 100).max(3)
    } else {
        max * 3 / 4
    }
}

/// The Router Advertisements on one interface, every value given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Ra {
    pub interface: String,
    /// MinRtrAdvInterval and MaxRtrAdvInterval, in seconds.
    pub min_interval: u32,
    pub max_interval: u32,
    /// AdvDefaultLifetime, in seconds; 0: not a default router.
    pub router_lifetime: u32,
    /// AdvCurHopLimit; 0: unspecified.
    pub hop_limit: u8,
    /// AdvManagedFlag and AdvOtherConfigFlag.
    pub managed: bool,
    pub other: bool,
    /// AdvLinkMTU: none (no MTU option) or one.
    pub mtu: Vec<u16>,
    /// AdvReachableTime and AdvRetransTimer, in milliseconds; 0: unspecified.
    pub reachable_time: u32,
    pub retrans_timer: u32,
    /// The Recursive DNS Server option's addresses (RFC 8106); none: no option.
    pub dns: Vec<String>,
    /// Its lifetime, in seconds.
    pub dns_lifetime: u32,
    /// The sources whose delegated prefixes it also advertises, found at run time:
    /// the source of the interface's `ipv6-from`, whose /64 confd adds to `prefix`
    /// in the part it hands neighd, with the delegated prefix's lifetimes.
    pub prefix_from: Vec<String>,
    /// AdvPrefixList.
    pub prefix: Vec<RaPrefix>,
}

/// One prefix of AdvPrefixList.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RaPrefix {
    /// `network/len`.
    pub prefix: String,
    /// AdvOnLinkFlag and AdvAutonomousFlag.
    pub on_link: bool,
    pub autonomous: bool,
    /// In seconds; 4294967295 is infinity.
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
}

/// `[[ra]]` of `ruster.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct RaEntry {
    interface: String,
    min_interval: Option<u32>,
    max_interval: Option<u32>,
    router_lifetime: Option<u32>,
    hop_limit: Option<u8>,
    managed: Option<bool>,
    other: Option<bool>,
    mtu: Option<u16>,
    reachable_time: Option<u32>,
    retrans_timer: Option<u32>,
    dns: Option<Vec<String>>,
    dns_lifetime: Option<u32>,
    valid_lifetime: Option<u32>,
    preferred_lifetime: Option<u32>,
}

/// `[[ra]]`: the defaults, the prefixes of the interface's /64 addresses, and the
/// interface's addresses that `[dns]` listens on as the DNS servers.
pub(crate) fn resolve(
    entry: RaEntry,
    interfaces: &[Interface],
    dns: Option<&Dns>,
) -> Result<Ra, String> {
    let at = format!("ra {:?}", entry.interface);
    let interface = interfaces
        .iter()
        .find(|i| i.name == entry.interface)
        .ok_or_else(|| format!("{at}: no such interface"))?;
    let max_interval = entry.max_interval.unwrap_or(RA_MAX_INTERVAL);
    let valid_lifetime = entry.valid_lifetime.unwrap_or(RA_VALID_LIFETIME);
    let preferred_lifetime = entry.preferred_lifetime.unwrap_or(RA_PREFERRED_LIFETIME);
    let mut prefix = Vec::new();
    let mut own = Vec::new();
    for text in &interface.ipv6 {
        let (address, network) = v6_and_network(text)
            .ok_or_else(|| format!("{at}: ipv6 {text:?} is not an address and prefix length"))?;
        if address.is_unicast_link_local() {
            continue;
        }
        own.push(address.to_string());
        if text.ends_with("/64") && !prefix.iter().any(|p: &RaPrefix| p.prefix == network) {
            prefix.push(RaPrefix {
                prefix: network,
                on_link: true,
                autonomous: true,
                valid_lifetime,
                preferred_lifetime,
            });
        }
    }
    let listened: Vec<String> = dns.map_or_else(Vec::new, |dns| {
        own.iter()
            .filter(|a| dns.listen.contains(a))
            .cloned()
            .collect()
    });
    Ok(Ra {
        interface: entry.interface,
        min_interval: entry
            .min_interval
            .unwrap_or_else(|| ra_min_interval(max_interval)),
        max_interval,
        router_lifetime: entry
            .router_lifetime
            .unwrap_or_else(|| max_interval.saturating_mul(3)),
        hop_limit: entry.hop_limit.unwrap_or(RA_HOP_LIMIT),
        managed: entry.managed.unwrap_or(false),
        other: entry.other.unwrap_or(false),
        mtu: entry.mtu.into_iter().collect(),
        reachable_time: entry.reachable_time.unwrap_or(0),
        retrans_timer: entry.retrans_timer.unwrap_or(0),
        dns: entry.dns.unwrap_or(listened),
        // RFC 8106 section 5.1: by default at least 3 * MaxRtrAdvInterval.
        dns_lifetime: entry
            .dns_lifetime
            .unwrap_or_else(|| max_interval.saturating_mul(3)),
        prefix_from: interface
            .ipv6_from
            .iter()
            .map(|f| f.source.clone())
            .collect(),
        prefix,
    })
}

/// An IPv6 `address/len` and its network as `network/len`.
fn v6_and_network(text: &str) -> Option<(Ipv6Addr, String)> {
    let (address, len) = text.split_once('/')?;
    let address: Ipv6Addr = address.parse().ok()?;
    let len: u8 = len.parse().ok().filter(|len| *len <= 128)?;
    let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
    let network = IpAddr::from(Ipv6Addr::from(u128::from(address) & mask));
    Some((address, format!("{network}/{len}")))
}

/// The part of the lock form that neighd takes for its Router Advertisements.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RaPart {
    version: u32,
    ra: Vec<Ra>,
}

/// neighd's Router Advertisement part of the lock form as TOML text: `version = 1`
/// and `ra`.
pub fn ra_part(ra: &[Ra]) -> String {
    let part = RaPart {
        version: VERSION,
        ra: ra.to_vec(),
    };
    toml::to_string(&part).expect("the lock form is plain TOML")
}

/// Reads neighd's Router Advertisement part of the lock form ([`ra_part`]).
pub fn parse_ra_part(text: &str) -> Result<Vec<Ra>, String> {
    crate::check_version(text)?;
    let part: RaPart = toml::from_str(text).map_err(|e| e.to_string())?;
    Ok(part.ra)
}
