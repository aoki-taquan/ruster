//! What confd makes from the prefixes delegated to its sources (DHCPv6-PD) at run
//! time: the configuration with those values in it.
//!
//! The lock form names the source only (`ipv6-from`, `prefix-from`); the prefix is
//! a value found at run time (`docs/design/router-box.md`, "lockに入れる値と入れない値").
//! confd keeps the configuration it was given and works out the one it uses from it
//! and the sources' values ([`with_delegated`]) whenever either changes. The FE,
//! ribd, neighd and the module parts all follow the one it uses.
//!
//! - An interface with `ipv6-from = { source, subnet }` gets the /64 of subnet ID
//!   `subnet` in the source's prefix, with the router at ::1 in it.
//! - An `[[ra]]` whose `prefix-from` names that source advertises that /64 too,
//!   on-link and for SLAAC, with the delegated prefix's lifetimes.
//!
//! # Standards
//!
//! - RFC 8415 section 6.3 and RFC 7084 L-2: the router numbers its LAN links from
//!   the delegated prefix, a /64 each (RFC 4291 section 2.5.1, RFC 4862 section
//!   5.5.3 for SLAAC).
//! - RFC 9096 section 3 (recommendation 1): the advertised prefix's preferred and
//!   valid lifetimes are at most the delegated prefix's.
//!
//! Deviations: the router's address is ::1 of the /64, not one made from the MAC
//! (EUI-64), so it does not change with the hardware. The lifetimes advertised
//! are those the delegating router gave at the last renewal, not counted down
//! (they are refreshed at each renewal, which comes well before they run out). A
//! prefix longer than /64, or one with no room for the subnet ID, numbers nothing.
//! The derived address is not checked against the other interfaces' prefixes.

use std::net::{IpAddr, Ipv6Addr};

use ruster_config::RaPrefix;

use crate::source::Sources;
use crate::Config;

/// The /64 of subnet ID `subnet` in `prefix/len`, if there is room for it.
pub fn subnet(prefix: Ipv6Addr, len: u8, subnet: u32) -> Option<Ipv6Addr> {
    if len > 64 {
        return None;
    }
    let room = 64 - u32::from(len);
    if room < 32 && subnet >> room != 0 {
        return None;
    }
    let base = u128::from(prefix) & !(u128::MAX >> len);
    Some(Ipv6Addr::from(base | (u128::from(subnet) << 64)))
}

/// `base` with the values the sources have now: the delegated /64s of the
/// interfaces and the prefixes advertised for them.
pub(crate) fn with_delegated(base: &Config, sources: &Sources) -> Config {
    let mut out = base.clone();
    for interface in &mut out.interfaces {
        let Some((source, id)) = &interface.ipv6_from else {
            continue;
        };
        let Some((prefix, len, preferred, valid)) = sources.prefix(source) else {
            continue;
        };
        let Some(network) = subnet(prefix, len, *id) else {
            continue;
        };
        let address = Ipv6Addr::from(u128::from(network) | 1);
        if !interface.ipv6.contains(&(address, 64)) {
            interface.ipv6.push((address, 64));
        }
        for ra in out.ra.iter_mut().filter(|ra| {
            ra.interface == interface.name && ra.prefix_from.iter().any(|s| s == source)
        }) {
            let text = format!("{}/64", IpAddr::V6(network));
            if ra.prefix.iter().all(|p| p.prefix != text) {
                ra.prefix.push(RaPrefix {
                    prefix: text,
                    on_link: true,
                    autonomous: true,
                    valid_lifetime: valid,
                    preferred_lifetime: preferred.min(valid),
                });
            }
        }
    }
    out
}
