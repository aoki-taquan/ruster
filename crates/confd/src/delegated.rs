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
//! - `[dns]`'s `upstream-from`: the DNS servers its sources have now, in order and
//!   once each, go to `ruster-unbound` with the `dns` part (`upstream-found`).
//! - A `[map-e]` with `prefix-from` is a MAP-E CE of the source's prefix: its
//!   tunnel, NAT and routes come and go with the prefix, worked out as for a
//!   prefix given (RFC 7597 sections 5.2 and 6, [`crate::file`]).
//!
//! # Standards
//!
//! - RFC 8415 section 6.3 and RFC 7084 L-2: the router numbers its LAN links from
//!   the delegated prefix, a /64 each (RFC 4291 section 2.5.1, RFC 4862 section
//!   5.5.3 for SLAAC).
//! - RFC 9096 section 3: the advertised prefix's preferred and valid lifetimes are
//!   at most the delegated prefix's, and at most ND_PREFERRED_LIMIT (2700 s) and
//!   ND_VALID_LIMIT (5400 s).
//!
//! Deviations: the router's address is ::1 of the /64, not one made from the MAC
//! (EUI-64), so it does not change with the hardware. The lifetimes advertised
//! are those the delegating router gave at the last renewal, not counted down
//! (they are refreshed at each renewal, which comes well before they run out). A
//! prefix longer than /64, or one with no room for the subnet ID, numbers nothing.
//! A prefix that went away is no longer advertised, rather than advertised with a
//! preferred lifetime of 0 for a while (RFC 9096 section 3, which updates RFC 7084
//! L-13).
//! The derived address is not checked against the other interfaces' prefixes. A
//! MAP-E prefix that does not fit the rule, or whose CE address is on a link's
//! prefix (so the LAN must not take subnet 0 of it), makes no CE, with nothing
//! said; nor is its IPv4 address checked against the other interfaces'.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ruster_config::RaPrefix;
use ruster_proto::table::{network, DEFAULT_VRF};

use crate::source::Sources;
use crate::{Config, RouteTarget, StaticRoute};

/// RFC 9096 section 3's caps on an advertised prefix's lifetimes, in seconds.
pub const ND_PREFERRED_LIMIT: u32 = 2_700;
pub const ND_VALID_LIMIT: u32 = 5_400;

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
                    valid_lifetime: valid.min(ND_VALID_LIMIT),
                    preferred_lifetime: preferred.min(valid).min(ND_PREFERRED_LIMIT),
                });
            }
        }
    }
    if let Some(dns) = &base.dns {
        for name in &dns.upstream_from {
            for server in sources.dns(name) {
                if !out.dns_found.contains(server) {
                    out.dns_found.push(*server);
                }
            }
        }
    }
    if let Some((entry, source)) = &base.map_e_from {
        if let Some((prefix, len, _, _)) = sources.prefix(source) {
            map_e(&mut out, entry, (prefix, len));
        }
    }
    out
}

/// The MAP-E CE of `prefix`: its tunnel, its NAT on the PSID's ports, the default
/// IPv4 route into the tunnel and a discard route for the prefix, as for a prefix
/// given ([`crate::file`]). Nothing when the prefix does not fit the rule, or
/// the CE's address would be on a link's prefix.
fn map_e(out: &mut Config, entry: &ruster_config::MapE, prefix: (Ipv6Addr, u8)) {
    let Ok((tunnel, nat, (delegated, delegated_len))) = crate::file::map_e(entry, prefix, None)
    else {
        return;
    };
    let Some((local, _)) = tunnel.tunnel else {
        return;
    };
    let on_link = out.interfaces.iter().any(|i| {
        i.tunnel.is_none()
            && i.ipv6
                .iter()
                .any(|&(a, len)| network(IpAddr::V6(a), len) == network(IpAddr::V6(local), len))
    });
    if on_link {
        return;
    }
    out.static_routes.push(StaticRoute {
        vrf: DEFAULT_VRF.to_owned(),
        prefix: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        len: 0,
        target: RouteTarget::Next {
            interface: tunnel.name.clone(),
            via: None,
        },
    });
    let discard = |r: &StaticRoute| {
        r.vrf == DEFAULT_VRF && r.prefix == IpAddr::V6(delegated) && r.len == delegated_len
    };
    if !out.static_routes.iter().any(discard) {
        out.static_routes.push(StaticRoute {
            vrf: DEFAULT_VRF.to_owned(),
            prefix: IpAddr::V6(delegated),
            len: delegated_len,
            target: RouteTarget::Discard,
        });
    }
    out.interfaces.push(tunnel);
    out.nat = Some(nat);
}
