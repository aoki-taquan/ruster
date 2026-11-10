//! SRv6 (`docs/design/overlay.md` section 5): the `[srv6]` of the lock form,
//! checked, and the routes confd hands to ribd for it.
//!
//! The local SIDs and the SR policies are routes of `ruster-fib` (RFC 8986 treats
//! a SID as a FIB entry), so confd hands them to ribd as it does its static routes,
//! and ribd writes them to the FE. Each SID is a /128 route of the default VRF; each
//! policy a route of its VRF whose packets the FE wraps.
//!
//! # Standards
//!
//! - RFC 8986 section 3.1: the SIDs are taken from the router's locator.
//! - RFC 8986 section 4 (End, End.X, End.DT6, End.DT4) and 5.1 and 5.2 (H.Encaps,
//!   H.Encaps.Red): the behaviours and their parameters.
//!
//! Deviations: the SIDs are in the default VRF, the locator is not announced (no
//! IS-IS or OSPF SRv6 extensions), and the source must be an address given to an
//! interface of the default VRF.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr};

use ruster_proto::table::{Key, RouteAction, Srv6Encap, Srv6Local, Value, DEFAULT_VRF};

use crate::{InterfaceConfig, StaticRoute};

/// `[srv6]`, checked: the routes it makes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Srv6 {
    pub sids: Vec<(Ipv6Addr, Srv6Local)>,
    /// VRF, prefix, length and the policy.
    pub policies: Vec<(String, IpAddr, u8, Srv6Encap)>,
}

fn unicast6(text: &str) -> Option<Ipv6Addr> {
    text.parse::<Ipv6Addr>()
        .ok()
        .filter(|a| crate::etherip::unicast(IpAddr::V6(*a)))
}

fn at_most_one<'a>(at: &str, what: &str, list: &'a [String]) -> Result<Option<&'a str>, String> {
    match list {
        [] => Ok(None),
        [one] => Ok(Some(one)),
        _ => Err(format!("{at}: give at most one {what}")),
    }
}

/// Checks `[srv6]` against the interfaces and the static routes.
pub(crate) fn check(
    lock: Vec<ruster_config::Srv6>,
    interfaces: &[InterfaceConfig],
    static_routes: &[StaticRoute],
) -> Result<Srv6, String> {
    let Some(srv6) = lock.into_iter().next() else {
        return Ok(Srv6::default());
    };
    let (locator, locator_len) = match crate::file::prefix(&srv6.locator) {
        Some((IpAddr::V6(a), len)) if ruster_proto::table::network(IpAddr::V6(a), len) == a => {
            (a, len)
        }
        _ => {
            return Err(format!(
                "srv6: locator {:?} must be an IPv6 prefix like fc00:1::/48",
                srv6.locator
            ))
        }
    };
    let source = unicast6(&srv6.source)
        .filter(|a| crate::etherip::given(interfaces, IpAddr::V6(*a)))
        .ok_or_else(|| {
            format!(
                "srv6: source {:?} must be an IPv6 address given to an interface of the default VRF",
                srv6.source
            )
        })?;
    let vrfs: BTreeSet<&str> = interfaces.iter().map(|i| i.vrf.as_str()).collect();
    let own: BTreeSet<Ipv6Addr> = interfaces
        .iter()
        .flat_map(|i| i.ipv6.iter().map(|&(a, _)| a))
        .collect();
    let mut out = Srv6::default();
    for entry in srv6.sid {
        let at = format!("srv6 sid {:?}", entry.sid);
        let sid =
            unicast6(&entry.sid).ok_or_else(|| format!("{at}: must be a unicast IPv6 address"))?;
        if ruster_proto::table::network(IpAddr::V6(sid), locator_len) != IpAddr::V6(locator) {
            return Err(format!("{at}: not in the locator {:?}", srv6.locator));
        }
        if own.contains(&sid) {
            return Err(format!("{at}: is an address of an interface"));
        }
        if out.sids.iter().any(|(other, _)| *other == sid) {
            return Err(format!("{at}: given twice"));
        }
        let vrf = at_most_one(&at, "vrf", &entry.vrf)?;
        let interface = at_most_one(&at, "interface", &entry.interface)?;
        let next_hop = at_most_one(&at, "next-hop", &entry.next_hop)?;
        let local = match (entry.behavior.as_str(), vrf, interface, next_hop) {
            ("End", None, None, None) => Srv6Local::End,
            ("End.X", None, Some(interface), Some(next_hop)) => {
                if !interfaces
                    .iter()
                    .any(|i| i.name == interface && i.vrf == DEFAULT_VRF)
                {
                    return Err(format!(
                        "{at}: interface {interface:?} is not an interface of the default VRF"
                    ));
                }
                let next_hop = next_hop
                    .parse::<Ipv6Addr>()
                    .ok()
                    .filter(|a| !a.is_unspecified() && !a.is_multicast() && !a.is_loopback())
                    .ok_or_else(|| format!("{at}: next-hop must be a unicast IPv6 address"))?;
                Srv6Local::EndX {
                    interface: interface.to_owned(),
                    next_hop,
                }
            }
            (dt @ ("End.DT4" | "End.DT6"), Some(vrf), None, None) => {
                if !vrfs.contains(vrf) {
                    return Err(format!("{at}: no interface is in VRF {vrf:?}"));
                }
                let vrf = vrf.to_owned();
                if dt == "End.DT4" {
                    Srv6Local::EndDt4 { vrf }
                } else {
                    Srv6Local::EndDt6 { vrf }
                }
            }
            _ => {
                return Err(format!(
                    "{at}: behavior is End, End.X (with interface and next-hop), or End.DT4 or \
                     End.DT6 (with vrf)"
                ))
            }
        };
        out.sids.push((sid, local));
    }
    let mut taken: BTreeSet<(&str, IpAddr, u8)> = static_routes
        .iter()
        .map(|r| (r.vrf.as_str(), r.prefix, r.len))
        .collect();
    for entry in &srv6.policy {
        let at = format!("srv6 policy {:?}", entry.prefix);
        let (prefix, len) = crate::file::prefix(&entry.prefix)
            .ok_or_else(|| format!("{at}: prefix is not like 10.0.0.0/8 or 2001:db8::/32"))?;
        if ruster_proto::table::network(prefix, len) != prefix {
            return Err(format!("{at}: bits are set after the prefix length"));
        }
        if !vrfs.contains(entry.vrf.as_str()) {
            return Err(format!("{at}: no interface is in VRF {:?}", entry.vrf));
        }
        if !taken.insert((entry.vrf.as_str(), prefix, len)) {
            return Err(format!(
                "{at}: VRF {:?} has another route or policy for it",
                entry.vrf
            ));
        }
        if entry.segments.is_empty()
            || entry.segments.len() > ruster_proto::table::SRV6_SEGMENTS_MAX
        {
            return Err(format!(
                "{at}: give 1 to {} segments",
                ruster_proto::table::SRV6_SEGMENTS_MAX
            ));
        }
        let segments = entry
            .segments
            .iter()
            .map(|s| {
                unicast6(s)
                    .ok_or_else(|| format!("{at}: segment {s:?} is not a unicast IPv6 address"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        out.policies.push((
            entry.vrf.clone(),
            prefix,
            len,
            Srv6Encap {
                source,
                segments,
                reduced: entry.reduced,
            },
        ));
    }
    Ok(out)
}

/// Adds the routes of `srv6` to `out` (ribd's routes from confd), after the
/// connected and static ones, which win.
pub(crate) fn routes(srv6: &Srv6, out: &mut BTreeMap<Key, Value>) {
    for (sid, local) in &srv6.sids {
        out.entry(Key::Route {
            vrf: DEFAULT_VRF.to_owned(),
            prefix: IpAddr::V6(*sid),
            len: 128,
        })
        .or_insert_with(|| Value::Route(RouteAction::Srv6Local(local.clone())));
    }
    for (vrf, prefix, len, encap) in &srv6.policies {
        out.entry(Key::Route {
            vrf: vrf.clone(),
            prefix: *prefix,
            len: *len,
        })
        .or_insert_with(|| Value::Route(RouteAction::Srv6Encap(encap.clone())));
    }
}
