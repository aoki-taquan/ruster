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
//! - RFC 8986 section 4 (End, End.X, End.DX6, End.DX4, End.DT6, End.DT4, End.DT46,
//!   and the flavors of section 4.16) and 5.1 and 5.2 (H.Encaps, H.Encaps.Red): the
//!   behaviours and their parameters.
//! - RFC 8986 sections 4.9 (End.DX2), 5.3 and 5.4 (H.Encaps.L2, H.Encaps.L2.Red):
//!   the SRv6 L2 interfaces, each a bridge member with its End.DX2 SID (from the
//!   locator) and the segments its frames go to; the FE's `ruster-if-srv6-l2` rows.
//!
//! Deviations: the SIDs, End.DX2's too, are in the default VRF, the locator is not
//! announced (no IS-IS or OSPF SRv6 extensions), and the source must be an address
//! given to an interface of the default VRF.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr};

use ruster_proto::table::{
    Key, RouteAction, Srv6Encap, Srv6Flavors, Srv6Local, Value, DEFAULT_VRF,
};

use crate::{InterfaceConfig, StaticRoute};

/// `[srv6]`, checked: the routes it makes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Srv6 {
    pub sids: Vec<(Ipv6Addr, Srv6Local)>,
    /// VRF, prefix, length and the policy.
    pub policies: Vec<(String, IpAddr, u8, Srv6Encap)>,
    /// The SRv6 L2 interfaces: the FE's rows for them.
    pub l2: Vec<(String, Value)>,
}

/// One SRv6 L2 interface of the lock form: its name, End.DX2 SID, segments and
/// whether reduced.
pub(crate) type L2Entry = (String, String, Vec<String>, bool);

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
    l2: Vec<L2Entry>,
    bridges: &[crate::bridge::Bridge],
) -> Result<Srv6, String> {
    if lock.len() > 1 {
        return Err("srv6: give it once".to_owned());
    }
    let Some(srv6) = lock.into_iter().next() else {
        if let Some((name, ..)) = l2.first() {
            return Err(format!(
                "interface {name:?}: an SRv6 L2 interface needs [srv6] (its locator and source)"
            ));
        }
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
    // The prefixes other routes have: a SID or a policy for one would not be offered.
    let mut taken: BTreeSet<(String, IpAddr, u8)> = static_routes
        .iter()
        .map(|r| (r.vrf.clone(), r.prefix, r.len))
        .collect();
    for interface in interfaces {
        let connected = interface
            .ipv4
            .map(|(a, len)| (IpAddr::V4(a), len))
            .into_iter()
            .chain(interface.ipv6.iter().map(|&(a, len)| (IpAddr::V6(a), len)));
        for (address, len) in connected {
            let network = ruster_proto::table::network(address, len);
            taken.insert((interface.vrf.clone(), network, len));
        }
    }
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
        let mut flavors = Srv6Flavors::default();
        for name in &entry.flavors {
            let on = match name.as_str() {
                "PSP" => &mut flavors.psp,
                "USP" => &mut flavors.usp,
                "USD" => &mut flavors.usd,
                _ => return Err(format!("{at}: flavors are PSP, USP and USD, not {name:?}")),
            };
            if std::mem::replace(on, true) {
                return Err(format!("{at}: flavor {name} given twice"));
            }
        }
        if flavors != Srv6Flavors::default() && !matches!(entry.behavior.as_str(), "End" | "End.X")
        {
            return Err(format!("{at}: only End and End.X take flavors"));
        }
        let local = match (entry.behavior.as_str(), vrf, interface, next_hop) {
            ("End", None, None, None) => Srv6Local::End { flavors },
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
                    flavors,
                }
            }
            (dx @ ("End.DX4" | "End.DX6"), None, Some(interface), Some(next_hop)) => {
                if !interfaces.iter().any(|i| i.name == interface) {
                    return Err(format!("{at}: no interface {interface:?}"));
                }
                let interface = interface.to_owned();
                let unicast =
                    |a: IpAddr| !a.is_unspecified() && !a.is_multicast() && !a.is_loopback();
                match (dx, next_hop.parse::<IpAddr>()) {
                    ("End.DX4", Ok(IpAddr::V4(next_hop))) if unicast(next_hop.into()) => {
                        Srv6Local::EndDx4 {
                            interface,
                            next_hop,
                        }
                    }
                    ("End.DX6", Ok(IpAddr::V6(next_hop))) if unicast(next_hop.into()) => {
                        Srv6Local::EndDx6 {
                            interface,
                            next_hop,
                        }
                    }
                    ("End.DX4", _) => {
                        return Err(format!("{at}: next-hop must be a unicast IPv4 address"))
                    }
                    _ => return Err(format!("{at}: next-hop must be a unicast IPv6 address")),
                }
            }
            (dt @ ("End.DT4" | "End.DT6" | "End.DT46"), Some(vrf), None, None) => {
                if !vrfs.contains(vrf) {
                    return Err(format!("{at}: no interface is in VRF {vrf:?}"));
                }
                let vrf = vrf.to_owned();
                match dt {
                    "End.DT4" => Srv6Local::EndDt4 { vrf },
                    "End.DT6" => Srv6Local::EndDt6 { vrf },
                    _ => Srv6Local::EndDt46 { vrf },
                }
            }
            _ => {
                return Err(format!(
                    "{at}: behavior is End, End.X, End.DX4 or End.DX6 (with interface and \
                     next-hop), or End.DT4, End.DT6 or End.DT46 (with vrf)"
                ))
            }
        };
        if !taken.insert((DEFAULT_VRF.to_owned(), IpAddr::V6(sid), 128)) {
            return Err(format!("{at}: the default VRF has another route for it"));
        }
        out.sids.push((sid, local));
    }
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
        if !taken.insert((entry.vrf.clone(), prefix, len)) {
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
    for (name, sid, segments, reduced) in l2 {
        let at = format!("interface {name:?}");
        let sid = unicast6(&sid)
            .ok_or_else(|| format!("{at}: srv6-l2 sid must be a unicast IPv6 address"))?;
        if ruster_proto::table::network(IpAddr::V6(sid), locator_len) != IpAddr::V6(locator) {
            return Err(format!(
                "{at}: srv6-l2 sid is not in the locator {:?}",
                srv6.locator
            ));
        }
        let used = out.sids.iter().any(|(other, _)| *other == sid)
            || out
                .l2
                .iter()
                .any(|(_, v)| matches!(v, Value::Srv6L2 { sid: other, .. } if *other == sid));
        if own.contains(&sid) || used {
            return Err(format!(
                "{at}: srv6-l2 sid is an address of an interface or another SID"
            ));
        }
        if taken.contains(&(DEFAULT_VRF.to_owned(), IpAddr::V6(sid), 128)) {
            return Err(format!("{at}: the default VRF has a route for its sid"));
        }
        if segments.is_empty() || segments.len() > ruster_proto::table::SRV6_SEGMENTS_MAX {
            return Err(format!(
                "{at}: srv6-l2 takes 1 to {} segments",
                ruster_proto::table::SRV6_SEGMENTS_MAX
            ));
        }
        let segments = segments
            .iter()
            .map(|s| {
                unicast6(s).ok_or_else(|| {
                    format!("{at}: srv6-l2 segment {s:?} is not a unicast IPv6 address")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !crate::bridge::is_member(bridges, &name) {
            return Err(format!(
                "{at}: an SRv6 L2 interface must be a member of a bridge"
            ));
        }
        let most = crate::etherip::LINK_MTU
            .saturating_sub(ruster_config::srv6_l2_overhead(segments.len(), reduced));
        let mtu = interfaces
            .iter()
            .find(|i| i.name == name)
            .map_or(0, |i| i.mtu);
        if mtu > most {
            return Err(format!(
                "{at}: mtu must be at most {most} (1500 less the outer headers)"
            ));
        }
        out.l2.push((
            name,
            Value::Srv6L2 {
                source,
                sid,
                segments,
                reduced,
            },
        ));
    }
    Ok(out)
}

/// The FE's table rows of the SRv6 L2 interfaces.
pub(crate) fn tables(srv6: &Srv6, out: &mut BTreeMap<Key, Value>) {
    for (name, value) in &srv6.l2 {
        out.insert(
            Key::Srv6L2 {
                interface: name.clone(),
            },
            value.clone(),
        );
    }
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
