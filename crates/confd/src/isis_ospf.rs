//! Checks `[[isis]]`, `[[ospf]]` and `[[ospf6]]` of the lock form: IS-IS, OSPFv2 and
//! OSPFv3 in the default VRF, which FRR speaks on the TAP device of each of their
//! interfaces (`docs/design/overlay.md` section 6). confd hands them to `ruster-frr`
//! in the `frr` part ([`crate::part`]).
//!
//! # Standards
//!
//! - ISO 10589 section 7.1.1 and RFC 1195: a Network Entity Title is an area address
//!   of 1 to 13 octets, a 6-octet system ID and the NSEL 00, written in hex as FRR
//!   reads it (`49.0001.1921.6800.1001.00`: the system ID and NSEL in the last four
//!   groups, the area in groups of one or two octets before them).
//! - RFC 5305 section 3: a wide metric is 24 bits; 2^24 - 1 takes the link out of
//!   SPF, so it is not taken.
//! - RFC 2328 appendix C.3: an interface's cost is 1 to 65535. Section 1.2 and
//!   appendix C.3: an area ID and the router ID are 32-bit numbers written as IPv4
//!   addresses; the router ID is not 0.0.0.0. RFC 5340 section 2.9 and appendix C.3:
//!   the same for OSPFv3.
//!
//! Deviations: only the default VRF; only the network types broadcast and
//! point-to-point; at most 32 interfaces for each. An interface whose address a
//! source finds (DHCP, PPPoE), a tunnel and a bridge member are not taken: IS-IS
//! and OSPF run on ports, VLANs and bridges' own interfaces with configured
//! addresses, whose TAP stands for them and holds the same addresses. An interface
//! cost of 10 when none is given, not FRR's from the link's bandwidth.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use ruster_config::{Isis, Ospf, ISIS_LEVELS, OSPF_NETWORKS};
use ruster_proto::table::DEFAULT_VRF;

use crate::bridge::Bridge;
use crate::InterfaceConfig;

/// The longest interface name: `rp-` and the name fit Linux's 15 characters.
const NAME_MAX: usize = 15 - ruster_config::TAP_PREFIX.len();
/// The most interfaces of each protocol.
const INTERFACES_MAX: usize = 32;
/// The largest wide metric that SPF uses (RFC 5305 section 3.7).
const METRIC_MAX: u32 = (1 << 24) - 2;

/// Checks `isis` (none or one).
pub(crate) fn check_isis(
    entries: Vec<Isis>,
    interfaces: &[InterfaceConfig],
    bridges: &[Bridge],
) -> Result<Option<Isis>, String> {
    if entries.len() > 1 {
        return Err("give at most one isis".into());
    }
    let Some(isis) = entries.into_iter().next() else {
        return Ok(None);
    };
    if !is_net(&isis.net) {
        return Err(format!(
            "isis: net {:?} must be an area of 1 to 13 octets, a 6-octet system ID and \
             00, as 49.0001.1921.6800.1001.00",
            isis.net
        ));
    }
    if !ISIS_LEVELS.contains(&isis.level.as_str()) {
        return Err(format!("isis: level must be one of {ISIS_LEVELS:?}"));
    }
    let names: Vec<&str> = isis.interface.iter().map(|i| i.name.as_str()).collect();
    check_interfaces("isis", &names, interfaces, bridges, false)?;
    for interface in &isis.interface {
        if !(1..=METRIC_MAX).contains(&interface.metric) {
            return Err(format!(
                "isis interface {:?}: metric must be 1 to {METRIC_MAX}",
                interface.name
            ));
        }
    }
    Ok(Some(isis))
}

/// Checks `ospf` or `ospf6` (`at`; none or one). OSPFv2 needs an IPv4 address on
/// each interface.
pub(crate) fn check_ospf(
    at: &str,
    entries: Vec<Ospf>,
    interfaces: &[InterfaceConfig],
    bridges: &[Bridge],
) -> Result<Option<Ospf>, String> {
    if entries.len() > 1 {
        return Err(format!("give at most one {at}"));
    }
    let Some(ospf) = entries.into_iter().next() else {
        return Ok(None);
    };
    let id: Ipv4Addr = ospf
        .router_id
        .parse()
        .map_err(|_| format!("{at}: router-id must be an IPv4 address"))?;
    if id.is_unspecified() {
        return Err(format!("{at}: router-id must not be 0.0.0.0"));
    }
    let names: Vec<&str> = ospf.interface.iter().map(|i| i.name.as_str()).collect();
    check_interfaces(at, &names, interfaces, bridges, at == "ospf")?;
    for interface in &ospf.interface {
        let at = format!("{at} interface {:?}", interface.name);
        if interface.area.parse::<Ipv4Addr>().is_err() {
            return Err(format!("{at}: area must be written as an IPv4 address"));
        }
        if !(1..=u32::from(u16::MAX)).contains(&interface.cost) {
            return Err(format!("{at}: cost must be 1 to 65535"));
        }
        if !OSPF_NETWORKS.contains(&interface.network.as_str()) {
            return Err(format!("{at}: network must be one of {OSPF_NETWORKS:?}"));
        }
    }
    Ok(Some(ospf))
}

/// Checks that each of `names` is a port, VLAN or bridge of the default VRF whose
/// TAP device's name fits, given once; with `ipv4`, that it has an IPv4 address
/// of its own.
fn check_interfaces(
    at: &str,
    names: &[&str],
    interfaces: &[InterfaceConfig],
    bridges: &[Bridge],
    ipv4: bool,
) -> Result<(), String> {
    if names.len() > INTERFACES_MAX {
        return Err(format!("{at}: give at most {INTERFACES_MAX} interfaces"));
    }
    let mut seen = BTreeSet::new();
    for &name in names {
        let at = format!("{at} interface {name:?}");
        if !seen.insert(name) {
            return Err(format!("{at}: given twice"));
        }
        let interface = interfaces
            .iter()
            .find(|i| i.name == name)
            .ok_or_else(|| format!("{at}: no such interface"))?;
        // The TAP device's name, and a word in FRR's configuration.
        if !name.bytes().all(|b| b.is_ascii_graphic() && b != b'/') {
            return Err(format!(
                "{at}: the name must be printable ASCII without spaces or /"
            ));
        }
        if name.len() > NAME_MAX {
            return Err(format!(
                "{at}: the name must be at most {NAME_MAX} characters, so that its TAP \
                 device {} fits",
                ruster_config::tap_device(name)
            ));
        }
        if interface.vrf != DEFAULT_VRF {
            return Err(format!("{at}: only interfaces of the default VRF"));
        }
        if interface.tunnel.is_some() || interface.pppoe.is_some() {
            return Err(format!("{at}: only a port, a VLAN or a bridge"));
        }
        if interface.address_from_source() {
            return Err(format!(
                "{at}: its address comes from a source; give one in the configuration"
            ));
        }
        if bridges.iter().any(|b| b.members.iter().any(|m| m == name)) {
            return Err(format!(
                "{at}: it is a bridge member; give the bridge instead"
            ));
        }
        if ipv4 && interface.ipv4.is_none() {
            return Err(format!("{at}: OSPFv2 needs an ipv4 address on it"));
        }
    }
    Ok(())
}

/// Whether `net` is a Network Entity Title in hex groups as FRR reads it: the
/// area in groups of one or two octets (1 to 13 octets), then the system ID in three
/// groups of two octets and `00`.
fn is_net(net: &str) -> bool {
    let groups: Vec<&str> = net.split('.').collect();
    let hex = |g: &str| !g.is_empty() && g.bytes().all(|b| b.is_ascii_hexdigit());
    let [area @ .., a, b, c, nsel] = groups.as_slice() else {
        return false;
    };
    let area_octets: usize = area.iter().map(|g| g.len() / 2).sum();
    *nsel == "00"
        && [a, b, c].iter().all(|g| g.len() == 4 && hex(g))
        && !area.is_empty()
        && area.iter().all(|g| matches!(g.len(), 2 | 4) && hex(g))
        && (1..=13).contains(&area_octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nets_are_read_as_frr_writes_them() {
        assert!(is_net("49.0001.1921.6800.1001.00"));
        assert!(is_net("49.1921.6800.1001.00"), "a one-octet area");
        assert!(is_net("49.01.1921.6800.1001.00"), "two octets");
        assert!(is_net("4901.1921.6800.1001.00"), "two octets in one group");
        assert!(!is_net("49.0.1921.6800.1001.00"));
        assert!(is_net("49.0001.0002.0003.0004.0005.0006.1921.6800.1001.00"));
        assert!(!is_net(
            "49.0001.0002.0003.0004.0005.0006.0007.1921.6800.1001.00"
        ));
        assert!(!is_net("49.0001.1921.6800.1001.01"), "NSEL 00 only");
        assert!(!is_net("49.0001.1921.6800.1001"));
        assert!(!is_net("4.0001.1921.6800.1001.00"));
        assert!(!is_net("49.000g.1921.6800.1001.00"));
        assert!(!is_net(""));
    }
}
