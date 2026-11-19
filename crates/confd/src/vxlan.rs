//! VXLAN interfaces (`docs/design/overlay.md`, section 3): the `vxlan` interfaces of
//! the lock form, checked, and the FE's `ruster-if-vxlan` rows confd writes for them.
//!
//! A VXLAN interface carries a bridge's frames in UDP from one of the router's
//! addresses to a list of remote VTEPs, which get every broadcast (head-end
//! replication). It is only a bridge member, so it has no address of its own; its
//! MTU leaves room for the outer headers on the largest link the outer packets can
//! leave through.
//!
//! # Standards
//!
//! - RFC 7348 section 5: a 24-bit VNI; the outer header IPv4 or IPv6.
//!
//! Deviations: the remote VTEPs are a list (no multicast underlay, RFC 7348 section
//! 4.2); the local address must be an address given to an interface of the default
//! VRF. A static MAC address on it is behind one of its VTEPs.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ruster_proto::table::{Key, Value, VXLAN_VNI_MAX};

use crate::etherip::{given, unicast};
use crate::InterfaceConfig;

/// One VXLAN interface, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vxlan {
    /// Its interface's name.
    pub name: String,
    pub vni: u32,
    pub local: IpAddr,
    pub remotes: Vec<IpAddr>,
    pub port: u16,
}

/// The most remote VTEPs of one interface.
const REMOTES_MAX: usize = 64;

/// Checks the VXLAN interfaces (name, VNI, local, remotes) against the interfaces
/// and the bridges.
pub(crate) fn check(
    entries: Vec<(String, u32, String, Vec<String>, u16)>,
    interfaces: &[InterfaceConfig],
    bridges: &[crate::bridge::Bridge],
    link_mtu: u16,
) -> Result<Vec<Vxlan>, String> {
    let mut out: Vec<Vxlan> = Vec::with_capacity(entries.len());
    for (name, vni, local, remote, port) in entries {
        let at = format!("interface {name:?}");
        if port == 0 {
            return Err(format!("{at}: vxlan port must be 1 to 65535"));
        }
        if !(1..=VXLAN_VNI_MAX).contains(&vni) {
            return Err(format!("{at}: vni must be 1 to {VXLAN_VNI_MAX}"));
        }
        let address = |text: &str, what: &str| -> Result<IpAddr, String> {
            text.parse()
                .ok()
                .filter(|a| unicast(*a))
                .ok_or_else(|| format!("{at}: vxlan {what} must be a unicast IP address"))
        };
        let local = address(&local, "local")?;
        if remote.is_empty() || remote.len() > REMOTES_MAX {
            return Err(format!(
                "{at}: vxlan remote must list 1 to {REMOTES_MAX} VTEPs"
            ));
        }
        let mut remotes: Vec<IpAddr> = Vec::with_capacity(remote.len());
        for text in &remote {
            let vtep = address(text, "remote")?;
            if vtep.is_ipv4() != local.is_ipv4() {
                return Err(format!(
                    "{at}: vxlan local and remote must all be IPv4 or all IPv6"
                ));
            }
            if vtep == local || remotes.contains(&vtep) {
                return Err(format!("{at}: vxlan remote {vtep} is local or given twice"));
            }
            remotes.push(vtep);
        }
        if !given(interfaces, local) {
            return Err(format!(
                "{at}: vxlan local {local} must be an address given to an interface in the default VRF"
            ));
        }
        let Some(bridge) = bridges.iter().find(|b| b.members.contains(&name)) else {
            return Err(format!(
                "{at}: a VXLAN interface must be a member of a bridge"
            ));
        };
        // Frames flooded from one VXLAN member go to the bridge's others: a VTEP
        // behind two would get them back, and two routers joined so would loop.
        if let Some(other) = out.iter().find(|v| {
            bridge.members.contains(&v.name) && v.remotes.iter().any(|r| remotes.contains(r))
        }) {
            return Err(format!(
                "{at}: a remote VTEP of it is also one of {:?}, in the same bridge {:?}",
                other.name, bridge.name
            ));
        }
        // A static address on it is behind one of its VTEPs.
        for (mac, _, vtep) in bridge
            .statics
            .iter()
            .filter(|(_, member, _)| *member == name)
        {
            if !vtep.is_some_and(|v| remotes.contains(&v)) {
                return Err(format!(
                    "{at}: static-mac {} must give a vtep of its remotes",
                    ruster_proto::table::format_mac(mac)
                ));
            }
        }
        let overhead = if local.is_ipv4() {
            ruster_config::VXLAN_OVERHEAD_IPV4
        } else {
            ruster_config::VXLAN_OVERHEAD_IPV6
        };
        let mtu = interfaces
            .iter()
            .find(|i| i.name == name)
            .map_or(0, |i| i.mtu);
        if mtu > link_mtu.saturating_sub(overhead) {
            return Err(format!(
                "{at}: mtu must be at most {} ({link_mtu}, the largest MTU of the links, less the outer headers)",
                link_mtu.saturating_sub(overhead)
            ));
        }
        // A received packet finds its interface by the local address and the VNI
        // (on any port: one VNI is one network).
        if out.iter().any(|v| v.local == local && v.vni == vni) {
            return Err(format!(
                "{at}: another VXLAN interface has the same local and vni"
            ));
        }
        out.push(Vxlan {
            name,
            vni,
            local,
            remotes,
            port,
        });
    }
    // A VTEP only on a VXLAN member's static address.
    for bridge in bridges {
        for (mac, member, vtep) in &bridge.statics {
            if vtep.is_some() && !out.iter().any(|v| v.name == *member) {
                return Err(format!(
                    "bridge {:?}: static-mac {} gives a vtep, but {member:?} is no VXLAN interface",
                    bridge.name,
                    ruster_proto::table::format_mac(mac)
                ));
            }
        }
    }
    Ok(out)
}

/// The FE's table rows of the VXLAN interfaces.
pub(crate) fn tables(vxlan: &[Vxlan], out: &mut BTreeMap<Key, Value>) {
    for interface in vxlan {
        out.insert(
            Key::Vxlan {
                interface: interface.name.clone(),
            },
            Value::Vxlan {
                vni: interface.vni,
                local: interface.local,
                remotes: interface.remotes.clone(),
                port: interface.port,
            },
        );
    }
}
