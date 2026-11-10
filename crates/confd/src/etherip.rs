//! EtherIP interfaces (`docs/design/overlay.md`, section 4): the `etherip`
//! interfaces of the lock form, checked, and the FE's `ruster-if-tunnel` rows confd
//! writes for them.
//!
//! An EtherIP interface carries a bridge's frames inside IP from one of the
//! router's addresses to one remote end. It is only a bridge member, so it has no
//! address of its own; its MTU leaves room for the outer headers on a 1500-byte
//! link.
//!
//! # Standards
//!
//! - RFC 3378 section 3: one remote end, an outer IPv4 or IPv6 header.
//!
//! Deviations: the local address must be an address given to an interface of the
//! default VRF (not one a DHCP client or PPPoE session finds), and the outer
//! packets are never fragmented, so the MTU is at most 1500 less the outer headers.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ruster_proto::table::{Key, Value, DEFAULT_VRF};

use crate::InterfaceConfig;

/// One EtherIP interface, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtherIp {
    /// Its interface's name.
    pub name: String,
    pub local: IpAddr,
    pub remote: IpAddr,
}

/// The most the FE takes on a link (frames of up to 1514 bytes).
pub(crate) const LINK_MTU: u16 = 1_500;

pub(crate) fn unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(a) => {
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_link_local())
        }
        IpAddr::V6(a) => {
            !(a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || a.is_unicast_link_local())
        }
    }
}

/// Whether `local` is an address given to an interface of the default VRF.
pub(crate) fn given(interfaces: &[InterfaceConfig], local: IpAddr) -> bool {
    interfaces.iter().any(|i| {
        i.vrf == DEFAULT_VRF
            && match local {
                IpAddr::V4(a) => i.ipv4.is_some_and(|(own, _)| own == a),
                IpAddr::V6(a) => i.ipv6.iter().any(|&(own, _)| own == a),
            }
    })
}

/// Checks the EtherIP interfaces (name, local, remote) against the interfaces and
/// the bridges.
pub(crate) fn check(
    entries: Vec<(String, String, String)>,
    interfaces: &[InterfaceConfig],
    bridges: &[crate::bridge::Bridge],
) -> Result<Vec<EtherIp>, String> {
    let mut out: Vec<EtherIp> = Vec::with_capacity(entries.len());
    for (name, local, remote) in entries {
        let at = format!("interface {name:?}");
        let address = |text: &str, what: &str| -> Result<IpAddr, String> {
            text.parse()
                .ok()
                .filter(|a| unicast(*a))
                .ok_or_else(|| format!("{at}: etherip {what} must be a unicast IP address"))
        };
        let (local, remote) = (address(&local, "local")?, address(&remote, "remote")?);
        if local.is_ipv4() != remote.is_ipv4() {
            return Err(format!(
                "{at}: etherip local and remote must both be IPv4 or both IPv6"
            ));
        }
        if local == remote {
            return Err(format!("{at}: etherip local and remote must differ"));
        }
        if !given(interfaces, local) {
            return Err(format!(
                "{at}: etherip local {local} must be an address given to an interface in the default VRF"
            ));
        }
        if !crate::bridge::is_member(bridges, &name) {
            return Err(format!(
                "{at}: an EtherIP tunnel must be a member of a bridge"
            ));
        }
        let overhead = if local.is_ipv4() {
            ruster_config::ETHERIP_OVERHEAD_IPV4
        } else {
            ruster_config::ETHERIP_OVERHEAD_IPV6
        };
        let mtu = interfaces
            .iter()
            .find(|i| i.name == name)
            .map_or(0, |i| i.mtu);
        if mtu > LINK_MTU - overhead {
            return Err(format!(
                "{at}: mtu must be at most {} (1500 less the outer headers)",
                LINK_MTU - overhead
            ));
        }
        if out.iter().any(|e| e.local == local && e.remote == remote) {
            return Err(format!(
                "{at}: another EtherIP tunnel has the same local and remote"
            ));
        }
        out.push(EtherIp {
            name,
            local,
            remote,
        });
    }
    Ok(out)
}

/// The FE's table rows of the EtherIP interfaces.
pub(crate) fn tables(etherip: &[EtherIp], out: &mut BTreeMap<Key, Value>) {
    for tunnel in etherip {
        out.insert(
            Key::EtherIp {
                interface: tunnel.name.clone(),
            },
            Value::EtherIp {
                local: tunnel.local,
                remote: tunnel.remote,
            },
        );
    }
}
