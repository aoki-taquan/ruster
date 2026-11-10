//! Bridges (`docs/design/overlay.md`): the `bridge` interfaces of the lock form,
//! checked, and the FE's `ruster-bridge` table rows confd writes for them.
//!
//! A bridge interface is the bridge's own interface (IRB): it routes like a port.
//! Its members are ports and VLAN sub-interfaces with no address of their own, each
//! in one bridge; its MTU is at most each member's.
//!
//! # Standards
//!
//! - IEEE 802.1Q 8.8.3: the ageing time is 10 to 1000000 seconds.
//! - IEEE 802.1Q 8.8.1: a static entry names a unicast address and one member.

use std::collections::BTreeMap;

use ruster_proto::table::{Key, Value, BRIDGE_AGING_RANGE};

use crate::InterfaceConfig;

/// One bridge, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bridge {
    /// Its name, which is its own interface's.
    pub name: String,
    pub members: Vec<String>,
    pub aging_s: u32,
    pub max_learned: u32,
    /// Addresses fixed to a member.
    pub statics: Vec<([u8; 6], String)>,
}

/// Checks the bridges (the interface's name and its `bridge`) against the
/// interfaces.
pub(crate) fn check(
    entries: Vec<(String, ruster_config::Bridge)>,
    interfaces: &[InterfaceConfig],
) -> Result<Vec<Bridge>, String> {
    let mut bridges = Vec::with_capacity(entries.len());
    let mut taken: BTreeMap<String, String> = BTreeMap::new();
    for (name, entry) in entries {
        let at = format!("interface {name:?}");
        if !BRIDGE_AGING_RANGE.contains(&entry.aging_time) {
            return Err(format!("{at}: aging-time must be 10 to 1000000 seconds"));
        }
        if entry.max_learned == 0 {
            return Err(format!("{at}: max-learned must be at least 1"));
        }
        if entry.members.is_empty() {
            return Err(format!("{at}: a bridge needs a member"));
        }
        let own = interfaces.iter().find(|i| i.name == name);
        for member in &entry.members {
            let Some(interface) = interfaces.iter().find(|i| i.name == *member) else {
                return Err(format!("{at}: member {member:?} is no interface"));
            };
            if *member == name
                || interface.tunnel.is_some()
                || interface.pppoe.is_some()
                || bridges.iter().any(|b: &Bridge| b.name == *member)
            {
                return Err(format!("{at}: member {member:?} must be a port or VLAN"));
            }
            if interface.ipv4.is_some()
                || !interface.ipv6.is_empty()
                || interface.ipv4_from.is_some()
                || interface.ipv6_from.is_some()
            {
                return Err(format!(
                    "{at}: member {member:?} must have no address (the bridge's own interface has them)"
                ));
            }
            if let Some(other) = taken.insert(member.clone(), name.clone()) {
                return Err(format!(
                    "{at}: member {member:?} is already in bridge {other:?}"
                ));
            }
            if own.is_some_and(|own| own.mtu > interface.mtu) {
                return Err(format!(
                    "{at}: mtu must be at most member {member:?}'s ({})",
                    interface.mtu
                ));
            }
        }
        let mut statics = Vec::with_capacity(entry.static_mac.len());
        for fixed in entry.static_mac {
            let mac = crate::file::mac(&fixed.mac)
                .filter(|mac| mac[0] & 1 == 0 && *mac != [0; 6])
                .ok_or_else(|| format!("{at}: static-mac {:?} must be a unicast address", fixed.mac))?;
            if !entry.members.contains(&fixed.interface) {
                return Err(format!(
                    "{at}: static-mac {:?} names {:?}, which is no member",
                    fixed.mac, fixed.interface
                ));
            }
            if statics.iter().any(|(m, _)| *m == mac) {
                return Err(format!("{at}: static-mac {:?} is given twice", fixed.mac));
            }
            statics.push((mac, fixed.interface));
        }
        bridges.push(Bridge {
            name,
            members: entry.members,
            aging_s: entry.aging_time,
            max_learned: entry.max_learned,
            statics,
        });
    }
    // A bridge's own interface is no member of another.
    if let Some(bridge) = bridges.iter().find(|b| taken.contains_key(&b.name)) {
        return Err(format!(
            "interface {:?}: a bridge is not a member of a bridge",
            bridge.name
        ));
    }
    Ok(bridges)
}

/// Whether `name` is a member of a bridge.
pub(crate) fn is_member(bridges: &[Bridge], name: &str) -> bool {
    bridges.iter().any(|b| b.members.iter().any(|m| m == name))
}

/// The FE's table rows of the bridges.
pub(crate) fn tables(bridges: &[Bridge], out: &mut BTreeMap<Key, Value>) {
    for bridge in bridges {
        out.insert(
            Key::Bridge {
                name: bridge.name.clone(),
            },
            Value::Bridge {
                aging_s: bridge.aging_s,
                max_learned: bridge.max_learned,
            },
        );
        for member in &bridge.members {
            out.insert(
                Key::BridgePort {
                    interface: member.clone(),
                },
                Value::BridgePort {
                    bridge: bridge.name.clone(),
                },
            );
        }
        for (mac, interface) in &bridge.statics {
            out.insert(
                Key::BridgeMac {
                    bridge: bridge.name.clone(),
                    mac: *mac,
                },
                Value::BridgeMac {
                    interface: interface.clone(),
                },
            );
        }
    }
}
