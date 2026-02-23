//! Bridge domain state and L2 forwarding decisions.
//!
//! A bridge domain groups a set of interfaces that share a common L2 broadcast
//! domain. Each bridge domain has its own FDB (Forwarding Database) for MAC
//! address learning and lookup.

use super::fdb::Fdb;
use crate::packet::PacketMeta;

/// The broadcast MAC address (FF:FF:FF:FF:FF:FF).
const BROADCAST_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

/// Per-bridge-domain runtime state.
#[derive(Debug)]
pub struct BridgeDomainState {
    /// Name of the bridge domain (from configuration).
    pub name: String,
    /// Member interface names that belong to this domain.
    pub members: Vec<String>,
    /// Forwarding database for this bridge domain.
    pub fdb: Fdb,
}

/// The result of L2 forwarding decision for a packet.
#[derive(Debug, Clone, PartialEq)]
pub enum L2Decision {
    /// The destination MAC is known in the FDB; send to a single interface.
    Unicast {
        /// The output interface name.
        out_ifname: String,
    },
    /// The destination MAC is unknown or is broadcast; flood to all member
    /// interfaces except the one the packet arrived on.
    Flood {
        /// The output interface names (excludes the ingress interface).
        out_ifnames: Vec<String>,
    },
    /// The ingress interface does not belong to any bridge domain.
    Drop,
}

impl BridgeDomainState {
    /// Create a new bridge domain state with the given name, members, and FDB
    /// capacity.
    pub fn new(name: String, members: Vec<String>, max_entries: usize) -> Self {
        Self {
            name,
            members,
            fdb: Fdb::new(max_entries),
        }
    }

    /// Process a packet within this bridge domain.
    ///
    /// 1. Learn the source MAC on the ingress interface.
    /// 2. Look up the destination MAC in the FDB.
    /// 3. If broadcast or unknown -> flood (excluding ingress).
    /// 4. If known -> unicast (but not back to ingress).
    pub fn process(&mut self, meta: &PacketMeta) -> L2Decision {
        // Step 1: Learn source MAC.
        self.fdb.learn(meta.l2.src_mac, &meta.in_ifname);

        // Step 2: Broadcast MAC always floods.
        if meta.l2.dst_mac == BROADCAST_MAC {
            return self.flood_decision(&meta.in_ifname);
        }

        // Step 3: Look up destination MAC.
        match self.fdb.lookup(&meta.l2.dst_mac) {
            Some(entry) => {
                // Known unicast. If the output is the same as input,
                // the packet should not be sent back — this means the
                // destination is on the same segment as the source,
                // so the switch already delivered it. We return Unicast
                // but the caller should check for this (or we could return
                // Drop). Per the spec: "do not flood" in this case.
                // The spec says "unicast output IF == input IF -> do not flood".
                // We interpret this as: suppress the forwarding entirely.
                if entry.out_ifname == meta.in_ifname {
                    // Source and destination are on the same port.
                    // No need to forward — the frame was already received
                    // on the correct segment.
                    L2Decision::Drop
                } else {
                    L2Decision::Unicast {
                        out_ifname: entry.out_ifname.clone(),
                    }
                }
            }
            None => {
                // Unknown unicast: flood to all members except ingress.
                self.flood_decision(&meta.in_ifname)
            }
        }
    }

    /// Build a Flood decision for all members except the ingress interface.
    fn flood_decision(&self, in_ifname: &str) -> L2Decision {
        let out_ifnames: Vec<String> = self
            .members
            .iter()
            .filter(|m| m.as_str() != in_ifname)
            .cloned()
            .collect();
        L2Decision::Flood { out_ifnames }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{L2Info, PacketMeta};

    /// Helper to build a minimal PacketMeta for bridge testing.
    fn make_meta(in_ifname: &str, src_mac: [u8; 6], dst_mac: [u8; 6]) -> PacketMeta {
        PacketMeta {
            in_ifname: in_ifname.to_string(),
            l2: L2Info {
                dst_mac,
                src_mac,
                ethertype: 0x0800,
            },
            l3: None,
            l4: None,
            raw_len: 64,
        }
    }

    const MAC_A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const MAC_B: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    fn make_bridge() -> BridgeDomainState {
        BridgeDomainState::new(
            "br0".to_string(),
            vec!["eth0".to_string(), "eth1".to_string(), "eth2".to_string()],
            1024,
        )
    }

    #[test]
    fn bridge_unicast_known_mac() {
        let mut bd = make_bridge();

        // First, learn MAC_B on eth1 by sending a packet from MAC_B on eth1.
        let learn_pkt = make_meta("eth1", MAC_B, MAC_A);
        let _ = bd.process(&learn_pkt);

        // Now send from MAC_A on eth0 to MAC_B -> should unicast to eth1.
        let pkt = make_meta("eth0", MAC_A, MAC_B);
        let decision = bd.process(&pkt);

        assert_eq!(
            decision,
            L2Decision::Unicast {
                out_ifname: "eth1".to_string()
            }
        );
    }

    #[test]
    fn bridge_flood_unknown_mac() {
        let mut bd = make_bridge();

        // Send to an unknown MAC -> should flood to all except ingress.
        let pkt = make_meta("eth0", MAC_A, MAC_B);
        let decision = bd.process(&pkt);

        match decision {
            L2Decision::Flood { ref out_ifnames } => {
                assert!(!out_ifnames.contains(&"eth0".to_string()));
                assert!(out_ifnames.contains(&"eth1".to_string()));
                assert!(out_ifnames.contains(&"eth2".to_string()));
                assert_eq!(out_ifnames.len(), 2);
            }
            _ => panic!("expected Flood, got {:?}", decision),
        }
    }

    #[test]
    fn bridge_flood_excludes_source() {
        let mut bd = make_bridge();

        // Flood should never include the ingress interface.
        let pkt = make_meta("eth1", MAC_A, MAC_B);
        let decision = bd.process(&pkt);

        match decision {
            L2Decision::Flood { ref out_ifnames } => {
                assert!(!out_ifnames.contains(&"eth1".to_string()));
            }
            _ => panic!("expected Flood, got {:?}", decision),
        }
    }

    #[test]
    fn bridge_broadcast_always_floods() {
        let mut bd = make_bridge();

        // Even if we've learned the broadcast MAC (which shouldn't happen
        // in practice), broadcast always floods.
        let pkt = make_meta("eth0", MAC_A, BROADCAST_MAC);
        let decision = bd.process(&pkt);

        match decision {
            L2Decision::Flood { ref out_ifnames } => {
                assert!(!out_ifnames.contains(&"eth0".to_string()));
                assert_eq!(out_ifnames.len(), 2);
            }
            _ => panic!("expected Flood for broadcast, got {:?}", decision),
        }
    }
}
