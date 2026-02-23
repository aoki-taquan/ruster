//! L2 bridging engine: MAC learning, FDB management, and bridge domain
//! forwarding.
//!
//! This module provides the [`L2Engine`] which manages multiple bridge domains,
//! each with its own forwarding database (FDB). The engine processes incoming
//! packets by learning source MACs and making unicast/flood/drop decisions.

pub mod bridge;
pub mod fdb;

use crate::packet::PacketMeta;
use bridge::{BridgeDomainState, L2Decision};
use ruster_config::model::L2Config;

/// The L2 bridging engine.
///
/// Manages a collection of bridge domains and provides packet processing
/// (MAC learning + forwarding decision) and FDB aging.
#[derive(Debug)]
pub struct L2Engine {
    /// Bridge domain states, one per configured bridge domain.
    domains: Vec<BridgeDomainState>,
    /// Aging timeout in seconds (entries older than this are purged).
    aging_sec: u64,
}

impl L2Engine {
    /// Build an L2 engine from the configuration.
    ///
    /// Each configured bridge domain is initialised with its member list
    /// and an FDB whose capacity comes from `l2_config.mac_table_max_entries`.
    pub fn from_config(l2_config: &L2Config) -> Self {
        let max_entries = l2_config.mac_table_max_entries as usize;
        let domains = l2_config
            .bridge_domains
            .iter()
            .map(|bd| BridgeDomainState::new(bd.name.clone(), bd.members.clone(), max_entries))
            .collect();

        Self {
            domains,
            aging_sec: u64::from(l2_config.mac_aging_sec),
        }
    }

    /// Process a packet through the L2 engine.
    ///
    /// The flow is:
    /// 1. Find the bridge domain that contains `meta.in_ifname`.
    /// 2. If no bridge domain matches, return [`L2Decision::Drop`].
    /// 3. Delegate to the bridge domain's `process()` method which handles
    ///    MAC learning and forwarding lookup.
    pub fn process(&mut self, meta: &PacketMeta) -> L2Decision {
        // Find the bridge domain whose members include the ingress interface.
        for domain in &mut self.domains {
            if domain.members.contains(&meta.in_ifname) {
                return domain.process(meta);
            }
        }

        // No bridge domain owns this interface.
        L2Decision::Drop
    }

    /// Run aging on all bridge domains' FDBs.
    ///
    /// Returns the total number of entries removed across all domains.
    pub fn age_all(&mut self) -> usize {
        let aging = self.aging_sec;
        self.domains.iter_mut().map(|d| d.fdb.age(aging)).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{L2Info, PacketMeta};
    use ruster_config::model::{BridgeDomain, L2Config};

    const MAC_A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const MAC_B: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    fn make_l2_config() -> L2Config {
        L2Config {
            mac_table_max_entries: 1024,
            mac_aging_sec: 300,
            arp_table_max_entries: 256,
            arp_timeout_sec: 120,
            bridge_domains: vec![BridgeDomain {
                name: "br0".to_string(),
                members: vec!["eth0".to_string(), "eth1".to_string(), "eth2".to_string()],
            }],
        }
    }

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

    #[test]
    fn l2engine_from_config() {
        let cfg = make_l2_config();
        let engine = L2Engine::from_config(&cfg);

        assert_eq!(engine.domains.len(), 1);
        assert_eq!(engine.domains[0].name, "br0");
        assert_eq!(engine.domains[0].members.len(), 3);
        assert_eq!(engine.aging_sec, 300);
    }

    #[test]
    fn l2engine_process_full_flow() {
        let cfg = make_l2_config();
        let mut engine = L2Engine::from_config(&cfg);

        // Step 1: MAC_B arrives on eth1 (destination doesn't matter here).
        let learn_pkt = make_meta("eth1", MAC_B, MAC_A);
        let _ = engine.process(&learn_pkt);

        // Step 2: MAC_A sends to MAC_B on eth0 -> should unicast to eth1.
        let pkt = make_meta("eth0", MAC_A, MAC_B);
        let decision = engine.process(&pkt);

        assert_eq!(
            decision,
            L2Decision::Unicast {
                out_ifname: "eth1".to_string()
            }
        );
    }

    #[test]
    fn l2engine_age_all() {
        let mut cfg = make_l2_config();
        cfg.mac_aging_sec = 0; // Age out everything immediately.
        let mut engine = L2Engine::from_config(&cfg);

        // Learn a MAC.
        let pkt = make_meta("eth0", MAC_A, MAC_B);
        let _ = engine.process(&pkt);

        // Age should remove the learned entry.
        let removed = engine.age_all();
        assert_eq!(removed, 1);
    }

    #[test]
    fn bridge_drop_unknown_domain() {
        let cfg = make_l2_config();
        let mut engine = L2Engine::from_config(&cfg);

        // "wan0" is not a member of any bridge domain.
        let pkt = make_meta("wan0", MAC_A, MAC_B);
        let decision = engine.process(&pkt);

        assert_eq!(decision, L2Decision::Drop);
    }
}
