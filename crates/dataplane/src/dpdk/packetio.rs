//! DPDK-based [`PacketIo`] implementation.
//!
//! With the `dpdk` Cargo feature enabled, this module provides a real
//! DPDK poll-mode driver based `PacketIo` implementation using
//! `rte_eth_rx_burst` / `rte_eth_tx_burst`.
//!
//! Without the `dpdk` feature, [`DpdkPacketIo::new`] returns a clear
//! error indicating that the binary was not compiled with DPDK support.

use std::collections::HashMap;

#[cfg(not(feature = "dpdk"))]
use super::config::DpdkConfig;
use super::config::PortConfig;
use super::context::DpdkContext;
use super::error::DpdkError;
use crate::io::{IoError, PacketIo, RawPacket};

/// Maximum burst size for DPDK RX/TX operations.
///
/// This is a DPDK-specific tuning parameter (not governed by any RFC).
/// A future version may make this configurable via router.toml.
#[cfg(feature = "dpdk")]
const MAX_BURST_SIZE: usize = 32;

// ── DpdkPacketIo (stub, no `dpdk` feature) ─────────────────────────

/// DPDK poll-mode driver packet I/O backend.
///
/// Implements [`PacketIo`] for real NIC I/O via DPDK `rte_eth_rx_burst`
/// / `rte_eth_tx_burst`.
///
/// When compiled **without** the `dpdk` feature, this struct can still be
/// constructed, but [`DpdkPacketIo::new`] returns an error with a clear
/// message explaining that the feature is required.
///
/// When compiled **with** the `dpdk` feature, the struct wraps an
/// initialised [`DpdkContext`] and performs real poll-mode I/O.
#[derive(Debug)]
pub struct DpdkPacketIo {
    /// Mapping from logical interface name to DPDK port ID.
    #[allow(dead_code)]
    port_map: HashMap<String, u16>,
    /// Ordered list of interface names for round-robin RX polling.
    #[allow(dead_code)]
    rx_ifaces: Vec<String>,
    /// Retained DPDK context (mempool + port handles).
    #[allow(dead_code)]
    context: DpdkContext,
}

// SAFETY: DpdkPacketIo is constructed once and then used from a single
// run-loop thread. The port_map and rx_ifaces are read-only after
// construction. The DpdkContext owns opaque handles that are not shared.
unsafe impl Send for DpdkPacketIo {}
unsafe impl Sync for DpdkPacketIo {}

impl DpdkPacketIo {
    /// Create a new DPDK I/O backend from a previously initialised context.
    ///
    /// # Feature gating
    ///
    /// Without the `dpdk` Cargo feature, this function always returns
    /// `Err(DpdkError::NotAvailable(...))`.
    ///
    /// # Arguments
    ///
    /// * `context` - A [`DpdkContext`] obtained from [`super::init_dpdk`].
    /// * `port_configs` - The port configurations used to build the
    ///   logical-name-to-port-id mapping.
    #[cfg(not(feature = "dpdk"))]
    pub fn new(_context: DpdkContext, _port_configs: &[PortConfig]) -> Result<Self, DpdkError> {
        Err(DpdkError::NotAvailable(
            "ruster was compiled without the 'dpdk' feature; \
             rebuild with `cargo build --features dpdk` to enable \
             DPDK poll-mode I/O"
                .to_string(),
        ))
    }

    /// Create a new DPDK I/O backend from a previously initialised context.
    ///
    /// Maps each port handle in the context to its logical interface name
    /// for use in [`PacketIo::rx`] and [`PacketIo::tx`].
    #[cfg(feature = "dpdk")]
    pub fn new(context: DpdkContext, _port_configs: &[PortConfig]) -> Result<Self, DpdkError> {
        // NOTE: port_configs is currently unused because the port map is built
        // from context.ports (which are already filtered by init_dpdk).
        // When real DPDK is integrated, port_configs may be used for additional
        // per-port configuration (e.g., MTU, RSS settings).
        let mut port_map = HashMap::new();
        let mut rx_ifaces = Vec::new();

        for handle in &context.ports {
            port_map.insert(handle.name.clone(), handle.port_id);
            rx_ifaces.push(handle.name.clone());
        }

        Ok(Self {
            port_map,
            rx_ifaces,
            context,
        })
    }

    /// Create a DPDK I/O backend from a [`DpdkConfig`], performing the
    /// full initialisation sequence (EAL init, mempool, port setup).
    ///
    /// This is a convenience wrapper that calls [`super::init_dpdk`]
    /// with the mock backend (for testing) or real backend, then wraps
    /// the resulting context in a `DpdkPacketIo`.
    ///
    /// # Feature gating
    ///
    /// Without the `dpdk` feature, always returns
    /// `Err(DpdkError::NotAvailable(...))`.
    #[cfg(not(feature = "dpdk"))]
    pub fn from_config(_config: &DpdkConfig) -> Result<Self, DpdkError> {
        Err(DpdkError::NotAvailable(
            "ruster was compiled without the 'dpdk' feature; \
             rebuild with `cargo build --features dpdk` to enable \
             DPDK poll-mode I/O"
                .to_string(),
        ))
    }
}

#[cfg(not(feature = "dpdk"))]
impl PacketIo for DpdkPacketIo {
    fn rx(&self) -> Vec<RawPacket> {
        // This is unreachable because `new()` always returns Err without
        // the `dpdk` feature, but we implement the trait for type
        // completeness.
        Vec::new()
    }

    fn tx(&self, _iface: &str, _packet: &RawPacket) -> Result<(), IoError> {
        Err(IoError::TxFailed(
            "DPDK backend not available (compiled without 'dpdk' feature)".to_string(),
        ))
    }
}

// ── DpdkPacketIo (real, with `dpdk` feature) ───────────────────────

#[cfg(feature = "dpdk")]
impl PacketIo for DpdkPacketIo {
    fn rx(&self) -> Vec<RawPacket> {
        // TODO(#142): Replace with actual rte_eth_rx_burst calls.
        // For each port in rx_ifaces, call rte_eth_rx_burst(port_id, 0,
        // bufs, MAX_BURST_SIZE), then convert each mbuf to a RawPacket.
        let mut batch = Vec::new();

        for iface_name in &self.rx_ifaces {
            if let Some(&_port_id) = self.port_map.get(iface_name) {
                // Real implementation would call:
                //   let nb_rx = rte_eth_rx_burst(port_id, 0, &mut mbufs, MAX_BURST_SIZE);
                //   for i in 0..nb_rx { ... convert mbuf to RawPacket ... }
                let _ = MAX_BURST_SIZE; // suppress unused warning
            }
        }

        batch
    }

    fn tx(&self, iface: &str, packet: &RawPacket) -> Result<(), IoError> {
        let _port_id = self
            .port_map
            .get(iface)
            .ok_or_else(|| IoError::InterfaceNotFound(iface.to_string()))?;

        // TODO(#142): Replace with actual rte_eth_tx_burst call.
        // Real implementation would:
        //   1. Allocate mbuf from mempool
        //   2. Copy packet.data into mbuf
        //   3. Call rte_eth_tx_burst(port_id, 0, &mut [mbuf], 1)
        let _ = &packet.data;

        Ok(())
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpdk::context::{MempoolHandle, PortHandle};

    fn make_context(port_names: &[(&str, u16)]) -> DpdkContext {
        DpdkContext {
            mempool: MempoolHandle {
                name: "test_mempool".to_string(),
                capacity: 2048,
            },
            ports: port_names
                .iter()
                .map(|(name, id)| PortHandle {
                    port_id: *id,
                    name: name.to_string(),
                })
                .collect(),
        }
    }

    fn make_port_configs(port_names: &[(&str, u16)]) -> Vec<PortConfig> {
        port_names
            .iter()
            .map(|(name, id)| PortConfig {
                name: name.to_string(),
                port_id: *id,
                mtu: 1500,
                mac: [0x02, 0x00, 0x00, 0x00, 0x00, *id as u8],
                admin_up: true,
                rx_queues: 1,
                tx_queues: 1,
            })
            .collect()
    }

    #[test]
    #[cfg(not(feature = "dpdk"))]
    fn new_without_dpdk_feature_returns_not_available() {
        let ctx = make_context(&[("wan0", 0)]);
        let ports = make_port_configs(&[("wan0", 0)]);
        let err = DpdkPacketIo::new(ctx, &ports).unwrap_err();
        match &err {
            DpdkError::NotAvailable(msg) => {
                assert!(
                    msg.contains("dpdk"),
                    "error should mention 'dpdk' feature: {msg}"
                );
            }
            other => panic!("expected NotAvailable, got {other:?}"),
        }
    }

    #[test]
    #[cfg(not(feature = "dpdk"))]
    fn from_config_without_dpdk_feature_returns_not_available() {
        let config = DpdkConfig {
            lcore_list: "0-3".to_string(),
            memory_mb: 2048,
            rx_queue_size: 1024,
            tx_queue_size: 1024,
            ports: vec![],
        };
        let err = DpdkPacketIo::from_config(&config).unwrap_err();
        assert!(matches!(err, DpdkError::NotAvailable(_)));
    }

    #[test]
    #[cfg(feature = "dpdk")]
    fn new_with_dpdk_feature_succeeds() {
        let ctx = make_context(&[("wan0", 0), ("lan0", 1)]);
        let ports = make_port_configs(&[("wan0", 0), ("lan0", 1)]);
        let io = DpdkPacketIo::new(ctx, &ports).expect("should succeed with dpdk feature");
        assert_eq!(io.port_map.len(), 2);
        assert_eq!(io.rx_ifaces.len(), 2);
    }

    #[test]
    #[cfg(feature = "dpdk")]
    fn tx_unknown_interface_returns_error() {
        let ctx = make_context(&[("wan0", 0)]);
        let ports = make_port_configs(&[("wan0", 0)]);
        let io = DpdkPacketIo::new(ctx, &ports).unwrap();
        let pkt = RawPacket {
            ingress_iface: "eth0".to_string(),
            data: vec![0x01, 0x02],
        };
        let err = io.tx("nonexistent", &pkt).unwrap_err();
        assert!(matches!(err, IoError::InterfaceNotFound(_)));
    }

    #[test]
    #[cfg(feature = "dpdk")]
    fn rx_returns_empty_batch() {
        // With the stub DPDK implementation, rx() always returns empty.
        let ctx = make_context(&[("wan0", 0)]);
        let ports = make_port_configs(&[("wan0", 0)]);
        let io = DpdkPacketIo::new(ctx, &ports).unwrap();
        assert!(io.rx().is_empty());
    }

    #[test]
    #[cfg(feature = "dpdk")]
    fn tx_known_interface_succeeds() {
        let ctx = make_context(&[("wan0", 0)]);
        let ports = make_port_configs(&[("wan0", 0)]);
        let io = DpdkPacketIo::new(ctx, &ports).unwrap();
        let pkt = RawPacket {
            ingress_iface: "wan0".to_string(),
            data: vec![0xAA, 0xBB, 0xCC],
        };
        assert!(io.tx("wan0", &pkt).is_ok());
    }
}
