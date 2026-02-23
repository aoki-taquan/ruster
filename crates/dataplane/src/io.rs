//! Packet I/O abstraction for the ruster dataplane.
//!
//! Defines the [`PacketIo`] trait that abstracts over the packet
//! receive/transmit backend. In v0.1 the backend is mocked for testing;
//! a future DPDK backend will implement this trait for real NIC I/O.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

// ── Error ────────────────────────────────────────────────────────────

/// Error returned by [`PacketIo::tx`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoError {
    /// The specified egress interface does not exist.
    InterfaceNotFound(String),
    /// The transmit operation failed for a backend-specific reason.
    TxFailed(String),
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IoError::InterfaceNotFound(name) => {
                write!(f, "interface not found: {name}")
            }
            IoError::TxFailed(reason) => write!(f, "tx failed: {reason}"),
        }
    }
}

impl std::error::Error for IoError {}

// ── RawPacket ────────────────────────────────────────────────────────

/// A raw packet buffer with metadata about which interface it arrived on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPacket {
    /// Name of the interface this packet was received on.
    pub ingress_iface: String,
    /// Raw packet bytes (Ethernet frame).
    pub data: Vec<u8>,
}

// ── PacketIo trait ───────────────────────────────────────────────────

/// Abstraction over packet receive/transmit backends.
///
/// In v0.1 this is used for testing via [`MockPacketIo`]; a future
/// DPDK backend will implement this trait for real NIC poll-mode I/O.
pub trait PacketIo: Send + Sync {
    /// Receive a batch of packets.
    ///
    /// Returns an empty `Vec` if no packets are currently available.
    /// The implementation should not block.
    fn rx(&self) -> Vec<RawPacket>;

    /// Transmit a packet on the specified egress interface.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::InterfaceNotFound`] if the interface does not
    /// exist, or [`IoError::TxFailed`] for backend-specific failures.
    fn tx(&self, iface: &str, packet: &RawPacket) -> Result<(), IoError>;
}

// ── MockPacketIo ─────────────────────────────────────────────────────

/// A mock packet I/O backend for testing.
///
/// Allows injecting packets into the RX queue and capturing packets
/// sent via TX. Both queues are protected by mutexes so the mock can
/// be shared with the dataplane run loop.
#[derive(Debug, Clone)]
pub struct MockPacketIo {
    /// Queue of packets waiting to be received.
    rx_queue: Arc<Mutex<VecDeque<RawPacket>>>,
    /// Capture of all transmitted packets.
    tx_capture: Arc<Mutex<Vec<(String, RawPacket)>>>,
    /// When true, `tx()` returns `Err(IoError::TxFailed(...))`.
    tx_fail_mode: Arc<Mutex<bool>>,
}

impl MockPacketIo {
    /// Create a new mock I/O backend with empty queues.
    pub fn new() -> Self {
        Self {
            rx_queue: Arc::new(Mutex::new(VecDeque::new())),
            tx_capture: Arc::new(Mutex::new(Vec::new())),
            tx_fail_mode: Arc::new(Mutex::new(false)),
        }
    }

    /// Enable or disable TX failure mode.
    ///
    /// When enabled, all `tx()` calls return `Err(IoError::TxFailed(...))`.
    pub fn set_tx_fail_mode(&self, fail: bool) {
        *self.tx_fail_mode.lock().unwrap() = fail;
    }

    /// Enqueue a packet for the next `rx()` call.
    pub fn inject(&self, packet: RawPacket) {
        self.rx_queue.lock().unwrap().push_back(packet);
    }

    /// Return all captured TX packets as `(egress_iface, packet)` pairs.
    pub fn tx_captured(&self) -> Vec<(String, RawPacket)> {
        self.tx_capture.lock().unwrap().clone()
    }

    /// Return the number of captured TX packets.
    pub fn tx_count(&self) -> usize {
        self.tx_capture.lock().unwrap().len()
    }
}

impl Default for MockPacketIo {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketIo for MockPacketIo {
    fn rx(&self) -> Vec<RawPacket> {
        let mut queue = self.rx_queue.lock().unwrap();
        queue.drain(..).collect()
    }

    fn tx(&self, iface: &str, packet: &RawPacket) -> Result<(), IoError> {
        if *self.tx_fail_mode.lock().unwrap() {
            return Err(IoError::TxFailed("mock tx failure".to_string()));
        }
        self.tx_capture
            .lock()
            .unwrap()
            .push((iface.to_string(), packet.clone()));
        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_io_rx_empty() {
        let io = MockPacketIo::new();
        assert!(io.rx().is_empty());
    }

    #[test]
    fn mock_io_inject_and_rx() {
        let io = MockPacketIo::new();
        io.inject(RawPacket {
            ingress_iface: "eth0".to_string(),
            data: vec![0xAA, 0xBB],
        });
        io.inject(RawPacket {
            ingress_iface: "eth1".to_string(),
            data: vec![0xCC],
        });

        let batch = io.rx();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].ingress_iface, "eth0");
        assert_eq!(batch[1].ingress_iface, "eth1");

        // Second call returns empty (queue drained).
        assert!(io.rx().is_empty());
    }

    #[test]
    fn mock_io_tx_captures() {
        let io = MockPacketIo::new();
        let pkt = RawPacket {
            ingress_iface: "eth0".to_string(),
            data: vec![0x01, 0x02, 0x03],
        };

        io.tx("wan0", &pkt).unwrap();
        io.tx("lan0", &pkt).unwrap();

        let captured = io.tx_captured();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].0, "wan0");
        assert_eq!(captured[1].0, "lan0");
        assert_eq!(io.tx_count(), 2);
    }

    #[test]
    fn io_error_display() {
        let e1 = IoError::InterfaceNotFound("eth99".to_string());
        assert_eq!(format!("{e1}"), "interface not found: eth99");

        let e2 = IoError::TxFailed("queue full".to_string());
        assert_eq!(format!("{e2}"), "tx failed: queue full");
    }

    #[test]
    fn mock_io_default() {
        let io = MockPacketIo::default();
        assert!(io.rx().is_empty());
        assert_eq!(io.tx_count(), 0);
    }

    #[test]
    fn mock_io_tx_fail_mode() {
        let io = MockPacketIo::new();
        let pkt = RawPacket {
            ingress_iface: "eth0".to_string(),
            data: vec![0x01, 0x02],
        };

        // Default: tx succeeds.
        assert!(io.tx("wan0", &pkt).is_ok());
        assert_eq!(io.tx_count(), 1);

        // Enable fail mode: tx returns error.
        io.set_tx_fail_mode(true);
        let err = io.tx("wan0", &pkt).unwrap_err();
        assert_eq!(err, IoError::TxFailed("mock tx failure".to_string()));
        // Tx count unchanged (packet not captured on failure).
        assert_eq!(io.tx_count(), 1);

        // Disable fail mode: tx succeeds again.
        io.set_tx_fail_mode(false);
        assert!(io.tx("wan0", &pkt).is_ok());
        assert_eq!(io.tx_count(), 2);
    }
}
