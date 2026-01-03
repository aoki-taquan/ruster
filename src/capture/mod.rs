//! Packet capture backends
//!
//! Provides abstraction over different I/O backends:
//! - AF_PACKET: Portable, no special setup required
//! - AF_XDP: High performance, requires kernel 4.18+
//! - DPDK: Maximum performance, requires driver setup

mod af_packet;

pub use af_packet::AfPacketSocket;

use crate::Result;
use std::future::Future;

/// Information about a received packet
#[derive(Debug, Clone)]
pub struct RxInfo {
    /// Number of bytes received
    pub len: usize,
    /// VLAN ID if the kernel stripped it
    pub vlan_id: Option<u16>,
}

/// Packet capture backend trait
///
/// All backends must implement this trait to be used with the data plane.
pub trait Capture: Send + Sync {
    /// Receive a packet into the provided buffer
    fn recv(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<RxInfo>> + Send;

    /// Send a packet
    fn send(&mut self, buf: &[u8]) -> impl Future<Output = Result<usize>> + Send;
}

/// Backend type selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    #[default]
    AfPacket,
    AfXdp,
    Dpdk,
}
