#![deny(unsafe_code)]
#![doc = "Linux AF_PACKET/TPACKET_V3 configuration and ownership primitives."]
//!
//! This crate currently provides checked configuration, fixed interface
//! lookup, ring geometry, descriptor bounds, ownership state, and the Linux
//! syscall/mmap boundary needed by the future AF_PACKET backend. It does not
//! yet implement [`ruster_core::PacketIo`] or perform RX/TX.
//!
//! The safe model is available on every target. Raw Linux UAPI access is
//! confined to `sys`; [`AfPacketPlatform::ensure_supported`] returns
//! [`PlatformError::UnsupportedPlatform`] elsewhere.

mod config;
mod error;
mod model;
mod platform;
mod stats;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod sys;

pub use config::{
    PortConfig, PortIndex, PortTable, RingGeometry, RingKind, RingLayout, ValidatedConfig,
    ValidatedPort, DEFAULT_MAX_FRAME_LEN, TPACKET_ALIGNMENT, TPACKET_BLOCK_HEADER_LEN,
    TPACKET_V3_ETHERNET_MAC_OFFSET, TPACKET_V3_HDRLEN, TPACKET_V3_HEADER_LEN,
};
pub use error::{
    ConfigError, Errno, GeometryError, OwnershipError, PlatformError, SyscallStage, TxOperation,
};
pub use model::{
    BlockDescriptor, PacketDescriptor, RxBlockModel, RxOwnership, TxFrameModel, TxOwnership,
    ValidatedPacket, TP_STATUS_AVAILABLE, TP_STATUS_KERNEL, TP_STATUS_SENDING,
    TP_STATUS_SEND_REQUEST, TP_STATUS_USER, TP_STATUS_WRONG_FORMAT,
};
pub use platform::{AfPacketPlatform, UapiLayout};
pub use stats::{BackendStat, BackendStats, BackendStatsSnapshot};
