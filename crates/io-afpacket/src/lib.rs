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
//! Linux builds are intentionally restricted to 64-bit targets until every
//! supported 32-bit ABI is checked independently.
//!
//! The AP0 profile is deliberately narrow: `SOCK_RAW` Ethernet II, no
//! `PACKET_RESERVE`, `TPACKET3_HDRLEN == 68`, RX `tp_mac == 82`, and
//! `tp_net == 96`. RX alone may set retire timeout, private bytes, and
//! `TP_FT_REQ_FILL_RXHASH`; all three corresponding TX request fields must be
//! zero. RX block-private geometry uses the kernel's checked eight-byte
//! `BLK_PLUS_PRIV` alignment and rejects configurations that cannot hold the
//! declared maximum Ethernet frame without truncation. TX frame capacity uses
//! the kernel's 48-byte minimum data offset rather than the larger RX Ethernet
//! offset. The socket is opened with protocol zero and becomes active only when
//! its validated `sockaddr_ll` is bound. Backend counters are fixed accumulators
//! only. AP1-0 additionally fixes disjoint RX/TX extents within the combined
//! mapping and cold-preallocates fixed metadata for later state machines. It
//! still provides no live I/O, `PacketIo`, wakeup, or cleanup telemetry.

#[cfg(all(target_os = "linux", not(target_pointer_width = "64")))]
compile_error!("ruster-io-afpacket currently supports only 64-bit Linux targets");

mod boundary;
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
    TPACKET_V3_ALIGNMENT, TPACKET_V3_ETHERNET_MAC_OFFSET, TPACKET_V3_ETHERNET_NETWORK_OFFSET,
    TPACKET_V3_HDRLEN, TPACKET_V3_HEADER_LEN, TPACKET_V3_TX_DATA_OFFSET, TPACKET_V3_VERSION,
};
pub use error::{
    ConfigError, Errno, GeometryError, MappingAccessError, OwnershipError, PlatformError,
    SyscallStage, TxOperation,
};
pub use model::{
    validate_v3_block_chain, BlockDescriptor, PacketDescriptor, RxBlockModel, RxOwnership,
    TxFrameModel, TxOwnership, ValidatedPacket, TP_STATUS_AVAILABLE, TP_STATUS_KERNEL,
    TP_STATUS_SENDING, TP_STATUS_SEND_REQUEST, TP_STATUS_USER, TP_STATUS_WRONG_FORMAT,
};
pub use platform::{AfPacketPlatform, UapiLayout};
pub use stats::{BackendStat, BackendStats, BackendStatsSnapshot};
