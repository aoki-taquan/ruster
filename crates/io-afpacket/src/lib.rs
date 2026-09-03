#![deny(unsafe_code)]
#![doc = "Linux AF_PACKET/TPACKET_V3 configuration and ownership primitives."]
//!
//! This crate provides checked configuration, fixed interface lookup, ring
//! geometry, descriptor bounds, ownership state, and a Linux syscall/mmap
//! boundary for a live `AfPacketIo` implementation of
//! [`ruster_core::PacketIo`] on Linux. Its TX engine publishes fixed frames, scans FIFO
//! completions, and batches nonblocking endpoint kicks; the adapter couples it
//! to zero-copy RX leases over USER-owned TPACKET_V3 blocks.
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
//! only. The combined mapping is split into checked, disjoint RX/TX extents
//! and cold-preallocated metadata. RX block ownership is returned on finish,
//! drop, and receive-time validation errors; accepted TX frames remain owned
//! by the existing TX completion engine.

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
    AfPacketError, ConfigError, Errno, GeometryError, MappingAccessError, OwnershipError,
    PlatformError, PublicationQuiescenceError, SyscallStage, TxCompletionError, TxOperation,
    TxSubmitError,
};
pub use model::{
    validate_v3_block_chain, BlockDescriptor, PacketDescriptor, RxBlockModel, RxOwnership,
    TxFrameModel, TxOwnership, ValidatedPacket, TP_STATUS_AVAILABLE, TP_STATUS_BLK_TMO,
    TP_STATUS_KERNEL, TP_STATUS_SENDING, TP_STATUS_SEND_REQUEST, TP_STATUS_USER,
    TP_STATUS_WRONG_FORMAT,
};
pub use platform::{AfPacketPlatform, UapiLayout};
pub use stats::{BackendStat, BackendStats, BackendStatsSnapshot};

#[cfg(target_os = "linux")]
pub use sys::{
    AfPacketBatch, AfPacketGeneratedBatch, AfPacketGeneratedSlot, AfPacketIo, AfPacketSlot,
};
