#![deny(unsafe_code)]
#![doc = "Linux AF_PACKET/TPACKET_V3 packet backend: checked configuration, ownership primitives, and the live `AfPacketIo` adapter."]
//!
//! This crate provides checked configuration, fixed interface lookup, ring
//! geometry, descriptor bounds, ownership state, the Linux syscall/mmap
//! boundary, and since AP3 the live backend [`AfPacketIo`] (Linux only).
//! The AF_PACKET backend is the fallback backend of `ruster-fe`; AF_XDP
//! is the primary one. `ruster-fe --backend af-packet` selects it.
//!
//! Engines (all private, static dispatch over one syscall seam that scripted
//! tests replace): the AP1 TX engine publishes fixed frames, scans FIFO
//! completions, and batches nonblocking endpoint kicks. The AP1 RX engine
//! keeps a persistent block cursor, validates each USER block chain before
//! exposing any packet, lends zero-copy packet views, and returns each block
//! exactly once after its last packet is terminal. AP2 unifies both
//! directions of every port in one engine that implements
//! [`ruster_core::PacketIo`] as a copy backend: leases borrow RX bytes in
//! place, and `commit` copies them exactly once into a TX frame of any port,
//! including the ingress port.
//!
//! AP3 makes the engine operable. [`AfPacketIo::open`] opens every port as a
//! failure-atomic transaction (socket, `PACKET_VERSION`,
//! `PACKET_IGNORE_OUTGOING`, `PACKET_LOSS`, both rings, one combined mapping,
//! then `bind` to the interface index as the single activation point).
//! `receive`, `begin_generated`, and the publication quiescence check first
//! *settle* ports: they reap TX completions (bounded FIFO scan) and retry
//! owed kicks with a 1 ms to 64 ms backoff paced by the loop clock
//! ([`AfPacketIo::set_clock`]). Kick errnos are classified: deferral and a
//! down link are not errors. Generated frames ([`ruster_core::GeneratedPacketIo`])
//! are the egress TX frames themselves, zeroed and lent in place, so a
//! router-generated frame is never copied. [`AfPacketIo::wait_rx`] is the
//! idle wait: `poll(2)` over every socket unless RX work is already visible.
//! [`ruster_core::BackendStats`] reports fixed-shape counters (OBS-028);
//! the kernel's `PACKET_STATISTICS` are folded in only by the cold
//! [`AfPacketIo::refresh_kernel_stats`]. [`AfPacketIo::drain`] stops I/O for
//! good and reaps with forced kicks; drop unmaps before it closes.
//!
//! Exposure model: unlike AF_XDP, AF_PACKET does not take frames away from
//! the kernel. The kernel stack still receives every frame of a port, so a
//! port must carry no kernel address, route, or forwarding role (the caller's
//! job; `ruster-fe` does not check it). TPACKET_V3 makes a
//! block visible only when it is full or its retire timer fires, so an idle
//! port delivers a lone frame up to the RX `retire_timeout_ms` late.
//!
//! The safe model is available on every target. Raw Linux UAPI access is
//! confined to `sys`; [`AfPacketPlatform::ensure_supported`] returns
//! [`PlatformError::UnsupportedPlatform`] elsewhere.
//! Linux builds are intentionally restricted to 64-bit targets until every
//! supported 32-bit ABI is checked independently.
//!
//! The AP0 profile is deliberately narrow: `SOCK_RAW` Ethernet II,
//! `PACKET_RESERVE` of [`TPACKET_V3_RESERVE`] (64), `TPACKET3_HDRLEN == 68`, RX
//! `tp_mac == 146`, and `tp_net == 160`. RX alone may set retire timeout, private bytes, and
//! `TP_FT_REQ_FILL_RXHASH`; all three corresponding TX request fields must be
//! zero. RX block-private geometry uses the kernel's checked eight-byte
//! `BLK_PLUS_PRIV` alignment and rejects configurations that cannot hold the
//! declared maximum Ethernet frame without truncation. TX frame capacity uses
//! the kernel's 48-byte minimum data offset rather than the larger RX Ethernet
//! offset. The strict profile requires GRO/LRO disabled (GSO superframes are
//! dropped as truncated or oversize). A VLAN tag the kernel removed is put back
//! into the frame before core sees it. The maximum frame length must not exceed the device MTU
//! plus 14; `PACKET_LOSS` keeps a frame the kernel cannot send from stalling
//! the TX ring.
//!
//! [`AfPacketIo`]: crate::AfPacketIo
//! [`AfPacketIo::open`]: crate::AfPacketIo::open
//! [`AfPacketIo::set_clock`]: crate::AfPacketIo::set_clock
//! [`AfPacketIo::wait_rx`]: crate::AfPacketIo::wait_rx
//! [`AfPacketIo::refresh_kernel_stats`]: crate::AfPacketIo::refresh_kernel_stats
//! [`AfPacketIo::drain`]: crate::AfPacketIo::drain

#[cfg(all(target_os = "linux", not(target_pointer_width = "64")))]
compile_error!("ruster-io-afpacket currently supports only 64-bit Linux targets");

mod boundary;
mod config;
mod error;
mod io_stats;
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
    TPACKET_V3_HDRLEN, TPACKET_V3_HEADER_LEN, TPACKET_V3_RESERVE, TPACKET_V3_TX_DATA_OFFSET,
    TPACKET_V3_VERSION,
};
pub use error::{
    ConfigError, Errno, GeometryError, MappingAccessError, OwnershipError, PlatformError,
    SyscallStage, TxOperation,
};
pub use io_stats::{AfPacketBackendStats, AfPacketCounters, AfPacketPortStats, RxWait};
pub use model::{
    validate_v3_block_chain, BlockDescriptor, PacketDescriptor, RxBlockModel, RxOwnership,
    TxFrameModel, TxOwnership, ValidatedPacket, TP_STATUS_AVAILABLE, TP_STATUS_KERNEL,
    TP_STATUS_SENDING, TP_STATUS_SEND_REQUEST, TP_STATUS_USER, TP_STATUS_WRONG_FORMAT,
};
pub use platform::{AfPacketPlatform, UapiLayout};
pub use stats::{BackendStat, BackendStats, BackendStatsSnapshot};
#[cfg(target_os = "linux")]
pub use sys::{
    AfPacketDrain, AfPacketError, AfPacketGeneratedBatch, AfPacketGeneratedSlot, AfPacketIo,
    AfPacketQuiescenceError, AfPacketRxBatch, AfPacketRxFault, AfPacketRxSlot, AfPacketTxFault,
};
