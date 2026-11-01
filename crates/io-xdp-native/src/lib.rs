#![deny(unsafe_code)]
#![doc = "Checked Linux UAPI facts and borrowed native AF_XDP ring views."]
#![doc = ""]
#![doc = "On x86_64 Linux, [`NativeSession::open`] runs one failure-atomic, libbpf-free"]
#![doc = "transaction through a private, dependency-free syscall/RAII seam: AF_XDP socket,"]
#![doc = "anonymous UMEM registration, four ring sizes, checked `XDP_MMAP_OFFSETS`, ring"]
#![doc = "mappings, `sockaddr_xdp` bind, and `XDP_OPTIONS` mode check."]
#![doc = "[`NativeSession::attach_xdp`] then redirects the bound queue to the socket with a"]
#![doc = "hand-assembled XDP program, an XSKMAP, and an unpinned `bpf_link` (Linux 5.9+),"]
#![doc = "refusing any interface that already has an XDP program. [`RxFillEngine`] runs"]
#![doc = "the datapath over the session's once-taken [`DatapathRings`] bundle with one"]
#![doc = "authoritative frame ledger: bounded Fill refill with starvation accounting,"]
#![doc = "validated RX descriptors, ledger-gated frame lending, same-frame TX bounded by"]
#![doc = "the TX ring capacity, validated completion reaping, need-wakeup kicks, and an"]
#![doc = "exactly-once shutdown drain. Core `PacketIo` integration remains unimplemented."]

mod config;
mod datapath;
mod error;
mod platform;
mod ring;
mod rx_fill;
mod session;
mod xdp_program;

#[path = "native_unsafe/abi.rs"]
pub mod abi;
mod native_unsafe {
    #[cfg(test)]
    #[path = "heap_kernel.rs"]
    pub(super) mod heap_kernel;
    #[path = "kick.rs"]
    pub(super) mod kick;
    #[path = "mmap.rs"]
    pub(super) mod mmap;
    #[path = "ring_mem.rs"]
    pub(super) mod ring_mem;
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[path = "session.rs"]
    pub(super) mod session;
    #[cfg(all(
        test,
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[path = "session_tests.rs"]
    mod session_tests;
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[path = "syscall.rs"]
    pub(super) mod syscall;
    #[path = "umem.rs"]
    pub(super) mod umem;
}

pub use config::{
    validate_descriptor_options, BindMode, RingConfig, RingEntries, RingName, UmemConfig,
    ValidatedBindFlags, MIN_VISIBLE_FRAME_CAPACITY, SUPPORTED_ALIGNED_CHUNK_SIZES,
    XDP_PACKET_HEADROOM,
};
pub use datapath::{DatapathError, DatapathRings, RingsError};
pub use ruster_io_xdp::native_profile::ConfigError;

pub use error::{
    AbiLayoutError, NativeRingError, NativeSyscallPlatformError, PlatformError, RingField,
    RingMapError,
};
pub use native_unsafe::kick::{KickDeferral, KickError, KickOutcome};
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
pub use native_unsafe::session::NativeSession;
pub use platform::{ensure_native_syscall_supported, ensure_supported};
pub use ring::{
    CompletionAcquisition, CompletionConsumer, FillProducer, FillReservation, NeedWakeup,
    ProducerPublication, RxAcquisition, RxConsumer, TxProducer, TxReservation,
};
pub use ruster_io_xdp::{AuditError, FrameId, FrameStateKind, LedgerError, UmemDomainId};
pub use rx_fill::{
    CompletionInvalidReason, CompletionLag, CompletionReport, DrainOutcome, DrainReport,
    FrameAccounting, RefillReport, RxBatch, RxFillAuditError, RxFillConfig, RxFillCounters,
    RxFillEngine, RxFillError, RxFillSetupError, RxFrame, RxInvalidReason, TxBlocked, TxCounters,
    TxHandoff, TxRejected, TxRejection, TxSubmitError, TxSubmitReport, ETHERNET_HEADER_LEN,
};
pub use session::{
    AttachError, AttachFailure, AttachStage, CleanupError, CleanupStage, NativeRings,
    NegotiatedMode, SessionConfig, SessionConfigError, SessionError, SessionFailure, SessionStage,
    UmemRegion, VerifierLogSummary, XdpAttachMode, INTERFACE_NAME_CAPACITY, MAX_QUEUE_ID,
    MAX_RING_HEADER_OFFSET,
};

#[cfg(test)]
mod rx_fill_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tx_completion_tests;
