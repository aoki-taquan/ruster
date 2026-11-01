#![deny(unsafe_code)]
#![doc = "Checked Linux UAPI facts and borrowed native AF_XDP ring views."]
#![doc = ""]
#![doc = "On x86_64 Linux, [`NativeSession::open`] runs one failure-atomic, libbpf-free"]
#![doc = "transaction through a private, dependency-free syscall/RAII seam: AF_XDP socket,"]
#![doc = "anonymous UMEM registration, four ring sizes, checked `XDP_MMAP_OFFSETS`, ring"]
#![doc = "mappings, `sockaddr_xdp` bind, and `XDP_OPTIONS` mode check. XDP program attach,"]
#![doc = "packet I/O, and core `PacketIo` integration remain unimplemented."]

mod config;
mod error;
mod platform;
mod ring;
mod session;

#[path = "native_unsafe/abi.rs"]
pub mod abi;
mod native_unsafe {
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
}

pub use config::{
    validate_descriptor_options, BindMode, RingConfig, RingEntries, RingName, UmemConfig,
    ValidatedBindFlags, MIN_VISIBLE_FRAME_CAPACITY, SUPPORTED_ALIGNED_CHUNK_SIZES,
    XDP_PACKET_HEADROOM,
};
pub use ruster_io_xdp::native_profile::ConfigError;

pub use error::{
    AbiLayoutError, NativeRingError, NativeSyscallPlatformError, PlatformError, RingField,
    RingMapError,
};
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
pub use session::{
    CleanupError, CleanupStage, NativeRings, NegotiatedMode, SessionConfig, SessionConfigError,
    SessionError, SessionFailure, SessionStage, UmemRegion, INTERFACE_NAME_CAPACITY, MAX_QUEUE_ID,
    MAX_RING_HEADER_OFFSET,
};

#[cfg(test)]
mod tests;
