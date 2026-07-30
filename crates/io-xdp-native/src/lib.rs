#![deny(unsafe_code)]
#![doc = "Checked Linux UAPI facts and borrowed native AF_XDP ring views."]
#![doc = ""]
#![doc = "A private, dependency-free x86_64 Linux syscall/RAII seam exists for later resource"]
#![doc = "setup, but no public API opens sockets or mappings. UMEM registration, ring"]
#![doc = "configuration, bind transactions, packet I/O, and libxdp integration remain"]
#![doc = "unimplemented."]

mod config;
mod error;
mod platform;
mod ring;

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
    #[path = "syscall.rs"]
    pub(super) mod syscall;
}

pub use config::{
    validate_descriptor_options, BindMode, RingConfig, RingEntries, RingName, UmemConfig,
    ValidatedBindFlags, MIN_VISIBLE_FRAME_CAPACITY, SUPPORTED_ALIGNED_CHUNK_SIZES,
    XDP_PACKET_HEADROOM,
};
pub use error::{
    AbiLayoutError, ConfigError, NativeRingError, NativeSyscallPlatformError, PlatformError,
    RingField, RingMapError,
};
pub use platform::{ensure_native_syscall_supported, ensure_supported};
pub use ring::{
    CompletionAcquisition, CompletionConsumer, FillProducer, FillReservation, NeedWakeup,
    ProducerPublication, RxAcquisition, RxConsumer, TxProducer, TxReservation,
};

#[cfg(test)]
mod tests;
