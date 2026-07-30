#![deny(unsafe_code)]
#![doc = "Checked Linux UAPI facts and borrowed native AF_XDP ring views."]
#![doc = ""]
#![doc = "This crate does not open sockets, create mappings, register UMEM, implement packet I/O,"]
#![doc = "or link libxdp. Callers retain ownership of every borrowed mapping."]

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
}

pub use config::{
    validate_descriptor_options, BindMode, RingConfig, RingEntries, RingName, UmemConfig,
    ValidatedBindFlags, MIN_VISIBLE_FRAME_CAPACITY, SUPPORTED_ALIGNED_CHUNK_SIZES,
    XDP_PACKET_HEADROOM,
};
pub use error::{
    AbiLayoutError, ConfigError, NativeRingError, PlatformError, RingField, RingMapError,
};
pub use platform::ensure_supported;
pub use ring::{
    CompletionAcquisition, CompletionConsumer, FillProducer, FillReservation, NeedWakeup,
    ProducerPublication, RxAcquisition, RxConsumer, TxProducer, TxReservation,
};

#[cfg(test)]
mod tests;
