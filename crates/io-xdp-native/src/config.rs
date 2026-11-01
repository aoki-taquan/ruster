//! The safe configuration profile lives in `ruster-io-xdp` so that cold
//! configuration validation can share it without depending on this crate's
//! unsafe ring and syscall code. It is re-exported here unchanged.

pub use ruster_io_xdp::native_profile::{
    validate_descriptor_options, BindMode, RingConfig, RingEntries, RingName, UmemConfig,
    ValidatedBindFlags, MIN_VISIBLE_FRAME_CAPACITY, SUPPORTED_ALIGNED_CHUNK_SIZES,
    XDP_PACKET_HEADROOM,
};
