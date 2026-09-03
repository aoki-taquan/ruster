#![deny(unsafe_code)]
#![doc = "Checked Linux UAPI facts and borrowed native AF_XDP ring views."]
#![doc = ""]
#![doc = "The resource setup API registers caller-owned UMEM, configures and maps all"]
#![doc = "four AF_XDP rings, and activates the queue with a checked bind transaction."]
#![doc = "The cold XDP program API also attaches and detaches through rtnetlink."]

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
mod aggregate;
mod config;
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
mod data_path;
mod error;
mod netlink;
mod platform;
mod program;
mod ring;
mod setup;
mod xskmap;

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
    // Crate-private only: the safe setup layer uses this static-dispatch seam.
    pub(crate) mod syscall;
}

pub use config::{
    validate_descriptor_options, BindMode, RingConfig, RingEntries, RingName, UmemConfig,
    ValidatedBindFlags, MAX_UMEM_BYTES, MAX_UMEM_FRAME_COUNT, MIN_VISIBLE_FRAME_CAPACITY,
    SUPPORTED_ALIGNED_CHUNK_SIZES, XDP_PACKET_HEADROOM,
};
pub use error::{
    AbiLayoutError, ConfigError, NativeRingError, NativeSyscallPlatformError, PlatformError,
    RingField, RingMapError, XdpAttachConfigError, XdpAttachError, XdpAttachOperation,
    XdpChunkState, XdpIoError, XdpPairIoError, XdpProgramError, XdpProgramOperation,
    XdpResourcePairError, XdpResourcePairIndex, XdpSetupArgumentError, XdpSetupError,
    XdpSetupStage, XskMapError, XskMapOperation,
};
pub use netlink::{
    ValidatedXdpAttachFlags, XdpAttachFlags, XdpAttachMode, XdpAttachOptions, XdpAttachment,
    IFLA_XDP, IFLA_XDP_EXPECTED_FD, IFLA_XDP_FD, IFLA_XDP_FLAGS, NLM_F_ACK, NLM_F_REQUEST,
    RTM_SETLINK, XDP_FLAGS_DRV_MODE, XDP_FLAGS_REPLACE, XDP_FLAGS_SKB_MODE,
    XDP_FLAGS_UPDATE_IF_NOEXIST,
};
pub use platform::{ensure_native_syscall_supported, ensure_supported};
pub use program::{
    encode_xdp_redirect_program, xdp_redirect_instructions, xdp_redirect_program_bytecode, BpfInsn,
    XdpRedirectProgram, XDP_REDIRECT_PROGRAM_BYTECODE_LEN, XDP_REDIRECT_PROGRAM_INSTRUCTION_COUNT,
};
pub use ring::{
    CompletionAcquisition, CompletionConsumer, FillProducer, FillReservation, NeedWakeup,
    ProducerPublication, RxAcquisition, RxConsumer, TxProducer, TxReservation,
};
pub use setup::{PageAlignedUmem, XdpResource, XdpResourceBuilder, XdpRingViews};
pub use xskmap::XskMap;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
pub use aggregate::{
    XdpPairGeneratedBatch, XdpPairGeneratedSlot, XdpPairPacketBatch, XdpPairPacketSlot,
    XdpResourcePair,
};
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
pub use data_path::{XdpGeneratedBatch, XdpGeneratedSlot, XdpPacketBatch, XdpPacketSlot};

#[cfg(test)]
mod tests;
