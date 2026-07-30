use std::fmt;

use ruster_core::IfId;

use crate::{RingKind, RxOwnership, TxOwnership};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Errno(i32);

impl Errno {
    #[must_use]
    pub const fn new(raw: i32) -> Self {
        Self(raw)
    }

    #[must_use]
    pub const fn get(self) -> i32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallStage {
    Socket,
    SetVersion,
    SetIgnoreOutgoing,
    SetRxRing,
    SetTxRing,
    Bind,
    Mmap,
    Munmap,
    Close,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformError {
    UnsupportedPlatform,
    UapiLayoutMismatch,
    Syscall { stage: SyscallStage, errno: Errno },
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => formatter.write_str("AF_PACKET requires Linux"),
            Self::UapiLayoutMismatch => {
                formatter.write_str("compiled TPACKET_V3 UAPI layout is incompatible")
            }
            Self::Syscall { stage, errno } => {
                write!(formatter, "{stage:?} failed with errno {}", errno.get())
            }
        }
    }
}

impl std::error::Error for PlatformError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeometryError {
    PageSizeNotPowerOfTwo { page_size: usize },
    ZeroMaxFrameLength,
    ZeroBlockSize,
    ZeroBlockCount,
    ZeroFrameSize,
    ZeroFrameCount,
    BlockSizeNotPageAligned { block_size: u32, page_size: usize },
    FrameSizeNotAligned { frame_size: u32 },
    FrameTooSmall { frame_size: u32, minimum: usize },
    FramesDoNotTileBlock { block_size: u32, frame_size: u32 },
    FrameCountMismatch { configured: u32, expected: usize },
    PrivateAreaNotAligned { private_size: u32 },
    PrivateAreaTooLarge { private_size: u32, block_size: u32 },
    UnknownFeatureFlags { feature_flags: u32 },
    FeatureFlagsUnsupportedForTx { feature_flags: u32 },
    ArithmeticOverflow,
    BlockIndexOutOfRange { block_index: usize },
    PacketCountZero,
    PacketCountExceedsBlock { packet_count: u32, maximum: usize },
    FirstPacketOffsetInvalid { offset: usize },
    PacketOffsetNotAligned { offset: usize },
    PacketHeaderOutOfBounds { offset: usize },
    MacOffsetBeforeHeader { mac_offset: usize },
    SnapshotExceedsWireLength { snap_len: usize, wire_len: usize },
    PacketDataOutOfBounds { offset: usize, length: usize },
    MissingNextPacketOffset,
    NextPacketOffsetNotAligned { offset: usize },
    NextPacketOffsetTooSmall { offset: usize },
    PacketCrossesNextOffset,
    InvalidRxStatus { status: u32 },
    InvalidTxStatus { status: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    NoPorts,
    TooManyPorts {
        count: usize,
    },
    ZeroIfIndex {
        interface: IfId,
    },
    IfIndexOutOfRange {
        interface: IfId,
        if_index: u32,
    },
    DuplicateInterface {
        interface: IfId,
    },
    DuplicateIfIndex {
        if_index: u32,
    },
    Ring {
        interface: IfId,
        kind: RingKind,
        source: GeometryError,
    },
    CombinedMapOverflow {
        interface: IfId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipError {
    RxAcquireWhileOwned {
        owner: RxOwnership,
    },
    RxReleaseWhileKernelOwned,
    RxPacketCountZero,
    RxTooManyCompletions {
        packets: u32,
    },
    RxPacketsOutstanding {
        remaining: u32,
    },
    TxInvalidTransition {
        from: TxOwnership,
        operation: TxOperation,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxOperation {
    Prepare,
    CancelPrepared,
    Publish,
    KernelAccept,
    KernelComplete,
    KernelRejectFormat,
    ReclaimUnconsumed,
    RecycleWrongFormat,
}
