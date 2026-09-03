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
    Poll,
    Mmap,
    Kick,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformError {
    UnsupportedPlatform,
    UapiLayoutMismatch,
    InvalidSocketAddress { family: u16, if_index: i32 },
    InvalidCombinedMapping(MappingAccessError),
    MetadataAllocationFailed { kind: RingKind, entries: usize },
    Syscall { stage: SyscallStage, errno: Errno },
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => formatter.write_str("AF_PACKET requires Linux"),
            Self::UapiLayoutMismatch => {
                formatter.write_str("compiled TPACKET_V3 UAPI layout is incompatible")
            }
            Self::InvalidSocketAddress { family, if_index } => {
                write!(
                    formatter,
                    "invalid AF_PACKET address family {family}, ifindex {if_index}"
                )
            }
            Self::InvalidCombinedMapping(source) => {
                write!(formatter, "invalid combined AF_PACKET mapping: {source:?}")
            }
            Self::MetadataAllocationFailed { kind, entries } => {
                write!(
                    formatter,
                    "cannot preallocate {entries} {kind:?} metadata entries"
                )
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
    PageSizeNotPowerOfTwo {
        page_size: usize,
    },
    ZeroMaxFrameLength,
    ZeroBlockSize,
    ZeroBlockCount,
    ZeroFrameSize,
    ZeroFrameCount,
    BlockSizeNotPageAligned {
        block_size: u32,
        page_size: usize,
    },
    BlockSizeExceedsKernelLimit {
        block_size: u32,
    },
    FrameSizeNotAligned {
        frame_size: u32,
    },
    FrameTooSmall {
        frame_size: u32,
        minimum: usize,
    },
    FramesDoNotTileBlock {
        block_size: u32,
        frame_size: u32,
    },
    FrameCountMismatch {
        configured: u32,
        expected: usize,
    },
    PrivateAreaTooLarge {
        private_size: u32,
        block_size: u32,
    },
    RxBlockBelowKernelMinimum {
        block_plus_private: usize,
        header_len: usize,
        block_size: u32,
    },
    RxBlockWouldTruncateMaxFrame {
        block_plus_private: usize,
        mac_offset: usize,
        max_frame_len: usize,
        block_size: u32,
    },
    UnknownFeatureFlags {
        feature_flags: u32,
    },
    RetireTimeoutUnsupportedForTx {
        retire_timeout_ms: u32,
    },
    PrivateAreaUnsupportedForTx {
        private_size: u32,
    },
    FeatureFlagsUnsupportedForTx {
        feature_flags: u32,
    },
    MapLengthExceedsAddressSpace {
        map_len: usize,
    },
    ArithmeticOverflow,
    BlockIndexOutOfRange {
        block_index: usize,
    },
    PacketCountZero,
    PacketCountExceedsBlock {
        packet_count: u32,
        maximum: usize,
    },
    PacketDescriptorCountMismatch {
        packet_count: u32,
        descriptors: usize,
    },
    PacketChainOffsetMismatch {
        expected: usize,
        actual: usize,
    },
    PacketTerminalFlagMismatch {
        index: usize,
    },
    UnsupportedBlockVersion {
        version: u32,
    },
    PrivateOffsetInvalid {
        offset: usize,
    },
    FirstPacketOffsetInvalid {
        offset: usize,
    },
    FirstPacketOffsetMismatch {
        configured: usize,
        expected: usize,
    },
    PacketOffsetNotAligned {
        offset: usize,
    },
    PacketHeaderOutOfBounds {
        offset: usize,
    },
    MacOffsetBeforeHeader {
        mac_offset: usize,
    },
    EthernetMacOffsetInvalid {
        mac_offset: usize,
    },
    EthernetNetworkOffsetInvalid {
        net_offset: usize,
    },
    SnapshotExceedsWireLength {
        snap_len: usize,
        wire_len: usize,
    },
    PacketDataOutOfBounds {
        offset: usize,
        length: usize,
    },
    MissingNextPacketOffset,
    TerminalPacketHasNextOffset {
        offset: usize,
    },
    NextPacketOffsetNotAligned {
        offset: usize,
    },
    NextPacketOffsetTooSmall {
        offset: usize,
    },
    PacketCrossesNextOffset,
    InvalidRxStatus {
        status: u32,
    },
    InvalidTxStatus {
        status: u32,
    },
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
    CombinedMapExceedsAddressSpace {
        interface: IfId,
        map_len: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingAccessError {
    ArithmeticOverflow,
    OffsetOutOfBounds {
        offset: usize,
        length: usize,
    },
    StatusNotAligned {
        offset: usize,
    },
    RingExtentsOverlap {
        rx_end: usize,
        tx_start: usize,
    },
    RingExtentGap {
        rx_end: usize,
        tx_start: usize,
    },
    RingExtentMisaligned {
        kind: RingKind,
        offset: usize,
        alignment: usize,
    },
    RingOffsetOutOfBounds {
        kind: RingKind,
        offset: usize,
        length: usize,
    },
    CombinedLengthMismatch {
        expected: usize,
        actual: usize,
    },
    BlockNotUser {
        status: u32,
    },
    PacketAlreadyBorrowed,
    PacketNotBorrowed,
    Geometry(GeometryError),
    Ownership(OwnershipError),
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
    RetryWrongFormat,
    ReclaimUnconsumed,
    RecycleWrongFormat,
}

/// A rejection or mapping failure while submitting one core-requested TX
/// packet to the existing TPACKET_V3 TX engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxSubmitError {
    /// The requested egress interface is not part of this backend.
    UnknownInterface,
    /// The packet is larger than the configured Ethernet frame limit.
    Oversize { length: usize, maximum: usize },
    /// The producer's next TX frame is still owned by the kernel or queued.
    Unavailable { status: u32 },
    /// The kernel exposed a status outside the supported TX state machine.
    InvalidStatus { status: u32 },
    /// The per-frame ownership generation cannot advance.
    GenerationExhausted { frame_index: usize },
    /// The mapped TX frame could not be addressed safely.
    Mapping(MappingAccessError),
    /// The userspace TX ownership model rejected a transition.
    Ownership(OwnershipError),
}

/// A failure while observing or recovering one endpoint's TX completions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxCompletionError {
    /// The requested interface is not part of this backend.
    UnknownInterface,
    /// The kernel exposed a status outside the supported TX state machine.
    InvalidStatus { status: u32 },
    /// The status and userspace ownership metadata disagree.
    UnexpectedOwnership {
        frame_index: usize,
        ownership: TxOwnership,
    },
    /// The nonblocking endpoint kick failed.
    Kick(PlatformError),
    /// The mapped TX frame could not be addressed safely.
    Mapping(MappingAccessError),
    /// The userspace TX ownership model rejected a transition.
    Ownership(OwnershipError),
}

/// Error returned by the live AF_PACKET packet-I/O adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AfPacketError {
    /// RX block status or descriptor validation failed for one ingress.
    Receive {
        interface: IfId,
        source: MappingAccessError,
    },
    /// A non-recoverable TX submission or ownership failure occurred.
    Transmit(TxSubmitError),
    /// TX completion observation or recovery failed for one egress.
    Completion {
        interface: IfId,
        source: TxCompletionError,
    },
    /// A batch kick failed after accepted descriptors were published.
    Kick(PlatformError),
    /// Waiting for RX readiness failed before a tick could resume.
    Wait(PlatformError),
    /// The backend observed outstanding or inconsistent publication ownership.
    Quiescence(PublicationQuiescenceError),
}

/// A fail-closed observation made while checking publication quiescence.
///
/// This taxonomy distinguishes a normal asynchronous TX completion from an
/// ownership or mapping inconsistency. The former may coexist with the
/// existing completion scan; every other case remains non-reentrant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationQuiescenceError {
    /// A TPACKET_V3 RX block is observed USER while an RX batch is active.
    RxBlockUser {
        interface: IfId,
        block_index: usize,
        status: u32,
    },
    /// A mapped RX block status is outside the supported ownership protocol.
    RxBlockInvalidStatus {
        interface: IfId,
        block_index: usize,
        status: u32,
    },
    /// A checked mapping operation failed while observing RX/TX ownership.
    Mapping(MappingAccessError),
    /// A TX frame is in the expected asynchronous kernel completion path.
    ///
    /// `receive` invokes the existing FIFO completion scan before creating its
    /// batch, so this is the only quiescence error classified as compatible
    /// with continuing the old publication.
    TxCompletionPending {
        interface: IfId,
        frame_index: usize,
        status: u32,
        ownership: TxOwnership,
    },
    /// TX metadata, mapped status, and engine in-flight accounting disagree.
    TxOwnershipMismatch {
        interface: IfId,
        frame_index: usize,
        status: u32,
        ownership: TxOwnership,
        in_flight: usize,
    },
    /// The endpoint-wide in-flight count disagrees with TX frame metadata.
    TxInFlightAccountingMismatch {
        interface: IfId,
        in_flight: usize,
        owned_frames: usize,
    },
    /// A generated batch was forgotten before its finish/drop path ran.
    GeneratedBatchActive,
    /// An RX batch was forgotten before its finish/drop path ran.
    RxBatchActive,
}
