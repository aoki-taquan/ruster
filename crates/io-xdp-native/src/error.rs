use std::{error::Error, fmt};

use crate::RingName;
use ruster_core::IfId;

/// A named field within one kernel-reported ring mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingField {
    /// Producer cursor.
    Producer,
    /// Consumer cursor.
    Consumer,
    /// Need-wakeup flags word.
    Flags,
    /// Descriptor array.
    Descriptors,
}

/// Cold configuration validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// At least one UMEM frame is required.
    ZeroFrameCount,
    /// The ownership ledger is bounded to a practical number of entries.
    UmemFrameCountExceedsLimit {
        /// Rejected total frame count.
        frame_count: u32,
        /// Maximum number of ledger entries accepted by the profile.
        limit: u32,
    },
    /// The initial aligned profile supports only 2,048 or 4,096-byte chunks.
    InvalidFrameSize(u32),
    /// Adding fixed kernel headroom and minimum visible capacity overflowed.
    HeadroomCapacityOverflow {
        /// Requested headroom.
        headroom: u32,
    },
    /// Combined configured and fixed headroom left no minimum visible area.
    InsufficientVisibleCapacity {
        /// Requested additional UMEM headroom.
        headroom: u32,
        /// Configured frame size.
        frame_size: u32,
        /// Fixed kernel RX headroom.
        kernel_headroom: u32,
        /// Minimum required packet capacity.
        minimum_visible: u32,
    },
    /// The initial profile does not accept these UMEM flags.
    UnsupportedUmemFlags(u32),
    /// At least one frame must be reserved for RX/FILL.
    ZeroRxFrames,
    /// At least one frame must be reserved for generated packets.
    ZeroGeneratedFrames,
    /// The two frame-pool counts overflowed.
    FramePartitionOverflow,
    /// The complete UMEM byte length overflowed its checked representation.
    UmemLengthOverflow,
    /// The complete UMEM mapping exceeds the practical byte limit.
    UmemByteLengthExceedsLimit {
        /// Rejected complete UMEM byte length.
        byte_len: u64,
        /// Maximum complete UMEM byte length accepted by the profile.
        limit: u64,
    },
    /// RX and generated pools did not partition the UMEM exactly.
    FramePartitionMismatch {
        /// Total configured frames.
        frame_count: u32,
        /// RX/FILL frame count.
        rx_frames: u32,
        /// Generated frame count.
        generated_frames: u32,
    },
    /// A ring capacity was zero or not a power of two.
    InvalidRingEntries {
        /// Ring whose capacity was rejected.
        ring: RingName,
        /// Rejected capacity.
        entries: u32,
    },
    /// Bind flags included unsupported or unknown bits.
    UnsupportedBindFlags(u16),
    /// The initial profile always requires `XDP_USE_NEED_WAKEUP`.
    NeedWakeupRequired,
    /// Copy and zero-copy were both required.
    ConflictingBindModes,
    /// Single-buffer descriptors require an option word of zero.
    UnsupportedDescriptorOptions(u32),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for ConfigError {}

/// Syscall stage reported by the AF_XDP resource setup transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpSetupStage {
    /// AF_XDP socket creation.
    OpenSocket,
    /// `setsockopt(2)` while registering UMEM or configuring a ring.
    SetSocketOption,
    /// `getsockopt(2)` while reading kernel mmap offsets.
    GetSocketOption,
    /// A ring mmap operation.
    MapMemory,
    /// A ring munmap operation during cleanup.
    UnmapMemory,
    /// The final `bind(2)` activation.
    BindSocket,
    /// An optional polling operation reserved for the later I/O layer.
    PollSocket,
    /// An optional TX wakeup operation reserved for the later I/O layer.
    SendToSocket,
    /// Socket close during cleanup.
    CloseSocket,
}

/// Checked argument failure at the native syscall boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpSetupArgumentError {
    /// The kernel returned a negative or otherwise invalid descriptor.
    InvalidFileDescriptor,
    /// A syscall received an empty byte extent.
    ZeroLength {
        /// Operation that rejected the extent.
        stage: XdpSetupStage,
    },
    /// A byte extent cannot be represented by Linux `socklen_t`.
    LengthDoesNotFitSockLen {
        /// Operation that rejected the extent.
        stage: XdpSetupStage,
        /// Rejected length.
        length: usize,
    },
    /// An mmap offset cannot be represented by Linux `off_t`.
    OffsetDoesNotFitOffT {
        /// Rejected offset.
        offset: u64,
    },
    /// The kernel reported more bytes than the supplied getsockopt buffer.
    KernelLengthOutOfBounds {
        /// Supplied buffer capacity.
        capacity: usize,
        /// Kernel-reported length.
        actual: usize,
    },
    /// An mmap extent is too large for process-relative pointer arithmetic.
    LengthDoesNotFitAddressSpace {
        /// Operation that rejected the extent.
        stage: XdpSetupStage,
        /// Rejected length.
        length: usize,
    },
}

/// Typed failure from the AF_XDP resource setup transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpSetupError {
    /// A caller-supplied configuration failed validation.
    Config(ConfigError),
    /// The native syscall profile is unavailable on this target.
    Platform(NativeSyscallPlatformError),
    /// AF_XDP interface indices are one-based and zero is invalid.
    InvalidInterfaceIndex {
        /// Rejected interface index.
        ifindex: u32,
    },
    /// The interface index cannot be represented by the core's checked
    /// interface identifier.
    InterfaceIndexNotRepresentable {
        /// Rejected interface index.
        ifindex: u32,
    },
    /// This owner registers a new UMEM and cannot bind with shared-UMEM mode.
    SharedUmemUnsupported,
    /// The configured UMEM length cannot be represented by this process.
    UmemLengthNotRepresentable {
        /// Configured UAPI length.
        length: u64,
    },
    /// The UMEM length exceeds the address-space extent accepted by setup.
    UmemLengthExceedsAddressSpace {
        /// Rejected length.
        length: u64,
    },
    /// The borrowed byte slice does not exactly match the configured UMEM.
    UmemLengthMismatch {
        /// Configured UAPI length.
        expected: u64,
        /// Borrowed slice length.
        actual: u64,
    },
    /// The UMEM address was null.
    UmemAddressIsNull,
    /// The page-backed UMEM allocator returned an address that was not aligned
    /// to the reviewed Linux page boundary.
    UmemAddressMisaligned {
        /// Process address returned by `mmap(2)`.
        address: usize,
        /// Required alignment in bytes.
        alignment: usize,
    },
    /// The UMEM address cannot be represented by the reviewed UAPI word.
    UmemAddressNotRepresentable {
        /// Rejected process address.
        address: usize,
    },
    /// The UMEM address plus length wrapped its integer representation.
    UmemAddressRangeOverflow {
        /// Start address.
        address: u64,
        /// Byte length.
        length: u64,
    },
    /// `XDP_MMAP_OFFSETS` did not return the complete reviewed structure.
    MmapOffsetsLengthMismatch {
        /// Required structure length.
        expected: usize,
        /// Kernel-reported length.
        actual: usize,
    },
    /// A kernel-reported ring layout failed checked ABI validation.
    RingLayout {
        /// Ring whose offsets were rejected.
        ring: RingName,
        /// Detailed checked-layout failure.
        source: AbiLayoutError,
    },
    /// The mmap file offset plus ring extent overflowed.
    RingMmapExtentOverflow {
        /// Ring whose mmap extent was rejected.
        ring: RingName,
        /// Linux mmap page offset.
        offset: u64,
        /// Required mapping length.
        length: usize,
    },
    /// The ring mapping is too large for process-relative address arithmetic.
    RingMmapLengthExceedsAddressSpace {
        /// Ring whose mapping was rejected.
        ring: RingName,
        /// Required mapping length.
        length: usize,
    },
    /// A syscall wrapper rejected an argument before entering libc.
    SyscallArgument(XdpSetupArgumentError),
    /// Linux returned an errno from the transaction.
    Syscall {
        /// Failing operation.
        stage: XdpSetupStage,
        /// Bounded Linux errno; `None` means errno capture was invalid.
        errno: Option<u16>,
    },
    /// The cold setup completed but the initial packet-path fill publication
    /// could not be established.
    DataPath(XdpIoError),
}

impl From<ConfigError> for XdpSetupError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}

impl fmt::Display for XdpSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for XdpSetupError {}

/// Stable ownership state of one UMEM chunk.
///
/// The native data path keeps one state for every configured chunk. The
/// state is an internal authority observation exposed here only so typed
/// ownership failures and cold diagnostics do not need an unstructured
/// string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpChunkState {
    /// The chunk is available for a new ownership cycle.
    Free,
    /// The chunk is reserved for an unpublished Fill entry.
    FillReserved,
    /// The kernel owns the chunk through the Fill ring.
    FillOwnedByKernel,
    /// The chunk is available in the RX ring.
    RxAvailable,
    /// Packet processing owns the chunk.
    Leased,
    /// Packet processing requested TX but publication has not started.
    PendingTx,
    /// The chunk is reserved for an unpublished TX entry.
    TxReserved,
    /// The kernel owns the chunk through the TX ring.
    TxOwnedByKernel,
    /// The kernel returned the chunk through the Completion ring.
    CompletionAvailable,
    /// The chunk is permanently excluded after an ownership/descriptor fault.
    Quarantined,
}

/// AF_XDP packet-path failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpIoError {
    /// The reviewed native syscall ABI is unavailable.
    Platform(NativeSyscallPlatformError),
    /// A native ring operation failed.
    Ring {
        /// Ring on which the operation failed.
        ring: RingName,
        /// Typed ring failure.
        source: NativeRingError,
    },
    /// A checked ring mapping could not be reconstructed for a data-path
    /// batch.
    Mapping(RingMapError),
    /// A polling or other native socket syscall failed before packet data was
    /// returned. The stage is kept typed so callers can distinguish a wait
    /// failure from a ring ownership failure.
    Syscall {
        /// Failing native operation.
        stage: XdpSetupStage,
        /// Bounded Linux errno; `None` means errno capture was invalid.
        errno: Option<u16>,
    },
    /// The kernel supplied a descriptor outside the checked single-buffer
    /// UMEM geometry.
    InvalidDescriptor {
        /// UMEM-relative packet address.
        address: u64,
        /// Visible packet length.
        len: u32,
        /// Descriptor option bits.
        options: u32,
    },
    /// The kernel supplied a completion address that cannot be tied to the
    /// TX ownership cycle which published it.
    InvalidCompletionAddress {
        /// UMEM-relative completion address.
        address: u64,
    },
    /// A checked ownership transition observed an unexpected state.
    Ownership {
        /// Affected zero-based chunk index.
        frame_index: u32,
        /// Required state.
        expected: XdpChunkState,
        /// State observed by the ledger.
        actual: XdpChunkState,
    },
    /// The caller requested an egress different from this one-queue socket.
    InterfaceMismatch {
        /// Interface represented by this socket.
        expected: ruster_core::IfId,
        /// Requested core egress.
        actual: ruster_core::IfId,
    },
    /// A packet or generated batch was started while another batch remained
    /// authoritative.
    BatchActive,
    /// The public raw ring-view escape hatch was used. Its writes are not
    /// reflected in the ownership ledger, so this resource is permanently
    /// disabled for the authoritative packet path.
    RawRingViewsExposed,
    /// An explicit wakeup syscall failed after producer publication.
    Wakeup {
        /// Bounded Linux errno; `None` means errno capture was invalid.
        errno: Option<u16>,
    },
    /// A quiescence probe found an outstanding authoritative owner.
    Quiescence {
        /// Affected chunk, when the failure is chunk-specific.
        frame_index: Option<u32>,
        /// State preventing publication handoff.
        state: XdpChunkState,
    },
}

impl fmt::Display for XdpIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for XdpIoError {}

impl XdpIoError {
    pub(crate) const fn from_ring_map(source: RingMapError) -> Self {
        Self::Mapping(source)
    }
}

/// The two fixed positions in an [`XdpResourcePair`](crate::XdpResourcePair).
///
/// The position is retained in aggregate I/O errors so a cold consumer can
/// identify which independently-owned socket reported the failure without
/// formatting or allocating on the packet path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpResourcePairIndex {
    /// The first resource supplied to [`XdpResourcePair::new`](crate::XdpResourcePair::new).
    First,
    /// The second resource supplied to [`XdpResourcePair::new`](crate::XdpResourcePair::new).
    Second,
}

/// A construction-time topology rejection for [`crate::XdpResourcePair`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpResourcePairError {
    /// Both sockets claim the same logical core interface identifier.
    DuplicateInterface { interface: IfId },
    /// Both sockets are bound to the same Linux link.
    DuplicateIfindex { ifindex: u32 },
}

impl fmt::Display for XdpResourcePairError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for XdpResourcePairError {}

/// A packet-path or quiescence failure from one member of an
/// [`XdpResourcePair`](crate::XdpResourcePair).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpPairIoError {
    /// The member resource reported the native failure.
    Resource {
        /// Fixed pair position of the failing resource.
        resource: XdpResourcePairIndex,
        /// Native resource error.
        error: XdpIoError,
    },
    /// No member is configured for the requested generated-packet egress.
    EgressNotFound { egress: IfId },
}

impl fmt::Display for XdpPairIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for XdpPairIoError {}

/// eBPF operation used by the XSKMAP resource API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XskMapOperation {
    /// `BPF_MAP_CREATE` for an XSKMAP.
    Create,
    /// `BPF_MAP_UPDATE_ELEM` for a queue-id/socket-fd entry.
    UpdateElem,
    /// Closing the owned map descriptor.
    Close,
}

impl fmt::Display for XskMapOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Create => "XSKMAP creation",
            Self::UpdateElem => "XSKMAP element update",
            Self::Close => "XSKMAP close",
        };
        formatter.write_str(name)
    }
}

/// Typed failure from XSKMAP creation, registration, or teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XskMapError {
    /// `max_entries` must contain at least one queue slot.
    InvalidMaxEntries {
        /// Rejected maximum element count.
        max_entries: u32,
    },
    /// The queue identifier cannot be represented by this map's array range.
    QueueIdOutOfRange {
        /// Rejected hardware queue identifier.
        queue_id: u32,
        /// Number of entries configured in the map.
        max_entries: u32,
    },
    /// The reviewed native bpf syscall profile is unavailable.
    Platform(NativeSyscallPlatformError),
    /// The kernel rejected the operation for lack of `CAP_BPF` or root.
    PermissionDenied {
        /// Operation that was rejected by the privilege boundary.
        operation: XskMapOperation,
    },
    /// The kernel returned an errno other than `EPERM`.
    Syscall {
        /// Operation that failed.
        operation: XskMapOperation,
        /// Bounded Linux errno; `None` means errno capture was invalid.
        errno: Option<u16>,
    },
    /// A syscall returned a descriptor outside the reviewed `RawFd` range.
    InvalidFileDescriptor {
        /// Operation that returned the invalid descriptor.
        operation: XskMapOperation,
    },
    /// A successful-looking bpf call returned an unexpected value.
    UnexpectedReturn {
        /// Operation whose return value was invalid.
        operation: XskMapOperation,
        /// Raw return value observed from `bpf(2)`.
        value: i64,
    },
}

impl XskMapError {
    /// Returns whether the failure is the explicit privilege boundary.
    #[must_use]
    pub const fn is_permission_denied(self) -> bool {
        matches!(self, Self::PermissionDenied { .. })
    }
}

impl fmt::Display for XskMapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMaxEntries { max_entries } => write!(
                formatter,
                "XSKMAP max_entries must be greater than zero (got {max_entries})"
            ),
            Self::QueueIdOutOfRange {
                queue_id,
                max_entries,
            } => write!(
                formatter,
                "XSKMAP queue id {queue_id} is outside max_entries {max_entries}"
            ),
            Self::Platform(error) => {
                write!(formatter, "XSKMAP native platform is unsupported: {error}")
            }
            Self::PermissionDenied { operation } => write!(
                formatter,
                "bpf(2) {operation} was denied: CAP_BPF or root is required"
            ),
            Self::Syscall { operation, errno } => match errno {
                Some(errno) => write!(formatter, "bpf(2) {operation} failed with errno {errno}"),
                None => write!(
                    formatter,
                    "bpf(2) {operation} failed with an invalid errno capture"
                ),
            },
            Self::InvalidFileDescriptor { operation } => {
                write!(
                    formatter,
                    "bpf(2) {operation} returned an invalid file descriptor"
                )
            }
            Self::UnexpectedReturn { operation, value } => {
                write!(
                    formatter,
                    "bpf(2) {operation} returned unexpected value {value}"
                )
            }
        }
    }
}

impl Error for XskMapError {}

/// eBPF operation used by the XDP redirect-program loader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpProgramOperation {
    /// `BPF_PROG_LOAD` for the XDP redirect program.
    Load,
    /// Closing the owned program descriptor.
    Close,
}

impl fmt::Display for XdpProgramOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Load => "XDP program load",
            Self::Close => "XDP program close",
        };
        formatter.write_str(name)
    }
}

/// Typed failure from XDP redirect-program construction, loading, or teardown.
///
/// A failed `BPF_PROG_LOAD` retains the verifier output. This is intentionally
/// an owned string because the kernel writes the log into a temporary user
/// buffer whose lifetime ends when the load syscall returns.
#[derive(Debug, Eq, PartialEq)]
pub enum XdpProgramError {
    /// The reviewed native bpf syscall profile is unavailable.
    Platform(NativeSyscallPlatformError),
    /// The XSKMAP descriptor could not be represented as a valid map fd.
    InvalidMapFileDescriptor {
        /// Rejected map descriptor.
        fd: i32,
    },
    /// The encoded instruction byte extent does not contain the declared
    /// number of eight-byte eBPF instructions.
    InstructionCountMismatch {
        /// Declared number of instructions passed to `BPF_PROG_LOAD`.
        insn_cnt: u32,
        /// Supplied byte extent.
        byte_len: usize,
    },
    /// The kernel rejected the load for lack of the required privilege.
    ///
    /// Loading requires `CAP_BPF` (or root); the separate rtnetlink
    /// interface-attachment operation requires `CAP_NET_ADMIN` (or root).
    /// Both privilege boundaries are kept explicit instead of being silently
    /// skipped.
    PermissionDenied {
        /// Operation rejected by the privilege boundary.
        operation: XdpProgramOperation,
        /// Verifier output captured before returning the error.
        verifier_log: String,
    },
    /// The kernel returned an errno other than `EPERM` while loading or
    /// closing the program.
    Syscall {
        /// Operation that failed.
        operation: XdpProgramOperation,
        /// Bounded Linux errno; `None` means errno capture was invalid.
        errno: Option<u16>,
        /// Verifier output captured during a load attempt, if any.
        verifier_log: String,
    },
    /// A successful-looking load returned a descriptor outside the reviewed
    /// `RawFd` range.
    InvalidFileDescriptor {
        /// Operation that returned the invalid descriptor.
        operation: XdpProgramOperation,
        /// Verifier output captured during the load attempt, if any.
        verifier_log: String,
    },
    /// A successful-looking operation returned an unexpected value.
    UnexpectedReturn {
        /// Operation whose return value was invalid.
        operation: XdpProgramOperation,
        /// Raw return value observed from `bpf(2)`.
        value: i64,
        /// Verifier output captured during the load attempt, if any.
        verifier_log: String,
    },
}

impl XdpProgramError {
    /// Returns whether the failure is the explicit privilege boundary.
    #[must_use]
    pub const fn is_permission_denied(&self) -> bool {
        matches!(self, Self::PermissionDenied { .. })
    }

    /// Returns the verifier log captured for a load attempt.
    #[must_use]
    pub fn verifier_log(&self) -> Option<&str> {
        match self {
            Self::PermissionDenied { verifier_log, .. }
            | Self::Syscall { verifier_log, .. }
            | Self::InvalidFileDescriptor { verifier_log, .. }
            | Self::UnexpectedReturn { verifier_log, .. } => Some(verifier_log),
            Self::Platform(_)
            | Self::InvalidMapFileDescriptor { .. }
            | Self::InstructionCountMismatch { .. } => None,
        }
    }
}

fn write_verifier_log(formatter: &mut fmt::Formatter<'_>, verifier_log: &str) -> fmt::Result {
    if verifier_log.is_empty() {
        formatter.write_str("; verifier log: <empty>")
    } else {
        write!(formatter, "; verifier log: {verifier_log}")
    }
}

impl fmt::Display for XdpProgramError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => {
                write!(
                    formatter,
                    "XDP program native platform is unsupported: {error}"
                )
            }
            Self::InvalidMapFileDescriptor { fd } => {
                write!(
                    formatter,
                    "XDP redirect program received invalid XSKMAP fd {fd}"
                )
            }
            Self::InstructionCountMismatch { insn_cnt, byte_len } => write!(
                formatter,
                "XDP program instruction count {insn_cnt} does not match bytecode length {byte_len}"
            ),
            Self::PermissionDenied {
                operation,
                verifier_log,
            } => {
                write!(
                    formatter,
                    "bpf(2) {operation} was denied: CAP_BPF is required (and CAP_NET_ADMIN for interface attachment), or root"
                )?;
                write_verifier_log(formatter, verifier_log)
            }
            Self::Syscall {
                operation,
                errno,
                verifier_log,
            } => {
                match errno {
                    Some(errno) => {
                        write!(formatter, "bpf(2) {operation} failed with errno {errno}")?
                    }
                    None => formatter
                        .write_str("bpf(2) {operation} failed with an invalid errno capture")?,
                }
                if *operation == XdpProgramOperation::Load {
                    write_verifier_log(formatter, verifier_log)?;
                }
                Ok(())
            }
            Self::InvalidFileDescriptor {
                operation,
                verifier_log,
            } => {
                write!(
                    formatter,
                    "bpf(2) {operation} returned an invalid file descriptor"
                )?;
                if *operation == XdpProgramOperation::Load {
                    write_verifier_log(formatter, verifier_log)?;
                }
                Ok(())
            }
            Self::UnexpectedReturn {
                operation,
                value,
                verifier_log,
            } => {
                write!(
                    formatter,
                    "bpf(2) {operation} returned unexpected value {value}"
                )?;
                if *operation == XdpProgramOperation::Load {
                    write_verifier_log(formatter, verifier_log)?;
                }
                Ok(())
            }
        }
    }
}

impl Error for XdpProgramError {}

/// Operation associated with one XDP netlink attachment transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpAttachOperation {
    /// Creation of the dedicated `AF_NETLINK` socket.
    OpenSocket,
    /// Binding the local netlink port.
    BindSocket,
    /// Reading the kernel-assigned local port ID.
    GetPortId,
    /// Duplicating the loaded program fd for the attachment identity guard.
    DuplicateProgramFd,
    /// Sending an `RTM_SETLINK` request.
    SendMessage,
    /// Receiving the `NLMSG_ERROR` acknowledgement.
    ReceiveMessage,
    /// Attaching the loaded XDP program.
    Attach,
    /// Detaching the XDP program.
    Detach,
    /// Closing the netlink socket.
    CloseSocket,
    /// Closing the attachment-owned expected-program fd.
    CloseExpectedProgramFd,
}

impl fmt::Display for XdpAttachOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::OpenSocket => "netlink socket open",
            Self::BindSocket => "netlink socket bind",
            Self::GetPortId => "netlink port-id query",
            Self::DuplicateProgramFd => "XDP expected-program fd duplicate",
            Self::SendMessage => "netlink request send",
            Self::ReceiveMessage => "netlink response receive",
            Self::Attach => "XDP interface attach",
            Self::Detach => "XDP interface detach",
            Self::CloseSocket => "netlink socket close",
            Self::CloseExpectedProgramFd => "XDP expected-program fd close",
        };
        formatter.write_str(name)
    }
}

/// Invalid or unsafe XDP attach flag policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpAttachConfigError {
    /// The raw word contains a flag outside the supported SKB/DRV profile.
    UnsupportedFlags(u32),
    /// SKB and DRV modes were requested at the same time.
    ConflictingModes,
    /// A raw flag word did not select either supported execution mode.
    MissingMode,
    /// Every attach in this profile must protect an existing program.
    UpdateIfNoExistRequired,
}

impl fmt::Display for XdpAttachConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFlags(flags) => {
                write!(formatter, "unsupported XDP attach flags 0x{flags:08x}")
            }
            Self::ConflictingModes => formatter.write_str("XDP SKB and DRV modes conflict"),
            Self::MissingMode => formatter.write_str("an XDP SKB or DRV mode is required"),
            Self::UpdateIfNoExistRequired => {
                formatter.write_str("XDP attach requires UPDATE_IF_NOEXIST")
            }
        }
    }
}

impl Error for XdpAttachConfigError {}

/// Typed failure from an XDP interface attach/detach netlink transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum XdpAttachError {
    /// The reviewed x86_64 Linux syscall profile is unavailable.
    Platform(NativeSyscallPlatformError),
    /// Interface indices are positive signed Linux `ifinfomsg` values.
    InvalidInterfaceIndex {
        /// Rejected interface index.
        ifindex: u32,
    },
    /// The program descriptor could not be represented as a valid fd.
    InvalidProgramFileDescriptor {
        /// Rejected program descriptor.
        fd: i32,
    },
    /// The netlink socket syscall returned a negative descriptor.
    InvalidSocketFileDescriptor {
        /// Rejected socket descriptor.
        fd: i32,
    },
    /// The caller supplied an unsafe or unsupported flag policy.
    Configuration(XdpAttachConfigError),
    /// The kernel or a socket syscall denied the operation.
    PermissionDenied {
        /// Operation rejected by the privilege boundary.
        operation: XdpAttachOperation,
    },
    /// A native socket syscall returned an errno other than `EPERM`.
    Syscall {
        /// Syscall operation that failed.
        operation: XdpAttachOperation,
        /// Bounded Linux errno; `None` means the capture was outside the
        /// reviewed positive errno range.
        errno: Option<u16>,
    },
    /// The kernel returned a negative errno in `nlmsgerr.error`.
    KernelRejected {
        /// Attach or detach request that was rejected.
        operation: XdpAttachOperation,
        /// Bounded Linux errno; `None` means the netlink value was outside the
        /// reviewed positive errno range.
        errno: Option<u16>,
    },
    /// `sendto(2)` did not consume the complete datagram.
    ShortSend {
        /// Number of request bytes submitted.
        expected: usize,
        /// Number of bytes reported as sent.
        actual: usize,
    },
    /// `recvmsg(2)` reported `MSG_TRUNC`.
    ResponseTruncated,
    /// The received extent was too short for the requested structure.
    ResponseTooShort {
        /// Bytes reported by `recvmsg(2)`.
        actual: usize,
        /// Minimum bytes required at the point of validation.
        minimum: usize,
    },
    /// The received extent did not contain exactly one aligned netlink msg.
    ResponseLengthMismatch {
        /// `nlmsg_len` from the response header.
        declared: usize,
        /// Bytes reported by `recvmsg(2)`.
        actual: usize,
    },
    /// The response was not the required `NLMSG_ERROR` message.
    UnexpectedMessageType {
        /// Message type observed in the response header.
        message_type: u16,
    },
    /// The response did not acknowledge the request sequence.
    UnexpectedSequence {
        /// Sequence submitted in the request.
        expected: u32,
        /// Sequence observed in the response.
        actual: u32,
    },
    /// `nlmsgerr.error` was positive instead of zero or a negative errno.
    InvalidErrorCode {
        /// Invalid raw netlink error value.
        code: i32,
    },
    /// The attach acknowledgement left kernel state unknown and the guarded
    /// rollback also failed. Both failures are retained so a caller can
    /// distinguish the original uncertainty from the cleanup failure.
    StateUnknownRollback {
        /// Original attach/acknowledgement failure.
        original: Box<Self>,
        /// Guarded rollback failure.
        rollback: Box<Self>,
    },
    /// The kernel returned less than a complete `sockaddr_nl`.
    PortIdResponseTooShort {
        /// Bytes reported by `getsockname(2)`.
        actual: usize,
        /// Required bytes for the fields used here.
        minimum: usize,
    },
    /// The kernel reported more address bytes than the checked buffer.
    PortIdResponseTooLong {
        /// Bytes reported by `getsockname(2)`.
        actual: usize,
        /// Supplied address buffer capacity.
        capacity: usize,
    },
    /// The local socket address was not an AF_NETLINK address.
    UnexpectedPortIdFamily {
        /// Family value returned by the kernel.
        family: u16,
    },
}

impl XdpAttachError {
    /// Reports whether this error is the explicit `CAP_NET_ADMIN` boundary.
    #[must_use]
    pub fn is_permission_denied(&self) -> bool {
        matches!(self, Self::PermissionDenied { .. })
    }
}

impl fmt::Display for XdpAttachError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => {
                write!(formatter, "XDP netlink platform is unsupported: {error}")
            }
            Self::InvalidInterfaceIndex { ifindex } => {
                write!(
                    formatter,
                    "XDP netlink received invalid interface index {ifindex}"
                )
            }
            Self::InvalidProgramFileDescriptor { fd } => {
                write!(formatter, "XDP netlink received invalid program fd {fd}")
            }
            Self::InvalidSocketFileDescriptor { fd } => {
                write!(formatter, "netlink socket returned invalid fd {fd}")
            }
            Self::Configuration(error) => {
                write!(formatter, "invalid XDP attach configuration: {error}")
            }
            Self::PermissionDenied { operation } => write!(
                formatter,
                "{operation} was denied: CAP_NET_ADMIN or root is required"
            ),
            Self::Syscall { operation, errno } => match errno {
                Some(errno) => write!(formatter, "{operation} failed with errno {errno}"),
                None => write!(
                    formatter,
                    "{operation} failed with an invalid errno capture"
                ),
            },
            Self::KernelRejected { operation, errno } => match errno {
                Some(errno) => write!(
                    formatter,
                    "{operation} was rejected by the kernel with errno {errno}"
                ),
                None => write!(
                    formatter,
                    "{operation} was rejected by the kernel with an invalid errno"
                ),
            },
            Self::ShortSend { expected, actual } => write!(
                formatter,
                "netlink request send consumed {actual} of {expected} bytes"
            ),
            Self::ResponseTruncated => formatter.write_str("netlink response was truncated"),
            Self::ResponseTooShort { actual, minimum } => write!(
                formatter,
                "netlink response was too short: {actual} bytes, {minimum} required"
            ),
            Self::ResponseLengthMismatch { declared, actual } => write!(
                formatter,
                "netlink response length declared {declared} bytes but received {actual}"
            ),
            Self::UnexpectedMessageType { message_type } => write!(
                formatter,
                "netlink response type {message_type} is not NLMSG_ERROR"
            ),
            Self::UnexpectedSequence { expected, actual } => write!(
                formatter,
                "netlink response sequence {actual} does not match request {expected}"
            ),
            Self::InvalidErrorCode { code } => {
                write!(
                    formatter,
                    "netlink response contained invalid error code {code}"
                )
            }
            Self::StateUnknownRollback { original, rollback } => write!(
                formatter,
                "XDP attach state is unknown; guarded rollback failed (original: {original}; rollback: {rollback})"
            ),
            Self::PortIdResponseTooShort { actual, minimum } => write!(
                formatter,
                "getsockname returned {actual} bytes, {minimum} required"
            ),
            Self::PortIdResponseTooLong { actual, capacity } => write!(
                formatter,
                "getsockname returned {actual} bytes into a {capacity}-byte buffer"
            ),
            Self::UnexpectedPortIdFamily { family } => {
                write!(formatter, "getsockname returned unexpected family {family}")
            }
        }
    }
}

impl Error for XdpAttachError {}

/// Failure while validating kernel-reported ring mapping offsets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbiLayoutError {
    /// A field offset does not meet its C ABI alignment.
    MisalignedOffset {
        /// Misaligned field.
        field: RingField,
        /// Kernel-reported offset.
        offset: u64,
        /// Required alignment.
        alignment: usize,
    },
    /// A field extent overflowed `u64`.
    ExtentOverflow {
        /// Field whose extent overflowed.
        field: RingField,
    },
    /// The mapping extent cannot be represented by this process.
    ExtentDoesNotFitUsize,
    /// Two independently accessed mapping fields overlap.
    OverlappingFields {
        /// First overlapping field.
        first: RingField,
        /// Second overlapping field.
        second: RingField,
    },
}

impl fmt::Display for AbiLayoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for AbiLayoutError {}

/// Failure while binding a checked ring layout to caller-owned mapped bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingMapError {
    /// The kernel-reported layout was invalid.
    Layout(AbiLayoutError),
    /// The borrowed mapping does not cover every checked field.
    MappingTooShort {
        /// Minimum byte length computed from the checked layout.
        required: usize,
        /// Actual borrowed byte length.
        actual: usize,
    },
    /// The owned mmap was already made inactive before a ring view was built.
    MappingInactive,
    /// The OS mapping returned a null address for a nonempty ring extent.
    MappingAddressIsNull,
    /// Adding the ring mapping length to its process address overflowed.
    MappingAddressRangeOverflow {
        /// Process address returned by the mapping operation.
        address: usize,
        /// Mapping byte length.
        length: usize,
    },
    /// A field address is misaligned even though its relative offset is aligned.
    MisalignedFieldAddress {
        /// Misaligned field.
        field: RingField,
        /// Required alignment.
        alignment: usize,
    },
    /// Adding a checked field offset to the mapping base address overflowed.
    FieldAddressOverflow {
        /// Field whose process address overflowed.
        field: RingField,
    },
}

impl From<AbiLayoutError> for RingMapError {
    fn from(value: AbiLayoutError) -> Self {
        Self::Layout(value)
    }
}

impl fmt::Display for RingMapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RingMapError {}

/// Native SPSC ring operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeRingError {
    /// A reservation or acquisition must contain at least one entry.
    ZeroLength,
    /// The requested range exceeds the configured ring capacity.
    LengthExceedsCapacity,
    /// The producer has insufficient free entries.
    RingFull,
    /// The consumer has insufficient published entries.
    RingEmpty,
    /// Published cursor distance exceeds the configured capacity.
    CorruptCursor {
        /// Producer cursor observed from shared memory.
        producer: u32,
        /// Consumer cursor observed from shared memory.
        consumer: u32,
        /// Checked ring capacity.
        capacity: u32,
    },
    /// The reservation was submitted before every descriptor was written.
    IncompleteReservation {
        /// Reserved entry count.
        reserved: u32,
        /// Entries written before submission.
        written: u32,
    },
    /// The acquisition was consumed before every descriptor was read.
    IncompleteAcquisition {
        /// Acquired entry count.
        acquired: u32,
        /// Entries read before consumption.
        read: u32,
    },
    /// The caller attempted to write or read beyond its fixed range.
    RangeExhausted,
    /// The kernel exposed ring flag bits outside the reviewed v6.8 profile.
    UnsupportedRingFlags(u32),
}

impl fmt::Display for NativeRingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for NativeRingError {}

/// Native platform support failure detected before any syscall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformError {
    /// AF_XDP native access is available only on Linux.
    UnsupportedOperatingSystem,
    /// The first reviewed ABI profile supports only 64-bit processes.
    UnsupportedPointerWidth,
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PlatformError {}

/// Narrow platform failure for the architecture-dependent native syscall seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSyscallPlatformError {
    /// Native syscalls are available only on Linux.
    UnsupportedOperatingSystem,
    /// The reviewed syscall ABI uses 64-bit pointer-sized C types.
    UnsupportedPointerWidth,
    /// Numeric syscall flags are audited only for x86_64.
    UnsupportedArchitecture,
}

impl fmt::Display for NativeSyscallPlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for NativeSyscallPlatformError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_contracts_keep_error_identity_and_payloads() {
        // Protects the formatter mutants for every error type in this file:
        // diagnostics must not collapse to an empty/default result.
        assert!(ConfigError::InvalidFrameSize(2048)
            .to_string()
            .contains("InvalidFrameSize"));
        assert!(XdpSetupError::InvalidInterfaceIndex { ifindex: 7 }
            .to_string()
            .contains("InvalidInterfaceIndex"));
        assert!(XdpIoError::Wakeup { errno: Some(11) }
            .to_string()
            .contains("Wakeup"));
        assert!(XdpResourcePairError::DuplicateIfindex { ifindex: 7 }
            .to_string()
            .contains("DuplicateIfindex"));
        assert!(XdpPairIoError::EgressNotFound { egress: IfId(7) }
            .to_string()
            .contains("EgressNotFound"));
        assert_eq!(
            XskMapOperation::UpdateElem.to_string(),
            "XSKMAP element update"
        );
        assert_eq!(XdpProgramOperation::Close.to_string(), "XDP program close");
        assert_eq!(
            XdpAttachOperation::Detach.to_string(),
            "XDP interface detach"
        );
        assert!(XdpAttachConfigError::UnsupportedFlags(0x12)
            .to_string()
            .contains("0x00000012"));
        assert!(XdpAttachError::InvalidInterfaceIndex { ifindex: 7 }
            .to_string()
            .contains("7"));
        assert!(AbiLayoutError::ExtentDoesNotFitUsize
            .to_string()
            .contains("ExtentDoesNotFitUsize"));
        assert!(RingMapError::MappingInactive
            .to_string()
            .contains("MappingInactive"));
        assert!(NativeRingError::UnsupportedRingFlags(2)
            .to_string()
            .contains("UnsupportedRingFlags"));
        assert!(PlatformError::UnsupportedPointerWidth
            .to_string()
            .contains("UnsupportedPointerWidth"));
        assert!(NativeSyscallPlatformError::UnsupportedArchitecture
            .to_string()
            .contains("UnsupportedArchitecture"));
    }

    #[test]
    fn permission_helpers_reject_non_permission_failures() {
        // Protects each permission predicate's false branch; a constant true
        // replacement would incorrectly classify ordinary syscall failures.
        assert!(!XskMapError::Syscall {
            operation: XskMapOperation::UpdateElem,
            errno: Some(5),
        }
        .is_permission_denied());
        assert!(!XdpProgramError::Syscall {
            operation: XdpProgramOperation::Load,
            errno: Some(5),
            verifier_log: String::new(),
        }
        .is_permission_denied());
        assert!(!XdpAttachError::Syscall {
            operation: XdpAttachOperation::Attach,
            errno: Some(5),
        }
        .is_permission_denied());
    }

    #[test]
    fn program_error_display_only_includes_verifier_log_for_load() {
        // Protects the three `operation == Load` display branches: verifier
        // output belongs to load diagnostics, not close diagnostics.
        let load_log = "load verifier detail";
        let close_log = "close should be omitted";
        let load_errors = [
            XdpProgramError::Syscall {
                operation: XdpProgramOperation::Load,
                errno: Some(5),
                verifier_log: load_log.to_owned(),
            },
            XdpProgramError::InvalidFileDescriptor {
                operation: XdpProgramOperation::Load,
                verifier_log: load_log.to_owned(),
            },
            XdpProgramError::UnexpectedReturn {
                operation: XdpProgramOperation::Load,
                value: -1,
                verifier_log: load_log.to_owned(),
            },
        ];
        let close_errors = [
            XdpProgramError::Syscall {
                operation: XdpProgramOperation::Close,
                errno: Some(5),
                verifier_log: close_log.to_owned(),
            },
            XdpProgramError::InvalidFileDescriptor {
                operation: XdpProgramOperation::Close,
                verifier_log: close_log.to_owned(),
            },
            XdpProgramError::UnexpectedReturn {
                operation: XdpProgramOperation::Close,
                value: -1,
                verifier_log: close_log.to_owned(),
            },
        ];
        for error in load_errors {
            assert!(error.to_string().contains(load_log));
        }
        for error in close_errors {
            assert!(!error.to_string().contains(close_log));
        }
    }
}
