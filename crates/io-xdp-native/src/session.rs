//! Safe parameters, outcomes, and typed failures of one native AF_XDP session.
//!
//! The failure-atomic builder itself lives in the private `native_unsafe`
//! module and is exposed as [`crate::NativeSession`] on x86_64 Linux only.
//! Every type here is plain data: no file descriptor, address, or packet byte
//! is stored or rendered.

use std::{error::Error, fmt};

use crate::{
    BindMode, NativeSyscallPlatformError, RingConfig, RingField, RingMapError, RingName,
    UmemConfig, ValidatedBindFlags,
};

/// Linux `IFNAMSIZ`: interface name bytes plus the terminating NUL.
pub const INTERFACE_NAME_CAPACITY: usize = 16;

/// Largest accepted queue id.
///
/// `sockaddr_xdp.sxdp_queue_id` is a `u32`, but Linux v6.8 `xsk_bind`
/// passes it to `xp_assign_dev` as a `u16`, so a larger id would silently
/// bind queue `id & 0xffff`. The configuration layer applies a stricter cap
/// (1023); this bound is the kernel truncation boundary.
pub const MAX_QUEUE_ID: u32 = u16::MAX as u32;

/// Largest kernel-reported ring header offset accepted from
/// `XDP_MMAP_OFFSETS` (one x86_64 page).
///
/// Linux v6.8 places the producer, consumer, and flags words on separate
/// cache lines of `struct xdp_ring` and the descriptor array immediately
/// after it, all well inside the first page. Larger offsets are rejected
/// before any ring is mapped.
pub const MAX_RING_HEADER_OFFSET: u64 = 4_096;

/// Checked parameters of one AF_XDP socket bound to one interface queue.
///
/// Callers derive the values from a validated configuration port (for
/// example `ruster_config::ValidatedAfXdpPortV1::{device, queue, bind_flags,
/// rings, umem}`); this crate does not depend on the configuration crate.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SessionConfig {
    name: [u8; INTERFACE_NAME_CAPACITY],
    queue: u32,
    bind_flags: ValidatedBindFlags,
    rings: RingConfig,
    umem: UmemConfig,
}

impl SessionConfig {
    /// Validates the device name against Linux `dev_valid_name` and the
    /// initial session profile.
    ///
    /// The name must be 1..=15 bytes of printable ASCII other than `/` and
    /// `:`, and must not be `.` or `..`. The queue id must not exceed
    /// [`MAX_QUEUE_ID`]. Shared UMEM is rejected: each session registers and
    /// owns exactly one UMEM.
    pub fn new(
        device: &str,
        queue: u32,
        bind_flags: ValidatedBindFlags,
        rings: RingConfig,
        umem: UmemConfig,
    ) -> Result<Self, SessionConfigError> {
        let bytes = device.as_bytes();
        if bytes.is_empty() {
            return Err(SessionConfigError::DeviceNameEmpty);
        }
        if bytes.len() >= INTERFACE_NAME_CAPACITY {
            return Err(SessionConfigError::DeviceNameTooLong { len: bytes.len() });
        }
        if device == "."
            || device == ".."
            || bytes
                .iter()
                .any(|byte| !byte.is_ascii_graphic() || *byte == b'/' || *byte == b':')
        {
            return Err(SessionConfigError::DeviceNameInvalid);
        }
        if queue > MAX_QUEUE_ID {
            return Err(SessionConfigError::QueueOutOfRange { queue });
        }
        if bind_flags.shared_umem() {
            return Err(SessionConfigError::SharedUmemUnsupported);
        }
        let mut name = [0_u8; INTERFACE_NAME_CAPACITY];
        name[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            name,
            queue,
            bind_flags,
            rings,
            umem,
        })
    }

    /// Returns the NUL-padded interface name.
    #[must_use]
    pub const fn interface_name_bytes(&self) -> &[u8; INTERFACE_NAME_CAPACITY] {
        &self.name
    }

    /// Returns the device queue id.
    #[must_use]
    pub const fn queue(&self) -> u32 {
        self.queue
    }

    /// Returns the checked bind flags.
    #[must_use]
    pub const fn bind_flags(&self) -> ValidatedBindFlags {
        self.bind_flags
    }

    /// Returns the four ring capacities.
    #[must_use]
    pub const fn rings(&self) -> RingConfig {
        self.rings
    }

    /// Returns the UMEM geometry.
    #[must_use]
    pub const fn umem(&self) -> UmemConfig {
        self.umem
    }

    /// Returns the requested copy policy.
    #[must_use]
    pub const fn mode(&self) -> BindMode {
        self.bind_flags.mode()
    }
}

impl fmt::Debug for SessionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self
            .name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.name.len());
        // The name is printable ASCII by construction.
        let device = std::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>");
        formatter
            .debug_struct("SessionConfig")
            .field("device", &device)
            .field("queue", &self.queue)
            .field("bind_flags", &self.bind_flags)
            .field("rings", &self.rings)
            .field("umem", &self.umem)
            .finish()
    }
}

/// Session parameter failure detected before any syscall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionConfigError {
    /// The device name is empty.
    DeviceNameEmpty,
    /// The device name does not fit `IFNAMSIZ` with its NUL.
    DeviceNameTooLong {
        /// Byte length of the rejected name.
        len: usize,
    },
    /// The device name is `.`/`..` or contains a non-printable, `/`, or `:` byte.
    DeviceNameInvalid,
    /// `XDP_SHARED_UMEM` is outside the initial session profile.
    SharedUmemUnsupported,
    /// The queue id exceeds [`MAX_QUEUE_ID`].
    QueueOutOfRange {
        /// Rejected queue id.
        queue: u32,
    },
}

impl fmt::Display for SessionConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for SessionConfigError {}

/// Copy policy that the kernel reported through `XDP_OPTIONS` after bind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegotiatedMode {
    /// The socket copies frames between the driver and UMEM.
    Copy,
    /// The driver DMAs directly into UMEM.
    ZeroCopy,
}

/// Ordered setup step of one session transaction.
///
/// Steps run in declaration order; a failure at one step releases every
/// resource acquired by the earlier steps in exact reverse order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStage {
    /// `if_nametoindex` in the caller's network namespace.
    InterfaceLookup,
    /// The bound queue must have a TX queue: Linux v6.8 `xsk_bind` only
    /// requires `queue < max(real_num_rx_queues, real_num_tx_queues)`, but
    /// copy-mode `__xsk_generic_xmit` silently transmits nothing on a queue
    /// at or above `real_num_tx_queues`. Checked through sysfs
    /// (`/sys/class/net/<dev>/queues/tx-<queue>`) after proving that the
    /// sysfs view's `ifindex` is the resolved device.
    TxQueueCheck,
    /// The device MTU (`/sys/class/net/<dev>/mtu`, through the same proven
    /// sysfs view as [`Self::TxQueueCheck`]), which bounds TX length.
    MtuProbe,
    /// `socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)`.
    OpenSocket,
    /// Anonymous page-aligned UMEM `mmap`.
    MapUmem,
    /// `XDP_UMEM_REG`.
    RegisterUmem,
    /// `XDP_UMEM_FILL_RING` size.
    SizeFillRing,
    /// `XDP_UMEM_COMPLETION_RING` size.
    SizeCompletionRing,
    /// `XDP_RX_RING` size.
    SizeRxRing,
    /// `XDP_TX_RING` size.
    SizeTxRing,
    /// `XDP_MMAP_OFFSETS` query and validation.
    QueryMmapOffsets,
    /// Fill ring `mmap`.
    MapFillRing,
    /// Completion ring `mmap`.
    MapCompletionRing,
    /// RX ring `mmap`.
    MapRxRing,
    /// TX ring `mmap`.
    MapTxRing,
    /// `bind` with `sockaddr_xdp`.
    Bind,
    /// `XDP_OPTIONS` query and negotiated-mode check.
    QueryOptions,
}

/// Value-free cause of one failed session step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionFailure {
    /// The target cannot run the reviewed x86_64 Linux syscall profile.
    Platform(NativeSyscallPlatformError),
    /// `EPERM` or `EACCES`: typically missing `CAP_NET_RAW` (socket) or
    /// `CAP_NET_ADMIN`/`CAP_IPC_LOCK`-related policy.
    PermissionDenied,
    /// `ENOMEM`.
    OutOfMemory,
    /// `ENOBUFS` from `XDP_UMEM_REG`: the UMEM exceeds `RLIMIT_MEMLOCK`
    /// without `CAP_IPC_LOCK`. It can be transient: Linux releases a closed
    /// session's UMEM accounting from deferred work.
    MemlockLimit,
    /// `ENODEV`: no such interface in this network namespace.
    NoSuchDevice,
    /// `EINVAL`. At [`SessionStage::Bind`] this most commonly means the
    /// queue id is not below the device's real RX and TX queue counts.
    InvalidArgument,
    /// `EBUSY`: the queue already has an AF_XDP pool or the socket state
    /// changed.
    Busy,
    /// `EOPNOTSUPP` outside a zero-copy bind, or `EAFNOSUPPORT` from
    /// `socket` (kernel without `CONFIG_XDP_SOCKETS`).
    Unsupported,
    /// `EOPNOTSUPP` from a bind that requested `XDP_ZEROCOPY`: the device
    /// does not advertise the complete `NETDEV_XDP_ACT_ZC` feature set, or
    /// its driver's `XDP_SETUP_XSK_POOL` returned `EOPNOTSUPP`. `auto` mode
    /// falls back to copy mode on exactly this failure.
    ZeroCopyUnsupported,
    /// Any other errno, kept numerically.
    Errno(u16),
    /// The thread errno was outside the Linux errno range.
    UnreadableErrno,
    /// A checked size or argument could not be represented for the syscall.
    ArgumentOutOfRange,
    /// The kernel returned a socket-option length other than the pinned
    /// v6.8 structure size.
    OptionLength {
        /// Pinned structure size.
        expected: usize,
        /// Kernel-reported length.
        actual: usize,
    },
    /// A kernel-reported ring layout failed alignment, extent, or overlap checks.
    RingLayout {
        /// Ring whose layout was rejected.
        ring: RingName,
        /// Layout or mapping failure.
        error: RingMapError,
    },
    /// A kernel-reported ring field offset exceeded [`MAX_RING_HEADER_OFFSET`].
    RingHeaderOutOfBounds {
        /// Ring whose layout was rejected.
        ring: RingName,
        /// Offending field.
        field: RingField,
    },
    /// A mapping address was zero or not page aligned.
    MisalignedMapping,
    /// `XDP_OPTIONS` reported bits outside the v6.8 profile. Unknown bits
    /// fail closed on purpose: a newer kernel option could change the
    /// socket's contract in ways this profile has not reviewed.
    UnsupportedOptions(u32),
    /// The bound queue has no TX queue on the device (queue id at or above
    /// its real TX queue count, for example RX 4 / TX 2 bound at queue 2,
    /// or after `ethtool -L`). Binding would succeed and TX would stall
    /// silently, so the session is refused.
    NoTxQueue,
    /// The TX queue count could not be verified: sysfs is not mounted for
    /// this network namespace, the device's sysfs `ifindex` differs from
    /// the resolved one (a stale sysfs view after `setns`, or a rename
    /// race), or sysfs could not be read. Fails closed.
    TxQueueUnverifiable,
    /// The device MTU could not be read from the proven sysfs view (or was
    /// zero). Fails closed: without it TX length cannot be bounded.
    MtuUnverifiable,
    /// The negotiated mode differs from the explicitly bound copy policy.
    NegotiatedModeMismatch {
        /// Mode reported by the kernel.
        negotiated: NegotiatedMode,
    },
}

/// Typed, value-free failure of [`crate::NativeSession`] setup.
///
/// Every resource acquired before the failing stage was already released in
/// exact reverse order when this value is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionError {
    stage: SessionStage,
    failure: SessionFailure,
}

impl SessionError {
    pub(crate) const fn new(stage: SessionStage, failure: SessionFailure) -> Self {
        Self { stage, failure }
    }

    /// Returns the failing setup stage.
    #[must_use]
    pub const fn stage(self) -> SessionStage {
        self.stage
    }

    /// Returns the classified cause.
    #[must_use]
    pub const fn failure(self) -> SessionFailure {
        self.failure
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for SessionError {}

/// How the XSK redirect program is attached to the session's interface.
///
/// Configuration maps `ruster_config::XdpAttachModeV1::{Native, Generic}`
/// onto these variants one to one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpAttachMode {
    /// Driver XDP, `XDP_FLAGS_DRV_MODE`.
    Native,
    /// Generic (skb) XDP, `XDP_FLAGS_SKB_MODE`. Requires a copy-mode session.
    Generic,
}

/// Ordered step of one XDP attach transaction.
///
/// A failure at one step releases every object created by the earlier steps
/// in exact reverse order (after a failed link, the socket's map entry is
/// deleted first). Only [`AttachStage::CreateLink`] changes the interface,
/// and it is the commit point: the kernel either installs the link or
/// rejects it under RTNL. In native mode a driver whose `ndo_bpf` fails
/// part-way may briefly reset its link (carrier) before returning the
/// error; no XDP program is left attached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachStage {
    /// Checks before any syscall: not already attached, mode compatible.
    Precondition,
    /// `BPF_MAP_CREATE` of a `BPF_MAP_TYPE_XSKMAP` with `queue + 1` slots.
    CreateMap,
    /// `BPF_PROG_LOAD` of the `BPF_PROG_TYPE_XDP` redirect program.
    LoadProgram,
    /// `BPF_MAP_UPDATE_ELEM` storing the session socket at the queue index.
    InsertSocket,
    /// `BPF_LINK_CREATE` with `BPF_XDP` on the session's ifindex.
    CreateLink,
}

/// Value-free cause of one failed attach step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachFailure {
    /// The target cannot run the reviewed x86_64 Linux syscall profile.
    Platform(NativeSyscallPlatformError),
    /// The session already owns an attached program.
    AlreadyAttached,
    /// Generic XDP was requested for a zero-copy session.
    GenericRequiresCopyMode,
    /// `EBUSY` or `EEXIST` from `BPF_LINK_CREATE`: another XDP program or
    /// link is attached to the interface in the requested mode or in the
    /// other of native/generic mode, or (Linux 5.15+) to an upper device.
    /// The existing program is never replaced or detached. A
    /// hardware-offloaded program (`XDP_FLAGS_HW_MODE`) can coexist with a
    /// native or generic one and is not reported.
    ExistingProgram,
    /// `EOPNOTSUPP` from a native `BPF_LINK_CREATE`: the driver has no
    /// native XDP support. A bond master whose slave already runs its own
    /// XDP program also reports this.
    NativeXdpUnsupported,
    /// `EPERM`, or `EACCES` outside program load: typically missing
    /// `CAP_NET_ADMIN` (XSKMAP, link) or `CAP_BPF`/`CAP_SYS_ADMIN` (load). On
    /// Linux before 5.11 a map or program over `RLIMIT_MEMLOCK` also
    /// reports `EPERM`.
    PermissionDenied,
    /// `EACCES` from `BPF_PROG_LOAD` with a nonempty verifier log: the
    /// verifier rejected the program. `EACCES` with an empty log is an
    /// earlier denial (an LSM hook) and reports [`Self::PermissionDenied`].
    /// The verifier can also reject with `EINVAL` or `E2BIG`.
    VerifierRejected,
    /// `EINVAL`. At [`AttachStage::CreateLink`] this includes an ifindex
    /// that no longer exists in the caller's network namespace (Linux
    /// `bpf_xdp_link_attach` reports a vanished device as `EINVAL`, not
    /// `ENODEV`).
    InvalidArgument,
    /// `E2BIG`: at [`AttachStage::InsertSocket`] the queue index is not
    /// below the map size; at load, a `bpf_attr` tail the kernel does not
    /// know or a verifier complexity limit.
    TooBig,
    /// `ENOSPC`: at load, the bounded verifier log was truncated; at link
    /// creation, a driver resource limit (veth: fewer RX queues than the
    /// peer's TX queues).
    NoSpace,
    /// `ENOMEM`.
    OutOfMemory,
    /// `EOPNOTSUPP` elsewhere.
    Unsupported,
    /// Any other errno, kept numerically.
    Errno(u16),
    /// The thread errno, or a returned fd, was outside the Linux range.
    UnreadableErrno,
    /// A checked argument could not be represented for the syscall.
    ArgumentOutOfRange,
}

/// Bounded summary of the kernel-written verifier log of one load.
///
/// The log bytes themselves are untrusted kernel output and are never
/// stored in or rendered by an error; only these counts are.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VerifierLogSummary {
    bytes: u32,
    truncated: bool,
}

impl VerifierLogSummary {
    pub(crate) const fn new(bytes: u32, truncated: bool) -> Self {
        Self { bytes, truncated }
    }

    /// Log bytes before the first NUL, at most the buffer capacity.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.bytes
    }

    /// Whether the kernel reported truncation (`ENOSPC`) or wrote no NUL.
    #[must_use]
    pub const fn truncated(self) -> bool {
        self.truncated
    }
}

/// Typed, value-free failure of [`crate::NativeSession::attach_xdp`].
///
/// Every BPF object created before the failing step was already closed in
/// exact reverse order, and the session itself is unchanged and usable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachError {
    stage: AttachStage,
    failure: AttachFailure,
    verifier_log: Option<VerifierLogSummary>,
}

impl AttachError {
    pub(crate) const fn new(
        stage: AttachStage,
        failure: AttachFailure,
        verifier_log: Option<VerifierLogSummary>,
    ) -> Self {
        Self {
            stage,
            failure,
            verifier_log,
        }
    }

    /// Returns the failing attach step.
    #[must_use]
    pub const fn stage(self) -> AttachStage {
        self.stage
    }

    /// Returns the classified cause.
    #[must_use]
    pub const fn failure(self) -> AttachFailure {
        self.failure
    }

    /// Returns the verifier log summary of a failed program load
    /// ([`AttachStage::LoadProgram`] only).
    #[must_use]
    pub const fn verifier_log(self) -> Option<VerifierLogSummary> {
        self.verifier_log
    }
}

impl fmt::Display for AttachError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for AttachError {}

/// Resource released by explicit session teardown, in teardown order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupStage {
    /// XDP link `close`: detaches the program (attached sessions only).
    CloseXdpLink,
    /// `BPF_MAP_DELETE_ELEM` of the socket's XSKMAP entry, which otherwise
    /// keeps the map alive until the socket closes.
    RemoveXskMapEntry,
    /// XDP program fd `close`.
    CloseXdpProgram,
    /// XSKMAP fd `close`.
    CloseXskMap,
    /// TX ring `munmap`.
    UnmapTxRing,
    /// RX ring `munmap`.
    UnmapRxRing,
    /// Completion ring `munmap`.
    UnmapCompletionRing,
    /// Fill ring `munmap`.
    UnmapFillRing,
    /// UMEM `munmap`.
    UnmapUmem,
    /// Socket `close`.
    CloseSocket,
}

/// First failure of an explicit teardown. Every later resource was still
/// released exactly once; failed releases are never retried.
///
/// A failed ring `munmap` can leave the mapping in place; its vma keeps a
/// reference to the socket, so the kernel socket (and its queue binding)
/// then lives until the process exits even though the fd is closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupError {
    stage: CleanupStage,
    errno: Option<u16>,
}

impl CleanupError {
    pub(crate) const fn new(stage: CleanupStage, errno: Option<u16>) -> Self {
        Self { stage, errno }
    }

    /// Returns the first failing release.
    #[must_use]
    pub const fn stage(self) -> CleanupStage {
        self.stage
    }

    /// Returns its errno, or `None` if the thread errno was unreadable.
    #[must_use]
    pub const fn errno(self) -> Option<u16> {
        self.errno
    }
}

impl fmt::Display for CleanupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for CleanupError {}

/// Geometry of the session-owned UMEM, borrowed with the ring views.
///
/// Byte access to frames is deliberately absent: it arrives with the frame
/// ownership ledger integration (X01–X03), which decides who may touch which
/// frame while the kernel owns others.
#[derive(Debug)]
pub struct UmemRegion<'session> {
    config: UmemConfig,
    _session: std::marker::PhantomData<&'session mut ()>,
}

impl UmemRegion<'_> {
    pub(crate) const fn new(config: UmemConfig) -> Self {
        Self {
            config,
            _session: std::marker::PhantomData,
        }
    }

    /// Returns the registered UMEM geometry.
    #[must_use]
    pub const fn config(&self) -> UmemConfig {
        self.config
    }

    /// Returns the registered UMEM byte length.
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.config.byte_len()
    }
}

/// The four role-typed ring views and UMEM geometry of one live session.
///
/// Every view exclusively borrows its kernel mapping through the session, so
/// none can outlive the mapping or coexist with a second set of views.
pub struct NativeRings<'session> {
    /// Application producer of the UMEM Fill ring.
    pub fill: crate::FillProducer<'session>,
    /// Application consumer of the UMEM Completion ring.
    pub completion: crate::CompletionConsumer<'session>,
    /// Application consumer of the RX ring.
    pub rx: crate::RxConsumer<'session>,
    /// Application producer of the TX ring.
    pub tx: crate::TxProducer<'session>,
    /// UMEM geometry.
    pub umem: UmemRegion<'session>,
}
