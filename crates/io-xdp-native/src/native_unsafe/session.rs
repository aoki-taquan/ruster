//! Failure-atomic native AF_XDP session transaction (X00C).
//!
//! One transaction turns a checked [`SessionConfig`] into one bound socket
//! with a registered UMEM and four mapped rings, through the sealed syscall
//! seam only. This module contains no `unsafe`: FFI stays in `syscall.rs`
//! and memory access stays in `ring_mem.rs`.
//!
//! Each acquired resource is a RAII local declared in acquisition order, so
//! an early return releases exactly the acquired resources in exact reverse
//! order, each once. [`SessionCore`] declares its owners in reverse
//! acquisition order, so dropping a live session releases the four ring
//! mappings (TX, RX, Completion, Fill), then the UMEM, then the socket.

use std::{marker::PhantomData, mem::size_of};

use crate::{
    abi::{
        RingElement, RingMmapLayout, SockAddrXdp, XdpMmapOffsets, XdpOptions, XdpRingOffset,
        XdpUmemReg, AF_XDP, SOL_XDP, XDP_COPY, XDP_MMAP_OFFSETS, XDP_OPTIONS, XDP_OPTIONS_ZEROCOPY,
        XDP_PGOFF_RX_RING, XDP_PGOFF_TX_RING, XDP_RX_RING, XDP_TX_RING, XDP_UMEM_COMPLETION_RING,
        XDP_UMEM_FILL_RING, XDP_UMEM_PGOFF_COMPLETION_RING, XDP_UMEM_PGOFF_FILL_RING, XDP_UMEM_REG,
        XDP_ZEROCOPY,
    },
    session::{
        CleanupError, CleanupStage, NativeRings, NegotiatedMode, SessionConfig, SessionError,
        SessionFailure, SessionStage, UmemRegion, MAX_RING_HEADER_OFFSET,
    },
    BindMode, CompletionConsumer, FillProducer, RingConfig, RingEntries, RingField, RingMapError,
    RingName, RxConsumer, TxProducer, UmemConfig,
};

use super::syscall::{
    errno, interface_index, Errno, LinuxSyscalls, MappedRegion, MapsRealMemory, OwnedXdpFd,
    ResourceError, SyscallError, IFNAMSIZ, PAGE_SIZE,
};

const _: [(); IFNAMSIZ] = [(); crate::session::INTERFACE_NAME_CAPACITY];
const UMEM_REG_LEN: usize = size_of::<XdpUmemReg>();
const MMAP_OFFSETS_LEN: usize = size_of::<XdpMmapOffsets>();
const OPTIONS_LEN: usize = size_of::<XdpOptions>();
const SOCKADDR_LEN: usize = size_of::<SockAddrXdp>();
const _: [(); 32] = [(); UMEM_REG_LEN];
const _: [(); 128] = [(); MMAP_OFFSETS_LEN];
const _: [(); 4] = [(); OPTIONS_LEN];
const _: [(); 16] = [(); SOCKADDR_LEN];

/// Classifies one seam failure at one stage. `zero_copy_bind` is true only
/// for a bind whose flags request `XDP_ZEROCOPY`.
pub(super) fn classify(
    stage: SessionStage,
    error: ResourceError,
    zero_copy_bind: bool,
) -> SessionError {
    let failure = match error {
        ResourceError::Platform(platform) => SessionFailure::Platform(platform),
        ResourceError::Argument(_) => SessionFailure::ArgumentOutOfRange,
        ResourceError::Syscall(SyscallError {
            errno: Errno::ArgumentRejected,
            ..
        }) => SessionFailure::ArgumentOutOfRange,
        ResourceError::Syscall(syscall) => match syscall.errno.raw() {
            None => SessionFailure::UnreadableErrno,
            Some(errno::EPERM | errno::EACCES) => SessionFailure::PermissionDenied,
            Some(errno::ENOMEM) => SessionFailure::OutOfMemory,
            Some(errno::ENOBUFS) if stage == SessionStage::RegisterUmem => {
                SessionFailure::MemlockLimit
            }
            Some(errno::ENODEV) => SessionFailure::NoSuchDevice,
            Some(errno::EINVAL) => SessionFailure::InvalidArgument,
            Some(errno::EBUSY) => SessionFailure::Busy,
            Some(errno::EOPNOTSUPP) if stage == SessionStage::Bind && zero_copy_bind => {
                SessionFailure::ZeroCopyUnsupported
            }
            Some(errno::EOPNOTSUPP | errno::EAFNOSUPPORT) => SessionFailure::Unsupported,
            Some(other) => SessionFailure::Errno(other),
        },
    };
    SessionError::new(stage, failure)
}

fn at(stage: SessionStage) -> impl FnOnce(ResourceError) -> SessionError {
    move |error| classify(stage, error, false)
}

const fn fail(stage: SessionStage, failure: SessionFailure) -> SessionError {
    SessionError::new(stage, failure)
}

fn encode_umem_reg(address: u64, umem: UmemConfig) -> [u8; UMEM_REG_LEN] {
    let mut bytes = [0_u8; UMEM_REG_LEN];
    bytes[0..8].copy_from_slice(&address.to_ne_bytes());
    bytes[8..16].copy_from_slice(&umem.byte_len().to_ne_bytes());
    bytes[16..20].copy_from_slice(&umem.frame_size().to_ne_bytes());
    // User headroom only; the kernel adds XDP_PACKET_HEADROOM itself.
    bytes[20..24].copy_from_slice(&umem.headroom().to_ne_bytes());
    // flags = 0 (aligned chunks, no software checksum) and
    // tx_metadata_len = 0 stay zero.
    bytes
}

fn encode_sockaddr(flags: u16, ifindex: u32, queue: u32) -> [u8; SOCKADDR_LEN] {
    let mut bytes = [0_u8; SOCKADDR_LEN];
    let family = u16::try_from(AF_XDP).expect("AF_XDP fits sa_family_t");
    bytes[0..2].copy_from_slice(&family.to_ne_bytes());
    bytes[2..4].copy_from_slice(&flags.to_ne_bytes());
    bytes[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    bytes[8..12].copy_from_slice(&queue.to_ne_bytes());
    // shared_umem_fd = 0: the initial profile never shares UMEM.
    bytes
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("eight-byte field inside a fixed buffer"),
    )
}

fn decode_ring_offset(bytes: &[u8], base: usize) -> XdpRingOffset {
    XdpRingOffset {
        producer: read_u64(bytes, base),
        consumer: read_u64(bytes, base + 8),
        descriptors: read_u64(bytes, base + 16),
        flags: read_u64(bytes, base + 24),
    }
}

fn decode_mmap_offsets(bytes: &[u8; MMAP_OFFSETS_LEN]) -> XdpMmapOffsets {
    XdpMmapOffsets {
        rx: decode_ring_offset(bytes, 0),
        tx: decode_ring_offset(bytes, 32),
        fill: decode_ring_offset(bytes, 64),
        completion: decode_ring_offset(bytes, 96),
    }
}

/// One ring's kernel offsets and checked minimum mapping length.
#[derive(Clone, Copy)]
struct RingPlan {
    raw: XdpRingOffset,
    entries: RingEntries,
    byte_len: usize,
}

fn plan_ring(
    ring: RingName,
    raw: XdpRingOffset,
    entries: RingEntries,
    element: RingElement,
) -> Result<RingPlan, SessionError> {
    let stage = SessionStage::QueryMmapOffsets;
    for (field, offset) in [
        (RingField::Producer, raw.producer),
        (RingField::Consumer, raw.consumer),
        (RingField::Flags, raw.flags),
        (RingField::Descriptors, raw.descriptors),
    ] {
        if offset > MAX_RING_HEADER_OFFSET {
            return Err(fail(
                stage,
                SessionFailure::RingHeaderOutOfBounds { ring, field },
            ));
        }
    }
    let layout = RingMmapLayout::new(raw, entries, element).map_err(|error| {
        fail(
            stage,
            SessionFailure::RingLayout {
                ring,
                error: RingMapError::Layout(error),
            },
        )
    })?;
    Ok(RingPlan {
        raw,
        entries,
        byte_len: layout.byte_len(),
    })
}

#[derive(Clone, Copy)]
struct RingPlans {
    fill: RingPlan,
    completion: RingPlan,
    rx: RingPlan,
    tx: RingPlan,
}

fn plan_rings(offsets: XdpMmapOffsets, rings: RingConfig) -> Result<RingPlans, SessionError> {
    Ok(RingPlans {
        fill: plan_ring(
            RingName::Fill,
            offsets.fill,
            rings.fill(),
            RingElement::UmemAddress,
        )?,
        completion: plan_ring(
            RingName::Completion,
            offsets.completion,
            rings.completion(),
            RingElement::UmemAddress,
        )?,
        rx: plan_ring(
            RingName::Rx,
            offsets.rx,
            rings.rx(),
            RingElement::PacketDescriptor,
        )?,
        tx: plan_ring(
            RingName::Tx,
            offsets.tx,
            rings.tx(),
            RingElement::PacketDescriptor,
        )?,
    })
}

fn check_page_aligned<S: MapsRealMemory>(
    stage: SessionStage,
    region: &MappedRegion<'_, S>,
) -> Result<(), SessionError> {
    let address = region.address_bits();
    if address == 0 || !address.is_multiple_of(PAGE_SIZE) {
        Err(fail(stage, SessionFailure::MisalignedMapping))
    } else {
        Ok(())
    }
}

fn map_ring<'s, S: MapsRealMemory>(
    fd: &OwnedXdpFd<'s, S>,
    stage: SessionStage,
    plan: RingPlan,
    page_offset: u64,
) -> Result<MappedRegion<'s, S>, SessionError> {
    let region = fd
        .map_shared(plan.byte_len, page_offset)
        .map_err(at(stage))?;
    check_page_aligned(stage, &region)?;
    Ok(region)
}

fn set_ring_size<S: MapsRealMemory>(
    fd: &OwnedXdpFd<'_, S>,
    stage: SessionStage,
    option: i32,
    entries: RingEntries,
) -> Result<(), SessionError> {
    fd.set_socket_option(SOL_XDP, option, &entries.get().to_ne_bytes())
        .map_err(at(stage))
}

/// Owned resources of one bound session.
///
/// Field order is drop order: ring mappings in reverse mapping order, then
/// the UMEM, then the socket. Ring views are produced only by borrowing this
/// value mutably, so no view can outlive a mapping.
pub(super) struct SessionCore<'s, S: MapsRealMemory> {
    tx: MappedRegion<'s, S>,
    rx: MappedRegion<'s, S>,
    completion: MappedRegion<'s, S>,
    fill: MappedRegion<'s, S>,
    umem: MappedRegion<'s, S>,
    fd: OwnedXdpFd<'s, S>,
    plans: RingPlans,
    umem_config: UmemConfig,
    ifindex: u32,
    queue: u32,
    mode: NegotiatedMode,
    zero_copy_fallback: bool,
}

impl<'s, S: MapsRealMemory> SessionCore<'s, S> {
    /// Runs the complete transaction, including the `auto` fallback.
    ///
    /// `auto` binds with `XDP_ZEROCOPY` first. Linux v6.8 `xp_assign_dev`
    /// decides zero-copy support in order: the device must advertise the
    /// complete `NETDEV_XDP_ACT_ZC` `xdp_features` set (else `EOPNOTSUPP`),
    /// an `XDP_USE_SG` bind needs `xdp_zc_max_segs > 1` (never requested by
    /// this profile), and finally the driver's
    /// `ndo_bpf(XDP_SETUP_XSK_POOL)` return value is passed through. Only
    /// `EOPNOTSUPP` from that bind releases the whole first attempt in
    /// reverse order and runs a fresh transaction with `XDP_COPY`. Any
    /// other driver or kernel failure, including `EINVAL`, `EBUSY`, and
    /// `ENOMEM`, fails closed without fallback.
    ///
    /// The fresh attempt registers a second UMEM while the kernel may still
    /// account the first one: Linux releases UMEM pinning and memlock
    /// accounting from deferred work after the socket is freed. Without
    /// `CAP_IPC_LOCK`, `auto` therefore needs `RLIMIT_MEMLOCK` of at least
    /// twice the UMEM size, or the fallback fails with `MemlockLimit`.
    pub(super) fn open(syscalls: &'s S, config: &SessionConfig) -> Result<Self, SessionError> {
        let ifindex = interface_index(syscalls, config.interface_name_bytes())
            .map_err(at(SessionStage::InterfaceLookup))?;
        let raw = config.bind_flags().raw();
        match config.mode() {
            BindMode::CopyRequired | BindMode::ZeroCopyRequired => {
                Self::attempt(syscalls, config, ifindex, raw)
            }
            BindMode::Automatic => {
                match Self::attempt(syscalls, config, ifindex, raw | XDP_ZEROCOPY) {
                    Err(error) if error.failure() == SessionFailure::ZeroCopyUnsupported => {
                        let mut session = Self::attempt(syscalls, config, ifindex, raw | XDP_COPY)?;
                        session.zero_copy_fallback = true;
                        Ok(session)
                    }
                    other => other,
                }
            }
        }
    }

    fn attempt(
        syscalls: &'s S,
        config: &SessionConfig,
        ifindex: u32,
        flags: u16,
    ) -> Result<Self, SessionError> {
        let umem_config = config.umem();
        let rings = config.rings();

        let fd = OwnedXdpFd::open(syscalls).map_err(at(SessionStage::OpenSocket))?;

        let umem_len = usize::try_from(umem_config.byte_len())
            .ok()
            .and_then(|len| len.checked_next_multiple_of(PAGE_SIZE))
            .ok_or(fail(
                SessionStage::MapUmem,
                SessionFailure::ArgumentOutOfRange,
            ))?;
        let umem =
            MappedRegion::map_anonymous(syscalls, umem_len).map_err(at(SessionStage::MapUmem))?;
        check_page_aligned(SessionStage::MapUmem, &umem)?;

        let address = u64::try_from(umem.address_bits()).map_err(|_| {
            fail(
                SessionStage::RegisterUmem,
                SessionFailure::ArgumentOutOfRange,
            )
        })?;
        fd.set_socket_option(
            SOL_XDP,
            XDP_UMEM_REG,
            &encode_umem_reg(address, umem_config),
        )
        .map_err(at(SessionStage::RegisterUmem))?;

        set_ring_size(
            &fd,
            SessionStage::SizeFillRing,
            XDP_UMEM_FILL_RING,
            rings.fill(),
        )?;
        set_ring_size(
            &fd,
            SessionStage::SizeCompletionRing,
            XDP_UMEM_COMPLETION_RING,
            rings.completion(),
        )?;
        set_ring_size(&fd, SessionStage::SizeRxRing, XDP_RX_RING, rings.rx())?;
        set_ring_size(&fd, SessionStage::SizeTxRing, XDP_TX_RING, rings.tx())?;

        let mut raw_offsets = [0_u8; MMAP_OFFSETS_LEN];
        let actual = fd
            .get_socket_option(SOL_XDP, XDP_MMAP_OFFSETS, &mut raw_offsets)
            .map_err(at(SessionStage::QueryMmapOffsets))?;
        if actual != MMAP_OFFSETS_LEN {
            return Err(fail(
                SessionStage::QueryMmapOffsets,
                SessionFailure::OptionLength {
                    expected: MMAP_OFFSETS_LEN,
                    actual,
                },
            ));
        }
        let plans = plan_rings(decode_mmap_offsets(&raw_offsets), rings)?;

        let mut fill = map_ring(
            &fd,
            SessionStage::MapFillRing,
            plans.fill,
            XDP_UMEM_PGOFF_FILL_RING,
        )?;
        let mut completion = map_ring(
            &fd,
            SessionStage::MapCompletionRing,
            plans.completion,
            XDP_UMEM_PGOFF_COMPLETION_RING,
        )?;
        let mut rx = map_ring(&fd, SessionStage::MapRxRing, plans.rx, XDP_PGOFF_RX_RING)?;
        let mut tx = map_ring(&fd, SessionStage::MapTxRing, plans.tx, XDP_PGOFF_TX_RING)?;
        // Bind the role views once against the real mappings; they are
        // dropped immediately and rebuilt on demand by `rings`.
        build_views(
            &mut fill,
            &mut completion,
            &mut rx,
            &mut tx,
            plans,
            umem_config,
        )
        .map_err(|(stage, failure)| fail(stage, failure))?;

        let zero_copy_bind = flags & XDP_ZEROCOPY != 0;
        fd.bind_bytes(&encode_sockaddr(flags, ifindex, config.queue()))
            .map_err(|error| classify(SessionStage::Bind, error, zero_copy_bind))?;

        let mut raw_options = [0_u8; OPTIONS_LEN];
        let actual = fd
            .get_socket_option(SOL_XDP, XDP_OPTIONS, &mut raw_options)
            .map_err(at(SessionStage::QueryOptions))?;
        if actual != OPTIONS_LEN {
            return Err(fail(
                SessionStage::QueryOptions,
                SessionFailure::OptionLength {
                    expected: OPTIONS_LEN,
                    actual,
                },
            ));
        }
        let options = u32::from_ne_bytes(raw_options);
        let unsupported = options & !XDP_OPTIONS_ZEROCOPY;
        if unsupported != 0 {
            return Err(fail(
                SessionStage::QueryOptions,
                SessionFailure::UnsupportedOptions(unsupported),
            ));
        }
        let mode = if options & XDP_OPTIONS_ZEROCOPY != 0 {
            NegotiatedMode::ZeroCopy
        } else {
            NegotiatedMode::Copy
        };
        // Every attempt binds with exactly one of XDP_COPY or XDP_ZEROCOPY,
        // so the kernel's own silent copy fallback never applies.
        let expected = if zero_copy_bind {
            NegotiatedMode::ZeroCopy
        } else {
            NegotiatedMode::Copy
        };
        if mode != expected {
            return Err(fail(
                SessionStage::QueryOptions,
                SessionFailure::NegotiatedModeMismatch { negotiated: mode },
            ));
        }

        Ok(Self {
            tx,
            rx,
            completion,
            fill,
            umem,
            fd,
            plans,
            umem_config,
            ifindex,
            queue: config.queue(),
            mode,
            zero_copy_fallback: false,
        })
    }

    /// Lends the four role-typed ring views and the UMEM geometry.
    pub(super) fn rings(&mut self) -> Result<NativeRings<'_>, RingMapError> {
        build_views(
            &mut self.fill,
            &mut self.completion,
            &mut self.rx,
            &mut self.tx,
            self.plans,
            self.umem_config,
        )
        .map_err(|(_, failure)| match failure {
            SessionFailure::RingLayout { error, .. } => error,
            _ => RingMapError::MappingTooShort {
                required: 1,
                actual: 0,
            },
        })
    }

    /// Releases every resource once in teardown order and reports the first
    /// failure. Failed releases are not retried.
    pub(super) fn close(self) -> Result<(), CleanupError> {
        let Self {
            tx,
            rx,
            completion,
            fill,
            umem,
            fd,
            ..
        } = self;
        let mut first = None;
        let mut note = |stage, result: Result<(), ResourceError>| {
            if let Err(error) = result {
                let errno = match error {
                    ResourceError::Syscall(syscall) => syscall.errno.raw(),
                    _ => None,
                };
                first.get_or_insert(CleanupError::new(stage, errno));
            }
        };
        note(CleanupStage::UnmapTxRing, tx.unmap());
        note(CleanupStage::UnmapRxRing, rx.unmap());
        note(CleanupStage::UnmapCompletionRing, completion.unmap());
        note(CleanupStage::UnmapFillRing, fill.unmap());
        note(CleanupStage::UnmapUmem, umem.unmap());
        note(CleanupStage::CloseSocket, fd.close());
        first.map_or(Ok(()), Err)
    }

    pub(super) const fn mode(&self) -> NegotiatedMode {
        self.mode
    }

    pub(super) const fn zero_copy_fallback(&self) -> bool {
        self.zero_copy_fallback
    }

    pub(super) const fn ifindex(&self) -> u32 {
        self.ifindex
    }

    pub(super) const fn queue(&self) -> u32 {
        self.queue
    }
}

type ViewFailure = (SessionStage, SessionFailure);

fn borrow_failure(stage: SessionStage, ring: RingName, error: RingMapError) -> ViewFailure {
    (stage, SessionFailure::RingLayout { ring, error })
}

fn build_views<'a, S: MapsRealMemory>(
    fill: &'a mut MappedRegion<'_, S>,
    completion: &'a mut MappedRegion<'_, S>,
    rx: &'a mut MappedRegion<'_, S>,
    tx: &'a mut MappedRegion<'_, S>,
    plans: RingPlans,
    umem: UmemConfig,
) -> Result<NativeRings<'a>, ViewFailure> {
    let inactive = |plan: RingPlan| RingMapError::MappingTooShort {
        required: plan.byte_len,
        actual: 0,
    };
    let fill = fill
        .borrow_mapping()
        .ok_or(inactive(plans.fill))
        .and_then(|mapping| FillProducer::with_mapping(mapping, plans.fill.raw, plans.fill.entries))
        .map_err(|error| borrow_failure(SessionStage::MapFillRing, RingName::Fill, error))?;
    let completion = completion
        .borrow_mapping()
        .ok_or(inactive(plans.completion))
        .and_then(|mapping| {
            CompletionConsumer::with_mapping(
                mapping,
                plans.completion.raw,
                plans.completion.entries,
            )
        })
        .map_err(|error| {
            borrow_failure(SessionStage::MapCompletionRing, RingName::Completion, error)
        })?;
    let rx = rx
        .borrow_mapping()
        .ok_or(inactive(plans.rx))
        .and_then(|mapping| RxConsumer::with_mapping(mapping, plans.rx.raw, plans.rx.entries))
        .map_err(|error| borrow_failure(SessionStage::MapRxRing, RingName::Rx, error))?;
    let tx = tx
        .borrow_mapping()
        .ok_or(inactive(plans.tx))
        .and_then(|mapping| TxProducer::with_mapping(mapping, plans.tx.raw, plans.tx.entries))
        .map_err(|error| borrow_failure(SessionStage::MapTxRing, RingName::Tx, error))?;
    Ok(NativeRings {
        fill,
        completion,
        rx,
        tx,
        umem: UmemRegion::new(umem),
    })
}

static LINUX_SYSCALLS: LinuxSyscalls = LinuxSyscalls;

/// One live AF_XDP socket on one interface queue: registered UMEM, four
/// mapped rings, bound with the negotiated copy policy.
///
/// [`Self::open`] is failure atomic: on error every acquired resource has
/// been released in exact reverse order. Dropping the session (or
/// [`Self::close`]) unmaps the TX, RX, Completion, and Fill rings, then the
/// UMEM, then closes the socket, each exactly once. No XDP program is
/// attached, so the socket receives nothing until a later slice redirects a
/// queue to it.
///
/// The session is `!Send` and `!Sync` through an explicit marker: one
/// worker owns its rings.
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<ruster_io_xdp_native::NativeSession>();
/// ```
///
/// ```compile_fail
/// fn sync<T: Sync>() {}
/// sync::<ruster_io_xdp_native::NativeSession>();
/// ```
///
/// Ring views borrow the session and cannot outlive it:
///
/// ```compile_fail
/// use ruster_io_xdp_native::{FillProducer, NativeSession, SessionConfig};
/// fn escape(config: &SessionConfig) -> FillProducer<'static> {
///     let mut session = NativeSession::open(config).expect("session");
///     session.rings().expect("rings").fill
/// }
/// ```
pub struct NativeSession {
    core: SessionCore<'static, LinuxSyscalls>,
    _worker_local: PhantomData<*mut ()>,
}

impl NativeSession {
    /// Opens, registers, maps, and binds one session in the caller's network
    /// namespace.
    pub fn open(config: &SessionConfig) -> Result<Self, SessionError> {
        SessionCore::open(&LINUX_SYSCALLS, config).map(|core| Self {
            core,
            _worker_local: PhantomData,
        })
    }

    /// Returns the mode reported by `XDP_OPTIONS` after bind.
    #[must_use]
    pub const fn mode(&self) -> NegotiatedMode {
        self.core.mode()
    }

    /// Reports whether `auto` fell back to copy mode after a zero-copy bind
    /// failed with `EOPNOTSUPP`.
    #[must_use]
    pub const fn zero_copy_fallback(&self) -> bool {
        self.core.zero_copy_fallback()
    }

    /// Returns the bound interface index.
    #[must_use]
    pub const fn ifindex(&self) -> u32 {
        self.core.ifindex()
    }

    /// Returns the bound queue id.
    #[must_use]
    pub const fn queue(&self) -> u32 {
        self.core.queue()
    }

    /// Lends the four ring views and the UMEM geometry for the borrow of
    /// `self`.
    pub fn rings(&mut self) -> Result<NativeRings<'_>, RingMapError> {
        self.core.rings()
    }

    /// Releases every resource once, in teardown order, and reports the
    /// first release failure. Later resources are still released.
    pub fn close(self) -> Result<(), CleanupError> {
        self.core.close()
    }
}

impl std::fmt::Debug for NativeSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeSession")
            .field("mode", &self.core.mode())
            .field("zero_copy_fallback", &self.core.zero_copy_fallback())
            .field("queue", &self.core.queue())
            .finish_non_exhaustive()
    }
}
