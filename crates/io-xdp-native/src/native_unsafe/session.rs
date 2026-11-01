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
        AttachError, AttachFailure, AttachStage, CleanupError, CleanupStage, NativeRings,
        NegotiatedMode, SessionConfig, SessionError, SessionFailure, SessionStage, UmemRegion,
        VerifierLogSummary, XdpAttachMode, MAX_RING_HEADER_OFFSET,
    },
    xdp_program::{XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE},
    BindMode, CompletionConsumer, FillProducer, RingConfig, RingEntries, RingField, RingMapError,
    RingName, RxConsumer, TxProducer, UmemConfig,
};

use super::umem::UmemMapping;
use crate::datapath::{DatapathError, DatapathParts, DatapathRings, RingsError};

use super::syscall::{
    errno, interface_index, Errno, LinuxSyscalls, MappedRegion, MapsRealMemory, OwnedBpfFd,
    OwnedXdpFd, ResourceError, SyscallError, IFNAMSIZ, PAGE_SIZE,
};

/// Verifier log capacity: the program's success log is about 100 bytes, so
/// 4 KiB holds any `BPF_LOG_LEVEL1` rejection of it without truncation.
pub(super) const VERIFIER_LOG_CAPACITY: usize = 4_096;

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

/// Classifies one seam failure at one attach step. `native` is true only
/// for a link requested with `XDP_FLAGS_DRV_MODE`.
pub(super) fn classify_attach(
    stage: AttachStage,
    error: ResourceError,
    native: bool,
    verifier_log: Option<VerifierLogSummary>,
) -> AttachError {
    let failure = match error {
        ResourceError::Platform(platform) => AttachFailure::Platform(platform),
        ResourceError::Argument(_)
        | ResourceError::Syscall(SyscallError {
            errno: Errno::ArgumentRejected,
            ..
        }) => AttachFailure::ArgumentOutOfRange,
        ResourceError::Syscall(syscall) => match (stage, syscall.errno.raw()) {
            (_, None) => AttachFailure::UnreadableErrno,
            (AttachStage::CreateLink, Some(errno::EBUSY | errno::EEXIST)) => {
                AttachFailure::ExistingProgram
            }
            (AttachStage::CreateLink, Some(errno::EOPNOTSUPP)) if native => {
                AttachFailure::NativeXdpUnsupported
            }
            // The verifier always logs its rejection; an empty log means an
            // earlier denial (an LSM `security_bpf_prog_load` hook).
            (AttachStage::LoadProgram, Some(errno::EACCES))
                if verifier_log.is_some_and(|log| log.bytes() > 0) =>
            {
                AttachFailure::VerifierRejected
            }
            (_, Some(errno::EPERM | errno::EACCES)) => AttachFailure::PermissionDenied,
            (_, Some(errno::EINVAL)) => AttachFailure::InvalidArgument,
            (_, Some(errno::E2BIG)) => AttachFailure::TooBig,
            (_, Some(errno::ENOSPC)) => AttachFailure::NoSpace,
            (_, Some(errno::ENOMEM)) => AttachFailure::OutOfMemory,
            (_, Some(errno::EOPNOTSUPP)) => AttachFailure::Unsupported,
            (_, Some(other)) => AttachFailure::Errno(other),
        },
    };
    AttachError::new(stage, failure, verifier_log)
}

/// Summarizes a kernel-written verifier log without interpreting or
/// copying its bytes. A buffer with no NUL counts as truncated.
pub(super) fn summarize_log(log: &[u8], kernel_truncated: bool) -> VerifierLogSummary {
    let (bytes, terminated) = match log.iter().position(|byte| *byte == 0) {
        Some(len) => (len, true),
        None => (log.len(), false),
    };
    VerifierLogSummary::new(
        u32::try_from(bytes).unwrap_or(u32::MAX),
        kernel_truncated || !terminated,
    )
}

/// XDP objects of one attach, partial while the transaction runs.
///
/// [`Self::release`] (also run by Drop) closes the link first, which
/// detaches the program, then deletes the socket's XSKMAP entry if one was
/// inserted, then closes the program, then the map. The entry delete
/// matters because each XSKMAP entry holds a map reference from the
/// socket's map list: without it, every attach/detach (or failed link)
/// would keep one map alive until the socket closes.
///
/// Each step `take`s its owner first, so if a release ever panicked
/// (currently unreachable: every release returns a `Result`), unwinding
/// would run Drop, which releases only the remaining owners, in the same
/// order and still at most once each.
pub(super) struct XdpObjects<'s, S: MapsRealMemory> {
    link: Option<OwnedBpfFd<'s, S>>,
    program: Option<OwnedBpfFd<'s, S>>,
    map: Option<OwnedBpfFd<'s, S>>,
    queue: u32,
    inserted: bool,
    mode: XdpAttachMode,
}

impl<S: MapsRealMemory> XdpObjects<'_, S> {
    /// Releases every remaining object once, in teardown order, noting
    /// each result. A second call does nothing.
    fn release(&mut self, note: &mut impl FnMut(CleanupStage, Result<(), ResourceError>)) {
        if let Some(link) = self.link.take() {
            note(CleanupStage::CloseXdpLink, link.close());
        }
        if std::mem::take(&mut self.inserted) {
            if let Some(map) = self.map.as_ref() {
                note(
                    CleanupStage::RemoveXskMapEntry,
                    map.remove_socket(self.queue),
                );
            }
        }
        if let Some(program) = self.program.take() {
            note(CleanupStage::CloseXdpProgram, program.close());
        }
        if let Some(map) = self.map.take() {
            note(CleanupStage::CloseXskMap, map.close());
        }
    }
}

impl<S: MapsRealMemory> Drop for XdpObjects<'_, S> {
    fn drop(&mut self) {
        self.release(&mut |_, _| {});
    }
}

fn cleanup_error(stage: CleanupStage, error: ResourceError) -> CleanupError {
    let errno = match error {
        ResourceError::Syscall(syscall) => syscall.errno.raw(),
        _ => None,
    };
    CleanupError::new(stage, errno)
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
/// Field order is drop order: the attached XDP objects (link first, so the
/// program is detached before anything else), then ring mappings in reverse
/// mapping order, then the UMEM, then the socket. Ring views are produced
/// only by borrowing this value mutably, so no view can outlive a mapping.
pub(super) struct SessionCore<'s, S: MapsRealMemory> {
    xdp: Option<XdpObjects<'s, S>>,
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
    datapath: DatapathAccess,
}

/// Which kind of ring access this session has handed out. The two kinds
/// never overlap, and the datapath bundle is handed out at most once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DatapathAccess {
    /// Nothing was lent yet.
    Untouched,
    /// `rings` lent raw views at least once.
    RawLent,
    /// `take_datapath` lent the bundle; it can never be lent again.
    Taken,
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
            xdp: None,
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
            datapath: DatapathAccess::Untouched,
        })
    }

    /// Lends the four role-typed ring views and the UMEM geometry.
    ///
    /// Refused once the datapath bundle was taken.
    pub(super) fn rings(&mut self) -> Result<NativeRings<'_>, RingsError> {
        if self.datapath == DatapathAccess::Taken {
            return Err(RingsError::DatapathTaken);
        }
        self.datapath = DatapathAccess::RawLent;
        self.raw_views().map_err(RingsError::Map)
    }

    /// Lends all datapath resources as one bundle, at most once per session
    /// and never after raw views were lent.
    pub(super) fn take_datapath(&mut self) -> Result<DatapathRings<'_>, DatapathError> {
        match self.datapath {
            DatapathAccess::Taken => return Err(DatapathError::AlreadyTaken),
            DatapathAccess::RawLent => return Err(DatapathError::RawRingsLent),
            DatapathAccess::Untouched => {}
        }
        // `open` rejected a zero or unaligned UMEM address, so only an
        // inactive region could yield no borrow.
        let Some(umem) = self.umem.borrow_mapping() else {
            return Err(DatapathError::Map(RingMapError::MappingTooShort {
                required: 1,
                actual: 0,
            }));
        };
        let umem = UmemMapping::from_mapping(umem);
        let views = build_views(
            &mut self.fill,
            &mut self.completion,
            &mut self.rx,
            &mut self.tx,
            self.plans,
            self.umem_config,
        )
        .map_err(|(_, failure)| DatapathError::Map(view_error(failure)))?;
        self.datapath = DatapathAccess::Taken;
        let NativeRings {
            fill,
            completion,
            rx,
            tx,
            umem: _,
        } = views;
        Ok(DatapathRings::new(DatapathParts {
            fill,
            completion,
            rx,
            tx,
            umem,
            umem_config: self.umem_config,
        }))
    }

    #[cfg(test)]
    pub(super) const fn datapath_access(&self) -> DatapathAccess {
        self.datapath
    }

    fn raw_views(&mut self) -> Result<NativeRings<'_>, RingMapError> {
        build_views(
            &mut self.fill,
            &mut self.completion,
            &mut self.rx,
            &mut self.tx,
            self.plans,
            self.umem_config,
        )
        .map_err(|(_, failure)| view_error(failure))
    }

    /// Releases every resource once in teardown order and reports the first
    /// failure. Failed releases are not retried.
    ///
    /// The destructuring moves every owner into a local binding, so a panic
    /// here (currently unreachable: each release returns a `Result`) would
    /// still drop the remaining bindings in reverse declaration order, which
    /// is the same teardown order.
    pub(super) fn close(self) -> Result<(), CleanupError> {
        let Self {
            xdp,
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
                first.get_or_insert(cleanup_error(stage, error));
            }
        };
        if let Some(mut objects) = xdp {
            objects.release(&mut note);
        }
        note(CleanupStage::UnmapTxRing, tx.unmap());
        note(CleanupStage::UnmapRxRing, rx.unmap());
        note(CleanupStage::UnmapCompletionRing, completion.unmap());
        note(CleanupStage::UnmapFillRing, fill.unmap());
        note(CleanupStage::UnmapUmem, umem.unmap());
        note(CleanupStage::CloseSocket, fd.close());
        first.map_or(Ok(()), Err)
    }

    /// Attaches the XSK redirect program to the bound interface.
    ///
    /// Order: XSKMAP (`queue + 1` slots) → program load → socket insert at
    /// `queue` → `BPF_LINK_CREATE`. Every step before the link is private to
    /// this process, so a failure there leaves the interface untouched. The
    /// socket is in the map before the link exists, so the first redirected
    /// packet already finds it. The link is the single commit point: Linux
    /// `dev_xdp_attach` refuses with `EBUSY`/`EEXIST` while another program
    /// or link is attached in the same or the other of native/generic mode
    /// (link create never sets `XDP_FLAGS_REPLACE`), so such a program is
    /// detected under RTNL and never replaced or detached. A failed link
    /// deletes the socket's map entry before closing program and map.
    pub(super) fn attach_xdp(&mut self, mode: XdpAttachMode) -> Result<(), AttachError> {
        let precondition = |failure| AttachError::new(AttachStage::Precondition, failure, None);
        if self.xdp.is_some() {
            return Err(precondition(AttachFailure::AlreadyAttached));
        }
        if mode == XdpAttachMode::Generic && self.mode == NegotiatedMode::ZeroCopy {
            return Err(precondition(AttachFailure::GenericRequiresCopyMode));
        }
        let native = mode == XdpAttachMode::Native;
        let flags = if native {
            XDP_FLAGS_DRV_MODE
        } else {
            XDP_FLAGS_SKB_MODE
        };
        let at = |stage| move |error| classify_attach(stage, error, native, None);
        // The queue id is at most MAX_QUEUE_ID, so this cannot overflow.
        let max_entries = self.queue.checked_add(1).ok_or(AttachError::new(
            AttachStage::CreateMap,
            AttachFailure::ArgumentOutOfRange,
            None,
        ))?;

        let map = OwnedBpfFd::create_xskmap(self.fd.syscalls(), max_entries)
            .map_err(at(AttachStage::CreateMap))?;

        let mut log = [0_u8; VERIFIER_LOG_CAPACITY];
        let program = match map.load_redirect_program(&mut log) {
            Ok(program) => program,
            Err(error) => {
                let truncated = matches!(
                    error,
                    ResourceError::Syscall(SyscallError { errno, .. })
                        if errno.raw() == Some(errno::ENOSPC)
                );
                let summary = summarize_log(&log, truncated);
                return Err(classify_attach(
                    AttachStage::LoadProgram,
                    error,
                    native,
                    Some(summary),
                ));
            }
        };

        // From here on Drop of `objects` releases in teardown order.
        let mut objects = XdpObjects {
            link: None,
            program: Some(program),
            map: Some(map),
            queue: self.queue,
            inserted: false,
            mode,
        };
        if let Some(map) = objects.map.as_ref() {
            map.insert_socket(self.queue, &self.fd)
                .map_err(at(AttachStage::InsertSocket))?;
        }
        objects.inserted = true;

        if let Some(program) = objects.program.as_ref() {
            let link = program
                .create_xdp_link(self.ifindex, flags)
                .map_err(at(AttachStage::CreateLink))?;
            objects.link = Some(link);
        }
        self.xdp = Some(objects);
        Ok(())
    }

    /// Detaches by closing the link, then deletes the socket's map entry and
    /// closes program and map, each once. A session without an attachment
    /// is a no-op.
    pub(super) fn detach_xdp(&mut self) -> Result<(), CleanupError> {
        let mut first = None;
        if let Some(mut objects) = self.xdp.take() {
            objects.release(&mut |stage, result: Result<(), ResourceError>| {
                if let Err(error) = result {
                    first.get_or_insert(cleanup_error(stage, error));
                }
            });
        }
        first.map_or(Ok(()), Err)
    }

    pub(super) fn xdp_attach_mode(&self) -> Option<XdpAttachMode> {
        self.xdp.as_ref().map(|objects| objects.mode)
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

fn view_error(failure: SessionFailure) -> RingMapError {
    match failure {
        SessionFailure::RingLayout { error, .. } => error,
        _ => RingMapError::MappingTooShort {
            required: 1,
            actual: 0,
        },
    }
}

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
/// been released in exact reverse order. The socket receives nothing until
/// [`Self::attach_xdp`] redirects its queue to it. Dropping the session (or
/// [`Self::close`]) first detaches an attached program (link, program, and
/// XSKMAP fds), then unmaps the TX, RX, Completion, and Fill rings, then
/// the UMEM, then closes the socket, each exactly once.
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
    /// `self`, for direct ring access without the engine.
    ///
    /// Once called, [`Self::take_datapath`] is refused for this session,
    /// because frames published through raw views are unknown to any
    /// engine ledger. After the datapath was taken this returns
    /// [`RingsError::DatapathTaken`].
    pub fn rings(&mut self) -> Result<NativeRings<'_>, RingsError> {
        self.core.rings()
    }

    /// Takes all datapath resources (Fill, Completion, RX, TX, and UMEM
    /// bytes) as one bundle for [`crate::RxFillEngine::new`].
    ///
    /// Succeeds at most once per session, and only if [`Self::rings`] was
    /// never called: the engine's ledger must have seen every Fill
    /// publication of this socket. Rebuilding an engine therefore requires
    /// closing the session, because the kernel or driver may still hold
    /// frames the first engine published.
    ///
    /// ```compile_fail,E0499
    /// fn two(session: &mut ruster_io_xdp_native::NativeSession) {
    ///     let first = session.take_datapath();
    ///     let raw = session.rings();
    ///     drop((first, raw));
    /// }
    /// ```
    pub fn take_datapath(&mut self) -> Result<DatapathRings<'_>, DatapathError> {
        self.core.take_datapath()
    }

    /// Attaches the XSK redirect program to the bound interface through an
    /// unpinned `bpf_link` (Linux 5.9+).
    ///
    /// Creates an XSKMAP with `queue + 1` slots, loads the redirect program,
    /// stores this socket at the bound queue, and creates the link. On
    /// error every object created so far has been closed in exact reverse
    /// order, the interface is unchanged, and the session stays usable. An
    /// interface that already has any XDP program or link yields
    /// [`AttachFailure::ExistingProgram`](crate::AttachFailure::ExistingProgram);
    /// that program is never replaced or detached. Packets on queues
    /// without a socket in the map are dropped (`XDP_DROP`, fail closed):
    /// use a single-queue device or steer all traffic to the bound queue.
    ///
    /// The link fd is close-on-exec and never pinned, so it is detached by
    /// [`Self::detach_xdp`], [`Self::close`], drop, or process exit
    /// (including `SIGKILL`). That assumes no other process holds the link
    /// fd: a `fork` without `exec`, `SCM_RIGHTS`, or `pidfd_getfd` would
    /// keep the link, and the program, alive.
    ///
    /// The ifindex was resolved by [`Self::open`] in the caller's network
    /// namespace, and the link is created in the namespace current at this
    /// call. Open and attach must therefore run in the same network
    /// namespace; a `setns` between them can attach to an unrelated device
    /// that happens to have the same ifindex.
    pub fn attach_xdp(&mut self, mode: XdpAttachMode) -> Result<(), AttachError> {
        self.core.attach_xdp(mode)
    }

    /// Detaches the program by closing its link, then closes the program
    /// and the XSKMAP, each once, and reports the first failure. Without an
    /// attachment this does nothing.
    pub fn detach_xdp(&mut self) -> Result<(), CleanupError> {
        self.core.detach_xdp()
    }

    /// Returns the attach mode of the live attachment, if any.
    #[must_use]
    pub fn xdp_attach_mode(&self) -> Option<XdpAttachMode> {
        self.core.xdp_attach_mode()
    }

    /// Releases every resource once, in teardown order, and reports the
    /// first release failure. Later resources are still released. An
    /// attached program is detached first.
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
            .field("xdp_attach_mode", &self.core.xdp_attach_mode())
            .finish_non_exhaustive()
    }
}
