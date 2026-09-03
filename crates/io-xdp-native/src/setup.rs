//! Checked AF_XDP socket, UMEM, ring, mmap, and bind setup.
//!
//! This module owns the cold resource transaction and exposes the configured
//! queue to the packet-path implementation. The packet path is authoritative
//! over descriptor ownership; the public raw ring views are therefore an
//! escape hatch that fail-closes the packet-path and publication APIs after
//! they have been handed out. The native syscall calls themselves remain in
//! `native_unsafe::syscall`; this layer only supplies validated values and
//! owns the returned RAII resources.

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
use std::marker::PhantomData;

use ruster_core::IfId;

use crate::{
    abi::{
        decode_xdp_mmap_offsets, encode_sockaddr_xdp, encode_xdp_umem_reg, RingElement,
        RingMmapLayout, SockAddrXdp, XdpMmapOffsets, XdpUmemReg, ABI_UMEM_REG_SOURCE, AF_XDP,
        SOL_XDP, XDP_MMAP_OFFSETS, XDP_PGOFF_RX_RING, XDP_PGOFF_TX_RING, XDP_RX_RING, XDP_TX_RING,
        XDP_UMEM_COMPLETION_RING, XDP_UMEM_FILL_RING, XDP_UMEM_PGOFF_COMPLETION_RING,
        XDP_UMEM_PGOFF_FILL_RING, XDP_UMEM_REG, XDP_USE_NEED_WAKEUP,
    },
    CompletionConsumer, FillProducer, RingConfig, RingEntries, RingMapError, RingName, RxConsumer,
    TxProducer, UmemConfig, ValidatedBindFlags, XdpSetupArgumentError, XdpSetupError,
    XdpSetupStage,
};

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
use crate::data_path::{BatchState, XdpBatchCore, XdpOwnership};

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
use crate::native_unsafe::syscall::{
    LinuxSyscalls, MappedRegion, OwnedXdpFd, ResourceError, SyscallArgumentError, SyscallStage,
    Syscalls,
};

/// A cold AF_XDP resource transaction for one interface queue.
///
/// `new` defaults to [`crate::BindMode::Automatic`], represented by
/// `XDP_USE_NEED_WAKEUP` without either mode-forcing bit. Automatic mode is
/// the default because the kernel can select zero-copy on capable drivers and
/// retain copy-mode compatibility elsewhere; callers can request either mode
/// explicitly with [`Self::with_bind_flags`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XdpResourceBuilder {
    umem: UmemConfig,
    rings: RingConfig,
    ifindex: u32,
    queue_id: u32,
    bind_flags: ValidatedBindFlags,
    logical_interface: Option<IfId>,
}

/// Four borrowed application views over one configured AF_XDP queue.
///
/// The views borrow their respective mmap regions from the resource owner for
/// the lifetime of this value. Keeping them together gives callers a safe
/// way to hold RX and TX (and the two UMEM rings) in the same tick without a
/// shared lock or packet allocation. Drop this value before calling
/// [`XdpResource::close`] or otherwise dropping its owner.
pub struct XdpRingViews<'owner> {
    /// Application producer for UMEM addresses supplied to the kernel.
    pub fill: FillProducer<'owner>,
    /// Kernel producer / application consumer for completed UMEM addresses.
    pub completion: CompletionConsumer<'owner>,
    /// Kernel producer / application consumer for received packet descriptors.
    pub rx: RxConsumer<'owner>,
    /// Application producer for transmitted packet descriptors.
    pub tx: TxProducer<'owner>,
}

/// The minimum base-page alignment guaranteed by the supported x86_64 Linux
/// `mmap(2)` profile.
///
/// AF_XDP UMEM must be backed by a stable mapping whose address remains valid
/// until every resource using it has been dropped. A normal `Vec<u8>` has no
/// public alignment guarantee suitable for this boundary; production callers
/// should use [`PageAlignedUmem`] (or provide an equivalent mmap-backed owner).
pub const PAGE_ALIGNED_UMEM_ALIGNMENT: usize = 4_096;

/// Page-aligned, mmap-backed UMEM storage for production AF_XDP resources.
///
/// The owner can be borrowed by one or more resources only through disjoint
/// mutable slices. The borrow checker then enforces that the mapping outlives
/// each `XdpResource`. Declare this owner before the resource(s), and drop the
/// resources before the owner. The mapping is unmapped exactly once by its RAII
/// owner; no `Vec` reallocation or packet-path allocation is involved.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
pub struct PageAlignedUmem {
    inner: MappedRegion<'static, LinuxSyscalls>,
}

/// Portable placeholder for the page-aligned UMEM owner.
#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
pub struct PageAlignedUmem {
    _unsupported: PhantomData<*mut [u8]>,
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
impl PageAlignedUmem {
    /// Allocates exactly `byte_len` writable anonymous mmap bytes.
    pub fn new(byte_len: usize) -> Result<Self, XdpSetupError> {
        let inner =
            MappedRegion::map_anonymous(&LINUX_SYSCALLS, byte_len).map_err(map_resource_error)?;
        if !inner.address_is_page_aligned() {
            return Err(XdpSetupError::UmemAddressMisaligned {
                address: inner.address(),
                alignment: PAGE_ALIGNED_UMEM_ALIGNMENT,
            });
        }
        Ok(Self { inner })
    }

    /// Allocates a mapping whose length exactly matches one checked UMEM
    /// configuration.
    pub fn for_umem(config: UmemConfig) -> Result<Self, XdpSetupError> {
        let byte_len = usize::try_from(config.byte_len()).map_err(|_| {
            XdpSetupError::UmemLengthNotRepresentable {
                length: config.byte_len(),
            }
        })?;
        Self::new(byte_len)
    }

    /// Returns the exact byte length supplied to `mmap(2)`.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.inner.byte_len()
    }

    /// Returns whether this owner contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Borrows the mapped UMEM bytes for a resource setup transaction.
    ///
    /// The returned borrow prevents this mapping from being unmapped while a
    /// resource retains it.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.inner
            .as_mut_bytes()
            .expect("a live PageAlignedUmem has an active mapping")
    }

    /// Explicitly unmaps this owner after all borrowed resources have been
    /// released. The mapping is marked inactive before the syscall, so the
    /// returned error is observable without a second Drop attempt.
    pub fn close(self) -> Result<(), XdpSetupError> {
        self.inner.unmap().map_err(map_resource_error)
    }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
impl PageAlignedUmem {
    /// Returns an explicit unsupported-platform error without entering a
    /// syscall.
    pub fn new(_byte_len: usize) -> Result<Self, XdpSetupError> {
        Err(XdpSetupError::Platform(native_platform_error()))
    }

    /// Returns an explicit unsupported-platform error without entering a
    /// syscall.
    pub fn for_umem(_config: UmemConfig) -> Result<Self, XdpSetupError> {
        Err(XdpSetupError::Platform(native_platform_error()))
    }

    /// This method is unreachable because construction is rejected above.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let _ = self;
        &mut []
    }

    /// Returns an explicit unsupported-platform error; no mapping exists on
    /// a target where the native AF_XDP profile is unavailable.
    pub fn close(self) -> Result<(), XdpSetupError> {
        let _ = self;
        Ok(())
    }

    /// Returns zero for the never-created portable placeholder.
    #[must_use]
    pub const fn len(&self) -> usize {
        0
    }

    /// The unsupported placeholder is always empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        true
    }
}

impl XdpResourceBuilder {
    /// Creates a setup builder for one newly registered UMEM and queue.
    ///
    /// The UMEM and ring values are already checked by [`UmemConfig`] and
    /// [`RingConfig`]. Interface index zero is rejected before any syscall.
    /// The default bind policy is Automatic with need-wakeup enabled.
    pub fn new(
        umem: UmemConfig,
        rings: RingConfig,
        ifindex: u32,
        queue_id: u32,
    ) -> Result<Self, XdpSetupError> {
        if ifindex == 0 {
            return Err(XdpSetupError::InvalidInterfaceIndex { ifindex });
        }
        let bind_flags = ValidatedBindFlags::new(XDP_USE_NEED_WAKEUP)
            .expect("the built-in Automatic bind profile is valid");
        Ok(Self {
            umem,
            rings,
            ifindex,
            queue_id,
            bind_flags,
            logical_interface: None,
        })
    }

    /// Supplies the logical core interface identifier for this queue.
    ///
    /// Linux `ifindex` values identify kernel links and are not interchangeable
    /// with the router's configured [`ruster_core::IfId`]. Existing callers
    /// that do not set this value retain the historical checked conversion of
    /// `ifindex`; production composition roots should always set it from their
    /// validated configuration.
    #[must_use]
    pub const fn with_interface_id(mut self, interface: IfId) -> Self {
        self.logical_interface = Some(interface);
        self
    }

    /// Replaces the checked copy/zero-copy and bind flag policy.
    #[must_use]
    pub const fn with_bind_flags(mut self, bind_flags: ValidatedBindFlags) -> Self {
        self.bind_flags = bind_flags;
        self
    }

    /// Validates and replaces raw UAPI bind flags.
    pub fn with_raw_bind_flags(self, raw: u16) -> Result<Self, XdpSetupError> {
        Ok(self.with_bind_flags(ValidatedBindFlags::new(raw)?))
    }

    /// Returns the checked UMEM geometry.
    #[must_use]
    pub const fn umem(&self) -> UmemConfig {
        self.umem
    }

    /// Returns the checked capacities of all four rings.
    #[must_use]
    pub const fn rings(&self) -> RingConfig {
        self.rings
    }

    /// Returns the interface index selected for bind.
    #[must_use]
    pub const fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Returns the hardware queue selected for bind.
    #[must_use]
    pub const fn queue_id(&self) -> u32 {
        self.queue_id
    }

    /// Returns the checked bind flags.
    #[must_use]
    pub const fn bind_flags(&self) -> ValidatedBindFlags {
        self.bind_flags
    }

    /// Registers `memory` as UMEM, maps all four rings, and binds the queue.
    ///
    /// The mutable borrow is retained for the lifetime of the returned owner;
    /// while the owner exists, the caller cannot access bytes that the kernel
    /// may DMA into or read from. Packet I/O is intentionally not part of this
    /// owner yet.
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    pub fn build<'umem>(
        self,
        memory: &'umem mut [u8],
    ) -> Result<XdpResource<'umem>, XdpSetupError> {
        let owner = self.build_with_syscalls(memory, &LINUX_SYSCALLS)?;
        Ok(XdpResource { inner: owner })
    }

    /// Returns a typed unsupported-platform error without entering a syscall.
    #[cfg(not(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    )))]
    pub fn build<'umem>(
        self,
        _memory: &'umem mut [u8],
    ) -> Result<XdpResource<'umem>, XdpSetupError> {
        let _ = self;
        Err(XdpSetupError::Platform(native_platform_error()))
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    pub(crate) fn build_with_syscalls<'umem, 'syscalls, S: Syscalls>(
        self,
        memory: &'umem mut [u8],
        syscalls: &'syscalls S,
    ) -> Result<ResourceOwner<'umem, 'syscalls, S>, XdpSetupError> {
        if self.bind_flags.shared_umem() {
            return Err(XdpSetupError::SharedUmemUnsupported);
        }

        let (umem_address, umem_len) = validate_umem(memory, self.umem)?;
        let socket = OwnedXdpFd::open(syscalls).map_err(map_resource_error)?;

        register_umem(&socket, umem_address, umem_len, self.umem)?;
        configure_ring(&socket, XDP_UMEM_FILL_RING, self.rings.fill())?;
        configure_ring(&socket, XDP_UMEM_COMPLETION_RING, self.rings.completion())?;
        configure_ring(&socket, XDP_RX_RING, self.rings.rx())?;
        configure_ring(&socket, XDP_TX_RING, self.rings.tx())?;

        let offsets = query_mmap_offsets(&socket)?;
        let fill_layout = checked_ring_layout(
            RingName::Fill,
            offsets.fill,
            self.rings.fill(),
            RingElement::UmemAddress,
        )?;
        let completion_layout = checked_ring_layout(
            RingName::Completion,
            offsets.completion,
            self.rings.completion(),
            RingElement::UmemAddress,
        )?;
        let rx_layout = checked_ring_layout(
            RingName::Rx,
            offsets.rx,
            self.rings.rx(),
            RingElement::PacketDescriptor,
        )?;
        let tx_layout = checked_ring_layout(
            RingName::Tx,
            offsets.tx,
            self.rings.tx(),
            RingElement::PacketDescriptor,
        )?;

        // `socket` is declared before every mapping. Rust drops locals in
        // reverse declaration order, so a partial setup unwinds every map
        // before closing this fd. The owner below repeats the same contract
        // explicitly in its Drop implementation.
        let fill_mapping = map_ring(
            &socket,
            RingName::Fill,
            fill_layout,
            XDP_UMEM_PGOFF_FILL_RING,
        )?;
        let completion_mapping = map_ring(
            &socket,
            RingName::Completion,
            completion_layout,
            XDP_UMEM_PGOFF_COMPLETION_RING,
        )?;
        let rx_mapping = map_ring(&socket, RingName::Rx, rx_layout, XDP_PGOFF_RX_RING)?;
        let tx_mapping = map_ring(&socket, RingName::Tx, tx_layout, XDP_PGOFF_TX_RING)?;

        let address = encode_sockaddr_xdp(SockAddrXdp {
            family: u16::try_from(AF_XDP).expect("AF_XDP fits sockaddr_xdp family"),
            flags: self.bind_flags.raw(),
            ifindex: self.ifindex,
            queue_id: self.queue_id,
            shared_umem_fd: 0,
        });
        socket.bind_bytes(&address).map_err(map_resource_error)?;

        let interface = match self.logical_interface {
            Some(interface) => interface,
            None => {
                let value = u16::try_from(self.ifindex).map_err(|_| {
                    XdpSetupError::InterfaceIndexNotRepresentable {
                        ifindex: self.ifindex,
                    }
                })?;
                IfId(value)
            }
        };
        let mut owner = ResourceOwner {
            _fill_mapping: fill_mapping,
            _completion_mapping: completion_mapping,
            _rx_mapping: rx_mapping,
            _tx_mapping: tx_mapping,
            socket,
            umem_memory: memory,
            umem: self.umem,
            rings: self.rings,
            ifindex: self.ifindex,
            queue_id: self.queue_id,
            interface,
            bind_flags: self.bind_flags,
            offsets,
            fill_layout,
            completion_layout,
            rx_layout,
            tx_layout,
            ownership: XdpOwnership::new(self.umem),
            batch_state: BatchState::Idle,
            fill_wakeup_pending: false,
            tx_wakeup_pending: false,
            raw_views_exposed: false,
        };
        owner
            .initialize_data_path()
            .map_err(XdpSetupError::DataPath)?;
        Ok(owner)
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
static LINUX_SYSCALLS: LinuxSyscalls = LinuxSyscalls;

/// Owner of one completely configured and bound AF_XDP queue.
///
/// This resource owns the socket, all ring mappings, the borrowed UMEM, and
/// the data-path ownership ledger in one non-detachable value. Packet I/O
/// batches borrow this exact owner and return every completed chunk through
/// that ledger. Call [`Self::close`] when cleanup failures must be observed:
/// it consumes the owner, attempts every unmap before closing the socket, and
/// returns the first cleanup error. Drop is best-effort and suppresses
/// cleanup errors; each mapping and the socket are attempted at most once.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
pub struct XdpResource<'umem> {
    inner: ResourceOwner<'umem, 'static, LinuxSyscalls>,
}

/// Placeholder resource type used to keep the public API portable.
#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
pub struct XdpResource<'umem> {
    _umem: PhantomData<&'umem mut [u8]>,
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
impl XdpResource<'_> {
    /// Explicit teardown is a no-op because unsupported targets never create
    /// an operating-system resource through [`XdpResourceBuilder::build`].
    pub fn close(self) -> Result<(), XdpSetupError> {
        let _ = self;
        Ok(())
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
impl XdpResource<'_> {
    /// Explicitly tears down all mappings and then closes the socket.
    ///
    /// Every cleanup operation is attempted in mapping-before-fd order. The
    /// first cleanup error is returned, while the consumed owner prevents
    /// [`Drop`] from issuing a second unmap or close. Dropping the resource
    /// remains the best-effort alternative when an error cannot be observed.
    pub fn close(self) -> Result<(), XdpSetupError> {
        self.inner.close()
    }

    /// Returns the checked UMEM geometry used for registration.
    #[must_use]
    pub const fn umem(&self) -> UmemConfig {
        self.inner.umem
    }

    /// Returns the checked capacities used for ring setup.
    #[must_use]
    pub const fn rings(&self) -> RingConfig {
        self.inner.rings
    }

    /// Returns the bound interface index.
    #[must_use]
    pub const fn ifindex(&self) -> u32 {
        self.inner.ifindex
    }

    /// Returns the logical core interface identifier used by packet routing.
    #[must_use]
    pub const fn interface_id(&self) -> IfId {
        self.inner.interface
    }

    /// Returns the bound hardware queue identifier.
    #[must_use]
    pub const fn queue_id(&self) -> u32 {
        self.inner.queue_id
    }

    /// Exposes the private bound-socket capability to the XSKMAP adapter.
    ///
    /// This remains crate-private: the only public value that can provide it
    /// is a resource returned after the setup transaction's successful
    /// `bind(2)` call.
    pub(crate) fn bound_socket(&self) -> &OwnedXdpFd<'static, LinuxSyscalls> {
        &self.inner.socket
    }

    /// Returns the checked bind flags used by `sockaddr_xdp`.
    #[must_use]
    pub const fn bind_flags(&self) -> ValidatedBindFlags {
        self.inner.bind_flags
    }

    /// Returns the kernel-reported offsets retained for a later I/O layer.
    #[must_use]
    pub const fn mmap_offsets(&self) -> XdpMmapOffsets {
        self.inner.offsets
    }

    /// Borrows all four mapped rings for one application tick.
    ///
    /// Each view is connected to the matching kernel-reported offsets and
    /// independently owned mmap. The returned value borrows this resource,
    /// so the socket and mappings cannot be closed while a view is alive.
    ///
    /// This is a compatibility escape hatch for low-level setup inspection,
    /// not the ownership-aware packet API. Because these views can publish or
    /// consume entries without updating the packet-path ledger, exposing them
    /// permanently retires this resource from `PacketIo` and
    /// `GeneratedPacketIo`; later authoritative operations fail closed.
    pub fn ring_views(&mut self) -> Result<XdpRingViews<'_>, RingMapError> {
        self.inner.ring_views()
    }

    /// Returns whether the resource can still enter the authoritative packet
    /// path. This crate-private boundary keeps `data_path` from reaching into
    /// the cold owner fields directly.
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    pub(crate) fn data_path_is_idle(&self) -> bool {
        self.inner.batch_state == BatchState::Idle
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    pub(crate) fn data_path_raw_views_exposed(&self) -> bool {
        self.inner.raw_views_exposed
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    pub(crate) fn data_path_nonquiescent_owner(&self) -> Option<(u32, crate::XdpChunkState)> {
        self.inner.ownership.has_nonquiescent_owner()
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    pub(crate) fn make_data_path_core<'owner>(
        &'owner mut self,
        kind: BatchState,
    ) -> Result<XdpBatchCore<'owner, 'static, LinuxSyscalls>, crate::XdpIoError> {
        self.inner.make_data_path_core(kind)
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
pub(crate) struct ResourceOwner<'umem, 'syscalls, S: Syscalls> {
    // Keep every mmap field before the fd field. This is both the documented
    // declaration-order invariant and the explicit order used by Drop below.
    _fill_mapping: MappedRegion<'syscalls, S>,
    _completion_mapping: MappedRegion<'syscalls, S>,
    _rx_mapping: MappedRegion<'syscalls, S>,
    _tx_mapping: MappedRegion<'syscalls, S>,
    socket: OwnedXdpFd<'syscalls, S>,
    umem_memory: &'umem mut [u8],
    umem: UmemConfig,
    rings: RingConfig,
    ifindex: u32,
    queue_id: u32,
    interface: IfId,
    bind_flags: ValidatedBindFlags,
    offsets: XdpMmapOffsets,
    fill_layout: RingMmapLayout,
    completion_layout: RingMmapLayout,
    rx_layout: RingMmapLayout,
    tx_layout: RingMmapLayout,
    ownership: XdpOwnership,
    batch_state: BatchState,
    fill_wakeup_pending: bool,
    tx_wakeup_pending: bool,
    /// A raw public ring view cannot update the ownership ledger. Such a
    /// resource is retired from the authoritative packet path.
    raw_views_exposed: bool,
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
impl<S: Syscalls> Drop for ResourceOwner<'_, '_, S> {
    fn drop(&mut self) {
        // Drop is deliberately best-effort. Callers that need to observe a
        // cleanup failure should use `ResourceOwner::close` through the public
        // `XdpResource::close` method.
        let _ = self.teardown();
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
impl<'umem, 'syscalls, S: Syscalls> ResourceOwner<'umem, 'syscalls, S> {
    /// Attempts every unmap before closing the socket and returns the first
    /// cleanup error, if any. Each underlying owner is made inactive before
    /// its syscall, so the consuming close method and the following Drop are
    /// exactly-once even when a syscall reports an error.
    pub(crate) fn close(mut self) -> Result<(), XdpSetupError> {
        self.teardown()
    }

    pub(crate) fn ring_views(&mut self) -> Result<XdpRingViews<'_>, RingMapError> {
        // The public view API predates the ownership-aware data path. It can
        // mutate ring cursors without going through `XdpOwnership`, so a
        // successful or attempted exposure retires this owner from the core
        // packet traits. The views themselves remain valid for this borrow.
        self.raw_views_exposed = true;
        self.make_ring_views()
    }

    fn make_ring_views(&mut self) -> Result<XdpRingViews<'_>, RingMapError> {
        let offsets = self.offsets;
        let rings = self.rings;
        let fill_layout = self.fill_layout;
        let completion_layout = self.completion_layout;
        let rx_layout = self.rx_layout;
        let tx_layout = self.tx_layout;

        let fill = FillProducer::new(
            self._fill_mapping.borrowed_ring(fill_layout)?,
            offsets.fill,
            rings.fill(),
        )?;
        let completion = CompletionConsumer::new(
            self._completion_mapping.borrowed_ring(completion_layout)?,
            offsets.completion,
            rings.completion(),
        )?;
        let rx = RxConsumer::new(
            self._rx_mapping.borrowed_ring(rx_layout)?,
            offsets.rx,
            rings.rx(),
        )?;
        let tx = TxProducer::new(
            self._tx_mapping.borrowed_ring(tx_layout)?,
            offsets.tx,
            rings.tx(),
        )?;

        Ok(XdpRingViews {
            fill,
            completion,
            rx,
            tx,
        })
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    pub(crate) fn make_data_path_core<'owner>(
        &'owner mut self,
        kind: BatchState,
    ) -> Result<XdpBatchCore<'owner, 'syscalls, S>, crate::XdpIoError> {
        let offsets = self.offsets;
        let rings = self.rings;
        let fill_layout = self.fill_layout;
        let completion_layout = self.completion_layout;
        let rx_layout = self.rx_layout;
        let tx_layout = self.tx_layout;

        let fill = FillProducer::new(
            self._fill_mapping
                .borrowed_ring(fill_layout)
                .map_err(crate::XdpIoError::from_ring_map)?,
            offsets.fill,
            rings.fill(),
        )
        .map_err(crate::XdpIoError::from_ring_map)?;
        let completion = CompletionConsumer::new(
            self._completion_mapping
                .borrowed_ring(completion_layout)
                .map_err(crate::XdpIoError::from_ring_map)?,
            offsets.completion,
            rings.completion(),
        )
        .map_err(crate::XdpIoError::from_ring_map)?;
        let rx = RxConsumer::new(
            self._rx_mapping
                .borrowed_ring(rx_layout)
                .map_err(crate::XdpIoError::from_ring_map)?,
            offsets.rx,
            rings.rx(),
        )
        .map_err(crate::XdpIoError::from_ring_map)?;
        let tx = TxProducer::new(
            self._tx_mapping
                .borrowed_ring(tx_layout)
                .map_err(crate::XdpIoError::from_ring_map)?,
            offsets.tx,
            rings.tx(),
        )
        .map_err(crate::XdpIoError::from_ring_map)?;

        Ok(XdpBatchCore::new(
            XdpRingViews {
                fill,
                completion,
                rx,
                tx,
            },
            &self.socket,
            self.umem_memory,
            &mut self.ownership,
            &mut self.batch_state,
            self.interface,
            &mut self.fill_wakeup_pending,
            &mut self.tx_wakeup_pending,
            kind,
        ))
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    pub(crate) fn initialize_data_path(&mut self) -> Result<(), crate::XdpIoError> {
        let mut core = self.make_data_path_core(BatchState::Maintenance)?;
        let first_error = core.refill_fill().err();
        let wake_error = core.wake_if_needed().err();
        core.release_state();
        first_error.or(wake_error).map_or(Ok(()), Err)
    }

    fn teardown(&mut self) -> Result<(), XdpSetupError> {
        let mut first_error = None;

        for result in [
            self._fill_mapping.unmap_once(),
            self._completion_mapping.unmap_once(),
            self._rx_mapping.unmap_once(),
            self._tx_mapping.unmap_once(),
        ] {
            if let Err(error) = result {
                if first_error.is_none() {
                    first_error = Some(map_resource_error(error));
                }
            }
        }

        if let Err(error) = self.socket.close_once() {
            if first_error.is_none() {
                first_error = Some(map_resource_error(error));
            }
        }

        first_error.map_or(Ok(()), Err)
    }

    #[cfg(test)]
    const fn mmap_offsets(&self) -> XdpMmapOffsets {
        self.offsets
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn validate_umem(memory: &mut [u8], config: UmemConfig) -> Result<(u64, u64), XdpSetupError> {
    let configured_len = config.byte_len();
    if configured_len > isize::MAX as u64 {
        return Err(XdpSetupError::UmemLengthExceedsAddressSpace {
            length: configured_len,
        });
    }
    let expected_len =
        usize::try_from(configured_len).map_err(|_| XdpSetupError::UmemLengthNotRepresentable {
            length: configured_len,
        })?;
    let actual_len =
        u64::try_from(memory.len()).map_err(|_| XdpSetupError::UmemLengthNotRepresentable {
            length: memory.len() as u64,
        })?;
    if memory.len() != expected_len {
        return Err(XdpSetupError::UmemLengthMismatch {
            expected: configured_len,
            actual: actual_len,
        });
    }

    let address_usize = memory.as_mut_ptr() as usize;
    let address =
        u64::try_from(address_usize).map_err(|_| XdpSetupError::UmemAddressNotRepresentable {
            address: address_usize,
        })?;
    if address == 0 {
        return Err(XdpSetupError::UmemAddressIsNull);
    }
    if address_usize.checked_add(memory.len()).is_none()
        || address.checked_add(actual_len).is_none()
    {
        return Err(XdpSetupError::UmemAddressRangeOverflow {
            address,
            length: actual_len,
        });
    }
    Ok((address, actual_len))
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn register_umem<S: Syscalls>(
    socket: &OwnedXdpFd<'_, S>,
    address: u64,
    len: u64,
    config: UmemConfig,
) -> Result<(), XdpSetupError> {
    let registration = XdpUmemReg {
        address,
        len,
        chunk_size: config.frame_size(),
        headroom: config.headroom(),
        flags: 0,
        tx_metadata_len: 0,
    };
    debug_assert_eq!(
        ABI_UMEM_REG_SOURCE,
        "/usr/src/linux-headers-6.8.0-137/include/uapi/linux/if_xdp.h:83-90"
    );
    let bytes = encode_xdp_umem_reg(registration);
    socket
        .set_socket_option(SOL_XDP, XDP_UMEM_REG, &bytes)
        .map_err(map_resource_error)
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn configure_ring<S: Syscalls>(
    socket: &OwnedXdpFd<'_, S>,
    option: i32,
    entries: RingEntries,
) -> Result<(), XdpSetupError> {
    let bytes = entries.get().to_ne_bytes();
    socket
        .set_socket_option(SOL_XDP, option, &bytes)
        .map_err(map_resource_error)
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn query_mmap_offsets<S: Syscalls>(
    socket: &OwnedXdpFd<'_, S>,
) -> Result<XdpMmapOffsets, XdpSetupError> {
    let expected = std::mem::size_of::<XdpMmapOffsets>();
    let mut bytes = [0_u8; std::mem::size_of::<XdpMmapOffsets>()];
    let actual = match socket.get_socket_option(SOL_XDP, XDP_MMAP_OFFSETS, &mut bytes) {
        Ok(actual) => actual,
        Err(ResourceError::Argument(SyscallArgumentError::KernelLengthOutOfBounds {
            actual,
            ..
        })) => {
            return Err(XdpSetupError::MmapOffsetsLengthMismatch { expected, actual });
        }
        Err(error) => return Err(map_resource_error(error)),
    };
    if actual != expected {
        return Err(XdpSetupError::MmapOffsetsLengthMismatch { expected, actual });
    }
    decode_xdp_mmap_offsets(&bytes)
        .ok_or(XdpSetupError::MmapOffsetsLengthMismatch { expected, actual })
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn checked_ring_layout(
    ring: RingName,
    offsets: crate::abi::XdpRingOffset,
    entries: RingEntries,
    element: RingElement,
) -> Result<RingMmapLayout, XdpSetupError> {
    RingMmapLayout::new(offsets, entries, element)
        .map_err(|source| XdpSetupError::RingLayout { ring, source })
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn map_ring<'syscalls, S: Syscalls>(
    socket: &OwnedXdpFd<'syscalls, S>,
    ring: RingName,
    layout: RingMmapLayout,
    offset: u64,
) -> Result<MappedRegion<'syscalls, S>, XdpSetupError> {
    let length = layout.byte_len();
    let length_u64 = u64::try_from(length)
        .map_err(|_| XdpSetupError::RingMmapLengthExceedsAddressSpace { ring, length })?;
    let offset_off_t = i64::try_from(offset).map_err(|_| {
        XdpSetupError::SyscallArgument(XdpSetupArgumentError::OffsetDoesNotFitOffT { offset })
    })?;
    let length_off_t = i64::try_from(length)
        .map_err(|_| XdpSetupError::RingMmapLengthExceedsAddressSpace { ring, length })?;
    if length > isize::MAX as usize {
        return Err(XdpSetupError::RingMmapLengthExceedsAddressSpace { ring, length });
    }
    offset
        .checked_add(length_u64)
        .ok_or(XdpSetupError::RingMmapExtentOverflow {
            ring,
            offset,
            length,
        })?;
    offset_off_t
        .checked_add(length_off_t)
        .ok_or(XdpSetupError::RingMmapExtentOverflow {
            ring,
            offset,
            length,
        })?;
    socket
        .map_shared(length, offset)
        .map_err(map_resource_error)
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn map_resource_error(error: ResourceError) -> XdpSetupError {
    match error {
        ResourceError::Platform(error) => XdpSetupError::Platform(error),
        ResourceError::Argument(error) => XdpSetupError::SyscallArgument(map_argument_error(error)),
        ResourceError::Syscall(error) => XdpSetupError::Syscall {
            stage: map_stage(error.stage),
            errno: error.errno.raw(),
        },
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn map_argument_error(error: SyscallArgumentError) -> XdpSetupArgumentError {
    match error {
        SyscallArgumentError::InvalidFileDescriptor => XdpSetupArgumentError::InvalidFileDescriptor,
        SyscallArgumentError::ZeroLength { stage } => XdpSetupArgumentError::ZeroLength {
            stage: map_stage(stage),
        },
        SyscallArgumentError::LengthDoesNotFitSockLen { stage, length } => {
            XdpSetupArgumentError::LengthDoesNotFitSockLen {
                stage: map_stage(stage),
                length,
            }
        }
        SyscallArgumentError::OffsetDoesNotFitOffT { offset } => {
            XdpSetupArgumentError::OffsetDoesNotFitOffT { offset }
        }
        SyscallArgumentError::KernelLengthOutOfBounds { capacity, actual } => {
            XdpSetupArgumentError::KernelLengthOutOfBounds { capacity, actual }
        }
        SyscallArgumentError::LengthDoesNotFitAddressSpace { stage, length } => {
            XdpSetupArgumentError::LengthDoesNotFitAddressSpace {
                stage: map_stage(stage),
                length,
            }
        }
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const fn map_stage(stage: SyscallStage) -> XdpSetupStage {
    match stage {
        SyscallStage::OpenSocket => XdpSetupStage::OpenSocket,
        SyscallStage::SetSocketOption => XdpSetupStage::SetSocketOption,
        SyscallStage::GetSocketOption => XdpSetupStage::GetSocketOption,
        SyscallStage::MapMemory => XdpSetupStage::MapMemory,
        SyscallStage::UnmapMemory => XdpSetupStage::UnmapMemory,
        SyscallStage::BindSocket => XdpSetupStage::BindSocket,
        SyscallStage::PollSocket => XdpSetupStage::PollSocket,
        SyscallStage::SendToSocket => XdpSetupStage::SendToSocket,
        SyscallStage::CloseSocket => XdpSetupStage::CloseSocket,
    }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
const fn native_platform_error() -> crate::NativeSyscallPlatformError {
    if !cfg!(target_os = "linux") {
        crate::NativeSyscallPlatformError::UnsupportedOperatingSystem
    } else if !cfg!(target_pointer_width = "64") {
        crate::NativeSyscallPlatformError::UnsupportedPointerWidth
    } else {
        crate::NativeSyscallPlatformError::UnsupportedArchitecture
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        mem::size_of,
        os::fd::RawFd,
    };

    use super::*;
    use crate::abi::{
        encode_xdp_mmap_offsets, RingElement, XdpDescriptor, XdpRingOffset, XDP_RING_NEED_WAKEUP,
    };
    use crate::{AbiLayoutError, BindMode, ConfigError, NeedWakeup, RingField};

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    use crate::native_unsafe::syscall::{sealed, Errno, MapRequest, PollDescriptor};

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    const TEST_OFFSETS: XdpMmapOffsets = XdpMmapOffsets {
        rx: XdpRingOffset {
            producer: 0,
            consumer: 64,
            descriptors: 192,
            flags: 128,
        },
        tx: XdpRingOffset {
            producer: 0,
            consumer: 64,
            descriptors: 192,
            flags: 128,
        },
        fill: XdpRingOffset {
            producer: 0,
            consumer: 64,
            descriptors: 192,
            flags: 128,
        },
        completion: XdpRingOffset {
            producer: 0,
            consumer: 64,
            descriptors: 192,
            flags: 128,
        },
    };

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    const TEST_ERRNO: Errno = Errno::Linux(13);

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    const MAX_CALLS: usize = 32;

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Call {
        Socket,
        SetSocketOption {
            name: i32,
            length: u32,
        },
        GetSocketOption {
            name: i32,
            capacity: u32,
        },
        Mmap {
            fd: RawFd,
            byte_len: usize,
            offset: i64,
        },
        Munmap {
            byte_len: usize,
        },
        Bind {
            length: u32,
        },
        Close {
            fd: RawFd,
        },
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    struct FakeSyscalls {
        calls: RefCell<Vec<Call>>,
        options: RefCell<Vec<Vec<u8>>>,
        bind: RefCell<Vec<u8>>,
        mappings: RefCell<Vec<Box<[u8]>>>,
        fail: Cell<Option<SyscallStage>>,
        returned: RefCell<Vec<u8>>,
        returned_len: Cell<Option<u32>>,
        forced_mmap_address: Cell<Option<usize>>,
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    impl FakeSyscalls {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::with_capacity(MAX_CALLS)),
                options: RefCell::new(Vec::with_capacity(MAX_CALLS)),
                bind: RefCell::new(Vec::new()),
                mappings: RefCell::new(Vec::with_capacity(4)),
                fail: Cell::new(None),
                returned: RefCell::new(Vec::new()),
                returned_len: Cell::new(None),
                forced_mmap_address: Cell::new(None),
            }
        }

        fn set_offsets(&self, offsets: XdpMmapOffsets) {
            *self.returned.borrow_mut() = encode_xdp_mmap_offsets(offsets).to_vec();
            self.returned_len.set(Some(
                u32::try_from(size_of::<XdpMmapOffsets>()).expect("test length"),
            ));
        }

        fn set_returned_len(&self, length: u32) {
            self.returned_len.set(Some(length));
        }

        fn set_next_mmap_address(&self, address: usize) {
            self.forced_mmap_address.set(Some(address));
        }

        fn result(&self, stage: SyscallStage) -> Result<(), Errno> {
            if self.fail.get() == Some(stage) {
                Err(TEST_ERRNO)
            } else {
                Ok(())
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.borrow().clone()
        }

        fn count_unmaps(&self) -> usize {
            self.calls
                .borrow()
                .iter()
                .filter(|call| matches!(call, Call::Munmap { .. }))
                .count()
        }

        fn count_closes(&self) -> usize {
            self.calls
                .borrow()
                .iter()
                .filter(|call| matches!(call, Call::Close { .. }))
                .count()
        }
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    impl sealed::Sealed for FakeSyscalls {}

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    impl Syscalls for FakeSyscalls {
        fn socket(&self, _domain: i32, _kind: i32, _protocol: i32) -> Result<RawFd, Errno> {
            self.calls.borrow_mut().push(Call::Socket);
            self.result(SyscallStage::OpenSocket).map(|()| 17)
        }

        fn set_socket_option(
            &self,
            _fd: RawFd,
            _level: i32,
            name: i32,
            value: &[u8],
            length: u32,
        ) -> Result<(), Errno> {
            self.calls
                .borrow_mut()
                .push(Call::SetSocketOption { name, length });
            self.options.borrow_mut().push(value.to_vec());
            self.result(SyscallStage::SetSocketOption)
        }

        fn get_socket_option(
            &self,
            _fd: RawFd,
            _level: i32,
            name: i32,
            value: &mut [u8],
            length: &mut u32,
        ) -> Result<(), Errno> {
            self.calls.borrow_mut().push(Call::GetSocketOption {
                name,
                capacity: *length,
            });
            self.result(SyscallStage::GetSocketOption)?;
            value.fill(0xa5);
            let returned = self.returned.borrow();
            let copied = returned.len().min(value.len());
            value[..copied].copy_from_slice(&returned[..copied]);
            *length = self
                .returned_len
                .get()
                .unwrap_or_else(|| u32::try_from(value.len()).expect("test length"));
            Ok(())
        }

        fn mmap(&self, request: MapRequest) -> Result<*mut std::ffi::c_void, Errno> {
            let (fd, byte_len, offset) = match request {
                MapRequest::Anonymous { byte_len } => (-1, byte_len, 0),
                MapRequest::Shared {
                    fd,
                    byte_len,
                    offset,
                } => (fd, byte_len, offset),
            };
            self.calls.borrow_mut().push(Call::Mmap {
                fd,
                byte_len,
                offset,
            });
            self.result(SyscallStage::MapMemory)?;
            if let Some(address) = self.forced_mmap_address.take() {
                return Ok(address as *mut std::ffi::c_void);
            }
            let mut backing = vec![0_u8; byte_len].into_boxed_slice();
            let address = backing.as_mut_ptr().cast::<std::ffi::c_void>();
            self.mappings.borrow_mut().push(backing);
            Ok(address)
        }

        fn munmap(&self, _address: *mut std::ffi::c_void, byte_len: usize) -> Result<(), Errno> {
            self.calls.borrow_mut().push(Call::Munmap { byte_len });
            self.result(SyscallStage::UnmapMemory)
        }

        fn bind(&self, _fd: RawFd, address: &[u8], length: u32) -> Result<(), Errno> {
            self.calls.borrow_mut().push(Call::Bind { length });
            *self.bind.borrow_mut() = address.to_vec();
            self.result(SyscallStage::BindSocket)
        }

        fn poll(
            &self,
            _descriptor: &mut PollDescriptor,
            _timeout_millis: i32,
        ) -> Result<u32, Errno> {
            self.result(SyscallStage::PollSocket).map(|()| 0)
        }

        fn send_to_wakeup(&self, _fd: RawFd) -> Result<(), Errno> {
            self.result(SyscallStage::SendToSocket)
        }

        fn bpf(&self, _command: u32, _attr: &mut [u8]) -> Result<std::ffi::c_long, Errno> {
            Ok(0)
        }

        fn close(&self, fd: RawFd) -> Result<(), Errno> {
            self.calls.borrow_mut().push(Call::Close { fd });
            self.result(SyscallStage::CloseSocket)
        }
    }

    fn valid_config() -> (UmemConfig, RingConfig) {
        (
            UmemConfig::new(2, 2_048, 256, 1, 1, 0).expect("UMEM config"),
            RingConfig::new(4, 4, 4, 4).expect("ring config"),
        )
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    fn build_builder() -> XdpResourceBuilder {
        let (umem, rings) = valid_config();
        XdpResourceBuilder::new(umem, rings, 7, 3).expect("builder")
    }

    fn write_u32(memory: &mut [u8], offset: usize, value: u32) {
        memory[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_ne_bytes());
    }

    fn read_u32(memory: &[u8], offset: usize) -> u32 {
        u32::from_ne_bytes(
            memory[offset..offset + size_of::<u32>()]
                .try_into()
                .expect("four bytes"),
        )
    }

    fn write_descriptor(memory: &mut [u8], offset: usize, descriptor: XdpDescriptor) {
        memory[offset..offset + 8].copy_from_slice(&descriptor.address.to_ne_bytes());
        memory[offset + 8..offset + 12].copy_from_slice(&descriptor.len.to_ne_bytes());
        memory[offset + 12..offset + 16].copy_from_slice(&descriptor.options.to_ne_bytes());
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn setup_registers_exact_umem_and_ring_arguments_before_bind() {
        let syscalls = FakeSyscalls::new();
        syscalls.set_offsets(TEST_OFFSETS);
        let builder = build_builder();
        let mut memory = vec![0_u8; 4_096];
        let expected_address = memory.as_mut_ptr() as u64;
        let resource = builder
            .build_with_syscalls(&mut memory, &syscalls)
            .expect("fake setup");

        let options = syscalls.options.borrow();
        assert_eq!(options.len(), 5);
        let umem = XdpUmemReg {
            address: expected_address,
            len: 4_096,
            chunk_size: 2_048,
            headroom: 256,
            flags: 0,
            tx_metadata_len: 0,
        };
        assert_eq!(options[0], encode_xdp_umem_reg(umem));
        assert_eq!(options[1], 4_u32.to_ne_bytes());
        assert_eq!(options[2], 4_u32.to_ne_bytes());
        assert_eq!(options[3], 4_u32.to_ne_bytes());
        assert_eq!(options[4], 4_u32.to_ne_bytes());
        assert_eq!(*syscalls.bind.borrow(), {
            encode_sockaddr_xdp(SockAddrXdp {
                family: AF_XDP as u16,
                flags: XDP_USE_NEED_WAKEUP,
                ifindex: 7,
                queue_id: 3,
                shared_umem_fd: 0,
            })
            .to_vec()
        });
        assert_eq!(resource.mmap_offsets(), TEST_OFFSETS);
        drop(resource);
        assert_eq!(syscalls.count_unmaps(), 4);
        assert_eq!(syscalls.count_closes(), 1);
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn setup_connects_all_four_views_to_their_mapped_ring_offsets() {
        let syscalls = FakeSyscalls::new();
        syscalls.set_offsets(TEST_OFFSETS);
        let builder = build_builder();
        let mut memory = vec![0_u8; 4_096];
        let mut resource = builder
            .build_with_syscalls(&mut memory, &syscalls)
            .expect("fake setup");

        let rx_descriptor = XdpDescriptor {
            address: 2_304,
            len: 64,
            options: 0,
        };
        let completion_address = 4_352_u64;
        {
            // The backing allocations are the fake kernel's mmap storage. The
            // writes below model kernel publication before the application
            // borrows the views.
            let mut mappings = syscalls.mappings.borrow_mut();
            write_u32(
                &mut mappings[0],
                TEST_OFFSETS.fill.flags as usize,
                XDP_RING_NEED_WAKEUP,
            );
            write_u32(&mut mappings[3], TEST_OFFSETS.tx.flags as usize, 0);
            write_u32(
                &mut mappings[1],
                TEST_OFFSETS.completion.producer as usize,
                1,
            );
            mappings[1][TEST_OFFSETS.completion.descriptors as usize
                ..TEST_OFFSETS.completion.descriptors as usize + size_of::<u64>()]
                .copy_from_slice(&completion_address.to_ne_bytes());
            write_u32(&mut mappings[2], TEST_OFFSETS.rx.producer as usize, 1);
            write_descriptor(
                &mut mappings[2],
                TEST_OFFSETS.rx.descriptors as usize,
                rx_descriptor,
            );
        }

        {
            let mut views = resource.ring_views().expect("four ring views");
            assert_eq!(views.fill.capacity(), 4);
            assert_eq!(views.completion.capacity(), 4);
            assert_eq!(views.rx.capacity(), 4);
            assert_eq!(views.tx.capacity(), 4);
            assert_eq!(views.fill.need_wakeup(), Ok(NeedWakeup::Required));
            assert_eq!(views.tx.need_wakeup(), Ok(NeedWakeup::NotRequired));

            // These independent mutable borrows compile while all four views
            // remain held in one tick.
            let mut fill_reservation = views.fill.reserve(1).expect("fill reserve");
            let mut tx_reservation = views.tx.reserve(1).expect("tx reserve");
            fill_reservation.write(1_024).expect("fill address");
            tx_reservation
                .write(XdpDescriptor {
                    address: 6_400,
                    len: 128,
                    options: 0,
                })
                .expect("tx descriptor");
            assert_eq!(
                fill_reservation
                    .release_submit()
                    .expect("fill publish")
                    .need_wakeup(),
                Ok(NeedWakeup::Required)
            );
            assert_eq!(
                tx_reservation
                    .release_submit()
                    .expect("tx publish")
                    .need_wakeup(),
                Ok(NeedWakeup::NotRequired)
            );

            let mut rx = views.rx.acquire(1).expect("rx acquire");
            assert_eq!(rx.read(), Ok(rx_descriptor));
            rx.release_consume().expect("rx consume");

            let mut completion = views.completion.acquire(1).expect("completion acquire");
            assert_eq!(completion.read(), Ok(completion_address));
            completion.release_consume().expect("completion consume");
        }

        let mappings = syscalls.mappings.borrow();
        assert_eq!(
            read_u32(&mappings[0], TEST_OFFSETS.fill.producer as usize),
            2
        );
        assert_eq!(read_u32(&mappings[3], TEST_OFFSETS.tx.producer as usize), 1);
        assert_eq!(read_u32(&mappings[2], TEST_OFFSETS.rx.consumer as usize), 1);
        assert_eq!(
            read_u32(&mappings[1], TEST_OFFSETS.completion.consumer as usize),
            1
        );
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn setup_rejects_malformed_offsets_before_any_ring_mapping() {
        let syscalls = FakeSyscalls::new();
        syscalls.set_offsets(XdpMmapOffsets {
            fill: XdpRingOffset {
                descriptors: u64::MAX - 7,
                ..TEST_OFFSETS.fill
            },
            ..TEST_OFFSETS
        });
        let builder = build_builder();
        let mut memory = vec![0_u8; 4_096];

        assert_eq!(
            builder
                .build_with_syscalls(&mut memory, &syscalls)
                .err()
                .expect("malformed offsets"),
            XdpSetupError::RingLayout {
                ring: RingName::Fill,
                source: AbiLayoutError::ExtentOverflow {
                    field: RingField::Descriptors,
                },
            }
        );
        assert_eq!(syscalls.count_unmaps(), 0);
        assert_eq!(syscalls.count_closes(), 1);
        assert!(!syscalls
            .calls()
            .iter()
            .any(|call| matches!(call, Call::Mmap { .. })));
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn setup_borrowed_ring_rejects_null_wrapping_and_inactive_mappings() {
        let entries = RingEntries::new(RingName::Fill, 4).expect("ring entries");
        let layout = RingMmapLayout::new(TEST_OFFSETS.fill, entries, RingElement::UmemAddress)
            .expect("ring layout");

        let null_syscalls = FakeSyscalls::new();
        null_syscalls.set_next_mmap_address(0);
        let null_socket = OwnedXdpFd::open(&null_syscalls).expect("fake socket");
        let mut null_mapping = null_socket
            .map_shared(layout.byte_len(), XDP_UMEM_PGOFF_FILL_RING)
            .expect("null fake mapping");
        assert_eq!(
            null_mapping.borrowed_ring(layout),
            Err(RingMapError::MappingAddressIsNull)
        );

        let wrapping_syscalls = FakeSyscalls::new();
        let wrapping_address = usize::MAX - (layout.byte_len() - 1);
        wrapping_syscalls.set_next_mmap_address(wrapping_address);
        let wrapping_socket = OwnedXdpFd::open(&wrapping_syscalls).expect("fake socket");
        let mut wrapping_mapping = wrapping_socket
            .map_shared(layout.byte_len(), XDP_UMEM_PGOFF_FILL_RING)
            .expect("wrapping fake mapping");
        assert_eq!(
            wrapping_mapping.borrowed_ring(layout),
            Err(RingMapError::MappingAddressRangeOverflow {
                address: wrapping_address,
                length: layout.byte_len(),
            })
        );

        let inactive_syscalls = FakeSyscalls::new();
        let inactive_socket = OwnedXdpFd::open(&inactive_syscalls).expect("fake socket");
        let mut inactive_mapping = inactive_socket
            .map_shared(layout.byte_len(), XDP_UMEM_PGOFF_FILL_RING)
            .expect("inactive fake mapping");
        inactive_mapping.unmap_once().expect("fake unmap");
        assert_eq!(
            inactive_mapping.borrowed_ring(layout),
            Err(RingMapError::MappingInactive)
        );
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn setup_borrowed_ring_boundary_and_shape_contracts_fail_closed() {
        let syscalls = FakeSyscalls::new();
        let socket = OwnedXdpFd::open(&syscalls).expect("fake socket");
        let entries = RingEntries::new(RingName::Rx, 4).expect("ring entries");

        let boundary_layout = RingMmapLayout::new(
            XdpRingOffset {
                descriptors: 248,
                ..TEST_OFFSETS.rx
            },
            entries,
            RingElement::UmemAddress,
        )
        .expect("boundary layout arithmetic");
        assert_eq!(
            boundary_layout.byte_len(),
            248 + entries.get() as usize * size_of::<u64>()
        );
        let mut short_boundary = socket
            .map_shared(256, XDP_PGOFF_RX_RING)
            .expect("short fake mapping");
        assert_eq!(
            short_boundary.borrowed_ring(boundary_layout),
            Err(RingMapError::MappingTooShort {
                required: 280,
                actual: 256,
            })
        );

        let packet_layout =
            RingMmapLayout::new(TEST_OFFSETS.rx, entries, RingElement::PacketDescriptor)
                .expect("packet layout");
        assert_eq!(
            packet_layout.byte_len(),
            TEST_OFFSETS.rx.descriptors as usize
                + entries.get() as usize * size_of::<XdpDescriptor>()
        );
        let mut short_element = socket
            .map_shared(224, XDP_PGOFF_RX_RING)
            .expect("short element mapping");
        assert_eq!(
            short_element.borrowed_ring(packet_layout),
            Err(RingMapError::MappingTooShort {
                required: 256,
                actual: 224,
            })
        );

        let larger_entries = RingEntries::new(RingName::Rx, 8).expect("larger ring entries");
        let larger_ring = RingMmapLayout::new(
            TEST_OFFSETS.rx,
            larger_entries,
            RingElement::PacketDescriptor,
        )
        .expect("larger packet layout");
        assert_eq!(
            larger_ring.byte_len(),
            TEST_OFFSETS.rx.descriptors as usize
                + larger_entries.get() as usize * size_of::<XdpDescriptor>()
        );
        let mut short_ring = socket
            .map_shared(256, XDP_PGOFF_RX_RING)
            .expect("short ring mapping");
        assert_eq!(
            short_ring.borrowed_ring(larger_ring),
            Err(RingMapError::MappingTooShort {
                required: 320,
                actual: 256,
            })
        );
    }

    #[test]
    fn setup_builder_rejects_invalid_chunk_frame_and_memory_geometry() {
        assert_eq!(
            UmemConfig::new(0, 2_048, 256, 0, 0, 0),
            Err(ConfigError::ZeroFrameCount)
        );
        assert_eq!(
            UmemConfig::new(2, 1_024, 0, 1, 1, 0),
            Err(ConfigError::InvalidFrameSize(1_024))
        );

        let (umem, rings) = valid_config();
        let builder = XdpResourceBuilder::new(umem, rings, 1, 0).expect("builder");
        assert_eq!(
            builder.with_raw_bind_flags(0),
            Err(XdpSetupError::Config(ConfigError::NeedWakeupRequired))
        );

        #[cfg(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        ))]
        {
            let syscalls = FakeSyscalls::new();
            syscalls.set_offsets(TEST_OFFSETS);
            let mut short_memory = vec![0_u8; 2_048];
            assert_eq!(
                builder
                    .build_with_syscalls(&mut short_memory, &syscalls)
                    .err()
                    .expect("short UMEM"),
                XdpSetupError::UmemLengthMismatch {
                    expected: 4_096,
                    actual: 2_048,
                }
            );
            assert!(syscalls.calls.borrow().is_empty());
        }
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn setup_rejects_short_mmap_offsets_before_mapping() {
        let syscalls = FakeSyscalls::new();
        syscalls.set_offsets(TEST_OFFSETS);
        syscalls.set_returned_len(u32::try_from(size_of::<XdpMmapOffsets>() - 8).expect("length"));
        let builder = build_builder();
        let mut memory = vec![0_u8; 4_096];
        assert_eq!(
            builder
                .build_with_syscalls(&mut memory, &syscalls)
                .err()
                .expect("short offsets"),
            XdpSetupError::MmapOffsetsLengthMismatch {
                expected: size_of::<XdpMmapOffsets>(),
                actual: size_of::<XdpMmapOffsets>() - 8,
            }
        );
        assert_eq!(syscalls.count_unmaps(), 0);
        assert_eq!(syscalls.count_closes(), 1);
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn setup_rejects_mmap_extent_outside_linux_off_t_before_mapping() {
        let syscalls = FakeSyscalls::new();
        let socket = OwnedXdpFd::open(&syscalls).expect("fake socket");
        let layout = RingMmapLayout::new(
            TEST_OFFSETS.rx,
            RingEntries::new(RingName::Rx, 4).expect("ring entries"),
            RingElement::PacketDescriptor,
        )
        .expect("ring layout");

        let overflowing_extent = u64::try_from(i64::MAX).expect("positive i64 max") - 1;
        assert!(matches!(
            map_ring(&socket, RingName::Rx, layout, overflowing_extent),
            Err(XdpSetupError::RingMmapExtentOverflow {
                ring: RingName::Rx,
                offset,
                length,
            }) if offset == overflowing_extent && length == layout.byte_len()
        ));
        let unrepresentable_offset = u64::try_from(i64::MAX).expect("positive i64 max") + 1;
        assert!(matches!(
            map_ring(&socket, RingName::Rx, layout, unrepresentable_offset),
            Err(XdpSetupError::SyscallArgument(
                XdpSetupArgumentError::OffsetDoesNotFitOffT {
                    offset,
                }
            )) if offset == unrepresentable_offset
        ));
        assert!(!syscalls
            .calls()
            .iter()
            .any(|call| matches!(call, Call::Mmap { .. })));
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn setup_bind_failure_unwinds_all_mmaps_before_fd_close() {
        let syscalls = FakeSyscalls::new();
        syscalls.set_offsets(TEST_OFFSETS);
        syscalls.fail.set(Some(SyscallStage::BindSocket));
        let builder = build_builder();
        let mut memory = vec![0_u8; 4_096];
        assert!(matches!(
            builder.build_with_syscalls(&mut memory, &syscalls),
            Err(XdpSetupError::Syscall {
                stage: XdpSetupStage::BindSocket,
                errno: Some(13),
            })
        ));
        assert_eq!(syscalls.count_unmaps(), 4);
        assert_eq!(syscalls.count_closes(), 1);
        let calls = syscalls.calls();
        let close_index = calls
            .iter()
            .position(|call| matches!(call, Call::Close { .. }))
            .expect("close");
        assert!(calls[..close_index]
            .iter()
            .rev()
            .take(4)
            .all(|call| matches!(call, Call::Munmap { .. })));
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn setup_drop_unmaps_every_ring_before_closing_fd() {
        let syscalls = FakeSyscalls::new();
        syscalls.set_offsets(TEST_OFFSETS);
        let builder = build_builder();
        let mut memory = vec![0_u8; 4_096];
        let resource = builder
            .build_with_syscalls(&mut memory, &syscalls)
            .expect("fake setup");
        drop(resource);
        let calls = syscalls.calls();
        let close_index = calls
            .iter()
            .position(|call| matches!(call, Call::Close { .. }))
            .expect("close");
        assert_eq!(calls[close_index + 1..].len(), 0);
        assert_eq!(
            calls[..close_index]
                .iter()
                .filter(|call| matches!(call, Call::Munmap { .. }))
                .count(),
            4
        );
        assert!(calls[..close_index]
            .iter()
            .rev()
            .take(4)
            .all(|call| matches!(call, Call::Munmap { .. })));
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn setup_explicit_close_attempts_all_cleanup_and_drop_does_not_repeat() {
        let syscalls = FakeSyscalls::new();
        syscalls.set_offsets(TEST_OFFSETS);
        let builder = build_builder();
        let mut memory = vec![0_u8; 4_096];
        let resource = builder
            .build_with_syscalls(&mut memory, &syscalls)
            .expect("fake setup");

        syscalls.fail.set(Some(SyscallStage::UnmapMemory));
        assert_eq!(
            resource.close(),
            Err(XdpSetupError::Syscall {
                stage: XdpSetupStage::UnmapMemory,
                errno: Some(13),
            })
        );

        let calls = syscalls.calls();
        assert_eq!(
            calls
                .iter()
                .filter(|call| matches!(call, Call::Munmap { .. }))
                .count(),
            4
        );
        let close_index = calls
            .iter()
            .position(|call| matches!(call, Call::Close { .. }))
            .expect("close after all unmaps");
        assert_eq!(close_index + 1, calls.len());
        assert!(calls[..close_index]
            .iter()
            .rev()
            .take(4)
            .all(|call| matches!(call, Call::Munmap { .. })));
        assert_eq!(
            calls
                .iter()
                .filter(|call| matches!(call, Call::Close { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn setup_default_is_automatic_and_explicit_modes_remain_checked() {
        let (umem, rings) = valid_config();
        let builder = XdpResourceBuilder::new(umem, rings, 1, 0).expect("builder");
        assert_eq!(builder.bind_flags().mode(), BindMode::Automatic);
        let copy = builder
            .with_raw_bind_flags(XDP_USE_NEED_WAKEUP | crate::abi::XDP_COPY)
            .expect("copy flags");
        assert_eq!(copy.bind_flags().mode(), BindMode::CopyRequired);
        let zero = builder
            .with_raw_bind_flags(XDP_USE_NEED_WAKEUP | crate::abi::XDP_ZEROCOPY)
            .expect("zero-copy flags");
        assert_eq!(zero.bind_flags().mode(), BindMode::ZeroCopyRequired);
    }
}
