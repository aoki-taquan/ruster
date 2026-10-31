use std::{
    ffi::{c_int, c_void},
    marker::PhantomData,
    mem::{align_of, offset_of, size_of},
    os::fd::RawFd,
    ptr::NonNull,
    sync::atomic::{fence, AtomicU32, Ordering},
};

use ruster_core::IfId;

use crate::{
    boundary::{ColdRingMetadata, CombinedRingExtents},
    BackendStats, Errno, MappingAccessError, OwnershipError, PlatformError, PortTable, RingKind,
    RingLayout, SyscallStage, TxOwnership, UapiLayout, ValidatedConfig, ValidatedPort,
    TPACKET_ALIGNMENT, TPACKET_V3_TX_DATA_OFFSET, TP_STATUS_AVAILABLE, TP_STATUS_SENDING,
    TP_STATUS_SEND_REQUEST, TP_STATUS_WRONG_FORMAT,
};

mod packet_io;
mod rx;

#[allow(unused_imports)]
pub(crate) use rx::{
    RxBatch, RxBatchReport, RxBlockReturn, RxBlockToken, RxBudget, RxFault, RxNext, RxPacket,
    RxPacketToken, RxReleaseError, RxStop,
};

const AF_PACKET: c_int = 17;
const SOCK_RAW: c_int = 3;
const SOL_PACKET: c_int = 263;
const PACKET_RX_RING: c_int = 5;
const PACKET_VERSION: c_int = 10;
const PACKET_TX_RING: c_int = 13;
const PACKET_IGNORE_OUTGOING: c_int = 23;
const TPACKET_V3: c_int = 2;
const ETH_P_ALL: u16 = 0x0003;
const PROT_READ: c_int = 1;
const PROT_WRITE: c_int = 2;
const MAP_SHARED: c_int = 1;
const MSG_DONTWAIT: c_int = 0x40;

const _: [(); 0] = [(); crate::TP_STATUS_KERNEL as usize];
const _: [(); 1] = [(); crate::TP_STATUS_USER as usize];
const _: [(); 0] = [(); crate::TP_STATUS_AVAILABLE as usize];
const _: [(); 1] = [(); crate::TP_STATUS_SEND_REQUEST as usize];
const _: [(); 2] = [(); crate::TP_STATUS_SENDING as usize];
const _: [(); 4] = [(); crate::TP_STATUS_WRONG_FORMAT as usize];
const _: [(); 2] = [(); crate::TPACKET_V3_VERSION as usize];

#[repr(C)]
struct TpacketHdrVariant1 {
    tp_rxhash: u32,
    tp_vlan_tci: u32,
    tp_vlan_tpid: u16,
    tp_padding: u16,
}

#[repr(C)]
struct Tpacket3Hdr {
    tp_next_offset: u32,
    tp_sec: u32,
    tp_nsec: u32,
    tp_snaplen: u32,
    tp_len: u32,
    tp_status: u32,
    tp_mac: u16,
    tp_net: u16,
    hv1: TpacketHdrVariant1,
    tp_padding: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TpacketBdTs {
    ts_sec: u32,
    ts_nsec: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TpacketHdrV1 {
    block_status: u32,
    num_pkts: u32,
    offset_to_first_pkt: u32,
    blk_len: u32,
    seq_num: u64,
    ts_first_pkt: TpacketBdTs,
    ts_last_pkt: TpacketBdTs,
}

#[repr(C)]
union TpacketBlockHeader {
    bh1: TpacketHdrV1,
}

#[repr(C)]
struct TpacketBlockDesc {
    version: u32,
    offset_to_priv: u32,
    hdr: TpacketBlockHeader,
}

#[repr(C)]
struct TpacketReq3 {
    tp_block_size: u32,
    tp_block_nr: u32,
    tp_frame_size: u32,
    tp_frame_nr: u32,
    tp_retire_blk_tov: u32,
    tp_sizeof_priv: u32,
    tp_feature_req_word: u32,
}

#[repr(C)]
pub(crate) struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

impl SockaddrLl {
    fn packet_all(if_index: u32) -> Result<Self, PlatformError> {
        let sll_ifindex =
            i32::try_from(if_index).map_err(|_| PlatformError::InvalidSocketAddress {
                family: AF_PACKET as u16,
                if_index: -1,
            })?;
        let address = Self {
            sll_family: AF_PACKET as u16,
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        address.validate()?;
        Ok(address)
    }

    fn validate(&self) -> Result<(), PlatformError> {
        if self.sll_family != AF_PACKET as u16 || self.sll_ifindex <= 0 {
            return Err(PlatformError::InvalidSocketAddress {
                family: self.sll_family,
                if_index: self.sll_ifindex,
            });
        }
        Ok(())
    }
}

const _: [(); 48] = [(); size_of::<Tpacket3Hdr>()];
const _: [(); 48] = [(); size_of::<TpacketBlockDesc>()];
const _: [(); 8] = [(); align_of::<TpacketHdrV1>()];
const _: [(); 8] = [(); align_of::<TpacketBlockDesc>()];
const _: [(); 28] = [(); size_of::<TpacketReq3>()];
const _: [(); 20] = [(); size_of::<SockaddrLl>()];
const _: [(); 20] = [(); offset_of!(Tpacket3Hdr, tp_status)];
const _: [(); 24] = [(); offset_of!(Tpacket3Hdr, tp_mac)];
const _: [(); 8] = [(); offset_of!(TpacketBlockDesc, hdr)];
const _: [(); 16] = [(); offset_of!(TpacketHdrV1, seq_num)];
const _: [(); crate::TPACKET_V3_HDRLEN] = [(); size_of::<Tpacket3Hdr>() + size_of::<SockaddrLl>()];

pub(crate) fn validated_uapi_layout() -> Result<UapiLayout, PlatformError> {
    let layout = UapiLayout {
        tpacket3_header: size_of::<Tpacket3Hdr>(),
        tpacket3_status_offset: offset_of!(Tpacket3Hdr, tp_status),
        tpacket3_mac_offset: offset_of!(Tpacket3Hdr, tp_mac),
        tpacket_block_descriptor: size_of::<TpacketBlockDesc>(),
        tpacket_block_alignment: align_of::<TpacketBlockDesc>(),
        block_status_offset: offset_of!(TpacketBlockDesc, hdr),
        block_sequence_offset: offset_of!(TpacketBlockDesc, hdr)
            + offset_of!(TpacketHdrV1, seq_num),
        tpacket_request3: size_of::<TpacketReq3>(),
        sockaddr_ll: size_of::<SockaddrLl>(),
        tpacket3_hdrlen: crate::TPACKET_V3_HDRLEN,
        ethernet_mac_offset: crate::TPACKET_V3_ETHERNET_MAC_OFFSET,
    };
    if layout
        != (UapiLayout {
            tpacket3_header: 48,
            tpacket3_status_offset: 20,
            tpacket3_mac_offset: 24,
            tpacket_block_descriptor: 48,
            tpacket_block_alignment: 8,
            block_status_offset: 8,
            block_sequence_offset: 24,
            tpacket_request3: 28,
            sockaddr_ll: 20,
            tpacket3_hdrlen: 68,
            ethernet_mac_offset: 82,
        })
    {
        return Err(PlatformError::UapiLayoutMismatch);
    }
    Ok(layout)
}

pub(crate) trait PacketOps: Clone {
    fn open_socket(&mut self) -> Result<RawFd, PlatformError>;

    fn set_socket_option<T>(
        &mut self,
        fd: RawFd,
        option: c_int,
        value: &T,
        stage: SyscallStage,
    ) -> Result<(), PlatformError>;

    fn bind(&mut self, fd: RawFd, address: &SockaddrLl) -> Result<(), PlatformError>;

    fn map(&mut self, fd: RawFd, len: usize) -> Result<NonNull<u8>, PlatformError>;

    fn kick(&mut self, fd: RawFd) -> Result<(), PlatformError>;

    fn unmap(&mut self, base: NonNull<u8>, len: usize);

    fn close(&mut self, fd: RawFd);
}

#[derive(Clone, Copy)]
pub(crate) struct LinuxOps;

impl PacketOps for LinuxOps {
    fn open_socket(&mut self) -> Result<RawFd, PlatformError> {
        // SAFETY: `socket` has no borrowed pointer arguments. Protocol zero
        // keeps capture inactive until the later checked bind.
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW, 0) };
        if fd < 0 {
            Err(last_error(SyscallStage::Socket))
        } else {
            Ok(fd)
        }
    }

    fn set_socket_option<T>(
        &mut self,
        fd: RawFd,
        option: c_int,
        value: &T,
        stage: SyscallStage,
    ) -> Result<(), PlatformError> {
        // SAFETY: `value` is initialized for `size_of::<T>()` bytes and
        // remains borrowed until Linux copies it during this call.
        let result = unsafe {
            setsockopt(
                fd,
                SOL_PACKET,
                option,
                (value as *const T).cast(),
                u32::try_from(size_of::<T>()).expect("socket option size fits socklen_t"),
            )
        };
        if result < 0 {
            Err(last_error(stage))
        } else {
            Ok(())
        }
    }

    fn bind(&mut self, fd: RawFd, address: &SockaddrLl) -> Result<(), PlatformError> {
        // SAFETY: `address` is a fully initialized C-layout `sockaddr_ll` and
        // remains live until the blocking call returns.
        let result = unsafe {
            bind(
                fd,
                (address as *const SockaddrLl).cast(),
                u32::try_from(size_of::<SockaddrLl>()).expect("sockaddr_ll size fits socklen_t"),
            )
        };
        if result < 0 {
            Err(last_error(SyscallStage::Bind))
        } else {
            Ok(())
        }
    }

    fn map(&mut self, fd: RawFd, len: usize) -> Result<NonNull<u8>, PlatformError> {
        // SAFETY: this requests one shared mapping from the uniquely owned
        // packet socket. The returned sentinel and null address are handled.
        let address = unsafe {
            mmap(
                std::ptr::null_mut(),
                len,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                fd,
                0_i64,
            )
        };
        if address as isize == -1 {
            return Err(last_error(SyscallStage::Mmap));
        }
        let Some(base) = NonNull::new(address.cast::<u8>()) else {
            // SAFETY: mmap succeeded at address zero, which Rust cannot hold
            // in NonNull. Release that exact mapping before returning.
            let _ = unsafe { munmap(address, len) };
            return Err(PlatformError::Syscall {
                stage: SyscallStage::Mmap,
                errno: Errno::new(14),
            });
        };
        Ok(base)
    }

    fn kick(&mut self, fd: RawFd) -> Result<(), PlatformError> {
        // SAFETY: a zero-length send does not dereference the null payload.
        // MSG_DONTWAIT makes this a bounded notification attempt.
        let result = unsafe { send(fd, std::ptr::null(), 0, MSG_DONTWAIT) };
        if result < 0 {
            Err(last_error(SyscallStage::Kick))
        } else {
            Ok(())
        }
    }

    fn unmap(&mut self, base: NonNull<u8>, len: usize) {
        // SAFETY: the mapping owner calls this once with the exact live range.
        let _ = unsafe { munmap(base.as_ptr().cast(), len) };
    }

    fn close(&mut self, fd: RawFd) {
        // SAFETY: the socket owner calls this once for its unique fd.
        let _ = unsafe { close(fd) };
    }
}

// AP0 establishes and reviews the unsafe lifetime boundary. AP1-0 keeps the
// combined mapping owner intact while fixing checked disjoint extents and cold
// metadata. AP1-TX and AP1-RX drive them through private per-port state; AP2
// unifies both directions of every port in one `AfPacketEngine`, which also
// implements `ruster_core::PacketIo`.
#[allow(dead_code)]
pub(crate) struct PacketRingResources<O: PacketOps = LinuxOps> {
    // Field declaration order is the required Drop order: unmap before close.
    mapping: MmapRegion<O>,
    socket: PacketSocket<O>,
    interface: IfId,
    max_frame_len: usize,
    rx: RingLayout,
    extents: CombinedRingExtents,
    metadata: ColdRingMetadata,
    rx_cursor: rx::RxCursor,
    rx_stats: BackendStats,
    tx_state: TxPortState,
    #[cfg(test)]
    rx_injection: rx::RxFaultInjection,
    #[cfg(test)]
    probe: std::rc::Rc<PortProbe>,
}

/// Test-only exact operation counters for one port.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProbeCounts {
    pub(crate) rx_status_reads: usize,
    pub(crate) rx_blocks_acquired: usize,
    pub(crate) rx_descriptor_visits: usize,
    pub(crate) rx_blocks_returned: usize,
    pub(crate) tx_submit_status_reads: usize,
    pub(crate) tx_completion_status_reads: usize,
    pub(crate) tx_copies: usize,
    pub(crate) tx_copied_bytes: usize,
}

/// Test-only probe shared with a conformance observer. Production builds
/// carry no such field; the counters let tests assert the exact work each
/// budget admits instead of inferring it from outcomes. `at_last_return`
/// freezes the counters at the most recent RX block return so per-block
/// observations exclude work done for the next ownership cycle.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct PortProbe {
    counts: std::cell::Cell<ProbeCounts>,
    at_last_return: std::cell::Cell<ProbeCounts>,
}

#[cfg(test)]
impl PortProbe {
    pub(crate) fn record(&self, update: impl FnOnce(&mut ProbeCounts)) {
        let mut counts = self.counts.get();
        update(&mut counts);
        self.counts.set(counts);
    }

    pub(crate) fn mark_rx_return(&self) {
        self.record(|counts| counts.rx_blocks_returned += 1);
        self.at_last_return.set(self.counts.get());
    }

    pub(crate) fn counts(&self) -> ProbeCounts {
        self.counts.get()
    }

    pub(crate) fn at_last_return(&self) -> ProbeCounts {
        self.at_last_return.get()
    }
}

#[allow(dead_code)]
impl PacketRingResources<LinuxOps> {
    pub(crate) fn open(port: ValidatedPort) -> Result<Self, PlatformError> {
        Self::open_with_ops(port, LinuxOps)
    }
}

#[allow(dead_code)]
impl<O: PacketOps> PacketRingResources<O> {
    fn open_with_ops(port: ValidatedPort, ops: O) -> Result<Self, PlatformError> {
        let extents =
            CombinedRingExtents::for_port(port).map_err(PlatformError::InvalidCombinedMapping)?;
        // All fallible cold allocation happens before external resources are
        // acquired, so allocation failure has no fd or mapping to unwind.
        let metadata = ColdRingMetadata::for_port(port)?;
        let mut socket = PacketSocket::open(ops.clone())?;
        socket.set_version()?;
        socket.ignore_outgoing()?;
        socket.set_ring(
            PACKET_RX_RING,
            port.rx().geometry(),
            SyscallStage::SetRxRing,
        )?;
        socket.set_ring(
            PACKET_TX_RING,
            port.tx().geometry(),
            SyscallStage::SetTxRing,
        )?;
        let mapping = MmapRegion::map(ops, socket.fd, port.combined_map_len())?;
        mapping
            .validate_extents(extents)
            .map_err(PlatformError::InvalidCombinedMapping)?;
        // The protocol-zero socket remains inactive through ring creation and
        // mmap. This validated bind is the single activation point.
        socket.bind(port.if_index())?;
        Ok(Self {
            mapping,
            socket,
            interface: port.interface(),
            max_frame_len: port.max_frame_len(),
            rx: port.rx(),
            extents,
            metadata,
            rx_cursor: rx::RxCursor::new(),
            rx_stats: BackendStats::new(),
            tx_state: TxPortState::default(),
            #[cfg(test)]
            rx_injection: rx::RxFaultInjection::default(),
            #[cfg(test)]
            probe: std::rc::Rc::default(),
        })
    }

    fn tx_frame_count(&self) -> usize {
        self.metadata.tx_frames().len()
    }

    fn load_tx_status(&self, frame_index: usize) -> Result<u32, MappingAccessError> {
        let status_offset = self.tx_frame_status_offset(frame_index)?;
        self.mapping.load_status_acquire(status_offset)
    }

    fn publish_tx_frame(
        &mut self,
        frame_index: usize,
        payload: TxPayload<'_>,
        generation: u64,
    ) -> Result<(), MappingAccessError> {
        let frame_offset = self.tx_frame_offset(frame_index)?;
        let header_address = self.mapping.ring_address(
            self.extents,
            RingKind::Tx,
            frame_offset,
            size_of::<Tpacket3Hdr>(),
            align_of::<Tpacket3Hdr>(),
        )?;
        let data_offset = frame_offset
            .checked_add(TPACKET_V3_TX_DATA_OFFSET)
            .ok_or(MappingAccessError::ArithmeticOverflow)?;
        let data_address =
            self.mapping
                .ring_address(self.extents, RingKind::Tx, data_offset, payload.len, 1)?;
        let length =
            u32::try_from(payload.len).map_err(|_| MappingAccessError::ArithmeticOverflow)?;
        // Every checked address, including the status word, is resolved
        // before ownership changes or any byte moves.
        let status_offset = self.tx_frame_status_offset(frame_index)?;
        let frame = &mut self.metadata.tx_frames_mut()[frame_index];
        frame
            .ownership
            .prepare()
            .map_err(MappingAccessError::Ownership)?;
        frame.generation = generation;
        let header = Tpacket3Hdr {
            tp_next_offset: 0,
            tp_sec: 0,
            tp_nsec: 0,
            tp_snaplen: length,
            tp_len: length,
            tp_status: TP_STATUS_AVAILABLE,
            tp_mac: 0,
            tp_net: 0,
            hv1: TpacketHdrVariant1 {
                tp_rxhash: 0,
                tp_vlan_tci: 0,
                tp_vlan_tpid: 0,
                tp_padding: 0,
            },
            tp_padding: [0; 8],
        };
        // SAFETY: ring_address proved the complete aligned header is within
        // the TX extent, and AVAILABLE ownership excludes kernel access.
        unsafe { std::ptr::write(header_address.cast::<Tpacket3Hdr>(), header) };
        // SAFETY: ring_address proved `data_address..+len` lies inside this
        // backend-owned TX frame of the live mapping, and AVAILABLE ownership
        // excludes the kernel. `TxPayload`'s constructor contract makes the
        // source readable for `len` bytes, free of any live `&mut` alias, and
        // disjoint from every TX extent: TX frame bytes are never lent out of
        // `sys`, and an RX source lies in an RX extent, which the checked
        // combined-mapping layout (`CombinedRingExtents`, RX `[0, rx_len)`,
        // TX `[rx_len, combined_len)`) keeps disjoint from the TX extent of
        // the same mapping; other ports own separate mappings. The ranges
        // therefore cannot overlap. This is the accepted path's single
        // packet-byte copy.
        unsafe {
            std::ptr::copy_nonoverlapping(payload.source.as_ptr(), data_address, payload.len);
        }
        #[cfg(test)]
        self.probe.record(|counts| {
            counts.tx_copies += 1;
            counts.tx_copied_bytes += payload.len;
        });
        if let Err(error) = frame.ownership.publish() {
            // The ring status is still AVAILABLE, so the kernel never sees
            // the copied bytes. Roll the frame back to Available instead of
            // leaving it Prepared, which would make it a silent permanent
            // Unavailable; the caller reports the error as a fault.
            let _ = frame.ownership.cancel_prepared();
            return Err(MappingAccessError::Ownership(error));
        }
        self.mapping
            .store_status_release(status_offset, TP_STATUS_SEND_REQUEST)
    }

    fn tx_metadata(&self, frame_index: usize) -> &crate::boundary::TxFrameMetadata {
        &self.metadata.tx_frames()[frame_index]
    }

    fn tx_metadata_mut(&mut self, frame_index: usize) -> &mut crate::boundary::TxFrameMetadata {
        &mut self.metadata.tx_frames_mut()[frame_index]
    }

    fn recycle_wrong_format(&mut self, frame_index: usize) -> Result<(), MappingAccessError> {
        let status_offset = self.tx_frame_status_offset(frame_index)?;
        self.mapping
            .store_status_release(status_offset, TP_STATUS_AVAILABLE)
    }

    fn kick_tx(&mut self) -> Result<(), PlatformError> {
        self.socket.ops.kick(self.socket.fd)
    }

    fn tx_frame_offset(&self, frame_index: usize) -> Result<usize, MappingAccessError> {
        if frame_index >= self.tx_frame_count() {
            return Err(MappingAccessError::RingOffsetOutOfBounds {
                kind: RingKind::Tx,
                offset: frame_index,
                length: 1,
            });
        }
        frame_index
            .checked_mul(self.metadata_tx_frame_size())
            .ok_or(MappingAccessError::ArithmeticOverflow)
    }

    fn tx_frame_status_offset(&self, frame_index: usize) -> Result<usize, MappingAccessError> {
        let frame_offset = self.tx_frame_offset(frame_index)?;
        let relative = frame_offset
            .checked_add(offset_of!(Tpacket3Hdr, tp_status))
            .ok_or(MappingAccessError::ArithmeticOverflow)?;
        let absolute = self
            .extents
            .tx()
            .start()
            .checked_add(relative)
            .ok_or(MappingAccessError::ArithmeticOverflow)?;
        self.mapping
            .checked_address(absolute, size_of::<u32>(), align_of::<u32>())?;
        Ok(absolute)
    }

    fn metadata_tx_frame_size(&self) -> usize {
        self.extents.tx().len() / self.tx_frame_count()
    }
}

/// Source bytes for exactly one TX publication copy.
///
/// The payload is a raw range rather than a `&[u8]` so that an RX packet of a
/// port can be copied into a TX frame of the *same* port (hairpin) while the
/// engine is borrowed mutably: no shared reference into the mapping is held
/// across the `&mut` call, and the copy itself reads through the raw source.
#[derive(Clone, Copy)]
pub(crate) struct TxPayload<'p> {
    source: NonNull<u8>,
    len: usize,
    _borrow: PhantomData<&'p [u8]>,
}

impl<'p> TxPayload<'p> {
    /// Borrows caller-owned bytes. TX frame bytes are never lent out of
    /// `sys`, so a slice obtained through any production API cannot overlap
    /// a TX frame.
    pub(crate) fn from_slice(bytes: &'p [u8]) -> Self {
        Self {
            source: NonNull::from(bytes).cast::<u8>(),
            len: bytes.len(),
            _borrow: PhantomData,
        }
    }

    /// # Safety
    ///
    /// For all of `'p`:
    ///
    /// - `source..source + len` stays readable and is not written by anyone,
    ///   neither userspace nor the kernel (an RX source must lie in a block
    ///   that stays USER-owned, which the kernel does not write);
    /// - no `&mut` reference aliases it;
    /// - it does not overlap any TX extent of any port mapping.
    ///
    /// The payload must not be retained beyond the submission call that
    /// consumes it.
    pub(super) const unsafe fn from_raw(source: NonNull<u8>, len: usize) -> Self {
        Self {
            source,
            len,
            _borrow: PhantomData,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TxSubmission {
    pub(crate) frame_index: usize,
    pub(crate) generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TxSubmitError {
    UnknownInterface,
    Oversize {
        length: usize,
        maximum: usize,
    },
    /// The batch's TX submit status-read budget is exhausted. No status was
    /// read and nothing was reserved or copied.
    StatusReadBudget,
    Unavailable {
        status: u32,
    },
    InvalidStatus {
        status: u32,
    },
    GenerationExhausted {
        frame_index: usize,
    },
    Mapping(MappingAccessError),
    Ownership(OwnershipError),
}

impl TxSubmitError {
    /// Whether the rejection reports a backend fault rather than a routine
    /// lookup, size, budget, or ring-full rejection.
    pub(crate) const fn is_fault(self) -> bool {
        matches!(
            self,
            Self::InvalidStatus { .. }
                | Self::GenerationExhausted { .. }
                | Self::Mapping(_)
                | Self::Ownership(_)
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TxCompletionReport {
    pub(crate) inspected: usize,
    pub(crate) reclaimed: usize,
    pub(crate) wrong_format: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TxCompletionError {
    UnknownInterface,
    InvalidStatus {
        status: u32,
    },
    UnexpectedOwnership {
        frame_index: usize,
        ownership: TxOwnership,
    },
    Mapping(MappingAccessError),
    Ownership(OwnershipError),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TxBatchReport {
    pub(crate) accepted: usize,
    pub(crate) kick_attempted: usize,
    pub(crate) kick_failed: usize,
    pub(crate) first_kick_error: Option<PlatformError>,
    /// Interface of the endpoint whose kick produced `first_kick_error`.
    pub(crate) first_kick_interface: Option<IfId>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TxPortState {
    producer_head: usize,
    completion_head: usize,
    in_flight: usize,
}

#[allow(dead_code)]
impl<O: PacketOps> PacketRingResources<O> {
    fn tx_submit(
        &mut self,
        payload: TxPayload<'_>,
        status_reads: &mut usize,
    ) -> Result<TxSubmission, TxSubmitError> {
        if payload.len > self.max_frame_len {
            return Err(TxSubmitError::Oversize {
                length: payload.len,
                maximum: self.max_frame_len,
            });
        }
        if *status_reads == 0 {
            return Err(TxSubmitError::StatusReadBudget);
        }
        *status_reads -= 1;
        let frame_index = self.tx_state.producer_head;
        #[cfg(test)]
        self.probe
            .record(|counts| counts.tx_submit_status_reads += 1);
        let status = self
            .load_tx_status(frame_index)
            .map_err(TxSubmitError::Mapping)?;
        match status {
            TP_STATUS_AVAILABLE => {}
            TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING | TP_STATUS_WRONG_FORMAT => {
                return Err(TxSubmitError::Unavailable { status });
            }
            _ => return Err(TxSubmitError::InvalidStatus { status }),
        }
        let metadata = self.tx_metadata(frame_index);
        if metadata.ownership.owner() != TxOwnership::Available {
            return Err(TxSubmitError::Unavailable { status });
        }
        let generation = metadata
            .generation
            .checked_add(1)
            .ok_or(TxSubmitError::GenerationExhausted { frame_index })?;
        self.publish_tx_frame(frame_index, payload, generation)
            .map_err(|error| match error {
                MappingAccessError::Ownership(source) => TxSubmitError::Ownership(source),
                source => TxSubmitError::Mapping(source),
            })?;
        let frame_count = self.tx_frame_count();
        let state = &mut self.tx_state;
        state.producer_head = (state.producer_head + 1) % frame_count;
        state.in_flight += 1;
        Ok(TxSubmission {
            frame_index,
            generation,
        })
    }

    fn tx_scan_completions(
        &mut self,
        budget: usize,
    ) -> Result<TxCompletionReport, TxCompletionError> {
        let mut report = TxCompletionReport::default();
        while report.inspected < budget && self.tx_state.in_flight != 0 {
            let frame_index = self.tx_state.completion_head;
            #[cfg(test)]
            self.probe
                .record(|counts| counts.tx_completion_status_reads += 1);
            let status = self
                .load_tx_status(frame_index)
                .map_err(TxCompletionError::Mapping)?;
            report.inspected += 1;
            let ownership = self.tx_metadata(frame_index).ownership.owner();
            match status {
                TP_STATUS_SEND_REQUEST => {
                    if ownership != TxOwnership::SendRequest {
                        return Err(TxCompletionError::UnexpectedOwnership {
                            frame_index,
                            ownership,
                        });
                    }
                    break;
                }
                TP_STATUS_SENDING => {
                    if ownership == TxOwnership::SendRequest {
                        self.tx_metadata_mut(frame_index)
                            .ownership
                            .kernel_accept()
                            .map_err(TxCompletionError::Ownership)?;
                    } else if ownership != TxOwnership::Sending {
                        return Err(TxCompletionError::UnexpectedOwnership {
                            frame_index,
                            ownership,
                        });
                    }
                    break;
                }
                TP_STATUS_AVAILABLE => {
                    let metadata = self.tx_metadata_mut(frame_index);
                    if ownership == TxOwnership::SendRequest {
                        metadata
                            .ownership
                            .reclaim_unconsumed()
                            .map_err(TxCompletionError::Ownership)?;
                    } else if ownership == TxOwnership::Sending {
                        metadata
                            .ownership
                            .kernel_complete()
                            .map_err(TxCompletionError::Ownership)?;
                    } else {
                        return Err(TxCompletionError::UnexpectedOwnership {
                            frame_index,
                            ownership,
                        });
                    }
                    report.reclaimed += 1;
                    self.tx_advance_completion();
                }
                TP_STATUS_WRONG_FORMAT => {
                    if ownership != TxOwnership::SendRequest {
                        return Err(TxCompletionError::UnexpectedOwnership {
                            frame_index,
                            ownership,
                        });
                    }
                    {
                        let metadata = self.tx_metadata_mut(frame_index);
                        metadata
                            .ownership
                            .kernel_reject_format()
                            .map_err(TxCompletionError::Ownership)?;
                        metadata
                            .ownership
                            .recycle_wrong_format()
                            .map_err(TxCompletionError::Ownership)?;
                    }
                    self.recycle_wrong_format(frame_index)
                        .map_err(TxCompletionError::Mapping)?;
                    report.reclaimed += 1;
                    report.wrong_format += 1;
                    self.tx_advance_completion();
                }
                _ => return Err(TxCompletionError::InvalidStatus { status }),
            }
        }
        Ok(report)
    }

    fn tx_advance_completion(&mut self) {
        let frame_count = self.tx_frame_count();
        let state = &mut self.tx_state;
        state.completion_head = (state.completion_head + 1) % frame_count;
        state.in_flight -= 1;
    }
}

/// Per-batch work limits that bound kernel-visible status and descriptor
/// accesses independently of the packet budget passed to `receive`.
///
/// RX limits apply to each port separately within one batch, so a port with
/// a corrupt or slowly validated ring cannot consume another port's RX work.
/// The TX limit is shared by all submissions of one batch. Without explicit
/// limits RX work is still bounded by ring geometry (each status read either
/// stops the port or acquires one block, and each block holds a fixed maximum
/// number of descriptors) and TX work by one status read per commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkLimits {
    pub(crate) rx_block_status_reads_per_port: usize,
    pub(crate) rx_descriptor_visits_per_port: usize,
    pub(crate) tx_submit_status_reads: usize,
}

impl WorkLimits {
    pub(crate) const GEOMETRY_BOUNDED: Self = Self {
        rx_block_status_reads_per_port: usize::MAX,
        rx_descriptor_visits_per_port: usize::MAX,
        tx_submit_status_reads: usize::MAX,
    };
}

/// One engine owning both directions of every configured port.
///
/// RX cursor, RX metadata, TX producer/completion state, and the combined
/// mapping of a port all live in that port's [`PacketRingResources`], and the
/// engine owns every port. A packet lease therefore borrows the engine (not a
/// single port), and committing it can copy into a TX frame of any port,
/// including its own ingress port, without a second owner of either state.
#[allow(dead_code)]
pub(crate) struct AfPacketEngine<O: PacketOps = LinuxOps> {
    table: PortTable,
    ports: Box<[PacketRingResources<O>]>,
    touched_epoch: Box<[u64]>,
    touched_ports: Box<[usize]>,
    epoch: u64,
    rx_start: usize,
    limits: WorkLimits,
}

#[allow(dead_code)]
impl AfPacketEngine<LinuxOps> {
    pub(crate) fn open(config: ValidatedConfig) -> Result<Self, PlatformError> {
        Self::open_with_ops(config, LinuxOps)
    }
}

#[allow(dead_code)]
impl<O: PacketOps> AfPacketEngine<O> {
    fn open_with_ops(config: ValidatedConfig, ops: O) -> Result<Self, PlatformError> {
        let (validated_ports, table, _max_frame_len) = config.into_parts();
        let entries = validated_ports.len();
        // Fixed engine storage is allocated before any port acquires a socket.
        let touched_epoch = fixed_tx_storage(entries, 0_u64)?;
        let touched_ports = fixed_tx_storage(entries, usize::MAX)?;
        let mut ports = Vec::new();
        ports
            .try_reserve_exact(entries)
            .map_err(|_| PlatformError::MetadataAllocationFailed {
                kind: RingKind::Tx,
                entries,
            })?;
        for port in validated_ports.iter().copied() {
            ports.push(PacketRingResources::open_with_ops(port, ops.clone())?);
        }
        Ok(Self {
            table,
            ports: ports.into_boxed_slice(),
            touched_epoch,
            touched_ports,
            epoch: 0,
            rx_start: 0,
            limits: WorkLimits::GEOMETRY_BOUNDED,
        })
    }

    pub(crate) fn set_work_limits(&mut self, limits: WorkLimits) {
        self.limits = limits;
    }

    pub(crate) const fn work_limits(&self) -> WorkLimits {
        self.limits
    }

    fn begin_epoch(&mut self) -> u64 {
        self.epoch = match self.epoch.checked_add(1) {
            Some(epoch) => epoch,
            None => {
                self.touched_epoch.fill(0);
                1
            }
        };
        self.epoch
    }

    /// Records `port_index` once per epoch in the fixed touched-port scratch.
    fn touch(&mut self, epoch: u64, touched_len: &mut usize, port_index: usize) {
        if self.touched_epoch[port_index] != epoch {
            self.touched_epoch[port_index] = epoch;
            self.touched_ports[*touched_len] = port_index;
            *touched_len += 1;
        }
    }

    pub(crate) fn begin_batch(&mut self) -> TxBatch<'_, O> {
        let epoch = self.begin_epoch();
        TxBatch {
            engine: self,
            epoch,
            touched_len: 0,
            accepted: 0,
            finished: false,
        }
    }

    pub(crate) fn scan_completions(
        &mut self,
        interface: IfId,
        budget: usize,
    ) -> Result<TxCompletionReport, TxCompletionError> {
        let port_index = self
            .table
            .lookup(interface)
            .ok_or(TxCompletionError::UnknownInterface)?
            .get();
        self.ports[port_index].tx_scan_completions(budget)
    }

    fn submit(
        &mut self,
        interface: IfId,
        payload: TxPayload<'_>,
        status_reads: &mut usize,
    ) -> Result<(usize, TxSubmission), TxSubmitError> {
        let port_index = self
            .table
            .lookup(interface)
            .ok_or(TxSubmitError::UnknownInterface)?
            .get();
        let submission = self.ports[port_index].tx_submit(payload, status_reads)?;
        Ok((port_index, submission))
    }

    fn kick_touched(&mut self, touched_len: usize, accepted: usize) -> TxBatchReport {
        let mut report = TxBatchReport {
            accepted,
            ..TxBatchReport::default()
        };
        for scratch_index in 0..touched_len {
            let port_index = self.touched_ports[scratch_index];
            report.kick_attempted += 1;
            if let Err(error) = self.ports[port_index].kick_tx() {
                report.kick_failed += 1;
                if report.first_kick_error.is_none() {
                    report.first_kick_error = Some(error);
                    report.first_kick_interface = Some(self.ports[port_index].interface);
                }
            }
            self.touched_ports[scratch_index] = usize::MAX;
        }
        report
    }
}

/// TX-only batch for payloads that do not come from an RX lease.
#[must_use]
pub(crate) struct TxBatch<'a, O: PacketOps = LinuxOps> {
    engine: &'a mut AfPacketEngine<O>,
    epoch: u64,
    touched_len: usize,
    accepted: usize,
    finished: bool,
}

#[allow(dead_code)]
impl<O: PacketOps> TxBatch<'_, O> {
    pub(crate) fn submit(
        &mut self,
        interface: IfId,
        payload: &[u8],
    ) -> Result<TxSubmission, TxSubmitError> {
        let mut status_reads = usize::MAX;
        let (port_index, submission) =
            self.engine
                .submit(interface, TxPayload::from_slice(payload), &mut status_reads)?;
        self.engine
            .touch(self.epoch, &mut self.touched_len, port_index);
        self.accepted += 1;
        Ok(submission)
    }

    pub(crate) fn finish(mut self) -> TxBatchReport {
        let report = self.engine.kick_touched(self.touched_len, self.accepted);
        self.finished = true;
        report
    }
}

impl<O: PacketOps> Drop for TxBatch<'_, O> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.engine.kick_touched(self.touched_len, self.accepted);
            self.finished = true;
        }
    }
}

fn fixed_tx_storage<T: Copy>(entries: usize, value: T) -> Result<Box<[T]>, PlatformError> {
    let mut storage = Vec::new();
    storage
        .try_reserve_exact(entries)
        .map_err(|_| PlatformError::MetadataAllocationFailed {
            kind: RingKind::Tx,
            entries,
        })?;
    storage.resize(entries, value);
    Ok(storage.into_boxed_slice())
}

struct PacketSocket<O: PacketOps> {
    fd: RawFd,
    ops: O,
}

impl<O: PacketOps> PacketSocket<O> {
    fn open(mut ops: O) -> Result<Self, PlatformError> {
        let fd = ops.open_socket()?;
        Ok(Self { fd, ops })
    }

    fn set_version(&mut self) -> Result<(), PlatformError> {
        self.ops.set_socket_option(
            self.fd,
            PACKET_VERSION,
            &TPACKET_V3,
            SyscallStage::SetVersion,
        )
    }

    fn ignore_outgoing(&mut self) -> Result<(), PlatformError> {
        self.ops.set_socket_option(
            self.fd,
            PACKET_IGNORE_OUTGOING,
            &1_i32,
            SyscallStage::SetIgnoreOutgoing,
        )
    }

    fn set_ring(
        &mut self,
        option: c_int,
        geometry: crate::RingGeometry,
        stage: SyscallStage,
    ) -> Result<(), PlatformError> {
        let request = TpacketReq3 {
            tp_block_size: geometry.block_size,
            tp_block_nr: geometry.block_count,
            tp_frame_size: geometry.frame_size,
            tp_frame_nr: geometry.frame_count,
            tp_retire_blk_tov: geometry.retire_timeout_ms,
            tp_sizeof_priv: geometry.private_size,
            tp_feature_req_word: geometry.feature_flags,
        };
        self.ops.set_socket_option(self.fd, option, &request, stage)
    }

    fn bind(&mut self, if_index: u32) -> Result<(), PlatformError> {
        let address = SockaddrLl::packet_all(if_index)?;
        self.ops.bind(self.fd, &address)
    }
}

impl<O: PacketOps> Drop for PacketSocket<O> {
    fn drop(&mut self) {
        self.ops.close(self.fd);
    }
}

struct MmapRegion<O: PacketOps = LinuxOps> {
    base: NonNull<u8>,
    len: usize,
    unmap_on_drop: bool,
    ops: O,
}

impl<O: PacketOps> MmapRegion<O> {
    fn map(mut ops: O, fd: RawFd, len: usize) -> Result<Self, PlatformError> {
        if len == 0 || len > isize::MAX as usize {
            return Err(PlatformError::UapiLayoutMismatch);
        }
        let base = ops.map(fd, len)?;
        Ok(Self {
            base,
            len,
            unmap_on_drop: true,
            ops,
        })
    }

    fn validate_extents(&self, extents: CombinedRingExtents) -> Result<(), MappingAccessError> {
        if self.len != extents.combined_len() {
            return Err(MappingAccessError::CombinedLengthMismatch {
                expected: extents.combined_len(),
                actual: self.len,
            });
        }
        for (kind, extent) in [(RingKind::Rx, extents.rx()), (RingKind::Tx, extents.tx())] {
            let end = extent
                .start()
                .checked_add(extent.len())
                .ok_or(MappingAccessError::ArithmeticOverflow)?;
            if end > self.len {
                return Err(MappingAccessError::OffsetOutOfBounds {
                    offset: extent.start(),
                    length: extent.len(),
                });
            }
            let address = self.base.as_ptr().wrapping_add(extent.start());
            if !(address as usize).is_multiple_of(TPACKET_ALIGNMENT) {
                return Err(MappingAccessError::RingExtentMisaligned {
                    kind,
                    offset: extent.start(),
                    alignment: TPACKET_ALIGNMENT,
                });
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn ring_address(
        &self,
        extents: CombinedRingExtents,
        kind: RingKind,
        offset: usize,
        length: usize,
        alignment: usize,
    ) -> Result<*mut u8, MappingAccessError> {
        let extent = match kind {
            RingKind::Rx => extents.rx(),
            RingKind::Tx => extents.tx(),
        };
        let relative_end = offset
            .checked_add(length)
            .ok_or(MappingAccessError::ArithmeticOverflow)?;
        if relative_end > extent.len() {
            return Err(MappingAccessError::RingOffsetOutOfBounds {
                kind,
                offset,
                length,
            });
        }
        let absolute = extent
            .start()
            .checked_add(offset)
            .ok_or(MappingAccessError::ArithmeticOverflow)?;
        self.checked_address(absolute, length, alignment)
    }

    fn ring_read_u32(
        &self,
        extents: CombinedRingExtents,
        kind: RingKind,
        offset: usize,
    ) -> Result<u32, MappingAccessError> {
        let address =
            self.ring_address(extents, kind, offset, size_of::<u32>(), align_of::<u32>())?;
        // SAFETY: ring_address proved a live, aligned 4-byte range inside the
        // requested ring extent. Volatile access keeps shared kernel metadata
        // from being cached or elided.
        Ok(unsafe { std::ptr::read_volatile(address.cast::<u32>()) })
    }

    fn ring_read_u16(
        &self,
        extents: CombinedRingExtents,
        kind: RingKind,
        offset: usize,
    ) -> Result<u16, MappingAccessError> {
        let address =
            self.ring_address(extents, kind, offset, size_of::<u16>(), align_of::<u16>())?;
        // SAFETY: ring_address proved a live, aligned 2-byte range inside the
        // requested ring extent. Volatile access keeps shared kernel metadata
        // from being cached or elided.
        Ok(unsafe { std::ptr::read_volatile(address.cast::<u16>()) })
    }

    // Ring status words are the kernel/userspace ownership handoff points, so
    // they are accessed as `AtomicU32` with Acquire/Release ordering rather
    // than as volatile accesses plus separate fences. Only the RX engine uses
    // these helpers; the AP1-TX status path is unchanged (follow-up).
    fn ring_load_status_acquire(
        &self,
        extents: CombinedRingExtents,
        kind: RingKind,
        offset: usize,
    ) -> Result<u32, MappingAccessError> {
        let address =
            self.ring_address(extents, kind, offset, size_of::<u32>(), align_of::<u32>())?;
        // SAFETY: ring_address proved a live 4-byte range inside the ring
        // extent, aligned to `align_of::<u32>() == align_of::<AtomicU32>()`.
        // The mapping outlives this call, and userspace never accesses a
        // status word non-atomically while the engine runs.
        let status = unsafe { AtomicU32::from_ptr(address.cast::<u32>()) };
        Ok(status.load(Ordering::Acquire))
    }

    fn ring_store_status_release(
        &mut self,
        extents: CombinedRingExtents,
        kind: RingKind,
        offset: usize,
        status: u32,
    ) -> Result<(), MappingAccessError> {
        let address =
            self.ring_address(extents, kind, offset, size_of::<u32>(), align_of::<u32>())?;
        // SAFETY: as in ring_load_status_acquire; `&mut self` additionally
        // excludes any simultaneous userspace access through this owner.
        let word = unsafe { AtomicU32::from_ptr(address.cast::<u32>()) };
        word.store(status, Ordering::Release);
        Ok(())
    }

    fn checked_address(
        &self,
        offset: usize,
        length: usize,
        alignment: usize,
    ) -> Result<*mut u8, MappingAccessError> {
        let end = offset
            .checked_add(length)
            .ok_or(MappingAccessError::ArithmeticOverflow)?;
        if end > self.len {
            return Err(MappingAccessError::OffsetOutOfBounds { offset, length });
        }
        let address = self.base.as_ptr().wrapping_add(offset);
        if !(address as usize).is_multiple_of(alignment) {
            return Err(MappingAccessError::StatusNotAligned { offset });
        }
        Ok(address)
    }

    fn read_u32_volatile(&self, offset: usize) -> Result<u32, MappingAccessError> {
        let address = self.checked_address(offset, size_of::<u32>(), align_of::<u32>())?;
        // SAFETY: checked_address proves a live, aligned 4-byte range. A
        // volatile read is required because the kernel may update this mmap.
        Ok(unsafe { std::ptr::read_volatile(address.cast::<u32>()) })
    }

    fn load_status_acquire(&self, offset: usize) -> Result<u32, MappingAccessError> {
        let status = self.read_u32_volatile(offset)?;
        fence(Ordering::Acquire);
        Ok(status)
    }

    fn store_status_release(
        &mut self,
        offset: usize,
        status: u32,
    ) -> Result<(), MappingAccessError> {
        let address = self.checked_address(offset, size_of::<u32>(), align_of::<u32>())?;
        fence(Ordering::Release);
        // SAFETY: checked_address proves a live, aligned 4-byte range and
        // `&mut self` excludes any simultaneous userspace mutable access.
        unsafe { std::ptr::write_volatile(address.cast::<u32>(), status) };
        Ok(())
    }

    #[cfg(test)]
    unsafe fn borrowed_for_test(base: NonNull<u8>, len: usize, ops: O) -> Self {
        Self {
            base,
            len,
            unmap_on_drop: false,
            ops,
        }
    }

    /// Test-only kernel stand-in: writes raw bytes at an absolute mapping
    /// offset after the same bounds check used by production accessors.
    #[cfg(test)]
    fn write_for_test(&mut self, offset: usize, bytes: &[u8]) {
        let address = self
            .checked_address(offset, bytes.len(), 1)
            .expect("test write inside mapping");
        // SAFETY: checked_address proved the exact range is live, and
        // `&mut self` excludes every other userspace access to the mapping.
        unsafe { std::slice::from_raw_parts_mut(address, bytes.len()) }.copy_from_slice(bytes);
    }
}

impl<O: PacketOps> Drop for MmapRegion<O> {
    fn drop(&mut self) {
        if !self.unmap_on_drop {
            return;
        }
        self.ops.unmap(self.base, self.len);
    }
}

fn last_error(stage: SyscallStage) -> PlatformError {
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(5);
    PlatformError::Syscall {
        stage,
        errno: Errno::new(errno),
    }
}

unsafe extern "C" {
    fn socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int;
    fn setsockopt(
        socket: c_int,
        level: c_int,
        option_name: c_int,
        option_value: *const c_void,
        option_len: u32,
    ) -> c_int;
    fn bind(socket: c_int, address: *const c_void, address_len: u32) -> c_int;
    fn mmap(
        address: *mut c_void,
        length: usize,
        protection: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(address: *mut c_void, length: usize) -> c_int;
    fn send(socket: c_int, buffer: *const c_void, length: usize, flags: c_int) -> isize;
    fn close(fd: c_int) -> c_int;
}

#[cfg(test)]
mod tests {
    use ruster_core::IfId;
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::{Cell, RefCell},
        ffi::c_int,
        os::fd::RawFd,
        ptr::NonNull,
        rc::Rc,
    };

    use super::{
        AfPacketEngine, LinuxOps, MmapRegion, PacketOps, PacketRingResources, SockaddrLl,
        TxCompletionError, TxCompletionReport, TxSubmitError, AF_PACKET, ETH_P_ALL,
    };
    use crate::{
        boundary::{ColdRingMetadata, CombinedRingExtents},
        Errno, MappingAccessError, PlatformError, PortConfig, RingGeometry, RingKind, RxOwnership,
        SyscallStage, ValidatedConfig, TPACKET_ALIGNMENT, TP_STATUS_AVAILABLE, TP_STATUS_KERNEL,
        TP_STATUS_SENDING, TP_STATUS_SEND_REQUEST, TP_STATUS_USER, TP_STATUS_WRONG_FORMAT,
    };

    struct CountingAllocator;

    thread_local! {
        static ALLOCATION_COUNT: Cell<u64> = const { Cell::new(0) };
    }

    // SAFETY: every allocation operation delegates the unchanged contract to
    // the system allocator. The const TLS counter does not allocate and keeps
    // concurrent test threads out of this test's measurement.
    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller supplies the GlobalAlloc layout contract.
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() {
                ALLOCATION_COUNT.with(|count| count.set(count.get().saturating_add(1)));
            }
            pointer
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller supplies the GlobalAlloc layout contract.
            let pointer = unsafe { System.alloc_zeroed(layout) };
            if !pointer.is_null() {
                ALLOCATION_COUNT.with(|count| count.set(count.get().saturating_add(1)));
            }
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: pointer and layout came from this allocator.
            unsafe { System.dealloc(pointer, layout) };
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            // SAFETY: the caller supplies the GlobalAlloc reallocation contract.
            let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
            if !new_pointer.is_null() {
                ALLOCATION_COUNT.with(|count| count.set(count.get().saturating_add(1)));
            }
            new_pointer
        }
    }

    #[global_allocator]
    static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

    pub(super) fn allocation_count() -> u64 {
        ALLOCATION_COUNT.with(Cell::get)
    }

    #[repr(align(16))]
    struct AlignedRing([u8; 4_096]);

    #[repr(align(4_096))]
    struct AlignedCombinedRing([u8; 8_193]);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ScriptedCall {
        Socket,
        Set(SyscallStage),
        Map(usize),
        Bind,
        Kick,
        Unmap(usize),
        Close,
    }

    struct ScriptedState {
        fail: Option<SyscallStage>,
        calls: Vec<ScriptedCall>,
        mapping: Box<AlignedCombinedRing>,
        second_mapping: Box<AlignedCombinedRing>,
        map_count: usize,
    }

    #[derive(Clone)]
    struct ScriptedOps(Rc<RefCell<ScriptedState>>);

    impl ScriptedOps {
        fn new(fail: Option<SyscallStage>) -> Self {
            Self(Rc::new(RefCell::new(ScriptedState {
                fail,
                calls: Vec::new(),
                mapping: Box::new(AlignedCombinedRing([0; 8_193])),
                second_mapping: Box::new(AlignedCombinedRing([0; 8_193])),
                map_count: 0,
            })))
        }

        fn calls(&self) -> Vec<ScriptedCall> {
            self.0.borrow().calls.clone()
        }

        fn fail_if_requested(&self, stage: SyscallStage) -> Result<(), PlatformError> {
            if self.0.borrow().fail == Some(stage) {
                Err(PlatformError::Syscall {
                    stage,
                    errno: Errno::new(5),
                })
            } else {
                Ok(())
            }
        }
    }

    impl PacketOps for ScriptedOps {
        fn open_socket(&mut self) -> Result<RawFd, PlatformError> {
            self.0.borrow_mut().calls.push(ScriptedCall::Socket);
            self.fail_if_requested(SyscallStage::Socket)?;
            Ok(71)
        }

        fn set_socket_option<T>(
            &mut self,
            _fd: RawFd,
            _option: c_int,
            _value: &T,
            stage: SyscallStage,
        ) -> Result<(), PlatformError> {
            self.0.borrow_mut().calls.push(ScriptedCall::Set(stage));
            self.fail_if_requested(stage)
        }

        fn bind(&mut self, _fd: RawFd, _address: &SockaddrLl) -> Result<(), PlatformError> {
            self.0.borrow_mut().calls.push(ScriptedCall::Bind);
            self.fail_if_requested(SyscallStage::Bind)
        }

        fn map(&mut self, _fd: RawFd, len: usize) -> Result<NonNull<u8>, PlatformError> {
            self.0.borrow_mut().calls.push(ScriptedCall::Map(len));
            self.fail_if_requested(SyscallStage::Mmap)?;
            let mut state = self.0.borrow_mut();
            assert!(len <= state.mapping.0.len());
            let map_count = state.map_count;
            state.map_count += 1;
            let base = if map_count == 0 {
                state.mapping.0.as_mut_ptr()
            } else {
                assert_eq!(map_count, 1, "test supports two mapped ports");
                state.second_mapping.0.as_mut_ptr()
            };
            Ok(NonNull::new(base).expect("scripted mapping"))
        }

        fn kick(&mut self, _fd: RawFd) -> Result<(), PlatformError> {
            self.0.borrow_mut().calls.push(ScriptedCall::Kick);
            self.fail_if_requested(SyscallStage::Kick)
        }

        fn unmap(&mut self, _base: NonNull<u8>, len: usize) {
            self.0.borrow_mut().calls.push(ScriptedCall::Unmap(len));
        }

        fn close(&mut self, _fd: RawFd) {
            self.0.borrow_mut().calls.push(ScriptedCall::Close);
        }
    }

    fn validated_port() -> crate::ValidatedPort {
        validated_config(&[IfId(7)]).ports()[0]
    }

    fn validated_config(interfaces: &[IfId]) -> ValidatedConfig {
        let rx = RingGeometry {
            block_size: 4_096,
            block_count: 1,
            frame_size: 2_048,
            frame_count: 2,
            retire_timeout_ms: 10,
            private_size: 16,
            feature_flags: 1,
        };
        let tx = RingGeometry {
            block_size: 4_096,
            block_count: 1,
            frame_size: 2_048,
            frame_count: 2,
            retire_timeout_ms: 0,
            private_size: 0,
            feature_flags: 0,
        };
        let ports = interfaces
            .iter()
            .enumerate()
            .map(|(index, interface)| PortConfig {
                interface: *interface,
                if_index: u32::try_from(index + 9).expect("small test ifindex"),
                rx,
                tx,
            })
            .collect::<Vec<_>>();
        ValidatedConfig::new(&ports, 4_096, 1_514).expect("combined ports")
    }

    #[test]
    fn status_alignment_and_inactive_socket_address_profile_are_exact() {
        let mut backing = AlignedRing([0; 4_096]);
        // SAFETY: backing outlives the mapping and is not otherwise accessed.
        let mapping = unsafe {
            MmapRegion::borrowed_for_test(
                std::ptr::NonNull::new(backing.0.as_mut_ptr()).expect("test backing"),
                backing.0.len(),
                LinuxOps,
            )
        };
        assert_eq!(
            mapping.load_status_acquire(1),
            Err(MappingAccessError::StatusNotAligned { offset: 1 })
        );
        drop(mapping);

        let address = SockaddrLl::packet_all(7).expect("validated address");
        assert_eq!(address.sll_family, AF_PACKET as u16);
        assert_eq!(address.sll_protocol, ETH_P_ALL.to_be());
        assert_eq!(address.sll_ifindex, 7);
        assert!(SockaddrLl::packet_all(0).is_err());
        let mut wrong_family = address;
        wrong_family.sll_family = 0;
        assert!(matches!(
            wrong_family.validate(),
            Err(crate::PlatformError::InvalidSocketAddress {
                family: 0,
                if_index: 7,
            })
        ));
        assert_eq!(
            RxOwnership::from_status(TP_STATUS_USER),
            Ok(RxOwnership::User)
        );
        assert_eq!(
            RxOwnership::from_status(TP_STATUS_KERNEL),
            Ok(RxOwnership::Kernel)
        );
    }

    #[test]
    fn combined_mapping_access_is_disjoint_exact_and_address_aligned() {
        let port = validated_port();
        let extents = CombinedRingExtents::for_port(port).expect("validated extents");
        let mut backing = AlignedCombinedRing([0; 8_193]);
        // SAFETY: backing outlives the non-owning mapping and is accessed only
        // through it until mapping is dropped.
        let mapping = unsafe {
            MmapRegion::borrowed_for_test(
                NonNull::new(backing.0.as_mut_ptr()).expect("combined backing"),
                port.combined_map_len(),
                LinuxOps,
            )
        };
        mapping.validate_extents(extents).expect("exact split");
        let rx = mapping
            .ring_address(extents, RingKind::Rx, 0, 16, TPACKET_ALIGNMENT)
            .expect("RX address");
        let tx = mapping
            .ring_address(extents, RingKind::Tx, 0, 16, TPACKET_ALIGNMENT)
            .expect("TX address");
        assert_eq!(rx, backing.0.as_mut_ptr());
        assert_eq!(
            tx,
            backing.0.as_mut_ptr().wrapping_add(port.tx_map_offset())
        );
        assert_eq!(
            mapping.ring_address(extents, RingKind::Rx, 4_090, 16, 1),
            Err(MappingAccessError::RingOffsetOutOfBounds {
                kind: RingKind::Rx,
                offset: 4_090,
                length: 16,
            })
        );
        drop(mapping);

        // SAFETY: the shifted range is still within backing and has the exact
        // combined length; validation must reject its actual misalignment.
        let shifted = unsafe {
            MmapRegion::borrowed_for_test(
                NonNull::new(backing.0.as_mut_ptr().wrapping_add(1)).expect("shifted backing"),
                port.combined_map_len(),
                LinuxOps,
            )
        };
        assert_eq!(
            shifted.validate_extents(extents),
            Err(MappingAccessError::RingExtentMisaligned {
                kind: RingKind::Rx,
                offset: 0,
                alignment: TPACKET_ALIGNMENT,
            })
        );
        drop(shifted);

        // SAFETY: no access occurs; this deliberately short logical mapping is
        // rejected before either extent can be used.
        let short = unsafe {
            MmapRegion::borrowed_for_test(
                NonNull::new(backing.0.as_mut_ptr()).expect("short backing"),
                port.combined_map_len() - 1,
                LinuxOps,
            )
        };
        assert_eq!(
            short.validate_extents(extents),
            Err(MappingAccessError::CombinedLengthMismatch {
                expected: port.combined_map_len(),
                actual: port.combined_map_len() - 1,
            })
        );
    }

    #[test]
    fn scripted_resource_failures_cleanup_mapping_before_socket_exactly_once() {
        let port = validated_port();
        for stage in [
            SyscallStage::Socket,
            SyscallStage::SetVersion,
            SyscallStage::SetIgnoreOutgoing,
            SyscallStage::SetRxRing,
            SyscallStage::SetTxRing,
            SyscallStage::Mmap,
            SyscallStage::Bind,
        ] {
            let ops = ScriptedOps::new(Some(stage));
            assert!(matches!(
                PacketRingResources::open_with_ops(port, ops.clone()),
                Err(PlatformError::Syscall {
                    stage: failed,
                    errno: _
                }) if failed == stage
            ));
            let calls = ops.calls();
            let closes = calls
                .iter()
                .filter(|call| **call == ScriptedCall::Close)
                .count();
            let unmaps = calls
                .iter()
                .filter(|call| matches!(call, ScriptedCall::Unmap(_)))
                .count();
            assert_eq!(closes, usize::from(stage != SyscallStage::Socket));
            assert_eq!(unmaps, usize::from(stage == SyscallStage::Bind));
            if stage == SyscallStage::Bind {
                assert!(matches!(
                    calls.as_slice(),
                    [
                        ..,
                        ScriptedCall::Bind,
                        ScriptedCall::Unmap(8_192),
                        ScriptedCall::Close
                    ]
                ));
            }
        }

        let ops = ScriptedOps::new(None);
        let resources =
            PacketRingResources::open_with_ops(port, ops.clone()).expect("scripted open");
        assert!(matches!(
            ops.calls().as_slice(),
            [
                ScriptedCall::Socket,
                ScriptedCall::Set(SyscallStage::SetVersion),
                ScriptedCall::Set(SyscallStage::SetIgnoreOutgoing),
                ScriptedCall::Set(SyscallStage::SetRxRing),
                ScriptedCall::Set(SyscallStage::SetTxRing),
                ScriptedCall::Map(8_192),
                ScriptedCall::Bind,
            ]
        ));
        drop(resources);
        assert!(matches!(
            ops.calls().as_slice(),
            [
                ..,
                ScriptedCall::Bind,
                ScriptedCall::Unmap(8_192),
                ScriptedCall::Close
            ]
        ));
    }

    #[test]
    fn cold_ring_metadata_preallocates_fixed_steady_storage() {
        let mut metadata =
            ColdRingMetadata::for_port(validated_port()).expect("cold fixed metadata");
        assert_eq!(metadata.rx_blocks().len(), 1);
        assert_eq!(metadata.rx_packets().len(), 84);
        assert_eq!(metadata.tx_frames().len(), 2);
        let block_address = metadata.rx_blocks().as_ptr();
        let rx_address = metadata.rx_packets().as_ptr();
        let tx_address = metadata.tx_frames().as_ptr();

        let before = allocation_count();
        let mut digest = 0_usize;
        for index in 0..10_000 {
            let rx_index = index % metadata.rx_packets().len();
            metadata.rx_packets_mut()[rx_index].data_len = index;
            digest ^= metadata.rx_packets()[rx_index].data_len;
            metadata.rx_blocks_mut()[0].generation = index as u64;
            digest ^= metadata.rx_blocks()[0].generation as usize;
            let tx_index = index % metadata.tx_frames().len();
            digest ^= metadata.tx_frames_mut()[tx_index].generation as usize;
        }
        std::hint::black_box(digest);
        let after = allocation_count();

        assert_eq!(after, before);
        assert_eq!(metadata.rx_blocks().as_ptr(), block_address);
        assert_eq!(metadata.rx_packets().as_ptr(), rx_address);
        assert_eq!(metadata.tx_frames().as_ptr(), tx_address);
    }

    fn set_engine_tx_status<O: PacketOps>(
        engine: &mut AfPacketEngine<O>,
        port_index: usize,
        frame_index: usize,
        status: u32,
    ) {
        let offset = engine.ports[port_index]
            .tx_frame_status_offset(frame_index)
            .expect("TX status offset");
        engine.ports[port_index]
            .mapping
            .store_status_release(offset, status)
            .expect("test status publication");
    }

    fn engine_tx_u32<O: PacketOps>(
        engine: &AfPacketEngine<O>,
        port_index: usize,
        frame_index: usize,
        field_offset: usize,
    ) -> u32 {
        let relative = engine.ports[port_index]
            .tx_frame_offset(frame_index)
            .expect("TX frame offset")
            + field_offset;
        let absolute = engine.ports[port_index].extents.tx().start() + relative;
        engine.ports[port_index]
            .mapping
            .read_u32_volatile(absolute)
            .expect("TX field")
    }

    fn engine_tx_payload<O: PacketOps>(
        engine: &AfPacketEngine<O>,
        port_index: usize,
        frame_index: usize,
        length: usize,
    ) -> &[u8] {
        let frame_offset = engine.ports[port_index]
            .tx_frame_offset(frame_index)
            .expect("TX frame offset");
        let address = engine.ports[port_index]
            .mapping
            .ring_address(
                engine.ports[port_index].extents,
                RingKind::Tx,
                frame_offset + crate::TPACKET_V3_TX_DATA_OFFSET,
                length,
                1,
            )
            .expect("TX payload");
        // SAFETY: ring_address proved this immutable test observation is
        // wholly inside the mapped TX frame, and no mutation overlaps it.
        unsafe { std::slice::from_raw_parts(address, length) }
    }

    #[test]
    fn tx_status_validation_precedes_reserve_and_rejected_packets_copy_nothing() {
        let ops = ScriptedOps::new(None);
        let mut engine = AfPacketEngine::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("TX engine");
        let payload = [0xa5; 64];

        {
            let mut batch = engine.begin_batch();
            assert_eq!(
                batch.submit(IfId(8), &payload),
                Err(TxSubmitError::UnknownInterface)
            );
            assert_eq!(
                batch.submit(IfId(7), &[0x5a; 1_515]),
                Err(TxSubmitError::Oversize {
                    length: 1_515,
                    maximum: 1_514
                })
            );
        }
        assert_eq!(
            ops.calls()
                .iter()
                .filter(|call| **call == ScriptedCall::Kick)
                .count(),
            0
        );
        assert_eq!(
            engine.ports[0].tx_metadata(0).ownership.owner(),
            crate::TxOwnership::Available
        );
        assert_eq!(engine.ports[0].tx_metadata(0).generation, 0);
        assert!(engine_tx_payload(&engine, 0, 0, payload.len())
            .iter()
            .all(|byte| *byte == 0));

        set_engine_tx_status(&mut engine, 0, 0, TP_STATUS_SEND_REQUEST);
        {
            let mut batch = engine.begin_batch();
            assert_eq!(
                batch.submit(IfId(7), &payload),
                Err(TxSubmitError::Unavailable {
                    status: TP_STATUS_SEND_REQUEST
                })
            );
        }
        set_engine_tx_status(&mut engine, 0, 0, 0x80);
        {
            let mut batch = engine.begin_batch();
            assert_eq!(
                batch.submit(IfId(7), &payload),
                Err(TxSubmitError::InvalidStatus { status: 0x80 })
            );
        }
        assert_eq!(
            engine.ports[0].tx_metadata(0).ownership.owner(),
            crate::TxOwnership::Available
        );
        assert_eq!(engine.ports[0].tx_metadata(0).generation, 0);
        assert!(engine_tx_payload(&engine, 0, 0, payload.len())
            .iter()
            .all(|byte| *byte == 0));

        set_engine_tx_status(&mut engine, 0, 0, TP_STATUS_AVAILABLE);
        engine.ports[0].tx_metadata_mut(0).generation = u64::MAX;
        {
            let mut batch = engine.begin_batch();
            assert_eq!(
                batch.submit(IfId(7), &payload),
                Err(TxSubmitError::GenerationExhausted { frame_index: 0 })
            );
        }
        assert!(engine_tx_payload(&engine, 0, 0, payload.len())
            .iter()
            .all(|byte| *byte == 0));
    }

    #[test]
    fn accepted_tx_writes_exact_v3_header_payload_and_release_status() {
        let ops = ScriptedOps::new(None);
        let mut engine = AfPacketEngine::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("TX engine");
        let payload = [0x33; 60];
        let mut batch = engine.begin_batch();
        let submission = batch.submit(IfId(7), &payload).expect("accepted");
        assert_eq!(
            submission,
            super::TxSubmission {
                frame_index: 0,
                generation: 1
            }
        );
        let report = batch.finish();
        assert_eq!(
            report,
            super::TxBatchReport {
                accepted: 1,
                kick_attempted: 1,
                kick_failed: 0,
                first_kick_error: None,
                first_kick_interface: None
            }
        );
        assert_eq!(engine_tx_u32(&engine, 0, 0, 0), 0);
        assert_eq!(engine_tx_u32(&engine, 0, 0, 12), 60);
        assert_eq!(engine_tx_u32(&engine, 0, 0, 16), 60);
        assert_eq!(engine_tx_u32(&engine, 0, 0, 20), TP_STATUS_SEND_REQUEST);
        assert_eq!(engine_tx_payload(&engine, 0, 0, payload.len()), payload);
        assert_eq!(engine.ports[0].tx_state.in_flight, 1);
        assert_eq!(
            ops.calls()
                .iter()
                .filter(|call| **call == ScriptedCall::Kick)
                .count(),
            1
        );
    }

    #[test]
    fn completion_scan_is_budgeted_fifo_and_handles_all_kernel_transitions_once() {
        let ops = ScriptedOps::new(None);
        let mut engine =
            AfPacketEngine::open_with_ops(validated_config(&[IfId(7)]), ops).expect("TX engine");
        let mut batch = engine.begin_batch();
        let first = batch.submit(IfId(7), &[0x11; 64]).expect("first");
        let second = batch.submit(IfId(7), &[0x22; 64]).expect("second");
        let _ = batch.finish();

        set_engine_tx_status(&mut engine, 0, second.frame_index, TP_STATUS_AVAILABLE);
        assert_eq!(
            engine
                .scan_completions(IfId(7), 2)
                .expect("blocked FIFO head"),
            TxCompletionReport {
                inspected: 1,
                reclaimed: 0,
                wrong_format: 0
            }
        );
        assert_eq!(engine.ports[0].tx_state.in_flight, 2);

        set_engine_tx_status(&mut engine, 0, first.frame_index, TP_STATUS_SENDING);
        assert_eq!(
            engine.scan_completions(IfId(7), 2).expect("kernel sending"),
            TxCompletionReport {
                inspected: 1,
                reclaimed: 0,
                wrong_format: 0
            }
        );
        assert_eq!(
            engine.ports[0]
                .tx_metadata(first.frame_index)
                .ownership
                .owner(),
            crate::TxOwnership::Sending
        );

        set_engine_tx_status(&mut engine, 0, first.frame_index, TP_STATUS_AVAILABLE);
        assert_eq!(
            engine.scan_completions(IfId(7), 1).expect("one completion"),
            TxCompletionReport {
                inspected: 1,
                reclaimed: 1,
                wrong_format: 0
            }
        );
        assert_eq!(engine.ports[0].tx_state.in_flight, 1);
        assert_eq!(
            engine
                .scan_completions(IfId(7), 1)
                .expect("unobserved direct completion"),
            TxCompletionReport {
                inspected: 1,
                reclaimed: 1,
                wrong_format: 0
            }
        );
        assert_eq!(engine.ports[0].tx_state.in_flight, 0);

        let mut batch = engine.begin_batch();
        let reused = batch.submit(IfId(7), &[0x44; 64]).expect("reused");
        assert_eq!(reused.frame_index, first.frame_index);
        assert_eq!(reused.generation, first.generation + 1);
        let _ = batch.finish();
        set_engine_tx_status(&mut engine, 0, reused.frame_index, TP_STATUS_WRONG_FORMAT);
        assert_eq!(
            engine
                .scan_completions(IfId(7), 8)
                .expect("wrong format recycle"),
            TxCompletionReport {
                inspected: 1,
                reclaimed: 1,
                wrong_format: 1
            }
        );
        assert_eq!(
            engine_tx_u32(&engine, 0, reused.frame_index, 20),
            TP_STATUS_AVAILABLE
        );
        assert_eq!(
            engine
                .scan_completions(IfId(7), 8)
                .expect("no double recycle"),
            TxCompletionReport::default()
        );
        assert_eq!(
            engine.scan_completions(IfId(99), 1),
            Err(TxCompletionError::UnknownInterface)
        );
    }

    #[test]
    fn fixed_touched_ports_kick_each_endpoint_once_and_drop_never_retries() {
        let ops = ScriptedOps::new(None);
        let mut engine =
            AfPacketEngine::open_with_ops(validated_config(&[IfId(7), IfId(8)]), ops.clone())
                .expect("two-port TX engine");
        let mut batch = engine.begin_batch();
        let _ = batch.submit(IfId(7), &[0x11; 64]).expect("port 7 first");
        let _ = batch.submit(IfId(7), &[0x22; 64]).expect("port 7 second");
        let _ = batch.submit(IfId(8), &[0x33; 64]).expect("port 8");
        drop(batch);
        assert_eq!(
            ops.calls()
                .iter()
                .filter(|call| **call == ScriptedCall::Kick)
                .count(),
            2
        );

        let failing = ScriptedOps::new(Some(SyscallStage::Kick));
        let mut engine =
            AfPacketEngine::open_with_ops(validated_config(&[IfId(9)]), failing.clone())
                .expect("failing-kick engine");
        let mut batch = engine.begin_batch();
        let submission = batch.submit(IfId(9), &[0x55; 64]).expect("published");
        let report = batch.finish();
        assert_eq!(report.accepted, 1);
        assert_eq!(report.kick_attempted, 1);
        assert_eq!(report.kick_failed, 1);
        assert!(matches!(
            report.first_kick_error,
            Some(PlatformError::Syscall {
                stage: SyscallStage::Kick,
                errno: _
            })
        ));
        assert_eq!(engine.ports[0].tx_state.in_flight, 1);
        assert_eq!(
            engine.ports[0]
                .tx_metadata(submission.frame_index)
                .ownership
                .owner(),
            crate::TxOwnership::SendRequest
        );
        assert_eq!(
            failing
                .calls()
                .iter()
                .filter(|call| **call == ScriptedCall::Kick)
                .count(),
            1
        );
    }

    #[derive(Clone)]
    struct QuietOps {
        base: NonNull<u8>,
        kicks: Rc<Cell<usize>>,
    }

    impl PacketOps for QuietOps {
        fn open_socket(&mut self) -> Result<RawFd, PlatformError> {
            Ok(73)
        }

        fn set_socket_option<T>(
            &mut self,
            _fd: RawFd,
            _option: c_int,
            _value: &T,
            _stage: SyscallStage,
        ) -> Result<(), PlatformError> {
            Ok(())
        }

        fn bind(&mut self, _fd: RawFd, _address: &SockaddrLl) -> Result<(), PlatformError> {
            Ok(())
        }

        fn map(&mut self, _fd: RawFd, _len: usize) -> Result<NonNull<u8>, PlatformError> {
            Ok(self.base)
        }

        fn kick(&mut self, _fd: RawFd) -> Result<(), PlatformError> {
            self.kicks.set(self.kicks.get() + 1);
            Ok(())
        }

        fn unmap(&mut self, _base: NonNull<u8>, _len: usize) {}

        fn close(&mut self, _fd: RawFd) {}
    }

    #[test]
    fn tx_submit_completion_reuse_has_zero_steady_allocations() {
        let mut backing = AlignedCombinedRing([0; 8_193]);
        let kicks = Rc::new(Cell::new(0));
        let ops = QuietOps {
            base: NonNull::new(backing.0.as_mut_ptr()).expect("quiet backing"),
            kicks: Rc::clone(&kicks),
        };
        let mut engine = AfPacketEngine::open_with_ops(validated_config(&[IfId(7)]), ops)
            .expect("quiet TX engine");
        let payload = [0x77; 64];
        let before = allocation_count();
        let mut generation = 0_u64;
        for _ in 0..10_000 {
            let mut batch = engine.begin_batch();
            let submission = batch.submit(IfId(7), &payload).expect("steady submit");
            generation ^= submission.generation;
            let report = batch.finish();
            assert_eq!(report.accepted, 1);
            set_engine_tx_status(&mut engine, 0, submission.frame_index, TP_STATUS_AVAILABLE);
            let completion = engine
                .scan_completions(IfId(7), 1)
                .expect("steady completion");
            assert_eq!(completion.reclaimed, 1);
        }
        std::hint::black_box(generation);
        let after = allocation_count();
        assert_eq!(after, before);
        assert_eq!(kicks.get(), 10_000);
    }
}
