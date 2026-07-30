use std::{
    ffi::{c_int, c_void},
    mem::{align_of, offset_of, size_of},
    os::fd::RawFd,
    ptr::NonNull,
    sync::atomic::{fence, Ordering},
};

use crate::{
    boundary::{ColdRingMetadata, CombinedRingExtents},
    BlockDescriptor, Errno, MappingAccessError, OwnershipError, PacketDescriptor, PlatformError,
    RingKind, RingLayout, RxBlockModel, RxOwnership, SyscallStage, UapiLayout, ValidatedPort,
    TPACKET_ALIGNMENT,
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
// metadata. Later slices consume them through their PacketIo state.
#[allow(dead_code)]
pub(crate) struct PacketRingResources<O: PacketOps = LinuxOps> {
    // Field declaration order is the required Drop order: unmap before close.
    mapping: MmapRegion<O>,
    socket: PacketSocket<O>,
    rx: RingLayout,
    extents: CombinedRingExtents,
    metadata: ColdRingMetadata,
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
            rx: port.rx(),
            extents,
            metadata,
        })
    }

    pub(crate) fn acquire_rx_block(
        &mut self,
        block_index: usize,
    ) -> Result<UserRxBlock<'_, O>, MappingAccessError> {
        self.mapping.acquire_user_block(self.rx, block_index)
    }
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

    fn read_u16_volatile(&self, offset: usize) -> Result<u16, MappingAccessError> {
        let address = self.checked_address(offset, size_of::<u16>(), align_of::<u16>())?;
        // SAFETY: checked_address proves a live, aligned 2-byte range. A
        // volatile read prevents the compiler from caching shared metadata.
        Ok(unsafe { std::ptr::read_volatile(address.cast::<u16>()) })
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

    fn packet_descriptor(
        &self,
        block_start: usize,
        packet_offset: usize,
        is_last: bool,
    ) -> Result<PacketDescriptor, MappingAccessError> {
        let packet_start = block_start
            .checked_add(packet_offset)
            .ok_or(MappingAccessError::ArithmeticOverflow)?;
        let snap_offset = checked_offset(packet_start, 12)?;
        let wire_offset = checked_offset(packet_start, 16)?;
        let mac_offset = checked_offset(packet_start, 24)?;
        let net_offset = checked_offset(packet_start, 26)?;
        Ok(PacketDescriptor {
            packet_offset,
            next_offset: self.read_u32_volatile(packet_start)? as usize,
            snap_len: self.read_u32_volatile(snap_offset)? as usize,
            wire_len: self.read_u32_volatile(wire_offset)? as usize,
            mac_offset: self.read_u16_volatile(mac_offset)? as usize,
            net_offset: self.read_u16_volatile(net_offset)? as usize,
            is_last,
        })
    }

    fn acquire_user_block(
        &mut self,
        layout: RingLayout,
        block_index: usize,
    ) -> Result<UserRxBlock<'_, O>, MappingAccessError> {
        let block_range = layout
            .block_range(block_index)
            .map_err(MappingAccessError::Geometry)?;
        let block_start = block_range.start;
        let status_offset = block_start
            .checked_add(offset_of!(TpacketBlockDesc, hdr))
            .ok_or(MappingAccessError::ArithmeticOverflow)?;
        let status = self.load_status_acquire(status_offset)?;
        if RxOwnership::from_status(status).map_err(MappingAccessError::Geometry)?
            != RxOwnership::User
        {
            return Err(MappingAccessError::BlockNotUser { status });
        }

        let block = BlockDescriptor {
            version: self.read_u32_volatile(block_start)?,
            offset_to_private: self.read_u32_volatile(checked_offset(block_start, 4)?)? as usize,
            packet_count: self.read_u32_volatile(checked_offset(block_start, 12)?)?,
            first_packet_offset: self.read_u32_volatile(checked_offset(block_start, 16)?)? as usize,
            block_len: self.read_u32_volatile(checked_offset(block_start, 20)?)? as usize,
        };
        block
            .validate(layout)
            .map_err(MappingAccessError::Geometry)?;

        let mut packet_offset = block.first_packet_offset;
        for index in 0..block.packet_count {
            let is_last = index + 1 == block.packet_count;
            let packet = self.packet_descriptor(block_start, packet_offset, is_last)?;
            let validated = packet
                .validate(block.block_len)
                .map_err(MappingAccessError::Geometry)?;
            if let Some(next) = validated.next_packet_offset() {
                packet_offset = next;
            }
        }

        let mut ownership = RxBlockModel::new();
        ownership
            .acquire(block.packet_count)
            .map_err(MappingAccessError::Ownership)?;
        Ok(UserRxBlock {
            mapping: self,
            status_offset,
            block_start,
            block_len: block.block_len,
            packet_count: block.packet_count,
            packet_index: 0,
            packet_offset: block.first_packet_offset,
            pending: false,
            pending_next: None,
            ownership,
        })
    }

    fn exact_packet_address(
        &self,
        absolute_offset: usize,
        length: usize,
    ) -> Result<*mut u8, MappingAccessError> {
        self.checked_address(absolute_offset, length, 1)
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
}

#[must_use]
#[allow(dead_code)]
pub(crate) struct UserRxBlock<'a, O: PacketOps = LinuxOps> {
    mapping: &'a mut MmapRegion<O>,
    status_offset: usize,
    block_start: usize,
    block_len: usize,
    packet_count: u32,
    packet_index: u32,
    packet_offset: usize,
    pending: bool,
    pending_next: Option<usize>,
    ownership: RxBlockModel,
}

#[allow(dead_code)]
impl<O: PacketOps> UserRxBlock<'_, O> {
    pub(crate) fn packet_data(&mut self) -> Result<&mut [u8], MappingAccessError> {
        if self.pending {
            return Err(MappingAccessError::PacketAlreadyBorrowed);
        }
        if self.ownership.owner() != RxOwnership::User || self.ownership.remaining() == 0 {
            return Err(MappingAccessError::Ownership(
                OwnershipError::RxReleaseWhileKernelOwned,
            ));
        }
        let is_last = self.packet_index + 1 == self.packet_count;
        let packet =
            self.mapping
                .packet_descriptor(self.block_start, self.packet_offset, is_last)?;
        let validated = packet
            .validate(self.block_len)
            .map_err(MappingAccessError::Geometry)?;
        let data = validated.data();
        let absolute_offset = self
            .block_start
            .checked_add(data.start)
            .ok_or(MappingAccessError::ArithmeticOverflow)?;
        let data_len = data.end - data.start;
        let address = self
            .mapping
            .exact_packet_address(absolute_offset, data_len)?;
        self.pending_next = validated.next_packet_offset();
        self.pending = true;
        // SAFETY: exact_packet_address proved this exact range is live.
        // UserRxBlock uniquely borrows the mapping, holds USER ownership, and
        // cannot be terminally completed while this returned borrow is live.
        Ok(unsafe { std::slice::from_raw_parts_mut(address, data_len) })
    }

    pub(crate) fn complete_packet(&mut self) -> Result<(), MappingAccessError> {
        if !self.pending {
            return Err(MappingAccessError::PacketNotBorrowed);
        }
        self.ownership
            .complete_packet()
            .map_err(MappingAccessError::Ownership)?;
        self.packet_index += 1;
        if let Some(next) = self.pending_next {
            self.packet_offset = next;
        }
        self.pending = false;
        self.pending_next = None;
        Ok(())
    }

    pub(crate) fn release(&mut self) -> Result<(), MappingAccessError> {
        if self.pending {
            return Err(MappingAccessError::PacketAlreadyBorrowed);
        }
        self.ownership
            .release()
            .map_err(MappingAccessError::Ownership)?;
        self.mapping
            .store_status_release(self.status_offset, crate::TP_STATUS_KERNEL)
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

fn checked_offset(base: usize, relative: usize) -> Result<usize, MappingAccessError> {
    base.checked_add(relative)
        .ok_or(MappingAccessError::ArithmeticOverflow)
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
        LinuxOps, MmapRegion, PacketOps, PacketRingResources, SockaddrLl, AF_PACKET, ETH_P_ALL,
    };
    use crate::{
        boundary::{ColdRingMetadata, CombinedRingExtents},
        Errno, GeometryError, MappingAccessError, PlatformError, PortConfig, RingGeometry,
        RingKind, RxOwnership, SyscallStage, ValidatedConfig, TPACKET_ALIGNMENT, TP_STATUS_KERNEL,
        TP_STATUS_USER,
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

    fn allocation_count() -> u64 {
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
        Unmap(usize),
        Close,
    }

    struct ScriptedState {
        fail: Option<SyscallStage>,
        calls: Vec<ScriptedCall>,
        mapping: Box<AlignedCombinedRing>,
    }

    #[derive(Clone)]
    struct ScriptedOps(Rc<RefCell<ScriptedState>>);

    impl ScriptedOps {
        fn new(fail: Option<SyscallStage>) -> Self {
            Self(Rc::new(RefCell::new(ScriptedState {
                fail,
                calls: Vec::new(),
                mapping: Box::new(AlignedCombinedRing([0; 8_193])),
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
            Ok(NonNull::new(state.mapping.0.as_mut_ptr()).expect("scripted mapping"))
        }

        fn unmap(&mut self, _base: NonNull<u8>, len: usize) {
            self.0.borrow_mut().calls.push(ScriptedCall::Unmap(len));
        }

        fn close(&mut self, _fd: RawFd) {
            self.0.borrow_mut().calls.push(ScriptedCall::Close);
        }
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
    }

    fn rx_layout() -> crate::RingLayout {
        RingGeometry {
            block_size: 4_096,
            block_count: 1,
            frame_size: 2_048,
            frame_count: 2,
            retire_timeout_ms: 10,
            private_size: 16,
            feature_flags: 1,
        }
        .validate_rx(4_096, 1_514)
        .expect("strict RX layout")
    }

    fn validated_port() -> crate::ValidatedPort {
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
        let config = ValidatedConfig::new(
            &[PortConfig {
                interface: IfId(7),
                if_index: 9,
                rx,
                tx,
            }],
            4_096,
            1_514,
        )
        .expect("combined port");
        config.ports()[0]
    }

    fn one_packet_ring(next_offset: u32) -> AlignedRing {
        let mut ring = AlignedRing([0; 4_096]);
        let bytes = &mut ring.0;
        write_u32(bytes, 0, 2);
        write_u32(bytes, 4, 48);
        write_u32(bytes, 8, TP_STATUS_USER);
        write_u32(bytes, 12, 1);
        write_u32(bytes, 16, 64);
        write_u32(bytes, 20, 4_096);

        write_u32(bytes, 64, next_offset);
        write_u32(bytes, 64 + 12, 60);
        write_u32(bytes, 64 + 16, 60);
        write_u32(bytes, 64 + 20, TP_STATUS_USER);
        write_u16(bytes, 64 + 24, 82);
        write_u16(bytes, 64 + 26, 96);
        bytes[146..206].fill(0xa5);
        ring
    }

    #[test]
    fn exact_packet_borrow_requires_user_ownership_and_release_is_terminal() {
        let mut backing = one_packet_ring(0);
        // SAFETY: backing remains alive and exclusively accessed through the
        // mapping until mapping is dropped below.
        let mut mapping = unsafe {
            MmapRegion::borrowed_for_test(
                std::ptr::NonNull::new(backing.0.as_mut_ptr()).expect("test backing"),
                backing.0.len(),
                LinuxOps,
            )
        };
        let mut block = mapping
            .acquire_user_block(rx_layout(), 0)
            .expect("validated USER block");
        assert_eq!(
            block.release(),
            Err(MappingAccessError::Ownership(
                crate::OwnershipError::RxPacketsOutstanding { remaining: 1 }
            ))
        );
        {
            let packet = block.packet_data().expect("exact packet borrow");
            assert_eq!(packet.len(), 60);
            assert!(packet.iter().all(|byte| *byte == 0xa5));
            packet[0] = 0x5a;
        }
        assert_eq!(
            block.packet_data(),
            Err(MappingAccessError::PacketAlreadyBorrowed)
        );
        block.complete_packet().expect("terminal packet completion");
        block.release().expect("whole block release");
        drop(block);
        assert_eq!(
            mapping.load_status_acquire(8).expect("status"),
            TP_STATUS_KERNEL
        );
        drop(mapping);
        assert_eq!(backing.0[146], 0x5a);
    }

    #[test]
    fn terminal_chain_and_inactive_socket_address_profile_are_exact() {
        let mut backing = one_packet_ring(48);
        // SAFETY: backing outlives the mapping and is not otherwise accessed.
        let mut mapping = unsafe {
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
        let error = mapping
            .acquire_user_block(rx_layout(), 0)
            .err()
            .expect("terminal next offset must fail");
        assert_eq!(
            error,
            MappingAccessError::Geometry(GeometryError::TerminalPacketHasNextOffset { offset: 48 })
        );

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
        assert_eq!(metadata.rx_packets().len(), 84);
        assert_eq!(metadata.tx_frames().len(), 2);
        let rx_address = metadata.rx_packets().as_ptr();
        let tx_address = metadata.tx_frames().as_ptr();

        let before = allocation_count();
        let mut digest = 0_usize;
        for index in 0..10_000 {
            let rx_index = index % metadata.rx_packets().len();
            metadata.rx_packets_mut()[rx_index].data_len = index;
            digest ^= metadata.rx_packets()[rx_index].data_len;
            let tx_index = index % metadata.tx_frames().len();
            digest ^= metadata.tx_frames_mut()[tx_index].generation as usize;
        }
        std::hint::black_box(digest);
        let after = allocation_count();

        assert_eq!(after, before);
        assert_eq!(metadata.rx_packets().as_ptr(), rx_address);
        assert_eq!(metadata.tx_frames().as_ptr(), tx_address);
    }
}
