use std::{
    ffi::{c_int, c_void},
    marker::PhantomData,
    mem::{align_of, offset_of, size_of},
    os::fd::RawFd,
    ptr::NonNull,
    sync::atomic::{fence, Ordering},
    time::Duration,
};

use ruster_core::{
    BatchCompletion, GeneratedAllocationError, GeneratedBatchCompletion, GeneratedPacketBatch,
    GeneratedPacketIo, GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion,
    PacketBatch, PacketIo, PacketLease, PacketSlot, PublicationBackendAuthority,
    PublicationBackendControl, PublicationQuiescenceBackend, PublicationQuiescenceDisposition,
    SlotCompletion,
};

use crate::{
    boundary::{ColdRingMetadata, CombinedRingExtents},
    AfPacketError, BlockDescriptor, Errno, MappingAccessError, OwnershipError, PacketDescriptor,
    PlatformError, PortTable, PublicationQuiescenceError, RingKind, RingLayout, RxBlockModel,
    RxOwnership, SyscallStage, TxCompletionError, TxOwnership, TxSubmitError, UapiLayout,
    ValidatedConfig, ValidatedPort, TPACKET_ALIGNMENT, TPACKET_V3_TX_DATA_OFFSET,
    TP_STATUS_AVAILABLE, TP_STATUS_BLK_TMO, TP_STATUS_KERNEL, TP_STATUS_SENDING,
    TP_STATUS_SEND_REQUEST, TP_STATUS_USER, TP_STATUS_WRONG_FORMAT,
};

const AF_PACKET: c_int = 17;
const SOCK_RAW: c_int = 3;
// Linux UAPI `include/uapi/asm-generic/fcntl.h` defines O_CLOEXEC as
// octal 02000000; Linux `include/linux/net.h` uses that value for SOCK_CLOEXEC.
const SOCK_CLOEXEC: c_int = 0x8_0000;
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
const POLLIN: i16 = 0x0001;
const EINTR: i32 = 4;

const _: [(); 0] = [(); crate::TP_STATUS_KERNEL as usize];
const _: [(); 1] = [(); crate::TP_STATUS_USER as usize];
const _: [(); 0] = [(); crate::TP_STATUS_AVAILABLE as usize];
const _: [(); 32] = [(); crate::TP_STATUS_BLK_TMO as usize];
const _: [(); 1] = [(); crate::TP_STATUS_SEND_REQUEST as usize];
const _: [(); 2] = [(); crate::TP_STATUS_SENDING as usize];
const _: [(); 4] = [(); crate::TP_STATUS_WRONG_FORMAT as usize];
const _: [(); 2] = [(); crate::TPACKET_V3_VERSION as usize];

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PollFd {
    fd: RawFd,
    events: i16,
    revents: i16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PollWaitResult {
    /// At least one descriptor reported the requested POLLIN event.
    Ready,
    /// `poll(2)` returned for another event such as POLLERR/POLLHUP/POLLNVAL.
    NoRxReady,
    TimedOut,
    Interrupted,
}

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
    fn open_socket(&mut self, socket_kind: c_int) -> Result<RawFd, PlatformError>;

    fn poll(
        &mut self,
        fds: &mut [PollFd],
        timeout_ms: c_int,
    ) -> Result<PollWaitResult, PlatformError>;

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
    fn open_socket(&mut self, socket_kind: c_int) -> Result<RawFd, PlatformError> {
        // SAFETY: `socket` has no borrowed pointer arguments. Protocol zero
        // keeps capture inactive until the later checked bind.
        let fd = unsafe { socket(AF_PACKET, socket_kind, 0) };
        if fd < 0 {
            Err(last_error(SyscallStage::Socket))
        } else {
            Ok(fd)
        }
    }

    fn poll(
        &mut self,
        fds: &mut [PollFd],
        timeout_ms: c_int,
    ) -> Result<PollWaitResult, PlatformError> {
        if fds.is_empty() {
            return Ok(PollWaitResult::TimedOut);
        }
        // SAFETY: every descriptor is a live repr(C) pollfd owned by this
        // backend, and the kernel only writes its revents field during poll.
        let result = unsafe { poll(fds.as_mut_ptr(), fds.len(), timeout_ms) };
        if result < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(5);
            if errno == EINTR {
                // Signals are an expected wakeup path. In particular, the
                // daemon uses this result to observe SIGTERM without turning
                // an orderly stop into a backend failure.
                return Ok(PollWaitResult::Interrupted);
            }
            return Err(PlatformError::Syscall {
                stage: SyscallStage::Poll,
                errno: Errno::new(errno),
            });
        }
        Ok(poll_result_from_revents(result, fds))
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
// metadata. Later slices consume them through their PacketIo state.
#[allow(dead_code)]
pub(crate) struct PacketRingResources<O: PacketOps = LinuxOps> {
    // Field declaration order is the required Drop order: unmap before close.
    mapping: MmapRegion<O>,
    socket: PacketSocket<O>,
    interface: ruster_core::IfId,
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
            interface: port.interface(),
            rx: port.rx(),
            extents,
            metadata,
        })
    }

    fn tx_mapping(&self) -> Result<MappingView<'_, O>, MappingAccessError> {
        self.mapping.ring_view(self.extents, RingKind::Tx)
    }

    fn tx_frame_count(&self) -> usize {
        self.metadata.tx_frames().len()
    }

    fn load_tx_status(&self, frame_index: usize) -> Result<u32, MappingAccessError> {
        let status_offset = self.tx_frame_status_offset(frame_index)?;
        self.tx_mapping()?.load_status_acquire(status_offset)
    }

    fn load_rx_block_status(&self, block_index: usize) -> Result<u32, MappingAccessError> {
        let block_start = self
            .rx
            .block_range(block_index)
            .map_err(MappingAccessError::Geometry)?
            .start;
        let status_offset = block_start
            .checked_add(offset_of!(TpacketBlockDesc, hdr))
            .ok_or(MappingAccessError::ArithmeticOverflow)?;
        self.mapping
            .ring_view(self.extents, RingKind::Rx)?
            .load_status_acquire(status_offset)
    }

    fn publish_tx_frame(
        &mut self,
        frame_index: usize,
        payload: &[u8],
        generation: u64,
    ) -> Result<(), MappingAccessError> {
        let frame_offset = self.tx_frame_offset(frame_index)?;
        let (header_address, data_address) = {
            let tx_mapping = self.mapping.ring_view(self.extents, RingKind::Tx)?;
            let header_address = tx_mapping.checked_address(
                frame_offset,
                size_of::<Tpacket3Hdr>(),
                align_of::<Tpacket3Hdr>(),
            )?;
            let data_offset = frame_offset
                .checked_add(TPACKET_V3_TX_DATA_OFFSET)
                .ok_or(MappingAccessError::ArithmeticOverflow)?;
            let data_address = tx_mapping.checked_address(data_offset, payload.len(), 1)?;
            (header_address, data_address)
        };
        let length =
            u32::try_from(payload.len()).map_err(|_| MappingAccessError::ArithmeticOverflow)?;
        {
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
            // SAFETY: ring_address proved the exact payload range is within this
            // distinct backend-owned TX frame. This is the accepted path's single
            // packet-byte copy.
            unsafe { std::slice::from_raw_parts_mut(data_address, payload.len()) }
                .copy_from_slice(payload);
            if let Err(error) = frame.ownership.publish() {
                // Header/payload preparation is private to this frame. If the
                // ownership model rejects publication, return the prepared frame
                // to the available pool before exposing the error to the batch.
                let _ = frame.ownership.cancel_prepared();
                return Err(MappingAccessError::Ownership(error));
            }
        }
        let mut tx_mapping = self.mapping.ring_view(self.extents, RingKind::Tx)?;
        let status_result = tx_mapping.store_status_release(
            frame_offset + offset_of!(Tpacket3Hdr, tp_status),
            TP_STATUS_SEND_REQUEST,
        );
        if let Err(error) = status_result {
            // The final status store is the only fallible operation after the
            // userspace model enters SEND_REQUEST. A failed store cannot have
            // published a usable descriptor, so reclaim the model slot.
            let _ = self.metadata.tx_frames_mut()[frame_index]
                .ownership
                .reclaim_unconsumed();
            return Err(error);
        }
        Ok(())
    }

    fn tx_metadata(&self, frame_index: usize) -> &crate::boundary::TxFrameMetadata {
        &self.metadata.tx_frames()[frame_index]
    }

    fn tx_metadata_mut(&mut self, frame_index: usize) -> &mut crate::boundary::TxFrameMetadata {
        &mut self.metadata.tx_frames_mut()[frame_index]
    }

    fn requeue_wrong_format(&mut self, frame_index: usize) -> Result<(), MappingAccessError> {
        let status_offset = self.tx_frame_status_offset(frame_index)?;
        self.tx_mapping()?
            .store_status_release(status_offset, TP_STATUS_SEND_REQUEST)
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
        self.tx_mapping()?
            .checked_address(relative, size_of::<u32>(), align_of::<u32>())?;
        Ok(relative)
    }

    fn metadata_tx_frame_size(&self) -> usize {
        self.extents.tx().len() / self.tx_frame_count()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TxSubmission {
    pub(crate) frame_index: usize,
    pub(crate) generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TxGeneratedReservation {
    port_index: usize,
    frame_index: usize,
    generation: u64,
    frame_len: usize,
    header_address: NonNull<u8>,
    data_address: NonNull<u8>,
    status_offset: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TxCompletionReport {
    pub(crate) inspected: usize,
    pub(crate) reclaimed: usize,
    pub(crate) wrong_format: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TxBatchReport {
    pub(crate) accepted: usize,
    pub(crate) kick_attempted: usize,
    pub(crate) kick_failed: usize,
    pub(crate) first_kick_error: Option<PlatformError>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TxPortState {
    producer_head: usize,
    completion_head: usize,
    in_flight: usize,
    kick_pending: bool,
}

#[allow(dead_code)]
pub(crate) struct TxEngine<O: PacketOps = LinuxOps> {
    table: PortTable,
    max_frame_len: usize,
    ports: Box<[PacketRingResources<O>]>,
    poll_fds: Box<[PollFd]>,
    states: Box<[TxPortState]>,
    touched_epoch: Box<[u64]>,
    touched_ports: Box<[usize]>,
    epoch: u64,
    generated_batch_active: bool,
    rx_batch_active: bool,
}

#[allow(dead_code)]
impl TxEngine<LinuxOps> {
    pub(crate) fn open(config: ValidatedConfig) -> Result<Self, PlatformError> {
        Self::open_with_ops(config, LinuxOps)
    }
}

#[allow(dead_code)]
impl<O: PacketOps> TxEngine<O> {
    fn open_with_ops(config: ValidatedConfig, ops: O) -> Result<Self, PlatformError> {
        let (validated_ports, table, max_frame_len) = config.into_parts();
        let entries = validated_ports.len();
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
        let mut poll_fds = Vec::new();
        poll_fds.try_reserve_exact(entries).map_err(|_| {
            PlatformError::MetadataAllocationFailed {
                kind: RingKind::Rx,
                entries,
            }
        })?;
        for resource in &ports {
            poll_fds.push(PollFd {
                fd: resource.socket.fd,
                events: POLLIN,
                revents: 0,
            });
        }
        // Do not request POLLOUT here: an AF_PACKET socket can remain
        // write-ready and would turn an idle loop into a busy loop. The normal
        // receive path scans TX completions before each tick, and this wait is
        // bounded by the daemon's timer/watchdog policy when RX is quiet.
        Ok(Self {
            table,
            max_frame_len,
            ports: ports.into_boxed_slice(),
            poll_fds: poll_fds.into_boxed_slice(),
            states: fixed_tx_storage(entries, TxPortState::default())?,
            touched_epoch: fixed_tx_storage(entries, 0_u64)?,
            touched_ports: fixed_tx_storage(entries, usize::MAX)?,
            epoch: 0,
            generated_batch_active: false,
            rx_batch_active: false,
        })
    }

    fn wait_for_rx(&mut self, timeout: Duration) -> Result<bool, PlatformError> {
        let timeout_ms = poll_timeout_ms(timeout);
        for poll_fd in &mut self.poll_fds {
            poll_fd.revents = 0;
        }
        let outcome = {
            let poll_fds = &mut self.poll_fds;
            let resource = self
                .ports
                .first_mut()
                .expect("validated AF_PACKET configuration has at least one port");
            resource.socket.ops.poll(poll_fds, timeout_ms)
        }?;
        Ok(matches!(outcome, PollWaitResult::Ready)
            && self
                .poll_fds
                .iter()
                .any(|poll_fd| poll_fd.revents & POLLIN != 0))
    }

    pub(crate) fn begin_batch(&mut self) -> TxBatch<'_, O> {
        self.epoch = match self.epoch.checked_add(1) {
            Some(epoch) => epoch,
            None => {
                self.touched_epoch.fill(0);
                1
            }
        };
        let epoch = self.epoch;
        TxBatch {
            engine: self,
            epoch,
            touched_len: 0,
            accepted: 0,
            finished: false,
            generated: false,
            rx: false,
        }
    }

    fn begin_generated(
        &mut self,
        egress: ruster_core::IfId,
    ) -> AfPacketGeneratedBatchWithOps<'_, O> {
        assert!(
            !self.generated_batch_active,
            "a generated batch must be finished or dropped before another begins"
        );
        assert!(
            !self.rx_batch_active,
            "an RX batch must be finished or dropped before a generated batch begins"
        );
        self.generated_batch_active = true;
        let mut tx = self.begin_batch();
        tx.generated = true;
        AfPacketGeneratedBatchWithOps::new(tx, egress)
    }

    fn begin_rx_batch(&mut self) -> TxBatch<'_, O> {
        assert!(
            !self.generated_batch_active,
            "a generated batch must be finished or dropped before an RX batch begins"
        );
        assert!(
            !self.rx_batch_active,
            "an RX batch must be finished or dropped before another begins"
        );
        self.rx_batch_active = true;
        let mut tx = self.begin_batch();
        tx.rx = true;
        tx
    }

    pub(crate) fn scan_completions(
        &mut self,
        interface: ruster_core::IfId,
        budget: usize,
    ) -> Result<TxCompletionReport, TxCompletionError> {
        let port_index = self
            .table
            .lookup(interface)
            .ok_or(TxCompletionError::UnknownInterface)?
            .get();
        let mut report = TxCompletionReport::default();
        let mut needs_kick = self.states[port_index].kick_pending;
        if needs_kick {
            self.kick_for_completion(port_index)?;
            needs_kick = false;
        }
        while report.inspected < budget && self.states[port_index].in_flight != 0 {
            let frame_index = self.states[port_index].completion_head;
            let status = self.ports[port_index]
                .load_tx_status(frame_index)
                .map_err(TxCompletionError::Mapping)?;
            report.inspected += 1;
            let ownership = self.ports[port_index]
                .tx_metadata(frame_index)
                .ownership
                .owner();
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
                        self.ports[port_index]
                            .tx_metadata_mut(frame_index)
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
                    let metadata = self.ports[port_index].tx_metadata_mut(frame_index);
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
                    self.advance_completion(port_index);
                    needs_kick = self.states[port_index].in_flight != 0;
                    self.states[port_index].kick_pending = needs_kick;
                }
                TP_STATUS_WRONG_FORMAT => {
                    if ownership != TxOwnership::SendRequest {
                        return Err(TxCompletionError::UnexpectedOwnership {
                            frame_index,
                            ownership,
                        });
                    }
                    {
                        let metadata = self.ports[port_index].tx_metadata_mut(frame_index);
                        metadata
                            .ownership
                            .kernel_reject_format()
                            .map_err(TxCompletionError::Ownership)?;
                        metadata
                            .ownership
                            .retry_wrong_format()
                            .map_err(TxCompletionError::Ownership)?;
                    }
                    self.ports[port_index]
                        .requeue_wrong_format(frame_index)
                        .map_err(TxCompletionError::Mapping)?;
                    report.wrong_format += 1;
                    needs_kick = true;
                    break;
                }
                _ => return Err(TxCompletionError::InvalidStatus { status }),
            }
        }
        if needs_kick {
            self.kick_for_completion(port_index)?;
        }
        Ok(report)
    }

    fn kick_for_completion(&mut self, port_index: usize) -> Result<(), TxCompletionError> {
        match self.ports[port_index].kick_tx() {
            Ok(()) => {
                self.states[port_index].kick_pending = false;
                Ok(())
            }
            Err(error) => {
                self.states[port_index].kick_pending = true;
                Err(TxCompletionError::Kick(error))
            }
        }
    }

    fn advance_completion(&mut self, port_index: usize) {
        let frame_count = self.ports[port_index].tx_frame_count();
        let state = &mut self.states[port_index];
        state.completion_head = (state.completion_head + 1) % frame_count;
        state.in_flight -= 1;
    }

    fn submit(
        &mut self,
        interface: ruster_core::IfId,
        payload: &[u8],
    ) -> Result<(usize, TxSubmission), TxSubmitError> {
        let port_index = self
            .table
            .lookup(interface)
            .ok_or(TxSubmitError::UnknownInterface)?
            .get();
        if payload.len() > self.max_frame_len {
            return Err(TxSubmitError::Oversize {
                length: payload.len(),
                maximum: self.max_frame_len,
            });
        }
        let frame_index = self.states[port_index].producer_head;
        let status = self.ports[port_index]
            .load_tx_status(frame_index)
            .map_err(TxSubmitError::Mapping)?;
        match status {
            TP_STATUS_AVAILABLE => {}
            TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING | TP_STATUS_WRONG_FORMAT => {
                return Err(TxSubmitError::Unavailable { status });
            }
            _ => return Err(TxSubmitError::InvalidStatus { status }),
        }
        let metadata = self.ports[port_index].tx_metadata(frame_index);
        if metadata.ownership.owner() != TxOwnership::Available {
            return Err(TxSubmitError::Unavailable { status });
        }
        let generation = metadata
            .generation
            .checked_add(1)
            .ok_or(TxSubmitError::GenerationExhausted { frame_index })?;
        self.ports[port_index]
            .publish_tx_frame(frame_index, payload, generation)
            .map_err(|error| match error {
                MappingAccessError::Ownership(source) => TxSubmitError::Ownership(source),
                source => TxSubmitError::Mapping(source),
            })?;
        let state = &mut self.states[port_index];
        state.producer_head = (state.producer_head + 1) % self.ports[port_index].tx_frame_count();
        state.in_flight += 1;
        Ok((
            port_index,
            TxSubmission {
                frame_index,
                generation,
            },
        ))
    }

    fn reserve_generated(
        &mut self,
        interface: ruster_core::IfId,
        frame_len: usize,
    ) -> Result<TxGeneratedReservation, TxSubmitError> {
        let port_index = self
            .table
            .lookup(interface)
            .ok_or(TxSubmitError::UnknownInterface)?
            .get();
        if frame_len > self.max_frame_len {
            return Err(TxSubmitError::Oversize {
                length: frame_len,
                maximum: self.max_frame_len,
            });
        }
        let frame_index = self.states[port_index].producer_head;
        let status = self.ports[port_index]
            .load_tx_status(frame_index)
            .map_err(TxSubmitError::Mapping)?;
        match status {
            TP_STATUS_AVAILABLE => {}
            TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING | TP_STATUS_WRONG_FORMAT => {
                return Err(TxSubmitError::Unavailable { status });
            }
            _ => return Err(TxSubmitError::InvalidStatus { status }),
        }
        let metadata = self.ports[port_index].tx_metadata(frame_index);
        if metadata.ownership.owner() != TxOwnership::Available {
            return Err(TxSubmitError::Unavailable { status });
        }
        let generation = metadata
            .generation
            .checked_add(1)
            .ok_or(TxSubmitError::GenerationExhausted { frame_index })?;
        let frame_offset = self.ports[port_index]
            .tx_frame_offset(frame_index)
            .map_err(TxSubmitError::Mapping)?;
        let (header_address, data_address, status_offset) = {
            let tx_mapping = self.ports[port_index]
                .mapping
                .ring_view(self.ports[port_index].extents, RingKind::Tx)
                .map_err(TxSubmitError::Mapping)?;
            let header_address = tx_mapping
                .checked_address(
                    frame_offset,
                    size_of::<Tpacket3Hdr>(),
                    align_of::<Tpacket3Hdr>(),
                )
                .map_err(TxSubmitError::Mapping)?;
            let data_offset = frame_offset.checked_add(TPACKET_V3_TX_DATA_OFFSET).ok_or(
                TxSubmitError::Mapping(MappingAccessError::ArithmeticOverflow),
            )?;
            let data_address = tx_mapping
                .checked_address(data_offset, frame_len, 1)
                .map_err(TxSubmitError::Mapping)?;
            let status_offset = frame_offset
                .checked_add(offset_of!(Tpacket3Hdr, tp_status))
                .ok_or(TxSubmitError::Mapping(
                    MappingAccessError::ArithmeticOverflow,
                ))?;
            tx_mapping
                .checked_address(status_offset, size_of::<u32>(), align_of::<u32>())
                .map_err(TxSubmitError::Mapping)?;
            (
                NonNull::new(header_address).expect("checked TX header is non-null"),
                NonNull::new(data_address).expect("checked TX payload is non-null"),
                status_offset,
            )
        };
        self.ports[port_index]
            .tx_metadata_mut(frame_index)
            .ownership
            .prepare()
            .map_err(TxSubmitError::Ownership)?;
        Ok(TxGeneratedReservation {
            port_index,
            frame_index,
            generation,
            frame_len,
            header_address,
            data_address,
            status_offset,
        })
    }

    fn commit_generated(
        &mut self,
        reservation: TxGeneratedReservation,
    ) -> Result<(), TxSubmitError> {
        let length = match u32::try_from(reservation.frame_len) {
            Ok(length) => length,
            Err(_) => {
                let error = TxSubmitError::Oversize {
                    length: reservation.frame_len,
                    maximum: self.max_frame_len,
                };
                let _ = self.cancel_generated(reservation);
                return Err(error);
            }
        };
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
        // SAFETY: the reservation was created only after checking the complete
        // aligned TX header range inside this backend-owned frame. The frame is
        // userspace-owned as Prepared, so the kernel cannot write it here.
        unsafe {
            std::ptr::write(
                reservation.header_address.cast::<Tpacket3Hdr>().as_ptr(),
                header,
            )
        };

        let ownership = self.ports[reservation.port_index]
            .tx_metadata_mut(reservation.frame_index)
            .ownership
            .publish();
        if let Err(source) = ownership {
            let _ = self.ports[reservation.port_index]
                .tx_metadata_mut(reservation.frame_index)
                .ownership
                .cancel_prepared();
            return Err(TxSubmitError::Ownership(source));
        }
        let status_result = self.ports[reservation.port_index]
            .mapping
            .ring_view(self.ports[reservation.port_index].extents, RingKind::Tx)
            .map_err(TxSubmitError::Mapping)
            .and_then(|mut tx_mapping| {
                tx_mapping
                    .store_status_release(reservation.status_offset, TP_STATUS_SEND_REQUEST)
                    .map_err(TxSubmitError::Mapping)
            });
        if let Err(error) = status_result {
            // The model entered SEND_REQUEST only immediately before this
            // release store. A failed checked store cannot be a usable publish,
            // so return the frame to the available pool.
            let _ = self.ports[reservation.port_index]
                .tx_metadata_mut(reservation.frame_index)
                .ownership
                .reclaim_unconsumed();
            return Err(error);
        }

        let frame_count = self.ports[reservation.port_index].tx_frame_count();
        let state = &mut self.states[reservation.port_index];
        state.producer_head = (state.producer_head + 1) % frame_count;
        state.in_flight += 1;
        self.ports[reservation.port_index]
            .tx_metadata_mut(reservation.frame_index)
            .generation = reservation.generation;
        Ok(())
    }

    fn cancel_generated(
        &mut self,
        reservation: TxGeneratedReservation,
    ) -> Result<(), TxSubmitError> {
        self.ports[reservation.port_index]
            .tx_metadata_mut(reservation.frame_index)
            .ownership
            .cancel_prepared()
            .map_err(TxSubmitError::Ownership)
    }

    fn mark_touched(&mut self, touched_len: &mut usize, epoch: u64, port_index: usize) {
        if self.touched_epoch[port_index] != epoch {
            self.touched_epoch[port_index] = epoch;
            self.touched_ports[*touched_len] = port_index;
            *touched_len += 1;
        }
    }

    fn inspect_publication_quiescence(&self) -> Result<(), PublicationQuiescenceError> {
        let mut first_error = None;
        if self.generated_batch_active {
            record_quiescence_error(
                &mut first_error,
                PublicationQuiescenceError::GeneratedBatchActive,
            );
        }
        if self.rx_batch_active {
            record_quiescence_error(&mut first_error, PublicationQuiescenceError::RxBatchActive);
        }
        for (port_index, port) in self.ports.iter().enumerate() {
            let interface = port.interface;
            for block_index in 0..port.rx.block_count() {
                match port.load_rx_block_status(block_index) {
                    Ok(status) if status == TP_STATUS_KERNEL => {}
                    // These are the only RX statuses this profile treats as
                    // kernel-delivered input without a userspace lease. Keep
                    // the match exact: a USER bit combined with an unknown
                    // flag must remain fail-closed below.
                    Ok(status)
                        if !self.rx_batch_active
                            && (status == TP_STATUS_USER
                                || status == (TP_STATUS_USER | TP_STATUS_BLK_TMO)) => {}
                    Ok(status) if status & TP_STATUS_USER != 0 => record_quiescence_error(
                        &mut first_error,
                        PublicationQuiescenceError::RxBlockUser {
                            interface,
                            block_index,
                            status,
                        },
                    ),
                    Ok(status) => record_quiescence_error(
                        &mut first_error,
                        PublicationQuiescenceError::RxBlockInvalidStatus {
                            interface,
                            block_index,
                            status,
                        },
                    ),
                    Err(source) => record_quiescence_error(
                        &mut first_error,
                        PublicationQuiescenceError::Mapping(source),
                    ),
                }
            }

            let mut owned_frames = 0_usize;
            for frame_index in 0..port.tx_frame_count() {
                let status = match port.load_tx_status(frame_index) {
                    Ok(status) => status,
                    Err(source) => {
                        record_quiescence_error(
                            &mut first_error,
                            PublicationQuiescenceError::Mapping(source),
                        );
                        continue;
                    }
                };
                let ownership = port.tx_metadata(frame_index).ownership.owner();
                let in_flight = self.states[port_index].in_flight;
                if matches!(
                    ownership,
                    TxOwnership::SendRequest | TxOwnership::Sending | TxOwnership::WrongFormat
                ) {
                    owned_frames = owned_frames
                        .checked_add(1)
                        .expect("TX ownership count cannot overflow");
                }
                let mapped = TxOwnership::from_status(status).ok();
                let completion_pending = in_flight != 0
                    && matches!(
                        (mapped, ownership),
                        (Some(TxOwnership::SendRequest), TxOwnership::SendRequest)
                            | (
                                Some(TxOwnership::Sending),
                                TxOwnership::SendRequest | TxOwnership::Sending
                            )
                            | (
                                Some(TxOwnership::Available),
                                TxOwnership::SendRequest | TxOwnership::Sending
                            )
                            | (Some(TxOwnership::WrongFormat), TxOwnership::SendRequest)
                    );
                if completion_pending {
                    record_quiescence_error(
                        &mut first_error,
                        PublicationQuiescenceError::TxCompletionPending {
                            interface,
                            frame_index,
                            status,
                            ownership,
                        },
                    );
                } else if mapped == Some(TxOwnership::Available)
                    && ownership == TxOwnership::Available
                {
                    // An available frame is quiescent even when another frame
                    // on this endpoint remains in the FIFO completion queue.
                } else {
                    record_quiescence_error(
                        &mut first_error,
                        PublicationQuiescenceError::TxOwnershipMismatch {
                            interface,
                            frame_index,
                            status,
                            ownership,
                            in_flight,
                        },
                    );
                }
            }
            if owned_frames != self.states[port_index].in_flight {
                record_quiescence_error(
                    &mut first_error,
                    PublicationQuiescenceError::TxInFlightAccountingMismatch {
                        interface,
                        in_flight: self.states[port_index].in_flight,
                        owned_frames,
                    },
                );
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn current_publication_disposition(&self) -> PublicationQuiescenceDisposition {
        // This is deliberately not a quiescence probe. A TP_STATUS_USER RX
        // block with no userspace lease is kernel-delivered input waiting for
        // the next receive call, not an alias held by this backend. The only
        // outstanding packet-I/O owners that can survive the borrow boundary
        // are the batch states below: their batch/lease lifetimes keep the
        // engine borrowed, and the flags also catch a batch forgotten by a
        // caller after that borrow has ended.
        if self.generated_batch_active || self.rx_batch_active {
            PublicationQuiescenceDisposition::SkipIo
        } else {
            PublicationQuiescenceDisposition::ContinueOldIo
        }
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
                self.states[port_index].kick_pending = true;
                report.kick_failed += 1;
                if report.first_kick_error.is_none() {
                    report.first_kick_error = Some(error);
                }
            } else {
                self.states[port_index].kick_pending = false;
            }
            self.touched_ports[scratch_index] = usize::MAX;
        }
        report
    }
}

#[must_use]
pub(crate) struct TxBatch<'a, O: PacketOps = LinuxOps> {
    engine: &'a mut TxEngine<O>,
    epoch: u64,
    touched_len: usize,
    accepted: usize,
    finished: bool,
    generated: bool,
    rx: bool,
}

#[allow(dead_code)]
impl<'a, O: PacketOps> TxBatch<'a, O> {
    /// Acquires an RX block while retaining the batch's exclusive engine
    /// borrow. The returned view is lifetime-bound to that borrow, but it is
    /// a raw-pointer handle rather than a Rust borrow of one resource field;
    /// this is what permits the same batch to submit to every TX port.
    fn acquire_rx_block(
        &mut self,
        port_index: usize,
        layout: RingLayout,
        block_index: usize,
    ) -> Result<UserRxBlock<'a, O>, MappingAccessError> {
        let resource = &self.engine.ports[port_index];
        let view = resource.mapping.ring_view(resource.extents, RingKind::Rx)?;
        // `self.engine` is an `&'a mut TxEngine<O>` held by this TxBatch. The
        // pointer and extent came from that engine's still-live MmapRegion;
        // only the marker lifetime is extended from the short field borrow to
        // `'a`, and no owner or mapping is copied or dropped here.
        let view = MappingView {
            base: view.base,
            len: view.len,
            _owner: PhantomData,
        };
        view.acquire_user_block(layout, block_index)
    }

    pub(crate) fn submit(
        &mut self,
        interface: ruster_core::IfId,
        payload: &[u8],
    ) -> Result<TxSubmission, TxSubmitError> {
        let (port_index, submission) = self.engine.submit(interface, payload)?;
        self.engine
            .mark_touched(&mut self.touched_len, self.epoch, port_index);
        self.accepted += 1;
        Ok(submission)
    }

    fn reserve_generated(
        &mut self,
        egress: ruster_core::IfId,
        frame_len: usize,
    ) -> Result<TxGeneratedReservation, TxSubmitError> {
        self.engine.reserve_generated(egress, frame_len)
    }

    fn commit_generated(
        &mut self,
        reservation: TxGeneratedReservation,
    ) -> Result<(), TxSubmitError> {
        self.engine.commit_generated(reservation)?;
        self.engine
            .mark_touched(&mut self.touched_len, self.epoch, reservation.port_index);
        self.accepted += 1;
        Ok(())
    }

    fn cancel_generated(
        &mut self,
        reservation: TxGeneratedReservation,
    ) -> Result<(), TxSubmitError> {
        self.engine.cancel_generated(reservation)
    }

    pub(crate) fn finish(mut self) -> TxBatchReport {
        let report = self.engine.kick_touched(self.touched_len, self.accepted);
        self.finished = true;
        if self.generated {
            self.engine.generated_batch_active = false;
        }
        if self.rx {
            self.engine.rx_batch_active = false;
        }
        report
    }
}

impl<O: PacketOps> Drop for TxBatch<'_, O> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.engine.kick_touched(self.touched_len, self.accepted);
            self.finished = true;
        }
        if self.generated {
            self.engine.generated_batch_active = false;
        }
        if self.rx {
            self.engine.rx_batch_active = false;
        }
    }
}

#[derive(Debug, Default)]
struct GeneratedBatchCounters {
    attempts: usize,
    allocated: usize,
    failed: usize,
    requested: usize,
    cancelled: usize,
    abandoned: usize,
    accepted: usize,
    rejected: usize,
}

/// Core generated batch shared by the fake-kernel seam and the live adapter.
///
/// A batch permits one outstanding lease at a time. This follows directly from
/// the GAT lease borrow: a live lease holds a mutable borrow of the batch, so a
/// second allocation cannot be requested until the first lease is completed.
/// The explicit `pending` reservation also handles a lease forgotten with
/// `mem::forget`: a later allocation returns `Unavailable`, and finish/drop
/// cancels that exact Prepared frame before releasing the TX batch.
struct AfPacketGeneratedBatchWithOps<'batch, O: PacketOps> {
    tx: Option<TxBatch<'batch, O>>,
    egress: ruster_core::IfId,
    pending: Option<TxGeneratedReservation>,
    counters: GeneratedBatchCounters,
    error: Option<AfPacketError>,
    finished: bool,
}

impl<'batch, O: PacketOps> AfPacketGeneratedBatchWithOps<'batch, O> {
    fn new(tx: TxBatch<'batch, O>, egress: ruster_core::IfId) -> Self {
        Self {
            tx: Some(tx),
            egress,
            pending: None,
            counters: GeneratedBatchCounters::default(),
            error: None,
            finished: false,
        }
    }

    fn record_error(&mut self, error: AfPacketError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    fn record_allocation_failure(&mut self, source: TxSubmitError) -> GeneratedAllocationError {
        match source {
            TxSubmitError::Oversize { .. } => GeneratedAllocationError::FrameTooLarge,
            TxSubmitError::Unavailable { .. } | TxSubmitError::UnknownInterface => {
                if matches!(source, TxSubmitError::UnknownInterface) {
                    self.record_error(AfPacketError::Transmit(source));
                }
                GeneratedAllocationError::Unavailable
            }
            TxSubmitError::InvalidStatus { .. }
            | TxSubmitError::GenerationExhausted { .. }
            | TxSubmitError::Mapping(_)
            | TxSubmitError::Ownership(_) => {
                self.record_error(AfPacketError::Transmit(source));
                GeneratedAllocationError::Unavailable
            }
        }
    }

    fn allocate_slot(
        &mut self,
        frame_len: usize,
    ) -> Result<AfPacketGeneratedSlotWithOps<'_, 'batch, O>, GeneratedAllocationError> {
        self.counters.attempts = self
            .counters
            .attempts
            .checked_add(1)
            .expect("generated allocation attempt count cannot overflow");
        if frame_len == 0 {
            self.counters.failed = self
                .counters
                .failed
                .checked_add(1)
                .expect("generated allocation failure count cannot overflow");
            return Err(GeneratedAllocationError::ZeroLength);
        }
        if self.pending.is_some() {
            self.counters.failed = self
                .counters
                .failed
                .checked_add(1)
                .expect("generated allocation failure count cannot overflow");
            return Err(GeneratedAllocationError::Unavailable);
        }
        let reservation = {
            let tx = self.tx.as_mut().expect("generated batch owns its TX batch");
            match tx.reserve_generated(self.egress, frame_len) {
                Ok(reservation) => reservation,
                Err(source) => {
                    self.counters.failed = self
                        .counters
                        .failed
                        .checked_add(1)
                        .expect("generated allocation failure count cannot overflow");
                    return Err(self.record_allocation_failure(source));
                }
            }
        };
        self.counters.allocated = self
            .counters
            .allocated
            .checked_add(1)
            .expect("generated allocation count cannot overflow");
        self.pending = Some(reservation);
        let tx = self.tx.as_mut().expect("generated batch owns its TX batch");
        Ok(AfPacketGeneratedSlotWithOps {
            tx,
            pending: &mut self.pending,
            reservation,
            counters: &mut self.counters,
            error: &mut self.error,
        })
    }

    fn recycle_pending(&mut self) {
        let Some(reservation) = self.pending.take() else {
            return;
        };
        let result = self
            .tx
            .as_mut()
            .expect("generated batch owns its TX batch")
            .cancel_generated(reservation);
        self.counters.abandoned = self
            .counters
            .abandoned
            .checked_add(1)
            .expect("generated abandoned count cannot overflow");
        if let Err(source) = result {
            self.record_error(AfPacketError::Transmit(source));
        }
    }

    fn finish_inner(&mut self) -> GeneratedBatchCompletion<AfPacketError> {
        // A forgotten lease is no longer callable by safe code. Its batch-level
        // reservation is still known, so reclaim it and account it as Abandoned
        // before the TX engine is kicked.
        self.recycle_pending();
        if let Some(tx) = self.tx.take() {
            let report = tx.finish();
            if let Some(error) = report.first_kick_error {
                self.record_error(AfPacketError::Kick(error));
            }
            self.counters.accepted = report.accepted;
        }
        self.finished = true;
        GeneratedBatchCompletion {
            attempts: self.counters.attempts,
            allocated: self.counters.allocated,
            failed: self.counters.failed,
            requested: self.counters.requested,
            cancelled: self.counters.cancelled,
            abandoned: self.counters.abandoned,
            accepted: self.counters.accepted,
            rejected: self.counters.rejected,
            error: self.error,
        }
    }
}

impl<'batch, O: PacketOps> GeneratedPacketBatch for AfPacketGeneratedBatchWithOps<'batch, O> {
    type Error = AfPacketError;
    type Slot<'a>
        = AfPacketGeneratedSlotWithOps<'a, 'batch, O>
    where
        Self: 'a;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        Ok(GeneratedPacketLease::new(self.allocate_slot(frame_len)?))
    }

    fn finish(mut self) -> GeneratedBatchCompletion<Self::Error> {
        self.finish_inner()
    }
}

impl<O: PacketOps> Drop for AfPacketGeneratedBatchWithOps<'_, O> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.recycle_pending();
        if let Some(tx) = self.tx.take() {
            drop(tx);
        }
        self.finished = true;
    }
}

struct AfPacketGeneratedSlotWithOps<'slot, 'batch, O: PacketOps> {
    tx: &'slot mut TxBatch<'batch, O>,
    pending: &'slot mut Option<TxGeneratedReservation>,
    reservation: TxGeneratedReservation,
    counters: &'slot mut GeneratedBatchCounters,
    error: &'slot mut Option<AfPacketError>,
}

impl<O: PacketOps> GeneratedPacketSlot for AfPacketGeneratedSlotWithOps<'_, '_, O> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: the reservation checked the exact visible range against the
        // live TX mapping while the frame was Available, then transferred its
        // userspace model to Prepared. The enclosing TxBatch keeps the mapping
        // owner alive and the batch-level pending reservation prevents another
        // slot from aliasing this frame until completion.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.reservation.data_address.as_ptr(),
                self.reservation.frame_len,
            )
        }
    }

    fn complete(self, completion: GeneratedSlotCompletion) {
        let Self {
            tx,
            pending,
            reservation,
            counters,
            error,
        } = self;
        match completion {
            GeneratedSlotCompletion::Transmit => {
                counters.requested = counters
                    .requested
                    .checked_add(1)
                    .expect("generated request count cannot overflow");
                match tx.commit_generated(reservation) {
                    Ok(()) => {
                        counters.accepted = counters
                            .accepted
                            .checked_add(1)
                            .expect("generated accepted count cannot overflow");
                    }
                    Err(source) => {
                        counters.rejected = counters
                            .rejected
                            .checked_add(1)
                            .expect("generated rejected count cannot overflow");
                        record_slot_error(error, AfPacketError::Transmit(source));
                    }
                }
            }
            GeneratedSlotCompletion::Cancelled => {
                counters.cancelled = counters
                    .cancelled
                    .checked_add(1)
                    .expect("generated cancelled count cannot overflow");
                if let Err(source) = tx.cancel_generated(reservation) {
                    record_slot_error(error, AfPacketError::Transmit(source));
                }
            }
            GeneratedSlotCompletion::Abandoned => {
                counters.abandoned = counters
                    .abandoned
                    .checked_add(1)
                    .expect("generated abandoned count cannot overflow");
                if let Err(source) = tx.cancel_generated(reservation) {
                    record_slot_error(error, AfPacketError::Transmit(source));
                }
            }
        }
        // The lease is terminal at this point. Clear the batch-level copy even
        // when the commit/cancel path reported an error, so finish cannot try to
        // operate on the same reservation a second time.
        *pending = None;
    }
}

/// Public generated batch for the live Linux adapter. Its implementation is a
/// thin concrete wrapper around the same generic batch used by ScriptedOps.
pub struct AfPacketGeneratedBatch<'batch> {
    inner: AfPacketGeneratedBatchWithOps<'batch, LinuxOps>,
}

pub struct AfPacketGeneratedSlot<'slot, 'batch> {
    inner: AfPacketGeneratedSlotWithOps<'slot, 'batch, LinuxOps>,
}

impl<'batch> GeneratedPacketBatch for AfPacketGeneratedBatch<'batch> {
    type Error = AfPacketError;
    type Slot<'a>
        = AfPacketGeneratedSlot<'a, 'batch>
    where
        Self: 'a;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        let slot = self.inner.allocate_slot(frame_len)?;
        Ok(GeneratedPacketLease::new(AfPacketGeneratedSlot {
            inner: slot,
        }))
    }

    fn finish(mut self) -> GeneratedBatchCompletion<Self::Error> {
        self.inner.finish_inner()
    }
}

impl GeneratedPacketSlot for AfPacketGeneratedSlot<'_, '_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        GeneratedPacketSlot::bytes_mut(&mut self.inner)
    }

    fn complete(self, completion: GeneratedSlotCompletion) {
        GeneratedPacketSlot::complete(self.inner, completion);
    }
}

/// RX state kept outside the TX engine so a live RX block borrow cannot
/// prevent a slot from submitting to any egress port.
struct RxState {
    ports: Box<[RxPort]>,
    next_port: usize,
}

struct RxPort {
    interface: ruster_core::IfId,
    layout: RingLayout,
    next_block: usize,
}

impl RxState {
    fn from_engine<O: PacketOps>(engine: &TxEngine<O>) -> Result<Self, PlatformError> {
        let entries = engine.ports.len();
        let mut ports = Vec::new();
        ports
            .try_reserve_exact(entries)
            .map_err(|_| PlatformError::MetadataAllocationFailed {
                kind: RingKind::Rx,
                entries,
            })?;
        for resource in &engine.ports {
            ports.push(RxPort {
                interface: resource.interface,
                layout: resource.rx,
                next_block: 0,
            });
        }
        Ok(Self {
            ports: ports.into_boxed_slice(),
            next_port: 0,
        })
    }

    fn acquire_block<'a, O: PacketOps>(
        &mut self,
        tx: &mut TxBatch<'a, O>,
        budget: usize,
    ) -> Result<Option<(ruster_core::IfId, UserRxBlock<'a, O>)>, AfPacketError> {
        if budget == 0 || self.ports.is_empty() {
            return Ok(None);
        }
        let port_count = self.ports.len();
        let start_port = self.next_port;
        for offset in 0..port_count {
            let port_index = (start_port + offset) % port_count;
            // Read the candidate without advancing either cursor. A KERNEL
            // block is still the head of this port's TPACKET FIFO, so probing
            // it must not make the next call skip ahead to a later block.
            let (interface, layout, block_index) = {
                let port = &self.ports[port_index];
                (port.interface, port.layout, port.next_block)
            };
            match tx.acquire_rx_block(port_index, layout, block_index) {
                Ok(block) => {
                    // Cursor movement is committed only after ownership has
                    // actually transferred to userspace.
                    let port = &mut self.ports[port_index];
                    port.next_block = (block_index + 1) % layout.block_count();
                    self.next_port = (port_index + 1) % port_count;
                    return Ok(Some((interface, block)));
                }
                Err(MappingAccessError::BlockNotUser { .. }) => {}
                Err(source) => {
                    return Err(AfPacketError::Receive { interface, source });
                }
            }
        }
        Ok(None)
    }
}

impl<O: PacketOps> TxEngine<O> {
    fn scan_all_completions(&mut self) -> Result<(), AfPacketError> {
        for port_index in 0..self.ports.len() {
            let interface = self.ports[port_index].interface;
            let budget = self.ports[port_index].tx_frame_count();
            self.scan_completions(interface, budget)
                .map_err(|source| AfPacketError::Completion { interface, source })?;
        }
        Ok(())
    }
}

/// Generic adapter used by the in-crate fake-kernel seam.
///
/// The public live adapter below fixes the operation type to [`LinuxOps`], so
/// the private fake operation surface never appears in the exported API.
struct AfPacketIoWithOps<O: PacketOps> {
    // `engine` owns every MmapRegion. `RxState` stores only cursors and
    // geometry; a live raw RX view is carried by an AfPacketBatch whose
    // TxBatch<'a> borrow prevents this owner from being dropped.
    engine: TxEngine<O>,
    rx: RxState,
}

impl<O: PacketOps> AfPacketIoWithOps<O> {
    fn open_with_ops(config: ValidatedConfig, ops: O) -> Result<Self, PlatformError> {
        let engine = TxEngine::open_with_ops(config, ops)?;
        let rx = RxState::from_engine(&engine)?;
        Ok(Self { engine, rx })
    }

    #[allow(dead_code)]
    fn wait_for_rx(&mut self, timeout: Duration) -> Result<bool, AfPacketError> {
        self.engine
            .wait_for_rx(timeout)
            .map_err(AfPacketError::Wait)
    }
}

impl<O: PacketOps> PacketIo for AfPacketIoWithOps<O> {
    type Error = AfPacketError;
    type Batch<'a>
        = AfPacketBatchWithOps<'a, O>
    where
        Self: 'a;

    fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
        if self.engine.generated_batch_active {
            return Err(AfPacketError::Quiescence(
                PublicationQuiescenceError::GeneratedBatchActive,
            ));
        }
        if self.engine.rx_batch_active {
            return Err(AfPacketError::Quiescence(
                PublicationQuiescenceError::RxBatchActive,
            ));
        }
        // Completion scanning is independent of the RX budget. It reclaims
        // completed TX frames before this batch can submit new egress data,
        // and preserves the engine's pending-kick/suffix recovery protocol.
        self.engine.scan_all_completions()?;
        let mut tx = self.engine.begin_rx_batch();
        let received = self.rx.acquire_block(&mut tx, budget)?;
        let (interface, rx_block, remaining) = match received {
            Some((interface, block)) => {
                let remaining = usize::try_from(block.packet_count)
                    .expect("TPACKET_V3 packet count fits this target")
                    .min(budget);
                (Some(interface), Some(block), remaining)
            }
            None => (None, None, 0),
        };
        Ok(AfPacketBatchWithOps {
            tx: Some(tx),
            rx_block,
            interface,
            remaining,
            counters: AfPacketBatchCounters::default(),
            error: None,
            finished: false,
        })
    }
}

impl<O: PacketOps> GeneratedPacketIo for AfPacketIoWithOps<O> {
    type Error = AfPacketError;
    type Batch<'a>
        = AfPacketGeneratedBatchWithOps<'a, O>
    where
        Self: 'a;

    fn begin_generated(&mut self, egress: ruster_core::IfId) -> Self::Batch<'_> {
        self.engine.begin_generated(egress)
    }
}

impl<O: PacketOps> PublicationQuiescenceBackend for AfPacketIoWithOps<O> {
    type Error = AfPacketError;

    fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {
        self.engine
            .inspect_publication_quiescence()
            .map_err(AfPacketError::Quiescence)
    }

    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
        self.engine.current_publication_disposition()
    }

    fn quiescence_error_disposition(error: &Self::Error) -> PublicationQuiescenceDisposition {
        match error {
            // A completed/released or still-SENDING TX frame is safe to coexist
            // with the old publication: receive() first runs the existing FIFO
            // completion scan, which also retries pending endpoint kicks.
            AfPacketError::Quiescence(PublicationQuiescenceError::TxCompletionPending {
                ..
            }) => PublicationQuiescenceDisposition::ContinueOldIo,
            _ => PublicationQuiescenceDisposition::SkipIo,
        }
    }
}

// SAFETY: `AfPacketIoWithOps` keeps the authoritative socket mappings,
// ownership metadata, cursors, and TX accounting in this exact value. All
// packet and generated batch/slot outputs hold lifetime-bounded borrows into
// those fields; they cannot detach or replace the backend. The private
// PacketOps surface returns no backend value or authoritative alias, and the
// quiescence probe observes every mapped RX block and TX frame.
#[allow(unsafe_code)]
unsafe impl<O: PacketOps> PublicationBackendAuthority for AfPacketIoWithOps<O> {}

// SAFETY: the fake-seam command has the same backend-local behavior as the
// live implementation. It only mutably borrows this exact adapter to wait on
// its private descriptor array and returns no backend or authoritative alias.
#[allow(unsafe_code)]
unsafe impl<O: PacketOps> PublicationBackendControl for AfPacketIoWithOps<O> {
    type Command = Duration;
    type Response = Result<bool, AfPacketError>;

    fn execute_publication_backend_command(&mut self, command: Self::Command) -> Self::Response {
        self.wait_for_rx(command)
    }
}

#[derive(Debug, Default)]
struct AfPacketBatchCounters {
    tx_requested: usize,
    tx_accepted: usize,
    tx_rejected: usize,
    recycled: usize,
}

/// A core-facing batch backed by one TPACKET_V3 USER block for the fake seam.
struct AfPacketBatchWithOps<'a, O: PacketOps> {
    tx: Option<TxBatch<'a, O>>,
    rx_block: Option<UserRxBlock<'a, O>>,
    interface: Option<ruster_core::IfId>,
    remaining: usize,
    counters: AfPacketBatchCounters,
    error: Option<AfPacketError>,
    finished: bool,
}

impl<O: PacketOps> AfPacketBatchWithOps<'_, O> {
    fn record_error(&mut self, error: AfPacketError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    fn release_rx(&mut self) {
        let Some(block) = self.rx_block.as_mut() else {
            return;
        };
        let interface = self.interface.expect("RX block has an interface");
        let (first_error, release_error) = match block.complete_remaining() {
            Ok(()) => match block.release() {
                Ok(()) => (None, None),
                Err(source) => {
                    let discard_error = block.release_discarding().err();
                    (Some(source), discard_error)
                }
            },
            Err(source) => (Some(source), block.release_discarding().err()),
        };
        if let Some(source) = first_error {
            self.record_error(AfPacketError::Receive { interface, source });
        }
        if let Some(source) = release_error {
            self.record_error(AfPacketError::Receive { interface, source });
        }
    }

    fn finish_inner(&mut self) -> BatchCompletion<AfPacketError> {
        self.release_rx();
        if let Some(tx) = self.tx.take() {
            let report = tx.finish();
            if let Some(error) = report.first_kick_error {
                self.record_error(AfPacketError::Kick(error));
            }
        }
        self.finished = true;
        BatchCompletion {
            tx_requested: self.counters.tx_requested,
            tx_accepted: self.counters.tx_accepted,
            tx_rejected: self.counters.tx_rejected,
            recycled: self.counters.recycled,
            error: self.error,
        }
    }
}

impl<'batch, O: PacketOps> PacketBatch for AfPacketBatchWithOps<'batch, O> {
    type Error = AfPacketError;
    type Slot<'slot>
        = AfPacketSlotWithOps<'slot, 'batch, O>
    where
        Self: 'slot;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        if self.remaining == 0 {
            return None;
        }
        let block = self.rx_block.as_mut()?;
        if !block.has_next_packet() {
            self.remaining = 0;
            return None;
        }
        let interface = self.interface.expect("RX block has an interface");
        let tx = self.tx.as_mut().expect("batch owns its TX engine borrow");
        self.remaining -= 1;
        Some(PacketLease::new(AfPacketSlotWithOps {
            block,
            tx,
            interface,
            counters: &mut self.counters,
            error: &mut self.error,
        }))
    }

    fn finish(mut self) -> BatchCompletion<Self::Error> {
        self.finish_inner()
    }
}

impl<O: PacketOps> Drop for AfPacketBatchWithOps<'_, O> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // A dropped batch has no return channel for errors, but ownership is
        // still terminal: every remaining RX packet is internally completed,
        // the block is returned to KERNEL, and the existing TxBatch drop hook
        // performs its normal endpoint kick.
        self.release_rx();
        if let Some(tx) = self.tx.take() {
            drop(tx);
        }
        self.finished = true;
    }
}

/// A single core lease over a TPACKET_V3 RX packet for the fake seam.
struct AfPacketSlotWithOps<'slot, 'batch, O: PacketOps> {
    block: &'slot mut UserRxBlock<'batch, O>,
    tx: &'slot mut TxBatch<'batch, O>,
    interface: ruster_core::IfId,
    counters: &'slot mut AfPacketBatchCounters,
    error: &'slot mut Option<AfPacketError>,
}

impl<O: PacketOps> PacketSlot for AfPacketSlotWithOps<'_, '_, O> {
    fn ingress(&self) -> ruster_core::IfId {
        self.interface
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        let result = if self.block.is_pending() {
            self.block.pending_packet_data()
        } else {
            self.block.packet_data()
        };
        result.expect("validated TPACKET_V3 packet remains addressable")
    }

    fn complete(self, completion: SlotCompletion) {
        let Self {
            block,
            tx,
            interface,
            counters,
            error,
        } = self;
        match completion {
            SlotCompletion::Transmit(egress) => {
                counters.tx_requested = counters
                    .tx_requested
                    .checked_add(1)
                    .expect("RX batch TX request count cannot overflow");
                let result = match block.ensure_packet_data() {
                    Ok(payload) => tx.submit(egress, payload).map(|_| ()),
                    Err(source) => Err(mapping_to_tx_submit_error(source)),
                };
                match result {
                    Ok(()) => {
                        counters.tx_accepted = counters
                            .tx_accepted
                            .checked_add(1)
                            .expect("RX batch TX accepted count cannot overflow");
                    }
                    Err(source) => {
                        counters.tx_rejected = counters
                            .tx_rejected
                            .checked_add(1)
                            .expect("RX batch TX rejected count cannot overflow");
                        if matches!(
                            source,
                            TxSubmitError::InvalidStatus { .. }
                                | TxSubmitError::GenerationExhausted { .. }
                                | TxSubmitError::Mapping(_)
                                | TxSubmitError::Ownership(_)
                        ) {
                            record_slot_error(error, AfPacketError::Transmit(source));
                        }
                    }
                }
                if let Err(source) = block.complete_packet() {
                    record_slot_error(error, AfPacketError::Receive { interface, source });
                }
            }
            SlotCompletion::Recycle(_)
            | SlotCompletion::Consume(_)
            | SlotCompletion::LeaseAbandoned => {
                if let Err(source) = block.ensure_packet_data() {
                    record_slot_error(error, AfPacketError::Receive { interface, source });
                } else if let Err(source) = block.complete_packet() {
                    record_slot_error(error, AfPacketError::Receive { interface, source });
                } else {
                    counters.recycled = counters
                        .recycled
                        .checked_add(1)
                        .expect("RX batch recycled count cannot overflow");
                }
            }
        }
    }
}

/// A live Linux AF_PACKET/TPACKET_V3 adapter implementing core packet I/O.
///
/// The adapter owns one socket and combined mapping per configured port. RX
/// batches borrow one USER-owned TPACKET_V3 block, while the same batch keeps
/// the existing all-port TX engine available for egress. RX bytes stay in the
/// mapped RX block; accepted TX uses the engine's one-copy publication into a
/// distinct TX frame.
pub struct AfPacketIo {
    engine: TxEngine<LinuxOps>,
    rx: RxState,
}

impl AfPacketIo {
    /// Opens and binds one TPACKET_V3 socket per validated port.
    pub fn open(config: ValidatedConfig) -> Result<Self, PlatformError> {
        let inner = AfPacketIoWithOps::open_with_ops(config, LinuxOps)?;
        Ok(Self {
            engine: inner.engine,
            rx: inner.rx,
        })
    }

    /// Blocks until a configured AF_PACKET port is ready for RX work, the
    /// timeout expires, or a signal interrupts the wait.
    ///
    /// The readiness result is `true` only when `poll(2)` reported `POLLIN` on
    /// at least one configured port; a timeout, an interrupted wait, or only
    /// `POLLERR`/`POLLHUP`/`POLLNVAL` returns `false`.
    /// Socket descriptors remain private to this backend so callers cannot
    /// alter their ownership or publication authority.
    pub fn wait_for_rx(&mut self, timeout: Duration) -> Result<bool, AfPacketError> {
        self.engine
            .wait_for_rx(timeout)
            .map_err(AfPacketError::Wait)
    }
}

impl PacketIo for AfPacketIo {
    type Error = AfPacketError;
    type Batch<'a>
        = AfPacketBatch<'a>
    where
        Self: 'a;

    fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
        if self.engine.generated_batch_active {
            return Err(AfPacketError::Quiescence(
                PublicationQuiescenceError::GeneratedBatchActive,
            ));
        }
        if self.engine.rx_batch_active {
            return Err(AfPacketError::Quiescence(
                PublicationQuiescenceError::RxBatchActive,
            ));
        }
        // Completion scanning is independent of the RX budget. It reclaims
        // completed TX frames before this batch can submit new egress data,
        // and preserves the engine's pending-kick/suffix recovery protocol.
        self.engine.scan_all_completions()?;
        let mut tx = self.engine.begin_rx_batch();
        let received = self.rx.acquire_block(&mut tx, budget)?;
        let (interface, rx_block, remaining) = match received {
            Some((interface, block)) => {
                let remaining = usize::try_from(block.packet_count)
                    .expect("TPACKET_V3 packet count fits this target")
                    .min(budget);
                (Some(interface), Some(block), remaining)
            }
            None => (None, None, 0),
        };
        Ok(AfPacketBatch {
            tx: Some(tx),
            rx_block,
            interface,
            remaining,
            counters: AfPacketBatchCounters::default(),
            error: None,
            finished: false,
        })
    }
}

impl GeneratedPacketIo for AfPacketIo {
    type Error = AfPacketError;
    type Batch<'a>
        = AfPacketGeneratedBatch<'a>
    where
        Self: 'a;

    fn begin_generated(&mut self, egress: ruster_core::IfId) -> Self::Batch<'_> {
        AfPacketGeneratedBatch {
            inner: self.engine.begin_generated(egress),
        }
    }
}

impl PublicationQuiescenceBackend for AfPacketIo {
    type Error = AfPacketError;

    fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {
        self.engine
            .inspect_publication_quiescence()
            .map_err(AfPacketError::Quiescence)
    }

    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
        self.engine.current_publication_disposition()
    }

    fn quiescence_error_disposition(error: &Self::Error) -> PublicationQuiescenceDisposition {
        match error {
            // The TX engine owns the frame and receive() scans completions
            // before exposing a new batch. This one asynchronous state can
            // therefore continue the old publication. All RX ownership
            // observations remain fail-closed because this static classifier
            // cannot distinguish a live lease from another USER status.
            AfPacketError::Quiescence(PublicationQuiescenceError::TxCompletionPending {
                ..
            }) => PublicationQuiescenceDisposition::ContinueOldIo,
            _ => PublicationQuiescenceDisposition::SkipIo,
        }
    }
}

// SAFETY: this live adapter owns the socket, mappings, RX cursors, TX
// ownership metadata, and in-flight accounting as one non-detachable value.
// Its batches and slots borrow only those internal mappings for bounded
// lifetimes, while quiescence covers every RX block and TX frame. No safe
// operation returns the backend or an authoritative alias, so the publication
// identity remains attached to this exact adapter.
#[allow(unsafe_code)]
unsafe impl PublicationBackendAuthority for AfPacketIo {}

// SAFETY: this command only mutably borrows the exact backend to wait on its
// private poll descriptor array. It never moves, replaces, or returns the
// backend and creates no alias to mappings, sockets, or ownership metadata.
#[allow(unsafe_code)]
unsafe impl PublicationBackendControl for AfPacketIo {
    type Command = Duration;
    type Response = Result<bool, AfPacketError>;

    fn execute_publication_backend_command(&mut self, command: Self::Command) -> Self::Response {
        self.wait_for_rx(command)
    }
}

/// A core-facing batch backed by one Linux TPACKET_V3 USER block.
pub struct AfPacketBatch<'a> {
    tx: Option<TxBatch<'a, LinuxOps>>,
    rx_block: Option<UserRxBlock<'a, LinuxOps>>,
    interface: Option<ruster_core::IfId>,
    remaining: usize,
    counters: AfPacketBatchCounters,
    error: Option<AfPacketError>,
    finished: bool,
}

impl AfPacketBatch<'_> {
    fn record_error(&mut self, error: AfPacketError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    fn release_rx(&mut self) {
        let Some(block) = self.rx_block.as_mut() else {
            return;
        };
        let interface = self.interface.expect("RX block has an interface");
        let (first_error, release_error) = match block.complete_remaining() {
            Ok(()) => match block.release() {
                Ok(()) => (None, None),
                Err(source) => {
                    let discard_error = block.release_discarding().err();
                    (Some(source), discard_error)
                }
            },
            Err(source) => (Some(source), block.release_discarding().err()),
        };
        if let Some(source) = first_error {
            self.record_error(AfPacketError::Receive { interface, source });
        }
        if let Some(source) = release_error {
            self.record_error(AfPacketError::Receive { interface, source });
        }
    }

    fn finish_inner(&mut self) -> BatchCompletion<AfPacketError> {
        self.release_rx();
        if let Some(tx) = self.tx.take() {
            let report = tx.finish();
            if let Some(error) = report.first_kick_error {
                self.record_error(AfPacketError::Kick(error));
            }
        }
        self.finished = true;
        BatchCompletion {
            tx_requested: self.counters.tx_requested,
            tx_accepted: self.counters.tx_accepted,
            tx_rejected: self.counters.tx_rejected,
            recycled: self.counters.recycled,
            error: self.error,
        }
    }
}

impl<'batch> PacketBatch for AfPacketBatch<'batch> {
    type Error = AfPacketError;
    type Slot<'slot>
        = AfPacketSlot<'slot, 'batch>
    where
        Self: 'slot;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        if self.remaining == 0 {
            return None;
        }
        let block = self.rx_block.as_mut()?;
        if !block.has_next_packet() {
            self.remaining = 0;
            return None;
        }
        let interface = self.interface.expect("RX block has an interface");
        let tx = self.tx.as_mut().expect("batch owns its TX engine borrow");
        self.remaining -= 1;
        Some(PacketLease::new(AfPacketSlot {
            block,
            tx,
            interface,
            counters: &mut self.counters,
            error: &mut self.error,
        }))
    }

    fn finish(mut self) -> BatchCompletion<Self::Error> {
        self.finish_inner()
    }
}

impl Drop for AfPacketBatch<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // A dropped batch has no return channel for errors, but ownership is
        // still terminal: every remaining RX packet is internally completed,
        // the block is returned to KERNEL, and the existing TxBatch drop hook
        // performs its normal endpoint kick.
        self.release_rx();
        if let Some(tx) = self.tx.take() {
            drop(tx);
        }
        self.finished = true;
    }
}

/// A single core lease over a Linux TPACKET_V3 RX packet.
pub struct AfPacketSlot<'slot, 'batch> {
    block: &'slot mut UserRxBlock<'batch, LinuxOps>,
    tx: &'slot mut TxBatch<'batch, LinuxOps>,
    interface: ruster_core::IfId,
    counters: &'slot mut AfPacketBatchCounters,
    error: &'slot mut Option<AfPacketError>,
}

impl PacketSlot for AfPacketSlot<'_, '_> {
    fn ingress(&self) -> ruster_core::IfId {
        self.interface
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        let result = if self.block.is_pending() {
            self.block.pending_packet_data()
        } else {
            self.block.packet_data()
        };
        result.expect("validated TPACKET_V3 packet remains addressable")
    }

    fn complete(self, completion: SlotCompletion) {
        let Self {
            block,
            tx,
            interface,
            counters,
            error,
        } = self;
        match completion {
            SlotCompletion::Transmit(egress) => {
                counters.tx_requested = counters
                    .tx_requested
                    .checked_add(1)
                    .expect("RX batch TX request count cannot overflow");
                let result = match block.ensure_packet_data() {
                    Ok(payload) => tx.submit(egress, payload).map(|_| ()),
                    Err(source) => Err(mapping_to_tx_submit_error(source)),
                };
                match result {
                    Ok(()) => {
                        counters.tx_accepted = counters
                            .tx_accepted
                            .checked_add(1)
                            .expect("RX batch TX accepted count cannot overflow");
                    }
                    Err(source) => {
                        counters.tx_rejected = counters
                            .tx_rejected
                            .checked_add(1)
                            .expect("RX batch TX rejected count cannot overflow");
                        if matches!(
                            source,
                            TxSubmitError::InvalidStatus { .. }
                                | TxSubmitError::GenerationExhausted { .. }
                                | TxSubmitError::Mapping(_)
                                | TxSubmitError::Ownership(_)
                        ) {
                            record_slot_error(error, AfPacketError::Transmit(source));
                        }
                    }
                }
                if let Err(source) = block.complete_packet() {
                    record_slot_error(error, AfPacketError::Receive { interface, source });
                }
            }
            SlotCompletion::Recycle(_)
            | SlotCompletion::Consume(_)
            | SlotCompletion::LeaseAbandoned => {
                if let Err(source) = block.ensure_packet_data() {
                    record_slot_error(error, AfPacketError::Receive { interface, source });
                } else if let Err(source) = block.complete_packet() {
                    record_slot_error(error, AfPacketError::Receive { interface, source });
                } else {
                    counters.recycled = counters
                        .recycled
                        .checked_add(1)
                        .expect("RX batch recycled count cannot overflow");
                }
            }
        }
    }
}

fn mapping_to_tx_submit_error(source: MappingAccessError) -> TxSubmitError {
    match source {
        MappingAccessError::Ownership(source) => TxSubmitError::Ownership(source),
        source => TxSubmitError::Mapping(source),
    }
}

fn record_slot_error(error: &mut Option<AfPacketError>, source: AfPacketError) {
    if error.is_none() {
        *error = Some(source);
    }
}

fn record_quiescence_error(
    first_error: &mut Option<PublicationQuiescenceError>,
    error: PublicationQuiescenceError,
) {
    let replace = match first_error.as_ref() {
        None => true,
        Some(PublicationQuiescenceError::TxCompletionPending { .. }) => !matches!(
            error,
            PublicationQuiescenceError::TxCompletionPending { .. }
        ),
        Some(_) => false,
    };
    if replace {
        *first_error = Some(error);
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
        let fd = ops.open_socket(SOCK_RAW | SOCK_CLOEXEC)?;
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

/// A checked, non-owning view of one disjoint extent in a live mmap.
///
/// The owning [`MmapRegion`] is retained by `PacketRingResources`. Views are
/// created only after the combined mapping has been checked, and the RX/TX
/// views cover non-overlapping ranges. Keeping the view separate from the mmap
/// owner is what lets one batch borrow RX bytes while its TX slot submits to
/// every endpoint. The view is intentionally `Copy` and has no `Drop`; it
/// never unmaps or owns the mapping. Its lifetime marker ties a view carried by
/// a batch to the `TxBatch<'owner>` borrow of the engine, while `MmapRegion`'s
/// `Drop` remains the sole unmap path.
struct MappingView<'owner, O: PacketOps = LinuxOps> {
    base: NonNull<u8>,
    len: usize,
    _owner: PhantomData<&'owner MmapRegion<O>>,
}

impl<'owner, O: PacketOps> Copy for MappingView<'owner, O> {}

impl<'owner, O: PacketOps> Clone for MappingView<'owner, O> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'owner, O: PacketOps> MappingView<'owner, O> {
    fn ring_view(
        self,
        extents: CombinedRingExtents,
        kind: RingKind,
    ) -> Result<Self, MappingAccessError> {
        let extent = match kind {
            RingKind::Rx => extents.rx(),
            RingKind::Tx => extents.tx(),
        };
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
        let address = self.checked_address(extent.start(), extent.len(), TPACKET_ALIGNMENT)?;
        Ok(Self {
            base: NonNull::new(address).expect("checked mmap address is non-null"),
            len: extent.len(),
            _owner: PhantomData,
        })
    }

    fn ring_address(
        self,
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
        self,
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

    fn exact_packet_address(
        self,
        offset: usize,
        length: usize,
    ) -> Result<*mut u8, MappingAccessError> {
        self.checked_address(offset, length, 1)
    }

    fn read_u32_volatile(self, offset: usize) -> Result<u32, MappingAccessError> {
        let address = self.checked_address(offset, size_of::<u32>(), align_of::<u32>())?;
        // SAFETY: checked_address proves a live, aligned 4-byte range. A
        // volatile read is required because the kernel may update this mmap.
        Ok(unsafe { std::ptr::read_volatile(address.cast::<u32>()) })
    }

    fn read_u16_volatile(self, offset: usize) -> Result<u16, MappingAccessError> {
        let address = self.checked_address(offset, size_of::<u16>(), align_of::<u16>())?;
        // SAFETY: checked_address proves a live, aligned 2-byte range. A
        // volatile read prevents the compiler from caching shared metadata.
        Ok(unsafe { std::ptr::read_volatile(address.cast::<u16>()) })
    }

    fn load_status_acquire(self, offset: usize) -> Result<u32, MappingAccessError> {
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
        self,
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
        mut self,
        layout: RingLayout,
        block_index: usize,
    ) -> Result<UserRxBlock<'owner, O>, MappingAccessError> {
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

        // From this point the kernel has transferred this block to userspace.
        // Validate all kernel-written metadata first, and return the block to
        // KERNEL on every validation failure before exposing the error.
        let result = self.validate_user_block(layout, block_start, status);
        let (block, ownership) = match result {
            Ok(result) => result,
            Err(error) => {
                return match self.store_status_release(status_offset, crate::TP_STATUS_KERNEL) {
                    Ok(()) => Err(error),
                    Err(release_error) => Err(release_error),
                };
            }
        };
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
            pending_data: None,
            ownership,
        })
    }

    fn validate_user_block(
        &self,
        layout: RingLayout,
        block_start: usize,
        status: u32,
    ) -> Result<(BlockDescriptor, RxBlockModel), MappingAccessError> {
        let block = BlockDescriptor {
            version: self.read_u32_volatile(block_start)?,
            offset_to_private: self.read_u32_volatile(checked_offset(block_start, 4)?)? as usize,
            packet_count: self.read_u32_volatile(checked_offset(block_start, 12)?)?,
            first_packet_offset: self.read_u32_volatile(checked_offset(block_start, 16)?)? as usize,
            block_len: self.read_u32_volatile(checked_offset(block_start, 20)?)? as usize,
        };
        let empty_timeout = block.packet_count == 0
            && status & (TP_STATUS_USER | TP_STATUS_BLK_TMO)
                == (TP_STATUS_USER | TP_STATUS_BLK_TMO);
        if empty_timeout {
            block
                .validate_empty_timeout(layout)
                .map_err(MappingAccessError::Geometry)?;
        } else {
            block
                .validate(layout)
                .map_err(MappingAccessError::Geometry)?;
        }

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
        if empty_timeout {
            ownership
                .acquire_empty_timeout()
                .map_err(MappingAccessError::Ownership)?;
        } else {
            ownership
                .acquire(block.packet_count)
                .map_err(MappingAccessError::Ownership)?;
        }
        Ok((block, ownership))
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

    fn view(&self) -> MappingView<'_, O> {
        MappingView {
            base: self.base,
            len: self.len,
            _owner: PhantomData,
        }
    }

    fn ring_view(
        &self,
        extents: CombinedRingExtents,
        kind: RingKind,
    ) -> Result<MappingView<'_, O>, MappingAccessError> {
        self.view().ring_view(extents, kind)
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
        self.view()
            .ring_address(extents, kind, offset, length, alignment)
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
pub(crate) struct UserRxBlock<'owner, O: PacketOps = LinuxOps> {
    // This is an owned, non-owning view value rather than a reference to a
    // local MappingView. The `'owner` marker is the same engine-borrow
    // lifetime held by the enclosing TxBatch, so the sole MmapRegion owner
    // cannot be dropped while this block is usable. MappingView has no Drop;
    // MmapRegion performs the one unmap after all batches have ended.
    mapping: MappingView<'owner, O>,
    status_offset: usize,
    block_start: usize,
    block_len: usize,
    packet_count: u32,
    packet_index: u32,
    packet_offset: usize,
    pending: bool,
    pending_next: Option<usize>,
    pending_data: Option<(usize, usize)>,
    ownership: RxBlockModel,
}

#[allow(dead_code)]
impl<'owner, O: PacketOps> UserRxBlock<'owner, O> {
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
        self.pending_data = Some((absolute_offset, data_len));
        self.pending = true;
        // SAFETY: exact_packet_address proved this exact range is live.
        // UserRxBlock uniquely borrows the mapping, holds USER ownership, and
        // cannot be terminally completed while this returned borrow is live.
        Ok(unsafe { std::slice::from_raw_parts_mut(address, data_len) })
    }

    pub(crate) fn pending_packet_data(&mut self) -> Result<&mut [u8], MappingAccessError> {
        let (offset, length) = self
            .pending_data
            .ok_or(MappingAccessError::PacketNotBorrowed)?;
        let address = self.mapping.exact_packet_address(offset, length)?;
        // SAFETY: `pending_data` was produced by packet_data after checked
        // descriptor bounds, and the slot still owns the same packet.
        Ok(unsafe { std::slice::from_raw_parts_mut(address, length) })
    }

    pub(crate) fn ensure_packet_data(&mut self) -> Result<&mut [u8], MappingAccessError> {
        if self.pending {
            self.pending_packet_data()
        } else {
            self.packet_data()
        }
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.pending
    }

    pub(crate) fn has_next_packet(&self) -> bool {
        self.ownership.owner() == RxOwnership::User
            && self.ownership.remaining() != 0
            && !self.pending
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
        self.pending_data = None;
        Ok(())
    }

    /// Completes packets that the caller did not lease because the batch
    /// budget was smaller than the block. These are internal discard/recycle
    /// transitions and deliberately do not increment PacketBatch::recycled.
    pub(crate) fn complete_remaining(&mut self) -> Result<(), MappingAccessError> {
        if self.pending {
            return Err(MappingAccessError::PacketAlreadyBorrowed);
        }
        while self.ownership.remaining() != 0 {
            self.ownership
                .complete_packet()
                .map_err(MappingAccessError::Ownership)?;
            self.packet_index += 1;
        }
        self.pending_next = None;
        self.pending_data = None;
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

    /// Returns the block to KERNEL even when an earlier internal completion
    /// check failed. This is used only by batch cleanup, where preserving the
    /// mmap ownership protocol is more important than retaining a secondary
    /// model error. The first error is returned after the status publication
    /// has been attempted.
    pub(crate) fn release_discarding(&mut self) -> Result<(), MappingAccessError> {
        let mut first_error = None;

        if self.pending {
            if let Err(error) = self.complete_packet() {
                first_error = Some(error);
            }
        }
        if !self.pending {
            if let Err(error) = self.complete_remaining() {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        if let Err(error) = self
            .ownership
            .release()
            .map_err(MappingAccessError::Ownership)
        {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
        if let Err(error) = self
            .mapping
            .store_status_release(self.status_offset, crate::TP_STATUS_KERNEL)
        {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }

        first_error.map_or(Ok(()), Err)
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

fn poll_timeout_ms(timeout: Duration) -> c_int {
    let millis = timeout.as_millis().min(i32::MAX as u128);
    // Preserve an explicit zero timeout for nonblocking probes, but do not
    // let a positive sub-millisecond wait turn into the same probe.
    let millis = if timeout.is_zero() {
        millis
    } else {
        millis.max(1)
    };
    millis as c_int
}

fn poll_result_from_revents(result: c_int, fds: &[PollFd]) -> PollWaitResult {
    debug_assert!(result >= 0);
    if result == 0 {
        return PollWaitResult::TimedOut;
    }

    // `poll(2)` can report POLLERR, POLLHUP, or POLLNVAL even when only
    // POLLIN was requested. Those events wake the syscall, but they are not
    // RX readiness for this API; the caller must not mistake them for work.
    if fds.iter().any(|poll_fd| poll_fd.revents & POLLIN != 0) {
        PollWaitResult::Ready
    } else {
        PollWaitResult::NoRxReady
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
    fn poll(fds: *mut PollFd, count: usize, timeout_ms: c_int) -> c_int;
}

#[cfg(test)]
mod tests {
    use ruster_core::{
        bind_publication_backend, DropReason, GeneratedAllocationError, GeneratedPacketBatch,
        GeneratedPacketIo, IfId, PacketBatch, PacketIo, PublicationQuiescence,
        PublicationQuiescenceBackend, PublicationQuiescenceDisposition,
    };
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::{Cell, RefCell},
        ffi::c_int,
        os::fd::RawFd,
        ptr::NonNull,
        rc::Rc,
        time::Duration,
    };

    use super::{
        poll_timeout_ms, record_quiescence_error, AfPacketError, AfPacketIoWithOps, LinuxOps,
        MmapRegion, PacketOps, PacketRingResources, PacketSocket, PollFd, PollWaitResult,
        SockaddrLl, TxCompletionError, TxCompletionReport, TxEngine, TxSubmitError, AF_PACKET,
        ETH_P_ALL, POLLIN, SOCK_CLOEXEC, SOCK_RAW,
    };
    use crate::{
        boundary::{ColdRingMetadata, CombinedRingExtents},
        Errno, GeometryError, MappingAccessError, PlatformError, PortConfig,
        PublicationQuiescenceError, RingGeometry, RingKind, RxOwnership, SyscallStage, TxOwnership,
        ValidatedConfig, TPACKET_ALIGNMENT, TP_STATUS_AVAILABLE, TP_STATUS_KERNEL,
        TP_STATUS_SENDING, TP_STATUS_SEND_REQUEST, TP_STATUS_USER, TP_STATUS_WRONG_FORMAT,
    };

    type AfPacketIo = AfPacketIoWithOps<ScriptedOps>;

    // Linux UAPI `TP_STATUS_BLK_TMO` from if_packet.h.
    const TP_STATUS_BLK_TMO: u32 = 1 << 5;

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
    struct AlignedCombinedRing([u8; 12_289]);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ScriptedCall {
        Socket(c_int),
        Set(SyscallStage),
        Map(usize),
        Bind,
        Poll {
            descriptors: usize,
            timeout_ms: c_int,
            events: i16,
        },
        Kick,
        Unmap(usize),
        Close,
    }

    struct ScriptedState {
        fail: Option<SyscallStage>,
        fail_once: Option<SyscallStage>,
        calls: Vec<ScriptedCall>,
        mapping: Box<AlignedCombinedRing>,
        second_mapping: Box<AlignedCombinedRing>,
        map_count: usize,
        poll_result: Result<PollWaitResult, PlatformError>,
        poll_revents: i16,
    }

    #[derive(Clone)]
    struct ScriptedOps(Rc<RefCell<ScriptedState>>);

    impl ScriptedOps {
        fn new(fail: Option<SyscallStage>) -> Self {
            Self(Rc::new(RefCell::new(ScriptedState {
                fail,
                fail_once: None,
                calls: Vec::new(),
                mapping: Box::new(AlignedCombinedRing([0; 12_289])),
                second_mapping: Box::new(AlignedCombinedRing([0; 12_289])),
                map_count: 0,
                poll_result: Ok(PollWaitResult::TimedOut),
                poll_revents: 0,
            })))
        }

        fn calls(&self) -> Vec<ScriptedCall> {
            self.0.borrow().calls.clone()
        }

        fn fail_next(&self, stage: SyscallStage) {
            self.0.borrow_mut().fail_once = Some(stage);
        }

        fn set_poll_result(&self, result: PollWaitResult) {
            self.0.borrow_mut().poll_result = Ok(result);
        }

        fn set_poll_revents(&self, revents: i16) {
            self.0.borrow_mut().poll_revents = revents;
        }

        fn set_poll_error(&self, error: PlatformError) {
            self.0.borrow_mut().poll_result = Err(error);
        }

        fn fail_if_requested(&self, stage: SyscallStage) -> Result<(), PlatformError> {
            let should_fail = {
                let mut state = self.0.borrow_mut();
                if state.fail == Some(stage) {
                    true
                } else if state.fail_once == Some(stage) {
                    state.fail_once = None;
                    true
                } else {
                    false
                }
            };
            if should_fail {
                Err(PlatformError::Syscall {
                    stage,
                    errno: Errno::new(5),
                })
            } else {
                Ok(())
            }
        }

        fn mutate_mapping(&self, mapping_index: usize, update: impl FnOnce(&mut [u8])) {
            let mut state = self.0.borrow_mut();
            let bytes = match mapping_index {
                0 => &mut state.mapping.0[..],
                1 => &mut state.second_mapping.0[..],
                other => panic!("unsupported scripted mapping index {other}"),
            };
            update(bytes);
        }

        fn mapping_u32(&self, mapping_index: usize, offset: usize) -> u32 {
            let state = self.0.borrow();
            let bytes = match mapping_index {
                0 => &state.mapping.0[..],
                1 => &state.second_mapping.0[..],
                other => panic!("unsupported scripted mapping index {other}"),
            };
            let raw: [u8; 4] = bytes[offset..offset + 4]
                .try_into()
                .expect("scripted u32 range");
            u32::from_ne_bytes(raw)
        }
    }

    impl PacketOps for ScriptedOps {
        fn open_socket(&mut self, socket_kind: c_int) -> Result<RawFd, PlatformError> {
            self.0
                .borrow_mut()
                .calls
                .push(ScriptedCall::Socket(socket_kind));
            self.fail_if_requested(SyscallStage::Socket)?;
            Ok(71)
        }

        fn poll(
            &mut self,
            fds: &mut [PollFd],
            timeout_ms: c_int,
        ) -> Result<PollWaitResult, PlatformError> {
            assert!(fds.iter().all(|fd| fd.events == POLLIN));
            let mut state = self.0.borrow_mut();
            state.calls.push(ScriptedCall::Poll {
                descriptors: fds.len(),
                timeout_ms,
                events: fds.first().map_or(0, |fd| fd.events),
            });
            let result = state.poll_result;
            let revents = state.poll_revents;
            drop(state);
            for fd in fds {
                fd.revents = revents;
            }
            result
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
        validated_config(&[IfId(7)]).ports()[0]
    }

    fn validated_config(interfaces: &[IfId]) -> ValidatedConfig {
        validated_config_with_max(interfaces, 1_514)
    }

    fn validated_config_with_max(interfaces: &[IfId], max_frame_len: usize) -> ValidatedConfig {
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
        ValidatedConfig::new(&ports, 4_096, max_frame_len).expect("combined ports")
    }

    fn validated_config_with_rx_blocks(
        interfaces: &[IfId],
        rx_block_count: u32,
    ) -> ValidatedConfig {
        let rx = RingGeometry {
            block_size: 4_096,
            block_count: rx_block_count,
            frame_size: 2_048,
            frame_count: rx_block_count * 2,
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
        ValidatedConfig::new(&ports, 4_096, 1_514).expect("multi-block combined ports")
    }

    #[test]
    fn packet_socket_open_passes_raw_cloexec_socket_kind() {
        let ops = ScriptedOps::new(None);
        let socket = PacketSocket::open(ops.clone()).expect("scripted socket");

        assert_eq!(
            ops.calls(),
            vec![ScriptedCall::Socket(SOCK_RAW | SOCK_CLOEXEC)]
        );
        drop(socket);
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

    fn timeout_empty_ring() -> AlignedRing {
        let mut ring = AlignedRing([0; 4_096]);
        let bytes = &mut ring.0;
        write_u32(bytes, 0, 2);
        write_u32(bytes, 4, 48);
        write_u32(bytes, 8, TP_STATUS_USER | TP_STATUS_BLK_TMO);
        write_u32(bytes, 12, 0);
        write_u32(bytes, 16, 64);
        write_u32(bytes, 20, 64);
        ring
    }

    fn install_rx_packets_at(
        ops: &ScriptedOps,
        mapping_index: usize,
        block_index: usize,
        payloads: &[&[u8]],
    ) {
        assert!(!payloads.is_empty(), "non-empty block fixture");
        ops.mutate_mapping(mapping_index, |bytes| {
            let block_start = block_index * 4_096;
            let block = &mut bytes[block_start..block_start + 4_096];
            block.fill(0);
            write_u32(block, 0, 2);
            write_u32(block, 4, 48);
            write_u32(block, 8, TP_STATUS_USER);
            write_u32(
                block,
                12,
                u32::try_from(payloads.len()).expect("small packet fixture"),
            );
            write_u32(block, 16, 64);
            write_u32(block, 20, 4_096);

            for (index, payload) in payloads.iter().enumerate() {
                let packet_offset = 64 + index * 256;
                let next_offset = if index + 1 == payloads.len() { 0 } else { 256 };
                write_u32(block, packet_offset, next_offset);
                let payload_len = u32::try_from(payload.len()).expect("small packet fixture");
                write_u32(block, packet_offset + 12, payload_len);
                write_u32(block, packet_offset + 16, payload_len);
                write_u32(block, packet_offset + 20, TP_STATUS_USER);
                write_u16(block, packet_offset + 24, 82);
                write_u16(block, packet_offset + 26, 96);
                let data_start = packet_offset + 82;
                let data_end = data_start + payload.len();
                block[data_start..data_end].copy_from_slice(payload);
            }
        });
    }

    fn install_rx_packets(ops: &ScriptedOps, mapping_index: usize, payloads: &[&[u8]]) {
        install_rx_packets_at(ops, mapping_index, 0, payloads);
    }

    fn populate_rx_block(bytes: &mut [u8], block_index: usize, payloads: &[&[u8]]) {
        assert!(!payloads.is_empty(), "non-empty block fixture");
        let block_start = block_index * 4_096;
        let block = &mut bytes[block_start..block_start + 4_096];
        block.fill(0);
        write_u32(block, 0, 2);
        write_u32(block, 4, 48);
        write_u32(block, 8, TP_STATUS_USER);
        write_u32(
            block,
            12,
            u32::try_from(payloads.len()).expect("small packet fixture"),
        );
        write_u32(block, 16, 64);
        write_u32(block, 20, 4_096);

        for (index, payload) in payloads.iter().enumerate() {
            let packet_offset = 64 + index * 256;
            let next_offset = if index + 1 == payloads.len() { 0 } else { 256 };
            write_u32(block, packet_offset, next_offset);
            let payload_len = u32::try_from(payload.len()).expect("small packet fixture");
            write_u32(block, packet_offset + 12, payload_len);
            write_u32(block, packet_offset + 16, payload_len);
            write_u32(block, packet_offset + 20, TP_STATUS_USER);
            write_u16(block, packet_offset + 24, 82);
            write_u16(block, packet_offset + 26, 96);
            let data_start = packet_offset + 82;
            let data_end = data_start + payload.len();
            block[data_start..data_end].copy_from_slice(payload);
        }
    }

    fn install_empty_timeout(ops: &ScriptedOps, mapping_index: usize) {
        ops.mutate_mapping(mapping_index, |bytes| {
            bytes[..4_096].fill(0);
            write_u32(bytes, 0, 2);
            write_u32(bytes, 4, 48);
            write_u32(bytes, 8, TP_STATUS_USER | TP_STATUS_BLK_TMO);
            write_u32(bytes, 12, 0);
            write_u32(bytes, 16, 64);
            write_u32(bytes, 20, 64);
        });
    }

    #[test]
    fn timeout_empty_block_can_be_released_and_reused() {
        let mut backing = timeout_empty_ring();
        // SAFETY: backing remains alive and exclusively accessed through the
        // mapping until mapping is dropped below.
        let mapping = unsafe {
            MmapRegion::borrowed_for_test(
                std::ptr::NonNull::new(backing.0.as_mut_ptr()).expect("test backing"),
                backing.0.len(),
                LinuxOps,
            )
        };

        for iteration in 0..2 {
            let mut block = mapping
                .view()
                .acquire_user_block(rx_layout(), 0)
                .expect("valid timeout-empty USER block");
            assert_eq!(block.packet_count, 0);
            block.release().expect("timeout-empty block release");
            drop(block);
            assert_eq!(
                mapping
                    .view()
                    .load_status_acquire(8)
                    .expect("kernel status"),
                TP_STATUS_KERNEL
            );

            if iteration == 0 {
                mapping
                    .view()
                    .store_status_release(8, TP_STATUS_USER | TP_STATUS_BLK_TMO)
                    .expect("rearm timeout-empty block");
            }
        }
    }

    #[test]
    fn exact_packet_borrow_requires_user_ownership_and_release_is_terminal() {
        let mut backing = one_packet_ring(0);
        // SAFETY: backing remains alive and exclusively accessed through the
        // mapping until mapping is dropped below.
        let mapping = unsafe {
            MmapRegion::borrowed_for_test(
                std::ptr::NonNull::new(backing.0.as_mut_ptr()).expect("test backing"),
                backing.0.len(),
                LinuxOps,
            )
        };
        let mut block = mapping
            .view()
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
            mapping.view().load_status_acquire(8).expect("status"),
            TP_STATUS_KERNEL
        );
        drop(mapping);
        assert_eq!(backing.0[146], 0x5a);
    }

    #[test]
    fn terminal_chain_and_inactive_socket_address_profile_are_exact() {
        let mut backing = one_packet_ring(48);
        // SAFETY: backing outlives the mapping and is not otherwise accessed.
        let mapping = unsafe {
            MmapRegion::borrowed_for_test(
                std::ptr::NonNull::new(backing.0.as_mut_ptr()).expect("test backing"),
                backing.0.len(),
                LinuxOps,
            )
        };
        assert_eq!(
            mapping.view().load_status_acquire(1),
            Err(MappingAccessError::StatusNotAligned { offset: 1 })
        );
        let error = mapping
            .view()
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
        let mut backing = AlignedCombinedRing([0; 12_289]);
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
                ScriptedCall::Socket(_),
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
    fn packet_io_budget_caps_leases_and_zero_budget_is_empty() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let first = [0x11; 60];
        let second = [0x22; 60];
        let third = [0x33; 60];
        install_rx_packets(&ops, 0, &[&first, &second, &third]);

        let mut empty = io.receive(0).expect("zero-budget batch");
        assert!(empty.next_packet().is_none());
        let empty_completion = empty.finish();
        assert_eq!(empty_completion.tx_requested, 0);
        assert_eq!(empty_completion.tx_accepted, 0);
        assert_eq!(empty_completion.tx_rejected, 0);
        assert_eq!(empty_completion.recycled, 0);
        assert!(empty_completion.error.is_none());
        assert!(empty_completion.invariants_hold());
        assert_eq!(ops.mapping_u32(0, 8), TP_STATUS_USER);

        let mut batch = io.receive(2).expect("budgeted batch");
        let first_lease = batch.next_packet().expect("first budgeted packet");
        assert_eq!(first_lease.ingress(), IfId(7));
        first_lease.recycle(DropReason::RouteMiss);
        let second_lease = batch.next_packet().expect("second budgeted packet");
        second_lease.recycle(DropReason::RouteMiss);
        assert!(batch.next_packet().is_none());

        let completion = batch.finish();
        assert_eq!(completion.tx_requested, 0);
        assert_eq!(completion.tx_accepted, 0);
        assert_eq!(completion.tx_rejected, 0);
        assert_eq!(completion.recycled, 2);
        assert!(completion.error.is_none());
        assert!(completion.invariants_hold());
        assert_eq!(ops.mapping_u32(0, 8), TP_STATUS_KERNEL);
    }

    #[test]
    fn wait_for_rx_timeout_polls_all_ports_with_polin() {
        let ops = ScriptedOps::new(None);
        ops.set_poll_result(PollWaitResult::TimedOut);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7), IfId(8)]), ops.clone())
            .expect("two-port packet IO");

        assert_eq!(io.wait_for_rx(Duration::from_millis(1_234)), Ok(false));
        assert!(ops.calls().iter().any(|call| {
            matches!(
                call,
                ScriptedCall::Poll {
                    descriptors: 2,
                    timeout_ms: 1_234,
                    events: POLLIN,
                }
            )
        }));
    }

    #[test]
    fn wait_for_rx_requires_polin_revents_for_readiness() {
        const POLLERR: i16 = 0x0008;
        const POLLHUP: i16 = 0x0010;
        const POLLNVAL: i16 = 0x0020;

        let ops = ScriptedOps::new(None);
        ops.set_poll_result(PollWaitResult::Ready);
        ops.set_poll_revents(POLLERR | POLLHUP | POLLNVAL);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");

        assert_eq!(io.wait_for_rx(Duration::from_millis(1)), Ok(false));

        ops.set_poll_revents(POLLIN);
        assert_eq!(io.wait_for_rx(Duration::from_millis(1)), Ok(true));
    }

    #[test]
    fn wait_for_rx_interrupted_by_signal_is_not_an_error() {
        let ops = ScriptedOps::new(None);
        ops.set_poll_result(PollWaitResult::Interrupted);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops)
            .expect("scripted packet IO");

        assert_eq!(io.wait_for_rx(Duration::from_secs(1)), Ok(false));
    }

    #[test]
    fn positive_submillisecond_wait_rounds_up_to_one_poll_millisecond() {
        assert_eq!(poll_timeout_ms(Duration::from_nanos(500)), 1);
    }

    #[test]
    fn watchdog_quarter_never_becomes_zero_afpacket_poll_timeout() {
        let raw_watchdog_quarter = Duration::from_micros(2) / 4;

        assert_eq!(raw_watchdog_quarter, Duration::from_nanos(500));
        assert_eq!(poll_timeout_ms(raw_watchdog_quarter), 1);
    }

    #[test]
    fn bound_backend_command_bridge_uses_backend_owned_wait() {
        let ops = ScriptedOps::new(None);
        ops.set_poll_result(PollWaitResult::Ready);
        ops.set_poll_revents(POLLIN);
        let io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let (_owner, mut bound) = bind_publication_backend(io).expect("backend binding");

        assert_eq!(
            bound.execute_backend_command(Duration::from_millis(17)),
            Ok(true)
        );
        assert!(ops.calls().iter().any(|call| {
            matches!(
                call,
                ScriptedCall::Poll {
                    descriptors: 1,
                    timeout_ms: 17,
                    events: POLLIN,
                }
            )
        }));
    }

    #[test]
    fn wait_for_rx_poll_failure_preserves_poll_syscall_stage() {
        let ops = ScriptedOps::new(None);
        let platform_error = PlatformError::Syscall {
            stage: SyscallStage::Poll,
            errno: Errno::new(5),
        };
        ops.set_poll_error(platform_error);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops)
            .expect("scripted packet IO");

        assert_eq!(
            io.wait_for_rx(Duration::from_millis(1)),
            Err(AfPacketError::Wait(platform_error))
        );
    }

    #[test]
    fn packet_io_recycles_every_leased_slot_and_accounts_only_leases() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let first = [0x41; 60];
        let second = [0x42; 60];
        install_rx_packets(&ops, 0, &[&first, &second]);

        let mut batch = io.receive(2).expect("two-packet batch");
        batch
            .next_packet()
            .expect("first packet")
            .recycle(DropReason::RouteMiss);
        batch
            .next_packet()
            .expect("second packet")
            .recycle(DropReason::RouteMiss);
        let completion = batch.finish();

        assert_eq!(completion.recycled, 2);
        assert_eq!(completion.tx_requested, 0);
        assert_eq!(completion.tx_accepted, 0);
        assert_eq!(completion.tx_rejected, 0);
        assert!(completion.error.is_none());
        assert!(completion.invariants_hold());
        assert_eq!(ops.mapping_u32(0, 8), TP_STATUS_KERNEL);
    }

    #[test]
    fn packet_io_transmit_uses_any_egress_port_and_preserves_tx_accounting() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7), IfId(8)]), ops.clone())
            .expect("two-port packet IO");
        let payload = [0x5a; 60];
        install_rx_packets(&ops, 0, &[&payload]);

        let mut batch = io.receive(1).expect("multi-port RX batch");
        let lease = batch.next_packet().expect("RX packet");
        assert_eq!(lease.ingress(), IfId(7));
        lease.commit(IfId(8));
        let completion = batch.finish();

        assert_eq!(completion.tx_requested, 1);
        assert_eq!(completion.tx_accepted, 1);
        assert_eq!(completion.tx_rejected, 0);
        assert_eq!(completion.recycled, 0);
        assert!(completion.error.is_none());
        assert!(completion.invariants_hold());
        assert_eq!(ops.mapping_u32(0, 8), TP_STATUS_KERNEL);
        assert_eq!(io.engine.states[1].in_flight, 1);
        assert_eq!(
            io.engine.ports[1].tx_metadata(0).ownership.owner(),
            TxOwnership::SendRequest
        );
        assert_eq!(engine_tx_u32(&io.engine, 1, 0, 20), TP_STATUS_SEND_REQUEST);
        assert_eq!(engine_tx_payload(&io.engine, 1, 0, payload.len()), payload);
        assert_eq!(
            ops.calls()
                .iter()
                .filter(|call| **call == ScriptedCall::Kick)
                .count(),
            1
        );
    }

    #[test]
    fn packet_io_round_robins_rx_acquisition_across_ports() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7), IfId(8)]), ops.clone())
            .expect("two-port packet IO");
        let payload = [0x63; 60];
        // Port 0 stays KERNEL-owned; the cursor must continue to port 1 and
        // expose its independently mapped RX block.
        install_rx_packets(&ops, 1, &[&payload]);

        let mut batch = io.receive(1).expect("round-robin RX batch");
        let lease = batch.next_packet().expect("port 1 packet");
        assert_eq!(lease.ingress(), IfId(8));
        lease.recycle(DropReason::RouteMiss);
        let completion = batch.finish();

        assert_eq!(completion.recycled, 1);
        assert!(completion.error.is_none());
        assert!(completion.invariants_hold());
        assert_eq!(ops.mapping_u32(1, 8), TP_STATUS_KERNEL);
        assert_eq!(ops.mapping_u32(0, 8), TP_STATUS_AVAILABLE);
    }

    #[test]
    fn packet_io_keeps_kernel_rx_cursor_until_user_block_is_acquired() {
        let ops = ScriptedOps::new(None);
        let mut io =
            AfPacketIo::open_with_ops(validated_config_with_rx_blocks(&[IfId(7)], 2), ops.clone())
                .expect("two-block packet IO");
        let first_block_payload = [0xa6; 60];
        let second_block_payload = [0xb7; 60];
        install_rx_packets_at(&ops, 0, 1, &[&second_block_payload]);

        let mut blocked = io.receive(1).expect("kernel-owned head is not an error");
        assert!(blocked.next_packet().is_none());
        let blocked_completion = blocked.finish();
        assert!(blocked_completion.error.is_none());
        assert!(blocked_completion.invariants_hold());
        assert_eq!(io.rx.ports[0].next_block, 0);
        assert_eq!(io.rx.next_port, 0);
        assert_eq!(ops.mapping_u32(0, 8), TP_STATUS_KERNEL);
        assert_eq!(ops.mapping_u32(0, 4_096 + 8), TP_STATUS_USER);

        install_rx_packets_at(&ops, 0, 0, &[&first_block_payload]);
        let mut first = io.receive(1).expect("head block becomes USER");
        let mut first_lease = first.next_packet().expect("head block packet");
        assert_eq!(first_lease.bytes_mut()[0], first_block_payload[0]);
        first_lease.recycle(DropReason::RouteMiss);
        let first_completion = first.finish();
        assert_eq!(first_completion.recycled, 1);
        assert!(first_completion.error.is_none());
        assert_eq!(io.rx.ports[0].next_block, 1);
        assert_eq!(ops.mapping_u32(0, 8), TP_STATUS_KERNEL);

        let mut second = io.receive(1).expect("next FIFO block");
        let mut second_lease = second.next_packet().expect("next block packet");
        assert_eq!(second_lease.bytes_mut()[0], second_block_payload[0]);
        second_lease.recycle(DropReason::RouteMiss);
        let second_completion = second.finish();
        assert_eq!(second_completion.recycled, 1);
        assert!(second_completion.error.is_none());
        assert_eq!(io.rx.ports[0].next_block, 0);
        assert_eq!(ops.mapping_u32(0, 4_096 + 8), TP_STATUS_KERNEL);
    }

    #[test]
    fn packet_io_rejected_tx_is_counted_without_recycling_twice() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("two-frame packet IO");
        let first = [0x6b; 60];
        let second = [0x7c; 60];
        let third = [0x8d; 60];
        install_rx_packets(&ops, 0, &[&first, &second, &third]);

        let mut batch = io.receive(3).expect("three-packet RX batch");
        batch.next_packet().expect("first packet").commit(IfId(7));
        batch.next_packet().expect("second packet").commit(IfId(7));
        batch.next_packet().expect("third packet").commit(IfId(7));
        let completion = batch.finish();

        assert_eq!(completion.tx_requested, 3);
        assert_eq!(completion.tx_accepted, 2);
        assert_eq!(completion.tx_rejected, 1);
        assert_eq!(completion.recycled, 0);
        assert!(completion.error.is_none());
        assert!(completion.invariants_hold());
        assert_eq!(ops.mapping_u32(0, 8), TP_STATUS_KERNEL);
        assert_eq!(io.engine.states[0].in_flight, 2);
        for (frame_index, payload) in [(0, &first[..]), (1, &second[..])] {
            assert_eq!(
                io.engine.ports[0]
                    .tx_metadata(frame_index)
                    .ownership
                    .owner(),
                TxOwnership::SendRequest
            );
            assert_eq!(io.engine.ports[0].tx_metadata(frame_index).generation, 1);
            assert_eq!(
                engine_tx_u32(&io.engine, 0, frame_index, 20),
                TP_STATUS_SEND_REQUEST
            );
            assert_eq!(
                engine_tx_payload(&io.engine, 0, frame_index, payload.len()),
                payload
            );
        }

        set_engine_tx_status(&mut io.engine, 0, 0, TP_STATUS_AVAILABLE);
        set_engine_tx_status(&mut io.engine, 0, 1, TP_STATUS_AVAILABLE);
        let scan = io
            .engine
            .scan_completions(IfId(7), 2)
            .expect("accepted TX frames complete");
        assert_eq!(scan.inspected, 2);
        assert_eq!(scan.reclaimed, 2);
        assert_eq!(io.engine.states[0].in_flight, 0);
        for frame_index in 0..2 {
            assert_eq!(
                io.engine.ports[0]
                    .tx_metadata(frame_index)
                    .ownership
                    .owner(),
                TxOwnership::Available
            );
            assert_eq!(io.engine.ports[0].tx_metadata(frame_index).generation, 1);
            assert_eq!(
                engine_tx_u32(&io.engine, 0, frame_index, 20),
                TP_STATUS_AVAILABLE
            );
        }
    }

    #[test]
    fn packet_io_batch_drop_abandons_lease_and_releases_unleased_packets() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let first = [0x71; 60];
        let second = [0x72; 60];
        install_rx_packets(&ops, 0, &[&first, &second]);

        let mut batch = io.receive(1).expect("drop-test batch");
        let lease = batch.next_packet().expect("abandoned packet");
        assert_eq!(lease.ingress(), IfId(7));
        drop(lease);
        drop(batch);

        assert_eq!(ops.mapping_u32(0, 8), TP_STATUS_KERNEL);
    }

    #[test]
    fn packet_io_batch_processing_error_releases_block_and_keeps_invariant() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let payload = [0x81; 60];
        install_rx_packets(&ops, 0, &[&payload]);

        let mut batch = io.receive(1).expect("error-test batch");
        let tx_status_offset = validated_port().tx_map_offset() + 20;
        ops.mutate_mapping(0, |bytes| write_u32(bytes, tx_status_offset, 0x80));
        batch
            .next_packet()
            .expect("error-test packet")
            .commit(IfId(7));
        let completion = batch.finish();

        assert_eq!(completion.tx_requested, 1);
        assert_eq!(completion.tx_accepted, 0);
        assert_eq!(completion.tx_rejected, 1);
        assert_eq!(completion.recycled, 0);
        assert_eq!(
            completion.error,
            Some(AfPacketError::Transmit(TxSubmitError::InvalidStatus {
                status: 0x80
            }))
        );
        assert!(completion.invariants_hold());
        assert_eq!(ops.mapping_u32(0, 8), TP_STATUS_KERNEL);
    }

    #[test]
    fn packet_io_finish_kick_error_still_releases_block_and_keeps_acceptance() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let payload = [0x91; 60];
        install_rx_packets(&ops, 0, &[&payload]);

        let mut batch = io.receive(1).expect("kick-error batch");
        batch
            .next_packet()
            .expect("kick-error packet")
            .commit(IfId(7));
        ops.fail_next(SyscallStage::Kick);
        let completion = batch.finish();

        assert_eq!(completion.tx_requested, 1);
        assert_eq!(completion.tx_accepted, 1);
        assert_eq!(completion.tx_rejected, 0);
        assert_eq!(completion.recycled, 0);
        let Some(AfPacketError::Kick(PlatformError::Syscall { stage, errno })) = completion.error
        else {
            panic!("finish must report the kick error");
        };
        assert_eq!(stage, SyscallStage::Kick);
        assert_eq!(errno.get(), 5);
        assert!(completion.invariants_hold());
        assert_eq!(ops.mapping_u32(0, 8), TP_STATUS_KERNEL);
        assert_eq!(ops.mapping_u32(0, 4_096 + 20), TP_STATUS_SEND_REQUEST);
        assert!(io.engine.states[0].kick_pending);
    }

    #[test]
    fn packet_io_validation_error_returns_user_block_to_kernel() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let payload = [0xa1; 60];
        install_rx_packets(&ops, 0, &[&payload]);
        ops.mutate_mapping(0, |bytes| write_u32(bytes, 64, 48));

        let error = match io.receive(1) {
            Ok(_) => panic!("malformed block must fail closed"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            AfPacketError::Receive {
                interface: IfId(7),
                source: MappingAccessError::Geometry(GeometryError::TerminalPacketHasNextOffset {
                    offset: 48
                }),
            }
        );
        assert_eq!(ops.mapping_u32(0, 8), TP_STATUS_KERNEL);
    }

    #[test]
    fn packet_io_empty_timeout_block_is_an_empty_released_batch() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        install_empty_timeout(&ops, 0);

        let mut batch = io.receive(64).expect("empty timeout batch");
        assert!(batch.next_packet().is_none());
        let completion = batch.finish();

        assert_eq!(completion.tx_requested, 0);
        assert_eq!(completion.tx_accepted, 0);
        assert_eq!(completion.tx_rejected, 0);
        assert_eq!(completion.recycled, 0);
        assert!(completion.error.is_none());
        assert!(completion.invariants_hold());
        assert_eq!(ops.mapping_u32(0, 8), TP_STATUS_KERNEL);
    }

    #[test]
    fn generated_batch_allocate_write_commit_publishes_fixed_tx_frame_and_kicks() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted generated packet IO");
        let mut batch = io.begin_generated(IfId(7));
        let mut lease = batch.allocate(60).expect("generated TX frame");
        assert_eq!(lease.bytes_mut().len(), 60);
        lease.bytes_mut().fill(0x3c);
        lease.commit();

        let completion = batch.finish();
        assert_eq!(completion.attempts, 1);
        assert_eq!(completion.allocated, 1);
        assert_eq!(completion.failed, 0);
        assert_eq!(completion.requested, 1);
        assert_eq!(completion.cancelled, 0);
        assert_eq!(completion.abandoned, 0);
        assert_eq!(completion.accepted, 1);
        assert_eq!(completion.rejected, 0);
        assert!(completion.error.is_none());
        assert!(completion.invariants_hold());

        assert_eq!(io.engine.states[0].producer_head, 1);
        assert_eq!(io.engine.states[0].completion_head, 0);
        assert_eq!(io.engine.states[0].in_flight, 1);
        assert_eq!(
            io.engine.ports[0].tx_metadata(0).ownership.owner(),
            TxOwnership::SendRequest
        );
        assert_eq!(
            io.engine.ports[0].tx_metadata(1).ownership.owner(),
            TxOwnership::Available
        );
        assert_eq!(engine_tx_u32(&io.engine, 0, 0, 0), 0);
        assert_eq!(engine_tx_u32(&io.engine, 0, 0, 12), 60);
        assert_eq!(engine_tx_u32(&io.engine, 0, 0, 16), 60);
        assert_eq!(engine_tx_u32(&io.engine, 0, 0, 20), TP_STATUS_SEND_REQUEST);
        assert_eq!(engine_tx_u32(&io.engine, 0, 1, 20), TP_STATUS_AVAILABLE);
        assert_eq!(engine_tx_payload(&io.engine, 0, 0, 60), [0x3c; 60]);
        assert_eq!(
            ops.calls()
                .iter()
                .filter(|call| **call == ScriptedCall::Kick)
                .count(),
            1
        );

        set_engine_tx_status(&mut io.engine, 0, 0, TP_STATUS_AVAILABLE);
        io.engine
            .scan_completions(IfId(7), 1)
            .expect("generated TX completion");
        assert_eq!(io.engine.states[0].in_flight, 0);
    }

    #[test]
    fn generated_batch_cancel_recycles_prepared_frame_without_advancing_fifo() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted generated packet IO");
        let mut batch = io.begin_generated(IfId(7));
        let mut lease = batch.allocate(60).expect("generated TX frame");
        lease.bytes_mut().fill(0xa7);
        lease.cancel();
        let completion = batch.finish();

        assert_eq!(completion.attempts, 1);
        assert_eq!(completion.allocated, 1);
        assert_eq!(completion.failed, 0);
        assert_eq!(completion.requested, 0);
        assert_eq!(completion.cancelled, 1);
        assert_eq!(completion.abandoned, 0);
        assert_eq!(completion.accepted, 0);
        assert_eq!(completion.rejected, 0);
        assert!(completion.error.is_none());
        assert!(completion.invariants_hold());
        assert_eq!(io.engine.states[0].producer_head, 0);
        assert_eq!(io.engine.states[0].completion_head, 0);
        assert_eq!(io.engine.states[0].in_flight, 0);
        assert_eq!(
            io.engine.ports[0].tx_metadata(0).ownership.owner(),
            TxOwnership::Available
        );
        assert_eq!(engine_tx_u32(&io.engine, 0, 0, 20), TP_STATUS_AVAILABLE);
        assert_eq!(
            ops.calls()
                .iter()
                .filter(|call| **call == ScriptedCall::Kick)
                .count(),
            0
        );

        let mut retry = io.begin_generated(IfId(7));
        let mut retry_lease = retry.allocate(60).expect("cancelled frame is reusable");
        retry_lease.bytes_mut().fill(0xb8);
        retry_lease.commit();
        let retry_completion = retry.finish();
        assert_eq!(retry_completion.accepted, 1);
        assert_eq!(retry_completion.rejected, 0);
        assert_eq!(io.engine.states[0].producer_head, 1);
        assert_eq!(engine_tx_payload(&io.engine, 0, 0, 60), [0xb8; 60]);

        set_engine_tx_status(&mut io.engine, 0, 0, TP_STATUS_AVAILABLE);
        io.engine
            .scan_completions(IfId(7), 1)
            .expect("reused generated TX completion");
    }

    #[test]
    fn generated_allocation_reports_zero_oversize_and_capacity_shortage_typed() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted generated packet IO");
        let mut invalid = io.begin_generated(IfId(7));
        assert!(matches!(
            invalid.allocate(0),
            Err(GeneratedAllocationError::ZeroLength)
        ));
        assert!(matches!(
            invalid.allocate(1_515),
            Err(GeneratedAllocationError::FrameTooLarge)
        ));
        let invalid_completion = invalid.finish();
        assert_eq!(invalid_completion.attempts, 2);
        assert_eq!(invalid_completion.allocated, 0);
        assert_eq!(invalid_completion.failed, 2);
        assert_eq!(invalid_completion.requested, 0);
        assert_eq!(invalid_completion.cancelled, 0);
        assert_eq!(invalid_completion.abandoned, 0);
        assert_eq!(invalid_completion.accepted, 0);
        assert_eq!(invalid_completion.rejected, 0);
        assert!(invalid_completion.error.is_none());
        assert!(invalid_completion.invariants_hold());

        for payload in [[0xc1; 60], [0xd2; 60]] {
            let mut generated = io.begin_generated(IfId(7));
            let mut lease = generated
                .allocate(payload.len())
                .expect("TX capacity frame");
            lease.bytes_mut().copy_from_slice(&payload);
            lease.commit();
            let completion = generated.finish();
            assert_eq!(completion.accepted, 1);
            assert_eq!(completion.rejected, 0);
            assert!(completion.invariants_hold());
        }
        assert_eq!(io.engine.states[0].producer_head, 0);
        assert_eq!(io.engine.states[0].in_flight, 2);

        let mut unavailable = io.begin_generated(IfId(7));
        assert!(matches!(
            unavailable.allocate(60),
            Err(GeneratedAllocationError::Unavailable)
        ));
        let unavailable_completion = unavailable.finish();
        assert_eq!(unavailable_completion.attempts, 1);
        assert_eq!(unavailable_completion.allocated, 0);
        assert_eq!(unavailable_completion.failed, 1);
        assert_eq!(unavailable_completion.requested, 0);
        assert_eq!(unavailable_completion.accepted, 0);
        assert_eq!(unavailable_completion.rejected, 0);
        assert!(unavailable_completion.error.is_none());
        assert!(unavailable_completion.invariants_hold());
        assert_eq!(io.engine.states[0].producer_head, 0);
        assert_eq!(io.engine.states[0].completion_head, 0);
        assert_eq!(io.engine.states[0].in_flight, 2);

        set_engine_tx_status(&mut io.engine, 0, 0, TP_STATUS_AVAILABLE);
        set_engine_tx_status(&mut io.engine, 0, 1, TP_STATUS_AVAILABLE);
        io.engine
            .scan_completions(IfId(7), 2)
            .expect("capacity frames complete");
        assert_eq!(io.engine.states[0].in_flight, 0);
        assert_eq!(io.engine.states[0].completion_head, 0);
    }

    #[test]
    fn publication_quiescence_checks_all_rx_blocks_and_async_tx_completion() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7), IfId(8)]), ops.clone())
            .expect("two-port packet IO");
        let payload = [0xe3; 60];
        install_rx_packets(&ops, 1, &[&payload]);

        assert!(io.check_publication_quiescence().is_ok());
        assert_eq!(
            io.current_io_disposition(),
            PublicationQuiescenceDisposition::ContinueOldIo
        );

        let mut rx = io.receive(1).expect("receive USER-owned block");
        rx.next_packet()
            .expect("RX block packet")
            .recycle(DropReason::RouteMiss);
        let rx_completion = rx.finish();
        assert_eq!(rx_completion.recycled, 1);
        assert!(rx_completion.error.is_none());
        assert!(io.check_publication_quiescence().is_ok());

        let mut generated = io.begin_generated(IfId(7));
        generated.allocate(60).expect("generated TX frame").commit();
        let generated_completion = generated.finish();
        assert_eq!(generated_completion.accepted, 1);
        assert!(generated_completion.invariants_hold());
        let tx_error = io
            .check_publication_quiescence()
            .expect_err("uncompleted TX frame is not quiescent");
        assert!(matches!(
            tx_error,
            AfPacketError::Quiescence(PublicationQuiescenceError::TxCompletionPending {
                interface: IfId(7),
                frame_index: 0,
                status: TP_STATUS_SEND_REQUEST,
                ownership: TxOwnership::SendRequest,
            })
        ));
        assert_eq!(
            io.current_io_disposition(),
            PublicationQuiescenceDisposition::ContinueOldIo
        );
        assert_eq!(
            <AfPacketIo as PublicationQuiescenceBackend>::quiescence_error_disposition(&tx_error),
            PublicationQuiescenceDisposition::ContinueOldIo
        );

        set_engine_tx_status(&mut io.engine, 0, 0, TP_STATUS_AVAILABLE);
        assert!(matches!(
            io.check_publication_quiescence(),
            Err(AfPacketError::Quiescence(
                PublicationQuiescenceError::TxCompletionPending {
                    status: TP_STATUS_AVAILABLE,
                    ..
                }
            ))
        ));
        io.engine
            .scan_completions(IfId(7), 1)
            .expect("FIFO TX completion scan");
        assert!(io.check_publication_quiescence().is_ok());
        assert_eq!(
            io.current_io_disposition(),
            PublicationQuiescenceDisposition::ContinueOldIo
        );
    }

    #[test]
    fn current_io_disposition_ignores_unleased_user_rx_block() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let payload = [0x7a; 60];
        install_rx_packets(&ops, 0, &[&payload]);

        assert!(io.check_publication_quiescence().is_ok());
        assert_eq!(
            io.current_io_disposition(),
            PublicationQuiescenceDisposition::ContinueOldIo
        );
    }

    #[test]
    fn unleased_rx_block_with_unknown_user_bit_is_fail_closed() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let payload = [0x6d; 60];
        install_rx_packets(&ops, 0, &[&payload]);
        let status = TP_STATUS_USER | 0x8000_0000;
        ops.mutate_mapping(0, |bytes| write_u32(bytes, 8, status));

        let error = io
            .check_publication_quiescence()
            .expect_err("unknown USER status must not be treated as input");
        assert_eq!(
            error,
            AfPacketError::Quiescence(PublicationQuiescenceError::RxBlockUser {
                interface: IfId(7),
                block_index: 0,
                status,
            })
        );
        assert_eq!(
            io.current_io_disposition(),
            PublicationQuiescenceDisposition::ContinueOldIo
        );
        assert_eq!(
            <AfPacketIo as PublicationQuiescenceBackend>::quiescence_error_disposition(&error),
            PublicationQuiescenceDisposition::SkipIo
        );
    }

    #[test]
    fn unleased_timeout_rx_block_does_not_fail_initial_publication_bind() {
        let ops = ScriptedOps::new(None);
        let io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let payload = [0x8b; 60];
        install_rx_packets(&ops, 0, &[&payload]);
        ops.mutate_mapping(0, |bytes| {
            write_u32(bytes, 8, TP_STATUS_USER | TP_STATUS_BLK_TMO);
        });

        let (_owner, mut bound) =
            bind_publication_backend(io).expect("publication binding identity available");
        let guard = bound
            .try_publication_quiescence()
            .expect("unleased kernel-delivered timeout block is not an alias");
        drop(guard);
        assert_eq!(
            bound.current_io_disposition(),
            PublicationQuiescenceDisposition::ContinueOldIo
        );
    }

    #[test]
    fn unleased_timeout_rx_block_does_not_stick_publication_and_io_continues() {
        let ops = ScriptedOps::new(None);
        let io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let payload = [0x9c; 60];
        install_rx_packets(&ops, 0, &[&payload]);
        ops.mutate_mapping(0, |bytes| {
            write_u32(bytes, 8, TP_STATUS_USER | TP_STATUS_BLK_TMO);
        });

        let timeout_error = AfPacketError::Quiescence(PublicationQuiescenceError::RxBlockUser {
            interface: IfId(7),
            block_index: 0,
            status: TP_STATUS_USER | TP_STATUS_BLK_TMO,
        });
        assert_eq!(
            <AfPacketIo as PublicationQuiescenceBackend>::quiescence_error_disposition(
                &timeout_error
            ),
            PublicationQuiescenceDisposition::SkipIo
        );

        let (_owner, mut bound) =
            bind_publication_backend(io).expect("publication binding identity available");
        let guard = bound
            .try_publication_quiescence()
            .expect("timeout-delivered input must not defer publication");
        drop(guard);

        let mut batch = bound
            .receive(1)
            .expect("I/O continues after publication check");
        batch
            .next_packet()
            .expect("timeout-delivered packet remains receivable")
            .recycle(DropReason::RouteMiss);
        let completion = batch.finish();
        assert_eq!(completion.recycled, 1);
        assert!(completion.error.is_none());
        assert!(completion.invariants_hold());
        assert_eq!(ops.mapping_u32(0, 8), TP_STATUS_KERNEL);

        let mut next = bound.receive(1).expect("next I/O operation is not stuck");
        assert!(next.next_packet().is_none());
        let next_completion = next.finish();
        assert!(next_completion.error.is_none());
        assert!(next_completion.invariants_hold());
    }

    #[test]
    fn publication_quiescence_rejects_tx_status_metadata_mismatch_fail_closed() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let status_offset = validated_port().tx_map_offset() + 20;
        ops.mutate_mapping(0, |bytes| {
            write_u32(bytes, status_offset, TP_STATUS_SEND_REQUEST)
        });

        let error = io
            .check_publication_quiescence()
            .expect_err("available metadata cannot own SEND_REQUEST");
        assert_eq!(
            error,
            AfPacketError::Quiescence(PublicationQuiescenceError::TxOwnershipMismatch {
                interface: IfId(7),
                frame_index: 0,
                status: TP_STATUS_SEND_REQUEST,
                ownership: TxOwnership::Available,
                in_flight: 0,
            })
        );
        assert_eq!(
            io.current_io_disposition(),
            PublicationQuiescenceDisposition::ContinueOldIo
        );
        assert_eq!(
            <AfPacketIo as PublicationQuiescenceBackend>::quiescence_error_disposition(&error),
            PublicationQuiescenceDisposition::SkipIo
        );
        ops.mutate_mapping(0, |bytes| {
            write_u32(bytes, status_offset, TP_STATUS_AVAILABLE)
        });
        assert!(io.check_publication_quiescence().is_ok());
    }

    #[test]
    fn generated_batch_finish_and_drop_reclaim_forgotten_prepared_frames() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted generated packet IO");
        let mut finished = io.begin_generated(IfId(7));
        let lease = finished.allocate(60).expect("generated TX frame");
        std::mem::forget(lease);
        let completion = finished.finish();
        assert_eq!(completion.attempts, 1);
        assert_eq!(completion.allocated, 1);
        assert_eq!(completion.failed, 0);
        assert_eq!(completion.requested, 0);
        assert_eq!(completion.cancelled, 0);
        assert_eq!(completion.abandoned, 1);
        assert_eq!(completion.accepted, 0);
        assert_eq!(completion.rejected, 0);
        assert!(completion.error.is_none());
        assert!(completion.invariants_hold());
        assert_eq!(io.engine.states[0].producer_head, 0);
        assert_eq!(io.engine.states[0].completion_head, 0);
        assert_eq!(io.engine.states[0].in_flight, 0);
        assert_eq!(
            io.engine.ports[0].tx_metadata(0).ownership.owner(),
            TxOwnership::Available
        );
        assert!(io.check_publication_quiescence().is_ok());

        let mut dropped = io.begin_generated(IfId(7));
        let lease = dropped.allocate(60).expect("generated TX frame");
        std::mem::forget(lease);
        drop(dropped);
        assert_eq!(io.engine.states[0].producer_head, 0);
        assert_eq!(io.engine.states[0].completion_head, 0);
        assert_eq!(io.engine.states[0].in_flight, 0);
        assert_eq!(
            io.engine.ports[0].tx_metadata(0).ownership.owner(),
            TxOwnership::Available
        );
        assert_eq!(engine_tx_u32(&io.engine, 0, 0, 20), TP_STATUS_AVAILABLE);
        assert!(io.check_publication_quiescence().is_ok());

        let mut next = io.begin_generated(IfId(7));
        next.allocate(60)
            .expect("drop cleanup leaves frame reusable")
            .cancel();
        assert!(next.finish().invariants_hold());

        // Keep both a real generated lease and its batch alive, then forget
        // them at the seam. The explicit batch flag must make the backend
        // conservative even though the Rust borrow has ended at this point.
        let mut forgotten_batch = io.begin_generated(IfId(7));
        let forgotten_lease = forgotten_batch
            .allocate(60)
            .expect("generated lease for forgotten-batch seam");
        std::mem::forget(forgotten_lease);
        std::mem::forget(forgotten_batch);
        assert_eq!(
            io.check_publication_quiescence(),
            Err(AfPacketError::Quiescence(
                PublicationQuiescenceError::GeneratedBatchActive
            ))
        );
        assert_eq!(
            io.current_io_disposition(),
            PublicationQuiescenceDisposition::SkipIo
        );
    }

    #[test]
    fn current_io_disposition_skips_forgotten_rx_batch_with_live_lease() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let payload = [0x4c; 60];
        install_rx_packets(&ops, 0, &[&payload]);

        let mut batch = io.receive(1).expect("receive USER-owned block");
        let lease = batch.next_packet().expect("live RX lease");
        std::mem::forget(lease);
        std::mem::forget(batch);

        assert_eq!(
            io.current_io_disposition(),
            PublicationQuiescenceDisposition::SkipIo
        );
        assert_eq!(
            io.check_publication_quiescence(),
            Err(AfPacketError::Quiescence(
                PublicationQuiescenceError::RxBatchActive
            ))
        );
    }

    #[test]
    fn status33_rx_block_with_live_lease_stays_fail_closed_after_forget() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let payload = [0x5e; 60];
        install_rx_packets(&ops, 0, &[&payload]);
        ops.mutate_mapping(0, |bytes| {
            write_u32(bytes, 8, TP_STATUS_USER | TP_STATUS_BLK_TMO);
        });

        let mut batch = io.receive(1).expect("status-33 block is receivable");
        assert_eq!(
            batch
                .tx
                .as_ref()
                .expect("RX batch retains engine")
                .engine
                .current_publication_disposition(),
            PublicationQuiescenceDisposition::SkipIo
        );
        let lease = batch.next_packet().expect("status-33 packet lease");
        let timeout_error = AfPacketError::Quiescence(PublicationQuiescenceError::RxBlockUser {
            interface: IfId(7),
            block_index: 0,
            status: TP_STATUS_USER | TP_STATUS_BLK_TMO,
        });
        assert_eq!(
            <AfPacketIo as PublicationQuiescenceBackend>::quiescence_error_disposition(
                &timeout_error
            ),
            PublicationQuiescenceDisposition::SkipIo
        );

        // Keep the actual RX lease and its batch alive across the borrow
        // boundary. The explicit active flag must make both the current
        // disposition and the quiescence result conservative after forget.
        std::mem::forget(lease);
        std::mem::forget(batch);
        assert_eq!(
            io.current_io_disposition(),
            PublicationQuiescenceDisposition::SkipIo
        );
        let error = io
            .check_publication_quiescence()
            .expect_err("forgotten status-33 RX lease must block publication");
        assert_eq!(
            error,
            AfPacketError::Quiescence(PublicationQuiescenceError::RxBatchActive)
        );
        assert_eq!(
            <AfPacketIo as PublicationQuiescenceBackend>::quiescence_error_disposition(&error),
            PublicationQuiescenceDisposition::SkipIo
        );
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

    fn set_engine_tx_status<O: PacketOps>(
        engine: &mut TxEngine<O>,
        port_index: usize,
        frame_index: usize,
        status: u32,
    ) {
        let offset = engine.ports[port_index]
            .tx_frame_status_offset(frame_index)
            .expect("TX status offset");
        let offset = engine.ports[port_index].extents.tx().start() + offset;
        engine.ports[port_index]
            .mapping
            .view()
            .store_status_release(offset, status)
            .expect("test status publication");
    }

    fn engine_tx_u32<O: PacketOps>(
        engine: &TxEngine<O>,
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
            .view()
            .read_u32_volatile(absolute)
            .expect("TX field")
    }

    fn engine_tx_payload<O: PacketOps>(
        engine: &TxEngine<O>,
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
        let mut engine =
            TxEngine::open_with_ops(validated_config(&[IfId(7)]), ops.clone()).expect("TX engine");
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
        let mut engine =
            TxEngine::open_with_ops(validated_config(&[IfId(7)]), ops.clone()).expect("TX engine");
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
                first_kick_error: None
            }
        );
        assert_eq!(engine_tx_u32(&engine, 0, 0, 0), 0);
        assert_eq!(engine_tx_u32(&engine, 0, 0, 12), 60);
        assert_eq!(engine_tx_u32(&engine, 0, 0, 16), 60);
        assert_eq!(engine_tx_u32(&engine, 0, 0, 20), TP_STATUS_SEND_REQUEST);
        assert_eq!(engine_tx_payload(&engine, 0, 0, payload.len()), payload);
        assert_eq!(engine.states[0].in_flight, 1);
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
            TxEngine::open_with_ops(validated_config(&[IfId(7)]), ops).expect("TX engine");
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
        assert_eq!(engine.states[0].in_flight, 2);

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
        assert_eq!(engine.states[0].in_flight, 1);
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
        assert_eq!(engine.states[0].in_flight, 0);

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
                reclaimed: 0,
                wrong_format: 1
            }
        );
        assert_eq!(
            engine_tx_u32(&engine, 0, reused.frame_index, 20),
            TP_STATUS_SEND_REQUEST
        );
        assert_eq!(
            engine.ports[0]
                .tx_metadata(reused.frame_index)
                .ownership
                .owner(),
            crate::TxOwnership::SendRequest
        );
        assert_eq!(engine.states[0].in_flight, 1);
        set_engine_tx_status(&mut engine, 0, reused.frame_index, TP_STATUS_AVAILABLE);
        assert_eq!(
            engine
                .scan_completions(IfId(7), 8)
                .expect("requeued format retry completion"),
            TxCompletionReport {
                inspected: 1,
                reclaimed: 1,
                wrong_format: 0
            }
        );
        assert_eq!(engine.states[0].in_flight, 0);
        assert_eq!(
            engine.scan_completions(IfId(99), 1),
            Err(TxCompletionError::UnknownInterface)
        );
    }

    #[test]
    fn completion_scan_kicks_after_available_head_with_send_request_suffix() {
        let ops = ScriptedOps::new(None);
        let mut engine =
            TxEngine::open_with_ops(validated_config(&[IfId(7)]), ops.clone()).expect("TX engine");
        let mut batch = engine.begin_batch();
        let first = batch.submit(IfId(7), &[0x11; 64]).expect("first");
        let second = batch.submit(IfId(7), &[0x22; 64]).expect("second");
        let batch_report = batch.finish();
        assert_eq!(batch_report.kick_attempted, 1);

        // The kernel completed/released the first frame but left the suffix
        // queued. A completion scan must restart the queued SEND_REQUEST.
        set_engine_tx_status(&mut engine, 0, first.frame_index, TP_STATUS_AVAILABLE);
        assert_eq!(
            engine_tx_u32(&engine, 0, second.frame_index, 20),
            TP_STATUS_SEND_REQUEST
        );
        assert_eq!(
            engine
                .scan_completions(IfId(7), 2)
                .expect("partial completion"),
            TxCompletionReport {
                inspected: 2,
                reclaimed: 1,
                wrong_format: 0
            }
        );
        assert_eq!(engine.states[0].in_flight, 1);
        assert_eq!(
            ops.calls()
                .iter()
                .filter(|call| **call == ScriptedCall::Kick)
                .count(),
            2,
            "reclaiming a frame with a SEND_REQUEST suffix must kick again"
        );

        // Model the suffix being consumed by the restarted kernel send.
        set_engine_tx_status(&mut engine, 0, second.frame_index, TP_STATUS_AVAILABLE);
        assert_eq!(
            engine
                .scan_completions(IfId(7), 1)
                .expect("suffix completion"),
            TxCompletionReport {
                inspected: 1,
                reclaimed: 1,
                wrong_format: 0
            }
        );
        assert_eq!(engine.states[0].in_flight, 0);
    }

    #[test]
    fn completion_scan_requeues_wrong_format_and_kicks_with_send_request_suffix() {
        let ops = ScriptedOps::new(None);
        let mut engine =
            TxEngine::open_with_ops(validated_config(&[IfId(7)]), ops.clone()).expect("TX engine");
        let mut batch = engine.begin_batch();
        let first = batch.submit(IfId(7), &[0x11; 64]).expect("first");
        let second = batch.submit(IfId(7), &[0x22; 64]).expect("second");
        let batch_report = batch.finish();
        assert_eq!(batch_report.kick_attempted, 1);

        // With PACKET_LOSS unset, Linux reports WRONG_FORMAT and requires
        // userspace to put that same frame back in SEND_REQUEST before a new
        // send(2) kick. The later frame is still a queued SEND_REQUEST.
        set_engine_tx_status(&mut engine, 0, first.frame_index, TP_STATUS_WRONG_FORMAT);
        assert_eq!(
            engine_tx_u32(&engine, 0, second.frame_index, 20),
            TP_STATUS_SEND_REQUEST
        );
        assert_eq!(
            engine
                .scan_completions(IfId(7), 2)
                .expect("format rejection"),
            TxCompletionReport {
                inspected: 1,
                reclaimed: 0,
                wrong_format: 1
            }
        );
        assert_eq!(
            engine_tx_u32(&engine, 0, first.frame_index, 20),
            TP_STATUS_SEND_REQUEST
        );
        assert_eq!(
            engine.ports[0]
                .tx_metadata(first.frame_index)
                .ownership
                .owner(),
            crate::TxOwnership::SendRequest
        );
        assert_eq!(engine.states[0].completion_head, first.frame_index);
        assert_eq!(engine.states[0].in_flight, 2);
        assert_eq!(
            ops.calls()
                .iter()
                .filter(|call| **call == ScriptedCall::Kick)
                .count(),
            2,
            "WRONG_FORMAT recovery with a queued suffix must restart TX"
        );

        // Once the retried head is consumed, the suffix remains observable
        // and can be completed in FIFO order.
        set_engine_tx_status(&mut engine, 0, first.frame_index, TP_STATUS_SENDING);
        assert_eq!(
            engine.scan_completions(IfId(7), 1).expect("retry accepted"),
            TxCompletionReport {
                inspected: 1,
                reclaimed: 0,
                wrong_format: 0
            }
        );
        set_engine_tx_status(&mut engine, 0, first.frame_index, TP_STATUS_AVAILABLE);
        assert_eq!(
            engine
                .scan_completions(IfId(7), 2)
                .expect("retry completed"),
            TxCompletionReport {
                inspected: 2,
                reclaimed: 1,
                wrong_format: 0
            }
        );
        set_engine_tx_status(&mut engine, 0, second.frame_index, TP_STATUS_AVAILABLE);
        assert_eq!(
            engine
                .scan_completions(IfId(7), 1)
                .expect("suffix completed"),
            TxCompletionReport {
                inspected: 1,
                reclaimed: 1,
                wrong_format: 0
            }
        );
        assert_eq!(engine.states[0].in_flight, 0);
    }

    #[test]
    fn completion_scan_retries_a_failed_recovery_kick_on_next_scan() {
        let ops = ScriptedOps::new(None);
        let mut engine =
            TxEngine::open_with_ops(validated_config(&[IfId(7)]), ops.clone()).expect("TX engine");
        let mut batch = engine.begin_batch();
        let first = batch.submit(IfId(7), &[0x11; 64]).expect("first");
        let second = batch.submit(IfId(7), &[0x22; 64]).expect("second");
        let batch_report = batch.finish();
        assert_eq!(batch_report.kick_attempted, 1);

        // The first frame is released while the suffix remains queued. Make
        // the recovery kick fail once, after the initial batch kick succeeds.
        ops.fail_next(SyscallStage::Kick);
        set_engine_tx_status(&mut engine, 0, first.frame_index, TP_STATUS_AVAILABLE);
        assert!(matches!(
            engine.scan_completions(IfId(7), 2),
            Err(TxCompletionError::Kick(PlatformError::Syscall {
                stage: SyscallStage::Kick,
                errno: _
            }))
        ));
        assert!(engine.states[0].kick_pending);
        assert_eq!(engine.states[0].in_flight, 1);
        assert_eq!(
            engine_tx_u32(&engine, 0, second.frame_index, 20),
            TP_STATUS_SEND_REQUEST
        );
        assert_eq!(
            ops.calls()
                .iter()
                .filter(|call| **call == ScriptedCall::Kick)
                .count(),
            2
        );

        // The one-shot failure is now clear. The next scan must retry the
        // pending kick even though the suffix is still SEND_REQUEST.
        assert_eq!(
            engine.scan_completions(IfId(7), 1),
            Ok(TxCompletionReport {
                inspected: 1,
                reclaimed: 0,
                wrong_format: 0
            })
        );
        assert!(!engine.states[0].kick_pending);
        assert_eq!(
            ops.calls()
                .iter()
                .filter(|call| **call == ScriptedCall::Kick)
                .count(),
            3,
            "a failed recovery kick must be retried by the next scan"
        );

        // Model the suffix being consumed after the successful retry.
        set_engine_tx_status(&mut engine, 0, second.frame_index, TP_STATUS_AVAILABLE);
        assert_eq!(
            engine.scan_completions(IfId(7), 1),
            Ok(TxCompletionReport {
                inspected: 1,
                reclaimed: 1,
                wrong_format: 0
            })
        );
        assert_eq!(engine.states[0].in_flight, 0);
    }

    #[test]
    fn completion_scan_persists_pending_kick_before_later_status_error() {
        let ops = ScriptedOps::new(None);
        let mut engine =
            TxEngine::open_with_ops(validated_config(&[IfId(7)]), ops.clone()).expect("TX engine");
        let mut batch = engine.begin_batch();
        let first = batch.submit(IfId(7), &[0x11; 64]).expect("first");
        let second = batch.submit(IfId(7), &[0x22; 64]).expect("second");
        let batch_report = batch.finish();
        assert_eq!(batch_report.kick_attempted, 1);

        // The first frame is reclaimed, but a later status error aborts this
        // scan before its recovery kick can be attempted.
        set_engine_tx_status(&mut engine, 0, first.frame_index, TP_STATUS_AVAILABLE);
        set_engine_tx_status(&mut engine, 0, second.frame_index, 0x80);
        assert_eq!(
            engine.scan_completions(IfId(7), 2),
            Err(TxCompletionError::InvalidStatus { status: 0x80 })
        );
        assert!(
            engine.states[0].kick_pending,
            "recovery kick must survive a later scan error"
        );
        assert_eq!(engine.states[0].in_flight, 1);

        // The suffix is now a valid pending request. Exercise a failed
        // recovery kick followed by the retry on the next scan.
        set_engine_tx_status(&mut engine, 0, second.frame_index, TP_STATUS_SEND_REQUEST);
        ops.fail_next(SyscallStage::Kick);
        assert!(matches!(
            engine.scan_completions(IfId(7), 1),
            Err(TxCompletionError::Kick(PlatformError::Syscall {
                stage: SyscallStage::Kick,
                errno: _
            }))
        ));
        assert!(engine.states[0].kick_pending);
        assert_eq!(
            engine.scan_completions(IfId(7), 1),
            Ok(TxCompletionReport {
                inspected: 1,
                reclaimed: 0,
                wrong_format: 0
            })
        );
        assert!(!engine.states[0].kick_pending);
        assert_eq!(
            ops.calls()
                .iter()
                .filter(|call| **call == ScriptedCall::Kick)
                .count(),
            3
        );

        set_engine_tx_status(&mut engine, 0, second.frame_index, TP_STATUS_AVAILABLE);
        assert_eq!(
            engine.scan_completions(IfId(7), 1),
            Ok(TxCompletionReport {
                inspected: 1,
                reclaimed: 1,
                wrong_format: 0
            })
        );
        assert_eq!(engine.states[0].in_flight, 0);
    }

    #[test]
    fn initial_batch_kick_failure_persists_pending_for_completion_scan() {
        let ops = ScriptedOps::new(None);
        ops.fail_next(SyscallStage::Kick);
        let mut engine =
            TxEngine::open_with_ops(validated_config(&[IfId(7)]), ops.clone()).expect("TX engine");
        let mut batch = engine.begin_batch();
        let submission = batch.submit(IfId(7), &[0x11; 64]).expect("published");
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
        assert_eq!(
            ops.calls()
                .iter()
                .filter(|call| **call == ScriptedCall::Kick)
                .count(),
            1
        );
        assert!(
            engine.states[0].kick_pending,
            "a failed initial batch kick must remain pending"
        );
        assert_eq!(
            engine_tx_u32(&engine, 0, submission.frame_index, 20),
            TP_STATUS_SEND_REQUEST
        );

        assert_eq!(
            engine.scan_completions(IfId(7), 1),
            Ok(TxCompletionReport {
                inspected: 1,
                reclaimed: 0,
                wrong_format: 0
            })
        );
        assert!(!engine.states[0].kick_pending);
        assert_eq!(
            ops.calls()
                .iter()
                .filter(|call| **call == ScriptedCall::Kick)
                .count(),
            2,
            "the later scan must retry the failed initial kick"
        );
    }

    #[test]
    fn fixed_touched_ports_kick_each_endpoint_once_and_drop_never_retries() {
        let ops = ScriptedOps::new(None);
        let mut engine =
            TxEngine::open_with_ops(validated_config(&[IfId(7), IfId(8)]), ops.clone())
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
        let mut engine = TxEngine::open_with_ops(validated_config(&[IfId(9)]), failing.clone())
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
        assert_eq!(engine.states[0].in_flight, 1);
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
        fn open_socket(&mut self, _socket_kind: c_int) -> Result<RawFd, PlatformError> {
            Ok(73)
        }

        fn poll(
            &mut self,
            _fds: &mut [PollFd],
            _timeout_ms: c_int,
        ) -> Result<PollWaitResult, PlatformError> {
            Ok(PollWaitResult::TimedOut)
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
        let mut backing = AlignedCombinedRing([0; 12_289]);
        let kicks = Rc::new(Cell::new(0));
        let ops = QuietOps {
            base: NonNull::new(backing.0.as_mut_ptr()).expect("quiet backing"),
            kicks: Rc::clone(&kicks),
        };
        let mut engine =
            TxEngine::open_with_ops(validated_config(&[IfId(7)]), ops).expect("quiet TX engine");
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

    #[test]
    fn status33_timeout_block_acquire_release_is_explicitly_terminal() {
        let mut backing = timeout_empty_ring();
        // SAFETY: backing remains alive and is accessed only through this
        // borrowed mapping for the duration of the block.
        let mapping = unsafe {
            MmapRegion::borrowed_for_test(
                NonNull::new(backing.0.as_mut_ptr()).expect("status-33 backing"),
                backing.0.len(),
                LinuxOps,
            )
        };

        // This protects the TPACKET_V3 empty-retirement interpretation:
        // USER|BLK_TMO is acquired as an empty userspace block, then its
        // status is published back to KERNEL exactly once.
        let mut block = mapping
            .view()
            .acquire_user_block(rx_layout(), 0)
            .expect("status-33 timeout block");
        assert_eq!(block.packet_count, 0);
        assert_eq!(block.ownership.owner(), RxOwnership::User);
        assert!(!block.has_next_packet());
        block.release().expect("status-33 release");
        drop(block);
        assert_eq!(mapping.view().load_status_acquire(8), Ok(TP_STATUS_KERNEL));
    }

    #[test]
    fn status33_timeout_block_is_quiescent_for_bind_and_continues_io() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        install_empty_timeout(&ops, 0);

        // This protects publication binding: a kernel-delivered empty timeout
        // is not a userspace alias while no RX batch is active.
        assert_eq!(io.check_publication_quiescence(), Ok(()));
        assert_eq!(
            io.current_io_disposition(),
            PublicationQuiescenceDisposition::ContinueOldIo
        );

        let (_owner, mut bound) =
            bind_publication_backend(io).expect("status-33 publication binding");
        let guard = bound
            .try_publication_quiescence()
            .expect("status-33 block is quiescent");
        drop(guard);
        assert_eq!(
            bound.current_io_disposition(),
            PublicationQuiescenceDisposition::ContinueOldIo
        );

        // This protects the continuation path: the same timeout block remains
        // receivable and is recycled before the following receive call.
        let mut batch = bound.receive(1).expect("status-33 receive");
        assert!(batch.next_packet().is_none());
        let completion = batch.finish();
        assert!(completion.error.is_none());
        assert!(completion.invariants_hold());
        assert_eq!(ops.mapping_u32(0, 8), TP_STATUS_KERNEL);

        let mut next = bound.receive(1).expect("I/O continues after status-33");
        assert!(next.next_packet().is_none());
        let next_completion = next.finish();
        assert!(next_completion.error.is_none());
        assert!(next_completion.invariants_hold());
    }

    #[test]
    fn quiescence_rejects_timeout_bit_without_user_bit() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        install_rx_packets(&ops, 0, &[&[0x31; 60]]);
        let status = TP_STATUS_BLK_TMO;
        ops.mutate_mapping(0, |bytes| write_u32(bytes, 8, status));

        // This protects both sides of the ownership predicate: BLK_TMO by
        // itself is not USER ownership and must be rejected as invalid.
        assert_eq!(
            io.check_publication_quiescence(),
            Err(AfPacketError::Quiescence(
                PublicationQuiescenceError::RxBlockInvalidStatus {
                    interface: IfId(7),
                    block_index: 0,
                    status,
                }
            ))
        );
    }

    #[test]
    fn quiescence_reports_unknown_user_bit_as_first_error() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        install_rx_packets(&ops, 0, &[&[0x32; 60]]);
        let status = TP_STATUS_USER | 0x80;
        ops.mutate_mapping(0, |bytes| write_u32(bytes, 8, status));

        // This protects fail-closed classification of an unknown USER status
        // and the first-error rule before the TX-frame scan can add errors.
        let error = io
            .check_publication_quiescence()
            .expect_err("unknown USER status must be reported");
        assert_eq!(
            error,
            AfPacketError::Quiescence(PublicationQuiescenceError::RxBlockUser {
                interface: IfId(7),
                block_index: 0,
                status,
            })
        );
        assert_eq!(
            <AfPacketIo as PublicationQuiescenceBackend>::quiescence_error_disposition(&error),
            PublicationQuiescenceDisposition::SkipIo
        );
    }

    #[test]
    fn quiescence_requires_inflight_for_tx_completion_pending() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let mut tx = io.engine.begin_batch();
        tx.submit(IfId(7), &[0x33; 64]).expect("TX frame");
        tx.finish();
        io.engine.states[0].in_flight = 0;

        // This protects the `in_flight != 0` guard: a SEND_REQUEST frame with
        // no endpoint accounting is a metadata mismatch, not a completion.
        assert_eq!(
            io.check_publication_quiescence(),
            Err(AfPacketError::Quiescence(
                PublicationQuiescenceError::TxOwnershipMismatch {
                    interface: IfId(7),
                    frame_index: 0,
                    status: TP_STATUS_SEND_REQUEST,
                    ownership: TxOwnership::SendRequest,
                    in_flight: 0,
                }
            ))
        );
    }

    #[test]
    fn quiescence_error_recording_promotes_non_pending_error() {
        let pending = PublicationQuiescenceError::TxCompletionPending {
            interface: IfId(7),
            frame_index: 0,
            status: TP_STATUS_SEND_REQUEST,
            ownership: TxOwnership::SendRequest,
        };
        let mismatch = PublicationQuiescenceError::TxOwnershipMismatch {
            interface: IfId(7),
            frame_index: 1,
            status: TP_STATUS_SEND_REQUEST,
            ownership: TxOwnership::Available,
            in_flight: 1,
        };
        let mut first_error = None;

        // This protects the fail-closed priority rule: a later ownership
        // mismatch must replace a previously observed asynchronous pending
        // completion.
        record_quiescence_error(&mut first_error, pending);
        record_quiescence_error(&mut first_error, mismatch);
        assert_eq!(first_error, Some(mismatch));
    }

    #[test]
    fn quiescence_classifier_only_continues_tx_completion_pending() {
        let pending = AfPacketError::Quiescence(PublicationQuiescenceError::TxCompletionPending {
            interface: IfId(7),
            frame_index: 0,
            status: TP_STATUS_SEND_REQUEST,
            ownership: TxOwnership::SendRequest,
        });
        let invalid = AfPacketError::Quiescence(PublicationQuiescenceError::RxBlockUser {
            interface: IfId(7),
            block_index: 0,
            status: TP_STATUS_USER | 0x80,
        });

        // This protects the publication policy boundary: only an already
        // asynchronous TX completion may continue the old publication.
        assert_eq!(
            <super::AfPacketIo as PublicationQuiescenceBackend>::quiescence_error_disposition(
                &pending
            ),
            PublicationQuiescenceDisposition::ContinueOldIo
        );
        assert_eq!(
            <super::AfPacketIo as PublicationQuiescenceBackend>::quiescence_error_disposition(
                &invalid
            ),
            PublicationQuiescenceDisposition::SkipIo
        );
    }

    #[test]
    fn tx_submit_paths_accept_exact_configured_maximum() {
        let ops = ScriptedOps::new(None);
        let mut engine =
            TxEngine::open_with_ops(validated_config(&[IfId(7)]), ops).expect("TX engine");
        let payload = [0x34; 1_514];

        // This protects the inclusive maximum-frame boundary for the copied
        // TX path.
        let mut batch = engine.begin_batch();
        let submission = batch
            .submit(IfId(7), &payload)
            .expect("exact maximum copied frame");
        assert_eq!(batch.finish().accepted, 1);
        set_engine_tx_status(&mut engine, 0, submission.frame_index, TP_STATUS_AVAILABLE);
        engine
            .scan_completions(IfId(7), 1)
            .expect("copied maximum frame completion");

        // This protects the same inclusive boundary for the backend-owned
        // generated-slot reservation path.
        let mut generated = engine.begin_generated(IfId(7));
        let mut lease = generated
            .allocate(payload.len())
            .expect("exact maximum generated frame");
        assert_eq!(lease.bytes_mut().len(), payload.len());
        lease.bytes_mut().copy_from_slice(&payload);
        lease.commit();
        let completion = generated.finish();
        assert_eq!(completion.accepted, 1);
        assert_eq!(completion.rejected, 0);
    }

    #[test]
    fn completion_scan_rejects_sending_with_wrong_metadata_owner() {
        let ops = ScriptedOps::new(None);
        let mut engine =
            TxEngine::open_with_ops(validated_config(&[IfId(7)]), ops).expect("TX engine");
        let mut batch = engine.begin_batch();
        let submission = batch.submit(IfId(7), &[0x35; 64]).expect("TX frame");
        batch.finish();
        engine.ports[0]
            .tx_metadata_mut(submission.frame_index)
            .ownership
            .kernel_reject_format()
            .expect("test wrong-format ownership");
        set_engine_tx_status(&mut engine, 0, submission.frame_index, TP_STATUS_SENDING);

        // This protects the non-SendRequest branch: SENDING paired with a
        // WrongFormat model must be rejected, not silently treated as idle.
        assert_eq!(
            engine.scan_completions(IfId(7), 1),
            Err(TxCompletionError::UnexpectedOwnership {
                frame_index: submission.frame_index,
                ownership: TxOwnership::WrongFormat,
            })
        );
    }

    #[test]
    fn receive_scans_all_tx_completions_before_starting_batch() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7)]), ops.clone())
            .expect("scripted packet IO");
        let mut tx = io.engine.begin_batch();
        tx.submit(IfId(7), &[0x3a; 64]).expect("in-flight TX frame");
        tx.finish();
        let status_offset = validated_port().tx_map_offset() + 20;
        ops.mutate_mapping(0, |bytes| write_u32(bytes, status_offset, 0x80));

        // This protects the receive ordering: an invalid TX status is exposed
        // as a completion error before an RX batch can be returned.
        let error = match io.receive(0) {
            Err(error) => error,
            Ok(_) => panic!("invalid TX status must prevent an RX batch"),
        };
        assert_eq!(
            error,
            AfPacketError::Completion {
                interface: IfId(7),
                source: TxCompletionError::InvalidStatus { status: 0x80 },
            }
        );
    }

    #[test]
    fn rx_cursor_commits_normalized_round_robin_position() {
        let ops = ScriptedOps::new(None);
        let mut io = AfPacketIo::open_with_ops(validated_config(&[IfId(7), IfId(8)]), ops.clone())
            .expect("two-port packet IO");
        install_rx_packets(&ops, 0, &[&[0x36; 60]]);
        install_rx_packets(&ops, 1, &[&[0x37; 60]]);

        // This protects both RX cursors: ownership transfer from port 0 must
        // commit the next-port cursor to port 1, and then wrap to port 0.
        let mut first = io.receive(1).expect("port 0 receive");
        first
            .next_packet()
            .expect("port 0 packet")
            .recycle(DropReason::RouteMiss);
        first.finish();
        assert_eq!(io.rx.next_port, 1);

        let mut second = io.receive(1).expect("port 1 receive");
        assert_eq!(
            second.next_packet().expect("port 1 packet").ingress(),
            IfId(8)
        );
        second.next_packet();
        // The lease above is intentionally abandoned by the batch cleanup;
        // the cursor assertion is independent of packet accounting.
        second.finish();
        assert_eq!(io.rx.next_port, 0);
    }

    #[test]
    fn packet_data_rejects_user_block_with_no_remaining_packets() {
        let mut backing = one_packet_ring(0);
        // SAFETY: backing remains alive and exclusively accessed through the
        // borrowed mapping below.
        let mapping = unsafe {
            MmapRegion::borrowed_for_test(
                NonNull::new(backing.0.as_mut_ptr()).expect("packet backing"),
                backing.0.len(),
                LinuxOps,
            )
        };
        let mut block = mapping
            .view()
            .acquire_user_block(rx_layout(), 0)
            .expect("one-packet block");
        {
            let packet = block.packet_data().expect("packet lease");
            assert_eq!(packet.len(), 60);
        }
        block.complete_packet().expect("packet completion");
        let expected = Err(MappingAccessError::Ownership(
            crate::OwnershipError::RxReleaseWhileKernelOwned,
        ));

        // This protects the ownership short-circuit: USER ownership with no
        // remaining packets must not re-read a stale descriptor.
        assert_eq!(block.packet_data(), expected);
        block.release().expect("empty user block release");
        assert_eq!(block.packet_data(), expected);
    }

    #[test]
    fn pending_packet_data_requires_pending_lease_and_preserves_bytes() {
        let mut backing = one_packet_ring(0);
        // SAFETY: backing remains alive and exclusively accessed through the
        // borrowed mapping below.
        let mapping = unsafe {
            MmapRegion::borrowed_for_test(
                NonNull::new(backing.0.as_mut_ptr()).expect("pending backing"),
                backing.0.len(),
                LinuxOps,
            )
        };
        let mut block = mapping
            .view()
            .acquire_user_block(rx_layout(), 0)
            .expect("one-packet block");

        // This protects the no-lease error and the pending flag transition.
        assert_eq!(
            block.pending_packet_data(),
            Err(MappingAccessError::PacketNotBorrowed)
        );
        assert!(!block.is_pending());
        {
            let packet = block.packet_data().expect("packet data");
            assert_eq!(packet, &[0xa5; 60]);
        }
        assert!(block.is_pending());
        let pending = block.pending_packet_data().expect("pending packet data");
        assert_eq!(pending, &[0xa5; 60]);
        let _ = pending;
        block.complete_packet().expect("packet completion");
        block.release().expect("block release");
    }

    #[test]
    fn has_next_packet_requires_remaining_unborrowed_user_packet() {
        let mut backing = one_packet_ring(0);
        // SAFETY: backing remains alive and exclusively accessed through the
        // borrowed mapping below.
        let mapping = unsafe {
            MmapRegion::borrowed_for_test(
                NonNull::new(backing.0.as_mut_ptr()).expect("next-packet backing"),
                backing.0.len(),
                LinuxOps,
            )
        };
        let mut block = mapping
            .view()
            .acquire_user_block(rx_layout(), 0)
            .expect("one-packet block");

        // This protects the three-state predicate: ownership, remaining
        // packets, and the absence of an outstanding byte borrow are all
        // required before another packet can be exposed.
        assert!(block.has_next_packet());
        {
            let _packet = block.packet_data().expect("packet data");
        }
        assert!(!block.has_next_packet());
        block.complete_packet().expect("packet completion");
        assert!(!block.has_next_packet());
        block.release().expect("block release");
        assert!(!block.has_next_packet());
    }

    #[test]
    fn complete_remaining_advances_packet_index_for_all_unleased_packets() {
        let mut backing = AlignedRing([0; 4_096]);
        populate_rx_block(&mut backing.0, 0, &[&[0x38; 60], &[0x39; 60]]);
        // SAFETY: backing remains alive and exclusively accessed through the
        // borrowed mapping below.
        let mapping = unsafe {
            MmapRegion::borrowed_for_test(
                NonNull::new(backing.0.as_mut_ptr()).expect("remaining backing"),
                backing.0.len(),
                LinuxOps,
            )
        };
        let mut block = mapping
            .view()
            .acquire_user_block(rx_layout(), 0)
            .expect("two-packet block");
        block
            .complete_remaining()
            .expect("complete unleased packets");

        // This protects the discard loop's monotonic packet cursor and its
        // exact two-completion count.
        assert_eq!(block.packet_index, 2);
        assert!(!block.has_next_packet());
    }

    #[test]
    fn release_discarding_completes_nonpending_packets_and_reports_store_failure() {
        let mut backing = one_packet_ring(0);
        // SAFETY: backing remains alive and exclusively accessed through the
        // borrowed mapping below.
        let mapping = unsafe {
            MmapRegion::borrowed_for_test(
                NonNull::new(backing.0.as_mut_ptr()).expect("discard backing"),
                backing.0.len(),
                LinuxOps,
            )
        };

        // This protects the non-pending cleanup branch: it must complete the
        // packet before releasing the block.
        let mut block = mapping
            .view()
            .acquire_user_block(rx_layout(), 0)
            .expect("first discard block");
        assert_eq!(block.release_discarding(), Ok(()));
        drop(block);
        assert_eq!(mapping.view().load_status_acquire(8), Ok(TP_STATUS_KERNEL));

        mapping
            .view()
            .store_status_release(8, TP_STATUS_USER)
            .expect("rearm discard block");
        let mut block = mapping
            .view()
            .acquire_user_block(rx_layout(), 0)
            .expect("second discard block");
        block.status_offset = backing.0.len();

        // This protects error propagation: a failed final status publication
        // must remain visible even after ownership cleanup has completed.
        assert_eq!(
            block.release_discarding(),
            Err(MappingAccessError::OffsetOutOfBounds {
                offset: backing.0.len(),
                length: 4,
            })
        );
    }

    #[test]
    fn mapping_view_accepts_an_exact_ring_endpoint() {
        let port = validated_port();
        let extents = CombinedRingExtents::for_port(port).expect("validated extents");
        let mut backing = AlignedCombinedRing([0; 12_289]);
        // SAFETY: backing remains alive and exclusively accessed through the
        // borrowed mapping below.
        let mapping = unsafe {
            MmapRegion::borrowed_for_test(
                NonNull::new(backing.0.as_mut_ptr()).expect("endpoint backing"),
                port.combined_map_len(),
                LinuxOps,
            )
        };
        let offset = extents.rx().len() - 16;

        // This protects the inclusive end boundary of a checked ring range.
        let address = mapping
            .ring_address(extents, RingKind::Rx, offset, 16, 1)
            .expect("exact RX endpoint");
        assert_eq!(address, backing.0.as_mut_ptr().wrapping_add(offset));
    }

    #[test]
    fn mmap_map_rejects_zero_and_address_space_overflow_but_accepts_limit() {
        let ops = QuietOps {
            base: NonNull::dangling(),
            kicks: Rc::new(Cell::new(0)),
        };
        let too_large = (isize::MAX as usize)
            .checked_add(1)
            .expect("usize can represent isize max plus one");

        // This protects both invalid-length branches and the exact
        // isize::MAX boundary before a backend map operation is attempted.
        assert!(MmapRegion::map(ops.clone(), 71, 0).is_err());
        assert!(MmapRegion::map(ops.clone(), 71, too_large).is_err());
        let exact = MmapRegion::map(ops, 71, isize::MAX as usize)
            .expect("isize::MAX mapping length is representable");
        drop(exact);
    }

    #[test]
    fn poll_result_requires_nonzero_result_and_polin_bit() {
        let no_rx = [PollFd {
            fd: 71,
            events: POLLIN,
            revents: 0x0008,
        }];
        let rx = [PollFd {
            fd: 71,
            events: POLLIN,
            revents: POLLIN,
        }];

        // This protects all poll-result gates: a zero result is a timeout,
        // non-POLLIN wakeups are not RX work, and POLLIN is readiness.
        assert_eq!(
            super::poll_result_from_revents(0, &rx),
            PollWaitResult::TimedOut
        );
        assert_eq!(
            super::poll_result_from_revents(1, &no_rx),
            PollWaitResult::NoRxReady
        );
        assert_eq!(
            super::poll_result_from_revents(1, &rx),
            PollWaitResult::Ready
        );
    }
}
