use std::{
    ffi::{c_int, c_void},
    mem::{offset_of, size_of},
    os::fd::RawFd,
    ptr::NonNull,
};

use crate::{Errno, PlatformError, SyscallStage, UapiLayout, ValidatedPort};

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
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

const _: [(); 48] = [(); size_of::<Tpacket3Hdr>()];
const _: [(); 48] = [(); size_of::<TpacketBlockDesc>()];
const _: [(); 28] = [(); size_of::<TpacketReq3>()];
const _: [(); 20] = [(); size_of::<SockaddrLl>()];
const _: [(); 20] = [(); offset_of!(Tpacket3Hdr, tp_status)];
const _: [(); 24] = [(); offset_of!(Tpacket3Hdr, tp_mac)];
const _: [(); 8] = [(); offset_of!(TpacketBlockDesc, hdr)];
const _: [(); crate::TPACKET_V3_HDRLEN] = [(); size_of::<Tpacket3Hdr>() + size_of::<SockaddrLl>()];

pub(crate) fn validated_uapi_layout() -> Result<UapiLayout, PlatformError> {
    let layout = UapiLayout {
        tpacket3_header: size_of::<Tpacket3Hdr>(),
        tpacket3_status_offset: offset_of!(Tpacket3Hdr, tp_status),
        tpacket3_mac_offset: offset_of!(Tpacket3Hdr, tp_mac),
        tpacket_block_descriptor: size_of::<TpacketBlockDesc>(),
        block_status_offset: offset_of!(TpacketBlockDesc, hdr),
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
            block_status_offset: 8,
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

// AP0 establishes and reviews the unsafe lifetime boundary. AP1/AP2 will own
// construction and consume these resources through their PacketIo state.
#[allow(dead_code)]
pub(crate) struct PacketRingResources {
    mapping: MmapRegion,
    socket: PacketSocket,
    rx_len: usize,
}

#[allow(dead_code)]
impl PacketRingResources {
    pub(crate) fn open(port: ValidatedPort) -> Result<Self, PlatformError> {
        let socket = PacketSocket::open()?;
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
        socket.bind(port.if_index())?;
        let mapping = MmapRegion::map(socket.fd, port.combined_map_len())?;
        Ok(Self {
            mapping,
            socket,
            rx_len: port.tx_map_offset(),
        })
    }

    pub(crate) fn rx_bytes(&mut self) -> &mut [u8] {
        &mut self.mapping.bytes_mut()[..self.rx_len]
    }

    pub(crate) fn tx_bytes(&mut self) -> &mut [u8] {
        &mut self.mapping.bytes_mut()[self.rx_len..]
    }
}

struct PacketSocket {
    fd: RawFd,
}

impl PacketSocket {
    fn open() -> Result<Self, PlatformError> {
        let protocol = ETH_P_ALL.to_be();
        // SAFETY: `socket` has no borrowed pointer arguments. The constants
        // are Linux UAPI values and a nonnegative return is an owned fd.
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW, c_int::from(protocol)) };
        if fd < 0 {
            return Err(last_error(SyscallStage::Socket));
        }
        Ok(Self { fd })
    }

    fn set_version(&self) -> Result<(), PlatformError> {
        set_socket_option(
            self.fd,
            PACKET_VERSION,
            &TPACKET_V3,
            SyscallStage::SetVersion,
        )
    }

    fn ignore_outgoing(&self) -> Result<(), PlatformError> {
        set_socket_option(
            self.fd,
            PACKET_IGNORE_OUTGOING,
            &1_i32,
            SyscallStage::SetIgnoreOutgoing,
        )
    }

    fn set_ring(
        &self,
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
        set_socket_option(self.fd, option, &request, stage)
    }

    fn bind(&self, if_index: u32) -> Result<(), PlatformError> {
        let address = SockaddrLl {
            sll_family: AF_PACKET as u16,
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex: i32::try_from(if_index).expect("validated interface index"),
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        // SAFETY: `address` is a fully initialized C-layout `sockaddr_ll`;
        // its pointer remains valid for the duration of this blocking call.
        let result = unsafe {
            bind(
                self.fd,
                (&address as *const SockaddrLl).cast(),
                u32::try_from(size_of::<SockaddrLl>()).expect("sockaddr_ll size fits socklen_t"),
            )
        };
        if result < 0 {
            return Err(last_error(SyscallStage::Bind));
        }
        Ok(())
    }
}

impl Drop for PacketSocket {
    fn drop(&mut self) {
        // SAFETY: `fd` is uniquely owned by this value and Drop runs once.
        let _ = unsafe { close(self.fd) };
    }
}

struct MmapRegion {
    base: NonNull<u8>,
    len: usize,
}

impl MmapRegion {
    fn map(fd: RawFd, len: usize) -> Result<Self, PlatformError> {
        // SAFETY: this requests a shared mapping from an owned packet socket;
        // the returned pointer is checked before it is stored.
        let address = unsafe {
            mmap(
                std::ptr::null_mut(),
                len,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                fd,
                0,
            )
        };
        if address as isize == -1 {
            return Err(last_error(SyscallStage::Mmap));
        }
        let base = NonNull::new(address.cast::<u8>()).ok_or(PlatformError::Syscall {
            stage: SyscallStage::Mmap,
            errno: Errno::new(14),
        })?;
        Ok(Self { base, len })
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: `base..base+len` is the live mapping owned by `self`.
        // Requiring `&mut self` prevents overlapping safe mutable slices.
        unsafe { std::slice::from_raw_parts_mut(self.base.as_ptr(), self.len) }
    }
}

impl Drop for MmapRegion {
    fn drop(&mut self) {
        // SAFETY: this exact nonempty mapping is uniquely owned and unmapped
        // once. `PacketRingResources` declares it before the socket so it is
        // dropped before the fd closes.
        let _ = unsafe { munmap(self.base.as_ptr().cast(), self.len) };
    }
}

fn set_socket_option<T>(
    fd: RawFd,
    option: c_int,
    value: &T,
    stage: SyscallStage,
) -> Result<(), PlatformError> {
    // SAFETY: `value` is initialized for `size_of::<T>()` bytes and remains
    // borrowed until `setsockopt` returns; Linux copies option data in-call.
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
        return Err(last_error(stage));
    }
    Ok(())
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
        offset: isize,
    ) -> *mut c_void;
    fn munmap(address: *mut c_void, length: usize) -> c_int;
    fn close(fd: c_int) -> c_int;
}
