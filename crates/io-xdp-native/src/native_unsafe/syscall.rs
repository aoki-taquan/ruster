#![allow(dead_code, unsafe_code)]
//! Private x86_64 Linux syscall and RAII seam used by AF_XDP resource setup.
//!
//! Public construction and transaction ownership live in the safe
//! [`crate::XdpResourceBuilder`] / [`crate::XdpResource`] API. This module
//! supplies the private socket, mmap, and syscall RAII primitives used by that
//! setup layer. The generic syscall boundary is sealed and statically
//! dispatched so NIC-free tests can inject a finite transcript without adding
//! a virtual call to the later packet data path.

use std::{
    ffi::{c_int, c_long, c_short, c_ulong, c_void},
    fmt,
    mem::{align_of, offset_of, size_of},
    os::fd::RawFd,
};

use crate::{
    abi::{
        RingMmapLayout, AF_XDP, BPF_ANY, BPF_ATTR_SIZE, BPF_MAP_CREATE, BPF_MAP_TYPE_XSKMAP,
        BPF_MAP_UPDATE_ELEM, BPF_PROG_LOAD, BPF_PROG_TYPE_XDP, BPF_SYSCALL_NUMBER,
        BPF_XSKMAP_KEY_SIZE, BPF_XSKMAP_VALUE_SIZE,
    },
    ensure_native_syscall_supported, NativeSyscallPlatformError, RingMapError, XdpProgramOperation,
    XskMapOperation,
};

/// Pinned source profile for architecture-dependent syscall constants.
const SYSCALL_ABI_PROFILE: &str =
    "Linux v6.8 x86_64: include/linux/net.h, include/linux/socket.h, \
     include/uapi/asm-generic/fcntl.h, include/uapi/linux/mman.h, \
     include/uapi/asm-generic/mman-common.h, \
     arch/x86/include/generated/uapi/asm/unistd_64.h, include/uapi/linux/bpf.h";

const SOCK_RAW: c_int = 3;
const SOCK_NONBLOCK: c_int = 0x800;
const SOCK_CLOEXEC: c_int = 0x8_0000;
const XDP_SOCKET_KIND: c_int = SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC;

const PROT_READ: c_int = 1;
const PROT_WRITE: c_int = 2;
const MAP_SHARED: c_int = 1;
const MAP_PRIVATE: c_int = 2;
const MAP_ANONYMOUS: c_int = 0x20;
const MSG_DONTWAIT: c_int = 0x40;
const MAP_FAILED: *mut c_void = usize::MAX as *mut c_void;
const NR_BPF: c_long = BPF_SYSCALL_NUMBER as c_long;
// Linux v6.8 include/uapi/linux/fcntl.h defines this as
// F_LINUX_SPECIFIC_BASE + 6, with the generic base equal to 1024. The
// duplicate is used only for the cold XDP identity guard.
const F_DUPFD_CLOEXEC: c_int = 1_030;

type SockLen = u32;
type Offset = i64;
type PollCount = usize;

const _: [(); 4] = [(); size_of::<c_int>()];
const _: [(); 4] = [(); size_of::<SockLen>()];
const _: [(); 8] = [(); size_of::<Offset>()];
const _: [(); 8] = [(); size_of::<PollCount>()];
const _: [(); 4] = [(); size_of::<RawFd>()];
const _: [(); 8] = [(); size_of::<c_long>()];
const _: [(); 8] = [(); size_of::<c_ulong>()];
const _: [(); 8] = [(); size_of::<usize>()];

/// Largest positive errno encoded by the reviewed Linux syscall ABI.
const MAX_LINUX_ERRNO: i32 = 4_095;

/// Bounded positive Linux errno value.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Errno {
    Linux(u16),
    InvalidCapture,
}

impl Errno {
    fn new(raw: i32) -> Option<Self> {
        if (1..=MAX_LINUX_ERRNO).contains(&raw) {
            Some(Self::Linux(raw as u16))
        } else {
            None
        }
    }

    const fn invalid_capture() -> Self {
        Self::InvalidCapture
    }

    pub(crate) const fn raw(self) -> Option<u16> {
        match self {
            Self::Linux(raw) => Some(raw),
            Self::InvalidCapture => None,
        }
    }
}

impl fmt::Debug for Errno {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linux(raw) => formatter.debug_tuple("Errno").field(raw).finish(),
            Self::InvalidCapture => formatter.write_str("Errno(<invalid-capture>)"),
        }
    }
}

/// Exact cold syscall stage associated with an errno.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SyscallStage {
    OpenSocket,
    SetSocketOption,
    GetSocketOption,
    MapMemory,
    UnmapMemory,
    BindSocket,
    PollSocket,
    SendToSocket,
    CloseSocket,
}

/// One syscall failure with no descriptor, address, or packet data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SyscallError {
    pub(crate) stage: SyscallStage,
    pub(crate) errno: Errno,
}

/// Checked argument failure detected before entering libc.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SyscallArgumentError {
    InvalidFileDescriptor,
    ZeroLength { stage: SyscallStage },
    LengthDoesNotFitSockLen { stage: SyscallStage, length: usize },
    OffsetDoesNotFitOffT { offset: u64 },
    KernelLengthOutOfBounds { capacity: usize, actual: usize },
    LengthDoesNotFitAddressSpace { stage: SyscallStage, length: usize },
}

/// Fixed-size error from the private syscall/RAII seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResourceError {
    Platform(NativeSyscallPlatformError),
    Argument(SyscallArgumentError),
    Syscall(SyscallError),
}

/// The two eBPF operations currently admitted by this native seam.
///
/// `bpf(2)` accepts a pointer to the full `union bpf_attr`; keeping the
/// operation name beside the typed error prevents a map-create failure from
/// being confused with an element-update failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BpfResourceError {
    Platform(NativeSyscallPlatformError),
    Argument(BpfArgumentError),
    Syscall {
        operation: XskMapOperation,
        errno: Errno,
    },
    UnexpectedReturn {
        operation: XskMapOperation,
        value: c_long,
    },
}

/// Fixed-shape failure from the `BPF_PROG_LOAD` syscall seam.
///
/// Unlike map operations, program loading has a verifier log that must be
/// owned after the temporary log buffer is released. It therefore has its own
/// non-`Copy` error rather than widening the existing map error.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum BpfProgramResourceError {
    Platform(NativeSyscallPlatformError),
    Argument(BpfProgramArgumentError),
    Syscall {
        operation: XdpProgramOperation,
        errno: Errno,
        verifier_log: String,
    },
    InvalidFileDescriptor {
        operation: XdpProgramOperation,
        verifier_log: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BpfArgumentError {
    InvalidMaxEntries { max_entries: u32 },
    QueueIdOutOfRange { queue_id: u32, max_entries: u32 },
    InvalidFileDescriptor { operation: XskMapOperation },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BpfProgramArgumentError {
    InstructionCountMismatch { insn_cnt: u32, byte_len: usize },
    InvalidLogSize,
}

/// Reviewed `union bpf_attr` map-create variant.
///
/// The field order and widths are taken from
/// `/usr/src/linux-headers-6.8.0-137/include/uapi/linux/bpf.h:1398-1427`.
/// The explicit padding fields model the x86_64 `__aligned_u64` boundaries so
/// that the bytes copied into the full union never contain uninitialized
/// padding.
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfMapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
}

/// Reviewed `union bpf_attr` map-element variant used by update.
///
/// The field order and widths are taken from
/// `/usr/src/linux-headers-6.8.0-137/include/uapi/linux/bpf.h:1429-1437`.
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfMapElemAttr {
    map_fd: u32,
    _padding: u32,
    key: u64,
    value: u64,
    flags: u64,
}

/// Reviewed `union bpf_attr` program-load variant.
///
/// The field order and widths are taken from the anonymous
/// `BPF_PROG_LOAD` structure at
/// `/usr/src/linux-headers-6.8.0-137/include/uapi/linux/bpf.h:1456-1496`.
/// The final `log_true_size` field is included because the kernel may write
/// the actual verifier-log extent there. The syscall seam therefore passes the
/// full attr as a mutable Rust byte slice, and the separate `log_buf` is also
/// writable for verifier output.
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
    prog_btf_fd: u32,
    func_info_rec_size: u32,
    func_info: u64,
    func_info_cnt: u32,
    line_info_rec_size: u32,
    line_info: u64,
    line_info_cnt: u32,
    attach_btf_id: u32,
    attach_prog_fd: u32,
    core_relo_cnt: u32,
    fd_array: u64,
    core_relos: u64,
    core_relo_rec_size: u32,
    log_true_size: u32,
}

/// The complete x86_64 `union bpf_attr` storage.
///
/// Only the two command variants above are modeled. The byte array is an
/// intentional full-union member: every constructor starts with 144 zero
/// bytes, then overwrites only its selected variant before passing the union
/// size to `bpf(2)`.
#[repr(C)]
union BpfAttr {
    map_create: BpfMapCreateAttr,
    map_elem: BpfMapElemAttr,
    prog_load: BpfProgLoadAttr,
    zeroed: [u8; BPF_ATTR_SIZE],
}

const _: [(); 72] = [(); size_of::<BpfMapCreateAttr>()];
const _: [(); 32] = [(); size_of::<BpfMapElemAttr>()];
const _: [(); 144] = [(); size_of::<BpfProgLoadAttr>()];
const _: [(); BPF_ATTR_SIZE] = [(); size_of::<BpfAttr>()];
const _: [(); 8] = [(); align_of::<BpfAttr>()];
const _: [(); 0] = [(); offset_of!(BpfMapCreateAttr, map_type)];
const _: [(); 4] = [(); offset_of!(BpfMapCreateAttr, key_size)];
const _: [(); 8] = [(); offset_of!(BpfMapCreateAttr, value_size)];
const _: [(); 12] = [(); offset_of!(BpfMapCreateAttr, max_entries)];
const _: [(); 16] = [(); offset_of!(BpfMapCreateAttr, map_flags)];
const _: [(); 64] = [(); offset_of!(BpfMapCreateAttr, map_extra)];
const _: [(); 0] = [(); offset_of!(BpfMapElemAttr, map_fd)];
const _: [(); 8] = [(); offset_of!(BpfMapElemAttr, key)];
const _: [(); 16] = [(); offset_of!(BpfMapElemAttr, value)];
const _: [(); 24] = [(); offset_of!(BpfMapElemAttr, flags)];
const _: [(); 0] = [(); offset_of!(BpfProgLoadAttr, prog_type)];
const _: [(); 4] = [(); offset_of!(BpfProgLoadAttr, insn_cnt)];
const _: [(); 8] = [(); offset_of!(BpfProgLoadAttr, insns)];
const _: [(); 16] = [(); offset_of!(BpfProgLoadAttr, license)];
const _: [(); 24] = [(); offset_of!(BpfProgLoadAttr, log_level)];
const _: [(); 28] = [(); offset_of!(BpfProgLoadAttr, log_size)];
const _: [(); 32] = [(); offset_of!(BpfProgLoadAttr, log_buf)];
const _: [(); 140] = [(); offset_of!(BpfProgLoadAttr, log_true_size)];

const BPF_INSN_SIZE: usize = 8;
const VERIFIER_LOG_LEVEL: u32 = 1;
const VERIFIER_LOG_SIZE: usize = 64 * 1024;
const GPL_LICENSE: &[u8] = b"GPL\0";

fn map_create_attr(max_entries: u32) -> [u8; BPF_ATTR_SIZE] {
    let mut attr = BpfAttr {
        zeroed: [0_u8; BPF_ATTR_SIZE],
    };
    // SAFETY: `BpfMapCreateAttr` is a fully initialized, C-layout Copy value.
    // The union was initialized with the complete zeroed storage above, so
    // bytes after this 72-byte variant remain zero.
    unsafe {
        attr.map_create = BpfMapCreateAttr {
            map_type: BPF_MAP_TYPE_XSKMAP,
            key_size: BPF_XSKMAP_KEY_SIZE,
            value_size: BPF_XSKMAP_VALUE_SIZE,
            max_entries,
            map_flags: 0,
            inner_map_fd: 0,
            numa_node: 0,
            map_name: [0; 16],
            map_ifindex: 0,
            btf_fd: 0,
            btf_key_type_id: 0,
            btf_value_type_id: 0,
            btf_vmlinux_value_type_id: 0,
            map_extra: 0,
        };
        attr.zeroed
    }
}

fn map_update_elem_attr(map_fd: u32, key: &u32, value: &u32) -> [u8; BPF_ATTR_SIZE] {
    let mut attr = BpfAttr {
        zeroed: [0_u8; BPF_ATTR_SIZE],
    };
    let key = u64::try_from(key as *const u32 as usize).expect("reviewed pointer fits u64");
    let value = u64::try_from(value as *const u32 as usize).expect("reviewed pointer fits u64");
    // SAFETY: `BpfMapElemAttr` is a fully initialized, C-layout Copy value.
    // The union was initialized with the complete zeroed storage above, so
    // bytes after this 32-byte variant remain zero.
    unsafe {
        attr.map_elem = BpfMapElemAttr {
            map_fd,
            _padding: 0,
            key,
            value,
            flags: BPF_ANY,
        };
        attr.zeroed
    }
}

fn program_load_attr(
    instructions: &[u8],
    insn_cnt: u32,
    log_buf: &mut [u8],
) -> Result<[u8; BPF_ATTR_SIZE], BpfProgramArgumentError> {
    let log_size =
        u32::try_from(log_buf.len()).map_err(|_| BpfProgramArgumentError::InvalidLogSize)?;
    let insns = u64::try_from(instructions.as_ptr() as usize)
        .expect("reviewed x86_64 pointer fits __aligned_u64");
    let license = u64::try_from(GPL_LICENSE.as_ptr() as usize)
        .expect("reviewed x86_64 pointer fits __aligned_u64");
    let log = u64::try_from(log_buf.as_mut_ptr() as usize)
        .expect("reviewed x86_64 pointer fits __aligned_u64");
    let mut attr = BpfAttr {
        zeroed: [0_u8; BPF_ATTR_SIZE],
    };
    // SAFETY: `BpfProgLoadAttr` is a fully initialized, C-layout Copy value.
    // The union starts as the complete zeroed 144-byte extent; all fields not
    // used by this XDP load variant therefore remain zero, including the
    // output-only `log_true_size` at offset 140 until the kernel writes it.
    unsafe {
        attr.prog_load = BpfProgLoadAttr {
            prog_type: BPF_PROG_TYPE_XDP,
            insn_cnt,
            insns,
            // `BPF_PROG_LOAD` receives a NUL-terminated GPL-compatible
            // license string. Supplying `GPL` keeps the loader compatible with
            // helpers whose availability is restricted to GPL-compatible
            // programs, and is required by the kernel's license validation.
            license,
            log_level: VERIFIER_LOG_LEVEL,
            log_size,
            log_buf: log,
            kern_version: 0,
            prog_flags: 0,
            prog_name: [0; 16],
            prog_ifindex: 0,
            expected_attach_type: 0,
            prog_btf_fd: 0,
            func_info_rec_size: 0,
            func_info: 0,
            func_info_cnt: 0,
            line_info_rec_size: 0,
            line_info: 0,
            line_info_cnt: 0,
            attach_btf_id: 0,
            attach_prog_fd: 0,
            core_relo_cnt: 0,
            fd_array: 0,
            core_relos: 0,
            core_relo_rec_size: 0,
            log_true_size: 0,
        };
        Ok(attr.zeroed)
    }
}

fn verifier_log_from_attr(attr: &[u8; BPF_ATTR_SIZE], log_buf: &[u8]) -> String {
    let reported = u32::from_ne_bytes(
        attr[140..140 + size_of::<u32>()]
            .try_into()
            .expect("log_true_size is a four-byte bpf attr field"),
    ) as usize;
    let reported_len = if reported == 0 {
        log_buf.len()
    } else {
        reported.min(log_buf.len())
    };
    let end = log_buf[..reported_len]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(reported_len);
    String::from_utf8_lossy(&log_buf[..end]).into_owned()
}

impl From<SyscallArgumentError> for ResourceError {
    fn from(value: SyscallArgumentError) -> Self {
        Self::Argument(value)
    }
}

fn syscall_error(stage: SyscallStage, errno: Errno) -> ResourceError {
    ResourceError::Syscall(SyscallError { stage, errno })
}

fn checked_sock_len(stage: SyscallStage, length: usize) -> Result<SockLen, SyscallArgumentError> {
    if length == 0 {
        return Err(SyscallArgumentError::ZeroLength { stage });
    }
    SockLen::try_from(length)
        .map_err(|_| SyscallArgumentError::LengthDoesNotFitSockLen { stage, length })
}

fn checked_offset(offset: u64) -> Result<Offset, SyscallArgumentError> {
    Offset::try_from(offset).map_err(|_| SyscallArgumentError::OffsetDoesNotFitOffT { offset })
}

fn checked_mmap_length(length: usize) -> Result<(), SyscallArgumentError> {
    if length == 0 {
        return Err(SyscallArgumentError::ZeroLength {
            stage: SyscallStage::MapMemory,
        });
    }
    if length > isize::MAX as usize {
        return Err(SyscallArgumentError::LengthDoesNotFitAddressSpace {
            stage: SyscallStage::MapMemory,
            length,
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) struct PollDescriptor {
    fd: RawFd,
    events: c_short,
    revents: c_short,
}

impl PollDescriptor {
    const fn new(fd: RawFd, events: c_short) -> Self {
        Self {
            fd,
            events,
            revents: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PollResult {
    pub(crate) ready: u32,
    pub(crate) events: i16,
}

#[derive(Clone, Copy)]
pub(crate) enum MapRequest {
    Anonymous {
        byte_len: usize,
    },
    Shared {
        fd: RawFd,
        byte_len: usize,
        offset: Offset,
    },
}

impl MapRequest {
    fn byte_len(self) -> usize {
        match self {
            Self::Anonymous { byte_len } | Self::Shared { byte_len, .. } => byte_len,
        }
    }
}

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// Sealed cold-path boundary; generic users are monomorphized, never dynamic.
pub(crate) trait Syscalls: sealed::Sealed {
    fn socket(&self, domain: c_int, kind: c_int, protocol: c_int) -> Result<RawFd, Errno>;
    fn set_socket_option(
        &self,
        fd: RawFd,
        level: c_int,
        name: c_int,
        value: &[u8],
        length: SockLen,
    ) -> Result<(), Errno>;
    fn get_socket_option(
        &self,
        fd: RawFd,
        level: c_int,
        name: c_int,
        value: &mut [u8],
        length: &mut SockLen,
    ) -> Result<(), Errno>;
    fn mmap(&self, request: MapRequest) -> Result<*mut c_void, Errno>;
    fn munmap(&self, address: *mut c_void, byte_len: usize) -> Result<(), Errno>;
    fn bind(&self, fd: RawFd, address: &[u8], length: SockLen) -> Result<(), Errno>;
    fn poll(&self, descriptor: &mut PollDescriptor, timeout_millis: c_int) -> Result<u32, Errno>;
    fn send_to_wakeup(&self, fd: RawFd) -> Result<(), Errno>;
    /// Passes a mutable full `union bpf_attr` extent because commands such as
    /// `BPF_PROG_LOAD` may write output fields including `log_true_size` at
    /// attr offset 140.
    fn bpf(&self, command: u32, attr: &mut [u8]) -> Result<c_long, Errno>;
    fn close(&self, fd: RawFd) -> Result<(), Errno>;
}

/// Result metadata returned by one native `recvmsg(2)` call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecvMessage {
    /// Number of payload bytes copied into the caller's buffer.
    pub(crate) byte_len: usize,
    /// Kernel message flags, including `MSG_TRUNC` when applicable.
    pub(crate) flags: c_int,
}

/// Sealed cold-path syscall boundary for rtnetlink XDP attachment.
///
/// This is a separate static seam from the AF_XDP data setup methods. It keeps
/// the netlink-only `getsockname(2)` and `recvmsg(2)` contracts explicit while
/// preserving monomorphized dispatch and leaving the packet path untouched.
pub(crate) trait NetlinkSyscalls: sealed::Sealed {
    fn socket(&self, domain: c_int, kind: c_int, protocol: c_int) -> Result<RawFd, Errno>;
    fn bind(&self, fd: RawFd, address: &[u8], length: u32) -> Result<(), Errno>;
    fn getsockname(&self, fd: RawFd, address: &mut [u8], length: &mut u32) -> Result<(), Errno>;
    fn dup_cloexec(&self, fd: RawFd) -> Result<RawFd, Errno>;
    fn send_netlink(&self, fd: RawFd, message: &[u8], destination: &[u8]) -> Result<usize, Errno>;
    fn recvmsg(&self, fd: RawFd, buffer: &mut [u8]) -> Result<RecvMessage, Errno>;
    fn close(&self, fd: RawFd) -> Result<(), Errno>;
}

/// Production Linux implementation used by the checked resource setup API.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LinuxSyscalls;

impl sealed::Sealed for LinuxSyscalls {}

impl Syscalls for LinuxSyscalls {
    fn socket(&self, domain: c_int, kind: c_int, protocol: c_int) -> Result<RawFd, Errno> {
        // SAFETY: `socket` has no pointer arguments. All integers are reviewed
        // Linux v6.8 constants, and a nonnegative result is an owned fd.
        let result = unsafe { ffi::socket(domain, kind, protocol) };
        result_from_minus_one(result).map(|value| value as RawFd)
    }

    fn set_socket_option(
        &self,
        fd: RawFd,
        level: c_int,
        name: c_int,
        value: &[u8],
        length: SockLen,
    ) -> Result<(), Errno> {
        debug_assert_eq!(usize::try_from(length), Ok(value.len()));
        // SAFETY: `value` remains readable for exactly `length` bytes during
        // the call. The checked wrapper produced the matching SockLen.
        let result =
            unsafe { ffi::setsockopt(fd, level, name, value.as_ptr().cast::<c_void>(), length) };
        result_from_minus_one(result).map(|_| ())
    }

    fn get_socket_option(
        &self,
        fd: RawFd,
        level: c_int,
        name: c_int,
        value: &mut [u8],
        length: &mut SockLen,
    ) -> Result<(), Errno> {
        debug_assert_eq!(usize::try_from(*length), Ok(value.len()));
        // SAFETY: `value` is writable for its checked initial length and
        // `length` is a valid in/out SockLen for the complete call.
        let result = unsafe {
            ffi::getsockopt(fd, level, name, value.as_mut_ptr().cast::<c_void>(), length)
        };
        result_from_minus_one(result).map(|_| ())
    }

    fn mmap(&self, request: MapRequest) -> Result<*mut c_void, Errno> {
        let (byte_len, flags, fd, offset) = match request {
            MapRequest::Anonymous { byte_len } => (byte_len, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
            MapRequest::Shared {
                fd,
                byte_len,
                offset,
            } => (byte_len, MAP_SHARED, fd, offset),
        };
        // SAFETY: the caller checked a nonzero extent and representable
        // offset. A null hint asks the kernel to choose the address. No memory
        // is dereferenced here; only MAP_FAILED denotes failure.
        let address = unsafe {
            ffi::mmap(
                std::ptr::null_mut(),
                byte_len,
                PROT_READ | PROT_WRITE,
                flags,
                fd,
                offset,
            )
        };
        decode_mmap_result(address)
    }

    fn munmap(&self, address: *mut c_void, byte_len: usize) -> Result<(), Errno> {
        // SAFETY: `MappedRegion` calls this at most once with the exact address
        // and length returned by one successful mmap call.
        let result = unsafe { ffi::munmap(address, byte_len) };
        result_from_minus_one(result).map(|_| ())
    }

    fn bind(&self, fd: RawFd, address: &[u8], length: SockLen) -> Result<(), Errno> {
        debug_assert_eq!(usize::try_from(length), Ok(address.len()));
        // SAFETY: `address` remains readable for exactly the checked SockLen
        // during the call. C2A does not select or interpret an address type.
        let result = unsafe { ffi::bind(fd, address.as_ptr().cast::<c_void>(), length) };
        result_from_minus_one(result).map(|_| ())
    }

    fn poll(&self, descriptor: &mut PollDescriptor, timeout_millis: c_int) -> Result<u32, Errno> {
        let mut raw = ffi::PollFd {
            fd: descriptor.fd,
            events: descriptor.events,
            revents: 0,
        };
        // SAFETY: `raw` is one initialized pollfd, remains writable during the
        // call, and the nfds value is exactly one.
        let result = unsafe { ffi::poll(&mut raw, 1, timeout_millis) };
        let ready = result_from_minus_one(result)?;
        descriptor.revents = raw.revents;
        Ok(ready as u32)
    }

    fn send_to_wakeup(&self, fd: RawFd) -> Result<(), Errno> {
        // SAFETY: Linux AF_XDP wakeup uses a zero-length datagram with null
        // buffer and destination. No memory is read through either null.
        let result =
            unsafe { ffi::sendto(fd, std::ptr::null(), 0, MSG_DONTWAIT, std::ptr::null(), 0) };
        result_from_ssize_minus_one(result).map(|_| ())
    }

    fn bpf(&self, command: u32, attr: &mut [u8]) -> Result<c_long, Errno> {
        debug_assert_eq!(attr.len(), BPF_ATTR_SIZE);
        // SAFETY: `attr` is a fully initialized full-union byte extent whose
        // lifetime covers the call and is writable for commands that return
        // data through the union. x86_64's `syscall(2)` ABI passes the
        // command, pointer, and size as machine-word arguments exactly as
        // required by `syscall(__NR_bpf, cmd, attr, size)`.
        let result = unsafe {
            ffi::syscall(
                NR_BPF,
                command as c_ulong,
                attr.as_mut_ptr().cast::<c_void>(),
                attr.len() as c_ulong,
            )
        };
        result_from_long_minus_one(result)
    }

    fn close(&self, fd: RawFd) -> Result<(), Errno> {
        // SAFETY: `OwnedXdpFd` transfers each nonnegative owned fd here at most
        // once. Close is deliberately not retried after an error because the
        // numeric fd may already have been released and reused.
        let result = unsafe { ffi::close(fd) };
        result_from_minus_one(result).map(|_| ())
    }
}

impl NetlinkSyscalls for LinuxSyscalls {
    fn socket(&self, domain: c_int, kind: c_int, protocol: c_int) -> Result<RawFd, Errno> {
        <Self as Syscalls>::socket(self, domain, kind, protocol)
    }

    fn bind(&self, fd: RawFd, address: &[u8], length: u32) -> Result<(), Errno> {
        <Self as Syscalls>::bind(self, fd, address, length)
    }

    fn getsockname(&self, fd: RawFd, address: &mut [u8], length: &mut u32) -> Result<(), Errno> {
        debug_assert_eq!(usize::try_from(*length), Ok(address.len()));
        // SAFETY: `address` is writable for the caller-provided socklen and
        // `length` is a valid in/out Linux socklen_t for this call.
        let result = unsafe {
            ffi::getsockname(
                fd,
                address.as_mut_ptr().cast::<c_void>(),
                length as *mut u32,
            )
        };
        result_from_minus_one(result).map(|_| ())
    }

    fn dup_cloexec(&self, fd: RawFd) -> Result<RawFd, Errno> {
        // SAFETY: `fd` is validated by the netlink attach layer as a
        // nonnegative live program descriptor. `F_DUPFD_CLOEXEC` is the
        // Linux fcntl command from include/uapi/linux/fcntl.h and returns a
        // new owned descriptor or -1 with errno.
        let result = unsafe { ffi::fcntl(fd, F_DUPFD_CLOEXEC, 0) };
        result_from_minus_one(result)
    }

    fn send_netlink(&self, fd: RawFd, message: &[u8], destination: &[u8]) -> Result<usize, Errno> {
        debug_assert!(!message.is_empty());
        debug_assert_eq!(destination.len(), 12);
        let destination_len = u32::try_from(destination.len()).expect("sockaddr_nl fits socklen_t");
        // SAFETY: both byte extents remain readable for the duration of the
        // datagram call; the destination length is the checked sockaddr_nl
        // extent used by the safe netlink owner.
        let result = unsafe {
            ffi::sendto(
                fd,
                message.as_ptr().cast::<c_void>(),
                message.len(),
                0,
                destination.as_ptr().cast::<c_void>(),
                destination_len,
            )
        };
        let sent = result_from_ssize_minus_one(result)?;
        usize::try_from(sent).map_err(|_| Errno::invalid_capture())
    }

    fn recvmsg(&self, fd: RawFd, buffer: &mut [u8]) -> Result<RecvMessage, Errno> {
        debug_assert!(!buffer.is_empty());
        let mut iovec = ffi::IoVec {
            base: buffer.as_mut_ptr().cast::<c_void>(),
            len: buffer.len(),
        };
        let mut message = ffi::MsgHdr {
            name: std::ptr::null_mut(),
            name_len: 0,
            iov: &mut iovec,
            iov_len: 1,
            control: std::ptr::null_mut(),
            control_len: 0,
            flags: 0,
        };
        // SAFETY: `message` and its one initialized iovec remain writable and
        // valid for the complete call; the iovec points at the full mutable
        // response buffer and no ancillary storage is requested.
        let result = unsafe { ffi::recvmsg(fd, &mut message, 0) };
        let byte_len = result_from_ssize_minus_one(result)?;
        let byte_len = usize::try_from(byte_len).map_err(|_| Errno::invalid_capture())?;
        Ok(RecvMessage {
            byte_len,
            flags: message.flags,
        })
    }

    fn close(&self, fd: RawFd) -> Result<(), Errno> {
        <Self as Syscalls>::close(self, fd)
    }
}

fn result_from_minus_one(result: c_int) -> Result<c_int, Errno> {
    if result == -1 {
        Err(last_errno())
    } else {
        Ok(result)
    }
}

fn result_from_ssize_minus_one(result: isize) -> Result<isize, Errno> {
    if result == -1 {
        Err(last_errno())
    } else {
        Ok(result)
    }
}

fn result_from_long_minus_one(result: c_long) -> Result<c_long, Errno> {
    if result == -1 {
        Err(last_errno())
    } else {
        Ok(result)
    }
}

fn decode_mmap_result(address: *mut c_void) -> Result<*mut c_void, Errno> {
    if address == MAP_FAILED {
        Err(last_errno())
    } else {
        // A successful mapping at address zero is distinct from MAP_FAILED.
        Ok(address)
    }
}

fn last_errno() -> Errno {
    // SAFETY: on Linux, `__errno_location` returns a valid pointer to the
    // calling thread's errno for the duration of this immediate read.
    let raw = unsafe { *ffi::__errno_location() };
    Errno::new(raw).unwrap_or_else(Errno::invalid_capture)
}

/// Owned nonnegative AF_XDP fd with exactly-once close semantics.
pub(crate) struct OwnedXdpFd<'syscalls, S: Syscalls> {
    syscalls: &'syscalls S,
    fd: Option<RawFd>,
}

impl<'syscalls, S: Syscalls> OwnedXdpFd<'syscalls, S> {
    pub(crate) fn open(syscalls: &'syscalls S) -> Result<Self, ResourceError> {
        ensure_native_syscall_supported().map_err(ResourceError::Platform)?;
        let fd = syscalls
            .socket(AF_XDP, XDP_SOCKET_KIND, 0)
            .map_err(|errno| syscall_error(SyscallStage::OpenSocket, errno))?;
        if fd < 0 {
            return Err(SyscallArgumentError::InvalidFileDescriptor.into());
        }
        Ok(Self {
            syscalls,
            fd: Some(fd),
        })
    }

    fn raw(&self) -> RawFd {
        self.fd.expect("owned fd is active")
    }

    pub(crate) fn set_socket_option(
        &self,
        level: c_int,
        name: c_int,
        value: &[u8],
    ) -> Result<(), ResourceError> {
        let length = checked_sock_len(SyscallStage::SetSocketOption, value.len())?;
        self.syscalls
            .set_socket_option(self.raw(), level, name, value, length)
            .map_err(|errno| syscall_error(SyscallStage::SetSocketOption, errno))
    }

    pub(crate) fn get_socket_option(
        &self,
        level: c_int,
        name: c_int,
        value: &mut [u8],
    ) -> Result<usize, ResourceError> {
        let capacity = value.len();
        let mut length = checked_sock_len(SyscallStage::GetSocketOption, capacity)?;
        self.syscalls
            .get_socket_option(self.raw(), level, name, value, &mut length)
            .map_err(|errno| syscall_error(SyscallStage::GetSocketOption, errno))?;
        let actual = length as usize;
        if actual > capacity {
            return Err(SyscallArgumentError::KernelLengthOutOfBounds { capacity, actual }.into());
        }
        Ok(actual)
    }

    pub(crate) fn map_shared(
        &self,
        byte_len: usize,
        offset: u64,
    ) -> Result<MappedRegion<'syscalls, S>, ResourceError> {
        if byte_len == 0 {
            return Err(SyscallArgumentError::ZeroLength {
                stage: SyscallStage::MapMemory,
            }
            .into());
        }
        let request = MapRequest::Shared {
            fd: self.raw(),
            byte_len,
            offset: checked_offset(offset)?,
        };
        MappedRegion::map(self.syscalls, request)
    }

    pub(crate) fn bind_bytes(&self, address: &[u8]) -> Result<(), ResourceError> {
        let length = checked_sock_len(SyscallStage::BindSocket, address.len())?;
        self.syscalls
            .bind(self.raw(), address, length)
            .map_err(|errno| syscall_error(SyscallStage::BindSocket, errno))
    }

    pub(crate) fn poll(
        &self,
        events: i16,
        timeout_millis: i32,
    ) -> Result<PollResult, ResourceError> {
        let mut descriptor = PollDescriptor::new(self.raw(), events);
        let ready = self
            .syscalls
            .poll(&mut descriptor, timeout_millis)
            .map_err(|errno| syscall_error(SyscallStage::PollSocket, errno))?;
        Ok(PollResult {
            ready,
            events: descriptor.revents,
        })
    }

    pub(crate) fn send_to_wakeup(&self) -> Result<(), ResourceError> {
        self.syscalls
            .send_to_wakeup(self.raw())
            .map_err(|errno| syscall_error(SyscallStage::SendToSocket, errno))
    }

    pub(crate) fn close(mut self) -> Result<(), ResourceError> {
        self.close_once()
    }

    pub(crate) fn close_once(&mut self) -> Result<(), ResourceError> {
        let Some(fd) = self.fd.take() else {
            return Ok(());
        };
        self.syscalls
            .close(fd)
            .map_err(|errno| syscall_error(SyscallStage::CloseSocket, errno))
    }
}

impl<S: Syscalls> fmt::Debug for OwnedXdpFd<'_, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedXdpFd")
            .field("fd", &"<redacted>")
            .field("active", &self.fd.is_some())
            .finish()
    }
}

impl<S: Syscalls> Drop for OwnedXdpFd<'_, S> {
    fn drop(&mut self) {
        let _ = self.close_once();
    }
}

/// Owned XSKMAP fd with exactly-once close semantics.
pub(crate) struct OwnedBpfMap<'syscalls, S: Syscalls> {
    syscalls: &'syscalls S,
    fd: Option<RawFd>,
    max_entries: u32,
}

impl<'syscalls, S: Syscalls> OwnedBpfMap<'syscalls, S> {
    pub(crate) fn create(
        syscalls: &'syscalls S,
        max_entries: u32,
    ) -> Result<Self, BpfResourceError> {
        if max_entries == 0 {
            return Err(BpfResourceError::Argument(
                BpfArgumentError::InvalidMaxEntries { max_entries },
            ));
        }
        ensure_native_syscall_supported().map_err(BpfResourceError::Platform)?;

        let mut attr = map_create_attr(max_entries);
        let result =
            syscalls
                .bpf(BPF_MAP_CREATE, &mut attr)
                .map_err(|errno| BpfResourceError::Syscall {
                    operation: XskMapOperation::Create,
                    errno,
                })?;
        let fd = RawFd::try_from(result).map_err(|_| {
            BpfResourceError::Argument(BpfArgumentError::InvalidFileDescriptor {
                operation: XskMapOperation::Create,
            })
        })?;
        Ok(Self {
            syscalls,
            fd: Some(fd),
            max_entries,
        })
    }

    pub(crate) fn update_xsk(
        &self,
        queue_id: u32,
        socket: &OwnedXdpFd<'syscalls, S>,
    ) -> Result<(), BpfResourceError> {
        if queue_id >= self.max_entries {
            return Err(BpfResourceError::Argument(
                BpfArgumentError::QueueIdOutOfRange {
                    queue_id,
                    max_entries: self.max_entries,
                },
            ));
        }
        let map_fd = u32::try_from(self.raw()).map_err(|_| {
            BpfResourceError::Argument(BpfArgumentError::InvalidFileDescriptor {
                operation: XskMapOperation::UpdateElem,
            })
        })?;
        let socket_fd = u32::try_from(socket.raw()).map_err(|_| {
            BpfResourceError::Argument(BpfArgumentError::InvalidFileDescriptor {
                operation: XskMapOperation::UpdateElem,
            })
        })?;
        let key = queue_id;
        let value = socket_fd;
        let mut attr = map_update_elem_attr(map_fd, &key, &value);
        let result = self
            .syscalls
            .bpf(BPF_MAP_UPDATE_ELEM, &mut attr)
            .map_err(|errno| BpfResourceError::Syscall {
                operation: XskMapOperation::UpdateElem,
                errno,
            })?;
        if result != 0 {
            return Err(BpfResourceError::UnexpectedReturn {
                operation: XskMapOperation::UpdateElem,
                value: result,
            });
        }
        Ok(())
    }

    pub(crate) const fn max_entries(&self) -> u32 {
        self.max_entries
    }

    pub(crate) fn raw(&self) -> RawFd {
        self.fd.expect("owned map fd is active")
    }

    pub(crate) fn close(mut self) -> Result<(), BpfResourceError> {
        self.close_once()
    }

    pub(crate) fn close_once(&mut self) -> Result<(), BpfResourceError> {
        let Some(fd) = self.fd.take() else {
            return Ok(());
        };
        self.syscalls
            .close(fd)
            .map_err(|errno| BpfResourceError::Syscall {
                operation: XskMapOperation::Close,
                errno,
            })
    }
}

impl<S: Syscalls> fmt::Debug for OwnedBpfMap<'_, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedBpfMap")
            .field("fd", &"<redacted>")
            .field("max_entries", &self.max_entries)
            .field("active", &self.fd.is_some())
            .finish()
    }
}

impl<S: Syscalls> Drop for OwnedBpfMap<'_, S> {
    fn drop(&mut self) {
        let _ = self.close_once();
    }
}

/// Owned XDP program fd with exactly-once close semantics.
pub(crate) struct OwnedBpfProgram<'syscalls, S: Syscalls> {
    syscalls: &'syscalls S,
    fd: Option<RawFd>,
}

impl<'syscalls, S: Syscalls> OwnedBpfProgram<'syscalls, S> {
    pub(crate) fn load(
        syscalls: &'syscalls S,
        instructions: &[u8],
        insn_cnt: u32,
    ) -> Result<Self, BpfProgramResourceError> {
        let expected_byte_len = usize::try_from(insn_cnt)
            .ok()
            .and_then(|count| count.checked_mul(BPF_INSN_SIZE));
        if expected_byte_len != Some(instructions.len()) {
            return Err(BpfProgramResourceError::Argument(
                BpfProgramArgumentError::InstructionCountMismatch {
                    insn_cnt,
                    byte_len: instructions.len(),
                },
            ));
        }
        ensure_native_syscall_supported().map_err(BpfProgramResourceError::Platform)?;

        let mut log_buf = vec![0_u8; VERIFIER_LOG_SIZE];
        let mut attr = program_load_attr(instructions, insn_cnt, &mut log_buf)
            .map_err(BpfProgramResourceError::Argument)?;
        let result = syscalls.bpf(BPF_PROG_LOAD, &mut attr).map_err(|errno| {
            BpfProgramResourceError::Syscall {
                operation: XdpProgramOperation::Load,
                errno,
                verifier_log: verifier_log_from_attr(&attr, &log_buf),
            }
        })?;
        let fd = RawFd::try_from(result).map_err(|_| {
            BpfProgramResourceError::InvalidFileDescriptor {
                operation: XdpProgramOperation::Load,
                verifier_log: verifier_log_from_attr(&attr, &log_buf),
            }
        })?;
        Ok(Self {
            syscalls,
            fd: Some(fd),
        })
    }

    pub(crate) fn raw(&self) -> RawFd {
        self.fd.expect("owned program fd is active")
    }

    pub(crate) fn close(mut self) -> Result<(), BpfProgramResourceError> {
        self.close_once()
    }

    pub(crate) fn close_once(&mut self) -> Result<(), BpfProgramResourceError> {
        let Some(fd) = self.fd.take() else {
            return Ok(());
        };
        self.syscalls
            .close(fd)
            .map_err(|errno| BpfProgramResourceError::Syscall {
                operation: XdpProgramOperation::Close,
                errno,
                verifier_log: String::new(),
            })
    }
}

impl<S: Syscalls> fmt::Debug for OwnedBpfProgram<'_, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedBpfProgram")
            .field("fd", &"<redacted>")
            .field("active", &self.fd.is_some())
            .finish()
    }
}

impl<S: Syscalls> Drop for OwnedBpfProgram<'_, S> {
    fn drop(&mut self) {
        let _ = self.close_once();
    }
}

/// One owned mmap result. Address zero is a valid stored success.
pub(crate) struct MappedRegion<'syscalls, S: Syscalls> {
    syscalls: &'syscalls S,
    address: *mut c_void,
    byte_len: usize,
    active: bool,
}

impl<'syscalls, S: Syscalls> MappedRegion<'syscalls, S> {
    pub(crate) fn map_anonymous(
        syscalls: &'syscalls S,
        byte_len: usize,
    ) -> Result<Self, ResourceError> {
        if byte_len == 0 {
            return Err(SyscallArgumentError::ZeroLength {
                stage: SyscallStage::MapMemory,
            }
            .into());
        }
        Self::map(syscalls, MapRequest::Anonymous { byte_len })
    }

    fn map(syscalls: &'syscalls S, request: MapRequest) -> Result<Self, ResourceError> {
        let byte_len = request.byte_len();
        checked_mmap_length(byte_len)?;
        let address = syscalls
            .mmap(request)
            .map_err(|errno| syscall_error(SyscallStage::MapMemory, errno))?;
        Ok(Self {
            syscalls,
            address,
            byte_len,
            active: true,
        })
    }

    pub(crate) fn unmap(mut self) -> Result<(), ResourceError> {
        self.unmap_once()
    }

    pub(crate) fn unmap_once(&mut self) -> Result<(), ResourceError> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        self.syscalls
            .munmap(self.address, self.byte_len)
            .map_err(|errno| syscall_error(SyscallStage::UnmapMemory, errno))
    }

    pub(crate) fn address(&self) -> usize {
        self.address.addr()
    }

    pub(crate) const fn byte_len(&self) -> usize {
        self.byte_len
    }

    pub(crate) fn address_is_page_aligned(&self) -> bool {
        self.address()
            .is_multiple_of(crate::setup::PAGE_ALIGNED_UMEM_ALIGNMENT)
    }

    /// Borrows the exact byte extent returned by anonymous `mmap(2)`.
    pub(crate) fn as_mut_bytes(&mut self) -> Option<&mut [u8]> {
        if !self.active || self.address.is_null() {
            return None;
        }
        self.address().checked_add(self.byte_len)?;

        // SAFETY: `MappedRegion::map` stores the exact nonfailed address and
        // length returned by mmap. The owner remains active for this borrow,
        // and `unmap_once` requires a mutable borrow, so the mapping cannot be
        // released while the returned slice is live.
        Some(unsafe { std::slice::from_raw_parts_mut(self.address.cast(), self.byte_len) })
    }

    /// Returns a checked mutable byte view over the prefix required by one
    /// ring layout.
    ///
    /// The returned borrow is tied to this owner field, so a ring view keeps
    /// the owning `MappedRegion` and its backing mapping alive. The address
    /// and full mapping extent are checked again at this boundary because the
    /// subsequent safe ring layer relies on the slice contract.
    pub(crate) fn borrowed_ring(
        &mut self,
        layout: RingMmapLayout,
    ) -> Result<&mut [u8], RingMapError> {
        if !self.active {
            return Err(RingMapError::MappingInactive);
        }

        let required = layout.byte_len();
        if required > self.byte_len {
            return Err(RingMapError::MappingTooShort {
                required,
                actual: self.byte_len,
            });
        }

        let address = self.address.addr();
        if address == 0 {
            return Err(RingMapError::MappingAddressIsNull);
        }
        address
            .checked_add(self.byte_len)
            .ok_or(RingMapError::MappingAddressRangeOverflow {
                address,
                length: self.byte_len,
            })?;

        // SAFETY: `MappedRegion::map` accepted a nonzero extent and stores the
        // exact address/length returned by a successful mmap. The checks above
        // reject an inactive, null, or wrapping range; `u8` has alignment one,
        // and the mmap length was checked to fit `isize`, as required by
        // `from_raw_parts_mut`. The returned borrow prevents unmap/move of this
        // region until every ring view using it is dropped.
        unsafe {
            Ok(std::slice::from_raw_parts_mut(
                self.address.cast::<u8>(),
                required,
            ))
        }
    }
}

impl<S: Syscalls> fmt::Debug for MappedRegion<'_, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MappedRegion")
            .field("address", &"<redacted>")
            .field("byte_len", &self.byte_len)
            .field("active", &self.active)
            .finish()
    }
}

impl<S: Syscalls> Drop for MappedRegion<'_, S> {
    fn drop(&mut self) {
        let _ = self.unmap_once();
    }
}

mod ffi {
    use super::{c_int, c_long, c_short, c_void, Offset, PollCount, SockLen};

    #[repr(C)]
    pub(super) struct PollFd {
        pub(super) fd: c_int,
        pub(super) events: c_short,
        pub(super) revents: c_short,
    }

    #[repr(C)]
    pub(super) struct IoVec {
        pub(super) base: *mut c_void,
        pub(super) len: usize,
    }

    #[repr(C)]
    pub(super) struct MsgHdr {
        pub(super) name: *mut c_void,
        pub(super) name_len: SockLen,
        pub(super) iov: *mut IoVec,
        pub(super) iov_len: usize,
        pub(super) control: *mut c_void,
        pub(super) control_len: usize,
        pub(super) flags: c_int,
    }

    // SAFETY: these declarations exactly match the reviewed x86_64 Linux libc
    // ABI. Every pointer extent and ownership precondition is established by
    // the safe wrappers before the corresponding function is called.
    unsafe extern "C" {
        pub(super) fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
        pub(super) fn setsockopt(
            fd: c_int,
            level: c_int,
            name: c_int,
            value: *const c_void,
            length: SockLen,
        ) -> c_int;
        pub(super) fn getsockopt(
            fd: c_int,
            level: c_int,
            name: c_int,
            value: *mut c_void,
            length: *mut SockLen,
        ) -> c_int;
        pub(super) fn mmap(
            address: *mut c_void,
            byte_len: usize,
            protection: c_int,
            flags: c_int,
            fd: c_int,
            offset: Offset,
        ) -> *mut c_void;
        pub(super) fn munmap(address: *mut c_void, byte_len: usize) -> c_int;
        pub(super) fn bind(fd: c_int, address: *const c_void, length: SockLen) -> c_int;
        pub(super) fn getsockname(fd: c_int, address: *mut c_void, length: *mut SockLen) -> c_int;
        pub(super) fn fcntl(fd: c_int, command: c_int, argument: c_int) -> c_int;
        pub(super) fn poll(
            descriptors: *mut PollFd,
            count: PollCount,
            timeout_millis: c_int,
        ) -> c_int;
        pub(super) fn sendto(
            fd: c_int,
            buffer: *const c_void,
            byte_len: usize,
            flags: c_int,
            destination: *const c_void,
            destination_len: SockLen,
        ) -> isize;
        pub(super) fn recvmsg(fd: c_int, message: *mut MsgHdr, flags: c_int) -> isize;
        pub(super) fn syscall(number: c_long, ...) -> c_long;
        pub(super) fn close(fd: c_int) -> c_int;
        pub(super) fn __errno_location() -> *mut c_int;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        mem::size_of,
    };

    use super::*;

    const TEST_ERRNO: Errno = Errno::Linux(13);
    const MAX_CALLS: usize = 32;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Call {
        Socket {
            domain: c_int,
            kind: c_int,
            protocol: c_int,
        },
        SetSocketOption {
            fd: RawFd,
            level: c_int,
            name: c_int,
            length: SockLen,
            first: u8,
        },
        GetSocketOption {
            fd: RawFd,
            level: c_int,
            name: c_int,
            capacity: SockLen,
        },
        Mmap {
            fd: RawFd,
            byte_len: usize,
            flags: c_int,
            offset: Offset,
        },
        Munmap {
            address: usize,
            byte_len: usize,
        },
        Bind {
            fd: RawFd,
            length: SockLen,
            first: u8,
        },
        Poll {
            fd: RawFd,
            events: i16,
            timeout_millis: i32,
        },
        SendTo {
            fd: RawFd,
            flags: c_int,
        },
        Bpf {
            command: u32,
            attr_size: usize,
        },
        Close {
            fd: RawFd,
        },
    }

    struct Transcript {
        entries: [Option<Call>; MAX_CALLS],
        len: usize,
    }

    impl Transcript {
        const fn new() -> Self {
            Self {
                entries: [None; MAX_CALLS],
                len: 0,
            }
        }

        fn push(&mut self, call: Call) {
            assert!(self.len < MAX_CALLS, "fixed transcript capacity exceeded");
            self.entries[self.len] = Some(call);
            self.len += 1;
        }

        fn as_slice(&self) -> &[Option<Call>] {
            &self.entries[..self.len]
        }
    }

    struct FakeSyscalls {
        transcript: RefCell<Transcript>,
        fail: Cell<Option<SyscallStage>>,
        next_address: Cell<usize>,
        returned_option_len: Cell<Option<SockLen>>,
        bpf_attrs: RefCell<Vec<[u8; BPF_ATTR_SIZE]>>,
        bpf_elem_values: RefCell<Vec<Option<(u32, u32)>>>,
        bpf_fail: Cell<Option<XskMapOperation>>,
        bpf_errno: Cell<Option<Errno>>,
        bpf_program_log: RefCell<Vec<u8>>,
        bpf_program_fail: Cell<bool>,
        bpf_program_errno: Cell<Option<Errno>>,
        bpf_program_return: Cell<c_long>,
        bpf_program_log_pointer: Cell<usize>,
        bpf_program_log_size: Cell<usize>,
    }

    impl FakeSyscalls {
        fn new() -> Self {
            Self {
                transcript: RefCell::new(Transcript::new()),
                fail: Cell::new(None),
                next_address: Cell::new(0x1_0000),
                returned_option_len: Cell::new(None),
                bpf_attrs: RefCell::new(Vec::new()),
                bpf_elem_values: RefCell::new(Vec::new()),
                bpf_fail: Cell::new(None),
                bpf_errno: Cell::new(None),
                bpf_program_log: RefCell::new(Vec::new()),
                bpf_program_fail: Cell::new(false),
                bpf_program_errno: Cell::new(None),
                bpf_program_return: Cell::new(23),
                bpf_program_log_pointer: Cell::new(0),
                bpf_program_log_size: Cell::new(0),
            }
        }

        fn record(&self, call: Call) {
            self.transcript.borrow_mut().push(call);
        }

        fn result(&self, stage: SyscallStage) -> Result<(), Errno> {
            if self.fail.get() == Some(stage) {
                Err(TEST_ERRNO)
            } else {
                Ok(())
            }
        }

        fn count(&self, predicate: impl Fn(Call) -> bool) -> usize {
            self.transcript
                .borrow()
                .as_slice()
                .iter()
                .flatten()
                .copied()
                .filter(|call| predicate(*call))
                .count()
        }
    }

    impl sealed::Sealed for FakeSyscalls {}

    impl Syscalls for FakeSyscalls {
        fn socket(&self, domain: c_int, kind: c_int, protocol: c_int) -> Result<RawFd, Errno> {
            self.record(Call::Socket {
                domain,
                kind,
                protocol,
            });
            self.result(SyscallStage::OpenSocket).map(|()| 17)
        }

        fn set_socket_option(
            &self,
            fd: RawFd,
            level: c_int,
            name: c_int,
            value: &[u8],
            length: SockLen,
        ) -> Result<(), Errno> {
            self.record(Call::SetSocketOption {
                fd,
                level,
                name,
                length,
                first: value[0],
            });
            self.result(SyscallStage::SetSocketOption)
        }

        fn get_socket_option(
            &self,
            fd: RawFd,
            level: c_int,
            name: c_int,
            value: &mut [u8],
            length: &mut SockLen,
        ) -> Result<(), Errno> {
            self.record(Call::GetSocketOption {
                fd,
                level,
                name,
                capacity: *length,
            });
            self.result(SyscallStage::GetSocketOption)?;
            value.fill(0xa5);
            *length = self
                .returned_option_len
                .get()
                .unwrap_or_else(|| SockLen::try_from(value.len()).expect("test buffer is bounded"));
            Ok(())
        }

        fn mmap(&self, request: MapRequest) -> Result<*mut c_void, Errno> {
            let (fd, byte_len, flags, offset) = match request {
                MapRequest::Anonymous { byte_len } => {
                    (-1, byte_len, MAP_PRIVATE | MAP_ANONYMOUS, 0)
                }
                MapRequest::Shared {
                    fd,
                    byte_len,
                    offset,
                } => (fd, byte_len, MAP_SHARED, offset),
            };
            self.record(Call::Mmap {
                fd,
                byte_len,
                flags,
                offset,
            });
            self.result(SyscallStage::MapMemory)?;
            let address = self.next_address.get();
            self.next_address.set(address.wrapping_add(0x1_0000));
            Ok(address as *mut c_void)
        }

        fn munmap(&self, address: *mut c_void, byte_len: usize) -> Result<(), Errno> {
            self.record(Call::Munmap {
                address: address as usize,
                byte_len,
            });
            self.result(SyscallStage::UnmapMemory)
        }

        fn bind(&self, fd: RawFd, address: &[u8], length: SockLen) -> Result<(), Errno> {
            self.record(Call::Bind {
                fd,
                length,
                first: address[0],
            });
            self.result(SyscallStage::BindSocket)
        }

        fn poll(
            &self,
            descriptor: &mut PollDescriptor,
            timeout_millis: c_int,
        ) -> Result<u32, Errno> {
            self.record(Call::Poll {
                fd: descriptor.fd,
                events: descriptor.events,
                timeout_millis,
            });
            self.result(SyscallStage::PollSocket)?;
            descriptor.revents = descriptor.events;
            Ok(1)
        }

        fn send_to_wakeup(&self, fd: RawFd) -> Result<(), Errno> {
            self.record(Call::SendTo {
                fd,
                flags: MSG_DONTWAIT,
            });
            self.result(SyscallStage::SendToSocket)
        }

        fn bpf(&self, command: u32, attr: &mut [u8]) -> Result<c_long, Errno> {
            self.record(Call::Bpf {
                command,
                attr_size: attr.len(),
            });
            let attr_copy: [u8; BPF_ATTR_SIZE] = (&*attr)
                .try_into()
                .expect("bpf seam receives the full union extent");
            if command == BPF_PROG_LOAD {
                let log_pointer = attr_u64(&attr_copy, 32) as usize;
                let log_size = attr_u32(&attr_copy, 28) as usize;
                self.bpf_program_log_pointer.set(log_pointer);
                self.bpf_program_log_size.set(log_size);
                let injected = self.bpf_program_log.borrow();
                if !injected.is_empty() {
                    assert!(log_pointer != 0, "program load must provide log_buf");
                    assert!(log_size != 0, "program load must provide log_size");
                    let writable_len = injected.len().min(log_size);
                    // SAFETY: `OwnedBpfProgram::load` allocates a writable
                    // `VERIFIER_LOG_SIZE` buffer, puts its exact pointer and
                    // length in this attr, and calls the fake synchronously.
                    // The fake writes only within that advertised extent.
                    let output =
                        unsafe { std::slice::from_raw_parts_mut(log_pointer as *mut u8, log_size) };
                    output[..writable_len].copy_from_slice(&injected[..writable_len]);
                    let true_size =
                        if writable_len < log_size && injected.last().copied() != Some(0) {
                            output[writable_len] = 0;
                            writable_len + 1
                        } else {
                            writable_len
                        };
                    attr[140..140 + size_of::<u32>()]
                        .copy_from_slice(&(true_size as u32).to_ne_bytes());
                }
                let attr_after: [u8; BPF_ATTR_SIZE] = (&*attr)
                    .try_into()
                    .expect("bpf seam receives the full union extent");
                self.bpf_attrs.borrow_mut().push(attr_after);
                self.bpf_elem_values.borrow_mut().push(None);
                if self.bpf_program_fail.get() {
                    return Err(self.bpf_program_errno.get().unwrap_or(TEST_ERRNO));
                }
                return Ok(self.bpf_program_return.get());
            }

            let operation = match command {
                BPF_MAP_CREATE => XskMapOperation::Create,
                BPF_MAP_UPDATE_ELEM => XskMapOperation::UpdateElem,
                _ => panic!("unexpected bpf command {command}"),
            };
            let elem_values = if operation == XskMapOperation::UpdateElem {
                let key_pointer = attr_u64(&attr_copy, 8) as *const u32;
                let value_pointer = attr_u64(&attr_copy, 16) as *const u32;
                // SAFETY: the checked production builder keeps both local
                // u32 values alive across this synchronous fake call.
                Some(unsafe { (key_pointer.read(), value_pointer.read()) })
            } else {
                None
            };
            self.bpf_attrs.borrow_mut().push(attr_copy);
            self.bpf_elem_values.borrow_mut().push(elem_values);
            if self.bpf_fail.get() == Some(operation) {
                return Err(self.bpf_errno.get().unwrap_or(TEST_ERRNO));
            }
            Ok(match operation {
                XskMapOperation::Create => 19,
                XskMapOperation::UpdateElem => 0,
                XskMapOperation::Close => unreachable!("close is not a bpf command"),
            })
        }

        fn close(&self, fd: RawFd) -> Result<(), Errno> {
            self.record(Call::Close { fd });
            self.result(SyscallStage::CloseSocket)
        }
    }

    /// Dedicated seam for the fd-sign validation test.  The existing
    /// `FakeSyscalls` transcript deliberately remains unchanged so its
    /// established tests continue to exercise the original fixed fd 17.
    struct FdBoundarySyscalls {
        inner: FakeSyscalls,
        socket_result: RawFd,
    }

    impl FdBoundarySyscalls {
        fn new(socket_result: RawFd) -> Self {
            Self {
                inner: FakeSyscalls::new(),
                socket_result,
            }
        }
    }

    impl sealed::Sealed for FdBoundarySyscalls {}

    impl Syscalls for FdBoundarySyscalls {
        fn socket(&self, domain: c_int, kind: c_int, protocol: c_int) -> Result<RawFd, Errno> {
            self.inner.record(Call::Socket {
                domain,
                kind,
                protocol,
            });
            self.inner
                .result(SyscallStage::OpenSocket)
                .map(|()| self.socket_result)
        }

        fn set_socket_option(
            &self,
            fd: RawFd,
            level: c_int,
            name: c_int,
            value: &[u8],
            length: SockLen,
        ) -> Result<(), Errno> {
            <FakeSyscalls as Syscalls>::set_socket_option(
                &self.inner,
                fd,
                level,
                name,
                value,
                length,
            )
        }

        fn get_socket_option(
            &self,
            fd: RawFd,
            level: c_int,
            name: c_int,
            value: &mut [u8],
            length: &mut SockLen,
        ) -> Result<(), Errno> {
            <FakeSyscalls as Syscalls>::get_socket_option(
                &self.inner,
                fd,
                level,
                name,
                value,
                length,
            )
        }

        fn mmap(&self, request: MapRequest) -> Result<*mut c_void, Errno> {
            <FakeSyscalls as Syscalls>::mmap(&self.inner, request)
        }

        fn munmap(&self, address: *mut c_void, byte_len: usize) -> Result<(), Errno> {
            <FakeSyscalls as Syscalls>::munmap(&self.inner, address, byte_len)
        }

        fn bind(&self, fd: RawFd, address: &[u8], length: SockLen) -> Result<(), Errno> {
            <FakeSyscalls as Syscalls>::bind(&self.inner, fd, address, length)
        }

        fn poll(
            &self,
            descriptor: &mut PollDescriptor,
            timeout_millis: c_int,
        ) -> Result<u32, Errno> {
            <FakeSyscalls as Syscalls>::poll(&self.inner, descriptor, timeout_millis)
        }

        fn send_to_wakeup(&self, fd: RawFd) -> Result<(), Errno> {
            <FakeSyscalls as Syscalls>::send_to_wakeup(&self.inner, fd)
        }

        fn bpf(&self, command: u32, attr: &mut [u8]) -> Result<c_long, Errno> {
            <FakeSyscalls as Syscalls>::bpf(&self.inner, command, attr)
        }

        fn close(&self, fd: RawFd) -> Result<(), Errno> {
            <FakeSyscalls as Syscalls>::close(&self.inner, fd)
        }
    }

    fn assert_static_syscalls<T: Syscalls>() {}

    fn attr_u32(attr: &[u8; BPF_ATTR_SIZE], offset: usize) -> u32 {
        u32::from_ne_bytes(
            attr[offset..offset + size_of::<u32>()]
                .try_into()
                .expect("four-byte bpf attr field"),
        )
    }

    fn attr_u64(attr: &[u8; BPF_ATTR_SIZE], offset: usize) -> u64 {
        u64::from_ne_bytes(
            attr[offset..offset + size_of::<u64>()]
                .try_into()
                .expect("eight-byte bpf attr field"),
        )
    }

    #[test]
    fn native_bpf_map_create_uses_checked_fields_and_zeroed_full_union() {
        assert_eq!(BPF_SYSCALL_NUMBER, 321);
        assert_eq!(BPF_MAP_CREATE, 0);
        assert_eq!(BPF_MAP_TYPE_XSKMAP, 17);
        assert_eq!(BPF_ATTR_SIZE, 144);
        assert_eq!(size_of::<BpfAttr>(), BPF_ATTR_SIZE);
        assert_eq!(align_of::<BpfAttr>(), 8);

        let syscalls = FakeSyscalls::new();
        let map = OwnedBpfMap::create(&syscalls, 64).expect("fake XSKMAP");
        assert_eq!(map.max_entries(), 64);
        assert_eq!(
            syscalls.transcript.borrow().as_slice(),
            &[Some(Call::Bpf {
                command: BPF_MAP_CREATE,
                attr_size: BPF_ATTR_SIZE,
            })]
        );

        let attr = syscalls.bpf_attrs.borrow()[0];
        assert_eq!(attr_u32(&attr, 0), BPF_MAP_TYPE_XSKMAP);
        assert_eq!(attr_u32(&attr, 4), BPF_XSKMAP_KEY_SIZE);
        assert_eq!(attr_u32(&attr, 8), BPF_XSKMAP_VALUE_SIZE);
        assert_eq!(attr_u32(&attr, 12), 64);
        assert_eq!(attr_u32(&attr, 16), 0);
        assert!(attr[20..].iter().all(|byte| *byte == 0));
        drop(map);
        assert_eq!(
            syscalls.count(|call| matches!(call, Call::Close { fd: 19 })),
            1
        );
    }

    #[test]
    fn native_bpf_map_create_rejects_zero_max_entries_before_syscall() {
        let syscalls = FakeSyscalls::new();
        assert!(matches!(
            OwnedBpfMap::create(&syscalls, 0),
            Err(BpfResourceError::Argument(
                BpfArgumentError::InvalidMaxEntries { max_entries: 0 }
            ))
        ));
        assert!(syscalls.transcript.borrow().as_slice().is_empty());
        assert!(syscalls.bpf_attrs.borrow().is_empty());
    }

    #[test]
    fn native_bpf_map_update_uses_queue_and_socket_fd_pointers() {
        let syscalls = FakeSyscalls::new();
        let map = OwnedBpfMap::create(&syscalls, 8).expect("fake XSKMAP");
        let socket = OwnedXdpFd::open(&syscalls).expect("fake AF_XDP socket");
        map.update_xsk(3, &socket).expect("fake map update");

        assert_eq!(
            syscalls.transcript.borrow().as_slice(),
            &[
                Some(Call::Bpf {
                    command: BPF_MAP_CREATE,
                    attr_size: BPF_ATTR_SIZE,
                }),
                Some(Call::Socket {
                    domain: AF_XDP,
                    kind: XDP_SOCKET_KIND,
                    protocol: 0,
                }),
                Some(Call::Bpf {
                    command: BPF_MAP_UPDATE_ELEM,
                    attr_size: BPF_ATTR_SIZE,
                }),
            ]
        );
        let attr = syscalls.bpf_attrs.borrow()[1];
        assert_eq!(attr_u32(&attr, 0), 19);
        assert_eq!(attr_u32(&attr, 4), 0);
        assert_eq!(attr_u64(&attr, 24), BPF_ANY);
        assert!(attr[32..].iter().all(|byte| *byte == 0));
        assert_eq!(
            syscalls.bpf_elem_values.borrow().as_slice(),
            &[None, Some((3, 17))]
        );
        drop(socket);
        drop(map);
    }

    #[test]
    fn native_bpf_eprem_is_preserved_as_a_typed_seam_error() {
        let syscalls = FakeSyscalls::new();
        syscalls.bpf_fail.set(Some(XskMapOperation::Create));
        syscalls.bpf_errno.set(Some(Errno::Linux(1)));
        assert!(matches!(
            OwnedBpfMap::create(&syscalls, 8),
            Err(BpfResourceError::Syscall {
                operation: XskMapOperation::Create,
                errno: Errno::Linux(1),
            })
        ));
        assert_eq!(syscalls.bpf_attrs.borrow().len(), 1);
    }

    #[test]
    fn native_bpf_program_load_uses_zeroed_xdp_attr_and_captures_log_pointer() {
        let syscalls = FakeSyscalls::new();
        *syscalls.bpf_program_log.borrow_mut() = b"verifier rejected\0".to_vec();
        syscalls.bpf_program_fail.set(true);
        syscalls.bpf_program_errno.set(Some(Errno::Linux(22)));

        let error = OwnedBpfProgram::load(&syscalls, &[0_u8; BPF_INSN_SIZE], 1)
            .expect_err("fake verifier failure");
        assert_eq!(
            error,
            BpfProgramResourceError::Syscall {
                operation: XdpProgramOperation::Load,
                errno: Errno::Linux(22),
                verifier_log: "verifier rejected".to_owned(),
            }
        );

        let attr = syscalls.bpf_attrs.borrow()[0];
        assert_eq!(attr.len(), BPF_ATTR_SIZE);
        assert_eq!(attr_u32(&attr, 0), BPF_PROG_TYPE_XDP);
        assert_eq!(attr_u32(&attr, 4), 1);
        assert_ne!(attr_u64(&attr, 8), 0, "insns pointer");
        assert_ne!(attr_u64(&attr, 16), 0, "license pointer");
        assert_eq!(attr_u32(&attr, 24), VERIFIER_LOG_LEVEL);
        assert_eq!(attr_u32(&attr, 28), VERIFIER_LOG_SIZE as u32);
        assert_eq!(
            attr_u64(&attr, 32),
            syscalls.bpf_program_log_pointer.get() as u64
        );
        assert_eq!(syscalls.bpf_program_log_size.get(), VERIFIER_LOG_SIZE);
        assert!(attr[40..140].iter().all(|byte| *byte == 0));
        assert_eq!(attr_u32(&attr, 140), b"verifier rejected\0".len() as u32);
    }

    #[test]
    fn native_bpf_program_load_requires_instruction_count_in_instructions() {
        let syscalls = FakeSyscalls::new();
        assert!(matches!(
            OwnedBpfProgram::load(&syscalls, &[0_u8; BPF_INSN_SIZE - 1], 1),
            Err(BpfProgramResourceError::Argument(
                BpfProgramArgumentError::InstructionCountMismatch {
                    insn_cnt: 1,
                    byte_len: 7,
                }
            ))
        ));
        assert!(syscalls.bpf_attrs.borrow().is_empty());
    }

    #[test]
    fn native_bpf_program_close_failure_consumes_fd_and_does_not_retry_on_drop() {
        let syscalls = FakeSyscalls::new();
        let program =
            OwnedBpfProgram::load(&syscalls, &[0_u8; BPF_INSN_SIZE], 1).expect("fake program load");
        syscalls.fail.set(Some(SyscallStage::CloseSocket));
        assert!(matches!(
            program.close(),
            Err(BpfProgramResourceError::Syscall {
                operation: XdpProgramOperation::Close,
                errno: TEST_ERRNO,
                verifier_log,
            }) if verifier_log.is_empty()
        ));
        assert_eq!(
            syscalls.count(|call| matches!(call, Call::Close { fd: 23 })),
            1
        );
    }

    #[test]
    fn native_x86_64_syscall_source_and_constants_are_exact() {
        const {
            assert!(cfg!(all(
                target_os = "linux",
                target_arch = "x86_64",
                target_pointer_width = "64"
            )));
        }
        assert_eq!(
            SYSCALL_ABI_PROFILE,
            "Linux v6.8 x86_64: include/linux/net.h, include/linux/socket.h, \
             include/uapi/asm-generic/fcntl.h, include/uapi/linux/mman.h, \
             include/uapi/asm-generic/mman-common.h, \
             arch/x86/include/generated/uapi/asm/unistd_64.h, include/uapi/linux/bpf.h"
        );
        assert_eq!(
            (SOCK_RAW, SOCK_NONBLOCK, SOCK_CLOEXEC, XDP_SOCKET_KIND),
            (3, 0x800, 0x8_0000, 3 | 0x800 | 0x8_0000)
        );
        assert_eq!((PROT_READ, PROT_WRITE), (1, 2));
        assert_eq!((MAP_SHARED, MAP_PRIVATE, MAP_ANONYMOUS), (1, 2, 0x20));
        assert_eq!(MSG_DONTWAIT, 0x40);
        assert_eq!(NR_BPF, 321);
        assert_eq!(
            (
                size_of::<c_int>(),
                size_of::<SockLen>(),
                size_of::<Offset>(),
                size_of::<PollCount>(),
                size_of::<RawFd>(),
                size_of::<c_long>(),
                size_of::<c_ulong>(),
            ),
            (4, 4, 8, 8, 4, 8, 8)
        );
    }

    #[test]
    fn native_syscall_raii_transcript_is_static_bounded_and_redacted() {
        assert_static_syscalls::<LinuxSyscalls>();
        assert_static_syscalls::<FakeSyscalls>();
        assert!(size_of::<Errno>() <= size_of::<u32>());
        assert_eq!(Errno::new(0), None);
        assert_eq!(Errno::new(1).and_then(Errno::raw), Some(1));
        assert_eq!(
            Errno::new(MAX_LINUX_ERRNO).and_then(Errno::raw),
            Some(MAX_LINUX_ERRNO as u16)
        );
        assert_eq!(Errno::new(MAX_LINUX_ERRNO + 1), None);

        let syscalls = FakeSyscalls::new();
        syscalls.next_address.set(0);
        let mut socket = OwnedXdpFd::open(&syscalls).expect("fake socket");
        assert_eq!(
            format!("{socket:?}"),
            "OwnedXdpFd { fd: \"<redacted>\", active: true }"
        );

        socket
            .set_socket_option(283, 4, &[0x31, 0x32])
            .expect("fake setsockopt");
        let mut output = [0_u8; 4];
        assert_eq!(
            socket
                .get_socket_option(283, 1, &mut output)
                .expect("fake getsockopt"),
            4
        );
        assert_eq!(output, [0xa5; 4]);

        let mut anonymous =
            MappedRegion::map_anonymous(&syscalls, 8_192).expect("zero address is success");
        assert_eq!(
            format!("{anonymous:?}"),
            "MappedRegion { address: \"<redacted>\", byte_len: 8192, active: true }"
        );
        let mut shared = socket
            .map_shared(4_096, 0x1_8000_0000)
            .expect("shared ring map");
        socket.bind_bytes(&[44, 0, 0, 0]).expect("fake bind");
        assert_eq!(
            socket.poll(1, 0).expect("fake poll"),
            PollResult {
                ready: 1,
                events: 1
            }
        );
        socket.send_to_wakeup().expect("fake sendto");

        anonymous.unmap_once().expect("first anonymous unmap");
        anonymous.unmap_once().expect("idempotent anonymous unmap");
        shared.unmap_once().expect("first shared unmap");
        shared.unmap_once().expect("idempotent shared unmap");
        drop(shared);
        drop(anonymous);
        socket.close_once().expect("first close");
        socket.close_once().expect("idempotent close");
        drop(socket);

        assert_eq!(
            syscalls.transcript.borrow().as_slice(),
            &[
                Some(Call::Socket {
                    domain: 44,
                    kind: XDP_SOCKET_KIND,
                    protocol: 0,
                }),
                Some(Call::SetSocketOption {
                    fd: 17,
                    level: 283,
                    name: 4,
                    length: 2,
                    first: 0x31,
                }),
                Some(Call::GetSocketOption {
                    fd: 17,
                    level: 283,
                    name: 1,
                    capacity: 4,
                }),
                Some(Call::Mmap {
                    fd: -1,
                    byte_len: 8_192,
                    flags: MAP_PRIVATE | MAP_ANONYMOUS,
                    offset: 0,
                }),
                Some(Call::Mmap {
                    fd: 17,
                    byte_len: 4_096,
                    flags: MAP_SHARED,
                    offset: 0x1_8000_0000,
                }),
                Some(Call::Bind {
                    fd: 17,
                    length: 4,
                    first: 44,
                }),
                Some(Call::Poll {
                    fd: 17,
                    events: 1,
                    timeout_millis: 0,
                }),
                Some(Call::SendTo {
                    fd: 17,
                    flags: MSG_DONTWAIT,
                }),
                Some(Call::Munmap {
                    address: 0,
                    byte_len: 8_192,
                }),
                Some(Call::Munmap {
                    address: 0x1_0000,
                    byte_len: 4_096,
                }),
                Some(Call::Close { fd: 17 }),
            ]
        );
    }

    #[test]
    fn native_syscall_failure_cleanup_is_exactly_once() {
        let open_failure = FakeSyscalls::new();
        open_failure.fail.set(Some(SyscallStage::OpenSocket));
        assert!(matches!(
            OwnedXdpFd::open(&open_failure),
            Err(ResourceError::Syscall(SyscallError {
                stage: SyscallStage::OpenSocket,
                errno: TEST_ERRNO,
            }))
        ));
        assert_eq!(
            open_failure.count(|call| matches!(call, Call::Close { .. })),
            0
        );

        let map_failure = FakeSyscalls::new();
        map_failure.fail.set(Some(SyscallStage::MapMemory));
        {
            let socket = OwnedXdpFd::open(&map_failure).expect("fake socket");
            assert!(matches!(
                socket.map_shared(4_096, 0),
                Err(ResourceError::Syscall(SyscallError {
                    stage: SyscallStage::MapMemory,
                    errno: TEST_ERRNO,
                }))
            ));
        }
        assert_eq!(
            map_failure.count(|call| matches!(call, Call::Mmap { .. })),
            1
        );
        assert_eq!(
            map_failure.count(|call| matches!(call, Call::Munmap { .. })),
            0
        );
        assert_eq!(
            map_failure.count(|call| matches!(call, Call::Close { .. })),
            1
        );

        for stage in [
            SyscallStage::SetSocketOption,
            SyscallStage::GetSocketOption,
            SyscallStage::BindSocket,
            SyscallStage::PollSocket,
            SyscallStage::SendToSocket,
        ] {
            let syscalls = FakeSyscalls::new();
            {
                let socket = OwnedXdpFd::open(&syscalls).expect("fake socket");
                let first = MappedRegion::map_anonymous(&syscalls, 4_096).expect("first fake map");
                let second = socket.map_shared(8_192, 0).expect("second fake map");
                syscalls.fail.set(Some(stage));
                let error = match stage {
                    SyscallStage::SetSocketOption => socket
                        .set_socket_option(283, 4, &[1])
                        .expect_err("injected"),
                    SyscallStage::GetSocketOption => socket
                        .get_socket_option(283, 1, &mut [0_u8; 4])
                        .expect_err("injected"),
                    SyscallStage::BindSocket => socket.bind_bytes(&[44]).expect_err("injected"),
                    SyscallStage::PollSocket => socket.poll(1, 0).expect_err("injected"),
                    SyscallStage::SendToSocket => socket.send_to_wakeup().expect_err("injected"),
                    _ => unreachable!("loop contains only operation stages"),
                };
                assert_eq!(
                    error,
                    ResourceError::Syscall(SyscallError {
                        stage,
                        errno: TEST_ERRNO,
                    })
                );
                syscalls.fail.set(None);
                drop(second);
                drop(first);
                drop(socket);
            }
            assert_eq!(
                syscalls.count(|call| matches!(call, Call::Munmap { .. })),
                2,
                "{stage:?}"
            );
            assert_eq!(
                syscalls.count(|call| matches!(call, Call::Close { .. })),
                1,
                "{stage:?}"
            );
            let transcript = syscalls.transcript.borrow();
            assert!(matches!(
                transcript.as_slice()[transcript.len - 3..],
                [
                    Some(Call::Munmap {
                        byte_len: 8_192,
                        ..
                    }),
                    Some(Call::Munmap {
                        byte_len: 4_096,
                        ..
                    }),
                    Some(Call::Close { fd: 17 })
                ]
            ));
        }

        let unmap_failure = FakeSyscalls::new();
        let mut mapping = MappedRegion::map_anonymous(&unmap_failure, 4_096).expect("fake mapping");
        unmap_failure.fail.set(Some(SyscallStage::UnmapMemory));
        assert!(mapping.unmap_once().is_err());
        assert_eq!(mapping.unmap_once(), Ok(()));
        drop(mapping);
        assert_eq!(
            unmap_failure.count(|call| matches!(call, Call::Munmap { .. })),
            1
        );

        let close_failure = FakeSyscalls::new();
        let mut socket = OwnedXdpFd::open(&close_failure).expect("fake socket");
        close_failure.fail.set(Some(SyscallStage::CloseSocket));
        assert!(socket.close_once().is_err());
        assert_eq!(socket.close_once(), Ok(()));
        drop(socket);
        assert_eq!(
            close_failure.count(|call| matches!(call, Call::Close { .. })),
            1
        );
    }

    #[test]
    fn native_syscall_arguments_fail_before_transcript_mutation() {
        let syscalls = FakeSyscalls::new();
        let socket = OwnedXdpFd::open(&syscalls).expect("fake socket");
        let baseline = syscalls.transcript.borrow().len;

        assert_eq!(
            socket.set_socket_option(283, 4, &[]),
            Err(ResourceError::Argument(SyscallArgumentError::ZeroLength {
                stage: SyscallStage::SetSocketOption,
            }))
        );
        assert_eq!(
            socket.get_socket_option(283, 1, &mut []),
            Err(ResourceError::Argument(SyscallArgumentError::ZeroLength {
                stage: SyscallStage::GetSocketOption,
            }))
        );
        assert!(matches!(
            socket.map_shared(4_096, u64::MAX),
            Err(ResourceError::Argument(
                SyscallArgumentError::OffsetDoesNotFitOffT { offset: u64::MAX }
            ))
        ));
        let oversized = u32::MAX as usize + 1;
        assert_eq!(
            checked_sock_len(SyscallStage::SetSocketOption, oversized),
            Err(SyscallArgumentError::LengthDoesNotFitSockLen {
                stage: SyscallStage::SetSocketOption,
                length: oversized,
            })
        );
        assert_eq!(
            MappedRegion::map_anonymous(&syscalls, 0).map(|_| ()),
            Err(ResourceError::Argument(SyscallArgumentError::ZeroLength {
                stage: SyscallStage::MapMemory,
            }))
        );
        assert_eq!(
            socket.bind_bytes(&[]),
            Err(ResourceError::Argument(SyscallArgumentError::ZeroLength {
                stage: SyscallStage::BindSocket,
            }))
        );
        assert_eq!(syscalls.transcript.borrow().len, baseline);

        syscalls.returned_option_len.set(Some(5));
        let mut output = [0_u8; 4];
        assert_eq!(
            socket.get_socket_option(283, 1, &mut output),
            Err(ResourceError::Argument(
                SyscallArgumentError::KernelLengthOutOfBounds {
                    capacity: 4,
                    actual: 5,
                }
            ))
        );
    }

    #[test]
    fn native_mmap_failure_sentinel_does_not_conflate_null_success() {
        assert_eq!(
            decode_mmap_result(std::ptr::null_mut()),
            Ok(std::ptr::null_mut())
        );

        // Set a valid deterministic errno before exercising the pure result
        // decoder's failure branch.
        // SAFETY: Linux exposes writable thread-local errno through this
        // pointer; the write affects only the current test thread.
        unsafe {
            *ffi::__errno_location() = 12;
        }
        assert_eq!(decode_mmap_result(MAP_FAILED), Err(Errno::Linux(12)));
    }

    #[test]
    fn native_errno_debug_and_minus_one_decoders_are_exact() {
        // Protects errno formatting and all three libc return-value adapters:
        // only the ABI sentinel -1 is an error, while zero and positive values
        // remain successful results.
        assert_eq!(format!("{:?}", Errno::Linux(13)), "Errno(13)");
        assert_eq!(
            format!("{:?}", Errno::InvalidCapture),
            "Errno(<invalid-capture>)"
        );

        unsafe {
            *ffi::__errno_location() = 13;
        }
        assert_eq!(result_from_minus_one(-1), Err(Errno::Linux(13)));
        assert_eq!(result_from_minus_one(0), Ok(0));
        assert_eq!(result_from_minus_one(7), Ok(7));
        assert_eq!(result_from_ssize_minus_one(-1), Err(Errno::Linux(13)));
        assert_eq!(result_from_ssize_minus_one(0), Ok(0));
        assert_eq!(result_from_ssize_minus_one(7), Ok(7));
        assert_eq!(result_from_long_minus_one(-1), Err(Errno::Linux(13)));
        assert_eq!(result_from_long_minus_one(0), Ok(0));
        assert_eq!(result_from_long_minus_one(7), Ok(7));
    }

    #[test]
    fn native_verifier_log_uses_reported_size_only_when_present() {
        // Protects the verifier-log boundary: zero means the whole supplied
        // buffer is usable, nonzero is capped, and the first NUL terminates it.
        assert_eq!(VERIFIER_LOG_SIZE, 64 * 1024);
        let attr = [0_u8; BPF_ATTR_SIZE];
        assert_eq!(
            verifier_log_from_attr(&attr, b"complete log"),
            "complete log"
        );

        let mut attr = [0_u8; BPF_ATTR_SIZE];
        attr[140..144].copy_from_slice(&2_u32.to_ne_bytes());
        assert_eq!(verifier_log_from_attr(&attr, b"abc\0tail"), "ab");
    }

    #[test]
    fn native_mmap_length_checks_include_the_isize_boundary() {
        // Protects the mmap length boundary: exactly isize::MAX is representable
        // to from_raw_parts_mut, while one byte more must be rejected first.
        assert_eq!(checked_mmap_length(isize::MAX as usize), Ok(()));
        assert_eq!(
            checked_mmap_length(isize::MAX as usize + 1),
            Err(SyscallArgumentError::LengthDoesNotFitAddressSpace {
                stage: SyscallStage::MapMemory,
                length: isize::MAX as usize + 1,
            })
        );
    }

    #[test]
    fn native_owned_fd_rejects_negative_and_accepts_zero() {
        // Protects the ownership boundary: -1 is never an owned descriptor,
        // while descriptor zero is valid and must not be rejected.
        let negative = FdBoundarySyscalls::new(-1);
        assert!(matches!(
            OwnedXdpFd::open(&negative),
            Err(ResourceError::Argument(
                SyscallArgumentError::InvalidFileDescriptor
            ))
        ));

        let zero = FdBoundarySyscalls::new(0);
        let socket = OwnedXdpFd::open(&zero).expect("fd zero is owned");
        assert_eq!(socket.raw(), 0);
        drop(socket);
        assert_eq!(
            zero.inner
                .count(|call| matches!(call, Call::Close { fd: 0 })),
            1
        );
    }

    #[test]
    fn native_owned_close_methods_propagate_errors() {
        // Protects explicit close methods from discarding close errors; the
        // returned error is the caller's only indication of a failed release.
        let socket_syscalls = FakeSyscalls::new();
        let socket = OwnedXdpFd::open(&socket_syscalls).expect("fake socket");
        socket_syscalls.fail.set(Some(SyscallStage::CloseSocket));
        assert!(matches!(
            socket.close(),
            Err(ResourceError::Syscall(SyscallError {
                stage: SyscallStage::CloseSocket,
                errno: TEST_ERRNO,
            }))
        ));

        let map_syscalls = FakeSyscalls::new();
        let map = OwnedBpfMap::create(&map_syscalls, 1).expect("fake map");
        map_syscalls.fail.set(Some(SyscallStage::CloseSocket));
        assert!(matches!(
            map.close(),
            Err(BpfResourceError::Syscall {
                operation: XskMapOperation::Close,
                errno: TEST_ERRNO,
            })
        ));
    }

    #[test]
    fn native_program_accessors_debug_and_drop_preserve_ownership() {
        // Protects the program raw/debug accessors and Drop cleanup path. A
        // successful load still owns fd 23 and must close it exactly once.
        let syscalls = FakeSyscalls::new();
        let program =
            OwnedBpfProgram::load(&syscalls, &[0_u8; BPF_INSN_SIZE], 1).expect("fake program");
        assert_eq!(program.raw(), 23);
        assert_eq!(
            format!("{program:?}"),
            "OwnedBpfProgram { fd: \"<redacted>\", active: true }"
        );
        drop(program);
        assert_eq!(
            syscalls.count(|call| matches!(call, Call::Close { fd: 23 })),
            1
        );

        let map = OwnedBpfMap::create(&syscalls, 1).expect("fake map");
        assert_eq!(
            format!("{map:?}"),
            "OwnedBpfMap { fd: \"<redacted>\", max_entries: 1, active: true }"
        );
        drop(map);
    }

    #[test]
    fn native_mapping_accessors_alignment_and_bytes_have_stateful_contracts() {
        // Protects mmap metadata accessors, page-alignment reporting, and the
        // active/non-null checks around the mutable mapping view.
        let syscalls = FakeSyscalls::new();
        let mut aligned = MappedRegion::map_anonymous(&syscalls, 8).expect("fake map");
        assert_eq!(aligned.address(), 0x1_0000);
        assert_eq!(aligned.byte_len(), 8);
        assert!(aligned.address_is_page_aligned());
        aligned.unmap_once().expect("fake unmap");

        syscalls.next_address.set(0x1_0001);
        let unaligned = MappedRegion::map_anonymous(&syscalls, 8).expect("fake map");
        assert!(!unaligned.address_is_page_aligned());
        drop(unaligned);

        let mut storage = Box::new([0_u8; 8]);
        let address = storage.as_mut_ptr().cast::<c_void>();
        let mut active = MappedRegion {
            syscalls: &syscalls,
            address,
            byte_len: storage.len(),
            active: true,
        };
        let bytes = active.as_mut_bytes().expect("active non-null map");
        bytes[0] = 0x5a;
        assert_eq!(storage[0], 0x5a);
        active.active = false;
        assert!(active.as_mut_bytes().is_none());
        drop(active);
    }

    #[test]
    fn native_mapping_unmap_method_propagates_failure() {
        // Protects the consuming unmap method from turning a kernel munmap
        // failure into a false success.
        let syscalls = FakeSyscalls::new();
        let mapping = MappedRegion::map_anonymous(&syscalls, 4_096).expect("fake map");
        syscalls.fail.set(Some(SyscallStage::UnmapMemory));
        assert!(matches!(
            mapping.unmap(),
            Err(ResourceError::Syscall(SyscallError {
                stage: SyscallStage::UnmapMemory,
                errno: TEST_ERRNO,
            }))
        ));
    }

    #[test]
    fn native_linux_wrappers_report_kernel_errors_and_poll_counts() {
        // Protects every production libc wrapper from accepting a failed
        // syscall, and checks both possible poll return values (ready and
        // timeout) so fabricated Ok(0)/Ok(1) replacements are observable.
        let linux = LinuxSyscalls;
        assert!(<LinuxSyscalls as Syscalls>::socket(&linux, -1, 0, 0).is_err());
        assert!(<LinuxSyscalls as Syscalls>::set_socket_option(&linux, -1, 0, 0, &[1], 1).is_err());
        let mut option = [0_u8; 4];
        let mut option_len = 4;
        assert!(<LinuxSyscalls as Syscalls>::get_socket_option(
            &linux,
            -1,
            0,
            0,
            &mut option,
            &mut option_len,
        )
        .is_err());
        assert!(<LinuxSyscalls as Syscalls>::bind(&linux, -1, &[0], 1).is_err());
        assert!(<LinuxSyscalls as Syscalls>::send_to_wakeup(&linux, -1).is_err());
        assert!(<LinuxSyscalls as Syscalls>::close(&linux, -1).is_err());

        let mut descriptor = PollDescriptor::new(-1, 1);
        assert_eq!(
            <LinuxSyscalls as Syscalls>::poll(&linux, &mut descriptor, 0),
            Ok(0)
        );

        use std::os::fd::AsRawFd;
        let ready = std::fs::File::open("/dev/null").expect("dev null");
        let mut descriptor = PollDescriptor::new(ready.as_raw_fd(), 1);
        assert_eq!(
            <LinuxSyscalls as Syscalls>::poll(&linux, &mut descriptor, 0),
            Ok(1)
        );

        let mut attr = [0_u8; BPF_ATTR_SIZE];
        assert!(<LinuxSyscalls as Syscalls>::bpf(&linux, BPF_MAP_CREATE, &mut attr).is_err());
        assert!(
            <LinuxSyscalls as Syscalls>::munmap(&linux, std::ptr::dangling_mut(), 4_096).is_err()
        );
    }

    #[test]
    fn native_linux_anonymous_mmap_is_writable_and_uses_a_real_mapping() {
        // Protects the production mmap result, anonymous flags, and read/write
        // protection. The write is intentionally part of the ABI contract.
        let linux = LinuxSyscalls;
        let address =
            <LinuxSyscalls as Syscalls>::mmap(&linux, MapRequest::Anonymous { byte_len: 4_096 })
                .expect("anonymous mmap");
        assert!(!address.is_null());
        // SAFETY: the preceding mmap returned a non-null successful mapping
        // with the requested writable protection and one page of extent.
        unsafe {
            address.cast::<u8>().write(0x5a);
        }
        <LinuxSyscalls as Syscalls>::munmap(&linux, address, 4_096).expect("anonymous munmap");
    }

    #[test]
    fn native_linux_netlink_wrappers_report_invalid_descriptor_errors() {
        // Protects the separate netlink libc seam, including send length
        // conversion and fd duplication, from fabricated successful returns.
        let linux = LinuxSyscalls;
        assert!(<LinuxSyscalls as NetlinkSyscalls>::socket(&linux, -1, 0, 0).is_err());
        assert!(<LinuxSyscalls as NetlinkSyscalls>::bind(&linux, -1, &[0], 1).is_err());
        let mut address = [0_u8; 12];
        let mut length = 12;
        assert!(<LinuxSyscalls as NetlinkSyscalls>::getsockname(
            &linux,
            -1,
            &mut address,
            &mut length,
        )
        .is_err());
        assert!(<LinuxSyscalls as NetlinkSyscalls>::dup_cloexec(&linux, -1).is_err());
        assert!(
            <LinuxSyscalls as NetlinkSyscalls>::send_netlink(&linux, -1, &[1], &[0; 12]).is_err()
        );
        assert!(<LinuxSyscalls as NetlinkSyscalls>::close(&linux, -1).is_err());
    }
}
