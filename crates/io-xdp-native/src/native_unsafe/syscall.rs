#![allow(dead_code, unsafe_code)]
//! Private x86_64 Linux syscall and RAII foundation for future AF_XDP resource setup.
//!
//! C2A deliberately has no public constructor and performs no UMEM
//! registration, ring configuration, bind transaction, or packet I/O. The
//! generic syscall boundary is sealed and statically dispatched so NIC-free
//! tests can inject a finite transcript without adding a virtual call to the
//! future data path.

use std::{
    ffi::{c_char, c_int, c_long, c_short, c_uint, c_void, CStr},
    fmt,
    mem::size_of,
    os::fd::RawFd,
    ptr::NonNull,
};

use crate::{
    abi::AF_XDP,
    ensure_native_syscall_supported,
    xdp_program::{
        redirect_program, BpfInsn, BPF_OBJ_NAME_LEN, MAP_NAME, PROGRAM_LICENSE, PROGRAM_NAME,
        REDIRECT_PROGRAM_LEN,
    },
    NativeSyscallPlatformError,
};

use super::mmap::BorrowedMmap;

/// Pinned source profile for architecture-dependent syscall constants.
const SYSCALL_ABI_PROFILE: &str =
    "Linux v6.8 x86_64: include/linux/net.h, include/linux/socket.h, \
     include/uapi/asm-generic/fcntl.h, include/uapi/linux/mman.h, \
     include/uapi/asm-generic/mman-common.h";

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
const MAP_FAILED: *mut c_void = std::ptr::without_provenance_mut(usize::MAX);

type SockLen = u32;
type Offset = i64;
type PollCount = usize;

const _: [(); 4] = [(); size_of::<c_int>()];
const _: [(); 4] = [(); size_of::<SockLen>()];
const _: [(); 8] = [(); size_of::<Offset>()];
const _: [(); 8] = [(); size_of::<PollCount>()];
const _: [(); 4] = [(); size_of::<RawFd>()];

/// Largest positive errno encoded by the reviewed Linux syscall ABI.
const MAX_LINUX_ERRNO: i32 = 4_095;

/// Linux `IFNAMSIZ` (`include/uapi/linux/if.h`): name bytes plus the NUL.
pub(super) const IFNAMSIZ: usize = 16;

/// x86_64 Linux base page size (`arch/x86/include/asm/page_types.h`).
pub(super) const PAGE_SIZE: usize = 4_096;

/// Pinned source profile of the `bpf(2)` subset used for XDP attach.
const BPF_ABI_PROFILE: &str = "Linux v6.8 x86_64: arch/x86/entry/syscalls/syscall_64.tbl, \
     include/uapi/linux/bpf.h, include/uapi/linux/bpf_common.h, \
     include/uapi/linux/if_link.h; minimum kernel 5.9 (BPF_LINK_CREATE for XDP)";

/// `__NR_bpf` on x86_64.
const SYS_BPF: c_long = 321;

/// `enum bpf_cmd`, object types, and `union bpf_attr` prefix lengths.
pub(super) mod bpf {
    pub(in crate::native_unsafe) const BPF_MAP_CREATE: u32 = 0;
    pub(in crate::native_unsafe) const BPF_MAP_UPDATE_ELEM: u32 = 2;
    pub(in crate::native_unsafe) const BPF_PROG_LOAD: u32 = 5;
    pub(in crate::native_unsafe) const BPF_LINK_CREATE: u32 = 28;
    /// `enum bpf_map_type` `BPF_MAP_TYPE_XSKMAP`.
    pub(in crate::native_unsafe) const BPF_MAP_TYPE_XSKMAP: u32 = 17;
    /// `enum bpf_prog_type` `BPF_PROG_TYPE_XDP`.
    pub(in crate::native_unsafe) const BPF_PROG_TYPE_XDP: u32 = 6;
    /// `enum bpf_attach_type` `BPF_XDP` (Linux 5.9+).
    pub(in crate::native_unsafe) const BPF_XDP: u32 = 37;
    /// `BPF_NOEXIST`: the update must not replace an occupied slot.
    pub(in crate::native_unsafe) const BPF_NOEXIST: u64 = 1;
    /// `BPF_LOG_LEVEL1`.
    pub(in crate::native_unsafe) const BPF_LOG_LEVEL1: u32 = 1;
    /// `BPF_MAXINSNS` (`bpf_common.h`), applied unconditionally.
    pub(in crate::native_unsafe) const BPF_MAXINSNS: usize = 4_096;
    /// Largest license copied by Linux `bpf_prog_load` (128-byte buffer).
    pub(in crate::native_unsafe) const LICENSE_CAPACITY: usize = 128;
    /// Bytes of `union bpf_attr` passed per command: exactly the leading
    /// fields this profile writes, all present since Linux 5.9. The kernel
    /// treats the omitted tail as zero.
    pub(in crate::native_unsafe) const MAP_CREATE_ATTR_LEN: usize = 44;
    pub(in crate::native_unsafe) const MAP_UPDATE_ATTR_LEN: usize = 32;
    pub(in crate::native_unsafe) const PROG_LOAD_ATTR_LEN: usize = 72;
    pub(in crate::native_unsafe) const LINK_CREATE_ATTR_LEN: usize = 16;
}

/// Accepted verifier log buffer lengths: Linux 5.x requires at least 128
/// bytes with a nonzero log level, and every version caps at `u32::MAX >> 2`.
pub(super) const BPF_LOG_CAPACITY_RANGE: std::ops::RangeInclusive<usize> =
    128..=(u32::MAX >> 2) as usize;

/// One XSKMAP creation request (`key_size = value_size = 4`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MapCreateRequest {
    pub(super) max_entries: u32,
    pub(super) name: [u8; BPF_OBJ_NAME_LEN],
}

/// One `BPF_PROG_LOAD` request for an XDP program.
pub(super) struct ProgramLoadRequest<'a> {
    pub(super) insns: &'a [BpfInsn],
    pub(super) license: &'a CStr,
    pub(super) name: [u8; BPF_OBJ_NAME_LEN],
    /// Kernel-written `BPF_LOG_LEVEL1` verifier log. Untrusted bytes.
    pub(super) log: &'a mut [u8],
}

/// Linux v6.8 `include/uapi/asm-generic/errno-base.h` and `errno.h` values
/// that the session builder classifies. Every other errno stays numeric.
pub(super) mod errno {
    pub(in crate::native_unsafe) const EPERM: u16 = 1;
    pub(in crate::native_unsafe) const E2BIG: u16 = 7;
    pub(in crate::native_unsafe) const ENOMEM: u16 = 12;
    pub(in crate::native_unsafe) const EACCES: u16 = 13;
    pub(in crate::native_unsafe) const EBUSY: u16 = 16;
    pub(in crate::native_unsafe) const EEXIST: u16 = 17;
    pub(in crate::native_unsafe) const ENODEV: u16 = 19;
    pub(in crate::native_unsafe) const EINVAL: u16 = 22;
    pub(in crate::native_unsafe) const ENOSPC: u16 = 28;
    pub(in crate::native_unsafe) const EOPNOTSUPP: u16 = 95;
    pub(in crate::native_unsafe) const EAFNOSUPPORT: u16 = 97;
    pub(in crate::native_unsafe) const ENOBUFS: u16 = 105;
}

/// Bounded positive Linux errno value.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Errno {
    Linux(u16),
    InvalidCapture,
    /// The production seam refused an argument before entering libc. The
    /// checked wrappers make this unreachable; it is a defense in depth.
    ArgumentRejected,
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

    pub(super) const fn raw(self) -> Option<u16> {
        match self {
            Self::Linux(raw) => Some(raw),
            Self::InvalidCapture | Self::ArgumentRejected => None,
        }
    }
}

impl fmt::Debug for Errno {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linux(raw) => formatter.debug_tuple("Errno").field(raw).finish(),
            Self::InvalidCapture => formatter.write_str("Errno(<invalid-capture>)"),
            Self::ArgumentRejected => formatter.write_str("Errno(<argument-rejected>)"),
        }
    }
}

/// Exact cold syscall stage associated with an errno.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SyscallStage {
    InterfaceIndex,
    OpenSocket,
    SetSocketOption,
    GetSocketOption,
    MapMemory,
    UnmapMemory,
    BindSocket,
    PollSocket,
    SendToSocket,
    CloseSocket,
    CreateBpfMap,
    LoadBpfProgram,
    UpdateBpfMap,
    CreateBpfLink,
    CloseBpfObject,
}

/// One syscall failure with no descriptor, address, or packet data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SyscallError {
    pub(super) stage: SyscallStage,
    pub(super) errno: Errno,
}

/// Checked argument failure detected before entering libc.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SyscallArgumentError {
    InvalidFileDescriptor,
    InvalidInterfaceName,
    ZeroLength {
        stage: SyscallStage,
    },
    LengthDoesNotFitSockLen {
        stage: SyscallStage,
        length: usize,
    },
    OffsetDoesNotFitOffT {
        offset: u64,
    },
    KernelLengthOutOfBounds {
        capacity: usize,
        actual: usize,
    },
    /// A BPF handle of the wrong kind was passed (a map where a program is
    /// required, for example).
    WrongBpfObject,
    /// A zero ifindex or XSKMAP size, or an XSKMAP key outside the map.
    BpfArgumentOutOfRange,
    /// The verifier log buffer is outside [`BPF_LOG_CAPACITY_RANGE`].
    VerifierLogLength {
        length: usize,
    },
}

/// Fixed-size error from the private syscall/RAII seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ResourceError {
    Platform(NativeSyscallPlatformError),
    Argument(SyscallArgumentError),
    Syscall(SyscallError),
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

#[derive(Clone, Copy)]
pub(super) struct PollDescriptor {
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
pub(super) struct PollResult {
    pub(super) ready: u32,
    pub(super) events: i16,
}

#[derive(Clone, Copy)]
pub(super) enum MapRequest {
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

pub(super) mod sealed {
    pub trait Sealed {}
}

/// Sealed cold-path boundary; generic users are monomorphized, never dynamic.
pub(super) trait Syscalls: sealed::Sealed {
    /// `if_nametoindex(3)`. `name` is NUL-padded with `name[IFNAMSIZ - 1] == 0`.
    fn interface_index(&self, name: &[u8; IFNAMSIZ]) -> Result<u32, Errno>;
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
    /// # Safety
    ///
    /// `address` and `byte_len` must be exactly one live mapping returned by
    /// this seam, and no ring view or other access may use it afterwards.
    /// Only `MappedRegion` calls this, at most once per mapping.
    unsafe fn munmap(&self, address: *mut c_void, byte_len: usize) -> Result<(), Errno>;
    fn bind(&self, fd: RawFd, address: &[u8], length: SockLen) -> Result<(), Errno>;
    fn poll(&self, descriptor: &mut PollDescriptor, timeout_millis: c_int) -> Result<u32, Errno>;
    fn send_to_wakeup(&self, fd: RawFd) -> Result<(), Errno>;
    /// # Safety
    ///
    /// `fd` must be an fd owned by the caller that is never used again,
    /// because its number may be reused immediately. Only `OwnedXdpFd`
    /// calls this, at most once per fd.
    unsafe fn close(&self, fd: RawFd) -> Result<(), Errno>;
    /// `bpf(BPF_MAP_CREATE)` for one XSKMAP; returns an owned CLOEXEC fd.
    fn bpf_map_create(&self, request: &MapCreateRequest) -> Result<RawFd, Errno>;
    /// `bpf(BPF_PROG_LOAD)` for one `BPF_PROG_TYPE_XDP` program; returns an
    /// owned CLOEXEC fd. The kernel writes at most `request.log.len()` bytes.
    fn bpf_prog_load(&self, request: &mut ProgramLoadRequest<'_>) -> Result<RawFd, Errno>;
    /// `bpf(BPF_MAP_UPDATE_ELEM, BPF_NOEXIST)` storing socket fd `value` at
    /// `key`.
    fn bpf_map_update(&self, map_fd: RawFd, key: u32, value: RawFd) -> Result<(), Errno>;
    /// `bpf(BPF_LINK_CREATE)` with `attach_type = BPF_XDP` on `ifindex`;
    /// returns an owned CLOEXEC link fd.
    fn bpf_link_create(&self, prog_fd: RawFd, ifindex: u32, flags: u32) -> Result<RawFd, Errno>;
}

/// Seam whose successful `mmap` results are real process mappings.
///
/// # Safety
///
/// Every `Ok(address)` returned by [`Syscalls::mmap`] for a request of
/// `byte_len` bytes must be a live `PROT_READ | PROT_WRITE` mapping of at
/// least `byte_len` bytes that no Rust reference aliases and that remains
/// valid until [`Syscalls::munmap`] is called with the same address and
/// length by its owning `MappedRegion`. Nothing else may unmap, remap, or
/// change the protection of any range overlapping that mapping (including
/// `MAP_FIXED` mappings or `munmap`/`mprotect` calls elsewhere in the
/// process); doing so breaks this contract.
/// [`MappedRegion::borrow_mapping`] relies on this to lend ring views.
/// Transcript-only fakes that return synthetic addresses must not implement
/// this trait.
pub(super) unsafe trait MapsRealMemory: Syscalls {}

/// Production Linux implementation. No C2A public API invokes it.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct LinuxSyscalls;

impl sealed::Sealed for LinuxSyscalls {}

// SAFETY: a successful Linux `mmap` returns exactly such a mapping; the seam
// requests PROT_READ|PROT_WRITE, and `MappedRegion` is the sole owner that
// calls `munmap` with the exact returned address and length.
unsafe impl MapsRealMemory for LinuxSyscalls {}

impl Syscalls for LinuxSyscalls {
    fn interface_index(&self, name: &[u8; IFNAMSIZ]) -> Result<u32, Errno> {
        if name[IFNAMSIZ - 1] != 0 {
            return Err(Errno::ArgumentRejected);
        }
        // SAFETY: `name` is a borrowed 16-byte array whose last byte is NUL
        // (checked by `interface_index`), so libc reads a terminated C
        // string entirely inside the borrow. The call retains no pointer.
        let index = unsafe { ffi::if_nametoindex(name.as_ptr().cast::<c_char>()) };
        if index == 0 {
            Err(last_errno())
        } else {
            Ok(index)
        }
    }

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
        if usize::try_from(length) != Ok(value.len()) {
            return Err(Errno::ArgumentRejected);
        }
        // SAFETY: `value` remains readable for exactly `length` bytes during
        // the call; the check above enforces the matching SockLen.
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
        if usize::try_from(*length) != Ok(value.len()) {
            return Err(Errno::ArgumentRejected);
        }
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

    unsafe fn munmap(&self, address: *mut c_void, byte_len: usize) -> Result<(), Errno> {
        // SAFETY: the caller upholds the trait contract: this is the exact
        // address and length of one live mapping, unmapped at most once, and
        // nothing accesses it afterwards.
        let result = unsafe { ffi::munmap(address, byte_len) };
        result_from_minus_one(result).map(|_| ())
    }

    fn bind(&self, fd: RawFd, address: &[u8], length: SockLen) -> Result<(), Errno> {
        if usize::try_from(length) != Ok(address.len()) {
            return Err(Errno::ArgumentRejected);
        }
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

    unsafe fn close(&self, fd: RawFd) -> Result<(), Errno> {
        // SAFETY: `OwnedXdpFd` transfers each nonnegative owned fd here at most
        // once. Close is deliberately not retried after an error because the
        // numeric fd may already have been released and reused.
        let result = unsafe { ffi::close(fd) };
        result_from_minus_one(result).map(|_| ())
    }

    fn bpf_map_create(&self, request: &MapCreateRequest) -> Result<RawFd, Errno> {
        if request.max_entries == 0 || request.name[BPF_OBJ_NAME_LEN - 1] != 0 {
            return Err(Errno::ArgumentRejected);
        }
        let mut attr = BpfAttr::<{ bpf::MAP_CREATE_ATTR_LEN }>::new();
        attr.put_u32(0, bpf::BPF_MAP_TYPE_XSKMAP);
        attr.put_u32(4, 4); // key_size: u32 queue index
        attr.put_u32(8, 4); // value_size: u32 socket fd
        attr.put_u32(12, request.max_entries);
        // map_flags, inner_map_fd, and numa_node stay zero.
        attr.put_bytes(28, &request.name);
        // SAFETY: `attr` is an owned, 8-byte aligned, pointer-free buffer of
        // exactly the passed length; the kernel only reads it.
        let result = unsafe { attr.call(bpf::BPF_MAP_CREATE) };
        result_from_fd(result)
    }

    fn bpf_prog_load(&self, request: &mut ProgramLoadRequest<'_>) -> Result<RawFd, Errno> {
        let insn_cnt = request.insns.len();
        let license = request.license.to_bytes_with_nul();
        if insn_cnt == 0
            || insn_cnt > bpf::BPF_MAXINSNS
            || license.len() > bpf::LICENSE_CAPACITY
            || !BPF_LOG_CAPACITY_RANGE.contains(&request.log.len())
            || request.name[BPF_OBJ_NAME_LEN - 1] != 0
        {
            return Err(Errno::ArgumentRejected);
        }
        let mut attr = BpfAttr::<{ bpf::PROG_LOAD_ATTR_LEN }>::new();
        attr.put_u32(0, bpf::BPF_PROG_TYPE_XDP);
        attr.put_u32(4, insn_cnt as u32);
        attr.put_u64(8, request.insns.as_ptr().expose_provenance() as u64);
        attr.put_u64(16, license.as_ptr().expose_provenance() as u64);
        attr.put_u32(24, bpf::BPF_LOG_LEVEL1);
        attr.put_u32(28, request.log.len() as u32);
        attr.put_u64(32, request.log.as_mut_ptr().expose_provenance() as u64);
        // kern_version and prog_flags stay zero.
        attr.put_bytes(48, &request.name);
        // prog_ifindex stays zero: the program is not device-bound.
        attr.put_u32(68, bpf::BPF_XDP);
        // SAFETY: the attr holds three user pointers, each derived from a
        // borrow that `request` holds for the whole call. `insns` is
        // readable for exactly `insn_cnt` 8-byte `repr(C)` instructions
        // (bounded above). `license` is NUL-terminated within 128 bytes,
        // and the kernel copies at most 127 bytes of it. `log` is
        // exclusively borrowed and writable for exactly `log_size` bytes,
        // which the kernel never exceeds. The kernel keeps none of the
        // pointers after returning.
        let result = unsafe { attr.call(bpf::BPF_PROG_LOAD) };
        result_from_fd(result)
    }

    fn bpf_map_update(&self, map_fd: RawFd, key: u32, value: RawFd) -> Result<(), Errno> {
        if map_fd < 0 || value < 0 {
            return Err(Errno::ArgumentRejected);
        }
        let key_bytes = key.to_ne_bytes();
        let value_bytes = value.to_ne_bytes();
        let mut attr = BpfAttr::<{ bpf::MAP_UPDATE_ATTR_LEN }>::new();
        attr.put_u32(0, map_fd.unsigned_abs());
        attr.put_u64(8, key_bytes.as_ptr().expose_provenance() as u64);
        attr.put_u64(16, value_bytes.as_ptr().expose_provenance() as u64);
        attr.put_u64(24, bpf::BPF_NOEXIST);
        // SAFETY: `key` and `value` point to live four-byte locals of this
        // frame, matching the XSKMAP key and value size. The kernel only
        // reads them during the call. The attr buffer has exactly the
        // passed length.
        let result = unsafe { attr.call(bpf::BPF_MAP_UPDATE_ELEM) };
        result_from_fd(result).map(|_| ())
    }

    fn bpf_link_create(&self, prog_fd: RawFd, ifindex: u32, flags: u32) -> Result<RawFd, Errno> {
        if prog_fd < 0 || ifindex == 0 {
            return Err(Errno::ArgumentRejected);
        }
        let mut attr = BpfAttr::<{ bpf::LINK_CREATE_ATTR_LEN }>::new();
        attr.put_u32(0, prog_fd.unsigned_abs());
        attr.put_u32(4, ifindex);
        attr.put_u32(8, bpf::BPF_XDP);
        attr.put_u32(12, flags);
        // SAFETY: `attr` is an owned, aligned, pointer-free buffer of exactly
        // the passed length; the kernel only reads it.
        let result = unsafe { attr.call(bpf::BPF_LINK_CREATE) };
        result_from_fd(result)
    }
}

/// Leading bytes of one `union bpf_attr`, 8-byte aligned like the kernel's
/// `__aligned_u64` fields.
#[repr(C, align(8))]
struct BpfAttr<const LEN: usize>([u8; LEN]);

impl<const LEN: usize> BpfAttr<LEN> {
    const fn new() -> Self {
        Self([0; LEN])
    }

    fn put_u32(&mut self, offset: usize, value: u32) {
        self.0[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }

    fn put_u64(&mut self, offset: usize, value: u64) {
        self.0[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
    }

    fn put_bytes(&mut self, offset: usize, value: &[u8]) {
        self.0[offset..offset + value.len()].copy_from_slice(value);
    }

    /// # Safety
    ///
    /// Every user pointer stored in the attr must be valid, for the whole
    /// call, for the access the kernel performs for `command`.
    unsafe fn call(&mut self, command: u32) -> c_long {
        // SAFETY: the caller upholds the pointer contract above. The attr
        // itself is valid for reads and writes of exactly `LEN` bytes. Every
        // variadic argument is passed as a full `long`, as `syscall(2)`
        // reads them.
        unsafe {
            ffi::syscall(
                SYS_BPF,
                c_long::from(command),
                self.0.as_mut_ptr().cast::<c_void>(),
                LEN as c_long,
            )
        }
    }
}

/// Decodes a `bpf(2)` result: an fd, or zero for a map update.
fn result_from_fd(result: c_long) -> Result<RawFd, Errno> {
    if result == -1 {
        Err(last_errno())
    } else {
        RawFd::try_from(result)
            .ok()
            .filter(|fd| *fd >= 0)
            .ok_or(Errno::InvalidCapture)
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

/// Resolves one NUL-padded interface name to its nonzero Linux ifindex in
/// the caller's network namespace. No resource is acquired.
pub(super) fn interface_index<S: Syscalls>(
    syscalls: &S,
    name: &[u8; IFNAMSIZ],
) -> Result<u32, ResourceError> {
    ensure_native_syscall_supported().map_err(ResourceError::Platform)?;
    if name[0] == 0 || name[IFNAMSIZ - 1] != 0 {
        return Err(SyscallArgumentError::InvalidInterfaceName.into());
    }
    syscalls
        .interface_index(name)
        .map_err(|errno| syscall_error(SyscallStage::InterfaceIndex, errno))
}

/// Owned nonnegative AF_XDP fd with exactly-once close semantics.
pub(super) struct OwnedXdpFd<'syscalls, S: Syscalls> {
    syscalls: &'syscalls S,
    fd: Option<RawFd>,
}

impl<'syscalls, S: Syscalls> OwnedXdpFd<'syscalls, S> {
    pub(super) fn open(syscalls: &'syscalls S) -> Result<Self, ResourceError> {
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

    /// The seam this fd releases through, for creating related objects.
    pub(super) const fn syscalls(&self) -> &'syscalls S {
        self.syscalls
    }

    pub(super) fn set_socket_option(
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

    pub(super) fn get_socket_option(
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

    pub(super) fn map_shared(
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

    pub(super) fn bind_bytes(&self, address: &[u8]) -> Result<(), ResourceError> {
        let length = checked_sock_len(SyscallStage::BindSocket, address.len())?;
        self.syscalls
            .bind(self.raw(), address, length)
            .map_err(|errno| syscall_error(SyscallStage::BindSocket, errno))
    }

    pub(super) fn poll(
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

    pub(super) fn send_to_wakeup(&self) -> Result<(), ResourceError> {
        self.syscalls
            .send_to_wakeup(self.raw())
            .map_err(|errno| syscall_error(SyscallStage::SendToSocket, errno))
    }

    pub(super) fn close(mut self) -> Result<(), ResourceError> {
        self.close_once()
    }

    fn close_once(&mut self) -> Result<(), ResourceError> {
        let Some(fd) = self.fd.take() else {
            return Ok(());
        };
        // SAFETY: `fd` came from one successful `socket` call, was owned only
        // by `self`, and `take` above makes this the single release; the
        // number is never used again.
        unsafe { self.syscalls.close(fd) }
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

/// Kind of kernel BPF object behind one [`OwnedBpfFd`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BpfObject {
    XskMap,
    XdpProgram,
    XdpLink,
}

/// Owned nonnegative BPF object fd with exactly-once close semantics.
///
/// Linux creates every map, program, and link fd with `O_CLOEXEC`, so none
/// leaks into an exec'd child. Closing the last reference of an XDP link
/// detaches its program; the link is never pinned, so process exit (even
/// SIGKILL) also detaches.
pub(super) struct OwnedBpfFd<'syscalls, S: Syscalls> {
    syscalls: &'syscalls S,
    fd: Option<RawFd>,
    object: BpfObject,
}

impl<'syscalls, S: Syscalls> OwnedBpfFd<'syscalls, S> {
    fn adopt(
        syscalls: &'syscalls S,
        object: BpfObject,
        result: Result<RawFd, Errno>,
        stage: SyscallStage,
    ) -> Result<Self, ResourceError> {
        let fd = result.map_err(|errno| syscall_error(stage, errno))?;
        if fd < 0 {
            return Err(SyscallArgumentError::InvalidFileDescriptor.into());
        }
        Ok(Self {
            syscalls,
            fd: Some(fd),
            object,
        })
    }

    /// Creates one XSKMAP with `max_entries` slots.
    pub(super) fn create_xskmap(
        syscalls: &'syscalls S,
        max_entries: u32,
    ) -> Result<Self, ResourceError> {
        ensure_native_syscall_supported().map_err(ResourceError::Platform)?;
        if max_entries == 0 {
            return Err(SyscallArgumentError::BpfArgumentOutOfRange.into());
        }
        let request = MapCreateRequest {
            max_entries,
            name: MAP_NAME,
        };
        let result = syscalls.bpf_map_create(&request);
        Self::adopt(
            syscalls,
            BpfObject::XskMap,
            result,
            SyscallStage::CreateBpfMap,
        )
    }

    /// Loads the redirect program bound to this XSKMAP. The kernel writes
    /// its verifier log into `log`, whose bytes the caller must treat as
    /// untrusted.
    pub(super) fn load_redirect_program(
        &self,
        log: &mut [u8],
    ) -> Result<OwnedBpfFd<'syscalls, S>, ResourceError> {
        let map_fd = self.raw_of(BpfObject::XskMap)?;
        if !BPF_LOG_CAPACITY_RANGE.contains(&log.len()) {
            return Err(SyscallArgumentError::VerifierLogLength { length: log.len() }.into());
        }
        let program: [BpfInsn; REDIRECT_PROGRAM_LEN] = redirect_program(map_fd);
        let mut request = ProgramLoadRequest {
            insns: &program,
            license: PROGRAM_LICENSE,
            name: PROGRAM_NAME,
            log,
        };
        let result = self.syscalls.bpf_prog_load(&mut request);
        Self::adopt(
            self.syscalls,
            BpfObject::XdpProgram,
            result,
            SyscallStage::LoadBpfProgram,
        )
    }

    /// Stores `socket` in this XSKMAP at `queue` (`BPF_NOEXIST`).
    pub(super) fn insert_socket(
        &self,
        queue: u32,
        socket: &OwnedXdpFd<'_, S>,
    ) -> Result<(), ResourceError> {
        let map_fd = self.raw_of(BpfObject::XskMap)?;
        self.syscalls
            .bpf_map_update(map_fd, queue, socket.raw())
            .map_err(|errno| syscall_error(SyscallStage::UpdateBpfMap, errno))
    }

    /// Attaches this program to `ifindex` through a new, unpinned link.
    pub(super) fn create_xdp_link(
        &self,
        ifindex: u32,
        flags: u32,
    ) -> Result<OwnedBpfFd<'syscalls, S>, ResourceError> {
        let prog_fd = self.raw_of(BpfObject::XdpProgram)?;
        if ifindex == 0 {
            return Err(SyscallArgumentError::BpfArgumentOutOfRange.into());
        }
        let result = self.syscalls.bpf_link_create(prog_fd, ifindex, flags);
        Self::adopt(
            self.syscalls,
            BpfObject::XdpLink,
            result,
            SyscallStage::CreateBpfLink,
        )
    }

    pub(super) const fn object(&self) -> BpfObject {
        self.object
    }

    fn raw_of(&self, object: BpfObject) -> Result<RawFd, ResourceError> {
        match self.fd {
            Some(fd) if self.object == object => Ok(fd),
            _ => Err(SyscallArgumentError::WrongBpfObject.into()),
        }
    }

    pub(super) fn close(mut self) -> Result<(), ResourceError> {
        self.close_once()
    }

    fn close_once(&mut self) -> Result<(), ResourceError> {
        let Some(fd) = self.fd.take() else {
            return Ok(());
        };
        // SAFETY: `fd` came from one successful `bpf(2)` call, was owned only
        // by `self`, and `take` above makes this the single release; the
        // number is never used again.
        unsafe { self.syscalls.close(fd) }
            .map_err(|errno| syscall_error(SyscallStage::CloseBpfObject, errno))
    }
}

impl<S: Syscalls> fmt::Debug for OwnedBpfFd<'_, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedBpfFd")
            .field("object", &self.object)
            .field("fd", &"<redacted>")
            .field("active", &self.fd.is_some())
            .finish()
    }
}

impl<S: Syscalls> Drop for OwnedBpfFd<'_, S> {
    fn drop(&mut self) {
        let _ = self.close_once();
    }
}

/// One owned mmap result. Address zero is a valid stored success.
pub(super) struct MappedRegion<'syscalls, S: Syscalls> {
    syscalls: &'syscalls S,
    address: *mut c_void,
    byte_len: usize,
    active: bool,
}

impl<S: MapsRealMemory> MappedRegion<'_, S> {
    /// Exclusively borrows the complete live mapping for ring access.
    ///
    /// Returns `None` for an inactive region or a mapping placed at address
    /// zero, which ring views cannot represent.
    pub(super) fn borrow_mapping(&mut self) -> Option<BorrowedMmap<'_>> {
        if !self.active {
            return None;
        }
        let base = NonNull::new(self.address.cast::<u8>())?;
        // SAFETY: `S: MapsRealMemory` and `active` mean
        // `address..address + byte_len` is the exact live read/write extent
        // returned by one successful mmap, and only `unmap_once` (requiring
        // `&mut self` or Drop) removes it. The returned borrow holds
        // `&mut self` for its whole lifetime, so the region can be neither
        // unmapped nor borrowed twice while ring views exist. Rust never
        // forms references into the mapping; ring access is atomic/volatile.
        Some(unsafe { BorrowedMmap::from_raw_parts(base, self.byte_len) })
    }
}

impl<'syscalls, S: Syscalls> MappedRegion<'syscalls, S> {
    pub(super) fn map_anonymous(
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

    pub(super) fn unmap(mut self) -> Result<(), ResourceError> {
        self.unmap_once()
    }

    /// Exact byte length passed to the successful mmap call.
    pub(super) const fn byte_len(&self) -> usize {
        self.byte_len
    }

    /// Numeric start address, for alignment checks only; never dereferenced.
    pub(super) fn address_bits(&self) -> usize {
        self.address.addr()
    }

    fn unmap_once(&mut self) -> Result<(), ResourceError> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        // SAFETY: `active` was true, so this is the exact live extent of one
        // successful mmap, released once. Any `BorrowedMmap` borrowed `&mut
        // self`, so no ring view can exist while this runs (it needs `&mut
        // self` or Drop), and `active = false` prevents later borrows.
        unsafe { self.syscalls.munmap(self.address, self.byte_len) }
            .map_err(|errno| syscall_error(SyscallStage::UnmapMemory, errno))
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
    use super::{c_char, c_int, c_long, c_short, c_uint, c_void, Offset, PollCount, SockLen};

    #[repr(C)]
    pub(super) struct PollFd {
        pub(super) fd: c_int,
        pub(super) events: c_short,
        pub(super) revents: c_short,
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
        pub(super) fn close(fd: c_int) -> c_int;
        pub(super) fn syscall(number: c_long, ...) -> c_long;
        pub(super) fn if_nametoindex(name: *const c_char) -> c_uint;
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
        InterfaceIndex {
            first: u8,
        },
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
        Close {
            fd: RawFd,
        },
        BpfMapCreate {
            max_entries: u32,
        },
        BpfProgLoad {
            insn_cnt: usize,
            map_fd: i32,
            log_len: usize,
        },
        BpfMapUpdate {
            map_fd: RawFd,
            key: u32,
            value: RawFd,
        },
        BpfLinkCreate {
            prog_fd: RawFd,
            ifindex: u32,
            flags: u32,
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
    }

    impl FakeSyscalls {
        fn new() -> Self {
            Self {
                transcript: RefCell::new(Transcript::new()),
                fail: Cell::new(None),
                next_address: Cell::new(0x1_0000),
                returned_option_len: Cell::new(None),
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
        fn interface_index(&self, name: &[u8; IFNAMSIZ]) -> Result<u32, Errno> {
            self.record(Call::InterfaceIndex { first: name[0] });
            self.result(SyscallStage::InterfaceIndex).map(|()| 3)
        }

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
            // Synthetic, never dereferenced: this fake is not `MapsRealMemory`.
            Ok(std::ptr::without_provenance_mut(address))
        }

        unsafe fn munmap(&self, address: *mut c_void, byte_len: usize) -> Result<(), Errno> {
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

        unsafe fn close(&self, fd: RawFd) -> Result<(), Errno> {
            self.record(Call::Close { fd });
            let stage = if fd == 17 {
                SyscallStage::CloseSocket
            } else {
                SyscallStage::CloseBpfObject
            };
            self.result(stage)
        }

        fn bpf_map_create(&self, request: &MapCreateRequest) -> Result<RawFd, Errno> {
            self.record(Call::BpfMapCreate {
                max_entries: request.max_entries,
            });
            self.result(SyscallStage::CreateBpfMap).map(|()| 30)
        }

        fn bpf_prog_load(&self, request: &mut ProgramLoadRequest<'_>) -> Result<RawFd, Errno> {
            self.record(Call::BpfProgLoad {
                insn_cnt: request.insns.len(),
                map_fd: request.insns[1].imm,
                log_len: request.log.len(),
            });
            self.result(SyscallStage::LoadBpfProgram).map(|()| 31)
        }

        fn bpf_map_update(&self, map_fd: RawFd, key: u32, value: RawFd) -> Result<(), Errno> {
            self.record(Call::BpfMapUpdate { map_fd, key, value });
            self.result(SyscallStage::UpdateBpfMap)
        }

        fn bpf_link_create(
            &self,
            prog_fd: RawFd,
            ifindex: u32,
            flags: u32,
        ) -> Result<RawFd, Errno> {
            self.record(Call::BpfLinkCreate {
                prog_fd,
                ifindex,
                flags,
            });
            self.result(SyscallStage::CreateBpfLink).map(|()| 32)
        }
    }

    fn assert_static_syscalls<T: Syscalls>() {}

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
             include/uapi/asm-generic/mman-common.h"
        );
        assert_eq!(
            (SOCK_RAW, SOCK_NONBLOCK, SOCK_CLOEXEC, XDP_SOCKET_KIND),
            (3, 0x800, 0x8_0000, 3 | 0x800 | 0x8_0000)
        );
        assert_eq!((PROT_READ, PROT_WRITE), (1, 2));
        assert_eq!((MAP_SHARED, MAP_PRIVATE, MAP_ANONYMOUS), (1, 2, 0x20));
        assert_eq!(MSG_DONTWAIT, 0x40);
        assert_eq!(
            (
                size_of::<c_int>(),
                size_of::<SockLen>(),
                size_of::<Offset>(),
                size_of::<PollCount>(),
                size_of::<RawFd>(),
            ),
            (4, 4, 8, 8, 4)
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
    fn native_linux_seam_rejects_inconsistent_arguments_before_ffi() {
        // Each production entry point re-checks its pointer/length contract
        // and returns a typed rejection without entering libc (fd -1 is
        // never passed to the kernel).
        let linux = LinuxSyscalls;
        assert_eq!(
            linux.interface_index(&[b'a'; IFNAMSIZ]),
            Err(Errno::ArgumentRejected)
        );
        assert_eq!(
            linux.set_socket_option(-1, 283, 4, &[1, 2], 3),
            Err(Errno::ArgumentRejected)
        );
        let mut length = 5;
        assert_eq!(
            linux.get_socket_option(-1, 283, 1, &mut [0_u8; 4], &mut length),
            Err(Errno::ArgumentRejected)
        );
        assert_eq!(length, 5);
        assert_eq!(
            linux.bind(-1, &[0_u8; 16], 15),
            Err(Errno::ArgumentRejected)
        );
        assert_eq!(Errno::ArgumentRejected.raw(), None);
        assert_eq!(
            format!("{:?}", Errno::ArgumentRejected),
            "Errno(<argument-rejected>)"
        );

        // The checked wrapper rejects a non-terminated name before the seam.
        let fake = FakeSyscalls::new();
        assert_eq!(
            interface_index(&fake, &[b'a'; IFNAMSIZ]),
            Err(ResourceError::Argument(
                SyscallArgumentError::InvalidInterfaceName
            ))
        );
        assert_eq!(
            interface_index(&fake, &[0; IFNAMSIZ]),
            Err(ResourceError::Argument(
                SyscallArgumentError::InvalidInterfaceName
            ))
        );
        assert_eq!(fake.transcript.borrow().len, 0);
    }

    #[test]
    fn native_bpf_seam_constants_and_attr_prefixes_are_pinned() {
        assert_eq!(
            BPF_ABI_PROFILE,
            "Linux v6.8 x86_64: arch/x86/entry/syscalls/syscall_64.tbl, \
             include/uapi/linux/bpf.h, include/uapi/linux/bpf_common.h, \
             include/uapi/linux/if_link.h; minimum kernel 5.9 (BPF_LINK_CREATE for XDP)"
        );
        assert_eq!(SYS_BPF, 321);
        assert_eq!(
            (
                bpf::BPF_MAP_CREATE,
                bpf::BPF_MAP_UPDATE_ELEM,
                bpf::BPF_PROG_LOAD,
                bpf::BPF_LINK_CREATE
            ),
            (0, 2, 5, 28)
        );
        assert_eq!(
            (
                bpf::BPF_MAP_TYPE_XSKMAP,
                bpf::BPF_PROG_TYPE_XDP,
                bpf::BPF_XDP
            ),
            (17, 6, 37)
        );
        assert_eq!(
            (bpf::BPF_NOEXIST, bpf::BPF_LOG_LEVEL1, bpf::BPF_MAXINSNS),
            (1, 1, 4_096)
        );
        // `union bpf_attr` prefix ends: map_name (28 + 16), flags (24 + 8),
        // expected_attach_type (68 + 4), link_create.flags (12 + 4).
        assert_eq!(
            (
                bpf::MAP_CREATE_ATTR_LEN,
                bpf::MAP_UPDATE_ATTR_LEN,
                bpf::PROG_LOAD_ATTR_LEN,
                bpf::LINK_CREATE_ATTR_LEN
            ),
            (44, 32, 72, 16)
        );
        assert_eq!(std::mem::align_of::<BpfAttr<16>>(), 8);
        assert_eq!(
            (
                *BPF_LOG_CAPACITY_RANGE.start(),
                *BPF_LOG_CAPACITY_RANGE.end()
            ),
            (128, (u32::MAX >> 2) as usize)
        );
        assert_eq!((errno::E2BIG, errno::EEXIST, errno::ENOSPC), (7, 17, 28));
        let mut attr = BpfAttr::<16>::new();
        attr.put_u32(4, 0x0102_0304);
        attr.put_u64(8, 0x0506_0708_090a_0b0c);
        assert_eq!(
            attr.0,
            [0, 0, 0, 0, 4, 3, 2, 1, 0x0c, 0x0b, 0x0a, 9, 8, 7, 6, 5]
        );
        assert_eq!(result_from_fd(7), Ok(7));
        assert_eq!(result_from_fd(0), Ok(0));
        assert_eq!(result_from_fd(-2), Err(Errno::InvalidCapture));
        assert_eq!(
            result_from_fd(c_long::from(i32::MAX) + 1),
            Err(Errno::InvalidCapture)
        );
    }

    #[test]
    fn native_bpf_objects_are_typed_redacted_and_closed_once() {
        let syscalls = FakeSyscalls::new();
        let socket = OwnedXdpFd::open(&syscalls).expect("fake socket");
        let map = OwnedBpfFd::create_xskmap(&syscalls, 4).expect("fake map");
        assert_eq!(map.object(), BpfObject::XskMap);
        assert_eq!(
            format!("{map:?}"),
            "OwnedBpfFd { object: XskMap, fd: \"<redacted>\", active: true }"
        );
        let mut log = [0_u8; 128];
        let program = map.load_redirect_program(&mut log).expect("fake load");
        map.insert_socket(3, &socket).expect("fake update");
        let link = program.create_xdp_link(9, 4).expect("fake link");
        assert_eq!(link.object(), BpfObject::XdpLink);

        // Handles of the wrong kind are refused before the seam.
        let baseline = syscalls.transcript.borrow().len;
        let wrong = ResourceError::Argument(SyscallArgumentError::WrongBpfObject);
        assert_eq!(program.insert_socket(3, &socket), Err(wrong));
        assert_eq!(link.load_redirect_program(&mut log).map(|_| ()), Err(wrong));
        assert_eq!(map.create_xdp_link(9, 4).map(|_| ()), Err(wrong));
        assert_eq!(
            program.create_xdp_link(0, 4).map(|_| ()),
            Err(ResourceError::Argument(
                SyscallArgumentError::BpfArgumentOutOfRange
            ))
        );
        assert_eq!(
            map.load_redirect_program(&mut [0_u8; 127]).map(|_| ()),
            Err(ResourceError::Argument(
                SyscallArgumentError::VerifierLogLength { length: 127 }
            ))
        );
        assert_eq!(
            OwnedBpfFd::create_xskmap(&syscalls, 0).map(|_| ()),
            Err(ResourceError::Argument(
                SyscallArgumentError::BpfArgumentOutOfRange
            ))
        );
        assert_eq!(syscalls.transcript.borrow().len, baseline);

        drop(link);
        drop(program);
        let mut map = map;
        map.close_once().expect("first close");
        map.close_once().expect("idempotent close");
        drop(map);
        drop(socket);
        assert_eq!(
            syscalls.transcript.borrow().as_slice(),
            &[
                Some(Call::Socket {
                    domain: 44,
                    kind: XDP_SOCKET_KIND,
                    protocol: 0,
                }),
                Some(Call::BpfMapCreate { max_entries: 4 }),
                Some(Call::BpfProgLoad {
                    insn_cnt: REDIRECT_PROGRAM_LEN,
                    map_fd: 30,
                    log_len: 128,
                }),
                Some(Call::BpfMapUpdate {
                    map_fd: 30,
                    key: 3,
                    value: 17,
                }),
                Some(Call::BpfLinkCreate {
                    prog_fd: 31,
                    ifindex: 9,
                    flags: 4,
                }),
                Some(Call::Close { fd: 32 }),
                Some(Call::Close { fd: 31 }),
                Some(Call::Close { fd: 30 }),
                Some(Call::Close { fd: 17 }),
            ]
        );

        // Failed creation adopts nothing; a failed close is never retried.
        for (stage, closes) in [
            (SyscallStage::CreateBpfMap, 0),
            (SyscallStage::LoadBpfProgram, 1),
            (SyscallStage::CreateBpfLink, 2),
        ] {
            let syscalls = FakeSyscalls::new();
            syscalls.fail.set(Some(stage));
            let error = OwnedBpfFd::create_xskmap(&syscalls, 1).and_then(|map| {
                map.load_redirect_program(&mut [0_u8; 128])
                    .and_then(|program| program.create_xdp_link(1, 2))
                    .map(|_| ())
            });
            assert_eq!(
                error,
                Err(ResourceError::Syscall(SyscallError {
                    stage,
                    errno: TEST_ERRNO,
                })),
                "{stage:?}"
            );
            assert_eq!(
                syscalls.count(|call| matches!(call, Call::Close { .. })),
                closes,
                "{stage:?}"
            );
        }
        let syscalls = FakeSyscalls::new();
        let mut map = OwnedBpfFd::create_xskmap(&syscalls, 1).expect("fake map");
        syscalls.fail.set(Some(SyscallStage::CloseBpfObject));
        assert!(map.close_once().is_err());
        assert_eq!(map.close_once(), Ok(()));
        drop(map);
        assert_eq!(syscalls.count(|call| matches!(call, Call::Close { .. })), 1);
    }

    #[test]
    fn native_bpf_linux_seam_rejects_inconsistent_arguments_before_ffi() {
        // Every rejection returns before `syscall(SYS_bpf)`; fd -1 and the
        // empty or oversized buffers below never reach the kernel.
        let linux = LinuxSyscalls;
        let name = [0_u8; BPF_OBJ_NAME_LEN];
        assert_eq!(
            linux.bpf_map_create(&MapCreateRequest {
                max_entries: 0,
                name,
            }),
            Err(Errno::ArgumentRejected)
        );
        assert_eq!(
            linux.bpf_map_create(&MapCreateRequest {
                max_entries: 1,
                name: [b'a'; BPF_OBJ_NAME_LEN],
            }),
            Err(Errno::ArgumentRejected)
        );
        let program = redirect_program(3);
        let oversized = vec![program[0]; bpf::BPF_MAXINSNS + 1];
        let mut license_bytes = [b'L'; 130];
        license_bytes[129] = 0;
        let long_license = CStr::from_bytes_with_nul(&license_bytes).expect("129 bytes plus NUL");
        for (insns, license, name, log_len) in [
            (&program[..0], PROGRAM_LICENSE, PROGRAM_NAME, 128),
            (&oversized[..], PROGRAM_LICENSE, PROGRAM_NAME, 128),
            (&program[..], long_license, PROGRAM_NAME, 128),
            (&program[..], PROGRAM_LICENSE, [b'a'; 16], 128),
            (&program[..], PROGRAM_LICENSE, PROGRAM_NAME, 127),
        ] {
            let mut log = [0_u8; 128];
            let mut request = ProgramLoadRequest {
                insns,
                license,
                name,
                log: &mut log[..log_len],
            };
            assert_eq!(
                linux.bpf_prog_load(&mut request),
                Err(Errno::ArgumentRejected)
            );
        }
        assert_eq!(linux.bpf_map_update(-1, 0, 3), Err(Errno::ArgumentRejected));
        assert_eq!(linux.bpf_map_update(3, 0, -1), Err(Errno::ArgumentRejected));
        assert_eq!(
            linux.bpf_link_create(-1, 1, 4),
            Err(Errno::ArgumentRejected)
        );
        assert_eq!(linux.bpf_link_create(3, 0, 4), Err(Errno::ArgumentRejected));
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
}
