#![allow(dead_code, unsafe_code)]
//! Private Linux syscall and RAII foundation for future AF_XDP resource setup.
//!
//! C2A deliberately has no public constructor and performs no UMEM
//! registration, ring configuration, bind transaction, or packet I/O. The
//! generic syscall boundary is sealed and statically dispatched so NIC-free
//! tests can inject a finite transcript without adding a virtual call to the
//! future data path.

use std::{
    ffi::{c_int, c_short, c_void},
    fmt,
    os::fd::RawFd,
};

use crate::abi::AF_XDP;

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

type SockLen = u32;
type Offset = i64;
type PollCount = usize;

/// Largest positive errno encoded by the reviewed Linux syscall ABI.
const MAX_LINUX_ERRNO: i32 = 4_095;

/// Bounded positive Linux errno value.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Errno {
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

    pub(super) const fn raw(self) -> Option<u16> {
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
pub(super) enum SyscallStage {
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
pub(super) struct SyscallError {
    pub(super) stage: SyscallStage,
    pub(super) errno: Errno,
}

/// Checked argument failure detected before entering libc.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SyscallArgumentError {
    InvalidFileDescriptor,
    ZeroLength { stage: SyscallStage },
    LengthDoesNotFitSockLen { stage: SyscallStage, length: usize },
    OffsetDoesNotFitOffT { offset: u64 },
    KernelLengthOutOfBounds { capacity: usize, actual: usize },
}

/// Fixed-size error from the private syscall/RAII seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ResourceError {
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

mod sealed {
    pub trait Sealed {}
}

/// Sealed cold-path boundary; generic users are monomorphized, never dynamic.
pub(super) trait Syscalls: sealed::Sealed {
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
    fn close(&self, fd: RawFd) -> Result<(), Errno>;
}

/// Production Linux implementation. No C2A public API invokes it.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct LinuxSyscalls;

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

    fn close(&self, fd: RawFd) -> Result<(), Errno> {
        // SAFETY: `OwnedXdpFd` transfers each nonnegative owned fd here at most
        // once. Close is deliberately not retried after an error because the
        // numeric fd may already have been released and reused.
        let result = unsafe { ffi::close(fd) };
        result_from_minus_one(result).map(|_| ())
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

/// Owned nonnegative AF_XDP fd with exactly-once close semantics.
pub(super) struct OwnedXdpFd<'syscalls, S: Syscalls> {
    syscalls: &'syscalls S,
    fd: Option<RawFd>,
}

impl<'syscalls, S: Syscalls> OwnedXdpFd<'syscalls, S> {
    pub(super) fn open(syscalls: &'syscalls S) -> Result<Self, ResourceError> {
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

/// One owned mmap result. Address zero is a valid stored success.
pub(super) struct MappedRegion<'syscalls, S: Syscalls> {
    syscalls: &'syscalls S,
    address: *mut c_void,
    byte_len: usize,
    active: bool,
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

    fn unmap_once(&mut self) -> Result<(), ResourceError> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        self.syscalls
            .munmap(self.address, self.byte_len)
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
    use super::{c_int, c_short, c_void, Offset, PollCount, SockLen};

    #[repr(C)]
    pub(super) struct PollFd {
        pub(super) fd: c_int,
        pub(super) events: c_short,
        pub(super) revents: c_short,
    }

    // SAFETY: these declarations exactly match the reviewed 64-bit Linux libc
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

        fn close(&self, fd: RawFd) -> Result<(), Errno> {
            self.record(Call::Close { fd });
            self.result(SyscallStage::CloseSocket)
        }
    }

    fn assert_static_syscalls<T: Syscalls>() {}

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
}
