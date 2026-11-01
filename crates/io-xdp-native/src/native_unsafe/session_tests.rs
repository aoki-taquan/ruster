#![allow(unsafe_code)]
//! Finite-fake failure injection for the X00C session transaction.
//!
//! The fake implements the sealed syscall seam with a bounded transcript, a
//! fixed table of real page-aligned arena mappings (so ring views built on
//! them are exercised for real), and exact fd/mapping accounting that
//! detects leaks and double releases.

use std::{
    alloc::{alloc_zeroed, dealloc, Layout},
    cell::{Cell, RefCell},
    ffi::{c_int, c_void},
    os::fd::RawFd,
};

use super::{
    session::{classify, SessionCore},
    syscall::{
        errno, sealed, Errno, MapRequest, MapsRealMemory, PollDescriptor, ResourceError,
        SyscallArgumentError, SyscallError, SyscallStage, Syscalls, IFNAMSIZ, PAGE_SIZE,
    },
};
use crate::{
    abi::{
        XdpMmapOffsets, XdpRingOffset, AF_XDP, SOL_XDP, XDP_COPY, XDP_MMAP_OFFSETS, XDP_OPTIONS,
        XDP_PGOFF_RX_RING, XDP_PGOFF_TX_RING, XDP_RX_RING, XDP_TX_RING, XDP_UMEM_COMPLETION_RING,
        XDP_UMEM_FILL_RING, XDP_UMEM_PGOFF_COMPLETION_RING, XDP_UMEM_PGOFF_FILL_RING, XDP_UMEM_REG,
        XDP_USE_NEED_WAKEUP, XDP_ZEROCOPY,
    },
    AbiLayoutError, CleanupStage, NativeSyscallPlatformError, NeedWakeup, NegotiatedMode,
    RingConfig, RingField, RingMapError, RingName, SessionConfig, SessionError, SessionFailure,
    SessionStage, UmemConfig, ValidatedBindFlags,
};

const FAKE_FD: RawFd = 17;
const FAKE_IFINDEX: u32 = 7;
const MAX_CALLS: usize = 64;
const SOCKET_KIND: c_int = 3 | 0x800 | 0x8_0000;
const OPTION_BYTES: usize = 32;

/// Linux v6.8 x86_64 `struct xdp_ring` offsets with 64-byte cache lines.
const KERNEL_RING: XdpRingOffset = XdpRingOffset {
    producer: 0,
    consumer: 128,
    flags: 196,
    descriptors: 320,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Call {
    InterfaceIndex {
        name: [u8; IFNAMSIZ],
    },
    Socket {
        domain: c_int,
        kind: c_int,
        protocol: c_int,
    },
    MapAnonymous {
        len: usize,
    },
    MapShared {
        len: usize,
        offset: i64,
    },
    /// Releases the mapping created by call `map_call` (1-based ordinal).
    Unmap {
        map_call: usize,
        len: usize,
    },
    SetOption {
        level: c_int,
        name: c_int,
        len: u32,
        value: [u8; OPTION_BYTES],
    },
    GetOption {
        level: c_int,
        name: c_int,
        capacity: u32,
    },
    Bind {
        len: u32,
        address: [u8; 16],
    },
    Close {
        fd: RawFd,
    },
}

#[derive(Clone, Copy)]
struct Mapping {
    base: *mut u8,
    layout: Layout,
    returned: usize,
    len: usize,
    live: bool,
}

struct SessionFake {
    calls: RefCell<[Option<Call>; MAX_CALLS]>,
    len: Cell<usize>,
    mappings: RefCell<[Option<Mapping>; MAX_CALLS]>,
    fail_at: Cell<Option<(usize, Errno)>>,
    also_fail_at: Cell<Option<(usize, Errno)>>,
    zero_copy_bind_errno: Cell<Option<u16>>,
    misalign_call: Cell<Option<usize>>,
    offsets: Cell<XdpMmapOffsets>,
    offsets_len: Cell<u32>,
    options_len: Cell<u32>,
    options_override: Cell<Option<u32>>,
    bound_flags: Cell<u16>,
    open_fds: Cell<u32>,
    double_releases: Cell<u32>,
}

impl SessionFake {
    fn new() -> Self {
        Self {
            calls: RefCell::new([None; MAX_CALLS]),
            len: Cell::new(0),
            mappings: RefCell::new([None; MAX_CALLS]),
            fail_at: Cell::new(None),
            also_fail_at: Cell::new(None),
            zero_copy_bind_errno: Cell::new(None),
            misalign_call: Cell::new(None),
            offsets: Cell::new(XdpMmapOffsets {
                rx: KERNEL_RING,
                tx: KERNEL_RING,
                fill: KERNEL_RING,
                completion: KERNEL_RING,
            }),
            offsets_len: Cell::new(128),
            options_len: Cell::new(4),
            options_override: Cell::new(None),
            bound_flags: Cell::new(0),
            open_fds: Cell::new(0),
            double_releases: Cell::new(0),
        }
    }

    fn failing_at(ordinal: usize, raw: u16) -> Self {
        let fake = Self::new();
        fake.fail_at.set(Some((ordinal, Errno::Linux(raw))));
        fake
    }

    /// Records one call and returns its ordinal and injected result.
    fn record(&self, call: Call) -> (usize, Result<(), Errno>) {
        let ordinal = self.len.get() + 1;
        assert!(ordinal <= MAX_CALLS, "finite transcript capacity exceeded");
        self.calls.borrow_mut()[ordinal - 1] = Some(call);
        self.len.set(ordinal);
        let result = match (self.fail_at.get(), self.also_fail_at.get()) {
            (Some((at, errno)), _) | (_, Some((at, errno))) if at == ordinal => Err(errno),
            _ => Ok(()),
        };
        (ordinal, result)
    }

    fn transcript(&self) -> Vec<Call> {
        self.calls.borrow()[..self.len.get()]
            .iter()
            .map(|call| call.expect("recorded"))
            .collect()
    }

    fn live_mappings(&self) -> usize {
        self.mappings
            .borrow()
            .iter()
            .flatten()
            .filter(|mapping| mapping.live)
            .count()
    }

    fn assert_released(&self) {
        assert_eq!(self.live_mappings(), 0, "leaked mapping");
        assert_eq!(self.open_fds.get(), 0, "leaked fd");
        assert_eq!(self.double_releases.get(), 0, "double release");
    }

    fn mapping_base(&self, map_call: usize) -> *mut u8 {
        let mapping = self.mappings.borrow()[map_call - 1].expect("mapping exists");
        mapping.returned as *mut u8
    }

    fn map(&self, call: Call, len: usize) -> Result<*mut c_void, Errno> {
        let (ordinal, result) = self.record(call);
        result?;
        let rounded = len.next_multiple_of(PAGE_SIZE) + PAGE_SIZE;
        let layout = Layout::from_size_align(rounded, PAGE_SIZE).expect("bounded test layout");
        // SAFETY: `layout` has nonzero size and a valid power-of-two
        // alignment. The block is released only in `Drop`.
        let base = unsafe { alloc_zeroed(layout) };
        assert!(!base.is_null(), "test arena allocation");
        let returned = if self.misalign_call.get() == Some(ordinal) {
            base.addr() + 64
        } else {
            base.addr()
        };
        self.mappings.borrow_mut()[ordinal - 1] = Some(Mapping {
            base,
            layout,
            returned,
            len,
            live: true,
        });
        Ok(base
            .wrapping_byte_add(returned - base.addr())
            .cast::<c_void>())
    }
}

impl Drop for SessionFake {
    fn drop(&mut self) {
        for mapping in self.mappings.get_mut().iter().flatten() {
            // SAFETY: each block was returned by `alloc_zeroed` with exactly
            // this layout and is deallocated once here, after every session
            // borrowing the fake has ended.
            unsafe { dealloc(mapping.base, mapping.layout) };
        }
    }
}

impl sealed::Sealed for SessionFake {}

// SAFETY: every successful `mmap` returns an address inside a live,
// zero-initialized, page-aligned heap block with at least `byte_len` bytes
// after it (the block adds one spare page for the misalignment probe). No
// Rust reference to a block exists, and blocks stay allocated until the fake
// drops, which outlives every borrowing `MappedRegion` and ring view.
unsafe impl MapsRealMemory for SessionFake {}

impl Syscalls for SessionFake {
    fn interface_index(&self, name: &[u8; IFNAMSIZ]) -> Result<u32, Errno> {
        self.record(Call::InterfaceIndex { name: *name })
            .1
            .map(|()| FAKE_IFINDEX)
    }

    fn socket(&self, domain: c_int, kind: c_int, protocol: c_int) -> Result<RawFd, Errno> {
        self.record(Call::Socket {
            domain,
            kind,
            protocol,
        })
        .1?;
        self.open_fds.set(self.open_fds.get() + 1);
        Ok(FAKE_FD)
    }

    fn set_socket_option(
        &self,
        _fd: RawFd,
        level: c_int,
        name: c_int,
        value: &[u8],
        length: u32,
    ) -> Result<(), Errno> {
        let mut bytes = [0_u8; OPTION_BYTES];
        bytes[..value.len()].copy_from_slice(value);
        self.record(Call::SetOption {
            level,
            name,
            len: length,
            value: bytes,
        })
        .1
    }

    fn get_socket_option(
        &self,
        _fd: RawFd,
        level: c_int,
        name: c_int,
        value: &mut [u8],
        length: &mut u32,
    ) -> Result<(), Errno> {
        self.record(Call::GetOption {
            level,
            name,
            capacity: *length,
        })
        .1?;
        match name {
            XDP_MMAP_OFFSETS => {
                let offsets = self.offsets.get();
                for (index, ring) in [offsets.rx, offsets.tx, offsets.fill, offsets.completion]
                    .into_iter()
                    .enumerate()
                {
                    let base = index * 32;
                    for (field, word) in
                        [ring.producer, ring.consumer, ring.descriptors, ring.flags]
                            .into_iter()
                            .enumerate()
                    {
                        let at = base + field * 8;
                        value[at..at + 8].copy_from_slice(&word.to_ne_bytes());
                    }
                }
                *length = self.offsets_len.get();
            }
            XDP_OPTIONS => {
                let negotiated = self.options_override.get().unwrap_or(
                    if self.bound_flags.get() & XDP_ZEROCOPY != 0 {
                        1
                    } else {
                        0
                    },
                );
                value[..4].copy_from_slice(&negotiated.to_ne_bytes());
                *length = self.options_len.get();
            }
            _ => panic!("unexpected getsockopt {name}"),
        }
        Ok(())
    }

    fn mmap(&self, request: MapRequest) -> Result<*mut c_void, Errno> {
        match request {
            MapRequest::Anonymous { byte_len } => {
                self.map(Call::MapAnonymous { len: byte_len }, byte_len)
            }
            MapRequest::Shared {
                fd,
                byte_len,
                offset,
            } => {
                assert_eq!(fd, FAKE_FD);
                self.map(
                    Call::MapShared {
                        len: byte_len,
                        offset,
                    },
                    byte_len,
                )
            }
        }
    }

    fn munmap(&self, address: *mut c_void, byte_len: usize) -> Result<(), Errno> {
        let map_call = self
            .mappings
            .borrow()
            .iter()
            .position(|mapping| {
                mapping.is_some_and(|mapping| {
                    mapping.returned == address.addr() && mapping.len == byte_len
                })
            })
            .map(|index| index + 1)
            .expect("munmap of an exact mapping");
        let (_, result) = self.record(Call::Unmap {
            map_call,
            len: byte_len,
        });
        let mut mappings = self.mappings.borrow_mut();
        let mapping = mappings[map_call - 1].as_mut().expect("mapping exists");
        if !mapping.live {
            self.double_releases.set(self.double_releases.get() + 1);
        }
        // Linux removes the mapping even when reporting some errors; the
        // seam never retries, so treat every attempt as the release.
        mapping.live = false;
        result
    }

    fn bind(&self, _fd: RawFd, address: &[u8], length: u32) -> Result<(), Errno> {
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(address);
        let (_, result) = self.record(Call::Bind {
            len: length,
            address: bytes,
        });
        result?;
        let flags = u16::from_ne_bytes([bytes[2], bytes[3]]);
        if flags & XDP_ZEROCOPY != 0 {
            if let Some(raw) = self.zero_copy_bind_errno.get() {
                return Err(Errno::Linux(raw));
            }
        }
        self.bound_flags.set(flags);
        Ok(())
    }

    fn poll(&self, _descriptor: &mut PollDescriptor, _timeout_millis: c_int) -> Result<u32, Errno> {
        panic!("session setup never polls")
    }

    fn send_to_wakeup(&self, _fd: RawFd) -> Result<(), Errno> {
        panic!("session setup never kicks")
    }

    fn close(&self, fd: RawFd) -> Result<(), Errno> {
        let (_, result) = self.record(Call::Close { fd });
        if self.open_fds.get() == 0 {
            self.double_releases.set(self.double_releases.get() + 1);
        } else {
            self.open_fds.set(self.open_fds.get() - 1);
        }
        result
    }
}

fn umem() -> UmemConfig {
    // 129 x 2048 bytes is not a page multiple, exercising the rounded map.
    UmemConfig::new(129, 2_048, 128, 65, 64, 0).expect("valid geometry")
}

fn config(mode_flag: u16) -> SessionConfig {
    SessionConfig::new(
        "veth0",
        3,
        ValidatedBindFlags::new(XDP_USE_NEED_WAKEUP | mode_flag).expect("valid flags"),
        RingConfig::new(64, 128, 64, 256).expect("valid rings"),
        umem(),
    )
    .expect("valid session config")
}

const UMEM_LEN: usize = 129 * 2_048;
const UMEM_MAP_LEN: usize = 65 * PAGE_SIZE;

fn name_bytes() -> [u8; IFNAMSIZ] {
    let mut name = [0_u8; IFNAMSIZ];
    name[..5].copy_from_slice(b"veth0");
    name
}

fn option(name: c_int, value: &[u8]) -> Call {
    let mut bytes = [0_u8; OPTION_BYTES];
    bytes[..value.len()].copy_from_slice(value);
    Call::SetOption {
        level: SOL_XDP,
        name,
        len: u32::try_from(value.len()).expect("small"),
        value: bytes,
    }
}

fn sockaddr(flags: u16) -> Call {
    let mut address = [0_u8; 16];
    address[0..2].copy_from_slice(&u16::try_from(AF_XDP).expect("fits").to_ne_bytes());
    address[2..4].copy_from_slice(&flags.to_ne_bytes());
    address[4..8].copy_from_slice(&FAKE_IFINDEX.to_ne_bytes());
    address[8..12].copy_from_slice(&3_u32.to_ne_bytes());
    Call::Bind { len: 16, address }
}

/// The exact transcript of one successful attempt after interface lookup.
fn attempt_calls(umem_address: usize, flags: u16) -> Vec<Call> {
    let mut reg = [0_u8; 32];
    reg[0..8].copy_from_slice(&(umem_address as u64).to_ne_bytes());
    reg[8..16].copy_from_slice(&(UMEM_LEN as u64).to_ne_bytes());
    reg[16..20].copy_from_slice(&2_048_u32.to_ne_bytes());
    reg[20..24].copy_from_slice(&128_u32.to_ne_bytes());
    vec![
        Call::Socket {
            domain: AF_XDP,
            kind: SOCKET_KIND,
            protocol: 0,
        },
        Call::MapAnonymous { len: UMEM_MAP_LEN },
        option(XDP_UMEM_REG, &reg),
        option(XDP_UMEM_FILL_RING, &64_u32.to_ne_bytes()),
        option(XDP_UMEM_COMPLETION_RING, &256_u32.to_ne_bytes()),
        option(XDP_RX_RING, &128_u32.to_ne_bytes()),
        option(XDP_TX_RING, &64_u32.to_ne_bytes()),
        Call::GetOption {
            level: SOL_XDP,
            name: XDP_MMAP_OFFSETS,
            capacity: 128,
        },
        Call::MapShared {
            len: 320 + 64 * 8,
            offset: XDP_UMEM_PGOFF_FILL_RING as i64,
        },
        Call::MapShared {
            len: 320 + 256 * 8,
            offset: XDP_UMEM_PGOFF_COMPLETION_RING as i64,
        },
        Call::MapShared {
            len: 320 + 128 * 16,
            offset: XDP_PGOFF_RX_RING as i64,
        },
        Call::MapShared {
            len: 320 + 64 * 16,
            offset: XDP_PGOFF_TX_RING as i64,
        },
        sockaddr(flags),
        Call::GetOption {
            level: SOL_XDP,
            name: XDP_OPTIONS,
            capacity: 4,
        },
    ]
}

/// Stage expected for a failure injected at each 1-based call ordinal.
const STAGES: [SessionStage; 15] = [
    SessionStage::InterfaceLookup,
    SessionStage::OpenSocket,
    SessionStage::MapUmem,
    SessionStage::RegisterUmem,
    SessionStage::SizeFillRing,
    SessionStage::SizeCompletionRing,
    SessionStage::SizeRxRing,
    SessionStage::SizeTxRing,
    SessionStage::QueryMmapOffsets,
    SessionStage::MapFillRing,
    SessionStage::MapCompletionRing,
    SessionStage::MapRxRing,
    SessionStage::MapTxRing,
    SessionStage::Bind,
    SessionStage::QueryOptions,
];

/// Reverse cleanup of every resource acquired by `prefix`, where the call at
/// `failed` (1-based, if any) acquired nothing.
fn reverse_cleanup(prefix: &[Call], failed: Option<usize>) -> Vec<Call> {
    let mut cleanup = Vec::new();
    for (index, call) in prefix.iter().enumerate().rev() {
        if failed == Some(index + 1) {
            continue;
        }
        match *call {
            Call::Socket { .. } => cleanup.push(Call::Close { fd: FAKE_FD }),
            Call::MapAnonymous { len } | Call::MapShared { len, .. } => cleanup.push(Call::Unmap {
                map_call: index + 1,
                len,
            }),
            _ => {}
        }
    }
    cleanup
}

fn umem_address_of(fake: &SessionFake) -> usize {
    fake.mapping_base(3).addr()
}

fn full_success_calls(fake: &SessionFake, flags: u16) -> Vec<Call> {
    let mut calls = vec![Call::InterfaceIndex { name: name_bytes() }];
    calls.extend(attempt_calls(umem_address_of(fake), flags));
    calls
}

/// Asserts the transcript is `prefix` followed by its exact reverse cleanup
/// and that nothing leaked or was released twice.
fn assert_atomic(fake: &SessionFake, prefix: &[Call], failed: Option<usize>) {
    let mut expected = prefix.to_vec();
    expected.extend(reverse_cleanup(prefix, failed));
    assert_eq!(fake.transcript(), expected);
    fake.assert_released();
}

fn copy_flags() -> u16 {
    XDP_USE_NEED_WAKEUP | XDP_COPY
}

fn read_cursor(base: *mut u8, offset: usize) -> u32 {
    // SAFETY: `base` is the start of a live arena block owned by the fake
    // with at least `offset + 4` bytes; the session's views have ended, so
    // this volatile read does not race with any Rust access.
    unsafe { base.add(offset).cast::<u32>().read_volatile() }
}

#[test]
fn native_session_open_is_exact_and_teardown_is_reverse() {
    let fake = SessionFake::new();
    let flags = copy_flags();
    {
        let mut session = SessionCore::open(&fake, &config(XDP_COPY)).expect("session opens");
        assert_eq!(session.mode(), NegotiatedMode::Copy);
        assert!(!session.zero_copy_fallback());
        assert_eq!((session.ifindex(), session.queue()), (FAKE_IFINDEX, 3));
        assert_eq!(fake.transcript(), full_success_calls(&fake, flags));
        assert_eq!(fake.live_mappings(), 5);
        assert_eq!(fake.open_fds.get(), 1);

        let mut rings = session.rings().expect("ring views");
        assert_eq!(
            (
                rings.fill.capacity(),
                rings.completion.capacity(),
                rings.rx.capacity(),
                rings.tx.capacity(),
            ),
            (64, 256, 128, 64)
        );
        assert_eq!(rings.umem.byte_len(), UMEM_LEN as u64);
        assert_eq!(rings.umem.config(), umem());
        let mut fill = rings.fill.reserve(2).expect("empty Fill ring");
        fill.write(0).expect("first frame");
        fill.write(2_048).expect("second frame");
        assert_eq!(
            fill.release_submit().expect("published").need_wakeup(),
            Ok(NeedWakeup::NotRequired)
        );
        assert_eq!(
            rings.rx.acquire(1).map(|_| ()),
            Err(crate::NativeRingError::RingEmpty)
        );
        // The views end here (NLL); the session borrow is released.
        // The Fill producer cursor was Release-published into the real
        // mapping created by call 10, and the descriptors follow it.
        let fill_base = fake.mapping_base(10);
        assert_eq!(read_cursor(fill_base, 0), 2);
        assert_eq!(read_cursor(fill_base, 320 + 8), 2_048);
        // A second, sequential borrow rebuilds the views over the same rings.
        assert_eq!(
            session
                .rings()
                .expect("ring views")
                .fill
                .reserve(62)
                .map(|reservation| reservation.release_cancel()),
            Ok(())
        );
    }
    let calls = full_success_calls(&fake, flags);
    assert_atomic(&fake, &calls, None);
    // Teardown order: TX, RX, Completion, Fill, UMEM, socket.
    assert_eq!(
        &fake.transcript()[calls.len()..],
        &[
            Call::Unmap {
                map_call: 13,
                len: 320 + 64 * 16
            },
            Call::Unmap {
                map_call: 12,
                len: 320 + 128 * 16
            },
            Call::Unmap {
                map_call: 11,
                len: 320 + 256 * 8
            },
            Call::Unmap {
                map_call: 10,
                len: 320 + 64 * 8
            },
            Call::Unmap {
                map_call: 3,
                len: UMEM_MAP_LEN
            },
            Call::Close { fd: FAKE_FD },
        ]
    );
}

#[test]
fn native_session_failure_at_every_step_releases_in_exact_reverse_order() {
    let reference = SessionFake::new();
    drop(SessionCore::open(&reference, &config(XDP_COPY)).expect("reference session"));
    let success = full_success_calls(&reference, copy_flags());
    assert_eq!(success.len(), STAGES.len());

    for (index, stage) in STAGES.iter().copied().enumerate() {
        let ordinal = index + 1;
        let fake = SessionFake::failing_at(ordinal, 1_000);
        let error = SessionCore::open(&fake, &config(XDP_COPY))
            .map(|_| ())
            .expect_err("injected failure");
        assert_eq!(
            error,
            SessionError::new(stage, SessionFailure::Errno(1_000)),
            "ordinal {ordinal}"
        );
        // The UMEM address differs per fake; rebuild the prefix with it.
        let mut prefix = vec![Call::InterfaceIndex { name: name_bytes() }];
        let umem_address = if ordinal > 3 {
            umem_address_of(&fake)
        } else {
            0
        };
        prefix.extend(attempt_calls(umem_address, copy_flags()));
        prefix.truncate(ordinal);
        assert_atomic(&fake, &prefix, Some(ordinal));
    }
}

#[test]
fn native_session_cleanup_failures_never_retry_or_leak() {
    // Every teardown call may fail; later resources are still released once.
    for teardown in 0..6 {
        let fake = SessionFake::new();
        let session = SessionCore::open(&fake, &config(XDP_COPY)).expect("session");
        let ordinal = STAGES.len() + 1 + teardown;
        fake.fail_at
            .set(Some((ordinal, Errno::Linux(errno::EINVAL))));
        let error = session.close().expect_err("injected cleanup failure");
        let expected = [
            CleanupStage::UnmapTxRing,
            CleanupStage::UnmapRxRing,
            CleanupStage::UnmapCompletionRing,
            CleanupStage::UnmapFillRing,
            CleanupStage::UnmapUmem,
            CleanupStage::CloseSocket,
        ][teardown];
        assert_eq!(
            (error.stage(), error.errno()),
            (expected, Some(errno::EINVAL))
        );
        let calls = full_success_calls(&fake, copy_flags());
        assert_atomic(&fake, &calls, None);
    }

    // Explicit close without failures is Ok and identical to Drop.
    let fake = SessionFake::new();
    let session = SessionCore::open(&fake, &config(XDP_COPY)).expect("session");
    assert_eq!(session.close(), Ok(()));
    assert_atomic(&fake, &full_success_calls(&fake, copy_flags()), None);

    // A failing munmap while unwinding a failed open does not stop later
    // releases and is not retried.
    let fake = SessionFake::new();
    fake.fail_at.set(Some((14, Errno::Linux(errno::EBUSY))));
    fake.also_fail_at
        .set(Some((16, Errno::Linux(errno::EINVAL))));
    let error = SessionCore::open(&fake, &config(XDP_COPY))
        .map(|_| ())
        .expect_err("bind fails");
    assert_eq!(
        error,
        SessionError::new(SessionStage::Bind, SessionFailure::Busy)
    );
    let mut prefix = full_success_calls(&fake, copy_flags());
    prefix.truncate(14);
    assert_atomic(&fake, &prefix, Some(14));
}

#[test]
fn native_session_kernel_reports_are_validated_fail_closed() {
    type Probe = fn(&SessionFake);
    let cases: [(Probe, usize, SessionStage, SessionFailure); 10] = [
        (
            |fake| fake.offsets_len.set(96),
            9,
            SessionStage::QueryMmapOffsets,
            SessionFailure::OptionLength {
                expected: 128,
                actual: 96,
            },
        ),
        (
            |fake| {
                let mut offsets = fake.offsets.get();
                offsets.rx.consumer = 2;
                fake.offsets.set(offsets);
            },
            9,
            SessionStage::QueryMmapOffsets,
            SessionFailure::RingLayout {
                ring: RingName::Rx,
                error: RingMapError::Layout(AbiLayoutError::MisalignedOffset {
                    field: RingField::Consumer,
                    offset: 2,
                    alignment: 4,
                }),
            },
        ),
        (
            |fake| {
                let mut offsets = fake.offsets.get();
                offsets.tx.flags = 0;
                fake.offsets.set(offsets);
            },
            9,
            SessionStage::QueryMmapOffsets,
            SessionFailure::RingLayout {
                ring: RingName::Tx,
                error: RingMapError::Layout(AbiLayoutError::OverlappingFields {
                    first: RingField::Producer,
                    second: RingField::Flags,
                }),
            },
        ),
        (
            |fake| {
                let mut offsets = fake.offsets.get();
                offsets.fill.descriptors = 4_104;
                fake.offsets.set(offsets);
            },
            9,
            SessionStage::QueryMmapOffsets,
            SessionFailure::RingHeaderOutOfBounds {
                ring: RingName::Fill,
                field: RingField::Descriptors,
            },
        ),
        (
            |fake| {
                let mut offsets = fake.offsets.get();
                offsets.completion.producer = u64::MAX - 3;
                fake.offsets.set(offsets);
            },
            9,
            SessionStage::QueryMmapOffsets,
            SessionFailure::RingHeaderOutOfBounds {
                ring: RingName::Completion,
                field: RingField::Producer,
            },
        ),
        (
            |fake| fake.misalign_call.set(Some(3)),
            3,
            SessionStage::MapUmem,
            SessionFailure::MisalignedMapping,
        ),
        (
            |fake| fake.misalign_call.set(Some(12)),
            12,
            SessionStage::MapRxRing,
            SessionFailure::MisalignedMapping,
        ),
        (
            |fake| fake.options_len.set(2),
            15,
            SessionStage::QueryOptions,
            SessionFailure::OptionLength {
                expected: 4,
                actual: 2,
            },
        ),
        (
            |fake| fake.options_override.set(Some(0b110)),
            15,
            SessionStage::QueryOptions,
            SessionFailure::UnsupportedOptions(0b110),
        ),
        (
            |fake| fake.options_override.set(Some(1)),
            15,
            SessionStage::QueryOptions,
            SessionFailure::NegotiatedModeMismatch {
                negotiated: NegotiatedMode::ZeroCopy,
            },
        ),
    ];
    for (probe, last_call, stage, failure) in cases {
        let fake = SessionFake::new();
        probe(&fake);
        let error = SessionCore::open(&fake, &config(XDP_COPY))
            .map(|_| ())
            .expect_err("kernel report rejected");
        assert_eq!(error, SessionError::new(stage, failure));
        let umem_address = fake.mappings.borrow()[2].map_or(0, |mapping| mapping.returned);
        let mut prefix = vec![Call::InterfaceIndex { name: name_bytes() }];
        prefix.extend(attempt_calls(umem_address, copy_flags()));
        prefix.truncate(last_call);
        if stage == SessionStage::MapUmem {
            // The misaligned UMEM is never registered.
            assert_eq!(prefix.len(), 3);
        }
        assert_atomic(&fake, &prefix, None);
    }

    // A zero-copy bind that negotiates copy is equally a mismatch.
    let fake = SessionFake::new();
    fake.options_override.set(Some(0));
    assert_eq!(
        SessionCore::open(&fake, &config(XDP_ZEROCOPY))
            .map(|_| ())
            .expect_err("mismatch"),
        SessionError::new(
            SessionStage::QueryOptions,
            SessionFailure::NegotiatedModeMismatch {
                negotiated: NegotiatedMode::Copy,
            }
        )
    );
    fake.assert_released();
}

#[test]
fn native_session_errnos_map_to_typed_value_free_failures() {
    let syscall = |raw: u16| {
        ResourceError::Syscall(SyscallError {
            stage: SyscallStage::OpenSocket,
            errno: Errno::Linux(raw),
        })
    };
    let cases = [
        (
            SessionStage::OpenSocket,
            errno::EPERM,
            false,
            SessionFailure::PermissionDenied,
        ),
        (
            SessionStage::OpenSocket,
            errno::EACCES,
            false,
            SessionFailure::PermissionDenied,
        ),
        (
            SessionStage::OpenSocket,
            errno::EAFNOSUPPORT,
            false,
            SessionFailure::Unsupported,
        ),
        (
            SessionStage::MapUmem,
            errno::ENOMEM,
            false,
            SessionFailure::OutOfMemory,
        ),
        (
            SessionStage::RegisterUmem,
            errno::ENOBUFS,
            false,
            SessionFailure::MemlockLimit,
        ),
        (
            SessionStage::RegisterUmem,
            errno::ENOMEM,
            false,
            SessionFailure::OutOfMemory,
        ),
        (
            SessionStage::SizeRxRing,
            errno::ENOBUFS,
            false,
            SessionFailure::Errno(errno::ENOBUFS),
        ),
        (
            SessionStage::InterfaceLookup,
            errno::ENODEV,
            false,
            SessionFailure::NoSuchDevice,
        ),
        (
            SessionStage::Bind,
            errno::ENODEV,
            false,
            SessionFailure::NoSuchDevice,
        ),
        (
            SessionStage::Bind,
            errno::EINVAL,
            true,
            SessionFailure::InvalidArgument,
        ),
        (
            SessionStage::Bind,
            errno::EBUSY,
            false,
            SessionFailure::Busy,
        ),
        (
            SessionStage::Bind,
            errno::EOPNOTSUPP,
            true,
            SessionFailure::ZeroCopyUnsupported,
        ),
        (
            SessionStage::Bind,
            errno::EOPNOTSUPP,
            false,
            SessionFailure::Unsupported,
        ),
        (
            SessionStage::QueryOptions,
            errno::EOPNOTSUPP,
            true,
            SessionFailure::Unsupported,
        ),
        (SessionStage::Bind, 98, false, SessionFailure::Errno(98)),
    ];
    for (stage, raw, zero_copy_bind, failure) in cases {
        assert_eq!(
            classify(stage, syscall(raw), zero_copy_bind),
            SessionError::new(stage, failure),
            "{stage:?} errno {raw}"
        );
    }
    assert_eq!(
        classify(
            SessionStage::Bind,
            ResourceError::Syscall(SyscallError {
                stage: SyscallStage::BindSocket,
                errno: Errno::InvalidCapture,
            }),
            false,
        )
        .failure(),
        SessionFailure::UnreadableErrno
    );
    assert_eq!(
        classify(
            SessionStage::OpenSocket,
            ResourceError::Platform(NativeSyscallPlatformError::UnsupportedArchitecture),
            false,
        )
        .failure(),
        SessionFailure::Platform(NativeSyscallPlatformError::UnsupportedArchitecture)
    );
    assert_eq!(
        classify(
            SessionStage::MapUmem,
            ResourceError::Argument(SyscallArgumentError::InvalidInterfaceName),
            false,
        )
        .failure(),
        SessionFailure::ArgumentOutOfRange
    );

    // End to end through the fake: the failing stage selects the class.
    for (ordinal, raw, mode, failure) in [
        (1, errno::ENODEV, XDP_COPY, SessionFailure::NoSuchDevice),
        (2, errno::EPERM, XDP_COPY, SessionFailure::PermissionDenied),
        (4, errno::ENOBUFS, XDP_COPY, SessionFailure::MemlockLimit),
        (14, errno::EINVAL, XDP_COPY, SessionFailure::InvalidArgument),
        (14, errno::EBUSY, XDP_ZEROCOPY, SessionFailure::Busy),
        (
            14,
            errno::EOPNOTSUPP,
            XDP_ZEROCOPY,
            SessionFailure::ZeroCopyUnsupported,
        ),
        (14, errno::EOPNOTSUPP, XDP_COPY, SessionFailure::Unsupported),
    ] {
        let fake = SessionFake::failing_at(ordinal, raw);
        let error = SessionCore::open(&fake, &config(mode))
            .map(|_| ())
            .expect_err("injected");
        assert_eq!(error, SessionError::new(STAGES[ordinal - 1], failure));
        fake.assert_released();
    }
}

#[test]
fn native_session_auto_falls_back_to_copy_only_on_zero_copy_eopnotsupp() {
    let auto_zero_copy = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY;
    let auto_copy = XDP_USE_NEED_WAKEUP | XDP_COPY;

    // Zero-copy available: one attempt, no fallback.
    let fake = SessionFake::new();
    let session = SessionCore::open(&fake, &config(0)).expect("auto zero-copy");
    assert_eq!(
        (session.mode(), session.zero_copy_fallback()),
        (NegotiatedMode::ZeroCopy, false)
    );
    drop(session);
    assert_atomic(&fake, &full_success_calls(&fake, auto_zero_copy), None);

    // EOPNOTSUPP from the zero-copy bind: the first attempt is released in
    // exact reverse order before a fresh copy-mode attempt.
    let fake = SessionFake::new();
    fake.zero_copy_bind_errno.set(Some(errno::EOPNOTSUPP));
    let session = SessionCore::open(&fake, &config(0)).expect("auto copy fallback");
    assert_eq!(
        (session.mode(), session.zero_copy_fallback()),
        (NegotiatedMode::Copy, true)
    );
    let first_attempt = full_success_calls(&fake, auto_zero_copy)[..14].to_vec();
    let mut expected = first_attempt.clone();
    expected.extend(reverse_cleanup(&first_attempt, Some(14)));
    let second_start = expected.len();
    let second_umem = fake.mapping_base(second_start + 2).addr();
    let second = attempt_calls(second_umem, auto_copy);
    expected.extend(second.iter().copied());
    assert_eq!(fake.transcript(), expected);
    assert_eq!(fake.live_mappings(), 5);
    drop(session);
    assert_eq!(&fake.transcript()[..expected.len()], &expected[..]);
    let tail: Vec<usize> = fake.transcript()[expected.len()..]
        .iter()
        .map(|call| match call {
            Call::Unmap { map_call, .. } => *map_call,
            Call::Close { .. } => 0,
            other => panic!("unexpected teardown call {other:?}"),
        })
        .collect();
    assert_eq!(tail, [32, 31, 30, 29, 22, 0]);
    fake.assert_released();

    // Any other zero-copy bind failure fails closed without fallback.
    for (raw, failure) in [
        (errno::EINVAL, SessionFailure::InvalidArgument),
        (errno::EBUSY, SessionFailure::Busy),
        (errno::ENOMEM, SessionFailure::OutOfMemory),
    ] {
        let fake = SessionFake::new();
        fake.zero_copy_bind_errno.set(Some(raw));
        let error = SessionCore::open(&fake, &config(0))
            .map(|_| ())
            .expect_err("no fallback");
        assert_eq!(error, SessionError::new(SessionStage::Bind, failure));
        assert_eq!(
            fake.transcript()
                .iter()
                .filter(|call| matches!(call, Call::Socket { .. }))
                .count(),
            1
        );
        fake.assert_released();
    }

    // A required zero-copy session never falls back.
    let fake = SessionFake::new();
    fake.zero_copy_bind_errno.set(Some(errno::EOPNOTSUPP));
    assert_eq!(
        SessionCore::open(&fake, &config(XDP_ZEROCOPY))
            .map(|_| ())
            .expect_err("required zero-copy"),
        SessionError::new(SessionStage::Bind, SessionFailure::ZeroCopyUnsupported)
    );
    fake.assert_released();

    // A failure inside the fallback attempt is reported and fully released.
    let fake = SessionFake::new();
    fake.zero_copy_bind_errno.set(Some(errno::EOPNOTSUPP));
    // Call 23 is the fallback attempt's UMEM registration (1 lookup, 13
    // first-attempt calls, 6 releases, then socket and UMEM map).
    fake.fail_at.set(Some((23, Errno::Linux(errno::ENOBUFS))));
    assert_eq!(
        SessionCore::open(&fake, &config(0))
            .map(|_| ())
            .expect_err("fallback fails"),
        SessionError::new(SessionStage::RegisterUmem, SessionFailure::MemlockLimit)
    );
    fake.assert_released();
}
