//! AP3 scheduling tests over scripted syscalls: TX completion reaping in
//! the live entry points, owed-kick classification and backoff, generated
//! frames lent from the TX ring, publication quiescence, the completion
//! fault stop, the shutdown drain, the idle `poll` wait, kernel statistics,
//! live stats shape, and steady allocation.

use std::{
    alloc::{alloc_zeroed, dealloc, Layout},
    cell::RefCell,
    collections::VecDeque,
    ffi::c_int,
    os::fd::RawFd,
    ptr::NonNull,
    rc::Rc,
};

use ruster_core::{
    DropReason, FieldValue, FieldVisitor, GeneratedAllocationError, GeneratedPacketBatch, IfId,
    MonotonicMillis, ObservableFields, PacketBatch, PublicationQuiescenceDisposition,
};

use super::{AfPacketQuiescenceError, KICK_BACKOFF_MAX_MS};
use crate::sys::rx::RxFault;
use crate::{
    sys::{
        packet_io::AfPacketIoError, tests::allocation_count, AfPacketEngine, PacketOps, PollFd,
        SockaddrLl, TpacketStatsV3, TxCompletionError, POLLIN,
    },
    Errno, PlatformError, PortConfig, RingGeometry, RxWait, SyscallStage, ValidatedConfig,
    TP_STATUS_AVAILABLE, TP_STATUS_KERNEL, TP_STATUS_SENDING, TP_STATUS_SEND_REQUEST,
    TP_STATUS_USER,
};

const PAGE: usize = 4_096;
const RX_LEN: usize = 4_096;
const TX_FRAME: usize = 2_048;
const TX_FRAMES: usize = 4;
const FIRST_PACKET: usize = 64;
const MAC: usize = 82;
const FIRST_FD: RawFd = 100;
const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const UNKNOWN: IfId = IfId(9);
const EIO: i32 = 5;
const ENXIO: i32 = 6;
const EAGAIN: i32 = 11;
const ENETDOWN: i32 = 100;
const ENOBUFS: i32 = 105;

#[derive(Default)]
struct LiveState {
    next_fd: RawFd,
    mappings: Vec<(Addr, usize)>,
    kicks: Vec<(RawFd, Result<(), i32>)>,
    kick_errnos: VecDeque<i32>,
    persistent_kick_errno: Option<i32>,
    polls: Vec<([PollFd; 2], c_int)>,
    poll_script: VecDeque<Result<i16, i32>>,
    stats_script: VecDeque<Result<TpacketStatsV3, i32>>,
    /// `SO_ERROR` reads: the fd, and what the scripted read returned.
    socket_errors: Vec<(RawFd, Result<i32, i32>)>,
    socket_error_script: VecDeque<Result<i32, i32>>,
}

/// Scripted Linux stand-in. Kick records go into storage reserved up front,
/// so recording a kick never allocates while engine code runs.
#[derive(Clone)]
struct LiveOps(Rc<RefCell<LiveState>>);

impl PacketOps for LiveOps {
    fn open_socket(&mut self) -> Result<RawFd, PlatformError> {
        let mut state = self.0.borrow_mut();
        let fd = state.next_fd;
        state.next_fd += 1;
        Ok(fd)
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

    fn map(&mut self, _fd: RawFd, len: usize) -> Result<NonNull<u8>, PlatformError> {
        let layout = Layout::from_size_align(len, PAGE).expect("mapping layout");
        // SAFETY: nonzero size (the engine rejects zero-length mappings) and
        // a valid power-of-two alignment.
        let base = NonNull::new(unsafe { alloc_zeroed(layout) }).expect("test mapping");
        self.0
            .borrow_mut()
            .mappings
            .push((Addr(base.as_ptr()), len));
        Ok(base)
    }

    fn kick(&mut self, fd: RawFd) -> Result<(), PlatformError> {
        let mut state = self.0.borrow_mut();
        let result = match state.kick_errnos.pop_front() {
            Some(errno) => Err(errno),
            None => state.persistent_kick_errno.map_or(Ok(()), Err),
        };
        state.kicks.push((fd, result));
        result.map_err(|errno| PlatformError::Syscall {
            stage: SyscallStage::Kick,
            errno: Errno::new(errno),
        })
    }

    fn poll(&mut self, fds: &mut [PollFd], timeout_ms: c_int) -> Result<usize, PlatformError> {
        let mut state = self.0.borrow_mut();
        let recorded = [fds[0], fds[1]];
        state.polls.push((recorded, timeout_ms));
        match state.poll_script.pop_front() {
            None => Ok(0),
            Some(Ok(revents)) => {
                fds[1].revents = revents;
                Ok(usize::from(revents != 0))
            }
            Some(Err(errno)) => Err(PlatformError::Syscall {
                stage: SyscallStage::Poll,
                errno: Errno::new(errno),
            }),
        }
    }

    fn packet_statistics(&mut self, _fd: RawFd) -> Result<TpacketStatsV3, PlatformError> {
        match self.0.borrow_mut().stats_script.pop_front() {
            None => Ok(TpacketStatsV3::default()),
            Some(Ok(stats)) => Ok(stats),
            Some(Err(errno)) => Err(PlatformError::Syscall {
                stage: SyscallStage::Statistics,
                errno: Errno::new(errno),
            }),
        }
    }

    fn take_socket_error(&mut self, fd: RawFd) -> Result<i32, PlatformError> {
        let mut state = self.0.borrow_mut();
        let result = state.socket_error_script.pop_front().unwrap_or(Ok(0));
        state.socket_errors.push((fd, result));
        result.map_err(|errno| PlatformError::Syscall {
            stage: SyscallStage::SocketError,
            errno: Errno::new(errno),
        })
    }

    fn unmap(&mut self, base: NonNull<u8>, len: usize) {
        let layout = Layout::from_size_align(len, PAGE).expect("mapping layout");
        // SAFETY: the mapping owner unmaps exactly once with the pointer and
        // length that `map` returned for this allocation.
        unsafe { dealloc(base.as_ptr(), layout) };
    }

    fn close(&mut self, _fd: RawFd) {}
}

/// A mapping address that keeps the pointer's provenance, so the harness
/// runs under Miri's strict provenance (`-Zmiri-strict-provenance`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Addr(*mut u8);

impl std::ops::Add<usize> for Addr {
    type Output = Self;

    fn add(self, offset: usize) -> Self {
        Self(self.0.wrapping_add(offset))
    }
}

fn raw_u32(address: Addr) -> u32 {
    // SAFETY: callers pass aligned addresses inside a live `LiveOps`
    // mapping; the engine reaches that memory only through raw pointers and
    // no Rust reference to it is held, so this volatile read conflicts with
    // no borrow.
    unsafe { std::ptr::read_volatile(address.0.cast::<u32>()) }
}

fn raw_write_u32(address: Addr, value: u32) {
    // SAFETY: as in `raw_u32`; the harness writes only words the kernel
    // would own, never while engine code runs.
    unsafe { std::ptr::write_volatile(address.0.cast::<u32>(), value) };
}

fn raw_write_u16(address: Addr, value: u16) {
    // SAFETY: as in `raw_write_u32`.
    unsafe { std::ptr::write_volatile(address.0.cast::<u16>(), value) };
}

fn raw_bytes(address: Addr, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    // SAFETY: as in `raw_u32`; the range lies inside one TX frame.
    unsafe { std::ptr::copy_nonoverlapping(address.0, bytes.as_mut_ptr(), len) };
    bytes
}

fn raw_write_bytes(address: Addr, bytes: &[u8]) {
    // SAFETY: as in `raw_write_u32`; the range lies inside the mapping.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), address.0, bytes.len()) };
}

/// Two ports (LAN, WAN), one 4 KiB RX block and four 2 KiB TX frames each.
struct Live {
    engine: AfPacketEngine<LiveOps>,
    ops: LiveOps,
}

impl Live {
    fn new() -> Self {
        let rx = RingGeometry {
            block_size: 4_096,
            block_count: 1,
            frame_size: 2_048,
            frame_count: 2,
            retire_timeout_ms: 1,
            private_size: 16,
            feature_flags: 0,
        };
        let tx = RingGeometry {
            block_size: 4_096,
            block_count: 2,
            frame_size: 2_048,
            frame_count: 4,
            retire_timeout_ms: 0,
            private_size: 0,
            feature_flags: 0,
        };
        let ports = [LAN, WAN].map(|interface| PortConfig {
            interface,
            if_index: u32::from(interface.0) + 10,
            rx,
            tx,
        });
        let config = ValidatedConfig::new(&ports, PAGE, 1_514).expect("config");
        let ops = LiveOps(Rc::new(RefCell::new(LiveState {
            next_fd: FIRST_FD,
            kicks: Vec::with_capacity(4_096),
            polls: Vec::with_capacity(4_096),
            socket_errors: Vec::with_capacity(4_096),
            ..LiveState::default()
        })));
        let engine = AfPacketEngine::open_with_ops(config, ops.clone()).expect("engine");
        Self { engine, ops }
    }

    fn base(&self, port: usize) -> Addr {
        self.ops.0.borrow().mappings[port].0
    }

    fn tx_frame(&self, port: usize, frame: usize) -> Addr {
        assert!(frame < TX_FRAMES);
        self.base(port) + RX_LEN + frame * TX_FRAME
    }

    fn tx_status(&self, port: usize, frame: usize) -> u32 {
        raw_u32(self.tx_frame(port, frame) + 20)
    }

    fn set_tx_status(&self, port: usize, frame: usize, status: u32) {
        raw_write_u32(self.tx_frame(port, frame) + 20, status);
    }

    /// Kernel side: every frame still SEND_REQUEST or SENDING was sent.
    fn kernel_completes(&self, port: usize) {
        for frame in 0..TX_FRAMES {
            if matches!(
                self.tx_status(port, frame),
                TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING
            ) {
                self.set_tx_status(port, frame, TP_STATUS_AVAILABLE);
            }
        }
    }

    fn tx_payload(&self, port: usize, frame: usize) -> Vec<u8> {
        let len = usize::try_from(raw_u32(self.tx_frame(port, frame) + 16)).expect("len");
        raw_bytes(self.tx_frame(port, frame) + 48, len)
    }

    fn rx_status(&self, port: usize) -> u32 {
        raw_u32(self.base(port) + 8)
    }

    /// Lays out `packets` in RX block 0 as TPACKET_V3 does and publishes
    /// USER last.
    fn inject_rx(&self, port: usize, packets: &[&[u8]]) {
        let base = self.base(port);
        assert_eq!(self.rx_status(port), TP_STATUS_KERNEL, "RX block not free");
        let mut offset = FIRST_PACKET;
        for (index, payload) in packets.iter().enumerate() {
            let total = (MAC + payload.len()).next_multiple_of(8);
            let next = if index + 1 == packets.len() { 0 } else { total };
            let header = base + offset;
            let length = u32::try_from(payload.len()).expect("small");
            raw_write_u32(header, u32::try_from(next).expect("small"));
            raw_write_u32(header + 12, length);
            raw_write_u32(header + 16, length);
            raw_write_u32(header + 20, TP_STATUS_USER);
            raw_write_u16(header + 24, u16::try_from(MAC).expect("small"));
            raw_write_u16(header + 26, 96);
            raw_write_bytes(header + MAC, payload);
            offset += total;
        }
        raw_write_u32(base, 2);
        raw_write_u32(base + 4, 48);
        raw_write_u32(base + 12, u32::try_from(packets.len()).expect("small"));
        raw_write_u32(base + 16, u32::try_from(FIRST_PACKET).expect("small"));
        raw_write_u32(base + 20, u32::try_from(offset).expect("small"));
        raw_write_u32(base + 8, TP_STATUS_USER);
    }

    fn kicks(&self) -> Vec<(RawFd, Result<(), i32>)> {
        // Drain, keeping the reserved capacity for allocation-free pushes.
        self.ops.0.borrow_mut().kicks.drain(..).collect()
    }

    fn fail_kicks(&self, errnos: &[i32]) {
        self.ops.0.borrow_mut().kick_errnos.extend(errnos);
    }

    fn fail_kicks_persistently(&self, errno: Option<i32>) {
        self.ops.0.borrow_mut().persistent_kick_errno = errno;
    }

    fn clock(&mut self, now: u64) {
        self.engine.set_clock(MonotonicMillis(now));
    }

    /// Generates `count` frames of `len` bytes on `egress` (raw session).
    fn generate(&mut self, egress: IfId, count: usize, len: usize) -> usize {
        let mut batch = self.engine.live_begin_generated(egress);
        for index in 0..count {
            let mut frame = batch.allocate(len).expect("generated frame");
            frame.bytes_mut()[0] = u8::try_from(index).expect("small");
            frame.commit();
        }
        let completion = batch.finish();
        assert!(completion.invariants_hold(), "{completion:?}");
        assert_eq!(completion.error, None, "{completion:?}");
        completion.accepted
    }

    fn port(&self, interface: IfId) -> crate::AfPacketPortStats {
        self.engine.port_stats(interface).expect("known port")
    }
}

const LAN_FD: RawFd = FIRST_FD;
const WAN_FD: RawFd = FIRST_FD + 1;

#[test]
fn af_packet_live_receive_reaps_tx_completions_so_the_ring_is_reused_without_more_calls() {
    let mut live = Live::new();
    // Four RX packets fill WAN's four-frame TX ring through the copy path.
    live.inject_rx(0, &[&[1; 60], &[2; 60], &[3; 60], &[4; 60]]);
    {
        let mut batch = live.engine.live_receive(8).expect("receive");
        while let Some(packet) = batch.next_packet() {
            packet.commit(WAN);
        }
        let completion = batch.finish();
        assert_eq!((completion.tx_accepted, completion.tx_rejected), (4, 0));
    }
    assert_eq!(live.port(WAN).tx_inflight, 4);
    // The AP2 PacketIo alone would now reject every commit as ring full.
    // The kernel sends; the next live receive reaps before RX.
    live.kernel_completes(1);
    live.inject_rx(0, &[&[5; 60]]);
    {
        let mut batch = live.engine.live_receive(8).expect("receive");
        batch.next_packet().expect("packet").commit(WAN);
        assert_eq!(batch.finish().tx_accepted, 1);
    }
    let wan = live.port(WAN);
    assert_eq!(wan.tx_inflight, 1);
    assert_eq!(wan.counters.tx_completed, 4);
    assert_eq!(wan.counters.tx_published, 5);
    assert_eq!(wan.counters.tx_copies, 5);
    assert_eq!(wan.counters.tx_inflight_high_water, 4);
    assert_eq!(wan.counters.tx_ring_full, 0);
    assert_eq!(live.tx_payload(1, 0), vec![5; 60], "frame 0 reused");
    let lan = live.port(LAN);
    assert_eq!(lan.counters.rx_packets, 5);
    assert_eq!(lan.counters.rx_blocks_returned, 2);
    // One kick per finished batch that published, none from settling.
    assert_eq!(live.kicks(), [(WAN_FD, Ok(())), (WAN_FD, Ok(()))]);
}

#[test]
fn af_packet_deferred_and_link_down_kicks_are_owed_not_errors_and_retry_with_backoff() {
    let mut live = Live::new();
    for (errno, link_down) in [(EAGAIN, false), (ENOBUFS, false), (ENETDOWN, true)] {
        let mut live_case = Live::new();
        live_case.fail_kicks(&[errno]);
        assert_eq!(
            live_case.generate(WAN, 1, 60),
            1,
            "errno {errno} is no error"
        );
        let wan = live_case.port(WAN);
        assert!(wan.kick_owed, "errno {errno}");
        assert_eq!(wan.link_down, link_down, "errno {errno}");
        assert_eq!(wan.counters.kicks_deferred, u64::from(!link_down));
        assert_eq!(wan.counters.kicks_link_down, u64::from(link_down));
        assert_eq!(wan.counters.kick_errors, 0);
    }

    // A down link: the first kick fails at t=0; retries wait 1, 2, 4 ... ms.
    live.fail_kicks_persistently(Some(ENETDOWN));
    live.clock(0);
    assert_eq!(live.generate(WAN, 2, 60), 2);
    assert_eq!(live.kicks().len(), 1);
    let mut retries = Vec::new();
    for now in 0..200 {
        live.clock(now);
        let _ = live.engine.live_receive(1).expect("receive").finish();
        if !live.kicks().is_empty() {
            retries.push(now);
        }
    }
    assert_eq!(retries, [1, 2, 4, 8, 16, 32, 64, 128, 192]);
    let wan = live.port(WAN);
    assert!(wan.link_down && wan.kick_owed);
    assert_eq!(wan.tx_inflight, 2, "frames stay published");
    assert_eq!(wan.counters.kick_retries, 9);
    assert_eq!(wan.counters.kicks_link_down, 10);
    assert!(wan.counters.kick_retries_suppressed > 150);
    assert_eq!(KICK_BACKOFF_MAX_MS, 64);

    // The link comes back: the next due retry sends, the kernel completes,
    // and the following settle clears the debt and the backoff.
    live.fail_kicks_persistently(None);
    live.clock(256);
    let _ = live.engine.live_receive(1).expect("receive").finish();
    assert_eq!(live.kicks(), [(WAN_FD, Ok(()))]);
    let wan = live.port(WAN);
    assert!(!wan.link_down && !wan.kick_owed);
    live.kernel_completes(1);
    let _ = live.engine.live_receive(1).expect("receive").finish();
    let wan = live.port(WAN);
    assert_eq!(wan.tx_inflight, 0);
    assert_eq!(live.engine.ports[1].kick.backoff_ms, 1);
    assert!(!live.engine.tx_outstanding());
}

#[test]
fn af_packet_fault_kick_errno_is_the_batch_error_and_stays_owed() {
    let mut live = Live::new();
    live.fail_kicks(&[EIO]);
    live.inject_rx(0, &[&[1; 60]]);
    let completion = {
        let mut batch = live.engine.live_receive(1).expect("receive");
        batch.next_packet().expect("packet").commit(WAN);
        batch.finish()
    };
    assert_eq!(completion.tx_accepted, 1, "a kick error never demotes");
    assert_eq!(
        completion.error,
        Some(AfPacketIoError::Kick {
            interface: WAN,
            error: PlatformError::Syscall {
                stage: SyscallStage::Kick,
                errno: Errno::new(EIO),
            },
        })
    );
    let wan = live.port(WAN);
    assert!(wan.kick_owed && !wan.link_down);
    assert_eq!(wan.counters.kick_errors, 1);
    // Generated sessions classify their single kick the same way.
    live.fail_kicks(&[EIO]);
    let mut batch = live.engine.live_begin_generated(LAN);
    batch.allocate(60).expect("frame").commit();
    assert!(matches!(
        batch.finish().error,
        Some(AfPacketIoError::Kick { interface: LAN, .. })
    ));
}

#[test]
fn af_packet_a_frame_the_kernel_left_send_request_after_a_good_kick_is_kicked_again() {
    let mut live = Live::new();
    live.clock(10);
    assert_eq!(live.generate(WAN, 2, 60), 2);
    assert_eq!(live.kicks(), [(WAN_FD, Ok(()))]);
    // The kernel took nothing (as `tpacket_snd` does when it cannot get an
    // skb under MSG_DONTWAIT): the next settle owes and retries at once.
    let _ = live.engine.live_receive(1).expect("receive").finish();
    assert_eq!(live.kicks(), [(WAN_FD, Ok(()))]);
    // Still not taken: the retry backs off (1 ms) instead of spinning.
    let _ = live.engine.live_receive(1).expect("receive").finish();
    assert!(live.kicks().is_empty());
    assert!(live.port(WAN).kick_owed);
    live.clock(11);
    let _ = live.engine.live_receive(1).expect("receive").finish();
    assert_eq!(live.kicks(), [(WAN_FD, Ok(()))]);
    // The kernel moved the head to SENDING: in flight, nothing owed.
    live.set_tx_status(1, 0, TP_STATUS_SENDING);
    live.set_tx_status(1, 1, TP_STATUS_SENDING);
    live.clock(100);
    let _ = live.engine.live_receive(1).expect("receive").finish();
    assert!(live.kicks().is_empty());
    let wan = live.port(WAN);
    assert!(!wan.kick_owed);
    assert_eq!(wan.tx_inflight, 2);
    assert_eq!(wan.counters.kick_retries, 2);
}

#[test]
fn af_packet_generated_frames_are_lent_tx_frames_zeroed_and_published_without_a_copy() {
    let mut live = Live::new();
    // Dirty the producer-head frame to prove the lease is zeroed.
    raw_write_bytes(live.tx_frame(1, 0) + 48, &[0xee; 100]);
    let frame0 = live.tx_frame(1, 0) + 48;
    {
        let mut batch = live.engine.live_begin_generated(WAN);
        assert_eq!(
            batch.allocate(0).err(),
            Some(GeneratedAllocationError::ZeroLength)
        );
        assert_eq!(
            batch.allocate(13).err(),
            Some(GeneratedAllocationError::FrameTooLarge)
        );
        assert_eq!(
            batch.allocate(1_515).err(),
            Some(GeneratedAllocationError::FrameTooLarge)
        );
        let mut frame = batch.allocate(60).expect("frame");
        assert_eq!(frame.bytes_mut().len(), 60);
        assert!(frame.bytes_mut().iter().all(|byte| *byte == 0), "zeroed");
        let address = frame.bytes_mut().as_mut_ptr();
        assert!(std::ptr::eq(address, frame0.0), "the TX frame itself");
        frame.bytes_mut().copy_from_slice(&[0x5a; 60]);
        frame.commit();
        // Cancel and abandon leave the next frame AVAILABLE and unpublished.
        batch.allocate(42).expect("frame").cancel();
        drop(batch.allocate(42).expect("frame"));
        let completion = batch.finish();
        assert_eq!(
            (
                completion.attempts,
                completion.allocated,
                completion.failed,
                completion.requested,
                completion.cancelled,
                completion.abandoned,
                completion.accepted,
                completion.rejected,
            ),
            (6, 3, 3, 1, 1, 1, 1, 0)
        );
        assert!(completion.invariants_hold());
        assert_eq!(completion.error, None);
    }
    assert_eq!(live.tx_status(1, 0), TP_STATUS_SEND_REQUEST);
    assert_eq!(live.tx_payload(1, 0), vec![0x5a; 60]);
    assert_eq!(live.tx_status(1, 1), TP_STATUS_AVAILABLE);
    // Cancel advanced the frame's generation (ABA protection) only.
    assert_eq!(live.engine.ports[1].tx_metadata(1).generation, 2);
    let wan = live.port(WAN);
    assert_eq!(
        (
            wan.counters.generated_allocated,
            wan.counters.generated_committed,
            wan.counters.generated_cancelled,
            wan.counters.generated_abandoned,
            wan.counters.generated_rejected,
            wan.counters.tx_copies,
        ),
        (3, 1, 1, 1, 2, 0)
    );
    assert_eq!(live.kicks(), [(WAN_FD, Ok(()))]);
    // The kernel took the frame (SENDING), so no settle owes a kick.
    live.set_tx_status(1, 0, TP_STATUS_SENDING);

    // A session that published nothing does not kick.
    let mut batch = live.engine.live_begin_generated(WAN);
    batch.allocate(42).expect("frame").cancel();
    let _ = batch.finish();
    assert!(live.kicks().is_empty());

    // A full ring is Unavailable without an error; an unknown egress too.
    assert_eq!(live.generate(WAN, 3, 42), 3);
    let mut batch = live.engine.live_begin_generated(WAN);
    assert_eq!(
        batch.allocate(42).err(),
        Some(GeneratedAllocationError::Unavailable)
    );
    assert_eq!(batch.finish().error, None);
    assert_eq!(live.port(WAN).counters.generated_unavailable, 1);
    let mut batch = live.engine.live_begin_generated(UNKNOWN);
    assert_eq!(
        batch.allocate(42).err(),
        Some(GeneratedAllocationError::Unavailable)
    );
    assert_eq!(batch.finish().error, None);
    assert_eq!(live.engine.backend_stats().generated_unknown_egress, 1);
    // The settle in `live_begin_generated` reclaims the ring.
    live.kernel_completes(1);
    assert_eq!(live.generate(WAN, 4, 42), 4);
}

#[test]
fn af_packet_quiescence_waits_for_in_flight_tx_and_then_admits_a_publication() {
    let mut live = Live::new();
    assert_eq!(live.engine.quiescence_check(), Ok(()));
    assert_eq!(live.generate(WAN, 2, 60), 2);
    let error = live.engine.quiescence_check().expect_err("in flight");
    assert_eq!(error, AfPacketQuiescenceError::TxInFlight { frames: 2 });
    assert_eq!(
        error.disposition(),
        PublicationQuiescenceDisposition::ContinueOldIo
    );
    assert_eq!(
        live.engine.io_disposition(),
        PublicationQuiescenceDisposition::ContinueOldIo
    );
    live.set_tx_status(1, 0, TP_STATUS_AVAILABLE);
    assert_eq!(
        live.engine.quiescence_check(),
        Err(AfPacketQuiescenceError::TxInFlight { frames: 1 })
    );
    live.kernel_completes(1);
    assert_eq!(live.engine.quiescence_check(), Ok(()));
}

#[test]
fn af_packet_a_completion_invariant_violation_stops_the_engine_for_good() {
    let mut live = Live::new();
    assert_eq!(live.generate(WAN, 1, 60), 1);
    live.set_tx_status(1, 0, 0x7);
    match live.engine.live_receive(1) {
        Err(AfPacketIoError::Completion {
            interface: WAN,
            error: TxCompletionError::InvalidStatus { status: 0x7 },
        }) => {}
        other => panic!("expected a completion fault: {:?}", other.err()),
    }
    assert!(matches!(
        live.engine.live_receive(1),
        Err(AfPacketIoError::Stopped)
    ));
    assert_eq!(
        live.engine.quiescence_check(),
        Err(AfPacketQuiescenceError::Stopped)
    );
    assert_eq!(
        AfPacketQuiescenceError::Stopped.disposition(),
        PublicationQuiescenceDisposition::Stop
    );
    assert_eq!(
        live.engine.io_disposition(),
        PublicationQuiescenceDisposition::Stop
    );
    let mut batch = live.engine.live_begin_generated(LAN);
    assert_eq!(
        batch.allocate(60).err(),
        Some(GeneratedAllocationError::Unavailable)
    );
    let _ = batch.finish();
    assert!(live.engine.backend_stats().stopped);
    // The drain does not scan the faulted ring again.
    assert_eq!(live.engine.drain(4).tx_in_flight, 1);
}

#[test]
fn af_packet_drain_stops_io_for_good_and_kicks_owed_ports_without_backoff() {
    let mut live = Live::new();
    live.inject_rx(0, &[&[1; 60]]);
    live.fail_kicks_persistently(Some(EAGAIN));
    assert_eq!(live.generate(WAN, 2, 60), 2);
    assert_eq!(live.kicks().len(), 1);
    // Four forced rounds, one retry each, although the clock never moves.
    let report = live.engine.drain(4);
    assert_eq!(report.tx_in_flight, 2);
    assert_eq!(report.kick_owed_ports, 1);
    assert!(!report.is_drained());
    assert_eq!(live.kicks().len(), 4);
    assert!(matches!(
        live.engine.live_receive(1),
        Err(AfPacketIoError::Stopped)
    ));
    assert_eq!(live.engine.wait_rx(1_000), Ok(RxWait::Ready), "no wait");
    assert!(live.ops.0.borrow().polls.is_empty());
    // The kernel takes them: the next drain call reaps and reports done.
    live.fail_kicks_persistently(None);
    let report = live.engine.drain(4);
    assert_eq!(report.tx_in_flight, 2, "kicked, not yet completed");
    live.kernel_completes(1);
    let report = live.engine.drain(4);
    assert!(report.is_drained());
    assert_eq!(report.kick_owed_ports, 0);
    assert!(live.engine.is_stopped());
    // The LAN block that was never received is still USER; the kernel
    // reclaims it with the socket.
    assert_eq!(live.rx_status(0), TP_STATUS_USER);
}

#[test]
fn af_packet_idle_wait_skips_poll_with_rx_work_and_maps_poll_outcomes() {
    let mut live = Live::new();
    // Empty rings: one poll over both sockets with POLLIN and the timeout.
    assert_eq!(live.engine.wait_rx(25), Ok(RxWait::TimedOut));
    {
        let state = live.ops.0.borrow();
        let (fds, timeout) = &state.polls[0];
        assert_eq!(*timeout, 25);
        assert_eq!(
            fds.iter().map(|fd| (fd.fd, fd.events)).collect::<Vec<_>>(),
            [(LAN_FD, POLLIN), (WAN_FD, POLLIN)]
        );
    }
    let script = |live: &Live, outcome| live.ops.0.borrow_mut().poll_script.push_back(outcome);
    script(&live, Ok(POLLIN));
    assert_eq!(live.engine.wait_rx(25), Ok(RxWait::Ready));
    script(&live, Err(4));
    assert_eq!(live.engine.wait_rx(25), Ok(RxWait::Interrupted));
    script(&live, Ok(0x020));
    assert_eq!(
        live.engine.wait_rx(25),
        Err(PlatformError::Syscall {
            stage: SyscallStage::Poll,
            errno: Errno::new(9),
        })
    );
    script(&live, Err(EIO));
    assert!(live.engine.wait_rx(25).is_err());
    // u32::MAX clamps to the largest poll timeout.
    assert_eq!(live.engine.wait_rx(u32::MAX), Ok(RxWait::TimedOut));
    assert_eq!(live.ops.0.borrow().polls.last().expect("poll").1, i32::MAX);
    let polls = live.ops.0.borrow().polls.len();
    assert_eq!(polls, 6);

    // A USER head block is RX work: no poll at all, until it is consumed.
    live.inject_rx(1, &[&[1; 60], &[2; 60]]);
    assert_eq!(live.engine.wait_rx(25), Ok(RxWait::Ready));
    // A block in delivery is still work after one of its packets.
    {
        let mut batch = live.engine.live_receive(1).expect("receive");
        batch
            .next_packet()
            .expect("packet")
            .recycle(DropReason::UnsupportedEtherType);
        let _ = batch.finish();
    }
    assert_eq!(live.engine.wait_rx(25), Ok(RxWait::Ready));
    {
        let mut batch = live.engine.live_receive(8).expect("receive");
        while let Some(packet) = batch.next_packet() {
            packet.recycle(DropReason::UnsupportedEtherType);
        }
        let _ = batch.finish();
    }
    assert_eq!(live.ops.0.borrow().polls.len(), polls);
    assert_eq!(live.engine.wait_rx(25), Ok(RxWait::TimedOut));
    assert_eq!(live.ops.0.borrow().polls.len(), polls + 1);
}

#[test]
fn af_packet_kernel_statistics_accumulate_across_resetting_reads_and_count_failures() {
    let mut live = Live::new();
    let stats = |packets, drops, freezes| {
        Ok(TpacketStatsV3 {
            tp_packets: packets,
            tp_drops: drops,
            tp_freeze_q_cnt: freezes,
        })
    };
    live.ops.0.borrow_mut().stats_script.extend([
        stats(5, 2, 1),
        stats(7, 0, 0),
        stats(3, 1, 1),
        Err(EIO),
    ]);
    assert_eq!(live.engine.refresh_kernel_stats(), Ok(()));
    assert_eq!(
        live.engine.refresh_kernel_stats(),
        Err(PlatformError::Syscall {
            stage: SyscallStage::Statistics,
            errno: Errno::new(EIO),
        })
    );
    let lan = live.port(LAN).counters;
    let wan = live.port(WAN).counters;
    assert_eq!(
        (lan.kernel_packets, lan.kernel_drops, lan.kernel_freeze_q),
        (8, 3, 2)
    );
    assert_eq!(
        (
            wan.kernel_packets,
            wan.kernel_drops,
            wan.kernel_stats_errors
        ),
        (7, 0, 1)
    );
    let total = live.engine.backend_stats().counters;
    assert_eq!((total.kernel_packets, total.kernel_stats_errors), (15, 1));
}

struct Collect(Vec<(&'static str, &'static str, FieldValue)>);

impl FieldVisitor for Collect {
    fn field(&mut self, section: &'static str, key: &'static str, value: FieldValue) {
        self.0.push((section, key, value));
    }
}

struct Count(usize);

impl FieldVisitor for Count {
    fn field(&mut self, _section: &'static str, _key: &'static str, _value: FieldValue) {
        self.0 += 1;
    }
}

#[test]
fn af_packet_backend_stats_sum_ports_with_a_fixed_shape_and_allocate_nothing() {
    let mut live = Live::new();
    live.inject_rx(0, &[&[1; 60], &[2; 60]]);
    {
        let mut batch = live.engine.live_receive(8).expect("receive");
        batch.next_packet().expect("packet").commit(WAN);
        batch.next_packet().expect("packet").commit(LAN);
        let _ = batch.finish();
    }
    // The kernel took both copies (SENDING): in flight, nothing owed.
    live.set_tx_status(0, 0, TP_STATUS_SENDING);
    live.set_tx_status(1, 0, TP_STATUS_SENDING);
    live.fail_kicks(&[ENETDOWN]);
    assert_eq!(live.generate(WAN, 1, 60), 1);
    let stats = live.engine.backend_stats();
    assert_eq!(stats.ports, 2);
    assert_eq!(stats.tx_inflight, 3);
    assert_eq!((stats.kick_owed_ports, stats.link_down_ports), (1, 1));
    assert_eq!(stats.counters.tx_published, 3);
    assert_eq!(stats.counters.tx_copies, 2);
    assert_eq!(stats.counters.rx_packets, 2);
    assert_eq!(
        stats.counters.tx_inflight_high_water, 2,
        "a maximum, not a sum"
    );
    assert!(!stats.stopped);

    let mut first = Collect(Vec::new());
    stats.visit_fields(&mut first);
    let mut second = Collect(Vec::new());
    stats.visit_fields(&mut second);
    assert_eq!(first.0, second.0, "fixed order");
    let mut keys = first.0.iter().map(|(_, key, _)| *key).collect::<Vec<_>>();
    assert_eq!(keys[..2], ["mode", "ports"]);
    keys.sort_unstable();
    let len = keys.len();
    keys.dedup();
    assert_eq!(keys.len(), len, "unique keys");
    assert!(first
        .0
        .iter()
        .all(|(section, _, _)| *section == "af_packet"));
    let port = live.port(WAN);
    let mut port_fields = Collect(Vec::new());
    port.visit_fields(&mut port_fields);
    assert!(port_fields
        .0
        .iter()
        .all(|(section, _, _)| *section == "af_packet_port"));
    assert!(port_fields
        .0
        .contains(&("af_packet_port", "kick_owed", FieldValue::Flag(true))));

    let before = allocation_count();
    let stats = live.engine.backend_stats();
    let mut count = Count(0);
    stats.visit_fields(&mut count);
    let port = live.engine.port_stats(WAN).expect("WAN");
    port.visit_fields(&mut count);
    assert_eq!(allocation_count(), before, "stats allocate nothing");
    assert_eq!(count.0, first.0.len() + port_fields.0.len());
}

#[test]
fn af_packet_steady_live_receive_generate_settle_and_wait_allocate_nothing() {
    let mut live = Live::new();
    let mut allocations = 0;
    for round in 0..64_u64 {
        live.inject_rx(0, &[&[1; 60], &[2; 60]]);
        live.clock(round);
        let before = allocation_count();
        {
            let mut batch = live.engine.live_receive(8).expect("receive");
            while let Some(packet) = batch.next_packet() {
                packet.commit(WAN);
            }
            let completion = batch.finish();
            assert_eq!(completion.tx_accepted, 2);
        }
        {
            let mut batch = live.engine.live_begin_generated(WAN);
            batch.allocate(42).expect("frame").commit();
            let _ = batch.finish();
        }
        let _ = live.engine.quiescence_check();
        let _ = live.engine.wait_rx(0);
        allocations += allocation_count() - before;
        live.kernel_completes(1);
        // The scripted ops record kicks and polls; drain them out of band.
        live.kicks();
        live.ops.0.borrow_mut().polls.clear();
    }
    assert_eq!(allocations, 0);
    assert_eq!(live.port(WAN).counters.tx_published, 64 * 3);
}

#[test]
fn af_packet_enxio_is_a_permanent_unbound_error_that_is_never_retried() {
    let mut live = Live::new();
    live.clock(0);
    live.fail_kicks_persistently(Some(ENXIO));
    let mut batch = live.engine.live_begin_generated(WAN);
    batch.allocate(60).expect("frame").commit();
    let completion = batch.finish();
    assert_eq!(completion.accepted, 1);
    assert_eq!(
        completion.error,
        Some(AfPacketIoError::Kick {
            interface: WAN,
            error: PlatformError::Syscall {
                stage: SyscallStage::Kick,
                errno: Errno::new(ENXIO),
            },
        })
    );
    assert_eq!(live.kicks().len(), 1);
    // No settle retries the gone device, however much time passes, and the
    // forced drain does not either.
    for now in 0..500 {
        live.clock(now);
        let _ = live.engine.live_receive(1).expect("receive").finish();
    }
    assert_eq!(live.engine.drain(8).tx_in_flight, 1);
    assert!(live.kicks().is_empty());
    let wan = live.port(WAN);
    assert!(wan.unbound && wan.kick_owed && !wan.link_down, "{wan:?}");
    assert_eq!(
        (
            wan.counters.kicks_unbound,
            wan.counters.kick_errors,
            wan.counters.kick_retries
        ),
        (1, 1, 0)
    );
    assert_eq!(live.engine.backend_stats().unbound_ports, 1);
}

#[test]
fn af_packet_without_a_clock_every_settle_retries_an_owed_kick() {
    let mut live = Live::new();
    live.fail_kicks(&[EAGAIN]);
    assert_eq!(live.generate(WAN, 1, 60), 1);
    assert_eq!(live.kicks().len(), 1);
    // Clock never set: the frame stays SEND_REQUEST, and every settle kicks.
    for _ in 0..3 {
        let _ = live.engine.live_receive(1).expect("receive").finish();
    }
    assert_eq!(live.kicks().len(), 3);
    // Once the loop hands in a clock, retries are paced again.
    live.clock(1_000);
    for _ in 0..3 {
        let _ = live.engine.live_receive(1).expect("receive").finish();
    }
    assert_eq!(live.kicks().len(), 1);
}

#[test]
fn af_packet_reclaim_progress_makes_the_next_retry_due_at_once() {
    let mut live = Live::new();
    live.clock(0);
    live.fail_kicks_persistently(Some(EAGAIN));
    assert_eq!(live.generate(WAN, 2, 60), 2);
    for now in 1..40 {
        live.clock(now);
        let _ = live.engine.live_receive(1).expect("receive").finish();
    }
    assert!(live.engine.ports[1].kick.backoff_ms > 1);
    let _ = live.kicks();
    // The kernel completes one frame: backoff and retry time reset, so the
    // still-owed second frame is kicked at the same settle.
    live.set_tx_status(1, 0, TP_STATUS_AVAILABLE);
    let _ = live.engine.live_receive(1).expect("receive").finish();
    assert_eq!(live.kicks().len(), 1);
    assert_eq!(live.port(WAN).tx_inflight, 1);
}

#[test]
fn af_packet_idle_wait_reads_and_clears_a_pending_socket_error() {
    const POLLERR: i16 = 0x008;
    let mut live = Live::new();
    let script = |live: &Live, outcome| live.ops.0.borrow_mut().poll_script.push_back(outcome);
    // The scripted poll reports `revents` on the WAN socket: POLLERR alone
    // (what a mapped TPACKET socket shows after its device went down).
    script(&live, Ok(POLLERR));
    live.ops
        .0
        .borrow_mut()
        .socket_error_script
        .push_back(Ok(ENETDOWN));
    assert_eq!(live.engine.wait_rx(25), Ok(RxWait::Ready));
    assert_eq!(
        live.ops.0.borrow().socket_errors,
        [(WAN_FD, Ok(ENETDOWN))],
        "exactly the erroring socket is read, once"
    );
    let wan = live.engine.port_stats(WAN).expect("wan");
    assert_eq!(wan.counters.socket_errors, 1);
    assert_eq!(wan.counters.socket_error_reads_failed, 0);
    let lan = live.engine.port_stats(LAN).expect("lan");
    assert_eq!(lan.counters.socket_errors, 0);
    // Cleared: the next wait blocks again (the scripted poll times out).
    assert_eq!(live.engine.wait_rx(25), Ok(RxWait::TimedOut));
    assert_eq!(live.ops.0.borrow().socket_errors.len(), 1);
    // POLLIN without POLLERR reads nothing.
    script(&live, Ok(POLLIN));
    assert_eq!(live.engine.wait_rx(25), Ok(RxWait::Ready));
    assert_eq!(live.ops.0.borrow().socket_errors.len(), 1);
    // A failed read is counted, and the wait still ends Ready.
    script(&live, Ok(POLLERR | POLLIN));
    live.ops
        .0
        .borrow_mut()
        .socket_error_script
        .push_back(Err(EIO));
    assert_eq!(live.engine.wait_rx(25), Ok(RxWait::Ready));
    let wan = live.engine.port_stats(WAN).expect("wan");
    assert_eq!(wan.counters.socket_errors, 1);
    assert_eq!(wan.counters.socket_error_reads_failed, 1);
    assert_eq!(live.engine.backend_stats().counters.socket_errors, 1);
}

#[test]
fn af_packet_idle_wait_does_not_spin_on_a_port_halted_mid_block() {
    let mut live = Live::new();
    live.inject_rx(0, &[&[1; 60]]);
    // The block return (status store) fails once: the cursor halts in the
    // delivery phase with every packet terminal.
    live.engine.ports[0].rx_injection.status_stores = 1;
    {
        let mut batch = live.engine.live_receive(8).expect("receive");
        batch
            .next_packet()
            .expect("packet")
            .recycle(DropReason::UnsupportedEtherType);
        let completion = batch.finish();
        assert!(matches!(
            completion.error,
            Some(AfPacketIoError::Rx {
                interface: LAN,
                fault: RxFault::Release(_),
            })
        ));
    }
    assert!(live.port(LAN).rx_halted);
    assert_eq!(live.rx_status(0), TP_STATUS_USER, "block not returned");
    // Halted in a non-Idle phase: not RX work, so the wait polls.
    assert_eq!(live.engine.wait_rx(5), Ok(RxWait::TimedOut));
    assert_eq!(live.ops.0.borrow().polls.len(), 1);
    // The next batch retries the return, which now succeeds.
    let mut batch = live.engine.live_receive(8).expect("receive");
    assert!(batch.next_packet().is_none());
    assert_eq!(batch.finish().error, None);
    assert_eq!(live.rx_status(0), TP_STATUS_KERNEL);
    assert!(!live.port(LAN).rx_halted);
}

#[test]
fn af_packet_forgotten_generated_lease_and_session_do_not_wedge_tx() {
    let mut live = Live::new();
    // A forgotten lease: its session's finish returns the frame and counts
    // the lease abandoned, so the invariants stay exact.
    {
        let mut batch = live.engine.live_begin_generated(WAN);
        std::mem::forget(batch.allocate(60).expect("frame"));
        let mut frame = batch.allocate(60).expect("the orphan is reused");
        frame.bytes_mut()[0] = 0x42;
        frame.commit();
        std::mem::forget(batch.allocate(42).expect("frame"));
        let completion = batch.finish();
        assert!(completion.invariants_hold(), "{completion:?}");
        assert_eq!(
            (
                completion.allocated,
                completion.accepted,
                completion.abandoned
            ),
            (3, 1, 2)
        );
        assert_eq!(completion.error, None);
    }
    assert_eq!(live.tx_status(1, 0), TP_STATUS_SEND_REQUEST);
    assert_eq!(live.tx_payload(1, 0)[0], 0x42);
    assert_eq!(live.tx_status(1, 1), TP_STATUS_AVAILABLE);
    // A forgotten session with a live lease: the next reservation of the
    // port returns the orphaned frame.
    {
        let mut batch = live.engine.live_begin_generated(WAN);
        std::mem::forget(batch.allocate(60).expect("frame"));
        std::mem::forget(batch);
    }
    live.set_tx_status(1, 0, TP_STATUS_SENDING);
    assert_eq!(live.generate(WAN, 3, 60), 3, "frames 1..=3, no wedge");
    let wan = live.port(WAN);
    assert_eq!(wan.counters.tx_orphans_reclaimed, 3);
    assert_eq!(wan.counters.generated_abandoned, 2);
    assert_eq!(wan.tx_inflight, 4);
    // An RX copy commit also reclaims an orphan at the producer head.
    live.kernel_completes(1);
    {
        let mut batch = live.engine.live_begin_generated(WAN);
        std::mem::forget(batch.allocate(60).expect("frame"));
        std::mem::forget(batch);
    }
    live.inject_rx(0, &[&[7; 60]]);
    let mut batch = live.engine.live_receive(1).expect("receive");
    batch.next_packet().expect("packet").commit(WAN);
    assert_eq!(batch.finish().tx_accepted, 1);
    assert_eq!(live.port(WAN).counters.tx_orphans_reclaimed, 4);
}

#[test]
fn af_packet_tx_timestamp_status_bits_do_not_stop_the_engine() {
    let mut live = Live::new();
    assert_eq!(live.generate(WAN, 2, 60), 2);
    // The kernel completes with TP_STATUS_AVAILABLE | TP_STATUS_TS_* when
    // timestamping is enabled.
    live.set_tx_status(1, 0, TP_STATUS_AVAILABLE | (1 << 29));
    live.set_tx_status(1, 1, TP_STATUS_AVAILABLE | (1 << 31));
    assert_eq!(live.engine.quiescence_check(), Ok(()));
    assert!(!live.engine.is_stopped());
    // Producer-head frames carrying timestamp bits are AVAILABLE too.
    live.set_tx_status(1, 2, TP_STATUS_AVAILABLE | (1 << 30));
    assert_eq!(live.generate(WAN, 4, 60), 4);
    assert_eq!(live.port(WAN).counters.tx_completed, 2);
}
