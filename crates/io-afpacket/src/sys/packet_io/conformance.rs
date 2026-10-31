//! IO-012 evidence: the reusable `ruster-io-conformance` RX-to-distinct-TX
//! copy suite run against the real [`AfPacketEngine`] over a scripted mapping.
//!
//! [`ConformanceOps`] is a private static-dispatch [`PacketOps`] stand-in for
//! Linux: it hands each port a zeroed, page-aligned heap "mmap", records every
//! nonblocking kick, and can inject one kick errno. The harness then plays the
//! kernel: it writes TPACKET_V3 RX blocks exactly as `packet_mmap` lays them
//! out and moves TX frames from SEND_REQUEST to SENDING/AVAILABLE.
//!
//! The PacketIo seen by the suite is [`TracedIo`], a pass-through decorator
//! around the engine. It forwards every call unchanged and observes.
//!
//! Observed from scripted ring/syscall state (independent of the engine):
//!
//! - source identity from lease addresses;
//! - TX acceptance from a TX frame status that became SEND_REQUEST in the
//!   ring of the port that received it, its descriptor length and payload
//!   from that frame's header and bytes;
//! - "no copy on reject": every byte of every TX frame of every port that was
//!   not newly published by an operation must be unchanged across it, and a
//!   published frame must be unchanged past its payload;
//! - RX block return from the block status word turning TP_STATUS_KERNEL,
//!   checked for every pending block after every engine call;
//! - kicks and their errno from the scripted syscall log.
//!
//! Taken from the test-only `PortProbe` (engine-side counters):
//!
//! - per-block scan observations (status reads, acquisitions, descriptor
//!   visits), frozen at the block's return, and the RX/TX status-read and
//!   descriptor counters of `CopyOperationCounters`;
//! - `copy_invocations`/`copied_bytes`, each cross-checked against the
//!   ring: the number of copies must equal the number of newly published
//!   frames, and the byte-unchanged check above catches a copy the probe
//!   does not count;
//! - the RX block-return count, asserted to agree with the status word.
//!
//! Generations reported at injection or acceptance are verified against
//! engine metadata before the next harness operation. Allocation is counted
//! only while engine code runs.
//!
//! AF_PACKET-specific adaptations (documented, not silent):
//!
//! - AF_PACKET has exactly one TX ring per port. The suite's `queue` numbers
//!   label the LAN and WAN rings; they are not hardware queues.
//! - Each port's RX ring has one 256 KiB block, so the kernel's next fill
//!   position is always block 0. `prefer_copy_rx_block` asserts that instead
//!   of choosing, which makes the RX ABA case exact.
//! - The TX ring is a strict FIFO producer ring, so `prefer_copy_tx_frame`
//!   asserts that the requested frame is the producer head rather than
//!   choosing one. The completed-TX-reuse case therefore runs on a one-frame
//!   TX ring ([`OneFrameHarness`]).
//! - RX status/descriptor budgets are per port per batch. Every case receives
//!   only on `CONFORMANCE_LAN`, so the RX work counters report the LAN port;
//!   the WAN port's single empty-ring status read per batch is independent
//!   and is not part of the case's ingress work.
//! - The finite TX pool of a case is the `CONFORMANCE_WAN` ring, the egress
//!   of every pool-sensitive case.
//!
//! Not applicable (each requires TX storage to be reserved, bound to a token,
//! and then rejected, which AF_PACKET never does: every rejection happens
//! before any frame is reserved or copied, so no TX token exists for it):
//!
//! - `partial_reject_reclaims_tx_and_terminals_source`
//! - `finish_error_preserves_accounting_and_single_kick` (it injects partial
//!   acceptance through the same reserve-then-reject budget)
//! - `rejected_tx_reuse_advances_generation`
//!
//! Their AF_PACKET contract (partial ring-full rejection with no copy, a
//! finish error preserving accounting and the single kick) is covered by the
//! native tests in `tests.rs`. The ABA protection that
//! `rejected_tx_reuse_advances_generation` targets holds trivially because a
//! rejection never reserves a frame or advances its generation: the AP1-TX
//! test `tx_status_validation_precedes_reserve_and_rejected_packets_copy_nothing`
//! asserts generation zero and untouched bytes after every rejection kind,
//! `settle()` checks each reported TX generation against engine metadata, and
//! the byte-unchanged check here proves no rejected commit wrote any frame.

use std::{
    alloc::{alloc_zeroed, dealloc, Layout},
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    ffi::c_int,
    os::fd::RawFd,
    ptr::NonNull,
    rc::Rc,
};

use ruster_core::{
    BatchCompletion, IfId, PacketBatch, PacketIo, PacketLease, PacketSlot, SlotCompletion,
};
use ruster_io_conformance::{
    rx_copy::{
        self, CopyErrno, CopyKickEvent, CopyLeaseObserver, CopyOperationBudgets,
        CopyOperationCounters, CopyPayloadObservation, CopyRxBlockReturn, CopyRxBlockToken,
        CopyRxDescriptorFault, CopyRxFaultEvent, CopyRxPacketToken, CopyRxScanObservation,
        CopySourceDisposition, CopySourceEvent, CopyTxCompletion, CopyTxDisposition, CopyTxEvent,
        CopyTxToken, InjectedCopyRxBlock, LiveCopyRxPacket, LiveCopyTxFrame,
        RxCopyAdversarialHarness, RxCopyCompletionHarness, RxCopyHarness, RxCopyKickErrorHarness,
        RxCopyPayloadHarness, RxCopyUnknownEgressHarness,
    },
    RxReclaim, TxEndpoint, CONFORMANCE_LAN, CONFORMANCE_LAN_ENDPOINT, CONFORMANCE_WAN,
    CONFORMANCE_WAN_ENDPOINT,
};

use super::{AfPacketBatch, AfPacketIoError, AfPacketSlot};
use crate::{
    sys::{
        tests::allocation_count, AfPacketEngine, PacketOps, PortProbe, ProbeCounts, SockaddrLl,
        WorkLimits,
    },
    BackendStatsSnapshot, Errno, PlatformError, PortConfig, RingGeometry, SyscallStage,
    TxOwnership, ValidatedConfig, TP_STATUS_AVAILABLE, TP_STATUS_KERNEL, TP_STATUS_SENDING,
    TP_STATUS_SEND_REQUEST, TP_STATUS_USER,
};

const PAGE: usize = 4_096;
pub(super) const RX_BLOCK: usize = 262_144;
const FIRST_PACKET: usize = 64;
const MAX_FRAME: usize = 1_514;
const TX_FRAME: usize = 4_096;
const TX_DATA: usize = 48;
const MAC: usize = 82;
const FIRST_FD: RawFd = 100;
pub(super) const LAN_PORT: usize = 0;
pub(super) const WAN_PORT: usize = 1;
const ENDPOINTS: [TxEndpoint; 2] = [CONFORMANCE_LAN_ENDPOINT, CONFORMANCE_WAN_ENDPOINT];

fn raw_u32(address: usize) -> u32 {
    assert!(address.is_multiple_of(4));
    // SAFETY: callers pass addresses inside a live `ConformanceOps` mapping.
    // The engine reaches that memory only through raw pointers and the
    // harness never holds a Rust reference to it, so this volatile read does
    // not conflict with any borrow.
    unsafe { std::ptr::read_volatile(address as *const u32) }
}

fn raw_write_u32(address: usize, value: u32) {
    assert!(address.is_multiple_of(4));
    // SAFETY: as in `raw_u32`; the harness writes only kernel-owned words or
    // words of a block it is about to publish, never while the engine runs.
    unsafe { std::ptr::write_volatile(address as *mut u32, value) };
}

fn raw_write_u16(address: usize, value: u16) {
    assert!(address.is_multiple_of(2));
    // SAFETY: as in `raw_write_u32`.
    unsafe { std::ptr::write_volatile(address as *mut u16, value) };
}

fn raw_write_bytes(address: usize, bytes: &[u8]) {
    // SAFETY: as in `raw_write_u32`; the range lies inside the RX block the
    // harness is filling while the block is still kernel-owned.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len()) };
}

fn raw_read_bytes(address: usize, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    // SAFETY: as in `raw_u32`; the range is a published TX frame's payload.
    unsafe { std::ptr::copy_nonoverlapping(address as *const u8, bytes.as_mut_ptr(), len) };
    bytes
}

struct OpsState {
    next_fd: RawFd,
    mappings: Vec<(usize, usize)>,
    kicks: Vec<(RawFd, Result<(), i32>)>,
    kick_calls: usize,
    fail_next_kick: Option<i32>,
}

/// Scripted Linux stand-in. Kick records go into storage reserved up front,
/// so recording a kick never allocates while engine code runs.
#[derive(Clone)]
pub(super) struct ConformanceOps(Rc<RefCell<OpsState>>);

impl ConformanceOps {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(OpsState {
            next_fd: FIRST_FD,
            mappings: Vec::with_capacity(2),
            kicks: Vec::with_capacity(4_096),
            kick_calls: 0,
            fail_next_kick: None,
        })))
    }
}

impl PacketOps for ConformanceOps {
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
        // SAFETY: the layout has nonzero size (the engine rejects zero-length
        // mappings before calling `map`) and a valid power-of-two alignment.
        let base = unsafe { alloc_zeroed(layout) };
        let base = NonNull::new(base).ok_or(PlatformError::Syscall {
            stage: SyscallStage::Mmap,
            errno: Errno::new(12),
        })?;
        self.0
            .borrow_mut()
            .mappings
            .push((base.as_ptr() as usize, len));
        Ok(base)
    }

    fn kick(&mut self, fd: RawFd) -> Result<(), PlatformError> {
        let mut state = self.0.borrow_mut();
        state.kick_calls += 1;
        let result = state.fail_next_kick.take().map_or(Ok(()), Err);
        state.kicks.push((fd, result));
        result.map_err(|errno| PlatformError::Syscall {
            stage: SyscallStage::Kick,
            errno: Errno::new(errno),
        })
    }

    fn unmap(&mut self, base: NonNull<u8>, len: usize) {
        let layout = Layout::from_size_align(len, PAGE).expect("mapping layout");
        // SAFETY: the engine's mapping owner unmaps exactly once with the
        // pointer and length this `map` returned for that allocation.
        unsafe { dealloc(base.as_ptr(), layout) };
    }

    fn close(&mut self, _fd: RawFd) {}
}

/// Kernel-side view of one port's scripted mapping.
#[derive(Clone, Copy)]
pub(super) struct PortView {
    base: usize,
    tx_start: usize,
    tx_frames: usize,
    pub(super) interface: IfId,
    endpoint: TxEndpoint,
}

impl PortView {
    pub(super) fn rx_status(self) -> u32 {
        raw_u32(self.base + 8)
    }

    pub(super) fn set_rx_status(self, status: u32) {
        raw_write_u32(self.base + 8, status);
    }

    fn tx_frame(self, frame: usize) -> usize {
        assert!(frame < self.tx_frames);
        self.base + self.tx_start + frame * TX_FRAME
    }

    pub(super) fn tx_status(self, frame: usize) -> u32 {
        raw_u32(self.tx_frame(frame) + 20)
    }

    pub(super) fn set_tx_status(self, frame: usize, status: u32) {
        raw_write_u32(self.tx_frame(frame) + 20, status);
    }

    pub(super) fn tx_len(self, frame: usize) -> usize {
        raw_u32(self.tx_frame(frame) + 16) as usize
    }

    /// Simulates a stray write into a TX frame's payload (test of the
    /// harness's own detector).
    pub(super) fn overwrite_tx_payload_for_test(self, frame: usize, bytes: &[u8]) {
        raw_write_bytes(self.tx_data_address(frame), bytes);
    }

    fn tx_frame_bytes(self, frame: usize) -> Vec<u8> {
        raw_read_bytes(self.tx_frame(frame), TX_FRAME)
    }

    pub(super) fn tx_data_address(self, frame: usize) -> usize {
        self.tx_frame(frame) + TX_DATA
    }

    pub(super) fn tx_payload(self, frame: usize) -> Vec<u8> {
        raw_read_bytes(self.tx_data_address(frame), self.tx_len(frame))
    }

    /// Lays out `packets` in RX block 0 exactly as TPACKET_V3 does (each
    /// header followed by `tp_mac` headroom and the payload, aligned to eight
    /// bytes, the terminal `tp_next_offset` zero) and publishes USER last.
    /// A `SafePacket` fault gives one descriptor an invalid MAC offset; an
    /// `UnsafeChain` fault gives it an unsafe next link, and no later
    /// descriptor is written.
    fn write_block(
        self,
        token: CopyRxBlockToken,
        packets: &[Vec<u8>],
        fault: Option<(usize, CopyRxDescriptorFault)>,
    ) -> Vec<LiveCopyRxPacket> {
        assert_eq!(self.rx_status(), TP_STATUS_KERNEL, "RX block is not free");
        let written = match fault {
            Some((index, CopyRxDescriptorFault::UnsafeChain)) => index + 1,
            _ => packets.len(),
        };
        let mut offset = FIRST_PACKET;
        let mut live = Vec::with_capacity(packets.len());
        for (index, payload) in packets.iter().enumerate() {
            let total = (MAC + payload.len()).next_multiple_of(8);
            let last = index + 1 == packets.len();
            live.push(LiveCopyRxPacket {
                token: CopyRxPacketToken {
                    block: token,
                    packet_index: u32::try_from(index).expect("small block"),
                },
                visible_address: self.base + offset + MAC,
                requested_len: payload.len(),
            });
            if index < written {
                assert!(offset + total <= RX_BLOCK, "fixture exceeds RX block");
                let header = self.base + offset;
                let mut next = if last {
                    0
                } else {
                    u32::try_from(total).expect("small offset")
                };
                let mut mac = u16::try_from(MAC).expect("MAC offset");
                match fault {
                    Some((fault_index, CopyRxDescriptorFault::SafePacket))
                        if fault_index == index =>
                    {
                        mac = 80;
                    }
                    Some((fault_index, CopyRxDescriptorFault::UnsafeChain))
                        if fault_index == index =>
                    {
                        next = if last { 8 } else { next + 4 };
                    }
                    _ => {}
                }
                let length = u32::try_from(payload.len()).expect("small payload");
                raw_write_u32(header, next);
                raw_write_u32(header + 12, length);
                raw_write_u32(header + 16, length);
                raw_write_u32(header + 20, TP_STATUS_USER);
                raw_write_u16(header + 24, mac);
                raw_write_u16(header + 26, 96);
                raw_write_bytes(header + MAC, payload);
            }
            offset += total;
        }
        let block_len = if written < packets.len() {
            RX_BLOCK
        } else {
            offset
        };
        raw_write_u32(self.base, 2);
        raw_write_u32(self.base + 4, 48);
        raw_write_u32(
            self.base + 12,
            u32::try_from(packets.len()).expect("small count"),
        );
        raw_write_u32(self.base + 16, u32::try_from(FIRST_PACKET).expect("offset"));
        raw_write_u32(self.base + 20, u32::try_from(block_len).expect("length"));
        self.set_rx_status(TP_STATUS_USER);
        live
    }
}

fn frame_id(port: usize, frame: usize) -> u64 {
    ((port as u64) << 32) | frame as u64
}

fn decode_id(id: u64) -> (usize, usize) {
    ((id >> 32) as usize, (id & 0xffff_ffff) as usize)
}

struct PendingBlock {
    port: usize,
    token: CopyRxBlockToken,
    ingress: IfId,
    packets: Vec<LiveCopyRxPacket>,
    terminal: Vec<bool>,
    fault: Option<(usize, CopyRxDescriptorFault)>,
    at_inject: ProbeCounts,
}

struct InFlight {
    tx: LiveCopyTxFrame,
    frame: usize,
    sequence: u64,
}

pub(super) struct TxSnapshot {
    statuses: [Vec<u32>; 2],
    frames: [Vec<Vec<u8>>; 2],
    probes: [ProbeCounts; 2],
}

/// Observations shared by the decorator, the observer, and the harness.
pub(super) struct Trace {
    views: [PortView; 2],
    probes: [Rc<PortProbe>; 2],
    sources: BTreeMap<usize, LiveCopyRxPacket>,
    pending: Vec<PendingBlock>,
    scans: BTreeMap<CopyRxBlockToken, CopyRxScanObservation>,
    tx_generations: [Vec<u64>; 2],
    inflight: [VecDeque<InFlight>; 2],
    next_sequence: u64,
    source_events: Vec<CopySourceEvent>,
    tx_events: Vec<CopyTxEvent>,
    payloads: Vec<CopyPayloadObservation>,
    block_returns: Vec<CopyRxBlockReturn>,
    rx_faults: Vec<CopyRxFaultEvent>,
    unverified_tx: Vec<(usize, usize, u64)>,
    unverified_rx: Vec<(usize, u64)>,
    pub(super) expected_stats: [BackendStatsSnapshot; 2],
    steady_allocations: usize,
}

impl Trace {
    pub(super) fn tx_snapshot(&self) -> TxSnapshot {
        TxSnapshot {
            statuses: [0, 1].map(|port| {
                (0..self.views[port].tx_frames)
                    .map(|frame| self.views[port].tx_status(frame))
                    .collect()
            }),
            frames: [0, 1].map(|port| {
                (0..self.views[port].tx_frames)
                    .map(|frame| self.views[port].tx_frame_bytes(frame))
                    .collect()
            }),
            probes: [0, 1].map(|port| self.probes[port].counts()),
        }
    }

    /// Asserts that no TX frame changed across an engine call except the
    /// `published` ones, and that a published frame changed only in its
    /// header and payload. Independent of the engine's own copy counter.
    pub(super) fn assert_tx_unchanged_except(
        &self,
        before: &TxSnapshot,
        published: &[(usize, usize)],
    ) {
        for port in 0..2 {
            for frame in 0..self.views[port].tx_frames {
                let now = self.views[port].tx_frame_bytes(frame);
                let old = &before.frames[port][frame];
                if published.contains(&(port, frame)) {
                    let end = TX_DATA + self.views[port].tx_len(frame);
                    assert_eq!(
                        now[end..],
                        old[end..],
                        "published TX frame {frame} of port {port} changed past its payload"
                    );
                } else {
                    assert!(
                        now == *old,
                        "TX frame {frame} of port {port} changed without being published"
                    );
                }
            }
        }
    }

    fn mark_terminal(&mut self, source: LiveCopyRxPacket) {
        let block = self
            .pending
            .iter_mut()
            .find(|block| block.token == source.token.block)
            .expect("source block is pending");
        let index = source.token.packet_index as usize;
        assert!(!block.terminal[index], "source completed twice");
        block.terminal[index] = true;
    }

    fn record_completion(
        &mut self,
        address: usize,
        ingress: IfId,
        completion: SlotCompletion,
        before: &TxSnapshot,
    ) {
        let source = *self.sources.get(&address).expect("leased source identity");
        self.mark_terminal(source);
        let mut published = Vec::new();
        for port in 0..2 {
            for frame in 0..self.views[port].tx_frames {
                let now = self.views[port].tx_status(frame);
                if now == TP_STATUS_SEND_REQUEST && before.statuses[port][frame] != now {
                    published.push((port, frame));
                }
            }
        }
        self.assert_tx_unchanged_except(before, &published);
        let copies: usize = (0..2)
            .map(|port| self.probes[port].counts().tx_copies - before.probes[port].tx_copies)
            .sum();
        assert_eq!(
            copies,
            published.len(),
            "copy count disagrees with the ring"
        );
        let disposition = match completion {
            SlotCompletion::Transmit(egress) => {
                assert!(published.len() <= 1, "one commit published twice");
                if let Some(&(port, frame)) = published.first() {
                    let view = self.views[port];
                    self.tx_generations[port][frame] += 1;
                    let generation = self.tx_generations[port][frame];
                    let descriptor_len = view.tx_len(frame);
                    let tx = LiveCopyTxFrame {
                        token: CopyTxToken {
                            frame_id: frame_id(port, frame),
                            generation,
                        },
                        visible_address: view.tx_data_address(frame),
                        requested_len: descriptor_len,
                    };
                    let copied_bytes = self.probes[port].counts().tx_copied_bytes
                        - before.probes[port].tx_copied_bytes;
                    self.tx_events.push(CopyTxEvent {
                        source,
                        tx,
                        endpoint: view.endpoint,
                        descriptor_len,
                        disposition: CopyTxDisposition::Submitted,
                        copied_bytes,
                    });
                    self.payloads.push(CopyPayloadObservation {
                        source,
                        tx,
                        observed_payload: view.tx_payload(frame),
                    });
                    let sequence = self.next_sequence;
                    self.next_sequence += 1;
                    self.inflight[port].push_back(InFlight {
                        tx,
                        frame,
                        sequence,
                    });
                    self.unverified_tx.push((port, frame, generation));
                    CopySourceDisposition::TxAccepted {
                        tx,
                        endpoint: view.endpoint,
                    }
                } else {
                    // Reject-before-copy: no TX frame was reserved, so there
                    // is no TX token and no TX event.
                    CopySourceDisposition::TxRejected {
                        tx: None,
                        attempted_egress: egress,
                        endpoint: self
                            .views
                            .iter()
                            .find(|view| view.interface == egress)
                            .map(|view| view.endpoint),
                    }
                }
            }
            SlotCompletion::Recycle(reason) => {
                assert!(published.is_empty());
                CopySourceDisposition::Reclaimed(RxReclaim::Recycled(reason))
            }
            SlotCompletion::Consume(reason) => {
                assert!(published.is_empty());
                CopySourceDisposition::Reclaimed(RxReclaim::Consumed(reason))
            }
            SlotCompletion::LeaseAbandoned => {
                assert!(published.is_empty());
                CopySourceDisposition::Reclaimed(RxReclaim::Abandoned)
            }
        };
        self.source_events.push(CopySourceEvent {
            source,
            ingress,
            disposition,
        });
    }

    /// Detects RX blocks the engine handed back to the kernel since the last
    /// check. Unleased packets of a returned block were faults by
    /// construction; the per-port stats expectation records them so the
    /// next settle step checks the engine counted exactly those faults.
    fn check_returns(&mut self) {
        let mut index = 0;
        while index < self.pending.len() {
            let port = self.pending[index].port;
            let returned = self.views[port].rx_status() == TP_STATUS_KERNEL;
            let counted = self.probes[port].counts().rx_blocks_returned
                > self.pending[index].at_inject.rx_blocks_returned;
            assert_eq!(
                returned, counted,
                "RX block status and the engine's return count disagree"
            );
            if !returned {
                index += 1;
                continue;
            }
            let block = self.pending.remove(index);
            let frozen = self.probes[port].at_last_return();
            self.scans.insert(
                block.token,
                CopyRxScanObservation {
                    block_status_reads: frozen.rx_status_reads - block.at_inject.rx_status_reads,
                    block_acquisitions: frozen.rx_blocks_acquired
                        - block.at_inject.rx_blocks_acquired,
                    descriptor_validations: frozen.rx_descriptor_visits
                        - block.at_inject.rx_descriptor_visits,
                },
            );
            for (packet_index, source) in block.packets.iter().enumerate() {
                self.sources.remove(&source.visible_address);
                if block.terminal[packet_index] {
                    continue;
                }
                let (fault_index, fault) = block
                    .fault
                    .expect("block returned with an unleased valid packet");
                if fault == CopyRxDescriptorFault::SafePacket {
                    assert_eq!(packet_index, fault_index, "valid sibling was not leased");
                }
                self.source_events.push(CopySourceEvent {
                    source: *source,
                    ingress: block.ingress,
                    disposition: CopySourceDisposition::RxInvalid(fault),
                });
            }
            if let Some((packet_index, fault)) = block.fault {
                match fault {
                    CopyRxDescriptorFault::SafePacket => {
                        self.expected_stats[port].descriptor_rejected += 1;
                    }
                    CopyRxDescriptorFault::UnsafeChain => {
                        self.expected_stats[port].geometry_rejected += 1;
                    }
                }
                self.rx_faults.push(CopyRxFaultEvent {
                    block: block.token,
                    packet_index,
                    fault,
                });
            }
            self.block_returns.push(CopyRxBlockReturn {
                block: block.token,
                packet_count: block.packets.len(),
            });
            self.unverified_rx.push((port, block.token.generation));
        }
    }
}

/// Pass-through PacketIo decorator around the real engine.
pub(super) struct TracedIo {
    pub(super) engine: AfPacketEngine<ConformanceOps>,
    trace: Rc<RefCell<Trace>>,
}

impl PacketIo for TracedIo {
    type Error = AfPacketIoError;
    type Batch<'a> = TracedBatch<'a>;

    fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
        let before = allocation_count();
        let inner = self.engine.receive(budget);
        let after = allocation_count();
        self.trace.borrow_mut().steady_allocations += (after - before) as usize;
        Ok(TracedBatch {
            inner: Some(inner?),
            trace: Rc::clone(&self.trace),
        })
    }
}

pub(super) struct TracedBatch<'a> {
    inner: Option<AfPacketBatch<'a, ConformanceOps>>,
    trace: Rc<RefCell<Trace>>,
}

impl<'a> PacketBatch for TracedBatch<'a> {
    type Error = AfPacketIoError;
    type Slot<'b>
        = TracedSlot<'b, 'a>
    where
        Self: 'b;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        let snapshot = self.trace.borrow().tx_snapshot();
        let before = allocation_count();
        let lease = self.inner.as_mut().expect("live batch").next_packet();
        let after = allocation_count();
        {
            let mut trace = self.trace.borrow_mut();
            trace.steady_allocations += (after - before) as usize;
            trace.assert_tx_unchanged_except(&snapshot, &[]);
            trace.check_returns();
        }
        let mut lease = lease?;
        let ingress = lease.ingress();
        let source_address = lease.bytes_mut().as_ptr() as usize;
        assert!(self.trace.borrow().sources.contains_key(&source_address));
        Some(PacketLease::new(TracedSlot {
            inner: Some(lease),
            trace: Rc::clone(&self.trace),
            ingress,
            source_address,
        }))
    }

    fn finish(mut self) -> BatchCompletion<Self::Error> {
        let inner = self.inner.take().expect("live batch");
        let snapshot = self.trace.borrow().tx_snapshot();
        let before = allocation_count();
        let completion = inner.finish();
        let after = allocation_count();
        let mut trace = self.trace.borrow_mut();
        trace.steady_allocations += (after - before) as usize;
        trace.assert_tx_unchanged_except(&snapshot, &[]);
        trace.check_returns();
        assert!(completion.invariants_hold());
        completion
    }
}

impl Drop for TracedBatch<'_> {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            let snapshot = self.trace.borrow().tx_snapshot();
            let before = allocation_count();
            drop(inner);
            let after = allocation_count();
            let mut trace = self.trace.borrow_mut();
            trace.steady_allocations += (after - before) as usize;
            trace.assert_tx_unchanged_except(&snapshot, &[]);
            trace.check_returns();
        }
    }
}

pub(super) struct TracedSlot<'b, 'a> {
    inner: Option<PacketLease<AfPacketSlot<'b, 'a, ConformanceOps>>>,
    trace: Rc<RefCell<Trace>>,
    ingress: IfId,
    source_address: usize,
}

impl TracedSlot<'_, '_> {
    fn forward(&mut self, completion: SlotCompletion) {
        let lease = self.inner.take().expect("traced slot completed once");
        let snapshot = self.trace.borrow().tx_snapshot();
        let before = allocation_count();
        match completion {
            SlotCompletion::Transmit(egress) => lease.commit(egress),
            SlotCompletion::Recycle(reason) => lease.recycle(reason),
            SlotCompletion::Consume(reason) => lease.consume(reason),
            SlotCompletion::LeaseAbandoned => drop(lease),
        }
        let after = allocation_count();
        let mut trace = self.trace.borrow_mut();
        trace.steady_allocations += (after - before) as usize;
        trace.record_completion(self.source_address, self.ingress, completion, &snapshot);
        trace.check_returns();
    }
}

impl PacketSlot for TracedSlot<'_, '_> {
    fn ingress(&self) -> IfId {
        self.ingress
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.inner.as_mut().expect("live traced slot").bytes_mut()
    }

    fn complete(mut self, completion: SlotCompletion) {
        self.forward(completion);
    }
}

impl Drop for TracedSlot<'_, '_> {
    fn drop(&mut self) {
        if self.inner.is_some() {
            self.forward(SlotCompletion::LeaseAbandoned);
        }
    }
}

pub(super) struct TracedObserver(Rc<RefCell<Trace>>);

impl CopyLeaseObserver for TracedObserver {
    fn observe_source(&self, bytes: &[u8]) -> LiveCopyRxPacket {
        let live = *self
            .0
            .borrow()
            .sources
            .get(&(bytes.as_ptr() as usize))
            .expect("source bytes have no live identity");
        assert_eq!(bytes.len(), live.requested_len);
        live
    }
}

/// Conformance harness over `TX_FRAMES` frames per TX ring.
pub(super) struct AfPacketCopyHarness<const TX_FRAMES: u32> {
    pub(super) io: TracedIo,
    observer: TracedObserver,
    ops: ConformanceOps,
    completion_budget: usize,
    head_sending: bool,
}

pub(super) type DefaultHarness = AfPacketCopyHarness<4>;
pub(super) type OneFrameHarness = AfPacketCopyHarness<1>;

impl<const TX_FRAMES: u32> AfPacketCopyHarness<TX_FRAMES> {
    fn config() -> ValidatedConfig {
        let rx = RingGeometry {
            block_size: u32::try_from(RX_BLOCK).expect("block size"),
            block_count: 1,
            frame_size: 2_048,
            frame_count: u32::try_from(RX_BLOCK / 2_048).expect("frame count"),
            retire_timeout_ms: 10,
            private_size: 16,
            feature_flags: 1,
        };
        let tx = RingGeometry {
            block_size: u32::try_from(TX_FRAME).expect("block size"),
            block_count: TX_FRAMES,
            frame_size: u32::try_from(TX_FRAME).expect("frame size"),
            frame_count: TX_FRAMES,
            retire_timeout_ms: 0,
            private_size: 0,
            feature_flags: 0,
        };
        let ports = [CONFORMANCE_LAN, CONFORMANCE_WAN].map(|interface| PortConfig {
            interface,
            if_index: u32::from(interface.0),
            rx,
            tx,
        });
        ValidatedConfig::new(&ports, PAGE, MAX_FRAME).expect("conformance config")
    }

    pub(super) fn trace(&self) -> std::cell::RefMut<'_, Trace> {
        self.io.trace.borrow_mut()
    }

    pub(super) fn view(&self, port: usize) -> PortView {
        self.io.trace.borrow().views[port]
    }

    /// Checks every identity reported since the last harness operation
    /// against engine metadata, and the per-port stats against the faults
    /// the harness observed.
    pub(super) fn settle(&mut self) {
        let engine = &self.io.engine;
        let mut trace = self.io.trace.borrow_mut();
        for (port, frame, generation) in trace.unverified_tx.drain(..) {
            assert_eq!(
                engine.ports[port].tx_metadata(frame).generation,
                generation,
                "reported TX generation differs from engine metadata"
            );
        }
        for (port, generation) in trace.unverified_rx.drain(..) {
            assert_eq!(
                engine.ports[port].metadata.rx_blocks()[0].generation,
                generation,
                "reported RX block generation differs from engine metadata"
            );
        }
        for port in 0..2 {
            assert_eq!(engine.ports[port].rx_stats(), trace.expected_stats[port]);
        }
    }

    fn inject(
        &mut self,
        ingress: IfId,
        packets: Vec<Vec<u8>>,
        fault: Option<(usize, CopyRxDescriptorFault)>,
    ) -> InjectedCopyRxBlock {
        self.settle();
        assert!(!packets.is_empty());
        let port = self
            .io
            .engine
            .table
            .lookup(ingress)
            .expect("known ingress")
            .get();
        let generation = self.io.engine.ports[port].metadata.rx_blocks()[0]
            .generation
            .checked_add(1)
            .expect("RX generation");
        let token = CopyRxBlockToken {
            block_id: frame_id(port, 0),
            generation,
        };
        let mut trace = self.io.trace.borrow_mut();
        assert!(
            trace.pending.iter().all(|block| block.port != port),
            "one-block ring already holds a pending block"
        );
        let at_inject = trace.probes[port].counts();
        let live = trace.views[port].write_block(token, &packets, fault);
        let written = match fault {
            Some((index, CopyRxDescriptorFault::UnsafeChain)) => index + 1,
            _ => live.len(),
        };
        for source in &live[..written] {
            assert!(trace
                .sources
                .insert(source.visible_address, *source)
                .is_none());
        }
        trace.pending.push(PendingBlock {
            port,
            token,
            ingress,
            packets: live.clone(),
            terminal: vec![false; live.len()],
            fault,
            at_inject,
        });
        InjectedCopyRxBlock {
            block: token,
            packets: live,
        }
    }

    fn tx_frames_with(&self, port: usize, available: bool) -> usize {
        let resources = &self.io.engine.ports[port];
        (0..resources.tx_frame_count())
            .filter(|frame| {
                (resources.tx_metadata(*frame).ownership.owner() == TxOwnership::Available)
                    == available
            })
            .count()
    }
}

impl<const TX_FRAMES: u32> RxCopyHarness for AfPacketCopyHarness<TX_FRAMES> {
    type Io = TracedIo;
    type Observer = TracedObserver;

    fn new() -> Self {
        let ops = ConformanceOps::new();
        let engine =
            AfPacketEngine::open_with_ops(Self::config(), ops.clone()).expect("conformance engine");
        let mappings = ops.0.borrow().mappings.clone();
        assert_eq!(mappings.len(), 2);
        let views = [0, 1].map(|port| {
            let resources = &engine.ports[port];
            assert_eq!(resources.rx.block_plus_private(), FIRST_PACKET);
            assert_eq!(mappings[port].1, resources.extents.combined_len());
            PortView {
                base: mappings[port].0,
                tx_start: resources.extents.tx().start(),
                tx_frames: resources.tx_frame_count(),
                interface: resources.interface,
                endpoint: ENDPOINTS[port],
            }
        });
        let probes = [0, 1].map(|port| Rc::clone(&engine.ports[port].probe));
        let tx_generations = [0, 1].map(|port| vec![0; views[port].tx_frames]);
        let trace = Rc::new(RefCell::new(Trace {
            views,
            probes,
            sources: BTreeMap::new(),
            pending: Vec::new(),
            scans: BTreeMap::new(),
            tx_generations,
            inflight: [VecDeque::new(), VecDeque::new()],
            next_sequence: 0,
            source_events: Vec::new(),
            tx_events: Vec::new(),
            payloads: Vec::new(),
            block_returns: Vec::new(),
            rx_faults: Vec::new(),
            unverified_tx: Vec::new(),
            unverified_rx: Vec::new(),
            expected_stats: [engine.ports[0].rx_stats(), engine.ports[1].rx_stats()],
            steady_allocations: 0,
        }));
        Self {
            io: TracedIo {
                engine,
                trace: Rc::clone(&trace),
            },
            observer: TracedObserver(trace),
            ops,
            completion_budget: usize::MAX,
            head_sending: false,
        }
    }

    fn io_and_observer(&mut self) -> (&mut Self::Io, &mut Self::Observer) {
        (&mut self.io, &mut self.observer)
    }

    fn inject_rx_block(&mut self, ingress: IfId, packets: Vec<Vec<u8>>) -> InjectedCopyRxBlock {
        self.inject(ingress, packets, None)
    }

    fn set_copy_tx_accept_budget(&mut self, _budget: usize) {
        panic!(
            "not applicable to AF_PACKET: rejection happens before any TX frame is \
             reserved, so there is no reserve-then-reject accept budget"
        );
    }

    fn set_copy_operation_budgets(&mut self, budgets: CopyOperationBudgets) {
        self.io.engine.set_work_limits(WorkLimits {
            rx_block_status_reads_per_port: budgets.rx_block_status_reads,
            rx_descriptor_visits_per_port: budgets.rx_descriptor_visits,
            tx_submit_status_reads: budgets.tx_submit_status_reads,
        });
        self.completion_budget = budgets.tx_completion_status_reads;
    }

    fn pending_copy_rx_packets(&self) -> usize {
        self.io
            .trace
            .borrow()
            .pending
            .iter()
            .map(|block| block.terminal.iter().filter(|done| !**done).count())
            .sum()
    }

    fn free_copy_tx_frames(&self) -> usize {
        self.tx_frames_with(WAN_PORT, true)
    }

    fn inflight_copy_tx_frames(&self) -> usize {
        self.tx_frames_with(WAN_PORT, false)
    }

    fn copy_operation_counters(&self) -> CopyOperationCounters {
        let trace = self.io.trace.borrow();
        let lan = trace.probes[LAN_PORT].counts();
        let all = [0, 1].map(|port| trace.probes[port].counts());
        CopyOperationCounters {
            rx_block_status_reads: lan.rx_status_reads,
            rx_descriptor_visits: lan.rx_descriptor_visits,
            tx_submit_status_reads: all.iter().map(|c| c.tx_submit_status_reads).sum(),
            tx_completion_status_reads: all.iter().map(|c| c.tx_completion_status_reads).sum(),
            copy_invocations: all.iter().map(|c| c.tx_copies).sum(),
            copied_bytes: all.iter().map(|c| c.tx_copied_bytes).sum(),
            kick_syscalls: self.ops.0.borrow().kick_calls,
            steady_allocations: trace.steady_allocations,
        }
    }

    fn production_payload_hook_enabled(&self) -> bool {
        // The engine has no payload hook; payloads are read from the TX ring
        // by this harness, playing the wire.
        false
    }

    fn copy_rx_scan_observation(&self, block: CopyRxBlockToken) -> CopyRxScanObservation {
        let trace = self.io.trace.borrow();
        if let Some(scan) = trace.scans.get(&block) {
            return *scan;
        }
        trace
            .pending
            .iter()
            .find(|pending| pending.token == block)
            .map_or_else(CopyRxScanObservation::default, |pending| {
                let now = trace.probes[pending.port].counts();
                CopyRxScanObservation {
                    block_status_reads: now.rx_status_reads - pending.at_inject.rx_status_reads,
                    block_acquisitions: now.rx_blocks_acquired
                        - pending.at_inject.rx_blocks_acquired,
                    descriptor_validations: now.rx_descriptor_visits
                        - pending.at_inject.rx_descriptor_visits,
                }
            })
    }

    fn drain_copy_source_events(&mut self) -> Vec<CopySourceEvent> {
        self.settle();
        std::mem::take(&mut self.trace().source_events)
    }

    fn drain_copy_tx_events(&mut self) -> Vec<CopyTxEvent> {
        self.settle();
        std::mem::take(&mut self.trace().tx_events)
    }

    fn drain_copy_rx_block_returns(&mut self) -> Vec<CopyRxBlockReturn> {
        self.settle();
        std::mem::take(&mut self.trace().block_returns)
    }

    fn drain_copy_tx_kicks(&mut self) -> Vec<CopyKickEvent> {
        self.ops
            .0
            .borrow_mut()
            .kicks
            .drain(..)
            .map(|(fd, result)| CopyKickEvent {
                endpoint: ENDPOINTS[usize::try_from(fd - FIRST_FD).expect("port fd")],
                result: result.map_err(CopyErrno),
            })
            .collect()
    }
}

impl<const TX_FRAMES: u32> RxCopyKickErrorHarness for AfPacketCopyHarness<TX_FRAMES> {
    fn fail_next_copy_kick(&mut self, errno: CopyErrno) {
        self.ops.0.borrow_mut().fail_next_kick = Some(errno.0);
    }
}

impl<const TX_FRAMES: u32> RxCopyUnknownEgressHarness for AfPacketCopyHarness<TX_FRAMES> {}

impl<const TX_FRAMES: u32> RxCopyCompletionHarness for AfPacketCopyHarness<TX_FRAMES> {
    fn complete_copy_submissions(&mut self) -> Vec<CopyTxCompletion> {
        self.settle();
        let head_sending = self.head_sending;
        let mut remaining = self.completion_budget;
        let mut completed = Vec::new();
        for (port, endpoint) in ENDPOINTS.into_iter().enumerate() {
            {
                // Kernel side: every in-flight frame was transmitted, except
                // an oldest one that the case marks as still SENDING.
                let trace = self.io.trace.borrow();
                let head = trace
                    .inflight
                    .iter()
                    .flat_map(|queue| queue.front())
                    .map(|entry| entry.sequence)
                    .min();
                for entry in &trace.inflight[port] {
                    let status = if head_sending && Some(entry.sequence) == head {
                        TP_STATUS_SENDING
                    } else {
                        TP_STATUS_AVAILABLE
                    };
                    trace.views[port].set_tx_status(entry.frame, status);
                }
            }
            if remaining == 0 {
                continue;
            }
            let interface = self.view(port).interface;
            let snapshot = self.trace().tx_snapshot();
            let reads_before = self.trace().probes[port]
                .counts()
                .tx_completion_status_reads;
            let before = allocation_count();
            let report = self
                .io
                .engine
                .scan_completions(interface, remaining)
                .expect("TX completion scan");
            let after = allocation_count();
            let mut trace = self.trace();
            trace.steady_allocations += (after - before) as usize;
            // Completion reclaims frames without touching their bytes; the
            // suite never produces WRONG_FORMAT, whose recycle writes status.
            assert_eq!(report.wrong_format, 0);
            trace.assert_tx_unchanged_except(&snapshot, &[]);
            let reads = trace.probes[port].counts().tx_completion_status_reads - reads_before;
            assert_eq!(reads, report.inspected);
            remaining -= report.inspected;
            for _ in 0..report.reclaimed {
                let entry = trace.inflight[port]
                    .pop_front()
                    .expect("reclaimed in flight");
                completed.push(CopyTxCompletion {
                    tx: entry.tx,
                    endpoint,
                });
            }
        }
        for completion in &completed {
            let (port, frame) = decode_id(completion.tx.token.frame_id);
            assert_eq!(
                self.io.engine.ports[port]
                    .tx_metadata(frame)
                    .ownership
                    .owner(),
                TxOwnership::Available
            );
        }
        completed
    }

    fn prefer_copy_tx_frame(&mut self, frame_id: u64) {
        self.settle();
        let (port, frame) = decode_id(frame_id);
        assert_eq!(
            self.io.engine.ports[port].tx_state.producer_head, frame,
            "AF_PACKET's FIFO TX ring cannot select frame {frame}; it is not the producer head"
        );
    }

    fn prefer_copy_rx_block(&mut self, block_id: u64) {
        self.settle();
        let (port, block) = decode_id(block_id);
        assert_eq!(block, 0, "the one-block RX ring always fills block 0 next");
        assert_eq!(self.view(port).rx_status(), TP_STATUS_KERNEL);
    }

    fn set_copy_completion_head_sending(&mut self, sending: bool) {
        assert!(
            self.trace().inflight.iter().any(|queue| !queue.is_empty()),
            "submitted TX head"
        );
        self.head_sending = sending;
    }
}

impl<const TX_FRAMES: u32> RxCopyPayloadHarness for AfPacketCopyHarness<TX_FRAMES> {
    fn drain_copy_payload_observations(&mut self) -> Vec<CopyPayloadObservation> {
        self.settle();
        std::mem::take(&mut self.trace().payloads)
    }
}

impl<const TX_FRAMES: u32> RxCopyAdversarialHarness for AfPacketCopyHarness<TX_FRAMES> {
    fn inject_rx_block_with_fault(
        &mut self,
        ingress: IfId,
        packets: Vec<Vec<u8>>,
        packet_index: usize,
        fault: CopyRxDescriptorFault,
    ) -> InjectedCopyRxBlock {
        assert!(packet_index < packets.len());
        self.inject(ingress, packets, Some((packet_index, fault)))
    }

    fn drain_copy_rx_faults(&mut self) -> Vec<CopyRxFaultEvent> {
        self.settle();
        std::mem::take(&mut self.trace().rx_faults)
    }
}

#[test]
fn af_packet_copy_conformance_01_zero_budget() {
    rx_copy::zero_budget_does_not_scan_or_advance::<DefaultHarness>();
}

#[test]
fn af_packet_copy_conformance_02_persistent_cursor() {
    rx_copy::split_budgets_resume_without_rescan_or_early_block_return::<DefaultHarness>();
}

#[test]
fn af_packet_copy_conformance_03_batch_drop() {
    rx_copy::dropped_batch_preserves_unleased_cursor::<DefaultHarness>();
}

#[test]
fn af_packet_copy_conformance_04_distinct_exact_copy() {
    rx_copy::transmit_uses_distinct_tx_storage_and_exact_payload::<DefaultHarness>();
}

#[test]
fn af_packet_copy_conformance_06_block_terminal_partition() {
    rx_copy::recycle_consume_abandon_delay_block_return::<DefaultHarness>();
}

#[test]
fn af_packet_copy_conformance_07_unknown_egress() {
    rx_copy::unknown_egress_touches_no_tx_or_kick::<DefaultHarness>();
}

#[test]
fn af_packet_copy_conformance_09_independent_completion() {
    rx_copy::source_block_returns_before_independent_tx_completion::<DefaultHarness>();
}

#[test]
fn af_packet_copy_conformance_10_tx_generation_on_one_frame_ring() {
    rx_copy::completed_tx_reuse_advances_generation::<OneFrameHarness>();
}

#[test]
fn af_packet_copy_conformance_11_kick_deduplication_with_hairpin() {
    rx_copy::one_batch_kicks_each_endpoint_at_most_once::<DefaultHarness>();
}

#[test]
fn af_packet_copy_conformance_12_tx_pool_exhaustion() {
    rx_copy::tx_pool_exhaustion_is_partial_and_source_terminal::<DefaultHarness>();
}

#[test]
fn af_packet_copy_conformance_13_validation_budgets_and_faults() {
    rx_copy::validation_budgets_and_fault_advance_are_bounded::<DefaultHarness>();
}

#[test]
fn af_packet_copy_conformance_14_submit_budget_precedes_copy() {
    rx_copy::submit_status_budget_precedes_copy::<DefaultHarness>();
}

#[test]
fn af_packet_copy_conformance_15_completion_budget_and_head_stop() {
    rx_copy::completion_budget_and_sending_head_are_bounded::<DefaultHarness>();
}

#[test]
fn af_packet_copy_conformance_16_completion_capable_batch_drop() {
    rx_copy::completion_capable_batch_drop_is_exact::<DefaultHarness>();
}

#[test]
fn af_packet_copy_conformance_17_kick_errno() {
    rx_copy::kick_errno_has_no_retry_or_reclassification::<DefaultHarness>();
}

#[test]
fn af_packet_copy_conformance_19_rx_block_aba() {
    rx_copy::returned_rx_block_reuse_advances_generation::<DefaultHarness>();
}

#[test]
fn af_packet_copy_conformance_20_safe_fault_terminal_positions() {
    rx_copy::safe_packet_fault_positions_are_terminal_exactly_once::<DefaultHarness>();
}
