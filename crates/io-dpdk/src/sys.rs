//! Raw DPDK FFI, and the live `DpdkIo`/`DpdkGeneratedBatch`/`DpdkGeneratedSlot`
//! backend built on it.
//!
//! `unsafe` is confined to this module, mirroring `ruster-io-afpacket`'s
//! `sys`: `lib.rs` carries `#![deny(unsafe_code)]` and lifts that ban only
//! for this module, which also carries the concrete backend types
//! themselves (as `ruster-io-afpacket::sys` does for `AfPacketIo` and
//! friends) so every raw pointer stays behind one boundary. `struct rte_mbuf`
//! and `struct rte_mempool` are never re-declared here: both are opaque, and
//! every field this crate needs is read through a shim function compiled
//! from `src/shim.c`, which includes the real DPDK headers. `rte_eal_init`,
//! `rte_eal_cleanup`, `rte_pktmbuf_pool_create`, `rte_eth_dev_count_avail`,
//! and `rte_eth_dev_start/stop/close` are genuine exported DPDK symbols and
//! are declared directly; `rte_eth_tx_burst`,
//! `rte_pktmbuf_alloc`, `rte_pktmbuf_free`, and `rte_pktmbuf_append` are
//! `static inline` in the DPDK headers and have no linkable symbol of their
//! own, so `src/shim.c` gives each one a real one (it does the same for
//! `rte_eth_rx_burst`, unused today but kept so a future RX path does not
//! need a second shim pass).
//!
//! Scope: only `GeneratedPacketIo`/`GeneratedPacketBatch`/`GeneratedPacketSlot`
//! (TX-only frame generation) are implemented here, matching requirement
//! IO-009. There is no `PacketIo`/RX path: DPDK ports are configured with
//! zero RX queues, and neither `rte_eth_rx_burst` nor any mbuf-reading
//! accessor is declared, since nothing in this crate calls them.

use std::{
    ffi::{c_char, c_int, c_uint, CString},
    ptr::NonNull,
};

use crate::error::{DpdkError, EalStage, EthdevStage};

/// `#define SOCKET_ID_ANY (-1)` in `rte_common.h`.
const SOCKET_ID_ANY: c_int = -1;

#[repr(C)]
pub(crate) struct RteMempool {
    _opaque: [u8; 0],
}

#[repr(C)]
pub(crate) struct RteMbuf {
    _opaque: [u8; 0],
}

extern "C" {
    fn rte_eal_init(argc: c_int, argv: *mut *mut c_char) -> c_int;
    fn rte_eal_cleanup() -> c_int;
    fn rte_pktmbuf_pool_create(
        name: *const c_char,
        n: c_uint,
        cache_size: c_uint,
        priv_size: u16,
        data_room_size: u16,
        socket_id: c_int,
    ) -> *mut RteMempool;
    fn rte_eth_dev_count_avail() -> u16;
    fn rte_eth_dev_start(port_id: u16) -> c_int;
    fn rte_eth_dev_stop(port_id: u16) -> c_int;
    fn rte_eth_dev_close(port_id: u16) -> c_int;

    fn ruster_dpdk_eth_dev_configure(port_id: u16, nb_rx_q: u16, nb_tx_q: u16) -> c_int;
    fn ruster_dpdk_eth_tx_queue_setup(port_id: u16, queue_id: u16, nb_desc: u16) -> c_int;
    fn ruster_dpdk_tx_burst(
        port_id: u16,
        queue_id: u16,
        pkts: *mut *mut RteMbuf,
        nb_pkts: u16,
    ) -> u16;
    fn ruster_dpdk_pktmbuf_alloc(pool: *mut RteMempool) -> *mut RteMbuf;
    fn ruster_dpdk_pktmbuf_free(mbuf: *mut RteMbuf);
    fn ruster_dpdk_pktmbuf_append(mbuf: *mut RteMbuf, len: u16) -> *mut u8;
    #[cfg(feature = "test-hooks")]
    fn ruster_dpdk_mempool_avail_count(pool: *const RteMempool) -> c_uint;
    fn ruster_dpdk_rte_errno() -> c_int;
}

/// Calls `rte_eal_init` exactly once for the process. DPDK's EAL is a
/// process-global singleton: a second call always fails, so callers must
/// serialize construction (`DpdkIo::open` does).
pub(crate) fn eal_init(args: &[String]) -> Result<(), DpdkError> {
    let program_name = CString::new("ruster-io-dpdk").expect("no interior NUL");
    let owned: Vec<CString> = args
        .iter()
        .map(|arg| CString::new(arg.as_str()).expect("EAL argument has no interior NUL"))
        .collect();
    let mut argv: Vec<*mut c_char> = std::iter::once(program_name.as_ptr() as *mut c_char)
        .chain(owned.iter().map(|arg| arg.as_ptr() as *mut c_char))
        .collect();
    let argc = c_int::try_from(argv.len()).expect("EAL argument count fits c_int");
    // SAFETY: `argv` holds `argc` valid, NUL-terminated C strings owned by
    // `program_name`/`owned`, both alive for this whole call. DPDK copies
    // what it needs out of `argv` before returning; it retains no pointer
    // into it afterward.
    let parsed = unsafe { rte_eal_init(argc, argv.as_mut_ptr()) };
    if parsed < 0 {
        return Err(DpdkError::Eal {
            stage: EalStage::Init,
            // SAFETY: no pointer/length argument; reads the current
            // thread's `rte_errno` sampled immediately after the failure.
            errno: unsafe { ruster_dpdk_rte_errno() },
        });
    }
    Ok(())
}

/// Best-effort: called only from `Drop`, where there is no way to surface a
/// failure.
pub(crate) fn eal_cleanup() {
    // SAFETY: no arguments; DPDK documents this as safe once every port this
    // process opened has already been stopped and closed.
    let _ = unsafe { rte_eal_cleanup() };
}

#[must_use]
pub(crate) fn eth_dev_count_avail() -> u16 {
    // SAFETY: no arguments.
    unsafe { rte_eth_dev_count_avail() }
}

pub(crate) fn pool_create(
    name: &str,
    capacity: u32,
    cache_size: u32,
    data_room_size: u16,
) -> Result<NonNull<RteMempool>, DpdkError> {
    let name = CString::new(name).expect("mbuf pool name has no interior NUL");
    // SAFETY: `name` is a valid, live NUL-terminated C string for the call.
    // `priv_size` is zero: this backend keeps no per-mbuf private area.
    let pool = unsafe {
        rte_pktmbuf_pool_create(
            name.as_ptr(),
            capacity,
            cache_size,
            0,
            data_room_size,
            SOCKET_ID_ANY,
        )
    };
    NonNull::new(pool).ok_or(DpdkError::PoolCreateFailed)
}

pub(crate) fn eth_dev_configure(port_id: u16, nb_tx_queues: u16) -> Result<(), DpdkError> {
    // SAFETY: no pointer arguments beyond the shim's own stack-local config.
    let rc = unsafe { ruster_dpdk_eth_dev_configure(port_id, 0, nb_tx_queues) };
    ethdev_result(EthdevStage::Configure, port_id, rc)
}

pub(crate) fn eth_tx_queue_setup(port_id: u16, nb_desc: u16) -> Result<(), DpdkError> {
    // SAFETY: no pointer arguments; queue 0 is this backend's only TX queue.
    let rc = unsafe { ruster_dpdk_eth_tx_queue_setup(port_id, 0, nb_desc) };
    ethdev_result(EthdevStage::TxQueueSetup, port_id, rc)
}

pub(crate) fn eth_dev_start(port_id: u16) -> Result<(), DpdkError> {
    // SAFETY: no pointer arguments.
    let rc = unsafe { rte_eth_dev_start(port_id) };
    ethdev_result(EthdevStage::Start, port_id, rc)
}

/// Best-effort: called only from `Drop`.
pub(crate) fn eth_dev_stop(port_id: u16) {
    // SAFETY: no pointer arguments.
    let _ = unsafe { rte_eth_dev_stop(port_id) };
}

/// Best-effort: called only from `Drop`.
pub(crate) fn eth_dev_close(port_id: u16) {
    // SAFETY: no pointer arguments.
    let _ = unsafe { rte_eth_dev_close(port_id) };
}

fn ethdev_result(stage: EthdevStage, port_id: u16, rc: c_int) -> Result<(), DpdkError> {
    if rc < 0 {
        Err(DpdkError::Ethdev {
            stage,
            port_id,
            errno: -rc,
        })
    } else {
        Ok(())
    }
}

/// Allocates one mbuf from `pool`, or `None` if the pool is exhausted.
pub(crate) fn pktmbuf_alloc(pool: NonNull<RteMempool>) -> Option<NonNull<RteMbuf>> {
    // SAFETY: `pool` was returned live by `pool_create` and outlives every
    // call made through this handle.
    let mbuf = unsafe { ruster_dpdk_pktmbuf_alloc(pool.as_ptr()) };
    NonNull::new(mbuf)
}

/// Returns `mbuf` to its pool. `mbuf` must not be used again afterward.
pub(crate) fn pktmbuf_free(mbuf: NonNull<RteMbuf>) {
    // SAFETY: `mbuf` came from `pktmbuf_alloc` and has not already been
    // freed, submitted, or otherwise consumed; the caller gives up
    // ownership of it in this call.
    unsafe { ruster_dpdk_pktmbuf_free(mbuf.as_ptr()) }
}

/// Reserves `len` bytes at the tail of a freshly allocated (empty) `mbuf`
/// and returns a writable pointer to them, or `None` if `len` exceeds the
/// pool's per-mbuf data room.
pub(crate) fn pktmbuf_append(mbuf: NonNull<RteMbuf>, len: u16) -> Option<NonNull<u8>> {
    // SAFETY: `mbuf` is live and owned by the caller for the duration of
    // this call.
    let data = unsafe { ruster_dpdk_pktmbuf_append(mbuf.as_ptr(), len) };
    NonNull::new(data)
}

#[cfg(feature = "test-hooks")]
#[must_use]
pub(crate) fn mempool_avail_count(pool: NonNull<RteMempool>) -> u32 {
    // SAFETY: `pool` was returned live by `pool_create` and outlives every
    // call made through this handle.
    unsafe { ruster_dpdk_mempool_avail_count(pool.as_ptr()) }
}

/// Submits `pkts` for transmission, taking ownership of exactly the mbufs at
/// indices `[0, return value)`. The caller retains ownership of the rest,
/// which DPDK never touched.
pub(crate) fn tx_burst(port_id: u16, pkts: &mut [NonNull<RteMbuf>]) -> u16 {
    let len = u16::try_from(pkts.len()).expect("TX batch fits a u16 burst");
    // SAFETY: `pkts` is a live, exclusively-borrowed array of `len` valid
    // mbuf pointers; queue 0 is this backend's only TX queue.
    unsafe { ruster_dpdk_tx_burst(port_id, 0, pkts.as_mut_ptr().cast(), len) }
}

/// Builds a `&mut [u8]` over `len` bytes at `data`.
///
/// The lifetime is inferred at the call site rather than named here; the
/// only caller, [`DpdkGeneratedSlot::bytes_mut`], returns it bound to its own
/// `&mut self`, which is itself bounded by the slot's borrow of the batch.
/// That chain is exactly what keeps this sound: `data` stays valid and
/// exclusively borrowed for as long as the slot the borrow-checker ties it
/// to is alive.
fn mbuf_bytes_mut<'a>(data: NonNull<u8>, len: usize) -> &'a mut [u8] {
    // SAFETY: `data` was returned live by `pktmbuf_append` for exactly `len`
    // bytes, and nothing else reads or writes it until `complete` runs.
    unsafe { std::slice::from_raw_parts_mut(data.as_ptr(), len) }
}

// ---------------------------------------------------------------------------
// Live backend: DpdkIo / DpdkGeneratedBatch / DpdkGeneratedSlot
// ---------------------------------------------------------------------------

#[cfg(feature = "test-hooks")]
use std::collections::VecDeque;

use ruster_core::{
    GeneratedAllocationError, GeneratedBatchCompletion, GeneratedPacketBatch, GeneratedPacketIo,
    GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion, IfId,
};

use crate::{
    config::ValidatedConfig,
    stats::{BackendStat, BackendStats, BackendStatsSnapshot},
};

/// Upper bound on how many frames one `finish()` ever hands to a single
/// `rte_eth_tx_burst` call. Sizes `DpdkIo::scratch`'s one-time reservation,
/// so accumulating commits inside a batch never allocates.
const MAX_GENERATED_BATCH: usize = 64;

struct PortState {
    interface: IfId,
    port_id: u16,
}

/// A live DPDK generated-frame backend: one shared mbuf pool and one or more
/// single-TX-queue ports, each bound to a Ruster interface.
///
/// Owns EAL initialization itself: DPDK's EAL is a process-global singleton,
/// so at most one `DpdkIo` may exist per process, and `Drop` runs
/// `rte_eal_cleanup`.
pub struct DpdkIo {
    pool: NonNull<RteMempool>,
    ports: Box<[PortState]>,
    max_frame_len: u16,
    stats: BackendStats,
    /// Committed mbufs waiting for the one `tx_burst` call `finish()` makes.
    /// Reserved once at construction; never reallocated afterward.
    scratch: Vec<NonNull<RteMbuf>>,
    #[cfg(feature = "test-hooks")]
    hooks: TestHooks,
}

fn configure_and_start_port(port_id: u16, nb_tx_desc: u16) -> Result<(), DpdkError> {
    eth_dev_configure(port_id, 1)?;
    eth_tx_queue_setup(port_id, nb_tx_desc)?;
    eth_dev_start(port_id)?;
    Ok(())
}

impl DpdkIo {
    /// Runs `rte_eal_init`, creates the shared mbuf pool, and configures,
    /// sets up, and starts every port in `config`. Rolls back everything it
    /// already brought up before returning an error.
    pub fn open(config: ValidatedConfig) -> Result<Self, DpdkError> {
        eal_init(config.eal_args())?;

        let pool = match pool_create(
            "ruster_dpdk_pool",
            config.pool_capacity(),
            config.pool_cache_size(),
            config.data_room_size(),
        ) {
            Ok(pool) => pool,
            Err(source) => {
                eal_cleanup();
                return Err(source);
            }
        };

        let mut started: Vec<u16> = Vec::with_capacity(config.ports().len());
        let available = eth_dev_count_avail();
        for port in config.ports() {
            let result = if port.port_id >= available {
                Err(DpdkError::PortUnavailable {
                    port_id: port.port_id,
                    available,
                })
            } else {
                configure_and_start_port(port.port_id, config.tx_ring_descriptors())
            };
            if let Err(source) = result {
                for port_id in started {
                    eth_dev_stop(port_id);
                    eth_dev_close(port_id);
                }
                eal_cleanup();
                return Err(source);
            }
            started.push(port.port_id);
        }

        let ports = config
            .ports()
            .iter()
            .map(|port| PortState {
                interface: port.interface,
                port_id: port.port_id,
            })
            .collect();

        Ok(Self {
            pool,
            ports,
            max_frame_len: config.max_frame_len(),
            stats: BackendStats::new(),
            scratch: Vec::with_capacity(MAX_GENERATED_BATCH),
            #[cfg(feature = "test-hooks")]
            hooks: TestHooks::default(),
        })
    }

    #[must_use]
    pub fn stats(&self) -> BackendStatsSnapshot {
        self.stats.snapshot()
    }

    /// Tightens or loosens the cap `allocate()` checks `frame_len` against.
    /// Independent of the pool's real `data_room_size`, which was fixed at
    /// [`Self::open`] time.
    pub fn set_max_frame_len(&mut self, max_frame_len: u16) {
        self.max_frame_len = max_frame_len;
    }
}

// SAFETY: every raw pointer `DpdkIo` holds is a process-lifetime handle into
// DPDK-managed pool/queue memory with no thread affinity of its own, and
// every operation on `DpdkIo` requires `&mut self`. Moving the whole value to
// another thread (for example behind a `Mutex`, as the reusable conformance
// suite's test harness does to serialize DPDK's process-global EAL across
// many `#[test]` functions) therefore never creates concurrent access.
#[allow(unsafe_code)]
unsafe impl Send for DpdkIo {}

impl Drop for DpdkIo {
    fn drop(&mut self) {
        for port in self.ports.iter() {
            eth_dev_stop(port.port_id);
            eth_dev_close(port.port_id);
        }
        eal_cleanup();
    }
}

impl GeneratedPacketIo for DpdkIo {
    type Error = DpdkError;
    type Batch<'a>
        = DpdkGeneratedBatch<'a>
    where
        Self: 'a;

    fn begin_generated(&mut self, egress: IfId) -> Self::Batch<'_> {
        let port_index = self.ports.iter().position(|port| port.interface == egress);
        self.scratch.clear();
        #[cfg(feature = "test-hooks")]
        let allocation_remaining = self.hooks.allocation_budget;
        DpdkGeneratedBatch {
            io: self,
            egress,
            port_index,
            counters: GeneratedCounters::default(),
            error: None,
            finished: false,
            #[cfg(feature = "test-hooks")]
            allocation_remaining,
        }
    }
}

#[derive(Default)]
struct GeneratedCounters {
    attempts: usize,
    allocated: usize,
    failed: usize,
    requested: usize,
    cancelled: usize,
    abandoned: usize,
    accepted: usize,
    rejected: usize,
}

/// Core-facing generated batch for the live DPDK backend.
///
/// Committed frames accumulate in `io.scratch` and reach `rte_eth_tx_burst`
/// only once, in `finish()` (or are freed, never transmitted, if the batch
/// is dropped without calling it): at most one kick per egress per batch.
pub struct DpdkGeneratedBatch<'a> {
    io: &'a mut DpdkIo,
    egress: IfId,
    port_index: Option<usize>,
    counters: GeneratedCounters,
    error: Option<DpdkError>,
    finished: bool,
    /// test-hooks only: this batch's own copy of `io.hooks.allocation_budget`
    /// at the moment it began, decremented on each successful `allocate()`.
    /// Copied rather than read live so the *sticky* setting on `io.hooks`
    /// applies fresh to every new batch (matching what the reusable suite
    /// expects: several of its cases call `set_generated_allocation_budget`
    /// once and then open more than one session against it).
    #[cfg(feature = "test-hooks")]
    allocation_remaining: Option<usize>,
}

impl DpdkGeneratedBatch<'_> {
    fn record_error(&mut self, error: DpdkError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    fn finish_inner(&mut self) -> GeneratedBatchCompletion<DpdkError> {
        self.flush_pending();
        #[cfg(feature = "test-hooks")]
        if self.io.hooks.fail_next_finish {
            self.io.hooks.fail_next_finish = false;
            self.record_error(DpdkError::InjectedFinishFailure);
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
            error: self.error.take(),
        }
    }

    /// Frees every entry left in `io.scratch` as rejected, without ever
    /// calling `tx_burst`. Used when this batch is dropped without calling
    /// `finish()`, and as the fallback when `port_index` never resolved.
    fn reject_all_pending(&mut self) {
        while let Some(mbuf) = self.io.scratch.pop() {
            #[cfg(feature = "test-hooks")]
            self.record_pending_event(RecordedDisposition::TxRejected);
            pktmbuf_free(mbuf);
            self.counters.rejected = self
                .counters
                .rejected
                .checked_add(1)
                .expect("generated rejected count cannot overflow");
            self.io.stats.record(BackendStat::TxRejected);
        }
    }

    fn flush_pending(&mut self) {
        let Some(port_index) = self.port_index else {
            if !self.io.scratch.is_empty() {
                self.record_error(DpdkError::UnknownEgress(self.egress));
            }
            self.reject_all_pending();
            return;
        };
        if self.io.scratch.is_empty() {
            return;
        }

        // test-hooks only: caps how many of the committed frames this
        // `finish()` even offers to the real `tx_burst` call. The production
        // path never does this; it always offers the whole committed batch
        // and trusts the real accept count DPDK returns.
        #[cfg(feature = "test-hooks")]
        if let Some(cap) = self.io.hooks.accept_cap {
            while self.io.scratch.len() > cap {
                let mbuf = self.io.scratch.pop().expect("checked non-empty above");
                self.record_pending_event(RecordedDisposition::TxRejected);
                pktmbuf_free(mbuf);
                self.counters.rejected = self
                    .counters
                    .rejected
                    .checked_add(1)
                    .expect("generated rejected count cannot overflow");
                self.io.stats.record(BackendStat::TxRejected);
            }
        }
        if self.io.scratch.is_empty() {
            return;
        }

        let port_id = self.io.ports[port_index].port_id;
        let sent = usize::from(tx_burst(port_id, &mut self.io.scratch));
        self.counters.accepted = self
            .counters
            .accepted
            .checked_add(sent)
            .expect("generated accepted count cannot overflow");
        // `tx_burst` took ownership of exactly the first `sent` mbufs; only
        // the tail from index `sent` onward is still ours to record and free.
        self.io.scratch.drain(..sent).for_each(drop);
        #[cfg(feature = "test-hooks")]
        for _ in 0..sent {
            self.pop_front_pending_event(RecordedDisposition::TxSubmitted);
        }
        for _ in 0..sent {
            self.io.stats.record(BackendStat::TxAccepted);
        }
        while let Some(mbuf) = self.io.scratch.pop() {
            #[cfg(feature = "test-hooks")]
            self.record_pending_event(RecordedDisposition::TxRejected);
            pktmbuf_free(mbuf);
            self.counters.rejected = self
                .counters
                .rejected
                .checked_add(1)
                .expect("generated rejected count cannot overflow");
            self.io.stats.record(BackendStat::TxRejected);
        }
    }

    #[cfg(feature = "test-hooks")]
    fn record_pending_event(&mut self, kind: RecordedDisposition) {
        let Some((data, len)) = self.io.hooks.pending_meta.pop() else {
            return;
        };
        self.io.hooks.record_event(self.egress, data, len, kind);
    }

    /// Same as `record_pending_event`, but for an entry consumed from the
    /// *front* of `io.scratch` (the accepted prefix `tx_burst` took), so it
    /// must also come from the front of the parallel `pending_meta` log.
    #[cfg(feature = "test-hooks")]
    fn pop_front_pending_event(&mut self, kind: RecordedDisposition) {
        if self.io.hooks.pending_meta.is_empty() {
            return;
        }
        let (data, len) = self.io.hooks.pending_meta.remove(0);
        self.io.hooks.record_event(self.egress, data, len, kind);
    }
}

impl<'batch> GeneratedPacketBatch for DpdkGeneratedBatch<'batch> {
    type Error = DpdkError;
    type Slot<'slot>
        = DpdkGeneratedSlot<'slot, 'batch>
    where
        Self: 'slot;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        self.counters.attempts = self
            .counters
            .attempts
            .checked_add(1)
            .expect("generated allocation attempts cannot overflow");
        if frame_len == 0 {
            self.counters.failed += 1;
            return Err(GeneratedAllocationError::ZeroLength);
        }
        if frame_len > usize::from(self.io.max_frame_len) {
            self.counters.failed += 1;
            return Err(GeneratedAllocationError::FrameTooLarge);
        }
        // test-hooks only: an artificial per-session cap on successful
        // allocations, independent of real pool capacity (which
        // `GeneratedFinitePoolHarness` observes separately, unaffected by
        // this). The production path has no such cap.
        #[cfg(feature = "test-hooks")]
        if self.allocation_remaining == Some(0) {
            self.counters.failed += 1;
            self.io.stats.record(BackendStat::AllocationFailed);
            return Err(GeneratedAllocationError::Unavailable);
        }
        let Some(mbuf) = pktmbuf_alloc(self.io.pool) else {
            self.counters.failed += 1;
            self.io.stats.record(BackendStat::AllocationFailed);
            return Err(GeneratedAllocationError::Unavailable);
        };
        let len = u16::try_from(frame_len).expect("frame_len was checked against max_frame_len");
        let Some(data) = pktmbuf_append(mbuf, len) else {
            pktmbuf_free(mbuf);
            self.counters.failed += 1;
            self.io.stats.record(BackendStat::AllocationFailed);
            return Err(GeneratedAllocationError::Unavailable);
        };
        self.counters.allocated = self
            .counters
            .allocated
            .checked_add(1)
            .expect("generated allocation count cannot overflow");
        #[cfg(feature = "test-hooks")]
        if let Some(remaining) = self.allocation_remaining.as_mut() {
            *remaining -= 1;
        }
        Ok(GeneratedPacketLease::new(DpdkGeneratedSlot {
            batch: self,
            mbuf,
            data,
            len: frame_len,
        }))
    }

    fn finish(mut self) -> GeneratedBatchCompletion<Self::Error> {
        self.finish_inner()
    }
}

impl Drop for DpdkGeneratedBatch<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.reject_all_pending();
        self.finished = true;
    }
}

/// Core-facing generated slot for the live DPDK backend.
pub struct DpdkGeneratedSlot<'slot, 'batch> {
    batch: &'slot mut DpdkGeneratedBatch<'batch>,
    mbuf: NonNull<RteMbuf>,
    data: NonNull<u8>,
    len: usize,
}

impl GeneratedPacketSlot for DpdkGeneratedSlot<'_, '_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        mbuf_bytes_mut(self.data, self.len)
    }

    fn complete(self, completion: GeneratedSlotCompletion) {
        let Self {
            batch,
            mbuf,
            data,
            len,
        } = self;
        // `data`/`len` are only read under `test-hooks`; this keeps both
        // bindings used (they are `Copy`) regardless of the feature.
        let _ = (data, len);
        match completion {
            GeneratedSlotCompletion::Transmit => {
                batch.counters.requested = batch
                    .counters
                    .requested
                    .checked_add(1)
                    .expect("generated request count cannot overflow");
                batch.io.scratch.push(mbuf);
                #[cfg(feature = "test-hooks")]
                batch.io.hooks.pending_meta.push((data, len));
            }
            GeneratedSlotCompletion::Cancelled => {
                batch.counters.cancelled = batch
                    .counters
                    .cancelled
                    .checked_add(1)
                    .expect("generated cancel count cannot overflow");
                #[cfg(feature = "test-hooks")]
                batch.io.hooks.record_event(
                    batch.egress,
                    data,
                    len,
                    RecordedDisposition::Cancelled,
                );
                pktmbuf_free(mbuf);
                batch.io.stats.record(BackendStat::Cancelled);
            }
            GeneratedSlotCompletion::Abandoned => {
                batch.counters.abandoned = batch
                    .counters
                    .abandoned
                    .checked_add(1)
                    .expect("generated abandon count cannot overflow");
                #[cfg(feature = "test-hooks")]
                batch.io.hooks.record_event(
                    batch.egress,
                    data,
                    len,
                    RecordedDisposition::Abandoned,
                );
                pktmbuf_free(mbuf);
                batch.io.stats.record(BackendStat::Abandoned);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// test-hooks: real pool-backed finite capacity, deterministic partial
// accept, injected finish failure, and an address-identified disposition
// log for the reusable conformance suite. None of this compiles into a
// production build.
// ---------------------------------------------------------------------------

#[cfg(feature = "test-hooks")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordedDisposition {
    TxSubmitted,
    TxRejected,
    Cancelled,
    Abandoned,
}

/// One recorded disposition, snapshotted for the reusable conformance suite.
///
/// `address` is the mbuf data pointer `bytes_mut()` returned at allocate
/// time, carried only as an opaque identity key (the suite's own observer
/// re-derives a `&[u8]` from it purely to match pointer and length against
/// its own `bind`-time record; it never reads through that slice). `bytes`
/// is a real content copy taken before the mbuf was freed or handed to
/// `tx_burst`, so it reflects exactly what the caller wrote.
#[cfg(feature = "test-hooks")]
#[derive(Clone, Debug)]
pub struct RecordedGeneratedEvent {
    pub egress: IfId,
    pub address: usize,
    pub len: usize,
    pub bytes: Vec<u8>,
    pub kind: RecordedDisposition,
}

#[cfg(feature = "test-hooks")]
#[derive(Default)]
struct TestHooks {
    /// Sticky per-*session* cap on successful allocations, applied fresh to
    /// each new batch by `begin_generated` (see
    /// `DpdkGeneratedBatch::allocation_remaining`). Independent of the real
    /// mbuf pool, which `GeneratedFinitePoolHarness` observes separately.
    allocation_budget: Option<usize>,
    /// Sticky cap on how many committed frames one `finish()` offers to the
    /// real `tx_burst` call. See `DpdkGeneratedBatch::flush_pending`.
    accept_cap: Option<usize>,
    /// One-shot: consumed by the next `finish()` that runs.
    fail_next_finish: bool,
    /// Parallel to `DpdkIo::scratch`: pushed and drained in the same order
    /// and at the same points, so index `i` here always describes the mbuf
    /// at index `i` there.
    pending_meta: Vec<(NonNull<u8>, usize)>,
    events: VecDeque<RecordedGeneratedEvent>,
}

#[cfg(feature = "test-hooks")]
impl TestHooks {
    fn record_event(
        &mut self,
        egress: IfId,
        data: NonNull<u8>,
        len: usize,
        kind: RecordedDisposition,
    ) {
        // SAFETY: the caller passes `data`/`len` before the mbuf that owned
        // them is freed or submitted, so the bytes are still exactly what
        // the test wrote. This is a one-time read-and-copy, not a stored
        // reference: nothing later dereferences `data` itself.
        let bytes = unsafe { std::slice::from_raw_parts(data.as_ptr(), len) }.to_vec();
        self.events.push_back(RecordedGeneratedEvent {
            egress,
            address: data.as_ptr() as usize,
            len,
            bytes,
            kind,
        });
    }
}

#[cfg(feature = "test-hooks")]
impl DpdkIo {
    /// Every session (`begin_generated` call) from now on allows at most
    /// `budget` successful allocations, until changed again.
    pub fn set_generated_allocation_budget_for_test(&mut self, budget: usize) {
        self.hooks.allocation_budget = Some(budget);
    }

    /// Every `finish()` from now on offers only the first `budget` committed
    /// frames to the real `tx_burst` call, until changed again; the rest are
    /// freed as rejected without ever reaching hardware. See
    /// `DpdkGeneratedBatch::flush_pending`.
    pub fn set_generated_accept_budget_for_test(&mut self, budget: usize) {
        self.hooks.accept_cap = Some(budget);
    }

    /// Clears every sticky/one-shot test seam back to its default
    /// (unlimited allocation, unlimited accept, no injected finish
    /// failure). Used by the reusable conformance suite's harness at the
    /// start of every `#[test]`, since all of them share one process-wide
    /// `DpdkIo` behind DPDK's single EAL.
    pub fn reset_generated_test_hooks_for_test(&mut self) {
        self.hooks.allocation_budget = None;
        self.hooks.accept_cap = None;
        self.hooks.fail_next_finish = false;
    }

    pub fn fail_next_generated_finish_for_test(&mut self) {
        self.hooks.fail_next_finish = true;
    }

    #[must_use]
    pub fn free_generated_frames_for_test(&self) -> usize {
        usize::try_from(mempool_avail_count(self.pool)).unwrap_or(usize::MAX)
    }

    pub fn drain_generated_events_for_test(&mut self) -> Vec<RecordedGeneratedEvent> {
        self.hooks.events.drain(..).collect()
    }
}
