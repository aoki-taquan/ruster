//! The public live AF_PACKET adapter (AP3).
//!
//! [`AfPacketIo`] owns one private [`AfPacketEngine`] over real Linux
//! sockets and mappings and implements the core [`PacketIo`],
//! [`GeneratedPacketIo`], [`PublicationQuiescence`], and [`BackendStats`]
//! contracts by static dispatch. The batch and slot types are thin
//! newtypes over the engine's own (which are generic over the private
//! syscall seam that scripted tests replace), so the scheduled behaviour the
//! tests exercise is exactly the one this adapter runs:
//!
//! - `receive` settles every port (TX completion reap and owed kick, see
//!   `schedule`) before it opens the AP2 copy batch;
//! - `begin_generated` settles the egress port, then lends TX frames of that
//!   port directly (no copy);
//! - `try_publication_quiescence` settles every port and succeeds only when
//!   no published frame is still in flight;
//! - `drain` stops RX and new TX for good and reaps with bounded kicks.
//!
//! Dropping the adapter unmaps every ring and then closes every socket,
//! each exactly once. Frames the kernel still holds are the kernel's to free
//! (it keeps its own page references), never touched by userspace again.

use std::fmt;

use ruster_core::{
    BackendMode, BackendStats, BatchCompletion, GeneratedAllocationError, GeneratedBatchCompletion,
    GeneratedPacketBatch, GeneratedPacketIo, GeneratedPacketLease, GeneratedPacketSlot,
    GeneratedSlotCompletion, IfId, MonotonicMillis, PacketBatch, PacketIo, PacketLease, PacketSlot,
    PublicationQuiescence, PublicationQuiescenceDisposition, PublicationQuiescenceGuard,
    SlotCompletion,
};

pub use super::schedule::{AfPacketDrain, AfPacketQuiescenceError};
use super::{
    generated::{AfPacketGenBatch, AfPacketGenSlot},
    packet_io::{AfPacketBatch, AfPacketIoError, AfPacketSlot},
    rx::RxFault,
    AfPacketEngine, LinuxOps, TxSubmitError,
};
use crate::{AfPacketBackendStats, AfPacketPortStats, PlatformError, RxWait, ValidatedConfig};

/// The live AF_PACKET backend: one bound TPACKET_V3 socket with a combined
/// RX/TX `packet_mmap` ring per configured port.
///
/// The adapter is worker-local (`!Send`): it holds raw mapping pointers and
/// must be driven by the thread that opened it.
pub struct AfPacketIo {
    engine: AfPacketEngine<LinuxOps>,
}

impl fmt::Debug for AfPacketIo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AfPacketIo")
            .field("ports", &self.engine.ports.len())
            .finish_non_exhaustive()
    }
}

impl AfPacketIo {
    /// Opens every port of `config` in configuration order as one
    /// failure-atomic transaction: per port, an `AF_PACKET`/`SOCK_RAW`
    /// socket with protocol zero (inactive), `PACKET_VERSION = TPACKET_V3`,
    /// `PACKET_IGNORE_OUTGOING`, `PACKET_LOSS`, `PACKET_RX_RING` and
    /// `PACKET_TX_RING` from the validated geometry, one combined
    /// `MAP_SHARED` mapping whose extents are rechecked, and finally `bind`
    /// to the port's interface index with `ETH_P_ALL`, the single activation
    /// point. A failure releases what was acquired, mapping before socket,
    /// each exactly once, including every earlier port.
    ///
    /// The interface index is resolved by the caller in the network
    /// namespace the process runs in. No promiscuous mode, fanout, or qdisc
    /// bypass is requested: the socket receives what the device accepts for
    /// its own MAC plus broadcast and multicast, and TX goes through the
    /// device's qdisc. Requires `CAP_NET_RAW`.
    ///
    /// # Exposure
    ///
    /// AF_PACKET receives *copies*: unlike AF_XDP it does not take frames
    /// away from the kernel, so the kernel stack still sees and processes
    /// every frame of every port. This constructor checks none of that. The
    /// caller must ensure that no port has a kernel IPv4 or IPv6 address, a
    /// kernel route, or a forwarding role, that `rp_filter` and IPv6
    /// (`disable_ipv6=1`) leave the kernel nothing to answer, and that the
    /// configured maximum frame does not exceed the device MTU plus 14.
    /// `ruster run` (`backend.kind = "af-packet"`, AFPKT-015) enforces this
    /// before it calls `open` and watches it while it runs.
    pub fn open(config: ValidatedConfig) -> Result<Self, PlatformError> {
        super::validated_uapi_layout()?;
        Ok(Self {
            engine: AfPacketEngine::open(config)?,
        })
    }

    /// Hands the adapter the loop's clock reading (cold boundary, once per
    /// loop iteration). The adapter never reads a clock itself: once a clock
    /// was handed in, owed-kick retries are paced by it (1 ms doubling to
    /// 64 ms). Before the first call there is nothing to pace by, so every
    /// settle retries an owed kick, as the AF_XDP adapter does.
    pub fn set_clock(&mut self, now: MonotonicMillis) {
        self.engine.set_clock(now);
    }

    /// The idle wait (cold boundary, between ticks). See the crate docs for
    /// the TPACKET_V3 block-retire latency.
    pub fn wait_rx(&mut self, timeout_ms: u32) -> Result<RxWait, PlatformError> {
        self.engine.wait_rx(timeout_ms)
    }

    /// Whether TX is in flight or a kick is owed: work that only a later
    /// settle completes, which an RX wait does not notice.
    #[must_use]
    pub fn tx_outstanding(&self) -> bool {
        self.engine.tx_outstanding()
    }

    /// One bounded shutdown drain call. The first call stops RX and new TX
    /// for good; call again until [`AfPacketDrain::is_drained`] or a
    /// deadline.
    pub fn drain(&mut self, rounds: u32) -> AfPacketDrain {
        self.engine.drain(rounds)
    }

    /// Whether the adapter was drained or stopped by a fault.
    #[must_use]
    pub const fn is_stopped(&self) -> bool {
        self.engine.is_stopped()
    }

    /// Reads and resets the kernel's `PACKET_STATISTICS` of every port into
    /// the cumulative `kernel_*` counters (cold path, one `getsockopt` per
    /// port). Returns the first failure after trying every port.
    pub fn refresh_kernel_stats(&mut self) -> Result<(), PlatformError> {
        self.engine.refresh_kernel_stats()
    }

    /// Number of ports.
    #[must_use]
    pub fn port_count(&self) -> usize {
        self.engine.ports.len()
    }

    /// Stats of the port of `interface`.
    #[must_use]
    pub fn port_stats(&self, interface: IfId) -> Option<AfPacketPortStats> {
        self.engine.port_stats(interface)
    }

    /// Stats of every port in configuration order (no allocation).
    pub fn ports(&self) -> impl Iterator<Item = AfPacketPortStats> + '_ {
        self.engine
            .ports
            .iter()
            .filter_map(|port| self.engine.port_stats(port.interface))
    }
}

/// A halting RX fault, without ring offsets or tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AfPacketRxFault {
    /// An unsafe block header or chain whose block return failed.
    Block,
    /// A validated block could not enter the ownership model.
    Acquire,
    /// A head block status that is neither KERNEL nor USER.
    Status { status: u32 },
    /// A block cannot receive a fresh generation.
    GenerationExhausted,
    /// A checked status access failed.
    Mapping,
    /// Completing or returning the current block failed.
    Release,
    /// A packet-local fault (never reported as a batch error).
    Packet,
}

impl AfPacketRxFault {
    const fn of(fault: RxFault) -> Self {
        match fault {
            RxFault::Packet { .. } => Self::Packet,
            RxFault::Block { .. } => Self::Block,
            RxFault::Acquire { .. } => Self::Acquire,
            RxFault::Status { status, .. } => Self::Status { status },
            RxFault::GenerationExhausted { .. } => Self::GenerationExhausted,
            RxFault::Mapping { .. } => Self::Mapping,
            RxFault::Release(_) => Self::Release,
        }
    }
}

/// A fault-class TX rejection, without ring offsets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AfPacketTxFault {
    /// The producer head status is not a TPACKET TX status.
    InvalidStatus { status: u32 },
    /// A frame cannot receive a fresh generation.
    GenerationExhausted,
    /// A checked mapping access failed.
    Mapping,
    /// The ownership model refused a transition.
    Ownership,
    /// A routine rejection (never reported as an error).
    Rejected,
}

impl AfPacketTxFault {
    const fn of(error: TxSubmitError) -> Self {
        match error {
            TxSubmitError::InvalidStatus { status } => Self::InvalidStatus { status },
            TxSubmitError::GenerationExhausted { .. } => Self::GenerationExhausted,
            TxSubmitError::Mapping(_) => Self::Mapping,
            TxSubmitError::Ownership(_) => Self::Ownership,
            TxSubmitError::UnknownInterface
            | TxSubmitError::Oversize { .. }
            | TxSubmitError::StatusReadBudget
            | TxSubmitError::Unavailable { .. } => Self::Rejected,
        }
    }
}

/// The first backend fault of a batch, or why I/O is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AfPacketError {
    /// A newly observed halting RX fault of `interface`.
    Rx {
        interface: IfId,
        fault: AfPacketRxFault,
    },
    /// A fault-class TX rejection; accounting is still exact.
    Tx {
        egress: IfId,
        fault: AfPacketTxFault,
    },
    /// The first fault-class kick failure. Frames stay in flight, owed.
    Kick {
        interface: IfId,
        error: PlatformError,
    },
    /// A TX completion scan found an invariant violation; the adapter
    /// stopped for good.
    Completion { interface: IfId },
    /// The adapter was drained or stopped by an earlier fault.
    Stopped,
}

impl AfPacketError {
    const fn of(error: AfPacketIoError) -> Self {
        match error {
            AfPacketIoError::Rx { interface, fault } => Self::Rx {
                interface,
                fault: AfPacketRxFault::of(fault),
            },
            AfPacketIoError::Tx { egress, error } => Self::Tx {
                egress,
                fault: AfPacketTxFault::of(error),
            },
            AfPacketIoError::Kick { interface, error } => Self::Kick { interface, error },
            AfPacketIoError::Completion { interface, .. } => Self::Completion { interface },
            AfPacketIoError::Stopped => Self::Stopped,
        }
    }
}

impl fmt::Display for AfPacketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rx { interface, fault } => {
                write!(
                    formatter,
                    "AF_PACKET RX halted on if{}: {fault:?}",
                    interface.0
                )
            }
            Self::Tx { egress, fault } => {
                write!(formatter, "AF_PACKET TX fault on if{}: {fault:?}", egress.0)
            }
            Self::Kick { interface, error } => {
                write!(formatter, "AF_PACKET TX kick on if{}: {error}", interface.0)
            }
            Self::Completion { interface } => write!(
                formatter,
                "AF_PACKET TX completion invariant violated on if{}",
                interface.0
            ),
            Self::Stopped => formatter.write_str("AF_PACKET backend stopped"),
        }
    }
}

impl std::error::Error for AfPacketError {}

fn completion(inner: BatchCompletion<AfPacketIoError>) -> BatchCompletion<AfPacketError> {
    BatchCompletion {
        tx_requested: inner.tx_requested,
        tx_accepted: inner.tx_accepted,
        tx_rejected: inner.tx_rejected,
        recycled: inner.recycled,
        error: inner.error.map(AfPacketError::of),
    }
}

impl PacketIo for AfPacketIo {
    type Error = AfPacketError;
    type Batch<'a>
        = AfPacketRxBatch<'a>
    where
        Self: 'a;

    fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
        self.engine
            .live_receive(budget)
            .map(AfPacketRxBatch)
            .map_err(AfPacketError::of)
    }
}

/// One RX pass over every port plus the TX copies it requests.
#[must_use]
pub struct AfPacketRxBatch<'a>(AfPacketBatch<'a, LinuxOps>);

impl<'a> PacketBatch for AfPacketRxBatch<'a> {
    type Error = AfPacketError;
    type Slot<'b>
        = AfPacketRxSlot<'b, 'a>
    where
        Self: 'b;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        self.0
            .next_slot()
            .map(|slot| PacketLease::new(AfPacketRxSlot(slot)))
    }

    fn finish(self) -> BatchCompletion<Self::Error> {
        completion(self.0.finish_batch())
    }
}

/// Backend slot behind one core RX [`PacketLease`].
pub struct AfPacketRxSlot<'b, 'a>(AfPacketSlot<'b, 'a, LinuxOps>);

impl PacketSlot for AfPacketRxSlot<'_, '_> {
    fn ingress(&self) -> IfId {
        self.0.ingress()
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.0.bytes_mut()
    }

    fn complete(self, completion: SlotCompletion) {
        self.0.complete(completion);
    }
}

impl GeneratedPacketIo for AfPacketIo {
    type Error = AfPacketError;
    type Batch<'a>
        = AfPacketGeneratedBatch<'a>
    where
        Self: 'a;

    fn begin_generated(&mut self, egress: IfId) -> Self::Batch<'_> {
        AfPacketGeneratedBatch(self.engine.live_begin_generated(egress))
    }
}

/// One generated session on one egress port.
#[must_use]
pub struct AfPacketGeneratedBatch<'a>(AfPacketGenBatch<'a, LinuxOps>);

impl<'a> GeneratedPacketBatch for AfPacketGeneratedBatch<'a> {
    type Error = AfPacketError;
    type Slot<'b>
        = AfPacketGeneratedSlot<'b, 'a>
    where
        Self: 'b;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        self.0
            .allocate_slot(frame_len)
            .map(|slot| GeneratedPacketLease::new(AfPacketGeneratedSlot(slot)))
    }

    fn finish(self) -> GeneratedBatchCompletion<Self::Error> {
        let inner = self.0.finish_batch();
        GeneratedBatchCompletion {
            attempts: inner.attempts,
            allocated: inner.allocated,
            failed: inner.failed,
            requested: inner.requested,
            cancelled: inner.cancelled,
            abandoned: inner.abandoned,
            accepted: inner.accepted,
            rejected: inner.rejected,
            error: inner.error.map(AfPacketError::of),
        }
    }
}

/// Backend slot behind one core [`GeneratedPacketLease`]: a TX frame.
pub struct AfPacketGeneratedSlot<'b, 'a>(AfPacketGenSlot<'b, 'a, LinuxOps>);

impl GeneratedPacketSlot for AfPacketGeneratedSlot<'_, '_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        self.0.bytes_mut()
    }

    fn complete(self, completion: GeneratedSlotCompletion) {
        self.0.complete(completion);
    }
}

impl PublicationQuiescence for AfPacketIo {
    type Error = AfPacketQuiescenceError;
    type Guard<'backend>
        = PublicationQuiescenceGuard<'backend, Self>
    where
        Self: 'backend;

    fn try_publication_quiescence(&mut self) -> Result<Self::Guard<'_>, Self::Error> {
        self.engine.quiescence_check()?;
        Ok(PublicationQuiescenceGuard::new(self))
    }

    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
        self.engine.io_disposition()
    }

    fn quiescence_error_disposition(error: &Self::Error) -> PublicationQuiescenceDisposition {
        error.disposition()
    }
}

impl BackendStats for AfPacketIo {
    type Stats = AfPacketBackendStats;

    const NAME: &'static str = "af_packet";
    /// Every AF_PACKET port copies: RX leases are zero-copy views, but a
    /// forwarded frame is copied exactly once into a TX frame.
    const MODE: BackendMode = BackendMode::Copy;

    fn backend_stats(&self) -> Self::Stats {
        self.engine.backend_stats()
    }
}
