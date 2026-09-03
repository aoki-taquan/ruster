#![deny(unsafe_code)]
#![doc = "Deterministic, in-memory packet I/O for ruster-core."]

use std::{collections::VecDeque, convert::Infallible};

use ruster_core::{
    forward_batch, forward_batch_with_firewall, forward_batch_with_firewall_and_icmpv4_errors,
    forward_batch_with_firewall_audited, forward_batch_with_nat44_tcp,
    forward_batch_with_nat44_udp, forward_batch_with_nat44_udp_and_tcp,
    forward_batch_with_nat44_udp_and_tcp_and_firewall,
    forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors,
    forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors_audited,
    forward_batch_with_nat44_udp_and_tcp_and_firewall_audited, BatchCompletion, BatchReport,
    BoundPublicationBackend, ConsumeReason, DropReason, FirewallAuditBuffer, FirewallConfig,
    FirewallRuntime, ForwardingSnapshot, GeneratedAllocationError, GeneratedArpTrace,
    GeneratedBatchCompletion, GeneratedIcmpv4Trace, GeneratedIcmpv4TraceSink, GeneratedPacketBatch,
    GeneratedPacketIo, GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion,
    GeneratedTraceSink, IfId, MonotonicMillis, Nat44TcpConfig, Nat44TcpRuntime, Nat44UdpConfig,
    Nat44UdpRuntime, PacketBatch, PacketIo, PacketLease, PacketSlot, PublicationBackendAuthority,
    PublicationBackendControl, PublicationQuiescenceBackend, PublicationQuiescenceDisposition,
    ResolutionRuntime, SlotCompletion, TraceEvent, TraceSink,
};

#[derive(Debug, Eq, PartialEq)]
struct Slot {
    sequence: u64,
    ingress: IfId,
    bytes: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TxFrame {
    pub sequence: u64,
    pub ingress: IfId,
    pub egress: IfId,
    pub origin: FrameOrigin,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameOrigin {
    Received { ingress: IfId },
    Generated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecycleCause {
    Forwarding(DropReason),
    Consumed(ConsumeReason),
    TxRejected,
    LeaseAbandoned,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RecycledFrame {
    pub sequence: u64,
    pub ingress: IfId,
    pub cause: RecycleCause,
    pub bytes: Vec<u8>,
}

/// Extended cold-path capture for backend conformance observation.
#[derive(Debug, Eq, PartialEq)]
pub struct RecycledFrameCapture {
    pub frame: RecycledFrame,
    pub rejected_egress: Option<IfId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedRecycleCause {
    Cancelled,
    Abandoned,
    TxRejected,
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedRecycledFrame {
    pub sequence: u64,
    pub egress: IfId,
    pub cause: GeneratedRecycleCause,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimGeneratedError {
    Injected,
}

/// Allocation-free, scalar statistics for one simulated backend.
///
/// Queue fields are snapshots of the simulator's actual queues; they are not
/// cumulative counters. `pending_tx` counts accepted TX frames that remain
/// owned by the simulated backend, and `completed_tx_total` counts accepted
/// frames returned by [`SimIo::pop_tx`]. Neither field represents wire
/// delivery: this backend has no network peer, and simulated completion is an
/// ownership transition only.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SimBackendStats {
    /// RX slots currently retained by the simulated backend.
    pub pending_rx: u64,
    /// The largest RX queue length observed after a successful injection.
    pub rx_queue_high_watermark: u64,
    /// Accepted TX frames currently retained by the simulated backend.
    ///
    /// A frame leaves this count only through [`SimIo::pop_tx`]; this is not a
    /// wire-delivery count.
    pub pending_tx: u64,
    /// The largest accepted-TX queue length observed by the backend.
    pub tx_queue_high_watermark: u64,
    /// RX recycle captures currently waiting to be popped.
    pub pending_recycled: u64,
    /// Generated recycle captures currently waiting to be popped.
    pub pending_generated_recycled: u64,
    /// Total successful RX injections.
    pub injected_rx_total: u64,
    /// Total RX and generated TX slots accepted by the simulated backend.
    pub accepted_tx_total: u64,
    /// Total accepted TX frames completed through [`SimIo::pop_tx`]. This is
    /// simulated backend ownership completion, not wire delivery.
    pub completed_tx_total: u64,
    /// RX slots recycled after a forwarding drop.
    pub rx_forwarding_recycled_total: u64,
    /// RX slots consumed by a control-plane action.
    pub rx_consumed_total: u64,
    /// RX TX requests rejected by the simulated backend.
    pub rx_tx_rejected_total: u64,
    /// RX leases abandoned before explicit completion.
    pub rx_lease_abandoned_total: u64,
    /// Generated slots explicitly cancelled.
    pub generated_cancelled_total: u64,
    /// Generated leases abandoned before explicit completion.
    pub generated_abandoned_total: u64,
    /// Generated TX requests rejected at batch finish.
    pub generated_tx_rejected_total: u64,
    /// RX slots retired explicitly by [`BoundSimIoObservabilityControl`].
    pub retired_rx_total: u64,
}

#[derive(Debug, Default)]
struct SimBackendStatsAccumulator {
    rx_queue_high_watermark: u64,
    tx_queue_high_watermark: u64,
    injected_rx_total: u64,
    accepted_tx_total: u64,
    completed_tx_total: u64,
    rx_forwarding_recycled_total: u64,
    rx_consumed_total: u64,
    rx_tx_rejected_total: u64,
    rx_lease_abandoned_total: u64,
    generated_cancelled_total: u64,
    generated_abandoned_total: u64,
    generated_tx_rejected_total: u64,
    retired_rx_total: u64,
}

impl SimBackendStatsAccumulator {
    fn snapshot(
        &self,
        pending_rx: usize,
        pending_tx: usize,
        pending_recycled: usize,
        pending_generated_recycled: usize,
    ) -> SimBackendStats {
        SimBackendStats {
            pending_rx: usize_to_u64_saturating(pending_rx),
            rx_queue_high_watermark: self.rx_queue_high_watermark,
            pending_tx: usize_to_u64_saturating(pending_tx),
            tx_queue_high_watermark: self.tx_queue_high_watermark,
            pending_recycled: usize_to_u64_saturating(pending_recycled),
            pending_generated_recycled: usize_to_u64_saturating(pending_generated_recycled),
            injected_rx_total: self.injected_rx_total,
            accepted_tx_total: self.accepted_tx_total,
            completed_tx_total: self.completed_tx_total,
            rx_forwarding_recycled_total: self.rx_forwarding_recycled_total,
            rx_consumed_total: self.rx_consumed_total,
            rx_tx_rejected_total: self.rx_tx_rejected_total,
            rx_lease_abandoned_total: self.rx_lease_abandoned_total,
            generated_cancelled_total: self.generated_cancelled_total,
            generated_abandoned_total: self.generated_abandoned_total,
            generated_tx_rejected_total: self.generated_tx_rejected_total,
            retired_rx_total: self.retired_rx_total,
        }
    }

    fn record_injected_rx(&mut self, pending_rx: usize) {
        self.injected_rx_total = self.injected_rx_total.saturating_add(1);
        self.rx_queue_high_watermark = self
            .rx_queue_high_watermark
            .max(usize_to_u64_saturating(pending_rx));
    }

    fn record_accepted_tx(&mut self, accepted: usize, pending_tx: usize) {
        self.accepted_tx_total = self
            .accepted_tx_total
            .saturating_add(usize_to_u64_saturating(accepted));
        if accepted != 0 {
            self.tx_queue_high_watermark = self
                .tx_queue_high_watermark
                .max(usize_to_u64_saturating(pending_tx));
        }
    }

    fn record_completed_tx(&mut self) {
        self.completed_tx_total = self.completed_tx_total.saturating_add(1);
    }

    fn record_rx_recycle(&mut self, cause: RecycleCause) {
        match cause {
            RecycleCause::Forwarding(_) => {
                self.rx_forwarding_recycled_total =
                    self.rx_forwarding_recycled_total.saturating_add(1);
            }
            RecycleCause::Consumed(_) => {
                self.rx_consumed_total = self.rx_consumed_total.saturating_add(1);
            }
            RecycleCause::TxRejected => {
                self.rx_tx_rejected_total = self.rx_tx_rejected_total.saturating_add(1);
            }
            RecycleCause::LeaseAbandoned => {
                self.rx_lease_abandoned_total = self.rx_lease_abandoned_total.saturating_add(1);
            }
        }
    }

    fn record_generated_recycle(&mut self, cause: GeneratedRecycleCause) {
        match cause {
            GeneratedRecycleCause::Cancelled => {
                self.generated_cancelled_total = self.generated_cancelled_total.saturating_add(1);
            }
            GeneratedRecycleCause::Abandoned => {
                self.generated_abandoned_total = self.generated_abandoned_total.saturating_add(1);
            }
            GeneratedRecycleCause::TxRejected => {
                self.generated_tx_rejected_total =
                    self.generated_tx_rejected_total.saturating_add(1);
            }
        }
    }

    fn record_retired_rx(&mut self, retired: usize) {
        self.retired_rx_total = self
            .retired_rx_total
            .saturating_add(usize_to_u64_saturating(retired));
    }
}

fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Exact reason why explicit RX retirement cannot run yet.
///
/// The priority is unfinished or forgotten RX batch, unfinished generated
/// batch, live RX lease, then live generated lease. The check is performed in
/// full before any retirement mutation, so every error is failure-atomic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimPendingRxRetirementError {
    /// An RX batch is active or has been forgotten without finishing.
    RxBatchNotFinished,
    /// A generated batch is active or has been forgotten without finishing.
    GeneratedBatchNotFinished,
    /// An RX lease is still live.
    RxLeaseNotCompleted,
    /// A generated lease is still live.
    GeneratedLeaseNotCompleted,
}

/// Exact bounded reason why the simulated backend cannot publish new
/// authority yet.
///
/// The priority is deterministic: unfinished RX batch, unfinished generated
/// batch, nonterminal RX lease, nonterminal generated lease, then accepted TX
/// awaiting explicit completion.
/// `SimIo`'s finite output queue is a conservative simulation boundary, not
/// evidence that a native AF_XDP completion queue has drained.
///
/// A successful guard keeps the exact bound wrapper exclusively borrowed:
///
/// ```compile_fail
/// use ruster_core::{bind_publication_backend, PacketIo, PublicationQuiescence};
/// use ruster_io_sim::SimIo;
///
/// let (_owner, mut io) = bind_publication_backend(SimIo::new()).unwrap();
/// let guard = io.try_publication_quiescence().unwrap();
/// let batch = io.receive(1);
/// drop((guard, batch));
/// ```
///
/// The raw guard is move-only:
///
/// ```compile_fail
/// use ruster_core::{bind_publication_backend, PublicationQuiescence};
/// use ruster_io_sim::SimIo;
///
/// let (_owner, mut io) = bind_publication_backend(SimIo::new()).unwrap();
/// let guard = io.try_publication_quiescence().unwrap();
/// let first = guard;
/// let second = guard;
/// drop((first, second));
/// ```
///
/// Standalone `SimIo` exposes only the backend hook, not the sealed runtime
/// publication guard API:
///
/// ```compile_fail
/// use ruster_core::PublicationQuiescence;
/// use ruster_io_sim::SimIo;
///
/// let mut io = SimIo::new();
/// let _guard = io.try_publication_quiescence();
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimPublicationQuiescenceError {
    RxBatchNotFinished,
    GeneratedBatchNotFinished,
    RxLeaseNotCompleted,
    GeneratedLeaseNotCompleted,
    TxCompletionPending,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum SimBatchState {
    #[default]
    Idle,
    Rx,
    Generated,
}

#[derive(Debug)]
pub struct SimIo {
    next_sequence: u64,
    rx: VecDeque<Slot>,
    tx: VecDeque<TxFrame>,
    recycled: VecDeque<RecycledFrameCapture>,
    generated_recycled: VecDeque<GeneratedRecycledFrame>,
    generated_budget: usize,
    generated_max_frame: usize,
    generated_accept_budget: usize,
    fail_generated_finish: bool,
    received_accept_budget: usize,
    batch_state: SimBatchState,
    rx_leases_live: usize,
    generated_leases_live: usize,
    backend_stats: SimBackendStatsAccumulator,
}

impl Default for SimIo {
    fn default() -> Self {
        Self {
            next_sequence: 0,
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            recycled: VecDeque::new(),
            generated_recycled: VecDeque::new(),
            generated_budget: usize::MAX,
            generated_max_frame: 1_514,
            generated_accept_budget: usize::MAX,
            fail_generated_finish: false,
            received_accept_budget: usize::MAX,
            batch_state: SimBatchState::Idle,
            rx_leases_live: 0,
            generated_leases_live: 0,
            backend_stats: SimBackendStatsAccumulator::default(),
        }
    }
}

impl SimIo {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inject(&mut self, ingress: IfId, bytes: Vec<u8>) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.rx.push_back(Slot {
            sequence,
            ingress,
            bytes,
        });
        self.backend_stats.record_injected_rx(self.rx.len());
        sequence
    }

    #[must_use]
    /// Number of RX frames currently owned by the simulated backend.
    pub fn pending_rx(&self) -> usize {
        self.rx.len()
    }

    #[must_use]
    /// Number of accepted TX frames still owned by the simulated backend.
    /// This is backend ownership only; it does not mean wire, NIC, or
    /// physical transmission.
    pub fn pending_tx(&self) -> usize {
        self.tx.len()
    }

    #[must_use]
    pub fn pending_recycled(&self) -> usize {
        self.recycled.len()
    }

    /// Completes and returns the oldest backend-accepted TX frame.
    ///
    /// Completion is a simulated backend ownership transition only; it does
    /// not mean wire delivery, NIC transmission, or physical transmission.
    /// Until every accepted frame is completed through this method, the
    /// simulated backend conservatively refuses publication quiescence.
    pub fn pop_tx(&mut self) -> Option<TxFrame> {
        let frame = self.tx.pop_front();
        if frame.is_some() {
            self.backend_stats.record_completed_tx();
        }
        frame
    }

    pub fn pop_recycled(&mut self) -> Option<RecycledFrame> {
        self.recycled.pop_front().map(|capture| capture.frame)
    }

    pub fn pop_recycled_capture(&mut self) -> Option<RecycledFrameCapture> {
        self.recycled.pop_front()
    }

    pub fn pop_generated_recycled(&mut self) -> Option<GeneratedRecycledFrame> {
        self.generated_recycled.pop_front()
    }

    #[must_use = "the snapshot reports current backend ownership and cumulative counters"]
    pub fn stats(&self) -> SimBackendStats {
        self.backend_stats.snapshot(
            self.rx.len(),
            self.tx.len(),
            self.recycled.len(),
            self.generated_recycled.len(),
        )
    }

    #[must_use = "the retirement result reports whether queued RX ownership was recovered"]
    /// Cold-shutdown-only recovery for backend-owned, unleased `self.rx`; all
    /// batch and lease preconditions are checked before mutation. Success is
    /// non-terminal and idempotent; pending TX/recycle/generated queues and
    /// the quiescence proof are unaffected.
    pub fn retire_pending_rx(&mut self) -> Result<usize, SimPendingRxRetirementError> {
        match self.batch_state {
            SimBatchState::Rx => {
                return Err(SimPendingRxRetirementError::RxBatchNotFinished);
            }
            SimBatchState::Generated => {
                return Err(SimPendingRxRetirementError::GeneratedBatchNotFinished);
            }
            SimBatchState::Idle => {}
        }
        if self.rx_leases_live != 0 {
            return Err(SimPendingRxRetirementError::RxLeaseNotCompleted);
        }
        if self.generated_leases_live != 0 {
            return Err(SimPendingRxRetirementError::GeneratedLeaseNotCompleted);
        }

        let retired = self.rx.len();
        self.rx.clear();
        self.backend_stats.record_retired_rx(retired);
        Ok(retired)
    }

    pub fn set_generated_budget(&mut self, budget: usize) {
        self.generated_budget = budget;
    }

    pub fn set_generated_max_frame(&mut self, max_frame: usize) {
        self.generated_max_frame = max_frame;
    }

    pub fn set_generated_accept_budget(&mut self, budget: usize) {
        self.generated_accept_budget = budget;
    }

    pub fn fail_next_generated_finish(&mut self) {
        self.fail_generated_finish = true;
    }

    pub fn set_received_accept_budget(&mut self, budget: usize) {
        self.received_accept_budget = budget;
    }

    pub fn run_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(forward_batch(batch, snapshot, trace))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_nat44_udp_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        resolution: &mut ResolutionRuntime<'_>,
        config: &Nat44UdpConfig,
        nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
        now: MonotonicMillis,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(forward_batch_with_nat44_udp(
            batch, snapshot, resolution, config, nat44_udp, now, trace,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_nat44_tcp_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        resolution: &mut ResolutionRuntime<'_>,
        config: &Nat44TcpConfig,
        nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
        now: MonotonicMillis,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(forward_batch_with_nat44_tcp(
            batch, snapshot, resolution, config, nat44_tcp, now, trace,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_nat44_udp_and_tcp_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        resolution: &mut ResolutionRuntime<'_>,
        udp_config: &Nat44UdpConfig,
        nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
        tcp_config: &Nat44TcpConfig,
        nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
        now: MonotonicMillis,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(forward_batch_with_nat44_udp_and_tcp(
            batch, snapshot, resolution, udp_config, nat44_udp, tcp_config, nat44_tcp, now, trace,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_firewall_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        resolution: &mut ResolutionRuntime<'_>,
        config: &FirewallConfig<'_>,
        firewall: Option<&mut FirewallRuntime<'_>>,
        now: MonotonicMillis,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(forward_batch_with_firewall(
            batch, snapshot, resolution, config, firewall, now, trace,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_firewall_audited_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        resolution: &mut ResolutionRuntime<'_>,
        config: &FirewallConfig<'_>,
        firewall: Option<&mut FirewallRuntime<'_>>,
        audit: &mut FirewallAuditBuffer<'_>,
        now: MonotonicMillis,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(forward_batch_with_firewall_audited(
            batch, snapshot, resolution, config, firewall, audit, now, trace,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_firewall_with_icmpv4_errors_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        resolution: &mut ResolutionRuntime<'_>,
        icmpv4_errors: &mut ruster_core::Icmpv4ErrorRuntime<'_>,
        config: &FirewallConfig<'_>,
        firewall: Option<&mut FirewallRuntime<'_>>,
        now: MonotonicMillis,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(forward_batch_with_firewall_and_icmpv4_errors(
            batch,
            snapshot,
            resolution,
            icmpv4_errors,
            config,
            firewall,
            now,
            trace,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_nat44_udp_and_tcp_with_firewall_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        resolution: &mut ResolutionRuntime<'_>,
        udp_config: &Nat44UdpConfig,
        nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
        tcp_config: &Nat44TcpConfig,
        nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
        firewall_config: &FirewallConfig<'_>,
        firewall: Option<&mut FirewallRuntime<'_>>,
        now: MonotonicMillis,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(forward_batch_with_nat44_udp_and_tcp_and_firewall(
            batch,
            snapshot,
            resolution,
            udp_config,
            nat44_udp,
            tcp_config,
            nat44_tcp,
            firewall_config,
            firewall,
            now,
            trace,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_nat44_udp_and_tcp_with_firewall_audited_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        resolution: &mut ResolutionRuntime<'_>,
        udp_config: &Nat44UdpConfig,
        nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
        tcp_config: &Nat44TcpConfig,
        nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
        firewall_config: &FirewallConfig<'_>,
        firewall: Option<&mut FirewallRuntime<'_>>,
        audit: &mut FirewallAuditBuffer<'_>,
        now: MonotonicMillis,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(forward_batch_with_nat44_udp_and_tcp_and_firewall_audited(
            batch,
            snapshot,
            resolution,
            udp_config,
            nat44_udp,
            tcp_config,
            nat44_tcp,
            firewall_config,
            firewall,
            audit,
            now,
            trace,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_nat44_udp_and_tcp_with_firewall_and_icmpv4_errors_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        resolution: &mut ResolutionRuntime<'_>,
        icmpv4_errors: &mut ruster_core::Icmpv4ErrorRuntime<'_>,
        udp_config: &Nat44UdpConfig,
        nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
        tcp_config: &Nat44TcpConfig,
        nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
        firewall_config: &FirewallConfig<'_>,
        firewall: Option<&mut FirewallRuntime<'_>>,
        now: MonotonicMillis,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(
            forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors(
                batch,
                snapshot,
                resolution,
                icmpv4_errors,
                udp_config,
                nat44_udp,
                tcp_config,
                nat44_tcp,
                firewall_config,
                firewall,
                now,
                trace,
            ),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_nat44_udp_and_tcp_with_firewall_and_icmpv4_errors_audited_once<T: TraceSink>(
        &mut self,
        budget: usize,
        snapshot: &ForwardingSnapshot<'_>,
        resolution: &mut ResolutionRuntime<'_>,
        icmpv4_errors: &mut ruster_core::Icmpv4ErrorRuntime<'_>,
        udp_config: &Nat44UdpConfig,
        nat44_udp: Option<&mut Nat44UdpRuntime<'_>>,
        tcp_config: &Nat44TcpConfig,
        nat44_tcp: Option<&mut Nat44TcpRuntime<'_>>,
        firewall_config: &FirewallConfig<'_>,
        firewall: Option<&mut FirewallRuntime<'_>>,
        audit: &mut FirewallAuditBuffer<'_>,
        now: MonotonicMillis,
        trace: &mut T,
    ) -> Result<BatchReport<Infallible>, Infallible> {
        let batch = self.receive(budget)?;
        Ok(
            forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors_audited(
                batch,
                snapshot,
                resolution,
                icmpv4_errors,
                udp_config,
                nat44_udp,
                tcp_config,
                nat44_tcp,
                firewall_config,
                firewall,
                audit,
                now,
                trace,
            ),
        )
    }
}

/// Backend-specific operations that remain safe after a [`SimIo`] is bound to
/// one publication identity.
///
/// This extension trait deliberately exposes only concrete simulator commands;
/// it never returns `&mut SimIo` or the owned backend. Callers therefore cannot
/// move out or replace the authoritative simulator while retaining the bound
/// wrapper's identity.
pub trait BoundSimIoControl {
    fn inject(&mut self, ingress: IfId, bytes: Vec<u8>) -> u64;

    /// RX ownership currently retained by the simulated backend.
    #[must_use]
    fn pending_rx(&self) -> usize;

    /// Number of accepted TX frames still owned by this simulated backend;
    /// this is not a wire-delivery or physical-send gauge.
    #[must_use]
    fn pending_tx(&self) -> usize;

    /// Completes backend-owned TX; completion is not wire/NIC/physical delivery.
    fn pop_tx(&mut self) -> Option<TxFrame>;

    fn pop_recycled(&mut self) -> Option<RecycledFrame>;
}

#[doc(hidden)]
pub enum SimIoPublicationCommand {
    Inject { ingress: IfId, bytes: Vec<u8> },
    PopTx,
    PopRecycled,
    RetirePendingRx,
}

#[doc(hidden)]
pub enum SimIoPublicationResponse {
    Sequence(u64),
    Tx(Option<TxFrame>),
    Recycled(Option<RecycledFrame>),
    RetiredRx(Result<usize, SimPendingRxRetirementError>),
}

// SAFETY: the closed command and response enums cannot contain an owned
// `SimIo` or an independently mutable alias. Every command operates on this
// exact simulator; the closed retirement command also preserves the exact
// wrapper identity. Batch, lease, and pending-TX state are not hidden from
// quiescence, while stats remain non-authoritative observations only.
#[allow(unsafe_code)]
unsafe impl PublicationBackendControl for SimIo {
    type Command = SimIoPublicationCommand;
    type Response = SimIoPublicationResponse;

    fn execute_publication_backend_command(&mut self, command: Self::Command) -> Self::Response {
        match command {
            SimIoPublicationCommand::Inject { ingress, bytes } => {
                SimIoPublicationResponse::Sequence(self.inject(ingress, bytes))
            }
            SimIoPublicationCommand::PopTx => SimIoPublicationResponse::Tx(self.pop_tx()),
            SimIoPublicationCommand::PopRecycled => {
                SimIoPublicationResponse::Recycled(self.pop_recycled())
            }
            SimIoPublicationCommand::RetirePendingRx => {
                SimIoPublicationResponse::RetiredRx(self.retire_pending_rx())
            }
        }
    }
}

impl BoundSimIoControl for BoundPublicationBackend<SimIo> {
    fn inject(&mut self, ingress: IfId, bytes: Vec<u8>) -> u64 {
        let SimIoPublicationResponse::Sequence(sequence) =
            self.execute_backend_command(SimIoPublicationCommand::Inject { ingress, bytes })
        else {
            unreachable!("inject command has one response variant");
        };
        sequence
    }

    fn pending_rx(&self) -> usize {
        self.inner().pending_rx()
    }

    fn pending_tx(&self) -> usize {
        self.inner().pending_tx()
    }

    fn pop_tx(&mut self) -> Option<TxFrame> {
        let SimIoPublicationResponse::Tx(frame) =
            self.execute_backend_command(SimIoPublicationCommand::PopTx)
        else {
            unreachable!("pop-tx command has one response variant");
        };
        frame
    }

    fn pop_recycled(&mut self) -> Option<RecycledFrame> {
        let SimIoPublicationResponse::Recycled(frame) =
            self.execute_backend_command(SimIoPublicationCommand::PopRecycled)
        else {
            unreachable!("pop-recycled command has one response variant");
        };
        frame
    }
}

/// Shutdown and statistics operations for a bound [`SimIo`].
///
/// [`Self::stats`] is a non-authoritative observation: it reports queue
/// lengths from the bound backend at the instant of the call and does not
/// participate in publication quiescence. [`Self::retire_pending_rx`] is the
/// explicit shutdown operation for still-queued RX slots; it never retires
/// accepted TX or generated/recycle captures.
pub trait BoundSimIoObservabilityControl {
    /// Returns a scalar, allocation-free snapshot of backend-owned state.
    #[must_use]
    fn stats(&self) -> SimBackendStats;

    /// Retires cold-path, backend-owned, unleased RX slots only.
    ///
    /// The operation is failure-atomic and nonterminal on error; success does
    /// not mean publication quiescence.
    #[must_use = "the retirement result reports whether queued RX ownership was recovered"]
    fn retire_pending_rx(&mut self) -> Result<usize, SimPendingRxRetirementError>;
}

impl BoundSimIoObservabilityControl for BoundPublicationBackend<SimIo> {
    fn stats(&self) -> SimBackendStats {
        self.inner().stats()
    }

    fn retire_pending_rx(&mut self) -> Result<usize, SimPendingRxRetirementError> {
        let SimIoPublicationResponse::RetiredRx(result) =
            self.execute_backend_command(SimIoPublicationCommand::RetirePendingRx)
        else {
            unreachable!("retire-RX command has one response variant");
        };
        result
    }
}

impl PublicationQuiescenceBackend for SimIo {
    type Error = SimPublicationQuiescenceError;

    fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {
        match self.batch_state {
            SimBatchState::Rx => {
                return Err(SimPublicationQuiescenceError::RxBatchNotFinished);
            }
            SimBatchState::Generated => {
                return Err(SimPublicationQuiescenceError::GeneratedBatchNotFinished);
            }
            SimBatchState::Idle => {}
        }
        if self.rx_leases_live != 0 {
            return Err(SimPublicationQuiescenceError::RxLeaseNotCompleted);
        }
        if self.generated_leases_live != 0 {
            return Err(SimPublicationQuiescenceError::GeneratedLeaseNotCompleted);
        }
        if !self.tx.is_empty() {
            return Err(SimPublicationQuiescenceError::TxCompletionPending);
        }
        Ok(())
    }

    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
        if self.batch_state != SimBatchState::Idle
            || self.rx_leases_live != 0
            || self.generated_leases_live != 0
        {
            PublicationQuiescenceDisposition::SkipIo
        } else {
            PublicationQuiescenceDisposition::ContinueOldIo
        }
    }

    fn quiescence_error_disposition(error: &Self::Error) -> PublicationQuiescenceDisposition {
        match error {
            SimPublicationQuiescenceError::TxCompletionPending => {
                PublicationQuiescenceDisposition::ContinueOldIo
            }
            SimPublicationQuiescenceError::RxBatchNotFinished
            | SimPublicationQuiescenceError::GeneratedBatchNotFinished
            | SimPublicationQuiescenceError::RxLeaseNotCompleted
            | SimPublicationQuiescenceError::GeneratedLeaseNotCompleted => {
                PublicationQuiescenceDisposition::SkipIo
            }
        }
    }
}

impl PacketIo for SimIo {
    type Error = Infallible;
    type Batch<'a> = SimBatch<'a>;

    fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
        assert_eq!(
            self.batch_state,
            SimBatchState::Idle,
            "simulated packet batches cannot overlap"
        );
        assert_eq!(
            (self.rx_leases_live, self.generated_leases_live),
            (0, 0),
            "nonterminal packet leases prevent another batch"
        );
        self.batch_state = SimBatchState::Rx;
        let remaining = budget.min(self.rx.len());
        Ok(SimBatch {
            rx: &mut self.rx,
            tx: &mut self.tx,
            recycled: &mut self.recycled,
            accept_budget: &mut self.received_accept_budget,
            state: &mut self.batch_state,
            leases_live: &mut self.rx_leases_live,
            backend_stats: &mut self.backend_stats,
            remaining,
            counters: BatchCounters::default(),
        })
    }
}

pub struct SimBatch<'a> {
    rx: &'a mut VecDeque<Slot>,
    tx: &'a mut VecDeque<TxFrame>,
    recycled: &'a mut VecDeque<RecycledFrameCapture>,
    accept_budget: &'a mut usize,
    state: &'a mut SimBatchState,
    leases_live: &'a mut usize,
    backend_stats: &'a mut SimBackendStatsAccumulator,
    remaining: usize,
    counters: BatchCounters,
}

#[derive(Debug, Default)]
struct BatchCounters {
    tx_requested: usize,
    tx_accepted: usize,
    tx_rejected: usize,
    recycled: usize,
}

impl PacketBatch for SimBatch<'_> {
    type Error = Infallible;
    type Slot<'a>
        = SimSlot<'a>
    where
        Self: 'a;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        if self.remaining == 0 {
            return None;
        }
        let slot = self.rx.pop_front()?;
        self.remaining -= 1;
        *self.leases_live = self
            .leases_live
            .checked_add(1)
            .expect("simulated RX lease count cannot overflow");
        Some(PacketLease::new(SimSlot {
            slot: Some(slot),
            tx: self.tx,
            recycled: self.recycled,
            accept_budget: self.accept_budget,
            counters: &mut self.counters,
            leases_live: self.leases_live,
            backend_stats: self.backend_stats,
        }))
    }

    fn finish(self) -> BatchCompletion<Self::Error> {
        *self.state = SimBatchState::Idle;
        BatchCompletion {
            tx_requested: self.counters.tx_requested,
            tx_accepted: self.counters.tx_accepted,
            tx_rejected: self.counters.tx_rejected,
            recycled: self.counters.recycled,
            error: None,
        }
    }
}

impl Drop for SimBatch<'_> {
    fn drop(&mut self) {
        *self.state = SimBatchState::Idle;
    }
}

pub struct SimSlot<'a> {
    slot: Option<Slot>,
    tx: &'a mut VecDeque<TxFrame>,
    recycled: &'a mut VecDeque<RecycledFrameCapture>,
    accept_budget: &'a mut usize,
    counters: &'a mut BatchCounters,
    leases_live: &'a mut usize,
    backend_stats: &'a mut SimBackendStatsAccumulator,
}

impl PacketSlot for SimSlot<'_> {
    fn ingress(&self) -> IfId {
        self.slot.as_ref().expect("live sim slot").ingress
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.slot.as_mut().expect("live sim slot").bytes
    }

    fn complete(mut self, completion: SlotCompletion) {
        let slot = self.slot.take().expect("sim slot completed exactly once");
        match completion {
            SlotCompletion::Transmit(egress) => {
                self.counters.tx_requested += 1;
                if *self.accept_budget == 0 {
                    self.counters.tx_rejected += 1;
                    self.recycled.push_back(RecycledFrameCapture {
                        frame: RecycledFrame {
                            sequence: slot.sequence,
                            ingress: slot.ingress,
                            cause: RecycleCause::TxRejected,
                            bytes: slot.bytes,
                        },
                        rejected_egress: Some(egress),
                    });
                    self.backend_stats
                        .record_rx_recycle(RecycleCause::TxRejected);
                } else {
                    *self.accept_budget -= 1;
                    self.tx.push_back(TxFrame {
                        sequence: slot.sequence,
                        ingress: slot.ingress,
                        egress,
                        origin: FrameOrigin::Received {
                            ingress: slot.ingress,
                        },
                        bytes: slot.bytes,
                    });
                    self.counters.tx_accepted += 1;
                    self.backend_stats.record_accepted_tx(1, self.tx.len());
                }
            }
            SlotCompletion::Recycle(reason) => {
                self.recycle(slot, RecycleCause::Forwarding(reason));
            }
            SlotCompletion::Consume(reason) => {
                self.recycle(slot, RecycleCause::Consumed(reason));
            }
            SlotCompletion::LeaseAbandoned => {
                self.recycle(slot, RecycleCause::LeaseAbandoned);
            }
        }
        *self.leases_live = self
            .leases_live
            .checked_sub(1)
            .expect("simulated RX lease completed exactly once");
    }
}

impl GeneratedPacketIo for SimIo {
    type Error = SimGeneratedError;
    type Batch<'a> = SimGeneratedBatch<'a>;

    fn begin_generated(&mut self, egress: IfId) -> Self::Batch<'_> {
        assert_eq!(
            self.batch_state,
            SimBatchState::Idle,
            "simulated packet batches cannot overlap"
        );
        assert_eq!(
            (self.rx_leases_live, self.generated_leases_live),
            (0, 0),
            "nonterminal packet leases prevent another batch"
        );
        self.batch_state = SimBatchState::Generated;
        let fail_finish = self.fail_generated_finish;
        self.fail_generated_finish = false;
        SimGeneratedBatch {
            next_sequence: &mut self.next_sequence,
            tx: &mut self.tx,
            recycled: &mut self.generated_recycled,
            egress,
            remaining_allocations: self.generated_budget,
            max_frame: self.generated_max_frame,
            accept_budget: self.generated_accept_budget,
            fail_finish,
            pending: VecDeque::new(),
            counters: GeneratedCounters::default(),
            state: &mut self.batch_state,
            leases_live: &mut self.generated_leases_live,
            backend_stats: &mut self.backend_stats,
        }
    }
}

// SAFETY: receive and begin_generated return lifetime-bounded batches borrowing
// private fields of this exact SimIo; their slots only borrow those batches and
// cannot return SimIo or an independent mutable alias. Operational errors are
// closed Copy enums or Infallible. No method replaces the backend as a whole,
// and the quiescence hook observes the shared batch state, all live lease counts,
// and every accepted TX retained by the simulator. Retirement runs only on this
// exact SimIo/wrapper identity, never hides live batches or leases or pending
// TX from quiescence, and stats snapshots are non-authoritative.
#[allow(unsafe_code)]
unsafe impl PublicationBackendAuthority for SimIo {}

#[derive(Debug)]
struct GeneratedSlot {
    sequence: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
struct GeneratedCounters {
    attempts: usize,
    allocated: usize,
    failed: usize,
    requested: usize,
    cancelled: usize,
    abandoned: usize,
}

pub struct SimGeneratedBatch<'a> {
    next_sequence: &'a mut u64,
    tx: &'a mut VecDeque<TxFrame>,
    recycled: &'a mut VecDeque<GeneratedRecycledFrame>,
    egress: IfId,
    remaining_allocations: usize,
    max_frame: usize,
    accept_budget: usize,
    fail_finish: bool,
    pending: VecDeque<GeneratedSlot>,
    counters: GeneratedCounters,
    state: &'a mut SimBatchState,
    leases_live: &'a mut usize,
    backend_stats: &'a mut SimBackendStatsAccumulator,
}

impl GeneratedPacketBatch for SimGeneratedBatch<'_> {
    type Error = SimGeneratedError;
    type Slot<'a>
        = SimGeneratedSlot<'a>
    where
        Self: 'a;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        self.counters.attempts += 1;
        let error = if frame_len == 0 {
            Some(GeneratedAllocationError::ZeroLength)
        } else if frame_len > self.max_frame {
            Some(GeneratedAllocationError::FrameTooLarge)
        } else if self.remaining_allocations == 0 {
            Some(GeneratedAllocationError::Unavailable)
        } else {
            None
        };
        if let Some(error) = error {
            self.counters.failed += 1;
            return Err(error);
        }
        self.remaining_allocations -= 1;
        self.counters.allocated += 1;
        *self.leases_live = self
            .leases_live
            .checked_add(1)
            .expect("simulated generated lease count cannot overflow");
        let sequence = *self.next_sequence;
        *self.next_sequence = self.next_sequence.wrapping_add(1);
        Ok(GeneratedPacketLease::new(SimGeneratedSlot {
            slot: Some(GeneratedSlot {
                sequence,
                bytes: vec![0xa5; frame_len],
            }),
            pending: &mut self.pending,
            recycled: self.recycled,
            counters: &mut self.counters,
            egress: self.egress,
            leases_live: self.leases_live,
            backend_stats: self.backend_stats,
        }))
    }

    fn finish(mut self) -> GeneratedBatchCompletion<Self::Error> {
        let accepted = self.accept_budget.min(self.pending.len());
        for _ in 0..accepted {
            let slot = self.pending.pop_front().expect("accepted generated slot");
            self.tx.push_back(TxFrame {
                sequence: slot.sequence,
                ingress: self.egress,
                egress: self.egress,
                origin: FrameOrigin::Generated,
                bytes: slot.bytes,
            });
        }
        self.backend_stats
            .record_accepted_tx(accepted, self.tx.len());
        let rejected = self.recycle_pending();
        *self.state = SimBatchState::Idle;
        GeneratedBatchCompletion {
            attempts: self.counters.attempts,
            allocated: self.counters.allocated,
            failed: self.counters.failed,
            requested: self.counters.requested,
            cancelled: self.counters.cancelled,
            abandoned: self.counters.abandoned,
            accepted,
            rejected,
            error: self.fail_finish.then_some(SimGeneratedError::Injected),
        }
    }
}

impl Drop for SimGeneratedBatch<'_> {
    fn drop(&mut self) {
        *self.state = SimBatchState::Idle;
        self.recycle_pending();
    }
}

impl SimGeneratedBatch<'_> {
    fn recycle_pending(&mut self) -> usize {
        let rejected = self.pending.len();
        while let Some(slot) = self.pending.pop_front() {
            self.recycled.push_back(GeneratedRecycledFrame {
                sequence: slot.sequence,
                egress: self.egress,
                cause: GeneratedRecycleCause::TxRejected,
                bytes: slot.bytes,
            });
            self.backend_stats
                .record_generated_recycle(GeneratedRecycleCause::TxRejected);
        }
        rejected
    }
}

pub struct SimGeneratedSlot<'a> {
    slot: Option<GeneratedSlot>,
    pending: &'a mut VecDeque<GeneratedSlot>,
    recycled: &'a mut VecDeque<GeneratedRecycledFrame>,
    counters: &'a mut GeneratedCounters,
    egress: IfId,
    leases_live: &'a mut usize,
    backend_stats: &'a mut SimBackendStatsAccumulator,
}

impl GeneratedPacketSlot for SimGeneratedSlot<'_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.slot.as_mut().expect("live generated sim slot").bytes
    }

    fn complete(mut self, completion: GeneratedSlotCompletion) {
        let slot = self
            .slot
            .take()
            .expect("generated sim slot completed exactly once");
        match completion {
            GeneratedSlotCompletion::Transmit => {
                self.counters.requested += 1;
                self.pending.push_back(slot);
            }
            GeneratedSlotCompletion::Cancelled => {
                self.counters.cancelled += 1;
                self.recycle(slot, GeneratedRecycleCause::Cancelled);
            }
            GeneratedSlotCompletion::Abandoned => {
                self.counters.abandoned += 1;
                self.recycle(slot, GeneratedRecycleCause::Abandoned);
            }
        }
        *self.leases_live = self
            .leases_live
            .checked_sub(1)
            .expect("simulated generated lease completed exactly once");
    }
}

impl SimGeneratedSlot<'_> {
    fn recycle(&mut self, slot: GeneratedSlot, cause: GeneratedRecycleCause) {
        self.recycled.push_back(GeneratedRecycledFrame {
            sequence: slot.sequence,
            egress: self.egress,
            cause,
            bytes: slot.bytes,
        });
        self.backend_stats.record_generated_recycle(cause);
    }
}

impl SimSlot<'_> {
    fn recycle(&mut self, slot: Slot, cause: RecycleCause) {
        self.recycled.push_back(RecycledFrameCapture {
            frame: RecycledFrame {
                sequence: slot.sequence,
                ingress: slot.ingress,
                cause,
                bytes: slot.bytes,
            },
            rejected_egress: None,
        });
        self.counters.recycled += 1;
        self.backend_stats.record_rx_recycle(cause);
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct VecTrace {
    events: Vec<TraceEvent>,
}

impl VecTrace {
    #[must_use]
    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl TraceSink for VecTrace {
    fn record(&mut self, event: TraceEvent) {
        self.events.push(event);
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct VecGeneratedTrace {
    events: Vec<GeneratedArpTrace>,
}

impl VecGeneratedTrace {
    #[must_use]
    pub fn events(&self) -> &[GeneratedArpTrace] {
        &self.events
    }
}

impl GeneratedTraceSink for VecGeneratedTrace {
    fn record_generated(&mut self, event: GeneratedArpTrace) {
        self.events.push(event);
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct VecGeneratedIcmpv4Trace {
    events: Vec<GeneratedIcmpv4Trace>,
}

impl VecGeneratedIcmpv4Trace {
    #[must_use]
    pub fn events(&self) -> &[GeneratedIcmpv4Trace] {
        &self.events
    }
}

impl GeneratedIcmpv4TraceSink for VecGeneratedIcmpv4Trace {
    fn record_generated_icmpv4(&mut self, event: GeneratedIcmpv4Trace) {
        self.events.push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_stats_accumulator_saturates_every_cumulative_counter() {
        let mut accumulator = SimBackendStatsAccumulator {
            rx_queue_high_watermark: u64::MAX,
            tx_queue_high_watermark: u64::MAX,
            injected_rx_total: u64::MAX,
            accepted_tx_total: u64::MAX,
            completed_tx_total: u64::MAX,
            rx_forwarding_recycled_total: u64::MAX,
            rx_consumed_total: u64::MAX,
            rx_tx_rejected_total: u64::MAX,
            rx_lease_abandoned_total: u64::MAX,
            generated_cancelled_total: u64::MAX,
            generated_abandoned_total: u64::MAX,
            generated_tx_rejected_total: u64::MAX,
            retired_rx_total: u64::MAX,
        };

        accumulator.record_injected_rx(usize::MAX);
        accumulator.record_accepted_tx(usize::MAX, usize::MAX);
        accumulator.record_completed_tx();
        accumulator.record_rx_recycle(RecycleCause::Forwarding(DropReason::RouteMiss));
        accumulator.record_rx_recycle(RecycleCause::Consumed(ConsumeReason::ArpControl));
        accumulator.record_rx_recycle(RecycleCause::TxRejected);
        accumulator.record_rx_recycle(RecycleCause::LeaseAbandoned);
        accumulator.record_generated_recycle(GeneratedRecycleCause::Cancelled);
        accumulator.record_generated_recycle(GeneratedRecycleCause::Abandoned);
        accumulator.record_generated_recycle(GeneratedRecycleCause::TxRejected);
        accumulator.record_retired_rx(usize::MAX);

        let snapshot = accumulator.snapshot(usize::MAX, usize::MAX, usize::MAX, usize::MAX);
        assert_eq!(
            snapshot,
            SimBackendStats {
                pending_rx: usize_to_u64_saturating(usize::MAX),
                rx_queue_high_watermark: u64::MAX,
                pending_tx: usize_to_u64_saturating(usize::MAX),
                tx_queue_high_watermark: u64::MAX,
                pending_recycled: usize_to_u64_saturating(usize::MAX),
                pending_generated_recycled: usize_to_u64_saturating(usize::MAX),
                injected_rx_total: u64::MAX,
                accepted_tx_total: u64::MAX,
                completed_tx_total: u64::MAX,
                rx_forwarding_recycled_total: u64::MAX,
                rx_consumed_total: u64::MAX,
                rx_tx_rejected_total: u64::MAX,
                rx_lease_abandoned_total: u64::MAX,
                generated_cancelled_total: u64::MAX,
                generated_abandoned_total: u64::MAX,
                generated_tx_rejected_total: u64::MAX,
                retired_rx_total: u64::MAX,
            }
        );
    }
}
