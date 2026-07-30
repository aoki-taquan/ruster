#![forbid(unsafe_code)]
#![doc = "Allocation-free, bounded single-worker tick orchestration for ruster."]

use ruster_core::{
    dispatch_host_unreachable_failures, execute_one_arp_request, execute_one_icmpv4_error,
    forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors, poll_resolution_timers,
    ArpRequestBuildError, BatchReport, ExecuteArpRequestError, ExecuteIcmpv4Error, FirewallConfig,
    FirewallRuntime, ForwardingSnapshot, GeneratedAllocationError, GeneratedIcmpv4TraceSink,
    GeneratedPacketIo, GeneratedTraceSink, Icmpv4ErrorBuildError, Icmpv4ErrorRuntime,
    MonotonicMillis, Nat44TcpConfig, Nat44TcpRuntime, Nat44UdpConfig, Nat44UdpRuntime, PacketIo,
    ResolutionFailureDispatchError, ResolutionFailureDispatchReport, ResolutionFailureTraceSink,
    ResolutionRuntime, ResolutionTimerError, ResolutionTimerReport, ResolutionTimerTraceSink,
    TraceSink,
};

/// All immutable authority and mutable worker-local state required by the
/// full UDP/TCP NAT44, firewall, resolution, and generated ICMP composition.
pub struct FullServiceView<'view, 'storage> {
    pub snapshot: &'view ForwardingSnapshot<'storage>,
    pub resolution: &'view mut ResolutionRuntime<'storage>,
    pub icmpv4_errors: &'view mut Icmpv4ErrorRuntime<'storage>,
    pub udp_config: &'view Nat44UdpConfig,
    pub nat44_udp: Option<&'view mut Nat44UdpRuntime<'storage>>,
    pub tcp_config: &'view Nat44TcpConfig,
    pub nat44_tcp: Option<&'view mut Nat44TcpRuntime<'storage>>,
    pub firewall_config: &'view FirewallConfig<'storage>,
    pub firewall: Option<&'view mut FirewallRuntime<'storage>>,
}

/// Atomic publication seam used by [`run_tick`].
///
/// `publish_candidate` must either install the entire candidate or leave the
/// previous active publication unchanged. A rejected candidate is reported,
/// but does not stop the tick: `active` is subsequently called so the old
/// publication can continue serving traffic. The active view returned for a
/// tick must remain one coherent generation until the view is dropped.
pub trait FullServicePublication<'storage> {
    type Candidate;
    type Reject;

    fn publish_candidate(&mut self, candidate: Self::Candidate) -> Result<(), Self::Reject>;

    fn active(&mut self) -> Option<FullServiceView<'_, 'storage>>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TickBudgets {
    pub rx: usize,
    pub resolution_timer_scans: usize,
    pub failure_dispatch_scans: usize,
    pub generated_arp: usize,
    pub generated_icmpv4: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TickPhase {
    Publication,
    Rx,
    ResolutionTimers,
    FailureDispatch,
    GeneratedArp,
    GeneratedIcmpv4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TickPhaseSkip {
    NoActivePublication,
    BackendIoFailure,
    BackendContractViolation,
    ClockRegression,
    GeneratedArpFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TickPhaseTrace {
    TickStarted,
    PhaseStarted(TickPhase),
    PhaseFinished(TickPhase),
    PhaseSkipped {
        phase: TickPhase,
        reason: TickPhaseSkip,
    },
    TickFinished,
}

pub trait TickPhaseTraceSink {
    fn record_tick_phase(&mut self, event: TickPhaseTrace);
}

#[derive(Default)]
pub struct NoTickPhaseTrace;

impl TickPhaseTraceSink for NoTickPhaseTrace {
    fn record_tick_phase(&mut self, _event: TickPhaseTrace) {}
}

#[derive(Debug, Eq, PartialEq)]
pub enum PublicationOutcome<E> {
    Unchanged,
    Applied,
    Rejected(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseReport<T, E> {
    Skipped(TickPhaseSkip),
    Completed(T),
    Failed(E),
}

#[derive(Debug, Eq, PartialEq)]
pub enum RxPhaseReport<E> {
    Skipped(TickPhaseSkip),
    ReceiveFailed(E),
    Completed(BatchReport<E>),
    AccountingInvariantViolation(BatchReport<E>),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GeneratedAccounting {
    pub sessions: usize,
    pub allocation_attempts: usize,
    pub allocated: usize,
    pub allocation_failed: usize,
    pub tx_requested: usize,
    pub cancelled: usize,
    pub abandoned: usize,
    /// Backend-accepted TX requests. This is descriptor publication, not wire
    /// delivery and not completion-queue ownership return.
    pub tx_accepted: usize,
    pub tx_rejected: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedCompletion<E> {
    pub attempts: usize,
    pub allocated: usize,
    pub failed: usize,
    pub requested: usize,
    pub cancelled: usize,
    pub abandoned: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub error: Option<E>,
}

impl<E> GeneratedCompletion<E> {
    fn from_core(completion: ruster_core::GeneratedBatchCompletion<E>) -> Self {
        Self {
            attempts: completion.attempts,
            allocated: completion.allocated,
            failed: completion.failed,
            requested: completion.requested,
            cancelled: completion.cancelled,
            abandoned: completion.abandoned,
            accepted: completion.accepted,
            rejected: completion.rejected,
            error: completion.error,
        }
    }

    #[must_use]
    pub const fn invariants_hold(&self) -> bool {
        let Some(attempts) = self.allocated.checked_add(self.failed) else {
            return false;
        };
        let Some(allocated) = self.requested.checked_add(self.cancelled) else {
            return false;
        };
        let Some(allocated) = allocated.checked_add(self.abandoned) else {
            return false;
        };
        let Some(requested) = self.accepted.checked_add(self.rejected) else {
            return false;
        };
        self.attempts == attempts && self.allocated == allocated && self.requested == requested
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedAccountingViolation<E, B> {
    pub completion: GeneratedCompletion<E>,
    pub allocation: Option<GeneratedAllocationError>,
    pub build: Option<B>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedArpFailure<E> {
    pub allocation: Option<GeneratedAllocationError>,
    pub build: Option<ArpRequestBuildError>,
    pub finish: Option<E>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum GeneratedArpStop<E> {
    QueueEmpty,
    BudgetExhausted { pending: usize },
    ClockRegression,
    Failed(GeneratedArpFailure<E>),
    AccountingInvariantViolation(GeneratedAccountingViolation<E, ArpRequestBuildError>),
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedIcmpv4Failure<E> {
    pub allocation: Option<GeneratedAllocationError>,
    pub build: Option<Icmpv4ErrorBuildError>,
    pub finish: Option<E>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum GeneratedIcmpv4Stop<E> {
    QueueEmpty,
    BudgetExhausted { pending: usize },
    ClockRegression,
    Failed(GeneratedIcmpv4Failure<E>),
    AccountingInvariantViolation(GeneratedAccountingViolation<E, Icmpv4ErrorBuildError>),
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedPhaseReport<S> {
    pub accounting: GeneratedAccounting,
    pub stop: S,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TickReport<PublicationError, RxError, GeneratedError> {
    pub publication: PublicationOutcome<PublicationError>,
    pub active: bool,
    pub rx: RxPhaseReport<RxError>,
    pub resolution_timers: PhaseReport<ResolutionTimerReport, ResolutionTimerError>,
    pub failure_dispatch:
        PhaseReport<ResolutionFailureDispatchReport, ResolutionFailureDispatchError>,
    pub generated_arp: PhaseReport<
        GeneratedPhaseReport<GeneratedArpStop<GeneratedError>>,
        core::convert::Infallible,
    >,
    pub generated_icmpv4: PhaseReport<
        GeneratedPhaseReport<GeneratedIcmpv4Stop<GeneratedError>>,
        core::convert::Infallible,
    >,
}

fn add_generated_accounting<E>(
    total: &mut GeneratedAccounting,
    completion: &GeneratedCompletion<E>,
) -> bool {
    let Some(sessions) = total.sessions.checked_add(1) else {
        return false;
    };
    total.sessions = sessions;
    if !completion.invariants_hold() {
        return false;
    }
    let Some(allocation_attempts) = total.allocation_attempts.checked_add(completion.attempts)
    else {
        return false;
    };
    let Some(allocated) = total.allocated.checked_add(completion.allocated) else {
        return false;
    };
    let Some(allocation_failed) = total.allocation_failed.checked_add(completion.failed) else {
        return false;
    };
    let Some(tx_requested) = total.tx_requested.checked_add(completion.requested) else {
        return false;
    };
    let Some(cancelled) = total.cancelled.checked_add(completion.cancelled) else {
        return false;
    };
    let Some(abandoned) = total.abandoned.checked_add(completion.abandoned) else {
        return false;
    };
    let Some(tx_accepted) = total.tx_accepted.checked_add(completion.accepted) else {
        return false;
    };
    let Some(tx_rejected) = total.tx_rejected.checked_add(completion.rejected) else {
        return false;
    };
    *total = GeneratedAccounting {
        sessions,
        allocation_attempts,
        allocated,
        allocation_failed,
        tx_requested,
        cancelled,
        abandoned,
        tx_accepted,
        tx_rejected,
    };
    true
}

fn run_generated_arp<I, T>(
    io: &mut I,
    runtime: &mut ResolutionRuntime<'_>,
    now: MonotonicMillis,
    budget: usize,
    trace: &mut T,
) -> (
    GeneratedPhaseReport<GeneratedArpStop<I::Error>>,
    Option<TickPhaseSkip>,
)
where
    I: GeneratedPacketIo,
    T: GeneratedTraceSink,
{
    let mut accounting = GeneratedAccounting::default();
    for _ in 0..budget {
        let result = match execute_one_arp_request(io, runtime, now, trace) {
            Ok(Some(result)) => result,
            Ok(None) => {
                return (
                    GeneratedPhaseReport {
                        accounting,
                        stop: GeneratedArpStop::QueueEmpty,
                    },
                    None,
                );
            }
            Err(ExecuteArpRequestError::ClockRegression) => {
                return (
                    GeneratedPhaseReport {
                        accounting,
                        stop: GeneratedArpStop::ClockRegression,
                    },
                    Some(TickPhaseSkip::ClockRegression),
                );
            }
        };
        let completion = GeneratedCompletion::from_core(result.completion);
        let accounting_valid = add_generated_accounting(&mut accounting, &completion);
        if !accounting_valid {
            return (
                GeneratedPhaseReport {
                    accounting,
                    stop: GeneratedArpStop::AccountingInvariantViolation(
                        GeneratedAccountingViolation {
                            completion,
                            allocation: result.allocation_error,
                            build: result.build_error,
                        },
                    ),
                },
                Some(TickPhaseSkip::BackendContractViolation),
            );
        }
        let failure = GeneratedArpFailure {
            allocation: result.allocation_error,
            build: result.build_error,
            finish: completion.error,
        };
        if failure.allocation.is_some() || failure.build.is_some() || failure.finish.is_some() {
            let downstream_skip = if failure.finish.is_some() {
                Some(TickPhaseSkip::BackendIoFailure)
            } else if failure.build.is_some()
                || failure
                    .allocation
                    .is_some_and(|error| error != GeneratedAllocationError::Unavailable)
            {
                Some(TickPhaseSkip::GeneratedArpFailure)
            } else {
                None
            };
            return (
                GeneratedPhaseReport {
                    accounting,
                    stop: GeneratedArpStop::Failed(failure),
                },
                downstream_skip,
            );
        }
    }
    let pending = runtime.pending_actions();
    (
        GeneratedPhaseReport {
            accounting,
            stop: if pending == 0 {
                GeneratedArpStop::QueueEmpty
            } else {
                GeneratedArpStop::BudgetExhausted { pending }
            },
        },
        None,
    )
}

fn run_generated_icmpv4<I, T>(
    io: &mut I,
    runtime: &mut Icmpv4ErrorRuntime<'_>,
    now: MonotonicMillis,
    budget: usize,
    trace: &mut T,
) -> (
    GeneratedPhaseReport<GeneratedIcmpv4Stop<I::Error>>,
    Option<TickPhaseSkip>,
)
where
    I: GeneratedPacketIo,
    T: GeneratedIcmpv4TraceSink,
{
    let mut accounting = GeneratedAccounting::default();
    for _ in 0..budget {
        let result = match execute_one_icmpv4_error(io, runtime, now, trace) {
            Ok(Some(result)) => result,
            Ok(None) => {
                return (
                    GeneratedPhaseReport {
                        accounting,
                        stop: GeneratedIcmpv4Stop::QueueEmpty,
                    },
                    None,
                );
            }
            Err(ExecuteIcmpv4Error::ClockRegression) => {
                return (
                    GeneratedPhaseReport {
                        accounting,
                        stop: GeneratedIcmpv4Stop::ClockRegression,
                    },
                    Some(TickPhaseSkip::ClockRegression),
                );
            }
        };
        let completion = GeneratedCompletion::from_core(result.completion);
        let accounting_valid = add_generated_accounting(&mut accounting, &completion);
        if !accounting_valid {
            return (
                GeneratedPhaseReport {
                    accounting,
                    stop: GeneratedIcmpv4Stop::AccountingInvariantViolation(
                        GeneratedAccountingViolation {
                            completion,
                            allocation: result.allocation_error,
                            build: result.build_error,
                        },
                    ),
                },
                Some(TickPhaseSkip::BackendContractViolation),
            );
        }
        let failure = GeneratedIcmpv4Failure {
            allocation: result.allocation_error,
            build: result.build_error,
            finish: completion.error,
        };
        if failure.allocation.is_some() || failure.build.is_some() || failure.finish.is_some() {
            return (
                GeneratedPhaseReport {
                    accounting,
                    stop: GeneratedIcmpv4Stop::Failed(failure),
                },
                None,
            );
        }
    }
    let pending = runtime.pending_actions();
    (
        GeneratedPhaseReport {
            accounting,
            stop: if pending == 0 {
                GeneratedIcmpv4Stop::QueueEmpty
            } else {
                GeneratedIcmpv4Stop::BudgetExhausted { pending }
            },
        },
        None,
    )
}

fn skip_phase<T: TickPhaseTraceSink>(trace: &mut T, phase: TickPhase, reason: TickPhaseSkip) {
    trace.record_tick_phase(TickPhaseTrace::PhaseSkipped { phase, reason });
}

/// Runs one bounded, single-worker service tick.
///
/// The phase order is publication, RX, resolution timers, failure dispatch,
/// generated ARP, and generated ICMPv4. The RX batch is moved into the full
/// composition wrapper in a lexical scope and is therefore finished before
/// either generated session can borrow `io`.
///
/// A backend accounting violation suppresses all later generated I/O in the
/// tick. A valid finish error, allocation error, or build error stops that
/// generated phase after one attempt while retaining any uncommitted action.
/// RX receive/finish errors still permit the non-I/O timer and failure phases,
/// but suppress generated I/O for the tick. Clock regression suppresses every
/// downstream phase. ARP allocation `Unavailable` is the only ARP failure that
/// still permits the independent ICMPv4 generated phase.
///
/// The backend contracts also prevent a caller from overlapping an RX batch
/// with a generated session:
///
/// ```compile_fail
/// use ruster_core::{GeneratedPacketIo, IfId, PacketIo};
///
/// fn overlap<I>(io: &mut I)
/// where
///     I: PacketIo + GeneratedPacketIo,
/// {
///     let Ok(rx) = io.receive(1) else { return };
///     let generated = io.begin_generated(IfId(1));
///     drop((rx, generated));
/// }
/// ```
#[allow(clippy::too_many_arguments)]
pub fn run_tick<'storage, P, I, T>(
    publication: &mut P,
    candidate: Option<P::Candidate>,
    io: &mut I,
    now: MonotonicMillis,
    budgets: TickBudgets,
    trace: &mut T,
) -> TickReport<P::Reject, <I as PacketIo>::Error, <I as GeneratedPacketIo>::Error>
where
    P: FullServicePublication<'storage>,
    I: PacketIo + GeneratedPacketIo,
    T: TickPhaseTraceSink
        + TraceSink
        + ResolutionTimerTraceSink
        + ResolutionFailureTraceSink
        + GeneratedTraceSink
        + GeneratedIcmpv4TraceSink,
{
    trace.record_tick_phase(TickPhaseTrace::TickStarted);
    trace.record_tick_phase(TickPhaseTrace::PhaseStarted(TickPhase::Publication));
    let publication_report = match candidate {
        Some(candidate) => match publication.publish_candidate(candidate) {
            Ok(()) => PublicationOutcome::Applied,
            Err(error) => PublicationOutcome::Rejected(error),
        },
        None => PublicationOutcome::Unchanged,
    };
    trace.record_tick_phase(TickPhaseTrace::PhaseFinished(TickPhase::Publication));

    let Some(view) = publication.active() else {
        for phase in [
            TickPhase::Rx,
            TickPhase::ResolutionTimers,
            TickPhase::FailureDispatch,
            TickPhase::GeneratedArp,
            TickPhase::GeneratedIcmpv4,
        ] {
            skip_phase(trace, phase, TickPhaseSkip::NoActivePublication);
        }
        trace.record_tick_phase(TickPhaseTrace::TickFinished);
        return TickReport {
            publication: publication_report,
            active: false,
            rx: RxPhaseReport::Skipped(TickPhaseSkip::NoActivePublication),
            resolution_timers: PhaseReport::Skipped(TickPhaseSkip::NoActivePublication),
            failure_dispatch: PhaseReport::Skipped(TickPhaseSkip::NoActivePublication),
            generated_arp: PhaseReport::Skipped(TickPhaseSkip::NoActivePublication),
            generated_icmpv4: PhaseReport::Skipped(TickPhaseSkip::NoActivePublication),
        };
    };
    let FullServiceView {
        snapshot,
        resolution,
        icmpv4_errors,
        udp_config,
        nat44_udp,
        tcp_config,
        nat44_tcp,
        firewall_config,
        firewall,
    } = view;

    trace.record_tick_phase(TickPhaseTrace::PhaseStarted(TickPhase::Rx));
    let rx = match io.receive(budgets.rx) {
        Ok(batch) => {
            let report = forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors(
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
            );
            if report.invariants_hold() {
                RxPhaseReport::Completed(report)
            } else {
                RxPhaseReport::AccountingInvariantViolation(report)
            }
        }
        Err(error) => RxPhaseReport::ReceiveFailed(error),
    };
    let mut generated_skip = match &rx {
        RxPhaseReport::AccountingInvariantViolation(_) => {
            Some(TickPhaseSkip::BackendContractViolation)
        }
        RxPhaseReport::ReceiveFailed(_) => Some(TickPhaseSkip::BackendIoFailure),
        RxPhaseReport::Completed(report) if report.completion.error.is_some() => {
            Some(TickPhaseSkip::BackendIoFailure)
        }
        RxPhaseReport::Skipped(_) | RxPhaseReport::Completed(_) => None,
    };
    trace.record_tick_phase(TickPhaseTrace::PhaseFinished(TickPhase::Rx));

    trace.record_tick_phase(TickPhaseTrace::PhaseStarted(TickPhase::ResolutionTimers));
    let resolution_timers =
        match poll_resolution_timers(resolution, now, budgets.resolution_timer_scans, trace) {
            Ok(report) => PhaseReport::Completed(report),
            Err(error) => PhaseReport::Failed(error),
        };
    trace.record_tick_phase(TickPhaseTrace::PhaseFinished(TickPhase::ResolutionTimers));

    let failure_dispatch = if matches!(
        resolution_timers,
        PhaseReport::Failed(ResolutionTimerError::ClockRegression)
    ) {
        skip_phase(
            trace,
            TickPhase::FailureDispatch,
            TickPhaseSkip::ClockRegression,
        );
        if generated_skip.is_none() {
            generated_skip = Some(TickPhaseSkip::ClockRegression);
        }
        PhaseReport::Skipped(TickPhaseSkip::ClockRegression)
    } else {
        trace.record_tick_phase(TickPhaseTrace::PhaseStarted(TickPhase::FailureDispatch));
        let report = match dispatch_host_unreachable_failures(
            resolution,
            icmpv4_errors,
            snapshot,
            now,
            budgets.failure_dispatch_scans,
            trace,
        ) {
            Ok(report) => PhaseReport::Completed(report),
            Err(error) => PhaseReport::Failed(error),
        };
        trace.record_tick_phase(TickPhaseTrace::PhaseFinished(TickPhase::FailureDispatch));
        if matches!(
            report,
            PhaseReport::Failed(ResolutionFailureDispatchError::ClockRegression)
        ) && generated_skip.is_none()
        {
            generated_skip = Some(TickPhaseSkip::ClockRegression);
        }
        report
    };

    let (generated_arp, arp_skip) = if let Some(reason) = generated_skip {
        skip_phase(trace, TickPhase::GeneratedArp, reason);
        (PhaseReport::Skipped(reason), Some(reason))
    } else {
        trace.record_tick_phase(TickPhaseTrace::PhaseStarted(TickPhase::GeneratedArp));
        let (report, downstream_skip) =
            run_generated_arp(io, resolution, now, budgets.generated_arp, trace);
        trace.record_tick_phase(TickPhaseTrace::PhaseFinished(TickPhase::GeneratedArp));
        (PhaseReport::Completed(report), downstream_skip)
    };

    let generated_icmpv4 = if let Some(reason) = arp_skip {
        skip_phase(trace, TickPhase::GeneratedIcmpv4, reason);
        PhaseReport::Skipped(reason)
    } else {
        trace.record_tick_phase(TickPhaseTrace::PhaseStarted(TickPhase::GeneratedIcmpv4));
        let (report, _) =
            run_generated_icmpv4(io, icmpv4_errors, now, budgets.generated_icmpv4, trace);
        trace.record_tick_phase(TickPhaseTrace::PhaseFinished(TickPhase::GeneratedIcmpv4));
        PhaseReport::Completed(report)
    };

    trace.record_tick_phase(TickPhaseTrace::TickFinished);
    TickReport {
        publication: publication_report,
        active: true,
        rx,
        resolution_timers,
        failure_dispatch,
        generated_arp,
        generated_icmpv4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruster_core::{
        forward_batch_with_resolution, forward_batch_with_resolution_and_icmpv4_errors,
        ipv4_header_checksum, BatchCompletion, FirewallHashKey, FirewallPolicy,
        GeneratedBatchCompletion, GeneratedPacketBatch, GeneratedPacketLease, GeneratedPacketSlot,
        GeneratedSlotCompletion, GeneratedTraceSink, Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy,
        Icmpv4ErrorStateSlot, IfId, Interface, Ipv4Address, LocalIpv4Binding, MacAddress,
        Nat44TcpPolicy, Nat44UdpPolicy, Neighbor, NoTrace, PacketBatch, PacketLease, PacketSlot,
        ResolutionActionSlot, ResolutionFailureHoldSlot, ResolutionFailureTrace, ResolutionPolicy,
        ResolutionStateSlot, ResolutionTimerTrace, Route, SlotCompletion, TraceEvent,
    };
    use ruster_io_sim::{FrameOrigin, SimIo};

    const LAN: IfId = IfId(1);
    const WAN: IfId = IfId(2);
    const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
    const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
    const HOST_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 50]);
    const LAN_IP: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 1]);
    const HOST_IP: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 50]);
    const WAN_IP: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);
    const GATEWAY: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 1]);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Candidate {
        Apply,
        Reject,
    }

    struct TestPublication<'view, 'storage> {
        enabled: bool,
        applied: usize,
        snapshot: &'view ForwardingSnapshot<'storage>,
        resolution: &'view mut ResolutionRuntime<'storage>,
        icmpv4_errors: &'view mut Icmpv4ErrorRuntime<'storage>,
        udp_config: Nat44UdpConfig,
        tcp_config: Nat44TcpConfig,
        firewall_config: FirewallConfig<'storage>,
    }

    impl<'view, 'storage> FullServicePublication<'storage> for TestPublication<'view, 'storage> {
        type Candidate = Candidate;
        type Reject = &'static str;

        fn publish_candidate(&mut self, candidate: Self::Candidate) -> Result<(), Self::Reject> {
            match candidate {
                Candidate::Apply => {
                    self.applied += 1;
                    Ok(())
                }
                Candidate::Reject => Err("rejected"),
            }
        }

        fn active(&mut self) -> Option<FullServiceView<'_, 'storage>> {
            self.enabled.then_some(FullServiceView {
                snapshot: self.snapshot,
                resolution: self.resolution,
                icmpv4_errors: self.icmpv4_errors,
                udp_config: &self.udp_config,
                nat44_udp: None,
                tcp_config: &self.tcp_config,
                nat44_tcp: None,
                firewall_config: &self.firewall_config,
                firewall: None,
            })
        }
    }

    fn with_fixture(run: impl FnOnce(&mut TestPublication<'_, '_>, &mut TestIo, &mut TestTrace)) {
        let routes = [
            Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
            Route::new(Ipv4Address::from_octets([0; 4]), 0, WAN, Some(GATEWAY)).unwrap(),
        ];
        let interfaces = [
            Interface {
                id: LAN,
                mac: LAN_MAC,
            },
            Interface {
                id: WAN,
                mac: WAN_MAC,
            },
        ];
        let bindings = [
            LocalIpv4Binding {
                interface: LAN,
                address: LAN_IP,
            },
            LocalIpv4Binding {
                interface: WAN,
                address: WAN_IP,
            },
        ];
        let neighbors = [Neighbor {
            interface: LAN,
            target: HOST_IP,
            mac: HOST_MAC,
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &bindings).unwrap();
        let udp_config = Nat44UdpConfig::new(
            &snapshot,
            LAN,
            WAN,
            WAN_IP,
            40_000,
            40_003,
            Nat44UdpPolicy::default(),
        )
        .unwrap();
        let tcp_config = Nat44TcpConfig::new(
            &snapshot,
            LAN,
            WAN,
            WAN_IP,
            40_000,
            40_003,
            Nat44TcpPolicy::default(),
        )
        .unwrap();
        let firewall_config = FirewallConfig::new(
            &snapshot,
            &[],
            FirewallPolicy::default(),
            1,
            FirewallHashKey::new(1, 2).unwrap(),
        )
        .unwrap();
        let mut resolution_states = [ResolutionStateSlot::EMPTY; 4];
        let mut resolution_actions = [ResolutionActionSlot::EMPTY; 4];
        let mut failure_holds = [ResolutionFailureHoldSlot::EMPTY; 4];
        let mut resolution = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
            ResolutionPolicy::new(1_000, 2_000).unwrap(),
            &mut resolution_states,
            &mut resolution_actions,
            &mut [],
            &mut failure_holds,
        );
        let mut icmp_states = [Icmpv4ErrorStateSlot::EMPTY; 2];
        let mut icmp_actions = [Icmpv4ErrorActionSlot::EMPTY; 2];
        let mut icmpv4_errors = Icmpv4ErrorRuntime::new(
            Icmpv4ErrorPolicy::default(),
            &mut icmp_states,
            &mut icmp_actions,
        );
        let mut publication = TestPublication {
            enabled: true,
            applied: 0,
            snapshot: &snapshot,
            resolution: &mut resolution,
            icmpv4_errors: &mut icmpv4_errors,
            udp_config,
            tcp_config,
            firewall_config,
        };
        let mut io = TestIo::default();
        let mut trace = TestTrace::default();
        run(&mut publication, &mut io, &mut trace);
    }

    fn seed_resolution(publication: &mut TestPublication<'_, '_>, last: u8, now: u64) {
        let mut frame = [0_u8; 34];
        frame[0..6].copy_from_slice(&WAN_MAC.0);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 99]);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&20_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
        frame[22] = 64;
        frame[23] = 17;
        frame[26..30].copy_from_slice(&[198, 51, 100, 99]);
        frame[30..34].copy_from_slice(&[10, 0, 0, last]);
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        let mut io = SimIo::new();
        io.inject(WAN, frame.to_vec());
        let batch = io.receive(1).unwrap();
        let report = forward_batch_with_resolution(
            batch,
            publication.snapshot,
            publication.resolution,
            MonotonicMillis(now),
            &mut NoTrace,
        );
        assert!(report.invariants_hold());
    }

    fn seed_icmpv4(publication: &mut TestPublication<'_, '_>, now: u64) {
        let mut frame = [0_u8; 34];
        frame[0..6].copy_from_slice(&LAN_MAC.0);
        frame[6..12].copy_from_slice(&HOST_MAC.0);
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&20_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
        frame[22] = 1;
        frame[23] = 17;
        frame[26..30].copy_from_slice(&HOST_IP.octets());
        frame[30..34].copy_from_slice(&[198, 51, 100, 99]);
        let checksum = ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        let mut io = SimIo::new();
        io.inject(LAN, frame.to_vec());
        let batch = io.receive(1).unwrap();
        let report = forward_batch_with_resolution_and_icmpv4_errors(
            batch,
            publication.snapshot,
            publication.resolution,
            publication.icmpv4_errors,
            MonotonicMillis(now),
            &mut NoTrace,
        );
        assert!(report.invariants_hold());
        assert_eq!(publication.icmpv4_errors.pending_actions(), 1);
    }

    fn arp_request() -> [u8; 60] {
        let mut frame = [0_u8; 60];
        frame[0..6].fill(0xff);
        frame[6..12].copy_from_slice(&HOST_MAC.0);
        frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
        frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[18] = 6;
        frame[19] = 4;
        frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
        frame[22..28].copy_from_slice(&HOST_MAC.0);
        frame[28..32].copy_from_slice(&HOST_IP.octets());
        frame[38..42].copy_from_slice(&LAN_IP.octets());
        frame
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RxError {
        Injected,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum GeneratedError {
        Finish,
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum RxMode {
        #[default]
        Empty,
        Fail,
        FinishError,
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum GeneratedMode {
        #[default]
        Exact,
        AllocationFailure,
        WrongLength,
        FinishError,
        InvalidAccounting,
    }

    struct TestIo {
        rx_mode: RxMode,
        generated_mode: GeneratedMode,
        rx_live: bool,
        receive_calls: usize,
        generated_calls: usize,
        frame: [u8; 590],
    }

    impl Default for TestIo {
        fn default() -> Self {
            Self {
                rx_mode: RxMode::Empty,
                generated_mode: GeneratedMode::Exact,
                rx_live: false,
                receive_calls: 0,
                generated_calls: 0,
                frame: [0; 590],
            }
        }
    }

    struct EmptyRxSlot;

    impl PacketSlot for EmptyRxSlot {
        fn ingress(&self) -> IfId {
            unreachable!("empty RX batch has no slot")
        }

        fn bytes_mut(&mut self) -> &mut [u8] {
            unreachable!("empty RX batch has no slot")
        }

        fn complete(self, _completion: SlotCompletion) {
            unreachable!("empty RX batch has no slot")
        }
    }

    struct EmptyRxBatch<'a> {
        live: &'a mut bool,
        finish_error: bool,
    }

    impl PacketBatch for EmptyRxBatch<'_> {
        type Error = RxError;
        type Slot<'a>
            = EmptyRxSlot
        where
            Self: 'a;

        fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
            None
        }

        fn finish(self) -> BatchCompletion<Self::Error> {
            *self.live = false;
            BatchCompletion {
                tx_requested: 0,
                tx_accepted: 0,
                tx_rejected: 0,
                recycled: 0,
                error: self.finish_error.then_some(RxError::Injected),
            }
        }
    }

    impl PacketIo for TestIo {
        type Error = RxError;
        type Batch<'a> = EmptyRxBatch<'a>;

        fn receive(&mut self, _budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
            self.receive_calls += 1;
            if self.rx_mode == RxMode::Fail {
                return Err(RxError::Injected);
            }
            assert!(!self.rx_live, "RX batches cannot overlap");
            self.rx_live = true;
            Ok(EmptyRxBatch {
                live: &mut self.rx_live,
                finish_error: self.rx_mode == RxMode::FinishError,
            })
        }
    }

    struct TestGeneratedSlot<'a> {
        bytes: &'a mut [u8],
        completion: &'a mut Option<GeneratedSlotCompletion>,
    }

    impl GeneratedPacketSlot for TestGeneratedSlot<'_> {
        fn bytes_mut(&mut self) -> &mut [u8] {
            self.bytes
        }

        fn complete(self, completion: GeneratedSlotCompletion) {
            *self.completion = Some(completion);
        }
    }

    struct TestGeneratedBatch<'a> {
        mode: GeneratedMode,
        frame: &'a mut [u8; 590],
        attempted: bool,
        completion: Option<GeneratedSlotCompletion>,
    }

    impl GeneratedPacketBatch for TestGeneratedBatch<'_> {
        type Error = GeneratedError;
        type Slot<'a>
            = TestGeneratedSlot<'a>
        where
            Self: 'a;

        fn allocate(
            &mut self,
            frame_len: usize,
        ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
            assert!(!self.attempted, "one action performs one allocation");
            self.attempted = true;
            if self.mode == GeneratedMode::AllocationFailure {
                return Err(GeneratedAllocationError::Unavailable);
            }
            let visible_len = if self.mode == GeneratedMode::WrongLength {
                frame_len - 1
            } else {
                frame_len
            };
            Ok(GeneratedPacketLease::new(TestGeneratedSlot {
                bytes: &mut self.frame[..visible_len],
                completion: &mut self.completion,
            }))
        }

        fn finish(self) -> GeneratedBatchCompletion<Self::Error> {
            let (allocated, failed, requested, cancelled, abandoned) = match self.completion {
                Some(GeneratedSlotCompletion::Transmit) => (1, 0, 1, 0, 0),
                Some(GeneratedSlotCompletion::Cancelled) => (1, 0, 0, 1, 0),
                Some(GeneratedSlotCompletion::Abandoned) => (1, 0, 0, 0, 1),
                None => (0, usize::from(self.attempted), 0, 0, 0),
            };
            let invalid = self.mode == GeneratedMode::InvalidAccounting;
            GeneratedBatchCompletion {
                attempts: usize::from(self.attempted),
                allocated,
                failed,
                requested,
                cancelled,
                abandoned,
                accepted: if invalid { 0 } else { requested },
                rejected: 0,
                error: (self.mode == GeneratedMode::FinishError).then_some(GeneratedError::Finish),
            }
        }
    }

    impl GeneratedPacketIo for TestIo {
        type Error = GeneratedError;
        type Batch<'a> = TestGeneratedBatch<'a>;

        fn begin_generated(&mut self, _egress: IfId) -> Self::Batch<'_> {
            assert!(
                !self.rx_live,
                "generated I/O began before the RX batch finished"
            );
            self.generated_calls += 1;
            TestGeneratedBatch {
                mode: self.generated_mode,
                frame: &mut self.frame,
                attempted: false,
                completion: None,
            }
        }
    }

    #[derive(Default)]
    struct TestTrace {
        phases: [Option<TickPhaseTrace>; 16],
        phase_len: usize,
    }

    impl TickPhaseTraceSink for TestTrace {
        fn record_tick_phase(&mut self, event: TickPhaseTrace) {
            self.phases[self.phase_len] = Some(event);
            self.phase_len += 1;
        }
    }

    impl TraceSink for TestTrace {
        fn record(&mut self, _event: TraceEvent) {}
    }

    impl ResolutionTimerTraceSink for TestTrace {
        fn record_resolution_timer(&mut self, _event: ResolutionTimerTrace) {}
    }

    impl ResolutionFailureTraceSink for TestTrace {
        fn record_resolution_failure(&mut self, _event: ResolutionFailureTrace) {}
    }

    impl GeneratedTraceSink for TestTrace {
        fn record_generated(&mut self, _event: ruster_core::GeneratedArpTrace) {}
    }

    impl GeneratedIcmpv4TraceSink for TestTrace {
        fn record_generated_icmpv4(&mut self, _event: ruster_core::GeneratedIcmpv4Trace) {}
    }

    #[test]
    fn rejected_candidate_keeps_old_view_and_phase_sentinels_are_exact() {
        with_fixture(|publication, io, trace| {
            seed_resolution(publication, 2, 0);
            let report = run_tick(
                publication,
                Some(Candidate::Reject),
                io,
                MonotonicMillis(0),
                TickBudgets {
                    rx: 0,
                    resolution_timer_scans: 0,
                    failure_dispatch_scans: 0,
                    generated_arp: 1,
                    generated_icmpv4: 0,
                },
                trace,
            );
            assert_eq!(report.publication, PublicationOutcome::Rejected("rejected"));
            assert!(report.active);
            assert_eq!(io.receive_calls, 1);
            assert_eq!(io.generated_calls, 1);
            assert!(!io.rx_live);
            assert!(matches!(
                report.resolution_timers,
                PhaseReport::Completed(ResolutionTimerReport {
                    scanned: 0,
                    pending: 1,
                    ..
                })
            ));
            assert!(matches!(
                report.failure_dispatch,
                PhaseReport::Completed(ResolutionFailureDispatchReport { scanned: 0, .. })
            ));
            assert!(matches!(
                report.generated_arp,
                PhaseReport::Completed(GeneratedPhaseReport {
                    accounting: GeneratedAccounting {
                        sessions: 1,
                        tx_requested: 1,
                        tx_accepted: 1,
                        ..
                    },
                    stop: GeneratedArpStop::QueueEmpty,
                })
            ));
            assert_eq!(
                &trace.phases[..trace.phase_len],
                &[
                    Some(TickPhaseTrace::TickStarted),
                    Some(TickPhaseTrace::PhaseStarted(TickPhase::Publication)),
                    Some(TickPhaseTrace::PhaseFinished(TickPhase::Publication)),
                    Some(TickPhaseTrace::PhaseStarted(TickPhase::Rx)),
                    Some(TickPhaseTrace::PhaseFinished(TickPhase::Rx)),
                    Some(TickPhaseTrace::PhaseStarted(TickPhase::ResolutionTimers)),
                    Some(TickPhaseTrace::PhaseFinished(TickPhase::ResolutionTimers)),
                    Some(TickPhaseTrace::PhaseStarted(TickPhase::FailureDispatch)),
                    Some(TickPhaseTrace::PhaseFinished(TickPhase::FailureDispatch)),
                    Some(TickPhaseTrace::PhaseStarted(TickPhase::GeneratedArp)),
                    Some(TickPhaseTrace::PhaseFinished(TickPhase::GeneratedArp)),
                    Some(TickPhaseTrace::PhaseStarted(TickPhase::GeneratedIcmpv4)),
                    Some(TickPhaseTrace::PhaseFinished(TickPhase::GeneratedIcmpv4)),
                    Some(TickPhaseTrace::TickFinished),
                ]
            );
        });
    }

    #[test]
    fn sim_full_composition_orders_rx_before_arp_and_icmp_generated_tx() {
        with_fixture(|publication, _unused_io, trace| {
            seed_resolution(publication, 2, 0);
            seed_icmpv4(publication, 0);
            let mut io = SimIo::new();
            io.inject(LAN, arp_request().into());
            let report = run_tick(
                publication,
                None,
                &mut io,
                MonotonicMillis(0),
                TickBudgets {
                    rx: 1,
                    generated_arp: 1,
                    generated_icmpv4: 1,
                    ..TickBudgets::default()
                },
                trace,
            );
            assert!(matches!(
                report.rx,
                RxPhaseReport::Completed(BatchReport {
                    received: 1,
                    tx_requested: 1,
                    ..
                })
            ));
            assert_eq!(io.pending_tx(), 3);
            assert!(matches!(
                io.pop_tx().unwrap().origin,
                FrameOrigin::Received { ingress: LAN }
            ));
            assert_eq!(io.pop_tx().unwrap().origin, FrameOrigin::Generated);
            assert_eq!(io.pop_tx().unwrap().origin, FrameOrigin::Generated);
        });
    }

    #[test]
    fn no_active_publication_is_a_typed_skip_without_backend_access() {
        with_fixture(|publication, io, trace| {
            publication.enabled = false;
            let report = run_tick(
                publication,
                Some(Candidate::Apply),
                io,
                MonotonicMillis(0),
                TickBudgets {
                    rx: usize::MAX,
                    resolution_timer_scans: usize::MAX,
                    failure_dispatch_scans: usize::MAX,
                    generated_arp: usize::MAX,
                    generated_icmpv4: usize::MAX,
                },
                trace,
            );
            assert_eq!(report.publication, PublicationOutcome::Applied);
            assert!(!report.active);
            assert_eq!((io.receive_calls, io.generated_calls), (0, 0));
            assert_eq!(
                report.rx,
                RxPhaseReport::Skipped(TickPhaseSkip::NoActivePublication)
            );
            assert!(matches!(
                report.generated_icmpv4,
                PhaseReport::Skipped(TickPhaseSkip::NoActivePublication)
            ));
            assert_eq!(trace.phase_len, 9);
            assert_eq!(
                trace.phases[trace.phase_len - 1],
                Some(TickPhaseTrace::TickFinished)
            );
        });
    }

    #[test]
    fn generated_budget_is_exact_and_failures_stop_after_one_session() {
        for (mode, expected_pending) in [
            (GeneratedMode::AllocationFailure, 2),
            (GeneratedMode::WrongLength, 2),
            (GeneratedMode::FinishError, 1),
        ] {
            with_fixture(|publication, io, trace| {
                for last in [2, 3] {
                    seed_resolution(publication, last, 0);
                }
                seed_icmpv4(publication, 0);
                io.generated_mode = mode;
                let report = run_tick(
                    publication,
                    None,
                    io,
                    MonotonicMillis(0),
                    TickBudgets {
                        generated_arp: 4,
                        generated_icmpv4: 1,
                        ..TickBudgets::default()
                    },
                    trace,
                );
                assert_eq!(
                    publication.resolution.pending_actions(),
                    expected_pending,
                    "mode {mode:?}"
                );
                let PhaseReport::Completed(arp) = report.generated_arp else {
                    panic!("generated ARP phase must run");
                };
                assert_eq!(arp.accounting.sessions, 1);
                assert!(matches!(arp.stop, GeneratedArpStop::Failed(_)));
                match mode {
                    GeneratedMode::AllocationFailure => {
                        assert_eq!(io.generated_calls, 2);
                        assert_eq!(publication.icmpv4_errors.pending_actions(), 1);
                        assert!(matches!(
                            report.generated_icmpv4,
                            PhaseReport::Completed(GeneratedPhaseReport {
                                stop: GeneratedIcmpv4Stop::Failed(GeneratedIcmpv4Failure {
                                    allocation: Some(GeneratedAllocationError::Unavailable),
                                    ..
                                }),
                                ..
                            })
                        ));
                    }
                    GeneratedMode::WrongLength => {
                        assert_eq!(io.generated_calls, 1);
                        assert_eq!(publication.icmpv4_errors.pending_actions(), 1);
                        assert!(matches!(
                            report.generated_icmpv4,
                            PhaseReport::Skipped(TickPhaseSkip::GeneratedArpFailure)
                        ));
                    }
                    GeneratedMode::FinishError => {
                        assert_eq!(io.generated_calls, 1);
                        assert_eq!(publication.icmpv4_errors.pending_actions(), 1);
                        assert!(matches!(
                            report.generated_icmpv4,
                            PhaseReport::Skipped(TickPhaseSkip::BackendIoFailure)
                        ));
                    }
                    GeneratedMode::Exact | GeneratedMode::InvalidAccounting => unreachable!(),
                }
            });
        }

        with_fixture(|publication, io, trace| {
            for last in [2, 3, 4] {
                seed_resolution(publication, last, 0);
            }
            let report = run_tick(
                publication,
                None,
                io,
                MonotonicMillis(0),
                TickBudgets {
                    resolution_timer_scans: 2,
                    failure_dispatch_scans: 1,
                    generated_arp: 2,
                    ..TickBudgets::default()
                },
                trace,
            );
            assert_eq!(io.generated_calls, 2);
            assert_eq!(publication.resolution.pending_actions(), 1);
            assert!(matches!(
                report.resolution_timers,
                PhaseReport::Completed(ResolutionTimerReport { scanned: 2, .. })
            ));
            assert!(matches!(
                report.failure_dispatch,
                PhaseReport::Completed(ResolutionFailureDispatchReport { scanned: 1, .. })
            ));
            assert!(matches!(
                report.generated_arp,
                PhaseReport::Completed(GeneratedPhaseReport {
                    accounting: GeneratedAccounting { sessions: 2, .. },
                    stop: GeneratedArpStop::BudgetExhausted { pending: 1 },
                })
            ));
        });
    }

    #[test]
    fn receive_error_runs_non_io_phases_but_skips_all_generated_io() {
        for mode in [RxMode::Fail, RxMode::FinishError] {
            with_fixture(|publication, io, trace| {
                seed_resolution(publication, 2, 10);
                io.rx_mode = mode;
                let report = run_tick(
                    publication,
                    None,
                    io,
                    MonotonicMillis(10),
                    TickBudgets {
                        generated_arp: 1,
                        ..TickBudgets::default()
                    },
                    trace,
                );
                match mode {
                    RxMode::Fail => {
                        assert_eq!(report.rx, RxPhaseReport::ReceiveFailed(RxError::Injected));
                    }
                    RxMode::FinishError => assert!(matches!(
                        report.rx,
                        RxPhaseReport::Completed(BatchReport {
                            completion: BatchCompletion {
                                error: Some(RxError::Injected),
                                ..
                            },
                            ..
                        })
                    )),
                    RxMode::Empty => unreachable!(),
                }
                assert!(matches!(
                    report.resolution_timers,
                    PhaseReport::Completed(ResolutionTimerReport { scanned: 0, .. })
                ));
                assert!(matches!(
                    report.failure_dispatch,
                    PhaseReport::Completed(ResolutionFailureDispatchReport { scanned: 0, .. })
                ));
                assert!(matches!(
                    report.generated_arp,
                    PhaseReport::Skipped(TickPhaseSkip::BackendIoFailure)
                ));
                assert!(matches!(
                    report.generated_icmpv4,
                    PhaseReport::Skipped(TickPhaseSkip::BackendIoFailure)
                ));
                assert_eq!(publication.resolution.pending_actions(), 1);
                assert_eq!(io.generated_calls, 0);
            });
        }
    }

    #[test]
    fn timer_clock_regression_skips_failure_and_both_generated_phases_atomically() {
        with_fixture(|publication, io, trace| {
            seed_resolution(publication, 2, 10);
            seed_icmpv4(publication, 10);
            let report = run_tick(
                publication,
                None,
                io,
                MonotonicMillis(9),
                TickBudgets {
                    failure_dispatch_scans: 1,
                    generated_arp: 1,
                    generated_icmpv4: 1,
                    ..TickBudgets::default()
                },
                trace,
            );
            assert!(matches!(
                report.resolution_timers,
                PhaseReport::Failed(ResolutionTimerError::ClockRegression)
            ));
            assert!(matches!(
                report.failure_dispatch,
                PhaseReport::Skipped(TickPhaseSkip::ClockRegression)
            ));
            assert!(matches!(
                report.generated_arp,
                PhaseReport::Skipped(TickPhaseSkip::ClockRegression)
            ));
            assert!(matches!(
                report.generated_icmpv4,
                PhaseReport::Skipped(TickPhaseSkip::ClockRegression)
            ));
            assert_eq!(publication.resolution.pending_actions(), 1);
            assert_eq!(publication.icmpv4_errors.pending_actions(), 1);
            assert_eq!(io.generated_calls, 0);
        });
    }

    #[test]
    fn generated_accounting_violation_stops_later_backend_phases() {
        with_fixture(|publication, io, trace| {
            for last in [2, 3] {
                seed_resolution(publication, last, 0);
            }
            io.generated_mode = GeneratedMode::InvalidAccounting;
            let report = run_tick(
                publication,
                None,
                io,
                MonotonicMillis(0),
                TickBudgets {
                    generated_arp: 2,
                    generated_icmpv4: 1,
                    ..TickBudgets::default()
                },
                trace,
            );
            assert_eq!(io.generated_calls, 1);
            assert_eq!(publication.resolution.pending_actions(), 1);
            let PhaseReport::Completed(GeneratedPhaseReport {
                accounting,
                stop: GeneratedArpStop::AccountingInvariantViolation(violation),
            }) = report.generated_arp
            else {
                panic!("raw invalid completion must be reported");
            };
            assert_eq!(accounting.sessions, 1);
            assert_eq!(
                (
                    violation.completion.attempts,
                    violation.completion.allocated,
                    violation.completion.requested,
                    violation.completion.accepted,
                    violation.completion.rejected,
                ),
                (1, 1, 1, 0, 0)
            );
            assert!(!violation.completion.invariants_hold());
            assert!(matches!(
                report.generated_icmpv4,
                PhaseReport::Skipped(TickPhaseSkip::BackendContractViolation)
            ));
        });
    }

    #[test]
    fn generated_icmpv4_build_failure_is_single_attempt_and_preserves_pending() {
        with_fixture(|publication, io, trace| {
            seed_icmpv4(publication, 0);
            io.generated_mode = GeneratedMode::WrongLength;
            let report = run_tick(
                publication,
                None,
                io,
                MonotonicMillis(0),
                TickBudgets {
                    generated_icmpv4: 4,
                    ..TickBudgets::default()
                },
                trace,
            );
            assert_eq!(io.generated_calls, 1);
            assert_eq!(publication.icmpv4_errors.pending_actions(), 1);
            assert!(matches!(
                report.generated_icmpv4,
                PhaseReport::Completed(GeneratedPhaseReport {
                    accounting: GeneratedAccounting {
                        sessions: 1,
                        cancelled: 1,
                        ..
                    },
                    stop: GeneratedIcmpv4Stop::Failed(GeneratedIcmpv4Failure {
                        build: Some(Icmpv4ErrorBuildError::ExactLengthRequired),
                        ..
                    }),
                })
            ));
        });
    }

    #[test]
    fn production_tick_source_keeps_heap_and_shared_fast_path_types_out() {
        let source = include_str!("lib.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source precedes tests");
        for forbidden in [
            "V\u{65}c",
            "B\u{6f}x",
            "Str\u{69}ng",
            "A\u{72}c",
            "Mut\u{65}x",
            "dyn Pack\u{65}tIo",
        ] {
            assert!(
                !source.contains(forbidden),
                "production tick source contains forbidden token {forbidden}"
            );
        }
    }
}
