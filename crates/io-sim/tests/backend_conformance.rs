use ruster_io_conformance::{
    generated, rx, BufferToken, GeneratedDisposition, GeneratedFinishErrorHarness,
    GeneratedHarness, GeneratedOutcome, InjectedFrame, RxDisposition, RxHarness, RxOutcome,
};
use ruster_io_sim::{FrameOrigin, GeneratedRecycleCause, RecycleCause, SimIo};

struct SimHarness {
    io: SimIo,
}

impl RxHarness for SimHarness {
    type Io = SimIo;

    fn new() -> Self {
        Self { io: SimIo::new() }
    }

    fn io(&mut self) -> &mut Self::Io {
        &mut self.io
    }

    fn inject_rx(&mut self, ingress: ruster_core::IfId, bytes: Vec<u8>) -> InjectedFrame {
        let allocation_address = bytes.as_ptr() as usize;
        let sequence = self.io.inject(ingress, bytes);
        InjectedFrame {
            token: BufferToken::new(sequence),
            allocation_address,
        }
    }

    fn set_rx_accept_budget(&mut self, budget: usize) {
        self.io.set_received_accept_budget(budget);
    }

    fn pending_rx(&self) -> usize {
        self.io.pending_rx()
    }

    fn drain_rx_outcomes(&mut self) -> Vec<RxOutcome> {
        let mut outcomes = Vec::new();
        while let Some(frame) = self.io.pop_tx() {
            assert!(matches!(frame.origin, FrameOrigin::Received { .. }));
            outcomes.push(RxOutcome {
                token: BufferToken::new(frame.sequence),
                allocation_address: frame.bytes.as_ptr() as usize,
                ingress: frame.ingress,
                bytes: frame.bytes,
                disposition: RxDisposition::Accepted {
                    egress: frame.egress,
                },
            });
        }
        while let Some(frame) = self.io.pop_recycled() {
            let disposition = match frame.cause {
                RecycleCause::Forwarding(reason) => RxDisposition::Recycled { reason },
                RecycleCause::Consumed(reason) => RxDisposition::Consumed { reason },
                RecycleCause::TxRejected => RxDisposition::Rejected,
                RecycleCause::LeaseAbandoned => RxDisposition::Abandoned,
            };
            outcomes.push(RxOutcome {
                token: BufferToken::new(frame.sequence),
                allocation_address: frame.bytes.as_ptr() as usize,
                ingress: frame.ingress,
                bytes: frame.bytes,
                disposition,
            });
        }
        outcomes
    }
}

impl GeneratedHarness for SimHarness {
    type Io = SimIo;

    fn new() -> Self {
        Self { io: SimIo::new() }
    }

    fn io(&mut self) -> &mut Self::Io {
        &mut self.io
    }

    fn set_generated_allocation_budget(&mut self, budget: usize) {
        self.io.set_generated_budget(budget);
    }

    fn set_generated_max_frame(&mut self, max_frame: usize) {
        self.io.set_generated_max_frame(max_frame);
    }

    fn set_generated_accept_budget(&mut self, budget: usize) {
        self.io.set_generated_accept_budget(budget);
    }

    fn drain_generated_outcomes(&mut self) -> Vec<GeneratedOutcome> {
        let mut outcomes = Vec::new();
        while let Some(frame) = self.io.pop_tx() {
            assert_eq!(frame.origin, FrameOrigin::Generated);
            outcomes.push(GeneratedOutcome {
                token: BufferToken::new(frame.sequence),
                allocation_address: frame.bytes.as_ptr() as usize,
                egress: frame.egress,
                bytes: frame.bytes,
                disposition: GeneratedDisposition::Accepted,
            });
        }
        while let Some(frame) = self.io.pop_generated_recycled() {
            let disposition = match frame.cause {
                GeneratedRecycleCause::Cancelled => GeneratedDisposition::Cancelled,
                GeneratedRecycleCause::Abandoned => GeneratedDisposition::Abandoned,
                GeneratedRecycleCause::TxRejected => GeneratedDisposition::Rejected,
            };
            outcomes.push(GeneratedOutcome {
                token: BufferToken::new(frame.sequence),
                allocation_address: frame.bytes.as_ptr() as usize,
                egress: frame.egress,
                bytes: frame.bytes,
                disposition,
            });
        }
        outcomes
    }
}

impl GeneratedFinishErrorHarness for SimHarness {
    fn fail_next_generated_finish(&mut self) {
        self.io.fail_next_generated_finish();
    }
}

#[test]
fn rx_budget_and_unleased_slots_are_exact() {
    rx::budget_and_unleased_slots_are_exact::<SimHarness>();
}

#[test]
fn rx_commit_is_in_place_and_egress_typed() {
    rx::commit_is_in_place_and_egress_typed::<SimHarness>();
}

#[test]
fn rx_recycle_consume_and_abandon_are_distinct() {
    rx::recycle_consume_and_abandon_are_distinct::<SimHarness>();
}

#[test]
fn rx_partial_reject_reclaims_exactly_before_finish_returns() {
    rx::partial_reject_reclaims_exactly_before_finish_returns::<SimHarness>();
}

#[test]
fn rx_repeated_reject_cycles_conserve_ownership() {
    rx::repeated_reject_cycles_conserve_rx_ownership::<SimHarness>();
}

#[test]
fn generated_empty_session_has_zero_accounting() {
    generated::empty_session_has_zero_accounting::<SimHarness>();
}

#[test]
fn generated_allocation_failures_are_typed_and_transfer_no_ownership() {
    generated::allocation_failures_are_typed_and_transfer_no_ownership::<SimHarness>();
}

#[test]
fn generated_commit_cancel_and_abandon_are_exact_length_and_distinct() {
    generated::commit_cancel_and_abandon_are_exact_length_and_distinct::<SimHarness>();
}

#[test]
fn generated_partial_reject_reclaims_exactly_before_finish_returns() {
    generated::partial_reject_reclaims_exactly_before_finish_returns::<SimHarness>();
}

#[test]
fn generated_sessions_pin_egress_without_cross_talk() {
    generated::sessions_pin_egress_without_cross_talk::<SimHarness>();
}

#[test]
fn generated_repeated_reject_cycles_conserve_pool() {
    generated::repeated_reject_cycles_conserve_generated_pool::<SimHarness>();
}

#[test]
fn generated_partial_reject_with_finish_error_is_exact() {
    generated::partial_reject_with_finish_error_is_exact::<SimHarness>();
}
