use std::collections::BTreeMap;

use ruster_io_conformance::{
    generated, rx, BufferToken, GeneratedCompletionHarness, GeneratedEvent, GeneratedEventKind,
    GeneratedFinishErrorHarness, GeneratedHarness, GeneratedReclaim, LeaseObserver, LiveFrame,
    RxCompletionHarness, RxEvent, RxEventKind, RxHarness, RxReclaim, TxCompletion, TxEndpoint,
    CONFORMANCE_LAN, CONFORMANCE_LAN_ENDPOINT, CONFORMANCE_WAN, CONFORMANCE_WAN_ENDPOINT,
};
use ruster_io_sim::{FrameOrigin, GeneratedRecycleCause, RecycleCause, SimIo};

#[derive(Default)]
struct SimObserver {
    generations: BTreeMap<u64, u64>,
    live: BTreeMap<usize, LiveFrame>,
}

impl LeaseObserver for SimObserver {
    fn bind(&mut self, bytes: &[u8], requested_len: usize) -> LiveFrame {
        assert_eq!(bytes.len(), requested_len);
        let visible_address = bytes.as_ptr() as usize;
        let frame_id = visible_address as u64;
        assert!(
            !self.live.contains_key(&visible_address),
            "sim allocation address is already live"
        );
        let generation = self.generations.entry(frame_id).or_default();
        *generation = generation.checked_add(1).expect("sim generation overflow");
        let frame = LiveFrame {
            token: BufferToken::new(frame_id, *generation),
            visible_address,
            requested_len,
        };
        self.live.insert(visible_address, frame);
        frame
    }

    fn observe(&self, bytes: &[u8]) -> LiveFrame {
        let address = bytes.as_ptr() as usize;
        let frame = *self
            .live
            .get(&address)
            .expect("sim terminal event has no lease-time identity");
        assert_eq!(bytes.len(), frame.requested_len);
        frame
    }
}

impl SimObserver {
    fn reclaim(&mut self, bytes: &[u8]) -> LiveFrame {
        let frame = self.observe(bytes);
        assert_eq!(self.live.remove(&frame.visible_address), Some(frame));
        frame
    }

    fn complete(&mut self, frame: LiveFrame) {
        assert_eq!(self.live.remove(&frame.visible_address), Some(frame));
    }
}

struct SimHarness {
    io: SimIo,
    observer: SimObserver,
    rx_completions: Vec<TxCompletion>,
    generated_completions: Vec<TxCompletion>,
}

impl SimHarness {
    fn publication_endpoint(egress: ruster_core::IfId) -> TxEndpoint {
        match egress {
            CONFORMANCE_LAN => CONFORMANCE_LAN_ENDPOINT,
            CONFORMANCE_WAN => CONFORMANCE_WAN_ENDPOINT,
            _ => TxEndpoint {
                interface: egress,
                queue: u32::MAX,
            },
        }
    }
}

impl RxHarness for SimHarness {
    type Io = SimIo;
    type Observer = SimObserver;

    fn new() -> Self {
        Self {
            io: SimIo::new(),
            observer: SimObserver::default(),
            rx_completions: Vec::new(),
            generated_completions: Vec::new(),
        }
    }

    fn io_and_observer(&mut self) -> (&mut Self::Io, &mut Self::Observer) {
        (&mut self.io, &mut self.observer)
    }

    fn inject_rx(&mut self, ingress: ruster_core::IfId, mut bytes: Vec<u8>) -> LiveFrame {
        let requested_len = bytes.len();
        let frame = self.observer.bind(&bytes, requested_len);
        self.io.inject(ingress, std::mem::take(&mut bytes));
        frame
    }

    fn set_rx_accept_budget(&mut self, budget: usize) {
        self.io.set_received_accept_budget(budget);
    }

    fn pending_rx(&self) -> usize {
        self.io.pending_rx()
    }

    fn drain_rx_events(&mut self) -> Vec<RxEvent> {
        let mut events = Vec::new();
        while let Some(frame) = self.io.pop_tx() {
            assert!(matches!(frame.origin, FrameOrigin::Received { .. }));
            let identity = self.observer.observe(&frame.bytes);
            let endpoint = Self::publication_endpoint(frame.egress);
            self.rx_completions.push(TxCompletion {
                frame: identity,
                endpoint,
            });
            events.push(RxEvent {
                frame: identity,
                ingress: frame.ingress,
                kind: RxEventKind::TxSubmitted {
                    endpoint,
                    descriptor_len: frame.bytes.len(),
                },
                bytes: frame.bytes,
            });
        }
        while let Some(capture) = self.io.pop_recycled_capture() {
            let frame = capture.frame;
            let identity = self.observer.reclaim(&frame.bytes);
            let kind = match frame.cause {
                RecycleCause::Forwarding(reason) => {
                    assert_eq!(capture.rejected_egress, None);
                    RxEventKind::Reclaimed(RxReclaim::Recycled(reason))
                }
                RecycleCause::Consumed(reason) => {
                    assert_eq!(capture.rejected_egress, None);
                    RxEventKind::Reclaimed(RxReclaim::Consumed(reason))
                }
                RecycleCause::TxRejected => {
                    let attempted_egress = capture.rejected_egress.expect("sim rejected TX egress");
                    RxEventKind::TxRejected {
                        attempted_egress,
                        endpoint: Some(Self::publication_endpoint(attempted_egress)),
                    }
                }
                RecycleCause::LeaseAbandoned => {
                    assert_eq!(capture.rejected_egress, None);
                    RxEventKind::Reclaimed(RxReclaim::Abandoned)
                }
            };
            events.push(RxEvent {
                frame: identity,
                ingress: frame.ingress,
                bytes: frame.bytes,
                kind,
            });
        }
        events
    }
}

impl RxCompletionHarness for SimHarness {
    // Sim has no hardware CQ. This capability models the same logical
    // completion boundary while keeping submission and completion distinct.
    fn complete_rx_submissions(&mut self) -> Vec<TxCompletion> {
        let completions = std::mem::take(&mut self.rx_completions);
        for completion in &completions {
            self.observer.complete(completion.frame);
        }
        completions
    }
}

impl GeneratedHarness for SimHarness {
    type Io = SimIo;
    type Observer = SimObserver;

    fn new() -> Self {
        <Self as RxHarness>::new()
    }

    fn io_and_observer(&mut self) -> (&mut Self::Io, &mut Self::Observer) {
        (&mut self.io, &mut self.observer)
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

    fn drain_generated_events(&mut self) -> Vec<GeneratedEvent> {
        let mut events = Vec::new();
        while let Some(frame) = self.io.pop_tx() {
            assert_eq!(frame.origin, FrameOrigin::Generated);
            let identity = self.observer.observe(&frame.bytes);
            let endpoint = Self::publication_endpoint(frame.egress);
            self.generated_completions.push(TxCompletion {
                frame: identity,
                endpoint,
            });
            events.push(GeneratedEvent {
                frame: identity,
                egress: frame.egress,
                kind: GeneratedEventKind::TxSubmitted {
                    endpoint,
                    descriptor_len: frame.bytes.len(),
                },
                bytes: frame.bytes,
            });
        }
        while let Some(frame) = self.io.pop_generated_recycled() {
            let identity = self.observer.reclaim(&frame.bytes);
            let kind = match frame.cause {
                GeneratedRecycleCause::Cancelled => {
                    GeneratedEventKind::Reclaimed(GeneratedReclaim::Cancelled)
                }
                GeneratedRecycleCause::Abandoned => {
                    GeneratedEventKind::Reclaimed(GeneratedReclaim::Abandoned)
                }
                GeneratedRecycleCause::TxRejected => GeneratedEventKind::TxRejected {
                    attempted_egress: frame.egress,
                    endpoint: Some(Self::publication_endpoint(frame.egress)),
                },
            };
            events.push(GeneratedEvent {
                frame: identity,
                egress: frame.egress,
                bytes: frame.bytes,
                kind,
            });
        }
        events
    }
}

impl GeneratedFinishErrorHarness for SimHarness {
    fn fail_next_generated_finish(&mut self) {
        self.io.fail_next_generated_finish();
    }
}

impl GeneratedCompletionHarness for SimHarness {
    // Sim has no hardware CQ. This capability models the same logical
    // completion boundary while keeping submission and completion distinct.
    fn complete_generated_submissions(&mut self) -> Vec<TxCompletion> {
        let completions = std::mem::take(&mut self.generated_completions);
        for completion in &completions {
            self.observer.complete(completion.frame);
        }
        completions
    }
}

#[test]
fn rx_budget_and_unleased_slots_are_exact() {
    rx::budget_and_unleased_slots_are_exact::<SimHarness>();
}

#[test]
fn rx_commit_is_submitted_in_place_with_exact_descriptor() {
    rx::commit_is_submitted_in_place_with_exact_descriptor::<SimHarness>();
}

#[test]
fn rx_recycle_consume_and_abandon_are_distinct() {
    rx::recycle_consume_and_abandon_are_distinct::<SimHarness>();
}

#[test]
fn rx_partial_reject_reclaims_exact_tokens() {
    rx::partial_reject_reclaims_exact_tokens::<SimHarness>();
}

#[test]
fn rx_completion_advances_the_exact_submitted_token() {
    rx::completion_advances_the_exact_submitted_token::<SimHarness>();
}

#[test]
fn generated_empty_session_has_zero_accounting() {
    generated::empty_session_has_zero_accounting::<SimHarness>();
}

#[test]
fn generated_allocation_failures_bind_only_successful_ownership() {
    generated::allocation_failures_bind_only_successful_ownership::<SimHarness>();
}

#[test]
fn generated_commit_cancel_and_abandon_bind_exact_lengths() {
    generated::commit_cancel_and_abandon_bind_exact_lengths::<SimHarness>();
}

#[test]
fn generated_partial_reject_reclaims_exact_tokens() {
    generated::partial_reject_reclaims_exact_tokens::<SimHarness>();
}

#[test]
fn generated_sessions_bind_concrete_endpoints() {
    generated::sessions_bind_concrete_endpoints::<SimHarness>();
}

#[test]
fn generated_partial_reject_with_finish_error_is_exact() {
    generated::partial_reject_with_finish_error_is_exact::<SimHarness>();
}

#[test]
fn generated_completion_advances_the_exact_submitted_token() {
    generated::completion_advances_the_exact_submitted_token::<SimHarness>();
}
