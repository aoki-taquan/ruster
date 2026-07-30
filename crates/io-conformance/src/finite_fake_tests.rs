use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    convert::Infallible,
    panic::{catch_unwind, AssertUnwindSafe},
    rc::Rc,
};

use ruster_core::{
    BatchCompletion, GeneratedAllocationError, GeneratedBatchCompletion, GeneratedPacketBatch,
    GeneratedPacketIo, GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion, IfId,
    PacketBatch, PacketIo, PacketLease, PacketSlot, SlotCompletion,
};

use super::{
    generated, rx, BufferToken, GeneratedCompletionHarness, GeneratedCqPoolHarness, GeneratedEvent,
    GeneratedEventKind, GeneratedFinitePoolHarness, GeneratedHarness, GeneratedReclaim,
    GeneratedUnknownEgressHarness, LeaseObserver, LiveFrame, RxCompletionHarness, RxCqPoolHarness,
    RxEvent, RxEventKind, RxFinitePoolHarness, RxHarness, RxReclaim, RxUnknownEgressHarness,
    TxCompletion, TxEndpoint, CONFORMANCE_LAN_ENDPOINT, CONFORMANCE_WAN_ENDPOINT,
};

const GOOD: u8 = 0;
const LEAK: u8 = 1;
const ALIAS: u8 = 2;
const STALE_GENERATION: u8 = 3;
const WRONG_LENGTH: u8 = 4;
const WRONG_RING: u8 = 5;
const TOKEN_INVENTION: u8 = 6;
const FRAME_CAPACITY: usize = 128;
const FRAME_COUNT: usize = 4;

struct Frame {
    id: u64,
    storage: Box<[u8; FRAME_CAPACITY]>,
    len: usize,
    ingress: IfId,
}

impl Frame {
    fn new(id: u64) -> Self {
        Self {
            id,
            storage: Box::new([0; FRAME_CAPACITY]),
            len: 0,
            ingress: IfId(0),
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.storage[..self.len]
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.storage[..self.len]
    }

    fn load(&mut self, ingress: IfId, bytes: &[u8]) {
        assert!(bytes.len() <= FRAME_CAPACITY);
        self.ingress = ingress;
        self.len = bytes.len();
        self.storage[..self.len].copy_from_slice(bytes);
    }

    fn allocate(&mut self, len: usize) {
        self.ingress = IfId(0);
        self.len = len;
        self.storage[..len].fill(0xa5);
    }
}

struct Submitted {
    frame: Frame,
    binding: LiveFrame,
    endpoint: TxEndpoint,
}

struct State<const FAULT: u8> {
    free: Vec<Frame>,
    rx: VecDeque<Frame>,
    rx_events: Vec<RxEvent>,
    generated_events: Vec<GeneratedEvent>,
    generated_pending: Vec<Frame>,
    submitted_rx: Vec<Submitted>,
    submitted_generated: Vec<Submitted>,
    physical_by_address: BTreeMap<usize, u64>,
    generations: BTreeMap<u64, u64>,
    live: BTreeMap<usize, LiveFrame>,
    rx_accept_budget: usize,
    generated_allocation_budget: usize,
    generated_max_frame: usize,
    generated_accept_budget: usize,
    preferred_generated_frame: Option<u64>,
}

impl<const FAULT: u8> State<FAULT> {
    fn new() -> Self {
        let free: Vec<_> = (0..FRAME_COUNT)
            .map(|index| Frame::new(100 + index as u64))
            .collect();
        let physical_by_address = free
            .iter()
            .map(|frame| (frame.storage.as_ptr() as usize, frame.id))
            .collect();
        Self {
            free,
            rx: VecDeque::new(),
            rx_events: Vec::new(),
            generated_events: Vec::new(),
            generated_pending: Vec::new(),
            submitted_rx: Vec::new(),
            submitted_generated: Vec::new(),
            physical_by_address,
            generations: BTreeMap::new(),
            live: BTreeMap::new(),
            rx_accept_budget: usize::MAX,
            generated_allocation_budget: usize::MAX,
            generated_max_frame: FRAME_CAPACITY,
            generated_accept_budget: usize::MAX,
            preferred_generated_frame: None,
        }
    }

    fn bind(&mut self, bytes: &[u8], requested_len: usize) -> LiveFrame {
        assert_eq!(bytes.len(), requested_len);
        let visible_address = bytes.as_ptr() as usize;
        assert!(
            !self.live.contains_key(&visible_address),
            "address already has a live ownership cycle"
        );
        let physical_id = *self
            .physical_by_address
            .get(&visible_address)
            .expect("binding points at a fake physical frame");
        let frame_id = if FAULT == ALIAS { 1 } else { physical_id };
        let generation = if FAULT == STALE_GENERATION {
            1
        } else {
            let generation = self.generations.entry(frame_id).or_default();
            *generation = generation.checked_add(1).expect("generation overflow");
            *generation
        };
        let frame = LiveFrame {
            token: BufferToken::new(frame_id, generation),
            visible_address,
            requested_len,
        };
        self.live.insert(visible_address, frame);
        frame
    }

    fn observe(&self, bytes: &[u8]) -> LiveFrame {
        let address = bytes.as_ptr() as usize;
        let frame = *self.live.get(&address).expect("frame has no live binding");
        assert_eq!(bytes.len(), frame.requested_len);
        frame
    }

    fn retire(&mut self, bytes: &[u8]) -> LiveFrame {
        let frame = self.observe(bytes);
        assert_eq!(self.live.remove(&frame.visible_address), Some(frame));
        frame
    }

    fn event_frame(frame: LiveFrame) -> LiveFrame {
        if FAULT == TOKEN_INVENTION {
            LiveFrame {
                token: BufferToken::new(frame.token.frame_id + 10_000, frame.token.generation),
                ..frame
            }
        } else {
            frame
        }
    }

    fn publication_endpoint(egress: IfId) -> Option<TxEndpoint> {
        let endpoint = match egress {
            interface if interface == CONFORMANCE_LAN_ENDPOINT.interface => {
                CONFORMANCE_LAN_ENDPOINT
            }
            interface if interface == CONFORMANCE_WAN_ENDPOINT.interface => {
                CONFORMANCE_WAN_ENDPOINT
            }
            _ => return None,
        };
        Some(if FAULT == WRONG_RING {
            TxEndpoint {
                queue: endpoint.queue + 1,
                ..endpoint
            }
        } else {
            endpoint
        })
    }

    fn descriptor_len(frame: LiveFrame) -> usize {
        if FAULT == WRONG_LENGTH {
            frame.requested_len + 1
        } else {
            frame.requested_len
        }
    }

    fn return_to_pool(&mut self, frame: Frame) {
        if FAULT != LEAK {
            self.free.push(frame);
        }
    }

    fn take_free(&mut self, preferred: Option<u64>) -> Option<Frame> {
        let index = preferred
            .and_then(|id| self.free.iter().position(|frame| frame.id == id))
            .unwrap_or_else(|| self.free.len().saturating_sub(1));
        if self.free.is_empty() {
            None
        } else {
            Some(self.free.swap_remove(index))
        }
    }
}

struct FakeObserver<const FAULT: u8>(Rc<RefCell<State<FAULT>>>);

impl<const FAULT: u8> LeaseObserver for FakeObserver<FAULT> {
    fn bind(&mut self, bytes: &[u8], requested_len: usize) -> LiveFrame {
        self.0.borrow_mut().bind(bytes, requested_len)
    }

    fn observe(&self, bytes: &[u8]) -> LiveFrame {
        self.0.borrow().observe(bytes)
    }
}

struct FakeIo<const FAULT: u8>(Rc<RefCell<State<FAULT>>>);

#[derive(Default)]
struct RxCounters {
    tx_requested: usize,
    tx_accepted: usize,
    tx_rejected: usize,
    recycled: usize,
}

struct FakeRxBatch<const FAULT: u8> {
    state: Rc<RefCell<State<FAULT>>>,
    leased: VecDeque<Frame>,
    counters: Rc<RefCell<RxCounters>>,
}

struct FakeRxSlot<const FAULT: u8> {
    state: Rc<RefCell<State<FAULT>>>,
    frame: Option<Frame>,
    counters: Rc<RefCell<RxCounters>>,
}

impl<const FAULT: u8> PacketIo for FakeIo<FAULT> {
    type Error = Infallible;
    type Batch<'a> = FakeRxBatch<FAULT>;

    fn receive(&mut self, budget: usize) -> Result<Self::Batch<'_>, Self::Error> {
        let mut state = self.0.borrow_mut();
        let count = budget.min(state.rx.len());
        let leased = state.rx.drain(..count).collect();
        drop(state);
        Ok(FakeRxBatch {
            state: Rc::clone(&self.0),
            leased,
            counters: Rc::new(RefCell::new(RxCounters::default())),
        })
    }
}

impl<const FAULT: u8> PacketBatch for FakeRxBatch<FAULT> {
    type Error = Infallible;
    type Slot<'a>
        = FakeRxSlot<FAULT>
    where
        Self: 'a;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        self.leased.pop_front().map(|frame| {
            PacketLease::new(FakeRxSlot {
                state: Rc::clone(&self.state),
                frame: Some(frame),
                counters: Rc::clone(&self.counters),
            })
        })
    }

    fn finish(self) -> BatchCompletion<Self::Error> {
        assert!(self.leased.is_empty(), "fake batch left unleased frames");
        let counters = self.counters.borrow();
        BatchCompletion {
            tx_requested: counters.tx_requested,
            tx_accepted: counters.tx_accepted,
            tx_rejected: counters.tx_rejected,
            recycled: counters.recycled,
            error: None,
        }
    }
}

impl<const FAULT: u8> PacketSlot for FakeRxSlot<FAULT> {
    fn ingress(&self) -> IfId {
        self.frame.as_ref().expect("live RX frame").ingress
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.frame.as_mut().expect("live RX frame").bytes_mut()
    }

    fn complete(mut self, completion: SlotCompletion) {
        let frame = self.frame.take().expect("RX slot completed once");
        let ingress = frame.ingress;
        let bytes = frame.bytes().to_vec();
        let mut state = self.state.borrow_mut();
        let binding = state.observe(frame.bytes());
        match completion {
            SlotCompletion::Transmit(egress) => {
                self.counters.borrow_mut().tx_requested += 1;
                let endpoint = State::<FAULT>::publication_endpoint(egress);
                if let Some(published_endpoint) = endpoint.filter(|_| state.rx_accept_budget != 0) {
                    state.rx_accept_budget -= 1;
                    self.counters.borrow_mut().tx_accepted += 1;
                    state.rx_events.push(RxEvent {
                        frame: State::<FAULT>::event_frame(binding),
                        ingress,
                        bytes,
                        kind: RxEventKind::TxSubmitted {
                            endpoint: published_endpoint,
                            descriptor_len: State::<FAULT>::descriptor_len(binding),
                        },
                    });
                    state.submitted_rx.push(Submitted {
                        frame,
                        binding,
                        endpoint: published_endpoint,
                    });
                } else {
                    self.counters.borrow_mut().tx_rejected += 1;
                    state.retire(frame.bytes());
                    state.rx_events.push(RxEvent {
                        frame: State::<FAULT>::event_frame(binding),
                        ingress,
                        bytes,
                        kind: RxEventKind::TxRejected {
                            attempted_egress: egress,
                            endpoint,
                        },
                    });
                    state.return_to_pool(frame);
                }
            }
            SlotCompletion::Recycle(reason) => {
                self.counters.borrow_mut().recycled += 1;
                state.retire(frame.bytes());
                state.rx_events.push(RxEvent {
                    frame: State::<FAULT>::event_frame(binding),
                    ingress,
                    bytes,
                    kind: RxEventKind::Reclaimed(RxReclaim::Recycled(reason)),
                });
                state.return_to_pool(frame);
            }
            SlotCompletion::Consume(reason) => {
                self.counters.borrow_mut().recycled += 1;
                state.retire(frame.bytes());
                state.rx_events.push(RxEvent {
                    frame: State::<FAULT>::event_frame(binding),
                    ingress,
                    bytes,
                    kind: RxEventKind::Reclaimed(RxReclaim::Consumed(reason)),
                });
                state.return_to_pool(frame);
            }
            SlotCompletion::LeaseAbandoned => {
                self.counters.borrow_mut().recycled += 1;
                state.retire(frame.bytes());
                state.rx_events.push(RxEvent {
                    frame: State::<FAULT>::event_frame(binding),
                    ingress,
                    bytes,
                    kind: RxEventKind::Reclaimed(RxReclaim::Abandoned),
                });
                state.return_to_pool(frame);
            }
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
}

struct FakeGeneratedBatch<const FAULT: u8> {
    state: Rc<RefCell<State<FAULT>>>,
    egress: IfId,
    remaining_allocations: usize,
    max_frame: usize,
    counters: Rc<RefCell<GeneratedCounters>>,
}

struct FakeGeneratedSlot<const FAULT: u8> {
    state: Rc<RefCell<State<FAULT>>>,
    frame: Option<Frame>,
    counters: Rc<RefCell<GeneratedCounters>>,
    egress: IfId,
}

impl<const FAULT: u8> GeneratedPacketIo for FakeIo<FAULT> {
    type Error = Infallible;
    type Batch<'a> = FakeGeneratedBatch<FAULT>;

    fn begin_generated(&mut self, egress: IfId) -> Self::Batch<'_> {
        let state = self.0.borrow();
        let remaining_allocations = state.generated_allocation_budget;
        let max_frame = state.generated_max_frame;
        drop(state);
        FakeGeneratedBatch {
            state: Rc::clone(&self.0),
            egress,
            remaining_allocations,
            max_frame,
            counters: Rc::new(RefCell::new(GeneratedCounters::default())),
        }
    }
}

impl<const FAULT: u8> GeneratedPacketBatch for FakeGeneratedBatch<FAULT> {
    type Error = Infallible;
    type Slot<'a>
        = FakeGeneratedSlot<FAULT>
    where
        Self: 'a;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        self.counters.borrow_mut().attempts += 1;
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
            self.counters.borrow_mut().failed += 1;
            return Err(error);
        }
        let mut state = self.state.borrow_mut();
        let preferred = state.preferred_generated_frame.take();
        let Some(mut frame) = state.take_free(preferred) else {
            self.counters.borrow_mut().failed += 1;
            return Err(GeneratedAllocationError::Unavailable);
        };
        frame.allocate(frame_len);
        drop(state);
        self.remaining_allocations -= 1;
        self.counters.borrow_mut().allocated += 1;
        Ok(GeneratedPacketLease::new(FakeGeneratedSlot {
            state: Rc::clone(&self.state),
            frame: Some(frame),
            counters: Rc::clone(&self.counters),
            egress: self.egress,
        }))
    }

    fn finish(self) -> GeneratedBatchCompletion<Self::Error> {
        let mut state = self.state.borrow_mut();
        let endpoint = State::<FAULT>::publication_endpoint(self.egress);
        let pending = std::mem::take(&mut state.generated_pending);
        let mut accepted = 0;
        let mut rejected = 0;
        for frame in pending {
            let binding = state.observe(frame.bytes());
            let bytes = frame.bytes().to_vec();
            if let Some(published_endpoint) =
                endpoint.filter(|_| accepted < state.generated_accept_budget)
            {
                accepted += 1;
                state.generated_events.push(GeneratedEvent {
                    frame: State::<FAULT>::event_frame(binding),
                    egress: self.egress,
                    bytes,
                    kind: GeneratedEventKind::TxSubmitted {
                        endpoint: published_endpoint,
                        descriptor_len: State::<FAULT>::descriptor_len(binding),
                    },
                });
                state.submitted_generated.push(Submitted {
                    frame,
                    binding,
                    endpoint: published_endpoint,
                });
            } else {
                rejected += 1;
                state.retire(frame.bytes());
                state.generated_events.push(GeneratedEvent {
                    frame: State::<FAULT>::event_frame(binding),
                    egress: self.egress,
                    bytes,
                    kind: GeneratedEventKind::TxRejected {
                        attempted_egress: self.egress,
                        endpoint,
                    },
                });
                state.return_to_pool(frame);
            }
        }
        let counters = self.counters.borrow();
        GeneratedBatchCompletion {
            attempts: counters.attempts,
            allocated: counters.allocated,
            failed: counters.failed,
            requested: counters.requested,
            cancelled: counters.cancelled,
            abandoned: counters.abandoned,
            accepted,
            rejected,
            error: None,
        }
    }
}

impl<const FAULT: u8> GeneratedPacketSlot for FakeGeneratedSlot<FAULT> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        self.frame
            .as_mut()
            .expect("live generated frame")
            .bytes_mut()
    }

    fn complete(mut self, completion: GeneratedSlotCompletion) {
        let frame = self.frame.take().expect("generated slot completed once");
        match completion {
            GeneratedSlotCompletion::Transmit => {
                self.counters.borrow_mut().requested += 1;
                self.state.borrow_mut().generated_pending.push(frame);
            }
            GeneratedSlotCompletion::Cancelled | GeneratedSlotCompletion::Abandoned => {
                let mut state = self.state.borrow_mut();
                let binding = state.retire(frame.bytes());
                let bytes = frame.bytes().to_vec();
                let kind = if completion == GeneratedSlotCompletion::Cancelled {
                    self.counters.borrow_mut().cancelled += 1;
                    GeneratedEventKind::Reclaimed(GeneratedReclaim::Cancelled)
                } else {
                    self.counters.borrow_mut().abandoned += 1;
                    GeneratedEventKind::Reclaimed(GeneratedReclaim::Abandoned)
                };
                state.generated_events.push(GeneratedEvent {
                    frame: State::<FAULT>::event_frame(binding),
                    egress: self.egress,
                    bytes,
                    kind,
                });
                state.return_to_pool(frame);
            }
        }
    }
}

struct FakeHarness<const FAULT: u8> {
    io: FakeIo<FAULT>,
    observer: FakeObserver<FAULT>,
}

impl<const FAULT: u8> FakeHarness<FAULT> {
    fn shared() -> Self {
        let state = Rc::new(RefCell::new(State::new()));
        Self {
            io: FakeIo(Rc::clone(&state)),
            observer: FakeObserver(state),
        }
    }

    fn inject_selected(
        &mut self,
        frame_id: Option<u64>,
        ingress: IfId,
        bytes: Vec<u8>,
    ) -> LiveFrame {
        let mut state = self.io.0.borrow_mut();
        let mut frame = state
            .take_free(frame_id)
            .expect("finite fake RX pool exhausted");
        frame.load(ingress, &bytes);
        drop(state);
        let binding = self.observer.bind(frame.bytes(), bytes.len());
        self.io.0.borrow_mut().rx.push_back(frame);
        binding
    }
}

impl<const FAULT: u8> RxHarness for FakeHarness<FAULT> {
    type Io = FakeIo<FAULT>;
    type Observer = FakeObserver<FAULT>;

    fn new() -> Self {
        Self::shared()
    }

    fn io_and_observer(&mut self) -> (&mut Self::Io, &mut Self::Observer) {
        (&mut self.io, &mut self.observer)
    }

    fn inject_rx(&mut self, ingress: IfId, bytes: Vec<u8>) -> LiveFrame {
        self.inject_selected(None, ingress, bytes)
    }

    fn set_rx_accept_budget(&mut self, budget: usize) {
        self.io.0.borrow_mut().rx_accept_budget = budget;
    }

    fn pending_rx(&self) -> usize {
        self.io.0.borrow().rx.len()
    }

    fn drain_rx_events(&mut self) -> Vec<RxEvent> {
        std::mem::take(&mut self.io.0.borrow_mut().rx_events)
    }
}

impl<const FAULT: u8> RxFinitePoolHarness for FakeHarness<FAULT> {
    fn free_rx_frames(&self) -> usize {
        self.io.0.borrow().free.len()
    }
}

impl<const FAULT: u8> RxCompletionHarness for FakeHarness<FAULT> {
    fn complete_rx_submissions(&mut self) -> Vec<TxCompletion> {
        let mut state = self.io.0.borrow_mut();
        let submitted = std::mem::take(&mut state.submitted_rx);
        submitted
            .into_iter()
            .map(|submission| {
                state.retire(submission.frame.bytes());
                let completion = TxCompletion {
                    frame: submission.binding,
                    endpoint: submission.endpoint,
                };
                state.return_to_pool(submission.frame);
                completion
            })
            .collect()
    }
}

impl<const FAULT: u8> RxCqPoolHarness for FakeHarness<FAULT> {
    fn inject_rx_from_free_frame(
        &mut self,
        frame_id: u64,
        ingress: IfId,
        bytes: Vec<u8>,
    ) -> LiveFrame {
        self.inject_selected(Some(frame_id), ingress, bytes)
    }
}

impl<const FAULT: u8> RxUnknownEgressHarness for FakeHarness<FAULT> {}

impl<const FAULT: u8> GeneratedHarness for FakeHarness<FAULT> {
    type Io = FakeIo<FAULT>;
    type Observer = FakeObserver<FAULT>;

    fn new() -> Self {
        Self::shared()
    }

    fn io_and_observer(&mut self) -> (&mut Self::Io, &mut Self::Observer) {
        (&mut self.io, &mut self.observer)
    }

    fn set_generated_allocation_budget(&mut self, budget: usize) {
        self.io.0.borrow_mut().generated_allocation_budget = budget;
    }

    fn set_generated_max_frame(&mut self, max_frame: usize) {
        self.io.0.borrow_mut().generated_max_frame = max_frame;
    }

    fn set_generated_accept_budget(&mut self, budget: usize) {
        self.io.0.borrow_mut().generated_accept_budget = budget;
    }

    fn drain_generated_events(&mut self) -> Vec<GeneratedEvent> {
        std::mem::take(&mut self.io.0.borrow_mut().generated_events)
    }
}

impl<const FAULT: u8> GeneratedFinitePoolHarness for FakeHarness<FAULT> {
    fn free_generated_frames(&self) -> usize {
        self.io.0.borrow().free.len()
    }
}

impl<const FAULT: u8> GeneratedCompletionHarness for FakeHarness<FAULT> {
    fn complete_generated_submissions(&mut self) -> Vec<TxCompletion> {
        let mut state = self.io.0.borrow_mut();
        let submitted = std::mem::take(&mut state.submitted_generated);
        submitted
            .into_iter()
            .map(|submission| {
                state.retire(submission.frame.bytes());
                let completion = TxCompletion {
                    frame: submission.binding,
                    endpoint: submission.endpoint,
                };
                state.return_to_pool(submission.frame);
                completion
            })
            .collect()
    }
}

impl<const FAULT: u8> GeneratedCqPoolHarness for FakeHarness<FAULT> {
    fn prefer_generated_frame(&mut self, frame_id: u64) {
        self.io.0.borrow_mut().preferred_generated_frame = Some(frame_id);
    }
}

impl<const FAULT: u8> GeneratedUnknownEgressHarness for FakeHarness<FAULT> {}

#[test]
fn finite_fake_positive_rx_cases_include_unknown_egress_and_cq_reuse() {
    rx::partial_reject_reclaims_exact_tokens::<FakeHarness<GOOD>>();
    rx::repeated_rejects_restore_physical_pool::<FakeHarness<GOOD>>();
    rx::unknown_egress_is_rejected_without_submission::<FakeHarness<GOOD>>();
    rx::cq_return_releases_same_rx_frame_with_new_generation::<FakeHarness<GOOD>>();
}

#[test]
fn finite_fake_positive_generated_cases_include_unknown_egress_and_cq_reuse() {
    generated::partial_reject_reclaims_exact_tokens::<FakeHarness<GOOD>>();
    generated::repeated_rejects_restore_physical_pool_and_advance_generation::<FakeHarness<GOOD>>();
    generated::unknown_egress_is_rejected_without_submission::<FakeHarness<GOOD>>();
    generated::cq_return_releases_same_generated_frame_with_new_generation::<FakeHarness<GOOD>>();
}

fn assert_detected(case: impl FnOnce()) {
    assert!(
        catch_unwind(AssertUnwindSafe(case)).is_err(),
        "deliberate fake-backend fault escaped conformance"
    );
}

#[test]
fn conformance_detects_a_physical_pool_leak() {
    assert_detected(rx::repeated_rejects_restore_physical_pool::<FakeHarness<LEAK>>);
}

#[test]
fn conformance_detects_live_frame_aliasing() {
    assert_detected(rx::budget_and_unleased_slots_are_exact::<FakeHarness<ALIAS>>);
}

#[test]
fn conformance_detects_stale_generation_after_cq_return() {
    assert_detected(
        rx::cq_return_releases_same_rx_frame_with_new_generation::<FakeHarness<STALE_GENERATION>>,
    );
}

#[test]
fn conformance_detects_wrong_descriptor_length() {
    assert_detected(
        rx::commit_is_submitted_in_place_with_exact_descriptor::<FakeHarness<WRONG_LENGTH>>,
    );
}

#[test]
fn conformance_detects_publication_on_the_wrong_ring() {
    assert_detected(
        rx::commit_is_submitted_in_place_with_exact_descriptor::<FakeHarness<WRONG_RING>>,
    );
}

#[test]
fn conformance_detects_terminal_token_invention() {
    assert_detected(
        rx::commit_is_submitted_in_place_with_exact_descriptor::<FakeHarness<TOKEN_INVENTION>>,
    );
}
