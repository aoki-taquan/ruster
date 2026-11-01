//! `ruster-io-conformance` Rx, Generated, and CQ/finite-pool suites run
//! against [`XdpPacketIo`] over two scripted kernels (M2 S6, X04a).
//!
//! The harness plays the kernel side of both sockets and observes only
//! what the kernel sees plus the adapter's test journal:
//!
//! - TX submissions are read from the scripted kernels' TX rings (the ring
//!   that received the descriptor names the endpoint).
//! - Reclaims and pre-descriptor refusals, which no ring shows, come from
//!   the adapter's test journal with a byte snapshot.
//! - Free-pool counts come from the engines' ledgers: an RX frame is free
//!   while it is `Free` or published to Fill and not yet used by the
//!   kernel for a packet; a generated frame while it is in the generated
//!   free list.
//! - An accept budget is real back-pressure: the harness commits filler
//!   generated frames that the kernel consumes and never completes, so
//!   the TX in-flight bound (the TX capacity) leaves exactly the budget.
//! - The finish-error capability fails the next TX kick (`ENETDOWN`) with
//!   the TX need-wakeup flag set.
//! - The generated allocation budget is the adapter's test gate, which
//!   returns `Unavailable` once the session's budget is spent.
//!
//! The Rx cases commit to [`CONFORMANCE_LAN`], the ingress itself: that is
//! the same-frame, in-place path the cases describe. Across ports the
//! adapter copies into the egress generated pool; `packet_io_tests` covers
//! that path. Not implemented: `RxReceiveErrorHarness` (a receive error is
//! a ring fault, which stops the adapter for good instead of being
//! retried) and `GeneratedUnknownEgressHarness` (a session for an unknown
//! egress allocates nothing; it fails `Unavailable` and reports
//! `UnknownEgress` at finish).
//!
//! The kernels are leaked to give the adapter its `'static` borrow, so
//! Miri (which reports leaks) skips these tests; `packet_io_tests` runs the
//! same paths over borrowed kernels under Miri.

use std::{cell::RefCell, collections::BTreeMap, collections::BTreeSet, rc::Rc};

use ruster_core::{
    GeneratedPacketBatch, GeneratedPacketIo, GeneratedSlotCompletion, IfId, SlotCompletion,
};
use ruster_io_conformance::{
    generated, rx, BufferToken, GeneratedCompletionHarness, GeneratedCqPoolHarness, GeneratedEvent,
    GeneratedEventKind, GeneratedFinishErrorHarness, GeneratedFinitePoolHarness, GeneratedHarness,
    GeneratedReclaim, LeaseObserver, LiveFrame, RxCompletionHarness, RxCqPoolHarness, RxEvent,
    RxEventKind, RxFinishErrorHarness, RxFinitePoolHarness, RxHarness, RxReclaim,
    RxUnknownEgressHarness, TxCompletion, TxEndpoint, CONFORMANCE_LAN, CONFORMANCE_LAN_ENDPOINT,
    CONFORMANCE_WAN, CONFORMANCE_WAN_ENDPOINT,
};

use crate::{
    abi::{XdpDescriptor, XDP_RING_NEED_WAKEUP},
    native_unsafe::heap_kernel::ScriptedKernel,
    packet_io::test_hooks::{EventKind, Journal, JournalEvent},
    packet_io_tests::{frame_of, kernel, port, HEADROOM, MTU, RING},
    FrameStateKind, XdpPacketIo, ETHERNET_HEADER_LEN,
};

const ENDPOINTS: [TxEndpoint; 2] = [CONFORMANCE_LAN_ENDPOINT, CONFORMANCE_WAN_ENDPOINT];
/// ENETDOWN.
const KICK_ERRNO: u16 = 100;

fn port_of(interface: IfId) -> usize {
    ENDPOINTS
        .iter()
        .position(|endpoint| endpoint.interface == interface)
        .expect("conformance interface")
}

/// Physical identity: the port in the high half, the UMEM frame below.
fn frame_id(port: usize, frame: u32) -> u64 {
    ((port as u64) << 32) | u64::from(frame)
}

#[derive(Default)]
struct Bindings {
    by_address: BTreeMap<usize, LiveFrame>,
    ingress: BTreeMap<usize, IfId>,
}

/// Maps lent byte addresses to the binding made when ownership began.
struct Observer {
    bindings: Rc<RefCell<Bindings>>,
    journal: Rc<RefCell<Journal>>,
}

impl LeaseObserver for Observer {
    /// Generated allocations: the adapter journaled the exact lease.
    fn bind(&mut self, bytes: &[u8], requested_len: usize) -> LiveFrame {
        assert_eq!(bytes.len(), requested_len);
        let address = bytes.as_ptr().addr();
        let journal = self.journal.borrow();
        let allocation = journal
            .events
            .iter()
            .rev()
            .find(|event| {
                event.kind == EventKind::GeneratedAllocated && event.snapshot.address == address
            })
            .expect("a journaled generated allocation at this address");
        let frame = LiveFrame {
            token: BufferToken::new(
                frame_id(allocation.snapshot.port, allocation.snapshot.frame),
                allocation.snapshot.generation,
            ),
            visible_address: address,
            requested_len,
        };
        self.bindings.borrow_mut().by_address.insert(address, frame);
        frame
    }

    fn observe(&self, bytes: &[u8]) -> LiveFrame {
        let frame = *self
            .bindings
            .borrow()
            .by_address
            .get(&bytes.as_ptr().addr())
            .expect("observed bytes have a live binding");
        assert_eq!(frame.requested_len, bytes.len());
        frame
    }
}

/// Shared kernel-side state of both harnesses.
struct Harness {
    kernels: &'static [ScriptedKernel; 2],
    io: Option<XdpPacketIo<'static>>,
    observer: Observer,
    journal: Rc<RefCell<Journal>>,
    mtu: u32,
    /// Fill frames the kernel took and has not used for a packet yet.
    spare_fill: [Vec<u64>; 2],
    /// Frames committed only to hold TX in-flight slots; never completed.
    fillers: [BTreeSet<u32>; 2],
    /// Consumed TX descriptors awaiting completion, with their binding.
    submitted: Vec<(usize, u64, LiveFrame)>,
    allocation_budget: Option<usize>,
}

impl Harness {
    fn new() -> Self {
        let journal = Rc::new(RefCell::new(Journal::default()));
        Self {
            kernels: Box::leak(Box::new([kernel(), kernel()])),
            io: None,
            observer: Observer {
                bindings: Rc::new(RefCell::new(Bindings::default())),
                journal: Rc::clone(&journal),
            },
            journal,
            mtu: MTU,
            spare_fill: [Vec::new(), Vec::new()],
            fillers: [BTreeSet::new(), BTreeSet::new()],
            submitted: Vec::new(),
            allocation_budget: None,
        }
    }

    /// The adapter, built on first use so the MTU can still be set.
    fn io(&mut self) -> &mut XdpPacketIo<'static> {
        if self.io.is_none() {
            let kernels: &'static [ScriptedKernel; 2] = self.kernels;
            let mut io = XdpPacketIo::new([
                port(&kernels[0], CONFORMANCE_LAN, ENDPOINTS[0].queue, self.mtu),
                port(&kernels[1], CONFORMANCE_WAN, ENDPOINTS[1].queue, self.mtu),
            ])
            .expect("adapter");
            io.install_journal(Rc::clone(&self.journal));
            io.set_generated_allocation_budget(self.allocation_budget);
            self.io = Some(io);
        }
        self.io.as_mut().expect("built")
    }

    fn engine_state(&mut self, port: usize, frame: u32) -> (FrameStateKind, Option<u64>) {
        let interface = ENDPOINTS[port].interface;
        let view = self
            .io()
            .engine(interface)
            .expect("port")
            .ledger()
            .state(frame)
            .expect("frame");
        (
            view.kind(),
            view.token().map(|token| token.generation().get()),
        )
    }

    /// Kernel-receives `bytes` on `port`, into `frame` if given.
    fn inject(&mut self, port: usize, frame: Option<u32>, bytes: &[u8]) -> LiveFrame {
        let kernel = &self.kernels[port];
        let base = loop {
            if let Some(wanted) = frame {
                if let Some(index) = self.spare_fill[port]
                    .iter()
                    .position(|base| frame_of(*base) == wanted)
                {
                    break self.spare_fill[port].swap_remove(index);
                }
            } else if let Some(base) = self.spare_fill[port].pop() {
                break base;
            }
            match kernel.consume_fill() {
                Some(base) if frame.is_none_or(|wanted| frame_of(base) == wanted) => break base,
                Some(base) => self.spare_fill[port].push(base),
                None => {
                    // Freed frames return to Fill on the next refill.
                    self.io().service().expect("service");
                    assert!(kernel.fill_pending() > 0, "no frame for the kernel");
                }
            }
        };
        let index = frame_of(base);
        let (state, generation) = self.engine_state(port, index);
        assert_eq!(state, FrameStateKind::FillOwnedByKernel);
        let address = base + HEADROOM;
        // `deliver` consumes Fill itself; write the chosen frame directly.
        kernel.write_umem(address, bytes);
        assert!(kernel.produce_rx(XdpDescriptor {
            address,
            len: u32::try_from(bytes.len()).expect("short"),
            options: 0,
        }));
        let visible_address = kernel.umem_address(address);
        let live = LiveFrame {
            token: BufferToken::new(frame_id(port, index), generation.expect("owned")),
            visible_address,
            requested_len: bytes.len(),
        };
        let mut bindings = self.observer.bindings.borrow_mut();
        bindings.by_address.insert(visible_address, live);
        bindings
            .ingress
            .insert(visible_address, ENDPOINTS[port].interface);
        live
    }

    /// Commits `RING - budget` generated fillers on every port; the kernel
    /// consumes them and never completes them.
    fn hold_tx_slots(&mut self, budget: usize) {
        let fillers = (RING as usize).saturating_sub(budget);
        let restore = self.allocation_budget;
        self.io().set_generated_allocation_budget(None);
        for (port, endpoint) in ENDPOINTS.iter().enumerate() {
            let interface = endpoint.interface;
            {
                let mut batch = self.io().begin_generated(interface);
                for _ in 0..fillers {
                    batch.allocate(60).expect("filler").commit();
                }
                assert_eq!(batch.finish().accepted, fillers);
            }
            while let Some(descriptor) = self.kernels[port].consume_tx() {
                self.fillers[port].insert(frame_of(descriptor.address));
            }
        }
        self.io().set_generated_allocation_budget(restore);
        self.journal.borrow_mut().events.clear();
    }

    /// Consumes every TX descriptor and reports the submitted ones.
    fn take_submissions(&mut self) -> Vec<(usize, XdpDescriptor, LiveFrame, Vec<u8>)> {
        let mut taken = Vec::new();
        for port in 0..2 {
            let kernel = &self.kernels[port];
            while let Some(descriptor) = kernel.consume_tx() {
                assert!(
                    !self.fillers[port].contains(&frame_of(descriptor.address)),
                    "a filler was submitted twice"
                );
                let address = kernel.umem_address(descriptor.address);
                let binding = *self
                    .observer
                    .bindings
                    .borrow()
                    .by_address
                    .get(&address)
                    .expect("a submitted frame was bound");
                let mut bytes = vec![0; descriptor.len as usize];
                kernel.read_umem(descriptor.address, &mut bytes);
                self.submitted.push((port, descriptor.address, binding));
                taken.push((port, descriptor, binding, bytes));
            }
        }
        taken
    }

    fn complete(&mut self) -> Vec<TxCompletion> {
        let _ = self.take_submissions();
        let mut completions = Vec::new();
        for (port, address, frame) in std::mem::take(&mut self.submitted) {
            assert!(self.kernels[port].produce_completion(address));
            completions.push(TxCompletion {
                frame,
                endpoint: ENDPOINTS[port],
            });
        }
        self.io().service().expect("service");
        completions
    }

    fn take_journal(&mut self) -> Vec<JournalEvent> {
        std::mem::take(&mut self.journal.borrow_mut().events)
    }

    fn binding(&self, address: usize) -> LiveFrame {
        *self
            .observer
            .bindings
            .borrow()
            .by_address
            .get(&address)
            .expect("journaled frame was bound")
    }

    fn fail_next_kick(&mut self, port: usize) {
        self.io();
        self.kernels[port].set_tx_flags(XDP_RING_NEED_WAKEUP);
        self.kernels[port].fail_next_kick(Some(KICK_ERRNO));
    }
}

// ---------------------------------------------------------------- RX ----

struct XdpRxHarness(Harness);

impl RxHarness for XdpRxHarness {
    type Io = XdpPacketIo<'static>;
    type Observer = Observer;

    const COMMIT_EGRESS: IfId = CONFORMANCE_LAN;
    const MIN_FRAME_LEN: usize = ETHERNET_HEADER_LEN as usize;

    fn new() -> Self {
        let mut harness = Harness::new();
        harness.io();
        Self(harness)
    }

    fn io_and_observer(&mut self) -> (&mut Self::Io, &mut Self::Observer) {
        self.0.io();
        let harness = &mut self.0;
        (harness.io.as_mut().expect("built"), &mut harness.observer)
    }

    fn inject_rx(&mut self, ingress: IfId, bytes: Vec<u8>) -> LiveFrame {
        self.0.inject(port_of(ingress), None, &bytes)
    }

    fn set_rx_accept_budget(&mut self, budget: usize) {
        self.0.hold_tx_slots(budget);
    }

    fn pending_rx(&self) -> usize {
        let io = self.0.io.as_ref().expect("built");
        (0..2)
            .map(|port| {
                let kernel = &self.0.kernels[port];
                let ring = kernel.rx_producer().wrapping_sub(kernel.rx_consumer());
                let engine = io.engine(ENDPOINTS[port].interface).expect("port");
                (engine.pending_rx() + ring) as usize
            })
            .sum()
    }

    fn drain_rx_events(&mut self) -> Vec<RxEvent> {
        let mut events = Vec::new();
        for (port, descriptor, frame, bytes) in self.0.take_submissions() {
            let ingress = self.0.observer.bindings.borrow().ingress[&frame.visible_address];
            events.push(RxEvent {
                frame,
                ingress,
                bytes,
                kind: RxEventKind::TxSubmitted {
                    endpoint: ENDPOINTS[port],
                    descriptor_len: descriptor.len as usize,
                },
            });
        }
        for event in self.0.take_journal() {
            let kind = match event.kind {
                EventKind::RxReclaimed(SlotCompletion::Recycle(reason)) => {
                    RxEventKind::Reclaimed(RxReclaim::Recycled(reason))
                }
                EventKind::RxReclaimed(SlotCompletion::Consume(reason)) => {
                    RxEventKind::Reclaimed(RxReclaim::Consumed(reason))
                }
                EventKind::RxReclaimed(SlotCompletion::LeaseAbandoned) => {
                    RxEventKind::Reclaimed(RxReclaim::Abandoned)
                }
                EventKind::RxRejected { attempted, port } => RxEventKind::TxRejected {
                    attempted_egress: attempted,
                    endpoint: port.map(|port| ENDPOINTS[port]),
                },
                _ => continue,
            };
            let address = event.snapshot.address;
            events.push(RxEvent {
                frame: self.0.binding(address),
                ingress: self.0.observer.bindings.borrow().ingress[&address],
                bytes: event.snapshot.bytes,
                kind,
            });
        }
        events
    }
}

impl RxFinishErrorHarness for XdpRxHarness {
    fn fail_next_rx_finish(&mut self) {
        self.0.fail_next_kick(port_of(Self::COMMIT_EGRESS));
    }
}

impl RxCompletionHarness for XdpRxHarness {
    fn complete_rx_submissions(&mut self) -> Vec<TxCompletion> {
        self.0.complete()
    }
}

impl RxFinitePoolHarness for XdpRxHarness {
    fn free_rx_frames(&self) -> usize {
        let io = self.0.io.as_ref().expect("built");
        let kernel = &self.0.kernels[0];
        let accounting = io.engine(CONFORMANCE_LAN).expect("LAN").frame_accounting();
        // Fill frames the kernel already used for a packet are no longer free.
        let used = kernel.rx_producer().wrapping_sub(kernel.rx_consumer());
        (accounting.free + accounting.fill_in_kernel - used) as usize
    }
}

impl RxUnknownEgressHarness for XdpRxHarness {}

impl RxCqPoolHarness for XdpRxHarness {
    fn inject_rx_from_free_frame(
        &mut self,
        frame_id: u64,
        ingress: IfId,
        bytes: Vec<u8>,
    ) -> LiveFrame {
        let port = port_of(ingress);
        assert_eq!(frame_id >> 32, port as u64, "a frame of the ingress port");
        let frame = u32::try_from(frame_id & u64::from(u32::MAX)).expect("frame");
        self.0.inject(port, Some(frame), &bytes)
    }
}

// --------------------------------------------------------- generated ----

struct XdpGeneratedHarness(Harness);

impl GeneratedHarness for XdpGeneratedHarness {
    type Io = XdpPacketIo<'static>;
    type Observer = Observer;

    fn new() -> Self {
        Self(Harness::new())
    }

    fn io_and_observer(&mut self) -> (&mut Self::Io, &mut Self::Observer) {
        self.0.io();
        let harness = &mut self.0;
        (harness.io.as_mut().expect("built"), &mut harness.observer)
    }

    fn set_generated_allocation_budget(&mut self, budget: usize) {
        self.0.allocation_budget = Some(budget);
        self.0.io().set_generated_allocation_budget(Some(budget));
    }

    /// The adapter's real TX bound: the port MTU plus the Ethernet header.
    fn set_generated_max_frame(&mut self, max_frame: usize) {
        assert!(self.0.io.is_none(), "the MTU is fixed when ports are built");
        self.0.mtu = u32::try_from(max_frame).expect("small") - ETHERNET_HEADER_LEN;
    }

    fn set_generated_accept_budget(&mut self, budget: usize) {
        self.0.hold_tx_slots(budget);
    }

    fn drain_generated_events(&mut self) -> Vec<GeneratedEvent> {
        let mut events = Vec::new();
        for (port, descriptor, frame, bytes) in self.0.take_submissions() {
            events.push(GeneratedEvent {
                frame,
                egress: ENDPOINTS[port].interface,
                bytes,
                kind: GeneratedEventKind::TxSubmitted {
                    endpoint: ENDPOINTS[port],
                    descriptor_len: descriptor.len as usize,
                },
            });
        }
        for event in self.0.take_journal() {
            let port = event.snapshot.port;
            let kind = match event.kind {
                EventKind::GeneratedRejected { port } => GeneratedEventKind::TxRejected {
                    attempted_egress: ENDPOINTS[port].interface,
                    endpoint: Some(ENDPOINTS[port]),
                },
                EventKind::GeneratedEnded(GeneratedSlotCompletion::Cancelled) => {
                    GeneratedEventKind::Reclaimed(GeneratedReclaim::Cancelled)
                }
                EventKind::GeneratedEnded(GeneratedSlotCompletion::Abandoned) => {
                    GeneratedEventKind::Reclaimed(GeneratedReclaim::Abandoned)
                }
                _ => continue,
            };
            events.push(GeneratedEvent {
                frame: self.0.binding(event.snapshot.address),
                egress: ENDPOINTS[port].interface,
                bytes: event.snapshot.bytes,
                kind,
            });
        }
        events
    }
}

impl GeneratedFinishErrorHarness for XdpGeneratedHarness {
    fn fail_next_generated_finish(&mut self) {
        self.0.fail_next_kick(port_of(CONFORMANCE_WAN));
    }
}

impl GeneratedCompletionHarness for XdpGeneratedHarness {
    fn complete_generated_submissions(&mut self) -> Vec<TxCompletion> {
        self.0.complete()
    }
}

impl GeneratedFinitePoolHarness for XdpGeneratedHarness {
    fn free_generated_frames(&self) -> usize {
        let io = self.0.io.as_ref().expect("built");
        ENDPOINTS
            .iter()
            .map(|endpoint| {
                io.engine(endpoint.interface)
                    .expect("port")
                    .generated_free_frames() as usize
            })
            .sum()
    }
}

impl GeneratedCqPoolHarness for XdpGeneratedHarness {
    fn prefer_generated_frame(&mut self, frame_id: u64) {
        let port = usize::try_from(frame_id >> 32).expect("port");
        let frame = u32::try_from(frame_id & u64::from(u32::MAX)).expect("frame");
        let interface = ENDPOINTS[port].interface;
        assert!(
            self.0
                .io()
                .engine_mut_for_test(interface)
                .prefer_generated_free_for_test(frame),
            "the preferred frame is free"
        );
    }
}

/// Audits both engines after a case: every frame accounted exactly once.
fn audit(harness: &Harness) {
    if let Some(io) = harness.io.as_ref() {
        for endpoint in ENDPOINTS {
            io.engine(endpoint.interface)
                .expect("port")
                .audit()
                .expect("engine audit");
        }
    }
}

#[test]
#[cfg_attr(miri, ignore = "the harness leaks its 'static scripted kernels")]
fn xdp_adapter_passes_the_rx_conformance_suite() {
    rx::budget_and_unleased_slots_are_exact::<XdpRxHarness>();
    rx::commit_is_submitted_in_place_with_exact_descriptor::<XdpRxHarness>();
    rx::recycle_consume_and_abandon_are_distinct::<XdpRxHarness>();
    rx::partial_reject_reclaims_exact_tokens::<XdpRxHarness>();
    rx::partial_reject_with_finish_error_is_exact::<XdpRxHarness>();
    rx::completion_advances_the_exact_submitted_token::<XdpRxHarness>();
    rx::repeated_rejects_restore_physical_pool::<XdpRxHarness>();
    rx::unknown_egress_is_rejected_without_submission::<XdpRxHarness>();
}

#[test]
#[cfg_attr(miri, ignore = "the harness leaks its 'static scripted kernels")]
fn xdp_adapter_passes_the_rx_cq_pool_suite() {
    rx::cq_return_releases_same_rx_frame_with_new_generation::<XdpRxHarness>();
    rx::dropped_batch_preserves_unleased_rx_and_cq_ownership::<XdpRxHarness>();
}

#[test]
#[cfg_attr(miri, ignore = "the harness leaks its 'static scripted kernels")]
fn xdp_adapter_passes_the_generated_conformance_suite() {
    generated::empty_session_has_zero_accounting::<XdpGeneratedHarness>();
    generated::allocation_failures_bind_only_successful_ownership::<XdpGeneratedHarness>();
    generated::commit_cancel_and_abandon_bind_exact_lengths::<XdpGeneratedHarness>();
    generated::partial_reject_reclaims_exact_tokens::<XdpGeneratedHarness>();
    generated::sessions_bind_concrete_endpoints::<XdpGeneratedHarness>();
    generated::partial_reject_with_finish_error_is_exact::<XdpGeneratedHarness>();
    generated::completion_advances_the_exact_submitted_token::<XdpGeneratedHarness>();
    generated::repeated_rejects_restore_physical_pool_and_advance_generation::<XdpGeneratedHarness>(
    );
}

#[test]
#[cfg_attr(miri, ignore = "the harness leaks its 'static scripted kernels")]
fn xdp_adapter_passes_the_generated_cq_pool_suite() {
    generated::cq_return_releases_same_generated_frame_with_new_generation::<XdpGeneratedHarness>();
    generated::dropped_batch_accounts_generated_and_cannot_carry_to_next_egress::<
        XdpGeneratedHarness,
    >();
}

/// The harness itself: an accept budget is real TX back-pressure, and the
/// engines stay consistent after a full case.
#[test]
#[cfg_attr(miri, ignore = "the harness leaks its 'static scripted kernels")]
fn xdp_conformance_harness_budget_is_real_back_pressure() {
    let mut harness = XdpRxHarness::new();
    harness.set_rx_accept_budget(1);
    let io = harness.0.io.as_ref().expect("built");
    let engine = io.engine(CONFORMANCE_LAN).expect("LAN");
    assert_eq!(engine.tx_inflight(), RING - 1, "fillers hold the slots");
    audit(&harness.0);
    // One commit is accepted, the next is refused as back-pressure.
    harness.inject_rx(CONFORMANCE_LAN, vec![0; 60]);
    harness.inject_rx(CONFORMANCE_LAN, vec![0; 60]);
    let completion = {
        let (io, _) = harness.io_and_observer();
        let mut batch = ruster_core::PacketIo::receive(io, 8).expect("receive");
        while let Some(packet) = ruster_core::PacketBatch::next_packet(&mut batch) {
            packet.commit(CONFORMANCE_LAN);
        }
        ruster_core::PacketBatch::finish(batch)
    };
    assert_eq!((completion.tx_accepted, completion.tx_rejected), (1, 1));
    assert_eq!(completion.error, None);
    let stats = harness
        .0
        .io
        .as_ref()
        .expect("built")
        .port_stats(CONFORMANCE_LAN)
        .expect("LAN")
        .counters;
    assert_eq!(stats.tx_blocked, 1);
    assert_eq!(harness.drain_rx_events().len(), 2);
    assert_eq!(harness.complete_rx_submissions().len(), 1);
    audit(&harness.0);
}
