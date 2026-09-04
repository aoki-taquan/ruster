#![forbid(unsafe_code)]
#![doc = "Reusable, deterministic conformance cases for ruster packet I/O backends."]
//!
//! Harnesses bind physical frame identity while a lease is live. Later
//! observations must reuse that binding and cannot create identity after
//! `finish`. Accepted TX is only submitted and remains in flight; optional
//! completion capabilities advance the same token separately. Finite-pool
//! capabilities must expose the real backend free pool or ring.

use ruster_core::{ConsumeReason, DropReason, GeneratedPacketIo, IfId, PacketIo};

/// Known ingress/egress used by reusable conformance cases.
pub const CONFORMANCE_LAN: IfId = IfId(11);
/// Second known ingress/egress used by reusable conformance cases.
pub const CONFORMANCE_WAN: IfId = IfId(22);
/// Interface deliberately absent from the backend's publication map.
pub const CONFORMANCE_UNKNOWN: IfId = IfId(99);
/// Required publication ring for [`CONFORMANCE_LAN`].
pub const CONFORMANCE_LAN_ENDPOINT: TxEndpoint = TxEndpoint {
    interface: CONFORMANCE_LAN,
    queue: 3,
};
/// Required publication ring for [`CONFORMANCE_WAN`].
pub const CONFORMANCE_WAN_ENDPOINT: TxEndpoint = TxEndpoint {
    interface: CONFORMANCE_WAN,
    queue: 7,
};

/// Backend frame identity plus an ownership-cycle generation.
///
/// `frame_id` identifies physical storage, such as an AF_XDP UMEM frame.
/// Reallocation of the same storage must increment `generation`, preventing an
/// old observation from being confused with a later ownership cycle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BufferToken {
    pub frame_id: u64,
    pub generation: u64,
}

impl BufferToken {
    #[must_use]
    pub const fn new(frame_id: u64, generation: u64) -> Self {
        Self {
            frame_id,
            generation,
        }
    }
}

/// Identity bound while a lease is live.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveFrame {
    pub token: BufferToken,
    pub visible_address: usize,
    pub requested_len: usize,
}

/// A concrete backend TX endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxEndpoint {
    pub interface: IfId,
    pub queue: u32,
}

/// Independent observer used while the I/O object is mutably borrowed.
///
/// `bind` is called exactly when ownership of an injected RX frame or a
/// generated allocation begins.
/// `observe` must return that existing binding and must never invent a new
/// token for a terminal event.
pub trait LeaseObserver {
    fn bind(&mut self, bytes: &[u8], requested_len: usize) -> LiveFrame;
    fn observe(&self, bytes: &[u8]) -> LiveFrame;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxReclaim {
    Recycled(DropReason),
    Consumed(ConsumeReason),
    Abandoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxEventKind {
    /// Descriptor publication succeeded; the frame remains in flight.
    TxSubmitted {
        endpoint: TxEndpoint,
        descriptor_len: usize,
    },
    /// Descriptor publication failed and the frame is already reclaimed.
    TxRejected {
        attempted_egress: IfId,
        endpoint: Option<TxEndpoint>,
    },
    /// A non-TX lifecycle returned the frame to the backend.
    Reclaimed(RxReclaim),
}

#[derive(Debug, Eq, PartialEq)]
pub struct RxEvent {
    pub frame: LiveFrame,
    pub ingress: IfId,
    /// Cold test snapshot. Ownership identity comes from `frame`.
    pub bytes: Vec<u8>,
    pub kind: RxEventKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedReclaim {
    Cancelled,
    Abandoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedEventKind {
    /// Descriptor publication succeeded; the frame remains in flight.
    TxSubmitted {
        endpoint: TxEndpoint,
        descriptor_len: usize,
    },
    /// Descriptor publication failed and the frame is already reclaimed.
    TxRejected {
        attempted_egress: IfId,
        endpoint: Option<TxEndpoint>,
    },
    Reclaimed(GeneratedReclaim),
}

#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedEvent {
    pub frame: LiveFrame,
    pub egress: IfId,
    /// Cold test snapshot. Ownership identity comes from `frame`.
    pub bytes: Vec<u8>,
    pub kind: GeneratedEventKind,
}

/// CQ/completion observation for a previously submitted frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxCompletion {
    pub frame: LiveFrame,
    pub endpoint: TxEndpoint,
}

pub trait RxHarness: Sized {
    type Io: PacketIo;
    type Observer: LeaseObserver;

    fn new() -> Self;
    fn io_and_observer(&mut self) -> (&mut Self::Io, &mut Self::Observer);
    fn inject_rx(&mut self, ingress: IfId, bytes: Vec<u8>) -> LiveFrame;
    fn set_rx_accept_budget(&mut self, budget: usize);
    fn pending_rx(&self) -> usize;
    /// Drains observations from actual publication and reclamation rings.
    ///
    /// Rejected/reclaimed events are already reusable; submitted events remain
    /// in flight until a completion capability advances them. The endpoint of
    /// a submitted event must identify the ring that received the descriptor,
    /// not a value inferred from the requested egress afterward.
    fn drain_rx_events(&mut self) -> Vec<RxEvent>;
}

pub trait RxReceiveErrorHarness: RxHarness {
    fn fail_next_receive(&mut self);
}

pub trait RxFinishErrorHarness: RxHarness {
    fn fail_next_rx_finish(&mut self);
}

pub trait RxCompletionHarness: RxHarness {
    /// Advances CQ-observed completions for previously submitted tokens.
    fn complete_rx_submissions(&mut self) -> Vec<TxCompletion>;
}

/// Physical finite-pool observation; implementations must read the backend
/// free pool/ring, not derive the value from conformance event counters.
/// `inject_rx` must reserve frames from this same reported pool.
pub trait RxFinitePoolHarness: RxHarness {
    fn free_rx_frames(&self) -> usize;
}

pub trait RxUnknownEgressHarness: RxHarness {}

pub trait RxCqPoolHarness: RxCompletionHarness + RxFinitePoolHarness {
    /// Reserves the named physical frame from the real free pool for RX.
    fn inject_rx_from_free_frame(
        &mut self,
        frame_id: u64,
        ingress: IfId,
        bytes: Vec<u8>,
    ) -> LiveFrame;
}

pub trait GeneratedHarness: Sized {
    type Io: GeneratedPacketIo;
    type Observer: LeaseObserver;

    fn new() -> Self;
    fn io_and_observer(&mut self) -> (&mut Self::Io, &mut Self::Observer);
    fn set_generated_allocation_budget(&mut self, budget: usize);
    fn set_generated_max_frame(&mut self, max_frame: usize);
    fn set_generated_accept_budget(&mut self, budget: usize);
    /// Drains observations from actual publication and reclamation rings.
    ///
    /// Rejected/reclaimed events are already reusable; submitted events remain
    /// in flight until a completion capability advances them. The endpoint of
    /// a submitted event must identify the ring that received the descriptor,
    /// not a value inferred from the requested egress afterward.
    fn drain_generated_events(&mut self) -> Vec<GeneratedEvent>;
}

pub trait GeneratedFinishErrorHarness: GeneratedHarness {
    fn fail_next_generated_finish(&mut self);
}

pub trait GeneratedCompletionHarness: GeneratedHarness {
    /// Advances CQ-observed completions for previously submitted tokens.
    fn complete_generated_submissions(&mut self) -> Vec<TxCompletion>;
}

/// Physical finite-pool observation; implementations must query the backend
/// free pool/ring rather than maintain an accounting shadow.
pub trait GeneratedFinitePoolHarness: GeneratedHarness {
    fn free_generated_frames(&self) -> usize;
}

pub trait GeneratedUnknownEgressHarness: GeneratedHarness {}

pub trait GeneratedCqPoolHarness: GeneratedCompletionHarness + GeneratedFinitePoolHarness {
    /// Makes the next allocation select the named physical free frame.
    fn prefer_generated_frame(&mut self, frame_id: u64);
}

pub mod rx {
    use std::collections::{BTreeMap, BTreeSet};

    use ruster_core::{ConsumeReason, DropReason, IfId, PacketBatch, PacketIo};

    use super::{
        BufferToken, LeaseObserver, LiveFrame, RxCompletionHarness, RxCqPoolHarness, RxEvent,
        RxEventKind, RxFinishErrorHarness, RxFinitePoolHarness, RxHarness, RxReceiveErrorHarness,
        RxReclaim, RxUnknownEgressHarness, TxEndpoint, CONFORMANCE_LAN, CONFORMANCE_LAN_ENDPOINT,
        CONFORMANCE_UNKNOWN, CONFORMANCE_WAN, CONFORMANCE_WAN_ENDPOINT,
    };

    const LAN: IfId = CONFORMANCE_LAN;
    const WAN: IfId = CONFORMANCE_WAN;

    fn expected_endpoint(egress: IfId) -> TxEndpoint {
        match egress {
            LAN => CONFORMANCE_LAN_ENDPOINT,
            WAN => CONFORMANCE_WAN_ENDPOINT,
            _ => panic!("unknown conformance endpoint"),
        }
    }

    fn assert_distinct_live(frames: &[LiveFrame]) {
        let frame_ids: BTreeSet<_> = frames.iter().map(|frame| frame.token.frame_id).collect();
        let tokens: BTreeSet<_> = frames.iter().map(|frame| frame.token).collect();
        let visible_addresses: BTreeSet<_> =
            frames.iter().map(|frame| frame.visible_address).collect();
        assert_eq!(frame_ids.len(), frames.len(), "live RX frame alias");
        assert_eq!(tokens.len(), frames.len(), "duplicate live RX token");
        assert_eq!(
            visible_addresses.len(),
            frames.len(),
            "live RX visible address alias"
        );
        assert!(frames.iter().all(|frame| frame.token.generation != 0));
    }

    fn expected_map(frames: &[LiveFrame]) -> BTreeMap<BufferToken, LiveFrame> {
        frames.iter().map(|frame| (frame.token, *frame)).collect()
    }

    fn assert_event_bindings(expected: &[LiveFrame], events: &[RxEvent]) {
        let expected = expected_map(expected);
        assert_eq!(events.len(), expected.len());
        let mut observed = BTreeSet::new();
        for event in events {
            assert!(
                observed.insert(event.frame.token),
                "duplicate RX event token"
            );
            assert_eq!(
                expected.get(&event.frame.token),
                Some(&event.frame),
                "RX terminal event changed or invented its lease-time binding"
            );
            assert_eq!(event.bytes.len(), event.frame.requested_len);
            if let RxEventKind::TxSubmitted { descriptor_len, .. } = event.kind {
                assert_eq!(
                    descriptor_len, event.frame.requested_len,
                    "RX descriptor length differs from the lease-time length"
                );
            }
        }
    }

    pub fn budget_and_unleased_slots_are_exact<H: RxHarness>() {
        let mut harness = H::new();
        let injected = [
            harness.inject_rx(LAN, vec![1, 0xa1]),
            harness.inject_rx(LAN, vec![2, 0xa2]),
            harness.inject_rx(LAN, vec![3, 0xa3]),
        ];
        assert_distinct_live(&injected);

        let completion = {
            let (io, _) = harness.io_and_observer();
            let mut batch = match io.receive(0) {
                Ok(batch) => batch,
                Err(_) => panic!("zero-budget receive failed"),
            };
            assert!(batch.next_packet().is_none());
            batch.finish()
        };
        assert!(completion.invariants_hold());
        assert_eq!(
            (
                completion.tx_requested,
                completion.tx_accepted,
                completion.tx_rejected,
                completion.recycled,
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(harness.pending_rx(), 3);

        let mut leased_tokens = BTreeSet::new();
        let completion = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = match io.receive(2) {
                Ok(batch) => batch,
                Err(_) => panic!("budgeted receive failed"),
            };
            while let Some(mut packet) = batch.next_packet() {
                let frame = observer.observe(packet.bytes_mut());
                assert!(leased_tokens.insert(frame.token));
                packet.recycle(DropReason::RouteMiss);
            }
            batch.finish()
        };
        assert!(completion.invariants_hold());
        assert_eq!(completion.recycled, 2);
        assert_eq!(harness.pending_rx(), 1);

        let completion = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = match io.receive(usize::MAX) {
                Ok(batch) => batch,
                Err(_) => panic!("remaining receive failed"),
            };
            let mut packet = batch.next_packet().expect("unleased RX slot");
            let frame = observer.observe(packet.bytes_mut());
            assert!(leased_tokens.insert(frame.token));
            packet.recycle(DropReason::RouteMiss);
            assert!(batch.next_packet().is_none());
            batch.finish()
        };
        assert!(completion.invariants_hold());
        assert_eq!(completion.recycled, 1);
        assert_eq!(
            leased_tokens,
            injected.iter().map(|frame| frame.token).collect()
        );
        let events = harness.drain_rx_events();
        assert_event_bindings(&injected, &events);
    }

    pub fn commit_is_submitted_in_place_with_exact_descriptor<H: RxHarness>() {
        let mut harness = H::new();
        let endpoint = expected_endpoint(WAN);
        let injected = harness.inject_rx(LAN, vec![0x10, 0x20, 0x30]);
        let completion = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = match io.receive(1) {
                Ok(batch) => batch,
                Err(_) => panic!("RX receive failed"),
            };
            let mut packet = batch.next_packet().expect("one RX lease");
            assert_eq!(packet.ingress(), LAN);
            let observed = observer.observe(packet.bytes_mut());
            assert_eq!(observed, injected);
            packet.bytes_mut()[1] = 0x99;
            packet.commit(WAN);
            batch.finish()
        };
        assert!(completion.invariants_hold());
        assert_eq!(
            (
                completion.tx_requested,
                completion.tx_accepted,
                completion.tx_rejected,
                completion.recycled,
            ),
            (1, 1, 0, 0)
        );
        let events = harness.drain_rx_events();
        assert_event_bindings(&[injected], &events);
        assert_eq!(events[0].bytes, [0x10, 0x99, 0x30]);
        assert_eq!(
            events[0].kind,
            RxEventKind::TxSubmitted {
                endpoint,
                descriptor_len: injected.requested_len,
            }
        );
    }

    pub fn recycle_consume_and_abandon_are_distinct<H: RxHarness>() {
        let mut harness = H::new();
        let injected = [
            harness.inject_rx(LAN, vec![1, 0x11]),
            harness.inject_rx(LAN, vec![2, 0x22]),
            harness.inject_rx(LAN, vec![3, 0x33]),
        ];
        assert_distinct_live(&injected);
        let completion = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = match io.receive(3) {
                Ok(batch) => batch,
                Err(_) => panic!("RX receive failed"),
            };
            while let Some(mut packet) = batch.next_packet() {
                let observed = observer.observe(packet.bytes_mut());
                assert_eq!(observed.requested_len, packet.bytes_mut().len());
                match packet.bytes_mut()[0] {
                    1 => packet.recycle(DropReason::NeighborUnresolved),
                    2 => packet.consume(ConsumeReason::ArpControl),
                    3 => drop(packet),
                    _ => panic!("unexpected RX marker"),
                }
            }
            batch.finish()
        };
        assert!(completion.invariants_hold());
        assert_eq!(completion.recycled, 3);
        let events = harness.drain_rx_events();
        assert_event_bindings(&injected, &events);
        for event in events {
            let expected = match event.bytes[0] {
                1 => RxEventKind::Reclaimed(RxReclaim::Recycled(DropReason::NeighborUnresolved)),
                2 => RxEventKind::Reclaimed(RxReclaim::Consumed(ConsumeReason::ArpControl)),
                3 => RxEventKind::Reclaimed(RxReclaim::Abandoned),
                _ => panic!("unexpected RX marker"),
            };
            assert_eq!(event.kind, expected);
        }
    }

    pub fn partial_reject_reclaims_exact_tokens<H: RxHarness>() {
        let mut harness = H::new();
        harness.set_rx_accept_budget(1);
        let endpoint = expected_endpoint(WAN);
        let injected = [
            harness.inject_rx(LAN, vec![1, 0x41]),
            harness.inject_rx(LAN, vec![2, 0x42]),
            harness.inject_rx(LAN, vec![3, 0x43]),
        ];
        assert_distinct_live(&injected);
        let completion = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = match io.receive(3) {
                Ok(batch) => batch,
                Err(_) => panic!("RX receive failed"),
            };
            while let Some(mut packet) = batch.next_packet() {
                let observed = observer.observe(packet.bytes_mut());
                assert!(injected.contains(&observed));
                packet.commit(WAN);
            }
            batch.finish()
        };
        assert!(completion.invariants_hold());
        assert_eq!(
            (
                completion.tx_requested,
                completion.tx_accepted,
                completion.tx_rejected,
                completion.recycled,
            ),
            (3, 1, 2, 0)
        );
        let events = harness.drain_rx_events();
        assert_event_bindings(&injected, &events);
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    event.kind
                        == RxEventKind::TxSubmitted {
                            endpoint,
                            descriptor_len: event.frame.requested_len,
                        }
                })
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    event.kind
                        == RxEventKind::TxRejected {
                            attempted_egress: WAN,
                            endpoint: Some(endpoint),
                        }
                })
                .count(),
            2
        );
    }

    pub fn receive_error_preserves_queued_ownership<H: RxReceiveErrorHarness>() {
        let mut harness = H::new();
        let injected = harness.inject_rx(LAN, vec![0x51, 0x52]);
        harness.fail_next_receive();
        let receive_failed = {
            let (io, _) = harness.io_and_observer();
            io.receive(1).is_err()
        };
        assert!(receive_failed);
        assert_eq!(harness.pending_rx(), 1);
        let completion = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = match io.receive(1) {
                Ok(batch) => batch,
                Err(_) => panic!("RX retry failed"),
            };
            let mut packet = batch.next_packet().expect("RX slot survives error");
            assert_eq!(observer.observe(packet.bytes_mut()), injected);
            packet.recycle(DropReason::RouteMiss);
            batch.finish()
        };
        assert!(completion.invariants_hold());
        assert_eq!(completion.recycled, 1);
        assert_event_bindings(&[injected], &harness.drain_rx_events());
    }

    pub fn partial_reject_with_finish_error_is_exact<H: RxFinishErrorHarness>() {
        let mut harness = H::new();
        harness.set_rx_accept_budget(1);
        harness.fail_next_rx_finish();
        let injected = [
            harness.inject_rx(LAN, vec![0x61]),
            harness.inject_rx(LAN, vec![0x62]),
            harness.inject_rx(LAN, vec![0x63]),
        ];
        let completion = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = match io.receive(3) {
                Ok(batch) => batch,
                Err(_) => panic!("RX receive failed"),
            };
            while let Some(mut packet) = batch.next_packet() {
                assert!(injected.contains(&observer.observe(packet.bytes_mut())));
                packet.commit(WAN);
            }
            batch.finish()
        };
        assert!(completion.invariants_hold());
        assert_eq!((completion.tx_accepted, completion.tx_rejected), (1, 2));
        assert!(completion.error.is_some());
        assert_event_bindings(&injected, &harness.drain_rx_events());
    }

    pub fn completion_advances_the_exact_submitted_token<H: RxCompletionHarness>() {
        let mut harness = H::new();
        let endpoint = expected_endpoint(WAN);
        let injected = harness.inject_rx(LAN, vec![0x71, 0x72]);
        {
            let (io, observer) = harness.io_and_observer();
            let mut batch = match io.receive(1) {
                Ok(batch) => batch,
                Err(_) => panic!("RX receive failed"),
            };
            let mut packet = batch.next_packet().expect("RX lease");
            assert_eq!(observer.observe(packet.bytes_mut()), injected);
            packet.commit(WAN);
            let completion = batch.finish();
            assert!(completion.invariants_hold());
            assert_eq!(completion.tx_accepted, 1);
        }
        let events = harness.drain_rx_events();
        assert!(matches!(events[0].kind, RxEventKind::TxSubmitted { .. }));
        let completions = harness.complete_rx_submissions();
        assert_eq!(
            completions,
            [super::TxCompletion {
                frame: injected,
                endpoint,
            }]
        );
    }

    pub fn repeated_rejects_restore_physical_pool<H: RxFinitePoolHarness>() {
        let mut harness = H::new();
        harness.set_rx_accept_budget(0);
        let baseline = harness.free_rx_frames();
        let mut last_generation = BTreeMap::<u64, u64>::new();
        for cycle in 0_u8..4 {
            let injected = [
                harness.inject_rx(LAN, vec![cycle, 1]),
                harness.inject_rx(LAN, vec![cycle, 2]),
            ];
            for frame in injected {
                if let Some(previous) =
                    last_generation.insert(frame.token.frame_id, frame.token.generation)
                {
                    assert!(
                        frame.token.generation > previous,
                        "reused RX frame did not advance ownership generation"
                    );
                }
            }
            assert_eq!(harness.free_rx_frames() + injected.len(), baseline);
            {
                let (io, observer) = harness.io_and_observer();
                let mut batch = match io.receive(2) {
                    Ok(batch) => batch,
                    Err(_) => panic!("RX receive failed"),
                };
                while let Some(mut packet) = batch.next_packet() {
                    assert!(injected.contains(&observer.observe(packet.bytes_mut())));
                    packet.commit(WAN);
                }
                let completion = batch.finish();
                assert!(completion.invariants_hold());
                assert_eq!(completion.tx_rejected, 2);
            }
            assert_eq!(
                harness.free_rx_frames(),
                baseline,
                "rejected frame was not returned by finish"
            );
            let events = harness.drain_rx_events();
            assert_event_bindings(&injected, &events);
        }
    }

    pub fn unknown_egress_is_rejected_without_submission<H: RxUnknownEgressHarness>() {
        let mut harness = H::new();
        let unknown = CONFORMANCE_UNKNOWN;
        let injected = harness.inject_rx(LAN, vec![0x81]);
        let completion = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = match io.receive(1) {
                Ok(batch) => batch,
                Err(_) => panic!("RX receive failed"),
            };
            let mut packet = batch.next_packet().expect("RX lease");
            assert_eq!(observer.observe(packet.bytes_mut()), injected);
            packet.commit(unknown);
            batch.finish()
        };
        assert!(completion.invariants_hold());
        assert_eq!((completion.tx_accepted, completion.tx_rejected), (0, 1));
        let events = harness.drain_rx_events();
        assert_event_bindings(&[injected], &events);
        assert_eq!(
            events[0].kind,
            RxEventKind::TxRejected {
                attempted_egress: unknown,
                endpoint: None,
            }
        );
    }

    pub fn cq_return_releases_same_rx_frame_with_new_generation<H: RxCqPoolHarness>() {
        let mut harness = H::new();
        harness.set_rx_accept_budget(1);
        let baseline = harness.free_rx_frames();
        assert!(baseline >= 1);
        let first = harness.inject_rx(LAN, vec![0x91, 0x92]);
        assert_eq!(harness.free_rx_frames() + 1, baseline);
        {
            let (io, observer) = harness.io_and_observer();
            let mut batch = match io.receive(1) {
                Ok(batch) => batch,
                Err(_) => panic!("RX receive failed"),
            };
            let mut packet = batch.next_packet().expect("RX lease");
            assert_eq!(observer.observe(packet.bytes_mut()), first);
            packet.commit(WAN);
            let completion = batch.finish();
            assert!(completion.invariants_hold());
            assert_eq!(completion.tx_accepted, 1);
        }
        let events = harness.drain_rx_events();
        assert_event_bindings(&[first], &events);
        assert_eq!(
            events[0].kind,
            RxEventKind::TxSubmitted {
                endpoint: expected_endpoint(WAN),
                descriptor_len: first.requested_len,
            }
        );
        assert_eq!(
            harness.free_rx_frames() + 1,
            baseline,
            "submitted RX frame returned before CQ observation"
        );
        assert_eq!(
            harness.complete_rx_submissions(),
            [super::TxCompletion {
                frame: first,
                endpoint: expected_endpoint(WAN),
            }]
        );
        assert_eq!(
            harness.free_rx_frames(),
            baseline,
            "CQ-observed RX frame was not returned to the free pool"
        );

        let second = harness.inject_rx_from_free_frame(first.token.frame_id, LAN, vec![0x93, 0x94]);
        assert_eq!(second.token.frame_id, first.token.frame_id);
        assert!(
            second.token.generation > first.token.generation,
            "CQ-returned RX frame reused a stale generation"
        );
        assert_eq!(harness.free_rx_frames() + 1, baseline);
        {
            let (io, observer) = harness.io_and_observer();
            let mut batch = match io.receive(1) {
                Ok(batch) => batch,
                Err(_) => panic!("RX receive failed"),
            };
            let mut packet = batch.next_packet().expect("re-leased RX frame");
            assert_eq!(observer.observe(packet.bytes_mut()), second);
            packet.recycle(DropReason::RouteMiss);
            let completion = batch.finish();
            assert!(completion.invariants_hold());
            assert_eq!(completion.recycled, 1);
        }
        assert_eq!(harness.free_rx_frames(), baseline);
        let events = harness.drain_rx_events();
        assert_event_bindings(&[second], &events);
        assert_eq!(
            events[0].kind,
            RxEventKind::Reclaimed(RxReclaim::Recycled(DropReason::RouteMiss))
        );
    }

    pub fn dropped_batch_preserves_unleased_rx_and_cq_ownership<H: RxCqPoolHarness>() {
        let mut harness = H::new();
        harness.set_rx_accept_budget(1);
        let baseline = harness.free_rx_frames();
        assert!(baseline >= 3);
        let injected = [
            harness.inject_rx(LAN, vec![0xc1]),
            harness.inject_rx(LAN, vec![0xc2]),
            harness.inject_rx(LAN, vec![0xc3]),
        ];
        assert_distinct_live(&injected);
        assert_eq!(harness.free_rx_frames() + injected.len(), baseline);

        {
            let (io, observer) = harness.io_and_observer();
            let mut batch = match io.receive(3) {
                Ok(batch) => batch,
                Err(_) => panic!("RX receive failed"),
            };
            let mut packet = batch.next_packet().expect("committed RX lease");
            assert_eq!(observer.observe(packet.bytes_mut()), injected[0]);
            packet.commit(WAN);
            drop(batch);
        }

        let terminal = harness.drain_rx_events();
        assert_event_bindings(&injected[..1], &terminal);
        let submitted = match terminal[0].kind {
            RxEventKind::TxSubmitted {
                endpoint,
                descriptor_len,
            } => {
                assert_eq!(endpoint, expected_endpoint(WAN));
                assert_eq!(descriptor_len, injected[0].requested_len);
                assert_eq!(
                    harness.free_rx_frames() + injected.len(),
                    baseline,
                    "batch drop returned a published RX frame before CQ"
                );
                true
            }
            RxEventKind::TxRejected {
                attempted_egress,
                endpoint,
            } => {
                assert_eq!(attempted_egress, WAN);
                assert_eq!(endpoint, Some(expected_endpoint(WAN)));
                assert_eq!(harness.free_rx_frames() + 2, baseline);
                false
            }
            RxEventKind::Reclaimed(_) => panic!("committed RX lease lost its TX disposition"),
        };
        assert_eq!(
            harness.pending_rx(),
            2,
            "batch drop lost or exposed unleased RX ownership"
        );

        let mut reobserved = Vec::new();
        {
            let (io, observer) = harness.io_and_observer();
            let mut batch = match io.receive(2) {
                Ok(batch) => batch,
                Err(_) => panic!("unleased RX retry failed"),
            };
            while let Some(mut packet) = batch.next_packet() {
                reobserved.push(observer.observe(packet.bytes_mut()));
                packet.recycle(DropReason::RouteMiss);
            }
            let completion = batch.finish();
            assert!(completion.invariants_hold());
            assert_eq!(completion.recycled, 2);
        }
        assert_eq!(
            reobserved
                .iter()
                .map(|frame| frame.token)
                .collect::<BTreeSet<_>>(),
            injected[1..]
                .iter()
                .map(|frame| frame.token)
                .collect::<BTreeSet<_>>(),
            "batch drop changed unleased RX ownership"
        );
        let reclaimed = harness.drain_rx_events();
        assert_event_bindings(&injected[1..], &reclaimed);
        assert!(reclaimed.iter().all(|event| {
            event.kind == RxEventKind::Reclaimed(RxReclaim::Recycled(DropReason::RouteMiss))
        }));

        let completions = harness.complete_rx_submissions();
        if submitted {
            assert_eq!(
                completions,
                [super::TxCompletion {
                    frame: injected[0],
                    endpoint: expected_endpoint(WAN),
                }]
            );
        } else {
            assert!(completions.is_empty());
        }
        assert_eq!(
            harness.free_rx_frames(),
            baseline,
            "batch-drop lifecycle did not restore the physical RX pool"
        );
    }
}

pub mod generated {
    use std::collections::{BTreeMap, BTreeSet};

    use ruster_core::{GeneratedAllocationError, GeneratedPacketBatch, GeneratedPacketIo, IfId};

    use super::{
        BufferToken, GeneratedCompletionHarness, GeneratedCqPoolHarness, GeneratedEvent,
        GeneratedEventKind, GeneratedFinishErrorHarness, GeneratedFinitePoolHarness,
        GeneratedHarness, GeneratedReclaim, GeneratedUnknownEgressHarness, LeaseObserver,
        LiveFrame, TxEndpoint, CONFORMANCE_LAN, CONFORMANCE_LAN_ENDPOINT, CONFORMANCE_UNKNOWN,
        CONFORMANCE_WAN, CONFORMANCE_WAN_ENDPOINT,
    };

    const LAN: IfId = CONFORMANCE_LAN;
    const WAN: IfId = CONFORMANCE_WAN;

    fn expected_endpoint(egress: IfId) -> TxEndpoint {
        match egress {
            LAN => CONFORMANCE_LAN_ENDPOINT,
            WAN => CONFORMANCE_WAN_ENDPOINT,
            _ => panic!("unknown conformance endpoint"),
        }
    }

    fn assert_distinct_live(frames: &[LiveFrame]) {
        let frame_ids: BTreeSet<_> = frames.iter().map(|frame| frame.token.frame_id).collect();
        let tokens: BTreeSet<_> = frames.iter().map(|frame| frame.token).collect();
        let visible_addresses: BTreeSet<_> =
            frames.iter().map(|frame| frame.visible_address).collect();
        assert_eq!(frame_ids.len(), frames.len(), "live generated frame alias");
        assert_eq!(tokens.len(), frames.len(), "duplicate generated token");
        assert_eq!(
            visible_addresses.len(),
            frames.len(),
            "live generated visible address alias"
        );
        assert!(frames.iter().all(|frame| frame.token.generation != 0));
    }

    fn assert_distinct_cycles(frames: &[LiveFrame]) {
        let tokens: BTreeSet<_> = frames.iter().map(|frame| frame.token).collect();
        assert_eq!(tokens.len(), frames.len(), "duplicate ownership cycle");
        assert!(frames.iter().all(|frame| frame.token.generation != 0));
    }

    fn expected_map(frames: &[LiveFrame]) -> BTreeMap<BufferToken, LiveFrame> {
        frames.iter().map(|frame| (frame.token, *frame)).collect()
    }

    fn assert_event_bindings(expected: &[LiveFrame], events: &[GeneratedEvent]) {
        let expected = expected_map(expected);
        assert_eq!(events.len(), expected.len());
        let mut observed = BTreeSet::new();
        for event in events {
            assert!(
                observed.insert(event.frame.token),
                "duplicate generated event token"
            );
            assert_eq!(
                expected.get(&event.frame.token),
                Some(&event.frame),
                "generated terminal event changed or invented its lease-time binding"
            );
            assert_eq!(event.bytes.len(), event.frame.requested_len);
            if let GeneratedEventKind::TxSubmitted { descriptor_len, .. } = event.kind {
                assert_eq!(
                    descriptor_len, event.frame.requested_len,
                    "generated descriptor length differs from requested length"
                );
            }
        }
    }

    pub fn empty_session_has_zero_accounting<H: GeneratedHarness>() {
        let mut harness = H::new();
        let completion = {
            let (io, _) = harness.io_and_observer();
            io.begin_generated(WAN).finish()
        };
        assert!(completion.invariants_hold());
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
            (0, 0, 0, 0, 0, 0, 0, 0)
        );
        assert!(harness.drain_generated_events().is_empty());
    }

    pub fn allocation_failures_bind_only_successful_ownership<H: GeneratedHarness>() {
        let mut harness = H::new();
        harness.set_generated_max_frame(64);
        harness.set_generated_allocation_budget(1);
        let mut live = Vec::new();
        let completion = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = io.begin_generated(WAN);
            assert!(matches!(
                batch.allocate(0),
                Err(GeneratedAllocationError::ZeroLength)
            ));
            assert!(matches!(
                batch.allocate(65),
                Err(GeneratedAllocationError::FrameTooLarge)
            ));
            let mut valid = batch
                .allocate(64)
                .expect("invalid attempts consumed allocation budget");
            valid.bytes_mut().fill(7);
            let frame = observer.bind(valid.bytes_mut(), 64);
            live.push(frame);
            valid.cancel();
            assert!(matches!(
                batch.allocate(64),
                Err(GeneratedAllocationError::Unavailable)
            ));
            batch.finish()
        };
        assert!(completion.invariants_hold());
        assert_eq!(
            (
                completion.attempts,
                completion.allocated,
                completion.failed,
                completion.requested,
                completion.cancelled,
                completion.abandoned,
            ),
            (4, 1, 3, 0, 1, 0)
        );
        let events = harness.drain_generated_events();
        assert_event_bindings(&live, &events);
        assert_eq!(
            events[0].kind,
            GeneratedEventKind::Reclaimed(GeneratedReclaim::Cancelled)
        );
    }

    pub fn commit_cancel_and_abandon_bind_exact_lengths<H: GeneratedHarness>() {
        let mut harness = H::new();
        harness.set_generated_max_frame(64);
        harness.set_generated_allocation_budget(3);
        let endpoint = expected_endpoint(WAN);
        let mut live = Vec::new();
        let completion = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = io.begin_generated(WAN);
            for (marker, len, terminal) in [(1_u8, 60, 0_u8), (2, 61, 1), (3, 62, 2)] {
                let mut packet = batch.allocate(len).expect("generated allocation");
                assert_eq!(packet.bytes_mut().len(), len);
                packet.bytes_mut().fill(marker);
                let frame = observer.bind(packet.bytes_mut(), len);
                live.push(frame);
                match terminal {
                    0 => packet.commit(),
                    1 => packet.cancel(),
                    2 => drop(packet),
                    _ => unreachable!(),
                }
            }
            assert_distinct_cycles(&live);
            assert_ne!(
                live[0].token.frame_id, live[1].token.frame_id,
                "committed frame aliased a later live allocation"
            );
            assert_ne!(
                live[0].token.frame_id, live[2].token.frame_id,
                "committed frame aliased a later live allocation"
            );
            if live[1].token.frame_id == live[2].token.frame_id {
                assert!(
                    live[2].token.generation > live[1].token.generation,
                    "reused frame did not advance ownership generation"
                );
            }
            batch.finish()
        };
        assert!(completion.invariants_hold());
        assert_eq!(
            (
                completion.requested,
                completion.cancelled,
                completion.abandoned,
                completion.accepted,
                completion.rejected,
            ),
            (1, 1, 1, 1, 0)
        );
        let events = harness.drain_generated_events();
        assert_event_bindings(&live, &events);
        for event in events {
            let expected = match event.bytes[0] {
                1 => GeneratedEventKind::TxSubmitted {
                    endpoint,
                    descriptor_len: 60,
                },
                2 => GeneratedEventKind::Reclaimed(GeneratedReclaim::Cancelled),
                3 => GeneratedEventKind::Reclaimed(GeneratedReclaim::Abandoned),
                _ => panic!("unexpected generated marker"),
            };
            assert_eq!(event.kind, expected);
        }
    }

    pub fn partial_reject_reclaims_exact_tokens<H: GeneratedHarness>() {
        let mut harness = H::new();
        harness.set_generated_allocation_budget(3);
        harness.set_generated_accept_budget(1);
        let endpoint = expected_endpoint(WAN);
        let mut live = Vec::new();
        let completion = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = io.begin_generated(WAN);
            for marker in 1_u8..=3 {
                let mut packet = batch.allocate(60).expect("generated allocation");
                packet.bytes_mut().fill(marker);
                live.push(observer.bind(packet.bytes_mut(), 60));
                packet.commit();
            }
            assert_distinct_live(&live);
            batch.finish()
        };
        assert!(completion.invariants_hold());
        assert_eq!((completion.accepted, completion.rejected), (1, 2));
        let events = harness.drain_generated_events();
        assert_event_bindings(&live, &events);
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    event.kind
                        == GeneratedEventKind::TxSubmitted {
                            endpoint,
                            descriptor_len: event.frame.requested_len,
                        }
                })
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    event.kind
                        == GeneratedEventKind::TxRejected {
                            attempted_egress: WAN,
                            endpoint: Some(endpoint),
                        }
                })
                .count(),
            2
        );
    }

    pub fn sessions_bind_concrete_endpoints<H: GeneratedHarness>() {
        let mut harness = H::new();
        harness.set_generated_allocation_budget(1);
        let expected = [
            (LAN, expected_endpoint(LAN), 1_u8),
            (WAN, expected_endpoint(WAN), 2_u8),
        ];
        let mut live = Vec::new();
        for (egress, _, marker) in expected {
            let completion = {
                let (io, observer) = harness.io_and_observer();
                let mut batch = io.begin_generated(egress);
                let mut packet = batch.allocate(60).expect("generated allocation");
                packet.bytes_mut().fill(marker);
                live.push(observer.bind(packet.bytes_mut(), 60));
                packet.commit();
                batch.finish()
            };
            assert!(completion.invariants_hold());
            assert_eq!(completion.accepted, 1);
        }
        assert_distinct_live(&live);
        let events = harness.drain_generated_events();
        assert_event_bindings(&live, &events);
        for event in events {
            let (_, endpoint, _) = expected
                .iter()
                .find(|(_, _, marker)| *marker == event.bytes[0])
                .expect("known marker");
            assert_eq!(
                event.kind,
                GeneratedEventKind::TxSubmitted {
                    endpoint: *endpoint,
                    descriptor_len: 60,
                }
            );
        }
    }

    pub fn partial_reject_with_finish_error_is_exact<H: GeneratedFinishErrorHarness>() {
        let mut harness = H::new();
        harness.set_generated_allocation_budget(3);
        harness.set_generated_accept_budget(1);
        harness.fail_next_generated_finish();
        let mut live = Vec::new();
        let completion = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = io.begin_generated(WAN);
            for marker in 1_u8..=3 {
                let mut packet = batch.allocate(60).expect("generated allocation");
                packet.bytes_mut().fill(marker);
                live.push(observer.bind(packet.bytes_mut(), 60));
                packet.commit();
            }
            assert_distinct_live(&live);
            batch.finish()
        };
        assert!(completion.invariants_hold());
        assert_eq!((completion.accepted, completion.rejected), (1, 2));
        assert!(completion.error.is_some());
        assert_event_bindings(&live, &harness.drain_generated_events());
    }

    pub fn completion_advances_the_exact_submitted_token<H: GeneratedCompletionHarness>() {
        let mut harness = H::new();
        harness.set_generated_allocation_budget(1);
        let endpoint = expected_endpoint(WAN);
        let frame = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = io.begin_generated(WAN);
            let mut packet = batch.allocate(60).expect("generated allocation");
            packet.bytes_mut().fill(9);
            let frame = observer.bind(packet.bytes_mut(), 60);
            packet.commit();
            let completion = batch.finish();
            assert!(completion.invariants_hold());
            assert_eq!(completion.accepted, 1);
            frame
        };
        let events = harness.drain_generated_events();
        assert!(matches!(
            events[0].kind,
            GeneratedEventKind::TxSubmitted { .. }
        ));
        assert_eq!(
            harness.complete_generated_submissions(),
            [super::TxCompletion { frame, endpoint }]
        );
    }

    pub fn repeated_rejects_restore_physical_pool_and_advance_generation<
        H: GeneratedFinitePoolHarness,
    >() {
        let mut harness = H::new();
        harness.set_generated_allocation_budget(2);
        harness.set_generated_accept_budget(0);
        let baseline = harness.free_generated_frames();
        assert!(baseline >= 2);
        let mut last_generation = BTreeMap::<u64, u64>::new();
        for cycle in 0_u8..4 {
            let mut live = Vec::new();
            {
                let (io, observer) = harness.io_and_observer();
                let mut batch = io.begin_generated(WAN);
                for slot in 1_u8..=2 {
                    let mut packet = batch.allocate(60).expect("physical pool leaked");
                    packet.bytes_mut().fill(cycle * 2 + slot);
                    let frame = observer.bind(packet.bytes_mut(), 60);
                    if let Some(previous) =
                        last_generation.insert(frame.token.frame_id, frame.token.generation)
                    {
                        assert!(frame.token.generation > previous, "ABA generation reused");
                    }
                    live.push(frame);
                    packet.commit();
                }
                assert_distinct_live(&live);
                let completion = batch.finish();
                assert!(completion.invariants_hold());
                assert_eq!(completion.rejected, 2);
            }
            assert_eq!(
                harness.free_generated_frames(),
                baseline,
                "rejected frame was not returned to the physical pool"
            );
            let events = harness.drain_generated_events();
            assert_event_bindings(&live, &events);
        }
    }

    pub fn unknown_egress_is_rejected_without_submission<H: GeneratedUnknownEgressHarness>() {
        let mut harness = H::new();
        harness.set_generated_allocation_budget(1);
        let unknown = CONFORMANCE_UNKNOWN;
        let frame = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = io.begin_generated(unknown);
            let mut packet = batch.allocate(60).expect("generated allocation");
            packet.bytes_mut().fill(0xa1);
            let frame = observer.bind(packet.bytes_mut(), 60);
            packet.commit();
            let completion = batch.finish();
            assert!(completion.invariants_hold());
            assert_eq!((completion.accepted, completion.rejected), (0, 1));
            frame
        };
        let events = harness.drain_generated_events();
        assert_event_bindings(&[frame], &events);
        assert_eq!(
            events[0].kind,
            GeneratedEventKind::TxRejected {
                attempted_egress: unknown,
                endpoint: None,
            }
        );
    }

    pub fn cq_return_releases_same_generated_frame_with_new_generation<
        H: GeneratedCqPoolHarness,
    >() {
        let mut harness = H::new();
        harness.set_generated_allocation_budget(1);
        harness.set_generated_accept_budget(1);
        let baseline = harness.free_generated_frames();
        assert!(baseline >= 1);
        let first = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = io.begin_generated(WAN);
            let mut packet = batch.allocate(60).expect("generated allocation");
            packet.bytes_mut().fill(0xb1);
            let frame = observer.bind(packet.bytes_mut(), 60);
            packet.commit();
            let completion = batch.finish();
            assert!(completion.invariants_hold());
            assert_eq!(completion.accepted, 1);
            frame
        };
        let events = harness.drain_generated_events();
        assert_event_bindings(&[first], &events);
        assert_eq!(
            events[0].kind,
            GeneratedEventKind::TxSubmitted {
                endpoint: expected_endpoint(WAN),
                descriptor_len: first.requested_len,
            }
        );
        assert_eq!(
            harness.free_generated_frames() + 1,
            baseline,
            "submitted generated frame returned before CQ observation"
        );
        assert_eq!(
            harness.complete_generated_submissions(),
            [super::TxCompletion {
                frame: first,
                endpoint: expected_endpoint(WAN),
            }]
        );
        assert_eq!(
            harness.free_generated_frames(),
            baseline,
            "CQ-observed generated frame was not returned to the free pool"
        );

        harness.prefer_generated_frame(first.token.frame_id);
        harness.set_generated_allocation_budget(1);
        let second = {
            let (io, observer) = harness.io_and_observer();
            let mut batch = io.begin_generated(WAN);
            let mut packet = batch.allocate(60).expect("re-leased generated frame");
            packet.bytes_mut().fill(0xb2);
            let frame = observer.bind(packet.bytes_mut(), 60);
            packet.cancel();
            let completion = batch.finish();
            assert!(completion.invariants_hold());
            assert_eq!(completion.cancelled, 1);
            frame
        };
        assert_eq!(second.token.frame_id, first.token.frame_id);
        assert!(
            second.token.generation > first.token.generation,
            "CQ-returned generated frame reused a stale generation"
        );
        assert_eq!(harness.free_generated_frames(), baseline);
        let events = harness.drain_generated_events();
        assert_event_bindings(&[second], &events);
        assert_eq!(
            events[0].kind,
            GeneratedEventKind::Reclaimed(GeneratedReclaim::Cancelled)
        );
    }

    pub fn dropped_batch_accounts_generated_and_cannot_carry_to_next_egress<
        H: GeneratedCqPoolHarness,
    >() {
        let mut harness = H::new();
        harness.set_generated_allocation_budget(3);
        harness.set_generated_accept_budget(1);
        let baseline = harness.free_generated_frames();
        assert!(baseline >= 3);
        let mut live = Vec::new();
        {
            let (io, observer) = harness.io_and_observer();
            let mut batch = io.begin_generated(WAN);
            for (marker, terminal) in [(0xd1_u8, 0_u8), (0xd2, 1), (0xd3, 2)] {
                let mut packet = batch.allocate(60).expect("generated allocation");
                packet.bytes_mut().fill(marker);
                live.push(observer.bind(packet.bytes_mut(), 60));
                match terminal {
                    0 => packet.commit(),
                    1 => packet.cancel(),
                    2 => drop(packet),
                    _ => unreachable!(),
                }
            }
            drop(batch);
        }
        assert_distinct_cycles(&live);
        let events = harness.drain_generated_events();
        assert_event_bindings(&live, &events);
        let mut submitted = false;
        for event in events {
            let expected = match event.bytes[0] {
                0xd1 => match event.kind {
                    GeneratedEventKind::TxSubmitted {
                        endpoint,
                        descriptor_len,
                    } => {
                        assert_eq!(endpoint, expected_endpoint(WAN));
                        assert_eq!(descriptor_len, live[0].requested_len);
                        submitted = true;
                        continue;
                    }
                    GeneratedEventKind::TxRejected {
                        attempted_egress,
                        endpoint,
                    } => {
                        assert_eq!(attempted_egress, WAN);
                        assert_eq!(endpoint, Some(expected_endpoint(WAN)));
                        continue;
                    }
                    GeneratedEventKind::Reclaimed(_) => {
                        panic!("committed generated lease lost its TX disposition")
                    }
                },
                0xd2 => GeneratedEventKind::Reclaimed(GeneratedReclaim::Cancelled),
                0xd3 => GeneratedEventKind::Reclaimed(GeneratedReclaim::Abandoned),
                _ => panic!("unexpected generated marker"),
            };
            assert_eq!(event.kind, expected);
        }
        assert_eq!(
            harness.free_generated_frames() + usize::from(submitted),
            baseline,
            "generated batch drop lost a frame or returned an in-flight frame"
        );

        harness.set_generated_allocation_budget(0);
        let next = {
            let (io, _) = harness.io_and_observer();
            io.begin_generated(LAN).finish()
        };
        assert!(next.invariants_hold());
        assert_eq!(
            (
                next.attempts,
                next.allocated,
                next.failed,
                next.requested,
                next.cancelled,
                next.abandoned,
                next.accepted,
                next.rejected,
            ),
            (0, 0, 0, 0, 0, 0, 0, 0),
            "later egress inherited a dropped generated batch"
        );
        assert!(
            harness.drain_generated_events().is_empty(),
            "later egress published or reclaimed stale generated ownership"
        );

        let completions = harness.complete_generated_submissions();
        if submitted {
            assert_eq!(
                completions,
                [super::TxCompletion {
                    frame: live[0],
                    endpoint: expected_endpoint(WAN),
                }]
            );
        } else {
            assert!(completions.is_empty());
        }
        assert_eq!(
            harness.free_generated_frames(),
            baseline,
            "batch-drop lifecycle did not restore the generated physical pool"
        );
    }
}

pub mod differential;
pub mod differential_live;
pub mod rx_copy;

#[cfg(test)]
mod copy_fake_tests;
#[cfg(test)]
mod finite_fake_tests;
