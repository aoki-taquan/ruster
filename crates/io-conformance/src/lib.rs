#![forbid(unsafe_code)]
#![doc = "Reusable, deterministic conformance cases for ruster packet I/O backends."]

use ruster_core::{ConsumeReason, DropReason, GeneratedPacketIo, IfId, PacketIo};

/// Stable identity for one backend-owned buffer during an ownership cycle.
///
/// A backend may reuse the value only after the corresponding frame has been
/// reclaimed. AF_XDP harnesses should derive it from the UMEM frame index or
/// address, rather than packet contents.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BufferToken(u64);

impl BufferToken {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Identity returned when a test frame enters an RX backend-owned buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InjectedFrame {
    pub token: BufferToken,
    pub allocation_address: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxDisposition {
    Accepted { egress: IfId },
    Recycled { reason: DropReason },
    Consumed { reason: ConsumeReason },
    Abandoned,
    Rejected,
}

/// One terminal RX-buffer observation, moved out of the backend test adapter.
#[derive(Debug, Eq, PartialEq)]
pub struct RxOutcome {
    pub token: BufferToken,
    pub allocation_address: usize,
    pub ingress: IfId,
    pub bytes: Vec<u8>,
    pub disposition: RxDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedDisposition {
    Accepted,
    Cancelled,
    Abandoned,
    Rejected,
}

/// One terminal generated-buffer observation.
#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedOutcome {
    pub token: BufferToken,
    pub allocation_address: usize,
    pub egress: IfId,
    pub bytes: Vec<u8>,
    pub disposition: GeneratedDisposition,
}

/// Test-only control and observation boundary for mandatory RX behavior.
///
/// The associated I/O object remains concrete, so conformance cases use
/// static dispatch and never place a trait object in the packet path.
pub trait RxHarness: Sized {
    type Io: PacketIo;

    fn new() -> Self;
    fn io(&mut self) -> &mut Self::Io;
    fn inject_rx(&mut self, ingress: IfId, bytes: Vec<u8>) -> InjectedFrame;
    fn set_rx_accept_budget(&mut self, budget: usize);
    fn pending_rx(&self) -> usize;
    fn drain_rx_outcomes(&mut self) -> Vec<RxOutcome>;
}

/// Optional RX receive-error fault injection.
pub trait RxReceiveErrorHarness: RxHarness {
    fn fail_next_receive(&mut self);
}

/// Optional RX finish-error fault injection.
pub trait RxFinishErrorHarness: RxHarness {
    fn fail_next_rx_finish(&mut self);
}

/// Test-only control and observation boundary for generated TX behavior.
pub trait GeneratedHarness: Sized {
    type Io: GeneratedPacketIo;

    fn new() -> Self;
    fn io(&mut self) -> &mut Self::Io;
    fn set_generated_allocation_budget(&mut self, budget: usize);
    fn set_generated_max_frame(&mut self, max_frame: usize);
    fn set_generated_accept_budget(&mut self, budget: usize);
    fn drain_generated_outcomes(&mut self) -> Vec<GeneratedOutcome>;
}

/// Optional generated finish-error fault injection.
pub trait GeneratedFinishErrorHarness: GeneratedHarness {
    fn fail_next_generated_finish(&mut self);
}

pub mod rx {
    use std::collections::{BTreeMap, BTreeSet};

    use ruster_core::{ConsumeReason, DropReason, IfId, PacketBatch, PacketIo};

    use super::{
        BufferToken, InjectedFrame, RxDisposition, RxFinishErrorHarness, RxHarness, RxOutcome,
        RxReceiveErrorHarness,
    };

    const LAN: IfId = IfId(11);
    const WAN: IfId = IfId(22);

    fn receive<H: RxHarness>(harness: &mut H, budget: usize) -> <H::Io as PacketIo>::Batch<'_> {
        match harness.io().receive(budget) {
            Ok(batch) => batch,
            Err(_) => panic!("RX conformance setup unexpectedly failed receive"),
        }
    }

    fn injected_map(frames: &[InjectedFrame]) -> BTreeMap<BufferToken, usize> {
        frames
            .iter()
            .map(|frame| (frame.token, frame.allocation_address))
            .collect()
    }

    fn assert_exact_rx_ownership(expected: &[InjectedFrame], outcomes: &[RxOutcome]) {
        let expected = injected_map(expected);
        assert_eq!(outcomes.len(), expected.len());
        let mut observed = BTreeSet::new();
        for outcome in outcomes {
            assert!(
                observed.insert(outcome.token),
                "duplicate RX terminal token"
            );
            assert_eq!(
                expected.get(&outcome.token),
                Some(&outcome.allocation_address),
                "RX allocation identity changed or an unknown token appeared"
            );
        }
        assert_eq!(
            observed,
            expected.keys().copied().collect(),
            "RX token was lost"
        );
    }

    pub fn budget_and_unleased_slots_are_exact<H: RxHarness>() {
        let mut harness = H::new();
        let injected = [
            harness.inject_rx(LAN, vec![1, 0xa1]),
            harness.inject_rx(LAN, vec![2, 0xa2]),
            harness.inject_rx(LAN, vec![3, 0xa3]),
        ];

        let completion = {
            let mut batch = receive(&mut harness, 0);
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

        let completion = {
            let mut batch = receive(&mut harness, 2);
            let mut leased = 0;
            while let Some(packet) = batch.next_packet() {
                packet.recycle(DropReason::RouteMiss);
                leased += 1;
            }
            assert_eq!(leased, 2);
            batch.finish()
        };
        assert_eq!(completion.recycled, 2);
        assert_eq!(harness.pending_rx(), 1);

        let completion = {
            let mut batch = receive(&mut harness, usize::MAX);
            let packet = batch.next_packet().expect("unleased RX slot");
            packet.recycle(DropReason::RouteMiss);
            assert!(batch.next_packet().is_none());
            batch.finish()
        };
        assert_eq!(completion.recycled, 1);
        assert_eq!(harness.pending_rx(), 0);

        let outcomes = harness.drain_rx_outcomes();
        assert_exact_rx_ownership(&injected, &outcomes);
        assert!(outcomes.iter().all(|outcome| {
            outcome.disposition
                == RxDisposition::Recycled {
                    reason: DropReason::RouteMiss,
                }
        }));
    }

    pub fn commit_is_in_place_and_egress_typed<H: RxHarness>() {
        let mut harness = H::new();
        let injected = harness.inject_rx(LAN, vec![0x10, 0x20, 0x30]);
        let completion = {
            let mut batch = receive(&mut harness, 1);
            let mut packet = batch.next_packet().expect("one RX lease");
            assert_eq!(packet.ingress(), LAN);
            let bytes = packet.bytes_mut();
            assert_eq!(bytes.as_ptr() as usize, injected.allocation_address);
            bytes[1] = 0x99;
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
        let outcomes = harness.drain_rx_outcomes();
        assert_exact_rx_ownership(&[injected], &outcomes);
        assert_eq!(outcomes[0].bytes, [0x10, 0x99, 0x30]);
        assert_eq!(
            outcomes[0].disposition,
            RxDisposition::Accepted { egress: WAN }
        );
    }

    pub fn recycle_consume_and_abandon_are_distinct<H: RxHarness>() {
        let mut harness = H::new();
        let injected = [
            harness.inject_rx(LAN, vec![1, 0x11]),
            harness.inject_rx(LAN, vec![2, 0x22]),
            harness.inject_rx(LAN, vec![3, 0x33]),
        ];
        let completion = {
            let mut batch = receive(&mut harness, 3);
            while let Some(mut packet) = batch.next_packet() {
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
        assert_eq!(
            (
                completion.tx_requested,
                completion.tx_accepted,
                completion.tx_rejected,
                completion.recycled,
            ),
            (0, 0, 0, 3)
        );

        let outcomes = harness.drain_rx_outcomes();
        assert_exact_rx_ownership(&injected, &outcomes);
        for outcome in outcomes {
            let expected = match outcome.bytes[0] {
                1 => RxDisposition::Recycled {
                    reason: DropReason::NeighborUnresolved,
                },
                2 => RxDisposition::Consumed {
                    reason: ConsumeReason::ArpControl,
                },
                3 => RxDisposition::Abandoned,
                _ => panic!("unexpected RX marker"),
            };
            assert_eq!(outcome.disposition, expected);
        }
    }

    pub fn partial_reject_reclaims_exactly_before_finish_returns<H: RxHarness>() {
        let mut harness = H::new();
        harness.set_rx_accept_budget(1);
        let injected = [
            harness.inject_rx(LAN, vec![1, 0x41]),
            harness.inject_rx(LAN, vec![2, 0x42]),
            harness.inject_rx(LAN, vec![3, 0x43]),
        ];
        let completion = {
            let mut batch = receive(&mut harness, 3);
            while let Some(packet) = batch.next_packet() {
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

        let outcomes = harness.drain_rx_outcomes();
        assert_exact_rx_ownership(&injected, &outcomes);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome.disposition, RxDisposition::Accepted { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.disposition == RxDisposition::Rejected)
                .count(),
            2
        );
    }

    pub fn repeated_reject_cycles_conserve_rx_ownership<H: RxHarness>() {
        let mut harness = H::new();
        harness.set_rx_accept_budget(0);
        for cycle in 0_u8..4 {
            let injected = [
                harness.inject_rx(LAN, vec![cycle, 1]),
                harness.inject_rx(LAN, vec![cycle, 2]),
            ];
            let completion = {
                let mut batch = receive(&mut harness, 2);
                while let Some(packet) = batch.next_packet() {
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
                (2, 0, 2, 0)
            );
            let outcomes = harness.drain_rx_outcomes();
            assert_exact_rx_ownership(&injected, &outcomes);
            assert!(outcomes
                .iter()
                .all(|outcome| outcome.disposition == RxDisposition::Rejected));
        }
    }

    pub fn receive_error_preserves_queued_ownership<H: RxReceiveErrorHarness>() {
        let mut harness = H::new();
        let injected = harness.inject_rx(LAN, vec![0x51, 0x52]);
        harness.fail_next_receive();
        assert!(harness.io().receive(1).is_err());
        assert_eq!(harness.pending_rx(), 1);

        let completion = {
            let mut batch = receive(&mut harness, 1);
            batch
                .next_packet()
                .expect("RX slot survives receive error")
                .recycle(DropReason::RouteMiss);
            batch.finish()
        };
        assert_eq!(completion.recycled, 1);
        let outcomes = harness.drain_rx_outcomes();
        assert_exact_rx_ownership(&[injected], &outcomes);
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
            let mut batch = receive(&mut harness, 3);
            while let Some(packet) = batch.next_packet() {
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
        assert!(completion.error.is_some());
        let outcomes = harness.drain_rx_outcomes();
        assert_exact_rx_ownership(&injected, &outcomes);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.disposition == RxDisposition::Rejected)
                .count(),
            2
        );
    }
}

pub mod generated {
    use std::collections::{BTreeMap, BTreeSet};

    use ruster_core::{GeneratedAllocationError, GeneratedPacketBatch, GeneratedPacketIo, IfId};

    use super::{
        GeneratedDisposition, GeneratedFinishErrorHarness, GeneratedHarness, GeneratedOutcome,
    };

    const LAN: IfId = IfId(11);
    const WAN: IfId = IfId(22);

    fn assert_exact_generated_ownership(
        expected_addresses: &BTreeMap<u8, usize>,
        outcomes: &[GeneratedOutcome],
    ) {
        assert_eq!(outcomes.len(), expected_addresses.len());
        let mut tokens = BTreeSet::new();
        for outcome in outcomes {
            assert!(
                tokens.insert(outcome.token),
                "duplicate generated terminal token"
            );
            let marker = outcome.bytes[0];
            assert_eq!(
                expected_addresses.get(&marker),
                Some(&outcome.allocation_address),
                "generated allocation identity changed"
            );
        }
    }

    pub fn empty_session_has_zero_accounting<H: GeneratedHarness>() {
        let mut harness = H::new();
        let completion = harness.io().begin_generated(WAN).finish();
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
        assert!(completion.error.is_none());
        assert!(harness.drain_generated_outcomes().is_empty());
    }

    pub fn allocation_failures_are_typed_and_transfer_no_ownership<H: GeneratedHarness>() {
        let mut harness = H::new();
        harness.set_generated_max_frame(64);
        harness.set_generated_allocation_budget(1);
        let mut addresses = BTreeMap::new();
        let completion = {
            let mut batch = harness.io().begin_generated(WAN);
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
                .expect("invalid requests must not consume allocation budget");
            valid.bytes_mut().fill(7);
            addresses.insert(7, valid.bytes_mut().as_ptr() as usize);
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
                completion.accepted,
                completion.rejected,
            ),
            (4, 1, 3, 0, 1, 0, 0, 0)
        );
        let outcomes = harness.drain_generated_outcomes();
        assert_exact_generated_ownership(&addresses, &outcomes);
        assert_eq!(outcomes[0].disposition, GeneratedDisposition::Cancelled);
    }

    pub fn commit_cancel_and_abandon_are_exact_length_and_distinct<H: GeneratedHarness>() {
        let mut harness = H::new();
        harness.set_generated_max_frame(64);
        harness.set_generated_allocation_budget(3);
        let mut addresses = BTreeMap::new();
        let completion = {
            let mut batch = harness.io().begin_generated(WAN);

            let mut committed = batch.allocate(60).expect("generated commit allocation");
            assert_eq!(committed.bytes_mut().len(), 60);
            committed.bytes_mut().fill(0);
            committed.bytes_mut()[0] = 1;
            addresses.insert(1, committed.bytes_mut().as_ptr() as usize);
            committed.commit();

            let mut cancelled = batch.allocate(61).expect("generated cancel allocation");
            assert_eq!(cancelled.bytes_mut().len(), 61);
            cancelled.bytes_mut().fill(0);
            cancelled.bytes_mut()[0] = 2;
            addresses.insert(2, cancelled.bytes_mut().as_ptr() as usize);
            cancelled.cancel();

            let mut abandoned = batch.allocate(62).expect("generated abandon allocation");
            assert_eq!(abandoned.bytes_mut().len(), 62);
            abandoned.bytes_mut().fill(0);
            abandoned.bytes_mut()[0] = 3;
            addresses.insert(3, abandoned.bytes_mut().as_ptr() as usize);
            drop(abandoned);

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
                completion.accepted,
                completion.rejected,
            ),
            (3, 3, 0, 1, 1, 1, 1, 0)
        );

        let outcomes = harness.drain_generated_outcomes();
        assert_exact_generated_ownership(&addresses, &outcomes);
        for outcome in outcomes {
            let expected = match outcome.bytes[0] {
                1 => GeneratedDisposition::Accepted,
                2 => GeneratedDisposition::Cancelled,
                3 => GeneratedDisposition::Abandoned,
                _ => panic!("unexpected generated marker"),
            };
            assert_eq!(outcome.disposition, expected);
            assert_eq!(outcome.egress, WAN);
        }
    }

    pub fn partial_reject_reclaims_exactly_before_finish_returns<H: GeneratedHarness>() {
        let mut harness = H::new();
        harness.set_generated_allocation_budget(3);
        harness.set_generated_accept_budget(1);
        let mut addresses = BTreeMap::new();
        let completion = {
            let mut batch = harness.io().begin_generated(WAN);
            for marker in 1_u8..=3 {
                let mut packet = batch.allocate(60).expect("generated allocation");
                packet.bytes_mut().fill(marker);
                addresses.insert(marker, packet.bytes_mut().as_ptr() as usize);
                packet.commit();
            }
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
                completion.accepted,
                completion.rejected,
            ),
            (3, 3, 0, 3, 0, 0, 1, 2)
        );
        let outcomes = harness.drain_generated_outcomes();
        assert_exact_generated_ownership(&addresses, &outcomes);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.disposition == GeneratedDisposition::Accepted)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.disposition == GeneratedDisposition::Rejected)
                .count(),
            2
        );
    }

    pub fn sessions_pin_egress_without_cross_talk<H: GeneratedHarness>() {
        let mut harness = H::new();
        harness.set_generated_allocation_budget(1);
        for (egress, marker) in [(LAN, 1_u8), (WAN, 2_u8)] {
            let completion = {
                let mut batch = harness.io().begin_generated(egress);
                let mut packet = batch.allocate(60).expect("generated allocation");
                packet.bytes_mut().fill(marker);
                packet.commit();
                batch.finish()
            };
            assert_eq!(completion.accepted, 1);
        }
        let outcomes = harness.drain_generated_outcomes();
        assert_eq!(outcomes.len(), 2);
        for outcome in outcomes {
            let expected = match outcome.bytes[0] {
                1 => LAN,
                2 => WAN,
                _ => panic!("unexpected generated marker"),
            };
            assert_eq!(outcome.egress, expected);
            assert_eq!(outcome.disposition, GeneratedDisposition::Accepted);
        }
    }

    pub fn repeated_reject_cycles_conserve_generated_pool<H: GeneratedHarness>() {
        let mut harness = H::new();
        harness.set_generated_allocation_budget(2);
        harness.set_generated_accept_budget(0);
        for cycle in 0_u8..4 {
            let mut addresses = BTreeMap::new();
            let completion = {
                let mut batch = harness.io().begin_generated(WAN);
                for slot in 1_u8..=2 {
                    let marker = cycle * 2 + slot;
                    let mut packet = batch.allocate(60).expect("pool capacity leaked");
                    packet.bytes_mut().fill(marker);
                    addresses.insert(marker, packet.bytes_mut().as_ptr() as usize);
                    packet.commit();
                }
                batch.finish()
            };
            assert!(completion.invariants_hold());
            assert_eq!(
                (
                    completion.attempts,
                    completion.allocated,
                    completion.failed,
                    completion.requested,
                    completion.accepted,
                    completion.rejected,
                ),
                (2, 2, 0, 2, 0, 2)
            );
            let outcomes = harness.drain_generated_outcomes();
            assert_exact_generated_ownership(&addresses, &outcomes);
            assert!(outcomes
                .iter()
                .all(|outcome| outcome.disposition == GeneratedDisposition::Rejected));
        }
    }

    pub fn partial_reject_with_finish_error_is_exact<H: GeneratedFinishErrorHarness>() {
        let mut harness = H::new();
        harness.set_generated_allocation_budget(3);
        harness.set_generated_accept_budget(1);
        harness.fail_next_generated_finish();
        let mut addresses = BTreeMap::new();
        let completion = {
            let mut batch = harness.io().begin_generated(WAN);
            for marker in 1_u8..=3 {
                let mut packet = batch.allocate(60).expect("generated allocation");
                packet.bytes_mut().fill(marker);
                addresses.insert(marker, packet.bytes_mut().as_ptr() as usize);
                packet.commit();
            }
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
                completion.accepted,
                completion.rejected,
            ),
            (3, 3, 0, 3, 0, 0, 1, 2)
        );
        assert!(completion.error.is_some());
        let outcomes = harness.drain_generated_outcomes();
        assert_exact_generated_ownership(&addresses, &outcomes);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.disposition == GeneratedDisposition::Rejected)
                .count(),
            2
        );
    }
}
