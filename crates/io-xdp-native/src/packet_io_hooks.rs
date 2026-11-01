//! Test-only instrumentation of the core adapter.
//!
//! The conformance harnesses need terminal events that no ring shows: why
//! an RX frame was reclaimed (recycle, consume, abandon), and which commits
//! were refused before a descriptor existed. When a harness installs a
//! journal, the adapter records those events with a byte snapshot. TX
//! submissions are never journaled: harnesses read them from the scripted
//! kernels' TX rings. Without a journal (every other test) nothing is
//! recorded or allocated.
//!
//! The generated allocation budget emulates the harnesses' per-session
//! allocation limit: once spent, `allocate` returns `Unavailable` exactly
//! as for an empty generated pool, before the engine is asked.

use std::{cell::RefCell, rc::Rc};

use ruster_core::{GeneratedSlotCompletion, IfId, SlotCompletion};

use super::XdpPacketIo;
use crate::{rx_fill::RawLease, RxFillEngine};

#[derive(Default)]
pub(crate) struct TestHooks {
    pub(crate) journal: Option<Rc<RefCell<Journal>>>,
    pub(crate) generated_allocation_budget: Option<usize>,
}

/// How a forwarded RX lease ended without a TX descriptor.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RxEnd {
    /// Refused for `attempted`; the port index of the egress, if known.
    Rejected(IfId, Option<usize>),
    Reclaimed(SlotCompletion),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EventKind {
    RxReclaimed(SlotCompletion),
    RxRejected {
        attempted: IfId,
        port: Option<usize>,
    },
    GeneratedAllocated,
    GeneratedRejected {
        port: usize,
    },
    GeneratedEnded(GeneratedSlotCompletion),
}

#[derive(Clone, Debug)]
pub(crate) struct Snapshot {
    pub(crate) port: usize,
    /// Address of the first visible byte, as the slot lent it.
    pub(crate) address: usize,
    pub(crate) frame: u32,
    pub(crate) generation: u64,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct JournalEvent {
    pub(crate) snapshot: Snapshot,
    pub(crate) kind: EventKind,
}

#[derive(Default, Debug)]
pub(crate) struct Journal {
    pub(crate) events: Vec<JournalEvent>,
}

impl<'memory> XdpPacketIo<'memory> {
    pub(crate) fn install_journal(&mut self, journal: Rc<RefCell<Journal>>) {
        self.test.journal = Some(journal);
    }

    pub(crate) fn set_generated_allocation_budget(&mut self, budget: Option<usize>) {
        self.test.generated_allocation_budget = budget;
    }

    pub(crate) fn engine_mut_for_test(&mut self, interface: IfId) -> &mut RxFillEngine<'memory> {
        let index = self.port_index(interface).expect("known port");
        &mut self.ports[index].engine
    }

    fn snapshot(&self, port: usize, lease: &RawLease) -> Option<Snapshot> {
        self.test.journal.as_ref()?;
        let bytes = self.ports[port].engine.lease_bytes(lease);
        let token = lease.token();
        Some(Snapshot {
            port,
            address: bytes.as_ptr().addr(),
            frame: token.frame().index(),
            generation: token.generation().get(),
            bytes: bytes.to_vec(),
        })
    }

    fn record(&self, snapshot: Option<Snapshot>, kind: EventKind) {
        if let (Some(journal), Some(snapshot)) = (self.test.journal.as_ref(), snapshot) {
            journal
                .borrow_mut()
                .events
                .push(JournalEvent { snapshot, kind });
        }
    }

    pub(super) fn test_rx_event(&self, port: usize, lease: &RawLease, end: RxEnd) {
        let kind = match end {
            RxEnd::Rejected(attempted, port) => EventKind::RxRejected { attempted, port },
            RxEnd::Reclaimed(completion) => EventKind::RxReclaimed(completion),
        };
        self.record(self.snapshot(port, lease), kind);
    }

    pub(super) fn test_rx_snapshot(&self, port: usize, lease: &RawLease) -> Option<Snapshot> {
        self.snapshot(port, lease)
    }

    pub(super) fn test_rx_rejected(
        &self,
        _port: usize,
        snapshot: Option<Snapshot>,
        attempted: IfId,
        egress: Option<usize>,
    ) {
        self.record(
            snapshot,
            EventKind::RxRejected {
                attempted,
                port: egress,
            },
        );
    }

    pub(super) fn test_generated_allocated(&self, port: usize, lease: &RawLease) {
        self.record(self.snapshot(port, lease), EventKind::GeneratedAllocated);
    }

    pub(super) fn test_generated_snapshot(
        &self,
        port: usize,
        lease: &RawLease,
    ) -> Option<Snapshot> {
        self.snapshot(port, lease)
    }

    pub(super) fn test_generated_rejected(&self, snapshot: Option<Snapshot>) {
        let port = snapshot.as_ref().map_or(0, |snapshot| snapshot.port);
        self.record(snapshot, EventKind::GeneratedRejected { port });
    }

    pub(super) fn test_generated_ended(
        &self,
        snapshot: Option<Snapshot>,
        completion: GeneratedSlotCompletion,
    ) {
        self.record(snapshot, EventKind::GeneratedEnded(completion));
    }
}
