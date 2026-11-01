//! The once-per-session datapath bundle consumed by the engine.
//!
//! The frame ledger of [`crate::RxFillEngine`] assumes that it is the only
//! party that ever published to this UMEM's Fill ring and the only one that
//! can submit TX descriptors naming its frames. That premise holds only if
//! the engine receives all five datapath resources of one session (Fill,
//! Completion, RX, TX, UMEM) together, before anyone else used them, and
//! exactly once per socket lifetime. [`DatapathRings`] is that bundle: it
//! has no public constructor and no way to replace or extract a member, so
//! views of different sessions, heap views, and views that already
//! published frames cannot be mixed into an engine.
//!
//! ```compile_fail,E0451
//! // A bundle cannot be assembled from independently obtained views.
//! fn assemble<'m>(
//!     fill: ruster_io_xdp_native::FillProducer<'m>,
//!     rx: ruster_io_xdp_native::RxConsumer<'m>,
//!     tx: ruster_io_xdp_native::TxProducer<'m>,
//!     completion: ruster_io_xdp_native::CompletionConsumer<'m>,
//! ) -> ruster_io_xdp_native::DatapathRings<'m> {
//!     ruster_io_xdp_native::DatapathRings { fill, rx, tx, completion }
//! }
//! ```
//!
//! ```compile_fail,E0616
//! // A member cannot be swapped for a view of another session or heap.
//! fn swap<'m>(
//!     mut bundle: ruster_io_xdp_native::DatapathRings<'m>,
//!     foreign: ruster_io_xdp_native::FillProducer<'m>,
//! ) -> ruster_io_xdp_native::DatapathRings<'m> {
//!     bundle.fill = foreign;
//!     bundle
//! }
//! ```

use std::{error::Error, fmt};

use crate::{
    native_unsafe::{kick::SocketKick, umem::UmemMapping},
    CompletionConsumer, FillProducer, RingMapError, RxConsumer, TxProducer, UmemConfig,
};

/// All datapath resources of one session, taken once.
///
/// Obtained only from `NativeSession::take_datapath` (or, in this crate's
/// tests, from the scripted heap kernel as one bundle) and consumed whole by
/// [`crate::RxFillEngine::new`]. Besides the four rings and the UMEM it
/// carries the socket's kick handle: a shared borrow of the session's
/// socket that can only `sendto` (TX wakeup) and `poll` (Fill wakeup), so
/// the engine can answer `XDP_RING_NEED_WAKEUP` while the bundle keeps the
/// session borrowed.
pub struct DatapathRings<'session> {
    fill: FillProducer<'session>,
    completion: CompletionConsumer<'session>,
    rx: RxConsumer<'session>,
    tx: TxProducer<'session>,
    umem: UmemMapping<'session>,
    umem_config: UmemConfig,
    kick: SocketKick<'session>,
    origin: u64,
}

/// Source of process-unique datapath origins (cold: one per session open or
/// test kernel).
static NEXT_ORIGIN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// A fresh nonzero origin identity for one session's datapath.
pub(crate) fn next_origin() -> u64 {
    let id = NEXT_ORIGIN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    assert_ne!(id, 0, "datapath origins exhausted");
    id
}

/// The members of one bundle, moved into the engine together.
pub(crate) struct DatapathParts<'session> {
    pub(crate) fill: FillProducer<'session>,
    pub(crate) completion: CompletionConsumer<'session>,
    pub(crate) rx: RxConsumer<'session>,
    pub(crate) tx: TxProducer<'session>,
    pub(crate) umem: UmemMapping<'session>,
    pub(crate) umem_config: UmemConfig,
    pub(crate) kick: SocketKick<'session>,
    /// The session (or test kernel) the bundle came from.
    pub(crate) origin: u64,
}

impl<'session> DatapathRings<'session> {
    #[cfg_attr(
        not(any(
            test,
            all(
                target_os = "linux",
                target_arch = "x86_64",
                target_pointer_width = "64"
            )
        )),
        allow(dead_code)
    )]
    pub(crate) const fn new(parts: DatapathParts<'session>) -> Self {
        let DatapathParts {
            fill,
            completion,
            rx,
            tx,
            umem,
            umem_config,
            kick,
            origin,
        } = parts;
        Self {
            fill,
            completion,
            rx,
            tx,
            umem,
            umem_config,
            kick,
            origin,
        }
    }

    pub(crate) fn into_parts(self) -> DatapathParts<'session> {
        let Self {
            fill,
            completion,
            rx,
            tx,
            umem,
            umem_config,
            kick,
            origin,
        } = self;
        DatapathParts {
            fill,
            completion,
            rx,
            tx,
            umem,
            umem_config,
            kick,
            origin,
        }
    }

    /// Returns the registered UMEM geometry.
    #[must_use]
    pub const fn umem_config(&self) -> UmemConfig {
        self.umem_config
    }

    /// Returns the Fill, RX, TX, and Completion capacities, in that order.
    #[must_use]
    pub const fn capacities(&self) -> [u32; 4] {
        [
            self.fill.capacity(),
            self.rx.capacity(),
            self.tx.capacity(),
            self.completion.capacity(),
        ]
    }
}

impl fmt::Debug for DatapathRings<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatapathRings")
            .field("capacities", &self.capacities())
            .field("umem", &self.umem)
            .field("umem_config", &self.umem_config)
            .finish()
    }
}

/// Why the datapath bundle cannot be taken.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatapathError {
    /// The bundle was already taken from this session. Building another
    /// engine requires closing the session and opening a new socket: the
    /// kernel or driver may still hold frames the first engine published.
    AlreadyTaken,
    /// Raw ring views were lent by `NativeSession::rings`, so frames may
    /// already have been published that no engine ledger tracks.
    RawRingsLent,
    /// A ring view could not be bound to its mapping.
    Map(RingMapError),
}

impl fmt::Display for DatapathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for DatapathError {}

/// Why raw ring views cannot be lent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingsError {
    /// The datapath bundle was taken; raw views would alias the engine.
    DatapathTaken,
    /// A ring view could not be bound to its mapping.
    Map(RingMapError),
}

impl fmt::Display for RingsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RingsError {}
