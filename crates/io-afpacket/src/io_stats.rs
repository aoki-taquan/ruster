//! Fixed-shape live counters of the AF_PACKET backend (AP3, OBS-028).
//!
//! Every counter is a saturating `u64` maintained in O(1) at the event that
//! it counts; reading the stats never scans a ring. The kernel's
//! `PACKET_STATISTICS` are not read on the packet path: the kernel resets
//! them on every read, so they are folded into the cumulative `kernel_*`
//! counters only by an explicit cold refresh (`AfPacketIo::refresh_kernel_stats`).

use ruster_core::{FieldValue, FieldVisitor, IfId, ObservableFields};

use crate::BackendStatsSnapshot;

/// Cumulative counters of one port, or the sum over every port.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AfPacketCounters {
    /// RX packets lent to core.
    pub rx_packets: u64,
    /// RX packets that failed local validation and were never lent.
    pub rx_packet_faults: u64,
    /// RX blocks returned unexposed because their header or chain was unsafe.
    pub rx_block_faults: u64,
    /// RX blocks handed back to the kernel.
    pub rx_blocks_returned: u64,
    /// TX frames published as SEND_REQUEST (copied and generated).
    pub tx_published: u64,
    /// Of those, frames copied from an RX lease.
    pub tx_copies: u64,
    /// Published frames the kernel handed back (AVAILABLE or WRONG_FORMAT).
    pub tx_completed: u64,
    /// Of those, frames the kernel marked WRONG_FORMAT.
    pub tx_wrong_format: u64,
    /// TX requests rejected because the producer head was not free.
    pub tx_ring_full: u64,
    /// TX requests rejected above the configured maximum frame length.
    pub tx_oversize: u64,
    /// TX requests rejected by a backend fault (invariant violation).
    pub tx_faults: u64,
    /// Highest number of frames in flight at once.
    pub tx_inflight_high_water: u64,
    /// Successful nonblocking `send` kicks.
    pub kicks: u64,
    /// Kicks the kernel deferred (`EAGAIN`, `ENOBUFS`, `EINTR`, `EBUSY`).
    pub kicks_deferred: u64,
    /// Kicks refused because the link is down (`ENETDOWN`, `ENXIO`).
    pub kicks_link_down: u64,
    /// Kicks that failed with any other errno.
    pub kick_errors: u64,
    /// Retry kicks of an owed port (after a failed kick or a frame the
    /// kernel left SEND_REQUEST).
    pub kick_retries: u64,
    /// Settles that left an owed retry for later because of the backoff.
    pub kick_retries_suppressed: u64,
    /// Generated frames lent to core.
    pub generated_allocated: u64,
    /// Generated allocations refused because the TX ring was full.
    pub generated_unavailable: u64,
    /// Generated allocations refused for their length.
    pub generated_rejected: u64,
    /// Generated frames published.
    pub generated_committed: u64,
    /// Generated frames cancelled before publication.
    pub generated_cancelled: u64,
    /// Generated leases dropped without a terminal action.
    pub generated_abandoned: u64,
    /// Kernel `tp_packets`: frames the socket received (accumulated).
    pub kernel_packets: u64,
    /// Kernel `tp_drops`: frames dropped because the RX ring was full.
    pub kernel_drops: u64,
    /// Kernel `tp_freeze_q_cnt`: times the RX ring froze (no free block).
    pub kernel_freeze_q: u64,
    /// Failed `PACKET_STATISTICS` reads.
    pub kernel_stats_errors: u64,
}

impl AfPacketCounters {
    /// Field-wise saturating sum; the high-water mark takes the maximum.
    pub(crate) fn accumulate(&mut self, other: &Self) {
        macro_rules! add {
            ($($field:ident),* $(,)?) => {
                $(self.$field = self.$field.saturating_add(other.$field);)*
            };
        }
        add!(
            rx_packets,
            rx_packet_faults,
            rx_block_faults,
            rx_blocks_returned,
            tx_published,
            tx_copies,
            tx_completed,
            tx_wrong_format,
            tx_ring_full,
            tx_oversize,
            tx_faults,
            kicks,
            kicks_deferred,
            kicks_link_down,
            kick_errors,
            kick_retries,
            kick_retries_suppressed,
            generated_allocated,
            generated_unavailable,
            generated_rejected,
            generated_committed,
            generated_cancelled,
            generated_abandoned,
            kernel_packets,
            kernel_drops,
            kernel_freeze_q,
            kernel_stats_errors,
        );
        self.tx_inflight_high_water = self
            .tx_inflight_high_water
            .max(other.tx_inflight_high_water);
    }

    fn visit<V: FieldVisitor>(&self, section: &'static str, visitor: &mut V) {
        macro_rules! visit {
            ($($field:ident),* $(,)?) => {
                $(visitor.field(section, stringify!($field), FieldValue::Count(self.$field));)*
            };
        }
        visit!(
            rx_packets,
            rx_packet_faults,
            rx_block_faults,
            rx_blocks_returned,
            tx_published,
            tx_copies,
            tx_completed,
            tx_wrong_format,
            tx_ring_full,
            tx_oversize,
            tx_faults,
            tx_inflight_high_water,
            kicks,
            kicks_deferred,
            kicks_link_down,
            kick_errors,
            kick_retries,
            kick_retries_suppressed,
            generated_allocated,
            generated_unavailable,
            generated_rejected,
            generated_committed,
            generated_cancelled,
            generated_abandoned,
            kernel_packets,
            kernel_drops,
            kernel_freeze_q,
            kernel_stats_errors,
        );
    }
}

fn visit_faults<V: FieldVisitor>(
    section: &'static str,
    faults: &BackendStatsSnapshot,
    visitor: &mut V,
) {
    visitor.field(
        section,
        "rx_geometry_rejected",
        FieldValue::Count(faults.geometry_rejected),
    );
    visitor.field(
        section,
        "rx_descriptor_rejected",
        FieldValue::Count(faults.descriptor_rejected),
    );
    visitor.field(
        section,
        "rx_status_rejected",
        FieldValue::Count(faults.status_rejected),
    );
    visitor.field(
        section,
        "rx_ownership_rejected",
        FieldValue::Count(faults.ownership_rejected),
    );
    visitor.field(
        section,
        "rx_mmap_errors",
        FieldValue::Count(faults.mmap_errors),
    );
}

/// Field-wise saturating sum of two RX fault snapshots.
pub(crate) const fn add_faults(
    left: BackendStatsSnapshot,
    right: BackendStatsSnapshot,
) -> BackendStatsSnapshot {
    BackendStatsSnapshot {
        geometry_rejected: left
            .geometry_rejected
            .saturating_add(right.geometry_rejected),
        descriptor_rejected: left
            .descriptor_rejected
            .saturating_add(right.descriptor_rejected),
        status_rejected: left.status_rejected.saturating_add(right.status_rejected),
        ownership_rejected: left
            .ownership_rejected
            .saturating_add(right.ownership_rejected),
        syscall_errors: left.syscall_errors.saturating_add(right.syscall_errors),
        mmap_errors: left.mmap_errors.saturating_add(right.mmap_errors),
    }
}

/// Live state and counters of one port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AfPacketPortStats {
    pub interface: IfId,
    pub if_index: u32,
    /// Largest frame accepted for TX (the configured maximum).
    pub max_frame: u32,
    pub rx_blocks: u32,
    pub tx_frames: u32,
    /// TX frames published and not yet handed back by the kernel.
    pub tx_inflight: u32,
    /// The RX cursor is halted on a fail-closed fault right now.
    pub rx_halted: bool,
    /// A later settle must kick this port (TX the kernel has not taken).
    pub kick_owed: bool,
    /// The last kick found the link down.
    pub link_down: bool,
    /// RX fault-class counters (each halt event counted once).
    pub faults: BackendStatsSnapshot,
    pub counters: AfPacketCounters,
}

impl ObservableFields for AfPacketPortStats {
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        const SECTION: &str = "af_packet_port";
        visitor.field(
            SECTION,
            "interface",
            FieldValue::Count(u64::from(self.interface.0)),
        );
        visitor.field(
            SECTION,
            "if_index",
            FieldValue::Count(u64::from(self.if_index)),
        );
        visitor.field(
            SECTION,
            "max_frame",
            FieldValue::Count(u64::from(self.max_frame)),
        );
        visitor.field(
            SECTION,
            "rx_blocks",
            FieldValue::Count(u64::from(self.rx_blocks)),
        );
        visitor.field(
            SECTION,
            "tx_frames",
            FieldValue::Count(u64::from(self.tx_frames)),
        );
        visitor.field(
            SECTION,
            "tx_inflight",
            FieldValue::Count(u64::from(self.tx_inflight)),
        );
        visitor.field(SECTION, "rx_halted", FieldValue::Flag(self.rx_halted));
        visitor.field(SECTION, "kick_owed", FieldValue::Flag(self.kick_owed));
        visitor.field(SECTION, "link_down", FieldValue::Flag(self.link_down));
        visit_faults(SECTION, &self.faults, visitor);
        self.counters.visit(SECTION, visitor);
    }
}

/// Backend stats summed over every port (OBS-028). Per-port detail is
/// `AfPacketIo::port_stats`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AfPacketBackendStats {
    pub ports: u32,
    /// TX frames in flight over every port.
    pub tx_inflight: u64,
    pub rx_halted_ports: u32,
    pub kick_owed_ports: u32,
    pub link_down_ports: u32,
    /// Generated sessions started for an interface without a port.
    pub generated_unknown_egress: u64,
    /// Drained or stopped by a TX completion fault: no more I/O.
    pub stopped: bool,
    pub faults: BackendStatsSnapshot,
    pub counters: AfPacketCounters,
}

impl ObservableFields for AfPacketBackendStats {
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        const SECTION: &str = "af_packet";
        visitor.field(SECTION, "mode", FieldValue::Label("copy"));
        visitor.field(SECTION, "ports", FieldValue::Count(u64::from(self.ports)));
        visitor.field(SECTION, "tx_inflight", FieldValue::Count(self.tx_inflight));
        visitor.field(
            SECTION,
            "rx_halted_ports",
            FieldValue::Count(u64::from(self.rx_halted_ports)),
        );
        visitor.field(
            SECTION,
            "kick_owed_ports",
            FieldValue::Count(u64::from(self.kick_owed_ports)),
        );
        visitor.field(
            SECTION,
            "link_down_ports",
            FieldValue::Count(u64::from(self.link_down_ports)),
        );
        visitor.field(
            SECTION,
            "generated_unknown_egress",
            FieldValue::Count(self.generated_unknown_egress),
        );
        visitor.field(SECTION, "stopped", FieldValue::Flag(self.stopped));
        visit_faults(SECTION, &self.faults, visitor);
        self.counters.visit(SECTION, visitor);
    }
}

/// Outcome of one idle wait (`AfPacketIo::wait_rx`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RxWait {
    /// A port has RX work (or reported a socket condition) now.
    Ready,
    /// The timeout passed without RX work.
    TimedOut,
    /// A signal handler ran (`EINTR`).
    Interrupted,
}
