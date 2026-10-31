//! Private TPACKET_V3 RX block engine (AP1-RX).
//!
//! Each port owns one persistent [`RxCursor`] over its RX block ring. A batch
//! advances that cursor under three independent budgets and never reads
//! outside the RX extent of the combined mapping:
//!
//! 1. *Observe*: one Acquire load of the head block status. KERNEL means the
//!    ring is empty; the cursor never skips ahead to a later block. USER
//!    assigns the block a fresh nonzero generation and validates its header.
//! 2. *Validate*: one descriptor per visit, following only checked chain
//!    links. Progress is saved in fixed per-packet metadata, so a later batch
//!    resumes at the exact descriptor and never rescans an earlier one. No
//!    packet of a block is exposed before its whole chain is validated.
//! 3. *Deliver*: packets are leased in chain order as borrowed views of the
//!    mapping. A lease mutably borrows the port, so the block cannot be
//!    returned, and no sibling can be leased, while its bytes are borrowed.
//!    Completing the final outstanding packet stores TP_STATUS_KERNEL with
//!    Release exactly once and advances the cursor.
//!
//! Status words are accessed as `AtomicU32` (Acquire load, Release store);
//! other descriptor fields are read volatile after the Acquire observation.
//!
//! Recovery policy (fail closed; no panic, no read past a failed check):
//!
//! - Head status that is neither KERNEL nor USER-flagged: the block may still
//!   be kernel-owned, so nothing is written. The cursor stays, the batch halts,
//!   and the next batch observes the same block again. The stat is counted
//!   once per distinct halt, not once per poll.
//! - Generation exhaustion: same as an invalid status; the block is untouched.
//! - Invalid block header, or a descriptor whose own placement or next link is
//!   unsafe: the block was observed USER, so it is returned to the kernel
//!   immediately without exposing any of its packets and without visiting any
//!   later descriptor. The cursor advances to the next block.
//! - A descriptor whose link is safe but whose own content is invalid
//!   (MAC/network offset, snapshot length, data range, truncation, a frame
//!   above the configured maximum, or a VLAN tag the kernel removed from the
//!   captured bytes): only that packet becomes a terminal fault. Its siblings
//!   are still delivered, and the block returns after the last sibling is
//!   terminal. GRO/LRO superframes therefore arrive as truncated or oversize
//!   faults and are dropped; the strict profile requires them disabled.
//! - Failure to mirror a validated block into the ownership model is an
//!   internal invariant violation: the batch halts without returning the
//!   block or changing the cursor.
//! - A failed block-return store leaves every packet terminal; the next step
//!   retries the return and halts again while it keeps failing.
//! - A lease that ends without running its completion (`mem::forget`) is
//!   completed as abandoned by the next cursor step that has packet budget,
//!   because its borrow has necessarily ended by then.
//!
//! [`RxBatch`] and [`RxPacket`] drive one port directly. The AP2 PacketIo
//! adapter (`sys::packet_io`) drives the same cursor through `rx_step` and
//! `rx_complete`, with leases that borrow the whole engine instead of one
//! port, so a packet can be copied into a TX frame of its own port.
//!
//! Persistent halts are not escalated (no port reinitialization) and the
//! `sll_pkttype` of captured frames is not filtered here; both are deferred.
//!
//! Steady operation performs no heap allocation, takes no lock, and does O(1)
//! work per status read, descriptor visit, and packet.

use std::{mem::offset_of, ptr::NonNull};

use ruster_core::IfId;

use super::{
    LinuxOps, PacketOps, PacketRingResources, Tpacket3Hdr, TpacketBlockDesc, TpacketHdrV1,
};
use crate::{
    boundary::{RxPacketFault, RxPacketMetadata},
    BackendStat, BackendStatsSnapshot, BlockDescriptor, GeometryError, MappingAccessError,
    OwnershipError, PacketDescriptor, RingKind, RxOwnership, TP_STATUS_KERNEL,
};

const BLOCK_HEADER: usize = offset_of!(TpacketBlockDesc, hdr);
const BLOCK_VERSION: usize = offset_of!(TpacketBlockDesc, version);
const BLOCK_PRIVATE: usize = offset_of!(TpacketBlockDesc, offset_to_priv);
const BLOCK_STATUS: usize = BLOCK_HEADER + offset_of!(TpacketHdrV1, block_status);
const BLOCK_PACKETS: usize = BLOCK_HEADER + offset_of!(TpacketHdrV1, num_pkts);
const BLOCK_FIRST: usize = BLOCK_HEADER + offset_of!(TpacketHdrV1, offset_to_first_pkt);
const BLOCK_LEN: usize = BLOCK_HEADER + offset_of!(TpacketHdrV1, blk_len);
const PACKET_NEXT: usize = offset_of!(Tpacket3Hdr, tp_next_offset);
const PACKET_SNAP: usize = offset_of!(Tpacket3Hdr, tp_snaplen);
const PACKET_WIRE: usize = offset_of!(Tpacket3Hdr, tp_len);
const PACKET_MAC: usize = offset_of!(Tpacket3Hdr, tp_mac);
const PACKET_NET: usize = offset_of!(Tpacket3Hdr, tp_net);
const PACKET_STATUS: usize = offset_of!(Tpacket3Hdr, tp_status);
/// Linux `TP_STATUS_VLAN_VALID` and `TP_STATUS_VLAN_TPID_VALID`: the kernel
/// moved an offloaded 802.1Q/802.1ad tag out of the captured bytes.
const TP_STATUS_VLAN_OFFLOADED: u32 = (1 << 4) | (1 << 6);

const _: [(); 0] = [(); BLOCK_VERSION];
const _: [(); 4] = [(); BLOCK_PRIVATE];
const _: [(); 8] = [(); BLOCK_STATUS];
const _: [(); 12] = [(); BLOCK_PACKETS];
const _: [(); 16] = [(); BLOCK_FIRST];
const _: [(); 20] = [(); BLOCK_LEN];
const _: [(); 0] = [(); PACKET_NEXT];
const _: [(); 12] = [(); PACKET_SNAP];
const _: [(); 16] = [(); PACKET_WIRE];
const _: [(); 24] = [(); PACKET_MAC];
const _: [(); 26] = [(); PACKET_NET];
const _: [(); 20] = [(); PACKET_STATUS];

/// Independent per-batch work limits.
///
/// Every step requires a remaining packet unit. Observing a new head block
/// additionally requires a status read *and* a descriptor visit, so a zero
/// value of any of the three performs no status read, header validation, or
/// generation step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RxBudget {
    /// Packet leases plus packet-local faults handed to the caller.
    pub(crate) packets: usize,
    /// Acquire loads of a head block status.
    pub(crate) block_status_reads: usize,
    /// Packet descriptors read and validated.
    pub(crate) descriptor_visits: usize,
}

/// One USER-ownership cycle of one physical RX block.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RxBlockToken {
    pub(crate) block_index: usize,
    /// Nonzero and strictly increasing for every observation of this block.
    pub(crate) generation: u64,
}

/// One packet within one block ownership cycle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RxPacketToken {
    pub(crate) block: RxBlockToken,
    pub(crate) packet_index: u32,
}

/// A whole block whose every packet was terminal and that was handed back to
/// the kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RxBlockReturn {
    pub(crate) block: RxBlockToken,
    pub(crate) packet_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RxReleaseError {
    /// The token does not name the cursor's outstanding packet.
    Stale(RxPacketToken),
    Ownership(OwnershipError),
    Mapping(MappingAccessError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RxFault {
    /// A locally invalid packet. It is terminal now and never exposed;
    /// `returned` is set when it was the block's final outstanding packet.
    Packet {
        token: RxPacketToken,
        fault: RxPacketFault,
        returned: Option<RxBlockReturn>,
    },
    /// The block header (`packet_index == None`) or the chain at
    /// `packet_index` is unsafe. The whole block was returned to the kernel
    /// unless `return_error` is set, in which case the batch halted.
    Block {
        block: RxBlockToken,
        packet_index: Option<u32>,
        error: MappingAccessError,
        return_error: Option<MappingAccessError>,
    },
    /// A fully validated block could not be mirrored into the ownership
    /// model. Internal invariant violation; nothing is returned; halts.
    Acquire {
        block: RxBlockToken,
        error: OwnershipError,
    },
    /// The head status is neither KERNEL nor USER-flagged. Untouched; halts.
    Status { block_index: usize, status: u32 },
    /// The head block cannot receive a fresh generation. Untouched; halts.
    GenerationExhausted { block_index: usize },
    /// Checked head status access failed. Untouched; halts.
    Mapping {
        block_index: usize,
        error: MappingAccessError,
    },
    /// Completing or returning the current block failed. Halts; the next
    /// step retries the pending return.
    Release(RxReleaseError),
}

impl RxFault {
    /// Fixed counter for a halting fault.
    const fn halt_stat(self) -> BackendStat {
        match self {
            Self::Status { .. } => BackendStat::StatusRejected,
            Self::Mapping { .. } | Self::Release(RxReleaseError::Mapping(_)) => {
                BackendStat::MmapError
            }
            Self::Block { .. } => BackendStat::MmapError,
            Self::Packet { .. }
            | Self::Acquire { .. }
            | Self::GenerationExhausted { .. }
            | Self::Release(_) => BackendStat::OwnershipRejected,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RxStop {
    PacketBudget,
    StatusBudget,
    DescriptorBudget,
    /// The head block is kernel-owned.
    RingEmpty,
    /// A fail-closed fault stopped this batch.
    Halted,
}

/// Work and lifecycle accounting for one batch.
///
/// Every counter is attributed to the batch during whose lifetime the event
/// happened. A lease cannot outlive its batch, so `released` (explicit
/// [`RxPacket::release`]) and `dropped` (lease dropped, including during
/// unwinding) always land in the leasing batch. A lease that was forgotten is
/// finalized by the first later step with packet budget, possibly in a later
/// batch, and is counted there once in `abandoned_leaks`, together with any
/// block return it triggers. No completion is counted twice; across the port
/// lifetime, with no lease live, `Σleased == Σ(released + dropped +
/// abandoned_leaks)`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RxBatchReport {
    pub(crate) status_reads: usize,
    pub(crate) descriptor_visits: usize,
    pub(crate) blocks_acquired: usize,
    pub(crate) leased: usize,
    pub(crate) released: usize,
    pub(crate) dropped: usize,
    pub(crate) abandoned_leaks: usize,
    pub(crate) packet_faults: usize,
    pub(crate) block_faults: usize,
    pub(crate) blocks_returned: usize,
    pub(crate) stop: Option<RxStop>,
}

#[allow(dead_code)]
pub(crate) enum RxNext<'b, O: PacketOps = LinuxOps> {
    Packet(RxPacket<'b, O>),
    Fault(RxFault),
}

/// Test-only fault injection for paths that checked geometry makes
/// unreachable in production: each nonzero counter fails that many of the
/// next corresponding accesses.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RxFaultInjection {
    pub(crate) status_loads: usize,
    pub(crate) status_stores: usize,
    pub(crate) data_addresses: usize,
}

#[cfg(test)]
fn take_injected(counter: &mut usize, offset: usize, length: usize) -> Option<MappingAccessError> {
    if *counter == 0 {
        return None;
    }
    *counter -= 1;
    Some(MappingAccessError::RingOffsetOutOfBounds {
        kind: RingKind::Rx,
        offset,
        length,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Completion {
    Released,
    Dropped,
    Abandoned,
    Fault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveBlock {
    token: RxBlockToken,
    /// RX-extent-relative start of the block.
    block_start: usize,
    block_len: usize,
    packet_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RxPhase {
    Idle,
    Validating {
        block: ActiveBlock,
        next_index: u32,
        next_offset: usize,
    },
    Delivering {
        block: ActiveBlock,
        next_index: u32,
        lent: bool,
    },
}

/// Persistent per-port cursor. It lives with the port resources, not with a
/// batch, so dropping a batch never loses or repeats progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RxCursor {
    head: usize,
    phase: RxPhase,
    /// The halting fault already counted, so a persistent condition is
    /// counted once per event rather than once per poll.
    sticky: Option<RxFault>,
}

impl RxCursor {
    pub(crate) const fn new() -> Self {
        Self {
            head: 0,
            phase: RxPhase::Idle,
            sticky: None,
        }
    }
}

pub(super) enum Step {
    Continue,
    Stop(RxStop),
    Fault(RxFault),
    Halt(RxFault),
    Lease {
        token: RxPacketToken,
        data: NonNull<u8>,
        len: usize,
    },
}

#[allow(dead_code)]
impl<O: PacketOps> PacketRingResources<O> {
    pub(crate) fn begin_rx(&mut self, budget: RxBudget) -> RxBatch<'_, O> {
        RxBatch {
            port: self,
            remaining: budget,
            report: RxBatchReport::default(),
        }
    }

    pub(crate) const fn rx_stats(&self) -> BackendStatsSnapshot {
        self.rx_stats.snapshot()
    }

    pub(super) fn rx_step(&mut self, remaining: &mut RxBudget, report: &mut RxBatchReport) -> Step {
        if remaining.packets == 0 {
            return Step::Stop(RxStop::PacketBudget);
        }
        match self.rx_cursor.phase {
            RxPhase::Idle => self.rx_observe_head(remaining, report),
            RxPhase::Validating {
                block,
                next_index,
                next_offset,
            } => self.rx_validate_next(block, next_index, next_offset, remaining, report),
            RxPhase::Delivering {
                block,
                next_index,
                lent,
            } => self.rx_deliver_next(block, next_index, lent, remaining, report),
        }
    }

    fn rx_observe_head(&mut self, remaining: &mut RxBudget, report: &mut RxBatchReport) -> Step {
        if remaining.block_status_reads == 0 {
            return Step::Stop(RxStop::StatusBudget);
        }
        if remaining.descriptor_visits == 0 {
            // A new block cannot make progress without a descriptor visit.
            return Step::Stop(RxStop::DescriptorBudget);
        }
        remaining.block_status_reads -= 1;
        report.status_reads += 1;
        #[cfg(test)]
        self.probe.record(|counts| counts.rx_status_reads += 1);
        let block_index = self.rx_cursor.head;
        let block_start = match self.rx.block_range(block_index) {
            Ok(range) => range.start,
            Err(error) => {
                return self.rx_halt(RxFault::Mapping {
                    block_index,
                    error: MappingAccessError::Geometry(error),
                })
            }
        };
        let status = match self.rx_load_status(block_start) {
            Ok(status) => status,
            Err(error) => return self.rx_halt(RxFault::Mapping { block_index, error }),
        };
        match RxOwnership::from_status(status) {
            Ok(RxOwnership::Kernel) => {
                self.rx_cursor.sticky = None;
                return Step::Stop(RxStop::RingEmpty);
            }
            Ok(RxOwnership::User) => {}
            Err(_) => {
                return self.rx_halt(RxFault::Status {
                    block_index,
                    status,
                })
            }
        }
        let Some(entry) = self.metadata.rx_blocks_mut().get_mut(block_index) else {
            return self.rx_halt(RxFault::Mapping {
                block_index,
                error: MappingAccessError::Geometry(GeometryError::BlockIndexOutOfRange {
                    block_index,
                }),
            });
        };
        let Some(generation) = entry.generation.checked_add(1) else {
            return self.rx_halt(RxFault::GenerationExhausted { block_index });
        };
        entry.generation = generation;
        self.rx_cursor.sticky = None;
        report.blocks_acquired += 1;
        #[cfg(test)]
        self.probe.record(|counts| counts.rx_blocks_acquired += 1);
        let token = RxBlockToken {
            block_index,
            generation,
        };
        let header = match self.rx_read_block_header(block_start) {
            Ok(header) => header,
            Err(error) => return self.rx_reject_block(token, block_start, None, error, report),
        };
        if let Err(error) = header.validate(self.rx) {
            return self.rx_reject_block(
                token,
                block_start,
                None,
                MappingAccessError::Geometry(error),
                report,
            );
        }
        self.rx_cursor.phase = RxPhase::Validating {
            block: ActiveBlock {
                token,
                block_start,
                block_len: header.block_len,
                packet_count: header.packet_count,
            },
            next_index: 0,
            next_offset: header.first_packet_offset,
        };
        Step::Continue
    }

    fn rx_validate_next(
        &mut self,
        block: ActiveBlock,
        index: u32,
        offset: usize,
        remaining: &mut RxBudget,
        report: &mut RxBatchReport,
    ) -> Step {
        if remaining.descriptor_visits == 0 {
            return Step::Stop(RxStop::DescriptorBudget);
        }
        remaining.descriptor_visits -= 1;
        report.descriptor_visits += 1;
        #[cfg(test)]
        self.probe.record(|counts| counts.rx_descriptor_visits += 1);
        let is_last = index + 1 == block.packet_count;
        let (descriptor, status) = match self.rx_read_descriptor(block.block_start, offset, is_last)
        {
            Ok(descriptor) => descriptor,
            Err(error) => {
                return self.rx_reject_block(
                    block.token,
                    block.block_start,
                    Some(index),
                    error,
                    report,
                )
            }
        };
        let next = match descriptor.validate_link(block.block_len) {
            Ok(next) => next,
            Err(error) => {
                return self.rx_reject_block(
                    block.token,
                    block.block_start,
                    Some(index),
                    MappingAccessError::Geometry(error),
                    report,
                )
            }
        };
        let metadata = self.rx_classify(descriptor, status, block.block_len, next);
        let Some(slot) = usize::try_from(index)
            .ok()
            .and_then(|index| self.metadata.rx_packets_mut().get_mut(index))
        else {
            let maximum = self.metadata.rx_packets().len();
            return self.rx_reject_block(
                block.token,
                block.block_start,
                Some(index),
                MappingAccessError::Geometry(GeometryError::PacketCountExceedsBlock {
                    packet_count: block.packet_count,
                    maximum,
                }),
                report,
            );
        };
        *slot = metadata;
        if !is_last {
            self.rx_cursor.phase = RxPhase::Validating {
                block,
                next_index: index + 1,
                next_offset: metadata.next_offset,
            };
            return Step::Continue;
        }
        let acquired = match self
            .metadata
            .rx_blocks_mut()
            .get_mut(block.token.block_index)
        {
            Some(entry) => entry.ownership.acquire(block.packet_count),
            None => Err(OwnershipError::RxAcquireWhileOwned {
                owner: RxOwnership::User,
            }),
        };
        if let Err(error) = acquired {
            // The model disagrees with an observed USER block. Neither return
            // the block nor move the cursor; a later step revisits only this
            // final descriptor and retries.
            return self.rx_halt(RxFault::Acquire {
                block: block.token,
                error,
            });
        }
        self.rx_cursor.phase = RxPhase::Delivering {
            block,
            next_index: 0,
            lent: false,
        };
        Step::Continue
    }

    fn rx_classify(
        &self,
        descriptor: PacketDescriptor,
        status: u32,
        block_len: usize,
        next: Option<usize>,
    ) -> RxPacketMetadata {
        let next_offset = next.unwrap_or(0);
        let fault = |fault| RxPacketMetadata {
            data_offset: 0,
            data_len: 0,
            next_offset,
            fault: Some(fault),
        };
        let packet = match descriptor.validate(block_len) {
            Ok(packet) => packet,
            Err(error) => return fault(RxPacketFault::Descriptor(error)),
        };
        if status & TP_STATUS_VLAN_OFFLOADED != 0 {
            // The visible frame would look untagged although it was tagged on
            // the wire; the strict profile does not forward VLAN traffic.
            return fault(RxPacketFault::VlanOffloaded { status });
        }
        if packet.is_truncated() {
            return fault(RxPacketFault::Truncated {
                snap_len: descriptor.snap_len,
                wire_len: descriptor.wire_len,
            });
        }
        if descriptor.snap_len > self.max_frame_len {
            return fault(RxPacketFault::Oversize {
                length: descriptor.snap_len,
                maximum: self.max_frame_len,
            });
        }
        let data = packet.data();
        RxPacketMetadata {
            data_offset: data.start,
            data_len: data.end - data.start,
            next_offset,
            fault: None,
        }
    }

    fn rx_deliver_next(
        &mut self,
        block: ActiveBlock,
        index: u32,
        lent: bool,
        remaining: &mut RxBudget,
        report: &mut RxBatchReport,
    ) -> Step {
        let token = RxPacketToken {
            block: block.token,
            packet_index: index,
        };
        if lent {
            // The previous lease of `index` ended without running its
            // completion. Its borrow is over, so completing it cannot race
            // with any live view of its bytes.
            return match self.rx_complete(token, Completion::Abandoned, report) {
                Ok(_) => Step::Continue,
                Err(error) => self.rx_halt(RxFault::Release(error)),
            };
        }
        if index >= block.packet_count {
            // Every packet is terminal, but an earlier return attempt failed.
            return match self.rx_return_block(block, report) {
                Ok(_) => Step::Continue,
                Err(error) => self.rx_halt(RxFault::Release(error)),
            };
        }
        let metadata = usize::try_from(index)
            .ok()
            .and_then(|index| self.metadata.rx_packets().get(index))
            .copied();
        let Some(metadata) = metadata else {
            return self.rx_halt(RxFault::Release(RxReleaseError::Stale(token)));
        };
        remaining.packets -= 1;
        let fault = match metadata.fault {
            Some(fault) => fault,
            None => match self.rx_data_address(block.block_start, metadata) {
                Ok(data) => {
                    self.rx_cursor.phase = RxPhase::Delivering {
                        block,
                        next_index: index,
                        lent: true,
                    };
                    report.leased += 1;
                    return Step::Lease {
                        token,
                        data,
                        len: metadata.data_len,
                    };
                }
                Err(error) => RxPacketFault::Mapping(error),
            },
        };
        self.rx_stats.record(BackendStat::DescriptorRejected);
        report.packet_faults += 1;
        match self.rx_complete(token, Completion::Fault, report) {
            Ok(returned) => Step::Fault(RxFault::Packet {
                token,
                fault,
                returned,
            }),
            Err(error) => self.rx_halt(RxFault::Release(error)),
        }
    }

    /// Marks the cursor's current packet terminal exactly once. Returns the
    /// block to the kernel when it was the final outstanding packet.
    pub(super) fn rx_complete(
        &mut self,
        token: RxPacketToken,
        kind: Completion,
        report: &mut RxBatchReport,
    ) -> Result<Option<RxBlockReturn>, RxReleaseError> {
        let RxPhase::Delivering {
            block,
            next_index,
            lent,
        } = self.rx_cursor.phase
        else {
            return Err(RxReleaseError::Stale(token));
        };
        if block.token != token.block
            || next_index != token.packet_index
            || lent != (kind != Completion::Fault)
        {
            return Err(RxReleaseError::Stale(token));
        }
        let entry = self
            .metadata
            .rx_blocks_mut()
            .get_mut(block.token.block_index)
            .ok_or(RxReleaseError::Stale(token))?;
        entry
            .ownership
            .complete_packet()
            .map_err(RxReleaseError::Ownership)?;
        match kind {
            Completion::Released => report.released += 1,
            Completion::Dropped => report.dropped += 1,
            Completion::Abandoned => report.abandoned_leaks += 1,
            Completion::Fault => {}
        }
        let next_index = next_index + 1;
        self.rx_cursor.phase = RxPhase::Delivering {
            block,
            next_index,
            lent: false,
        };
        if next_index < block.packet_count {
            return Ok(None);
        }
        self.rx_return_block(block, report).map(Some)
    }

    fn rx_return_block(
        &mut self,
        block: ActiveBlock,
        report: &mut RxBatchReport,
    ) -> Result<RxBlockReturn, RxReleaseError> {
        let index = block.token.block_index;
        let entry = self
            .metadata
            .rx_blocks()
            .get(index)
            .ok_or(RxReleaseError::Mapping(MappingAccessError::Geometry(
                GeometryError::BlockIndexOutOfRange { block_index: index },
            )))?;
        if entry.ownership.owner() != RxOwnership::User {
            return Err(RxReleaseError::Ownership(
                OwnershipError::RxReleaseWhileKernelOwned,
            ));
        }
        let outstanding = entry.ownership.remaining();
        if outstanding != 0 {
            return Err(RxReleaseError::Ownership(
                OwnershipError::RxPacketsOutstanding {
                    remaining: outstanding,
                },
            ));
        }
        // Every packet is terminal and no lease is live: hand the block back.
        self.rx_store_kernel(block.block_start)
            .map_err(RxReleaseError::Mapping)?;
        if let Some(entry) = self.metadata.rx_blocks_mut().get_mut(index) {
            entry
                .ownership
                .release()
                .map_err(RxReleaseError::Ownership)?;
        }
        self.rx_advance(index);
        report.blocks_returned += 1;
        #[cfg(test)]
        self.probe.mark_rx_return();
        Ok(RxBlockReturn {
            block: block.token,
            packet_count: block.packet_count,
        })
    }

    fn rx_reject_block(
        &mut self,
        block: RxBlockToken,
        block_start: usize,
        packet_index: Option<u32>,
        error: MappingAccessError,
        report: &mut RxBatchReport,
    ) -> Step {
        self.rx_stats.record(BackendStat::GeometryRejected);
        report.block_faults += 1;
        // The block was observed USER, so userspace may hand it back. None of
        // its packets was exposed and no later descriptor is visited.
        let return_error = self.rx_store_kernel(block_start).err();
        self.rx_cursor.phase = RxPhase::Idle;
        let fault = RxFault::Block {
            block,
            packet_index,
            error,
            return_error,
        };
        if return_error.is_some() {
            // Each retry re-observes the block under a new generation, so
            // every failed return is a distinct event.
            self.rx_stats.record(BackendStat::MmapError);
            return Step::Halt(fault);
        }
        self.rx_advance(block.block_index);
        report.blocks_returned += 1;
        #[cfg(test)]
        self.probe.mark_rx_return();
        Step::Fault(fault)
    }

    fn rx_advance(&mut self, block_index: usize) {
        let next = block_index + 1;
        self.rx_cursor.head = if next == self.rx.block_count() {
            0
        } else {
            next
        };
        self.rx_cursor.phase = RxPhase::Idle;
        self.rx_cursor.sticky = None;
    }

    /// Halts the batch, counting the fault only when it differs from the
    /// halt already counted for the current condition.
    fn rx_halt(&mut self, fault: RxFault) -> Step {
        self.rx_note_halt(fault);
        Step::Halt(fault)
    }

    /// The halting fault already counted for the current condition, if any.
    /// A halt equal to this value is a repeat of an event already reported.
    pub(super) const fn rx_sticky_halt(&self) -> Option<RxFault> {
        self.rx_cursor.sticky
    }

    pub(super) fn rx_note_halt(&mut self, fault: RxFault) {
        if self.rx_cursor.sticky != Some(fault) {
            self.rx_stats.record(fault.halt_stat());
            self.rx_cursor.sticky = Some(fault);
        }
    }

    fn rx_load_status(&mut self, block_start: usize) -> Result<u32, MappingAccessError> {
        let offset = block_start + BLOCK_STATUS;
        #[cfg(test)]
        if let Some(error) = take_injected(&mut self.rx_injection.status_loads, offset, 4) {
            return Err(error);
        }
        self.mapping
            .ring_load_status_acquire(self.extents, RingKind::Rx, offset)
    }

    fn rx_store_kernel(&mut self, block_start: usize) -> Result<(), MappingAccessError> {
        let offset = block_start + BLOCK_STATUS;
        #[cfg(test)]
        if let Some(error) = take_injected(&mut self.rx_injection.status_stores, offset, 4) {
            return Err(error);
        }
        self.mapping
            .ring_store_status_release(self.extents, RingKind::Rx, offset, TP_STATUS_KERNEL)
    }

    fn rx_data_address(
        &mut self,
        block_start: usize,
        metadata: RxPacketMetadata,
    ) -> Result<NonNull<u8>, MappingAccessError> {
        let offset = block_start
            .checked_add(metadata.data_offset)
            .ok_or(MappingAccessError::ArithmeticOverflow)?;
        #[cfg(test)]
        if let Some(error) = take_injected(
            &mut self.rx_injection.data_addresses,
            offset,
            metadata.data_len,
        ) {
            return Err(error);
        }
        let address =
            self.mapping
                .ring_address(self.extents, RingKind::Rx, offset, metadata.data_len, 1)?;
        NonNull::new(address).ok_or(MappingAccessError::ArithmeticOverflow)
    }

    fn rx_read_u32(&self, offset: usize) -> Result<u32, MappingAccessError> {
        self.mapping
            .ring_read_u32(self.extents, RingKind::Rx, offset)
    }

    fn rx_read_u16(&self, offset: usize) -> Result<u16, MappingAccessError> {
        self.mapping
            .ring_read_u16(self.extents, RingKind::Rx, offset)
    }

    fn rx_read_block_header(
        &self,
        block_start: usize,
    ) -> Result<BlockDescriptor, MappingAccessError> {
        Ok(BlockDescriptor {
            version: self.rx_read_u32(block_start + BLOCK_VERSION)?,
            offset_to_private: self.rx_read_u32(block_start + BLOCK_PRIVATE)? as usize,
            packet_count: self.rx_read_u32(block_start + BLOCK_PACKETS)?,
            first_packet_offset: self.rx_read_u32(block_start + BLOCK_FIRST)? as usize,
            block_len: self.rx_read_u32(block_start + BLOCK_LEN)? as usize,
        })
    }

    fn rx_read_descriptor(
        &self,
        block_start: usize,
        packet_offset: usize,
        is_last: bool,
    ) -> Result<(PacketDescriptor, u32), MappingAccessError> {
        let packet = block_start
            .checked_add(packet_offset)
            .ok_or(MappingAccessError::ArithmeticOverflow)?;
        let descriptor = PacketDescriptor {
            packet_offset,
            next_offset: self.rx_read_u32(packet + PACKET_NEXT)? as usize,
            snap_len: self.rx_read_u32(packet + PACKET_SNAP)? as usize,
            wire_len: self.rx_read_u32(packet + PACKET_WIRE)? as usize,
            mac_offset: usize::from(self.rx_read_u16(packet + PACKET_MAC)?),
            net_offset: usize::from(self.rx_read_u16(packet + PACKET_NET)?),
            is_last,
        };
        Ok((descriptor, self.rx_read_u32(packet + PACKET_STATUS)?))
    }
}

/// One budgeted pass over a port's persistent RX cursor.
#[must_use]
pub(crate) struct RxBatch<'a, O: PacketOps = LinuxOps> {
    port: &'a mut PacketRingResources<O>,
    remaining: RxBudget,
    report: RxBatchReport,
}

#[allow(dead_code)]
impl<O: PacketOps> RxBatch<'_, O> {
    /// Returns the next packet lease or terminal fault, or `None` once a
    /// budget is exhausted, the ring is empty, or a fault halted the batch.
    pub(crate) fn next(&mut self) -> Option<RxNext<'_, O>> {
        if self.report.stop.is_some() {
            return None;
        }
        loop {
            match self.port.rx_step(&mut self.remaining, &mut self.report) {
                Step::Continue => {}
                Step::Stop(stop) => {
                    self.report.stop = Some(stop);
                    return None;
                }
                Step::Fault(fault) => return Some(RxNext::Fault(fault)),
                Step::Halt(fault) => {
                    self.report.stop = Some(RxStop::Halted);
                    return Some(RxNext::Fault(fault));
                }
                Step::Lease { token, data, len } => {
                    return Some(RxNext::Packet(RxPacket {
                        port: &mut *self.port,
                        report: &mut self.report,
                        token,
                        data,
                        len,
                        completed: false,
                    }))
                }
            }
        }
    }

    pub(crate) const fn report(&self) -> RxBatchReport {
        self.report
    }

    pub(crate) fn finish(self) -> RxBatchReport {
        self.report
    }
}

/// Borrowed, zero-copy view of one validated packet in a USER-owned block.
///
/// The lease mutably borrows the port, so the containing block cannot be
/// returned and no other packet can be leased while it is live. Explicit
/// [`Self::release`] is counted as `released`; dropping the lease (including
/// during unwinding) completes it once and is counted as `dropped`.
#[must_use]
pub(crate) struct RxPacket<'b, O: PacketOps = LinuxOps> {
    port: &'b mut PacketRingResources<O>,
    report: &'b mut RxBatchReport,
    token: RxPacketToken,
    data: NonNull<u8>,
    len: usize,
    completed: bool,
}

#[allow(dead_code)]
impl<O: PacketOps> RxPacket<'_, O> {
    pub(crate) const fn token(&self) -> RxPacketToken {
        self.token
    }

    pub(crate) fn ingress(&self) -> IfId {
        self.port.interface
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        // SAFETY: `data..data+len` was proved by ring_address to lie inside
        // the RX extent of the live mapping and inside this packet's
        // validated data range. The block stays USER-owned until this lease
        // completes, so the kernel does not write it, and the lease's
        // exclusive port borrow excludes every other userspace access.
        unsafe { std::slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as in `bytes`; additionally `&mut self` makes this the only
        // live view, and sibling packet ranges are disjoint and never leased
        // concurrently.
        unsafe { std::slice::from_raw_parts_mut(self.data.as_ptr(), self.len) }
    }

    /// Completes this packet. Returns the block when it was the final
    /// outstanding packet of its block. On a failed block return every packet
    /// stays terminal and the next cursor step retries the return.
    pub(crate) fn release(mut self) -> Result<Option<RxBlockReturn>, RxReleaseError> {
        self.completed = true;
        let result = self
            .port
            .rx_complete(self.token, Completion::Released, self.report);
        if let Err(error) = result {
            self.port.rx_note_halt(RxFault::Release(error));
        }
        result
    }
}

impl<O: PacketOps> Drop for RxPacket<'_, O> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.completed = true;
        if let Err(error) = self
            .port
            .rx_complete(self.token, Completion::Dropped, self.report)
        {
            self.port.rx_note_halt(RxFault::Release(error));
        }
    }
}

#[cfg(test)]
mod tests;
