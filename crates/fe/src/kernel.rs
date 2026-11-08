//! The router's own packets, read from each VRF's kernel pipe, as packets for core to
//! forward like a host's (`docs/design/fe-ce-split.md`, "IPの通信: kernelは内側のホスト").
//!
//! Each VRF has a kernel interface ([`crate::build::Built::kernel`]). A packet the
//! kernel wrote becomes an Ethernet frame to that interface's MAC address and goes
//! into the same batch as the ports' frames ([`Joined`]), so NAT, tunnels, PPPoE,
//! VLANs, fragmentation and ICMP errors all treat it the same way. Frames core
//! generates for a kernel interface (ICMP errors about the kernel's packets) are
//! caught by [`WithKernel`] and written to its pipe without the Ethernet header.

use std::convert::Infallible;

use ruster_core::{
    BatchCompletion, GeneratedAllocationError, GeneratedBatchCompletion, GeneratedPacketBatch,
    GeneratedPacketIo, GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion, IfId,
    MacAddress, PacketBatch, PacketLease, PacketSlot, SlotCompletion,
};

const ETHERNET_HEADER: usize = 14;

/// Room before a kernel packet for the headers core may add (an IPv6 header for a
/// tunnel, a PPPoE header, a VLAN tag).
const HEADROOM: usize = 64;

/// The MAC address of VRF `at`'s kernel interface.
pub(crate) fn interface_mac(at: usize) -> MacAddress {
    MacAddress([0x02, 0x72, 0x75, 0x6b, 0x00, at as u8])
}

/// The source MAC address of the frames made from VRF `at`'s kernel packets.
fn stack_mac(at: usize) -> MacAddress {
    MacAddress([0x02, 0x72, 0x75, 0x6b, 0x01, at as u8])
}

/// One kernel packet as a frame, with room in front.
pub(crate) struct Frame {
    ingress: IfId,
    buf: Vec<u8>,
    start: usize,
}

impl Frame {
    /// The frame for `packet` (an IP packet) from VRF `at`'s kernel interface.
    pub(crate) fn new(ingress: IfId, at: usize, packet: &[u8]) -> Self {
        let mut buf = vec![0; HEADROOM + ETHERNET_HEADER + packet.len()];
        let frame = &mut buf[HEADROOM..];
        frame[0..6].copy_from_slice(&interface_mac(at).0);
        frame[6..12].copy_from_slice(&stack_mac(at).0);
        let ethertype: [u8; 2] = if packet.first().is_some_and(|b| b >> 4 == 6) {
            [0x86, 0xdd]
        } else {
            [0x08, 0x00]
        };
        frame[12..14].copy_from_slice(&ethertype);
        frame[ETHERNET_HEADER..].copy_from_slice(packet);
        Self {
            ingress,
            buf,
            start: HEADROOM,
        }
    }

    /// `frame` (Ethernet) as it arrived on `ingress`: a packet the FE put back
    /// together.
    pub(crate) fn from_ethernet(ingress: IfId, frame: &[u8]) -> Self {
        let mut buf = vec![0; HEADROOM + frame.len()];
        buf[HEADROOM..].copy_from_slice(frame);
        Self {
            ingress,
            buf,
            start: HEADROOM,
        }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.buf[self.start..]
    }
}

/// How the kernel's frames in one batch ended.
#[derive(Default)]
pub(crate) struct Outcome {
    /// Frames to send out of a port, with the port.
    pub(crate) sent: Vec<(IfId, Frame)>,
    pub(crate) dropped: u64,
    /// Frames from the ports that core sent to a kernel interface (to the router's
    /// host: replies NAT turned back to the router's address), with the interface.
    pub(crate) to_kernel: Vec<(IfId, Vec<u8>)>,
}

/// A port batch followed by the kernel's frames.
pub(crate) struct Joined<'o, B> {
    pub(crate) ports: B,
    /// The kernel interfaces.
    pub(crate) kernel_ids: &'o [IfId],
    pub(crate) kernel: std::vec::IntoIter<Frame>,
    pub(crate) outcome: &'o mut Outcome,
    pub(crate) kernel_done: usize,
}

pub(crate) enum Slot<'a, S> {
    Port {
        slot: S,
        kernel_ids: &'a [IfId],
        outcome: &'a mut Outcome,
    },
    Kernel {
        frame: Option<Frame>,
        outcome: &'a mut Outcome,
        done: &'a mut usize,
    },
}

impl<B: PacketBatch> PacketBatch for Joined<'_, B> {
    type Error = B::Error;
    type Slot<'a>
        = Slot<'a, B::Slot<'a>>
    where
        Self: 'a;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        // Ports first; once they are empty, the kernel's frames.
        let kernel_ids = self.kernel_ids;
        if let Some(lease) = self.ports.next_packet() {
            let outcome = &mut *self.outcome;
            return Some(lease.map_slot(|slot| Slot::Port {
                slot,
                kernel_ids,
                outcome,
            }));
        }
        let frame = self.kernel.next()?;
        Some(PacketLease::new(Slot::Kernel {
            frame: Some(frame),
            outcome: self.outcome,
            done: &mut self.kernel_done,
        }))
    }

    fn finish(self) -> BatchCompletion<Self::Error> {
        let mut completion = self.ports.finish();
        // Kernel frames to send are sent by the FE after the batch; count them as
        // accepted here so the accounting stays whole.
        let sent = self.outcome.sent.len();
        completion.tx_requested += sent;
        completion.tx_accepted += sent;
        completion.recycled += self.kernel_done - sent;
        // Port frames core sent to a kernel interface: the backend took them back as
        // consumed (copied out), core counted them sent; the FE writes them.
        let to_kernel = self.outcome.to_kernel.len();
        completion.recycled -= to_kernel;
        completion.tx_requested += to_kernel;
        completion.tx_accepted += to_kernel;
        completion
    }
}

impl<S: PacketSlot> PacketSlot for Slot<'_, S> {
    fn ingress(&self) -> IfId {
        match self {
            Self::Port { slot, .. } => slot.ingress(),
            Self::Kernel { frame, .. } => frame.as_ref().expect("live kernel frame").ingress,
        }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Port { slot, .. } => slot.bytes_mut(),
            Self::Kernel { frame, .. } => {
                let frame = frame.as_mut().expect("live kernel frame");
                &mut frame.buf[frame.start..]
            }
        }
    }

    fn resize_front(&mut self, delta: isize) -> bool {
        match self {
            Self::Port { slot, .. } => slot.resize_front(delta),
            Self::Kernel { frame, .. } => {
                let frame = frame.as_mut().expect("live kernel frame");
                let start = frame.start as isize + delta;
                if start < 0 || start as usize > frame.buf.len() {
                    return false;
                }
                frame.start = start as usize;
                true
            }
        }
    }

    fn truncate(&mut self, len: usize) -> bool {
        match self {
            Self::Port { slot, .. } => slot.truncate(len),
            Self::Kernel { frame, .. } => {
                let frame = frame.as_mut().expect("live kernel frame");
                if len == 0 || frame.start + len > frame.buf.len() {
                    return false;
                }
                frame.buf.truncate(frame.start + len);
                true
            }
        }
    }

    fn complete(self, completion: SlotCompletion) {
        match self {
            Self::Port {
                mut slot,
                kernel_ids,
                outcome,
            } => match completion {
                // To the router's host: the FE writes it to the kernel's pipe.
                SlotCompletion::Transmit(egress) if kernel_ids.contains(&egress) => {
                    outcome.to_kernel.push((egress, slot.bytes_mut().to_vec()));
                    slot.complete(SlotCompletion::Consume(
                        ruster_core::ConsumeReason::LocalToControl,
                    ));
                }
                completion => slot.complete(completion),
            },
            Self::Kernel {
                mut frame,
                outcome,
                done,
            } => {
                *done += 1;
                let frame = frame.take().expect("kernel frame completed once");
                match completion {
                    SlotCompletion::Transmit(egress) => outcome.sent.push((egress, frame)),
                    SlotCompletion::Recycle(_) | SlotCompletion::LeaseAbandoned => {
                        outcome.dropped += 1;
                    }
                    // Copied out by core (to the kernel again, or fragmented).
                    SlotCompletion::Consume(_) => {}
                }
            }
        }
    }
}

/// The ports' generated frames, with the kernel interfaces' caught for their pipes.
pub(crate) struct WithKernel<'a, I> {
    pub(crate) io: &'a mut I,
    /// The backend's ports are the interfaces below this; the others (the kernel's,
    /// VLAN sub-interfaces, PPPoE sessions, tunnels) are caught, for the FE to
    /// send in its own way.
    pub(crate) ports: usize,
    /// Caught frames, with the interface they are for.
    pub(crate) caught: &'a mut Vec<(IfId, Vec<u8>)>,
}

pub(crate) enum Batch<'a, B> {
    Port(B),
    Kernel {
        egress: IfId,
        caught: &'a mut Vec<(IfId, Vec<u8>)>,
        completion: GeneratedBatchCompletion<Infallible>,
    },
}

pub(crate) enum GeneratedSlot<'a, S> {
    Port(S),
    Kernel {
        egress: IfId,
        bytes: Vec<u8>,
        caught: &'a mut Vec<(IfId, Vec<u8>)>,
        completion: &'a mut GeneratedBatchCompletion<Infallible>,
    },
}

impl<I: GeneratedPacketIo> GeneratedPacketIo for WithKernel<'_, I> {
    type Error = I::Error;
    type Batch<'a>
        = Batch<'a, I::Batch<'a>>
    where
        Self: 'a;

    fn begin_generated(&mut self, egress: IfId) -> Self::Batch<'_> {
        if usize::from(egress.0) >= self.ports {
            Batch::Kernel {
                egress,
                caught: self.caught,
                completion: GeneratedBatchCompletion {
                    attempts: 0,
                    allocated: 0,
                    failed: 0,
                    requested: 0,
                    cancelled: 0,
                    abandoned: 0,
                    accepted: 0,
                    rejected: 0,
                    error: None,
                },
            }
        } else {
            Batch::Port(self.io.begin_generated(egress))
        }
    }
}

impl<B: GeneratedPacketBatch> GeneratedPacketBatch for Batch<'_, B> {
    type Error = B::Error;
    type Slot<'a>
        = GeneratedSlot<'a, B::Slot<'a>>
    where
        Self: 'a;

    fn allocate(
        &mut self,
        frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {
        match self {
            Self::Port(batch) => batch
                .allocate(frame_len)
                .map(|lease| lease.map_slot(GeneratedSlot::Port)),
            Self::Kernel {
                egress,
                caught,
                completion,
            } => {
                completion.attempts += 1;
                if frame_len <= ETHERNET_HEADER {
                    completion.failed += 1;
                    return Err(GeneratedAllocationError::ZeroLength);
                }
                completion.allocated += 1;
                Ok(GeneratedPacketLease::new(GeneratedSlot::Kernel {
                    egress: *egress,
                    bytes: vec![0; frame_len],
                    caught,
                    completion,
                }))
            }
        }
    }

    fn check_capacity(
        &mut self,
        frames: usize,
        frame_len: usize,
    ) -> Result<(), GeneratedAllocationError> {
        match self {
            Self::Port(batch) => batch.check_capacity(frames, frame_len),
            Self::Kernel { .. } if frames > 0 && frame_len == 0 => {
                Err(GeneratedAllocationError::ZeroLength)
            }
            Self::Kernel { .. } => Ok(()),
        }
    }

    fn finish(self) -> GeneratedBatchCompletion<Self::Error> {
        match self {
            Self::Port(batch) => batch.finish(),
            Self::Kernel { completion, .. } => GeneratedBatchCompletion {
                attempts: completion.attempts,
                allocated: completion.allocated,
                failed: completion.failed,
                requested: completion.requested,
                cancelled: completion.cancelled,
                abandoned: completion.abandoned,
                accepted: completion.accepted,
                rejected: completion.rejected,
                error: None,
            },
        }
    }
}

impl<S: GeneratedPacketSlot> GeneratedPacketSlot for GeneratedSlot<'_, S> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Port(slot) => slot.bytes_mut(),
            Self::Kernel { bytes, .. } => bytes,
        }
    }

    fn complete(self, completion: GeneratedSlotCompletion) {
        match self {
            Self::Port(slot) => slot.complete(completion),
            Self::Kernel {
                egress,
                bytes,
                caught,
                completion: counts,
            } => match completion {
                GeneratedSlotCompletion::Transmit => {
                    counts.requested += 1;
                    counts.accepted += 1;
                    caught.push((egress, bytes));
                }
                GeneratedSlotCompletion::Cancelled => counts.cancelled += 1,
                GeneratedSlotCompletion::Abandoned => counts.abandoned += 1,
            },
        }
    }
}
