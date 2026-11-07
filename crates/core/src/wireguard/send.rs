//! WireGuard's send side in the forwarding path. A packet routed to a WireGuard
//! interface is sealed into its outer Ethernet frame right away and kept in a
//! staging area; after the batch the frames are copied into generated frames and
//! sent ([`execute_one_wireguard_send`]), the way IPv4 fragments are. The received
//! frame cannot grow at its tail, so the frame that leaves is a new one.
//!
//! # Standards
//!
//! See [`super`] and [`super::peer`].
//!
//! Deviations:
//!
//! - The outer packet is routed by the snapshot's own IPv4 table and leaves a plain
//!   port: an endpoint reached through a VLAN sub-interface or a PPPoE session is
//!   not supported yet.
//! - An outer packet longer than the egress MTU is dropped (it carries DF).
//! - An endpoint whose MAC address is not in the neighbor table is dropped: the
//!   resolution request for it is not sent yet.

use core::marker::PhantomData;
use std::rc::Rc;

use super::{encapsulate, PeerState, SendError, WireguardInterface, OUTER_HEADERS_LEN};
use crate::{
    DropReason, GeneratedBatchCompletion, GeneratedPacketBatch, GeneratedPacketIo, IfId,
    PacketLease, PacketSlot,
};

const ETHERNET: usize = 14;
const IPV4_ETHERTYPE: [u8; 2] = [0x08, 0x00];

/// Why staging storage was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireguardStorageError {
    /// `bytes` is not `slots.len()` equal slots, or a slot cannot hold an
    /// Ethernet frame with the outer headers.
    SlotBytes,
}

/// One staged frame.
#[derive(Clone, Copy, Debug, Default)]
pub struct WireguardStagedFrame {
    egress: Option<IfId>,
    len: u16,
}

/// What the send side did, since it was made.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WireguardSendCounters {
    pub staged: u64,
    pub sent: u64,
    pub dropped_unavailable: u64,
    pub dropped_over_budget: u64,
}

/// The staging area of sealed frames, over storage the caller provides: no
/// allocation per packet. A worker owns one.
///
/// ```compile_fail
/// fn require_send<T: Send>() {}
/// require_send::<ruster_core::wireguard::WireguardSendRuntime<'static>>();
/// ```
pub struct WireguardSendRuntime<'a> {
    slots: &'a mut [WireguardStagedFrame],
    bytes: &'a mut [u8],
    slot_bytes: usize,
    head: usize,
    len: usize,
    counters: WireguardSendCounters,
    _worker_local: PhantomData<Rc<()>>,
}

impl<'a> WireguardSendRuntime<'a> {
    pub fn new(
        slots: &'a mut [WireguardStagedFrame],
        bytes: &'a mut [u8],
    ) -> Result<Self, WireguardStorageError> {
        let slot_bytes = if slots.is_empty() {
            0
        } else {
            bytes.len() / slots.len()
        };
        if slot_bytes * slots.len() != bytes.len()
            || (!slots.is_empty() && slot_bytes < ETHERNET + OUTER_HEADERS_LEN + 32)
        {
            return Err(WireguardStorageError::SlotBytes);
        }
        Ok(Self {
            slots,
            bytes,
            slot_bytes,
            head: 0,
            len: 0,
            counters: WireguardSendCounters::default(),
            _worker_local: PhantomData,
        })
    }

    pub fn counters(&self) -> WireguardSendCounters {
        self.counters
    }

    /// Frames staged and not yet sent.
    pub fn pending(&self) -> usize {
        self.len
    }

    fn slot_index(&self, offset: usize) -> usize {
        (self.head + offset) % self.slots.len()
    }

    /// The free slot to build the next frame in, if there is one.
    fn next_free(&mut self) -> Option<(usize, &mut [u8])> {
        if self.len == self.slots.len() {
            return None;
        }
        let index = self.slot_index(self.len);
        let start = index * self.slot_bytes;
        Some((index, &mut self.bytes[start..start + self.slot_bytes]))
    }

    fn commit(&mut self, index: usize, egress: IfId, len: usize) {
        self.slots[index] = WireguardStagedFrame {
            egress: Some(egress),
            len: len as u16,
        };
        self.len += 1;
        self.counters.staged += 1;
    }

    fn take_front(&mut self) -> Option<(IfId, usize, usize)> {
        if self.len == 0 {
            return None;
        }
        let index = self.head;
        let slot = self.slots[index];
        self.head = (self.head + 1) % self.slots.len();
        self.len -= 1;
        Some((
            slot.egress.expect("a staged slot has its egress"),
            index * self.slot_bytes,
            usize::from(slot.len),
        ))
    }
}

/// The WireGuard interface whose interface id is `egress`.
pub(crate) fn of<'s, 'a>(
    interfaces: &'s [WireguardInterface<'a>],
    egress: IfId,
) -> Option<&'s WireguardInterface<'a>> {
    interfaces.iter().find(|w| w.interface == egress)
}

/// Seals the forwarded IPv4 `packet` (already rewritten for the WireGuard
/// interface) into an outer frame in `runtime`. The received frame is then the
/// caller's to consume.
pub(crate) fn stage<S: PacketSlot>(
    packet: &mut PacketLease<S>,
    wireguard: &WireguardInterface<'_>,
    snapshot: &crate::ForwardingSnapshot<'_>,
    states: &mut [PeerState],
    runtime: &mut WireguardSendRuntime<'_>,
) -> Result<(), DropReason> {
    let bytes = packet.bytes_mut();
    if bytes.len() < ETHERNET + 20 || bytes[12..14] != IPV4_ETHERTYPE {
        return Err(DropReason::WireguardInnerInvalid);
    }
    let total = usize::from(u16::from_be_bytes([
        bytes[ETHERNET + 2],
        bytes[ETHERNET + 3],
    ]));
    if total < 20 || ETHERNET + total > bytes.len() {
        return Err(DropReason::WireguardInnerInvalid);
    }
    let inner = &bytes[ETHERNET..ETHERNET + total];
    let destination = [inner[16], inner[17], inner[18], inner[19]];
    let peer = wireguard
        .config
        .peer_for_destination(destination)
        .ok_or(DropReason::WireguardNoPeer)?;
    let endpoint = wireguard.config.peers[peer].endpoint;
    let origin = snapshot
        .origin(std::net::IpAddr::V4(endpoint.into()))
        .ok_or(DropReason::WireguardNoRoute)?;
    if crate::pppoe::of(snapshot.pppoe, origin.egress).is_some()
        || snapshot.vlans.iter().any(|v| v.sub == origin.egress)
    {
        return Err(DropReason::WireguardUnderlyingUnsupported);
    }
    let mac = origin
        .destination_mac
        .ok_or(DropReason::NeighborUnresolved)?;
    let mtu = snapshot
        .interface(origin.egress)
        .ok_or(DropReason::InterfaceMiss)?
        .mtu;
    let end = wireguard.first_peer + wireguard.config.peers.len();
    let peers = states
        .get_mut(wireguard.first_peer..end)
        .ok_or(DropReason::WireguardNoSession)?;
    let (index, slot) = runtime.next_free().ok_or(DropReason::WireguardQueueFull)?;
    // The sealed outer packet is the headers, the WireGuard header, the padded
    // inner packet and the tag.
    let outer = OUTER_HEADERS_LEN + super::HEADER_LEN + super::padded_len(total) + 16;
    if outer > usize::from(mtu) {
        return Err(DropReason::WireguardMtuExceeded);
    }
    if ETHERNET + outer > slot.len() {
        return Err(DropReason::WireguardNoRoom);
    }
    let length = match encapsulate(&wireguard.config, peers, inner, &mut slot[ETHERNET..]) {
        Ok((_, length)) => length,
        Err(SendError::NoPeer) => return Err(DropReason::WireguardNoPeer),
        Err(SendError::NoSession | SendError::Exhausted) => {
            return Err(DropReason::WireguardNoSession)
        }
        Err(SendError::NoRoom) => return Err(DropReason::WireguardNoRoom),
        Err(SendError::InnerInvalid) => return Err(DropReason::WireguardInnerInvalid),
    };
    slot[0..6].copy_from_slice(&mac.0);
    slot[6..12].copy_from_slice(&origin.source_mac.0);
    slot[12..14].copy_from_slice(&IPV4_ETHERTYPE);
    runtime.commit(index, origin.egress, ETHERNET + length);
    Ok(())
}

/// What happened to one staged frame.
#[derive(Debug, Eq, PartialEq)]
pub struct GeneratedWireguardReport<E> {
    pub egress: IfId,
    /// `None` when it was not tried (over the tick's frame budget).
    pub completion: Option<GeneratedBatchCompletion<E>>,
    pub sent: bool,
}

/// Sends the oldest staged frame as a generated frame. `frame_budget` is the
/// tick's generated frames left. Returns `None` when nothing is staged.
pub fn execute_one_wireguard_send<I>(
    io: &mut I,
    runtime: &mut WireguardSendRuntime<'_>,
    frame_budget: &mut usize,
) -> Option<GeneratedWireguardReport<I::Error>>
where
    I: GeneratedPacketIo,
{
    let (egress, start, len) = runtime.take_front()?;
    if *frame_budget == 0 {
        runtime.counters.dropped_over_budget += 1;
        return Some(GeneratedWireguardReport {
            egress,
            completion: None,
            sent: false,
        });
    }
    *frame_budget -= 1;
    let staged = &runtime.bytes[start..start + len];
    let mut batch = io.begin_generated(egress);
    let sent = match batch.check_capacity(1, len) {
        Err(_) => false,
        Ok(()) => match batch.allocate(len) {
            Ok(mut lease) => {
                if lease.bytes_mut().len() == len {
                    lease.bytes_mut().copy_from_slice(staged);
                    lease.commit();
                    true
                } else {
                    lease.cancel();
                    false
                }
            }
            Err(_) => false,
        },
    };
    let completion = batch.finish();
    if sent {
        runtime.counters.sent += 1;
    } else {
        runtime.counters.dropped_unavailable += 1;
    }
    Some(GeneratedWireguardReport {
        egress,
        completion: Some(completion),
        sent,
    })
}
