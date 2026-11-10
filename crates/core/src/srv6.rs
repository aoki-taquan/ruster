//! SRv6: the router's own SIDs (segment identifiers).
//!
//! A [`Srv6Table`] given with
//! [`with_srv6`](crate::ForwardingSnapshot::with_srv6) holds the router's local SIDs.
//! An IPv6 packet that arrives in the default VRF, to the receiving interface's MAC
//! address, whose destination is one of them is handled by the SID's behaviour
//! before it is routed; every other packet is left alone (a transit node does not
//! look at the Segment Routing Header, RFC 8754 section 4.2).
//!
//! # Standards
//!
//! - RFC 8754 section 2: the Segment Routing Header (Routing Type 4) is read: Hdr Ext
//!   Len, Segments Left, Last Entry and the Segment List. Its flags, tag and TLVs
//!   are not looked at (section 4.3.1.1.1: no TLV processing is configured).
//! - RFC 8754 section 4.3.1.1 and RFC 8986 section 4.1 (End): with Segments Left
//!   0 the next header is processed; otherwise a Hop Limit of 1 or less gets Time
//!   Exceeded (code 0), and a Last Entry beyond the header or a Segments Left
//!   above Last Entry + 1 gets Parameter Problem code 0 pointing at Segments Left.
//!   Otherwise Segments Left is decremented, Segment List[Segments Left] becomes the
//!   destination and the packet is routed in the default VRF; the routing
//!   decrements the Hop Limit (S12). A new destination that is again a local SID is
//!   handled again, up to [`MAX_LOCAL_SEGMENTS`] times in all, each decrementing the
//!   Hop Limit once more.
//! - RFC 8986 section 4.2 (End.X): the same, but the packet leaves through the
//!   SID's interface to its next hop, without a route lookup.
//! - RFC 8986 section 4.6 (End.DT6) and 4.7 (End.DT4): a Segments Left other than
//!   0 gets Parameter Problem code 0 pointing at Segments Left. An upper-layer
//!   header 41 (End.DT6) or 4 (End.DT4) is unwrapped: the outer IPv6 header and its
//!   extension headers are taken off and the inner packet is routed in the SID's
//!   VRF, as a packet received on the same interface (its TTL or Hop Limit is
//!   decremented as any forwarded packet's).
//! - RFC 8986 section 4.1.1 and RFC 8754 section 4.3.1.2: any other upper-layer
//!   header, or No Next Header, gets Parameter Problem code 4 (SR Upper-layer
//!   Header Error) pointing at it. No upper-layer header is allowed by
//!   configuration, so an Echo Request to a SID is answered with this error too.
//! - RFC 8200 section 4.4: a Routing header of another type in a packet to a SID is
//!   stepped over when its Segments Left is 0, and gets Parameter Problem code 0
//!   pointing at its Routing Type otherwise.
//! - RFC 8200 section 4: Hop-by-Hop and Destination Options headers are stepped
//!   over, at most [`MAX_EXTENSION_HEADERS`] extension headers in all.
//!
//! Deviations:
//!
//! - The SIDs are the default VRF's; the router does not take SIDs in another VRF.
//! - A fragment to a SID (a Fragment header before the upper-layer header) is
//!   dropped: it is not put back together.
//! - No HMAC (RFC 8754 section 2.1.2) is checked, and the source address is not
//!   checked (RFC 8754 section 5.1 places that in the access lists at the edges of
//!   the SR domain; the forward firewall can do it for traffic it guards).
//! - A packet unwrapped by End.DT4 or End.DT6 whose inner destination is the
//!   router's (in the SID's VRF) is dropped, not delivered: its way to the kernel
//!   follows the VRF of the interface it came in on.
//! - A SID whose VRF the snapshot does not have drops its packets.
//! - The ICMPv6 errors are rate limited and routed as the others (`crate::ipv6`).

use crate::{DropReason, IfId, PacketLease, PacketSlot};

const ETHERNET: usize = 14;
const IPV6_HEADER: usize = 40;
const IPV4_ETHERTYPE: [u8; 2] = [0x08, 0x00];
const IPV6_ETHERTYPE: [u8; 2] = [0x86, 0xdd];
const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const DESTINATION_OPTIONS: u8 = 60;
const IPV4: u8 = 4;
const IPV6: u8 = 41;
/// The Routing Type of the Segment Routing Header (RFC 8754 section 2).
const SEGMENT_ROUTING: u8 = 4;
const TIME_EXCEEDED: u8 = 3;
const PARAMETER_PROBLEM: u8 = 4;
/// Parameter Problem code 0: erroneous header field encountered.
const ERRONEOUS_FIELD: u8 = 0;
/// Parameter Problem code 4: SR Upper-layer Header Error (RFC 8754 section 4.3.1.2).
const SR_UPPER_LAYER: u8 = 4;

/// Extension headers stepped over in a packet to a SID, at most.
const MAX_EXTENSION_HEADERS: usize = 8;
/// Local SIDs one packet goes through in a row, at most.
const MAX_LOCAL_SEGMENTS: usize = 4;

/// What the router does with a packet to one of its SIDs (RFC 8986 section 4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Srv6Behaviour {
    /// End (section 4.1): on to the next segment, routed in the default VRF.
    End,
    /// End.X (section 4.2): on to the next segment, out of `egress` to `next_hop`.
    EndX { egress: IfId, next_hop: [u8; 16] },
    /// End.DT6 (section 4.6): the inner IPv6 packet, routed in VRF `vrf` (an index
    /// into the snapshots of [`with_vrfs`](crate::ForwardingSnapshot::with_vrfs)).
    EndDt6 { vrf: u16 },
    /// End.DT4 (section 4.7): the inner IPv4 packet, routed in VRF `vrf`.
    EndDt4 { vrf: u16 },
}

/// One local SID: the addresses `prefix/len` (a SID, or a SID with its arguments).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Srv6Sid {
    prefix: [u8; 16],
    len: u8,
    behaviour: Srv6Behaviour,
}

/// Why a SID or SID table was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Srv6Error {
    PrefixLengthTooLong,
    HostBitsSet,
    /// Two SIDs for the same prefix.
    DuplicateSid,
}

impl Srv6Sid {
    pub fn new(prefix: [u8; 16], len: u8, behaviour: Srv6Behaviour) -> Result<Self, Srv6Error> {
        if len > 128 {
            return Err(Srv6Error::PrefixLengthTooLong);
        }
        if masked(prefix, len) != prefix {
            return Err(Srv6Error::HostBitsSet);
        }
        Ok(Self {
            prefix,
            len,
            behaviour,
        })
    }
}

/// The router's SRv6 tables.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Srv6Table {
    /// Longest prefix first.
    sids: Box<[Srv6Sid]>,
}

impl Srv6Table {
    pub fn new(mut sids: Vec<Srv6Sid>) -> Result<Self, Srv6Error> {
        sids.sort_by(|a, b| b.len.cmp(&a.len).then(a.prefix.cmp(&b.prefix)));
        if sids
            .windows(2)
            .any(|w| w[0].len == w[1].len && w[0].prefix == w[1].prefix)
        {
            return Err(Srv6Error::DuplicateSid);
        }
        Ok(Self { sids: sids.into() })
    }

    fn sid(&self, destination: [u8; 16]) -> Option<&Srv6Sid> {
        self.sids
            .iter()
            .find(|sid| masked(destination, sid.len) == sid.prefix)
    }
}

fn masked(address: [u8; 16], len: u8) -> [u8; 16] {
    let bits = u128::from_be_bytes(address);
    let mask = u128::MAX
        .checked_shl(128 - u32::from(len.min(128)))
        .unwrap_or(0);
    (bits & mask).to_be_bytes()
}

/// What [`receive`] did with a packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Received {
    /// Not to a local SID: left as it was.
    NotSid,
    /// On to its next segment, its destination rewritten: routed in the default
    /// VRF, or out of the interface and to the next hop `via` (End.X).
    Forward { via: Option<(IfId, [u8; 16])> },
    /// Unwrapped: the inner packet (Ethernet kept) is routed in VRF `vrf`.
    Unwrapped { vrf: u16 },
}

/// Why [`receive`] did not pass a packet on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Rejected {
    Drop(DropReason),
    /// Dropped, with an ICMPv6 error of this type, code and parameter to send
    /// about the packet (as received, or as the SIDs before rewrote it).
    Error(DropReason, u8, u8, u32),
}

/// The headers of a packet to a SID, as [`walk`] found them.
enum Chain {
    /// A Segment Routing Header at this offset (in the frame) with Segments Left
    /// other than 0.
    Segments(usize),
    /// The upper-layer header (or No Next Header): its type and offset.
    Upper(u8, usize),
}

/// Handles `packet` when it is to one of the router's SIDs: see the module
/// documentation. Only `snapshot`'s (the default VRF's) packets are looked at.
pub(crate) fn receive<S: PacketSlot>(
    packet: &mut PacketLease<S>,
    snapshot: &crate::ForwardingSnapshot<'_>,
) -> Result<Received, Rejected> {
    let Some(table) = snapshot.srv6.filter(|t| !t.sids.is_empty()) else {
        return Ok(Received::NotSid);
    };
    let ingress = packet.ingress();
    if snapshot.vrf_of(ingress) != 0 || snapshot.is_kernel_ingress(ingress) {
        return Ok(Received::NotSid);
    }
    let bytes = packet.bytes_mut();
    if bytes.len() < ETHERNET + IPV6_HEADER || bytes[12..14] != IPV6_ETHERTYPE {
        return Ok(Received::NotSid);
    }
    let ip = ETHERNET;
    if bytes[ip] >> 4 != 6 {
        return Ok(Received::NotSid);
    }
    let Some(mut sid) = table.sid(address(bytes, ip + 24)) else {
        return Ok(Received::NotSid);
    };
    // Only a frame sent to the receiving interface itself.
    let interface = snapshot
        .interface(ingress)
        .ok_or(Rejected::Drop(DropReason::Ipv6IngressInterfaceUnknown))?;
    if bytes[0..6] != interface.mac.0 {
        return Ok(Received::NotSid);
    }
    let payload = usize::from(u16::from_be_bytes([bytes[ip + 4], bytes[ip + 5]]));
    let end = ip + IPV6_HEADER + payload;
    if end > bytes.len() {
        return Err(Rejected::Drop(DropReason::Ipv6PayloadLengthExceedsPacket));
    }
    let bytes = &mut bytes[..end];
    for segment in 0..MAX_LOCAL_SEGMENTS {
        let chain = walk(bytes)?;
        match (sid.behaviour, chain) {
            (Srv6Behaviour::End | Srv6Behaviour::EndX { .. }, Chain::Segments(srh)) => {
                // RFC 8986 4.1 S05: before anything is changed. For a further SID
                // in a row, the Hop Limit counts the decrement the routing after
                // this still makes.
                if bytes[ip + 7] <= 1 + u8::from(segment > 0) {
                    return Err(Rejected::Error(
                        DropReason::Ipv6HopLimitExpired,
                        TIME_EXCEEDED,
                        0,
                        0,
                    ));
                }
                next_segment(bytes, srh)?;
                // The routing after this decrements the Hop Limit once (S12 of the
                // first SID); each further SID in a row decrements it here.
                if segment > 0 {
                    bytes[ip + 7] -= 1;
                }
                if let Srv6Behaviour::EndX { egress, next_hop } = sid.behaviour {
                    return Ok(Received::Forward {
                        via: Some((egress, next_hop)),
                    });
                }
                match table.sid(address(bytes, ip + 24)) {
                    Some(next) => sid = next,
                    None => return Ok(Received::Forward { via: None }),
                }
            }
            (Srv6Behaviour::EndDt4 { .. } | Srv6Behaviour::EndDt6 { .. }, Chain::Segments(srh)) => {
                return Err(segments_left_error(srh));
            }
            (Srv6Behaviour::EndDt4 { vrf }, Chain::Upper(IPV4, at))
            | (Srv6Behaviour::EndDt6 { vrf }, Chain::Upper(IPV6, at)) => {
                let target = snapshot
                    .vrf_snapshot(vrf)
                    .ok_or(Rejected::Drop(DropReason::Srv6VrfUnknown))?;
                // The inner packet must lie inside the outer one, and not be for the
                // router: such a packet would reach the kernel of the VRF its
                // ingress interface is in, not the SID's.
                let local = match bytes.get(at..) {
                    Some(inner) if inner.len() >= 20 && inner[0] >> 4 == 4 => {
                        let mut d = [0; 4];
                        d.copy_from_slice(&inner[16..20]);
                        target.is_local_ipv4(crate::Ipv4Address::from_octets(d))
                    }
                    Some(inner) if inner.len() >= IPV6_HEADER && inner[0] >> 4 == 6 => target
                        .ipv6
                        .is_some_and(|fib| fib.is_local(address(inner, 24))),
                    _ => return Err(Rejected::Drop(DropReason::Srv6HeaderInvalid)),
                };
                if local {
                    return Err(Rejected::Drop(DropReason::Srv6ToRouter));
                }
                unwrap(packet, at, end)?;
                return Ok(Received::Unwrapped { vrf });
            }
            (_, Chain::Upper(_, at)) => {
                return Err(Rejected::Error(
                    DropReason::Srv6ParameterProblem,
                    PARAMETER_PROBLEM,
                    SR_UPPER_LAYER,
                    pointer(at),
                ));
            }
        }
    }
    Err(Rejected::Drop(DropReason::Srv6HeaderInvalid))
}

fn address(frame: &[u8], at: usize) -> [u8; 16] {
    let mut out = [0; 16];
    out.copy_from_slice(&frame[at..at + 16]);
    out
}

/// The offset of `at` (in the frame) from the start of the IPv6 header, as an
/// ICMPv6 Parameter Problem points.
fn pointer(at: usize) -> u32 {
    u32::try_from(at - ETHERNET).unwrap_or(u32::MAX)
}

fn segments_left_error(srh: usize) -> Rejected {
    Rejected::Error(
        DropReason::Srv6ParameterProblem,
        PARAMETER_PROBLEM,
        ERRONEOUS_FIELD,
        pointer(srh + 3),
    )
}

/// Steps over the extension headers of the IPv6 packet `frame` (Ethernet, cut at
/// its Payload Length) to the first Segment Routing Header with segments left, or
/// to the upper-layer header.
fn walk(frame: &[u8]) -> Result<Chain, Rejected> {
    let invalid = Rejected::Drop(DropReason::Srv6HeaderInvalid);
    let mut next = frame[ETHERNET + 6];
    let mut at = ETHERNET + IPV6_HEADER;
    for _ in 0..MAX_EXTENSION_HEADERS {
        match next {
            HOP_BY_HOP | DESTINATION_OPTIONS | ROUTING => {
                let header = frame.get(at..at + 8).ok_or(invalid)?;
                let len = (usize::from(header[1]) + 1) * 8;
                if at + len > frame.len() {
                    return Err(invalid);
                }
                if next == ROUTING && header[3] != 0 {
                    if header[2] == SEGMENT_ROUTING {
                        return Ok(Chain::Segments(at));
                    }
                    // RFC 8200 4.4: an unrecognized Routing Type with segments left.
                    return Err(Rejected::Error(
                        DropReason::Srv6ParameterProblem,
                        PARAMETER_PROBLEM,
                        ERRONEOUS_FIELD,
                        pointer(at + 2),
                    ));
                }
                next = header[0];
                at += len;
            }
            FRAGMENT => return Err(invalid),
            upper => return Ok(Chain::Upper(upper, at)),
        }
    }
    Err(invalid)
}

/// RFC 8754 4.3.1.1 S09 to S16 on the Segment Routing Header at `srh`, whose
/// Segments Left is not 0: checks it, decrements Segments Left and copies the
/// segment it now points at to the destination address.
fn next_segment(frame: &mut [u8], srh: usize) -> Result<(), Rejected> {
    let length = i32::from(frame[srh + 1]);
    let max_last_entry = length / 2 - 1;
    let left = frame[srh + 3];
    let last_entry = frame[srh + 4];
    if i32::from(last_entry) > max_last_entry || u16::from(left) > u16::from(last_entry) + 1 {
        return Err(segments_left_error(srh));
    }
    let left = left - 1;
    frame[srh + 3] = left;
    let segment = srh + 8 + 16 * usize::from(left);
    frame.copy_within(segment..segment + 16, ETHERNET + 24);
    Ok(())
}

/// Takes the outer IPv6 header and its extension headers (up to `inner`, the
/// offset of the inner packet) off `packet`, keeping its Ethernet addresses. What
/// follows the outer packet (`end`) goes.
fn unwrap<S: PacketSlot>(
    packet: &mut PacketLease<S>,
    inner: usize,
    end: usize,
) -> Result<(), Rejected> {
    if !packet.truncate(end) {
        return Err(Rejected::Drop(DropReason::Srv6NoRoom));
    }
    let bytes = packet.bytes_mut();
    let version = bytes.get(inner).map(|b| b >> 4);
    let ethertype = match version {
        Some(4) => IPV4_ETHERTYPE,
        Some(6) => IPV6_ETHERTYPE,
        _ => return Err(Rejected::Drop(DropReason::Srv6HeaderInvalid)),
    };
    let outer = inner - ETHERNET;
    bytes.copy_within(0..12, outer);
    bytes[outer + 12..outer + 14].copy_from_slice(&ethertype);
    if !packet.resize_front(outer as isize) {
        return Err(Rejected::Drop(DropReason::Srv6NoRoom));
    }
    Ok(())
}
