//! Puts a tunnel's fragmented IPv6 packets back together, so that the tunnel's
//! inner IPv4 packet can be unwrapped (DS-Lite and MAP-E: the AFTR or BR fragments
//! the outer packet when the inner one is too big for the IPv6 path). Core passes
//! each such fragment up through the control queue; the whole packet goes into the
//! next batch as if it had arrived so, on the interface its fragments came in on.
//!
//! # Standards
//!
//! - RFC 6333 section 5.3 and RFC 2473 section 7.2: the tunnel end reassembles the
//!   outer packet before unwrapping it.
//! - RFC 8200 section 4.5: fragments are matched by source, destination and
//!   Identification; the unfragmentable part is the first fragment's; the
//!   reassembled packet's Payload Length covers the unfragmentable extension
//!   headers and the fragmentable part; a fragment whose length is not a multiple
//!   of 8 octets but is not the last is discarded; reassembly is abandoned 60
//!   seconds after the first fragment arrived.
//! - RFC 5722: a fragment that overlaps another discards the whole packet.
//!
//! Deviations: no ICMPv6 Time Exceeded (code 1) when reassembly times out, and no
//! Parameter Problem for a bad fragment length; at most [`MAX_PACKETS`] packets are
//! put together at a time (an older one is abandoned for a new one).

use ruster_core::IfId;

const ETHERNET: usize = 14;
const IPV6_HEADER: usize = 40;
const HOP_BY_HOP: u8 = 0;
const DESTINATION_OPTIONS: u8 = 60;
const FRAGMENT: u8 = 44;
/// Hop-by-Hop and Destination Options headers before the Fragment header, at most
/// (as core steps over).
const MAX_OPTION_HEADERS: usize = 2;
/// RFC 8200 4.5: reassembly is abandoned this long after the first fragment.
pub(crate) const TIMEOUT_MS: u64 = 60_000;
/// Packets put together at the same time, at most.
pub(crate) const MAX_PACKETS: usize = 64;

/// One packet being put together.
struct Packet {
    ingress: IfId,
    source: [u8; 16],
    destination: [u8; 16],
    identification: u32,
    started_ms: u64,
    /// The first fragment's Ethernet header and unfragmentable part, with the
    /// header before the Fragment header naming the fragment's next header.
    head: Option<Vec<u8>>,
    /// The fragmentable part's pieces: offset in bytes and the bytes.
    pieces: Vec<(usize, Vec<u8>)>,
    /// The fragmentable part's length, once the last fragment arrived.
    total: Option<usize>,
}

/// The packets being put together.
#[derive(Default)]
pub(crate) struct Reassembly {
    packets: Vec<Packet>,
}

/// A fragment's fields, from a frame core passed up.
struct Fragment<'a> {
    source: [u8; 16],
    destination: [u8; 16],
    identification: u32,
    offset: usize,
    more: bool,
    data: &'a [u8],
    /// The Ethernet header and unfragmentable part, and where in it the next
    /// header before the Fragment header is.
    head: &'a [u8],
    next_at: usize,
    next: u8,
}

fn parse(frame: &[u8]) -> Option<Fragment<'_>> {
    let ip = ETHERNET;
    if frame.len() < ip + IPV6_HEADER || frame[ip] >> 4 != 6 {
        return None;
    }
    let payload = usize::from(u16::from_be_bytes([frame[ip + 4], frame[ip + 5]]));
    let end = ip + IPV6_HEADER + payload;
    let frame = frame.get(..end)?;
    let mut next_at = ip + 6;
    let mut header = IPV6_HEADER;
    for _ in 0..MAX_OPTION_HEADERS {
        if !matches!(frame[next_at], HOP_BY_HOP | DESTINATION_OPTIONS) {
            break;
        }
        let length = *frame.get(ip + header + 1)?;
        next_at = ip + header;
        header += (usize::from(length) + 1) * 8;
    }
    if frame[next_at] != FRAGMENT {
        return None;
    }
    let fragment = frame.get(ip + header..ip + header + 8)?;
    let field = u16::from_be_bytes([fragment[2], fragment[3]]);
    let mut source = [0; 16];
    source.copy_from_slice(&frame[ip + 8..ip + 24]);
    let mut destination = [0; 16];
    destination.copy_from_slice(&frame[ip + 24..ip + 40]);
    Some(Fragment {
        source,
        destination,
        identification: u32::from_be_bytes([fragment[4], fragment[5], fragment[6], fragment[7]]),
        offset: usize::from(field >> 3) * 8,
        more: field & 1 == 1,
        data: &frame[ip + header + 8..],
        head: &frame[..ip + header],
        next_at,
        next: fragment[0],
    })
}

impl Reassembly {
    /// Adds the fragment in `frame` (Ethernet, as core passed it up) that came in
    /// on `ingress`. Returns the whole packet's frame once every fragment is in.
    pub(crate) fn add(&mut self, ingress: IfId, frame: &[u8], now_ms: u64) -> Option<Vec<u8>> {
        self.packets
            .retain(|p| now_ms.saturating_sub(p.started_ms) < TIMEOUT_MS);
        let fragment = parse(frame)?;
        // Not the last, and not a multiple of 8 octets: discarded (RFC 8200 4.5).
        if fragment.more && fragment.data.len() % 8 != 0 || fragment.data.is_empty() {
            return None;
        }
        let at = match self.packets.iter().position(|p| {
            p.ingress == ingress
                && p.source == fragment.source
                && p.destination == fragment.destination
                && p.identification == fragment.identification
        }) {
            Some(at) => at,
            None => {
                if self.packets.len() >= MAX_PACKETS {
                    self.packets.remove(0);
                }
                self.packets.push(Packet {
                    ingress,
                    source: fragment.source,
                    destination: fragment.destination,
                    identification: fragment.identification,
                    started_ms: now_ms,
                    head: None,
                    pieces: Vec::new(),
                    total: None,
                });
                self.packets.len() - 1
            }
        };
        let packet = &mut self.packets[at];
        let start = fragment.offset;
        let end = start + fragment.data.len();
        let beyond = packet.total.is_some_and(|total| end > total)
            || (!fragment.more
                && packet
                    .pieces
                    .iter()
                    .any(|(at, bytes)| at + bytes.len() > end))
            || (!fragment.more && packet.total.is_some_and(|total| total != end));
        let overlaps = packet
            .pieces
            .iter()
            .any(|(at, bytes)| start < at + bytes.len() && *at < end);
        // An overlap or a contradiction discards the whole packet (RFC 5722).
        let unfragmentable = fragment.head.len() - ETHERNET - IPV6_HEADER;
        if beyond || overlaps || unfragmentable + end > usize::from(u16::MAX) {
            self.packets.remove(at);
            return None;
        }
        if !fragment.more {
            packet.total = Some(end);
        }
        if start == 0 {
            let mut head = fragment.head.to_vec();
            head[fragment.next_at] = fragment.next;
            packet.head = Some(head);
        }
        packet.pieces.push((start, fragment.data.to_vec()));
        let total = packet.total?;
        packet.head.as_ref()?;
        let covered: usize = packet.pieces.iter().map(|(_, bytes)| bytes.len()).sum();
        if covered != total {
            return None;
        }
        let mut packet = self.packets.remove(at);
        packet.pieces.sort_by_key(|(at, _)| *at);
        let mut whole = packet.head.take().expect("checked above");
        let unfragmentable = whole.len() - ETHERNET - IPV6_HEADER;
        let payload = u16::try_from(unfragmentable + total).ok()?;
        whole[ETHERNET + 4..ETHERNET + 6].copy_from_slice(&payload.to_be_bytes());
        for (_, bytes) in packet.pieces {
            whole.extend_from_slice(&bytes);
        }
        Some(whole)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fragment of an IPv6 packet carrying IPv4 (Next Header 4).
    fn fragment(identification: u32, offset: usize, more: bool, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0_u8; ETHERNET + IPV6_HEADER + 8];
        frame[12..14].copy_from_slice(&[0x86, 0xdd]);
        let ip = ETHERNET;
        frame[ip] = 0x60;
        let payload = (8 + data.len()) as u16;
        frame[ip + 4..ip + 6].copy_from_slice(&payload.to_be_bytes());
        frame[ip + 6] = FRAGMENT;
        frame[ip + 7] = 64;
        frame[ip + 8] = 0x20;
        frame[ip + 24] = 0x30;
        frame[ip + 40] = 4;
        let field = ((offset / 8) as u16) << 3 | u16::from(more);
        frame[ip + 42..ip + 44].copy_from_slice(&field.to_be_bytes());
        frame[ip + 44..ip + 48].copy_from_slice(&identification.to_be_bytes());
        frame.extend_from_slice(data);
        frame
    }

    #[test]
    fn fragments_in_any_order_make_the_whole_packet() {
        let data: Vec<u8> = (0..40).collect();
        let mut reassembly = Reassembly::default();
        assert!(reassembly
            .add(IfId(1), &fragment(7, 24, false, &data[24..]), 0)
            .is_none());
        assert!(reassembly
            .add(IfId(1), &fragment(7, 8, true, &data[8..24]), 1)
            .is_none());
        let whole = reassembly
            .add(IfId(1), &fragment(7, 0, true, &data[..8]), 2)
            .expect("whole");
        assert_eq!(whole[ETHERNET + 6], 4, "Next Header is the fragment's");
        assert_eq!(u16::from_be_bytes([whole[18], whole[19]]), 40);
        assert_eq!(&whole[ETHERNET + IPV6_HEADER..], &data[..]);
        assert!(reassembly.packets.is_empty());
    }

    #[test]
    fn an_overlap_discards_the_packet() {
        let data = [1_u8; 32];
        let mut reassembly = Reassembly::default();
        assert!(reassembly
            .add(IfId(1), &fragment(7, 0, true, &data[..16]), 0)
            .is_none());
        assert!(reassembly
            .add(IfId(1), &fragment(7, 8, false, &data[8..]), 0)
            .is_none());
        assert!(reassembly.packets.is_empty());
    }

    #[test]
    fn fragments_of_other_packets_or_after_the_timeout_do_not_join() {
        let data = [1_u8; 16];
        let mut reassembly = Reassembly::default();
        reassembly.add(IfId(1), &fragment(7, 0, true, &data[..8]), 0);
        assert!(reassembly
            .add(IfId(1), &fragment(8, 8, false, &data[8..]), 0)
            .is_none());
        assert!(reassembly
            .add(IfId(2), &fragment(7, 8, false, &data[8..]), 0)
            .is_none());
        assert!(reassembly
            .add(IfId(1), &fragment(7, 8, false, &data[8..]), TIMEOUT_MS)
            .is_none());
    }

    #[test]
    fn a_short_fragment_that_is_not_the_last_is_discarded() {
        let mut reassembly = Reassembly::default();
        assert!(reassembly
            .add(IfId(1), &fragment(7, 0, true, &[1; 12]), 0)
            .is_none());
        assert!(reassembly.packets.is_empty());
    }
}
