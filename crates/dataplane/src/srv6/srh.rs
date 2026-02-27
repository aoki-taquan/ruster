//! Segment Routing Header (SRH) parsing and serialization.
//!
//! RFC-REF: RFC 8754 Section 2
//! The Segment Routing Header (SRH) is a new type of the IPv6
//! Routing Header (Routing Type = 4) defined in RFC 8200.
//!
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Next Header   |  Hdr Ext Len  | Routing Type  | Segments Left |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Last Entry   |     Flags     |              Tag              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |            Segment List\[0\] (128-bit IPv6 address)           |
//! |                                                               |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                         ...                                   |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |            Segment List\[n\] (128-bit IPv6 address)           |
//! |                                                               |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

use super::Srv6DropReason;

/// SRH Routing Type value.
///
/// RFC-REF: RFC 8754 Section 2
/// "Routing Type: 4"
pub const SRH_ROUTING_TYPE: u8 = 4;

/// SRH fixed header length (before segment list): 8 bytes.
pub const SRH_FIXED_HEADER_LEN: usize = 8;

/// Size of a single SID in the segment list: 16 bytes (128-bit IPv6 address).
pub const SID_SIZE: usize = 16;

/// IPv6 next-header value for Routing Header.
///
/// RFC-REF: RFC 8200 Section 4.4
/// "Routing Header: Next Header value = 43"
pub const IPV6_NH_ROUTING: u8 = 43;

/// Parsed Segment Routing Header.
///
/// RFC-REF: RFC 8754 Section 2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srh {
    /// Next Header field: identifies the type of header immediately
    /// following the SRH.
    pub next_header: u8,

    /// Hdr Ext Len: length of the SRH in 8-octet units, not including
    /// the first 8 octets.
    pub hdr_ext_len: u8,

    /// Routing Type: must be 4 for SRH.
    pub routing_type: u8,

    /// Segments Left: index (in the Segment List) of the current
    /// active segment. Decremented at each segment endpoint.
    pub segments_left: u8,

    /// Last Entry: index (zero-based) of the last element of the
    /// Segment List.
    pub last_entry: u8,

    /// Flags: 8 bits of flags (currently unused, must be 0).
    pub flags: u8,

    /// Tag: 16-bit tag field for grouping SRH packets.
    pub tag: u16,

    /// Segment List: ordered list of 128-bit SIDs.
    /// Segment List\[0\] contains the last segment in the path (the final
    /// destination). Segment List\[Last Entry\] contains the first segment.
    ///
    /// RFC-REF: RFC 8754 Section 2
    /// "The Segment List is encoded starting from the last segment of the
    /// SR Policy."
    pub segment_list: Vec<[u8; 16]>,

    /// Total byte length of the SRH (including the 8-byte fixed header).
    pub total_len: usize,
}

impl Srh {
    /// Parse an SRH from a byte slice.
    ///
    /// `data` must start at the first byte of the SRH (the Next Header field).
    ///
    /// # Errors
    ///
    /// Returns [`Srv6DropReason`] if the SRH is malformed.
    pub fn parse(data: &[u8]) -> Result<Self, Srv6DropReason> {
        if data.len() < SRH_FIXED_HEADER_LEN {
            return Err(Srv6DropReason::SrhTooShort);
        }

        let next_header = data[0];
        let hdr_ext_len = data[1];
        let routing_type = data[2];
        let segments_left = data[3];
        let last_entry = data[4];
        let flags = data[5];
        let tag = u16::from_be_bytes([data[6], data[7]]);

        // RFC-REF: RFC 8754 Section 2
        // "Routing Type: 4"
        if routing_type != SRH_ROUTING_TYPE {
            return Err(Srv6DropReason::InvalidRoutingType {
                found: routing_type,
            });
        }

        // RFC-REF: RFC 8754 Section 2
        // The total length of the SRH is (Hdr Ext Len + 1) * 8 bytes.
        let total_len = (hdr_ext_len as usize + 1) * 8;
        if data.len() < total_len {
            return Err(Srv6DropReason::SrhTooShort);
        }

        // The segment list occupies total_len - 8 bytes.
        let segment_data_len = total_len - SRH_FIXED_HEADER_LEN;
        if !segment_data_len.is_multiple_of(SID_SIZE) {
            // RFC-DEVIATION:
            // reason: We reject SRH with TLVs for simplicity in v0.1
            // impact: Packets with SRH TLVs will be dropped
            // issue: #160
            // plan: v0.2 で SRH TLV parsing を実装
            return Err(Srv6DropReason::InvalidSegmentListLength);
        }

        let num_segments = segment_data_len / SID_SIZE;

        // RFC-REF: RFC 8754 Section 4.1.1
        // "If Segments Left is greater than Last Entry, send an ICMP
        // Parameter Problem [...] and discard the packet."
        if segments_left > last_entry {
            return Err(Srv6DropReason::SegmentsLeftExceedsLastEntry);
        }

        // Validate that Last Entry matches actual segment count.
        if last_entry as usize + 1 != num_segments {
            return Err(Srv6DropReason::InvalidLastEntry);
        }

        let mut segment_list = Vec::with_capacity(num_segments);
        for i in 0..num_segments {
            let offset = SRH_FIXED_HEADER_LEN + i * SID_SIZE;
            let mut sid = [0u8; 16];
            sid.copy_from_slice(&data[offset..offset + SID_SIZE]);
            segment_list.push(sid);
        }

        Ok(Self {
            next_header,
            hdr_ext_len,
            routing_type,
            segments_left,
            last_entry,
            flags,
            tag,
            segment_list,
            total_len,
        })
    }

    /// Serialize the SRH to a byte vector.
    ///
    /// This produces a valid SRH that can be inserted into an IPv6 packet.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.total_len);

        buf.push(self.next_header);
        buf.push(self.hdr_ext_len);
        buf.push(self.routing_type);
        buf.push(self.segments_left);
        buf.push(self.last_entry);
        buf.push(self.flags);
        buf.extend_from_slice(&self.tag.to_be_bytes());

        for sid in &self.segment_list {
            buf.extend_from_slice(sid);
        }

        buf
    }

    /// Create a new SRH with the given segment list.
    ///
    /// `next_header` is the protocol number of the header following the SRH.
    /// The segment list should be ordered with the final destination at
    /// index 0 and the first hop at the last index.
    pub fn new(next_header: u8, segment_list: Vec<[u8; 16]>) -> Self {
        assert!(!segment_list.is_empty(), "segment list must not be empty");
        let last_entry = (segment_list.len() - 1) as u8;
        let segments_left = last_entry;
        // Hdr Ext Len = ((8 + num_segments * 16) / 8) - 1
        let total_len = SRH_FIXED_HEADER_LEN + segment_list.len() * SID_SIZE;
        let hdr_ext_len = ((total_len / 8) - 1) as u8;

        Self {
            next_header,
            hdr_ext_len,
            routing_type: SRH_ROUTING_TYPE,
            segments_left,
            last_entry,
            flags: 0,
            tag: 0,
            segment_list,
            total_len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal SRH with 2 segments.
    fn make_srh_bytes(next_header: u8, segments_left: u8) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(next_header); // Next Header (e.g., TCP=6)
        buf.push(4); // Hdr Ext Len: (8 + 2*16)/8 - 1 = 4
        buf.push(SRH_ROUTING_TYPE); // Routing Type: 4
        buf.push(segments_left); // Segments Left
        buf.push(1); // Last Entry: 1 (2 segments, index 0 and 1)
        buf.push(0); // Flags
        buf.extend_from_slice(&[0x00, 0x00]); // Tag

        // Segment List[0]: fd00::1 (final destination)
        let sid0: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        buf.extend_from_slice(&sid0);

        // Segment List[1]: fd00::2 (first hop)
        let sid1: [u8; 16] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        buf.extend_from_slice(&sid1);

        buf
    }

    #[test]
    fn parse_valid_srh() {
        let data = make_srh_bytes(6, 1);
        let srh = Srh::parse(&data).unwrap();

        assert_eq!(srh.next_header, 6);
        assert_eq!(srh.hdr_ext_len, 4);
        assert_eq!(srh.routing_type, SRH_ROUTING_TYPE);
        assert_eq!(srh.segments_left, 1);
        assert_eq!(srh.last_entry, 1);
        assert_eq!(srh.flags, 0);
        assert_eq!(srh.tag, 0);
        assert_eq!(srh.segment_list.len(), 2);
        assert_eq!(
            srh.segment_list[0],
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(
            srh.segment_list[1],
            [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
        );
        assert_eq!(srh.total_len, 40); // 8 + 2*16
    }

    #[test]
    fn parse_srh_too_short() {
        let data = [0u8; 7]; // less than 8 bytes
        assert_eq!(Srh::parse(&data), Err(Srv6DropReason::SrhTooShort));
    }

    #[test]
    fn parse_srh_wrong_routing_type() {
        let mut data = make_srh_bytes(6, 1);
        data[2] = 3; // wrong routing type
        assert_eq!(
            Srh::parse(&data),
            Err(Srv6DropReason::InvalidRoutingType { found: 3 })
        );
    }

    #[test]
    fn parse_srh_truncated_segment_list() {
        let data = make_srh_bytes(6, 1);
        // Truncate to only include header + 1 segment (need 2)
        let truncated = &data[..24]; // 8 + 16 = 24 (but need 8 + 32 = 40)
        assert_eq!(Srh::parse(truncated), Err(Srv6DropReason::SrhTooShort));
    }

    #[test]
    fn parse_srh_segments_left_exceeds_last_entry() {
        let data = make_srh_bytes(6, 2); // segments_left=2 > last_entry=1
        assert_eq!(
            Srh::parse(&data),
            Err(Srv6DropReason::SegmentsLeftExceedsLastEntry)
        );
    }

    #[test]
    fn serialize_round_trip() {
        let data = make_srh_bytes(6, 1);
        let srh = Srh::parse(&data).unwrap();
        let serialized = srh.serialize();
        assert_eq!(data, serialized);
    }

    #[test]
    fn new_srh() {
        let sid0 = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let sid1 = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let srh = Srh::new(6, vec![sid0, sid1]);

        assert_eq!(srh.next_header, 6);
        assert_eq!(srh.routing_type, SRH_ROUTING_TYPE);
        assert_eq!(srh.segments_left, 1);
        assert_eq!(srh.last_entry, 1);
        assert_eq!(srh.segment_list.len(), 2);
        assert_eq!(srh.total_len, 40);

        // Verify serialize produces valid output
        let bytes = srh.serialize();
        let parsed = Srh::parse(&bytes).unwrap();
        assert_eq!(parsed, srh);
    }

    #[test]
    fn new_srh_single_segment() {
        let sid = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let srh = Srh::new(59, vec![sid]); // NH=59 (No Next Header)

        assert_eq!(srh.segments_left, 0);
        assert_eq!(srh.last_entry, 0);
        assert_eq!(srh.total_len, 24); // 8 + 16
    }
}
