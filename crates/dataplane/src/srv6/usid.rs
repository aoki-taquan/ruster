//! uSID (micro-SID) handling for compressed SRv6 segment lists.
//!
//! RFC-REF: RFC 8986 Section 4.3.1 (uN behavior)
//! uSID is a compressed SID format defined in
//! draft-ietf-spring-srv6-srh-compression. A 128-bit SID is divided
//! into a "block" prefix and one or more micro-segments (uSIDs).
//!
//! Layout (default: 32-bit block + 16-bit uSID):
//!
//! ```text
//! |<--- block_len --->|<-- usid_len -->|<-- usid_len -->|...|
//! |    Block Prefix   |   uSID #1     |   uSID #2     |...|
//! ```
//!
//! The uN endpoint behavior shifts the active uSID out and moves the
//! remaining uSIDs left within the same 128-bit container.

use super::config::Srv6Config;

/// Default uSID block length in bits.
pub const DEFAULT_BLOCK_LEN: u8 = 32;

/// Default uSID length in bits.
pub const DEFAULT_USID_LEN: u8 = 16;

/// uSID container: a 128-bit SID with block/uSID structure.
///
/// RFC-REF: RFC 8986 Section 4.3.1
/// The uSID container holds the block prefix and one or more
/// compressed micro-SIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsidContainer {
    /// The raw 128-bit SID.
    pub sid: [u8; 16],
    /// Block prefix length in bits (typically 32).
    pub block_len: u8,
    /// Individual uSID length in bits (typically 16).
    pub usid_len: u8,
}

impl UsidContainer {
    /// Create a new uSID container from a 128-bit SID.
    pub fn new(sid: [u8; 16], block_len: u8, usid_len: u8) -> Self {
        Self {
            sid,
            block_len,
            usid_len,
        }
    }

    /// Create a uSID container from a SID using the given SRv6 config.
    pub fn from_config(sid: [u8; 16], config: &Srv6Config) -> Self {
        Self::new(sid, config.block_len, config.usid_len)
    }

    /// Extract the block prefix (first `block_len` bits).
    ///
    /// Returns the block prefix as a 128-bit address with the block bits
    /// set and all other bits zeroed.
    pub fn block_prefix(&self) -> [u8; 16] {
        let mut prefix = [0u8; 16];
        let full_bytes = (self.block_len / 8) as usize;
        let remaining_bits = self.block_len % 8;

        prefix[..full_bytes].copy_from_slice(&self.sid[..full_bytes]);
        if remaining_bits > 0 && full_bytes < 16 {
            let mask = 0xFF << (8 - remaining_bits);
            prefix[full_bytes] = self.sid[full_bytes] & mask;
        }

        prefix
    }

    /// Extract the active (first) uSID value.
    ///
    /// The active uSID starts at bit offset `block_len` and is
    /// `usid_len` bits long. Returns the uSID as a u32 (the actual
    /// value is only `usid_len` bits, but fits in a u32 for all
    /// reasonable uSID sizes).
    pub fn active_usid(&self) -> u32 {
        self.extract_usid(0)
    }

    /// Extract the uSID at the given index (0-based, relative to
    /// the first uSID position after the block prefix).
    pub fn extract_usid(&self, index: u32) -> u32 {
        let bit_offset = self.block_len as u32 + index * self.usid_len as u32;
        extract_bits(&self.sid, bit_offset, self.usid_len)
    }

    /// Check if the active uSID is zero (indicating the end of the
    /// uSID container).
    ///
    /// RFC-REF: RFC 8986 Section 4.3.1
    /// "When the active uSID is all zeros, the next SID from the SRH
    /// Segment List is used."
    pub fn is_active_usid_zero(&self) -> bool {
        self.active_usid() == 0
    }

    /// Perform the uSID shift operation (uN behavior).
    ///
    /// RFC-REF: RFC 8986 Section 4.3.1
    /// The shift operation advances to the next micro-segment by:
    /// 1. Shifting the uSID portion left by `usid_len` bits
    /// 2. Filling the vacated position with zeros
    ///
    /// Returns a new SID with the shift applied.
    pub fn shift(&self) -> [u8; 16] {
        let mut result = self.sid;
        let block_bytes = (self.block_len / 8) as usize;
        let usid_bytes = (self.usid_len / 8) as usize;

        // RFC-DEVIATION:
        // reason: Only byte-aligned block_len and usid_len are supported
        // impact: Non-byte-aligned configurations are rejected at config time
        // issue: #160
        // plan: v0.2 で bit-granularity shift を実装

        // Shift the uSID region left by usid_len bits (= usid_bytes bytes).
        let usid_region_start = block_bytes;
        let usid_region_end = 16;
        let shift_amount = usid_bytes;

        if shift_amount > 0 && usid_region_start + shift_amount <= usid_region_end {
            for i in usid_region_start..(usid_region_end - shift_amount) {
                result[i] = result[i + shift_amount];
            }
            // Zero out the vacated bytes at the end.
            for byte in result
                .iter_mut()
                .take(usid_region_end)
                .skip(usid_region_end - shift_amount)
            {
                *byte = 0;
            }
        }

        result
    }

    /// Returns the maximum number of uSIDs that fit in this container
    /// (excluding the block prefix).
    pub fn max_usids(&self) -> u32 {
        let available_bits = 128 - self.block_len as u32;
        available_bits / self.usid_len as u32
    }
}

/// Extract `bit_count` bits starting at `bit_offset` from a 128-bit value.
fn extract_bits(data: &[u8; 16], bit_offset: u32, bit_count: u8) -> u32 {
    let mut result: u32 = 0;
    for i in 0..bit_count as u32 {
        let global_bit = bit_offset + i;
        let byte_idx = (global_bit / 8) as usize;
        let bit_idx = 7 - (global_bit % 8); // MSB first

        if byte_idx < 16 && (data[byte_idx] >> bit_idx) & 1 == 1 {
            result |= 1 << (bit_count as u32 - 1 - i);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a SID: fd00:0001:0002:0003:: (block=fd00::, usids=0001,0002,0003)
    fn make_usid_sid() -> [u8; 16] {
        [
            0xfd, 0x00, 0x00, 0x00, // block: fd00::/32
            0x00, 0x01, // uSID #0: 0x0001
            0x00, 0x02, // uSID #1: 0x0002
            0x00, 0x03, // uSID #2: 0x0003
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // remaining: zeros
        ]
    }

    #[test]
    fn block_prefix_extraction() {
        let sid = make_usid_sid();
        let container = UsidContainer::new(sid, 32, 16);
        let prefix = container.block_prefix();
        assert_eq!(
            prefix,
            [0xfd, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn active_usid_extraction() {
        let sid = make_usid_sid();
        let container = UsidContainer::new(sid, 32, 16);
        assert_eq!(container.active_usid(), 0x0001);
    }

    #[test]
    fn extract_usid_at_index() {
        let sid = make_usid_sid();
        let container = UsidContainer::new(sid, 32, 16);
        assert_eq!(container.extract_usid(0), 0x0001);
        assert_eq!(container.extract_usid(1), 0x0002);
        assert_eq!(container.extract_usid(2), 0x0003);
        assert_eq!(container.extract_usid(3), 0x0000);
    }

    #[test]
    fn is_active_usid_zero() {
        // SID with zero active uSID
        let sid = [0xfd, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let container = UsidContainer::new(sid, 32, 16);
        assert!(container.is_active_usid_zero());

        // SID with non-zero active uSID
        let sid2 = make_usid_sid();
        let container2 = UsidContainer::new(sid2, 32, 16);
        assert!(!container2.is_active_usid_zero());
    }

    #[test]
    fn usid_shift_operation() {
        let sid = make_usid_sid();
        let container = UsidContainer::new(sid, 32, 16);
        let shifted = container.shift();

        // After shift: block stays, uSIDs shift left by 16 bits
        // fd00:0002:0003:0000::
        assert_eq!(
            shifted,
            [
                0xfd, 0x00, 0x00, 0x00, // block preserved
                0x00, 0x02, // was uSID #1, now active
                0x00, 0x03, // was uSID #2
                0x00, 0x00, // was uSID #3 (zero)
                0x00, 0x00, // shifted in zeros
                0x00, 0x00, 0x00, 0x00,
            ]
        );

        // The new active uSID should be 0x0002
        let new_container = UsidContainer::new(shifted, 32, 16);
        assert_eq!(new_container.active_usid(), 0x0002);
    }

    #[test]
    fn usid_shift_until_zero() {
        let sid = make_usid_sid();
        let container = UsidContainer::new(sid, 32, 16);

        // Shift 3 times to exhaust all uSIDs
        let shifted1 = container.shift();
        let c1 = UsidContainer::new(shifted1, 32, 16);
        assert_eq!(c1.active_usid(), 0x0002);

        let shifted2 = c1.shift();
        let c2 = UsidContainer::new(shifted2, 32, 16);
        assert_eq!(c2.active_usid(), 0x0003);

        let shifted3 = c2.shift();
        let c3 = UsidContainer::new(shifted3, 32, 16);
        assert!(c3.is_active_usid_zero());
    }

    #[test]
    fn max_usids() {
        let sid = [0u8; 16];
        let container = UsidContainer::new(sid, 32, 16);
        // (128 - 32) / 16 = 6
        assert_eq!(container.max_usids(), 6);
    }

    #[test]
    fn max_usids_different_config() {
        let sid = [0u8; 16];
        // 48-bit block, 16-bit uSID
        let container = UsidContainer::new(sid, 48, 16);
        // (128 - 48) / 16 = 5
        assert_eq!(container.max_usids(), 5);
    }
}
