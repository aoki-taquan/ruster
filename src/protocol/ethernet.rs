//! Ethernet frame parsing and construction

use super::{EtherType, MacAddr, VlanTag};
use crate::{Error, Result};

/// Minimum Ethernet frame size (without FCS)
pub const MIN_FRAME_SIZE: usize = 14;
/// Maximum Ethernet frame size (without FCS, with VLAN tag)
pub const MAX_FRAME_SIZE: usize = 1522;

/// Parsed Ethernet frame (zero-copy reference)
#[derive(Debug)]
pub struct Frame<'a> {
    buffer: &'a [u8],
    vlan_tag: Option<VlanTag>,
    payload_offset: usize,
}

impl<'a> Frame<'a> {
    /// Parse an Ethernet frame from a buffer
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < MIN_FRAME_SIZE {
            return Err(Error::Parse("frame too short".into()));
        }

        let ethertype_offset = 12;
        let ethertype =
            u16::from_be_bytes([buffer[ethertype_offset], buffer[ethertype_offset + 1]]);

        let (vlan_tag, payload_offset) = if ethertype == EtherType::Vlan as u16 {
            if buffer.len() < 18 {
                return Err(Error::Parse("VLAN frame too short".into()));
            }
            let tag = VlanTag::from_bytes([buffer[14], buffer[15]]);
            (Some(tag), 18)
        } else {
            (None, 14)
        };

        Ok(Self {
            buffer,
            vlan_tag,
            payload_offset,
        })
    }

    pub fn dst_mac(&self) -> MacAddr {
        MacAddr(self.buffer[0..6].try_into().unwrap())
    }

    pub fn src_mac(&self) -> MacAddr {
        MacAddr(self.buffer[6..12].try_into().unwrap())
    }

    pub fn ethertype(&self) -> u16 {
        let offset = if self.vlan_tag.is_some() { 16 } else { 12 };
        u16::from_be_bytes([self.buffer[offset], self.buffer[offset + 1]])
    }

    pub fn vlan_tag(&self) -> Option<VlanTag> {
        self.vlan_tag
    }

    pub fn payload(&self) -> &[u8] {
        &self.buffer[self.payload_offset..]
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.buffer
    }
}

/// Builder for constructing Ethernet frames
pub struct FrameBuilder {
    buffer: Vec<u8>,
}

impl FrameBuilder {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(MAX_FRAME_SIZE),
        }
    }

    pub fn dst_mac(mut self, mac: MacAddr) -> Self {
        self.buffer.extend_from_slice(&mac.0);
        self
    }

    pub fn src_mac(mut self, mac: MacAddr) -> Self {
        self.buffer.extend_from_slice(&mac.0);
        self
    }

    pub fn vlan_tag(mut self, tag: VlanTag) -> Self {
        self.buffer
            .extend_from_slice(&(EtherType::Vlan as u16).to_be_bytes());
        self.buffer.extend_from_slice(&tag.to_bytes());
        self
    }

    pub fn ethertype(mut self, ethertype: u16) -> Self {
        self.buffer.extend_from_slice(&ethertype.to_be_bytes());
        self
    }

    pub fn payload(mut self, payload: &[u8]) -> Self {
        self.buffer.extend_from_slice(payload);
        self
    }

    pub fn build(self) -> Vec<u8> {
        self.buffer
    }
}

impl Default for FrameBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_frame() -> Vec<u8> {
        let mut frame = Vec::new();
        // dst MAC: 00:11:22:33:44:55
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // src MAC: 66:77:88:99:aa:bb
        frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        // EtherType: IPv4 (0x0800)
        frame.extend_from_slice(&[0x08, 0x00]);
        // Payload
        frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        frame
    }

    fn make_vlan_frame() -> Vec<u8> {
        let mut frame = Vec::new();
        // dst MAC
        frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // src MAC
        frame.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        // EtherType: VLAN (0x8100)
        frame.extend_from_slice(&[0x81, 0x00]);
        // VLAN tag: VID=100, PCP=0, DEI=0
        frame.extend_from_slice(&[0x00, 0x64]);
        // Inner EtherType: IPv4
        frame.extend_from_slice(&[0x08, 0x00]);
        // Payload
        frame.extend_from_slice(&[0xca, 0xfe]);
        frame
    }

    #[test]
    fn test_frame_parse_simple() {
        let data = make_simple_frame();
        let frame = Frame::parse(&data).unwrap();

        assert_eq!(
            frame.dst_mac(),
            MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(
            frame.src_mac(),
            MacAddr([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb])
        );
        assert_eq!(frame.ethertype(), EtherType::Ipv4 as u16);
        assert!(frame.vlan_tag().is_none());
        assert_eq!(frame.payload(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_frame_parse_vlan() {
        let data = make_vlan_frame();
        let frame = Frame::parse(&data).unwrap();

        assert_eq!(
            frame.dst_mac(),
            MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(
            frame.src_mac(),
            MacAddr([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb])
        );
        assert_eq!(frame.ethertype(), EtherType::Ipv4 as u16);

        let vlan = frame.vlan_tag().unwrap();
        assert_eq!(vlan.vid, 100);
        assert_eq!(vlan.pcp, 0);
        assert!(!vlan.dei);

        assert_eq!(frame.payload(), &[0xca, 0xfe]);
    }

    #[test]
    fn test_frame_parse_too_short() {
        let short_data = vec![0u8; 13]; // Less than MIN_FRAME_SIZE
        assert!(Frame::parse(&short_data).is_err());
    }

    #[test]
    fn test_frame_parse_vlan_too_short() {
        let mut data = vec![0u8; 14];
        // Set EtherType to VLAN
        data[12] = 0x81;
        data[13] = 0x00;
        assert!(Frame::parse(&data).is_err());
    }

    #[test]
    fn test_frame_as_bytes() {
        let data = make_simple_frame();
        let frame = Frame::parse(&data).unwrap();
        assert_eq!(frame.as_bytes(), &data[..]);
    }

    #[test]
    fn test_frame_builder_simple() {
        let dst = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let src = MacAddr([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        let payload = [0xde, 0xad, 0xbe, 0xef];

        let frame = FrameBuilder::new()
            .dst_mac(dst)
            .src_mac(src)
            .ethertype(EtherType::Ipv4 as u16)
            .payload(&payload)
            .build();

        assert_eq!(frame, make_simple_frame());
    }

    #[test]
    fn test_frame_builder_with_vlan() {
        let dst = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let src = MacAddr([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        let payload = [0xca, 0xfe];

        let frame = FrameBuilder::new()
            .dst_mac(dst)
            .src_mac(src)
            .vlan_tag(VlanTag::new(100))
            .ethertype(EtherType::Ipv4 as u16)
            .payload(&payload)
            .build();

        assert_eq!(frame, make_vlan_frame());
    }

    #[test]
    fn test_frame_builder_default() {
        let builder = FrameBuilder::default();
        assert_eq!(builder.build(), Vec::<u8>::new());
    }

    #[test]
    fn test_frame_roundtrip() {
        let original = make_simple_frame();
        let frame = Frame::parse(&original).unwrap();

        let rebuilt = FrameBuilder::new()
            .dst_mac(frame.dst_mac())
            .src_mac(frame.src_mac())
            .ethertype(frame.ethertype())
            .payload(frame.payload())
            .build();

        assert_eq!(rebuilt, original);
    }

    #[test]
    fn test_frame_roundtrip_vlan() {
        let original = make_vlan_frame();
        let frame = Frame::parse(&original).unwrap();

        let rebuilt = FrameBuilder::new()
            .dst_mac(frame.dst_mac())
            .src_mac(frame.src_mac())
            .vlan_tag(frame.vlan_tag().unwrap())
            .ethertype(frame.ethertype())
            .payload(frame.payload())
            .build();

        assert_eq!(rebuilt, original);
    }
}
