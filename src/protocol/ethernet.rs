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
        let ethertype = u16::from_be_bytes([buffer[ethertype_offset], buffer[ethertype_offset + 1]]);

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
        self.buffer.extend_from_slice(&(EtherType::Vlan as u16).to_be_bytes());
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
