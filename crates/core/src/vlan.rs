//! IEEE 802.1Q VLAN sub-interfaces.
//!
//! A [`VlanBinding`] makes frames tagged `vid` on port `parent` arrive on interface
//! `sub`, and frames sent out of `sub` leave `parent` tagged `vid`. Untagged frames
//! stay on the parent. A snapshot carries the bindings after
//! [`with_vlans`](crate::ForwardingSnapshot::with_vlans).
//!
//! # Standards
//!
//! - IEEE 802.1Q: the C-tag (TPID 0x8100, then PCP, DEI and the 12-bit VLAN ID).
//! - `draft-ietf-netmod-sub-intf-vlan-model`: a sub-interface matches one outer tag
//!   and pops it on receive, pushes it on send.
//! - IEEE 802.1Q: a priority-tagged frame (VLAN ID 0) belongs to the port itself,
//!   as an untagged one; VLAN ID 4095 is reserved and matches no sub-interface.
//!
//! Deviations: S-tags (0x88a8) and stacked tags are not matched; sent frames carry
//! priority 0.

use crate::{DropReason, IfId, PacketLease, PacketSlot};

const TPID: [u8; 2] = [0x81, 0x00];
const TAG: usize = 4;

/// Port `parent` with VLAN ID `vid` is interface `sub`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VlanBinding {
    pub parent: IfId,
    pub vid: u16,
    pub sub: IfId,
}

/// Takes the tag off a tagged frame and makes it arrive on its sub-interface.
pub(crate) fn receive<S: PacketSlot>(
    packet: &mut PacketLease<S>,
    vlans: &[VlanBinding],
) -> Result<(), DropReason> {
    let port = packet.port();
    let bytes = packet.bytes_mut();
    if bytes.get(12..14) != Some(&TPID) {
        return Ok(());
    }
    let tci = u16::from_be_bytes([
        *bytes.get(14).ok_or(DropReason::EthernetHeaderTruncated)?,
        *bytes.get(15).ok_or(DropReason::EthernetHeaderTruncated)?,
    ]);
    let vid = tci & 0x0fff;
    // A priority-tagged frame (VLAN ID 0) is the port's own, untagged.
    if vid == 0 {
        bytes.copy_within(0..12, TAG);
        if !packet.resize_front(TAG as isize) {
            return Err(DropReason::VlanNoRoom);
        }
        return Ok(());
    }
    let binding = vlans
        .iter()
        .find(|b| b.parent == port && b.vid == vid)
        .ok_or(DropReason::VlanUnknown)?;
    bytes.copy_within(0..12, TAG);
    if !packet.resize_front(TAG as isize) {
        return Err(DropReason::VlanNoRoom);
    }
    packet.set_ingress(binding.sub);
    Ok(())
}

/// Tags a frame for `egress` when it is a sub-interface; returns the port to send it
/// out of.
pub(crate) fn transmit<S: PacketSlot>(
    packet: &mut PacketLease<S>,
    egress: IfId,
    vlans: &[VlanBinding],
) -> Result<IfId, DropReason> {
    let Some(binding) = vlans.iter().find(|b| b.sub == egress) else {
        return Ok(egress);
    };
    if !packet.resize_front(-(TAG as isize)) {
        return Err(DropReason::VlanNoRoom);
    }
    let bytes = packet.bytes_mut();
    bytes.copy_within(TAG..TAG + 12, 0);
    bytes[12..14].copy_from_slice(&TPID);
    bytes[14..16].copy_from_slice(&(binding.vid & 0x0fff).to_be_bytes());
    Ok(binding.parent)
}
