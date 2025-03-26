#![cfg(feature = "arp")]

// RFC 826 から引用
// 16.bit: (ar$hrd) Hardware address space (e.g., Ethernet,
//                  Packet Radio Net.)
// 16.bit: (ar$pro) Protocol address space.  For Ethernet
//                  hardware, this is from the set of type
//                  fields ether_typ$<protocol>.
//  8.bit: (ar$hln) byte length of each hardware address
//  8.bit: (ar$pln) byte length of each protocol address
// 16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
// nbytes: (ar$sha) Hardware address of sender of this
//                  packet, n from the ar$hln field.
// mbytes: (ar$spa) Protocol address of sender of this
//                  packet, m from the ar$pln field.
// nbytes: (ar$tha) Hardware address of target of this
//                  packet (if known).
// mbytes: (ar$tpa) Protocol address of target.
#[repr(C)]
pub struct ArpPacket {
    pub hrd: u16,
    pub pro: u16,
    pub hln: u8,
    pub pln: u8,
    pub op: u16,
    pub sha: [u8; 6],
    pub spa: [u8; 4],
    pub tha: [u8; 6],
    pub tpa: [u8; 4],
}
