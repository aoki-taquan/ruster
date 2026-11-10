//! Bridge members that carry Ethernet frames inside IP: EtherIP and VXLAN.
//!
//! See `docs/design/overlay.md`, sections 3 and 4. An [`Overlay`] is an interface
//! that is a member of a bridge, like a port, but whose frames travel inside IP
//! packets between the router's address `local` and remote ends. A frame the bridge
//! sends out of it gets the outer headers ([`transmit_member`]) and is routed by the
//! default VRF, as the outer packets of the other tunnels are; an outer packet from a
//! remote end to `local` loses them ([`receive`]) and its frame is received on the
//! member. An EtherIP interface has one remote end. A VXLAN interface has one VNI and
//! a list of remote VTEPs: a frame goes to the VTEP its destination was learned
//! behind, and the FE sends a flooded one to each of them (head-end replication).
//!
//! # Standards
//!
//! - RFC 3378 section 3 (EtherIP): IP protocol 97, a two-byte header of version 3
//!   and twelve reserved bits set to zero, then the Ethernet frame without its FCS.
//!   A packet whose version is not 3 is dropped. The outer header is IPv4 or IPv6.
//! - RFC 7348 section 5 (VXLAN): UDP to port 4789, an eight-byte header with the I
//!   flag set and the 24-bit VNI, then the Ethernet frame without its FCS. The UDP
//!   source port is a hash of the inner frame's flow (its IP addresses and ports,
//!   or its MAC addresses), in 49152 to 65535. A packet without the I flag, or whose
//!   inner frame has a VLAN tag (section 6.1), is dropped. Over IPv4 the UDP
//!   checksum is 0; over IPv6 it is computed (RFC 6935 is not used). A received
//!   checksum is not checked (RFC 7348 section 5 allows that).
//! - RFC 7348 section 4.1: the outer source address of a received frame is learned
//!   with its inner source MAC address (see `crate::MacTable`).
//! - RFC 791 and RFC 8200: the outer header, TTL or Hop Limit 64; an IPv4 outer
//!   header has DF set (RFC 7348 section 4.3) and identification 0 (RFC 6864
//!   section 4.1: an atomic datagram). An IPv4 outer header with a bad checksum is
//!   dropped (RFC 1122 section 3.2.1.2).
//!
//! Deviations:
//!
//! - The outer packet is never fragmented, and outer fragments are dropped, not put
//!   back together (RFC 3378 does not forbid fragmenting): a frame longer than the
//!   underlying interface's MTU less the outer headers is dropped and counted
//!   ([`DropReason::OverlayMtuExceeded`]).
//! - The reserved bits of a received EtherIP header and VXLAN header are not looked
//!   at.
//! - IPv6 extension headers before the EtherIP or UDP header are not stepped over:
//!   such packets are not unwrapped.
//! - VXLAN: no multicast underlay (RFC 7348 section 4.2); the remote VTEPs are a
//!   list given in the tables, and packets from any other address are dropped. The
//!   UDP port is always 4789.
//! - The outer packets are always routed in the default VRF, only out of a port or a
//!   VLAN sub-interface (not a tunnel, PPPoE session or bridge), and only those
//!   arriving on an interface of the default VRF are unwrapped.

use std::net::IpAddr;

use crate::{DropReason, IfId, PacketLease, PacketSlot, TraceEvent, TraceSink};

const ETHERNET: usize = 14;
const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const IPV4_ETHERTYPE: [u8; 2] = [0x08, 0x00];
const IPV6_ETHERTYPE: [u8; 2] = [0x86, 0xdd];
const VLAN_ETHERTYPE: [u8; 2] = [0x81, 0x00];
/// IP protocol numbers of EtherIP, UDP and TCP.
const ETHERIP: u8 = 97;
const UDP: u8 = 17;
const TCP: u8 = 6;
/// The EtherIP header: version 3, reserved 0.
const ETHERIP_HEADER: [u8; 2] = [0x30, 0x00];
/// The UDP port of VXLAN (IANA), and the UDP and VXLAN headers' length.
const VXLAN_PORT: u16 = 4789;
const VXLAN_HEADERS: usize = 16;
/// The I flag of the VXLAN header.
const VXLAN_I: u8 = 0x08;
/// TTL and Hop Limit of the outer header.
const HOP_LIMIT: u8 = 64;
/// The longest outer header (Ethernet, IPv6, UDP and VXLAN).
const MAX_HEADER: usize = ETHERNET + IPV6_HEADER + VXLAN_HEADERS;

/// A bridge member whose frames travel inside IP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Overlay {
    /// The member interface. It must be one of the snapshot's interfaces.
    pub interface: IfId,
    /// The router's address the outer packets come from and go to.
    pub local: IpAddr,
    pub kind: OverlayKind,
}

/// What carries the frames. The remote ends are of the family of `local`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OverlayKind {
    /// EtherIP (RFC 3378) to and from one remote end.
    EtherIp { remote: IpAddr },
    /// VXLAN (RFC 7348) network `vni` (1 to 16777215), to and from the remote VTEPs
    /// `remotes`.
    Vxlan { vni: u32, remotes: Vec<IpAddr> },
}

impl Overlay {
    /// The remote ends: where a frame of an unknown destination goes.
    #[must_use]
    pub fn remotes(&self) -> &[IpAddr] {
        match &self.kind {
            OverlayKind::EtherIp { remote } => std::slice::from_ref(remote),
            OverlayKind::Vxlan { remotes, .. } => remotes,
        }
    }

    /// Whether it is a VXLAN interface: a frame flooded from one is not sent to
    /// another (every VTEP sends its own frames to all the others).
    #[must_use]
    pub fn is_vxlan(&self) -> bool {
        matches!(self.kind, OverlayKind::Vxlan { .. })
    }
}

/// The overlay whose interface is `id`.
pub(crate) fn of(overlays: &[Overlay], id: IfId) -> Option<&Overlay> {
    overlays.iter().find(|o| o.interface == id)
}

/// The outer header a frame leaves an overlay with, and the interface it leaves
/// through (a port or a VLAN sub-interface).
#[derive(Clone, Copy, Debug)]
pub struct OverlayHeader {
    pub egress: IfId,
    len: usize,
    bytes: [u8; MAX_HEADER],
}

impl OverlayHeader {
    /// The header, Ethernet first: the frame follows it.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The outer IP packet: its addresses, the bytes after its header and before its
/// end, and its protocol.
struct Outer {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    payload: usize,
    end: usize,
}

/// Reads the outer IPv4 or IPv6 header of `bytes` (Ethernet). `None` for a frame
/// that is no IP packet or is cut short; an IPv4 header that is wrong once it is
/// known to be for an overlay is checked by [`check_ipv4`].
fn outer(bytes: &[u8]) -> Option<Outer> {
    let ethertype = bytes.get(12..14)?;
    let ip = bytes.get(ETHERNET..)?;
    if ethertype == IPV4_ETHERTYPE {
        if ip.len() < IPV4_HEADER || ip[0] >> 4 != 4 {
            return None;
        }
        let header = usize::from(ip[0] & 0x0f) * 4;
        let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
        if header < IPV4_HEADER || total < header || total > ip.len() {
            return None;
        }
        let address = |at: usize| <[u8; 4]>::try_from(&ip[at..at + 4]).ok().map(IpAddr::from);
        return Some(Outer {
            source: address(12)?,
            destination: address(16)?,
            protocol: ip[9],
            payload: ETHERNET + header,
            end: ETHERNET + total,
        });
    }
    if ethertype == IPV6_ETHERTYPE {
        if ip.len() < IPV6_HEADER || ip[0] >> 4 != 6 {
            return None;
        }
        let total = IPV6_HEADER + usize::from(u16::from_be_bytes([ip[4], ip[5]]));
        if total > ip.len() {
            return None;
        }
        let address = |at: usize| {
            <[u8; 16]>::try_from(&ip[at..at + 16])
                .ok()
                .map(IpAddr::from)
        };
        return Some(Outer {
            source: address(8)?,
            destination: address(24)?,
            protocol: ip[6],
            payload: ETHERNET + IPV6_HEADER,
            end: ETHERNET + total,
        });
    }
    None
}

/// An IPv4 outer header must be whole (its checksum right) and not a fragment.
fn check_ipv4(bytes: &[u8], payload: usize) -> Result<(), DropReason> {
    let header = &bytes[ETHERNET..payload];
    if crate::ipv4_header_checksum(header) != 0 {
        return Err(DropReason::OverlayInvalid);
    }
    // More Fragments or a fragment offset.
    if u16::from_be_bytes([header[6], header[7]]) & 0x3fff != 0 {
        return Err(DropReason::OverlayInvalid);
    }
    Ok(())
}

/// What [`receive`] did with a packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Received {
    /// Not an overlay's outer packet: left as it was.
    NotOverlay,
    /// Unwrapped: its frame arrives on the overlay's interface, from remote VTEP
    /// `vtep` for a VXLAN interface.
    Unwrapped { vtep: Option<IpAddr> },
}

/// Unwraps `packet` when it is an outer packet of one of the snapshot's overlays:
/// its frame is left, received on the overlay's interface. Any other packet is left
/// as it was. `snapshot` is the outer (default VRF's) one.
pub(crate) fn receive<S: PacketSlot>(
    packet: &mut PacketLease<S>,
    snapshot: &crate::ForwardingSnapshot<'_>,
) -> Result<Received, DropReason> {
    let overlays = snapshot.overlays;
    if overlays.is_empty() {
        return Ok(Received::NotOverlay);
    }
    let ingress = packet.ingress();
    let bytes = packet.bytes_mut();
    let Some(outer) = outer(bytes) else {
        return Ok(Received::NotOverlay);
    };
    let ours = |vxlan: bool| {
        overlays
            .iter()
            .any(|o| o.local == outer.destination && o.is_vxlan() == vxlan)
    };
    let vxlan = match outer.protocol {
        ETHERIP if ours(false) => false,
        UDP if ours(true)
            && bytes.get(outer.payload + 2..outer.payload + 4)
                == Some(&VXLAN_PORT.to_be_bytes()[..]) =>
        {
            true
        }
        _ => return Ok(Received::NotOverlay),
    };
    // For one of the overlays' addresses from here on: dropped unless it is right.
    if outer.source.is_ipv4() {
        check_ipv4(bytes, outer.payload)?;
    }
    // Only through the default VRF, as the outer packets are sent, and to the
    // receiving interface itself.
    if snapshot.for_ingress(ingress).authority() != snapshot.authority() {
        return Err(DropReason::OverlayUnknownPeer);
    }
    let interface = snapshot
        .interface(ingress)
        .ok_or(DropReason::OverlayUnknownPeer)?;
    if bytes[0..6] != interface.mac.0 {
        return Err(DropReason::OverlayUnknownPeer);
    }
    let (overlay, frame) = if vxlan {
        let header = bytes
            .get(outer.payload..outer.payload + VXLAN_HEADERS)
            .ok_or(DropReason::OverlayInvalid)?;
        let length = usize::from(u16::from_be_bytes([header[4], header[5]]));
        if header[8] & VXLAN_I == 0 || length < VXLAN_HEADERS || outer.payload + length > outer.end
        {
            return Err(DropReason::OverlayInvalid);
        }
        let vni = u32::from_be_bytes([0, header[12], header[13], header[14]]);
        let overlay = overlays
            .iter()
            .find(|o| {
                o.local == outer.destination
                    && matches!(&o.kind, OverlayKind::Vxlan { vni: v, remotes }
                        if *v == vni && remotes.contains(&outer.source))
            })
            .ok_or(DropReason::OverlayUnknownPeer)?;
        let frame = outer.payload + VXLAN_HEADERS;
        // RFC 7348 6.1: an inner VLAN tag is not taken.
        if bytes.get(frame + 12..frame + 14) == Some(&VLAN_ETHERTYPE[..]) {
            return Err(DropReason::OverlayInvalid);
        }
        (overlay, frame)
    } else {
        let overlay = overlays
            .iter()
            .find(|o| {
                o.local == outer.destination
                    && matches!(o.kind, OverlayKind::EtherIp { remote } if remote == outer.source)
            })
            .ok_or(DropReason::OverlayUnknownPeer)?;
        let header = bytes
            .get(outer.payload..outer.payload + 2)
            .ok_or(DropReason::OverlayInvalid)?;
        if header[0] >> 4 != ETHERIP_HEADER[0] >> 4 {
            return Err(DropReason::OverlayInvalid);
        }
        (overlay, outer.payload + 2)
    };
    if outer.end < frame + ETHERNET {
        return Err(DropReason::OverlayInvalid);
    }
    let member = overlay.interface;
    let vtep = vxlan.then_some(outer.source);
    // Padding after the outer packet goes, then the outer headers.
    if !packet.truncate(outer.end) || !packet.resize_front(frame as isize) {
        return Err(DropReason::OverlayNoRoom);
    }
    packet.set_ingress(member);
    Ok(Received::Unwrapped { vtep })
}

/// A hash of the flow of `inner` (an Ethernet frame): its IP addresses and, for TCP
/// and UDP that are not later fragments, its ports; its MAC addresses otherwise
/// (FNV-1a).
pub(crate) fn flow_hash(inner: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    let mut add = |bytes: &[u8]| {
        for &b in bytes {
            hash = (hash ^ u32::from(b)).wrapping_mul(0x0100_0193);
        }
    };
    let ip = &inner[ETHERNET.min(inner.len())..];
    let ports = |at: usize, protocol: u8| match protocol {
        TCP | UDP => ip.get(at..at + 4),
        _ => None,
    };
    match inner.get(12..14) {
        Some(t) if t == IPV4_ETHERTYPE && ip.len() >= IPV4_HEADER => {
            add(&ip[12..20]);
            let later = u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff != 0;
            let header = usize::from(ip[0] & 0x0f) * 4;
            if let Some(p) = ports(header, ip[9]).filter(|_| !later) {
                add(p);
            }
        }
        Some(t) if t == IPV6_ETHERTYPE && ip.len() >= IPV6_HEADER => {
            add(&ip[8..40]);
            if let Some(p) = ports(IPV6_HEADER, ip[6]) {
                add(p);
            }
        }
        _ => add(&inner[..12.min(inner.len())]),
    }
    hash
}

/// The one's complement sum of `bytes` as 16-bit words, added to `sum`.
fn add_words(mut sum: u64, bytes: &[u8]) -> u64 {
    let mut words = bytes.chunks_exact(2);
    for word in words.by_ref() {
        sum += u64::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let Some(&last) = words.remainder().first() {
        sum += u64::from(last) << 8;
    }
    sum
}

/// The outer header for `inner` (an Ethernet frame) leaving `overlay` for its
/// remote end `remote`, routed by `snapshot` (the default VRF's). `irb` tells the
/// bridges' own interfaces, which the outer packet may not leave through. A next hop
/// missing from the neighbor table is recorded in `trace`.
pub(crate) fn header<T: TraceSink>(
    snapshot: &crate::ForwardingSnapshot<'_>,
    overlay: &Overlay,
    remote: IpAddr,
    inner: &[u8],
    irb: impl Fn(IfId) -> bool,
    trace: &mut T,
) -> Result<OverlayHeader, DropReason> {
    if inner.len() < ETHERNET {
        return Err(DropReason::EthernetHeaderTruncated);
    }
    if !overlay.remotes().contains(&remote) {
        return Err(DropReason::OverlayUnknownPeer);
    }
    let vni = match overlay.kind {
        OverlayKind::Vxlan { vni, .. } => {
            // RFC 7348 6.1: no inner VLAN tag is sent.
            if inner[12..14] == VLAN_ETHERTYPE {
                return Err(DropReason::OverlayInvalid);
            }
            Some(vni)
        }
        OverlayKind::EtherIp { .. } => None,
    };
    let (egress, mac) = route(snapshot, remote, trace)?;
    if irb(egress) || snapshot.wraps_frames(egress) || of(snapshot.overlays, egress).is_some() {
        return Err(DropReason::OverlayUnderlayUnsupported);
    }
    let interface = snapshot
        .interface(egress)
        .ok_or(DropReason::InterfaceMiss)?;
    let mut out = OverlayHeader {
        egress,
        len: 0,
        bytes: [0; MAX_HEADER],
    };
    let b = &mut out.bytes;
    b[0..6].copy_from_slice(&mac.0);
    b[6..12].copy_from_slice(&interface.mac.0);
    let encapsulation = if vni.is_some() {
        VXLAN_HEADERS
    } else {
        ETHERIP_HEADER.len()
    };
    let carried = encapsulation + inner.len();
    let ip = ETHERNET;
    let protocol = if vni.is_some() { UDP } else { ETHERIP };
    let payload = match (overlay.local, remote) {
        (IpAddr::V4(local), IpAddr::V4(remote)) => {
            let total = IPV4_HEADER + carried;
            if total > usize::from(interface.mtu) {
                return Err(DropReason::OverlayMtuExceeded);
            }
            let total = u16::try_from(total).map_err(|_| DropReason::OverlayMtuExceeded)?;
            b[12..14].copy_from_slice(&IPV4_ETHERTYPE);
            b[ip] = 0x45;
            b[ip + 2..ip + 4].copy_from_slice(&total.to_be_bytes());
            // Don't Fragment; identification 0.
            b[ip + 6] = 0x40;
            b[ip + 8] = HOP_LIMIT;
            b[ip + 9] = protocol;
            b[ip + 12..ip + 16].copy_from_slice(&local.octets());
            b[ip + 16..ip + 20].copy_from_slice(&remote.octets());
            let checksum = crate::ipv4_header_checksum(&b[ip..ip + IPV4_HEADER]);
            b[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
            ip + IPV4_HEADER
        }
        (IpAddr::V6(local), IpAddr::V6(remote)) => {
            if IPV6_HEADER + carried > usize::from(interface.mtu) {
                return Err(DropReason::OverlayMtuExceeded);
            }
            let length = u16::try_from(carried).map_err(|_| DropReason::OverlayMtuExceeded)?;
            b[12..14].copy_from_slice(&IPV6_ETHERTYPE);
            b[ip] = 0x60;
            b[ip + 4..ip + 6].copy_from_slice(&length.to_be_bytes());
            b[ip + 6] = protocol;
            b[ip + 7] = HOP_LIMIT;
            b[ip + 8..ip + 24].copy_from_slice(&local.octets());
            b[ip + 24..ip + 40].copy_from_slice(&remote.octets());
            ip + IPV6_HEADER
        }
        _ => return Err(DropReason::OverlayInvalid),
    };
    let Some(vni) = vni else {
        b[payload..payload + 2].copy_from_slice(&ETHERIP_HEADER);
        out.len = payload + 2;
        return Ok(out);
    };
    let udp = payload;
    let length = u16::try_from(carried).map_err(|_| DropReason::OverlayMtuExceeded)?;
    // 49152 to 65535 (RFC 7348 section 5).
    let port = 0xc000 | (flow_hash(inner) & 0x3fff) as u16;
    b[udp..udp + 2].copy_from_slice(&port.to_be_bytes());
    b[udp + 2..udp + 4].copy_from_slice(&VXLAN_PORT.to_be_bytes());
    b[udp + 4..udp + 6].copy_from_slice(&length.to_be_bytes());
    b[udp + 8] = VXLAN_I;
    b[udp + 12..udp + 15].copy_from_slice(&vni.to_be_bytes()[1..]);
    if overlay.local.is_ipv6() {
        // Over the pseudo-header (addresses, length, next header), the UDP and
        // VXLAN headers and the frame (RFC 8200 section 8.1).
        let mut sum = add_words(0, &b[ip + 8..ip + 40]);
        sum += u64::from(length) + u64::from(UDP);
        sum = add_words(sum, &b[udp..udp + VXLAN_HEADERS]);
        sum = add_words(sum, inner);
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let checksum = match !(sum as u16) {
            0 => 0xffff,
            c => c,
        };
        b[udp + 6..udp + 8].copy_from_slice(&checksum.to_be_bytes());
    }
    out.len = udp + VXLAN_HEADERS;
    Ok(out)
}

/// The interface toward `remote` in the default VRF and its next hop's MAC
/// address.
fn route<T: TraceSink>(
    snapshot: &crate::ForwardingSnapshot<'_>,
    remote: IpAddr,
    trace: &mut T,
) -> Result<(IfId, crate::MacAddress), DropReason> {
    match remote {
        IpAddr::V4(remote) => {
            let route = snapshot
                .route_lookup(crate::Ipv4Address::from_octets(remote.octets()))
                .ok_or(DropReason::OverlayNoRoute)?;
            let egress = route.egress();
            let target = route
                .next_hop()
                .unwrap_or(crate::Ipv4Address::from_octets(remote.octets()));
            match snapshot.static_neighbor(egress, target) {
                Some(neighbor) => {
                    trace.record(TraceEvent::Routed {
                        egress,
                        neighbor_target: target,
                    });
                    Ok((egress, neighbor.mac))
                }
                None => {
                    if !snapshot.is_unreachable_neighbor(egress, target) {
                        trace.record(TraceEvent::NeighborMissing { egress, target });
                    }
                    Err(DropReason::NeighborUnresolved)
                }
            }
        }
        IpAddr::V6(remote) => {
            let fib = snapshot.ipv6.ok_or(DropReason::OverlayNoRoute)?;
            let (egress, next_hop) = fib
                .next_hop(remote.octets())
                .ok_or(DropReason::OverlayNoRoute)?;
            match fib.neighbor(egress, next_hop) {
                Some(mac) => {
                    trace.record(TraceEvent::Ipv6Routed { egress, next_hop });
                    Ok((egress, mac))
                }
                None => {
                    if !fib.unreachable.contains(&(egress, next_hop)) {
                        trace.record(TraceEvent::Ipv6NeighborMissing {
                            egress,
                            target: next_hop,
                        });
                    }
                    Err(DropReason::NeighborUnresolved)
                }
            }
        }
    }
}

/// Sends the bridged frame `packet` out of `member`: wrapped when it is an overlay
/// (see [`header`]) for the remote end `vtep` (a VXLAN interface's, learned with
/// the destination) or its only one (EtherIP), then tagged when the interface below
/// is a VLAN sub-interface. Returns the port to commit it to. `snapshot` is the
/// outer one.
pub(crate) fn transmit_member<S: PacketSlot, T: TraceSink>(
    packet: &mut PacketLease<S>,
    member: IfId,
    vtep: Option<IpAddr>,
    snapshot: &crate::ForwardingSnapshot<'_>,
    irb: impl Fn(IfId) -> bool,
    trace: &mut T,
) -> Result<IfId, DropReason> {
    let egress = match of(snapshot.overlays, member) {
        Some(overlay) => {
            let remote = match (&overlay.kind, vtep) {
                (OverlayKind::EtherIp { remote }, _) => *remote,
                (OverlayKind::Vxlan { .. }, Some(vtep)) => vtep,
                // A VXLAN destination known with no VTEP: nowhere to send it.
                (OverlayKind::Vxlan { .. }, None) => return Err(DropReason::OverlayNoRoute),
            };
            let outer = header(snapshot, overlay, remote, packet.bytes_mut(), irb, trace)?;
            let len = outer.len;
            if !packet.resize_front(-(len as isize)) {
                return Err(DropReason::OverlayNoRoom);
            }
            packet.bytes_mut()[..len].copy_from_slice(outer.bytes());
            outer.egress
        }
        None => member,
    };
    crate::vlan::transmit(packet, egress, snapshot.vlans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Interface, LocalIpv4Binding, MacAddress, Neighbor, NoTrace as NullTrace, Route,
        SlotCompletion,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// A frame in a `Vec`, with as much room in front as asked for.
    struct Slot(IfId, Vec<u8>);

    impl PacketSlot for Slot {
        fn ingress(&self) -> IfId {
            self.0
        }
        fn bytes_mut(&mut self) -> &mut [u8] {
            &mut self.1
        }
        fn complete(self, _: SlotCompletion) {}
        fn resize_front(&mut self, delta: isize) -> bool {
            match usize::try_from(delta) {
                Ok(drop) if drop <= self.1.len() => {
                    self.1.drain(..drop);
                }
                Ok(_) => return false,
                Err(_) => {
                    let add = vec![0; delta.unsigned_abs()];
                    self.1.splice(0..0, add);
                }
            }
            true
        }
        fn truncate(&mut self, len: usize) -> bool {
            self.1.truncate(len);
            true
        }
    }

    fn lease(ingress: IfId, bytes: Vec<u8>) -> PacketLease<Slot> {
        PacketLease::new(Slot(ingress, bytes))
    }

    const PORT: IfId = IfId(0);
    const MEMBER: IfId = IfId(5);
    const PORT_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
    const LOCAL4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const REMOTE4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

    struct Tables {
        routes: Vec<Route>,
        interfaces: Vec<Interface>,
        neighbors: Vec<Neighbor>,
        local: Vec<LocalIpv4Binding>,
        overlays: Vec<Overlay>,
        ipv6: crate::Ipv6Fib,
    }

    fn tables(mtu: u16, local: IpAddr, remote: IpAddr) -> Tables {
        let port = Interface {
            id: PORT,
            mac: MacAddress(PORT_MAC),
            mtu,
        };
        let member = Interface {
            id: MEMBER,
            mac: MacAddress([2, 0, 0, 0, 0, 5]),
            mtu: 1500,
        };
        let v6 = |a: &str| a.parse::<Ipv6Addr>().unwrap().octets();
        Tables {
            routes: vec![Route::new(
                crate::Ipv4Address::from_octets([192, 0, 2, 0]),
                24,
                PORT,
                None,
            )
            .unwrap()],
            interfaces: vec![port, member],
            neighbors: vec![Neighbor {
                interface: PORT,
                target: crate::Ipv4Address::from_octets(REMOTE4.octets()),
                mac: MacAddress(PEER_MAC),
            }],
            local: vec![LocalIpv4Binding {
                interface: PORT,
                address: crate::Ipv4Address::from_octets(LOCAL4.octets()),
            }],
            overlays: vec![Overlay {
                interface: MEMBER,
                local,
                kind: OverlayKind::EtherIp { remote },
            }],
            ipv6: crate::Ipv6Fib::new(
                vec![crate::Ipv6Route::new(v6("2001:db8::"), 64, PORT, None).unwrap()],
                vec![crate::Ipv6Neighbor {
                    interface: PORT,
                    target: v6("2001:db8::2"),
                    mac: MacAddress(PEER_MAC),
                }],
                vec![],
            )
            .unwrap(),
        }
    }

    fn snapshot(t: &Tables) -> crate::ForwardingSnapshot<'_> {
        crate::ForwardingSnapshot::new(&t.routes, &t.interfaces, &t.neighbors, &t.local)
            .unwrap()
            .with_ipv6(&t.ipv6)
            .with_overlays(&t.overlays)
    }

    fn inner() -> Vec<u8> {
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&[2, 0, 0, 0, 0, 0x11, 0x08, 0x06]);
        f.extend_from_slice(&[0xab; 28]);
        f
    }

    #[test]
    fn wraps_in_ipv4_with_df_and_a_checksum() {
        let t = tables(1500, LOCAL4.into(), REMOTE4.into());
        let s = snapshot(&t);
        let frame = inner();
        let h = header(
            &s,
            &t.overlays[0],
            t.overlays[0].remotes()[0],
            &frame,
            |_| false,
            &mut NullTrace,
        )
        .unwrap();
        assert_eq!(h.egress, PORT);
        let b = h.bytes();
        assert_eq!(b.len(), 14 + 20 + 2);
        assert_eq!(&b[0..6], &PEER_MAC);
        assert_eq!(&b[6..12], &PORT_MAC);
        assert_eq!(&b[12..14], &[0x08, 0x00]);
        assert_eq!(b[14], 0x45);
        assert_eq!(
            usize::from(u16::from_be_bytes([b[16], b[17]])),
            20 + 2 + frame.len()
        );
        assert_eq!(&b[20..22], &[0x40, 0]);
        assert_eq!((b[22], b[23]), (64, 97));
        assert_eq!(crate::ipv4_header_checksum(&b[14..34]), 0);
        assert_eq!(&b[26..30], &LOCAL4.octets());
        assert_eq!(&b[30..34], &REMOTE4.octets());
        assert_eq!(&b[34..36], &[0x30, 0x00]);
    }

    #[test]
    fn wraps_in_ipv6() {
        let local: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let remote: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let t = tables(1500, local.into(), remote.into());
        let s = snapshot(&t);
        let frame = inner();
        let h = header(
            &s,
            &t.overlays[0],
            t.overlays[0].remotes()[0],
            &frame,
            |_| false,
            &mut NullTrace,
        )
        .unwrap();
        let b = h.bytes();
        assert_eq!(b.len(), 14 + 40 + 2);
        assert_eq!(&b[12..14], &[0x86, 0xdd]);
        assert_eq!(
            usize::from(u16::from_be_bytes([b[18], b[19]])),
            2 + frame.len()
        );
        assert_eq!((b[20], b[21]), (97, 64));
        assert_eq!(&b[22..38], &local.octets());
        assert_eq!(&b[38..54], &remote.octets());
        assert_eq!(&b[54..56], &[0x30, 0x00]);
    }

    #[test]
    fn a_frame_too_long_for_the_link_is_dropped() {
        let t = tables(1500, LOCAL4.into(), REMOTE4.into());
        let s = snapshot(&t);
        let mut frame = inner();
        // 20 + 2 + 1478 = 1500 fits; one more does not.
        frame.resize(1478, 0);
        assert!(header(
            &s,
            &t.overlays[0],
            t.overlays[0].remotes()[0],
            &frame,
            |_| false,
            &mut NullTrace
        )
        .is_ok());
        frame.push(0);
        assert_eq!(
            header(
                &s,
                &t.overlays[0],
                t.overlays[0].remotes()[0],
                &frame,
                |_| false,
                &mut NullTrace
            )
            .unwrap_err(),
            DropReason::OverlayMtuExceeded
        );
        // Nor out of a bridge's own interface.
        assert_eq!(
            header(
                &s,
                &t.overlays[0],
                t.overlays[0].remotes()[0],
                &inner(),
                |id| id == PORT,
                &mut NullTrace
            )
            .unwrap_err(),
            DropReason::OverlayUnderlayUnsupported
        );
    }

    fn outer_ipv4(source: Ipv4Addr, version: u8, frame: &[u8]) -> Vec<u8> {
        let mut p = PORT_MAC.to_vec();
        p.extend_from_slice(&PEER_MAC);
        p.extend_from_slice(&[0x08, 0x00]);
        let total = u16::try_from(20 + 2 + frame.len()).unwrap();
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0x40, 0, 64, 97, 0, 0]);
        ip.extend_from_slice(&source.octets());
        ip.extend_from_slice(&LOCAL4.octets());
        let checksum = crate::ipv4_header_checksum(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        p.extend_from_slice(&ip);
        p.extend_from_slice(&[version << 4, 0]);
        p.extend_from_slice(frame);
        p
    }

    fn unwrap(t: &Tables, bytes: Vec<u8>) -> (Result<Received, DropReason>, Vec<u8>, IfId) {
        let s = snapshot(t);
        let mut packet = lease(PORT, bytes);
        let result = receive(&mut packet, &s);
        let ingress = packet.ingress();
        let bytes = packet.bytes_mut().to_vec();
        packet.recycle(DropReason::OverlayInvalid);
        (result, bytes, ingress)
    }

    #[test]
    fn unwraps_from_the_remote_end_only() {
        let t = tables(1500, LOCAL4.into(), REMOTE4.into());
        let frame = inner();
        // With Ethernet padding after the outer packet.
        let mut padded = outer_ipv4(REMOTE4, 3, &frame);
        padded.extend_from_slice(&[0; 6]);
        let (result, bytes, ingress) = unwrap(&t, padded);
        assert_eq!(result, Ok(Received::Unwrapped { vtep: None }));
        assert_eq!(bytes, frame);
        assert_eq!(ingress, MEMBER);
        // Another source: dropped.
        let other = Ipv4Addr::new(192, 0, 2, 9);
        let (result, _, _) = unwrap(&t, outer_ipv4(other, 3, &frame));
        assert_eq!(result, Err(DropReason::OverlayUnknownPeer));
        // Another version: dropped.
        let (result, _, _) = unwrap(&t, outer_ipv4(REMOTE4, 4, &frame));
        assert_eq!(result, Err(DropReason::OverlayInvalid));
        // A bad checksum: dropped.
        let mut bad = outer_ipv4(REMOTE4, 3, &frame);
        bad[24] ^= 1;
        let (result, _, _) = unwrap(&t, bad);
        assert_eq!(result, Err(DropReason::OverlayInvalid));
        // A fragment: dropped.
        let mut fragment = outer_ipv4(REMOTE4, 3, &frame);
        fragment[20] = 0x20;
        let checksum = {
            fragment[24..26].copy_from_slice(&[0, 0]);
            crate::ipv4_header_checksum(&fragment[14..34])
        };
        fragment[24..26].copy_from_slice(&checksum.to_be_bytes());
        let (result, _, _) = unwrap(&t, fragment);
        assert_eq!(result, Err(DropReason::OverlayInvalid));
        // To another MAC address: dropped.
        let mut elsewhere = outer_ipv4(REMOTE4, 3, &frame);
        elsewhere[5] ^= 1;
        let (result, _, _) = unwrap(&t, elsewhere);
        assert_eq!(result, Err(DropReason::OverlayUnknownPeer));
    }

    #[test]
    fn other_packets_are_left_alone() {
        let t = tables(1500, LOCAL4.into(), REMOTE4.into());
        let mut udp = outer_ipv4(REMOTE4, 3, &inner());
        udp[23] = 17;
        udp[24..26].copy_from_slice(&[0, 0]);
        let checksum = crate::ipv4_header_checksum(&udp[14..34]);
        udp[24..26].copy_from_slice(&checksum.to_be_bytes());
        let (result, bytes, ingress) = unwrap(&t, udp.clone());
        assert_eq!(result, Ok(Received::NotOverlay));
        assert_eq!((bytes, ingress), (udp, PORT));
    }

    #[test]
    fn a_wrapped_frame_unwraps_to_itself() {
        let local: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let remote: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let t = tables(1500, local.into(), remote.into());
        let s = snapshot(&t);
        let frame = inner();
        let mut packet = lease(PORT, frame.clone());
        let port =
            transmit_member(&mut packet, MEMBER, None, &s, |_| false, &mut NullTrace).unwrap();
        assert_eq!(port, PORT);
        let mut wrapped = packet.bytes_mut().to_vec();
        packet.commit(port);
        // As the remote end would send it back.
        wrapped[0..6].copy_from_slice(&PORT_MAC);
        let (a, b) = (wrapped[22..38].to_vec(), wrapped[38..54].to_vec());
        wrapped[22..38].copy_from_slice(&b);
        wrapped[38..54].copy_from_slice(&a);
        let (result, bytes, ingress) = unwrap(&t, wrapped);
        assert_eq!(result, Ok(Received::Unwrapped { vtep: None }));
        assert_eq!((bytes, ingress), (frame, MEMBER));
    }

    /// The tables with the overlay a VXLAN interface of VNI 100 to `remotes`.
    fn vxlan(local: IpAddr, remotes: Vec<IpAddr>) -> Tables {
        let mut t = tables(1500, local, remotes[0]);
        t.overlays[0].kind = OverlayKind::Vxlan { vni: 100, remotes };
        t
    }

    fn udp_ipv4(inner_frame: &[u8]) -> Vec<u8> {
        let mut f = inner_frame.to_vec();
        f[12..14].copy_from_slice(&[0x08, 0x00]);
        f.truncate(14);
        let mut ip = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 17, 0, 0];
        ip.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        ip.extend_from_slice(&[0x30, 0x39, 0x00, 0x50, 0, 20, 0, 0]);
        ip.extend_from_slice(&[0; 12]);
        f.extend_from_slice(&ip);
        f
    }

    #[test]
    fn vxlan_wraps_in_ipv4_with_checksum_zero_and_a_hashed_port() {
        let other = Ipv4Addr::new(192, 0, 2, 3);
        let mut t = vxlan(LOCAL4.into(), vec![REMOTE4.into(), other.into()]);
        t.neighbors.push(Neighbor {
            interface: PORT,
            target: crate::Ipv4Address::from_octets(other.octets()),
            mac: MacAddress([2, 0, 0, 0, 0, 3]),
        });
        let s = snapshot(&t);
        let frame = udp_ipv4(&inner());
        let h = header(
            &s,
            &t.overlays[0],
            REMOTE4.into(),
            &frame,
            |_| false,
            &mut NullTrace,
        )
        .unwrap();
        let b = h.bytes();
        assert_eq!(b.len(), 14 + 20 + 8 + 8);
        assert_eq!(&b[20..22], &[0x40, 0], "DF");
        assert_eq!(b[23], 17);
        assert_eq!(crate::ipv4_header_checksum(&b[14..34]), 0);
        let port = u16::from_be_bytes([b[34], b[35]]);
        assert!(port >= 49152);
        assert_eq!(&b[36..38], &4789_u16.to_be_bytes());
        assert_eq!(
            usize::from(u16::from_be_bytes([b[38], b[39]])),
            16 + frame.len()
        );
        assert_eq!(&b[40..42], &[0, 0], "no UDP checksum over IPv4");
        assert_eq!(&b[42..50], &[0x08, 0, 0, 0, 0, 0, 100, 0]);
        // The same flow, the same port; another flow, most likely another.
        let again = header(
            &s,
            &t.overlays[0],
            other.into(),
            &frame,
            |_| false,
            &mut NullTrace,
        )
        .unwrap();
        assert_eq!(&again.bytes()[34..36], &b[34..36]);
        let mut moved = frame.clone();
        moved[14 + 20 + 1] = 0x3a;
        let elsewhere = header(
            &s,
            &t.overlays[0],
            REMOTE4.into(),
            &moved,
            |_| false,
            &mut NullTrace,
        )
        .unwrap();
        assert_ne!(&elsewhere.bytes()[34..36], &b[34..36]);
        // Not to an address off the list, and no inner VLAN tag.
        let stranger = IpAddr::from([192, 0, 2, 9]);
        assert_eq!(
            header(
                &s,
                &t.overlays[0],
                stranger,
                &frame,
                |_| false,
                &mut NullTrace
            )
            .unwrap_err(),
            DropReason::OverlayUnknownPeer
        );
        let mut tagged = frame;
        tagged[12..14].copy_from_slice(&[0x81, 0x00]);
        assert_eq!(
            header(
                &s,
                &t.overlays[0],
                REMOTE4.into(),
                &tagged,
                |_| false,
                &mut NullTrace
            )
            .unwrap_err(),
            DropReason::OverlayInvalid
        );
    }

    #[test]
    fn vxlan_over_ipv6_has_a_udp_checksum() {
        let local: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let remote: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let t = vxlan(local.into(), vec![remote.into()]);
        let s = snapshot(&t);
        let frame = inner();
        let h = header(
            &s,
            &t.overlays[0],
            remote.into(),
            &frame,
            |_| false,
            &mut NullTrace,
        )
        .unwrap();
        let b = h.bytes();
        assert_eq!(b.len(), 14 + 40 + 16);
        let length = u16::try_from(16 + frame.len()).unwrap();
        let mut pseudo = b[22..54].to_vec();
        pseudo.extend_from_slice(&[0, 0]);
        pseudo.extend_from_slice(&length.to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
        pseudo.extend_from_slice(&b[54..70]);
        pseudo.extend_from_slice(&frame);
        assert_ne!(&b[60..62], &[0, 0]);
        assert_eq!(crate::internet_checksum(&pseudo), 0);
    }

    fn outer_vxlan(source: Ipv4Addr, flags: u8, vni: u32, frame: &[u8]) -> Vec<u8> {
        let mut p = PORT_MAC.to_vec();
        p.extend_from_slice(&PEER_MAC);
        p.extend_from_slice(&[0x08, 0x00]);
        let total = u16::try_from(20 + 16 + frame.len()).unwrap();
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&source.octets());
        ip.extend_from_slice(&LOCAL4.octets());
        let checksum = crate::ipv4_header_checksum(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        p.extend_from_slice(&ip);
        let length = u16::try_from(16 + frame.len()).unwrap();
        p.extend_from_slice(&[0xc0, 0x01, 0x12, 0xb5]);
        p.extend_from_slice(&length.to_be_bytes());
        p.extend_from_slice(&[0, 0, flags, 0, 0, 0]);
        p.extend_from_slice(&vni.to_be_bytes()[1..]);
        p.push(0);
        p.extend_from_slice(frame);
        p
    }

    #[test]
    fn vxlan_unwraps_from_listed_vteps_with_the_vni() {
        let t = vxlan(LOCAL4.into(), vec![REMOTE4.into()]);
        let frame = inner();
        let (result, bytes, ingress) = unwrap(&t, outer_vxlan(REMOTE4, 0x08, 100, &frame));
        assert_eq!(
            result,
            Ok(Received::Unwrapped {
                vtep: Some(REMOTE4.into())
            })
        );
        assert_eq!((bytes, ingress), (frame.clone(), MEMBER));
        let stranger = Ipv4Addr::new(192, 0, 2, 9);
        for (outer, reason) in [
            (
                outer_vxlan(stranger, 0x08, 100, &frame),
                DropReason::OverlayUnknownPeer,
            ),
            (
                outer_vxlan(REMOTE4, 0x08, 101, &frame),
                DropReason::OverlayUnknownPeer,
            ),
            (
                outer_vxlan(REMOTE4, 0, 100, &frame),
                DropReason::OverlayInvalid,
            ),
        ] {
            assert_eq!(unwrap(&t, outer).0, Err(reason));
        }
        let mut tagged = frame;
        tagged[12..14].copy_from_slice(&[0x81, 0x00]);
        assert_eq!(
            unwrap(&t, outer_vxlan(REMOTE4, 0x08, 100, &tagged)).0,
            Err(DropReason::OverlayInvalid)
        );
        // Another UDP port: not VXLAN's.
        let mut other = outer_vxlan(REMOTE4, 0x08, 100, &inner());
        other[36..38].copy_from_slice(&4790_u16.to_be_bytes());
        assert_eq!(unwrap(&t, other).0, Ok(Received::NotOverlay));
    }

    #[test]
    fn vxlan_sends_to_the_learned_vtep_only() {
        let t = vxlan(LOCAL4.into(), vec![REMOTE4.into()]);
        let s = snapshot(&t);
        let mut packet = lease(PORT, inner());
        assert_eq!(
            transmit_member(&mut packet, MEMBER, None, &s, |_| false, &mut NullTrace),
            Err(DropReason::OverlayNoRoute)
        );
        let port = transmit_member(
            &mut packet,
            MEMBER,
            Some(REMOTE4.into()),
            &s,
            |_| false,
            &mut NullTrace,
        )
        .unwrap();
        assert_eq!(&packet.bytes_mut()[30..34], &REMOTE4.octets());
        packet.commit(port);
    }
}
