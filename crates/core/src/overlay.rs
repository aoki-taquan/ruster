//! Bridge members that carry Ethernet frames inside IP: EtherIP.
//!
//! See `docs/design/overlay.md`, section 4. An [`Overlay`] is an interface that is
//! a member of a bridge, like a port, but whose frames travel inside IP packets
//! between the router's address `local` and the remote end. A frame the bridge
//! sends out of it gets the outer headers ([`transmit_member`]) and is routed by
//! the default VRF, as the outer packets of the other tunnels are; an outer packet
//! from the remote end to `local` loses them ([`receive`]) and its frame is
//! received on the member.
//!
//! # Standards
//!
//! - RFC 3378 section 3 (EtherIP): IP protocol 97, a two-byte header of version 3
//!   and twelve reserved bits set to zero, then the Ethernet frame without its FCS.
//!   A packet whose version is not 3 is dropped. The outer header is IPv4 or IPv6.
//! - RFC 791 and RFC 8200: the outer header, TTL or Hop Limit 64; an IPv4 outer
//!   header has DF set and identification 0 (RFC 6864 section 4.1: an atomic
//!   datagram). An IPv4 outer header with a bad checksum is dropped (RFC 1122
//!   section 3.2.1.2).
//!
//! Deviations:
//!
//! - The outer packet is never fragmented, and outer fragments are dropped, not
//!   put back together (RFC 3378 does not forbid fragmenting): a frame longer than
//!   the underlying interface's MTU less the outer headers is dropped and counted
//!   ([`DropReason::OverlayMtuExceeded`]).
//! - The reserved bits of a received EtherIP header are not looked at.
//! - IPv6 extension headers before the EtherIP header are not stepped over: such
//!   packets are not unwrapped.
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
/// IP protocol number of EtherIP.
const ETHERIP: u8 = 97;
/// The EtherIP header: version 3, reserved 0.
const ETHERIP_HEADER: [u8; 2] = [0x30, 0x00];
/// TTL and Hop Limit of the outer header.
const HOP_LIMIT: u8 = 64;
/// The longest outer header (Ethernet, IPv6, UDP and VXLAN).
const MAX_HEADER: usize = ETHERNET + IPV6_HEADER + 16;

/// A bridge member whose frames travel inside IP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Overlay {
    /// The member interface. It must be one of the snapshot's interfaces.
    pub interface: IfId,
    /// The router's address the outer packets come from and go to.
    pub local: IpAddr,
    pub kind: OverlayKind,
}

/// What carries the frames.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OverlayKind {
    /// EtherIP (RFC 3378) to and from one remote end, of the family of `local`.
    EtherIp { remote: IpAddr },
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

/// Reads the outer IPv4 or IPv6 header of `bytes` (Ethernet). `Ok(None)` for a
/// frame that is no IP packet or is cut short; an IPv4 header that is wrong once
/// it is known to be for an overlay is checked by [`check_ipv4`].
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

/// Unwraps `packet` when it is an outer packet of one of the snapshot's overlays:
/// its frame is left, received on the overlay's interface. `Ok(false)` leaves any
/// other packet as it was. `snapshot` is the outer (default VRF's) one.
pub(crate) fn receive<S: PacketSlot>(
    packet: &mut PacketLease<S>,
    snapshot: &crate::ForwardingSnapshot<'_>,
) -> Result<bool, DropReason> {
    let overlays = snapshot.overlays;
    if overlays.is_empty() {
        return Ok(false);
    }
    let ingress = packet.ingress();
    let bytes = packet.bytes_mut();
    let Some(outer) = outer(bytes) else {
        return Ok(false);
    };
    if outer.protocol != ETHERIP || !overlays.iter().any(|o| o.local == outer.destination) {
        return Ok(false);
    }
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
    let frame = outer.payload + 2;
    if outer.end < frame + ETHERNET {
        return Err(DropReason::OverlayInvalid);
    }
    let member = overlay.interface;
    // Padding after the outer packet goes, then the outer headers.
    if !packet.truncate(outer.end) || !packet.resize_front(frame as isize) {
        return Err(DropReason::OverlayNoRoom);
    }
    packet.set_ingress(member);
    Ok(true)
}

/// The outer header for `inner` (an Ethernet frame) leaving `overlay`, routed by
/// `snapshot` (the default VRF's). `irb` tells the bridges' own interfaces, which
/// the outer packet may not leave through. A next hop missing from the neighbor
/// table is recorded in `trace`.
pub(crate) fn header<T: TraceSink>(
    snapshot: &crate::ForwardingSnapshot<'_>,
    overlay: &Overlay,
    inner: &[u8],
    irb: impl Fn(IfId) -> bool,
    trace: &mut T,
) -> Result<OverlayHeader, DropReason> {
    let OverlayKind::EtherIp { remote } = overlay.kind;
    if inner.len() < ETHERNET {
        return Err(DropReason::EthernetHeaderTruncated);
    }
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
    let carried = ETHERIP_HEADER.len() + inner.len();
    let ip = ETHERNET;
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
            b[ip + 9] = ETHERIP;
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
            b[ip + 6] = ETHERIP;
            b[ip + 7] = HOP_LIMIT;
            b[ip + 8..ip + 24].copy_from_slice(&local.octets());
            b[ip + 24..ip + 40].copy_from_slice(&remote.octets());
            ip + IPV6_HEADER
        }
        _ => return Err(DropReason::OverlayInvalid),
    };
    b[payload..payload + 2].copy_from_slice(&ETHERIP_HEADER);
    out.len = payload + 2;
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
/// (see [`header`]), then tagged when the interface below is a VLAN
/// sub-interface. Returns the port to commit it to. `snapshot` is the outer one.
pub(crate) fn transmit_member<S: PacketSlot, T: TraceSink>(
    packet: &mut PacketLease<S>,
    member: IfId,
    snapshot: &crate::ForwardingSnapshot<'_>,
    irb: impl Fn(IfId) -> bool,
    trace: &mut T,
) -> Result<IfId, DropReason> {
    let egress = match of(snapshot.overlays, member) {
        Some(overlay) => {
            let outer = header(snapshot, overlay, packet.bytes_mut(), irb, trace)?;
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
        let h = header(&s, &t.overlays[0], &frame, |_| false, &mut NullTrace).unwrap();
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
        let h = header(&s, &t.overlays[0], &frame, |_| false, &mut NullTrace).unwrap();
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
        assert!(header(&s, &t.overlays[0], &frame, |_| false, &mut NullTrace).is_ok());
        frame.push(0);
        assert_eq!(
            header(&s, &t.overlays[0], &frame, |_| false, &mut NullTrace).unwrap_err(),
            DropReason::OverlayMtuExceeded
        );
        // Nor out of a bridge's own interface.
        assert_eq!(
            header(
                &s,
                &t.overlays[0],
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

    fn unwrap(t: &Tables, bytes: Vec<u8>) -> (Result<bool, DropReason>, Vec<u8>, IfId) {
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
        assert_eq!(result, Ok(true));
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
        assert_eq!(result, Ok(false));
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
        let port = transmit_member(&mut packet, MEMBER, &s, |_| false, &mut NullTrace).unwrap();
        assert_eq!(port, PORT);
        let mut wrapped = packet.bytes_mut().to_vec();
        packet.commit(port);
        // As the remote end would send it back.
        wrapped[0..6].copy_from_slice(&PORT_MAC);
        let (a, b) = (wrapped[22..38].to_vec(), wrapped[38..54].to_vec());
        wrapped[22..38].copy_from_slice(&b);
        wrapped[38..54].copy_from_slice(&a);
        let (result, bytes, ingress) = unwrap(&t, wrapped);
        assert_eq!(result, Ok(true));
        assert_eq!((bytes, ingress), (frame, MEMBER));
    }
}
