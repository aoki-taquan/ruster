//! IPv4 in IPv6 tunnels (a DS-Lite B4's softwire): an IPv4 packet routed to a
//! tunnel interface leaves inside an IPv6 packet from the tunnel's local address to
//! its remote one, routed by the default VRF's IPv6 table; such an IPv6 packet
//! arriving is unwrapped and its IPv4 packet received again on the tunnel
//! interface.
//!
//! # Standards
//!
//! - RFC 6333 (DS-Lite) section 5, the B4 element: IPv4 in IPv6 to the AFTR.
//! - RFC 2473 (Generic Packet Tunneling in IPv6): the encapsulating header, Next
//!   Header 4, the inner packet unchanged after its own forwarding (TTL already
//!   decremented).
//! - RFC 8200 section 4: Hop-by-Hop and Destination Options headers before the
//!   inner packet (such as RFC 2473 4.1.1's Tunnel Encapsulation Limit) are
//!   stepped over when unwrapping; other extension headers are not.
//! - RFC 2983 (uniform model): the inner IPv4 TOS byte is copied to the outer
//!   Traffic Class.
//!
//! Deviations:
//!
//! - The outer packet is never fragmented (RFC 6333 5.3 allows the B4 to): a
//!   tunnel's MTU is at most the underlying link's less 40, and an inner datagram
//!   longer than it is handled by the IPv4 MTU rule on the tunnel interface: with
//!   DF clear it is fragmented first and each fragment goes in its own IPv6 packet
//!   (RFC 2473 7.2 lets the inner packet be fragmented).
//! - No tunnel encapsulation limit option (RFC 2473 4.1.1) and no ICMPv6 errors
//!   from the tunnel path are relayed as ICMPv4 errors (RFC 2473 8).
//! - The outer packets are always routed in the default VRF.
//! - A tunnel's packets are unwrapped only when they arrive on the interface the
//!   default VRF routes the remote end through (a strict reverse-path check), so
//!   with two uplinks and asymmetric routing, those arriving on the other one are
//!   dropped.

use crate::{DropReason, IfId, PacketLease, PacketSlot, TraceEvent, TraceSink};

const ETHERNET: usize = 14;
const IPV6_HEADER: usize = 40;
const IPV6_ETHERTYPE: [u8; 2] = [0x86, 0xdd];
const IPV4_ETHERTYPE: [u8; 2] = [0x08, 0x00];
/// IP protocol number of IPv4 (IP in IP), as IPv6 Next Header.
const IPV4_IN_IP: u8 = 4;
const HOP_BY_HOP: u8 = 0;
const DESTINATION_OPTIONS: u8 = 60;
/// Option headers stepped over before the inner packet, at most.
const MAX_OPTION_HEADERS: usize = 2;
/// Hop Limit of the outer header.
const HOP_LIMIT: u8 = 64;

/// One IPv4 in IPv6 tunnel: the interface IPv4 routes point at, and the outer
/// addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4InIpv6Tunnel {
    /// The tunnel interface. It must be one of the snapshot's interfaces; its MTU
    /// is the inner MTU.
    pub interface: IfId,
    /// The router's IPv6 address the tunnel is sent from (the B4's).
    pub local: [u8; 16],
    /// The remote end (the AFTR's address).
    pub remote: [u8; 16],
}

/// The tunnel whose interface is `egress`.
pub(crate) fn of(tunnels: &[Ipv4InIpv6Tunnel], egress: IfId) -> Option<&Ipv4InIpv6Tunnel> {
    tunnels.iter().find(|t| t.interface == egress)
}

/// Unwraps `packet` when it is an IPv6 packet of one of `tunnels` (from its remote
/// address to its local one, Next Header 4) for this router: the Ethernet header
/// is kept, the IPv6 header removed, and the packet now arrives on the tunnel
/// interface, addressed to that interface's MAC address. `Ok(false)` leaves any
/// other packet as it was.
pub(crate) fn receive<S: PacketSlot>(
    packet: &mut PacketLease<S>,
    snapshot: &crate::ForwardingSnapshot<'_>,
) -> Result<bool, DropReason> {
    let tunnels = snapshot.tunnels;
    if tunnels.is_empty() {
        return Ok(false);
    }
    let ingress = packet.ingress();
    let bytes = packet.bytes_mut();
    if bytes.len() < ETHERNET + IPV6_HEADER || bytes[12..14] != IPV6_ETHERTYPE {
        return Ok(false);
    }
    let ip = ETHERNET;
    if bytes[ip] >> 4 != 6 {
        return Ok(false);
    }
    // Hop-by-Hop and Destination Options headers (such as RFC 2473's Tunnel
    // Encapsulation Limit) may come before the inner packet; they are stepped over.
    let mut next = bytes[ip + 6];
    let mut header = IPV6_HEADER;
    for _ in 0..MAX_OPTION_HEADERS {
        if !matches!(next, HOP_BY_HOP | DESTINATION_OPTIONS) {
            break;
        }
        let Some(&[following, length]) = bytes.get(ip + header..ip + header + 2) else {
            return Ok(false);
        };
        next = following;
        header += (usize::from(length) + 1) * 8;
    }
    if next != IPV4_IN_IP {
        return Ok(false);
    }
    let source = &bytes[ip + 8..ip + 24];
    let destination = &bytes[ip + 24..ip + 40];
    let Some(tunnel) = tunnels
        .iter()
        .find(|t| t.remote == source && t.local == destination)
    else {
        return Ok(false);
    };
    let tunnel = *tunnel;
    // Only from where the tunnel's remote end is: the interface the default VRF
    // routes it through (a strict reverse-path check), so no other link or VRF can
    // pass packets off as the remote end's.
    let through = snapshot
        .ipv6
        .and_then(|fib| fib.next_hop(tunnel.remote))
        .map(|(egress, _)| egress);
    if through != Some(ingress) {
        return Err(DropReason::TunnelWrongIngress);
    }
    // Only a frame sent to the receiving interface itself.
    let interface = snapshot
        .interface(ingress)
        .ok_or(DropReason::Ipv6IngressInterfaceUnknown)?;
    if bytes[0..6] != interface.mac.0 {
        return Err(DropReason::Ipv6EthernetAddressInvalid);
    }
    let payload = usize::from(u16::from_be_bytes([bytes[ip + 4], bytes[ip + 5]]));
    if ip + IPV6_HEADER + payload > bytes.len() {
        return Err(DropReason::Ipv6PayloadLengthExceedsPacket);
    }
    if payload <= header - IPV6_HEADER || bytes[ip + header] >> 4 != 4 {
        return Err(DropReason::TunnelInnerInvalid);
    }
    let tunnel_mac = snapshot
        .interface(tunnel.interface)
        .ok_or(DropReason::InterfaceMiss)?
        .mac;
    // The source MAC stays (as the previous hop's), the destination becomes the
    // tunnel interface's so the inner packet passes its Ethernet check.
    bytes.copy_within(6..12, 6 + header);
    bytes[header..header + 6].copy_from_slice(&tunnel_mac.0);
    bytes[header + 12..header + 14].copy_from_slice(&IPV4_ETHERTYPE);
    if !packet.resize_front(header as isize) {
        return Err(DropReason::TunnelNoRoom);
    }
    packet.set_ingress(tunnel.interface);
    Ok(true)
}

/// Wraps the forwarded IPv4 `packet` (already rewritten for `tunnel`'s interface)
/// in IPv6 and routes it by the default VRF's IPv6 table. Returns the interface to
/// send it out of.
pub(crate) fn transmit<S: PacketSlot, T: TraceSink>(
    packet: &mut PacketLease<S>,
    tunnel: &Ipv4InIpv6Tunnel,
    outer: &crate::ForwardingSnapshot<'_>,
    trace: &mut T,
) -> Result<IfId, DropReason> {
    let fib = outer.ipv6.ok_or(DropReason::TunnelNoRoute)?;
    let (egress, next_hop) = fib
        .next_hop(tunnel.remote)
        .ok_or(DropReason::TunnelNoRoute)?;
    let interface = outer.interface(egress).ok_or(DropReason::InterfaceMiss)?;
    let session = crate::pppoe::of(outer.pppoe, egress).is_some();
    let Some(mac) = fib
        .neighbor(egress, next_hop)
        .or(session.then_some(crate::MacAddress([0; 6])))
    else {
        trace.record(TraceEvent::Ipv6NeighborMissing {
            egress,
            target: next_hop,
        });
        return Err(DropReason::NeighborUnresolved);
    };
    let bytes = packet.bytes_mut();
    let inner = bytes
        .get(ETHERNET + 2..ETHERNET + 4)
        .map(|len| usize::from(u16::from_be_bytes([len[0], len[1]])))
        .ok_or(DropReason::Ipv4HeaderTruncated)?;
    if IPV6_HEADER + inner > usize::from(interface.mtu) {
        return Err(DropReason::TunnelMtuExceeded);
    }
    let payload = u16::try_from(inner).map_err(|_| DropReason::TunnelMtuExceeded)?;
    let tos = packet.bytes_mut()[ETHERNET + 1];
    if !packet.resize_front(-(IPV6_HEADER as isize)) {
        return Err(DropReason::TunnelNoRoom);
    }
    let bytes = packet.bytes_mut();
    bytes[0..6].copy_from_slice(&mac.0);
    bytes[6..12].copy_from_slice(&interface.mac.0);
    bytes[12..14].copy_from_slice(&IPV6_ETHERTYPE);
    let ip = ETHERNET;
    bytes[ip] = 0x60 | (tos >> 4);
    bytes[ip + 1] = tos << 4;
    bytes[ip + 2] = 0;
    bytes[ip + 3] = 0;
    bytes[ip + 4..ip + 6].copy_from_slice(&payload.to_be_bytes());
    bytes[ip + 6] = IPV4_IN_IP;
    bytes[ip + 7] = HOP_LIMIT;
    bytes[ip + 8..ip + 24].copy_from_slice(&tunnel.local);
    bytes[ip + 24..ip + 40].copy_from_slice(&tunnel.remote);
    Ok(egress)
}

/// The generated IPv4 `frame` (Ethernet) for the tunnel interface `egress`, inside
/// the tunnel's IPv6 as [`transmit`] puts a forwarded one: the interface to send it
/// out of and the frame. `None` when `egress` is no tunnel's. Cold path.
pub(crate) fn wrap(
    snapshot: &crate::ForwardingSnapshot<'_>,
    egress: IfId,
    frame: &[u8],
) -> Option<Result<(IfId, Vec<u8>), crate::TunnelOriginError>> {
    use crate::TunnelOriginError::{Dropped, TooBig};
    let tunnel = of(snapshot.tunnels, egress)?;
    Some((|| {
        if frame.get(12..14) != Some(&IPV4_ETHERTYPE[..]) {
            return Err(Dropped(DropReason::Ipv4HeaderTruncated));
        }
        let inner = &frame[ETHERNET..];
        let fib = snapshot.ipv6.ok_or(Dropped(DropReason::TunnelNoRoute))?;
        let (out, next_hop) = fib
            .next_hop(tunnel.remote)
            .ok_or(Dropped(DropReason::TunnelNoRoute))?;
        let interface = snapshot
            .interface(out)
            .ok_or(Dropped(DropReason::InterfaceMiss))?;
        let session = crate::pppoe::of(snapshot.pppoe, out).is_some();
        let mac = fib
            .neighbor(out, next_hop)
            .or(session.then_some(crate::MacAddress([0; 6])))
            .ok_or(Dropped(DropReason::NeighborUnresolved))?;
        if IPV6_HEADER + inner.len() > usize::from(interface.mtu) {
            return Err(TooBig {
                mtu: interface.mtu.saturating_sub(IPV6_HEADER as u16),
            });
        }
        let payload = u16::try_from(inner.len()).map_err(|_| TooBig { mtu: u16::MAX })?;
        let tos = inner.get(1).copied().unwrap_or(0);
        let mut out_frame = Vec::with_capacity(ETHERNET + IPV6_HEADER + inner.len());
        out_frame.extend_from_slice(&mac.0);
        out_frame.extend_from_slice(&interface.mac.0);
        out_frame.extend_from_slice(&IPV6_ETHERTYPE);
        out_frame.extend_from_slice(&[0x60 | (tos >> 4), tos << 4, 0, 0]);
        out_frame.extend_from_slice(&payload.to_be_bytes());
        out_frame.extend_from_slice(&[IPV4_IN_IP, HOP_LIMIT]);
        out_frame.extend_from_slice(&tunnel.local);
        out_frame.extend_from_slice(&tunnel.remote);
        out_frame.extend_from_slice(inner);
        Ok((out, out_frame))
    })())
}
