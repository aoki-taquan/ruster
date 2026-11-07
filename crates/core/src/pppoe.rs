//! PPPoE sessions (RFC 2516): an interface whose IPv4 and IPv6 packets travel in
//! one PPPoE session on a parent interface (a port or a VLAN sub-interface).
//! Establishing the session (Discovery, LCP, authentication, IPCP and IPv6CP) is
//! the job of a daemon outside ruster; core only puts packets into the session
//! and takes them out.
//!
//! # Standards
//!
//! - RFC 2516 section 4: Ethernet type 0x8864, version and type 1, code 0, the
//!   session ID and the payload length, then the PPP protocol field (RFC 1661):
//!   0x0021 for IPv4 (RFC 1332), 0x0057 for IPv6 (RFC 5072).
//! - RFC 4638 is not used: a session's MTU is its interface's (1492 on a 1500-byte
//!   link).
//!
//! Deviations: session frames that are not IPv4 or IPv6 (LCP, IPCP, ...) and
//! Discovery frames are dropped; handing them to the daemon comes later.

use crate::{DropReason, IfId, MacAddress, PacketLease, PacketSlot};

const ETHERNET: usize = 14;
/// The PPPoE header and the PPP protocol field.
const HEADER: usize = 8;
const SESSION_ETHERTYPE: [u8; 2] = [0x88, 0x64];
const PPP_IPV4: [u8; 2] = [0x00, 0x21];
const PPP_IPV6: [u8; 2] = [0x00, 0x57];
const IPV4_ETHERTYPE: [u8; 2] = [0x08, 0x00];
const IPV6_ETHERTYPE: [u8; 2] = [0x86, 0xdd];

/// One PPPoE session: the interface routes point at, the interface it runs on,
/// and its ID and peer (the access concentrator).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PppoeSession {
    pub interface: IfId,
    pub parent: IfId,
    pub session: u16,
    pub peer: MacAddress,
}

/// The session whose interface is `egress`.
pub(crate) fn of(sessions: &[PppoeSession], egress: IfId) -> Option<&PppoeSession> {
    sessions.iter().find(|s| s.interface == egress)
}

/// Takes a session frame of one of `sessions` out of its session: it then arrives
/// on the session's interface as an Ethernet frame addressed to that interface.
/// Other frames are left as they are.
pub(crate) fn receive<S: PacketSlot>(
    packet: &mut PacketLease<S>,
    snapshot: &crate::ForwardingSnapshot<'_>,
) -> Result<(), DropReason> {
    let sessions = snapshot.pppoe;
    if sessions.is_empty() {
        return Ok(());
    }
    let ingress = packet.ingress();
    let bytes = packet.bytes_mut();
    if bytes.get(12..14) != Some(&SESSION_ETHERTYPE) {
        return Ok(());
    }
    if bytes.len() < ETHERNET + HEADER {
        return Err(DropReason::PppoeMalformed);
    }
    let id = u16::from_be_bytes([bytes[16], bytes[17]]);
    let Some(session) = sessions
        .iter()
        .find(|s| s.parent == ingress && s.session == id && bytes[6..12] == s.peer.0)
    else {
        return Err(DropReason::PppoeUnknownSession);
    };
    let session = *session;
    if bytes[14] != 0x11 || bytes[15] != 0 {
        return Err(DropReason::PppoeMalformed);
    }
    let length = usize::from(u16::from_be_bytes([bytes[18], bytes[19]]));
    if length < 2 || ETHERNET + 6 + length > bytes.len() {
        return Err(DropReason::PppoeMalformed);
    }
    let ethertype = match [bytes[20], bytes[21]] {
        PPP_IPV4 => IPV4_ETHERTYPE,
        PPP_IPV6 => IPV6_ETHERTYPE,
        _ => return Err(DropReason::PppoeNotIp),
    };
    let mac = snapshot
        .interface(session.interface)
        .ok_or(DropReason::InterfaceMiss)?
        .mac;
    bytes.copy_within(6..12, 6 + HEADER);
    bytes[HEADER..HEADER + 6].copy_from_slice(&mac.0);
    bytes[HEADER + 12..HEADER + 14].copy_from_slice(&ethertype);
    if !packet.resize_front(HEADER as isize) {
        return Err(DropReason::PppoeNoRoom);
    }
    packet.set_ingress(session.interface);
    Ok(())
}

/// `frame` (Ethernet, IPv4 or IPv6) for the session interface `egress`, in its
/// session: the parent to send it out of and the frame to send. `None` when
/// `egress` is no session's. Cold path (generated frames).
pub(crate) fn wrap(
    snapshot: &crate::ForwardingSnapshot<'_>,
    egress: IfId,
    frame: &[u8],
) -> Option<Result<(IfId, Vec<u8>), crate::TunnelOriginError>> {
    use crate::TunnelOriginError::{Dropped, TooBig};
    let session = of(snapshot.pppoe, egress)?;
    Some((|| {
        let parent = snapshot
            .interface(session.parent)
            .ok_or(Dropped(DropReason::InterfaceMiss))?;
        let mtu = snapshot
            .interface(session.interface)
            .ok_or(Dropped(DropReason::InterfaceMiss))?
            .mtu
            .min(parent.mtu.saturating_sub(HEADER as u16));
        let protocol = match frame.get(12..14) {
            Some(&[0x08, 0x00]) => PPP_IPV4,
            Some(&[0x86, 0xdd]) => PPP_IPV6,
            _ => return Err(Dropped(DropReason::PppoeNotIp)),
        };
        let ip = frame.get(ETHERNET..).unwrap_or(&[]);
        if ip.len() > usize::from(mtu) {
            return Err(TooBig { mtu });
        }
        let length = u16::try_from(ip.len() + 2).map_err(|_| TooBig { mtu })?;
        let mut out = Vec::with_capacity(ETHERNET + HEADER + ip.len());
        out.extend_from_slice(&session.peer.0);
        out.extend_from_slice(&parent.mac.0);
        out.extend_from_slice(&SESSION_ETHERTYPE);
        out.extend_from_slice(&[0x11, 0]);
        out.extend_from_slice(&session.session.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&protocol);
        out.extend_from_slice(ip);
        Ok((session.parent, out))
    })())
}

/// Puts the frame for `session`'s interface into the session; returns the
/// interface to send it out of (the session's parent).
pub(crate) fn transmit<S: PacketSlot>(
    packet: &mut PacketLease<S>,
    session: &PppoeSession,
    snapshot: &crate::ForwardingSnapshot<'_>,
) -> Result<IfId, DropReason> {
    let parent = snapshot
        .interface(session.parent)
        .ok_or(DropReason::InterfaceMiss)?;
    let bytes = packet.bytes_mut();
    let protocol = match bytes.get(12..14) {
        Some(&[0x08, 0x00]) => PPP_IPV4,
        Some(&[0x86, 0xdd]) => PPP_IPV6,
        _ => return Err(DropReason::PppoeNotIp),
    };
    let ip = bytes.get(ETHERNET..).unwrap_or(&[]);
    let ip_len = match protocol {
        PPP_IPV4 => ip
            .get(2..4)
            .map(|l| usize::from(u16::from_be_bytes([l[0], l[1]]))),
        _ => ip
            .get(4..6)
            .map(|l| 40 + usize::from(u16::from_be_bytes([l[0], l[1]]))),
    }
    .ok_or(DropReason::PppoeMalformed)?;
    let length = u16::try_from(ip_len + 2).map_err(|_| DropReason::PppoeMalformed)?;
    if !packet.resize_front(-(HEADER as isize)) {
        return Err(DropReason::PppoeNoRoom);
    }
    let bytes = packet.bytes_mut();
    bytes[0..6].copy_from_slice(&session.peer.0);
    bytes[6..12].copy_from_slice(&parent.mac.0);
    bytes[12..14].copy_from_slice(&SESSION_ETHERTYPE);
    bytes[14] = 0x11;
    bytes[15] = 0;
    bytes[16..18].copy_from_slice(&session.session.to_be_bytes());
    bytes[18..20].copy_from_slice(&length.to_be_bytes());
    bytes[20..22].copy_from_slice(&protocol);
    Ok(session.parent)
}
