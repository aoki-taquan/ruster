//! WireGuard data messages in the forwarding path: a UDP packet to an interface's
//! listen port is opened, and the packet inside arrives on the WireGuard interface.
//!
//! # Standards
//!
//! See [`super`] and [`super::peer`]. A handshake message (types 1 to 3) is not
//! touched: it is a UDP packet addressed to the router and goes on as one, to
//! whoever terminates the handshake (the kernel behind the TUN, or a daemon).
//!
//! Deviations: the outer packet is accepted from whichever port it arrived on;
//! only its destination address and port, and the peer's endpoint, are checked.

use super::{decapsulate, InterfaceConfig, PeerState, ReceiveError, Received};
use crate::{DropReason, IfId, PacketLease, PacketSlot};

const ETHERNET: usize = 14;
const IPV4_ETHERTYPE: [u8; 2] = [0x08, 0x00];

/// One WireGuard interface of a snapshot.
#[derive(Clone, Copy, Debug)]
pub struct WireguardInterface<'a> {
    /// The interface inner packets arrive on and are sent from. It must be one of
    /// the snapshot's interfaces.
    pub interface: IfId,
    pub config: InterfaceConfig<'a>,
    /// Where this interface's peers start in the peer state slice
    /// ([`crate::Services::wireguard`]): peer `i` is at `first_peer + i`.
    pub first_peer: usize,
}

fn reason(error: ReceiveError) -> DropReason {
    match error {
        ReceiveError::OuterInvalid => DropReason::WireguardOuterInvalid,
        ReceiveError::UnknownSession => DropReason::WireguardUnknownSession,
        ReceiveError::WrongEndpoint => DropReason::WireguardWrongEndpoint,
        ReceiveError::Authentication => DropReason::WireguardAuthentication,
        ReceiveError::Replay => DropReason::WireguardReplay,
        ReceiveError::InnerInvalid => DropReason::WireguardInnerInvalid,
        ReceiveError::NotAllowed => DropReason::WireguardNotAllowed,
    }
}

/// Opens `packet` when it is a WireGuard data message for one of the snapshot's
/// interfaces: the Ethernet header is kept, the outer headers and the WireGuard
/// header are removed, the padding and tag cut off, and the packet now arrives on
/// the WireGuard interface, addressed to its MAC address. Anything else is left as
/// it was.
pub(crate) fn receive<S: PacketSlot>(
    packet: &mut PacketLease<S>,
    snapshot: &crate::ForwardingSnapshot<'_>,
    states: Option<&mut [PeerState]>,
) -> Result<(), DropReason> {
    let interfaces = snapshot.wireguard;
    let Some(states) = states else {
        return Ok(());
    };
    if interfaces.is_empty() {
        return Ok(());
    }
    let ingress = packet.ingress();
    let bytes = packet.bytes_mut();
    if bytes.len() < ETHERNET + super::OUTER_HEADERS_LEN || bytes[12..14] != IPV4_ETHERTYPE {
        return Ok(());
    }
    // Only a frame sent to the receiving interface itself.
    let Some(receiver) = snapshot.interface(ingress) else {
        return Ok(());
    };
    if bytes[0..6] != receiver.mac.0 {
        return Ok(());
    }
    for wireguard in interfaces {
        let end = wireguard.first_peer + wireguard.config.peers.len();
        let Some(peers) = states.get_mut(wireguard.first_peer..end) else {
            continue;
        };
        match decapsulate(&wireguard.config, peers, &mut bytes[ETHERNET..]) {
            Ok(Received::NotForUs | Received::Handshake) => continue,
            // Authenticated, nothing to forward.
            Ok(Received::Keepalive { .. }) => return Err(DropReason::WireguardKeepalive),
            Ok(Received::Data { inner, .. }) => {
                let inner_start = ETHERNET + inner.start;
                let inner_len = inner.len();
                let tunnel_mac = snapshot
                    .interface(wireguard.interface)
                    .ok_or(DropReason::InterfaceMiss)?
                    .mac;
                let header = inner_start - ETHERNET;
                bytes.copy_within(6..12, header + 6);
                bytes[header..header + 6].copy_from_slice(&tunnel_mac.0);
                bytes[header + 12..header + 14].copy_from_slice(&IPV4_ETHERTYPE);
                if !packet.resize_front(header as isize) || !packet.truncate(ETHERNET + inner_len) {
                    return Err(DropReason::WireguardNoRoom);
                }
                packet.set_ingress(wireguard.interface);
                return Ok(());
            }
            Err(error) => return Err(reason(error)),
        }
    }
    Ok(())
}
