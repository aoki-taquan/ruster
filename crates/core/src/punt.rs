//! Frames for the control side that are picked out before anything else looks at
//! them: PPPoE Discovery, PPP control in PPPoE sessions, and IP packets to a
//! broadcast or link-local multicast address on chosen protocols and ports (DHCP).
//! A frame that one of the snapshot's [`PuntFrameMatch`]es matches is copied into
//! the control queue as [`crate::ControlKind::Punt`] with the match's class, and is
//! not forwarded.
//!
//! IP packets to the router's own addresses are not picked out here: they reach
//! the control queue as [`crate::ControlKind::Local`] after the input firewall,
//! and the caller sorts them.
//!
//! # Standards
//!
//! - RFC 2516 section 5: PPPoE Discovery frames have Ethernet type 0x8863.
//! - RFC 2516 section 4 and RFC 1661 section 2: in a session frame (0x8864, version
//!   and type 1, code 0) a PPP protocol number from 0x8000 is a control protocol
//!   (LCP 0xc021, PAP 0xc023, CHAP 0xc223, IPCP 0x8021, IPv6CP 0x8057); IPv4
//!   (0x0021) and IPv6 (0x0057) are data and are forwarded.
//! - RFC 919 section 7: 255.255.255.255 is the broadcast of the local network; RFC
//!   4291 section 2.7: ff02::/16 is link-local scope multicast. DHCP (RFC 2131
//!   section 4.1, ports 67 and 68) and DHCPv6 (RFC 8415 section 7, ff02::1:2, ports
//!   546 and 547) reach the router at those addresses.
//!
//! Deviations: a session frame of any session ID is picked out, whether or not a
//! session interface has it, because control comes before the session is set up.
//! The PPP protocol field is read as two bytes (no protocol-field compression, RFC
//! 1661 6.5). An IP packet is matched only with its transport header right after
//! the IP header: not an IPv4 fragment, nor IPv6 with an extension header.

use crate::IfId;

const ETHERNET: usize = 14;
const DISCOVERY: [u8; 2] = [0x88, 0x63];
const SESSION: [u8; 2] = [0x88, 0x64];
const IPV4: [u8; 2] = [0x08, 0x00];
const IPV6: [u8; 2] = [0x86, 0xdd];

/// What a [`PuntFrameMatch`] picks out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PuntFrameKind {
    PppoeDiscovery,
    PppControl,
    /// IP packets of `protocol` to 255.255.255.255 or to an ff02::/16 address; for
    /// TCP and UDP only to the destination ports `first..=last` when given.
    Ip {
        protocol: u8,
        ports: Option<(u16, u16)>,
    },
}

/// One kind of frame to pick out, on `ingress` or on any interface, and the class
/// the caller knows it by.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PuntFrameMatch {
    pub ingress: Option<IfId>,
    pub kind: PuntFrameKind,
    pub class: u16,
}

/// The class of the first match of `frame` (Ethernet, without a VLAN tag) that came
/// in on `ingress`.
#[must_use]
pub fn select(frame: &[u8], ingress: IfId, matches: &[PuntFrameMatch]) -> Option<u16> {
    let ethertype = frame.get(12..14)?;
    let found = |kind: &dyn Fn(PuntFrameKind) -> bool| {
        matches
            .iter()
            .find(|m| m.ingress.is_none_or(|id| id == ingress) && kind(m.kind))
            .map(|m| m.class)
    };
    match [ethertype[0], ethertype[1]] {
        DISCOVERY => found(&|kind| kind == PuntFrameKind::PppoeDiscovery),
        SESSION => {
            let header = frame.get(ETHERNET..ETHERNET + 8)?;
            let protocol = u16::from_be_bytes([header[6], header[7]]);
            if header[0] != 0x11 || header[1] != 0 || protocol < 0x8000 {
                return None;
            }
            found(&|kind| kind == PuntFrameKind::PppControl)
        }
        IPV4 | IPV6 => {
            let (protocol, port) = ip_to_link(frame)?;
            found(&|kind| match kind {
                PuntFrameKind::Ip { protocol: p, ports } => {
                    p == protocol
                        && ports.is_none_or(|(first, last)| {
                            port.is_some_and(|port| (first..=last).contains(&port))
                        })
                }
                _ => false,
            })
        }
        _ => None,
    }
}

/// For an IP packet to 255.255.255.255 or ff02::/16 with its transport header
/// right after the IP header: the protocol and, for TCP and UDP, the destination
/// port.
fn ip_to_link(frame: &[u8]) -> Option<(u8, Option<u16>)> {
    let ip = frame.get(ETHERNET..)?;
    let (protocol, header) = match ip.first()? >> 4 {
        4 => {
            let header = usize::from(ip[0] & 0x0f) * 4;
            let flags = u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]);
            // A fragment, the first included, or not to the broadcast address.
            if header < 20 || flags & 0x3fff != 0 || ip.get(16..20)? != [0xff; 4] {
                return None;
            }
            (*ip.get(9)?, header)
        }
        6 => {
            let destination = ip.get(24..40)?;
            if destination[0] != 0xff || destination[1] & 0x0f != 2 {
                return None;
            }
            (ip[6], 40)
        }
        _ => return None,
    };
    let port = match protocol {
        6 | 17 => Some(u16::from_be_bytes([
            *ip.get(header + 2)?,
            *ip.get(header + 3)?,
        ])),
        _ => None,
    };
    Some((protocol, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DHCP: PuntFrameMatch = PuntFrameMatch {
        ingress: Some(IfId(1)),
        kind: PuntFrameKind::Ip {
            protocol: 17,
            ports: Some((67, 67)),
        },
        class: 9,
    };
    const DHCPV6: PuntFrameMatch = PuntFrameMatch {
        ingress: None,
        kind: PuntFrameKind::Ip {
            protocol: 17,
            ports: Some((547, 547)),
        },
        class: 10,
    };
    const DISCOVERY_ANY: PuntFrameMatch = PuntFrameMatch {
        ingress: None,
        kind: PuntFrameKind::PppoeDiscovery,
        class: 11,
    };
    const CONTROL_ANY: PuntFrameMatch = PuntFrameMatch {
        ingress: None,
        kind: PuntFrameKind::PppControl,
        class: 12,
    };
    const ALL: [PuntFrameMatch; 4] = [DHCP, DHCPV6, DISCOVERY_ANY, CONTROL_ANY];

    fn dhcp_discover(destination: [u8; 4], flags: u16) -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + 28];
        frame[12..14].copy_from_slice(&IPV4);
        frame[14] = 0x45;
        frame[14 + 6..14 + 8].copy_from_slice(&flags.to_be_bytes());
        frame[14 + 9] = 17;
        frame[14 + 16..14 + 20].copy_from_slice(&destination);
        frame[14 + 22..14 + 24].copy_from_slice(&67_u16.to_be_bytes());
        frame
    }

    fn dhcpv6_solicit(destination: [u8; 16], next_header: u8) -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + 48];
        frame[12..14].copy_from_slice(&IPV6);
        frame[14] = 0x60;
        frame[14 + 6] = next_header;
        frame[14 + 24..14 + 40].copy_from_slice(&destination);
        frame[14 + 42..14 + 44].copy_from_slice(&547_u16.to_be_bytes());
        frame
    }

    fn session(protocol: u16) -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + 8 + 4];
        frame[12..14].copy_from_slice(&SESSION);
        frame[14] = 0x11;
        frame[16..18].copy_from_slice(&7_u16.to_be_bytes());
        frame[18..20].copy_from_slice(&6_u16.to_be_bytes());
        frame[20..22].copy_from_slice(&protocol.to_be_bytes());
        frame
    }

    #[test]
    fn dhcp_to_the_broadcast_address_on_its_interface_is_picked_out() {
        let broadcast = dhcp_discover([255; 4], 0);
        assert_eq!(select(&broadcast, IfId(1), &ALL), Some(9));
        assert_eq!(select(&broadcast, IfId(2), &ALL), None, "another port");
        let unicast = dhcp_discover([192, 0, 2, 1], 0);
        assert_eq!(select(&unicast, IfId(1), &ALL), None, "to an address");
        let fragment = dhcp_discover([255; 4], 0x2000);
        assert_eq!(select(&fragment, IfId(1), &ALL), None, "a first fragment");
        let mut other_port = broadcast.clone();
        other_port[14 + 23] = 68;
        assert_eq!(select(&other_port, IfId(1), &ALL), None);
    }

    #[test]
    fn dhcpv6_to_link_local_multicast_is_picked_out() {
        let mut all_servers = [0_u8; 16];
        all_servers[0] = 0xff;
        all_servers[1] = 0x02;
        all_servers[13] = 1;
        all_servers[15] = 2;
        assert_eq!(
            select(&dhcpv6_solicit(all_servers, 17), IfId(3), &ALL),
            Some(10)
        );
        assert_eq!(
            select(&dhcpv6_solicit(all_servers, 0), IfId(3), &ALL),
            None,
            "behind a Hop-by-Hop header"
        );
        let mut site = all_servers;
        site[1] = 0x05;
        assert_eq!(select(&dhcpv6_solicit(site, 17), IfId(3), &ALL), None);
    }

    #[test]
    fn pppoe_discovery_and_ppp_control_are_picked_out_but_not_session_data() {
        let mut padi = vec![0_u8; 14 + 6];
        padi[12..14].copy_from_slice(&DISCOVERY);
        assert_eq!(select(&padi, IfId(0), &ALL), Some(11));
        assert_eq!(select(&session(0xc021), IfId(0), &ALL), Some(12), "LCP");
        assert_eq!(select(&session(0x8057), IfId(0), &ALL), Some(12), "IPv6CP");
        assert_eq!(select(&session(0x0021), IfId(0), &ALL), None, "IPv4");
        assert_eq!(select(&session(0x0057), IfId(0), &ALL), None, "IPv6");
        let mut bad_version = session(0xc021);
        bad_version[14] = 0x21;
        assert_eq!(select(&bad_version, IfId(0), &ALL), None);
        assert_eq!(select(&padi, IfId(0), &[DHCP]), None, "not asked for");
    }

    #[test]
    fn short_frames_are_not_read_past_their_end() {
        let frames = [
            dhcp_discover([255; 4], 0),
            dhcpv6_solicit([0xff; 16], 17),
            session(0xc021),
        ];
        for frame in &frames {
            for len in 0..frame.len() {
                let _ = select(&frame[..len], IfId(1), &ALL);
            }
        }
        let mut bad_ihl = dhcp_discover([255; 4], 0);
        bad_ihl[14] = 0x41;
        assert_eq!(select(&bad_ihl, IfId(1), &ALL), None);
    }
}
