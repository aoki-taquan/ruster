//! Frames for the control side that are picked out before anything else looks at
//! them: PPPoE Discovery, PPP control in PPPoE sessions, IP packets to a
//! broadcast or link-local multicast address on chosen protocols and ports (DHCP),
//! and the routing protocols the kernel's daemons speak on an interface's TAP
//! device: IS-IS PDUs and OSPF to its multicast addresses.
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
//! - ISO 10589 section 8.4.8 and ISO/IEC 8802-2: IS-IS PDUs are LLC frames with
//!   DSAP and SSAP 0xFE, to AllL1ISs 01-80-C2-00-00-14 or AllL2ISs
//!   01-80-C2-00-00-15; on a point-to-point circuit to AllISs 09-00-2B-00-00-05
//!   (ISO 9542).
//! - RFC 2328 appendix A.1 and RFC 5340 appendix A.1: OSPF is IP protocol 89, to
//!   AllSPFRouters (224.0.0.5, ff02::5) and AllDRouters (224.0.0.6, ff02::6).
//!
//! Deviations: a session frame of any session ID is picked out, whether or not a
//! session interface has it, because control comes before the session is set up.
//! The PPP protocol field is read as two bytes (no protocol-field compression, RFC
//! 1661 6.5). An IP packet is matched only with its transport header right after
//! the IP header: not an IPv4 fragment, nor IPv6 with an extension header. OSPF
//! to its multicast addresses is matched in IPv4 fragments too (the kernel puts
//! them back together), but not behind an IPv6 extension header (a fragment
//! header included). OSPF to the router's own addresses is not picked out here
//! (see above).

use crate::IfId;

const ETHERNET: usize = 14;
const DISCOVERY: [u8; 2] = [0x88, 0x63];
const SESSION: [u8; 2] = [0x88, 0x64];
const IPV4: [u8; 2] = [0x08, 0x00];
const IPV6: [u8; 2] = [0x86, 0xdd];
/// An Ethernet type field below this is an IEEE 802.3 length: an LLC frame follows.
const LENGTH_LIMIT: u16 = 0x0600;
/// The LLC service access point of ISO network layer protocols (IS-IS).
const ISO_NETWORK_SAP: u8 = 0xfe;
/// The destinations of IS-IS PDUs: AllL1ISs, AllL2ISs and AllISs.
const ISIS_DESTINATIONS: [[u8; 6]; 3] = [
    [0x01, 0x80, 0xc2, 0x00, 0x00, 0x14],
    [0x01, 0x80, 0xc2, 0x00, 0x00, 0x15],
    [0x09, 0x00, 0x2b, 0x00, 0x00, 0x05],
];
const OSPF: u8 = 89;

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
    /// IS-IS PDUs.
    Isis,
    /// OSPF to AllSPFRouters or AllDRouters.
    Ospf,
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
    if u16::from_be_bytes([ethertype[0], ethertype[1]]) < LENGTH_LIMIT {
        let to_isis = ISIS_DESTINATIONS.iter().any(|d| frame[..6] == d[..]);
        let sap = frame.get(ETHERNET..ETHERNET + 2)?;
        return (to_isis && sap == [ISO_NETWORK_SAP; 2])
            .then(|| found(&|kind| kind == PuntFrameKind::Isis))
            .flatten();
    }
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
            // An interface's OSPF class first; without one, a class for protocol
            // 89 to link-local multicast takes it as before.
            if is_ospf_multicast(frame) {
                if let Some(class) = found(&|kind| kind == PuntFrameKind::Ospf) {
                    return Some(class);
                }
            }
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

/// Whether `frame` (IPv4 or IPv6 by its Ethernet type) is OSPF to AllSPFRouters or
/// AllDRouters, with OSPF right after the IP header.
fn is_ospf_multicast(frame: &[u8]) -> bool {
    let Some(ip) = frame.get(ETHERNET..) else {
        return false;
    };
    let version = ip.first().map(|b| b >> 4);
    if frame.get(12..14) == Some(&IPV4[..]) && version == Some(4) {
        ip.get(9) == Some(&OSPF)
            && ip.get(16..19) == Some(&[224, 0, 0][..])
            && matches!(ip.get(19), Some(5 | 6))
    } else if frame.get(12..14) == Some(&IPV6[..]) && version == Some(6) {
        let mut group = [0_u8; 16];
        group[0] = 0xff;
        group[1] = 0x02;
        ip.get(6) == Some(&OSPF)
            && ip.get(24..39) == Some(&group[..15])
            && matches!(ip.get(39), Some(5 | 6))
    } else {
        false
    }
}

/// For an IP packet to 255.255.255.255 or ff02::/16 with its transport header
/// right after the IP header: the protocol and, for TCP and UDP, the destination
/// port.
fn ip_to_link(frame: &[u8]) -> Option<(u8, Option<u16>)> {
    let ip = frame.get(ETHERNET..)?;
    // The version agrees with the Ethernet type, as forwarding would check.
    let version = if frame.get(12..14)? == IPV6 { 6 } else { 4 };
    let (protocol, header) = match ip.first()? >> 4 {
        4 if version == 4 => {
            let header = usize::from(ip[0] & 0x0f) * 4;
            let flags = u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]);
            // A fragment, the first included, or not to the broadcast address.
            if header < 20 || flags & 0x3fff != 0 || ip.get(16..20)? != [0xff; 4] {
                return None;
            }
            (*ip.get(9)?, header)
        }
        6 if version == 6 => {
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

    const ISIS_ON_1: PuntFrameMatch = PuntFrameMatch {
        ingress: Some(IfId(1)),
        kind: PuntFrameKind::Isis,
        class: 13,
    };
    const OSPF_ON_1: PuntFrameMatch = PuntFrameMatch {
        ingress: Some(IfId(1)),
        kind: PuntFrameKind::Ospf,
        class: 14,
    };

    fn isis_hello(destination: [u8; 6]) -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + 3 + 27];
        frame[..6].copy_from_slice(&destination);
        frame[12..14].copy_from_slice(&30_u16.to_be_bytes());
        frame[14..17].copy_from_slice(&[0xfe, 0xfe, 0x03]);
        frame[17] = 0x83;
        frame
    }

    fn ospf(v4: [u8; 4]) -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + 20 + 24];
        frame[12..14].copy_from_slice(&IPV4);
        frame[14] = 0x45;
        frame[14 + 9] = 89;
        frame[14 + 16..14 + 20].copy_from_slice(&v4);
        frame
    }

    fn ospf6(last: u8) -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + 40 + 16];
        frame[12..14].copy_from_slice(&IPV6);
        frame[14] = 0x60;
        frame[14 + 6] = 89;
        frame[14 + 24] = 0xff;
        frame[14 + 25] = 0x02;
        frame[14 + 39] = last;
        frame
    }

    #[test]
    fn isis_pdus_are_picked_out_on_their_interface() {
        let all = [ISIS_ON_1, OSPF_ON_1];
        for to in ISIS_DESTINATIONS {
            assert_eq!(select(&isis_hello(to), IfId(1), &all), Some(13));
        }
        assert_eq!(
            select(&isis_hello(ISIS_DESTINATIONS[0]), IfId(2), &all),
            None
        );
        let mut other_sap = isis_hello(ISIS_DESTINATIONS[0]);
        other_sap[14] = 0x42;
        assert_eq!(select(&other_sap, IfId(1), &all), None, "STP's LLC");
        let mut unicast = isis_hello(ISIS_DESTINATIONS[0]);
        unicast[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        assert_eq!(select(&unicast, IfId(1), &all), None);
    }

    #[test]
    fn ospf_to_its_groups_is_picked_out_on_its_interface() {
        let all = [ISIS_ON_1, OSPF_ON_1];
        assert_eq!(select(&ospf([224, 0, 0, 5]), IfId(1), &all), Some(14));
        assert_eq!(select(&ospf([224, 0, 0, 6]), IfId(1), &all), Some(14));
        assert_eq!(select(&ospf([224, 0, 0, 5]), IfId(2), &all), None);
        assert_eq!(select(&ospf([224, 0, 0, 9]), IfId(1), &all), None, "RIP's");
        assert_eq!(select(&ospf([192, 0, 2, 1]), IfId(1), &all), None);
        let mut fragment = ospf([224, 0, 0, 5]);
        fragment[14 + 7] = 8;
        assert_eq!(
            select(&fragment, IfId(1), &all),
            Some(14),
            "a later fragment"
        );
        assert_eq!(select(&ospf6(5), IfId(1), &all), Some(14));
        assert_eq!(select(&ospf6(6), IfId(1), &all), Some(14));
        assert_eq!(select(&ospf6(1), IfId(1), &all), None);
        let mut behind = ospf6(5);
        behind[14 + 6] = 0;
        assert_eq!(
            select(&behind, IfId(1), &all),
            None,
            "behind an extension header"
        );
        let any_89 = PuntFrameMatch {
            ingress: None,
            kind: PuntFrameKind::Ip {
                protocol: 89,
                ports: None,
            },
            class: 15,
        };
        let both = [OSPF_ON_1, any_89];
        assert_eq!(select(&ospf6(5), IfId(1), &both), Some(14));
        assert_eq!(select(&ospf6(5), IfId(2), &both), Some(15), "as before");
        let mut not_v4 = ospf([224, 0, 0, 5]);
        not_v4[14] = 0x65;
        assert_eq!(select(&not_v4, IfId(1), &all), None);
    }

    #[test]
    fn short_frames_are_not_read_past_their_end() {
        let frames = [
            dhcp_discover([255; 4], 0),
            dhcpv6_solicit([0xff; 16], 17),
            session(0xc021),
            isis_hello(ISIS_DESTINATIONS[1]),
            ospf([224, 0, 0, 5]),
            ospf6(6),
        ];
        let all = [
            DHCP,
            DHCPV6,
            DISCOVERY_ANY,
            CONTROL_ANY,
            ISIS_ON_1,
            OSPF_ON_1,
        ];
        for frame in &frames {
            for len in 0..frame.len() {
                let _ = select(&frame[..len], IfId(1), &all);
            }
        }
        let mut bad_ihl = dhcp_discover([255; 4], 0);
        bad_ihl[14] = 0x41;
        assert_eq!(select(&bad_ihl, IfId(1), &ALL), None);
    }
}
