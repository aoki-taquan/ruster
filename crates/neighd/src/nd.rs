//! IPv6 Neighbor Discovery messages: reading and checking them, and building the
//! Neighbor Solicitations and Advertisements neighd sends.
//!
//! # Standards
//!
//! - RFC 4861 section 4.3 and 4.4: the Neighbor Solicitation and Advertisement
//!   formats; section 4.6.1: the Source and Target Link-Layer Address options.
//! - RFC 4861 sections 7.1.1 and 7.1.2: the checks on a received message (Hop Limit
//!   255, valid ICMP checksum, code 0, length at least 24, target not multicast, no
//!   option of length 0, an unspecified source only to a solicited-node group and
//!   without a Source Link-Layer Address option, a multicast destination only with
//!   the Solicited flag clear).
//! - RFC 4291 section 2.7.1: the solicited-node multicast address; RFC 2464 section
//!   7: its Ethernet address.
//! - RFC 4443 section 2.3: the ICMPv6 checksum over the pseudo-header.

use std::net::Ipv6Addr;

const ETHERNET_HEADER: usize = 14;
const IPV6_HEADER: usize = 40;
const ICMPV6: u8 = 58;
const ND_HOP_LIMIT: u8 = 255;
pub const NEIGHBOR_SOLICITATION: u8 = 135;
pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;
const OPTION_SOURCE_LINK_LAYER: u8 = 1;
const OPTION_TARGET_LINK_LAYER: u8 = 2;
/// Neighbor Advertisement flags (RFC 4861 section 4.4).
const FLAG_ROUTER: u8 = 0x80;
const FLAG_SOLICITED: u8 = 0x40;
const FLAG_OVERRIDE: u8 = 0x20;

/// A checked Neighbor Solicitation or Advertisement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    pub source_mac: [u8; 6],
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub kind: Kind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Solicitation {
        target: Ipv6Addr,
        source_link_layer: Option<[u8; 6]>,
    },
    Advertisement {
        target: Ipv6Addr,
        solicited: bool,
        overrides: bool,
        target_link_layer: Option<[u8; 6]>,
    },
}

/// Why a frame was not a usable Neighbor Discovery message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Router Solicitation and Advertisement, Redirect: not neighd's.
    NotForNeighd,
    Invalid,
}

fn address(bytes: &[u8]) -> Ipv6Addr {
    let mut out = [0; 16];
    out.copy_from_slice(&bytes[..16]);
    Ipv6Addr::from(out)
}

/// The ICMPv6 checksum of `icmp` between `source` and `destination`.
fn checksum(source: Ipv6Addr, destination: Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |bytes: &[u8]| {
        for pair in bytes.chunks(2) {
            let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
            sum += u32::from(word);
        }
    };
    add(&source.octets());
    add(&destination.octets());
    let len = u32::try_from(icmp.len()).unwrap_or(u32::MAX);
    add(&len.to_be_bytes());
    add(&[0, 0, 0, ICMPV6]);
    add(icmp);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Reads one Ethernet frame carrying an ND message.
pub fn parse(frame: &[u8]) -> Result<Message, Refused> {
    let ip = ETHERNET_HEADER;
    if frame.len() < ip + IPV6_HEADER || frame[12..14] != [0x86, 0xdd] || frame[ip] >> 4 != 6 {
        return Err(Refused::Invalid);
    }
    let payload_len = usize::from(u16::from_be_bytes([frame[ip + 4], frame[ip + 5]]));
    let icmp_at = ip + IPV6_HEADER;
    let Some(icmp) = frame.get(icmp_at..icmp_at + payload_len) else {
        return Err(Refused::Invalid);
    };
    if frame[ip + 6] != ICMPV6 || icmp.is_empty() {
        return Err(Refused::Invalid);
    }
    let kind = icmp[0];
    if kind != NEIGHBOR_SOLICITATION && kind != NEIGHBOR_ADVERTISEMENT {
        return Err(Refused::NotForNeighd);
    }
    let source = address(&frame[ip + 8..]);
    let destination = address(&frame[ip + 24..]);
    if frame[ip + 7] != ND_HOP_LIMIT
        || icmp.len() < 24
        || icmp[1] != 0
        || checksum(source, destination, icmp) != 0
    {
        return Err(Refused::Invalid);
    }
    let target = address(&icmp[8..]);
    if target.is_multicast() {
        return Err(Refused::Invalid);
    }
    let mut source_link_layer = None;
    let mut target_link_layer = None;
    let mut options = &icmp[24..];
    while !options.is_empty() {
        let (Some(&option), Some(&units)) = (options.first(), options.get(1)) else {
            return Err(Refused::Invalid);
        };
        let len = usize::from(units) * 8;
        if len == 0 || len > options.len() {
            return Err(Refused::Invalid);
        }
        if len == 8 {
            let mut mac = [0; 6];
            mac.copy_from_slice(&options[2..8]);
            match option {
                OPTION_SOURCE_LINK_LAYER => source_link_layer = Some(mac),
                OPTION_TARGET_LINK_LAYER => target_link_layer = Some(mac),
                _ => {}
            }
        }
        options = &options[len..];
    }
    let mut source_mac = [0; 6];
    source_mac.copy_from_slice(&frame[6..12]);
    let kind = if kind == NEIGHBOR_SOLICITATION {
        if source.is_unspecified()
            && (!is_solicited_node(destination) || source_link_layer.is_some())
        {
            return Err(Refused::Invalid);
        }
        Kind::Solicitation {
            target,
            source_link_layer,
        }
    } else {
        let flags = icmp[4];
        let solicited = flags & FLAG_SOLICITED != 0;
        if destination.is_multicast() && solicited {
            return Err(Refused::Invalid);
        }
        Kind::Advertisement {
            target,
            solicited,
            overrides: flags & FLAG_OVERRIDE != 0,
            target_link_layer,
        }
    };
    Ok(Message {
        source_mac,
        source,
        destination,
        kind,
    })
}

fn is_solicited_node(address: Ipv6Addr) -> bool {
    let o = address.octets();
    o[..13] == [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff]
}

/// The solicited-node multicast address of `target` (RFC 4291 section 2.7.1).
pub fn solicited_node(target: Ipv6Addr) -> Ipv6Addr {
    let t = target.octets();
    let mut o = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0];
    o[13..].copy_from_slice(&t[13..]);
    Ipv6Addr::from(o)
}

/// The Ethernet address of an IPv6 multicast group (RFC 2464 section 7).
pub fn multicast_mac(group: Ipv6Addr) -> [u8; 6] {
    let o = group.octets();
    [0x33, 0x33, o[12], o[13], o[14], o[15]]
}

fn frame(
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    mut icmp: Vec<u8>,
) -> Vec<u8> {
    let sum = checksum(source, destination, &icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut out = Vec::with_capacity(ETHERNET_HEADER + IPV6_HEADER + icmp.len());
    out.extend_from_slice(&destination_mac);
    out.extend_from_slice(&source_mac);
    out.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    out.extend_from_slice(&u16::try_from(icmp.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&[ICMPV6, ND_HOP_LIMIT]);
    out.extend_from_slice(&source.octets());
    out.extend_from_slice(&destination.octets());
    out.extend_from_slice(&icmp);
    out
}

/// A Neighbor Solicitation for `target` to its solicited-node group, from `source`
/// with our link-layer address.
pub fn solicitation(mac: [u8; 6], source: Ipv6Addr, target: Ipv6Addr) -> Vec<u8> {
    let group = solicited_node(target);
    let mut icmp = vec![NEIGHBOR_SOLICITATION, 0, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&target.octets());
    icmp.extend_from_slice(&[OPTION_SOURCE_LINK_LAYER, 1]);
    icmp.extend_from_slice(&mac);
    frame(multicast_mac(group), mac, source, group, icmp)
}

/// A Neighbor Solicitation for `target` sent to it alone, at `target_mac`: the probe
/// that confirms a neighbor is still reachable (RFC 4861 section 7.3.3, PROBE).
pub fn solicitation_to(
    mac: [u8; 6],
    source: Ipv6Addr,
    target: Ipv6Addr,
    target_mac: [u8; 6],
) -> Vec<u8> {
    let mut icmp = vec![NEIGHBOR_SOLICITATION, 0, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&target.octets());
    icmp.extend_from_slice(&[OPTION_SOURCE_LINK_LAYER, 1]);
    icmp.extend_from_slice(&mac);
    frame(target_mac, mac, source, target, icmp)
}

/// A Neighbor Advertisement for our `target` address, as a router, overriding.
/// `to` is the asker; `None` (an asker doing duplicate address detection) sends it to
/// all nodes, unsolicited (RFC 4861 section 7.2.4).
pub fn advertisement(mac: [u8; 6], target: Ipv6Addr, to: Option<(Ipv6Addr, [u8; 6])>) -> Vec<u8> {
    let (destination, destination_mac, solicited) = match to {
        Some((address, mac)) => (address, mac, FLAG_SOLICITED),
        None => {
            let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
            (all_nodes, multicast_mac(all_nodes), 0)
        }
    };
    let mut icmp = vec![
        NEIGHBOR_ADVERTISEMENT,
        0,
        0,
        0,
        FLAG_ROUTER | solicited | FLAG_OVERRIDE,
        0,
        0,
        0,
    ];
    icmp.extend_from_slice(&target.octets());
    icmp.extend_from_slice(&[OPTION_TARGET_LINK_LAYER, 1]);
    icmp.extend_from_slice(&mac);
    frame(destination_mac, mac, target, destination, icmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

    #[test]
    fn what_is_built_reads_back() {
        let source: Ipv6Addr = "fe80::1".parse().unwrap();
        let target: Ipv6Addr = "fe80::2".parse().unwrap();
        let ns = parse(&solicitation(MAC, source, target)).unwrap();
        assert_eq!(
            ns.destination,
            "ff02::1:ff00:2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            ns.kind,
            Kind::Solicitation {
                target,
                source_link_layer: Some(MAC)
            }
        );
        let na = parse(&advertisement(MAC, target, Some((source, [2; 6])))).unwrap();
        assert_eq!(
            na.kind,
            Kind::Advertisement {
                target,
                solicited: true,
                overrides: true,
                target_link_layer: Some(MAC)
            }
        );
        let unsolicited = parse(&advertisement(MAC, target, None)).unwrap();
        assert!(matches!(
            unsolicited.kind,
            Kind::Advertisement {
                solicited: false,
                ..
            }
        ));
    }

    #[test]
    fn broken_messages_are_refused() {
        let good = solicitation(MAC, "fe80::1".parse().unwrap(), "fe80::2".parse().unwrap());
        // Changes one byte and puts the checksum right again, so only that byte is wrong.
        let with = |at: usize, value: u8| {
            let mut frame = good.clone();
            frame[at] = value;
            frame[56..58].copy_from_slice(&[0, 0]);
            let sum = checksum(address(&frame[22..]), address(&frame[38..]), &frame[54..]);
            frame[56..58].copy_from_slice(&sum.to_be_bytes());
            frame
        };
        assert!(
            parse(&with(14 + 40 + 4, 0)).is_ok(),
            "the helper keeps it valid"
        );
        let mut sum = good.clone();
        sum[56] ^= 1;
        let cases = [
            with(21, 64),
            sum,
            with(55, 1),
            with(14 + 40 + 25, 0),
            with(14 + 40 + 8, 0xff),
            good[..60].to_vec(),
        ];
        for bad in cases {
            assert_eq!(parse(&bad), Err(Refused::Invalid));
        }
    }
}
