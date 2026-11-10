//! The TAP devices of the interfaces that run IS-IS or OSPF
//! (`docs/design/overlay.md` section 6): the kernel's daemons speak the routing
//! protocols on `rp-<interface>`, an Ethernet device in the kernel's namespace that
//! stands for that interface.
//!
//! Frames of a punt class whose destination is the TAP (kinds `isis` and `ospf`)
//! are written to the TAP of the interface they came in on, unchanged. What the
//! kernel writes to a TAP is sorted by [`sort`]:
//!
//! - an LLC frame (IS-IS) or IP to a link-local multicast group goes out of that
//!   interface unchanged (into the bridge, for an IRB);
//! - IPv6 to a link-local unicast address (OSPFv3 to a neighbor) goes out of that
//!   interface to the neighbor's MAC address, which the kernel does not know: the
//!   TAP has no ARP or Neighbor Discovery (`NOARP`), so it puts its own;
//! - other IP is the router's own packet, handled as one the kernel wrote to the
//!   VRF's TUN (routed by the FE's tables).
//!
//! # Standards
//!
//! - IEEE 802.3 clause 3.2.6: a type field below 0x0600 is a length, and an LLC
//!   frame (ISO/IEC 8802-2) follows.
//! - RFC 5771 section 4: 224.0.0.0/24 is the local network control block, not
//!   forwarded; RFC 4291 section 2.7: ff02::/16 is link-local scope.
//! - RFC 4291 section 2.5.6: fe80::/10 is link-local unicast, valid only on its link.
//!
//! Deviations: no other frame leaves a TAP (ARP, other Ethernet types); IPv4 to a
//! neighbor on the link takes the TUN's way, through the FE's routes.

/// Where a frame the kernel wrote to an interface's TAP goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FromTap {
    /// Out of the interface, unchanged.
    Link,
    /// Out of the interface to this IPv6 link-local neighbor, its MAC address put in.
    Neighbor([u8; 16]),
    /// Through the FE's routes, as the kernel's packet (from the IP header on).
    Routed,
    /// Nowhere.
    Drop,
}

const ETHERNET_HEADER: usize = 14;
const LENGTH_LIMIT: u16 = 0x0600;

/// Where `frame`, written to a TAP by the kernel, goes.
pub(crate) fn sort(frame: &[u8]) -> FromTap {
    let Some(&[a, b]) = frame.get(12..14) else {
        return FromTap::Drop;
    };
    let ip = &frame[ETHERNET_HEADER..];
    match u16::from_be_bytes([a, b]) {
        length if length < LENGTH_LIMIT => FromTap::Link,
        0x0800 if ip.first().is_some_and(|v| v >> 4 == 4) => match ip.get(16..19) {
            Some([224, 0, 0]) => FromTap::Link,
            Some(_) => FromTap::Routed,
            None => FromTap::Drop,
        },
        0x86dd if ip.first().is_some_and(|v| v >> 4 == 6) => {
            let Some(destination) = ip.get(24..40) else {
                return FromTap::Drop;
            };
            let mut address = [0_u8; 16];
            address.copy_from_slice(destination);
            match address {
                [0xff, 0x02, ..] => FromTap::Link,
                [0xfe, second, ..] if second & 0xc0 == 0x80 => FromTap::Neighbor(address),
                _ => FromTap::Routed,
            }
        }
        _ => FromTap::Drop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(ethertype: u16, ip: &[u8]) -> Vec<u8> {
        let mut frame = vec![0_u8; 14];
        frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(ip);
        frame
    }

    fn ipv4(destination: [u8; 4]) -> Vec<u8> {
        let mut ip = vec![0_u8; 20];
        ip[0] = 0x45;
        ip[16..20].copy_from_slice(&destination);
        ip
    }

    fn ipv6(destination: [u8; 16]) -> Vec<u8> {
        let mut ip = vec![0_u8; 40];
        ip[0] = 0x60;
        ip[24..40].copy_from_slice(&destination);
        ip
    }

    #[test]
    fn link_frames_go_out_and_the_rest_is_routed() {
        assert_eq!(sort(&frame(30, &[0xfe, 0xfe, 3])), FromTap::Link, "IS-IS");
        assert_eq!(sort(&frame(0x0800, &ipv4([224, 0, 0, 5]))), FromTap::Link);
        assert_eq!(sort(&frame(0x0800, &ipv4([224, 0, 1, 5]))), FromTap::Routed);
        assert_eq!(sort(&frame(0x0800, &ipv4([192, 0, 2, 2]))), FromTap::Routed);
        let mut group = [0_u8; 16];
        group[..2].copy_from_slice(&[0xff, 0x02]);
        group[15] = 5;
        assert_eq!(sort(&frame(0x86dd, &ipv6(group))), FromTap::Link);
        let mut neighbor = [0_u8; 16];
        neighbor[..2].copy_from_slice(&[0xfe, 0x80]);
        neighbor[15] = 2;
        assert_eq!(
            sort(&frame(0x86dd, &ipv6(neighbor))),
            FromTap::Neighbor(neighbor)
        );
        let mut global = [0_u8; 16];
        global[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(sort(&frame(0x86dd, &ipv6(global))), FromTap::Routed);
    }

    #[test]
    fn other_frames_are_dropped() {
        assert_eq!(sort(&frame(0x0806, &[0; 28])), FromTap::Drop, "ARP");
        assert_eq!(
            sort(&frame(0x0800, &ipv6([0; 16]))),
            FromTap::Drop,
            "not IPv4"
        );
        assert_eq!(sort(&frame(0x86dd, &ipv4([224, 0, 0, 5]))), FromTap::Drop);
        assert_eq!(sort(&frame(0x0800, &[0x45; 10])), FromTap::Drop, "short");
        assert_eq!(sort(&[0; 13]), FromTap::Drop);
    }
}
