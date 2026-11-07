//! Traffic addressed to the router: handed to the kernel, one pipe per VRF, and the
//! kernel's packets sent back out.
//!
//! A pipe carries one IP packet per message, as a TUN device without packet
//! information does. Packets to the kernel are limited per class (ICMP, TCP, UDP,
//! other) by a token bucket, so a flood of one kind does not crowd out the others or
//! the forwarding.

use std::io;
use std::os::unix::net::UnixDatagram;

/// One VRF's connection to the kernel: one IP packet per message.
pub trait LocalPipe {
    fn send(&self, packet: &[u8]) -> io::Result<usize>;
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
}

impl LocalPipe for UnixDatagram {
    fn send(&self, packet: &[u8]) -> io::Result<usize> {
        UnixDatagram::send(self, packet)
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        UnixDatagram::recv(self, buf)
    }
}

impl LocalPipe for std::fs::File {
    fn send(&self, packet: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut &*self, packet)
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut &*self, buf)
    }
}

/// The classes packets to the router are limited by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    Icmp = 0,
    Tcp = 1,
    Udp = 2,
    Other = 3,
}

/// The class of an IP packet (`packet` starts at the IP header).
pub(crate) fn class(packet: &[u8]) -> Class {
    let protocol = match packet.first().map(|b| b >> 4) {
        Some(4) => packet.get(9).copied(),
        Some(6) => packet.get(6).copied(),
        _ => None,
    };
    match protocol {
        Some(1 | 58) => Class::Icmp,
        Some(6) => Class::Tcp,
        Some(17) => Class::Udp,
        _ => Class::Other,
    }
}

/// Packets per class that may go to the kernel at once.
pub const LOCAL_BURST: u32 = 200;
/// One more packet of a class may go after this many microseconds (2000 per second).
pub const LOCAL_INTERVAL_US: u64 = 500;

/// Token buckets, one per class.
#[derive(Debug)]
pub(crate) struct Limiter {
    tokens: [u32; 4],
    refilled_at_us: [u64; 4],
}

impl Default for Limiter {
    fn default() -> Self {
        Self {
            tokens: [LOCAL_BURST; 4],
            refilled_at_us: [0; 4],
        }
    }
}

impl Limiter {
    pub(crate) fn take(&mut self, class: Class, now_ms: u64) -> bool {
        let i = class as usize;
        let now_us = now_ms.saturating_mul(1_000);
        let earned = now_us.saturating_sub(self.refilled_at_us[i]) / LOCAL_INTERVAL_US;
        if earned > 0 {
            let earned = u32::try_from(earned).unwrap_or(u32::MAX);
            self.tokens[i] = self.tokens[i].saturating_add(earned).min(LOCAL_BURST);
            self.refilled_at_us[i] = now_us;
        }
        if self.tokens[i] == 0 {
            return false;
        }
        self.tokens[i] -= 1;
        true
    }
}

/// The destination address of an IP packet.
pub(crate) fn destination(packet: &[u8]) -> Option<std::net::IpAddr> {
    match packet.first()? >> 4 {
        4 => {
            let d: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            Some(std::net::IpAddr::V4(d.into()))
        }
        6 => {
            let d: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            Some(std::net::IpAddr::V6(d.into()))
        }
        _ => None,
    }
}

/// For an IPv4 `packet` from the kernel that a tunnel of `mtu` cannot carry and
/// that may not be fragmented (DF set): an ICMP Destination Unreachable,
/// Fragmentation Needed (RFC 792, RFC 1191 section 4, the Next-Hop MTU), back to
/// the kernel, so its path MTU discovery lowers the size. Its source is the
/// packet's destination: the kernel matches it by the quoted header only.
pub(crate) fn fragmentation_needed(packet: &[u8], mtu: u16) -> Option<Vec<u8>> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header = usize::from(packet[0] & 0x0f) * 4;
    let flags = u16::from_be_bytes([packet[6], packet[7]]);
    let df = flags & 0x4000 != 0;
    if !df || flags & 0x1fff != 0 || packet.len() < header {
        return None;
    }
    let quote = &packet[..(header + 8).min(packet.len())];
    let total = 20 + 8 + quote.len();
    let mut out = vec![0_u8; total];
    out[0] = 0x45;
    out[2..4].copy_from_slice(&u16::try_from(total).ok()?.to_be_bytes());
    out[8] = 64;
    out[9] = 1;
    out[12..16].copy_from_slice(&packet[16..20]);
    out[16..20].copy_from_slice(&packet[12..16]);
    let checksum = ruster_core::ipv4_header_checksum(&out[..20]);
    out[10..12].copy_from_slice(&checksum.to_be_bytes());
    out[20] = 3;
    out[21] = 4;
    out[26..28].copy_from_slice(&mtu.to_be_bytes());
    out[28..].copy_from_slice(quote);
    let checksum = ruster_core::internet_checksum(&out[20..]);
    out[22..24].copy_from_slice(&checksum.to_be_bytes());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_class_has_its_own_bucket() {
        let mut limiter = Limiter::default();
        for _ in 0..LOCAL_BURST {
            assert!(limiter.take(Class::Udp, 0));
        }
        assert!(!limiter.take(Class::Udp, 0), "UDP is used up");
        assert!(limiter.take(Class::Tcp, 0), "TCP is not");
        assert!(limiter.take(Class::Udp, 1), "two more after a millisecond");
        assert!(limiter.take(Class::Udp, 1));
        assert!(!limiter.take(Class::Udp, 1));
    }
}
