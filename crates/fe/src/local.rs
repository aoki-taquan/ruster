//! Traffic addressed to the router: handed to the kernel, one pipe per VRF, and the
//! kernel's packets sent back out.
//!
//! A pipe carries one IP packet per message, as a TUN device without packet
//! information does. Packets to the kernel are limited per class (ICMP errors,
//! other ICMP, TCP SYNs, other TCP, UDP, other) by a token bucket, so a flood of one kind does not crowd out the others or
//! the forwarding; ARP and Neighbor Discovery to the neighbor process have their own
//! buckets too.

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
    /// ARP to the neighbor process.
    Arp = 4,
    /// Neighbor Discovery to the neighbor process.
    Nd = 5,
    /// ICMP and ICMPv6 errors (Destination Unreachable, Packet Too Big, Time
    /// Exceeded, Parameter Problem): the router's own connections need them, so a
    /// flood of echo requests does not take their place (RFC 6192 section 3).
    IcmpError = 6,
    /// TCP SYNs that open a connection: a flood of them does not take the place of
    /// established connections (BGP, SSH) (RFC 6192 section 3).
    TcpSyn = 7,
}

/// The class of an IP packet (`packet` starts at the IP header).
pub(crate) fn class(packet: &[u8]) -> Class {
    let (protocol, header) = match packet.first().map(|b| b >> 4) {
        Some(4) => (packet.get(9).copied(), usize::from(packet[0] & 0x0f) * 4),
        Some(6) => (packet.get(6).copied(), 40),
        _ => (None, 0),
    };
    let icmp_type = packet.get(header).copied();
    match protocol {
        Some(1) if matches!(icmp_type, Some(3 | 11 | 12)) => Class::IcmpError,
        Some(58) if matches!(icmp_type, Some(1..=4)) => Class::IcmpError,
        Some(1 | 58) => Class::Icmp,
        Some(6)
            if packet
                .get(header + 13)
                .is_some_and(|flags| flags & 0x12 == 0x02) =>
        {
            Class::TcpSyn
        }
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
    tokens: [u32; 8],
    refilled_at_us: [u64; 8],
}

impl Default for Limiter {
    fn default() -> Self {
        Self {
            tokens: [LOCAL_BURST; 8],
            refilled_at_us: [0; 8],
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
        assert!(limiter.take(Class::Arp, 0), "nor ARP");
        assert!(limiter.take(Class::Nd, 0), "nor ND");
        assert!(limiter.take(Class::IcmpError, 0), "nor ICMP errors");
        assert!(limiter.take(Class::Udp, 1), "two more after a millisecond");
        assert!(limiter.take(Class::Udp, 1));
        assert!(!limiter.take(Class::Udp, 1));
    }

    #[test]
    fn icmp_errors_are_their_own_class() {
        let mut v4 = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1];
        v4.resize(28, 0);
        v4[20] = 3;
        assert_eq!(class(&v4), Class::IcmpError);
        v4[20] = 8;
        assert_eq!(class(&v4), Class::Icmp);
        let mut v6 = vec![0x60, 0, 0, 0, 0, 8, 58, 64];
        v6.resize(48, 0);
        v6[40] = 2;
        assert_eq!(class(&v6), Class::IcmpError);
        v6[40] = 128;
        assert_eq!(class(&v6), Class::Icmp);
        let mut tcp = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6];
        tcp.resize(40, 0);
        tcp[33] = 0x02;
        assert_eq!(class(&tcp), Class::TcpSyn);
        tcp[33] = 0x12;
        assert_eq!(class(&tcp), Class::Tcp, "a SYN-ACK is a reply");
        tcp[33] = 0x10;
        assert_eq!(class(&tcp), Class::Tcp);
    }
}
