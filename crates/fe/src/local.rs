//! Traffic addressed to the router: handed to the kernel, one pipe per VRF, and the
//! kernel's packets sent back out.
//!
//! A pipe carries one IP packet per message, as a TUN device without packet
//! information does. Which class of the punt table ([`crate::punt_table`]) a packet to the
//! kernel belongs to, and so its rate limit, is decided there; this module holds the
//! pipes, the kinds the kernel's traffic falls into when no class names it (ICMP
//! errors, other ICMP, TCP SYNs, other TCP, UDP, other), and the token bucket every
//! class is limited by.
//!
//! # Standards
//!
//! - RFC 6192 section 3 (Informational, an example rather than a requirement):
//!   traffic to the router is sorted into classes before it reaches the control
//!   side, and each class is rate limited, at rates each deployment sets
//!   (section 3.2).
//!
//! Deviations: no class is filtered by source address, and fragments are not
//! dropped (section 3.1). The kind is read at a fixed place: an ICMPv6 packet
//! behind an extension header, and an IPv4 fragment after the first, are of the
//! kind `other`.

use std::io;
use std::os::unix::net::UnixDatagram;

use ruster_proto::table::PuntKind;

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

/// The kind of an IP packet to the kernel (`packet` starts at the IP header): one of
/// `icmp-error`, `icmp`, `tcp-syn`, `tcp`, `udp` and `other`.
pub(crate) fn kind(packet: &[u8]) -> PuntKind {
    let (protocol, header) = match packet.first().map(|b| b >> 4) {
        // A fragment after the first has no transport header: its bytes there are
        // data, so it is classed by nothing but being IP.
        Some(4) if is_later_fragment(packet) => (None, 0),
        Some(4) => (packet.get(9).copied(), usize::from(packet[0] & 0x0f) * 4),
        Some(6) => (packet.get(6).copied(), 40),
        _ => (None, 0),
    };
    let icmp_type = packet.get(header).copied();
    match protocol {
        Some(1) if matches!(icmp_type, Some(3 | 11 | 12)) => PuntKind::IcmpError,
        Some(58) if matches!(icmp_type, Some(1..=4)) => PuntKind::IcmpError,
        Some(1 | 58) => PuntKind::Icmp,
        Some(6)
            if packet
                .get(header + 13)
                .is_some_and(|flags| flags & 0x12 == 0x02) =>
        {
            PuntKind::TcpSyn
        }
        Some(6) => PuntKind::Tcp,
        Some(17) => PuntKind::Udp,
        _ => PuntKind::Other,
    }
}

/// Whether an IPv4 packet is a fragment after the first (its offset is not 0).
fn is_later_fragment(packet: &[u8]) -> bool {
    packet
        .get(6..8)
        .is_some_and(|f| u16::from_be_bytes([f[0], f[1]]) & 0x1fff != 0)
}

/// A token bucket: `rate` packets per second, `burst` at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bucket {
    rate: u32,
    burst: u32,
    tokens: u32,
    refilled_at_us: u64,
}

impl Bucket {
    /// A full bucket. `rate` and `burst` are at least 1 (the table checks them).
    pub(crate) fn new(rate: u32, burst: u32) -> Self {
        Self {
            rate: rate.max(1),
            burst: burst.max(1),
            tokens: burst.max(1),
            refilled_at_us: 0,
        }
    }

    /// The same bucket with another rate and burst, keeping its tokens (at most the
    /// new burst).
    pub(crate) fn with_limits(self, rate: u32, burst: u32) -> Self {
        let mut next = Self::new(rate, burst);
        next.tokens = self.tokens.min(next.burst);
        next.refilled_at_us = self.refilled_at_us;
        next
    }

    pub(crate) fn take(&mut self, now_ms: u64) -> bool {
        let now_us = now_ms.saturating_mul(1_000);
        let elapsed = u128::from(now_us.saturating_sub(self.refilled_at_us));
        let earned = elapsed * u128::from(self.rate) / 1_000_000;
        if earned > 0 {
            let earned = u32::try_from(earned).unwrap_or(u32::MAX);
            self.tokens = self.tokens.saturating_add(earned).min(self.burst);
            // The time the earned tokens took, so that a fraction is kept for the
            // next one; all of it once the bucket is full.
            self.refilled_at_us = if self.tokens == self.burst {
                now_us
            } else {
                let spent = u128::from(earned) * 1_000_000 / u128::from(self.rate);
                self.refilled_at_us
                    .saturating_add(u64::try_from(spent).unwrap_or(u64::MAX))
            };
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bucket_gives_its_burst_then_its_rate() {
        let mut bucket = Bucket::new(2_000, 200);
        for _ in 0..200 {
            assert!(bucket.take(0));
        }
        assert!(!bucket.take(0), "used up");
        assert!(bucket.take(1), "two more after a millisecond");
        assert!(bucket.take(1));
        assert!(!bucket.take(1));
        // 3 per second: one every 333 ms, the fractions kept.
        let mut slow = Bucket::new(3, 3);
        for _ in 0..3 {
            assert!(slow.take(0));
        }
        assert!(!slow.take(300));
        assert!(slow.take(334));
        assert!(!slow.take(600));
        assert!(slow.take(667));
        assert!(slow.take(1_000));
        assert!(!slow.take(1_000));
    }

    #[test]
    fn new_limits_keep_the_tokens_left() {
        let mut bucket = Bucket::new(10, 10);
        for _ in 0..8 {
            assert!(bucket.take(0));
        }
        let mut changed = bucket.with_limits(10, 5);
        assert!(changed.take(0));
        assert!(changed.take(0));
        assert!(!changed.take(0), "2 left, not a new burst");
    }

    #[test]
    fn icmp_errors_are_their_own_kind() {
        let mut v4 = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1];
        v4.resize(28, 0);
        v4[20] = 3;
        assert_eq!(kind(&v4), PuntKind::IcmpError);
        v4[20] = 8;
        assert_eq!(kind(&v4), PuntKind::Icmp);
        let mut v6 = vec![0x60, 0, 0, 0, 0, 8, 58, 64];
        v6.resize(48, 0);
        v6[40] = 2;
        assert_eq!(kind(&v6), PuntKind::IcmpError);
        v6[40] = 128;
        assert_eq!(kind(&v6), PuntKind::Icmp);
        let mut tcp = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6];
        tcp.resize(40, 0);
        tcp[33] = 0x02;
        assert_eq!(kind(&tcp), PuntKind::TcpSyn);
        tcp[33] = 0x12;
        assert_eq!(kind(&tcp), PuntKind::Tcp, "a SYN-ACK is a reply");
        tcp[33] = 0x10;
        assert_eq!(kind(&tcp), PuntKind::Tcp);
    }

    #[test]
    fn a_later_fragment_is_not_classed_by_its_data() {
        // Offset 8 (64 bytes): what sits where a TCP header would be is data.
        let mut later = vec![0x45, 0, 0, 40, 0, 0, 0, 8, 64, 6];
        later.resize(40, 0);
        later[33] = 0x02;
        assert_eq!(kind(&later), PuntKind::Other);
        // The first fragment (MF set, offset 0) has the header.
        later[6] = 0x20;
        later[7] = 0;
        assert_eq!(kind(&later), PuntKind::TcpSyn);
    }
}
