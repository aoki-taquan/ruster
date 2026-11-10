//! Router Advertisements: the message neighd sends for one interface's `[[ra]]`,
//! and when it sends them.
//!
//! [`advertisement`] builds the Ethernet frame. [`Schedule`] says when the next
//! one is due on an advertising interface: unsolicited ones at random intervals,
//! the first few sooner, and answers to Router Solicitations, never two within
//! [`MIN_DELAY_BETWEEN_RAS_MS`]. [`Final`] sends the last ones, with a router
//! lifetime of 0, when the interface stops advertising.
//!
//! # Standards
//!
//! - RFC 4861 section 4.2: the Router Advertisement format; section 4.6.1 the
//!   Source Link-Layer Address option, 4.6.2 the Prefix Information option, 4.6.4
//!   the MTU option. Section 6.2.3: the Source Link-Layer Address option is
//!   included, the MTU option when AdvLinkMTU is set, a Prefix Information option per
//!   prefix; the source is the interface's link-local address, the destination the
//!   all-nodes group ff02::1 (RFC 2464 section 7: 33:33:00:00:00:01), the Hop Limit
//!   255.
//! - RFC 4861 section 6.2.4: unsolicited advertisements at intervals uniformly
//!   random between MinRtrAdvInterval and MaxRtrAdvInterval; the first
//!   MAX_INITIAL_RTR_ADVERTISEMENTS (3) at most MAX_INITIAL_RTR_ADVERT_INTERVAL
//!   (16 s) apart. The same again when the interface's settings change.
//! - RFC 4861 section 6.2.6: a solicitation is answered after a random delay of up
//!   to MAX_RA_DELAY_TIME (500 ms) with a multicast advertisement, or that delay
//!   after MIN_DELAY_BETWEEN_RAS (3 s) from the last multicast one, which resets the
//!   unsolicited interval; when one is scheduled already, or the next unsolicited one
//!   comes no later, nothing more is scheduled.
//! - RFC 4861 section 6.2.5: an interface that stops advertising sends
//!   MAX_FINAL_RTR_ADVERTISEMENTS (3) with a router lifetime of 0.
//! - RFC 8106 section 5.1: the Recursive DNS Server option.
//! - RFC 4443 section 2.3: the ICMPv6 checksum.
//!
//! Deviations: answers to solicitations are always multicast (section 6.2.6 allows
//! unicast, and a multicast one is the usual case); the final advertisements go
//! [`MIN_DELAY_BETWEEN_RAS_MS`] apart (section 6.2.5 gives no spacing) and keep the
//! other fields and options of the last settings.

use std::net::Ipv6Addr;

use ruster_config::Ra;

use crate::nd;

pub const ROUTER_ADVERTISEMENT: u8 = 134;
const OPTION_SOURCE_LINK_LAYER: u8 = 1;
const OPTION_PREFIX: u8 = 3;
const OPTION_MTU: u8 = 5;
const OPTION_RDNSS: u8 = 25;
const FLAG_MANAGED: u8 = 0x80;
const FLAG_OTHER: u8 = 0x40;
const FLAG_ON_LINK: u8 = 0x80;
const FLAG_AUTONOMOUS: u8 = 0x40;

/// RFC 4861 section 10, the router constants.
pub const MAX_INITIAL_RTR_ADVERT_INTERVAL_MS: u64 = 16_000;
pub const MAX_INITIAL_RTR_ADVERTISEMENTS: u32 = 3;
pub const MAX_FINAL_RTR_ADVERTISEMENTS: u32 = 3;
pub const MIN_DELAY_BETWEEN_RAS_MS: u64 = 3_000;
pub const MAX_RA_DELAY_TIME_MS: u64 = 500;

/// The all-nodes group.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// A Router Advertisement of `ra` from `mac` and the link-local `source` to all
/// nodes. `stopping` gives a router lifetime of 0 (the final ones).
pub fn advertisement(ra: &Ra, mac: [u8; 6], source: Ipv6Addr, stopping: bool) -> Vec<u8> {
    let lifetime = if stopping {
        0
    } else {
        u16::try_from(ra.router_lifetime).unwrap_or(u16::MAX)
    };
    let flags = if ra.managed { FLAG_MANAGED } else { 0 } | if ra.other { FLAG_OTHER } else { 0 };
    let mut icmp = vec![ROUTER_ADVERTISEMENT, 0, 0, 0, ra.hop_limit, flags];
    icmp.extend_from_slice(&lifetime.to_be_bytes());
    icmp.extend_from_slice(&ra.reachable_time.to_be_bytes());
    icmp.extend_from_slice(&ra.retrans_timer.to_be_bytes());
    icmp.extend_from_slice(&[OPTION_SOURCE_LINK_LAYER, 1]);
    icmp.extend_from_slice(&mac);
    if let Some(&mtu) = ra.mtu.first() {
        icmp.extend_from_slice(&[OPTION_MTU, 1, 0, 0]);
        icmp.extend_from_slice(&u32::from(mtu).to_be_bytes());
    }
    for prefix in &ra.prefix {
        // confd checked each prefix; one that does not read is left out.
        let Some((network, len)) = prefix
            .prefix
            .split_once('/')
            .and_then(|(a, l)| Some((a.parse::<Ipv6Addr>().ok()?, l.parse::<u8>().ok()?)))
        else {
            continue;
        };
        let flags = if prefix.on_link { FLAG_ON_LINK } else { 0 }
            | if prefix.autonomous {
                FLAG_AUTONOMOUS
            } else {
                0
            };
        icmp.extend_from_slice(&[OPTION_PREFIX, 4, len, flags]);
        icmp.extend_from_slice(&prefix.valid_lifetime.to_be_bytes());
        icmp.extend_from_slice(&prefix.preferred_lifetime.to_be_bytes());
        icmp.extend_from_slice(&[0; 4]);
        icmp.extend_from_slice(&network.octets());
    }
    let servers: Vec<Ipv6Addr> = ra.dns.iter().filter_map(|a| a.parse().ok()).collect();
    if !servers.is_empty() {
        let units = u8::try_from(1 + 2 * servers.len()).unwrap_or(u8::MAX);
        icmp.extend_from_slice(&[OPTION_RDNSS, units, 0, 0]);
        icmp.extend_from_slice(&ra.dns_lifetime.to_be_bytes());
        for server in servers {
            icmp.extend_from_slice(&server.octets());
        }
    }
    nd::frame(nd::multicast_mac(ALL_NODES), mac, source, ALL_NODES, icmp)
}

/// A small random number source (xorshift64*): the intervals need not be
/// unpredictable, only spread so routers on a link do not keep in step.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    /// Uniform in `low..=high` (near enough).
    pub fn between(&mut self, low: u64, high: u64) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        let value = self.0.wrapping_mul(0x2545_f491_4f6c_dd1d);
        low + value % (high.saturating_sub(low) + 1)
    }
}

/// When an advertising interface sends its next Router Advertisement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    /// The next unsolicited one.
    next_at: u64,
    /// An answer to a solicitation, when one is scheduled.
    answer_at: Option<u64>,
    last_sent: Option<u64>,
    /// Initial advertisements still to send.
    initial: u32,
}

impl Schedule {
    /// An interface that starts advertising: the first goes now.
    pub fn new(now_ms: u64) -> Self {
        Self {
            next_at: now_ms,
            answer_at: None,
            last_sent: None,
            initial: MAX_INITIAL_RTR_ADVERTISEMENTS,
        }
    }

    /// The settings changed: the initial advertisements again, the first as soon as
    /// MIN_DELAY_BETWEEN_RAS allows.
    pub fn restart(&mut self, now_ms: u64) {
        self.initial = MAX_INITIAL_RTR_ADVERTISEMENTS;
        self.next_at = self.earliest(now_ms);
        self.answer_at = None;
    }

    /// `at`, or MIN_DELAY_BETWEEN_RAS after the last one when that is later.
    pub fn earliest(&self, at: u64) -> u64 {
        self.last_sent
            .map_or(at, |last| at.max(last + MIN_DELAY_BETWEEN_RAS_MS))
    }

    /// A valid Router Solicitation came at `now_ms` (section 6.2.6).
    pub fn solicited(&mut self, now_ms: u64, rng: &mut Rng) {
        if self.answer_at.is_some() {
            return;
        }
        let delay = rng.between(0, MAX_RA_DELAY_TIME_MS);
        // Within MIN_DELAY_BETWEEN_RAS of the last one: that much after it, plus the
        // delay.
        let at = match self.last_sent {
            Some(last) if now_ms < last + MIN_DELAY_BETWEEN_RAS_MS => {
                last + MIN_DELAY_BETWEEN_RAS_MS + delay
            }
            _ => now_ms + delay,
        };
        if self.next_at > at {
            self.answer_at = Some(at);
        }
    }

    /// When the next one is due.
    pub fn due_at(&self) -> u64 {
        self.answer_at
            .map_or(self.next_at, |at| at.min(self.next_at))
    }

    /// One was sent at `now_ms`; the next unsolicited one is a random interval
    /// later.
    pub fn sent(&mut self, ra: &Ra, now_ms: u64, rng: &mut Rng) {
        self.last_sent = Some(now_ms);
        self.answer_at = None;
        let mut interval = rng.between(
            u64::from(ra.min_interval) * 1_000,
            u64::from(ra.max_interval) * 1_000,
        );
        if self.initial > 0 {
            self.initial -= 1;
            interval = interval.min(MAX_INITIAL_RTR_ADVERT_INTERVAL_MS);
        }
        self.next_at = now_ms + interval;
    }
}

/// The final advertisements of an interface that stopped advertising.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Final {
    /// The settings it last advertised.
    pub ra: Ra,
    pub left: u32,
    pub next_at: u64,
}

impl Final {
    pub fn new(ra: Ra, now_ms: u64) -> Self {
        Self {
            ra,
            left: MAX_FINAL_RTR_ADVERTISEMENTS,
            next_at: now_ms,
        }
    }

    /// One was sent at `now_ms`; false when it was the last.
    pub fn sent(&mut self, now_ms: u64) -> bool {
        self.left = self.left.saturating_sub(1);
        self.next_at = now_ms + MIN_DELAY_BETWEEN_RAS_MS;
        self.left > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruster_config::RaPrefix;

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

    fn ra() -> Ra {
        Ra {
            interface: "lan".into(),
            min_interval: 200,
            max_interval: 600,
            router_lifetime: 1_800,
            hop_limit: 64,
            managed: true,
            other: false,
            mtu: vec![1_480],
            reachable_time: 30_000,
            retrans_timer: 1_000,
            dns: vec!["2001:db8:1::1".into()],
            dns_lifetime: 1_800,
            prefix_from: Vec::new(),
            prefix: vec![RaPrefix {
                prefix: "2001:db8:1::/64".into(),
                on_link: true,
                autonomous: true,
                valid_lifetime: 2_592_000,
                preferred_lifetime: 604_800,
            }],
        }
    }

    #[test]
    fn the_advertisement_has_every_field_and_option() {
        let source: Ipv6Addr = "fe80::1".parse().unwrap();
        let frame = advertisement(&ra(), MAC, source, false);
        assert_eq!(&frame[0..6], &[0x33, 0x33, 0, 0, 0, 1]);
        assert_eq!(&frame[6..12], &MAC);
        assert_eq!(&frame[12..14], &[0x86, 0xdd]);
        let ip = &frame[14..54];
        assert_eq!(ip[6], 58);
        assert_eq!(ip[7], 255, "Hop Limit 255");
        assert_eq!(&ip[8..24], &source.octets());
        assert_eq!(&ip[24..40], &ALL_NODES.octets());
        let icmp = &frame[54..];
        assert_eq!(usize::from(u16::from_be_bytes([ip[4], ip[5]])), icmp.len());
        assert_eq!(
            nd::checksum(source, ALL_NODES, icmp),
            0,
            "the checksum adds up"
        );
        #[rustfmt::skip]
        let expected: Vec<u8> = [
            &[134, 0][..], &icmp[2..4], &[64, 0x80, 0x07, 0x08],
            &30_000_u32.to_be_bytes(), &1_000_u32.to_be_bytes(),
            &[1, 1, 2, 0, 0, 0, 0, 1],
            &[5, 1, 0, 0], &1_480_u32.to_be_bytes(),
            &[3, 4, 64, 0xc0], &2_592_000_u32.to_be_bytes(), &604_800_u32.to_be_bytes(), &[0; 4],
            &"2001:db8:1::".parse::<Ipv6Addr>().unwrap().octets(),
            &[25, 3, 0, 0], &1_800_u32.to_be_bytes(),
            &"2001:db8:1::1".parse::<Ipv6Addr>().unwrap().octets(),
        ]
        .concat();
        assert_eq!(icmp, &expected[..]);
        // The final one differs only in its router lifetime (and checksum).
        let last = advertisement(&ra(), MAC, source, true);
        assert_eq!(&last[54 + 6..54 + 8], &[0, 0]);
        assert_eq!(nd::checksum(source, ALL_NODES, &last[54..]), 0);
        assert_eq!(&last[54 + 8..], &frame[54 + 8..]);
    }

    #[test]
    fn options_left_unset_are_not_sent() {
        let mut bare = ra();
        bare.mtu.clear();
        bare.dns.clear();
        bare.prefix.clear();
        bare.managed = false;
        let frame = advertisement(&bare, MAC, "fe80::1".parse().unwrap(), false);
        assert_eq!(
            frame.len(),
            54 + 16 + 8,
            "the header and the link-layer address"
        );
        assert_eq!(frame[54 + 5], 0, "no flags");
    }

    #[test]
    fn unsolicited_ones_go_at_random_intervals_the_first_three_sooner() {
        let ra = ra();
        let mut rng = Rng::new(7);
        let mut schedule = Schedule::new(1_000);
        assert_eq!(schedule.due_at(), 1_000, "the first goes at once");
        let mut now = 1_000;
        let mut gaps = Vec::new();
        for _ in 0..20 {
            schedule.sent(&ra, now, &mut rng);
            gaps.push(schedule.due_at() - now);
            now = schedule.due_at();
        }
        for gap in &gaps[..3] {
            assert!(*gap <= MAX_INITIAL_RTR_ADVERT_INTERVAL_MS, "{gaps:?}");
        }
        for gap in &gaps[3..] {
            assert!((200_000..=600_000).contains(gap), "{gaps:?}");
        }
        assert!(
            gaps[3..].windows(2).any(|w| w[0] != w[1]),
            "random: {gaps:?}"
        );
    }

    #[test]
    fn solicitations_are_answered_soon_but_not_within_three_seconds() {
        let ra = ra();
        let mut rng = Rng::new(9);
        let mut schedule = Schedule::new(0);
        schedule.sent(&ra, 0, &mut rng);
        let unsolicited = schedule.due_at();
        // Within 3 s of the last one: 3 s after it, and the delay.
        schedule.solicited(1_000, &mut rng);
        let answer = schedule.due_at();
        assert!((3_000..=3_500).contains(&answer), "{answer}");
        // A second solicitation before then changes nothing.
        schedule.solicited(2_000, &mut rng);
        assert_eq!(schedule.due_at(), answer);
        schedule.sent(&ra, answer, &mut rng);
        assert_ne!(schedule.due_at(), unsolicited, "the interval starts again");
        // Long after: within 500 ms.
        let later = schedule.due_at() - 10_000;
        assert!(later > answer + MIN_DELAY_BETWEEN_RAS_MS);
        schedule.solicited(later, &mut rng);
        assert!((later..=later + MAX_RA_DELAY_TIME_MS).contains(&schedule.due_at()));
        // When the unsolicited one comes first anyway, no answer is scheduled.
        let mut soon = Schedule::new(0);
        soon.solicited(0, &mut rng);
        assert_eq!(soon.due_at(), 0);
        assert_eq!(soon.answer_at, None);
    }

    #[test]
    fn a_restart_sends_the_initial_ones_again() {
        let ra = ra();
        let mut rng = Rng::new(3);
        let mut schedule = Schedule::new(0);
        for at in [0, 16_000, 32_000, 48_000] {
            schedule.sent(&ra, at, &mut rng);
        }
        assert!(schedule.due_at() >= 48_000 + 200_000);
        schedule.restart(49_000);
        assert_eq!(schedule.due_at(), 51_000, "3 s after the last");
        schedule.sent(&ra, 51_000, &mut rng);
        assert!(schedule.due_at() <= 51_000 + MAX_INITIAL_RTR_ADVERT_INTERVAL_MS);
    }

    #[test]
    fn three_final_ones_go() {
        let mut last = Final::new(ra(), 5);
        assert_eq!(last.next_at, 5);
        assert!(last.sent(5));
        assert!(last.sent(last.next_at));
        assert!(!last.sent(last.next_at));
    }
}
