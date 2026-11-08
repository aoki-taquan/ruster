//! IPv4 Identification of translated non-atomic datagrams (MTU2,
//! NAT44-126).
//!
//! A NAPT collapses many inside sources onto one public address, so two
//! inside hosts can send the same ID toward one destination; if those
//! non-atomic datagrams are fragmented downstream the destination can merge
//! their fragments.
//!
//! The NAT therefore gives every translated non-atomic datagram (DF clear,
//! whole or the first fragment; the fragment association table gives later
//! fragments the same ID) a new ID from a fixed array of [`IPV4_ID_BUCKETS`]
//! counters per direction. The bucket and a per tuple offset come from one
//! keyed hash of the translated (source, destination, protocol) tuple, so
//! consecutive datagrams of one tuple get consecutive IDs and no ID of a
//! tuple repeats before 65536 datagrams hash into its bucket. The key is
//! secret, so the IDs are not predictable from outside, and one tuple
//! observes only the datagrams that share its bucket. Atomic datagrams (DF
//! set, MF clear, offset 0) keep their ID.
//!
//! Outbound and inbound translations count in separate arrays (MTU2 review
//! M1/L1). A tuple whose source is the public address (outbound: the source
//! was rewritten to the public address; hairpin, whose source is rewritten
//! to the public address too) counts in the outbound array; every other
//! tuple (inbound: an outside source, the destination rewritten to an inside
//! host) counts in the inbound array. With one array an outside host could
//! advance, by sending DF-clear datagrams inward, the counter behind an
//! outbound tuple it shares a bucket with: push that tuple toward wrap
//! within the MDL, and measure exact deltas of other traffic. Hairpin goes
//! with outbound: its source is the public address, its traffic is driven
//! only by inside hosts (like outbound), and its tuples (public address,
//! inside host) never equal an outbound tuple (public address, outside
//! host), so it neither collides with outbound sequences nor lets the
//! outside reach them. Inside hosts still share the outbound array.
//!
//! **Rate limit.** Each counter's 65536 values are in four quarters, and the
//! time each quarter was last used is kept. A counter enters a quarter only
//! when that quarter was last used at least the maximum datagram lifetime
//! (MDL, 120 s) ago; otherwise the datagram is dropped
//! (`NAT44_IPV4_ID_RATE_EXCEEDED`). So no ID of a tuple repeats within the
//! MDL, and a bucket carries at most 65536 non-atomic datagrams per MDL
//! (about 550 per second on average, more in bursts). The tuples sharing a
//! bucket share its rate: one inside host sending DF-clear datagrams to one
//! destination that fast holds back the others in that bucket.
//!
//! The split stops outside traffic from advancing an outbound sequence
//! *directly*. It can still do so indirectly: an outside host that elicits
//! DF-clear replies from inside hosts or routers (UDP answers, Echo
//! Replies) has those replies counted in the outbound bucket of
//! (public, attacker, protocol), a bucket it cannot choose (the key is
//! secret). An observer holding N tuples covers about 1 - (1 - 1/B)^N of
//! the B buckets: with B = 1024, 1024 addresses cover about 63%; with the
//! B = 4096 used since MTU2 part B, about 22% (4096 addresses about 63%).
//!
//! The inbound array is shared by every outside sender, so outside volume
//! can wrap another remote's inbound sequence (X, H, protocol): one bucket
//! needs on average 65536 x B datagrams (about 2.7e8 at B = 4096, 6.7e7 at
//! 1024) to wrap. Since MTU2 part B the router fragments inbound DF-clear
//! datagrams toward a smaller LAN MTU with the generated ID (one ID for every
//! fragment), so a wrap within the inside host's reassembly time (Linux:
//! 30 s, so about 9 Mpps) could make it misassemble. That rate is far beyond
//! one worker and transport checksums catch most misassembly; it is a
//! documented residual (NAT44-126 (7)), not special-cased: copying the
//! received ID or refusing to fragment would each break a standard (see
//! # Standards).
//!
//! The counters advance by exactly 1. A random per-bucket increment (Linux
//! `ip_idents`) is not used: it shortens the wrap period of every tuple
//! (uniqueness is what the standard requires), and with the direction split an
//! outside observer no longer sees inbound volume; what remains observable
//! is outbound volume of tuples in the observer's own outbound bucket.
//!
//! The arrays are inline (no allocation; with the times of the quarters,
//! about 72 KiB per direction), owned by one worker's runtime (no
//! lock), and never reset by reconcile or flush, so a configuration apply
//! does not restart the sequence of a tuple. The key is the NAT runtime's
//! construction key and is fixed for the runtime's lifetime (not rotated on
//! reconcile, deliberately, so that sequences are not reset).
//!
//! Multi-worker: the generator is per worker. Two workers translating the
//! same (source, destination, protocol) tuple with the same key would
//! repeat each other's IDs. A multi-worker design needs a per-worker
//! derived key and disjoint ID ranges, or (source, destination,
//! protocol)-affine sharding so that one tuple is always translated by one
//! worker. Today the router has one worker.
//!
//! # Standards
//!
//! - RFC 6864 section 5.3.1: an address-sharing device makes the ID of the
//!   datagrams it translates follow the rules for a source, and generates it
//!   rather than copying it.
//! - RFC 6864 section 4.3: the ID of a non-atomic datagram does not repeat
//!   within the MDL for one (source, destination, protocol) tuple. Section 5.2:
//!   the rate of non-atomic datagrams is limited so that it holds (the rate
//!   limit above). Section 4.1: an atomic datagram's ID may be any value, so
//!   it is kept.
//! - RFC 791: every fragment of a datagram has the same ID; RFC 1812 section
//!   4.2.2.7: a DF-clear datagram larger than the egress MTU is fragmented.
//! - RFC 7739 section 5 (written for IPv6, applied here): the IDs cannot be
//!   predicted without the key.
//! - RFC 4963 section 2 describes the misassembly the IDs avoid.
//!
//! Deviations: the limit is per bucket, not per tuple, so tuples that share a
//! bucket share the rate. The time is kept in whole seconds, and with more
//! than one worker the generators would need disjoint ranges (above).

use crate::fixed_directory::{DirectoryHashDomain, DirectoryHashKey};

/// Counters of one direction. A power of two, so the bucket is the low bits
/// of the hash. 4096 since MTU2 part B (1024 before): an 8 KiB inline array
/// per direction, a quarter of the bucket coverage per observed tuple, and
/// four times the volume needed to wrap a bucket, for one indexed u16 per
/// DF-clear datagram as before.
pub(crate) const IPV4_ID_BUCKETS: usize = 4096;

/// The maximum datagram lifetime the IDs stay unique within, in seconds.
pub(crate) const IPV4_ID_MDL_S: u64 = 120;

/// Each bucket's 65536 IDs in this many parts; the time each part was last
/// used is kept.
const QUARTERS: usize = 4;

/// One direction's counters, and when each quarter of each counter was last
/// used (seconds + 1; 0 for never).
struct Counters {
    next: [u16; IPV4_ID_BUCKETS],
    used_at: [[u32; QUARTERS]; IPV4_ID_BUCKETS],
}

impl Counters {
    const fn new() -> Self {
        Self {
            next: [0; IPV4_ID_BUCKETS],
            used_at: [[0; QUARTERS]; IPV4_ID_BUCKETS],
        }
    }

    /// The bucket's next counter value, or `None` when it would enter a
    /// quarter used less than the MDL ago (the rate limit).
    fn take(&mut self, bucket: usize, now_ms: u64) -> Option<u16> {
        let counter = self.next[bucket];
        let quarter = usize::from(counter >> 14);
        let now = u32::try_from(now_ms / 1_000).unwrap_or(u32::MAX - 1) + 1;
        let used_at = self.used_at[bucket][quarter];
        if counter & 0x3fff == 0
            && used_at != 0
            && u64::from(now.saturating_sub(used_at)) < IPV4_ID_MDL_S
        {
            return None;
        }
        self.used_at[bucket][quarter] = now;
        self.next[bucket] = counter.wrapping_add(1);
        Some(counter)
    }
}

/// Per-worker generator of the IDs of translated non-atomic datagrams.
pub(crate) struct Ipv4IdGenerator {
    key: DirectoryHashKey,
    /// Tuples whose source is the public address (outbound, hairpin).
    outbound: Counters,
    /// Every other tuple (inbound: destination rewritten to an inside host).
    inbound: Counters,
}

impl Ipv4IdGenerator {
    pub(crate) const fn new(key: DirectoryHashKey) -> Self {
        Self {
            key,
            outbound: Counters::new(),
            inbound: Counters::new(),
        }
    }

    /// The ID of the next non-atomic datagram of the translated tuple;
    /// `public` is the NAT's public address, which selects the direction.
    pub(crate) fn next(
        &mut self,
        source: [u8; 4],
        destination: [u8; 4],
        protocol: u8,
        public: [u8; 4],
        now_ms: u64,
    ) -> Option<u16> {
        let addresses = (u64::from(u32::from_be_bytes(source)) << 32)
            | u64::from(u32::from_be_bytes(destination));
        let hash = self.key.hash_words(
            DirectoryHashDomain::Ipv4Identification,
            &[addresses, u64::from(protocol)],
        );
        let counters = if source == public {
            &mut self.outbound
        } else {
            &mut self.inbound
        };
        let bucket = (hash as usize) & (IPV4_ID_BUCKETS - 1);
        let counter = counters.take(bucket, now_ms)?;
        Some(counter.wrapping_add((hash >> 48) as u16))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generator(first: u64) -> Ipv4IdGenerator {
        Ipv4IdGenerator::new(DirectoryHashKey::new(first, 0x0123_4567_89ab_cdef).unwrap())
    }

    const P: [u8; 4] = [203, 0, 113, 1];
    const D: [u8; 4] = [198, 51, 100, 7];

    #[test]
    fn one_tuple_never_repeats_an_id_within_65536_datagrams() {
        let mut ids = generator(7);
        let mut seen = vec![false; 65_536];
        let first = ids.next(P, D, 17, P, 0).unwrap();
        seen[usize::from(first)] = true;
        for step in 1..65_536_u32 {
            let id = ids.next(P, D, 17, P, 0).unwrap();
            assert_eq!(id, first.wrapping_add(step as u16), "consecutive per tuple");
            assert!(!seen[usize::from(id)], "repeated at {step}");
            seen[usize::from(id)] = true;
        }
        // The 65537th waits for the MDL (the rate limit), then wraps to the first ID.
        assert_eq!(ids.next(P, D, 17, P, 0), None);
        assert_eq!(ids.next(P, D, 17, P, IPV4_ID_MDL_S * 1_000).unwrap(), first);
    }

    /// The rate limit: a quarter of a bucket's IDs is used again only once
    /// the MDL has passed since its last use, so no ID repeats within it.
    #[test]
    fn a_quarter_is_used_again_only_after_the_mdl() {
        let mut ids = generator(7);
        let mdl = IPV4_ID_MDL_S * 1_000;
        // Three quarters at t = 0, the last at t = 10 s.
        for _ in 0..3 * 16_384 {
            ids.next(P, D, 17, P, 0).unwrap();
        }
        for _ in 0..16_384 {
            ids.next(P, D, 17, P, 10_000).unwrap();
        }
        // The first quarter was last used at 0: refused until the MDL.
        assert_eq!(ids.next(P, D, 17, P, mdl - 1_000), None);
        assert!(ids.next(P, D, 17, P, mdl).is_some());
        for _ in 1..3 * 16_384 {
            ids.next(P, D, 17, P, mdl).unwrap();
        }
        // The fourth quarter was last used at 10 s.
        assert_eq!(ids.next(P, D, 17, P, mdl + 9_000), None);
        assert!(ids.next(P, D, 17, P, mdl + 10_000).is_some());
    }

    #[test]
    fn tuples_are_independent_and_keyed() {
        let mut ids = generator(7);
        let udp = ids.next(P, D, 17, P, 0).unwrap();
        // Other tuples (protocol, destination, source) do not consume the
        // UDP tuple's sequence unless they share its bucket.
        let tcp = ids.next(P, D, 6, P, 0).unwrap();
        let other_destination = ids.next(P, [198, 51, 100, 8], 17, P, 0).unwrap();
        let other_source = ids.next([203, 0, 113, 2], D, 17, P, 0).unwrap();
        assert_ne!(udp, tcp);
        assert_ne!(udp, other_destination);
        assert_ne!(udp, other_source);
        assert_eq!(ids.next(P, D, 17, P, 0).unwrap(), udp.wrapping_add(1));
        // A different key gives a different (unpredictable) start.
        let mut other_key = generator(8);
        assert_ne!(other_key.next(P, D, 17, P, 0).unwrap(), udp);
    }

    #[test]
    fn the_bucket_and_offset_come_from_the_documented_hash() {
        let key = DirectoryHashKey::new(7, 0x0123_4567_89ab_cdef).unwrap();
        let hash = key.hash_words(
            DirectoryHashDomain::Ipv4Identification,
            &[
                (u64::from(u32::from_be_bytes(P)) << 32) | u64::from(u32::from_be_bytes(D)),
                17,
            ],
        );
        let mut ids = Ipv4IdGenerator::new(key);
        assert_eq!(ids.next(P, D, 17, P, 0).unwrap(), (hash >> 48) as u16);
        let bucket = (hash as usize) & (IPV4_ID_BUCKETS - 1);
        assert_eq!(ids.outbound.next[bucket], 1);
        assert_eq!(
            ids.outbound.next.iter().map(|&c| u32::from(c)).sum::<u32>(),
            1
        );
        assert!(ids.inbound.next.iter().all(|&c| c == 0));
    }

    /// Review M1/L1: inbound translations (source not the public address)
    /// count in their own array, so outside traffic cannot advance an
    /// outbound tuple's sequence even in the same bucket.
    #[test]
    fn inbound_volume_never_advances_an_outbound_sequence() {
        let mut ids = generator(7);
        let first = ids.next(P, D, 17, P, 0).unwrap();
        let key = DirectoryHashKey::new(7, 0x0123_4567_89ab_cdef).unwrap();
        let bucket = |source: [u8; 4], destination: [u8; 4]| {
            let hash = key.hash_words(
                DirectoryHashDomain::Ipv4Identification,
                &[
                    (u64::from(u32::from_be_bytes(source)) << 32)
                        | u64::from(u32::from_be_bytes(destination)),
                    17,
                ],
            );
            (hash as usize) & (IPV4_ID_BUCKETS - 1)
        };
        let target = bucket(P, D);
        // An inbound tuple whose hash lands in the outbound tuple's bucket:
        // with one array it would share the outbound counter.
        let colliding = (0..=u8::MAX)
            .flat_map(|a| (0..=u8::MAX).map(move |b| [198, 51, a, b]))
            .find(|&source| bucket(source, [10, 0, 0, 10]) == target)
            .expect("some outside source shares the bucket");
        // Spread over time, so that the rate limit lets the counter wrap.
        for i in 0..70_000_u64 {
            ids.next(colliding, [10, 0, 0, 10], 17, P, i * 10).unwrap();
        }
        assert_eq!(ids.inbound.next[target], (70_000_u32 % 65_536) as u16);
        assert_eq!(ids.outbound.next[target], 1);
        assert_eq!(ids.next(P, D, 17, P, 0).unwrap(), first.wrapping_add(1));
        // Hairpin (source the public address, destination inside) counts
        // with outbound.
        ids.next(P, [10, 0, 0, 11], 17, P, 0).unwrap();
        assert_eq!(
            ids.outbound.next.iter().map(|&c| u32::from(c)).sum::<u32>(),
            3
        );
    }
}
