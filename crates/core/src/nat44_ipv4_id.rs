//! IPv4 Identification of translated non-atomic datagrams (MTU2,
//! NAT44-126).
//!
//! RFC 6864 §5.3.1: an address-sharing device MUST make the ID of the
//! datagrams it translates obey the rules of a source, and generate the ID
//! rather than copy it when it rewrites the source address, destination
//! address, or protocol. A NAPT collapses many inside sources onto one public
//! address, so two inside hosts can send the same ID toward one destination;
//! if those non-atomic datagrams are fragmented downstream the destination
//! can merge their fragments (RFC 6864 §5.3.1, RFC 4963 §2).
//!
//! The NAT therefore gives every translated non-atomic datagram (DF clear;
//! the NAT only translates whole datagrams, so MF=0 and offset 0) a new ID
//! from a fixed array of [`IPV4_ID_BUCKETS`] counters. The bucket and a per
//! tuple offset come from one keyed hash of the translated (source,
//! destination, protocol) tuple (RFC 6864 §4.3: uniqueness is per tuple), so
//! consecutive datagrams of one tuple get consecutive IDs and no ID of a
//! tuple repeats before 65536 datagrams hash into its bucket. The key is
//! secret, so the IDs are not predictable from outside (RFC 7739 §5, applied
//! to IPv4), and one tuple observes only the datagrams that share its bucket.
//! Atomic datagrams (DF set) keep their ID: RFC 6864 §4.1 lets a source use
//! any value and every device MUST ignore it.
//!
//! The array is inline (no allocation), owned by one worker's runtime (no
//! lock), and never reset by reconcile or flush, so a configuration apply
//! does not restart the sequence of a tuple.

use crate::fixed_directory::{DirectoryHashDomain, DirectoryHashKey};

/// Counters of one generator. A power of two, so the bucket is the low bits
/// of the hash.
pub(crate) const IPV4_ID_BUCKETS: usize = 1024;

/// Per-worker generator of the IDs of translated non-atomic datagrams.
pub(crate) struct Ipv4IdGenerator {
    key: DirectoryHashKey,
    counters: [u16; IPV4_ID_BUCKETS],
}

impl Ipv4IdGenerator {
    pub(crate) const fn new(key: DirectoryHashKey) -> Self {
        Self {
            key,
            counters: [0; IPV4_ID_BUCKETS],
        }
    }

    /// The ID of the next non-atomic datagram of the translated tuple.
    pub(crate) fn next(&mut self, source: [u8; 4], destination: [u8; 4], protocol: u8) -> u16 {
        let addresses = (u64::from(u32::from_be_bytes(source)) << 32)
            | u64::from(u32::from_be_bytes(destination));
        let hash = self.key.hash_words(
            DirectoryHashDomain::Ipv4Identification,
            &[addresses, u64::from(protocol)],
        );
        let bucket = (hash as usize) & (IPV4_ID_BUCKETS - 1);
        let counter = self.counters[bucket];
        self.counters[bucket] = counter.wrapping_add(1);
        counter.wrapping_add((hash >> 48) as u16)
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
        let first = ids.next(P, D, 17);
        seen[usize::from(first)] = true;
        for step in 1..65_536_u32 {
            let id = ids.next(P, D, 17);
            assert_eq!(id, first.wrapping_add(step as u16), "consecutive per tuple");
            assert!(!seen[usize::from(id)], "repeated at {step}");
            seen[usize::from(id)] = true;
        }
        // The 65537th wraps to the first ID (RFC 6864 §5.2 rate residual).
        assert_eq!(ids.next(P, D, 17), first);
    }

    #[test]
    fn tuples_are_independent_and_keyed() {
        let mut ids = generator(7);
        let udp = ids.next(P, D, 17);
        // Other tuples (protocol, destination, source) do not consume the
        // UDP tuple's sequence unless they share its bucket.
        let tcp = ids.next(P, D, 6);
        let other_destination = ids.next(P, [198, 51, 100, 8], 17);
        let other_source = ids.next([203, 0, 113, 2], D, 17);
        assert_ne!(udp, tcp);
        assert_ne!(udp, other_destination);
        assert_ne!(udp, other_source);
        assert_eq!(ids.next(P, D, 17), udp.wrapping_add(1));
        // A different key gives a different (unpredictable) start.
        let mut other_key = generator(8);
        assert_ne!(other_key.next(P, D, 17), udp);
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
        assert_eq!(ids.next(P, D, 17), (hash >> 48) as u16);
        let bucket = (hash as usize) & (IPV4_ID_BUCKETS - 1);
        assert_eq!(ids.counters[bucket], 1);
        assert_eq!(ids.counters.iter().map(|&c| u32::from(c)).sum::<u32>(), 1);
    }
}
