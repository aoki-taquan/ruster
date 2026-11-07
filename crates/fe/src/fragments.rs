//! IPv4 fragmentation (RFC 791 section 3.2) of datagrams longer than the egress MTU
//! that may be fragmented, and the association of fragments with their first
//! fragment so NAT and the firewall treat a fragmented datagram as one (core's
//! NAT-FRAG; RFC 4787 REQ-14 and RFC 5508 section 6 ask NAT to handle fragments).
//!
//! Both are core's; the FE only gives them storage, allocated once.
//!
//! # Standards
//!
//! - RFC 791 section 3.2 and RFC 1812 section 5.2.1: fragmentation at the egress
//!   MTU (up to 1500, the most the FE takes).
//! - RFC 4787 REQ-14: NAT handles fragmented UDP, in or out of order.
//!
//! Deviations: fragments leave only through ports, not VLAN sub-interfaces; a
//! datagram's fragments arriving within `TIMEOUT_MS` of its first one are
//! associated, later ones are dropped.

use ruster_core::{
    ipv4_fragment_slot_bytes, ipv4_fragment_tracking_buckets, ipv4_fragment_tracking_tombstones,
    DirectoryBucket, DirectoryNode, Ipv4FragmentEntrySlot, Ipv4FragmentHeldSlot,
    Ipv4FragmentHostSlot, Ipv4FragmentSlot, Ipv4FragmentTombstoneSlot, Ipv4FragmentTracker,
    Ipv4FragmentTrackingPolicy, Ipv4FragmentTrackingStorage, Ipv4FragmentationPolicy,
    Ipv4FragmentationRuntime, ResolutionHashKey,
};

/// Datagrams waiting to be cut in one batch.
const DATAGRAMS: usize = 64;
/// The largest egress MTU the FE has.
const MTU: u16 = 1_500;
/// Datagrams whose fragments are being associated, and fragments held before
/// their first fragment arrives.
const ENTRIES: usize = 1_024;
const HELD: usize = 64;
const TIMEOUT_MS: u32 = 5_000;
/// Per source host.
const ENTRIES_PER_HOST: u32 = 64;
const HELD_PER_HOST: u32 = 16;
/// Fragment frames sent per batch.
pub(crate) const FRAMES_PER_BATCH: usize = 256;

pub(crate) fn fragmentation() -> Ipv4FragmentationRuntime<'static> {
    Ipv4FragmentationRuntime::new(
        Ipv4FragmentationPolicy::default(),
        leak(DATAGRAMS, Ipv4FragmentSlot::EMPTY),
        leak(DATAGRAMS * ipv4_fragment_slot_bytes(MTU), 0_u8),
    )
    .expect("fragmentation storage")
}

pub(crate) fn tracker() -> Ipv4FragmentTracker<'static> {
    let buckets = ipv4_fragment_tracking_buckets(ENTRIES);
    let tombstones = ipv4_fragment_tracking_tombstones(ENTRIES);
    let key = loop {
        let (a, b) = crate::nat::words();
        if let Ok(key) = ResolutionHashKey::new(a, b) {
            break key;
        }
    };
    Ipv4FragmentTracker::new(
        Ipv4FragmentTrackingPolicy::new(TIMEOUT_MS, ENTRIES_PER_HOST, HELD_PER_HOST)
            .expect("fragment tracking policy"),
        Ipv4FragmentTrackingStorage {
            entries: leak(ENTRIES, Ipv4FragmentEntrySlot::EMPTY),
            entry_buckets: leak(buckets, DirectoryBucket::default()),
            entry_nodes: leak(ENTRIES, DirectoryNode::default()),
            hosts: leak(ENTRIES, Ipv4FragmentHostSlot::EMPTY),
            host_buckets: leak(buckets, DirectoryBucket::default()),
            host_nodes: leak(ENTRIES, DirectoryNode::default()),
            tombstones: leak(tombstones, Ipv4FragmentTombstoneSlot::EMPTY),
            tombstone_buckets: leak(
                ipv4_fragment_tracking_buckets(tombstones),
                DirectoryBucket::default(),
            ),
            tombstone_nodes: leak(tombstones, DirectoryNode::default()),
            held: leak(HELD, Ipv4FragmentHeldSlot::EMPTY),
            held_bytes: leak(HELD * ipv4_fragment_slot_bytes(MTU), 0_u8),
        },
        key,
    )
    .expect("fragment tracking storage")
}

fn leak<T: Clone>(count: usize, value: T) -> &'static mut [T] {
    Box::leak(vec![value; count].into_boxed_slice())
}
