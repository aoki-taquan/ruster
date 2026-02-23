//! ARP cache (neighbor table) for IPv4-to-MAC address resolution.
//!
//! The ARP cache maps IPv4 addresses to their resolved MAC addresses.
//! It supports learning, lookup, pending-state tracking, and time-based
//! aging of entries.
//!
//! RFC-REF: RFC 826
//! An Ethernet Address Resolution Protocol defines the basic ARP
//! mechanism. The cache holds dynamically learned address bindings.

use std::collections::HashMap;
use std::time::Instant;

/// State of an ARP cache entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpEntryState {
    /// The entry was confirmed by a recent ARP reply or request.
    Reachable,
    /// The entry has not been refreshed recently and may be outdated.
    Stale,
    /// An ARP request has been sent but no reply received yet.
    Pending,
}

/// A single ARP cache entry recording the MAC address for an IPv4 address.
#[derive(Debug, Clone)]
pub struct ArpEntry {
    /// The resolved MAC address (meaningless when state is `Pending`).
    pub mac: [u8; 6],
    /// The time at which this entry was learned or last refreshed.
    pub learned_at: Instant,
    /// Current state of this entry.
    pub state: ArpEntryState,
}

/// ARP cache: learns, looks up, and ages IPv4-to-MAC bindings.
///
/// The table has a configurable maximum size. When full, new insertion
/// attempts are silently ignored (existing entries are preserved), matching
/// the behavior of the FDB.
#[derive(Debug)]
pub struct ArpCache {
    /// IPv4 address (4 bytes) -> ARP entry.
    entries: HashMap<[u8; 4], ArpEntry>,
    /// Maximum number of entries the cache can hold.
    max_entries: usize,
}

impl ArpCache {
    /// Create a new ARP cache with the given maximum entry capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    /// Look up an IPv4 address in the ARP cache.
    ///
    /// Returns `Some(&ArpEntry)` if the address is known, or `None` otherwise.
    pub fn lookup(&self, ip: &[u8; 4]) -> Option<&ArpEntry> {
        self.entries.get(ip)
    }

    /// Insert or update an ARP entry as `Reachable`.
    ///
    /// If the IP is already present, the entry is updated with the new MAC
    /// and a refreshed timestamp. If the table is full and the IP is not
    /// already present, the insertion is silently ignored.
    ///
    /// RFC-REF: RFC 826
    /// "If the pair <protocol type, sender protocol address> is already in
    /// my translation table, update the sender hardware address field."
    pub fn insert(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        if self.entries.contains_key(&ip) {
            // Update existing entry.
            let entry = self.entries.get_mut(&ip).unwrap();
            entry.mac = mac;
            entry.learned_at = Instant::now();
            entry.state = ArpEntryState::Reachable;
        } else if self.entries.len() < self.max_entries {
            // Insert new entry only if there is room.
            self.entries.insert(
                ip,
                ArpEntry {
                    mac,
                    learned_at: Instant::now(),
                    state: ArpEntryState::Reachable,
                },
            );
        }
        // If table is full and IP is unknown, silently ignore.
    }

    /// Mark an IPv4 address as `Pending` (ARP request sent, awaiting reply).
    ///
    /// If the IP is already present, its state is changed to `Pending` and
    /// the timestamp is refreshed. If the table is full and the IP is not
    /// present, the operation is silently ignored.
    pub fn mark_pending(&mut self, ip: [u8; 4]) {
        if let Some(entry) = self.entries.get_mut(&ip) {
            entry.state = ArpEntryState::Pending;
            entry.learned_at = Instant::now();
        } else if self.entries.len() < self.max_entries {
            self.entries.insert(
                ip,
                ArpEntry {
                    mac: [0; 6],
                    learned_at: Instant::now(),
                    state: ArpEntryState::Pending,
                },
            );
        }
    }

    /// Remove entries older than `timeout_sec` seconds.
    ///
    /// Returns the number of entries that were removed.
    pub fn age(&mut self, timeout_sec: u64) -> usize {
        let now = Instant::now();
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| now.duration_since(entry.learned_at).as_secs() < timeout_sec);
        before - self.entries.len()
    }

    /// Return the current number of entries in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    const IP_A: [u8; 4] = [192, 168, 1, 1];
    const IP_B: [u8; 4] = [192, 168, 1, 2];
    const IP_C: [u8; 4] = [192, 168, 1, 3];

    const MAC_A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const MAC_B: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    #[test]
    fn cache_insert_and_lookup() {
        let mut cache = ArpCache::new(100);
        cache.insert(IP_A, MAC_A);

        let entry = cache.lookup(&IP_A).expect("IP_A should be in cache");
        assert_eq!(entry.mac, MAC_A);
        assert_eq!(entry.state, ArpEntryState::Reachable);
    }

    #[test]
    fn cache_lookup_miss() {
        let cache = ArpCache::new(100);
        assert!(cache.lookup(&IP_A).is_none());
    }

    #[test]
    fn cache_insert_updates_existing() {
        let mut cache = ArpCache::new(100);
        cache.insert(IP_A, MAC_A);

        // Update same IP with different MAC.
        cache.insert(IP_A, MAC_B);
        assert_eq!(cache.len(), 1);

        let entry = cache.lookup(&IP_A).unwrap();
        assert_eq!(entry.mac, MAC_B);
        assert_eq!(entry.state, ArpEntryState::Reachable);
    }

    #[test]
    fn cache_mark_pending_new_entry() {
        let mut cache = ArpCache::new(100);
        cache.mark_pending(IP_A);

        let entry = cache.lookup(&IP_A).expect("IP_A should be pending");
        assert_eq!(entry.state, ArpEntryState::Pending);
        assert_eq!(entry.mac, [0; 6]);
    }

    #[test]
    fn cache_mark_pending_existing_entry() {
        let mut cache = ArpCache::new(100);
        cache.insert(IP_A, MAC_A);
        assert_eq!(cache.lookup(&IP_A).unwrap().state, ArpEntryState::Reachable);

        cache.mark_pending(IP_A);
        let entry = cache.lookup(&IP_A).unwrap();
        assert_eq!(entry.state, ArpEntryState::Pending);
    }

    #[test]
    fn cache_pending_resolved_by_insert() {
        let mut cache = ArpCache::new(100);
        cache.mark_pending(IP_A);
        assert_eq!(cache.lookup(&IP_A).unwrap().state, ArpEntryState::Pending);

        // ARP reply arrives, resolving the pending entry.
        cache.insert(IP_A, MAC_A);
        let entry = cache.lookup(&IP_A).unwrap();
        assert_eq!(entry.state, ArpEntryState::Reachable);
        assert_eq!(entry.mac, MAC_A);
    }

    #[test]
    fn cache_age_removes_old() {
        let mut cache = ArpCache::new(100);
        cache.insert(IP_A, MAC_A);

        // Sleep briefly so the entry ages.
        thread::sleep(Duration::from_millis(50));

        // With timeout_sec=0, all entries are removed (no duration < 0).
        let removed = cache.age(0);
        assert_eq!(removed, 1);
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_age_keeps_recent() {
        let mut cache = ArpCache::new(100);
        cache.insert(IP_A, MAC_A);

        // With a large timeout, no entries should be removed.
        let removed = cache.age(3600);
        assert_eq!(removed, 0);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_max_entries() {
        let mut cache = ArpCache::new(2);
        cache.insert(IP_A, MAC_A);
        cache.insert(IP_B, MAC_B);
        assert_eq!(cache.len(), 2);

        // Table is full; new IP should be ignored.
        cache.insert(IP_C, MAC_A);
        assert_eq!(cache.len(), 2);
        assert!(cache.lookup(&IP_C).is_none());
    }

    #[test]
    fn cache_max_entries_pending() {
        let mut cache = ArpCache::new(1);
        cache.insert(IP_A, MAC_A);
        assert_eq!(cache.len(), 1);

        // Table is full; mark_pending for new IP should be ignored.
        cache.mark_pending(IP_B);
        assert_eq!(cache.len(), 1);
        assert!(cache.lookup(&IP_B).is_none());
    }

    #[test]
    fn cache_len_and_is_empty() {
        let mut cache = ArpCache::new(100);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        cache.insert(IP_A, MAC_A);
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
    }
}
