//! Forwarding Database (FDB) / MAC address table.
//!
//! The FDB maps MAC addresses to the interface on which they were last seen.
//! It supports learning, lookup, and time-based aging of entries.

use std::collections::HashMap;
use std::time::Instant;

use crate::pipeline::IfIndex;

/// A single FDB entry recording which interface a MAC address was learned on.
#[derive(Debug, Clone)]
pub struct FdbEntry {
    /// The interface index where this MAC address was last observed.
    pub out_ifindex: IfIndex,
    /// The time at which this entry was learned (or last refreshed).
    pub learned_at: Instant,
}

/// Forwarding Database: learns, looks up, and ages MAC address entries.
///
/// The table has a configurable maximum size. When full, new learning
/// attempts are silently ignored (the existing entries are preserved).
#[derive(Debug)]
pub struct Fdb {
    /// MAC -> (output interface, learned timestamp).
    entries: HashMap<[u8; 6], FdbEntry>,
    /// Maximum number of entries the table can hold.
    max_entries: usize,
}

impl Fdb {
    /// Create a new FDB with the given maximum entry capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    /// Learn a MAC address: record that `mac` was seen on `in_ifindex`.
    ///
    /// If the MAC is already present, the entry is updated with the new
    /// interface and a refreshed timestamp. If the table is full and the
    /// MAC is not already present, the learning is silently ignored.
    pub fn learn(&mut self, mac: [u8; 6], in_ifindex: IfIndex) {
        if self.entries.contains_key(&mac) {
            // Update existing entry (port migration or timestamp refresh).
            let entry = self.entries.get_mut(&mac).unwrap();
            entry.out_ifindex = in_ifindex;
            entry.learned_at = Instant::now();
        } else if self.entries.len() < self.max_entries {
            // Insert new entry only if there is room.
            self.entries.insert(
                mac,
                FdbEntry {
                    out_ifindex: in_ifindex,
                    learned_at: Instant::now(),
                },
            );
        }
        // If table is full and MAC is unknown, silently ignore.
    }

    /// Look up a MAC address in the FDB.
    ///
    /// Returns `Some(&FdbEntry)` if the MAC is known, or `None` otherwise.
    pub fn lookup(&self, mac: &[u8; 6]) -> Option<&FdbEntry> {
        self.entries.get(mac)
    }

    /// Remove entries older than `aging_sec` seconds.
    ///
    /// Returns the number of entries that were removed.
    pub fn age(&mut self, aging_sec: u64) -> usize {
        let now = Instant::now();
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| now.duration_since(entry.learned_at).as_secs() < aging_sec);
        before - self.entries.len()
    }

    /// Return the current number of entries in the FDB.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the FDB contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    const MAC_A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const MAC_B: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    const MAC_C: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    #[test]
    fn fdb_learn_and_lookup() {
        let mut fdb = Fdb::new(100);
        fdb.learn(MAC_A, 0);

        let entry = fdb.lookup(&MAC_A).expect("MAC_A should be in FDB");
        assert_eq!(entry.out_ifindex, 0);
    }

    #[test]
    fn fdb_lookup_miss() {
        let fdb = Fdb::new(100);
        assert!(fdb.lookup(&MAC_A).is_none());
    }

    #[test]
    fn fdb_age_removes_old() {
        let mut fdb = Fdb::new(100);
        fdb.learn(MAC_A, 0);

        // Sleep briefly so the entry ages past 0 seconds.
        thread::sleep(Duration::from_millis(50));

        // Age with a very short threshold: entries older than 0s should be removed.
        // We use aging_sec = 0 which means "remove anything that is >= 0 seconds old".
        // But since duration_since >= 0 is always true for any non-zero time,
        // we need the entry to be at least 1 second old. Instead, let's use
        // a custom approach: age everything older than 0 seconds.
        // Actually, the condition is `duration < aging_sec`. With aging_sec=0,
        // no duration is < 0, so everything is removed.
        let removed = fdb.age(0);
        assert_eq!(removed, 1);
        assert!(fdb.is_empty());
    }

    #[test]
    fn fdb_max_entries() {
        let mut fdb = Fdb::new(2);
        fdb.learn(MAC_A, 0);
        fdb.learn(MAC_B, 1);
        assert_eq!(fdb.len(), 2);

        // Table is full; new MAC should be ignored.
        fdb.learn(MAC_C, 2);
        assert_eq!(fdb.len(), 2);
        assert!(fdb.lookup(&MAC_C).is_none());
    }

    #[test]
    fn fdb_learn_updates_existing() {
        let mut fdb = Fdb::new(100);
        fdb.learn(MAC_A, 0);

        // Same MAC learned on a different interface (port migration).
        fdb.learn(MAC_A, 1);
        assert_eq!(fdb.len(), 1);

        let entry = fdb.lookup(&MAC_A).unwrap();
        assert_eq!(entry.out_ifindex, 1);
    }
}
