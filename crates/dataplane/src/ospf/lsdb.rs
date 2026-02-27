//! Link State Database (LSDB).
//!
//! The LSDB stores all LSAs received from neighbors and self-originated
//! LSAs.  It is the basis for SPF computation.
//!
//! RFC-REF: RFC 2328 Section 12
//! "The link state database consists of a collection of LSAs."

use super::packet::{Lsa, LsaBody, LsaHeader, LsaType};
use std::collections::HashMap;

/// Maximum age for an LSA in seconds.
///
/// RFC-REF: RFC 2328 Section 4.3
/// "MaxAge = 3600 (1 hour)"
pub const MAX_AGE: u16 = 3600;

/// LS Sequence Number initial value.
///
/// RFC-REF: RFC 2328 Appendix A.4.1
/// "InitialSequenceNumber = 0x80000001"
pub const INITIAL_SEQUENCE_NUMBER: u32 = 0x80000001;

/// Key for uniquely identifying an LSA in the LSDB.
///
/// RFC-REF: RFC 2328 Section 12.1.1
/// "An LSA is uniquely identified by its LS type, Link State ID,
/// and Advertising Router."
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LsaKey {
    pub ls_type: u8,
    pub link_state_id: [u8; 4],
    pub advertising_router: [u8; 4],
}

impl LsaKey {
    /// Create a key from an LSA header.
    pub fn from_header(header: &LsaHeader) -> Self {
        Self {
            ls_type: header.ls_type,
            link_state_id: header.link_state_id,
            advertising_router: header.advertising_router,
        }
    }
}

/// Entry in the LSDB storing an LSA and its metadata.
#[derive(Debug, Clone)]
pub struct LsdbEntry {
    /// The LSA itself.
    pub lsa: Lsa,
    /// Timestamp when the LSA was installed (epoch seconds).
    pub installed_at: u64,
}

/// The Link State Database.
///
/// RFC-REF: RFC 2328 Section 12
/// "The LSDB is the central data structure used by OSPF."
#[derive(Debug, Clone)]
pub struct Lsdb {
    /// LSAs indexed by their unique key.
    entries: HashMap<LsaKey, LsdbEntry>,
}

impl Lsdb {
    /// Create an empty LSDB.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Install or update an LSA in the LSDB.
    ///
    /// RFC-REF: RFC 2328 Section 13
    /// "When a new instance of an LSA is received, it must be
    /// installed in the LSDB."
    ///
    /// Returns `true` if the LSA was actually installed (new or newer
    /// than existing), `false` if it was rejected as older/duplicate.
    pub fn install(&mut self, lsa: Lsa, now_secs: u64) -> bool {
        let key = LsaKey::from_header(&lsa.header);

        if let Some(existing) = self.entries.get(&key) {
            // RFC-REF: RFC 2328 Section 13.1
            // "An LSA is more recent if it has a higher LS Sequence
            // Number, or if both have the same sequence number but the
            // received LSA has a smaller LS Checksum, or finally a
            // smaller LS Age."
            if !is_newer(&lsa.header, &existing.lsa.header) {
                return false;
            }
        }

        self.entries.insert(
            key,
            LsdbEntry {
                lsa,
                installed_at: now_secs,
            },
        );
        true
    }

    /// Remove an LSA by its key.
    pub fn remove(&mut self, key: &LsaKey) -> Option<LsdbEntry> {
        self.entries.remove(key)
    }

    /// Look up an LSA by its key.
    pub fn get(&self, key: &LsaKey) -> Option<&LsdbEntry> {
        self.entries.get(key)
    }

    /// Return all LSAs in the LSDB.
    pub fn all_lsas(&self) -> Vec<&Lsa> {
        self.entries.values().map(|e| &e.lsa).collect()
    }

    /// Return all Router-LSAs.
    pub fn router_lsas(&self) -> Vec<&Lsa> {
        self.entries
            .values()
            .filter(|e| e.lsa.header.ls_type == LsaType::Router as u8)
            .map(|e| &e.lsa)
            .collect()
    }

    /// Return all Network-LSAs.
    pub fn network_lsas(&self) -> Vec<&Lsa> {
        self.entries
            .values()
            .filter(|e| e.lsa.header.ls_type == LsaType::Network as u8)
            .map(|e| &e.lsa)
            .collect()
    }

    /// Return all LSA headers (for Database Description exchange).
    pub fn all_headers(&self) -> Vec<&LsaHeader> {
        self.entries.values().map(|e| &e.lsa.header).collect()
    }

    /// Age all LSAs and remove those that have reached MaxAge.
    ///
    /// RFC-REF: RFC 2328 Section 14
    /// "Every LSA has an LS Age field. While it is contained in the
    /// database, each LSA is aged by incrementing the LS Age field."
    ///
    /// Returns the keys of LSAs that were flushed.
    pub fn age_lsas(&mut self, now_secs: u64) -> Vec<LsaKey> {
        let mut flushed = Vec::new();

        self.entries.retain(|key, entry| {
            let elapsed = now_secs.saturating_sub(entry.installed_at);
            let current_age = if elapsed >= MAX_AGE as u64 {
                MAX_AGE
            } else {
                entry.lsa.header.ls_age.saturating_add(elapsed as u16)
            };

            if current_age >= MAX_AGE {
                flushed.push(key.clone());
                false
            } else {
                true
            }
        });

        flushed
    }

    /// Return the number of LSAs in the LSDB.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true if the LSDB is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for Lsdb {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if `new_header` is newer than `existing_header`.
///
/// RFC-REF: RFC 2328 Section 13.1
/// "An LSA is considered newer if:
///  1. It has a higher LS Sequence Number.
///  2. Only one has LS Age MaxAge (it is considered newer).
///  3. LS Checksum differs — higher checksum is considered newer.
///  4. LS Age differs by more than MaxAgeDiff (900s) — smaller age
///     is newer."
fn is_newer(new_header: &LsaHeader, existing_header: &LsaHeader) -> bool {
    // 1. Higher sequence number wins.
    if new_header.ls_sequence_number != existing_header.ls_sequence_number {
        // Sequence numbers are signed 32-bit integers with initial
        // value 0x80000001.  Higher unsigned value means newer.
        return (new_header.ls_sequence_number as i32)
            > (existing_header.ls_sequence_number as i32);
    }

    // 2. If only one has MaxAge, that one is newer (for flushing).
    if new_header.ls_age == MAX_AGE && existing_header.ls_age != MAX_AGE {
        return true;
    }
    if existing_header.ls_age == MAX_AGE && new_header.ls_age != MAX_AGE {
        return false;
    }

    // 3. Different checksums: higher wins.
    if new_header.ls_checksum != existing_header.ls_checksum {
        return new_header.ls_checksum > existing_header.ls_checksum;
    }

    // 4. Age difference > 900s: smaller age wins.
    const MAX_AGE_DIFF: u16 = 900;
    let age_diff = (new_header.ls_age as i32 - existing_header.ls_age as i32).unsigned_abs() as u16;
    if age_diff > MAX_AGE_DIFF {
        return new_header.ls_age < existing_header.ls_age;
    }

    // Otherwise, they are considered the same instance.
    false
}

/// Create a self-originated Router-LSA.
pub fn originate_router_lsa(
    router_id: [u8; 4],
    _area_id: [u8; 4],
    links: Vec<super::packet::RouterLink>,
    seq: u32,
) -> Lsa {
    let body = LsaBody::Router(super::packet::RouterLsa { flags: 0, links });

    // Calculate length: header(20) + flags/reserved/num_links(4) + links(12 each).
    let num_links = match &body {
        LsaBody::Router(r) => r.links.len(),
        _ => 0,
    };
    let length = 20 + 4 + (num_links * 12);

    Lsa {
        header: LsaHeader {
            ls_age: 0,
            options: 0x02, // E-bit (external routing)
            ls_type: LsaType::Router as u8,
            link_state_id: router_id,
            advertising_router: router_id,
            ls_sequence_number: seq,
            ls_checksum: 0, // Simplified: checksum not computed.
            length: length as u16,
        },
        body,
    }
    // Note: area_id is used for scoping but is not part of the LSA
    // header itself.  The caller tracks which area an LSA belongs to.
    // We use the parameter to prevent an unused warning.
    // In a complete implementation, the LSDB is per-area.
}

// Suppress unused parameter warning for area_id in originate_router_lsa.
// The function signature includes it for future multi-area support.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ospf::packet::{LsaBody, LsaType, RouterLink, RouterLsa, LINK_TYPE_STUB};

    fn make_router_lsa(router_id: [u8; 4], seq: u32, age: u16, links: Vec<RouterLink>) -> Lsa {
        let num_links = links.len();
        Lsa {
            header: LsaHeader {
                ls_age: age,
                options: 0x02,
                ls_type: LsaType::Router as u8,
                link_state_id: router_id,
                advertising_router: router_id,
                ls_sequence_number: seq,
                ls_checksum: 0,
                length: (20 + 4 + num_links * 12) as u16,
            },
            body: LsaBody::Router(RouterLsa { flags: 0, links }),
        }
    }

    fn make_stub_link(prefix: [u8; 4], mask: [u8; 4], metric: u16) -> RouterLink {
        RouterLink {
            link_id: prefix,
            link_data: mask,
            link_type: LINK_TYPE_STUB,
            num_tos: 0,
            metric,
        }
    }

    // ── Install / lookup tests ──────────────────────────────────────

    #[test]
    fn install_and_get() {
        let mut lsdb = Lsdb::new();
        assert!(lsdb.is_empty());

        let lsa = make_router_lsa([1, 1, 1, 1], INITIAL_SEQUENCE_NUMBER, 0, vec![]);
        assert!(lsdb.install(lsa.clone(), 100));

        assert_eq!(lsdb.len(), 1);

        let key = LsaKey {
            ls_type: LsaType::Router as u8,
            link_state_id: [1, 1, 1, 1],
            advertising_router: [1, 1, 1, 1],
        };
        assert!(lsdb.get(&key).is_some());
    }

    #[test]
    fn install_newer_replaces() {
        let mut lsdb = Lsdb::new();

        let lsa1 = make_router_lsa([1, 1, 1, 1], INITIAL_SEQUENCE_NUMBER, 0, vec![]);
        lsdb.install(lsa1, 100);

        // Newer (higher seq).
        let lsa2 = make_router_lsa(
            [1, 1, 1, 1],
            INITIAL_SEQUENCE_NUMBER + 1,
            0,
            vec![make_stub_link([10, 0, 0, 0], [255, 0, 0, 0], 10)],
        );
        assert!(lsdb.install(lsa2, 101));
        assert_eq!(lsdb.len(), 1);

        let key = LsaKey {
            ls_type: LsaType::Router as u8,
            link_state_id: [1, 1, 1, 1],
            advertising_router: [1, 1, 1, 1],
        };
        let entry = lsdb.get(&key).unwrap();
        assert_eq!(
            entry.lsa.header.ls_sequence_number,
            INITIAL_SEQUENCE_NUMBER + 1
        );
    }

    #[test]
    fn install_older_rejected() {
        let mut lsdb = Lsdb::new();

        let lsa1 = make_router_lsa([1, 1, 1, 1], INITIAL_SEQUENCE_NUMBER + 1, 0, vec![]);
        lsdb.install(lsa1, 100);

        // Older (lower seq).
        let lsa2 = make_router_lsa([1, 1, 1, 1], INITIAL_SEQUENCE_NUMBER, 0, vec![]);
        assert!(!lsdb.install(lsa2, 101));
        assert_eq!(lsdb.len(), 1);
    }

    #[test]
    fn install_same_seq_rejected_as_duplicate() {
        let mut lsdb = Lsdb::new();

        let lsa1 = make_router_lsa([1, 1, 1, 1], INITIAL_SEQUENCE_NUMBER, 0, vec![]);
        lsdb.install(lsa1, 100);

        // Same seq, same checksum, similar age -> duplicate.
        let lsa2 = make_router_lsa([1, 1, 1, 1], INITIAL_SEQUENCE_NUMBER, 10, vec![]);
        assert!(!lsdb.install(lsa2, 101));
    }

    // ── Remove test ─────────────────────────────────────────────────

    #[test]
    fn remove_lsa() {
        let mut lsdb = Lsdb::new();
        let lsa = make_router_lsa([1, 1, 1, 1], INITIAL_SEQUENCE_NUMBER, 0, vec![]);
        lsdb.install(lsa, 100);

        let key = LsaKey {
            ls_type: LsaType::Router as u8,
            link_state_id: [1, 1, 1, 1],
            advertising_router: [1, 1, 1, 1],
        };
        assert!(lsdb.remove(&key).is_some());
        assert!(lsdb.is_empty());
    }

    // ── Aging test ──────────────────────────────────────────────────

    #[test]
    fn age_lsas_flushes_old() {
        let mut lsdb = Lsdb::new();

        let lsa = make_router_lsa([1, 1, 1, 1], INITIAL_SEQUENCE_NUMBER, 0, vec![]);
        lsdb.install(lsa, 100);

        // Not yet at MaxAge.
        let flushed = lsdb.age_lsas(3000);
        assert!(flushed.is_empty());
        assert_eq!(lsdb.len(), 1);

        // At MaxAge (3600 seconds elapsed).
        let flushed = lsdb.age_lsas(3700);
        assert_eq!(flushed.len(), 1);
        assert!(lsdb.is_empty());
    }

    #[test]
    fn age_lsas_partial_flush() {
        let mut lsdb = Lsdb::new();

        let lsa1 = make_router_lsa([1, 1, 1, 1], INITIAL_SEQUENCE_NUMBER, 0, vec![]);
        lsdb.install(lsa1, 100);

        let lsa2 = make_router_lsa([2, 2, 2, 2], INITIAL_SEQUENCE_NUMBER, 0, vec![]);
        lsdb.install(lsa2, 3000); // installed much later

        // At time 3700: lsa1 is old (3600s), lsa2 is young (700s).
        let flushed = lsdb.age_lsas(3700);
        assert_eq!(flushed.len(), 1);
        assert_eq!(lsdb.len(), 1);
    }

    // ── Query tests ─────────────────────────────────────────────────

    #[test]
    fn router_lsas_filter() {
        let mut lsdb = Lsdb::new();

        let router_lsa = make_router_lsa([1, 1, 1, 1], INITIAL_SEQUENCE_NUMBER, 0, vec![]);
        lsdb.install(router_lsa, 100);

        let network_lsa = Lsa {
            header: LsaHeader {
                ls_age: 0,
                options: 0x02,
                ls_type: LsaType::Network as u8,
                link_state_id: [10, 0, 0, 1],
                advertising_router: [1, 1, 1, 1],
                ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
                ls_checksum: 0,
                length: 28, // header(20) + mask(4) + one router(4)
            },
            body: LsaBody::Network(super::super::packet::NetworkLsa {
                network_mask: [255, 255, 255, 0],
                attached_routers: vec![[1, 1, 1, 1]],
            }),
        };
        lsdb.install(network_lsa, 100);

        assert_eq!(lsdb.router_lsas().len(), 1);
        assert_eq!(lsdb.network_lsas().len(), 1);
        assert_eq!(lsdb.all_lsas().len(), 2);
    }

    // ── is_newer tests ──────────────────────────────────────────────

    #[test]
    fn is_newer_higher_seq() {
        let new_header = LsaHeader {
            ls_age: 0,
            options: 0,
            ls_type: 1,
            link_state_id: [1, 1, 1, 1],
            advertising_router: [1, 1, 1, 1],
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER + 1,
            ls_checksum: 0,
            length: 20,
        };
        let old_header = LsaHeader {
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ..new_header.clone()
        };
        assert!(is_newer(&new_header, &old_header));
        assert!(!is_newer(&old_header, &new_header));
    }

    #[test]
    fn is_newer_maxage_wins() {
        let maxage_header = LsaHeader {
            ls_age: MAX_AGE,
            options: 0,
            ls_type: 1,
            link_state_id: [1, 1, 1, 1],
            advertising_router: [1, 1, 1, 1],
            ls_sequence_number: INITIAL_SEQUENCE_NUMBER,
            ls_checksum: 0,
            length: 20,
        };
        let young_header = LsaHeader {
            ls_age: 100,
            ..maxage_header.clone()
        };
        assert!(is_newer(&maxage_header, &young_header));
        assert!(!is_newer(&young_header, &maxage_header));
    }

    // ── originate_router_lsa test ───────────────────────────────────

    #[test]
    fn originate_router_lsa_basic() {
        let links = vec![make_stub_link([192, 168, 1, 0], [255, 255, 255, 0], 10)];
        let lsa = originate_router_lsa([1, 1, 1, 1], [0, 0, 0, 0], links, INITIAL_SEQUENCE_NUMBER);
        assert_eq!(lsa.header.ls_type, LsaType::Router as u8);
        assert_eq!(lsa.header.link_state_id, [1, 1, 1, 1]);
        assert_eq!(lsa.header.advertising_router, [1, 1, 1, 1]);
        match &lsa.body {
            LsaBody::Router(r) => assert_eq!(r.links.len(), 1),
            _ => panic!("expected Router-LSA"),
        }
    }
}
