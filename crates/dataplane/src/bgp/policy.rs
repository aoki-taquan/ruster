//! Minimal BGP import/export policy (prefix-list filter).
//!
//! Provides basic prefix-list filtering for import and export policies.
//! Routes matching a deny entry are filtered out; routes matching a
//! permit entry (or with no matching entry) are allowed.
//!
//! RFC-DEVIATION:
//! reason: minimal policy engine — only prefix-list filtering supported
//! impact: cannot implement route-maps, community-based policy, etc.
//! issue: #158
//! plan: add route-map support in v0.3

use super::rib_in::AdjRibInEntry;

/// Action for a prefix-list entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Allow the route.
    Permit,
    /// Deny (filter out) the route.
    Deny,
}

/// A single prefix-list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixListEntry {
    /// Prefix to match.
    pub prefix: [u8; 4],
    /// Prefix length to match.
    pub prefix_len: u8,
    /// Whether to match only this exact prefix length (`true`) or
    /// also longer prefixes (`false` = "le 32").
    pub exact: bool,
    /// Action if matched.
    pub action: PolicyAction,
}

/// A prefix-list policy.
///
/// Entries are evaluated in order. The first matching entry determines
/// the action. If no entry matches, the default action applies.
#[derive(Debug, Clone)]
pub struct PrefixList {
    /// Policy entries evaluated in order.
    pub entries: Vec<PrefixListEntry>,
    /// Default action when no entry matches.
    pub default_action: PolicyAction,
}

impl PrefixList {
    /// Create a new prefix-list with the given default action.
    pub fn new(default_action: PolicyAction) -> Self {
        Self {
            entries: Vec::new(),
            default_action,
        }
    }

    /// Create a permit-all policy (no filtering).
    pub fn permit_all() -> Self {
        Self {
            entries: Vec::new(),
            default_action: PolicyAction::Permit,
        }
    }

    /// Create a deny-all policy.
    pub fn deny_all() -> Self {
        Self {
            entries: Vec::new(),
            default_action: PolicyAction::Deny,
        }
    }

    /// Evaluate a route against this prefix-list.
    ///
    /// Returns the action (Permit or Deny) for the given prefix.
    pub fn evaluate(&self, prefix: &[u8; 4], prefix_len: u8) -> PolicyAction {
        for entry in &self.entries {
            if self.matches_entry(entry, prefix, prefix_len) {
                return entry.action;
            }
        }
        self.default_action
    }

    /// Check if a prefix matches a prefix-list entry.
    fn matches_entry(
        &self,
        entry: &PrefixListEntry,
        prefix: &[u8; 4],
        prefix_len: u8,
    ) -> bool {
        if entry.exact {
            // Exact match: both prefix and prefix_len must match.
            prefix_len == entry.prefix_len && prefix_matches(prefix, &entry.prefix, entry.prefix_len)
        } else {
            // The route prefix must be at least as specific as the entry
            // and must match the entry's prefix bits.
            prefix_len >= entry.prefix_len
                && prefix_matches(prefix, &entry.prefix, entry.prefix_len)
        }
    }
}

/// Check if the first `bits` of two IPv4 addresses match.
fn prefix_matches(a: &[u8; 4], b: &[u8; 4], bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    let full_bytes = (bits / 8) as usize;
    let remaining_bits = bits % 8;

    if a[..full_bytes] != b[..full_bytes] {
        return false;
    }

    if remaining_bits > 0 {
        let mask = 0xFF << (8 - remaining_bits);
        (a[full_bytes] & mask) == (b[full_bytes] & mask)
    } else {
        true
    }
}

/// Minimal import policy: filters Adj-RIB-In entries through a prefix-list.
#[derive(Debug, Clone)]
pub struct ImportPolicy {
    pub prefix_list: PrefixList,
}

impl ImportPolicy {
    /// Create a new import policy with the given prefix-list.
    pub fn new(prefix_list: PrefixList) -> Self {
        Self { prefix_list }
    }

    /// Create a permit-all import policy (no filtering).
    pub fn permit_all() -> Self {
        Self {
            prefix_list: PrefixList::permit_all(),
        }
    }

    /// Apply the import policy to a set of Adj-RIB-In entries.
    ///
    /// Returns only the entries that pass the prefix-list filter.
    pub fn apply<'a>(&self, entries: &'a [AdjRibInEntry]) -> Vec<&'a AdjRibInEntry> {
        entries
            .iter()
            .filter(|e| {
                self.prefix_list.evaluate(&e.prefix, e.prefix_len) == PolicyAction::Permit
            })
            .collect()
    }
}

/// Minimal export policy: filters routes before advertisement.
#[derive(Debug, Clone)]
pub struct ExportPolicy {
    pub prefix_list: PrefixList,
}

impl ExportPolicy {
    /// Create a new export policy with the given prefix-list.
    pub fn new(prefix_list: PrefixList) -> Self {
        Self { prefix_list }
    }

    /// Create a permit-all export policy.
    pub fn permit_all() -> Self {
        Self {
            prefix_list: PrefixList::permit_all(),
        }
    }

    /// Check if a prefix should be advertised.
    pub fn should_advertise(&self, prefix: &[u8; 4], prefix_len: u8) -> bool {
        self.prefix_list.evaluate(prefix, prefix_len) == PolicyAction::Permit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::path::{AsPath, AsPathSegment, Origin, PathAttributes};
    use crate::bgp::rib_in::AdjRibInEntry;

    fn make_entry(prefix: [u8; 4], prefix_len: u8) -> AdjRibInEntry {
        AdjRibInEntry {
            prefix,
            prefix_len,
            attributes: PathAttributes {
                origin: Origin::Igp,
                as_path: AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                },
                next_hop: [10, 0, 0, 2],
                med: None,
                local_pref: Some(100),
            },
            peer_router_id: [10, 0, 0, 2],
        }
    }

    // ── PrefixList tests ─────────────────────────────────────────────

    #[test]
    fn permit_all_allows_everything() {
        let pl = PrefixList::permit_all();
        assert_eq!(
            pl.evaluate(&[192, 168, 1, 0], 24),
            PolicyAction::Permit
        );
        assert_eq!(pl.evaluate(&[0, 0, 0, 0], 0), PolicyAction::Permit);
    }

    #[test]
    fn deny_all_blocks_everything() {
        let pl = PrefixList::deny_all();
        assert_eq!(
            pl.evaluate(&[192, 168, 1, 0], 24),
            PolicyAction::Deny
        );
    }

    #[test]
    fn exact_match_prefix_list() {
        let mut pl = PrefixList::new(PolicyAction::Permit);
        pl.entries.push(PrefixListEntry {
            prefix: [10, 0, 0, 0],
            prefix_len: 8,
            exact: true,
            action: PolicyAction::Deny,
        });

        // Exact match: denied.
        assert_eq!(pl.evaluate(&[10, 0, 0, 0], 8), PolicyAction::Deny);
        // More specific: not matched (exact=true), default permit.
        assert_eq!(pl.evaluate(&[10, 0, 0, 0], 16), PolicyAction::Permit);
        // Different prefix: not matched, default permit.
        assert_eq!(
            pl.evaluate(&[192, 168, 1, 0], 24),
            PolicyAction::Permit
        );
    }

    #[test]
    fn non_exact_match_prefix_list() {
        let mut pl = PrefixList::new(PolicyAction::Deny);
        pl.entries.push(PrefixListEntry {
            prefix: [192, 168, 0, 0],
            prefix_len: 16,
            exact: false,
            action: PolicyAction::Permit,
        });

        // Matches: 192.168.1.0/24 is within 192.168.0.0/16.
        assert_eq!(
            pl.evaluate(&[192, 168, 1, 0], 24),
            PolicyAction::Permit
        );
        // Matches: exact match also works.
        assert_eq!(
            pl.evaluate(&[192, 168, 0, 0], 16),
            PolicyAction::Permit
        );
        // Does not match: different prefix.
        assert_eq!(pl.evaluate(&[10, 0, 0, 0], 8), PolicyAction::Deny);
        // Less specific: /8 is not within /16.
        assert_eq!(pl.evaluate(&[192, 0, 0, 0], 8), PolicyAction::Deny);
    }

    #[test]
    fn first_matching_entry_wins() {
        let mut pl = PrefixList::new(PolicyAction::Permit);
        pl.entries.push(PrefixListEntry {
            prefix: [10, 0, 0, 0],
            prefix_len: 8,
            exact: false,
            action: PolicyAction::Deny,
        });
        pl.entries.push(PrefixListEntry {
            prefix: [10, 1, 0, 0],
            prefix_len: 16,
            exact: true,
            action: PolicyAction::Permit,
        });

        // 10.1.0.0/16 matches the first entry (deny) before the second.
        assert_eq!(pl.evaluate(&[10, 1, 0, 0], 16), PolicyAction::Deny);
    }

    // ── prefix_matches tests ─────────────────────────────────────────

    #[test]
    fn prefix_matches_zero_bits() {
        assert!(prefix_matches(&[1, 2, 3, 4], &[5, 6, 7, 8], 0));
    }

    #[test]
    fn prefix_matches_full_byte_boundary() {
        assert!(prefix_matches(&[10, 0, 0, 1], &[10, 0, 0, 2], 24));
        assert!(!prefix_matches(&[10, 0, 1, 0], &[10, 0, 0, 0], 24));
    }

    #[test]
    fn prefix_matches_partial_byte() {
        // 192.168.0.0/12: first 12 bits = 192.160.0.0 mask
        assert!(prefix_matches(&[192, 168, 1, 0], &[192, 160, 0, 0], 12));
        assert!(!prefix_matches(&[192, 128, 1, 0], &[192, 160, 0, 0], 12));
    }

    // ── ImportPolicy tests ───────────────────────────────────────────

    #[test]
    fn import_permit_all() {
        let policy = ImportPolicy::permit_all();
        let entries = vec![
            make_entry([192, 168, 1, 0], 24),
            make_entry([10, 0, 0, 0], 8),
        ];
        let accepted = policy.apply(&entries);
        assert_eq!(accepted.len(), 2);
    }

    #[test]
    fn import_filters_denied_prefixes() {
        let mut pl = PrefixList::new(PolicyAction::Permit);
        pl.entries.push(PrefixListEntry {
            prefix: [10, 0, 0, 0],
            prefix_len: 8,
            exact: false,
            action: PolicyAction::Deny,
        });
        let policy = ImportPolicy::new(pl);

        let entries = vec![
            make_entry([192, 168, 1, 0], 24),
            make_entry([10, 0, 0, 0], 8),
            make_entry([10, 1, 0, 0], 16),
        ];
        let accepted = policy.apply(&entries);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].prefix, [192, 168, 1, 0]);
    }

    // ── ExportPolicy tests ───────────────────────────────────────────

    #[test]
    fn export_permit_all() {
        let policy = ExportPolicy::permit_all();
        assert!(policy.should_advertise(&[10, 0, 0, 0], 8));
    }

    #[test]
    fn export_denies_filtered_prefix() {
        let mut pl = PrefixList::new(PolicyAction::Permit);
        pl.entries.push(PrefixListEntry {
            prefix: [172, 16, 0, 0],
            prefix_len: 12,
            exact: false,
            action: PolicyAction::Deny,
        });
        let policy = ExportPolicy::new(pl);

        assert!(!policy.should_advertise(&[172, 16, 0, 0], 12));
        assert!(!policy.should_advertise(&[172, 16, 1, 0], 24));
        assert!(policy.should_advertise(&[10, 0, 0, 0], 8));
    }
}
