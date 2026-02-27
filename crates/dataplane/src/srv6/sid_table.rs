//! Local SID table: maps SIDs to endpoint actions.
//!
//! RFC-REF: RFC 8986 Section 4
//! "A node maintains a 'My Local SID Table'. This table contains all
//! the local SRv6 SIDs explicitly instantiated at the node."
//!
//! The table supports:
//! - Exact-match SID lookup (for full 128-bit SIDs)
//! - Longest-prefix-match SID lookup (for uSID block matching)

use super::actions::Srv6Action;
use super::config::LocalSidConfig;
use crate::nd::parse_ipv6_addr;
use crate::routing::ipv6_table::matches_ipv6_prefix;

/// A single entry in the Local SID table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidEntry {
    /// The SID (128-bit IPv6 address).
    pub sid: [u8; 16],
    /// Prefix length for matching (128 = exact match).
    pub prefix_len: u8,
    /// The action to perform when this SID is matched.
    pub action: Srv6Action,
}

/// Local SID table.
///
/// RFC-REF: RFC 8986 Section 4
/// Entries are sorted by prefix length descending for longest-prefix-match.
#[derive(Debug, Clone)]
pub struct SidTable {
    entries: Vec<SidEntry>,
}

impl SidTable {
    /// Create a new empty SID table.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Build a SID table from configuration.
    pub fn from_config(local_sids: &[LocalSidConfig]) -> Result<Self, SidTableError> {
        let mut entries = Vec::with_capacity(local_sids.len());
        let mut errors: Vec<String> = Vec::new();

        for (i, cfg) in local_sids.iter().enumerate() {
            let (sid, prefix_len) = match parse_sid_with_prefix(&cfg.sid) {
                Some(v) => v,
                None => {
                    errors.push(format!("local_sids[{}]: invalid SID \"{}\"", i, cfg.sid));
                    continue;
                }
            };

            let action = Srv6Action::from_config(cfg);
            entries.push(SidEntry {
                sid,
                prefix_len,
                action,
            });
        }

        if !errors.is_empty() {
            return Err(SidTableError { messages: errors });
        }

        // Sort by prefix_len descending for LPM.
        entries.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));

        Ok(Self { entries })
    }

    /// Insert a SID entry into the table, maintaining LPM sort order.
    pub fn insert(&mut self, entry: SidEntry) {
        self.entries.push(entry);
        self.entries.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
    }

    /// Look up a SID in the table using longest-prefix-match.
    ///
    /// RFC-REF: RFC 8986 Section 4.1
    /// "When a node receives a packet with DA matching a local SID,
    /// it applies the associated function."
    pub fn lookup(&self, sid: &[u8; 16]) -> Option<&SidEntry> {
        self.entries
            .iter()
            .find(|entry| matches_ipv6_prefix(sid, &entry.sid, entry.prefix_len))
    }

    /// Returns the number of entries in the table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for SidTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Error when building a SID table from configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidTableError {
    pub messages: Vec<String>,
}

impl std::fmt::Display for SidTableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SID table errors: {}", self.messages.join("; "))
    }
}

impl std::error::Error for SidTableError {}

/// Parse a SID string, optionally with a prefix length.
///
/// Accepts "fd00:1::/64" or "fd00:1::" (defaults to /128).
fn parse_sid_with_prefix(sid_str: &str) -> Option<([u8; 16], u8)> {
    if let Some((ip_str, len_str)) = sid_str.split_once('/') {
        let ip = parse_ipv6_addr(ip_str)?;
        let prefix_len: u8 = len_str.parse().ok()?;
        if prefix_len > 128 {
            return None;
        }
        Some((ip, prefix_len))
    } else {
        let ip = parse_ipv6_addr(sid_str)?;
        Some((ip, 128))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sid_exact_match() {
        let (sid, prefix_len) = parse_sid_with_prefix("fd00::1").unwrap();
        assert_eq!(prefix_len, 128);
        assert_eq!(sid[0], 0xfd);
        assert_eq!(sid[15], 0x01);
    }

    #[test]
    fn parse_sid_with_prefix_len() {
        let (sid, prefix_len) = parse_sid_with_prefix("fd00::/32").unwrap();
        assert_eq!(prefix_len, 32);
        assert_eq!(sid[0], 0xfd);
        assert_eq!(sid[1], 0x00);
    }

    #[test]
    fn parse_sid_invalid() {
        assert!(parse_sid_with_prefix("not-an-ip").is_none());
        assert!(parse_sid_with_prefix("fd00::/129").is_none());
    }

    #[test]
    fn sid_table_exact_match_lookup() {
        let mut table = SidTable::new();
        let sid = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        table.insert(SidEntry {
            sid,
            prefix_len: 128,
            action: Srv6Action::End,
        });

        // Exact match should succeed.
        assert!(table.lookup(&sid).is_some());
        assert_eq!(table.lookup(&sid).unwrap().action, Srv6Action::End);

        // Different SID should not match.
        let other = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        assert!(table.lookup(&other).is_none());
    }

    #[test]
    fn sid_table_prefix_match_lookup() {
        let mut table = SidTable::new();
        // Block prefix: fd00::/32 -> End (uSID block match)
        let block = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        table.insert(SidEntry {
            sid: block,
            prefix_len: 32,
            action: Srv6Action::UN,
        });

        // Any SID starting with fd00:: should match.
        let sid1 = [0xfd, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(table.lookup(&sid1).is_some());
        assert_eq!(table.lookup(&sid1).unwrap().action, Srv6Action::UN);

        // SID with different block should not match.
        let sid2 = [0xfe, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(table.lookup(&sid2).is_none());
    }

    #[test]
    fn sid_table_longest_prefix_match() {
        let mut table = SidTable::new();

        // Insert a broad match (/32) and a specific match (/128).
        let block = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        table.insert(SidEntry {
            sid: block,
            prefix_len: 32,
            action: Srv6Action::UN,
        });

        let specific = [0xfd, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        table.insert(SidEntry {
            sid: specific,
            prefix_len: 128,
            action: Srv6Action::End,
        });

        // The specific entry should win for an exact match.
        assert_eq!(table.lookup(&specific).unwrap().action, Srv6Action::End);

        // A different SID in the same block should match the /32 entry.
        let other = [0xfd, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(table.lookup(&other).unwrap().action, Srv6Action::UN);
    }

    #[test]
    fn sid_table_empty() {
        let table = SidTable::new();
        let sid = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(table.lookup(&sid).is_none());
        assert!(table.is_empty());
    }

    #[test]
    fn sid_table_from_config() {
        let configs = vec![
            LocalSidConfig {
                sid: "fd00::1".to_string(),
                action: "end".to_string(),
                table: None,
            },
            LocalSidConfig {
                sid: "fd00::2".to_string(),
                action: "end_dt4".to_string(),
                table: Some("default".to_string()),
            },
        ];

        let table = SidTable::from_config(&configs).unwrap();
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn sid_table_from_config_invalid_sid() {
        let configs = vec![LocalSidConfig {
            sid: "not-valid".to_string(),
            action: "end".to_string(),
            table: None,
        }];

        assert!(SidTable::from_config(&configs).is_err());
    }
}
