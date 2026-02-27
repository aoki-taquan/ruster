//! SRv6 Policy / Binding SID (BSID) support (minimal).
//!
//! RFC-REF: RFC 8986 Section 5
//! A Binding SID (BSID) is bound to an SR Policy. When a packet
//! matches a BSID, the associated SRH segment list is applied.
//!
//! This is a minimal implementation providing the data structures
//! and a simple BSID → segment list mapping.

/// An SRv6 policy entry.
///
/// RFC-REF: RFC 8986 Section 5
/// Associates a Binding SID with a segment list to be imposed on
/// matching packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv6Policy {
    /// Policy name for identification.
    pub name: String,
    /// Binding SID (BSID): packets matching this SID trigger the policy.
    pub bsid: [u8; 16],
    /// Segment list to impose on matching packets.
    pub segment_list: Vec<[u8; 16]>,
}

/// SRv6 policy table.
///
/// Maps Binding SIDs to their associated policies.
#[derive(Debug, Clone, Default)]
pub struct PolicyTable {
    policies: Vec<Srv6Policy>,
}

impl PolicyTable {
    /// Create a new empty policy table.
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Insert a policy into the table.
    pub fn insert(&mut self, policy: Srv6Policy) {
        self.policies.push(policy);
    }

    /// Look up a policy by Binding SID.
    pub fn lookup(&self, bsid: &[u8; 16]) -> Option<&Srv6Policy> {
        self.policies.iter().find(|p| &p.bsid == bsid)
    }

    /// Returns the number of policies in the table.
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bsid() -> [u8; 16] {
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0x01]
    }

    fn make_policy() -> Srv6Policy {
        let sid1 = [0xfd, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let sid2 = [0xfd, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        Srv6Policy {
            name: "test-policy".to_string(),
            bsid: make_bsid(),
            segment_list: vec![sid1, sid2],
        }
    }

    #[test]
    fn policy_table_insert_and_lookup() {
        let mut table = PolicyTable::new();
        let policy = make_policy();
        table.insert(policy.clone());

        let found = table.lookup(&make_bsid()).unwrap();
        assert_eq!(found.name, "test-policy");
        assert_eq!(found.segment_list.len(), 2);
    }

    #[test]
    fn policy_table_not_found() {
        let table = PolicyTable::new();
        let bsid = make_bsid();
        assert!(table.lookup(&bsid).is_none());
    }

    #[test]
    fn policy_table_empty() {
        let table = PolicyTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }
}
