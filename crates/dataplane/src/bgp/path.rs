//! BGP path attributes and best-path selection.
//!
//! Defines the path attributes carried in BGP UPDATE messages and the
//! best-path selection algorithm used to choose the preferred route
//! among multiple paths to the same prefix.
//!
//! RFC-REF: RFC 4271 Section 5
//! "A variable-length sequence of path attributes is present in every
//! UPDATE message, except for an UPDATE message that carries only the
//! withdrawn routes field."
//!
//! RFC-REF: RFC 4271 Section 9.1.2
//! "The Decision Process selects routes for subsequent advertisement
//! by applying the policies in the local Policy Information Base (PIB)
//! to the routes stored in its Adj-RIBs-In."

use std::fmt;

/// ORIGIN attribute values.
///
/// RFC-REF: RFC 4271 Section 5.1.1
/// "ORIGIN is a well-known mandatory attribute."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// Network Layer Reachability Information is interior to the AS.
    Igp,
    /// NLRI was learned via EGP.
    Egp,
    /// NLRI was learned by some other means.
    Incomplete,
}

impl Default for Origin {
    fn default() -> Self {
        Self::Igp
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Igp => write!(f, "IGP"),
            Self::Egp => write!(f, "EGP"),
            Self::Incomplete => write!(f, "?"),
        }
    }
}

/// An AS_PATH segment.
///
/// RFC-REF: RFC 4271 Section 5.1.2
/// "AS_PATH is a well-known mandatory attribute [...] composed of a
/// sequence of AS path segments."
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsPathSegment {
    /// AS_SET: unordered set of ASNs.
    AsSet(Vec<u32>),
    /// AS_SEQUENCE: ordered sequence of ASNs (most common).
    AsSequence(Vec<u32>),
}

/// The full AS_PATH attribute.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsPath {
    pub segments: Vec<AsPathSegment>,
}

impl AsPath {
    /// Return the total AS path length for best-path comparison.
    ///
    /// RFC-REF: RFC 4271 Section 9.1.2.2 (step a)
    /// "Prefer the route with the shortest AS_PATH.  An AS_SET counts
    /// as 1 regardless of the number of ASNs in the set."
    pub fn length(&self) -> usize {
        self.segments
            .iter()
            .map(|seg| match seg {
                AsPathSegment::AsSequence(asns) => asns.len(),
                AsPathSegment::AsSet(_) => 1, // AS_SET counts as 1
            })
            .sum()
    }

    /// Check if the AS_PATH contains a specific ASN (loop detection).
    ///
    /// RFC-REF: RFC 4271 Section 9
    /// "If the local AS number is found in the AS path of the route,
    /// that route MUST NOT be accepted."
    pub fn contains_asn(&self, asn: u32) -> bool {
        self.segments.iter().any(|seg| match seg {
            AsPathSegment::AsSequence(asns) | AsPathSegment::AsSet(asns) => asns.contains(&asn),
        })
    }

    /// Prepend our local ASN to the AS_PATH (for eBGP advertisement).
    ///
    /// RFC-REF: RFC 4271 Section 5.1.2
    /// "When a BGP speaker propagates a route [...] it modifies its
    /// AS_PATH attribute based on the location of the BGP speaker
    /// within the AS."
    pub fn prepend(&self, local_as: u32) -> AsPath {
        let mut new_segments = Vec::with_capacity(self.segments.len() + 1);

        // If the first segment is an AS_SEQUENCE, prepend to it.
        // Otherwise, create a new AS_SEQUENCE.
        let mut prepended = false;
        for (i, seg) in self.segments.iter().enumerate() {
            if i == 0 {
                if let AsPathSegment::AsSequence(asns) = seg {
                    let mut new_asns = Vec::with_capacity(asns.len() + 1);
                    new_asns.push(local_as);
                    new_asns.extend(asns);
                    new_segments.push(AsPathSegment::AsSequence(new_asns));
                    prepended = true;
                    continue;
                }
            }
            new_segments.push(seg.clone());
        }

        if !prepended {
            new_segments.insert(0, AsPathSegment::AsSequence(vec![local_as]));
        }

        AsPath {
            segments: new_segments,
        }
    }
}

impl fmt::Display for AsPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for seg in &self.segments {
            match seg {
                AsPathSegment::AsSequence(asns) => {
                    for asn in asns {
                        if !first {
                            write!(f, " ")?;
                        }
                        write!(f, "{asn}")?;
                        first = false;
                    }
                }
                AsPathSegment::AsSet(asns) => {
                    if !first {
                        write!(f, " ")?;
                    }
                    write!(f, "{{")?;
                    for (i, asn) in asns.iter().enumerate() {
                        if i > 0 {
                            write!(f, ",")?;
                        }
                        write!(f, "{asn}")?;
                    }
                    write!(f, "}}")?;
                    first = false;
                }
            }
        }
        Ok(())
    }
}

/// Collected path attributes for a BGP route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathAttributes {
    /// ORIGIN attribute (well-known mandatory).
    pub origin: Origin,
    /// AS_PATH attribute (well-known mandatory).
    pub as_path: AsPath,
    /// NEXT_HOP attribute (well-known mandatory for IPv4 unicast).
    pub next_hop: [u8; 4],
    /// MULTI_EXIT_DISC (MED) attribute (optional non-transitive).
    pub med: Option<u32>,
    /// LOCAL_PREF attribute (well-known for iBGP, used locally for eBGP).
    pub local_pref: Option<u32>,
}

impl Default for PathAttributes {
    fn default() -> Self {
        Self {
            origin: Origin::Igp,
            as_path: AsPath::default(),
            next_hop: [0; 4],
            med: None,
            local_pref: None,
        }
    }
}

/// Compare two path attribute sets for best-path selection.
///
/// Returns `std::cmp::Ordering::Less` if `a` is preferred over `b`.
///
/// RFC-REF: RFC 4271 Section 9.1.2.2
/// "The following procedure describes the Decision Process used when
/// selecting routes from the Adj-RIBs-In."
///
/// Selection steps (eBGP only, simplified):
/// 1. Highest LOCAL_PREF wins.
/// 2. Shortest AS_PATH wins.
/// 3. Prefer IGP > EGP > Incomplete origin.
/// 4. Lowest MED wins (only compared between routes from the same
///    neighbor AS).
/// 5. Lowest router-id (tie-breaker).
pub fn compare_paths(
    a: &PathAttributes,
    a_router_id: [u8; 4],
    b: &PathAttributes,
    b_router_id: [u8; 4],
) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    // Step 1: Highest LOCAL_PREF (higher = better, so reverse comparison).
    let a_lp = a.local_pref.unwrap_or(100);
    let b_lp = b.local_pref.unwrap_or(100);
    match b_lp.cmp(&a_lp) {
        Ordering::Equal => {}
        other => return other,
    }

    // Step 2: Shortest AS_PATH.
    match a.as_path.length().cmp(&b.as_path.length()) {
        Ordering::Equal => {}
        other => return other,
    }

    // Step 3: Origin preference: IGP < EGP < Incomplete.
    let origin_rank = |o: Origin| -> u8 {
        match o {
            Origin::Igp => 0,
            Origin::Egp => 1,
            Origin::Incomplete => 2,
        }
    };
    match origin_rank(a.origin).cmp(&origin_rank(b.origin)) {
        std::cmp::Ordering::Equal => {}
        other => return other,
    }

    // Step 4: Lowest MED (only within same neighbor AS — simplified:
    // always compare MED in this minimal implementation).
    // RFC-DEVIATION:
    // reason: comparing MED across different neighbor ASNs for simplicity
    // impact: may prefer suboptimal routes in multi-AS topologies
    // issue: #158
    // plan: implement same-neighbor-AS MED comparison in v0.3
    let a_med = a.med.unwrap_or(0);
    let b_med = b.med.unwrap_or(0);
    match a_med.cmp(&b_med) {
        Ordering::Equal => {}
        other => return other,
    }

    // Step 5: Lowest router-id as tie-breaker.
    a_router_id.cmp(&b_router_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    // ── AS_PATH tests ────────────────────────────────────────────────

    #[test]
    fn as_path_length_sequence() {
        let path = AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001, 65002, 65003])],
        };
        assert_eq!(path.length(), 3);
    }

    #[test]
    fn as_path_length_set_counts_as_one() {
        let path = AsPath {
            segments: vec![AsPathSegment::AsSet(vec![65001, 65002, 65003])],
        };
        assert_eq!(path.length(), 1);
    }

    #[test]
    fn as_path_length_mixed() {
        let path = AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65001, 65002]),
                AsPathSegment::AsSet(vec![65003, 65004]),
            ],
        };
        assert_eq!(path.length(), 3); // 2 + 1
    }

    #[test]
    fn as_path_length_empty() {
        let path = AsPath::default();
        assert_eq!(path.length(), 0);
    }

    #[test]
    fn as_path_contains_asn() {
        let path = AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001, 65002])],
        };
        assert!(path.contains_asn(65001));
        assert!(path.contains_asn(65002));
        assert!(!path.contains_asn(65003));
    }

    #[test]
    fn as_path_contains_asn_in_set() {
        let path = AsPath {
            segments: vec![AsPathSegment::AsSet(vec![65001, 65002])],
        };
        assert!(path.contains_asn(65001));
    }

    #[test]
    fn as_path_prepend_to_existing_sequence() {
        let path = AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002, 65003])],
        };
        let new_path = path.prepend(65001);
        assert_eq!(new_path.length(), 3);
        match &new_path.segments[0] {
            AsPathSegment::AsSequence(asns) => {
                assert_eq!(asns, &[65001, 65002, 65003]);
            }
            _ => panic!("expected AsSequence"),
        }
    }

    #[test]
    fn as_path_prepend_to_empty() {
        let path = AsPath::default();
        let new_path = path.prepend(65001);
        assert_eq!(new_path.length(), 1);
        match &new_path.segments[0] {
            AsPathSegment::AsSequence(asns) => {
                assert_eq!(asns, &[65001]);
            }
            _ => panic!("expected AsSequence"),
        }
    }

    #[test]
    fn as_path_display() {
        let path = AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001, 65002])],
        };
        assert_eq!(format!("{path}"), "65001 65002");
    }

    #[test]
    fn as_path_display_with_set() {
        let path = AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65001]),
                AsPathSegment::AsSet(vec![65002, 65003]),
            ],
        };
        assert_eq!(format!("{path}"), "65001 {65002,65003}");
    }

    // ── Best-path selection tests ────────────────────────────────────

    fn make_attrs(
        local_pref: Option<u32>,
        as_path_len: usize,
        origin: Origin,
        med: Option<u32>,
    ) -> PathAttributes {
        let asns: Vec<u32> = (0..as_path_len).map(|i| 65000 + i as u32).collect();
        PathAttributes {
            origin,
            as_path: AsPath {
                segments: if asns.is_empty() {
                    vec![]
                } else {
                    vec![AsPathSegment::AsSequence(asns)]
                },
            },
            next_hop: [10, 0, 0, 1],
            med,
            local_pref,
        }
    }

    #[test]
    fn best_path_higher_local_pref_wins() {
        let a = make_attrs(Some(200), 1, Origin::Igp, None);
        let b = make_attrs(Some(100), 1, Origin::Igp, None);
        assert_eq!(
            compare_paths(&a, [1, 1, 1, 1], &b, [2, 2, 2, 2]),
            Ordering::Less
        );
    }

    #[test]
    fn best_path_shorter_as_path_wins() {
        let a = make_attrs(Some(100), 1, Origin::Igp, None);
        let b = make_attrs(Some(100), 3, Origin::Igp, None);
        assert_eq!(
            compare_paths(&a, [1, 1, 1, 1], &b, [2, 2, 2, 2]),
            Ordering::Less
        );
    }

    #[test]
    fn best_path_igp_origin_preferred() {
        let a = make_attrs(Some(100), 1, Origin::Igp, None);
        let b = make_attrs(Some(100), 1, Origin::Egp, None);
        assert_eq!(
            compare_paths(&a, [1, 1, 1, 1], &b, [2, 2, 2, 2]),
            Ordering::Less
        );
    }

    #[test]
    fn best_path_lower_med_wins() {
        let a = make_attrs(Some(100), 1, Origin::Igp, Some(50));
        let b = make_attrs(Some(100), 1, Origin::Igp, Some(200));
        assert_eq!(
            compare_paths(&a, [1, 1, 1, 1], &b, [2, 2, 2, 2]),
            Ordering::Less
        );
    }

    #[test]
    fn best_path_lower_router_id_tie_breaker() {
        let a = make_attrs(Some(100), 1, Origin::Igp, None);
        let b = make_attrs(Some(100), 1, Origin::Igp, None);
        assert_eq!(
            compare_paths(&a, [1, 1, 1, 1], &b, [2, 2, 2, 2]),
            Ordering::Less
        );
        assert_eq!(
            compare_paths(&a, [2, 2, 2, 2], &b, [1, 1, 1, 1]),
            Ordering::Greater
        );
    }

    #[test]
    fn best_path_equal() {
        let a = make_attrs(Some(100), 1, Origin::Igp, None);
        let b = make_attrs(Some(100), 1, Origin::Igp, None);
        assert_eq!(
            compare_paths(&a, [1, 1, 1, 1], &b, [1, 1, 1, 1]),
            Ordering::Equal
        );
    }

    #[test]
    fn best_path_default_local_pref() {
        // When LOCAL_PREF is None, default 100 is assumed.
        let a = make_attrs(None, 1, Origin::Igp, None);
        let b = make_attrs(Some(100), 1, Origin::Igp, None);
        // Should be equal since both effectively have LP=100.
        assert_eq!(
            compare_paths(&a, [1, 1, 1, 1], &b, [1, 1, 1, 1]),
            Ordering::Equal
        );
    }
}
