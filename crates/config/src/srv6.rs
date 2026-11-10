//! `[srv6]`: the router's SRv6 SIDs and SR policies (`docs/design/overlay.md`
//! section 5), which confd hands to ribd as routes.

use serde::{Deserialize, Serialize};

/// SRv6, every value given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Srv6 {
    /// The IPv6 prefix the router's SIDs are taken from.
    pub locator: String,
    /// The outer source address of the SR policies.
    pub source: String,
    pub sid: Vec<Srv6Sid>,
    pub policy: Vec<Srv6Policy>,
}

/// One local SID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Srv6Sid {
    /// An IPv6 address in the locator.
    pub sid: String,
    /// `End`, `End.X`, `End.DT4` or `End.DT6` (RFC 8986 section 10.2's names).
    pub behavior: String,
    /// None or one: End.DT4's and End.DT6's VRF.
    pub vrf: Vec<String>,
    /// None or one: End.X's interface.
    pub interface: Vec<String>,
    /// None or one: End.X's next hop.
    pub next_hop: Vec<String>,
}

/// One SR policy: packets to `prefix` in `vrf` leave wrapped toward `segments`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Srv6Policy {
    pub prefix: String,
    pub vrf: String,
    /// The first segment first.
    pub segments: Vec<String>,
    /// H.Encaps.Red: the first segment left out of the Segment Routing Header.
    pub reduced: bool,
}

/// `[srv6]` of `ruster.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct Srv6Entry {
    locator: String,
    source: String,
    #[serde(default)]
    sid: Vec<SidEntry>,
    #[serde(default)]
    policy: Vec<PolicyEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct SidEntry {
    sid: String,
    behavior: String,
    vrf: Option<String>,
    interface: Option<String>,
    next_hop: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct PolicyEntry {
    prefix: String,
    vrf: Option<String>,
    segments: Vec<String>,
    reduced: Option<bool>,
}

pub(crate) fn resolve(entry: Srv6Entry) -> Srv6 {
    Srv6 {
        locator: entry.locator,
        source: entry.source,
        sid: entry
            .sid
            .into_iter()
            .map(|s| Srv6Sid {
                sid: s.sid,
                behavior: s.behavior,
                vrf: s.vrf.into_iter().collect(),
                interface: s.interface.into_iter().collect(),
                next_hop: s.next_hop.into_iter().collect(),
            })
            .collect(),
        policy: entry
            .policy
            .into_iter()
            .map(|p| Srv6Policy {
                prefix: p.prefix,
                vrf: p.vrf.unwrap_or_else(|| "default".to_owned()),
                segments: p.segments,
                reduced: p.reduced.unwrap_or(false),
            })
            .collect(),
    }
}
