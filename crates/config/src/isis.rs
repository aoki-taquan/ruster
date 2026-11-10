//! `[isis]`: IS-IS, which FRR's isisd speaks on the TAP devices of its interfaces
//! (`docs/design/overlay.md` section 6) and `ruster-frr` configures.

use serde::{Deserialize, Serialize};

/// The level an IS-IS router takes part in when not told (ISO 10589 section 7.1:
/// a router may be both).
pub const ISIS_LEVEL: &str = "level-1-2";
/// An interface's metric when not told (ISO 10589's default).
pub const ISIS_METRIC: u32 = 10;
/// The levels: one, the other, or both.
pub const ISIS_LEVELS: [&str; 3] = ["level-1", "level-2", "level-1-2"];

/// IS-IS in the default VRF, every value given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Isis {
    /// The Network Entity Title: the area, the system ID and NSEL 00, as
    /// `49.0001.1921.6800.1001.00`.
    pub net: String,
    /// One of [`ISIS_LEVELS`].
    pub level: String,
    pub interface: Vec<IsisInterface>,
}

/// One interface IS-IS runs on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct IsisInterface {
    pub name: String,
    /// The wide metric (RFC 5305).
    pub metric: u32,
    /// Its prefixes are announced, but no adjacency is formed on it.
    pub passive: bool,
}

/// `[isis]` of `ruster.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct IsisEntry {
    net: String,
    level: Option<String>,
    #[serde(default)]
    interface: Vec<IsisInterfaceEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct IsisInterfaceEntry {
    name: String,
    metric: Option<u32>,
    passive: Option<bool>,
}

pub(crate) fn resolve(entry: IsisEntry) -> Isis {
    Isis {
        net: entry.net,
        level: entry.level.unwrap_or_else(|| ISIS_LEVEL.to_owned()),
        interface: entry
            .interface
            .into_iter()
            .map(|i| IsisInterface {
                name: i.name,
                metric: i.metric.unwrap_or(ISIS_METRIC),
                passive: i.passive.unwrap_or(false),
            })
            .collect(),
    }
}
