//! The router's configuration in the lock form.
//!
//! The lock form spells out every parameter; nothing in it is optional, and it
//! carries a format version. [`parse_lock`] reads it and [`Lock::to_text`] writes
//! it. The processes are to take this form only and hold no defaults.
//!
//! It holds the defaults and the values that follow from the configuration alone
//! (a VLAN's MTU from its parent's). What depends on values found at run time (the
//! firewall's outside from the default routes, MAP-E's address from the delegated
//! prefix) is still worked out by the process.
//!
//! # The lock form
//!
//! The settings of confd's configuration file (`ruster_confd::file`) with every
//! key given. A value there may be none or one of
//! is a list (`ipv4 = []`, `via = ["198.51.100.1"]`, `nat = []`); an empty list
//! means there is none, and for a firewall match, that it matches anything. An
//! interface's `kind` and a route's `target` say what it is.
//!
//! ```toml
//! version = 1
//! firewall-filtering = "endpoint-independent"
//! firewall-outside = "derive"  # NAT's outside and the default routes', or a list
//! map-e = []                   # a [[map-e]] has all of [map-e]'s keys, and
//!                              # mac = "02:00:00:00:00:fe" and ports = "1024-32767"
//!                              # (the NAT's ports when the address is not shared)
//!
//! [icmp-errors]
//! ipv4-interval-ms = 100
//! ipv6-burst = 10
//! ipv6-interval-ms = 10
//!
//! [[interface]]
//! name = "lan"
//! mac = "02:00:00:00:00:01"
//! mtu = 1500
//! enabled = true
//! vrf = "default"
//! ipv4 = ["192.0.2.1/24"]
//! ipv6 = []
//! kind = "port"
//!
//! [[interface]]
//! name = "lan.10"
//! mac = "02:00:00:00:00:01"
//! mtu = 1496
//! enabled = true
//! vrf = "default"
//! ipv4 = []
//! ipv6 = []
//!
//! [interface.kind.vlan]        # or [interface.kind.tunnel] with local and remote,
//! parent = "lan"               # [interface.kind.pppoe] with parent, session, peer
//! id = 10
//!
//! [[nat]]
//! inside = "lan.10"
//! outside = "lan"
//! ports = "1024-32767"
//! external = []                # the outside's own address
//! filtering = "endpoint-independent"
//! ipv4-id-rate-limit = true
//! ports-per-host = 0
//! state-per-host = 0
//!
//! [[route]]
//! vrf = "default"
//! prefix = "10.0.0.0/8"
//! target = "discard"           # or "reject"
//!
//! [[route]]
//! vrf = "default"
//! prefix = "0.0.0.0/0"
//!
//! [route.target.forward]       # or [route.target] with lookup-vrf = "red"
//! interface = "lan"
//! via = ["192.0.2.254"]
//!
//! [[firewall]]
//! action = "accept"
//! protocol = "udp"
//! ingress = ["lan"]
//! egress = []
//! source = []
//! destination = []
//! source-ports = []
//! destination-ports = ["53"]
//! ```
//!
//! Text with another `version` is refused. A later version that removes a
//! parameter or changes its meaning gets a new number.
//!
//! # Standards
//!
//! - RFC 6243: the lock form is the configuration with its defaults reported, as
//!   `report-all` does. Deviation: it is TOML, not a YANG instance.

use serde::{Deserialize, Serialize};

/// The lock form's version that this ruster reads and writes.
pub const VERSION: u32 = 1;

/// The configuration with every parameter given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Lock {
    pub version: u32,
    pub firewall_filtering: String,
    pub firewall_outside: FirewallOutside,
    pub icmp_errors: IcmpErrors,
    pub interface: Vec<Interface>,
    /// None or one.
    pub map_e: Vec<MapE>,
    /// None or one.
    pub nat: Vec<Nat>,
    pub route: Vec<Route>,
    pub firewall: Vec<FirewallRule>,
}

/// The firewall's outside interfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "OutsideText", into = "OutsideText")]
pub enum FirewallOutside {
    /// NAT's outside and the interfaces of the default routes, found at run time.
    Derive,
    Interfaces(Vec<String>),
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum OutsideText {
    Word(String),
    List(Vec<String>),
}

impl TryFrom<OutsideText> for FirewallOutside {
    type Error = String;
    fn try_from(text: OutsideText) -> Result<Self, String> {
        match text {
            OutsideText::Word(word) if word == "derive" => Ok(Self::Derive),
            OutsideText::Word(_) => Err("firewall-outside must be \"derive\" or a list".into()),
            OutsideText::List(names) => Ok(Self::Interfaces(names)),
        }
    }
}

impl From<FirewallOutside> for OutsideText {
    fn from(outside: FirewallOutside) -> Self {
        match outside {
            FirewallOutside::Derive => Self::Word("derive".into()),
            FirewallOutside::Interfaces(names) => Self::List(names),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct IcmpErrors {
    pub ipv4_interval_ms: u32,
    pub ipv6_burst: u32,
    pub ipv6_interval_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Interface {
    pub name: String,
    pub mac: String,
    pub mtu: u16,
    pub enabled: bool,
    pub vrf: String,
    /// None or one.
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub kind: Kind,
}

/// What an interface is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum Kind {
    /// An FE port.
    Port,
    /// A VLAN sub-interface of a port.
    Vlan { parent: String, id: u16 },
    /// An IPv4 in IPv6 tunnel (DS-Lite).
    Tunnel { local: String, remote: String },
    /// A PPPoE session on a port or VLAN.
    Pppoe {
        parent: String,
        session: u16,
        peer: String,
    },
}

/// A MAP-E CE (RFC 7597): one Basic Mapping Rule, the delegated prefix, the BR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct MapE {
    /// The tunnel interface it makes.
    pub interface: String,
    /// The NAT's inside interface.
    pub inside: String,
    /// The end-user IPv6 prefix (the one delegated to the CE).
    pub prefix: String,
    pub rule_ipv6: String,
    pub rule_ipv4: String,
    pub ea_length: u8,
    pub psid_offset: u8,
    pub br: String,
    pub mtu: u16,
    /// The tunnel's MAC address.
    pub mac: String,
    /// The NAT's ports when the address is not shared (no PSID).
    pub ports: String,
    pub filtering: String,
    pub ipv4_id_rate_limit: bool,
    pub ports_per_host: u16,
    pub state_per_host: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Nat {
    pub inside: String,
    pub outside: String,
    pub ports: String,
    /// None (the outside's own address) or one.
    pub external: Vec<String>,
    pub filtering: String,
    pub ipv4_id_rate_limit: bool,
    pub ports_per_host: u16,
    pub state_per_host: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Route {
    pub vrf: String,
    pub prefix: String,
    pub target: Target,
}

/// Where a route sends its packets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum Target {
    /// Out of an interface, to `via` (none or one) or on-link.
    Forward { interface: String, via: Vec<String> },
    /// Looked up again in another VRF.
    LookupVrf(String),
    /// Dropped silently.
    Discard,
    /// Dropped with a Destination Unreachable.
    Reject,
}

/// A firewall rule; each match is none (anything) or one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct FirewallRule {
    pub action: String,
    pub protocol: String,
    pub ingress: Vec<String>,
    pub egress: Vec<String>,
    pub source: Vec<String>,
    pub destination: Vec<String>,
    pub source_ports: Vec<String>,
    pub destination_ports: Vec<String>,
}

impl Lock {
    /// The lock form as TOML text.
    pub fn to_text(&self) -> String {
        toml::to_string(self).expect("the lock form is plain TOML")
    }
}

/// Whether the text is the lock form: it has a top-level `version`.
pub fn is_lock(text: &str) -> Result<bool, String> {
    let table: toml::Table = toml::from_str(text).map_err(|e| e.to_string())?;
    Ok(table.contains_key("version"))
}

/// Reads the lock form. Every key must be there, and the version must be
/// [`VERSION`].
pub fn parse_lock(text: &str) -> Result<Lock, String> {
    let table: toml::Table = toml::from_str(text).map_err(|e| e.to_string())?;
    match table.get("version") {
        None => return Err("version is missing: not the lock form".into()),
        Some(toml::Value::Integer(v)) if *v == i64::from(VERSION) => {}
        Some(v) => {
            return Err(format!(
                "version {v} is not one this ruster reads; it reads version {VERSION}"
            ))
        }
    }
    toml::from_str(text).map_err(|e| e.to_string())
}
