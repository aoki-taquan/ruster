//! OSPF configuration types.
//!
//! Defines the configuration structures for OSPFv2, including
//! area definitions, interface parameters, and timer settings.
//!
//! RFC-REF: RFC 2328 Appendix C
//! "Configurable Constants" — lists the per-interface and
//! per-area configuration knobs that an OSPF implementation
//! should expose.

/// Top-level OSPF configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfConfig {
    /// Router ID in dotted-decimal form (e.g. "10.0.0.1").
    ///
    /// RFC-REF: RFC 2328 Section 4.1
    /// "Each router has an associated 32-bit quantity known as the
    /// Router ID."
    pub router_id: [u8; 4],

    /// OSPF areas (v0.2: only area 0 is supported).
    pub areas: Vec<AreaConfig>,
}

/// Per-area configuration.
///
/// RFC-DEVIATION:
/// reason: Only backbone area (0.0.0.0) is supported in v0.2.
/// impact: Multi-area OSPF topologies will not work.
/// issue: #157
/// plan: Add multi-area support in a future version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AreaConfig {
    /// Area ID as a 4-byte value (e.g. `[0,0,0,0]` for backbone).
    ///
    /// RFC-REF: RFC 2328 Section 4.2
    /// "Each OSPF area is identified by a 32-bit Area ID."
    pub id: [u8; 4],

    /// Interfaces participating in this area.
    pub interfaces: Vec<OspfInterfaceConfig>,
}

/// Per-interface OSPF configuration.
///
/// RFC-REF: RFC 2328 Section 9
/// "Each OSPF interface has a number of configurable parameters."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfInterfaceConfig {
    /// Logical interface name (must match an entry in the router's
    /// interface table).
    pub name: String,

    /// Seconds between Hello packet transmissions.
    ///
    /// RFC-REF: RFC 2328 Section 9.5
    /// "The length of time, in seconds, between the Hello packets
    /// that the router sends on the interface."
    pub hello_interval: u16,

    /// Seconds before declaring a silent neighbor down.
    ///
    /// RFC-REF: RFC 2328 Section 9.6
    /// "An interval of RouterDeadInterval seconds is used to detect
    /// non-functioning routers."
    pub dead_interval: u16,
}

impl Default for OspfInterfaceConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            hello_interval: 10,
            dead_interval: 40,
        }
    }
}

/// Parse a dotted-decimal IP string (e.g. "10.0.0.1") into a 4-byte
/// array.  Returns `None` if the string is malformed.
pub fn parse_router_id(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut id = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        id[i] = part.parse::<u8>().ok()?;
    }
    Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_router_id_valid() {
        assert_eq!(parse_router_id("10.0.0.1"), Some([10, 0, 0, 1]));
        assert_eq!(parse_router_id("0.0.0.0"), Some([0, 0, 0, 0]));
        assert_eq!(
            parse_router_id("255.255.255.255"),
            Some([255, 255, 255, 255])
        );
    }

    #[test]
    fn parse_router_id_invalid() {
        assert_eq!(parse_router_id("10.0.0"), None);
        assert_eq!(parse_router_id("10.0.0.1.2"), None);
        assert_eq!(parse_router_id("abc.def.ghi.jkl"), None);
        assert_eq!(parse_router_id("256.0.0.1"), None);
    }

    #[test]
    fn default_interface_config() {
        let cfg = OspfInterfaceConfig::default();
        assert_eq!(cfg.hello_interval, 10);
        assert_eq!(cfg.dead_interval, 40);
    }
}
