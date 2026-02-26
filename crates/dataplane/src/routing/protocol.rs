//! Routing protocol source definitions and plugin interface.
//!
//! This module defines the [`ProtocolSource`] enum that identifies which
//! routing protocol installed a given route, the default administrative
//! distances for each source, and the [`RoutingProtocol`] trait that
//! future protocol implementations (OSPF, BGP) will implement.
//!
//! # Administrative distance
//!
//! When multiple routing protocols advertise the same prefix, the route
//! with the lowest administrative distance wins.  The defaults follow
//! Cisco IOS conventions:
//!
//! | Source    | Default AD |
//! |-----------|-----------|
//! | Connected | 0         |
//! | Static    | 1         |
//! | eBGP      | 20        |
//! | OSPF      | 110       |
//!
//! RFC-REF: RFC 791 Section 3.2
//! "The internet module uses the addresses carried in the internet header
//! to select the next gateway or destination host."
//! Administrative distance is vendor convention (not RFC-defined) used
//! to select among multiple routing sources for the same prefix.

use super::rib::RibEntry;

/// Identifies which routing protocol or mechanism installed a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProtocolSource {
    /// Directly connected network (derived from interface addresses).
    Connected,
    /// Statically configured route (from `router.toml`).
    Static,
    /// eBGP-learned route.
    Bgp,
    /// OSPF-learned route.
    Ospf,
}

impl ProtocolSource {
    /// Return the default administrative distance for this protocol source.
    ///
    /// Lower values are preferred.  These defaults follow Cisco IOS
    /// conventions:
    /// - Connected: 0
    /// - Static: 1
    /// - eBGP: 20
    /// - OSPF: 110
    pub fn default_admin_distance(self) -> u8 {
        match self {
            Self::Connected => 0,
            Self::Static => 1,
            Self::Bgp => 20,
            Self::Ospf => 110,
        }
    }
}

impl std::fmt::Display for ProtocolSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connected => write!(f, "connected"),
            Self::Static => write!(f, "static"),
            Self::Bgp => write!(f, "bgp"),
            Self::Ospf => write!(f, "ospf"),
        }
    }
}

/// Trait that routing protocol implementations must satisfy.
///
/// Each protocol adapter (e.g. a future OSPF or BGP daemon interface)
/// implements this trait so that its routes can be injected into the RIB
/// through a uniform interface.
///
/// # Example (future OSPF adapter)
///
/// ```ignore
/// struct OspfAdapter { /* ... */ }
///
/// impl RoutingProtocol for OspfAdapter {
///     fn name(&self) -> &str { "ospf" }
///     fn source(&self) -> ProtocolSource { ProtocolSource::Ospf }
///     fn admin_distance(&self) -> u8 { ProtocolSource::Ospf.default_admin_distance() }
///     fn routes(&self) -> Vec<RibEntry> { /* query OSPF LSDB */ }
/// }
/// ```
pub trait RoutingProtocol {
    /// Human-readable protocol name (e.g. "ospf", "bgp").
    fn name(&self) -> &str;

    /// The protocol source identifier for routes from this protocol.
    fn source(&self) -> ProtocolSource;

    /// The administrative distance assigned to this protocol instance.
    ///
    /// Defaults can be obtained from [`ProtocolSource::default_admin_distance`],
    /// but implementations may override (e.g. iBGP vs eBGP).
    fn admin_distance(&self) -> u8;

    /// Return all routes currently known by this protocol.
    ///
    /// Called by the RIB manager when (re)synchronizing protocol routes.
    fn routes(&self) -> Vec<RibEntry>;
}

/// A simple static route adapter that implements [`RoutingProtocol`].
///
/// This wraps a set of pre-built [`RibEntry`] values (from config) so
/// that static routes participate in the same RIB insertion path as
/// dynamic protocols.
pub struct StaticRouteAdapter {
    entries: Vec<RibEntry>,
}

impl StaticRouteAdapter {
    /// Create a new adapter holding the given static route entries.
    pub fn new(entries: Vec<RibEntry>) -> Self {
        Self { entries }
    }
}

impl RoutingProtocol for StaticRouteAdapter {
    fn name(&self) -> &str {
        "static"
    }

    fn source(&self) -> ProtocolSource {
        ProtocolSource::Static
    }

    fn admin_distance(&self) -> u8 {
        ProtocolSource::Static.default_admin_distance()
    }

    fn routes(&self) -> Vec<RibEntry> {
        self.entries.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_distance_ordering() {
        // Connected < Static < BGP < OSPF.
        assert!(ProtocolSource::Connected.default_admin_distance() < ProtocolSource::Static.default_admin_distance());
        assert!(ProtocolSource::Static.default_admin_distance() < ProtocolSource::Bgp.default_admin_distance());
        assert!(ProtocolSource::Bgp.default_admin_distance() < ProtocolSource::Ospf.default_admin_distance());
    }

    #[test]
    fn admin_distance_exact_values() {
        assert_eq!(ProtocolSource::Connected.default_admin_distance(), 0);
        assert_eq!(ProtocolSource::Static.default_admin_distance(), 1);
        assert_eq!(ProtocolSource::Bgp.default_admin_distance(), 20);
        assert_eq!(ProtocolSource::Ospf.default_admin_distance(), 110);
    }

    #[test]
    fn display_names() {
        assert_eq!(format!("{}", ProtocolSource::Connected), "connected");
        assert_eq!(format!("{}", ProtocolSource::Static), "static");
        assert_eq!(format!("{}", ProtocolSource::Bgp), "bgp");
        assert_eq!(format!("{}", ProtocolSource::Ospf), "ospf");
    }

    #[test]
    fn static_adapter_implements_trait() {
        let entries = vec![RibEntry {
            prefix: [10, 0, 0, 0],
            prefix_len: 8,
            next_hop: [10, 0, 0, 1],
            out_ifname: "wan0".to_string(),
            metric: 100,
            source: ProtocolSource::Static,
            admin_distance: 1,
        }];
        let adapter = StaticRouteAdapter::new(entries.clone());
        assert_eq!(adapter.name(), "static");
        assert_eq!(adapter.source(), ProtocolSource::Static);
        assert_eq!(adapter.admin_distance(), 1);
        assert_eq!(adapter.routes().len(), 1);
        assert_eq!(adapter.routes()[0].prefix, [10, 0, 0, 0]);
    }
}
