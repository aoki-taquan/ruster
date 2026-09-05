use crate::MacAddress;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IfId(pub u16);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ipv4Address(u32);

impl Ipv4Address {
    #[must_use]
    pub const fn from_octets(octets: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(octets))
    }

    #[must_use]
    pub const fn octets(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    #[must_use]
    pub const fn is_unspecified(self) -> bool {
        self.0 == 0
    }
}

/// The largest IPv4 datagram, in bytes, one interface will transmit.
///
/// The lower bound is the 68 bytes every IPv4 implementation must be able to
/// forward (RFC 791 §3.2); the upper bound is the largest total length an
/// IPv4 header can express. The value counts the IPv4 datagram only, never
/// the link-layer header, so it is directly comparable to `total_len`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ipv4Mtu(u16);

/// The smallest IPv4 MTU a link may declare (RFC 791 §3.2).
pub const IPV4_MINIMUM_MTU: u16 = 68;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4MtuError {
    BelowMinimum { bytes: u16 },
}

impl Ipv4Mtu {
    /// The MTU of a standard Ethernet link, and the default for an interface
    /// whose configuration does not state one.
    pub const ETHERNET: Self = Self(1_500);

    /// The smallest MTU this router accepts.
    pub const MINIMUM: Self = Self(IPV4_MINIMUM_MTU);

    /// Checks a configured MTU against the IPv4 minimum.
    pub const fn new(bytes: u16) -> Result<Self, Ipv4MtuError> {
        if bytes < IPV4_MINIMUM_MTU {
            return Err(Ipv4MtuError::BelowMinimum { bytes });
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn bytes(self) -> u16 {
        self.0
    }

    /// Returns the MTU as a length comparable to a validated `total_len`.
    #[must_use]
    pub const fn as_len(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Interface {
    pub id: IfId,
    pub mac: MacAddress,
    pub mtu: Ipv4Mtu,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Neighbor {
    pub interface: IfId,
    pub target: Ipv4Address,
    pub mac: MacAddress,
}

/// The single IPv4 address owned by one interface in the current profile.
///
/// The binding deliberately has no MAC address. [`Interface`] remains the
/// single source of truth for the link-layer identity used by ARP replies.
/// [`crate::ForwardingSnapshot::new`] rejects a second address on an interface
/// and the same address on another interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalIpv4Binding {
    pub interface: IfId,
    pub address: Ipv4Address,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Route {
    prefix: Ipv4Address,
    prefix_len: u8,
    egress: IfId,
    next_hop: Option<Ipv4Address>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteError {
    InvalidPrefixLength,
    HostBitsSet,
}

impl Route {
    pub fn new(
        prefix: Ipv4Address,
        prefix_len: u8,
        egress: IfId,
        next_hop: Option<Ipv4Address>,
    ) -> Result<Self, RouteError> {
        let mask = prefix_mask(prefix_len).ok_or(RouteError::InvalidPrefixLength)?;
        if prefix.0 & !mask != 0 {
            return Err(RouteError::HostBitsSet);
        }
        Ok(Self {
            prefix,
            prefix_len,
            egress,
            next_hop,
        })
    }

    #[must_use]
    pub const fn prefix(self) -> Ipv4Address {
        self.prefix
    }

    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    #[must_use]
    pub const fn egress(self) -> IfId {
        self.egress
    }

    #[must_use]
    pub const fn next_hop(self) -> Option<Ipv4Address> {
        self.next_hop
    }

    pub(crate) fn matches(self, address: Ipv4Address) -> bool {
        let mask = prefix_mask(self.prefix_len).expect("Route::new validates prefix length");
        address.0 & mask == self.prefix.0
    }

    pub(crate) fn is_connected_directed_broadcast(self, address: Ipv4Address) -> bool {
        self.next_hop.is_none() && self.is_prefix_directed_broadcast(address)
    }

    pub(crate) fn is_connected_network_address(self, address: Ipv4Address) -> bool {
        self.next_hop.is_none() && self.is_prefix_network_address(address)
    }

    pub(crate) fn is_prefix_directed_broadcast(self, address: Ipv4Address) -> bool {
        if self.prefix_len > 30 || !self.matches(address) {
            return false;
        }
        let mask = prefix_mask(self.prefix_len).expect("Route::new validates prefix length");
        address.0 == self.prefix.0 | !mask
    }

    pub(crate) fn is_prefix_network_address(self, address: Ipv4Address) -> bool {
        self.prefix_len <= 30 && self.matches(address) && address == self.prefix
    }
}

pub(crate) fn lookup(routes: &[Route], destination: Ipv4Address) -> Option<Route> {
    routes
        .iter()
        .copied()
        .filter(|route| route.matches(destination))
        .max_by_key(|route| route.prefix_len)
}

fn prefix_mask(prefix_len: u8) -> Option<u32> {
    match prefix_len {
        0 => Some(0),
        1..=32 => Some(u32::MAX << (32 - u32::from(prefix_len))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(octets: [u8; 4]) -> Ipv4Address {
        Ipv4Address::from_octets(octets)
    }

    #[test]
    fn lpm_selects_host_route_over_default() {
        let routes = [
            Route::new(ip([0, 0, 0, 0]), 0, IfId(1), Some(ip([10, 0, 0, 1]))).unwrap(),
            Route::new(ip([192, 0, 2, 9]), 32, IfId(2), None).unwrap(),
        ];
        assert_eq!(
            lookup(&routes, ip([192, 0, 2, 9])).unwrap().egress(),
            IfId(2)
        );
        assert_eq!(
            lookup(&routes, ip([192, 0, 2, 10])).unwrap().egress(),
            IfId(1)
        );
    }

    #[test]
    fn route_rejects_noncanonical_and_oversized_prefixes() {
        assert_eq!(
            Route::new(ip([10, 0, 0, 1]), 24, IfId(1), None),
            Err(RouteError::HostBitsSet)
        );
        assert_eq!(
            Route::new(ip([0, 0, 0, 0]), 33, IfId(1), None),
            Err(RouteError::InvalidPrefixLength)
        );
    }

    #[test]
    fn prefix_boundaries_are_independent_of_gateway_and_exclude_point_to_point() {
        let gateway =
            Route::new(ip([198, 51, 100, 0]), 24, IfId(1), Some(ip([192, 0, 2, 1]))).unwrap();
        assert!(gateway.is_prefix_network_address(ip([198, 51, 100, 0])));
        assert!(gateway.is_prefix_directed_broadcast(ip([198, 51, 100, 255])));
        assert!(!gateway.is_connected_network_address(ip([198, 51, 100, 0])));
        assert!(!gateway.is_connected_directed_broadcast(ip([198, 51, 100, 255])));

        for prefix_len in [31, 32] {
            let route = Route::new(ip([198, 51, 100, 0]), prefix_len, IfId(1), None).unwrap();
            assert!(!route.is_prefix_network_address(ip([198, 51, 100, 0])));
            assert!(!route.is_prefix_directed_broadcast(ip([198, 51, 100, 0])));
        }
    }

    #[test]
    fn unspecified_address_is_only_all_zeroes() {
        // Protects Ipv4Address::is_unspecified from reporting every address as unspecified.
        assert!(ip([0, 0, 0, 0]).is_unspecified());
        assert!(!ip([0, 0, 0, 1]).is_unspecified());
    }

    #[test]
    fn slash_thirty_prefix_has_a_directed_broadcast() {
        // Protects the > 30 boundary so a /30 directed broadcast is still recognized.
        let route = Route::new(ip([198, 51, 100, 0]), 30, IfId(1), None).unwrap();

        assert!(route.is_prefix_directed_broadcast(ip([198, 51, 100, 3])));
        assert!(!route.is_prefix_directed_broadcast(ip([198, 51, 100, 2])));
    }

    // The | -> ^ mutant is equivalent: Route::new rejects host bits in the prefix,
    // so prefix.0 and !mask never share a set bit and OR equals XOR here.
}
