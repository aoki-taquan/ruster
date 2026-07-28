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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Interface {
    pub id: IfId,
    pub mac: MacAddress,
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
}
