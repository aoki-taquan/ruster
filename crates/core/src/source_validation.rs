//! Per-interface IPv4 source address validation (URPF).
//!
//! RFC 1812 §5.3.8: "A router SHOULD IMPLEMENT the ability to filter
//! traffic based on a comparison of the source address of a packet and the
//! forwarding table for a logical interface on which the packet was
//! received. If this filtering is enabled, the router MUST silently discard
//! a packet if the interface on which the packet was received is not the
//! interface on which a packet would be forwarded to reach the address
//! contained in the source address. [...] If this feature is implemented,
//! it MUST be disabled by default." That is [`SourceValidation::Strict`],
//! and [`SourceValidation::Off`] is the default.
//!
//! RFC 3704 (BCP 84) §2.4 adds loose reverse-path forwarding (the source
//! only needs some route), and §2.5 the variant ignoring default routes,
//! which is [`SourceValidation::Loose`]; [`SourceValidation::LooseAllowDefault`]
//! is §2.4 without that exception. RFC 2827 (BCP 38) is the ingress
//! filtering these modes automate.
//!
//! Feasible-path uRPF (RFC 3704 §2.3) and its enhanced form (RFC 8704)
//! accept any of the alternate paths a router knows for the source's
//! prefix. The forwarding table holds exactly one path per prefix (no
//! ECMP, no RIB of alternate paths), so feasible-path would be strict and
//! is not offered.
//!
//! The check reuses the route lookup of the source that the IPv4 ingress
//! validation already performs for the martian source checks, so it adds no
//! lookup; with every interface off the snapshot holds no binding and the
//! check is a single empty-slice branch.
//!
//! # Standards
//!
//! - RFC 1812 section 5.3.8: strict reverse-path filtering, off by default.
//! - RFC 3704 sections 2.4 and 2.5: loose reverse-path filtering, with and without
//!   default routes.
//!
//! Deviations: no feasible-path reverse-path filtering (RFC 3704 section 2.3, RFC
//! 8704): the table holds one path per prefix.

use crate::{IfId, Route};

/// The source address validation mode of one ingress interface.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub enum SourceValidation {
    /// No check (RFC 1812 §5.3.8: disabled by default).
    #[default]
    Off,
    /// RFC 3704 §2.5 loose mode ignoring default routes: the longest
    /// matching route for the source exists and is not a `/0`, out of any
    /// interface.
    Loose,
    /// RFC 3704 §2.4 loose mode: the source has any route, a default route
    /// included. With a default route this admits every source the martian
    /// checks admit.
    LooseAllowDefault,
    /// RFC 1812 §5.3.8, RFC 3704 §2.2 strict mode: the longest matching
    /// route for the source (a default route included) leaves through the
    /// ingress interface.
    Strict,
}

impl SourceValidation {
    /// Stable lowercase label (`off`, `loose`, `loose-allow-default`,
    /// `strict`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Loose => "loose",
            Self::LooseAllowDefault => "loose-allow-default",
            Self::Strict => "strict",
        }
    }

    /// Whether a datagram received on `ingress` whose source has
    /// `source_route` as its longest matching route passes this mode.
    ///
    /// TODO(URPF): the forwarding table has no null (blackhole) route yet.
    /// When one is added, a source whose longest match is a null route must
    /// fail both loose and strict (RFC 3704 §2.4: a route to a null
    /// interface does not count), so this match has to learn about it.
    #[inline]
    #[must_use]
    pub(crate) fn admits(self, ingress: IfId, source_route: Option<Route>) -> bool {
        match self {
            Self::Off => true,
            Self::Loose => source_route.is_some_and(|route| route.prefix_len() != 0),
            Self::LooseAllowDefault => source_route.is_some(),
            Self::Strict => source_route.is_some_and(|route| route.egress() == ingress),
        }
    }
}

/// The source validation mode of one interface in a forwarding snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceValidationBinding {
    pub interface: IfId,
    pub mode: SourceValidation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ipv4Address;

    const LAN: IfId = IfId(1);
    const WAN: IfId = IfId(2);

    fn route(prefix: [u8; 4], len: u8, egress: IfId) -> Route {
        Route::new(Ipv4Address::from_octets(prefix), len, egress, None).unwrap()
    }

    #[test]
    fn source_validation_modes_follow_rfc1812_and_rfc3704() {
        let lan = Some(route([192, 0, 2, 0], 24, LAN));
        let default_wan = Some(route([0, 0, 0, 0], 0, WAN));
        for (mode, none, on_lan, default) in [
            (SourceValidation::Off, true, true, true),
            (SourceValidation::Loose, false, true, false),
            (SourceValidation::LooseAllowDefault, false, true, true),
            (SourceValidation::Strict, false, true, true),
        ] {
            assert_eq!(mode.admits(LAN, None), none, "{mode:?} no route");
            assert_eq!(mode.admits(LAN, lan), on_lan, "{mode:?} route via ingress");
            assert_eq!(mode.admits(WAN, default_wan), default, "{mode:?} default");
        }
        // Asymmetric: the route back leaves through another interface.
        assert!(!SourceValidation::Strict.admits(WAN, lan));
        assert!(SourceValidation::Loose.admits(WAN, lan));
        assert!(SourceValidation::LooseAllowDefault.admits(WAN, lan));
        assert!(!SourceValidation::Strict.admits(LAN, default_wan));
        assert_eq!(SourceValidation::default(), SourceValidation::Off);
        assert_eq!(
            [
                SourceValidation::Off,
                SourceValidation::Loose,
                SourceValidation::LooseAllowDefault,
                SourceValidation::Strict
            ]
            .map(SourceValidation::label),
            ["off", "loose", "loose-allow-default", "strict"]
        );
    }
}
