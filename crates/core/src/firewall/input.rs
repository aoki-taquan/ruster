//! Input (local-delivery) firewall (INPUT-FW): a stateless first-match
//! policy for datagrams addressed to the router itself.
//!
//! The forward firewall ([`super::FirewallConfig`]) judges transit and NAT
//! traffic only. A datagram for one of the router's own addresses (Echo,
//! the ICMP-ERR local errors, any other local traffic) is judged here,
//! after the martian and URPF ingress checks and before any local
//! decision, so a denied datagram is dropped without any ICMP error: no
//! Echo Reply, Port or Protocol Unreachable, or Parameter Problem.
//!
//! The policy is stateless on purpose. The router originates no TCP or UDP
//! session and no ICMP query, so nothing addressed to it is a reply to
//! traffic it started; the ICMP errors it originates are never answered
//! (RFC 1122 §3.2.2), and replies to NAT traffic go to the NAT path, which
//! the forward firewall judges with its flow state. A flow table would
//! therefore hold nothing a rule could not say, and costs storage.
//!
//! The rules reuse the forward rule language: the rule id, interface,
//! prefix, and port range types and their matchers. Selectors are the
//! ingress interface, source and destination prefixes, the IPv4 protocol,
//! and, for ICMP, the message type, or, for TCP and UDP, the destination
//! port. The default action is [`InputFirewallAction::Accept`], which is
//! the RFC behavior and the behavior without the table.
//!
//! A datagram whose transport header cannot be read (a fragment that is
//! not the first, or a datagram the link truncated) has no transport
//! selectors. A rule that needs one then matches only if it denies: an
//! `accept` rule for ICMP Echo never admits a datagram whose type is
//! unknown, and a `deny` rule for some port refuses it (fail closed).

use super::{FirewallInterface, FirewallIpv4Prefix, FirewallPortRange, FirewallRuleId};
use crate::{IfId, Ipv4Address};

/// The action of an input rule or of the input default.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum InputFirewallAction {
    /// Deliver the datagram to the router's local decision (Echo, the
    /// ICMP-ERR errors, consume), as without an input firewall.
    #[default]
    Accept,
    /// Drop the datagram silently, without any ICMP error.
    Deny,
}

impl InputFirewallAction {
    /// Stable lowercase label (`accept`, `deny`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Deny => "deny",
        }
    }
}

/// The transport selector of an input rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputFirewallProtocol {
    /// Every IPv4 protocol.
    Any,
    /// ICMP (protocol 1), with one message type or every type.
    Icmp { icmp_type: Option<u8> },
    /// TCP (protocol 6) to a destination port range.
    Tcp {
        destination_ports: FirewallPortRange,
    },
    /// UDP (protocol 17) to a destination port range.
    Udp {
        destination_ports: FirewallPortRange,
    },
}

impl InputFirewallProtocol {
    /// Whether the selector reads the transport header (an ICMP type, or
    /// a port range narrower than every port).
    const fn needs_transport(self) -> bool {
        match self {
            Self::Any => false,
            Self::Icmp { icmp_type } => icmp_type.is_some(),
            Self::Tcp { destination_ports } | Self::Udp { destination_ports } => {
                !(destination_ports.first() == 0 && destination_ports.last() == u16::MAX)
            }
        }
    }
}

/// One stateless first-match input rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputFirewallRule {
    id: FirewallRuleId,
    ingress: FirewallInterface,
    source: FirewallIpv4Prefix,
    destination: FirewallIpv4Prefix,
    protocol: InputFirewallProtocol,
    action: InputFirewallAction,
}

impl InputFirewallRule {
    #[must_use]
    pub const fn new(
        id: FirewallRuleId,
        ingress: FirewallInterface,
        source: FirewallIpv4Prefix,
        destination: FirewallIpv4Prefix,
        protocol: InputFirewallProtocol,
        action: InputFirewallAction,
    ) -> Self {
        Self {
            id,
            ingress,
            source,
            destination,
            protocol,
            action,
        }
    }

    #[must_use]
    pub const fn id(self) -> FirewallRuleId {
        self.id
    }

    #[must_use]
    pub const fn ingress(self) -> FirewallInterface {
        self.ingress
    }

    #[must_use]
    pub const fn source(self) -> FirewallIpv4Prefix {
        self.source
    }

    #[must_use]
    pub const fn destination(self) -> FirewallIpv4Prefix {
        self.destination
    }

    #[must_use]
    pub const fn protocol(self) -> InputFirewallProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn action(self) -> InputFirewallAction {
        self.action
    }

    fn matches(self, packet: &InputFirewallPacket) -> bool {
        if !(self.ingress.matches(packet.ingress)
            && self.source.matches(packet.source)
            && self.destination.matches(packet.destination))
        {
            return false;
        }
        let transport = match (self.protocol, packet.protocol) {
            (InputFirewallProtocol::Any, _) => return true,
            (InputFirewallProtocol::Icmp { .. }, 1)
            | (InputFirewallProtocol::Tcp { .. }, 6)
            | (InputFirewallProtocol::Udp { .. }, 17) => packet.transport,
            _ => return false,
        };
        if !self.protocol.needs_transport() {
            return true;
        }
        let Some(value) = transport else {
            // Fail closed: an unknown transport header matches a rule that
            // needs it only when the rule denies.
            return self.action == InputFirewallAction::Deny;
        };
        match self.protocol {
            InputFirewallProtocol::Icmp { icmp_type } => icmp_type == Some(value as u8),
            InputFirewallProtocol::Tcp { destination_ports }
            | InputFirewallProtocol::Udp { destination_ports } => destination_ports.contains(value),
            InputFirewallProtocol::Any => true,
        }
    }
}

/// The configuration errors of an input policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InputFirewallError {
    RuleIdZero,
    DuplicateRuleId,
    IngressInterfaceMissing,
}

/// Rule identity and interface checks, in slice order; within a rule zero
/// id, duplicate id, then a missing ingress interface. `interface_known`
/// says whether an interface id is configured.
pub(crate) fn check_input_firewall_rules(
    rules: &[InputFirewallRule],
    interface_known: impl Fn(IfId) -> bool,
) -> Result<(), InputFirewallError> {
    for (index, rule) in rules.iter().enumerate() {
        if rule.id.0 == 0 {
            return Err(InputFirewallError::RuleIdZero);
        }
        if rules[..index]
            .iter()
            .any(|candidate| candidate.id == rule.id)
        {
            return Err(InputFirewallError::DuplicateRuleId);
        }
        if let FirewallInterface::Interface(interface) = rule.ingress {
            if !interface_known(interface) {
                return Err(InputFirewallError::IngressInterfaceMissing);
            }
        }
    }
    Ok(())
}

/// Validates input rule identity and interface references against
/// `snapshot` (the control-plane seam, like
/// [`super::validate_firewall_rules`]).
pub fn validate_input_firewall_rules(
    snapshot: &crate::ForwardingSnapshot<'_>,
    rules: &[InputFirewallRule],
) -> Result<(), InputFirewallError> {
    check_input_firewall_rules(rules, |interface| snapshot.interface(interface).is_some())
}

/// The facts of one locally addressed datagram the input policy reads.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InputFirewallPacket {
    pub(crate) ingress: IfId,
    pub(crate) source: Ipv4Address,
    pub(crate) destination: Ipv4Address,
    pub(crate) protocol: u8,
    /// The ICMP type (ICMP) or the destination port (TCP, UDP); `None`
    /// when the header cannot be read (a later fragment, a truncated
    /// datagram, a short transport header) or for another protocol.
    pub(crate) transport: Option<u16>,
}

/// The verdict of the input policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InputFirewallVerdict {
    Accept,
    DeniedByRule(FirewallRuleId),
    DeniedByDefault,
}

/// First match over `rules`, else `default`. At most `rules.len()` (4096
/// after config validation) rule tests, no allocation.
#[inline]
pub(crate) fn evaluate_input_firewall(
    rules: &[InputFirewallRule],
    default: InputFirewallAction,
    packet: &InputFirewallPacket,
) -> InputFirewallVerdict {
    for rule in rules {
        if rule.matches(packet) {
            return match rule.action {
                InputFirewallAction::Accept => InputFirewallVerdict::Accept,
                InputFirewallAction::Deny => InputFirewallVerdict::DeniedByRule(rule.id),
            };
        }
    }
    match default {
        InputFirewallAction::Accept => InputFirewallVerdict::Accept,
        InputFirewallAction::Deny => InputFirewallVerdict::DeniedByDefault,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAN: IfId = IfId(1);
    const WAN: IfId = IfId(2);

    fn prefix(octets: [u8; 4], len: u8) -> FirewallIpv4Prefix {
        FirewallIpv4Prefix::new(Ipv4Address::from_octets(octets), len).unwrap()
    }

    fn any() -> FirewallIpv4Prefix {
        prefix([0; 4], 0)
    }

    fn rule(
        id: u32,
        ingress: FirewallInterface,
        source: FirewallIpv4Prefix,
        protocol: InputFirewallProtocol,
        action: InputFirewallAction,
    ) -> InputFirewallRule {
        InputFirewallRule::new(FirewallRuleId(id), ingress, source, any(), protocol, action)
    }

    fn packet(
        ingress: IfId,
        source: [u8; 4],
        protocol: u8,
        transport: Option<u16>,
    ) -> InputFirewallPacket {
        InputFirewallPacket {
            ingress,
            source: Ipv4Address::from_octets(source),
            destination: Ipv4Address::from_octets([203, 0, 113, 2]),
            protocol,
            transport,
        }
    }

    #[test]
    fn first_match_then_default() {
        let echo = InputFirewallProtocol::Icmp { icmp_type: Some(8) };
        let rules = [
            rule(
                1,
                FirewallInterface::Interface(WAN),
                prefix([198, 51, 100, 0], 24),
                echo,
                InputFirewallAction::Accept,
            ),
            rule(
                2,
                FirewallInterface::Interface(LAN),
                any(),
                InputFirewallProtocol::Any,
                InputFirewallAction::Accept,
            ),
        ];
        let deny = InputFirewallAction::Deny;
        let check = |packet| evaluate_input_firewall(&rules, deny, &packet);
        assert_eq!(
            check(packet(WAN, [198, 51, 100, 7], 1, Some(8))),
            InputFirewallVerdict::Accept
        );
        // Another type, another source, another protocol: the default.
        for denied in [
            packet(WAN, [198, 51, 100, 7], 1, Some(13)),
            packet(WAN, [192, 0, 2, 7], 1, Some(8)),
            packet(WAN, [198, 51, 100, 7], 17, Some(8)),
            packet(WAN, [198, 51, 100, 7], 1, None),
        ] {
            assert_eq!(check(denied), InputFirewallVerdict::DeniedByDefault);
        }
        assert_eq!(
            check(packet(LAN, [192, 168, 1, 10], 47, None)),
            InputFirewallVerdict::Accept
        );
        assert_eq!(
            evaluate_input_firewall(
                &[],
                InputFirewallAction::Accept,
                &packet(WAN, [1; 4], 6, None)
            ),
            InputFirewallVerdict::Accept
        );
    }

    #[test]
    fn unknown_transport_matches_only_deny_rules() {
        let ports = FirewallPortRange::new(53, 53).unwrap();
        let udp53 = InputFirewallProtocol::Udp {
            destination_ports: ports,
        };
        let deny53 = [rule(
            7,
            FirewallInterface::Any,
            any(),
            udp53,
            InputFirewallAction::Deny,
        )];
        let accept53 = [rule(
            8,
            FirewallInterface::Any,
            any(),
            udp53,
            InputFirewallAction::Accept,
        )];
        let unknown = packet(WAN, [192, 0, 2, 1], 17, None);
        assert_eq!(
            evaluate_input_firewall(&deny53, InputFirewallAction::Accept, &unknown),
            InputFirewallVerdict::DeniedByRule(FirewallRuleId(7))
        );
        assert_eq!(
            evaluate_input_firewall(&accept53, InputFirewallAction::Deny, &unknown),
            InputFirewallVerdict::DeniedByDefault
        );
        // A full port range or an ICMP rule without a type needs no header.
        let all_udp = [rule(
            9,
            FirewallInterface::Any,
            any(),
            InputFirewallProtocol::Udp {
                destination_ports: FirewallPortRange::new(0, u16::MAX).unwrap(),
            },
            InputFirewallAction::Accept,
        )];
        assert_eq!(
            evaluate_input_firewall(&all_udp, InputFirewallAction::Deny, &unknown),
            InputFirewallVerdict::Accept
        );
        let all_icmp = [rule(
            10,
            FirewallInterface::Any,
            any(),
            InputFirewallProtocol::Icmp { icmp_type: None },
            InputFirewallAction::Accept,
        )];
        assert_eq!(
            evaluate_input_firewall(
                &all_icmp,
                InputFirewallAction::Deny,
                &packet(WAN, [192, 0, 2, 1], 1, None)
            ),
            InputFirewallVerdict::Accept
        );
        assert_eq!(
            evaluate_input_firewall(
                &deny53,
                InputFirewallAction::Accept,
                &packet(WAN, [192, 0, 2, 1], 17, Some(54))
            ),
            InputFirewallVerdict::Accept
        );
    }

    #[test]
    fn rule_checks_follow_the_forward_precedence() {
        let accept = |id| {
            rule(
                id,
                FirewallInterface::Interface(WAN),
                any(),
                InputFirewallProtocol::Any,
                InputFirewallAction::Accept,
            )
        };
        let known = |interface: IfId| interface == WAN;
        assert_eq!(
            check_input_firewall_rules(&[accept(1), accept(2)], known),
            Ok(())
        );
        assert_eq!(
            check_input_firewall_rules(&[accept(0)], known),
            Err(InputFirewallError::RuleIdZero)
        );
        assert_eq!(
            check_input_firewall_rules(&[accept(3), accept(3)], known),
            Err(InputFirewallError::DuplicateRuleId)
        );
        assert_eq!(
            check_input_firewall_rules(&[accept(3)], |_| false),
            Err(InputFirewallError::IngressInterfaceMissing)
        );
    }
}
