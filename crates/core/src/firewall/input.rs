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
//! The policy is stateless. The FE gives it no rules: traffic to the router
//! goes on to its kernel through the kernel's interface, where the forward
//! firewall judges it, and the sessions the kernel starts (BGP, SSH, DNS) and
//! their replies, with its flow state. Replies to NAT traffic go to the NAT
//! path.
//!
//! The rules reuse the forward rule language: the rule id, interface,
//! prefix, and port range types and their matchers. Selectors are the
//! ingress interface, source and destination prefixes, the IPv4 protocol,
//! and, for ICMP, the message type, or, for TCP and UDP, the destination
//! port. The default action is [`InputFirewallAction::Accept`], which is
//! the behavior without the table.
//!
//! A datagram whose transport header cannot be read (a fragment that is
//! not the first, or a datagram the link truncated) has no transport
//! selectors. A rule that needs one then matches only if it denies: an
//! `accept` rule for ICMP Echo never admits a datagram whose type is
//! unknown, and a `deny` rule for some port refuses it (fail closed).
//!
//! # Standards
//!
//! No standard defines the rules or their language.
//!
//! - RFC 1122 section 3.2.2: no ICMP message is sent about an ICMP error, so
//!   no state is needed to admit an answer to an error the router sent.
//! - RFC 1812 section 4.3.3.6: with the default (accept), Echo Requests are
//!   answered as without the table.
//!
//! Deviations: a denied datagram is dropped without Destination Unreachable
//! code 13 (RFC 1812 section 5.2.7.1), even when the operator turns code 13
//! on; that switch is used only by the forward firewall.

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
            && self.source.matches(packet.source.into())
            && self.destination.matches(packet.destination.into()))
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
    /// More than [`INPUT_FIREWALL_MAX_RULES`] rules.
    TooManyRules,
    RuleIdZero,
    DuplicateRuleId,
    IngressInterfaceMissing,
}

/// Most input rules one policy may hold (INPUT-FW). Any host that can
/// reach a router address makes the router walk them, so the bound is the
/// per-datagram worst case: 256 rule tests (about 1.5 µs at the measured
/// 6 ns per forward rule test) even before the per-ingress and
/// per-protocol split of the owner's index shortens the walk. An edge
/// input policy needs a handful of rules; 256 also allows one rule per
/// interface at the interface bound.
pub const INPUT_FIREWALL_MAX_RULES: usize = 256;

/// The rule count bound first, then rule identity and interface checks in
/// slice order; within a rule zero id, duplicate id, then a missing
/// ingress interface. `interface_known` says whether an interface id is
/// configured.
pub(crate) fn check_input_firewall_rules(
    rules: &[InputFirewallRule],
    interface_known: impl Fn(IfId) -> bool,
) -> Result<(), InputFirewallError> {
    if rules.len() > INPUT_FIREWALL_MAX_RULES {
        return Err(InputFirewallError::TooManyRules);
    }
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

/// First match over `rules`, else `default`, and the number of rule tests.
/// With `index` (owner snapshots) only the rules that can match the
/// datagram's ingress and protocol class are tested, in their original
/// order, so the verdict is the linear one; without it (snapshots borrowed
/// directly, tests and benches) every rule. At most
/// [`INPUT_FIREWALL_MAX_RULES`] tests, no allocation.
#[inline]
pub(crate) fn evaluate_input_firewall(
    rules: &[InputFirewallRule],
    index: Option<&InputFirewallIndex>,
    default: InputFirewallAction,
    packet: &InputFirewallPacket,
) -> (InputFirewallVerdict, u64) {
    let mut tests = 0_u64;
    let verdict = |rule: &InputFirewallRule| match rule.action {
        InputFirewallAction::Accept => InputFirewallVerdict::Accept,
        InputFirewallAction::Deny => InputFirewallVerdict::DeniedByRule(rule.id),
    };
    match index {
        Some(index) => {
            for &slot in index.candidates(packet.ingress, packet.protocol) {
                let rule = &rules[usize::from(slot)];
                tests += 1;
                if rule.matches(packet) {
                    return (verdict(rule), tests);
                }
            }
        }
        None => {
            for rule in rules {
                tests += 1;
                if rule.matches(packet) {
                    return (verdict(rule), tests);
                }
            }
        }
    }
    let verdict = match default {
        InputFirewallAction::Accept => InputFirewallVerdict::Accept,
        InputFirewallAction::Deny => InputFirewallVerdict::DeniedByDefault,
    };
    (verdict, tests)
}

/// The protocol class of an IPv4 protocol number in the index.
const fn protocol_class(protocol: u8) -> usize {
    match protocol {
        1 => 0,
        6 => 1,
        17 => 2,
        _ => 3,
    }
}

const PROTOCOL_CLASSES: usize = 4;

/// Publication-time split of the input rules by ingress interface and
/// protocol class (ICMP, TCP, UDP, other), each list in first-match order
/// (sec M1 of #353). A rule without an ingress selector is in the lists
/// of every interface, and a rule without a protocol in every class, at its
/// original position, so walking one list gives the linear verdict.
/// Interfaces no rule names share one set of lists. Snapshot memory, not
/// runtime storage: at most about 130 KiB for 256 rules (128 rules for any
/// interface and protocol, 128 naming distinct interfaces), freed with the
/// owner.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct InputFirewallIndex {
    /// Rule slots (indexes into the rules), list after list.
    entries: Box<[u16]>,
    /// `(interface id, list bounds)` sorted by id, for every interface a
    /// rule names: class `c` is `entries[bounds[c]..bounds[c + 1]]`.
    interfaces: Box<[(u16, [u32; PROTOCOL_CLASSES + 1])]>,
    /// The lists of every other interface (rules without an ingress).
    shared: [u32; PROTOCOL_CLASSES + 1],
}

impl InputFirewallIndex {
    /// Builds the lists of `rules` (validated: at most
    /// [`INPUT_FIREWALL_MAX_RULES`]). Cold, O(interfaces x rules).
    pub(crate) fn build(rules: &[InputFirewallRule]) -> Self {
        debug_assert!(rules.len() <= INPUT_FIREWALL_MAX_RULES);
        let in_class = |rule: &InputFirewallRule, class: usize| match rule.protocol {
            InputFirewallProtocol::Any => true,
            InputFirewallProtocol::Icmp { .. } => class == 0,
            InputFirewallProtocol::Tcp { .. } => class == 1,
            InputFirewallProtocol::Udp { .. } => class == 2,
        };
        let mut entries = Vec::new();
        let lists = |ingress: Option<IfId>, entries: &mut Vec<u16>| {
            let mut bounds = [0_u32; PROTOCOL_CLASSES + 1];
            for (class, bound) in bounds.iter_mut().take(PROTOCOL_CLASSES).enumerate() {
                *bound = entries.len() as u32;
                for (slot, rule) in rules.iter().enumerate() {
                    let ingress_matches = match (rule.ingress, ingress) {
                        (FirewallInterface::Any, _) => true,
                        (FirewallInterface::Interface(named), Some(id)) => named == id,
                        (FirewallInterface::Interface(_), None) => false,
                    };
                    if ingress_matches && in_class(rule, class) {
                        entries.push(slot as u16);
                    }
                }
            }
            bounds[PROTOCOL_CLASSES] = entries.len() as u32;
            bounds
        };
        let shared = lists(None, &mut entries);
        let mut named: Vec<IfId> = rules
            .iter()
            .filter_map(|rule| match rule.ingress {
                FirewallInterface::Interface(id) => Some(id),
                FirewallInterface::Any => None,
            })
            .collect();
        named.sort_unstable();
        named.dedup();
        let interfaces = named
            .into_iter()
            .map(|id| (id.0, lists(Some(id), &mut entries)))
            .collect();
        Self {
            entries: entries.into_boxed_slice(),
            interfaces,
            shared,
        }
    }

    /// The rule slots that can match a datagram from `ingress` with
    /// `protocol`, in first-match order (binary search over the named
    /// interfaces, at most 256).
    #[inline]
    pub(crate) fn candidates(&self, ingress: IfId, protocol: u8) -> &[u16] {
        let bounds = match self
            .interfaces
            .binary_search_by_key(&ingress.0, |(id, _)| *id)
        {
            Ok(position) => &self.interfaces[position].1,
            Err(_) => &self.shared,
        };
        let class = protocol_class(protocol);
        &self.entries[bounds[class] as usize..bounds[class + 1] as usize]
    }

    /// Heap bytes of the lists (snapshot memory).
    pub(crate) fn heap_bytes(&self) -> usize {
        std::mem::size_of_val(&*self.entries) + std::mem::size_of_val(&*self.interfaces)
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

    /// The linear verdict, checked against the indexed one.
    fn eval(
        rules: &[InputFirewallRule],
        default: InputFirewallAction,
        packet: &InputFirewallPacket,
    ) -> InputFirewallVerdict {
        let (linear, _) = evaluate_input_firewall(rules, None, default, packet);
        let index = InputFirewallIndex::build(rules);
        let (indexed, _) = evaluate_input_firewall(rules, Some(&index), default, packet);
        assert_eq!(linear, indexed, "{packet:?}");
        linear
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
        let check = |packet| eval(&rules, deny, &packet);
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
            eval(
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
            eval(&deny53, InputFirewallAction::Accept, &unknown),
            InputFirewallVerdict::DeniedByRule(FirewallRuleId(7))
        );
        assert_eq!(
            eval(&accept53, InputFirewallAction::Deny, &unknown),
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
            eval(&all_udp, InputFirewallAction::Deny, &unknown),
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
            eval(
                &all_icmp,
                InputFirewallAction::Deny,
                &packet(WAN, [192, 0, 2, 1], 1, None)
            ),
            InputFirewallVerdict::Accept
        );
        assert_eq!(
            eval(
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

    /// sec M1 of #353: the per-ingress, per-protocol lists give the linear
    /// first-match verdict on random rule sets, and a datagram only tests
    /// the rules of its own ingress and protocol class.
    #[test]
    fn indexed_walk_matches_the_linear_reference() {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move |bound: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % bound
        };
        let interfaces = [IfId(1), IfId(2), IfId(3), IfId(9)];
        for round in 0..200 {
            let count = next(24) as usize;
            let rules: Vec<InputFirewallRule> = (0..count)
                .map(|slot| {
                    let ingress = match next(3) {
                        0 => FirewallInterface::Any,
                        _ => FirewallInterface::Interface(interfaces[next(3) as usize]),
                    };
                    let source = match next(3) {
                        0 => any(),
                        1 => prefix([10, 0, 0, 0], 8),
                        _ => prefix([192, 0, 2, 0], 24),
                    };
                    let ports = FirewallPortRange::new(50, 60).unwrap();
                    let protocol = match next(5) {
                        0 => InputFirewallProtocol::Any,
                        1 => InputFirewallProtocol::Icmp {
                            icmp_type: [None, Some(8), Some(13)][next(3) as usize],
                        },
                        2 => InputFirewallProtocol::Tcp {
                            destination_ports: ports,
                        },
                        _ => InputFirewallProtocol::Udp {
                            destination_ports: ports,
                        },
                    };
                    let action = if next(2) == 0 {
                        InputFirewallAction::Accept
                    } else {
                        InputFirewallAction::Deny
                    };
                    rule(slot as u32 + 1, ingress, source, protocol, action)
                })
                .collect();
            let index = InputFirewallIndex::build(&rules);
            for _ in 0..50 {
                let protocol = [1, 6, 17, 47][next(4) as usize];
                let transport = match next(4) {
                    0 => None,
                    1 => Some(8),
                    2 => Some(55),
                    _ => Some(13),
                };
                let source = [[10, 1, 2, 3], [192, 0, 2, 9], [198, 51, 100, 1]][next(3) as usize];
                let ingress = [IfId(1), IfId(2), IfId(3), IfId(9), IfId(4)][next(5) as usize];
                let probe = packet(ingress, source, protocol, transport);
                for default in [InputFirewallAction::Accept, InputFirewallAction::Deny] {
                    let (linear, all) = evaluate_input_firewall(&rules, None, default, &probe);
                    let (indexed, some) =
                        evaluate_input_firewall(&rules, Some(&index), default, &probe);
                    assert_eq!(linear, indexed, "round {round} {probe:?}");
                    assert!(some <= all);
                    let candidates = index.candidates(ingress, protocol);
                    assert!(candidates.windows(2).all(|pair| pair[0] < pair[1]));
                    assert!(candidates.iter().all(|&slot| {
                        let rule = rules[usize::from(slot)];
                        matches!(rule.ingress, FirewallInterface::Any)
                            || rule.ingress == FirewallInterface::Interface(ingress)
                    }));
                }
            }
        }
    }

    /// A WAN datagram walks only the WAN and any-ingress rules of its
    /// protocol class.
    #[test]
    fn a_datagram_tests_only_its_own_ingress_and_protocol() {
        let mut rules = Vec::new();
        for id in 1..=200 {
            rules.push(rule(
                id,
                FirewallInterface::Interface(LAN),
                any(),
                InputFirewallProtocol::Any,
                InputFirewallAction::Accept,
            ));
        }
        rules.push(rule(
            300,
            FirewallInterface::Interface(WAN),
            prefix([198, 51, 100, 0], 24),
            InputFirewallProtocol::Icmp { icmp_type: Some(8) },
            InputFirewallAction::Accept,
        ));
        let index = InputFirewallIndex::build(&rules);
        let probe = packet(WAN, [192, 0, 2, 1], 17, Some(53));
        let (verdict, tests) =
            evaluate_input_firewall(&rules, Some(&index), InputFirewallAction::Deny, &probe);
        assert_eq!(verdict, InputFirewallVerdict::DeniedByDefault);
        assert_eq!(tests, 0, "no WAN UDP rule");
        let probe = packet(WAN, [192, 0, 2, 1], 1, Some(8));
        let (_, tests) =
            evaluate_input_firewall(&rules, Some(&index), InputFirewallAction::Deny, &probe);
        assert_eq!(tests, 1);
        let (_, linear) = evaluate_input_firewall(&rules, None, InputFirewallAction::Deny, &probe);
        assert_eq!(linear, 201);
        assert!(index.heap_bytes() > 0);
    }

    #[test]
    fn the_rule_count_is_bounded() {
        let rules: Vec<_> = (1..=INPUT_FIREWALL_MAX_RULES as u32 + 1)
            .map(|id| {
                rule(
                    id,
                    FirewallInterface::Any,
                    any(),
                    InputFirewallProtocol::Any,
                    InputFirewallAction::Deny,
                )
            })
            .collect();
        assert_eq!(
            check_input_firewall_rules(&rules, |_| true),
            Err(InputFirewallError::TooManyRules)
        );
        assert_eq!(
            check_input_firewall_rules(&rules[..INPUT_FIREWALL_MAX_RULES], |_| true),
            Ok(())
        );
    }
}
