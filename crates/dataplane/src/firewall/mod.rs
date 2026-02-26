//! Minimal stateful firewall engine.
//!
//! Evaluates packets against a rule chain (input/forward/output) with zone
//! and protocol matching. Works with the conntrack engine to allow return
//! traffic for established sessions (`allow_established_related`).
//!
//! The engine returns [`FwVerdict`] values; the caller is responsible for
//! acting on the verdict (drop the packet or continue processing).

use ruster_config::model::{
    Chain, ConnState, DefaultPolicy, FirewallConfig, FirewallRule, FirewallZone, RuleAction,
    RuleProto,
};

use crate::conntrack::session::SessionKey;
use crate::conntrack::ConntrackEngine;
use crate::packet::{L4Info, PacketMeta};

// ── Public types ────────────────────────────────────────────────────

/// Which chain to evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FwChain {
    Input,
    Forward,
    Output,
}

/// Firewall verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FwVerdict {
    /// Allow the packet.
    Accept,
    /// Drop the packet.
    Drop,
    /// Drop with the matched rule name (for logging).
    DropRule { rule_name: String },
    /// Accept with the matched rule name (for logging).
    AcceptRule { rule_name: String },
}

/// L4 protocol classification for firewall matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FwProto {
    Tcp,
    Udp,
    Icmp,
    Other,
}

/// Context for firewall evaluation (derived from packet + interface info).
pub struct FwContext {
    pub chain: FwChain,
    pub src_zone: FirewallZone,
    pub dst_zone: FirewallZone,
    pub proto: FwProto,
    pub is_established: bool,
    pub is_new: bool,
}

impl FwContext {
    /// Build a firewall context from a parsed packet, chain, interface zones,
    /// and the conntrack engine.
    ///
    /// The `is_new_session` flag indicates whether the conntrack pipeline
    /// stage just created a new session for this packet (true) or the
    /// packet matched an existing session (false). Untracked packets
    /// (non-IPv4, no L4) should pass `true`.
    ///
    /// This flag is necessary because the pipeline creates conntrack
    /// sessions *before* the firewall evaluation. Without it, a
    /// just-created session would appear "established" to the firewall.
    pub fn from_packet(
        meta: &PacketMeta,
        chain: FwChain,
        in_zone: FirewallZone,
        out_zone: FirewallZone,
        conntrack: &ConntrackEngine,
        is_new_session: bool,
    ) -> Self {
        // Extract L4 protocol.
        let proto = match &meta.l4 {
            Some(L4Info::Tcp(_)) => FwProto::Tcp,
            Some(L4Info::Udp(_)) => FwProto::Udp,
            Some(L4Info::Icmp(_)) => FwProto::Icmp,
            None => FwProto::Other,
        };

        // Determine connection state from conntrack.
        //
        // If the pipeline tells us this is a new session, the packet is
        // "new" for firewall purposes. Otherwise (existing or untracked
        // that matched reverse), it is "established".
        let (is_established, is_new) = if is_new_session {
            (false, true)
        } else {
            // Packet matched an existing session (forward or reverse).
            // Verify via conntrack lookup.
            match SessionKey::from_packet(meta) {
                Some(key) => {
                    let reverse_key = key.reverse();
                    let has_forward = conntrack.lookup(&key).is_some();
                    let has_reverse = conntrack.lookup(&reverse_key).is_some();
                    if has_forward || has_reverse {
                        (true, false)
                    } else {
                        // Should not happen if pipeline is correct, but
                        // treat as new as a safe fallback.
                        (false, true)
                    }
                }
                None => (false, true),
            }
        };

        Self {
            chain,
            src_zone: in_zone,
            dst_zone: out_zone,
            proto,
            is_established,
            is_new,
        }
    }
}

// ── FirewallEngine ──────────────────────────────────────────────────

/// The stateful firewall engine.
///
/// Holds the firewall configuration and provides the [`FirewallEngine::evaluate`] method
/// for per-packet verdict computation.
#[derive(Debug)]
pub struct FirewallEngine {
    enabled: bool,
    default_input: DefaultPolicy,
    default_forward: DefaultPolicy,
    default_output: DefaultPolicy,
    allow_established_related: bool,
    rules: Vec<FirewallRule>,
}

impl FirewallEngine {
    /// Build a firewall engine from the firewall configuration section.
    pub fn from_config(fw_config: &FirewallConfig) -> Self {
        Self {
            enabled: fw_config.enabled,
            default_input: fw_config.default_input,
            default_forward: fw_config.default_forward,
            default_output: fw_config.default_output,
            allow_established_related: fw_config.allow_established_related,
            rules: fw_config.rules.clone(),
        }
    }

    /// Evaluate a packet context against the firewall rules.
    ///
    /// The evaluation order is:
    /// 1. If the firewall is disabled, accept everything.
    /// 2. If `allow_established_related` is true and the packet belongs
    ///    to an established session, accept it.
    /// 3. Iterate rules in configuration order; the first matching rule
    ///    determines the verdict.
    /// 4. If no rule matches, fall through to the default policy for the
    ///    relevant chain.
    pub fn evaluate(&self, ctx: &FwContext) -> FwVerdict {
        // 1. Firewall disabled -> accept all.
        if !self.enabled {
            return FwVerdict::Accept;
        }

        // 2. Allow established/related if configured.
        if self.allow_established_related && ctx.is_established {
            return FwVerdict::Accept;
        }

        // 3. Iterate rules in order; first match wins.
        for rule in &self.rules {
            if self.rule_matches(rule, ctx) {
                return match rule.action {
                    RuleAction::Accept => FwVerdict::AcceptRule {
                        rule_name: rule.name.clone(),
                    },
                    RuleAction::Drop => FwVerdict::DropRule {
                        rule_name: rule.name.clone(),
                    },
                };
            }
        }

        // 4. Default policy for the chain.
        let policy = match ctx.chain {
            FwChain::Input => self.default_input,
            FwChain::Forward => self.default_forward,
            FwChain::Output => self.default_output,
        };

        match policy {
            DefaultPolicy::Accept => FwVerdict::Accept,
            DefaultPolicy::Drop => FwVerdict::Drop,
        }
    }

    /// Check whether a single rule matches the given context.
    fn rule_matches(&self, rule: &FirewallRule, ctx: &FwContext) -> bool {
        // Chain must match.
        if !chain_matches(rule.chain, ctx.chain) {
            return false;
        }

        // Source zone must match.
        if !zone_matches(rule.src_zone, ctx.src_zone) {
            return false;
        }

        // Destination zone must match.
        if !zone_matches(rule.dst_zone, ctx.dst_zone) {
            return false;
        }

        // Protocol must match.
        if !proto_matches(rule.proto, ctx.proto) {
            return false;
        }

        // State must match (if the rule specifies states).
        if !state_matches(&rule.state, ctx) {
            return false;
        }

        true
    }
}

// ── Match helpers ────────────────────────────────────────────────────

/// Check if a rule's chain matches the context chain.
fn chain_matches(rule_chain: Chain, ctx_chain: FwChain) -> bool {
    matches!(
        (rule_chain, ctx_chain),
        (Chain::Input, FwChain::Input)
            | (Chain::Forward, FwChain::Forward)
            | (Chain::Output, FwChain::Output)
    )
}

/// Check if a rule's zone matches the context zone.
///
/// `FirewallZone::Any` in the rule matches any context zone.
fn zone_matches(rule_zone: FirewallZone, ctx_zone: FirewallZone) -> bool {
    match rule_zone {
        FirewallZone::Any => true,
        FirewallZone::Wan => ctx_zone == FirewallZone::Wan,
        FirewallZone::Lan => ctx_zone == FirewallZone::Lan,
    }
}

/// Check if a rule's protocol matches the context protocol.
///
/// `RuleProto::Any` matches every protocol (including `FwProto::Other`).
fn proto_matches(rule_proto: RuleProto, ctx_proto: FwProto) -> bool {
    match rule_proto {
        RuleProto::Any => true,
        RuleProto::Tcp => ctx_proto == FwProto::Tcp,
        RuleProto::Udp => ctx_proto == FwProto::Udp,
        RuleProto::Icmp => ctx_proto == FwProto::Icmp,
    }
}

/// Check if a rule's state list matches the context.
///
/// If the rule has an empty state list, it matches unconditionally.
/// Otherwise, at least one of the rule's states must match the context.
fn state_matches(rule_states: &[ConnState], ctx: &FwContext) -> bool {
    if rule_states.is_empty() {
        return true;
    }

    for state in rule_states {
        match state {
            ConnState::New if ctx.is_new => return true,
            ConnState::Established if ctx.is_established => return true,
            ConnState::Related if ctx.is_established => return true, // simplified: related ~ established
            _ => {}
        }
    }

    false
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::session::{SessionKey, SessionProto, SessionState, TcpState};
    use crate::conntrack::{ConntrackConfig, ConntrackEngine};
    use crate::packet::{IcmpInfo, Ipv4Info, L2Info, L3Info, L4Info, PacketMeta, TcpInfo, UdpInfo};
    use ruster_config::model::{
        Chain, ConnState, DefaultPolicy, FirewallConfig, FirewallRule, FirewallZone, RuleAction,
        RuleProto,
    };

    // ── Helpers ──────────────────────────────────────────────────────

    fn default_fw_config() -> FirewallConfig {
        FirewallConfig {
            enabled: true,
            default_input: DefaultPolicy::Drop,
            default_forward: DefaultPolicy::Drop,
            default_output: DefaultPolicy::Accept,
            allow_established_related: true,
            rules: vec![],
        }
    }

    fn make_rule(
        name: &str,
        chain: Chain,
        action: RuleAction,
        proto: RuleProto,
        src_zone: FirewallZone,
        dst_zone: FirewallZone,
        state: Vec<ConnState>,
    ) -> FirewallRule {
        FirewallRule {
            name: name.to_string(),
            chain,
            action,
            proto,
            src_zone,
            dst_zone,
            state,
        }
    }

    fn make_ctx(
        chain: FwChain,
        src_zone: FirewallZone,
        dst_zone: FirewallZone,
        proto: FwProto,
        is_established: bool,
        is_new: bool,
    ) -> FwContext {
        FwContext {
            chain,
            src_zone,
            dst_zone,
            proto,
            is_established,
            is_new,
        }
    }

    fn make_conntrack() -> ConntrackEngine {
        ConntrackEngine::new(ConntrackConfig {
            max_sessions: 1000,
            tcp_established_timeout_sec: 7200,
            tcp_transitory_timeout_sec: 120,
            udp_timeout_sec: 300,
            icmp_timeout_sec: 30,
        })
    }

    fn make_l2() -> L2Info {
        L2Info {
            dst_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            ethertype: 0x0800,
        }
    }

    fn make_ipv4(src: [u8; 4], dst: [u8; 4], protocol: u8) -> Ipv4Info {
        Ipv4Info {
            src_addr: src,
            dst_addr: dst,
            ttl: 64,
            protocol,
            header_len: 20,
            total_len: 40,
            identification: 1,
            flags: 0x40,
            fragment_offset: 0,
            checksum: 0,
            payload_offset: 34,
        }
    }

    fn make_tcp_meta(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> PacketMeta {
        PacketMeta {
            in_ifname: "eth0".to_string(),
            l2: make_l2(),
            l3: Some(L3Info::Ipv4(make_ipv4(src, dst, 6))),
            l4: Some(L4Info::Tcp(TcpInfo {
                src_port,
                dst_port,
                seq_num: 1000,
                ack_num: 0,
                data_offset: 5,
                flags: 0x02,
                window: 65535,
                checksum: 0,
            })),
            raw_len: 54,
        }
    }

    fn make_udp_meta(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> PacketMeta {
        PacketMeta {
            in_ifname: "eth0".to_string(),
            l2: make_l2(),
            l3: Some(L3Info::Ipv4(make_ipv4(src, dst, 17))),
            l4: Some(L4Info::Udp(UdpInfo {
                src_port,
                dst_port,
                length: 8,
                checksum: 0,
            })),
            raw_len: 42,
        }
    }

    fn make_icmp_meta(src: [u8; 4], dst: [u8; 4]) -> PacketMeta {
        PacketMeta {
            in_ifname: "eth0".to_string(),
            l2: make_l2(),
            l3: Some(L3Info::Ipv4(make_ipv4(src, dst, 1))),
            l4: Some(L4Info::Icmp(IcmpInfo {
                icmp_type: 8,
                icmp_code: 0,
                checksum: 0,
                rest_of_header: [0x12, 0x34, 0x00, 0x01],
            })),
            raw_len: 42,
        }
    }

    fn make_non_ipv4_meta() -> PacketMeta {
        PacketMeta {
            in_ifname: "eth0".to_string(),
            l2: L2Info {
                dst_mac: [0xFF; 6],
                src_mac: [0xAA; 6],
                ethertype: 0x0806,
            },
            l3: None,
            l4: None,
            raw_len: 42,
        }
    }

    // ── Test: Disabled firewall accepts everything ───────────────────

    #[test]
    fn disabled_firewall_accepts_all() {
        let mut config = default_fw_config();
        config.enabled = false;
        let engine = FirewallEngine::from_config(&config);

        let ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Wan,
            FirewallZone::Lan,
            FwProto::Tcp,
            false,
            true,
        );

        assert_eq!(engine.evaluate(&ctx), FwVerdict::Accept);
    }

    // ── Test: allow_established_related ──────────────────────────────

    #[test]
    fn established_session_accepted_with_allow_established() {
        let config = default_fw_config(); // allow_established_related = true
        let engine = FirewallEngine::from_config(&config);

        // Established session on forward chain (default_forward = drop).
        let ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Wan,
            FirewallZone::Lan,
            FwProto::Tcp,
            true,  // is_established
            false, // is_new
        );

        assert_eq!(engine.evaluate(&ctx), FwVerdict::Accept);
    }

    #[test]
    fn new_session_falls_through_to_rules_with_allow_established() {
        let mut config = default_fw_config();
        config.rules = vec![make_rule(
            "deny-wan-to-lan",
            Chain::Forward,
            RuleAction::Drop,
            RuleProto::Any,
            FirewallZone::Wan,
            FirewallZone::Lan,
            vec![ConnState::New],
        )];
        let engine = FirewallEngine::from_config(&config);

        // New session from WAN to LAN on forward chain.
        let ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Wan,
            FirewallZone::Lan,
            FwProto::Tcp,
            false, // not established
            true,  // is new
        );

        assert_eq!(
            engine.evaluate(&ctx),
            FwVerdict::DropRule {
                rule_name: "deny-wan-to-lan".to_string()
            }
        );
    }

    #[test]
    fn allow_established_disabled_does_not_auto_accept() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        // default_forward = drop, no rules
        let engine = FirewallEngine::from_config(&config);

        // Even an established session should fall through to default policy.
        let ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Wan,
            FirewallZone::Lan,
            FwProto::Tcp,
            true,
            false,
        );

        assert_eq!(engine.evaluate(&ctx), FwVerdict::Drop);
    }

    // ── Test: Chain matching ─────────────────────────────────────────

    #[test]
    fn input_rule_does_not_match_forward_traffic() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        config.rules = vec![make_rule(
            "allow-input",
            Chain::Input,
            RuleAction::Accept,
            RuleProto::Any,
            FirewallZone::Any,
            FirewallZone::Any,
            vec![],
        )];
        let engine = FirewallEngine::from_config(&config);

        // Forward traffic should not match the input rule.
        let ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Lan,
            FirewallZone::Wan,
            FwProto::Tcp,
            false,
            true,
        );

        // Should fall through to default_forward = drop.
        assert_eq!(engine.evaluate(&ctx), FwVerdict::Drop);
    }

    #[test]
    fn forward_rule_does_not_match_input_traffic() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        config.rules = vec![make_rule(
            "allow-forward",
            Chain::Forward,
            RuleAction::Accept,
            RuleProto::Any,
            FirewallZone::Any,
            FirewallZone::Any,
            vec![],
        )];
        let engine = FirewallEngine::from_config(&config);

        // Input traffic should not match the forward rule.
        let ctx = make_ctx(
            FwChain::Input,
            FirewallZone::Lan,
            FirewallZone::Any,
            FwProto::Tcp,
            false,
            true,
        );

        // Should fall through to default_input = drop.
        assert_eq!(engine.evaluate(&ctx), FwVerdict::Drop);
    }

    // ── Test: Zone matching ──────────────────────────────────────────

    #[test]
    fn wan_to_lan_rule_matches_wan_to_lan_traffic() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        config.rules = vec![make_rule(
            "block-wan-lan",
            Chain::Forward,
            RuleAction::Drop,
            RuleProto::Any,
            FirewallZone::Wan,
            FirewallZone::Lan,
            vec![],
        )];
        let engine = FirewallEngine::from_config(&config);

        let ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Wan,
            FirewallZone::Lan,
            FwProto::Tcp,
            false,
            true,
        );

        assert_eq!(
            engine.evaluate(&ctx),
            FwVerdict::DropRule {
                rule_name: "block-wan-lan".to_string()
            }
        );
    }

    #[test]
    fn wan_to_wan_rule_does_not_match_wan_to_lan_traffic() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        config.rules = vec![make_rule(
            "allow-wan-wan",
            Chain::Forward,
            RuleAction::Accept,
            RuleProto::Any,
            FirewallZone::Wan,
            FirewallZone::Wan,
            vec![],
        )];
        let engine = FirewallEngine::from_config(&config);

        // Traffic is WAN -> LAN, but rule is WAN -> WAN.
        let ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Wan,
            FirewallZone::Lan,
            FwProto::Tcp,
            false,
            true,
        );

        // Should fall through to default_forward = drop.
        assert_eq!(engine.evaluate(&ctx), FwVerdict::Drop);
    }

    #[test]
    fn any_zone_matches_both_wan_and_lan() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        config.rules = vec![make_rule(
            "allow-any-any",
            Chain::Forward,
            RuleAction::Accept,
            RuleProto::Any,
            FirewallZone::Any,
            FirewallZone::Any,
            vec![],
        )];
        let engine = FirewallEngine::from_config(&config);

        // WAN -> LAN traffic should match.
        let ctx1 = make_ctx(
            FwChain::Forward,
            FirewallZone::Wan,
            FirewallZone::Lan,
            FwProto::Tcp,
            false,
            true,
        );
        assert_eq!(
            engine.evaluate(&ctx1),
            FwVerdict::AcceptRule {
                rule_name: "allow-any-any".to_string()
            }
        );

        // LAN -> WAN traffic should also match.
        let ctx2 = make_ctx(
            FwChain::Forward,
            FirewallZone::Lan,
            FirewallZone::Wan,
            FwProto::Udp,
            false,
            true,
        );
        assert_eq!(
            engine.evaluate(&ctx2),
            FwVerdict::AcceptRule {
                rule_name: "allow-any-any".to_string()
            }
        );
    }

    // ── Test: Protocol matching ──────────────────────────────────────

    #[test]
    fn tcp_rule_matches_tcp_not_udp() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        config.rules = vec![make_rule(
            "allow-tcp",
            Chain::Forward,
            RuleAction::Accept,
            RuleProto::Tcp,
            FirewallZone::Any,
            FirewallZone::Any,
            vec![],
        )];
        let engine = FirewallEngine::from_config(&config);

        // TCP should match.
        let tcp_ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Lan,
            FirewallZone::Wan,
            FwProto::Tcp,
            false,
            true,
        );
        assert_eq!(
            engine.evaluate(&tcp_ctx),
            FwVerdict::AcceptRule {
                rule_name: "allow-tcp".to_string()
            }
        );

        // UDP should not match -> default drop.
        let udp_ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Lan,
            FirewallZone::Wan,
            FwProto::Udp,
            false,
            true,
        );
        assert_eq!(engine.evaluate(&udp_ctx), FwVerdict::Drop);
    }

    #[test]
    fn any_proto_rule_matches_all_protocols() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        config.rules = vec![make_rule(
            "allow-all-proto",
            Chain::Forward,
            RuleAction::Accept,
            RuleProto::Any,
            FirewallZone::Any,
            FirewallZone::Any,
            vec![],
        )];
        let engine = FirewallEngine::from_config(&config);

        for proto in &[FwProto::Tcp, FwProto::Udp, FwProto::Icmp, FwProto::Other] {
            let ctx = make_ctx(
                FwChain::Forward,
                FirewallZone::Lan,
                FirewallZone::Wan,
                *proto,
                false,
                true,
            );
            assert_eq!(
                engine.evaluate(&ctx),
                FwVerdict::AcceptRule {
                    rule_name: "allow-all-proto".to_string()
                }
            );
        }
    }

    // ── Test: State matching ─────────────────────────────────────────

    #[test]
    fn rule_with_new_state_matches_new_not_established() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        config.rules = vec![make_rule(
            "allow-new",
            Chain::Forward,
            RuleAction::Accept,
            RuleProto::Any,
            FirewallZone::Any,
            FirewallZone::Any,
            vec![ConnState::New],
        )];
        let engine = FirewallEngine::from_config(&config);

        // New connection should match.
        let new_ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Lan,
            FirewallZone::Wan,
            FwProto::Tcp,
            false,
            true,
        );
        assert_eq!(
            engine.evaluate(&new_ctx),
            FwVerdict::AcceptRule {
                rule_name: "allow-new".to_string()
            }
        );

        // Established connection should not match -> default drop.
        let est_ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Lan,
            FirewallZone::Wan,
            FwProto::Tcp,
            true,
            false,
        );
        assert_eq!(engine.evaluate(&est_ctx), FwVerdict::Drop);
    }

    #[test]
    fn rule_with_established_state_matches_established() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        config.rules = vec![make_rule(
            "allow-est",
            Chain::Forward,
            RuleAction::Accept,
            RuleProto::Any,
            FirewallZone::Any,
            FirewallZone::Any,
            vec![ConnState::Established],
        )];
        let engine = FirewallEngine::from_config(&config);

        let est_ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Lan,
            FirewallZone::Wan,
            FwProto::Tcp,
            true,
            false,
        );
        assert_eq!(
            engine.evaluate(&est_ctx),
            FwVerdict::AcceptRule {
                rule_name: "allow-est".to_string()
            }
        );
    }

    #[test]
    fn rule_with_empty_state_matches_unconditionally() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        config.rules = vec![make_rule(
            "allow-any-state",
            Chain::Forward,
            RuleAction::Accept,
            RuleProto::Any,
            FirewallZone::Any,
            FirewallZone::Any,
            vec![], // empty state list
        )];
        let engine = FirewallEngine::from_config(&config);

        // Both new and established should match.
        let new_ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Lan,
            FirewallZone::Wan,
            FwProto::Tcp,
            false,
            true,
        );
        assert_eq!(
            engine.evaluate(&new_ctx),
            FwVerdict::AcceptRule {
                rule_name: "allow-any-state".to_string()
            }
        );

        let est_ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Lan,
            FirewallZone::Wan,
            FwProto::Tcp,
            true,
            false,
        );
        assert_eq!(
            engine.evaluate(&est_ctx),
            FwVerdict::AcceptRule {
                rule_name: "allow-any-state".to_string()
            }
        );
    }

    // ── Test: Default policy ─────────────────────────────────────────

    #[test]
    fn default_drop_with_no_matching_rules() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        // default_forward = drop, no rules
        let engine = FirewallEngine::from_config(&config);

        let ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Lan,
            FirewallZone::Wan,
            FwProto::Tcp,
            false,
            true,
        );

        assert_eq!(engine.evaluate(&ctx), FwVerdict::Drop);
    }

    #[test]
    fn default_accept_with_no_matching_rules() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        // default_output = accept, no rules
        let engine = FirewallEngine::from_config(&config);

        let ctx = make_ctx(
            FwChain::Output,
            FirewallZone::Any,
            FirewallZone::Any,
            FwProto::Tcp,
            false,
            true,
        );

        assert_eq!(engine.evaluate(&ctx), FwVerdict::Accept);
    }

    #[test]
    fn default_input_policy_applied_for_input_chain() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        config.default_input = DefaultPolicy::Accept;
        let engine = FirewallEngine::from_config(&config);

        let ctx = make_ctx(
            FwChain::Input,
            FirewallZone::Lan,
            FirewallZone::Any,
            FwProto::Tcp,
            false,
            true,
        );

        assert_eq!(engine.evaluate(&ctx), FwVerdict::Accept);
    }

    // ── Test: Rule evaluation order (first match wins) ───────────────

    #[test]
    fn first_match_wins() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        config.rules = vec![
            make_rule(
                "drop-first",
                Chain::Forward,
                RuleAction::Drop,
                RuleProto::Any,
                FirewallZone::Any,
                FirewallZone::Any,
                vec![],
            ),
            make_rule(
                "accept-second",
                Chain::Forward,
                RuleAction::Accept,
                RuleProto::Any,
                FirewallZone::Any,
                FirewallZone::Any,
                vec![],
            ),
        ];
        let engine = FirewallEngine::from_config(&config);

        let ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Lan,
            FirewallZone::Wan,
            FwProto::Tcp,
            false,
            true,
        );

        // First rule (drop) should win over the second (accept).
        assert_eq!(
            engine.evaluate(&ctx),
            FwVerdict::DropRule {
                rule_name: "drop-first".to_string()
            }
        );
    }

    // ── Test: Full scenario (router.toml.example-like) ───────────────

    #[test]
    fn full_scenario_router_toml_example() {
        // Mimic router.toml.example:
        // - allow_established_related = true
        // - default_forward = drop
        // - allow lan->wan new/established/related
        // - allow lan input ICMP new
        let config = FirewallConfig {
            enabled: true,
            default_input: DefaultPolicy::Drop,
            default_forward: DefaultPolicy::Drop,
            default_output: DefaultPolicy::Accept,
            allow_established_related: true,
            rules: vec![
                make_rule(
                    "allow-lan-to-wan",
                    Chain::Forward,
                    RuleAction::Accept,
                    RuleProto::Any,
                    FirewallZone::Lan,
                    FirewallZone::Wan,
                    vec![ConnState::New, ConnState::Established, ConnState::Related],
                ),
                make_rule(
                    "allow-lan-input-icmp",
                    Chain::Input,
                    RuleAction::Accept,
                    RuleProto::Icmp,
                    FirewallZone::Lan,
                    FirewallZone::Any,
                    vec![ConnState::New],
                ),
            ],
        };
        let engine = FirewallEngine::from_config(&config);

        // 1. New LAN -> WAN forward should be accepted.
        let lan_wan_new = make_ctx(
            FwChain::Forward,
            FirewallZone::Lan,
            FirewallZone::Wan,
            FwProto::Tcp,
            false,
            true,
        );
        assert_eq!(
            engine.evaluate(&lan_wan_new),
            FwVerdict::AcceptRule {
                rule_name: "allow-lan-to-wan".to_string()
            }
        );

        // 2. Established WAN -> LAN (return traffic) should be accepted
        //    by allow_established_related.
        let wan_lan_est = make_ctx(
            FwChain::Forward,
            FirewallZone::Wan,
            FirewallZone::Lan,
            FwProto::Tcp,
            true,
            false,
        );
        assert_eq!(engine.evaluate(&wan_lan_est), FwVerdict::Accept);

        // 3. New WAN -> LAN forward should be dropped (no matching rule).
        let wan_lan_new = make_ctx(
            FwChain::Forward,
            FirewallZone::Wan,
            FirewallZone::Lan,
            FwProto::Tcp,
            false,
            true,
        );
        assert_eq!(engine.evaluate(&wan_lan_new), FwVerdict::Drop);

        // 4. New ICMP from LAN to input should be accepted.
        let lan_input_icmp = make_ctx(
            FwChain::Input,
            FirewallZone::Lan,
            FirewallZone::Any,
            FwProto::Icmp,
            false,
            true,
        );
        assert_eq!(
            engine.evaluate(&lan_input_icmp),
            FwVerdict::AcceptRule {
                rule_name: "allow-lan-input-icmp".to_string()
            }
        );

        // 5. New TCP from WAN to input should be dropped.
        let wan_input_tcp = make_ctx(
            FwChain::Input,
            FirewallZone::Wan,
            FirewallZone::Any,
            FwProto::Tcp,
            false,
            true,
        );
        assert_eq!(engine.evaluate(&wan_input_tcp), FwVerdict::Drop);

        // 6. Output should be accepted (default_output = accept).
        let output = make_ctx(
            FwChain::Output,
            FirewallZone::Any,
            FirewallZone::Any,
            FwProto::Tcp,
            false,
            true,
        );
        assert_eq!(engine.evaluate(&output), FwVerdict::Accept);
    }

    // ── Test: FwContext::from_packet ─────────────────────────────────

    #[test]
    fn fw_context_from_tcp_packet() {
        let conntrack = make_conntrack();
        let meta = make_tcp_meta([192, 168, 1, 100], [10, 0, 0, 1], 49152, 80);

        let ctx = FwContext::from_packet(
            &meta,
            FwChain::Forward,
            FirewallZone::Lan,
            FirewallZone::Wan,
            &conntrack,
            true, // new session
        );

        assert_eq!(ctx.chain, FwChain::Forward);
        assert_eq!(ctx.src_zone, FirewallZone::Lan);
        assert_eq!(ctx.dst_zone, FirewallZone::Wan);
        assert_eq!(ctx.proto, FwProto::Tcp);
        assert!(ctx.is_new);
        assert!(!ctx.is_established);
    }

    #[test]
    fn fw_context_from_udp_packet() {
        let conntrack = make_conntrack();
        let meta = make_udp_meta([10, 0, 0, 5], [10, 0, 0, 1], 12345, 53);

        let ctx = FwContext::from_packet(
            &meta,
            FwChain::Input,
            FirewallZone::Wan,
            FirewallZone::Any,
            &conntrack,
            true, // new session
        );

        assert_eq!(ctx.proto, FwProto::Udp);
        assert!(ctx.is_new);
        assert!(!ctx.is_established);
    }

    #[test]
    fn fw_context_from_icmp_packet() {
        let conntrack = make_conntrack();
        let meta = make_icmp_meta([192, 168, 1, 1], [192, 168, 1, 2]);

        let ctx = FwContext::from_packet(
            &meta,
            FwChain::Input,
            FirewallZone::Lan,
            FirewallZone::Any,
            &conntrack,
            true, // new session
        );

        assert_eq!(ctx.proto, FwProto::Icmp);
        assert!(ctx.is_new);
    }

    #[test]
    fn fw_context_from_non_ipv4_packet() {
        let conntrack = make_conntrack();
        let meta = make_non_ipv4_meta();

        let ctx = FwContext::from_packet(
            &meta,
            FwChain::Input,
            FirewallZone::Wan,
            FirewallZone::Any,
            &conntrack,
            true, // untracked -> new
        );

        assert_eq!(ctx.proto, FwProto::Other);
        // Non-trackable -> treated as new.
        assert!(ctx.is_new);
        assert!(!ctx.is_established);
    }

    #[test]
    fn fw_context_established_when_session_exists() {
        let mut conntrack = make_conntrack();

        // Pre-create a session in conntrack.
        let key = SessionKey {
            src_ip: [192, 168, 1, 100],
            dst_ip: [10, 0, 0, 1],
            proto: SessionProto::Tcp {
                src_port: 49152,
                dst_port: 80,
            },
        };
        conntrack
            .create_session(key, SessionState::Tcp(TcpState::Established))
            .unwrap();

        let meta = make_tcp_meta([192, 168, 1, 100], [10, 0, 0, 1], 49152, 80);

        let ctx = FwContext::from_packet(
            &meta,
            FwChain::Forward,
            FirewallZone::Lan,
            FirewallZone::Wan,
            &conntrack,
            false, // existing session
        );

        assert!(ctx.is_established);
        assert!(!ctx.is_new);
    }

    // ── Test: Related state treated like established ─────────────────

    #[test]
    fn related_state_in_rule_matches_established_context() {
        let mut config = default_fw_config();
        config.allow_established_related = false;
        config.rules = vec![make_rule(
            "allow-related",
            Chain::Forward,
            RuleAction::Accept,
            RuleProto::Any,
            FirewallZone::Any,
            FirewallZone::Any,
            vec![ConnState::Related],
        )];
        let engine = FirewallEngine::from_config(&config);

        // Established context should match a rule with Related state.
        let ctx = make_ctx(
            FwChain::Forward,
            FirewallZone::Wan,
            FirewallZone::Lan,
            FwProto::Icmp,
            true,
            false,
        );
        assert_eq!(
            engine.evaluate(&ctx),
            FwVerdict::AcceptRule {
                rule_name: "allow-related".to_string()
            }
        );
    }
}
