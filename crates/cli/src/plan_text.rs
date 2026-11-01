//! Deterministic text rendering of an [`ApplyPlan`].
//!
//! Layout (one item per line, sections in this fixed order, each list in the
//! plan's key order):
//!
//! ```text
//! plan: reloadable | restart-required
//! restart-required: none | CODE[,CODE...]
//! changes: N
//!   <kind> <+|-|~> <rendered item>[ -> <rendered item>]
//! expected-flush:
//!   <counter> all|<n>
//! ```
//!
//! Interfaces are written as `if<id>`. No allocator seed or hash key is part
//! of any plan item, so none can be printed. Interface name/device labels
//! are the only operator text; validation already restricts them to
//! `[A-Za-z0-9._-]`, and [`label`] escapes every other byte as `\xNN`
//! anyway, so a plan line can never contain whitespace, a control
//! character, or `->` from a label.

use std::fmt::Write as _;

use ruster_control::{ApplyPlan, Change, Delta, FlushCount, NatChange, StateFlush};
use ruster_core::{
    FirewallAction, FirewallInterface, FirewallProtocol, FirewallRule, IfId, Interface,
    Ipv4Address, LocalIpv4Binding, MacAddress, Neighbor, Route,
};

fn ip(address: Ipv4Address) -> String {
    let [a, b, c, d] = address.octets();
    format!("{a}.{b}.{c}.{d}")
}

fn mac(address: MacAddress) -> String {
    let [a, b, c, d, e, f] = address.0;
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

/// Defensive escape of an operator label: bytes outside `[A-Za-z0-9._-]`
/// become `\xNN`, and an empty label is written as `""`.
fn label(text: &str) -> String {
    if text.is_empty() {
        return "\"\"".to_owned();
    }
    let mut escaped = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
            escaped.push(char::from(byte));
        } else {
            let _ = write!(escaped, "\\x{byte:02x}");
        }
    }
    escaped
}

fn iface(id: IfId) -> String {
    format!("if{}", id.0)
}

fn route(route: &Route) -> String {
    let mut text = format!(
        "{}/{} dev {}",
        ip(route.prefix()),
        route.prefix_len(),
        iface(route.egress())
    );
    if let Some(via) = route.next_hop() {
        let _ = write!(text, " via {}", ip(via));
    }
    text
}

fn neighbor(neighbor: &Neighbor) -> String {
    format!(
        "{} {} lladdr {}",
        iface(neighbor.interface),
        ip(neighbor.target),
        mac(neighbor.mac)
    )
}

fn local(binding: &LocalIpv4Binding) -> String {
    format!("{} {}", iface(binding.interface), ip(binding.address))
}

fn interface(interface: &Interface) -> String {
    format!("{} mac {}", iface(interface.id), mac(interface.mac))
}

fn side(interface: FirewallInterface) -> String {
    match interface {
        FirewallInterface::Any => "any".to_owned(),
        FirewallInterface::Interface(id) => iface(id),
    }
}

fn rule(rule: &FirewallRule) -> String {
    let protocol = match rule.protocol() {
        FirewallProtocol::Tcp => "tcp",
        FirewallProtocol::Udp => "udp",
    };
    let action = match rule.action() {
        FirewallAction::AllowStateful => "allow-stateful",
        FirewallAction::Deny => "deny",
    };
    let (source, destination) = (rule.source(), rule.destination());
    let (sport, dport) = (rule.source_ports(), rule.destination_ports());
    format!(
        "id {} {} {} -> {} {}/{} -> {}/{} sport {}-{} dport {}-{} {}",
        rule.id().0,
        protocol,
        side(rule.ingress()),
        side(rule.egress()),
        ip(source.address()),
        source.prefix_len(),
        ip(destination.address()),
        destination.prefix_len(),
        sport.first(),
        sport.last(),
        dport.first(),
        dport.last(),
        action
    )
}

fn changes<T>(
    lines: &mut Vec<String>,
    kind: &str,
    items: &[Change<T>],
    show: impl Fn(&T) -> String,
) {
    for item in items {
        lines.push(match item {
            Change::Added(new) => format!("{kind} + {}", show(new)),
            Change::Removed(old) => format!("{kind} - {}", show(old)),
            Change::Changed(Delta { old, new }) => {
                format!("{kind} ~ {} -> {}", show(old), show(new))
            }
        });
    }
}

fn nat(lines: &mut Vec<String>, kind: &str, change: NatChange) {
    if let Some(Delta { old, new }) = change.realm {
        let realm = |r: ruster_control::NatRealm| {
            format!(
                "inside {} outside {} public {}",
                iface(r.inside),
                iface(r.outside),
                ip(r.public_address)
            )
        };
        lines.push(format!("{kind} realm ~ {} -> {}", realm(old), realm(new)));
    }
    if let Some(Delta { old, new }) = change.ports {
        lines.push(format!(
            "{kind} ports ~ {}-{} -> {}-{}",
            old.first, old.last, new.first, new.last
        ));
    }
    if let Some(Delta { old, new }) = change.filtering {
        lines.push(format!(
            "{kind} filtering ~ {} -> {}",
            old.config_name(),
            new.config_name()
        ));
    }
    if let Some(Delta { old, new }) = change.hairpinning {
        let switch = |enabled: bool| if enabled { "on" } else { "off" };
        lines.push(format!(
            "{kind} hairpinning ~ {} -> {}",
            switch(old),
            switch(new)
        ));
    }
    if change.policy_changed {
        lines.push(format!("{kind} policy ~ changed"));
    }
}

fn flush_lines(flush: StateFlush) -> [(&'static str, FlushCount); 11] {
    [
        ("resolution_states", flush.resolution_states),
        ("resolution_actions", flush.resolution_actions),
        ("dynamic_neighbors", flush.dynamic_neighbors),
        ("failure_holds", flush.failure_holds),
        ("icmpv4_error_states", flush.icmpv4_error_states),
        ("icmpv4_error_actions", flush.icmpv4_error_actions),
        ("nat44_udp_mappings", flush.nat44_udp_mappings),
        ("nat44_udp_peers", flush.nat44_udp_peers),
        ("nat44_tcp_mappings", flush.nat44_tcp_mappings),
        ("nat44_tcp_sessions", flush.nat44_tcp_sessions),
        ("firewall_flows", flush.firewall_flows),
    ]
}

/// Renders `plan` as deterministic text.
pub fn render(plan: &ApplyPlan) -> String {
    let mut lines = Vec::new();
    changes(&mut lines, "interface", plan.interfaces(), interface);
    for Delta { old, new } in plan.interface_labels() {
        lines.push(format!(
            "interface-label ~ {} name {} device {} -> name {} device {}",
            iface(old.id),
            label(&old.name),
            label(&old.device),
            label(&new.name),
            label(&new.device)
        ));
    }
    changes(&mut lines, "local-ipv4", plan.local_ipv4(), local);
    changes(&mut lines, "route", plan.routes(), route);
    changes(&mut lines, "neighbor", plan.neighbors(), neighbor);
    changes(&mut lines, "firewall-rule", plan.firewall_rules(), rule);
    if plan.firewall_rule_order_changed() {
        lines.push("firewall-rule-order ~ changed".to_owned());
    }
    if plan.firewall_policy_changed() {
        lines.push("firewall-policy ~ changed".to_owned());
    }
    if plan.ipv4_origin_changed() {
        lines.push("ipv4-origin ~ changed".to_owned());
    }
    nat(&mut lines, "nat44-udp", plan.nat44_udp());
    nat(&mut lines, "nat44-tcp", plan.nat44_tcp());

    let mut text = String::new();
    let restart: Vec<&str> = plan.restart_required().iter().map(|r| r.code()).collect();
    let _ = writeln!(
        text,
        "plan: {}",
        if restart.is_empty() {
            "reloadable"
        } else {
            "restart-required"
        }
    );
    let _ = writeln!(
        text,
        "restart-required: {}",
        if restart.is_empty() {
            "none".to_owned()
        } else {
            restart.join(",")
        }
    );
    let _ = writeln!(text, "changes: {}", lines.len());
    for line in &lines {
        let _ = writeln!(text, "  {line}");
    }
    text.push_str("expected-flush:\n");
    for (name, count) in flush_lines(plan.flush()) {
        let _ = match count {
            FlushCount::All => writeln!(text, "  {name} all"),
            FlushCount::Exact(count) => writeln!(text, "  {name} {count}"),
        };
    }
    text
}

#[cfg(test)]
mod tests {
    use super::label;

    #[test]
    fn labels_are_escaped_to_one_safe_token() {
        assert_eq!(label("wan"), "wan");
        assert_eq!(label("Aa0._-"), "Aa0._-");
        assert_eq!(label(""), "\"\"");
        // The review reproduction: a label forging a `route -` line and
        // emitting a terminal escape.
        let forged = label("wan device x -> name y\n  route - 0.0.0.0\u{1b}[31m");
        assert_eq!(
            forged,
            "wan\\x20device\\x20x\\x20-\\x3e\\x20name\\x20y\\x0a\\x20\\x20route\\x20-\\x20\
             0.0.0.0\\x1b\\x5b31m"
        );
        assert!(forged
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-\\".contains(&b)));
        assert!(!forged.contains("->"));
        assert_eq!(label("\u{e9}\\"), "\\xc3\\xa9\\x5c");
    }
}
