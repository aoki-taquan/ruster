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
//! of any plan item, so none can be printed.

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
            old.name,
            old.device,
            new.name,
            new.device
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
