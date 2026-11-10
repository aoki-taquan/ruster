//! FRR's configuration for IS-IS, OSPFv2 and OSPFv3 from the `frr` part: an
//! `interface rp-<name>` section for each interface that runs one of them (the TAP
//! device that stands for it in the kernel's namespace, `docs/design/overlay.md`
//! section 6), then `router isis ruster`, `router ospf` and `router ospf6`.
//!
//! Each value is checked again for its form before it is written, so nothing else
//! reaches the file.
//!
//! # Standards
//!
//! - ISO 10589 and RFC 1195: one IS-IS instance, with the NET and the level given;
//!   RFC 5305: wide metrics (`metric-style wide`); RFC 5308: IPv6 on an interface
//!   with a global IPv6 prefix.
//! - RFC 2328 (OSPFv2) and RFC 5340 (OSPFv3): the router ID, and per interface its
//!   area, cost and network type (broadcast or point-to-point); a passive
//!   interface's prefixes are announced but no adjacency is formed on it.
//!
//! Deviations: none of the protocols is here; FRR implements them. Only the
//! default VRF.

use std::fmt::Write as _;
use std::net::Ipv4Addr;

use ruster_config::{Connected, Frr, ISIS_LEVELS, OSPF_NETWORKS};

/// The IS-IS instance's name.
pub const ISIS_INSTANCE: &str = "ruster";

/// Writes the interface sections and the `router` sections of `frr`.
pub fn write(out: &mut String, frr: &Frr) -> Result<(), String> {
    let mut names: Vec<&str> = Vec::new();
    let isis = frr.isis.iter().flat_map(|i| &i.interface).map(|i| &i.name);
    let ospf = [&frr.ospf, &frr.ospf6]
        .into_iter()
        .flatten()
        .flat_map(|o| &o.interface)
        .map(|i| &i.name);
    for name in isis.chain(ospf) {
        if !names.contains(&name.as_str()) {
            names.push(name);
        }
    }
    for name in names {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic() && b != b'/') {
            return Err(format!("interface {name:?}: not a name FRR takes"));
        }
        let _ = writeln!(out, "interface {}", ruster_config::tap_device(name));
        if let Some(isis) = &frr.isis {
            if let Some(i) = isis.interface.iter().find(|i| i.name == name) {
                let _ = writeln!(out, " ip router isis {ISIS_INSTANCE}");
                if has_ipv6(name, &frr.connected) {
                    let _ = writeln!(out, " ipv6 router isis {ISIS_INSTANCE}");
                }
                let _ = writeln!(out, " isis metric {}", i.metric);
                if i.passive {
                    out.push_str(" isis passive\n");
                }
            }
        }
        for (ospf, ip, word) in [(&frr.ospf, "ip", "ospf"), (&frr.ospf6, "ipv6", "ospf6")] {
            let Some(i) = ospf
                .iter()
                .flat_map(|o| &o.interface)
                .find(|i| i.name == name)
            else {
                continue;
            };
            let area: Ipv4Addr = i
                .area
                .parse()
                .map_err(|_| format!("{word} interface {name:?}: area {:?}", i.area))?;
            if !OSPF_NETWORKS.contains(&i.network.as_str()) {
                return Err(format!(
                    "{word} interface {name:?}: network {:?}",
                    i.network
                ));
            }
            let _ = writeln!(out, " {ip} {word} area {area}");
            let _ = writeln!(out, " {ip} {word} cost {}", i.cost);
            let _ = writeln!(out, " {ip} {word} network {}", i.network);
            if i.passive {
                let _ = writeln!(out, " {ip} {word} passive");
            }
        }
        out.push_str("exit\n");
    }
    if let Some(isis) = &frr.isis {
        let net_form = |b: u8| b.is_ascii_hexdigit() || b == b'.';
        if isis.net.is_empty() || !isis.net.bytes().all(net_form) {
            return Err(format!("isis: net {:?}", isis.net));
        }
        let is_type = match isis.level.as_str() {
            "level-1" => "level-1",
            "level-2" => "level-2-only",
            "level-1-2" => "level-1-2",
            other => {
                return Err(format!(
                    "isis: level {other:?} is not one of {ISIS_LEVELS:?}"
                ))
            }
        };
        let _ = writeln!(
            out,
            "router isis {ISIS_INSTANCE}\n net {}\n is-type {is_type}\n metric-style wide\nexit",
            isis.net
        );
    }
    for (ospf, word) in [(&frr.ospf, "ospf"), (&frr.ospf6, "ospf6")] {
        if let Some(ospf) = ospf {
            let id: Ipv4Addr = ospf
                .router_id
                .parse()
                .map_err(|_| format!("{word}: router-id {:?}", ospf.router_id))?;
            let _ = writeln!(out, "router {word}\n {word} router-id {id}\nexit");
        }
    }
    Ok(())
}

/// Whether interface `name` has a global IPv6 prefix.
fn has_ipv6(name: &str, connected: &[Connected]) -> bool {
    connected
        .iter()
        .any(|c| c.interface == name && c.prefix.contains(':'))
}
