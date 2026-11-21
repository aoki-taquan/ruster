//! bird-rs's configuration for IS-IS, OSPFv2 and OSPFv3 from the `bird` part: a
//! `protocol isis`, `protocol ospf v2` and `protocol ospf v3` on the TAP devices
//! that stand for the interfaces in the kernel's namespace (`rp-<name>`,
//! `docs/design/overlay.md` section 6). Their routes go to ribd through `protocol
//! ruster` ([`crate::conf`]), not to the kernel.
//!
//! Each value is checked again for its form before it is written, so nothing else
//! reaches the file.
//!
//! # Standards
//!
//! - ISO 10589 and RFC 1195: one IS-IS instance, with the NET and the level given;
//!   RFC 5305: wide metrics (bird-rs's default); RFC 5308: IPv6.
//! - RFC 2328 (OSPFv2) and RFC 5340 (OSPFv3): the router ID, and per interface its
//!   area, cost and network type (broadcast or point-to-point); a passive
//!   interface's prefixes are announced but no adjacency is formed on it (bird-rs's
//!   `stub`).
//!
//! Deviations: none of the protocols is here; bird-rs implements them. Only the
//! default VRF. IS-IS carries IPv6 on all of its interfaces or on none (bird-rs has
//! no switch per interface): a mix of interfaces with and without an IPv6 prefix is
//! refused. An OSPF with no interface is not written.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::Ipv4Addr;

use ruster_config::{Frr, Ospf, ISIS_LEVELS};

/// Whether `routing` runs IS-IS or OSPF.
#[must_use]
pub fn runs(routing: &Frr) -> bool {
    routing.isis.is_some() || routing.ospf.is_some() || routing.ospf6.is_some()
}

/// The TAP device of interface `name`, quoted for the file.
fn device(name: &str) -> Result<String, String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"/\"\\*?".contains(&b))
    {
        return Err(format!("interface {name:?}: not a name bird-rs takes"));
    }
    Ok(format!("\"{}\"", ruster_config::tap_device(name)))
}

/// Writes the IS-IS and OSPF protocols of `routing`.
pub fn write(out: &mut String, routing: &Frr) -> Result<(), String> {
    if let Some(isis) = &routing.isis {
        let net_form = |b: u8| b.is_ascii_hexdigit() || b == b'.';
        if isis.net.is_empty() || !isis.net.bytes().all(net_form) {
            return Err(format!("isis: net {:?}", isis.net));
        }
        let level = match isis.level.as_str() {
            "level-1" => "1",
            "level-2" => "2",
            "level-1-2" => "1-2",
            other => {
                return Err(format!(
                    "isis: level {other:?} is not one of {ISIS_LEVELS:?}"
                ))
            }
        };
        // bird-rs carries IPv6 on every circuit or on none: FRR's bridge has it on
        // those with an IPv6 prefix, so both agree only when all or none have one.
        let with_ipv6 = isis
            .interface
            .iter()
            .filter(|i| has_ipv6(&i.name, &routing.connected))
            .count();
        let ipv6 = match with_ipv6 {
            0 => "",
            n if n == isis.interface.len() => "  ipv6 { import all; export none; };\n",
            _ => {
                return Err(
                    "isis: with bird-rs, give IPv6 to all of its interfaces or to none".into(),
                )
            }
        };
        // Quoted: bird-rs reads only one form of NET bare.
        let _ = write!(
            out,
            "protocol isis ruster_isis {{\n  net \"{}\";\n  level {level};\n  \
             ipv4 {{ import all; export none; }};\n{ipv6}",
            isis.net
        );
        for i in &isis.interface {
            let passive = if i.passive { " passive;" } else { "" };
            let _ = writeln!(
                out,
                "  interface {} {{ metric {};{passive} }};",
                device(&i.name)?,
                i.metric
            );
        }
        out.push_str("}\n");
    }
    for (ospf, version, channel) in [
        (&routing.ospf, "v2", "ipv4"),
        (&routing.ospf6, "v3", "ipv6"),
    ] {
        if let Some(ospf) = ospf {
            write_ospf(out, ospf, version, channel)?;
        }
    }
    Ok(())
}

fn write_ospf(out: &mut String, ospf: &Ospf, version: &str, channel: &str) -> Result<(), String> {
    // bird-rs takes no OSPF without an area: with no interface it runs nothing.
    if ospf.interface.is_empty() {
        return Ok(());
    }
    let word = if version == "v2" { "ospf" } else { "ospf6" };
    let id: Ipv4Addr = ospf
        .router_id
        .parse()
        .map_err(|_| format!("{word}: router-id {:?}", ospf.router_id))?;
    let mut areas: BTreeMap<Ipv4Addr, String> = BTreeMap::new();
    for i in &ospf.interface {
        let area: Ipv4Addr = i
            .area
            .parse()
            .map_err(|_| format!("{word} interface {:?}: area {:?}", i.name, i.area))?;
        let kind = match i.network.as_str() {
            "broadcast" => "broadcast",
            "point-to-point" => "ptp",
            other => return Err(format!("{word} interface {:?}: network {other:?}", i.name)),
        };
        let stub = if i.passive { " stub;" } else { "" };
        let _ = writeln!(
            areas.entry(area).or_default(),
            "    interface {} {{ cost {}; type {kind};{stub} }};",
            device(&i.name)?,
            i.cost
        );
    }
    let _ = write!(
        out,
        "protocol ospf {version} ruster_{word} {{\n  router id {id};\n  \
         {channel} {{ import all; export none; }};\n"
    );
    for (area, interfaces) in &areas {
        let _ = write!(out, "  area {area} {{\n{interfaces}  }};\n");
    }
    out.push_str("}\n");
    Ok(())
}

/// Whether interface `name` has a global IPv6 prefix.
fn has_ipv6(name: &str, connected: &[ruster_config::Connected]) -> bool {
    connected
        .iter()
        .any(|c| c.interface == name && c.prefix.contains(':'))
}

/// A router ID for IS-IS alone: the last four octets of the NET's system ID (the
/// six octets before the NSEL), so that it stays the same across restarts.
pub fn isis_router_id(net: &str) -> Option<Ipv4Addr> {
    let hex: String = net.chars().filter(|c| *c != '.').collect();
    // ... system ID (12 hex digits), NSEL (2).
    let system = hex.get(hex.len().checked_sub(14)?..hex.len() - 2)?;
    let octet = |at: usize| u8::from_str_radix(system.get(at..at + 2)?, 16).ok();
    Some(Ipv4Addr::new(octet(4)?, octet(6)?, octet(8)?, octet(10)?))
}
