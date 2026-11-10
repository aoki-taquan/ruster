//! The PPPoE client's part (`[[pppoe]]`, for `ruster-pppoed`) and the punt classes
//! that hand it PPPoE Discovery and PPP control.
//!
//! Each `[[pppoe]]` sets up the session of one source of kind pppoe, on the parent
//! of the interface that names the source. confd hands the entries to
//! `ruster-pppoed` on `confd/part.sock` (module `pppoe`), and for each parent
//! writes two punt classes to the FE: `pppoe-discovery-<parent>` and
//! `ppp-control-<parent>`, to the control process `pppoed`.
//!
//! # Standards
//!
//! - RFC 2516 section 5: Discovery frames (Ethernet type 0x8863) of the parent go to
//!   the client. RFC 1661 section 2 and RFC 2516 section 4: so do the PPP control
//!   protocols (LCP, PAP, CHAP, IPCP, IPv6CP) in session frames.
//! - RFC 1334 section 2.2.1 (PAP) and RFC 1994 section 4.1 (CHAP): the user and
//!   password are at most 255 bytes, which their length fields hold; the service
//!   and AC names are kept to the same.
//!
//! Deviations: the parts of the client's settings that are not in RFCs (the echo
//! interval, the default route) are ruster's own.

use std::collections::BTreeMap;

use ruster_proto::table::{Key, PuntClass, PuntDestination, PuntKind, PuntMatch, Value};

use crate::source::Spec;
use crate::InterfaceConfig;

/// The control process (`<run>/pppoed/punt.sock`) PPPoE frames are handed to.
pub const PPPOE_CONTROL: &str = "pppoed";
/// Discovery frames per second, and at once, one parent hands over: a few per
/// session attempt, and room for a misbehaving AC without flooding the client.
pub const DISCOVERY_RATE: u32 = 20;
pub const DISCOVERY_BURST: u32 = 20;
/// PPP control frames per second, and at once: negotiation and LCP echoes.
pub const CONTROL_RATE: u32 = 100;
pub const CONTROL_BURST: u32 = 50;

/// The longest user, password, service name and AC name.
const TEXT_MAX: usize = 255;

/// Checks the lock form's `[[pppoe]]` against the interfaces and sources.
pub fn check(
    entries: Vec<ruster_config::Pppoe>,
    interfaces: &[InterfaceConfig],
    sources: &[Spec],
) -> Result<Vec<ruster_config::Pppoe>, String> {
    let mut out: Vec<ruster_config::Pppoe> = Vec::with_capacity(entries.len());
    for entry in entries {
        let at = format!("pppoe {:?}", entry.source);
        if !sources
            .iter()
            .any(|s| s.name == entry.source && s.kind == crate::source::Kind::Pppoe)
        {
            return Err(format!("{at}: source must be a source of kind pppoe"));
        }
        if out.iter().any(|e| e.source == entry.source) {
            return Err(format!("{at}: given twice"));
        }
        let interface = interfaces
            .iter()
            .find(|i| i.pppoe.as_ref().is_some_and(|(_, s)| *s == entry.source))
            .ok_or_else(|| format!("{at}: no PPPoE interface names this source"))?;
        let (parent, _) = interface.pppoe.as_ref().expect("found by it");
        let mac = ruster_proto::table::format_mac(&interface.mac);
        let same_mac = ruster_proto::table::parse_mac(&entry.mac.to_ascii_lowercase())
            .is_ok_and(|m| m == interface.mac);
        if entry.interface != interface.name
            || entry.vrf != interface.vrf
            || entry.parent != *parent
            || !same_mac
        {
            return Err(format!(
                "{at}: interface, vrf, parent and mac must be those of interface {:?} ({}, {parent}, {mac})",
                interface.name, interface.vrf
            ));
        }
        if entry.user.is_empty() {
            return Err(format!("{at}: user is empty"));
        }
        if entry.echo_failures > 100 {
            return Err(format!("{at}: echo-failures must be at most 100"));
        }
        for (what, text) in [
            ("user", &entry.user),
            ("password", &entry.password),
            ("service", &entry.service),
        ] {
            if text.len() > TEXT_MAX {
                return Err(format!("{at}: {what} is longer than {TEXT_MAX} bytes"));
            }
        }
        match entry.ac_name.as_slice() {
            [] => {}
            [name] if name.len() <= TEXT_MAX => {}
            [_] => return Err(format!("{at}: ac-name is longer than {TEXT_MAX} bytes")),
            _ => return Err(format!("{at}: ac-name takes at most one value")),
        }
        if entry.echo_interval > 0 && entry.echo_failures == 0 {
            return Err(format!("{at}: echo-failures must be at least 1"));
        }
        if entry.echo_interval > 3_600 {
            return Err(format!("{at}: echo-interval must be at most 3600"));
        }
        out.push(entry);
    }
    Ok(out)
}

/// How many punt classes the entries take: two per parent.
pub fn class_count(entries: &[ruster_config::Pppoe]) -> usize {
    let parents: std::collections::BTreeSet<&str> =
        entries.iter().map(|e| e.parent.as_str()).collect();
    parents.len() * 2
}

/// The punt classes of the parents the entries' sessions run on.
pub fn punt_classes(entries: &[ruster_config::Pppoe], out: &mut BTreeMap<Key, Value>) {
    for entry in entries {
        for (prefix, kind, rate, burst) in [
            (
                "pppoe-discovery-",
                PuntKind::PppoeDiscovery,
                DISCOVERY_RATE,
                DISCOVERY_BURST,
            ),
            (
                "ppp-control-",
                PuntKind::PppControl,
                CONTROL_RATE,
                CONTROL_BURST,
            ),
        ] {
            out.insert(
                Key::Punt {
                    class: format!("{prefix}{}", entry.parent),
                },
                Value::Punt(PuntClass {
                    matches: PuntMatch::Kind(kind),
                    interface: Some(entry.parent.clone()),
                    destination: PuntDestination::Control(PPPOE_CONTROL.to_owned()),
                    rate,
                    burst,
                }),
            );
        }
    }
}
