//! The kernel side of traffic addressed to the router (`docs/design/ce-processes.md`):
//! in confd's network namespace, one persistent TUN device per VRF holding the
//! router's addresses in that VRF, inside a Linux VRF device for VRFs other than
//! `default`, with the default routes pointing at the TUN device so every answer
//! goes back through the FE.
//!
//! This is cold-path setup done with `ip` (iproute2) commands. Each apply is
//! idempotent: devices are created when missing, the addresses of a TUN device are
//! replaced with the configured ones, and routes are replaced.
//!
//! Limits: link-local addresses are not put on the TUN devices; VRF names longer than
//! 11 bytes have no kernel side.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::process::Command;

use ruster_proto::table::DEFAULT_VRF;

use crate::Config;

/// The first kernel routing table of a VRF other than `default`.
const FIRST_TABLE: u32 = 1_000;

/// The commands for `config`, in order. Each is `ip` arguments.
pub fn commands(config: &Config) -> Vec<Vec<String>> {
    let mut by_vrf: BTreeMap<&str, Vec<(IpAddr, u8)>> = BTreeMap::new();
    for interface in config.interfaces.iter().filter(|i| i.enabled) {
        let addresses = by_vrf.entry(interface.vrf.as_str()).or_default();
        if let Some((a, len)) = interface.ipv4 {
            addresses.push((IpAddr::V4(a), len));
        }
        for &(a, len) in &interface.ipv6 {
            if !a.is_unicast_link_local() {
                addresses.push((IpAddr::V6(a), len));
            }
        }
    }
    let mut out = Vec::new();
    let mut run = |args: &[&str]| out.push(args.iter().map(|a| (*a).to_owned()).collect());
    let mut table = FIRST_TABLE;
    for (vrf, addresses) in &by_vrf {
        let tun = format!("rt-{vrf}");
        let master = format!("vrf-{vrf}");
        if tun.len() > 15 || master.len() > 15 {
            continue;
        }
        run(&["tuntap", "add", "mode", "tun", "dev", &tun]);
        let table_id = table.to_string();
        if *vrf != DEFAULT_VRF {
            run(&["link", "add", &master, "type", "vrf", "table", &table_id]);
            run(&["link", "set", &master, "up"]);
            run(&["link", "set", &tun, "master", &master]);
            table += 1;
        }
        run(&["link", "set", &tun, "up"]);
        run(&["address", "flush", "dev", &tun]);
        for (address, len) in addresses {
            let with_len = format!("{address}/{len}");
            if address.is_ipv6() {
                run(&["address", "add", &with_len, "dev", &tun, "nodad"]);
            } else {
                run(&["address", "add", &with_len, "dev", &tun]);
            }
        }
        for family in ["-4", "-6"] {
            let mut args = vec![family, "route", "replace", "default", "dev", &tun];
            if *vrf != DEFAULT_VRF {
                args.extend(["table", &table_id]);
            }
            run(&args);
        }
    }
    out
}

/// Runs the commands for `config`. A command that fails because what it creates
/// already exists is fine; other failures are returned as text, and the rest still
/// run.
pub fn apply(config: &Config) -> Vec<String> {
    let mut errors = Vec::new();
    for args in commands(config) {
        match Command::new("ip").args(&args).output() {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("File exists") && !stderr.contains("Device or resource busy") {
                    errors.push(format!("ip {}: {}", args.join(" "), stderr.trim()));
                }
            }
            Err(error) => errors.push(format!("ip {}: {error}", args.join(" "))),
        }
    }
    errors
}
