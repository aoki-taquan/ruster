//! The kernel side of traffic addressed to the router (`docs/design/ce-processes.md`):
//! in confd's network namespace, one persistent TUN device per VRF holding the
//! router's addresses in that VRF, inside a Linux VRF device for VRFs other than
//! `default`, with the default routes pointing at the TUN device so every answer
//! goes back through the FE.
//!
//! This is cold-path setup done with `ip` (iproute2) commands. Each apply is
//! idempotent: devices are created when missing (a VRF device on the wrong table is
//! made again), the addresses of a TUN device are brought to the configured ones by
//! adding and removing only the difference, and routes are replaced. A VRF's kernel
//! table comes from its name, so adding or removing VRFs never moves another's.
//! Forwarding is turned off in the namespace: the kernel only terminates traffic, it
//! never routes it around the FE.
//!
//! Run it in the router's own network namespace: it replaces that namespace's
//! default routes.
//!
//! Limits: link-local addresses are not put on the TUN devices; devices of a VRF that
//! is removed stay. The configuration file keeps VRF names to 11 bytes, so the device
//! names fit.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::process::Command;

use ruster_proto::table::DEFAULT_VRF;

use crate::Config;

/// The kernel routing table of a VRF other than `default`: from a hash of its name
/// (FNV-1a), above the tables Linux and distributions use.
pub fn table(vrf: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in vrf.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    1_000 + hash % 0x7fff_0000
}

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
    for (vrf, addresses) in &by_vrf {
        let tun = format!("rt-{vrf}");
        let master = format!("vrf-{vrf}");
        if tun.len() > 15 || master.len() > 15 {
            continue;
        }
        run(&["tuntap", "add", "mode", "tun", "dev", &tun]);
        let table_id = table(vrf).to_string();
        if *vrf != DEFAULT_VRF {
            run(&["link", "add", &master, "type", "vrf", "table", &table_id]);
            run(&["link", "set", &master, "up"]);
            run(&["link", "set", &tun, "master", &master]);
        }
        run(&["link", "set", &tun, "up"]);
        for (address, len) in addresses {
            let with_len = format!("{address}/{len}");
            if address.is_ipv6() {
                run(&["address", "replace", &with_len, "dev", &tun, "nodad"]);
            } else {
                run(&["address", "replace", &with_len, "dev", &tun]);
            }
        }
        // With NAT, the router's own IPv4 leaves from its address on NAT's inside,
        // so that NAT translates it as a host's there (`fe-ce-split.md`).
        let nat_source = (*vrf == DEFAULT_VRF)
            .then_some(config.nat.as_ref())
            .flatten()
            .and_then(|nat| {
                config
                    .interfaces
                    .iter()
                    .find(|i| i.name == nat.inside && i.enabled)
            })
            .and_then(|inside| inside.ipv4)
            .map(|(address, _)| address.to_string());
        for family in ["-4", "-6"] {
            let mut args = vec![family, "route", "replace", "default", "dev", &tun];
            if *vrf != DEFAULT_VRF {
                args.extend(["table", &table_id]);
            }
            if let (Some(source), "-4") = (&nat_source, family) {
                args.extend(["src", source]);
            }
            run(&args);
        }
    }
    out
}

fn words(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

/// Runs the commands for `config`, after turning forwarding off and making again any
/// VRF device on another table, and then removes addresses no longer configured.
/// Only the creation of a device that already exists may fail quietly; other failures
/// are returned as text, and the rest still run.
pub fn apply(config: &Config) -> Vec<String> {
    let mut errors = Vec::new();
    for (path, value) in [
        ("/proc/sys/net/ipv4/ip_forward", "0"),
        ("/proc/sys/net/ipv6/conf/all/forwarding", "0"),
    ] {
        if let Err(error) = std::fs::write(path, value) {
            errors.push(format!("{path}: {error}"));
        }
    }
    let commands = commands(config);
    for args in &commands {
        if let ["link", "add", master, "type", "vrf", "table", wanted] = words(args).as_slice() {
            if vrf_table(master).is_some_and(|current| current.to_string() != *wanted) {
                let _ = ip(&["link", "del", master]);
            }
        }
    }
    // Devices first, then the addresses no longer configured are removed, and only
    // then the configured ones and the routes are put in: removing an old primary
    // address after adding a new one in the same subnet would take the new one (a
    // secondary) with it, and the routes too.
    let is_device = |w: &[&str]| matches!(w, ["tuntap", ..] | ["link", ..]);
    let run = |args: &Vec<String>, errors: &mut Vec<String>| {
        let w = words(args);
        let creates = matches!(w.as_slice(), ["tuntap", "add", ..] | ["link", "add", ..]);
        if let Err(stderr) = ip(&w) {
            let exists =
                stderr.contains("File exists") || stderr.contains("Device or resource busy");
            if !(creates && exists) {
                errors.push(format!("ip {}: {}", args.join(" "), stderr.trim()));
            }
        }
    };
    for args in commands.iter().filter(|a| is_device(&words(a))) {
        run(args, &mut errors);
    }
    for (tun, wanted) in wanted_addresses(&commands) {
        let promote = format!("/proc/sys/net/ipv4/conf/{tun}/promote_secondaries");
        let _ = std::fs::write(promote, "1");
        for present in addresses_of(&tun) {
            if !wanted.contains(&present) && !present.starts_with("fe80:") {
                if let Err(stderr) = ip(&["address", "del", &present, "dev", &tun]) {
                    errors.push(format!(
                        "ip address del {present} dev {tun}: {}",
                        stderr.trim()
                    ));
                }
            }
        }
    }
    for args in commands.iter().filter(|a| !is_device(&words(a))) {
        run(args, &mut errors);
    }
    errors
}

fn ip(args: &[&str]) -> Result<String, String> {
    match Command::new("ip").args(args).output() {
        Ok(output) if output.status.success() => {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
        Ok(output) => Err(String::from_utf8_lossy(&output.stderr).into_owned()),
        Err(error) => Err(error.to_string()),
    }
}

/// The table of an existing VRF device, from `ip -d link show`.
fn vrf_table(device: &str) -> Option<u32> {
    let shown = ip(&["-d", "link", "show", device]).ok()?;
    let mut words = shown.split_whitespace();
    while let Some(word) = words.next() {
        if word == "table" {
            return words.next()?.parse().ok();
        }
    }
    None
}

/// The addresses (`address/len`) on a device, from `ip -o address show`.
fn addresses_of(device: &str) -> Vec<String> {
    let Ok(shown) = ip(&["-o", "address", "show", "dev", device]) else {
        return Vec::new();
    };
    shown
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            words.find(|w| *w == "inet" || *w == "inet6")?;
            words.next().map(str::to_owned)
        })
        .collect()
}

/// For each TUN device, the addresses the commands put on it.
fn wanted_addresses(commands: &[Vec<String>]) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for args in commands {
        match words(args).as_slice() {
            ["tuntap", "add", "mode", "tun", "dev", tun] => {
                out.entry((*tun).to_owned()).or_default();
            }
            ["address", "replace", address, "dev", tun, ..] => {
                out.entry((*tun).to_owned())
                    .or_default()
                    .push((*address).to_owned());
            }
            _ => {}
        }
    }
    out
}
