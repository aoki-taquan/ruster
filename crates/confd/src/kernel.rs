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
//! An interface that runs IS-IS or OSPF gets a persistent TAP device of its own,
//! `rp-<interface>` (`docs/design/overlay.md` section 6), where FRR speaks them:
//! with the interface's MAC address and MTU, in the VRF device, without ARP and
//! Neighbor Discovery (`NOARP`, so no DAD either) and without addresses of its own
//! making (`addrgenmode none`, no Router Solicitations). It holds the interface's
//! addresses, its link-local one included, instead of the TUN device, and the
//! kernel adds their prefix routes on it. Packets to those addresses still come in
//! through the TUN device, so reverse path filtering is loose on both. A TAP device
//! no interface needs any more is removed.
//!
//! Limits: link-local addresses are not put on the TUN devices (a TAP device has its
//! interface's); devices of a VRF that is removed stay. The configuration file keeps VRF names to 11 bytes, so the device
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

/// The interfaces of `config` that get a TAP device: enabled, running IS-IS or OSPF.
fn tap_interfaces(config: &Config) -> Vec<&crate::InterfaceConfig> {
    let names = crate::isis_ospf::tap_interfaces(config);
    config
        .interfaces
        .iter()
        .filter(|i| i.enabled && names.iter().any(|(name, ..)| *name == i.name))
        .collect()
}

/// The commands for `config`, in order. Each is `ip` arguments.
pub fn commands(config: &Config) -> Vec<Vec<String>> {
    let mut by_vrf: BTreeMap<&str, Vec<(IpAddr, u8)>> = BTreeMap::new();
    let taps = tap_interfaces(config);
    for interface in config.interfaces.iter().filter(|i| i.enabled) {
        let addresses = by_vrf.entry(interface.vrf.as_str()).or_default();
        // Its TAP device holds them.
        if taps.iter().any(|t| t.name == interface.name) {
            continue;
        }
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
            .then(|| nat_inside_address(config))
            .flatten();
        // NAT's outside prefix too: otherwise a host on the WAN's subnet (the ISP's
        // gateway) is reached from the WAN address, which is NAT's public address, and
        // its answers find no mapping there. Every other IPv4 prefix leaves from its
        // own address, so that each apply decides these routes (also after NAT is
        // removed).
        let nat_outside = (*vrf == DEFAULT_VRF)
            .then_some(config.nat.as_ref())
            .flatten()
            .and_then(|nat| {
                config
                    .interfaces
                    .iter()
                    .find(|i| i.name == nat.outside && i.enabled)
            })
            .and_then(|outside| outside.ipv4)
            .map(|(address, _)| IpAddr::V4(address));
        for (address, len) in addresses {
            if address.is_ipv4() {
                let prefix = format!("{}/{len}", ruster_proto::table::network(*address, *len));
                let source = match &nat_source {
                    Some(inside) if Some(*address) == nat_outside => inside.clone(),
                    _ => address.to_string(),
                };
                run(&[
                    "-4", "route", "replace", &prefix, "dev", &tun, "src", &source,
                ]);
            }
        }
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
    for interface in taps {
        let tap = ruster_config::tap_device(&interface.name);
        let mac = interface
            .mac
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        // The FE takes frames of up to 1514 bytes from a TAP device.
        let mtu = interface.mtu.min(ruster_config::MTU).to_string();
        run(&["tuntap", "add", "mode", "tap", "dev", &tap]);
        run(&[
            "link",
            "set",
            &tap,
            "address",
            &mac,
            "mtu",
            &mtu,
            "arp",
            "off",
            "addrgenmode",
            "none",
        ]);
        if interface.vrf != DEFAULT_VRF {
            run(&[
                "link",
                "set",
                &tap,
                "master",
                &format!("vrf-{}", interface.vrf),
            ]);
        }
        run(&["link", "set", &tap, "up"]);
        let link_local = crate::link_local(interface.mac);
        let addresses = interface
            .ipv4
            .map(|(a, len)| (IpAddr::V4(a), len))
            .into_iter()
            .chain(std::iter::once((IpAddr::V6(link_local), 64)))
            .chain(
                interface
                    .ipv6
                    .iter()
                    .filter(|(a, _)| *a != link_local)
                    .map(|&(a, len)| (IpAddr::V6(a), len)),
            );
        for (address, len) in addresses {
            let with_len = format!("{address}/{len}");
            if address.is_ipv6() {
                run(&["address", "replace", &with_len, "dev", &tap, "nodad"]);
            } else {
                run(&["address", "replace", &with_len, "dev", &tap]);
            }
        }
        // NAT's outside: its prefix route (the kernel's own on the TAP) leaves from
        // the inside address, as on the TUN device above.
        let inside = nat_inside_address(config);
        let outside = config
            .nat
            .as_ref()
            .is_some_and(|n| n.outside == interface.name);
        if let (Some(source), Some((address, len)), true) = (&inside, interface.ipv4, outside) {
            let prefix = format!(
                "{}/{len}",
                ruster_proto::table::network(IpAddr::V4(address), len)
            );
            run(&[
                "-4", "route", "replace", &prefix, "dev", &tap, "src", source,
            ]);
        }
    }
    out
}

/// The address of NAT's inside interface, which the router's own IPv4 leaves from.
fn nat_inside_address(config: &Config) -> Option<String> {
    let nat = config.nat.as_ref()?;
    let inside = config
        .interfaces
        .iter()
        .find(|i| i.name == nat.inside && i.enabled)?;
    inside.ipv4.map(|(address, _)| address.to_string())
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
    // TAP devices no interface needs any more.
    let wanted_taps: Vec<String> = tap_interfaces(config)
        .iter()
        .map(|i| ruster_config::tap_device(&i.name))
        .collect();
    if let Ok(devices) = std::fs::read_dir("/sys/class/net") {
        for device in devices.flatten() {
            let name = device.file_name().to_string_lossy().into_owned();
            if name.starts_with(ruster_config::TAP_PREFIX) && !wanted_taps.contains(&name) {
                if let Err(stderr) = ip(&["link", "del", &name]) {
                    errors.push(format!("ip link del {name}: {}", stderr.trim()));
                }
            }
        }
    }
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
    // Packets to a TAP device's addresses come in through the TUN device: reverse
    // path filtering is loose (the larger of `all` and the device's counts), and
    // a TAP device sends no Router Solicitation.
    let mut sysctl = |path: String, value: &str| {
        if let Err(error) = std::fs::write(&path, value) {
            errors.push(format!("{path}: {error}"));
        }
    };
    if std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter")
        .is_ok_and(|v| v.trim() == "1")
    {
        sysctl("/proc/sys/net/ipv4/conf/all/rp_filter".into(), "2");
    }
    for device in wanted_addresses(&commands).into_keys() {
        sysctl(format!("/proc/sys/net/ipv4/conf/{device}/rp_filter"), "2");
        if device.starts_with(ruster_config::TAP_PREFIX) {
            sysctl(format!("/proc/sys/net/ipv6/conf/{device}/accept_ra"), "0");
        }
    }
    for (tun, wanted) in wanted_addresses(&commands) {
        let promote = format!("/proc/sys/net/ipv4/conf/{tun}/promote_secondaries");
        let _ = std::fs::write(promote, "1");
        for present in addresses_of(&tun) {
            // A TUN device's link-local addresses are the kernel's; a TAP device's
            // is its interface's, from the MAC address.
            let tap = tun.starts_with(ruster_config::TAP_PREFIX);
            if !wanted.contains(&present) && (tap || !present.starts_with("fe80:")) {
                if let Err(stderr) = ip(&["address", "del", &present, "dev", &tun]) {
                    errors.push(format!(
                        "ip address del {present} dev {tun}: {}",
                        stderr.trim()
                    ));
                }
            }
        }
    }
    // Every address before any route: a route's `src` must be an address the
    // kernel has (NAT's inside address may be on a TAP device, set up after the
    // TUN device's routes in `commands`).
    let is_address = |w: &[&str]| matches!(w, ["address", ..]);
    for args in commands.iter().filter(|a| is_address(&words(a))) {
        run(args, &mut errors);
    }
    for args in commands
        .iter()
        .filter(|a| !is_device(&words(a)) && !is_address(&words(a)))
    {
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
            ["tuntap", "add", "mode", "tun" | "tap", "dev", tun] => {
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
