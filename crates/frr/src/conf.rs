//! FRR's configuration from confd's `frr` part, and having FRR apply it.
//!
//! `ruster-frr` writes the whole of FRR's integrated configuration file
//! (`frr.conf`), in this order:
//!
//! 1. zebra's FPM settings: `fpm address 127.0.0.1 port <port>`, where `ruster-frr`
//!    listens (without `port` for FRR's default 2620, as FRR shows it, so a reload
//!    does not change it and zebra does not connect again), and `no fpm use-next-hop-groups`, so each route carries its next
//!    hops ([`crate::fpm`]). zebra must be started with `-M dplane_fpm_nl` (in
//!    `/etc/frr/daemons`).
//! 2. With `bgp`: the import and export policies, prefix lists and route maps named
//!    `ruster-*`, and `router bgp` with the router ID, the neighbors, and per address
//!    family the networks and the neighbors of that family.
//! 3. The operator's include file, as it is. It comes last, so it may add to what is
//!    above (more settings in `router bgp` or for a neighbor, logging, passwords);
//!    `ruster-frr` does not read it. It should not give again a setting written
//!    above with another value (a second inbound route map for a neighbor):
//!    `frr-reload.py` applies differences line by line, and which of the two holds
//!    after a reload is not certain. A changed include file is read when confd next
//!    sends the part.
//!
//! The policies: every neighbor takes every route (`route-map ruster-in`, which also
//! prefers an IPv6 next hop's global address to its link-local one, since a
//! link-local address does not say which FE interface it is on) and is sent only the
//! configured networks of its family (`route-map ruster-out` for IPv4,
//! `ruster-out-v6-<n>` for the n-th IPv6 neighbor), so routes learned from one
//! neighbor are not passed to another. An IPv6 neighbor's map also gives the
//! link-local address of the FE interface it is on as the next hop's: bgpd would
//! give the kernel's TUN device's, which no FE port answers for, and it needs one
//! on the TUN to talk to a neighbor on the link at all. The networks are announced whether or not FRR has a
//! route for them (`no bgp network import-check`): FRR sees only the kernel's side,
//! not the routes of the FE.
//!
//! Then [`Bridge::take`] runs a command that has FRR apply the file
//! (`/usr/lib/frr/frr-reload.py --reload` with the file appended, unless told
//! otherwise). When it fails or takes longer than [`COMMAND_LIMIT`], the file before
//! is put back, the command runs once more, and the part is refused.
//!
//! # Standards
//!
//! - RFC 8212: eBGP routes are taken and sent only through an explicit policy (the
//!   `ruster-in` and `ruster-out` route maps).
//! - RFC 4760: an IPv4 neighbor is activated in IPv4 unicast, an IPv6 neighbor in
//!   IPv6 unicast.
//!
//! Deviations: none of BGP itself is here; FRR implements it.

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ruster_config::{Bgp, Connected};

/// The first line of the file.
pub const HEADER: &str =
    "! Written by ruster-frr from confd's frr part; it is replaced on each change.";
/// FRR's FPM port when none is given.
pub const FPM_PORT: u16 = 2620;
/// The largest include file read.
pub const INCLUDE_MAX: u64 = 1 << 20;

/// FRR's configuration for `bgp`, with FPM on `fpm_port` and the include file's
/// text. Each value is read as an address, prefix or number again, so nothing else
/// reaches the file but the include.
pub fn config(
    bgp: Option<&Bgp>,
    connected: &[Connected],
    include: &str,
    fpm_port: u16,
) -> Result<String, String> {
    let port = match fpm_port {
        FPM_PORT => String::new(),
        port => format!(" port {port}"),
    };
    let mut out = format!("{HEADER}\nfpm address 127.0.0.1{port}\nno fpm use-next-hop-groups\n");
    if let Some(bgp) = bgp {
        router_bgp(&mut out, bgp, connected)?;
    }
    out.push_str(include);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

/// The link-local address of the interface whose prefix holds `neighbor`.
fn link_local_for(neighbor: IpAddr, connected: &[Connected]) -> Option<std::net::Ipv6Addr> {
    connected.iter().find_map(|c| {
        let (network, len) = c.prefix.split_once('/')?;
        let network: IpAddr = network.parse().ok()?;
        let len: u8 = len.parse().ok()?;
        let on = network.is_ipv6() == neighbor.is_ipv6()
            && len <= 128
            && ruster_proto::table::network(neighbor, len) == network;
        on.then(|| c.link_local.parse().ok()).flatten()
    })
}

fn router_bgp(out: &mut String, bgp: &Bgp, connected: &[Connected]) -> Result<(), String> {
    let id: std::net::Ipv4Addr = bgp
        .router_id
        .parse()
        .map_err(|_| format!("router-id {:?} is not an IPv4 address", bgp.router_id))?;
    let mut networks: [Vec<String>; 2] = Default::default();
    for text in &bgp.networks {
        let (address, len) = text
            .split_once('/')
            .and_then(|(a, l)| Some((a.parse::<IpAddr>().ok()?, l.parse::<u8>().ok()?)))
            .filter(|(a, l)| *l <= if a.is_ipv4() { 32 } else { 128 })
            .ok_or_else(|| format!("network {text:?} is not a prefix"))?;
        networks[usize::from(address.is_ipv6())].push(format!("{address}/{len}"));
    }
    let mut neighbors: [Vec<IpAddr>; 2] = Default::default();
    let mut lines = String::new();
    for neighbor in &bgp.neighbor {
        let address: IpAddr = neighbor
            .address
            .parse()
            .map_err(|_| format!("neighbor {:?} is not an address", neighbor.address))?;
        neighbors[usize::from(address.is_ipv6())].push(address);
        let _ = writeln!(
            lines,
            " neighbor {address} remote-as {}",
            neighbor.remote_as
        );
        for text in &neighbor.description {
            if text.is_empty() || !text.bytes().all(|b| (b' '..=b'~').contains(&b)) {
                return Err(format!("neighbor {address}: description {text:?}"));
            }
            let _ = writeln!(lines, " neighbor {address} description {text}");
        }
    }
    for (family, (keyword, list)) in [("ip", "v4"), ("ipv6", "v6")].into_iter().enumerate() {
        for (at, prefix) in networks[family].iter().enumerate() {
            let _ = writeln!(
                out,
                "{keyword} prefix-list ruster-out-{list} seq {} permit {prefix}",
                (at + 1) * 5
            );
        }
    }
    out.push_str("route-map ruster-in permit 10\n set ipv6 next-hop prefer-global\nexit\n");
    if !networks[0].is_empty() {
        out.push_str(
            "route-map ruster-out permit 10\n match ip address prefix-list ruster-out-v4\nexit\n",
        );
    }
    out.push_str("route-map ruster-out deny 100\nexit\n");
    // An IPv6 neighbor on the link is given the FE interface's link-local address as
    // the next hop, not the kernel's TUN device's, which only the kernel has.
    let mut out_map = Vec::new();
    for (at, address) in neighbors[1].iter().enumerate() {
        let link_local = link_local_for(*address, connected)
            .ok_or_else(|| format!("neighbor {address}: on no interface's prefix"))?;
        let name = format!("ruster-out-v6-{}", at + 1);
        if !networks[1].is_empty() {
            let _ = writeln!(
                out,
                "route-map {name} permit 10\n match ipv6 address prefix-list ruster-out-v6\n set ipv6 next-hop local {link_local}\nexit"
            );
        }
        let _ = writeln!(out, "route-map {name} deny 100\nexit");
        out_map.push(name);
    }
    let _ = writeln!(out, "router bgp {}", bgp.asn);
    let _ = writeln!(out, " bgp router-id {id}");
    out.push_str(" no bgp default ipv4-unicast\n no bgp network import-check\n");
    out.push_str(&lines);
    for (family, name) in ["ipv4", "ipv6"].into_iter().enumerate() {
        if networks[family].is_empty() && neighbors[family].is_empty() {
            continue;
        }
        let _ = writeln!(out, " address-family {name} unicast");
        for prefix in &networks[family] {
            let _ = writeln!(out, "  network {prefix}");
        }
        for (at, address) in neighbors[family].iter().enumerate() {
            let out_name = match family {
                0 => "ruster-out",
                _ => &out_map[at],
            };
            let _ = writeln!(out, "  neighbor {address} activate");
            let _ = writeln!(out, "  neighbor {address} route-map ruster-in in");
            let _ = writeln!(out, "  neighbor {address} route-map {out_name} out");
        }
        out.push_str(" exit-address-family\n");
    }
    out.push_str("exit\n");
    Ok(())
}

/// How long the command may take; it is stopped after this and counts as failed.
/// The command and the run that puts the file before back fit together before confd
/// stops waiting for an answer (30 s).
pub const COMMAND_LIMIT: Duration = Duration::from_secs(12);

/// Writes FRR's configuration file and runs the command that has FRR apply it.
#[derive(Debug)]
pub struct Bridge {
    path: PathBuf,
    /// The program and its arguments; the file is added as the last argument.
    reload: Vec<String>,
    fpm_port: u16,
    /// Whether a part was taken since ruster-frr started.
    took: bool,
}

impl Bridge {
    pub fn new(path: PathBuf, reload: Vec<String>, fpm_port: u16) -> Self {
        Self {
            path,
            reload,
            fpm_port,
            took: false,
        }
    }

    /// What taking an `frr` part would change: the line diff of `frr.conf`, or the
    /// reason it would be refused. Nothing is written, and FRR is not asked; it may
    /// still refuse the file when it reads it. What follows the word `password` on a
    /// line is not shown (the include may hold passwords), so a changed password
    /// shows as no change.
    pub fn check(&self, part: &str) -> Result<String, String> {
        let (bgp, connected) = ruster_config::parse_frr_part(part)?;
        let include = match bgp.as_ref().and_then(|b| b.include.first()) {
            Some(path) => read_include(path)?,
            None => String::new(),
        };
        let text = config(bgp.as_ref(), &connected, &include, self.fpm_port)?;
        let before = match std::fs::read_to_string(&self.path) {
            Ok(before) => before,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(format!("{}: {error}", self.path.display())),
        };
        let name = self.path.display().to_string();
        Ok(ruster_confd::diff::lines(
            &hide_passwords(&before),
            &hide_passwords(&text),
            (&name, "candidate"),
        ))
    }

    /// Takes an `frr` part ([`ruster_config::frr_part`]), or refuses it with the
    /// reason; the interfaces' prefixes in it, for the next hops.
    pub fn take(&mut self, part: &str) -> Result<Vec<Connected>, String> {
        let (bgp, connected) = ruster_config::parse_frr_part(part)?;
        let include = match bgp.as_ref().and_then(|b| b.include.first()) {
            Some(path) => read_include(path)?,
            None => String::new(),
        };
        let text = config(bgp.as_ref(), &connected, &include, self.fpm_port)?;
        let before = match std::fs::read_to_string(&self.path) {
            Ok(before) => Some(before),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("{}: {error}", self.path.display())),
        };
        // After a start, the command runs even for the file it finds: FRR may not
        // have applied it (ruster-frr may have stopped between the two).
        if self.took && before.as_deref() == Some(text.as_str()) {
            return Ok(connected);
        }
        if before.as_deref() != Some(text.as_str()) {
            self.write(&text)?;
        }
        if let Err(error) = self.run_reload() {
            // FRR may hold part of the new configuration now; it is applied again
            // on the next part, even one the file already holds.
            self.took = false;
            // With no file before, FRR is brought back to one without bgp.
            let before = match before {
                Some(before) => before,
                None => config(None, &[], "", self.fpm_port)?,
            };
            let put_back = self.write(&before);
            if let Err(again) = put_back.and_then(|()| self.run_reload()) {
                eprintln!("ruster-frr: putting the file before back: {again}");
            }
            return Err(error);
        }
        self.took = true;
        Ok(connected)
    }

    fn write(&self, text: &str) -> Result<(), String> {
        let mut next = self.path.clone().into_os_string();
        next.push(".next");
        let at = |e: std::io::Error| format!("{}: {e}", self.path.display());
        // Not for everyone to read: the include may hold passwords. It keeps the
        // owner of the file before.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o640)
            .open(&next)
            .map_err(at)?;
        std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o640)).map_err(at)?;
        if let Ok(old) = std::fs::metadata(&self.path) {
            std::os::unix::fs::chown(&next, Some(old.uid()), Some(old.gid())).map_err(at)?;
        }
        file.write_all(text.as_bytes()).map_err(at)?;
        drop(file);
        std::fs::rename(&next, &self.path).map_err(at)
    }

    fn run_reload(&self) -> Result<(), String> {
        let Some((program, args)) = self.reload.split_first() else {
            return Ok(());
        };
        let command = format!("{} {}", self.reload.join(" "), self.path.display());
        // frr-reload.py says why it failed on its standard output: both are read.
        let (mut reader, writer) = std::io::pipe().map_err(|e| e.to_string())?;
        let mut child = Command::new(program)
            .args(args)
            .arg(&self.path)
            .stdin(Stdio::null())
            .stdout(writer.try_clone().map_err(|e| e.to_string())?)
            .stderr(writer)
            // Its own process group, so that a command stopped for taking too long
            // takes the programs it started (vtysh) with it.
            .process_group(0)
            .spawn()
            .map_err(|e| format!("{program}: {e}"))?;
        // Read while it runs, so a full pipe never holds the command up.
        let (said_tx, said_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut said = Vec::new();
            let _ = std::io::copy(&mut (&mut reader).take(4_096), &mut said);
            let _ = said_tx.send(said);
            let _ = std::io::copy(&mut reader, &mut std::io::sink());
        });
        let stop = |child: &mut std::process::Child| {
            let _ = Command::new("kill")
                .args(["-KILL", "--", &format!("-{}", child.id())])
                .stderr(Stdio::null())
                .status();
            let _ = child.kill();
            let _ = child.wait();
        };
        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if start.elapsed() < COMMAND_LIMIT => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    stop(&mut child);
                    return Err(format!("{command} took longer than {COMMAND_LIMIT:?}"));
                }
                Err(error) => {
                    stop(&mut child);
                    return Err(format!("{command}: {error}"));
                }
            }
        };
        if status.success() {
            return Ok(());
        }
        // What it said, unless something it left running holds the pipe.
        let said = said_rx
            .recv_timeout(Duration::from_secs(1))
            .map(|said| String::from_utf8_lossy(&said).into_owned())
            .unwrap_or_default();
        Err(format!("{command} failed ({status}): {}", said.trim()))
    }
}

/// The include file's text, of at most [`INCLUDE_MAX`] bytes.
fn read_include(path: &str) -> Result<String, String> {
    let at = |e: std::io::Error| format!("include {path}: {e}");
    let file = std::fs::File::open(path).map_err(at)?;
    let mut text = String::new();
    let read = file
        .take(INCLUDE_MAX + 1)
        .read_to_string(&mut text)
        .map_err(at)?;
    if read as u64 > INCLUDE_MAX {
        return Err(format!("include {path}: larger than {INCLUDE_MAX} bytes"));
    }
    Ok(text)
}

/// `text` with what follows the word `password` on each line replaced by `(hidden)`.
fn hide_passwords(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.iter().position(|w| *w == "password") {
            Some(at) => {
                let indent = &line[..line.len() - line.trim_start().len()];
                out.push_str(indent);
                out.push_str(&words[..=at].join(" "));
                out.push_str(" (hidden)");
            }
            None => out.push_str(line),
        }
        out.push('\n');
    }
    out
}
