//! FRR's configuration from confd's `frr` part, and having FRR apply it.
//!
//! `ruster-frr` writes the whole of FRR's integrated configuration file
//! (`frr.conf`), in this order:
//!
//! 1. zebra's FPM settings: `fpm address 127.0.0.1 port <port>`, where `ruster-frr`
//!    listens, and `no fpm use-next-hop-groups`, so each route carries its next
//!    hops ([`crate::fpm`]). zebra must be started with `-M dplane_fpm_nl` (in
//!    `/etc/frr/daemons`).
//! 2. With `bgp`: the import and export policies, prefix lists and route maps named
//!    `ruster-*`, and `router bgp` with the router ID, the neighbors, and per address
//!    family the networks and the neighbors of that family.
//! 3. The operator's include file, as it is. It comes last, so it may add to what is
//!    above (more settings in `router bgp`, other route maps for a neighbor) or
//!    change it; `ruster-frr` does not read it. Logging, passwords and the like go
//!    there too.
//!
//! The policies: every neighbor takes every route (`route-map ruster-in`, which also
//! prefers an IPv6 next hop's global address to its link-local one, since a
//! link-local address does not say which FE interface it is on) and is sent only the
//! configured networks (`route-map ruster-out`), so routes learned from one neighbor
//! are not passed to another. The networks are announced whether or not FRR has a
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
use std::io::Read as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ruster_config::{Bgp, Connected};

/// The first line of the file.
pub const HEADER: &str =
    "! Written by ruster-frr from confd's frr part; it is replaced on each change.";
/// The largest include file read.
pub const INCLUDE_MAX: u64 = 1 << 20;

/// FRR's configuration for `bgp`, with FPM on `fpm_port` and the include file's
/// text. Each value is read as an address, prefix or number again, so nothing else
/// reaches the file but the include.
pub fn config(bgp: Option<&Bgp>, include: &str, fpm_port: u16) -> Result<String, String> {
    let mut out =
        format!("{HEADER}\nfpm address 127.0.0.1 port {fpm_port}\nno fpm use-next-hop-groups\n");
    if let Some(bgp) = bgp {
        router_bgp(&mut out, bgp)?;
    }
    out.push_str(include);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

fn router_bgp(out: &mut String, bgp: &Bgp) -> Result<(), String> {
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
    for (family, (keyword, list)) in [("ip", "v4"), ("ipv6", "v6")].into_iter().enumerate() {
        if !networks[family].is_empty() {
            let _ = writeln!(
                out,
                "route-map ruster-out permit {}\n match {keyword} address prefix-list ruster-out-{list}\nexit",
                (family + 1) * 10
            );
        }
    }
    out.push_str("route-map ruster-out deny 100\nexit\n");
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
        for address in &neighbors[family] {
            let _ = writeln!(out, "  neighbor {address} activate");
            let _ = writeln!(out, "  neighbor {address} route-map ruster-in in");
            let _ = writeln!(out, "  neighbor {address} route-map ruster-out out");
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

    /// Takes an `frr` part ([`ruster_config::frr_part`]), or refuses it with the
    /// reason; the interfaces' prefixes in it, for the next hops.
    pub fn take(&mut self, part: &str) -> Result<Vec<Connected>, String> {
        let (bgp, connected) = ruster_config::parse_frr_part(part)?;
        let include = match bgp.as_ref().and_then(|b| b.include.first()) {
            Some(path) => read_include(path)?,
            None => String::new(),
        };
        let text = config(bgp.as_ref(), &include, self.fpm_port)?;
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
            let put_back = match &before {
                Some(before) => self.write(before),
                None => std::fs::remove_file(&self.path).map_err(|e| e.to_string()),
            };
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
        std::fs::write(&next, text).map_err(at)?;
        std::fs::rename(&next, &self.path).map_err(at)
    }

    fn run_reload(&self) -> Result<(), String> {
        let Some((program, args)) = self.reload.split_first() else {
            return Ok(());
        };
        let command = format!("{} {}", self.reload.join(" "), self.path.display());
        let mut child = Command::new(program)
            .args(args)
            .arg(&self.path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{program}: {e}"))?;
        // Read while it runs, so a full pipe never holds the command up.
        let stderr = child.stderr.take().map(|stderr| {
            std::thread::spawn(move || {
                let mut stderr = stderr;
                let mut said = Vec::new();
                let _ = std::io::copy(&mut (&mut stderr).take(4_096), &mut said);
                let _ = std::io::copy(&mut stderr, &mut std::io::sink());
                said
            })
        });
        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if start.elapsed() < COMMAND_LIMIT => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{command} took longer than {COMMAND_LIMIT:?}"));
                }
                Err(error) => return Err(format!("{command}: {error}")),
            }
        };
        if status.success() {
            return Ok(());
        }
        let said = stderr
            .and_then(|reader| reader.join().ok())
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
