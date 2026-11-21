//! bird-rs's configuration from confd's `bird` part, and having bird-rs apply it.
//!
//! `ruster-bird` writes the whole of bird-rs's configuration file, in this order:
//!
//! 1. `router id` (with `bgp`), and `protocol device`.
//! 2. With `bgp`: a `protocol static` per address family that holds the configured
//!    networks (as unreachable routes, so that they are announced whether or not a
//!    route for them is known), and a `protocol bgp` per neighbor with the channel of
//!    its family. Every neighbor takes every route and is sent only the networks of
//!    its family, so routes learned from one neighbor are not passed to another. An
//!    IPv6 neighbor prefers the global next hop of a route it takes (a link-local one
//!    does not say which FE interface it is on), and is given the link-local address
//!    of the FE interface it is on as the next hop's (bird-rs would give the kernel's
//!    TUN device's, which no FE port answers for).
//! 3. With `bgp`: `protocol ruster`, which gives ribd the BGP routes as the source
//!    [`SOURCE`] under the run directory.
//! 4. The operator's include file, as it is (bird-rs's syntax). `ruster-bird` does
//!    not read it.
//!
//! The routes are not given to the kernel (`protocol kernel`): the FE forwards by
//! ribd's choice, and the router's own packets reach it through the TUN device.
//!
//! [`Bridge::take`] checks the file with `birdc configure check` before it puts it in
//! place, then has bird-rs read it with `birdc configure`. bird-rs keeps the
//! configuration before when it cannot read a file, so a refused part changes
//! nothing.
//!
//! With a neighbor of `evpn = true`, also the EVPN parts: the router's addresses on
//! the TUN device in tables of their own (`protocol direct ruster_tun`, which the
//! EVPN channels resolve next hops through), the EVPN and Ethernet tables, the
//! `protocol evpn` of the VNI, an `evpn` channel on those neighbors, and in
//! `protocol ruster` the bridge's learned addresses (`eth`) and the EVPN routes of
//! the VNI's route target (`evpn`). Turning EVPN on or off restarts `protocol
//! ruster` and those sessions (bird-rs restarts a protocol whose channels change):
//! ribd gets the routes again.
//!
//! # Standards
//!
//! - RFC 8212: eBGP routes are taken and sent only through an explicit policy (the
//!   channels' import and export filters).
//! - RFC 4760: an IPv4 neighbor carries IPv4 unicast, an IPv6 neighbor IPv6 unicast;
//!   an EVPN neighbor also l2vpn evpn (RFC 7432).
//! - RFC 7432 section 7.9: the RD is of type 1, `<router-id>:<VNI>`. RFC 8365 section
//!   5.1.2.1: the route target is `<AS>:<VNI>`. RFC 9252 section 6: over SRv6 the
//!   router's End.DT2U and End.DT2M SIDs.
//!
//! Deviations: none of BGP itself is here; bird-rs implements it. A remote VTEP
//! resolves only on a connected prefix of the default VRF (the EVPN next hops are
//! looked up in the TUN device's tables alone). One EVPN instance (VNI) per router; a VNI above 65535 does not fit the RD's number and is
//! refused, as is a route target of a four-octet AS with such a VNI.

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv6Addr};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ruster_config::{Bgp, Connected, EvpnVni, Frr};

/// The first line of the file.
pub const HEADER: &str =
    "# Written by ruster-bird from confd's bird part; it is replaced on each change.";
/// The route source's name at ribd.
pub const SOURCE: &str = "bird";
/// The largest include file read.
pub const INCLUDE_MAX: u64 = 1 << 20;

/// bird-rs's configuration for the part `routing`, with ruster's run directory
/// `run_dir` and the include file's text. Each value is read as an address, prefix
/// or number again, so nothing else reaches the file but the include.
pub fn config(routing: &Frr, include: &str, run_dir: &str) -> Result<String, String> {
    // Refused rather than left out: the operator would believe they run.
    if routing.isis.is_some() || routing.ospf.is_some() || routing.ospf6.is_some() {
        return Err("isis, ospf and ospf6 are not run through ruster-bird yet".into());
    }
    let mut out = format!("{HEADER}\n");
    if let Some(bgp) = &routing.bgp {
        let id: std::net::Ipv4Addr = bgp
            .router_id
            .parse()
            .map_err(|_| format!("router-id {:?} is not an IPv4 address", bgp.router_id))?;
        let _ = writeln!(out, "router id {id};");
    }
    out.push_str("protocol device {}\n");
    if let Some(bgp) = &routing.bgp {
        let evpn = evpn_of(bgp, &routing.evpn)?;
        if let Some(vni) = evpn {
            write_evpn(&mut out, bgp, vni)?;
        }
        write_bgp(&mut out, bgp, &routing.connected, evpn)?;
        if run_dir.is_empty() || run_dir.contains(['"', '\\', '\n']) {
            return Err(format!("run directory {run_dir:?}"));
        }
        let _ = write!(
            out,
            "protocol ruster {{\n  run dir \"{run_dir}\";\n  source \"{SOURCE}\";\n  \
             ipv4 {{ export where source = RTS_BGP; }};\n  \
             ipv6 {{ export where source = RTS_BGP; }};\n"
        );
        if let Some(vni) = evpn {
            let n = vni.vni;
            // Over SRv6 the label is a SID's function, not the VNI.
            let by_label = if vni.encapsulation == "srv6" {
                format!(" ruster vni {n};")
            } else {
                String::new()
            };
            let _ = write!(
                out,
                "  eth {{ table ruster_eth; export all; ruster bridge \"{}\"; }};\n  \
                 evpn {{ table ruster_evpn; export where (rt, {}, {n}) ~ bgp_ext_community;{by_label} }};\n",
                vni.bridge, bgp.asn
            );
        }
        out.push_str("}\n");
    }
    out.push_str(include);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

/// The link-local address of the interface whose prefix holds `neighbor`.
fn link_local_for(neighbor: IpAddr, connected: &[Connected]) -> Option<Ipv6Addr> {
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

/// The VNI of the EVPN sessions of `bgp`, when it has any: there is one (confd
/// checks it), of a name and addresses that fit the file.
fn evpn_of<'a>(bgp: &Bgp, vnis: &'a [EvpnVni]) -> Result<Option<&'a EvpnVni>, String> {
    if !bgp.neighbor.iter().any(|n| n.evpn) {
        return Ok(None);
    }
    let [vni] = vnis else {
        return Err(format!("evpn takes one VNI, not {}", vnis.len()));
    };
    let name_fits = !vni.bridge.is_empty()
        && vni
            .bridge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    // The RD `<router-id>:<VNI>` takes a two-octet number.
    if !name_fits || !(1..=0xffff).contains(&vni.vni) {
        return Err(format!("evpn: bridge {:?}, VNI {}", vni.bridge, vni.vni));
    }
    vni.router_address
        .parse::<IpAddr>()
        .map_err(|_| format!("evpn: router address {:?}", vni.router_address))?;
    for sid in vni.unicast_sid.iter().chain(&vni.multicast_sid) {
        sid.parse::<Ipv6Addr>()
            .map_err(|_| format!("evpn: SID {sid:?}"))?;
    }
    Ok(Some(vni))
}

/// The EVPN tables, the router's addresses on the default VRF's TUN device in
/// tables of their own (so that a remote VTEP's address resolves through them,
/// and they do not take the place of the networks announced, or of learned routes,
/// in the main tables), and the `protocol evpn` of the VNI: RD
/// `<router-id>:<VNI>` (RFC 7432 section 7.9, type 1), route target `<AS>:<VNI>`
/// (RFC 8365 section 5.1.2.1), VXLAN from its local address or SRv6 with its SIDs.
fn write_evpn(out: &mut String, bgp: &Bgp, vni: &EvpnVni) -> Result<(), String> {
    let n = vni.vni;
    let encapsulation = match (vni.encapsulation.as_str(), &vni.unicast_sid[..], &vni.multicast_sid[..]) {
        ("vxlan", [], []) => format!("encapsulation vxlan {{ router address {}; }}", vni.router_address),
        ("srv6", [unicast], [multicast]) => format!(
            "encapsulation srv6 {{ unicast sid {unicast}; multicast sid {multicast}; router address {}; }}",
            vni.router_address
        ),
        (other, ..) => return Err(format!("evpn: encapsulation {other:?}")),
    };
    let _ = writeln!(
        out,
        "ipv4 table ruster_tun4;\n\
         ipv6 table ruster_tun6;\n\
         protocol direct ruster_tun {{ ipv4 {{ table ruster_tun4; }}; ipv6 {{ table ruster_tun6; }}; \
         interface \"rt-default\"; }}\n\
         evpn table ruster_evpn;\n\
         eth table ruster_eth;\n\
         protocol evpn ruster_evpn_{n} {{\n  eth {{ table ruster_eth; }};\n  \
         evpn {{ table ruster_evpn; }};\n  {encapsulation};\n  rd {}:{n};\n  \
         route target (rt, {}, {n});\n  vni {n};\n}}",
        bgp.router_id, bgp.asn
    );
    Ok(())
}

fn write_bgp(
    out: &mut String,
    bgp: &Bgp,
    connected: &[Connected],
    evpn: Option<&EvpnVni>,
) -> Result<(), String> {
    let mut networks: [Vec<String>; 2] = Default::default();
    for text in &bgp.networks {
        let (address, len) = text
            .split_once('/')
            .and_then(|(a, l)| Some((a.parse::<IpAddr>().ok()?, l.parse::<u8>().ok()?)))
            .filter(|(a, l)| *l <= if a.is_ipv4() { 32 } else { 128 })
            .ok_or_else(|| format!("network {text:?} is not a prefix"))?;
        networks[usize::from(address.is_ipv6())].push(format!("{address}/{len}"));
    }
    for (family, channel) in ["ipv4", "ipv6"].into_iter().enumerate() {
        if networks[family].is_empty() {
            continue;
        }
        let _ = writeln!(
            out,
            "protocol static ruster_networks_{channel} {{\n  {channel};"
        );
        for prefix in &networks[family] {
            let _ = writeln!(out, "  route {prefix} unreachable;");
        }
        out.push_str("}\n");
    }
    for neighbor in &bgp.neighbor {
        let address: IpAddr = neighbor
            .address
            .parse()
            .map_err(|_| format!("neighbor {:?} is not an address", neighbor.address))?;
        let channel = if address.is_ipv4() { "ipv4" } else { "ipv6" };
        // Named by its address: another neighbor's coming or going restarts no
        // other session.
        let name: String = address
            .to_string()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let _ = writeln!(
            out,
            "protocol bgp ruster_neighbor_{name} {{\n  local as {};\n  neighbor {address} as {};",
            bgp.asn, neighbor.remote_as
        );
        for text in &neighbor.description {
            let fits = !text.is_empty()
                && text
                    .bytes()
                    .all(|b| (b' '..=b'~').contains(&b) && b != b'"' && b != b'\\');
            if !fits {
                return Err(format!("neighbor {address}: description {text:?}"));
            }
            let _ = writeln!(out, "  description \"{text}\";");
        }
        let export = if networks[usize::from(address.is_ipv6())].is_empty() {
            "none".to_owned()
        } else {
            format!("where proto = \"ruster_networks_{channel}\"")
        };
        let _ = write!(
            out,
            "  {channel} {{\n    import all;\n    export {export};\n"
        );
        if address.is_ipv6() {
            out.push_str("    next hop prefer global;\n");
            let link_local = link_local_for(address, connected)
                .ok_or_else(|| format!("neighbor {address}: on no interface's prefix"))?;
            let _ = writeln!(out, "    next hop link local {link_local};");
        }
        out.push_str("  };\n");
        // EVPN: everything taken, only this router's own routes sent.
        if let Some(vni) = evpn.filter(|_| neighbor.evpn) {
            let _ = writeln!(
                out,
                "  evpn {{\n    table ruster_evpn;\n    import all;\n    \
                 export where proto = \"ruster_evpn_{}\";\n    \
                 igp table ruster_tun4;\n    igp table ruster_tun6;\n  }};",
                vni.vni
            );
        }
        out.push_str("}\n");
    }
    Ok(())
}

/// How long a `birdc` command may take; it is stopped after this and counts as
/// failed. A take runs at most three (the check, the configure, and the configure
/// of the file put back), which fit together before confd stops waiting for an
/// answer (30 s).
pub const COMMAND_LIMIT: Duration = Duration::from_secs(9);

/// Writes bird-rs's configuration file and has bird-rs apply it.
#[derive(Debug)]
pub struct Bridge {
    path: PathBuf,
    /// The program and its arguments before the command (`birdc -s <socket>`).
    birdc: Vec<String>,
    /// ruster's run directory, for `protocol ruster`.
    run_dir: String,
    /// Whether a part was taken since ruster-bird started.
    took: bool,
}

impl Bridge {
    pub fn new(path: PathBuf, birdc: Vec<String>, run_dir: String) -> Self {
        Self {
            path,
            birdc,
            run_dir,
            took: false,
        }
    }

    fn text(&self, part: &str) -> Result<String, String> {
        let routing = ruster_config::parse_frr_part(part)?;
        let include = match routing.bgp.as_ref().and_then(|b| b.include.first()) {
            Some(path) => read_include(path)?,
            None => String::new(),
        };
        config(&routing, &include, &self.run_dir)
    }

    fn before(&self) -> Result<Option<String>, String> {
        match std::fs::read_to_string(&self.path) {
            Ok(before) => Ok(Some(before)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{}: {error}", self.path.display())),
        }
    }

    /// What taking a `bird` part would change: the line diff of the file, or the
    /// reason it would be refused. Nothing is written, and bird-rs is not asked.
    /// What follows a word of [`SECRET_WORDS`] on a line is not shown (the include
    /// may hold passwords); a line whose secret changes shows as `(hidden, changed)`.
    pub fn check(&self, part: &str) -> Result<String, String> {
        let text = self.text(part)?;
        let before = self.before()?.unwrap_or_default();
        let name = self.path.display().to_string();
        Ok(ruster_confd::diff::lines(
            &hide_secrets(&before, &before),
            &hide_secrets(&text, &before),
            (&name, "candidate"),
        ))
    }

    /// Takes a `bird` part, or refuses it with the reason: bird-rs checks the new
    /// file before it is put in place, and reads it then. When bird-rs does not
    /// take it after all, the file before is put back and read again.
    pub fn take(&mut self, part: &str) -> Result<(), String> {
        let text = self.text(part)?;
        let before = self.before()?;
        // After a start, bird-rs reads even the file it has: ruster-bird may have
        // stopped between writing it and bird-rs reading it.
        if self.took && before.as_deref() == Some(text.as_str()) {
            return Ok(());
        }
        let next = self.next();
        let quoted_next = quoted(&next)?;
        let quoted_path = quoted(&self.path)?;
        self.write_next(&text)?;
        if let Err(error) = self.birdc(&["configure", "check", &quoted_next]) {
            let _ = std::fs::remove_file(&next);
            return Err(error);
        }
        if let Err(error) = std::fs::rename(&next, &self.path) {
            let _ = std::fs::remove_file(&next);
            return Err(format!("{}: {error}", self.path.display()));
        }
        if let Err(error) = self.birdc(&["configure", &quoted_path]) {
            // bird-rs may hold the new file or the one before: it reads one again
            // on the next part, even one the file already holds.
            self.took = false;
            let before = match before {
                Some(before) => before,
                None => config(&Frr::default(), "", &self.run_dir)?,
            };
            let put_back = self
                .write_next(&before)
                .and_then(|()| {
                    std::fs::rename(&next, &self.path)
                        .map_err(|e| format!("{}: {e}", self.path.display()))
                })
                .and_then(|()| self.birdc(&["configure", &quoted_path]).map(drop));
            if let Err(again) = put_back {
                eprintln!("ruster-bird: putting the file before back: {again}");
            }
            return Err(error);
        }
        self.took = true;
        Ok(())
    }

    fn next(&self) -> PathBuf {
        let mut next = self.path.clone().into_os_string();
        next.push(".next");
        PathBuf::from(next)
    }

    /// Writes `text` to the file beside it that is put in place after the check.
    fn write_next(&self, text: &str) -> Result<(), String> {
        let next = self.next();
        let at = |e: std::io::Error| format!("{}: {e}", next.display());
        // Not for everyone to read: the include may hold passwords.
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
        file.write_all(text.as_bytes()).map_err(at)
    }

    /// Runs `birdc` with `command`; its answer when it succeeds (exit status 0:
    /// a reply code below 8000).
    fn birdc(&self, command: &[&str]) -> Result<String, String> {
        let Some((program, args)) = self.birdc.split_first() else {
            return Ok(String::new());
        };
        let (mut reader, writer) = std::io::pipe().map_err(|e| e.to_string())?;
        let mut child = Command::new(program)
            .args(args)
            .args(command)
            .stdin(Stdio::null())
            .stdout(writer.try_clone().map_err(|e| e.to_string())?)
            .stderr(writer)
            .spawn()
            .map_err(|e| format!("{program}: {e}"))?;
        let (said_tx, said_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut said = Vec::new();
            let _ = std::io::copy(&mut (&mut reader).take(4_096), &mut said);
            let _ = said_tx.send(said);
            let _ = std::io::copy(&mut reader, &mut std::io::sink());
        });
        let shown = format!("{} {}", self.birdc.join(" "), command.join(" "));
        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if start.elapsed() < COMMAND_LIMIT => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) | Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{shown} took longer than {COMMAND_LIMIT:?}"));
                }
            }
        };
        let said = said_rx
            .recv_timeout(Duration::from_secs(1))
            .map(|said| String::from_utf8_lossy(&said).trim().to_owned())
            .unwrap_or_default();
        if status.success() {
            Ok(said)
        } else {
            Err(format!("{shown} failed ({status}): {said}"))
        }
    }
}

/// `path` as a quoted string of bird-rs's command line.
fn quoted(path: &std::path::Path) -> Result<String, String> {
    let text = path.to_str().ok_or("the file's path is not UTF-8")?;
    if text.contains(['"', '\\', '\n']) {
        return Err(format!("the file's path {text:?}"));
    }
    Ok(format!("\"{text}\""))
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

/// The words after which bird-rs's configuration holds a secret.
pub const SECRET_WORDS: [&str; 3] = ["password", "secret", "key"];

/// `text` with what follows a word of [`SECRET_WORDS`] on each line replaced by
/// `(hidden)`, or by `(hidden, changed)` when the line is not in `before`.
fn hide_secrets(text: &str, before: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.iter().position(|w| SECRET_WORDS.contains(w)) {
            Some(at) => {
                let indent = &line[..line.len() - line.trim_start().len()];
                out.push_str(indent);
                out.push_str(&words[..=at].join(" "));
                if before.lines().any(|b| b == line) {
                    out.push_str(" (hidden)");
                } else {
                    out.push_str(" (hidden, changed)");
                }
            }
            None => out.push_str(line),
        }
        out.push('\n');
    }
    out
}
