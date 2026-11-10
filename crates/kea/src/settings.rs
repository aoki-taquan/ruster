//! Kea's settings for the `dhcp` part, and having Kea read them again.
//!
//! ruster-kea writes one file that the operator's `kea-dhcp4.conf` includes inside
//! its `Dhcp4` map (`<?include "FILE" ?>`, followed by a comma and the operator's
//! own members: the lease database, the control socket, logging). The file holds
//! two members:
//!
//! - `interfaces-config`: Kea listens only on the address ruster-kea relays to
//!   (`lo/127.0.0.1` unless told otherwise), with `dhcp-socket-type` `udp`, so Kea
//!   needs no raw sockets and no LAN port.
//! - `subnet4`: a subnet per `dhcp` entry, the interface's prefix. Kea picks it by
//!   the relay's address (`giaddr`), which is in it. Its id is the subnet's address
//!   as a number, so it stays the same when other entries come and go, and the
//!   leases stay with it. Each has the pool, the lease time, and the options
//!   `routers`, `domain-name-servers` and `dhcp-server-identifier`; the last is the
//!   interface's address, so that clients renew to the router's address on the
//!   LAN, which the FE hands to ruster-kea, rather than to Kea's own.
//!
//! Every value written is read again as an address, number or interface name, so
//! nothing else reaches the file.
//!
//! [`reload`] sends Kea `config-reload` on its control socket and reads the answer.
//!
//! # Standards
//!
//! - RFC 2132 sections 3.5 (routers), 3.8 (domain name servers), 9.2 (lease time)
//!   and 9.7 (server identifier): the options Kea is told to give.
//!
//! Deviations: none of DHCP itself is here; Kea implements it.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use ruster_config::Dhcp;

use crate::relay::Link;

/// The first line of the file.
pub const HEADER: &str =
    "// Written by ruster-kea from confd's dhcp part; it is replaced on each change.";

/// Where Kea listens: an interface and its IPv4 address, as Kea writes it
/// (`lo/127.0.0.1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listen {
    pub interface: String,
    pub address: Ipv4Addr,
}

impl Listen {
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = || format!("{text:?} is not like lo/127.0.0.1");
        let (interface, address) = text.split_once('/').ok_or_else(bad)?;
        let named = !interface.is_empty()
            && interface.len() <= 15
            && interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        if !named {
            return Err(bad());
        }
        Ok(Self {
            interface: interface.to_owned(),
            address: address.parse().map_err(|_| bad())?,
        })
    }
}

/// One `dhcp` entry, read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Served {
    pub link: Link,
    pub len: u8,
    pub pool: (Ipv4Addr, Ipv4Addr),
    pub lease_time: u32,
    pub router: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
}

/// Reads the `dhcp` entries of a part. confd checked them; this reads them again
/// so that only addresses and numbers are written.
pub fn read(dhcp: &[Dhcp]) -> Result<Vec<Served>, String> {
    dhcp.iter()
        .map(|entry| {
            let at = format!("dhcp {:?}", entry.interface);
            let address = |text: &str| {
                text.parse::<Ipv4Addr>()
                    .map_err(|_| format!("{at}: {text:?} is not an IPv4 address"))
            };
            let (own, len) = entry
                .address
                .split_once('/')
                .ok_or_else(|| format!("{at}: address has no prefix length"))?;
            let len: u8 = len
                .parse()
                .ok()
                .filter(|len| *len <= 32)
                .ok_or_else(|| format!("{at}: bad prefix length"))?;
            let (first, last) = entry
                .pool
                .split_once('-')
                .ok_or_else(|| format!("{at}: pool is not a range"))?;
            let mut mac = [0; 6];
            let mut parts = entry.mac.split(':');
            for byte in &mut mac {
                *byte = parts
                    .next()
                    .and_then(|p| u8::from_str_radix(p, 16).ok())
                    .ok_or_else(|| format!("{at}: bad mac"))?;
            }
            if entry.interface.is_empty() || entry.interface.len() > 255 {
                return Err(format!("{at}: bad interface name"));
            }
            Ok(Served {
                link: Link {
                    interface: entry.interface.clone(),
                    mac,
                    address: address(own)?,
                },
                len,
                pool: (address(first)?, address(last)?),
                lease_time: entry.lease_time,
                router: entry
                    .router
                    .iter()
                    .map(|a| address(a))
                    .collect::<Result<_, _>>()?,
                dns: entry
                    .dns
                    .iter()
                    .map(|a| address(a))
                    .collect::<Result<_, _>>()?,
            })
        })
        .collect()
}

/// The text of the included file.
pub fn settings(listen: &Listen, served: &[Served]) -> String {
    let mut out = format!("{HEADER}\n\"interfaces-config\": {{\n    \"interfaces\": [");
    if !served.is_empty() {
        let _ = write!(out, " \"{}/{}\" ", listen.interface, listen.address);
    }
    out.push_str("],\n    \"dhcp-socket-type\": \"udp\"\n},\n\"subnet4\": [");
    for (at, s) in served.iter().enumerate() {
        let mask = u32::MAX.checked_shl(32 - u32::from(s.len)).unwrap_or(0);
        let subnet = u32::from(s.link.address) & mask;
        let list = |addresses: &[Ipv4Addr]| {
            addresses
                .iter()
                .map(Ipv4Addr::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mut options = vec![("dhcp-server-identifier", s.link.address.to_string())];
        if !s.router.is_empty() {
            options.push(("routers", list(&s.router)));
        }
        if !s.dns.is_empty() {
            options.push(("domain-name-servers", list(&s.dns)));
        }
        let options = options
            .iter()
            .map(|(name, data)| format!("{{ \"name\": \"{name}\", \"data\": \"{data}\" }}"))
            .collect::<Vec<_>>()
            .join(",\n            ");
        let _ = write!(
            out,
            "{}\n    {{\n        \"id\": {subnet},\n        \"subnet\": \"{}/{}\",\n        \
             \"valid-lifetime\": {},\n        \
             \"pools\": [ {{ \"pool\": \"{} - {}\" }} ],\n        \
             \"option-data\": [\n            {options}\n        ]\n    }}",
            if at == 0 { "" } else { "," },
            Ipv4Addr::from(subnet),
            s.len,
            s.lease_time,
            s.pool.0,
            s.pool.1,
        );
    }
    out.push_str(if served.is_empty() { "]\n" } else { "\n]\n" });
    out
}

/// How long Kea may take to answer; the command and the one that puts the file
/// before back fit together before confd stops waiting for an answer (30 s).
pub const RELOAD_LIMIT: Duration = Duration::from_secs(12);

/// Has Kea read its configuration file again: `config-reload` on the control
/// socket at `path`. `Ok(false)` when Kea is not there (it reads the file when it
/// starts); an error when Kea answers that it could not take the file.
pub fn reload(path: &Path) -> Result<bool, String> {
    let at = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut stream = match UnixStream::connect(path) {
        Ok(stream) => stream,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(false)
        }
        Err(e) => return Err(at(e)),
    };
    stream.set_read_timeout(Some(RELOAD_LIMIT)).map_err(at)?;
    stream.set_write_timeout(Some(RELOAD_LIMIT)).map_err(at)?;
    stream
        .write_all(br#"{ "command": "config-reload" }"#)
        .map_err(at)?;
    let mut answer = Vec::new();
    let mut buf = [0; 4096];
    // Kea closes the connection after its answer; it is read until then, or until
    // it is a whole JSON object.
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                answer.extend_from_slice(&buf[..n]);
                if answer.len() > 1 << 20 || whole(&answer) {
                    break;
                }
            }
            Err(e) => return Err(at(e)),
        }
    }
    let answer = String::from_utf8_lossy(&answer);
    match result(&answer) {
        Some(0) => Ok(true),
        Some(_) => Err(format!("Kea refused the settings: {}", answer.trim())),
        None => Err(format!("Kea's answer has no result: {}", answer.trim())),
    }
}

/// Whether `bytes` holds a whole JSON object or list: its brackets, outside
/// strings, balance.
fn whole(bytes: &[u8]) -> bool {
    let (mut depth, mut string, mut escaped, mut seen) = (0_i64, false, false, false);
    for &b in bytes {
        if string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => string = true,
            b'{' | b'[' => {
                depth += 1;
                seen = true;
            }
            b'}' | b']' => depth -= 1,
            _ => {}
        }
    }
    seen && depth <= 0
}

/// The number after the first `"result":` in Kea's answer.
fn result(answer: &str) -> Option<i64> {
    let rest = &answer[answer.find("\"result\"")? + "\"result\"".len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '-'))
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_result_of_an_answer_is_read() {
        assert_eq!(
            result(r#"{ "arguments": { "hash": "AB" }, "result": 0, "text": "ok" }"#),
            Some(0)
        );
        assert_eq!(result(r#"[ { "result" : 1, "text": "no" } ]"#), Some(1));
        assert_eq!(result(r#"{ "text": "result" }"#), None);
        assert!(whole(br#"{ "text": "a } b", "result": 0 }"#));
        assert!(!whole(br#"{ "text": "a } b""#));
    }
}
