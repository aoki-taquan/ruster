//! `ruster`: the command line for a running router.
//!
//! ```text
//! ruster check FILE                       check a configuration file as confd reads it
//! ruster [--run-dir DIR] apply FILE       check it, then make it confd's configuration
//! ruster [--run-dir DIR] show             print every table the FE holds
//! ruster [--run-dir DIR] route add --source NAME [--vrf VRF] PREFIX dev IFACE [via ADDR]
//! ruster [--run-dir DIR] route del --source NAME [--vrf VRF] PREFIX
//! ```
//!
//! `apply` sends the file to confd, which sends what changed to the FE, ribd and neighd
//! and answers once they have answered. If one of them refuses, confd puts the
//! configuration it had before back ([`ruster_confd::apply`]).
//!
//! `route` writes to ribd as the route source NAME, the way a routing daemon does
//! (ribd must have been started with that source). ribd picks between sources by
//! preference and sends the result to the FE.

use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use ruster_proto::coap::Code;
use ruster_proto::daemon::{self, socket};
use ruster_proto::session::{decode_changes, Client, Event};
use ruster_proto::table::{
    format_mac, network, Change, Key, NextHop, RouteAction, Value, WireguardSession, DEFAULT_VRF,
};

const WAIT: Duration = Duration::from_secs(5);

const USAGE: &str = "usage:
  ruster check FILE
  ruster [--run-dir DIR] apply FILE
  ruster [--run-dir DIR] show
  ruster [--run-dir DIR] route add --source NAME [--vrf VRF] PREFIX dev IFACE [via ADDR]
  ruster [--run-dir DIR] route del --source NAME [--vrf VRF] PREFIX
  ruster [--run-dir DIR] wireguard session add IFACE PEER PEER_INDEX LOCAL_INDEX
      (the send and receive keys come from standard input: two lines of 64 hex digits)
  ruster [--run-dir DIR] wireguard session del IFACE PEER";

/// Sends one request and waits for its answer.
fn request(
    path: &Path,
    send: impl FnOnce(&mut Client) -> Result<u32, String>,
) -> Result<(Code, Vec<u8>), String> {
    let stream = UnixStream::connect(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut client = Client::new(stream).map_err(|e| e.to_string())?;
    let token = send(&mut client)?;
    let start = Instant::now();
    while start.elapsed() < WAIT {
        let (_, events) = client.poll();
        for event in events {
            if let Event::Response {
                token: t,
                code,
                payload,
            } = event
            {
                if t == token {
                    // One more poll sends anything still queued (sync-done).
                    client.poll();
                    return Ok((code, payload));
                }
            }
        }
        if client.is_closed() {
            return Err(format!("{}: closed", path.display()));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Err(format!("{}: no answer", path.display()))
}

/// One table entry as a line of text.
fn line(change: &Change) -> String {
    let Some(value) = &change.value else {
        return String::new();
    };
    match (&change.key, value) {
        (
            Key::Interface { name },
            Value::Interface {
                enabled,
                mac,
                mtu,
                vrf,
                vlan,
                tunnel,
                pppoe,
            },
        ) => format!(
            "interface {name} {} mac {} mtu {mtu} vrf {vrf}{}{}{}",
            if *enabled { "up" } else { "down" },
            format_mac(mac),
            vlan.as_ref()
                .map(|v| format!(" vlan {} on {}", v.id, v.parent))
                .unwrap_or_default(),
            tunnel
                .as_ref()
                .map(|t| format!(" tunnel {} to {}", t.local, t.remote))
                .unwrap_or_default(),
            pppoe
                .as_ref()
                .map(|p| format!(
                    " pppoe session {} on {} to {}",
                    p.session,
                    p.parent,
                    format_mac(&p.peer)
                ))
                .unwrap_or_default()
        ),
        (Key::Address { interface, address }, Value::Address { prefix_len }) => {
            format!("address {interface} {address}/{prefix_len}")
        }
        (Key::Route { vrf, prefix, len }, Value::Route(action)) => {
            let action = match action {
                RouteAction::Forward(hops) => hops
                    .iter()
                    .map(|hop| match hop.address {
                        Some(via) => format!("via {via} dev {}", hop.interface),
                        None => format!("dev {}", hop.interface),
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
                RouteAction::Local => "local".into(),
                RouteAction::Discard => "discard".into(),
                RouteAction::Reject => "reject".into(),
                RouteAction::LookupVrf(other) => format!("lookup-vrf {other}"),
            };
            format!("route {vrf} {prefix}/{len} {action}")
        }
        (Key::Neighbor { interface, address }, Value::Neighbor { mac }) => {
            format!("neighbor {interface} {address} {}", format_mac(mac))
        }
        _ => String::new(),
    }
}

fn show(run_dir: &Path) -> Result<(), String> {
    let (code, payload) = request(&run_dir.join(socket::FE_STATE), |c| Ok(c.get_all()))?;
    if code != Code::CONTENT {
        return Err(format!("the FE answered {code:?}"));
    }
    let changes = decode_changes(&payload).map_err(|e| e.to_string())?;
    let mut lines: Vec<String> = changes.iter().map(line).filter(|l| !l.is_empty()).collect();
    lines.sort();
    for line in lines {
        println!("{line}");
    }
    Ok(())
}

fn prefix(text: &str) -> Result<(IpAddr, u8), String> {
    let bad = || format!("{text}: not a prefix like 10.0.0.0/8");
    let (address, len) = text.split_once('/').ok_or_else(bad)?;
    let address: IpAddr = address.parse().map_err(|_| bad())?;
    let len: u8 = len.parse().map_err(|_| bad())?;
    if len > ruster_proto::table::max_len(&address) || network(address, len) != address {
        return Err(bad());
    }
    Ok((address, len))
}

fn route(run_dir: &Path, args: &[String]) -> Result<(), String> {
    let (op, rest) = args.split_first().ok_or(USAGE)?;
    let mut source = None;
    let mut vrf = DEFAULT_VRF.to_owned();
    let mut words = Vec::new();
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--source" => source = it.next().cloned(),
            "--vrf" => vrf = it.next().cloned().ok_or(USAGE)?,
            _ => words.push(arg.as_str()),
        }
    }
    let source = source.ok_or("route needs --source NAME")?;
    let (prefix, len) = prefix(words.first().ok_or(USAGE)?)?;
    let key = Key::Route { vrf, prefix, len };
    let change = match (op.as_str(), &words[1..]) {
        ("add", ["dev", interface]) | ("add", ["dev", interface, "via", _]) => {
            let via = match words.get(4) {
                Some(text) => Some(
                    text.parse::<IpAddr>()
                        .map_err(|_| format!("{text}: not an address"))?,
                ),
                None => None,
            };
            Change::set(
                key,
                Value::Route(RouteAction::Forward(vec![NextHop {
                    interface: (*interface).to_owned(),
                    address: via,
                }])),
            )
        }
        ("del", []) => Change::delete(key),
        _ => return Err(USAGE.into()),
    };
    change.validate().map_err(|e| e.to_string())?;
    let path = run_dir.join(socket::ribd_source(&source));
    let (code, _) = request(&path, |c| {
        let token = c.patch(&[change]).map_err(|e| e.to_string())?;
        c.sync_done();
        Ok(token)
    })?;
    if code.class() != 2 {
        return Err(format!("ribd refused the change ({code:?})"));
    }
    Ok(())
}

/// 32 bytes from 64 hex digits.
fn hex32(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("a key must be 64 hex digits".to_owned());
    }
    let mut out = [0_u8; 32];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// Writes or deletes a WireGuard session, as the key exchange daemon does. The keys
/// come from standard input, so that they are not on a command line.
fn wireguard(run_dir: &Path, args: &[String]) -> Result<(), String> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let change = match words[..] {
        ["session", "add", interface, peer, peer_index, local_index] => {
            let index = |text: &str| {
                text.parse::<u32>()
                    .map_err(|_| format!("{text}: not an index"))
            };
            let mut lines = std::io::stdin().lines();
            let mut key = || -> Result<[u8; 32], String> {
                let line = lines
                    .next()
                    .ok_or("the keys come from standard input")?
                    .map_err(|e| e.to_string())?;
                hex32(line.trim())
            };
            let (send, receive) = (key()?, key()?);
            Change::set(
                Key::WireguardSession {
                    interface: interface.to_owned(),
                    peer: peer.to_owned(),
                },
                Value::WireguardSession(WireguardSession {
                    send,
                    receive,
                    peer_index: index(peer_index)?,
                    local_index: index(local_index)?,
                }),
            )
        }
        ["session", "del", interface, peer] => Change::delete(Key::WireguardSession {
            interface: interface.to_owned(),
            peer: peer.to_owned(),
        }),
        _ => return Err(USAGE.into()),
    };
    change.validate().map_err(|e| e.to_string())?;
    let path = run_dir.join(socket::CONFD_WIREGUARD_KEYS);
    let (code, payload) = request(&path, |c| c.patch(&[change]).map_err(|e| e.to_string()))?;
    if code.class() != 2 {
        return Err(format!(
            "confd refused the session: {}",
            String::from_utf8_lossy(&payload)
        ));
    }
    Ok(())
}

fn check(path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let config = ruster_confd::file::parse(&text).map_err(|e| format!("{path}: {e}"))?;
    println!(
        "{path}: ok ({} interfaces, {} routes)",
        config.interfaces.len(),
        config.static_routes.len()
    );
    Ok(())
}

fn apply(run_dir: &Path, path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    ruster_confd::file::parse(&text).map_err(|e| format!("{path}: {e}"))?;
    let socket = run_dir.join(socket::CONFD_CONFIG);
    let (code, payload) = request(&socket, |c| Ok(c.post(&["config"], text.as_bytes())))?;
    let said = String::from_utf8_lossy(&payload);
    match code.class() {
        2 => {}
        4 => return Err(format!("{path}: not applied: {said}")),
        // A timeout leaves the new configuration in confd; the text says so.
        _ => return Err(format!("{path}: {said}")),
    }
    println!("{path}: applied");
    if !said.is_empty() {
        println!("{said}");
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let (run_dir, rest) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    match rest.split_first() {
        Some((command, args)) => match (command.as_str(), args) {
            ("check", [file]) => check(file),
            ("apply", [file]) => apply(&run_dir, file),
            ("show", []) => show(&run_dir),
            ("route", args) => route(&run_dir, args),
            ("wireguard", args) => wireguard(&run_dir, args),
            _ => Err(USAGE.into()),
        },
        None => Err(USAGE.into()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ruster: {error}");
            ExitCode::from(2)
        }
    }
}
