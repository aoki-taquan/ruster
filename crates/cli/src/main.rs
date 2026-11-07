//! `ruster`: the command line for a running router.
//!
//! ```text
//! ruster check FILE                       check a configuration file as confd reads it
//! ruster [--run-dir DIR] show             print every table the FE holds
//! ruster [--run-dir DIR] route add --source NAME [--vrf VRF] PREFIX dev IFACE [via ADDR]
//! ruster [--run-dir DIR] route del --source NAME [--vrf VRF] PREFIX
//! ```
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
    format_mac, network, Change, Key, NextHop, RouteAction, Value, DEFAULT_VRF,
};

const WAIT: Duration = Duration::from_secs(5);

const USAGE: &str = "usage:
  ruster check FILE
  ruster [--run-dir DIR] show
  ruster [--run-dir DIR] route add --source NAME [--vrf VRF] PREFIX dev IFACE [via ADDR]
  ruster [--run-dir DIR] route del --source NAME [--vrf VRF] PREFIX";

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
            },
        ) => format!(
            "interface {name} {} mac {} mtu {mtu} vrf {vrf}{}",
            if *enabled { "up" } else { "down" },
            format_mac(mac),
            vlan.as_ref()
                .map(|v| format!(" vlan {} on {}", v.id, v.parent))
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

fn run() -> Result<(), String> {
    let (run_dir, rest) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    match rest.split_first() {
        Some((command, args)) => match (command.as_str(), args) {
            ("check", [file]) => check(file),
            ("show", []) => show(&run_dir),
            ("route", args) => route(&run_dir, args),
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
