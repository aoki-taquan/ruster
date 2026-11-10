//! `ruster`: the command line for a running router.
//!
//! ```text
//! ruster check FILE                       check a configuration file as confd reads it
//! ruster resolve FILE                     print a ruster.toml in the lock form
//! ruster [--run-dir DIR] apply FILE       check it, then make it confd's configuration
//! ruster [--run-dir DIR] versions         list the versions confd keeps, newest first
//! ruster [--run-dir DIR] rollback N       make version N the configuration again
//! ruster [--run-dir DIR] show             print every table the FE holds
//! ruster [--run-dir DIR] route add --source NAME [--vrf VRF] PREFIX dev IFACE [via ADDR]
//! ruster [--run-dir DIR] route del --source NAME [--vrf VRF] PREFIX
//! ruster [--run-dir DIR] source NAME [--lifetime SECONDS] [pppoe SESSION PEER MTU] [ipv4 ADDRESS/LEN]
//! ```
//!
//! `apply` sends the file to confd, which sends what changed to the FE, ribd and neighd
//! and answers once they have answered. If one of them refuses, confd puts the
//! configuration it had before back ([`ruster_confd::apply`]). Otherwise confd keeps it
//! as the next version ([`ruster_confd::versions`]). `rollback N` goes the same way
//! with version N's configuration, which becomes a new version: the versions between
//! stay.
//!
//! `route` writes to ribd as the route source NAME, the way a routing daemon does
//! (ribd must have been started with that source). ribd picks between sources by
//! preference and sends the result to the FE.
//!
//! `source` writes to confd as the source NAME, the way `ruster-pppoed` does
//! ([`ruster_confd::source`]): the values given replace all the source had, each
//! for SECONDS (3600 when left out), and with none it has none. It ends with
//! `sync-done`, as a daemon does after connecting.

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
  ruster resolve FILE
  ruster [--run-dir DIR] apply FILE
  ruster [--run-dir DIR] versions
  ruster [--run-dir DIR] rollback N
  ruster [--run-dir DIR] show
  ruster [--run-dir DIR] route add --source NAME [--vrf VRF] PREFIX dev IFACE [via ADDR]
  ruster [--run-dir DIR] route del --source NAME [--vrf VRF] PREFIX
  ruster [--run-dir DIR] source NAME [--lifetime SECONDS] [pppoe SESSION PEER MTU] [ipv4 ADDRESS/LEN]";

/// How long the values of `ruster source` last when no lifetime is given.
const SOURCE_LIFETIME: u32 = 3_600;

/// Sends one request and waits for its answer.
fn request(
    path: &Path,
    send: impl FnOnce(&mut Client) -> Result<u32, String>,
) -> Result<(Code, Vec<u8>), String> {
    requests(path, |c| send(c).map(|token| vec![token]))
}

/// Sends requests and waits for their answers: the first refusal, or the last
/// answer.
fn requests(
    path: &Path,
    send: impl FnOnce(&mut Client) -> Result<Vec<u32>, String>,
) -> Result<(Code, Vec<u8>), String> {
    let stream = UnixStream::connect(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut client = Client::new(stream).map_err(|e| e.to_string())?;
    let mut tokens = send(&mut client)?;
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
                if !tokens.contains(&t) {
                    continue;
                }
                tokens.retain(|&other| other != t);
                if tokens.is_empty() || code.class() != 2 {
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

fn source(run_dir: &Path, args: &[String]) -> Result<(), String> {
    let (name, rest) = args.split_first().ok_or(USAGE)?;
    let number = |text: &str, what: &str| -> Result<u32, String> {
        text.parse().map_err(|_| format!("{text}: not a {what}"))
    };
    let mut lifetime = SOURCE_LIFETIME;
    let mut session = None;
    let mut ipv4 = None;
    let words: Vec<&str> = rest.iter().map(String::as_str).collect();
    let mut words = words.as_slice();
    loop {
        words = match words {
            [] => break,
            ["--lifetime", seconds, rest @ ..] => {
                lifetime = number(seconds, "lifetime in seconds")?;
                rest
            }
            ["pppoe", id, peer, mtu, rest @ ..] => {
                let id = u16::try_from(number(id, "session ID")?)
                    .map_err(|_| format!("{id}: not a session ID"))?;
                let peer = ruster_proto::table::parse_mac(peer)
                    .map_err(|_| format!("{peer}: not a MAC address"))?;
                let mtu =
                    u16::try_from(number(mtu, "MTU")?).map_err(|_| format!("{mtu}: not an MTU"))?;
                session = Some((id, peer, mtu));
                rest
            }
            ["ipv4", text, rest @ ..] => {
                let bad = || format!("{text}: not an address like 198.51.100.2/32");
                let (address, len) = text.split_once('/').ok_or_else(bad)?;
                ipv4 = Some((
                    address.parse().map_err(|_| bad())?,
                    len.parse().map_err(|_| bad())?,
                ));
                rest
            }
            _ => return Err(USAGE.into()),
        };
    }
    let mut changes = Vec::new();
    if let Some((session, peer, mtu)) = session {
        changes.push(Change::set(
            Key::SourcePppoe {
                source: name.clone(),
            },
            Value::SourcePppoe {
                session,
                peer,
                mtu,
                lifetime,
            },
        ));
    }
    if let Some((address, prefix_len)) = ipv4 {
        changes.push(Change::set(
            Key::SourceIpv4 {
                source: name.clone(),
            },
            Value::SourceIpv4 {
                address,
                prefix_len,
                lifetime,
            },
        ));
    }
    for change in &changes {
        change.validate().map_err(|e| e.to_string())?;
    }
    let path = run_dir.join(socket::confd_source(name));
    let (code, payload) = requests(&path, |c| {
        let mut tokens = vec![c.resync_begin()];
        if !changes.is_empty() {
            tokens.push(c.patch(&changes).map_err(|e| e.to_string())?);
        }
        tokens.push(c.resync_end());
        tokens.push(c.sync_done());
        Ok(tokens)
    })?;
    if code.class() != 2 {
        let said = String::from_utf8_lossy(&payload);
        return Err(format!("confd refused the values ({code:?}): {said}"));
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

/// Prints the lock form of a `ruster.toml` (or of a lock form, which is then
/// checked).
fn resolve(path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let lock = if ruster_config::is_lock(&text).map_err(|e| format!("{path}: {e}"))? {
        ruster_config::parse_lock(&text)
    } else {
        ruster_config::resolve(&text)
    };
    print!("{}", lock.map_err(|e| format!("{path}: {e}"))?.to_text());
    Ok(())
}

fn apply(run_dir: &Path, path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    ruster_confd::file::parse(&text).map_err(|e| format!("{path}: {e}"))?;
    commit(run_dir, path, &["config"], text.as_bytes())
}

/// Makes version `number` the latest version again.
fn rollback(run_dir: &Path, number: &str) -> Result<(), String> {
    let number: u64 = number
        .parse()
        .map_err(|_| format!("{number}: not a version number"))?;
    commit(
        run_dir,
        &format!("version {number}"),
        &["rollback", &number.to_string()],
        &[],
    )
}

/// Asks confd to put a configuration in use and says how it went; `what` names it.
fn commit(run_dir: &Path, what: &str, path: &[&str], payload: &[u8]) -> Result<(), String> {
    let socket = run_dir.join(socket::CONFD_CONFIG);
    let (code, payload) = request(&socket, |c| Ok(c.post(path, payload)))?;
    let said = String::from_utf8_lossy(&payload);
    match code.class() {
        2 => {}
        4 => return Err(format!("{what}: not applied: {said}")),
        // A timeout leaves the new configuration in confd; the text says so.
        _ => return Err(format!("{what}: {said}")),
    }
    println!("{what}: applied");
    if !said.is_empty() {
        println!("{said}");
    }
    Ok(())
}

/// Lists the versions confd keeps, newest first.
fn versions(run_dir: &Path) -> Result<(), String> {
    let socket = run_dir.join(socket::CONFD_CONFIG);
    let (code, payload) = request(&socket, |c| Ok(c.get(&["versions"])))?;
    let said = String::from_utf8_lossy(&payload);
    if code != Code::CONTENT {
        return Err(format!("versions: confd answered {code:?} {said}"));
    }
    print!("{said}");
    Ok(())
}

fn run() -> Result<(), String> {
    let (run_dir, rest) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    match rest.split_first() {
        Some((command, args)) => match (command.as_str(), args) {
            ("check", [file]) => check(file),
            ("resolve", [file]) => resolve(file),
            ("apply", [file]) => apply(&run_dir, file),
            ("versions", []) => versions(&run_dir),
            ("rollback", [number]) => rollback(&run_dir, number),
            ("show", []) => show(&run_dir),
            ("route", args) => route(&run_dir, args),
            ("source", args) => source(&run_dir, args),
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
