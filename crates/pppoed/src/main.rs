//! `ruster-pppoed [--run-dir DIR] SETTINGS`: the PPPoE client.
//!
//! It takes PPPoE Discovery and PPP control frames from the FE on
//! `pppoed/punt.sock` and sends its own to `fe/punt/pppoed.sock`; the FE's punt
//! table must send the `pppoe-discovery` and `ppp-control` kinds to the control
//! process `pppoed`. It runs every session of the settings file and writes one
//! line to standard output when a session comes up, changes or goes down:
//!
//! ```text
//! up wan session=4660 ac=02:00:00:00:00:ac mtu=1492 ipv4=198.51.100.2 peer-ipv4=198.51.100.1 dns=192.0.2.53,192.0.2.54 ipv6-id=a1b2:c3d4:e5f6:0708 peer-ipv6-id=0000:0000:0000:0001
//! down wan reason=ac-terminated
//! failed wan reason=auth-failed
//! ```
//!
//! A value not known is `-`. `up` comes again whenever a value changes, each
//! line whole; `failed` is an attempt that ended before the session was up. Both
//! are followed by a new attempt. Messages for people go to standard error.
//!
//! The settings file is TOML, one `[[session]]` per session:
//!
//! ```toml
//! [[session]]
//! name = "wan"                # the name in the output lines
//! interface = "r-wan"         # the FE port the session runs on
//! mac = "02:00:00:00:00:02"   # that port's MAC address
//! user = "user@isp.example"
//! password = "secret"
//! # service = ""              # the service name; empty (the default) for any
//! # ac-name = "ac1"           # take offers only from this AC
//! # ipv6 = true               # run IPv6CP too (the default)
//! # echo-interval = 10        # seconds between LCP Echo-Requests; 0 for none
//! # echo-failures = 3         # unanswered Echo-Requests that end the session
//! ```
//!
//! The values belong in the whole configuration from confd later; the output
//! lines are where [`SessionUp`] and [`SessionDown`] will go to confd instead.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ruster_pppoed::lcp::Echo;
use ruster_pppoed::session::{
    Event, FrameKind, Output, Reason, Session, SessionDown, SessionUp, Settings,
};
use ruster_proto::daemon::{self, socket, Clock};
use ruster_proto::punt::{reason, Direction, Punt};
use ruster_proto::table::{format_mac, parse_mac};
use ruster_proto::task::Progress;
use serde::Deserialize;

/// The control process name the FE's punt table uses.
const NAME: &str = "pppoed";
/// The longest datagram read from the FE: a whole Ethernet frame and the header.
const DATAGRAM_MAX: usize = 2_048;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    session: Vec<SessionFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct SessionFile {
    name: String,
    interface: String,
    mac: String,
    user: String,
    password: String,
    #[serde(default)]
    service: String,
    ac_name: Option<String>,
    #[serde(default = "yes")]
    ipv6: bool,
    #[serde(default = "ten")]
    echo_interval: u32,
    #[serde(default = "three")]
    echo_failures: u32,
}

fn yes() -> bool {
    true
}
fn ten() -> u32 {
    10
}
fn three() -> u32 {
    3
}

/// Reads the settings file: each session's name and settings.
fn settings(text: &str) -> Result<Vec<(String, Settings)>, String> {
    let file: File = toml::from_str(text).map_err(|error| error.to_string())?;
    if file.session.is_empty() {
        return Err("no [[session]]".into());
    }
    let mut out: Vec<(String, Settings)> = Vec::new();
    for s in file.session {
        let name = s.name;
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(format!("session name {name:?}: empty or with spaces"));
        }
        if out.iter().any(|(n, _)| *n == name) {
            return Err(format!("session {name}: named twice"));
        }
        if s.interface.is_empty() || s.interface.len() > 255 {
            return Err(format!("session {name}: interface name"));
        }
        let mac = parse_mac(&s.mac).map_err(|_| format!("session {name}: mac {:?}", s.mac))?;
        for (what, value) in [
            ("user", &s.user),
            ("password", &s.password),
            ("service", &s.service),
        ] {
            if value.len() > 255 {
                return Err(format!("session {name}: {what} longer than 255 bytes"));
            }
        }
        if s.ac_name.as_ref().is_some_and(|a| a.len() > 255) {
            return Err(format!("session {name}: ac-name longer than 255 bytes"));
        }
        if s.echo_interval > 0 && s.echo_failures == 0 {
            return Err(format!("session {name}: echo-failures must be at least 1"));
        }
        out.push((
            name,
            Settings {
                interface: s.interface,
                mac,
                user: s.user.into_bytes(),
                password: s.password.into_bytes(),
                service: s.service.into_bytes(),
                ac_name: s.ac_name.map(String::into_bytes),
                echo: Echo {
                    interval_ms: u64::from(s.echo_interval) * 1_000,
                    failures: s.echo_failures,
                },
                ipv6: s.ipv6,
            },
        ));
    }
    Ok(out)
}

fn reason_text(reason: Reason) -> &'static str {
    match reason {
        Reason::Refused => "refused",
        Reason::AcTerminated => "ac-terminated",
        Reason::PeerTerminated => "peer-terminated",
        Reason::NoEcho => "no-echo",
        Reason::AuthFailed => "auth-failed",
        Reason::LinkFailed => "link-failed",
        Reason::NetworkFailed => "network-failed",
    }
}

fn interface_id(id: Option<[u8; 8]>) -> String {
    id.map_or_else(
        || "-".into(),
        |id| {
            id.chunks(2)
                .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
                .collect::<Vec<_>>()
                .join(":")
        },
    )
}

fn optional<T: ToString>(value: Option<T>) -> String {
    value.map_or_else(|| "-".into(), |v| v.to_string())
}

/// The output line for an event.
fn line(name: &str, event: &Event) -> String {
    match event {
        Event::Up(SessionUp {
            session_id,
            ac,
            mtu,
            ipv4,
            peer_ipv4,
            dns,
            ipv6_local_id,
            ipv6_peer_id,
        }) => {
            let dns: Vec<String> = dns.iter().map(ToString::to_string).collect();
            let dns = if dns.is_empty() {
                "-".into()
            } else {
                dns.join(",")
            };
            format!(
                "up {name} session={session_id} ac={} mtu={mtu} ipv4={} peer-ipv4={} dns={dns} \
                 ipv6-id={} peer-ipv6-id={}",
                format_mac(ac),
                optional(*ipv4),
                optional(*peer_ipv4),
                interface_id(*ipv6_local_id),
                interface_id(*ipv6_peer_id),
            )
        }
        Event::Down(SessionDown { reason }) => {
            format!("down {name} reason={}", reason_text(*reason))
        }
        Event::Failed(reason) => format!("failed {name} reason={}", reason_text(*reason)),
    }
}

/// A seed for each session from the system's random source.
fn seed() -> u64 {
    let mut bytes = [0; 8];
    let read = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes));
    match read {
        Ok(()) => u64::from_ne_bytes(bytes),
        // Different between processes and calls, which is all the seed needs.
        Err(_) => {
            let time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64);
            time ^ (u64::from(std::process::id()) << 32)
        }
    }
}

struct Daemon {
    socket: UnixDatagram,
    fe: PathBuf,
    sessions: Vec<(String, Session)>,
    message: Vec<u8>,
    unsent: u64,
}

impl Daemon {
    fn send(&mut self, interface: &str, output: &Output) {
        for (kind, frame) in &output.frames {
            let why = match kind {
                FrameKind::Discovery => reason::PPPOE_DISCOVERY,
                FrameKind::Control => reason::PPP_CONTROL,
            };
            self.message.clear();
            let encoded = Punt {
                direction: Direction::FromControl,
                reason: why,
                interface,
                frame,
            }
            .encode(&mut self.message);
            if encoded.is_err() || self.socket.send_to(&self.message, &self.fe).is_err() {
                // The FE is not up yet, or has no punt class for us: the
                // retransmissions try again.
                self.unsent += 1;
            }
        }
    }

    fn handle(&mut self, index: usize, output: Output) {
        let (name, session) = &self.sessions[index];
        let interface = session.settings().interface.clone();
        let mut stdout = std::io::stdout().lock();
        for event in &output.events {
            let _ = writeln!(stdout, "{}", line(name, event));
        }
        let _ = stdout.flush();
        drop(stdout);
        self.send(&interface, &output);
    }

    /// Reads what the FE sent; whether there was anything.
    fn receive(&mut self, now: u64) -> bool {
        let mut buf = [0; DATAGRAM_MAX];
        let mut any = false;
        loop {
            let n = match self.socket.recv(&mut buf) {
                Ok(n) => n,
                Err(error) if error.kind() == ErrorKind::WouldBlock => return any,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => {
                    eprintln!("ruster-pppoed: {}: {error}", socket::control_punt(NAME));
                    return any;
                }
            };
            any = true;
            let Ok(punt) = Punt::decode(&buf[..n]) else {
                continue;
            };
            let kind = match (punt.direction, punt.reason) {
                (Direction::ToControl, reason::PPPOE_DISCOVERY) => FrameKind::Discovery,
                (Direction::ToControl, reason::PPP_CONTROL) => FrameKind::Control,
                _ => continue,
            };
            for index in 0..self.sessions.len() {
                if self.sessions[index].1.settings().interface != punt.interface {
                    continue;
                }
                let mut output = Output::default();
                self.sessions[index]
                    .1
                    .receive(now, kind, punt.frame, &mut output);
                self.handle(index, output);
            }
        }
    }

    fn timers(&mut self, now: u64) -> Option<u64> {
        for index in 0..self.sessions.len() {
            if self.sessions[index]
                .1
                .next_timer()
                .is_some_and(|at| at <= now)
            {
                let mut output = Output::default();
                self.sessions[index].1.timeout(now, &mut output);
                self.handle(index, output);
            }
        }
        self.sessions
            .iter()
            .filter_map(|(_, s)| s.next_timer())
            .min()
    }
}

fn run() -> Result<(), String> {
    let (run_dir, rest) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    let [file] = rest.as_slice() else {
        return Err("usage: ruster-pppoed [--run-dir DIR] SETTINGS".into());
    };
    let text =
        std::fs::read_to_string(Path::new(file)).map_err(|error| format!("{file}: {error}"))?;
    let sessions = settings(&text).map_err(|error| format!("{file}: {error}"))?;
    let path = run_dir.join(socket::control_punt(NAME));
    let socket = daemon::bind_datagram(&path)
        .map_err(|error| format!("{}: {error}", socket::control_punt(NAME)))?;
    let mut daemon = Daemon {
        socket,
        fe: run_dir.join(socket::fe_punt(NAME)),
        sessions: sessions
            .into_iter()
            .map(|(name, settings)| (name, Session::new(settings, seed())))
            .collect(),
        message: Vec::new(),
        unsent: 0,
    };
    eprintln!(
        "ruster-pppoed: {} session(s); waiting for frames on {}",
        daemon.sessions.len(),
        path.display()
    );
    daemon::notify("READY=1");

    let clock = Clock::new();
    let mut idle = daemon::Idle::new();
    let mut reported_unsent = 0;
    loop {
        let now = clock.now_ms();
        let busy = daemon.receive(now);
        let wake_at = daemon.timers(now);
        if daemon.unsent / 100 != reported_unsent / 100 {
            reported_unsent = daemon.unsent;
            eprintln!(
                "ruster-pppoed: {} frames not taken by the FE ({})",
                daemon.unsent,
                socket::fe_punt(NAME)
            );
        }
        idle.wait(Progress { busy, wake_at });
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ruster-pppoed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_file() {
        let text = r#"
            [[session]]
            name = "wan"
            interface = "r-wan"
            mac = "02:00:00:00:00:02"
            user = "u"
            password = "p"
            ac-name = "ac1"
            echo-interval = 0
        "#;
        let got = settings(text).unwrap();
        assert_eq!(got.len(), 1);
        let (name, s) = &got[0];
        assert_eq!(name, "wan");
        assert_eq!(s.mac, [2, 0, 0, 0, 0, 2]);
        assert_eq!(s.ac_name.as_deref(), Some(&b"ac1"[..]));
        assert!(s.service.is_empty() && s.ipv6);
        assert_eq!(s.echo.interval_ms, 0);

        let twice = format!("{text}\n{text}");
        assert!(settings(&twice).unwrap_err().contains("named twice"));
        assert!(settings("").is_err());
        assert!(settings(&text.replace("02:00:00:00:00:02", "02:00")).is_err());
        assert!(settings(&format!("{text}\nfoo = 1")).is_err());
    }

    #[test]
    fn output_lines() {
        let up = Event::Up(SessionUp {
            session_id: 4660,
            ac: [2, 0, 0, 0, 0, 0xac],
            mtu: 1492,
            ipv4: Some([198, 51, 100, 2].into()),
            peer_ipv4: None,
            dns: vec![[192, 0, 2, 53].into(), [192, 0, 2, 54].into()],
            ipv6_local_id: Some([0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 7, 8]),
            ipv6_peer_id: None,
        });
        assert_eq!(
            line("wan", &up),
            "up wan session=4660 ac=02:00:00:00:00:ac mtu=1492 ipv4=198.51.100.2 peer-ipv4=- \
             dns=192.0.2.53,192.0.2.54 ipv6-id=a1b2:c3d4:e5f6:0708 peer-ipv6-id=-"
        );
        assert_eq!(
            line(
                "wan",
                &Event::Down(SessionDown {
                    reason: Reason::NoEcho
                })
            ),
            "down wan reason=no-echo"
        );
    }
}
