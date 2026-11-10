//! `ruster-pppoed [--run-dir DIR]`: the PPPoE client.
//!
//! It takes its settings, one session per `[[pppoe]]`, from confd: the `pppoe`
//! part on `confd/part.sock` ([`ruster_config::Pppoe`]). A session whose settings
//! change starts again; one that is no longer there stops.
//!
//! It takes PPPoE Discovery and PPP control frames from the FE on
//! `pppoed/punt.sock` and sends its own to `fe/punt/pppoed.sock`; confd writes the
//! FE's punt classes that send them to the control process `pppoed`.
//!
//! What a session gets goes to its confd source (`confd/source/<name>.sock`): the
//! session ID, the AC's MAC, the MTU, the IPCP address and DNS servers
//! ([`ruster_pppoed::writer`]). With `default-route`, the IPv4 default route out of
//! the session interface goes to ribd as the route source `pppoed` (ribd must be
//! started with it). It also writes one line to standard output when a session
//! comes up, changes or goes down:
//!
//! ```text
//! up pppoe-wan session=4660 ac=02:00:00:00:00:ac mtu=1492 ipv4=198.51.100.2 peer-ipv4=198.51.100.1 dns=192.0.2.53,192.0.2.54 ipv6-id=a1b2:c3d4:e5f6:0708 peer-ipv6-id=0000:0000:0000:0001
//! down pppoe-wan reason=ac-terminated
//! failed pppoe-wan reason=auth-failed
//! ```
//!
//! The name is the source's. A value not known is `-`. `up` comes again whenever a
//! value changes, each line whole; `failed` is an attempt that ended before the
//! session was up. Both are followed by a new attempt. Messages for people go to
//! standard error. The DNS servers go to the source too, for the DNS bridge
//! (`[dns]`'s `upstream-from`).

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use ruster_confd::part::{Client, Module};
use ruster_pppoed::lcp::Echo;
use ruster_pppoed::session::{
    Event, FrameKind, Output, Reason, Session, SessionDown, SessionUp, Settings,
};
use ruster_pppoed::writer::{self, Writer};
use ruster_proto::daemon::{self, socket, Clock};
use ruster_proto::punt::{reason, Direction, Punt};
use ruster_proto::table::{format_mac, parse_mac, Change, Key};
use ruster_proto::task::Progress;

/// How long to wait for confd at start-up.
const CONFD_WAIT: Duration = Duration::from_secs(10);
/// The control process name the FE's punt table uses, and the route source.
const NAME: &str = "pppoed";
/// The longest datagram read from the FE: a whole Ethernet frame and the header.
const DATAGRAM_MAX: usize = 2_048;
/// The most datagrams read in one round, so that a flood does not keep the timers
/// from running.
const DATAGRAMS_PER_ROUND: usize = 64;

/// A session's settings from its `[[pppoe]]`.
fn settings(entry: &ruster_config::Pppoe) -> Result<Settings, String> {
    let mac = parse_mac(&entry.mac).map_err(|_| format!("pppoe {}: mac", entry.source))?;
    Ok(Settings {
        interface: entry.parent.clone(),
        mac,
        user: entry.user.clone().into_bytes(),
        password: entry.password.clone().into_bytes(),
        service: entry.service.clone().into_bytes(),
        ac_name: entry.ac_name.first().map(|a| a.clone().into_bytes()),
        echo: Echo {
            interval_ms: u64::from(entry.echo_interval) * 1_000,
            failures: entry.echo_failures,
        },
        ipv6: entry.ipv6,
    })
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
    run_dir: PathBuf,
    /// Each session with its `[[pppoe]]`.
    sessions: Vec<(ruster_config::Pppoe, Session)>,
    /// Each source's writer, kept while the source is known.
    sources: BTreeMap<String, Writer>,
    /// ribd's writer, made when a session wants the default route.
    ribd: Option<Writer>,
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
        let (entry, session) = &self.sessions[index];
        let interface = session.settings().interface.clone();
        let mut stdout = std::io::stdout().lock();
        for event in &output.events {
            let _ = writeln!(stdout, "{}", line(&entry.source, event));
        }
        let _ = stdout.flush();
        drop(stdout);
        if !output.events.is_empty() {
            let entry = entry.clone();
            let up = session.up().cloned();
            self.write(&entry, up.as_ref());
        }
        self.send(&interface, &output);
    }

    /// Writes a session's values to its source, and its default route to ribd.
    fn write(&mut self, entry: &ruster_config::Pppoe, up: Option<&SessionUp>) {
        let run_dir = &self.run_dir;
        self.sources
            .entry(entry.source.clone())
            .or_insert_with(|| {
                Writer::new(
                    run_dir.join(socket::confd_source(&entry.source)),
                    Some(writer::REFRESH_MS),
                )
            })
            .set(writer::source_values(&entry.source, up));
        self.routes();
    }

    /// Sends ribd the default routes of the sessions that want one: per VRF, out of
    /// the first such session that is up with an address. Made again from all the
    /// sessions each time, so a session that stopped or moved leaves none behind.
    fn routes(&mut self) {
        let mut want: BTreeMap<Key, Change> = BTreeMap::new();
        for (entry, session) in &self.sessions {
            if !entry.default_route {
                continue;
            }
            let route = writer::default_route(&entry.vrf, &entry.interface, session.up());
            if route.value.is_some() {
                want.entry(route.key.clone()).or_insert(route);
            }
        }
        if want.is_empty()
            && self.ribd.is_none()
            && !self.sessions.iter().any(|(e, _)| e.default_route)
        {
            return;
        }
        let run_dir = &self.run_dir;
        let ribd = self
            .ribd
            .get_or_insert_with(|| Writer::new(run_dir.join(socket::ribd_source(NAME)), None));
        let mut changes: Vec<Change> = ribd
            .held()
            .keys()
            .filter(|key| !want.contains_key(*key))
            .map(|key| Change::delete(key.clone()))
            .collect();
        changes.extend(want.into_values());
        ribd.set(changes);
    }

    /// Takes a new `pppoe` part: sessions whose settings are the same keep running,
    /// the others start again or stop.
    fn take(&mut self, text: &str) -> Result<(), String> {
        let entries = ruster_config::parse_pppoe_part(text)?;
        let mut fresh = Vec::with_capacity(entries.len());
        for entry in &entries {
            fresh.push(settings(entry)?);
        }
        let mut old = std::mem::take(&mut self.sessions);
        for (entry, settings) in entries.into_iter().zip(fresh) {
            match old.iter().position(|(e, _)| *e == entry) {
                Some(at) => self.sessions.push(old.swap_remove(at)),
                None => {
                    self.sessions
                        .push((entry.clone(), Session::new(settings, seed())));
                    self.write(&entry, None);
                }
            }
        }
        // The values of a session that stopped, unless a new one has its source.
        for (entry, _) in old {
            if !self.sessions.iter().any(|(e, _)| e.source == entry.source) {
                self.write(&entry, None);
            }
        }
        self.routes();
        Ok(())
    }

    /// Moves the writers' messages; whether anything moved, and when to come back.
    fn writers(&mut self, now: u64) -> (bool, Option<u64>) {
        let mut busy = false;
        let mut wake: Option<u64> = None;
        for (name, writer) in self
            .sources
            .iter_mut()
            .map(|(n, w)| (n.as_str(), w))
            .chain(self.ribd.as_mut().map(|w| (NAME, w)))
        {
            let (moved, at) = writer.step(now);
            busy |= moved;
            wake = match (wake, at) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            if let Some(reason) = writer.refused.take() {
                eprintln!("ruster-pppoed: {name}: refused: {reason}");
            }
        }
        (busy, wake)
    }

    /// Reads what the FE sent, from the FE's socket only; whether there was
    /// anything.
    fn receive(&mut self, now: u64) -> bool {
        let mut buf = [0; DATAGRAM_MAX];
        let mut any = false;
        for _ in 0..DATAGRAMS_PER_ROUND {
            let n = match self.socket.recv_from(&mut buf) {
                Ok((n, from)) if from.as_pathname() == Some(self.fe.as_path()) => n,
                Ok(_) => {
                    any = true;
                    continue;
                }
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
        any
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
    if !rest.is_empty() {
        return Err("usage: ruster-pppoed [--run-dir DIR]".into());
    }
    let path = run_dir.join(socket::control_punt(NAME));
    let socket = daemon::bind_datagram(&path)
        .map_err(|error| format!("{}: {error}", socket::control_punt(NAME)))?;
    let part_path = run_dir.join(socket::CONFD_PART);
    let stream = daemon::connect(&part_path, CONFD_WAIT).map_err(|e| format!("connecting: {e}"))?;
    let mut part = Client::new(stream, Module::Pppoe).map_err(|e| e.to_string())?;
    let mut daemon = Daemon {
        socket,
        fe: run_dir.join(socket::fe_punt(NAME)),
        run_dir: run_dir.clone(),
        sessions: Vec::new(),
        sources: BTreeMap::new(),
        ribd: None,
        message: Vec::new(),
        unsent: 0,
    };
    eprintln!("ruster-pppoed: waiting for frames on {}", path.display());

    let clock = Clock::new();
    let mut idle = daemon::Idle::new();
    let mut retry = daemon::Retry::default();
    let mut reported_unsent = 0;
    let mut ready = false;
    loop {
        let now = clock.now_ms();
        if part.is_closed() && retry.due(now) {
            if let Some(stream) = daemon::try_connect(&part_path) {
                match Client::new(stream, Module::Pppoe) {
                    Ok(again) => {
                        part = again;
                        eprintln!("ruster-pppoed: connected to confd again");
                    }
                    Err(error) => eprintln!("ruster-pppoed: connecting: {error}"),
                }
            }
        }
        let parted = part.poll(&mut |text| {
            let taken = daemon.take(text);
            match &taken {
                Ok(()) => {
                    eprintln!("ruster-pppoed: {} session(s)", daemon.sessions.len());
                    if !ready {
                        ready = true;
                        daemon::notify("READY=1");
                    }
                }
                Err(error) => eprintln!("ruster-pppoed: refused a part: {error}"),
            }
            taken
        })?;
        let busy = daemon.receive(now) | parted.busy;
        let timer = daemon.timers(now);
        let (moved, written) = daemon.writers(now);
        if daemon.unsent / 100 != reported_unsent / 100 {
            reported_unsent = daemon.unsent;
            eprintln!(
                "ruster-pppoed: {} frames not taken by the FE ({})",
                daemon.unsent,
                socket::fe_punt(NAME)
            );
        }
        let wake_at = match (timer, written) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let wake_at = if part.is_closed() {
            Some(wake_at.map_or(now + 1_000, |w| w.min(now + 1_000)))
        } else {
            wake_at
        };
        idle.wait(Progress {
            busy: busy || moved,
            wake_at,
        });
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
    fn settings_from_the_part() {
        let entry = ruster_config::Pppoe {
            source: "pppoe-wan".into(),
            interface: "ppp".into(),
            vrf: "default".into(),
            parent: "r-wan".into(),
            mac: "02:00:00:00:00:02".into(),
            user: "u".into(),
            password: "p".into(),
            service: String::new(),
            ac_name: vec!["ac1".into()],
            ipv6: true,
            echo_interval: 0,
            echo_failures: 3,
            default_route: false,
        };
        let s = settings(&entry).unwrap();
        assert_eq!(s.interface, "r-wan");
        assert_eq!(s.mac, [2, 0, 0, 0, 0, 2]);
        assert_eq!(s.ac_name.as_deref(), Some(&b"ac1"[..]));
        assert!(s.service.is_empty() && s.ipv6);
        assert_eq!(s.echo.interval_ms, 0);
        let bad = ruster_config::Pppoe {
            mac: "02:00".into(),
            ..entry
        };
        assert!(settings(&bad).is_err());
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
