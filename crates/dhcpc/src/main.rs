//! `ruster-dhcpc [--run-dir DIR]`: the WAN side's DHCP client.
//!
//! It takes its settings, one interface per `[[dhcp-client]]`, from confd: the
//! `dhcpc` part on `confd/part/dhcpc/part.sock` ([`ruster_config::DhcpClient`]). An
//! interface whose settings change starts again; one that is no longer there gives
//! its leases back (DHCPRELEASE, DHCPv6 Release) and stops. The FE may already have
//! dropped the punt classes then, and with them the release: the server then keeps
//! the lease until it ends. Stopping the process
//! gives nothing back: the server keeps the lease until it ends, and the next start
//! asks for it again.
//!
//! The FE hands it DHCP and DHCPv6 replies on `dhcpc/punt.sock` (the punt classes
//! `dhcpc-<interface>` and `dhcpc6-<interface>` that confd writes) and it sends its
//! frames to `fe/punt/dhcpc.sock`. DHCPv4 goes from 0.0.0.0 or the leased address,
//! to 255.255.255.255 or, when renewing, to the server, at the Ethernet address the
//! server's replies came from. DHCPv6 goes from the interface's link-local address
//! to ff02::1:2.
//!
//! What a client gets goes to its confd source ([`ruster_dhcpc::values`]); with
//! `default-route`, the default routes go to ribd as the route source `dhcpc` (ribd
//! must be started with it). It also writes one line to standard output whenever a
//! lease is taken, changes or is lost:
//!
//! ```text
//! bound4 wan address=198.51.100.20/24 router=198.51.100.1 dns=198.51.100.53 lease=3600
//! bound6 wan prefix=2001:db8:12:3400::/56 address=- dns=2001:db8::53 via=fe80::1
//! lost4 wan
//! ```

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use ruster_confd::part::{Asked, Client, Module};
use ruster_config::DhcpClient;
use ruster_dhcpc::client6::Want;
use ruster_dhcpc::{client4, client6, dhcp4, dhcp6, frame, values};
use ruster_proto::daemon::{self, socket, Clock};
use ruster_proto::punt::{reason, Direction, Punt};
use ruster_proto::table::{parse_mac, Change, Key};
use ruster_proto::task::Progress;
use ruster_proto::writer::Writer;

/// How long to wait for confd at start-up.
const CONFD_WAIT: Duration = Duration::from_secs(10);
/// The control process name the FE's punt table uses, and the route source.
const NAME: &str = "dhcpc";
const DATAGRAM_MAX: usize = 2_048;
const DATAGRAMS_PER_ROUND: usize = 64;

/// A seed from the system's random source.
fn seed() -> u64 {
    let mut bytes = [0; 8];
    let read = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes));
    match read {
        Ok(()) => u64::from_ne_bytes(bytes),
        Err(_) => {
            let time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64);
            time ^ (u64::from(std::process::id()) << 32)
        }
    }
}

fn list<T: ToString>(items: &[T]) -> String {
    if items.is_empty() {
        return "-".into();
    }
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// The clients of one interface.
struct Interface {
    entry: DhcpClient,
    mac: [u8; 6],
    link_local: Ipv6Addr,
    v4: Option<client4::Client>,
    v6: Option<client6::Client>,
    /// The Ethernet address DHCPv4 replies came from: where unicast goes.
    server_mac: Option<[u8; 6]>,
    /// The address the DHCPv6 replies that gave the lease came from.
    via6: Option<Ipv6Addr>,
}

impl Interface {
    fn new(entry: DhcpClient, now: u64) -> Result<Self, String> {
        let at = format!("dhcp-client {}", entry.interface);
        let mac = parse_mac(&entry.mac.to_ascii_lowercase()).map_err(|_| format!("{at}: mac"))?;
        let link_local: Ipv6Addr = entry
            .link_local
            .parse()
            .map_err(|_| format!("{at}: link-local"))?;
        let v4 = (!entry.ipv4_source.is_empty()).then(|| client4::Client::new(mac, seed(), now));
        let v6 = (!entry.ipv6_source.is_empty()).then(|| {
            let want = Want {
                address: entry.ipv6_address,
                prefix: true,
            };
            client6::Client::new(mac, want, seed(), now)
        });
        Ok(Self {
            entry,
            mac,
            link_local,
            v4,
            v6,
            server_mac: None,
            via6: None,
        })
    }

    fn next_timer(&self) -> Option<u64> {
        [
            self.v4.as_ref().and_then(client4::Client::next_timer),
            self.v6.as_ref().and_then(client6::Client::next_timer),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

/// What taking a `dhcpc` part would change for clients with `before`: the settings
/// that change, and the interfaces whose clients would start, start again
/// (releasing what they have) or stop; or the reason it would be refused.
fn changes(before: &[DhcpClient], text: &str) -> Result<String, String> {
    let entries = ruster_config::parse_dhcp_client_part(text)?;
    for entry in &entries {
        Interface::new(entry.clone(), 0)?;
    }
    Ok(ruster_confd::part::changes(
        before,
        &entries,
        |e| &e.interface,
        ruster_config::dhcp_client_part,
        [
            "the client starts",
            "the client starts again",
            "the client stops",
        ],
    ))
}

struct Daemon {
    socket: UnixDatagram,
    fe: PathBuf,
    run_dir: PathBuf,
    interfaces: Vec<Interface>,
    sources: BTreeMap<String, Writer>,
    ribd: Option<Writer>,
    message: Vec<u8>,
    unsent: u64,
}

impl Daemon {
    fn send_frame(&mut self, interface: &str, frame: &[u8]) {
        self.message.clear();
        let encoded = Punt {
            direction: Direction::FromControl,
            reason: reason::IP,
            interface,
            frame,
        }
        .encode(&mut self.message);
        if encoded.is_err() || self.socket.send_to(&self.message, &self.fe).is_err() {
            self.unsent += 1;
        }
    }

    fn source(&mut self, name: &str) -> &mut Writer {
        let run_dir = &self.run_dir;
        self.sources.entry(name.to_owned()).or_insert_with(|| {
            Writer::new(
                run_dir.join(socket::confd_source(name)),
                Some(values::REFRESH_MS),
            )
        })
    }

    /// Sends what the DHCPv4 client of interface `index` put out, and writes its
    /// lease.
    fn handle4(&mut self, index: usize, out: client4::Output) {
        let (name, mac, server_mac) = {
            let i = &self.interfaces[index];
            (i.entry.interface.clone(), i.mac, i.server_mac)
        };
        for send in &out.sends {
            let (to, to_mac) = match send.to {
                client4::To::Broadcast => (Ipv4Addr::BROADCAST, None),
                client4::To::Server(server) => (server, server_mac),
            };
            let frame = frame::ipv4(mac, to_mac, send.from, to, &send.payload);
            self.send_frame(&name, &frame);
        }
        if out.events.is_empty() {
            return;
        }
        let i = &self.interfaces[index];
        let lease = i.v4.as_ref().and_then(|c| c.lease()).cloned();
        let source = i.entry.ipv4_source[0].clone();
        let mut stdout = std::io::stdout().lock();
        let _ = match &lease {
            Some(l) => writeln!(
                stdout,
                "bound4 {name} address={}/{} router={} dns={} lease={}",
                l.address,
                l.prefix_len,
                list(&l.routers),
                list(&l.dns),
                l.lease_time
            ),
            None => writeln!(stdout, "lost4 {name}"),
        };
        let _ = stdout.flush();
        drop(stdout);
        if lease.is_none() {
            self.interfaces[index].server_mac = None;
        }
        self.source(&source)
            .set(values::values4(&source, lease.as_ref()));
        self.routes();
    }

    fn handle6(&mut self, index: usize, out: client6::Output, from: Option<Ipv6Addr>) {
        let (name, mac, link_local) = {
            let i = &self.interfaces[index];
            (i.entry.interface.clone(), i.mac, i.link_local)
        };
        for payload in &out.sends {
            let frame = frame::ipv6(mac, link_local, payload);
            self.send_frame(&name, &frame);
        }
        if out.events.is_empty() {
            return;
        }
        let i = &mut self.interfaces[index];
        let lease = i.v6.as_ref().and_then(|c| c.lease()).cloned();
        if lease.is_some() {
            if let Some(from) = from {
                i.via6 = Some(from);
            }
        } else {
            i.via6 = None;
        }
        let via = i.via6;
        let source = i.entry.ipv6_source[0].clone();
        let mut stdout = std::io::stdout().lock();
        let _ = match &lease {
            Some(l) => writeln!(
                stdout,
                "bound6 {name} prefix={} address={} dns={} via={}",
                l.prefix
                    .map_or_else(|| "-".into(), |p| format!("{}/{}", p.prefix, p.len)),
                l.address
                    .map_or_else(|| "-".into(), |a| a.address.to_string()),
                list(&l.dns),
                via.map_or_else(|| "-".into(), |v| v.to_string()),
            ),
            None => writeln!(stdout, "lost6 {name}"),
        };
        let _ = stdout.flush();
        drop(stdout);
        self.source(&source)
            .set(values::values6(&source, lease.as_ref()));
        self.routes();
    }

    /// Sends ribd the default routes of the interfaces that want them: per VRF and
    /// family, the first that has one. Made again each time, so a lease that ended
    /// leaves none behind.
    fn routes(&mut self) {
        let mut want: BTreeMap<Key, Change> = BTreeMap::new();
        for i in self.interfaces.iter().filter(|i| i.entry.default_route) {
            let (vrf, name) = (&i.entry.vrf, &i.entry.interface);
            let lease4 = i.v4.as_ref().and_then(|c| c.lease());
            let v6_bound = i.v6.as_ref().is_some_and(|c| c.lease().is_some());
            for route in [
                values::route4(vrf, name, lease4),
                values::route6(vrf, name, i.via6.filter(|_| v6_bound)),
            ] {
                if route.value.is_some() {
                    want.entry(route.key.clone()).or_insert(route);
                }
            }
        }
        if want.is_empty() && self.ribd.is_none() {
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

    /// What taking a `dhcpc` part would change ([`changes`]).
    fn check(&self, text: &str) -> Result<String, String> {
        let before: Vec<DhcpClient> = self.interfaces.iter().map(|i| i.entry.clone()).collect();
        changes(&before, text)
    }

    /// Takes a new `dhcpc` part: interfaces whose settings are the same keep their
    /// clients, the others start again, and those no longer there give their leases
    /// back.
    fn take(&mut self, text: &str, now: u64) -> Result<(), String> {
        let entries = ruster_config::parse_dhcp_client_part(text)?;
        let mut fresh = Vec::with_capacity(entries.len());
        let mut old = std::mem::take(&mut self.interfaces);
        for entry in entries {
            match old.iter().position(|i| i.entry == entry) {
                Some(at) => fresh.push(old.swap_remove(at)),
                None => fresh.push(Interface::new(entry, now)?),
            }
        }
        // Stop the old ones first, so a source they share with a new one ends up
        // with the new one's values.
        self.interfaces = old;
        for index in 0..self.interfaces.len() {
            let mut out4 = client4::Output::default();
            let mut out6 = client6::Output::default();
            if let Some(c) = self.interfaces[index].v4.as_mut() {
                c.release(now, &mut out4);
            }
            if let Some(c) = self.interfaces[index].v6.as_mut() {
                c.release(now, &mut out6);
            }
            let had4 = self.interfaces[index].v4.is_some();
            let had6 = self.interfaces[index].v6.is_some();
            if had4 {
                out4.events.push(client4::Event::Lost);
                self.handle4(index, out4);
            }
            if had6 {
                out6.events.push(client6::Event::Lost);
                self.handle6(index, out6, None);
            }
        }
        self.interfaces = fresh;
        // The writers of sources no longer used stay, holding nothing: they still
        // have to send the deletions.
        self.routes();
        Ok(())
    }

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
            wake = [wake, at].into_iter().flatten().min();
            if let Some(reason) = writer.refused.take() {
                eprintln!("ruster-dhcpc: {name}: refused: {reason}");
            }
        }
        (busy, wake)
    }

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
                    eprintln!("ruster-dhcpc: {}: {error}", socket::control_punt(NAME));
                    return any;
                }
            };
            any = true;
            let Ok(punt) = Punt::decode(&buf[..n]) else {
                continue;
            };
            if (punt.direction, punt.reason) != (Direction::ToControl, reason::IP) {
                continue;
            }
            let Some(index) = self
                .interfaces
                .iter()
                .position(|i| i.entry.interface == punt.interface)
            else {
                continue;
            };
            let Some(got) = frame::read(punt.frame) else {
                continue;
            };
            match (got.port, got.from) {
                (dhcp4::CLIENT_PORT, IpAddr::V4(_)) => {
                    let Some(client) = self.interfaces[index].v4.as_mut() else {
                        continue;
                    };
                    let mut out = client4::Output::default();
                    client.receive(now, got.payload, &mut out);
                    if out
                        .events
                        .iter()
                        .any(|e| matches!(e, client4::Event::Bound(_)))
                    {
                        self.interfaces[index].server_mac = Some(got.from_mac);
                    }
                    self.handle4(index, out);
                }
                (dhcp6::CLIENT_PORT, IpAddr::V6(from)) => {
                    let Some(client) = self.interfaces[index].v6.as_mut() else {
                        continue;
                    };
                    let mut out = client6::Output::default();
                    client.receive(now, got.payload, &mut out);
                    self.handle6(index, out, Some(from));
                }
                _ => {}
            }
        }
        any
    }

    fn timers(&mut self, now: u64) -> Option<u64> {
        for index in 0..self.interfaces.len() {
            let i = &mut self.interfaces[index];
            if let Some(c) =
                i.v4.as_mut()
                    .filter(|c| c.next_timer().is_some_and(|t| t <= now))
            {
                let mut out = client4::Output::default();
                c.timeout(now, &mut out);
                self.handle4(index, out);
            }
            let i = &mut self.interfaces[index];
            if let Some(c) =
                i.v6.as_mut()
                    .filter(|c| c.next_timer().is_some_and(|t| t <= now))
            {
                let mut out = client6::Output::default();
                c.timeout(now, &mut out);
                self.handle6(index, out, None);
            }
        }
        self.interfaces
            .iter()
            .filter_map(Interface::next_timer)
            .min()
    }
}

fn run() -> Result<(), String> {
    let (run_dir, rest) = daemon::run_dir_and_rest(std::env::args().skip(1))?;
    if !rest.is_empty() {
        return Err("usage: ruster-dhcpc [--run-dir DIR]".into());
    }
    let path = run_dir.join(socket::control_punt(NAME));
    let socket = daemon::bind_datagram(&path)
        .map_err(|error| format!("{}: {error}", socket::control_punt(NAME)))?;
    let part_path = run_dir.join(socket::confd_part(Module::Dhcpc.name()));
    let stream = daemon::connect(&part_path, CONFD_WAIT).map_err(|e| format!("connecting: {e}"))?;
    let mut part = Client::new(stream, Module::Dhcpc).map_err(|e| e.to_string())?;
    let mut daemon = Daemon {
        socket,
        fe: run_dir.join(socket::fe_punt(NAME)),
        run_dir: run_dir.clone(),
        interfaces: Vec::new(),
        sources: BTreeMap::new(),
        ribd: None,
        message: Vec::new(),
        unsent: 0,
    };
    eprintln!("ruster-dhcpc: waiting for frames on {}", path.display());

    let clock = Clock::new();
    let mut idle = daemon::Idle::new();
    let mut retry = daemon::Retry::default();
    let mut reported_unsent = 0;
    let mut ready = false;
    loop {
        let now = clock.now_ms();
        if part.is_closed() && retry.due(now) {
            if let Some(stream) = daemon::try_connect(&part_path) {
                match Client::new(stream, Module::Dhcpc) {
                    Ok(again) => {
                        part = again;
                        eprintln!("ruster-dhcpc: connected to confd again");
                    }
                    Err(error) => eprintln!("ruster-dhcpc: connecting: {error}"),
                }
            }
        }
        let parted = part.poll(&mut |asked| {
            let text = match asked {
                Asked::Check(text) => return daemon.check(text),
                Asked::Take(text) => text,
            };
            let taken = daemon.take(text, now);
            match &taken {
                Ok(()) => {
                    eprintln!("ruster-dhcpc: {} interface(s)", daemon.interfaces.len());
                    if !ready {
                        ready = true;
                        daemon::notify("READY=1");
                    }
                }
                Err(error) => eprintln!("ruster-dhcpc: refused a part: {error}"),
            }
            taken.map(|()| String::new())
        })?;
        let busy = daemon.receive(now) | parted.busy;
        let timer = daemon.timers(now);
        let (moved, written) = daemon.writers(now);
        if daemon.unsent / 100 != reported_unsent / 100 {
            reported_unsent = daemon.unsent;
            eprintln!(
                "ruster-dhcpc: {} frames not taken by the FE ({})",
                daemon.unsent,
                socket::fe_punt(NAME)
            );
        }
        let mut wake_at = [timer, written].into_iter().flatten().min();
        if part.is_closed() {
            wake_at = Some(wake_at.map_or(now + 1_000, |w| w.min(now + 1_000)));
        }
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
            eprintln!("ruster-dhcpc: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_check_names_the_settings_and_clients_that_change() {
        let entry = DhcpClient {
            interface: "wan".into(),
            vrf: "default".into(),
            mac: "02:00:00:00:00:02".into(),
            link_local: "fe80::ff:fe00:2".into(),
            ipv4_source: vec!["dhcp-wan".into()],
            ipv6_source: Vec::new(),
            ipv6_address: false,
            default_route: true,
            punt_rate: 200,
            punt_burst: 100,
        };
        let part = ruster_config::dhcp_client_part;
        assert_eq!(
            changes(
                std::slice::from_ref(&entry),
                &part(std::slice::from_ref(&entry))
            )
            .unwrap(),
            ""
        );
        let first = changes(&[], &part(std::slice::from_ref(&entry))).unwrap();
        assert!(first.ends_with("wan: the client starts\n"), "{first}");
        let other = DhcpClient {
            default_route: false,
            ..entry.clone()
        };
        let text = changes(std::slice::from_ref(&entry), &part(&[other])).unwrap();
        assert!(text.contains("-default-route = true"), "{text}");
        assert!(text.contains("+default-route = false"), "{text}");
        assert!(text.ends_with("wan: the client starts again\n"), "{text}");
        let gone = changes(std::slice::from_ref(&entry), &part(&[])).unwrap();
        assert!(gone.ends_with("wan: the client stops\n"), "{gone}");
        let bad = DhcpClient {
            link_local: "x".into(),
            ..entry
        };
        assert!(changes(&[], &part(&[bad])).is_err());
    }
}
