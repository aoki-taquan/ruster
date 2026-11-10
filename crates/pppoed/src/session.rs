//! One PPPoE session from Discovery to the network phase, started again whenever
//! it ends.
//!
//! A [`Session`] runs Discovery, then LCP, then the authentication the peer asked
//! for, then IPCP and (when enabled) IPv6CP. It reports [`Event::Up`] with every
//! value the session got ([`SessionUp`]) when the first network protocol opens,
//! and again whenever a value changes; each report is whole, not a change. When no
//! network protocol is open any more it reports [`Event::Down`]: the session has
//! ended, or the peer is negotiating again, and an Up may follow on the same
//! session. An attempt that ends without an Up is reported as [`Event::Failed`].
//! Either way an ended attempt starts again from Discovery after a wait that
//! doubles while attempts keep failing. The first reason found for an ending is
//! the one reported.
//!
//! # Standards
//!
//! - RFC 1661 section 3.2: the phases. LCP starts when Discovery gives the session
//!   (the lower layer is up). Section 3.4: authentication, when LCP agreed on one,
//!   comes before the network phase, and network-protocol packets that come before
//!   it are discarded. Section 3.5: IPCP and IPv6CP start once authentication has
//!   succeeded. Section 3.7 and RFC 2516 section 5.5: when LCP finishes, the host
//!   sends a PADT; a PADT from the AC is the lower layer going down.
//! - RFC 1661 section 5.7: a packet of a protocol we do not run is answered with a
//!   Protocol-Reject while LCP is open, and dropped otherwise.
//! - RFC 2516 section 6: session frames count only with our session ID, from the
//!   AC and to our MAC address.
//!
//! Deviations: when no network protocol is left open or negotiating, the host
//! closes LCP (RFC 1661 leaves it open). The authentication phase ends badly after
//! [`AUTH_TIMEOUT_MS`]. The wait before starting again is ours: [`FIRST_RETRY_MS`],
//! doubling up to [`LONGEST_RETRY_MS`].

use std::net::Ipv4Addr;

use crate::auth::{Client, Outcome};
use crate::discovery::{self, Discovery};
use crate::fsm::{self, Action, Fsm, Limits};
use crate::ipcp::IpcpOptions;
use crate::ipv6cp::Ipv6cpOptions;
use crate::lcp::{self, Echo, Lcp, Notice};
use crate::ppp::{self, protocol, SessionFrame};
use crate::{Mac, Rng};

/// How long the peer has to finish authentication.
pub const AUTH_TIMEOUT_MS: u64 = 30_000;
/// The first wait before starting again after an attempt ended.
pub const FIRST_RETRY_MS: u64 = 3_000;
/// The longest wait before starting again.
pub const LONGEST_RETRY_MS: u64 = 60_000;

/// What one session is set up with. Its `Debug` does not show the password.
#[derive(Clone, PartialEq, Eq)]
pub struct Settings {
    /// The interface the session runs on (the parent of the session interface).
    pub interface: String,
    /// That interface's MAC address.
    pub mac: Mac,
    pub user: Vec<u8>,
    pub password: Vec<u8>,
    /// The service name; empty for any.
    pub service: Vec<u8>,
    /// Take offers only from the AC of this name.
    pub ac_name: Option<Vec<u8>>,
    pub echo: Echo,
    /// Run IPv6CP too.
    pub ipv6: bool,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Every field by name, so that a new one is not missed.
        let Self {
            interface,
            mac,
            user,
            password: _,
            service,
            ac_name,
            echo,
            ipv6,
        } = self;
        f.debug_struct("Settings")
            .field("interface", interface)
            .field("mac", mac)
            .field("user", user)
            .field("password", &ruster_config::HIDDEN)
            .field("service", service)
            .field("ac_name", ac_name)
            .field("echo", echo)
            .field("ipv6", ipv6)
            .finish()
    }
}

/// What an established session gives: the values the FE's `pppoe` interface, its
/// addresses and the DNS forwarder need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionUp {
    pub session_id: u16,
    /// The AC's MAC address.
    pub ac: Mac,
    /// The most the peer takes in one PPP frame (its MRU, at most 1492).
    pub mtu: u16,
    pub ipv4: Option<Ipv4Addr>,
    pub peer_ipv4: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    /// Our IPv6 interface identifier and the peer's (IPv6CP).
    pub ipv6_local_id: Option<[u8; 8]>,
    pub ipv6_peer_id: Option<[u8; 8]>,
}

/// Why a session or an attempt ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The AC refused the session in its PADS.
    Refused,
    /// The AC sent a PADT.
    AcTerminated,
    /// The peer sent an LCP Terminate-Request.
    PeerTerminated,
    /// The peer stopped answering Echo-Requests.
    NoEcho,
    AuthFailed,
    /// LCP did not agree.
    LinkFailed,
    /// No network protocol could be opened.
    NetworkFailed,
}

/// A session that was up went down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionDown {
    pub reason: Reason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Up(SessionUp),
    Down(SessionDown),
    /// An attempt ended before the session was up.
    Failed(Reason),
}

/// Which punt reason a frame is sent with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Discovery,
    Control,
}

/// What a session gives back from one call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Output {
    pub frames: Vec<(FrameKind, Vec<u8>)>,
    pub events: Vec<Event>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    /// Waiting to start again.
    Dead,
    Discovery,
    Establish,
    Authenticate,
    Network,
}

/// One PPPoE session.
#[derive(Clone, Debug)]
pub struct Session {
    settings: Settings,
    rng: Rng,
    phase: Phase,
    discovery: Discovery,
    lcp: Lcp,
    auth: Option<Client>,
    auth_deadline: Option<u64>,
    ipcp: Fsm<IpcpOptions>,
    ipv6cp: Fsm<Ipv6cpOptions>,
    restart_at: Option<u64>,
    retry_ms: u64,
    reason: Option<Reason>,
    reported: Option<SessionUp>,
    /// This attempt was reported up at least once.
    was_up: bool,
}

impl Session {
    /// A session that starts at the first [`Session::timeout`]. `seed` makes the
    /// Host-Uniq, magic numbers and interface identifiers.
    pub fn new(settings: Settings, seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        let discovery = Discovery::new(
            discovery::Settings {
                mac: settings.mac,
                service: settings.service.clone(),
                ac_name: settings.ac_name.clone(),
            },
            rng.next_u64().to_be_bytes(),
        );
        let lcp = Lcp::new(Rng::new(rng.next_u64()), Limits::default(), settings.echo);
        let ipv6cp = Fsm::new(
            Ipv6cpOptions::new(Rng::new(rng.next_u64())),
            Limits::default(),
        );
        Self {
            settings,
            rng,
            phase: Phase::Dead,
            discovery,
            lcp,
            auth: None,
            auth_deadline: None,
            ipcp: Fsm::new(IpcpOptions::default(), Limits::default()),
            ipv6cp,
            restart_at: Some(0),
            retry_ms: FIRST_RETRY_MS,
            reason: None,
            reported: None,
            was_up: false,
        }
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// What the session reported last as up, if it is up.
    pub fn up(&self) -> Option<&SessionUp> {
        self.reported.as_ref()
    }

    /// The earliest time [`Session::timeout`] has something to do.
    pub fn next_timer(&self) -> Option<u64> {
        [
            self.restart_at,
            self.discovery.next_timer(),
            self.lcp.next_timer(),
            self.auth.as_ref().and_then(Client::next_timer),
            self.auth_deadline,
            self.ipcp.next_timer(),
            self.ipv6cp.next_timer(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Runs the timers that are due.
    pub fn timeout(&mut self, now: u64, out: &mut Output) {
        if self.restart_at.is_some_and(|at| now >= at) {
            self.restart_at = None;
            self.phase = Phase::Discovery;
            self.reason = None;
            // A new Host-Uniq, so that a late answer to an earlier attempt is
            // not taken.
            self.discovery = Discovery::new(
                discovery::Settings {
                    mac: self.settings.mac,
                    service: self.settings.service.clone(),
                    ac_name: self.settings.ac_name.clone(),
                },
                self.rng.next_u64().to_be_bytes(),
            );
            let mut frames = Vec::new();
            self.discovery.start(now, &mut frames);
            push(out, FrameKind::Discovery, frames);
        }
        let mut frames = Vec::new();
        self.discovery.timeout(now, &mut frames);
        push(out, FrameKind::Discovery, frames);
        if self.phase >= Phase::Establish {
            let mut actions = Vec::new();
            let notice = self.lcp.timeout(now, &mut actions);
            self.lcp_actions(now, actions, out);
            if notice == Some(Notice::NoEcho) {
                self.reason.get_or_insert(Reason::NoEcho);
                self.lower_down(now, true, out);
            }
        }
        if let Some(client) = &mut self.auth {
            let mut packets = Vec::new();
            let outcome = client.timeout(now, &mut packets);
            let protocol = client.protocol();
            self.send_all(protocol, packets, out);
            if let Some(outcome) = outcome {
                self.auth_outcome(now, outcome, out);
            }
        }
        if self.auth_deadline.is_some_and(|at| now >= at) {
            self.auth_outcome(now, Outcome::Failure, out);
        }
        if self.phase == Phase::Network {
            let mut actions = Vec::new();
            self.ipcp.timeout(now, &mut actions);
            self.ncp_actions(now, protocol::IPCP, actions, out);
            let mut actions = Vec::new();
            self.ipv6cp.timeout(now, &mut actions);
            self.ncp_actions(now, protocol::IPV6CP, actions, out);
        }
        self.report(out);
    }

    /// A frame the FE passed: Discovery or PPP control in a session frame.
    pub fn receive(&mut self, now: u64, kind: FrameKind, frame: &[u8], out: &mut Output) {
        match kind {
            FrameKind::Discovery => self.receive_discovery(now, frame, out),
            FrameKind::Control => self.receive_control(now, frame, out),
        }
        self.report(out);
    }

    fn receive_discovery(&mut self, now: u64, frame: &[u8], out: &mut Output) {
        let mut frames = Vec::new();
        let event = self.discovery.receive(now, frame, &mut frames);
        push(out, FrameKind::Discovery, frames);
        match event {
            Some(discovery::Event::Session { .. }) => self.begin_link(now, out),
            Some(discovery::Event::Refused(_)) => {
                self.reason.get_or_insert(Reason::Refused);
                self.end(now, out);
            }
            Some(discovery::Event::Terminated) => {
                self.reason.get_or_insert(Reason::AcTerminated);
                self.lower_down(now, false, out);
            }
            None => {}
        }
    }

    fn receive_control(&mut self, now: u64, frame: &[u8], out: &mut Output) {
        let (Some((id, ac)), Some(packet)) = (self.discovery.session(), SessionFrame::parse(frame))
        else {
            return;
        };
        if packet.session != id || packet.source != ac || packet.destination != self.settings.mac {
            return;
        }
        let information = packet.information;
        match packet.protocol {
            protocol::LCP => {
                let was_opened = self.lcp.opened();
                let mut actions = Vec::new();
                let notice = self.lcp.receive(now, information, &mut actions);
                if was_opened
                    && self.lcp.fsm.state() == fsm::State::Stopping
                    && ppp::Packet::parse(information)
                        .is_some_and(|p| p.code == fsm::code::TERMINATE_REQUEST)
                {
                    self.reason.get_or_insert(Reason::PeerTerminated);
                }
                self.lcp_actions(now, actions, out);
                if let Some(Notice::ProtocolRejected(rejected)) = notice {
                    let mut actions = Vec::new();
                    match rejected {
                        protocol::IPCP => self.ipcp.rxj(now, false, &mut actions),
                        protocol::IPV6CP => self.ipv6cp.rxj(now, false, &mut actions),
                        _ => {}
                    }
                    self.ncp_actions(now, rejected, actions, out);
                }
            }
            p if self.auth.as_ref().is_some_and(|c| c.protocol() == p) => {
                if self.phase >= Phase::Authenticate {
                    let mut packets = Vec::new();
                    let outcome = self
                        .auth
                        .as_mut()
                        .and_then(|c| c.receive(information, &mut packets));
                    self.send_all(p, packets, out);
                    if let Some(outcome) = outcome {
                        self.auth_outcome(now, outcome, out);
                    }
                }
            }
            protocol::IPCP if self.phase == Phase::Network => {
                let mut actions = Vec::new();
                self.ipcp.receive(now, information, &mut actions);
                self.ncp_actions(now, protocol::IPCP, actions, out);
            }
            protocol::IPV6CP if self.settings.ipv6 && self.phase == Phase::Network => {
                let mut actions = Vec::new();
                self.ipv6cp.receive(now, information, &mut actions);
                self.ncp_actions(now, protocol::IPV6CP, actions, out);
            }
            protocol::IPCP => {}
            protocol::IPV6CP if self.settings.ipv6 => {}
            // Before the network phase, other packets are discarded (RFC 1661
            // section 3.4).
            other if self.phase == Phase::Network => {
                if let Some(reject) = self.lcp.protocol_reject(other, information) {
                    self.send(protocol::LCP, reject, out);
                }
            }
            _ => {}
        }
    }

    /// Discovery gave a session: start LCP with everything above it fresh.
    fn begin_link(&mut self, now: u64, out: &mut Output) {
        self.lcp = Lcp::new(
            Rng::new(self.rng.next_u64()),
            Limits::default(),
            self.settings.echo,
        );
        self.auth = None;
        self.auth_deadline = None;
        self.ipcp = Fsm::new(IpcpOptions::default(), Limits::default());
        self.ipv6cp = Fsm::new(
            Ipv6cpOptions::new(Rng::new(self.rng.next_u64())),
            Limits::default(),
        );
        self.phase = Phase::Establish;
        let mut actions = Vec::new();
        self.lcp.fsm.up(now, &mut actions);
        self.lcp.fsm.open(now, &mut actions);
        self.lcp_actions(now, actions, out);
    }

    fn lcp_actions(&mut self, now: u64, actions: Vec<Action>, out: &mut Output) {
        for action in actions {
            match action {
                Action::Send(packet) => self.send(protocol::LCP, packet, out),
                Action::Up => match self.lcp.fsm.negotiation.auth {
                    Some(method) => {
                        self.phase = Phase::Authenticate;
                        let mut client =
                            Client::new(method, &self.settings.user, &self.settings.password);
                        let mut packets = Vec::new();
                        client.start(now, &mut packets);
                        self.send_all(client.protocol(), packets, out);
                        self.auth = Some(client);
                        self.auth_deadline = Some(now + AUTH_TIMEOUT_MS);
                    }
                    None => self.network(now, out),
                },
                Action::Down => {
                    self.phase = Phase::Establish;
                    self.auth = None;
                    self.auth_deadline = None;
                    let mut actions = Vec::new();
                    self.ipcp.down(&mut actions);
                    self.ncp_actions(now, protocol::IPCP, actions, out);
                    let mut actions = Vec::new();
                    self.ipv6cp.down(&mut actions);
                    self.ncp_actions(now, protocol::IPV6CP, actions, out);
                }
                Action::Started => {}
                Action::Finished => {
                    let mut frames = Vec::new();
                    self.discovery.terminate(&mut frames);
                    push(out, FrameKind::Discovery, frames);
                    self.reason.get_or_insert(Reason::LinkFailed);
                    self.end(now, out);
                }
            }
        }
    }

    fn auth_outcome(&mut self, now: u64, outcome: Outcome, out: &mut Output) {
        self.auth_deadline = None;
        match outcome {
            Outcome::Success if self.phase == Phase::Authenticate => self.network(now, out),
            Outcome::Success => {}
            Outcome::Failure => {
                self.auth = None;
                self.reason.get_or_insert(Reason::AuthFailed);
                let mut actions = Vec::new();
                self.lcp.fsm.close(now, &mut actions);
                self.lcp_actions(now, actions, out);
            }
        }
    }

    /// The network phase: open IPCP and, when enabled, IPv6CP.
    fn network(&mut self, now: u64, out: &mut Output) {
        self.phase = Phase::Network;
        let mut actions = Vec::new();
        self.ipcp.up(now, &mut actions);
        self.ipcp.open(now, &mut actions);
        self.ncp_actions(now, protocol::IPCP, actions, out);
        if self.settings.ipv6 {
            let mut actions = Vec::new();
            self.ipv6cp.up(now, &mut actions);
            self.ipv6cp.open(now, &mut actions);
            self.ncp_actions(now, protocol::IPV6CP, actions, out);
        }
    }

    fn ncp_actions(&mut self, now: u64, protocol: u16, actions: Vec<Action>, out: &mut Output) {
        let mut finished = false;
        for action in actions {
            match action {
                Action::Send(packet) => self.send(protocol, packet, out),
                Action::Finished => finished = true,
                Action::Up | Action::Down | Action::Started => {}
            }
        }
        let stopped = |state| matches!(state, fsm::State::Stopped | fsm::State::Closed);
        let ipv6_stopped = !self.settings.ipv6 || stopped(self.ipv6cp.state());
        if finished && self.phase == Phase::Network && stopped(self.ipcp.state()) && ipv6_stopped {
            self.reason.get_or_insert(Reason::NetworkFailed);
            let mut actions = Vec::new();
            self.lcp.fsm.close(now, &mut actions);
            self.lcp_actions(now, actions, out);
        }
    }

    /// The session is gone below LCP (a PADT from the AC, or no echo). With
    /// `padt`, tell the AC.
    fn lower_down(&mut self, now: u64, padt: bool, out: &mut Output) {
        let mut frames = Vec::new();
        if padt {
            self.discovery.terminate(&mut frames);
        } else {
            self.discovery.stop();
        }
        push(out, FrameKind::Discovery, frames);
        let mut actions = Vec::new();
        self.lcp.fsm.down(&mut actions);
        self.lcp_actions(now, actions, out);
        self.end(now, out);
    }

    /// The attempt is over: report and wait to start again.
    fn end(&mut self, now: u64, out: &mut Output) {
        self.phase = Phase::Dead;
        self.auth = None;
        self.auth_deadline = None;
        self.discovery.stop();
        let reason = self.reason.unwrap_or(Reason::LinkFailed);
        if self.reported.take().is_some() {
            out.events.push(Event::Down(SessionDown { reason }));
        } else if !self.was_up {
            out.events.push(Event::Failed(reason));
        }
        if std::mem::take(&mut self.was_up) {
            self.retry_ms = FIRST_RETRY_MS;
        }
        self.restart_at = Some(now + self.retry_ms);
        self.retry_ms = (self.retry_ms * 2).min(LONGEST_RETRY_MS);
        // Nothing below LCP is left: it starts fresh with the next session.
        self.lcp = Lcp::new(
            Rng::new(self.rng.next_u64()),
            Limits::default(),
            self.settings.echo,
        );
        self.ipcp = Fsm::new(IpcpOptions::default(), Limits::default());
        self.ipv6cp = Fsm::new(
            Ipv6cpOptions::new(Rng::new(self.rng.next_u64())),
            Limits::default(),
        );
    }

    /// Reports Up when the values changed, or Down when no network protocol is
    /// open any more.
    fn report(&mut self, out: &mut Output) {
        if self.phase == Phase::Dead {
            return;
        }
        let ipcp = self.ipcp.state() == fsm::State::Opened;
        let ipv6cp = self.ipv6cp.state() == fsm::State::Opened;
        let now_up = match self.discovery.session() {
            Some((session_id, ac)) if self.phase == Phase::Network && (ipcp || ipv6cp) => {
                let v4 = &self.ipcp.negotiation;
                let v6 = &self.ipv6cp.negotiation;
                Some(SessionUp {
                    session_id,
                    ac,
                    mtu: self.lcp.fsm.negotiation.peer_mru.min(lcp::MRU),
                    ipv4: v4.address().filter(|_| ipcp),
                    peer_ipv4: v4.peer.filter(|_| ipcp),
                    dns: if ipcp { v4.dns() } else { Vec::new() },
                    ipv6_local_id: v6.local().filter(|_| ipv6cp),
                    ipv6_peer_id: v6.peer.filter(|_| ipv6cp),
                })
            }
            _ => None,
        };
        if now_up == self.reported {
            return;
        }
        match now_up.clone() {
            Some(up) => {
                self.was_up = true;
                out.events.push(Event::Up(up));
            }
            None => out.events.push(Event::Down(SessionDown {
                reason: self.reason.unwrap_or(Reason::NetworkFailed),
            })),
        }
        self.reported = now_up;
    }

    fn send_all(&self, protocol: u16, packets: Vec<Vec<u8>>, out: &mut Output) {
        for packet in packets {
            self.send(protocol, packet, out);
        }
    }

    fn send(&self, protocol: u16, packet: Vec<u8>, out: &mut Output) {
        if let Some((id, ac)) = self.discovery.session() {
            out.frames.push((
                FrameKind::Control,
                ppp::session_frame(ac, self.settings.mac, id, protocol, &packet),
            ));
        }
    }
}

fn push(out: &mut Output, kind: FrameKind, frames: Vec<Vec<u8>>) {
    out.frames
        .extend(frames.into_iter().map(|frame| (kind, frame)));
}
