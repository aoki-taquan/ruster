//! The option negotiation automaton that LCP and the network control protocols
//! (IPCP, IPv6CP) share.
//!
//! [`Fsm`] holds the state, the restart timer and counters, and the identifier of
//! the last Configure-Request. What the options mean is left to a [`Negotiation`]:
//! it builds our Configure-Request, judges the peer's, and takes the peer's Nak and
//! Reject. Each event method appends what to do to a list of [`Action`]s: packets
//! to send and the this-layer-up, -down, -started and -finished actions.
//!
//! # Standards
//!
//! - RFC 1661 section 4.1: the ten states and the transition table, every event
//!   and action as written there (the `irc`, `zrc`, `scr`, `sca`, `scn`, `str`,
//!   `sta`, `scj` actions; `ser` belongs to LCP alone, in `lcp.rs`).
//! - RFC 1661 section 4.6: the restart timer (3 seconds), Max-Terminate (2),
//!   Max-Configure (10) and Max-Failure (5). After Max-Failure Configure-Naks
//!   without a Configure-Ack, options that would be Nak'd are rejected instead. The
//!   timer runs only in the Closing, Stopping, Request-Sent, Ack-Received and
//!   Ack-Sent states.
//! - RFC 1661 section 5.2 to 5.4: a Configure-Ack, -Nak or -Reject whose identifier
//!   is not that of the last Configure-Request is discarded; so is an Ack whose
//!   options are not exactly those sent, and a Reject naming an option that was
//!   not sent. Section 5.7: a Code-Reject of a code from 1 to 7 is RXJ-, of
//!   another code RXJ+. Section 5.6: Code-Reject carries the rejected packet, cut
//!   to fit [`CODE_REJECT_MAX`].
//!
//! Deviations: neither the Passive nor the Restart option of section 4.1 is
//! offered (an Open in Stopped or Opened does nothing; in Closing it goes to
//! Stopping). A retransmitted Configure-Request keeps its options, and its
//! identifier unless an Ack for it came. Code-Reject is cut to 1492 octets, not
//! to a smaller MRU the peer may have set.

use crate::ppp::{self, Opt};

/// The codes every control protocol has.
pub mod code {
    pub const CONFIGURE_REQUEST: u8 = 1;
    pub const CONFIGURE_ACK: u8 = 2;
    pub const CONFIGURE_NAK: u8 = 3;
    pub const CONFIGURE_REJECT: u8 = 4;
    pub const TERMINATE_REQUEST: u8 = 5;
    pub const TERMINATE_ACK: u8 = 6;
    pub const CODE_REJECT: u8 = 7;
}

/// The longest Code-Reject sent: what fits a 1492-octet MRU.
pub const CODE_REJECT_MAX: usize = 1492;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Initial,
    Starting,
    Closed,
    Stopped,
    Closing,
    Stopping,
    RequestSent,
    AckReceived,
    AckSent,
    Opened,
}

/// How the peer's Configure-Request is answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Ack,
    /// The options with the values we would accept.
    Nak(Vec<u8>),
    /// The options we do not accept, as the peer sent them.
    Reject(Vec<u8>),
}

/// What the options of one protocol mean.
pub trait Negotiation {
    /// The options of the next Configure-Request.
    fn request(&mut self) -> Vec<u8>;
    /// Judges the peer's Configure-Request. When `nak` is false (Max-Failure was
    /// reached), what would be Nak'd is rejected instead. An Ack takes the peer's
    /// values into use.
    fn check(&mut self, options: &[Opt<'_>], nak: bool) -> Reply;
    /// The peer Nak'd our request with these options.
    fn naked(&mut self, options: &[Opt<'_>]);
    /// The peer rejected these options of our request.
    fn rejected(&mut self, options: &[Opt<'_>]);
}

/// What the caller is to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Send this control packet.
    Send(Vec<u8>),
    /// This-Layer-Up: the options are agreed.
    Up,
    /// This-Layer-Down.
    Down,
    /// This-Layer-Started: the lower layer is wanted.
    Started,
    /// This-Layer-Finished: the lower layer is not needed any more.
    Finished,
}

/// The timer and counters (RFC 1661 section 4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub restart_ms: u64,
    pub max_terminate: u32,
    pub max_configure: u32,
    pub max_failure: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            restart_ms: 3_000,
            max_terminate: 2,
            max_configure: 10,
            max_failure: 5,
        }
    }
}

/// One protocol's automaton.
#[derive(Clone, Debug)]
pub struct Fsm<N> {
    state: State,
    pub negotiation: N,
    limits: Limits,
    restart_counter: u32,
    failures: u32,
    timer: Option<u64>,
    next_id: u8,
    request: Vec<u8>,
    request_id: u8,
}

impl<N: Negotiation> Fsm<N> {
    pub fn new(negotiation: N, limits: Limits) -> Self {
        Self {
            state: State::Initial,
            negotiation,
            limits,
            restart_counter: 0,
            failures: 0,
            timer: None,
            next_id: 1,
            request: Vec::new(),
            request_id: 0,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// When the restart timer runs out.
    pub fn next_timer(&self) -> Option<u64> {
        self.timer
    }

    /// A new identifier, for packets the caller sends itself (Echo-Request).
    pub fn new_id(&mut self) -> u8 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// The lower layer is up.
    pub fn up(&mut self, now: u64, out: &mut Vec<Action>) {
        match self.state {
            State::Initial => self.state = State::Closed,
            State::Starting => {
                self.failures = 0;
                self.irc(self.limits.max_configure);
                self.scr(now, out, false);
                self.state = State::RequestSent;
            }
            _ => {}
        }
        self.settle();
    }

    /// The lower layer is down.
    pub fn down(&mut self, out: &mut Vec<Action>) {
        self.state = match self.state {
            State::Closed | State::Closing => State::Initial,
            State::Stopped => {
                out.push(Action::Started);
                State::Starting
            }
            State::Stopping | State::RequestSent | State::AckReceived | State::AckSent => {
                State::Starting
            }
            State::Opened => {
                out.push(Action::Down);
                State::Starting
            }
            state => state,
        };
        self.settle();
    }

    /// The administrative Open.
    pub fn open(&mut self, now: u64, out: &mut Vec<Action>) {
        match self.state {
            State::Initial => {
                out.push(Action::Started);
                self.state = State::Starting;
            }
            State::Closed => {
                self.failures = 0;
                self.irc(self.limits.max_configure);
                self.scr(now, out, false);
                self.state = State::RequestSent;
            }
            State::Closing => self.state = State::Stopping,
            _ => {}
        }
        self.settle();
    }

    /// The administrative Close.
    pub fn close(&mut self, now: u64, out: &mut Vec<Action>) {
        match self.state {
            State::Starting => {
                out.push(Action::Finished);
                self.state = State::Initial;
            }
            State::Stopped => self.state = State::Closed,
            State::Stopping => self.state = State::Closing,
            State::RequestSent | State::AckReceived | State::AckSent | State::Opened => {
                if self.state == State::Opened {
                    out.push(Action::Down);
                }
                self.irc(self.limits.max_terminate);
                self.str(now, out);
                self.state = State::Closing;
            }
            _ => {}
        }
        self.settle();
    }

    /// The restart timer, when it is due.
    pub fn timeout(&mut self, now: u64, out: &mut Vec<Action>) {
        if self.timer.is_none_or(|at| now < at) {
            return;
        }
        if self.restart_counter > 0 {
            match self.state {
                State::Closing | State::Stopping => self.str(now, out),
                State::RequestSent => self.scr(now, out, true),
                State::AckReceived => {
                    // A valid reply came for the last identifier (RFC 1661 5.1).
                    self.request_id = self.new_id();
                    self.scr(now, out, true);
                    self.state = State::RequestSent;
                }
                State::AckSent => self.scr(now, out, true),
                _ => {}
            }
        } else {
            self.state = match self.state {
                State::Closing => {
                    out.push(Action::Finished);
                    State::Closed
                }
                State::Stopping | State::RequestSent | State::AckReceived | State::AckSent => {
                    out.push(Action::Finished);
                    State::Stopped
                }
                state => state,
            };
        }
        self.settle();
    }

    /// A received packet of this protocol with a code from 1 to 7; any other code
    /// is an unknown code (RUC) and is rejected. `information` is the whole packet.
    pub fn receive(&mut self, now: u64, information: &[u8], out: &mut Vec<Action>) {
        let Some(packet) = ppp::Packet::parse(information) else {
            return;
        };
        if matches!(self.state, State::Initial | State::Starting) {
            return;
        }
        match packet.code {
            code::CONFIGURE_REQUEST => self.rcr(now, packet, out),
            code::CONFIGURE_ACK => self.rca(now, packet, out),
            code::CONFIGURE_NAK | code::CONFIGURE_REJECT => self.rcn(now, packet, out),
            code::TERMINATE_REQUEST => self.rtr(now, packet.id, out),
            code::TERMINATE_ACK => self.rta(now, out),
            code::CODE_REJECT => {
                let catastrophic = packet.data.first().is_some_and(|c| (1..=7).contains(c));
                self.rxj(now, !catastrophic, out);
            }
            _ => self.ruc(information, out),
        }
        self.settle();
    }

    /// An unknown code (RUC): a Code-Reject carrying the packet.
    pub fn ruc(&mut self, information: &[u8], out: &mut Vec<Action>) {
        if matches!(self.state, State::Initial | State::Starting) || information.len() < 4 {
            return;
        }
        let length = usize::from(u16::from_be_bytes([information[2], information[3]]))
            .clamp(4, information.len());
        let rejected = &information[..length.min(CODE_REJECT_MAX - 4)];
        let id = self.new_id();
        out.push(Action::Send(ppp::packet(code::CODE_REJECT, id, rejected)));
    }

    /// A Code-Reject or Protocol-Reject: RXJ+ when `permitted`, else RXJ-.
    pub fn rxj(&mut self, now: u64, permitted: bool, out: &mut Vec<Action>) {
        if permitted {
            if self.state == State::AckReceived {
                self.state = State::RequestSent;
            }
            return;
        }
        self.state = match self.state {
            State::Closed | State::Closing => {
                out.push(Action::Finished);
                State::Closed
            }
            State::Stopped
            | State::Stopping
            | State::RequestSent
            | State::AckReceived
            | State::AckSent => {
                out.push(Action::Finished);
                State::Stopped
            }
            State::Opened => {
                out.push(Action::Down);
                self.irc(self.limits.max_terminate);
                self.str(now, out);
                State::Stopping
            }
            state => state,
        };
        self.settle();
    }

    fn rcr(&mut self, now: u64, packet: ppp::Packet<'_>, out: &mut Vec<Action>) {
        let Some(options) = ppp::options(packet.data) else {
            return;
        };
        match self.state {
            State::Closed => return self.sta(packet.id, out),
            State::Closing | State::Stopping => return,
            State::Stopped => {
                self.irc(self.limits.max_configure);
                self.scr(now, out, false);
            }
            State::Opened => {
                out.push(Action::Down);
                self.scr(now, out, false);
            }
            _ => {}
        }
        let nak = self.failures < self.limits.max_failure;
        let reply = self.negotiation.check(&options, nak);
        let good = reply == Reply::Ack;
        let sent = match reply {
            Reply::Ack => {
                self.failures = 0;
                ppp::packet(code::CONFIGURE_ACK, packet.id, packet.data)
            }
            Reply::Nak(options) => {
                self.failures = self.failures.saturating_add(1);
                ppp::packet(code::CONFIGURE_NAK, packet.id, &options)
            }
            Reply::Reject(options) => ppp::packet(code::CONFIGURE_REJECT, packet.id, &options),
        };
        out.push(Action::Send(sent));
        self.state = match (self.state, good) {
            (State::AckReceived, true) => {
                out.push(Action::Up);
                State::Opened
            }
            (State::AckReceived, false) => State::AckReceived,
            (_, true) => State::AckSent,
            (_, false) => State::RequestSent,
        };
    }

    fn rca(&mut self, now: u64, packet: ppp::Packet<'_>, out: &mut Vec<Action>) {
        if packet.id != self.request_id || packet.data != self.request.as_slice() {
            return;
        }
        match self.state {
            State::Closed | State::Stopped => self.sta(packet.id, out),
            State::RequestSent => {
                self.irc(self.limits.max_configure);
                self.state = State::AckReceived;
            }
            State::AckReceived => {
                self.scr(now, out, false);
                self.state = State::RequestSent;
            }
            State::AckSent => {
                self.irc(self.limits.max_configure);
                out.push(Action::Up);
                self.state = State::Opened;
            }
            State::Opened => {
                out.push(Action::Down);
                self.scr(now, out, false);
                self.state = State::RequestSent;
            }
            _ => {}
        }
    }

    fn rcn(&mut self, now: u64, packet: ppp::Packet<'_>, out: &mut Vec<Action>) {
        if packet.id != self.request_id {
            return;
        }
        let Some(options) = ppp::options(packet.data) else {
            return;
        };
        let reject = packet.code == code::CONFIGURE_REJECT;
        if reject {
            let sent = ppp::options(&self.request).unwrap_or_default();
            if !options.iter().all(|o| sent.contains(o)) {
                return;
            }
        }
        match self.state {
            State::Closed | State::Stopped => return self.sta(packet.id, out),
            State::Closing | State::Stopping => return,
            _ => {}
        }
        if reject {
            self.negotiation.rejected(&options);
        } else {
            self.negotiation.naked(&options);
        }
        match self.state {
            State::RequestSent | State::AckSent => self.irc(self.limits.max_configure),
            State::Opened => out.push(Action::Down),
            _ => {}
        }
        self.scr(now, out, false);
        if self.state != State::AckSent {
            self.state = State::RequestSent;
        }
    }

    fn rtr(&mut self, now: u64, id: u8, out: &mut Vec<Action>) {
        match self.state {
            State::AckReceived | State::AckSent => self.state = State::RequestSent,
            State::Opened => {
                out.push(Action::Down);
                self.restart_counter = 0;
                self.timer = Some(now + self.limits.restart_ms);
                self.state = State::Stopping;
            }
            _ => {}
        }
        self.sta(id, out);
    }

    fn rta(&mut self, now: u64, out: &mut Vec<Action>) {
        self.state = match self.state {
            State::Closing => {
                out.push(Action::Finished);
                State::Closed
            }
            State::Stopping => {
                out.push(Action::Finished);
                State::Stopped
            }
            State::AckReceived => State::RequestSent,
            State::Opened => {
                out.push(Action::Down);
                self.scr(now, out, false);
                State::RequestSent
            }
            state => state,
        };
    }

    fn irc(&mut self, count: u32) {
        self.restart_counter = count;
    }

    /// Sends a Configure-Request: the last one again when `again`, else a new one.
    fn scr(&mut self, now: u64, out: &mut Vec<Action>, again: bool) {
        if !again {
            self.request = self.negotiation.request();
            self.request_id = self.new_id();
        }
        out.push(Action::Send(ppp::packet(
            code::CONFIGURE_REQUEST,
            self.request_id,
            &self.request,
        )));
        self.restart_counter = self.restart_counter.saturating_sub(1);
        self.timer = Some(now + self.limits.restart_ms);
    }

    fn str(&mut self, now: u64, out: &mut Vec<Action>) {
        let id = self.new_id();
        out.push(Action::Send(ppp::packet(code::TERMINATE_REQUEST, id, &[])));
        self.restart_counter = self.restart_counter.saturating_sub(1);
        self.timer = Some(now + self.limits.restart_ms);
    }

    fn sta(&mut self, id: u8, out: &mut Vec<Action>) {
        out.push(Action::Send(ppp::packet(code::TERMINATE_ACK, id, &[])));
    }

    /// Stops the restart timer in the states that do not use it.
    fn settle(&mut self) {
        if !matches!(
            self.state,
            State::Closing
                | State::Stopping
                | State::RequestSent
                | State::AckReceived
                | State::AckSent
        ) {
            self.timer = None;
        }
    }
}
