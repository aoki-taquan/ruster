//! LCP for the host of a PPPoE session: the options, the echo keepalive, and the
//! LCP-only codes, on top of the shared automaton ([`crate::fsm`]).
//!
//! The host asks for an MRU of [`MRU`] and a Magic-Number. Of the peer's options it
//! takes the MRU (up to [`MRU`]), the Magic-Number and the Authentication-Protocol
//! (PAP, or CHAP with MD5); it rejects every other option. Once LCP is open, an
//! Echo-Request goes to the peer every echo interval; when that many in a row get
//! no Echo-Reply, the link is reported dead ([`Notice::NoEcho`]).
//!
//! # Standards
//!
//! - RFC 1661 section 6.1: Maximum-Receive-Unit. Section 6.2: Authentication-
//!   Protocol; one we cannot do is Nak'd with CHAP and MD5 (RFC 1994 section 3).
//!   Section 6.4: Magic-Number; a Configure-Request carrying our own number (or 0)
//!   is Nak'd with another random number, and a Nak of ours makes us pick a new
//!   one.
//! - RFC 2516 section 7: the MRU is at most 1492; ACCM, ACFC and FCS-Alternatives
//!   are rejected and never asked for; PFC is not asked for.
//! - RFC 1661 section 5.7: a Protocol-Reject of LCP is RXJ-, of another protocol
//!   RXJ+, and that protocol is no longer used. Sections 5.8 and 5.9: an
//!   Echo-Request is answered with our Magic-Number only in the Opened state;
//!   Discard-Request is dropped; Echo packets that carry our own Magic-Number
//!   (a looped-back link) are dropped. Protocol-Reject for a protocol we do not
//!   run is sent only in the Opened state, cut to fit the MRU.
//!
//! Deviations: PFC and every other option not listed above are rejected (PFC is
//! allowed by RFC 2516 but the FE reads two-byte protocol numbers). A peer that
//! Code-Rejects Echo-Request is not sent more of them. The echo keepalive is not in
//! RFC 1661; its interval and limit are ours.

use crate::fsm::{self, Action, Fsm, Limits, Negotiation, Reply};
use crate::ppp::{self, protocol, push_option, Opt};
use crate::Rng;

/// The LCP option types.
pub mod option {
    pub const MRU: u8 = 1;
    pub const AUTH_PROTOCOL: u8 = 3;
    pub const MAGIC_NUMBER: u8 = 5;
}

/// The codes LCP has beyond those of [`fsm::code`].
pub mod code {
    pub const PROTOCOL_REJECT: u8 = 8;
    pub const ECHO_REQUEST: u8 = 9;
    pub const ECHO_REPLY: u8 = 10;
    pub const DISCARD_REQUEST: u8 = 11;
}

/// The largest MRU on PPPoE (RFC 2516 section 7).
pub const MRU: u16 = 1492;
/// The smallest MRU of the peer we take.
pub const MRU_MIN: u16 = 128;
const CHAP_MD5: [u8; 3] = [0xc2, 0x23, 0x05];

/// The authentication the peer asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    Pap,
    ChapMd5,
}

/// The LCP options of both sides.
#[derive(Clone, Debug)]
pub struct LcpOptions {
    rng: Rng,
    /// The MRU we ask for, and whether we still ask (the peer may reject it).
    pub mru: u16,
    ask_mru: bool,
    pub magic: u32,
    ask_magic: bool,
    /// The peer's MRU: the most we may send it.
    pub peer_mru: u16,
    pub peer_magic: u32,
    /// The authentication the peer asked for and we agreed to.
    pub auth: Option<Auth>,
}

impl LcpOptions {
    pub fn new(mut rng: Rng) -> Self {
        let magic = rng.non_zero_u32();
        Self {
            rng,
            mru: MRU,
            ask_mru: true,
            magic,
            ask_magic: true,
            peer_mru: MRU,
            peer_magic: 0,
            auth: None,
        }
    }

    /// A new magic number that is neither 0 nor `not`.
    fn new_magic(&mut self, not: u32) -> u32 {
        loop {
            let magic = self.rng.non_zero_u32();
            if magic != not {
                return magic;
            }
        }
    }
}

impl Negotiation for LcpOptions {
    fn request(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.ask_mru {
            push_option(&mut out, option::MRU, &self.mru.to_be_bytes());
        }
        if self.ask_magic {
            push_option(&mut out, option::MAGIC_NUMBER, &self.magic.to_be_bytes());
        }
        out
    }

    fn check(&mut self, options: &[Opt<'_>], nak: bool) -> Reply {
        let mut naks = Vec::new();
        let mut rejects = Vec::new();
        let mut peer_mru = MRU;
        let mut peer_magic = 0;
        let mut auth = None;
        for &(kind, value) in options {
            let suggestion: Option<Vec<u8>> = match (kind, value.len()) {
                (option::MRU, 2) => {
                    let mru = u16::from_be_bytes([value[0], value[1]]);
                    if (MRU_MIN..=MRU).contains(&mru) {
                        peer_mru = mru;
                        None
                    } else {
                        Some(MRU.to_be_bytes().to_vec())
                    }
                }
                (option::AUTH_PROTOCOL, _) => match value {
                    [0xc0, 0x23] => {
                        auth = Some(Auth::Pap);
                        None
                    }
                    [0xc2, 0x23, 0x05] => {
                        auth = Some(Auth::ChapMd5);
                        None
                    }
                    _ => Some(CHAP_MD5.to_vec()),
                },
                (option::MAGIC_NUMBER, 4) => {
                    let magic = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                    if magic == 0 || magic == self.magic {
                        // Perhaps a looped-back link: both sides pick again.
                        self.magic = self.new_magic(magic);
                        let other = self.new_magic(self.magic);
                        Some(other.to_be_bytes().to_vec())
                    } else {
                        peer_magic = magic;
                        None
                    }
                }
                _ => {
                    push_option(&mut rejects, kind, value);
                    continue;
                }
            };
            if let Some(suggestion) = suggestion {
                if nak {
                    push_option(&mut naks, kind, &suggestion);
                } else {
                    push_option(&mut rejects, kind, value);
                }
            }
        }
        if !rejects.is_empty() {
            Reply::Reject(rejects)
        } else if !naks.is_empty() {
            Reply::Nak(naks)
        } else {
            self.peer_mru = peer_mru;
            self.peer_magic = peer_magic;
            self.auth = auth;
            Reply::Ack
        }
    }

    fn naked(&mut self, options: &[Opt<'_>]) {
        for &(kind, value) in options {
            match (kind, value.len()) {
                (option::MRU, 2) => {
                    let mru = u16::from_be_bytes([value[0], value[1]]);
                    if (MRU_MIN..=MRU).contains(&mru) {
                        self.mru = mru;
                    }
                }
                (option::MAGIC_NUMBER, 4) => self.magic = self.new_magic(self.magic),
                _ => {}
            }
        }
    }

    fn rejected(&mut self, options: &[Opt<'_>]) {
        for &(kind, _) in options {
            match kind {
                option::MRU => self.ask_mru = false,
                option::MAGIC_NUMBER => {
                    self.ask_magic = false;
                    self.magic = 0;
                }
                _ => {}
            }
        }
    }
}

/// What LCP tells the session besides the automaton's actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    /// The peer rejected this protocol; stop it.
    ProtocolRejected(u16),
    /// Echo-Requests went unanswered: the link is dead.
    NoEcho,
}

/// The echo keepalive settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo {
    /// Milliseconds between Echo-Requests; 0 for none.
    pub interval_ms: u64,
    /// How many unanswered Echo-Requests in a row make the link dead.
    pub failures: u32,
}

impl Default for Echo {
    fn default() -> Self {
        Self {
            interval_ms: 10_000,
            failures: 3,
        }
    }
}

/// LCP of one session.
#[derive(Clone, Debug)]
pub struct Lcp {
    pub fsm: Fsm<LcpOptions>,
    echo: Echo,
    echo_at: Option<u64>,
    unanswered: u32,
    /// The peer rejected Echo-Request.
    echo_refused: bool,
}

impl Lcp {
    pub fn new(rng: Rng, limits: Limits, echo: Echo) -> Self {
        Self {
            fsm: Fsm::new(LcpOptions::new(rng), limits),
            echo,
            echo_at: None,
            unanswered: 0,
            echo_refused: false,
        }
    }

    pub fn opened(&self) -> bool {
        self.fsm.state() == fsm::State::Opened
    }

    pub fn next_timer(&self) -> Option<u64> {
        match (self.fsm.next_timer(), self.echo_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// A received LCP packet (the whole information field).
    pub fn receive(
        &mut self,
        now: u64,
        information: &[u8],
        out: &mut Vec<Action>,
    ) -> Option<Notice> {
        let packet = ppp::Packet::parse(information)?;
        let opened = self.opened();
        let notice = match packet.code {
            code::PROTOCOL_REJECT if opened => {
                let rejected = packet.data.get(..2)?;
                let rejected = u16::from_be_bytes([rejected[0], rejected[1]]);
                self.fsm.rxj(now, rejected != protocol::LCP, out);
                Some(Notice::ProtocolRejected(rejected))
            }
            code::ECHO_REQUEST if opened => {
                if self.looped(packet.data) {
                    return None;
                }
                let mut data = self.fsm.negotiation.magic.to_be_bytes().to_vec();
                data.extend_from_slice(&packet.data[4..]);
                out.push(Action::Send(ppp::packet(
                    code::ECHO_REPLY,
                    packet.id,
                    &data,
                )));
                None
            }
            code::ECHO_REPLY if opened => {
                if !self.looped(packet.data) {
                    self.unanswered = 0;
                }
                None
            }
            code::PROTOCOL_REJECT
            | code::ECHO_REQUEST
            | code::ECHO_REPLY
            | code::DISCARD_REQUEST => None,
            fsm::code::CODE_REJECT => {
                if matches!(packet.data.first(), Some(&code::ECHO_REQUEST)) {
                    self.echo_refused = true;
                }
                self.fsm.receive(now, information, out);
                None
            }
            _ => {
                self.fsm.receive(now, information, out);
                None
            }
        };
        self.settle_echo(now);
        notice
    }

    /// Runs the restart timer and the keepalive when they are due.
    pub fn timeout(&mut self, now: u64, out: &mut Vec<Action>) -> Option<Notice> {
        self.fsm.timeout(now, out);
        self.settle_echo(now);
        if self.echo_at.is_some_and(|at| now >= at) {
            if self.unanswered >= self.echo.failures {
                self.echo_at = None;
                return Some(Notice::NoEcho);
            }
            self.unanswered += 1;
            let id = self.fsm.new_id();
            let magic = self.fsm.negotiation.magic.to_be_bytes();
            out.push(Action::Send(ppp::packet(code::ECHO_REQUEST, id, &magic)));
            self.echo_at = Some(now + self.echo.interval_ms);
        }
        None
    }

    /// The Protocol-Reject for a received packet of a protocol we do not run; only
    /// while LCP is open.
    pub fn protocol_reject(&mut self, rejected: u16, information: &[u8]) -> Option<Vec<u8>> {
        if !self.opened() {
            return None;
        }
        let room = usize::from(self.fsm.negotiation.peer_mru).saturating_sub(6);
        let mut data = rejected.to_be_bytes().to_vec();
        data.extend_from_slice(&information[..information.len().min(room)]);
        let id = self.fsm.new_id();
        Some(ppp::packet(code::PROTOCOL_REJECT, id, &data))
    }

    /// Whether an Echo packet carries our own magic number.
    fn looped(&self, data: &[u8]) -> bool {
        let magic = self.fsm.negotiation.magic;
        data.len() < 4 || (magic != 0 && data[..4] == magic.to_be_bytes())
    }

    /// Starts the keepalive when LCP opens and stops it when it leaves Opened.
    fn settle_echo(&mut self, now: u64) {
        if !self.opened() || self.echo.interval_ms == 0 || self.echo_refused {
            self.echo_at = None;
            self.unanswered = 0;
        } else if self.echo_at.is_none() && self.unanswered == 0 {
            self.echo_at = Some(now + self.echo.interval_ms);
        }
    }
}
