//! PPPoE Discovery for the host: find an access concentrator (AC) and get a session
//! ID from it.
//!
//! The host broadcasts a PADI, takes the first PADO that offers the wanted service
//! (and, when set, comes from the wanted AC name), sends that AC a PADR and gets
//! the session ID in its PADS. A PADT from the AC ends the session; the host sends
//! one to end it itself. Every PADI and PADR carries the host's Host-Uniq, and only
//! answers that echo it are taken, so several sessions can share an interface.
//!
//! # Standards
//!
//! - RFC 2516 section 4: the packet format (version 1, type 1, the codes) and the
//!   tags of Appendix A. A tag list ends at the payload length or at End-Of-List;
//!   a tag that runs past the payload makes the packet invalid.
//! - RFC 2516 section 5.1: the PADI is broadcast with exactly one Service-Name tag.
//!   Section 5.2: a PADO is taken only from a unicast source, sent to us, with
//!   session ID 0, an AC-Name tag and a Service-Name tag for the wanted service.
//!   Section 5.3: the PADR goes to that AC with one Service-Name tag. Section 5.4:
//!   a PADS with an error tag or session ID 0 refuses the session. Section 5.5: a
//!   PADT from the AC for our session ID ends it.
//! - RFC 2516 Appendix A: Host-Uniq is sent in PADI and PADR and must come back
//!   unchanged; AC-Cookie and Relay-Session-Id from the PADO are returned in the
//!   PADR.
//! - RFC 2516 sections 5.1 and 5.3: with no PADO, the PADI is sent again with the
//!   wait doubled; with no PADS, the PADR is sent again the same way and, after
//!   [`PADR_TRIES`], Discovery starts again from the PADI.
//!
//! Deviations: the wait starts at [`FIRST_WAIT_MS`] and stops doubling at
//! [`LONGEST_WAIT_MS`] (the RFC sets no values). The first acceptable PADO is
//! taken; offers are not compared. Vendor-Specific tags are ignored, and the host
//! sends none.

use crate::Mac;

/// The Ethernet type of PPPoE Discovery.
pub const ETHERTYPE: [u8; 2] = [0x88, 0x63];
const BROADCAST: Mac = [0xff; 6];
const ETHERNET: usize = 14;
const HEADER: usize = 6;
const VERSION_TYPE: u8 = 0x11;

/// The Discovery codes (RFC 2516 section 5).
pub mod code {
    pub const PADI: u8 = 0x09;
    pub const PADO: u8 = 0x07;
    pub const PADR: u8 = 0x19;
    pub const PADS: u8 = 0x65;
    pub const PADT: u8 = 0xa7;
}

/// The tag types (RFC 2516 Appendix A).
pub mod tag {
    pub const END_OF_LIST: u16 = 0x0000;
    pub const SERVICE_NAME: u16 = 0x0101;
    pub const AC_NAME: u16 = 0x0102;
    pub const HOST_UNIQ: u16 = 0x0103;
    pub const AC_COOKIE: u16 = 0x0104;
    pub const RELAY_SESSION_ID: u16 = 0x0110;
    pub const SERVICE_NAME_ERROR: u16 = 0x0201;
    pub const AC_SYSTEM_ERROR: u16 = 0x0202;
    pub const GENERIC_ERROR: u16 = 0x0203;
}

/// The first wait for a PADO or PADS, in milliseconds.
pub const FIRST_WAIT_MS: u64 = 2_000;
/// The longest wait: the doubling stops here.
pub const LONGEST_WAIT_MS: u64 = 32_000;
/// How many PADRs are sent before starting again from the PADI.
pub const PADR_TRIES: u32 = 3;

/// A Discovery packet in an Ethernet frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    pub destination: Mac,
    pub source: Mac,
    pub code: u8,
    pub session: u16,
    /// The tags, up to the PPPoE length (Ethernet padding removed).
    pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
    /// Reads a Discovery frame. `None` for another Ethernet type, another version
    /// or type, or a length past the frame.
    pub fn parse(frame: &'a [u8]) -> Option<Self> {
        let header = frame.get(ETHERNET..ETHERNET + HEADER)?;
        if frame[12..14] != ETHERTYPE || header[0] != VERSION_TYPE {
            return None;
        }
        let length = usize::from(u16::from_be_bytes([header[4], header[5]]));
        let payload = frame.get(ETHERNET + HEADER..ETHERNET + HEADER + length)?;
        Some(Self {
            destination: frame[0..6].try_into().ok()?,
            source: frame[6..12].try_into().ok()?,
            code: header[1],
            session: u16::from_be_bytes([header[2], header[3]]),
            payload,
        })
    }
}

/// A Discovery frame with `tags` in order.
pub fn frame(
    destination: Mac,
    source: Mac,
    code: u8,
    session: u16,
    tags: &[(u16, &[u8])],
) -> Vec<u8> {
    let length: usize = tags.iter().map(|(_, value)| 4 + value.len()).sum();
    let mut out = Vec::with_capacity(ETHERNET + HEADER + length);
    out.extend_from_slice(&destination);
    out.extend_from_slice(&source);
    out.extend_from_slice(&ETHERTYPE);
    out.extend_from_slice(&[VERSION_TYPE, code]);
    out.extend_from_slice(&session.to_be_bytes());
    out.extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes());
    for (kind, value) in tags {
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}

/// The tags of a packet that the host looks at.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tags<'a> {
    pub service_names: Vec<&'a [u8]>,
    pub ac_name: Option<&'a [u8]>,
    pub host_uniq: Option<&'a [u8]>,
    pub ac_cookie: Option<&'a [u8]>,
    pub relay_session_id: Option<&'a [u8]>,
    /// The first error tag (Service-Name-Error, AC-System-Error or Generic-Error).
    pub error: Option<u16>,
}

impl<'a> Tags<'a> {
    /// Reads the tags of `payload`. `None` when a tag runs past the end. Of a tag
    /// that appears more than once, the first is kept (all Service-Names are).
    pub fn parse(payload: &'a [u8]) -> Option<Self> {
        let mut tags = Self::default();
        let mut rest = payload;
        while !rest.is_empty() {
            let head = rest.get(..4)?;
            let kind = u16::from_be_bytes([head[0], head[1]]);
            let length = usize::from(u16::from_be_bytes([head[2], head[3]]));
            let value = rest.get(4..4 + length)?;
            rest = &rest[4 + length..];
            match kind {
                tag::END_OF_LIST => break,
                tag::SERVICE_NAME => tags.service_names.push(value),
                tag::AC_NAME => {
                    tags.ac_name.get_or_insert(value);
                }
                tag::HOST_UNIQ => {
                    tags.host_uniq.get_or_insert(value);
                }
                tag::AC_COOKIE => {
                    tags.ac_cookie.get_or_insert(value);
                }
                tag::RELAY_SESSION_ID => {
                    tags.relay_session_id.get_or_insert(value);
                }
                tag::SERVICE_NAME_ERROR | tag::AC_SYSTEM_ERROR | tag::GENERIC_ERROR => {
                    tags.error.get_or_insert(kind);
                }
                _ => {}
            }
        }
        Some(tags)
    }
}

/// What the host asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The MAC address of the interface the session runs on.
    pub mac: Mac,
    /// The service name; empty for any service.
    pub service: Vec<u8>,
    /// Take offers only from the AC of this name.
    pub ac_name: Option<Vec<u8>>,
}

/// What Discovery found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The AC gave the session ID.
    Session { id: u16, ac: Mac },
    /// The AC refused the session in its PADS (the error tag, or 0 for a session ID
    /// of 0). Discovery stops; the caller starts it again.
    Refused(u16),
    /// The AC ended the session with a PADT. Discovery stops.
    Terminated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    Idle,
    /// The PADI is sent; waiting for a PADO.
    Selecting,
    /// The PADR is sent to `ac`; waiting for its PADS.
    Requesting {
        ac: Mac,
        cookie: Option<Vec<u8>>,
        relay: Option<Vec<u8>>,
        tries: u32,
    },
    Session {
        ac: Mac,
        id: u16,
    },
}

/// One session's Discovery.
#[derive(Clone, Debug)]
pub struct Discovery {
    settings: Settings,
    host_uniq: [u8; 8],
    state: State,
    /// When to send the PADI or PADR again.
    timer: Option<u64>,
    wait_ms: u64,
}

impl Discovery {
    /// `host_uniq` must differ between the sessions on one interface.
    pub fn new(settings: Settings, host_uniq: [u8; 8]) -> Self {
        Self {
            settings,
            host_uniq,
            state: State::Idle,
            timer: None,
            wait_ms: FIRST_WAIT_MS,
        }
    }

    pub fn host_uniq(&self) -> [u8; 8] {
        self.host_uniq
    }

    /// The session ID and the AC's MAC address, once the PADS came.
    pub fn session(&self) -> Option<(u16, Mac)> {
        match self.state {
            State::Session { ac, id } => Some((id, ac)),
            _ => None,
        }
    }

    /// The time the next retransmission is due.
    pub fn next_timer(&self) -> Option<u64> {
        self.timer
    }

    /// Starts again from the PADI, whatever the state.
    pub fn start(&mut self, now: u64, out: &mut Vec<Vec<u8>>) {
        self.state = State::Selecting;
        self.wait_ms = FIRST_WAIT_MS;
        self.send_padi(now, out);
    }

    /// Ends the session: a PADT to the AC if there is one. Discovery stops.
    pub fn terminate(&mut self, out: &mut Vec<Vec<u8>>) {
        if let State::Session { ac, id } = self.state {
            out.push(frame(ac, self.settings.mac, code::PADT, id, &[]));
        }
        self.stop();
    }

    /// Stops without sending anything.
    pub fn stop(&mut self) {
        self.state = State::Idle;
        self.timer = None;
    }

    /// Sends the PADI or PADR again when its wait is over.
    pub fn timeout(&mut self, now: u64, out: &mut Vec<Vec<u8>>) {
        if self.timer.is_none_or(|at| now < at) {
            return;
        }
        match &mut self.state {
            State::Selecting => {}
            State::Requesting { tries, .. } if *tries < PADR_TRIES => *tries += 1,
            State::Requesting { .. } => return self.start(now, out),
            State::Idle | State::Session { .. } => {
                self.timer = None;
                return;
            }
        }
        self.wait_ms = (self.wait_ms * 2).min(LONGEST_WAIT_MS);
        if self.state == State::Selecting {
            self.send_padi(now, out);
        } else {
            self.send_padr(now, out);
        }
    }

    /// Takes a received Discovery frame.
    pub fn receive(&mut self, now: u64, frame: &[u8], out: &mut Vec<Vec<u8>>) -> Option<Event> {
        let packet = Packet::parse(frame)?;
        if packet.destination != self.settings.mac {
            return None;
        }
        match (&self.state, packet.code) {
            (State::Selecting, code::PADO) => {
                let tags = self.answer_tags(&packet)?;
                let ac_name = tags.ac_name?;
                let service = self.settings.service.as_slice();
                let offered = tags
                    .service_names
                    .iter()
                    .any(|name| service.is_empty() || *name == service);
                let wanted_ac = self
                    .settings
                    .ac_name
                    .as_deref()
                    .is_none_or(|name| name == ac_name);
                if packet.session != 0
                    || packet.source[0] & 1 != 0
                    || tags.error.is_some()
                    || !offered
                    || !wanted_ac
                {
                    return None;
                }
                self.state = State::Requesting {
                    ac: packet.source,
                    cookie: tags.ac_cookie.map(<[u8]>::to_vec),
                    relay: tags.relay_session_id.map(<[u8]>::to_vec),
                    tries: 1,
                };
                self.wait_ms = FIRST_WAIT_MS;
                self.send_padr(now, out);
                None
            }
            (State::Requesting { ac, .. }, code::PADS) if packet.source == *ac => {
                let ac = *ac;
                let tags = self.answer_tags(&packet)?;
                if let Some(error) = tags.error {
                    self.stop();
                    return Some(Event::Refused(error));
                }
                if packet.session == 0 {
                    self.stop();
                    return Some(Event::Refused(0));
                }
                self.state = State::Session {
                    ac,
                    id: packet.session,
                };
                self.timer = None;
                Some(Event::Session {
                    id: packet.session,
                    ac,
                })
            }
            (State::Session { ac, id }, code::PADT)
                if packet.source == *ac && packet.session == *id =>
            {
                self.stop();
                Some(Event::Terminated)
            }
            _ => None,
        }
    }

    /// The tags of a PADO or PADS, if they are valid and echo our Host-Uniq.
    fn answer_tags<'a>(&self, packet: &Packet<'a>) -> Option<Tags<'a>> {
        let tags = Tags::parse(packet.payload)?;
        (tags.host_uniq == Some(self.host_uniq.as_slice())).then_some(tags)
    }

    fn send_padi(&mut self, now: u64, out: &mut Vec<Vec<u8>>) {
        out.push(frame(
            BROADCAST,
            self.settings.mac,
            code::PADI,
            0,
            &[
                (tag::SERVICE_NAME, &self.settings.service),
                (tag::HOST_UNIQ, &self.host_uniq),
            ],
        ));
        self.timer = Some(now + self.wait_ms);
    }

    fn send_padr(&mut self, now: u64, out: &mut Vec<Vec<u8>>) {
        let State::Requesting {
            ac, cookie, relay, ..
        } = &self.state
        else {
            return;
        };
        let mut tags: Vec<(u16, &[u8])> = vec![
            (tag::SERVICE_NAME, &self.settings.service),
            (tag::HOST_UNIQ, &self.host_uniq),
        ];
        if let Some(cookie) = cookie {
            tags.push((tag::AC_COOKIE, cookie));
        }
        if let Some(relay) = relay {
            tags.push((tag::RELAY_SESSION_ID, relay));
        }
        out.push(frame(*ac, self.settings.mac, code::PADR, 0, &tags));
        self.timer = Some(now + self.wait_ms);
    }
}
