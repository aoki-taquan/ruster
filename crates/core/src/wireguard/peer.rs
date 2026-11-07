//! One WireGuard interface's peers over IPv4: which peer an inner packet goes to,
//! the outer IPv4 and UDP headers around a sealed message, and the checks on an
//! outer packet that arrives. Nothing here allocates per packet.
//!
//! # Standards
//!
//! - WireGuard whitepaper section 2.1 (cryptokey routing): an outgoing packet goes
//!   to the peer whose allowed addresses hold its destination (the longest prefix
//!   wins); an incoming packet is accepted only if its source is within the
//!   allowed addresses of the peer whose session decrypted it.
//! - RFC 791 and RFC 768 for the outer headers. The UDP checksum is 0 ("none",
//!   RFC 768), which WireGuard receivers accept over IPv4.
//!
//! Deviations:
//!
//! - No endpoint roaming (whitepaper 2.1): a message from an address or port that
//!   is not the configured endpoint is dropped before it is opened, so a peer
//!   whose NAT changes its port is not reached until the configuration changes.
//! - Only IPv4 inside and outside for now.
//! - The outer ECN field is always 0 (the inner one is not copied).
//! - Outer packets with IPv4 options, or that are fragments, are not accepted.
//! - One session per peer (no "previous" and "next" keypair): the daemon replaces
//!   the keys, and a packet sealed with the old keys after that is refused.

use super::{open, parse_header, seal, ReplayWindow, SealError, HEADER_LEN, MESSAGE_TYPE_DATA};

const IPV4_HEADER: usize = 20;
const UDP_HEADER: usize = 8;
/// Bytes the outer headers add before the WireGuard message.
pub const OUTER_HEADERS_LEN: usize = IPV4_HEADER + UDP_HEADER;
const PROTOCOL_UDP: u8 = 17;
const OUTER_TTL: u8 = 64;
const FLAG_MORE_FRAGMENTS: u16 = 0x2000;
const FRAGMENT_OFFSET_MASK: u16 = 0x1fff;

/// An IPv4 prefix a peer may send from and be sent to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllowedPrefix {
    pub address: [u8; 4],
    pub len: u8,
}

impl AllowedPrefix {
    fn contains(self, address: [u8; 4]) -> bool {
        let mask = match self.len {
            0 => 0,
            len => u32::MAX << (32 - u32::from(len.min(32))),
        };
        u32::from_be_bytes(self.address) & mask == u32::from_be_bytes(address) & mask
    }
}

/// The keys of one session, as the key-exchange daemon hands them over.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionKeys {
    /// Seals what we send.
    pub send: [u8; 32],
    /// Opens what we receive.
    pub receive: [u8; 32],
    /// The index the peer gave this session: the receiver index of what we send.
    pub peer_index: u32,
    /// The index we gave this session: the receiver index of what we receive.
    pub local_index: u32,
}

/// What does not change while a configuration is in use.
#[derive(Clone, Copy, Debug)]
pub struct PeerConfig<'a> {
    pub endpoint: [u8; 4],
    pub endpoint_port: u16,
    pub allowed: &'a [AllowedPrefix],
}

/// What changes: the session and its counters.
#[derive(Clone, Debug, Default)]
pub struct PeerState {
    keys: Option<SessionKeys>,
    send_counter: u64,
    replay: ReplayWindow,
}

impl PeerState {
    /// Starts using new session keys: the counters start over.
    pub fn set_keys(&mut self, keys: SessionKeys) {
        *self = Self {
            keys: Some(keys),
            send_counter: 0,
            replay: ReplayWindow::new(),
        };
    }

    /// Like [`Self::set_keys`], for keys that may be ones used before: the send
    /// counter starts at `send_counter` (the next one the same send key has not used)
    /// and the replay window is `replay` when given. A send key must never seal two
    /// messages with the same counter.
    pub fn set_keys_continuing(
        &mut self,
        keys: SessionKeys,
        send_counter: u64,
        replay: Option<ReplayWindow>,
    ) {
        *self = Self {
            keys: Some(keys),
            send_counter,
            replay: replay.unwrap_or_default(),
        };
    }

    /// The session in use.
    pub fn keys(&self) -> Option<SessionKeys> {
        self.keys
    }

    /// The counter the next sent message uses.
    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// The counters received so far.
    pub fn replay_window(&self) -> &ReplayWindow {
        &self.replay
    }

    /// Stops using the session (it expired).
    pub fn clear_keys(&mut self) {
        *self = Self::default();
    }

    pub fn has_session(&self) -> bool {
        self.keys.is_some()
    }
}

/// One WireGuard interface.
#[derive(Clone, Copy, Debug)]
pub struct InterfaceConfig<'a> {
    pub local: [u8; 4],
    pub listen_port: u16,
    pub peers: &'a [PeerConfig<'a>],
}

impl InterfaceConfig<'_> {
    /// The peer an inner packet to `destination` goes to: the longest allowed
    /// prefix wins.
    pub fn peer_for_destination(&self, destination: [u8; 4]) -> Option<usize> {
        self.peers
            .iter()
            .enumerate()
            .flat_map(|(index, peer)| {
                peer.allowed
                    .iter()
                    .filter(move |p| p.contains(destination))
                    .map(move |p| (p.len, index))
            })
            .max_by_key(|&(len, _)| len)
            .map(|(_, index)| index)
    }
}

/// Why an outgoing packet was not made into a WireGuard packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendError {
    /// No peer's allowed addresses hold the destination.
    NoPeer,
    /// The peer has no session: the daemon must do a handshake.
    NoSession,
    /// The session's counter is used up: the daemon must do a handshake.
    Exhausted,
    /// `out` is too small.
    NoRoom,
    /// The inner packet is not IPv4.
    InnerInvalid,
}

/// Makes the outer IPv4 packet (without an Ethernet header) that carries `inner`
/// (an IPv4 packet) to its peer, into `out`. Returns the peer's index and the
/// length written. `out` needs [`OUTER_HEADERS_LEN`] + 16 + the padded inner
/// length + 16 bytes.
pub fn encapsulate(
    interface: &InterfaceConfig<'_>,
    peers: &mut [PeerState],
    inner: &[u8],
    out: &mut [u8],
) -> Result<(usize, usize), SendError> {
    if inner.len() < IPV4_HEADER || inner[0] >> 4 != 4 {
        return Err(SendError::InnerInvalid);
    }
    let destination = [inner[16], inner[17], inner[18], inner[19]];
    let index = interface
        .peer_for_destination(destination)
        .ok_or(SendError::NoPeer)?;
    let (config, state) = (&interface.peers[index], &mut peers[index]);
    let keys = state.keys.ok_or(SendError::NoSession)?;
    if out.len() < OUTER_HEADERS_LEN + HEADER_LEN + inner.len() {
        return Err(SendError::NoRoom);
    }
    let message = &mut out[OUTER_HEADERS_LEN..];
    message[HEADER_LEN..HEADER_LEN + inner.len()].copy_from_slice(inner);
    let length = seal(
        &keys.send,
        keys.peer_index,
        state.send_counter,
        message,
        inner.len(),
    )
    .map_err(|e| match e {
        SealError::CounterExhausted => SendError::Exhausted,
        SealError::NoRoom => SendError::NoRoom,
    })?;
    state.send_counter += 1;

    let total = OUTER_HEADERS_LEN + length;
    let udp_length = (UDP_HEADER + length) as u16;
    let ip = &mut out[..IPV4_HEADER];
    ip[0] = 0x45;
    ip[1] = inner[1] & 0xfc; // DSCP is copied; the ECN bits are left 0
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[4..8].fill(0);
    ip[6] = 0x40; // Don't Fragment
    ip[8] = OUTER_TTL;
    ip[9] = PROTOCOL_UDP;
    ip[10..12].fill(0);
    ip[12..16].copy_from_slice(&interface.local);
    ip[16..20].copy_from_slice(&config.endpoint);
    let checksum = crate::ipv4_header_checksum(ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    let udp = &mut out[IPV4_HEADER..OUTER_HEADERS_LEN];
    udp[0..2].copy_from_slice(&interface.listen_port.to_be_bytes());
    udp[2..4].copy_from_slice(&config.endpoint_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_length.to_be_bytes());
    udp[6..8].fill(0);
    Ok((index, total))
}

/// What arrived on the WireGuard port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Received {
    /// Not for this interface (another address or port, or not UDP).
    NotForUs,
    /// A handshake message (types 1 to 3, or a cookie reply): for the daemon.
    Handshake,
    /// An empty data message: the peer is alive.
    Keepalive { peer: usize },
    /// A decrypted inner packet at `inner` in the outer packet's bytes, `peer`'s.
    Data {
        peer: usize,
        inner: core::ops::Range<usize>,
    },
}

/// Why an outer packet was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveError {
    /// Malformed outer headers, an option or a fragment.
    OuterInvalid,
    /// No session has this receiver index.
    UnknownSession,
    /// Not from the peer's endpoint.
    WrongEndpoint,
    /// Wrong tag or an invalid message.
    Authentication,
    /// A repeated or too old counter.
    Replay,
    /// The decrypted packet is not a whole IPv4 packet.
    InnerInvalid,
    /// The inner source is outside the peer's allowed addresses.
    NotAllowed,
}

/// Checks and decrypts the outer IPv4 packet `packet` (no Ethernet header) in place.
pub fn decapsulate(
    interface: &InterfaceConfig<'_>,
    peers: &mut [PeerState],
    packet: &mut [u8],
) -> Result<Received, ReceiveError> {
    use ReceiveError::*;
    if packet.len() < OUTER_HEADERS_LEN || packet[0] >> 4 != 4 {
        return Ok(Received::NotForUs);
    }
    if packet[9] != PROTOCOL_UDP || packet[16..20] != interface.local {
        return Ok(Received::NotForUs);
    }
    let header = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header < IPV4_HEADER || total > packet.len() || total < header + UDP_HEADER {
        return Err(OuterInvalid);
    }
    if u16::from_be_bytes([packet[header + 2], packet[header + 3]]) != interface.listen_port {
        return Ok(Received::NotForUs);
    }
    let flags = u16::from_be_bytes([packet[6], packet[7]]);
    if header != IPV4_HEADER
        || flags & (FLAG_MORE_FRAGMENTS | FRAGMENT_OFFSET_MASK) != 0
        || crate::internet_checksum(&packet[..header]) != 0
    {
        return Err(OuterInvalid);
    }
    let udp_length = usize::from(u16::from_be_bytes([packet[header + 4], packet[header + 5]]));
    if udp_length < UDP_HEADER || header + udp_length != total {
        return Err(OuterInvalid);
    }
    let source = [packet[12], packet[13], packet[14], packet[15]];
    let source_port = u16::from_be_bytes([packet[header], packet[header + 1]]);
    let message = &mut packet[OUTER_HEADERS_LEN..total];
    if message.first() != Some(&MESSAGE_TYPE_DATA) {
        return Ok(Received::Handshake);
    }
    let Some(data) = parse_header(message) else {
        return Err(Authentication);
    };
    let index = peers
        .iter()
        .position(|p| p.keys.is_some_and(|k| k.local_index == data.receiver_index))
        .ok_or(UnknownSession)?;
    let (config, state) = (&interface.peers[index], &mut peers[index]);
    if config.endpoint != source || config.endpoint_port != source_port {
        return Err(WrongEndpoint);
    }
    let keys = state.keys.expect("found by its keys");
    let range = open(&keys.receive, message).ok_or(Authentication)?;
    if !state.replay.accept(data.counter) {
        return Err(Replay);
    }
    if range.is_empty() {
        return Ok(Received::Keepalive { peer: index });
    }
    let inner = &message[range.clone()];
    if inner.len() < IPV4_HEADER || inner[0] >> 4 != 4 {
        return Err(InnerInvalid);
    }
    let inner_total = usize::from(u16::from_be_bytes([inner[2], inner[3]]));
    if inner_total < IPV4_HEADER || inner_total > inner.len() {
        return Err(InnerInvalid);
    }
    let inner_source = [inner[12], inner[13], inner[14], inner[15]];
    if !config.allowed.iter().any(|p| p.contains(inner_source)) {
        return Err(NotAllowed);
    }
    let start = OUTER_HEADERS_LEN + range.start;
    Ok(Received::Data {
        peer: index,
        inner: start..start + inner_total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: [u8; 4] = [192, 0, 2, 1];
    const REMOTE: [u8; 4] = [198, 51, 100, 7];

    fn ipv4(source: [u8; 4], destination: [u8; 4], payload: usize) -> Vec<u8> {
        let mut p = vec![0u8; 20 + payload];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + payload) as u16).to_be_bytes());
        p[8] = 63;
        p[9] = 1;
        p[12..16].copy_from_slice(&source);
        p[16..20].copy_from_slice(&destination);
        p
    }

    fn keys(local_index: u32) -> SessionKeys {
        SessionKeys {
            send: [1; 32],
            receive: [2; 32],
            peer_index: 77,
            local_index,
        }
    }

    /// Two ends: A (192.0.2.1) and B (198.51.100.7), with mirrored keys.
    struct Pair {
        a_allowed: Vec<AllowedPrefix>,
        b_allowed: Vec<AllowedPrefix>,
    }

    fn pair() -> Pair {
        Pair {
            a_allowed: vec![AllowedPrefix {
                address: [10, 2, 0, 0],
                len: 16,
            }],
            b_allowed: vec![AllowedPrefix {
                address: [10, 1, 0, 0],
                len: 16,
            }],
        }
    }

    fn end<'a>(
        local: [u8; 4],
        remote: [u8; 4],
        allowed: &'a [AllowedPrefix],
        peers: &'a mut Vec<PeerConfig<'a>>,
    ) -> InterfaceConfig<'a> {
        peers.push(PeerConfig {
            endpoint: remote,
            endpoint_port: 51820,
            allowed,
        });
        InterfaceConfig {
            local,
            listen_port: 51820,
            peers,
        }
    }

    #[test]
    fn a_packet_goes_through_the_tunnel_and_comes_out_intact() {
        let p = pair();
        let (mut ca, mut cb) = (Vec::new(), Vec::new());
        let (ia, ib) = (
            end(LOCAL, REMOTE, &p.a_allowed, &mut ca),
            end(REMOTE, LOCAL, &p.b_allowed, &mut cb),
        );
        let mut sa = vec![PeerState::default()];
        let mut sb = vec![PeerState::default()];
        sa[0].set_keys(SessionKeys {
            send: [1; 32],
            receive: [2; 32],
            peer_index: 22,
            local_index: 11,
        });
        sb[0].set_keys(SessionKeys {
            send: [2; 32],
            receive: [1; 32],
            peer_index: 11,
            local_index: 22,
        });

        let inner = ipv4([10, 1, 0, 5], [10, 2, 0, 9], 33);
        let mut out = vec![0u8; 2000];
        let (peer, len) = encapsulate(&ia, &mut sa, &inner, &mut out).unwrap();
        assert_eq!(peer, 0);
        assert_eq!(len, 28 + 16 + 64 + 16);
        // A real IPv4 header: valid checksum, UDP, DF, from our port to the endpoint's.
        assert_eq!(crate::internet_checksum(&out[..20]), 0);
        assert_eq!(out[9], 17);
        assert_eq!(out[6] & 0x40, 0x40);

        let mut wire = out[..len].to_vec();
        let got = decapsulate(&ib, &mut sb, &mut wire).unwrap();
        let Received::Data {
            peer: 0,
            inner: range,
        } = got
        else {
            panic!("{got:?}")
        };
        assert_eq!(wire[range], inner[..]);

        // The same packet again is a replay.
        let mut again = out[..len].to_vec();
        assert_eq!(
            decapsulate(&ib, &mut sb, &mut again),
            Err(ReceiveError::Replay)
        );
    }

    #[test]
    fn cryptokey_routing_picks_the_longest_prefix_and_checks_the_source() {
        let wide = [AllowedPrefix {
            address: [10, 0, 0, 0],
            len: 8,
        }];
        let narrow = [AllowedPrefix {
            address: [10, 9, 0, 0],
            len: 16,
        }];
        let peers = [
            PeerConfig {
                endpoint: REMOTE,
                endpoint_port: 1,
                allowed: &wide,
            },
            PeerConfig {
                endpoint: REMOTE,
                endpoint_port: 2,
                allowed: &narrow,
            },
        ];
        let interface = InterfaceConfig {
            local: LOCAL,
            listen_port: 51820,
            peers: &peers,
        };
        assert_eq!(interface.peer_for_destination([10, 9, 1, 1]), Some(1));
        assert_eq!(interface.peer_for_destination([10, 8, 1, 1]), Some(0));
        assert_eq!(interface.peer_for_destination([11, 0, 0, 1]), None);
        let all = [AllowedPrefix {
            address: [0, 0, 0, 0],
            len: 0,
        }];
        let default = [PeerConfig {
            endpoint: REMOTE,
            endpoint_port: 1,
            allowed: &all,
        }];
        let interface = InterfaceConfig {
            local: LOCAL,
            listen_port: 1,
            peers: &default,
        };
        assert_eq!(interface.peer_for_destination([203, 0, 113, 1]), Some(0));
    }

    #[test]
    fn sending_needs_a_peer_a_session_and_room() {
        let p = pair();
        let mut c = Vec::new();
        let ia = end(LOCAL, REMOTE, &p.a_allowed, &mut c);
        let mut sa = vec![PeerState::default()];
        let mut out = vec![0u8; 2000];
        let inner = ipv4([10, 1, 0, 5], [10, 2, 0, 9], 10);
        assert_eq!(
            encapsulate(&ia, &mut sa, &inner, &mut out),
            Err(SendError::NoSession)
        );
        let elsewhere = ipv4([10, 1, 0, 5], [10, 7, 0, 9], 10);
        assert_eq!(
            encapsulate(&ia, &mut sa, &elsewhere, &mut out),
            Err(SendError::NoPeer)
        );
        sa[0].set_keys(keys(1));
        let mut small = vec![0u8; 40];
        assert_eq!(
            encapsulate(&ia, &mut sa, &inner, &mut small),
            Err(SendError::NoRoom)
        );
        assert_eq!(
            encapsulate(&ia, &mut sa, &[0x60; 40], &mut out),
            Err(SendError::InnerInvalid)
        );
        sa[0].send_counter = crate::wireguard::REJECT_AFTER_MESSAGES;
        assert_eq!(
            encapsulate(&ia, &mut sa, &inner, &mut out),
            Err(SendError::Exhausted)
        );
    }

    fn sealed_from_remote(source: [u8; 4], port: u16) -> (Vec<u8>, Vec<PeerState>, Pair) {
        let p = pair();
        let mut c = Vec::new();
        let sender = end(REMOTE, LOCAL, &p.b_allowed, &mut c);
        let mut ss = vec![PeerState::default()];
        ss[0].set_keys(SessionKeys {
            send: [2; 32],
            receive: [1; 32],
            peer_index: 11,
            local_index: 22,
        });
        let inner = ipv4(source, [10, 1, 0, 9], 8);
        let mut out = vec![0u8; 500];
        let (_, len) = encapsulate(&sender, &mut ss, &inner, &mut out).unwrap();
        out.truncate(len);
        out[IPV4_HEADER..IPV4_HEADER + 2].copy_from_slice(&port.to_be_bytes());
        let mut receiver = vec![PeerState::default()];
        receiver[0].set_keys(SessionKeys {
            send: [1; 32],
            receive: [2; 32],
            peer_index: 22,
            local_index: 11,
        });
        (out, receiver, p)
    }

    fn receive(
        packet: &mut [u8],
        states: &mut [PeerState],
        p: &Pair,
    ) -> Result<Received, ReceiveError> {
        let mut c = Vec::new();
        let i = end(LOCAL, REMOTE, &p.a_allowed, &mut c);
        decapsulate(&i, states, packet)
    }

    #[test]
    fn what_is_not_ours_or_not_allowed_is_refused() {
        // The sender's source is inside A's allowed 10.2/16? No: A allows 10.2/16 as
        // the peer's source, so a packet from 10.1.0.5 is outside it.
        let (mut wire, mut states, p) = sealed_from_remote([10, 1, 0, 5], 51820);
        assert_eq!(
            receive(&mut wire, &mut states, &p),
            Err(ReceiveError::NotAllowed)
        );

        let (mut wire, mut states, p) = sealed_from_remote([10, 2, 0, 5], 51820);
        let mut other_port = wire.clone();
        other_port[IPV4_HEADER + 2..IPV4_HEADER + 4].copy_from_slice(&9u16.to_be_bytes());
        assert_eq!(
            receive(&mut other_port, &mut states, &p),
            Ok(Received::NotForUs)
        );
        let mut elsewhere = wire.clone();
        elsewhere[16] ^= 1;
        assert_eq!(
            receive(&mut elsewhere, &mut states, &p),
            Ok(Received::NotForUs)
        );
        let mut wrong_source_port = wire.clone();
        wrong_source_port[IPV4_HEADER..IPV4_HEADER + 2].copy_from_slice(&9u16.to_be_bytes());
        assert_eq!(
            receive(&mut wrong_source_port, &mut states, &p),
            Err(ReceiveError::WrongEndpoint)
        );
        let mut forged = wire.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert_eq!(
            receive(&mut forged, &mut states, &p),
            Err(ReceiveError::Authentication)
        );
        // A forged packet did not move the replay window: the real one still passes
        // its counter check (it then fails only the allowed-address check).
        assert_eq!(
            receive(&mut wire, &mut states, &p),
            Ok(Received::Data {
                peer: 0,
                inner: 44..72
            })
        );
    }

    #[test]
    fn handshakes_unknown_sessions_fragments_and_keepalives() {
        let (wire, mut states, p) = sealed_from_remote([10, 2, 0, 5], 51820);
        let mut handshake = wire.clone();
        handshake[OUTER_HEADERS_LEN] = 1;
        assert_eq!(
            receive(&mut handshake, &mut states, &p),
            Ok(Received::Handshake)
        );

        let mut unknown = wire.clone();
        unknown[OUTER_HEADERS_LEN + 4] ^= 1;
        assert_eq!(
            receive(&mut unknown, &mut states, &p),
            Err(ReceiveError::UnknownSession)
        );

        let mut fragment = wire.clone();
        fragment[6] = 0x20;
        assert_eq!(
            receive(&mut fragment, &mut states, &p),
            Err(ReceiveError::OuterInvalid)
        );
        let mut short_udp = wire.clone();
        short_udp[IPV4_HEADER + 5] ^= 1;
        assert_eq!(
            receive(&mut short_udp, &mut states, &p),
            Err(ReceiveError::OuterInvalid)
        );

        // A keepalive: sealed with no inner packet.
        let keys = states[0].keys.unwrap();
        let mut keepalive = wire[..OUTER_HEADERS_LEN].to_vec();
        keepalive.resize(OUTER_HEADERS_LEN + 32, 0);
        seal(
            &[2; 32],
            keys.local_index,
            5,
            &mut keepalive[OUTER_HEADERS_LEN..],
            0,
        )
        .unwrap();
        let total = keepalive.len();
        keepalive[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        keepalive[IPV4_HEADER + 4..IPV4_HEADER + 6]
            .copy_from_slice(&((total - 20) as u16).to_be_bytes());
        keepalive[10..12].fill(0);
        let sum = crate::ipv4_header_checksum(&keepalive[..20]);
        keepalive[10..12].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(
            receive(&mut keepalive, &mut states, &p),
            Ok(Received::Keepalive { peer: 0 })
        );
    }

    #[test]
    fn continuing_keeps_the_counter_and_the_window_it_is_given() {
        let mut earlier = PeerState::default();
        earlier.set_keys(keys(1));
        earlier.send_counter = 40;
        assert!(earlier.replay.accept(9));
        let mut state = PeerState::default();
        state.set_keys_continuing(
            keys(2),
            earlier.send_counter(),
            Some(earlier.replay_window().clone()),
        );
        assert_eq!(state.send_counter(), 40);
        assert_eq!(state.keys(), Some(keys(2)));
        assert!(!state.replay.accept(9), "a counter seen is still refused");
        assert!(state.replay.accept(10));
        // Without a window, a new one.
        state.set_keys_continuing(keys(3), 5, None);
        assert!(state.replay.accept(9));
    }

    #[test]
    fn replacing_the_keys_restarts_the_counters() {
        let mut state = PeerState::default();
        assert!(!state.has_session());
        state.set_keys(keys(1));
        state.send_counter = 9;
        assert!(state.replay.accept(4));
        state.set_keys(keys(2));
        assert_eq!(state.send_counter, 0);
        assert!(state.replay.accept(4));
        state.clear_keys();
        assert!(!state.has_session());
    }
}
