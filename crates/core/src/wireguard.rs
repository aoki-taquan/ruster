//! WireGuard's data messages (type 4, "transport data") and the receive side's
//! replay window. The handshake is not here: a daemon outside the FE does it and
//! hands the FE the session keys.
//!
//! A message is worked on in place in a borrowed buffer: no allocation.
//!
//! # Standards
//!
//! - WireGuard whitepaper (Donenfeld, 2020) sections 5.4.6 (transport data
//!   message layout, padding to a multiple of 16, keepalive as an empty packet),
//!   5.4.6 and 6.1 (counter and message limits), and the sliding window of
//!   RFC 6479 (IPsec Anti-Replay Algorithm without Bit Shifting), which WireGuard
//!   uses with a window of 8128 counters.
//! - ChaCha20-Poly1305 with the nonce of RFC 8439 as WireGuard builds it:
//!   the `chacha20poly1305` module.
//!
//! Deviations: none for the data messages. Rekey timers (the whitepaper's 6.1
//! `REKEY_AFTER_*`) are the key-exchange daemon's job; the FE only refuses to
//! send or receive past the hard limits.

use crate::chacha20poly1305::{self, TAG_LEN};

mod peer;
mod receive;
mod send;
pub use peer::{
    decapsulate, encapsulate, AllowedPrefix, InterfaceConfig, PeerConfig, PeerState, ReceiveError,
    Received, SendError, SessionKeys, OUTER_HEADERS_LEN,
};
pub(crate) use receive::receive;
pub use receive::WireguardInterface;
pub use send::{
    execute_one_wireguard_send, GeneratedWireguardReport, WireguardSendCounters,
    WireguardSendRuntime, WireguardStagedFrame, WireguardStorageError,
};
pub(crate) use send::{of, stage};

/// Message type of a transport data message.
pub const MESSAGE_TYPE_DATA: u8 = 4;
/// Bytes before the encrypted part: type, three reserved bytes, receiver index,
/// counter.
pub const HEADER_LEN: usize = 16;
/// Smallest message: the header and the tag of an empty (keepalive) packet.
pub const MIN_MESSAGE_LEN: usize = HEADER_LEN + TAG_LEN;
/// The encrypted part is padded to a multiple of this.
pub const PADDING_STEP: usize = 16;
/// A key is not used for this many messages or more (2^64 - 2^13 - 1).
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
/// How many counters behind the highest one are still accepted.
pub const REPLAY_WINDOW: u64 = 8128;

const WINDOW_WORDS: usize = 128;

/// The length of the padded encrypted part for an inner packet of `inner_len`.
pub const fn padded_len(inner_len: usize) -> usize {
    inner_len.div_ceil(PADDING_STEP) * PADDING_STEP
}

/// The fields of a transport data message that are readable before decrypting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataHeader {
    /// The index the receiver gave this session, to pick the session by.
    pub receiver_index: u32,
    /// The sender's packet counter, the nonce of this message.
    pub counter: u64,
}

/// Reads the header of a transport data message, or `None` if `message` is not
/// one (wrong type, reserved bytes set, or shorter than a keepalive).
pub fn parse_header(message: &[u8]) -> Option<DataHeader> {
    if message.len() < MIN_MESSAGE_LEN
        || message[0] != MESSAGE_TYPE_DATA
        || message[1..4] != [0, 0, 0]
    {
        return None;
    }
    Some(DataHeader {
        receiver_index: u32::from_le_bytes(message[4..8].try_into().ok()?),
        counter: u64::from_le_bytes(message[8..16].try_into().ok()?),
    })
}

/// Why a message was not sealed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealError {
    /// The counter is at the limit: the key must not be used again.
    CounterExhausted,
    /// The buffer has no room for the padding and the tag after the inner packet.
    NoRoom,
}

/// Builds a transport data message in `buf`. The inner packet is already in
/// `buf[HEADER_LEN..HEADER_LEN + inner_len]` (empty for a keepalive). Pads it with
/// zeros to a multiple of 16, encrypts it, writes the header and the tag, and
/// returns the length of the whole message.
pub fn seal(
    key: &[u8; 32],
    receiver_index: u32,
    counter: u64,
    buf: &mut [u8],
    inner_len: usize,
) -> Result<usize, SealError> {
    if counter >= REJECT_AFTER_MESSAGES {
        return Err(SealError::CounterExhausted);
    }
    let encrypted_end = HEADER_LEN + padded_len(inner_len);
    let total = encrypted_end + TAG_LEN;
    if inner_len > buf.len() || total > buf.len() {
        return Err(SealError::NoRoom);
    }
    buf[HEADER_LEN + inner_len..encrypted_end].fill(0);
    buf[0] = MESSAGE_TYPE_DATA;
    buf[1..4].fill(0);
    buf[4..8].copy_from_slice(&receiver_index.to_le_bytes());
    buf[8..16].copy_from_slice(&counter.to_le_bytes());
    let nonce = chacha20poly1305::wireguard_nonce(counter);
    let tag = chacha20poly1305::seal(key, &nonce, &[], &mut buf[HEADER_LEN..encrypted_end]);
    buf[encrypted_end..total].copy_from_slice(&tag);
    Ok(total)
}

/// Authenticates and decrypts a transport data message in place. On success
/// returns the range of `message` that holds the decrypted, still padded, packet:
/// the receiver finds the real length from the inner IP header. An empty range is
/// a keepalive. Returns `None` if the message is malformed, its counter is at the
/// limit, or the tag is wrong (then `message` is unchanged).
///
/// The encrypted part need not be a multiple of 16: senders cap the padding at
/// their MTU (Linux and wireguard-go pad to `min(mtu, ALIGN(len, 16))`), so a
/// packet of an MTU like 1420 arrives unpadded.
///
/// This does not look at the replay window: update it with [`ReplayWindow::accept`]
/// only after this succeeds, so that forged messages cannot move it.
#[must_use]
pub fn open(key: &[u8; 32], message: &mut [u8]) -> Option<core::ops::Range<usize>> {
    let header = parse_header(message)?;
    let body = message.len() - TAG_LEN;
    if header.counter >= REJECT_AFTER_MESSAGES {
        return None;
    }
    let (data, tag) = message.split_at_mut(body);
    let tag: &[u8; TAG_LEN] = (&*tag).try_into().ok()?;
    let nonce = chacha20poly1305::wireguard_nonce(header.counter);
    chacha20poly1305::open(key, &nonce, &[], &mut data[HEADER_LEN..], tag)
        .then_some(HEADER_LEN..body)
}

/// The receive side's record of which counters were seen (RFC 6479).
#[derive(Clone, Debug)]
pub struct ReplayWindow {
    highest: u64,
    bits: [u64; WINDOW_WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// A window that has seen nothing.
    pub const fn new() -> Self {
        Self {
            highest: 0,
            bits: [0; WINDOW_WORDS],
        }
    }

    /// Records `counter` of an authenticated message. Returns `false`, and records
    /// nothing, if it is a replay, too old, or at the limit.
    pub fn accept(&mut self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        let word = counter >> 6;
        if counter > self.highest {
            let current = self.highest >> 6;
            let advance = (word - current).min(WINDOW_WORDS as u64);
            for step in 1..=advance {
                self.bits[((current + step) as usize) % WINDOW_WORDS] = 0;
            }
            self.highest = counter;
        } else if counter + REPLAY_WINDOW < self.highest {
            return false;
        }
        let slot = &mut self.bits[(word as usize) % WINDOW_WORDS];
        let bit = 1u64 << (counter & 63);
        if *slot & bit != 0 {
            return false;
        }
        *slot |= bit;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn message(inner: &[u8], counter: u64) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_LEN + padded_len(inner.len()) + TAG_LEN];
        buf[HEADER_LEN..HEADER_LEN + inner.len()].copy_from_slice(inner);
        let len = seal(&KEY, 0x0a0b_0c0d, counter, &mut buf, inner.len()).unwrap();
        assert_eq!(len, buf.len());
        buf
    }

    #[test]
    fn a_sealed_message_has_the_whitepaper_layout() {
        let msg = message(&[1; 20], 5);
        assert_eq!(msg[..4], [4, 0, 0, 0]);
        assert_eq!(msg[4..8], [0x0d, 0x0c, 0x0b, 0x0a]);
        assert_eq!(msg[8..16], 5u64.to_le_bytes());
        assert_eq!(msg.len(), 16 + 32 + 16);
        assert_eq!(
            parse_header(&msg),
            Some(DataHeader {
                receiver_index: 0x0a0b_0c0d,
                counter: 5
            })
        );
    }

    #[test]
    fn open_returns_the_padded_packet() {
        let inner: Vec<u8> = (1..=20).collect();
        let mut msg = message(&inner, 9);
        let range = open(&KEY, &mut msg).unwrap();
        assert_eq!(range, 16..48);
        assert_eq!(msg[16..36], inner[..]);
        assert_eq!(msg[36..48], [0; 12]);
    }

    #[test]
    fn a_message_padded_short_of_16_is_opened() {
        // As Linux sends a 1420-byte packet on a 1420 MTU: 1420 is not a multiple
        // of 16 and the padding stops at the MTU.
        let inner: Vec<u8> = (0..1420).map(|i| i as u8).collect();
        let mut msg = vec![0u8; HEADER_LEN + inner.len() + TAG_LEN];
        msg[0] = MESSAGE_TYPE_DATA;
        msg[4..8].copy_from_slice(&7u32.to_le_bytes());
        msg[8..16].copy_from_slice(&3u64.to_le_bytes());
        msg[HEADER_LEN..HEADER_LEN + inner.len()].copy_from_slice(&inner);
        let nonce = chacha20poly1305::wireguard_nonce(3);
        let tag = chacha20poly1305::seal(
            &KEY,
            &nonce,
            &[],
            &mut msg[HEADER_LEN..HEADER_LEN + inner.len()],
        );
        let end = msg.len();
        msg[end - TAG_LEN..].copy_from_slice(&tag);
        let range = open(&KEY, &mut msg).unwrap();
        assert_eq!(msg[range], inner[..]);
    }

    #[test]
    fn a_keepalive_is_the_header_and_a_tag() {
        let mut msg = message(&[], 0);
        assert_eq!(msg.len(), MIN_MESSAGE_LEN);
        assert_eq!(open(&KEY, &mut msg), Some(16..16));
    }

    #[test]
    fn a_wrong_key_or_a_changed_byte_is_refused_and_leaves_the_message() {
        let msg = message(&[3; 40], 1);
        let mut other_key = msg.clone();
        assert_eq!(open(&[8; 32], &mut other_key), None);
        assert_eq!(other_key, msg);
        for at in [9, 20, msg.len() - 1] {
            let mut changed = msg.clone();
            changed[at] ^= 1;
            let before = changed.clone();
            assert_eq!(open(&KEY, &mut changed), None, "byte {at}");
            assert_eq!(changed, before);
        }
    }

    #[test]
    fn malformed_messages_are_refused() {
        let msg = message(&[3; 16], 1);
        for bad in [
            msg[..MIN_MESSAGE_LEN - 1].to_vec(),
            msg[..msg.len() - 1].to_vec(),
            {
                let mut m = msg.clone();
                m[0] = 1;
                m
            },
            {
                let mut m = msg.clone();
                m[2] = 1;
                m
            },
        ] {
            let mut bad = bad;
            assert!(parse_header(&bad).is_none() || open(&KEY, &mut bad).is_none());
        }
    }

    #[test]
    fn the_counter_limit_stops_sealing_and_opening() {
        let mut buf = [0u8; 64];
        assert_eq!(
            seal(&KEY, 1, REJECT_AFTER_MESSAGES, &mut buf, 0),
            Err(SealError::CounterExhausted)
        );
        assert!(seal(&KEY, 1, REJECT_AFTER_MESSAGES - 1, &mut buf, 0).is_ok());
        let mut last = buf[..MIN_MESSAGE_LEN].to_vec();
        assert!(open(&KEY, &mut last).is_some());
        assert!(!ReplayWindow::new().accept(REJECT_AFTER_MESSAGES));
    }

    #[test]
    fn sealing_needs_room_for_padding_and_tag() {
        let mut buf = [0u8; HEADER_LEN + 32 + TAG_LEN - 1];
        assert_eq!(seal(&KEY, 1, 0, &mut buf, 20), Err(SealError::NoRoom));
    }

    #[test]
    fn the_replay_window_refuses_repeats_and_the_too_old() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(!w.accept(0));
        assert!(w.accept(2));
        assert!(w.accept(1));
        assert!(!w.accept(1));
        assert!(w.accept(10_000));
        assert!(!w.accept(10_000));
        // 10_000 - 8128 = 1872 is the oldest still inside the window.
        assert!(w.accept(1872));
        assert!(!w.accept(1871));
        assert!(!w.accept(2));
        // A jump of more than the whole ring clears it.
        assert!(w.accept(10_000 + 100_000));
        assert!(w.accept(10_000 + 100_000 - 1));
        assert!(!w.accept(10_000 + 100_000 - 1));
    }

    #[test]
    fn the_replay_window_forgets_slots_it_reuses() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(5));
        // 8192 later the same ring slot is used for a new counter.
        assert!(w.accept(5 + 8192));
        assert!(w.accept(5 + 8192 - 1));
        assert!(!w.accept(5));
    }
}
