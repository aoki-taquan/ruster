//! CoAP messages framed for reliable byte streams (RFC 8323 section 3.2).
//!
//! The FE and CE talk over Unix stream sockets, so they use the TCP framing of CoAP:
//! no message IDs, no acknowledgements, and a length at the front of every message.
//!
//! ```text
//! Len (4 bits) | TKL (4 bits) | Extended Length (0, 1, 2 or 4 bytes)
//! Code (1 byte) | Token (TKL bytes) | Options | 0xFF Payload
//! ```
//!
//! `Len` counts the options, the payload marker and the payload. The option encoding
//! is the one from RFC 7252 section 3.1.
//!
//! [`decode`] reads one message from the front of a buffer without copying. It says
//! how many more bytes it needs when the buffer holds only part of a message, so a
//! reader can keep appending from the socket and call it again.

use std::fmt;

/// A CoAP code: a class (0 to 7) and a detail (0 to 31), written `class.detail`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Code(pub u8);

impl Code {
    pub const GET: Self = Self::new(0, 1);
    pub const POST: Self = Self::new(0, 2);
    pub const PUT: Self = Self::new(0, 3);
    pub const DELETE: Self = Self::new(0, 4);
    pub const FETCH: Self = Self::new(0, 5);
    pub const IPATCH: Self = Self::new(0, 7);

    pub const CREATED: Self = Self::new(2, 1);
    pub const DELETED: Self = Self::new(2, 2);
    pub const CHANGED: Self = Self::new(2, 4);
    pub const CONTENT: Self = Self::new(2, 5);
    pub const BAD_REQUEST: Self = Self::new(4, 0);
    pub const FORBIDDEN: Self = Self::new(4, 3);
    pub const NOT_FOUND: Self = Self::new(4, 4);
    pub const METHOD_NOT_ALLOWED: Self = Self::new(4, 5);
    pub const REQUEST_ENTITY_TOO_LARGE: Self = Self::new(4, 13);
    pub const INTERNAL_SERVER_ERROR: Self = Self::new(5, 0);

    /// Signaling codes (RFC 8323 section 5).
    pub const CSM: Self = Self::new(7, 1);
    pub const PING: Self = Self::new(7, 2);
    pub const PONG: Self = Self::new(7, 3);
    pub const RELEASE: Self = Self::new(7, 4);
    pub const ABORT: Self = Self::new(7, 5);

    pub const fn new(class: u8, detail: u8) -> Self {
        Self((class << 5) | (detail & 0x1f))
    }

    pub const fn class(self) -> u8 {
        self.0 >> 5
    }

    pub const fn detail(self) -> u8 {
        self.0 & 0x1f
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:02}", self.class(), self.detail())
    }
}

/// Option numbers this project uses.
pub mod option {
    pub const OBSERVE: u16 = 6;
    pub const URI_PATH: u16 = 11;
    pub const CONTENT_FORMAT: u16 = 12;
    pub const URI_QUERY: u16 = 15;
    pub const ACCEPT: u16 = 17;
    /// In a CSM message (RFC 8323 section 5.3.1).
    pub const MAX_MESSAGE_SIZE: u16 = 2;
}

/// The longest token CoAP allows.
pub const MAX_TOKEN_LEN: usize = 8;

const PAYLOAD_MARKER: u8 = 0xff;

/// One decoded message. Every field borrows from the input buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message<'a> {
    pub code: Code,
    pub token: &'a [u8],
    /// The encoded options, already checked by [`decode`]. Read them with [`Message::options`].
    options: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> Message<'a> {
    /// The options in the order they were written (ascending option number).
    pub fn options(&self) -> Options<'a> {
        Options {
            rest: self.options,
            number: 0,
        }
    }

    /// The first value of an option, if present.
    pub fn option(&self, number: u16) -> Option<&'a [u8]> {
        self.options()
            .find(|&(n, _)| n == number)
            .map(|(_, value)| value)
    }
}

/// Iterates the options of a [`Message`] as `(number, value)`.
#[derive(Clone, Debug)]
pub struct Options<'a> {
    rest: &'a [u8],
    number: u16,
}

impl<'a> Iterator for Options<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        // `decode` already checked every option, so this cannot fail.
        let (delta, len, header) = option_header(self.rest).ok()?;
        self.number += delta;
        let value = &self.rest[header..header + len];
        self.rest = &self.rest[header + len..];
        Some((self.number, value))
    }
}

/// The result of [`decode`] on a buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoded<'a> {
    /// A whole message, and how many bytes of the buffer it used.
    Message(Message<'a>, usize),
    /// The buffer holds only the start of a message. At least this many more bytes
    /// are needed before trying again.
    NeedMore(usize),
}

/// Why a message could not be decoded. The stream cannot be read further after any of
/// these, because the message boundaries are lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The message is larger than the limit given to [`decode`].
    TooLarge { size: u64, limit: usize },
    /// TKL is 9 to 15, which RFC 8323 reserves.
    BadTokenLength,
    /// An option uses the reserved value 15 for its delta or length.
    BadOption,
    /// An option runs past the end of the message.
    TruncatedOption,
    /// An option number is larger than 65535.
    OptionNumberOverflow,
    /// A payload marker with nothing after it.
    EmptyPayload,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { size, limit } => {
                write!(
                    f,
                    "CoAP message of {size} bytes exceeds the limit of {limit}"
                )
            }
            Self::BadTokenLength => write!(f, "CoAP token length is reserved"),
            Self::BadOption => write!(f, "CoAP option uses a reserved value"),
            Self::TruncatedOption => write!(f, "CoAP option runs past the message"),
            Self::OptionNumberOverflow => write!(f, "CoAP option number is too large"),
            Self::EmptyPayload => write!(f, "CoAP payload marker without a payload"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Reads one message from the front of `buf`.
///
/// `limit` is the largest whole message (header, token, options and payload) the reader
/// accepts. A message that announces a larger size is refused from its header alone,
/// before the reader buffers it.
pub fn decode(buf: &[u8], limit: usize) -> Result<Decoded<'_>, FrameError> {
    let Some(&first) = buf.first() else {
        return Ok(Decoded::NeedMore(1));
    };
    let len_nibble = first >> 4;
    let token_len = usize::from(first & 0x0f);
    if token_len > MAX_TOKEN_LEN {
        return Err(FrameError::BadTokenLength);
    }

    let ext_len = match len_nibble {
        13 => 1,
        14 => 2,
        15 => 4,
        _ => 0,
    };
    let header_len = 1 + ext_len + 1;
    if buf.len() < 1 + ext_len {
        return Ok(Decoded::NeedMore(1 + ext_len - buf.len()));
    }
    let ext = &buf[1..1 + ext_len];
    let body_len: u64 = match len_nibble {
        13 => u64::from(ext[0]) + 13,
        14 => u64::from(u16::from_be_bytes([ext[0], ext[1]])) + 269,
        15 => u64::from(u32::from_be_bytes([ext[0], ext[1], ext[2], ext[3]])) + 65805,
        n => u64::from(n),
    };

    let size = (header_len + token_len) as u64 + body_len;
    if size > limit as u64 {
        return Err(FrameError::TooLarge { size, limit });
    }
    // `size` fits in usize now, because it is at most `limit`.
    let size = size as usize;
    if buf.len() < size {
        return Ok(Decoded::NeedMore(size - buf.len()));
    }

    let code = Code(buf[1 + ext_len]);
    let token = &buf[header_len..header_len + token_len];
    let body = &buf[header_len + token_len..size];
    let (options, payload) = split_options(body)?;
    Ok(Decoded::Message(
        Message {
            code,
            token,
            options,
            payload,
        },
        size,
    ))
}

/// Checks every option and returns the option bytes and the payload.
fn split_options(body: &[u8]) -> Result<(&[u8], &[u8]), FrameError> {
    let mut pos = 0;
    let mut number: u32 = 0;
    while pos < body.len() {
        if body[pos] == PAYLOAD_MARKER {
            let payload = &body[pos + 1..];
            if payload.is_empty() {
                return Err(FrameError::EmptyPayload);
            }
            return Ok((&body[..pos], payload));
        }
        let (delta, len, header) = option_header(&body[pos..])?;
        number += u32::from(delta);
        if number > u32::from(u16::MAX) {
            return Err(FrameError::OptionNumberOverflow);
        }
        if body.len() - pos - header < len {
            return Err(FrameError::TruncatedOption);
        }
        pos += header + len;
    }
    Ok((body, &[]))
}

/// Reads an option header: the delta, the value length and the header size.
fn option_header(buf: &[u8]) -> Result<(u16, usize, usize), FrameError> {
    let first = *buf.first().ok_or(FrameError::TruncatedOption)?;
    let mut pos = 1;
    let mut extended = |nibble: u8| -> Result<u32, FrameError> {
        match nibble {
            0..=12 => Ok(u32::from(nibble)),
            13 => {
                let b = *buf.get(pos).ok_or(FrameError::TruncatedOption)?;
                pos += 1;
                Ok(u32::from(b) + 13)
            }
            14 => {
                let b = buf.get(pos..pos + 2).ok_or(FrameError::TruncatedOption)?;
                pos += 2;
                Ok(u32::from(u16::from_be_bytes([b[0], b[1]])) + 269)
            }
            _ => Err(FrameError::BadOption),
        }
    };
    let delta = extended(first >> 4)?;
    let len = extended(first & 0x0f)?;
    let delta = u16::try_from(delta).map_err(|_| FrameError::OptionNumberOverflow)?;
    Ok((delta, len as usize, pos))
}

/// Why a message could not be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The token is longer than [`MAX_TOKEN_LEN`].
    TokenTooLong,
    /// Options must be given in ascending option number.
    OptionsOutOfOrder,
    /// An option value is longer than the option encoding allows (65804 bytes).
    OptionTooLong,
    /// The message does not fit the 32-bit extended length.
    TooLarge,
}

/// The longest option value the option encoding can express.
const MAX_OPTION_LEN: usize = 65_804;

/// Appends one message to `out`.
///
/// `options` must be sorted by option number; repeating a number is allowed.
pub fn encode(
    out: &mut Vec<u8>,
    code: Code,
    token: &[u8],
    options: &[(u16, &[u8])],
    payload: &[u8],
) -> Result<(), EncodeError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(EncodeError::TokenTooLong);
    }
    if options.windows(2).any(|pair| pair[0].0 > pair[1].0) {
        return Err(EncodeError::OptionsOutOfOrder);
    }
    if options
        .iter()
        .any(|(_, value)| value.len() > MAX_OPTION_LEN)
    {
        return Err(EncodeError::OptionTooLong);
    }

    let mut body_len: u64 = 0;
    let mut previous = 0;
    for &(number, value) in options {
        body_len += (1 + ext_size(u32::from(number - previous)) + ext_size(value.len() as u32))
            as u64
            + value.len() as u64;
        previous = number;
    }
    if !payload.is_empty() {
        body_len += 1 + payload.len() as u64;
    }

    let (len_nibble, ext): (u8, Vec<u8>) = match body_len {
        0..=12 => (body_len as u8, Vec::new()),
        13..=268 => (13, vec![(body_len - 13) as u8]),
        269..=65_804 => (14, ((body_len - 269) as u16).to_be_bytes().to_vec()),
        _ => {
            let ext = u32::try_from(body_len - 65_805).map_err(|_| EncodeError::TooLarge)?;
            (15, ext.to_be_bytes().to_vec())
        }
    };

    out.push((len_nibble << 4) | token.len() as u8);
    out.extend_from_slice(&ext);
    out.push(code.0);
    out.extend_from_slice(token);
    let mut previous = 0;
    for &(number, value) in options {
        let delta = u32::from(number - previous);
        let len = value.len() as u32;
        out.push((nibble(delta) << 4) | nibble(len));
        push_ext(out, delta);
        push_ext(out, len);
        out.extend_from_slice(value);
        previous = number;
    }
    if !payload.is_empty() {
        out.push(PAYLOAD_MARKER);
        out.extend_from_slice(payload);
    }
    Ok(())
}

fn nibble(value: u32) -> u8 {
    match value {
        0..=12 => value as u8,
        13..=268 => 13,
        _ => 14,
    }
}

fn ext_size(value: u32) -> usize {
    match value {
        0..=12 => 0,
        13..=268 => 1,
        _ => 2,
    }
}

fn push_ext(out: &mut Vec<u8>, value: u32) {
    match value {
        0..=12 => {}
        13..=268 => out.push((value - 13) as u8),
        _ => out.extend_from_slice(&((value - 269) as u16).to_be_bytes()),
    }
}

/// Encodes an unsigned option value the CoAP way: big-endian with no leading zero
/// bytes, so 0 is the empty string.
pub fn uint_option(value: u32, buf: &mut [u8; 4]) -> &[u8] {
    *buf = value.to_be_bytes();
    let skip = (value.leading_zeros() / 8) as usize;
    &buf[skip..]
}

/// Reads an unsigned option value. `None` when it is longer than 4 bytes.
pub fn read_uint_option(value: &[u8]) -> Option<u32> {
    if value.len() > 4 {
        return None;
    }
    Some(value.iter().fold(0, |acc, &b| (acc << 8) | u32::from(b)))
}
