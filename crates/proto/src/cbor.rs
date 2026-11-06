//! The part of CBOR (RFC 8949) that the FE and CE messages use.
//!
//! Supported: unsigned and negative integers, byte strings, text strings, arrays,
//! maps, `false`, `true` and `null`. Every length is definite.
//!
//! Not supported, and rejected when decoding: indefinite lengths, tags, floats and
//! the other simple values. The messages never need them, and refusing them keeps
//! one way to write each value.
//!
//! The encoder always writes the shortest head (RFC 8949 section 4.2.1). The decoder
//! accepts longer heads too, because they carry the same value.
//!
//! A message body is a CBOR sequence (RFC 8742): items written one after another.
//! [`Decoder`] reads them in order until [`Decoder::is_empty`].

use std::fmt;

const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;

const SIMPLE_FALSE: u64 = 20;
const SIMPLE_TRUE: u64 = 21;
const SIMPLE_NULL: u64 = 22;

/// The kind of the next item, as far as this subset knows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Unsigned,
    Negative,
    Bytes,
    Text,
    Array,
    Map,
    Bool,
    Null,
}

/// Why decoding failed. Positions are byte offsets into the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended inside an item.
    UnexpectedEnd,
    /// The item at `at` is a `found`, but the caller asked for an `expected`.
    WrongKind {
        at: usize,
        expected: Kind,
        found: Kind,
    },
    /// The item at `at` uses a part of CBOR this subset does not accept.
    Unsupported { at: usize, what: Unsupported },
    /// The text string at `at` is not valid UTF-8.
    InvalidUtf8 { at: usize },
    /// The integer at `at` does not fit the requested Rust type.
    OutOfRange { at: usize },
}

/// The parts of CBOR the decoder refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    IndefiniteLength,
    Tag,
    Float,
    SimpleValue,
    /// Additional information 28, 29 or 30, which RFC 8949 reserves.
    ReservedHead,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd => write!(f, "input ended inside a CBOR item"),
            Self::WrongKind {
                at,
                expected,
                found,
            } => write!(f, "expected {expected:?} at byte {at}, found {found:?}"),
            Self::Unsupported { at, what } => {
                write!(f, "unsupported CBOR ({what:?}) at byte {at}")
            }
            Self::InvalidUtf8 { at } => write!(f, "invalid UTF-8 in text string at byte {at}"),
            Self::OutOfRange { at } => write!(f, "integer at byte {at} is out of range"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Writes CBOR items to the end of a buffer.
#[derive(Debug)]
pub struct Encoder<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Encoder<'a> {
    pub fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }

    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.head(MAJOR_UNSIGNED, value);
        self
    }

    pub fn i64(&mut self, value: i64) -> &mut Self {
        if value >= 0 {
            self.head(MAJOR_UNSIGNED, value.unsigned_abs());
        } else {
            // CBOR stores a negative number n as -1 - n.
            self.head(MAJOR_NEGATIVE, (-1 - value).unsigned_abs());
        }
        self
    }

    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.head(MAJOR_BYTES, value.len() as u64);
        self.out.extend_from_slice(value);
        self
    }

    pub fn text(&mut self, value: &str) -> &mut Self {
        self.head(MAJOR_TEXT, value.len() as u64);
        self.out.extend_from_slice(value.as_bytes());
        self
    }

    /// Starts an array. The caller then writes exactly `len` items.
    pub fn array(&mut self, len: u64) -> &mut Self {
        self.head(MAJOR_ARRAY, len);
        self
    }

    /// Starts a map. The caller then writes exactly `len` key and value pairs.
    pub fn map(&mut self, len: u64) -> &mut Self {
        self.head(MAJOR_MAP, len);
        self
    }

    pub fn bool(&mut self, value: bool) -> &mut Self {
        self.head(MAJOR_SIMPLE, if value { SIMPLE_TRUE } else { SIMPLE_FALSE });
        self
    }

    pub fn null(&mut self) -> &mut Self {
        self.head(MAJOR_SIMPLE, SIMPLE_NULL);
        self
    }

    fn head(&mut self, major: u8, value: u64) {
        let major = major << 5;
        if value < 24 {
            self.out.push(major | value as u8);
        } else if let Ok(value) = u8::try_from(value) {
            self.out.extend_from_slice(&[major | 24, value]);
        } else if let Ok(value) = u16::try_from(value) {
            self.out.push(major | 25);
            self.out.extend_from_slice(&value.to_be_bytes());
        } else if let Ok(value) = u32::try_from(value) {
            self.out.push(major | 26);
            self.out.extend_from_slice(&value.to_be_bytes());
        } else {
            self.out.push(major | 27);
            self.out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

/// Reads CBOR items from a buffer without copying strings.
///
/// When a read fails with [`DecodeError::WrongKind`], nothing is consumed and the caller
/// may try another kind. After any other error the position is unspecified and the
/// message should be dropped.
#[derive(Clone, Debug)]
pub struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

/// One item head: its kind, its argument and where it starts.
#[derive(Clone, Copy)]
struct Head {
    at: usize,
    kind: Kind,
    value: u64,
}

impl<'a> Decoder<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    /// The byte offset of the next item.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// True when every item has been read.
    pub fn is_empty(&self) -> bool {
        self.pos == self.input.len()
    }

    /// The kind of the next item, without reading it.
    pub fn peek_kind(&self) -> Result<Kind, DecodeError> {
        self.clone().read_head().map(|head| head.kind)
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(self.expect(Kind::Unsigned)?.value)
    }

    /// Reads an unsigned or negative integer. On a wrong kind, the error names
    /// [`Kind::Unsigned`] as the expected kind, though [`Kind::Negative`] is accepted too.
    pub fn i64(&mut self) -> Result<i64, DecodeError> {
        let start = self.pos;
        let head = self.read_head()?;
        let out_of_range = DecodeError::OutOfRange { at: head.at };
        let value = match head.kind {
            Kind::Unsigned => i64::try_from(head.value).map_err(|_| out_of_range)?,
            // -1 - n fits in i64 exactly when n fits in i64.
            Kind::Negative => -1 - i64::try_from(head.value).map_err(|_| out_of_range)?,
            found => {
                self.pos = start;
                return Err(DecodeError::WrongKind {
                    at: head.at,
                    expected: Kind::Unsigned,
                    found,
                });
            }
        };
        Ok(value)
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let head = self.expect(Kind::Bytes)?;
        self.take(head.value)
    }

    pub fn text(&mut self) -> Result<&'a str, DecodeError> {
        let head = self.expect(Kind::Text)?;
        let raw = self.take(head.value)?;
        std::str::from_utf8(raw).map_err(|_| DecodeError::InvalidUtf8 { at: head.at })
    }

    /// Reads an array head and returns how many items follow.
    ///
    /// The count is never larger than the bytes left, because every item takes at least
    /// one byte. A caller may size a buffer from it without trusting the sender.
    pub fn array(&mut self) -> Result<u64, DecodeError> {
        let head = self.expect(Kind::Array)?;
        self.check_count(head.value, 1)
    }

    /// Reads a map head and returns how many key and value pairs follow.
    ///
    /// The count is never larger than half the bytes left (a key and a value take at
    /// least two bytes).
    pub fn map(&mut self) -> Result<u64, DecodeError> {
        let head = self.expect(Kind::Map)?;
        self.check_count(head.value, 2)
    }

    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        Ok(self.expect(Kind::Bool)?.value == SIMPLE_TRUE)
    }

    pub fn null(&mut self) -> Result<(), DecodeError> {
        self.expect(Kind::Null).map(|_| ())
    }

    /// Skips one whole item, including everything inside it.
    ///
    /// This counts the items still to skip instead of recursing, so deep nesting cannot
    /// exhaust the stack. Each item takes at least one byte, so the loop ends within the
    /// input length.
    pub fn skip(&mut self) -> Result<(), DecodeError> {
        let mut pending: u64 = 1;
        while pending > 0 {
            pending -= 1;
            let head = self.read_head()?;
            match head.kind {
                Kind::Bytes | Kind::Text => {
                    self.take(head.value)?;
                }
                Kind::Array => pending = pending.saturating_add(head.value),
                Kind::Map => pending = pending.saturating_add(head.value.saturating_mul(2)),
                Kind::Unsigned | Kind::Negative | Kind::Bool | Kind::Null => {}
            }
        }
        Ok(())
    }

    fn expect(&mut self, expected: Kind) -> Result<Head, DecodeError> {
        let start = self.pos;
        let head = self.read_head()?;
        if head.kind != expected {
            self.pos = start;
            return Err(DecodeError::WrongKind {
                at: head.at,
                expected,
                found: head.kind,
            });
        }
        Ok(head)
    }

    fn check_count(&self, count: u64, bytes_per_entry: u64) -> Result<u64, DecodeError> {
        let remaining = (self.input.len() - self.pos) as u64;
        match count.checked_mul(bytes_per_entry) {
            Some(needed) if needed <= remaining => Ok(count),
            _ => Err(DecodeError::UnexpectedEnd),
        }
    }

    fn take(&mut self, len: u64) -> Result<&'a [u8], DecodeError> {
        let remaining = self.input.len() - self.pos;
        let len = usize::try_from(len)
            .ok()
            .filter(|&len| len <= remaining)
            .ok_or(DecodeError::UnexpectedEnd)?;
        let out = &self.input[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    fn read_head(&mut self) -> Result<Head, DecodeError> {
        let at = self.pos;
        let first = *self.input.get(at).ok_or(DecodeError::UnexpectedEnd)?;
        self.pos += 1;
        let major = first >> 5;
        let info = first & 0x1f;
        let unsupported = |what| DecodeError::Unsupported { at, what };

        // Refuse tags and floats before reading their argument, so a truncated one is
        // reported as what it is rather than as a short input.
        if major == MAJOR_TAG && info != 31 {
            return Err(unsupported(Unsupported::Tag));
        }
        if major == MAJOR_SIMPLE && matches!(info, 25..=27) {
            return Err(unsupported(Unsupported::Float));
        }

        let value = match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(self.fixed()?)),
            26 => u64::from(u32::from_be_bytes(self.fixed()?)),
            27 => u64::from_be_bytes(self.fixed()?),
            28..=30 => return Err(unsupported(Unsupported::ReservedHead)),
            // 31 starts an indefinite-length item, or is the "break" (0xff) that ends one.
            _ => return Err(unsupported(Unsupported::IndefiniteLength)),
        };

        let kind = match major {
            MAJOR_UNSIGNED => Kind::Unsigned,
            MAJOR_NEGATIVE => Kind::Negative,
            MAJOR_BYTES => Kind::Bytes,
            MAJOR_TEXT => Kind::Text,
            MAJOR_ARRAY => Kind::Array,
            MAJOR_MAP => Kind::Map,
            MAJOR_TAG => return Err(unsupported(Unsupported::Tag)),
            _ => match (info, value) {
                (_, SIMPLE_FALSE | SIMPLE_TRUE) if info < 24 => Kind::Bool,
                (_, SIMPLE_NULL) if info < 24 => Kind::Null,
                _ => return Err(unsupported(Unsupported::SimpleValue)),
            },
        };
        Ok(Head { at, kind, value })
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let raw = self.take(N as u64)?;
        let mut out = [0; N];
        out.copy_from_slice(raw);
        Ok(out)
    }
}
