//! One CoAP connection over a non-blocking Unix stream socket.
//!
//! [`Connection`] buffers both directions so that no call waits:
//! [`Connection::pump`] moves bytes between the socket and the buffers, and
//! [`Connection::next_message`] hands out whole messages. Signaling messages
//! (RFC 8323 section 5) are handled here: each side sends a CSM with its
//! Max-Message-Size first, a Ping is answered with a Pong, and an Abort closes the
//! connection.
//!
//! Messages are copied into [`Incoming`] values. This is the control path, where
//! a copy is cheaper than tying the caller to the buffer.
//!
//! # Standards
//!
//! - RFC 8323 section 5.3: each side sends a CSM first, with Max-Message-Size.
//! - RFC 8323 section 5.4: a Ping is answered with a Pong.
//! - RFC 8323 section 5.6: an Abort closes the connection.
//!
//! Deviations: a Release (section 5.5) is ignored instead of draining the connection,
//! and the Block-Wise-Transfer CSM option is not offered.

use std::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;

use crate::coap::{self, option, Code, Decoded, EncodeError, FrameError};

/// The largest message either side accepts, announced in the CSM.
pub const DEFAULT_LIMIT: usize = 16 * 1024 * 1024;

/// At most this many bytes are read from the socket in one [`Connection::pump`].
const READ_CHUNK: usize = 64 * 1024;

/// At most this many signaling messages are handled in one [`Connection::next_message`].
const SIGNALS_PER_CALL: usize = 64;

/// A request or response this side received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incoming {
    pub code: Code,
    pub token: Vec<u8>,
    /// The Uri-Path segments, in order.
    pub path: Vec<String>,
    pub observe: Option<u32>,
    pub payload: Vec<u8>,
}

/// A request or response to send.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outgoing<'a> {
    pub code: Option<Code>,
    pub token: &'a [u8],
    pub path: &'a [&'a str],
    pub observe: Option<u32>,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub enum ConnError {
    Io(io::Error),
    /// The peer sent something that is not a valid message. The stream cannot be
    /// read further.
    Frame(FrameError),
}

impl fmt::Display for ConnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Frame(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ConnError {}

impl From<io::Error> for ConnError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct Connection {
    stream: UnixStream,
    limit: usize,
    inbuf: Vec<u8>,
    /// Bytes at the front of `inbuf` already handed out; removed once per pump.
    consumed: usize,
    outbuf: Vec<u8>,
    closed: bool,
    peer_limit: Option<usize>,
    more: bool,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("buffered_in", &self.buffered_in())
            .field("buffered_out", &self.outbuf.len())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// Takes over `stream`, makes it non-blocking and queues this side's CSM.
    pub fn new(stream: UnixStream, limit: usize) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        let mut conn = Self {
            stream,
            limit,
            inbuf: Vec::new(),
            consumed: 0,
            outbuf: Vec::new(),
            closed: false,
            peer_limit: None,
            more: false,
        };
        let mut size = [0; 4];
        let size = coap::uint_option(u32::try_from(limit).unwrap_or(u32::MAX), &mut size);
        coap::encode(
            &mut conn.outbuf,
            Code::CSM,
            &[],
            &[(option::MAX_MESSAGE_SIZE, size)],
            &[],
        )
        .expect("a CSM always encodes");
        Ok(conn)
    }

    /// True once the peer closed the stream or sent an Abort, or after an error.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// The Max-Message-Size from the peer's CSM, once it has arrived.
    pub fn peer_limit(&self) -> Option<usize> {
        self.peer_limit
    }

    /// Queues one message. Nothing is sent until [`Connection::pump`].
    pub fn send(&mut self, message: &Outgoing<'_>) -> Result<(), EncodeError> {
        let mut observe = [0; 4];
        let mut options: Vec<(u16, &[u8])> = Vec::new();
        if let Some(value) = message.observe {
            options.push((option::OBSERVE, coap::uint_option(value, &mut observe)));
        }
        for segment in message.path {
            options.push((option::URI_PATH, segment.as_bytes()));
        }
        coap::encode(
            &mut self.outbuf,
            message.code.unwrap_or(Code::CONTENT),
            message.token,
            &options,
            message.payload,
        )
    }

    /// Writes what it can and reads what is there, without waiting.
    ///
    /// Returns whether any byte moved. After an error the connection is closed.
    pub fn pump(&mut self) -> Result<bool, ConnError> {
        if self.closed {
            return Ok(false);
        }
        let result = self.pump_inner();
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    fn pump_inner(&mut self) -> Result<bool, ConnError> {
        let mut moved = false;
        // Remove what was handed out, once per pump instead of once per message.
        self.inbuf.drain(..self.consumed);
        self.consumed = 0;
        while !self.outbuf.is_empty() {
            match self.stream.write(&self.outbuf) {
                Ok(0) => {
                    self.closed = true;
                    return Ok(moved);
                }
                Ok(n) => {
                    self.outbuf.drain(..n);
                    moved = true;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == ErrorKind::BrokenPipe => {
                    self.closed = true;
                    return Ok(moved);
                }
                Err(error) => return Err(error.into()),
            }
        }
        // Backpressure: stop reading while a whole message's worth is unread, so a
        // peer that sends faster than this side handles cannot grow the buffer.
        if self.inbuf.len() >= self.limit {
            return Ok(moved);
        }
        let start = self.inbuf.len();
        self.inbuf.resize(start + READ_CHUNK, 0);
        let read = loop {
            match self.stream.read(&mut self.inbuf[start..]) {
                Ok(n) => break n,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break usize::MAX,
                Err(error) if error.kind() == ErrorKind::ConnectionReset => break 0,
                Err(error) => {
                    self.inbuf.truncate(start);
                    return Err(error.into());
                }
            }
        };
        match read {
            usize::MAX => self.inbuf.truncate(start),
            0 => {
                self.inbuf.truncate(start);
                self.closed = true;
            }
            n => {
                self.inbuf.truncate(start + n);
                moved = true;
            }
        }
        Ok(moved)
    }

    /// Returns the next whole request or response, handling signaling messages on
    /// the way. `Ok(None)` means no whole message is buffered yet.
    pub fn next_message(&mut self) -> Result<Option<Incoming>, ConnError> {
        // Bound the signaling messages handled in one call; the rest wait for the next.
        for _ in 0..SIGNALS_PER_CALL {
            let decoded = match coap::decode(&self.inbuf[self.consumed..], self.limit) {
                Ok(decoded) => decoded,
                Err(error) => {
                    self.closed = true;
                    return Err(ConnError::Frame(error));
                }
            };
            let (message, used) = match decoded {
                Decoded::NeedMore(_) => return Ok(None),
                Decoded::Message(message, used) => (message, used),
            };
            let code = message.code;
            let incoming = Incoming {
                code,
                token: message.token.to_vec(),
                path: message
                    .options()
                    .filter(|&(number, _)| number == option::URI_PATH)
                    .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
                    .collect(),
                observe: message
                    .option(option::OBSERVE)
                    .and_then(coap::read_uint_option),
                payload: message.payload.to_vec(),
            };
            let max_size = message
                .option(option::MAX_MESSAGE_SIZE)
                .and_then(coap::read_uint_option);
            self.consumed += used;
            match code {
                Code::CSM => {
                    if let Some(size) = max_size {
                        self.peer_limit = Some(size as usize);
                    }
                }
                Code::PING if self.outbuf.len() < self.limit => {
                    let token = incoming.token.clone();
                    self.send(&Outgoing {
                        code: Some(Code::PONG),
                        token: &token,
                        ..Outgoing::default()
                    })
                    .expect("a Pong always encodes");
                }
                Code::PING | Code::PONG | Code::RELEASE => {}
                Code::ABORT => {
                    self.closed = true;
                    return Ok(None);
                }
                _ => return Ok(Some(incoming)),
            }
        }
        self.more = true;
        Ok(None)
    }

    /// True once after [`Connection::next_message`] stopped early with whole messages
    /// still buffered, so the caller steps again instead of waiting for the socket.
    pub fn take_more(&mut self) -> bool {
        std::mem::take(&mut self.more)
    }

    /// True when nothing is waiting to be written.
    pub fn flushed(&self) -> bool {
        self.outbuf.is_empty()
    }

    /// Bytes queued but not yet written.
    pub fn backlog(&self) -> usize {
        self.outbuf.len()
    }

    /// Bytes received but not yet handed out.
    pub fn buffered_in(&self) -> usize {
        self.inbuf.len() - self.consumed
    }

    /// The largest message this side accepts.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Stops using the connection. The peer sees the socket close when it is dropped.
    pub fn close(&mut self) {
        self.closed = true;
        // Requests the peer had already sent are not handed out any more.
        self.consumed = self.inbuf.len();
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}
