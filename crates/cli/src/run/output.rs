//! Non-blocking stdout/stderr for `ruster run`.
//!
//! A write to a pipe nobody drains blocks forever (the signal handlers use
//! `SA_RESTART`), so the run-loop thread never writes to a file descriptor
//! itself. [`ColdOutput`] owns one writer thread; [`LineWriter`] (the `out`
//! and `err` of `run::execute`) collects bytes and hands complete lines
//! (and, on `flush`, everything pending) to that thread with a bounded
//! `try_send`. When the queue is full or the thread is gone the message is
//! dropped and [`dropped`] counts it; the caller never waits.
//!
//! The writer only runs on the cold path: startup lines, the readiness
//! line, warnings, periodic stats blocks (once per interval), and the
//! shutdown summary. The tick path never writes, so it takes no lock and
//! allocates nothing here. At exit [`ColdOutput::finish`] waits a bounded
//! time for the thread to write what is queued; a thread still blocked on
//! a full pipe is abandoned (it dies with the process).

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread;
use std::time::Duration;

/// Messages queued for the writer thread before new ones are dropped.
pub const QUEUE: usize = 64;

static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Output messages dropped because the writer could not keep up (a full
/// or undrained pipe), process-wide.
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stream {
    Out,
    Err,
}

type Message = (Stream, Vec<u8>);

/// The writer thread and its queue.
pub struct ColdOutput {
    sender: SyncSender<Message>,
    done: Receiver<()>,
}

impl ColdOutput {
    /// Starts the writer thread over `out` and `err`.
    pub fn spawn<O, E>(mut out: O, mut err: E) -> io::Result<Self>
    where
        O: Write + Send + 'static,
        E: Write + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel::<Message>(QUEUE);
        let (finished, done) = mpsc::channel();
        thread::Builder::new()
            .name("ruster-output".into())
            .spawn(move || {
                for (stream, bytes) in receiver {
                    // Errors (a closed pipe) are ignored: output is
                    // best effort and never blocks the router.
                    let _ = match stream {
                        Stream::Out => out.write_all(&bytes).and_then(|()| out.flush()),
                        Stream::Err => err.write_all(&bytes).and_then(|()| err.flush()),
                    };
                }
                let _ = finished.send(());
            })?;
        Ok(Self { sender, done })
    }

    /// A writer for `stream`.
    pub fn writer(&self, stream: Stream) -> LineWriter {
        LineWriter {
            sender: self.sender.clone(),
            stream,
            pending: Vec::new(),
        }
    }

    /// Closes the queue and waits at most `timeout` for the thread to write
    /// what is queued. Every [`LineWriter`] must be dropped first. Returns
    /// whether everything was written.
    pub fn finish(self, timeout: Duration) -> bool {
        drop(self.sender);
        self.done.recv_timeout(timeout).is_ok()
    }
}

/// Collects bytes and queues complete lines without blocking.
pub struct LineWriter {
    sender: SyncSender<Message>,
    stream: Stream,
    pending: Vec<u8>,
}

impl LineWriter {
    fn send(&mut self, bytes: Vec<u8>) {
        match self.sender.try_send((self.stream, bytes)) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Write for LineWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        if let Some(end) = self.pending.iter().rposition(|byte| *byte == b'\n') {
            let rest = self.pending.split_off(end + 1);
            let lines = std::mem::replace(&mut self.pending, rest);
            self.send(lines);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            let pending = std::mem::take(&mut self.pending);
            self.send(pending);
        }
        Ok(())
    }
}

impl Drop for LineWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[test]
    fn lines_reach_the_thread_in_order() {
        let (mut reader, writer) = io::pipe().expect("pipe");
        let err = writer.try_clone().expect("clone");
        let output = ColdOutput::spawn(writer, err).expect("spawn");
        let mut out = output.writer(Stream::Out);
        write!(out, "a").unwrap();
        writeln!(out, "b").unwrap();
        write!(out, "c").unwrap();
        out.flush().unwrap();
        drop(out);
        assert!(output.finish(Duration::from_secs(10)));
        let mut text = String::new();
        reader.read_to_string(&mut text).expect("read");
        assert_eq!(text, "ab\nc");
    }
}
