//! Non-blocking stdout/stderr for `ruster run`.
//!
//! A write to a pipe nobody drains blocks forever (the signal handlers use
//! `SA_RESTART`), so the run-loop thread never writes to a file descriptor
//! itself. [`ColdOutput`] owns one writer thread per stream, each with its
//! own bounded queue, so a stuck stdout cannot starve stderr (startup
//! failures, warnings, and the summary still get out). [`LineWriter`] (the
//! `out` and `err` of `run::execute`) collects bytes and hands complete
//! lines (and, on `flush`, everything pending) to its stream's thread with
//! `try_send`. When the queue is full or the thread is gone the message is
//! dropped and [`dropped`] counts it; the caller never waits.
//!
//! [`ColdOutput::process`] gives the threads duplicates of fd 1 and fd 2
//! wrapped in `File`, not `std::io::stdout()`/`stderr()`: a thread blocked
//! in a write then holds no std lock, so neither `main` nor std's exit-time
//! cleanup can wait on it.
//!
//! The writers only run on the cold path: startup lines, the readiness
//! line, warnings, periodic stats blocks (once per interval), and the
//! shutdown summary. The tick path never writes, so it takes no lock and
//! allocates nothing here. At exit [`ColdOutput::finish`] waits a bounded
//! time for the threads to write what is queued; a thread still blocked on
//! a full pipe is abandoned (it dies with the process), so the final stats
//! or summary of a blocked stream may be lost.

use std::fs::File;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

/// Messages queued per stream before new ones are dropped.
pub const QUEUE: usize = 64;

static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Output messages dropped because a writer could not keep up (a full or
/// undrained pipe), process-wide.
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stream {
    Out,
    Err,
}

struct Lane {
    sender: SyncSender<Vec<u8>>,
    done: Receiver<()>,
}

impl Lane {
    fn spawn<W: Write + Send + 'static>(mut sink: W, name: &str) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(QUEUE);
        let (finished, done) = mpsc::channel();
        thread::Builder::new().name(name.into()).spawn(move || {
            for bytes in receiver {
                // Errors (a closed pipe) are ignored: output is best
                // effort and never blocks the router.
                let _ = sink.write_all(&bytes).and_then(|()| sink.flush());
            }
            let _ = finished.send(());
        })?;
        Ok(Self { sender, done })
    }
}

/// One writer thread and queue per stream.
pub struct ColdOutput {
    out: Lane,
    err: Lane,
}

impl ColdOutput {
    /// Starts the writer threads over `out` and `err`.
    pub fn spawn<O, E>(out: O, err: E) -> io::Result<Self>
    where
        O: Write + Send + 'static,
        E: Write + Send + 'static,
    {
        Ok(Self {
            out: Lane::spawn(out, "ruster-stdout")?,
            err: Lane::spawn(err, "ruster-stderr")?,
        })
    }

    /// Writer threads over duplicates of this process's fd 1 and fd 2, as
    /// plain `File`s that take no std stdout/stderr lock.
    pub fn process() -> io::Result<Self> {
        use std::os::fd::AsFd;

        let out = File::from(io::stdout().as_fd().try_clone_to_owned()?);
        let err = File::from(io::stderr().as_fd().try_clone_to_owned()?);
        Self::spawn(out, err)
    }

    /// A writer for `stream`.
    pub fn writer(&self, stream: Stream) -> LineWriter {
        let lane = match stream {
            Stream::Out => &self.out,
            Stream::Err => &self.err,
        };
        LineWriter {
            sender: lane.sender.clone(),
            pending: Vec::new(),
        }
    }

    /// Closes both queues and waits at most `timeout` in total for the
    /// threads to write what is queued. Every [`LineWriter`] must be
    /// dropped first. Returns whether both streams were written out.
    pub fn finish(self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let Self { out, err } = self;
        drop((out.sender, err.sender));
        let wait = |done: &Receiver<()>| {
            done.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .is_ok()
        };
        // Both are waited on (the second gets the remaining time).
        let err_done = wait(&err.done);
        let out_done = wait(&out.done);
        err_done && out_done
    }
}

/// Collects bytes and queues complete lines without blocking.
pub struct LineWriter {
    sender: SyncSender<Vec<u8>>,
    pending: Vec<u8>,
}

impl LineWriter {
    fn send(&mut self, bytes: Vec<u8>) {
        match self.sender.try_send(bytes) {
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

/// Aborts the test process if `guard` is not disarmed within `limit`, so
/// a regression to a blocking write fails the test run instead of hanging.
#[cfg(test)]
pub struct Watchdog(std::sync::Arc<std::sync::atomic::AtomicBool>);

#[cfg(test)]
impl Watchdog {
    pub fn arm(limit: Duration, what: &'static str) -> Self {
        let disarmed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&disarmed);
        thread::spawn(move || {
            let deadline = Instant::now() + limit;
            while Instant::now() < deadline {
                if flag.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_millis(20));
            }
            eprintln!("watchdog: {what} did not finish within {limit:?}; aborting");
            std::process::abort();
        });
        Self(disarmed)
    }
}

#[cfg(test)]
impl Drop for Watchdog {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[test]
    fn lines_reach_each_stream_in_order() {
        let (mut out_reader, out_writer) = io::pipe().expect("pipe");
        let (mut err_reader, err_writer) = io::pipe().expect("pipe");
        let output = ColdOutput::spawn(out_writer, err_writer).expect("spawn");
        let mut out = output.writer(Stream::Out);
        let mut err = output.writer(Stream::Err);
        write!(out, "a").unwrap();
        writeln!(out, "b").unwrap();
        write!(out, "c").unwrap();
        writeln!(err, "e").unwrap();
        drop((out, err));
        assert!(output.finish(Duration::from_secs(10)));
        let mut text = String::new();
        out_reader.read_to_string(&mut text).expect("read");
        assert_eq!(text, "ab\nc");
        text.clear();
        err_reader.read_to_string(&mut text).expect("read");
        assert_eq!(text, "e\n");
    }

    /// The process wiring takes no std stdout/stderr lock: with both held
    /// by this thread, the writer threads still write and finish. Wiring
    /// the threads to `io::stdout()`/`io::stderr()` again blocks them on
    /// the held locks and fails this test (bounded by `finish`).
    #[test]
    fn process_output_writes_without_the_std_locks() {
        let _watchdog = Watchdog::arm(Duration::from_secs(60), "process output");
        let stdout = io::stdout();
        let stderr = io::stderr();
        let held = (stdout.lock(), stderr.lock());
        let output = ColdOutput::process().expect("dup fds");
        let mut out = output.writer(Stream::Out);
        let mut err = output.writer(Stream::Err);
        writeln!(out, "ruster-output-wiring-probe").unwrap();
        writeln!(err, "ruster-output-wiring-probe").unwrap();
        drop((out, err));
        let finished = output.finish(Duration::from_secs(5));
        drop(held);
        assert!(finished, "a writer thread waited on a std stdio lock");
    }

    /// A stuck stdout does not starve stderr.
    #[test]
    fn a_blocked_stdout_does_not_starve_stderr() {
        let _watchdog = Watchdog::arm(Duration::from_secs(60), "stderr lane");
        let (out_reader, out_writer) = io::pipe().expect("pipe");
        let (mut err_reader, err_writer) = io::pipe().expect("pipe");
        let output = ColdOutput::spawn(out_writer, err_writer).expect("spawn");
        let mut out = output.writer(Stream::Out);
        let mut err = output.writer(Stream::Err);
        let block = vec![b'x'; 16 * 1024];
        for _ in 0..(QUEUE + 64) {
            out.write_all(&block).unwrap();
            out.flush().unwrap();
        }
        writeln!(err, "summary").unwrap();
        drop((out, err));
        // stdout stays blocked (never read), so finish times out, but the
        // stderr line is written.
        assert!(!output.finish(Duration::from_millis(500)));
        let mut line = [0_u8; 8];
        err_reader.read_exact(&mut line).expect("stderr delivered");
        assert_eq!(&line, b"summary\n");
        drop(out_reader);
    }
}
