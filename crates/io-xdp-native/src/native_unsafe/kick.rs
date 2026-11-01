//! Borrowed need-wakeup kick handle of one datapath bundle (M2 S4, X02).
//!
//! The engine owns every ring of its socket through the once-per-session
//! `DatapathRings` bundle, which borrows the session mutably for the
//! engine's whole life. The kernel still needs a syscall on the socket fd
//! to make progress when it sets `XDP_RING_NEED_WAKEUP`: `sendto` for TX
//! (and, in copy mode, for every TX at all), and `poll` for Fill in
//! zero-copy mode. [`SocketKick`] is the only way to reach that fd while
//! the bundle is lent: a shared borrow of the session's owned socket that
//! exposes exactly these two kicks and nothing that could close, bind,
//! map, or reconfigure the socket.
//!
//! This module contains no `unsafe`. Every syscall goes through the sealed
//! seam in `syscall.rs`, whose FFI blocks carry the SAFETY argument and
//! whose Linux implementation rejects a negative fd before entering libc on
//! every call (always on, not a debug assertion).

use std::{fmt, marker::PhantomData};

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
use super::syscall::{LinuxSyscalls, OwnedXdpFd, ResourceError, SyscallError};

/// Linux v6.8 `include/uapi/asm-generic/errno-base.h` and `errno.h` values
/// that a kick classifies. They are architecture independent on Linux.
mod errno {
    pub(super) const EINTR: u16 = 4;
    pub(super) const ENXIO: u16 = 6;
    pub(super) const EAGAIN: u16 = 11;
    pub(super) const EBUSY: u16 = 16;
    pub(super) const ENETDOWN: u16 = 100;
    pub(super) const ENOBUFS: u16 = 105;
}

/// `POLLIN` from Linux v6.8 `include/uapi/asm-generic/poll.h`.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
const POLLIN: i16 = 0x001;

/// Which ring a kick serves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KickRing {
    /// `sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0)`: Linux `xsk_sendmsg`
    /// runs the copy-mode transmit loop or the driver's `ndo_xsk_wakeup`.
    Tx,
    /// `poll(fd, POLLIN, 0)`: Linux `xsk_poll` wakes the zero-copy driver
    /// for the flags it requested (Fill refill) and never sleeps here. In
    /// copy mode `xsk_poll` runs the copy-mode transmit loop instead, so
    /// this kick also advances pending TX there.
    Fill,
}

/// A kick the kernel accepted, or a benign reason to retry it later.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KickOutcome {
    /// The syscall returned success.
    Woken,
    /// A transient refusal; the published descriptors stay published and
    /// the next kick (or the next poll) retries.
    Deferred(KickDeferral),
}

/// Transient kick refusals that libxdp also treats as benign.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KickDeferral {
    /// `EAGAIN`: in Linux v6.8 copy mode this mostly means one transmit
    /// round hit `TX_BATCH_SIZE` (32 descriptors) with more pending, so
    /// kick again soon. (A failed completion-slot reservation ends the
    /// round with success, `Woken`.)
    WouldBlock,
    /// `EBUSY`: the driver or the copy-mode transmit path is busy.
    Busy,
    /// `ENOBUFS`: the kernel lacked buffers for this transmit round.
    NoBuffers,
    /// `EINTR`: interrupted before the kernel acted.
    Interrupted,
}

/// A kick that failed for a reason retrying does not fix by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KickError {
    /// `ENETDOWN`: the interface is down. Published TX descriptors stay in
    /// the ring (and in flight in the ledger) until the link returns or the
    /// session closes.
    NetworkDown,
    /// `ENXIO`: the socket is not bound to a device (or the device left).
    NotBound,
    /// Another Linux errno, kept numeric.
    Errno(u16),
    /// The seam refused the call before entering the kernel (negative or
    /// inactive fd, unsupported platform) or captured no valid errno.
    Rejected,
}

impl fmt::Display for KickError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for KickError {}

/// Maps a kick syscall result to its typed outcome.
///
/// `Err(Some(errno))` is a kernel errno, `Err(None)` a refusal before the
/// kernel (or an unusable capture).
pub(crate) const fn classify(result: Result<(), Option<u16>>) -> Result<KickOutcome, KickError> {
    match result {
        Ok(()) => Ok(KickOutcome::Woken),
        Err(Some(errno::EAGAIN)) => Ok(KickOutcome::Deferred(KickDeferral::WouldBlock)),
        Err(Some(errno::EBUSY)) => Ok(KickOutcome::Deferred(KickDeferral::Busy)),
        Err(Some(errno::ENOBUFS)) => Ok(KickOutcome::Deferred(KickDeferral::NoBuffers)),
        Err(Some(errno::EINTR)) => Ok(KickOutcome::Deferred(KickDeferral::Interrupted)),
        Err(Some(errno::ENETDOWN)) => Err(KickError::NetworkDown),
        Err(Some(errno::ENXIO)) => Err(KickError::NotBound),
        Err(Some(other)) => Err(KickError::Errno(other)),
        Err(None) => Err(KickError::Rejected),
    }
}

/// What a bundle's kick reaches.
pub(super) enum KickTarget<'session> {
    /// The live session's owned socket, borrowed shared: it cannot be
    /// closed (close consumes the owner) while this borrow lives.
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    Live(&'session OwnedXdpFd<'session, LinuxSyscalls>),
    /// A test script that records kicks and injects errno values.
    #[cfg(test)]
    Scripted(&'session ScriptedKicks),
    /// Unreachable marker that keeps `'session` used on every target.
    #[allow(dead_code)]
    Never(std::convert::Infallible, PhantomData<&'session ()>),
}

/// The kick operations of one bundle's socket, and nothing else.
pub(crate) struct SocketKick<'session> {
    target: KickTarget<'session>,
    /// Worker-local like the rest of the bundle.
    _worker_local: PhantomData<*mut ()>,
}

impl<'session> SocketKick<'session> {
    pub(super) const fn new(target: KickTarget<'session>) -> Self {
        Self {
            target,
            _worker_local: PhantomData,
        }
    }

    /// Performs one kick and classifies the result.
    pub(crate) fn kick(&self, ring: KickRing) -> Result<KickOutcome, KickError> {
        classify(self.raw_kick(ring))
    }

    fn raw_kick(&self, ring: KickRing) -> Result<(), Option<u16>> {
        match &self.target {
            #[cfg(all(
                target_os = "linux",
                target_arch = "x86_64",
                target_pointer_width = "64"
            ))]
            KickTarget::Live(fd) => {
                // Always-on argument check on top of the seam's own: an
                // owner can be inactive only after close, which a shared
                // borrow excludes.
                if !fd.is_active() {
                    return Err(None);
                }
                let result = match ring {
                    KickRing::Tx => fd.send_to_wakeup(),
                    KickRing::Fill => fd.poll(POLLIN, 0).map(|_| ()),
                };
                result.map_err(|error| match error {
                    ResourceError::Syscall(SyscallError { errno, .. }) => errno.raw(),
                    ResourceError::Platform(_) | ResourceError::Argument(_) => None,
                })
            }
            #[cfg(test)]
            KickTarget::Scripted(script) => script.kick(ring),
            KickTarget::Never(never, _) => match *never {},
        }
    }
}

impl fmt::Debug for SocketKick<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SocketKick")
            .field("fd", &"<redacted>")
            .finish()
    }
}

/// Test-only kick recorder with errno injection.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct ScriptedKicks {
    tx: std::cell::Cell<u32>,
    fill: std::cell::Cell<u32>,
    fail_next: std::cell::Cell<Option<Option<u16>>>,
}

#[cfg(test)]
impl ScriptedKicks {
    fn kick(&self, ring: KickRing) -> Result<(), Option<u16>> {
        let counter = match ring {
            KickRing::Tx => &self.tx,
            KickRing::Fill => &self.fill,
        };
        counter.set(counter.get() + 1);
        self.fail_next.take().map_or(Ok(()), Err)
    }

    /// Kicks recorded for `ring`.
    pub(crate) fn count(&self, ring: KickRing) -> u32 {
        match ring {
            KickRing::Tx => self.tx.get(),
            KickRing::Fill => self.fill.get(),
        }
    }

    /// Makes the next kick fail with `errno` (`None`: refused before the
    /// kernel).
    pub(crate) fn fail_next(&self, errno: Option<u16>) {
        self.fail_next.set(Some(errno));
    }
}

#[cfg(test)]
mod tests {
    use super::{classify, KickDeferral, KickError, KickOutcome};

    #[test]
    fn kick_errno_mapping_is_exact() {
        assert_eq!(classify(Ok(())), Ok(KickOutcome::Woken));
        for (errno, deferral) in [
            (11, KickDeferral::WouldBlock),
            (16, KickDeferral::Busy),
            (105, KickDeferral::NoBuffers),
            (4, KickDeferral::Interrupted),
        ] {
            assert_eq!(
                classify(Err(Some(errno))),
                Ok(KickOutcome::Deferred(deferral))
            );
        }
        assert_eq!(classify(Err(Some(100))), Err(KickError::NetworkDown));
        assert_eq!(classify(Err(Some(6))), Err(KickError::NotBound));
        assert_eq!(classify(Err(Some(22))), Err(KickError::Errno(22)));
        assert_eq!(classify(Err(None)), Err(KickError::Rejected));
    }
}
