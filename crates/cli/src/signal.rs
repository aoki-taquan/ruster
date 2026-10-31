//! SIGINT/SIGTERM stop flag through a minimal private FFI.
//!
//! The handler only stores `true` into a static [`AtomicBool`]; the run loop
//! reads it at every tick boundary and performs the ordered shutdown itself.
//! The handlers stay installed for the life of the process and are never
//! restored: a repeated signal only stores `true` again, and the loop stops
//! within one tick (plus at most one hold pacing sleep).
//!
//! SIGTERM is always handled. SIGINT follows the shell convention: if the
//! process started with SIGINT ignored (for example a background `cmd &`
//! without job control), it stays ignored. The disposition is probed by
//! first setting SIG_IGN, so a SIGINT arriving during the probe is ignored
//! rather than killing the process. SIGHUP and other signals keep their
//! inherited disposition (not handled in M1).
//!
//! On targets other than Linux nothing is installed and the flag never
//! becomes set; the process then keeps the default signal behaviour.

use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

/// Whether a handled SIGINT or SIGTERM arrived since [`install`].
pub fn stop_requested() -> bool {
    STOP.load(Ordering::Relaxed)
}

/// Installs the SIGTERM handler and, unless SIGINT was inherited as
/// ignored, the SIGINT handler.
pub fn install() -> Result<(), &'static str> {
    imp::install()
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod imp {
    use std::os::raw::c_int;
    use std::sync::atomic::Ordering;

    // Linux signal numbers, identical on every Linux architecture.
    const SIGINT: c_int = 2;
    const SIGTERM: c_int = 15;
    // `sighandler_t` special values: SIG_IGN is `(sighandler_t) 1`, SIG_ERR
    // is `(sighandler_t) -1`.
    const SIG_IGN: usize = 1;
    const SIG_ERR: usize = usize::MAX;

    extern "C" {
        // `sighandler_t signal(int, sighandler_t)` from the C library that
        // std already links (glibc or musl). `sighandler_t` is a pointer, so
        // it is passed and returned as a pointer-sized `usize`. Both libcs
        // give it BSD semantics on Linux: the handler stays installed and
        // interrupted syscalls restart (SA_RESTART).
        fn signal(signum: c_int, handler: usize) -> usize;
    }

    extern "C" fn on_stop(_signum: c_int) {
        // Async-signal-safe: a single lock-free atomic store, no allocation,
        // no lock, no errno change, no reentrancy into std.
        super::STOP.store(true, Ordering::Relaxed);
    }

    // The handler relies on a lock-free byte-sized atomic.
    #[cfg(not(target_has_atomic = "8"))]
    compile_error!("the signal stop flag requires lock-free 8-bit atomics");

    /// Sets `handler` for `signum` and returns the previous disposition.
    fn set(signum: c_int, handler: usize, name: &'static str) -> Result<usize, &'static str> {
        // SAFETY: `signal` is the C library function with the declared ABI
        // (`int` and a pointer-sized handler in, previous handler out).
        // `handler` is either SIG_IGN or the address of `on_stop`, an
        // `extern "C" fn(c_int)` with static lifetime whose body is
        // async-signal-safe (one relaxed store to a static lock-free
        // `AtomicBool`), so it may run at any instruction of any thread.
        // Installation happens once on the main thread before any tick, and
        // no other code in this process changes these dispositions.
        let previous = unsafe { signal(signum, handler) };
        if previous == SIG_ERR {
            return Err(name);
        }
        Ok(previous)
    }

    pub fn install() -> Result<(), &'static str> {
        let handler = on_stop as extern "C" fn(c_int) as usize;
        set(SIGTERM, handler, "SIGTERM")?;
        // Probe by ignoring first; keep ignoring if that was inherited.
        if set(SIGINT, SIG_IGN, "SIGINT")? != SIG_IGN {
            set(SIGINT, handler, "SIGINT")?;
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    pub fn install() -> Result<(), &'static str> {
        Ok(())
    }
}
