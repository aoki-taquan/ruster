//! SIGINT/SIGTERM stop flag through a minimal private FFI.
//!
//! The handler only stores `true` into a static [`AtomicBool`]; the run loop
//! reads it at every tick boundary and performs the ordered shutdown itself.
//! The handlers stay installed for the life of the process and are never
//! restored: a repeated signal only stores `true` again, and the loop stops
//! within one tick (plus at most one hold pacing sleep). Handlers are
//! installed even when the parent left SIGINT ignored, because `run-sim`
//! promises an ordered shutdown on both signals.
//!
//! On targets other than Linux nothing is installed and the flag never
//! becomes set; the process then keeps the default signal behaviour.

use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

/// Whether SIGINT or SIGTERM arrived since [`install`].
pub fn stop_requested() -> bool {
    STOP.load(Ordering::Relaxed)
}

/// Installs the SIGINT and SIGTERM handlers.
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
    // `SIG_ERR` is `(sighandler_t) -1`.
    const SIG_ERR: usize = usize::MAX;

    type SigHandler = extern "C" fn(c_int);

    extern "C" {
        // `sighandler_t signal(int, sighandler_t)` from the C library that
        // std already links (glibc or musl). Both give it BSD semantics on
        // Linux: the handler stays installed and interrupted syscalls
        // restart (SA_RESTART).
        fn signal(signum: c_int, handler: SigHandler) -> usize;
    }

    extern "C" fn on_stop(_signum: c_int) {
        // Async-signal-safe: a single lock-free atomic store, no allocation,
        // no lock, no errno change, no reentrancy into std.
        super::STOP.store(true, Ordering::Relaxed);
    }

    // The handler relies on a lock-free byte-sized atomic.
    #[cfg(not(target_has_atomic = "8"))]
    compile_error!("the signal stop flag requires lock-free 8-bit atomics");

    pub fn install() -> Result<(), &'static str> {
        for (signum, name) in [(SIGINT, "SIGINT"), (SIGTERM, "SIGTERM")] {
            // SAFETY: `signal` is the C library function with the declared
            // signature (`int`, function pointer -> previous handler as a
            // pointer-sized value). `on_stop` is an `extern "C" fn(c_int)`
            // with static lifetime whose body is async-signal-safe (one
            // relaxed store to a static lock-free `AtomicBool`), so it may run
            // at any instruction of any thread. Installation happens once on
            // the main thread before any tick, and no other code in this
            // process changes these dispositions.
            let previous = unsafe { signal(signum, on_stop) };
            if previous == SIG_ERR {
                return Err(name);
            }
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
