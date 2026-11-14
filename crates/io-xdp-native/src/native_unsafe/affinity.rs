#![allow(unsafe_code)]
//! Pinning the calling thread to one CPU (`sched_setaffinity(2)`), for a
//! forwarding worker that should keep its core and its caches.

use std::io;

/// Words of the CPU mask: `CPU_SETSIZE` (1024) bits.
const MASK_WORDS: usize = 16;

/// Pins the calling thread to CPU `cpu`. Fails for a CPU the mask cannot name
/// (1024 or more) and with the kernel's error for one the thread may not run on
/// (`EINVAL`: offline, outside the cgroup's set).
pub fn pin_current_thread(cpu: usize) -> io::Result<()> {
    if cpu >= MASK_WORDS * 64 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut mask = [0_u64; MASK_WORDS];
    mask[cpu / 64] = 1 << (cpu % 64);
    // SAFETY: `mask` is a live, initialized buffer of exactly the length passed,
    // which the kernel only reads; pid 0 is the calling thread. The declaration
    // matches glibc's `int sched_setaffinity(pid_t, size_t, const cpu_set_t *)`.
    let result = unsafe { ffi::sched_setaffinity(0, std::mem::size_of_val(&mask), mask.as_ptr()) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

mod ffi {
    use std::ffi::c_int;

    // SAFETY: glibc's prototype on Linux; `pid_t` is `int`.
    unsafe extern "C" {
        pub(super) fn sched_setaffinity(pid: c_int, size: usize, mask: *const u64) -> c_int;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cpu_the_mask_cannot_name_is_refused() {
        let error = pin_current_thread(MASK_WORDS * 64).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_thread_is_pinned_to_a_cpu_it_may_run_on() {
        // On a thread of its own, so the test runner's threads keep their CPUs.
        let pinned = std::thread::spawn(|| {
            let cpus = std::thread::available_parallelism().map_or(1, usize::from);
            (0..cpus.max(1)).any(|cpu| pin_current_thread(cpu).is_ok())
        })
        .join()
        .unwrap();
        assert!(pinned, "some CPU in the allowed set takes the thread");
    }
}
