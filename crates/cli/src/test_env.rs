//! Process environment reads with a per-thread override for tests.
//!
//! Tests must not call [`std::env::set_var`]. The environment is shared by
//! every test thread in the binary, and glibc reallocates the `environ` array
//! on write, so a concurrent [`std::env::var_os`] in another thread can
//! observe a torn or stale value. That is not hypothetical here: the daemon
//! and the control socket both read their configuration from the environment,
//! and their suites raced each other.
//!
//! Overriding per thread keeps each test's view private, needs no global
//! lock, and cannot poison one. Production builds compile to a direct
//! [`std::env::var_os`] call.

#[cfg(test)]
use std::ffi::OsStr;
use std::ffi::OsString;

/// Reads an environment variable, honouring this thread's test override.
pub(crate) fn var_os(key: &str) -> Option<OsString> {
    #[cfg(test)]
    if let Some(value) = overridden(key) {
        return value;
    }
    std::env::var_os(key)
}

#[cfg(test)]
std::thread_local! {
    /// Keys this thread has overridden, each with the value the thread should
    /// observe. `None` means the thread observes the variable as unset.
    static OVERRIDES: std::cell::RefCell<Vec<(String, Option<OsString>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Returns `Some(view)` when this thread has overridden `key`.
///
/// The outer `Option` distinguishes "not overridden, read the real
/// environment" from the inner `None`, "overridden to unset".
#[cfg(test)]
fn overridden(key: &str) -> Option<Option<OsString>> {
    OVERRIDES.with_borrow(|overrides| {
        overrides
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
    })
}

/// Makes this thread observe `key` as `value` until the guard is dropped.
#[cfg(test)]
pub(crate) fn override_for_thread(key: &str, value: Option<&OsStr>) -> EnvOverrideGuard {
    let previous = overridden(key);
    OVERRIDES.with_borrow_mut(|overrides| {
        let value = value.map(OsStr::to_os_string);
        match overrides.iter_mut().find(|(name, _)| name == key) {
            Some(entry) => entry.1 = value,
            None => overrides.push((key.to_owned(), value)),
        }
    });
    EnvOverrideGuard {
        key: key.to_owned(),
        previous,
    }
}

/// Restores the overriding thread's previous view of one variable.
#[cfg(test)]
pub(crate) struct EnvOverrideGuard {
    key: String,
    previous: Option<Option<OsString>>,
}

#[cfg(test)]
impl Drop for EnvOverrideGuard {
    fn drop(&mut self) {
        OVERRIDES.with_borrow_mut(|overrides| {
            let position = overrides.iter().position(|(name, _)| *name == self.key);
            match (position, self.previous.take()) {
                (Some(index), Some(previous)) => overrides[index].1 = previous,
                (Some(index), None) => {
                    overrides.swap_remove(index);
                }
                (None, Some(previous)) => overrides.push((self.key.clone(), previous)),
                (None, None) => {}
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "RUSTER_TEST_ENV_OVERRIDE_PROBE";

    #[test]
    fn an_override_is_visible_only_until_the_guard_drops() {
        assert_eq!(var_os(KEY), None);
        {
            let _guard = override_for_thread(KEY, Some(OsStr::new("value")));
            assert_eq!(var_os(KEY).as_deref(), Some(OsStr::new("value")));
        }
        assert_eq!(var_os(KEY), None);
    }

    #[test]
    fn nested_overrides_restore_the_enclosing_view() {
        let _outer = override_for_thread(KEY, Some(OsStr::new("outer")));
        {
            let _inner = override_for_thread(KEY, Some(OsStr::new("inner")));
            assert_eq!(var_os(KEY).as_deref(), Some(OsStr::new("inner")));
        }
        assert_eq!(var_os(KEY).as_deref(), Some(OsStr::new("outer")));
    }

    #[test]
    fn an_override_to_unset_hides_a_present_variable() {
        let _present = override_for_thread(KEY, Some(OsStr::new("present")));
        let _hidden = override_for_thread(KEY, None);
        assert_eq!(var_os(KEY), None);
    }

    #[test]
    fn an_unrelated_key_still_reads_the_real_environment() {
        let _guard = override_for_thread(KEY, Some(OsStr::new("value")));
        assert_eq!(var_os("PATH"), std::env::var_os("PATH"));
    }
}
