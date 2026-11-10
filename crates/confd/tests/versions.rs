//! The versions confd keeps, in memory and in a state directory.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use ruster_confd::file;
use ruster_confd::versions::{utc, Versions, Waiting, KEEP};

fn state_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ruster-confd-versions-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

const TOML: &str =
    "[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:01\"\nipv4 = \"192.0.2.1/24\"\n";

#[test]
fn versions_are_written_and_read_back() {
    let dir = state_dir("round-trip");
    let mut versions = Versions::open(&dir).unwrap();
    assert!(versions.latest().is_none());
    let lock = file::candidate(TOML).unwrap().lock;
    assert_eq!(versions.commit("apply", &lock, Some(TOML)), Ok(1));
    assert_eq!(versions.commit("rollback to 1", &lock, None), Ok(2));

    let again = Versions::open(&dir).unwrap();
    assert_eq!(again.list(), versions.list());
    let first = again.get(1).unwrap();
    assert_eq!(first.how, "apply");
    assert_eq!(first.lock, lock);
    assert_eq!(first.toml.as_deref(), Some(TOML));
    assert_eq!(again.get(2).unwrap().toml, None);

    // Only the owner reads them: the lock form can hold passwords.
    let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(dir.join("versions")), 0o700);
    assert_eq!(mode(dir.join("versions/000001.toml")), 0o600);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn only_the_last_versions_are_kept() {
    let dir = state_dir("keep");
    let mut versions = Versions::open(&dir).unwrap();
    for _ in 0..KEEP + 2 {
        versions.commit("apply", "version = 1\n", None).unwrap();
    }
    let numbers: Vec<u64> = versions.list().iter().map(|v| v.number).collect();
    assert_eq!(numbers.len(), KEEP);
    assert_eq!(numbers[0], 3);
    assert_eq!(*numbers.last().unwrap(), KEEP as u64 + 2);
    let files = std::fs::read_dir(dir.join("versions")).unwrap().count();
    assert_eq!(files, KEEP);
    // Numbers are not used again after a restart.
    let mut again = Versions::open(&dir).unwrap();
    assert_eq!(
        again.commit("apply", "version = 1\n", None),
        Ok(KEEP as u64 + 3)
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_temporary_file_left_by_a_crash_is_not_a_version() {
    let dir = state_dir("temporary");
    let mut versions = Versions::open(&dir).unwrap();
    versions.commit("apply", "version = 1\n", None).unwrap();
    std::fs::write(dir.join("versions/.000002.toml.tmp"), "half a fi").unwrap();
    let mut again = Versions::open(&dir).unwrap();
    assert_eq!(again.list().len(), 1);
    // The next version writes over it.
    assert_eq!(again.commit("apply", "version = 1\n", None), Ok(2));
    assert!(!dir.join("versions/.000002.toml.tmp").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn confd_starts_with_the_file_only_when_there_is_no_version() {
    let dir = state_dir("start");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("router.toml");
    std::fs::write(&path, TOML).unwrap();
    let path = path.to_str().unwrap();

    let mut versions = Versions::open(&dir).unwrap();
    let (config, from) = versions.starting_config(path).unwrap();
    assert_eq!(from, path);
    assert_eq!(config.interfaces[0].mtu, 1500);
    let first = versions.latest().unwrap();
    assert_eq!(first.number, 1);
    assert_eq!(first.how, format!("start-up file {path}"));
    assert_eq!(first.toml.as_deref(), Some(TOML));

    // A newer version wins over the file, even a changed one.
    let newer = file::candidate(&TOML.replace("192.0.2.1", "192.0.2.2")).unwrap();
    versions.commit("apply", &newer.lock, None).unwrap();
    std::fs::write(path, TOML.replace("192.0.2.1", "192.0.2.3")).unwrap();
    let mut again = Versions::open(&dir).unwrap();
    let (config, from) = again.starting_config(path).unwrap();
    assert_eq!(from, "version 2");
    assert_eq!(
        config.interfaces[0].ipv4.unwrap().0.to_string(),
        "192.0.2.2"
    );
    assert_eq!(again.list().len(), 2, "the file is not kept again");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_latest_version_that_cannot_be_read_stops_the_start() {
    let dir = state_dir("unreadable");
    let mut versions = Versions::open(&dir).unwrap();
    versions.commit("apply", "version = 99\n", None).unwrap();
    let mut again = Versions::open(&dir).unwrap();
    let error = again.starting_config("/nonexistent").unwrap_err();
    assert!(error.starts_with("version 1:"), "{error}");
    assert!(error.contains("version 99"), "{error}");

    std::fs::write(dir.join("versions/000002.toml"), "how = 3").unwrap();
    let error = Versions::open(&dir).unwrap_err();
    assert!(error.contains("000002.toml"), "{error}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_lock_form_from_before_an_update_is_resolved_again_from_its_ruster_toml() {
    let dir = state_dir("update");
    let mut versions = Versions::open(&dir).unwrap();
    // As if an older ruster had written a lock form this one does not read.
    versions
        .commit("apply", "version = 1\nold-key = 3\n", Some(TOML))
        .unwrap();
    let mut again = Versions::open(&dir).unwrap();
    let (config, from) = again.starting_config("/nonexistent").unwrap();
    assert_eq!(
        from,
        "version 2 (ruster.toml of version 1 resolved again at start-up)"
    );
    assert_eq!(config.interfaces[0].name, "lan");
    let latest = again.latest().unwrap();
    assert_eq!(latest.lock, file::candidate(TOML).unwrap().lock);
    assert_eq!(latest.toml.as_deref(), Some(TOML));

    // With a ruster.toml that does not read either, confd does not start.
    versions
        .commit(
            "apply",
            "version = 1\nold-key = 3\n",
            Some("[[interface]]\n"),
        )
        .unwrap();
    let error = Versions::open(&dir)
        .unwrap()
        .starting_config("/nonexistent")
        .unwrap_err();
    assert!(error.contains("does not read either"), "{error}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn an_older_version_that_does_not_read_is_left_out() {
    let dir = state_dir("older");
    let mut versions = Versions::open(&dir).unwrap();
    versions.commit("apply", "version = 1\n", None).unwrap();
    versions.commit("apply", "version = 1\n", None).unwrap();
    std::fs::write(dir.join("versions/000001.toml"), "how = 3").unwrap();
    // Names confd does not write are not versions.
    std::fs::write(dir.join("versions/1.toml"), "how = 3").unwrap();
    std::fs::write(dir.join("versions/+00002.toml"), "how = 3").unwrap();
    let again = Versions::open(&dir).unwrap();
    let numbers: Vec<u64> = again.list().iter().map(|v| v.number).collect();
    assert_eq!(numbers, [2]);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_deadline_for_a_version_that_is_not_the_latest_is_dropped() {
    let dir = state_dir("waiting");
    let mut versions = Versions::open(&dir).unwrap();
    versions.commit("apply", "version = 1\n", None).unwrap();
    let waiting = Waiting {
        version: 2,
        back_to: 1,
        deadline: 4_000_000_000,
        minutes: 5,
    };
    // Written, and then confd stopped before version 2 was.
    versions.set_waiting(Some(waiting)).unwrap();
    assert!(dir.join("versions/confirm.toml").exists());
    let mut again = Versions::open(&dir).unwrap();
    assert_eq!(again.waiting(), None);
    assert!(!dir.join("versions/confirm.toml").exists());

    // Once version 2 is there, it is kept.
    again.set_waiting(Some(waiting)).unwrap();
    again.commit("apply", "version = 1\n", None).unwrap();
    assert_eq!(Versions::open(&dir).unwrap().waiting(), Some(waiting));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_waiting_version_resolved_again_at_start_up_still_waits() {
    let dir = state_dir("waiting-update");
    let mut versions = Versions::open(&dir).unwrap();
    let lock = file::candidate(TOML).unwrap().lock;
    versions.commit("apply", &lock, Some(TOML)).unwrap();
    let waiting = Waiting {
        version: 2,
        back_to: 1,
        deadline: 4_000_000_000,
        minutes: 5,
    };
    versions.set_waiting(Some(waiting)).unwrap();
    // As if an older ruster had written version 2's lock form.
    versions
        .commit("apply", "version = 1\nold-key = 3\n", Some(TOML))
        .unwrap();

    let mut again = Versions::open(&dir).unwrap();
    let (_, from) = again.starting_config("/nonexistent").unwrap();
    assert!(from.starts_with("version 3 "), "{from}");
    let moved = Waiting {
        version: 3,
        ..waiting
    };
    assert_eq!(again.waiting(), Some(moved));
    // And after one more start, it still waits.
    assert_eq!(Versions::open(&dir).unwrap().waiting(), Some(moved));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn times_are_shown_in_utc() {
    assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(utc(951_782_400), "2000-02-29 00:00:00 UTC");
    assert_eq!(utc(1_794_312_345), "2026-11-10 12:05:45 UTC");
}

#[test]
fn the_listing_is_newest_first() {
    let mut versions = Versions::in_memory();
    versions
        .commit("start-up file a.toml", "version = 1\n", None)
        .unwrap();
    versions.commit("apply", "version = 1\n", None).unwrap();
    let listing = versions.listing();
    let lines: Vec<&str> = listing.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("     2  "), "{listing}");
    assert!(lines[0].ends_with("UTC  apply"), "{listing}");
    assert!(lines[1].ends_with("start-up file a.toml"), "{listing}");
}
