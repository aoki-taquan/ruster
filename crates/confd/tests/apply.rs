//! `ruster apply` against confd and a stand-in FE.

use std::os::unix::net::UnixStream;

use ruster_confd::apply::{Apply, ANSWER_WAIT_MS, GIVE_UP_MS};
use ruster_confd::versions::{Start, Versions};
use ruster_confd::{file, Confd};
use ruster_proto::coap::Code;
use ruster_proto::session::{Client, Event, Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::{Key, Value};
use ruster_proto::task::Task;

/// Refuses any table with an interface MTU of `refuse_mtu`.
struct Check {
    refuse_mtu: Option<u16>,
}

impl Hook for Check {
    fn check(&mut self, next: &Store) -> Result<(), String> {
        let bad = next.iter().any(|(_, value)| {
            matches!(value, Value::Interface { mtu, .. } if Some(*mtu) == self.refuse_mtu)
        });
        if bad {
            Err("mtu refused".into())
        } else {
            Ok(())
        }
    }
    fn committed(&mut self, _store: &Store) {}
}

fn text(mtu: u16) -> String {
    format!(
        "[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:01\"\nmtu = {mtu}\nipv4 = \"192.0.2.1/24\"\n"
    )
}

struct Rig {
    fe: Server,
    check: Check,
    confd: Confd,
    apply: Apply,
    cli: Client,
    now_ms: u64,
}

impl Rig {
    fn new() -> Self {
        Self::with(Versions::in_memory())
    }

    /// With these versions, and a first one of MTU 1500 if there is none, as
    /// confd's start-up does.
    fn with(mut versions: Versions) -> Self {
        if versions.latest().is_none() {
            let first = file::candidate(&text(1500)).unwrap();
            versions.commit("start", &first.lock, None).unwrap();
        }
        let mut fe = Server::new();
        let mut confd = Confd::new(file::parse(&versions.latest().unwrap().lock).unwrap());
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, &[sid::INTERFACE, sid::ADDRESS, sid::ICMP_ERRORS])
            .unwrap();
        confd.connect_fe(b).unwrap();
        let mut apply = Apply::new(versions);
        let (a, b) = UnixStream::pair().unwrap();
        apply.attach(a).unwrap();
        let mut rig = Self {
            fe,
            check: Check { refuse_mtu: None },
            confd,
            apply,
            cli: Client::new(b).unwrap(),
            now_ms: 0,
        };
        rig.answers();
        assert_eq!(rig.mtu(), Some(rig.confd.config().interfaces[0].mtu));
        rig
    }

    /// Runs everything until it is quiet and returns the CLI's answers.
    fn answers(&mut self) -> Vec<(Code, String)> {
        let mut out = Vec::new();
        let mut quiet = 0;
        for _ in 0..1_000 {
            let busy = self.fe.step(&mut self.check).busy
                | self.confd.step(self.now_ms).busy
                | self
                    .apply
                    .step(&mut self.confd, self.now_ms, &mut |_| Vec::new())
                    .busy;
            let (polled, events) = self.cli.poll();
            for event in events {
                if let Event::Response { code, payload, .. } = event {
                    out.push((code, String::from_utf8(payload).unwrap()));
                }
            }
            quiet = if busy || polled.busy { 0 } else { quiet + 1 };
            if quiet > 3 {
                return out;
            }
        }
        panic!("never settled");
    }

    fn mtu(&self) -> Option<u16> {
        match self.fe.store().get(&Key::Interface { name: "lan".into() }) {
            Some(Value::Interface { mtu, .. }) => Some(*mtu),
            _ => None,
        }
    }
}

#[test]
fn a_new_file_reaches_the_fe_before_the_answer() {
    let mut rig = Rig::new();
    rig.cli.post(&["config"], text(1400).as_bytes());
    let answers = rig.answers();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].0, Code::CHANGED, "{answers:?}");
    assert!(
        answers[0].1.contains("ribd is not connected"),
        "{answers:?}"
    );
    assert_eq!(rig.mtu(), Some(1400));
    assert_eq!(rig.confd.config().interfaces[0].mtu, 1400);
}

#[test]
fn a_refused_file_puts_the_configuration_before_it_back() {
    let mut rig = Rig::new();
    rig.check.refuse_mtu = Some(1400);
    rig.cli.post(&["config"], text(1400).as_bytes());
    let answers = rig.answers();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].0, Code::BAD_REQUEST);
    assert!(
        answers[0].1.contains("the FE refused it: mtu refused"),
        "{answers:?}"
    );
    assert_eq!(rig.confd.config().interfaces[0].mtu, 1500);
    assert_eq!(rig.mtu(), Some(1500));
    assert_eq!(
        rig.fe.store().len(),
        4,
        "the interface, both addresses and the ICMP error limits"
    );

    // The next file goes through as usual.
    rig.cli.post(&["config"], text(1280).as_bytes());
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::CHANGED, "{answers:?}");
    assert_eq!(rig.mtu(), Some(1280));
}

#[test]
fn a_file_with_an_error_changes_nothing() {
    let mut rig = Rig::new();
    rig.cli
        .post(&["config"], b"[[interface]]\nname = \"lan\"\n");
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::BAD_REQUEST);
    assert!(answers[0].1.contains("mac"), "{answers:?}");
    rig.cli.post(&["config"], &[0xff]);
    rig.cli.post(&["other"], b"");
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::BAD_REQUEST);
    assert_eq!(answers[1].0, Code::NOT_FOUND);
    assert_eq!(rig.mtu(), Some(1500));
}

#[test]
fn a_second_file_waits_and_a_silent_process_times_out() {
    let mut rig = Rig::new();
    // The FE does not run: the first file waits for it, the second is turned away.
    let mut fe = std::mem::take(&mut rig.fe);
    rig.cli.post(&["config"], text(1400).as_bytes());
    rig.cli.post(&["config"], text(1280).as_bytes());
    let answers = rig.answers();
    assert_eq!(answers.len(), 1, "{answers:?}");
    assert_eq!(answers[0].0, Code::SERVICE_UNAVAILABLE);

    rig.now_ms = ANSWER_WAIT_MS;
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::GATEWAY_TIMEOUT, "{answers:?}");
    assert_eq!(rig.confd.config().interfaces[0].mtu, 1400, "it stays");

    // When the FE runs again it takes the new configuration.
    std::mem::swap(&mut rig.fe, &mut fe);
    rig.answers();
    assert_eq!(rig.mtu(), Some(1400));
}

#[test]
fn a_refusal_after_the_timeout_still_puts_the_configuration_before_back() {
    let mut rig = Rig::new();
    let mut fe = std::mem::take(&mut rig.fe);
    rig.check.refuse_mtu = Some(1400);
    rig.cli.post(&["config"], text(1400).as_bytes());
    assert!(rig.answers().is_empty());
    rig.now_ms = ANSWER_WAIT_MS;
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::GATEWAY_TIMEOUT, "{answers:?}");

    // The FE answers late, and refuses: every process goes back.
    std::mem::swap(&mut rig.fe, &mut fe);
    assert!(rig.answers().is_empty(), "nothing more to the CLI");
    assert_eq!(rig.confd.config().interfaces[0].mtu, 1500);
    assert_eq!(rig.mtu(), Some(1500));

    // The late refusal does not count against the next file.
    rig.cli.post(&["config"], text(1280).as_bytes());
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::CHANGED, "{answers:?}");
    assert_eq!(rig.mtu(), Some(1280));
}

#[test]
fn a_process_that_reconnects_and_refuses_still_puts_the_configuration_before_back() {
    let mut rig = Rig::new();
    rig.check.refuse_mtu = Some(1400);
    // The FE goes away with the change in flight.
    let silent = std::mem::take(&mut rig.fe);
    rig.cli.post(&["config"], text(1400).as_bytes());
    assert!(rig.answers().is_empty());
    drop(silent);
    assert!(rig.answers().is_empty(), "waits for the FE to come back");

    // A new FE: confd connects and sends everything; the FE refuses it.
    let (a, b) = UnixStream::pair().unwrap();
    rig.fe
        .attach(a, &[sid::INTERFACE, sid::ADDRESS, sid::ICMP_ERRORS])
        .unwrap();
    rig.confd.connect_fe(b).unwrap();
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::BAD_REQUEST, "{answers:?}");
    assert_eq!(rig.confd.config().interfaces[0].mtu, 1500);
    assert_eq!(rig.mtu(), Some(1500));
}

#[test]
fn confd_stops_waiting_after_a_while() {
    let mut rig = Rig::new();
    let _silent = std::mem::take(&mut rig.fe);
    rig.cli.post(&["config"], text(1400).as_bytes());
    assert!(rig.answers().is_empty());
    rig.now_ms = ANSWER_WAIT_MS;
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::GATEWAY_TIMEOUT, "{answers:?}");
    assert_eq!(rig.apply.counters().gave_up, 0);
    rig.now_ms = GIVE_UP_MS;
    assert!(rig.answers().is_empty());
    assert_eq!(rig.apply.counters().gave_up, 1);
    // The configuration in use is the latest version.
    let latest = rig.apply.versions().latest().unwrap();
    assert_eq!(latest.number, 2);
    assert!(latest.lock.contains("mtu = 1400"), "{}", latest.lock);
}

#[test]
fn a_process_already_down_is_not_waited_for() {
    let mut rig = Rig::new();
    drop(std::mem::take(&mut rig.fe));
    rig.answers();
    rig.cli.post(&["config"], text(1400).as_bytes());
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::CHANGED, "{answers:?}");
    assert!(
        answers[0].1.contains("the FE is not connected"),
        "{answers:?}"
    );
}

fn state_dir(name: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("ruster-confd-apply-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn each_taken_file_is_kept_as_the_next_version() {
    let mut rig = Rig::new();
    rig.cli.post(&["config"], text(1400).as_bytes());
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::CHANGED, "{answers:?}");
    assert!(
        answers[0].1.contains("kept as version 2 (apply)"),
        "{answers:?}"
    );
    let latest = rig.apply.versions().latest().unwrap();
    assert!(latest.lock.contains("mtu = 1400"), "{}", latest.lock);
    assert_eq!(latest.toml.as_deref(), Some(text(1400).as_str()));

    // A refused file and a file with an error are not kept.
    rig.check.refuse_mtu = Some(1280);
    rig.cli.post(&["config"], text(1280).as_bytes());
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::BAD_REQUEST, "{answers:?}");
    rig.cli.post(&["config"], b"[[interface]]\n");
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::BAD_REQUEST, "{answers:?}");
    assert_eq!(rig.apply.versions().latest().unwrap().number, 2);

    // The lock form is kept as it came, without a toml text.
    let lock = rig.apply.versions().latest().unwrap().lock.clone();
    rig.cli.post(
        &["config"],
        lock.replace("mtu = 1400", "mtu = 1300").as_bytes(),
    );
    let answers = rig.answers();
    assert!(answers[0].1.contains("kept as version 3"), "{answers:?}");
    let latest = rig.apply.versions().latest().unwrap();
    assert!(latest.lock.contains("mtu = 1300"), "{}", latest.lock);
    assert_eq!(latest.toml, None);
}

#[test]
fn the_versions_outlive_confd() {
    let dir = state_dir("outlive");
    let mut rig = Rig::with(Versions::open(&dir).unwrap());
    rig.cli.post(&["config"], text(1400).as_bytes());
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::CHANGED, "{answers:?}");
    drop(rig);

    // confd started again: the file is not read, the latest version is used.
    let mut versions = Versions::open(&dir).unwrap();
    assert_eq!(versions.list().len(), 2);
    let Start { config, from, .. } = versions
        .starting_config("/nonexistent/router.toml")
        .unwrap();
    assert_eq!(from, "version 2");
    assert_eq!(config.interfaces[0].mtu, 1400);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_version_that_cannot_be_written_is_said_with_5_00() {
    let dir = state_dir("unwritable");
    let mut rig = Rig::with(Versions::open(&dir).unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
    rig.cli.post(&["config"], text(1400).as_bytes());
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::INTERNAL_SERVER_ERROR, "{answers:?}");
    assert!(
        answers[0].1.contains("would go back to version 1"),
        "{answers:?}"
    );
    // It is in use all the same.
    assert_eq!(rig.mtu(), Some(1400));
    assert_eq!(rig.apply.versions().latest().unwrap().number, 1);
}

#[test]
fn a_rollback_makes_an_old_version_the_latest() {
    let mut rig = Rig::new();
    rig.cli.post(&["config"], text(1400).as_bytes());
    rig.answers();
    rig.cli.post(&["rollback", "1"], b"");
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::CHANGED, "{answers:?}");
    assert!(
        answers[0].1.contains("kept as version 3 (rollback to 1)"),
        "{answers:?}"
    );
    assert_eq!(rig.mtu(), Some(1500));
    let versions = rig.apply.versions();
    assert_eq!(
        versions.latest().unwrap().lock,
        versions.get(1).unwrap().lock
    );
    assert_eq!(versions.list().len(), 3, "version 2 stays");

    rig.cli.get(&["versions"]);
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::CONTENT);
    let lines: Vec<&str> = answers[0].1.lines().collect();
    assert_eq!(lines.len(), 3, "{answers:?}");
    assert!(lines[0].ends_with("rollback to 1"), "{answers:?}");
    assert!(lines[2].ends_with("start"), "{answers:?}");
}

#[test]
fn a_rollback_goes_like_a_new_file() {
    let mut rig = Rig::new();
    rig.cli.post(&["config"], text(1400).as_bytes());
    rig.answers();
    rig.cli.post(&["rollback", "7"], b"");
    rig.cli.post(&["rollback", "x"], b"");
    rig.cli.post(&["rollback", "+1"], b"");
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::NOT_FOUND, "{answers:?}");
    assert_eq!(answers[0].1, "it is not kept", "{answers:?}");
    assert_eq!(answers[1].0, Code::BAD_REQUEST, "{answers:?}");
    assert!(
        answers[1].1.contains("x: not a version number"),
        "{answers:?}"
    );
    assert_eq!(answers[2].0, Code::BAD_REQUEST, "{answers:?}");

    // A refusal puts version 2 back and keeps nothing.
    rig.check.refuse_mtu = Some(1500);
    rig.cli.post(&["rollback", "1"], b"");
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::BAD_REQUEST, "{answers:?}");
    assert_eq!(rig.mtu(), Some(1400));
    assert_eq!(rig.apply.versions().latest().unwrap().number, 2);

    // While a change waits for answers, a rollback waits too.
    let _silent = std::mem::take(&mut rig.fe);
    rig.check.refuse_mtu = None;
    rig.cli.post(&["config"], text(1300).as_bytes());
    rig.cli.post(&["rollback", "1"], b"");
    let answers = rig.answers();
    assert_eq!(answers.len(), 1, "{answers:?}");
    assert_eq!(answers[0].0, Code::SERVICE_UNAVAILABLE, "{answers:?}");
}

#[test]
fn a_rollback_to_a_lock_form_this_confd_does_not_read_is_refused_with_a_hint() {
    let mut versions = Versions::in_memory();
    let first = file::candidate(&text(1500)).unwrap();
    versions
        .commit("start", &first.lock, Some(&text(1500)))
        .unwrap();
    // As if written by an older ruster with another lock form.
    versions
        .commit("apply", "version = 1\nold-key = 3\n", Some(&text(1400)))
        .unwrap();
    versions.commit("apply", &first.lock, None).unwrap();
    let mut rig = Rig::with(versions);
    rig.cli.post(&["rollback", "2"], b"");
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::BAD_REQUEST, "{answers:?}");
    assert!(answers[0].1.starts_with("version 2: "), "{answers:?}");
    assert!(answers[0].1.contains("ruster.toml is kept"), "{answers:?}");
    assert_eq!(rig.apply.versions().latest().unwrap().number, 3);
}

#[test]
fn a_diff_shows_the_changes_and_sends_nothing() {
    let mut rig = Rig::new();
    rig.cli.post(&["diff"], text(1400).as_bytes());
    let answers = rig.answers();
    assert_eq!(answers.len(), 1, "{answers:?}");
    assert_eq!(answers[0].0, Code::CONTENT, "{answers:?}");
    let said = &answers[0].1;
    assert!(said.contains("--- version 1\n+++ new\n"), "{said}");
    assert!(said.contains("\n-mtu = 1500\n+mtu = 1400\n"), "{said}");
    assert!(
        said.contains(
            "- interface lan up mac 02:00:00:00:00:01 mtu 1500 vrf default\n\
             + interface lan up mac 02:00:00:00:00:01 mtu 1400 vrf default\n"
        ),
        "{said}"
    );
    assert!(
        said.contains("routes offered to ribd:\nno change\n"),
        "{said}"
    );
    // Nothing was sent or kept.
    assert_eq!(rig.mtu(), Some(1500));
    assert_eq!(rig.apply.versions().list().len(), 1);

    // The configuration in use has no change; a file with an error has no diff.
    rig.cli.post(&["diff"], text(1500).as_bytes());
    rig.cli.post(&["diff"], b"[[interface]]\n");
    let answers = rig.answers();
    assert_eq!(answers[0].1.matches("no change").count(), 3, "{answers:?}");
    assert_eq!(answers[1].0, Code::BAD_REQUEST, "{answers:?}");

    // While a change waits for answers, the version is not what is in use.
    let _silent = std::mem::take(&mut rig.fe);
    rig.cli.post(&["config"], text(1300).as_bytes());
    rig.cli.post(&["diff"], text(1400).as_bytes());
    let answers = rig.answers();
    assert_eq!(answers.len(), 1, "{answers:?}");
    assert_eq!(answers[0].0, Code::SERVICE_UNAVAILABLE, "{answers:?}");
}

const MINUTE_MS: u64 = 60_000;

/// Applies `text(mtu)` to wait `minutes` for `ruster confirm`, and returns the answer.
fn apply_to_confirm(rig: &mut Rig, mtu: u16, minutes: &str) -> (Code, String) {
    rig.cli
        .post(&["config", "confirm-within", minutes], text(mtu).as_bytes());
    let mut answers = rig.answers();
    assert_eq!(answers.len(), 1, "{answers:?}");
    answers.remove(0)
}

#[test]
fn a_confirmed_version_stays() {
    let mut rig = Rig::new();
    let (code, said) = apply_to_confirm(&mut rig, 1400, "10");
    assert_eq!(code, Code::CHANGED, "{said}");
    assert!(
        said.contains("kept as version 2 (apply); it goes back to version 1 at "),
        "{said}"
    );
    assert!(
        said.contains(" UTC unless `ruster confirm` comes first\n"),
        "{said}"
    );
    assert_eq!(rig.mtu(), Some(1400));
    let waiting = rig.apply.waiting().unwrap();
    assert_eq!(
        (waiting.version, waiting.back_to, waiting.minutes),
        (2, 1, 10)
    );

    // Meanwhile nothing else is applied; a diff is still shown, and the list says so.
    rig.cli.post(&["config"], text(1300).as_bytes());
    rig.cli.post(&["rollback", "1"], b"");
    rig.cli.post(&["diff"], text(1300).as_bytes());
    rig.cli.get(&["versions"]);
    let answers = rig.answers();
    for answer in &answers[..2] {
        assert_eq!(answer.0, Code::SERVICE_UNAVAILABLE, "{answers:?}");
        assert!(
            answer.1.contains("version 2 waits for `ruster confirm`"),
            "{answers:?}"
        );
    }
    assert_eq!(answers[2].0, Code::CONTENT, "{answers:?}");
    assert!(
        answers[3]
            .1
            .lines()
            .next()
            .unwrap()
            .contains("goes back to version 1 at"),
        "{answers:?}"
    );

    rig.cli.post(&["confirm"], b"");
    let answers = rig.answers();
    assert_eq!(
        answers[0],
        (Code::CHANGED, "version 2 confirmed".to_owned())
    );
    assert!(rig.apply.waiting().is_none());
    // Long after, it stays.
    rig.now_ms = 11 * MINUTE_MS;
    rig.answers();
    assert_eq!(rig.mtu(), Some(1400));
    rig.cli.post(&["confirm"], b"");
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::BAD_REQUEST, "{answers:?}");
    assert!(answers[0].1.contains("nothing waits"), "{answers:?}");
}

#[test]
fn a_version_not_confirmed_in_time_goes_back_as_a_new_version() {
    let mut rig = Rig::new();
    apply_to_confirm(&mut rig, 1400, "1");
    rig.now_ms = MINUTE_MS - 1;
    rig.answers();
    assert_eq!(rig.mtu(), Some(1400), "not yet");
    rig.now_ms = MINUTE_MS;
    assert!(rig.answers().is_empty(), "no one is answered");
    assert_eq!(rig.mtu(), Some(1500));
    let latest = rig.apply.versions().latest().unwrap();
    assert_eq!(latest.number, 3);
    assert_eq!(latest.how, "back to 1: version 2 was not confirmed");
    assert_eq!(latest.lock, rig.apply.versions().get(1).unwrap().lock);
    assert!(rig.apply.waiting().is_none());
    // A confirm comes too late; the next file goes through.
    rig.cli.post(&["confirm"], b"");
    rig.cli.post(&["config"], text(1300).as_bytes());
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::BAD_REQUEST, "{answers:?}");
    assert_eq!(answers[1].0, Code::CHANGED, "{answers:?}");
}

#[test]
fn a_refused_going_back_is_tried_again() {
    let mut rig = Rig::new();
    apply_to_confirm(&mut rig, 1400, "1");
    rig.check.refuse_mtu = Some(1500);
    rig.now_ms = MINUTE_MS;
    rig.answers();
    assert_eq!(rig.mtu(), Some(1400), "the FE refused going back");
    assert_eq!(rig.apply.waiting().unwrap().version, 2, "it still waits");
    let log = rig.apply.take_log().join("\n");
    assert!(log.contains("going back was refused"), "{log}");
    rig.check.refuse_mtu = None;
    rig.now_ms = MINUTE_MS + 60_000;
    rig.answers();
    assert_eq!(rig.mtu(), Some(1500));
    assert!(rig.apply.waiting().is_none());
}

#[test]
fn a_process_that_never_answers_does_not_stop_going_back() {
    let mut rig = Rig::new();
    // The FE stops reading, its socket still open: the confirmed apply times out,
    // and confd gives up waiting and keeps it.
    let _silent = std::mem::take(&mut rig.fe);
    rig.cli
        .post(&["config", "confirm-within", "1"], text(1400).as_bytes());
    assert!(rig.answers().is_empty());
    rig.now_ms = ANSWER_WAIT_MS;
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::GATEWAY_TIMEOUT, "{answers:?}");
    assert!(
        answers[0].1.contains("waits 1 min for `ruster confirm`"),
        "{answers:?}"
    );
    rig.now_ms = GIVE_UP_MS;
    rig.answers();
    assert_eq!(rig.apply.waiting().unwrap().version, 2);

    // At the deadline confd goes back all the same, and gives up waiting for the FE.
    rig.now_ms = GIVE_UP_MS + MINUTE_MS;
    rig.answers();
    assert_eq!(rig.confd.config().interfaces[0].mtu, 1500);
    rig.now_ms += GIVE_UP_MS;
    rig.answers();
    assert!(rig.apply.waiting().is_none());
    let latest = rig.apply.versions().latest().unwrap();
    assert_eq!(latest.how, "back to 1: version 2 was not confirmed");
}

#[test]
fn a_confirm_that_comes_while_going_back_is_refused() {
    // RFC 6241 section 8.4: once the timeout has passed, the configuration goes
    // back; a confirming commit that comes after is too late. Here the FE does not
    // answer, so going back is still under way when `confirm` comes.
    let mut rig = Rig::new();
    apply_to_confirm(&mut rig, 1400, "1");
    let _silent = std::mem::take(&mut rig.fe);
    rig.now_ms = MINUTE_MS;
    rig.answers();
    rig.cli.post(&["confirm"], b"");
    let answers = rig.answers();
    assert_eq!(answers[0].0, Code::SERVICE_UNAVAILABLE, "{answers:?}");
    assert!(answers[0].1.contains("too late"), "{answers:?}");
    assert_eq!(rig.confd.config().interfaces[0].mtu, 1500);
}

#[test]
fn a_deadline_beyond_the_wait_given_goes_back_at_once() {
    let dir = state_dir("confirm-clock");
    let mut rig = Rig::with(Versions::open(&dir).unwrap());
    apply_to_confirm(&mut rig, 1400, "5");
    drop(rig);
    // As if the clock had gone back an hour before confd started again.
    let mut versions = Versions::open(&dir).unwrap();
    let mut waiting = versions.waiting().unwrap();
    waiting.deadline += 3_600;
    versions.set_waiting(Some(waiting)).unwrap();

    let mut rig = Rig::with(Versions::open(&dir).unwrap());
    rig.answers();
    assert_eq!(rig.mtu(), Some(1500));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_refused_or_bad_confirmed_apply_does_not_wait() {
    let mut rig = Rig::new();
    for minutes in ["0", "x", "1441", "+1"] {
        let (code, said) = apply_to_confirm(&mut rig, 1400, minutes);
        assert_eq!(code, Code::BAD_REQUEST, "{minutes}: {said}");
        assert!(said.contains("minutes from 1 to 1440"), "{said}");
    }
    rig.check.refuse_mtu = Some(1400);
    let (code, _) = apply_to_confirm(&mut rig, 1400, "1");
    assert_eq!(code, Code::BAD_REQUEST);
    assert!(rig.apply.waiting().is_none());
    assert_eq!(rig.apply.versions().latest().unwrap().number, 1);
}

#[test]
fn confd_started_again_in_the_window_still_goes_back() {
    let dir = state_dir("confirm-restart");
    let mut rig = Rig::with(Versions::open(&dir).unwrap());
    apply_to_confirm(&mut rig, 1400, "1");
    drop(rig);

    // confd started again: it runs version 2 and keeps counting.
    let versions = Versions::open(&dir).unwrap();
    let waiting = versions.waiting().unwrap();
    assert_eq!((waiting.version, waiting.back_to), (2, 1));
    let mut rig = Rig::with(versions);
    assert_eq!(rig.mtu(), Some(1400));
    let log = rig.apply.take_log().join("\n");
    assert!(
        log.contains("version 2 waits for `ruster confirm`"),
        "{log}"
    );
    rig.now_ms = MINUTE_MS + 1_000;
    rig.answers();
    assert_eq!(rig.mtu(), Some(1500));
    drop(rig);

    // Started again after that, it runs the version put back, and nothing waits.
    let versions = Versions::open(&dir).unwrap();
    assert!(versions.waiting().is_none());
    assert_eq!(versions.latest().unwrap().number, 3);
    assert!(!dir.join("versions/confirm.toml").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn confd_started_again_after_the_deadline_goes_back_at_once() {
    let dir = state_dir("confirm-late");
    let mut rig = Rig::with(Versions::open(&dir).unwrap());
    apply_to_confirm(&mut rig, 1400, "5");
    drop(rig);
    // As if confd had been down past the deadline.
    let mut versions = Versions::open(&dir).unwrap();
    let mut waiting = versions.waiting().unwrap();
    waiting.deadline -= 10 * 60;
    versions.set_waiting(Some(waiting)).unwrap();

    let mut rig = Rig::with(Versions::open(&dir).unwrap());
    rig.answers();
    assert_eq!(rig.mtu(), Some(1500));
    assert_eq!(rig.apply.versions().latest().unwrap().number, 3);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_deadline_that_cannot_be_written_goes_back_at_once() {
    let dir = state_dir("confirm-unwritable");
    let mut rig = Rig::with(Versions::open(&dir).unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
    let (code, said) = apply_to_confirm(&mut rig, 1400, "10");
    assert_eq!(code, Code::INTERNAL_SERVER_ERROR, "{said}");
    assert!(said.contains("going back to version 1 now"), "{said}");
    rig.answers();
    assert_eq!(rig.mtu(), Some(1500));
    assert!(rig.apply.waiting().is_none());
}
