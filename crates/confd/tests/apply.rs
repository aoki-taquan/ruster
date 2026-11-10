//! `ruster apply` against confd and a stand-in FE.

use std::os::unix::net::UnixStream;

use ruster_confd::apply::{Apply, ANSWER_WAIT_MS, GIVE_UP_MS};
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
        let mut fe = Server::new();
        let mut confd = Confd::new(file::parse(&text(1500)).unwrap());
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, &[sid::INTERFACE, sid::ADDRESS, sid::ICMP_ERRORS])
            .unwrap();
        confd.connect_fe(b).unwrap();
        let mut apply = Apply::new();
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
        assert_eq!(rig.mtu(), Some(1500));
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
