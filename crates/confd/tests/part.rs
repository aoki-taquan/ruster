//! Processes taking their part of the configuration, with `ruster apply`.

use std::os::unix::net::UnixStream;

use ruster_confd::apply::Apply;
use ruster_confd::part::{Asked, Client, Module};
use ruster_confd::{file, Confd};
use ruster_proto::coap::Code;
use ruster_proto::session::{self, Event, Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::task::Task;

struct Accept;

impl Hook for Accept {
    fn check(&mut self, _next: &Store) -> Result<(), String> {
        Ok(())
    }
    fn committed(&mut self, _store: &Store) {}
}

fn text(mtu: u16, upstream: &str) -> String {
    format!(
        "[[interface]]\nname = \"lan\"\nmac = \"02:00:00:00:00:01\"\nmtu = {mtu}\nipv4 = \"192.0.2.1/24\"\n\n[dns]\nlisten = [\"lan\"]\nupstream = [\"{upstream}\"]\n"
    )
}

/// A process for `dns` that refuses parts with `refuse` in them; with
/// `check_passes`, only when it takes them, not when it checks them.
struct Process {
    client: Client,
    refuse: Option<&'static str>,
    check_passes: bool,
    taken: Vec<String>,
}

impl Process {
    fn new(rig: &mut Rig) -> Self {
        let (a, b) = UnixStream::pair().unwrap();
        rig.confd.attach_part(Module::Dns, a).unwrap();
        Self {
            client: Client::new(b, Module::Dns).unwrap(),
            refuse: None,
            check_passes: false,
            taken: Vec::new(),
        }
    }

    fn poll(&mut self) -> bool {
        let refuse = self.refuse;
        let check_passes = self.check_passes;
        let taken = &mut self.taken;
        self.client
            .poll(&mut |asked| match (asked, refuse) {
                (Asked::Take(part), Some(word)) if part.contains(word) => {
                    Err(format!("{word} refused"))
                }
                (Asked::Check(part), Some(word)) if part.contains(word) && !check_passes => {
                    Err(format!("{word} refused"))
                }
                (Asked::Check(part), _) => Ok(format!("would take {} lines", part.lines().count())),
                (Asked::Take(part), _) => {
                    taken.push(part.to_owned());
                    Ok(String::new())
                }
            })
            .unwrap()
            .busy
    }
}

struct Rig {
    fe: Server,
    confd: Confd,
    apply: Apply,
    cli: session::Client,
}

impl Rig {
    fn new() -> Self {
        let mut fe = Server::new();
        let mut confd = Confd::new(file::parse(&text(1500, "192.0.2.53")).unwrap());
        let (a, b) = UnixStream::pair().unwrap();
        fe.attach(a, &[sid::INTERFACE, sid::ADDRESS, sid::ICMP_ERRORS])
            .unwrap();
        confd.connect_fe(b).unwrap();
        let mut apply = Apply::new(ruster_confd::versions::Versions::in_memory());
        let (a, b) = UnixStream::pair().unwrap();
        apply.attach(a).unwrap();
        Self {
            fe,
            confd,
            apply,
            cli: session::Client::new(b).unwrap(),
        }
    }

    /// Runs everything until it is quiet and returns the CLI's answers.
    fn run(&mut self, processes: &mut [&mut Process]) -> Vec<(Code, String)> {
        let mut out = Vec::new();
        let mut quiet = 0;
        for _ in 0..1_000 {
            let mut busy = self.fe.step(&mut Accept).busy
                | self.confd.step(0).busy
                | self
                    .apply
                    .step(&mut self.confd, 0, &mut |_| Vec::new())
                    .busy;
            for process in processes.iter_mut() {
                busy |= process.poll();
            }
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
}

fn upstream(part: &str) -> Vec<String> {
    ruster_config::parse_dns_part(part)
        .unwrap()
        .unwrap()
        .upstream
}

#[test]
fn a_process_takes_its_part_and_each_change_to_it() {
    let mut rig = Rig::new();
    let mut dns = Process::new(&mut rig);
    rig.run(&mut [&mut dns]);
    assert!(dns.client.named());
    assert_eq!(dns.taken.len(), 1);
    assert_eq!(upstream(&dns.taken[0]), ["192.0.2.53"]);
    assert!(!dns.taken[0].contains("interface"), "only its own module");

    // A change elsewhere is not put again; a change to dns is.
    rig.cli
        .post(&["config"], text(1400, "192.0.2.53").as_bytes());
    assert_eq!(rig.run(&mut [&mut dns])[0].0, Code::CHANGED);
    assert_eq!(dns.taken.len(), 1);
    rig.cli
        .post(&["config"], text(1400, "192.0.2.54").as_bytes());
    assert_eq!(rig.run(&mut [&mut dns])[0].0, Code::CHANGED);
    assert_eq!(dns.taken.len(), 2);
    assert_eq!(upstream(&dns.taken[1]), ["192.0.2.54"]);
}

#[test]
fn a_refused_part_puts_the_configuration_before_back() {
    let mut rig = Rig::new();
    let mut dns = Process::new(&mut rig);
    rig.run(&mut [&mut dns]);
    // The check passes; the software behind the process refuses it when it is taken.
    dns.refuse = Some("192.0.2.99");
    dns.check_passes = true;
    rig.cli
        .post(&["config"], text(1400, "192.0.2.99").as_bytes());
    let answers = rig.run(&mut [&mut dns]);
    assert_eq!(answers[0].0, Code::BAD_REQUEST, "{answers:?}");
    assert!(
        answers[0]
            .1
            .contains("the process for dns refused it: 192.0.2.99 refused"),
        "{answers:?}"
    );
    assert_eq!(rig.confd.config().interfaces[0].mtu, 1500, "the FE too");
    assert_eq!(dns.taken.len(), 1, "it keeps the part it had");

    rig.cli
        .post(&["config"], text(1400, "192.0.2.54").as_bytes());
    assert_eq!(rig.run(&mut [&mut dns])[0].0, Code::CHANGED);
    assert_eq!(upstream(dns.taken.last().unwrap()), ["192.0.2.54"]);
}

#[test]
fn a_process_that_is_not_connected_is_named_in_the_answer() {
    let mut rig = Rig::new();
    rig.run(&mut []);
    rig.cli
        .post(&["config"], text(1400, "192.0.2.54").as_bytes());
    let answers = rig.run(&mut []);
    assert_eq!(answers[0].0, Code::CHANGED);
    assert!(
        answers[0]
            .1
            .contains("the process for dns is not connected"),
        "{answers:?}"
    );
}

#[test]
fn a_process_that_starts_again_replaces_the_old_one() {
    let mut rig = Rig::new();
    let mut old = Process::new(&mut rig);
    rig.run(&mut [&mut old]);
    let mut new = Process::new(&mut rig);
    rig.run(&mut [&mut old, &mut new]);
    assert_eq!(new.taken.len(), 1, "the new one gets the part at once");
    assert!(old.client.is_closed());
    rig.cli
        .post(&["config"], text(1500, "192.0.2.54").as_bytes());
    assert_eq!(rig.run(&mut [&mut new])[0].0, Code::CHANGED);
    assert_eq!(new.taken.len(), 2);
}

/// The answer to naming `name` on `socket`'s socket.
fn name_on(rig: &mut Rig, socket: Module, name: &str) -> Option<Code> {
    let (a, b) = UnixStream::pair().unwrap();
    rig.confd.attach_part(socket, a).unwrap();
    let mut conn = ruster_proto::conn::Connection::new(b, 1 << 20).unwrap();
    conn.send(&ruster_proto::conn::Outgoing {
        code: Some(Code::POST),
        token: &[1],
        path: &[name],
        ..Default::default()
    })
    .unwrap();
    for _ in 0..100 {
        rig.confd.step(0);
        conn.pump().unwrap();
        if let Ok(Some(message)) = conn.next_message() {
            return Some(message.code);
        }
    }
    None
}

#[test]
fn an_unknown_module_is_refused() {
    let mut rig = Rig::new();
    assert_eq!(name_on(&mut rig, Module::Dns, "kea"), Some(Code::NOT_FOUND));
}

#[test]
fn a_socket_hands_out_only_its_own_module() {
    let mut rig = Rig::new();
    // A process that may open only the dns socket cannot take the PPPoE passwords.
    assert_eq!(
        name_on(&mut rig, Module::Dns, "pppoe"),
        Some(Code::NOT_FOUND)
    );
    assert_eq!(
        name_on(&mut rig, Module::Pppoe, "pppoe"),
        Some(Code::CHANGED)
    );
}

#[test]
fn connections_waiting_on_one_socket_do_not_keep_the_others_out() {
    let mut rig = Rig::new();
    let mut held = Vec::new();
    for _ in 0..ruster_confd::part::MAX_UNNAMED {
        let (a, b) = UnixStream::pair().unwrap();
        rig.confd.attach_part(Module::Dns, a).unwrap();
        held.push(b);
    }
    let (a, _b) = UnixStream::pair().unwrap();
    assert!(rig.confd.attach_part(Module::Dns, a).is_err());
    assert_eq!(
        name_on(&mut rig, Module::Pppoe, "pppoe"),
        Some(Code::CHANGED)
    );
}

#[test]
fn a_check_gets_each_process_answer_without_taking_the_part() {
    use ruster_confd::part::Checked;
    let mut rig = Rig::new();
    let mut dns = Process::new(&mut rig);
    rig.run(&mut [&mut dns]);
    let candidate = file::parse(&text(1500, "192.0.2.54")).unwrap();
    rig.confd.check_parts(&candidate);
    assert_eq!(
        rig.confd.part_checks().get(&Module::Dns),
        Some(&Checked::NoAnswer)
    );
    rig.run(&mut [&mut dns]);
    let Some(Checked::Changes(said)) = rig.confd.part_checks().get(&Module::Dns) else {
        panic!("{:?}", rig.confd.part_checks());
    };
    assert!(said.starts_with("would take"), "{said}");
    assert_eq!(dns.taken.len(), 1, "a check takes nothing");
    assert_eq!(upstream(&dns.taken[0]), ["192.0.2.53"]);
    // Only modules a process takes, or the candidate has, are named.
    assert_eq!(rig.confd.part_checks().len(), 1);

    dns.refuse = Some("192.0.2.99");
    rig.confd
        .check_parts(&file::parse(&text(1500, "192.0.2.99")).unwrap());
    rig.run(&mut [&mut dns]);
    assert_eq!(
        rig.confd.part_checks().get(&Module::Dns),
        Some(&Checked::Refused("192.0.2.99 refused".into()))
    );
    assert_eq!(dns.taken.len(), 1);
}

#[test]
fn a_check_names_the_modules_no_process_takes() {
    use ruster_confd::part::Checked;
    let mut rig = Rig::new();
    rig.run(&mut []);
    rig.confd
        .check_parts(&file::parse(&text(1500, "192.0.2.54")).unwrap());
    assert_eq!(
        rig.confd.part_checks().get(&Module::Dns),
        Some(&Checked::NotConnected)
    );

    // A process that goes away before it answers is not connected either.
    let mut dns = Process::new(&mut rig);
    rig.run(&mut [&mut dns]);
    rig.confd
        .check_parts(&file::parse(&text(1500, "192.0.2.55")).unwrap());
    drop(dns);
    rig.run(&mut []);
    assert_eq!(
        rig.confd.part_checks().get(&Module::Dns),
        Some(&Checked::NotConnected)
    );
}

#[test]
fn changes_names_the_entries_that_start_change_and_stop() {
    let part = |entries: &[(&str, u32)]| {
        entries
            .iter()
            .map(|(k, v)| format!("{k} = {v}\n"))
            .collect::<String>()
    };
    let before = [("a", 1), ("b", 2)];
    let after = [("b", 3), ("c", 4)];
    let text = ruster_confd::part::changes(
        &before,
        &after,
        |e| e.0,
        |entries| part(entries),
        ["starts", "changes", "stops"],
    );
    assert!(text.contains("-a = 1\n"), "{text}");
    assert!(text.contains("+b = 3\n"), "{text}");
    assert!(
        text.ends_with("b: changes\nc: starts\na: stops\n"),
        "{text}"
    );
    assert_eq!(
        ruster_confd::part::changes(&before, &before, |e| e.0, |e| part(e), ["", "", ""]),
        ""
    );
}

#[test]
fn a_long_check_answer_is_cut_to_fit() {
    use ruster_confd::part::Checked;
    let (a, b) = UnixStream::pair().unwrap();
    let mut confd = Confd::new(file::parse(&text(1500, "192.0.2.53")).unwrap());
    confd.attach_part(Module::Dns, a).unwrap();
    let mut client = Client::new(b, Module::Dns).unwrap();
    let mut answer = |asked: Asked<'_>| match asked {
        Asked::Check(_) => Ok("x".repeat(2 << 20)),
        Asked::Take(_) => Ok(String::new()),
    };
    for _ in 0..50 {
        confd.step(0);
        client.poll(&mut answer).unwrap();
    }
    confd.check_parts(&file::parse(&text(1500, "192.0.2.54")).unwrap());
    for _ in 0..200 {
        confd.step(0);
        client.poll(&mut answer).unwrap();
    }
    let Some(Checked::Changes(said)) = confd.part_checks().get(&Module::Dns) else {
        panic!("{:?}", confd.part_checks().get(&Module::Dns));
    };
    assert!(said.ends_with(" more bytes)\n"), "cut");
    assert!(!client.is_closed());
}

#[test]
fn a_candidate_a_process_refuses_is_not_sent_to_anyone() {
    let mut rig = Rig::new();
    let mut dns = Process::new(&mut rig);
    rig.run(&mut [&mut dns]);
    dns.refuse = Some("192.0.2.99");
    rig.cli
        .post(&["config"], text(1400, "192.0.2.99").as_bytes());
    let answers = rig.run(&mut [&mut dns]);
    assert_eq!(answers[0].0, Code::BAD_REQUEST, "{answers:?}");
    assert_eq!(
        answers[0].1,
        "ruster-unbound (dns) refuses it: 192.0.2.99 refused\n\
         nothing was sent; the configuration in use stays"
    );
    assert_eq!(dns.taken.len(), 1, "nothing was put");
    assert_eq!(
        rig.confd.config().interfaces[0].mtu,
        1500,
        "nor sent to the FE"
    );
    assert!(rig.apply.versions().list().is_empty(), "nor kept");
}

#[test]
fn a_diff_shows_what_each_process_would_change() {
    let mut rig = Rig::new();
    let mut dns = Process::new(&mut rig);
    rig.run(&mut [&mut dns]);
    rig.cli.post(&["diff"], text(1500, "192.0.2.54").as_bytes());
    dns.refuse = Some("192.0.2.99");
    rig.cli.post(&["diff"], text(1500, "192.0.2.99").as_bytes());
    let answers = rig.run(&mut [&mut dns]);
    assert_eq!(answers.len(), 2, "{answers:?}");
    assert_eq!(answers[0].0, Code::CONTENT);
    assert!(
        answers[0]
            .1
            .contains("\nruster-unbound (dns):\nwould take "),
        "{answers:?}"
    );
    assert!(
        answers[1]
            .1
            .contains("ruster-unbound (dns):\nrefuses it: 192.0.2.99 refused\n"),
        "{answers:?}"
    );
    assert_eq!(dns.taken.len(), 1);

    // Without the process, the diff says so.
    drop(dns);
    rig.run(&mut []);
    rig.cli.post(&["diff"], text(1500, "192.0.2.54").as_bytes());
    let answers = rig.run(&mut []);
    assert!(
        answers[0].1.contains(
            "ruster-unbound (dns):\nnot connected; it gets the configuration when it connects\n"
        ),
        "{answers:?}"
    );
}

#[test]
fn a_process_that_does_not_answer_the_check_does_not_hold_the_change_up() {
    use ruster_proto::conn::{Connection, Outgoing};
    let mut rig = Rig::new();
    let (a, b) = UnixStream::pair().unwrap();
    rig.confd.attach_part(Module::Dns, a).unwrap();
    let mut conn = Connection::new(b, 1 << 20).unwrap();
    conn.send(&Outgoing {
        code: Some(Code::POST),
        token: &[0],
        path: &["dns"],
        ..Default::default()
    })
    .unwrap();
    // Takes each part, and never answers a check.
    let silent = |conn: &mut Connection| {
        conn.pump().unwrap();
        while let Ok(Some(message)) = conn.next_message() {
            if message.code == Code::PUT {
                conn.send(&Outgoing {
                    code: Some(Code::CHANGED),
                    token: &message.token,
                    ..Default::default()
                })
                .unwrap();
            }
        }
        conn.pump().unwrap();
    };
    let mut answers = Vec::new();
    for _ in 0..20 {
        rig.fe.step(&mut Accept);
        rig.confd.step(0);
        silent(&mut conn);
    }
    rig.cli
        .post(&["config"], text(1400, "192.0.2.54").as_bytes());
    for now in [0, 0, 0, 0, 0, ruster_confd::apply::ANSWER_WAIT_MS]
        .into_iter()
        .chain(std::iter::repeat_n(ruster_confd::apply::ANSWER_WAIT_MS, 50))
    {
        rig.fe.step(&mut Accept);
        rig.confd.step(now);
        rig.apply.step(&mut rig.confd, now, &mut |_| Vec::new());
        silent(&mut conn);
        let (_, events) = rig.cli.poll();
        for event in events {
            if let Event::Response { code, payload, .. } = event {
                answers.push((code, String::from_utf8(payload).unwrap()));
            }
        }
    }
    assert_eq!(answers.len(), 1, "{answers:?}");
    assert_eq!(answers[0].0, Code::CHANGED, "{answers:?}");
    assert!(
        answers[0]
            .1
            .starts_with("ruster-unbound (dns) did not answer the check in time\n"),
        "{answers:?}"
    );
    assert_eq!(rig.confd.config().interfaces[0].mtu, 1400);
}

#[test]
fn a_part_that_does_not_change_is_not_checked() {
    use ruster_confd::part::Checked;
    let mut rig = Rig::new();
    let mut dns = Process::new(&mut rig);
    rig.run(&mut [&mut dns]);
    // It would refuse even the part it holds; an unrelated change still goes in.
    dns.refuse = Some("192.0.2.53");
    dns.check_passes = false;
    rig.cli
        .post(&["config"], text(1400, "192.0.2.53").as_bytes());
    let answers = rig.run(&mut [&mut dns]);
    assert_eq!(answers[0].0, Code::CHANGED, "{answers:?}");
    assert_eq!(rig.confd.config().interfaces[0].mtu, 1400);
    assert_eq!(
        rig.confd.part_checks().get(&Module::Dns),
        Some(&Checked::Changes(String::new()))
    );
}
