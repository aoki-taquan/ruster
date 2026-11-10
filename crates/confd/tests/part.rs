//! Processes taking their part of the configuration, with `ruster apply`.

use std::os::unix::net::UnixStream;

use ruster_confd::apply::Apply;
use ruster_confd::part::{Client, Module};
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

/// A process for `dns` that refuses parts with `refuse` in them.
struct Process {
    client: Client,
    refuse: Option<&'static str>,
    taken: Vec<String>,
}

impl Process {
    fn new(rig: &mut Rig) -> Self {
        let (a, b) = UnixStream::pair().unwrap();
        rig.confd.attach_part(Module::Dns, a).unwrap();
        Self {
            client: Client::new(b, Module::Dns).unwrap(),
            refuse: None,
            taken: Vec::new(),
        }
    }

    fn poll(&mut self) -> bool {
        let refuse = self.refuse;
        let taken = &mut self.taken;
        self.client
            .poll(&mut |part| match refuse {
                Some(word) if part.contains(word) => Err(format!("{word} refused")),
                _ => {
                    taken.push(part.to_owned());
                    Ok(())
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
    dns.refuse = Some("192.0.2.99");
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
