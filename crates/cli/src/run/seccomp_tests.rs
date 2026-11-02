//! Tests of the seccomp filter: the assembled program on a classic BPF
//! interpreter (synthetic `seccomp_data`), and the live filter in child
//! processes of this test binary.

use super::*;

/// `AUDIT_ARCH_I386`.
const AUDIT_ARCH_I386: u32 = 0x4000_0003;
const PID: u32 = 4242;
/// Size of `struct seccomp_data`.
const DATA_LEN: usize = 64;

/// A `struct seccomp_data` (little endian).
fn data(arch: u32, nr: u32, args: [u64; 6]) -> [u8; DATA_LEN] {
    let mut out = [0_u8; DATA_LEN];
    out[0..4].copy_from_slice(&nr.to_le_bytes());
    out[4..8].copy_from_slice(&arch.to_le_bytes());
    out[8..16].copy_from_slice(&0x7f00_dead_beef_u64.to_le_bytes());
    for (index, arg) in args.iter().enumerate() {
        let at = 16 + 8 * index;
        out[at..at + 8].copy_from_slice(&arg.to_le_bytes());
    }
    out
}

/// The kernel's static checks of a seccomp program, restricted to the
/// instructions [`program`] emits: known opcodes, aligned in-bounds loads
/// of `seccomp_data`, forward jumps inside the program, a return last.
fn validate(program: &[SockFilter]) {
    assert!(!program.is_empty() && program.len() <= MAX_INSNS);
    for (at, insn) in program.iter().enumerate() {
        match insn.code {
            LD_W_ABS => {
                let k = insn.k as usize;
                assert!(k.is_multiple_of(4) && k + 4 <= DATA_LEN, "load {k} at {at}");
            }
            JEQ_K | JSET_K => {
                let last = at + 1 + usize::from(insn.jt.max(insn.jf));
                assert!(last < program.len(), "jump out of the program at {at}");
            }
            RET_K => {}
            other => panic!("opcode {other:#x} at {at}"),
        }
    }
    assert_eq!(program.last().map(|insn| insn.code), Some(RET_K));
}

/// Runs a classic BPF program over `data` and returns its action.
fn interpret(program: &[SockFilter], data: &[u8; DATA_LEN]) -> u32 {
    let mut pc = 0_usize;
    let mut accumulator = 0_u32;
    loop {
        let insn = program[pc];
        pc += 1;
        match insn.code {
            LD_W_ABS => {
                let k = insn.k as usize;
                accumulator = u32::from_le_bytes(data[k..k + 4].try_into().unwrap());
            }
            JEQ_K => {
                pc += usize::from(if accumulator == insn.k {
                    insn.jt
                } else {
                    insn.jf
                });
            }
            JSET_K => {
                pc += usize::from(if accumulator & insn.k != 0 {
                    insn.jt
                } else {
                    insn.jf
                });
            }
            RET_K => return insn.k,
            other => panic!("opcode {other:#x}"),
        }
    }
}

struct Filter {
    program: Vec<SockFilter>,
    violation: u32,
}

impl Filter {
    fn new(mode: SeccompMode) -> Self {
        let violation = violation(mode).expect("an action");
        let program = program(ALLOWLIST, violation, PID).expect("assembles");
        validate(&program);
        Self { program, violation }
    }

    fn eval(&self, nr: u32, args: [u64; 6]) -> u32 {
        interpret(&self.program, &data(AUDIT_ARCH_X86_64, nr, args))
    }

    fn allows(&self, nr: u32, args: [u64; 6]) -> bool {
        match self.eval(nr, args) {
            RET_ALLOW => true,
            action => {
                assert_eq!(action, self.violation, "nr {nr} {args:?}");
                false
            }
        }
    }
}

fn rule(name: &str) -> Rule {
    *ALLOWLIST
        .iter()
        .find(|rule| rule.name == name)
        .unwrap_or_else(|| panic!("{name} not allowed"))
}

#[test]
fn the_program_is_valid_classic_bpf_and_small() {
    for mode in [SeccompMode::Kill, SeccompMode::Log] {
        let filter = Filter::new(mode);
        // Header (6), one instruction per unconditional rule, a block per
        // conditional rule, the default action and the shared allow.
        assert!(filter.program.len() < 120, "{}", filter.program.len());
    }
    assert_eq!(violation(SeccompMode::Kill), Some(RET_KILL_PROCESS));
    assert_eq!(violation(SeccompMode::Log), Some(RET_LOG));
    assert_eq!(violation(SeccompMode::Off), None);
    assert_eq!(allowed_syscalls() as usize, ALLOWLIST.len());
}

#[test]
fn every_rule_is_listed_once_and_matches_the_kernel_numbers() {
    let mut numbers: Vec<u32> = ALLOWLIST.iter().map(|rule| rule.nr).collect();
    numbers.sort_unstable();
    numbers.dedup();
    assert_eq!(numbers.len(), ALLOWLIST.len(), "duplicate number");
    let mut names: Vec<&str> = ALLOWLIST.iter().map(|rule| rule.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), ALLOWLIST.len(), "duplicate name");
    // Cross-check with the kernel UAPI header where it is installed.
    let Ok(header) = std::fs::read_to_string("/usr/include/x86_64-linux-gnu/asm/unistd_64.h")
    else {
        return;
    };
    for rule in ALLOWLIST {
        let define = format!("#define __NR_{} {}", rule.name, rule.nr);
        assert!(
            header.lines().any(|line| line.trim() == define),
            "{define} not in unistd_64.h"
        );
    }
}

#[test]
fn the_arch_and_x32_checks_kill_in_every_mode() {
    for mode in [SeccompMode::Kill, SeccompMode::Log] {
        let filter = Filter::new(mode);
        let getpid = rule("getpid").nr;
        assert!(filter.allows(getpid, [0; 6]));
        // i386 `getpid` is 20; any number under a foreign arch is killed.
        for nr in [20, getpid, 0, 1] {
            assert_eq!(
                interpret(&filter.program, &data(AUDIT_ARCH_I386, nr, [0; 6])),
                RET_KILL_PROCESS
            );
            assert_eq!(
                interpret(&filter.program, &data(0, nr, [0; 6])),
                RET_KILL_PROCESS
            );
        }
        // x32: the allowed numbers with the x32 bit are killed.
        for rule in ALLOWLIST {
            assert_eq!(
                filter.eval(rule.nr | X32_SYSCALL_BIT, [0; 6]),
                RET_KILL_PROCESS,
                "x32 {}",
                rule.name
            );
        }
        assert_eq!(filter.eval(u32::MAX, [0; 6]), RET_KILL_PROCESS);
    }
}

#[test]
fn only_the_allowlist_runs_and_everything_else_gets_the_violation_action() {
    for mode in [SeccompMode::Kill, SeccompMode::Log] {
        let filter = Filter::new(mode);
        let args = [7, 0, 0, 0, 0, 0];
        for nr in 0..1024 {
            let listed = ALLOWLIST.iter().find(|rule| rule.nr == nr);
            match listed {
                Some(rule) if rule.conditions.is_empty() => {
                    assert!(filter.allows(nr, args), "{}", rule.name);
                    assert!(filter.allows(nr, [u64::MAX; 6]), "{}", rule.name);
                }
                Some(_) => {}
                None => assert!(!filter.allows(nr, args), "nr {nr}"),
            }
        }
    }
    let filter = Filter::new(SeccompMode::Kill);
    // What a compromised router would reach for first.
    for (name, nr) in [
        ("open", 2),
        ("ioctl", 16),
        ("dup2", 33),
        ("socketpair", 53),
        ("clone", 56),
        ("fork", 57),
        ("vfork", 58),
        ("execve", 59),
        ("kill", 62),
        ("ptrace", 101),
        ("setuid", 105),
        ("setgid", 106),
        ("prctl", 157),
        ("mount", 165),
        ("bind", 49),
        ("listen", 50),
        ("accept", 43),
        ("sendmsg", 46),
        ("recvmsg", 47),
        ("unlink", 87),
        ("rename", 82),
        ("mkdir", 83),
        ("creat", 85),
        ("chmod", 90),
        ("chown", 92),
        ("process_vm_readv", 310),
        ("process_vm_writev", 311),
        ("seccomp", 317),
        ("memfd_create", 319),
        ("execveat", 322),
        ("userfaultfd", 323),
        ("io_uring_setup", 425),
        ("open_tree", 428),
        ("fsopen", 430),
        ("pidfd_open", 434),
        ("clone3", 435),
        ("openat2", 437),
        ("pidfd_getfd", 438),
        ("perf_event_open", 298),
        ("init_module", 175),
        ("finit_module", 313),
        ("unshare", 272),
        ("setns", 308),
        ("pwrite64", 18),
        ("writev", 20),
    ] {
        assert!(!filter.allows(nr, [0; 6]), "{name} allowed");
        assert!(!ALLOWLIST.iter().any(|rule| rule.name == name), "{name}");
    }
}

#[test]
fn the_argument_filters_hold_on_the_low_32_bits() {
    let filter = Filter::new(SeccompMode::Kill);
    let high = 1_u64 << 32;
    // socket: NETLINK_ROUTE only.
    let socket = rule("socket").nr;
    let raw_cloexec = 3 | 0o2_000_000;
    assert!(filter.allows(socket, [16, raw_cloexec, 0, 0, 0, 0]));
    // The kernel reads only the low 32 bits of an `int`.
    assert!(filter.allows(socket, [high | 16, raw_cloexec, high, 0, 0, 0]));
    for (domain, protocol) in [(2, 0), (10, 0), (17, 0), (1, 0), (16, 4), (16, 9), (16, 15)] {
        assert!(
            !filter.allows(socket, [domain, raw_cloexec, protocol, 0, 0, 0]),
            "socket({domain}, _, {protocol})"
        );
    }
    // setsockopt: NETLINK_GET_STRICT_CHK only.
    let setsockopt = rule("setsockopt").nr;
    assert!(filter.allows(setsockopt, [5, 270, 12, 0, 4, 0]));
    for (level, name) in [(270, 1), (270, 11), (1, 12), (283, 12), (283, 4), (0, 0)] {
        assert!(!filter.allows(setsockopt, [5, level, name, 0, 4, 0]));
    }
    // bpf: the XSKMAP entry delete only.
    let bpf = rule("bpf").nr;
    assert!(filter.allows(bpf, [3, 0, 0, 0, 0, 0]));
    for command in [0, 1, 2, 4, 5, 6, 7, 8, 28, 36, u64::from(u32::MAX)] {
        assert!(
            !filter.allows(bpf, [command, 0, 0, 0, 0, 0]),
            "bpf {command}"
        );
    }
    // mmap/mprotect: never executable.
    for name in ["mmap", "mprotect"] {
        let nr = rule(name).nr;
        for prot in [0, 1, 2, 3, 0x0100_0000 | 3] {
            assert!(filter.allows(nr, [0, 4096, prot, 0x22, u64::MAX, 0]));
        }
        for prot in [4, 5, 7, 6, 0x0100_0007] {
            assert!(
                !filter.allows(nr, [0, 4096, prot, 0x22, u64::MAX, 0]),
                "{name} {prot:#x}"
            );
        }
    }
    // openat: read-only, never create or truncate.
    let openat = rule("openat").nr;
    let cwd = u64::from(-100_i32 as u32);
    for flags in [
        0,
        0o2_000_000,
        0o2_000_000 | 0o200_000,
        0o4_000 | 0o400,
        0o2_000_000 | 0o4_000 | 0o400,
    ] {
        assert!(filter.allows(openat, [cwd, 0, flags, 0, 0, 0]), "{flags:o}");
    }
    for flags in [
        0o1,
        0o2,
        0o3,
        0o100,
        0o1_000,
        0o100 | 0o200,
        0o20_200_000 | 0o2,
        0o2_000_000 | 0o1 | 0o100 | 0o1_000,
    ] {
        assert!(
            !filter.allows(openat, [cwd, 0, flags, 0o644, 0, 0]),
            "{flags:o}"
        );
    }
    // fcntl: F_GETFD only.
    let fcntl = rule("fcntl").nr;
    assert!(filter.allows(fcntl, [3, 1, 0, 0, 0, 0]));
    for command in [0, 2, 3, 4, 1030, 1024] {
        assert!(
            !filter.allows(fcntl, [3, command, 0, 0, 0, 0]),
            "fcntl {command}"
        );
    }
    // tgkill: this process only.
    let tgkill = rule("tgkill").nr;
    assert!(filter.allows(tgkill, [u64::from(PID), 4243, 6, 0, 0, 0]));
    for pid in [1, 0, u64::from(PID) + 1, u64::from(u32::MAX)] {
        assert!(
            !filter.allows(tgkill, [pid, 4243, 6, 0, 0, 0]),
            "tgkill {pid}"
        );
    }
    // The log mode logs (and runs) the same calls.
    let log = Filter::new(SeccompMode::Log);
    assert_eq!(log.eval(socket, [2, 2, 0, 0, 0, 0]), RET_LOG);
    assert_eq!(log.eval(bpf, [5, 0, 0, 0, 0, 0]), RET_LOG);
    assert_eq!(log.eval(socket, [16, 3, 0, 0, 0, 0]), RET_ALLOW);
}

#[test]
fn a_program_whose_jumps_do_not_fit_is_refused() {
    static MANY: [Rule; 300] = {
        let mut rules = [Rule {
            name: "x",
            nr: 0,
            conditions: &[],
        }; 300];
        let mut at = 0;
        while at < 300 {
            rules[at].nr = at as u32;
            at += 1;
        }
        rules
    };
    assert_eq!(program(&MANY, RET_KILL_PROCESS, 1), Err(ProgramTooLong));
    let fits = program(&MANY[..200], RET_KILL_PROCESS, 1).expect("fits");
    validate(&fits);
    assert_eq!(
        interpret(&fits, &data(AUDIT_ARCH_X86_64, 199, [0; 6])),
        RET_ALLOW
    );
    assert_eq!(
        interpret(&fits, &data(AUDIT_ARCH_X86_64, 200, [0; 6])),
        RET_KILL_PROCESS
    );
}

const CONFINED: &str = "Name:\truster\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n\
    Speculation_Store_Bypass:\tthread vulnerable\n";

#[test]
fn status_rows_parse_and_fail_closed() {
    let confined = parse_confinement(CONFINED).expect("parse");
    assert_eq!(
        confined,
        Confinement {
            mode: 2,
            filters: 1,
            no_new_privs: true
        }
    );
    assert_eq!(check(confined, 1), Ok(()));
    assert_eq!(check(confined, 2), Err(Unconfined::Filters));
    assert_eq!(
        check(
            Confinement {
                mode: 0,
                ..confined
            },
            1
        ),
        Err(Unconfined::Mode)
    );
    assert_eq!(
        check(
            Confinement {
                no_new_privs: false,
                ..confined
            },
            1
        ),
        Err(Unconfined::NoNewPrivs)
    );
    for row in ["NoNewPrivs", "Seccomp", "Seccomp_filters"] {
        let without: String = CONFINED
            .lines()
            .filter(|line| !line.starts_with(&format!("{row}:")))
            .map(|line| format!("{line}\n"))
            .collect();
        assert_eq!(parse_confinement(&without), None, "{row} missing");
    }
    for broken in [
        CONFINED.replace("NoNewPrivs:\t1", "NoNewPrivs:\t2"),
        CONFINED.replace("Seccomp:\t2", "Seccomp:\tx"),
        CONFINED.replace("Seccomp_filters:\t1", "Seccomp_filters:\t-1"),
    ] {
        assert_eq!(parse_confinement(&broken), None, "{broken}");
    }
}

#[test]
fn state_lines_fields_and_failures_are_value_free() {
    let report = ConfineReport {
        threads: 5,
        syscalls: allowed_syscalls(),
    };
    let kill = SeccompState::Confined {
        mode: SeccompMode::Kill,
        report,
    };
    assert_eq!(
        kill.line(),
        format!(
            "seccomp filter installed: mode=kill threads=5 syscalls={} arch=x86_64",
            ALLOWLIST.len()
        )
    );
    let log = SeccompState::Confined {
        mode: SeccompMode::Log,
        report,
    };
    assert!(log.line().contains("mode=log"));
    assert!(log
        .line()
        .ends_with("\nruster run: warning: seccomp=log (--seccomp log): a syscall outside the allowlist is logged by the kernel and allowed"));
    assert_eq!(
        SeccompState::Off.line(),
        "warning: seccomp=off (--seccomp off): no syscall filter"
    );
    let mut text = String::new();
    super::super::stats::write_fields(&mut text, None, &kill);
    assert_eq!(
        text,
        format!(
            "seccomp.mode=kill\nseccomp.threads=5\nseccomp.syscalls={}\n",
            ALLOWLIST.len()
        )
    );
    let mut text = String::new();
    super::super::stats::write_fields(&mut text, None, &SeccompState::Off);
    assert_eq!(
        text,
        "seccomp.mode=off\nseccomp.threads=0\nseccomp.syscalls=0\n"
    );
    for (failure, code) in [
        (
            ConfineFailure::Syscall {
                step: ConfineStep::Install,
                errno: 22,
            },
            "code=INSTALL/ERRNO_22",
        ),
        (
            ConfineFailure::Syscall {
                step: ConfineStep::NoNewPrivs,
                errno: 1,
            },
            "code=NO_NEW_PRIVS/ERRNO_1",
        ),
        (
            ConfineFailure::Syscall {
                step: ConfineStep::ActionAvail,
                errno: 38,
            },
            "code=ACTION_AVAIL/ERRNO_38",
        ),
        (ConfineFailure::ActionUnavailable, "code=ACTION_UNAVAILABLE"),
        (ConfineFailure::TsyncConflict, "code=TSYNC_CONFLICT"),
        (ConfineFailure::ProgramTooLong, "code=PROGRAM_TOO_LONG"),
        (ConfineFailure::Unreadable, "code=STATUS_UNREADABLE"),
        (
            ConfineFailure::NotConfined(Unconfined::Filters),
            "code=NOT_CONFINED/FILTERS",
        ),
        (
            ConfineFailure::NotConfined(Unconfined::NoNewPrivs),
            "code=NOT_CONFINED/NO_NEW_PRIVS",
        ),
    ] {
        assert_eq!(failure.to_string(), code);
    }
}

/// The live filter, in child processes of this test binary (a filter
/// cannot be removed, so it never runs in the test process itself; a
/// re-executed child instead of `fork`, which is unsound in a
/// multi-threaded test process). No privilege is needed: the child sets
/// `no_new_privs` first.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
mod live {
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Output};

    use super::super::linux::{confine, sys};
    use super::*;

    const CHILD: &str = "RUSTER_SECCOMP_CHILD";
    const ALLOWED: &str = "seccomp-child: allowed ok";
    const SURVIVED: &str = "seccomp-child: survived";
    const SIGSYS: i32 = 31;

    fn mark(line: &str) {
        let mut out = std::io::stdout();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }

    /// What the router's threads do after startup, under the filter.
    fn exercise_allowed() {
        // Allocation: mmap/mremap/munmap/brk/madvise.
        let mut big = vec![1_u8; 8 << 20];
        big.resize(32 << 20, 2);
        assert_eq!(
            big.iter().map(|&b| u64::from(b)).sum::<u64>(),
            (8 << 20) + (48 << 20)
        );
        drop(big);
        // Read-only files, metadata, symbolic links, directories.
        let status = std::fs::read_to_string("/proc/self/status").expect("status");
        assert!(status.contains("Seccomp:\t2"), "{status}");
        assert!(std::fs::metadata("/proc/self/status").is_ok());
        assert!(std::fs::symlink_metadata("/proc/self").is_ok());
        assert!(std::fs::read_link("/proc/self/exe").is_ok());
        assert!(std::fs::read_dir("/proc/self/task").expect("tasks").count() >= 1);
        // The link watch: a NETLINK_ROUTE socket with strict checking,
        // connected, a link query and a dump.
        let mut probe = super::super::super::netlink::LinkProbe::open().expect("netlink");
        let lo = probe.query(1).expect("lo");
        assert!(lo.mtu > 0);
        let _ = probe.ipv4_addresses(1).expect("addresses");
        drop(probe);
        // Sleep, the clock, std's hash keys, a caught panic.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let _ = std::time::Instant::now();
        let mut map = std::collections::HashMap::new();
        map.insert(1, 2);
        assert_eq!(map.get(&1), Some(&2));
        let caught = std::panic::catch_unwind(|| panic!("seccomp-child: a caught panic"));
        assert!(caught.is_err());
    }

    /// The child side: does nothing unless started by [`run_child`].
    #[test]
    fn seccomp_child() {
        let Ok(scenario) = std::env::var(CHILD) else {
            return;
        };
        // Not dumpable, no_new_privs, no capability: as `ruster run`
        // after its drop (and no core file for the expected SIGSYS).
        super::super::super::privileges::linux::drop_thread(
            super::super::super::privileges::PrivilegePolicy::Drop { identity: None },
        )
        .expect("drop");
        let mode = if scenario.starts_with("log") {
            SeccompMode::Log
        } else {
            SeccompMode::Kill
        };
        // A thread that exists before the install and exits and is joined
        // under the filter (no thread can be started under it).
        // It must have started running first: glibc registers `rseq` at
        // the start of a new thread, which the filter denies (`ruster
        // run`'s threads have all reported their prologue by then).
        let (go, wait) = std::sync::mpsc::channel::<()>();
        let (started, running) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            let _ = started.send(());
            let _ = wait.recv();
            std::thread::sleep(std::time::Duration::from_millis(1));
            std::thread::yield_now();
            7_u32
        });
        running.recv().expect("worker started");
        let report = confine(mode).expect("confine");
        assert!(report.threads >= 1);
        assert_eq!(report.syscalls, allowed_syscalls());
        exercise_allowed();
        let _ = go.send(());
        assert_eq!(worker.join().expect("worker"), 7);
        mark(ALLOWED);
        match scenario.as_str() {
            // A normal end: the test returns, the harness reports and the
            // process exits through `main`.
            "kill-exit" => {}
            "kill-process-exit" => {
                mark(SURVIVED);
                std::process::exit(0);
            }
            "kill-socket" | "log-socket" => {
                drop(std::net::UdpSocket::bind("127.0.0.1:0"));
            }
            "kill-open-write" => {
                let _ = std::fs::OpenOptions::new()
                    .write(true)
                    .open("/proc/self/comm");
            }
            "log-x32" => {
                let _ = sys::raw0(i64::from(X32_SYSCALL_BIT | 39));
            }
            other => panic!("unknown scenario {other}"),
        }
        mark(SURVIVED);
    }

    fn run_child(scenario: &str) -> Output {
        Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "run::seccomp::tests::live::seccomp_child",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, scenario)
            // The caught panic prints a backtrace under the filter.
            .env("RUST_BACKTRACE", "1")
            .output()
            .expect("child")
    }

    #[test]
    fn a_denied_syscall_kills_the_process_and_allowed_ones_run() {
        for scenario in ["kill-socket", "kill-open-write", "log-x32"] {
            let output = run_child(scenario);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(
                output.status.signal(),
                Some(SIGSYS),
                "{scenario}: {:?}\n{stdout}\n{stderr}",
                output.status
            );
            assert!(stdout.contains(ALLOWED), "{scenario}: {stdout}\n{stderr}");
            assert!(!stdout.contains(SURVIVED), "{scenario}: {stdout}");
        }
    }

    #[test]
    fn a_thread_exit_and_both_process_exits_pass_the_kill_filter() {
        for scenario in ["kill-exit", "kill-process-exit"] {
            let output = run_child(scenario);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "{scenario}: {:?}\n{stdout}\n{stderr}",
                output.status
            );
            assert!(
                stdout.contains(ALLOWED) && stdout.contains(SURVIVED),
                "{scenario}: {stdout}"
            );
        }
    }

    #[test]
    fn the_log_mode_lets_a_denied_syscall_run() {
        let output = run_child("log-socket");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{:?}\n{stdout}\n{stderr}",
            output.status
        );
        assert!(
            stdout.contains(ALLOWED) && stdout.contains(SURVIVED),
            "{stdout}"
        );
    }
}
