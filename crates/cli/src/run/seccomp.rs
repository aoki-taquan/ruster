//! Seccomp-BPF syscall allowlist of `ruster run` after startup (H8,
//! CLI-102 to CLI-107).
//!
//! Once every port is attached, generation 1 is active, the workers run,
//! and the privilege drop ([`super::privileges`]) is verified, the router
//! thread confines the whole process to the syscalls the run needs
//! ([`ALLOWLIST`]) with one classic BPF program ([`program`]):
//!
//! 1. `seccomp_data.arch` must be `AUDIT_ARCH_X86_64`, and the syscall
//!    number must not carry `__X32_SYSCALL_BIT`; anything else (an i386
//!    `int 0x80` call, an x32 call) kills the process in every mode: the
//!    allowlist numbers are x86_64 numbers, and ruster never makes such a
//!    call.
//! 2. A syscall on the allowlist runs if its argument conditions (on the
//!    low 32 bits of an `int` argument, which is all the kernel reads of
//!    it) hold.
//! 3. Every other syscall gets the violation action of [`SeccompMode`]:
//!    `SECCOMP_RET_KILL_PROCESS` (the default, fail closed: the kernel
//!    kills every thread at once, which closes every fd, so the unpinned
//!    XDP links detach as after SIGKILL) or `SECCOMP_RET_LOG` (logged by
//!    the kernel's audit/printk path and then run).
//!
//! # Installation
//!
//! One `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC)` call
//! on the router thread, after the privilege drop: TSYNC attaches the same
//! filter to every thread of the process atomically (the four other
//! threads exist by then: the two output threads and the two workers,
//! each fully started, since its spawn waited for its prologue's outcome,
//! so the C library's thread start (`rseq`, `set_robust_list`) is behind
//! it; no thread is started later), or to none when any thread has a filter
//! that is not an ancestor of the caller's (the kernel then returns that
//! thread's id: `TSYNC_CONFLICT`). One call instead of a filter per
//! thread prologue because the threads that drop their privileges early
//! (the output threads, before startup) still have startup ahead of the
//! process, and because a single attach point is simpler to verify. The
//! kernel needs `no_new_privs` (or `CAP_SYS_ADMIN`) on the caller: the drop
//! already set it; with `--keep-privileges` it is set here (it takes no
//! capability away; it only stops an `execve` from granting any, and
//! ruster never executes anything), and TSYNC sets it on every thread.
//! The router thread then requires every thread of the process
//! (`/proc/self/task/*/status`) to show `Seccomp: 2`, `NoNewPrivs: 1`, and
//! one more filter (`Seccomp_filters`, Linux 5.9) than it had before
//! (a supervisor's own filter, such as systemd's `SystemCallFilter=`,
//! stays underneath; the stricter result of all filters applies). Any
//! failure aborts startup with the full rollback (exit 1, `stage=seccomp`).
//!
//! # The allowlist
//!
//! Derived by reading the code of every thread after the drop, and checked
//! against `strace -f` of the whole privileged smoke attached to the
//! running router after readiness (the runbook, section 5, lists each
//! entry and why). Nothing after startup opens a file for writing, creates
//! an inet socket, loads a BPF program, maps executable memory, starts a
//! thread or a process, or changes a credential.

use std::fmt;

use ruster_core::{FieldValue, FieldVisitor, ObservableFields};

pub use crate::args::SeccompMode;

/// `AUDIT_ARCH_X86_64` (`EM_X86_64 | __AUDIT_ARCH_64BIT |
/// __AUDIT_ARCH_LE`).
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
/// `__X32_SYSCALL_BIT`.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;
/// `SECCOMP_RET_KILL_PROCESS` (Linux 4.14).
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
/// `SECCOMP_RET_LOG` (Linux 4.14).
pub const RET_LOG: u32 = 0x7FFC_0000;
/// `SECCOMP_RET_ALLOW`.
pub const RET_ALLOW: u32 = 0x7FFF_0000;

/// Offsets into `struct seccomp_data` (`nr`, `arch`, `instruction_pointer`,
/// `args[6]`; 64 bytes).
const DATA_NR: u32 = 0;
const DATA_ARCH: u32 = 4;
const DATA_ARGS: u32 = 16;

/// Byte offset of the low 32 bits of argument `index` (little endian).
const fn arg_low(index: u8) -> u32 {
    DATA_ARGS + 8 * index as u32
}

// Classic BPF opcodes (`linux/bpf_common.h`).
/// `BPF_LD | BPF_W | BPF_ABS`.
pub const LD_W_ABS: u16 = 0x20;
/// `BPF_JMP | BPF_JEQ | BPF_K`.
pub const JEQ_K: u16 = 0x15;
/// `BPF_JMP | BPF_JSET | BPF_K`.
pub const JSET_K: u16 = 0x45;
/// `BPF_RET | BPF_K`.
pub const RET_K: u16 = 0x06;

/// `BPF_MAXINSNS`: the kernel's limit on a classic program.
pub const MAX_INSNS: usize = 4096;

/// One classic BPF instruction (`struct sock_filter`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const _: () = assert!(std::mem::size_of::<SockFilter>() == 8);

impl SockFilter {
    const fn load(offset: u32) -> Self {
        Self {
            code: LD_W_ABS,
            jt: 0,
            jf: 0,
            k: offset,
        }
    }

    const fn ret(action: u32) -> Self {
        Self {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: action,
        }
    }

    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        Self { code, jt, jf, k }
    }
}

/// The value an argument is compared with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Value {
    Fixed(u32),
    /// The process id, fixed for the life of the process (taken when the
    /// program is assembled).
    OwnPid,
}

/// A condition on the low 32 bits of one argument (every filtered
/// argument is a C `int`, of which the kernel reads only those bits).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Condition {
    /// `args[index] == value`.
    Equal { index: u8, value: Value },
    /// `args[index] & mask == 0`.
    Clear { index: u8, mask: u32 },
    /// `(args[first], args[second])` is one of `pairs` (a `getsockopt`
    /// level and option name, say).
    OneOf {
        first: u8,
        second: u8,
        pairs: &'static [(u32, u32)],
    },
}

impl Condition {
    /// Instructions of the condition in [`program`]: a load and a test,
    /// or two of each per pair.
    const fn len(self) -> usize {
        match self {
            Self::Equal { .. } | Self::Clear { .. } => 2,
            Self::OneOf { pairs, .. } => 4 * pairs.len(),
        }
    }
}

/// One allowed syscall: its x86_64 number and the conditions (all must
/// hold) on its arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rule {
    pub name: &'static str,
    pub nr: u32,
    pub conditions: &'static [Condition],
}

const fn allow(name: &'static str, nr: u32) -> Rule {
    Rule {
        name,
        nr,
        conditions: &[],
    }
}

const fn only(name: &'static str, nr: u32, conditions: &'static [Condition]) -> Rule {
    Rule {
        name,
        nr,
        conditions,
    }
}

const fn equal(index: u8, value: u32) -> Condition {
    Condition::Equal {
        index,
        value: Value::Fixed(value),
    }
}

// Argument values (x86_64 Linux UAPI).
pub const AF_NETLINK: u32 = 16;
pub const NETLINK_ROUTE: u32 = 0;
pub const SOL_NETLINK: u32 = 270;
pub const NETLINK_GET_STRICT_CHK: u32 = 12;
pub const BPF_MAP_DELETE_ELEM: u32 = 3;
pub const SOL_SOCKET: u32 = 1;
pub const SO_ERROR: u32 = 4;
pub const SOL_PACKET: u32 = 263;
pub const PACKET_STATISTICS: u32 = 6;
pub const SOL_XDP: u32 = 283;
pub const XDP_STATISTICS: u32 = 7;
/// The `getsockopt` (level, option) pairs a run may read after startup.
pub const GETSOCKOPT_ALLOWED: &[(u32, u32)] = &[
    (SOL_XDP, XDP_STATISTICS),
    (SOL_PACKET, PACKET_STATISTICS),
    (SOL_SOCKET, SO_ERROR),
];
pub const PROT_EXEC: u32 = 0x4;
pub const F_GETFD: u32 = 1;
/// `O_WRONLY | O_RDWR | O_CREAT | O_TRUNC`: any of them makes an open
/// able to change a file (`O_TMPFILE` needs a write mode too).
pub const OPEN_WRITE_FLAGS: u32 = 0o1 | 0o2 | 0o100 | 0o1000;

/// Every syscall `ruster run` may make after startup, hot path first (the
/// kernel caches an unconditional allow per syscall number since Linux
/// 5.11, so for those the order costs nothing there; it matters on older
/// kernels). The runbook (section 5, "Syscall filter") explains each.
pub const ALLOWLIST: &[Rule] = &[
    // Router thread: AF_XDP TX kick (`sendto(fd, NULL, 0, MSG_DONTWAIT)`),
    // also the link watcher's netlink requests (`send`).
    allow("sendto", 44),
    // Router: the Fill-ring wakeup of the need-wakeup profile.
    allow("poll", 7),
    // Router: AF_XDP `XDP_STATISTICS` of every stats sample; AF_PACKET
    // `PACKET_STATISTICS` of every health sample and `SO_ERROR` after a
    // `POLLERR` (AFPKT-015). Nothing else.
    only(
        "getsockopt",
        55,
        &[Condition::OneOf {
            first: 1,
            second: 2,
            pairs: GETSOCKOPT_ALLOWED,
        }],
    ),
    // Router idle backoff and every `thread::sleep` (std), and the restart
    // of an interrupted one after a signal; `nanosleep` where the C
    // library's sleep uses it (older glibc, musl).
    allow("clock_nanosleep", 230),
    allow("restart_syscall", 219),
    allow("nanosleep", 35),
    // The monotonic clock is a vDSO call; without a vDSO (`vdso=0`) it is
    // this syscall.
    allow("clock_gettime", 228),
    // Channels and locks between the threads (std); std's channels back
    // off with `thread::yield_now` in disconnect and preemption races
    // (dropping the worker and output channels).
    allow("futex", 202),
    allow("sched_yield", 24),
    // Output threads: stdout/stderr; config and sysctl reads; the
    // `/dev/urandom` key reads of a reload; `/proc` reads.
    allow("write", 1),
    allow("read", 0),
    // Link watcher: netlink answers, the socket's port id.
    allow("recvfrom", 45),
    allow("getsockname", 51),
    // Read-only opens only (config, sysctls, `/proc`): never create,
    // truncate, or write a file.
    only(
        "openat",
        257,
        &[Condition::Clear {
            index: 2,
            mask: OPEN_WRITE_FLAGS,
        }],
    ),
    allow("close", 3),
    // std's file metadata (`File::metadata`, `symlink_metadata`: config
    // checks of a reload).
    allow("statx", 332),
    // `read_link("/proc/self/fd/N")` of `--strict-config-perms`.
    allow("readlink", 89),
    // `read_dir` of `/proc/self/task` (the verification right after the
    // install): glibc's `opendir` checks the fd with `fstat`, which is
    // the `fstat` syscall on glibc 2.39 and newer (and before 2.33) but
    // `newfstatat(fd, "", AT_EMPTY_PATH)` on glibc 2.33 to 2.38 (Ubuntu
    // 22.04, Debian 12, RHEL 9). std's `stat64`/`lstat64`/`fstat64`
    // fallbacks (when a supervisor refuses `statx`) end there too. Both
    // are read-only metadata, the same capability as `statx`.
    allow("getdents64", 217),
    allow("fstat", 5),
    allow("newfstatat", 262),
    // Debug builds of std check an fd before closing it.
    only("fcntl", 72, &[equal(1, F_GETFD)]),
    // Allocation (glibc malloc and its arenas): never executable memory.
    only(
        "mmap",
        9,
        &[Condition::Clear {
            index: 2,
            mask: PROT_EXEC,
        }],
    ),
    only(
        "mprotect",
        10,
        &[Condition::Clear {
            index: 2,
            mask: PROT_EXEC,
        }],
    ),
    allow("munmap", 11),
    allow("mremap", 25),
    allow("brk", 12),
    allow("madvise", 28),
    // std's per-thread `HashMap` keys, drawn lazily on a thread's first
    // map.
    allow("getrandom", 318),
    // Link watcher: a replacement `NETLINK_ROUTE` socket after a failed
    // query, strict checking on it, connected to the kernel.
    only(
        "socket",
        41,
        &[equal(0, AF_NETLINK), equal(2, NETLINK_ROUTE)],
    ),
    only(
        "setsockopt",
        54,
        &[equal(1, SOL_NETLINK), equal(2, NETLINK_GET_STRICT_CHK)],
    ),
    allow("connect", 42),
    // Teardown: the XSKMAP entry delete through the map fd this process
    // holds (closing the link fd detaches the program).
    only("bpf", 321, &[equal(0, BPF_MAP_DELETE_ELEM)]),
    // Signals: the SIGINT/SIGTERM/SIGHUP handlers return through it.
    allow("rt_sigreturn", 15),
    // Thread and process exit (glibc unmaps the thread's stack and
    // alternate signal stack, blocks signals first).
    allow("exit", 60),
    allow("exit_group", 231),
    allow("sigaltstack", 131),
    allow("rt_sigprocmask", 14),
    // `abort` (a panic while panicking, a std runtime abort) raises
    // SIGABRT at this process only, and std's SIGSEGV/SIGBUS handler
    // resets the default action before a fault is re-raised, so a crash
    // keeps its own signal instead of becoming a seccomp kill.
    allow("getpid", 39),
    // A panic message names the thread's id, and with `RUST_BACKTRACE=1`
    // std shortens the backtrace's paths against the working directory
    // (std).
    allow("gettid", 186),
    allow("getcwd", 79),
    // ... and reads the binary's debug info to symbolize it.
    allow("lseek", 8),
    only(
        "tgkill",
        234,
        &[Condition::Equal {
            index: 0,
            value: Value::OwnPid,
        }],
    ),
    allow("rt_sigaction", 13),
];

/// Instructions of `conditions` in [`program`].
fn conditions_len(conditions: &[Condition]) -> usize {
    conditions.iter().map(|condition| condition.len()).sum()
}

/// Number of allowed syscalls (for the startup line and the stats).
pub const fn allowed_syscalls() -> u32 {
    ALLOWLIST.len() as u32
}

/// Why the program could not be assembled (a jump out of `u8` range or
/// too many instructions; checked by the tests for the real allowlist).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramTooLong;

fn offset(distance: usize) -> Result<u8, ProgramTooLong> {
    u8::try_from(distance).map_err(|_| ProgramTooLong)
}

/// The violation action of a mode, `None` for [`SeccompMode::Off`].
pub const fn violation(mode: SeccompMode) -> Option<u32> {
    match mode {
        SeccompMode::Kill => Some(RET_KILL_PROCESS),
        SeccompMode::Log => Some(RET_LOG),
        SeccompMode::Off => None,
    }
}

/// Assembles the filter of `rules` with `action` for a syscall outside
/// them, for process `pid`. Specific to little-endian x86_64: the
/// argument loads read the low 32 bits at the lower address of each
/// 64-bit `args[i]`, and the numbers and `AUDIT_ARCH_X86_64` are x86_64's.
///
///
/// ```text
///      ld  [arch]
///      jeq #AUDIT_ARCH_X86_64, 1, 0
///      ret #KILL_PROCESS
///      ld  [nr]
///      jset #X32_SYSCALL_BIT, 0, 1
///      ret #KILL_PROCESS
///      jeq #nr, allow, 0          ; one per unconditional rule
///      ...
///      jeq #nr, 0, next           ; one block per conditional rule:
///      ld  [args[i] low]          ;   per condition, a load and a test
///      jeq #v, 0, deny | jset #m, deny, 0
///      ld  [args[a] low]          ;   (a one-of condition: per pair,
///      jeq #x, 0, pair'           ;    two loads and tests; a match
///      ld  [args[b] low]          ;    goes on after the condition,
///      jeq #y, end, pair'         ;    the last mismatch to deny)
///      ret #ALLOW
/// deny:ret #action
/// next:...
///      ret #action
/// allow: ret #ALLOW
/// ```
pub fn program(rules: &[Rule], action: u32, pid: u32) -> Result<Vec<SockFilter>, ProgramTooLong> {
    let mut out = vec![
        SockFilter::load(DATA_ARCH),
        SockFilter::jump(JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        SockFilter::ret(RET_KILL_PROCESS),
        SockFilter::load(DATA_NR),
        SockFilter::jump(JSET_K, X32_SYSCALL_BIT, 0, 1),
        SockFilter::ret(RET_KILL_PROCESS),
    ];
    let (plain, conditional): (Vec<&Rule>, Vec<&Rule>) =
        rules.iter().partition(|rule| rule.conditions.is_empty());
    let blocks: usize = conditional
        .iter()
        .map(|rule| 1 + conditions_len(rule.conditions) + 2)
        .sum();
    // Index of the final `ret #ALLOW`.
    let allow_at = out.len() + plain.len() + blocks + 1;
    for rule in &plain {
        let next = out.len() + 1;
        out.push(SockFilter::jump(
            JEQ_K,
            rule.nr,
            offset(allow_at - next)?,
            0,
        ));
    }
    for rule in &conditional {
        out.push(SockFilter::jump(
            JEQ_K,
            rule.nr,
            0,
            offset(conditions_len(rule.conditions) + 2)?,
        ));
        for (at, condition) in rule.conditions.iter().enumerate() {
            // Instructions after this condition up to the block's `ret
            // #ALLOW`, inclusive; the deny follows it.
            let rest = conditions_len(&rule.conditions[at + 1..]) + 1;
            // From the instruction after a two-instruction test to deny.
            let deny = offset(rest)?;
            match *condition {
                Condition::Equal { index, value } => {
                    let value = match value {
                        Value::Fixed(value) => value,
                        Value::OwnPid => pid,
                    };
                    out.push(SockFilter::load(arg_low(index)));
                    out.push(SockFilter::jump(JEQ_K, value, 0, deny));
                }
                Condition::Clear { index, mask } => {
                    out.push(SockFilter::load(arg_low(index)));
                    out.push(SockFilter::jump(JSET_K, mask, deny, 0));
                }
                Condition::OneOf {
                    first,
                    second,
                    pairs,
                } => {
                    let len = condition.len();
                    for (pair, (a, b)) in pairs.iter().enumerate() {
                        let last = pair + 1 == pairs.len();
                        // Relative to the instruction after the first test
                        // (`4 * pair + 2` into the condition): the next
                        // pair, or the deny after the last.
                        let miss_first = if last {
                            offset(len + rest - 4 * pair - 2)?
                        } else {
                            2
                        };
                        // ... and after the second test: the next pair
                        // (right there), or the deny; a match leaves the
                        // condition.
                        let miss_second = if last {
                            offset(len + rest - 4 * pair - 4)?
                        } else {
                            0
                        };
                        let matched = offset(len - 4 * pair - 4)?;
                        out.push(SockFilter::load(arg_low(first)));
                        out.push(SockFilter::jump(JEQ_K, *a, 0, miss_first));
                        out.push(SockFilter::load(arg_low(second)));
                        out.push(SockFilter::jump(JEQ_K, *b, matched, miss_second));
                    }
                }
            }
        }
        out.push(SockFilter::ret(RET_ALLOW));
        out.push(SockFilter::ret(action));
    }
    out.push(SockFilter::ret(action));
    debug_assert_eq!(out.len(), allow_at);
    out.push(SockFilter::ret(RET_ALLOW));
    if out.len() > MAX_INSNS {
        return Err(ProgramTooLong);
    }
    Ok(out)
}

/// The step of the install that failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfineStep {
    /// `PR_SET_NO_NEW_PRIVS` 1 on the router thread.
    NoNewPrivs,
    /// `SECCOMP_GET_ACTION_AVAIL` of the violation action.
    ActionAvail,
    /// `SECCOMP_SET_MODE_FILTER` with `SECCOMP_FILTER_FLAG_TSYNC`.
    Install,
}

/// What a thread showed after the install.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unconfined {
    /// `Seccomp` is not 2 (filter mode).
    Mode,
    /// `Seccomp_filters` is not one more than before the install.
    Filters,
    /// `NoNewPrivs` is not 1.
    NoNewPrivs,
}

/// Why the filter could not be installed. Value-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfineFailure {
    /// A syscall of the install failed with this errno.
    Syscall { step: ConfineStep, errno: i32 },
    /// The kernel does not know the violation action (Linux 4.14 and
    /// newer do).
    ActionUnavailable,
    /// TSYNC: a thread has a filter that is not an ancestor of the router
    /// thread's; nothing was installed.
    TsyncConflict,
    /// The program does not fit classic BPF.
    ProgramTooLong,
    /// A thread's `/proc/.../status` could not be read or parsed (also a
    /// kernel without `Seccomp_filters`, before 5.9).
    Unreadable,
    /// A thread of the process is not confined as expected.
    NotConfined(Unconfined),
    /// A failure injected by a test host.
    #[cfg(test)]
    Injected,
}

impl fmt::Display for ConfineFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        use super::startup::token;
        match self {
            Self::Syscall { step, errno } => {
                write!(formatter, "code={}/ERRNO_{errno}", token(step))
            }
            Self::ActionUnavailable => formatter.write_str("code=ACTION_UNAVAILABLE"),
            Self::TsyncConflict => formatter.write_str("code=TSYNC_CONFLICT"),
            Self::ProgramTooLong => formatter.write_str("code=PROGRAM_TOO_LONG"),
            Self::Unreadable => formatter.write_str("code=STATUS_UNREADABLE"),
            Self::NotConfined(what) => write!(formatter, "code=NOT_CONFINED/{}", token(what)),
            #[cfg(test)]
            Self::Injected => formatter.write_str("code=INJECTED"),
        }
    }
}

/// The seccomp facts of one thread (`/proc/<pid>/task/<tid>/status`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Confinement {
    /// `Seccomp`: 0 none, 1 strict, 2 filter.
    pub mode: u32,
    /// `Seccomp_filters`: filters attached to the thread.
    pub filters: u32,
    pub no_new_privs: bool,
}

fn number_row(status: &str, name: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))?
        .trim()
        .parse()
        .ok()
}

/// Parses the seccomp rows of a `status` file; `None` if one is missing
/// or malformed (fail closed).
pub fn parse_confinement(status: &str) -> Option<Confinement> {
    let no_new_privs = match number_row(status, "NoNewPrivs")? {
        0 => false,
        1 => true,
        _ => return None,
    };
    Some(Confinement {
        mode: number_row(status, "Seccomp")?,
        filters: number_row(status, "Seccomp_filters")?,
        no_new_privs,
    })
}

/// Checks one thread after the install: filter mode, `no_new_privs`, and
/// exactly `filters` filters.
pub fn check(confinement: Confinement, filters: u32) -> Result<(), Unconfined> {
    if confinement.mode != 2 {
        return Err(Unconfined::Mode);
    }
    if !confinement.no_new_privs {
        return Err(Unconfined::NoNewPrivs);
    }
    if confinement.filters != filters {
        return Err(Unconfined::Filters);
    }
    Ok(())
}

/// The outcome of a successful install.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfineReport {
    /// Threads verified (every thread of the process).
    pub threads: u32,
    /// Allowed syscalls.
    pub syscalls: u32,
}

/// The syscall filter of the running router, for the startup line and the
/// stats blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeccompState {
    /// Installed with this mode (never `Off`).
    Confined {
        mode: SeccompMode,
        report: ConfineReport,
    },
    /// `--seccomp off`.
    Off,
}

impl SeccompState {
    /// The value-free startup line(s).
    pub fn line(self) -> String {
        match self {
            Self::Confined { mode, report } => {
                let installed = format!(
                    "seccomp filter installed: mode={} threads={} syscalls={} arch=x86_64",
                    mode.label(),
                    report.threads,
                    report.syscalls,
                );
                if mode == SeccompMode::Log {
                    format!(
                        "{installed}\nruster run: warning: seccomp=log (--seccomp log): a syscall \
                         outside the allowlist is logged by the kernel and allowed"
                    )
                } else {
                    installed
                }
            }
            Self::Off => "warning: seccomp=off (--seccomp off): no syscall filter".to_owned(),
        }
    }

    const fn mode(self) -> SeccompMode {
        match self {
            Self::Confined { mode, .. } => mode,
            Self::Off => SeccompMode::Off,
        }
    }
}

impl ObservableFields for SeccompState {
    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        const SECTION: &str = "seccomp";
        let (threads, syscalls) = match self {
            Self::Confined { report, .. } => (report.threads, report.syscalls),
            Self::Off => (0, 0),
        };
        visitor.field(SECTION, "mode", FieldValue::Label(self.mode().label()));
        visitor.field(SECTION, "threads", FieldValue::Count(u64::from(threads)));
        visitor.field(SECTION, "syscalls", FieldValue::Count(u64::from(syscalls)));
    }
}

/// The live install: x86_64 Linux only (x86_64 syscall numbers and
/// `AUDIT_ARCH_X86_64`).
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
pub mod linux {
    use std::fs;

    use super::{
        allowed_syscalls, check, parse_confinement, program, violation, ConfineFailure,
        ConfineReport, ConfineStep, Confinement, SeccompMode, ALLOWLIST,
    };

    fn own() -> Result<Confinement, ConfineFailure> {
        let text = fs::read_to_string("/proc/thread-self/status")
            .map_err(|_| ConfineFailure::Unreadable)?;
        parse_confinement(&text).ok_or(ConfineFailure::Unreadable)
    }

    fn step<T>(step: ConfineStep, result: Result<T, i32>) -> Result<T, ConfineFailure> {
        result.map_err(|errno| ConfineFailure::Syscall { step, errno })
    }

    /// Installs the filter of `mode` on every thread of the process (TSYNC)
    /// and verifies every thread. `mode` must not be
    /// [`SeccompMode::Off`] (reported as `ACTION_UNAVAILABLE`).
    pub fn confine(mode: SeccompMode) -> Result<ConfineReport, ConfineFailure> {
        let action = violation(mode).ok_or(ConfineFailure::ActionUnavailable)?;
        let before = own()?;
        // Assembled (and the pid taken) before the filter exists.
        let program = program(ALLOWLIST, action, std::process::id())
            .map_err(|_| ConfineFailure::ProgramTooLong)?;
        step(ConfineStep::NoNewPrivs, sys::set_no_new_privs())?;
        match sys::action_available(action) {
            Ok(()) => {}
            Err(sys::EOPNOTSUPP) => return Err(ConfineFailure::ActionUnavailable),
            Err(errno) => {
                return Err(ConfineFailure::Syscall {
                    step: ConfineStep::ActionAvail,
                    errno,
                })
            }
        }
        if step(ConfineStep::Install, sys::install_tsync(&program))? != 0 {
            return Err(ConfineFailure::TsyncConflict);
        }
        let filters = before.filters.saturating_add(1);
        let mut threads = 0_u32;
        let tasks = fs::read_dir("/proc/self/task").map_err(|_| ConfineFailure::Unreadable)?;
        for task in tasks {
            let task = task.map_err(|_| ConfineFailure::Unreadable)?;
            let text = fs::read_to_string(task.path().join("status"))
                .map_err(|_| ConfineFailure::Unreadable)?;
            let confinement = parse_confinement(&text).ok_or(ConfineFailure::Unreadable)?;
            check(confinement, filters).map_err(ConfineFailure::NotConfined)?;
            threads = threads.saturating_add(1);
        }
        if threads == 0 {
            return Err(ConfineFailure::Unreadable);
        }
        Ok(ConfineReport {
            threads,
            syscalls: allowed_syscalls(),
        })
    }

    /// Raw `prctl` and `seccomp` syscalls (x86_64 numbers; the C library
    /// has no `seccomp` wrapper everywhere).
    #[allow(unsafe_code)]
    pub(super) mod sys {
        use std::os::raw::c_long;

        use super::super::SockFilter;

        const SYS_PRCTL: c_long = 157;
        const SYS_SECCOMP: c_long = 317;
        const PR_SET_NO_NEW_PRIVS: c_long = 38;
        const SECCOMP_SET_MODE_FILTER: c_long = 1;
        const SECCOMP_GET_ACTION_AVAIL: c_long = 2;
        const SECCOMP_FILTER_FLAG_TSYNC: c_long = 1;
        pub const EOPNOTSUPP: i32 = 95;
        const EINVAL: i32 = 22;

        /// `struct sock_fprog`: the length, then (after padding) the
        /// pointer to the first instruction.
        #[repr(C)]
        struct SockFprog {
            len: u16,
            filter: *const SockFilter,
        }

        const _: () = assert!(std::mem::size_of::<SockFprog>() == 16);

        extern "C" {
            // `long syscall(long number, ...)` from the C library std
            // already links (glibc or musl); it passes up to six
            // `long`-sized arguments to the kernel and returns -1 with
            // `errno` set on failure.
            fn syscall(number: c_long, ...) -> c_long;
        }

        fn errno() -> i32 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        }

        /// `PR_SET_NO_NEW_PRIVS` 1 on the calling thread.
        pub fn set_no_new_privs() -> Result<(), i32> {
            // SAFETY: `prctl` with this option reads only its integer
            // arguments (the unused ones are passed as 0, as the kernel
            // requires); no memory is passed.
            let value =
                unsafe { syscall(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1_i64, 0_i64, 0_i64, 0_i64) };
            if value == -1 {
                Err(errno())
            } else {
                Ok(())
            }
        }

        /// `SECCOMP_GET_ACTION_AVAIL`: whether the kernel knows `action`
        /// (the mode's violation action only: `SECCOMP_RET_ALLOW` is
        /// always known, and `SECCOMP_RET_KILL_PROCESS` of the arch and
        /// x32 checks dates from the same kernel, 4.14, as
        /// `SECCOMP_RET_LOG`).
        pub fn action_available(action: u32) -> Result<(), i32> {
            // SAFETY: `action` is a live, initialized `u32` that the kernel
            // only reads (four bytes) during the call; flags are 0.
            let value = unsafe {
                syscall(
                    SYS_SECCOMP,
                    SECCOMP_GET_ACTION_AVAIL,
                    0_i64,
                    (&raw const action).cast::<u8>(),
                )
            };
            if value == -1 {
                Err(errno())
            } else {
                Ok(())
            }
        }

        /// `SECCOMP_SET_MODE_FILTER` with TSYNC: 0 when every thread now
        /// has the filter, or the id of a thread that could not be synced
        /// (nothing was installed then).
        pub fn install_tsync(program: &[SockFilter]) -> Result<c_long, i32> {
            // At most `BPF_MAXINSNS` (4096) instructions: checked by
            // `program`; the kernel refuses more with `EINVAL` anyway.
            let len = u16::try_from(program.len()).map_err(|_| EINVAL)?;
            let fprog = SockFprog {
                len,
                filter: program.as_ptr(),
            };
            // SAFETY: `fprog` is a live, initialized `repr(C)` `sock_fprog`
            // whose `filter` points to `len` live, initialized `repr(C)`
            // `sock_filter`s (8 bytes each, checked above); the kernel only
            // reads them during the call (it copies the program). Both
            // outlive the call.
            let value = unsafe {
                syscall(
                    SYS_SECCOMP,
                    SECCOMP_SET_MODE_FILTER,
                    SECCOMP_FILTER_FLAG_TSYNC,
                    (&raw const fprog).cast::<u8>(),
                )
            };
            if value == -1 {
                Err(errno())
            } else {
                Ok(value)
            }
        }

        /// A raw syscall without arguments (tests: the x32 number of
        /// `getpid`, which the filter must refuse before the kernel
        /// dispatches it).
        #[cfg(test)]
        pub fn raw0(number: c_long) -> c_long {
            // SAFETY: a syscall number without arguments; whatever the
            // kernel does with it reads no memory of this process.
            unsafe { syscall(number) }
        }
    }
}

#[cfg(test)]
#[path = "seccomp_tests.rs"]
mod tests;
