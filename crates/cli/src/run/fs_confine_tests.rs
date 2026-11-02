//! Tests of the filesystem confinement: the pure policy, and the live
//! Landlock ruleset on spawned threads of this test binary (Landlock
//! confines only the calling thread, so the other tests are unaffected;
//! it needs no privilege).

use std::path::Path;

use super::*;

#[test]
fn the_handled_rights_are_those_of_the_abi_up_to_abi_5() {
    assert_eq!(handled_access(0), 0);
    assert_eq!(handled_access(1), 0x1FFF, "13 rights of ABI 1");
    assert_eq!(handled_access(2), 0x3FFF, "+ refer");
    assert_eq!(handled_access(3), 0x7FFF, "+ truncate");
    assert_eq!(handled_access(4), 0x7FFF, "ABI 4 adds network rights only");
    for abi in [5, 6, 7, 8, 9, 100, u32::MAX] {
        assert_eq!(handled_access(abi), 0xFFFF, "+ ioctl_dev, nothing later");
    }
    // Every right is one bit, and ABI 1 has the first 13.
    let all = [
        ACCESS_EXECUTE,
        ACCESS_WRITE_FILE,
        ACCESS_READ_FILE,
        ACCESS_READ_DIR,
        ACCESS_REMOVE_DIR,
        ACCESS_REMOVE_FILE,
        ACCESS_MAKE_CHAR,
        ACCESS_MAKE_DIR,
        ACCESS_MAKE_REG,
        ACCESS_MAKE_SOCK,
        ACCESS_MAKE_FIFO,
        ACCESS_MAKE_BLOCK,
        ACCESS_MAKE_SYM,
        ACCESS_REFER,
        ACCESS_TRUNCATE,
        ACCESS_IOCTL_DEV,
    ];
    for (bit, right) in all.into_iter().enumerate() {
        assert_eq!(right, 1 << bit);
    }
}

#[test]
fn every_grant_is_read_only_and_handled_from_abi_1() {
    for grant in [
        Grant::ConfigDirectory,
        Grant::ConfigTarget,
        Grant::Process,
        Grant::NetSysctls,
        Grant::Executable,
    ] {
        let access = grant.access();
        assert_ne!(access & ACCESS_READ_FILE, 0, "{grant:?}");
        assert_eq!(
            access & !(ACCESS_READ_FILE | ACCESS_READ_DIR),
            0,
            "{grant:?} grants only reading"
        );
        assert_eq!(access & !handled_access(1), 0, "{grant:?}");
    }
    // Only the process directory can be listed (`/proc/self/task`).
    assert_eq!(Grant::Process.access(), ACCESS_READ_FILE | ACCESS_READ_DIR);
    assert_eq!(Grant::ConfigDirectory.access(), ACCESS_READ_FILE);
    assert_eq!(Grant::NetSysctls.access(), ACCESS_READ_FILE);
    assert_eq!(Grant::Executable.access(), ACCESS_READ_FILE);
}

#[test]
fn the_config_directory_is_the_parent_or_the_working_directory() {
    for (path, directory) in [
        ("/etc/ruster/router.toml", "/etc/ruster"),
        ("conf/router.toml", "conf"),
        ("./router.toml", "."),
        ("router.toml", "."),
        ("/router.toml", "/"),
        ("../x/router.toml", "../x"),
    ] {
        assert_eq!(
            config_directory(Path::new(path)),
            Path::new(directory),
            "{path}"
        );
    }
}

fn ids(ids: &[u32]) -> std::collections::BTreeSet<u32> {
    ids.iter().copied().collect()
}

#[test]
fn exactly_the_threads_of_the_process_must_be_confined() {
    assert_eq!(
        check_threads(&ids(&[10, 11, 12]), &ids(&[12, 10, 11])),
        Ok(())
    );
    assert_eq!(check_threads(&ids(&[7]), &ids(&[7])), Ok(()));
    for (confined, tasks) in [
        // One thread missing.
        (&[10, 11][..], &[10, 11, 12][..]),
        // A thread that is not in the process (or has ended).
        (&[10, 11, 12, 13][..], &[10, 11, 12][..]),
        // The same number, but another thread: a counter would pass this.
        (&[10, 11, 13][..], &[10, 11, 12][..]),
        (&[][..], &[1][..]),
    ] {
        assert_eq!(
            check_threads(&ids(confined), &ids(tasks)),
            Err(FsFailure::NotConfined(Unconfined::Threads)),
            "{confined:?} {tasks:?}"
        );
    }
    assert_eq!(
        check_threads(&ids(&[]), &ids(&[])),
        Err(FsFailure::Unreadable)
    );
    assert_eq!(
        check_threads(&ids(&[5]), &ids(&[])),
        Err(FsFailure::Unreadable)
    );
}

#[test]
fn the_root_directory_is_refused_and_broad_ones_are_named() {
    assert_eq!(classify_directory(Path::new("/")), DirectoryScope::Root);
    for broad in ["/etc", "/home", "/root", "/usr", "/var"] {
        assert_eq!(
            classify_directory(Path::new(broad)),
            DirectoryScope::Broad(broad)
        );
    }
    for dedicated in [
        "/etc/ruster",
        "/home/router/conf",
        "/run/ruster-smoke.x",
        "/srv",
        "/etcetera",
        "/var/lib/ruster",
    ] {
        assert_eq!(
            classify_directory(Path::new(dedicated)),
            DirectoryScope::Dedicated,
            "{dedicated}"
        );
    }
    assert_eq!(
        broad_warning("/etc"),
        "warning: fs-confine code=CONFIG_DIRECTORY_BROAD directory=/etc: every file beneath \
         it that the process's user may read stays readable; keep the config in a directory \
         of its own (such as /etc/ruster)"
    );
}

#[test]
fn tcp_is_handled_from_abi_4() {
    for abi in 0..4 {
        assert_eq!(handled_net_access(abi), 0, "ABI {abi}");
    }
    for abi in [4, 5, 8, 100] {
        assert_eq!(handled_net_access(abi), 0b11, "ABI {abi}");
    }
    assert_eq!(ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP, 0b11);
}

#[test]
fn failures_are_value_free_codes() {
    for (failure, code) in [
        (FsFailure::Unsupported, "code=LANDLOCK_UNSUPPORTED"),
        (FsFailure::Disabled, "code=LANDLOCK_DISABLED"),
        (FsFailure::Blocked, "code=LANDLOCK_BLOCKED"),
        (FsFailure::ConfigDirectoryRoot, "code=CONFIG_DIRECTORY_ROOT"),
        (
            FsFailure::Syscall {
                step: FsStep::Abi,
                errno: 1,
            },
            "code=ABI/ERRNO_1",
        ),
        (
            FsFailure::Syscall {
                step: FsStep::Open(Grant::ConfigDirectory),
                errno: 2,
            },
            "code=OPEN.CONFIG_DIRECTORY/ERRNO_2",
        ),
        (
            FsFailure::Syscall {
                step: FsStep::AddRule(Grant::NetSysctls),
                errno: 22,
            },
            "code=ADD_RULE.NET_SYSCTLS/ERRNO_22",
        ),
        (
            FsFailure::Syscall {
                step: FsStep::Restrict,
                errno: 1,
            },
            "code=RESTRICT/ERRNO_1",
        ),
        (
            FsFailure::Syscall {
                step: FsStep::NoNewPrivs,
                errno: 22,
            },
            "code=NO_NEW_PRIVS/ERRNO_22",
        ),
        (
            FsFailure::Syscall {
                step: FsStep::Probe,
                errno: 5,
            },
            "code=PROBE/ERRNO_5",
        ),
        (FsFailure::NotPrepared, "code=NOT_PREPARED"),
        (
            FsFailure::NotConfined(Unconfined::Probe),
            "code=NOT_CONFINED/PROBE",
        ),
        (
            FsFailure::NotConfined(Unconfined::Threads),
            "code=NOT_CONFINED/THREADS",
        ),
        (FsFailure::Unreadable, "code=STATUS_UNREADABLE"),
    ] {
        assert_eq!(failure.to_string(), code);
        // Every failure the operator can fix with a setting has a hint
        // naming `--fs-confine off`; the others none.
        let hinted = matches!(
            failure,
            FsFailure::Unsupported
                | FsFailure::Disabled
                | FsFailure::Blocked
                | FsFailure::ConfigDirectoryRoot
        );
        assert_eq!(failure.hint().is_some(), hinted, "{failure:?}");
        if let Some(hint) = failure.hint() {
            assert!(hint.contains("--fs-confine off"), "{hint}");
        }
    }
    assert!(FsFailure::Blocked
        .hint()
        .unwrap()
        .contains("landlock_create_ruleset, landlock_add_rule, and landlock_restrict_self"));
}

#[test]
fn the_state_has_a_line_and_stats_fields() {
    let confined = FsState::Confined(FsReport {
        abi: 6,
        rules: 4,
        threads: 5,
    });
    assert_eq!(
        confined.line(),
        "filesystem confined: mode=landlock abi=6 rules=4 threads=5"
    );
    let mut out = String::new();
    super::super::stats::write_fields(&mut out, None, &confined);
    assert_eq!(
        out,
        "fs.confine=landlock\nfs.abi=6\nfs.rules=4\nfs.threads=5\n"
    );
    assert_eq!(
        FsState::Off.line(),
        "warning: fs-confine=off (--fs-confine off): no filesystem confinement; every file \
         the process's user may read stays readable"
    );
    let mut out = String::new();
    super::super::stats::write_fields(&mut out, None, &FsState::Off);
    assert_eq!(out, "fs.confine=off\nfs.abi=0\nfs.rules=0\nfs.threads=0\n");
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
mod live {
    use std::fs;
    use std::io::ErrorKind;
    use std::path::{Path, PathBuf};

    use super::super::linux::Prepared;
    use super::super::{FsFailure, FsStep, Grant};

    /// A scratch directory under the test temp directory: `conf/` with the
    /// config, `outside/` next to it, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "ruster-h11-{name}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("conf")).unwrap();
            fs::create_dir_all(root.join("outside")).unwrap();
            fs::write(root.join("conf/router.toml"), "a = 1\n").unwrap();
            fs::write(root.join("conf/other.toml"), "b = 2\n").unwrap();
            fs::write(root.join("outside/secret"), "s\n").unwrap();
            Self(root)
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.0.join(relative)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn readable(path: &Path) -> Result<(), ErrorKind> {
        fs::read(path).map(drop).map_err(|error| error.kind())
    }

    fn denied(path: &Path) {
        assert_eq!(
            readable(path),
            Err(ErrorKind::PermissionDenied),
            "{}",
            path.display()
        );
    }

    /// Prepares the ruleset for `config` and runs `check` on a new thread
    /// that confined itself with it.
    fn confined<T: Send + 'static>(
        config: PathBuf,
        check: impl FnOnce(&Prepared) -> T + Send + 'static,
    ) -> T {
        std::thread::spawn(move || {
            let prepared = match Prepared::new(&config) {
                Ok(prepared) => prepared,
                Err(failure) => panic!(
                    "Landlock is needed for these tests (Linux 5.13+, landlock in \
                     /sys/kernel/security/lsm): {failure}"
                ),
            };
            prepared.restrict_thread().expect("restrict");
            check(&prepared)
        })
        .join()
        .expect("confined thread")
    }

    #[test]
    fn a_confined_thread_reads_only_what_the_run_reads() {
        let scratch = Scratch::new("view");
        let config = scratch.path("conf/router.toml");
        let outside = scratch.path("outside/secret");
        let other = scratch.path("conf/other.toml");
        let (abi, rules) = confined(config.clone(), move |prepared| {
            // The reload: the config, also another file of its directory
            // (an atomic replace writes one first).
            readable(&config).expect("config");
            readable(&other).expect("config directory");
            // The verifications and the strict effective uid.
            readable(Path::new("/proc/self/status")).expect("status");
            readable(Path::new("/proc/thread-self/status")).expect("thread status");
            let tasks = fs::read_dir("/proc/self/task").expect("task list");
            let mut read = 0;
            for task in tasks {
                // Other test threads may end between the listing and the
                // read (`NotFound`, or `ESRCH` while reading); only a
                // refusal is a confinement failure.
                match readable(&task.expect("task").path().join("status")) {
                    Ok(()) => read += 1,
                    Err(ErrorKind::PermissionDenied) => panic!("task status refused"),
                    Err(_) => {}
                }
            }
            assert!(read >= 1);
            // The link watch.
            readable(Path::new("/proc/sys/net/ipv4/conf/lo/forwarding")).expect("ipv4 sysctl");
            readable(Path::new("/proc/sys/net/ipv4/ip_forward")).expect("ip_forward");
            // Backtrace symbols.
            readable(&std::env::current_exe().unwrap()).expect("executable");
            // Not even listable: the config directory, `/`.
            assert_eq!(
                fs::read_dir(config.parent().unwrap())
                    .map(drop)
                    .map_err(|e| e.kind()),
                Err(ErrorKind::PermissionDenied)
            );
            assert_eq!(
                fs::read_dir("/").map(drop).map_err(|e| e.kind()),
                Err(ErrorKind::PermissionDenied)
            );
            // Everything else.
            denied(&outside);
            for path in [
                "/etc/passwd",
                "/proc/1/status",
                "/proc/self/root/etc/passwd",
                "/proc/self/cwd/Cargo.toml",
                "/proc/sys/kernel/osrelease",
                "/proc/version",
                "/sys/class/net/lo/mtu",
                "/dev/urandom",
            ] {
                denied(Path::new(path));
            }
            // Metadata and links are not file opens.
            fs::symlink_metadata("/etc/passwd").expect("lstat");
            fs::read_link("/proc/self/exe").expect("readlink");
            // No write, create, or remove, also in the config directory.
            assert_eq!(
                fs::OpenOptions::new()
                    .append(true)
                    .open(&config)
                    .map(drop)
                    .map_err(|e| e.kind()),
                Err(ErrorKind::PermissionDenied)
            );
            assert_eq!(
                fs::write(config.with_file_name("new.toml"), "c").map_err(|e| e.kind()),
                Err(ErrorKind::PermissionDenied)
            );
            assert_eq!(
                fs::remove_file(&other).map_err(|e| e.kind()),
                Err(ErrorKind::PermissionDenied)
            );
            (prepared.abi(), prepared.rules())
        });
        assert!(abi >= 1);
        // Config directory, process, net sysctls, executable.
        assert_eq!(rules, 4);
        // The other threads of this process are not confined.
        readable(&scratch.path("outside/secret")).expect("unconfined thread");
        assert!(fs::read_dir("/").is_ok());
    }

    #[test]
    fn an_atomic_replace_of_the_config_stays_readable() {
        let scratch = Scratch::new("replace");
        let config = scratch.path("conf/router.toml");
        let next = scratch.path("conf/router.toml.next");
        let (go, wait) = std::sync::mpsc::channel::<()>();
        let (done, confined_ready) = std::sync::mpsc::channel::<()>();
        let reader = {
            let config = config.clone();
            std::thread::spawn(move || {
                confined(config.clone(), move |_| {
                    done.send(()).unwrap();
                    wait.recv().unwrap();
                    fs::read_to_string(&config).expect("replaced config")
                })
            })
        };
        confined_ready.recv().unwrap();
        // By an unconfined thread: a new inode renamed over the old one.
        fs::write(&next, "a = 2\n").unwrap();
        fs::rename(&next, &config).unwrap();
        go.send(()).unwrap();
        assert_eq!(reader.join().unwrap(), "a = 2\n");
    }

    #[test]
    fn a_symlinked_config_grants_its_target_directory_too() {
        let scratch = Scratch::new("symlink");
        fs::create_dir_all(scratch.path("link")).unwrap();
        let config = scratch.path("link/router.toml");
        std::os::unix::fs::symlink(scratch.path("conf/router.toml"), &config).unwrap();
        let other = scratch.path("conf/other.toml");
        let outside = scratch.path("outside/secret");
        let link = config.clone();
        let rules = confined(config, move |prepared| {
            readable(&link).expect("through the link");
            readable(&other).expect("target directory");
            denied(&outside);
            prepared.rules()
        });
        assert_eq!(rules, 5, "link directory, target directory, and the rest");
        // A symlink in the granted directory that leads elsewhere is
        // refused: what counts is where the open resolves.
        let escape = scratch.path("conf/escape");
        std::os::unix::fs::symlink(scratch.path("outside/secret"), &escape).unwrap();
        confined(scratch.path("conf/router.toml"), move |_| denied(&escape));
    }

    #[test]
    fn a_relative_config_grants_the_working_directory() {
        // The test binary's working directory is the crate directory.
        let rules = confined(PathBuf::from("Cargo.toml"), |prepared| {
            readable(Path::new("Cargo.toml")).expect("relative config");
            readable(Path::new("src/main.rs")).expect("beneath it");
            denied(Path::new("../../Cargo.toml"));
            prepared.rules()
        });
        assert_eq!(rules, 4, "`.` and the resolved directory are one");
    }

    #[test]
    fn a_missing_config_directory_fails_the_preparation() {
        let scratch = Scratch::new("missing");
        let failure = Prepared::new(&scratch.path("nope/router.toml"))
            .err()
            .expect("refused");
        assert_eq!(
            failure,
            FsFailure::Syscall {
                step: FsStep::Open(Grant::ConfigDirectory),
                errno: 2,
            }
        );
    }

    #[test]
    fn a_config_in_the_root_directory_is_refused() {
        // Refused before anything else (the file need not exist).
        assert_eq!(
            Prepared::new(Path::new("/ruster-h11-no-such-config.toml"))
                .err()
                .expect("refused"),
            FsFailure::ConfigDirectoryRoot
        );
        // Also when only the resolved file is in `/`.
        let scratch = Scratch::new("rootlink");
        let link = scratch.path("conf/root.toml");
        let target = fs::read_dir("/")
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| fs::symlink_metadata(path).is_ok_and(|m| m.is_file()))
            .or_else(|| {
                // No regular file in `/`: a directory entry resolves the
                // same way (its parent is `/`).
                fs::read_dir("/")
                    .unwrap()
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .find(|path| fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()))
            })
            .expect("an entry of /");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            Prepared::new(&link).err().expect("refused"),
            FsFailure::ConfigDirectoryRoot
        );
    }

    #[test]
    fn a_config_in_a_broad_directory_is_named_for_the_warning() {
        let prepared = Prepared::new(Path::new("/etc/passwd")).expect("prepared");
        assert_eq!(prepared.broad(), Some("/etc"));
        let scratch = Scratch::new("dedicated");
        let prepared = Prepared::new(&scratch.path("conf/router.toml")).expect("prepared");
        assert_eq!(prepared.broad(), None);
        // A dedicated name that resolves into a broad directory is named.
        let link = scratch.path("conf/passwd.toml");
        std::os::unix::fs::symlink("/etc/passwd", &link).unwrap();
        assert_eq!(
            Prepared::new(&link).expect("prepared").broad(),
            Some("/etc")
        );
    }

    #[test]
    fn a_confined_thread_cannot_use_tcp_from_abi_4() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().unwrap();
        let scratch = Scratch::new("tcp");
        let (abi, connect, bind) = confined(scratch.path("conf/router.toml"), move |prepared| {
            let connect = std::net::TcpStream::connect(address)
                .map(drop)
                .map_err(|e| e.kind());
            let bind = std::net::TcpListener::bind("127.0.0.1:0")
                .map(drop)
                .map_err(|e| e.kind());
            // UDP is not a Landlock right.
            std::net::UdpSocket::bind("127.0.0.1:0").expect("udp");
            (prepared.abi(), connect, bind)
        });
        if abi >= 4 {
            assert_eq!(connect, Err(ErrorKind::PermissionDenied));
            assert_eq!(bind, Err(ErrorKind::PermissionDenied));
        } else {
            assert_eq!(connect, Ok(()));
        }
        // This (unconfined) thread still can.
        std::net::TcpStream::connect(address).expect("unconfined connect");
    }

    #[test]
    fn the_self_check_refuses_an_unconfined_thread() {
        // This test thread is not confined: it can list `/`.
        assert_eq!(
            super::super::linux::probe(),
            Err(FsFailure::NotConfined(super::super::Unconfined::Probe))
        );
        let scratch = Scratch::new("probe");
        confined(scratch.path("conf/router.toml"), |_| {
            super::super::linux::probe().expect("confined");
        });
    }

    #[test]
    fn a_second_confinement_of_a_thread_is_harmless() {
        let scratch = Scratch::new("twice");
        let config = scratch.path("conf/router.toml");
        confined(config.clone(), move |prepared| {
            prepared.restrict_thread().expect("again");
            readable(&config).expect("config");
            denied(Path::new("/etc/passwd"));
        });
    }
}
