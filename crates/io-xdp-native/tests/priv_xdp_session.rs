//! Privileged real-kernel smoke for the X00C native AF_XDP session and the
//! X00D XDP program/`bpf_link` lifecycle.
//!
//! Runs only with `RUSTER_PRIV_XDP=1`, normally through
//! `scripts/priv-xdp-smoke.sh`, which creates a dedicated network namespace
//! with its own two-queue veth pair, runs this prebuilt test inside it phase
//! by phase, and always deletes the namespace. When the variable is set,
//! every missing precondition (namespace identity, device, capability) fails
//! the test; it never skips. The tests refuse to run in the initial network
//! namespace, so they cannot touch a host interface. Each phase prints a
//! `priv_xdp_*: ... verified` marker that the script requires.
//!
//! Phases other than the session phase also need `RUSTER_PRIV_XDP_PHASE`
//! to name them, because they depend on namespace state the script sets up
//! (a peer address, a foreign program, a holder directory).

#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]

use std::{
    env, fs,
    net::UdpSocket,
    os::unix::fs::MetadataExt,
    process::Command,
    thread::sleep,
    time::{Duration, Instant},
};

use ruster_io_xdp_native::{
    abi::{XDP_COPY, XDP_USE_NEED_WAKEUP},
    AttachFailure, AttachStage, NativeRingError, NativeSession, NegotiatedMode, RingConfig,
    SessionConfig, SessionFailure, SessionStage, UmemConfig, ValidatedBindFlags, XdpAttachMode,
};

const FRAME_SIZE: u64 = 2_048;
const FRAME_COUNT: u64 = 256;
/// Peer-side TEST-NET-1 addresses, configured only inside the namespace.
const PEER_SOURCE: &str = "192.0.2.2:0";
const UNANSWERED_TARGET: &str = "192.0.2.1:9";

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("RUSTER_PRIV_XDP=1 requires {name}"))
}

fn netns_inode(path: &str) -> u64 {
    fs::metadata(path)
        .unwrap_or_else(|error| panic!("cannot stat {path}: {error}"))
        .ino()
}

/// Returns the device if this privileged phase was requested, after
/// proving the process runs inside the dedicated namespace.
fn requested(phase: Option<&str>) -> Option<String> {
    if env::var_os("RUSTER_PRIV_XDP").is_none() {
        eprintln!("priv_xdp: RUSTER_PRIV_XDP unset; privileged smoke not requested");
        return None;
    }
    assert_eq!(
        env::var("RUSTER_PRIV_XDP").as_deref(),
        Ok("1"),
        "RUSTER_PRIV_XDP must be exactly 1"
    );
    if let Some(phase) = phase {
        if env::var("RUSTER_PRIV_XDP_PHASE").as_deref() != Ok(phase) {
            eprintln!("priv_xdp: phase {phase} not selected");
            return None;
        }
    }
    let netns = required("RUSTER_PRIV_XDP_NETNS");
    let device = required("RUSTER_PRIV_XDP_DEVICE");
    assert!(
        netns.starts_with("ruster-") && !netns.contains('/'),
        "the smoke namespace must be a dedicated ruster-* namespace"
    );
    // Refuse anything but the dedicated namespace: never the host's.
    let current = netns_inode("/proc/self/ns/net");
    assert_eq!(
        current,
        netns_inode(&format!("/run/netns/{netns}")),
        "the test must run inside the named namespace"
    );
    assert_ne!(
        current,
        netns_inode("/proc/1/ns/net"),
        "refusing to run in the initial network namespace"
    );
    Some(device)
}

fn session_config(device: &str, queue: u32, mode_flag: u16) -> SessionConfig {
    SessionConfig::new(
        device,
        queue,
        ValidatedBindFlags::new(XDP_USE_NEED_WAKEUP | mode_flag).expect("valid flags"),
        RingConfig::new(64, 64, 64, 64).expect("valid rings"),
        // frame-count >= fill + tx + generated, as configuration requires.
        UmemConfig::new(FRAME_COUNT as u32, FRAME_SIZE as u32, 0, 192, 64, 0).expect("valid UMEM"),
    )
    .expect("valid session config")
}

/// Opens `config`, retrying only the bounded transient bind EBUSY that
/// follows the previous session's deferred kernel pool release.
fn open_after_release(config: &SessionConfig) -> NativeSession {
    for _ in 0..100 {
        match NativeSession::open(config) {
            Ok(session) => return session,
            Err(error)
                if (error.stage(), error.failure())
                    == (SessionStage::Bind, SessionFailure::Busy) =>
            {
                sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("session open failed: {error:?}"),
        }
    }
    panic!("queue still busy one second after teardown");
}

/// XDP program attached to `device` as reported by `ip -details`, in this
/// namespace only: `(mode keyword, program id, program name)`.
fn attached_program(device: &str) -> Option<(String, u32, String)> {
    let output = Command::new("ip")
        .args(["-details", "link", "show", "dev", device])
        .output()
        .expect("run ip link show");
    assert!(output.status.success(), "ip link show {device} failed");
    let text = String::from_utf8(output.stdout).expect("ip output is UTF-8");
    // The link line names the mode (`xdp`, `xdpgeneric`); the details line
    // is `prog/xdp id N name NAME ...` in either mode.
    let mode = text
        .lines()
        .next()
        .and_then(|line| {
            line.split_whitespace()
                .find(|word| matches!(*word, "xdp" | "xdpgeneric" | "xdpoffload" | "xdpmulti"))
        })
        .unwrap_or("none")
        .to_owned();
    let mut words = text.split_whitespace();
    while let Some(word) = words.next() {
        if word.starts_with("prog/xdp") {
            assert_eq!(words.next(), Some("id"), "unexpected ip output: {text}");
            let id = words
                .next()
                .and_then(|id| id.parse().ok())
                .expect("program id");
            let name = match words.next() {
                Some("name") => words.next().unwrap_or_default().to_owned(),
                _ => String::new(),
            };
            return Some((mode, id, name));
        }
    }
    None
}

/// Waits (bounded) until no XDP program is attached to `device`.
fn wait_detached(device: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while attached_program(device).is_some() {
        assert!(
            Instant::now() < deadline,
            "XDP program still attached two seconds after detach"
        );
        sleep(Duration::from_millis(10));
    }
}

fn fill_all(session: &mut NativeSession) {
    let mut rings = session.rings().expect("ring views");
    let mut fill = rings.fill.reserve(64).expect("empty Fill ring");
    for frame in 0..64_u64 {
        fill.write(frame * FRAME_SIZE).expect("Fill entry");
    }
    fill.release_submit()
        .expect("Fill publication")
        .need_wakeup()
        .expect("v6.8 ring flags");
}

#[test]
fn priv_xdp_session_opens_copy_mode_on_netns_veth() {
    let Some(device) = requested(None) else {
        return;
    };

    // Copy mode on the namespace-local veth: rings are mapped and usable.
    let mut session =
        NativeSession::open(&session_config(&device, 0, XDP_COPY)).expect("copy session opens");
    assert_eq!(session.mode(), NegotiatedMode::Copy);
    assert!(!session.zero_copy_fallback());
    assert_ne!(session.ifindex(), 0);
    assert_eq!(session.queue(), 0);
    assert_eq!(session.xdp_attach_mode(), None);
    {
        let mut rings = session.rings().expect("ring views");
        assert_eq!(
            (
                rings.fill.capacity(),
                rings.completion.capacity(),
                rings.rx.capacity(),
                rings.tx.capacity()
            ),
            (64, 64, 64, 64)
        );
        assert_eq!(rings.umem.byte_len(), FRAME_COUNT * FRAME_SIZE);
        let mut fill = rings.fill.reserve(64).expect("empty Fill ring");
        for frame in 0..64_u64 {
            fill.write(frame * FRAME_SIZE).expect("Fill entry");
        }
        fill.release_submit()
            .expect("Fill publication")
            .need_wakeup()
            .expect("v6.8 ring flags");
        assert_eq!(
            rings.fill.reserve(1).map(|_| ()),
            Err(NativeRingError::RingFull)
        );
        // Without an XDP program nothing is redirected to the socket.
        assert_eq!(
            rings.rx.acquire(1).map(|_| ()),
            Err(NativeRingError::RingEmpty)
        );
        assert_eq!(
            rings.completion.acquire(1).map(|_| ()),
            Err(NativeRingError::RingEmpty)
        );
        rings
            .tx
            .reserve(64)
            .expect("empty TX ring")
            .release_cancel();
    }

    // The bound queue is exclusive: a second socket gets a typed EBUSY.
    let busy = NativeSession::open(&session_config(&device, 0, XDP_COPY))
        .expect_err("second socket on the same queue");
    assert_eq!(
        (busy.stage(), busy.failure()),
        (SessionStage::Bind, SessionFailure::Busy)
    );
    session.close().expect("clean teardown");

    // After teardown the queue becomes free again. Linux releases the
    // buffer pool's queue registration from a deferred work item after the
    // last socket reference drops, so a reopen may briefly see EBUSY.
    open_after_release(&session_config(&device, 0, XDP_COPY))
        .close()
        .expect("clean teardown");

    // Auto mode on veth: zero-copy is unsupported, so copy after fallback.
    let auto = open_after_release(&session_config(&device, 0, 0));
    assert_eq!(
        (auto.mode(), auto.zero_copy_fallback()),
        (NegotiatedMode::Copy, true)
    );
    auto.close().expect("clean teardown");

    // Real-kernel errno classification. The smoke veth has two queues.
    let bad_queue = NativeSession::open(&session_config(&device, 2, XDP_COPY))
        .expect_err("veth has two queues");
    assert_eq!(
        (bad_queue.stage(), bad_queue.failure()),
        (SessionStage::Bind, SessionFailure::InvalidArgument)
    );
    let missing = NativeSession::open(&session_config("ruster-absent", 0, XDP_COPY))
        .expect_err("absent device");
    assert_eq!(
        (missing.stage(), missing.failure()),
        (SessionStage::InterfaceLookup, SessionFailure::NoSuchDevice)
    );
    eprintln!("priv_xdp_session: copy, auto fallback, EBUSY, EINVAL, ENODEV verified");
}

#[test]
fn priv_xdp_attach_redirects_refuses_second_and_detaches_on_netns_veth() {
    let Some(device) = requested(Some("attach")) else {
        return;
    };
    assert_eq!(attached_program(&device), None, "veth starts without XDP");

    let mut session = open_after_release(&session_config(&device, 0, XDP_COPY));
    fill_all(&mut session);
    session
        .attach_xdp(XdpAttachMode::Native)
        .expect("native attach on veth");
    assert_eq!(session.xdp_attach_mode(), Some(XdpAttachMode::Native));
    let (mode, id, name) = attached_program(&device).expect("program attached");
    assert_eq!((mode.as_str(), name.as_str()), ("xdp", "ruster_xsk"));

    // A frame sent from the peer end (an ARP request for an address nobody
    // owns) is redirected into the RX ring of queue 0.
    let peer = UdpSocket::bind(PEER_SOURCE).expect("peer address configured by the script");
    let deadline = Instant::now() + Duration::from_secs(3);
    let descriptor = loop {
        peer.send_to(b"ruster", UNANSWERED_TARGET)
            .expect("peer send");
        let mut rings = session.rings().expect("ring views");
        if let Ok(mut acquisition) = rings.rx.acquire(1) {
            let descriptor = acquisition.read().expect("RX descriptor");
            acquisition.release_consume().expect("RX consume");
            break descriptor;
        }
        assert!(
            Instant::now() < deadline,
            "no frame reached the RX ring within three seconds"
        );
        sleep(Duration::from_millis(20));
    };
    assert!(descriptor.len >= 42, "shorter than an ARP frame");
    assert!(descriptor.address + u64::from(descriptor.len) <= FRAME_COUNT * FRAME_SIZE);

    // A second attach on the same interface, from another socket on the
    // other queue, is refused in either mode and leaves the link in place.
    let mut second = open_after_release(&session_config(&device, 1, XDP_COPY));
    for mode in [XdpAttachMode::Native, XdpAttachMode::Generic] {
        let error = second.attach_xdp(mode).expect_err("existing link");
        assert_eq!(
            (error.stage(), error.failure()),
            (AttachStage::CreateLink, AttachFailure::ExistingProgram),
            "{mode:?}"
        );
    }
    assert_eq!(second.xdp_attach_mode(), None);
    second.close().expect("second session teardown");
    assert_eq!(
        attached_program(&device).map(|(_, id, _)| id),
        Some(id),
        "refused attach changed the attached program"
    );

    // Detach by closing the link; then generic mode attaches and detaches.
    session.detach_xdp().expect("detach");
    wait_detached(&device);
    session
        .attach_xdp(XdpAttachMode::Generic)
        .expect("generic attach on veth");
    let (mode, _, name) = attached_program(&device).expect("generic program attached");
    assert_eq!((mode.as_str(), name.as_str()), ("xdpgeneric", "ruster_xsk"));
    // Close detaches before releasing the socket.
    session.close().expect("attached session teardown");
    wait_detached(&device);
    eprintln!(
        "priv_xdp_attach: native redirect to RX ring, ExistingProgram for a second attach, \
         detach, generic attach, close-detach verified"
    );
}

#[test]
fn priv_xdp_attach_refuses_foreign_program_and_leaves_it_untouched() {
    let Some(device) = requested(Some("foreign")) else {
        return;
    };
    let foreign = attached_program(&device).expect("script pre-attached a foreign program");
    assert_eq!(foreign.0, "xdpgeneric");
    assert_ne!(foreign.2, "ruster_xsk");

    let mut session = open_after_release(&session_config(&device, 0, XDP_COPY));
    for mode in [XdpAttachMode::Generic, XdpAttachMode::Native] {
        let error = session.attach_xdp(mode).expect_err("foreign program");
        assert_eq!(
            (error.stage(), error.failure()),
            (AttachStage::CreateLink, AttachFailure::ExistingProgram),
            "{mode:?}"
        );
        assert_eq!(attached_program(&device), Some(foreign.clone()));
    }
    session.close().expect("teardown");
    assert_eq!(attached_program(&device), Some(foreign));
    eprintln!(
        "priv_xdp_foreign: ExistingProgram in both modes, foreign program untouched verified"
    );
}

/// Attaches and then waits to be killed by the script with SIGKILL.
#[test]
fn priv_xdp_attach_holder_waits_for_sigkill() {
    let Some(device) = requested(Some("holder")) else {
        return;
    };
    let ready = required("RUSTER_PRIV_XDP_READY");
    let mut session = open_after_release(&session_config(&device, 0, XDP_COPY));
    session
        .attach_xdp(XdpAttachMode::Native)
        .expect("native attach");
    fs::write(&ready, format!("{}\n", std::process::id())).expect("write ready file");
    eprintln!("priv_xdp_holder: attached; waiting for SIGKILL");
    // The script kills this process; returning normally means it did not.
    sleep(Duration::from_secs(60));
    panic!("holder was not killed within 60 seconds");
}
