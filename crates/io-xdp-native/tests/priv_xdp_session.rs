//! Privileged real-kernel smoke for the X00C native AF_XDP session, the
//! X00D XDP program/`bpf_link` lifecycle, the X01 RX/Fill engine, and the
//! X02 TX/Completion half, the X03 generated frames, and the X04a core
//! adapter forwarding between two ports.
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
    io::{BufRead, BufReader},
    net::UdpSocket,
    num::{NonZeroU128, NonZeroU32},
    os::unix::fs::MetadataExt,
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use ruster_core::{
    forward_batch, BackendStats, ForwardingSnapshot, GeneratedPacketBatch, GeneratedPacketIo, IfId,
    Interface, Ipv4Address, MacAddress, Neighbor, NoTrace, PacketIo, PublicationQuiescence, Route,
};

use ruster_io_xdp_native::{
    abi::{XDP_COPY, XDP_USE_NEED_WAKEUP},
    AttachFailure, AttachStage, DatapathError, DrainOutcome, GeneratedAllocError,
    GeneratedRejectReason, KickOutcome, NativeRingError, NativeSession, NeedWakeup, NegotiatedMode,
    RingConfig, RingsError, RxFillConfig, RxFillEngine, SessionConfig, SessionFailure,
    SessionStage, UmemConfig, UmemDomainId, ValidatedBindFlags, XdpAttachMode, XdpIoError,
    XdpPacketIo, XdpPort, XdpPortConfig, XDP_PACKET_HEADROOM,
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
    // Queue 2 on a 2/2-queue veth: the TX queue check refuses it before
    // any resource (the bind would have failed with EINVAL).
    let bad_queue = NativeSession::open(&session_config(&device, 2, XDP_COPY))
        .expect_err("veth has two queues");
    assert_eq!(
        (bad_queue.stage(), bad_queue.failure()),
        (SessionStage::TxQueueCheck, SessionFailure::NoTxQueue)
    );
    // RX 4 / TX 2: Linux would bind queue 2 (below max(RX, TX)) and then
    // never transmit from it; the session refuses it. Queue 1 has both.
    let asymmetric = required("RUSTER_PRIV_XDP_ASYM_DEVICE");
    let no_tx =
        NativeSession::open(&session_config(&asymmetric, 2, XDP_COPY)).expect_err("RX-only queue");
    assert_eq!(
        (no_tx.stage(), no_tx.failure()),
        (SessionStage::TxQueueCheck, SessionFailure::NoTxQueue)
    );
    NativeSession::open(&session_config(&asymmetric, 1, XDP_COPY))
        .expect("queue with RX and TX opens")
        .close()
        .expect("asymmetric session teardown");
    let missing = NativeSession::open(&session_config("ruster-absent", 0, XDP_COPY))
        .expect_err("absent device");
    assert_eq!(
        (missing.stage(), missing.failure()),
        (SessionStage::InterfaceLookup, SessionFailure::NoSuchDevice)
    );
    eprintln!("priv_xdp_session: copy, auto fallback, EBUSY, no-TX-queue refusal, ENODEV verified");
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
    // owns) is redirected into the RX ring of queue 0. This relies on the
    // peer's frames landing on RX queue 0 of the two-queue veth: frames on
    // queue 1 have no socket and are dropped by the XDP_DROP fallback
    // (XDP-050), so if this check becomes flaky, look at the veth queue
    // selection first.
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
fn priv_xdp_engine_validates_and_recycles_peer_frames() {
    let Some(device) = requested(Some("engine")) else {
        return;
    };
    assert_eq!(attached_program(&device), None, "veth starts without XDP");
    let mut session = open_after_release(&session_config(&device, 0, XDP_COPY));
    // Attach first: the engine then borrows the session's mappings for its
    // whole life. Frames arriving before the first refill are dropped by
    // the kernel (empty Fill ring), not mis-owned.
    session
        .attach_xdp(XdpAttachMode::Native)
        .expect("native attach on veth");
    let peer = UdpSocket::bind(PEER_SOURCE).expect("peer address configured by the script");
    {
        let datapath = session.take_datapath().expect("first datapath take");
        let mut engine = RxFillEngine::new(
            datapath,
            UmemDomainId::new(NonZeroU128::new(0x5333).expect("nonzero")),
            RxFillConfig::new(NonZeroU32::new(64).expect("nonzero")),
        )
        .expect("engine over the live mappings");
        assert_eq!(engine.counters().fill_published, 64);
        engine.audit().expect("primed engine audit");

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut verified = 0_u32;
        while verified < 2 {
            peer.send_to(b"ruster", UNANSWERED_TARGET)
                .expect("peer send");
            sleep(Duration::from_millis(20));
            let mut batch = engine.poll(16).expect("poll");
            while let Some(frame) = batch.next_frame() {
                let bytes = frame.bytes();
                assert_eq!(bytes.len(), frame.len() as usize);
                assert!(frame.frame().index() < 192, "RX pool frame");
                // Copy mode places data exactly after the kernel headroom
                // (user headroom is 0): `xsk_buff_alloc` data at
                // `XDP_PACKET_HEADROOM`, and the redirect program never
                // moves it (XDP-067).
                assert_eq!(
                    frame.descriptor().data_offset(),
                    XDP_PACKET_HEADROOM,
                    "copy-mode RX data offset"
                );
                // The peer's unanswered ARP request: broadcast, EtherType ARP.
                if bytes.len() >= 42 && bytes[..6] == [0xff; 6] && bytes[12..14] == [0x08, 0x06] {
                    verified += 1;
                }
                frame.recycle();
            }
            engine.audit().expect("engine audit after poll");
            assert!(
                Instant::now() < deadline,
                "no ARP frame passed the engine within five seconds: {:?}",
                engine.counters()
            );
        }
        // Recycled frames go back to Fill on the next refill.
        let _ = engine.refill().expect("refill recycled frames");
        engine.audit().expect("engine audit after refill");
        let counters = engine.counters();
        assert_eq!(counters.rx_invalid_total(), 0, "{counters:?}");
        assert!(counters.rx_recycled >= 2);
        assert!(
            counters.fill_published >= 64 + counters.rx_recycled,
            "{counters:?}"
        );
    }
    // The bundle is never lent twice, and raw views never alias it.
    assert_eq!(
        session.take_datapath().map(|_| ()),
        Err(DatapathError::AlreadyTaken)
    );
    assert_eq!(session.rings().map(|_| ()), Err(RingsError::DatapathTaken));
    session.close().expect("attached session teardown");
    wait_detached(&device);
    eprintln!(
        "priv_xdp_engine: peer ARP frames validated, lent, recycled, and refilled through the \
         RX/Fill engine verified"
    );
}

/// Locally administered unicast MAC the TX phase answers ARP with.
const REFLECTOR_MAC: [u8; 6] = [0x02, 0x52, 0x55, 0x53, 0x54, 0x52];
const REFLECTOR_MAC_TEXT: &str = "02:52:55:53:54:52";
const UNANSWERED_IP: [u8; 4] = [192, 0, 2, 1];
const PEER_IP: [u8; 4] = [192, 0, 2, 2];

/// Rewrites the peer's ARP request for `UNANSWERED_IP` in place into the
/// matching ARP reply from `REFLECTOR_MAC` (same length, so the RX
/// descriptor geometry is the TX geometry). Returns `false` and leaves the
/// bytes alone for any other frame.
fn rewrite_arp_request_into_reply(bytes: &mut [u8]) -> bool {
    let is_request = bytes.len() >= 42
        && bytes[..6] == [0xff; 6]
        && bytes[12..14] == [0x08, 0x06]
        && bytes[14..22] == [0, 1, 8, 0, 6, 4, 0, 1]
        && bytes[28..32] == PEER_IP
        && bytes[38..42] == UNANSWERED_IP;
    if !is_request {
        return false;
    }
    let mut peer_mac = [0_u8; 6];
    peer_mac.copy_from_slice(&bytes[6..12]);
    // Ethernet: back to the peer, from the reflector.
    bytes[..6].copy_from_slice(&peer_mac);
    bytes[6..12].copy_from_slice(&REFLECTOR_MAC);
    // ARP reply: sender is the reflector at the asked-for address.
    bytes[21] = 2;
    bytes[22..28].copy_from_slice(&REFLECTOR_MAC);
    bytes[28..32].copy_from_slice(&UNANSWERED_IP);
    bytes[32..38].copy_from_slice(&peer_mac);
    bytes[38..42].copy_from_slice(&PEER_IP);
    true
}

/// The peer's neighbor entry for `UNANSWERED_IP`, in this namespace only.
fn peer_neighbor(peer: &str) -> String {
    let output = Command::new("ip")
        .args(["neigh", "show", "192.0.2.1", "dev", peer])
        .output()
        .expect("run ip neigh show");
    assert!(output.status.success(), "ip neigh show failed");
    String::from_utf8(output.stdout).expect("ip output is UTF-8")
}

#[test]
fn priv_xdp_tx_reflects_peer_frame_completes_and_drains_on_netns_veth() {
    let Some(device) = requested(Some("tx")) else {
        return;
    };
    let peer_device = required("RUSTER_PRIV_XDP_PEER");
    assert_eq!(attached_program(&device), None, "veth starts without XDP");
    assert!(
        !peer_neighbor(&peer_device).contains(REFLECTOR_MAC_TEXT),
        "the peer must not know the reflector yet"
    );
    let mut session = open_after_release(&session_config(&device, 0, XDP_COPY));
    // attach_xdp needs `&mut session`, so it must precede take_datapath:
    // the bundle (and its kick handle) borrows the session from then on.
    session
        .attach_xdp(XdpAttachMode::Native)
        .expect("native attach on veth");
    let peer = UdpSocket::bind(PEER_SOURCE).expect("peer address configured by the script");
    {
        let datapath = session.take_datapath().expect("first datapath take");
        let mut engine = RxFillEngine::new(
            datapath,
            UmemDomainId::new(NonZeroU128::new(0x5444).expect("nonzero")),
            RxFillConfig::new(NonZeroU32::new(64).expect("nonzero")),
        )
        .expect("engine over the live mappings");
        assert_eq!(engine.tx_inflight_limit(), 64);
        engine.audit().expect("primed engine audit");

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut reflected = 0_u32;
        while engine.tx_counters().tx_completed == 0 {
            if reflected == 0 {
                peer.send_to(b"ruster", UNANSWERED_TARGET)
                    .expect("peer send");
            }
            sleep(Duration::from_millis(20));
            let mut handoff = None;
            {
                let mut batch = engine.poll(16).expect("poll");
                while let Some(mut frame) = batch.next_frame() {
                    if handoff.is_none() && rewrite_arp_request_into_reply(frame.bytes_mut()) {
                        handoff = Some(frame.stage_tx());
                    } else {
                        frame.recycle();
                    }
                }
            }
            if let Some(handoff) = handoff {
                let descriptor = handoff.descriptor();
                assert_eq!(descriptor.data_offset(), XDP_PACKET_HEADROOM);
                let report = engine
                    .submit_tx(handoff)
                    .map_err(|rejected| rejected.reason())
                    .expect("TX ring has room");
                assert_eq!(report.submitted(), 1);
                reflected += 1;
            }
            // Copy mode transmits only from sendto, and keeps asking.
            if reflected > 0 && engine.tx_needs_wakeup() == Ok(NeedWakeup::Required) {
                match engine.wake_tx() {
                    Ok(KickOutcome::Woken | KickOutcome::Deferred(_)) => {}
                    Err(error) => panic!("TX kick failed: {error:?}"),
                }
            }
            engine.audit().expect("engine audit after poll");
            assert!(
                Instant::now() < deadline,
                "no reflected frame completed within five seconds: {:?} {:?}",
                engine.counters(),
                engine.tx_counters()
            );
        }
        let counters = engine.tx_counters();
        assert_eq!(counters.tx_submitted, u64::from(reflected));
        assert_eq!(counters.tx_invalid_completion_total(), 0, "{counters:?}");
        assert!(counters.tx_kicks >= 1, "{counters:?}");

        // The peer kernel received the reply that left the same veth: it
        // learned the reflector's MAC for the address it asked about.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let neighbor = peer_neighbor(&peer_device);
            if neighbor.contains(REFLECTOR_MAC_TEXT) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the peer never learned the reflected ARP reply: {neighbor:?}"
            );
            sleep(Duration::from_millis(20));
        }

        // Ordered shutdown with a frame still in flight: the peer's next
        // UDP datagram (now sent to the reflector MAC) is reflected with
        // swapped MACs and submitted without any kick or reap, so only the
        // drain (which kicks while the kernel asks, then reaps) can
        // complete it. The veth peer picks its TX queue (our RX queue) by
        // flow hash, and only queue 0 has a socket, so each attempt uses a
        // fresh source port until one flow lands on queue 0.
        let deadline = Instant::now() + Duration::from_secs(5);
        while engine.tx_inflight() == 0 {
            UdpSocket::bind(PEER_SOURCE)
                .expect("peer address configured by the script")
                .send_to(b"ruster", UNANSWERED_TARGET)
                .expect("peer send");
            sleep(Duration::from_millis(20));
            let mut handoff = None;
            {
                let mut batch = engine.poll(16).expect("poll");
                while let Some(mut frame) = batch.next_frame() {
                    let bytes = frame.bytes_mut();
                    if handoff.is_none() && bytes.len() >= 34 && bytes[12..14] == [0x08, 0x00] {
                        let (destination, rest) = bytes.split_at_mut(6);
                        destination.swap_with_slice(&mut rest[..6]);
                        handoff = Some(frame.stage_tx());
                    } else {
                        frame.recycle();
                    }
                }
            }
            if let Some(handoff) = handoff {
                let report = engine
                    .submit_tx(handoff)
                    .map_err(|rejected| rejected.reason())
                    .expect("TX ring has room");
                assert_eq!(report.submitted(), 1);
                reflected += 1;
            }
            assert!(
                Instant::now() < deadline,
                "no peer IPv4 frame to reflect within five seconds"
            );
        }
        assert_eq!(engine.completion_lag().in_flight(), 1);
        let kicks = engine.tx_counters().tx_kicks;
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut drained_completions = 0;
        let report = loop {
            let report = engine.drain(16).expect("drain");
            drained_completions += report.completed();
            if report.outcome() == DrainOutcome::Drained {
                break report;
            }
            assert!(report.rounds() > 0, "{report:?}");
            assert!(Instant::now() < deadline, "drain timed out: {report:?}");
            sleep(Duration::from_millis(10));
        };
        assert_eq!(
            drained_completions, 1,
            "the drain reaped the in-flight frame"
        );
        assert!(
            engine.tx_counters().tx_kicks > kicks,
            "copy mode needs the drain's kick"
        );
        let accounting = report.accounting();
        assert_eq!(accounting.tx_in_flight, 0);
        assert_eq!(accounting.tx_handoffs, 0);
        assert_eq!(accounting.total(), 192);
        assert_eq!(engine.tx_counters().tx_completed, u64::from(reflected));
        engine.audit().expect("engine audit after drain");
    }
    session.close().expect("attached session teardown");
    wait_detached(&device);
    eprintln!(
        "priv_xdp_tx: peer ARP request rewritten in place, transmitted from the same frame on \
         the same veth, received by the peer, completed, and an in-flight frame drained verified"
    );
}

/// Source of the engine-generated ARP request (TEST-NET-1, unused by the
/// tx phase, so the peer cannot know it from earlier phases).
const GENERATOR_MAC: [u8; 6] = [0x02, 0x52, 0x55, 0x53, 0x54, 0x47];
const GENERATOR_MAC_TEXT: &str = "02:52:55:53:54:47";
const GENERATOR_IP: [u8; 4] = [192, 0, 2, 3];

/// Writes a broadcast ARP request from the generator for `PEER_IP` into
/// exactly 42 bytes.
fn build_arp_request(bytes: &mut [u8]) {
    assert_eq!(bytes.len(), 42);
    bytes[..6].fill(0xff);
    bytes[6..12].copy_from_slice(&GENERATOR_MAC);
    bytes[12..14].copy_from_slice(&[0x08, 0x06]);
    bytes[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    bytes[22..28].copy_from_slice(&GENERATOR_MAC);
    bytes[28..32].copy_from_slice(&GENERATOR_IP);
    bytes[32..38].fill(0);
    bytes[38..42].copy_from_slice(&PEER_IP);
}

/// Whether `bytes` is the peer's ARP reply to the generator.
fn is_reply_to_generator(bytes: &[u8]) -> bool {
    bytes.len() >= 42
        && bytes[..6] == GENERATOR_MAC
        && bytes[12..14] == [0x08, 0x06]
        && bytes[20..22] == [0, 2]
        && bytes[28..32] == PEER_IP
        && bytes[38..42] == GENERATOR_IP
}

/// The peer's neighbor entry for `GENERATOR_IP`, in this namespace only.
fn peer_generator_neighbor(peer: &str) -> String {
    let output = Command::new("ip")
        .args(["neigh", "show", "192.0.2.3", "dev", peer])
        .output()
        .expect("run ip neigh show");
    assert!(output.status.success(), "ip neigh show failed");
    String::from_utf8(output.stdout).expect("ip output is UTF-8")
}

#[test]
fn priv_xdp_generated_arp_request_is_learned_by_the_peer_and_drained() {
    let Some(device) = requested(Some("generated")) else {
        return;
    };
    let peer_device = required("RUSTER_PRIV_XDP_PEER");
    assert_eq!(attached_program(&device), None, "veth starts without XDP");
    assert!(
        !peer_generator_neighbor(&peer_device).contains(GENERATOR_MAC_TEXT),
        "the peer must not know the generator yet"
    );
    let mut session = open_after_release(&session_config(&device, 0, XDP_COPY));
    session
        .attach_xdp(XdpAttachMode::Native)
        .expect("native attach on veth");
    {
        let datapath = session.take_datapath().expect("first datapath take");
        let mut engine = RxFillEngine::new(
            datapath,
            UmemDomainId::new(NonZeroU128::new(0x5447).expect("nonzero")),
            RxFillConfig::new(NonZeroU32::new(64).expect("nonzero")),
        )
        .expect("engine over the live mappings");
        assert_eq!(engine.generated_frames(), 64);
        engine.audit().expect("primed engine audit");

        // Generate from the generated pool, commit through TX, kick (copy
        // mode transmits only from sendto), and reap, until the peer
        // kernel has learned the generator from the request.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut replies = 0_u32;
        loop {
            if engine.generated_counters().generated_committed
                <= engine.generated_counters().generated_completed
            {
                let rx_frames = engine.rx_frames();
                let mut frame = engine.allocate_generated(42).expect("generated frame");
                assert!(frame.frame().index() >= rx_frames);
                assert_eq!(frame.bytes().len(), 42);
                assert_eq!(frame.descriptor().data_offset(), XDP_PACKET_HEADROOM);
                build_arp_request(frame.bytes_mut());
                let report = frame
                    .commit()
                    .map_err(|rejected| rejected.reason())
                    .expect("TX ring has room");
                assert_eq!(report.submitted(), 1);
            }
            if engine.tx_needs_wakeup() == Ok(NeedWakeup::Required) {
                match engine.wake_tx() {
                    Ok(KickOutcome::Woken | KickOutcome::Deferred(_)) => {}
                    Err(error) => panic!("TX kick failed: {error:?}"),
                }
            }
            sleep(Duration::from_millis(20));
            {
                let mut batch = engine.poll(16).expect("poll reaps completions");
                while let Some(frame) = batch.next_frame() {
                    if is_reply_to_generator(frame.bytes()) {
                        replies += 1;
                    }
                    frame.recycle();
                }
            }
            engine.audit().expect("engine audit after poll");
            if engine.generated_counters().generated_completed > 0
                && peer_generator_neighbor(&peer_device).contains(GENERATOR_MAC_TEXT)
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the peer never learned the generated ARP request: {:?} {:?} {:?}",
                engine.generated_counters(),
                engine.tx_counters(),
                peer_generator_neighbor(&peer_device)
            );
        }
        let counters = engine.generated_counters();
        assert!(counters.generated_committed >= 1, "{counters:?}");
        assert_eq!(counters.generated_unavailable, 0, "{counters:?}");
        assert_eq!(counters.generated_rejected_total(), 0, "{counters:?}");
        assert_eq!(engine.tx_counters().tx_invalid_completion_total(), 0);

        // Ordered shutdown: generate one more, submit without a kick, and
        // let the drain kick and reap it back into the generated pool.
        let mut frame = engine.allocate_generated(42).expect("generated frame");
        build_arp_request(frame.bytes_mut());
        let report = frame
            .commit()
            .map_err(|rejected| rejected.reason())
            .expect("TX ring has room");
        assert_eq!(report.submitted(), 1);
        let deadline = Instant::now() + Duration::from_secs(2);
        let report = loop {
            let report = engine.drain(16).expect("drain");
            if report.outcome() == DrainOutcome::Drained {
                break report;
            }
            assert!(Instant::now() < deadline, "drain timed out: {report:?}");
            sleep(Duration::from_millis(10));
        };
        let generated = report.generated_accounting();
        assert_eq!(generated.free, 64, "{generated:?}");
        assert_eq!(generated.tx_in_flight, 0);
        assert_eq!(generated.total(), 64);
        assert_eq!(report.accounting().total(), 192);
        let counters = engine.generated_counters();
        assert_eq!(counters.generated_completed, counters.generated_committed);
        assert_eq!(
            engine.allocate_generated(42).map(|_| ()),
            Err(GeneratedAllocError::Rejected(
                GeneratedRejectReason::Draining
            ))
        );
        engine.audit().expect("engine audit after drain");
        eprintln!(
            "priv_xdp_generated: {} generated ARP requests committed and completed, {replies} \
             replies seen",
            counters.generated_committed
        );
    }
    session.close().expect("attached session teardown");
    wait_detached(&device);
    eprintln!(
        "priv_xdp_generated: ARP request generated from the generated pool, transmitted, learned \
         by the peer, completed back to the generated pool, and drained verified"
    );
}

/// Router MAC of `device` from sysfs (inside the namespace).
fn device_mac(device: &str) -> [u8; 6] {
    let text = fs::read_to_string(format!("/sys/class/net/{device}/address"))
        .unwrap_or_else(|error| panic!("cannot read the MAC of {device}: {error}"));
    let mut mac = [0_u8; 6];
    let mut parts = text.trim().split(':');
    for byte in &mut mac {
        *byte = u8::from_str_radix(parts.next().expect("six octets"), 16).expect("hex octet");
    }
    assert!(parts.next().is_none(), "six octets");
    mac
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
        .collect()
}

/// Sends one raw Ethernet frame out of `device` (an AF_PACKET socket in
/// python, run inside the namespace by the already-privileged test).
const RAW_SEND: &str = r"
import socket, sys
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((sys.argv[1], 0))
s.send(bytes.fromhex(sys.argv[2]))
";

/// Prints `ready`, then the hex of the first IPv4 frame received (not
/// sent) on `device` that contains the marker, or fails after a timeout.
const RAW_RECEIVE: &str = r"
import select, socket, sys, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
s.bind((sys.argv[1], 0))
marker = bytes.fromhex(sys.argv[2])
print('ready', flush=True)
deadline = time.time() + float(sys.argv[3])
while time.time() < deadline:
    ready, _, _ = select.select([s], [], [], 0.05)
    if not ready:
        continue
    data, address = s.recvfrom(65535)
    if address[2] == socket.PACKET_OUTGOING:
        continue
    if marker in data:
        print(data.hex(), flush=True)
        sys.exit(0)
sys.exit(1)
";

const FORWARD_MARKER: &[u8] = b"ruster-x04a-forward";
const FORWARD_HOST_MAC: [u8; 6] = [0x02, 0x52, 0x55, 0x53, 0x54, 0x41];
const FORWARD_SOURCE: [u8; 4] = [192, 0, 2, 2];
const FORWARD_TARGET: [u8; 4] = [198, 51, 100, 2];

/// An IPv4/UDP frame from the A-side host to the B-side host, addressed
/// to router port A's MAC.
fn forward_frame(router_a: [u8; 6]) -> Vec<u8> {
    let payload_len = FORWARD_MARKER.len();
    let total = 20 + 8 + payload_len;
    let mut bytes = vec![0_u8; 14 + total];
    bytes[0..6].copy_from_slice(&router_a);
    bytes[6..12].copy_from_slice(&FORWARD_HOST_MAC);
    bytes[12..14].copy_from_slice(&[0x08, 0x00]);
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&u16::try_from(total).expect("short").to_be_bytes());
    bytes[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&FORWARD_SOURCE);
    bytes[30..34].copy_from_slice(&FORWARD_TARGET);
    let checksum = ruster_core::ipv4_header_checksum(&bytes[14..34]);
    bytes[24..26].copy_from_slice(&checksum.to_be_bytes());
    bytes[34..36].copy_from_slice(&40_000_u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&9_u16.to_be_bytes());
    bytes[38..40].copy_from_slice(&u16::try_from(8 + payload_len).expect("short").to_be_bytes());
    bytes[42..].copy_from_slice(FORWARD_MARKER);
    bytes
}

fn engine(session: &mut NativeSession, domain: u128) -> RxFillEngine<'_> {
    RxFillEngine::new(
        session.take_datapath().expect("first datapath take"),
        UmemDomainId::new(NonZeroU128::new(domain).expect("nonzero")),
        RxFillConfig::new(NonZeroU32::new(64).expect("nonzero")),
    )
    .expect("engine over the live mappings")
}

fn adapter_session_config(device: &str) -> SessionConfig {
    // One queue per veth end in this phase: the peer's TX always lands on
    // the bound queue 0.
    session_config(device, 0, XDP_COPY)
}

#[test]
fn priv_xdp_adapter_forwards_between_two_veth_ports_through_core_and_drains() {
    let Some(_device) = requested(Some("adapter")) else {
        return;
    };
    let port_a = required("RUSTER_PRIV_XDP_FWD_A");
    let peer_a = required("RUSTER_PRIV_XDP_FWD_A_PEER");
    let port_b = required("RUSTER_PRIV_XDP_FWD_B");
    let peer_b = required("RUSTER_PRIV_XDP_FWD_B_PEER");
    for device in [&port_a, &port_b] {
        assert_eq!(attached_program(device), None, "veth starts without XDP");
    }
    let (mac_a, mac_b, mac_peer_b) = (
        device_mac(&port_a),
        device_mac(&port_b),
        device_mac(&peer_b),
    );
    let lan = IfId(1);
    let wan = IfId(2);
    let mut session_a = open_after_release(&adapter_session_config(&port_a));
    let mut session_b = open_after_release(&adapter_session_config(&port_b));
    for session in [&mut session_a, &mut session_b] {
        assert_eq!(session.mode(), NegotiatedMode::Copy);
        assert_eq!(session.mtu(), 1_500, "veth default MTU from sysfs");
        session
            .attach_xdp(XdpAttachMode::Native)
            .expect("native attach on veth");
    }
    let config_a = XdpPortConfig::from_session(lan, &session_a);
    let config_b = XdpPortConfig::from_session(wan, &session_b);
    assert_eq!(config_a.max_frame_len(), 1_514);
    {
        let mut io = XdpPacketIo::new([
            XdpPort::new(config_b, engine(&mut session_b, 0x5462)),
            XdpPort::new(config_a, engine(&mut session_a, 0x5461)),
        ])
        .expect("adapter");
        let ip = Ipv4Address::from_octets;
        let routes = [
            Route::new(ip([192, 0, 2, 0]), 24, lan, None).expect("route"),
            Route::new(ip([198, 51, 100, 0]), 24, wan, None).expect("route"),
        ];
        let interfaces = [
            Interface {
                id: lan,
                mac: MacAddress(mac_a),
            },
            Interface {
                id: wan,
                mac: MacAddress(mac_b),
            },
        ];
        let neighbors = [Neighbor {
            interface: wan,
            target: ip(FORWARD_TARGET),
            mac: MacAddress(mac_peer_b),
        }];
        let snapshot =
            ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &[]).expect("snapshot");

        let mut receiver = Command::new("python3")
            .args(["-I", "-c", RAW_RECEIVE, &peer_b, &hex(FORWARD_MARKER), "8"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn the peer B receiver");
        let mut stdout = BufReader::new(receiver.stdout.take().expect("piped stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line).expect("receiver ready line");
        assert_eq!(line.trim(), "ready", "receiver did not start");

        let original = forward_frame(mac_a);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut sent = 0_u32;
        while io.port_stats(wan).expect("WAN").counters.cross_port_copies == 0 {
            if sent < 50 {
                let status = Command::new("python3")
                    .args(["-I", "-c", RAW_SEND, &peer_a, &hex(&original)])
                    .status()
                    .expect("run the peer A sender");
                assert!(status.success(), "raw send from {peer_a} failed");
                sent += 1;
            }
            sleep(Duration::from_millis(20));
            let report = forward_batch(io.receive(64).expect("receive"), &snapshot, &mut NoTrace);
            assert!(report.invariants_hold(), "{report:?}");
            assert_eq!(report.completion.error, None, "{report:?}");
            for interface in [lan, wan] {
                io.engine(interface).expect("port").audit().expect("audit");
            }
            assert!(
                Instant::now() < deadline,
                "no frame forwarded A -> B within five seconds: {:?}",
                io.backend_stats()
            );
        }
        let mut forwarded = String::new();
        stdout.read_line(&mut forwarded).expect("forwarded frame");
        assert!(
            receiver.wait().expect("receiver exit").success(),
            "peer B never received the forwarded frame"
        );
        let bytes = unhex(forwarded.trim());
        assert_eq!(bytes.len(), original.len(), "exact length on the wire");
        assert_eq!(&bytes[0..6], &mac_peer_b, "next-hop MAC");
        assert_eq!(&bytes[6..12], &mac_b, "egress port MAC");
        assert_eq!(bytes[22], 63, "TTL decremented once");
        assert_eq!(
            ruster_core::internet_checksum(&bytes[14..34]),
            0,
            "IPv4 checksum updated"
        );
        assert_eq!(
            &bytes[34..],
            &original[34..],
            "UDP header and payload intact"
        );

        let stats = io.backend_stats();
        assert_eq!(stats.ports, 2);
        assert_eq!(stats.copy_ports, 2);
        let wan_stats = io.port_stats(wan).expect("WAN");
        assert!(wan_stats.counters.cross_port_copies >= 1, "{wan_stats:?}");
        assert!(wan_stats.counters.tx_kicks >= 1, "{wan_stats:?}");
        assert!(
            wan_stats.tx_need_wakeup,
            "copy mode keeps asking for sendto"
        );
        assert_eq!(stats.counters.tx_over_mtu, 0);
        assert_eq!(stats.counters.tx_invalid_completions, 0);

        // The kernel's XDP_STATISTICS reach the per-port stats.
        let kernel = io.port_stats(wan).expect("WAN").kernel;
        assert!(
            kernel.is_some(),
            "getsockopt(XDP_STATISTICS) on a live socket"
        );

        // A burst above copy mode's 32 descriptors per sendto completes in
        // the batch's own finish, without any further traffic or call.
        let completed = io.port_stats(wan).expect("WAN").counters.tx_completed;
        let kicks = io.port_stats(wan).expect("WAN").counters.tx_kicks;
        {
            let mut batch = io.begin_generated(wan);
            for _ in 0..60 {
                let mut frame = batch.allocate(42).expect("generated frame");
                build_arp_request(frame.bytes_mut());
                frame.commit();
            }
            let completion = batch.finish();
            assert_eq!(completion.accepted, 60, "{completion:?}");
            assert_eq!(completion.error, None, "{completion:?}");
        }
        let burst = io.port_stats(wan).expect("WAN").counters;
        assert_eq!(burst.tx_inflight, 0, "all 60 completed: {burst:?}");
        assert_eq!(burst.tx_completed, completed + 60, "{burst:?}");
        assert!(burst.tx_kicks >= kicks + 2, "two sendto rounds: {burst:?}");

        // Link flap on B (inside the namespace): TX while down, then up,
        // and no new traffic. The quiescence check alone settles the owed
        // kick until the publication is ready.
        let ip_link = |state: &str| {
            let status = Command::new("ip")
                .args(["link", "set", "dev", port_b.as_str(), state])
                .status()
                .expect("run ip link set");
            assert!(status.success(), "ip link set {port_b} {state} failed");
        };
        ip_link("down");
        {
            let mut batch = io.begin_generated(wan);
            for _ in 0..3 {
                let mut frame = batch.allocate(42).expect("generated frame");
                build_arp_request(frame.bytes_mut());
                frame.commit();
            }
            let completion = batch.finish();
            assert_eq!(completion.error, None, "link down is not an error");
        }
        let down = io.port_stats(wan).expect("WAN");
        ip_link("up");
        let deadline = Instant::now() + Duration::from_secs(5);
        while let Err(error) = io.try_publication_quiescence().map(|_| ()) {
            assert!(
                Instant::now() < deadline,
                "quiescence never became ready after the flap: {error:?} {:?}",
                io.port_stats(wan)
            );
            sleep(Duration::from_millis(20));
        }
        let up = io.port_stats(wan).expect("WAN");
        assert_eq!(up.counters.tx_inflight, 0, "{up:?}");
        assert!(!up.link_down && !up.kick_owed, "{up:?}");
        eprintln!(
            "priv_xdp_adapter: burst of 60 used {} kicks; flap: link_down {} kicks_link_down {} \
             deferred {} in flight {} while down",
            burst.tx_kicks - kicks,
            down.link_down,
            down.counters.kicks_link_down,
            down.counters.kicks_deferred,
            down.counters.tx_inflight
        );

        // Ordered shutdown of both ports.
        let deadline = Instant::now() + Duration::from_secs(2);
        let report = loop {
            let report = io.drain(16).expect("drain");
            if report.is_drained() {
                break report;
            }
            assert!(Instant::now() < deadline, "drain timed out: {report:?}");
            sleep(Duration::from_millis(10));
        };
        assert_eq!(report.tx_in_flight, 0);
        for interface in [lan, wan] {
            let engine = io.engine(interface).expect("port");
            engine.audit().expect("audit after drain");
            assert_eq!(engine.tx_inflight(), 0);
            assert_eq!(engine.generated_accounting().free, 64);
            assert_eq!(engine.frame_accounting().total(), 192);
        }
        assert!(matches!(io.receive(1), Err(XdpIoError::Stopped)));
        eprintln!(
            "priv_xdp_adapter: {} raw frames sent, {} cross-port copies, {} completed before the drain",
            sent, wan_stats.counters.cross_port_copies, wan_stats.counters.tx_completed
        );
    }
    session_a.close().expect("port A teardown");
    session_b.close().expect("port B teardown");
    wait_detached(&port_a);
    wait_detached(&port_b);
    eprintln!(
        "priv_xdp_adapter: a frame from veth A was forwarded by core through the adapter, \
         copied into port B's generated pool, transmitted on veth B with the rewritten MACs and \
         TTL, received by B's peer, a 60-frame burst completed without more traffic, a link \
         flap on B recovered to a ready quiescence, and both ports drained verified"
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
    // Write then rename, so the script never reads a partial pid.
    let partial = format!("{ready}.partial");
    fs::write(&partial, format!("{}\n", std::process::id())).expect("write ready file");
    fs::rename(&partial, &ready).expect("publish ready file");
    eprintln!("priv_xdp_holder: attached; waiting for SIGKILL");
    // The script kills this process; returning normally means it did not.
    sleep(Duration::from_secs(30));
    panic!("holder was not killed within 30 seconds");
}
