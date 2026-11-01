//! Privileged real-kernel smoke for the X00C native AF_XDP session.
//!
//! Runs only with `RUSTER_PRIV_XDP=1`, normally through
//! `scripts/priv-xdp-smoke.sh`, which creates a dedicated network namespace
//! with its own veth pair, runs this prebuilt test inside it, and always
//! deletes the namespace. When the variable is set, every missing
//! precondition (namespace identity, device, capability) fails the test; it
//! never skips. The test refuses to run in the initial network namespace, so
//! it cannot touch a host interface.
//!
//! No XDP program is attached, so the socket receives nothing; the test
//! checks setup, ring readiness, typed real-kernel errors, and teardown.

#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]

use std::{env, fs, os::unix::fs::MetadataExt};

use ruster_io_xdp_native::{
    abi::{XDP_COPY, XDP_USE_NEED_WAKEUP},
    NativeRingError, NativeSession, NegotiatedMode, RingConfig, SessionConfig, SessionFailure,
    SessionStage, UmemConfig, ValidatedBindFlags,
};

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("RUSTER_PRIV_XDP=1 requires {name}"))
}

fn netns_inode(path: &str) -> u64 {
    fs::metadata(path)
        .unwrap_or_else(|error| panic!("cannot stat {path}: {error}"))
        .ino()
}

fn session_config(device: &str, queue: u32, mode_flag: u16) -> SessionConfig {
    SessionConfig::new(
        device,
        queue,
        ValidatedBindFlags::new(XDP_USE_NEED_WAKEUP | mode_flag).expect("valid flags"),
        RingConfig::new(64, 64, 64, 64).expect("valid rings"),
        // frame-count >= fill + tx + generated, as configuration requires.
        UmemConfig::new(256, 2_048, 0, 192, 64, 0).expect("valid UMEM"),
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
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("session open failed: {error:?}"),
        }
    }
    panic!("queue still busy one second after teardown");
}

#[test]
fn priv_xdp_session_opens_copy_mode_on_netns_veth() {
    if env::var_os("RUSTER_PRIV_XDP").is_none() {
        eprintln!("priv_xdp_session: RUSTER_PRIV_XDP unset; privileged smoke not requested");
        return;
    }
    assert_eq!(
        env::var("RUSTER_PRIV_XDP").as_deref(),
        Ok("1"),
        "RUSTER_PRIV_XDP must be exactly 1"
    );
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

    // Copy mode on the namespace-local veth: rings are mapped and usable.
    let mut session =
        NativeSession::open(&session_config(&device, 0, XDP_COPY)).expect("copy session opens");
    assert_eq!(session.mode(), NegotiatedMode::Copy);
    assert!(!session.zero_copy_fallback());
    assert_ne!(session.ifindex(), 0);
    assert_eq!(session.queue(), 0);
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
        assert_eq!(rings.umem.byte_len(), 256 * 2_048);
        let mut fill = rings.fill.reserve(64).expect("empty Fill ring");
        for frame in 0..64_u64 {
            fill.write(frame * 2_048).expect("Fill entry");
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

    // Real-kernel errno classification.
    let bad_queue =
        NativeSession::open(&session_config(&device, 1, XDP_COPY)).expect_err("veth has one queue");
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
