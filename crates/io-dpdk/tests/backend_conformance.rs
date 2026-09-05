//! Runs the same reusable `ruster-io-conformance` generated-frame suite that
//! `ruster-io-sim` runs against `SimIo`, here against a real DPDK port over
//! the `af_packet` PMD.
//!
//! Requires the `dpdk`+`test-hooks` features and a real `libdpdk`; see
//! `crates/io-dpdk/src/lib.rs` for what "real" means. `required-features`
//! keeps this target from being *built* at all without both features, but
//! that alone says nothing about whether `libdpdk` itself was actually
//! found: `#![cfg(dpdk_available)]` below is what does, since Cargo applies
//! a package's build-script cfgs to every target in that package, this test
//! binary included. `cargo test --all-features` on a host without `libdpdk`
//! (as `scripts/check-requirements.sh` does) therefore still builds and
//! runs this binary, just with zero tests in it, rather than failing.
//!
//! Environment this was proven against: two `af_packet` vdevs, each bound to
//! one end of a veth pair, brought up with:
//!
//! ```sh
//! sudo ip link add veth-lan0 type veth peer name veth-lan1
//! sudo ip link add veth-wan0 type veth peer name veth-wan1
//! sudo ip link set veth-lan0 up; sudo ip link set veth-lan1 up
//! sudo ip link set veth-wan0 up; sudo ip link set veth-wan1 up
//! ```
//!
//! DPDK's EAL is a process-global singleton and AF_PACKET sockets need
//! `CAP_NET_RAW`, so this binary must run once, as root:
//!
//! ```sh
//! cargo test -p ruster-io-dpdk --features dpdk,test-hooks --no-run
//! sudo target/debug/deps/backend_conformance-* --test-threads=1
//! ```

#![cfg(dpdk_available)]

use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard, OnceLock},
};

use ruster_core::IfId;
use ruster_io_conformance::{
    generated, BufferToken, GeneratedEvent, GeneratedEventKind, GeneratedFinishErrorHarness,
    GeneratedFinitePoolHarness, GeneratedHarness, GeneratedReclaim, GeneratedUnknownEgressHarness,
    LeaseObserver, LiveFrame, TxEndpoint, CONFORMANCE_LAN, CONFORMANCE_LAN_ENDPOINT,
    CONFORMANCE_WAN, CONFORMANCE_WAN_ENDPOINT,
};
use ruster_io_dpdk::{DpdkConfig, DpdkIo, PortBinding, RecordedDisposition, ValidatedConfig};

fn test_config() -> DpdkConfig {
    DpdkConfig {
        eal_args: vec![
            "--no-huge".to_string(),
            "-m".to_string(),
            "512".to_string(),
            "-l".to_string(),
            "0-1".to_string(),
            "--no-pci".to_string(),
            "--vdev=net_af_packet0,iface=veth-lan0".to_string(),
            "--vdev=net_af_packet1,iface=veth-wan0".to_string(),
        ],
        ports: vec![
            PortBinding {
                interface: CONFORMANCE_LAN,
                port_id: 0,
            },
            PortBinding {
                interface: CONFORMANCE_WAN,
                port_id: 1,
            },
        ],
        pool_capacity: 4096,
        // Zero: several cases assert the pool's exact avail-count before and
        // after a cycle of allocations and rejects. A nonzero per-lcore
        // cache can hold freed mbufs back from the ring instead of
        // returning them immediately, which would make those assertions
        // flaky rather than wrong; disabling the cache keeps every
        // alloc/free hitting the ring directly.
        pool_cache_size: 0,
        max_frame_len: 1500,
        tx_ring_descriptors: 128,
    }
}

/// DPDK's EAL initializes exactly once per process, and every test in this
/// binary shares one pair of ports, so all of them run against one live
/// `DpdkIo` serialized behind this lock rather than each opening their own.
fn world() -> &'static Mutex<DpdkIo> {
    static WORLD: OnceLock<Mutex<DpdkIo>> = OnceLock::new();
    WORLD.get_or_init(|| {
        let validated = ValidatedConfig::new(test_config()).expect("valid DPDK test config");
        let io = DpdkIo::open(validated).expect(
            "DPDK test environment missing: create veth-lan0/veth-lan1 and \
             veth-wan0/veth-wan1 and run this binary as root, see the module docs",
        );
        Mutex::new(io)
    })
}

#[derive(Default)]
struct DpdkObserver {
    generations: BTreeMap<u64, u64>,
    live: BTreeMap<usize, LiveFrame>,
}

impl LeaseObserver for DpdkObserver {
    fn bind(&mut self, bytes: &[u8], requested_len: usize) -> LiveFrame {
        assert_eq!(bytes.len(), requested_len);
        let visible_address = bytes.as_ptr() as usize;
        let frame_id = visible_address as u64;
        assert!(
            !self.live.contains_key(&visible_address),
            "DPDK allocation address is already live"
        );
        let generation = self.generations.entry(frame_id).or_default();
        *generation = generation.checked_add(1).expect("DPDK generation overflow");
        let frame = LiveFrame {
            token: BufferToken::new(frame_id, *generation),
            visible_address,
            requested_len,
        };
        self.live.insert(visible_address, frame);
        frame
    }

    fn observe(&self, bytes: &[u8]) -> LiveFrame {
        let address = bytes.as_ptr() as usize;
        let frame = *self
            .live
            .get(&address)
            .expect("DPDK terminal event has no lease-time identity");
        assert_eq!(bytes.len(), frame.requested_len);
        frame
    }
}

impl DpdkObserver {
    /// This backend has no completion capability (see the crate docs): every
    /// disposition this harness ever observes is therefore terminal from the
    /// observer's point of view, submitted included, so every one of them
    /// releases the binding rather than only reclaim/reject.
    fn terminal(&mut self, bytes: &[u8]) -> LiveFrame {
        let frame = self.observe(bytes);
        assert_eq!(self.live.remove(&frame.visible_address), Some(frame));
        frame
    }
}

struct DpdkHarness {
    io: MutexGuard<'static, DpdkIo>,
    observer: DpdkObserver,
}

impl DpdkHarness {
    fn publication_endpoint(egress: IfId) -> Option<TxEndpoint> {
        match egress {
            CONFORMANCE_LAN => Some(CONFORMANCE_LAN_ENDPOINT),
            CONFORMANCE_WAN => Some(CONFORMANCE_WAN_ENDPOINT),
            _ => None,
        }
    }
}

impl GeneratedHarness for DpdkHarness {
    type Io = DpdkIo;
    type Observer = DpdkObserver;

    fn new() -> Self {
        let mut io = world()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Every test in this binary shares one process-wide `DpdkIo`; start
        // each one from the same clean slate regardless of what an earlier
        // test configured.
        io.reset_generated_test_hooks_for_test();
        io.set_max_frame_len(1500);
        Self {
            io,
            observer: DpdkObserver::default(),
        }
    }

    fn io_and_observer(&mut self) -> (&mut Self::Io, &mut Self::Observer) {
        (&mut self.io, &mut self.observer)
    }

    fn set_generated_allocation_budget(&mut self, budget: usize) {
        self.io.set_generated_allocation_budget_for_test(budget);
    }

    fn set_generated_max_frame(&mut self, max_frame: usize) {
        let max_frame = u16::try_from(max_frame).expect("test max_frame fits u16");
        self.io.set_max_frame_len(max_frame);
    }

    fn set_generated_accept_budget(&mut self, budget: usize) {
        self.io.set_generated_accept_budget_for_test(budget);
    }

    fn drain_generated_events(&mut self) -> Vec<GeneratedEvent> {
        self.io
            .drain_generated_events_for_test()
            .into_iter()
            .map(|event| {
                // SAFETY: `event.address`/`event.len` describe the exact
                // live range `bind()` was given at allocate time; this
                // slice's contents are never read, only its pointer and
                // length are compared against the observer's own record.
                let identity =
                    unsafe { std::slice::from_raw_parts(event.address as *const u8, event.len) };
                let frame = self.observer.terminal(identity);
                let kind = match event.kind {
                    RecordedDisposition::TxSubmitted => GeneratedEventKind::TxSubmitted {
                        endpoint: Self::publication_endpoint(event.egress)
                            .expect("a submitted frame always has a known endpoint"),
                        descriptor_len: event.bytes.len(),
                    },
                    RecordedDisposition::TxRejected => GeneratedEventKind::TxRejected {
                        attempted_egress: event.egress,
                        endpoint: Self::publication_endpoint(event.egress),
                    },
                    RecordedDisposition::Cancelled => {
                        GeneratedEventKind::Reclaimed(GeneratedReclaim::Cancelled)
                    }
                    RecordedDisposition::Abandoned => {
                        GeneratedEventKind::Reclaimed(GeneratedReclaim::Abandoned)
                    }
                };
                GeneratedEvent {
                    frame,
                    egress: event.egress,
                    bytes: event.bytes,
                    kind,
                }
            })
            .collect()
    }
}

impl GeneratedFinishErrorHarness for DpdkHarness {
    fn fail_next_generated_finish(&mut self) {
        self.io.fail_next_generated_finish_for_test();
    }
}

impl GeneratedFinitePoolHarness for DpdkHarness {
    fn free_generated_frames(&self) -> usize {
        self.io.free_generated_frames_for_test()
    }
}

impl GeneratedUnknownEgressHarness for DpdkHarness {}

#[test]
fn generated_empty_session_has_zero_accounting() {
    generated::empty_session_has_zero_accounting::<DpdkHarness>();
}

#[test]
fn generated_allocation_failures_bind_only_successful_ownership() {
    generated::allocation_failures_bind_only_successful_ownership::<DpdkHarness>();
}

#[test]
fn generated_commit_cancel_and_abandon_bind_exact_lengths() {
    generated::commit_cancel_and_abandon_bind_exact_lengths::<DpdkHarness>();
}

#[test]
fn generated_partial_reject_reclaims_exact_tokens() {
    generated::partial_reject_reclaims_exact_tokens::<DpdkHarness>();
}

#[test]
fn generated_sessions_bind_concrete_endpoints() {
    generated::sessions_bind_concrete_endpoints::<DpdkHarness>();
}

#[test]
fn generated_partial_reject_with_finish_error_is_exact() {
    generated::partial_reject_with_finish_error_is_exact::<DpdkHarness>();
}

#[test]
fn generated_repeated_rejects_restore_physical_pool_and_advance_generation() {
    generated::repeated_rejects_restore_physical_pool_and_advance_generation::<DpdkHarness>();
}

#[test]
fn generated_unknown_egress_is_rejected_without_submission() {
    generated::unknown_egress_is_rejected_without_submission::<DpdkHarness>();
}
