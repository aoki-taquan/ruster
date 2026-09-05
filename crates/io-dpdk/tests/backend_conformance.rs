//! Runs the same reusable `ruster-io-conformance` generated-frame and RX
//! suites that `ruster-io-sim` runs against `SimIo`, here against a real
//! DPDK port over the `af_packet` PMD.
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
//!
//! # RX injection and the Ethernet minimum frame size
//!
//! `RxHarness::inject_rx` sends real bytes over the wire (through a raw
//! `AF_PACKET` socket bound to the peer end of the injected interface's veth
//! pair) so the DPDK port genuinely receives them via `rte_eth_rx_burst`.
//! Linux's `AF_PACKET` raw send path refuses anything shorter than
//! `ETH_HLEN` (14 bytes) with `EINVAL` (verified empirically: sending 13
//! bytes fails, 14 succeeds) — a real NIC/kernel constraint, not a DPDK
//! quirk, and one a pure-software backend like `SimIo` never hits.
//! `inject_rx` pads any shorter payload up to 14 bytes with trailing zeros
//! and reports the *padded* length as `requested_len`, so every
//! length/token/kind assertion in the reusable suite still holds. The one
//! exception is `commit_is_submitted_in_place_with_exact_descriptor`, whose
//! body hardcodes an exact 3-byte content comparison
//! (`assert_eq!(events[0].bytes, [0x10, 0x99, 0x30])`); no padding scheme
//! can satisfy that against a real wire, since the receiver has no way to
//! tell which trailing bytes were padding. That one case is therefore not
//! wired to this real backend; `commit_is_submitted_in_place_with_a_real_wire_frame`
//! below exercises the same "commit lands in place with the exact
//! descriptor" property directly, with a payload at the real Ethernet
//! minimum.

#![cfg(dpdk_available)]
#![allow(unsafe_code)]

use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::{c_char, c_int, c_void, CString},
    io, mem,
    os::fd::RawFd,
    sync::{Mutex, MutexGuard, OnceLock},
};

use ruster_core::{IfId, PacketBatch, PacketIo};
use ruster_io_conformance::{
    generated, rx, BufferToken, GeneratedEvent, GeneratedEventKind, GeneratedFinishErrorHarness,
    GeneratedFinitePoolHarness, GeneratedHarness, GeneratedReclaim, GeneratedUnknownEgressHarness,
    LeaseObserver, LiveFrame, RxEvent, RxEventKind, RxFinishErrorHarness, RxHarness,
    RxReceiveErrorHarness, RxReclaim, TxEndpoint, CONFORMANCE_LAN, CONFORMANCE_LAN_ENDPOINT,
    CONFORMANCE_WAN, CONFORMANCE_WAN_ENDPOINT,
};
use ruster_io_dpdk::{
    DpdkConfig, DpdkIo, PortBinding, RecordedDisposition, RecordedRxDisposition, ValidatedConfig,
};

/// Real Ethernet minimum frame size (`ETH_HLEN`): dst MAC + src MAC +
/// ethertype. `inject_rx` pads up to this; see the module docs.
const ETH_HLEN: usize = 14;

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
        // This fixes the pool's `data_room_size` (128-byte headroom plus
        // this) at DPDK port setup time; `af_packet`'s `rte_eth_rx_queue_setup`
        // refused a data room under ~2016 bytes ("will not fit in mbuf"),
        // even though every test payload is far smaller. The generated-path
        // tests separately call `set_max_frame_len(1500)` on every fresh
        // harness, which only tightens `allocate()`'s runtime size check;
        // it does not touch this fixed pool geometry.
        max_frame_len: 2048,
        tx_ring_descriptors: 128,
        rx_ring_descriptors: 128,
    }
}

/// Everything the test binary shares across every `#[test]`: the one live
/// `DpdkIo` DPDK's process-global EAL allows, and one raw injection socket
/// per interface, each bound to that interface's *peer* veth end so sending
/// on it is received by the DPDK port on the other end.
struct World {
    io: DpdkIo,
    lan_sender: RawFrameSender,
    wan_sender: RawFrameSender,
}

/// DPDK's EAL initializes exactly once per process, and every test in this
/// binary shares one pair of ports, so all of them run against one live
/// `DpdkIo` (and its injection sockets) serialized behind this lock rather
/// than each opening their own.
fn world() -> &'static Mutex<World> {
    static WORLD: OnceLock<Mutex<World>> = OnceLock::new();
    WORLD.get_or_init(|| {
        let validated = ValidatedConfig::new(test_config()).expect("valid DPDK test config");
        let io = DpdkIo::open(validated).expect(
            "DPDK test environment missing: create veth-lan0/veth-lan1 and \
             veth-wan0/veth-wan1 and run this binary as root, see the module docs",
        );
        let lan_sender = RawFrameSender::open("veth-lan1").expect(
            "cannot open the veth-lan1 injection socket: create the veth pair and run as root",
        );
        let wan_sender = RawFrameSender::open("veth-wan1").expect(
            "cannot open the veth-wan1 injection socket: create the veth pair and run as root",
        );
        Mutex::new(World {
            io,
            lan_sender,
            wan_sender,
        })
    })
}

// ---------------------------------------------------------------------------
// Generated-frame harness (unchanged in behavior from the TX-only round;
// address-keyed identity is correct here because this crate's own
// `allocate()` hands out the real backing address up front).
// ---------------------------------------------------------------------------

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

fn publication_endpoint(egress: IfId) -> Option<TxEndpoint> {
    match egress {
        CONFORMANCE_LAN => Some(CONFORMANCE_LAN_ENDPOINT),
        CONFORMANCE_WAN => Some(CONFORMANCE_WAN_ENDPOINT),
        _ => None,
    }
}

struct DpdkHarness {
    world: MutexGuard<'static, World>,
    observer: DpdkObserver,
}

impl GeneratedHarness for DpdkHarness {
    type Io = DpdkIo;
    type Observer = DpdkObserver;

    fn new() -> Self {
        let mut world = world()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Every test in this binary shares one process-wide `DpdkIo`; start
        // each one from the same clean slate regardless of what an earlier
        // test configured.
        world.io.reset_test_hooks_for_test();
        world.io.set_max_frame_len(1500);
        Self {
            world,
            observer: DpdkObserver::default(),
        }
    }

    fn io_and_observer(&mut self) -> (&mut Self::Io, &mut Self::Observer) {
        (&mut self.world.io, &mut self.observer)
    }

    fn set_generated_allocation_budget(&mut self, budget: usize) {
        self.world
            .io
            .set_generated_allocation_budget_for_test(budget);
    }

    fn set_generated_max_frame(&mut self, max_frame: usize) {
        let max_frame = u16::try_from(max_frame).expect("test max_frame fits u16");
        self.world.io.set_max_frame_len(max_frame);
    }

    fn set_generated_accept_budget(&mut self, budget: usize) {
        self.world.io.set_generated_accept_budget_for_test(budget);
    }

    fn drain_generated_events(&mut self) -> Vec<GeneratedEvent> {
        self.world
            .io
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
                        endpoint: publication_endpoint(event.egress)
                            .expect("a submitted frame always has a known endpoint"),
                        descriptor_len: event.bytes.len(),
                    },
                    RecordedDisposition::TxRejected => GeneratedEventKind::TxRejected {
                        attempted_egress: event.egress,
                        endpoint: publication_endpoint(event.egress),
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
        self.world.io.fail_next_generated_finish_for_test();
    }
}

impl GeneratedFinitePoolHarness for DpdkHarness {
    fn free_generated_frames(&self) -> usize {
        self.world.io.free_generated_frames_for_test()
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

// ---------------------------------------------------------------------------
// RX harness. Identity is content-keyed rather than address-keyed: a real
// received mbuf's address is chosen by the pool/driver, not by this
// harness, so `inject_rx` cannot know it up front the way `allocate()`'s
// caller does for the generated path. Every payload this suite injects is
// distinct, so keying on the (post-padding) byte content is unambiguous —
// but only until the first `observe()`: a backend is allowed to commit a
// frame *with in-place edits already applied*
// (`commit_is_submitted_in_place_with_a_real_wire_frame` below does exactly
// that), so content is not stable for the frame's whole lifetime the way a
// real address is. The first `observe()` call therefore "upgrades" a
// frame's identity from its original content to the real address it was
// observed at (still consistent, since a live mbuf's address never moves),
// and every later lookup for that frame uses the address instead. `observe`
// takes `&self` per the trait, so the two maps live behind a `RefCell`.
#[derive(Default)]
struct RxObserver {
    next_id: RefCell<u64>,
    live_by_content: RefCell<BTreeMap<Vec<u8>, LiveFrame>>,
    live_by_address: RefCell<BTreeMap<usize, LiveFrame>>,
}

impl RxObserver {
    fn inject(&self, bytes: &[u8]) -> LiveFrame {
        let mut next_id = self.next_id.borrow_mut();
        *next_id = next_id.checked_add(1).expect("RX injection id overflow");
        let frame = LiveFrame {
            token: BufferToken::new(*next_id, 1),
            visible_address: usize::try_from(*next_id).expect("id fits usize"),
            requested_len: bytes.len(),
        };
        self.live_by_content
            .borrow_mut()
            .insert(bytes.to_vec(), frame);
        frame
    }
}

impl LeaseObserver for RxObserver {
    /// The reusable suite never calls `bind()` on an RX observer directly
    /// (RX identity begins at `inject_rx`, not inside a leased slot's
    /// `bytes_mut()`); this exists only to satisfy the trait.
    fn bind(&mut self, bytes: &[u8], requested_len: usize) -> LiveFrame {
        assert_eq!(bytes.len(), requested_len);
        self.inject(bytes)
    }

    fn observe(&self, bytes: &[u8]) -> LiveFrame {
        let address = bytes.as_ptr() as usize;
        if let Some(frame) = self.live_by_address.borrow().get(&address) {
            return *frame;
        }
        let frame = *self.live_by_content.borrow().get(bytes).expect(
            "DPDK RX terminal event content does not match any injected frame's original bytes",
        );
        self.live_by_content.borrow_mut().remove(bytes);
        self.live_by_address.borrow_mut().insert(address, frame);
        frame
    }
}

impl RxObserver {
    fn terminal(&mut self, bytes: &[u8]) -> LiveFrame {
        let frame = self.observe(bytes);
        let address = bytes.as_ptr() as usize;
        self.live_by_address.borrow_mut().remove(&address);
        self.live_by_content.borrow_mut().remove(bytes);
        frame
    }
}

struct DpdkRxHarness {
    world: MutexGuard<'static, World>,
    observer: RxObserver,
    /// Frames sent via `inject_rx` but not yet accounted for by
    /// `io.rx_pulled_total_for_test()`. See `pending_rx()`.
    injected_len: usize,
}

impl DpdkRxHarness {
    fn sender_for(&mut self, ingress: IfId) -> &mut RawFrameSender {
        match ingress {
            CONFORMANCE_LAN => &mut self.world.lan_sender,
            CONFORMANCE_WAN => &mut self.world.wan_sender,
            other => panic!("no injection socket configured for interface {other:?}"),
        }
    }
}

impl RxHarness for DpdkRxHarness {
    type Io = DpdkIo;
    type Observer = RxObserver;

    fn new() -> Self {
        let mut world = world()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        world.io.reset_test_hooks_for_test();
        Self {
            world,
            observer: RxObserver::default(),
            injected_len: 0,
        }
    }

    fn io_and_observer(&mut self) -> (&mut Self::Io, &mut Self::Observer) {
        (&mut self.world.io, &mut self.observer)
    }

    fn inject_rx(&mut self, ingress: IfId, bytes: Vec<u8>) -> LiveFrame {
        // See the module docs: Linux's AF_PACKET raw send refuses anything
        // shorter than the real Ethernet minimum frame size.
        let mut wire = bytes;
        wire.resize(wire.len().max(ETH_HLEN), 0);
        let frame = self.observer.inject(&wire);
        self.sender_for(ingress)
            .send(&wire)
            .unwrap_or_else(|error| panic!("raw RX injection send failed: {error}"));
        self.injected_len += 1;
        frame
    }

    fn set_rx_accept_budget(&mut self, budget: usize) {
        self.world.io.set_rx_accept_budget_for_test(budget);
    }

    fn pending_rx(&self) -> usize {
        let pulled = self.world.io.rx_pulled_total_for_test();
        let pulled = usize::try_from(pulled).unwrap_or(usize::MAX);
        self.injected_len.saturating_sub(pulled)
    }

    fn drain_rx_events(&mut self) -> Vec<RxEvent> {
        self.world
            .io
            .drain_rx_events_for_test()
            .into_iter()
            .map(|event| {
                // SAFETY: same reasoning as the generated harness's
                // `drain_generated_events`: this slice's contents are never
                // read, only compared by pointer and length against the
                // observer's own content-keyed record. (The lookup itself
                // is content-based, so this only needs to be a valid,
                // readable range — which it is, since nothing has freed or
                // reused this address between recording and draining.)
                let identity =
                    unsafe { std::slice::from_raw_parts(event.address as *const u8, event.len) };
                let frame = self.observer.terminal(identity);
                let kind = match event.kind {
                    RecordedRxDisposition::TxSubmitted => RxEventKind::TxSubmitted {
                        endpoint: publication_endpoint(
                            event
                                .egress
                                .expect("a submitted frame always has an egress"),
                        )
                        .expect("a submitted frame always has a known endpoint"),
                        descriptor_len: event.bytes.len(),
                    },
                    RecordedRxDisposition::TxRejected => RxEventKind::TxRejected {
                        attempted_egress: event
                            .egress
                            .expect("a rejected frame always has an egress"),
                        endpoint: event.egress.and_then(publication_endpoint),
                    },
                    RecordedRxDisposition::Recycled(reason) => {
                        RxEventKind::Reclaimed(RxReclaim::Recycled(reason))
                    }
                    RecordedRxDisposition::Consumed(reason) => {
                        RxEventKind::Reclaimed(RxReclaim::Consumed(reason))
                    }
                    RecordedRxDisposition::Abandoned => {
                        RxEventKind::Reclaimed(RxReclaim::Abandoned)
                    }
                };
                RxEvent {
                    frame,
                    ingress: event.ingress,
                    bytes: event.bytes,
                    kind,
                }
            })
            .collect()
    }
}

impl RxReceiveErrorHarness for DpdkRxHarness {
    fn fail_next_receive(&mut self) {
        self.world.io.fail_next_receive_for_test();
    }
}

impl RxFinishErrorHarness for DpdkRxHarness {
    fn fail_next_rx_finish(&mut self) {
        self.world.io.fail_next_rx_finish_for_test();
    }
}

#[test]
fn rx_budget_and_unleased_slots_are_exact() {
    rx::budget_and_unleased_slots_are_exact::<DpdkRxHarness>();
}

#[test]
fn rx_recycle_consume_and_abandon_are_distinct() {
    rx::recycle_consume_and_abandon_are_distinct::<DpdkRxHarness>();
}

#[test]
fn rx_partial_reject_reclaims_exact_tokens() {
    rx::partial_reject_reclaims_exact_tokens::<DpdkRxHarness>();
}

#[test]
fn rx_receive_error_preserves_queued_ownership() {
    rx::receive_error_preserves_queued_ownership::<DpdkRxHarness>();
}

#[test]
fn rx_partial_reject_with_finish_error_is_exact() {
    rx::partial_reject_with_finish_error_is_exact::<DpdkRxHarness>();
}

/// Same property as the reusable suite's
/// `commit_is_submitted_in_place_with_exact_descriptor`, exercised directly
/// with a real Ethernet-minimum-sized payload instead of that function's
/// hardcoded 3-byte one (see the module docs for why the exact function
/// cannot run against a real wire).
#[test]
fn commit_is_submitted_in_place_with_a_real_wire_frame() {
    let mut harness = DpdkRxHarness::new();
    let endpoint = CONFORMANCE_WAN_ENDPOINT;
    let payload = vec![0x10_u8; ETH_HLEN];
    let injected = harness.inject_rx(CONFORMANCE_LAN, payload);
    let completion = {
        let (io, observer) = harness.io_and_observer();
        let mut batch = io.receive(1).expect("RX receive failed");
        let mut packet = batch.next_packet().expect("one RX lease");
        assert_eq!(packet.ingress(), CONFORMANCE_LAN);
        let observed = observer.observe(packet.bytes_mut());
        assert_eq!(observed, injected);
        packet.bytes_mut()[1] = 0x99;
        packet.commit(CONFORMANCE_WAN);
        batch.finish()
    };
    assert!(completion.invariants_hold());
    assert_eq!(
        (
            completion.tx_requested,
            completion.tx_accepted,
            completion.tx_rejected,
            completion.recycled,
        ),
        (1, 1, 0, 0)
    );
    let events = harness.drain_rx_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].frame, injected);
    let mut expected_bytes = vec![0x10_u8; ETH_HLEN];
    expected_bytes[1] = 0x99;
    assert_eq!(events[0].bytes, expected_bytes);
    assert_eq!(
        events[0].kind,
        RxEventKind::TxSubmitted {
            endpoint,
            descriptor_len: injected.requested_len,
        }
    );
}

// ---------------------------------------------------------------------------
// Minimal raw AF_PACKET sender used only to inject RX traffic for the tests
// above. Adapted from `ruster-io-sim`'s
// `tests/backend_differential_live.rs::RawPacketSender`, trimmed to a
// single bound-interface `send` (this harness always knows which interface
// it is injecting on; it does not need a per-packet destination address).
// ---------------------------------------------------------------------------

const AF_PACKET: c_int = 17;
const SOCK_RAW: c_int = 3;
const SOCK_CLOEXEC: c_int = 0x0008_0000;
const ETH_P_ALL: u16 = 0x0003;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

struct RawFrameSender {
    fd: RawFd,
}

impl RawFrameSender {
    fn open(interface: &str) -> Result<Self, String> {
        let name = CString::new(interface).expect("interface name has no interior NUL");
        // SAFETY: `name` is a live, NUL-terminated interface name for this
        // one call.
        let if_index = unsafe { if_nametoindex(name.as_ptr()) };
        if if_index == 0 {
            return Err(format!(
                "if_nametoindex({interface}): {}",
                io::Error::last_os_error()
            ));
        }
        let protocol = ETH_P_ALL.to_be();
        // SAFETY: no pointer arguments; the returned descriptor is owned by
        // this value on success.
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, i32::from(protocol)) };
        if fd < 0 {
            return Err(format!("socket(AF_PACKET): {}", io::Error::last_os_error()));
        }
        let sender = Self { fd };
        let address = SockaddrLl {
            sll_family: AF_PACKET as u16,
            sll_protocol: protocol,
            sll_ifindex: i32::try_from(if_index).expect("Linux ifindex fits sockaddr_ll"),
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        // SAFETY: `address` is initialized and lives for this call; the
        // socket is owned exclusively by `sender`.
        let result = unsafe {
            bind(
                sender.fd,
                (&address as *const SockaddrLl).cast::<c_void>(),
                u32::try_from(mem::size_of::<SockaddrLl>()).expect("sockaddr_ll fits socklen_t"),
            )
        };
        if result < 0 {
            return Err(format!(
                "bind(AF_PACKET, {interface}): {}",
                io::Error::last_os_error()
            ));
        }
        Ok(sender)
    }

    fn send(&mut self, frame: &[u8]) -> Result<(), String> {
        // SAFETY: `frame` is live for the duration of this call, and the
        // socket is bound and owned exclusively by `self`.
        let sent = unsafe { libc_send(self.fd, frame.as_ptr().cast::<c_void>(), frame.len(), 0) };
        if sent < 0 {
            return Err(format!("send(AF_PACKET): {}", io::Error::last_os_error()));
        }
        let sent = usize::try_from(sent).expect("successful send length is nonnegative");
        if sent != frame.len() {
            return Err(format!(
                "send(AF_PACKET) wrote {sent} bytes instead of {}",
                frame.len()
            ));
        }
        Ok(())
    }
}

impl Drop for RawFrameSender {
    fn drop(&mut self) {
        // SAFETY: this value owns the descriptor `socket` returned.
        unsafe {
            let _ = close(self.fd);
        }
    }
}

extern "C" {
    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    fn bind(fd: c_int, address: *const c_void, length: u32) -> c_int;
    #[link_name = "send"]
    fn libc_send(fd: c_int, buffer: *const c_void, length: usize, flags: c_int) -> isize;
    fn close(fd: c_int) -> c_int;
    fn if_nametoindex(name: *const c_char) -> u32;
}
