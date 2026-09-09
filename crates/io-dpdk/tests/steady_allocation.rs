//! Verifies the DPDK backend's own Rust code allocates nothing once it
//! reaches steady state, using the same thread-local `GlobalAlloc`-counting
//! idiom as `crates/runtime/tests/steady_allocation.rs` and
//! `crates/integration/tests/steady_allocation.rs`.
//!
//! Deliberately built with the `dpdk` feature only, **not** `test-hooks`:
//! `test-hooks`'s disposition event log calls `.to_vec()` on every commit,
//! unconditionally at compile time (the `#[cfg(feature = "test-hooks")]`
//! gate controls compilation, not a runtime branch), which would measure
//! that test-only instrumentation instead of the production hot path. This
//! binary exercises `GeneratedPacketIo` and `PacketIo` directly, with no
//! test-hook methods at all.
//!
//! `#![cfg(all(dpdk_available, not(feature = "test-hooks")))]` below makes
//! this structural rather than a documentation note to remember: Cargo
//! unifies features workspace-wide per invocation, so
//! `cargo test --features dpdk,test-hooks` (the command
//! `tests/backend_conformance.rs` needs) would otherwise silently link this
//! binary against the test-hooks-instrumented library too and turn a real
//! measurement into a false, if fully reproducible, failure. With the cfg
//! gate, that same invocation instead compiles this file to zero tests, and
//! the correct measuring invocation (below) is the only way to actually run
//! it.
//!
//! # Scope of this measurement
//!
//! This can only speak for `ruster-io-dpdk`'s own Rust code, which is
//! everything this crate controls: every `Vec` on the hot path
//! (`DpdkIo::scratch`, `PortState::tx_pending`, `DpdkIo::rx_scratch`,
//! `DpdkIo::touched_scratch`) is reserved once at construction and only
//! ever `clear()`/`pop()`/bounded-`push()`ed afterward, matching the
//! measurement below. It says nothing about what `libdpdk` itself does
//! inside `rte_pktmbuf_alloc`/`rte_eth_rx_burst`/`rte_eth_tx_burst`: those
//! are calls into a C library that manages its own memory (mempool rings
//! backed by `--no-huge` anonymous `mmap`, not `malloc`/`free` per packet in
//! steady state) entirely outside Rust's `#[global_allocator]` hook, which
//! only intercepts `std::alloc`-routed allocations made by code compiled
//! against it. A C library calling `malloc` directly is invisible to it.
//! DPDK's own documented mempool design does not allocate per-object once
//! the pool is created, but that is a property of `libdpdk`, not something
//! this counter can observe or prove.
//!
//! Same environment as `tests/backend_conformance.rs`: two `af_packet`
//! vdevs over veth pairs, run as root.
//!
//! ```sh
//! cargo test -p ruster-io-dpdk --features dpdk --no-run
//! sudo target/debug/deps/steady_allocation-* --test-threads=1
//! ```
//!
//! Build this target with **exactly** `--features dpdk` in its own
//! `cargo test`/`--no-run` invocation. Building it together with
//! `test-hooks` (as `tests/backend_conformance.rs` needs) does not fail and
//! does not measure anything either: the cfg gate below degrades it to zero
//! tests in that configuration instead.

#![cfg(all(dpdk_available, not(feature = "test-hooks")))]
#![allow(unsafe_code)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    ffi::{c_char, c_int, c_void, CString},
    mem,
    os::fd::RawFd,
    sync::{Mutex, OnceLock},
};

use ruster_core::{GeneratedPacketBatch, GeneratedPacketIo, IfId, PacketBatch, PacketIo};
use ruster_io_dpdk::{DpdkConfig, DpdkIo, PortBinding, ValidatedConfig};

struct CountingAllocator;

// Per thread, matching every other allocation suite in this workspace: a
// process-wide counter would also see allocations from unrelated threads
// (this binary's own DPDK EAL housekeeping threads included).
thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn record_allocation() {
    ALLOCATIONS.with(|count| count.set(count.get().saturating_add(1)));
}

fn allocation_count() -> usize {
    ALLOCATIONS.with(Cell::get)
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: `layout` is the allocator contract supplied by the caller.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` and `layout` came from this allocator.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: `layout` is the allocator contract supplied by the caller.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation();
        // SAFETY: `pointer` and `layout` came from this allocator.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

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
        pool_cache_size: 0,
        // >=2016 to satisfy the af_packet PMD's RX queue setup; see
        // tests/backend_conformance.rs's module docs for the same
        // constraint.
        max_frame_len: 2048,
        tx_ring_descriptors: 128,
        rx_ring_descriptors: 128,
    }
}

const CONFORMANCE_LAN: IfId = IfId(11);
const CONFORMANCE_WAN: IfId = IfId(22);
const ITERATIONS: usize = 1_024;
const FRAME_LEN: usize = 64;
const ETH_HLEN: usize = 14;

/// DPDK's EAL initializes exactly once per process (`rte_eal_cleanup`
/// running when the first test's `DpdkIo` drops was not, in practice,
/// enough to let a second `rte_eal_init` in the same process succeed
/// against these `af_packet` vdevs — it failed with "already called
/// initialization"), so both tests below share one live `DpdkIo` and
/// injection socket, serialized behind this lock, exactly like
/// `tests/backend_conformance.rs` does for the same reason.
struct World {
    io: DpdkIo,
    lan_sender: RawFrameSender,
}

fn world() -> &'static Mutex<World> {
    static WORLD: OnceLock<Mutex<World>> = OnceLock::new();
    WORLD.get_or_init(|| {
        let validated = ValidatedConfig::new(test_config()).expect("valid DPDK test config");
        let io = DpdkIo::open(validated).expect(
            "DPDK test environment missing: create veth-lan0/veth-lan1 and \
             veth-wan0/veth-wan1 and run this binary as root",
        );
        let lan_sender = RawFrameSender::open("veth-lan1").expect(
            "cannot open the veth-lan1 injection socket: create the veth pair and run as root",
        );
        Mutex::new(World { io, lan_sender })
    })
}

#[test]
fn generated_tx_reaches_zero_allocation_steady_state() {
    let mut world = world()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Warm-up: exercises every code path once before measuring, matching
    // the idiom in crates/runtime and crates/integration's own
    // steady_allocation tests.
    for _ in 0..64 {
        run_one_generated_cycle(&mut world.io);
    }

    let before = allocation_count();
    for _ in 0..ITERATIONS {
        run_one_generated_cycle(&mut world.io);
    }
    let after = allocation_count();

    assert_eq!(
        after, before,
        "ruster-io-dpdk's own Rust code allocated during steady-state generated TX"
    );
}

fn run_one_generated_cycle(io: &mut DpdkIo) {
    let mut batch = io.begin_generated(CONFORMANCE_LAN);
    let mut packet = batch.allocate(FRAME_LEN).expect("generated allocation");
    packet.bytes_mut().fill(0xab);
    packet.commit();
    let completion = batch.finish();
    assert!(completion.invariants_hold());
}

#[test]
fn rx_forward_reaches_zero_allocation_steady_state() {
    let mut guard = world()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let world = &mut *guard;
    let frame = [0xcd_u8; ETH_HLEN];

    for _ in 0..64 {
        run_one_rx_cycle(&mut world.io, &mut world.lan_sender, &frame);
    }

    let before = allocation_count();
    for _ in 0..ITERATIONS {
        run_one_rx_cycle(&mut world.io, &mut world.lan_sender, &frame);
    }
    let after = allocation_count();

    assert_eq!(
        after, before,
        "ruster-io-dpdk's own Rust code allocated during steady-state RX forwarding"
    );
}

fn run_one_rx_cycle(io: &mut DpdkIo, sender: &mut RawFrameSender, frame: &[u8; ETH_HLEN]) {
    sender.send(frame).expect("raw RX injection send failed");
    // The kernel delivers the frame to the af_packet socket asynchronously;
    // an empty poll just means it has not arrived yet. Bounded so a genuine
    // delivery failure fails the test instead of spinning forever; a local
    // veth normally resolves this on the first or second attempt.
    for _ in 0..1_000 {
        let mut batch = io.receive(8).expect("RX receive failed");
        let Some(packet) = batch.next_packet() else {
            let completion = batch.finish();
            assert!(completion.invariants_hold());
            continue;
        };
        packet.commit(CONFORMANCE_WAN);
        let completion = batch.finish();
        assert!(completion.invariants_hold());
        assert_eq!(completion.tx_accepted, 1);
        return;
    }
    panic!("injected RX frame never arrived within the retry bound");
}

// ---------------------------------------------------------------------------
// Minimal raw AF_PACKET sender, identical in spirit to the one in
// tests/backend_conformance.rs but reusing one fixed-size buffer with no
// per-call allocation, since this one runs inside the measured window.
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
            return Err(format!("if_nametoindex({interface}) failed"));
        }
        let protocol = ETH_P_ALL.to_be();
        // SAFETY: no pointer arguments; the returned descriptor is owned by
        // this value on success.
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, i32::from(protocol)) };
        if fd < 0 {
            return Err("socket(AF_PACKET) failed".to_string());
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
            return Err(format!("bind(AF_PACKET, {interface}) failed"));
        }
        Ok(sender)
    }

    fn send(&mut self, frame: &[u8]) -> Result<(), String> {
        // SAFETY: `frame` is live for the duration of this call, and the
        // socket is bound and owned exclusively by `self`.
        let sent = unsafe { libc_send(self.fd, frame.as_ptr().cast::<c_void>(), frame.len(), 0) };
        if sent < 0 || usize::try_from(sent).unwrap_or(0) != frame.len() {
            return Err("send(AF_PACKET) failed".to_string());
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
