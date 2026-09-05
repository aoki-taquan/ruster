//! Privileged three-way differential testing of the real packet backends.
//!
//! The deterministic model lane lives in `backend_differential.rs` and always
//! runs without privileges.  This target is the opt-in live lane: it injects
//! the same wire-safe Ethernet frame through a raw AF_PACKET sender, runs the
//! real `SimIo`, `AfPacketIo`, and `XdpResource` paths with one shared core
//! snapshot, and compares the normalized report and forwarding trace.

#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
#![allow(unsafe_code)]

use std::{
    ffi::{c_char, c_int, c_void, CString},
    fs, io,
    mem::size_of,
    os::fd::RawFd,
    time::Duration,
};

use ruster_core::{
    forward_batch, ipv4_header_checksum, ForwardingSnapshot, IfId, Interface, Ipv4Address, Ipv4Mtu,
    MacAddress, Neighbor, PacketIo, PublicationQuiescenceBackend, Route,
};
use ruster_io_conformance::{
    differential::{generate_case, DifferentialCase, ErrorCategory, NormalizedObservation},
    differential_live::{
        observation_from_trace, run_native_live_case, LiveBackendConfig, LiveFrameSender,
    },
};
use ruster_io_sim::{FrameOrigin, RecycleCause, SimIo, VecTrace};

const LIVE_RANDOM_SEED: u64 = 0x6c69_7665_6469_6601;
const LIVE_STRUCTURED_SEED: u64 = 0x6c69_7665_6469_6602;
const LIVE_DEFAULT_ITERATIONS: usize = 5;
const LIVE_MAX_ITERATIONS: usize = 64;
const LIVE_DEFAULT_TIMEOUT_MS: u64 = 2_000;
const LIVE_MAX_TIMEOUT_MS: u64 = 30_000;

const DESTINATION_IP: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 20]);
const DESTINATION_PREFIX: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 0]);

const AF_PACKET: c_int = 17;
const SOCK_RAW: c_int = 3;
const SOCK_CLOEXEC: c_int = 0x0008_0000;
const ETH_P_ALL: u16 = 0x0003;
const MSG_DONTWAIT: c_int = 0x40;
const EAGAIN: i32 = 11;
const EINTR: i32 = 4;
const SC_PAGESIZE: c_int = 30;

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

struct RawPacketSender {
    fd: RawFd,
    peer_if_index: u32,
}

impl RawPacketSender {
    fn open(peer_if_index: u32) -> Result<Self, String> {
        let protocol = ETH_P_ALL.to_be();
        // SAFETY: socket has no pointer arguments and the descriptor is
        // owned by the returned sender on success.
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, i32::from(protocol)) };
        if fd < 0 {
            return Err(format!("socket(AF_PACKET): {}", io::Error::last_os_error()));
        }
        let sender = Self { fd, peer_if_index };
        let address = sockaddr(peer_if_index, protocol, &[0; 6]);
        // SAFETY: `address` is initialized and lives for the duration of the
        // bind call; `sender.fd` is owned by this value.
        let result = unsafe {
            bind(
                sender.fd,
                (&address as *const SockaddrLl).cast::<c_void>(),
                u32::try_from(size_of::<SockaddrLl>()).expect("sockaddr_ll fits socklen_t"),
            )
        };
        if result < 0 {
            return Err(format!(
                "bind(AF_PACKET peer): {}",
                io::Error::last_os_error()
            ));
        }
        Ok(sender)
    }
}

impl Drop for RawPacketSender {
    fn drop(&mut self) {
        // SAFETY: this value owns the descriptor returned by `socket`.
        unsafe {
            let _ = close(self.fd);
        }
    }
}

impl LiveFrameSender for RawPacketSender {
    fn send(&mut self, peer_if_index: u32, frame: &[u8]) -> Result<(), String> {
        if peer_if_index != self.peer_if_index {
            return Err("sender peer ifindex changed during a live run".to_owned());
        }
        let destination = frame.get(..6).ok_or_else(|| {
            "live sender received a frame shorter than an Ethernet address".to_owned()
        })?;
        let address = sockaddr(peer_if_index, ETH_P_ALL.to_be(), destination);
        loop {
            // SAFETY: `frame` and `address` remain live for this syscall.
            let sent = unsafe {
                sendto(
                    self.fd,
                    frame.as_ptr().cast::<c_void>(),
                    frame.len(),
                    MSG_DONTWAIT,
                    (&address as *const SockaddrLl).cast::<c_void>(),
                    u32::try_from(size_of::<SockaddrLl>()).expect("sockaddr_ll fits socklen_t"),
                )
            };
            if sent >= 0 {
                let sent = usize::try_from(sent).expect("successful send length is nonnegative");
                if sent == frame.len() {
                    return Ok(());
                }
                return Err(format!(
                    "sendto(AF_PACKET) wrote {sent} bytes instead of {}",
                    frame.len()
                ));
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(EINTR) => continue,
                Some(EAGAIN) => {
                    return Err(format!("sendto(AF_PACKET) would block: {error}"));
                }
                _ => return Err(format!("sendto(AF_PACKET): {error}")),
            }
        }
    }
}

#[test]
fn privileged_backend_differential_live_lane() {
    if !privileged_live_lane_requested() {
        return;
    }

    let target_name = required_var("RUSTER_DIFF_TARGET_IFACE");
    let peer_name = required_var("RUSTER_DIFF_PEER_IFACE");
    assert_ne!(
        target_name, peer_name,
        "RUSTER_DIFF_TARGET_IFACE and RUSTER_DIFF_PEER_IFACE must name different links"
    );
    let target_if_index = interface_index(&target_name);
    let peer_if_index = interface_index(&peer_name);
    let target_mac = interface_mac(&target_name);
    let peer_mac = interface_mac(&peer_name);
    let target_interface = parse_if_id("RUSTER_DIFF_TARGET_IF_ID", 11);
    let page_size = system_page_size();
    let queue_id = parse_u32("RUSTER_DIFF_QUEUE_ID", 0);
    let timeout = Duration::from_millis(parse_u64_bounded(
        "RUSTER_DIFF_TIMEOUT_MS",
        LIVE_DEFAULT_TIMEOUT_MS,
        LIVE_MAX_TIMEOUT_MS,
    ));
    let iterations = parse_usize_bounded(
        "RUSTER_DIFF_ITERATIONS",
        LIVE_DEFAULT_ITERATIONS,
        LIVE_MAX_ITERATIONS,
    );
    let config = LiveBackendConfig {
        target_if_index,
        peer_if_index,
        target_interface,
        page_size,
        queue_id,
        timeout,
    };
    let snapshot = differential_snapshot(target_interface, target_mac, peer_mac);
    let mut sender = RawPacketSender::open(peer_if_index)
        .unwrap_or_else(|error| panic!("privileged live sender setup failed: {error}"));

    for structured in [false, true] {
        let seed = if structured {
            LIVE_STRUCTURED_SEED
        } else {
            LIVE_RANDOM_SEED
        };
        for iteration in 0..iterations {
            let case = wire_safe_case(
                seed,
                iteration as u64,
                structured,
                target_interface,
                target_mac,
                peer_mac,
            );
            let sim = run_sim_case(&case, &snapshot);
            let (af_packet, xdp_native) = run_native_live_case(
                &mut sender,
                config,
                &case,
                &snapshot,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "privileged live backend setup/execution failed: {error:?}; strategy={} seed=0x{:016x} iteration={} frame_len={} frame_hex={}",
                    if structured { "structured" } else { "random" },
                    case.seed,
                    case.iteration,
                    case.frame.len(),
                    hex(&case.frame),
                )
            });
            assert_eq!(
                sim,
                af_packet,
                "live differential mismatch: sim vs AF_PACKET strategy={} seed=0x{:016x} iteration={} frame_hex={}",
                if structured { "structured" } else { "random" },
                case.seed,
                case.iteration,
                hex(&case.frame),
            );
            assert_eq!(
                sim,
                xdp_native,
                "live differential mismatch: sim vs AF_XDP strategy={} seed=0x{:016x} iteration={} frame_hex={}",
                if structured { "structured" } else { "random" },
                case.seed,
                case.iteration,
                hex(&case.frame),
            );
            assert_eq!(
                af_packet, xdp_native,
                "live differential mismatch: AF_PACKET vs AF_XDP strategy={} seed=0x{:016x} iteration={} frame_hex={}",
                if structured { "structured" } else { "random" },
                case.seed,
                case.iteration,
                hex(&case.frame),
            );
        }
    }
}

fn privileged_live_lane_requested() -> bool {
    match std::env::var("RUSTER_PRIVILEGED_E2E") {
        Ok(value) if value == "1" => true,
        Ok(value) => {
            println!(
                "backend differential live lane skipped: RUSTER_PRIVILEGED_E2E={value:?}; set it to 1 to request the privileged live lane"
            );
            false
        }
        Err(std::env::VarError::NotPresent) => {
            println!(
                "backend differential live lane skipped: RUSTER_PRIVILEGED_E2E is unset; set it to 1 to request the privileged live lane"
            );
            false
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            println!(
                "backend differential live lane skipped: RUSTER_PRIVILEGED_E2E is not valid UTF-8; set it to 1 to request the privileged live lane"
            );
            false
        }
    }
}

fn required_var(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|error| panic!("{name} is required when RUSTER_PRIVILEGED_E2E=1: {error}"))
}

fn parse_if_id(name: &str, default: u16) -> IfId {
    let value = std::env::var(name).unwrap_or_else(|_| default.to_string());
    let value = value
        .parse::<u16>()
        .unwrap_or_else(|error| panic!("{name} must be a u16: {error}"));
    assert_ne!(value, u16::MAX, "{name} must not be u16::MAX");
    IfId(value)
}

fn parse_u32(name: &str, default: u32) -> u32 {
    let value = std::env::var(name).unwrap_or_else(|_| default.to_string());
    value
        .parse::<u32>()
        .unwrap_or_else(|error| panic!("{name} must be a u32: {error}"))
}

fn parse_u64_bounded(name: &str, default: u64, max: u64) -> u64 {
    let value = std::env::var(name).unwrap_or_else(|_| default.to_string());
    let value = value
        .parse::<u64>()
        .unwrap_or_else(|error| panic!("{name} must be a u64: {error}"));
    assert!(value > 0 && value <= max, "{name} must be in 1..={max}");
    value
}

fn parse_usize_bounded(name: &str, default: usize, max: usize) -> usize {
    let value = std::env::var(name).unwrap_or_else(|_| default.to_string());
    let value = value
        .parse::<usize>()
        .unwrap_or_else(|error| panic!("{name} must be a usize: {error}"));
    assert!(value > 0 && value <= max, "{name} must be in 1..={max}");
    value
}

fn differential_snapshot(
    target_interface: IfId,
    target_mac: MacAddress,
    peer_mac: MacAddress,
) -> ForwardingSnapshot<'static> {
    let routes = Box::leak(Box::new([Route::new(
        DESTINATION_PREFIX,
        24,
        target_interface,
        None,
    )
    .expect("live route")]));
    let interfaces = Box::leak(Box::new([Interface {
        id: target_interface,
        mac: target_mac,
        mtu: Ipv4Mtu::ETHERNET,
    }]));
    let neighbors = Box::leak(Box::new([Neighbor {
        interface: target_interface,
        target: DESTINATION_IP,
        mac: peer_mac,
    }]));
    ForwardingSnapshot::new(routes, interfaces, neighbors, &[]).expect("live snapshot")
}

fn wire_safe_case(
    seed: u64,
    iteration: u64,
    structured: bool,
    target_interface: IfId,
    target_mac: MacAddress,
    peer_mac: MacAddress,
) -> DifferentialCase {
    let mut case = generate_case(seed, iteration, structured);
    const BOUNDARIES: [usize; 8] = [60, 64, 1_499, 1_500, 1_514, 61, 1_501, 1_513];
    let length = if iteration < BOUNDARIES.len() as u64 {
        BOUNDARIES[iteration as usize]
    } else {
        60 + (((seed ^ iteration.wrapping_mul(0x9e37_79b9_7f4a_7c15)) as usize) % 1_455)
    };
    let schedule = (iteration as usize) % BOUNDARIES.len();
    case.frame.resize(length, 0xa5);
    case.frame[0..6].copy_from_slice(&target_mac.0);
    case.frame[6..12].copy_from_slice(&peer_mac.0);
    case.ingress = target_interface.0;
    // Keep the native lane within the checked ring profiles while ensuring
    // the default five cases include a single packet, budget truncation,
    // multiple packets, and a real bounded TX rejection path.
    case.packet_count = match schedule {
        0 => 1,
        1 => 2,
        2 => 3,
        3 => 4,
        4 => 2,
        5 => 4,
        6 => 3,
        _ => 1,
    };
    case.rx_budget = match schedule {
        0 => 1,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 2,
        6 => 4,
        _ => 1,
    };
    case.tx_capacity = match schedule % 3 {
        0 => 2,
        1 => 4,
        _ => 2,
    };
    if matches!(schedule, 0 | 2 | 3 | 6) {
        make_valid_forward_frame(&mut case.frame, target_mac, peer_mac);
    }
    case
}

fn make_valid_forward_frame(frame: &mut [u8], target_mac: MacAddress, peer_mac: MacAddress) {
    assert!(frame.len() >= 60);
    frame[0..6].copy_from_slice(&target_mac.0);
    frame[6..12].copy_from_slice(&peer_mac.0);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = 0;
    frame[16..18].copy_from_slice(&20_u16.to_be_bytes());
    frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[24..26].fill(0);
    frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
    frame[30..34].copy_from_slice(&DESTINATION_IP.octets());
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
}

fn run_sim_case(
    case: &DifferentialCase,
    snapshot: &ForwardingSnapshot<'_>,
) -> NormalizedObservation {
    let ingress = IfId(case.ingress);
    let mut io = SimIo::new();
    io.set_received_accept_budget(case.tx_capacity);
    for _ in 0..case.packet_count {
        io.inject(ingress, case.frame.clone());
    }
    let active_disposition = io.current_io_disposition();
    let mut trace = VecTrace::default();
    let batch = io
        .receive(case.rx_budget)
        .expect("SimIo receive is infallible");
    let report = forward_batch(batch, snapshot, &mut trace);
    let disposition = io.current_io_disposition();
    let observation = observation_from_trace(
        report,
        trace.events(),
        active_disposition,
        disposition,
        ErrorCategory::None,
    );
    assert!(observation.batch_invariants);
    assert!(observation.completion_invariants);

    while let Some(frame) = io.pop_tx() {
        assert_eq!(frame.origin, FrameOrigin::Received { ingress });
        assert_eq!(frame.ingress, ingress);
    }
    while let Some(capture) = io.pop_recycled_capture() {
        assert_eq!(capture.frame.ingress, ingress);
        assert_ne!(capture.frame.cause, RecycleCause::LeaseAbandoned);
    }
    if io.pending_rx() != 0 {
        io.retire_pending_rx().expect("unoffered RX is retired");
    }
    assert_eq!(io.pending_rx(), 0);
    assert_eq!(io.pending_tx(), 0);
    assert_eq!(io.pending_recycled(), 0);
    observation
}

fn interface_index(name: &str) -> u32 {
    let name = CString::new(name.as_bytes())
        .unwrap_or_else(|_| panic!("interface name {name:?} contains an embedded NUL"));
    // SAFETY: `name` is a live NUL-terminated interface name.
    let index = unsafe { if_nametoindex(name.as_ptr()) };
    assert_ne!(
        index,
        0,
        "cannot resolve interface: {}",
        io::Error::last_os_error()
    );
    index
}

fn interface_mac(name: &str) -> MacAddress {
    let path = format!("/sys/class/net/{name}/address");
    let value =
        fs::read_to_string(&path).unwrap_or_else(|error| panic!("cannot read {path:?}: {error}"));
    let octets = value
        .trim()
        .split(':')
        .map(|part| {
            u8::from_str_radix(part, 16)
                .unwrap_or_else(|error| panic!("invalid MAC {value:?}: {error}"))
        })
        .collect::<Vec<_>>();
    let octets: [u8; 6] = octets
        .try_into()
        .unwrap_or_else(|_| panic!("interface {name:?} has a non-Ethernet MAC {value:?}"));
    MacAddress(octets)
}

fn system_page_size() -> usize {
    // SAFETY: `sysconf` has no pointer arguments.
    let page_size = unsafe { sysconf(SC_PAGESIZE) };
    usize::try_from(page_size)
        .unwrap_or_else(|_| panic!("sysconf(_SC_PAGESIZE) returned {page_size}"))
}

fn sockaddr(if_index: u32, protocol: u16, destination: &[u8]) -> SockaddrLl {
    assert!(destination.len() <= 6);
    let mut address = [0_u8; 8];
    address[..destination.len()].copy_from_slice(destination);
    SockaddrLl {
        sll_family: AF_PACKET as u16,
        sll_protocol: protocol,
        sll_ifindex: i32::try_from(if_index).expect("Linux ifindex fits sockaddr_ll"),
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: u8::try_from(destination.len()).expect("Ethernet address length fits"),
        sll_addr: address,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        output.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    output
}

extern "C" {
    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    fn bind(fd: c_int, address: *const c_void, length: u32) -> c_int;
    fn sendto(
        fd: c_int,
        buffer: *const c_void,
        length: usize,
        flags: c_int,
        address: *const c_void,
        address_length: u32,
    ) -> isize;
    fn close(fd: c_int) -> c_int;
    fn if_nametoindex(name: *const c_char) -> u32;
    fn sysconf(name: c_int) -> isize;
}
