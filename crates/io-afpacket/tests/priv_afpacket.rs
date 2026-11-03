//! Privileged real-kernel smoke of the live AF_PACKET adapter (AP3).
//!
//! Runs only with `RUSTER_PRIV_AFPACKET=1`, normally through
//! `scripts/priv-afpacket-smoke.sh`, which creates a dedicated network
//! namespace with two veth pairs, runs this prebuilt test inside it, and
//! always deletes the namespace. When the variable is set, every missing
//! precondition fails the test; it never skips. With `RUSTER_REQUIRE_PRIV=1`
//! (the `XDP veth` CI job) an unset `RUSTER_PRIV_AFPACKET` fails too, so a
//! misconfigured run cannot pass vacuously. The test refuses to run in the
//! initial network namespace, so it cannot touch a host interface, and
//! prints a `priv_afpacket_*: ... verified` marker the script requires.

#![cfg(all(target_os = "linux", target_pointer_width = "64"))]

use std::{
    env, fs,
    io::{BufRead, BufReader},
    os::unix::fs::MetadataExt,
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use ruster_core::{
    forward_batch, BackendStats, DropReason, ForwardingSnapshot, GeneratedPacketBatch,
    GeneratedPacketIo, IfId, Interface, Ipv4Address, MacAddress, MonotonicMillis, Neighbor,
    NoTrace, PacketBatch, PacketIo, PublicationQuiescence, PublicationQuiescenceDisposition, Route,
};
use ruster_io_afpacket::{
    AfPacketError, AfPacketIo, AfPacketPlatform, Errno, PlatformError, PortConfig, RingGeometry,
    RxWait, SyscallStage, ValidatedConfig,
};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const TX_FRAMES: u32 = 128;

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("RUSTER_PRIV_AFPACKET=1 requires {name}"))
}

fn netns_inode(path: &str) -> u64 {
    fs::metadata(path)
        .unwrap_or_else(|error| panic!("cannot stat {path}: {error}"))
        .ino()
}

#[derive(Debug, PartialEq, Eq)]
enum Gate {
    Run,
    Skip(&'static str),
}

/// Decides the privileged test from `RUSTER_PRIV_AFPACKET` and
/// `RUSTER_REQUIRE_PRIV`; under the latter every would-be skip is an error.
fn gate(privileged: Option<&str>, require: Option<&str>) -> Result<Gate, &'static str> {
    let required = match require {
        None => false,
        Some("1") => true,
        Some(_) => return Err("RUSTER_REQUIRE_PRIV must be exactly 1 or unset"),
    };
    match privileged {
        None if required => {
            Err("PRIV_REQUIRED: RUSTER_REQUIRE_PRIV=1 but RUSTER_PRIV_AFPACKET is unset")
        }
        None => Ok(Gate::Skip(
            "RUSTER_PRIV_AFPACKET unset; privileged smoke not requested",
        )),
        Some("1") => Ok(Gate::Run),
        Some(_) => Err("RUSTER_PRIV_AFPACKET must be exactly 1"),
    }
}

#[test]
fn priv_afpacket_gate_fails_instead_of_skipping_when_required() {
    assert_eq!(
        gate(None, None),
        Ok(Gate::Skip(
            "RUSTER_PRIV_AFPACKET unset; privileged smoke not requested"
        ))
    );
    assert!(gate(None, Some("1")).is_err());
    assert!(gate(None, Some("0")).is_err());
    assert!(gate(None, Some("")).is_err());
    assert!(gate(Some("yes"), None).is_err());
    assert!(gate(Some("yes"), Some("1")).is_err());
    assert_eq!(gate(Some("1"), None), Ok(Gate::Run));
    assert_eq!(gate(Some("1"), Some("1")), Ok(Gate::Run));
}

/// Whether the privileged test runs, after proving the process is inside
/// the dedicated namespace.
fn requested() -> bool {
    let privileged = env::var("RUSTER_PRIV_AFPACKET").ok();
    let require = env::var("RUSTER_REQUIRE_PRIV").ok();
    match gate(privileged.as_deref(), require.as_deref()) {
        Ok(Gate::Run) => {}
        Ok(Gate::Skip(reason)) => {
            eprintln!("priv_afpacket: {reason}");
            return false;
        }
        Err(reason) => panic!("priv_afpacket: {reason}"),
    }
    let netns = required("RUSTER_PRIV_AFPACKET_NETNS");
    assert!(
        netns.starts_with("ruster-") && !netns.contains('/'),
        "the smoke namespace must be a dedicated ruster-* namespace"
    );
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
    true
}

fn sysfs(device: &str, file: &str) -> String {
    fs::read_to_string(format!("/sys/class/net/{device}/{file}"))
        .unwrap_or_else(|error| panic!("cannot read {file} of {device}: {error}"))
        .trim()
        .to_owned()
}

fn if_index(device: &str) -> u32 {
    sysfs(device, "ifindex").parse().expect("numeric ifindex")
}

fn device_mac(device: &str) -> [u8; 6] {
    let text = sysfs(device, "address");
    let mut mac = [0_u8; 6];
    let mut parts = text.split(':');
    for byte in &mut mac {
        *byte = u8::from_str_radix(parts.next().expect("six octets"), 16).expect("hex octet");
    }
    assert!(parts.next().is_none(), "six octets");
    mac
}

fn open_fds() -> usize {
    fs::read_dir("/proc/self/fd").expect("fd list").count()
}

fn config(ports: &[(IfId, u32)]) -> ValidatedConfig {
    let page = AfPacketPlatform::page_size().expect("page size");
    assert_eq!(page, 4_096, "the smoke geometry assumes 4 KiB pages");
    // Retire timeout 1 ms: an idle router sees a lone frame within 1 ms.
    let rx = RingGeometry {
        block_size: 65_536,
        block_count: 4,
        frame_size: 2_048,
        frame_count: 128,
        retire_timeout_ms: 1,
        private_size: 0,
        feature_flags: 0,
    };
    let tx = RingGeometry {
        block_size: 65_536,
        block_count: 4,
        frame_size: 2_048,
        frame_count: TX_FRAMES,
        retire_timeout_ms: 0,
        private_size: 0,
        feature_flags: 0,
    };
    let ports = ports
        .iter()
        .map(|&(interface, if_index)| PortConfig {
            interface,
            if_index,
            rx,
            tx,
        })
        .collect::<Vec<_>>();
    ValidatedConfig::new(&ports, page, 1_514).expect("smoke geometry")
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

/// Sends one raw Ethernet frame out of `argv[1]` (python, run inside the
/// namespace by the already-privileged test).
const RAW_SEND: &str = r"
import socket, sys
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((sys.argv[1], 0))
s.send(bytes.fromhex(sys.argv[2]))
";

/// Sends one raw frame on `argv[1]` after `argv[3]` seconds.
const DELAYED_RAW_SEND: &str = r"
import socket, sys, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((sys.argv[1], 0))
time.sleep(float(sys.argv[3]))
s.send(bytes.fromhex(sys.argv[2]))
";

/// Prints `ready`, then the hex of the first frame received (not sent) on
/// `argv[1]` that contains the marker `argv[2]`, or fails after `argv[3]`
/// seconds.
const RAW_RECEIVE: &str = r"
import select, socket, sys, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
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

const FORWARD_MARKER: &[u8] = b"ruster-ap3-forward";
const GENERATED_MARKER: [u8; 4] = [192, 0, 2, 77];
const HOST_A_MAC: [u8; 6] = [0x02, 0x52, 0x55, 0x53, 0x54, 0x41];
const HOST_A_IP: [u8; 4] = [192, 0, 2, 2];
const HOST_B_IP: [u8; 4] = [198, 51, 100, 2];

/// An IPv4/UDP frame from host A to host B, addressed to router port A.
fn forward_frame(router_a: [u8; 6]) -> Vec<u8> {
    let payload_len = FORWARD_MARKER.len();
    let total = 20 + 8 + payload_len;
    let mut bytes = vec![0_u8; 14 + total];
    bytes[0..6].copy_from_slice(&router_a);
    bytes[6..12].copy_from_slice(&HOST_A_MAC);
    bytes[12..14].copy_from_slice(&[0x08, 0x00]);
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&u16::try_from(total).expect("short").to_be_bytes());
    bytes[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&HOST_A_IP);
    bytes[30..34].copy_from_slice(&HOST_B_IP);
    let checksum = ruster_core::ipv4_header_checksum(&bytes[14..34]);
    bytes[24..26].copy_from_slice(&checksum.to_be_bytes());
    bytes[34..36].copy_from_slice(&40_000_u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&9_u16.to_be_bytes());
    bytes[38..40].copy_from_slice(&u16::try_from(8 + payload_len).expect("short").to_be_bytes());
    bytes[42..].copy_from_slice(FORWARD_MARKER);
    bytes
}

/// A broadcast ARP request from `source` asking for `GENERATED_MARKER`.
fn build_arp_request(bytes: &mut [u8], source: [u8; 6]) {
    assert_eq!(bytes.len(), 42);
    bytes[..6].fill(0xff);
    bytes[6..12].copy_from_slice(&source);
    bytes[12..14].copy_from_slice(&[0x08, 0x06]);
    bytes[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    bytes[22..28].copy_from_slice(&source);
    bytes[28..32].copy_from_slice(&[198, 51, 100, 1]);
    bytes[32..38].fill(0);
    bytes[38..42].copy_from_slice(&GENERATED_MARKER);
}

/// Receives and recycles every RX frame; whether one contained `marker`.
fn recycle_rx(io: &mut AfPacketIo, marker: &[u8]) -> bool {
    let mut seen = false;
    loop {
        let mut batch = io.receive(64).expect("receive");
        let mut any = false;
        while let Some(mut packet) = batch.next_packet() {
            any = true;
            seen |= packet
                .bytes_mut()
                .windows(marker.len())
                .any(|window| window == marker);
            packet.recycle(DropReason::UnsupportedEtherType);
        }
        assert_eq!(batch.finish().error, None);
        if !any {
            return seen;
        }
    }
}

/// The idle wait blocks in `poll` over both sockets until its timeout, and
/// a frame arriving while it blocks ends it long before the timeout.
fn idle_wait_blocks_and_wakes_on_a_frame(io: &mut AfPacketIo, peer_a: &str, frame: &[u8]) {
    recycle_rx(io, FORWARD_MARKER);
    let mut quiet = None;
    for _ in 0..50 {
        let started = Instant::now();
        match io.wait_rx(30).expect("poll") {
            RxWait::TimedOut => {
                quiet = Some(started.elapsed());
                break;
            }
            RxWait::Ready => {
                recycle_rx(io, FORWARD_MARKER);
            }
            RxWait::Interrupted => {}
        }
    }
    let quiet = quiet.expect("no idle wait timed out in 50 tries");
    assert!(
        quiet >= Duration::from_millis(29) && quiet < Duration::from_secs(1),
        "a 30 ms wait took {quiet:?}"
    );
    let mut sender = Command::new("python3")
        .args(["-I", "-c", DELAYED_RAW_SEND, peer_a, &hex(frame), "0.3"])
        .spawn()
        .expect("spawn the delayed peer A sender");
    let started = Instant::now();
    let woke = loop {
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the frame never ended a wait"
        );
        match io.wait_rx(10_000).expect("poll") {
            RxWait::TimedOut => panic!("a 10 s wait timed out with a frame on the way"),
            RxWait::Ready => {
                let woke = started.elapsed();
                if recycle_rx(io, FORWARD_MARKER) {
                    break woke;
                }
            }
            RxWait::Interrupted => {}
        }
    };
    assert!(sender.wait().expect("sender exit").success());
    assert!(
        woke >= Duration::from_millis(250),
        "woke after {woke:?}, before the frame was sent"
    );
    eprintln!(
        "priv_afpacket_idle_wait: a 30 ms idle poll timed out after {quiet:?}; a frame sent \
         0.3 s into a 10 s poll ended it after {woke:?}"
    );
}

fn now_ms(start: Instant) -> MonotonicMillis {
    MonotonicMillis(u64::try_from(start.elapsed().as_millis()).expect("ms"))
}

fn generate_arp(io: &mut AfPacketIo, egress: IfId, count: usize, source: [u8; 6]) -> usize {
    let mut batch = io.begin_generated(egress);
    for _ in 0..count {
        let mut frame = batch.allocate(42).expect("generated frame");
        assert!(frame.bytes_mut().iter().all(|byte| *byte == 0), "zeroed");
        build_arp_request(frame.bytes_mut(), source);
        frame.commit();
    }
    let completion = batch.finish();
    assert!(completion.invariants_hold(), "{completion:?}");
    assert_eq!(completion.error, None, "{completion:?}");
    completion.accepted
}

#[test]
fn priv_afpacket_forwards_between_two_veth_ports_through_core_and_drains() {
    if !requested() {
        return;
    }
    let port_a = required("RUSTER_PRIV_AFPACKET_FWD_A");
    let peer_a = required("RUSTER_PRIV_AFPACKET_FWD_A_PEER");
    let port_b = required("RUSTER_PRIV_AFPACKET_FWD_B");
    let peer_b = required("RUSTER_PRIV_AFPACKET_FWD_B_PEER");
    let (mac_a, mac_b, mac_peer_b) = (
        device_mac(&port_a),
        device_mac(&port_b),
        device_mac(&peer_b),
    );
    let (index_a, index_b) = (if_index(&port_a), if_index(&port_b));
    let fds_before = open_fds();

    // Failure atomicity: the second port's bind fails (no such device), and
    // the first port's socket and mapping are released again.
    match AfPacketIo::open(config(&[(LAN, index_a), (WAN, 999_999)])) {
        Err(PlatformError::Syscall {
            stage: SyscallStage::Bind,
            errno,
        }) => assert_eq!(errno, Errno::new(19), "ENODEV"),
        other => panic!("open with a missing device: {other:?}"),
    }
    assert_eq!(open_fds(), fds_before, "failed open leaked a descriptor");

    let start = Instant::now();
    let mut io = AfPacketIo::open(config(&[(LAN, index_a), (WAN, index_b)])).expect("open");
    assert_eq!(io.port_count(), 2);
    assert_eq!(open_fds(), fds_before + 2, "one socket per port");
    io.set_clock(now_ms(start));

    let ip = Ipv4Address::from_octets;
    let routes = [
        Route::new(ip([192, 0, 2, 0]), 24, LAN, None).expect("route"),
        Route::new(ip([198, 51, 100, 0]), 24, WAN, None).expect("route"),
    ];
    let interfaces = [
        Interface {
            id: LAN,
            mac: MacAddress(mac_a),
            mtu: 1500,
        },
        Interface {
            id: WAN,
            mac: MacAddress(mac_b),
            mtu: 1500,
        },
    ];
    let neighbors = [Neighbor {
        interface: WAN,
        target: ip(HOST_B_IP),
        mac: MacAddress(mac_peer_b),
    }];
    let snapshot =
        ForwardingSnapshot::new(&routes, &interfaces, &neighbors, &[]).expect("snapshot");

    idle_wait_blocks_and_wakes_on_a_frame(&mut io, &peer_a, &forward_frame(mac_a));

    // Forward A -> B through core.
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
    while io.port_stats(WAN).expect("WAN").counters.tx_copies == 0 {
        if sent < 50 {
            let status = Command::new("python3")
                .args(["-I", "-c", RAW_SEND, &peer_a, &hex(&original)])
                .status()
                .expect("run the peer A sender");
            assert!(status.success(), "raw send from {peer_a} failed");
            sent += 1;
        }
        sleep(Duration::from_millis(20));
        io.set_clock(now_ms(start));
        let report = forward_batch(io.receive(64).expect("receive"), &snapshot, &mut NoTrace);
        assert!(report.invariants_hold(), "{report:?}");
        assert_eq!(report.completion.error, None, "{report:?}");
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
    drop(stdout);
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
    assert_eq!(&bytes[34..], &original[34..], "UDP header and payload");

    // The copied frame completes without further traffic: the next settle
    // (here the quiescence check) reaps it.
    let deadline = Instant::now() + Duration::from_secs(2);
    while let Err(error) = io.try_publication_quiescence().map(|_| ()) {
        assert_eq!(
            AfPacketIo::quiescence_error_disposition(&error),
            PublicationQuiescenceDisposition::ContinueOldIo
        );
        assert!(Instant::now() < deadline, "{error:?}");
        sleep(Duration::from_millis(5));
    }
    let wan = io.port_stats(WAN).expect("WAN");
    assert_eq!(wan.tx_inflight, 0, "{wan:?}");
    assert!(wan.counters.tx_completed >= 1, "{wan:?}");
    assert!(wan.counters.kicks >= 1, "{wan:?}");
    assert_eq!(wan.counters.tx_wrong_format, 0, "{wan:?}");
    let lan = io.port_stats(LAN).expect("LAN");
    assert!(lan.counters.rx_packets >= 1, "{lan:?}");
    assert!(lan.counters.rx_blocks_returned >= 1, "{lan:?}");
    assert_eq!(lan.counters.rx_packet_faults, 0, "{lan:?}");

    // Kernel PACKET_STATISTICS reach the cumulative counters.
    io.refresh_kernel_stats().expect("PACKET_STATISTICS");
    let lan = io.port_stats(LAN).expect("LAN");
    assert!(lan.counters.kernel_packets >= 1, "{lan:?}");
    assert_eq!(lan.counters.kernel_stats_errors, 0);

    // A generated burst of 2x the TX ring completes through settles alone:
    // generated frames are the TX frames themselves (no copy).
    let mut receiver = Command::new("python3")
        .args([
            "-I",
            "-c",
            RAW_RECEIVE,
            &peer_b,
            &hex(&GENERATED_MARKER),
            "8",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn the peer B receiver");
    let mut stdout = BufReader::new(receiver.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("receiver ready line");
    assert_eq!(line.trim(), "ready", "receiver did not start");
    let before = io.port_stats(WAN).expect("WAN").counters;
    let mut accepted = 0;
    let deadline = Instant::now() + Duration::from_secs(5);
    while accepted < 2 * TX_FRAMES as usize {
        io.set_clock(now_ms(start));
        accepted += generate_arp(&mut io, WAN, 32, mac_b);
        assert!(Instant::now() < deadline, "burst stalled at {accepted}");
    }
    let mut generated = String::new();
    stdout.read_line(&mut generated).expect("generated frame");
    assert!(receiver.wait().expect("receiver exit").success());
    drop(stdout);
    let bytes = unhex(generated.trim());
    assert_eq!(bytes.len(), 42);
    assert_eq!(&bytes[6..12], &mac_b);
    while io.try_publication_quiescence().is_err() {
        assert!(Instant::now() < deadline, "burst never completed");
        sleep(Duration::from_millis(5));
    }
    let after = io.port_stats(WAN).expect("WAN").counters;
    assert_eq!(
        after.generated_committed - before.generated_committed,
        accepted as u64
    );
    assert_eq!(after.tx_completed - before.tx_completed, accepted as u64);
    assert_eq!(
        after.tx_copies, before.tx_copies,
        "generated frames copy nothing"
    );

    // Link flap on B (inside the namespace): a kick on the down link is a
    // link state, not an error; the owed retry sends after the link is up.
    let ip_link = |state: &str| {
        let status = Command::new("ip")
            .args(["link", "set", "dev", port_b.as_str(), state])
            .status()
            .expect("run ip link set");
        assert!(status.success(), "ip link set {port_b} {state} failed");
    };
    ip_link("down");
    io.set_clock(now_ms(start));
    assert_eq!(generate_arp(&mut io, WAN, 3, mac_b), 3);
    let down = io.port_stats(WAN).expect("WAN");
    assert!(down.link_down && down.kick_owed, "{down:?}");
    assert_eq!(down.tx_inflight, 3, "{down:?}");
    // OPS-EXIT (AFPKT-017): TX held on the down link does not block a
    // publication; the granted check counts it and the frames stay.
    assert!(io.try_publication_quiescence().is_ok());
    let held = io.port_stats(WAN).expect("WAN");
    assert_eq!(held.counters.quiescence_link_down_tx, 3, "{held:?}");
    assert_eq!(held.tx_inflight, 3, "{held:?}");
    ip_link("up");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        io.set_clock(now_ms(start));
        let ready = io.try_publication_quiescence().is_ok();
        let port = io.port_stats(WAN).expect("WAN");
        if ready && !port.link_down && port.tx_inflight == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "quiescence never became ready after the flap: {:?}",
            io.port_stats(WAN)
        );
        sleep(Duration::from_millis(5));
    }
    let up = io.port_stats(WAN).expect("WAN");
    assert!(
        !up.link_down && !up.kick_owed && up.tx_inflight == 0,
        "{up:?}"
    );
    assert!(up.counters.kicks_link_down >= 1, "{up:?}");
    assert!(up.counters.kick_retries >= 1, "{up:?}");
    assert_eq!(up.counters.kick_errors, 0, "{up:?}");

    let stats = io.backend_stats();
    assert_eq!(stats.ports, 2);
    assert!(!stats.stopped);

    // Ordered shutdown: drain, then refuse I/O, then release on drop.
    let deadline = Instant::now() + Duration::from_secs(2);
    let report = loop {
        let report = io.drain(16);
        if report.is_drained() {
            break report;
        }
        assert!(Instant::now() < deadline, "drain timed out: {report:?}");
        sleep(Duration::from_millis(10));
    };
    assert_eq!(report.kick_owed_ports, 0);
    assert!(matches!(io.receive(1), Err(AfPacketError::Stopped)));
    assert!(io.backend_stats().stopped);
    drop(io);
    assert_eq!(open_fds(), fds_before, "drop closed every socket");
    eprintln!(
        "priv_afpacket_adapter: {sent} raw frames sent; a frame from veth A was forwarded by \
         core, copied once into port B's TX ring, received by B's peer with the rewritten MACs \
         and TTL, a {accepted}-frame generated burst completed through settles, a link flap on \
         B recovered through the owed kick, failed open released port A, and both ports \
         drained and closed verified"
    );
}
