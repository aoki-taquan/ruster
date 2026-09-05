#![cfg(target_os = "linux")]

use ruster_config::{parse, validate, ValidatedConfig, ValidationLimits};
use ruster_control::{plan_full_service_v1, FullServicePlanInputs};
use ruster_core::{
    bind_publication_backend, DropReason, FirewallHashKey, GeneratedArpTrace, GeneratedIcmpv4Trace,
    GeneratedIcmpv4TraceSink, GeneratedTraceSink, Icmpv4TimestampClock, IfId, MonotonicMillis,
    Nat44TcpHashKey, Nat44UdpDisposition, Nat44UdpHashKey, ResolutionFailureTrace,
    ResolutionFailureTraceSink, ResolutionTimerTrace, ResolutionTimerTraceSink, TraceEvent,
    TraceSink,
};
use ruster_integration::{activate_initial, FullServiceRuntimeStorage};
use ruster_io_afpacket::{
    AfPacketIo, AfPacketPlatform, PlatformError, PortConfig, RingGeometry,
    ValidatedConfig as AfPacketValidatedConfig,
};
use ruster_runtime::{
    run_tick, PhaseReport, PublicationOutcome, RxPhaseReport, TickPhaseTrace, TickPhaseTraceSink,
    TickReport,
};
use std::{
    env::VarError,
    ffi::{c_char, c_int, c_void, CString},
    io,
    mem::size_of,
    num::NonZeroU64,
    os::fd::RawFd,
    thread,
    time::{Duration, Instant},
};

const AF_PACKET: c_int = 17;
const SOCK_RAW: c_int = 3;
const SOCK_CLOEXEC: c_int = 0x8_0000;
const SOL_PACKET: c_int = 263;
const PACKET_IGNORE_OUTGOING: c_int = 23;
const ETH_P_ALL: u16 = 0x0003;
const ETH_P_IPV4: u16 = 0x0800;
const MSG_DONTWAIT: c_int = 0x40;
const POLLIN: i16 = 0x0001;
const POLLERR: i16 = 0x0008;
const POLLHUP: i16 = 0x0010;
const POLLNVAL: i16 = 0x0020;
const PACKET_OUTGOING: u8 = 4;
const EAGAIN: i32 = 11;
const EINTR: i32 = 4;
const EPERM: i32 = 1;
const EACCES: i32 = 13;
const SC_PAGESIZE: c_int = 30;

const ROUTER_A: IfId = IfId(1);
const ROUTER_B: IfId = IfId(2);
const ROUTER_A_IP: [u8; 4] = [10, 0, 1, 1];
const ROUTER_B_IP: [u8; 4] = [10, 0, 2, 1];
const PEER_A_IP: [u8; 4] = [10, 0, 1, 2];
const PEER_B_IP: [u8; 4] = [10, 0, 2, 2];
const MARTIAN_IP: [u8; 4] = [127, 0, 0, 1];

const ROUTER_A_MAC: [u8; 6] = [0x02, 0x72, 0x75, 0x72, 0x14, 0x01];
const ROUTER_B_MAC: [u8; 6] = [0x02, 0x72, 0x75, 0x72, 0x14, 0x02];
const PEER_A_MAC: [u8; 6] = [0x02, 0x72, 0x75, 0x72, 0x14, 0x11];
const PEER_B_MAC: [u8; 6] = [0x02, 0x72, 0x75, 0x72, 0x14, 0x12];

const FORWARD_PAYLOAD: &[u8] = b"ruster-r14-forward-payload";
const REVERSE_PAYLOAD: &[u8] = b"ruster-r14-reverse-payload";
const MARTIAN_PAYLOAD: &[u8] = b"ruster-r14-martian-must-drop";
const UNREQUESTED_PAYLOAD: &[u8] = b"ruster-r14-unrequested-must-bypass";
const FORWARD_SOURCE_PORT: u16 = 41_000;
const FORWARD_DESTINATION_PORT: u16 = 42_000;
const REVERSE_SOURCE_PORT: u16 = FORWARD_DESTINATION_PORT;
const REVERSE_DESTINATION_PORT: u16 = FORWARD_SOURCE_PORT;
const UNREQUESTED_SOURCE_PORT: u16 = 42_001;
const UNREQUESTED_DESTINATION_PORT: u16 = 43_000;
const NAT_FIRST_PORT: u16 = 40_000;
const NAT_LAST_PORT: u16 = 40_031;
const RX_BLOCK_RETIRE_TIMEOUT_MS: u32 = 20;
const MAX_FRAME_LEN: usize = 1_514;
const E2E_TIMEOUT: Duration = Duration::from_secs(20);
const MARTIAN_OBSERVATION: Duration = Duration::from_millis(1_000);
const ROUTER_COMPLETION_GRACE: Duration = Duration::from_millis(300);
const PEER_POLL_SLICE: Duration = Duration::from_millis(50);
const REVERSE_RETRY_INTERVAL: Duration = Duration::from_millis(1);
const REVERSE_SEND_WINDOW: Duration = Duration::from_secs(1);

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

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

struct RawPacketSocket {
    fd: RawFd,
}

impl RawPacketSocket {
    fn fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for RawPacketSocket {
    fn drop(&mut self) {
        // SAFETY: this is the sole owner of the descriptor returned by socket.
        unsafe {
            close(self.fd);
        }
    }
}

#[test]
fn netns_route_e2e() {
    if !privileged_e2e_requested() {
        return;
    }

    match std::env::var("RUSTER_E2E_ROLE") {
        Ok(role) if role == "router" => run_router(),
        Ok(role) if role == "peer-a" => run_peer_a(),
        Ok(role) if role == "peer-b" => run_peer_b(),
        Ok(role) => panic!("privileged AF_PACKET route E2E has unknown role {role:?}"),
        Err(VarError::NotPresent) => {
            panic!("privileged AF_PACKET route E2E requires RUSTER_E2E_ROLE")
        }
        Err(VarError::NotUnicode(_)) => {
            panic!("privileged AF_PACKET route E2E role is not valid UTF-8")
        }
    }
}

fn privileged_e2e_requested() -> bool {
    match std::env::var("RUSTER_PRIVILEGED_E2E") {
        Ok(value) if value == "1" => true,
        Ok(value) => {
            println!(
                "netns_route_e2e: skipped: RUSTER_PRIVILEGED_E2E={value:?}; set it to 1 to request the privileged E2E"
            );
            false
        }
        Err(VarError::NotPresent) => {
            println!(
                "netns_route_e2e: skipped: RUSTER_PRIVILEGED_E2E is unset; set it to 1 to request the privileged E2E"
            );
            false
        }
        Err(VarError::NotUnicode(_)) => {
            println!(
                "netns_route_e2e: skipped: RUSTER_PRIVILEGED_E2E is not valid UTF-8; set it to 1 to request the privileged E2E"
            );
            false
        }
    }
}

fn run_router() {
    let interface_a = required_interface("RUSTER_ROUTE_A_IFACE");
    let interface_b = required_interface("RUSTER_ROUTE_B_IFACE");
    let if_index_a = interface_index(&interface_a);
    let if_index_b = interface_index(&interface_b);

    if let Err(error) = AfPacketPlatform::ensure_supported() {
        panic!("privileged AF_PACKET route E2E platform validation failed: {error}");
    }

    let afpacket_config = afpacket_config(if_index_a, if_index_b);
    let candidate = planned_candidate(&interface_a, &interface_b, false, 1);
    let mut successor = Some(planned_candidate(&interface_a, &interface_b, true, 2));
    let mut storage = FullServiceRuntimeStorage::try_for_candidate(&candidate)
        .unwrap_or_else(|error| panic!("route E2E runtime storage allocation failed: {error:?}"));
    let publication = activate_initial(&mut storage, candidate).unwrap_or_else(|failure| {
        panic!("route E2E initial activation failed: {:?}", failure.error())
    });
    let io = AfPacketIo::open(afpacket_config).unwrap_or_else(|error| {
        panic_platform_error("AfPacketIo::open", error);
    });
    let (owner_binding, mut io) = bind_publication_backend(io)
        .unwrap_or_else(|_| panic!("route E2E publication backend binding identity exhausted"));
    let mut publication = publication
        .bind_backend(owner_binding, &mut io)
        .unwrap_or_else(|failure| {
            panic!("route E2E backend binding failed: {:?}", failure.error())
        });

    println!(
        "netns_route_e2e router: running run_tick forwarding engine on {:?} (IfId 1) and {:?} (IfId 2)",
        interface_a, interface_b
    );

    let deadline = Instant::now() + E2E_TIMEOUT;
    let start = Instant::now();
    let mut trace = RouteTrace::default();
    let mut successor_applied = false;
    let mut tick = 0_u64;
    while Instant::now() < deadline && (!trace.complete() || !successor_applied) {
        let now = MonotonicMillis(
            u64::try_from(start.elapsed().as_millis()).expect("test elapsed time fits u64"),
        );
        // The successor reverses the NAT realm and therefore flushes the
        // initial mapping.  Keep it behind the complete wire-level flow,
        // including the peer-a martian probe and the separate unrequested
        // external-to-internal probe.
        let applying_successor = trace.complete() && !successor_applied;
        let candidate = if applying_successor {
            successor.take()
        } else {
            None
        };
        tick = tick.saturating_add(1);
        let report = run_tick(
            &mut publication,
            candidate,
            &mut io,
            now,
            Icmpv4TimestampClock(u32::try_from(now.0 % 86_400_000).unwrap_or(0)),
            &mut trace,
        );
        trace.dump_tick_diagnostics(tick, now, &report);
        if applying_successor {
            match report.publication {
                PublicationOutcome::Applied(apply) => {
                    assert_eq!(
                        apply.previous_generation(),
                        NonZeroU64::new(1).expect("nonzero initial generation")
                    );
                    assert_eq!(
                        apply.generation(),
                        NonZeroU64::new(2).expect("nonzero successor generation")
                    );
                    successor_applied = true;
                    println!(
                        "netns_route_e2e router: applied fresh reverse NAT generation through run_tick"
                    );
                }
                PublicationOutcome::Deferred { candidate, .. } => {
                    successor = Some(candidate);
                }
                PublicationOutcome::Rejected { rejection, .. } => {
                    let (_candidate, error) = rejection.into_parts();
                    panic!("route E2E reverse successor was rejected: {error:?}");
                }
                PublicationOutcome::BackendMismatch { candidate } => {
                    panic!(
                        "route E2E reverse successor backend mismatch; candidate returned={}",
                        candidate.is_some()
                    );
                }
                PublicationOutcome::Unchanged => {
                    panic!("route E2E reverse successor was unexpectedly unchanged");
                }
            }
        }
        match report.rx {
            RxPhaseReport::Completed(batch) => {
                assert!(
                    batch.invariants_hold(),
                    "route E2E RX batch accounting invariants failed: {batch:?}"
                );
            }
            RxPhaseReport::AccountingInvariantViolation(batch) => {
                panic!("route E2E RX accounting violation: {batch:?}");
            }
            RxPhaseReport::ReceiveFailed(error) => {
                panic!("route E2E RX receive failed: {error:?}");
            }
            RxPhaseReport::Skipped(reason) => {
                panic!("route E2E RX phase unexpectedly skipped: {reason:?}");
            }
        }
        thread::sleep(Duration::from_millis(1));
    }

    assert!(
        trace.complete(),
        "route E2E timed out: routed_a_to_b={}, routed_b_to_a={}, nat_outbound_public_port={:?}, nat_outbound_trace_mismatch={}, nat_inbound_translated={}, nat_inbound_trace_mismatch={}, martian_drop={}, unrequested_bypass_drop={}, drop_counts={{martian={}, bypass={}, unsupported_ethertype={}, other={}}}",
        trace.routed_a_to_b,
        trace.routed_b_to_a,
        trace.nat_outbound_public_port,
        trace.nat_outbound_trace_mismatch,
        trace.nat_inbound_translated,
        trace.nat_inbound_trace_mismatch,
        trace.martian_drop,
        trace.unrequested_bypass_drop,
        trace.martian_drop_count,
        trace.unrequested_bypass_drop_count,
        trace.unsupported_ethertype_drop_count,
        trace.other_drop_count
    );
    assert!(
        successor_applied,
        "route E2E did not apply the fresh reverse-direction successor"
    );
    println!(
        "netns_route_e2e router: observed NAT outbound/inbound wire flow, martian drop, unrequested external-to-internal bypass, and applied reverse NAT generation"
    );
    thread::sleep(ROUTER_COMPLETION_GRACE);
}

fn run_peer_a() {
    let interface = required_interface("RUSTER_ROUTE_A_IFACE");
    let sender = open_raw_socket(&interface, false).unwrap_or_else(|error| {
        panic_raw_socket_error("peer-a sender socket setup", error);
    });
    let observer = open_raw_socket(&interface, true).unwrap_or_else(|error| {
        panic_raw_socket_error("peer-a observer socket setup", error);
    });
    let destination = packet_address(interface_index(&interface), Some(&ROUTER_A_MAC));
    let forward = udp_frame(
        PEER_A_MAC,
        ROUTER_A_MAC,
        PEER_A_IP,
        PEER_B_IP,
        FORWARD_SOURCE_PORT,
        FORWARD_DESTINATION_PORT,
        FORWARD_PAYLOAD,
    );
    let deadline = Instant::now() + E2E_TIMEOUT;
    let mut receive_buffer = [0_u8; 2_048];
    let mut reverse_received = false;

    println!("netns_route_e2e peer-a: sending A->B UDP datagram");
    while Instant::now() < deadline && !reverse_received {
        match send_frame(sender.fd(), &destination, &forward) {
            Ok(()) => {}
            Err(error) if is_would_block(&error) || is_interrupted(&error) => {}
            Err(error) => panic!("privileged AF_PACKET route E2E peer-a send failed: {error}"),
        }

        let wait_deadline = (Instant::now() + PEER_POLL_SLICE).min(deadline);
        if !poll_readable(observer.fd(), wait_deadline).unwrap_or_else(|error| {
            panic!("privileged AF_PACKET route E2E peer-a poll failed: {error}")
        }) {
            continue;
        }
        while let Some((length, packet_type)) = receive_frame(observer.fd(), &mut receive_buffer)
            .unwrap_or_else(|error| {
                panic!("privileged AF_PACKET route E2E peer-a receive failed: {error}")
            })
        {
            if packet_type != PACKET_OUTGOING && is_reverse_frame(&receive_buffer[..length]) {
                reverse_received = true;
                break;
            }
            if !poll_readable(observer.fd(), Instant::now()).unwrap_or_else(|error| {
                panic!("privileged AF_PACKET route E2E peer-a poll failed: {error}")
            }) {
                break;
            }
        }
    }

    assert!(
        reverse_received,
        "timed out waiting for B->A forwarded UDP datagram on {interface:?}"
    );

    let martian = udp_frame(
        PEER_A_MAC,
        ROUTER_A_MAC,
        MARTIAN_IP,
        PEER_B_IP,
        FORWARD_SOURCE_PORT + 1,
        FORWARD_DESTINATION_PORT,
        MARTIAN_PAYLOAD,
    );
    send_until(
        sender.fd(),
        &destination,
        &martian,
        Instant::now() + PEER_POLL_SLICE,
        "peer-a martian send",
    );
    println!(
        "netns_route_e2e peer-a: inbound translated payload/TTL/MAC checks passed; sent Ipv4SourceLoopback martian probe"
    );
    thread::sleep(MARTIAN_OBSERVATION);
}

fn run_peer_b() {
    let interface = required_interface("RUSTER_ROUTE_B_IFACE");
    let sender = open_raw_socket(&interface, false).unwrap_or_else(|error| {
        panic_raw_socket_error("peer-b sender socket setup", error);
    });
    let observer = open_raw_socket(&interface, true).unwrap_or_else(|error| {
        panic_raw_socket_error("peer-b observer socket setup", error);
    });
    let destination = packet_address(interface_index(&interface), Some(&ROUTER_B_MAC));
    let deadline = Instant::now() + E2E_TIMEOUT;
    let mut receive_buffer = [0_u8; 2_048];
    let mut forward_received = false;
    let mut public_endpoint = None;

    println!("netns_route_e2e peer-b: waiting for A->B forwarded UDP datagram");
    while Instant::now() < deadline && !forward_received {
        let wait_deadline = (Instant::now() + PEER_POLL_SLICE).min(deadline);
        if !poll_readable(observer.fd(), wait_deadline).unwrap_or_else(|error| {
            panic!("privileged AF_PACKET route E2E peer-b poll failed: {error}")
        }) {
            continue;
        }
        while let Some((length, packet_type)) = receive_frame(observer.fd(), &mut receive_buffer)
            .unwrap_or_else(|error| {
                panic!("privileged AF_PACKET route E2E peer-b receive failed: {error}")
            })
        {
            if packet_type != PACKET_OUTGOING {
                if let Some(endpoint) = inspect_forward_frame(&receive_buffer[..length]) {
                    public_endpoint = Some(endpoint);
                    forward_received = true;
                    break;
                }
            }
            if !poll_readable(observer.fd(), Instant::now()).unwrap_or_else(|error| {
                panic!("privileged AF_PACKET route E2E peer-b poll failed: {error}")
            }) {
                break;
            }
        }
    }

    assert!(
        forward_received,
        "timed out waiting for A->B forwarded UDP datagram"
    );
    let (public_address, public_port) =
        public_endpoint.expect("forwarded frame must provide a NAT public endpoint");
    let reverse = udp_frame(
        PEER_B_MAC,
        ROUTER_B_MAC,
        PEER_B_IP,
        public_address,
        REVERSE_SOURCE_PORT,
        public_port,
        REVERSE_PAYLOAD,
    );
    let reverse_deadline = (Instant::now() + REVERSE_SEND_WINDOW).min(deadline);
    send_repeatedly_until(
        sender.fd(),
        &destination,
        &reverse,
        reverse_deadline,
        "peer-b normal NAT return send",
    );
    let unrequested = udp_frame(
        PEER_B_MAC,
        ROUTER_B_MAC,
        PEER_B_IP,
        PEER_A_IP,
        UNREQUESTED_SOURCE_PORT,
        UNREQUESTED_DESTINATION_PORT,
        UNREQUESTED_PAYLOAD,
    );
    send_until(
        sender.fd(),
        &destination,
        &unrequested,
        (Instant::now() + PEER_POLL_SLICE).min(deadline),
        "peer-b unrequested external-to-internal probe",
    );
    println!(
        "netns_route_e2e peer-b: forwarded payload/TTL/MAC checks passed; reused wire public endpoint {public_address:?}:{public_port} for normal NAT return and sent a separate unrequested bypass probe"
    );

    observe_no_martian(observer.fd(), Instant::now() + MARTIAN_OBSERVATION);
    println!("netns_route_e2e peer-b: martian probe was not forwarded");
}

#[derive(Default)]
struct RouteTrace {
    routed_a_to_b: bool,
    routed_b_to_a: bool,
    nat_outbound_public_port: Option<u16>,
    nat_outbound_trace_mismatch: bool,
    nat_inbound_translated: bool,
    nat_inbound_trace_mismatch: bool,
    martian_drop: bool,
    unrequested_bypass_drop: bool,
    martian_drop_count: usize,
    unrequested_bypass_drop_count: usize,
    unsupported_ethertype_drop_count: usize,
    other_drop_count: usize,
    diagnostic_samples: usize,
    events: Vec<RouteTraceEvent>,
}

enum RouteTraceEvent {
    TickPhase(TickPhaseTrace),
    Forwarding(TraceEvent),
    ResolutionTimer(ResolutionTimerTrace),
    ResolutionFailure(ResolutionFailureTrace),
    GeneratedArp(GeneratedArpTrace),
    GeneratedIcmpv4(GeneratedIcmpv4Trace),
}

impl RouteTrace {
    fn complete(&self) -> bool {
        self.routed_a_to_b
            && self.routed_b_to_a
            && self.nat_outbound_public_port.is_some()
            && !self.nat_outbound_trace_mismatch
            && self.nat_inbound_translated
            && !self.nat_inbound_trace_mismatch
            && self.martian_drop
            && self.unrequested_bypass_drop
    }

    fn dump_tick_diagnostics<C, P, Q, R, G, A>(
        &mut self,
        tick: u64,
        now: MonotonicMillis,
        report: &TickReport<C, P, Q, R, G, A>,
    ) where
        P: std::fmt::Debug,
        Q: std::fmt::Debug,
        R: std::fmt::Debug,
        G: std::fmt::Debug,
        A: std::fmt::Debug,
    {
        let rx_failed = matches!(
            &report.rx,
            RxPhaseReport::AccountingInvariantViolation(_)
                | RxPhaseReport::ReceiveFailed(_)
                | RxPhaseReport::Skipped(_)
        );
        let phase_failed = matches!(
            &report.resolution_timers,
            PhaseReport::Skipped(_) | PhaseReport::Failed(_)
        ) || matches!(
            &report.failure_dispatch,
            PhaseReport::Skipped(_) | PhaseReport::Failed(_)
        );
        let has_phase_skip = self.events.iter().any(|event| {
            matches!(
                event,
                RouteTraceEvent::TickPhase(TickPhaseTrace::PhaseSkipped { .. })
            )
        });
        let has_forwarding_trace = self.events.iter().any(|event| {
            !matches!(
                event,
                RouteTraceEvent::TickPhase(_)
                    | RouteTraceEvent::Forwarding(TraceEvent::BatchCompleted {
                        tx_accepted: 0,
                        tx_rejected: 0,
                    })
            )
        });
        let publication_has_activity =
            !matches!(&report.publication, PublicationOutcome::Unchanged);
        let detailed = rx_failed
            || phase_failed
            || publication_has_activity
            || has_phase_skip
            || (!report.active && self.diagnostic_samples == 0)
            || (has_forwarding_trace && self.diagnostic_samples < 3);
        if !detailed {
            self.events.clear();
            return;
        }

        if has_forwarding_trace {
            self.diagnostic_samples = self.diagnostic_samples.saturating_add(1);
        }

        eprintln!(
            "route E2E diagnostic tick={tick} now_ms={}: TickReport={report:?}",
            now.0
        );
        eprintln!("  publication: {:?}", report.publication);
        eprintln!("  active: {}", report.active);
        eprintln!("  RX PhaseReport: {:?}", report.rx);
        match &report.rx {
            RxPhaseReport::Completed(batch)
            | RxPhaseReport::AccountingInvariantViolation(batch) => {
                let completion = &batch.completion;
                let (forwarded, traced_dropped) = self.forwarding_counts();
                let drop_reasons = self.forwarding_drop_reasons();
                eprintln!("  RX BatchReport: {batch:?}");
                eprintln!(
                    "  forwarding: routed/forwarded={forwarded}, BatchReport.dropped={}, TraceEvent::Dropped={traced_dropped}, drop_reasons={drop_reasons:?}, consumed={}, tx_requested={}",
                    batch.dropped, batch.consumed, batch.tx_requested
                );
                eprintln!(
                    "  RX TX: requested={}, accepted={}, rejected={}, recycled={}, backend_error={:?}",
                    completion.tx_requested,
                    completion.tx_accepted,
                    completion.tx_rejected,
                    completion.recycled,
                    completion.error
                );
                dump_kick_observation("RX TX", completion.error.as_ref());
            }
            RxPhaseReport::Skipped(reason) => {
                eprintln!("  RX skipped: reason={reason:?}");
            }
            RxPhaseReport::ReceiveFailed(error) => {
                eprintln!("  RX receive failed: error={error:?}");
            }
        }
        eprintln!(
            "  resolution_timers PhaseReport: {:?}",
            report.resolution_timers
        );
        eprintln!(
            "  failure_dispatch PhaseReport: {:?}",
            report.failure_dispatch
        );
        eprintln!("  generated_arp PhaseReport: {:?}", report.generated_arp);
        if let PhaseReport::Completed(generated) = &report.generated_arp {
            eprintln!(
                "  generated ARP TX: requested={}, accepted={}, rejected={}, accounting={:?}, stop={:?}",
                generated.accounting.tx_requested,
                generated.accounting.tx_accepted,
                generated.accounting.tx_rejected,
                generated.accounting,
                generated.stop
            );
        }
        eprintln!(
            "  generated_icmpv4 PhaseReport: {:?}",
            report.generated_icmpv4
        );
        if let PhaseReport::Completed(generated) = &report.generated_icmpv4 {
            eprintln!(
                "  generated ICMPv4 TX: requested={}, accepted={}, rejected={}, accounting={:?}, stop={:?}",
                generated.accounting.tx_requested,
                generated.accounting.tx_accepted,
                generated.accounting.tx_rejected,
                generated.accounting,
                generated.stop
            );
        }

        for event in self.events.drain(..) {
            match event {
                RouteTraceEvent::TickPhase(event) => {
                    eprintln!("  TickPhaseTraceSink: {event:?}");
                }
                RouteTraceEvent::Forwarding(event) => {
                    eprintln!("  TraceSink: {event:?}");
                }
                RouteTraceEvent::ResolutionTimer(event) => {
                    eprintln!("  ResolutionTimerTraceSink: {event:?}");
                }
                RouteTraceEvent::ResolutionFailure(event) => {
                    eprintln!("  ResolutionFailureTraceSink: {event:?}");
                }
                RouteTraceEvent::GeneratedArp(event) => {
                    eprintln!("  GeneratedTraceSink: {event:?}");
                }
                RouteTraceEvent::GeneratedIcmpv4(event) => {
                    eprintln!("  GeneratedIcmpv4TraceSink: {event:?}");
                }
            }
        }
    }

    fn forwarding_counts(&self) -> (usize, usize) {
        self.events
            .iter()
            .fold((0, 0), |(forwarded, dropped), event| match event {
                RouteTraceEvent::Forwarding(TraceEvent::Routed { .. }) => (forwarded + 1, dropped),
                RouteTraceEvent::Forwarding(TraceEvent::Dropped { .. }) => (forwarded, dropped + 1),
                _ => (forwarded, dropped),
            })
    }

    fn forwarding_drop_reasons(&self) -> Vec<DropReason> {
        self.events
            .iter()
            .filter_map(|event| match event {
                RouteTraceEvent::Forwarding(TraceEvent::Dropped { reason, .. }) => Some(*reason),
                _ => None,
            })
            .collect()
    }
}

impl TickPhaseTraceSink for RouteTrace {
    fn record_tick_phase(&mut self, event: TickPhaseTrace) {
        self.events.push(RouteTraceEvent::TickPhase(event));
    }
}

impl TraceSink for RouteTrace {
    fn record(&mut self, event: TraceEvent) {
        match event {
            TraceEvent::Routed { egress, .. } if egress == ROUTER_A => {
                self.routed_b_to_a = true;
            }
            TraceEvent::Routed { egress, .. } if egress == ROUTER_B => {
                self.routed_a_to_b = true;
            }
            TraceEvent::Nat44Udp {
                ingress: ROUTER_A,
                disposition:
                    Nat44UdpDisposition::OutboundTranslated {
                        public_port,
                        mapping_created,
                        peer_created,
                    },
            } => {
                if let Some(previous_port) = self.nat_outbound_public_port {
                    if previous_port != public_port {
                        self.nat_outbound_trace_mismatch = true;
                    }
                } else {
                    self.nat_outbound_public_port = Some(public_port);
                    if !(NAT_FIRST_PORT..=NAT_LAST_PORT).contains(&public_port)
                        || !mapping_created
                        || !peer_created
                    {
                        self.nat_outbound_trace_mismatch = true;
                    }
                }
            }
            TraceEvent::Nat44Udp {
                ingress: ROUTER_B,
                disposition:
                    Nat44UdpDisposition::InboundTranslated {
                        internal_address,
                        internal_port,
                    },
            } => {
                if internal_address.octets() == PEER_A_IP && internal_port == FORWARD_SOURCE_PORT {
                    self.nat_inbound_translated = true;
                } else {
                    self.nat_inbound_trace_mismatch = true;
                }
            }
            TraceEvent::Dropped {
                ingress: ROUTER_A,
                reason: DropReason::Ipv4SourceLoopback,
            } => {
                self.martian_drop = true;
                self.martian_drop_count = self.martian_drop_count.saturating_add(1);
            }
            TraceEvent::Dropped {
                ingress: ROUTER_B,
                reason: DropReason::Nat44ExternalToInternalBypass,
            } => {
                self.unrequested_bypass_drop = true;
                self.unrequested_bypass_drop_count =
                    self.unrequested_bypass_drop_count.saturating_add(1);
            }
            TraceEvent::Dropped {
                reason: DropReason::UnsupportedEtherType,
                ..
            } => {
                self.unsupported_ethertype_drop_count =
                    self.unsupported_ethertype_drop_count.saturating_add(1);
            }
            TraceEvent::Dropped { .. } => {
                self.other_drop_count = self.other_drop_count.saturating_add(1);
            }
            _ => {}
        }
        self.events.push(RouteTraceEvent::Forwarding(event));
    }
}

impl ResolutionTimerTraceSink for RouteTrace {
    fn record_resolution_timer(&mut self, event: ResolutionTimerTrace) {
        self.events.push(RouteTraceEvent::ResolutionTimer(event));
    }
}

impl ResolutionFailureTraceSink for RouteTrace {
    fn record_resolution_failure(&mut self, event: ResolutionFailureTrace) {
        self.events.push(RouteTraceEvent::ResolutionFailure(event));
    }
}

impl GeneratedTraceSink for RouteTrace {
    fn record_generated(&mut self, event: GeneratedArpTrace) {
        self.events.push(RouteTraceEvent::GeneratedArp(event));
    }
}

impl GeneratedIcmpv4TraceSink for RouteTrace {
    fn record_generated_icmpv4(&mut self, event: GeneratedIcmpv4Trace) {
        self.events.push(RouteTraceEvent::GeneratedIcmpv4(event));
    }
}

fn dump_kick_observation<E: std::fmt::Debug>(label: &str, error: Option<&E>) {
    match error {
        Some(error) => {
            eprintln!(
                "  {label} backend completion error (AfPacketError::Kick is shown here on kick failure): {error:?}"
            );
        }
        None => {
            eprintln!("  {label} kick/error: no backend error reported");
        }
    }
}

fn planned_candidate(
    interface_a: &str,
    interface_b: &str,
    reverse_nat: bool,
    generation: u64,
) -> ruster_control::FullServiceCandidateV1 {
    let source = router_config(interface_a, interface_b, reverse_nat);
    let parsed = parse(source.as_bytes())
        .unwrap_or_else(|error| panic!("route E2E config parse failed: {error:?}"));
    let config = match validate(
        parsed,
        ValidationLimits {
            max_slots_per_table: 1_048_576,
            max_runtime_bytes: 1 << 30,
        },
    )
    .unwrap_or_else(|error| panic!("route E2E config validation failed: {error:?}"))
    {
        ValidatedConfig::V1(config) => config,
        _ => unreachable!("route E2E uses schema V1"),
    };
    let nat44 = config
        .nat44()
        .unwrap_or_else(|| panic!("route E2E config check: [nat44.realm] is missing"));
    let udp = nat44
        .udp()
        .unwrap_or_else(|| panic!("route E2E config check: [nat44.udp] is missing"));
    let tcp = nat44
        .tcp()
        .unwrap_or_else(|| panic!("route E2E config check: [nat44.tcp] is missing"));
    let (expected_inside, expected_outside, expected_public_address) = if reverse_nat {
        (ROUTER_B, ROUTER_A, ROUTER_A_IP)
    } else {
        (ROUTER_A, ROUTER_B, ROUTER_B_IP)
    };
    assert_eq!(udp.inside(), expected_inside);
    assert_eq!(udp.outside(), expected_outside);
    assert_eq!(udp.public_address().octets(), expected_public_address);
    assert_eq!(udp.first_port(), NAT_FIRST_PORT);
    assert_eq!(udp.last_port(), NAT_LAST_PORT);
    assert_eq!(tcp.inside(), expected_inside);
    assert_eq!(tcp.outside(), expected_outside);
    assert_eq!(tcp.public_address().octets(), expected_public_address);
    assert_eq!(tcp.first_port(), NAT_FIRST_PORT);
    assert_eq!(tcp.last_port(), NAT_LAST_PORT);
    if generation == 1 {
        println!(
            "netns_route_e2e config check: full-service plan has mandatory Nat44 UDP/TCP; using NAT semantics with public address {expected_public_address:?} and port pool {NAT_FIRST_PORT}..={NAT_LAST_PORT}"
        );
    }
    let inputs = FullServicePlanInputs::new(
        NonZeroU64::new(generation).expect("nonzero route E2E generation"),
        Nat44UdpHashKey::new(
            0x11_u64.saturating_add(generation),
            0x12_u64.saturating_add(generation),
        )
        .expect("nonzero route E2E UDP key"),
        Nat44TcpHashKey::new(
            0x21_u64.saturating_add(generation),
            0x22_u64.saturating_add(generation),
        )
        .expect("nonzero route E2E TCP key"),
        FirewallHashKey::new(
            0x31_u64.saturating_add(generation),
            0x32_u64.saturating_add(generation),
        )
        .expect("nonzero route E2E firewall key"),
    );
    let plan = plan_full_service_v1(config, inputs).unwrap_or_else(|failure| {
        panic!(
            "route E2E full-service planning failed: {:?}",
            failure.error()
        )
    });
    plan.into_candidate()
        .unwrap_or_else(|error| panic!("route E2E candidate minting failed: {error:?}"))
}

fn router_config(interface_a: &str, interface_b: &str, reverse_nat: bool) -> String {
    // Policy A is intentional: config validation permits optional services,
    // but the full-service planner used by this E2E requires both NAT44
    // protocol services.  The validated values are asserted before planning.
    let (inside, outside, public_address) = if reverse_nat {
        ("b", "a", "10.0.1.1")
    } else {
        ("a", "b", "10.0.2.1")
    };
    format!(
        r#"schema-version = 1

[[interfaces]]
id = 1
name = "a"
device = "{interface_a}"
mac = "02:72:75:72:14:01"

[[interfaces]]
id = 2
name = "b"
device = "{interface_b}"
mac = "02:72:75:72:14:02"

[[addresses]]
interface = "a"
ipv4 = "10.0.1.1/24"

[[addresses]]
interface = "b"
ipv4 = "10.0.2.1/24"

[[routes]]
prefix = "10.0.1.2/32"
egress = "a"

[[routes]]
prefix = "10.0.2.2/32"
egress = "b"

[[neighbors]]
interface = "a"
address = "10.0.1.2"
mac = "02:72:75:72:14:11"

[[neighbors]]
interface = "b"
address = "10.0.2.2"
mac = "02:72:75:72:14:12"

[ipv4-origin]
default-ttl = 64

[resolution.policy]
interval-ms = 1000
state-ttl-ms = 3000
dynamic-neighbor-ttl-ms = 60000
max-attempts = 3

[resolution.capacity]
states = 4
actions = 4
dynamic-neighbors = 4
failure-holds = 4

[icmpv4-errors.policy]
interval-ms = 100
state-ttl-ms = 60000

[icmpv4-errors.capacity]
states = 4
actions = 4

[nat44.realm]
inside = "{inside}"
outside = "{outside}"
public-address = "{public_address}"

[nat44.realm.ports]
first = 40000
last = 40031

[nat44.udp]
idle-ttl-ms = 300000
allocator-seed = "101"
icmpv4-errors = "disabled"

[nat44.udp.capacity]
mappings = 4
peers = 4

[nat44.tcp]
idle-ttl-ms = 7440000
allocator-seed = "103"
icmpv4-errors = "disabled"

[nat44.tcp.capacity]
mappings = 4
sessions = 4

[firewall.policy]
udp-idle-ttl-ms = 300000
tcp-opening-idle-ttl-ms = 240000
tcp-active-idle-ttl-ms = 7440000

[firewall.capacity]
states = 4

[[firewall.rules]]
id = 1
source = "0.0.0.0/0"
destination = "0.0.0.0/0"
protocol = "udp"
action = "allow-stateful"

[firewall.rules.source-ports]
first = 1
last = 65535

[firewall.rules.destination-ports]
first = 1
last = 65535

[tick]
rx = 64
resolution-timer-scans = 16
failure-dispatch-scans = 8
generated-arp = 4
generated-icmpv4 = 2
"#,
        interface_a = interface_a,
        interface_b = interface_b,
        inside = inside,
        outside = outside,
        public_address = public_address,
    )
}

fn afpacket_config(if_index_a: u32, if_index_b: u32) -> AfPacketValidatedConfig {
    let page_size = system_page_size();
    let rx = RingGeometry {
        block_size: 4_096,
        block_count: 2,
        frame_size: 2_048,
        frame_count: 4,
        retire_timeout_ms: RX_BLOCK_RETIRE_TIMEOUT_MS,
        private_size: 0,
        feature_flags: 0,
    };
    let tx = RingGeometry {
        retire_timeout_ms: 0,
        private_size: 0,
        feature_flags: 0,
        ..rx
    };
    AfPacketValidatedConfig::new(
        &[
            PortConfig {
                interface: ROUTER_A,
                if_index: if_index_a,
                rx,
                tx,
            },
            PortConfig {
                interface: ROUTER_B,
                if_index: if_index_b,
                rx,
                tx,
            },
        ],
        page_size,
        MAX_FRAME_LEN,
    )
    .unwrap_or_else(|error| panic!("route E2E AF_PACKET configuration failed: {error:?}"))
}

fn required_interface(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => value,
        Ok(_) => panic!("{name} must not be empty for privileged route E2E"),
        Err(VarError::NotPresent) => panic!("{name} is required for privileged route E2E"),
        Err(VarError::NotUnicode(_)) => panic!("{name} is not valid UTF-8"),
    }
}

fn interface_index(interface_name: &str) -> u32 {
    let c_name = CString::new(interface_name)
        .unwrap_or_else(|_| panic!("interface name {interface_name:?} contains an embedded NUL"));
    // SAFETY: c_name is a live, NUL-terminated interface name.
    let if_index = unsafe { if_nametoindex(c_name.as_ptr()) };
    if if_index == 0 {
        let error = io::Error::last_os_error();
        panic!("cannot resolve interface {interface_name:?}: {error}");
    }
    if_index
}

fn system_page_size() -> usize {
    // SAFETY: sysconf has no borrowed pointer arguments.
    let page_size = unsafe { sysconf(SC_PAGESIZE) };
    usize::try_from(page_size)
        .unwrap_or_else(|_| panic!("sysconf(_SC_PAGESIZE) returned invalid value {page_size}"))
}

fn udp_frame(
    source_mac: [u8; 6],
    destination_mac: [u8; 6],
    source_ip: [u8; 4],
    destination_ip: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ipv4_total_length = 20_usize
        .checked_add(8)
        .and_then(|length| length.checked_add(payload.len()))
        .expect("route E2E UDP datagram length fits usize");
    let total_length = 14_usize
        .checked_add(ipv4_total_length)
        .expect("route E2E Ethernet frame length fits usize");
    assert!(
        total_length >= 60,
        "route E2E frame must satisfy Ethernet minimum frame length"
    );
    let mut frame = vec![0_u8; total_length];
    frame[..6].copy_from_slice(&destination_mac);
    frame[6..12].copy_from_slice(&source_mac);
    frame[12..14].copy_from_slice(&ETH_P_IPV4.to_be_bytes());
    frame[14] = 0x45;
    frame[15] = 0;
    frame[16..18].copy_from_slice(
        &u16::try_from(ipv4_total_length)
            .expect("route E2E IPv4 total length fits u16")
            .to_be_bytes(),
    );
    frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[24..26].copy_from_slice(&0_u16.to_be_bytes());
    frame[26..30].copy_from_slice(&source_ip);
    frame[30..34].copy_from_slice(&destination_ip);
    let checksum = ruster_core::ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame[34..36].copy_from_slice(&source_port.to_be_bytes());
    frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
    frame[38..40].copy_from_slice(
        &u16::try_from(8_usize + payload.len())
            .expect("route E2E UDP length fits u16")
            .to_be_bytes(),
    );
    frame[40..42].copy_from_slice(&0_u16.to_be_bytes());
    frame[42..].copy_from_slice(payload);
    frame
}

fn is_reverse_frame(frame: &[u8]) -> bool {
    if !frame_has_udp_payload(frame, REVERSE_PAYLOAD) {
        return false;
    }
    assert_udp_frame(
        frame,
        PEER_A_MAC,
        ROUTER_A_MAC,
        PEER_B_IP,
        PEER_A_IP,
        Some(REVERSE_SOURCE_PORT),
        REVERSE_DESTINATION_PORT,
        REVERSE_PAYLOAD,
    );
    true
}

fn inspect_forward_frame(frame: &[u8]) -> Option<([u8; 4], u16)> {
    if !frame_has_udp_payload(frame, FORWARD_PAYLOAD) {
        return None;
    }
    let (source_port, destination_port) = assert_udp_frame(
        frame,
        PEER_B_MAC,
        ROUTER_B_MAC,
        ROUTER_B_IP,
        PEER_B_IP,
        None,
        FORWARD_DESTINATION_PORT,
        FORWARD_PAYLOAD,
    );
    assert!(
        (NAT_FIRST_PORT..=NAT_LAST_PORT).contains(&source_port),
        "forwarded UDP source port {source_port} was not allocated from the configured NAT pool"
    );
    assert_eq!(destination_port, FORWARD_DESTINATION_PORT);
    Some(([frame[26], frame[27], frame[28], frame[29]], source_port))
}

fn frame_has_udp_payload(frame: &[u8], expected_payload: &[u8]) -> bool {
    frame.len() >= 42 + expected_payload.len()
        && frame[12..14] == ETH_P_IPV4.to_be_bytes()
        && frame[14] == 0x45
        && frame[23] == 17
        && frame[42..42 + expected_payload.len()] == *expected_payload
}

#[allow(
    clippy::too_many_arguments,
    reason = "the E2E assertion keeps every expected wire-level field explicit"
)]
fn assert_udp_frame(
    frame: &[u8],
    expected_destination_mac: [u8; 6],
    expected_source_mac: [u8; 6],
    expected_source_ip: [u8; 4],
    expected_destination_ip: [u8; 4],
    expected_source_port: Option<u16>,
    expected_destination_port: u16,
    expected_payload: &[u8],
) -> (u16, u16) {
    assert!(
        frame.len() >= 42 + expected_payload.len(),
        "forwarded UDP frame is shorter than its expected payload"
    );
    assert_eq!(&frame[..6], expected_destination_mac.as_slice());
    assert_eq!(&frame[6..12], expected_source_mac.as_slice());
    assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETH_P_IPV4);
    assert_eq!(frame[14], 0x45, "IPv4 must have a 20-byte header");
    let ipv4_total_length = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
    assert_eq!(ipv4_total_length, 28 + expected_payload.len());
    assert_eq!(
        frame[22], 63,
        "forwarding must decrement IPv4 TTL from 64 to 63"
    );
    assert_eq!(frame[23], 17, "route E2E packet must remain UDP");
    assert_eq!(&frame[26..30], expected_source_ip.as_slice());
    assert_eq!(&frame[30..34], expected_destination_ip.as_slice());
    let source_port = u16::from_be_bytes([frame[34], frame[35]]);
    let destination_port = u16::from_be_bytes([frame[36], frame[37]]);
    if let Some(expected_source_port) = expected_source_port {
        assert_eq!(source_port, expected_source_port);
    }
    assert_eq!(destination_port, expected_destination_port);
    let udp_length = usize::from(u16::from_be_bytes([frame[38], frame[39]]));
    assert_eq!(udp_length, 8 + expected_payload.len());
    assert_eq!(&frame[42..42 + expected_payload.len()], expected_payload);
    (source_port, destination_port)
}

fn open_raw_socket(
    interface_name: &str,
    ignore_outgoing: bool,
) -> Result<RawPacketSocket, io::Error> {
    let if_index = interface_index(interface_name);
    // SAFETY: socket has no borrowed pointer arguments.
    let fd = unsafe {
        socket(
            AF_PACKET,
            SOCK_RAW | SOCK_CLOEXEC,
            c_int::from(ETH_P_ALL.to_be()),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = RawPacketSocket { fd };

    if ignore_outgoing {
        let value: c_int = 1;
        // SAFETY: value is initialized and remains live for the syscall.
        let result = unsafe {
            setsockopt(
                socket.fd,
                SOL_PACKET,
                PACKET_IGNORE_OUTGOING,
                (&value as *const c_int).cast::<c_void>(),
                u32::try_from(size_of::<c_int>()).expect("c_int size fits socklen_t"),
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let address = packet_address(if_index, None);
    // SAFETY: address is a fully initialized sockaddr_ll and remains live for
    // the syscall.
    let result = unsafe {
        bind(
            socket.fd,
            (&address as *const SockaddrLl).cast::<c_void>(),
            u32::try_from(size_of::<SockaddrLl>()).expect("sockaddr_ll size fits socklen_t"),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn packet_address(if_index: u32, destination: Option<&[u8; 6]>) -> SockaddrLl {
    let mut sll_addr = [0_u8; 8];
    let sll_halen = if let Some(destination) = destination {
        sll_addr[..destination.len()].copy_from_slice(destination);
        6
    } else {
        0
    };
    SockaddrLl {
        sll_family: AF_PACKET as u16,
        sll_protocol: ETH_P_ALL.to_be(),
        sll_ifindex: i32::try_from(if_index).expect("Linux interface index fits sockaddr_ll"),
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen,
        sll_addr,
    }
}

fn send_until(fd: RawFd, address: &SockaddrLl, frame: &[u8], deadline: Instant, operation: &str) {
    loop {
        match send_frame(fd, address, frame) {
            Ok(()) => return,
            Err(error) if is_would_block(&error) || is_interrupted(&error) => {
                if Instant::now() >= deadline {
                    panic!("privileged AF_PACKET route E2E {operation} timed out: {error}");
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("privileged AF_PACKET route E2E {operation} failed: {error}"),
        }
    }
}

fn send_repeatedly_until(
    fd: RawFd,
    address: &SockaddrLl,
    frame: &[u8],
    deadline: Instant,
    operation: &str,
) {
    let mut sent = false;
    while Instant::now() < deadline {
        match send_frame(fd, address, frame) {
            Ok(()) => sent = true,
            Err(error) if is_would_block(&error) || is_interrupted(&error) => {}
            Err(error) => panic!("privileged AF_PACKET route E2E {operation} failed: {error}"),
        }
        if Instant::now() < deadline {
            thread::sleep(REVERSE_RETRY_INTERVAL);
        }
    }
    assert!(
        sent,
        "privileged AF_PACKET route E2E {operation} deadline expired before any frame was sent"
    );
}

fn send_frame(fd: RawFd, address: &SockaddrLl, frame: &[u8]) -> Result<(), io::Error> {
    // SAFETY: frame and address are live for the duration of the syscall.
    let sent = unsafe {
        sendto(
            fd,
            frame.as_ptr().cast::<c_void>(),
            frame.len(),
            MSG_DONTWAIT,
            (address as *const SockaddrLl).cast::<c_void>(),
            u32::try_from(size_of::<SockaddrLl>()).expect("sockaddr_ll size fits socklen_t"),
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let sent = usize::try_from(sent).expect("successful sendto length is nonnegative");
    if sent != frame.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("sendto wrote {sent} bytes instead of {}", frame.len()),
        ));
    }
    Ok(())
}

fn poll_readable(fd: RawFd, deadline: Instant) -> Result<bool, io::Error> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
        let mut poll_fd = PollFd {
            fd,
            events: POLLIN,
            revents: 0,
        };
        // SAFETY: poll_fd is one initialized pollfd and remains live for the
        // duration of the syscall.
        let result = unsafe { poll(&mut poll_fd, 1, timeout) };
        if result > 0 {
            if poll_fd.revents & POLLNVAL != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "poll reported POLLNVAL",
                ));
            }
            return Ok(poll_fd.revents & (POLLIN | POLLERR | POLLHUP) != 0);
        }
        if result == 0 {
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        if is_interrupted(&error) {
            continue;
        }
        return Err(error);
    }
}

fn receive_frame(fd: RawFd, buffer: &mut [u8]) -> Result<Option<(usize, u8)>, io::Error> {
    let mut address = SockaddrLl {
        sll_family: 0,
        sll_protocol: 0,
        sll_ifindex: 0,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    let mut address_length =
        u32::try_from(size_of::<SockaddrLl>()).expect("sockaddr_ll size fits socklen_t");
    // SAFETY: buffer and address are initialized writable storage and remain
    // live for the duration of the syscall.
    let received = unsafe {
        recvfrom(
            fd,
            buffer.as_mut_ptr().cast::<c_void>(),
            buffer.len(),
            MSG_DONTWAIT,
            (&mut address as *mut SockaddrLl).cast::<c_void>(),
            &mut address_length,
        )
    };
    if received < 0 {
        let error = io::Error::last_os_error();
        if is_would_block(&error) {
            return Ok(None);
        }
        return Err(error);
    }
    let length = usize::try_from(received).expect("successful recvfrom length is nonnegative");
    Ok(Some((length, address.sll_pkttype)))
}

fn observe_no_martian(fd: RawFd, deadline: Instant) {
    let mut receive_buffer = [0_u8; 2_048];
    while Instant::now() < deadline {
        if !poll_readable(fd, deadline).unwrap_or_else(|error| {
            panic!("privileged AF_PACKET route E2E peer-b poll failed: {error}")
        }) {
            return;
        }
        while let Some((length, packet_type)) = receive_frame(fd, &mut receive_buffer)
            .unwrap_or_else(|error| {
                panic!("privileged AF_PACKET route E2E peer-b receive failed: {error}")
            })
        {
            if packet_type != PACKET_OUTGOING
                && receive_buffer[..length]
                    .windows(MARTIAN_PAYLOAD.len())
                    .any(|window| window == MARTIAN_PAYLOAD)
            {
                panic!("router forwarded the martian probe to netns B");
            }
            if !poll_readable(fd, Instant::now()).unwrap_or_else(|error| {
                panic!("privileged AF_PACKET route E2E peer-b poll failed: {error}")
            }) {
                break;
            }
        }
    }
}

fn is_would_block(error: &io::Error) -> bool {
    error.raw_os_error() == Some(EAGAIN)
}

fn is_interrupted(error: &io::Error) -> bool {
    error.raw_os_error() == Some(EINTR)
}

fn panic_platform_error(operation: &str, error: PlatformError) -> ! {
    if let PlatformError::Syscall { errno, .. } = error {
        if matches!(errno.get(), EPERM | EACCES) {
            panic!(
                "privileged E2E was requested but CAP_NET_RAW is unavailable ({operation}: {error})"
            );
        }
    }
    panic!("privileged AF_PACKET route E2E {operation} failed: {error}");
}

fn panic_raw_socket_error(operation: &str, error: io::Error) -> ! {
    if matches!(error.raw_os_error(), Some(EPERM | EACCES)) {
        panic!(
            "privileged E2E was requested but CAP_NET_RAW is unavailable ({operation}: {error})"
        );
    }
    panic!("privileged AF_PACKET route E2E {operation} failed: {error}");
}

unsafe extern "C" {
    fn socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int;
    fn setsockopt(
        socket: c_int,
        level: c_int,
        option_name: c_int,
        option_value: *const c_void,
        option_len: u32,
    ) -> c_int;
    fn bind(socket: c_int, address: *const c_void, address_len: u32) -> c_int;
    fn sendto(
        fd: c_int,
        buffer: *const c_void,
        length: usize,
        flags: c_int,
        address: *const c_void,
        address_len: u32,
    ) -> isize;
    fn recvfrom(
        fd: c_int,
        buffer: *mut c_void,
        length: usize,
        flags: c_int,
        address: *mut c_void,
        address_len: *mut u32,
    ) -> isize;
    fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
    fn if_nametoindex(ifname: *const c_char) -> u32;
    fn sysconf(name: c_int) -> isize;
    fn close(fd: c_int) -> c_int;
}
