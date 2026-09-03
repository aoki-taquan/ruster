//! Read-only-gated physical-NIC acceptance measurement for the AF_PACKET path.
//!
//! The companion script supplies exactly one interface name.  This harness
//! never creates, deletes, or reconfigures an interface.  When the inspected
//! NIC satisfies the hardware identity and speed gate, it sends a bounded
//! stream of tagged frames through that same interface and measures the
//! receive path.  Linux packet sockets report the locally generated frames to
//! the TPACKET receive ring as `PACKET_OUTGOING`, which keeps this entry point
//! usable without inventing a peer interface.

#![cfg_attr(target_os = "linux", allow(unsafe_code))]

#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../../bench/src/throughput_measurement.rs"]
mod throughput_measurement;

#[cfg(target_os = "linux")]
mod linux {
    use super::throughput_measurement::{
        acceptance_measurement_error_token, acceptance_measurement_skip_reason,
        assert_machine_readable_ascii_token_field, assert_machine_readable_ascii_token_list_field,
        assert_machine_readable_record_line, clear_frame_timestamp, configure_receiver_affinity,
        evaluate_hardware_acceptance, format_cache_miss_rate, format_cycles_per_packet,
        format_latency_value, format_optional_i32, format_optional_usize, inspect_nic,
        read_perf_event_paranoid, read_system_conditions, stamp_frame_with_last,
        HardwareAcceptanceReport, LatencyCollector, LatencySummary, PerfEventSet, PerfReport,
        SystemConditions, LATENCY_CLOCK_DOMAIN, LATENCY_CLOCK_NAME, LATENCY_PERCENTILE_METHOD,
    };
    use ruster_core::{DropReason, PacketBatch, PacketIo};
    use ruster_io_afpacket::{
        AfPacketIo, AfPacketPlatform, PlatformError, PortConfig, RingGeometry, ValidatedConfig,
    };
    use std::{
        env,
        ffi::{c_char, c_int, c_void, CString},
        io,
        mem::size_of,
        os::fd::RawFd,
        sync::{
            atomic::{AtomicI32, AtomicU64, AtomicU8, Ordering},
            Arc,
        },
        thread,
        time::{Duration, Instant},
    };

    const AF_PACKET: c_int = 17;
    const SOCK_RAW: c_int = 3;
    const SOCK_CLOEXEC: c_int = 0x8_0000;
    const ETH_P_ALL: u16 = 0x0003;
    const MSG_DONTWAIT: c_int = 0x40;
    const EAGAIN: i32 = 11;
    const EIO: i32 = 5;
    const EPERM: i32 = 1;
    const EACCES: i32 = 13;
    const SC_PAGESIZE: c_int = 30;

    const PHASE_IDLE: u8 = 0;
    const PHASE_WARMUP: u8 = 1;
    const PHASE_MEASURE: u8 = 2;
    const PHASE_STOP: u8 = 3;
    const PHASE_FAILED: u8 = 4;

    const DEFAULT_FRAME_SIZE: usize = 60;
    const DEFAULT_DURATION_MS: u64 = 3_000;
    const DEFAULT_WARMUP_MS: u64 = 100;
    const MIN_FRAME_SIZE: usize = 60;
    const MAX_FRAME_SIZE: usize = 1_514;
    const RX_BLOCK_SIZE: u32 = 1_048_576;
    const RX_BLOCK_COUNT: u32 = 8;
    const RX_FRAME_SIZE: u32 = 2_048;
    const RX_FRAMES_PER_BLOCK: u32 = RX_BLOCK_SIZE / RX_FRAME_SIZE;
    const RX_FRAME_COUNT: u32 = RX_BLOCK_COUNT * RX_FRAMES_PER_BLOCK;
    const RX_RETIRE_TIMEOUT_MS: u32 = 10;
    const POLL_SLICE: Duration = Duration::from_millis(5);
    const QUIET_DRAIN_TIMEOUT: Duration = Duration::from_millis(50);
    const BROADCAST_MAC: [u8; 6] = [0xff; 6];
    const SOURCE_MAC: [u8; 6] = [0x02, 0x72, 0x75, 0x73, 0x74, 0x4e];

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
            // SAFETY: this owner is the sole owner of the socket descriptor.
            unsafe {
                let _ = close(self.fd);
            }
        }
    }

    struct Settings {
        interface: String,
        frame_size: usize,
        duration: Duration,
        warmup: Duration,
    }

    impl Settings {
        fn from_environment() -> Self {
            let interface = required_interface();
            validate_interface_name(&interface);
            let frame_size = parse_u64(
                "RUSTER_NIC_ACCEPTANCE_FRAME_SIZE",
                DEFAULT_FRAME_SIZE as u64,
            );
            let duration_ms = parse_u64("RUSTER_NIC_ACCEPTANCE_DURATION_MS", DEFAULT_DURATION_MS);
            let warmup_ms = parse_u64("RUSTER_NIC_ACCEPTANCE_WARMUP_MS", DEFAULT_WARMUP_MS);
            let frame_size = usize::try_from(frame_size)
                .unwrap_or_else(|_| panic!("RUSTER_NIC_ACCEPTANCE_FRAME_SIZE does not fit usize"));
            assert!(
                (MIN_FRAME_SIZE..=MAX_FRAME_SIZE).contains(&frame_size),
                "frame size must be between {MIN_FRAME_SIZE} and {MAX_FRAME_SIZE} bytes"
            );
            assert!(
                duration_ms > 0,
                "acceptance measurement duration must be greater than zero"
            );
            assert!(warmup_ms >= 20, "acceptance warmup must be at least 20 ms");
            Self {
                interface,
                frame_size,
                duration: Duration::from_millis(duration_ms),
                warmup: Duration::from_millis(warmup_ms),
            }
        }
    }

    #[derive(Clone, Copy)]
    struct SenderSnapshot {
        attempted: u64,
        sent: u64,
        would_block: u64,
        timestamp_failures: u64,
        timestamp_failure_errno: Option<i32>,
    }

    struct SenderCounters {
        phase: AtomicU8,
        attempted: AtomicU64,
        sent: AtomicU64,
        would_block: AtomicU64,
        fatal_errno: AtomicI32,
        timestamp_failures: AtomicU64,
        timestamp_failure_errno: AtomicI32,
    }

    impl SenderCounters {
        fn new() -> Self {
            Self {
                phase: AtomicU8::new(PHASE_IDLE),
                attempted: AtomicU64::new(0),
                sent: AtomicU64::new(0),
                would_block: AtomicU64::new(0),
                fatal_errno: AtomicI32::new(0),
                timestamp_failures: AtomicU64::new(0),
                timestamp_failure_errno: AtomicI32::new(0),
            }
        }

        fn snapshot(&self) -> SenderSnapshot {
            SenderSnapshot {
                attempted: self.attempted.load(Ordering::Acquire),
                sent: self.sent.load(Ordering::Acquire),
                would_block: self.would_block.load(Ordering::Acquire),
                timestamp_failures: self.timestamp_failures.load(Ordering::Acquire),
                timestamp_failure_errno: match self.timestamp_failure_errno.load(Ordering::Acquire)
                {
                    0 => None,
                    errno => Some(errno),
                },
            }
        }
    }

    struct SenderGuard {
        counters: Arc<SenderCounters>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl SenderGuard {
        fn start(interface: &str, frame_size: usize) -> Result<Self, io::Error> {
            let socket = open_raw_socket(interface)?;
            let if_index = interface_index(interface);
            let destination = packet_address(if_index, &BROADCAST_MAC);
            let counters = Arc::new(SenderCounters::new());
            let thread_counters = Arc::clone(&counters);
            let handle = thread::Builder::new()
                .name("ruster-nic-acceptance-tx".to_owned())
                .spawn(move || sender_loop(thread_counters, socket, destination, frame_size))?;
            Ok(Self {
                counters,
                handle: Some(handle),
            })
        }

        fn stop(&mut self) -> Result<(), String> {
            self.counters.phase.store(PHASE_STOP, Ordering::Release);
            let Some(handle) = self.handle.take() else {
                return Ok(());
            };
            if handle.join().is_err() {
                Err("sender thread panicked during shutdown".to_owned())
            } else {
                Ok(())
            }
        }
    }

    impl Drop for SenderGuard {
        fn drop(&mut self) {
            self.counters.phase.store(PHASE_STOP, Ordering::Release);
            if let Some(handle) = self.handle.take() {
                if handle.join().is_err() {
                    eprintln!("NIC acceptance sender thread panicked during cleanup");
                }
            }
        }
    }

    #[derive(Default, Clone, Copy)]
    struct ReceivedTotals {
        packets: u64,
        bytes: u64,
        unexpected_frame_size: u64,
    }

    impl ReceivedTotals {
        fn add(&mut self, other: Self) {
            self.packets = self
                .packets
                .checked_add(other.packets)
                .expect("received packet counter overflowed");
            self.bytes = self
                .bytes
                .checked_add(other.bytes)
                .expect("received byte counter overflowed");
            self.unexpected_frame_size = self
                .unexpected_frame_size
                .checked_add(other.unexpected_frame_size)
                .expect("unexpected packet counter overflowed");
        }
    }

    struct Measurement {
        receiver: ReceivedTotals,
        sender: SenderSnapshot,
        elapsed: Duration,
        latency: LatencySummary,
        perf: PerfReport,
    }

    impl Measurement {
        fn not_measured() -> Self {
            Self {
                receiver: ReceivedTotals::default(),
                sender: SenderSnapshot {
                    attempted: 0,
                    sent: 0,
                    would_block: 0,
                    timestamp_failures: 0,
                    timestamp_failure_errno: None,
                },
                elapsed: Duration::ZERO,
                latency: LatencyCollector::new().finish(),
                perf: PerfReport::not_measured(),
            }
        }
    }

    #[test]
    #[ignore = "requires an explicit root physical-NIC acceptance run"]
    fn physical_nic_acceptance_af_packet() {
        require_privileged_execution();
        require_traffic_opt_in();
        let settings = Settings::from_environment();
        let nic = inspect_nic(&settings.interface);
        let affinity = configure_receiver_affinity();
        let conditions = read_system_conditions(&settings.interface, affinity);

        let mut measurement = Measurement::not_measured();
        let mut measurement_error = acceptance_measurement_skip_reason(&nic);
        if measurement_error.is_none() {
            match run_measurement(&settings) {
                Ok(value) => measurement = value,
                Err(error) => measurement_error = Some(error),
            }
        }
        let acceptance = evaluate_hardware_acceptance(
            &nic,
            &measurement.latency,
            measurement.perf,
            &conditions,
            measurement_error.as_deref(),
        );
        print_measurement(
            &settings,
            &nic,
            &conditions,
            &measurement,
            &acceptance,
            measurement_error.as_deref(),
        );
        assert!(
            acceptance.hardware_acceptance,
            "physical NIC acceptance rejected: {}",
            acceptance.blockers_detail()
        );
    }

    fn require_privileged_execution() {
        match env::var("RUSTER_PRIVILEGED_E2E") {
            Ok(value) if value == "1" => {}
            Ok(value) => panic!(
                "physical NIC acceptance is an explicit privileged measurement; RUSTER_PRIVILEGED_E2E must be 1, got {value:?}"
            ),
            Err(env::VarError::NotPresent) => panic!(
                "physical NIC acceptance is an explicit privileged measurement; set RUSTER_PRIVILEGED_E2E=1"
            ),
            Err(env::VarError::NotUnicode(_)) => {
                panic!("RUSTER_PRIVILEGED_E2E is not valid UTF-8")
            }
        }
        // The acceptance contract requires UID 0 in addition to the raw
        // packet capability, so a missing privilege cannot become a skip.
        // SAFETY: geteuid has no pointer arguments and is a read-only query.
        let effective_uid = unsafe { geteuid() };
        assert_eq!(
            effective_uid, 0,
            "physical NIC acceptance requires root (uid 0) and CAP_NET_RAW"
        );
    }

    fn require_traffic_opt_in() {
        match env::var("RUSTER_NIC_ACCEPTANCE_GENERATE_TRAFFIC") {
            Ok(value) if value == "1" => {}
            Ok(value) => panic!(
                "physical NIC acceptance traffic is opt-in; RUSTER_NIC_ACCEPTANCE_GENERATE_TRAFFIC must be 1, got {value:?}"
            ),
            Err(env::VarError::NotPresent) => panic!(
                "physical NIC acceptance traffic is opt-in; set RUSTER_NIC_ACCEPTANCE_GENERATE_TRAFFIC=1 through the acceptance script"
            ),
            Err(env::VarError::NotUnicode(_)) => panic!(
                "RUSTER_NIC_ACCEPTANCE_GENERATE_TRAFFIC is not valid UTF-8"
            ),
        }
    }

    fn run_measurement(settings: &Settings) -> Result<Measurement, String> {
        AfPacketPlatform::ensure_supported()
            .map_err(|error| format!("AF_PACKET platform is unsupported: {error}"))?;
        let rx_if_index = interface_index(&settings.interface);
        let page_size = system_page_size();
        let rx = RingGeometry {
            block_size: RX_BLOCK_SIZE,
            block_count: RX_BLOCK_COUNT,
            frame_size: RX_FRAME_SIZE,
            frame_count: RX_FRAME_COUNT,
            retire_timeout_ms: RX_RETIRE_TIMEOUT_MS,
            private_size: 0,
            feature_flags: 0,
        };
        let tx = RingGeometry {
            retire_timeout_ms: 0,
            private_size: 0,
            feature_flags: 0,
            ..rx
        };
        let config = ValidatedConfig::new(
            &[PortConfig {
                interface: ruster_core::IfId(1),
                if_index: rx_if_index,
                rx,
                tx,
            }],
            page_size,
            settings.frame_size,
        )
        .map_err(|error| format!("AF_PACKET ring configuration failed: {error:?}"))?;
        let mut io = AfPacketIo::open(config).map_err(|error| {
            if let Some(errno) = platform_errno(&error) {
                if matches!(errno, EPERM | EACCES) {
                    return format!(
                        "AF_PACKET open requires CAP_NET_RAW/root (errno={errno}): {error:?}"
                    );
                }
            }
            format!("AF_PACKET open failed: {error:?}")
        })?;
        let mut sender = SenderGuard::start(&settings.interface, settings.frame_size)
            .map_err(|error| raw_socket_error("sender setup", error))?;

        sender.counters.phase.store(PHASE_WARMUP, Ordering::Release);
        let warmup_deadline = Instant::now() + settings.warmup;
        while Instant::now() < warmup_deadline {
            let remaining = warmup_deadline.saturating_duration_since(Instant::now());
            io.wait_for_rx(remaining.min(POLL_SLICE))
                .map_err(|error| format!("AF_PACKET warmup wait failed: {error:?}"))?;
            receive_and_recycle(&mut io, settings.frame_size, None)?;
        }
        if sender.counters.phase.load(Ordering::Acquire) == PHASE_FAILED {
            let errno = sender.counters.fatal_errno.load(Ordering::Acquire);
            return Err(format!("sender failed during warmup with errno {errno}"));
        }
        sender.counters.phase.store(PHASE_IDLE, Ordering::Release);
        drain_until_quiet(&mut io, settings.frame_size)?;
        let sender_before = sender.counters.snapshot();

        let mut latency = LatencyCollector::new();
        let mut perf = PerfEventSet::open_current_thread();
        let measurement_start = Instant::now();
        perf.start();
        sender
            .counters
            .phase
            .store(PHASE_MEASURE, Ordering::Release);
        let measurement_end_target = measurement_start + settings.duration;
        let mut receiver = ReceivedTotals::default();
        while Instant::now() < measurement_end_target {
            let remaining = measurement_end_target.saturating_duration_since(Instant::now());
            io.wait_for_rx(remaining.min(POLL_SLICE))
                .map_err(|error| format!("AF_PACKET measurement wait failed: {error:?}"))?;
            let batch = receive_and_recycle(&mut io, settings.frame_size, Some(&mut latency))?;
            receiver.add(batch);
            if sender.counters.phase.load(Ordering::Acquire) == PHASE_FAILED {
                let errno = sender.counters.fatal_errno.load(Ordering::Acquire);
                return Err(format!(
                    "sender failed during measurement with errno {errno}"
                ));
            }
        }
        let elapsed = Instant::now().saturating_duration_since(measurement_start);
        let perf = perf.stop_and_read();
        let sender_after = sender.counters.snapshot();
        sender
            .stop()
            .map_err(|error| format!("sender cleanup failed: {error}"))?;
        if let Some(errno) = nonzero_errno(sender.counters.fatal_errno.load(Ordering::Acquire)) {
            return Err(format!("sender failed with errno {errno}"));
        }
        let sender = subtract_sender(sender_after, sender_before)?;
        Ok(Measurement {
            receiver,
            sender,
            elapsed,
            latency: latency.finish(),
            perf,
        })
    }

    fn drain_until_quiet(io: &mut AfPacketIo, frame_size: usize) -> Result<(), String> {
        let deadline = Instant::now() + QUIET_DRAIN_TIMEOUT;
        let mut empty_batches = 0_u8;
        while Instant::now() < deadline && empty_batches < 3 {
            io.wait_for_rx(Duration::from_millis(1))
                .map_err(|error| format!("AF_PACKET quiet-drain wait failed: {error:?}"))?;
            let received = receive_and_recycle(io, frame_size, None)?;
            if received.packets == 0 {
                empty_batches = empty_batches.saturating_add(1);
            } else {
                empty_batches = 0;
            }
        }
        Ok(())
    }

    fn receive_and_recycle(
        io: &mut AfPacketIo,
        frame_size: usize,
        mut latency: Option<&mut LatencyCollector>,
    ) -> Result<ReceivedTotals, String> {
        // A TPACKET_V3 block can expose every descriptor in the acquired
        // block; usize::MAX lets the backend clamp to its bounded block size.
        let mut batch = io
            .receive(usize::MAX)
            .map_err(|error| format!("AF_PACKET PacketIo::receive failed: {error:?}"))?;
        let mut totals = ReceivedTotals::default();
        let mut leased = 0_usize;
        while let Some(mut lease) = batch.next_packet() {
            leased = leased
                .checked_add(1)
                .expect("leased packet counter overflowed");
            let bytes = lease.bytes_mut();
            if let Some(collector) = latency.as_deref_mut() {
                collector.record_received(bytes);
            }
            totals.packets = totals
                .packets
                .checked_add(1)
                .expect("received packet counter overflowed");
            totals.bytes = totals
                .bytes
                .checked_add(u64::try_from(bytes.len()).expect("packet length fits u64"))
                .expect("received byte counter overflowed");
            if bytes.len() != frame_size {
                totals.unexpected_frame_size = totals
                    .unexpected_frame_size
                    .checked_add(1)
                    .expect("unexpected packet counter overflowed");
            }
            lease.recycle(DropReason::RouteMiss);
        }
        let completion = batch.finish();
        if !completion.invariants_hold() {
            return Err(format!(
                "AF_PACKET batch completion invariants failed: {completion:?}"
            ));
        }
        if let Some(error) = completion.error {
            return Err(format!(
                "AF_PACKET batch completed with an error: {error:?}"
            ));
        }
        if completion.tx_requested != 0
            || completion.tx_accepted != 0
            || completion.tx_rejected != 0
            || completion.recycled != leased
        {
            return Err(format!(
                "AF_PACKET receiver ownership accounting failed: {completion:?} leased={leased}"
            ));
        }
        Ok(totals)
    }

    fn sender_loop(
        counters: Arc<SenderCounters>,
        socket: RawPacketSocket,
        destination: SockaddrLl,
        frame_size: usize,
    ) {
        let mut frame = build_frame(frame_size);
        let mut last_timestamp = 0_u64;
        loop {
            let phase = counters.phase.load(Ordering::Acquire);
            if phase >= PHASE_STOP {
                return;
            }
            if phase != PHASE_WARMUP && phase != PHASE_MEASURE {
                thread::yield_now();
                continue;
            }
            if let Err(error) = stamp_frame_with_last(&mut frame, &mut last_timestamp) {
                if phase == PHASE_MEASURE {
                    counters.timestamp_failures.fetch_add(1, Ordering::Relaxed);
                    let code = if error.code() == 0 { -1 } else { error.code() };
                    let _ = counters.timestamp_failure_errno.compare_exchange(
                        0,
                        code,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                }
                clear_frame_timestamp(&mut frame);
            }
            if phase == PHASE_MEASURE {
                counters.attempted.fetch_add(1, Ordering::Relaxed);
            }
            // SAFETY: the socket is owned only by this thread; `frame` and
            // `destination` are live initialized buffers for the synchronous
            // nonblocking sendto call, which reads but does not retain them.
            let sent = unsafe {
                sendto(
                    socket.fd(),
                    frame.as_ptr().cast::<c_void>(),
                    frame.len(),
                    MSG_DONTWAIT,
                    (&destination as *const SockaddrLl).cast::<c_void>(),
                    u32::try_from(size_of::<SockaddrLl>()).expect("sockaddr_ll fits socklen_t"),
                )
            };
            if sent < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(EAGAIN) {
                    if phase == PHASE_MEASURE {
                        counters.would_block.fetch_add(1, Ordering::Relaxed);
                    }
                    thread::yield_now();
                    continue;
                }
                counters
                    .fatal_errno
                    .store(error.raw_os_error().unwrap_or(-1), Ordering::Release);
                counters.phase.store(PHASE_FAILED, Ordering::Release);
                return;
            }
            if usize::try_from(sent).ok() != Some(frame.len()) {
                counters.fatal_errno.store(EIO, Ordering::Release);
                counters.phase.store(PHASE_FAILED, Ordering::Release);
                return;
            }
            if phase == PHASE_MEASURE {
                counters.sent.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn build_frame(frame_size: usize) -> Vec<u8> {
        let mut frame = vec![0_u8; frame_size];
        frame[..BROADCAST_MAC.len()].copy_from_slice(&BROADCAST_MAC);
        frame[BROADCAST_MAC.len()..BROADCAST_MAC.len() + SOURCE_MAC.len()]
            .copy_from_slice(&SOURCE_MAC);
        frame[12..14].copy_from_slice(&0x88b5_u16.to_be_bytes());
        for (index, byte) in frame[14..].iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17).wrapping_add(0x4e);
        }
        frame
    }

    fn open_raw_socket(interface: &str) -> Result<RawPacketSocket, io::Error> {
        let if_index = interface_index(interface);
        // SAFETY: socket has no pointer arguments; its returned descriptor is
        // immediately owned by RawPacketSocket.
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
        let address = packet_address(if_index, &BROADCAST_MAC);
        // SAFETY: address is initialized and live for this synchronous bind.
        let result = unsafe {
            bind(
                socket.fd(),
                (&address as *const SockaddrLl).cast::<c_void>(),
                u32::try_from(size_of::<SockaddrLl>()).expect("sockaddr_ll fits socklen_t"),
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }

    fn packet_address(if_index: u32, destination: &[u8; 6]) -> SockaddrLl {
        let mut address = [0_u8; 8];
        address[..destination.len()].copy_from_slice(destination);
        SockaddrLl {
            sll_family: AF_PACKET as u16,
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex: i32::try_from(if_index).expect("Linux interface index fits sockaddr_ll"),
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: address,
        }
    }

    fn interface_index(interface: &str) -> u32 {
        let name = CString::new(interface)
            .unwrap_or_else(|_| panic!("interface name contains an embedded NUL byte"));
        // SAFETY: name is a live, NUL-terminated interface name.
        let index = unsafe { if_nametoindex(name.as_ptr()) };
        if index == 0 {
            panic!(
                "cannot resolve interface {interface:?}: {}",
                io::Error::last_os_error()
            );
        }
        index
    }

    fn system_page_size() -> usize {
        // SAFETY: sysconf has no pointer arguments.
        let page_size = unsafe { sysconf(SC_PAGESIZE) };
        let page_size = usize::try_from(page_size)
            .unwrap_or_else(|_| panic!("sysconf(_SC_PAGESIZE) returned {page_size}"));
        assert!(
            page_size.is_power_of_two(),
            "system page size is not a power of two"
        );
        page_size
    }

    fn required_interface() -> String {
        match env::var("RUSTER_NIC_ACCEPTANCE_IFACE") {
            Ok(value) if !value.is_empty() => value,
            Ok(_) => panic!("RUSTER_NIC_ACCEPTANCE_IFACE must not be empty"),
            Err(env::VarError::NotPresent) => panic!(
                "RUSTER_NIC_ACCEPTANCE_IFACE is required; pass --interface to the acceptance script"
            ),
            Err(env::VarError::NotUnicode(_)) => {
                panic!("RUSTER_NIC_ACCEPTANCE_IFACE is not valid UTF-8")
            }
        }
    }

    fn validate_interface_name(name: &str) {
        assert!(!name.is_empty(), "interface name must not be empty");
        assert!(name.len() <= 15, "interface name is longer than IFNAMSIZ-1");
        assert!(
            name.bytes().all(|byte| byte != 0 && byte != b'/'),
            "interface name contains an unsafe path character"
        );
    }

    fn parse_u64(name: &str, default: u64) -> u64 {
        match env::var(name) {
            Ok(value) => value
                .parse::<u64>()
                .unwrap_or_else(|_| panic!("{name} must be an unsigned integer, got {value:?}")),
            Err(env::VarError::NotPresent) => default,
            Err(env::VarError::NotUnicode(_)) => panic!("{name} is not valid UTF-8"),
        }
    }

    fn subtract_sender(
        after: SenderSnapshot,
        before: SenderSnapshot,
    ) -> Result<SenderSnapshot, String> {
        let subtract = |current: u64, previous: u64, name: &str| {
            current
                .checked_sub(previous)
                .ok_or_else(|| format!("sender {name} counter moved backwards"))
        };
        Ok(SenderSnapshot {
            attempted: subtract(after.attempted, before.attempted, "attempted")?,
            sent: subtract(after.sent, before.sent, "sent")?,
            would_block: subtract(after.would_block, before.would_block, "would_block")?,
            timestamp_failures: subtract(
                after.timestamp_failures,
                before.timestamp_failures,
                "timestamp_failures",
            )?,
            timestamp_failure_errno: after.timestamp_failure_errno,
        })
    }

    fn nonzero_errno(errno: i32) -> Option<i32> {
        (errno != 0).then_some(errno)
    }

    fn platform_errno(error: &PlatformError) -> Option<i32> {
        match error {
            PlatformError::Syscall { errno, .. } => Some(errno.get()),
            _ => None,
        }
    }

    fn raw_socket_error(operation: &str, error: io::Error) -> String {
        if matches!(error.raw_os_error(), Some(EPERM | EACCES)) {
            format!("AF_PACKET {operation} requires CAP_NET_RAW/root: {error}")
        } else {
            format!("AF_PACKET {operation} failed: {error}")
        }
    }

    fn print_measurement(
        settings: &Settings,
        nic: &super::throughput_measurement::NicInspection,
        conditions: &SystemConditions,
        measurement: &Measurement,
        acceptance: &HardwareAcceptanceReport,
        measurement_error: Option<&str>,
    ) {
        let link_speed_verdict = nic.link_speed_at_least_acceptance_threshold();
        let driver = nic.driver.as_deref().unwrap_or("unknown");
        let measurement_error_token = acceptance_measurement_error_token(nic, measurement_error);
        let measurement_record = format!(
            "measurement_kind=physical_nic_acceptance hardware_acceptance={} interface_type=physical_nic interface={} backend=af_packet self_generated_traffic=true measurement_started={} measurement_error={} frame_size={} warmup_ms={} duration_ms_requested={} measurement_duration_ms={:.3} receiver_packets={} receiver_bytes={} sender_attempted_packets={} sender_sent_packets={} sender_would_block_packets={} sender_timestamp_write_failures={} unexpected_frame_size_packets={} latency_clock={} latency_clock_domain={} latency_clock_same_host=true latency_one_way=true latency_percentile_method={} latency_samples={} latency_min_samples_p50=2 latency_min_samples_p90=10 latency_min_samples_p99=100 latency_min_samples_p99_9=1000 latency_p50_ns={} latency_p90_ns={} latency_p99_ns={} latency_p99_9_ns={} latency_min_ns={} latency_max_ns={} latency_unmatched_packets={} latency_missing_timestamps={} latency_backwards_timestamps={} latency_clock_errors={} latency_clock_error_errno={} perf_event_open_syscall={} perf_event_attr_size={} perf_event_scope=receiving_thread perf_event_paranoid={} perf_cycles_count={} perf_cycles_status={} cycles_per_packet={} perf_cache_references_count={} perf_cache_references_status={} perf_cache_misses_count={} perf_cache_misses_status={} cache_miss_rate_percent={} cpu_affinity_requested={} cpu_affinity_selection={} cpu_affinity_set={} cpu_affinity_get={} cpu_affinity_verified={} cpu_affinity_current_cpu={} cpu_affinity_observed_mask={} cpu_affinity_set_errno={} cpu_affinity_get_errno={} numa_node={} numa_node_status={} irq_count={} irq_count_status={} irq_affinity={} irq_affinity_status={} irq_affinity_verified={} irq_affinity_verification={} rss_queue_count={} rss_queue_count_status={} rss_queue_verified={} rss_queue_verification={} rss_indirection_table_size={} nic_device_present={} nic_driver={} nic_driver_virtual={} nic_link_speed_mbps={} nic_link_speed_raw={} nic_physical_verdict={} nic_link_speed_verdict={} irq_affinity_configuration=read_only rss_configuration=read_only",
            acceptance.hardware_acceptance,
            shell_safe(&settings.interface),
            measurement.receiver.packets > 0 || measurement.sender.attempted > 0,
            measurement_error_token,
            settings.frame_size,
            settings.warmup.as_millis(),
            settings.duration.as_millis(),
            measurement.elapsed.as_secs_f64() * 1_000.0,
            measurement.receiver.packets,
            measurement.receiver.bytes,
            measurement.sender.attempted,
            measurement.sender.sent,
            measurement.sender.would_block,
            measurement.sender.timestamp_failures,
            measurement.receiver.unexpected_frame_size,
            LATENCY_CLOCK_NAME,
            LATENCY_CLOCK_DOMAIN,
            LATENCY_PERCENTILE_METHOD,
            measurement.latency.samples,
            format_latency_value(measurement.latency.p50_ns),
            format_latency_value(measurement.latency.p90_ns),
            format_latency_value(measurement.latency.p99_ns),
            format_latency_value(measurement.latency.p99_9_ns),
            format_latency_value(measurement.latency.min_ns),
            format_latency_value(measurement.latency.max_ns),
            measurement.latency.unmatched_packets,
            measurement.latency.missing_timestamps,
            measurement.latency.backwards_timestamps,
            measurement.latency.clock_errors,
            format_optional_i32(measurement.latency.last_clock_error),
            PerfEventSet::syscall_number(),
            PerfEventSet::attr_size(),
            read_perf_event_paranoid(),
            measurement.perf.cycles.value(),
            measurement.perf.cycles.status(),
            format_cycles_per_packet(measurement.perf, measurement.receiver.packets),
            measurement.perf.cache_references.value(),
            measurement.perf.cache_references.status(),
            measurement.perf.cache_misses.value(),
            measurement.perf.cache_misses.status(),
            format_cache_miss_rate(measurement.perf),
            conditions.affinity.selected_cpu,
            conditions.affinity.selection_source,
            if conditions.affinity.set_ok { "verified" } else { "failed" },
            if conditions.affinity.get_ok { "verified" } else { "failed" },
            conditions.affinity.verified,
            format_optional_usize(conditions.affinity.current_cpu),
            conditions.affinity.observed_mask.as_str(),
            format_optional_i32(conditions.affinity.set_errno),
            format_optional_i32(conditions.affinity.get_errno),
            conditions.numa_node.value.as_str(),
            conditions.numa_node.status(),
            conditions.irq_count.value.as_str(),
            conditions.irq_count.status(),
            conditions.irq_affinity.value.as_str(),
            conditions.irq_affinity.status(),
            conditions.irq_affinity_verified,
            conditions.irq_affinity_verification.as_str(),
            conditions.rss_queue_count.value.as_str(),
            conditions.rss_queue_count.status(),
            conditions.rss_queue_verified,
            conditions.rss_queue_verification.as_str(),
            conditions
                .rss_indirection_table_size
                .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
            nic.device_present,
            shell_safe(driver),
            nic.driver_is_virtual,
            nic.link_speed_mbps
                .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
            shell_safe(&nic.link_speed_raw),
            nic.physical_verdict,
            link_speed_verdict,
        );
        assert_machine_readable_record_line(&measurement_record);
        assert_machine_readable_ascii_token_field(&measurement_record, "measurement_error");
        println!("{measurement_record}");
        let blockers_record = format!(
            "acceptance_blockers_count={} acceptance_blockers={}",
            acceptance.blockers.len(),
            acceptance.blocker_tokens_value()
        );
        assert_machine_readable_record_line(&blockers_record);
        assert_machine_readable_ascii_token_list_field(&blockers_record, "acceptance_blockers");
        println!("{blockers_record}");
        if let Some(detail) = measurement_error {
            eprintln!("MEASUREMENT_ERROR_DETAIL: {detail}");
        }
        if !acceptance.hardware_acceptance {
            eprintln!(
                "ACCEPTANCE_BLOCKERS_DETAIL: {}",
                acceptance.blockers_detail()
            );
        }
        if measurement.sender.timestamp_failures > 0 {
            eprintln!(
                "MEASUREMENT_WARNING component=latency stage=sender_timestamp failures={} errno={}",
                measurement.sender.timestamp_failures,
                format_optional_i32(measurement.sender.timestamp_failure_errno),
            );
        }
        if !measurement.latency.percentiles_complete() {
            eprintln!(
                "MEASUREMENT_WARNING component=latency status=insufficient_samples samples={} required_p99_9=1000",
                measurement.latency.samples,
            );
        }
    }

    fn shell_safe(value: &str) -> String {
        let mut safe = String::with_capacity(value.len());
        for character in value.chars() {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ':') {
                safe.push(character);
            } else {
                safe.push('_');
            }
        }
        if safe.is_empty() {
            "unknown".to_owned()
        } else {
            safe
        }
    }

    // SAFETY: these declarations are Linux/POSIX ABI boundaries; each call
    // site below supplies initialized pointers whose lifetimes cover the call.
    unsafe extern "C" {
        fn socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int;
        fn bind(socket: c_int, address: *const c_void, address_len: u32) -> c_int;
        fn sendto(
            socket: c_int,
            buffer: *const c_void,
            length: usize,
            flags: c_int,
            address: *const c_void,
            address_len: u32,
        ) -> isize;
        fn close(fd: c_int) -> c_int;
        fn if_nametoindex(interface: *const c_char) -> u32;
        fn sysconf(name: c_int) -> isize;
        fn geteuid() -> u32;
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
#[ignore = "requires Linux and an explicit root physical-NIC acceptance run"]
fn physical_nic_acceptance_af_packet() {
    panic!("physical NIC AF_PACKET acceptance is unsupported on this operating system");
}
