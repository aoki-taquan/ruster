//! Functional veth throughput measurement for the native AF_XDP data path.
//!
//! The test is a privileged opt-in measurement.  The shell harness creates a
//! fresh veth pair; this process opens independent raw AF_PACKET senders on
//! one end and attaches the checked SKB-mode XDP redirect path to the other
//! end. The receiver uses only `XdpResource`'s `PacketIo::receive` API and
//! recycles every received lease.

#![cfg_attr(
    all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ),
    allow(unsafe_code)
)]

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
#[path = "../../bench/src/throughput_measurement.rs"]
mod throughput_measurement;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
mod linux_x86_64 {
    use super::throughput_measurement::{
        assert_machine_readable_record_line, clear_frame_timestamp, configure_receiver_affinity,
        format_cache_miss_rate, format_cycles_per_packet, format_latency_value,
        format_optional_i32, format_optional_usize, read_perf_event_paranoid,
        read_system_conditions, stamp_frame_with_last, unmeasured_fields, AffinityReport,
        LatencyCollector, LatencySummary, Observation, PerfEventSet, PerfReport, SystemConditions,
        LATENCY_CLOCK_DOMAIN, LATENCY_CLOCK_NAME, LATENCY_PERCENTILE_METHOD,
    };
    use ruster_core::{DropReason, PacketBatch, PacketIo};
    use ruster_io_xdp_native::{
        abi::{XDP_COPY, XDP_USE_NEED_WAKEUP},
        ensure_native_syscall_supported, ensure_supported, RingConfig, UmemConfig,
        ValidatedBindFlags, XdpAttachMode, XdpResource, XdpResourceBuilder, XskMap,
    };
    use std::{
        env,
        ffi::{c_char, c_int, c_void, CString},
        fs, io,
        mem::size_of,
        os::fd::RawFd,
        ptr::null_mut,
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
    const EPERM: i32 = 1;
    const EACCES: i32 = 13;
    const SC_PAGESIZE: c_int = 30;
    const PROT_READ: c_int = 0x1;
    const PROT_WRITE: c_int = 0x2;
    const MAP_PRIVATE: c_int = 0x02;
    const MAP_ANONYMOUS: c_int = 0x20;

    const PHASE_IDLE: u8 = 0;
    const PHASE_WARMUP: u8 = 1;
    const PHASE_MEASURE: u8 = 2;
    const PHASE_STOP: u8 = 3;
    const PHASE_FAILED: u8 = 4;

    const DEFAULT_FRAME_SIZE: usize = 60;
    const DEFAULT_DURATION_MS: u64 = 3_000;
    const DEFAULT_WARMUP_MS: u64 = 100;
    const DEFAULT_WINDOW_MS: u64 = 250;
    const DEFAULT_SENDER_THREADS: usize = 3;
    const DEFAULT_SEND_BATCH_SIZE: usize = 8;
    const MAX_SENDER_THREADS: usize = 16;
    const MAX_SEND_BATCH_SIZE: usize = 32;
    const MIN_FRAME_SIZE: usize = 60;
    const MAX_FRAME_SIZE: usize = 1_514;
    const UMEM_FRAME_SIZE: u32 = 2_048;
    const UMEM_FRAME_COUNT: u32 = 256;
    const UMEM_RX_FRAMES: u32 = 192;
    const UMEM_GENERATED_FRAMES: u32 = UMEM_FRAME_COUNT - UMEM_RX_FRAMES;
    const RING_ENTRIES: u32 = 256;
    const POLL_SLICE: Duration = Duration::from_millis(5);
    const QUIET_DRAIN_TIMEOUT: Duration = Duration::from_millis(50);
    const BROADCAST_MAC: [u8; 6] = [0xff; 6];
    const SOURCE_MAC: [u8; 6] = [0x02, 0x72, 0x75, 0x73, 0x74, 0x52];

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

    // These layouts match the Linux x86_64 userspace ABI used by the
    // `sendmmsg` symbol. The corresponding installed-header definitions are
    // cited in the measurement report; no external crate is needed here.
    #[repr(C)]
    struct Iovec {
        iov_base: *mut c_void,
        iov_len: usize,
    }

    #[repr(C)]
    struct MsgHdr {
        msg_name: *mut c_void,
        msg_namelen: u32,
        msg_iov: *mut Iovec,
        msg_iovlen: usize,
        msg_control: *mut c_void,
        msg_controllen: usize,
        msg_flags: c_int,
    }

    #[repr(C)]
    struct Mmsghdr {
        msg_hdr: MsgHdr,
        msg_len: u32,
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

    struct AnonymousMemory {
        address: *mut u8,
        len: usize,
        active: bool,
    }

    impl AnonymousMemory {
        fn new(len: usize, page_size: usize) -> Result<Self, io::Error> {
            assert!(len > 0, "AF_XDP UMEM length must be nonzero");
            assert_eq!(
                len % page_size,
                0,
                "AF_XDP UMEM length must be page-aligned"
            );
            // SAFETY: these arguments request a private writable anonymous
            // mapping; mmap does not dereference a caller-owned pointer.
            let address = unsafe {
                mmap(
                    null_mut(),
                    len,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if address.is_null() || address as isize == -1 {
                return Err(io::Error::last_os_error());
            }
            assert_eq!(
                address as usize % page_size,
                0,
                "AF_XDP UMEM mmap did not return page-aligned memory"
            );
            Ok(Self {
                address: address.cast(),
                len,
                active: true,
            })
        }

        fn as_mut_slice(&mut self) -> &mut [u8] {
            assert!(self.active, "AF_XDP UMEM mapping is already closed");
            // SAFETY: the mapping is live, writable, and exactly `self.len`
            // bytes long for the returned borrow.
            unsafe { std::slice::from_raw_parts_mut(self.address, self.len) }
        }

        fn close(mut self) -> Result<(), io::Error> {
            if !self.active {
                return Ok(());
            }
            let address = self.address;
            let len = self.len;
            self.active = false;
            self.address = null_mut();
            self.len = 0;
            // SAFETY: address and len are the exact extent returned by mmap;
            // this owner marks itself inactive before the syscall, so Drop
            // cannot issue a second unmap.
            let result = unsafe { munmap(address.cast::<c_void>(), len) };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    impl Drop for AnonymousMemory {
        fn drop(&mut self) {
            if !self.active {
                return;
            }
            // SAFETY: this is the still-active mmap extent owned by this
            // value; Drop is the best-effort fallback after an unwind.
            let result = unsafe { munmap(self.address.cast::<c_void>(), self.len) };
            self.active = false;
            if result != 0 {
                eprintln!("AF_XDP UMEM munmap failed: {}", io::Error::last_os_error());
            }
        }
    }

    struct Settings {
        rx_interface: String,
        tx_interface: String,
        frame_size: usize,
        duration: Duration,
        warmup: Duration,
        window: Duration,
        sender_threads: usize,
        send_batch_size: usize,
    }

    impl Settings {
        fn from_environment() -> Self {
            let backend =
                env::var("RUSTER_THROUGHPUT_BACKEND").unwrap_or_else(|error| match error {
                    env::VarError::NotPresent => "af_xdp".to_owned(),
                    env::VarError::NotUnicode(_) => {
                        panic!("RUSTER_THROUGHPUT_BACKEND is not valid UTF-8")
                    }
                });
            if backend != "af_xdp" {
                panic!("AF_XDP throughput test requires backend=af_xdp; requested {backend:?}");
            }

            let rx_interface = required_interface(
                "RUSTER_VETH_RX_IFACE",
                "RUSTER_E2E_IFACE",
                "AF_XDP throughput receiver",
            );
            let tx_interface = required_interface(
                "RUSTER_VETH_TX_IFACE",
                "RUSTER_E2E_PEER_IFACE",
                "AF_XDP throughput sender",
            );
            validate_interface_name(&rx_interface);
            validate_interface_name(&tx_interface);

            let frame_size = parse_u64("RUSTER_THROUGHPUT_FRAME_SIZE", DEFAULT_FRAME_SIZE as u64);
            let duration_ms = parse_u64("RUSTER_THROUGHPUT_DURATION_MS", DEFAULT_DURATION_MS);
            let warmup_ms = parse_u64("RUSTER_THROUGHPUT_WARMUP_MS", DEFAULT_WARMUP_MS);
            let window_ms = parse_u64("RUSTER_THROUGHPUT_WINDOW_MS", DEFAULT_WINDOW_MS);
            let sender_threads =
                parse_usize("RUSTER_THROUGHPUT_SENDER_THREADS", DEFAULT_SENDER_THREADS);
            let send_batch_size =
                parse_usize("RUSTER_THROUGHPUT_SEND_BATCH_SIZE", DEFAULT_SEND_BATCH_SIZE);
            let frame_size = usize::try_from(frame_size)
                .unwrap_or_else(|_| panic!("RUSTER_THROUGHPUT_FRAME_SIZE does not fit usize"));
            assert!(
                (MIN_FRAME_SIZE..=MAX_FRAME_SIZE).contains(&frame_size),
                "frame size must be between {MIN_FRAME_SIZE} and {MAX_FRAME_SIZE} bytes"
            );
            assert!(
                duration_ms > 0,
                "measurement duration must be greater than zero"
            );
            assert!(warmup_ms >= 20, "warmup must be at least 20 ms");
            assert!(
                window_ms > 0,
                "measurement window must be greater than zero"
            );
            assert!(
                (1..=MAX_SENDER_THREADS).contains(&sender_threads),
                "sender thread count must be between 1 and {MAX_SENDER_THREADS}"
            );
            assert!(
                (1..=MAX_SEND_BATCH_SIZE).contains(&send_batch_size),
                "send batch size must be between 1 and {MAX_SEND_BATCH_SIZE}"
            );

            Self {
                rx_interface,
                tx_interface,
                frame_size,
                duration: Duration::from_millis(duration_ms),
                warmup: Duration::from_millis(warmup_ms),
                window: Duration::from_millis(window_ms),
                sender_threads,
                send_batch_size,
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
        handles: Vec<thread::JoinHandle<()>>,
    }

    impl SenderGuard {
        fn spawn(
            counters: Arc<SenderCounters>,
            sockets: Vec<RawPacketSocket>,
            destination: SockaddrLl,
            frame_size: usize,
            batch_size: usize,
        ) -> Result<Self, io::Error> {
            let mut handles = Vec::with_capacity(sockets.len());
            for (thread_index, socket) in sockets.into_iter().enumerate() {
                let thread_counters = Arc::clone(&counters);
                let result = thread::Builder::new()
                    .name(format!("ruster-veth-tx-{thread_index}"))
                    .spawn(move || {
                        sender_loop(thread_counters, socket, destination, frame_size, batch_size);
                    });
                match result {
                    Ok(handle) => handles.push(handle),
                    Err(error) => {
                        counters.phase.store(PHASE_STOP, Ordering::Release);
                        for handle in handles {
                            let _ = handle.join();
                        }
                        return Err(error);
                    }
                }
            }

            Ok(Self { counters, handles })
        }

        fn stop(&mut self) -> Result<(), &'static str> {
            self.counters.phase.store(PHASE_STOP, Ordering::Release);
            let mut panicked = false;
            for handle in self.handles.drain(..) {
                if handle.join().is_err() {
                    panicked = true;
                }
            }
            if panicked {
                Err("sender thread panicked during shutdown")
            } else {
                Ok(())
            }
        }
    }

    impl Drop for SenderGuard {
        fn drop(&mut self) {
            self.counters.phase.store(PHASE_STOP, Ordering::Release);
            for handle in self.handles.drain(..) {
                if handle.join().is_err() {
                    eprintln!("AF_XDP throughput sender thread panicked during cleanup");
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

    #[derive(Clone, Copy)]
    struct RateRange {
        min: f64,
        max: f64,
        samples: u64,
    }

    impl Default for RateRange {
        fn default() -> Self {
            Self {
                min: f64::INFINITY,
                max: f64::NEG_INFINITY,
                samples: 0,
            }
        }
    }

    impl RateRange {
        fn record(&mut self, count: u64, elapsed: Duration) {
            let seconds = elapsed.as_secs_f64();
            if seconds <= 0.0 {
                return;
            }
            let rate = count as f64 / seconds;
            self.min = self.min.min(rate);
            self.max = self.max.max(rate);
            self.samples = self
                .samples
                .checked_add(1)
                .expect("sample counter overflowed");
        }

        fn value(self, minimum: bool) -> String {
            if self.samples == 0 {
                "unknown".to_owned()
            } else if minimum {
                format!("{:.3}", self.min)
            } else {
                format!("{:.3}", self.max)
            }
        }
    }

    #[derive(Default, Clone, Copy)]
    struct RateRanges {
        receiver_pps: RateRange,
        receiver_bps: RateRange,
        sender_attempted_pps: RateRange,
        sender_sent_pps: RateRange,
    }

    #[derive(Clone, Copy)]
    struct KernelCounters {
        rx_dropped: Option<u64>,
        rx_missed_errors: Option<u64>,
        tx_dropped: Option<u64>,
    }

    impl KernelCounters {
        fn read(interface: &str) -> Self {
            Self {
                rx_dropped: read_sysfs_counter(interface, "rx_dropped"),
                rx_missed_errors: read_sysfs_counter(interface, "rx_missed_errors"),
                tx_dropped: read_sysfs_counter(interface, "tx_dropped"),
            }
        }
    }

    struct Measurement {
        receiver: ReceivedTotals,
        sender: SenderSnapshot,
        elapsed: Duration,
        ranges: RateRanges,
        rx_before: KernelCounters,
        rx_after: KernelCounters,
        tx_before: KernelCounters,
        tx_after: KernelCounters,
        latency: LatencySummary,
        perf: PerfReport,
        conditions: SystemConditions,
    }

    #[test]
    #[ignore = "requires an explicit root veth throughput run"]
    fn veth_throughput_af_xdp() {
        require_privileged_execution();
        let settings = Settings::from_environment();
        let measurement = run_measurement(&settings);
        print_measurement(&settings, measurement);
    }

    fn require_privileged_execution() {
        match env::var("RUSTER_PRIVILEGED_E2E") {
            Ok(value) if value == "1" => {}
            Ok(value) => panic!(
                "veth throughput is an explicit privileged measurement; RUSTER_PRIVILEGED_E2E must be 1, got {value:?}"
            ),
            Err(env::VarError::NotPresent) => panic!(
                "veth throughput is an explicit privileged measurement; set RUSTER_PRIVILEGED_E2E=1"
            ),
            Err(env::VarError::NotUnicode(_)) => {
                panic!("RUSTER_PRIVILEGED_E2E is not valid UTF-8")
            }
        }
        // The harness deliberately requires UID 0 even when a process has a
        // narrower capability set, matching the privileged E2E contract.
        // SAFETY: geteuid has no pointer arguments and is a read-only query.
        let effective_uid = unsafe { geteuid() };
        assert_eq!(effective_uid, 0, "veth throughput requires root (uid 0)");
    }

    fn run_measurement(settings: &Settings) -> Measurement {
        ensure_supported()
            .unwrap_or_else(|error| panic!("AF_XDP platform is unsupported: {error:?}"));
        ensure_native_syscall_supported().unwrap_or_else(|error| {
            panic!("AF_XDP native syscall platform is unsupported: {error:?}")
        });

        let rx_if_index = interface_index(&settings.rx_interface);
        let tx_if_index = interface_index(&settings.tx_interface);
        let page_size = system_page_size();
        let frame_count = usize::try_from(UMEM_FRAME_COUNT).expect("UMEM frame count fits usize");
        let umem_frame_size = usize::try_from(UMEM_FRAME_SIZE).expect("UMEM frame size fits usize");
        let umem_len = frame_count
            .checked_mul(umem_frame_size)
            .expect("UMEM length cannot overflow");
        assert_eq!(umem_len % page_size, 0, "UMEM length must be page-aligned");
        let umem = UmemConfig::new(
            UMEM_FRAME_COUNT,
            UMEM_FRAME_SIZE,
            0,
            UMEM_RX_FRAMES,
            UMEM_GENERATED_FRAMES,
            0,
        )
        .unwrap_or_else(|error| panic!("AF_XDP UMEM configuration failed: {error:?}"));
        let rings = RingConfig::new(RING_ENTRIES, RING_ENTRIES, RING_ENTRIES, RING_ENTRIES)
            .unwrap_or_else(|error| panic!("AF_XDP ring configuration failed: {error:?}"));
        let bind_flags = ValidatedBindFlags::new(XDP_USE_NEED_WAKEUP | XDP_COPY)
            .unwrap_or_else(|error| panic!("AF_XDP bind flags failed: {error:?}"));

        let mut memory = AnonymousMemory::new(umem_len, page_size)
            .unwrap_or_else(|error| panic!("AF_XDP anonymous UMEM mmap failed: {error}"));
        let mut resource = XdpResourceBuilder::new(umem, rings, rx_if_index, 0)
            .unwrap_or_else(|error| panic!("AF_XDP resource builder failed: {error:?}"))
            .with_bind_flags(bind_flags)
            .build(memory.as_mut_slice())
            .unwrap_or_else(|error| panic!("AF_XDP resource build failed: {error:?}"));

        let map = XskMap::new(1)
            .unwrap_or_else(|error| panic!("AF_XDP XSKMAP creation failed: {error:?}"));
        map.register(&resource)
            .unwrap_or_else(|error| panic!("AF_XDP XSKMAP registration failed: {error:?}"));
        let program = map
            .load_redirect_program()
            .unwrap_or_else(|error| panic!("AF_XDP redirect program load failed: {error:?}"));
        let mut attachment = program
            .attach_with_mode(rx_if_index, XdpAttachMode::Skb)
            .unwrap_or_else(|error| panic!("AF_XDP SKB attachment failed: {error:?}"));
        assert!(
            attachment.is_attached(),
            "AF_XDP attachment did not become active"
        );

        let sender_sockets = (0..settings.sender_threads)
            .map(|_| {
                open_raw_socket(&settings.tx_interface).unwrap_or_else(|error| {
                    panic_raw_socket_error("peer AF_PACKET sender setup", error);
                })
            })
            .collect::<Vec<_>>();
        let destination = packet_address(tx_if_index, &BROADCAST_MAC);
        let counters = Arc::new(SenderCounters::new());
        let mut sender = SenderGuard::spawn(
            Arc::clone(&counters),
            sender_sockets,
            destination,
            settings.frame_size,
            settings.send_batch_size,
        )
        .unwrap_or_else(|error| panic!("AF_XDP sender thread setup failed: {error}"));
        let affinity = configure_receiver_affinity();
        let conditions = read_system_conditions(&settings.rx_interface, affinity);

        counters.phase.store(PHASE_WARMUP, Ordering::Release);
        let warmup_deadline = Instant::now() + settings.warmup;
        while Instant::now() < warmup_deadline {
            let remaining = warmup_deadline.saturating_duration_since(Instant::now());
            let _ = resource
                .wait_for_rx(remaining.min(POLL_SLICE))
                .unwrap_or_else(|error| panic!("AF_XDP warmup wait failed: {error:?}"));
            let _ = receive_and_recycle(&mut resource, settings.frame_size, None);
        }

        if counters.phase.load(Ordering::Acquire) == PHASE_FAILED {
            let fatal_errno = counters.fatal_errno.load(Ordering::Acquire);
            if let Err(error) = sender.stop() {
                panic!("AF_XDP sender cleanup failed: {error}");
            }
            panic!("AF_XDP sender failed during warmup with errno {fatal_errno}");
        }
        counters.phase.store(PHASE_IDLE, Ordering::Release);
        drain_until_quiet(&mut resource, settings.frame_size);
        counters.attempted.store(0, Ordering::Release);
        counters.sent.store(0, Ordering::Release);
        counters.would_block.store(0, Ordering::Release);
        counters.fatal_errno.store(0, Ordering::Release);
        counters.timestamp_failures.store(0, Ordering::Release);
        counters.timestamp_failure_errno.store(0, Ordering::Release);

        let rx_before = KernelCounters::read(&settings.rx_interface);
        let tx_before = KernelCounters::read(&settings.tx_interface);
        let mut latency = LatencyCollector::new();
        let mut perf = PerfEventSet::open_current_thread();
        let measurement_start = Instant::now();
        let requested_end = measurement_start + settings.duration;
        perf.start();
        counters.phase.store(PHASE_MEASURE, Ordering::Release);

        let mut receiver = ReceivedTotals::default();
        let mut ranges = RateRanges::default();
        let mut interval_start = measurement_start;
        let mut interval_receiver = ReceivedTotals::default();
        let mut interval_sender = SenderSnapshot {
            attempted: 0,
            sent: 0,
            would_block: 0,
            timestamp_failures: 0,
            timestamp_failure_errno: None,
        };
        let mut next_window = measurement_start + settings.window;

        while Instant::now() < requested_end {
            if counters.phase.load(Ordering::Acquire) == PHASE_FAILED {
                break;
            }
            let remaining = requested_end.saturating_duration_since(Instant::now());
            let _ = resource
                .wait_for_rx(remaining.min(POLL_SLICE))
                .unwrap_or_else(|error| panic!("AF_XDP measurement wait failed: {error:?}"));
            let batch = receive_and_recycle(&mut resource, settings.frame_size, Some(&mut latency));
            receiver.add(batch);

            let now = Instant::now();
            if now >= next_window {
                let snapshot = counters.snapshot();
                record_interval(
                    &mut ranges,
                    now.saturating_duration_since(interval_start),
                    receiver,
                    interval_receiver,
                    snapshot,
                    interval_sender,
                );
                interval_start = now;
                interval_receiver = receiver;
                interval_sender = snapshot;
                next_window = now + settings.window;
            }
        }

        let measurement_end = Instant::now();
        let sender_final = counters.snapshot();
        let perf = perf.stop_and_read();
        if let Err(error) = sender.stop() {
            panic!("AF_XDP sender cleanup failed: {error}");
        }
        let fatal_errno = counters.fatal_errno.load(Ordering::Acquire);
        if fatal_errno != 0 {
            panic!("AF_XDP sender failed with errno {fatal_errno}");
        }
        record_interval(
            &mut ranges,
            measurement_end.saturating_duration_since(interval_start),
            receiver,
            interval_receiver,
            sender_final,
            interval_sender,
        );

        let rx_after = KernelCounters::read(&settings.rx_interface);
        let tx_after = KernelCounters::read(&settings.tx_interface);
        let measurement = Measurement {
            receiver,
            sender: sender_final,
            elapsed: measurement_end.saturating_duration_since(measurement_start),
            ranges,
            rx_before,
            rx_after,
            tx_before,
            tx_after,
            latency: latency.finish(),
            perf,
            conditions,
        };

        // Teardown follows the kernel/object dependency chain: detach first,
        // then close the program, map, resource, and finally the borrowed
        // page-aligned UMEM. Every explicit close is attempted even if an
        // earlier one reports an error.
        let mut cleanup_error = None;
        if let Err(error) = attachment.detach() {
            cleanup_error = Some(format!("AF_XDP attachment detach failed: {error:?}"));
        }
        drop(attachment);
        if let Err(error) = program.close() {
            append_cleanup_error(
                &mut cleanup_error,
                format!("AF_XDP program close failed: {error:?}"),
            );
        }
        if let Err(error) = map.close() {
            append_cleanup_error(
                &mut cleanup_error,
                format!("AF_XDP map close failed: {error:?}"),
            );
        }
        if let Err(error) = resource.close() {
            append_cleanup_error(
                &mut cleanup_error,
                format!("AF_XDP resource close failed: {error:?}"),
            );
        }
        if let Err(error) = memory.close() {
            append_cleanup_error(
                &mut cleanup_error,
                format!("AF_XDP UMEM munmap failed: {error}"),
            );
        }
        if let Some(error) = cleanup_error {
            panic!("AF_XDP cleanup failed: {error}");
        }
        measurement
    }

    fn append_cleanup_error(slot: &mut Option<String>, message: String) {
        if let Some(existing) = slot {
            existing.push(';');
            existing.push(' ');
            existing.push_str(&message);
        } else {
            *slot = Some(message);
        }
    }

    fn drain_until_quiet(resource: &mut XdpResource<'_>, frame_size: usize) {
        let deadline = Instant::now() + QUIET_DRAIN_TIMEOUT;
        let mut empty_batches = 0_u8;
        while Instant::now() < deadline && empty_batches < 3 {
            let _ = resource
                .wait_for_rx(Duration::from_millis(1))
                .unwrap_or_else(|error| panic!("AF_XDP quiet-drain wait failed: {error:?}"));
            let received = receive_and_recycle(resource, frame_size, None);
            if received.packets == 0 {
                empty_batches += 1;
            } else {
                empty_batches = 0;
            }
        }
    }

    fn record_interval(
        ranges: &mut RateRanges,
        elapsed: Duration,
        receiver: ReceivedTotals,
        previous_receiver: ReceivedTotals,
        sender: SenderSnapshot,
        previous_sender: SenderSnapshot,
    ) {
        let receiver_packets = receiver
            .packets
            .checked_sub(previous_receiver.packets)
            .expect("receiver packet samples moved backwards");
        let receiver_bytes = receiver
            .bytes
            .checked_sub(previous_receiver.bytes)
            .expect("receiver byte samples moved backwards");
        let sender_attempted = sender
            .attempted
            .checked_sub(previous_sender.attempted)
            .expect("sender attempted samples moved backwards");
        let sender_sent = sender
            .sent
            .checked_sub(previous_sender.sent)
            .expect("sender sent samples moved backwards");
        ranges.receiver_pps.record(receiver_packets, elapsed);
        ranges.receiver_bps.record(receiver_bytes, elapsed);
        ranges
            .sender_attempted_pps
            .record(sender_attempted, elapsed);
        ranges.sender_sent_pps.record(sender_sent, elapsed);
    }

    fn receive_and_recycle(
        resource: &mut XdpResource<'_>,
        frame_size: usize,
        mut latency: Option<&mut LatencyCollector>,
    ) -> ReceivedTotals {
        // usize::MAX is intentional. The AF_XDP implementation clamps the
        // budget to descriptors currently available in the RX ring, so this
        // loop owns every available descriptor before finish() refills Fill.
        let mut batch = resource
            .receive(usize::MAX)
            .unwrap_or_else(|error| panic!("AF_XDP PacketIo::receive failed: {error:?}"));
        let mut totals = ReceivedTotals::default();
        let mut leased = 0_usize;
        while let Some(mut lease) = batch.next_packet() {
            leased += 1;
            let length = lease.bytes_mut().len();
            if let Some(collector) = latency.as_deref_mut() {
                collector.record_received(lease.bytes_mut());
            }
            totals.packets = totals
                .packets
                .checked_add(1)
                .expect("received packet counter overflowed");
            totals.bytes = totals
                .bytes
                .checked_add(u64::try_from(length).expect("packet length fits u64"))
                .expect("received byte counter overflowed");
            if length != frame_size {
                totals.unexpected_frame_size = totals
                    .unexpected_frame_size
                    .checked_add(1)
                    .expect("unexpected packet counter overflowed");
            }
            lease.recycle(DropReason::RouteMiss);
        }
        let completion = batch.finish();
        assert!(
            completion.invariants_hold(),
            "AF_XDP batch completion invariants failed: {completion:?}"
        );
        assert!(
            completion.error.is_none(),
            "AF_XDP batch completed with an error: {completion:?}"
        );
        assert_eq!(
            completion.tx_requested, 0,
            "throughput receiver must not transmit"
        );
        assert_eq!(
            completion.tx_accepted, 0,
            "throughput receiver must not transmit"
        );
        assert_eq!(
            completion.tx_rejected, 0,
            "throughput receiver must not transmit"
        );
        assert_eq!(
            completion.recycled, leased,
            "every available AF_XDP descriptor must be leased and recycled before finish"
        );
        totals
    }

    fn sender_loop(
        counters: Arc<SenderCounters>,
        socket: RawPacketSocket,
        destination: SockaddrLl,
        frame_size: usize,
        batch_size: usize,
    ) {
        let mut frames = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            frames.push(build_frame(frame_size));
        }
        let frame_len = u32::try_from(frame_size).expect("frame size fits mmsghdr::msg_len");
        let batch_len = u32::try_from(batch_size).expect("send batch size fits sendmmsg");
        let mut iovecs = Vec::with_capacity(batch_size);
        for frame in &mut frames {
            iovecs.push(Iovec {
                iov_base: frame.as_mut_ptr().cast::<c_void>(),
                iov_len: frame.len(),
            });
        }
        let iovecs_ptr = iovecs.as_mut_ptr();
        let mut messages = Vec::with_capacity(batch_size);
        for index in 0..batch_size {
            messages.push(Mmsghdr {
                msg_hdr: MsgHdr {
                    msg_name: (&destination as *const SockaddrLl)
                        .cast_mut()
                        .cast::<c_void>(),
                    msg_namelen: u32::try_from(size_of::<SockaddrLl>())
                        .expect("sockaddr_ll fits socklen_t"),
                    msg_iov: iovecs_ptr.wrapping_add(index),
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            });
        }

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

            let measured = phase == PHASE_MEASURE;
            for frame in &mut frames {
                if let Err(error) = stamp_frame_with_last(frame, &mut last_timestamp) {
                    if measured {
                        counters.timestamp_failures.fetch_add(1, Ordering::Relaxed);
                        let error_code = if error.code() == 0 { -1 } else { error.code() };
                        let _ = counters.timestamp_failure_errno.compare_exchange(
                            0,
                            error_code,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        );
                    }
                    clear_frame_timestamp(frame);
                }
            }
            if measured {
                counters.attempted.fetch_add(
                    u64::try_from(batch_size).expect("batch size fits u64"),
                    Ordering::Relaxed,
                );
            }
            // SAFETY: `socket` is owned only by this sender thread. `messages`
            // and `iovecs` are stable, initialized #[repr(C)] arrays of the
            // lengths passed to sendmmsg; every iovec points to a live private
            // frame in `frames`, and every message name points to the live
            // `destination`. The nonblocking call may write only the
            // mmsghdr result fields within `messages`.
            let sent =
                unsafe { sendmmsg(socket.fd(), messages.as_mut_ptr(), batch_len, MSG_DONTWAIT) };
            if sent < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(EAGAIN) {
                    if measured {
                        counters.would_block.fetch_add(
                            u64::try_from(batch_size).expect("batch size fits u64"),
                            Ordering::Relaxed,
                        );
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
            let sent = usize::try_from(sent).expect("successful sendmmsg count is nonnegative");
            if sent > batch_size {
                counters.fatal_errno.store(-3, Ordering::Release);
                counters.phase.store(PHASE_FAILED, Ordering::Release);
                return;
            }
            if messages
                .iter()
                .take(sent)
                .any(|message| message.msg_len != frame_len)
            {
                counters.fatal_errno.store(-2, Ordering::Release);
                counters.phase.store(PHASE_FAILED, Ordering::Release);
                return;
            }
            if measured {
                counters.sent.fetch_add(
                    u64::try_from(sent).expect("sendmmsg count fits u64"),
                    Ordering::Relaxed,
                );
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
            *byte = (index as u8).wrapping_mul(13).wrapping_add(0x41);
        }
        frame
    }

    fn open_raw_socket(interface: &str) -> Result<RawPacketSocket, io::Error> {
        let if_index = interface_index(interface);
        // SAFETY: socket has no pointer arguments.
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
        // SAFETY: address is initialized and live for this bind call.
        let result = unsafe {
            bind(
                socket.fd,
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

    fn required_interface(primary: &str, fallback: &str, subject: &str) -> String {
        match env::var(primary) {
            Ok(value) if !value.is_empty() => value,
            Ok(_) => panic!("{primary} must not be empty for {subject}"),
            Err(env::VarError::NotPresent) => match env::var(fallback) {
                Ok(value) if !value.is_empty() => value,
                Ok(_) => panic!("{fallback} must not be empty for {subject}"),
                Err(env::VarError::NotPresent) => {
                    panic!("{primary} (or compatibility variable {fallback}) is required")
                }
                Err(env::VarError::NotUnicode(_)) => panic!("{fallback} is not valid UTF-8"),
            },
            Err(env::VarError::NotUnicode(_)) => panic!("{primary} is not valid UTF-8"),
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

    fn parse_usize(name: &str, default: usize) -> usize {
        usize::try_from(parse_u64(
            name,
            u64::try_from(default).expect("default usize fits u64"),
        ))
        .unwrap_or_else(|_| panic!("{name} does not fit usize"))
    }

    fn read_sysfs_counter(interface: &str, counter: &str) -> Option<u64> {
        let path = format!("/sys/class/net/{interface}/statistics/{counter}");
        fs::read_to_string(path).ok()?.trim().parse::<u64>().ok()
    }

    fn counter_delta(before: Option<u64>, after: Option<u64>) -> Option<u64> {
        before
            .zip(after)
            .and_then(|(before, after)| after.checked_sub(before))
    }

    fn sum_optional(first: Option<u64>, second: Option<u64>) -> Option<u64> {
        first
            .zip(second)
            .and_then(|(first, second)| first.checked_add(second))
    }

    fn optional_u64(value: Option<u64>) -> String {
        value.map_or_else(|| "unknown".to_owned(), |value| value.to_string())
    }

    fn total_rate(count: u64, elapsed: Duration) -> String {
        if elapsed.is_zero() {
            "unknown".to_owned()
        } else {
            format!("{:.3}", count as f64 / elapsed.as_secs_f64())
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

    fn kernel_version() -> String {
        fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map_or_else(|| "unknown".to_owned(), |value| shell_safe(value.trim()))
    }

    fn cpu_model() -> String {
        let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") else {
            return "unknown".to_owned();
        };
        for line in cpuinfo.lines() {
            if let Some(value) = line.strip_prefix("model name") {
                if let Some((_, model)) = value.split_once(':') {
                    return shell_safe(model.trim());
                }
            }
        }
        "unknown".to_owned()
    }

    fn nproc() -> String {
        std::thread::available_parallelism().map_or_else(
            |_| "unknown".to_owned(),
            |parallelism| parallelism.get().to_string(),
        )
    }

    struct RecordMetadata {
        kernel_version: String,
        cpu_model: String,
        nproc: String,
        perf_event_paranoid: String,
    }

    impl RecordMetadata {
        fn from_system() -> Self {
            Self {
                kernel_version: kernel_version(),
                cpu_model: cpu_model(),
                nproc: nproc(),
                perf_event_paranoid: read_perf_event_paranoid(),
            }
        }
    }

    fn build_record(
        settings: &Settings,
        measurement: &Measurement,
        metadata: &RecordMetadata,
    ) -> String {
        let rx_dropped = counter_delta(
            measurement.rx_before.rx_dropped,
            measurement.rx_after.rx_dropped,
        );
        let rx_missed = counter_delta(
            measurement.rx_before.rx_missed_errors,
            measurement.rx_after.rx_missed_errors,
        );
        let rx_tx_dropped = counter_delta(
            measurement.rx_before.tx_dropped,
            measurement.rx_after.tx_dropped,
        );
        let sender_tx_dropped = counter_delta(
            measurement.tx_before.tx_dropped,
            measurement.tx_after.tx_dropped,
        );
        let receive_drop_packets = sum_optional(rx_dropped, rx_missed);
        let receive_drop_observed =
            rx_dropped.is_some_and(|value| value > 0) || rx_missed.is_some_and(|value| value > 0);
        let packet_gap =
            i128::from(measurement.sender.sent) - i128::from(measurement.receiver.packets);
        let sender_not_sent = measurement
            .sender
            .attempted
            .checked_sub(measurement.sender.sent);
        let sender_limited = if measurement.sender.would_block > 0
            || sender_not_sent.is_some_and(|value| value > 0)
        {
            "possible"
        } else {
            "not_observed"
        };
        let sender_receiver_pps_ratio = if measurement.receiver.packets == 0 {
            None
        } else {
            Some(measurement.sender.sent as f64 / measurement.receiver.packets as f64)
        };
        let receiver_saturation = match sender_receiver_pps_ratio {
            None => "unknown",
            Some(ratio) if ratio > 1.1 => "observed_by_pps_ratio",
            Some(_) if receive_drop_observed => "observed_by_receive_drop",
            Some(_) => "not_observed",
        };
        let sender_receiver_comparison =
            if measurement.sender.sent == 0 || measurement.receiver.packets == 0 {
                "unknown"
            } else if measurement.sender.sent >= measurement.receiver.packets {
                "sender_at_or_above_receiver"
            } else {
                "receiver_above_sender_boundary_or_noise"
            };
        let unmeasured = unmeasured_fields(
            &measurement.latency,
            measurement.perf,
            measurement.receiver.packets,
            &measurement.conditions,
        );
        let primary_record = format!(
            "measurement_kind=veth_functional hardware_acceptance=false kernel_version={} cpu_model={} nproc={} interface_type=veth rx_interface={} tx_interface={} backend=af_xdp xdp_mode=skb umem_allocation=anonymous_mmap_page_aligned frame_size={} warmup_ms={} duration_ms_requested={} measurement_duration_ms={:.3} window_ms={} window_count={} sender_threads={} sender_socket_count={} sender_socket_sharing=none sender_batch_size={} sender_sendmmsg=enabled receiver_packets={} receiver_bytes={} receiver_packets_per_sec={} receiver_bytes_per_sec={} receiver_pps_min={} receiver_pps_max={} receiver_bytes_per_sec_min={} receiver_bytes_per_sec_max={} sender_attempted_packets={} sender_sent_packets={} sender_would_block_packets={} sender_not_sent_packets={} sender_attempted_pps={} sender_packets_per_sec={} sender_attempted_pps_min={} sender_attempted_pps_max={} sender_pps_min={} sender_pps_max={} sender_limited={} sender_receiver_comparison={} sender_receiver_pps_ratio={} receiver_saturation={} packet_gap={} drop_count={} receive_drop_packets={} kernel_rx_dropped_delta={} kernel_rx_missed_errors_delta={} kernel_tx_dropped_delta={} sender_interface_kernel_tx_dropped_delta={} unexpected_frame_size_packets={} note=values_do_not_represent_physical_NIC_performance unmeasured={}",
            metadata.kernel_version.as_str(),
            metadata.cpu_model.as_str(),
            metadata.nproc.as_str(),
            shell_safe(&settings.rx_interface),
            shell_safe(&settings.tx_interface),
            settings.frame_size,
            settings.warmup.as_millis(),
            settings.duration.as_millis(),
            measurement.elapsed.as_secs_f64() * 1_000.0,
            settings.window.as_millis(),
            measurement.ranges.receiver_pps.samples,
            settings.sender_threads,
            settings.sender_threads,
            settings.send_batch_size,
            measurement.receiver.packets,
            measurement.receiver.bytes,
            total_rate(measurement.receiver.packets, measurement.elapsed),
            total_rate(measurement.receiver.bytes, measurement.elapsed),
            measurement.ranges.receiver_pps.value(true),
            measurement.ranges.receiver_pps.value(false),
            measurement.ranges.receiver_bps.value(true),
            measurement.ranges.receiver_bps.value(false),
            measurement.sender.attempted,
            measurement.sender.sent,
            measurement.sender.would_block,
            optional_u64(sender_not_sent),
            total_rate(measurement.sender.attempted, measurement.elapsed),
            total_rate(measurement.sender.sent, measurement.elapsed),
            measurement.ranges.sender_attempted_pps.value(true),
            measurement.ranges.sender_attempted_pps.value(false),
            measurement.ranges.sender_sent_pps.value(true),
            measurement.ranges.sender_sent_pps.value(false),
            sender_limited,
            sender_receiver_comparison,
            sender_receiver_pps_ratio.map_or_else(
                || "unknown".to_owned(),
                |ratio| format!("{ratio:.6}"),
            ),
            receiver_saturation,
            packet_gap,
            optional_u64(rx_dropped),
            optional_u64(receive_drop_packets),
            optional_u64(rx_dropped),
            optional_u64(rx_missed),
            optional_u64(rx_tx_dropped),
            optional_u64(sender_tx_dropped),
            measurement.receiver.unexpected_frame_size,
            unmeasured,
        );
        let detail_record = format!(
            "latency_clock={} latency_clock_domain={} latency_clock_same_host=true latency_one_way=true latency_percentile_method={} latency_samples={} latency_min_samples_p50=2 latency_min_samples_p90=10 latency_min_samples_p99=100 latency_min_samples_p99_9=1000 latency_p50_ns={} latency_p90_ns={} latency_p99_ns={} latency_p99_9_ns={} latency_min_ns={} latency_max_ns={} latency_unmatched_packets={} latency_missing_timestamps={} latency_backwards_timestamps={} latency_clock_errors={} latency_clock_error_errno={} latency_timestamp_write_failures={} latency_timestamp_write_errno={} perf_event_open_syscall={} perf_event_attr_size={} perf_event_scope=receiving_thread perf_event_paranoid={} perf_cycles_count={} perf_cycles_status={} cycles_per_packet={} perf_cache_references_count={} perf_cache_references_status={} perf_cache_misses_count={} perf_cache_misses_status={} cache_miss_rate_percent={} cpu_affinity_requested={} cpu_affinity_selection={} cpu_affinity_set={} cpu_affinity_get={} cpu_affinity_verified={} cpu_affinity_current_cpu={} cpu_affinity_observed_mask={} cpu_affinity_set_errno={} cpu_affinity_get_errno={} numa_node={} numa_node_status={} irq_count={} irq_count_status={} irq_affinity={} irq_affinity_status={} rss_queue_count={} rss_queue_count_status={}",
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
            measurement.sender.timestamp_failures,
            format_optional_i32(measurement.sender.timestamp_failure_errno),
            PerfEventSet::syscall_number(),
            PerfEventSet::attr_size(),
            metadata.perf_event_paranoid.as_str(),
            measurement.perf.cycles.value(),
            measurement.perf.cycles.status(),
            format_cycles_per_packet(measurement.perf, measurement.receiver.packets),
            measurement.perf.cache_references.value(),
            measurement.perf.cache_references.status(),
            measurement.perf.cache_misses.value(),
            measurement.perf.cache_misses.status(),
            format_cache_miss_rate(measurement.perf),
            measurement.conditions.affinity.selected_cpu,
            measurement.conditions.affinity.selection_source,
            if measurement.conditions.affinity.set_ok {
                "verified"
            } else {
                "failed"
            },
            if measurement.conditions.affinity.get_ok {
                "verified"
            } else {
                "failed"
            },
            measurement.conditions.affinity.verified,
            format_optional_usize(measurement.conditions.affinity.current_cpu),
            measurement.conditions.affinity.observed_mask.as_str(),
            format_optional_i32(measurement.conditions.affinity.set_errno),
            format_optional_i32(measurement.conditions.affinity.get_errno),
            measurement.conditions.numa_node.value.as_str(),
            measurement.conditions.numa_node.status(),
            measurement.conditions.irq_count.value.as_str(),
            measurement.conditions.irq_count.status(),
            measurement.conditions.irq_affinity.value.as_str(),
            measurement.conditions.irq_affinity.status(),
            measurement.conditions.rss_queue_count.value.as_str(),
            measurement.conditions.rss_queue_count.status(),
        );
        format!("{primary_record} {detail_record}")
    }

    fn print_measurement(settings: &Settings, measurement: Measurement) {
        if measurement.sender.timestamp_failures > 0 {
            eprintln!(
                "MEASUREMENT_WARNING component=latency stage=sender_timestamp failures={} errno={}",
                measurement.sender.timestamp_failures,
                format_optional_i32(measurement.sender.timestamp_failure_errno),
            );
        }
        if measurement.latency.clock_errors > 0 {
            eprintln!(
                "MEASUREMENT_WARNING component=latency stage=receiver_clock_gettime failures={} errno={}",
                measurement.latency.clock_errors,
                format_optional_i32(measurement.latency.last_clock_error),
            );
        }
        if !measurement.latency.percentiles_complete() {
            eprintln!(
                "MEASUREMENT_WARNING component=latency status=insufficient_samples samples={} required_p99_9=1000",
                measurement.latency.samples,
            );
        }
        let metadata = RecordMetadata::from_system();
        let record = build_record(settings, &measurement, &metadata);
        assert_machine_readable_record_line(&record);
        println!("{record}");
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn test_settings() -> Settings {
            Settings {
                rx_interface: "veth-rx".to_owned(),
                tx_interface: "veth-tx".to_owned(),
                frame_size: 60,
                duration: Duration::from_millis(250),
                warmup: Duration::from_millis(100),
                window: Duration::from_millis(50),
                sender_threads: 1,
                send_batch_size: 1,
            }
        }

        fn measured(value: &str) -> Observation {
            Observation {
                value: value.to_owned(),
                measured: true,
                not_applicable: false,
            }
        }

        fn not_applicable() -> Observation {
            Observation {
                value: "not_applicable".to_owned(),
                measured: false,
                not_applicable: true,
            }
        }

        fn test_conditions() -> SystemConditions {
            SystemConditions {
                affinity: AffinityReport {
                    selected_cpu: 0,
                    selection_source: "test",
                    set_ok: true,
                    get_ok: true,
                    verified: true,
                    current_cpu: Some(0),
                    observed_mask: "0".to_owned(),
                    set_errno: None,
                    get_errno: None,
                },
                numa_node: measured("0"),
                irq_count: not_applicable(),
                irq_affinity: not_applicable(),
                irq_affinity_verified: false,
                irq_affinity_verification: "irq_affinity_data_not_measured".to_owned(),
                rss_queue_count: not_applicable(),
                rss_queue_verified: false,
                rss_queue_verification: "rss_rx_queue_count_not_measured".to_owned(),
                rss_indirection_table_size: None,
            }
        }

        fn test_measurement() -> Measurement {
            Measurement {
                receiver: ReceivedTotals {
                    packets: 3,
                    bytes: 180,
                    unexpected_frame_size: 0,
                },
                sender: SenderSnapshot {
                    attempted: 4,
                    sent: 3,
                    would_block: 0,
                    timestamp_failures: 0,
                    timestamp_failure_errno: None,
                },
                elapsed: Duration::from_millis(250),
                ranges: RateRanges {
                    receiver_pps: RateRange {
                        min: 10.0,
                        max: 20.0,
                        samples: 1,
                    },
                    receiver_bps: RateRange {
                        min: 600.0,
                        max: 1_200.0,
                        samples: 1,
                    },
                    sender_attempted_pps: RateRange {
                        min: 20.0,
                        max: 20.0,
                        samples: 1,
                    },
                    sender_sent_pps: RateRange {
                        min: 12.0,
                        max: 12.0,
                        samples: 1,
                    },
                },
                rx_before: KernelCounters {
                    rx_dropped: Some(10),
                    rx_missed_errors: Some(2),
                    tx_dropped: Some(4),
                },
                rx_after: KernelCounters {
                    rx_dropped: Some(11),
                    rx_missed_errors: Some(3),
                    tx_dropped: Some(4),
                },
                tx_before: KernelCounters {
                    rx_dropped: Some(5),
                    rx_missed_errors: Some(1),
                    tx_dropped: Some(7),
                },
                tx_after: KernelCounters {
                    rx_dropped: Some(5),
                    rx_missed_errors: Some(1),
                    tx_dropped: Some(8),
                },
                latency: LatencyCollector::new().finish(),
                perf: PerfReport::not_measured(),
                conditions: test_conditions(),
            }
        }

        #[test]
        fn build_record_is_machine_parseable() {
            let metadata = RecordMetadata {
                kernel_version: "6.8.0-test".to_owned(),
                cpu_model: "test_cpu".to_owned(),
                nproc: "1".to_owned(),
                perf_event_paranoid: "3".to_owned(),
            };
            let record = build_record(&test_settings(), &test_measurement(), &metadata);
            assert_machine_readable_record_line(&record);
            assert!(record.contains("backend=af_xdp"));
        }
    }

    fn panic_raw_socket_error(operation: &str, error: io::Error) -> ! {
        if matches!(error.raw_os_error(), Some(EPERM | EACCES)) {
            panic!(
                "RUSTER_PRIVILEGED_E2E=1 but CAP_NET_RAW/root is unavailable ({operation}: {error})"
            );
        }
        panic!("AF_PACKET {operation} failed: {error}");
    }

    unsafe extern "C" {
        fn socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int;
        fn bind(socket: c_int, address: *const c_void, address_len: u32) -> c_int;
        fn sendmmsg(
            socket: c_int,
            messages: *mut Mmsghdr,
            message_count: u32,
            flags: c_int,
        ) -> c_int;
        fn close(fd: c_int) -> c_int;
        fn if_nametoindex(interface: *const c_char) -> u32;
        fn sysconf(name: c_int) -> isize;
        fn geteuid() -> u32;
        fn mmap(
            address: *mut c_void,
            length: usize,
            protection: c_int,
            flags: c_int,
            fd: c_int,
            offset: isize,
        ) -> *mut c_void;
        fn munmap(address: *mut c_void, length: usize) -> c_int;
    }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
#[test]
#[ignore = "requires Linux x86_64 and an explicit root veth throughput run"]
fn veth_throughput_af_xdp() {
    panic!(
        "AF_XDP veth throughput is unsupported: native measurement requires Linux x86_64 with 64-bit pointers"
    );
}
