//! Privileged live differential helpers for the native backends.
//!
//! The helper deliberately contains no raw Linux FFI.  The test target owns
//! the raw AF_PACKET sender, while this module opens the real AF_PACKET and
//! AF_XDP packet-I/O objects through their public APIs and runs the same core
//! forwarding operation against both.  Keeping the sender outside this crate
//! preserves `forbid(unsafe_code)` on the reusable conformance library.

#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]

use std::{
    cell::{Cell, RefCell},
    fmt::Debug,
    time::{Duration, Instant},
};

use ruster_core::{
    forward_batch, BatchCompletion, BatchReport, DropReason, ForwardingSnapshot, IfId, PacketBatch,
    PacketIo, PacketLease, PacketSlot, PublicationQuiescenceBackend,
    PublicationQuiescenceDisposition, SlotCompletion, TraceEvent, TraceSink,
};
use ruster_io_afpacket::{
    AfPacketError, AfPacketIo, AfPacketPlatform, PortConfig, RingGeometry, ValidatedConfig,
};
use ruster_io_xdp_native::{
    abi::{XDP_COPY, XDP_USE_NEED_WAKEUP},
    ensure_supported, PageAlignedUmem, RingConfig, UmemConfig, ValidatedBindFlags, XdpAttachMode,
    XdpIoError, XdpResourceBuilder, XdpSetupStage, XskMap,
};

use crate::differential::{
    DifferentialCase, ErrorCategory, ForwardingResult, NormalizedObservation,
};

const MAX_FRAME_LEN: usize = 1_514;
const AF_PACKET_RX_BLOCK_RETIRE_TIMEOUT_MS: u32 = 20;
const AF_PACKET_BLOCK_SIZE: u32 = 16_384;
const AF_PACKET_FRAME_SIZE: u32 = 4_096;
const AF_PACKET_RX_FRAME_COUNT: u32 = AF_PACKET_BLOCK_SIZE / AF_PACKET_FRAME_SIZE;
const XDP_FRAME_COUNT: u32 = 8;
const XDP_FRAME_SIZE: u32 = 2_048;
const XDP_RX_FRAMES: u32 = 4;
const XDP_GENERATED_FRAMES: u32 = XDP_FRAME_COUNT - XDP_RX_FRAMES;
const XDP_RING_ENTRIES: u32 = 4;
const MAX_LIVE_SLOTS: usize = 4;
const DRAIN_BUDGET: usize = MAX_LIVE_SLOTS;

/// Input-side capability used by a live test to inject the exact same bytes
/// into each native backend.
pub trait LiveFrameSender {
    /// Sends one complete Ethernet frame through the configured peer link.
    fn send(&mut self, peer_if_index: u32, frame: &[u8]) -> Result<(), String>;
}

/// Runtime parameters for one privileged native differential run.
#[derive(Clone, Copy, Debug)]
pub struct LiveBackendConfig {
    /// Linux ifindex bound by both native backends.
    pub target_if_index: u32,
    /// Linux ifindex used by the test sender to reach the target link.
    pub peer_if_index: u32,
    /// Core-facing interface identifier shared by the three runs.
    pub target_interface: IfId,
    /// System page size used by the TPACKET_V3 geometry validator.
    pub page_size: usize,
    /// Hardware queue selected for the AF_XDP resource and XSKMAP.
    pub queue_id: u32,
    /// Maximum wait for the packet injected for one case.
    pub timeout: Duration,
}

/// Error returned when a privileged native lane cannot produce an observation.
#[derive(Debug)]
pub enum LiveDifferentialError {
    InvalidCase(&'static str),
    InputCount {
        expected: usize,
        observed: usize,
    },
    InputIngress {
        expected: IfId,
        observed: IfId,
    },
    InputLength {
        expected: usize,
        observed: usize,
    },
    InputByte {
        offset: usize,
        expected: u8,
        observed: u8,
    },
    TraceCount {
        expected: usize,
        observed: usize,
    },
    TraceIngress {
        expected: IfId,
        observed: IfId,
    },
    TraceEgress {
        expected: IfId,
        observed: IfId,
    },
    Sender(String),
    AfPacketPlatform(String),
    AfPacketSetup(String),
    AfPacketWait(String),
    AfPacketReceive(String),
    AfPacketCleanup(String),
    XdpPlatform(String),
    XdpSetup(String),
    XdpMap(String),
    XdpProgram(String),
    XdpAttach(String),
    XdpWait(String),
    XdpReceive(String),
    XdpCleanup(String),
    ProbeCompletion(String),
    Timeout(&'static str),
}

/// Runs one input through the real AF_PACKET and AF_XDP packet paths.
///
/// The caller runs the same [`DifferentialCase`] through the real `SimIo`
/// before or after calling this function.  Native setup is intentionally
/// recreated for each case so an accepted TX descriptor or a kernel-owned RX
/// packet cannot become hidden state in the next comparison.  The test lane
/// is small and privileged-only; this cold-path cost is preferable to
/// weakening ownership cleanup or exposing backend internals.
pub fn run_native_live_case<S: LiveFrameSender>(
    sender: &mut S,
    config: LiveBackendConfig,
    case: &DifferentialCase,
    snapshot: &ForwardingSnapshot<'_>,
) -> Result<(NormalizedObservation, NormalizedObservation), LiveDifferentialError> {
    validate_case(config, case)?;
    let af_packet = run_af_packet_case(sender, config, case, snapshot)?;
    let xdp = run_xdp_case(sender, config, case, snapshot)?;
    Ok((af_packet, xdp))
}

fn validate_case(
    config: LiveBackendConfig,
    case: &DifferentialCase,
) -> Result<(), LiveDifferentialError> {
    if case.ingress != config.target_interface.0 {
        return Err(LiveDifferentialError::InvalidCase(
            "live case ingress must equal the configured target interface",
        ));
    }
    if case.frame.len() < 60 || case.frame.len() > MAX_FRAME_LEN {
        return Err(LiveDifferentialError::InvalidCase(
            "live case frame must be a 60..=1514 byte Ethernet frame",
        ));
    }
    if case.rx_budget == 0 {
        return Err(LiveDifferentialError::InvalidCase(
            "live case RX budget must be nonzero",
        ));
    }
    if case.packet_count == 0 || case.packet_count > MAX_LIVE_SLOTS {
        return Err(LiveDifferentialError::InvalidCase(
            "live case packet count must fit the reviewed native ring",
        ));
    }
    if case.rx_budget > MAX_LIVE_SLOTS {
        return Err(LiveDifferentialError::InvalidCase(
            "live case RX budget must fit the reviewed native ring",
        ));
    }
    if !matches!(case.tx_capacity, 2 | 4) {
        return Err(LiveDifferentialError::InvalidCase(
            "live case TX capacity must be two or four native ring entries",
        ));
    }
    if config.target_if_index == 0 || config.peer_if_index == 0 {
        return Err(LiveDifferentialError::InvalidCase(
            "live target and peer ifindices must be nonzero",
        ));
    }
    if config.page_size == 0 || !config.page_size.is_power_of_two() {
        return Err(LiveDifferentialError::InvalidCase(
            "live TPACKET page size must be a nonzero power of two",
        ));
    }
    Ok(())
}

fn run_af_packet_case<S: LiveFrameSender>(
    sender: &mut S,
    config: LiveBackendConfig,
    case: &DifferentialCase,
    snapshot: &ForwardingSnapshot<'_>,
) -> Result<NormalizedObservation, LiveDifferentialError> {
    AfPacketPlatform::ensure_supported()
        .map_err(|error| LiveDifferentialError::AfPacketPlatform(format!("{error:?}")))?;

    let (rx, tx) = af_packet_geometry(case);
    let validated = ValidatedConfig::new(
        &[PortConfig {
            interface: config.target_interface,
            if_index: config.target_if_index,
            rx,
            tx,
        }],
        config.page_size,
        MAX_FRAME_LEN,
    )
    .map_err(|error| LiveDifferentialError::AfPacketSetup(format!("{error:?}")))?;
    let mut io = AfPacketIo::open(validated)
        .map_err(|error| LiveDifferentialError::AfPacketSetup(format!("{error:?}")))?;

    // A fresh socket can still see traffic queued before setup.  Drain only
    // complete backend batches before injecting this case; accepting such a
    // packet as the first result would make the comparison non-differential.
    drain_af_packet_rx(&mut io, config.timeout)?;

    // PacketLease is intentionally concrete in the public core API, so a
    // generic batch wrapper cannot inspect a lease and then hand it back to
    // `forward_batch`.  A one-packet probe gives this live lane an exact
    // ingress/length/byte check immediately before the case while preserving
    // the backend's ownership protocol: the probe lease is always recycled
    // and its batch is finished before the case packets are injected.
    sender
        .send(config.peer_if_index, &case.frame)
        .map_err(LiveDifferentialError::Sender)?;
    wait_for_af_packet(&mut io, config.timeout)?;
    let probe = io
        .receive(1)
        .map_err(|error| LiveDifferentialError::AfPacketReceive(format!("{error:?}")))?;
    validate_probe_batch(probe, IfId(case.ingress), &case.frame)?;
    drain_af_packet_rx(&mut io, config.timeout)?;

    let expected_packets = case.packet_count.min(case.rx_budget);
    // This is sampled immediately before `receive`, when no batch or lease
    // can be live.  It therefore has the same meaning as the model lane's
    // pre-batch disposition.
    let active_disposition = io.current_io_disposition();
    let validation = InputValidation::default();
    let mut trace = RecordingTrace::default();
    let mut observation = None;
    let mut received = 0;
    let deadline = Instant::now() + config.timeout;

    for _ in 0..case.packet_count {
        sender
            .send(config.peer_if_index, &case.frame)
            .map_err(LiveDifferentialError::Sender)?;
    }

    // TPACKET_V3 readiness only guarantees that a USER block exists.  The
    // block may contain a prefix of the sent frames, so keep receiving blocks
    // until the case budget has been observed instead of treating one poll
    // edge as an all-packets barrier.
    while received < expected_packets {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(LiveDifferentialError::Timeout("AF_PACKET RX batch"));
        }
        wait_for_af_packet(&mut io, remaining)?;
        let batch = io
            .receive(case.packet_count)
            .map_err(|error| LiveDifferentialError::AfPacketReceive(format!("{error:?}")))?;
        let trace_start = trace.events.len();
        let report = forward_batch(
            ExactBatch::new(batch, IfId(case.ingress), &case.frame, &validation)
                .with_rx_limit(expected_packets - received),
            snapshot,
            &mut trace,
        );
        let disposition = io.current_io_disposition();
        let error_category = report
            .completion
            .error
            .as_ref()
            .map_or(ErrorCategory::None, af_packet_error_category);
        let batch_observation = observation_from_trace(
            report,
            &trace.events[trace_start..],
            active_disposition,
            disposition,
            error_category,
        );
        received += batch_observation.received;
        merge_observation(&mut observation, batch_observation);
    }

    let input_result = validation.finish(expected_packets);
    let trace_result = validate_trace(
        &trace.events,
        expected_packets,
        IfId(case.ingress),
        config.target_interface,
    );
    let observation = observation.expect("a positive live RX budget yields an observation");

    // The public AF_PACKET API intentionally exposes no TX mapping accessor,
    // so a safe live test cannot inspect the copied egress bytes.  The
    // terminal trace still checks one decision per exact input and its egress.
    drain_af_packet_rx(&mut io, config.timeout)?;
    drain_af_packet_tx(&mut io, config.timeout)?;
    if observation.received != expected_packets {
        return Err(LiveDifferentialError::InputCount {
            expected: expected_packets,
            observed: observation.received,
        });
    }
    input_result?;
    trace_result?;
    Ok(observation)
}

fn af_packet_geometry(case: &DifferentialCase) -> (RingGeometry, RingGeometry) {
    // Keep all four generated packets in one USER block.  AfPacketIo exposes
    // one block per batch, so a multi-block geometry would make an otherwise
    // valid four-packet case look short before the explicit leftover drain.
    let rx_block_count = 1;
    let rx_frame_count = AF_PACKET_RX_FRAME_COUNT;
    let rx = RingGeometry {
        block_size: AF_PACKET_BLOCK_SIZE,
        block_count: rx_block_count,
        frame_size: AF_PACKET_FRAME_SIZE,
        frame_count: rx_frame_count,
        retire_timeout_ms: AF_PACKET_RX_BLOCK_RETIRE_TIMEOUT_MS,
        private_size: 0,
        feature_flags: 0,
    };
    // TX has one 16 KiB frame per block, allowing the case's capacity of two
    // or four to become a real kernel-facing admission limit.  The geometry
    // is deliberately a power-of-two-sized profile shared with the XDP TX
    // ring capacity selected by the same case.
    let tx_frame_count = u32::try_from(case.tx_capacity).expect("live slots fit");
    let tx = RingGeometry {
        block_size: AF_PACKET_BLOCK_SIZE,
        block_count: tx_frame_count,
        frame_size: AF_PACKET_BLOCK_SIZE,
        frame_count: tx_frame_count,
        retire_timeout_ms: 0,
        private_size: 0,
        feature_flags: 0,
    };
    (rx, tx)
}

fn wait_for_af_packet(io: &mut AfPacketIo, timeout: Duration) -> Result<(), LiveDifferentialError> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(LiveDifferentialError::Timeout("AF_PACKET"));
        }
        let slice = remaining.min(Duration::from_millis(100));
        if io
            .wait_for_rx(slice)
            .map_err(|error| LiveDifferentialError::AfPacketWait(format!("{error:?}")))?
        {
            return Ok(());
        }
    }
}

fn drain_af_packet_rx(
    io: &mut AfPacketIo,
    timeout: Duration,
) -> Result<usize, LiveDifferentialError> {
    let deadline = Instant::now() + timeout;
    let mut drained = 0;
    loop {
        if !io
            .wait_for_rx(Duration::ZERO)
            .map_err(|error| LiveDifferentialError::AfPacketCleanup(format!("{error:?}")))?
        {
            return Ok(drained);
        }
        if Instant::now() >= deadline {
            return Err(LiveDifferentialError::Timeout("AF_PACKET RX drain"));
        }
        let mut batch = io
            .receive(DRAIN_BUDGET)
            .map_err(|error| LiveDifferentialError::AfPacketCleanup(format!("{error:?}")))?;
        while let Some(packet) = batch.next_packet() {
            packet.recycle(DropReason::EthernetHeaderTruncated);
            drained += 1;
        }
        let completion = batch.finish();
        if let Some(error) = completion.error {
            return Err(LiveDifferentialError::AfPacketCleanup(format!(
                "RX drain completion returned an error: {error:?}"
            )));
        }
    }
}

fn drain_af_packet_tx(io: &mut AfPacketIo, timeout: Duration) -> Result<(), LiveDifferentialError> {
    let deadline = Instant::now() + timeout;
    loop {
        let completion = io
            .receive(0)
            .map_err(|error| LiveDifferentialError::AfPacketCleanup(format!("{error:?}")))?
            .finish();
        if let Some(error) = completion.error {
            return Err(LiveDifferentialError::AfPacketCleanup(format!(
                "completion scan returned an error: {error:?}"
            )));
        }
        match io.check_publication_quiescence() {
            Ok(()) => return Ok(()),
            Err(_error) if Instant::now() < deadline => std::thread::yield_now(),
            Err(error) => {
                return Err(LiveDifferentialError::AfPacketCleanup(format!(
                    "TX completion did not quiesce: {error:?}"
                )))
            }
        }
    }
}

fn drain_xdp_rx(
    resource: &mut ruster_io_xdp_native::XdpResource<'_>,
    timeout: Duration,
) -> Result<usize, LiveDifferentialError> {
    let deadline = Instant::now() + timeout;
    let mut drained = 0;
    loop {
        if !resource
            .wait_for_rx(Duration::ZERO)
            .map_err(|error| LiveDifferentialError::XdpCleanup(format!("{error:?}")))?
        {
            return Ok(drained);
        }
        if Instant::now() >= deadline {
            return Err(LiveDifferentialError::Timeout("AF_XDP RX drain"));
        }
        let mut batch = resource
            .receive(DRAIN_BUDGET)
            .map_err(|error| LiveDifferentialError::XdpCleanup(format!("{error:?}")))?;
        let before = drained;
        while let Some(packet) = batch.next_packet() {
            packet.recycle(DropReason::EthernetHeaderTruncated);
            drained += 1;
        }
        let completion = batch.finish();
        if let Some(error) = completion.error {
            return Err(LiveDifferentialError::XdpCleanup(format!(
                "RX drain completion returned an error: {error:?}"
            )));
        }
        // A readiness edge can race with the consumer cursor.  Do not spin
        // forever on that edge; the deadline still gives the kernel a bounded
        // opportunity to make the descriptor visible.
        if drained == before {
            std::thread::yield_now();
        }
    }
}

fn run_xdp_case<S: LiveFrameSender>(
    sender: &mut S,
    config: LiveBackendConfig,
    case: &DifferentialCase,
    snapshot: &ForwardingSnapshot<'_>,
) -> Result<NormalizedObservation, LiveDifferentialError> {
    ensure_supported().map_err(|error| LiveDifferentialError::XdpPlatform(format!("{error:?}")))?;

    let umem = UmemConfig::new(
        XDP_FRAME_COUNT,
        XDP_FRAME_SIZE,
        0,
        XDP_RX_FRAMES,
        XDP_GENERATED_FRAMES,
        0,
    )
    .map_err(|error| LiveDifferentialError::XdpSetup(format!("{error:?}")))?;
    let rings = RingConfig::new(
        XDP_RING_ENTRIES,
        XDP_RING_ENTRIES,
        u32::try_from(case.tx_capacity).expect("live TX ring size fits u32"),
        XDP_RING_ENTRIES,
    )
    .map_err(|error| LiveDifferentialError::XdpSetup(format!("{error:?}")))?;
    let bind_flags = ValidatedBindFlags::new(XDP_USE_NEED_WAKEUP | XDP_COPY)
        .map_err(|error| LiveDifferentialError::XdpSetup(format!("{error:?}")))?;
    let mut memory = PageAlignedUmem::for_umem(umem)
        .map_err(|error| LiveDifferentialError::XdpSetup(format!("{error:?}")))?;
    let mut resource =
        XdpResourceBuilder::new(umem, rings, config.target_if_index, config.queue_id)
            .map_err(|error| LiveDifferentialError::XdpSetup(format!("{error:?}")))?
            .with_interface_id(config.target_interface)
            .with_bind_flags(bind_flags)
            .build(memory.as_mut_slice())
            .map_err(|error| LiveDifferentialError::XdpSetup(format!("{error:?}")))?;

    let map_entries = config
        .queue_id
        .checked_add(1)
        .ok_or(LiveDifferentialError::InvalidCase(
            "AF_XDP queue id overflows XSKMAP size",
        ))?;
    let map = XskMap::new(map_entries)
        .map_err(|error| LiveDifferentialError::XdpMap(format!("{error:?}")))?;
    map.register(&resource)
        .map_err(|error| LiveDifferentialError::XdpMap(format!("{error:?}")))?;
    let program = map
        .load_redirect_program()
        .map_err(|error| LiveDifferentialError::XdpProgram(format!("{error:?}")))?;
    let mut attachment = program
        .attach_with_mode(config.target_if_index, XdpAttachMode::Skb)
        .map_err(|error| LiveDifferentialError::XdpAttach(format!("{error:?}")))?;

    sender
        .send(config.peer_if_index, &case.frame)
        .map_err(LiveDifferentialError::Sender)?;
    wait_for_xdp(&mut resource, config.timeout)?;
    let probe = resource
        .receive(1)
        .map_err(|error| LiveDifferentialError::XdpReceive(format!("{error:?}")))?;
    validate_probe_batch(probe, IfId(case.ingress), &case.frame)?;
    drain_xdp_rx(&mut resource, config.timeout)?;

    let expected_packets = case.packet_count.min(case.rx_budget);
    // Sample the state at the same pre-batch point as AF_PACKET and SimIo.
    let active_disposition = resource.current_io_disposition();
    let validation = InputValidation::default();
    let mut trace = RecordingTrace::default();
    let mut observation = None;
    let mut received = 0;
    let deadline = Instant::now() + config.timeout;

    for _ in 0..case.packet_count {
        sender
            .send(config.peer_if_index, &case.frame)
            .map_err(LiveDifferentialError::Sender)?;
    }

    // AF_XDP readiness is an edge/availability signal, not a packet-count
    // barrier.  A single receive may observe only the descriptors currently
    // published by the kernel, so retain the same case-level budget while
    // consuming subsequent ready batches until all expected slots arrive.
    while received < expected_packets {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(LiveDifferentialError::Timeout("AF_XDP RX batch"));
        }
        wait_for_xdp(&mut resource, remaining)?;
        let batch = resource
            .receive(case.packet_count)
            .map_err(|error| LiveDifferentialError::XdpReceive(format!("{error:?}")))?;
        let trace_start = trace.events.len();
        let report = forward_batch(
            ExactBatch::new(batch, IfId(case.ingress), &case.frame, &validation)
                .with_rx_limit(expected_packets - received),
            snapshot,
            &mut trace,
        );
        let disposition = resource.current_io_disposition();
        let error_category = report
            .completion
            .error
            .as_ref()
            .map_or(ErrorCategory::None, xdp_error_category);
        let batch_observation = observation_from_trace(
            report,
            &trace.events[trace_start..],
            active_disposition,
            disposition,
            error_category,
        );
        received += batch_observation.received;
        merge_observation(&mut observation, batch_observation);
    }

    let input_result = validation.finish(expected_packets);
    let trace_result = validate_trace(
        &trace.events,
        expected_packets,
        IfId(case.ingress),
        config.target_interface,
    );
    let observation = observation.expect("a positive live RX budget yields an observation");

    // `receive(budget)` deliberately exposes only the requested prefix.  RX
    // descriptors left in the ring must be completed before the resource is
    // allowed to enter the TX completion/teardown path.
    drain_xdp_rx(&mut resource, config.timeout)?;
    drain_xdp_tx(&mut resource, config.timeout)?;

    if observation.received != expected_packets {
        return Err(LiveDifferentialError::InputCount {
            expected: expected_packets,
            observed: observation.received,
        });
    }
    input_result?;
    trace_result?;

    attachment
        .detach()
        .map_err(|error| LiveDifferentialError::XdpAttach(format!("{error:?}")))?;
    drop(attachment);
    program
        .close()
        .map_err(|error| LiveDifferentialError::XdpProgram(format!("{error:?}")))?;
    map.close()
        .map_err(|error| LiveDifferentialError::XdpMap(format!("{error:?}")))?;
    resource
        .close()
        .map_err(|error| LiveDifferentialError::XdpSetup(format!("{error:?}")))?;
    memory
        .close()
        .map_err(|error| LiveDifferentialError::XdpSetup(format!("{error:?}")))?;
    Ok(observation)
}

fn drain_xdp_tx(
    resource: &mut ruster_io_xdp_native::XdpResource<'_>,
    timeout: Duration,
) -> Result<(), LiveDifferentialError> {
    let deadline = Instant::now() + timeout;
    loop {
        let completion = resource
            .receive(0)
            .map_err(|error| LiveDifferentialError::XdpCleanup(format!("{error:?}")))?
            .finish();
        if let Some(error) = completion.error {
            return Err(LiveDifferentialError::XdpCleanup(format!(
                "completion scan returned an error: {error:?}"
            )));
        }
        match resource.check_publication_quiescence() {
            Ok(()) => return Ok(()),
            Err(_error) if Instant::now() < deadline => std::thread::yield_now(),
            Err(error) => {
                return Err(LiveDifferentialError::XdpCleanup(format!(
                    "TX completion did not quiesce: {error:?}"
                )))
            }
        }
    }
}

fn wait_for_xdp(
    resource: &mut ruster_io_xdp_native::XdpResource<'_>,
    timeout: Duration,
) -> Result<(), LiveDifferentialError> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(LiveDifferentialError::Timeout("AF_XDP"));
        }
        let slice = remaining.min(Duration::from_millis(100));
        if resource
            .wait_for_rx(slice)
            .map_err(|error| LiveDifferentialError::XdpWait(format!("{error:?}")))?
        {
            return Ok(());
        }
    }
}

#[derive(Default)]
struct RecordingTrace {
    events: Vec<TraceEvent>,
}

impl TraceSink for RecordingTrace {
    fn record(&mut self, event: TraceEvent) {
        self.events.push(event);
    }
}

#[derive(Default)]
struct InputValidation {
    observed: Cell<usize>,
    error: RefCell<Option<LiveDifferentialError>>,
}

impl InputValidation {
    fn observe<S: PacketSlot>(
        &self,
        packet: &mut PacketLease<S>,
        expected_ingress: IfId,
        expected_frame: &[u8],
    ) {
        let observed = self.observed.get();
        self.observed.set(
            observed
                .checked_add(1)
                .expect("live input observation count cannot overflow"),
        );
        if packet.ingress() != expected_ingress {
            self.record(LiveDifferentialError::InputIngress {
                expected: expected_ingress,
                observed: packet.ingress(),
            });
        }
        let bytes = packet.bytes_mut();
        if bytes.len() != expected_frame.len() {
            self.record(LiveDifferentialError::InputLength {
                expected: expected_frame.len(),
                observed: bytes.len(),
            });
        } else if let Some((offset, (&expected, &observed))) = expected_frame
            .iter()
            .zip(bytes.iter())
            .enumerate()
            .find(|(_, (expected, observed))| expected != observed)
        {
            self.record(LiveDifferentialError::InputByte {
                offset,
                expected,
                observed,
            });
        }
    }

    fn record(&self, error: LiveDifferentialError) {
        let mut current = self.error.borrow_mut();
        if current.is_none() {
            *current = Some(error);
        }
    }

    fn finish(self, expected: usize) -> Result<(), LiveDifferentialError> {
        if let Some(error) = self.error.into_inner() {
            return Err(error);
        }
        let observed = self.observed.into_inner();
        if observed != expected {
            return Err(LiveDifferentialError::InputCount { expected, observed });
        }
        Ok(())
    }
}

/// A batch adapter that checks each lease before the core forwarding code sees
/// it.  The native batch remains the owner of the slot; this wrapper only
/// delegates its terminal completion, so an input mismatch cannot skip RX
/// recycle or TX rejection cleanup.
struct ExactBatch<'expected, B> {
    inner: B,
    expected_ingress: IfId,
    expected_frame: &'expected [u8],
    rx_limit: usize,
    exposed: usize,
    validation: &'expected InputValidation,
}

impl<'expected, B> ExactBatch<'expected, B> {
    fn new(
        inner: B,
        expected_ingress: IfId,
        expected_frame: &'expected [u8],
        validation: &'expected InputValidation,
    ) -> Self {
        Self {
            inner,
            expected_ingress,
            expected_frame,
            rx_limit: usize::MAX,
            exposed: 0,
            validation,
        }
    }

    fn with_rx_limit(mut self, rx_limit: usize) -> Self {
        self.rx_limit = rx_limit;
        self
    }
}

impl<'expected, B> PacketBatch for ExactBatch<'expected, B>
where
    B: PacketBatch,
{
    type Error = B::Error;
    type Slot<'a>
        = ExactSlot<B::Slot<'a>>
    where
        Self: 'a;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {
        if self.exposed >= self.rx_limit {
            return None;
        }
        let mut lease = self.inner.next_packet()?;
        self.exposed += 1;
        self.validation
            .observe(&mut lease, self.expected_ingress, self.expected_frame);
        Some(PacketLease::new(ExactSlot { lease }))
    }

    fn finish(self) -> BatchCompletion<Self::Error> {
        self.inner.finish()
    }
}

struct ExactSlot<S: PacketSlot> {
    lease: PacketLease<S>,
}

impl<S: PacketSlot> PacketSlot for ExactSlot<S> {
    fn ingress(&self) -> IfId {
        self.lease.ingress()
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.lease.bytes_mut()
    }

    fn complete(self, completion: SlotCompletion) {
        match completion {
            SlotCompletion::Transmit(egress) => self.lease.commit(egress),
            SlotCompletion::Recycle(reason) => self.lease.recycle(reason),
            SlotCompletion::Consume(reason) => self.lease.consume(reason),
            SlotCompletion::LeaseAbandoned => drop(self.lease),
        }
    }
}

fn validate_probe_batch<B>(
    mut batch: B,
    expected_ingress: IfId,
    expected_frame: &[u8],
) -> Result<(), LiveDifferentialError>
where
    B: PacketBatch,
    B::Error: Debug,
{
    let mut observed = 0;
    let mut first_error = None;
    while let Some(mut packet) = batch.next_packet() {
        observed += 1;
        if packet.ingress() != expected_ingress && first_error.is_none() {
            first_error = Some(LiveDifferentialError::InputIngress {
                expected: expected_ingress,
                observed: packet.ingress(),
            });
        }
        let bytes = packet.bytes_mut();
        if bytes.len() != expected_frame.len() && first_error.is_none() {
            first_error = Some(LiveDifferentialError::InputLength {
                expected: expected_frame.len(),
                observed: bytes.len(),
            });
        } else if bytes.len() == expected_frame.len() && first_error.is_none() {
            if let Some((offset, (&expected, &observed))) = expected_frame
                .iter()
                .zip(bytes.iter())
                .enumerate()
                .find(|(_, (expected, observed))| expected != observed)
            {
                first_error = Some(LiveDifferentialError::InputByte {
                    offset,
                    expected,
                    observed,
                });
            }
        }
        packet.recycle(DropReason::EthernetHeaderTruncated);
    }
    let completion = batch.finish();
    if let Some(error) = first_error {
        return Err(error);
    }
    if observed != 1 {
        return Err(LiveDifferentialError::InputCount {
            expected: 1,
            observed,
        });
    }
    if let Some(error) = completion.error {
        return Err(LiveDifferentialError::ProbeCompletion(format!(
            "probe completion returned an error: {error:?}"
        )));
    }
    Ok(())
}

fn validate_trace(
    events: &[TraceEvent],
    expected: usize,
    expected_ingress: IfId,
    expected_egress: IfId,
) -> Result<(), LiveDifferentialError> {
    let mut observed = 0;
    for event in events {
        match *event {
            TraceEvent::TxRequested { egress } => {
                observed += 1;
                if egress != expected_egress {
                    return Err(LiveDifferentialError::TraceEgress {
                        expected: expected_egress,
                        observed: egress,
                    });
                }
            }
            TraceEvent::Dropped { ingress, .. }
            | TraceEvent::Consumed { ingress, .. }
            | TraceEvent::Ipv4LocalConsumed { ingress, .. } => {
                observed += 1;
                if ingress != expected_ingress {
                    return Err(LiveDifferentialError::TraceIngress {
                        expected: expected_ingress,
                        observed: ingress,
                    });
                }
            }
            _ => {}
        }
    }
    if observed != expected {
        return Err(LiveDifferentialError::TraceCount { expected, observed });
    }
    Ok(())
}

fn af_packet_error_category(error: &AfPacketError) -> ErrorCategory {
    match error {
        AfPacketError::Receive { .. } => ErrorCategory::Receive,
        AfPacketError::Transmit(_) => ErrorCategory::Transmit,
        AfPacketError::Completion { .. } => ErrorCategory::Completion,
        AfPacketError::Kick(_) => ErrorCategory::Kick,
        AfPacketError::Wait(_) => ErrorCategory::Wait,
        AfPacketError::Quiescence(_) => ErrorCategory::Quiescence,
    }
}

fn xdp_error_category(error: &XdpIoError) -> ErrorCategory {
    match error {
        XdpIoError::Platform(_) => ErrorCategory::Platform,
        XdpIoError::Ring { .. } => ErrorCategory::Ring,
        XdpIoError::Mapping(_) => ErrorCategory::Mapping,
        XdpIoError::Syscall { stage, .. } => match stage {
            XdpSetupStage::PollSocket => ErrorCategory::Wait,
            XdpSetupStage::SendToSocket => ErrorCategory::Kick,
            _ => ErrorCategory::Setup,
        },
        XdpIoError::InvalidDescriptor { .. } | XdpIoError::InvalidCompletionAddress { .. } => {
            ErrorCategory::Ring
        }
        XdpIoError::Ownership { .. } => ErrorCategory::Ownership,
        XdpIoError::InterfaceMismatch { .. } => ErrorCategory::Setup,
        XdpIoError::BatchActive => ErrorCategory::Ownership,
        XdpIoError::RawRingViewsExposed => ErrorCategory::Ownership,
        XdpIoError::Wakeup { .. } => ErrorCategory::Kick,
        XdpIoError::Quiescence { .. } => ErrorCategory::Quiescence,
    }
}

fn merge_observation(accumulated: &mut Option<NormalizedObservation>, next: NormalizedObservation) {
    let Some(current) = accumulated.as_mut() else {
        *accumulated = Some(next);
        return;
    };

    current.received = current
        .received
        .checked_add(next.received)
        .expect("live observation count cannot overflow");
    current.dropped = current
        .dropped
        .checked_add(next.dropped)
        .expect("live observation count cannot overflow");
    current.consumed = current
        .consumed
        .checked_add(next.consumed)
        .expect("live observation count cannot overflow");
    current.tx_requested = current
        .tx_requested
        .checked_add(next.tx_requested)
        .expect("live observation count cannot overflow");
    current.tx_accepted = current
        .tx_accepted
        .checked_add(next.tx_accepted)
        .expect("live observation count cannot overflow");
    current.tx_rejected = current
        .tx_rejected
        .checked_add(next.tx_rejected)
        .expect("live observation count cannot overflow");
    current.recycled = current
        .recycled
        .checked_add(next.recycled)
        .expect("live observation count cannot overflow");
    current.error_present |= next.error_present;
    current.batch_invariants &= next.batch_invariants;
    current.completion_invariants &= next.completion_invariants;
    if current.error_category == ErrorCategory::None {
        current.error_category = next.error_category;
    }
    current.forwarding.extend(next.forwarding);
    // `active_disposition` describes the state before the first batch.  The
    // final disposition is the one observed after the last batch finished.
    current.disposition = next.disposition;
}

/// Converts one real backend report and its core forwarding trace into the
/// stable observation compared by the differential test.
pub fn observation_from_trace<E>(
    report: BatchReport<E>,
    events: &[TraceEvent],
    active_disposition: PublicationQuiescenceDisposition,
    disposition: PublicationQuiescenceDisposition,
    error_category: ErrorCategory,
) -> NormalizedObservation {
    let forwarding = events
        .iter()
        .filter_map(|event| match *event {
            TraceEvent::TxRequested { .. } => Some(ForwardingResult::Forwarded),
            TraceEvent::Dropped { reason, .. } => Some(ForwardingResult::Dropped(reason)),
            TraceEvent::Consumed { reason, .. } | TraceEvent::Ipv4LocalConsumed { reason, .. } => {
                Some(ForwardingResult::Consumed(reason))
            }
            _ => None,
        })
        .collect();
    let completion = &report.completion;
    NormalizedObservation {
        received: report.received,
        dropped: report.dropped,
        consumed: report.consumed,
        tx_requested: report.tx_requested,
        tx_accepted: completion.tx_accepted,
        tx_rejected: completion.tx_rejected,
        recycled: completion.recycled,
        error_present: completion.error.is_some(),
        batch_invariants: report.invariants_hold(),
        completion_invariants: completion.invariants_hold(),
        forwarding,
        error_category,
        active_disposition,
        disposition,
    }
}
