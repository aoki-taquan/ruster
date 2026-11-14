#![forbid(unsafe_code)]
//! The forwarding element (FE): it holds the tables and forwards packets by them.
//!
//! See `docs/design/fe-internals.md`. One worker, IPv4 and IPv6, VRFs, and one next
//! hop per route (the first active one of several). The tables arrive over the table
//! server ([`ruster_proto::session`]); every accepted change rebuilds the core's
//! [`ValidatedForwardingOwner`](ruster_core::ValidatedForwardingOwner) and the worker uses the new one from its next batch.
//!
//! ARP goes to the neighbor process: core hands each ARP packet over
//! ([`ForwardingSnapshot::with_arp_to_control`](ruster_core::ForwardingSnapshot::with_arp_to_control)) and the FE sends it on the punt
//! socket. A packet whose next hop is not in the neighbor table is dropped and turned
//! into a resolve request notification, at most one per next hop per second.
//! Frames the neighbor process sends back go out through the backend's generated
//! frames.
//!
//! Bridges (`docs/design/overlay.md`): core relays the frames of bridge members and
//! sends what leaves a bridge's own interface (IRB) to the member its destination
//! was learned on ([`ruster_core::Bridges`]). The frames it floods are copied out and
//! sent here after the batch, out of every other member; so are the frames the
//! control processes, ICMP errors and fragments send out of an IRB. A member that is
//! an EtherIP interface ([`ruster_core::Overlay`]) gets those frames wrapped here too,
//! with the outer header core makes; a frame that does not fit once wrapped is
//! dropped and counted.
//!
//! IS-IS and OSPF go to the TAP device of the interface they came in on, and what
//! the kernel's daemons write there goes out of that interface ([`tap`]).
//!
//! # Standards
//!
//! - Forwarding decisions are `ruster-core`'s (RFC 1812 sections 5.2.2 and 5.3.1:
//!   header checks and the TTL).
//! - RFC 1122 section 2.3.2.1: at most one resolve request per second per next hop.
//! - IEEE 802.1Q 8.6: a flooded frame leaves every member but the one it came in on
//!   (the rest as in `ruster_core`'s bridge module).
//!
//! Deviations: ARP is not answered in the FE; every ARP packet goes to the neighbor
//! process.

use std::collections::BTreeMap;
use std::io::{self, ErrorKind};
use std::net::IpAddr;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{
    self, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError, TrySendError,
};
use std::sync::Arc;
use std::time::Duration;

use ruster_core::{
    execute_one_icmpv4_error, execute_one_ipv4_fragmentation, forward_batch_with_control,
    ArpOpcode, ControlKind, ControlQueue, GeneratedIcmpv4Trace, GeneratedIcmpv4TraceSink,
    GeneratedPacketBatch, GeneratedPacketIo, Icmpv4ErrorActionSlot, Icmpv4ErrorPolicy,
    Icmpv4ErrorRuntime, Icmpv4ErrorStateSlot, IfId, MonotonicMillis, Nat44IcmpConfig,
    Nat44TcpConfig, Nat44UdpConfig, PacketIo, Services, TraceEvent, TraceSink, VlanBinding,
};
use ruster_proto::cbor::Encoder;
use ruster_proto::punt::{self, Direction, Punt};
use ruster_proto::session::{Hook, Server, Store};
use ruster_proto::sid;
use ruster_proto::table::ResolveRequest;
use ruster_proto::task::{Progress, Task};

mod build;
mod control;
mod firewall;
mod fragments;
mod handover;
mod kernel;
mod local;
mod nat;
mod punt_table;
mod reassembly;
mod tap;

pub use handover::HandoverTask;
pub use local::LocalPipe;
pub use punt_table::PuntCounters;
use ruster_proto::table::{Key, PuntDestination, PuntKind, PuntMatch, Value};

/// The tables each kind of writer may change (one writer per table).
pub mod writers {
    use ruster_proto::sid;

    pub const CONFIG: &[u64] = &[
        sid::INTERFACE,
        sid::ADDRESS,
        sid::NAT,
        sid::FIREWALL_POLICY,
        sid::ICMP_ERRORS,
        sid::FIREWALL_RULE,
        sid::PUNT,
        sid::BRIDGE,
        sid::BRIDGE_PORT,
        sid::BRIDGE_MAC,
        sid::ETHERIP,
        sid::VXLAN,
    ];
    pub const ROUTE: &[u64] = &[sid::ROUTE];
    pub const NEIGHBOR: &[u64] = &[sid::NEIGHBOR];
    pub const READ_ONLY: &[u64] = &[];
}

/// The only VRF of the skeleton.
pub const DEFAULT_VRF: &str = ruster_proto::table::DEFAULT_VRF;

/// Packets taken from the backend in one step.
const RX_BUDGET: usize = 64;
/// ARP packets and resolve requests remembered per batch; more are dropped and counted.
const EVENTS_PER_BATCH: usize = 64;
/// Neighbors marked used at most between two reads of the marks.
const USED_MAX: usize = 8_192;
/// Frames read from the punt socket per step.
const INJECT_PER_STEP: usize = 64;
/// While the ports bring packets step after step, what the kernel and the control
/// processes hand in is read once in this many steps: each of their sockets
/// costs a system call a step, also when it has nothing. Only after
/// [`BUSY_STEPS`] steps in a row with packets from the ports; until then, and
/// after any step without, every step reads them, so an FE that is not loaded
/// answers as fast as before.
const HANDED_IN_EVERY: u8 = 8;
/// See [`HANDED_IN_EVERY`].
const BUSY_STEPS: u8 = 2;
/// One resolve request per next hop per this many milliseconds.
/// The most writes one step leaves to the handover; more are dropped and counted.
const HANDED_PER_STEP: usize = 1_024;

const RESOLVE_INTERVAL_MS: u64 = 1_000;
/// Next hops remembered for the rate limit. Older ones are forgotten first; when all
/// are recent, further requests wait (and are counted).
const RESOLVE_REMEMBERED: usize = 1_024;
/// MAC addresses the bridges learn, all together.
const BRIDGE_MACS: usize = 8_192;
/// Flooded frames copied out in one batch; more are dropped and counted.
const FLOOD_SLOTS: usize = RX_BUDGET;
/// Slots of the MAC address table looked at for aged entries per step.
const AGING_PER_STEP: usize = 256;
/// The largest frame accepted from the punt socket (Ethernet with a 1500-byte payload
/// and a VLAN tag, plus the punt header).
const PUNT_MAX: usize = 1_522 + 300;
const ETHERNET_HEADER: usize = 14;
const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];
const ETHERTYPE_IPV6: [u8; 2] = [0x86, 0xdd];

/// Counters for things the FE dropped on its own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeCounters {
    pub batches: u64,
    pub forwarded: u64,
    pub dropped: u64,
    /// Packets the other workers handed to worker 0, which owns the state
    /// ([`Fe::with_workers`]); worker 0 counts them again as it forwards them.
    pub handed_to_owner: u64,
    /// Those dropped because worker 0's queue was full.
    pub handed_dropped: u64,
    pub arp_to_control: u64,
    pub arp_to_control_dropped: u64,
    pub resolve_requests: u64,
    pub resolve_requests_dropped: u64,
    pub injected: u64,
    pub inject_dropped: u64,
    /// ICMP errors generated (rate limited per egress interface).
    pub icmp_errors_sent: u64,
    /// Packets addressed to the router written to the kernel, and those dropped
    /// (rate limit, no pipe for the VRF, or the pipe full).
    pub to_kernel: u64,
    pub to_kernel_dropped: u64,
    /// Packets from the kernel sent out, and those dropped (no route, no neighbor
    /// yet, or no room).
    pub from_kernel: u64,
    pub from_kernel_dropped: u64,
    /// Frames written to an interface's TAP device (IS-IS, OSPF), and those dropped
    /// (rate limit, no TAP, or the TAP full).
    pub to_tap: u64,
    pub to_tap_dropped: u64,
    /// Frames the kernel wrote to a TAP that were sent out or routed, and those
    /// dropped (another kind, an interface not enabled, a neighbor not known yet,
    /// or no room).
    pub from_tap: u64,
    pub from_tap_dropped: u64,
    /// Tunnels' IPv6 packets put back together from their fragments.
    pub tunnel_reassembled: u64,
    /// Fragments sent for datagrams longer than the egress MTU, and datagrams whose
    /// fragments could not be sent.
    pub fragments_sent: u64,
    pub fragmentation_dropped: u64,
    /// ICMP errors and fragments for an interface that is not a port (a tunnel, a
    /// PPPoE session, a VLAN sub-interface) that could not be sent after they were
    /// counted.
    pub generated_dropped: u64,
    /// The bridges' counters added up (see [`ruster_core::BridgeCounters`]).
    pub bridge_learned: u64,
    pub bridge_moved: u64,
    pub bridge_aged: u64,
    pub bridge_limited: u64,
    pub bridge_forwarded: u64,
    pub bridge_flooded: u64,
    pub bridge_flood_dropped: u64,
    pub bridge_dropped: u64,
    /// Frames bridged to an overlay (EtherIP) that were dropped because they do not
    /// fit the underlying interface's MTU once wrapped, and those dropped for any
    /// other reason (no route toward the remote end, say).
    pub overlay_too_big: u64,
    pub overlay_dropped: u64,
}

/// The forwarding element: the control task and the worker.
///
/// The two share nothing. The control task sends the worker each version of the
/// tables it builds, and the worker sends back its notifications for the table
/// connections and which version it now uses, over one queue each way.
///
/// [`Fe::step`] steps both, one after the other, on the caller's thread. After
/// [`Fe::detach_control`] it steps the worker only, and the caller steps the
/// [`Control`] it got wherever it likes: building a large version of the tables
/// then does not hold up forwarding.
pub struct Fe<B> {
    /// `None` once detached.
    control: Option<ControlTask>,
    worker: Worker<B>,
    /// The other workers ([`Fe::with_workers`]); empty once detached.
    others: Vec<OtherWorker<B>>,
    /// Their counters, kept after they are detached.
    others_counters: Vec<Arc<OtherCounters>>,
}

/// What the control task sends a worker other than worker 0 with each version:
/// the tables, and the NAT whose packets it hands over.
#[derive(Clone)]
struct ForOther {
    tables: Arc<build::Built>,
    nat: Option<(Nat44UdpConfig, Nat44TcpConfig, Nat44IcmpConfig)>,
}

/// What a worker other than worker 0 sends it after a batch: the packets it
/// handed over (ingress, frame), and the next hops of those it forwarded, for
/// the neighbors' "used" marks.
struct Handed {
    /// As frames with room in front, so worker 0 forwards them without another
    /// copy.
    frames: Vec<kernel::Frame>,
    used: Vec<(u16, IpAddr)>,
    /// The tables the marks were made by, by address: marks made by others than
    /// worker 0's name other interfaces.
    tables: usize,
}

/// How many batches the other workers may have handed over and worker 0 not
/// taken yet; more are dropped and counted.
const HANDED_QUEUED: usize = 16;

/// Collects the next hops a batch's packets went to.
#[derive(Default)]
struct UsedMarks(Vec<(u16, IpAddr)>);

impl TraceSink for UsedMarks {
    fn record(&mut self, event: TraceEvent) {
        let next_hop = match event {
            TraceEvent::Routed {
                egress,
                neighbor_target,
            } => (egress.0, IpAddr::V4(neighbor_target.octets().into())),
            TraceEvent::Ipv6Routed { egress, next_hop } => (egress.0, IpAddr::V6(next_hop.into())),
            _ => return,
        };
        if self.0.last() != Some(&next_hop) {
            self.0.push(next_hop);
        }
    }
}

/// The counters of a worker other than worker 0, read by [`Fe::counters`] from
/// any thread.
#[derive(Default)]
struct OtherCounters {
    batches: AtomicU64,
    forwarded: AtomicU64,
    dropped: AtomicU64,
    handed: AtomicU64,
    handed_dropped: AtomicU64,
}

/// A worker other than worker 0 ([`Fe::with_workers`]): it forwards by itself
/// only what needs no state (`ruster_core::forward_batch_stateless`) and hands
/// every other packet to worker 0, which owns NAT, the firewall, the bridges and
/// the connections to the control side.
pub struct OtherWorker<B> {
    io: B,
    tables: Arc<build::Built>,
    kernel_bits: Vec<u64>,
    punt_frames: Vec<ruster_core::PuntFrameMatch>,
    nat: Option<(Nat44UdpConfig, Nat44TcpConfig, Nat44IcmpConfig)>,
    versions: Receiver<Box<ForOther>>,
    to_control: Sender<FromWorker>,
    to_owner: SyncSender<Handed>,
    /// Set while worker 0's NAT or firewall is still bound to older tables (it
    /// could not move them): then every packet is handed over, as worker 0 drops
    /// what that NAT or firewall would have handled.
    hand_all: Arc<AtomicBool>,
    counters: Arc<OtherCounters>,
    gone: bool,
}

impl OtherWorker<()> {
    /// The worker, forwarding on `io`.
    pub fn with_io<B>(self, io: B) -> OtherWorker<B> {
        OtherWorker {
            io,
            tables: self.tables,
            kernel_bits: self.kernel_bits,
            punt_frames: self.punt_frames,
            nat: self.nat,
            versions: self.versions,
            to_control: self.to_control,
            to_owner: self.to_owner,
            hand_all: self.hand_all,
            counters: self.counters,
            gone: self.gone,
        }
    }
}

impl<B: PacketIo> OtherWorker<B> {
    /// Whether the [`Fe`] it worked for is gone.
    pub fn fe_gone(&self) -> bool {
        self.gone
    }

    /// Its backend.
    pub fn io_mut(&mut self) -> &mut B {
        &mut self.io
    }

    fn step(&mut self, now_ms: u64) -> bool {
        let mut last = None;
        loop {
            match self.versions.try_recv() {
                Ok(version) => last = Some(version),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.gone = true;
                    break;
                }
            }
        }
        if let Some(version) = last {
            self.kernel_bits = ruster_core::kernel_ingress_bits(&version.tables.kernel);
            self.punt_frames = version.tables.punt.frame_matches();
            self.nat = version.nat;
            let old = std::mem::replace(&mut self.tables, version.tables);
            self.gone |= self.to_control.send(FromWorker::OtherUsing(old)).is_err();
        }
        let tables = &*self.tables;
        let snapshots = vrf_snapshots(tables, &self.kernel_bits, |_| false);
        let snapshot = outer_snapshot(&snapshots, tables, &self.kernel_bits, &self.punt_frames)
            .with_now(MonotonicMillis(now_ms));
        let Ok(ports) = self.io.receive(RX_BUDGET) else {
            return false;
        };
        let stateful = ruster_core::Stateful {
            nat44_udp: self.nat.as_ref().map(|nat| &nat.0),
            nat44_tcp: self.nat.as_ref().map(|nat| &nat.1),
            nat44_icmp: self.nat.as_ref().map(|nat| &nat.2),
            firewall: tables.firewall_on || self.hand_all.load(Ordering::Relaxed),
            bridges: !tables.bridges.is_empty(),
        };
        let mut handed = Vec::new();
        let mut used = UsedMarks::default();
        let report = ruster_core::forward_batch_stateless(
            ports,
            &snapshot,
            stateful,
            |ingress, frame| handed.push(kernel::Frame::from_ethernet(ingress, frame)),
            &mut used,
        );
        if report.received == 0 {
            return false;
        }
        let counters = &self.counters;
        counters.batches.fetch_add(1, Ordering::Relaxed);
        counters
            .forwarded
            .fetch_add(report.tx_requested as u64, Ordering::Relaxed);
        counters
            .dropped
            .fetch_add(report.dropped as u64, Ordering::Relaxed);
        if !handed.is_empty() || !used.0.is_empty() {
            let count = handed.len() as u64;
            let handed = Handed {
                frames: handed,
                used: used.0,
                tables: Arc::as_ptr(&self.tables) as usize,
            };
            match self.to_owner.try_send(handed) {
                Ok(()) => counters.handed.fetch_add(count, Ordering::Relaxed),
                Err(TrySendError::Full(_)) => {
                    counters.handed_dropped.fetch_add(count, Ordering::Relaxed)
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.gone = true;
                    0
                }
            };
        }
        true
    }
}

impl<B: PacketIo> Task for OtherWorker<B> {
    fn step(&mut self, now_ms: u64) -> Progress {
        Progress::busy(OtherWorker::step(self, now_ms))
    }
}

/// The control task of an [`Fe`], taken out of it by [`Fe::detach_control`] to be
/// stepped on another thread.
pub struct Control(ControlTask);

// A thread can be given it.
const _: fn() = || {
    fn is_send<T: Send>() {}
    is_send::<Control>();
};

impl Control {
    /// Accepts a table connection that may write `writes` (see [`writers`]).
    pub fn attach(&mut self, stream: UnixStream, writes: &[u64]) -> io::Result<()> {
        self.0.server.attach(stream, writes)
    }

    /// Whether the [`Fe`] this was taken out of is gone: nothing is left to build
    /// tables for.
    pub fn fe_gone(&self) -> bool {
        self.0.worker_gone
    }

    /// Waits until the worker says something, at most `longest`: for a thread that
    /// found nothing to do in its last step. What arrives on the table connections
    /// is seen at the next step only.
    pub fn wait(&mut self, longest: Duration) {
        match self.0.from_worker.recv_timeout(longest) {
            Ok(message) => self.0.on_message(message),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => self.0.worker_gone = true,
        }
    }
}

impl Task for Control {
    fn step(&mut self, _now_ms: u64) -> Progress {
        self.0.step()
    }
}

/// The tables built for one accepted store, with its firewall and NAT.
/// The tables are shared by reference: a worker reads them, and gives the
/// version it moved away from back to the control task, which frees it.
type Version = (
    Arc<build::Built>,
    firewall::Publication,
    Option<nat::Publication>,
);

/// What the control task sends the worker, in this order.
enum ToWorker {
    Version(Box<Version>),
    /// The answer to [`FromWorker::Sync`] with the same number: every table change
    /// that had arrived when the worker asked is in a version sent before this.
    Synced(u64),
}

/// What the worker tells the control task.
enum FromWorker {
    /// A notification for the table connections that observe (a resolve request).
    Notify(Vec<u8>),
    /// The worker now uses a version whose interfaces have these names, by id.
    Using(Vec<String>),
    /// The worker holds frames the control processes gave it to send, and asks to
    /// be told ([`ToWorker::Synced`]) once the table changes that arrived before
    /// them are in a version. A control process that writes a table and then sends
    /// a frame (the neighbor process: a neighbor, then its ARP reply) can count on
    /// the frame leaving after the change is in use, as long as what it wrote
    /// before the frame is read within [`SYNC_STEPS`] steps of the control task (64
    /// requests and 64 KiB a connection in each).
    Sync(u64),
    /// The tables of a version the worker moved away from, to be freed here, not
    /// on the worker's thread.
    Retired(Arc<build::Built>),
    /// Another worker ([`Fe::with_workers`]) now uses the last version sent, and
    /// gives back the tables it moved away from.
    OtherUsing(Arc<build::Built>),
}

/// The steps of the control task after which a [`FromWorker::Sync`] is answered
/// even if table changes keep arriving, so that a writer that never pauses (routes
/// while a routing protocol converges) does not keep the frames of the control
/// processes from leaving.
const SYNC_STEPS: u32 = 4;

/// The control role of `docs/design/fe-internals.md`: it talks to the table
/// connections and builds a version of the tables for each accepted change. It
/// does not touch packets.
struct ControlTask {
    server: Server,
    builder: Builder,
    versions: Sender<ToWorker>,
    from_worker: Receiver<FromWorker>,
    /// The number of the worker's last [`FromWorker::Sync`] not answered yet.
    sync_wanted: Option<u64>,
    /// The steps that looked at the table connections since it was asked.
    sync_steps: u32,
    /// The other workers' queues ([`Fe::with_workers`]).
    others: Vec<Sender<Box<ForOther>>>,
    /// How many of the other workers have not said yet that they use the last
    /// version sent.
    others_awaited: usize,
    /// A version was sent and the worker has not said yet that it uses it.
    ///
    /// Until it does, no further change is looked at: the next version must be built
    /// on the interface ids of the one the worker uses, or an interface could get
    /// another's id while the worker's state (NAT, the firewall) still names it.
    awaiting_worker: bool,
    /// The worker's end of the queues is gone.
    worker_gone: bool,
}

impl ControlTask {
    fn on_message(&mut self, message: FromWorker) {
        match message {
            FromWorker::Notify(payload) => self.server.notify(&payload),
            FromWorker::Using(names) => {
                self.builder.names = names;
                self.awaiting_worker = false;
                self.release_when_all_moved();
            }
            FromWorker::OtherUsing(tables) => {
                drop(tables);
                self.others_awaited = self.others_awaited.saturating_sub(1);
                self.release_when_all_moved();
            }
            FromWorker::Sync(number) => {
                self.sync_wanted = Some(number);
                self.sync_steps = 0;
            }
            FromWorker::Retired(tables) => drop(tables),
        }
    }

    /// Once every worker uses the version the changes are in, their writers are
    /// told. (With the worker gone, nobody is: the FE is stopping.)
    fn release_when_all_moved(&mut self) {
        if !self.awaiting_worker && self.others_awaited == 0 {
            self.server.release_changed();
        }
    }

    fn step(&mut self) -> Progress {
        loop {
            match self.from_worker.try_recv() {
                Ok(message) => self.on_message(message),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.worker_gone = true;
                    break;
                }
            }
        }
        if (self.awaiting_worker || self.others_awaited > 0) && !self.worker_gone {
            return Progress::IDLE;
        }
        let progress = self.server.step(&mut self.builder);
        // Of several versions built in one step, the last.
        if let Some(version) = self.builder.built.take() {
            let (built, publication, nat) = version;
            let built = Arc::new(built);
            let other = ForOther {
                tables: Arc::clone(&built),
                nat: nat.as_ref().map(nat::Publication::configs),
            };
            self.others_awaited = 0;
            for to_other in &self.others {
                if to_other.send(Box::new(other.clone())).is_ok() {
                    self.others_awaited += 1;
                }
            }
            let version = (built, publication, nat);
            let sent = self.versions.send(ToWorker::Version(Box::new(version)));
            self.worker_gone |= sent.is_err();
            self.awaiting_worker = true;
        }
        if let Some(number) = self.sync_wanted {
            self.sync_steps += 1;
            // Nothing more had arrived; or enough was looked at. After the version
            // of this step, if there is one: the worker moves to it first.
            if !progress.busy || self.sync_steps >= SYNC_STEPS {
                self.sync_wanted = None;
                self.worker_gone |= self.versions.send(ToWorker::Synced(number)).is_err();
            }
        }
        progress
    }
}

/// The worker role: it receives, forwards and sends packets by the version of the
/// tables it has, and holds the state packets make (NAT, the firewall, fragments,
/// the bridges' MAC addresses).
struct Worker<B> {
    io: B,
    /// The backend's ports, in order: port `i` is `IfId(i)`.
    ports: Vec<String>,
    /// The tables of the version in use: core's tables per VRF (the default VRF
    /// first), the VRF of each port, the names of the VRFs and of every interface
    /// by id (the ports, then the others, each keeping its id across table changes;
    /// an empty name is an id no interface has), the VLAN sub-interfaces, tunnels,
    /// SRv6, overlays, PPPoE sessions, kernel interfaces, punt classes and the
    /// enabled interfaces.
    tables: Arc<build::Built>,
    /// Each VRF's kernel interface as a bitmap by id ([`ruster_core::kernel_ingress_bits`]), which
    /// each packet is looked up in.
    kernel_bits: Vec<u64>,
    /// The pipes to the kernel, the TAP devices and the sockets to the control
    /// processes, for traffic addressed to the router.
    handover: handover::Handover,
    /// What the step left to the handover to write, in order; and the buffers
    /// of those written, to be used again.
    outbox: Vec<handover::Out>,
    spare: Vec<Vec<u8>>,
    /// The names the writes are resolved by, of the current tables.
    handover_names: handover::Names,
    /// The number of the current tables, for counting writes that come back from
    /// a handover on another thread after the tables changed.
    version: u64,
    /// The queues to and from the handover's writes on another thread
    /// ([`Fe::detach_handover`]); `None` while they are written here.
    writer: Option<(Sender<handover::ToWriter>, Receiver<handover::Written>)>,
    /// Their rate limits and counters; to the kernel, per VRF in the order of
    /// `vrfs`: a flood in one VRF does not crowd out another's (BGP in another VRF,
    /// say).
    limits: punt_table::Limits,
    /// The versions the control task built; the worker moves to the last.
    versions: Receiver<ToWorker>,
    to_control: Sender<FromWorker>,
    /// The control task's end of the queues is gone.
    control_gone: bool,
    /// The control task was taken out of the `Fe`: it sees table changes at its own
    /// pace, so the frames of the control processes wait for it ([`FromWorker::Sync`]).
    detached: bool,
    /// The frames read from the control processes' sockets and not sent yet, with
    /// how many of them are not the neighbor process's (those come first).
    held: Option<(Vec<Vec<u8>>, usize)>,
    /// The number of the last [`FromWorker::Sync`] sent, and of the last answered.
    sync: u64,
    synced: u64,
    /// What core picks out for them before forwarding.
    punt_frames: Vec<ruster_core::PuntFrameMatch>,
    last_resolve: BTreeMap<(IfId, IpAddr), u64>,
    /// Neighbor Discovery frames core copied out of the last batch.
    control: ControlQueue,
    /// ICMPv4 errors core queued in the last batch, and their rate limits.
    icmpv4_errors: Icmpv4ErrorRuntime<'static>,
    /// The default VRF's forward firewall, once a rule has arrived.
    firewall: Option<firewall::Firewall>,
    /// The default VRF's NAPT, once the tables have had one.
    nat: Option<nat::Nat>,
    fragmentation: ruster_core::Ipv4FragmentationRuntime<'static>,
    /// Tunnels' fragmented IPv6 packets being put back together, and those put
    /// together, for the next batch.
    reassembly: reassembly::Reassembly,
    reassembled: Vec<kernel::Frame>,
    /// The neighbors packets went to since the neighbor process last read them.
    used: std::collections::HashSet<(u16, IpAddr)>,
    /// What the last batch's packets left to act on; see [`FeTrace`].
    trace: FeTrace,
    /// Steps in a row, up to now, in which the ports brought packets (it stops
    /// counting at [`BUSY_STEPS`]).
    busy_steps: u8,
    /// Steps since the kernel's and the control processes' sockets were read.
    unread_steps: u8,
    fragment_tracking: ruster_core::Ipv4FragmentTracker<'static>,
    /// The bridges, their MAC address tables and the frames they flood.
    bridges: ruster_core::Bridges,
    /// The bridges' names, in the order of their ids.
    bridge_names: Vec<String>,
    /// The time of the current step.
    now_ms: u64,
    counters: FeCounters,
    /// What the other workers handed over, to be forwarded as received here.
    from_others: Receiver<Handed>,
    /// Told to the other workers: this worker's NAT or firewall could not move
    /// to the tables in use.
    hand_all: Arc<AtomicBool>,
}

impl<B> std::fmt::Debug for Fe<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fe")
            .field("ports", &self.worker.ports)
            .field("counters", &self.worker.counters)
            .finish_non_exhaustive()
    }
}

impl<B> Fe<B>
where
    B: PacketIo + GeneratedPacketIo,
{
    /// `ports` names the backend's ports; port `i` is `IfId(i)`. The tables start empty,
    /// so nothing is forwarded until a writer adds interfaces and routes.
    pub fn new(io: B, ports: Vec<String>) -> Self {
        Self::with_workers(io, Vec::new(), ports)
    }

    /// Like [`Fe::new`], with more workers on `others` (other queues of the same
    /// ports): they forward what needs no state and hand the rest to the first.
    pub fn with_workers(io: B, others: Vec<B>, ports: Vec<String>) -> Self {
        let (mut fe, seeds) = Self::with_worker_seeds(io, others.len(), ports);
        fe.others = seeds
            .into_iter()
            .zip(others)
            .map(|(seed, io)| seed.with_io(io))
            .collect();
        fe
    }

    /// Like [`Fe::with_workers`] with `others` workers not in the `Fe` and not yet
    /// given their backends: each is given its own with [`OtherWorker::with_io`],
    /// on its own thread (a backend that cannot move between threads is opened
    /// there), and stepped there.
    pub fn with_worker_seeds(
        io: B,
        others: usize,
        ports: Vec<String>,
    ) -> (Self, Vec<OtherWorker<()>>) {
        let mut builder = Builder {
            ports: ports.clone(),
            built: None,
            routes: None,
            generation: 0,
            names: Vec::new(),
        };
        builder
            .check(&Store::default())
            .expect("empty tables build");
        let (built, _, _) = builder.built.take().expect("built");
        let built = Arc::new(built);
        builder.names.clone_from(&built.interface_names);
        let limits = punt_table::Limits::new(&built.punt, built.vrfs.len());
        let (versions, from_control) = mpsc::channel();
        let (to_control, from_worker) = mpsc::channel();
        let (to_owner, from_others) = mpsc::sync_channel(HANDED_QUEUED);
        let hand_all = Arc::new(AtomicBool::new(false));
        let mut to_others = Vec::new();
        let mut other_workers = Vec::new();
        for _ in 0..others {
            let (to_other, versions) = mpsc::channel();
            to_others.push(to_other);
            other_workers.push(OtherWorker {
                io: (),
                tables: Arc::clone(&built),
                kernel_bits: ruster_core::kernel_ingress_bits(&built.kernel),
                punt_frames: Vec::new(),
                nat: None,
                versions,
                to_control: to_control.clone(),
                to_owner: to_owner.clone(),
                hand_all: Arc::clone(&hand_all),
                counters: Arc::default(),
                gone: false,
            });
        }
        drop(to_owner);
        let mut server = Server::new();
        server.hold_changed();
        let control = ControlTask {
            server,
            builder,
            versions,
            from_worker,
            sync_wanted: None,
            sync_steps: 0,
            others: to_others,
            others_awaited: 0,
            awaiting_worker: false,
            worker_gone: false,
        };
        let worker = Worker {
            io,
            ports,
            kernel_bits: ruster_core::kernel_ingress_bits(&built.kernel),
            handover: handover::Handover::default(),
            outbox: Vec::new(),
            spare: Vec::new(),
            handover_names: handover::Names::default(),
            version: 0,
            writer: None,
            limits,
            versions: from_control,
            to_control,
            tables: built,
            control_gone: false,
            detached: false,
            held: None,
            sync: 0,
            synced: 0,
            punt_frames: Vec::new(),
            last_resolve: BTreeMap::new(),
            control: ControlQueue::new(EVENTS_PER_BATCH).with_icmpv6_errors(EVENTS_PER_BATCH),
            icmpv4_errors: icmpv4_error_runtime(),
            firewall: None,
            nat: None,
            fragmentation: fragments::fragmentation(),
            reassembly: reassembly::Reassembly::default(),
            reassembled: Vec::new(),
            used: std::collections::HashSet::new(),
            trace: FeTrace::default(),
            busy_steps: 0,
            unread_steps: 0,
            fragment_tracking: fragments::tracker(),
            bridges: ruster_core::Bridges::new(BRIDGE_MACS, FLOOD_SLOTS, hash_key()),
            bridge_names: Vec::new(),
            now_ms: 0,
            counters: FeCounters::default(),
            from_others,
            hand_all,
        };
        let others_counters = other_workers
            .iter()
            .map(|w| Arc::clone(&w.counters))
            .collect();
        let fe = Self {
            control: Some(control),
            worker,
            others: Vec::new(),
            others_counters,
        };
        (fe, other_workers)
    }

    /// The backend of worker `worker`: 0 is the one [`Fe::io_mut`] gives, the
    /// others those given to [`Fe::with_workers`] (until detached).
    pub fn worker_io_mut(&mut self, worker: usize) -> Option<&mut B> {
        match worker {
            0 => Some(&mut self.worker.io),
            n => self.others.get_mut(n - 1).map(|other| &mut other.io),
        }
    }

    /// Takes the other workers out ([`Fe::with_workers`]), each to be stepped on
    /// a thread of its own. From then on [`Fe::step`] steps worker 0 only. Each
    /// must keep being stepped while the `Fe` runs: the control task answers a
    /// table change only once every worker moved to it.
    pub fn detach_workers(&mut self) -> Vec<OtherWorker<B>> {
        std::mem::take(&mut self.others)
    }

    /// Accepts a table connection that may write `writes` (see [`writers`]).
    ///
    /// Fails after [`Fe::detach_control`]: the connection is then the [`Control`]'s
    /// to accept.
    pub fn attach(&mut self, stream: UnixStream, writes: &[u64]) -> io::Result<()> {
        match &mut self.control {
            Some(control) => control.server.attach(stream, writes),
            None => Err(io::Error::new(
                ErrorKind::Unsupported,
                "the control task was detached",
            )),
        }
    }

    /// Takes the control task out, to be stepped on another thread; `None` when it
    /// was taken before. From then on [`Fe::step`] steps the worker only.
    pub fn detach_control(&mut self) -> Option<Control> {
        let control = self.control.take()?;
        self.worker.detached = true;
        Some(Control(control))
    }

    /// Moves the handover's writes (to the kernel, the TAP devices and the control
    /// processes) to the returned task, to be stepped on another thread. The
    /// worker keeps reading. `None` once taken, or when a socket cannot be given
    /// a second handle.
    pub fn detach_handover(&mut self) -> Option<HandoverTask> {
        if self.worker.writer.is_some() {
            return None;
        }
        let endpoints = self.worker.handover.try_clone().ok()?;
        let (to_writer, from_worker) = mpsc::channel();
        let (to_worker, from_writer) = mpsc::channel();
        self.worker.writer = Some((to_writer, from_writer));
        Some(HandoverTask::new(
            endpoints,
            self.worker.handover_names.clone(),
            from_worker,
            to_worker,
        ))
    }

    /// Whether the [`Control`] taken out of this is gone: the tables will not change
    /// any more.
    pub fn control_gone(&self) -> bool {
        self.worker.control_gone
    }

    /// Uses `socket` to pass ARP to the neighbor process and to take frames back.
    /// It replaces an earlier one, for when the neighbor process restarts.
    pub fn attach_punt(&mut self, socket: UnixDatagram) -> io::Result<()> {
        socket.set_nonblocking(true)?;
        self.worker.handover.attach_punt(socket, None);
        self.worker.endpoints_changed();
        Ok(())
    }

    /// Like [`Fe::attach_punt`] for a socket bound at a fixed path that is not
    /// connected: ARP is sent to the socket at `peer`, and frames are taken from
    /// whoever sends them. A neighbor process that restarts binds the same path again.
    pub fn attach_punt_to(&mut self, socket: UnixDatagram, peer: PathBuf) -> io::Result<()> {
        socket.set_nonblocking(true)?;
        self.worker.handover.attach_punt(socket, Some(peer));
        self.worker.endpoints_changed();
        Ok(())
    }

    /// Binds the sockets to the control processes the punt classes name under
    /// `dir`, the socket directory (`fe/punt/<name>.sock`), from the next table change.
    pub fn set_punt_dir(&mut self, dir: PathBuf) {
        self.worker.handover.set_control_dir(dir);
    }

    /// Uses the connected `socket` for control process `name` of the punt classes,
    /// instead of one under the socket directory.
    pub fn attach_control(&mut self, name: &str, socket: UnixDatagram) -> io::Result<()> {
        self.worker.handover.attach_control(name, socket)?;
        self.worker.endpoints_changed();
        Ok(())
    }

    /// Uses `pipe` to hand the traffic addressed to the router in `vrf` to the kernel,
    /// and to send the kernel's packets out. Without a pipe, core answers Echo
    /// Requests itself and drops the rest.
    pub fn attach_local(&mut self, vrf: &str, pipe: Box<dyn LocalPipe>) {
        self.worker.handover.attach_local(vrf, pipe);
        self.worker.endpoints_changed();
    }

    /// Stops handing VRF `vrf`'s traffic to the kernel (its device went away).
    pub fn detach_local(&mut self, vrf: &str) {
        self.worker.handover.detach_local(vrf);
        self.worker.endpoints_changed();
    }

    /// The interfaces whose IS-IS and OSPF go to their TAP device, by the punt
    /// classes of the current tables.
    pub fn tap_interfaces(&self) -> Vec<String> {
        self.worker
            .tables
            .punt
            .taps()
            .into_iter()
            .filter_map(|id| self.worker.tables.interface_names.get(usize::from(id.0)))
            .filter(|name| !name.is_empty())
            .cloned()
            .collect()
    }

    /// Uses `pipe`, one Ethernet frame per message, as the TAP device of
    /// `interface` ([`tap`]).
    pub fn attach_tap(&mut self, interface: &str, pipe: Box<dyn LocalPipe>) {
        self.worker.handover.attach_tap(interface, pipe);
        self.worker.endpoints_changed();
    }

    /// Stops using the TAP device of `interface`.
    pub fn detach_tap(&mut self, interface: &str) {
        self.worker.handover.detach_tap(interface);
        self.worker.endpoints_changed();
    }

    /// The ports that must take frames for every MAC address (promiscuous mode),
    /// in port order: the bridge members, and the parents of VLAN sub-interfaces
    /// that are members. A member takes frames for the hosts behind it and for the
    /// IRB, whose MAC address is not the port's.
    pub fn promiscuous_ports(&self) -> Vec<String> {
        let mut wanted = vec![false; self.worker.ports.len()];
        let bridges = (0..self.worker.bridge_names.len()).filter_map(|b| u16::try_from(b).ok());
        for bridge in bridges {
            for &member in self.worker.bridges.members(bridge) {
                let port = self
                    .worker
                    .tables
                    .vlans
                    .iter()
                    .find(|v| v.sub == member)
                    .map_or(member, |v| v.parent);
                if let Some(w) = wanted.get_mut(usize::from(port.0)) {
                    *w = true;
                }
            }
        }
        self.worker
            .ports
            .iter()
            .zip(wanted)
            .filter(|(_, w)| *w)
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Whether the link of `interface` is up, given whether each port's link is up
    /// (`ports_up`, in port order): down when the current tables do not enable it;
    /// a VLAN sub-interface's follows its parent's; an IRB's is up while one of its
    /// members' is, a tunnel member counting as up; another's (a tunnel's, a PPPoE
    /// session's, which IS-IS and OSPF do not run on) is up.
    pub fn link_up(&self, interface: &str, ports_up: &[bool]) -> bool {
        interface_id(&self.worker.tables.interface_names, interface)
            .is_some_and(|id| self.interface_link_up(id, ports_up))
    }

    fn interface_link_up(&self, id: IfId, ports_up: &[bool]) -> bool {
        if !self.worker.tables.active.contains(&id) {
            return false;
        }
        let member_up = |member: IfId| {
            let port = self
                .worker
                .tables
                .vlans
                .iter()
                .find(|v| v.sub == member)
                .map_or(member, |v| v.parent);
            if !self.worker.tables.active.contains(&port) {
                return false;
            }
            if usize::from(port.0) < self.worker.ports.len() {
                ports_up.get(usize::from(port.0)).copied().unwrap_or(false)
            } else {
                true
            }
        };
        match self.worker.bridges.irb_of(id) {
            Some(bridge) => self
                .worker
                .bridges
                .members(bridge)
                .iter()
                .any(|&m| member_up(m)),
            None => member_up(id),
        }
    }

    /// The ports, in order: port `i` is `IfId(i)`.
    pub fn ports(&self) -> &[String] {
        &self.worker.ports
    }

    /// The VRFs of the current tables, the default VRF first.
    pub fn vrfs(&self) -> &[String] {
        &self.worker.tables.names
    }

    pub fn io_mut(&mut self) -> &mut B {
        &mut self.worker.io
    }

    pub fn counters(&self) -> FeCounters {
        let mut counters = self.worker.counters;
        for other in &self.others_counters {
            counters.batches += other.batches.load(Ordering::Relaxed);
            counters.forwarded += other.forwarded.load(Ordering::Relaxed);
            counters.dropped += other.dropped.load(Ordering::Relaxed);
            counters.handed_to_owner += other.handed.load(Ordering::Relaxed);
            counters.handed_dropped += other.handed_dropped.load(Ordering::Relaxed);
        }
        for b in self.worker.bridges.table.counters() {
            counters.bridge_learned += b.learned;
            counters.bridge_moved += b.moved;
            counters.bridge_aged += b.aged;
            counters.bridge_limited += b.limited;
            counters.bridge_forwarded += b.forwarded;
            counters.bridge_flooded += b.flooded;
            counters.bridge_flood_dropped += b.flood_dropped;
            counters.bridge_dropped += b.dropped + b.filtered;
        }
        counters
    }

    /// Each bridge's counters, by name.
    pub fn bridge_counters(&self) -> Vec<(String, ruster_core::BridgeCounters)> {
        self.worker
            .bridge_names
            .iter()
            .cloned()
            .zip(self.worker.bridges.table.counters())
            .collect()
    }

    /// Every entry of the bridges' MAC address tables, with its bridge's name.
    pub fn bridge_entries(&self) -> Vec<(String, ruster_core::MacEntry)> {
        self.worker
            .bridges
            .table
            .entries()
            .filter_map(|e| {
                Some((
                    self.worker.bridge_names.get(usize::from(e.bridge))?.clone(),
                    e,
                ))
            })
            .collect()
    }

    /// Each class of the punt table, by name: what it handed over and dropped.
    pub fn punt_counters(&self) -> Vec<(String, PuntCounters)> {
        self.worker.limits.counters()
    }

    /// The current tables; `None` after [`Fe::detach_control`].
    pub fn store(&self) -> Option<&Store> {
        self.control.as_ref().map(|control| control.server.store())
    }
}

impl<B> Worker<B>
where
    B: PacketIo + GeneratedPacketIo,
{
    /// Moves to the last version the control task built, if there is a new one,
    /// then forwards a batch and sends the frames the control processes gave back.
    fn step(&mut self, now_ms: u64) -> bool {
        self.now_ms = now_ms;
        self.count_returned();
        let mut last = None;
        loop {
            match self.versions.try_recv() {
                Ok(ToWorker::Version(version)) => last = Some(*version),
                Ok(ToWorker::Synced(number)) => self.synced = number,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.control_gone = true;
                    break;
                }
            }
        }
        if let Some(version) = last {
            self.take(version);
        }
        // See `HANDED_IN_EVERY`.
        let read_handed_in = self.busy_steps < BUSY_STEPS || self.unread_steps >= HANDED_IN_EVERY;
        self.unread_steps = if read_handed_in {
            0
        } else {
            self.unread_steps + 1
        };
        let worked = self.worker(now_ms, read_handed_in);
        // Frames held for the control task's answer go out whatever the ports do.
        let injected = (read_handed_in || self.held.is_some()) && self.inject();
        self.write_handed();
        worked || injected
    }

    /// Leaves the bytes `fill` writes (if it says they are good) to the handover,
    /// to be written to `to` at the end of the step. Counted as not written when
    /// they are not good or the list is full.
    fn hand(&mut self, to: handover::Where, fill: impl FnOnce(&mut Vec<u8>) -> bool) {
        let mut bytes = self.buffer();
        let good = fill(&mut bytes);
        self.leave(to, bytes, good);
    }

    /// An empty buffer for [`Self::leave`].
    fn buffer(&mut self) -> Vec<u8> {
        let mut bytes = self.spare.pop().unwrap_or_default();
        bytes.clear();
        bytes
    }

    /// Leaves `bytes` to the handover if they are `good` and the list has room;
    /// else counts them as not written.
    fn leave(&mut self, to: handover::Where, bytes: Vec<u8>, good: bool) {
        if good && self.outbox.len() < HANDED_PER_STEP {
            self.outbox.push(handover::Out { to, bytes });
        } else {
            self.spare.push(bytes);
            self.count_written(to, false);
        }
    }

    /// Writes a port's `frame` that core sent to kernel interface `egress`, within
    /// the punt limits, and counts it.
    fn counted_to_kernel(&mut self, egress: IfId, frame: &[u8], now_ms: u64) {
        let packet = frame.get(ETHERNET_HEADER..).unwrap_or_default();
        let vrf = self
            .tables
            .kernel
            .iter()
            .position(|&kernel| kernel == egress);
        // From the kernel itself: by its kind, as no interface names it.
        let class = punt_table::built_in(local::kind(packet));
        if self.admit_to_kernel(class, vrf, now_ms) && self.write_kernel(egress, frame) {
            self.counters.to_kernel += 1;
            self.limits.handed(class);
        } else {
            self.counters.to_kernel_dropped += 1;
        }
    }

    /// Has the handover write what the step left, in order, and counts each; or
    /// sends it to the handover's thread, which sends back what it wrote.
    fn write_handed(&mut self) {
        if self.outbox.is_empty() {
            return;
        }
        if let Some((to_writer, _)) = &self.writer {
            let outs = std::mem::take(&mut self.outbox);
            if let Err(error) = to_writer.send(handover::ToWriter::Write(self.version, outs)) {
                // The handover's thread is gone: nothing is written.
                self.writer = None;
                if let handover::ToWriter::Write(_, outs) = error.0 {
                    for out in outs {
                        self.count_written(out.to, false);
                    }
                }
            }
            return;
        }
        let mut outbox = std::mem::take(&mut self.outbox);
        for out in outbox.drain(..) {
            let sent = self.handover.write_out(&self.handover_names, &out);
            self.count_written(out.to, sent);
            if self.spare.len() < HANDED_PER_STEP {
                self.spare.push(out.bytes);
            }
        }
        self.outbox = outbox;
    }

    /// Counts what the handover's thread wrote. Those left under other tables
    /// are counted without their punt class, whose number may now be another's.
    fn count_returned(&mut self) {
        loop {
            let Some((_, from_writer)) = &self.writer else {
                return;
            };
            let Ok(written) = from_writer.try_recv() else {
                return;
            };
            let current = written.version == self.version;
            for (out, sent) in written.outs.into_iter().zip(written.sent) {
                self.count_written_as(out.to, sent, current);
                if self.spare.len() < HANDED_PER_STEP {
                    self.spare.push(out.bytes);
                }
            }
        }
    }

    /// Sends `message` to the handover's thread, if there is one.
    fn tell_writer(&mut self, message: handover::ToWriter) {
        if let Some((to_writer, _)) = &self.writer {
            if to_writer.send(message).is_err() {
                self.writer = None;
            }
        }
    }

    /// Gives the handover's thread the endpoints again, after one changed.
    fn endpoints_changed(&mut self) {
        if self.writer.is_none() {
            return;
        }
        match self.handover.try_clone() {
            Ok(endpoints) => self.tell_writer(handover::ToWriter::Endpoints(Box::new(endpoints))),
            Err(error) => eprintln!("ruster-fe: the handover's endpoints: {error}"),
        }
    }

    /// Counts a write left to the handover, written or not.
    fn count_written(&mut self, to: handover::Where, sent: bool) {
        self.count_written_as(to, sent, true);
    }

    /// The same, with its punt class only if `classed`.
    fn count_written_as(&mut self, to: handover::Where, sent: bool, classed: bool) {
        let class = match to {
            handover::Where::Neighbor(class) => {
                if sent {
                    self.counters.arp_to_control += 1;
                } else {
                    self.counters.arp_to_control_dropped += 1;
                }
                class
            }
            handover::Where::Control(class) => Some(class),
            handover::Where::Tap(_, class) => {
                if sent {
                    self.counters.to_tap += 1;
                } else {
                    self.counters.to_tap_dropped += 1;
                }
                Some(class)
            }
            handover::Where::Kernel(_, class) => {
                if sent {
                    self.counters.to_kernel += 1;
                } else {
                    self.counters.to_kernel_dropped += 1;
                }
                Some(class)
            }
            handover::Where::Generated(_) => {
                if !sent {
                    self.counters.to_kernel_dropped += 1;
                }
                None
            }
        };
        if let Some(class) = class.filter(|_| classed) {
            if sent {
                self.limits.handed(class);
            } else {
                self.limits.dropped(class);
            }
        }
    }

    /// Replaces the tables with `version`'s. State that names the old tables'
    /// interfaces is dropped or moved, as each part below says.
    fn take(&mut self, (built, publication, nat): Version) {
        // The control task builds the next version on these ids.
        let _ = self
            .to_control
            .send(FromWorker::Using(built.interface_names.clone()));
        // The tracker's entries name the old tables' egress, neighbors and
        // translations: later fragments of those datagrams are dropped.
        self.fragment_tracking.flush_with_key(fragments::key());
        // Queued ICMP errors and staged fragments name the old tables' interfaces,
        // whose numbers may now be another interface's: they are dropped.
        self.fragmentation.flush();
        while self.icmpv4_errors.discard_front() {}
        // The ICMP error rate limits, or the defaults when none are set (core's:
        // 100 ms for IPv4; 10 at once and one every 10 ms for IPv6).
        let (ipv4_interval, ipv6_burst, ipv6_interval) = built.icmp_errors.unwrap_or((100, 10, 10));
        // A state lives at least as long as its interval, so any interval works.
        let interval = u64::from(ipv4_interval);
        if let Ok(policy) = ruster_core::Icmpv4ErrorPolicy::new(interval, interval.max(60_000)) {
            self.icmpv4_errors.set_policy(policy);
        }
        self.control
            .set_error_limit(ipv6_burst, u64::from(ipv6_interval));
        // So do the tunnel packets put back together and the neighbors' "used"
        // marks.
        self.reassembled.clear();
        self.used.clear();
        // As for the firewall: a NAT that cannot move stays bound to the old
        // tables, and core drops what it would have translated.
        let mut stuck = false;
        if let Err(error) = nat::Nat::publish(&mut self.nat, nat) {
            eprintln!("ruster-fe: {error}");
            stuck = true;
        }
        // Until a move succeeds the old firewall stays, bound to the old tables:
        // core then drops what it would have checked.
        // With the IPv6 tables, so that IPv6 flows whose route moved go, and with
        // every VRF's, so that flows leaked in from another VRF go when its
        // route changed.
        let current: Vec<_> = self
            .tables
            .vrfs
            .iter()
            .map(|vrf| vrf.owner.snapshot().with_ipv6(&vrf.ipv6))
            .collect();
        let next: Vec<_> = built
            .vrfs
            .iter()
            .map(|vrf| vrf.owner.snapshot().with_ipv6(&vrf.ipv6))
            .collect();
        if let Err(error) = firewall::Firewall::publish(
            &mut self.firewall,
            publication,
            current[0].with_vrfs(&current, &self.tables.by_ingress),
            next[0].with_vrfs(&next, &built.by_ingress),
        ) {
            eprintln!("ruster-fe: {error}");
            stuck = true;
        }
        self.hand_all.store(stuck, Ordering::Relaxed);
        if self.tables.names != built.names {
            // The per-VRF buckets start again.
            self.limits.update(&built.punt, 0);
        }
        self.limits.update(&built.punt, built.names.len());
        self.punt_frames = built.punt.frame_matches();
        self.handover.controls.follow(built.punt.controls());
        self.kernel_bits = ruster_core::kernel_ingress_bits(&built.kernel);
        let old = std::mem::replace(&mut self.tables, built);
        // Freed on the control task's side; here only when it is gone.
        let _ = self.to_control.send(FromWorker::Retired(old));
        self.version += 1;
        self.handover_names = handover::Names {
            interfaces: self.tables.interface_names.clone(),
            vrfs: self.tables.names.clone(),
            controls: (0..self.tables.punt.len())
                .map(|class| match &self.tables.punt.get(class).destination {
                    PuntDestination::Control(name) => Some(name.clone()),
                    _ => None,
                })
                .collect(),
        };
        self.endpoints_changed();
        self.tell_writer(handover::ToWriter::Names(self.handover_names.clone()));
        // A bridge that stays keeps what it learned on the members it keeps.
        let old_of_new: Vec<Option<u16>> = self
            .tables
            .bridges
            .iter()
            .map(|(name, _)| {
                let at = self.bridge_names.iter().position(|old| old == name)?;
                u16::try_from(at).ok()
            })
            .collect();
        let (names, configs): (Vec<String>, Vec<_>) = self.tables.bridges.iter().cloned().unzip();
        self.bridge_names = names;
        let left = self
            .bridges
            .publish(configs, &old_of_new, &self.tables.bridge_statics);
        if left > 0 {
            eprintln!("ruster-fe: {left} static MAC addresses left out: the table is full");
        }
    }

    /// Forwards one batch by the tables the worker has. Whether it did anything.
    fn worker(&mut self, now_ms: u64, read_handed_in: bool) -> bool {
        // The lists a batch fills are kept from step to step, emptied.
        let mut trace = std::mem::take(&mut self.trace);
        let before = self.busy_steps;
        self.busy_steps = 0;
        let worked = self.forward(now_ms, read_handed_in, before, &mut trace);
        trace.clear();
        self.trace = trace;
        worked
    }

    /// `busy_before` is [`Self::busy_steps`] as the last step left it; this step
    /// sets it again, to zero wherever it ends without packets from the ports.
    fn forward(
        &mut self,
        now_ms: u64,
        read_handed_in: bool,
        busy_before: u8,
        trace: &mut FeTrace,
    ) -> bool {
        // The kernel's packets join the ports' in one batch, after them.
        let mut kernel_frames = if read_handed_in {
            let mut frames = self.read_kernel();
            frames.append(&mut self.read_taps(now_ms));
            frames
        } else {
            Vec::new()
        };
        let handed_in = kernel_frames.len();
        kernel_frames.append(&mut self.reassembled);
        // What the other workers handed over joins as if received here.
        while kernel_frames.len() < RX_BUDGET {
            let Ok(handed) = self.from_others.try_recv() else {
                break;
            };
            kernel_frames.extend(handed.frames);
            if handed.tables == Arc::as_ptr(&self.tables) as usize {
                let room = USED_MAX.saturating_sub(self.used.len());
                self.used.extend(handed.used.into_iter().take(room));
            }
        }
        // One snapshot per VRF; each packet uses its ingress interface's.
        let tables = &*self.tables;
        let handover = &self.handover;
        let snapshots = vrf_snapshots(tables, &self.kernel_bits, |name| handover.has_local(name));
        let mut firewall = self.firewall.as_mut().and_then(firewall::Firewall::service);
        // IPv6 goes through the firewall too; should its runtime be missing, IPv6 is
        // not forwarded through the default VRF rather than forwarded unchecked.
        let snapshot = outer_snapshot(&snapshots, tables, &self.kernel_bits, &self.punt_frames)
            .with_now(MonotonicMillis(now_ms))
            .with_ipv6_forwarding_blocked(firewall.is_some());
        let Ok(ports) = self.io.receive(RX_BUDGET) else {
            self.counters.from_kernel_dropped += kernel_frames.len() as u64;
            return false;
        };
        let mut from_kernel = kernel::Outcome::default();
        let batch = kernel::Joined {
            ports,
            kernel_ids: &self.kernel_bits,
            kernel: kernel_frames.into_iter(),
            outcome: &mut from_kernel,
            kernel_done: 0,
        };
        self.control.clear();
        let now = MonotonicMillis(now_ms);
        self.control.set_clock(now);
        let mut services = Services {
            icmpv4_errors: Some(&mut self.icmpv4_errors),
            firewall: firewall
                .as_mut()
                .map(|(config, runtime)| (&*config, &mut **runtime)),
            fragmentation: Some(&mut self.fragmentation),
            fragment_tracking: Some(&mut self.fragment_tracking),
            ..Services::default()
        };
        if let Some(nat) = self.nat.as_mut() {
            nat.services(&mut services);
        }
        self.bridges.clear_flood();
        if !self.bridges.is_empty() {
            services.bridges = Some(&mut self.bridges);
        }
        let report =
            forward_batch_with_control(batch, &snapshot, &mut self.control, services, &mut *trace);
        // Unsolicited inbound SYNs whose wait is over get their Port Unreachable,
        // also in a batch with no packets: the wait ends by the clock.
        let answered = self.nat.as_mut().map_or(0, |nat| {
            nat.answer_unsolicited_syns(
                &mut self.icmpv4_errors,
                &snapshot,
                firewall
                    .as_mut()
                    .map(|(config, runtime)| (&*config, &mut **runtime)),
                now,
                &mut *trace,
            )
        });
        self.bridges.table.age(now_ms, AGING_PER_STEP);
        self.send_flood();
        // What the ports brought, without what was handed in.
        if report.received > handed_in {
            self.busy_steps = (busy_before + 1).min(BUSY_STEPS);
        }
        if report.received == 0 && answered == 0 {
            return false;
        }
        self.counters.batches += 1;
        self.counters.forwarded += report.tx_requested as u64;
        self.counters.dropped += report.dropped as u64;
        self.counters.arp_to_control_dropped += trace.overflow;
        self.counters.overlay_too_big += trace.overlay_too_big;
        self.counters.overlay_dropped += trace.overlay_dropped;
        self.counters.from_kernel_dropped += from_kernel.dropped;
        for (egress, frame) in from_kernel.to_kernel {
            self.counted_to_kernel(egress, &frame, now_ms);
        }
        // A frame of a port handed over by another worker, to the kernel: as one
        // received here (the punt limits and counts).
        let (handed_to_kernel, sent): (Vec<_>, Vec<_>) = from_kernel
            .sent
            .into_iter()
            .partition(|(egress, frame)| !frame.kernel && self.tables.kernel.contains(egress));
        for (egress, frame) in sent {
            let sent = if self.tables.kernel.contains(&egress) {
                self.write_kernel(egress, frame.bytes())
            } else {
                self.send_port(egress, None, frame.bytes())
            };
            match (frame.kernel, sent) {
                (true, true) => self.counters.from_kernel += 1,
                (true, false) => self.counters.from_kernel_dropped += 1,
                (false, true) => {}
                (false, false) => self.counters.dropped += 1,
            }
        }
        for (egress, frame) in handed_to_kernel {
            self.counted_to_kernel(egress, frame.bytes(), now_ms);
        }

        // Until one cannot be built or allocated (it stays queued for the next batch).
        // Those for an interface that is not a port (the kernel's, a VLAN
        // sub-interface, a PPPoE session, a tunnel) are caught and sent after.
        let ports = self.ports.len();
        let mut caught = Vec::new();
        while let Ok(Some(report)) = execute_one_icmpv4_error(
            &mut kernel::WithKernel {
                io: &mut self.io,
                ports,
                caught: &mut caught,
            },
            &mut self.icmpv4_errors,
            now,
            &mut NoTrace,
        ) {
            if report.allocation_error.is_some() || report.build_error.is_some() {
                // One for an egress the backend does not have would stay at the front
                // and block every later error: drop it. Others wait for the next batch.
                let unknown = usize::from(report.action.egress.0) >= self.ports.len();
                if unknown {
                    self.icmpv4_errors.discard_front();
                    continue;
                }
                break;
            }
            self.counters.icmp_errors_sent += 1;
        }
        let mut budget = fragments::FRAMES_PER_BATCH;
        while let Some(report) = execute_one_ipv4_fragmentation(
            &mut kernel::WithKernel {
                io: &mut self.io,
                ports,
                caught: &mut caught,
            },
            &mut self.fragmentation,
            &mut budget,
        ) {
            if matches!(report.outcome, ruster_core::Ipv4FragmentOutcome::Sent) {
                self.counters.fragments_sent += u64::from(report.fragments);
            } else {
                self.counters.fragmentation_dropped += 1;
            }
        }
        for (egress, frame) in caught {
            if !self.send_generated(egress, &frame) {
                self.counters.generated_dropped += 1;
            }
        }
        let arp_class = punt_table::built_in(PuntKind::Arp);
        for arp in &trace.arp {
            if self.limits.admit(arp_class, None, now_ms) {
                self.punt_arp(arp);
            } else {
                self.counters.arp_to_control_dropped += 1;
            }
        }
        for index in 0..self.control.errors().len() {
            let error = &self.control.errors()[index];
            let (egress, bytes) = (error.ingress, error.bytes().to_vec());
            if self.send_generated(egress, &bytes) {
                self.counters.icmp_errors_sent += 1;
            }
        }
        for index in 0..self.control.frames().len() {
            let frame = &self.control.frames()[index];
            let (kind, ingress, bytes) = (frame.kind, frame.ingress, frame.bytes().to_vec());
            match kind {
                ControlKind::Punt(class) => {
                    let class = usize::from(class);
                    if self.tables.punt.get(class).destination == PuntDestination::Tap {
                        self.hand_to_tap(class, ingress, &bytes, now_ms);
                    } else {
                        self.hand_to_control(class, ingress, &bytes, now_ms);
                    }
                }
                ControlKind::Neighbor => {
                    let class = punt_table::built_in(PuntKind::Nd);
                    if self.limits.admit(class, None, now_ms) {
                        self.punt_frame(ingress, punt::reason::ND, Some(class), &bytes);
                    } else {
                        self.counters.arp_to_control_dropped += 1;
                    }
                }
                ControlKind::Local => {
                    let packet = &bytes[ETHERNET_HEADER..];
                    let class = self.tables.punt.of_local(ingress, packet);
                    match self.tables.punt.get(class).destination {
                        PuntDestination::Control(_) => {
                            self.hand_to_control(class, ingress, &bytes, now_ms);
                        }
                        PuntDestination::Tap => self.hand_to_tap(class, ingress, &bytes, now_ms),
                        _ => self.send_to_kernel(ingress, class, packet, now_ms),
                    }
                }
                ControlKind::TunnelFragment => {
                    if let Some(whole) = self.reassembly.add(ingress, &bytes, now_ms) {
                        self.counters.tunnel_reassembled += 1;
                        self.reassembled
                            .push(kernel::Frame::from_ethernet(ingress, &whole));
                    }
                }
            }
        }
        if self.used.len() < USED_MAX {
            self.used.extend(trace.used.drain(..));
        }
        for &(egress, target) in &trace.misses {
            self.resolve_request(egress, target, now_ms);
        }
        true
    }

    /// Sends each frame the bridges flooded in the last batch out of every member of
    /// its bridge but the one it came in on.
    fn send_flood(&mut self) {
        if self.bridges.flood().is_empty() {
            return;
        }
        let mut trace = FeTrace::default();
        let mut failed = Vec::new();
        {
            let mut members = Members::of(self, &mut trace);
            for frame in members.bridges.flood() {
                let mut dropped = 0;
                for &member in members.bridges.members(frame.bridge) {
                    if members.floods_to(frame.from, member)
                        && !members.send(member, None, frame.bytes())
                    {
                        dropped += 1;
                    }
                }
                if dropped > 0 {
                    failed.push((frame.bridge, dropped));
                }
            }
        }
        self.bridges.clear_flood();
        for (bridge, dropped) in failed {
            for _ in 0..dropped {
                self.bridges.table.count_flood_dropped(bridge);
            }
        }
        self.after_members(trace);
    }

    /// Counts what sending to the members dropped, and asks for the next hops
    /// toward an overlay's remote end that were missing.
    fn after_members(&mut self, trace: FeTrace) {
        self.counters.overlay_too_big += trace.overlay_too_big;
        self.counters.overlay_dropped += trace.overlay_dropped;
        for (egress, target) in trace.misses {
            self.resolve_request(egress, target, self.now_ms);
        }
    }

    fn punt_arp(&mut self, arp: &ArpEvent) {
        let body = arp.body();
        let class = punt_table::built_in(PuntKind::Arp);
        self.punt_frame(arp.ingress, punt::reason::ARP, Some(class), &body);
    }

    /// Sends `frame` to the neighbor process; counted with the ARP counters, and
    /// with those of punt class `class`.
    fn punt_frame(&mut self, ingress: IfId, reason: u16, class: Option<usize>, frame: &[u8]) {
        // An id no interface has now (a hole the tables left) is not sent.
        if name_at(&self.tables.interface_names, usize::from(ingress.0)).is_none_or(str::is_empty) {
            return;
        }
        if !self.handover.has_punt() {
            self.counters.arp_to_control_dropped += 1;
            if let Some(class) = class {
                self.limits.dropped(class);
            }
            return;
        }
        let mut message = self.buffer();
        let good = Punt {
            direction: Direction::ToControl,
            reason,
            interface: &self.tables.interface_names[usize::from(ingress.0)],
            frame,
        }
        .encode(&mut message)
        .is_ok();
        self.leave(handover::Where::Neighbor(class), message, good);
    }

    /// Sends the whole `frame` of punt class `class` to its control process.
    fn hand_to_control(&mut self, class: usize, ingress: IfId, frame: &[u8], now_ms: u64) {
        let entry = self.tables.punt.get(class);
        if !matches!(entry.destination, PuntDestination::Control(_)) {
            self.limits.dropped(class);
            return;
        }
        let why = match entry.matches {
            PuntMatch::Kind(PuntKind::PppoeDiscovery) => punt::reason::PPPOE_DISCOVERY,
            PuntMatch::Kind(PuntKind::PppControl) => punt::reason::PPP_CONTROL,
            _ => punt::reason::IP,
        };
        if name_at(&self.tables.interface_names, usize::from(ingress.0)).is_none_or(str::is_empty) {
            self.limits.dropped(class);
            return;
        }
        if !self.limits.admit(class, None, now_ms) {
            return;
        }
        let mut message = self.buffer();
        let good = Punt {
            direction: Direction::ToControl,
            reason: why,
            interface: &self.tables.interface_names[usize::from(ingress.0)],
            frame,
        }
        .encode(&mut message)
        .is_ok();
        self.leave(handover::Where::Control(class), message, good);
    }

    /// Writes the whole `frame` of punt class `class` to the TAP device of the
    /// interface it came in on.
    fn hand_to_tap(&mut self, class: usize, ingress: IfId, frame: &[u8], now_ms: u64) {
        let tap = self
            .tables
            .interface_names
            .get(usize::from(ingress.0))
            .filter(|name| !name.is_empty() && self.handover.has_tap(name));
        if tap.is_none() {
            self.limits.dropped(class);
            self.counters.to_tap_dropped += 1;
            return;
        }
        if !self.limits.admit(class, None, now_ms) {
            self.counters.to_tap_dropped += 1;
            return;
        }
        self.hand(handover::Where::Tap(ingress, class), |bytes| {
            bytes.extend_from_slice(frame);
            true
        });
    }

    /// Takes what the kernel wrote to the TAP devices: frames for the link are
    /// sent out of their interface now; the router's other packets are returned,
    /// for the batch, as packets from their VRF's kernel interface.
    fn read_taps(&mut self, now_ms: u64) -> Vec<kernel::Frame> {
        let mut routed = Vec::new();
        let names = self.handover.tap_names();
        if names.is_empty() {
            return routed;
        }
        // One byte more than taken, to see a frame that was cut short.
        let mut buf = [0_u8; PUNT_MAX + 1];
        for name in names {
            let id = interface_id(&self.tables.interface_names, &name)
                .filter(|id| self.tables.active.contains(id));
            for _ in 0..INJECT_PER_STEP {
                let Some(n) = self.handover.recv_tap(&name, &mut buf) else {
                    break;
                };
                if n > PUNT_MAX {
                    self.counters.from_tap_dropped += 1;
                    continue;
                }
                let vrf = id.and_then(|id| self.tables.by_ingress.get(usize::from(id.0)));
                let (Some(id), Some(&at)) = (id, vrf) else {
                    self.counters.from_tap_dropped += 1;
                    continue;
                };
                let at = usize::from(at);
                let sent = match tap::sort(&buf[..n]) {
                    tap::FromTap::Link => self.send_generated(id, &buf[..n]),
                    tap::FromTap::Neighbor(address) => {
                        match self
                            .tables
                            .vrfs
                            .get(at)
                            .and_then(|v| v.ipv6.neighbor(id, address))
                        {
                            Some(mac) => {
                                buf[..6].copy_from_slice(&mac.0);
                                self.send_generated(id, &buf[..n])
                            }
                            None => {
                                self.resolve_request(id, IpAddr::V6(address.into()), now_ms);
                                false
                            }
                        }
                    }
                    tap::FromTap::Routed => match self.tables.kernel.get(at) {
                        Some(&kernel) => {
                            routed.push(kernel::Frame::new(kernel, at, &buf[ETHERNET_HEADER..n]));
                            true
                        }
                        None => false,
                    },
                    tap::FromTap::Drop => false,
                };
                if sent {
                    self.counters.from_tap += 1;
                } else {
                    self.counters.from_tap_dropped += 1;
                }
            }
        }
        routed
    }

    fn resolve_request(&mut self, egress: IfId, address: IpAddr, now_ms: u64) {
        let last = self.last_resolve.get(&(egress, address)).copied();
        if last.is_some_and(|at| now_ms.saturating_sub(at) < RESOLVE_INTERVAL_MS) {
            return;
        }
        let Some(name) = self
            .tables
            .interface_names
            .get(usize::from(egress.0))
            .filter(|name| !name.is_empty())
        else {
            return;
        };
        if self.last_resolve.len() >= RESOLVE_REMEMBERED {
            self.last_resolve
                .retain(|_, at| now_ms.saturating_sub(*at) < RESOLVE_INTERVAL_MS);
            if self.last_resolve.len() >= RESOLVE_REMEMBERED {
                self.counters.resolve_requests_dropped += 1;
                return;
            }
        }
        self.last_resolve.insert((egress, address), now_ms);
        let mut payload = Vec::new();
        ResolveRequest {
            interface: name.clone(),
            address,
        }
        .encode(&mut Encoder::new(&mut payload));
        // Nobody is left to tell when the control task is gone.
        let _ = self.to_control.send(FromWorker::Notify(payload));
        self.counters.resolve_requests += 1;
    }

    /// Sends the frames the control processes gave back. Whether there was any.
    ///
    /// With the control task on another thread, the frames read are held until it
    /// says that the table changes that arrived before them are in the version the
    /// worker uses (see [`FromWorker::Sync`]); forwarding goes on meanwhile.
    fn inject(&mut self) -> bool {
        if !self.detached {
            let (frames, others, refused) = self.read_injected();
            self.send_injected(&frames, others);
            return !frames.is_empty() || refused;
        }
        if self.held.is_none() {
            let (frames, others, refused) = self.read_injected();
            if frames.is_empty() {
                return refused;
            }
            self.held = Some((frames, others));
            self.sync += 1;
            // If it is gone, the frames go out on the next step.
            let _ = self.to_control.send(FromWorker::Sync(self.sync));
        }
        if self.synced == self.sync || self.control_gone {
            if let Some((frames, others)) = self.held.take() {
                self.send_injected(&frames, others);
            }
        }
        // Busy while frames wait, so that the answer is seen at once.
        true
    }

    /// Reads the frames the control processes gave back: the frames, how many of
    /// them are not the neighbor process's (those come first), and whether any was
    /// refused.
    fn read_injected(&mut self) -> (Vec<Vec<u8>>, usize, bool) {
        let mut refused = 0;
        let mut frames = self
            .handover
            .controls
            .receive(INJECT_PER_STEP, PUNT_MAX, &mut refused);
        self.counters.inject_dropped += refused;
        // The neighbor process's come after the others'.
        let others = frames.len();
        // One byte more than accepted, to see a datagram that was cut short.
        let mut buf = [0_u8; PUNT_MAX + 1];
        for _ in 0..INJECT_PER_STEP {
            match self.handover.recv_punt(&mut buf) {
                Some(handover::FromPunt::Taken(n)) => frames.push(buf[..n].to_vec()),
                Some(handover::FromPunt::Refused) => self.counters.inject_dropped += 1,
                None => break,
            }
        }
        (frames, others, refused > 0)
    }

    /// Sends `frames`, of which the first `others` are not the neighbor process's.
    fn send_injected(&mut self, frames: &[Vec<u8>], others: usize) {
        for (at, message) in frames.iter().enumerate() {
            let neighbor = at >= others;
            let Ok(punt) = Punt::decode(message) else {
                self.counters.inject_dropped += 1;
                continue;
            };
            // Only out of an interface the current tables have enabled.
            let egress = interface_id(&self.tables.interface_names, punt.interface)
                .filter(|id| self.tables.active.contains(id));
            match (punt.direction, punt.reason, egress) {
                // The neighbor process reads the "used" marks, which are then cleared.
                (Direction::FromControl, punt::reason::NEIGHBOR_USED, _) if neighbor => {
                    let used: Vec<_> = self.used.drain().collect();
                    for (interface, address) in used {
                        let bytes = match address {
                            IpAddr::V4(a) => a.octets().to_vec(),
                            IpAddr::V6(a) => a.octets().to_vec(),
                        };
                        self.punt_frame(IfId(interface), punt::reason::NEIGHBOR_USED, None, &bytes);
                    }
                }
                // The other control processes' frames were checked as they came.
                (Direction::FromControl, reason, Some(egress))
                    if punt.frame.len() >= ETHERNET_HEADER
                        && if neighbor {
                            (reason == punt::reason::ARP && punt.frame[12..14] == ETHERTYPE_ARP)
                                || (reason == punt::reason::ND
                                    && punt.frame[12..14] == ETHERTYPE_IPV6)
                        } else {
                            true
                        } =>
                {
                    if self.send_generated(egress, punt.frame) {
                        self.counters.injected += 1;
                    } else {
                        self.counters.inject_dropped += 1;
                    }
                }
                _ => self.counters.inject_dropped += 1,
            }
        }
    }

    /// Whether a packet of punt class `class` may go to the kernel of the VRF at
    /// `vrf` (in the order of `vrfs`): the class goes there and is within that VRF's
    /// limit. A refused packet is counted as the class's drop.
    fn admit_to_kernel(&mut self, class: usize, vrf: Option<usize>, now_ms: u64) -> bool {
        match (&self.tables.punt.get(class).destination, vrf) {
            (PuntDestination::Kernel, Some(_)) => self.limits.admit(class, vrf, now_ms),
            _ => {
                self.limits.dropped(class);
                false
            }
        }
    }

    /// Writes a packet addressed to the router, of punt class `class`, to its VRF's
    /// kernel pipe, as the class allows.
    fn send_to_kernel(&mut self, ingress: IfId, class: usize, packet: &[u8], now_ms: u64) {
        let at = self
            .tables
            .by_ingress
            .get(usize::from(ingress.0))
            .map(|&at| usize::from(at));
        let admitted = self.admit_to_kernel(class, at, now_ms);
        match at {
            Some(at) if admitted => self.hand(handover::Where::Kernel(at, class), |bytes| {
                bytes.extend_from_slice(packet);
                true
            }),
            _ => self.counters.to_kernel_dropped += 1,
        }
    }

    /// The packets the kernel wrote to each VRF's pipe, as frames from its kernel
    /// interface.
    fn read_kernel(&self) -> Vec<kernel::Frame> {
        let mut frames = Vec::new();
        if !self.handover.any_local() {
            return frames;
        }
        let mut buf = [0_u8; PUNT_MAX];
        for (at, name) in self.tables.names.iter().enumerate() {
            let Some(&ingress) = self.tables.kernel.get(at) else {
                continue;
            };
            for _ in 0..INJECT_PER_STEP {
                match self.handover.recv_kernel(name, &mut buf) {
                    Some(n) => frames.push(kernel::Frame::new(ingress, at, &buf[..n])),
                    None => break,
                }
            }
        }
        frames
    }

    /// Writes `frame` (Ethernet) for kernel interface `egress` to its VRF's pipe,
    /// without the Ethernet header.
    fn write_kernel(&mut self, egress: IfId, frame: &[u8]) -> bool {
        let at = self.tables.kernel.iter().position(|&id| id == egress);
        match (at, frame.get(ETHERNET_HEADER..)) {
            (Some(at), Some(packet)) => {
                self.hand(handover::Where::Generated(at), |bytes| {
                    bytes.extend_from_slice(packet);
                    true
                });
                true
            }
            _ => false,
        }
    }

    /// Sends `frame` out of `egress`; out of a VLAN sub-interface's parent, tagged,
    /// for a sub-interface.
    fn send_generated(&mut self, egress: IfId, frame: &[u8]) -> bool {
        if self.tables.kernel.contains(&egress) {
            return self.write_kernel(egress, frame);
        }
        // Into a tunnel or a PPPoE session, then out of the interface below it.
        let outer = self.tables.vrfs[0]
            .owner
            .snapshot()
            .with_ipv6(&self.tables.vrfs[0].ipv6)
            .with_tunnels(&self.tables.tunnels)
            .with_srv6(&self.tables.srv6)
            .with_pppoe(&self.tables.pppoe);
        match outer.tunnel_frame(egress, frame) {
            Some(Ok((below, wrapped))) => return self.send_generated(below, &wrapped),
            Some(Err(_)) => return false,
            None => {}
        }
        match outer.srv6_frame(egress, frame) {
            Some(Ok((below, wrapped))) => return self.send_generated(below, &wrapped),
            Some(Err(_)) => return false,
            None => {}
        }
        match outer.pppoe_frame(egress, frame) {
            Some(Ok((parent, wrapped))) => return self.send_generated(parent, &wrapped),
            Some(Err(_)) => return false,
            None => {}
        }
        // Out of a bridge's own interface: to the member the destination is on,
        // or out of every member.
        if let Some(bridge) = self.bridges.irb_of(egress) {
            let Some(destination) = frame.get(..6).and_then(|d| <[u8; 6]>::try_from(d).ok()) else {
                return false;
            };
            let now_ms = self.now_ms;
            let known = self.bridges.table.send(bridge, &destination, now_ms);
            let mut trace = FeTrace::default();
            let mut sent = false;
            let mut dropped = 0;
            {
                let mut members = Members::of(self, &mut trace);
                if let Some((member, vtep)) = known {
                    sent = members.send(member, vtep, frame);
                } else {
                    for &member in members.bridges.members(bridge) {
                        if members.send(member, None, frame) {
                            sent = true;
                        } else {
                            dropped += 1;
                        }
                    }
                }
            }
            if known.is_some() {
                self.bridges.table.count_forwarded(bridge);
            } else {
                self.bridges.table.count_flood(bridge, dropped);
            }
            self.after_members(trace);
            return sent;
        }
        send_member(&mut self.io, &self.tables.vlans, egress, frame)
    }

    /// Sends `frame` out of port `port` as it is, with VLAN tag `tag` put in.
    fn send_port(&mut self, port: IfId, tag: Option<u16>, frame: &[u8]) -> bool {
        send_on_port(&mut self.io, port, tag, frame)
    }
}

/// Sends `frame` out of `egress`, a port or a VLAN sub-interface (out of its parent,
/// tagged).
fn send_member<B: GeneratedPacketIo>(
    io: &mut B,
    vlans: &[VlanBinding],
    egress: IfId,
    frame: &[u8],
) -> bool {
    send_parts(io, vlans, egress, frame, &[])
}

/// Sends `head` and `body`, one frame, out of `egress`, a port or a VLAN
/// sub-interface.
fn send_parts<B: GeneratedPacketIo>(
    io: &mut B,
    vlans: &[VlanBinding],
    egress: IfId,
    head: &[u8],
    body: &[u8],
) -> bool {
    let (port, tag) = match vlans.iter().find(|b| b.sub == egress) {
        Some(binding) => (binding.parent, Some(binding.vid)),
        None => (egress, None),
    };
    send_on_port_parts(io, port, tag, head, body)
}

/// Where the frames of bridge members go: out of ports and VLAN sub-interfaces, or
/// wrapped for an overlay and routed by the default VRF.
struct Members<'f, 't, B> {
    io: &'f mut B,
    vlans: &'f [VlanBinding],
    bridges: &'f ruster_core::Bridges,
    outer: ruster_core::ForwardingSnapshot<'f>,
    trace: &'t mut FeTrace,
}

impl<'f, 't, B: GeneratedPacketIo> Members<'f, 't, B> {
    fn of(fe: &'f mut Worker<B>, trace: &'t mut FeTrace) -> Self {
        let Worker {
            io,
            bridges,
            tables,
            ..
        } = fe;
        let build::Built {
            vlans,
            vrfs,
            tunnels,
            overlays,
            pppoe,
            unreachable,
            ..
        } = &**tables;
        let outer = vrfs[0]
            .owner
            .snapshot()
            .with_ipv6(&vrfs[0].ipv6)
            .with_tunnels(tunnels)
            .with_pppoe(pppoe)
            .with_overlays(overlays)
            .with_unreachable_neighbors(unreachable);
        Self {
            io,
            vlans,
            bridges,
            outer,
            trace,
        }
    }

    /// Sends `frame` out of `member`: for an overlay, to remote end `vtep` when it
    /// is known (a VXLAN interface's, learned with the destination), or to each of
    /// its remote ends. Whether it went out at least once.
    fn send(&mut self, member: IfId, vtep: Option<IpAddr>, frame: &[u8]) -> bool {
        let Some(overlay) = self.outer.overlay(member) else {
            return send_member(self.io, self.vlans, member, frame);
        };
        let remotes = match &vtep {
            Some(vtep) if overlay.is_vxlan() => std::slice::from_ref(vtep),
            _ => overlay.remotes(),
        };
        let bridges = self.bridges;
        let mut sent = false;
        for &remote in remotes {
            let irb = |id: IfId| bridges.irb_of(id).is_some();
            match self
                .outer
                .overlay_header(member, remote, frame, irb, self.trace)
            {
                Some(Ok(header)) => {
                    sent |= send_parts(self.io, self.vlans, header.egress, header.bytes(), frame);
                }
                Some(Err(reason)) => self.trace.overlay_drop(reason),
                None => {}
            }
        }
        sent
    }

    /// Whether a frame flooded from `from` goes out of `member`: not back where it
    /// came from, nor from one VXLAN interface to another (RFC 8365 section 8.3:
    /// each VTEP sends its own frames to every other).
    fn floods_to(&self, from: Option<IfId>, member: IfId) -> bool {
        let vxlan = |id: IfId| {
            self.outer
                .overlay(id)
                .is_some_and(ruster_core::Overlay::is_vxlan)
        };
        match from {
            Some(from) => from != member && !(vxlan(from) && vxlan(member)),
            None => true,
        }
    }
}

/// Sends `frame` out of port `port` as it is, with VLAN tag `tag` put in.
fn send_on_port<B: GeneratedPacketIo>(
    io: &mut B,
    port: IfId,
    tag: Option<u16>,
    frame: &[u8],
) -> bool {
    send_on_port_parts(io, port, tag, frame, &[])
}

/// Sends `head` and `body`, one frame, out of port `port`, with VLAN tag `tag`
/// put in.
fn send_on_port_parts<B: GeneratedPacketIo>(
    io: &mut B,
    port: IfId,
    tag: Option<u16>,
    head: &[u8],
    body: &[u8],
) -> bool {
    // An all-zero destination is what core puts on a frame to be wrapped (a
    // tunnel's, a session's): one that was not wrapped never leaves a port.
    if head.len() < ETHERNET_HEADER || head[..6] == [0; 6] {
        return false;
    }
    let extra = if tag.is_some() { 4 } else { 0 };
    let mut batch = io.begin_generated(port);
    let sent = match batch.allocate(head.len() + body.len() + extra) {
        Ok(mut lease) => {
            let bytes = lease.bytes_mut();
            let rest = match tag {
                Some(vid) => {
                    bytes[..12].copy_from_slice(&head[..12]);
                    bytes[12..14].copy_from_slice(&[0x81, 0x00]);
                    bytes[14..16].copy_from_slice(&(vid & 0x0fff).to_be_bytes());
                    bytes[16..4 + head.len()].copy_from_slice(&head[12..]);
                    4 + head.len()
                }
                None => {
                    bytes[..head.len()].copy_from_slice(head);
                    head.len()
                }
            };
            bytes[rest..].copy_from_slice(body);
            lease.commit();
            true
        }
        Err(_) => false,
    };
    let completion = batch.finish();
    sent && completion.error.is_none()
}

impl<B> Task for Fe<B>
where
    B: PacketIo + GeneratedPacketIo,
{
    fn step(&mut self, now_ms: u64) -> Progress {
        // The other workers first, so that what they hand over is forwarded in
        // the same step.
        let mut others = false;
        for other in &mut self.others {
            others |= other.step(now_ms);
        }
        let Some(control) = &mut self.control else {
            return Progress::busy(self.worker.step(now_ms) || others);
        };
        let before = control.step();
        let worked = self.worker.step(now_ms) || others;
        // The worker's notifications go out now.
        let flushed = control.step();
        before.and(flushed).and(Progress::busy(worked))
    }
}

/// A secret key for hashed tables, so no one outside can aim at their buckets.
fn hash_key() -> ruster_core::ResolutionHashKey {
    loop {
        let (a, b) = nat::words();
        if let Ok(key) = ruster_core::ResolutionHashKey::new(a, b) {
            break key;
        }
    }
}

/// ICMPv4 error slots: limiter states and queued errors, enough for one batch.
const ICMPV4_ERROR_SLOTS: usize = 64;

/// The ICMPv4 error runtime with the default policy (RFC 1812 section 4.3.2.8 rate
/// limits). Its slots are allocated once for the life of the process.
fn icmpv4_error_runtime() -> Icmpv4ErrorRuntime<'static> {
    let states =
        Box::leak(vec![Icmpv4ErrorStateSlot::EMPTY; ICMPV4_ERROR_SLOTS].into_boxed_slice());
    let actions =
        Box::leak(vec![Icmpv4ErrorActionSlot::EMPTY; ICMPV4_ERROR_SLOTS].into_boxed_slice());
    // A secret key for the limiter of NAT-translated errors, so no one outside can
    // aim at its buckets.
    let key = loop {
        let (a, b) = nat::words();
        if let Ok(key) = ruster_core::ResolutionHashKey::new(a, b) {
            break key;
        }
    };
    Icmpv4ErrorRuntime::new(Icmpv4ErrorPolicy::default(), states, actions)
        .with_translated_limit_key(key)
}

/// Generated ICMPv4 frames are counted, not traced.
struct NoTrace;

impl GeneratedIcmpv4TraceSink for NoTrace {
    fn record_generated_icmpv4(&mut self, _event: GeneratedIcmpv4Trace) {}
}

/// Turns the tables into core's tables.
struct Builder {
    ports: Vec<String>,
    /// The tables built for the last accepted store and their firewall, until the
    /// control task sends them to the worker at the end of its step.
    built: Option<(
        build::Built,
        firewall::Publication,
        Option<nat::Publication>,
    )>,
    /// What the routes came to in the last build, for the next one to start from.
    routes: Option<build::Routes>,
    /// Of the last firewall publication.
    generation: u64,
    /// The interface of each id in the tables the worker uses (it says so each time
    /// it moves to a version): a table change keeps the ids of the interfaces that
    /// stay. Several changes checked in one step build on these, not on each other,
    /// since the worker takes only the last.
    names: Vec<String>,
}

/// The id of the interface `name` (a port or a VLAN sub-interface) in `names`.
/// One snapshot per VRF of `tables`; `local` says whether a VRF's traffic to the
/// router goes to the kernel.
fn vrf_snapshots<'t>(
    tables: &'t build::Built,
    kernel_bits: &'t [u64],
    local: impl Fn(&str) -> bool,
) -> Vec<ruster_core::ForwardingSnapshot<'t>> {
    tables
        .vrfs
        .iter()
        .zip(&tables.names)
        .map(|(vrf, name)| {
            vrf.owner
                .snapshot()
                .with_arp_to_control(true)
                .with_ipv6(&vrf.ipv6)
                .with_local_to_control(local(name))
                .with_kernel_ingress(&tables.kernel)
                .with_kernel_ingress_bits(kernel_bits)
                .with_vlans(&tables.vlans)
                .with_tunnels(&tables.tunnels)
                .with_srv6(&tables.srv6)
                .with_unreachable_neighbors(&tables.unreachable)
                .with_pppoe(&tables.pppoe)
        })
        .collect()
}

/// The snapshot a batch is forwarded by: the default VRF's, with every VRF's.
fn outer_snapshot<'t>(
    snapshots: &'t [ruster_core::ForwardingSnapshot<'t>],
    tables: &'t build::Built,
    kernel_bits: &'t [u64],
    punt_frames: &'t [ruster_core::PuntFrameMatch],
) -> ruster_core::ForwardingSnapshot<'t> {
    snapshots[0]
        .with_vrfs(snapshots, &tables.by_ingress)
        .with_vlans(&tables.vlans)
        .with_tunnels(&tables.tunnels)
        .with_srv6(&tables.srv6)
        .with_overlays(&tables.overlays)
        .with_pppoe(&tables.pppoe)
        .with_kernel_ingress(&tables.kernel)
        .with_kernel_ingress_bits(kernel_bits)
        .with_punt_frames(punt_frames)
}

/// The name at `at`, if there is one.
fn name_at(names: &[String], at: usize) -> Option<&str> {
    names.get(at).map(String::as_str)
}

fn interface_id(names: &[String], name: &str) -> Option<IfId> {
    let index = names.iter().position(|n| n == name)?;
    u16::try_from(index).ok().map(IfId)
}

impl Hook for Builder {
    fn check(&mut self, next: &Store) -> Result<(), String> {
        self.rebuild(next, None)
    }

    fn check_patch(
        &mut self,
        next: &Store,
        changed: &[(&Key, Option<&Value>)],
    ) -> Result<(), String> {
        self.rebuild(next, Some(changed))
    }

    fn committed(&mut self, _store: &Store) {}
}

impl Builder {
    /// Builds the tables for `next`, which is the store of the last build with an
    /// iPATCH made that touched `changed`, when that is given.
    fn rebuild(
        &mut self,
        next: &Store,
        changed: Option<&[(&Key, Option<&Value>)]>,
    ) -> Result<(), String> {
        // The kept routes are for the store of the last change that was accepted.
        // They are put back only once this one is, at the end: a change refused
        // anywhere below is taken out of the store again, and the routes it came
        // to must not stay. After a refusal there are none, and the next build
        // reads the routes again.
        let kept = self.routes.take().zip(changed);
        let (built, routes) = build::build(&self.ports, next, &self.names, kept)?;
        self.generation += 1;
        let default = built.vrfs.first().ok_or("no default VRF")?;
        let publication = firewall::Publication::new(
            &default.owner.snapshot(),
            &built.firewall,
            built.firewall_on,
            built.firewall_filtering,
            built.firewall_interfaces,
            self.generation,
        )?;
        let nat = built
            .nat
            .map(|nat| nat::Publication::new(&default.owner.snapshot(), nat))
            .transpose()?;
        self.built = Some((built, publication, nat));
        self.routes = Some(routes);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct ArpEvent {
    ingress: IfId,
    opcode: ArpOpcode,
    sender_hardware: [u8; 6],
    sender_protocol: [u8; 4],
    target_protocol: [u8; 4],
}

impl ArpEvent {
    /// The 28-byte Ethernet/IPv4 ARP body. The target hardware address is zero.
    fn body(&self) -> [u8; 28] {
        let mut body = [0_u8; 28];
        body[0..2].copy_from_slice(&1_u16.to_be_bytes());
        body[2..4].copy_from_slice(&0x0800_u16.to_be_bytes());
        body[4] = 6;
        body[5] = 4;
        let opcode: u16 = match self.opcode {
            ArpOpcode::Request => 1,
            ArpOpcode::Reply => 2,
        };
        body[6..8].copy_from_slice(&opcode.to_be_bytes());
        body[8..14].copy_from_slice(&self.sender_hardware);
        body[14..18].copy_from_slice(&self.sender_protocol);
        body[24..28].copy_from_slice(&self.target_protocol);
        body
    }
}

/// Collects what the FE acts on after a batch: ARP for the control side and next hops
/// that missed the neighbor table.
#[derive(Default)]
struct FeTrace {
    arp: Vec<ArpEvent>,
    misses: Vec<(IfId, IpAddr)>,
    /// Next hops packets went to in this batch (the neighbors' "used" marks),
    /// in the order of the packets; one that repeats the one before is left out,
    /// so a run of packets to one next hop costs one entry.
    used: Vec<(u16, IpAddr)>,
    overflow: u64,
    /// Frames bridged to an overlay dropped for their length, and for any other
    /// reason.
    overlay_too_big: u64,
    overlay_dropped: u64,
}

impl TraceSink for FeTrace {
    fn record(&mut self, event: TraceEvent) {
        match event {
            TraceEvent::ArpToControl {
                ingress,
                opcode,
                sender_hardware,
                sender_protocol,
                target_protocol,
            } => {
                if self.arp.len() < EVENTS_PER_BATCH {
                    self.arp.push(ArpEvent {
                        ingress,
                        opcode,
                        sender_hardware: sender_hardware.0,
                        sender_protocol: sender_protocol.octets(),
                        target_protocol: target_protocol.octets(),
                    });
                } else {
                    self.overflow += 1;
                }
            }
            TraceEvent::Routed {
                egress,
                neighbor_target,
            } => {
                self.mark_used((egress.0, IpAddr::V4(neighbor_target.octets().into())));
            }
            TraceEvent::Ipv6Routed { egress, next_hop } => {
                self.mark_used((egress.0, IpAddr::V6(next_hop.into())));
            }
            TraceEvent::NeighborMissing { egress, target } => {
                self.miss(egress, IpAddr::V4(target.octets().into()));
            }
            TraceEvent::Ipv6NeighborMissing { egress, target } => {
                self.miss(egress, IpAddr::V6(target.into()));
            }
            TraceEvent::Dropped { reason, .. } => self.overlay_drop(reason),
            _ => {}
        }
    }
}

impl FeTrace {
    /// Empties it for the next batch, keeping the lists' memory.
    fn clear(&mut self) {
        self.arp.clear();
        self.misses.clear();
        self.used.clear();
        self.overflow = 0;
        self.overlay_too_big = 0;
        self.overlay_dropped = 0;
    }

    fn mark_used(&mut self, next_hop: (u16, IpAddr)) {
        if self.used.last() != Some(&next_hop) {
            self.used.push(next_hop);
        }
    }

    /// Counts a frame bridged to an overlay that was dropped (any other drop is
    /// left alone).
    fn overlay_drop(&mut self, reason: ruster_core::DropReason) {
        use ruster_core::DropReason::{
            OverlayMtuExceeded, OverlayNoRoom, OverlayNoRoute, OverlayUnderlayUnsupported,
        };
        match reason {
            OverlayMtuExceeded => self.overlay_too_big += 1,
            OverlayNoRoom | OverlayNoRoute | OverlayUnderlayUnsupported => {
                self.overlay_dropped += 1;
            }
            _ => {}
        }
    }

    fn miss(&mut self, egress: IfId, target: IpAddr) {
        let miss = (egress, target);
        if self.misses.len() < EVENTS_PER_BATCH && !self.misses.contains(&miss) {
            self.misses.push(miss);
        }
    }
}

/// The SIDs a neighbor process writes, for callers that build their own writer sets.
pub const NEIGHBOR_TABLE: u64 = sid::NEIGHBOR;
