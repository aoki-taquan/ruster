//! The default VRF's NAPT (UDP, TCP and ICMP queries), from the tables' `nat` entry,
//! and its mappings.
//!
//! Every accepted table change makes new configurations for the new tables. The
//! runtimes take them over and keep their mappings when core allows it (same
//! interfaces, public address and port range; see `preflight_reconcile_carrying`),
//! and flush them otherwise. The runtimes' storage is allocated when NAT first
//! appears and kept for the life of the process. Only a port range of another size
//! needs new storage, and then the old one is not given back: a range is resized by
//! hand, rarely.
//!
//! # Standards
//!
//! - RFC 4787 (UDP), RFC 5382 (TCP) and RFC 5508 (ICMP queries and errors), as
//!   core's NAT44 implements them, with its default policies (endpoint-independent
//!   mapping, the filtering the configuration names for UDP and TCP,
//!   endpoint-independent by default, and hairpinning). ICMP queries stay
//!   address-dependent. With endpoint-independent filtering, any outside host may
//!   reach a mapping the router's own traffic made too (its LAN address goes
//!   through NAT); at most 8 TCP sessions are opened from one outside address.
//!
//! Deviations:
//!
//! - UDP and TCP to the public address on a port outside the pool are the router's
//!   own and are not translated. The pool must therefore not overlap the ports the
//!   router's kernel picks for its own connections, or their replies are taken for
//!   NAT's.
//! - No per-host limits: one inside host may take every mapping.
//! - Unsolicited inbound SYNs are dropped at once; RFC 5382 REQ-4's hold before an
//!   ICMP error needs storage the FE does not give yet.
//! - Fragments whose datagram started before a table change are dropped
//!   (`fragments.rs`).
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;

use ruster_core::{
    dispatch_nat44_tcp_unsolicited_syns, ipv4_id_rate_limit_storage, port_free_bitmap_words,
    DirectoryBucket, DirectoryNode, FirewallConfig, FirewallRuntime, ForwardingSnapshot,
    Icmpv4ErrorRuntime, MonotonicMillis, Nat44HostCounter, Nat44HostLink, Nat44HostStorage,
    Nat44IcmpConfig, Nat44IcmpHashKey, Nat44IcmpPolicy, Nat44IcmpRuntime, Nat44TcpConfig,
    Nat44TcpHashKey, Nat44TcpHostSlot, Nat44TcpIndexStorage, Nat44TcpMappingSlot, Nat44TcpPolicy,
    Nat44TcpRuntime, Nat44TcpSessionHostSlot, Nat44TcpSessionSlot, Nat44TcpSynHoldSlot,
    Nat44UdpConfig, Nat44UdpHashKey, Nat44UdpHostSlot, Nat44UdpIndexStorage, Nat44UdpMappingSlot,
    Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpRuntime, PortOwnerSlot, Services, TraceSink,
};

use crate::build;

/// UDP and ICMP mappings, and their peers.
const MAPPINGS: usize = 1 << 13;
/// TCP mappings and sessions.
const TCP_MAPPINGS: usize = 1 << 13;
const TCP_SESSIONS: usize = 1 << 14;
/// Unsolicited inbound SYNs held for their delayed Port Unreachable.
const SYN_HOLDS: usize = 1 << 10;
/// Matured holds answered per batch.
const SYN_ANSWERS_PER_BATCH: usize = 64;

/// The NAT configurations made for one set of tables.
#[derive(Clone, Copy)]
pub(crate) struct Publication {
    udp: Nat44UdpConfig,
    tcp: Nat44TcpConfig,
    icmp: Nat44IcmpConfig,
    ipv4_id_rate_limit: bool,
}

impl Publication {
    /// The configurations of `nat` for tables whose default VRF is `snapshot`.
    pub(crate) fn new(snapshot: &ForwardingSnapshot<'_>, nat: build::Nat) -> Result<Self, String> {
        let failed = |error: String| format!("nat: {error}");
        let build::Nat {
            inside,
            outside,
            public,
            ports,
            filtering,
            ipv4_id_rate_limit,
        } = nat;
        Ok(Self {
            udp: Nat44UdpConfig::with_port_set(
                snapshot,
                inside,
                outside,
                public,
                ports,
                Nat44UdpPolicy::default().with_filtering(filtering),
            )
            .map_err(|e| failed(format!("{e:?}")))?,
            tcp: Nat44TcpConfig::with_port_set(
                snapshot,
                inside,
                outside,
                public,
                ports,
                // With filtering that lets other endpoints in, one outside host
                // may open at most 8 sessions (it cannot fill the table alone).
                Nat44TcpPolicy::default()
                    .with_filtering(filtering)
                    .with_inbound_sessions_per_remote(8)
                    .expect("8 is within the limit"),
            )
            .map_err(|e| failed(format!("{e:?}")))?,
            icmp: Nat44IcmpConfig::with_port_set(
                snapshot,
                inside,
                outside,
                public,
                ports,
                Nat44IcmpPolicy::default(),
            )
            .map_err(|e| failed(format!("{e:?}")))?,
            ipv4_id_rate_limit,
        })
    }

    fn ports(&self) -> usize {
        self.udp.ports().count()
    }
}

/// The NAT in use: its configurations and runtimes.
pub(crate) struct Nat {
    current: Publication,
    /// Off while the tables have no NAT; the runtimes are kept for when it returns.
    on: bool,
    udp: Nat44UdpRuntime<'static>,
    tcp: Nat44TcpRuntime<'static>,
    icmp: Nat44IcmpRuntime<'static>,
}

impl Nat {
    /// Moves `nat` to `next` (`None` when the tables have no NAT).
    pub(crate) fn publish(nat: &mut Option<Self>, next: Option<Publication>) -> Result<(), String> {
        let Some(next) = next else {
            if let Some(this) = nat {
                this.on = false;
            }
            return Ok(());
        };
        match nat {
            Some(this) if this.current.ports() == next.ports() => {
                // On before the move: if it fails, the old configurations stay
                // bound to the old tables and core drops what NAT would take,
                // rather than letting it out untranslated.
                this.on = true;
                let failed = |error: String| format!("nat: {error}");
                // Each is checked before any is committed, so a refusal leaves all
                // three as they were.
                let udp = this
                    .udp
                    .preflight_reconcile_carrying(next.udp, udp_key())
                    .map_err(|e| failed(format!("UDP: {e:?}")))?;
                let tcp = this
                    .tcp
                    .preflight_reconcile_carrying(next.tcp, tcp_key())
                    .map_err(|e| failed(format!("TCP: {e:?}")))?;
                let icmp = this
                    .icmp
                    .preflight_reconcile_carrying(next.icmp, icmp_key())
                    .map_err(|e| failed(format!("ICMP: {e:?}")))?;
                udp.commit();
                tcp.commit();
                icmp.commit();
                this.current = next;
                this.limit_ipv4_id_rate();
            }
            _ => *nat = Some(Self::allocate(next)?),
        }
        Ok(())
    }

    /// Turns the IPv4 ID rate limit on or off as the current tables say.
    fn limit_ipv4_id_rate(&mut self) {
        let on = self.current.ipv4_id_rate_limit;
        self.udp.set_ipv4_id_rate_limited(on);
        self.tcp.set_ipv4_id_rate_limited(on);
        self.icmp.set_ipv4_id_rate_limited(on);
    }

    /// The NAT services to forward with, or none while the tables have no NAT.
    pub(crate) fn services<'s>(&'s mut self, services: &mut Services<'s, '_, 'static>) {
        if !self.on {
            return;
        }
        services.nat44_udp = Some((&self.current.udp, &mut self.udp));
        services.nat44_tcp = Some((&self.current.tcp, &mut self.tcp));
        services.nat44_icmp = Some((&self.current.icmp, &mut self.icmp));
    }

    /// Answers the unsolicited inbound SYNs whose 6 seconds are over with a Port
    /// Unreachable, queued in `errors` (see `ruster_core::dispatch_nat44_tcp_unsolicited_syns`).
    /// Returns how many holds matured.
    pub(crate) fn answer_unsolicited_syns<T: TraceSink>(
        &mut self,
        errors: &mut Icmpv4ErrorRuntime<'_>,
        snapshot: &ForwardingSnapshot<'_>,
        firewall: Option<(&FirewallConfig<'_>, &mut FirewallRuntime<'_>)>,
        now: MonotonicMillis,
        trace: &mut T,
    ) -> usize {
        if !self.on {
            return 0;
        }
        let (config, runtime) = match firewall {
            Some((config, runtime)) => (Some(config), Some(runtime)),
            None => (None, None),
        };
        dispatch_nat44_tcp_unsolicited_syns(
            &mut self.tcp,
            errors,
            snapshot,
            config,
            runtime,
            now,
            SYN_ANSWERS_PER_BATCH,
            trace,
        )
        .map_or(0, |report| report.matured)
    }

    fn allocate(next: Publication) -> Result<Self, String> {
        let failed = |error: String| format!("nat: {error}");
        let ports = next.ports();
        let udp = Nat44UdpRuntime::new(
            next.udp,
            leak(MAPPINGS, Nat44UdpMappingSlot::default()),
            leak(MAPPINGS, Nat44UdpPeerSlot::default()),
            udp_storage(ports, MAPPINGS, MAPPINGS),
            udp_key(),
        )
        .map_err(|e| failed(format!("UDP: {e:?}")))?
        .with_ipv4_id_rate_limit(Box::leak(ipv4_id_rate_limit_storage()));
        let icmp = Nat44IcmpRuntime::new(
            next.icmp,
            leak(MAPPINGS, Nat44UdpMappingSlot::default()),
            leak(MAPPINGS, Nat44UdpPeerSlot::default()),
            udp_storage(ports, MAPPINGS, MAPPINGS),
            icmp_key(),
        )
        .map_err(|e| failed(format!("ICMP: {e:?}")))?
        .with_ipv4_id_rate_limit(Box::leak(ipv4_id_rate_limit_storage()));
        let (mappings, sessions) = (TCP_MAPPINGS, TCP_SESSIONS);
        let hosts = Nat44HostStorage::new(
            leak(mappings, Nat44HostLink::EMPTY),
            leak(mappings, Nat44TcpHostSlot::EMPTY),
            buckets(mappings),
            leak(mappings, DirectoryNode::default()),
        );
        let session_hosts = Nat44HostStorage::new(
            leak(sessions, Nat44HostLink::EMPTY),
            leak(sessions, Nat44TcpSessionHostSlot::EMPTY),
            buckets(sessions),
            leak(sessions, DirectoryNode::default()),
        )
        .with_link_words(leak(sessions, 0_u32));
        let tcp = Nat44TcpRuntime::new(
            next.tcp,
            leak(mappings, Nat44TcpMappingSlot::default()),
            leak(sessions, Nat44TcpSessionSlot::default()),
            Nat44TcpIndexStorage::new(
                buckets(mappings),
                leak(mappings, DirectoryNode::default()),
                buckets(sessions),
                leak(sessions, DirectoryNode::default()),
                buckets(sessions),
                leak(sessions, DirectoryNode::default()),
                leak(ports, PortOwnerSlot::default()),
                leak(port_free_bitmap_words(ports), 0_u64),
                hosts,
            )
            .with_session_hosts(session_hosts),
            tcp_key(),
        )
        .map_err(|e| failed(format!("TCP: {e:?}")))?
        .with_unsolicited_syn_holds(leak(SYN_HOLDS, Nat44TcpSynHoldSlot::EMPTY))
        .map_err(|e| failed(format!("TCP SYN holds: {e:?}")))?
        .with_ipv4_id_rate_limit(Box::leak(ipv4_id_rate_limit_storage()));
        let mut nat = Self {
            current: next,
            on: true,
            udp,
            tcp,
            icmp,
        };
        nat.limit_ipv4_id_rate();
        Ok(nat)
    }
}

/// Index storage of a UDP or ICMP runtime.
fn udp_storage(ports: usize, mappings: usize, peers: usize) -> Nat44UdpIndexStorage<'static> {
    Nat44UdpIndexStorage::new(
        buckets(mappings),
        leak(mappings, DirectoryNode::default()),
        buckets(peers),
        leak(peers, DirectoryNode::default()),
        leak(ports, PortOwnerSlot::default()),
        leak(port_free_bitmap_words(ports), 0_u64),
        Nat44HostStorage::new(
            leak(mappings, Nat44HostLink::EMPTY),
            leak(mappings, Nat44UdpHostSlot::EMPTY),
            buckets(mappings),
            leak(mappings, DirectoryNode::default()),
        )
        .with_link_words(leak(mappings, 0_u32))
        .with_host_counters(leak(mappings, Nat44HostCounter::EMPTY)),
    )
}

fn leak<T: Clone>(count: usize, value: T) -> &'static mut [T] {
    Box::leak(vec![value; count].into_boxed_slice())
}

/// The hash buckets for `count` entries.
fn buckets(count: usize) -> &'static mut [DirectoryBucket] {
    leak(count.next_power_of_two(), DirectoryBucket::default())
}

/// Two random words, from the standard library's `RandomState` (seeded from the
/// operating system), for a key that is new for every publication.
pub(crate) fn words() -> (u64, u64) {
    let state = RandomState::new();
    (state.hash_one(1_u8), state.hash_one(2_u8))
}

fn udp_key() -> Nat44UdpHashKey {
    loop {
        let (a, b) = words();
        if let Ok(key) = Nat44UdpHashKey::new(a, b) {
            return key;
        }
    }
}

fn tcp_key() -> Nat44TcpHashKey {
    loop {
        let (a, b) = words();
        if let Ok(key) = Nat44TcpHashKey::new(a, b) {
            return key;
        }
    }
}

fn icmp_key() -> Nat44IcmpHashKey {
    loop {
        let (a, b) = words();
        if let Ok(key) = Nat44IcmpHashKey::new(a, b) {
            return key;
        }
    }
}
