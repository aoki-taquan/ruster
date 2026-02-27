pub mod arp;
pub mod bgp;
pub mod conntrack;
pub mod dpdk;
pub mod firewall;
pub mod icmp;
pub mod io;
pub mod l2;
pub mod nat;
pub mod nd;
pub mod ospf;
pub mod packet;
pub mod pipeline;
pub mod rewrite;
pub mod routing;
pub mod srv6;

#[cfg(target_os = "linux")]
pub mod afpacket;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ruster_config::model::RouterConfig;

/// Initialization error for the dataplane.
#[derive(Debug, thiserror::Error)]
pub enum DataplaneError {
    /// DPDK subsystem initialization failed.
    #[error("DPDK init: {0}")]
    Dpdk(#[from] dpdk::error::DpdkError),

    /// L3 routing engine configuration failed (invalid routes or local IPs).
    #[error("L3 routing config: {0}")]
    Routing(#[from] routing::L3ConfigError),

    /// IPv6 route table configuration failed.
    #[error("IPv6 routing config: {0}")]
    Ipv6Routing(String),
}

/// The dataplane runtime holding initialized engines.
///
/// Created via [`Dataplane::init`] from a validated [`RouterConfig`].
/// In v0.1 the DPDK backend is mocked, so no real NIC init happens;
/// however all forwarding engines (L2, ARP, L3, NAT, firewall, conntrack)
/// are fully constructed from configuration.
#[derive(Debug)]
pub struct Dataplane {
    /// L2 bridging engine (MAC learning, FDB, bridge domains).
    ///
    /// Wrapped in a `Mutex` because [`l2::L2Engine::process`] requires
    /// `&mut self` (for MAC learning), while the run loop takes `&self`.
    pub l2: Mutex<l2::L2Engine>,
    /// ARP resolution engine (per-interface ARP caches).
    ///
    /// Wrapped in a `Mutex` because [`arp::ArpEngine::resolve`] requires
    /// `&mut self`, while the run loop takes `&self`.
    pub arp: Mutex<arp::ArpEngine>,
    /// L3 IPv4 forwarding engine (static routing, LPM).
    pub l3: routing::L3Engine,
    /// Neighbor Discovery engine for IPv6 address resolution.
    ///
    /// Wrapped in a `Mutex` because [`nd::NdEngine::resolve`] and
    /// [`nd::NdEngine::process_nd`] require `&mut self`.
    pub nd: Mutex<nd::NdEngine>,
    /// IPv6 static route table with LPM lookup.
    pub ipv6_routes: routing::ipv6_table::Ipv6RouteTable,
    /// SRv6 processing engine (optional, enabled when [srv6] config is present).
    ///
    /// RFC-REF: RFC 8986 (SRv6 Network Programming)
    pub srv6: Option<srv6::Srv6Engine>,
    /// NAT44 engine (NAPT, port forwarding, hairpin).
    ///
    /// Wrapped in a `Mutex` because [`nat::NatEngine::process_outbound`] and
    /// other NAT methods require `&mut self`, while the run loop takes `&self`.
    pub nat: Mutex<nat::NatEngine>,
    /// Stateful firewall engine.
    pub firewall: firewall::FirewallEngine,
    /// Connection tracking engine (session table).
    ///
    /// Wrapped in a `Mutex` because [`pipeline::process_packet`] requires
    /// `&mut self` for session create/update, while the run loop takes `&self`.
    pub conntrack: Mutex<conntrack::ConntrackEngine>,
    /// Zone resolver: maps interface names to firewall zones.
    pub zone_resolver: pipeline::ZoneResolver,
    /// Per-interface MAC addresses for src MAC rewriting on egress.
    iface_macs: std::collections::HashMap<String, [u8; 6]>,
    /// Linux device name -> logical interface name mapping (for ARP refresh).
    linux_to_logical: std::collections::HashMap<String, String>,
    /// Counter for TX errors encountered in the run loop.
    tx_errors: AtomicU64,
    /// Observability hub: per-interface and per-stage counters.
    pub observer: Arc<ruster_observe::Observer>,
    /// ARP hold queue: buffers packets waiting for next-hop MAC resolution.
    ///
    /// Wrapped in a `Mutex` because enqueue/flush/gc all require `&mut self`.
    pub hold_queue: Mutex<arp::hold_queue::HoldQueue>,
    /// ARP hold queue GC timeout in seconds (same as ARP timeout).
    hold_queue_timeout_sec: u64,
}

impl Dataplane {
    /// Initialize the dataplane from a validated configuration.
    ///
    /// Creates all sub-engines (L2, ARP, L3, NAT, FW, conntrack) from config.
    /// In v0.1 the DPDK backend is mocked, so no real NIC init happens.
    pub fn init(config: &RouterConfig) -> Result<Self, DataplaneError> {
        let l2 = l2::L2Engine::from_config(&config.l2);
        let mut arp = arp::ArpEngine::from_config(&config.l2, &config.interfaces);
        let l3 = routing::L3Engine::from_config(&config.routing, &config.interfaces)?;
        let nd = nd::NdEngine::from_config(&config.l2, &config.interfaces);
        let ipv6_routes = routing::ipv6_table::Ipv6RouteTable::from_config(&config.routing)
            .map_err(|errs| {
                DataplaneError::Ipv6Routing(
                    errs.iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; "),
                )
            })?;
        // Build SRv6 engine if configured.
        let srv6 = if let Some(ref srv6_cfg) = config.srv6 {
            let internal_cfg = srv6::config::Srv6Config {
                locator_block: srv6_cfg.locator_block.clone(),
                block_len: srv6_cfg.block_len,
                usid_len: srv6_cfg.usid_len,
                local_sids: srv6_cfg
                    .local_sids
                    .iter()
                    .map(|s| srv6::config::LocalSidConfig {
                        sid: s.sid.clone(),
                        action: s.action.clone(),
                        table: s.table.clone(),
                    })
                    .collect(),
            };
            match srv6::Srv6Engine::from_config(internal_cfg) {
                Ok(engine) => Some(engine),
                Err(e) => {
                    eprintln!("SRv6: failed to initialize: {e}");
                    None
                }
            }
        } else {
            None
        };

        let nat = nat::NatEngine::from_config(&config.nat, &config.interfaces);
        let firewall = firewall::FirewallEngine::from_config(&config.firewall);
        let conntrack = conntrack::ConntrackEngine::from_nat_config(&config.nat);
        let zone_resolver = pipeline::ZoneResolver::from_config(&config.interfaces);

        let iface_macs: std::collections::HashMap<String, [u8; 6]> = config
            .interfaces
            .iter()
            .map(|iface| {
                let mac = parse_mac_str(&iface.mac);
                (iface.name.clone(), mac)
            })
            .collect();

        // Build linux device -> logical name mapping for ARP cache pre-loading.
        let linux_to_logical: std::collections::HashMap<String, String> = config
            .interfaces
            .iter()
            .filter_map(|iface| {
                iface
                    .linux_if
                    .as_ref()
                    .map(|linux_name| (linux_name.clone(), iface.name.clone()))
            })
            .collect();

        // Pre-populate ARP caches from the kernel's neighbor table so that
        // directly connected hosts can be forwarded to immediately.
        let arp_loaded = arp.load_kernel_arp(&linux_to_logical);
        if arp_loaded > 0 {
            println!("  ARP: loaded {} entries from kernel", arp_loaded);
        }

        let iface_names: Vec<String> = config.interfaces.iter().map(|i| i.name.clone()).collect();
        let observer = Arc::new(ruster_observe::Observer::new(&iface_names));

        let hold_queue = arp::hold_queue::HoldQueue::new(
            config.l2.arp_hold_queue_per_ip as usize,
            config.l2.arp_hold_queue_max as usize,
        );
        let hold_queue_timeout_sec = u64::from(config.l2.arp_timeout_sec);

        Ok(Self {
            l2: Mutex::new(l2),
            arp: Mutex::new(arp),
            l3,
            nd: Mutex::new(nd),
            ipv6_routes,
            srv6,
            nat: Mutex::new(nat),
            firewall,
            conntrack: Mutex::new(conntrack),
            zone_resolver,
            iface_macs,
            linux_to_logical,
            tx_errors: AtomicU64::new(0),
            observer,
            hold_queue: Mutex::new(hold_queue),
            hold_queue_timeout_sec,
        })
    }

    /// Run the dataplane event loop until the shutdown flag is set.
    ///
    /// Receives packets via [`io::PacketIo::rx`], processes them through
    /// the pipeline (parse -> L3 route -> firewall), and transmits
    /// forwarded packets via [`io::PacketIo::tx`].
    ///
    /// If the RX queue is empty the loop sleeps briefly to avoid busy-spinning.
    ///
    /// Returns `Ok(())` on clean shutdown.
    pub fn run(
        &self,
        shutdown: Arc<AtomicBool>,
        io: Box<dyn io::PacketIo>,
    ) -> Result<(), DataplaneError> {
        let mut last_stats = std::time::Instant::now();
        let mut last_arp_refresh = std::time::Instant::now();
        let mut last_hold_queue_gc = std::time::Instant::now();
        let mut last_arp_retry = std::time::Instant::now();
        let mut last_conntrack_gc = std::time::Instant::now();

        while !shutdown.load(Ordering::Relaxed) {
            // Periodically refresh ARP cache from the kernel neighbor table.
            if last_arp_refresh.elapsed() >= Duration::from_secs(5) {
                let mut arp_guard = self.arp.lock().unwrap();
                arp_guard.load_kernel_arp(&self.linux_to_logical);
                drop(arp_guard);
                last_arp_refresh = std::time::Instant::now();
            }

            // Periodically GC the ARP hold queue (remove timed-out entries).
            if last_hold_queue_gc.elapsed() >= Duration::from_secs(1) {
                let gc_dropped = {
                    let mut hq_guard = self.hold_queue.lock().unwrap();
                    hq_guard.gc(self.hold_queue_timeout_sec)
                };
                if gc_dropped > 0 {
                    self.observer.inc_arp_hold_gc_dropped(gc_dropped as u64);
                }
                last_hold_queue_gc = std::time::Instant::now();
            }

            // Periodically re-send ARP requests for pending hold queue entries
            // and try to flush any that have been resolved since the last check.
            if last_arp_retry.elapsed() >= Duration::from_secs(1) {
                self.retry_pending_arp(&*io);
                last_arp_retry = std::time::Instant::now();
            }

            // Periodically garbage-collect expired conntrack sessions (every 10s).
            if last_conntrack_gc.elapsed() >= Duration::from_secs(10) {
                let mut ct_guard = self.conntrack.lock().unwrap();
                let expired = ct_guard.gc();
                let session_count = ct_guard.session_count();
                drop(ct_guard);
                if expired > 0 {
                    self.observer.add_conntrack_expired(expired as u64);
                    eprintln!("conntrack GC: expired {expired} sessions, {session_count} active");
                }
                last_conntrack_gc = std::time::Instant::now();
            }

            let batch = io.rx();
            if batch.is_empty() {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            for raw_pkt in &batch {
                // Count RX on ingress interface.
                self.observer
                    .inc_rx(&raw_pkt.ingress_iface, raw_pkt.data.len() as u64);

                // TODO(#149): Per-packet conntrack counters (inc_conntrack_new,
                // inc_conntrack_established) are not wired yet because
                // ConntrackResult is internal to process_packet. To wire
                // them, propagate ConntrackResult out of PipelineResult or
                // pass an observer reference into the pipeline. For now,
                // only conntrack_table_full (via DropReason) and
                // conntrack_expired (via GC) are tracked.
                let result = {
                    let mut l2_guard = self.l2.lock().unwrap();
                    let mut ct_guard = self.conntrack.lock().unwrap();
                    let mut nat_guard = self.nat.lock().unwrap();
                    let mut nd_guard = self.nd.lock().unwrap();
                    pipeline::process_packet_v6(
                        raw_pkt,
                        &mut l2_guard,
                        &self.l3,
                        &self.firewall,
                        &mut ct_guard,
                        &mut nat_guard,
                        &self.zone_resolver,
                        &self.iface_macs,
                        Some(&mut nd_guard),
                        Some(&self.ipv6_routes),
                        self.srv6.as_ref(),
                    )
                };
                match result {
                    pipeline::PipelineResult::Forward {
                        egress_iface,
                        new_ttl,
                        next_hop,
                        nat: nat_result,
                    } => {
                        self.observer.inc_forwarded();

                        // Apply packet rewrites for L3 forwarding.
                        let tx_data;
                        let needs_rewrite = new_ttl.is_some()
                            || next_hop.is_some()
                            || nat_result != pipeline::NatResult::None;
                        let tx_pkt = if needs_rewrite {
                            let mut data = raw_pkt.data.clone();

                            // 1. NAT rewrite (SNAT/DNAT) — must be before TTL
                            //    so that checksum updates are layered correctly.
                            //
                            // RFC-REF: RFC 3022 Section 4.3
                            // "The checksum adjustment must be performed any time
                            // the IP header or the TCP/UDP header is modified."
                            match &nat_result {
                                pipeline::NatResult::Snat {
                                    new_src_ip,
                                    new_src_port,
                                } => {
                                    rewrite::rewrite_snat(&mut data, *new_src_ip, *new_src_port);
                                    self.observer.inc_nat_snat();
                                }
                                pipeline::NatResult::Dnat {
                                    new_dst_ip,
                                    new_dst_port,
                                } => {
                                    rewrite::rewrite_dnat(&mut data, *new_dst_ip, *new_dst_port);
                                    self.observer.inc_nat_dnat();
                                }
                                pipeline::NatResult::None => {}
                            }

                            // 2. TTL + checksum
                            if let Some(ttl) = new_ttl {
                                rewrite::rewrite_ipv4_ttl(&mut data, ttl);
                            }

                            // 3. src MAC -> egress IF's MAC
                            if let Some(mac) = self.iface_macs.get(&egress_iface) {
                                rewrite::rewrite_src_mac(&mut data, mac);
                            }

                            // 3. dst MAC -> ARP resolve
                            if let Some(nh) = next_hop {
                                // Determine the IP to ARP-resolve:
                                // - If next_hop != 0.0.0.0: resolve the next-hop gateway
                                // - If next_hop == 0.0.0.0: directly connected, resolve
                                //   the packet's destination IP
                                let arp_target = if nh != [0, 0, 0, 0] {
                                    nh
                                } else {
                                    // Extract dst IP from the IPv4 header (offset 30..34
                                    // in an Ethernet+IPv4 frame: 14 eth + 16 dst offset)
                                    if data.len() >= 34 {
                                        [data[30], data[31], data[32], data[33]]
                                    } else {
                                        // Malformed, cannot extract dst IP
                                        self.observer
                                            .inc_drop_reason(ruster_observe::DropReason::L3NoRoute);
                                        continue;
                                    }
                                };
                                let arp_result = {
                                    let mut arp_guard = self.arp.lock().unwrap();
                                    arp_guard.resolve(arp_target, &egress_iface)
                                };
                                match arp_result {
                                    arp::ArpAction::Forward { resolved_mac } => {
                                        rewrite::rewrite_dst_mac(&mut data, &resolved_mac);
                                    }
                                    arp::ArpAction::SendRequest {
                                        out_ifname,
                                        target_ip,
                                        sender_ip,
                                        sender_mac,
                                    } => {
                                        // Enqueue the packet in the ARP hold queue.
                                        let enqueue_result = {
                                            let mut hq_guard = self.hold_queue.lock().unwrap();
                                            hq_guard.enqueue(
                                                arp_target,
                                                egress_iface.clone(),
                                                data,
                                                new_ttl,
                                            )
                                        };
                                        match enqueue_result {
                                            arp::hold_queue::EnqueueResult::Enqueued => {
                                                self.observer.inc_arp_hold_enqueued();
                                            }
                                            _ => {
                                                self.observer.inc_arp_hold_tail_dropped();
                                            }
                                        }

                                        // Send ARP request (rate-limited).
                                        let should_send = {
                                            let mut arp_guard = self.arp.lock().unwrap();
                                            arp_guard.should_send_request(target_ip)
                                        };
                                        if should_send {
                                            let arp_pkt = arp::build_arp_request(
                                                sender_mac, sender_ip, target_ip,
                                            );
                                            let arp_raw = io::RawPacket {
                                                ingress_iface: out_ifname.clone(),
                                                data: arp_pkt,
                                            };
                                            let _ = io.tx(&out_ifname, &arp_raw);
                                        }
                                        continue;
                                    }
                                    arp::ArpAction::Drop => {
                                        self.observer.inc_drop_reason(
                                            ruster_observe::DropReason::ArpUnresolved,
                                        );
                                        continue;
                                    }
                                    arp::ArpAction::Reply { .. } | arp::ArpAction::Update => {
                                        // Unexpected from resolve(); log and drop.
                                        eprintln!(
                                            "unexpected ArpAction from resolve() for {}",
                                            egress_iface
                                        );
                                        self.observer.inc_drop_reason(
                                            ruster_observe::DropReason::ArpUnresolved,
                                        );
                                        continue;
                                    }
                                }
                            }

                            tx_data = io::RawPacket {
                                ingress_iface: raw_pkt.ingress_iface.clone(),
                                data,
                            };
                            &tx_data
                        } else {
                            raw_pkt
                        };

                        match io.tx(&egress_iface, tx_pkt) {
                            Ok(()) => {
                                self.observer
                                    .inc_tx(&egress_iface, raw_pkt.data.len() as u64);
                            }
                            Err(e) => {
                                self.tx_errors.fetch_add(1, Ordering::Relaxed);
                                self.observer.inc_tx_drop(&egress_iface);
                                eprintln!("TX error on {}: {}", egress_iface, e);
                            }
                        }
                    }
                    pipeline::PipelineResult::ForwardV6 {
                        egress_iface,
                        new_hop_limit,
                        next_hop_v6,
                        srv6_new_da,
                    } => {
                        self.observer.inc_forwarded();

                        let mut data = raw_pkt.data.clone();

                        // 0. SRv6 DA rewrite (must happen before ND resolution
                        //    since ND may use the DA from the packet).
                        if let Some(ref new_da) = srv6_new_da {
                            rewrite::rewrite_ipv6_da(&mut data, new_da);
                        }

                        // 1. Hop Limit (no checksum update needed for IPv6).
                        rewrite::rewrite_ipv6_hop_limit(&mut data, new_hop_limit);

                        // 2. src MAC -> egress IF's MAC.
                        if let Some(mac) = self.iface_macs.get(&egress_iface) {
                            rewrite::rewrite_src_mac(&mut data, mac);
                        }

                        // 3. dst MAC -> ND resolve.
                        // Determine the IPv6 address to resolve:
                        // - If next_hop != :: : resolve the next-hop gateway
                        // - If next_hop == :: : directly connected, resolve
                        //   the packet's destination IPv6
                        let nd_target = if next_hop_v6 != [0u8; 16] {
                            next_hop_v6
                        } else {
                            // Extract dst IPv6 from the IPv6 header (offset 14+24..14+40
                            // in an Ethernet+IPv6 frame)
                            if data.len() >= 54 {
                                let mut dst = [0u8; 16];
                                dst.copy_from_slice(&data[38..54]);
                                dst
                            } else {
                                self.observer
                                    .inc_drop_reason(ruster_observe::DropReason::L3NoRoute);
                                continue;
                            }
                        };

                        let nd_result = {
                            let mut nd_guard = self.nd.lock().unwrap();
                            nd_guard.resolve(nd_target, &egress_iface)
                        };
                        match nd_result {
                            nd::NdAction::Forward { resolved_mac } => {
                                rewrite::rewrite_dst_mac(&mut data, &resolved_mac);
                            }
                            _ => {
                                // ND unresolved -> drop
                                self.observer
                                    .inc_drop_reason(ruster_observe::DropReason::L3NoRoute);
                                continue;
                            }
                        }

                        let tx_data = io::RawPacket {
                            ingress_iface: raw_pkt.ingress_iface.clone(),
                            data,
                        };

                        match io.tx(&egress_iface, &tx_data) {
                            Ok(()) => {
                                self.observer
                                    .inc_tx(&egress_iface, raw_pkt.data.len() as u64);
                            }
                            Err(e) => {
                                self.tx_errors.fetch_add(1, Ordering::Relaxed);
                                self.observer.inc_tx_drop(&egress_iface);
                                eprintln!("TX error on {}: {}", egress_iface, e);
                            }
                        }
                    }
                    pipeline::PipelineResult::Flood { egress_ifaces } => {
                        self.observer.inc_forwarded();
                        for iface in &egress_ifaces {
                            match io.tx(iface, raw_pkt) {
                                Ok(()) => {
                                    self.observer.inc_tx(iface, raw_pkt.data.len() as u64);
                                }
                                Err(e) => {
                                    self.tx_errors.fetch_add(1, Ordering::Relaxed);
                                    self.observer.inc_tx_drop(iface);
                                    eprintln!("TX error on {}: {}", iface, e);
                                }
                            }
                        }
                    }
                    pipeline::PipelineResult::Drop {
                        reason,
                        icmp_reply: Some(reply),
                    } => {
                        let obs_reason = map_pipeline_drop_to_observe(&reason);
                        self.observer.inc_drop_reason(obs_reason);
                        if reason == pipeline::DropReason::ConntrackTableFull {
                            self.observer.inc_conntrack_table_full();
                        }
                        if reason == pipeline::DropReason::NatDrop {
                            self.observer.inc_nat_drop();
                        }
                        let icmp_pkt = io::RawPacket {
                            ingress_iface: reply.egress_iface.clone(),
                            data: reply.data,
                        };
                        if let Err(e) = io.tx(&reply.egress_iface, &icmp_pkt) {
                            self.tx_errors.fetch_add(1, Ordering::Relaxed);
                            eprintln!("TX error for ICMP reply on {}: {}", reply.egress_iface, e);
                        }
                    }
                    pipeline::PipelineResult::Drop { reason, .. } => {
                        let obs_reason = map_pipeline_drop_to_observe(&reason);
                        self.observer.inc_drop_reason(obs_reason);
                        // Wire conntrack table-full counter.
                        if reason == pipeline::DropReason::ConntrackTableFull {
                            self.observer.inc_conntrack_table_full();
                        }
                        // Wire NAT drop counter.
                        if reason == pipeline::DropReason::NatDrop {
                            self.observer.inc_nat_drop();
                        }
                    }
                    pipeline::PipelineResult::Consumed => {
                        self.observer.inc_local_delivery();
                    }
                    pipeline::PipelineResult::NdReply {
                        egress_iface,
                        reply_info,
                    } => {
                        self.observer.inc_local_delivery();
                        let na_data = nd::build_na_packet(&reply_info);
                        let na_pkt = io::RawPacket {
                            ingress_iface: egress_iface.clone(),
                            data: na_data,
                        };
                        match io.tx(&egress_iface, &na_pkt) {
                            Ok(()) => {
                                self.observer
                                    .inc_tx(&egress_iface, na_pkt.data.len() as u64);
                            }
                            Err(e) => {
                                self.tx_errors.fetch_add(1, Ordering::Relaxed);
                                self.observer.inc_tx_drop(&egress_iface);
                                eprintln!("TX error for ND reply on {}: {}", egress_iface, e);
                            }
                        }
                    }
                }
            }

            // Periodic stats output every 10 seconds.
            if last_stats.elapsed() >= Duration::from_secs(10) {
                let snap = self.observer.snapshot();
                eprintln!("{}", snap);
                // Log conntrack table occupancy.
                let ct_guard = self.conntrack.lock().unwrap();
                let ct_sessions = ct_guard.session_count();
                drop(ct_guard);
                eprintln!("conntrack sessions: {ct_sessions}");
                last_stats = std::time::Instant::now();
            }
        }

        Ok(())
    }

    /// Retry pending ARP resolutions and flush any that have been resolved.
    ///
    /// Called periodically from the run loop. For each pending IP in the
    /// hold queue, checks the ARP cache; if resolved, flushes the held
    /// packets and transmits them. If still unresolved, re-sends the ARP
    /// request (subject to rate limiting).
    fn retry_pending_arp(&self, io: &dyn io::PacketIo) {
        let pending_ips = {
            let hq_guard = self.hold_queue.lock().unwrap();
            hq_guard.pending_ips()
        };

        for (target_ip, egress_iface) in pending_ips {
            // Use lookup_resolved (read-only) instead of resolve() to avoid
            // the side effect of re-marking the entry as Pending.
            let resolved_mac = {
                let arp_guard = self.arp.lock().unwrap();
                arp_guard.lookup_resolved(&target_ip, &egress_iface)
            };

            if let Some(mac) = resolved_mac {
                // ARP resolved! Flush all held packets.
                let held_packets = {
                    let mut hq_guard = self.hold_queue.lock().unwrap();
                    hq_guard.flush(&target_ip)
                };
                let flushed_count = held_packets.len() as u64;

                for mut held in held_packets {
                    rewrite::rewrite_dst_mac(&mut held.data, &mac);
                    if let Some(ttl) = held.new_ttl {
                        rewrite::rewrite_ipv4_ttl(&mut held.data, ttl);
                    }
                    let tx_pkt = io::RawPacket {
                        ingress_iface: held.egress_iface.clone(),
                        data: held.data,
                    };
                    match io.tx(&held.egress_iface, &tx_pkt) {
                        Ok(()) => {
                            self.observer
                                .inc_tx(&held.egress_iface, tx_pkt.data.len() as u64);
                        }
                        Err(e) => {
                            self.tx_errors.fetch_add(1, Ordering::Relaxed);
                            self.observer.inc_tx_drop(&held.egress_iface);
                            eprintln!(
                                "TX error on {} (hold queue flush): {}",
                                held.egress_iface, e
                            );
                        }
                    }
                }

                if flushed_count > 0 {
                    self.observer.inc_arp_hold_flushed(flushed_count);
                }
            } else {
                // Still unresolved; re-send ARP request (rate-limited).
                let (should_send, if_info) = {
                    let mut arp_guard = self.arp.lock().unwrap();
                    let should = arp_guard.should_send_request(target_ip);
                    let info = arp_guard.interface_info_for_request(&egress_iface);
                    (should, info)
                };
                if should_send {
                    if let Some((sender_mac, sender_ip)) = if_info {
                        let arp_pkt = arp::build_arp_request(sender_mac, sender_ip, target_ip);
                        let arp_raw = io::RawPacket {
                            ingress_iface: egress_iface.clone(),
                            data: arp_pkt,
                        };
                        let _ = io.tx(&egress_iface, &arp_raw);
                    }
                }
            }
        }
    }

    /// Return the total number of TX errors observed by the run loop.
    pub fn tx_error_count(&self) -> u64 {
        self.tx_errors.load(Ordering::Relaxed)
    }
}

/// Parse a MAC address string (e.g. "00:11:22:33:44:55") into a 6-byte array.
///
/// Returns `[0; 6]` if the string cannot be parsed.
pub fn parse_mac_str(mac_str: &str) -> [u8; 6] {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return [0; 6];
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).unwrap_or(0);
    }
    mac
}

/// Map a pipeline [`pipeline::DropReason`] to an observe [`ruster_observe::DropReason`].
fn map_pipeline_drop_to_observe(reason: &pipeline::DropReason) -> ruster_observe::DropReason {
    match reason {
        pipeline::DropReason::ParseError => ruster_observe::DropReason::ParseError,
        pipeline::DropReason::L2Drop => ruster_observe::DropReason::L2NoBridgeDomain,
        pipeline::DropReason::L3NoRoute => ruster_observe::DropReason::L3NoRoute,
        pipeline::DropReason::L3TtlExpired => ruster_observe::DropReason::L3TtlExpired,
        pipeline::DropReason::L3NotIpv4 => ruster_observe::DropReason::L3NotIpv4,
        pipeline::DropReason::L3HopLimitExpired => ruster_observe::DropReason::L3TtlExpired,
        pipeline::DropReason::FirewallDrop => ruster_observe::DropReason::FirewallDrop,
        pipeline::DropReason::NatDrop => ruster_observe::DropReason::NatTableFull,
        pipeline::DropReason::ConntrackTableFull => ruster_observe::DropReason::ConntrackTableFull,
        pipeline::DropReason::Srv6Drop(_) => ruster_observe::DropReason::Srv6Drop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn example_toml() -> String {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop(); // crates
        path.pop(); // project root
        path.push("router.toml.example");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
    }

    fn load_example() -> RouterConfig {
        ruster_config::load_from_str(&example_toml()).expect("valid config")
    }

    #[test]
    fn dataplane_init_succeeds_with_valid_config() {
        let config = load_example();
        let dp = Dataplane::init(&config).expect("init should succeed");

        // Verify all engines were created from the example config.
        // The example has 2 bridge domains, 1 static route, NAT enabled.
        assert!(dp.nat.lock().unwrap().is_enabled());
    }

    #[test]
    fn dataplane_init_returns_result() {
        // Verify the return type is Result (compile-time check, essentially).
        let config = load_example();
        let result: Result<Dataplane, DataplaneError> = Dataplane::init(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn dataplane_run_returns_on_shutdown() {
        let config = load_example();
        let dp = Dataplane::init(&config).expect("init should succeed");

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_trigger = Arc::clone(&shutdown);

        // Signal shutdown after a short delay from another thread.
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            shutdown_trigger.store(true, Ordering::Relaxed);
        });

        // run() should block until the shutdown flag is set, then return Ok.
        let mock_io = io::MockPacketIo::new();
        let result = dp.run(shutdown, Box::new(mock_io));
        assert!(result.is_ok(), "run should return Ok on clean shutdown");

        handle.join().expect("trigger thread should join cleanly");
    }

    #[test]
    fn dataplane_run_returns_immediately_if_already_shutdown() {
        let config = load_example();
        let dp = Dataplane::init(&config).expect("init should succeed");

        // Pre-set the shutdown flag before calling run.
        let shutdown = Arc::new(AtomicBool::new(true));

        let start = std::time::Instant::now();
        let mock_io = io::MockPacketIo::new();
        let result = dp.run(shutdown, Box::new(mock_io));
        let elapsed = start.elapsed();

        assert!(result.is_ok(), "run should return Ok");
        assert!(
            elapsed < Duration::from_millis(50),
            "run should return immediately when shutdown is pre-set, took {:?}",
            elapsed
        );
    }

    #[test]
    fn dataplane_tx_error_count_starts_at_zero() {
        let config = load_example();
        let dp = Dataplane::init(&config).expect("init should succeed");
        assert_eq!(dp.tx_error_count(), 0, "tx_error_count should start at 0");
    }

    /// Load the example config with the firewall, NAT disabled and
    /// bridge domains emptied so that packets go straight to L3
    /// (reach TX) in the run loop.
    fn load_example_fw_disabled() -> RouterConfig {
        let mut config = {
            let toml = example_toml()
                .replace(
                    "\n[firewall]\nenabled = true\n",
                    "\n[firewall]\nenabled = false\n",
                )
                .replace("\n[nat]\nenabled = true\n", "\n[nat]\nenabled = false\n");
            ruster_config::load_from_str(&toml).expect("valid config with fw disabled")
        };
        // Clear bridge domains so L2 processing is skipped and
        // packets go directly to L3 routing.
        config.l2.bridge_domains.clear();
        config
    }

    /// Pre-populate the ARP cache so that the default route's next hop
    /// (203.0.113.1 via wan0) can be resolved. Without this, L3 forwarding
    /// would drop packets waiting for ARP resolution.
    fn prepopulate_arp(dp: &Dataplane) {
        let mut arp_guard = dp.arp.lock().unwrap();
        // Default route next_hop in example config: 203.0.113.1
        let next_hop = [203, 0, 113, 1];
        let fake_gw_mac = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        arp_guard.insert("wan0", next_hop, fake_gw_mac);
    }

    /// Build a minimal valid Ethernet+IPv4+UDP packet that the pipeline
    /// will route via the default route (wan0) in the example config.
    fn make_forwardable_packet() -> io::RawPacket {
        let mut pkt = Vec::new();
        // Ethernet header (14 bytes)
        let dst_mac = [0x02, 0x00, 0x00, 0x00, 0x10, 0x01]; // wan0 mac
        let src_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        pkt.extend_from_slice(&dst_mac);
        pkt.extend_from_slice(&src_mac);
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes)
        let ipv4_start = pkt.len();
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00); // DSCP/ECN
        let total_len: u16 = 20 + 8; // IP header + 8 bytes UDP
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // identification
        pkt.extend_from_slice(&[0x00, 0x00]); // flags/fragment
        pkt.push(64); // TTL
        pkt.push(17); // protocol: UDP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&[192, 168, 10, 100]); // src IP (LAN)
        pkt.extend_from_slice(&[8, 8, 8, 8]); // dst IP (internet)

        // Compute IPv4 checksum.
        {
            let hdr = &mut pkt[ipv4_start..ipv4_start + 20];
            hdr[10] = 0x00;
            hdr[11] = 0x00;
            let mut sum: u32 = 0;
            for i in (0..hdr.len()).step_by(2) {
                let word = u16::from_be_bytes([hdr[i], hdr[i + 1]]);
                sum += word as u32;
            }
            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            let cksum = !(sum as u16);
            hdr[10] = (cksum >> 8) as u8;
            hdr[11] = (cksum & 0xFF) as u8;
        }

        // Minimal UDP header (8 bytes).
        pkt.extend_from_slice(&[0x00, 0x50]); // src port: 80
        pkt.extend_from_slice(&[0x00, 0x51]); // dst port: 81
        pkt.extend_from_slice(&[0x00, 0x08]); // length: 8
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum: 0

        io::RawPacket {
            ingress_iface: "lan0".to_string(),
            data: pkt,
        }
    }

    #[test]
    fn dataplane_run_counts_tx_errors() {
        let config = load_example_fw_disabled();
        let dp = Dataplane::init(&config).expect("init should succeed");
        prepopulate_arp(&dp);

        let mock_io = io::MockPacketIo::new();

        // Inject two forwardable packets.
        mock_io.inject(make_forwardable_packet());
        mock_io.inject(make_forwardable_packet());

        // Enable TX failure mode so all tx() calls fail.
        mock_io.set_tx_fail_mode(true);

        // Pre-set shutdown; the loop will process the queued packets
        // then exit on the next iteration when rx() returns empty.
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_trigger = Arc::clone(&shutdown);

        // Signal shutdown after a short delay to allow processing.
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            shutdown_trigger.store(true, Ordering::Relaxed);
        });

        let result = dp.run(shutdown, Box::new(mock_io));
        assert!(result.is_ok(), "run should return Ok on clean shutdown");

        handle.join().expect("trigger thread should join cleanly");

        // Both forwarded packets should have caused TX errors.
        assert_eq!(
            dp.tx_error_count(),
            2,
            "tx_error_count should reflect 2 TX failures"
        );
    }

    // ── Observer wiring tests ──────────────────────────────────────────

    #[test]
    fn observer_created_with_config_interfaces() {
        let config = load_example();
        let dp = Dataplane::init(&config).expect("init should succeed");

        // The example config has 3 interfaces: wan0, lan0, lan1.
        assert_eq!(dp.observer.interfaces.len(), 3);
        assert!(dp.observer.interfaces.contains_key("wan0"));
        assert!(dp.observer.interfaces.contains_key("lan0"));
        assert!(dp.observer.interfaces.contains_key("lan1"));
    }

    #[test]
    fn observer_rx_counter_increments_on_packet_process() {
        let config = load_example_fw_disabled();
        let dp = Dataplane::init(&config).expect("init should succeed");

        let mock_io = io::MockPacketIo::new();
        let pkt = make_forwardable_packet();
        let pkt_len = pkt.data.len() as u64;
        mock_io.inject(pkt);

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_trigger = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            shutdown_trigger.store(true, Ordering::Relaxed);
        });

        dp.run(shutdown, Box::new(mock_io)).expect("run ok");
        handle.join().unwrap();

        let snap = dp.observer.snapshot();
        // The packet enters on lan0.
        let lan0 = snap.interfaces.iter().find(|i| i.name == "lan0").unwrap();
        assert_eq!(lan0.rx_packets, 1, "RX packet count on lan0");
        assert_eq!(lan0.rx_bytes, pkt_len, "RX byte count on lan0");
    }

    #[test]
    fn observer_tx_counter_increments_on_successful_forward() {
        let config = load_example_fw_disabled();
        let dp = Dataplane::init(&config).expect("init should succeed");
        prepopulate_arp(&dp);

        let mock_io = io::MockPacketIo::new();
        let pkt = make_forwardable_packet();
        let pkt_len = pkt.data.len() as u64;
        mock_io.inject(pkt);

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_trigger = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            shutdown_trigger.store(true, Ordering::Relaxed);
        });

        dp.run(shutdown, Box::new(mock_io)).expect("run ok");
        handle.join().unwrap();

        let snap = dp.observer.snapshot();
        // The packet is forwarded to wan0 (default route).
        let wan0 = snap.interfaces.iter().find(|i| i.name == "wan0").unwrap();
        assert_eq!(wan0.tx_packets, 1, "TX packet count on wan0");
        assert_eq!(wan0.tx_bytes, pkt_len, "TX byte count on wan0");
        assert_eq!(snap.forwarded, 1, "forwarded count");
    }

    #[test]
    fn observer_tx_drop_counter_increments_on_tx_failure() {
        let config = load_example_fw_disabled();
        let dp = Dataplane::init(&config).expect("init should succeed");
        prepopulate_arp(&dp);

        let mock_io = io::MockPacketIo::new();
        mock_io.inject(make_forwardable_packet());
        mock_io.inject(make_forwardable_packet());
        mock_io.set_tx_fail_mode(true);

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_trigger = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            shutdown_trigger.store(true, Ordering::Relaxed);
        });

        dp.run(shutdown, Box::new(mock_io)).expect("run ok");
        handle.join().unwrap();

        let snap = dp.observer.snapshot();
        // TX fails -> tx_drops on wan0 should be 2.
        let wan0 = snap.interfaces.iter().find(|i| i.name == "wan0").unwrap();
        assert_eq!(wan0.tx_drops, 2, "TX drop count on wan0");
        assert_eq!(wan0.tx_packets, 0, "TX packets should be 0 when all fail");
        // Forwarded count still increments (decision was made to forward).
        assert_eq!(snap.forwarded, 2, "forwarded count still 2");
    }

    #[test]
    fn observer_drop_reason_parse_error() {
        let config = load_example_fw_disabled();
        let dp = Dataplane::init(&config).expect("init should succeed");

        let mock_io = io::MockPacketIo::new();
        // Inject a too-short packet that will fail parsing.
        mock_io.inject(io::RawPacket {
            ingress_iface: "lan0".to_string(),
            data: vec![0x00; 5],
        });

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_trigger = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            shutdown_trigger.store(true, Ordering::Relaxed);
        });

        dp.run(shutdown, Box::new(mock_io)).expect("run ok");
        handle.join().unwrap();

        let snap = dp.observer.snapshot();
        assert_eq!(snap.drops.parse_error, 1, "parse error drop count");
        // RX counter should still be incremented (we received the packet).
        let lan0 = snap.interfaces.iter().find(|i| i.name == "lan0").unwrap();
        assert_eq!(lan0.rx_packets, 1, "RX counted even for parse errors");
    }

    #[test]
    fn observer_drop_reason_ttl_expired() {
        let config = load_example_fw_disabled();
        let dp = Dataplane::init(&config).expect("init should succeed");

        let mock_io = io::MockPacketIo::new();
        // Build a packet with TTL=1 to trigger TTL expiration.
        let mut pkt = make_forwardable_packet();
        // TTL is at IPv4 header offset 8, which starts at Ethernet header (14) + 8.
        pkt.data[14 + 8] = 1; // Set TTL to 1
                              // Recompute IPv4 checksum.
        {
            let hdr = &mut pkt.data[14..34];
            hdr[10] = 0x00;
            hdr[11] = 0x00;
            let mut sum: u32 = 0;
            for i in (0..hdr.len()).step_by(2) {
                let word = u16::from_be_bytes([hdr[i], hdr[i + 1]]);
                sum += word as u32;
            }
            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            let cksum = !(sum as u16);
            hdr[10] = (cksum >> 8) as u8;
            hdr[11] = (cksum & 0xFF) as u8;
        }
        mock_io.inject(pkt);

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_trigger = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            shutdown_trigger.store(true, Ordering::Relaxed);
        });

        dp.run(shutdown, Box::new(mock_io)).expect("run ok");
        handle.join().unwrap();

        let snap = dp.observer.snapshot();
        assert_eq!(snap.drops.l3_ttl_expired, 1, "TTL expired drop count");
    }

    #[test]
    fn observer_drop_reason_no_route() {
        // Build a config with no default route so packets to external IPs get dropped.
        let toml = example_toml()
            .replace(
                "\n[firewall]\nenabled = true\n",
                "\n[firewall]\nenabled = false\n",
            )
            .replace("\n[nat]\nenabled = true\n", "\n[nat]\nenabled = false\n")
            .replace(
                "ipv4_static_routes = [\n  { prefix = \"0.0.0.0/0\"",
                "ipv4_static_routes = [\n  { prefix = \"10.99.99.0/24\"",
            );
        let mut config = ruster_config::load_from_str(&toml).expect("valid config");
        config.l2.bridge_domains.clear();
        let dp = Dataplane::init(&config).expect("init should succeed");

        let mock_io = io::MockPacketIo::new();
        // The packet destination 8.8.8.8 has no route (no default route).
        mock_io.inject(make_forwardable_packet());

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_trigger = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            shutdown_trigger.store(true, Ordering::Relaxed);
        });

        dp.run(shutdown, Box::new(mock_io)).expect("run ok");
        handle.join().unwrap();

        let snap = dp.observer.snapshot();
        assert_eq!(snap.drops.l3_no_route, 1, "no route drop count");
    }

    #[test]
    fn observer_local_delivery_increments_on_consumed() {
        let config = load_example_fw_disabled();
        let dp = Dataplane::init(&config).expect("init should succeed");

        let mock_io = io::MockPacketIo::new();
        // Build a packet destined to the router's own WAN IP (203.0.113.2).
        let mut pkt = make_forwardable_packet();
        // Overwrite destination IP (bytes 30..34) to the router's WAN IP.
        pkt.data[30] = 203;
        pkt.data[31] = 0;
        pkt.data[32] = 113;
        pkt.data[33] = 2;
        // Recompute IPv4 checksum.
        {
            let hdr = &mut pkt.data[14..34];
            hdr[10] = 0x00;
            hdr[11] = 0x00;
            let mut sum: u32 = 0;
            for i in (0..hdr.len()).step_by(2) {
                let word = u16::from_be_bytes([hdr[i], hdr[i + 1]]);
                sum += word as u32;
            }
            while (sum >> 16) != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            let cksum = !(sum as u16);
            hdr[10] = (cksum >> 8) as u8;
            hdr[11] = (cksum & 0xFF) as u8;
        }
        mock_io.inject(pkt);

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_trigger = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            shutdown_trigger.store(true, Ordering::Relaxed);
        });

        dp.run(shutdown, Box::new(mock_io)).expect("run ok");
        handle.join().unwrap();

        let snap = dp.observer.snapshot();
        assert_eq!(snap.local_delivery, 1, "local delivery count");
    }

    #[test]
    fn observer_snapshot_after_mixed_traffic() {
        let config = load_example_fw_disabled();
        let dp = Dataplane::init(&config).expect("init should succeed");
        prepopulate_arp(&dp);

        let mock_io = io::MockPacketIo::new();

        // 1. Forwardable packet.
        mock_io.inject(make_forwardable_packet());

        // 2. Parse error packet.
        mock_io.inject(io::RawPacket {
            ingress_iface: "lan0".to_string(),
            data: vec![0x00; 5],
        });

        // 3. Another forwardable packet.
        mock_io.inject(make_forwardable_packet());

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_trigger = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            shutdown_trigger.store(true, Ordering::Relaxed);
        });

        dp.run(shutdown, Box::new(mock_io)).expect("run ok");
        handle.join().unwrap();

        let snap = dp.observer.snapshot();

        // 3 packets received on lan0.
        let lan0 = snap.interfaces.iter().find(|i| i.name == "lan0").unwrap();
        assert_eq!(lan0.rx_packets, 3, "all 3 packets counted on RX");

        // 2 forwarded, 1 parse error.
        assert_eq!(snap.forwarded, 2, "2 packets forwarded");
        assert_eq!(snap.drops.parse_error, 1, "1 parse error");

        // 2 TX on wan0.
        let wan0 = snap.interfaces.iter().find(|i| i.name == "wan0").unwrap();
        assert_eq!(wan0.tx_packets, 2, "2 packets transmitted on wan0");
    }

    #[test]
    fn map_pipeline_drop_to_observe_covers_all_variants() {
        use pipeline::DropReason as PD;
        use ruster_observe::DropReason as OD;

        assert_eq!(
            map_pipeline_drop_to_observe(&PD::ParseError),
            OD::ParseError
        );
        assert_eq!(
            map_pipeline_drop_to_observe(&PD::L2Drop),
            OD::L2NoBridgeDomain
        );
        assert_eq!(map_pipeline_drop_to_observe(&PD::L3NoRoute), OD::L3NoRoute);
        assert_eq!(
            map_pipeline_drop_to_observe(&PD::L3TtlExpired),
            OD::L3TtlExpired
        );
        assert_eq!(map_pipeline_drop_to_observe(&PD::L3NotIpv4), OD::L3NotIpv4);
        assert_eq!(
            map_pipeline_drop_to_observe(&PD::L3HopLimitExpired),
            OD::L3TtlExpired
        );
        assert_eq!(
            map_pipeline_drop_to_observe(&PD::FirewallDrop),
            OD::FirewallDrop
        );
        assert_eq!(map_pipeline_drop_to_observe(&PD::NatDrop), OD::NatTableFull);
        assert_eq!(
            map_pipeline_drop_to_observe(&PD::ConntrackTableFull),
            OD::ConntrackTableFull
        );
        assert_eq!(
            map_pipeline_drop_to_observe(&PD::Srv6Drop(crate::srv6::Srv6DropReason::SrhTooShort)),
            OD::Srv6Drop
        );
    }
}
