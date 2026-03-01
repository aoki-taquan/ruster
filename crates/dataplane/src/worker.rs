//! Worker thread pool for parallel packet processing.
//!
//! Each [`Worker`] runs a dedicated RX/TX loop on a subset of interfaces.
//! The [`WorkerPool`] manages the lifecycle of all workers: spawn, shutdown,
//! and join.
//!
//! Engines are shared via `Arc`-wrapped references:
//! - Read-only engines (L3, firewall, zone_resolver, iface_macs) need no locking.
//! - Mutable engines (L2, ARP, NAT, conntrack, ND, hold_queue) are `Mutex`-wrapped
//!   in the parent [`Dataplane`] struct.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::io::{self, PacketIo, RawPacket};
use crate::{arp, map_pipeline_drop_to_observe, nd, pipeline, rewrite, Dataplane};

/// A single packet-processing worker thread.
///
/// Each worker is assigned a set of interfaces and runs a tight RX → pipeline → TX
/// loop until the shutdown flag is set.
pub struct Worker {
    /// Worker identifier (0-indexed).
    pub id: usize,
    /// Interfaces assigned to this worker for RX.
    pub assigned_ifaces: Vec<String>,
    /// Thread handle (populated after spawn).
    handle: Option<JoinHandle<()>>,
}

/// Pool of worker threads for parallel packet processing.
pub struct WorkerPool {
    workers: Vec<Worker>,
}

impl WorkerPool {
    /// Distribute interfaces across `worker_count` workers using round-robin.
    fn assign_interfaces(all_ifaces: &[String], worker_count: usize) -> Vec<Vec<String>> {
        let mut assignments: Vec<Vec<String>> = (0..worker_count).map(|_| Vec::new()).collect();
        for (i, iface) in all_ifaces.iter().enumerate() {
            assignments[i % worker_count].push(iface.clone());
        }
        assignments
    }

    /// Spawn worker threads.
    ///
    /// Each worker gets a subset of interfaces and runs a dedicated RX/TX loop.
    /// The `dataplane` reference provides shared access to all engines.
    /// The `io` backend is shared (Arc) across all workers.
    pub fn spawn(
        dataplane: Arc<Dataplane>,
        io: Arc<dyn PacketIo>,
        shutdown: Arc<AtomicBool>,
        worker_count: usize,
        all_ifaces: &[String],
    ) -> Self {
        let assignments = Self::assign_interfaces(all_ifaces, worker_count);

        let workers: Vec<Worker> = assignments
            .into_iter()
            .enumerate()
            .map(|(id, ifaces)| {
                let dp = Arc::clone(&dataplane);
                let io = Arc::clone(&io);
                let shutdown = Arc::clone(&shutdown);
                let ifaces_clone = ifaces.clone();

                let handle = thread::Builder::new()
                    .name(format!("worker-{id}"))
                    .spawn(move || {
                        worker_loop(id, &ifaces_clone, &dp, &*io, &shutdown);
                    })
                    .expect("failed to spawn worker thread");

                Worker {
                    id,
                    assigned_ifaces: ifaces,
                    handle: Some(handle),
                }
            })
            .collect();

        eprintln!("WorkerPool: spawned {} workers", workers.len());
        for w in &workers {
            eprintln!("  worker-{}: interfaces {:?}", w.id, w.assigned_ifaces);
        }

        Self { workers }
    }

    /// Wait for all worker threads to finish.
    ///
    /// Should be called after setting the shutdown flag. Returns once all
    /// workers have exited their RX/TX loops.
    pub fn join_all(&mut self) {
        for worker in &mut self.workers {
            if let Some(handle) = worker.handle.take() {
                if let Err(e) = handle.join() {
                    eprintln!("worker-{}: thread panicked: {:?}", worker.id, e);
                }
            }
        }
    }

    /// Return the number of workers.
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }
}

/// The packet-processing loop for a single worker.
///
/// Receives packets from the assigned interfaces, processes them through
/// the pipeline, and transmits the results. Runs until the shutdown flag
/// is set.
fn worker_loop(
    worker_id: usize,
    ifaces: &[String],
    dp: &Dataplane,
    io: &dyn PacketIo,
    shutdown: &AtomicBool,
) {
    eprintln!("worker-{worker_id}: started, interfaces: {ifaces:?}");

    while !shutdown.load(Ordering::Relaxed) {
        let batch = io.rx_on_ifaces(ifaces);
        if batch.is_empty() {
            thread::sleep(Duration::from_millis(1));
            continue;
        }

        for raw_pkt in &batch {
            dp.observer
                .inc_rx(&raw_pkt.ingress_iface, raw_pkt.data.len() as u64);

            let result = {
                let mut l2_guard = dp.l2.lock().unwrap();
                let mut ct_guard = dp.conntrack.lock().unwrap();
                let mut nat_guard = dp.nat.lock().unwrap();
                let mut nd_guard = dp.nd.lock().unwrap();
                pipeline::process_packet_v6(
                    raw_pkt,
                    &mut l2_guard,
                    &dp.l3,
                    &dp.firewall,
                    &mut ct_guard,
                    &mut nat_guard,
                    &dp.zone_resolver,
                    &dp.iface_macs,
                    Some(&mut nd_guard),
                    Some(&dp.ipv6_routes),
                    dp.srv6.as_ref(),
                    &dp.ifindex_map,
                )
            };

            handle_pipeline_result(dp, io, raw_pkt, result);
        }
    }

    eprintln!("worker-{worker_id}: shutting down");
}

/// Handle a pipeline result: apply rewrites and transmit.
///
/// Factored out of the run loop so that both the single-threaded path
/// and the worker-pool path can share the same logic.
pub fn handle_pipeline_result(
    dp: &Dataplane,
    io: &dyn PacketIo,
    raw_pkt: &RawPacket,
    result: pipeline::PipelineResult,
) {
    let ifm = &dp.ifindex_map;

    match result {
        pipeline::PipelineResult::Forward {
            egress_ifindex,
            new_ttl,
            next_hop,
            nat: nat_result,
        } => {
            let egress_iface = ifm.get_name(egress_ifindex);
            dp.observer.inc_forwarded();

            let tx_data;
            let needs_rewrite =
                new_ttl.is_some() || next_hop.is_some() || nat_result != pipeline::NatResult::None;
            let tx_pkt = if needs_rewrite {
                let mut data = raw_pkt.data.clone();

                // 1. NAT rewrite
                match &nat_result {
                    pipeline::NatResult::Snat {
                        new_src_ip,
                        new_src_port,
                    } => {
                        if !rewrite::rewrite_snat(&mut data, *new_src_ip, *new_src_port) {
                            dp.observer.inc_nat_drop();
                            return;
                        }
                        dp.observer.inc_nat_snat();
                    }
                    pipeline::NatResult::Dnat {
                        new_dst_ip,
                        new_dst_port,
                    } => {
                        if !rewrite::rewrite_dnat(&mut data, *new_dst_ip, *new_dst_port) {
                            dp.observer.inc_nat_drop();
                            return;
                        }
                        dp.observer.inc_nat_dnat();
                    }
                    pipeline::NatResult::None => {}
                }

                // 2. TTL + checksum
                if let Some(ttl) = new_ttl {
                    rewrite::rewrite_ipv4_ttl(&mut data, ttl);
                }

                // 3. src MAC -> egress IF's MAC
                if let Some(mac) = dp.iface_macs.get(egress_iface) {
                    rewrite::rewrite_src_mac(&mut data, mac);
                }

                // 4. dst MAC -> ARP resolve
                if let Some(nh) = next_hop {
                    let arp_target = if nh != [0, 0, 0, 0] {
                        nh
                    } else if data.len() >= 34 {
                        [data[30], data[31], data[32], data[33]]
                    } else {
                        dp.observer
                            .inc_drop_reason(ruster_observe::DropReason::L3NoRoute);
                        return;
                    };
                    let arp_result = {
                        let mut arp_guard = dp.arp.lock().unwrap();
                        arp_guard.resolve(arp_target, egress_iface)
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
                            let enqueue_result = {
                                let mut hq_guard = dp.hold_queue.lock().unwrap();
                                hq_guard.enqueue(arp_target, egress_iface.to_owned(), data, new_ttl)
                            };
                            match enqueue_result {
                                arp::hold_queue::EnqueueResult::Enqueued => {
                                    dp.observer.inc_arp_hold_enqueued();
                                }
                                _ => {
                                    dp.observer.inc_arp_hold_tail_dropped();
                                }
                            }

                            let should_send = {
                                let mut arp_guard = dp.arp.lock().unwrap();
                                arp_guard.should_send_request(target_ip)
                            };
                            if should_send {
                                let arp_pkt =
                                    arp::build_arp_request(sender_mac, sender_ip, target_ip);
                                let arp_raw = io::RawPacket {
                                    ingress_iface: out_ifname.clone(),
                                    data: arp_pkt,
                                };
                                let _ = io.tx(&out_ifname, &arp_raw);
                            }
                            return;
                        }
                        arp::ArpAction::Drop => {
                            dp.observer
                                .inc_drop_reason(ruster_observe::DropReason::ArpUnresolved);
                            return;
                        }
                        arp::ArpAction::Reply { .. } | arp::ArpAction::Update => {
                            dp.observer
                                .inc_drop_reason(ruster_observe::DropReason::ArpUnresolved);
                            return;
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

            match io.tx(egress_iface, tx_pkt) {
                Ok(()) => {
                    dp.observer.inc_tx(egress_iface, raw_pkt.data.len() as u64);
                }
                Err(e) => {
                    dp.tx_errors.fetch_add(1, Ordering::Relaxed);
                    dp.observer.inc_tx_drop(egress_iface);
                    eprintln!("TX error on {}: {}", egress_iface, e);
                }
            }
        }
        pipeline::PipelineResult::ForwardV6 {
            egress_ifindex,
            new_hop_limit,
            next_hop_v6,
            srv6_new_da,
            srv6_srh_rewrite,
        } => {
            let egress_iface = ifm.get_name(egress_ifindex);
            dp.observer.inc_forwarded();

            let mut data = raw_pkt.data.clone();

            if let Some(ref new_da) = srv6_new_da {
                rewrite::rewrite_ipv6_da(&mut data, new_da);
            }
            if let Some((srh_offset, new_sl)) = srv6_srh_rewrite {
                rewrite::rewrite_srh_segments_left(&mut data, srh_offset, new_sl);
            }
            rewrite::rewrite_ipv6_hop_limit(&mut data, new_hop_limit);

            if let Some(mac) = dp.iface_macs.get(egress_iface) {
                rewrite::rewrite_src_mac(&mut data, mac);
            }

            let nd_target = if next_hop_v6 != [0u8; 16] {
                next_hop_v6
            } else if data.len() >= 54 {
                let mut dst = [0u8; 16];
                dst.copy_from_slice(&data[38..54]);
                dst
            } else {
                dp.observer
                    .inc_drop_reason(ruster_observe::DropReason::L3NoRoute);
                return;
            };

            let nd_result = {
                let mut nd_guard = dp.nd.lock().unwrap();
                nd_guard.resolve(nd_target, egress_iface)
            };
            match nd_result {
                nd::NdAction::Forward { resolved_mac } => {
                    rewrite::rewrite_dst_mac(&mut data, &resolved_mac);
                }
                _ => {
                    dp.observer
                        .inc_drop_reason(ruster_observe::DropReason::L3NoRoute);
                    return;
                }
            }

            let tx_data = io::RawPacket {
                ingress_iface: raw_pkt.ingress_iface.clone(),
                data,
            };

            match io.tx(egress_iface, &tx_data) {
                Ok(()) => {
                    dp.observer.inc_tx(egress_iface, raw_pkt.data.len() as u64);
                }
                Err(e) => {
                    dp.tx_errors.fetch_add(1, Ordering::Relaxed);
                    dp.observer.inc_tx_drop(egress_iface);
                    eprintln!("TX error on {}: {}", egress_iface, e);
                }
            }
        }
        pipeline::PipelineResult::Flood { egress_ifindices } => {
            dp.observer.inc_forwarded();
            for idx in &egress_ifindices {
                let iface = ifm.get_name(*idx);
                match io.tx(iface, raw_pkt) {
                    Ok(()) => {
                        dp.observer.inc_tx(iface, raw_pkt.data.len() as u64);
                    }
                    Err(e) => {
                        dp.tx_errors.fetch_add(1, Ordering::Relaxed);
                        dp.observer.inc_tx_drop(iface);
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
            dp.observer.inc_drop_reason(obs_reason);
            if reason == pipeline::DropReason::ConntrackTableFull {
                dp.observer.inc_conntrack_table_full();
            }
            if reason == pipeline::DropReason::NatDrop {
                dp.observer.inc_nat_drop();
            }
            let icmp_pkt = io::RawPacket {
                ingress_iface: reply.egress_iface.clone(),
                data: reply.data,
            };
            if let Err(e) = io.tx(&reply.egress_iface, &icmp_pkt) {
                dp.tx_errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("TX error for ICMP reply on {}: {}", reply.egress_iface, e);
            }
        }
        pipeline::PipelineResult::Drop { reason, .. } => {
            let obs_reason = map_pipeline_drop_to_observe(&reason);
            dp.observer.inc_drop_reason(obs_reason);
            if reason == pipeline::DropReason::ConntrackTableFull {
                dp.observer.inc_conntrack_table_full();
            }
            if reason == pipeline::DropReason::NatDrop {
                dp.observer.inc_nat_drop();
            }
        }
        pipeline::PipelineResult::DecapToIpv4 { inner_offset } => {
            // SRv6 End.DT4: extract inner IPv4 packet and re-inject.
            //
            // RFC-REF: RFC 8986 Section 4.1.4
            // "Pop the outer IPv6 header with all its extension headers and
            // submit the inner IPv4 packet to the IPv4 FIB."
            if inner_offset >= raw_pkt.data.len() {
                dp.observer
                    .inc_drop_reason(ruster_observe::DropReason::ParseError);
                return;
            }
            let inner = &raw_pkt.data[inner_offset..];
            // Build a synthetic Ethernet frame: reuse original MACs + IPv4 EtherType.
            let mut synth = Vec::with_capacity(14 + inner.len());
            synth.extend_from_slice(&raw_pkt.data[0..12]); // dst + src MAC
            synth.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4
            synth.extend_from_slice(inner);

            let synth_pkt = io::RawPacket {
                ingress_iface: raw_pkt.ingress_iface.clone(),
                data: synth,
            };

            let inner_result = {
                let mut l2_guard = dp.l2.lock().unwrap();
                let mut ct_guard = dp.conntrack.lock().unwrap();
                let mut nat_guard = dp.nat.lock().unwrap();
                let mut nd_guard = dp.nd.lock().unwrap();
                pipeline::process_packet_v6(
                    &synth_pkt,
                    &mut l2_guard,
                    &dp.l3,
                    &dp.firewall,
                    &mut ct_guard,
                    &mut nat_guard,
                    &dp.zone_resolver,
                    &dp.iface_macs,
                    Some(&mut nd_guard),
                    Some(&dp.ipv6_routes),
                    dp.srv6.as_ref(),
                )
            };
            handle_pipeline_result(dp, io, &synth_pkt, inner_result);
        }
        pipeline::PipelineResult::DecapToIpv6 { inner_offset } => {
            // SRv6 End.DT6: extract inner IPv6 packet and re-inject.
            //
            // RFC-REF: RFC 8986 Section 4.1.5
            // "Pop the outer IPv6 header with all its extension headers and
            // submit the inner IPv6 packet to the IPv6 FIB."
            if inner_offset >= raw_pkt.data.len() {
                dp.observer
                    .inc_drop_reason(ruster_observe::DropReason::ParseError);
                return;
            }
            let inner = &raw_pkt.data[inner_offset..];
            // Build a synthetic Ethernet frame: reuse original MACs + IPv6 EtherType.
            let mut synth = Vec::with_capacity(14 + inner.len());
            synth.extend_from_slice(&raw_pkt.data[0..12]); // dst + src MAC
            synth.extend_from_slice(&[0x86, 0xDD]); // EtherType: IPv6
            synth.extend_from_slice(inner);

            let synth_pkt = io::RawPacket {
                ingress_iface: raw_pkt.ingress_iface.clone(),
                data: synth,
            };

            let inner_result = {
                let mut l2_guard = dp.l2.lock().unwrap();
                let mut ct_guard = dp.conntrack.lock().unwrap();
                let mut nat_guard = dp.nat.lock().unwrap();
                let mut nd_guard = dp.nd.lock().unwrap();
                pipeline::process_packet_v6(
                    &synth_pkt,
                    &mut l2_guard,
                    &dp.l3,
                    &dp.firewall,
                    &mut ct_guard,
                    &mut nat_guard,
                    &dp.zone_resolver,
                    &dp.iface_macs,
                    Some(&mut nd_guard),
                    Some(&dp.ipv6_routes),
                    dp.srv6.as_ref(),
                )
            };
            handle_pipeline_result(dp, io, &synth_pkt, inner_result);
        }
        pipeline::PipelineResult::Consumed => {
            dp.observer.inc_local_delivery();
        }
        pipeline::PipelineResult::NdReply {
            egress_ifindex,
            reply_info,
        } => {
            let egress_iface = ifm.get_name(egress_ifindex);
            dp.observer.inc_local_delivery();
            let na_data = nd::build_na_packet(&reply_info);
            let na_pkt = io::RawPacket {
                ingress_iface: egress_iface.to_owned(),
                data: na_data,
            };
            match io.tx(egress_iface, &na_pkt) {
                Ok(()) => {
                    dp.observer.inc_tx(egress_iface, na_pkt.data.len() as u64);
                }
                Err(e) => {
                    dp.tx_errors.fetch_add(1, Ordering::Relaxed);
                    dp.observer.inc_tx_drop(egress_iface);
                    eprintln!("TX error for ND reply on {}: {}", egress_iface, e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::MockPacketIo;
    use std::path::PathBuf;

    fn example_toml() -> String {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.push("router.toml.example");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
    }

    fn load_example() -> ruster_config::model::RouterConfig {
        ruster_config::load_from_str(&example_toml()).expect("valid config")
    }

    #[test]
    fn worker_pool_assign_interfaces_round_robin() {
        let ifaces = vec![
            "lan0".to_string(),
            "wan0".to_string(),
            "lan1".to_string(),
            "wan1".to_string(),
        ];
        let assignments = WorkerPool::assign_interfaces(&ifaces, 2);
        assert_eq!(assignments.len(), 2);
        assert_eq!(assignments[0], vec!["lan0", "lan1"]);
        assert_eq!(assignments[1], vec!["wan0", "wan1"]);
    }

    #[test]
    fn worker_pool_assign_single_worker() {
        let ifaces = vec!["lan0".to_string(), "wan0".to_string()];
        let assignments = WorkerPool::assign_interfaces(&ifaces, 1);
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0], vec!["lan0", "wan0"]);
    }

    #[test]
    fn worker_pool_assign_more_workers_than_ifaces() {
        let ifaces = vec!["lan0".to_string()];
        let assignments = WorkerPool::assign_interfaces(&ifaces, 3);
        assert_eq!(assignments.len(), 3);
        assert_eq!(assignments[0], vec!["lan0"]);
        assert!(assignments[1].is_empty());
        assert!(assignments[2].is_empty());
    }

    #[test]
    fn worker_pool_spawn_and_shutdown() {
        let config = load_example();
        let dp = Arc::new(Dataplane::init(&config).expect("init"));
        let io: Arc<dyn PacketIo> = Arc::new(MockPacketIo::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let ifaces = vec!["lan0".to_string(), "wan0".to_string()];
        let mut pool = WorkerPool::spawn(
            Arc::clone(&dp),
            Arc::clone(&io),
            Arc::clone(&shutdown),
            2,
            &ifaces,
        );
        assert_eq!(pool.worker_count(), 2);

        // Signal shutdown and wait for workers to exit.
        shutdown.store(true, Ordering::Relaxed);
        pool.join_all();
    }

    #[test]
    fn worker_pool_processes_packets() {
        let config = load_example();
        let dp = Arc::new(Dataplane::init(&config).expect("init"));
        let mock_io = MockPacketIo::new();

        // Inject a simple packet (will likely be dropped as parse error, but
        // verifies the worker loop processes it without panicking).
        mock_io.inject(io::RawPacket {
            ingress_iface: "lan0".to_string(),
            data: vec![0xFF; 64],
        });

        let io: Arc<dyn PacketIo> = Arc::new(mock_io);
        let shutdown = Arc::new(AtomicBool::new(false));

        let ifaces = vec!["lan0".to_string(), "wan0".to_string()];
        let mut pool = WorkerPool::spawn(
            Arc::clone(&dp),
            Arc::clone(&io),
            Arc::clone(&shutdown),
            1,
            &ifaces,
        );

        // Give worker time to process the packet.
        std::thread::sleep(Duration::from_millis(50));

        shutdown.store(true, Ordering::Relaxed);
        pool.join_all();

        // The packet should have been counted (RX on lan0).
        let snap = format!("{}", dp.observer.snapshot());
        assert!(
            snap.contains("lan0"),
            "observer should have lan0 stats: {snap}"
        );
    }
}
