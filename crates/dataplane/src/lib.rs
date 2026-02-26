pub mod arp;
pub mod conntrack;
pub mod dpdk;
pub mod firewall;
pub mod icmp;
pub mod io;
pub mod l2;
pub mod nat;
pub mod packet;
pub mod pipeline;
pub mod routing;

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
    /// ARP resolution engine (per-interface ARP caches and hold queue).
    ///
    /// Wrapped in a `Mutex` because [`arp::ArpEngine::resolve`] and
    /// [`arp::ArpEngine::queue_packet`] require `&mut self`, while the
    /// run loop takes `&self`.
    pub arp: Mutex<arp::ArpEngine>,
    /// L3 IPv4 forwarding engine (static routing, LPM).
    pub l3: routing::L3Engine,
    /// NAT44 engine (NAPT, port forwarding, hairpin).
    pub nat: nat::NatEngine,
    /// Stateful firewall engine.
    pub firewall: firewall::FirewallEngine,
    /// Connection tracking engine (session table).
    pub conntrack: conntrack::ConntrackEngine,
    /// Zone resolver: maps interface names to firewall zones.
    pub zone_resolver: pipeline::ZoneResolver,
    /// Counter for TX errors encountered in the run loop.
    tx_errors: AtomicU64,
    /// Observability hub: per-interface and per-stage counters.
    pub observer: Arc<ruster_observe::Observer>,
}

impl Dataplane {
    /// Initialize the dataplane from a validated configuration.
    ///
    /// Creates all sub-engines (L2, ARP, L3, NAT, FW, conntrack) from config.
    /// In v0.1 the DPDK backend is mocked, so no real NIC init happens.
    pub fn init(config: &RouterConfig) -> Result<Self, DataplaneError> {
        let l2 = l2::L2Engine::from_config(&config.l2);
        let arp = arp::ArpEngine::from_config(&config.l2, &config.interfaces);
        let l3 = routing::L3Engine::from_config(&config.routing, &config.interfaces)?;
        let nat = nat::NatEngine::from_config(&config.nat, &config.interfaces);
        let firewall = firewall::FirewallEngine::from_config(&config.firewall);
        let conntrack = conntrack::ConntrackEngine::from_nat_config(&config.nat);
        let zone_resolver = pipeline::ZoneResolver::from_config(&config.interfaces);

        let iface_names: Vec<String> = config.interfaces.iter().map(|i| i.name.clone()).collect();
        let observer = Arc::new(ruster_observe::Observer::new(&iface_names));

        Ok(Self {
            l2: Mutex::new(l2),
            arp: Mutex::new(arp),
            l3,
            nat,
            firewall,
            conntrack,
            zone_resolver,
            tx_errors: AtomicU64::new(0),
            observer,
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

        while !shutdown.load(Ordering::Relaxed) {
            let batch = io.rx();
            if batch.is_empty() {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            for raw_pkt in &batch {
                // Count RX on ingress interface.
                self.observer
                    .inc_rx(&raw_pkt.ingress_iface, raw_pkt.data.len() as u64);

                let result = {
                    let mut l2_guard = self.l2.lock().unwrap();
                    let mut arp_guard = self.arp.lock().unwrap();
                    pipeline::process_packet(
                        raw_pkt,
                        &mut l2_guard,
                        &self.l3,
                        &mut arp_guard,
                        &self.firewall,
                        &self.conntrack,
                        &self.zone_resolver,
                    )
                };
                match result {
                    pipeline::PipelineResult::Forward { egress_iface } => {
                        self.observer.inc_forwarded();
                        match io.tx(&egress_iface, raw_pkt) {
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
                        let obs_reason = map_pipeline_drop_to_observe(reason);
                        self.observer.inc_drop_reason(obs_reason);
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
                        let obs_reason = map_pipeline_drop_to_observe(reason);
                        self.observer.inc_drop_reason(obs_reason);
                    }
                    pipeline::PipelineResult::Consumed => {
                        self.observer.inc_local_delivery();
                    }
                    pipeline::PipelineResult::Queued { arp_request } => {
                        // The packet is held in the ARP engine's hold
                        // queue. If the ARP action is a Reply or
                        // SendRequest, we would need to construct and
                        // send the ARP packet. For v0.1, we log the
                        // event; the actual ARP packet transmission
                        // requires building a raw ARP frame which is
                        // handled in a future iteration.
                        //
                        // When the next ARP reply arrives for this
                        // next-hop, the hold queue will be flushed in
                        // the next iteration.
                        let _ = arp_request; // Suppress unused warning.
                    }
                }
            }

            // Periodic stats output every 10 seconds.
            if last_stats.elapsed() >= Duration::from_secs(10) {
                let snap = self.observer.snapshot();
                eprintln!("{}", snap);
                last_stats = std::time::Instant::now();
            }
        }

        Ok(())
    }

    /// Return the total number of TX errors observed by the run loop.
    pub fn tx_error_count(&self) -> u64 {
        self.tx_errors.load(Ordering::Relaxed)
    }
}

/// Map a pipeline [`pipeline::DropReason`] to an observe [`ruster_observe::DropReason`].
fn map_pipeline_drop_to_observe(reason: pipeline::DropReason) -> ruster_observe::DropReason {
    match reason {
        pipeline::DropReason::ParseError => ruster_observe::DropReason::ParseError,
        pipeline::DropReason::L2Drop => ruster_observe::DropReason::L2NoBridgeDomain,
        pipeline::DropReason::L3NoRoute => ruster_observe::DropReason::L3NoRoute,
        pipeline::DropReason::L3TtlExpired => ruster_observe::DropReason::L3TtlExpired,
        pipeline::DropReason::L3NotIpv4 => ruster_observe::DropReason::L3NotIpv4,
        pipeline::DropReason::FirewallDrop => ruster_observe::DropReason::FirewallDrop,
        pipeline::DropReason::NatDrop => ruster_observe::DropReason::NatTableFull,
        pipeline::DropReason::ArpUnresolved => ruster_observe::DropReason::ArpUnresolved,
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
        assert!(dp.nat.is_enabled());
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

    /// Pre-populate the ARP cache on the dataplane with the default
    /// gateway MAC so that forwardable packets get `Forward` instead
    /// of `Queued` (ARP cache miss).
    fn prepopulate_arp_cache(dp: &Dataplane) {
        use crate::packet::{ArpInfo, L2Info, L3Info, PacketMeta};

        let mut arp = dp.arp.lock().unwrap();

        // Simulate an ARP reply from the default gateway (203.0.113.1)
        // arriving on wan0 with a fake MAC.
        let gw_mac = [0xDE, 0xAD, 0x00, 0x00, 0x00, 0x01];
        let wan_mac = [0x02, 0x00, 0x00, 0x00, 0x10, 0x01];
        let arp_reply = PacketMeta {
            in_ifname: "wan0".to_string(),
            l2: L2Info {
                dst_mac: wan_mac,
                src_mac: gw_mac,
                ethertype: 0x0806,
            },
            l3: Some(L3Info::Arp(ArpInfo {
                operation: 2, // ARP Reply
                sender_mac: gw_mac,
                sender_ip: [203, 0, 113, 1],
                target_mac: wan_mac,
                target_ip: [203, 0, 113, 2],
            })),
            l4: None,
            raw_len: 42,
        };
        arp.process_arp(&arp_reply);
    }

    #[test]
    fn dataplane_run_counts_tx_errors() {
        let config = load_example_fw_disabled();
        let dp = Dataplane::init(&config).expect("init should succeed");
        prepopulate_arp_cache(&dp);

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
        prepopulate_arp_cache(&dp);

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
        prepopulate_arp_cache(&dp);

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
        prepopulate_arp_cache(&dp);

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
        prepopulate_arp_cache(&dp);

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

        assert_eq!(map_pipeline_drop_to_observe(PD::ParseError), OD::ParseError);
        assert_eq!(
            map_pipeline_drop_to_observe(PD::L2Drop),
            OD::L2NoBridgeDomain
        );
        assert_eq!(map_pipeline_drop_to_observe(PD::L3NoRoute), OD::L3NoRoute);
        assert_eq!(
            map_pipeline_drop_to_observe(PD::L3TtlExpired),
            OD::L3TtlExpired
        );
        assert_eq!(map_pipeline_drop_to_observe(PD::L3NotIpv4), OD::L3NotIpv4);
        assert_eq!(
            map_pipeline_drop_to_observe(PD::FirewallDrop),
            OD::FirewallDrop
        );
        assert_eq!(map_pipeline_drop_to_observe(PD::NatDrop), OD::NatTableFull);
        assert_eq!(
            map_pipeline_drop_to_observe(PD::ArpUnresolved),
            OD::ArpUnresolved
        );
    }
}
