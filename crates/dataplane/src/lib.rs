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
use std::sync::Arc;
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
    pub l2: l2::L2Engine,
    /// ARP resolution engine (per-interface ARP caches).
    pub arp: arp::ArpEngine,
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

        Ok(Self {
            l2,
            arp,
            l3,
            nat,
            firewall,
            conntrack,
            zone_resolver,
            tx_errors: AtomicU64::new(0),
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
        while !shutdown.load(Ordering::Relaxed) {
            let batch = io.rx();
            if batch.is_empty() {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            for raw_pkt in &batch {
                let result = pipeline::process_packet(
                    raw_pkt,
                    &self.l3,
                    &self.firewall,
                    &self.conntrack,
                    &self.zone_resolver,
                );
                match result {
                    pipeline::PipelineResult::Forward { egress_iface } => {
                        if let Err(e) = io.tx(&egress_iface, raw_pkt) {
                            self.tx_errors.fetch_add(1, Ordering::Relaxed);
                            eprintln!("TX error on {}: {}", egress_iface, e);
                        }
                    }
                    pipeline::PipelineResult::Drop {
                        icmp_reply: Some(reply),
                        ..
                    } => {
                        let icmp_pkt = io::RawPacket {
                            ingress_iface: reply.egress_iface.clone(),
                            data: reply.data,
                        };
                        if let Err(e) = io.tx(&reply.egress_iface, &icmp_pkt) {
                            self.tx_errors.fetch_add(1, Ordering::Relaxed);
                            eprintln!("TX error for ICMP reply on {}: {}", reply.egress_iface, e);
                        }
                    }
                    pipeline::PipelineResult::Drop { .. } | pipeline::PipelineResult::Consumed => {}
                }
            }
        }

        Ok(())
    }

    /// Return the total number of TX errors observed by the run loop.
    pub fn tx_error_count(&self) -> u64 {
        self.tx_errors.load(Ordering::Relaxed)
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

    /// Load the example config with the firewall and NAT disabled so
    /// that packets are forwarded (reach TX) in the run loop.
    fn load_example_fw_disabled() -> RouterConfig {
        let toml = example_toml()
            .replace(
                "\n[firewall]\nenabled = true\n",
                "\n[firewall]\nenabled = false\n",
            )
            .replace("\n[nat]\nenabled = true\n", "\n[nat]\nenabled = false\n");
        ruster_config::load_from_str(&toml).expect("valid config with fw disabled")
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
}
