pub mod arp;
pub mod conntrack;
pub mod dpdk;
pub mod firewall;
pub mod io;
pub mod l2;
pub mod nat;
pub mod packet;
pub mod pipeline;
pub mod routing;

use std::sync::atomic::{AtomicBool, Ordering};
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

        Ok(Self {
            l2,
            arp,
            l3,
            nat,
            firewall,
            conntrack,
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
                let result =
                    pipeline::process_packet(raw_pkt, &self.l3, &self.firewall, &self.conntrack);
                match result {
                    pipeline::PipelineResult::Forward { egress_iface } => {
                        let _ = io.tx(&egress_iface, raw_pkt);
                    }
                    pipeline::PipelineResult::Drop { .. } | pipeline::PipelineResult::Consumed => {}
                }
            }
        }

        Ok(())
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
}
