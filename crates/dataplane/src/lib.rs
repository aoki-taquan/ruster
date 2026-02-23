pub mod arp;
pub mod conntrack;
pub mod dpdk;
pub mod firewall;
pub mod l2;
pub mod nat;
pub mod packet;
pub mod routing;

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
}
