pub mod backend;
pub mod config;
pub mod context;
pub mod error;
pub mod mock;
pub mod packetio;

use self::backend::DpdkBackend;
use self::config::DpdkConfig;
use self::context::DpdkContext;
use self::error::DpdkError;

/// Run the full DPDK initialisation sequence:
/// 1. Validate config
/// 2. EAL init
/// 3. Create mempool
/// 4. For each port with `admin_up = true`: init + start
pub fn init_dpdk(backend: &dyn DpdkBackend, config: &DpdkConfig) -> Result<DpdkContext, DpdkError> {
    config.validate()?;

    backend.eal_init(config)?;
    let mempool = backend.create_mempool(config)?;

    let mut ports = Vec::new();
    for port_cfg in &config.ports {
        if !port_cfg.admin_up {
            continue;
        }
        let handle = backend.init_port(port_cfg, &mempool)?;
        backend.start_port(&handle)?;
        ports.push(handle);
    }

    Ok(DpdkContext { mempool, ports })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::config::{DpdkConfig, PortConfig};
    use super::error::DpdkError;
    use super::init_dpdk;
    use super::mock::MockDpdkBackend;

    fn default_config() -> DpdkConfig {
        DpdkConfig {
            lcore_list: "0-3".to_string(),
            memory_mb: 2048,
            rx_queue_size: 1024,
            tx_queue_size: 1024,
            ports: vec![],
        }
    }

    fn wan_port() -> PortConfig {
        PortConfig {
            name: "wan0".to_string(),
            port_id: 0,
            mtu: 1500,
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            admin_up: true,
            rx_queues: 1,
            tx_queues: 1,
        }
    }

    fn lan_port() -> PortConfig {
        PortConfig {
            name: "lan0".to_string(),
            port_id: 1,
            mtu: 1500,
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            admin_up: true,
            rx_queues: 1,
            tx_queues: 1,
        }
    }

    #[test]
    fn two_port_init_succeeds() {
        let backend = MockDpdkBackend::new();
        let mut cfg = default_config();
        cfg.ports = vec![wan_port(), lan_port()];

        let ctx = init_dpdk(&backend, &cfg).expect("init should succeed");
        assert_eq!(ctx.ports.len(), 2);
        assert_eq!(ctx.ports[0].name, "wan0");
        assert_eq!(ctx.ports[1].name, "lan0");
    }

    #[test]
    fn admin_down_port_skipped() {
        let backend = MockDpdkBackend::new();
        let mut cfg = default_config();
        let mut down = lan_port();
        down.admin_up = false;
        cfg.ports = vec![wan_port(), down];

        let ctx = init_dpdk(&backend, &cfg).expect("init should succeed");
        assert_eq!(ctx.ports.len(), 1);
        assert_eq!(ctx.ports[0].name, "wan0");
    }

    #[test]
    fn eal_init_failure() {
        let backend = MockDpdkBackend::new();
        backend.fail_eal_init.store(true, Ordering::Relaxed);
        let cfg = default_config();

        let err = init_dpdk(&backend, &cfg).unwrap_err();
        assert!(matches!(err, DpdkError::EalInit { .. }));
    }

    #[test]
    fn mempool_create_failure() {
        let backend = MockDpdkBackend::new();
        backend.fail_mempool.store(true, Ordering::Relaxed);
        let cfg = default_config();

        let err = init_dpdk(&backend, &cfg).unwrap_err();
        assert!(matches!(err, DpdkError::MempoolCreate { .. }));
    }

    #[test]
    fn port_init_failure() {
        let backend = MockDpdkBackend::new();
        *backend.fail_port_init.lock().unwrap() = Some(1);
        let mut cfg = default_config();
        cfg.ports = vec![wan_port(), lan_port()];

        let err = init_dpdk(&backend, &cfg).unwrap_err();
        match &err {
            DpdkError::PortInit { port_id, name, .. } => {
                assert_eq!(*port_id, 1);
                assert_eq!(name, "lan0");
            }
            other => panic!("expected PortInit, got {other:?}"),
        }
    }

    #[test]
    fn port_start_failure() {
        let backend = MockDpdkBackend::new();
        *backend.fail_port_start.lock().unwrap() = Some(0);
        let mut cfg = default_config();
        cfg.ports = vec![wan_port()];

        let err = init_dpdk(&backend, &cfg).unwrap_err();
        match &err {
            DpdkError::PortStart { port_id, name, .. } => {
                assert_eq!(*port_id, 0);
                assert_eq!(name, "wan0");
            }
            other => panic!("expected PortStart, got {other:?}"),
        }
    }

    #[test]
    fn empty_ports_succeeds() {
        let backend = MockDpdkBackend::new();
        let cfg = default_config();

        let ctx = init_dpdk(&backend, &cfg).expect("init with no ports should succeed");
        assert!(ctx.ports.is_empty());
    }

    #[test]
    fn validate_memory_mb_zero() {
        let backend = MockDpdkBackend::new();
        let mut cfg = default_config();
        cfg.memory_mb = 0;

        let err = init_dpdk(&backend, &cfg).unwrap_err();
        assert!(matches!(err, DpdkError::Config(_)));
    }

    #[test]
    fn validate_lcore_list_empty() {
        let backend = MockDpdkBackend::new();
        let mut cfg = default_config();
        cfg.lcore_list = String::new();

        let err = init_dpdk(&backend, &cfg).unwrap_err();
        assert!(matches!(err, DpdkError::Config(_)));
    }

    #[test]
    fn validate_rx_queue_size_zero() {
        let backend = MockDpdkBackend::new();
        let mut cfg = default_config();
        cfg.rx_queue_size = 0;

        let err = init_dpdk(&backend, &cfg).unwrap_err();
        assert!(matches!(err, DpdkError::Config(_)));
    }

    #[test]
    fn validate_tx_queue_size_zero() {
        let backend = MockDpdkBackend::new();
        let mut cfg = default_config();
        cfg.tx_queue_size = 0;

        let err = init_dpdk(&backend, &cfg).unwrap_err();
        assert!(matches!(err, DpdkError::Config(_)));
    }
}
