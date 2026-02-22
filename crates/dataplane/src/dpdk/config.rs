use super::error::DpdkError;

/// DPDK startup configuration.
#[derive(Debug, Clone)]
pub struct DpdkConfig {
    /// EAL lcore list, e.g. "0-3".
    pub lcore_list: String,
    /// Hugepage memory in MiB.
    pub memory_mb: u32,
    /// Per-port RX descriptor ring size.
    pub rx_queue_size: u16,
    /// Per-port TX descriptor ring size.
    pub tx_queue_size: u16,
    /// Port configurations (only `admin_up = true` ports are initialised).
    pub ports: Vec<PortConfig>,
}

/// Per-port configuration.
#[derive(Debug, Clone)]
pub struct PortConfig {
    pub name: String,
    pub port_id: u16,
    pub mtu: u16,
    pub mac: [u8; 6],
    pub admin_up: bool,
    /// Number of RX queues (v0.1: always 1).
    pub rx_queues: u16,
    /// Number of TX queues (v0.1: always 1).
    pub tx_queues: u16,
}

impl DpdkConfig {
    /// Validate configuration before EAL init.
    pub fn validate(&self) -> Result<(), DpdkError> {
        if self.lcore_list.is_empty() {
            return Err(DpdkError::Config(
                "lcore_list must not be empty".to_string(),
            ));
        }
        if self.memory_mb == 0 {
            return Err(DpdkError::Config("memory_mb must be > 0".to_string()));
        }
        if self.rx_queue_size == 0 {
            return Err(DpdkError::Config("rx_queue_size must be > 0".to_string()));
        }
        if self.tx_queue_size == 0 {
            return Err(DpdkError::Config("tx_queue_size must be > 0".to_string()));
        }
        Ok(())
    }
}
