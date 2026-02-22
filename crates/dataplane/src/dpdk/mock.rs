use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use super::backend::DpdkBackend;
use super::config::{DpdkConfig, PortConfig};
use super::context::{MempoolHandle, PortHandle};
use super::error::DpdkError;

/// Test-only DPDK backend that never touches real hardware.
#[derive(Debug, Default)]
pub struct MockDpdkBackend {
    pub fail_eal_init: AtomicBool,
    pub fail_mempool: AtomicBool,
    /// If `Some(port_id)`, `init_port` will fail for that port.
    pub fail_port_init: Mutex<Option<u16>>,
    /// If `Some(port_id)`, `start_port` will fail for that port.
    pub fail_port_start: Mutex<Option<u16>>,
}

impl MockDpdkBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl DpdkBackend for MockDpdkBackend {
    fn eal_init(&self, _config: &DpdkConfig) -> Result<(), DpdkError> {
        if self.fail_eal_init.load(Ordering::Relaxed) {
            return Err(DpdkError::EalInit {
                reason: "mock EAL init failure".to_string(),
            });
        }
        Ok(())
    }

    fn create_mempool(&self, config: &DpdkConfig) -> Result<MempoolHandle, DpdkError> {
        if self.fail_mempool.load(Ordering::Relaxed) {
            return Err(DpdkError::MempoolCreate {
                reason: "mock mempool creation failure".to_string(),
            });
        }
        Ok(MempoolHandle {
            name: "mock_mempool".to_string(),
            capacity: config.memory_mb,
        })
    }

    fn init_port(
        &self,
        port: &PortConfig,
        _mempool: &MempoolHandle,
    ) -> Result<PortHandle, DpdkError> {
        let fail_id = self.fail_port_init.lock().unwrap();
        if *fail_id == Some(port.port_id) {
            return Err(DpdkError::PortInit {
                port_id: port.port_id,
                name: port.name.clone(),
                reason: "mock port init failure".to_string(),
            });
        }
        Ok(PortHandle {
            port_id: port.port_id,
            name: port.name.clone(),
        })
    }

    fn start_port(&self, handle: &PortHandle) -> Result<(), DpdkError> {
        let fail_id = self.fail_port_start.lock().unwrap();
        if *fail_id == Some(handle.port_id) {
            return Err(DpdkError::PortStart {
                port_id: handle.port_id,
                name: handle.name.clone(),
                reason: "mock port start failure".to_string(),
            });
        }
        Ok(())
    }
}
