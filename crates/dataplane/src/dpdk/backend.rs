use super::config::{DpdkConfig, PortConfig};
use super::context::{MempoolHandle, PortHandle};
use super::error::DpdkError;

/// Abstraction over real DPDK FFI so the init flow can be tested with mocks.
pub trait DpdkBackend: Send + Sync {
    /// Initialise the DPDK EAL.
    fn eal_init(&self, config: &DpdkConfig) -> Result<(), DpdkError>;

    /// Create the packet mempool.
    fn create_mempool(&self, config: &DpdkConfig) -> Result<MempoolHandle, DpdkError>;

    /// Configure and set up queues for a single port.
    fn init_port(
        &self,
        port: &PortConfig,
        mempool: &MempoolHandle,
    ) -> Result<PortHandle, DpdkError>;

    /// Start an already-configured port.
    fn start_port(&self, handle: &PortHandle) -> Result<(), DpdkError>;
}
