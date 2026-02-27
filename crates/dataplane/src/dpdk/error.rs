/// DPDK subsystem errors.
#[derive(Debug, thiserror::Error)]
pub enum DpdkError {
    #[error("EAL initialization failed: {reason}")]
    EalInit { reason: String },

    #[error("mempool creation failed: {reason}")]
    MempoolCreate { reason: String },

    #[error("port {port_id} ({name}) initialization failed: {reason}")]
    PortInit {
        port_id: u16,
        name: String,
        reason: String,
    },

    #[error("port {port_id} ({name}) start failed: {reason}")]
    PortStart {
        port_id: u16,
        name: String,
        reason: String,
    },

    #[error("configuration error: {0}")]
    Config(String),

    /// DPDK packet I/O is not available because the `dpdk` feature was not
    /// enabled at compile time. Rebuild with `--features dpdk` to use the
    /// DPDK backend.
    #[error("DPDK backend not available: {0}")]
    NotAvailable(String),
}
