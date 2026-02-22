/// Opaque handle to a DPDK mempool.
#[derive(Debug)]
pub struct MempoolHandle {
    pub name: String,
    pub capacity: u32,
}

/// Opaque handle to an initialised DPDK port.
#[derive(Debug)]
pub struct PortHandle {
    pub port_id: u16,
    pub name: String,
}

/// State retained after successful DPDK initialisation.
#[derive(Debug)]
pub struct DpdkContext {
    pub mempool: MempoolHandle,
    pub ports: Vec<PortHandle>,
}
