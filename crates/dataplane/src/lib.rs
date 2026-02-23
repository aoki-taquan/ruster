pub mod dpdk;
pub mod l2;
pub mod packet;

#[derive(Debug, Default)]
pub struct Dataplane;

impl Dataplane {
    pub fn new() -> Self {
        Self
    }

    pub fn start(&self) {
        // Placeholder: DPDK/EAL startup will be implemented in v0.1 issues.
    }
}
