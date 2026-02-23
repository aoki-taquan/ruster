pub mod arp;
pub mod conntrack;
pub mod dpdk;
pub mod l2;
pub mod nat;
pub mod packet;
pub mod routing;

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
