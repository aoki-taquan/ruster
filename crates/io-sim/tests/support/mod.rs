use ruster_core::{
    DirectoryBucket, DirectoryNode, Nat44UdpConfig, Nat44UdpHashKey, Nat44UdpIndexStorage,
    Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpRuntime, PortOwnerSlot,
};

pub struct UdpTestIndexes {
    mapping_buckets: Vec<DirectoryBucket>,
    mapping_nodes: Vec<DirectoryNode>,
    peer_buckets: Vec<DirectoryBucket>,
    peer_nodes: Vec<DirectoryNode>,
    port_owners: Vec<PortOwnerSlot>,
}

impl UdpTestIndexes {
    pub fn new(config: Nat44UdpConfig, mapping_capacity: usize, peer_capacity: usize) -> Self {
        let mapping_bucket_count = if mapping_capacity == 0 {
            0
        } else {
            mapping_capacity.next_power_of_two()
        };
        let peer_bucket_count = if peer_capacity == 0 {
            0
        } else {
            peer_capacity.next_power_of_two()
        };
        let port_count = usize::from(config.last_port() - config.first_port()) + 1;
        Self {
            mapping_buckets: vec![DirectoryBucket::default(); mapping_bucket_count],
            mapping_nodes: vec![DirectoryNode::default(); mapping_capacity],
            peer_buckets: vec![DirectoryBucket::default(); peer_bucket_count],
            peer_nodes: vec![DirectoryNode::default(); peer_capacity],
            port_owners: vec![PortOwnerSlot::default(); port_count],
        }
    }

    pub fn runtime<'a>(
        &'a mut self,
        config: Nat44UdpConfig,
        mappings: &'a mut [Nat44UdpMappingSlot],
        peers: &'a mut [Nat44UdpPeerSlot],
    ) -> Nat44UdpRuntime<'a> {
        let storage = Nat44UdpIndexStorage::new(
            &mut self.mapping_buckets,
            &mut self.mapping_nodes,
            &mut self.peer_buckets,
            &mut self.peer_nodes,
            &mut self.port_owners,
        );
        Nat44UdpRuntime::new(
            config,
            mappings,
            peers,
            storage,
            Nat44UdpHashKey::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210).unwrap(),
        )
        .unwrap()
    }
}
