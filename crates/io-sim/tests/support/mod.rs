use ruster_core::{
    DirectoryBucket, DirectoryNode, Nat44TcpConfig, Nat44TcpHashKey, Nat44TcpIndexStorage,
    Nat44TcpMappingSlot, Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44UdpConfig, Nat44UdpHashKey,
    Nat44UdpIndexStorage, Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpRuntime, PortOwnerSlot,
};

#[allow(dead_code)]
pub fn tcp_runtime<'a>(
    config: Nat44TcpConfig,
    mappings: &'a mut [Nat44TcpMappingSlot],
    sessions: &'a mut [Nat44TcpSessionSlot],
) -> Nat44TcpRuntime<'a> {
    let mapping_bucket_count = if mappings.is_empty() {
        0
    } else {
        mappings.len().next_power_of_two()
    };
    let session_bucket_count = if sessions.is_empty() {
        0
    } else {
        sessions.len().next_power_of_two()
    };
    let mapping_buckets =
        Box::leak(vec![DirectoryBucket::default(); mapping_bucket_count].into_boxed_slice());
    let mapping_nodes =
        Box::leak(vec![DirectoryNode::default(); mappings.len()].into_boxed_slice());
    let session_buckets =
        Box::leak(vec![DirectoryBucket::default(); session_bucket_count].into_boxed_slice());
    let session_nodes =
        Box::leak(vec![DirectoryNode::default(); sessions.len()].into_boxed_slice());
    let port_count = usize::from(config.last_port() - config.first_port()) + 1;
    let port_owners = Box::leak(vec![PortOwnerSlot::default(); port_count].into_boxed_slice());
    Nat44TcpRuntime::new(
        config,
        mappings,
        sessions,
        Nat44TcpIndexStorage::new(
            mapping_buckets,
            mapping_nodes,
            session_buckets,
            session_nodes,
            port_owners,
        ),
        Nat44TcpHashKey::new(0xc001_d00d_f00d_beef, 0x1234_5678_9abc_def0).unwrap(),
    )
    .unwrap()
}

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
