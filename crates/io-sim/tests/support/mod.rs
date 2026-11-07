use ruster_core::{
    port_free_bitmap_words, DirectoryBucket, DirectoryNode, Nat44HostCounter, Nat44HostLink,
    Nat44HostStorage, Nat44TcpConfig, Nat44TcpHashKey, Nat44TcpHostSlot, Nat44TcpIndexStorage,
    Nat44TcpMappingSlot, Nat44TcpRuntime, Nat44TcpSessionHostSlot, Nat44TcpSessionSlot,
    Nat44UdpConfig, Nat44UdpHashKey, Nat44UdpHostSlot, Nat44UdpIndexStorage, Nat44UdpMappingSlot,
    Nat44UdpPeerSlot, Nat44UdpRuntime, PortOwnerSlot,
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
    let session_address_buckets =
        Box::leak(vec![DirectoryBucket::default(); session_bucket_count].into_boxed_slice());
    let session_address_nodes =
        Box::leak(vec![DirectoryNode::default(); sessions.len()].into_boxed_slice());
    let port_count = config.ports().count();
    let port_owners = Box::leak(vec![PortOwnerSlot::default(); port_count].into_boxed_slice());
    let port_free_bits =
        Box::leak(vec![0_u64; port_free_bitmap_words(port_count)].into_boxed_slice());
    // Per-host accounting storage (N3), so a test can set a per-host limit.
    let hosts = Nat44HostStorage::new(
        Box::leak(vec![Nat44HostLink::EMPTY; mappings.len()].into_boxed_slice()),
        Box::leak(vec![Nat44TcpHostSlot::EMPTY; mappings.len()].into_boxed_slice()),
        Box::leak(vec![DirectoryBucket::default(); mapping_bucket_count].into_boxed_slice()),
        Box::leak(vec![DirectoryNode::default(); mappings.len()].into_boxed_slice()),
    );
    // Per-host session accounting storage (N6), one link word per session.
    let session_hosts = Nat44HostStorage::new(
        Box::leak(vec![Nat44HostLink::EMPTY; sessions.len()].into_boxed_slice()),
        Box::leak(vec![Nat44TcpSessionHostSlot::EMPTY; sessions.len()].into_boxed_slice()),
        Box::leak(vec![DirectoryBucket::default(); session_bucket_count].into_boxed_slice()),
        Box::leak(vec![DirectoryNode::default(); sessions.len()].into_boxed_slice()),
    )
    .with_link_words(Box::leak(vec![0_u32; sessions.len()].into_boxed_slice()));
    Nat44TcpRuntime::new(
        config,
        mappings,
        sessions,
        Nat44TcpIndexStorage::new(
            mapping_buckets,
            mapping_nodes,
            session_buckets,
            session_nodes,
            session_address_buckets,
            session_address_nodes,
            port_owners,
            port_free_bits,
            hosts,
        )
        .with_session_hosts(session_hosts),
        Nat44TcpHashKey::new(0xc001_d00d_f00d_beef, 0x1234_5678_9abc_def0).unwrap(),
    )
    .unwrap()
}

#[allow(dead_code)]
pub struct UdpTestIndexes {
    mapping_buckets: Vec<DirectoryBucket>,
    mapping_nodes: Vec<DirectoryNode>,
    peer_buckets: Vec<DirectoryBucket>,
    peer_nodes: Vec<DirectoryNode>,
    port_owners: Vec<PortOwnerSlot>,
    port_free_bits: Vec<u64>,
    host_links: Vec<Nat44HostLink>,
    hosts: Vec<Nat44UdpHostSlot>,
    host_buckets: Vec<DirectoryBucket>,
    host_nodes: Vec<DirectoryNode>,
    host_words: Vec<u32>,
    host_counters: Vec<Nat44HostCounter>,
}

#[allow(dead_code)]
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
        let port_count = config.ports().count();
        Self {
            mapping_buckets: vec![DirectoryBucket::default(); mapping_bucket_count],
            mapping_nodes: vec![DirectoryNode::default(); mapping_capacity],
            peer_buckets: vec![DirectoryBucket::default(); peer_bucket_count],
            peer_nodes: vec![DirectoryNode::default(); peer_capacity],
            port_owners: vec![PortOwnerSlot::default(); port_count],
            port_free_bits: vec![0; port_free_bitmap_words(port_count)],
            host_links: vec![Nat44HostLink::EMPTY; mapping_capacity],
            hosts: vec![Nat44UdpHostSlot::EMPTY; mapping_capacity],
            host_buckets: vec![DirectoryBucket::default(); mapping_bucket_count],
            host_nodes: vec![DirectoryNode::default(); mapping_capacity],
            host_words: vec![0; mapping_capacity],
            host_counters: vec![Nat44HostCounter::EMPTY; mapping_capacity],
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
            &mut self.port_free_bits,
            Nat44HostStorage::new(
                &mut self.host_links,
                &mut self.hosts,
                &mut self.host_buckets,
                &mut self.host_nodes,
            )
            .with_link_words(&mut self.host_words)
            .with_host_counters(&mut self.host_counters),
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

/// An ICMP query NAT runtime (N5) on leaked storage sized like a UDP
/// runtime's, with the identifier pool as the port pool.
#[allow(dead_code)]
pub fn icmp_runtime(
    config: ruster_core::Nat44IcmpConfig,
    mapping_capacity: usize,
    peer_capacity: usize,
) -> ruster_core::Nat44IcmpRuntime<'static> {
    let bucket_count = |capacity: usize| {
        if capacity == 0 {
            0
        } else {
            capacity.next_power_of_two()
        }
    };
    let leak = |count: usize, value: DirectoryBucket| -> &'static mut [DirectoryBucket] {
        Box::leak(vec![value; count].into_boxed_slice())
    };
    let nodes = |count: usize| -> &'static mut [DirectoryNode] {
        Box::leak(vec![DirectoryNode::default(); count].into_boxed_slice())
    };
    let identifiers = config.identifiers().count();
    let storage = Nat44UdpIndexStorage::new(
        leak(bucket_count(mapping_capacity), DirectoryBucket::default()),
        nodes(mapping_capacity),
        leak(bucket_count(peer_capacity), DirectoryBucket::default()),
        nodes(peer_capacity),
        Box::leak(vec![PortOwnerSlot::default(); identifiers].into_boxed_slice()),
        Box::leak(vec![0_u64; port_free_bitmap_words(identifiers)].into_boxed_slice()),
        Nat44HostStorage::new(
            Box::leak(vec![Nat44HostLink::EMPTY; mapping_capacity].into_boxed_slice()),
            Box::leak(vec![Nat44UdpHostSlot::EMPTY; mapping_capacity].into_boxed_slice()),
            leak(bucket_count(mapping_capacity), DirectoryBucket::default()),
            nodes(mapping_capacity),
        )
        .with_link_words(Box::leak(vec![0_u32; mapping_capacity].into_boxed_slice()))
        .with_host_counters(Box::leak(
            vec![Nat44HostCounter::EMPTY; mapping_capacity].into_boxed_slice(),
        )),
    );
    ruster_core::Nat44IcmpRuntime::new(
        config,
        Box::leak(vec![Nat44UdpMappingSlot::default(); mapping_capacity].into_boxed_slice()),
        Box::leak(vec![Nat44UdpPeerSlot::default(); peer_capacity].into_boxed_slice()),
        storage,
        ruster_core::Nat44IcmpHashKey::new(0x5eed_1c3b_0bad_f00d, 0x0fed_cba9_8765_4321).unwrap(),
    )
    .unwrap()
}

/// Forwards `batch` the way the FE does, with ICMPv4 errors and no ARP resolution:
/// the clock is `now`, and a missing neighbor is a drop.
#[allow(dead_code)]
pub fn forward_with_errors<B, T>(
    batch: B,
    snapshot: &ruster_core::ForwardingSnapshot<'_>,
    errors: &mut ruster_core::Icmpv4ErrorRuntime<'_>,
    now: ruster_core::MonotonicMillis,
    trace: &mut T,
) -> ruster_core::BatchReport<B::Error>
where
    B: ruster_core::PacketBatch,
    T: ruster_core::TraceSink,
{
    let mut control = ruster_core::ControlQueue::new(4);
    ruster_core::forward_batch_with_control(
        batch,
        &snapshot.with_now(now),
        &mut control,
        ruster_core::Services {
            icmpv4_errors: Some(errors),
            ..ruster_core::Services::default()
        },
        trace,
    )
}

/// Forwards `batch` the way the FE does, with `services`, on the clock `now`.
#[allow(dead_code)]
pub fn forward<B, T>(
    batch: B,
    snapshot: &ruster_core::ForwardingSnapshot<'_>,
    now: ruster_core::MonotonicMillis,
    services: ruster_core::Services<'_, '_, '_>,
    trace: &mut T,
) -> ruster_core::BatchReport<B::Error>
where
    B: ruster_core::PacketBatch,
    T: ruster_core::TraceSink,
{
    let mut control = ruster_core::ControlQueue::new(4);
    ruster_core::forward_batch_with_control(
        batch,
        &snapshot.with_now(now),
        &mut control,
        services,
        trace,
    )
}
