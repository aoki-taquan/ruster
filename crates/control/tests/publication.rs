use std::num::NonZeroU64;

use ruster_control::{
    FirewallPublicationInput, FullServiceStorageShape, Icmpv4ErrorStorageShape,
    Nat44TcpPublicationInput, Nat44TcpStoragePlan, Nat44UdpPublicationInput, Nat44UdpStoragePlan,
    PublicationCandidateError, PublicationPlan, ResolutionStorageShape, RuntimeService,
    StorageShapeError, SuccessorError, ValidatedCandidate,
};
use ruster_core::{
    DirectoryBucket, DirectoryNode, FirewallHashKey, FirewallPolicy, FirewallRuntime,
    FirewallStateSlot, Icmpv4ErrorPolicy, IfId, Interface, Ipv4Address, Ipv4Mtu, Ipv4OriginPolicy,
    LocalIpv4Binding, MacAddress, Nat44TcpHashKey, Nat44TcpIndexStorage, Nat44TcpMappingSlot,
    Nat44TcpPolicy, Nat44TcpRuntime, Nat44TcpSessionSlot, Nat44UdpHashKey, Nat44UdpIndexStorage,
    Nat44UdpMappingSlot, Nat44UdpPeerSlot, Nat44UdpPolicy, Nat44UdpRuntime, PortOwnerSlot,
    ResolutionPolicy, Route,
};

const LAN: IfId = IfId(1);
const WAN: IfId = IfId(2);
const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);

fn exact_shape() -> FullServiceStorageShape {
    FullServiceStorageShape::new(
        ResolutionStorageShape::new(1, 1, 1, 1, 1),
        Icmpv4ErrorStorageShape::new(1, 1),
        Nat44UdpStoragePlan::new(1, 1, 1, 1, 1, 1, 1),
        Nat44TcpStoragePlan::new(1, 1, 1, 1, 1, 1, 1),
        1,
    )
}

fn plan_with_shape(
    generation: u64,
    udp_key: (u64, u64),
    tcp_key: (u64, u64),
    firewall_key: (u64, u64),
    shape: FullServiceStorageShape,
) -> PublicationPlan {
    plan_with_controls(
        generation,
        udp_key,
        tcp_key,
        firewall_key,
        shape,
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        Icmpv4ErrorPolicy::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn plan_with_controls(
    generation: u64,
    udp_key: (u64, u64),
    tcp_key: (u64, u64),
    firewall_key: (u64, u64),
    shape: FullServiceStorageShape,
    resolution_policy: ResolutionPolicy,
    icmpv4_error_policy: Icmpv4ErrorPolicy,
) -> PublicationPlan {
    base_plan(generation, shape, resolution_policy, icmpv4_error_policy)
        .with_nat44_udp(udp_input(udp_key))
        .with_nat44_tcp(tcp_input(tcp_key))
        .with_firewall(firewall_input(firewall_key))
}

fn base_plan(
    generation: u64,
    shape: FullServiceStorageShape,
    resolution_policy: ResolutionPolicy,
    icmpv4_error_policy: Icmpv4ErrorPolicy,
) -> PublicationPlan {
    let routes = [
        Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
        Route::new(
            Ipv4Address::from_octets([0; 4]),
            0,
            WAN,
            Some(Ipv4Address::from_octets([203, 0, 113, 1])),
        )
        .unwrap(),
    ];
    let interfaces = [
        Interface {
            id: LAN,
            mac: MacAddress([2, 0, 0, 0, 0, 1]),
            mtu: Ipv4Mtu::ETHERNET,
        },
        Interface {
            id: WAN,
            mac: MacAddress([2, 0, 0, 0, 0, 2]),
            mtu: Ipv4Mtu::ETHERNET,
        },
    ];
    let bindings = [
        LocalIpv4Binding {
            interface: LAN,
            address: Ipv4Address::from_octets([10, 0, 0, 1]),
        },
        LocalIpv4Binding {
            interface: WAN,
            address: PUBLIC,
        },
    ];
    PublicationPlan::new(
        NonZeroU64::new(generation).unwrap(),
        shape,
        routes.into(),
        interfaces.into(),
        Vec::new().into_boxed_slice(),
        bindings.into(),
        Ipv4OriginPolicy::default(),
        resolution_policy,
        icmpv4_error_policy,
    )
}

fn udp_input(hash_key: (u64, u64)) -> Nat44UdpPublicationInput {
    Nat44UdpPublicationInput::new(
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44UdpPolicy::default(),
        Nat44UdpHashKey::new(hash_key.0, hash_key.1).unwrap(),
    )
}

fn tcp_input(hash_key: (u64, u64)) -> Nat44TcpPublicationInput {
    Nat44TcpPublicationInput::new(
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44TcpPolicy::default(),
        Nat44TcpHashKey::new(hash_key.0, hash_key.1).unwrap(),
    )
}

fn firewall_input(hash_key: (u64, u64)) -> FirewallPublicationInput {
    FirewallPublicationInput::new(
        Vec::new().into_boxed_slice(),
        FirewallPolicy::default(),
        FirewallHashKey::new(hash_key.0, hash_key.1).unwrap(),
    )
}

fn plan(
    generation: u64,
    udp_key: (u64, u64),
    tcp_key: (u64, u64),
    firewall_key: (u64, u64),
) -> PublicationPlan {
    plan_with_shape(generation, udp_key, tcp_key, firewall_key, exact_shape())
}

fn candidate(generation: u64, seed: u64) -> ValidatedCandidate {
    ValidatedCandidate::new(plan(
        generation,
        (seed, seed + 1),
        (seed + 2, seed + 3),
        (seed + 4, seed + 5),
    ))
    .unwrap()
}

#[test]
fn candidate_rejects_missing_services_shapes_and_realm_before_runtime() {
    let missing_udp = base_plan(
        1,
        exact_shape(),
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        Icmpv4ErrorPolicy::default(),
    );
    assert_eq!(
        ValidatedCandidate::new(missing_udp).err(),
        Some(PublicationCandidateError::MissingService(
            RuntimeService::Nat44Udp
        ))
    );
    let missing_tcp = base_plan(
        1,
        exact_shape(),
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        Icmpv4ErrorPolicy::default(),
    )
    .with_nat44_udp(udp_input((1, 2)));
    assert_eq!(
        ValidatedCandidate::new(missing_tcp).err(),
        Some(PublicationCandidateError::MissingService(
            RuntimeService::Nat44Tcp
        ))
    );
    let missing_firewall = base_plan(
        1,
        exact_shape(),
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        Icmpv4ErrorPolicy::default(),
    )
    .with_nat44_udp(udp_input((1, 2)))
    .with_nat44_tcp(tcp_input((3, 4)));
    assert_eq!(
        ValidatedCandidate::new(missing_firewall).err(),
        Some(PublicationCandidateError::MissingService(
            RuntimeService::Firewall
        ))
    );

    let invalid_shape = FullServiceStorageShape::new(
        ResolutionStorageShape::new(1, 1, 1, 1, 1),
        Icmpv4ErrorStorageShape::new(1, 1),
        Nat44UdpStoragePlan::new(1, 1, 1, 0, 1, 1, 1),
        Nat44TcpStoragePlan::new(1, 1, 1, 1, 1, 1, 1),
        1,
    );
    assert_eq!(
        ValidatedCandidate::new(plan_with_shape(1, (1, 2), (3, 4), (5, 6), invalid_shape)).err(),
        Some(PublicationCandidateError::StorageShape(
            StorageShapeError::UdpMappingNodeCount
        ))
    );

    let mismatched_tcp = Nat44TcpPublicationInput::new(
        WAN,
        LAN,
        Ipv4Address::from_octets([10, 0, 0, 1]),
        40_000,
        40_000,
        Nat44TcpPolicy::default(),
        Nat44TcpHashKey::new(9, 10).unwrap(),
    );
    let realm = plan(1, (1, 2), (3, 4), (5, 6)).with_nat44_tcp(mismatched_tcp);
    assert_eq!(
        ValidatedCandidate::new(realm).err(),
        Some(PublicationCandidateError::Nat44RealmMismatch)
    );
}

#[test]
fn every_nat_storage_shape_component_is_validated_exactly() {
    let resolution = ResolutionStorageShape::new(1, 1, 1, 1, 1);
    let icmp = Icmpv4ErrorStorageShape::new(1, 1);
    let udp = Nat44UdpStoragePlan::new(1, 1, 1, 1, 1, 1, 1);
    let tcp = Nat44TcpStoragePlan::new(1, 1, 1, 1, 1, 1, 1);
    let cases = [
        (
            FullServiceStorageShape::new(
                resolution,
                icmp,
                Nat44UdpStoragePlan::new(1, 1, 1, 0, 1, 1, 1),
                tcp,
                1,
            ),
            StorageShapeError::UdpMappingNodeCount,
        ),
        (
            FullServiceStorageShape::new(
                resolution,
                icmp,
                Nat44UdpStoragePlan::new(1, 1, 1, 1, 1, 0, 1),
                tcp,
                1,
            ),
            StorageShapeError::UdpPeerNodeCount,
        ),
        (
            FullServiceStorageShape::new(
                resolution,
                icmp,
                Nat44UdpStoragePlan::new(1, 1, 0, 1, 1, 1, 1),
                tcp,
                1,
            ),
            StorageShapeError::UdpMappingDirectory,
        ),
        (
            FullServiceStorageShape::new(
                resolution,
                icmp,
                Nat44UdpStoragePlan::new(1, 1, 1, 1, 0, 1, 1),
                tcp,
                1,
            ),
            StorageShapeError::UdpPeerDirectory,
        ),
        (
            FullServiceStorageShape::new(
                resolution,
                icmp,
                Nat44UdpStoragePlan::new(1, 1, 1, 1, 1, 1, 2),
                tcp,
                1,
            ),
            StorageShapeError::UdpPortOwnerCount,
        ),
        (
            FullServiceStorageShape::new(
                resolution,
                icmp,
                udp,
                Nat44TcpStoragePlan::new(1, 1, 1, 0, 1, 1, 1),
                1,
            ),
            StorageShapeError::TcpMappingNodeCount,
        ),
        (
            FullServiceStorageShape::new(
                resolution,
                icmp,
                udp,
                Nat44TcpStoragePlan::new(1, 1, 1, 1, 1, 0, 1),
                1,
            ),
            StorageShapeError::TcpSessionNodeCount,
        ),
        (
            FullServiceStorageShape::new(
                resolution,
                icmp,
                udp,
                Nat44TcpStoragePlan::new(1, 1, 0, 1, 1, 1, 1),
                1,
            ),
            StorageShapeError::TcpMappingDirectory,
        ),
        (
            FullServiceStorageShape::new(
                resolution,
                icmp,
                udp,
                Nat44TcpStoragePlan::new(1, 1, 1, 1, 0, 1, 1),
                1,
            ),
            StorageShapeError::TcpSessionDirectory,
        ),
        (
            FullServiceStorageShape::new(
                resolution,
                icmp,
                udp,
                Nat44TcpStoragePlan::new(1, 1, 1, 1, 1, 1, 2),
                1,
            ),
            StorageShapeError::TcpPortOwnerCount,
        ),
    ];
    for (shape, expected) in cases {
        assert_eq!(
            ValidatedCandidate::new(plan_with_shape(1, (1, 2), (3, 4), (5, 6), shape,)).err(),
            Some(PublicationCandidateError::StorageShape(expected))
        );
    }
}

#[test]
fn independently_owned_candidates_have_exact_distinct_cross_bindings() {
    let first = candidate(1, 10);
    let second = candidate(2, 100);
    let first_authority = first.authority();
    let second_authority = second.authority();

    assert_ne!(
        first_authority.nat44_udp_config(),
        second_authority.nat44_udp_config()
    );
    assert_ne!(
        first_authority.nat44_tcp_config(),
        second_authority.nat44_tcp_config()
    );
    assert_ne!(
        first_authority.firewall_config(),
        second_authority.firewall_config()
    );
}

#[test]
fn runtimes_reject_every_cross_candidate_authority_binding() {
    let first = candidate(1, 10);
    let second = candidate(2, 100);

    let mut udp_mappings = [Nat44UdpMappingSlot::default(); 1];
    let mut udp_peers = [Nat44UdpPeerSlot::default(); 1];
    let mut udp_mapping_buckets = [DirectoryBucket::default(); 1];
    let mut udp_mapping_nodes = [DirectoryNode::default(); 1];
    let mut udp_peer_buckets = [DirectoryBucket::default(); 1];
    let mut udp_peer_nodes = [DirectoryNode::default(); 1];
    let mut udp_port_owners = [PortOwnerSlot::default(); 1];
    let udp_indexes = Nat44UdpIndexStorage::new(
        &mut udp_mapping_buckets,
        &mut udp_mapping_nodes,
        &mut udp_peer_buckets,
        &mut udp_peer_nodes,
        &mut udp_port_owners,
    );
    let mut tcp_mappings = [Nat44TcpMappingSlot::default(); 1];
    let mut tcp_sessions = [Nat44TcpSessionSlot::default(); 1];
    let mut tcp_mapping_buckets = [DirectoryBucket::default(); 1];
    let mut tcp_mapping_nodes = [DirectoryNode::default(); 1];
    let mut tcp_session_buckets = [DirectoryBucket::default(); 1];
    let mut tcp_session_nodes = [DirectoryNode::default(); 1];
    let mut tcp_port_owners = [PortOwnerSlot::default(); 1];
    let tcp_indexes = Nat44TcpIndexStorage::new(
        &mut tcp_mapping_buckets,
        &mut tcp_mapping_nodes,
        &mut tcp_session_buckets,
        &mut tcp_session_nodes,
        &mut tcp_port_owners,
    );
    let mut firewall_states = [FirewallStateSlot::default(); 1];
    let (udp, tcp, firewall) = {
        let first_authority = first.authority();
        let udp = Nat44UdpRuntime::new(
            first_authority.nat44_udp_config(),
            &mut udp_mappings,
            &mut udp_peers,
            udp_indexes,
            first_authority.nat44_udp_hash_key(),
        )
        .unwrap();
        let tcp = Nat44TcpRuntime::new(
            first_authority.nat44_tcp_config(),
            &mut tcp_mappings,
            &mut tcp_sessions,
            tcp_indexes,
            first_authority.nat44_tcp_hash_key(),
        )
        .unwrap();
        let firewall =
            FirewallRuntime::new(first_authority.firewall_config(), &mut firewall_states);
        (udp, tcp, firewall)
    };

    let second_authority = second.authority();
    assert!(!udp.publication_binding_matches(
        second_authority.nat44_udp_config(),
        second_authority.nat44_udp_hash_key(),
    ));
    assert!(!tcp.publication_binding_matches(
        second_authority.nat44_tcp_config(),
        second_authority.nat44_tcp_hash_key(),
    ));
    assert!(!firewall.config_matches(&second_authority.firewall_config()));
}

#[test]
fn moving_composite_candidate_preserves_every_owned_binding() {
    let owner = candidate(1, 10);
    let mut firewall_states = [FirewallStateSlot::default(); 1];
    let (udp, tcp, firewall) = {
        let before = owner.authority();
        (
            before.nat44_udp_config(),
            before.nat44_tcp_config(),
            FirewallRuntime::new(before.firewall_config(), &mut firewall_states),
        )
    };

    let moved = owner;
    let after = moved.authority();
    assert_eq!(after.nat44_udp_config(), udp);
    assert_eq!(after.nat44_tcp_config(), tcp);
    assert!(firewall.config_matches(&after.firewall_config()));
}

#[test]
fn successor_checks_generation_keys_shape_and_fixed_policies_without_apply() {
    let active = candidate(1, 10);
    assert_eq!(
        active.validate_successor(&candidate(1, 100)),
        Err(SuccessorError::GenerationNotIncreasing)
    );
    assert_eq!(
        candidate(2, 200).validate_successor(&candidate(1, 300)),
        Err(SuccessorError::GenerationNotIncreasing)
    );
    let udp_reuse = ValidatedCandidate::new(plan(2, (10, 11), (102, 103), (104, 105))).unwrap();
    assert_eq!(
        active.validate_successor(&udp_reuse),
        Err(SuccessorError::Nat44UdpHashKeyReused)
    );
    let tcp_reuse = ValidatedCandidate::new(plan(2, (100, 101), (12, 13), (104, 105))).unwrap();
    assert_eq!(
        active.validate_successor(&tcp_reuse),
        Err(SuccessorError::Nat44TcpHashKeyReused)
    );
    let firewall_reuse =
        ValidatedCandidate::new(plan(2, (100, 101), (102, 103), (14, 15))).unwrap();
    assert_eq!(
        active.validate_successor(&firewall_reuse),
        Err(SuccessorError::FirewallHashKeyReused)
    );
    let changed_shape = FullServiceStorageShape::new(
        exact_shape().resolution(),
        exact_shape().icmpv4_errors(),
        exact_shape().nat44_udp(),
        exact_shape().nat44_tcp(),
        2,
    );
    let shape_candidate = ValidatedCandidate::new(plan_with_shape(
        2,
        (100, 101),
        (102, 103),
        (104, 105),
        changed_shape,
    ))
    .unwrap();
    assert_eq!(
        active.validate_successor(&shape_candidate),
        Err(SuccessorError::StorageShapeChanged)
    );
    let resolution_candidate = ValidatedCandidate::new(plan_with_controls(
        2,
        (100, 101),
        (102, 103),
        (104, 105),
        exact_shape(),
        ResolutionPolicy::new(2_000, 4_000).unwrap(),
        Icmpv4ErrorPolicy::default(),
    ))
    .unwrap();
    assert_eq!(
        active.validate_successor(&resolution_candidate),
        Err(SuccessorError::ResolutionPolicyChanged)
    );
    let icmp_candidate = ValidatedCandidate::new(plan_with_controls(
        2,
        (100, 101),
        (102, 103),
        (104, 105),
        exact_shape(),
        ResolutionPolicy::new(1_000, 2_000).unwrap(),
        Icmpv4ErrorPolicy::new(200, 60_000).unwrap(),
    ))
    .unwrap();
    assert_eq!(
        active.validate_successor(&icmp_candidate),
        Err(SuccessorError::Icmpv4ErrorPolicyChanged)
    );
    assert_eq!(active.validate_successor(&candidate(2, 100)), Ok(()));

    let exhausted = candidate(u64::MAX, 200);
    assert_eq!(
        exhausted.validate_successor(&candidate(u64::MAX - 1, 300)),
        Err(SuccessorError::GenerationExhausted)
    );
}

#[test]
fn typed_errors_and_source_never_format_nested_authority_or_secrets() {
    let first = candidate(1, u64::MAX - 20);
    let same_generation = candidate(1, u64::MAX - 40);
    assert_eq!(
        format!(
            "{:?}",
            first.validate_successor(&same_generation).unwrap_err()
        ),
        "GenerationNotIncreasing"
    );

    let source = include_str!("../src/publication.rs");
    let exports = include_str!("../src/lib.rs");
    for forbidden in [
        "impl std::fmt::Debug for PublicationPlan",
        "impl std::fmt::Debug for ValidatedCandidate",
        "impl std::fmt::Debug for ValidatedAuthority",
        "Box::leak",
        "Box::into_raw",
        "unsafe {",
        "Mutex<",
        "dyn PacketIo",
        "pub struct ActivePublication",
        "pub struct FullServiceRuntimeSet",
        "ruster-runtime",
    ] {
        assert!(!source.contains(forbidden), "forbidden source: {forbidden}");
    }
    assert!(!exports.contains("    ActivePublication,"));
    assert!(!exports.contains("    FullServiceRuntimeSet,"));
    let manifest = include_str!("../Cargo.toml");
    assert!(!manifest.contains("ruster-runtime"));

    let candidate_start = source.find("pub struct ValidatedCandidate {").unwrap();
    let candidate_end = source[candidate_start..]
        .find("impl ValidatedCandidate {")
        .map(|offset| candidate_start + offset)
        .unwrap();
    let candidate_fields = &source[candidate_start..candidate_end];
    let udp_config = candidate_fields.find("nat44_udp: Nat44UdpConfig").unwrap();
    let tcp_config = candidate_fields.find("nat44_tcp: Nat44TcpConfig").unwrap();
    let firewall_owner = candidate_fields
        .find("firewall: ValidatedFirewallOwner")
        .unwrap();
    let forwarding_owner = candidate_fields
        .find("forwarding: ValidatedForwardingOwner")
        .unwrap();
    assert!(udp_config < firewall_owner);
    assert!(tcp_config < firewall_owner);
    assert!(firewall_owner < forwarding_owner);
}
