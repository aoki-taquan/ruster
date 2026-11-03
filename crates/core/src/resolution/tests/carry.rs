//! RELOAD-CARRY for resolution: a carrying commit flushes pending states,
//! queued ARP actions, and failure holds (old snapshot authority) like the
//! flushing commit, keeps the index key, and keeps exactly the learned
//! neighbors whose interface binding is unchanged, that no new static
//! neighbor shadows, and that are on-link when the successor enables the
//! ARP-031 hardening.

use super::*;

const LAN: IfId = IfId(1);
const LAN_IP: Ipv4Address = Ipv4Address::from_octets([10, 0, 0, 1]);

fn lan(last: u8) -> Ipv4Address {
    Ipv4Address::from_octets([10, 0, 0, last])
}

/// Snapshot tables: WAN 192.0.2.0/24 bound to `wan_ip`, LAN 10.0.0.0/24
/// bound to 10.0.0.1, and the given static neighbors.
struct Tables {
    routes: [Route; 2],
    interfaces: [Interface; 2],
    bindings: [LocalIpv4Binding; 2],
    neighbors: Vec<Neighbor>,
}

impl Tables {
    fn new(wan_ip: Ipv4Address, neighbors: Vec<Neighbor>) -> Self {
        Self {
            routes: [
                Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 24, WAN, None).unwrap(),
                Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap(),
            ],
            interfaces: [
                Interface {
                    id: WAN,
                    mac: SOURCE_MAC,
                    mtu: 1500,
                },
                Interface {
                    id: LAN,
                    mac: MacAddress([2, 0, 0, 0, 0, 2]),
                    mtu: 1500,
                },
            ],
            bindings: [
                LocalIpv4Binding {
                    interface: WAN,
                    address: wan_ip,
                },
                LocalIpv4Binding {
                    interface: LAN,
                    address: LAN_IP,
                },
            ],
            neighbors,
        }
    }

    fn snapshot(&self) -> ForwardingSnapshot<'_> {
        ForwardingSnapshot::new(
            &self.routes,
            &self.interfaces,
            &self.neighbors,
            &self.bindings,
        )
        .unwrap()
    }
}

fn learn(runtime: &mut ResolutionRuntime<'_>, interface: IfId, address: Ipv4Address, mac: u8) {
    assert_eq!(
        runtime.merge_dynamic(
            interface,
            address,
            MacAddress([2, 0, 0, 0, 1, mac]),
            true,
            false,
            MonotonicMillis(10),
        ),
        ControlDisposition::Inserted
    );
}

fn hit(runtime: &mut ResolutionRuntime<'_>, interface: IfId, address: Ipv4Address) -> bool {
    matches!(
        runtime.lookup_dynamic(interface, address, MonotonicMillis(20)),
        DynamicLookup::Hit(_)
    )
}

/// A runtime with three learned neighbors (two on WAN, one on LAN) and a
/// pending resolution; `run` gets it with its storage.
fn with_learned(run: impl FnOnce(&mut ResolutionRuntime<'_>)) {
    let policy = ResolutionPolicy::new(1_000, 1_000).unwrap();
    let mut states = [ResolutionStateSlot::EMPTY; 4];
    let mut actions = [ResolutionActionSlot::EMPTY; 4];
    let mut dynamic = [DynamicNeighborSlot::EMPTY; 8];
    let mut holds = [ResolutionFailureHoldSlot::EMPTY; 2];
    let mut runtime = ResolutionRuntime::with_dynamic_neighbors_and_failure_holds(
        policy,
        &mut states,
        &mut actions,
        &mut dynamic,
        &mut holds,
    );
    learn(&mut runtime, WAN, target(7), 7);
    learn(&mut runtime, WAN, target(8), 8);
    learn(&mut runtime, LAN, lan(9), 9);
    assert_eq!(
        runtime.schedule(action(2), MonotonicMillis(10), false),
        ResolutionResult::Queued
    );
    run(&mut runtime);
}

#[test]
fn unchanged_bindings_carry_every_learned_neighbor_and_flush_pending_work() {
    with_learned(|runtime| {
        let tables = Tables::new(SOURCE_IP, Vec::new());
        let snapshot = tables.snapshot();
        let key = runtime.hash_key;
        let permit = runtime.preflight_publication().unwrap();
        let preview = permit.preview_carrying(&snapshot, &snapshot);
        let report = permit.commit_carrying(&snapshot, &snapshot);
        assert_eq!(report, preview);
        assert_eq!(
            report,
            ResolutionPublicationReport {
                states_flushed: 1,
                actions_flushed: 1,
                dynamic_neighbors_flushed: 0,
                failure_holds_flushed: 0,
                dynamic_neighbors_carried: 3,
                outcome: crate::StateCarryOutcome::Carried,
            }
        );
        assert_eq!(runtime.hash_key, key, "the index key is kept");
        assert_eq!(runtime.pending_actions(), 0);
        assert_eq!(runtime.pending_states(), 0);
        assert_eq!(runtime.dynamic_neighbor_count(), 3);
        assert!(hit(runtime, WAN, target(7)));
        assert!(hit(runtime, WAN, target(8)));
        assert!(hit(runtime, LAN, lan(9)));
        assert!(runtime.validate_publication_invariants().is_ok());
        // Pending work starts over from the next packet.
        assert_eq!(
            runtime.schedule(action(2), MonotonicMillis(30), false),
            ResolutionResult::Queued
        );
    });
}

#[test]
fn a_changed_binding_or_a_new_static_neighbor_drops_exactly_those_entries() {
    with_learned(|runtime| {
        let current_tables = Tables::new(SOURCE_IP, Vec::new());
        // WAN is renumbered; LAN gets a static neighbor for 10.0.0.9.
        let next_tables = Tables::new(
            target(3),
            vec![Neighbor {
                interface: LAN,
                target: lan(9),
                mac: MacAddress([4; 6]),
            }],
        );
        let (current, next) = (current_tables.snapshot(), next_tables.snapshot());
        let permit = runtime.preflight_publication().unwrap();
        let preview = permit.preview_carrying(&current, &next);
        let report = permit.commit_carrying(&current, &next);
        assert_eq!(report, preview);
        assert_eq!(
            (
                report.dynamic_neighbors_flushed,
                report.dynamic_neighbors_carried
            ),
            (3, 0)
        );
        assert_eq!(runtime.dynamic_neighbor_count(), 0);
        assert!(runtime.validate_publication_invariants().is_ok());
    });
    with_learned(|runtime| {
        // Only the LAN binding changes: WAN entries stay.
        let current_tables = Tables::new(SOURCE_IP, Vec::new());
        let mut next_tables = Tables::new(SOURCE_IP, Vec::new());
        next_tables.bindings[1].address = lan(2);
        let (current, next) = (current_tables.snapshot(), next_tables.snapshot());
        let report = runtime
            .preflight_publication()
            .unwrap()
            .commit_carrying(&current, &next);
        assert_eq!(
            (
                report.dynamic_neighbors_flushed,
                report.dynamic_neighbors_carried
            ),
            (1, 2)
        );
        assert!(hit(runtime, WAN, target(7)));
        assert!(hit(runtime, WAN, target(8)));
        assert!(!hit(runtime, LAN, lan(9)));
        assert!(runtime.validate_publication_invariants().is_ok());
    });
}

#[test]
fn switching_on_the_on_link_hardening_drops_off_link_entries_only() {
    with_learned(|runtime| {
        // 192.0.2.8 learned under RFC 826 is off-link once WAN's direct
        // route shrinks to 192.0.2.0/29 and ARP-031 is on.
        let current_tables = Tables::new(SOURCE_IP, Vec::new());
        let mut next_tables = Tables::new(SOURCE_IP, Vec::new());
        next_tables.routes[0] =
            Route::new(Ipv4Address::from_octets([192, 0, 2, 0]), 29, WAN, None).unwrap();
        let current = current_tables.snapshot();
        let relaxed = next_tables.snapshot();
        let hardened = next_tables
            .snapshot()
            .with_arp_policy(crate::ArpPolicy::RFC826.with_require_on_link_sender(true));
        // Without the hardening the shrunk route alone drops nothing.
        let permit = runtime.preflight_publication().unwrap();
        assert_eq!(
            permit
                .preview_carrying(&current, &relaxed)
                .dynamic_neighbors_flushed,
            0
        );
        let report = permit.commit_carrying(&current, &hardened);
        assert_eq!(
            (
                report.dynamic_neighbors_flushed,
                report.dynamic_neighbors_carried
            ),
            (1, 2)
        );
        assert!(hit(runtime, WAN, target(7)));
        assert!(!hit(runtime, WAN, target(8)));
        assert!(hit(runtime, LAN, lan(9)));
        assert!(runtime.validate_publication_invariants().is_ok());
    });
}

#[test]
fn a_dropped_permit_carries_nothing_away() {
    with_learned(|runtime| {
        let before = runtime_image(runtime);
        let tables = Tables::new(target(3), Vec::new());
        let snapshot = tables.snapshot();
        let permit = runtime.preflight_publication().unwrap();
        assert_eq!(
            permit
                .preview_carrying(&snapshot, &snapshot)
                .dynamic_neighbors_carried,
            3
        );
        drop(permit);
        assert!(runtime_image(runtime) == before);
    });
}
