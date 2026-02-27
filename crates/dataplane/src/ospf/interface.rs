//! OSPF interface state and timer management.
//!
//! Each OSPF-enabled interface maintains its own state, neighbor list,
//! and periodic Hello timer.
//!
//! RFC-REF: RFC 2328 Section 9
//! "The OSPF interface connects the router to the attached network."

use super::config::OspfInterfaceConfig;
use super::neighbor::{Neighbor, NeighborEvent, NeighborState};
use super::packet::HelloPacket;

use std::fmt;

// ── Interface state ─────────────────────────────────────────────────

/// OSPF interface states.
///
/// RFC-REF: RFC 2328 Section 9.1
/// "An OSPF interface has several possible states."
///
/// RFC-DEVIATION:
/// reason: We only implement Down, Waiting, PointToPoint, and
///         DROther/Backup/DR states are simplified.  DR election
///         is not performed.
/// impact: Broadcast network DR election does not work.
/// issue: #157
/// plan: Add DR election in a future version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceState {
    /// Interface is not operational.
    Down,
    /// Interface is up, sending Hellos, waiting for DR election.
    ///
    /// RFC-DEVIATION:
    /// reason: We skip DR election and treat all interfaces as
    ///         point-to-point-like.
    /// impact: Broadcast networks will not have DR/BDR.
    /// issue: #157
    /// plan: Add DR election in a future version.
    Waiting,
    /// Interface is operating as a point-to-point link.
    PointToPoint,
}

impl fmt::Display for InterfaceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Down => write!(f, "Down"),
            Self::Waiting => write!(f, "Waiting"),
            Self::PointToPoint => write!(f, "PointToPoint"),
        }
    }
}

// ── OSPF interface ──────────────────────────────────────────────────

/// OSPF interface data structure.
///
/// RFC-REF: RFC 2328 Section 9
/// "The OSPF interface data structure contains information about
/// the interface as well as about the router's neighbors on the
/// network."
#[derive(Debug, Clone)]
pub struct OspfInterface {
    /// Logical interface name (e.g. "eth0").
    pub name: String,
    /// Interface state.
    pub state: InterfaceState,
    /// Interface IP address.
    pub ip_addr: [u8; 4],
    /// Network mask.
    pub network_mask: [u8; 4],
    /// Area ID this interface belongs to.
    pub area_id: [u8; 4],
    /// Seconds between Hello transmissions.
    ///
    /// RFC-REF: RFC 2328 Section 9.5
    pub hello_interval: u16,
    /// Seconds before a neighbor is declared dead.
    ///
    /// RFC-REF: RFC 2328 Section 9.6
    pub dead_interval: u16,
    /// Neighbors discovered on this interface.
    pub neighbors: Vec<Neighbor>,
    /// Timestamp of the last Hello sent (epoch seconds).
    pub last_hello_sent: u64,
}

impl OspfInterface {
    /// Create a new OSPF interface from configuration.
    pub fn new(
        config: &OspfInterfaceConfig,
        ip_addr: [u8; 4],
        network_mask: [u8; 4],
        area_id: [u8; 4],
    ) -> Self {
        Self {
            name: config.name.clone(),
            state: InterfaceState::Down,
            ip_addr,
            network_mask,
            area_id,
            hello_interval: config.hello_interval,
            dead_interval: config.dead_interval,
            neighbors: Vec::new(),
            last_hello_sent: 0,
        }
    }

    /// Bring the interface up.
    ///
    /// RFC-REF: RFC 2328 Section 9.2
    /// "Event: InterfaceUp"
    pub fn up(&mut self) {
        self.state = InterfaceState::PointToPoint;
    }

    /// Bring the interface down.
    ///
    /// RFC-REF: RFC 2328 Section 9.2
    /// "Event: InterfaceDown"
    pub fn down(&mut self) {
        // Kill all neighbors.
        for nbr in &mut self.neighbors {
            nbr.handle_event(NeighborEvent::KillNbr);
        }
        self.neighbors.clear();
        self.state = InterfaceState::Down;
    }

    /// Check if the interface is operationally up.
    pub fn is_up(&self) -> bool {
        self.state != InterfaceState::Down
    }

    /// Check if it is time to send a Hello.
    pub fn should_send_hello(&self, now_secs: u64) -> bool {
        self.is_up()
            && (now_secs.saturating_sub(self.last_hello_sent) >= self.hello_interval as u64)
    }

    /// Process a received Hello packet.
    ///
    /// RFC-REF: RFC 2328 Section 10.5
    /// "When a Hello packet is received from a neighbor, a number of
    /// checks must be made."
    ///
    /// Returns the neighbor state after processing.
    pub fn process_hello(
        &mut self,
        hello: &HelloPacket,
        source_ip: [u8; 4],
        our_router_id: [u8; 4],
        now_secs: u64,
    ) -> NeighborState {
        let neighbor_router_id = hello.header.router_id;

        // RFC-REF: RFC 2328 Section 10.5
        // "Verify that HelloInterval and RouterDeadInterval match."
        if hello.hello_interval != self.hello_interval
            || hello.router_dead_interval != self.dead_interval as u32
        {
            return NeighborState::Down;
        }

        // Find or create the neighbor.
        let nbr_idx = self.find_or_create_neighbor(neighbor_router_id, source_ip);
        let nbr = &mut self.neighbors[nbr_idx];

        // Update neighbor fields from the Hello.
        nbr.priority = hello.router_priority;
        nbr.designated_router = hello.designated_router;
        nbr.backup_designated_router = hello.backup_designated_router;
        nbr.last_hello = now_secs;

        // If neighbor is in Down state, transition to Init.
        if nbr.state == NeighborState::Down {
            nbr.handle_event(NeighborEvent::HelloReceived);
        } else {
            // Refresh the Hello timer by recording the event.
            nbr.handle_event(NeighborEvent::HelloReceived);
        }

        // Check for bidirectional communication.
        // RFC-REF: RFC 2328 Section 10.5
        // "The neighbor is declared bidirectional when the router
        // finds its own Router ID in the neighbor's Hello."
        let our_id_in_neighbor_list = hello.neighbors.contains(&our_router_id);

        if our_id_in_neighbor_list {
            if nbr.state == NeighborState::Init {
                nbr.handle_event(NeighborEvent::TwoWayReceived);
            }
        } else if nbr.state >= NeighborState::TwoWay {
            // RFC-REF: RFC 2328 Section 10.5
            // "If the router no longer appears in the neighbor's
            // Hello, event 1-Way is generated."
            nbr.handle_event(NeighborEvent::OneWay);
        }

        nbr.state
    }

    /// Expire neighbors whose dead interval has elapsed.
    ///
    /// RFC-REF: RFC 2328 Section 10.2
    /// "Event: InactivityTimer — Fired when no Hello packet has been
    /// seen from a neighbor recently."
    ///
    /// Returns the Router IDs of neighbors that were declared dead.
    pub fn expire_dead_neighbors(&mut self, now_secs: u64) -> Vec<[u8; 4]> {
        let dead_interval = self.dead_interval as u64;
        let mut dead_ids = Vec::new();

        for nbr in &mut self.neighbors {
            if nbr.state != NeighborState::Down
                && now_secs.saturating_sub(nbr.last_hello) >= dead_interval
            {
                dead_ids.push(nbr.router_id);
                nbr.handle_event(NeighborEvent::InactivityTimer);
            }
        }

        // Remove Down neighbors.
        self.neighbors
            .retain(|nbr| nbr.state != NeighborState::Down);

        dead_ids
    }

    /// Find a neighbor by Router ID, or create a new one.
    fn find_or_create_neighbor(&mut self, router_id: [u8; 4], ip_addr: [u8; 4]) -> usize {
        if let Some(idx) = self.neighbors.iter().position(|n| n.router_id == router_id) {
            idx
        } else {
            self.neighbors
                .push(Neighbor::new(router_id, ip_addr, self.name.clone()));
            self.neighbors.len() - 1
        }
    }

    /// Get a neighbor by Router ID.
    pub fn get_neighbor(&self, router_id: &[u8; 4]) -> Option<&Neighbor> {
        self.neighbors.iter().find(|n| n.router_id == *router_id)
    }

    /// Get a mutable neighbor by Router ID.
    pub fn get_neighbor_mut(&mut self, router_id: &[u8; 4]) -> Option<&mut Neighbor> {
        self.neighbors
            .iter_mut()
            .find(|n| n.router_id == *router_id)
    }

    /// Return the count of neighbors in Full state.
    pub fn full_neighbor_count(&self) -> usize {
        self.neighbors
            .iter()
            .filter(|n| n.state == NeighborState::Full)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ospf::packet::{OspfHeader, OspfPacketType, OSPF_VERSION};

    fn make_interface() -> OspfInterface {
        let config = OspfInterfaceConfig {
            name: "eth0".to_string(),
            hello_interval: 10,
            dead_interval: 40,
        };
        OspfInterface::new(
            config.borrow(),
            [10, 0, 0, 1],
            [255, 255, 255, 0],
            [0, 0, 0, 0],
        )
    }

    // Borrow helper for tests.
    impl OspfInterfaceConfig {
        fn borrow(&self) -> &OspfInterfaceConfig {
            self
        }
    }

    fn make_hello(
        router_id: [u8; 4],
        hello_interval: u16,
        dead_interval: u32,
        neighbors: Vec<[u8; 4]>,
    ) -> HelloPacket {
        HelloPacket {
            header: OspfHeader {
                version: OSPF_VERSION,
                packet_type: OspfPacketType::Hello,
                packet_length: 0,
                router_id,
                area_id: [0, 0, 0, 0],
                checksum: 0,
                auth_type: 0,
                auth_data: [0; 8],
            },
            network_mask: [255, 255, 255, 0],
            hello_interval,
            options: 0x02,
            router_priority: 1,
            router_dead_interval: dead_interval,
            designated_router: [0; 4],
            backup_designated_router: [0; 4],
            neighbors,
        }
    }

    #[test]
    fn interface_up_down() {
        let mut iface = make_interface();
        assert_eq!(iface.state, InterfaceState::Down);
        assert!(!iface.is_up());

        iface.up();
        assert_eq!(iface.state, InterfaceState::PointToPoint);
        assert!(iface.is_up());

        iface.down();
        assert_eq!(iface.state, InterfaceState::Down);
        assert!(!iface.is_up());
    }

    #[test]
    fn process_hello_creates_neighbor_init() {
        let mut iface = make_interface();
        iface.up();

        let hello = make_hello([2, 2, 2, 2], 10, 40, vec![]);
        let state = iface.process_hello(&hello, [10, 0, 0, 2], [1, 1, 1, 1], 100);

        // No bidirectionality yet — neighbor should be in Init.
        assert_eq!(state, NeighborState::Init);
        assert_eq!(iface.neighbors.len(), 1);
        assert_eq!(iface.neighbors[0].router_id, [2, 2, 2, 2]);
    }

    #[test]
    fn process_hello_bidirectional_to_exstart() {
        let mut iface = make_interface();
        iface.up();

        let our_router_id = [1, 1, 1, 1];

        // First Hello: no bidirectional.
        let hello = make_hello([2, 2, 2, 2], 10, 40, vec![]);
        iface.process_hello(&hello, [10, 0, 0, 2], our_router_id, 100);

        // Second Hello: our Router ID is in the neighbor's list.
        let hello = make_hello([2, 2, 2, 2], 10, 40, vec![our_router_id]);
        let state = iface.process_hello(&hello, [10, 0, 0, 2], our_router_id, 101);

        assert_eq!(state, NeighborState::ExStart);
    }

    #[test]
    fn process_hello_mismatched_interval_stays_down() {
        let mut iface = make_interface();
        iface.up();

        // Wrong hello_interval.
        let hello = make_hello([2, 2, 2, 2], 20, 40, vec![]);
        let state = iface.process_hello(&hello, [10, 0, 0, 2], [1, 1, 1, 1], 100);
        assert_eq!(state, NeighborState::Down);
        assert!(iface.neighbors.is_empty());
    }

    #[test]
    fn expire_dead_neighbors() {
        let mut iface = make_interface();
        iface.up();

        let hello = make_hello([2, 2, 2, 2], 10, 40, vec![]);
        iface.process_hello(&hello, [10, 0, 0, 2], [1, 1, 1, 1], 100);
        assert_eq!(iface.neighbors.len(), 1);

        // Not yet expired (only 30 seconds passed, dead_interval = 40).
        let dead = iface.expire_dead_neighbors(130);
        assert!(dead.is_empty());
        assert_eq!(iface.neighbors.len(), 1);

        // Now expired (41 seconds passed).
        let dead = iface.expire_dead_neighbors(141);
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0], [2, 2, 2, 2]);
        assert!(iface.neighbors.is_empty());
    }

    #[test]
    fn should_send_hello_timing() {
        let mut iface = make_interface();
        iface.up();
        iface.last_hello_sent = 100;

        assert!(!iface.should_send_hello(105)); // Only 5s elapsed
        assert!(iface.should_send_hello(110)); // 10s = hello_interval
        assert!(iface.should_send_hello(120)); // 20s > hello_interval
    }

    #[test]
    fn should_send_hello_down_interface() {
        let iface = make_interface();
        assert!(!iface.should_send_hello(1000));
    }

    #[test]
    fn full_neighbor_count() {
        let mut iface = make_interface();
        iface.up();

        assert_eq!(iface.full_neighbor_count(), 0);

        // Create a neighbor and push it to Full.
        let our_id = [1, 1, 1, 1];
        let hello = make_hello([2, 2, 2, 2], 10, 40, vec![our_id]);
        iface.process_hello(&hello, [10, 0, 0, 2], our_id, 100);

        // Drive neighbor to Full.
        if let Some(nbr) = iface.get_neighbor_mut(&[2, 2, 2, 2]) {
            nbr.handle_event(NeighborEvent::NegotiationDone);
            nbr.handle_event(NeighborEvent::ExchangeDone);
            nbr.handle_event(NeighborEvent::LoadingDone);
        }
        assert_eq!(iface.full_neighbor_count(), 1);
    }

    #[test]
    fn one_way_detection() {
        let mut iface = make_interface();
        iface.up();
        let our_id = [1, 1, 1, 1];

        // Establish bidirectional.
        let hello = make_hello([2, 2, 2, 2], 10, 40, vec![our_id]);
        iface.process_hello(&hello, [10, 0, 0, 2], our_id, 100);

        // Now receive a Hello without our ID (1-Way).
        let hello = make_hello([2, 2, 2, 2], 10, 40, vec![]);
        let state = iface.process_hello(&hello, [10, 0, 0, 2], our_id, 101);

        // Should be back to Init.
        assert_eq!(state, NeighborState::Init);
    }
}
