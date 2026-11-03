//! OBS-017: the firewall audit buffer reports its record count, the most
//! records it held across clears, and its capacity; records past the
//! capacity are counted as dropped and do not move the mark past it.

use super::*;

#[test]
fn audit_buffer_high_water_survives_clears_and_stays_within_capacity() {
    let mut storage = [FirewallAuditRecord::default(); 2];
    let mut audit = FirewallAuditBuffer::new(&mut storage);
    let disposition = FirewallAuditRecord::default().disposition;
    let flow = packet(FirewallProtocol::Udp, 0);
    let occupancy = |audit: &FirewallAuditBuffer<'_>| {
        let occupancy = audit.occupancy();
        (
            occupancy.occupied(),
            occupancy.high_water(),
            occupancy.capacity(),
        )
    };
    assert_eq!(occupancy(&audit), (0, 0, 2));
    audit.record(flow, disposition);
    assert_eq!(occupancy(&audit), (1, 1, 2));
    audit.clear();
    assert_eq!(occupancy(&audit), (0, 1, 2));
    for _ in 0..3 {
        audit.record(flow, disposition);
    }
    assert_eq!(audit.dropped_records(), 1);
    assert_eq!(occupancy(&audit), (2, 2, 2));
    audit.clear();
    assert_eq!(occupancy(&audit), (0, 2, 2));
}
