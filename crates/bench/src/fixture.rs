use ruster_core::{ipv4_header_checksum, ETHERNET_HEADER_LEN};

const ETHERNET_FCS_BYTES: usize = 4;
const ETHERNET_PREAMBLE_SFD_BYTES: usize = 8;
const ETHERNET_INTER_PACKET_GAP_BYTES: usize = 12;

/// Explicit packet-size conventions used by benchmark rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameSize {
    /// Minimum Ethernet frame: 60 bytes in the backend buffer and 64 bytes
    /// from destination MAC through FCS on the wire.
    Wire64,
    /// IPv4 MTU 1500: 1514 bytes in the backend buffer and 1518 bytes through
    /// FCS on the wire.
    Ipv4Mtu1500,
}

impl FrameSize {
    pub const ALL: [Self; 2] = [Self::Wire64, Self::Ipv4Mtu1500];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Wire64 => "wire64",
            Self::Ipv4Mtu1500 => "ip-mtu1500",
        }
    }

    #[must_use]
    pub const fn backend_bytes(self) -> usize {
        match self {
            Self::Wire64 => 60,
            Self::Ipv4Mtu1500 => 1_514,
        }
    }

    #[must_use]
    pub const fn ethernet_bytes_including_fcs(self) -> usize {
        self.backend_bytes() + ETHERNET_FCS_BYTES
    }

    #[must_use]
    pub const fn wire_bytes_with_preamble_ifg(self) -> usize {
        self.ethernet_bytes_including_fcs()
            + ETHERNET_PREAMBLE_SFD_BYTES
            + ETHERNET_INTER_PACKET_GAP_BYTES
    }

    #[must_use]
    pub const fn ipv4_total_bytes(self) -> usize {
        self.backend_bytes() - ETHERNET_HEADER_LEN
    }
}

/// Creates one deterministic, valid Ethernet/IPv4/UDP forwarding fixture.
///
/// UDP checksum zero is legal and keeps this foundation case focused on the
/// plain IPv4 forwarding path. Later profile-specific benchmark slices own
/// transport checksum fixtures.
#[must_use]
pub fn plain_ipv4_fixture(size: FrameSize, seed: u64) -> Vec<u8> {
    let mut frame = vec![0_u8; size.backend_bytes()];
    frame[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x10]);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());

    let ip = ETHERNET_HEADER_LEN;
    frame[ip] = 0x45;
    frame[ip + 1] = 0;
    frame[ip + 2..ip + 4].copy_from_slice(
        &u16::try_from(size.ipv4_total_bytes())
            .unwrap()
            .to_be_bytes(),
    );
    frame[ip + 4..ip + 6].copy_from_slice(&0x1234_u16.to_be_bytes());
    frame[ip + 6..ip + 8].copy_from_slice(&0x4000_u16.to_be_bytes());
    frame[ip + 8] = 64;
    frame[ip + 9] = 17;
    frame[ip + 12..ip + 16].copy_from_slice(&[192, 0, 2, 10]);
    frame[ip + 16..ip + 20].copy_from_slice(&[198, 51, 100, 10]);

    let udp = ip + 20;
    frame[udp..udp + 2].copy_from_slice(&12_345_u16.to_be_bytes());
    frame[udp + 2..udp + 4].copy_from_slice(&443_u16.to_be_bytes());
    frame[udp + 4..udp + 6].copy_from_slice(
        &u16::try_from(size.ipv4_total_bytes() - 20)
            .unwrap()
            .to_be_bytes(),
    );
    frame[udp + 6..udp + 8].copy_from_slice(&0_u16.to_be_bytes());

    let mut state = seed.max(1);
    for byte in &mut frame[udp + 8..] {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }

    let checksum = ipv4_header_checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
    frame
}

#[cfg(test)]
mod tests {
    use ruster_core::validate_ipv4_frame;

    use super::*;

    #[test]
    fn size_labels_state_backend_and_wire_conventions_exactly() {
        assert_eq!(FrameSize::Wire64.backend_bytes(), 60);
        assert_eq!(FrameSize::Wire64.ethernet_bytes_including_fcs(), 64);
        assert_eq!(FrameSize::Wire64.wire_bytes_with_preamble_ifg(), 84);
        assert_eq!(FrameSize::Wire64.ipv4_total_bytes(), 46);

        assert_eq!(FrameSize::Ipv4Mtu1500.backend_bytes(), 1_514);
        assert_eq!(FrameSize::Ipv4Mtu1500.ethernet_bytes_including_fcs(), 1_518);
        assert_eq!(FrameSize::Ipv4Mtu1500.wire_bytes_with_preamble_ifg(), 1_538);
        assert_eq!(FrameSize::Ipv4Mtu1500.ipv4_total_bytes(), 1_500);
    }

    #[test]
    fn fixtures_are_valid_and_seed_deterministic() {
        for size in FrameSize::ALL {
            let first = plain_ipv4_fixture(size, 7);
            let same = plain_ipv4_fixture(size, 7);
            let other = plain_ipv4_fixture(size, 8);
            assert_eq!(first, same);
            assert_ne!(first, other);
            let ipv4 = validate_ipv4_frame(&first).unwrap();
            assert_eq!(ipv4.total_len, size.ipv4_total_bytes());
            assert_eq!(ipv4.ttl, 64);
            assert_eq!(first.len(), size.backend_bytes());
        }
    }
}
