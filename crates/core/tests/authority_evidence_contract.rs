use ruster_core::{
    FirewallAuthorityEvidence, Nat44TcpAuthorityEvidence, Nat44UdpAuthorityEvidence,
};

fn assert_copy_eq<T: Copy + Eq + PartialEq>() {}

#[test]
fn public_authority_evidence_is_opaque_copy_eq_and_redacted() {
    assert_copy_eq::<Nat44UdpAuthorityEvidence>();
    assert_copy_eq::<Nat44TcpAuthorityEvidence>();
    assert_copy_eq::<FirewallAuthorityEvidence>();

    let udp_words = [0x0123_4567_89ab_cdef; 29];
    let udp = Nat44UdpAuthorityEvidence::from_expected_contract(2, 2, 2, 2, 2, 2, 2, udp_words);
    let tcp_words = [0xfedc_ba98_7654_3210; 29];
    let tcp = Nat44TcpAuthorityEvidence::from_expected_contract(2, 2, 2, 2, 2, 2, 2, tcp_words);
    let firewall_words = [
        0xfedc_ba98_7654_3210,
        0x0123_4567_89ab_cdef,
        0xaaaaaaaa_55555555,
        3,
        2,
        2,
        0x1357_9bdf_2468_ace0,
    ];
    let firewall = FirewallAuthorityEvidence::from_expected_contract(firewall_words);

    for index in 0..29 {
        let mut changed = udp_words;
        changed[index] ^= 1;
        assert_ne!(
            udp,
            Nat44UdpAuthorityEvidence::from_expected_contract(2, 2, 2, 2, 2, 2, 2, changed),
            "UDP hidden word {index} must participate in Eq"
        );

        let mut tcp_changed = tcp_words;
        tcp_changed[index] ^= 1;
        assert_ne!(
            tcp,
            Nat44TcpAuthorityEvidence::from_expected_contract(2, 2, 2, 2, 2, 2, 2, tcp_changed),
            "TCP hidden word {index} must participate in Eq"
        );
    }
    for index in 0..7 {
        let mut changed = firewall_words;
        changed[index] ^= 1;
        assert_ne!(
            firewall,
            FirewallAuthorityEvidence::from_expected_contract(changed),
            "firewall hidden word {index} must participate in Eq"
        );
    }

    assert_eq!(format!("{udp:?}"), "Nat44UdpAuthorityEvidence([REDACTED])");
    assert_eq!(format!("{tcp:?}"), "Nat44TcpAuthorityEvidence([REDACTED])");
    assert_eq!(
        format!("{firewall:?}"),
        "FirewallAuthorityEvidence([REDACTED])"
    );
}
