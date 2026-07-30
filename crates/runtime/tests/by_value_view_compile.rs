use ruster_core::{
    FirewallConfig, FirewallRuntime, ForwardingSnapshot, Icmpv4ErrorRuntime, Nat44TcpConfig,
    Nat44TcpRuntime, Nat44UdpConfig, Nat44UdpRuntime, ResolutionRuntime,
};
use ruster_runtime::{FullServicePublication, FullServiceView};

/// A downstream crate's minimal adapter fixture. Keeping this as an
/// integration test makes the public struct literal and lifetime shortening
/// compile through the same surface available to external users.
struct ExternalPublication<'owner, 'storage> {
    snapshot: &'owner ForwardingSnapshot<'storage>,
    resolution: &'owner mut ResolutionRuntime<'storage>,
    icmpv4_errors: &'owner mut Icmpv4ErrorRuntime<'storage>,
    udp_config: Nat44UdpConfig,
    nat44_udp: Option<&'owner mut Nat44UdpRuntime<'storage>>,
    tcp_config: Nat44TcpConfig,
    nat44_tcp: Option<&'owner mut Nat44TcpRuntime<'storage>>,
    firewall_config: FirewallConfig<'storage>,
    firewall: Option<&'owner mut FirewallRuntime<'storage>>,
}

impl<'owner, 'storage> FullServicePublication<'storage> for ExternalPublication<'owner, 'storage> {
    type Candidate = ();
    type Reject = ();

    fn publish_candidate(&mut self, _candidate: Self::Candidate) -> Result<(), Self::Reject> {
        Ok(())
    }

    fn active(&mut self) -> Option<FullServiceView<'_, 'storage>> {
        Some(FullServiceView {
            snapshot: *self.snapshot,
            resolution: self.resolution,
            icmpv4_errors: self.icmpv4_errors,
            udp_config: self.udp_config,
            nat44_udp: self.nat44_udp.as_deref_mut(),
            tcp_config: self.tcp_config,
            nat44_tcp: self.nat44_tcp.as_deref_mut(),
            firewall_config: self.firewall_config,
            firewall: self.firewall.as_deref_mut(),
        })
    }
}

fn require_external_publication<P: FullServicePublication<'static>>() {}

#[test]
fn external_downstream_adapter_compiles_with_by_value_authority() {
    require_external_publication::<ExternalPublication<'static, 'static>>();
}
