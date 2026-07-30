use std::num::NonZeroU64;

use ruster_core::{
    FirewallConfig, FirewallRuntime, ForwardingSnapshot, Icmpv4ErrorRuntime, Nat44TcpConfig,
    Nat44TcpRuntime, Nat44UdpConfig, Nat44UdpRuntime, PublicationQuiescenceGuard,
    ResolutionRuntime,
};
use ruster_io_sim::SimIo;
use ruster_runtime::{
    FirewallServiceView, FullServicePublication, FullServiceView, Nat44TcpServiceView,
    Nat44UdpServiceView,
};

/// A downstream crate's minimal adapter fixture. Keeping this as an
/// integration test makes the public struct literal, exact backend guard, and
/// lifetime shortening compile through the same surface available to external
/// users.
struct ExternalPublication<'owner, 'storage> {
    generation: NonZeroU64,
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

impl<'owner, 'storage> FullServicePublication<'storage, SimIo>
    for ExternalPublication<'owner, 'storage>
{
    type Candidate = ();
    type Reject = ();

    fn publish_candidate(
        &mut self,
        _candidate: Self::Candidate,
        _quiescence: PublicationQuiescenceGuard<'_, SimIo>,
    ) -> Result<(), Self::Reject> {
        Ok(())
    }

    fn active(&mut self) -> Option<FullServiceView<'_, 'storage>> {
        Some(FullServiceView {
            generation: self.generation,
            snapshot: *self.snapshot,
            resolution: self.resolution,
            icmpv4_errors: self.icmpv4_errors,
            nat44_udp: Nat44UdpServiceView {
                config: self.udp_config,
                runtime: self.nat44_udp.as_deref_mut(),
            },
            nat44_tcp: Nat44TcpServiceView {
                config: self.tcp_config,
                runtime: self.nat44_tcp.as_deref_mut(),
            },
            firewall: FirewallServiceView {
                config: self.firewall_config,
                runtime: self.firewall.as_deref_mut(),
            },
        })
    }
}

fn require_external_publication<P: FullServicePublication<'static, SimIo>>() {}

#[test]
fn external_adapter_compiles_with_paired_generation_and_exact_backend_guard() {
    require_external_publication::<ExternalPublication<'static, 'static>>();
}
