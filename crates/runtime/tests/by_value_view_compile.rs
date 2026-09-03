use ruster_core::{
    BoundPublicationBackend, FirewallConfig, FirewallRuntime, ForwardingSnapshot,
    Icmpv4ErrorRuntime, MatchedPublicationQuiescenceGuard, Nat44TcpConfig, Nat44TcpRuntime,
    Nat44UdpConfig, Nat44UdpRuntime, PublicationOwnerBinding, ResolutionRuntime,
};
use ruster_io_sim::SimIo;
use ruster_runtime::{
    ActivePublicationStatus, ActiveTickAuthority, FirewallServiceView, FullServicePublication,
    FullServiceView, Nat44TcpServiceView, Nat44UdpServiceView, PublicationRejection, TickBudgets,
};

type Backend = BoundPublicationBackend<SimIo>;

/// A downstream crate's minimal adapter fixture. Keeping this as an
/// integration test makes the public constructor, exact backend guard, and
/// lifetime shortening compile through the same surface available to external
/// users.
struct ExternalPublication<'owner, 'storage> {
    owner_binding: PublicationOwnerBinding<Backend>,
    tick_authority: ActiveTickAuthority,
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

#[allow(unsafe_code)]
unsafe impl<'owner, 'storage> FullServicePublication<'storage, Backend>
    for ExternalPublication<'owner, 'storage>
{
    type Candidate = ();
    type Reject = ();
    type ApplyReport = ();

    fn publication_owner_binding(&self) -> &PublicationOwnerBinding<Backend> {
        &self.owner_binding
    }

    fn reject_candidate_if_active_stopped(
        &self,
        candidate: Self::Candidate,
    ) -> Result<Self::Candidate, PublicationRejection<Self::Candidate, Self::Reject>> {
        Ok(candidate)
    }

    #[allow(unsafe_code)]
    unsafe fn publish_candidate_authorized(
        &mut self,
        _candidate: Self::Candidate,
        _quiescence: MatchedPublicationQuiescenceGuard<'_, Backend>,
    ) -> Result<Self::ApplyReport, PublicationRejection<Self::Candidate, Self::Reject>> {
        Ok(())
    }

    fn active_status(&self) -> ActivePublicationStatus {
        ActivePublicationStatus::ContinueOldIo
    }

    fn active(&mut self) -> FullServiceView<'_, 'storage> {
        FullServiceView::new(
            &self.tick_authority,
            *self.snapshot,
            self.resolution,
            self.icmpv4_errors,
            Nat44UdpServiceView::new(self.udp_config, self.nat44_udp.as_deref_mut()),
            Nat44TcpServiceView::new(self.tcp_config, self.nat44_tcp.as_deref_mut()),
            FirewallServiceView::new(self.firewall_config, self.firewall.as_deref_mut()),
        )
    }
}

fn require_external_publication<P: FullServicePublication<'static, Backend>>() {}

fn copy_generation_bound_budgets(view: &FullServiceView<'_, '_>) -> TickBudgets {
    view.tick_budgets()
}

#[test]
fn external_adapter_compiles_with_paired_generation_and_exact_backend_guard() {
    require_external_publication::<ExternalPublication<'static, 'static>>();
    let _accessor: fn(&FullServiceView<'_, '_>) -> TickBudgets = copy_generation_bound_budgets;
}

#[test]
fn external_adapter_can_return_the_exact_rejected_candidate() {
    let candidate = Box::new(47);
    let candidate_pointer = core::ptr::from_ref(candidate.as_ref());
    let rejection = PublicationRejection::new(candidate, "rejected");

    assert_eq!(rejection.error(), &"rejected");
    let (candidate, error) = rejection.into_parts();
    assert_eq!(error, "rejected");
    assert_eq!(candidate.as_ref(), &47);
    assert_eq!(core::ptr::from_ref(candidate.as_ref()), candidate_pointer);
}
