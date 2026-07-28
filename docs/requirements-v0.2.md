# v0.2 requirement and RFC ledger

Statusは`implemented`、`deferred`、`deviation`のいずれかです。test名はそのまま
`cargo test`のfilterとして利用できます。

| Requirement ID | 根拠 | Test ID | Status | deviation / note |
|---|---|---|---|---|
| IO-001 borrowed GAT batch/core RAII completion | architecture contract | `unfinished_core_lease_is_backend_lifecycle_recycle` | implemented | leaseは!Send/!Sync |
| IO-002 RX bufferをcloneせずTXへmove | architecture contract | `gateway_route_rewrites_and_reports_backend_acceptance` | implemented | allocation addressも検証 |
| IO-003 requested/accepted/recycled accounting | architecture contract | `mixed_batch_is_fifo_budgeted_and_reports_requested_accepted_recycled` | implemented | backend finishで確定 |
| IO-004 partial/error completion preserves report | architecture contract | `partial_backend_completion_preserves_report_and_aggregate_trace` | implemented | rejected slotはbackend所有で解放 |
| IO-005 ARP partial/error completion preserves report | architecture contract | `arp_partial_backend_rejection_preserves_error_report_and_trace` | implemented | requested=1/accepted=0/rejected=1とerrorを保持 |
| IO-006 generated GAT lease lifecycle/exact accounting | architecture contract | `generated_lease_commit_cancel_abandon_and_allocation_failures_are_exact` | implemented | beginでegress固定。commit/cancel/abandon accounting、allocation failure ownershipなし、allocation address moveを検証 |
| IO-007 generated partial/error completion | architecture contract | `generated_partial_tx_error_preserves_invariants_and_recycles_rejects` | implemented | 三つのaccounting不変条件を保持しrejectをreturn前にrecycle |
| IO-008 generated builder failure isolation | defensive backend boundary | `builder_failure_cancels_lease_and_retains_action` | implemented | exact-length契約違反bufferをcancelしactionを保持 |
| ETH-001 Ethernet II framing | RFC 894 | `all_validation_and_decision_drops_are_granular_and_atomic` | implemented | 802.3 LLC/VLANはdeferred |
| IP4-001 Version/IHL/Total Length validation | RFC 791 §3.1 | `all_validation_and_decision_drops_are_granular_and_atomic` | implemented | なし |
| IP4-002 Total Length後のpadding無視 | RFC 791 §3.1 | `padding_is_ignored_but_preserved` | implemented | なし |
| IP4-003 optionsを含むheader validation | RFC 791 §3.1 | `options_header_is_valid_but_forwarding_is_explicitly_unsupported` | implemented | header length/checksumを検証 |
| IP4-003A IPv4 options forwarding | RFC 791 §3.1 | `all_validation_and_decision_drops_are_granular_and_atomic` | deviation | option意味論未実装のためbyte不変drop。options利用packetは転送不可 |
| IP4-004 fragmentをL3転送 | RFC 791 §3.1 | `fragment_flags_offset_payload_and_checksum_are_preserved_or_updated_correctly` | implemented | reassemblyはrouter slice外 |
| IP4-005 header checksum validation | RFC 1071 | `all_validation_and_decision_drops_are_granular_and_atomic` | implemented | なし |
| FWD-001 `/0`と`/32`を含むLPM | forwarding requirement | `lpm_supports_default_and_host_routes` | implemented | ECMPなし |
| FWD-002 connected/gateway neighbor selection | forwarding requirement | `connected_route_uses_packet_destination_as_neighbor_target` | implemented | ARP学習自体はdeferred |
| FWD-003 TTL decrement | RFC 791 §3.1 | `gateway_route_rewrites_and_reports_backend_acceptance` | implemented | TTL expiry ICMP生成はdeferred |
| FWD-004 incremental checksum update | RFC 1624 §4 | `rfc_1624_negative_zero_boundary_is_positive_zero` | implemented | `0xdd2f,0x5555→0x3285 = 0x0000` |
| FWD-005 drop atomicity | architecture contract | `all_validation_and_decision_drops_are_granular_and_atomic` | implemented | なし |
| FWD-006 snapshot integrity | architecture contract | `snapshot_constructor_rejects_all_broken_references_and_duplicates` | implemented | 公開前にvalidation |
| FWD-007 unresolved trigger atomicity/request action | RFC 1122 §2.3.2.1 | `unresolved_neighbor_generates_broadcast_arp_request_and_recycles_trigger_atomically` | implemented | 元IPv4はbyte不変NeighborUnresolved、RX finish後にgenerated session |
| FWD-008 unresolved packet hold/replay | RFC 1122 §2.3.2.2, RFC 1812 §3.3.2 | `unresolved_neighbor_generates_broadcast_arp_request_and_recycles_trigger_atomically` | deferred | hold/replayなし。最初のpacketは解決後も自動再送されない |
| ARP-001 Ethernet/IPv4 request profile validation | RFC 826, RFC 5494/IANA ARP Parameters | `arp_profile_validation_drops_are_granular_and_atomic` | implemented | HTYPE=1/PTYPE=0x0800/HLEN=6/PLEN=4/opcode=1。replyとunknown opcodeを区別 |
| ARP-002 local target in-place reply on ingress | RFC 826 | `arp_request_for_local_ipv4_replies_in_place_on_ingress` | implemented | 同じRX allocation、egress=ingress、wire fieldsを検証 |
| ARP-003 probe reply with zero target protocol | RFC 5227 §2.5（Probe形式は§1.1/§2.1.1） | `arp_probe_for_local_ipv4_replies_with_zero_target_protocol` | implemented | SPA=0 requestにも通常reply |
| ARP-004 request THA ignored/source identities not coupled | RFC 826 | `arp_request_target_hardware_is_ignored` | implemented | Ethernet source≠ARP SHAも受理 |
| ARP-005 tail/padding preservation | RFC 826 wire profile | `arp_padding_is_ignored_and_preserved_on_reply` | implemented | 42 byte以後を変更しない |
| ARP-006 nonlocal/proxy-disabled/reply/unknown opcode stable recycle | RFC 826, RFC 1027, RFC 5494/IANA ARP Parameters | `arp_nonlocal_and_reply_are_recycled_without_mutation` | implemented | nonlocal targetへ応答せずproxy ARPは無効。replyとunknown opcodeは別stable reason |
| ARP-007 local binding snapshot integrity | architecture contract | `arp_snapshot_rejects_duplicate_or_unknown_local_addresses` | implemented | interfaceごとにlocal IPv4一つ、address重複/unknown interface/unspecified SPAを拒否。MACはInterfaceのみ |
| ARP-008 address conflict detection/defense | RFC 5227 §2.4 | `arp_foreign_sender_claiming_local_address_gets_normal_reply` | deviation | foreign SHAがlocal SPAを名乗ってもconflict state/defensive announcementなし。local targetへの通常replyのみ |
| ARP-009 learning/cache/aging/flush | RFC 826 | `arp_reply_does_not_learn_or_generate_for_unresolved_neighbor` | deferred | responderとrequest generatorはneighbor snapshotを変更しない |
| ARP-010 normal request 60-byte wire profile | RFC 826 | `unresolved_neighbor_generates_broadcast_arp_request_and_recycles_trigger_atomically` | implemented | broadcast Ethernet、SPAはnonzero local、THA zero、18-byte zero padding、FCSなし |
| ARP-010A ordinary request is not Probe/Announcement | RFC 826, local deterministic profile | `ordinary_resolution_request_is_not_probe_or_announcement` | implemented | SPA nonzero、SPA≠TPA、opcode Request |
| ARP-011 flood suppression exact deadline | RFC 1122 §2.3.2.1 | `same_target_is_rate_limited_to_one_request_per_second_at_exact_deadline` | implemented | commit時刻基準、999ms suppress/1000ms queue。partial rejectもrequestedなので開始 |
| ARP-011A suppression policy validation | RFC 1122 §2.3.2.1, local policy | `resolution_policy_rejects_short_interval_and_state_ttl` | implemented | interval>=1000ms、state TTL>=interval |
| ARP-012 action ring full semantics | architecture contract | `action_full_does_not_create_phantom_suppression` | implemented | action fullはphantom deadlineなし |
| ARP-012A state table full semantics | architecture contract | `state_full_never_evicts_live_entry_and_ttl_allows_reuse` | implemented | live非evict、TTL到達でreuse |
| ARP-012B monotonic clock regression | architecture contract | `clock_regression_is_typed_and_does_not_mutate_queue` | implemented | typed result/counter/trace、queue非変更 |
| ARP-012C resolution key independence | architecture contract | `resolution_keys_are_independent_by_interface_and_target` | implemented | target違いとIfId違いを独立queue |
| ARP-013 forbidden request targets | local safety policy | `local_binding_missing_and_forbidden_targets_generate_nothing` | implemented | unspecified/multicast/limited broadcast/確定可能なdirected broadcastとbindingなしは生成しない |
| ARP-014 traffic-driven retry/timer retry | RFC 1122 §2.3.2.1 | `allocation_failure_retains_action_and_does_not_start_deadline` | deferred | action保持とtraffic miss retryのみ。timer-only retry/max attempts/Failedなし |
| OBS-001 stable reason code | explainability requirement | `drop_reason_discriminants_and_codes_are_stable_and_unique` | implemented | repr(u16) |
| OBS-002 requestedとaggregate TX outcome trace | explainability requirement | `partial_backend_completion_preserves_report_and_aggregate_trace` | implemented | packet単位accepted traceはdeferred |
| OBS-003 protocol-aware ARP trace ordering | explainability requirement | `arp_trace_is_deterministic_and_tx_follows_commit` | implemented | validated/reply requested/TX requested/completionを順序検証 |
| SIM-001 FIFO/budget/mixed batch | deterministic test requirement | `mixed_batch_is_fifo_budgeted_and_reports_requested_accepted_recycled` | implemented | なし |
| SIM-002 mixed IPv4/ARP FIFO and budget | deterministic test requirement | `mixed_ipv4_and_arp_batch_is_fifo_budgeted_and_deterministic` | implemented | protocol混在でもsequenceとbudgetを保持 |
| SIM-003 mixed RX/generated FIFO and typed origin | deterministic test requirement | `mixed_rx_and_generated_tx_are_fifo_budgeted_and_origin_typed` | implemented | RX batch finish後に生成しoriginを型で区別 |

## RFC deviation rule

RFC準拠の挙動を意図的に変える変更は、この表に`deviation`としてRFC section、理由、
影響範囲、対応testを同じPRで記録します。未実装機能は準拠を主張せず`deferred`として
scopeを明示します。
