# v0.2 requirement and RFC ledger

Statusは`implemented`、`deferred`、`deviation`のいずれかです。test名はそのまま
`cargo test`のfilterとして利用できます。直接test不能な将来要件に限り、`deferred`
かつnote付きでTest IDを`—`にできます。

| Requirement ID | 根拠 | Test ID | Status | deviation / note |
|---|---|---|---|---|
| IO-001 borrowed GAT batch/core RAII completion | architecture contract | `unfinished_core_lease_is_backend_lifecycle_recycle` | implemented | unfinished leaseのRAII recycleを検証 |
| IO-002 RX bufferをcloneせずTXへmove | architecture contract | `gateway_route_rewrites_and_reports_backend_acceptance` | implemented | allocation addressも検証 |
| IO-003 requested/accepted/recycled accounting | architecture contract | `mixed_batch_is_fifo_budgeted_and_reports_requested_accepted_recycled` | implemented | backend finishで確定 |
| IO-004 partial/error completion preserves report | architecture contract | `partial_backend_completion_preserves_report_and_aggregate_trace` | implemented | rejected slotはbackend所有で解放 |
| IO-005 ARP partial/error completion preserves report | architecture contract | `arp_partial_backend_rejection_preserves_error_report_and_trace` | implemented | requested=1/accepted=0/rejected=1とerrorを保持 |
| IO-006 generated GAT lease lifecycle/exact accounting | architecture contract | `generated_lease_commit_cancel_abandon_and_allocation_failures_are_exact` | implemented | beginでegress固定。commit/cancel/abandon accounting、allocation failure ownershipなし、allocation address moveを検証 |
| IO-007 generated partial/error completion | architecture contract | `generated_partial_tx_error_preserves_invariants_and_recycles_rejects` | implemented | 三つのaccounting不変条件を保持しrejectをreturn前にrecycle |
| IO-008 generated builder failure isolation | defensive backend boundary | `builder_failure_cancels_lease_and_retains_action` | implemented | exact-length契約違反bufferをcancelしactionを保持 |
| IO-009 real generated backend | backend roadmap | — | deferred | AF_XDP/DPDK generated allocator/TXは未実装 |
| IO-010 ARP control consume lifecycle/accounting | architecture contract | `mixed_reply_then_ipv4_uses_dynamic_mapping_in_same_batch` | implemented | `BatchReport`/`RecycleCause`でlogical consumeを区別。physical recycle countはdrop+consumeを含み、received=TX+drop+consume |
| IO-011 local IPv4 consume lifecycle/accounting | architecture contract | `valid_unsupported_local_traffic_is_consumed_without_routing` | implemented | valid unsupported local deliveryをrouting/ARPへ流さずtyped consume |
| ETH-001 Ethernet II framing | RFC 894 | `all_validation_and_decision_drops_are_granular_and_atomic` | implemented | 802.3 LLC/VLANはdeferred |
| IP4-001 Version/IHL/Total Length validation | RFC 791 §3.1 | `all_validation_and_decision_drops_are_granular_and_atomic` | implemented | なし |
| IP4-002 Total Length後のpadding無視 | RFC 791 §3.1 | `padding_is_ignored_but_preserved` | implemented | なし |
| IP4-003 optionsを含むheader validation | RFC 791 §3.1 | `options_header_is_valid_but_forwarding_is_explicitly_unsupported` | implemented | header length/checksumを検証 |
| IP4-003A IPv4 options forwarding | RFC 791 §3.1 | `all_validation_and_decision_drops_are_granular_and_atomic` | deviation | option意味論未実装のためbyte不変drop。options利用packetは転送不可 |
| IP4-004 fragmentをL3転送 | RFC 791 §3.1 | `fragment_flags_offset_payload_and_checksum_are_preserved_or_updated_correctly` | implemented | reassemblyはrouter slice外 |
| IP4-005 header checksum validation | RFC 1071 | `all_validation_and_decision_drops_are_granular_and_atomic` | implemented | なし |
| FWD-001 `/0`と`/32`を含むLPM | forwarding requirement | `lpm_supports_default_and_host_routes` | implemented | ECMPなし |
| FWD-002 connected/gateway neighbor selection | forwarding requirement | `connected_route_uses_packet_destination_as_neighbor_target` | implemented | static lookupを優先しdynamicへfallback |
| FWD-003 TTL decrement | RFC 791 §3.1 | `gateway_route_rewrites_and_reports_backend_acceptance` | implemented | TTL 2以上を転送時に1減算 |
| FWD-004 incremental checksum update | RFC 1624 §4 | `rfc_1624_negative_zero_boundary_is_positive_zero` | implemented | `0xdd2f,0x5555→0x3285 = 0x0000` |
| FWD-005 drop atomicity | architecture contract | `all_validation_and_decision_drops_are_granular_and_atomic` | implemented | なし |
| FWD-006 snapshot integrity | architecture contract | `snapshot_constructor_rejects_all_broken_references_and_duplicates` | implemented | 公開前にvalidation |
| FWD-007 unresolved trigger atomicity/request action | RFC 1122 §2.3.2.1 | `unresolved_neighbor_generates_broadcast_arp_request_and_recycles_trigger_atomically` | implemented | 元IPv4はbyte不変NeighborUnresolved、RX finish後にgenerated session |
| FWD-008 unresolved packet hold/replay | RFC 1122 §2.3.2.2, RFC 1812 §3.3.2 | — | deferred | hold/replay未実装。最初のpacketは解決後も自動再送されない |
| ICMP4-001 ingress-scoped local delivery | RFC 1122 §3.3.4.2, RFC 1812 §5.2.3 | `local_address_matching_is_strictly_ingress_scoped` | deviation | Strong ES同様のingress scopeを採用し、RFC 1812のrouter-wide local deliveryと異なる |
| ICMP4-002 Echo Request/Reply in-place profile | RFC 792, RFC 1122 §3.2.2.6 | `local_echo_reply_is_in_place_exact_and_traced` | implemented | Type 8/Code 0を同じRX allocationでType 0へ変換しingress commit |
| ICMP4-002A Echo with IPv4 options | RFC 1122 §3.2.2.6, RFC 1812 §4.3.3.6, §§5.3.13.4–5.3.13.6 | `local_echo_with_ipv4_options_is_an_atomic_documented_deviation` | deviation | source-route reversalとSource Route/RR/Timestamp処理を未実装のためbyte不変drop |
| ICMP4-003 full/odd-length checksum and Total Length boundary | RFC 792, RFC 1071 | `odd_length_echo_payload_checksum_and_ttl_zero_are_supported` | implemented | ICMP全messageを検証しodd final octetとlink paddingを区別 |
| ICMP4-004 malformed Echo atomic drop | RFC 792, architecture contract | `invalid_ipv4_or_icmp_checksum_and_nonzero_echo_code_are_atomic` | implemented | invalid IPv4/ICMP checksumとnonzero codeはstable reasonでbyte不変drop |
| ICMP4-005 exact ICMP/Echo minimum lengths | RFC 792 | `exact_icmp_truncation_boundaries_have_stable_atomic_reasons` | implemented | common header 4 bytes、Echo header 8 bytesの直前/境界を検証 |
| ICMP4-006 local fragment reassembly | RFC 1122 §3.2.1.4 | `local_echo_fragments_are_typed_atomic_drops` | deviation | reassembly未実装のためMF/offset付きlocal ICMPをbyte不変dropし応答しない |
| ICMP4-006A reserved IPv4 flag handling | RFC 1812 §4.2.2.3 | `local_echo_reserved_flag_is_accepted_and_cleared_in_reply` | implemented | reserved bitだけでは受信dropせず、originated atomic ReplyではclearしてDFだけを設定 |
| ICMP4-007 invalid IPv4 source reply suppression | RFC 1812 §§4.2.2.11, 5.3.7 | `invalid_echo_ipv4_sources_cannot_trigger_replies` | implemented | non-host、connected network/broadcast、ingress-local sourceへ応答しない |
| ICMP4-008 exact L2 reply admission | RFC 1812 §5.3.4, local anti-amplification policy | `echo_requires_unicast_source_mac_and_exact_local_destination_mac` | implemented | link broadcast/multicastを抑止し、local policyでnonzero unicast sourceとexact local destination MACを要求 |
| ICMP4-009 atomic reply IPv4 profile | RFC 6864, local deterministic policy | `local_echo_reply_is_in_place_exact_and_traced` | implemented | default TTL=64、ID=0、DF=1、MF/offset=0。DSCP/ECNとTotal Lengthは保存 |
| ICMP4-009A configurable originated TTL | RFC 1122 §3.2.1.7, RFC 1812 §4.2.2.9 | `configured_origin_ttl_is_validated_and_used_for_echo_reply` | implemented | `Ipv4OriginPolicy`はdefault 64、1..=255を許可しzeroをreject |
| ICMP4-010 unsupported local consume lifecycle | architecture contract | `valid_unsupported_local_traffic_is_consumed_without_routing` | implemented | local non-ICMPとchecksum-valid non-Echo ICMPをbyte不変consumeしownershipを終端 |
| ICMP4-010A ICMP user interface delivery | RFC 1122 §3.2.2, RFC 1812 §4.3.3 | — | deferred | Echo ReplyとICMP error/controlを渡すupper-layer interfaceは未実装 |
| ICMP4-011 partial TX completion | architecture contract | `echo_partial_backend_rejection_preserves_lifecycle_and_trace` | implemented | requested/accepted/rejected/errorとterminal traceを保持 |
| ICMP4-012 Time Exceeded Code 0 generation | RFC 792, RFC 1812 §§4.3.2, 5.2.7.3 | `ttl_expiry_is_atomic_and_generates_exact_asymmetric_static_reply` | implemented | nonlocal TTL 0/1をbyte不変drop後、別generated sessionでType 11/Code 0 |
| ICMP4-012A RFC error suppression | RFC 1812 §§4.3.2.7, 4.3.2.8, 5.3.1 | `rfc1812_suppression_matrix_is_typed_and_byte_atomic` | implemented | invalid source/destination、L2 group、noninitial fragment、ICMP error recursionをtyped suppression |
| ICMP4-012A1 selected-prefix boundary suppression | RFC 1812 §4.3.2.7, §§4.2.3.1, 5.3.5 | `selected_gateway_prefix_suppresses_remote_boundaries_but_lpm_host_routes_win` | implemented | source/destinationともgateway-routed `/24`のnetwork/directed broadcastを抑止。LPM-selected `/32`を優先し、`/31` endpointを許可 |
| ICMP4-012B reverse route and neighbor authority | RFC 1812 §4.3.2.4, §§5.2.4.1–5.2.4.3 | `unresolved_reverse_neighbor_queues_only_arp_and_same_batch_learning_is_ordered` | implemented | sourceへの通常LPM。ingress Ethernet sourceを信用せず、static→fresh dynamic。missはARPだけでICMP holdなし |
| ICMP4-012C bounded quote and generated wire | RFC 792, RFC 1812 §§4.3.2.3, 4.3.2.5 | `quote_boundaries_exclude_padding_and_zero_generated_padding` | implemented | received IPv4を最大548 bytes引用、outer IP最大576/frame最大590、odd checksum、padding zero |
| ICMP4-012D per-egress timer limiter | RFC 1812 §4.3.2.8 | `allocation_build_and_backend_reject_lifecycles_are_exact` | implemented | default 100ms、commit起点、exact boundary、rejectもdeadline開始、allocation/build失敗はaction保持 |
| ICMP4-012E fixed caller-backed error runtime | architecture contract | `wrapped_fifo_reuses_only_expired_idle_state` | implemented | ARPと別FIFO/state、one queued per egress、expired idleだけreuse、zero capacity/clock regression safe |
| ICMP4-012F options Time Exceeded | RFC 1812 §4.3.2.6, §§5.3.13.4–5.3.13.6 | `ethernet_group_destination_and_options_suppress_without_mutation` | deviation | source-route reversal/option処理未実装のためTTL判定前にbyte不変drop |
| ICMP4-012G Destination Unreachable Network generation | RFC 792, RFC 1812 §§4.3.2, 5.2.7.1 | `route_miss_is_atomic_and_generates_exact_type3_code0` | implemented | valid nonlocal IHL=5の完全なLPM missだけをbyte不変`RouteMiss`後にType 3/Code 0化。TTLよりroute missを優先 |
| ICMP4-012G1 shared typed generated-error runtime | RFC 1812 §4.3.2.8, architecture contract | `mixed_kinds_share_fifo_pending_and_exact_rate_boundary` | implemented | kindをFIFO/builder/report/traceへ保持し、Time Exceededとaction capacity/per-egress limiterを共有 |
| ICMP4-012G2 Destination Unreachable reverse authority | RFC 1812 §4.3.2.4, §§5.2.4.1–5.2.4.3 | `reverse_connected_static_and_gateway_dynamic_neighbors_are_authoritative` | implemented | original sourceへのconnected/gateway LPM、static→fresh dynamic。unresolved時はARPだけでfresh packetが必要 |
| ICMP4-012G3 Destination Unreachable suppression/options | RFC 1812 §§4.3.2.6–4.3.2.8 | `route_miss_suppression_matrix_and_options_are_atomic` | deviation | RFC error suppressionを共有。source-route/options未実装のためLPM前にbyte不変drop |
| ICMP4-012G4 Destination Unreachable bounded wire | RFC 792, RFC 1812 §§4.3.2.3, 4.3.2.5 | `destination_unreachable_quote_bounds_exclude_padding_and_checksum_odd_lengths` | implemented | Type 3/Code 0/unused zero、quote最大548、outer最大576、odd checksum、padding zero |
| ICMP4-012H Destination Unreachable Host generation | RFC 792, RFC 1812 §3.3.2 | `direct_timeout_after_accepted_arp_generates_exact_type3_code1` | implemented | direct targetのfruitless ARP generationだけType 3/Code 1。final full interval、accepted>=1、exact wire/quote |
| ICMP4-012H1 quote-only first-wins hold | RFC 1122 §2.3.2.2, RFC 1812 §3.3.2, local bounded policy | `first_eligible_candidate_wins_and_suppressed_first_can_be_filled` | deviation | packet/leaseをhold/replayせず別fixed slotへ最大548 bytes copy。latest packetでなくfirst eligibleを保持 |
| ICMP4-012H2 accepted-attempt terminal admission | architecture accounting contract | `rejected_arp_never_generates_but_mixed_acceptance_is_eligible` | implemented | committed attemptとaccepted attemptを分離。全rejectは`NoAcceptedArpRequest`、finish errorでもcompletion acceptedを反映 |
| ICMP4-012H3 direct-only and bounded capacity | RFC 1812 §3.3.2, local safety policy | `gateway_failure_and_zero_hold_capacity_never_queue_code1` | implemented | gateway next-hop failureは対象外。hold zero/fullでもresolution本体へ影響しない |
| ICMP4-012H4 reverse resolution continuation | RFC 1812 §4.3.2.4, §§5.2.4.1–5.2.4.3 | `reverse_miss_survives_arp_then_learning_queues_once` | implemented | reverse missはholdなし通常ARP、candidateは残し、learning後fresh originalなしでCode 1 queue。active token反復scanはpendingでschedule二重計上せず、recursive failureはretire |
| ICMP4-012H5 publication/learning cancellation | control-plane publication contract | `publication_and_learning_cancel_unqueued_holds_and_storage_recreation_zeroes_it` | implemented | forward dynamic/static success、direct authority変更、runtime recreateで未queue quoteをcancel/zero化 |
| ICMP4-012I other ICMP errors and queries | RFC 792, RFC 1122 §3.2.2 | — | deferred | Destination Unreachableの他code、Parameter Problem、Redirect、Timestamp等は未実装 |
| ICMP4-013 resolution isolation | architecture contract | `local_echo_and_consume_leave_resolution_runtime_untouched` | implemented | Echo/consumeはdynamic cache、pending state/action、FIFO/capacity、monotonic watermarkを変更しない |
| ARP-001 Ethernet/IPv4 Request/Reply profile validation | RFC 826, RFC 5494/IANA ARP Parameters | `arp_profile_validation_drops_are_granular_and_atomic` | implemented | HTYPE=1/PTYPE=0x0800/HLEN=6/PLEN=4、unknown opcodeはdrop |
| ARP-002 local target in-place reply on ingress | RFC 826 | `arp_request_for_local_ipv4_replies_in_place_on_ingress` | implemented | 同じRX allocation、egress=ingress、wire fieldsを検証 |
| ARP-003 probe reply with zero target protocol | RFC 5227 §2.5（Probe形式は§1.1/§2.1.1） | `arp_probe_for_local_ipv4_replies_with_zero_target_protocol` | implemented | SPA=0 requestにも通常reply |
| ARP-004 request THA ignored/source identities not coupled | RFC 826 | `arp_request_target_hardware_is_ignored` | implemented | Ethernet source≠ARP SHAも受理 |
| ARP-005 tail/padding preservation | RFC 826 wire profile | `arp_padding_is_ignored_and_preserved_on_reply` | implemented | 42 byte以後を変更しない |
| ARP-006 valid Reply/nonlocal Request consume | RFC 826, RFC 1027 | `arp_nonlocal_and_reply_are_recycled_without_mutation` | implemented | proxy ARPなし、valid controlはbyte不変consume。unknown opcodeだけdrop |
| ARP-007 local binding snapshot integrity | architecture contract | `arp_snapshot_rejects_duplicate_or_unknown_local_addresses` | implemented | interfaceごとにlocal IPv4一つ、address重複/unknown interface/unspecified SPAを拒否。MACはInterfaceのみ |
| ARP-008 address conflict detection/defense | RFC 5227 §2.4 | `foreign_local_spa_cannot_poison_and_static_mapping_has_priority` | deviation | foreign SHAのlocal SPA claimはcacheへ入れず、local Requestには通常replyするがdefenseなし |
| ARP-009 request/reply learn-forward vertical slice | RFC 826 | `miss_request_reply_consume_then_reinjected_ipv4_forwards` | implemented | miss→Request→Reply consume/learn→fresh reinject forward。元packet holdなし |
| ARP-009A dynamic TTL/lazy stale removal | RFC 1122 §2.3.2.1 | `ttl_boundary_refresh_expired_reuse_and_cache_full_are_exact` | implemented | configurable TTL、TTL-1 hit、exact expiry、expired reuse、live非evict |
| ARP-009B eager cache scan/administrative flush | control-plane roadmap | — | deferred | lookup/insert時のlazy expiryのみ |
| ARP-010 normal request 60-byte wire profile | RFC 826, RFC 894 | `unresolved_neighbor_generates_broadcast_arp_request_and_recycles_trigger_atomically` | implemented | broadcast Ethernet、SPAはnonzero local、THA zero、18-byte zero padding、FCSなし |
| ARP-010A ordinary request is not Probe/Announcement | RFC 826, local deterministic profile | `ordinary_resolution_request_is_not_probe_or_announcement` | implemented | SPA nonzero、SPA≠TPA、opcode Request |
| ARP-011 commit-based suppression deadline | RFC 1122 §2.3.2.1 flood-prevention boundary、local timing policy | `suppression_deadline_starts_at_generated_commit_time` | implemented | enqueue=0ms、commit=700ms、1699ms suppress、1700ms queue |
| ARP-011B exact interval and rejected request suppression | local commit/accounting policy within RFC 1122 §2.3.2.1 flood prevention | `same_target_is_rate_limited_to_one_request_per_second_at_exact_deadline` | implemented | local 1000ms interval。partial rejectもTX requestedなので0msから999ms suppress、1000ms queue |
| ARP-011A suppression policy validation | local policy、RFC 1122 §2.3.2.1はflood preventionのみ | `resolution_policy_rejects_short_interval_and_state_ttl` | implemented | local interval>=1000ms、Failed hold>=interval |
| ARP-011C committed cooldown survives authority churn | RFC 1122 §2.3.2.1 flood-prevention boundary、local fixed-storage policy | `learned_mapping_with_short_ttl_cannot_reset_committed_cooldown` | implemented | learn/cache expiry後もcommit時刻をtombstone保持しexact intervalまで再Requestしない |
| ARP-011D static publication cooldown continuity | control-plane publication contract | `static_publication_removal_cannot_reset_committed_cooldown` | implemented | static publish/remove churnはcommitted cooldownを消さず、tombstoneはretryを生成しない |
| ARP-011E uncommitted cancel and tombstone reuse | architecture contract | `uncommitted_cancel_has_no_cooldown_and_expired_tombstone_is_reusable` | implemented | 未commit cancelは即vacate、committed tombstoneはexact expiry後だけ別keyへreuse |
| ARP-011F authority reconciliation cooldown safety | control-plane publication contract | `authority_change_scrubs_retry_but_preserves_cooldown_and_clock_atomicity` | implemented | stale source actionをscrubし、cooldown/clock atomicityを維持、exact後はnew authorityだけqueue |
| ARP-012 action ring full semantics | architecture contract | `action_full_does_not_create_phantom_suppression` | implemented | action fullはphantom deadlineなし |
| ARP-012A state table full semantics | architecture contract | `state_full_never_evicts_active_or_failed_entry_and_hold_expiry_allows_reuse` | implemented | active/Failed非evict、Failed hold exact expiry後だけreuse |
| ARP-012B monotonic clock regression | architecture contract | `clock_regression_is_typed_and_does_not_mutate_queue` | implemented | typed result/counter/trace、queue非変更 |
| ARP-012C resolution key independence | architecture contract | `resolution_keys_are_independent_by_interface_and_target` | implemented | target違いとIfId違いを独立queue |
| ARP-012D runtime storage initialization | architecture contract | `recreating_runtime_clears_caller_state_and_queued_actions` | implemented | constructorはstate/action storageをemptyへ初期化 |
| ARP-012E runtime state persistence/resume | architecture contract | — | deferred | process/runtime再生成をまたぐresolution state永続化は未実装 |
| ARP-013 forbidden request targets | local safety policy | `local_binding_missing_and_forbidden_targets_generate_nothing` | implemented | unspecified/multicast/limited broadcast/確定可能なnetwork・directed broadcastとbindingなしは生成しない |
| ARP-013A local source address target prohibition | local safety policy | `local_source_ip_is_forbidden_as_connected_or_gateway_target` | implemented | connected destinationとgateway next-hopの両方でsource local IPを拒否 |
| ARP-013B all-connected-route directed broadcast check | local safety policy | `gateway_target_matching_same_egress_connected_broadcast_is_forbidden` | implemented | packet選択default route以外の同一egress connected /24も確認 |
| ARP-014 allocation failure action retention | architecture contract | `allocation_failure_retains_action_and_does_not_start_deadline` | implemented | action保持、attempt/deadline非開始、後続executorでretry可能 |
| ARP-014E build failure action retention | architecture contract | `builder_failure_cancels_lease_and_retains_action` | implemented | short allocationをcancelしaction保持、attempt/deadline非開始 |
| ARP-014A timer retry/max attempts/Failed | local policy、RFC 1812 §3.3.2はfruitless resolutionの上位境界 | `exact_three_attempt_timeline_and_max_one_wait_full_interval` | implemented | default total 3、max=1もfinal commitからfull interval後に一度だけTimedOut。RFC固定値ではない |
| ARP-014B traffic-independent bounded timer progress | architecture contract | `late_poll_queues_only_one_retry_and_rx_timer_order_is_idempotent` | implemented | explicit scan budget、late poll一attempt、RX/timer順序によらずone queued |
| ARP-014F timer action pressure fairness | architecture contract | `bounded_round_robin_makes_progress_under_action_pressure` | implemented | persistent RR、action-full deferred report/trace、次keyも飢餓しない |
| ARP-014C terminal hold lifecycle | architecture contract | `failed_hold_has_one_terminal_transition_and_exact_expiry_new_generation` | implemented | TTL-1 Failed、exact fresh generation、世代ごとにterminal通知一度 |
| ARP-014G terminal forwarding visibility | architecture contract | `terminal_resolution_is_typed_in_forwarding_trace_but_drop_stays_unresolved` | implemented | dropはNeighborUnresolvedのままresolution resultはTimedOut/Failed |
| ARP-014D committed attempt lifecycle | architecture contract | `same_target_is_rate_limited_to_one_request_per_second_at_exact_deadline` | implemented | lease commitだけattempt増加。backend rejectもcommitted attempt |
| ARP-014H generated finish error attempt lifecycle | architecture contract | `generated_finish_error_still_commits_one_resolution_attempt` | implemented | finish errorでもTX requested済みの一attemptとして数える |
| ARP-015 multi-worker resolution ownership/sharding | concurrency design | — | deferred | 現sliceはsingle worker ownerのみ。shard/SPSC handoff未実装 |
| ARP-016 Probe/Announcement/GARP/ACD generation | RFC 5227 | — | deferred | generated pathは通常ARP Requestだけ。Probe/Announcement/GARP/ACDは未実装 |
| ARP-017 target-local unsolicited admission/nonlocal ignore | RFC 826 | `unsolicited_local_reply_learns_while_nonlocal_absent_is_ignored` | implemented | solicited-only制限なし。target-local Replyはinsert、nonlocal absentはconsume-ignore |
| ARP-018 merge precedes opcode/target and GARP refresh | RFC 826 | `existing_mapping_merge_precedes_target_and_opcode_and_garp_refreshes` | implemented | existing keyはReply/Request/Announcement、local/nonlocal TPAに依らずSHAへmerge |
| ARP-018A unknown opcode atomic hardening drop | RFC 826 merge orderからのhardening deviation | `unknown_opcode_drops_before_merge_without_mutating_cache_or_pending` | deviation | unsupported opcodeはprofile validationで先にdropし、MAC/TTL/pending/bytesを変更しない |
| ARP-019 local Request/Probe/SHA authority | RFC 826, RFC 5227 | `local_request_learns_sha_even_when_ethernet_source_differs_and_probe_does_not` | implemented | Requestはlearn後reply、Probeはno-learn、Ethernet source≠SHAでもSHAを採用 |
| ARP-020 invalid sender hardware security drop | RFC 1812 §3.3.2, local zero policy | `invalid_sender_hardware_drops_atomically_without_cache_or_action_mutation` | implemented | zero/broadcast/multicast SHAはbyte/cache/action atomic drop |
| ARP-021 non-host sender protocol no-learn | RFC 1122 §3.2.1.3, local safety policy | `non_host_sender_protocol_addresses_are_consumed_without_learning` | implemented | nonzero `0/8`、`127/8`、multicast、`240/4`、limited broadcast、connected network/directed broadcast SPAはconsume/no-learn、cache/action不変 |
| ARP-021A point-to-point endpoint learning | RFC 3021, host-route semantics | `point_to_point_prefix_endpoints_are_learnable` | implemented | `/31`と`/32`はnetwork/broadcast addressとして除外しない |
| ARP-021B local SPA claim is ingress scoped | RFC 5227 link scope | `local_address_value_on_another_interface_is_learnable_on_ingress` | implemented | 別IfIdのlocal IPv4値と同じSPAはingress上のpeerとして学習可能 |
| ARP-022 static authority over dynamic | local authority policy | `foreign_local_spa_cannot_poison_and_static_mapping_has_priority` | deviation | staticはARPで上書き/slot消費せず常にforward優先し、同keyのstale dynamic/pendingを削除 |
| ARP-022A static snapshot reconciliation | control-plane publication contract | `reconcile_static_clears_stale_cache_and_wrapped_middle_action_fifo` | implemented | snapshot公開と同worker tickでdynamic/active state/actionを削除し、commit済みcooldownとwrapped ringのFIFO/IfId独立性を保持 |
| ARP-022B full publication retry authority | control-plane publication contract | `publication_reconciliation_removes_static_and_invalid_authority_only` | implemented | timer/packet前にsnapshotをreconcileし、static解決またはMAC/binding/route/target authorityがstaleなactive state/actionだけを削除。cooldownはsource actionを持たない |
| ARP-023 cache-full disposition/pending preservation | architecture contract | `ttl_boundary_refresh_expired_reuse_and_cache_full_are_exact` | implemented | live entry非evict、Reply consume、matching pending actionをclearしない |
| ARP-024 unified monotonic watermark | architecture contract | `clock_regression_does_not_mutate_cache_and_later_equal_time_recovers` | implemented | regressionはcache/action不変、後続normal nowで回復 |
| ARP-025 learned mapping cancels matching resolution | architecture contract | `reply_before_generated_execution_cancels_only_matching_fifo_action` | implemented | matching active action/stateだけcancel、committed cooldownとunrelated key/IfId FIFOを維持 |
| ARP-026 same-batch sequential visibility | architecture contract | `mixed_reply_then_ipv4_uses_dynamic_mapping_in_same_batch` | implemented | `[Reply, IPv4]`の2packet目が直前のdynamic mergeを利用 |
| ARP-027 zero capacity/recreate safety | architecture contract | `zero_capacity_and_runtime_recreation_are_safe` | implemented | zero容量panicなし、constructorでcacheをemptyへ初期化 |
| ARP-028 unresolved datagram hold/replay | RFC 1122 §2.3.2.2, RFC 1812 §3.3.2 | `direct_timeout_after_accepted_arp_generates_exact_type3_code1` | deviation | packet bufferは即recycleし成功時replayなし。first eligibleのbounded quote-only candidateでterminal Code 1だけ生成 |
| OBS-001 stable reason code | explainability requirement | `drop_reason_discriminants_and_codes_are_stable_and_unique` | implemented | repr(u16) |
| OBS-002 requestedとaggregate TX outcome trace | explainability requirement | `partial_backend_completion_preserves_report_and_aggregate_trace` | implemented | packet単位accepted traceはdeferred |
| OBS-003 protocol-aware ARP trace ordering | explainability requirement | `arp_trace_is_deterministic_and_tx_follows_commit` | implemented | validated/reply requested/TX requested/completionを順序検証 |
| SIM-001 FIFO/budget/mixed batch | deterministic test requirement | `mixed_batch_is_fifo_budgeted_and_reports_requested_accepted_recycled` | implemented | なし |
| SIM-002 mixed IPv4/ARP FIFO and budget | deterministic test requirement | `mixed_ipv4_and_arp_batch_is_fifo_budgeted_and_deterministic` | implemented | protocol混在でもsequenceとbudgetを保持 |
| SIM-003 mixed RX/generated FIFO and typed origin | deterministic test requirement | `mixed_rx_and_generated_tx_are_fifo_budgeted_and_origin_typed` | implemented | RX batch finish後に生成しoriginを型で区別 |
| NAT44-001 opt-in single-domain UDP NAPT | RFC 3022 §§2–4, architecture contract | `exact_bidirectional_wire_and_same_batch_visibility` | implemented | one inside/outside/public IPv4。既存forwarding wrapperはNATなしの挙動を維持 |
| NAT44-002 Endpoint-Independent Mapping | RFC 4787 REQ-1 | `eim_reuses_public_tuple_and_adf_keys_only_remote_address` | implemented | keyはinside/internal IPv4/internal UDP port。remote endpointを含めない |
| NAT44-003 Address-Dependent Filtering | RFC 4787 filtering taxonomy, local profile | `eim_reuses_public_tuple_and_adf_keys_only_remote_address` | implemented | contacted remote IPv4だけ許可しremote portは任意。unknown IPはbyte不変drop |
| NAT44-004 unique deterministic public port | RFC 4787 REQ-3, local bounded allocator | `allocator_preserves_then_falls_back_without_overload_and_exhausts` | implemented | internal portを可能なら保存し、seeded startからpoolを一周。overload/live evictionなし |
| NAT44-005 fixed caller-backed state/generation | architecture contract | `full_tables_do_not_evict_or_refresh_live_state_and_zero_capacity_is_safe` | implemented | mapping/peer zero/full safe、generationでstale peerを無効化、`!Send + !Sync` |
| NAT44-006 idle timer and refresh direction | RFC 4787 REQ-5/REQ-6, RFC 7857 §§7–7.1 | `exact_idle_expiry_outbound_refresh_and_inbound_no_refresh` | implemented | default 300s/minimum 120s、exact expiry。outbound TX requestだけrefreshし、inboundはrefreshしない |
| NAT44-007 monotonic clock atomicity | architecture contract | `failed_lookup_and_capacity_operations_advance_the_watermark` | implemented | non-regressed operationはdropでもwatermarkを進める。regressionはcounter/trace以外を変更せずequal timeで回復 |
| NAT44-008 atomic IPv4-only profile | RFC 6864 §§4.1–4.2 | `structural_and_policy_failures_are_byte_and_state_atomic` | deviation | DF=1/MF=0/offset=0だけ変換。DF=0を含むfragment-capable datagramはtyped drop |
| NAT44-009 UDP length and padding | RFC 768 | `checksum_zero_invalid_nonzero_and_odd_or_padded_udp_are_algebraic` | implemented | UDP length 8..=IPv4 payload。UDP後のIP/link paddingを保存 |
| NAT44-010 incremental address/port checksum | RFC 1624 §4, RFC 768 | `checksum_zero_invalid_nonzero_and_odd_or_padded_udp_are_algebraic` | implemented | UDP zeroを保存。nonzeroはaddress/port更新、negative zeroを`0xffff` encode |
| NAT44-011 original route/neighbor before state | RFC 1812 §§5.2.4–5.2.7, architecture contract | `route_ttl_neighbor_and_reverse_authority_fail_before_nat_state` | implemented | route/TTL/egress/static-or-dynamic neighbor失敗でmapping/peerなし |
| NAT44-012 internal source authority | RFC 1812 §5.3.7, local anti-spoof policy | `route_ttl_neighbor_and_reverse_authority_fail_before_nat_state` | implemented | non-host/local/public sourceを拒否しsource reverse-LPMはinside必須 |
| NAT44-013 inbound intercept before local | RFC 3022 translation direction | `exact_bidirectional_wire_and_same_batch_visibility` | implemented | outside/public UDPをordinary local consumeより先にmapping/ADFへ渡す |
| NAT44-014 transactional rewrite/state/TX request | architecture contract | `backend_reject_keeps_tx_request_mapping_and_filter_state` | implemented | full plan後bytes→state→lease commit。backend rejectでもTX-request stateを保持 |
| NAT44-015 publication mismatch and flush | control-plane publication contract | `absent_runtime_and_stale_snapshot_authority_fail_closed` | implemented | runtime absent/mismatchはfail closed。`reconcile`は全mapping/peerをflush |
| NAT44-016 malformed/unsupported fail closed | RFC 768, local security boundary | `malformed_udp_options_and_unsupported_transport_never_create_state` | implemented | truncated/invalid length/options/unsupported protocol crossingでprivate sourceを漏らさずstateなし。非TCP/UDPはNAT state/trace/watermark不変 |
| NAT44-017 hairpinning | RFC 4787 REQ-9 | `structural_and_policy_failures_are_byte_and_state_atomic` | deferred | inside→own publicはWANへ漏らさずtyped drop。hairpin translation未実装 |
| NAT44-018 fragment translation | RFC 3022 §6.3, RFC 4787 REQ-14 | `structural_and_policy_failures_are_byte_and_state_atomic` | deferred | fragment association/reassembly未実装。atomic DF=1だけの初期profile |
| NAT44-019 external Fragmentation Needed tuple translation | RFC 5508 REQ-4, RFC 1191, RFC 3022 §4.3 | `udp_frag_needed_translates_cascade_and_keeps_nat_state_read_only` | implemented | policy opt-inのoutside/public Type 3/Code 4だけouter destinationと引用UDP/TCP source tupleをinsideへ戻しtype/codeを保存 |
| NAT44-019A ICMP error payload validation | RFC 5508 REQ-3(a-c) | `malformed_candidate_matrix_has_stable_atomic_reasons` | implemented | outer ICMPと引用IPv4 checksumを検証しoptions IHLを使用。embedded transport checksumは検証しない |
| NAT44-019B read-only ICMP NAT session | RFC 5508 REQ-6 safety objective generalized by local policy, architecture contract | `backend_reject_and_clock_regression_leave_icmp_lookup_state_unchanged` | implemented | REQ-6が直接対象にするICMP Query/responseに加え、UDP/TCP引用でもlookup成功/drop/backend reject時にmapping/peer/session/last time/counter/watermarkを変更しないlocal generalization |
| NAT44-019C bounded quoted transport checksum rewrite | RFC 1624 §4, local bounded profile | `tcp_quote_boundaries_and_exact_session_authority_are_enforced` | implemented | UDP zero/negative-zero、TCP 8..16/17/18境界を区別し引用Total Length内だけを更新 |
| NAT44-019D opaque trailing bytes boundary | local safe boundary; RFC 5508 REQ-3(d)/RFC 4884 full parsing tracked by NAT44-019N | `tcp_total_length_prevents_opaque_trailing_bytes_from_becoming_a_checksum` | implemented | local safe boundaryのみ実装。引用Total Length外をtransport checksumと誤認しないだけで、REQ-3(d)のRFC 4884 object検出・解析を直接実装したものではない |
| NAT44-019E external source admission and preservation | RFC 5508 REQ-4, RFC 1812 §5.3.8, local strict-uRPF policy | `outer_source_admission_rejects_non_hosts_local_and_inside_routes_atomically` | implemented | host-unicastかつreverse outsideだけ許可するためasymmetric external pathを意図的に拒否し、中継sourceは引用remoteと不一致でもouter sourceを保存 |
| NAT44-019F protocol-side opt-in and padding bound | architecture compatibility contract | `mixed_protocol_policies_and_padding_peek_preserve_legacy_local_handling` | implemented | 引用protocol側policyだけがinterceptしType/Code peekをouter Total Length内に限定 |
| NAT44-019G Next-Hop MTU pass-through | RFC 1191 §§3–4, RFC 5508 §7.1.2 | `same_batch_combined_dispatches_same_public_port_and_preserves_all_mtu_values` | implemented | unused+MTU 32 bitsを解釈せず保存しMTU 0/68/1500/65535を同等に扱う |
| NAT44-019H private-to-external ICMP error translation | RFC 5508 REQ-5 | — | deferred | ExternalOnly profileの逆方向は未実装 |
| NAT44-019I hairpin ICMP error traversal | RFC 5508 REQ-7 | — | deferred | hairpin NAT自体とouter/引用の二重変換を未実装 |
| NAT44-019J other ICMP error type/code translation | RFC 5508 REQ-3/4 | — | deferred | Type 3/Code 4以外はlegacy local control path |
| NAT44-019K local Packet Too Big generation | RFC 1191 §4, RFC 5508 §7.1.1 | — | deferred | local egress MTU判定とType 3/Code 4生成を未実装 |
| NAT44-019L DF-zero fragmentation | RFC 5508 §7.1.1, RFC 1812 §5.2.7 | — | deferred | forwarding MTU超過時のIPv4 fragmentation未実装 |
| NAT44-019M PMTU cache and plateau fallback | RFC 1191 §§5–7 | — | deferred | received MTUによるcache更新、timer、MTU 0推定を未実装 |
| NAT44-019N RFC 4884 extension parsing | RFC 5508 REQ-3(d), RFC 4884 | — | deferred | optional paddingとextension objectを識別・変換するfull support未実装 |
| NAT44-020 other transports/features | RFC 3022, RFC 4787, RFC 7857 | — | deferred | ICMP query NAT、static forwards、multi-public、port randomization/parity、full packet filter/firewall |
| NAT44-021 external-to-internal bypass prevention | RFC 3022 traditional NAT domain boundary, local security policy | `outside_to_inside_lpm_bypass_is_always_fail_closed_before_neighbor_work` | implemented | authorized public UDP/TCP DNAT以外のoutside→inside LPMをprotocol/runtime/state非依存でneighbor処理前にgeneric drop |
| NAT44-022 outbound-initiated TCP EIM | RFC 3022 §§2–4, RFC 5382 §§4–5 | `syn_synack_and_data_translate_bidirectionally_in_one_batch` | implemented | internal TCP tuple mapping。新規sessionはoutbound initial SYNだけ。RFC 5382全体準拠は非主張 |
| NAT44-023 exact TCP endpoint filtering | RFC 5382 §5, RFC 7857 §4 | `eim_reuses_mapping_but_filter_is_exact_remote_endpoint` | deviation | remote IPv4+port完全一致のconnection-dependent filter。推奨EIF/ADFより厳しい |
| NAT44-024 fixed TCP mapping/session state | architecture contract | `tcp_zero_and_full_capacity_never_evict_live_state` | implemented | separate caller-backed mapping/session、generation、`!Send + !Sync`、live eviction/overloadなし |
| NAT44-025 conservative TCP idle lifetime | RFC 5382 §5, RFC 7857 §2.1 | `exact_idle_boundary_bidirectional_refresh_and_unmatched_no_refresh` | deviation | 全session単一default/minimum 2h4m。FIN/RST cleanupなし、successful bidirectional TX requestだけrefresh |
| NAT44-026 TCP header/full checksum admission | RFC 9293 §3.1, RFC 3022 §4.1 | `a_deliberately_valid_zero_tcp_checksum_field_is_accepted` | implemented | Data Offsetを検証しpseudo-header+IPv4 TCP payload全体をfull checksum。valid field zeroも受理 |
| NAT44-027 TCP incremental checksum zero semantics | RFC 1624 §4, RFC 9293 §3.1 | `incremental_tcp_checksum_keeps_mathematical_zero_on_wire` | implemented | address/portをincremental更新。UDP式zero preservation/`0xffff` normalizationなし |
| NAT44-028 TCP flag admission without phase claims | RFC 9293 §§3.1, 3.10.7 | `only_initial_syn_creates_and_fin_rst_only_refresh_idle_lifetime` | deviation | initial SYNだけstate作成。既存exact sessionの全valid flagsを変換するがsequence/window/ACK validationなし |
| NAT44-029 protocol-separated combined service | RFC 3022 traditional NAPT, architecture contract | `combined_udp_tcp_realms_keep_protocol_state_and_ports_independent` | implemented | UDP/TCPは同一数値public port可。single-protocol crossingとcombined realm mismatchはfail closed |
| NAT44-030 TCP fragment/hairpin/other ICMP | RFC 3022 §§4.3, 6.3, RFC 5382 §§6–9, RFC 6864 §§4.1–4.2 | `malformed_checksum_fragment_source_zero_and_options_are_atomic` | deferred | atomic DF=1のみ。hairpin、fragment association、Type 3/Code 4以外のembedded ICMP、full RFC 5382 sequence lifecycleは未実装 |

## RFC deviation rule

RFC準拠の挙動を意図的に変える変更は、この表に`deviation`としてRFC section、理由、
影響範囲、対応testを同じPRで記録します。未実装機能は準拠を主張せず`deferred`として
scopeを明示します。
