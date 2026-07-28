# v0.2 requirement and RFC ledger

Statusは`implemented`、`deferred`、`deviation`のいずれかです。test名はそのまま
`cargo test`のfilterとして利用できます。

| Requirement ID | 根拠 | Test ID | Status | deviation / note |
|---|---|---|---|---|
| IO-001 borrowed GAT batch/core RAII completion | architecture contract | `unfinished_core_lease_is_backend_lifecycle_recycle` | implemented | leaseは!Send/!Sync |
| IO-002 RX bufferをcloneせずTXへmove | architecture contract | `gateway_route_rewrites_and_reports_backend_acceptance` | implemented | allocation addressも検証 |
| IO-003 requested/accepted/recycled accounting | architecture contract | `mixed_batch_is_fifo_budgeted_and_reports_requested_accepted_recycled` | implemented | backend finishで確定 |
| IO-004 partial/error completion preserves report | architecture contract | `partial_backend_completion_preserves_report_and_aggregate_trace` | implemented | rejected slotはbackend所有で解放 |
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
| OBS-001 stable reason code | explainability requirement | `drop_reason_discriminants_and_codes_are_stable_and_unique` | implemented | repr(u16) |
| OBS-002 requestedとaggregate TX outcome trace | explainability requirement | `partial_backend_completion_preserves_report_and_aggregate_trace` | implemented | packet単位accepted traceはdeferred |
| SIM-001 FIFO/budget/mixed batch | deterministic test requirement | `mixed_batch_is_fifo_budgeted_and_reports_requested_accepted_recycled` | implemented | なし |

## RFC deviation rule

RFC準拠の挙動を意図的に変える変更は、この表に`deviation`としてRFC section、理由、
影響範囲、対応testを同じPRで記録します。未実装機能は準拠を主張せず`deferred`として
scopeを明示します。
