# 実装計画

状態: 2026-11-10。設計図（この directory の他の文書）を、今のコードを土台にして実現する順番。

## 方針

- 今のコードを土台に作り変える。作り直しはしない。I/O層とパケット処理（NAT、firewall、ICMP、
  フラグメント）は設計のFEとほぼ重なり、実績がある。
- 最初に「骨組み」を作る。sim上で、FE、confd、ribd、neighdがメッセージでつながり、IPv4が端から端まで
  転送できるところまで。設計の中心（メッセージ形式、表の版の差し替え、受け渡し、プロセスの分け方）を
  ここで確かめる。
- 機能は骨組みに一つずつ載せる。骨組みができる前に機能を足さない。
- 進め方はAGENTS.mdのとおり。1 PRは非テストで500行程度まで。mergeはCIとレビューの結果を見てagentが判断する。
- 実装は一つのagentが通しで行う。独立レビューを頼むのは、unsafe、メッセージ形式、表の版の差し替え、
  NAT/firewallの状態に触るPRだけ。

## 今のコードの行き先

| 今のコード | 行き先 |
|---|---|
| `ruster-core`のパケット処理（`forwarding`、`nat44*`、`firewall*`、`icmpv4_error`、`ipv4_fragment*`など） | FE。そのまま使う |
| `ruster-core`のARP（`resolution.rs`、`resolution/announce.rs`、`arp_hold.rs`と、`forwarding.rs`内の学習、待たせ、再送） | neighdへ移す。FEには静的な近隣の表と解決依頼だけを残す |
| `ruster-core`の`io.rs`、`generated.rs` | FE。`PublicationQuiescence`は版の差し替え方が変わるので外す |
| `ruster-runtime` | FE。ARPの段階を外し、仕事と実行役の形へ |
| `ruster-control`の`activation.rs`、`publication.rs` | FE。設定全体からではなく、メッセージから表の版を作る形へ |
| `ruster-control`の`plan.rs`、`config_bridge.rs`と、`ruster-config` | confd |
| `ruster-config`の直結経路と静的経路の組み立て | ribd |
| `ruster-cli`の`run/`のうち起動、権限、seccomp、Landlock、systemd通知など | FEの実行ファイル |
| `ruster-cli`の`run/reload.rs`、`config_cmd.rs`、`plan_text.rs` | confdとCLI（制御のsocketに置き換わる） |
| `ruster-io-*` | FEのI/O層。そのまま使う |
| `ruster-io-sim`、`ruster-io-conformance`、`ruster-sim-scenario` | 試験の土台。`sim-scenario`の`apply`はメッセージに置き換える |
| `ruster-bench`の`hardware_protocol`、`hardware_artifact`、`hardware_plan`（約5,900行） | 削除候補（性能は北極星に入れないため） |

## 段階

### 段階0: 片付け（動作は変えない）

1. READMEを200行以内に縮める（済み）。
2. 見直し前の計画と運用の文書（`architecture-v0.2.md`、`development-plan-v0.2.md`、`runbook-m2.md`、
   `release-evidence/`）を削除する（済み）。進み具合はこの文書の一か所に書く。
3. `ruster-bench`のhardware benchmark一式を削除する（済み）。
4. 要件ID台帳（`requirements-v0.2.md`、842 ID）と`check-requirements.sh`を削除する（済み）。試験の名前と設計図で足りるようにする。

### 段階1: 骨組み

| 順 | PR | 中身 |
|---|---|---|
| 1-1 | CBOR | 使う範囲（整数、バイト列、文字列、配列、マップ、null、真偽値）の読み書き。新しいcrate `ruster-proto` |
| 1-2 | CoAPの枠組み | RFC 8323の枠組みの読み書き。最大メッセージ長の交換 |
| 1-3 | SIDと`.sid`ファイル | 最初の四つの表（`ietf-interfaces`、`ietf-ip`、`ruster-fib`、`ruster-neighbor`）のSIDと、`.sid`ファイルとの突き合わせの試験 |
| 1-4 | 表の版 | iPATCHの中身を、今の`Interface`、`LocalIpv4Binding`、`Route`、`Neighbor`へ変換し、表の版を作る。参照先が無いエントリは無効として持つ |
| 1-5 | 仕事と実行役 | `進める(時刻)`の形と実行役。workerを最初の仕事にする |
| 1-6 | FEの制御の口 | Unix socketでiPATCH、FETCH、PUT、resyncを受け、版を差し替える。差し替えで送信の完了を待たないようにする |
| 1-7 | 受け渡し | 受け渡しの役割、SOCK_SEQPACKETの固定ヘッダ、近隣の解決依頼の通知 |
| 1-8 | neighd（ARPだけ） | 解決依頼を受けてARP Requestを送り、応答を近隣の表へ書く。ルータのアドレスへのARPに応答する |
| 1-9 | ribd（静的と直結だけ） | 送り手からの経路の受け取り、選択、FIBへの書き込み、「送り終わった」 |
| 1-10 | confd（インターフェースとアドレスだけ） | 今のTOMLの読み込みをそのまま入力に使う（人が書く書き方は後で決める）。静的経路をribdへ渡す |
| 1-11 | 端から端までの試験 | 全プロセスを一つの実行役に載せ、socketpairでつないでsim上でIPv4を転送する。CEの再起動とFEの表の保持も確かめる |

#### 段階1の結果（2026-11-06）

全部merge済み（#359、#362〜#370）。`crates/e2e/tests/skeleton.rs`で、FE、confd、ribd、neighdが
Unix socketのメッセージでつながり、IPv4が両方向に転送され、各CEプロセス（と三つ同時）を止めて
起動し直しても転送が止まらないことを確かめている。

計画から変えた点:

- 受け渡しはSOCK_SEQPACKETではなくUnix datagram。インターフェースは番号でなく名前で示す。
- 標準モジュールの項目のSIDも、`.sid`ファイルが公開されていないので当面はローカルの番号。
- ARPはcoreのスイッチ（`with_arp_to_control`）でneighdへ渡している。coreからARPを消すのは段階2。
- neighdは再起動したときresyncせず、FEの近隣の表を引き継ぐ。
- 送り手の「送り終わった」は`POST c/sync-done`。

骨組みに入っていないもの:

- 学習した近隣の確かめ直しと期限切れ、FEやribdへの再接続、表の一部を共有する構造。

#### 実際のLinuxの上の骨組み（2026-11-07）

各プロセスは実行ファイルになった（`ruster-fe`、`ruster-ribd`、`ruster-neighd`、`ruster-confd`）。
FEはAF_PACKETの上で動き、confdはTOMLの設定ファイル（`crates/confd/src/file.rs`）を読む。
socketは`/run/ruster`の下の[`control-protocol.md`](control-protocol.md)の置き場所（`--run-dir`で変えられる）。
`sudo scripts/netns-skeleton.sh`が、netnsとvethでつないだ2台のホストの間をIPv4が両方向に
転送されることを確かめる。CIでは回していない。

- 起動の順番はFEが先。ほかのプロセスは相手のsocketができるまで10秒待つ。
- 接続が切れた書き手は1秒ごとにつなぎ直し、自分の表を全部送り直す（2-1）。netnsの試験で、
  ribd、neighd、confdを`kill -9`して起動し直しても転送が止まらないこと、FEを起動し直すと
  三つが表を埋め直すことを確かめている。
- FEは暇なとき1ms待つだけで回り続ける。待ち方はAF_XDPに替えるときに見直す。

### 段階2: 置き換え

骨組みが動いたら、今の作りを新しい作りに置き換える。

- `ruster run`を新しいFEの実行ファイルに替える（AF_XDP、AF_PACKET）。FEは設定ファイルを読まない。
- `ruster-core`からARPの処理を消す（neighdへ移した後）。
- SIGHUPでのTOMLの再読み込みを消す（confdへの反映に替わる）。

### 段階3以降: 機能

骨組みの上に[`tables.md`](tables.md)の表を一つずつ載せる。順番はagentが決める（AGENTS.md）。

#### できたもの（2026-11-10）

charterの「作るもの」は全部ある。項目ごとの、従う決まりと外している点（そのモジュールの`# Standards`。どのRFCの
どの節に沿うかはそこにだけ書く）と、確かめている試験は次の二つの表のとおり。試験は、RFCなどの決まりの
フィールドの並びから手で組んだ入力と、決まりの値から出した期待値を使う。

FEとCEの基本:

| 作るもの | `# Standards`のあるモジュール | 確かめている試験 |
|---|---|---|
| IPv4とIPv6の転送 | core `forwarding.rs`、`route.rs`、`ipv6.rs` | io-sim `acceptance`、`ipv4_property_model`、`ipv6`。netns `skeleton` |
| VRF | confd `file.rs` | io-sim `vrf`。netns `vrf`、`vrf-vlan`、`vrf-firewall` |
| VLAN | core `vlan.rs` | io-sim `vlan`。netns `vlan`、`vlan-nat`、`vrf-vlan` |
| NAT44 | core `nat44.rs`、`nat44_ipv4_id.rs`、fe `nat.rs` | io-sim `nat44_*`、`nat_frag`、`nat_services`。fe `fe.rs`。netns `nat`、`vlan-nat`、`pppoe-nat` |
| MAP-Eのポートの範囲 | core `port_set.rs`、confd `file.rs` | netns `map-e`、`map-e-pppoe`、`map-e-pd` |
| 状態を持つfirewall | core `firewall.rs`、`firewall6.rs` | io-sim `stateful_firewall`、`firewall_ipv6`。netns `firewall6`、`dslite-firewall6`、`vrf-firewall`、`nat` |
| フラグメント | core `ipv4_fragmentation.rs` | io-sim `ipv4_fragmentation*`、`nat_frag`。netns `vlan`、`nat`、`pppoe`、`pppoe-nat`、`dslite` |
| ICMPとICMPv6のエラー | core `icmpv4_error.rs`、`ipv6.rs` | io-sim `icmpv4_*`、`nat44_icmpv4_*`。netns `skeleton`、`vlan`、`vlan-nat` |
| トンネル（MAP-E、DS-Lite） | core `tunnel.rs` | io-sim `tunnel`。netns `dslite`、`dslite-firewall6`、`map-e`、`map-e-pppoe` |
| PPPoEの包み | core `pppoe.rs` | io-sim `pppoe`。netns `pppoe`、`pppoe-nat`、`map-e-pppoe` |
| ルータ宛て通信の分類、流量制限、TUN | fe `local.rs` | io-sim `local_to_control`、`kernel`。fe `fe.rs`。netns `skeleton`、`nat`、`pppoe` |
| confd、ribd、neighd | confd `file.rs`、ribd `lib.rs`、neighd `lib.rs`、`nd.rs` | 各crateの試験、e2e `skeleton`。netns `skeleton` |
| I/O層（AF_XDP、AF_PACKET、sim） | — | io-sim `backend_conformance`。netnsの全部を両方のbackendで |
| メッセージ形式 | proto `session.rs`、`table.rs` | proto の試験 |

ルータ箱としての組み立てと、L2、トンネル、SRv6（2026-11-10に足したもの）。試験の欄は、ファイルと、
決まりの値で確かめている主な試験と、その中身。

| 作るもの | `# Standards`のあるモジュールと、主な外している点 | 確かめている試験 | netns |
|---|---|---|---|
| L2のブリッジとIRB（IEEE 802.1Q。RFCではない） | core `bridge.rs`、confd `bridge.rs`。spanning treeは無い。VLANごとに一つのブリッジ | core `bridge.rs`の`learns_forwards_floods_and_filters`（学習、転送、フラッディング、来たポートへは返さない）、`entries_age`（既定300秒の境目）、`a_frame_from_an_address_restarts_its_ageing`、`multicast_is_flooded_and_never_learned`、`the_reserved_block_ends_at_0f`（01-80-C2-00-00-00〜0Fは中継しない）。fe `tests/bridge.rs`の9本（IRB、VLANのメンバー、移動とエージング、promiscuous、リンク）。confd `tests/bridge.rs`（エージングの範囲10〜1000000秒） | `bridge` |
| VXLAN | core `overlay.rs`、confd `vxlan.rs`。送り先は設定のVTEPだけ。IPv6でもUDPのchecksumは0にしない。外側をフラグメントしない | core `overlay.rs`の`vxlan_wraps_in_ipv4_with_checksum_zero_and_a_hashed_port`（ヘッダのバイト、Iフラグ、port 4789）、`vxlan_over_ipv6_has_a_udp_checksum`、`vxlan_reserved_bits_are_ignored_on_receipt`（Iフラグの無いものは捨てる）、`vxlan_vni_takes_all_24_bits`、`vxlan_source_ports_stay_in_the_dynamic_range`（49152〜65535）。fe `tests/vxlan.rs`（VTEPへのフラッディング、VTEPからのものを他のVTEPへ流さない）。confd `tests/vxlan.rs`（VNIの範囲） | `vxlan`（相手はLinuxのvxlan。外側IPv4とIPv6） |
| EtherIP | core `overlay.rs`、confd `etherip.rs`。受けたヘッダのreservedは見ない。フラグメントしない | core `overlay.rs`の`wraps_in_ipv4_with_df_and_a_checksum`、`wraps_in_ipv6`、`etherip_takes_version_3_only`（0〜15のうち3だけ）、`unwraps_from_the_remote_end_only`。fe `tests/etherip.rs`の2本 | `etherip`（相手もruster。外側IPv4とIPv6） |
| SRv6 | core `srv6.rs`、confd `srv6.rs`。SIDはdefault VRFだけ。SIDへのフラグメントは捨てる。HMACは見ない。外側をフラグメントしない | io-sim `srv6.rs`: End、End.X、End.DT4、End.DT6の手順（`segments_left_picks_the_segment_at_its_new_value`、`segments_left_one_above_last_entry_is_followed`、`the_hop_limit_is_checked_before_the_header`）、Parameter Problemのcodeとpointer（Segments Leftの43、前に拡張ヘッダがあるときの51、上位ヘッダの40、80、88、Segments Leftが残るEnd.DT4とEnd.DT6）、Time Exceeded。io-sim `srv6_encap.rs`: H.EncapsのSRHのバイト、H.Encaps.Red（`reduced_with_two_segments_lists_only_the_second`、一つならSRH無し）、包んで長すぎるときのPacket Too Big。fe `tests/srv6.rs`: DFの無いIPv4は切ってから包む、DFありはFragmentation Needed（MTU 1460）。confd `tests/srv6.rs` | `srv6`（相手はLinuxのseg6） |
| IS-ISとOSPFのTAP | fe `tap.rs`、confd `isis_ospf.rs`、frr `isis_ospf.rs`。default VRFだけ。broadcastとpoint-to-pointだけ。プロトコルはFRR | fe `tap.rs`の`the_ranges_end_where_the_standards_say`（LLCと長さの境目1500/0x0600、224.0.0.0/24、fe80::/10）。fe `tests/tap.rs`の4本。confd `tests/isis_ospf.rs`（NET、metric、cost、router IDの範囲）。frr `tests/conf.rs`の`isis_and_ospf_are_written_on_the_tap_devices`、`is_is_on_an_interface_without_ipv6_carries_ipv4_only_and_passive_forms_no_adjacency` | `isis`、`ospf`（v2とv3、point-to-pointとbroadcast） |
| 再帰の次の転送先 | ribd `resolve.rs`。結果をBGPへは返さない（FRRのzebraが持つ） | ribd `resolve.rs`の試験（最長一致、自分自身やその下の経路で解決しない、loop、深さ、VRF、`an_ipv6_next_hop_is_resolved_the_same_way`、`several_next_hops_of_the_match_are_all_kept_in_order`）。ribd `tests/ribd.rs`の`a_gateway_route_is_resolved_and_follows_the_routes_it_goes_through` | `bgp`（multihopの近隣） |
| 全体の設定（`ruster.toml`とlockの形） | config `lib.rs`、confd `file.rs`。lockはYANGのインスタンスではなくTOML。決まりは[`router-box.md`](router-box.md) | config `tests/lock.rs`（lockの形の読み戻し、全部のkeyが要る、別の版は断る）、`tests/resolve.rs`（既定値の埋め方）、`tests/secrets.rs` | 全部（`ruster apply`で設定を渡す） |
| 版、差分、confirm、候補の確認 | confd `apply.rs`、`diff.rs`、`part.rs`。confirmの期限は分。persist-idとcancel-commitは無い。FE、ribd、neighdは候補の確認に加わらない | confd `tests/apply.rs`（版、rollback、断られたら前へ戻す、期限内のconfirm、期限後のconfirmは5.03、confdの起動し直し）、`tests/versions.rs`、`tests/diff.rs`（POSIXの`diff -u`の範囲）、`tests/part.rs`（一つでも候補を断れば誰にも送らない）、`tests/refused.rs` | `commit` |
| Unboundの橋渡し役 | unbound `lib.rs`。DNSはUnboundが行う | unbound `tests/unbound.rs`（access-controlは聞くプレフィックスだけ、上流の順、断られたら元のファイルへ戻す） | `dns`、`dhcpc`、`pppoed` |
| Keaの橋渡し役とDHCPv4のリレー | kea `relay.rs`、`settings.rs`。giaddrが入っているものとoption 82が付いているものは捨てる。hopsの上限は4 | kea `tests/relay.rs`の`a_request_gets_giaddr_a_hop_and_the_circuit`（バイト単位。option 82はEndの直前）、`a_request_at_the_hops_threshold_is_relayed`、`requests_that_cannot_be_relayed_are_dropped`、`a_reply_goes_to_the_client_without_option_82`、`option_82_is_taken_out_of_a_reply_wherever_it_is`、`a_request_that_option_82_would_make_too_long_is_relayed_without_it`、`a_reply_is_broadcast_when_the_client_asks_or_has_no_address` | `dhcp` |
| DHCPv6のリレー | kea `relay6.rs`、`settings6.rs`。他のリレーからのRelay-forwardは捨てる（hop-countは常に0） | kea `tests/relay6.rs`の`a_client_message_is_relayed_with_the_link_and_the_client`（Relay-forwardの型12、hop-count、link-address、peer-address、Interface-Id、option 79）、`every_client_message_type_is_relayed_unchanged`、`a_relay_reply_goes_to_the_client`、`every_server_to_client_type_is_passed_to_the_client`、`a_relay_reply_for_another_link_or_broken_is_dropped` | `dhcp6` |
| FRRの橋渡し役（FPM、BGP、IS-IS、OSPF） | frr `fpm.rs`、`routes.rs`、`server.rs`、`conf.rs`、confd `bgp.rs`。FPMの枠はFRRの形でRFCではない。中はnetlinkの経路のメッセージ。main tableだけ。RTA_NH_IDは断る | frr `tests/fpm.rs`（FRR 10.5の実際のフレーム、`the_fpm_length_counts_its_own_four_bytes`、`attributes_are_aligned_to_four_bytes_and_unknown_ones_are_passed_over`、`ipv6_routes_with_rtnexthops_and_deletes`、`rtm_type_and_rta_table_take_linux_s_values`、`lengths_that_do_not_fit_are_refused`）、`tests/routes.rs`、`tests/server.rs`、`tests/conf.rs`（明示のpolicy）。confd `tests/bgp.rs`（AS 0、23456、4294967295は断る） | `bgp`、`isis`、`ospf` |
| PPPoEの制御: Discovery | pppoed `discovery.rs`。待ちは2秒から32秒まで倍に | pppoed `tests/discovery.rs`の`codes_and_tags_are_those_of_rfc_2516`、`hand_built_pado_gives_the_padr_byte_for_byte`（PADIからPADTまで手で組んだバイト列。Host-Uniq、AC-Cookie、Relay-Session-Idを返す）、PADIとPADRの送り直し、合わない申し出を捨てる | `pppoed`、`pppoe-nat` |
| PPPoEの制御: LCPと状態機械 | pppoed `fsm.rs`、`lcp.rs`、`session.rs`。PassiveとRestartの選択肢は無い | pppoed `tests/fsm.rs`の`every_cell_of_the_rfc_1661_transition_table`（遷移表の125の欄の動作と次の状態）、`limits_are_those_of_rfc_1661`（3秒、Max-Terminate 2、Max-Configure 10、Max-Failure 5）。`tests/lcp.rs`（MRU 1492、Magic-Numberのloopback、Echo、Protocol-Reject）。`tests/ppp.rs`の`protocol_numbers_and_codes_are_those_of_the_rfcs` | `pppoed`、`pppoe-nat` |
| PPPoEの制御: PAPとCHAP | pppoed `auth.rs`。PAPは10回まで | pppoed `tests/auth.rs`（PAPのRequestのバイト、CHAP MD5を固定の値と比べる、Success/Failureは最後のidだけ） | `pppoed`、`pppoe-nat` |
| PPPoEの制御: IPCPとIPv6CP | pppoed `ipcp.rs`、`ipv6cp.rs`。VJの圧縮は断る | pppoed `tests/ncp.rs`（IP-Address、DNSの129と131をNakで埋める、Interface-Identifier、両方0なら断る）、`tests/writer.rs` | `pppoed`、`pppoe-nat` |
| DHCPv4のクライアント | dhcpc `client4.rs`、`dhcp4.rs`、`frame.rs`。ARPでの確かめとINIT-REBOOTは無い。overload（52）は読まない | dhcpc `tests/client4.rs`の`a_discover_follows_table_5`、`a_request_in_selecting_repeats_the_discovers_xid_and_secs`、`requests_in_requesting_are_sent_again_as_section_4_1_says`（4、8、16秒±1秒）、`renewing_and_rebinding_wait_half_the_time_left_but_at_least_60_s`、`t1_and_t2_from_the_server_are_used`（既定はリースの0.5と0.875）、`decline_and_release_follow_table_5`。`tests/dhcp4.rs`（オプションの形）、`tests/frame.rs` | `dhcpc` |
| DHCPv6のクライアント（プレフィックスの委任） | dhcpc `client6.rs`、`dhcp6.rs`、`values.rs`。最初のAdvertiseを待たずに取る。Confirm、Reconfigure、Rapid Commitは無い | dhcpc `tests/client6.rs`の`solicits_are_sent_again_as_section_15_says`、`the_first_solicits_rt_is_strictly_above_irt`、`requests_are_sent_again_with_req_timeout_and_req_max_rt`、`renews_and_rebinds_are_sent_again_with_their_timeouts`、`every_option_request_asks_for_sol_max_rt`、`a_sol_max_rt_option_becomes_solicits_mrt`、`the_ia_pd_asked_for_has_the_section_21_21_layout`、`zero_t1_and_t2_are_the_clients_to_choose`、`messages_without_the_right_identifiers_are_dropped`。confd `tests/delegated.rs`（委任からLANの/64、RA、MAP-EのCE） | `dhcpc`、`map-e-pd` |
| LANへのRA | neighd `ra.rs`、config `lib.rs`、confd `ra.rs`。RSへの答えは常にマルチキャスト。最後のRAは3秒おき | neighd `ra.rs`の`the_advertisement_has_every_field_and_option`（フレーム全部のバイト）、`unsolicited_ones_go_at_random_intervals_the_first_three_sooner`（最初の三つは16秒以内）、`solicitations_are_answered_soon_but_not_within_three_seconds`（0〜500ms、前のRAから3秒）、`the_rdnss_option_carries_every_server`（RDNSSの長さ）。neighd `tests/ra.rs`の3本。config `tests/ra.rs`（Minは0.33×Max）。confd `tests/ra.rs`（値の範囲） | `ra`、`dhcp6` |

試験で見つかり直した、決まりから外れていた点: DHCPv4のリレーが、option 82を足すとMTUを超えるときも足していた
（#775）。DHCPv4のクライアントのREQUESTの`secs`がDISCOVERと違った。DHCPv6のクライアントの最初のSolicitの待ちが
IRTちょうどになりえた。Option RequestにSOL_MAX_RTが無かった（#779）。

netnsの試験は29本で、全部をAF_XDPとAF_PACKETの両方で回す（`scripts/netns-all.sh`）。2026-11-10の結果:

29本×2のbackendの58回が全部通った（main 9aca396）。構成は`bgp`、`bridge`、`commit`、`dhcp`、`dhcp6`、`dhcpc`、`dns`、`dslite-firewall6`、`dslite`、`etherip`、`firewall6`、`isis`、`map-e-pd`、`map-e-pppoe`、`map-e`、`nat`、`ospf`、`pppoe-nat`、`pppoe`、`pppoed`、`ra`、`skeleton`、`srv6`、`vlan-nat`、`vlan`、`vrf-firewall`、`vrf-vlan`、`vrf`、`vxlan`。

#### 残り

charterの「作るもの」は上の表のとおりそろい、2026-11-10 にownerが達成とみなした。下はcharterの外で、
使う場面が出たらownerがcharterに足してから作る。外から設定を入れるAPIの形も未決のまま置く。

- VRFごとのBGP。
- `ruster diff`に消えるNATセッションを出すことと、FE、ribd、neighdを候補の確認に加えること。
- ブリッジのMACの表をFEの状態のsocketで見せること（今は数をログに出すだけ）。
- FRRからFPMでSRv6の経路（`seg6local`と`seg6`のencap）を受けることと、SIDごとの数を見せること。
- `backlog`のissueに残したMediumとLow（試験の不足、数え方、説明の細かい点、作らないと決めて理由を書いた点）は、
  backlogのまま置き、使う場面が出たものから片付ける。

#### 経路や通信の数が増えたとき

FRRの橋渡し役は100万経路まで受ける。2026-11-10に測ると、FEは表が大きいと更新に時間がかかり、その間は
転送も止まっていた。2026-11-11までに次を直した。数字はsimの上、release build。

- 転送を止めない: 表の接続と表の版の作成を、転送と別のthreadで行う（#787、#788、#790）。128,000経路を
  入れている間のworkerの一回りの最長は133msから0.33ms。CEへの応答は、workerが新しい版を使い始めてから返す。
- FEが経路1本の変更にかける時間: 表の検証の2乗を消し（#784）、`Store`を写すのをやめ（#792）、探す表だけを
  読み（#793）、経路だけの変更は前の経路の一覧に変更分だけを当てる（#794）。

  | 経路の数 | 最初 | 今 |
  |---|---|---|
  | 32,000 | 365ms | 2.6ms |
  | 128,000 | 137ms（#784の後） | 13ms |
  | 512,000 | 測っていない | 53ms |

- ribdが経路1本の変更にかける時間: sourceの変更で触れた経路だけを見る（#795）。128,000経路で294msから
  0.2ms（経路数によらない）。gatewayだけで書かれた経路があるときは、今までどおり全部を見る。
- IPv6の経路と近隣を二分探索で引く（#785）。

FEに残っているのは経路数に比例する部分（lookup-vrfの展開のための写し、coreの表の検証と索引の作り直し）。
2026-11-11にBGPのフルルートの大きさで測ると、更新だけでなく転送も遅い。IPv4の/24経路、宛先は全経路に
散らした乱数、release build。

| 経路の数 | 検索1回 | 経路1本の変更（FE） | 全経路を1,000本ずつ入れる |
|---|---|---|---|
| 4,096 | 50ns | 測っていない | 測っていない |
| 131,072 | 193ns | 20ms | 1.8秒 |
| 1,048,576 | 494ns | 175ms | 86秒 |

検索が遅いのは、二分探索が20段になり、索引（29MB）がCPUのキャッシュに載らないため。検索だけで1コア
毎秒200万パケットが上限になる。測り方は`lookup_timing_up_to_a_full_table`（core）と
`build_timing_up_to_a_full_table`（fe）。

そこで、経路の表を設計図の「前の版と一部を共有する木」に替える（2026-11-11 owner決定）。順番は次のとおり。

1. IPv4の木をcoreに足す（まだ転送には使わない）。形は、候補を測って決める。長さごとのハッシュも比べる。
2. 転送の検索を木に替える。
3. 変更した道筋だけを作り直し、残りは前の版と共有する。検証も変更分だけにする。
4. IPv6も同じ形にする。
5. FEに残る、経路数に比例する部分を変更分だけにする。

その後の残り。どれも大きいので、始める前に分け方をownerに見せる。

1. workerを複数にする（NATやfirewallの状態の持ち主を決める仕組み。パケットのleaseが`Rc`である点は
   「気をつけること」のとおり）。今はNICのqueue 0だけを使い、コアを足しても速くならない。
2. NATとfirewallの状態の数（今は定数。NATの対応8,192、TCPセッションとfirewallの状態は各16,384）を
   起動時の引数にする。

測って効くと分かるまで触らないもの: workerが一回りごとにメモリを確保していること（パケットの無い一回りは
約1.4µs）、転送そのものの速さ（`ruster-bench`で素のIPv4が1パケット約350ns）。

組み立ての作りは[`router-box.md`](router-box.md)、L2とトンネルとSRv6の作りは[`overlay.md`](overlay.md)にある。
BGP EVPNは見送り（2026-11-10 owner決定）。

今は作らないもの（2026-11-08 owner決定）: マルチキャスト（MLDを含む）、ルータのlink-localへのND以外の通信
（IS-ISとOSPFがTAPで受けるものを除く）。
外れている点として、それぞれのモジュールの`# Standards`に書く。

## 気をつけること

- 今のパケットのleaseは`Rc`で`Send`できない。workerごとのqueueには問題ないが、workerの間でbufferを
  移すことはできない。複数workerの段階で、コピーで渡すか、I/O層を変えるかを決める。
- `forwarding.rs`には約20個の`forward_batch_with_*`の入口がある。ARPを外すときに一つにまとめる。
- ARPは、待たせたパケットを通じてフラグメントやNATの状態とも絡んでいる。外す順番を間違えると
  転送が壊れるので、段階2で外す前に試験を揃える。
- 設計図と食い違う実装上の事情が出たら、コードを合わせるのではなく、まず設計図を直してownerに確認する。
