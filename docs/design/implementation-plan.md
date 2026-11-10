# 実装計画

状態: 2026-11-06。設計図（この directory の他の文書）を、今のコードを土台にして実現する順番。

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

#### できたもの（2026-11-09）

charterの「作るもの」は全部ある。項目ごとの、従う決まりと外している点（そのモジュールの`# Standards`）と、
確かめている試験は次のとおり。netnsの試験は14本で、どれもAF_XDPとAF_PACKETの両方で通る
（`scripts/netns-all.sh`）。

| 作るもの | `# Standards`のあるモジュール | 確かめている試験 |
|---|---|---|
| IPv4とIPv6の転送 | core `forwarding.rs`、`route.rs`、`ipv6.rs` | io-sim `acceptance`、`ipv4_property_model`、`ipv6`。netns `skeleton` |
| VRF | confd `file.rs` | io-sim `vrf`。netns `vrf`、`vrf-vlan`、`vrf-firewall` |
| VLAN | core `vlan.rs` | io-sim `vlan`。netns `vlan`、`vlan-nat`、`vrf-vlan` |
| NAT44 | core `nat44.rs`、`nat44_ipv4_id.rs`、fe `nat.rs` | io-sim `nat44_*`、`nat_frag`、`nat_services`。fe `fe.rs`。netns `nat`、`vlan-nat`、`pppoe-nat` |
| MAP-Eのポートの範囲 | core `port_set.rs`、confd `file.rs` | netns `map-e`、`map-e-pppoe` |
| 状態を持つfirewall | core `firewall.rs`、`firewall6.rs` | io-sim `stateful_firewall`、`firewall_ipv6`。netns `firewall6`、`dslite-firewall6`、`vrf-firewall`、`nat` |
| フラグメント | core `ipv4_fragmentation.rs` | io-sim `ipv4_fragmentation*`、`nat_frag`。netns `vlan`、`nat`、`pppoe`、`pppoe-nat`、`dslite` |
| ICMPとICMPv6のエラー | core `icmpv4_error.rs`、`ipv6.rs` | io-sim `icmpv4_*`、`nat44_icmpv4_*`。netns `skeleton`、`vlan`、`vlan-nat` |
| トンネル（MAP-E、DS-Lite） | core `tunnel.rs` | io-sim `tunnel`。netns `dslite`、`dslite-firewall6`、`map-e`、`map-e-pppoe` |
| PPPoEの包み | core `pppoe.rs` | io-sim `pppoe`。netns `pppoe`、`pppoe-nat`、`map-e-pppoe` |
| ルータ宛て通信の分類、流量制限、TUN | fe `local.rs` | io-sim `local_to_control`、`kernel`。fe `fe.rs`。netns `skeleton`、`nat`、`pppoe` |
| confd、ribd、neighd | confd `file.rs`、ribd `lib.rs`、neighd `lib.rs`、`nd.rs` | 各crateの試験、e2e `skeleton`。netns `skeleton` |
| I/O層（AF_XDP、AF_PACKET、sim） | — | io-sim `backend_conformance`。netnsの全部を両方のbackendで |
| メッセージ形式 | proto `session.rs`、`table.rs` | proto の試験 |
| 設定を確かめて反映するCLI | — | confd `apply`。netns `skeleton`（`ruster apply`） |

#### 残り

charterの「作るもの」は上の表のとおりそろい、2026-11-09 にownerが達成とみなした。`backlog`のissueに
残したMediumとLow（試験の不足、数え方、説明の細かい点、作らないと決めて理由を書いた点）は、
backlogのまま置き、使う場面が出たものから片付ける。

次はルータ箱としての組み立て（2026-11-10 charterに追加）。順番は[`router-box.md`](router-box.md)の
「作る順番」に従う。lockの形（版1）、confdが各プロセスへ担当の部分を渡すsocket（モジュールごとの`confd/part/<モジュール>/part.sock`）、
Unboundの橋渡し役（`ruster-unbound`、netns `dns`）と、Keaの橋渡し役とDHCPv4のリレー（`ruster-kea`、
netns `dhcp`）、neighdのRA（`[[ra]]`、netns `ra`）、DHCPv6のリレー（`[[dhcp6]]`、netns `dhcp6`）まで済んだ。
FRRの橋渡し役（`[bgp]`、`ruster-frr`、netns `bgp`）も済んだ。ribdが直結していない次の転送先を
自分の経路で解決するので、multihopの近隣も使える。VRFごとのBGPはまだ。confdは受け取った設定を番号付きの版として`--state-dir`に残し（`ruster versions`、`ruster rollback N`）、
`ruster diff`でlockの形、confdが書くFEの表、ribdへ渡す経路の差分を出す。`ruster apply --confirm-within M`は、
M分以内に`ruster confirm`が無ければ（confdが起動し直しても）前の版に戻す。各プロセスに差分を聞くのと、
候補と確定を分けるのはまだ。

`ruster-dhcpc`（「作る順番」の4）は、WAN側のDHCPv4とDHCPv6（プレフィックスの委任）のクライアント。設定は
confdの`dhcpc`の部分（`[[dhcp-client]]`）から受け取り、得た値は送り手（種類`dhcp-client`、`dhcpv6-client`）
としてconfdへ、default経路はribdへ（送り手`dhcpc`）書く。confdは、インターフェースの`ipv4-from`でWANの
IPv4アドレスを、`ipv6-from`で委任からLANの/64とRAのプレフィックスを、`[map-e]`の`prefix-from`で
委任からMAP-EのCEを作り、`[dns]`の`upstream-from`で送り手のDNSサーバをUnboundへ添える（netns `dhcpc`、
`map-e-pd`）。IPv6のdefault経路はDHCPv6の返事の送り元へ向ける（WAN側のRAは読まない）。

`ruster-pppoed`（「作る順番」の6）は、Discovery、LCP、PAPとCHAP、IPCP、IPv6CPでセッションを張る。設定は
confdの`pppoe`の部分（`[[pppoe]]`）から受け取り、得た値は送り手（種類`pppoe`）としてconfdへ、`default-route`の
ときはdefault経路をribdへ（送り手`pppoed`）書く。confdはその値から、セッションのある間だけFEにセッションの
インターフェースを置き、親のPPPoEのフレームを`pppoed`へ受け渡す行を書く（netns `pppoed`、`pppoe-nat`）。
`pppoe`と`map-e-pppoe`は、FEの転送を見るために固定のセッションを`ruster source`で渡している。IPCPで
得たDNSサーバも送り手へ書き、`upstream-from`でUnboundへ渡る。

今は作らないもの（2026-11-08 owner決定）: マルチキャスト（MLDを含む）、ルータのlink-localへのND以外の通信。
外れている点として、それぞれのモジュールの`# Standards`に書く。

## 気をつけること

- 今のパケットのleaseは`Rc`で`Send`できない。workerごとのqueueには問題ないが、workerの間でbufferを
  移すことはできない。複数workerの段階で、コピーで渡すか、I/O層を変えるかを決める。
- `forwarding.rs`には約20個の`forward_batch_with_*`の入口がある。ARPを外すときに一つにまとめる。
- ARPは、待たせたパケットを通じてフラグメントやNATの状態とも絡んでいる。外す順番を間違えると
  転送が壊れるので、段階2で外す前に試験を揃える。
- 設計図と食い違う実装上の事情が出たら、コードを合わせるのではなく、まず設計図を直してownerに確認する。
