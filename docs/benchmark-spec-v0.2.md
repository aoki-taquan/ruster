# Benchmark specification v0.2 (R17)

- spec ID: `ruster.benchmark-spec/v0.2`
- status: **APPROVED — owner承認済み（#282）**
- 対象: M1（sim smokeのみ）とM2（AF_XDP hardware gate）
- 対象外: M3 benchmark（1 queue baseline対全queue、state capacity直前flow、24時間soak）は
  M3着手前に別specとしてfreezeする

このdocumentはdevelopment plan R17の「結果取得前に数値をfreezeするbenchmark
specification」です。本文中の数値thresholdはimplementerが#282で提案し、M1 owner決定
「R17の数値thresholdはimplementerがPRで提案し、ownerがそのPRで承認する」に従って
ownerが承認しました。X05はこのspecの`spec_git_sha`に対してだけ測定し、thresholdを変更しません。

- 承認: 2026-11-01、ownerが#282の提案値を変更なしで承認（「ベンチマークは一旦ok」）。
  下の「owner決定」の全項目を含みます。

### 承認手順

v0.2は#282で次の手順により承認されました。以後のversionも、ownerが数値を承認（必要なら修正）
するPRで、同じcommit内に次をすべて行います。

1. status行を`- status: **APPROVED — owner承認済み（承認PR番号）**`へ変える。本文の変更は
   status、承認記録（承認日とowner決定の引用）、提案段階を示す表示の除去、ownerへの確認事項を
   owner決定へ置き換えることだけに限る。ownerが修正した値を除き、数値は変更しない。
2. repository rootで`sha256sum docs/benchmark-spec-v0.2.md > docs/benchmark-spec-v0.2.sha256`を
   実行してdigestを再生成する。
3. `crates/bench/tests/benchmark_spec.rs`のdraft marker testを`APPROVED`を要求するtestへ
   置き換える（v0.2では`benchmark_spec_v0_2_is_marked_approved_by_owner`）。
4. `docs/requirements-v0.2.md`のBENCH-009を`deferred`から実装済みの状態とtest IDへ更新する。

frozen specは、このPRが`main`へsquash mergeされたcommitです。そのcommit SHAを`spec_git_sha`、
そのcommitにおける`docs/benchmark-spec-v0.2.md`のbytesのSHA-256を`spec_sha256`とします。
以後の数値変更は新しいspec versionとして同じ手順を繰り返し、X05の結果PRで緩和しません。

## 既存hardware v1文書との関係

このspecはcase集合、測定手順、artifact形式を再定義しません。次の3文書とcodeをそのまま
参照し、その上に**gate選択とthreshold**の層だけを追加します。

| layer | 正本 | このspecが追加するもの |
|---|---|---|
| case集合 | [hardware benchmark plan v1](hardware-benchmark-plan-v1.md)、`hardware_plan_v1()`（237 case、fingerprint `f68c80b72065c023`） | 各caseのgate tier、offered load |
| 測定手順 | [hardware measurement protocol v1](hardware-measurement-protocol-v1.md)、`HardwareMeasurementProtocol` | warmup/duration/repeat/drain/latency profileの値 |
| 記録形式 | [hardware benchmark artifact v1](hardware-benchmark-artifact-v1.md)、`ruster.hardware-bench/v1` | summary fieldに対する合否式、baseline比較 |

- case IDはplan v1のcanonical ID
  `v1:{mode}:q{queue_count}:b{batch_size}:{frame}:f{flow_count}:{direction}:{service}:{transport}`
  をそのまま使います。このspecはcaseを追加・削除・改名しません。
- 名前の`v0.2`はruster project versionで、`v1`はhardware plan/protocol/artifactの
  schema versionです。plan/protocol/artifactのversionが変わる場合は、このspecも新versionとして
  再freezeします。
- protocol v1の`spec_git_sha`と`spec_sha256`は上の「承認手順」の定義に従います
  （`APPROVED` specが`main`へsquash mergeされたcommitと、そのspec bytesのSHA-256）。
  `spec_sha256`は[`benchmark-spec-v0.2.sha256`](benchmark-spec-v0.2.sha256)
  （`sha256sum -c`形式）に固定し、`.gitattributes`の`-text`でcheckout間のbytesを安定させます。
- plan v1/protocol v1/artifact v1の文書が「threshold、pass/fail非対象」と書いている点は
  変わりません。合否はこのspecとX05のevaluatorだけが扱います。

## M1で適用する範囲

M1では性能合否を判定しません。M1で必須なのは次だけです。

1. `.github/workflows/benchmark-smoke.yml`が`ruster-bench --suite smoke --format jsonl`を
   bounded timeoutで実行し、exit 0、1行以上、全行`"schema_version":1`、全行
   `"timed_allocations":0`を確認してJSONLをartifactとして保存する。ns/opやops/sの値は
   どのthresholdとも比較しない（CI host間で比較可能な値ではないため）。
2. 同workflowと通常testが、このspecのbytesとpin済みdigestの一致、およびこのspecのtier表・
   offered load表・case ID参照がplan v1と矛盾しないことを検証する。
3. M1 release evidence（S9）は、承認後のspec commit SHAと`spec_sha256`を記録する。

hardware、AF_XDP、traffic generator、baselineはM1の対象外です。

## M2 hardware gate

### Hardware前提

M2 minimum topologyは2 ports、各port 1 RX/TX queueです。これはtier `SC`のq1 caseが
評価します。ただしplan v1のcomplete runはexact 237 caseを要求し、そのうちq1は36 case
（single-queue 27、udp-zeroのzero-copy/q1/flow4096 9）で、237中201 caseが`q4`なので、X05のlabは**port当たり4 queue以上をsupportするNIC**を必要とします
（下の「owner決定」1）。

### Gate tier

全237 caseをcase fieldsから決定的に次の3 tierへ分けます（上から順に適用）。

| tier | rule | 意味 |
|---|---|---|
| `R` (report-only) | `mode=copy`、または`batch_size != 64` | 測定・記録のみ。性能合否なし。共通invariantは必須 |
| `SC` (single-core) | `queue_count = 1`、または`flow_count = 1` | 1 RX queue（RSSで1 queueへ集中するflow1を含む）の性能gate |
| `MQ` (multi-queue) | 上記以外 | 4 queueの性能gate |

class別の内訳です（testがplan v1から再計算して一致を検証します）。

<!-- r17:tier-table:begin -->
| class | tier | cases |
|---|---|---:|
| primary | MQ | 90 |
| flow-one | SC | 27 |
| flow64-imix | MQ | 9 |
| single-queue | SC | 27 |
| copy-mode | R | 27 |
| standalone-firewall | MQ | 18 |
| udp-zero | SC | 18 |
| udp-zero | MQ | 9 |
| udp-zero | R | 9 |
| batch-sweep | R | 3 |
<!-- r17:tier-table:end -->

合計はMQ 126、SC 72、R 39、全237です。M2 exit criteriaが要求する64/128/512/1500-byteと
IMIX、single-flowと複数flow、plain/NAT/NAT+FW、双方向は、MQのprimary（全frame、
flow4096）とSCのflow-one（flow1）で満たします。eth128とIMIXはplan v1上q4/flow≥64にしか
存在しないため、SCには含まれません。

rationale: copy modeはdriver依存のfallbackでM2では「観測できること」が要件のため
report-only。batch-sweepはb64を基準としたtuning情報でありgateはprimaryのb64で行う。

### Offered load

offeredは**active directionごと**のpackets/sで、10,000,000,000 bits/sに対するplan v1の
exact line-rate rational（L1 = FCS + preamble/SFD + IFG）に百分率を掛けて切り捨てた値です。
bidirectionalでは両directionへ同じ値を同時に与えます。R tierは同じframeのMQ値で送信します。

<!-- r17:offered-table:begin -->
| tier | frame | percent of 10GbE line rate | offered pps per direction |
|---|---|---:|---:|
| MQ | eth64 | 25 | 3720238 |
| MQ | eth128 | 50 | 4222972 |
| MQ | eth512 | 100 | 2349624 |
| MQ | ip-mtu1500 | 100 | 812743 |
| MQ | ruster-imix-v1 | 100 | 3526093 |
| SC | eth64 | 10 | 1488095 |
| SC | eth512 | 50 | 1174812 |
| SC | ip-mtu1500 | 100 | 812743 |
<!-- r17:offered-table:end -->

rationale:

- 「10GbE対応」はhousehold用途で支配的なMTU-size転送とmixed trafficで主張するため、
  ip-mtu1500とIMIXは4 queueで100% line rate、eth512も100%とする。
- eth64/eth128 line rate（14.88/8.45 Mpps）はsoftware router 1 hostの家庭用目標ではないため、
  主張対象外とし、pps処理能力の下限確認として25%/50%に置く。
- SCは1 core相当のため、1500-byteだけ100%（812,743 pps/direction）を維持し、eth512 50%、
  eth64 10%とする。M2 minimum topology（各port 1 queue）でも1500-byte 10GbEを満たすことを
  意味する。
- 参考値（gateの根拠ではない）: 開発VM（Xeon E5-2650 v4）のsim smoke（hot-cache、1 thread）で
  plain約5.9 Mops/s、NAT44+firewall約1.1 Mops/s（batch 32、64-byte）。MQ IMIX bidirectional
  NAT+FW（約7.05 Mpps合計）は4 workerでも余裕が小さいが、ownerは100%のまま承認した（owner決定2）。

### 合否式

MQ/SCの各caseは、protocol v1が導出したsummaryに対して次をすべて満たします。
`D`はactive direction数（outbound/inbound = 1、bidirectional = 2）、`O`は上表のoffered値です。

| metric | artifact field | threshold | rationale |
|---|---|---|---|
| maximum loss | `loss_ratio_worst` | binary64で`loss_ratio_worst <= 1e-5`（0.001%） | near-zero-loss基準。1500-byte 30秒で約2,438万packet中243以下。TCPのloss感度から、測定可能な最小の非zero許容値を置く |
| minimum accepted rate | `accepted_pps_median` | ≥ `D × O × 0.99999` | loss上限と同じ比率をrateへ写す。line-rate比はMQ/SC表のpercent × 0.99999 |
| p50 latency | `p50_latency_ns_worst` | ≤ 100,000 ns（100 µs） | batch 64のpoll遅延と2回のwire serializationを含めても十分小さく、household interactive trafficの数msの予算に影響しない |
| p99 latency | `p99_latency_ns_worst` | ≤ 1,000,000 ns（1 ms） | VoIP/game等の片道20 ms級予算の5%以下 |

latencyはround-trip profile（generator TX timestamp→DUT→generator RX timestamp、DUTを
通らないgenerator loopbackの値は別artifactとしてhash記録し、差し引かない）を使います。

全tier（Rを含む）で、protocol v1がすでにfail closedにするduplicate/unexpected/oracle failure
zeroに加え、次の共通invariantを要求します。

- 各repeatの`frame_health_before.total == frame_health_after.total`（schemaが既に検証）
- `invalid_descriptors = 0`、`double_owned = 0`（before/afterとも）
- caseのdrain後lifecycle `frame_health`で`rx_owned = core_borrowed = tx_owned = 0`

### Protocol parameters

| parameter | value | rationale |
|---|---|---|
| warmup | 10 s | ARP/NAT/FW stateとcacheの定常化。state確立はmeasurement外 |
| duration | 30 s | 1500-byteでもrepeat当たり2,400万packetを超え、0.001% lossを分解できる |
| repeat count | 3（odd） | protocol v1のmedian/worst導出に必要な最小odd数 |
| drain timeout | 5,000 ms | ring/completion drainに十分で、hangを早期に検出する |
| case timeout | 300,000 ms | `10 + 30×3 + 5 = 105 s`以上（protocol要件）に余裕を持たせる |
| run timeout | 71,100,000 ms（= case timeout × 237、約19.75 h） | protocol v1の下限そのもの |
| latency profile | round-trip、`sample_every_packets = 1024` | 1500-byteで1 repeat約23,800 sample、p99に十分 |

### Baseline regression

- baselineは、同じ`hardware_profile_id`、`generator_id`、`offload_profile_id`、
  `rss_profile_id`、`build_profile`で、このspecの全MQ/SC gateを満たした最初の完全run
  artifactです。その`source_git_sha`をbaseline SHAとして記録します。
- M2最初のX05 runはbaselineを確立するrunで、regression判定は適用しません（絶対thresholdは適用）。
- 以降のrunはMQ/SCの各caseで、同じcase IDのbaseline summaryに対して次を満たします。
  R tierには適用しません。

| metric | allowed regression | rationale |
|---|---|---|
| `accepted_pps_median` | regression判定なし（下の注記） | 絶対下限が常に支配する |
| `p50_latency_ns_worst` | ≤ max(baseline × 1.10, baseline + 5,000 ns) | 小さい値でのnoiseを絶対値5 µsで吸収 |
| `p99_latency_ns_worst` | ≤ max(baseline × 1.20, baseline + 20,000 ns) | tailはnoiseが大きいので20%または20 µs |
| `loss_ratio_worst` | 相対比較なし（絶対上限0.001%のみ） | zero近傍の比率比較は不安定 |

hardware profileが異なるrunはbaselineと比較せず、新しいbaselineの確立として扱います。

注記（owner決定6）: protocol v1はofferedを固定するため、baselineの
`accepted_pps_median`は`D × O`以下で、絶対下限`≥ D × O × 0.99999`を満たすrunは
`baseline × 0.95`も必ず満たします。したがってpps regression ruleは決して発火しない
no-opであり、このspecでは採用しません。throughput regressionを意味のある形で検出するには、
最大no-drop rateを探索する測定（RFC 2544 throughput型）か、artifactにcycles/packetや
CPU使用率を追加するprotocol/artifact v2が必要で、v1の範囲外です。v0.2のregression gateは
latencyだけです。

### Soak（M2）

- case: `v1:zero-copy:q4:b64:ruster-imix-v1:f4096:bidirectional:nat44-firewall:udp-checksum`
  の設定で、offeredは50%（1,763,046 pps/direction）。
- duration: 2時間（600秒window × 12）。protocol v1の237-case runとは別の連続runとし、
  artifact形式はX05で定義する（owner決定4）。
- 各window: binary64で`loss_ratio <= 1e-5`、`p99 ≤ 1 ms`。
- 全体: frame health totalが不変、`invalid_descriptors = double_owned = 0`、worker healthの
  last successful tickが1秒を超えて止まらない、window 1終了時からwindow 12終了時までの
  process RSS増加 ≤ 4 MiB、NAT/FW live state数がwindow 1終了時を超えて単調増加しない。
- rationale: M3の24時間soakより短い、M2の最初のleak検出。約2.5×10^10 packetを処理し、
  descriptor/frame/state leakを検出できる。

### Operator criteria（M2）

各手順を3回実行し、全回で満たします。背景loadは
`v1:zero-copy:q4:b64:ip-mtu1500:f4096:outbound:plain:udp-checksum`の設定で10%
（81,274 pps）とします。共通して、各手順後にframe health totalが開始時と一致し、
`invalid_descriptors = double_owned = 0`です。

| scenario | numeric criteria |
|---|---|
| cold start | process起動から最初のforwarded packetまで ≤ 10 s。startup summaryにgeneration、backend、copy/zero-copy、capacityを出す |
| validate/plan/apply（reloadable） | apply開始から新generation activeまで ≤ 1 s。forwarding停止はoffered rateで10 ms相当以下のloss（≤ 812 packets） |
| invalid apply | lossなし、generation不変、旧publication継続 |
| link down/up | link up後 ≤ 5 s でforwarding再開。healthがlink downを観測できる |
| TX ring full | process継続、TX rejectがtyped counterに出る。条件解除後 ≤ 1 s でoffered rate復帰 |
| graceful shutdown（SIGTERM、load中） | ≤ 5 s でexit 0、最終generation/counterを出力、`rx_owned = core_borrowed = tx_owned = 0`、XDP programはdetach policyどおり |
| forced termination（SIGKILL）後restart | restartから最初のforwarded packetまで ≤ 10 s。他者のXDP programを無断で置換しない。generationは前回より大きい |

rationale: 家庭用routerのreboot/再設定でユーザーが体感しない範囲（秒単位の起動、apply中の
ms級停止）を上限とする。

## owner決定（2026-11-01）

ownerは#282の確認事項すべてについて提案どおりに承認しました。

1. M2 minimum topology（各port 1 queue）とplan v1（237中201 caseがq4、q1は36 case）の差は、
   X05 labに**port当たり4 queue以上をsupportするNIC**を要求することで解消する。plan v2は作らない。
2. MQ IMIX/eth512 100%（bidirectional NAT+FWを含む）を含め、offered load表の値を変更しない。
3. loss 0.001%（zero-lossではない）、p50 100 µs/p99 1 msの水準を採用する。
4. soakとoperator testのartifact形式はprotocol v1外であり、X05で定義する。
5. latencyはgenerator loopbackを差し引かない。
6. pps regressionはfixed offered loadでは発火しないため不採用とし、v0.2のregression gateは
   latencyだけとする。throughput regressionが必要になった場合は、no-drop rate探索または
   cycles/packetを持つprotocol/artifact v2を別sliceで追加する。
7. 承認手順は上の「承認手順」のとおりとし、#282が`main`へsquash mergeされたcommitを
   `spec_git_sha`とする。
