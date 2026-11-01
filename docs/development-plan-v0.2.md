# v0.2 development plan

この文書は、2026-07-30時点のactive v0.2 treeに対するrepository全体の並列監査を統合し、
「libraryとして検証できるpacket-processing core」から「自宅ラボで起動、設定、運用、
測定できるrouter」までの実装順を定める。実装済み機能の詳細なRFC根拠は
[`requirements-v0.2.md`](requirements-v0.2.md)、現在のdata-plane契約は
[`architecture-v0.2.md`](architecture-v0.2.md)を正とする。

## 前提と非交渉事項

- active実装はv0.2だけである。`prototype-v0.1`は履歴説明とblack-box期待値の参考であり、
  Rust実装をcopy、port、改変しない。
- fast pathはworker-ownedであり、共有`Mutex`、packet clone、packet単位`String`、
  `dyn PacketIo`を導入しない。
- backendはbackend-owned bufferをcoreへborrowし、各slotをcommit、recycle、consume、
  abandonのいずれかでexactly once完了する。
- correctness、security、public API compatibility、failure atomicityに関する
  Critical/High/Medium findingはmerge前に解消する。
- 実装者の自己検証とは別に、各PRへ独立reviewerを割り当てる。

`docs/prototype-v0.1.md`には意図的に旧設計の説明が残る。repository-wide検索やaudit toolが
これをactive code、現在の依存、未解決TODOと誤認する可能性があるため、監査結果には検索対象を
明記する。prototype由来のfindingはactive treeで再現した場合だけbacklogへ入れる。

## 現在地

2026-11-01時点の`main`（codeは`c256e92`、#285まで。docsは`5fc4663`、#286まで）をcodeと
repository rulesetから確認した状態である。以下で矛盾する
場合はcode、[`requirements-v0.2.md`](requirements-v0.2.md)のledger、
[`release-evidence/m1.md`](release-evidence/m1.md)を正とする。

### 実装済み

workspaceは12 crateからなる。data-planeとI/Oのlibrary crate（`ruster-core`、`ruster-io-*`、
`ruster-runtime`、`ruster-bench`）は外部依存を持たない。外部依存は`ruster-config`と
`ruster-sim-scenario`が直接使うserde/serde_path_to_error/tomlだけで、`ruster-control`と
`ruster-cli`はpath depを通じてそれらを推移的に含む。

- packet core（`ruster-core`）
  - backend-owned RX/generated bufferのGAT/RAII lease、stableな`DropReason`/`ConsumeReason`
  - Ethernet II、exact ingress MAC admission、IPv4 header/length/checksum、common martian
    admission（P0-INGRESS、ETH-002、IP4 rows）
  - LPM、TTL/checksum/MAC rewrite、static/dynamic ARP、retry、failure hold、generated ARP
  - local ICMPv4 Echo、Time Exceeded、Network/Host Unreachable
  - worker-local fixed-capacity UDP/TCP NAT44（caller-backed directoryとdirect public-port
    ownerによるbounded lookup/allocator、P0-NAT-INDEX）とexternal ICMPv4 Type 3/Code 4
    translation
  - opt-in stateful IPv4 UDP/TCP firewall、NAT RELATED照合、期限切れslotのbounded sweep回収
    （#281、FW-021A）
  - UDP/TCP NAT44+FW+generated ICMPのunaudited/audited public full composition（P0-COMPOSE）
  - backend stats extension（`BackendStats`、`ObservableFields`）
- worker runtime（`ruster-runtime`）: generic publication seam、`PublicationTick` token、
  backend quiescence gate、明示budget付きbounded single-worker `run_tick`（RT-001〜003）、
  allocation-freeな`TickObserver`とhealth/counter snapshot（OBS-004〜021）
- config（`ruster-config`）: 最大1 MiBのversioned TOML parserとbounded semantic validation
  （CONFIG-001〜003）
- control（`ruster-control`）: owned `ValidatedCandidate`、config→candidate bridge、
  sim専用決定的key source、`FullServiceStorage`/`ActivePublication`による5 runtimeの
  preflight後一点commit、`ApplyPlan`、guard不要dry-run、`PublicationSequencer`による
  generation/key採番とrollback（PUB-001〜009）
- sim（`ruster-io-sim`、`ruster-io-conformance`、`ruster-sim-scenario`）: deterministic
  RX/TX/recycle FIFO、backend conformance suite、`ruster-scenario/v1` model/frame builder、
  run-sim driverとcanonical JSONL `ruster-run-sim/v1`、M1 golden fixture（SIM-001〜019）
- CLI（`ruster-cli`、binary `ruster`）: `validate`、`plan`、`run-sim [--hold]`、
  SIGINT/SIGTERMのordered shutdown（CLI-001〜007）
- benchmark（`ruster-bench`）: NIC-free sim smoke/datapath suite、hardware plan/protocol/
  artifact v1 schema（BENCH-001〜006）、owner承認済みv0.2 benchmark spec（R17、#282、
  `spec_git_sha` `5c57f41`）とpin済みdigest/matrix/承認marker test（BENCH-007〜009）
- real-I/O scaffold（productionではない）
  - `ruster-io-afpacket`: checked TPACKET_V3 mapping、fixed-frame TX engine、persistent
    RX block engine、core `PacketIo`のcopy backend（AFPKT-001〜007、IO-012）。証跡は
    scripted syscall上のconformanceだけで、public live constructor、TX completion
    scheduling、poll、netns/実NIC E2Eは無い
  - `ruster-io-xdp`/`ruster-io-xdp-native`: AF_XDP ownership model、native ABI/ring
    scaffold、private syscall RAII seam（XDP rows）。socket/UMEM登録、attach、`PacketIo`接続は
    無い
- CI: `CI` workflow（Check、Musl、Test、Clippy、Format、Doc。Testはdoctestとrequirements
  gateを含む）、`Security Smoke` workflow（`R16A Bounded`、8 target×4 fixed seed）、
  `Benchmark Smoke` workflow（spec digest、plan v1照合、sim smoke）。
  repository rulesetのrequired checkは`Check`、`Test`、`Clippy`、`Format`、`Doc`、
  `R16A Bounded`で（2026-11-01追加）、`Musl`と`Benchmark Smoke`はrequiredではない

milestone状態: M0のP0 rowはすべてledger上implementedだが、M0の独立release evidence fileは
作っていない。M1は2026-11-01にcloseした。[`release-evidence/m1.md`](release-evidence/m1.md)の
9 exit criterionはすべてmetで、closing SHAはそのevidenceをcloseへ更新したPRのsquash merge
commitである。route撤去後の既存flowがsilentな点はtracked deviation（FW-025）として残り、
NAT port pool size明確化とOBS-017/018延期のowner確認は任意でM1 closeを妨げない。

次のmilestoneはM2（Operable AF_XDP static router）である。経路はdependency graphの
X00 → X01/X02/X03 → X04 attach/config/ops integration → X05 hardware benchmarkで、X04は
R08/R09/R10/R15、X05はR17 frozen specに依存する。下の「Partialまたは欠落」のうち（M2）と
記したproduction backend、`ruster run`、production key sourceがM2の対象である。

### Partialまたは欠落

- production backendが無い。AF_PACKETはscripted syscall上のcopy backendまで、AF_XDPは
  ownership model/native scaffoldまでで、`ruster run`、XDP program lifecycle、multi-queue
  worker ownership、netns/実NIC E2Eは無い（M2）。
- `run-sim`はrestart-required applyをrejectとして報告し、同一process内でstorageを
  作り直さない（SIM-016 deferred）。process restartをまたぐgeneration/key履歴は無い。
- OS乱数によるproduction key sourceと、sim専用key sourceを`run`で拒否する仕組みが無い（M2）。
- NAT/FW占有、resolution/action/audit high-watermark、native ringのsaturationが無い
  （OBS-015/017/018 deferred）。core `PublicationQuiescenceGuard::new`はsealされていない。
- optional serviceを表すcomposition seamが無く、M1はUDP/TCP NAT44+FWを必須とする。
- `ruster run-sim`によるfrozen benchmark spec SHAの表示（R12 acceptance）が無い。spec SHA自体は
  M1 release evidenceへ固定済み。
- privilege separation、persistent diagnostics、structured log、metrics endpoint、
  config history、sanitizer、long soak、netns/hardware CIが無い。

### 計画との差分（2026-10-31確認）

実装を進めた結果、この文書の次の記述は実態とずれている。設計変更はせず事実だけを記録する。

- 依存とlock: 「外部依存なし」は旧状態。serde/tomlは#251がcodeと同じPRで追加し、新crate追加
  PR（#259、#267、#277、#279等）も`Cargo.lock`を変更した。root `Cargo.toml`/`Cargo.lock`を
  RI-DEPだけが編集する規則は守られていない。規則を改めるかはowner判断である。
- R10/live activation: plan/applyとlive activationは`ruster-control`
  （`plan.rs`の`ApplyPlan`/`PublicationSequencer`、`activation.rs`）に置いた（S2/S3）。work packet表のR10 rowは
  これに合わせて更新した。
- R16: 実装は`fuzz/`ではなく`crates/io-sim/tests/r16a_support`と`fuzz-smoke.yml`
  （#249、#252、#280）。work packet表のR16 rowを更新した。`R16A Bounded`は
  2026-11-01にrequired checkへ追加された。`Musl`（#244 titleは「required」）は現状required
  checkではない。
- R15: core accessorが必要なhigh-watermarkは見送り（OBS-015/017/018）、R15 rowへ注記した。
  #276は`BackendStats`/`DropReason::ALL`等をcoreへ追加しており、`crates/core/src/lib.rs`を
  RI0だけが編集する規則とはずれている。
- dependency graph: R11（S5b driver）は実際にはR10（S3）、live activation（S2）、R15（S4）の
  merge後に実装した。graphへ注記した。
- R17とhardware v1文書の関係、M1/M2でのspec SHAの扱いは#282で決定した（spec v0.2の
  「M1で適用する範囲」、`spec_git_sha`はM1 release evidenceへ固定）。
- config/control/runtimeのservice必須性とrollbackの意味は「M1 owner決定」で解決済みである。

### Open issue hygiene

#200、#202、#207はactive v0.2 treeより前のcrate、API、reportを前提にしていたため、次のmappingを
issue tracker側へcommentしたうえで2026-07-30に`not planned`としてcloseした（H00完了）。
prototype Rustを実装資産として再利用しない。

| Issue | 当時の前提 | v0.2での扱い | Tracker action |
|---|---|---|---|
| #200 DPDK実I/O | 消滅した`ruster-dataplane`、`DpdkPacketIo`、旧`router.toml`を前提 | M2はAF_XDPをproduction backendの第一候補とする。DPDKはP2かM3後に、新backend contractから設計し直すまでdefer | superseded noteを追加しclose済み |
| #202 OSPF/BGP run loop | active treeに存在しない旧engine、RIB/FIB、main loopを「実装済み」とする | dynamic routingはM3のstatic-router運用後に再scopeする。RFCとblack-box protocol期待値だけを再利用し、旧engine codeは移植しない | P2-ROUTING後の新design issueが必要と記録しclose済み |
| #207 v0.1性能report | 旧benchmark binaryとplaceholder reportを前提 | R17でv0.2 benchmark specを先にfreezeし、X05がそのSHAに対する実測artifactを作る。v0.1 reportへv0.2数値を追記しない | R17/X05 mappingをcommentしclose済み |

将来DPDKやdynamic routingを再開する場合も、v0.2 backend/publication/runtime
contractから新しいacceptance criteriaを作る。

## P0/P1/P2 backlog

priorityは実装量ではなく、次milestoneを安全に開始できる順序を示す。

### P0: backendまたはdaemonより前に閉じる

| ID | Work | 理由 / 完了状態 |
|---|---|---|
| P0-INGRESS | ingress L2/martian admission | foreign unicast、invalid Ethernet source、IPv4 martianをplain/NAT/FW全pathでmutation/state/LPM前にtyped drop。local controlとARPの許可profileを別に保つ |
| P0-NAT-INDEX | bounded NAT index/allocator | TCP `O(P*M*S)`とUDP `O(P*M)`をpacket pathから除去し、lookup、free-port、expiry/reuseを明示上限付きにする |
| P0-PUBLICATION | publication lifetime contract | owned generationがsnapshot/config/runtimeより長生きし、apply失敗時に旧generationを継続。capacity変更とrollbackをtyped planにする |
| P0-COMPOSE | full service composition | UDP/TCP NAT+FW+generated ICMPのunaudited/audited public APIとsim proofを追加 |
| P0-BACKEND-CONTRACT | backend conformance suite | lease exactly-once、partial TX、finish error、generated accounting、batch abandonをbackend共通suiteで検証 |
| P0-TICK | bounded worker tick | architecture順序をgeneric、allocation-free、明示budgetで固定し、RX borrow終了後だけgenerated sessionを開始 |
| P0-CI | baseline gate hardening | R00Cが現行workspaceのformat、clippy、test、doctest、rustdoc、check、requirementsを固定toolchainで実行し、backend contract testを通常CIへ追加する。fuzz/privileged/hardware jobはP1の専用PRへ分離 |

ingress admissionは少なくとも次をblack-box testに固定する。

- IPv4 unicast forwardingはEthernet destinationがingress interface MACと一致すること。
- Ethernet sourceはzero、broadcast、multicastではないこと。
- IPv4 sourceはunspecified、limited broadcast、multicast、loopback、class-E/reserved、
  ingress connected network/directed-broadcast、ingress local claimではないこと。
- destinationのlimited/direct broadcast、multicast、loopback等は明示profileなしに
  unicast forwardingしない。
- dropはpacket bytes、NAT/FW/resolution state、ARP/ICMP actionを変更しない。
- ARP broadcastと既存local control admissionを誤って遮断しない。

martian集合とexceptionは実装前にRFC/deviation ledgerへ追加する。XDPをpromiscuous相当で
attachした時に「kernel/NICが先に捨てるはず」と仮定しない。

### P1: runnable/operableに必要

| ID | Work | 完了状態 |
|---|---|---|
| P1-CONFIG | R09 versioned declarative config | interface、address、route、neighbor、NAT、FW、capacity、tick budgetをparseし、全semantic validation後だけpublication候補を作る |
| P1-PLAN-APPLY | R10 validate → plan → apply | generation diff、state flush、restart-required、rollback-as-new-generationを表示し、tick boundaryでatomic apply |
| P1-DAEMON | R12 worker supervisor/CLI | `validate`、`plan`、`run-sim`、後の`run`、signal、ordered shutdown、nonzero exit、privilege boundary |
| P1-OBS | R15 observability | typed counter snapshot、config generation、queue/capacity high-watermark、drop reason、backend mode、health/readiness |
| P1-AF_PACKET | R13/R14 real-I/O correctness rung | preallocated backend-owned slots、multi-interface IfId mapping、partial send/recycle、veth/netns E2E。copy backendであることを明示 |
| P1-AF_XDP | X00–X05 AF_XDP queue backend | queue/UMEM/descriptor ownership、RX/FILL/TX/COMPLETION、generated slots、need-wakeup、copy/zero-copy capability |
| P1-SEC-TEST | R16 fuzz/property/E2E | Ethernet/IPv4/ARP/ICMP/UDP/TCP parser、checksum、state transaction、clock/capacity/publicationのadversarial test |
| P1-BENCH | R17/X05 reproducible benchmark | sim microbench、AF_PACKET netns、AF_XDP hardware matrixとbaseline artifact |

### P2: household scaleと長期運用

| ID | Work | 完了状態 |
|---|---|---|
| P2-SCALE | multi-queue/multi-worker sharding | NAT/FW/resolution ownershipをqueueへ固定し、cross-worker flow routingを共有lockなしで定義 |
| P2-ROUTING | scalable route/neighbor lookup | linear LPM/table scanをbounded indexed structureへ移し、publication build時に検証 |
| P2-NAT | NAT product features | static forward、hairpin、multiple public addresses、port policy、ICMP query/追加error、fragment/PMTU方針 |
| P2-FW | firewall product features | plain NAT-less RELATED、rule compiler/index、state export、運用可能なdeny/audit policy |
| P2-NET | VLAN/IPv6/MTU | VLAN、IPv6、egress MTU、fragmentation/Packet Too Bigを個別milestoneで追加 |
| P2-OPS | durable operations | config history、automatic rollback policy、upgrade/drain、metrics endpoint、support bundle |
| P2-LAB | PVE/hardware automation | ephemeral runner、NIC binding recovery、reboot-safe cleanup、nightly soak、regression thresholds |

## Milestone

### M0: Production-backend readiness

production backendの実装を安全に並列化できるcore/runtime境界を完成させる。

すべてのP0は次のevidenceを満たす。表の一行でも未達ならM0未完了である。

| P0 ID | Required PR | Exit evidence |
|---|---|---|
| P0-INGRESS | R01 | ledgerにmartian/L2 policyとdeviation、全pathのbyte/state/action atomic test、独立RFC/security approval |
| P0-NAT-INDEX | R02→R03→R04 | frozen complexity contract、UDP/TCP capacity/property test、packet-path lookup/allocatorに`P*M*S` nested scanが無いことを示すreview |
| P0-PUBLICATION | R06 | owned publication lifetime compile test、failed apply/rollback runtime test、独立lifecycle approval |
| P0-COMPOSE | R05→RI0 | R05がinternal wrapper behaviorを固定し、RI0がunaudited/audited re-export、public compile/full-service integration test、matching requirements rowを同時追加してAPI/security approvalを得る |
| P0-BACKEND-CONTRACT | R07 | `ruster-io-sim`がRX/generated exactly-once、partial reject、finish error、abandon suiteに合格 |
| P0-TICK | R08 | phase-order trace、全phase budget、RX borrow終了後generated開始、error accounting test |
| P0-CI | R00C | pinned toolchainでREADMEの6 gate、requirements gate、R07 conformanceを通常CIの必須jobとして成功 |

加えて、backend-facing traitにUMEM、raw pointer、headroom/capacity全体を公開せず、fast-path
forbidden patternを機械checkと独立performance reviewで確認する。production backendが依存する
public APIはRI0のcompatibility reviewを通過する。

M0はAF_XDPがpacketを送れることではない。「backendを足しても既知のingress security holeや
unbounded NAT pathをそのままwireへ公開しない」状態である。

### M1: Runnable deterministic router

rootやNICなしで、宣言的設定からrouter processを起動し、完全なworker lifecycleを実行する。

exit criteria:

- `ruster validate`、`ruster plan`、`ruster run-sim`がdocumented exampleで動く。
- LAN/WAN、route、dynamic ARP、UDP/TCP NAT、FW allow/deny、TTL/route/host ICMPを含む
  deterministic scenarioがpublic full composition APIを通る。
- 同じconfig/scenarioはbyte/order-identical resultを返す。
- invalid config/applyは旧publicationとruntimeを変更しない。
- reloadはgeneration境界で行い、capacity変更はrestart-required、rollbackは新generationとなる。
- SIGINT/SIGTERMでlive leaseを残さず、最終counter/config generationを出力して終了する。
- R15のcounter snapshot/health/config generationを`run-sim`出力でoperatorが確認できる。
- R16のparser/state/publication property suiteとbounded fuzz smokeが必須CIで成功する。
- R17がbenchmark specificationをcommitし、そのspec SHAをM1 release evidenceへ固定する。

#### M1 owner決定（2026-11-01決定）

- binary: `crates/cli`（package `ruster-cli`、bin `ruster`）。arg parsingは手書きでclapは使わない。
- signal: binary内の小さなprivate FFIでhandlerはstatic `AtomicBool`へstoreするだけ。新しい依存は追加しない。
- scenario: `--scenario`で渡す別TOML file。frameは型付きbuilderとraw hex。reload stepは
  scenario fileからの相対pathでconfig fileを参照する。
- `run-sim`出力: stdoutはversion付きcanonical JSONL `ruster-run-sim/v1`、stderrは人向けsummary。
  wall clockは含めない。signal試験用に`--hold` modeを持つ。
- exit code: 0 = 正常終了またはsignalによる正常shutdown、1 = runtime/invariant failure、
  2 = usage/config invalid。
- hash key: `run-sim`はscenario seedからsim専用型で決定的に導出する。OS乱数による
  key sourceはM2の`run`へ延期する。
- service: M1ではNAT44 UDP、NAT44 TCP、FWを全て必須とし、欠落はtyped rejectとする。
- restart-required: storage shape、resolution/ICMP policy、interface IfId/MAC変更。
  route、neighbor、FW rule、NAT port/realmはreload可能。
  - 補足（2026-11-01、実装による明確化。owner確認待ち）: NAT port poolのsize変更はstorage shapeを
    変えるためrestart-required。同sizeのrange shiftとrealm変更はreload可能。
- rollback: M1では旧config fileを新generationとして再applyすることを指す。
- 補足（S5b review、2026-11-01 owner決定）: ownerは「基本的な判断基準としてRFC準拠」とし、
  firewall有効時のroute missはdeviationを受容せずcore修正#284をmergeする。#284はegress=noneでingress/src/dst/protocol/port ruleと
  default policyを評価し、どのegressへも新規flowとして許可され、egress依存のNAT gateにも
  当たらないpacketだけにICMPv4 Destination Unreachable Networkを生成する（egress限定allowは
  matchせず、egress限定denyはfail closed。route oracleの考察はarchitecture）。それ以外は
  silentな`FIREWALL_ROUTE_UNAVAILABLE`のまま。M1 goldenはv2のegress `Any` rule 40で
  Type 3/Code 0を検証する（SIM-010、FW-025）。同じ決定で次を確定した。
  - egress限定denyはroute missでもdenyとして扱う。firewall filteringはRFC 1812が認める
    operator policyであり、route oracleを防ぐ。
  - route missのegress-free評価はfirewall auditへ記録せず、`denied_by_rule`/`denied_default`も
    数えない（drop reasonで区別できる）。
  - route撤去後の既存flowのpacketがsilentな点（FW-025）はtracked deviationとして残し、
    RFC準拠を基準に別PRで再検討する。security上offにしたい挙動を設定可能にする要求
    （ownerの同日決定）も同じ別PRで扱う。
  - 補足（2026-11-01、上記の別PRで実装）: router-originated ICMPv4の4 classに
    default onのswitchを追加した（`[ipv4-origin] echo-reply`はreloadable、
    `[icmpv4-errors.generate]`の`time-exceeded`/`net-unreachable`/`host-unreachable`は
    ICMPv4 error policyとしてrestart-required）。FW-025は再評価の結果deviationを維持した:
    全reloadがfirewall flowをflushするため撤去前flowのstateは存在せず、route missだけ
    answerするとroute oracleになる（理由はarchitecture、ledger FW-025）。
- R17の数値thresholdはimplementerがPRで提案し、ownerがそのPRで承認する。
- NAT/FW占有のhigh-watermarkはM2へ延期する。
  - 補足（S4実装による明確化。owner確認待ち）: R15/Operability minimumのresolution state、action
    queue、firewall auditのhigh-watermarkも同じくcore accessorが必要なため未実装（ledger OBS-017）。
    RX/TX queue saturationはSimIoのpending RX/TX high-watermarkだけ実装し、native ringの
    RX/TX/FILL/COMPLETIONは各backendの`BackendStats`実装まで延期（OBS-018）。
- sim専用key sourceの拒否: 現在は型名と自己申告の`KeySourceKind`だけで区別している。M2の`run`は
  `DeterministicSimulation`を拒否する仕組み（`S::KIND`のconst assertionまたはsealed production
  marker trait）を実装する。

M1への経路はgap分析のslice S1〜S9とする。

- S1: config→publication candidate bridge（`ruster-control`、sim専用key source）。
- S2: live activation（storage所有、5 runtime preflight後の一点commit）。
- S3: R10 plan/apply（typed diff、restart理由、generation採番、rollback）。reloadごとのARP/NAT/FW
  flush数をplan出力に表示する。restartをまたぐ単調なgeneration/key採番（A→B→Aのkey再利用防止）と
  guard不要のdry-run successor checkもS3が持つ。
- S4: R15 observability（counter snapshot、drop reason集計、health）。
- S5a/S5b: scenario modelとsim driver、golden fixture。golden scenarioはreloadのflush数を出力する。
- S6a/S6b: CLI `validate`/`plan`、`run-sim`/signal/E2E。
- S7: R17 benchmark specとsmoke workflow。
- S8a/S8b: R16 NAT/FW state・config fuzz、publication/apply property。
- S9: RD0 docsとM1 release evidence。

実績（2026-11-01更新）: S1 #273、S2 #274、S3 #275、S4 #276、S5a #277、S5b #278、S6a/S6b #279
（一PR）、S8a/S8b #280（一PR）はmerge済み。#280が見つけたfirewall期限切れslotのliveness
bugは#281で修正した。S7は#282（owner承認済み）、route-miss ICMPの修正は#284、ICMPv4生成switchは
#285でmerge済み。S9はRD0とM1 release evidence
（[`release-evidence/m1.md`](release-evidence/m1.md)）。M1 exit判定はevidence fileで行い、
2026-11-01に`R16A Bounded`のrequired化を記録して9 criterionすべてmetとし、M1をcloseした。

### M2: Operable AF_XDP static router

一workerまたはqueue-shardedな静的LAN/WAN構成をAF_XDPで継続運用できる。

exit criteria:

- interface/queue bind、XDP attach、UMEM registration、ring setup、shutdown/detachがfailure atomic。
- RX forward/drop、same-frame TX、generated ARP/ICMP、partial TX、completion recycleが
  descriptor-levelでexactly once。
- zero-copy/copy mode、need-wakeup、ring fill、starvation、invalid descriptorを観測できる。
- veth/copy-mode integrationを通常またはprivileged CI、zero-copyをhardware runnerで検証。
- config reload、link down/up、TX ring full、process crash後の再起動をlab runbookで回復できる。
- R17で結果取得前にreview/mergeされたbenchmark specのcommit SHAをrelease evidenceに記録する。
  M2のminimum topologyは2 ports、各port 1 RX/TX queueで、specは少なくとも64/128/512/1500-byteと
  IMIX、single-flowと複数flow、plain/NAT/NAT+FW、双方向を含む。
- specは各caseのoffered pps、minimum accepted ppsまたはline-rate比、maximum loss率、
  p50/p99 latency上限、baseline SHAからの許容regression率を数値でfreezeする。X05のresult PRは
  測定後にこれらを緩和できない。
- X05 artifactはqueue/flow/packet caseごとのpps、Gbps、loss、p50/p99、cycles/packet、
  ring starvationを含み、全thresholdを満たす。
- operator testはcold start、validate/plan/apply、link down/up、TX full、graceful shutdown、
  forced termination後restartをrunbookどおり実行し、期待したhealth/config generation/
  descriptor回収をassertする。

### M3: Household/scaled router

家庭回線で必要な機能、容量、長時間運用を満たす。

exit criteria:

- multi-queue scalingとflow affinityがworker-local state contractを破らない。
- household向けstatic forward/hairpin/VLAN/MTU policyのscopeとRFC deviationが実装・試験済み。
- 24時間以上のmixed-traffic soak、config churn、link flap、capacity pressureを通過する。
- PVE/実NIC runnerのcleanupとrollbackが自動化され、mainへ再現可能なperformance regression
  signalを返す。
- operatorがconfig history、health、drop/state/capacity、backend modeを説明できる。
- M3 benchmark specは実装/測定より前のreviewed SHAとしてfreezeし、1 queue baselineと
  target hardwareでsupportする全queue countを比較する。flow数はsingle、steady-state、
  NAT/FW state capacity直前の各絶対値をspecに固定する。
- packet/IMIX、direction、plain/NAT/NAT+FW、queue/flowの全caseにoffered/accepted pps、
  maximum loss、p50/p99 latency、M2 baselineからのmaximum regressionを数値で定める。
- soak時間、config churn回数、link flap回数、capacity pressure profile、許容state leak/
  descriptor leakをspecに固定し、hardware artifactで全caseをpassする。
- operator acceptanceはinstall/upgrade、apply/rollback、drain/restart、NIC bind recovery、
  support bundle取得を別担当者がrunbookだけで完遂し、期待generation/health/traffic recoveryを
  assertする。

## PR dependency graph

```text
R00 workspace/new-crate scaffold
 ├─ R01 ingress L2 + martian
 │    └─ R05 full composition             (forwarding.rsを直列化)
 ├─ R02 NAT index contract
 │    └─ R03 UDP index
 │         └─ R04 TCP index               (nat44.rsを直列化)
 ├─ R06 publication ownership/lifetime
 └─ R07 backend conformance
      └─ R00C baseline CI hardening

R01 + R03 + R04 + R05 ──► RI0 core shared-file/re-export integration
RI0 + R06 + R07 ─────────► R08 bounded worker tick ───────────────┐
                               ├─ R09 config schema/validation     │
                               │    ├─ R10 plan/apply/reload       │
                               │    └─ R15 observability           │
                               ├─ R11 deterministic sim driver     │
                               ├─ R13 AF_PACKET ──► R14 netns CI   │
                                                                  │
R01+R03+R04+R05+R06+R08+R09 ──► R16 fuzz/property/security CI     │
R08 + R15 ─────────────────────► R17 frozen benchmark spec/harness│
R08+R10+R11+R15+R16+R17 ──────► R12 CLI/supervisor/M1 E2E ◄─────┘

R07 ─► X00 AF_XDP ABI/ring
         ├─ X01 RX/FILL
         ├─ X02 TX/COMPLETION
         └─ X03 generated-frame

X01+X02+X03+R08+R09+R10+R15 ─► X04 attach/config/ops integration
X04 + R17 ────────────────────► X05 hardware benchmark / M2

各waveのcode PR群 ─► RD0 README/architecture integration
dependency追加を伴うPR群 ─► RI-DEP Cargo.lock integration（常に一つずつ）
RD0 ─► H00 #200/#202/#207 tracker hygiene
```

R01とR05、R03とR04は同一monolithic sourceを変更するため並列実装しない。R09、R11、R13は
R08 merge後に別crate/fileで並列化でき、R15はconfig generation schemaを使うためR09 merge後に
開始する。X01、X02、X03はX00がring/descriptor moduleとre-export pointを確定した後、別fileで
並列化できる。R12はR10とR11の両方に依存し、X04はX01–X03に加えて
runtime/config/observabilityへ依存する。

実績注記（M1）: reloadを含むM1 golden scenarioのため、R11のdriver（S5b #278）は実際には
R10（S3 #275）、live activation（S2 #274）、R15（S4 #276）のmerge後に実装した。
scenario model（S5a #277）だけがR08後に独立して進められた。

## Work packets、file ownership、acceptance

全packetがconflict-freeではない。共有fileは明示したintegration ownerだけが編集し、
monolithic fileはdependency順にrebaseして直列mergeする。

以下のownerは実装範囲、reviewerは独立reviewの専門領域を示す。同一agentが両方を担当しない。
外部から観測可能なbehavior、public API、RFC statusを追加・変更するPRは例外なく、そのbehaviorを
固定するtest sourceと`docs/requirements-v0.2.md`のmatching rowを同じPRに含める。
requirements ledgerは共有fileなので、該当PRを直前のledger変更へrebaseして一つずつmergeする。
R05はinternal plumbingだけを追加しpublic/RFC completionを主張せず、RI0がpublic test、re-export、
matching requirements rowを同じPRで完成させる。

| PR | Depends / exact owner scope | Acceptance criteria | Independent reviewer |
|---|---|---|---|
| R00 | root `Cargo.toml`、planned crate manifests/skeleton、`Cargo.lock`だけ | workspace discoveryと既存full gateが不変。feature実装やCI policy変更なし | build/reproducibility |
| R00C | R07後。既存`.github/workflows/ci.yml`と専用CI scriptだけ | pinned toolchainでREADME 6 commands、requirements、sim backend conformanceをrequired job化。fuzz/netns/hardwareを含めない | CI/security |
| R01 | `crates/core/src/forwarding.rs`とnew ingress test。R05より先 | P0-INGRESS matrix、bytes/state/action atomicity、ARP/local regressionsなし | RFC/security |
| R02 | new ADR/black-box test scaffoldだけ。`nat44.rs`変更なし | key、capacity、expiry、generation wrap、overload、complexity上限をfreeze | performance/API |
| R03 | R02後、`crates/core/src/nat44.rs`のUDP部分とnew UDP test。R04より先 | bounded lookup/free-port、live非evict、EIM/ADF、clock semantics維持 | NAT/RFC |
| R04 | R03へrebaseし、同`nat44.rs`のTCP部分とnew TCP test | `O(P*M*S)`除去、exact session、same-batch、expiry/RELATED維持 | performance/security |
| R05 | R01へrebaseし、同`forwarding.rs`のinternal full wrapper plumbingとmodule-level test。`lib.rs`は触らない | 全service引数の内部binding、deny/TTL/RELATED/neighbor atomicity。public/RFC completionは主張しない | API/security |
| RI0 | R01/R03/R04/R05後。`crates/core/src/lib.rs`、public compile/full-service integration test、matching requirements row | unaudited/audited public re-export、old API compatibility、外部crateからfull compositionを実行 | API/compatibility |
| R06 | new publication crate/moduleと専用test。既存core monolithは触らない | storageが全borrowより長命。move/reload/rollback/partial failure test | lifecycle/unsafe |
| R07 | new backend conformance crate/filesとsim adapter test | RX/generated exactly-once、partial reject、finish error、abandon | backend ownership |
| R08 | RI0/R06/R07後。new runtime crateのtick module/test | phase順、全budget bounded、RX borrow後generated、error時pending保存 | lifecycle/performance |
| R09 | R08後。config crateの`model`/`parse`/`validate` module | schema version、duplicate/unknown/canonicality/realm/capacityをmutation前にtyped reject | product/security |
| R10 | R09後。config/runtimeの`plan`/`apply` module（実績: publication ownerである`ruster-control`の`plan`/`activation` moduleに置いた。S2 #274、S3 #275） | dry-run diff、all-or-nothing apply、restart-required、new-generation rollback | failure atomicity |
| R11 | R08後。sim scenario crate/moduleとgolden fixtures | deterministic timestamp/ingress/frame inputとtyped output。packet path Stringなし | test/product |
| R15 | R09後（R09はR08依存）。runtime `observability` moduleと専用snapshot test | allocation-free typed snapshot、generation、health、core state/action/audit high-watermark、backend stats extension pointとsim実装、saturating counters。formatはcold consumerだけ（実績 #276: core accessorが要るhigh-watermarkはOBS-015/017/018でdeferred） | operations/performance |
| R16 | R01/R03/R04/R05/R06/R08/R09後。`fuzz/`、new property tests、`.github/workflows/fuzz-smoke.yml`だけ（実績: dependency-free runnerを`crates/io-sim/tests/r16a_support`に置いた。#249、#252、#280） | fixed seed/corpusと時間上限を記録し、parser/checksum/state/publication invariants、過去failure corpusをrequired unprivileged smokeで実行 | security/test |
| R17 | R08/R15後。benchmark crate、`docs/benchmark-spec-v0.2.md`、`.github/workflows/benchmark-smoke.yml`だけ | queue/flow/packet/service matrix、pps/loss/p50/p99/regression/soak/operator thresholdを結果取得前に数値freezeしspec SHAを出力。通常CIはsim smokeのみ | performance/reproducibility |
| R12 | R08/R10/R11/R15/R16/R17後。binary crateとnew M1 E2E | validate/plan/run-sim、exit status、signals、ordered shutdown、observability、frozen spec SHA表示 | operations/security |
| R13 | R07/R08後。AF_PACKET crateのbackend files | backend-owned preallocated slots、IfId mapping、partial TX、no packet clone | backend/performance |
| R14 | R13後。`.github/workflows/netns.yml`とnetns harnessだけ | forward/drop/generated、link failure、cleanup idempotence。capability不足をsilent passしない | integration/CI |
| X00 | R07後。AF_XDP crateの`ffi`/`ring` filesとmock | ABI checks、wrap/memory-order、unsafe範囲とSAFETY invariant | unsafe/kernel |
| X01 | X00後。AF_XDP `rx_fill` file/testだけ | invalid len/address拒否、borrow中recycle禁止、starvation accounting | ownership/security |
| X02 | X00後。AF_XDP `tx_completion` file/testだけ | same-frame TX、partial/full ring、completion lag、shutdown drain exactly once | backend/performance |
| X03 | X00後。AF_XDP `generated` file/testだけ | exact visible length、unavailable/cancel/abandon/reject invariants | lifecycle |
| X04 | X01/X02/X03/R08/R09/R10/R15後。AF_XDP app adapter/attach module | attach rollback、existing program policy、queue ownership、reload、copy/zero-copy、health | operations/kernel |
| X05 | X04/R17後。`.github/workflows/hardware-bench.yml`、lab script、result artifactだけ | frozen spec SHAの全queue/flow/pps/loss/latency/operator caseを実行。threshold変更なし | performance/lab |
| RI-DEP | dependency追加PRの直前に一つだけ。root `Cargo.lock`とworkspace dependency stanza | source PRで承認済みのexact dependency/versionだけをlockし、supply-chain reviewを記録 | dependency/security |
| RD0 | 各wave末尾。READMEと`docs/architecture-v0.2.md`だけ | すでに各behavior PRでledger化されたmerged behaviorとissue mappingを説明。requirements row/testを後追い集約しない | docs/architecture |
| H00 | RD0後。GitHub issue #200/#202/#207のcomment/label/close操作だけ | replacement PR/issue、defer先milestone、prototype Rust非再利用を相互linkし、各issueをsuperseded closeまたは明示deferred化 | product/issue hygiene |

共有点のownershipは次のとおり固定する。

- `forwarding.rs`: R01 merge後にR05をrebaseして直列化する。
- `nat44.rs`: R03 merge後にR04をrebaseして直列化する。
- `crates/core/src/lib.rs`: RI0だけが編集する。
- root `Cargo.toml`/`Cargo.lock`: R00後はRI-DEPだけが一回ずつ編集する。
- READMEとarchitecture: RD0だけがwave末尾に編集する。
- requirements ledger: matching behavior/testのPR自身が編集し、ledger変更PRを必ず直列rebaseする。
- CI workflow: R00C=`ci.yml`、R16=`fuzz-smoke.yml`、R14=`netns.yml`、
  R17=`benchmark-smoke.yml`、X05=`hardware-bench.yml`。同一workflowを並列編集しない。

実装者はtargeted testを反復し、ready SHAでfull gateを一度実行する。reviewerは担当領域の
adversarial testを中心にし、全reviewerが同じfull suiteを重複実行しない。GitHub CIを最終
full gateとする。

## Publication、daemon、operations

### Lifetime model

`OwnedPublication`はinterface、binding、route、neighbor、firewall rule等のowned storageを持つ。
そこから作る`ForwardingSnapshot`、NAT config、FirewallConfig、およびそれらを保持するruntimeは
publicationを越えて生存できない。自己参照struct、leaked allocation、pointer identityの
再構築でこの制約を回避しない。

daemon workerはgeneration loopを使う。

```text
candidate parse/validate/allocate
→ apply planを作成
→ tick boundaryを待つ
→ old runtime/snapshot borrowをdrop
→ candidateをcurrent ownershipへmove
→ new snapshot/config/runtimeをbind
→ reconcile後にRX再開
```

apply前に失敗し得る検証とallocationを完了する。apply後に失敗し得るbackend operationがある
場合は、backend resourceをcandidate側でprepareし、commit pointを一つにする。容量変更は
in-place resizeせずrestart-requiredとする。rollbackは古いgeneration/hash keyを再利用せず、
旧内容から新publicationを作る。

### Operability minimum

- startup summary: config generation、interfaces/queues、backend、copy/zero-copy、capacities
- health: worker alive、last successful tick、RX/TX progress、clock regression
- saturation: RX/TX/FILL/COMPLETION、NAT/FW/resolution/action/audit high-watermark
- policy: stable DropReason、FW rule/default、state failureをbounded counterでexport
- reload: plan、apply result、flushed state数、restart-required reason
- shutdown: RX停止、generated/TX flushまたはtyped reject、descriptor回収、program detach policy

packet pathでlog messageをformatしない。typed counters/eventsをworker-local fixed storageへ
記録し、control threadがtick boundary後にsnapshotして文字列化する。

## Test、CI、benchmark progression

### Required unprivileged CI

workflowごとのscopeを固定し、同じtestを複数jobへ無差別に重複させない。

- `ci.yml`（R00C）
  - README記載のformat、clippy `-D warnings`、workspace tests、doctests、rustdoc
    `-D warnings`、check
  - requirements gate
  - R07のsim backend conformance test
  - prototype pathをactive implementation scanから除外したaudit結果
- `fuzz-smoke.yml`（R16）
  - parser/checksumのfixed corpusとfixed seedによる時間上限付きsmoke
  - packet/state/publication property tests
  - 過去crash inputのregression corpus
  - privileged syscall、AF_XDP attach、performance thresholdは扱わない
- `benchmark-smoke.yml`（R17）
  - deterministic sim benchmark harnessが実行でき、schema付きartifactを出せること
  - throughput合否やhardware比較は扱わない

AF_PACKET/AF_XDP crate追加後の通常compile/clippyはworkspaceの`ci.yml`が担当する。
libxdp enabled buildにhost libraryが必要なら別の明示container jobをX00で追加し、library不在を
silent skipしない。packet/property matrixはtruncation、length/checksum、fragment、odd payload、
incremental/full checksum一致、generation/clock/capacityを含む。

### Privileged ephemeral CI (`netns.yml`, R14)

- network namespace + vethでAF_PACKET E2E
- attach/detach rollback、existing XDP program、link down、process termination
- capability不足は成功扱いのsilent skipにせず、明示されたjob policyに従う

XDP attachをvethで検証するjobを追加する場合はX04が別workflowを所有し、AF_PACKETの
`netns.yml`を並列編集しない。

### Hardware CI (`hardware-bench.yml`, X05)

固定条件をartifactへ含める。

- CPU model/governor、NUMA、IRQ/RSS/XPS、queue count、kernel、NIC/driver/firmware
- XDP copy/zero-copy、frame size、batch、flow count、direction、NAT/FW on/off
- packets/s、bits/s、drop、p50/p99 latency、cycles/packet、cache miss、ring starvation
- warmup、sample数、confidence、baseline SHA

jobはR17のfrozen spec SHAをinputとして検証し、異なるspecまたは未commitのthresholdで測定を
開始しない。hardware unavailableはjob failureまたは明示されたscheduler待ちであり、passへ
変換しない。

「10GbE対応」はlink speedや一回のpeak値ではなく、定義したpacket/flow matrixでlossとlatencyの
thresholdを満たした場合だけ主張する。

## Production AF_XDP merge blockers

次を満たさないAF_XDP PRはexperimental branchでは検証できてもproduction backendとして
mainへmergeしない。

1. libxdp/libbpf/kernel UAPIのABI、build/link、minimum kernel/driver条件を固定し、通常CIで
   enabled/disabled buildを検証する。
2. XDP program attachが既存programを無断で置換せず、partial attach失敗とshutdownで元状態を
   回復する。
3. `RLIMIT_MEMLOCK`、UMEM registration、queue bind、zero-copy request/fallbackをtyped errorと
   capability reportにする。
4. shared UMEMを使う場合、fill/completion ringのowner、frame partition、queue間handoffを
   明文化し、共有`Mutex`なしでsingle ownerを証明する。証明できるまではworkerごとの独立UMEMを
   採用する。
5. descriptor address、offset、length、headroom、frame boundaryをRX/TX前に検証し、invalid
   descriptorをcoreへ渡さない。
6. RX→TX commit、drop recycle、generated commit/cancel/abandon、TX reject、completion、
   process shutdownの全pathで各frameがexactly once free/FILLへ戻る。
7. ring producer/consumer index、wrap、memory ordering、`XDP_USE_NEED_WAKEUP`、poll/kick、
   completion lagをmock/model testと実kernel testで検証する。
8. multi-interface/queueの`IfId` mappingとegress選択をstartup時に固定し、packet pathへ
   interface `String`、trait object、global lockを入れない。
9. TX ring full、FILL starvation、allocation unavailable、partial completion、link down、
   backend errorでも既存completion accounting invariantを守る。
10. veth/copy-mode E2E、supported NICのzero-copy E2E、長時間soak、ordered shutdown、
    crash/restart recoveryの結果を残す。
11. security/unsafe reviewerがFFI、mmap lifetime、pointer arithmetic、aliasing、DMA ownershipを
    独立reviewし、すべてのunsafe blockに局所的なSAFETY根拠がある。
12. performance reviewerがcopy/zero-copyを区別したbaselineを承認し、sim benchmarkだけで
    production性能を主張していない。

## Milestone運用

一つのPRがmergeされてもmilestone完了とはしない。各merge後にdependency graph上のready packetを
開始し、同時に次waveのdesign/review packetを準備する。milestone statusはexit criteriaの
evidence、ready SHA、CI URL、benchmarkまたはlab artifactで判定し、実装量やPR数では判定しない。
