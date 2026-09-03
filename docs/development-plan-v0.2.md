# v0.2 development plan

この文書は、2026-08-23時点のactive v0.2 treeに対するrepository全体の並列監査を統合し、
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

### 実装済み

active workspaceはpacket coreだけでなく、config、cold planning、bounded runtime、integration、
sim/conformance、benchmark schema、AF_PACKET/AF_XDP scaffoldまでcrate境界を分離している。
production dependencyは下位層から上位compositionへ逆流させない。

- `ruster-core`
  - backend-owned RX/generated bufferのGAT/RAII leaseとexactly-once terminal action
  - unified ingress L2/martian admission、Ethernet II/IPv4/LPM、ARP、local/generated ICMPv4
  - caller-backed bounded UDP/TCP NAT44、stateful firewall、NAT RELATED/full composition
- `ruster-config` / `ruster-control`
  - bounded versioned TOML parse、canonical semantic validation、full runtime storage shape/bytes
  - `ValidatedConfigV1::into_parts`が返すpublic `ValidatedConfigV1Parts`の`#[non_exhaustive]` top-level transfer boundaryと、Resolution/ICMP、
    UDP/TCP NAT、firewall、tick、runtime storage shapeのconfig-owned nested exact consuming seam。各nested
    `Self` patternとcontrol plannerのreturned inventoryを省略せず、current behavior-bearing fieldの未転送を
    compile failureへ寄せる。現行のvalue equality/pointer identity/source-contract testは、それぞれcurrent
    runtime forwarding、owned allocation、exact source shapeの範囲だけを証明する
  - `ValidatedFirewallV1::into_rules(self) -> Box<[FirewallRule]>`をlegacy rules-only caller向けpublic
    compatibility seamとして維持。全current fieldをexact destructureし、policy/state_slotsをnamed discardする。
    production plannerは`into_planning_parts`でrules/policy/state_slotsを全てforwardし、legacy seamとplanner
    inventory seamを分離する
  - caller generation/typed hash keyをbindしたcold full-service plan/candidate、missing-service ownership
    recovery、value-free terminal candidate minting error、candidate-only `classify_successor`/
    `plan_successor`。`PlanSectionDiff`、`PlanGenerationTransition`、Initial/InPlace/Restart/Rejectedの
    value-only outcomeと、Rejectedでもdiffを保持するstatic planningを実装済み
- `ruster-runtime`
  - core-owned `BoundPublicationBackend<I>`とexact owner capabilityによるcandidate-preserving
    publication/quiescence seam、typed apply report
  - backend precheck、safe matched-guard gate、external `unsafe` authorized hook、foreign backendの
    candidate-preserving全phase fail-close
  - generationとtick budgetを不可分に束ねたsealed full-service view、publication後のactive viewを使う
    single-worker tick
  - `RX → resolution timer → failure dispatch → generated ARP → generated ICMPv4`のphase ordering
  - candidate-safe reject/defer時の旧active継続、active invariant failureのpersistent stop latch、backend
    disposition別skip/stop、steady-tick allocation zero evidence
  - R15: allocation-freeでgeneration-tagged化された`observability` module（saturating counter/high
    watermark、`active_status`から導出する`Readiness`、backend統計拡張点`BackendObservabilityStats`）。
    snapshot生成自体はformatを行わずcold consumer専用
- `ruster-integration`
  - `control + core + runtime`へだけ依存するcomposition root
  - active ownerからcontrol plannerへ委譲するallocation-free read-only `plan_successor`。raw candidateを
    公開せず、owner/current runtime stateを変更しない
  - candidate-boundな21 fixed backing arrayのfallible allocationとconcrete byte照合
  - worker開始前のfive-service cold initial activation、backend-bound owner typestate、storage
    lifetime-bound owner、sealed active view
  - same-interface/same-shape successorのall-five preflight、失敗不能commit、candidate-last metadata切替、
    guard解放後の旧candidate drop、service別flush report。interface/storage/Resolution/ICMP policyの
    typed restart-required、candidate-preserving reject/deferとdynamic gateをstatic planから分離する境界
  - validated configからplanner/activation/bound `SimIo` one tickまでのrootless integration evidence
  - `FullServicePublicationOwner::observability_snapshot`でtickごとのobservability snapshotを取得
- `ruster-sim-scenario`（R11）
  - public full composition API（parse→validate→plan→initial activation→`bind_publication_backend`→
    `run_tick`）だけを経由するdeterministic multi-tick scenario driver。呼び出し側が渡す論理clockだけを
    使いwall clockを読まず、ingress/typed outcomeに`String`を使わない
  - LAN内ARP解決/転送、WAN route経由のUDP/TCP NAT44、firewall allow/deny、複数tickのdynamic neighbor
    解決、TTL超過とARP解決失敗（max-attempts消尽）によるICMPv4生成、同一scenarioのbyte/順序完全一致
    replayをgolden fixtureとして保持。route-unreachable ICMPはfirewall route oracle抑制のためpublic
    full composition API経由では原理的に再現不能なためscope外
- I/O / test foundation
  - `ruster-io-sim`のdeterministic RX/TX/recycle FIFO、partial/error lifecycle、inner backend向けquiescence
    model。`SimIo::new`/`Default`はstandaloneで、publication pathは`bind_publication_backend`を使う
  - backend conformance、AF_PACKET TPACKET_V3 checked scaffold/fixed-frame TX engine
  - AF_XDP pure ownership/ring modelとnative UAPI/ring/syscall RAII scaffold
  - deterministic security replay/property smokeとNIC-free benchmark artifact/plan validation
- CI
  - format、clippy、workspace tests、doctests、rustdoc、check
  - requirements ledgerが参照する一行一Test IDの機械検証

NAT/FWはrewrite成功後、TX request前にstateをcommitし、backend rejectでも同一batch内の
後続packetから見える。resolution、ICMP error、firewall、NATのmutable stateはcaller-backedで
worker-localであり、live capacity pressureで別flowをevictしない。cold initial activationでも
candidate/storage/runtime lifetimeをsafe borrowで束ね、self-reference、leak、unsafe pointerを使わない。
ICMPv4 error publication validationはstate/actionの双方向backreferenceによりaction 2 pass + state 1 passの
`O(A + S)`で、nested searchとmutation-on-rejectionを持ちません。x86_64ではbackreference追加後のstate/action
slotが32/592 bytes（各+8 bytes）で、config/control/integrationのrequired byte計算は`size_of`へ自動追随します。

### Partialまたは欠落

- integration ownerはcore-owned bound backendのexact owner capabilityへbindし、same-interface/same-shape
  successorについて全5 runtimeをmutation-freeにpreflightする。matched quiescence guard保持中に失敗不能
  commitして最後にgeneration/tick/authority candidateを置換し、guard解放後に旧candidateをdropする。
  interface bindingまたはruntime storage shapeの変更は、exact candidate付きのtyped `RestartRequired`として
  拒否する。candidate-bound prepared backend resourceのinstall、capacity変更のcold rebuild/restart実行、
  native backendとのmetadata同時切替は未実装。
- initial activationはshape/byte precheckまではmutation-freeだが、sequential constructor開始後の
  late TCP failureで先行storage clearingとUDP process identityをrollbackしない。typed terminal境界で
  あり、restart/rebuild policyは後続のcontrol/daemon workflowで定める。
- config parse/validate、cold planner、candidate-only `classify_successor`/`plan_successor`、
  semantic diff/generation transition、library-level apply境界は実装済み。initial/in-place/
  restart/rejectedのstatic outcome、policy-only restart、actual publicationのcandidate-preserving
  reject/defer、旧config contentをhigher generation/fresh keyで再planするrollback evidenceまで固定している。
  残るのはbackend/storage resourceのrestart execution、reloadとoperator recovery workflow、
  daemon/CLI/thread/signal lifecycle、persistent diagnostics。
- AF_PACKETはPacketIo RX/live adapter未接続。AF_XDPはnative resource setup/session、UMEM登録、
  XDP attach、core PacketIo接続、実completion drainが未実装。multi-queue worker ownershipも後続。
- R15: allocation-freeでtyped counter snapshot（generation、readiness、firewall/UDP/TCP NAT44の
  saturating累積/high watermark、backend統計拡張点）はruntimeライブラリとして実装済み。structured log、
  queue/capacity high-watermark、drop reasonの内訳、backend mode、およびoperator向けのCLI/`run-sim`出力
  表示（R12依存）は未実装。
- security replay/property smokeはあるが、loom相当、sanitizer、長時間soak、網羅的failure injection、
  privileged netns/hardware matrixは未完成。
- benchmark schema/plan/math validatorはあるが、実packet driver、review済み性能threshold、latency、
  cycles/packet、cache miss、copy/zero-copy判定、10GbE acceptance artifact、hardware runnerがない。

### Open issue hygiene

open issueのうち、#200、#202、#207はactive v0.2 treeより前のcrate、API、reportを前提にする。
issue本文にあるprototype Rustを実装資産として再利用せず、次のmappingをissue tracker側へ
commentした後にsupersedeまたはdeferする。roadmap文書のmergeだけでissueをcloseしたことには
しない。

| Issue | 現在の前提 | v0.2での扱い | Tracker action |
|---|---|---|---|
| #200 DPDK実I/O | 消滅した`ruster-dataplane`、`DpdkPacketIo`、旧`router.toml`を前提 | M2はAF_XDPをproduction backendの第一候補とする。DPDKはP2かM3後に、新backend contractから設計し直すまでdefer | #200へR07/X00–X05を参照するsuperseded/deferred noteを追加し、旧実装taskとしてcloseするか`deferred` labelへ移す |
| #202 OSPF/BGP run loop | active treeに存在しない旧engine、RIB/FIB、main loopを「実装済み」とする | dynamic routingはM3のstatic-router運用後に再scopeする。RFCとblack-box protocol期待値だけを再利用し、旧engine codeは移植しない | #202へP2-ROUTING後の新design issueが必要と記録し、現issueをsuperseded/deferredにする |
| #207 v0.1性能report | 旧benchmark binaryとplaceholder reportを前提 | R17でv0.2 benchmark specを先にfreezeし、X05がそのSHAに対する実測artifactを作る。v0.1 reportへv0.2数値を追記しない | #207へR17/X05 mappingをcommentし、v0.1計測taskとしてsuperseded closeする |

issue整理PR/operationはdocs/code PRと分け、close理由、replacement PR/issue、prototype非再利用を
相互linkする。将来DPDKやdynamic routingを再開する場合も、v0.2 backend/publication/runtime
contractから新しいacceptance criteriaを作る。

## P0/P1/P2 backlog

priorityは実装量ではなく、次milestoneを安全に開始できる順序を示す。

### P0: backendまたはdaemonより前に閉じる

| ID | Work | 理由 / 完了状態 |
|---|---|---|
| P0-INGRESS | ingress L2/martian admission | implemented。foreign unicast、invalid Ethernet source、IPv4 martianをplain/NAT/FW全pathでmutation/state前にtyped dropし、local control/ARP profileを分離 |
| P0-NAT-INDEX | bounded NAT index/allocator | implemented。caller-backed keyed directory/direct ownerでlookup、free-port、expiry/reuseを明示上限化し、TCP mapping再生成はgeneration+epochで旧sessionをlazy invalidation |
| P0-PUBLICATION | publication lifetime contract | partial。owned cold candidate、candidate-bound external storage、core-owned bound backend/exact owner capability、five-service backend-bound initial owner、candidate-only static plan/diff、active-owner read-only delegation、candidate-preserving reject/defer、sealed active view、safe matched-guard gate、same-interface/same-shape all-five successor apply、guard外旧candidate drop、typed flush reportは実装済み。prepared backend resource install、capacity/restart execution、reloadとoperator recovery workflowは未実装 |
| P0-COMPOSE | full service composition | implemented。UDP/TCP NAT+FW+generated ICMPのunaudited/audited public API、sim proof、integration initial owner wiringを保持 |
| P0-BACKEND-CONTRACT | backend conformance suite | implemented for Sim/conformance foundation。lease exactly-once、partial TX、finish error、generated accounting、batch abandon、inner backend quiescence hookとcore-owned identity wrapperを検証。production adapter適用は各backend milestoneで継続 |
| P0-TICK | bounded worker tick | implemented。exact backend precheck、candidate-preserving publication、typed apply report、active failure persistent fail-close、allocation-free steady tick、generation-bound active viewから選ぶbudget/phase順を固定し、RX borrow終了後だけgenerated sessionを開始 |
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
| P1-CONFIG | R09 versioned declarative config | implemented through cold candidate planning。interface、address、route、neighbor、NAT、FW、capacity、tick budgetをparse/validateし、public top-level `ValidatedConfigV1Parts`とnested exact consuming seamsでcurrent owned inventoryを保持する。caller generation/keyとbindしたcandidateを作る。CLI/daemon applyは別項 |
| P1-PLAN-APPLY | R10 validate → plan → apply | library boundaryは実装済み。candidate-only static `PlanSectionDiff`/`PlanGenerationTransition`、initial/in-place/restart/rejected outcome、policy restart、all-five same-shape atomic apply、candidate-preserving actual reject/defer、higher-generation/fresh-key rollback re-planを固定する。R10-009〜012でnested/top-level exact inventory、planner forwarding、source-contract boundaryを、FW-025でlegacy `into_rules` compatibilityを固定する。CLI表示、backend/storage restart execution、reload orchestrationは後続 |
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
| P0-PUBLICATION | R06→integration initial slice→successor apply | cold candidate/storage/initial owner lifetime、allocation-free exact backend binding、sealed/matched guard、candidate-preserving reject/defer/mismatch、rootless bound-backend one-tick、same-interface/same-shape all-five preflight/commit、preflight失敗時の旧active保持、guard外旧candidate drop、typed apply report、higher-generation/fresh-keyで旧config contentを再planするtestは実装済み。capacity/restart execution、prepared backend resource install、独立lifecycle approvalが残る |
| P0-COMPOSE | R05→RI0 | R05がinternal wrapper behaviorを固定し、RI0がunaudited/audited re-export、public compile/full-service integration test、matching requirements rowを同時追加してAPI/security approvalを得る |
| P0-BACKEND-CONTRACT | R07 | `ruster-io-sim`がRX/generated exactly-once、partial reject、finish error、abandon、quiescence hook、foreign wrapper mismatch suiteに合格 |
| P0-TICK | R08 | phase-order trace、全phase budget、RX borrow終了後generated開始、error accounting、active invariant current/next tick fail-close test |
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
- LAN/WAN、route、dynamic ARP、UDP/TCP NAT、FW allow/deny、TTL/host ICMPを含む
  deterministic scenarioがpublic full composition APIを通る。route-unreachable ICMPは
  production full-service candidateが常にfirewallを含む（PUB-001）ため、public full
  composition APIでは意図的に再現不能（ICMP4-012G5、route topology oracle抑制）。この
  1シナリオはpublic full composition API外のcore-levelテスト（ICMP4-012G）で担保する。
- 同じconfig/scenarioはbyte/order-identical resultを返す。
- invalid config/applyは旧publicationとruntimeを変更しない。
- reloadはgeneration境界で行い、capacity変更はrestart-required、rollbackは新generationとなる。
- SIGINT/SIGTERMでlive leaseを残さず、最終counter/config generationを出力して終了する。
- R15のcounter snapshot/health/config generationを`run-sim`出力でoperatorが確認できる。
- R16のparser/state/publication property suiteとbounded fuzz smokeが必須CIで成功する。
- R17がbenchmark specificationをcommitし、そのspec SHAをM1 release evidenceへ固定する。

現在のM1基礎は、versioned configのparse/validate、cold full-service planner、candidate-bound
external storage、five-service initial activation、core-owned bound `SimIo` one tickに加え、
same-interface/same-shapeのsuccessorを全5 runtimeへpreflight/commitするlibrary transactionまで進んでいます。
`classify_successor`/`plan_successor`はcandidate-onlyのstatic decisionをallocation-freeに返し、
active ownerのread-only delegation、全successor outcomeのsemantic diff/generation transition、
Resolution/ICMP policy-onlyのtyped restart-required、Rejectedを含むcandidate-preserving publicationを
固定しています。rollbackは旧config contentをhigher generation/fresh keyで再planするlibrary evidenceがあり、
全履歴key freshnessとcold generation persistenceはcaller責務です。
config transferでは、top-level `ValidatedConfigV1Parts`のpublic `#[non_exhaustive]` boundaryと、nested
Resolution/ICMP/NAT/firewall/tick/storageのexact consuming seamsを分けて維持しています。current sourceの
exact `Self` destructureとplannerのreturned inventory destructureがcompile-time evolution boundaryを作り、
実行時testはcurrent valuesとowned Box pointer identityをforwarding先で確認します。legacy
`ValidatedFirewallV1::into_rules`はrules-only caller向けに復元済みですが、planner pathは
`into_planning_parts`でfirewall rules/policy/state_slotsを全てforwardします。generation、hash key、runtime
authorityのpublication責務はconfig transferの外側にあります。
`run_tick`はpublication後のactive viewからgeneration-bound budgetを選ぶため、成功tickはnew budget、
candidate-safe reject/defer tickはold budgetを使います。foreign backendはcandidate有無にかかわらず全phaseを
skipし、active invariant failureは現tickからpersistentに停止します。R15のruntime `observability` module
（allocation-free typed snapshot、generation、readiness、saturating high watermark、backend統計拡張点）と
R11のdeterministic sim scenario driver（`ruster-sim-scenario`、public full composition API経由のgolden
fixture 9件）も実装済みです。interface/backend resource swap、capacity restart execution、`run-sim`
process（R15 snapshotのoperator向けCLI表示を含む）、reload orchestration、signal/shutdownは未実装です。

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

次のgraphはwork packet間の設計依存を示す。現在のtreeはR01–R09の主要core/config/runtime基盤、
R10のstatic planner、active-owner delegation、candidate-preserving publication、rollback re-plan evidence、
integration initial activation、same-interface/same-shape successor applyまで進んでいる。graph上のR10は
library boundaryの完了に加え、backend/storage restart execution、reload orchestration、operator向けの
plan/apply/rollback transactionを含むwork packetとして扱う。`ruster-integration`
追加時のworkspace memberとlockfileはRI-DEPの一方向依存規則に従い、lower crateからintegrationへの
逆依存はない。

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
| R10 | R09後。config/runtimeの`plan`/`apply` module | static section diff/generation transition、initial/in-place/restart/rejected outcome、all-or-nothing same-shape apply、policy-only restart、candidate-preserving reject/defer、higher-generation/fresh-key rollback re-plan。backend/storage restart executionとreload orchestrationは後続 | failure atomicity |
| R11 | R08後。sim scenario crate/moduleとgolden fixtures | deterministic timestamp/ingress/frame inputとtyped output。packet path Stringなし | test/product |
| R15 | R09後（R09はR08依存）。runtime `observability` moduleと専用snapshot test | allocation-free typed snapshot、generation、health、core state/action/audit high-watermark、backend stats extension pointとsim実装、saturating counters。formatはcold consumerだけ | operations/performance |
| R16 | R01/R03/R04/R05/R06/R08/R09後。`fuzz/`、new property tests、`.github/workflows/fuzz-smoke.yml`だけ | fixed seed/corpusと時間上限を記録し、parser/checksum/state/publication invariants、過去failure corpusをrequired unprivileged smokeで実行 | security/test |
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

cold `FullServiceCandidateV1`はinterface、binding、route、neighbor、firewall rule等のowned
storageとgeneration/key/tick/shape metadataを不可分に持つ。`ruster-integration`の
`FullServiceRuntimeStorage`はcandidateの21-array shape/bytesにbindしてfallibleに確保し、
`activate_initial`成功後はcandidateと全runtimeを`FullServicePublicationOwner`が所有する。initial ownerは
backend未指定のtypestateで、`bind_publication_backend`がinner backendをconsumeして同時発行する
`BoundPublicationBackend<I>`とexact owner capabilityへbindしたownerだけがruntime publication traitを
実装する。checked allocation-free identityが枯渇した場合は`PublicationBindingIdentityExhausted`を返し、
wrap/再利用しない。storage borrowはownerより長生きし、snapshot/config/rules borrowとmutable runtimeは
ownerのsealed active view lifetimeへ短縮される。自己参照struct、leaked allocation、pointer identity再構築で
この制約を回避しない。

初回cold startで現在実装済みの流れは次です。

```text
config parse/validate
→ caller generation/keyでcold candidateをplan/mint
→ candidate-bound external storageをfallibleに確保
→ shape/concrete bytesをprecheck
→ worker開始前にfive-service runtimeをactivate
→ SimIo::new()をbind_publication_backendへconsumeしてexact wrapper/capabilityを作る
→ initial ownerをcapabilityへbindし、sealed active viewをborrowしてbound Sim tickを実行
```

shape/byte mismatchはconstructor前にexact candidateと無変更storageを返します。constructor開始後の
late failureはcandidateを返してもstorage/process identityをrollbackしないterminal boundaryです。
現行のsame-interface/same-shape successorはinitial helperでruntimeを再生成せず、既存21 backingと
runtime identityを再利用して次のtransactionを実行します。

```text
successor candidateをmoveでrun_tickへ渡す
→ candidate有無より先にexact owner/backend wrapperを照合する
→ inner backendのquiescence check後、raw guardをownerへmatchしてopaque guardにする
→ matched guard保持中にstatic successor、same interface、same storage shapeを検査
→ Resolution → ICMPv4 error → UDP NAT → TCP NAT → firewallのpermitを全取得
→ 全permitを失敗不能commitしてold worker-local stateをflush/rebind
→ active candidateを最後に置換してgeneration/tick/authorityを同時にactive化
→ matched guardを解放し、退避したold candidateをdropする
→ typed apply reportを返し、new active viewのbudgetで同じtickのRXを再開
```

raw guardをexact ownerへ照合するsafe entryはruntime-owned `try_publish_candidate`だけです。照合済み
`MatchedPublicationQuiescenceGuard`を受け取るexternal adapter hookは
`unsafe fn publish_candidate_authorized`で、safe callerがmatchを省略するdirect pathはありません。inner backendの
`PublicationQuiescenceBackend`実装が、事前alias、`Arc`/shared physical resource、interior mutabilityを含む
全authoritative ownershipを`check_publication_quiescence`で、現在I/O可否を`current_io_disposition`で、check
error後のI/O可否を`quiescence_error_disposition`で正確に報告し、一度返した`Stop`をbackend valueの寿命中
terminalに保つことがsemantic trust境界です。shared stateをこれらの報告から隠してはなりません。inner traitは
identity、guard constructor、binding accessorを持ちません。

`BoundPublicationBackend`はimmutable inspection以外のgeneric `&mut I`、consuming extraction、whole innerの
move/replace/swap seamをsafeに公開しません。backend固有のmutationは`unsafe trait PublicationBackendControl`の
closed command/responseへ限定し、safeな`execute_backend_command`はaudited `unsafe impl`へ依存します。その
Safety contractは、whole innerをmove/replace/swap/returnしないこと、authoritative stateへの独立mutable aliasを
作らないこと、hidden/shared stateをquiescence対象から切り離さないこと、check/current/error dispositionを正しく
分類すること、terminalな`Stop`となったbackend valueを再利用しないことです。したがってtyped commandの正当性は
単なるsafe traitのsemantic trustではなく、publication authorityを保つunsafe implementation trust boundaryです。
`SimIo`はclosed enumとquiescence visibilityを根拠に局所的な`SAFETY` comment付き`unsafe impl`を持ち、
`BoundSimIoControl`はinject、RX/TX queue inspection、TX/recycle dequeueだけをsafeに公開します。

preflight途中の失敗は先行permitを無変更でdropし、旧active/runtimeとexact candidate ownershipを
保持してbackend guardを解放します。candidate入力だけに起因する`InvalidSuccessor`/`RestartRequired`は
`ContinueOldIo`です。既存runtime/authorityのcoherence failureはcauseをownerへpersistentにlatchし、現tickと
candidate-freeな後続tickの全phaseを`ActivePublicationInvalid`で停止します。foreign same-type backendは
quiescenceより前にcandidateの有無を保った`BackendMismatch`となり、ownerをpoisonしません。
interface bindingまたはstorage shapeが変わるcandidateはcommitせずtyped `RestartRequired`を返します。
native interface/backend resourceを切り替える後続sliceでは、失敗し得るallocation、socket/mmap/bind/attachを
candidate側でcold prepareし、guard下commitを失敗不能なowned resource swapだけに限定します。容量変更は
in-place resizeせずrestart executionへ送り、rollbackは古いgeneration/hash keyを再利用せず、旧内容から
higher generation/fresh keyの新publicationを作ります。

### Operability minimum

- startup summary: config generation、interfaces/queues、backend、copy/zero-copy、capacities
- health: worker alive、last successful tick、RX/TX progress、clock regression
- saturation: RX/TX/FILL/COMPLETION、NAT/FW/resolution/action/audit high-watermark
- policy: stable DropReason、FW rule/default、state failureをbounded counterでexport
- reload: plan、apply result、flushed state数、restart-required reason
- shutdown: RX停止、generated/TX flushまたはtyped reject、descriptor回収、program detach policy

library-level successor applyはprevious/new generationと全5 serviceのflush reportをtyped resultとして
返します。operator向けsnapshot、structured log、CLI表示、persistent historyへのexportはR15/R12の
後続です。packet pathでlog messageをformatせず、typed counters/eventsをworker-local fixed storageへ
記録し、control threadがtick boundary後にsnapshotして文字列化します。

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
