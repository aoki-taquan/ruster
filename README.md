# ruster

自宅ラボで実用でき、挙動を自分で説明できるソフトウェアルータを、パケット処理コアから作るプロジェクトです。

`main`の旧実装は [`prototype-v0.1`](docs/prototype-v0.1.md) として固定しました。現在の
active treeは、そのコードを継承しないv0.2のゼロベース実装です。

## v0.2 bootstrap

active treeは、外部依存を持たないpacket core、bounded worker runtime、sim I/O、
benchmark harness、I/O conformance、AF_XDP ownership modelに加え、cold config/controlと
one-wayなintegration composition layerで構成します。data-plane、runtime、integration、I/Oの
library crateは外部依存を持ちません。cold control-planeの`ruster-config`だけは、保守されている
Serde/TOML parserを最小featureで利用します。

- `ruster-config`: 最大1 MiBのUTF-8 TOMLをschema versionでpredispatchし、V1の
  interface/address/route/neighbor/NAT44/firewall/capacity/tick budget DTOへexact decode
  する。unknown/duplicate field、runtime生成値、過大listをvalue-freeなtyped diagnosticで
  fail-closeする。cold semantic validationはcanonicalなowned core値、connected route、
  cross-reference/on-link検証、policy/NAT/firewall検証、全runtime storage shapeを作る。
  publication非依存の`into_parts`はvalidated table/rule Boxを再確保せず後段へmoveする。
  generation、hash key、publication型、runtime allocation、activation、applyは持たない。
- `ruster-control`: `ValidatedConfigV1`とcaller-supplied generation/typed hash keyをconsumeし、
  forwarding tableとfirewall rulesをclone/reallocationなしで`PublicationPlan`へmoveする。
  full-service欠落はstable typed failureで拒否してconfig/inputs ownershipを返す。interface metadata、
  tick、required runtime bytesは同じgenerationへtagしたopaque planへ保持する。planner-produced
  `FullServicePlanV1`では、metadataを保持するpublic consuming transitionは不可分なcandidate
  transitionだけであり、publication authorityをmintしてmetadataと一緒に保持する。このplanner pathの
  mint失敗はplanをconsumeする。public `FullServiceCandidateError`はprocess-lifetime terminalな
  forwarding/firewall publication nonce exhaustionを区別し、その他のlower-level validation errorは
  caller-correctableでないvalue-freeな`InternalInvariantViolation`へcollapseする。activation/apply
  failureではない。key生成・全履歴freshness証明、activation、applyは未実装。
- `ruster-core`: backend所有packetを借用し、Ethernet II / IPv4検証、LPM、
  TTL/checksum/MAC rewrite、local IPv4向けARP reply、static neighbor miss時の
  ARP Request生成action、fixed-capacity dynamic ARP cache、local ICMPv4 Echo
  responder、ICMPv4 Time Exceeded / Destination Unreachable生成、opt-inの
  single-domain UDP NAT44/NAPT、outbound-initiated TCP NAT44/NAPT、最小IPv4
  stateful forward firewallを扱う。
- `ruster-io-sim`: rootやNICなしでRX/generated TXのFIFO、budget、TX/drop、
  traceを決定的に検証する。
- `ruster-io-afpacket`: Linux AF_PACKET/TPACKET_V3 backendのchecked configuration、
  fixed IfId mapping、ring ownership/UAPI scaffold。combined mmapのRX/TX extentを
  overlap/gap/overflow/実address alignmentまで検証し、後続state machine用metadataを
  resource取得前のcold pathで固定長preallocateする。内部TX engineはfixed frameへexact
  one-copyでpublishし、FIFO completionとendpoint単位のnonblocking kickをboundedに処理する。
  `AfPacketIo`としてcore `PacketIo`を実装し、USER所有TPACKET_V3 blockに対する
  zero-copy RX leaseとTX engineを結合する。検証はscripted kernel seamによる
  model levelのみで、実NIC/privileged netnsでの実測は未実施。
  64-bit Linux、SOCK_RAW Ethernet II、PACKET_RESERVEなしのstrict profileで、TX
  requestのretire timeout/private/feature fieldsはzeroに限定する。RX private areaは
  kernel同様に8-byte alignした`BLK_PLUS_PRIV`を使い、宣言した最大Ethernet frameを
  block内で切り詰めず保持できるgeometryだけを許す。Linux syscallとtest scriptは
  privateなstatic dispatch seamを共有するが、public live adapter、copy/zero-copy mode、
  RX、poll、cleanup/stats、実NIC throughputを主張する段階ではない。
- `ruster-io-xdp`: AF_XDP native接続より前に固定するpure-Rust ownership model。
  UMEM layout、descriptor境界、nonzero generation token、frame state ledger、
  fixed-storage ring、authoritative ledgerと結合したfinite fake kernelを持つ。socket、
  native ring、FFI、core `PacketIo`接続はまだ持たない。
- `ruster-io-xdp-native`: Linux v6.8 AF_XDP UAPIのC layout、raw flag profile、
  2048/4096-byte aligned UMEMと固定256-byte kernel headroomを含むring geometry、
  kernel報告mmap offsetをcold pathで検証するnative scaffold。caller-owned mappingを
  排他的にborrowするFill/TX producerとRX/Completion consumerは、wrapping cursor、
  Acquire/Release publication、need-wakeup flagをallocationなしで扱う。後続resource setup用の
  private x86_64 Linux syscall/RAII seamは、CLOEXEC/nonblocking AF_XDP socket、socket option、
  mmap/munmap、bind、poll、sendto、closeをdependencyなしで包み、fd/addressをDebugから
  redactしてcleanupを高々一回にする。他の64-bit Linux architectureはC0/C1のpure ABI/ring
  validationを狭めず、別のtyped syscall capability checkで拒否する。publicなsocket/mapping
  constructor、UMEM登録、
  ring設定・bind transaction、live session、libxdp link、core `PacketIo`接続はまだ持たず、
  FFI/pointer accessはprivateな`native_unsafe` moduleだけに閉じる。
- `ruster-runtime`: core-ownedな`BoundPublicationBackend<I>`とexact owner capabilityへbindした
  publication seamから一つのactive generationを借用する。
  `RX → resolution timer → failure dispatch → generated ARP → generated ICMPv4`をsingle-worker tickとして
  実行する。`TickBudgets`はcallerの
  独立引数ではなく、publication後のtick-local `FullServiceView`がactive generationと一緒に所有する。
  safeな`try_publish_candidate`だけがraw quiescence guardをownerへ照合し、成功時だけopaque matched
  guardで`unsafe`なadapter hookを呼ぶ。candidate reject/deferではexact candidateをcallerへ返し、
  candidate-safe errorは旧active generationを継続する。active invariant failureはpersistentにlatchして
  現tick以降の全data phaseを停止し、exact backend照合後は後続candidateをbackend quiescenceより前に同じ
  latched typed causeでrejectする。quiescenceを経てcandidateがApplied/Rejectedになった後もdata phase前に
  backendのcurrent I/O dispositionを再取得し、terminal `Stop`ならdata phaseをskipする。成功時は
  `PublicationOutcome::Applied`でadapter固有のtyped reportを返す。`FullServicePublication`は`unsafe trait`で、
  candidate provenance、atomic install、binding安定性、必須のimmutable `active_status`
  （`Absent`/`ContinueOldIo`/`StopOldPublication`）をimplementorの監査契約として課す。backend mismatch判定は
  この`active_status`だけを参照しmutableな`active()`は呼ばない。viewはprivate fieldでmutable runtimeを封じ、
  authorityだけをread-onlyに公開する。`observability`moduleはallocation-freeでgeneration付きの
  typed snapshot（`readiness`、firewall/UDP/TCP NAT44のsaturating累積とtickごとのhigh watermark、
  backend固有統計を運ぶ拡張点`BackendObservabilityStats`）を提供し、生成自体はcold consumer向けの
  formatを一切行わない。
- `ruster-integration`: `ruster-control`、`ruster-core`、`ruster-runtime`の上にだけ依存する
  composition root。candidateの21-array concrete shape/byte metadataを照合してexternal fixed
  storageをfallibleに確保し、Resolution、ICMPv4 error、UDP/TCP NAT44、firewallとcandidateをunboundな
  `FullServicePublicationOwner`へcold activateする。worker開始前に`bind_backend<I>`がfactory発行のexact
  owner capabilityとbackendを受け取り、exact identity照合・quiescence成功・`current_io_disposition`が
  `ContinueOldIo`であることを検証できた場合だけbackend-bound typestateへ移すfallible transitionを実行する。
  失敗時はunbound ownerとbinding capabilityを`InitialBackendBindFailure`からretry可能な形のまま回収できる。
  bound ownerだけがruntimeの`FullServicePublication`を実装する。storageはownerより長生きし、active viewは
  generation-coherentかつsealedである。same-interface/same-shape successorは5 runtimeすべてを
  mutation-freeにpreflightし、全permitが揃った後だけinfallible commitしてcandidateを最後にswapする。
  旧candidateの所有allocationはbackend quiescence guard解放後にdropする。`FullServiceApplyReport`は
  旧/新generationと各serviceのflush reportを返す。interface bindingまたはstorage shape変更はexact
  candidateを保持した`RestartRequired`であり、prepared backend/native interface resource swap、
  AF_PACKET/XDP接続、capacity rebuild、rollback UXは後続である。
- `ruster-sim-scenario`: `ruster-config`/`ruster-control`/`ruster-runtime`/`ruster-integration`/
  `ruster-io-sim`のpublic full composition APIだけを経由してmulti-tickのdeterministic router
  scenarioを駆動する。ingress frameとtyped outcomeはpacket pathに`String`を使わず、呼び出し側が
  与える論理clock（`MonotonicMillis`）だけで進み、wall clockを読まない。LAN内ARP解決/転送、
  WAN route経由のUDP/TCP NAT44、firewall allow/deny、複数tickのdynamic neighbor解決、TTL超過と
  ARP解決失敗によるICMPv4生成、同一scenarioの完全なbyte/順序一致replayをgolden fixtureとして持つ。

```text
inject Vec<u8>
      │
      ▼
sim RX slot ──borrow──► ruster-core ──commit──► sim TX slot
                            │
                            └──recycle────────► drop capture
```

fast pathはpacket batchをworkerが専有します。共有`Mutex`、packet単位の`String`、
packet clone、`dyn PacketIo`を導入しません。simの`Vec`はcold I/O境界に閉じています。
ARP replyも同じRX bufferをin-placeで書き換え、受信interfaceへcommitします。現在の
ARP profileはinterfaceごとにlocal IPv4を一つだけ持つ静的snapshotです。
同じbinding宛てのICMPv4 Echo Requestも、checksumとsource admissionを完了してから同じ
RX bufferをEcho Replyへ書き換えます。local宛ての未実装protocol/controlはroutingへ
fall throughせず、typed consumeで終端します。

static neighbor missでは元IPv4 packetをbyte不変でrecycleした後、worker-localな固定
storageでARP Requestを生成します。defaultは1秒間隔、total 3 attemptsで、
traffic-independentなbounded timer pollがretryとterminal `Failed` hold-downを進めます。
これらのretry回数・schedule・Failed/hold-downはRFC固定値ではなくlocal policyです。
RX batchとgenerated TX sessionは二相に分離し、生成frameもbackend所有bufferを借用します。
ARP Reply/RequestはRFC 826 mergeでworker-local cacheへ学習し、matching retry/Failed stateを
cancelします。packet bufferのhold/replayは行いません。directly-connected targetの最初の
eligible missだけは別caller-backed slotへ最大548-byte IPv4 quoteをcopyし、少なくとも一つ
accepted ARP Requestを含むgenerationがfruitlessに終わった場合、bounded dispatchから
ICMPv4 Destination Unreachable Type 3/Code 1を生成できます。元RXは直ちにrecycleされ、
ARP成功時にも自動replayしません。gateway failureはCode 1対象外です。

nonlocal IPv4はoptions/local判定後にまずLPMします。routeが無ければ元packetをbyte不変の
`RouteMiss`でdropし、eligibleならICMPv4 Destination Unreachable Type 3/Code 0をqueueします。
routeがありTTL 0/1なら`Ipv4TtlExpired`とTime Exceeded Type 11/Code 0です。両kindは同じ
fixed-capacity worker-local FIFOとper-egress default 100ms timer limiterを共有します。
逆経路は元sourceへの通常LPMで選び、受信Ethernet sourceをnext-hopとして信用しません。
staticまたはfresh dynamic neighborが無い場合はARPだけを開始し、今回のICMP actionは保持
しません。generated outer IPv4は576 bytes以下、quoteは受信時IPv4 bytesを最大548 bytes
所有し、link paddingを含みません。

EtherTypeを読んだ直後、IPv4/ARPはsnapshot上の正確なingress interfaceを解決し、
Ethernet sourceのzero/broadcast/multicastをstableなtyped reasonでbyte不変dropします。
IPv4 destinationはそのingress interface MACとの完全一致を要求し、ARP destinationだけは
完全一致またはexact broadcastを許可します。別interfaceのrouter MACを含むforeign unicast、
ARP destinationのzero/multicastもprotocol parser、時刻・state・action mutationより前に
拒否します。Ethernet sourceとARP SHAの一致は要求せず、individual unicast sourceは許可します。
VLAN/QinQ (`0x8100`/`0x88a8`) はinner frameを解析せず`UnsupportedEtherType`です。

IPv4の構造とheader checksumを検証した後、`0/8`、`127/8`、multicast、`240/4`の
source/destination、limited broadcast、routerのいずれかのlocal IPv4を名乗るsourceを
stableなtyped reasonでbyte不変dropします。forward対象ではsourceとdestinationの
LPM-selected prefixに対するnetwork/directed-broadcastも拒否します。
more-specific host routeを優先し、RFC 3021の`/31`とhost routeの`/32` endpointは許可します。
このcommon admissionはNAT/FWの時刻・state・audit、resolution、ICMP error actionより前です。
同一interfaceへrouteされるpacketもこの正確なingress MAC admissionを通れば従来どおり
forwardできます。generated ARP/ICMPはRX admissionを通らず、egress interfaceから正しい
Ethernet sourceを組み立てます。limited broadcastを転送しないRFC 1812 §5.3.5.1の境界は
実装済みですが、同節のlocal receptionはupper-layer delivery/BOOTP relayが
未実装のためdropする明示deviationです。

UDP NAT44は`forward_batch_with_nat44_udp`、またはgenerated ICMP errorも含む
`forward_batch_with_nat44_udp_and_icmpv4_errors`を選んだworkerだけで有効です。一つの
inside/outside/public IPv4とnonzero port poolを設定し、mappingとremote-address filter
peerに加えてmapping/peer directoryとpublic-port ownerをcaller-backed固定配列で所有します。
control planeはruntime生成とreconcileごとにfreshな`Nat44UdpHashKey`を供給します。
mapping/peer/public-port lookupは固定capacityでbounded、port allocationはpoolを最大一周し、
候補ごとのmapping全走査は行いません。outboundはEndpoint-Independent Mapping、
inboundは過去に送信したremote IPv4だけを許すAddress-Dependent Filteringです。
IPv4 optionsなし、DF=1/MF=0/offset=0のatomic UDPだけを変換します。受信reserved flagは
fragment判定から除外し、NAT rewrite後もwire上に保存します。UDP checksum zeroを保存、
nonzero checksumとIPv4 checksumをRFC 1624でincremental更新します。

idle TTLはdefault 300秒、minimum 120秒で、outbound TX requestだけがrefreshします。
live stateをcapacity pressureでevictせず、snapshot/config mismatchはfail closedです。
NAT runtimeへ到達した非退行時刻はdrop結果でもwatermarkへ反映し、expired/miss後の古い
時刻によるmapping復活を許しません。outsideからinsideへのpublic DNATを通らない直通LPMも
neighbor解決前にfail closedです。
publication変更はvalidated config、fresh hash key、reconcile permitの事前検証後に行う
明示的な全state/index flushを要求します。`storage_shape`はmapping/peerと全index backing
arrayのcapacityを一つのopaque valueとして返します。policyで明示的にopt-inした場合だけ、
outside/public宛てICMPv4 Type 3/Code 4が
引用するlive UDP mapping/ADF peerをread-only参照し、outer destinationと引用source tupleを
insideへ戻します。outer sourceはexternal host-unicastかつoutsideへのreverse LPMを要求する
local strict-uRPF policyで、asymmetric external pathを意図的に拒否します。中継routerの
addressは引用remoteと異なっていても保存します。fragment、hairpin、private発の
ICMP error、他のtype/codeとquery NAT、local MTU起因のType 3/Code 4生成、PMTU cache、
static forward、
multi-public、port randomization/parity、full packet filterはdeferredで、RFC 4787/7857全体への
準拠は主張しません。
引用UDP/TCP IPv4 headerもreserved flagをfragment判定から除外し、reserved以外は
DF=1/MF=0/offset=0を要求します。引用reserved flagはtuple rewrite後も保存します。

TCP NAT44は別のcaller-backed mapping/session storage、両keyed directory、direct
public-port ownerを持ち、UDPと同じ数値public portを独立して使用できます。freshなTCP専用
redacted keyとgeneration+lifecycle epochでstale authorityを遮断します。mappingはinternal
TCP tupleのEndpoint-Independent Mapping、filterは
remote IPv4とremote TCP portのexact matchです。新規sessionはoutbound SYN=1かつ
ACK/RST/FIN=0だけが作成し、既存sessionではSYN-ACK、data、FIN、RSTを含むvalid packetを
双方向に変換します。TCP header/options/dataを含むIPv4 payload全体のchecksumをstate更新前に
検証し、address/port rewrite後もRFC 1624で更新します。TCPでは算術結果zeroもwire zeroの
ままです。TCPもreserved flagをfragment判定から除外してwireへ保存し、reserved以外は
DF=1/MF=0/offset=0を要求します。

outbound lookupはmapping/session/port pool capacityをそれぞれ最大1回だけ調べる
additive `O(M+S+P)`、inboundとquoted ICMPはdirect owner後にexact sessionだけを調べます。
mapping再生成時は旧sessionを全走査せずgeneration+epochでlazyに無効化します。

TCP session idle TTLはdefault/minimumともに2時間4分です。sequence/window/ACK妥当性は追跡
せず、FIN/RSTもsessionを削除・短縮せず通常のsuccessful TX requestとしてTTLだけをrefresh
します。この保守的な単一timer profile、recommended EIF/ADFより厳しいconnection-dependent
filter、fragment/hairpin未実装を明示し、RFC 5382全体への準拠は主張しません。TCPもpolicyで
opt-inしたType 3/Code 4だけ、引用public source portとexact live remote address/port sessionを
read-only参照してinsideへ変換します。UDP-only/TCP-only wrapperは他方のprotocolがdomainを
crossするとfail closedにし、combined wrapperはinside/outside/public realm一致を要求します。

IPv4 forward firewallは`forward_batch_with_firewall`を選んだworkerだけで有効です。immutableな
ordered rule sliceとmutableなfixed-capacity state sliceをcallerが所有し、first-matchの
`AllowStateful`/`Deny`とimplicit default denyを適用します。対象はoptionsなし、DF=0または
DF=1のnonfragment UDP/TCPです。ARP、router-local、router-originated generated packetは対象外で、
その他のforward protocol、options、MF/fragment offsetはfail closedです。reserved flagだけでは
dropせずforward wireに保存します。UDP checksum zeroは許可し、nonzeroはfull検証します。
UDPはexact reverse pseudo-session、TCPはinitial SYN
だけが新規stateを作り、tupleとorigin ingress/egressの完全一致だけをlocal `ESTABLISHED`として
扱います。これはTCP sequence/window stateやRFC 5382/7857全体への準拠を意味しません。
snapshot/rule fingerprintは設定publication時に固定します。control planeがpublicationごとに
生成する非ゼロ128-bit `FirewallHashKey`を必須とし、established lookupはforward/reverse共通の
keyed canonical hashとopen addressingで行います。秘密鍵生成のrandom/syscallはfast path外です。
generation更新時のkey再利用は拒否します。capacity 4以上は最大75%のusable loadに制限し、
packetごとの期限切れmaintenanceは最大1回のbackward-shiftと1回の再scanだけです。したがって
worst caseはtable容量に線形で、繰返しattemptにより漸進回収します。新規flowだけordered
ruleをscanします。
non-regressiveなvalid attemptはdeny/missでもsecurity watermarkを進め、古い時刻でのstate
復活をfail closedにします。`*_audited` APIはcaller-backed固定bufferへRuleId/default、
matched action、New/Established、terminal failureとeffective `Allow|Drop` verdictをpacket順に
保存します。

NATとのcombined APIではoutboundをpre-SNAT internal→remote、inboundをpost-DNAT
remote→internalのcanonical tupleで照合します。NAT mappingだけではinboundを許可せず、exact
reverse firewall stateが無ければinside neighbor処理前にdenyします。packet rewrite成功後、
NAT/FW stateをTX request前にcommitするためbackend rejectでも両stateを保持します。ICMPv4
Type 3/Code 4はopt-in NAT translationがmapping/sessionから復元したpre-SNAT
internal→remote tupleを、firewall origin stateへdirect exactかつread-onlyで照合します。
hitだけを`RELATED`として許可し、missは`FIREWALL_RELATED_ICMPV4_STATE_MISS`でneighbor処理前に
silent dropします。lookupはrule scan、reverse match、activity/phase/counter/watermark更新を
行いません。NATを伴わないplain forwarded RELATEDはdeferredで、既存の
`FIREWALL_RELATED_ICMPV4_UNSUPPORTED` discriminantは予約したままです。

UDP/TCP NAT44、firewall、router-originated ICMPv4 errorを同じworkerへbindする場合は、
`forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors`または監査付きvariantを
選び、`Icmpv4ErrorRuntime`を必須で渡します。firewall deny、authority failure、route missは
silentのままで、認可後のeligible TTL expiryはSNAT前の受信IPv4をquoteしてactionをqueueします。
RX batchとgenerated TXは融合せず、既定のworker tick順どおりRX完了後に生成します。生成packet
そのものはfirewallの対象外です。既存のICMP runtimeを取らないcombined APIは変更しません。
ICMPv4 error publication preflightはstate側の`action_slot`とaction側の`state_index`による双方向
backreferenceを検証します。action arrayを2回、state arrayを1回だけ走査する`O(A + S)`境界で、
nested searchを行いません。commitも各arrayを1回clearする線形処理で、corruption rejectionとpermit
Dropはruntimeを変更しません。
`ruster-runtime`はcandidate publicationをtick先頭でatomicに試し、成功時はadapter固有の
typed apply reportを`PublicationOutcome::Applied(report)`で返します。candidate-safe rejectは旧active
publicationで継続しますが、active runtime/authority invariant failureは`StopOldPublication`として
persistentにlatchし、exact backend照合直後・quiescence要求より前にこのlatchを同じtyped causeで優先
rejectします。rejectしたtickとcandidate-freeな後続tickの全data phaseをtyped skipします。quiescenceを
経てcandidateがApplied/Rejectedになった後もdata phase前にbackendのcurrent I/O dispositionを再取得し、
terminal `Stop`ならdata phaseをskipします。active publicationがなければpacket I/Oを開始せず同様に
skipします。presence/skip判断は必須のimmutable`active_status`（`Absent`/`ContinueOldIo`/
`StopOldPublication`）だけを参照し、mutableな`active()`は呼びません。RX batchはfull composition wrapperへ
moveされ、そのborrowが終了した後だけgenerated sessionを開始します。
各phase reportは固定サイズで、RX errorとgenerated error、clock regression、budget exhaustion、
allocation/build/finish/accounting failureを区別します。backendのTX acceptedはdescriptor publicationで
あり、wire送信やcompletion queue返却を意味しません。tick-local `FullServiceView`は非ゼロgenerationと
そのgenerationの`TickBudgets`を48-byte値`ActiveTickAuthority`へ集約して1本の参照で持ち、
`run_tick`はpublication phase後にborrowしたactive viewからbudgetを得ます。したがって同じtickでも
Appliedは新generationのbudget、`ContinueOldIo`のRejected/DeferredとUnchangedは継続中generationのbudgetを
使い、`StopOldPublication`および post-attempt `BackendStopped`ではdata phaseを実行しません。successor
適用時はcandidate-last swap直前に`ActiveTickAuthority`全体を一体更新するため、generationとbudgetは常に
coherentです。UDP/TCP NAT44とfirewallの各configは対応するoptional runtimeと
nested viewで対にし、resolutionとgenerated ICMP runtimeは直接borrowのままです。現行core full wrapperは
3 configを必須とするため、service pair全体の不在表現はoptional-config composition seamを追加する
後続作業です。
`ruster-integration`のinitial pathはvalidated planner candidateにbindしたexternal fixed storageを
fallibleに確保し、shapeとconcrete byte totalをruntime constructorより前に照合します。成功時はまず
5 service runtimeとcandidateをunbound ownerへcold activateし、worker開始前に
`bind_publication_backend`が発行したexact owner capabilityとbackendを`bind_backend<I>`へ渡します。
`bind_backend`はexact identity照合・backend quiescence成功・`current_io_disposition`が`ContinueOldIo`で
あることを検証できた場合だけbackend-bound typestateへ移すfallible transitionで、失敗時はunbound owner/
binding capabilityを`InitialBackendBindFailure`からretry可能な形のまま回収できます。このbound owner
だけがruntime publicationを実装し、rootless`SimIo` tickから同じgenerationをborrowします。`SimIo::new`と
`Default`はpacket/quiescence単体用途のstandalone inner backendであり、publication pathでは必ずfactoryが
返す`BoundPublicationBackend<SimIo>`を使います。shape/byte precheck failureはstorageを変更せずexact
candidateを返します。一方、constructor開始後のlate TCP failureではcandidate ownershipは返りますが、
先行runtimeによるstorage初期化やUDP process identity消費はrollbackしないterminal boundaryです。
successor pathは同じinterface bindingと21-array storage shapeに限定し、Resolution、ICMPv4 error、
UDP/TCP NAT44、firewallの全preflightが成功するまで旧runtimeとcandidateを変更しません。その後の5
commitはinfallibleで、active candidateを最後にswapし、旧candidateはbackend guard解放後にdropして、
旧/新generationと各service flushをtyped reportで返します。interface/storage変更はcandidate-preserving
`RestartRequired`です。prepared backend/native interface resource swap、AF_PACKET/XDP backend接続、
capacity rebuild、rollback-as-new-generationのoperator UXは後続です。

`bind_publication_backend`はinner backendをconsumeするcore-ownedな`BoundPublicationBackend<I>`と、
そのexact wrapperだけに対応するmove-only owner capabilityを返します。private `NonZeroU64` identityの
採番はallocation-freeなchecked monotonic counterで、最後の値の後はtyped
`PublicationBindingIdentityExhausted`となり、wrap、回復、identity再利用によるABAを許しません。
wrapperはimmutable inspection以外のgeneric `&mut I`やconsuming extractionをsafeに公開せず、whole innerを
move、replace、swapするgeneric seamも持ちません。backend固有のmutationは
`unsafe trait PublicationBackendControl`のclosed command/responseをsafeな`execute_backend_command`経由で
実行します。このsafe methodはaudited `unsafe impl`へ依存します。各implementationはwhole innerの
move/replace/swap/return、
authoritative stateへの独立mutable alias、hidden/shared stateのquiescence対象からの切離し、
`check_publication_quiescence`/`current_io_disposition`/`quiescence_error_disposition`の誤分類、一度`Stop`となった
backend valueの再利用を禁止するpublication-authority contractを守らなければなりません。これはmemory safety
ではなくunsafe implementation trust boundaryです。`SimIo`は局所的な`SAFETY`根拠を付けた`unsafe impl`を持ち、
`BoundSimIoControl`はinject、RX/TX queue inspection、TX/recycle dequeueだけをsafeに公開して、owned `SimIo`や
独立mutable aliasを返しません。

runtimeはcandidate有無を調べる前にownerとbackendを照合します。same-typeのforeign wrapperなら
candidateを`Option`のままexactに保持した`BackendMismatch`とし、quiescence、publication hook、RX、timer、
failure、generatedの全phaseを実行せず、そのtickだけfail-closeします。ownerのactive healthはpoisonしません。

exact backendにcandidateがあるtickだけ、sealedな`PublicationQuiescence`がinner backendの
`PublicationQuiescenceBackend::check_publication_quiescence`を呼びます。inner `I`はfactoryへ渡す前から
alias、`Arc`で共有したstate/physical resource、interior mutabilityを持ち得ます。backend実装がそれらを
含むauthoritative ownershipを`check_publication_quiescence`で、現在I/O可否を
`current_io_disposition`で、check error後のI/O可否を`quiescence_error_disposition`で正確に報告し、
一度返した`Stop`をbackend valueの寿命中terminalに保つことがsemantic trust境界です。shared stateを
これらの報告から隠してはなりません。check成功後、core-owned raw guardをowner capabilityがidentity
照合してopaqueな`MatchedPublicationQuiescenceGuard`へ変換します。safeな
`try_publish_candidate`だけがこの照合を行い、成功時だけexternal adapterの
`unsafe fn publish_candidate_authorized`を呼べます。unfinished RX/generated batch、terminal action未完了の
leased slot、またはcompletion待ちTXがあればcandidateをadapterへ渡さず、backendのtyped dispositionを伴う
`Deferred`とします。Simではaccepted TX completion待ちだけが旧activeでI/Oを継続でき、unfinished batch
またはterminal未完了leaseは旧activeを保持したまま全data phaseをskipします。candidateなしのtickはguardを
取得せず、backendのboundedなread-only current-I/O dispositionを使います。`SkipIo`は明示的なownership
回収まで継続し、`Stop`はbackend valueの寿命中terminalです。未知errorは保守的にI/Oをskipします。Sim
backendの出力queue完了は保守的なmodelであり、AF_XDP CQ drainを実装・証明したものではありません。

## 開発

stable Rustだけで検証できます。

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --doc --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo check --workspace --all-targets --all-features --locked
scripts/check-requirements.sh
scripts/test-check-requirements.sh
```

CIの`Musl` jobは、固定したRust 1.97.1へtargetを追加して次のcheckも実行します。

```bash
rustup target add --toolchain 1.97.1 x86_64-unknown-linux-musl
cargo +1.97.1 check --workspace --all-targets --all-features --locked --target x86_64-unknown-linux-musl
```

これはmusl targetでworkspace全体が型検査を通ることだけを確認するcompile-only portability
checkです。musl向けartifactのlink、test実行、実NICでのruntime compatibilityは保証しません。

設計契約と非対象は[architecture v0.2](docs/architecture-v0.2.md)、要件とRFC根拠は
[requirements](docs/requirements-v0.2.md)、production backendから自宅ラボ運用までの
優先順位とmilestoneは[development plan](docs/development-plan-v0.2.md)を参照してください。
