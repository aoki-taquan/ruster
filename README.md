# ruster

自宅ラボで実用でき、挙動を自分で説明できるソフトウェアルータを、パケット処理コアから作るプロジェクトです。

`main`の旧実装は [`prototype-v0.1`](docs/prototype-v0.1.md) として固定しました。現在の
active treeは、そのコードを継承しないv0.2のゼロベース実装です。

## v0.2の構成と現在地

M1（Runnable deterministic router）では、rootやNICなしで宣言的configから
`config → validate → publication candidate → live activation → run_tick → observability →
run-sim JSONL`をend-to-endで実行できます（下の「使い方」）。backendは決定的な`SimIo`だけで、
AF_PACKET/AF_XDPはproduction backendではなく、実NICでの動作やthroughputは主張しません。
M1は2026-11-01にcloseしました（9 exit criterionすべてmet。`R16A Bounded`はrequired checkです）。
exit criterionごとの証跡は
[`docs/release-evidence/m1.md`](docs/release-evidence/m1.md)にあります。M2
（[Operable AF_XDP static router](docs/development-plan-v0.2.md#m2-operable-af_xdp-static-router)）は
openです。そのうちM2a（`ruster run`の下で動くcopy-mode、portごとに1 queueのAF_XDP router、veth
E2EをCIで実行。coordinatorのscoping提案でowner決定ではない）は完了し、exit criterionごとの判定は
[`docs/release-evidence/m2.md`](docs/release-evidence/m2.md)、運用手順は
[`docs/runbook-m2.md`](docs/runbook-m2.md)にあります。multi-queue、zero-copy、X05 hardware
benchmark（M2b）はowner決定（2026-11-02）でdeferredです: multi-queueは2a「C」で当面portごとに1 queue
（X05のNIC選定と合わせて再検討）、X05 labは当面不要で運用はveth（実NIC/native/zero-copy未検証の
riskはownerが受け入れ）。B3（delayed ICMP、NAT44-038）は「A」で、CLI-034 hardeningの後（順序はcoordinator既定）に実装します。

workspaceは12 crateです。data-planeとI/Oのlibrary crateは外部依存を持ちません。cold
control-planeの`ruster-config`とsim専用の`ruster-sim-scenario`だけが、保守されている
Serde/TOML parserを最小featureで直接利用します（`ruster-control`と`ruster-cli`はpath depを
通じて推移的に含みます）。

- `ruster-core`: backend所有packetを借用し、Ethernet II / IPv4検証、LPM、
  TTL/checksum/MAC rewrite、local IPv4向けARP reply、static neighbor miss時の
  ARP Request生成action、fixed-capacity dynamic ARP cache、local ICMPv4 Echo
  responder、ICMPv4 Time Exceeded / Destination Unreachable生成、opt-inの
  single-domain UDP NAT44/NAPT、outbound-initiated TCP NAT44/NAPT、最小IPv4
  stateful forward firewallと、それらを一workerへbindするfull composition wrapperを扱う。
- `ruster-runtime`: genericなpublication seamから一つのactive generationを借用し、
  `RX → resolution timer → failure dispatch → generated ARP → generated ICMPv4`を
  明示budget付きのsingle-worker tickとして実行する。`TickObserver`はtraceとして渡す
  allocation-freeなsaturating counter sinkで、drop/consume reason別数、tick集計、注入時刻
  だけによるhealth、generation/apply結果、NAT44/firewall/ICMPv4 limiter state tableの占有
  （割当済みslot数、generation内high-water、capacity、flushを越えるpeak。coreがO(1)で保守し
  table scanなし）をtick境界で固定順snapshotにする。
- `ruster-config`: 最大1 MiBのUTF-8 TOMLをschema versionでpredispatchし、V1の
  interface/address/route/neighbor/NAT44/firewall/capacity/tick budget/packet backend DTOへ
  exact decodeする。unknown/duplicate field、runtime生成値、過大listをvalue-freeなtyped diagnosticで
  fail-closeする。cold semantic validationはcanonicalなowned core値、connected route、
  cross-reference/on-link検証、policy/NAT/firewall検証、全runtime storage shapeを作る。
  AF_XDP backendのring/UMEM/bind flagは`ruster-io-xdp`の`native_profile`（unsafeなしの
  native profile。`ruster-io-xdp-native`も同じ型をre-export）のvalidatorで構築し、
  native crateには依存しない（下の「packet backend」）。`#![forbid(unsafe_code)]`。publication identityとsecretは持たない。
- `ruster-control`: validated configからpublication candidateを作るbridge（M1は
  Resolution/ICMPv4 error/NAT44 UDP/TCP/firewallを全て必須とし、欠落はtyped reject）、
  scenario seed由来のsim専用key source、`/dev/urandom`由来のproduction key source
  `OsRandomKeySource`とsim sourceをcompile時に拒否する`ProductionSequencer`（`ruster run`用、
  失敗はtyped errorでfallbackなし）、shapeどおりのslot配列を一度だけ確保する
  `FullServiceStorage`、5 runtimeをpreflightしてから一点でcommitする`ActivePublication`、
  mutationなしの`ApplyPlan`/dry-run、単調なgenerationとkey非再利用を保証する
  `PublicationSequencer`（rollbackは旧configを新generationとして再apply）を持つ。
- `ruster-io-sim`: rootやNICなしでRX/generated TXのFIFO、budget、TX/drop、
  traceを決定的に検証する。
- `ruster-io-conformance`: backend共通のlease exactly-once、partial TX、finish error、
  abandonを検証する再利用可能なconformance suite。
- `ruster-sim-scenario`: 最大256 KiBの`ruster-scenario/v1` TOMLを、seed、初期config path、
  `inject`/`tick`/`apply`/`expect`/末尾`hold` stepのtyped modelへexact decodeする。
  Ethernet II、ARP、IPv4、ICMPv4 Echo、UDP、TCPのcold側builderとraw hexでframeを
  checksum込みのexact bytesへ組み立てる（`pad-to-min`で60 bytesまでzero padding）。config pathはscenario directory内の相対pathに限り、
  時刻後退、unknown/duplicate field、上限超過をvalue-freeなtyped errorで拒否する。
  driverはscenarioと参照configを読み、full-service publicationを`SimIo`上の`run_tick`で
  注入時刻だけを使って実行し、`expect`（TX bytes/egress、累積drop/consume、generation）を
  typed errorで評価してcanonical JSONL `ruster-run-sim/v1`を出力する。M1 golden fixtureは
  [`fixtures/m1`](fixtures/m1)にあり、golden出力の再生成は
  `RUSTER_UPDATE_GOLDEN=1 cargo test -p ruster-sim-scenario --test driver`（CIでは拒否）。
- `ruster-cli`: binary `ruster`。手書きarg parsingで`validate`/`plan`/`run-sim`と、M2 S10a/S10bの
  `run`（x86_64 LinuxのAF_XDP static router、下の「`ruster run`」）を提供し、SIGINT/SIGTERMは
  private FFIのhandlerがstatic `AtomicBool`へswap/storeするだけです（二回目のsignalはforce
  flag。`run`のSIGHUPはreload flagへstoreするだけ）。`unsafe`はそのhandlerと`run`のrtnetlink
  query（IPv4/IPv6のaddress dump、全tableのroute dump、link）だけです（下の「使い方」）。
  外部crateを直接には追加しません。
- `ruster-bench`: NIC-freeなsim smoke/datapath benchmarkとhardware benchmark plan/
  measurement protocol/artifact v1のschema検証。sim結果からproduction性能を主張しない。
- `ruster-io-afpacket`: Linux AF_PACKET/TPACKET_V3 backendのchecked configuration、
  fixed IfId mapping、ring ownership/UAPI scaffold。combined mmapのRX/TX extentを
  overlap/gap/overflow/実address alignmentまで検証し、後続state machine用metadataを
  resource取得前のcold pathで固定長preallocateする。内部TX engineはfixed frameへexact
  one-copyでpublishし、FIFO completionとendpoint単位のnonblocking kickをboundedに処理する。
  内部RX engineはpersistent block cursorでUSER blockを検証してからzero-copy leaseを貸す。
  AP2では全portのRX/TXを一つのprivate engineへ統合し、core `PacketIo`のcopy backendとして
  RX leaseをin-placeで借用させ、受理時だけ任意port(ingress自身のhairpinを含む)のTX frameへ
  exactly one copyする。reusable copy conformance suiteをscripted syscall上の実engineで実行する。
  64-bit Linux、SOCK_RAW Ethernet II、PACKET_RESERVEなしのstrict profileで、TX
  requestのretire timeout/private/feature fieldsはzeroに限定する。RX private areaは
  kernel同様に8-byte alignした`BLK_PLUS_PRIV`を使い、宣言した最大Ethernet frameを
  block内で切り詰めず保持できるgeometryだけを許す。Linux syscallとtest scriptは
  privateなstatic dispatch seamを共有するが、public live constructor/adapter、zero-copy
  TX mode、poll、cleanup/stats、実NIC/netns E2E、throughputを主張する段階ではない。
- `ruster-io-xdp`: AF_XDP native接続より前に固定するpure-Rust ownership model。
  UMEM layout、descriptor境界、nonzero generation token、frame state ledger、
  fixed-storage ring、authoritative ledgerと結合したfinite fake kernelを持つ。
  `native_profile`はbind flag、ring capacity、UMEM geometryのsafeなLinux v6.8 profileで、
  `ruster-config`と`ruster-io-xdp-native`が共有する。socket、native ring、FFI、core
  `PacketIo`接続はまだ持たない。
- `ruster-io-xdp-native`: Linux v6.8 AF_XDP UAPIのC layout、raw flag profile、
  2048/4096-byte aligned UMEMと固定256-byte kernel headroomを含むring geometry、
  kernel報告mmap offsetをcold pathで検証するnative scaffold。caller-owned mappingを
  排他的にborrowするFill/TX producerとRX/Completion consumerは、wrapping cursor、
  Acquire/Release publication、need-wakeup flagをallocationなしで扱う。後続resource setup用の
  private x86_64 Linux syscall/RAII seamは、CLOEXEC/nonblocking AF_XDP socket、socket option、
  mmap/munmap、bind、poll、sendto、closeをdependencyなしで包み、fd/addressをDebugから
  redactしてcleanupを高々一回にする。他の64-bit Linux architectureはC0/C1のpure ABI/ring
  validationを狭めず、別のtyped syscall capability checkで拒否する。M2 S1（X00C）の
  `NativeSession::open(&SessionConfig)`（x86_64 Linuxだけ）は、libbpf/libxdpなしのraw UAPI
  v6.8 profileで一socket（一interface queue）を`if_nametoindex` → AF_XDP socket → UMEM
  mmap/`XDP_UMEM_REG` → 四ring size → `XDP_MMAP_OFFSETS`検証 → 四ring mmap → `sockaddr_xdp`
  bind → `XDP_OPTIONS`のmode確認まで一つのfailure-atomic transactionで組み立て、失敗時は取得済み
  resourceだけをexact reverse orderで一回ずつ解放する。`SessionConfig`は
  `ValidatedAfXdpPortV1`の`device`/`queue`/`bind_flags`/`rings`/`umem`から作る。`auto`は
  zero-copy bindがEOPNOTSUPPのときだけcopyへfallbackし、errorはvalue-freeな
  `SessionError{stage, failure}`（PermissionDenied、MemlockLimit、NoSuchDevice、Busy等）。
  ring viewは`rings(&mut self)`が実mappingを排他borrowして貸すためmappingより長命になれない。
  M2 S2（X00D）の`NativeSession::attach_xdp(XdpAttachMode::{Native, Generic})`は、手組みの
  original eBPF redirect program（`rx_queue_index`でXSKMAPを引き、空slotは`XDP_DROP`でfail closed）を
  `bpf(2)`で直接loadし、`queue + 1` slotのXSKMAPへsocketを入れてから`BPF_LINK_CREATE`で
  attachする（libbpf不要、minimum kernel 5.9、license `MIT OR Apache-2.0`）。既存のXDP program/
  linkがあれば置換もdetachもせず`ExistingProgram`で拒否し、失敗時は作成済みobjectだけを逆順に
  閉じる。detachはlink fdのclose（`detach_xdp`、`close`、drop）で、linkはpinしないため
  process crashでも自動detachされる。errorはvalue-freeな`AttachError{stage, failure}`で、
  verifier logは長さとtruncationだけを返す。bind queue以外のframeは捨てる（firewall/NATの迂回を
  防ぐ）ので、portはsingle-queue deviceにするかethtool RSS/ntupleでbind queueへ寄せ、kernelの
  L3設定を残さない。M2 S3（X01）の`RxFillEngine`はdatapath engineのRX/Fill半分で、
  `NativeSession::take_datapath()`がsessionごとに一回だけ貸す`DatapathRings`（Fill、Completion、
  RX、TX、UMEMの一組。二回目や`rings()`との併用は拒否し、engineの作り直しにはsessionのcloseが
  要る）を一workerで所有し、
  free RX-pool frameを`fill_batch`以下ずつFillへpublishし（free listが空でFillにroomがあれば
  `fill_starved`を数えてstallしない）、RX descriptorをUMEM範囲、kernel所有（重複を拒否）、
  options、headroom、Ethernet header長（14 byte）、chunk境界でcoreに見せる前に検証する（違反は
  reason別に数え、kernelがprofile外で返したframeはquarantine、runtはrecycle）。need-wakeupは
  毎refillと`fill_needs_wakeup()`で観測できる。valid frameはengineをborrowする`RxFrame`として
  一つずつ貸し、`recycle`/`stage_tx`（`TxHandoff`）/dropで終える。bytes借用中のrecycleは
  compile errorで、UMEM byte accessはledgerが`Leased`と記録するframeだけに限る。M2 S4（X02）の
  TX/Completion半分は同じengineと同じledgerにあり、`submit_tx`/`submit_tx_batch`がcoreのin-place
  rewrite後のframeをcopyせずRX geometryのままTX ringへ出す。in-flight TXはTX ring capacity以下
  （engine setupは`completion >= tx`を要求）で、ring満杯やcompletion遅れは`TxBlocked`
  （`RingFull`/`InflightLimit`/`Draining`）のrecoverableなwould-blockとしてhandoffを不変で返し、
  cancelすればfree list経由でFillへ戻る。pollはrefill前にCompletion ringをboundedにreapし、各address
  をUMEM範囲、in-flight所有（重複を拒否）、提出したexact addressで検証する（違うaddressのframeは
  quarantine）。`completion_lag()`はin-flight数と最古frameのpoll年齢。bundleはsocketのkick handle
  も運び、`wake_tx()`（`sendto` `MSG_DONTWAIT`）と`wake_fill()`（`poll`、timeout 0）は
  `EAGAIN`/`EBUSY`/`ENOBUFS`/`EINTR`を`KickOutcome::Deferred`、他をtyped `KickError`にする。
  `attach_xdp`は`take_datapath`より前に呼ぶ。`NativeSession::open`はinterface lookup直後に、bind queueに
  TX queueがあることをsysfs（`/sys/class/net/<dev>/queues/tx-<queue>`、sysfsの`ifindex`が解決済みdeviceと
  一致することを先に確認）で確かめ、無ければresource取得前に`SessionFailure::NoTxQueue`で拒否する
  （Linuxは`queue < max(RX, TX)`でbindを許すがcopy-mode TXは黙って何も送らない）。`drain(rounds)`は新規TXとFillを止めてcompletionを
  回収し、全frameを一回だけledgerへ戻し、kernelがまだ持つframeを`DrainOutcome::TxInFlight`と
  `FrameAccounting`で報告する（返ったことにはしない）。M2 S5（X03）の`allocate_generated(len)`は
  同じengineと同じledgerでgenerated pool（`rx_frames..frame_count`、Fillへは一度も出さない）から
  frameを取り、headroomの後ろのexactに`len` byte（zero化済み、その先は到達不能）だけを
  `GeneratedFrame`として貸す。`commit`（または`stage_tx`して`submit_tx_batch`）はforwarded frameと
  同じTX ring、in-flight上限、`TxBlocked`を共有し、`cancel`、drop（abandon）、generated handoffの
  cancel、completionはgenerated free listへ戻る。どのpoolへ戻すかはframe indexだけで決めるので
  RX completionがgenerated poolへ、generated frameがFillへ入ることはない。拒否は`Rejected`
  （`Draining`/`ZeroLength`/`BelowMinimum`/`TooLarge`）とpool枯渇の`Unavailable`でblockせず、
  `GeneratedCounters`（allocated/unavailable/committed/cancelled/abandoned/completed/
  rejected(reason)、gauge inflight、`generated_quarantined_after_tx`）と`GeneratedAccounting`、
  両poolを見る`audit()`で観測する。M2 S6（X04a）の`XdpPacketIo`はinterfaceごとのengine
  （`XdpPort { XdpPortConfig { interface, queue, mode, mtu }, engine }`）をconstruction時に`IfId`順へ
  固定し（空集合、重複`IfId`、MTU 0はtyped error）、core `PacketIo`、`GeneratedPacketIo`、
  `PublicationQuiescence`、`BackendStats`をstatic dispatchで実装する（`ruster-core`へ依存する。
  coreは外部依存なし）。RXは全portをrotating startでpollしてport順にlendし、ingress自身への
  commitは同じUMEM frameのsame-frame TX、別portへのcommitはportごとにUMEMが別なのでegressの
  generated poolへframeを一回exact copyしてcommitしingressのframeをrecycleする
  （`cross_port_copies`。shared UMEMのzero-copyはdeferred）。TXはegressの`mtu + 14`以下に限り
  （MTUは`NativeSession::open`がsysfsからresource取得前に読み`mtu()`で渡す）、超過は`tx_over_mtu`/
  `FrameTooLarge`で拒否する。`TxBlocked`はerrorなしの`tx_rejected`（core back-pressure）、
  `BelowMinimum`は`FrameTooLarge`、`Draining`は`Unavailable`へmapし、ring破損は一回のerrorの後
  adapterを`Stop`にする。`finish`はTXを公開したportごとに一回need-wakeupに従ってkickする。
  quiescenceはcompletionをreapしてからlease/handoff/in-flight TXが無いことを要求し、in-flightは
  `ContinueOldIo`で延期する。kickはportごとのdebtとしてbatchをまたいで保持し、TXがin-flightの間は
  `finish`、`receive`、`begin_generated`、`service`、quiescence check、back-pressure直後にreapと
  kickを繰り返す（一回`ceil(in_flight/32)+2` kick以内。copy modeの一`sendto` 32 descriptor上限を
  越えるbatchも`finish`で完了）。`ENETDOWN`はerrorでなくportのlink stateで、linkが戻れば新しい
  trafficなしに回復する（`ruster run`ではdown中の再試行を1 msから64 msへ倍増するbackoffでrate limitし、
  見送ったsettleは`kick_retries_suppressed`。XDP-178）。cross-port copyはrouter生成ARP/ICMP用のgenerated reserve
  `max(2, pool/8)`を取らない。portの設定は`XdpPortConfig::from_session`でだけ作れ、別sessionの
  engineとの組は拒否する。`backend_stats()`は全port合計、`port_stats(IfId)`はportごとの
  mode、need-wakeup、link state、Fill/RX/TX/CQ saturationとring占有、completion lag、invalid
  descriptor、kernel `XDP_STATISTICS`（stats呼び出し時だけgetsockopt）、quarantine、generated、
  cross-port copyのcounterを固定順・allocationなしで出す。configからのport構築と
  `ruster run`はM2 S10a（X04b前半、`ruster-cli`）。FFI/pointer accessはprivateな`native_unsafe` moduleだけに閉じる。
  privileged smokeは`scripts/priv-xdp-smoke.sh`（`sudo -n`で専用netnsとその中だけのveth pairを
  作り、`RUSTER_PRIV_XDP=1`で実行してnetnsを必ず削除。不足はskipせずfail）。

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

routerが自身で生成するICMPv4（Echo Reply、Time Exceeded、Destination Unreachable
Network/Host）はすべてdefaultでRFC 1812どおり生成し、security上の理由でclassごとにoffに
できます（RFC 1812 §1.1.3はdefaultが準拠するoptionを許す）。offにしたerror class
（Time Exceeded、Network/Host Unreachable）は元packetのbyte不変drop reasonを変えず、ICMPも
reverse ARPも生成せず、rate limiterとclockにも触れずに専用counterだけを加算します。Echoをoffに
すると、valid Echo Requestは新しいreason `ICMPV4_ECHO_DISABLED`でdropされます。

```toml
[ipv4-origin]
default-ttl = 64
echo-reply = true          # false: Echo Requestを ICMPV4_ECHO_DISABLED でdrop（reload可能）

[icmpv4-errors.generate]   # table/keyとも省略可能、default true。変更はrestart-required
time-exceeded = true       # Type 11/Code 0  -> icmpv4_errors.disabled_time_exceeded
net-unreachable = true     # Type 3/Code 0   -> icmpv4_errors.disabled_destination_unreachable
host-unreachable = true    # Type 3/Code 1   -> icmpv4_errors.disabled_host_unreachable
```

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
候補ごとのmapping全走査は行いません。outboundはEndpoint-Independent Mappingです。
inbound filteringはUDP/TCPごとにRFC 4787 §5の三分類から選べ、defaultは過去に送信した
remote IPv4だけを許すAddress-Dependent Filteringです（下の「NAT44 inbound filtering」）。
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
arrayのcapacityを一つのopaque valueとして返します。受信ICMPv4 errorの変換（RFC 5508）は下の
「NAT44 ICMPv4 error translation」を参照してください。outside/public宛てerrorは引用する
live UDP mapping/ADF peerをread-only参照し、outer destinationと引用source tupleをinsideへ
戻します。outer sourceはexternal host-unicastかつoutsideへのreverse LPMを要求する
local strict-uRPF policyで、asymmetric external pathを意図的に拒否します。中継routerの
addressは引用remoteと異なっていても保存します。fragment、query NAT、local MTU起因の
Type 3/Code 4生成、PMTU cache、static forward、
multi-public、port randomization/parity、full packet filterはdeferredで、RFC 4787/7857全体への
準拠は主張しません。
引用UDP/TCP IPv4 headerもreserved flagをfragment判定から除外し、reserved以外は
DF=1/MF=0/offset=0を要求します。引用reserved flagはtuple rewrite後も保存します。

TCP NAT44は別のcaller-backed mapping/session storage、両keyed directory、direct
public-port ownerを持ち、UDPと同じ数値public portを独立して使用できます。freshなTCP専用
redacted keyとgeneration+lifecycle epochでstale authorityを遮断します。mappingはinternal
TCP tupleのEndpoint-Independent Mappingです。新規mappingはoutbound SYN=1かつ
ACK/RST/FIN=0だけが作成し、新規sessionはそれに加えてinbound filteringが許可した同じflagの
inbound initial SYNだけが既存live mapping上に作成します。既存sessionではSYN-ACK、data、FIN、
RSTを含むvalid packetを双方向に変換します。TCP header/options/dataを含むIPv4 payload全体のchecksumをstate更新前に
検証し、address/port rewrite後もRFC 1624で更新します。TCPでは算術結果zeroもwire zeroの
ままです。TCPもreserved flagをfragment判定から除外してwireへ保存し、reserved以外は
DF=1/MF=0/offset=0を要求します。

outbound lookupはmapping/session/port pool capacityをそれぞれ最大1回だけ調べる
additive `O(M+S+P)`、inboundとquoted ICMPはdirect owner後にexact sessionだけを調べます。
mapping再生成時は旧sessionを全走査せずgeneration+epochでlazyに無効化します。

TCP session idle TTLはdefault/minimumともに2時間4分です。sequence/window/ACK妥当性は追跡
せず、FIN/RSTもsessionを削除・短縮せず通常のsuccessful TX requestとしてTTLだけをrefresh
します。この保守的な単一timer profile、unsolicited SYNへのdelayed ICMP Port Unreachable
（RFC 5382 REQ-4のSHOULD）を送らずsilent dropすること、fragment未実装を明示し、
RFC 5382全体への準拠は主張しません。TCPのICMPv4 error変換は、引用public source portと
exact live remote address/port sessionをread-only参照します。UDP-only/TCP-only wrapperは他方のprotocolがdomainを
crossするとfail closedにし、combined wrapperはinside/outside/public realm一致を要求します。

NAT44 inbound filteringは`[nat44.udp]`と`[nat44.tcp]`の`filtering`で個別に選びます。
RFC 4787 REQ-8とRFC 5382 REQ-3は、transparency重視ならEndpoint-Independent、より厳しい
filtering重視ならAddress-DependentをRECOMMENDEDとし、administrator option化と
protocolごとの独立を許します。defaultはUDP/TCPとも後者で、UDPの挙動は従来どおりです。
TCPの従来のexact remote address/port filterは`address-and-port-dependent`としてopt-inで
残ります。

```toml
[nat44.udp]
# 省略時 "address-dependent"。変更はreloadable（applyで全NAT stateをflush）
filtering = "address-dependent"  # | "endpoint-independent" | "address-and-port-dependent"

[nat44.tcp]
filtering = "address-dependent"
inbound-sessions-per-remote = 0  # 省略時0（無制限）。新規inboundを許可するなら8推奨、最大16（reloadable）
```

| `filtering` | UDP inbound（live mapping必須） | TCP inbound（exact live sessionが無い場合） |
|---|---|---|
| `endpoint-independent` | 任意remote | initial SYNなら新session |
| `address-dependent`（default） | 送信済みremote IPv4（任意port） | 同mappingにそのremote IPv4のlive sessionがあるinitial SYNだけ新session |
| `address-and-port-dependent` | 送信済みremote IPv4+port | 新sessionを作らない |

拒否はbyte不変のsilent drop（`NAT44_UDP_FILTER_DENIED`、`NAT44_TCP_SESSION_MISS`）で、
inboundはmappingを作りません。firewallを同じworkerへbindした場合はpost-DNAT packetを従来どおり
評価するため、緩いNAT filterが許可したpacketもfirewall policyが許可しなければdropし、NAT state
もcommitしません。外部→内部bypass拒否（NAT44-021）とroute-miss時のNAT gateはfilteringに
依存しません。UDP ICMPv4 errorの変換authorityは`endpoint-independent`でもaddress粒度の
peerを要求します。TCPのaddress-dependent判定はsession slotを共有するcaller-backed
remote-address directoryの一回のbounded lookupで、このdirectory分だけTCP storageが増えます
（M1 fixtureで448 bytes）。`endpoint-independent`とinbound新規flowを許可するfirewall ruleを
組み合わせると、外部からのSYNがsession slotを2時間4分占有し得ます。defaultの`address-dependent`でも
mappingが既に話しているremote address（CDNやDNS serverなど）を詐称したSYNなら同じことができ
ます（NAT44-041）。これをopt-inの`[nat44.tcp] inbound-sessions-per-remote`（default `0`は無制限、
推奨8、最大16）が抑えます。外部initial SYNが一つのmappingに一つのremote IPv4から作ったlive sessionが
上限数あれば、次のSYNはbyte不変の`NAT44_TCP_INBOUND_REMOTE_QUOTA_EXCEEDED`（counter
`nat44_tcp.inbound_remote_quota_exceeded`）でdropし、stateを作らずevictもしません。outbound開始
sessionとhairpinのinbound half（remoteがrouter自身の`P`）は数えません。数はstored counterでは
なくlive slotから導くため、idle expiry、slot再利用、reconcileで自然に戻ります。ただしFIN/RSTを
追跡しないため、closeしたconnectionもidle TTL（2時間4分）まで数え、上限をdefaultにすると同じremoteから
の短い再接続を数時間拒否し得ます。このためdefaultは無制限です（transitory/FIN-aware timerはNAT44-058）。
chainの最初の16 nodeにある同じmapping/remoteのoutbound開始session分だけ実効上限は下がり（最大16は
名目値）、上限が1以上だと16 nodeを超えるchainではADF単独なら許可したSYNも拒否します。どのREQも
filterを通ったSYNの全受理を求めないため、MUSTに反しないlocal security policyです。
`endpoint-independent`では詐称addressを変えれば`上限 × address数`まで残ります（per-mapping上限は
deferred、NAT44-058）。
firewall判定より前に走るinbound SYNのNAT側workは、session capacityに
よらず`NAT44_TCP_INBOUND_SLOT_PROBES`（16）slot/chain nodeまでに上限されます。

NAT44 hairpinning（RFC 4787 §6 REQ-9、RFC 5382 §7.2 REQ-8）はUDP/TCPともdefaultで有効です。
inside host X1がpublic address `P`のlive mapping `P:x2'`（X2のmapping。X1自身でもよい）へ
送ったpacketを、X1自身のexternal mapping `P:x1'`をsourceにして（REQ-9 a / REQ-8 a）X2へ
戻します。X1にmappingが無ければ通常のoutbound規則で作ります。一つのpacketを二つのNAT
traversalとして扱い、それぞれatomicにcommitします。outbound half（X1のmappingとpeer/session）は
同じhostの通常outbound packetと同じplanで、firewallはingress inside/egress outside、pre-SNAT
`X1:x1 -> P:x2'`で評価します。inbound halfはdestination mappingのfilteringと、firewallの
ingress outside/egress inside、post-DNAT `P:x1' -> X2:x2`で、通常inboundと同じに評価します。
inbound halfが拒否されてもoutbound halfは残る（remote NATにdropされたoutbound packetと同じ）
ため、defaultの`address-dependent`では最初のX1→X2'が`NAT44_UDP_HAIRPIN_FILTERED`/
`NAT44_TCP_HAIRPIN_FILTERED`、続くX2→X1'が届き、以後双方向に通るhole punching（RFC 5128
§3.3.2、TCPは§3.4 simultaneous open）になります。hairpinはfirewallのbypassにならず、outbound
halfのfirewall deny、malformed、unknown mapping、offでは何もcommitしません。hairpin stateのremoteは
router自身の`P`で、`P`をsourceとするoutside packetはcommon admissionで、`P`などrouter addressを
引用remoteとするoutside ICMPv4 errorは`NAT44_ICMPV4_QUOTED_REMOTE_LOCAL`でdropするため、
外部からは使えません。`address-dependent`ではX1のpeer `P`がinside全host共通のwildcardになる
（REQ-9 aから不可避。firewallはexact reverseを要求）点に注意してください。hairpinした
datagramについてのICMP error（RFC 5508 REQ-7）は次の節のとおり変換します。

```toml
[nat44.udp]
hairpinning = true   # 省略時true（RFC MUST）。false: NAT44_UDP_HAIRPIN_DISABLED でdrop（reloadable）

[nat44.tcp]
hairpinning = true   # false: NAT44_TCP_HAIRPIN_DISABLED。counter nat44_*.hairpin_disabled
```

NAT44 ICMPv4 error translation（RFC 5508）はUDP/TCPごとの`icmpv4-errors`で選び、defaultの
`bidirectional`は三方向すべてを変換します。対象はDestination Unreachable code 0–4, 6, 7, 9–15、
Time Exceeded code 0、Parameter Problem code 0–2で、type/codeとrest-of-header（MTU、pointer）は
保存します。Source Quench、Redirect、code 5/8、Time Exceeded code 1は変換しません
（architectureの「NAT44 ICMPv4 Fragmentation Needed translation」）。Protocol/Port Unreachable
（3/2、3/3）はend host自身からだけ受け付けます（outsideでは引用destination、insideでは引用
internal host）。off-path hostのport sweepによる注入を防ぐlocal policyで、中継routerが送る
他のtypeについての残余riskはrequirements NAT44-065を参照してください。

| 方向 | 変換 | 必要なauthority |
|---|---|---|
| outside → `P`（REQ-4） | outer destinationと引用sourceをinside hostへ | mapping + peer/session（引用remote）、outer sourceはoutsideへのreverse LPM |
| inside → external（REQ-5） | outer sourceを`P`、引用destinationを`P:x'`へ | outer destinationが引用source、outer sourceが引用internal host自身かそこへのinside next hop、mapping + peer/session |
| inside → `P`、hairpin（REQ-7） | outer `P -> X1`、引用`X1:x1 -> P:x2'` | 上記に加えhairpinning有効、X2側とX1側outbound halfの両方 |

変換はread-onlyでstateを作らず、firewallをbindするとerrorは引用flowにRELATEDなときだけ通ります
（inside発は受信packetとしてflowのorigin/replyのどちらか、hairpinは両half）。inside hostが別hostの
flowを詐称したり、mappingが通信していないexternal hostへerrorを送ったりはできません。
例外としてUDPはEIFでもaddress粒度peerを要求し、inside pathの2 hop目以降のrouterのerrorは
変換しません（requirements NAT44-063/064のdeviation）。逆にfirewallなしのADF/EIFではUDP peerが
address粒度なので、hairpin errorはX1が送っていない`P`のportを引用しても届き（NAT44-061）、
REQ-5の引用remote portもauthorityになりません。firewallをbindするとどちらもexactです。

```toml
[nat44.udp]
# 省略時 "bidirectional"（RFC 5508 REQ-4/5/7）。security option: "external-only"
# （outsideからのerrorだけ）、"disabled"（変換しない）。変更はreloadable（applyで全NAT stateをflush）
icmpv4-errors = "bidirectional"

[nat44.tcp]
icmpv4-errors = "bidirectional"
```

defaultは以前`disabled`で、outsideからのFrag Neededをconsumeしていました（PMTUD black hole）。
以前はkeyが必須だったため、既存configは値を必ず明示しており、その`"disabled"`はそのままです。
ただし明示した`"external-only"`も変換するtype/codeがType 3/Code 4から上の集合へ広がるため、
挙動が変わります。keyの省略が許されるのは新しく書くconfigだけで、省略は`"bidirectional"`です。

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
NAT/FW stateをTX request前にcommitするためbackend rejectでも両stateを保持します。outsideからの
ICMPv4 errorはNAT translationがmapping/sessionから復元したpre-SNAT
internal→remote tupleを、firewall origin stateへdirect exactかつread-onlyで照合します
（inside発errorの照合は上の「NAT44 ICMPv4 error translation」）。
hitだけを`RELATED`として許可し、missは`FIREWALL_RELATED_ICMPV4_STATE_MISS`でneighbor処理前に
silent dropします。lookupはrule scan、reverse match、activity/phase/counter/watermark更新を
行いません。NATを伴わないplain forwarded RELATEDはdeferredで、既存の
`FIREWALL_RELATED_ICMPV4_UNSUPPORTED` discriminantは予約したままです。

UDP/TCP NAT44、firewall、router-originated ICMPv4 errorを同じworkerへbindする場合は、
`forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors`または監査付きvariantを
選び、`Icmpv4ErrorRuntime`を必須で渡します。firewall deny、authority failureはsilentのままで、
認可後のeligible TTL expiryはSNAT前の受信IPv4をquoteしてactionをqueueします。route missは
egress不明のため、egress以外のselectorで「どのegressへも新規flowとして許可される」と判定
でき、egress依存のNAT gate（outside→insideのbypass等）にも当たらないpacketだけに
Destination Unreachable Network（Type 3/Code 0）をqueueし、それ以外は
silentな`FIREWALL_ROUTE_UNAVAILABLE`です（route oracleを作らない、architecture参照）。
RX batchとgenerated TXは融合せず、既定のworker tick順どおりRX完了後に生成します。生成packet
そのものはfirewallの対象外です。既存のICMP runtimeを取らないcombined APIは変更しません。
`ruster-runtime`はcandidate publicationをtick先頭でatomicに試し、reject時は旧active
publicationで継続します。active publicationがなければbackendへ触れず全data phaseをtyped
skipします。RX batchはfull composition wrapperへmoveされ、そのborrowが終了した後だけ
generated sessionを開始します。各phase reportは固定サイズで、RX errorとgenerated error、
clock regression、budget exhaustion、allocation/build/finish/accounting failureを区別します。
backendのTX acceptedはdescriptor publicationであり、wire送信やcompletion queue返却を
意味しません。tick-local `FullServiceView`は非ゼロgenerationを持ち、UDP/TCP NAT44と
firewallの各configを対応するoptional runtimeとnested viewで対にします。resolutionと
generated ICMP runtimeは直接borrowのままです。runtime borrowはviewのprivate fieldで、
publication seamの`active`/`publish_candidate`は`run_tick`だけが作る`PublicationTick`を要求します
（呼出しを`run_tick`から到達するcodeに限定するもので、adapter実装はtrusted、backend instanceの
同一性はcallerの責任、guard mintは未seal）。現行core full wrapperは3 configを必須とする
ため、service pair全体の不在表現はoptional-config composition seamを追加する後続作業です。
candidateがあるtickだけ、backendはboundedな所有状態からpublication quiescenceを検証し、
exact `&mut backend`を保持するsealed GAT guardをpublicationへ渡します。unfinished RX/generated
batch、terminal action未完了のleased slot、またはcompletion待ちTXがあればcandidateを
publicationへ渡さず、backendのtyped dispositionを伴う`Deferred`とします。Simではaccepted TX
completion待ちだけが旧activeでI/Oを継続でき、unfinished batchまたはterminal未完了leaseは
旧activeを保持したままRX、timer、failure、generatedの全data phaseをskipします。backendは
candidateなしのtickにもboundedなread-only current-I/O dispositionを返し、明示的なownership
回収まで`SkipIo`を維持し、`Stop`はbackend valueの寿命中terminalです。このためstickyな
forgotten batch/leaseを次tickで再進入しません。未知errorは保守的にI/Oをskipし、candidateなしの
steady tickはquiescence guard checkを行いません。Sim backendの出力queue完了は保守的なmodelで
あり、AF_XDP CQ drainを実装・証明したものではありません。

## 使い方（M1 `ruster` CLI）

`crates/cli`（package `ruster-cli`）がbinary `ruster`を提供します。rootやNICは不要で、
[`fixtures/m1`](fixtures/m1)をdocumented exampleとして使えます。

```bash
cargo build -p ruster-cli
B=target/debug/ruster

# parse + semantic validation + M1 service bridge。成功時はstdoutへ値を含まない要約
$B validate fixtures/m1/router-v1.toml
# valid: schema-version=1 interfaces=2 routes=3 neighbors=1 local-ipv4=2 firewall-rules=3 ...

# 失敗時はstderrへstage/code/schema path/数値上限だけを出しexit 2
$B validate fixtures/m1/router-invalid.toml
# ruster: invalid config: stage=validate code=GATEWAY_NOT_ON_LINK path=routes[0].via

# current→nextのapply plan（決定的なtext）。restart-requiredでもplanを出せればexit 0
$B plan fixtures/m1/router-v1.toml fixtures/m1/router-v2.toml
# plan: reloadable
# restart-required: none
# changes: 2
#   route + 192.0.2.0/24 dev if2 via 203.0.113.1
#   firewall-rule + id 40 udp if1 -> any 192.168.1.0/24 -> 0.0.0.0/0 sport 1-65535 dport 1-65535 allow-stateful
# expected-flush:
#   resolution_states all
#   ...

# scenarioを決定的に実行。stdoutはcanonical JSONL ruster-run-sim/v1、stderrは人向けsummary
$B run-sim --scenario fixtures/m1/scenario.toml > out.jsonl
cmp out.jsonl fixtures/m1/expected.jsonl

# --hold: scenario終了後もidle tickを続け、SIGINT/SIGTERMでordered shutdownしてfinalを出す
$B run-sim --scenario fixtures/m1/scenario.toml --hold
```

- `validate`/`plan`は`run-sim`と同じvalidation limitを使い、allocator seed、hash key、
  scenario seedを出力しません。`validate`はM1で必須のresolution、ICMPv4 error、NAT44
  UDP/TCP、firewallの欠落も`stage=bridge`で拒否します。
- `plan`は両documentに`validate`と同じbridge確認を行います。`expected-flush`はdocument間の
  planなので`all`（apply時に全live stateをflush）で、実際のflush数は`run-sim`の`apply` eventに
  出ます。capacityやresolution/ICMP/NAT/firewall policyの変更はrestart理由（`STORAGE_SHAPE`等）
  または`changed` flagとしてだけ出し、fieldごとの値は出しません。例外はsecretでないNAT
  filtering、hairpinning、TCP inbound limitで、`nat44-tcp filtering ~ address-dependent -> endpoint-independent`、
  `nat44-udp hairpinning ~ on -> off`、`nat44-tcp inbound-sessions-per-remote ~ unlimited -> 8`の
  ように値を出し、`policy ~ changed`はそれ以外のNAT policy変更だけを表します。interface labelは
  `[A-Za-z0-9._-]`以外を`\xNN`でescapeします（configも同じcharsetと15 bytes上限を要求）。
  `--format jsonl`は未実装です。
- `run-sim`はstepごと（tickは1回ずつ）に停止flagを確認します。`--hold`なしのrun中にsignalを
  受けても残りのstepを実行せずordered shutdownしてexit 0、stderrは`stopped by signal`です。
  したがってexit 0だけで「全expectが成功した」と判断せず、stderrの`finished`を確認してください。
  SIGTERMは常に処理し、SIGINTは起動時にignoreされていれば（job controlなしの`cmd &`など）
  ignoreのままです。SIGHUPなど他のsignalは扱いません。scenario pathが`-`で始まる場合は
  `--scenario=<path>`または`run-sim [--hold] -- <path>`を使います。`--hold`のidle tickは
  注入時刻を100 msずつ進め（wall clockは読まない）、空回りを避けるため実時間100 msの
  sleepを挟みます。stderrの`ruster run-sim: holding`行がhold開始の目印で、hold中はidle tickごとに
  stdoutをflushします。signal受信後はtick境界で止まり、backendのpublication quiescence
  （未完了batch、live lease、未完了TXなし）を確認してから`final` event（counter、health、
  generation、state table占有）を書きます。
- exit status: `0`成功（restart-requiredのplan、signalによるordered shutdownを含む）、
  `1` runtime/I/O/invariant失敗とscenarioの`expect`/`apply`不一致、`2` usage errorと
  invalid config/scenario（未知interface名を含む）。file read失敗（存在しない、読めない）は
  内容のinvalidとは区別して`1`で、stderrは`cannot read config: NOT_FOUND`のような安定codeです。

### `ruster run`（M2 S10a/S10b、AF_XDP static router）

`ruster run --config <config.toml>`は`kind = "af-xdp"`のconfigでx86_64 Linuxの各portにAF_XDP
socketを開き、XDP programをattachしてrouterを動かします（`kind = "sim"`は`stage=backend
code=SIM_BACKEND`でexit 2、`run-sim`を使う）。操作手順は[`docs/runbook-m2.md`](docs/runbook-m2.md)。

```bash
cargo build --release -p ruster-cli
sudo target/release/ruster run --config router.toml                # 既定: 60秒ごとにstats
sudo target/release/ruster run --stats-interval 0 -- router.toml   # 周期statsなし
sudo target/release/ruster run --startup-attempts 1 -- router.toml # 起動retryなし
# stderr: ruster run: running generation 1 on 2 port(s); send SIGINT or SIGTERM to stop, SIGHUP to reload
sudo kill -HUP <pid>                                               # configをreload
```

- 権限: 実効capabilityに`CAP_NET_ADMIN`と`CAP_NET_RAW`、および`CAP_BPF`+`CAP_PERFMON`
  （または`CAP_SYS_ADMIN`）、つまりrootか`setcap`/systemdの`AmbientCapabilities`です。
  `CAP_IPC_LOCK`が無ければsoft `RLIMIT_MEMLOCK`がport UMEMの合計（`mode = "auto"`は2倍、
  5.11前のkernelのBPF object分としてportごとに64 KiBを加算した下限）以上必要です（`ulimit -l`、systemdの`LimitMEMLOCK=`）。不足は何も取得せずexit 4で、不足した
  capabilityまたは`limit-bytes`/`required-bytes`を表示します。起動後もprivilegeは落としません。
- portの前提（起動時に確認）: deviceのRX queueは1つ（rtnetlinkの`IFLA_NUM_RX_QUEUES`で数えるので
  namespaceに正しいが、driverが確保したqueue数。`ethtool -L <dev> combined 1`しても確保数が多い
  NICやRSS/ntupleで全trafficをbind queueへ寄せたなら`--allow-multi-queue`、他queueのframeは
  XDPが捨てる）。MTU + 14がUMEM frame（`frame-size - 256 - headroom`）に収まること
  （`MTU_ABOVE_FRAME`）。port上に
  kernelのIPv4 addressと、portを出口にするIPv4 route（rtnetlink `RTM_GETROUTE`で全table、
  policy routing tableとmultipath nexthopを含む）を置かない（`ip -4 addr flush dev <dev>`）。
  attach中は無意味で、停止中やcrash後にkernelがfirewall/NATを迂回してforwardし得るためで、
  `stage=checks code=KERNEL_IPV4_ADDRESSES`/`KERNEL_IPV4_ROUTES`/`MULTI_QUEUE_DEVICE`で拒否します。
  routerはIPv4だけなので、portのIPv6は無効にする必要があります（`sysctl -w
  net.ipv6.conf.<dev>.disable_ipv6=1`、そのportのIPv6 checkは全て通る）。IPv6がonのportは
  link-localだけでも既定で拒否します（`KERNEL_IPV6_ENABLED`）: Linuxはweak host modelでIPv6には
  `rp_filter`が無いため、detach中はportに届いたhostの任意のIPv6 address宛てframeがlocalに配送され、
  `[::]`でlistenするservice（sshd等）がportから応答し得るからです（link-localだけではport間の
  forwardはできない、RFC 4291 2.5.6）。より具体的なもの、つまり読めないIPv6 fact（`UNVERIFIABLE
  probe=ipv6-*`）、link-local（`fe80::/10`）以外のIPv6 address（`KERNEL_IPV6_ADDRESSES`）、自動の
  link-local/multicast route以外のIPv6 route（`KERNEL_IPV6_ROUTES`）、IPv6 forwarding
  （`KERNEL_IPV6_FORWARDING_ENABLED scope=global|device|force|multicast`: `conf/all/forwarding`、
  `conf/<dev>/forwarding`（単独ではforwardを有効にしないが確認する）、Linux 6.17+の
  `force_forwarding`、`mc_forwarding`）を先に報告します。`--allow-kernel-ipv6`はこれらをまとめて
  warningにします（detach中にkernelのIPv6 stackがportで受信・応答・forwardし得るriskを受け入れる
  宣言。IPv4の拒否と`--allow-kernel-forwarding`には影響しません）。既存環境への影響: 新しいnetnsや
  deviceは`disable_ipv6=0`が既定なので、portに`disable_ipv6=1`を設定する（または
  `--allow-kernel-ipv6`）まで起動を拒否します。IPv4の`mc_forwarding`（multicast routing daemon）は
  `KERNEL_FORWARDING_ENABLED scope=multicast`で拒否（`--allow-kernel-forwarding`でwarning）。
  addressの無いportで実効`rp_filter`と`arp_ignore`が共に0なら`IPV4_WEAK_HOST_EXPOSURE`の
  warningだけを出します（拒否するかはowner判断待ち。`net.ipv4.conf.all.arp_ignore=1`と
  `rp_filter=1`を推奨）。
  `net.ipv4.ip_forward`や`conf/<dev>/forwarding`が1（または読めない）なら既定で
  `KERNEL_FORWARDING_ENABLED`（`UNVERIFIABLE probe=forwarding`）で拒否します。router停止中・exit後・
  crash後にport間をfirewall/NAT抜きで運び得るのはkernel forwardingだからで、namespaceの他の
  interfaceに必要なら`--allow-kernel-forwarding`でwarningにできます。`--strict-config-perms`
  （既定off）はgroup/otherが書けるか、root/実効user以外が所有するconfigを起動時とreload時に
  `stage=permissions`で拒否します（configは`O_NONBLOCK|O_NOCTTY`でregular fileだけ）。既存のXDP programが
  あるdeviceは`stage=attach code=CREATE_LINK/EXISTING_PROGRAM`で拒否し、置換しません。
- 起動はfailure atomicです: どのstageで失敗しても開いたportを逆順にclose（XDP detachを含む）
  してから`ruster run: startup failed: stage=<stage> [port=if<id>] code=<TOKEN>`を出します。
  exit statusはstageによります: 権限/memlock不足は4、config（bridge rejectionを含む）は2、
  open/check/attach等のbackend stageとkey sourceは1です（下のexit status）。`code=`は
  `BIND/BUSY`、`CREATE_LINK/EXISTING_PROGRAM`のような安定したSCREAMING_SNAKE tokenです。
- stdout/stderrは別threadが書き、run loopは上限付きqueueへ`try_send`するだけです。読まれない
  pipeで詰まってもtickと停止は止まらず、溢れたblock/行は捨てて`output.dropped`に数えます。
- 停止: SIGINT/SIGTERMでtickを止め、各portを最大2秒drainしてから逆順にdetach/closeし、
  stdoutへfinal statsを、stderrへ`stopped by signal; drain calls=... tx-in-flight=N
  fill-in-kernel=M ...; detached and closed 2 port(s)`を出します。二回目のsignalはdrainを
  打ち切ります。SIGKILLやcrashでもunpinned linkはkernelが自動でdetachします。
- 起動retry（XDP-045）: 直前のrunのsocket/UMEMはkernelが遅延解放するため、port openの一時的な
  `BIND/BUSY`、`REGISTER_UMEM/MEMLOCK_LIMIT`（`OUT_OF_MEMORY`）、`ERRNO_11`だけは開いた全portを
  rollbackしてから250 ms（倍々、最大2 s）後に起動全体をやり直します。`--startup-attempts`
  （1〜10、既定3、1でretryなし）が上限で、他の失敗はretryしません。
- SIGHUP reload: handlerはflagを立てるだけで、tick境界で`--config`を起動時と同じ経路で読み直して
  validateし（regular file以外は拒否）、新generationのcandidateを作り`ApplyPlan::for_active`で
  稼働中generationと比べます。restart-required（`[backend]`、interface id/MAC、storage shape、
  resolution/ICMPv4 policy）は`reload refused: code=RESTART_REQUIRED reasons=...`、読めない・不正・
  dry run失敗は`reload failed: stage=... code=...`で、どちらも旧generationがそのまま動き続けます。
  通ればbackendがquiescent（旧generationのTXがkernelに無い）になったtick境界でpublication phaseへ
  渡し（待つ間はRXを最大200 ms止める。過ぎれば`stage=quiesce code=TIMEOUT`）、
  `reload applied: generation=N previous=P; interfaces=.. routes=.. firewall-rules=.. ...; flushed ...`
  です（件数で切り詰められたconfigに気づける）。適用時はcontrol-planeの契約どおり
  ARP学習・NAT44 mapping・firewall flowをflushし（hash keyがrotateする）、counterは保持します。
  `reload.requested|applied|refused|failed`をstatsに出し、停止時に待機中のreloadは
  `stage=quiesce code=STOPPED`で数えるのでfinalでは常にrequested = applied + refused + failedです。
  parse/planとquiescence待ちはrouter threadで同期的に走るため、負荷中はRX ringが溢れ得ます
  （`kernel_rx_ring_full`）。SIGHUPで`ruster run`は終了しません。
- health/link watch（cold path）: 500 msごとにportのcounterを、1 sごとにrtnetlink `RTM_GETLINK`で
  linkを見ます。最古のin-flight TX frameが完了しない`TX_STALL`は既定1 sでwarning、10 sでfatal、
  `FILL_STARVED`はwarningだけ、`ENETDOWN`以外のkick errorが続く`KICK_ERRORS`は既定5 sでfatal。
  `--tx-stall-warn-secs`/`--tx-stall-fatal-secs`/`--kick-errors-fatal-secs`で変えられ、fatalを0にすると
  warningだけです（802.3x PAUSE floodのようにwireからTX stallを起こせる環境向け。既定がfatalなのは
  exit後もforwarding拒否とkernel L3拒否でfail closedだから）。同じroundでportにkernel IPv4
  addressや全tableのIPv4 routeが現れたり（`RTM_GETADDR`/`RTM_GETROUTE`）、kernel forwardingがonに
  なったら（procfs）、portの`disable_ipv6`が0になったり、IPv6がonのportでIPv6の
  address/route/forwardingが現れたら`KERNEL_IPV4_ADDRESSES`/`KERNEL_IPV4_ROUTES`/
  `KERNEL_FORWARDING_ENABLED`/`KERNEL_IPV6_ENABLED`/`KERNEL_IPV6_ADDRESSES`/
  `KERNEL_IPV6_ROUTES`/`KERNEL_IPV6_FORWARDING_ENABLED`（`IPV4_WEAK_HOST_EXPOSURE`も）のwarningで動き続けます（attach中はkernelが
  frameを見ないので無害で、fatalにするとdetachがbypassを作るため。次の起動は拒否、exit時に種類ごとの
  警告行）。各queryの失敗は種類ごとに数え3回連続でfatal（IPv6は`--allow-kernel-ipv6`なら
  `IPV6_UNVERIFIABLE` warning）。
  link downはwarningと計数だけで動き続け、upで`recovered`になりowed kickが再開します。device削除
  （`DEVICE_REMOVED`）、startup MTU未満へのMTU低下（`MTU_DECREASED`）、frameに収まらないMTU
  （`MTU_ABOVE_FRAME`）、3回連続のlink query失敗はfatalです。fatalはdrain・detach・closeの後
  exit 1（`stopped after a fatal health event port=if<id> code=...`）。statsは`watch.state`、
  `if<id>.watch.*`。行はすべて`warning:|recovered:|fatal: port=if<id> health=<CODE>`のvalue-free形式。
- stats: `ruster-run-stats kind=periodic|final uptime-ms=N`の後に`section.key=value`行
  （`observer.*`、`health.*`、`tick.*`、`rx.*`、`drop.*`、`af_xdp.*`、`if<id>.af_xdp_port.*`、
  `reload.*`、`watch.*`、`if<id>.watch.*`等）と
  `end`。counterとlabelだけでaddress、MAC、device名、key、seedは出しません。
- idle時は64 tick spinした後50 µsから1 msまで倍々でsleepします（idle後最初のframeは最大約1 ms
  遅れる。負荷中はsleepしない）。
- exit status: `0` clean shutdown（起動中のsignalでrollbackした場合も）、`1`起動失敗、backend
  fault、fatal health/device event、drain失敗、drain後に残ったTX handoff、close error、
  `2` usage/invalid config、`3`停止期限（または二回目のsignal）で
  TX frameがkernelに残った（detach/closeは済み）、`4`権限/memlock不足。reloadの拒否・失敗では
  終了しません。
- privilege drop、socket fdの`poll`待機、multi-queue、systemd notify、SIGUSR1 statsはdeferred
  （requirements CLI-034、runbookの「Known limits」）。

### packet backend（`[backend]`）

`[backend]`は省略可能で、省略時は`kind = "sim"`です（M1 fixtureとgoldenは不変）。
`kind = "af-xdp"`はM2のAF_XDP backend用のvalidated configで、`ruster run`（下）がこの
portごとにsocket作成とXDP attachを行います。`validate`/`plan`は受理し、`run-sim`は
`SimIo`だけを動かすため無視せず`stage=backend code=UNSUPPORTED_BACKEND`で拒否します
（初期configはexit 2、apply stepは`invalid`）。

```toml
[backend]
kind = "af-xdp"                  # 省略時 "sim"
existing-xdp-program = "refuse"  # 省略時 "refuse"（唯一の値。既存programを置換しない）

[[backend.ports]]                # interfaceごとに1つ（M2は1 queue/interface）
interface = "wan"                # [[interfaces]] の name。その device をbindする
queue = 0                        # 0..=1023
mode = "copy"                    # "copy" | "zero-copy" | "auto"
need-wakeup = true               # 省略時 true。native profileが必須とするため false は拒否
xdp-attach = "native"            # "native" | "generic"（skb）。generic は mode = "copy" だけ
rings = { fill = 2048, rx = 2048, tx = 2048, completion = 2048 }  # power of two、64..=16384
frame-size = 4096                # 2048 | 4096（aligned chunk）
frame-count = 4608               # >= fill + tx + generated-frames（最低限のfloor）
generated-frames = 512           # >= 1。生成ARP/ICMPv4用、残りがRX用
headroom = 0                     # 省略時 0。kernel固定256 bytesに加算
```

制約（違反は`stage=validate code=BACKEND_* path=backend.ports[i].<field>`、数値はlimit/actualだけ）:

- 全`[[interfaces]]`にちょうど1つのport。同じ(device, queue)の重複、同じinterfaceの2つ目のqueue、
  未知interfaceは拒否します。`kind = "sim"`でportを書くと`BACKEND_PORTS_WITHOUT_AF_XDP`です。
- `xdp-attach = "generic"`（skb XDPは常にcopy）では`mode = "copy"`だけを受理し、`zero-copy`/`auto`は
  `BACKEND_MODE_REQUIRES_NATIVE_ATTACH`です。
- `completion >= tx`。`frame-size - 256 - headroom >= 1514`（1500-byte MTUのEthernet IIを
  single bufferに収める）。
- `frame-count - generated-frames >= fill + tx`はlibxdpと同じ**最低限のfloor**です。Fill ringを
  満杯にでき、かつTX ring一杯のforward frameを出せるだけの量で、未回収のcompletion、driverが
  dequeue済みのTX frame、coreが借用中のRX frameまでは数えません。不足時に詰まらないことは
  backend側の責務です（in-flight TXを`tx`以下に抑え、free listが足りなければFillを減らして
  進む。後続X01/X02、ledger BACKEND-004）。生成frameは別poolです。
- UMEMは1 socket 256 MiB、全socket合計1 GiBまで。
- `[backend]`のどんな変更も`plan`で`restart-required: BACKEND`になり、`backend ~ sim -> af-xdp`や
  `backend-port ~ if2 dev eth1 queue 0 copy native rings 2048/2048/2048/2048 frames 4608x4096
  generated 512 headroom 0 -> ...`のように値を出します（secretを含まないため）。portはbindする
  deviceを含むので、af-xdpでinterfaceの`device`を変える（2つのdeviceを入れ替えるのも）と
  label変更に加えてrestart-requiredです（sim backendではlabel変更だけでreloadable）。`validate`の要約は末尾に
  `backend=sim`または`backend=af-xdp ports=2 umem-bytes=...`を出します。

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

`ruster-io-xdp-native`のunsafe/fake test（RX/Fill engine、TX/Completion半分、generated frame、core adapterのheap scripted kernel testを含む。kernelを`'static`へleakするconformance harness testだけはskip）は任意でMiriでも確認できます（nightlyとMiri sysrootが
必要。CI gateではありません）。

```bash
MIRIFLAGS=-Zmiri-strict-provenance cargo +nightly miri test -p ruster-io-xdp-native --lib
```

AF_XDP native session/XDP attachのprivileged smokeは`sudo -n`が使えるLinux 5.9以上のhost
（`ip`はlibbpf付きiproute2、`python3`が必要）で明示的に実行します（CIでは下の`XDP veth` job）。

```bash
scripts/priv-xdp-smoke.sh
```

`ruster run`のprivileged E2Eは`scripts/priv-run-smoke.sh`です（同じ前提に加え`ethtool`）。
binaryを通常userでbuildし、router用とhost A/B用の三つの専用netns（`ruster-run-<pid>-<random>`と
`-a`/`-b`）にveth pairを作り（initial namespaceには作らない）、netns内で`ruster run`をchild
processとして起動します。host Aからhost BへのUDPがrouterのARP、NAT44、firewallを通って届くこと、
SIGTERMでexit 0・XDP detach・final stats、二つ目のportのopen/attach失敗でexit 1と一つ目のportの
detach（外部programは不変）、2-queue device・kernel IPv4 address・kernel routeの拒否、SIGKILL後の
auto-detachと再起動（transientなBusy/MemlockLimitはrouter自身もretryし、test側もbounded retry）、
M2 S10bのops phase（一つの稼働中routerでSIGHUP reloadによりUDP ruleをdenyにして届かなくなり、
戻して再び届く。generation 2/3でrestartなし。UMEM shapeを変えたreloadは`RESTART_REQUIRED`で
拒否され転送は継続。router netns内の`ip link set ra down/up`でwarningとrecovered、転送回復。rbの
MTUをframe上限超へ上げるとexit 1でdetach）、kernel forwardingの段（`ip_forward=1`の起動拒否、
overrideでのwarning、稼働中のwarningとrecovered。M2 S11で`ip_forward=0`のまま
`conf/ra/forwarding=1`の起動拒否`scope=device`と稼働中のif1だけのwarning/recoveredを追加）、
読まれないFIFOへstdoutを向けたstuck phase（FIFOがcapacityまで埋まり動かないことを`FIONREAD`で
確かめてからSIGTERM、有界時間でexit 0）、最後にrouter netns内でraのvethを削除するとexit 1
（`DEVICE_REMOVED`）で何もattachが残らないことを確認し、成否によらず三つのnetnsを削除します。

```bash
scripts/priv-run-smoke.sh
```

`priv-xdp-smoke.sh`はtest binaryを通常userでbuildし、`ruster-x00c-<pid>-<random>`というnetnsとその中だけのveth pair
（`rx00c0`/`rx00c1`）を作ってnetns内でtestを実行し、成否によらずnetnsを削除します（同名netnsが既にあれば触らずfail）。host側の
interfaceには触れません。testはinitial netnsでの実行を拒否し、`RUSTER_PRIV_XDP=1`なのに
netns/device/capabilityが欠ける場合はskipせずfailします。veth pairは2 queueで、phaseは
session（X00C）、attach（native attach、peer端からのframeがRX ringへ届く、別queueからの二度目の
attachが`ExistingProgram`、detach、generic attach）、engine（live mapping上の`RxFillEngine`で
peerのARP frameが検証を通りlend、recycle、refillされる、X01）、tx（peerのARP requestを同じframeで
replyへ書き換えて送りpeerが学習、in-flight frameをdrain、X02）、generated（generated poolのframeに
ARP requestを生成してcommitし、peerが送信元を`ip neigh`に学習、completionとdrainでgenerated poolへ
戻る、X03）、adapter（別の1-queue veth pair二つ`rx00c4`/`rx00c5`と`rx00c6`/`rx00c7`を一つの
`XdpPacketIo`の二portにし、Aのpeerから送ったIPv4/UDP frameをcore `forward_batch`で転送してBの
generated poolへcopyし、Bのpeerが書き換え済みMACとTTLで受信、60 frame burstが一batchで完了、netns内の`ip link set down/up`によるBのlink flapから新しいtrafficなしにquiescenceがreadyへ戻る、両portをdrain、X04a）、foreign（`ip link set ... xdpgeneric obj`で
付けた外部programを両modeで拒否しprogram id不変。objectは`scripts/priv-xdp-foreign-elf.py`が
compilerなしで生成）、holder（attachした別processをSIGKILLしlinkが消える）の順です。

### CI: `XDP veth` job（M2 S11）

`.github/workflows/xdp-veth.yml`の`XDP veth` jobは、pull requestとmainへのpushごとに
`ubuntu-24.04` hosted runner（passwordless sudo）で上の二つのprivileged smokeを実行します
（30分上限、`permissions: contents: read`、secretなし。owner決定2e「当面は任意のまま」によりrequired checkではない）。

1. `scripts/priv-xdp-probe.sh`: kernel 5.9以上、sudo下の`CapEff`、libbpf付きiproute2、throwaway
   netns（`ruster-probe-<pid>-<random>`）内でのveth作成とsysctl書き込み、`socket(AF_XDP)`、
   generic/native XDP attachを確かめます。どれかができなければ`priv-xdp-probe: FAIL code=PROBE_*`
   でjobがfailし、skipやvacuousなpassにはなりません。netnsは必ず削除します。
2. binaryとtest binaryをrunner userでbuildし、skip/fail判定の純粋関数test
   （`priv_gate_fails_instead_of_skipping_when_required`）を非特権で実行。
3. `RUSTER_REQUIRE_PRIV=1`で`scripts/priv-xdp-smoke.sh`（`priv_xdp_session`の各phase）と
   `scripts/priv-run-smoke.sh`。この変数の下ではtestは`RUSTER_PRIV_XDP`が無い・phaseが選ばれて
   いない場合もskipせずfailします。scriptは`1`か未設定だけを受け、空文字は未設定として扱います
   （testへ渡さない）。`priv-xdp-smoke.sh`はtest binaryの`priv_xdp_*` testの集合が配線済みphaseと
   一致しなければfailします。
4. `ruster-*` netnsが残っていないことを確認し、失敗時はsmoke log（value-free、throwaway netns内）
   をartifactとして保存します。

localでも同じ順に実行できます（`TMPDIR`は小さい`/tmp`を避けたい場合に指定）。

```bash
scripts/priv-xdp-probe.sh
RUSTER_REQUIRE_PRIV=1 scripts/priv-xdp-smoke.sh
RUSTER_REQUIRE_PRIV=1 scripts/priv-run-smoke.sh
```

検証するのはhosted runnerのkernel一つとveth copy/native modeだけで、zero-copy NICや5.9〜6.xの
網羅、性能は対象外です（runbookの「CI and E2E」）。

設計契約と非対象は[architecture v0.2](docs/architecture-v0.2.md)、要件とRFC根拠は
[requirements](docs/requirements-v0.2.md)、production backendから自宅ラボ運用までの
優先順位とmilestoneは[development plan](docs/development-plan-v0.2.md)を参照してください。
