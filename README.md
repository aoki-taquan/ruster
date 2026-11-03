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
riskはownerが受け入れ）。B3（delayed ICMP、NAT44-038）は「A」で、CLI-034 hardeningの後（順序はcoordinator既定）に実装しました（下のNAT44 TCP）。

workspaceは12 crateです。data-planeとI/Oのlibrary crateは外部依存を持ちません。cold
control-planeの`ruster-config`とsim専用の`ruster-sim-scenario`だけが、保守されている
Serde/TOML parserを最小featureで直接利用します（`ruster-control`と`ruster-cli`はpath depを
通じて推移的に含みます）。

- `ruster-core`: backend所有packetを借用し、Ethernet II / IPv4検証、LPM、
  TTL/checksum/MAC rewrite、local IPv4向けARP reply、static neighbor miss時の
  ARP Request生成action、fixed-capacity dynamic ARP cache、local ICMPv4 Echo
  responder、ICMPv4 Time Exceeded / Destination Unreachable生成、opt-inの
  single-domain UDP NAT44/NAPT、outbound-initiated TCP NAT44/NAPT、最小IPv4
  stateful forward firewall、forwardしたDF=0 datagramのfragmentation（MTU2 part B）、受信fragmentを
  最初のfragmentの判定へ結びつけるfragment association（NAT-FRAG）と、それらを一workerへbindする
  full composition wrapperを扱う。
- `ruster-runtime`: genericなpublication seamから一つのactive generationを借用し、
  `RX → resolution timer → failure dispatch → generated ARP → generated ICMPv4 → generated fragments`を
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
  `run`（x86_64 LinuxのAF_XDP static router、AFPKT-015からAF_PACKETも、下の「`ruster run`」）を提供し、SIGINT/SIGTERMは
  private FFIのhandlerがstatic `AtomicBool`へswap/storeするだけです（二回目のsignalはforce
  flag。`run`のSIGHUPはreload flag、SIGUSR1はstats flagへstoreするだけ）。`unsafe`はそのhandler、`run`のrtnetlink
  query（IPv4/IPv6のaddress dump、全tableのroute dump、link）、起動後のprivilege drop
  （threadごとの`prctl`/`capset`/`setresuid`等のraw syscall）、filesystem confinement
  （`landlock_create_ruleset`/`landlock_add_rule`/`landlock_restrict_self`/`prctl`のraw syscall）と
  seccomp filterのinstall（`prctl`/`seccomp`のraw syscall）、systemd reload通知の`clock_gettime(CLOCK_MONOTONIC)`、
  AF_PACKET portのreceive offload確認（起動時の`SIOCETHTOOL` ioctl）だけです（下の「使い方」）。
  外部crateを直接には追加しません。
- `ruster-bench`: NIC-freeなsim smoke/datapath benchmarkとhardware benchmark plan/
  measurement protocol/artifact v1のschema検証。sim結果からproduction性能を主張しない。
- `ruster-io-afpacket`: Linux AF_PACKET/TPACKET_V3 backend（AF_XDPに対するdebug/fallback
  backend）。checked configuration、fixed IfId mapping、ring ownership/UAPI scaffold。combined
  mmapのRX/TX extentをoverlap/gap/overflow/実address alignmentまで検証し、metadataを
  resource取得前のcold pathで固定長preallocateする。内部TX engineはfixed frameへexact
  one-copyでpublishし、FIFO completionとendpoint単位のnonblocking kickをboundedに処理する。
  内部RX engineはpersistent block cursorでUSER blockを検証してからzero-copy leaseを貸す。
  AP2では全portのRX/TXを一つのprivate engineへ統合し、core `PacketIo`のcopy backendとして
  RX leaseをin-placeで借用させ、受理時だけ任意port(ingress自身のhairpinを含む)のTX frameへ
  exactly one copyする。reusable copy conformance suiteをscripted syscall上の実engineで実行する。
  AP3のpublic `AfPacketIo::open(ValidatedConfig)`（64-bit Linux、`CAP_NET_RAW`）はportごとに
  socket→`PACKET_VERSION`→`PACKET_IGNORE_OUTGOING`→`PACKET_LOSS`→RX/TX ring→combined
  mmap→`bind`を一つのfailure-atomic transactionで組み立てる（promiscuous、fanout、qdisc
  bypassなし）。`receive`/`begin_generated`/quiescence checkはbatchを開く前にTX completionを
  boundedに回収し、kickを借りたport（kick失敗、またはkernelがSEND_REQUESTのまま残したframe）を
  `set_clock`のloop clockで1 msから64 msへ倍増するbackoffでretryする。kick errnoは
  `EAGAIN`/`ENOBUFS`/`EINTR`/`EBUSY`がdeferred、`ENETDOWN`がlink downでどちらもerrorに
  しない。`ENXIO`（bind先deviceの削除）は恒久なのでbatch errorでportを`unbound`にしretryしない。core `GeneratedPacketIo`のframeはegress TX ringのframeそのもの（zero化して貸し、copy
  なし）。`PublicationQuiescence`はin-flight TXが無いときだけguardを返し、`wait_rx`は全socketの
  `poll(2)`によるidle wait、`BackendStats`（OBS-028）は固定順のport合計counter（kernel
  `PACKET_STATISTICS`はcoldな`refresh_kernel_stats`だけが累積）、`drain`はI/Oを恒久停止して
  強制kickで回収する。completion ringの不正statusはengineを恒久停止する（fail closed）。
  AF_PACKETはAF_XDPと違いframeをkernelから奪わずcopyを受け取るだけなので、portにkernelの
  address/route/forwardingを持たせてはならない。TPACKET_V3のblock retireのため、idle時の単発
  frameは最大RX `retire_timeout_ms`遅れる。privileged smokeは`scripts/priv-afpacket-smoke.sh`
  （専用netns内のveth二組、`RUSTER_PRIV_AFPACKET=1`）。AFPKT-015で`ruster run`から
  `backend.kind = "af-packet"`として選べます（下の「AF_PACKET backend」）。kernelの
  pending socket error（bind先deviceのdown/削除）は`wait_rx`が`POLLERR`を見たportだけ
  `getsockopt(SO_ERROR)`で読んで消すので、idle waitはsleepへ劣化しません（`socket_errors`）。
  実NIC E2Eとthroughputは未検証。
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

ARPのsender protocol addressには既定でon-link条件を課しません（RFC 826のmerge/reply
algorithmどおり。ARP-032）。ingressのconnected/direct routeにもgatewayにも入らないsenderの
ARPを学習も返答もせず`ARP_SENDER_NOT_ON_LINK`でdropするARP-031はopt-inのhardeningです
（owner決定2026-11-02「rfc準きょで」: RFC挙動が既定でhardeningはopt-in、という読み方は
coordinatorの解釈。H4c（#311）では無条件dropでした）。有効にするとLANのhostが他prefixの
addressで動的cacheを埋められなくなる一方、linkを共有する別prefixのhost（secondary subnet）は
direct `[[routes]]`（`via`なし）を足すまで解決されません。

```toml
[arp]                           # table/keyとも省略可能
require-on-link-sender = false  # true: off-link senderのARPを ARP_SENDER_NOT_ON_LINK でdrop（reload可能）
```

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
fragmentation-needed = true # Type 3/Code 4  -> icmpv4_errors.disabled_fragmentation_needed
```

interfaceごとのIPv4 MTU（MTU1）は`[[interfaces]] mtu`（省略時1500、68〜65535、変更は
`INTERFACES`のrestart-required）です。forwardingはTTL判定とfirewallの後、NAT/firewall stateを
commitする前に、受信frameを送るすべてのIPv4 decision（plain、NAT44 UDP/TCP/ICMP query、
hairpin、翻訳したICMP error、local Echo Reply）のTotal Lengthをegress interfaceのMTUと比べます
（NATは長さを変えません）。ちょうどMTUは通り、超過はbyte不変dropです: DF付きは
`IPV4_FRAGMENTATION_NEEDED`とDestination Unreachable, Fragmentation Needed and DF Set
（Type 3/Code 4、RFC 1812 §5.2.7.1）で、ICMP header 2語目の下位16 bitにegress MTUを
Next-Hop MTUとして入れ（RFC 1191 §4）、NAT前の受信datagramを引用して元sourceへ返します
（PMTUD）。他のerrorと同じsuppressionとreverse routeを通り、limiterは専用class
（`[icmpv4-errors.policy] fragmentation-needed-interval-ms`、default 10 ms、egressごと）なので
Time Exceeded等のfloodに使い切られません（`icmpv4-errors.capacity.states`は2 × interfaces以上、
Port Unreachableも送るなら+1）。Ethernet payload（Total Length後のbytesを含む）がMTUを超える
frameは`IPV4_FRAME_EXCEEDS_MTU`でdropします。
DFなしはfragmentします（MTU2 part B、RFC 791 §3.2、RFC 1812 §4.2.2.7。NATを通るDFなし
datagramも変換とID生成の後に。下の`[fragmentation]`）。local Echo Replyの超過は
`ICMPV4_ECHO_REPLY_EXCEEDS_MTU`です。firewallが拒否するdatagramはfirewallの
reasonで落ちerrorを生みません。router生成のすべてのICMP errorはreverse egressのMTUに
収まるようquoteを切ります。`ruster run`はconfigのMTUがdeviceのMTU以下であることをattach前に
確かめ、超えれば`MTU_BELOW_CONFIG`でexit 1です（device MTUがconfigより大きいのは可で、
`MTU_BELOW_DEVICE`を警告します）。

```toml
[[interfaces]]
id = 2
name = "wan"
device = "eth1"
mac = "02:00:00:00:00:02"
mtu = 1400                 # 省略時1500。deviceのMTU以下（ruster runが確認）
```

DF=0でegress MTUを超えるdatagramは、firewall、NAT planなど全decisionの後、何もcommitする前に
fragmentationの上限とslotを確かめ（拒否は`IPV4_FRAGMENTATION_TOO_MANY_FRAGMENTS`、
`IPV4_FRAGMENTATION_QUEUE_FULL`、`IPV4_FRAGMENTATION_DATAGRAM_TOO_LARGE`、
`IPV4_FRAGMENTATION_OFFSET_OVERFLOW`でdatagram丸ごとdrop、NAT/firewall state/IDは消費しない。slotは
14 + max(最大interface MTU, 3826, AF_PACKETの`max-frame-len` - 14) bytesで、受信できるdatagramはすべて収まる）、
通常どおり書き換えてcore所有のslotへcopyし、受信frameは`IPV4_FRAGMENTED`でbackendへ返します。
同じtickの最後（router自身のARP/ICMPの後）のgenerated fragment phaseが、`[tick] generated-fragments`
（省略時64 frame、1〜65536。収まらないsetは丸ごとdrop、`fragmentation.dropped_budget`）の範囲で、
egressのgenerated sessionにset全体のroomを`check_capacity`で確かめてから（roomが無ければ一枚も送らない。
AF_XDPとAF_PACKETはARP/ICMP用のrouter reserveをsetに渡さない）、RFC 791どおりのfragment（最後以外は
8の倍数のdata、同じID、MF/offset、checksum再計算）を送ります。受信fragmentもfragment association
（下）の後にMTUを超えれば再fragmentします（offsetとMFを保つ）。optionsは従来どおり拒否なのでoption copyは起きません。

```toml
[fragmentation]                     # 省略時は全項目default（on）。変更はrestart-required
enabled = true                      # 省略時true（RFC 1812のMUST）。falseはhardeningでIPV4_FRAGMENTATION_REQUIRED
max-fragments-per-datagram = 1365   # 省略時1365（どのdatagramも収まる最大）、2〜1365
datagrams = 64                      # 省略時64、1〜1024。1 tickでfragmentできるdatagram数（[tick] rx以上を推奨）
```

受信したfragment（MFかoffset≠0）はfragment association（NAT-FRAG、RFC 4787 REQ-14）で通します。
transport headerを持つ最初のfragment（offset 0）だけがfirewallとNATの通常の判定を受け（headerだけを検証し、
datagram全体を覆うtransport checksumは受信側に任せる）、その書き換え（MAC、変換後のaddress、NAT44-126で
datagramに一度だけ生成したID、egress）をcore所有の固定長table（key = ingress, source, destination,
protocol, ID）に記録し、同じdatagramの後続fragmentは同じ書き換えで転送、最初のfragmentが拒否されれば
`IPV4_FRAGMENT_FIRST_DENIED`です。最初のfragmentより先に届いた後続fragmentはcore所有のheld slotへcopyして
`IPV4_FRAGMENT_HELD`でbackendへ返し、最初のfragmentの許可で同じtickのfragment phaseから送ります
（拒否かtimeoutで破棄）。transport headerの中から始まるfragment（RFC 1858/3128）は
`IPV4_FRAGMENT_TRANSPORT_HEADER_OVERLAP`、decided datagramの二つ目の最初のfragmentは
`IPV4_FRAGMENT_DUPLICATE_FIRST`（byte一致の重複以外はassociationをpoisonし、同じkeyの両datagramの残りを拒否。
keyはportを含まないのでIDの再利用や二hostへの同じIDの応答を混ぜない）、RFC 791の構造違反は`IPV4_FRAGMENT_MALFORMED`、table/held/host上限は
`IPV4_FRAGMENT_TABLE_FULL`、`HOST_LIMIT`、`HOLD_FULL`、`HOST_HOLD_LIMIT`、`HOLD_TOO_LARGE`です
（host単位は(ingress, source)。一つのingressはtableの`ingress-share-percent`（50）まで（超過は`IPV4_FRAGMENT_INGRESS_LIMIT`）。
上限では古いpending/deny、無ければtimeoutの1/5停滞したallowをevict。一datagramのholdは16まで（`IPV4_FRAGMENT_DATAGRAM_HOLD_LIMIT`）。
完了は0から終端までの全byteを重複なしに数え、終端と矛盾するfragmentは`IPV4_FRAGMENT_MALFORMED`でpoison）。
routerのlocal address宛てのfragmentは対象外（reassembly未実装）。apply（SIGHUP reload）で全associationを
破棄します。fragmentでないframeのfast pathはflags wordの一回の読みだけです。

```toml
[fragment-tracking]                 # 省略時は全項目default（associate）。変更はrestart-required
mode = "associate"                  # 省略時associate。"refuse"はhardeningで全fragmentを拒否（FIREWALL_FRAGMENT_UNSUPPORTED）
entries = 256                       # 省略時256、1〜16384。同時にassociationするdatagram数
entries-per-host = 32               # 省略時32、1以上。source addressごと
held-fragments = 64                 # 省略時64、0〜512。最初のfragmentより先に届いた分（[fragmentation] offではholdしない）
held-per-host = 16                  # 省略時16。source addressごと
timeout-ms = 5000                   # 省略時5000、100〜60000。最初に見たfragmentから
ingress-share-percent = 50          # 省略時50、1〜100。一つのinterfaceが取れるtableの割合
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
mapping/peer/public-port lookupは固定capacityでbounded、新しいmapping/peerの再利用slotと
public portはactivity順のslot listとfree-port bitmapからO(1)で選びます（PERF-001、H4a）。outboundはEndpoint-Independent Mappingです。
inbound filteringはUDP/TCPごとにRFC 4787 §5の三分類から選べ、defaultは過去に送信した
remote IPv4だけを許すAddress-Dependent Filteringです（下の「NAT44 inbound filtering」）。
IPv4 optionsなし、MF=0/offset=0の完全なUDP datagramをDFの有無によらず変換します（MTU2 part A、
NAT44-008。fragmentは`NAT44_UDP_NON_ATOMIC_IPV4_UNSUPPORTED`でdrop、fragment変換はNAT44-018で
deferred）。DF=0のdatagramは変換後にIPv4 IDを生成し直します（RFC 6864 §5.3.1、NAT44-126:
変換後の(source, destination, protocol)ごとにkeyed counter（方向ごとに4096個）で連続、DF=1はIDを
保存、設定なし。egress MTUを超えるDF=0 datagramは生成したIDでfragmentする）。
受信reserved flagはfragment判定から除外し、NAT rewrite後もwire上に保存します。UDP checksum zeroを保存、
nonzero checksumとIPv4 checksumをRFC 1624でincremental更新します。

idle TTLはdefault 300秒、minimum 120秒で、outbound TX requestだけがrefreshします。
live stateをcapacity pressureでevictせず、snapshot/config mismatchはfail closedです。
NAT runtimeへ到達した非退行時刻はdrop結果でもwatermarkへ反映し、expired/miss後の古い
時刻によるmapping復活を許しません。outsideからinsideへのpublic DNATを通らない直通LPMも
neighbor解決前にfail closedです。
publication変更はvalidated config、fresh hash key、reconcile permitの事前検証後に行う
明示的な全state/index flushか、realm・port pool・filteringが同じsuccessorへのstate/index/keyの
引き継ぎ（RELOAD-CARRY、下の「reload時のstate引き継ぎ」）を要求します。`storage_shape`はmapping/peerと全index backing
arrayのcapacityを一つのopaque valueとして返します。受信ICMPv4 errorの変換（RFC 5508）は下の
「NAT44 ICMPv4 error translation」を参照してください。outside/public宛てerrorは引用する
live UDP mapping/ADF peerをread-only参照し、outer destinationと引用source tupleをinsideへ
戻します。outer sourceはexternal host-unicastかつoutsideへのreverse LPMを要求する
local strict-uRPF policyで、asymmetric external pathを意図的に拒否します。中継routerの
addressは引用remoteと異なっていても保存します。fragment、local MTU起因の
Type 3/Code 4生成、PMTU cache、static forward、
multi-public、port randomization/parity、full packet filterはdeferredで、RFC 4787/7857全体への
準拠は主張しません。
引用UDP/TCP IPv4 headerもreserved flagをfragment判定から除外し、
MF=0/offset=0を要求します（DFは問わない）。引用reserved flagはtuple rewrite後も保存します。

TCP NAT44は別のcaller-backed mapping/session storage、両keyed directory、direct
public-port ownerを持ち、UDPと同じ数値public portを独立して使用できます。freshなTCP専用
redacted keyとgeneration+lifecycle epochでstale authorityを遮断します。mappingはinternal
TCP tupleのEndpoint-Independent Mappingです。新規mappingはoutbound SYN=1かつ
ACK/RST/FIN=0だけが作成し、新規sessionはそれに加えてinbound filteringが許可した同じflagの
inbound initial SYNだけが既存live mapping上に作成します。既存sessionではSYN-ACK、data、FIN、
RSTを含むvalid packetを双方向に変換します。TCP header/options/dataを含むIPv4 payload全体のchecksumをstate更新前に
検証し、address/port rewrite後もRFC 1624で更新します。TCPでは算術結果zeroもwire zeroの
ままです。TCPもreserved flagをfragment判定から除外してwireへ保存し、MF=0/offset=0を要求します
（DFは問わず、DF=0ならUDPと同じくIDを生成。fragmentは`NAT44_TCP_NON_ATOMIC_IPV4_UNSUPPORTED`）。

outboundの再利用slotとpublic portの探索はO(1)（UDPと同じslot listとfree-port bitmap）、
inboundとquoted ICMPはdirect owner後にexact sessionだけを調べます。
mapping再生成時は旧sessionを全走査せずgeneration+epochでlazyに無効化します。

TCP sessionは変換したsegmentのSYN/ACK/FIN/RSTを方向別に記録し、RFC 5382 §5のphaseごとの
idle TTL（REQ-5）を使います（N1、RFC 7857 §2の状態機械）: SYNの後ACKが両方向に揃うまでの
opening（`opening-idle-ttl-ms`、default 4分）、揃った後のestablished（`idle-ttl-ms`、
default/minimum 2時間4分。片方向のFINではここに留まる）、FINが両方向か最後のsegmentがRSTの
closing（`closing-idle-ttl-ms`、default 4分）。transitoryの二つは4分未満とestablished超を
`NAT44_TCP_POLICY`で拒否します。RSTはsessionを削除せず変換してclosing TTLへ移し、続く非RST
segment（SYNも含む）で元のphaseへ戻します（RFC 7857 §2.2）。FIN両方向で閉じたsessionへの
insideからのinitial SYNか、remoteの新しいSYNへのinsideのSYN-ACKだけが同じ5-tupleの新connectionとしてやり直します。sequence/windowは
追跡しないため、RSTはexact 5-tupleのsessionに一致すれば受理しますが、注入されたRSTでもsessionは
closing TTLより早くは消えません。詐称し得るinbound RST/FINとinsideのSYN-ACKだけでphaseを
進めないopt-inの`inbound-rst = "corroborate"`もあります（default `"closing"`、reloadable、
planは`nat44-tcp inbound-rst ~ closing -> corroborate`）。mappingとpublic portは最後のsessionと共にexpireし（establishedが残る間は
established TTL）、closeしたconnectionのsession slotとportは2時間4分ではなく4分で空きます。
counterは`nat44_tcp.sessions_established`、`sessions_closed`、`sessions_reset`、
`sessions_expired_{opening,established,closing}`です。unsolicited SYNへのdelayed ICMP Port
Unreachable（RFC 5382 REQ-4）はB3で実装（下記）、fragmentは未実装で、
RFC 5382全体への準拠は主張しません。

```toml
[nat44.tcp]
idle-ttl-ms = 7440000          # established（必須、7440000以上）
opening-idle-ttl-ms = 240000   # 省略時240000。240000以上かつidle-ttl-ms以下（reloadable）
closing-idle-ttl-ms = 240000   # 同上。FIN両方向とRST後
inbound-rst = "closing"        # 省略時"closing"（RFC 7857 §2.2）| "corroborate"（reloadable）
```
TCPのICMPv4 error変換は、引用public source portと
exact live remote address/port sessionをread-only参照します。UDP-only/TCP-only wrapperは他方のprotocolがdomainを
crossするとfail closedにし、combined wrapperはinside/outside/public realm一致を要求します。

public portの選択（N2、NAT44-089〜091）: internal portがpool内で空いていればそれを保ち
（port preservation）、そうでなければNATのsecret hash key（UDP/TCP別、reconcileごとにrotateし、
sequencerが同じkeyの再発行を拒否）で
internal endpointをSipHashしたstartから最初の空きportを選びます（RFC 6056 §3.3.3 Algorithm 3を
EIMに合わせてremote endpointを除いたもの。free-port bitmapで最大34 word）。poolの全portに
ownerがあるときは、keyed probe 8個でexpiredなownerのportを探し、無ければ最も古いexpired
mappingのportです（probeの重複があるのでfallbackの確率はおよそ(1-f)^8よりわずかに高い。fは
expired ownerの割合）。`allocator-seed`は非secretのsaltとしてhashに入るだけです。
RFC 6056 §4とRFC 7857 §9はport-preserving NAPTを認め（portを変えるときだけobfuscate）、
defaultは`true`です。inside hostのsource portが予測可能なら`false`で常にkeyed portにでき、
hostのport選択をpublic portから隠せます。ただし`false`でもkeyed startは同じkey generation内で
endpointごとに固定で、戻ってきたendpointは自分のportを再利用するので、source portを固定した
endpoint（例えばDNS resolver）のpublic portはflowごとに変わりません。resolverは自分でsource portを
randomizeする必要があります（RFC 5452）。inside hostを信頼できない構成で`false`を選ぶ理由は
runbookの「Port preservation」にあります。

```toml
[nat44.udp]
port-preservation = true   # 省略時true。false: 常にkeyed port（reloadable、NAT stateは引き継ぐ）

[nat44.tcp]
port-preservation = true
```

internal hostごとのmapping上限（N3、NAT44-092。RFC 6888 REQ-4はsubscriberごとのexternal port数の
制限をsupportすることを求め、値は定めない）: `mappings-per-host`が非zeroなら、同じinternal IPv4
addressが既にその数のlive mappingを持つとき新規mappingをbyte不変の
`NAT44_UDP_HOST_QUOTA_EXCEEDED`/`NAT44_TCP_HOST_QUOTA_EXCEEDED`（counter
`nat44_{udp,tcp}.host_quota_exceeded`）でdropし、何もevictしません。既存mappingのrefresh、
既存mappingへの新しいpeer/session、inboundは影響を受けません。数えるのはpublic portを持つ
mappingで（hostごとのexternal port数）、hostのmappingがexpireすれば次の新mappingはそのslotを
引き継ぎ（portは通常の選択）、手動操作なしに戻ります（他hostのslotは取りません）。TCPのliveは
hostが保っているもの（自分の開いたconnectionかestablished connectionでhostが送るsegmentだけが
進める）で、remoteがSYNを送り続けてもhostを上限に留められません。hostごとの
intrusive listとkeyed host directoryでO(1)、scanもtimerもありません。defaultの`0`は無制限で、
host storageも確保しません。非zeroにするとmapping capacity分のhost storage（mapping slotごとに
UDP約76、TCP約76 bytes）を確保するので、`0`と非zeroの切り替えはrestart-required
（`STORAGE_SHAPE`）、非zero同士の変更はreloadableなので、値は最初から決めておくのが安全です。
推奨値（pool size ÷ inside host数など）と限界（LAN上のsource address詐称）はrunbookの
「Known limits」にあります。

internal hostごとのpeer/session上限（N6、NAT44-119〜125。RFC 6888 REQ-5はsubscriberごとの
state memory（session数、filter数など）の制限をsupportすることをSHOULDで求める）:
`[nat44.udp]`/`[nat44.icmp]`の`peers-per-host`はhostのlive mappingが持つfilter peer（話している
remote）の合計、`[nat44.tcp]`の`sessions-per-host`はhostがoutbound SYNで開き、自分で保っている
sessionの数を制限します。上限では新しいpeer/session（それを運ぶ新mappingも）をbyte不変の
`NAT44_UDP_HOST_PEER_QUOTA_EXCEEDED`/`NAT44_ICMP_HOST_PEER_QUOTA_EXCEEDED`/
`NAT44_TCP_HOST_SESSION_QUOTA_EXCEEDED`（counter `nat44_{udp,icmp}.host_peer_quota_exceeded`、
`nat44_tcp.host_session_quota_exceeded`）でdropし、何もevictしません。これで一つのhostが共有の
`peers`/`sessions` tableを使い切って他hostを`PEER_TABLE_FULL`/`SESSION_TABLE_FULL`にすることを
防ぎます。inbound SYNが作るsession（remoteが開くconnection、hairpinのinbound半分）は数えないので、
remoteがvictimのTCP予算を使い切ることはできず（UDPはEIFでresponderを動かすhostなら応答先の
remoteに使い切られうるので、その組み合わせは避ける。runbook）、remoteのsegmentやそれへのhostのRST/TIME-WAIT ACKは
countを延ばしません。数えなくなったsessionをhostが再び動かすと上限内で数え直します。hostがFINを送ったconnectionは4分（transitory）で数えなくなります（N3の
mapping quotaも同じ。NAT44-124）。回復はO(1)で、UDPはmappingのexpiry、TCPはhostがsessionを
4分（opening/閉じたもの）またはestablished timeout動かさなかった時点です。default `0`は無制限。
UDP/ICMPは`mappings-per-host`と同じhost storageを使い、TCPはsession slotごとに約92 bytesを
確保するので、storageの有無が変わる切り替えはrestart-required、非zero同士はreloadableです。

```toml
[nat44.udp]
mappings-per-host = 1024   # 省略時0（無制限）。u16
peers-per-host = 2048      # 省略時0（無制限）。u16

[nat44.tcp]
mappings-per-host = 1024
sessions-per-host = 1024   # 省略時0（無制限）。u16
```

ICMP query NAT（N5、NAT44-100〜118。RFC 5508 §3）: `[nat44.icmp]`があるとき、insideからの
Echo Request（`ping`）とTimestamp Requestをpublic addressとpublic identifierへ変換し、その
Reply（type 0/14）をinsideへ戻します（REQ-1、REQ-10 a.3/b）。mappingはinternal address・
Identifierごとのendpoint-independent mapping（REQ-1 a）で、UDP NAT44と同じcaller-backedな
mapping engine（O(1) slot list、keyed directory、free bitmap、per-host list）を別storage・
ICMP専用のfresh hash key・別counterで使います。timeoutは60秒以上（REQ-2、default 60秒、
outbound queryだけがrefresh）、reply filteringはdefault address-dependent（queryにportは
無いので`address-and-port-dependent`は拒否）、Identifierの選択はN2と同じ（preservation、
keyed start）です。queryを引用するICMP error（traceroute -IのTime Exceededなど）は
UDP/TCP引用と同じ経路でread-onlyに変換され（REQ-4/5/6）、N4のlimiterとFrag Needed MTU
checkも共有します。public address宛てのEcho Requestはinsideからでもoutsideからでもrouter
自身が答えます（NAPTにはhairpinできるinbound query sessionが無い。REQ-7はBasic NATの要件、
RFC 7857 §12）。Information/Address Mask（RFC 6918でdeprecated）とinsideからのReplyは
変換せず`NAT44_ICMP_TYPE_UNSUPPORTED`です。UDP/TCPと同じく、fragmentでない
queryはDF=0でも変換します（LinuxのEcho ReplyとWindowsのpingはDF=0。NAT44-116）。sectionが無ければ従来どおりinside→
outsideのICMP queryは`NAT44_UDP_UNSUPPORTED_TRANSPORT`（UDPが無くTCPだけなら`NAT44_TCP_UNSUPPORTED_TRANSPORT`）でdrop（local policyとしての無効化）
で、sectionの追加・削除はstorage shapeの変更（restart-required）です。firewallは
`protocol = "icmp"`のrule（portは書けず全Identifierに一致）でqueryをstatefulに許可し、Reply
はRequestが作ったflowの逆tupleとしてだけ通ります。方向（Request/Reply）はtupleと別に運ぶので、
Identifier 8や13でも逆向きのRequestがReplyとして通ることはなく、flowの無いReplyは
`FIREWALL_ICMP_REPLY_WITHOUT_REQUEST`です。ICMP flowのTTLは`udp-idle-ttl-ms`（120秒以上）でNATの
`idle-ttl-ms`とは独立です。firewall付きの構成ではNATを通らないroutedなEcho/Timestampもruleで
評価されます（以前は`FIREWALL_UNSUPPORTED_PROTOCOL`、今はICMP ruleが無ければ
`FIREWALL_DEFAULT_DENIED`。default denyは同じでdrop reasonだけが変わる）。`[nat44.icmp]`があると
public address宛てのEcho ReplyはNATのpathへ入るので、router自身がpublic addressからpingしても
Replyは`NAT44_ICMP_MAPPING_MISS`で落ちます（routerはpingを送らないので通常は無関係）。

```toml
[nat44.icmp]                       # 省略時: ICMP query NATなし
idle-ttl-ms = 60000                # 省略時60000（60000以上、RFC 5508 REQ-2）
filtering = "address-dependent"    # | "endpoint-independent"（reloadable）
identifier-preservation = true     # false: 常にkeyed identifier（reloadable）
icmpv4-errors = "bidirectional"    # queryを引用するerrorの変換（reloadable）
mappings-per-host = 0              # 0=無制限。0⇔非0はrestart-required
peers-per-host = 0                 # 0=無制限（N6）。mappings-per-hostとstorageを共有

[nat44.icmp.identifiers]           # 省略時[nat44.realm.ports]の数値（identifierごとに32 byte）
first = 40000
last = 40015

[nat44.icmp.capacity]              # 必須
mappings = 8
peers = 16

[[firewall.rules]]
id = 50
ingress = "lan"
egress = "wan"
source = "192.168.1.0/24"
destination = "0.0.0.0/0"
protocol = "icmp"                  # source-ports/destination-portsは書かない
action = "allow-stateful"
```

`icmp` ruleは「Replyだけ」や「Echoだけ」を表せません。outsideからinsideへのallow-stateful ruleを
書くと、その範囲の全てのEcho/Timestamp Requestが通ります（insideからのpingのReplyにはrule不要で、
flowが通します）。

NAT44 inbound filteringは`[nat44.udp]`と`[nat44.tcp]`の`filtering`で個別に選びます。
RFC 4787 REQ-8とRFC 5382 REQ-3は、transparency重視ならEndpoint-Independent、より厳しい
filtering重視ならAddress-DependentをRECOMMENDEDとし、administrator option化と
protocolごとの独立を許します。defaultはUDP/TCPとも後者で、UDPの挙動は従来どおりです。
TCPの従来のexact remote address/port filterは`address-and-port-dependent`としてopt-inで
残ります。

```toml
[nat44.udp]
# 省略時 "address-dependent"。変更はreloadable（filter peerのkeyが変わるのでapplyはそのNAT stateをflush）
filtering = "address-dependent"  # | "endpoint-independent" | "address-and-port-dependent"

[nat44.tcp]
filtering = "address-dependent"
inbound-sessions-per-remote = 0  # 省略時0（無制限）。新規inboundを許可するなら8推奨、最大16（reloadable）
unsolicited-syn-icmp = true      # 省略時true（RFC 5382 REQ-4 SHOULD）。false: silent dropだけ（reloadable）

[nat44.tcp.capacity]
unsolicited-syn-holds = 64       # 省略時64。quote table（本番上限4096、592 bytes/slot）。変更はrestart-required
                                 # 0でswitch off時の約37 KiBを返せる

[icmpv4-errors.policy]
port-unreachable-interval-ms = 1000  # 省略時1000。Port Unreachable専用limiter（egressごと）。restart-required
fragmentation-needed-interval-ms = 10  # 省略時10。Fragmentation Needed専用limiter（egressごと、0不可）。restart-required

[icmpv4-errors.translated]  # 省略可。outsideからの変換errorの(inside host, 引用remote)ごとの上限（NAT44-065）。restart-required
rate-per-second = 100       # 省略時100（1〜1000000、無制限設定なし）
burst = 100                 # 省略時100（同時刻に届く上限）。両方1000000で実質off

[icmpv4-errors.capacity]
states = 8   # Fragmentation Neededがon（default）なら2 × interface数以上、delayed Port Unreachableもon（switch onかつholds > 0）なら2 × interface数 + 1以上が必須（Fragmentation Needed offならinterface数 + 1）
actions = 8  # states下限以上を推奨（少ないと一つのclassが次の実行までaction_fullになり得る）
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
組み合わせると、外部からのSYNがsession slotを占有し得ます（N1以降、SYNだけならopening TTLの4分。
sequenceを見ないのでblindなACKまで送る攻撃者のsessionはdefaultではestablishedになり2時間4分、
`inbound-rst = "corroborate"`なら4分）。defaultの`address-dependent`でも
mappingが既に話しているremote address（CDNやDNS serverなど）を詐称したSYNなら同じことができ
ます（NAT44-041）。これをopt-inの`[nat44.tcp] inbound-sessions-per-remote`（default `0`は無制限、
推奨8、最大16）が抑えます。外部initial SYNが一つのmappingに一つのremote IPv4から作ったlive sessionが
上限数あれば、次のSYNはbyte不変の`NAT44_TCP_INBOUND_REMOTE_QUOTA_EXCEEDED`（counter
`nat44_tcp.inbound_remote_quota_exceeded`）でdropし、stateを作らずevictもしません。outbound開始
sessionとhairpinのinbound half（remoteがrouter自身の`P`）は数えません。数はstored counterでは
なくlive slotから導くため、idle expiry、slot再利用、reconcileで自然に戻ります。closeやRSTした
connectionはclosing TTL（default 4分）、remoteがACKしないSYNはopening TTL（default 4分）まで
数えます（N1以前はどれも2時間4分で、defaultを無制限にした理由でした）。defaultは`0`（無制限）の
ままで、8へ変える案はowner判断待ちです（NAT44-086）。上限は詐称で正当なremoteの枠を埋めて
その本物のinboundを拒否するtargeted denialにも使えるので、両面があります。
chainの最初の16 nodeにある同じmapping/remoteのoutbound開始session分だけ実効上限は下がり（最大16は
名目値）、上限が1以上だと16 nodeを超えるchainではADF単独なら許可したSYNも拒否します。どのREQも
filterを通ったSYNの全受理を求めないため、MUSTに反しないlocal security policyです。
`endpoint-independent`では詐称addressを変えれば`上限 × address数`まで残ります（per-mapping上限は
deferred、NAT44-058）。
firewall判定より前に走るinbound SYNのNAT側workは、session capacityに
よらず`NAT44_TCP_INBOUND_SLOT_PROBES`（16）slot/chain nodeまでに上限されます。

unsolicited inbound TCP SYN（public portにlive mappingが無い、またはfilteringが拒否した外部initial
SYN）はその場でbyte不変のsilent drop（`NAT44_TCP_MAPPING_MISS`/`NAT44_TCP_SESSION_MISS`）のまま、
RFC 5382 §5 REQ-4（B3、owner決定「A」）に従い受信IPv4（最大548 bytes）をbounded hold tableへcopy
します。受信から6秒（`NAT44_TCP_UNSOLICITED_SYN_HOLD_MS`）より前には決して応答せず（loop clockのms切り捨てと読み取りからRXまでの遅れを覆う2 msのmargin `NAT44_TCP_UNSOLICITED_SYN_CLOCK_MARGIN_MS`を期限に足す）、その間に同じ
connection（変換後source `P:p`、destinationがSYNのremote `R:r`）のoutbound SYNを変換したらholdを
silent dropします（simultaneous open）。それ以外は満了後のtickで、NATがそのSYNの再送をまだ拒否する
場合に限り、ICMP Destination Unreachable Port Unreachable（Type 3/Code 3）をholdしたSYNを引用して
一つだけ送ります。ICMPは他のgenerated ICMPv4と同じqueueを通りますが、limiterはPort Unreachable
専用のclass（egressごと、`[icmpv4-errors.policy] port-unreachable-interval-ms`、default 1000 ms）で、
SYN floodがTime ExceededやNet/Host Unreachableのlimiterを使い切ることはありません。limiterや
reverse neighborが拒否したholdは再試行しません（1 SYNに最大1 ICMP、増幅なし）。同じconnectionの
再SYNはholdを増やさず期限を延ばし、TCP sequence numberが同じ（再送）なら最初のSYNを、違う
（再接続）なら最新のSYNを引用します。

firewallがboundのとき（REQ-4 a、security policyに反する応答はしない）、holdと満了時の応答は、
firewallがそのSYNを**全inside destinationへのnew flowとして許可する**場合だけです。変換先のinside
address/portは分からないので、ingress（outside）、egress（inside）、source、source port、TCPで
first-match: destinationが`0.0.0.0/0`かつport 1-65535を含む`allow-stateful`（egress `any`も可）だけが
許可、destinationが狭いallowは飛ばし、matchした`deny`はdestinationによらず拒否、無ければdefault deny
です。つまりoutside→insideのnew flowを許可しない通常のfirewall（default deny）や、sourceを`deny`する
ruleがあれば、unsolicited SYNはsilent dropのままです（`nat44_tcp.unsolicited_syn_firewall_denied`）。
判定はmappingの有無によらず、満了時にもやり直すのでhold中のfirewall変更も反映されます。NATが許可し
firewallが拒否したSYN、sourceのreverse routeがoutside interfaceから出ない（詐称inside source等）SYN、
hairpin、quota超過もholdしません。表が満杯ならsilent drop（REQ-4 a）です。hold表の不整合は表全体を
flushして`unsolicited_syn_index_corrupt`で数えます（fail closed）。resolution runtime（clock）の無い
workerはholdしません。`unsolicited-syn-icmp = false`または容量0ならREQ-4 aのsilent dropだけです。

hardening: 全destinationへのinbound allowがあるとき、EIFではmapping済みportへのSYNは転送され
未mapping portにはICMPが返るので、public portの使用状況は転送の有無と同程度に外から分かります。
port scanに沈黙だけを返したいなら`unsolicited-syn-icmp = false`（reloadable）で残るoracleも無くなり、
`unsolicited-syn-holds = 0`（restart-required）でhold表の約37 KiBも返せます。

counterは`nat44_tcp.unsolicited_syn_*`、`icmpv4_errors.*_port_unreachable`、occupancyは
`occupancy.nat44_tcp_unsolicited_syn_holds`。run_tick経由の例は`fixtures/b3/scenario.toml`
（rule 40がWAN→LANのnew TCP flowを全destinationへ許可する）。

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
他のtypeはsweepでlive flowに当たり得ます。outsideからinside hostへ変換されるerrorは
`[icmpv4-errors.translated]`で(inside host, 引用remote)ごと（secret keyのhashで選ぶ4096 bucket）にburst 100、毎秒100までに制限し（N4、
NAT44-065。超過は`NAT44_ICMPV4_TRANSLATED_RATE_LIMITED`、traceroute/mtr/PMTUDは制限されない）、
Next-Hop MTU 1〜67のFragmentation Neededは両方向で`NAT44_ICMPV4_FRAG_NEEDED_MTU_INVALID`として
dropします（NAT44-098）。TCP sequenceのvalidation等の見送りはNAT44-099です。

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
# （outsideからのerrorだけ）、"disabled"（変換しない）。変更はreloadable（NAT stateは引き継ぐ）
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
# changes: 3
#   route + 192.0.2.0/24 dev if2 via 203.0.113.1
#   firewall-rule + id 40 udp if1 -> any 192.168.1.0/24 -> 0.0.0.0/0 sport 1-65535 dport 1-65535 allow-stateful
#   reload-state ~ carry -> flush
# expected-flush:
#   resolution_states all
#   ...
# state: flush
#   arp flushed
#   ...

# scenarioを決定的に実行。stdoutはcanonical JSONL ruster-run-sim/v1、stderrは人向けsummary
$B run-sim --scenario fixtures/m1/scenario.toml > out.jsonl
cmp out.jsonl fixtures/m1/expected.jsonl

# --hold: scenario終了後もidle tickを続け、SIGINT/SIGTERMでordered shutdownしてfinalを出す
$B run-sim --scenario fixtures/m1/scenario.toml --hold
```

- `validate`/`plan`はdocumentの`backend.kind`でvalidation limitを選びます: `af-xdp`は
  `ruster run`と同じ本番limit（`PRODUCTION_VALIDATION_LIMITS`）、`sim`（省略を含む）は`run-sim`と
  同じ`SIM_VALIDATION_LIMITS`です（`plan`は両sideをそれぞれのbackendで）。allocator seed、hash key、
  scenario seedを出力しません。`validate`はM1で必須のresolution、ICMPv4 error、NAT44
  UDP/TCP、firewallの欠落も`stage=bridge`で拒否します。
- `plan`は両documentに`validate`と同じbridge確認を行います。`expected-flush`はdocument間の
  planなので、flushするfamilyは`all`、引き継ぐNAT/firewallは`0`、引き継ぐが新文書が無効にする
  entryだけ落ちる学習ARP neighborとruleの変わるfirewall flowは`invalidated`です。続く`state:`
  blockは`carry`/`flush`/`restart`とfamilyごとの`carried`・`flushed`・`flushed:<reason>`
  （firewallはruleが変われば` reevaluate`）を出します（RELOAD-CARRY）。実際のflush数とcarry数は
  `run-sim`の`apply` event（`flush`と`carry` object）に出ます。capacityやresolution/ICMP/NAT/firewall policyの変更はrestart理由（`STORAGE_SHAPE`等）
  または`changed` flagとしてだけ出し、fieldごとの値は出しません。例外はsecretでないNAT
  filtering、hairpinning、TCP inbound limit、TCP unsolicited-SYN ICMP switch、TCP inbound-rst policy（`nat44-tcp inbound-rst ~ closing -> corroborate`）で、`nat44-tcp filtering ~ address-dependent -> endpoint-independent`、
  `nat44-udp hairpinning ~ on -> off`、`nat44-tcp inbound-sessions-per-remote ~ unlimited -> 8`、
  `nat44-tcp unsolicited-syn-icmp ~ on -> off`の
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
sudo target/release/ruster run -- router.toml                      # 既定のdrop
# stderr: ruster run: privileges dropped: threads=5 capabilities=none bounding-set=cleared no-new-privs=1 identity=unchanged
sudo target/release/ruster run --user 990 --group 990 -- router.toml # 起動後にuid/gid 990へ切替
# stderr: ruster run: privileges dropped: threads=5 capabilities=none bounding-set=cleared no-new-privs=1 identity=switched
# stderr: ruster run: filesystem confined: mode=landlock abi=6 rules=4 threads=5
# stderr: ruster run: seccomp filter installed: mode=kill threads=5 syscalls=43 arch=x86_64
sudo target/release/ruster run --fs-confine off -- router.toml    # Landlockの無いkernel用（risk付きopt-out）
sudo target/release/ruster run --seccomp log -- router.toml       # allowlist外のsyscallをkernelがlogして許可（診断用）
# stderr: ruster run: running generation 1 on 2 port(s); send SIGINT or SIGTERM to stop, SIGHUP to reload
sudo kill -HUP <pid>                                               # configをreload
```

- 権限: 実効capabilityに`CAP_NET_ADMIN`と`CAP_NET_RAW`、および`CAP_BPF`+`CAP_PERFMON`
  （または`CAP_SYS_ADMIN`）、つまりrootか`setcap`/systemdの`AmbientCapabilities`です。
  `CAP_IPC_LOCK`が無ければsoft `RLIMIT_MEMLOCK`がport UMEMの合計（`mode = "auto"`は2倍、
  5.11前のkernelのBPF object分としてportごとに64 KiBを加算した下限）以上必要です（`ulimit -l`、systemdの`LimitMEMLOCK=`）。不足は何も取得せずexit 4で、不足した
  capabilityまたは`limit-bytes`/`required-bytes`を表示します。
- privilege drop（H6、CLI-089〜CLI-095）: 権限が要るのは起動（socket、UMEM、XDP attach）だけなので、
  generation 1をactivateした後・最初のtickの前に全threadの全capability（effective、permitted、
  inheritable、ambient、`CAP_SETPCAP`があればbounding setも）を落とし、`no_new_privs`を立てます。
  既定でonで、`--keep-privileges`で無効にできます（起動後も全capabilityを持ち続けるrisk付きの
  opt-out）。`--user <uid> --group <gid>`（数値、両方そろえて）は同時にreal/effective/saved/fsの
  uid/gidを切り替えsupplementary groupを消します（`CAP_SETUID`/`CAP_SETGID`が必要）。credentialは
  threadごとなので、stdout/stderrのoutput threadとlink watcher/reload workerのthread（H7）は
  spawn時に自分で、router threadはactivate後に最後に自分でraw syscall（libcのprocess全体へのset-id broadcastは使わない）で落とし、最後に
  `/proc/self/task/*/status`で全threadを確かめます。どれかが失敗すれば全portをrollbackして
  `stage=privilege-drop`でexit 1（fail closed）。drop後もRX/TX kick、`XDP_STATISTICS`、link watch
  （netlink dump）、SIGHUP reload、health/device eventのfatal、drain、detachは権限なしで動きます
  （privileged smokeで確認）。teardownのXSKMAP entry削除はLinux 6.5以上（または
  `kernel.unprivileged_bpf_disabled=0`）でないと権限が要るため、それ以外では起動前に
  `TEARDOWN_NEEDS_CAPABILITIES`でexit 4です（挙動変更: Ubuntu 22.04やRHEL 9既定のkernelでは
  変更していないunitがexit 4になり`Restart=on-failure`でloopするので`--keep-privileges`が要る。
  vendor backportは検出せずfail closed）。processはdrop時からdumpable 0（core dumpなし、
  `ptrace`には`CAP_SYS_PTRACE`）。drop後のrootは`CAP_DAC_OVERRIDE`を持たないので、
  reloadするconfigは通常のpermissionで読める必要があります（推奨: `/etc/ruster`を
  `root:<group> 0750`、configを`root:<group> 0640`。rootはownerとして、切替後のuserはgroupで読め、
  `--strict-config-perms`も受理）。statsは`privileges.state=dropped|kept`
  等。詳細はrunbookの「Privilege drop」。
- filesystem confinement（H11、CLI-122〜CLI-127）: drop後もuid 0（`--user`なし）はroot所有の
  全file（`/etc/shadow`、鍵）をread-onlyで開けたので、既定（`--fs-confine landlock`）でLandlockにより
  全threadが開けるfileをrunが読むものだけに絞ります: configのdirectory（pathが指すものと、symlinkなら
  解決先のdirectory。file読み取りだけで一覧は不可。reloadのatomic replaceも読める）、自processの
  `/proc/<pid>`（drop/seccompの検証と`--strict-config-perms`のeuid）、`/proc/sys/net`（link watchの
  sysctl）、自binary（panic backtraceのsymbol）。それ以外のopen/一覧/実行/書き込み/作成/削除/rename/
  （truncateはLandlock ABI 3以上。それ未満はseccompの`openat`の`O_TRUNC`拒否と`truncate`不許可だけが
  防ぐので`--seccomp log|off`では防げない）はpathでは全て`EACCES`（`/etc`、`/dev`、`/sys`、他processの`/proc/<pid>`、
  `/proc/<pid>/root/...`経由やconfig directoryから外へのsymlinkも）。既に開いたfd（socket、
  `/dev/urandom`、stdout/stderr）とmetadata（`stat`、`readlink`）は影響なし。mount namespace+
  `pivot_root`ではなくLandlockを選んだ理由: 権限不要（startupは`CAP_SYS_ADMIN`を要求しない）、
  dropと同じthreadごとのprologueで掛けられる（mount namespaceは呼んだthreadだけで、output threadは
  起動前から居る）、pathもprocfsのnetnsも変わらない。rulesetはthreadが一つの間に作り、各threadは
  自分のdropの直後に自分を閉じ込め（output threadはspawn時、workerはactivate後のspawn時、router
  threadはdropの直後・seccompの前）、各threadは`/`の一覧が`EACCES`になることを、router threadは
  `/proc/self/task`の数だけthreadが閉じ込められたことを確かめます。`landlock_*`/`prctl`はseccompの
  前だけでallowlistは不変。Landlock ABI 1（Linux 5.13）以上で有効（`/sys/kernel/security/lsm`に
  `landlock`）が必要で、ABI 5までのfilesystem権利をhandleし後のABIの権利は扱わない。Landlockが無ければ何も開かずに
  `stage=fs-confine code=LANDLOCK_UNSUPPORTED|LANDLOCK_DISABLED|LANDLOCK_BLOCKED`（`BLOCKED`は
  supervisorのsyscall filterが`EPERM`で拒否）でexit 1（fail closed。
  挙動変更）、`--fs-confine off`はrisk付きのopt-out（warning行）。他の失敗も全portをrollbackして
  `stage=fs-confine`でexit 1。statsは`fs.confine=landlock|off`、`fs.abi`、`fs.rules`、`fs.threads`。
  ABI 4以上ではTCPの`bind`/`connect`も拒否（portを許すruleなし。runはTCPを使わない）。
  configは専用directory（`/etc/ruster/`）に置く（そのdirectory内でuserが読めるfileは読める）。
  directory（名前どおりかsymlink解決後）が`/`なら起動拒否（`code=CONFIG_DIRECTORY_ROOT`）、
  `/etc`、`/home`、`/root`、`/usr`、`/var`なら`CONFIG_DIRECTORY_BROAD` warning。各threadは
  自分のthread idを記録し、router threadは`/proc/self/task`のidと完全一致を要求します。
  詳細はrunbookの「Filesystem confinement (Landlock)」。
- seccomp filter（H8、CLI-102〜CLI-109）: privilege dropの直後・最初のtickの前に、router threadが
  `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC)`一回で全thread（router、output 2、
  `ruster-watch`、`ruster-reload`）を同じsyscall allowlistへ閉じ込めます（`--keep-privileges`でも。
  そのとき`no_new_privs`もここで立てる）。手で組んだclassic BPFで、archが`AUDIT_ARCH_X86_64`でないか
  x32 bitがあれば常にkill、allowlist（AF_XDPの`sendto`/`poll`/`getsockopt`、sleep/futex、read/write、
  read-onlyの`openat`、netlinkの`socket`/`setsockopt`/`connect`/`recvfrom`、teardownの
  `bpf(BPF_MAP_DELETE_ELEM)`、allocation、exit等の43個。codeの読解とprivileged smoke全体の
  `strace -f`から導出）だけを通します。引数filter: `socket`は`AF_NETLINK`/`NETLINK_ROUTE`だけ、
  `bpf`はmap entry削除だけ、`mmap`/`mprotect`は`PROT_EXEC`なし、`openat`は書き込み・作成・切り詰め
  なし、`setsockopt`/`fcntl`/`tgkill`も限定。それ以外は`--seccomp kill`（既定:
  `SECCOMP_RET_KILL_PROCESS`で全threadが即死し、kernelが全fdを閉じてXDP linkはSIGKILL同様に
  detach）、`--seccomp log`（`SECCOMP_RET_LOG`: kernelがlogして実行。診断用）、`--seccomp off`
  （filterなし）。log/offはrisk付きのopt-out（warning行）。installの後に全threadの`Seccomp: 2`、
  `NoNewPrivs: 1`、`Seccomp_filters`が一つ増えたことを`/proc/self/task/*/status`で確かめ、失敗は
  全portをrollbackして`stage=seccomp`でexit 1。statsは`seccomp.mode=kill|log|off`、
  `seccomp.threads`、`seccomp.syscalls`。killの診断は`journalctl -k | grep type=1326`（syscall番号と
  thread名）と`--seccomp log`。詳細はrunbookの「Syscall filter (seccomp)」。
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
  addressの無いportで実効`rp_filter`（`all`とdeviceの大きい方）が0なら、detach中はportのMAC宛てに
  届いたhostの任意のIPv4 address宛てframeがlocalに配送されるので（`arp_ignore`はARP応答を止めるだけで
  これは防がない）、H5から起動を`KERNEL_IPV4_WEAK_HOST`（読めなければ`UNVERIFIABLE
  probe=rp-filter`）で拒否します（owner決定2026-11-02「1.は拒否」、CLI-079）。
  `--allow-ipv4-weak-host`は従来どおり`IPV4_WEAK_HOST_EXPOSURE`のwarningにします（detach中に
  hostの全IPv4 serviceがportから届き得るriskを受け入れる宣言。他のoverrideでは受理しません）。
  既存環境への影響: 新しいnetnsの既定は`rp_filter=0`なので、`net.ipv4.conf.all.rp_filter=1`
  （または2）を設定する（または`--allow-ipv4-weak-host`）まで起動しません。助言として
  `arp_ignore=1`も推奨。
  `net.ipv4.ip_forward`や`conf/<dev>/forwarding`が1（または読めない）なら既定で
  `KERNEL_FORWARDING_ENABLED`（`UNVERIFIABLE probe=forwarding`）で拒否します。router停止中・exit後・
  crash後にport間をfirewall/NAT抜きで運び得るのはkernel forwardingだからで、namespaceの他の
  interfaceに必要なら`--allow-kernel-forwarding`でwarningにできます。`--strict-config-perms`
  （既定off）はgroup/otherが書けるか、root/実効user以外が所有するconfigを起動時とreload時に
  `stage=permissions`で拒否します（configは`O_NONBLOCK|O_NOCTTY`でregular fileだけ）。既存のXDP programが
  あるdeviceは`stage=attach code=CREATE_LINK/EXISTING_PROGRAM`で拒否し、置換しません。
- validation limit（H3、H4b）: configは起動時もreload時も本番limitで検証します。slotごとに
  quoted datagramを持つ3 table（`resolution.capacity.failure-holds`、
  `icmpv4-errors.capacity.actions`、`nat44.tcp.capacity.unsolicited-syn-holds`）はmemoryのため一つ4096 slotまで（`run-sim`は65536）、他の
  table（resolution states/actions/dynamic-neighbors、ICMPv4 error states、NAT44とfirewallの
  directory、port poolを含む）は65536 slotまでです。packet pathでtable全体をscanする処理は
  ありません（PERF-001。NAT44はH4a、resolution/ICMPv4 errorはH4bでkeyed index化。想定traffic
  に合わせて設定する）。runtime storageの合計は64 MiBまで（`run-sim`と同じ）。全tableを
  上限にしたconfig（`fixtures/limits/router-production-max.toml`、`[fragmentation] datagrams = 1024`と`[fragment-tracking] entries = 16384, held-fragments = 512`を含む）のstorageは63.53 MiBです。storageは
  通常のheap（memlockではない）で起動時に一度だけ確保し、`validate`の`storage-bytes=`がその量です。
  最悪のRAMはstorage 64 MiB + UMEM（最大1 GiB、memlock。`auto`のcopy fallback中は2倍で2 GiB）+
  config数MiB。超過は`stage=validate code=CAPACITY_LIMIT_EXCEEDED path=<field> limit=<上限>
  actual=N`または`RUNTIME_STORAGE_BYTES_EXCEEDED`でexit 2です。limit表、tableごとのpacketあたりの
  costと推奨値、slotごとのbyte数はrunbookの「Validation limits and memory」。
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
- SIGHUP reload: handlerはflagを立てるだけで、tick境界でreload worker thread（`ruster-reload`、H7）へ
  渡します。workerが`--config`を起動時と同じ経路で読み直してvalidateし（regular file以外は拒否）、
  新generationのcandidateを作り（production key sequencerは起動後ずっとworkerだけが持つ）、
  稼働中generationの文書と比べます。その間もrouter threadはtickを続け、答えを受けてlive dry runだけを
  行います。準備中・待機中のSIGHUPは一つにまとまって後で一回reloadされます。restart-required（`[backend]`、interface id/MAC、storage shape、
  resolution/ICMPv4 policy）は`reload refused: code=RESTART_REQUIRED reasons=...`、読めない・不正・
  dry run失敗は`reload failed: stage=... code=...`で、どちらも旧generationがそのまま動き続けます。
  通ればbackendがquiescent（旧generationのTXがkernelに無い）になったtick境界でpublication phaseへ
  渡し（待つ間はRXを最大200 ms止める。過ぎれば`stage=quiesce code=TIMEOUT`）、
  `reload applied: generation=N previous=P; interfaces=.. routes=.. firewall-rules=.. ...; flushed ...`
  です（件数で切り詰められたconfigに気づける。行の後半は`carried ...; state arp=.. nat44-udp=..
  nat44-tcp=.. nat44-icmp=.. firewall=..`）。適用時はpending resolution/ICMPv4 errorを捨て、
  NAT44 mapping/session・firewall flow・学習ARP neighborは下の「reload時のstate引き継ぎ」に従って
  引き継ぐか（既定）flushし、counterは保持します。
  `reload.requested|applied|refused|failed`をstatsに出し、停止時に準備中・待機中のreloadは
  `stage=prepare|quiesce code=STOPPED`で数えるのでfinalでは常にrequested = applied + refused + failedです。
  準備中のreloadの経過は`reload.preparing_ms`に出し、10 sを超えると一回だけ
  `warning: reload preparation running for N s; later SIGHUPs are held`を出します。
  quiescence待ち（最大200 ms）だけはRXを止めるので、負荷中はその間にRX ringが溢れ得ます
  （`kernel_rx_ring_full`）。SIGHUPで`ruster run`は終了しません。
- health/link watch（cold path）: 500 msごとにportのcounterを、1 sごとにrtnetlink `RTM_GETLINK`で
  linkを見ます（rtnetlinkとsysctlのroundはlink watcher thread `ruster-watch`が行い、router threadは
  戻った結果を判定するだけ。H7。RTNL lock待ちでwatcherが詰まってもforwardingは止まらず、roundが
  `--link-stale-secs`（既定5）より古くなると以後dueごとにlink query失敗として数え
  `LINK_WATCH_STALE`、3回目で`LINK_UNVERIFIABLE` fatal）。最古のin-flight TX frameが完了しない`TX_STALL`は既定1 sでwarning、10 sでfatal、
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
  （`DEVICE_REMOVED`）、portのrename（`IFLA_IFNAME`が設定の`device`と違う`DEVICE_RENAMED`、H10。
  sysctl pathは名前で引くので、旧名を取った別deviceを読まないようfail closed）、startup MTU未満へのMTU低下（`MTU_DECREASED`）、frameに収まらないMTU
  （`MTU_ABOVE_FRAME`）、3回連続のlink query失敗はfatalです。fatalはdrain・detach・closeの後
  exit 1（`stopped after a fatal health event port=if<id> code=...`）。statsは`watch.state`、
  `if<id>.watch.*`。行はすべて`warning:|recovered:|fatal: port=if<id> health=<CODE>`のvalue-free形式。
- stats: `ruster-run-stats kind=periodic|on-demand|final uptime-ms=N`（`on-demand`はSIGUSR1、H10。100 msに一つまで、その間のSIGUSR1はまとめて後で一つ。
  受け取ったものは次のtick間で一つにまとめて出し、periodicの間隔は変えない）の後に`section.key=value`行
  （`observer.*`、`health.*`、`tick.*`、`rx.*`、`drop.*`、`af_xdp.*`、`if<id>.af_xdp_port.*`、
  `reload.*`、`idle.*`、`notify.*`、`watch.*`（`watch.link_rounds`/`link_rounds_late`/`link_rounds_stale`を含む）、
  `if<id>.watch.*`等）と
  `end`。counterとlabelだけでaddress、MAC、device名、key、seedは出しません。
- idle時は64 tick spinした後、全portのAF_XDP socketへ`POLLIN`の`poll()`で待ちます（H9。`pollfd`
  配列は起動時に一度だけ確保）。frameが届けば即座に起き（H9前は最大約1 ms遅れた）、signal handlerでも
  戻り、timeoutは`--idle-wait-ms`（既定10 ms、1〜100）です。runtimeのtimerはtickでしか進まないので、
  resolutionのpending state/hold/queued request、queued ICMPv4 error、unsolicited-SYN hold（B3）、
  adapterのTX in flightかowed kick、reload workerへ出ているrequestのどれかがある間は1 ms以下に保ち、
  periodic stats、health sample、link roundの期限も越えません。idleのrouter threadのwake-upは毎秒
  約1000回から約100回に減ります。準備完了のままconsumeできないsocketは1 ms sleepと交互になり
  busy spinしません。`idle.*`（`waits`、`woken`、`timed_out`、`interrupted`、`short`、`sleeps`、
  `errors`、`max_wait_ms`）をstatsに出します。負荷中は待ちません。
- exit status: `0` clean shutdown（起動中のsignalでrollbackした場合も）、`1`起動失敗、backend
  fault、fatal health/device event、drain失敗、drain後に残ったTX handoff、close error、
  `2` usage/invalid config、`3`停止期限（または二回目のsignal）で
  TX frameがkernelに残った（detach/closeは済み）、`4`権限/memlock不足（`--user`/`--group`の
  `CAP_SETUID`/`CAP_SETGID`不足、drop後のteardownに権限が要るkernelを含む）。privilege dropの
  失敗は`1`。filesystem confinement（Landlockなしを含む）とseccomp filterのinstall失敗も`1`、filterによるkillはSIGSYS（shellでは159）。
  reloadの拒否・失敗では終了しません。
- systemd通知（H10、`sd_notify`）: `NOTIFY_SOCKET`がある時だけ、起動の最初（threadが一つの間）に
  環境変数を読んで消し、`AF_UNIX` datagram socketを一つ開きます（privilege dropとseccompの前。以後は
  既存fdへの`sendto`だけでallowlistは不変）。readiness行の後に`READY=1`、SIGHUP reloadの開始で
  `RELOADING=1`と`MONOTONIC_USEC=`、終わりで`READY=1`、loopの終わりで`STOPPING=1`、`WATCHDOG_USEC`が
  あればその半分ごとにrouter threadのtick間から`WATCHDOG=1`（止まったrouterはpingしない）。送信は
  blockせず、失敗は`notify.failed`。不正な`NOTIFY_SOCKET`/`WATCHDOG_*`は`stage=notify`でexit 1。
  unit例は`Type=notify-reload`と`WatchdogSec=`（runbookの2章）。
- multi-queue、structured logはdeferred
  （requirements CLI-034、runbookの「Known limits」）。filesystemの閉じ込め（CLI-034の
  chroot/mount namespace項目）はH11でLandlockとして実装。

### reload時のstate引き継ぎ（RELOAD-CARRY）

applyするsuccessor文書の`[reload] state`が、reloadで既存stateをどうするかを決めます（table/key
省略時は`carry`。mode切り替え自体もreloadable）。

```toml
[reload]
state = "carry"   # 既定。"flush": RELOAD以前どおり全flushして全hash keyをrotate
```

`carry`ではfamilyごとに、新文書が意味を変えないstateをhash keyごと引き継ぎます。firewall ruleの
追加のような無関係な変更でNATを通るTCP/UDP接続は切れません（RFC 4787 REQ-1/REQ-5、RFC 5382
REQ-5）。

| family | 引き継ぐ条件 | 引き継げないとき |
|---|---|---|
| NAT44 UDP/TCP/ICMP query | inside/outside、public address、port pool、filteringが同じで、UDP/ICMP idle timeoutが延びず、per-host limitが下がらず新設もされない（TCPはphase timeoutも同じ） | そのfamilyだけflush（`flushed:interfaces`/`public-address`/`port-range`/`filtering`/`timers`/`quota`） |
| firewall flow | idle timeoutが延びない。expire済みのflowは落とし、routeのegressが変わった（消えた）flowはrevoke、ruleが変わればapply時に残る全flowを新ruleで再評価し、拒否されるflowはrevoke（以後どちらの向きも通らない） | timeout延長はflush（`flushed:timers`）、`live flows x (rules + 4 x 16)`が4194304 testを超えるとflush（`flushed:reevaluation-budget`、件数であり時間ではない。最大tableで開発host 20〜48 ms、route lookupは1件16単位） |
| 学習ARP neighbor | interfaceのIPv4 addressが同じ、static neighborに置き換わらない、ARP-031有効時はon-link | そのentryだけ削除 |

pending resolution、ICMPv4 error queue/limiter、TCP unsolicited-SYN holdは常に捨てます。旧設定で
expireしたstateはreloadで生き返りません（timeoutの延長はflush、短縮は引き継いだstateに最終
activityから効く）。carry中はhash keyがprocessの寿命の間変わらないので、`state = "flush"`のreload
かrestartで定期的に回してください（毒されたARP学習とNAT/FW stateも同時に消えます）。applyは失敗原子的で、失敗したreloadは
何も引き継ぎも捨てもしません。restartは常に全flushです。詳細はarchitectureの「reload state carry」、
運用はrunbookの6章です。

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

#### AF_PACKET backend（AFPKT-015）

`kind = "af-packet"`は`ruster run`のAF_PACKET（TPACKET_V3）backendです。XDP program、`CAP_BPF`、
`RLIMIT_MEMLOCK`、single-queue/RSS steeringが要らず`CAP_NET_RAW`だけで動くdebug/fallback用で、
AF_XDPが主backendのままです（性能は未測定。forwardごとに一回copyし、kernel stackも同じframeを処理し、
TXはqdisc経由なのでAF_XDP copy modeより遅い想定）。

```toml
[backend]
kind = "af-packet"

[backend.af-packet]
max-frame-len = 1514             # 省略時1514（590..=9230）。全portのdevice MTUは max-frame-len - 14 以下

[[backend.af-packet.ports]]      # interfaceごとに1つ
interface = "wan"
rx = { block-size = 65536, block-count = 8, retire-timeout-ms = 2 }  # 4096..=4MiBの2の冪、1..=65536、1..=1000
tx = { block-size = 65536, block-count = 4 }
```

- frame slotは`max-frame-len`から導出（kernelのper-frame header込みの2の冪、1514なら2048）、TX ringは
  `block-size / slot * block-count` frame。ring合計はportごと256 MiB、全体1 GiBまで。page sizeの倍数は
  起動時に`ruster-io-afpacket`が再検査します。`validate`の要約は`backend=af-packet ports=2
  max-frame-len=1514 ring-bytes=...`、`plan`は`backend af-packet max-frame-len ~ ...`、
  `backend-af-packet-port + if1 dev eth0 rx 8x65536 frame 2048 retire 2 ms tx 4x65536 frame 2048`で常に
  restart-required `BACKEND`。`af-packet`以外のkindでの`[backend.af-packet]`は
  `BACKEND_AF_PACKET_WITHOUT_KIND`、`af-packet`での`[[backend.ports]]`は`BACKEND_PORTS_WITHOUT_AF_XDP`。
- AF_PACKETはframeをkernelから奪わずcopyを受け取るだけで、kernel stackはrun中も全frameを処理します。
  起動時のkernel露出拒否（IPv4 address/route、forwarding、weak host、IPv6、同じoverride）はAF_XDPと同じで、
  RX queue数は問いません。加えてdevice MTUが`max-frame-len - 14`を超える（`MTU_ABOVE_FRAME`。小さいのは可で、
  9000のLANと1500のWANは`max-frame-len = 9014`で動く）、bridge/bond/team/VRFへの従属や同じnamespaceで
  portに積まれたVLAN/macvlan/ipvlan/MACsec/veth peer（`KERNEL_UPPER_DEVICE`、run中もfatal）、GRO/LRO/hardware GROがon
  （`RECEIVE_OFFLOAD feature=rx-gro`等、`ethtool -K <dev> gro off lro off`）を拒否します。
  `[[interfaces]] mtu`（MTU1）はAF_XDPと同じくdevice MTU超過が`MTU_BELOW_CONFIG`（拒否）、未満が
  `MTU_BELOW_DEVICE`（warning）です。
- run中はlink watchのkernel露出（address、route、forwarding、weak host、IPv6）がAF_XDPのwarningではなく
  同じcodeのfatal（exit 1）です（overrideで受理したものはwarningのまま）。kickの`ENXIO`でbind先deviceが
  消えたportは`DEVICE_REMOVED`、kernelの`PACKET_STATISTICS`（32-bit、読むとreset）はhealth sample
  （500 ms）ごとにfoldします。shutdownはdrain後にsocketを閉じ`closed N port(s)`です。
- seccompの`getsockopt`は(level, option)の組`(SOL_XDP, XDP_STATISTICS)`、`(SOL_PACKET,
  PACKET_STATISTICS)`、`(SOL_SOCKET, SO_ERROR)`だけに限定しました（AF_XDPも同じfilter）。
- 詳細とtroubleshootingは[runbook](docs/runbook-m2.md)の「AF_PACKET backend」、privileged smokeは
  `scripts/priv-run-smoke.sh`の`priv_run_afpacket_*`（veth、NAT、ICMP、reload、link、socket error、
  kernelが自frameを送らないこと、SIGTERM drain、device削除）。

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

`ruster-io-afpacket`のscripted syscall test（AP3のscheduling testを含む）も任意でMiriで確認できます。
test harnessがmapping addressを整数で持つためpermissive provenanceで実行します（CI gateではありません）。

```bash
MIRIFLAGS=-Zmiri-permissive-provenance cargo +nightly miri test -p ruster-io-afpacket --lib
```

AF_XDP native session/XDP attachのprivileged smokeは`sudo -n`が使えるLinux 5.9以上のhost
（`ip`はlibbpf付きiproute2、`python3`が必要）で明示的に実行します（CIでは下の`XDP veth` job）。

```bash
scripts/priv-xdp-smoke.sh
```

AF_PACKET live adapterのprivileged smoke（AP3）は`sudo -n`と`ip`、`python3`があるLinuxで
`scripts/priv-afpacket-smoke.sh`です（CIでは同じ`XDP veth` jobの一step）。専用netns内だけに
veth二組を作り、netnsを必ず削除します。

```bash
scripts/priv-afpacket-smoke.sh
```

`ruster run`のprivileged E2Eは`scripts/priv-run-smoke.sh`です（同じ前提に加え`ethtool`）。
binaryを通常userでbuildし、router用とhost A/B用の三つの専用netns（`ruster-run-<pid>-<random>`と
`-a`/`-b`）にveth pairを作り（initial namespaceには作らない）、netns内で`ruster run`をchild
processとして起動します。host Aからhost BへのUDPがrouterのARP、NAT44、firewallを通って届くこと、
SIGTERMでexit 0・XDP detach・final stats、二つ目のportのopen/attach失敗でexit 1と一つ目のportの
detach（外部programは不変）、2-queue device・kernel IPv4 address・kernel routeの拒否、SIGKILL後の
auto-detachと再起動（transientなBusy/MemlockLimitはrouter自身もretryし、test側もbounded retry）、
H6のprivilege drop（全phaseが既定のdropで動き、forward phaseで全threadの`CapInh`/`CapPrm`/`CapEff`/
`CapAmb`/`CapBnd`が0で`NoNewPrivs`が1、ops/icmp phaseは`--user`/`--group`で実行userへ切り替えて
全threadのuid/gidとsupplementary groupなしを確認した上でreload・link down/up・MTU fatalを行い、
privileges phaseでdrop後のrootが他userの0700 directoryのconfigをreloadできない
（`PERMISSION_DENIED`）こと、`--keep-privileges`ではcapabilityが残り同じreloadが通ることを確認）、
H8のseccomp filter（全phaseが既定の`--seccomp kill`で動き、threadを確かめる所では全threadが
`Seccomp: 2`、`NoNewPrivs: 1`、shellより一つ多い`Seccomp_filters`。seccomp phaseで`--seccomp log`の
forward・reload・link down/upとdmesgに記録が無いこと、`--seccomp off`で全thread未filter、SIGSYSでの
group exitで両linkがdetachすること、最後にsmoke全体でruster binaryのseccomp記録が増えないことを確認）、
H11のfilesystem confinement（全phaseが既定の`--fs-confine landlock`で動き、forward phaseで
`filesystem confined: mode=landlock ... threads=5`と`fs.*`。fs phaseはreloadをprobeにして、configを
directory外の読めるfileへのsymlinkにatomicに置き換えると`stage=read code=PERMISSION_DENIED`で転送は継続、
directory内へ置くとapply。uid 0では`/etc/shadow`、`/etc/passwd`、`/proc/1/status`、
`/proc/<pid>/root/etc/shadow`へのsymlinkが全て`PERMISSION_DENIED`。対照として`--fs-confine off`では
同じ`/etc/passwd`がreadを通る）、
RELOAD-CARRYのreload_carry phase（host Aからhost BへのNAT越しの長寿命TCP接続と固定source portのUDP flowが、無関係なfirewall ruleを足すSIGHUP reloadの後も同じsocket・同じpublic portで通り（reload行は全family `carried`、revoke 0）、両方を拒否するruleへのreloadでrevokeされ以後通らない（`firewall-revoked=2`）。AF_PACKET phaseの中でも同じ確認をする）、B3のunsolicited_syn phase（WAN→LANのnew TCP flowを全destinationへ許可するruleを足すと、host BのTCP SYNが未mappingのpublic portへ届いて6秒以上後に一つだけICMP 3/3、reloadでswitch offにすると何も返らず、router-v1のdefault deny firewallへreloadしても何も返らない）、N5のicmp_query phase（`[nat44.icmp]`の無いrouter-v1ではhost Aからhost Bへの`ping`が届かず`NAT44_UDP_UNSUPPORTED_TRANSPORT`、`[nat44.icmp]`と`icmp` firewall ruleを足した構成（planは`nat44-icmp ~ off -> on`でrestart-required）ではhost Bへのpingが3/3返り（host Bには192.168.1.0/24への経路が無いので、replyが返ること自体が変換の証拠）、public addressへのpingはrouter自身が答え、`nat44_icmp.outbound_translated=3`と`inbound_translated=3`、mapping 1つ）、MTU2 part Aのdf_clear phase（host Aのraw socketから同じIPv4 IDのDF=0 UDP二つとDF=1一つをhost Bへ送ると、host Bでは三つとも203.0.113.2から届き、DF=0の二つはDF=0のまま連続した生成ID、DF=1は送ったIDのまま）、MTU2 part Bのfrag phase（WANを1400にするとhost AのDF=0 1500-byte UDPがNAT後にRFC 791どおりの2 fragmentでhost Bに届き再構成され、LANを1280にするとhost BのDF=0 1400-byte UDPがinboundで2 fragmentになりhost Aで再構成される）、NAT-FRAGのnatfrag phase（firewall on、host Bのkernelがfragmentした3000-byte UDPがNATを通ってhost Aで再構成され、host Aのraw socketから最後のfragmentを先に送ったoutboundもrouterがholdとreleaseしてhost Bで再構成される。`mode = "refuse"`では届かない）、
M2 S10bのops phase（一つの稼働中routerでSIGHUP reloadによりUDP ruleをdenyにして届かなくなり、
戻して再び届く。generation 2/3でrestartなし。UMEM shapeを変えたreloadは`RESTART_REQUIRED`で
拒否され転送は継続。router netns内の`ip link set ra down/up`でwarningとrecovered、転送回復。rbの
MTUをframe上限超へ上げるとexit 1でdetach）、kernel forwardingの段（`ip_forward=1`の起動拒否、
overrideでのwarning、稼働中のwarningとrecovered。M2 S11で`ip_forward=0`のまま
`conf/ra/forwarding=1`の起動拒否`scope=device`と稼働中のif1だけのwarning/recoveredを追加）、
H10のsystemd phase（work directoryのdatagram socketをpython受信者がsystemdの代わりに受け、`NOTIFY_SOCKET`と`WATCHDOG_USEC=400000`、実行userへの切り替え、既定の`--seccomp kill`の下で`READY=1`が最初、2 sに6〜14回の`WATCHDOG=1`、reloadで`RELOADING=1`（`MONOTONIC_USEC`付き）と generation 2の`READY=1`、SIGUSR1で`kind=on-demand` block、`STOPPING=1`が最後）とrename phase（稼働中に`ip link set ra down`と`name rx`でexit 1 `DEVICE_RENAMED`、attachが残らない）、
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
