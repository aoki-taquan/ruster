# ruster

自宅ラボで実用でき、挙動を自分で説明できるソフトウェアルータを、パケット処理コアから作るプロジェクトです。

`main`の旧実装は [`prototype-v0.1`](docs/prototype-v0.1.md) として固定しました。現在の
active treeは、そのコードを継承しないv0.2のゼロベース実装です。

## v0.2 bootstrap

この最初の縦切りは、外部依存を持たない二つのlibrary crateだけで構成します。

- `ruster-core`: backend所有packetを借用し、Ethernet II / IPv4検証、LPM、
  TTL/checksum/MAC rewrite、local IPv4向けARP reply、static neighbor miss時の
  ARP Request生成action、fixed-capacity dynamic ARP cache、local ICMPv4 Echo
  responder、ICMPv4 Time Exceeded / Destination Unreachable生成、opt-inの
  single-domain UDP NAT44/NAPT、outbound-initiated TCP NAT44/NAPT、最小IPv4
  stateful forward firewallを扱う。
- `ruster-io-sim`: rootやNICなしでRX/generated TXのFIFO、budget、TX/drop、
  traceを決定的に検証する。

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
peerをcaller-backed固定配列で所有します。outboundはEndpoint-Independent Mapping、
inboundは過去に送信したremote IPv4だけを許すAddress-Dependent Filteringです。
IPv4 optionsなし、DF=1/MF=0/offset=0のatomic UDPだけを変換します。受信reserved flagは
fragment判定から除外し、NAT rewrite後もwire上に保存します。UDP checksum zeroを保存、
nonzero checksumとIPv4 checksumをRFC 1624でincremental更新します。

idle TTLはdefault 300秒、minimum 120秒で、outbound TX requestだけがrefreshします。
live stateをcapacity pressureでevictせず、snapshot/config mismatchはfail closedです。
NAT runtimeへ到達した非退行時刻はdrop結果でもwatermarkへ反映し、expired/miss後の古い
時刻によるmapping復活を許しません。outsideからinsideへのpublic DNATを通らない直通LPMも
neighbor解決前にfail closedです。
publication変更はvalidated configと`Nat44UdpRuntime::reconcile`による明示的な全state flushを
要求します。policyで明示的にopt-inした場合だけ、outside/public宛てICMPv4 Type 3/Code 4が
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

TCP NAT44は別のcaller-backed mapping/session storageを持ち、UDPと同じ数値public portを
独立して使用できます。mappingはinternal TCP tupleのEndpoint-Independent Mapping、filterは
remote IPv4とremote TCP portのexact matchです。新規sessionはoutbound SYN=1かつ
ACK/RST/FIN=0だけが作成し、既存sessionではSYN-ACK、data、FIN、RSTを含むvalid packetを
双方向に変換します。TCP header/options/dataを含むIPv4 payload全体のchecksumをstate更新前に
検証し、address/port rewrite後もRFC 1624で更新します。TCPでは算術結果zeroもwire zeroの
ままです。TCPもreserved flagをfragment判定から除外してwireへ保存し、reserved以外は
DF=1/MF=0/offset=0を要求します。

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

設計契約と非対象は[architecture v0.2](docs/architecture-v0.2.md)、要件とRFC根拠は
[requirements](docs/requirements-v0.2.md)、production backendから自宅ラボ運用までの
優先順位とmilestoneは[development plan](docs/development-plan-v0.2.md)を参照してください。
