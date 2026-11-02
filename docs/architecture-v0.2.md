# Architecture v0.2

## 境界

`ruster-core`はNIC、thread、OS、設定形式を知りません。worker-ownedな`PacketIo`から
GATでbatchを借用し、batchから一度に一つのcore所有`PacketLease`を得ます。backendの
raw `PacketSlot`はcallerへ返りません。leaseはzero-sizeな`Rc` markerで`!Send + !Sync`
となり、live slotをworker間で移動できません。

packet leaseには三つの正常な終端があります。

1. forwardするslotは、in-place rewrite後にegress `IfId`を付けて`commit`する。
2. dropするslotは、stableな`DropReason`を付けて`recycle`する。
3. router自身が処理したcontrol packetは、typed `ConsumeReason`で`consume`する。

leaseを未完了のままdropした場合、coreのRAII実装が`LeaseAbandoned` lifecycle completion
をbackendへ必ず返します。これはforwardingの`DropReason`とは別です。batchからまだ
leaseしていないslotはRX backendの所有下に残ります。coreからUMEM、mbuf、simの`Vec`
は見えません。

`consume`はforwarding上の論理終端です。backendはそのRX bufferを物理的にはrecycleし、
simの`BatchCompletion.recycled`にはdropとconsumeの両方を数えます。両者の区別は
`BatchReport.consumed`、typed `RecycleCause`、terminal traceで保持します。

`forward_batch*`へ渡すbatchは`PacketIo::receive`が返したfreshなbatchに限ります。
事前に`next_packet`を呼んだり、leaseを完了したりしてはならず、batch lifecycle counterは
zeroから始まります。`BatchCompletion`はforwarding関数の差分ではなくbatch生成からの
全期間を集計するため、partial/pre-accounted batchはservice APIの対象外です。

`receive`はbackend固有errorを返せます。`finish`はerror時にも失われないcompletionを
必ず返し、TX requested/accepted/rejectedを分けます。常に
`accepted + rejected == requested`で、reject slotはbackendがreturn前にrecycle/free
します。AF_XDPのacceptedは`finish`のreturn前にTX producerへdescriptorをpublishしたことを
意味し、wire送信やcompletion queue到着を意味しません。publish後のwakeup errorでもその
descriptorはaccepted/in-flightのままです。rejectedはpublishされずreturn前にreclaimされます。
publish済みframeはcompletionまでbackend所有で、`recycled`には数えません。これにより
AF_XDP ring fullやDPDK partial TXでもrequestを成功と誤認しません。

## forwarding transaction

処理はvalidate/decideとmutate/commitの二段階です。

```text
Ethernet validate
  ├─ IPv4 version/IHL/Total Length/header checksum validate
  │    ├─ ingress local binding → ICMPv4 validate/admission → Echo Reply or local consume
  │    └─ options policy → LPM（missならICMP Type 3/Code 0）→ TTL check
  │         （expiredならICMP Type 11/Code 0）→ typed neighbor/interface lookup
  │         → TTL/checksum/MAC rewrite → commit
  └─ Ethernet/IPv4 ARP profile validate → ingress local target lookup
       → RFC 826 merge → Request localならin-place Reply、それ以外はlocal consume
```

leaseからmutable sliceを一度だけ取得し、同じsliceをimmutable reborrowして全判断を
終えます。rewrite直前に全rangeを再検証するため、drop時のpacket bytesは入力と同一です。
packet terminal traceの`TxRequested`はcommit後に記録しますが、wire送信やbackend accept
を意味しません。finish後の`BatchCompleted`だけがaggregate accepted/rejectedを示します。
ordered outcome/tokenを導入するまではpacket単位accepted traceを主張しません。
`TraceSink`はpanic禁止の契約で、productionの`NoTrace`はallocationしません。
`VecTrace`はsim crateだけに存在します。
`DropReason`は既存の`repr(u16)` discriminantを変更せず末尾へ追加します。
`TraceEvent`と`ConsumeReason`は今後のprotocol追加をsource-compatibleにするため
`#[non_exhaustive]`です。downstreamはwildcard armを持つ必要があります。

route、interface、neighbor、local IPv4 bindingはvalidated immutable snapshotのborrowed
sliceです。routeはcanonical prefixだけを受け付け、lookupは`/0`と`/32`を含む
longest-prefix matchです。gateway routeはnext-hopを、connected routeはpacket
destinationをneighbor targetにします。

snapshot公開前にcontrol planeが守る不変条件は次の通りです。

- route prefix/length、interface `IfId`、neighbor `(IfId, target)`は重複しない。
- routeとneighborが参照するegress `IfId`はinterface snapshot内で解決できる。
- local IPv4 bindingが参照する`IfId`は解決でき、現profileでは一つのinterfaceに
  local IPv4は一つだけ、同じlocal IPv4を複数interfaceへ設定しない。

local bindingはMACを持ちません。ARP replyのlocal MACは対応する`Interface`からだけ
取得し、link-layer identityのsingle source of truthを維持します。複数local IPv4を
一つのinterfaceへ設定するprofileは将来scopeです。

routeに対応するneighborがまだ無いこと自体はvalidです。ARP解決前の通常状態として
forwarding時に`NeighborUnresolved`でbytes不変recycleします。

static neighbor missでは、routeが選んだ`(egress, next-hopまたはdestination)`と、
egress interfaceのMAC/local IPv4からtyped `ArpRequestAction`を作れます。RX処理中は
caller提供の固定ringへactionを積むだけで、RX batchの`finish`後に独立したgenerated
sessionを開始します。元packetは常にbyte不変`NeighborUnresolved`でrecycleし、hold
しません。

generated sessionはbegin時にegressを固定し、最終Ethernet frame長ちょうどの
backend-owned bufferをGAT/RAII leaseで借用します。coreにはheadroom、capacity全体、
UMEM、mbufを公開しません。leaseは`!Send + !Sync`で、`commit`、`cancel`、未完了Dropの
いずれかをexactly onceでbackendへ返します。allocationのzero length、max frame超過、
buffer unavailableを区別し、失敗時はownershipを移しません。finishはerror時も
`attempts=allocated+failed`、`allocated=requested+cancelled+abandoned`、
`accepted+rejected=requested`のaccountingを返し、rejectをreturn前にrecycleします。

resolution runtimeも`!Send + !Sync`で、caller提供のlinear fixed resolution table、
action ring、dynamic neighbor table、任意のfailure hold tableを借用します。すべてのkeyは
`(IfId,target IPv4)`です。stateはauthoritativeなRequest action、generation、committed
total attempts、backend accepted attempts、request/failure時刻を保持し、
`InitialQueued → Waiting → RetryQueued → Waiting → Failed`を明示します。
intervalは1000ms以上、Failed hold-down TTLはinterval以上、max attemptsはnonzeroとし、
local defaultはtotal 3 attemptsです。この回数とhold-downはRFCの固定値ではありません。
batch/timer単位で注入された`MonotonicMillis`だけを使い、加算deadlineや
`attempts * interval`を作らず、順序確認後の差分で判定するため`u64` overflowはありません。
逆行はcounter/trace以外のaction/state/poll cursorを変更しません。active/Failed entryは
evictせず、Failed TTL exact boundary後だけreuseします。runtime生成時は全storageを
emptyへ初期化します。processをまたぐstate永続化/resumeは未実装です。

dynamic neighbor TTLはzeroを拒否するconfigurable policyです。static neighborを最初に
lookupし、static missだけdynamicを参照します。dynamic slotは`elapsed < TTL`だけliveで、
exact boundaryではlazy expiryして転送に使いません。insert時もempty/expired slotだけを
reuseし、liveな別keyをevictしません。既存keyのMAC/refresh時刻更新は追加capacity不要です。
periodic scanはなく、lookup/insert時のbounded linear lazy maintenanceです。

control planeがforwarding snapshotを公開する同じworker tickでは、timer pollや次のpacket
より前に、そのsnapshotを`ResolutionRuntime::reconcile_publication`へ渡します。これにより
static keyと一致するdynamic/active state/actionに加え、interface MAC、local binding、
route authority、target safetyが新snapshotと一致しないstale retryを削除し、wrapped action ringのunrelated
FIFOを維持します。旧static-only caller向け`reconcile_static`は互換APIとして残します。
static公開後に同keyのARPを受けた場合もmerge pathが同じkey cleanupを行います。

新しいpublication pathでは`ValidatedForwardingOwner`がcallerから受け取ったboxed tableを
一度だけ検証・hashし、以後の`ForwardingSnapshot` viewをallocation/再scanなしのO(1) borrowで
返します。ownerごとのnonzero nonceはchecked incrementだけで発行し、枯渇時はwrapせず
publicationを拒否します。pointer/contentが同じでもnonceが異なるため、allocator reuseを
publication identityとして受理しません。公開前の`ResolutionRuntime::preflight_publication`
はaction ring windowとpending countをread-onlyで検証し、exact runtimeのexclusive borrowを
permitへ保持します。permitのDropは全field不変、`commit`は失敗分岐やpanic/overflowなしに
state/action/dynamic neighbor/failure holdを全flushしてcursor/countをzeroへ戻します。
累積運用counterとmonotonic watermarkは履歴として保持します。これは旧snapshot由来の
ARP request、learned MAC、Host Unreachable候補を新publicationへ持ち越さない保守的境界です。
`reconcile_publication`は既存caller向けの選択的互換APIとして残します。
一度でもRequestをcommitしたkeyを学習/static/authority変更でcancelする場合、retry actionと
stale source authorityは削除しますが、`(IfId,target,requested_at)`だけのnon-retrying
`Cooldown` tombstoneを残します。dynamic TTL expiryやstatic publish/remove churnはこの
commit起点intervalを短縮できません。timer pollはtombstoneからretryを生成せず、exact
interval後だけfresh packetが新しいsnapshot authorityで新世代を開始できます。未commit
actionのcancelはtombstoneを残しません。expired tombstoneだけstate pressure時にreuseします。

同じkeyのactionは一つだけqueueできます。抑制deadlineはenqueue時でなく、generated
leaseをcommitしてTX requestedになった注入時刻から開始します。allocation/build失敗時は
actionを保持しattempt/deadlineを消費しません。backend reject/finish errorでもcommit済み
total attemptとして数えますが、accepted attemptはcompletionの`accepted`だけを
generation-safeに数えます。最後のRequest commit直後にはFailedにせず、完全なinterval後の
schedule/timer pollが一世代一度だけ`TimedOut`へ遷移させ、その後はhold-down中`Failed`を
返します。

`poll_resolution_timers`はI/Oを行わず、明示scan budgetまでpersistent round-robin cursorで
走査します。late pollも一つの次attemptしかqueueせずcatch-up burstを作りません。action
capacity不足はtyped deferred report/traceとなり、cursorを進めて他keyを飢餓させません。
traffic missもdue retry/timeout/Failed expiryを進めるため、timer頻度だけに正しさを依存
しません。normal forwardingとreverse ICMP neighbor missは同じruntimeを使い、terminalでも
受信packetのdrop reasonは`NeighborUnresolved`のままですがresolution resultで区別できます。

target `0.0.0.0`、IPv4 multicast、limited broadcast、local address、およびcanonical
connected routeから確定できるnetwork/directed-broadcastにはARP Requestを生成しません。
判定はpacketを選択したrouteだけでなく、snapshot内の同一egressにある全connected routeを
確認します。

生成する通常RequestはRFC 894のEthernet minimum framingに合わせた、FCSを含まない
60 bytesです。先頭42 bytesをRFC 826の
Ethernet/IPv4 ARP（Ethernet destination broadcast、SHA/source MACはlocal、SPAはnonzero
local IPv4、THA zero、TPA target）として書き、残り18 bytesを必ずzero paddingします。
THA zeroは決定的なlocal profile choiceであり、RFCのMUSTとは主張しません。

RFC 1122 §2.3.2.1から採用する境界はARP cache invalidation adviceとRequest flood
preventionです。retry scheduling、max attempts、`Failed`、hold-downとそのdefault値は
すべてlocal policyであり、RFC要件とは主張しません。RFC 1812 §3.3.2はfruitless
resolutionを永遠に続けずdatagramを捨てる、より広いrouter behaviorの境界として扱います。
packet bufferのhold/replayは実装しません。代わりにdirectly-connected destinationの最初の
eligible missだけ、別caller-backed slotへvalidated metadataと元IPv4を最大548 bytes copy
します。元RX leaseは直ちに`NeighborUnresolved`でrecycleされ、ARP成功後もreplayしません。
generationの最後のcommitted attemptからfull interval経過し、同generationで少なくとも一つ
ARP Requestがbackend acceptedだった場合だけType 3/Code 1候補へpromotionします。全Request
reject、gateway next-hop failure、hold capacity不足では生成しません。RFC 1122 §2.3.2.2の
「最新datagramを保存してresolution成功時に送る」SHOULDとは異なる、DoS耐性を優先した
quote-only/first-eligible-wins deviationです。multi-worker resolution ownership/SPSCは
未実装です。

## IPv4 scope

v0.2 bootstrapはEthernet II上のIPv4 datagramを転送します。

- IPv4 Total Lengthより後ろはlink paddingとして解析結果から除外する。
- IHLが示すoptionsをheader length/checksumの対象にする。
- option固有の意味論は未実装のため`Ipv4OptionsUnsupported`でbytes不変dropする。
- fragment offsetやMFに関係なく、このsliceはL4を参照しないためdatagramとして転送する。
- TTLは1減算し、header checksumはRFC 1624のincremental updateで更新する。

EtherTypeを読んだ直後、IPv4/ARPのprotocol parserより前にcommon Ethernet ingress admissionを
行います。その後のIPv4構造/header checksum検証とIP admissionを含め、NAT/FWの
runtime/config参照、monotonic watermark、state、audit、resolution、ICMP error action、
packet rewriteより前に完了します。順序とstable reasonは次のとおりです。

1. ingress `IfId`がsnapshotのinterfaceに存在すること。
2. Ethernet sourceのzero、exact broadcast、multicast/groupを拒否すること。任意の
   individual unicast sourceは許可し、sourceがrouter MACと同じ値であることだけでは拒否しない。
3. IPv4 destinationはexact ingress interface MACだけを許可する。ARP destinationはexact
   ingress interface MACまたはexact broadcastだけを許可し、zero、その他のgroup、
   別interfaceのrouter MACを含むforeign unicastを拒否する。ARPではEthernet sourceとSHAの
   一致を要求しない。
4. IPv4 sourceはrouterのいずれかのlocal IPv4 address、`0/8`、`127/8`、`224/4` multicast、
   `240/4` Class Eを拒否すること。
5. IPv4 destinationはlimited broadcastを最優先で分類し、`0/8`、`127/8`、multicast、
   その他の`240/4`を拒否すること。
6. read-only LPMで選んだsource prefixのnetwork/directed-broadcastを拒否する。nonlocal
   destinationも同様に選択prefix境界を拒否し、そのRouteを後続処理で再利用する。

RFC 1812 §§4.2.2.11, 5.3.4, 5.3.5, 5.3.7に基づくmartian/group境界です。BOOTP relayや
IPv4 multicast forwardingのhandlerは存在しないため例外を設けずfail closedにします。
limited broadcastをforwardしないRFC 1812 §5.3.5.1のMUSTは満たします。一方、同節は受信した
limited broadcastをdiscardせずlocal deliveryすることも要求します。現profileにはgenericな
IPv4 local deliveryとBOOTP relayが無いためcommon admissionでdropしており、このlocal reception
要件は明示deviationです。
LPMはmore-specific routeを優先するため明示`/32` host routeが広いprefixの境界を上書きします。
RFC 3021の`/31`と`/32`はnetwork/directed-broadcast分類から除外します。local destinationは
forward destination境界判定を受けずStrong ES local処理へ進みますが、source admissionは共通です。
同一interfaceをegressに選ぶrouteもexact ingress MACを満たせば通常どおりforwardします。
generated ARP/ICMP frameはRX ingress admissionを通らず、生成時にegress interfaceのMACを
使用します。VLAN/QinQ (`0x8100`/`0x88a8`) はinner EtherTypeを解析せず
`UnsupportedEtherType`でbyte不変dropします。
reserved IPv4 flagだけを理由にdropしない既存契約は維持します。

## ICMPv4 local control scope

RFC 792とRFC 1122 §3.2.2.6のEcho responder要件を実装します。ただしlocal deliveryは
RFC 1122 §3.3.4.2のStrong ES modelと同様に、ingress `IfId`にbindingされたdestinationだけを
router自身宛てとして扱います。同じaddressが別interfaceにbindingされていてもlocal扱いせず、
通常のL3 forwardingへ進めます。これはrouterのいずれかのinterface address宛てをlocal
deliveryとするRFC 1812 §5.2.3からのbootstrap deviationです。local判定はIPv4
version/IHL/Total Length/header checksum検証後、forwardingのTTL expiry/LPM/ARPより前です。
したがってTTL 0/1のlocal Echo Requestにも応答します。

originated IPv4のTTLはRFC 1122 §3.2.1.7とRFC 1812 §4.2.2.9に従うvalidated
`Ipv4OriginPolicy`から取得します。`ForwardingSnapshot::new`はdefault 64を使い、
`with_ipv4_origin_policy`で1..=255を選べます。zeroはsnapshotへ到達する前にrejectします。
Echo Reply TTLは受信値から独立したこのpolicy値です。

実装profileはIHL=5、protocol=1、unfragmented、Echo Request Type 8/Code 0です。ICMP message
範囲はIPv4 Total Lengthで閉じ、Internet checksumはodd lengthを含む全messageで検証します。
全validation/admissionを終えるまでbytesを変更しません。replyは同じRX leaseをingressへ
commitし、次だけを書き換えます。

- Ethernet destinationをrequest source、sourceをingress Interface MACにする。
- IPv4 source/destinationを交換し、TTLをvalidated origin policy値にする。
- RFC 6864のatomic datagram profileとしてID=0、DF=1、MF=0、fragment offset=0にする。
- ICMP Typeを0へ変え、IPv4/ICMP checksumをRFC 1624で正しく更新する。

DSCP/ECN、Total Length、protocol、ICMP identifier/sequence/data、IPv4 Total Length後の
link paddingは保存します。IPv4 address pairの交換はone's-complement sumを変えないため、
IPv4 checksum更新対象はTTL/protocol word、ID、flags/offsetです。

RFC 1812 §§4.2.2.11, 5.3.4, 5.3.7とlocal anti-amplification policyに基づくnarrow
admission profileとして、replyを生成する前に次を要求します。

- IPv4 sourceがingress上のunicast hostである。`0/8`、`127/8`、multicast、`240/4`、
  limited/directed broadcast、connected network address、ingress-local claimはdropする。
- RFC 1812 §5.3.4のlink broadcast/multicast抑止に加え、local policyとしてEthernet
  sourceがnonzero unicastである。
- local policyとしてEthernet destinationがingress Interface MACと完全一致する。
  broadcast、multicast、foreign unicast宛てのIP-local frameには応答しない。

validなlocal non-ICMPと、checksum-validなunfragmented non-Echo ICMPは
`Ipv4LocalUnsupported`でbyte不変consumeし、routing/ARPへ流しません。malformed/truncated
Echo、invalid checksum、nonzero Echo code、source/L2 admission failureはstable
`DropReason`でbyte不変dropします。このconsumeはpacket ownershipを確実に終端するarchitecture
behaviorであり、RFC準拠のupper-layer deliveryを主張しません。RFC 1122 §3.2.2とRFC 1812
§4.3.3が想定するEcho ReplyおよびICMP error/controlのICMP user interfaceはまだ存在せず、
deliveryはdeferredです。

IPv4 reassemblyはRFC 1122 §3.2.1.4に対する現時点の明示deviationです。local ICMP fragmentは
reassemblyや応答を行わず`Icmpv4FragmentUnsupported`でdropします。RFC 1812 §4.2.2.3に従い、
reserved IPv4 flagがnonzeroであることだけを理由に受信packetをdropしません。valid local Echo
として処理し、originated atomic Replyではreserved bitをclearしてDFだけを設定します。
IPv4 options付きlocal Echoもbyte不変dropします。RFC 1122 §3.2.2.6、RFC 1812
§4.3.3.6および§§5.3.13.4–5.3.13.6がsource-route reversalとSource Route/Record
Route/Timestamp処理を要求しているため、これは明示deviationです。Timestamp等の他ICMP
query、options処理、Destination UnreachableのCode 0以外、Parameter Problem、Redirect、
PMTU処理は
deferredです。

## ICMPv4 generated error scope

RFC 792のType 11/Code 0とType 3/Code 0/Code 1、RFC 1812 §§3.3.2, 4.3.2, 4.3.3,
5.2.7.1, 5.2.7.3, 5.3.1を対象にします。valid IHL=5のnonlocal IPv4はlocal/options判定後にLPMし、
route missならTTL値にかかわらず元RX leaseを一切変更せず`RouteMiss`でrecycleして
eligibleなDestination Unreachable Network actionをqueueします。route hitかつTTL 0/1は
従来どおり`Ipv4TtlExpired`とTime Exceeded TTL actionです。一つのpacketから両方を生成
しません。eligibleなpacketだけARPとは別のcaller-backed `Icmpv4ErrorRuntime`へactionを
queueし、RX batch終了後のgenerated sessionで送信します。kindはFIFO/retry/builder/report/
traceまでtypedに保持し、action FIFOとper-egress rate stateは両kindで共有します。
worker-localであり、共有lock、packet clone、backend buffer pointerを持ちません。

### router-originated ICMPv4 inventoryとoperator switch

routerが自身の名前で生成または応答するICMPv4は次の4 classだけです（NAT44のICMPv4 error変換は
受信errorのtranslationで生成ではなく、`nat44.*.icmpv4-errors`で別途設定します）。owner方針
（2026-11-01）により既定値はすべてRFC動作で、security上offにしたい運用者向けにclassごとの
switchを持ちます。RFC 1812 §1.1.3は、default設定がRFC準拠である限り、SHOULDに反するoption
およびMUSTに反するoption（明示的に禁止された場合を除く）を許します。

| class | 生成条件 | RFC要件 | switch（default） | off時 | 変更の分類 |
|---|---|---|---|---|---|
| Echo Reply（Type 0） | router addressへの有効なEcho Request | RFC 1812 §4.3.3.6 MUST implement、無視optionはSHOULD提供かつMUST default応答。RFC 1122 §3.2.2.6 MUST | `[ipv4-origin] echo-reply`（`true`） | 全validation後に`ICMPV4_ECHO_DISABLED`でbyte不変drop | reloadable（`Ipv4OriginPolicy`、`default-ttl`と同じ） |
| Time Exceeded（Type 11/Code 0） | route hitでTTL 0/1 | RFC 1812 §5.3.1 MUST | `[icmpv4-errors.generate] time-exceeded`（`true`） | `IPV4_TTL_EXPIRED`のまま、`icmpv4_errors.disabled_time_exceeded` | restart-required（`Icmpv4ErrorPolicy`） |
| Destination Unreachable Network（Type 3/Code 0） | LPM miss（firewall有効時はegress-free permitのみ） | RFC 1812 §§4.3.3.1, 5.2.7.1 MUST | `net-unreachable`（`true`） | `ROUTE_MISS`/`FIREWALL_ROUTE_UNAVAILABLE`のまま、`icmpv4_errors.disabled_destination_unreachable` | restart-required |
| Destination Unreachable Host（Type 3/Code 1） | direct targetのfruitless ARP | RFC 1812 §5.2.7.1（MUST be able to generate、最も近いcodeをSHOULD） | `host-unreachable`（`true`） | holdをreverse route/reverse ARP前にretire、`icmpv4_errors.disabled_host_unreachable`と`ResolutionFailureCounters::generation_disabled` | restart-required |

security上の理由は、Echoがhost discovery、Time Exceededがtraceroute topology disclosure、
Network Unreachableがroute table probing、Host UnreachableがLAN host enumerationに使えることです。
rate limit（RFC 1812 §4.3.2.8のSHOULD settable）は既存の`interval-ms`/`state-ttl-ms`で、switchは
limiterを変更しません。disabled kindは`decide_icmpv4_error`先頭（および`schedule`と
failure dispatch）で判定し、clock watermark、per-egress limiter state、reverse LPM、reverse ARPに
触れずcounterだけを加算するため、他kindのrate limitを消費しません。Host Unreachableのfailure holdは
switchに関係なくcaptureし（ARP miss時のfixed slotへのbounded copy）、ARPが実際に失敗した時点で
retireして数えます。captureをskipするとARP成否が未定の時点で数えるか、数えられなくなるためです。switchは公開runtimeの
`Copy` policyに入ったbit/boolの読み出しだけで、allocation、lock、packet cloneを伴いません。
error switchの変更はinterval等と同じ`Icmpv4ErrorPolicy`の変更としてrestart-required
（`RestartRequired::Icmpv4ErrorPolicy`）、Echo switchは`Ipv4OriginPolicy`の変更として通常reload
（全reloadと同じflushを伴う）です。snapshot authorityへはEcho switchがdefaultでない場合だけmixし、
既存publicationのauthority値を変えません。

Code 1はconnected routeのdirect targetだけが対象です。failure holdはresolution state/action
とは別のfixed sliceで、`{egress,target,generation}` token、元source/destination/TOS、
forward authority、最大548-byte quoteだけを持ちます。packet lease、Ethernet header、
padding、buffer pointerは保持しません。各generationの最初のeligible packetが勝ち、後続packet
はquoteを置換しません。最初がRFC error suppression対象なら後続eligible packetで空slotを
埋められますが、すでにFailedのgenerationへretroactive captureはしません。generation wrapは
live forward/reverse tokenをbounded scanでskipします。

terminal候補のdispatchも明示scan budgetとpersistent round-robin cursorを使います。current
snapshotでforward direct authorityと未解決状態を再確認し、元sourceへのreverse LPMを行います。
reverse static/fresh dynamic hitなら共有`Icmpv4ErrorRuntime`へCode 1をqueueします。reverse miss
では通常ARPをholdなしでscheduleし、候補だけを保持します。学習後の後続dispatchでfresh RXなしに
queueでき、reverse generationがFailedならrecursive ICMPを作らずretireします。同じfailed
forward keyをreverse resolutionとして再開しません。ICMP FIFOのPending/rate/state/action
pressureは候補を保持し、forward learning/static、authority変更は未queue候補を
cancelします。`reverse_arp_scheduled`はfailure dispatch自身が`Queued`/`RetryQueued`を作った
場合だけ増やします。同じactive tokenの`InitialQueued`/`Waiting`/`RetryQueued`を反復scanした
場合は`ReverseArpPending`であり、既存actionやtimer-generated retryを新規scheduleとして
二重計上しません。通常処理中にqueue済みICMP actionはhistorical eventとしてcancelしません。
ただしpublication境界ではegress/MAC/IP authorityが旧snapshotへbindされているため、
`Icmpv4ErrorRuntime::preflight_publication`がring/stateの全単射とcapacity/head/windowを
read-onlyで検証し、exclusive permitのtotal commitでqueue、limiter、head/len、watermarkを
全flushします。累積counterは保持し、permit Dropと全preflight errorはruntime不変です。

worker tick順は `publication/reconcile → RX → resolution timer poll → failure dispatch →
generated ARP → generated ICMP` です。exact timeoutでのARP学習は、ICMP actionがqueueされる前
なら `poll → learn → dispatch` と `learn → poll` の両方で勝ちます。

逆経路は元IPv4 sourceへの通常LPMです。gateway routeではnext-hop、connected routeでは
元sourceをneighbor targetにし、reverse egressのInterface MAC/local IPv4 bindingを使います。
static neighborを優先し、次にfresh dynamic ARP entryを使います。未解決時は既存ARP actionを
scheduleしますがICMP actionは保存しません。受信Ethernet sourceはprevious hopにすぎないため
neighborとして信用しません。このため最初のtraceroute probeがARP warm-upだけで終わることが
あり、学習後のfresh probeが必要です。同じbatchでは先行ARP学習だけが後続TTL packetから見え、
後続ARPは先行TTL packetにretroactiveな生成を行いません。

actionは受信時のIPv4 datagram bytesを`min(Total Length, 548)`だけ固定配列へcopyします。
Ethernet headerとTotal Length後のpaddingは引用しません。生成wire profileは次です。

- Ethernet II frame lengthは`max(60, 14 + 28 + quote_len)`、FCSなし。padding/tailをzero-fill。
- outer IPv4はIHL=5、Total Length=`28 + quote_len`、ID=0、DF=1、MF/offset=0、
  protocol=1。TTLはvalidated `Ipv4OriginPolicy`。
- outer TOSはRFC 1812 legacy profileのprecedence 6として
  `(original_tos & 0x1e) | 0xc0`。reserved bit 0をclearし、source/destinationはreverse
  binding/original source。
- ICMPはTime ExceededならType 11/Code 0、Destination Unreachable NetworkならType 3/
  Code 0、fruitless direct ARPならType 3/Code 1で、いずれもunused=0。odd lengthを含む
  header+quote全体をchecksumする。
- outer IPv4 Total Lengthは最大576、Ethernet frameは最大590 bytes。

RFC 1812のerror suppressionとして、router-local source、noninitial fragment、ICMP error
Types 3/4/5/11/12、protocol 1でtype byteが無いpacket、
reverse route/interface/binding/neighbor不在では生成しません。invalid/non-host source、
IP multicast/limited/prefix-network/directed-broadcast destination、Ethernet group destinationは
common ingress admissionがerror runtimeより先にbyte不変dropします。first fragment
offset=0/MF=1とICMP queryは生成可能です。source/destinationのprefix network/broadcast
判定はgateway routeを含むLPM-selected prefixに対して行い、more-specific `/32`を優先し、
`/31`と`/32` endpointをnetwork/broadcast扱いしません。RFC 1812 §4.3.2.6と
§§5.3.13.4–5.3.13.6のsource-route reversalおよびoptions処理を実装していないため、
IPv4 optionsは従来どおりLPM/TTL判定前に`Ipv4OptionsUnsupported`でatomic dropする
deviationです。route missにはselected destination prefixが無いためprefix network/
directed-broadcast判定はできませんが、multicast/limited broadcast/L2 groupは抑止します。
`InterfaceMiss`、`NeighborUnresolved`、options/source route等をType 3/Code 0へ変換せず、
このCodeはLPMが完全にmissした場合だけに限定します。

rate limiterはreverse egress単位のtimer方式でdefault 100msです。intervalはnonzero、
state TTLはinterval以上を要求します。egressごとにqueue中actionは一つ、lease commitから
deadlineを開始しexact boundaryを許可します。allocation/build失敗はactionを保持してdeadlineを
開始せず、backend reject/finish errorもTX requested済みなのでdeadlineを開始します。
state/action fullとclock regressionはphantom state/action/deadlineを作りません。expired idle
stateだけ再利用します。multi-worker共通limit、packet hold/replay、RFC 4884 extension、
MTU別quote縮小/generated fragmentation、interface別disableはdeferredです。

## ARP control scope

Ethernet II / IPv4 profile（HTYPE 1、PTYPE 0x0800、HLEN 6、PLEN 4）のRequest/Replyを
扱います。RFC 826の順序どおり、supported opcodeかつvalid senderの既存dynamic entryは
TPA非依存でmergeし、entryが無い場合はTPAがingress localのときだけinsertします。その後local
Requestは同じRX bufferをReplyへ書き換えてingressへcommitし、Replyとnonlocal Requestは
byte不変でlocal consumeします。`received == tx_requested + dropped + consumed`です。
unknown opcodeはhardening deviationとしてprofile validationでdropし、既存entryの
MAC/refresh時刻やpending resolutionを変更しません。

- RX Ethernet sourceはindividual unicast、destinationはingress interface MACまたはexact
  broadcastを要求し、ARP parser/cache mergeより前にbyte不変dropする。
- Ethernet destinationとTHAはrequest SHA、Ethernet sourceとSHAはlocal interface MAC。
- SPAはrequest TPA、TPAはrequest SPA。ARP ProbeのSPA `0.0.0.0`にもTPA zeroでreplyする。
- Probeは学習しない。GARP/Announcementは既存entryだけ更新し、absent keyをinsertしない。
- request THAは無視し、Ethernet sourceとrequest SHAの一致も要求しない。mapping authorityは
  ARP SHAであり、ARP自体にはspoofingを認証する仕組みがないことが残余riskです。
- 42 byte以後はpadding/tailとして長さと内容を保存する。
- static mappingはdynamicより常に優先し、ARPで上書きもdynamic slot消費もしないlocal policy。
- zero/broadcast/multicast SHAはRFC 1812 group-address prohibitionとlocal zero policyにより
  stable security reasonでdropする。RFC 1122 §3.2.1.3とlocal safety policyにより、SPAの
  `0/8`（exact zeroはProbe）、`127/8`、multicast、`240/4`、limited broadcast、connected
  `/0`から`/30`のnetwork/directed broadcast addressはconsumeするが学習しない。`/31`と
  `/32`にはnetwork/broadcast endpoint除外を適用しない。
- local SPA claimの保護はlink scopedで、`(ingress IfId, SPA)`がlocal bindingと一致する場合
  だけ学習しない。同じIPv4値が別interfaceのlocal bindingでも、ingress上では通常peerとして
  学習できる。
- 学習成功時だけmatching active resolution/actionをcancelし、unrelated FIFOを維持する。
  commit済みRequestのflood cooldown tombstoneは残す。

Reply admissionへsolicited-only制約は追加しません。`ArpReplyUnsupported`と
`ArpTargetNotLocal`のstable reason番号は互換性のためretired/reservedとして維持します。

RFC 5227 §2.4のaddress conflict detection/defenseは未実装です。foreign SHAが同じingressの
local SPAを名乗り、そのlocal addressをTPAにしたrequestも通常requestとしてdirected reply
するだけで、conflict状態やdefensive announcementを生成しません。正常なlocal target requestを
追加policyでdropしないことを優先した明示deviationです。

## UDP NAT44/NAPT vertical slice

NATは既存wrapperへ暗黙に入れず、`forward_batch_with_nat44_udp`、またはgenerated ICMP
errorも含む`forward_batch_with_nat44_udp_and_icmpv4_errors`という合成service APIで
ARP resolutionと同じworker tickへ明示的にbindします。config公開済みでruntime storageが
無い場合、またはruntime/config/snapshot authority fingerprintが不一致ならdomain crossingを
fail closedにします。新snapshot公開時はそのsnapshotでconfigをvalidateし、
freshなUDP専用hash keyを伴う`preflight_reconcile`でexact runtimeを排他的に借用する
one-shot permitを作り、publication owner交換後はinfallibleな`permit.commit()`で
mapping/peer/indexを全flushします。permitは別runtimeへ移せず、drop時は何も変更しません。
互換`reconcile`はこの二段階処理のwrapperです。dimension/key/config validationはclearより先に
完了し、失敗時は旧publicationを保持します。commit経路に再validation、`Result`、panicは
ありません。`storage_shape`はmapping/peer slot、両directory
のbucket/node、port-owner slotの全capacityをopaque valueで比較可能にします。旧generation
または旧runtime lifecycle epochのpeer/port ownerが新mappingを許可することはありません。

mapping keyは`(inside IfId, internal IPv4, internal UDP port)`でremote endpointを含めない
Endpoint-Independent Mappingです。別のremoteへ送っても同じpublic tupleを使います。
filter peerのcanonical index wordsは
`(mapping slot, mapping generation, lifecycle epoch high, lifecycle epoch low, remote IPv4 | key port << 32)`
で、mappingは`(inside IfId, internal IPv4, internal UDP port)`です。key portは
`address-and-port-dependent`のときだけremote UDP port、それ以外はzeroなので、defaultの
address-granular peerのhashは従来と同一です。inbound filterは後述の
「NAT44 inbound filtering modes」に従い、default（`address-dependent`）は既知IPの任意remote
UDP portを許し、未接触IPをbyte不変dropします。outboundでpeer slotを確保できなければ
mappingをrefreshせずdropし、filterを緩めません。live mappingをevictせず、port overloadも
しません。
内部portがpool内かつfreeなら保存し、それ以外はcaller seedを混ぜたstartからinclusive poolを
一周だけscanします。各candidateはdirect owner tableを一回参照し、mapping tableを再scan
しません。randomness、parity、low-class preservationは保証しません。

対象packetの順序は次です。

1. common Ethernet/IPv4 validationとoptions rejection。
2. outboundはoriginal destinationのLPM、TTL、selected outside egress、static/fresh dynamic
   neighborを先に確定。source reverse-LPMがinsideであることを確認。
3. inbound public UDPはlocal deliveryより先にinterceptし、mapping/ADF lookup後、
   translated internal destinationを通常LPMしinside neighborを確定。
4. reserved flagをfragment判定からmaskした上でDF=1/MF=0/offset=0、UDP header/length、
   全offset、mapping/peer/port transactionをmutationなしでplan。
5. L2、TTL、IPv4 address、UDP port、IPv4/UDP checksumの完全なrewrite planを適用。
6. mapping/peer/refreshをinfallible commitし、最後にRX leaseをTX requestへcommit。

core dropはpacket bytesとmapping/peer stateを変更しません。outbound TX requestでmapping
idle timeとADF peerをcommitするため、backend aggregate rejectでもrollbackしません。
same batchの後続inboundは直前outboundのstateを見ます。inboundはmapping idle timeをrefresh
しません。NAT runtimeへ到達した非退行operationは、mapping/filter miss、capacity/port
exhaustion、後続route/neighbor failure、structural/policy dropでもoperation開始時にwatermarkを
進めます。これによりexact expiryを観測した後の古い時刻でmapping/ADFが復活しません。
clock regressionはcounter/trace以外を変更せずfail closedにし、直前watermarkと等しい時刻で
回復します。default idle TTLは300秒、minimum 120秒、exact boundaryでexpiredです。

outside ingressから通常LPMがinside egressを選んだpacketは、宛先public UDPのauthorized
DNAT pathを先に完了した場合を除き、protocol/runtime/mappingの有無にかかわらず
`Nat44ExternalToInternalBypass`でdropします。この境界はneighbor lookup/ARP scheduleより前で、
single-domain traditional NATを迂回する外部から内部への直接転送を許可しません。

RFC 768のUDP lengthは8以上かつIPv4 payload以下を要求し、短いUDP lengthの後ろにあるIP
paddingは保存します。checksum zeroはzeroのままです。nonzero checksumはRFC 1624で
translated IPv4 address wordsとportを更新し、算術結果zeroをUDP wireの`0xffff`へencode
します。入力nonzero checksumを新規にfull validationしないrouter profileです。IPv4 IDは
RFC 6864 atomic datagramとして保存します。RFC 1812 §4.2.2.3に従いreserved flagだけでは
dropせず、IPv4 flags/fragment wordをNAT rewrite後のwireへそのまま保存します。

fragment handling/reassembly、ICMP query
NAT、static port forward、複数public address、port randomization/parity、minimal
stateful sliceを越えるfull packet filterはdeferredです。RFC 3022/4787/7857の全機能準拠は
主張しません。

## Outbound-initiated TCP NAT44/NAPT vertical slice

TCP serviceはRFC 3022のtraditional NAPT tuple rewrite、RFC 5382/7857のtimerとmapping/filter
用語、RFC 9293のTCP header、RFC 1624のincremental checksum、RFC 6864のatomic datagram
profileを参照する限定実装です。RFC 5382全体への準拠は主張しません。

`Nat44TcpRuntime`はUDP runtimeとstorage、key、generation、watermark、allocatorを共有しない
`!Send + !Sync` worker-local ownerです。caller-backed mapping/session directoryと
protocol-local direct public-port ownerを専有し、outbound worst-caseはadditive
`O(M+S+P)`、inbound/quoted ICMPはownerからexact sessionへ直接到達します。mapping keyは
`(inside IfId, internal IPv4, internal TCP port)`、session keyは
`(mapping slot, mapping generation, lifecycle epoch, remote IPv4, remote TCP port)`です。
mapping再生成は旧sessionを全走査せずgeneration+epochでlazyに無効化します。複数remote sessionは
同じpublic tupleを再利用します。同じsession slotをkey
`(mapping slot, mapping generation, lifecycle epoch, remote IPv4)`で引く二つ目のcaller-backed
remote-address directory（session directoryと同じbucket/node数）を持ち、address-dependent
filteringの判定に使います。exact sessionが無いinboundの扱いは後述の
「NAT44 inbound filtering modes」に従います。protocol-dependent tableなのでUDPとTCPは同じ
数値public portを同時に所有できます。

新mappingを作れるpacketはinsideからoutsideへ向かうSYN=1、ACK=0、RST=0、FIN=0だけです。
新sessionはこのoutbound initial SYNに加え、filterが許可した同じflagのinbound initial SYNが
既存live mapping上にだけ作れます。ECE/CWR、TCP options、SYN dataは許可します。既存exact sessionではflagによる
phase遷移を行わず、SYN retransmit、inbound exact SYN（basic simultaneous open）、
SYN-ACK、ACK/data、FIN、RSTを同じ規則で変換します。sequence number、receive window、
ACK妥当性を追跡しないため、flagだけを信頼したFIN/RST cleanupは安全ではありません。
このため全sessionはdefault/minimum 7,440,000ms（2時間4分）、設定上限7日間の単一idle
timerを使い、FIN/RSTも削除・短縮せずsuccessful TX request時にexact sessionをrefresh
するだけです。unmatched inboundはrefreshしません。exact boundaryでsessionがexpireし、
最後のlive linked sessionが無くなったmapping/public portだけが再利用可能です。
各mappingは同generationで最後にcommitされたsession activityを要約として保持します。
non-regressing clockの下ではこの値がlinked sessionの最大activityと一致するため、
mappingのlive判定はsession storageを走査せずO(1)です。refresh planはmapping/sessionの
両方のcopyを更新し、後続処理が成功したcommitでだけ同時に公開するため、破棄されたplanは
mapping lifetimeを延長しません。要約はcaller-backed mapping slotごとに`u64` 1個
（logical 8 bytes、Rust layoutのpaddingを除く）を追加し、session capacityには比例しません。
planはruntime epoch、nonwrapping state revision、計画時watermark、prepared directory/owner
topologyへbindします。packet rewrite前に全topologyを検証し、rewrite後commitはinfallibleです。
release buildのcommitも全authorityが一致しないstale planをtyped errorとして拒否するため、
reconcileがgenerationをresetしたABAやslot再利用後に旧tupleを復活させません。

admissionとtransaction順はUDP profileに合わせ、次を追加します。

1. IHL=5、reserved flagを除いてDF=1/MF=0/offset=0、protocol=6、IPv4 payload 20 bytes以上を
   要求する。reserved flagは受理してNAT rewrite後も保存する。
2. TCP Data Offsetは5以上かつheader endがIPv4 Total Length内であることを要求する。
3. pseudo-headerとIPv4 TCP payload全体（odd final byteはlogical zero pad）を含むincoming
   TCP checksumをfull validationする。TCP checksum field zeroも無効化表現ではなく、
   full checksumがvalidな場合だけ受理する。
4. outboundはoriginal LPM/TTL/outside neighborとsource reverse authority、inboundは
   public mapping/exact session後のinside route/neighborをstate commit前に確定する。
5. L2、TTL、IPv4 address、TCP port、IPv4/TCP checksumをplanしてin-place applyし、
   mapping/sessionをinfallible commitしてからTX requestする。backend rejectでも
   TX-request済みstateは残す。

TCP checksumはRFC 1624でpseudo-header address wordsとportを更新します。UDPと異なり
checksum zero保存や算術zeroの`0xffff` normalizationは行わず、数学的結果zeroはwire zeroの
ままです。options/data、IPv4 Total Length内のTCP payload、Total Length後のlink paddingを
保存します。capacity/port exhaustion、malformed/checksum/source/authority/route/TTL/neighbor
failureはpacket bytesとmapping/sessionを変更せず、非退行clock watermarkだけを観測します。
generationは再利用mappingからstale sessionを切り離します。live state evictionとport
overloadは行いません。

UDP-only serviceはTCP domain crossingを、TCP-only serviceはUDP domain crossingをfail
closedにします。combined serviceはinside/outside/public IPv4 realmが完全一致しなければ
TCP/UDPのpublic宛てまたはdomain crossingをfail closedにし、各runtime stateは独立して
dispatchします。opt-in ICMP error candidate以外のICMPとその他のprotocolはrealm mismatch判定
の対象外で、どちらのruntime、watermark、counter、NAT traceも変更しません。ただし
traditional NAT domain境界はprotocol非依存です。設定済みoutside→inside direct LPMと、
変換不能なinside→outside protocolはneighbor lookup/ARP scheduleより前にgeneric fail-closeし、
private sourceや外部から内部へのbypassを許可しません。runtime/config/snapshot mismatchはneighbor処理やstate変更より前にtyped dropします。
inside発のpublic address宛てUDP/TCPは後述の「NAT44 hairpinning」で扱います。

TCP fragment association/reassembly、ICMP query
translation、static forwards、sequence/window validation、full RFC 5382 lifecycle、
safe FIN/RST cleanupはdeferredです。

## NAT44 inbound filtering modes

UDPとTCPのinbound filtering behaviorはprotocolごとに`Nat44Filtering`で選び、RFC 4787 §5の
三分類を使います。RFC 4787 REQ-8（UDP）とRFC 5382 REQ-3（TCP）は、application
transparencyを最重視するならEndpoint-Independent Filtering、より厳しいfilteringを重視する
ならAddress-Dependent FilteringをRECOMMENDEDとし、administrator optionにしてよい
（REQ-8 a、REQ-3 a）、TCPとUDPで独立でよい（RFC 5382 REQ-3 b）としています。

| config `filtering` | `Nat44Filtering` | UDP inbound（live mapping必須） | TCP inbound（exact live sessionなし） |
|---|---|---|---|
| `endpoint-independent` | `EndpointIndependent` | 任意remote endpoint | initial SYNならどのremoteからも新session |
| `address-dependent`（default） | `AddressDependent` | 送信済みremote IPv4、任意port | 同mappingにそのremote IPv4のlive sessionがあるinitial SYNだけ新session |
| `address-and-port-dependent` | `AddressAndPortDependent` | 送信済みremote IPv4+port | 新sessionを作らない |

defaultはUDP/TCPとも`address-dependent`です。両RFCがRECOMMENDEDとする二つのうち、
security上より厳しい側をRFC準拠のbaselineとし（owner policy 2026-11-01）、transparencyを
選ぶoperatorは`endpoint-independent`へ緩め、さらに厳しくしたいoperatorは
`address-and-port-dependent`をopt-inします。UDPのdefaultは従来の挙動と同一です。TCPの従来の
exact remote address/port filterは`address-and-port-dependent`として残り、defaultだけを
RECOMMENDEDの`address-dependent`へ移しました。FIN/RSTでsessionを削除しないため、従来の挙動は
RFC 5382 §4.3のConnection-Dependent Filteringではなく、exact sessionのidle timer中は同じ
remote endpointからのSYNを通すAddress and Port-Dependent Filteringに当たります。

UDPでは全modeでlive mappingを要求し、`endpoint-independent`はpeer lookupを行いません。
inboundはpeerを作らずrefreshもしません。TCPではexact live sessionのpacketを全modeで変換し、
exact sessionが無ければSYN=1、ACK=0、RST=0、FIN=0のinitial SYNだけがfilter判定に進みます。
admitされたSYNは既存live mappingの上にsessionを一つ作ります（RFC 5382 §4.3、REQ-2の外部
開始connection）。mappingは作らず、mapping idle summaryとsessionを同じcommitで更新します。
`address-dependent`の判定はremote-address directoryの一回のkeyed lookupで、live
sessionだけを数えます。expired sessionや旧generationのsessionは許可根拠になりません。
outbound開始だけでなくinbound開始のsessionも許可根拠になり、inbound packetのTX requestは
sessionとmappingのidle timeをrefreshします。したがって同じremote addressからSYNやACKを送り
続ける限り、そのaddressのadmissionとmappingは生き続けます。
`endpoint-independent`と`address-and-port-dependent`はlookupを行いません。

filterを通ったinbound initial SYNは認証されておらず、firewallの判定（後段のpost-DNAT plan）より
前にNAT planが走るため、そのper-packet workはsession capacityではなく
`NAT44_TCP_INBOUND_SLOT_PROBES`（16）で上限します。remote-address chainは最大16 nodeだけ辿り、
それを越えるchainは拒否（fail closed）とします。同じ`(mapping, remote IPv4)`のsessionは全て
同じbucketに入るためchainはsession capacity近くまで伸び得ますが、lookupはどの場合も16 node
までです。新sessionのslotは、exact tupleのexpired slotがあればそれを再利用し、無ければ
16 slot以下のtableは全体を、それより大きいtableはruntimeのsecret hash key、tuple、時刻、
probe番号から独立に決めた16個のslot位置だけを調べます。引いた位置が既に調べた位置と重なれば、まだ調べていない次の位置へ進める（最大15 step）ため、16 probeは常に互いに異なるslotを調べ、16 slotを少し超える小さくほぼ満杯のtableでも重複で空きを取り逃しません。outboundのindex 0からの全scan
（NAT44-035）はinbound開始では使いません。外部senderは位置を選べず、再送SYNは別の位置を
調べます。outbound作成がlive slotを低indexへ集めても各probeは独立なので、live率ρのとき
missの確率は約ρ^16です（ρ = 1/2で約1.5×10^-5。連続16 slotの窓では窓がlive領域から始まると
ほぼ必ず満杯で、missが約ρになっていました）。probe位置に空きが無ければ他所に空きがあっても
`NAT44_TCP_SESSION_TABLE_FULL`でdropし、live sessionをevictしません（inbound開始はbest-effort）。
session作成は
exact session directoryとremote-address directoryの両方へprepared link/relinkを
rewrite前に検証し、commitはinfallibleです。そのためTCP outbound planは二つの
prepared session linkを持ち、x86_64で288 bytes（上限320 bytesをtestで固定）になります。
新しいcounter `nat44_tcp.inbound_sessions_created`は`sessions_created`にも含めて数えます。

filterが拒否したpacketはbyte不変のsilent dropで、UDPは`NAT44_UDP_FILTER_DENIED`、TCPは
`NAT44_TCP_SESSION_MISS`です。RFC 5382 REQ-4はunsolicited inbound SYNへ受信後少なくとも
6秒は応答しないこと（MUST）と、その間にoutbound SYNを変換したら元のSYNをsilent dropすること
（MUST）を求め、それ以外はICMP Port Unreachable（Type 3/Code 3）をSHOULDとし、応答がNATの
security policyに反するならREQ-4 aでsilent dropをMUSTとします。このsliceはunsolicited SYNに
TCP RSTもICMPも返さないため二つのMUSTを満たし、SHOULDのdelayed Port Unreachableは送りません。
packet hold/replayをしない設計なので、REQ-4 aのsilent dropを現在の唯一のlocal policyとし、
6秒以上のbounded quote hold、outbound SYNによるcancel、rate limit、operator switchを持つ
delayed ICMPはdeferredです（requirements NAT44-038）。

REQ-5のtimerはmodeに依存しません。inbound開始のsessionもoutbound開始と同じ単一idle timer
（default/minimum 2時間4分）を使うため、partially open phaseのtransitory idle-timeout下限
4分も満たしますが、外部から開いたまま応答の無いSYNもsession slotを2時間4分占有します。
`endpoint-independent`と、inbound新規flowを許可するfirewall ruleを組み合わせると、外部hostが
mapping済みpublic portへのSYNでsession tableを埋め、内部からの新規sessionが
`NAT44_TCP_SESSION_TABLE_FULL`になり得ます。defaultの`address-dependent`でも、admissionは
packetのsource addressだけで判定するため、off-pathの攻撃者がmappingが既にsessionを持つ
remote address（広く使われるCDNやDNS serverのaddressなど）を詐称し、source portを変えたSYNを
送れば同じことができます（requirements NAT44-041）。必要なのはmapping済みpublic portと、その
mappingが話しているremote addressの推測です。この詐称で作られたsessionは2時間4分残り、同じ
`(mapping, remote IPv4)`のchainを伸ばしますが、上の16 node上限によりlookup costは増えず、16 node以内に
live sessionが見つからないADF判定（同じkeyでも、bucketが衝突する別keyでも）が拒否側に倒れるだけです。M1のようにfirewallがoutside→insideの新規flowを
許可しない構成では、NAT planはcommitされないためsessionは作られません。これに対する
remoteごとのinbound開始session数の上限は下の「TCP per-remote inbound session limit」です。
RFC 5382 REQ-6が扱うTCP ALGはこのsliceに無く、defaultでdisabledという要求を自明に満たします。

filteringはNAT domainの境界を緩めません。firewallを同じworkerへbindする場合、firewallは
従来どおりpost-DNATのremote→internal tupleでinbound packetを評価し、NAT filterが許可した
packetもexact reverse stateか、outside→insideの新規flowを許可するruleが無ければ
`FIREWALL_DEFAULT_DENIED`等でdropします。NAT planはfirewall planが成功するまでread-onlyなので、
firewallが拒否したinbound SYNはNAT sessionも作りません。逆にfirewall ruleがflowを許可しても
NAT filterが拒否すればdropします（実効admissionは両者の積）。NAT44-021の外部→内部direct LPM
bypass拒否、route-miss時のNAT gate（#284）、realm mismatch、runtime/config authority検査は
public宛てNAT interceptより前またはそれとは別の経路で、filtering modeを参照しません。

filteringはpolicyの一部で、変更はreloadableです。storage shapeはmodeに依存しない
（remote-address directoryは常に確保する）ため`STORAGE_SHAPE`にはならず、applyは他のNAT policy
変更と同じく全mapping/peer/session/indexをflushします。そのため異なるkey粒度のpeerが混在する
ことはありません。`ApplyPlan`は`NatChange::filtering`をtyped deltaとして出し、seedを含む
残りのpolicyの変更だけを`policy_changed`にします。

### TCP per-remote inbound session limit

`[nat44.tcp] inbound-sessions-per-remote`（core `Nat44TcpPolicy::with_inbound_sessions_per_remote`）は、
外部からのinitial SYN（hairpinでないもの）が一つのmappingに一つのremote IPv4（portは問わない）から
作ったlive sessionの数を制限するopt-inのlocal security policyです（requirements NAT44-041）。
default `0`（無制限）、有効範囲0〜16（`NAT44_TCP_MAX_INBOUND_SESSIONS_PER_REMOTE`）で、外部からの
新規inbound flowをfirewallで許可するoperatorには8を推奨します。filterが許可した外部SYNは、
そのmappingとremote addressのlive外部開始sessionが既に上限数あれば、byte不変の
`NAT44_TCP_INBOUND_REMOTE_QUOTA_EXCEEDED`（drop code 150、counter
`nat44_tcp.inbound_remote_quota_exceeded`）でdropされます。sessionもmappingも作らず、refreshも
evictもせず、live sessionは不変です。RFC 5382 §9はREQ-3の議論で、Address-Dependent Filteringが
remote NAT配下で同じIP addressを共有する攻撃者からは完全には守らないことを、REQ-5の議論で、
NATがliveを能動的に確認したりより保守的なtimeoutを選んだりしてよいことを述べます。詐称そのものは
扱っていませんが、RFC 5382/4787のどのREQも「filterを通ったSYNを全て受け入れる」ことを要求しない
ため、上限はMUSTに反しないlocal policyです。limitはconfigで固定し負荷に応じて変えないため、
RFC 4787 §13が警告する条件依存の非決定的挙動にもなりません。

defaultを`0`にする理由: TCP NATはFIN/RSTを追跡しないため、正常にcloseしたconnectionのsessionも
idle TTL（default/minimum 2時間4分）が切れるまでliveのまま数えられます。上限をdefaultにすると、
inside P2P listenerが一つのremote IPv4（BitTorrent peerの再接続、CGNAT配下の複数client）から短い
connectionを上限数受けただけで、以後約2時間そのremoteからのSYNを拒否します。owner policy
（2026-11-01: RFC baselineをdefault、security強化はopt-in）に従い、transitoryまたはFIN/RST-awareな
timer（NAT44-058）ができるまではdefaultを無制限とし、新規inbound flowを許可する構成のoperatorが
明示的に有効にします。

dataは新たに増やしません。session slotに「外部SYNが作った」flag（`is_external_inbound`）を一つ
持ち、数はSYNごとに既存のremote-address directory（key = mapping index/generation/epoch +
remote IPv4）のchainを一回、最大`NAT44_TCP_INBOUND_SLOT_PROBES`（16）node辿ってlive slotから
数えます。stored counterを持たないので、lazyなidle expiry、slotの再利用（outboundが再利用すれば
flagはfalseになる）、mapping再生成（generationが変わりkeyが変わる）、reconcileの全flushで、
何もしなくても数は正しく減ります。walkはlimitに達した時点で止まり拒否、chainの末尾に達すれば
countはlimit未満と証明されて許可、16 nodeで末尾に届かなければcountを証明できないためfail closed
で同じreasonで拒否します。limitの上限16はこのwalk予算に一致させています。chainには同じ
mapping/remoteのoutbound開始sessionやbucketが衝突する別keyのnodeも入るため、最初の16 nodeに
あるそれらの数だけ実効上限は下がり、上限16は名目値です。また上限が1以上なら、同じ
`(mapping, remote)`のchainが16 nodeを超えると、#288の`address-dependent`判定だけなら許可した
SYN（最初のlive sessionが16 node以内にある）も拒否します。`address-dependent`では
同じwalkがADF判定（live sessionの有無）も兼ね、limit `0`の`address-dependent`は従来と同じく最初の
live sessionで止まり、limit `0`の`endpoint-independent`はwalkしません。outbound開始sessionは
許可根拠にはなりますが数えません。

walk中に同じmappingとremote addressのexpired slotを見つけたら、新sessionはそのslotを（exact
tupleのexpired slotの次、keyed random probeより先に）再利用します。これにより期限切れnodeが
そのremoteのchainに溜まらず、攻撃が止んだ後の正当なSYNが16 node予算を食い潰されて拒否される
ことを防ぎます。workはSYNごとにchain 16 node + slot 16 probe、caller-backedでallocationは
ありません。planはread-onlyで、拒否はplan errorなのでcommitは何も行わず（transactional
plan/commitのまま）、firewall bind時もfirewall判定より前のNAT planで拒否します。

hairpinのinbound half（remoteはrouter自身の`P`）は数えも制限もしません。`P`はinside全hostに共通の
remoteなので、数えると一つのinside serverへ`P`経由で入るinside client全体が上限数のsessionに制限され、
正当なhairpin利用（同じNAT配下のclientからのpublic address経由接続）を壊します。一方`P`をsourceと
するoutside packetはcommon admissionで落ちる（NAT44-047）ため、off-pathの詐称者は`P`を使えず、
inside hostはもともとoutboundでsession tableを使えるので、hairpinを数えても防げる脅威はありません。

`endpoint-independent`では攻撃者がremote addressを自由に選べるため、per-remote limitだけでは
`limit × 詐称address数`まで埋められます。mappingごとの外部開始session上限はdeferredです
（数えるにはmapping単位のchainか別directoryが要り、P2P listenerなど正当な多数inboundとの
trade-offも大きい）。`address-dependent`（filteringのdefault）では詐称できるaddressがmappingの話している
remoteに限られるため、攻撃者が占有できるのは高々`limit × そのremote数`です。

limitはpolicyの一部で、変更はreloadable（storage shapeに依存しないため`STORAGE_SHAPE`にならず、
applyは全NAT stateをflush）です。`NatChange::inbound_sessions_per_remote`（TCPのみ）はtyped
deltaで`policy_changed`に含めず、plan textは`nat44-tcp inbound-sessions-per-remote ~ unlimited -> 8`
と値を出します。範囲外（17〜255）はvalidateが`NAT44_TCP_POLICY`
（path `nat44.tcp.inbound-sessions-per-remote`）、u8外や型違いはparserが`INVALID_TYPE`で拒否します。

## NAT44 hairpinning

RFC 4787 §6 REQ-9（UDP）とRFC 5382 §7.2 REQ-8（TCP）はhairpinningをMUSTとし、REQ-9 a /
REQ-8 aはhairpinしたpacketのsourceを「External source IP address and port」にすることを
MUSTとします。inside host `X1:x1`がpublic address `P`のlive mapping `P:x2'`（inside host
`X2:x2`のmapping。`X2 = X1`でもよい）へ送ったUDP/TCPを、`P:x1' -> X2:x2`としてinsideへ戻します。
`P:x1'`はX1自身のexternal mappingで、無ければ通常のoutbound規則（EIM、port allocation）で
作ります。対象はinside ingressでdestinationが`P`、protocolがそのruntimeのもの（UDPまたは
TCP）であるpacketで、ordinary route lookupより前にinterceptします。UDP-only serviceへの
TCP、TCP-only serviceへのUDPは従来どおり`*_UNSUPPORTED_TRANSPORT`です。

### 二つのtraversal

RFC 4787 §6はfilteringに触れませんが、hairpinしたpacketはNATを一度出て`P:x1'`から戻ってくる
外部packetと同じ扱いにします。したがって一つのpacketを二つのNAT traversalとして扱い、
それぞれをatomicにcommitします。

1. **outbound half**: `X1:x1 -> P:x2'`を通常のoutbound packetとしてplanします。NAT planは
   通常outboundと同じ関数（UDPはmapping + peer、TCPはmapping + session。新規作成は
   TCP initial SYNだけ）で、firewallをbindしていれば通常outboundと同じcanonical tupleで
   planします。source admission（host unicast、router/public addressでない、source
   reverse-LPMがinside）、atomic IPv4/transport validation、TTL>1、destination portが
   live mappingであることをread-onlyで確認してから、NATとfirewallのplanが両方成功した
   場合だけ二つを続けてcommitします（TCPはprevalidate後）。packetはoutsideへ出ないため
   outside route/neighborは要求しません。commitするstateは同じhostが通常のoutbound
   packetで作るものと同一で、hairpinは新しいstate作成能力ではありません。remoteがrouter
   自身の`P`なので、外部からこのstateを使うことはできません。`P`をsourceとするoutside
   packetはcommon admissionの`IPV4_SOURCE_LOCAL_ADDRESS`でdropし、outsideからのICMPv4 error
   変換は引用remoteがrouterのlocal address（`P`を含む）なら全lookup前に
   `NAT44_ICMPV4_QUOTED_REMOTE_LOCAL`でdropします（outside由来の入力がremoteでNAT stateを
   引くのはこの二経路だけで、firewallのRELATED lookupはNAT変換が復元したtupleに限られます）。
   ただしslotの形が同じでも許可の意味は外部remote一つ分より広くなります。全inside hostの
   external sourceは`P`なので（REQ-9 aから不可避）、`address-dependent`ではX1のpeer/session
   `P`はどのinside hostからのhairpinも許すinside全体のwildcardです（`address-and-port-dependent`
   は`P:x2'`一つ）。firewallは引き続き`P:x2' -> X1:x1`のexact reverseだけをestablishedと
   します。
2. **inbound half**: outbound half commit後のstateに対し、`P:x1' -> P:x2'`を通常の
   inbound packetとしてplanします。destination mappingのfiltering（mode別、TCPはexact
   sessionかfilterを通ったinitial SYN）、translated destinationのinside route、firewall、
   inside neighborの順で、成功すればbytesをrewriteし、inbound NAT planとfirewall planを
   TX request時にcommitします（通常inboundと同じ）。唯一の違いとして、TCP inbound halfが作る
   sessionはper-remote inbound session limitに数えず制限もしません（remote `P`はinside全host
   共通で外部から使えないため。上の「TCP per-remote inbound session limit」）。

inbound halfが拒否された場合（NAT filter、firewall、session capacity、route/neighbor）、
packetはbyte不変でdropしますが、outbound halfは残ります。remote NATにdropされたoutbound
packetと同じで、同じNATの背後の二hostのhole punchingはこれに依存します（RFC 5128 §3.3.2の
UDP、§3.4のTCP simultaneous open）。defaultの`address-dependent`では、最初のX1→`P:x2'`は
X2のmappingが`P`へ送っていないため`NAT44_UDP_HAIRPIN_FILTERED`（TCPは
`NAT44_TCP_HAIRPIN_FILTERED`）になりますが、X1のmappingに`P`のpeer/sessionを残します。
続くX2→`P:x1'`はそのpeer/sessionで通り、以後X1→`P:x2'`も通ります。`endpoint-independent`
では最初から通ります。inbound halfを評価する前にoutbound halfをcommitするため、self-hairpin
（X1→`P:x1'`）は全modeで最初のpacketから届き、TCPでは同じsessionが両halfのexact sessionに
なります。

hairpinning off、malformed、unknown destination mapping、送信元authority違反、TTL≤1、
outbound halfのNAT capacity不足やfirewall denyは何もcommitしません。translated destinationの
route miss/`WrongEgress`はdefensive checkで、mappingをinside-routed sourceにしか作らず
reconcileでflushする固定publicationでは到達しません。TTL≤1はICMP Time
Exceededを生成しないsilent dropです（NAT inboundと同じ。deferred）。

### firewall

firewallは各halfを、それが表す通常traversalと同じ方向・tupleで評価します。

| half | ingress | egress | source | destination | 通常traversalとの対応 |
|---|---|---|---|---|---|
| outbound | inside | outside | `X1:x1`（pre-SNAT） | `P:x2'`（pre-DNAT） | 通常outboundのpre-SNAT internal→remote |
| inbound | outside | inside | `P:x1'`（post-SNAT） | `X2:x2`（post-DNAT） | 通常inboundのpost-DNAT remote→internal |

auditはpacketごとにこの順で二recordを残します。inside→insideのrule（ingress = egress =
inside）はhairpinに使いません。そのためoutbound-onlyのpolicy（M1）では、最初のpacketの
inbound halfはunsolicited inboundとして`FIREWALL_DEFAULT_DENIED`になり、X2の返信のinbound
halfはX1のoutbound half stateのexact reverseとして`ESTABLISHED`になります。実効admissionは
NAT filteringとfirewallの積で、「X2が`P:x1'`という外部hostから受け取るもの」と一致します。
inside hostはhairpinでfirewallが拒否するものに到達できず、通常outboundで拒否される宛先
（たとえば`P:x2'`を拒否するrule）はoutbound halfで拒否されてstateを残しません。NAT44-021の
outside→inside direct bypass拒否、route-miss時のNAT gate（#284）、realm mismatch、
runtime/config authority検査はhairpin interceptと別経路で変わりません。

### 変換とcounter

source address/port（`X1:x1 -> P:x1'`）とdestination address/port（`P:x2' -> X2:x2`）、TTL、
Ethernetを一つのplanでin-place rewriteし、IPv4 header checksumとUDP/TCP checksumはRFC
1624で両address、両port、TTL/protocol wordをincremental更新します。UDP checksum zeroは保存、
算術zeroは`0xffff`、TCPの算術zeroはwire zeroのままです。IPv4 ID/flagsとpayloadは保存します。
per-packet allocation、shared lock、packet cloneはありません。workは通常のoutbound
plan（NAT44-035のreusable-slot scanを含むcapacity有界のwork）、destination mappingの
direct port-owner lookup一回、通常のinbound plan（TCP inbound session slotは16 probe上限）、
firewall plan二回の和で有界です。

counterはprotocolごとに`hairpin_translated`（両half commit）、`hairpin_inbound_refused`
（outbound half commit後にinbound halfが拒否された数。通常の`filter_denied`/`session_misses`には
数えない。`decide`後のTCP commit prevalidationとrewrite適用の失敗は逐次packet pathでは起きない
前提なので数えない）、`hairpin_disabled`です。outbound halfは`mappings_*`/`peers_created`/`sessions_*`に
数えますが、`outbound_translated`と`inbound_translated`にはどちらのhalfも数えません。

### switch

`Nat44UdpPolicy`/`Nat44TcpPolicy`の`hairpinning`はdefault true（RFC準拠）です。security上の
理由でoperatorは`[nat44.udp]`/`[nat44.tcp]`の`hairpinning = false`でprotocolごとに切れます
（RFC 1812 §1.1.3はdefaultが準拠するoptionを許す）。offではhairpin packetをNAT validation、
NAT/firewall/resolution stateの変更、neighbor workより前に`NAT44_UDP_HAIRPIN_DISABLED` /
`NAT44_TCP_HAIRPIN_DISABLED`でdropし`hairpin_disabled`に数えます。drop前にNAT runtimeの
`observe_now`が通常のNAT packetと同じくclock watermarkとstate revisionを進め、firewallを
bindしたworkerでは他のinside発packetと同じくfirewallのtransport preflightとclock watermarkも
進みます。stable code 37/57は旧`*_HAIRPIN_UNSUPPORTED`の改名で、意味も狭まりました。旧codeは
inside発のpublic address宛てのそのprotocol全部（UDP-only serviceへのTCPなどを含む）でしたが、
新codeはそのprotocolのruntimeがhairpinning offの場合だけで、他protocolは
`*_UNSUPPORTED_TRANSPORT`です。変更はfilteringと同じ
reloadableで、storage shapeは変わらず、applyは全NAT stateをflushします。`ApplyPlan`は
`NatChange::hairpinning`を`Delta<bool>`として出し、`policy_changed`には含めません。

### RFC 5508 REQ-7

RFC 5508 §5 REQ-7はhairpinしたICMP Error messageのtraversal（outer destinationをtranslation後の
embedded sourceに合わせる等、outerとembeddedの二重変換）をMUSTとします。default policy
`bidirectional`とhairpinning有効の組合せで実装済みです（後述の「NAT44 ICMPv4 inside-realm
error translation」、requirements NAT44-019I）。policy `disabled`/`external-only`では従来どおり
他のnon-UDP/TCP inside→outside crossingと同じくfail closed（`NAT44_UDP_UNSUPPORTED_TRANSPORT`、
firewall bind時は`FIREWALL_UNSUPPORTED_PROTOCOL`。`external-only`で`P`宛てなら
`NAT44_ICMPV4_WRONG_INGRESS`）です。

## NAT44 ICMPv4 Fragmentation Needed translation

この節はoutside realmからのerror（RFC 5508 REQ-4）を扱います。題名のType 3/Code 4が最初の
対象でしたが、現在は全方向で同じtype/code集合を変換します（NAT44-019J）: Destination
Unreachable code 0–4, 6, 7, 9–15、Time Exceeded code 0、Parameter Problem code 0–2。
除外はType 3 code 5（NAT44はoptionsなしpacketだけを変換するのでsource routeを持つ変換済み
packetは無い）、code 8（obsolete。RFC 1812 §5.2.7.1はSHOULD NOT generateで禁止ではなく、古い
routerが送り得るがdeviation NAT44-067として除外）、未割当code、Time Exceeded code 1
（変換はatomic datagramだけでreassemblyが起きない）、Source Quench（REQ-10 c.1 SHOULD NOT、
RFC 6633）、Redirect（link-local advice）です。非対象はcandidateにならず従来の経路に残ります。

`Nat44UdpPolicy`/`Nat44TcpPolicy`の`icmpv4_errors`（`Nat44Icmpv4ErrorPolicy`）は
`Bidirectional`（default）、`ExternalOnly`、`Disabled`の三値です。前二者のserviceが、outside
ingress/public IPv4宛ての対応errorをlocal consumeより前にinterceptします。`Disabled`は従来
どおりunsupported local controlとしてconsumeします。defaultは以前`Disabled`で、outsideからの
Frag NeededをconsumeしてPMTUDをblack holeにしていました。REQ-4/5/7はactive mappingに一致する
errorの変換をMUSTとし（「unless explicitly overridden by local policy」）、owner方針
（2026-11-01、RFC準拠を基準、securityのためのcontrolは設定可能に）に合わせてdefaultを
`Bidirectional`へ変更しました（behavior change、NAT44-062）。`ExternalOnly`/`Disabled`は
RFC 1812 §1.1.3のsecurity optionです。combined serviceでは引用protocolに対応するpolicyだけが
判定を所有するため、UDPだけを有効にしてもTCP引用をinterceptせず、その逆も同じです。

Protocol Unreachable（3/2）とPort Unreachable（3/3）はdestination host自身だけが生成する
ため、outer sourceが引用destination（remote host）でなければ
`NAT44_ICMPV4_END_HOST_SOURCE_MISMATCH`でdropします（REQ-4のlocal policy override、
NAT44-066）。これが無いとoff-pathのoutside hostが自分のaddressのまま（BCP38は効かない）public
port全域をsweepし、inside UDP flowへhard errorを注入できます。中継routerが正当に送る他の
type（Type 3 code 0/1/4/6/7/9–15、Time Exceeded、Parameter Problem）は同じsweepでlive mappingに
当たり得ます。これはREQ-4に従う残余riskで、rate limitやvalidationはNAT44-065としてdeferred、
securityを優先するなら`external-only`/`disabled`を選べます。Type/Codeと引用protocolの
peekはouter IPv4 Total Length内だけで行い、link paddingをcandidate bytesとして扱いません。
対象はouter IHL=5、nonfragment、TTL>1、valid ICMP checksumと、validなIPv4 headerを含む
引用です。引用datagramはreserved flagをfragment判定からmaskした上で
DF=1/MF=0/offset=0、UDPまたはTCP、public sourceで、IPv4 headerとtransport先頭8 bytesが
実際に存在することを要求します。RFC 1812 §4.2.2.3に従いreserved flagだけではdropせず、
引用tuple/checksum rewrite後もflags/fragment wordへ保存します。reserved併存MF/offsetは
MF/offsetを理由にtyped dropします。

RFC 5508 REQ-3に従いouter ICMP checksumと引用IPv4 checksumを検証し、引用IPv4 optionsを
IHLで越えてtransportを探し、embedded transport checksumそのものは検証しません。outer
sourceはhost-unicast、router-localでないこと、outsideへreverse LPMされることを要求します。
これはRFC 1812 §5.3.8を根拠にしたlocal strict-uRPF anti-spoof policyであり、asymmetricな
external pathを意図的に拒否するtradeoffがあります。0/8、127/8、multicast、240/4、
limited/selected-prefix network/broadcast、inside/local sourceはstateやresolutionを変更せず
dropします。RFC 5508 REQ-4のexternal-realm profileとして、validな中継router sourceは
引用remote addressと一致する必要がなく、translation後も不変です。

UDPはpublic source portのlive mappingと同generationのfilter peerを、runtimeのkey粒度
（`address-and-port-dependent`だけ引用remote destination IPv4/port、それ以外は引用remote
destination IPv4）でauthorityとします。`endpoint-independent`でもpeerはaddress粒度で記録し、
このauthorityに使うため、inbound filterを緩めても未接触addressを引用するICMPは変換しません。
TCPはfiltering modeにかかわらずpublic source portのlive mapping
と引用remote destination IPv4/portに完全一致するlive sessionを要求します。lookupは
mapping/session/peer、last activity、counter、monotonic watermarkを変更しません。退行時刻は
typed drop、同時刻以上はread-onlyです。RFC 5508 REQ-6が直接扱うのはICMP Queryまたは
そのresponseに関係するICMP Errorです。このUDP/TCP引用でもstateを変更しない挙動は、
REQ-6の安全目的を一般化したlocal policyであり、REQ-6の直接実装という主張ではありません。

変換はouter Ethernet、outer destination/TTL/IPv4 checksum、引用source IPv4/source port/
IPv4 checksum、ICMP checksumを一つのpreflight後にin-place更新します。引用UDP checksum
zeroは保存し、nonzeroはRFC 1624更新後のzeroを`0xffff`へencodeします。TCP引用がtransport
8..16 bytesならchecksum fieldを更新せず、17 bytesだけならpartial fieldとしてdropし、
18 bytes以上なら更新します。引用IPv4 Total Lengthを境界にするため、その外側のopaque
trailing bytesをTCP checksum fieldと誤認しません。これはlocal safe boundaryだけであり、
RFC 5508 REQ-3(d)を完全に実装したという主張ではありません。RFC 4884 extension objectの
検出・解析を含むfull supportはNAT44-019Nとしてdeferredです。
translated internal addressを通常LPMし、inside egressと通常neighbor authorityを要求します。
NAT state commitは無く、backend TX rejectでもstateは不変です。

RFC 1191およびRFC 5508 §7.1.2に関係する受信Type 3/Code 4として、unused 16 bitsとNext-Hop
MTU 16 bitsは解釈・clampせず32 bitsすべてを保存します。MTU 0、68、1500、65535も同じです。
local forwarding MTUとの比較、PMTU cache更新、MTU 0のplateau推定、local MTU超過時の
Type 3/Code 4生成はまだありません。DF=0 packetの必要なfragmentation、ICMP query NAT、
RFC 4884 full supportもdeferredです。

## NAT44 ICMPv4 inside-realm error translation

policy `Bidirectional`のserviceは、inside realmから来るICMPv4 errorも変換します。
`forwarding/nat44_icmpv4_inside.rs`が担当し、candidate判定は外部errorより先です。そうしないと
`P`宛てのinside errorを外部candidateがwrong ingressとして拾うためです。candidateは次の全部を
満たすpacketです: inside ingress、router-localでない宛先、対応type/code、引用protocol側の
policyが`Bidirectional`、宛先が`P`（REQ-7）またはLPMでoutsideへ出る（REQ-5）。それ以外は
従来どおりfail closedです。parserとvalidation（outer IHL 5、nonfragment、TTL>1、ICMPと引用
IPv4のchecksum、引用のDF=1/MF=0/offset=0、UDP/TCP、transport先頭8 bytes）は外部errorと共有します。

**REQ-5。** inside host X（またはXへのinside next hop）が、NATが届けたinbound packet
`R:r -> X:x`についてRへerrorを返します。NATは引用を外部での姿`R:r -> P:x'`へ戻し（REQ-5 a）、
type/codeを保存し（b）、outer sourceを`P`にします（c、NAPT）。outer destinationは引用source
`R`と一致する必要があります。errorは引用packetの送信者へだけ行くべきで、そうでなければ
`NAT44_ICMPV4_OUTER_DESTINATION_MISMATCH`です。egressはoutside、neighborは通常のforwardと同じです。

**REQ-7。** `X1:x1 -> P:x2'`がhairpinされ`P:x1' -> X2:x2`としてX2へ届いた後、X2が`P`宛てに
返すerrorを二重変換します。引用は`X1:x1 -> P:x2'`（X1が送ったpacket）、outer destinationは
X1（REQ-7 a）、outer sourceは`P`（REQ-5 cをREQ-7がそのまま適用）、egressはinsideです。
hairpinning offでは`NAT44_*_HAIRPIN_DISABLED`、引用sourceが`P`でなければ
`NAT44_ICMPV4_QUOTED_PUBLIC_SOURCE_MISMATCH`です。

**authority（全てread-only）。** NAT/firewallのstate、counter、watermarkを作成・更新・削除しません。

- outer sourceはhost-unicast、router-localでなく、reverse LPMがinside（local strict uRPF、
  `NAT44_ICMPV4_SOURCE_FORBIDDEN`）。さらに引用internal destination自身か、routerがそこへ使う
  inside routeのnext hopであること（`NAT44_ICMPV4_INSIDE_SOURCE_MISMATCH`）。これで別のinside
  hostのflowについてerrorを詐称できません。next hopはegressがinsideのrouteのものに限り、
  Protocol/Port Unreachable（3/2、3/3）はinternal host自身からだけ受け付けます（NAT44-066）。REQ-5 cはinside realmのどのrouterのerrorも変換対象に
  しますが、2 hop目以降のrouterのerrorはこのlocal policyで拒否します（deviation NAT44-064）。
  L2上でのIP source詐称そのものは、通常のoutbound UDP/TCPと同じく検出できません。
- 引用internal endpointは、liveでpublic portを今も所有するmappingを持つ必要があります
  （internal tupleのdirectory lookupと、public port owner経由で同じslot/generationに戻るかの
  照合）。UDPは引用remoteがruntimeのkey粒度のpeer（EIFでもaddress粒度、NAT44-040と同じ）、
  TCPはexact live session。inside hostは、mappingが一度も通信していないexternal hostへerrorを
  送れません。EIFで未接触remoteから届いたdatagramについてのUDP errorは変換しません
  （deviation NAT44-063）。REQ-7ではX2側（X2:x2のmappingとpeer/session `P:x1'`）とX1側
  outbound half（`P:x1'`のmappingとpeer/session `P:x2'`）の両方を要求します。
- REQ-5の引用remoteがrouter addressなら`NAT44_ICMPV4_QUOTED_REMOTE_LOCAL`です。hairpin state
  （remote `P`）に届くのはREQ-7の経路だけで、外部からは従来どおり届きません（NAT44-047）。
- 作業はpacketごとに固定です。directory lookupが最大3回（REQ-7）、firewall probeが最大2回、
  RFC 1624の固定数のword updateです。翻訳はforwardであり、routerが送信元となるICMPの生成では
  ないため、RFC 1812 §4.3.2.8の生成rate limiter（既存のper-egress limiter）は適用しません
  （NAT44-065）。inside hostは同じrateでUDP/TCPも送れます。

**firewall view。** ICMP error自体はrule評価もstate作成もせず、RELATEDとしてだけ扱います。
REQ-5の引用は送信者が受信したpacketそのもの（post-DNAT、ingress outside/egress inside、
`R:r -> X:x`）で、live stateのoriginまたはexact reply（interfaceも反転）に一致する必要が
あります（`FirewallRuntime::inspect_related_icmpv4_either_direction`）。X発のflowへのreply
についてのerror（典型的にはclose済みsocketへのUDP replyに対するPort Unreachable）はreply側、
Rが開始してruleが許可したflowはorigin側で一致します。REQ-7はinbound half
`P:x1' -> X2:x2`とoutbound half `X1:x1 -> P:x2'`の両方が一致する必要があります。
address-dependentではX1のpeer `P`がinside全体のwildcardなので（NAT44-046）、X2はX1が送って
いないpacketについてもNAT authorityを満たせますが、X1のexact outbound flowが無いため
firewallが拒否します（NAT44-061）。missは`FIREWALL_RELATED_ICMPV4_STATE_MISS`、auditは
`Related`です。firewallなしのADF/EIFでは、UDP REQ-7 errorがX1の送っていない`P`のport
（`X1:x1 -> P:x2'`）を引用しても届きます（review L1）。REQ-9 aとADFが要求するaddress粒度peerの
帰結で、errorはinside realm内にとどまりX1 socketのtuple照合が最終guardです。同様にREQ-5の
UDP引用remote portもADF/EIFではauthorityになりません（review L2、利得は無視できる）。
outside→inside（REQ-4）は従来どおりdirect originだけを照合します。NAT44-021の
外部→内部bypass拒否とroute-miss NAT gateは別経路で不変です。

**rewrite。** 共通builder（`Nat44Icmpv4Rewrite`）がouter source/destination、引用
source/destination address/portを任意に置換し、outer IPv4（TTL−1を含む）、引用IPv4、引用
transport（引用Total Length内だけ、UDP zero保存、算術zeroは`0xffff`、TCP 8..16/17/18境界は
NAT44-019C）、ICMP checksumをRFC 1624で更新します。外部errorの変換も同じbuilderを使います。

## Minimal IPv4 stateful forward firewall

firewallはopt-inの追加serviceであり、既存`forward_batch*` APIとdefault forwardingを変更
しません。`forward_batch_with_firewall`はplain forwarding、combined APIはUDP/TCP NAT44と
同じworker-local RX transactionで合成します。対象はrouterを通過するunfragmented IPv4
UDP/TCPだけです。ARP、ingress-scoped router-local IPv4、RX phase後に実行するrouter-originated
generated packetはfirewall domain外です。options、MF、nonzero fragment offset、
TCP/UDP以外のforward protocolはsilent typed dropで、ICMP/RSTを生成しません。
RFC 791のfragment fieldsでMF=0/offset=0なら、DF=0とDF=1のどちらもunfragmented datagram
として許可します。RFC 1812 §4.2.2.3に従いreserved flagはfragment判定からmaskし、単独では
dropせずforward wireへ保存します。reserved flagとMF/offsetが同時にある場合は、MF/offsetを
理由に従来どおりdropします。ここでRFC 6864のatomic datagramという用語は使いません。

UDP/TCP NAT44、firewall、router-originated ICMPv4 error captureを全て有効にするworkerは
`forward_batch_with_nat44_udp_and_tcp_and_firewall_and_icmpv4_errors`または監査付きvariantを
選び、caller-backed `Icmpv4ErrorRuntime`を必須でbindします。既存のruntimeを取らない
combined APIは非生成のままです。公開APIへfeature選択用のoptional runtimeを追加せず、
capabilityはentry pointで明示します。

ruleはstable `FirewallRuleId`を持つimmutable sliceで、ingress/egress `IfId|Any`、
canonical source/destination prefix、TCP/UDP、inclusive source/destination port range、
`AllowStateful|Deny`を持ちます。順序どおりfirst-matchし、matchなしはimplicit default deny
です。overlapは順序の意味を持つため許可し、duplicate ID、unknown interface、
noncanonical prefix、reversed range、invalid timeout、zero config generationはpublication
前に拒否します。さらにcontrol planeはCSPRNGからpublicationごとにfreshな非ゼロ128-bit
`FirewallHashKey`を生成してconfigへ渡します。all-zero keyはtyped constructorで拒否し、
randomnessやsyscallをpacket pathへ持ち込みません。同一generationと同一rules/snapshot
identity/hash keyのreconcileはno-op、
同一generationの別identityとgeneration regressionは拒否します。generation前進時に同じ
hash keyを再利用したpublicationも`HashKeyNotRotated`で拒否し、fresh keyを伴うforward
generationだけが全stateをflushします。
新しいpublication pathでは`ValidatedFirewallOwner`が
`ValidatedForwardingOwner`のnonzero nonceへbindしたboxed rulesを一度だけ検証・fingerprint化
します。owner固有のnonzero firewall publication nonceもchecked incrementだけで発行し、
枯渇時はwrapせず拒否します。`config()`はowner lifetime内のO(1) borrowで、pointer/contentが
再利用されてもnonceが異なるため同一identityにはなりません。互換用`FirewallConfig::new`は
firewall nonce zeroのlegacy identityを作れます。`ValidatedFirewallOwner::new`はnonzero
forwarding nonceを持つsnapshotだけを受理し、nonzero firewall nonceを生成します。
packetごとのsnapshot再hashやrules slice equalityは行いません。
runtimeがpublicationを跨いで保持するのはpointerをdereferenceしないowned binding metadata
だけで、rules sliceはcurrent `FirewallConfig`からrule scan中だけborrowします。
`preflight_reconcile`はgeneration regression、same-generation collision、hash-key reuse、
runtime epoch exhaustionをmutation前に検証し、exact runtime borrowをpermitへ保持します。
permit Dropとerrorは全field不変です。fresh generationのtotal commitは全flow stateをflushし、
binding/epochを更新し、counterだけをsaturating加算します。旧rules allocationはその後drop
でき、新allocationだけを次batchへ渡せるためself-referenceを作らず、fast pathのrule scanは
borrow-onlyのままです。

flow keyはprotocol、origin ingress/egress、initiator/responder IPv4 address+port、
config generationです。ordinary forwardingはwire view、NAT outboundはpre-SNAT
internal→remote、NAT inboundはpost-DNAT remote→internalをcanonical viewにします。
reverseはaddress/portだけでなくinterfaceもexact swapが必要なので、asymmetric interface
returnは別flowとしてrule evaluationされ、通常はdefault denyです。TCP/UDPはprotocolで
分離され、同じ数値portを共有しません。

UDPはchecksum zeroを許可し、nonzero checksumはUDP Length境界のpseudo-headerを含めてfull
検証します。destination port zeroは拒否し、source port zeroはplain forwardingの明示ruleが
rangeに含めた場合だけ許可します。NAT pathは既存NAT policyによりsource zeroを引き続き
拒否します。許可されたdatagramはdefault 300秒、minimum 120秒のexact reverse
pseudo-sessionを作ります。

TCPはfull header/data-offset/checksum/portを検証し、新規stateはSYN=1かつ
ACK/RST/FIN=0だけです。ECE/CWRとTCP Fast Open payloadは妨げません。既存exact flowでは
simultaneous-open、ACK、data、FIN、RSTを許可します。両方向でACKを観測したときだけ
`Opening`から`Active`へ移しますが、sequence/window/ACK numberは検証しません。Openingは
default/minimum 240秒、Activeはdefault/minimum 2時間4分、最大7日です。FINでdelete/shorten
せず、RSTはstateをdeleteせずidle timeもphaseもrefreshしません。ここでいう
`ESTABLISHED`はlocal exact state hitだけで、conntrack helper、TCP reassembly、RFC 5382/
RFC 7857 full complianceの主張ではありません。

stateはcaller-backed fixed sliceをworkerが専有し、runtimeは`!Send + !Sync`です。
forward/reverseで同じhomeになるSipHash-2-4相当のkeyed canonical hashを使うlinear open
addressingです。capacity 4以上の`usable_capacity`は`N-ceil(N/4)`、つまり最大75% occupiedとし、
少なくとも25%のempty headroomを維持します。0はusable 0、caller-backedの小容量test/profileを
壊さないため1..=3だけは全slot usableという明示的例外です。commitも上限を再検証するため、
複数のoutstanding planからlive loadを超過できません。通常live hitはsecret hashとheadroomの下で
expected O(1)、established lookupはemptyまたはcapacityまでのbounded probeで、new flowだけ
ordered ruleをscanします。

exact expiryをprobe中に発見したattemptは最大1 slotだけ`occupied=false`へ戻し、最大capacity回の
backward-shift deletionで後続live entryのprobe chainを修復し、最大1回だけ先頭から再scanします。
再scanで見つけた別のexpired slotは追加deleteせずfirst reuse候補として扱います。

lazy cleanupはprobe chain上のexpired slotしか回収しないため、それだけでは全flow失効後の
full tableで、empty homeに直接着地するtuple（同一tupleの再送を含む）が永久に
`FirewallStateTableFull`になり得ます。そこでrule許可済みの新規flowが「placement先がempty
かつ`occupied_count >= usable`」で拒否されそうなときだけ、refusal-path sweepを1回実行します。
sweepはworker-localな`reclaim_cursor`（初期値とreconcile後は0）から循環して最大N slot
（1周）を読み、最初のexpired slotを1件だけ同じbackward-shiftで削除してから同じtupleを再probe
します。成功したsweepはcursorを削除位置に残します。sweep自身のshiftはentryをholeへ寄せる
だけでcursorの後ろへは動かさないため、通常は次のsweepが回収済み・再充填済みのslotを読み直し
ません。ただしcursorより手前でlazy probe cleanupが削除すると、そのshiftがentry（expiredを
含む）をcursorの後ろへ移すことがあります。これはcostだけに影響し、次の1周で必ず見つかるため
回復保証は変わりません。worker-localな`reclaim_not_before_ms`（全occupied slotの
idle deadline `last_activity + TTL`の下界。初期値とreconcile後は0）が`now`より大きい間は
sweepを読まずO(1)で拒否します。expired slotが無かったsweepは下界をlive slotの正確な最小
deadline（`now`より後）へ上げ、commitは書いたslotのdeadlineで下界を下げる（ACKによる
Opening→Active昇格でdeadlineが早まる場合を含む）ため、下界は常に正しく、full-liveな表への
新規flowは失敗sweepを下界時刻ごとに高々1回しか起こしません。失敗sweep後の下界は`now`より
後なので、時間軸でも失敗sweepは1 msあたり高々1回です。最早deadlineのflowをrefreshし続ける
攻撃者でも、強制できるのはおよそ1 msに1回のfull sweep（N read）までです。下界が
`u64::MAX`に飽和したslotは`now == u64::MAX`のときだけ毎packet sweepを走らせますが、
上限内で無害です。

単一packetの上限は、probe 2N+shift、sweep N+shift、再probe 2N+shiftの定数倍N
（delete最大3件）でstrict O(N)のままで、expired数を掛けたO(N²)にはなりません。cursorにより
全失効後の再充填は償却O(1)/createです。実測（N=65536、usable 49152を全失効させて49152件を
再作成、probe+maintenance counter合計）は、slot 0から毎回scanする版の総計4.04e8・平均8224・
最大65584に対し、総計854350（約13N）・平均17・最大329でした。償却O(1)はこの一斉失効後の
再充填の場合です。1 msに1 flowずつ失効するtrickle/staggered expiryでは、cursorから次の
expired slotまでの距離が長く、createは引き続き約O(N)です（N=65536で実測平均≈N/2）。
この場合も下界gateにより概ね1 msあたり1周、かつ持続可能な失効率usable/TTLで抑えられます。回復保証:
expired slotが1件でもあれば、そのdeadlineは下界以上かつ`now`以下なのでsweepが必ず走って
1件削除し、`occupied_count < usable`となって同じattempt内の再probeがempty slotで終わり
placementが成功します。したがって`FirewallStateTableFull`はoccupied slotが全てliveの
ときだけ返り、同一tupleの再送も含め失効由来の拒否は0回で回復します（timer phaseや他packet
の通過には依存しません）。cleanupによるdelete/moveはruntime epochを進め、移動前planを
release buildでもstaleとして拒否します。live evictionはありません。probe、maintenance shift/hash/scan、
rule evaluation数はcounterで観測できます。

NAT44 UDP/TCPのexpired mapping/peer/sessionは、作成時の`find_reusable_*`がslice全体を
linear scanし、`select_port`が非liveなport ownerを置換候補にするため、opportunisticな回収
だけに頼る同種のliveness gapはありません。ただしこれらはindex 0からの走査で下界gateも
cursorも持たず、ほぼ満杯時には新規作成attemptごとにO(N)の既存costがあります（NAT44-035、
follow-up）。

common Ethernet ingress admissionはprotocol parserより前にexact ingress MACを検証します。
続くIPv4 structural/header-checksum検証後のIP admissionだけは、sourceとnonlocal destinationの
selected-prefix境界を分類するread-only LPMを行います。このlookupはbytes、watermark、state、
audit、resolution、generated actionを変更せず、rejectionはICMP/ARPを一切生成しないsilent drop
なのでwire-visibleなroute oracleを作りません。local `DropReason`だけが境界を区別します。
このcommon admissionを通過したpacketでは、runtime/config/snapshot authorityとIPv4/transport
structural/checksum validationを通常forwarding destination LPMより前に行います。valid attemptは
state/NAT lookupより前にworker-local security watermarkを単調更新し、
rule/default deny、state full、route/neighbor/NAT missでも戻しません。そのためfuture時刻のdeny
やmiss後に古い時刻でflowが復活することはなく、古いpacketはbyte/state/activity不変の
`FirewallClockRegression`またはNAT clock regressionになります。NAT inboundもFW state/rule判定を
TTL判定より先に行います。

FW opt-in時のLPM missにはegressが無いため、stateful planではなくegress-freeなpolicy評価を
行います（RFC 1812 §5.2.7.1のDestination Unreachable Networkを、policyが許すpacketにだけ返す）。
ruleはfirst-match順に、egress以外のselector（ingress、source/destination prefix、protocol、
port range）で照合します。

- egress `Any`のruleが判定する。`AllowStateful`ならpermit、`Deny`ならdeny。
- egressを一つに限定した`AllowStateful` ruleはmatchできず、skipする。
- egressを一つに限定した`Deny` ruleがmatchすれば、routeがそのegressを指していれば拒否される
  ため、fail closedでdenyする。
- 判定するruleが無ければdefault deny。TCPは新規flowと同じくvalid initial SYNだけをpermitする。

established stateはkeyにegressを含むため参照しません。評価はstate作成/refresh、security
watermark、audit record、deny counterを変更せず、`rule_evaluations`だけを数えます（clockは
共通preflightで観測済み）。permitならfirewallなしのroute missと同じ`decide_icmpv4_error`
（同じper-egress rate limiter、quote規則、reverse authority/source選択、TTLよりroute miss優先）で
Type 3/Code 0をqueueして`RouteMiss`、denyなら従来どおりICMP/ARPをqueueしないsilentな
`FirewallRouteUnavailable`です。route missはNAT outbound translationより前に判定するので、
quoteは受信datagramのままで、NAT mapping/sessionもfirewall flowも作りません。

route oracle: errorを返すのは「どのegressに対しても新規flowとして許可されるpacket」だけです。
そのpacketはroute hitなら転送（またはTTL/host error）されるため、Network Unreachableが示すのは
同じpacketの転送可否から既に観測できるroute有無（RFC 1812がrouterに通知を求める情報）だけ
です。egress限定ruleを単に「不一致」とすると、例えば「WAN→LAN deny、その後egress `Any`の
allow」というrulesetで、LANへroute hitするprobeはsilent、route missはICMPになり、denyされた
宛先空間のroute有無が漏れます。egress限定denyのfail closedがこのoracleを塞ぎます。代償として、
同じegressへの先行allowにshadowされたegress限定denyでもroute missは保守的にsilentです。
egress限定ruleだけのruleset（M1 fixtureのv1など）では、route missは従来どおりsilentです。

「どのegressでも許可」はfirewall ruleだけでは決まりません。route hitではfirewall planより前に、
egressに依存するNAT gateがsilent dropします（external→internalの
`Nat44ExternalToInternalBypass`、combined realm mismatchのcrossing reject、inside→outsideの
NAT runtime/authority要求）。これを無視すると、例えばNAT inside=LAN/outside=WANで
`ingress Any / egress Any`のUDP allowがある場合、WANからLAN host宛はsilent、未routeの宛先は
ICMPとなり、外部からinside側のroute有無を走査できます。そのためroute missでは、firewall評価の
前にread-onlyな`route_miss_may_hit_nat_reject`で、いずれかのNAT configのoutsideがingress、
realm mismatch時のTCP/UDPでingressがinside、またはinside発のUDP/TCPで対応するNAT runtimeが
不在/不一致なら、counter/trace/stateを変えずsilentな`FirewallRouteUnavailable`にします
（いずれも保守側で、該当egressへのrouteが無い場合も含む）。firewall評価より後で行う
outbound NATのshape/plan reject（DF=0の`Nat44UdpNonAtomicIpv4Unsupported`、source port 0、
SourceForbidden、ReverseAuthorityMismatch、port pool枯渇など）は再現しないため、例えばLANからの
DF=0 UDP/53はroute有りならsilent、route無しならICMPになります。これは受容します: 送信者はinside
にいて有効なDF=1 trafficで同じroute有無を知ることができ、firewallなしの経路にも同じ非対称が
あり、生成errorはper-egress rate limiterで抑えられるためです。

残るdeviation: routeが撤去された後の既存flowのpacket（例: established TCPのACK、許可ruleが
egress限定のflowのUDP）はsilentな`FirewallRouteUnavailable`で、firewallなしの経路やRFC 1812
§5.2.7.1のMUSTと異なりNetwork Unreachableを返しません（FW-025）。2026-11-01にRFC準拠を基準として
再評価し、次の理由でdeviationを維持しました。

- routeはconfig publicationでしか変わらず、すべてのpublicationは新generationとfirewall hash key
  rotationで全flowをflushします。route missの時点で「撤去前のflow」のstateは存在しないため、
  established lookup（egress非依存にinterfaceごとprobeする等）を加えてもhitせず、効果がありません。
- 同じreloadの後にrouteが残っていても、そのpacketはstateなしの新規attemptとしてfirewallにsilent
  dropされます（TCP ACKなら`FirewallTcpInvalidInitialFlags`）。route missの場合だけerrorを返すと
  route有無が外から観測でき、上記のroute oracleを再び開きます。
- egress限定allowで許可されていたUDPをadmitするには撤去前routeのegressを知る必要がありますが、
  routerはそれを保持せず、推測でadmitすると拒否宛先空間のroute有無が漏れます。

解消には、flowを保ったままrouteを変えるpublication（動的routing等）と、それに合わせたstate
参照が前提になるため、そのsliceで再検討します。RFC動作が必要なtrafficはegress `Any`のallow
ruleでegress-free評価をpermitにでき、逆にroute-miss errorを全体に止めたい場合は
`net-unreachable = false`を使えます。

full compositionでもfirewall authorizationはTTL判定とgenerated error captureより先です。
rule/default deny、runtime/config/snapshot authority failure、上記egress-free評価でdenyされた
LPM missはICMP/ARPをqueueしないsilent dropを維持します。認可済みpacketのTTL 0/1は既存のerror suppressionとreverse
authorityを通過した場合にactionをqueueし、quoteはNAT rewrite前の受信IPv4 datagramです。
TTL failureではNAT mapping/sessionとfirewall flowをcommitしません。captureはRX phaseだけで、
generated実行をforwarding wrapper内へ融合しません。worker tick順は引き続き
`publication/reconcile → RX → resolution timer poll → failure dispatch → generated ARP →
generated ICMP`で、生成packetはfirewall domain外です。

planが返すcreate/refresh replacementと論理的にliveなflowのactivity/phaseはcommitまで反映
しません。一方、security watermarkと同様にlazy expiry housekeepingはprobe中に実行でき、
expired slotのdelete、backward-shift move、expired counter、maintenance counter、runtime
epochを更新します。planはそのhousekeeping後のruntime epoch、config generation、slot
generationを保持します。commitはrelease buildでもこれらとusable capacityを検証するtyped
`Result`で、reconcile/cleanupはepochを進めるため、
reconcile後またはslot reuse後のstale planをcommitできません。直列packet pathではvalidation、
NAT authority、LPM、FW rule/state、TTL/neighbor、rewrite preflightが成功してbytesを更新した
後にchecked NAT/FW commitを行い、TX requestします。同batchの次packetは直前commitを参照でき、
backend rejectでもTX-request stateを保持します。deny、route/neighbor/NAT/rewrite failureでは
FW flowを作りません。

audited APIはcaller-backed fixed `FirewallAuditBuffer`へ、policy evaluationへ到達した各packetの
effective `Allow|Drop`、`New|Established`、`Rule(FirewallRuleId)|Default`、matched action、
typed terminal failureを順番に記録します。allow ruleへmatchしてもinvalid initial TCPやstate
fullで最終的に転送しないpacketは、matched actionを`AllowStateful`のまま保持しつつeffective
verdictを`Drop`、failureをそれぞれ`InvalidInitialTcp|StateTableFull`として記録します。
buffer不足はtyped overflow countになり、`clear`はrecord/overflow viewをresetします。hot pathに
heap、`String`、trait objectを導入しません。

NAT inbound mapping/sessionがあってもexact reverse FW stateが無ければinside neighborより前に
denyします。NAT/FWどちらかのcapacity plan failureでも他方をcommitしません。outsideからのNAT44
ICMPv4 errorは、NAT read-only inspectionが復元したpre-SNAT internal address/portと引用内の
remote address/portから、origin ingress=inside、egress=outsideのcanonical forward tupleを
構成します。UDPもremote portまでexactにfirewall照合し、TCPはNAT sessionとfirewall stateの
両方でendpoint exactを要求します。firewall lookupはkeyed tableを最大capacity回probeし、
live/config generation/interface/tupleのdirect origin一致だけをRELATEDとして許可します。
reverse match、rule scan、expiry cleanup、delete/move、activity/phase/counter/watermark更新は
行いません（inside発errorのeither-direction照合は「NAT44 ICMPv4 inside-realm error
translation」）。退行時刻は状態不変のtyped clock regression、state missは
`FirewallRelatedIcmpv4StateMiss`でinside route/neighbor/rewriteより前にsilent dropします。
audit到達時だけhitを`Allow/Related/Rule(origin)/AllowStateful`、missを
`Drop/Related/Default`かつ`matched_action=None`、`failure=None`として記録します。terminalな
miss理由はaudit failure enumを拡張せず`FirewallRelatedIcmpv4StateMiss`で表現します。
parser、NAT authority/lookup、clock errorはRELATED auditを残しません。tracked hit後の
neighbor missだけがARPをscheduleでき、fresh retryで再照合します。backend rejectを含め
NAT/FW stateはread-onlyです。

NATを伴わないplain forwarded ICMPv4 RELATEDは、引用tupleからorigin interface authorityを
安全に一意化する契約が未確定のためdeferredです。既存の
`FirewallRelatedIcmpv4Unsupported = 114`は互換性のため予約し、renumberしません。

eager dynamic-cache scan/flush、unresolved packet hold queue、gratuitous ARP生成、
ARP Probe/Announcement生成、proxy ARP、VLAN、Address Conflict Detection、実装済み
Echo Reply/Time Exceeded/Destination Unreachable Network以外のICMP生成、
firewall conntrack helper/application inspection、config parser、pcap、AF_XDP、DPDK、binary、thread、
benchmarkはこの
sliceのscope外です。

## M1 sim router: config → publication → tick → run-sim

M1の`ruster`はrootやNICを使わず、宣言的configから`SimIo`上のfull-service routerを決定的に
動かします。各段はcold path（parse、validate、candidate構築、storage確保、plan、文字列化）と
hot path（`run_tick`内のpacket処理）に分かれ、hot pathにはparser、allocation、lock、format、
`dyn PacketIo`が入りません。

```text
config TOML ──parse/validate──► ValidatedConfigV1            (ruster-config)
   │                                 │ candidate_from_config + PublicationSequencer
   │                                 ▼  (generation, sim key source)
   │                           ValidatedCandidate             (ruster-control)
   │                                 │ FullServiceStorage + ActivePublication<SimIo>
   │                                 ▼  successor: validate → 5 preflight → 1 commit
   │                    FullServicePublication seam           (ruster-runtime)
   │                                 │ run_tick(publication, candidate?, SimIo, now, budgets, TickObserver)
   │                                 ▼
   │                  core full composition wrapper           (ruster-core)
   │                                 │ TickReport / counters / BackendStats
   ▼                                 ▼
ruster validate / plan     TickObserver snapshot ──► run-sim JSONL / CLI (sim-scenario, cli)
```

段ごとの契約は以下の小節にまとめます。scenarioのfixtureは[`fixtures/m1`](../fixtures/m1)、
exit criterionごとの証跡は[`release-evidence/m1.md`](release-evidence/m1.md)です。
M1が示すのはsim backend上の決定的なend-to-end動作であり、AF_PACKET/AF_XDPでの実NIC動作、
throughput、production key sourceは含みません。

### config（`ruster-config`）

`parse`は最大1 MiB（`MAX_CONFIG_BYTES`）のUTF-8 TOMLをschema versionでpredispatchし、V1の
interface、address、route、neighbor、NAT44、firewall、capacity、tick budgetのDTOへexact
decodeします。unknown/duplicate field、runtime生成値の指定、上限超過のlistはvalue-freeな
`Diagnostic`（stage、code、schema path、数値上限だけ）でfail closedです。`validate`は
`ValidationLimits`の下でcanonicalなowned core値、connected route、cross-reference/on-link、
policy/NAT/firewall、全runtime storage shapeを作ります。interface name/deviceは
`[A-Za-z0-9._-]`、15 bytes以下に制限します（CONFIG-003）。configはpublication identity、
hash key、generationを持たず、validationはmutationを起こしません。configではservice sectionを
省略できますが、M1のbridgeはResolution、ICMPv4 error、NAT44 UDP/TCP、firewallの全てを要求し、
欠落を`MissingService`でtyped rejectします（M1 owner決定）。

任意の`[backend]`（M2 S9、CONFIG-004〜007）はpacket backendを選びます。省略時は`sim`で、
schema-version 1のまま後方互換です。`af-xdp`はinterfaceごとに一つの`[[backend.ports]]`
（queue、copy/zero-copy/auto、need-wakeup、native/generic attach、4 ring、frame size/count、
generated frame、headroom）を持ち、`validate`はmutationもresource取得もせずboundedに検査して
IfId順の`ValidatedBackendV1`（portはbindするdevice名のcopyを持つ）を返します。bind flag、
`RingConfig`、`UmemConfig`は`ruster-io-xdp::native_profile`のvalidatorが構築します。このmoduleは
unsafeもFFIも含まないsafe profileで、`ruster-io-xdp-native`は同じ型・定数をre-exportして使うため、
`ruster-config`（`#![forbid(unsafe_code)]`）、`ruster-control`、`ruster-cli`、`ruster-sim-scenario`は
native crateへ依存せずに、configがnative profile（need-wakeup必須、
2048/4096-byte aligned chunk、kernel固定256-byte headroomへの加算、exact RX/generated
partition）より緩くなれません。configの追加policyは、1 queue/interface、queue ≤ 1023、ring
64..=16384、`completion >= tx`、visible packet bytes ≥ 1514、generic attachでは`mode = "copy"`
だけ（skb XDPは常にcopyなので`zero-copy`/`auto`を拒否）、UMEM 256 MiB/socketと1 GiB/config、
そして`frame-count - generated-frames >= fill + tx`です。最後の式はlibxdp慣行と同じ最低限の
floorで、Fill ring満杯とTX ring一杯のforward frameを同時に賄えるだけです。未回収のcompletion、
driverがdequeue済みのTX frame、coreが借用中のRX frameは数えないため、それだけで枯渇しないことは
保証しません。X01/X02 engine（M2 S3/S4）は、in-flight TXを`tx` entry以下に制限し、free listが
Fill ringを満たせないときもstallせずに進みます（部分的なFill、refill前のcompletion回収。ledger
BACKEND-004、「AF_XDP TX/Completion half」節）。
`existing-xdp-program`は`refuse`だけで、既存programを置換・detachしない方針を明示するために
fieldを残します。`queue`は`backend.ports[i]`直下でだけoperator入力として許し、他の位置の
queue/shard/umem/worker fieldはruntime生成値として従来どおり拒否します。

`ApplyPlan`は`[backend]`の差を`BackendChange`（kind、existing-program、IfId keyのport差分）
として出し、差があれば`RestartRequired::Backend`を最後の理由に加えます。portはdeviceを含むため、
af-xdpでbind先interfaceの`device`を変える、または二つのdeviceを入れ替えるとrestart-requiredです
（sim backendではdevice変更は従来どおりreloadableなlabel変更）。`ApplyPlan::for_active`は
`Backend`を含むplanでlive dry-runを行わず、`dry_run()`を
`Err(ApplyError::RestartRequired(Backend))`、flushを`All`にして、in-place reload可能に見せません。publication
candidateはbackendを持たないので、live activationはこの理由を返しません。backend
resource（socket、UMEM、XDP program）を所有するprocessがreload時に拒否します。`run-sim`は
`SimIo`だけを動かすため、非`sim` backendのconfigを初期configでもapply stepでも
`UnsupportedBackend`（stage `backend`）としてtyped rejectし、黙って`SimIo`で実行しません。

### publication、activation、plan（`ruster-control`）

`candidate_from_config`は`ValidatedConfigV1`、generation、`PublicationKeySource`から
`ValidatedCandidate`を作ります。key sourceは`KIND`で由来を自己申告し、M1の
`SimDeterministicKeySource`はscenario seedとgenerationから決定的にUDP/TCP NAT44/firewall keyを
導出する`DeterministicSimulation`です。key、seed、allocator seedはどのDebug/plan/run-sim出力にも
出ません。

production key sourceは`OsRandomKeySource`（KIND=`OperatingSystemRandom`）です。`open`で
`/dev/urandom`を`std`だけで一度開いてcharacter deviceかつdevice番号1:9/1:8であることを確かめ、
publicationごとに48 bytesを新たに読みます。kernel 5.18未満の`/dev/urandom`は起動初期にseed前の
CRNG出力を返しうるため、`getrandom(2)`化はfollow-upです。short readは続きを読み、`EINTR`は再試行し、それ以外のopen/read失敗、
EOF、all-zero keyはvalue-freeな`KeySourceError`（`ErrorKind`だけを持つ）になり、予測可能な
keyへfallbackしません。generation採番、key再利用拒否、rollbackは`PublicationSequencer`の
ままです。live trafficの入口は`ProductionSequencer`で、sealed marker `ProductionKeySource`
（`OsRandomKeySource`だけが実装）を要求し、`new`が`S::KIND.is_production()`をcompile時に
assertします。sim sourceはcompileできず、`run-sim`は従来どおり`PublicationSequencer`と
`SimDeterministicKeySource`を使います（M1 goldenは不変）。`ruster run`（M2 S10a）は起動処理
全体が`ProductionSequencer<K: ProductionKeySource>`だけを受け取ります。sourceのDebugはredactし、keyは`Copy`のcore値として
authorityと各runtimeへ複製されるため、`unsafe`もdependencyも使わないこのcrateではzeroizeを
保証できず、行いません（PUB-010〜013）。

`ruster-control`のstatic-only owned publication境界は、nonzero generation、固定runtime
storage shape、owned forwarding table、必須UDP/TCP NAT44 input、owned firewall rulesを
`PublicationPlan`へ集約します。`ValidatedCandidate`構築はfull-service presenceと全NAT
directory/node/port-owner shapeを先に検査し、`ValidatedForwardingOwner`を作ってからその
snapshotへUDP/TCP configと`ValidatedFirewallOwner`をbindします。dependent configとfirewall
ownerをforwarding ownerより先にdropするfield順で保持しますが、self-reference、leak、unsafe
pointerは使いません。`authority()`はcandidate lifetimeに制約されたsnapshot/config viewを
allocation、再validation、再hashなしのO(1)で返します。generation前進、UDP/TCP/firewall key
rotation、固定shape/policyはstatic successor checkだけを提供し、ownerのinstallやruntime変更は
行いません。

live activationは`FullServiceStorage`と`ActivePublication<'storage>`だけで行います。
`FullServiceStorage`はcandidateのstorage shapeどおりに全runtime slot配列を一度だけ確保し、
`ActivePublication`はそれを`'storage`の間exclusive borrowして5 runtimeを新規構築します。
既存runtimeのadoptはできません。`ActivePublication`は一つのbackend型に束縛され、
`ruster-runtime`の`FullServicePublication`をそのbackendに対してだけ実装します。seamの
`active`/`publish_candidate`は`run_tick`だけが作れる`PublicationTick` tokenを要求し、
`FullServiceView`のruntime borrowはprivateなので、tick外やviewを受け取ったwrapperから
runtimeを変更できません。ただしtokenが保証するのは「`run_tick`から到達するcodeだけが呼べる」
ことまでです。`FullServicePublication`実装（adapter、wrapperを含む）はtokenを受け取り転送
できるtrusted codeです。backendへの束縛は型だけで、毎tick同じbackend instanceを渡すのは
callerの責任です。core `PublicationQuiescenceGuard::new`はsealされていないため、guardは型の
規律でありquiescenceの証明ではありません。backendの実checkからguardを得るのは`run_tick`
自身だけです。guard mintのseal（backend専用化またはunsafe化）は後続課題です。
applyは`validate_successor`の後、Resolution/ICMPv4 errorの`preflight_publication`と
NAT44 UDP/TCP・firewallの`preflight_reconcile`の5 permitを同時に保持し、全て成功した場合だけ
一点でcommitします。各permit commitとcandidate swapには失敗分岐がありません。途中の失敗では
permitのDropにより全runtimeが不変で、旧candidate/snapshot/generationが継続します。
Resolution/ICMP runtimeは旧snapshotのauthorityを持つqueueを全flushし、NAT/firewallはkey
rotationに伴いflow stateを全flushします。累積counterは保持します。storage shapeと
Resolution/ICMP policy、interface IfId/MACの変更はtyped `RestartRequired`としてrejectし、
resizeしません。reloadのたびにARP学習も消え、NAT/FW keyのrotationによりTCP sessionも切れます。
`ApplyPlan`は二つのvalidated config文書からmutationなしでkey順のroute/neighbor/local IPv4/
interface/FW rule差分、FW順序・policy、NAT realm/port/policy変更、restart理由、flush見込みを
作ります。`ActivePublication::check_successor`はguardなしで同じ検証と5 preflightを行い、
permitをcommitせず破棄するdry-runで、live flush数を返します。generationは
`PublicationSequencer`が単調に採番し、発行済みkeyの再利用をrejectします。M1のrollbackは
旧config文書を再validateし、新generation・新keyとしてapplyすることです。storageは
activateした最大generationを保持し、再activationはそれより大きいgenerationだけを受理します。
process restartをまたぐgeneration/key履歴は持たず、M1はprocess起動ごとに新規開始します。

### worker tick（`ruster-runtime`）

`ruster-runtime`の`FullServicePublication`は、具体的なowned publicationやparserを持たず、
candidateのall-or-nothing適用とactive full-service viewの借用だけを抽象化します。
candidate rejectは旧active viewを失効させず、そのtickのdata phaseを旧generationで継続します。
candidateがある場合だけ、runtimeはpacket backendの`PublicationQuiescence`を先に呼びます。
backendはunfinished RX/generated batch、terminal action未完了のleased RX/generated slot、
accepted TX completion待ちをboundedな所有状態から検査し、成功時はexact `&mut backend`を内包
するsealed、move-only、`!Send + !Sync`のGAT guardを返します。batch finish/dropはlive leaseを
推測してclearせず、terminal commit/recycle/consume/cancel/abandonだけがlease countを減らします。
runtimeはopaqueな`I::Guard<'_>`をcandidateと一緒にpublicationへmoveし、publication callが戻って
guardがdropされた後にだけactive viewとpacket I/Oへ進みます。quiescence failureはcandidateを
publicationへ渡さないtyped `Deferred`です。backendはerrorごとに`ContinueOldIo`、`SkipIo`、
`Stop`を返し、未知errorのdefaultは`SkipIo`です。Simのaccepted TX completion待ちだけは旧active
generationでI/Oを継続し、unfinished batchまたはterminal未完了leaseは旧activeを保持したまま
RX、resolution timer、failure dispatch、generated ARP/ICMPの全data phaseをskipします。
candidateなしのtickはguardを取得せず、backendのboundedなread-only current-I/O dispositionを
確認します。`SkipIo`はbackendがconflicting ownershipを明示回収するまで継続し、`Stop`はその
backend valueの寿命中terminalです。したがってforgotten batch/leaseのsticky busyは次tickにも
全data phaseを抑止します。Simのaccepted TX output queueを明示completionする有限modelは、
AF_XDP CQ drainやnative backend quiescenceを実装済みとは主張しません。
active viewがなければRXを開始せず、残りの全phaseを`NoActivePublication`としてtyped skipします。
一度借用したactive viewはtick終了まで同一generationであり、RXにはUDP/TCP NAT44、firewall、
resolution、generated ICMP captureのfull composition wrapperだけを使用します。
`active`はO(1)のsteady-tick borrowであり、semantic validation、fingerprint/hash計算、slice scan、
allocationを繰り返しません。これらはcandidate構築・publicationのcold pathで完了します。
validated snapshotとNAT/firewall config identityは`Copy`値としてviewへ渡し、publication
adapterに一時値への参照を返させません。UDP/TCP NAT44とfirewallは各configと対応するoptional
runtimeをservice-specific nested viewで対にし、resolutionとgenerated ICMP runtimeは直接
borrowします。view自身の`NonZeroU64` generationがtick内のcoherent publication identityです。
snapshot内sliceとfirewall rulesのborrowはactive adapter borrowと同じview lifetimeへ短縮し、
mutable runtime storageもそのtick-local viewだけがexclusiveにreborrowします。
`FullServiceView`自身は`Copy`/`Clone`にせず、viewをtick外へescapeさせません。このsnapshot
by-value化、generation追加、flat config/runtime fieldのnested化はpre-1.0 APIの意図したsource
breakであり、runtime borrowはprivate fieldにしたためdownstream adapterは`FullServiceView::new`と
各`*ServiceView::new`でviewを構築します。`active`/`publish_candidate`は`run_tick`だけが作る
`PublicationTick`を要求します。現行core full wrapperは3 configを
必須とするため、service pair全体の不在表現はoptional-config composition seamを追加する後続
作業です。64-bit buildではsnapshot 144 bytes、Firewall config 160 bytes、UDP/TCP NAT configは
各112 bytesで、full view全体を576 bytes以下に保ちます。1024 tickの回帰fixtureは各tickの
`active`呼出しがexactly once、heap allocationとvalidation/fingerprint/hash/slice scan再実行が
zeroであることを固定します。

`TickBudgets`はRX packet数、resolution timer scan、failure dispatch scan、generated ARP action、
generated ICMPv4 actionを独立に制限します。RX batchはlexical scopeでwrapperへmoveし、
`finish`後にだけgenerated I/Oを再borrowします。generated allocation/build/finish errorは同じ
tickで同じpending actionを再試行せず、そのphaseを一回で停止します。accounting invariant違反は
backend contract failureとして以後のgenerated phaseを停止します。固定サイズreportとphase
sentinel traceは、RX errorとgenerated error、clock regression、zero/exact budgetを区別します。
RX receive/finish error後もtimerとfailure dispatchは進めますが、同tickのgenerated I/Oは
開始しません。timer clock regressionはfailure dispatchを含む全後続phaseをskipし、failure
dispatchまたはgenerated ARPのclock regressionも全後続generated phaseをskipします。generated
ARPの`Unavailable` allocationだけは独立したICMP generated sessionの試行を許し、build/finish
errorは許しません。accounting違反reportはbackendが返した生counterを保持し、runtime側で
帳尻を推測・修復しません。
TX accepted/submittedはdescriptor publicationであってwire deliveryやcompletion queue返却では
ありません。runtime packet pathはheap allocationと共有同期を行いません。

### observability（R15）

R15 observabilityの`TickObserver`は`run_tick`の`trace`引数としてstatic dispatchで渡します。
tick中はdrop/consume eventごとに固定配列の一要素とphase skipごとに一counterをsaturating加算
するだけで、format、allocation、lockを行いません。`DropReason`はstableな`repr(u16)`
discriminantで直接indexし、表外のreasonは`UNCLASSIFIED`に数えて失いません。表の完全性は
core側の`DropReason::ALL`/`ConsumeReason::ALL`（宣言scan testとconst assertion）が保証し、
出力は全reasonをzero込みで固定順に並べます。cold sideは
`run_tick`が返した`TickReport`を`observe_tick`でO(1)集計し、注入された`MonotonicMillis`だけから
health（last tick/last successful tick、RX/TX progress、入力時刻regressionとruntime報告の
clock regression、連続backend I/O failure、quiescence deferral、sticky `Stop`）を導きます。
health時刻は単調high-waterで後退しません。staleness（last tickがpolicyより古い）はDegradedより
優先し、activation前のtickはDegradedです。apply結果は`PublicationOutcome`から、flush数は
core publication reportから作る`ApplyFlushCounts`を`record_apply_flush`で一度だけ添付するので、
runtimeはcontrolへ依存しません。apply tickごとに呼ぶcontractで、欠落は
`publications_applied - apply_flushes_recorded`として見えます。各runtimeの累積counterは
`ServiceCounters::capture`でpublication ownerのread-only accessorからcopyします。
`BackendStats`と`ObservableFields`語彙は`ruster-core`に置き（runtimeはre-export）、backendは
coreだけに依存してstatic dispatchで固定statsを提供します。`SimIo`はqueue/lease占有と
pending RX/TXのhigh-watermarkを返します。snapshotは`Copy`の固定サイズ値で、
`ObservableFields`がmapなしの固定順`(section, key, value)`を訪問し、`FieldsDisplay`はcold side
だけで`section.key=value`行へ描画します。`ruster-sim-scenario`のdriverが同じ訪問順を
canonical JSONL `ruster-run-sim/v1`の`final` eventへ描画し、`ruster run-sim`がそのままstdoutへ出します。

state table占有（OBS-015、M2 S8）はcoreの各runtimeがslot書込点でO(1)に保守する
`TableOccupancy`（`occupied`/`high_water`/`capacity`）で、NAT44 UDP mapping/peer、TCP mapping/
session/external-inbound session、firewall state、ICMPv4 error limiter stateが対象です。
`occupied`はreclaim・削除・flushされていない割当済みslot数です。expiryはlazyなので期限切れでも
未回収のslotは数え、live stateの上界です（NAT44とlimiterは期限切れslotをin-placeで再利用するため
generation内では減らず、firewallはprobe cleanup/sweepの削除で減る）。`high_water`はgeneration内で
単調で、flushするpublicationでcountと共にzeroへ戻り、同generationのreconcileでは保持します。
per-tick scanをしない理由は、lazy expiryのtableでexact live数を得るにはexpiry順indexか全scanが
必要で、前者はrefreshごとのhot path workを、後者はtable長に比例するtick workを足すためです
（live数はOBS-027としてdeferred）。runtimeは毎tick後に`ServiceOccupancy::capture`（4 runtimeの
accessor copy）を`TickObserver::record_occupancy`へ渡し、最後の値と、flushを越える`peak`
（全sampleの`high_water`の最大）、`samples`を保持します。flushはtick先頭のpublication phaseだけで
起きるため、毎tick後のsampleでpeakはexactです。snapshotは`flushed.*`の後に`occupancy.*`
29 keyを常に出します。resolution/action/audit high-watermark（OBS-017）とnative ring
saturation（OBS-018）はcore accessorまたはnative backend実装が必要なため未実装です。

### deterministic scenario driver（`ruster-sim-scenario`）

`ruster-sim-scenario`のdriverはscenarioと初期configを読み、process唯一の
`PublicationSequencer`（scenario seed由来のsim専用key source）でgeneration 1を作り、
`FullServiceStorage`上の`ActivePublication<SimIo>`を`run_tick`で駆動します。時刻は
scenarioの注入`MonotonicMillis`だけで、毎tick後に全TXを`pop_tx`で完了させるためtick境界は
常にquiescentです。`apply`はfileをparse/validateし、失敗（parse、validate、M1 service bridge）は
tickなしの`invalid`、成功時はsequencerがgenerationを消費してcandidateを現在時刻の1 tickの
publication phaseへ渡し、そのtickの結果を`applied`または`restart-required`として扱います。
restart-requiredでもstorageは作り直さず旧generationで継続します（M1 run-simの範囲）。
`expect`は前回expect以降のTX（egress、exact bytes）、累積drop/consume数、generationを照合し、
最初の差分をtyped errorで返します。参照fileのread失敗はrunのI/O failure（CLIはexit 1）で、
読めたがparse/validate/bridgeに失敗したfileはscenario内の`invalid` rejectです。`hold`後は
`SimRun::idle_tick`で単調な注入時刻のidle tickを続けられます。出力はfield順固定の手書きJSONLで、wall clock、map順、
hash key、seedを含みません。step単位（tickは1回ずつ）の`SimRun::step`で呼出し側がtick間に
停止flagを確認できます。full compositionはfirewall必須のため、route missは上記のegress-free
policy評価でpermitされた場合だけDestination Unreachable Networkを生成し、それ以外はsilentな
`FIREWALL_ROUTE_UNAVAILABLE`です（M1 goldenはv1でsilent、egress `Any`のrule 40を持つv2でType 3/
Code 0を検証）。

### `ruster` CLI（`ruster-cli`）

`ruster-cli`はcold sideだけのbinaryで、data-plane/I/O crateへcodeを追加しません。
`validate`/`plan`はconfigを`run-sim`と同じlimitでparse/validateし、どちらも（planは両document
とも）捨てるcandidateを作ってM1 service bridgeまで確認します（key値は出力しない）。`plan`は
`ApplyPlan::between`をfield順固定のtextへ描画します。interface name/deviceはconfig validationで
`[A-Za-z0-9._-]`かつ15 bytes以下に制限され、planはさらにそれ以外のbyteを`\xNN`へescapeするため
labelから行の偽造や制御文字出力はできません。`run-sim`は`SimRun::step`の各呼出し前に
停止flagを読み、signalはtick境界でだけ効きます。shutdownは「stepを止める→
`SimRun::check_quiescence`（backendの`try_publication_quiescence`）→`final` event」の順で、
quiescenceが崩れていればexit 1です。注入済みで未受信のframeはleaseではなく`pending_rx`として
`final`に出ます。signal handlerは`signal(2)`で登録し、static `AtomicBool`へのrelaxed store
だけを行います（lock-free atomic storeはasync-signal-safe）。handlerは戻しません。SIGTERMは常に登録し、SIGINTは慣習どおり
起動時にSIG_IGNを継承していれば（job controlなしの`cmd &`など）ignoreのまま残します（SIG_IGNを
先に設定して旧dispositionを調べるため、調査中のSIGINTはignoreされる）。M2 S10bから`ruster run`だけが
SIGHUPを登録し（継承したSIG_IGNでも登録する。daemonではreload要求）、handlerは`RELOAD`へのrelaxed
storeだけです。`run-sim`はSIGHUPを扱わず、他のsignalも扱いません。Linux以外ではhandlerを登録しません。M2 S10aでhandlerは`STOP.swap(true)`が既に`true`
なら`FORCE`もstoreするようになり（二回目のsignal、`ruster run`のforced teardown）、`run-sim`は
`STOP`だけを読むので挙動は変わりません。`unsafe`はprivate `signal` moduleと`ruster run`の
rtnetlink address dump（`run::netlink`）だけで、crateは`#![deny(unsafe_code)]`です。

### M1の範囲と既知の差分

- backendは`SimIo`だけです。`ruster run`、AF_PACKET/AF_XDPのlive constructor、実NIC/netns
  E2Eはありません（M2）。AF_XDPの`[backend]` configはvalidate/planできますが（M2 S9）、
  それを使うbackendはまだ無く、`run-sim`は拒否します。run-simの結果を性能値として扱いません（simは注入frameごとに
  cold側`Vec<u8>`を確保します）。
- firewall有効時のroute missは、egress-free評価で許可されegress依存のNAT gateにも当たらない
  packetだけにDestination Unreachable Networkを返します。route撤去後の既存flowのpacketは
  silentです（RFC 1812 §5.2.7.1からのtracked deviation、FW-025。全reloadがflowをflushするため
  参照できるstateがなく、answerするとroute oracleになるため2026-11-01の再評価でも維持）。
- router-originated ICMPv4の4 class（Echo Reply、Time Exceeded、Network/Host Unreachable）は
  default onで、classごとにoffにできます（上記inventory）。
- restart-requiredのapplyはrun-sim内でrejectとして報告し、storageを作り直しません（SIM-016）。
  generation/key履歴はprocess内だけです。
- NAT/FW占有は割当済みslot数とgeneration内high-water（OBS-015）で、TTL未満のlive数は出しません
  （OBS-027）。resolution/action/audit high-watermarkと、runtimeへ接続したnative ring saturationは
  未実装です（OBS-017/018。AF_XDP RX/Fill engine自身のcounterはM2 S3のXDP-064以降）。

## backend progression

`ruster-io-sim`はRXとgenerated TXのFIFO、budget、max frame、allocation exhaustion、
cancel/abandon、partial TX/reject、finish errorを決定的に実装します。captureは
`FrameOrigin`でRXとgeneratedを区別します。RX/生成の`Vec<u8>`そのものをTX/dropへmoveし、
packet bytesをcloneしません。次の実I/O backendも同じlease contractを実装し、
backend固有pointerをcoreへ漏らしません。

以下のAF_PACKET/AF_XDPはproduction backendではありません。AF_PACKETはscripted syscall上で
copy `PacketIo` conformanceを通した段階（IO-012）、AF_XDPはownership model、native
ABI/ring/syscall scaffold、session/attach、RX/Fill engine（M2 S3）の段階で、どちらも`ruster` CLIからは使えず、実NIC動作やthroughputを
主張しません。

### AF_PACKET checked combined-mapping substrate

`ruster-io-afpacket`のAP0は、64-bit Linuxのstrict TPACKET_V3 profileについて
socket option、single combined mmap、bind activation、RX block/packet descriptor、
RX/TX ownership modelを固定します。AP1-0はpacket処理を接続せず、このresource境界を
後続RX/TX state machineが安全に所有できる形へ限定して拡張します。

combined mappingはRXをoffset zero、TXを`rx.map_len()`直後に置きます。cold validationは
RX/TX overlap、間隙、`usize`加算overflow、exact combined length、16-byteのTX relative
alignmentを検証します。mapping取得後はactual base addressを加えたRX/TX先頭alignmentと
各ring内のrelative access rangeを再検証し、RX accessがTX extentへ、またはその逆へ
越境するpointerを生成しません。mapping ownerは分割されず一つのresourceに残り、field drop順を
mapping、socketに固定するため、通常終了とbind失敗のどちらもunmapがcloseより先です。

syscall境界はprivate genericによるstatic dispatchです。productionのzero-sized `LinuxOps`は
既存FFIを直接呼び、test専用`ScriptedOps`はsetup各段のerrnoとcleanup順をNIC/rootなしで
注入します。trait object、runtime backend selection、共有lockは追加しません。
validated portごとに、一つのRX blockが取り得る最大packet metadataとTX全frame metadataを
socket取得前にfallibleなcold pathで固定長確保します。確保後の反復accessはallocationせず、
storage addressも変わりません。

AP1-TXのprivate engineはfixed `IfId` tableからportをO(1)選択し、各portのproducer headだけを
確認します。TX statusをAcquireで読む前にframeをreserveせず、unknown interface、宣言最大長超過、
AVAILABLE以外、未知status、generation枯渇はpayloadをcopyせず拒否します。受理時だけdistinctな
backend-owned TX mmap frameへ一度だけcopy(AP2以降は`copy_nonoverlapping`)し、`tp_next_offset=0`、
`tp_snaplen=tp_len=payload length`のV3 headerを構築してSEND_REQUESTをRelease publishします。
固定metadataのownershipとchecked generationはframe再利用cycleを区別します。

completionは固定budget内でFIFO headだけを走査し、SEND_REQUESTまたはSENDINGを見た時点で後続を
skipせず停止します。AVAILABLEはSENDINGを観測しなかった直接遷移も含め一度だけreclaimし、
WRONG_FORMATは一度だけAVAILABLEへrecycleします。batchは固定長epoch/scratchでpublish済みportを
deduplicateし、明示finishとDropのどちらも各endpointへ
`send(fd, NULL, 0, MSG_DONTWAIT)`を最大一回だけ試し、失敗をretryしません。kick失敗はすでに
publishしたsubmissionをrejectへ巻き戻さずin-flightに残します。hot submit/completion/reuseは
heap allocationしません。

AP1-RXのprivate engineは、portごとにbatchから独立したpersistent cursorをresource側に持ちます。
batchはpacket、block status read、descriptor visitの独立budgetで進みます。packet budgetがzeroなら
何もしません。新しいhead blockの観測にはstatus readとdescriptor visitの両方の残りが必要で、
どちらかがzeroならstatus read、header検証、generation更新を一切行いません。head blockのstatusは
`AtomicU32`のAcquire loadで一度だけ読み、KERNELなら後続blockをskipせずring emptyとして止まります。
USERなら固定per-block metadataのchecked nonzero generationを進めてblock headerを検証し、
descriptorを一つずつchain linkに沿って検証します。検証進捗とper-packet data rangeは固定metadataへ
保存するため、budgetで中断したbatchを捨てても次のbatchは正確に同じdescriptorから再開し、既検証
descriptorを再走査しません。blockのpacketはchain全体の検証が終わるまで一つも公開しません。
status以外のdescriptor readはAcquire観測後のRX extent内checked range、volatile accessです。

公開するpacketはmmap上のexact data rangeを指すzero-copy leaseで、portを排他的にborrowします。
従ってleaseが生きている間はsibling leaseもblock returnも型上起こりません。packetは明示release、
drop(panic unwind中を含む)、`mem::forget`後にpacket budgetを持つ次のcursor stepのいずれかで
一度だけterminalになり、最後のpacketがterminalになった時点でだけTP_STATUS_KERNELを`AtomicU32`の
Release storeで返し、ring順に次blockへ進みます。古いgenerationやpacket indexのcompletionは、
同じblockが新generationでDelivering中でもstale tokenとして拒否します。batch reportはeventが
起きたbatchへ計上します。`released`は明示release、`dropped`はdrop、`abandoned_leaks`はforget
されたleaseを後続batchが確定した数で、同じcompletionを二重に数えません。forgetされた最後の
packetによるblock returnも確定したbatchへ計上します。

malformed inputのrecovery policyはfail closedです。KERNELでもUSER bit付きでもないstatusと
generation枯渇はkernel所有の可能性があるblockへ書かずcursorを保持してbatchをhaltします。
同じ条件が続く間のhaltはpollごとではなくevent一回として`BackendStats`へ数えます。
block header不正、またはdescriptor自身の配置/next linkが不安全なchainはUSER観測済みなので、
どのpacketも公開せず、後続descriptorも読まずにblock全体を即kernelへ返します。linkが安全で
MAC/network offset、snapshot、data range、truncation、宣言最大frame超過、kernelがcaptured bytes
から外したVLAN offload tagのいずれかが不正なpacketだけを個別terminal faultにし、siblingは配送
します。検証済みblockをownership modelへ反映できない場合は内部不変条件違反として、blockを返さず
cursorも動かさずにhaltします。block return storeの失敗ではpacketはterminalのまま残り、次stepが
returnを再試行します。これらmapping失敗経路はchecked geometry上productionでは到達しないため、
test専用のfault injection seamで検証します。counterは既存の固定saturating `BackendStats`だけを
使い、正常、packet fault、block rejectのsteady経路はheap allocationしません。

strict profileはGRO/LROの無効化を前提にします。GSO superframeはTruncatedまたはOversize faultとして
dropされます。kernelがVLAN tagを外して渡したtagged frameも同様に拒否します。

AP1-RXは`PacketDescriptor::validate`と`validate_v3_block_chain`のerror優先順位を変更しました。
chain link(packet offset、header bounds、next offset)のerrorはMAC/network offset、snapshot、
data rangeのerrorより先に返ります。例えばmac=80かつnext=148のdescriptorは、以前の
`EthernetMacOffsetInvalid`ではなく`NextPacketOffsetNotAligned`になります。

AP1-RXは`PacketIo` lease、RXからTXへのadapter接続、poll、live stats/cleanupを実装しません。
persistent halt時のescalation/port再初期化policyと`sll_pkttype` policyもdeferredです。

AP2はportごとのRX cursor/metadata、TX producer/completion state、combined mappingを同じ
`PacketRingResources`に置き、全portを一つのprivate `AfPacketEngine`が所有します。engineは
core `PacketIo`をcopy backendとして実装します。`receive`のbatchはengine全体を排他borrowし、
各portのpersistent RX cursorをround-robinで進めます。packet budgetはbatch共通、RX status
read/descriptor visit budgetはport単位、TX submit status read budgetはbatch共通です。
次batchの開始portはpacket budgetを使い切ったportの次へ回ります。leaseはingress portの
RX extent内にある検証済みpacketのzero-copy viewです。mappingは`PROT_READ|PROT_WRITE`の
`MAP_SHARED`で、USER blockはTP_STATUS_KERNELを書き戻すまでuserspace所有なので、coreは
`bytes_mut`でin-place rewriteできます。

`commit(egress)`はO(1) IfId lookup、宣言最大長、TX status read budget、egress producer headの
Acquire status、frame ownershipを先に検査し、拒否時はframeをreserveもcopyもしません。受理時だけ
RX packetからegress portのTX frameへ一度`copy_nonoverlapping`し、SEND_REQUESTをRelease
publishします。egressはingress自身でもよく(hairpin)、その後にRX packetをterminalにします。
leaseはbatch経由でengineをborrowするため、lease中に他のleaseやport stateへのaccessは型上
存在しません。core向け`&mut [u8]`は`bytes_mut(&mut self)`経由だけで、`complete(self)`が
slotをconsumeするためcopy開始前に終わっています。copy sourceは`&[u8]`ではなくraw
`(NonNull<u8>, len)`の`TxPayload`として`&mut` engine呼び出しへ渡すので、同一portのsharedと
exclusive borrowを同時に作りません。sourceはingress RX extent、destinationはegress TX extent
内と`ring_address`で証明済みで、同一mapping内ではchecked `CombinedRingExtents`がRXを
`[0, rx_len)`、TXを`[rx_len, combined_len)`に固定し、port間はmappingが別なので、両rangeは
重なりません。`recycle`/`consume`/abandonはTXに触れずRX packetを完了します。

`finish`の`BatchCompletion`は、`tx_requested`を全Transmit、`tx_accepted`をfinish前に
publishしたSEND_REQUEST(kick失敗でも降格しない)、`tx_rejected`をunknown egress、oversize、
TX budget枯渇、ring full、fault-class reject(未知status、generation枯渇、mapping/ownership
違反)、`recycled`をRecycle/Consume/LeaseAbandonedとして`invariants_hold`を常に満たします。
検証faultのRX packetはleaseされないため`recycled`に入らずport `BackendStats`だけに計上し、
`mem::forget`されたleaseは後続cursor stepが一度だけabandonとして確定します。`error`は
batch中最初のbackend fault(新たに観測したport単位のRX halt、fault-class TX reject、最初の
kick失敗)で、通常のrejectはerrorにしません。

RX haltはedge-triggeredです。haltは、`BackendStats`へ一回だけ数える既存のsticky halt event
identityを使い、そのeventを最初に観測したbatchでだけ`error`になります。同じ条件が続く間の
後続batchはhalt中portをerrorなしでskipし、別のhalt、またはportが進捗した後の再発は新しい
eventとして再度報告します。runtimeはfinish errorを`BackendIoFailure`として扱い、そのtickの
generated ARP/ICMPを全portでskipするため、level-triggeredでは一つのhalt portが健全なportを
無期限にstarveさせます。halt状態は`BackendStats`で引き続き観測でき、health報告とescalationは
R15/AP3へdeferredです。

`PacketIo`単体はTX completionを回収しません。受理frameを戻すのはengineのbounded
`scan_completions`だけで、現在これを呼ぶのはtestだけです。従って各egress TX ringは
`frame_count`回の受理で尽き、以降のcommitはring fullの通常rejectとして`error == None`の
まま拒否されます。AP3がcompletion schedulingを追加するまでpublic constructorを公開しては
なりません。`finish`とDropは受理portごとに`send(MSG_DONTWAIT)`を最大
一回だけ試しretryしません。hot pathはheap allocation、lock、trait objectを使いません。

IO-012の証跡として、reusable `ruster-io-conformance` RX-to-distinct-TX copy suiteを
private static-dispatchの`ConformanceOps`(scripted mmap/kick)上の実engineで実行します。
pass-through decoratorはscripted ring/syscall状態から、lease address、実TX ringの
SEND_REQUEST遷移、frame header/payload、新規publish以外の全TX frameが全byte不変であること
(reject時copyなしの独立証拠)、RX block statusのKERNEL化(各engine呼び出し後に全pending block
を確認)、syscall logを観測し、報告したgenerationをengine metadataと照合します。per-block scan
counter、RX/TX status read・descriptor counter、copy回数/byte数はtest専用`PortProbe`由来で、
copy回数は新規publish frame数と、block return数はstatus wordと照合します。AF_PACKETはportごとにTX ringが一つなのでsuiteのqueue番号はring labelであり、
FIFO producer/one-block RX ringのためpreferred frame/block指定は選択ではなくassertです
(TX reuse caseはone-frame TX ringで実行)。RX work counterは全caseのingressであるLAN portの
値です。TX storageを予約しtokenを付けてからrejectする前提の3 case(partial reject、finish
error、rejected TX ABA)はAF_PACKETにreserve-then-reject経路が無いため非適用とします。
rejected TX ABAが守る性質は、rejectがframeをreserveせずgenerationを進めないことから自明に
成り立ち、AP1-TXの`tx_status_validation_precedes_reserve_and_rejected_packets_copy_nothing`、
`settle()`のgeneration/metadata照合、上記byte不変checkで検証します。代わりにring full
によるpartial reject、kick失敗のfinish errorとsingle kick、RX halt/TX faultのerror mapping、
hairpin byte、round-robin、forget、steady allocation zeroをAF_PACKET固有testで検証します。
poll統合、TX completionのscheduling、live stats/cleanup、public constructorはAP3、実NIC/netns
E2Eと性能はR14以降へdeferredです。AP1-TXのstatus pathはvolatileとfenceのままで、RXの
`AtomicU32`化とは共有helperを持たないためfollow-upです。

`ruster-io-xdp`の最初のsliceは、native AF_XDP backendではなく、全targetでcompileできる
pure-Rust ownership/ring modelです。socket、native ring、libxdp FFI、XDP program、core
`PacketIo` adapterを持たず、`unsafe`をcrate全体で禁止します。従ってIO-009のreal generated
backendはdeferredのままです。

UMEMは固定長frameの集合として表現し、descriptor addressはUMEM相対値です。
`FrameId`はaddressをframe sizeで正規化したindexだけをcanonical identityとし、packet data
offsetやvirtual addressをidentityに使いません。layoutはnonzero frame count、power-of-two
frame size、frameより小さいheadroomをpublication前に検証します。descriptorはoptions zeroの
single-buffer profileに限定し、nonzero visible length、UMEM範囲、headroom、同一frame内の
`addr + len`をchecked arithmeticで検証してからledgerへ渡します。

control planeはUMEM ownership lifetimeごとにnonzero 128-bit unique inputをcold pathで生成し、
move-onlyな`UmemDomainId`としてlayoutへ渡します。この値はpointer、公開counter、ZST identity
から導出せず、Debugでもredactします。同じ値を別のlive ledger、process restart後、UMEM
recreate後に再利用してはなりません。layoutはledgerへconsumeされ、domainをin-place
reconcileするAPIは持ちません。UMEMまたはledgerを作り直す場合は必ず新domainで全frameを
Free/generation zeroから作り、旧token/descriptorをforeign domainとして拒否します。
unique inputを知るconstructor callerはtrusted control-plane境界で、token consumerには値を
公開しません。`FrameToken`と内部domain identityは`Hash`を実装しません。domainを
caller-controlled `Hasher`へ渡さないため、token holderはHash経由で値を回収して
`UmemDomainId`を再構成できません。

各frameはledgerだけが発行できる
`(hidden UMEM domain, FrameId, NonZeroU64 generation)` tokenで一ownership cycleを識別します。
validated descriptorも同じhidden domainを保持します。token/descriptorはring state間で
allocationなしに渡すため`Copy`ですが、copyから新しいownershipやdomain identityは生まれません。
最初の有効なstate transition後、同じtokenの別copyはexact state checkで拒否されます。別ledgerの
同じFrameId/generation tokenと、別layoutで検証した同じFrameId descriptorは、entry/counterを
変更する前にtyped foreign-domain errorとなります。

generationはchecked incrementだけで進め、`u64::MAX`の次へwrapせず、そのframeを
`Quarantined`へ移して永久に通常reuseから外します。ledgerはFree、fill予約/kernel所有、
RX available、core lease、pending/reserved/kernel TX、completion available、quarantineの
exact partitionを持ちます。通常遷移はframe indexによるO(1) lookupと二つのstate counter更新
だけです。全entry、domain、token identity、generation、descriptor、counterを再計算する
`deep_audit`は明示的なcold pathです。stale token、wrong-state token、tokenと異なるframeへ
canonicalizeされたdescriptorもentryとcounterを変更せずtyped errorで拒否します。

ledgerはUMEMの全frame partitionを一workerが所有するため`!Send + !Sync`です。このpure modelは
live byte sliceを貸し出しません。native RX/Fill engine（下の「AF_XDP RX/Fill engine」）はledgerを
engineに閉じ込めて同じworker localityを維持します。別設計にする場合は明示的ownership handoffを
追加しなければなりません。

### pure-Rust AF_XDP ring/fake model

physical endpoint observationはadapterがinterface/queue/ring kindを自己申告して作る値では
ありません。finite fakeが所有する`PhysicalEndpoint`のborrowed `EndpointHandle`だけが
`RingObservation`を作れ、public constructorはありません。observationはendpoint identity、
visibleなinterface index/queue、Fill/RX/TX/Completion kindをbindします。別endpointまたは
別ring observationでsealされたsubmissionは、slot/cursor不変の`WrongRing`です。fake endpoint
identityはcold pathのnonzero unique inputをconsumeし、Debugではredactします。native endpoint
handleの作成は後続sliceです。

`SpscRing<T, N>`はinline `[Option<ObservedSubmission<T>>; N]`だけを所有し、`N`はnonzero
power-of-twoかつ`u32` representableでなければなりません。producer/consumer cursorは
wrapping `u32`、occupancyは`producer.wrapping_sub(consumer) <= N`です。logical cursorから
physical slotへの変換は`cursor & (N - 1)`で、wrap前後もFIFOを維持します。hot reserve、
write、submit、acquire、peek、consume、cancelはheap allocation、shared lock、packet clone、
packet単位Stringを使いません。

producerはexact lengthをreserveし、各offsetを一度だけwriteした後でrange全体を
`release_submit`します。writeはcursorをpublishせず、wrong ring、duplicate offset、
range外offset、incomplete submitをtyped errorにします。unreleased reservationのDropと
explicit cancelは書いたunpublished slotをすべてclearし、producer cursorを変えません。
consumerはpublished rangeをacquireしてpeekし、`release_consume`で全slotを検証・clearしてから
consumer cursorを進めます。Dropとexplicit cancelはslot/cursor不変です。Rust modelは
`&mut` exclusionで逐次実行するためatomicをまだ持ちませんが、native mappingの順序契約は
descriptor write → Release producer、Acquire producer → descriptor read、
read完了 → Release consumer、Acquire consumer → slot reuseです。

`FakeKernel<RING_SIZE, FRAME_COUNT>`は四ringと単一のauthoritative `FrameLedger`を所有します。
constructorはledgerをconsumeし、そのUMEM domainとexact frame countへfake全体をbindします。
callerはraw `FrameToken`/`RingDescriptor`をFill/TX ringへ投入できません。Fillは
`FillReservation`、TXは`TxReservation`というledger stateから発行した用途別・move-only・
public constructorなしのcapabilityだけをpublishできます。kernel側の次段もring consumeから
得た`ConsumedFill`/`ConsumedTx`だけを受け取ります。四capabilityはfakeを排他的にborrowする
guardです。未解決のFill/TX reservationをDropするとそれぞれFree/PendingTxへrollbackし、
consumed Fill/TX guardは元ringのconsumer acquisitionを次段完了まで保持します。Dropは
consumer cursor不変のin-place cancelとなり、descriptorをtailへ再送しません。従って
`[A, B]`のAをDropしても次のacquireはAで、FIFOとexactly-once publicationを同時に保ちます。
panic/early return後も同じkernel ownershipを再取得できます。RX/CQ acquisitionのDropも
同じcursor/state不変のcancelです。

各操作はdescriptor/ring capacityを先に検証してunpublished slotへwriteし、ledger transition
成功後にcursorをpublishします。consumer側はrange全体のledger stateと重複を検証し、ring
consume後に同じrangeのledger transitionを完了します。従ってgenerated leaseのFill利用、
FillReserved tokenのTX利用、別domain capability、同generation二重publish、invalid descriptorは
ring cursorとledger partitionを両方不変に保ち、正しいownerがretryできます。Fill publication
→ kernel Fill consume → RX publication → application lease → TX stage/reserve/publication
→ kernel TX consume → Completion publication → recycleの全段でledger countersとdeep auditが
frame partition conservationを検証します。fakeのhot operationは四ringのinline storageと
構築時だけallocateするledgerを使い、operation単位のallocationはありません。
非TX leaseは明示recycleでき、PendingTxはleaseへrollback後にrecycleできます。lifecycle testの
終端は四ringすべてempty、全frame Free、deep audit成功を要求します。

fakeはengine、`PacketIo` adapter、socket、FFI、XDP attach、wakeup/pollを実装せず、
token/domain constructorもX00A ledger/control-plane境界から移しません。

### native AF_XDP ABI and borrowed ring scaffold

`ruster-io-xdp-native`のC0 sliceは、Linux v6.8
`include/uapi/linux/if_xdp.h`を明示profileとして、将来のnative resource取得より前に必要な
C layoutとcold validationだけを固定します。`sockaddr_xdp`、ring offset/mmap offsets、
UMEM registration、statistics、negotiated options、RX/TX descriptorのsize、alignment、
field offsetとsocket option/mmap offset定数をdependencyなしの`repr(C)`型として保持します。
C0のABI/config moduleはFFI call、socket、mmap、pointer access、libxdp linkを行わず、
`unsafe`をdenyします。従ってnative backend、実kernel互換、packet送受信、zero-copy性能は
まだ主張しません。

initial profileのbind flagは`XDP_USE_NEED_WAKEUP`を必須とし、automatic、copy required、
zero-copy requiredを区別します。`XDP_SHARED_UMEM`は許可しますが、copyとzero-copyの同時指定、
scatter/gather、unknown bitをresource取得前にtyped rejectします。UMEMはunaligned flagなしの
exact 2048-byteまたは4096-byte chunkだけに限定します。他のpower-of-two sizeも、page sizeと
platform条件を別途検証する後続sliceまではrejectします。Linux v6.8
`include/uapi/linux/bpf.h`の`XDP_PACKET_HEADROOM=256`をuser-configured UMEM headroomへ
checked加算し、少なくとも1-byteのvisible packet capacityが残らなければtyped rejectします。
metadataなし、software checksum指定なし、RX/generated frame exact partitionを要求します。
四ring capacityはnonzero power-of-twoです。RX/TX descriptorはsingle-bufferのoptions zeroだけを
許可します。

kernelが将来`XDP_MMAP_OFFSETS`で返す各ring offsetは、producer、consumer、flags、
descriptor領域のalignment、checked extent、process `usize`変換、相互非overlapを検証してから
minimum mmap byte lengthへ変換します。この計算はmemoryをaccessせず、offset overflowや
aliasするlayoutをtyped errorにします。C0/C1のpure ABI/ring profileは64-bit Linuxを対象とし、
non-Linuxと未reviewのpointer widthはtyped unsupportedです。architecture依存定数を持つC2A
syscall seamは、後述する別のnarrower x86_64 boundaryを使います。

C1 sliceはOS mappingを作成せず、caller-owned `&mut [u8]`をmapping lifetime全体で
排他的にborrowします。C0 layout検証後にactual base addressを加え、minimum extentと
producer/consumer/flags/descriptorの実address alignmentを再検証します。public raw pointer
constructorはなく、kernel-mutated memoryへのreferenceもAPIから返しません。pointer、
`AtomicU32`、volatile descriptor accessはprivateな`native_unsafe/mmap.rs`と
`native_unsafe/ring_mem.rs`だけに閉じ、各unsafe blockはchecked extent、alignment、
value validity、SPSC ownershipの根拠を記載します。

application-owned roleは`FillProducer<u64>`相当、`TxProducer<XdpDescriptor>`相当、
`RxConsumer<XdpDescriptor>`相当、`CompletionConsumer<u64>`相当の四つを別のpublic typeで
表します。実際の型はelement parameterを公開せず、foreign elementのwriteをcompile時に
拒否します。producer reservationとconsumer acquisitionはring viewを排他的にborrowし、
heap allocation、shared `Mutex`、packet clone、packet単位`String`、`dyn PacketIo`を
導入しません。範囲内を順番にwrite/readするためbitmapも不要です。

cursorはpower-of-two capacityとwrapping `u32`差分でexact full/emptyを判定し、差分が
capacityを超えればcorrupt cursorとしてcursor不変でrejectします。producerはconsumerを
Acquire loadし、全descriptorをvolatile writeした後だけproducerをRelease storeします。
Drop、明示cancel、incomplete submitはproducer cursorを変更せず、未publishの古いslot byteは
kernelから不可視です。consumerはproducerをAcquire loadしてからdescriptorをcopy readし、
全rangeをreadした後だけconsumerをRelease storeします。Drop、cancel、incomplete consumeは
consumer cursor不変です。kernel-mutated descriptorへのlong-lived referenceは生成しません。

producer publication直後にflagsをAcquire loadし、Linux v6.8の
`XDP_RING_NEED_WAKEUP`以外をtyped unsupportedとして返します。flag errorを返す時点でも
descriptorとproducer cursorは既にpublish済みであり、rollbackを意味しません。この順序により
callerはpublication前の古いneed-wakeup観測をkick判断に利用しません。socket fd、ring/UMEMの
OS mmap、UMEM registration、bind、poll/sendto kick、libxdp attach、core `PacketIo` adapterは
後続sliceです。

C2A sliceは後続resource setupだけが使うprivateなx86_64 Linux syscall/RAII seamを追加します。
Linux v6.8 profileの`socket`、`setsockopt`、`getsockopt`、`mmap`、`munmap`、`bind`、
`poll`、`sendto`、`close`をdependencyなしのprivate FFIへ閉じ、sealed genericでstatic
dispatchします。production実装とNIC不要のfinite fakeは同じ境界を使いますが、このsliceに
public resource constructorはなく、packet fast pathへtrait objectやsyscall dispatchを追加
しません。socket作成要求は`SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK`で固定します。
`SOCK_NONBLOCK=0x800`、`SOCK_CLOEXEC=0x80000`、`MAP_ANONYMOUS=0x20`を含む定数と
`socklen_t`/`off_t`/`nfds_t`幅はLinux v6.8 x86_64 UAPI profileとしてcompile-timeとunit testで
固定します。これらが異なるmips64/sparc64等へasm-generic値を誤適用しません。

C0/C1のlayout計算とborrowed ringは従来どおり64-bit Linux profileを維持します。一方、
resource builderが将来公開される場合は別の`ensure_native_syscall_supported`を最初に呼び、
non-Linux、非64-bit、64-bit Linux上の非x86_64をそれぞれtyped rejectしなければなりません。
C2Aのfd owner自身もsocket callより前にこのnarrower checkを実行します。

socket optionとsocket addressの動的byte lengthはnonzeroかつLinux `socklen_t`へ表現可能、
ring mmap offsetは64-bit `off_t`へ表現可能であることをFFI前に検証します。kernelが返した
getsockopt lengthがcaller bufferを超えればtyped rejectします。mmap失敗はexact
`MAP_FAILED`だけであり、address zeroを失敗と取り違えません。fd、mapping address、packet
dataはerrorまたはresourceのDebugへ出しません。

fdとmappingは取得成功後だけRAII ownerへ入り、明示cleanupとDropはresourceをcall前にinactive
化するため、close/munmapがerrorでもretryせず高々一回です。これはclose後に同じ数値へ再利用
されたfdを誤ってcloseすることも防ぎます。finite fakeは各syscallのexact transcript、
argument validation前後、partial failure、reverse cleanup、cleanup failureをroot/NICなしで
検証します。

C2AはUMEM allocation/registration、Fill/Completion/RX/TX ring configuration、
`XDP_MMAP_OFFSETS` query、ring mappingの組立、`sockaddr_xdp` bind transaction、negotiated
mode、wakeup policy、live session、XDP program/XSKMAP、libxdp、core `PacketIo`を実装済みとは
主張しません。これらのresource lifetimeとpacket ownershipは後続sliceで別途検証します。

### native AF_XDP session builder (X00C, M2 S1)

X00Cはvalidated configから一つのsocket（一interface queue）のready ringまでを、上記sealed
seamだけを通る一つのfailure-atomic transactionとして組み立てます。libbpf/libxdpにlinkせず、
Linux v6.8 raw UAPI profile（`if_xdp.h`の`repr(C)` layoutとx86_64 syscall定数）だけを使います。
XDP program/XSKMAP attach（次節X00D、S2）とdatapath engine（S3）は含みません。public APIはx86_64 Linuxだけの
`NativeSession`で、他targetではtypeそのものが存在しません（pure ABI/ring/configはC0/C1どおり）。

入力の`SessionConfig::new(device, queue, bind_flags, rings, umem)`は`ValidatedAfXdpPortV1`の同名
accessorから作ります（native crateはconfig crateへ依存しない）。syscall前にdevice名をLinux
`dev_valid_name`相当（1..=15 byteのprintable ASCII、`/`・`:`・`.`/`..`なし）へ制限して
NUL-padded `IFNAMSIZ` bufferにし、queue idを`MAX_QUEUE_ID`（`u16::MAX`）以下に制限し、
`XDP_SHARED_UMEM`を拒否します（sessionごとに独立UMEM）。queue上限はv6.8 `xsk_bind`が
`xp_assign_dev`へqueue idを`u16`で渡し、65536を黙ってqueue 0へbindするtruncation境界です
（config層はさらに厳しい1023）。

`NativeSession::open`のstep順は固定です。

| # | step | 内容と検証 |
|---|---|---|
| 1 | `InterfaceLookup` | `if_nametoindex(3)`。callerのnetwork namespaceで解決し、sysfsに依存しない |
| 2 | `OpenSocket` | `socket(AF_XDP, SOCK_RAW \| SOCK_CLOEXEC \| SOCK_NONBLOCK, 0)` |
| 3 | `MapUmem` | anonymous private RW `mmap`。`UmemConfig::byte_len`をchecked `usize`化し4 KiBの倍数へ切上げ、addressが0またはpage非alignなら拒否 |
| 4 | `RegisterUmem` | `XDP_UMEM_REG`（addr、len=`byte_len`、chunk=`frame_size`、headroom=user headroom、flags/tx_metadata_len 0）。kernelが`XDP_PACKET_HEADROOM`を加える |
| 5–8 | `Size*Ring` | Fill、Completion、RX、TXの順に`u32` entryをsetsockopt |
| 9 | `QueryMmapOffsets` | exact 128 byte（v1 layoutは拒否）。各ringで全field offset ≤ `MAX_RING_HEADER_OFFSET`（4096）、alignment、overlap、overflow、`usize`表現をring mmap前に検証 |
| 10–13 | `Map*Ring` | Fill、Completion、RX、TXを各pgoffで`MAP_SHARED`。長さはchecked layoutの`descriptors + entries * element`。page非alignを拒否し、role-typed viewを一度実mapping上に組んで検証 |
| 14 | `Bind` | `sockaddr_xdp{AF_XDP, flags, ifindex, queue, shared_umem_fd 0}`。flagsは`ValidatedBindFlags`（need-wakeup必須）で、必ず`XDP_COPY`か`XDP_ZEROCOPY`の一方を含む |
| 15 | `QueryOptions` | `XDP_OPTIONS`はexact 4 byte。`XDP_OPTIONS_ZEROCOPY`以外のbit（未reviewのkernel optionが契約を変え得るため意図的にfail closed）、bindしたpolicyと異なるnegotiated modeを拒否 |

各resourceは取得成功後だけRAII ownerへ入り、取得順に宣言したlocalなので、途中のerrorは取得済み
resourceだけをexact reverse orderで一回ずつ解放します。live sessionはowner fieldを逆順（TX、RX、
Completion、Fill ring、UMEM、socket）に宣言し、Dropと明示`close`はこの順にunmap/closeします。
`close`は全releaseを一回ずつ試み、最初の失敗だけを`CleanupError{stage, errno}`で返します。
UMEM pageはkernelがpinしているため、socket close前のUMEM unmapでもkernel側pageは解放されません。
ring `munmap`が失敗するとそのvmaがsocket fileを参照し続け、fdをcloseしてもkernel socket（と
queue binding）はprocess終了まで残ります。`CleanupError`はこのstageを報告します。

ring viewは`NativeSession::rings(&mut self)`が返す`NativeRings<'_>`（`FillProducer`、
`CompletionConsumer`、`RxConsumer`、`TxProducer`、`UmemRegion`）だけで、各viewは対応する
`MappedRegion`を排他borrowします。従ってviewはmappingより長命になれず、二組を同時に持てず、
borrow中はunmapもできません。この借用を作る`MappedRegion::borrow_mapping`は、`mmap`成功値が
実mappingであることを約束する`unsafe trait MapsRealMemory`を実装したseamだけで使え、
synthetic addressを返すtranscript-only fakeでは使えません。UMEM byte accessはまだ公開せず、
frame ownership ledgerと結合するX01〜X03で追加します。sessionは`!Send + !Sync`です。

failureは値を持たない`SessionError{stage, failure}`です。errnoの分類は次のとおりです。

| errno | `SessionFailure` |
|---|---|
| EPERM、EACCES | `PermissionDenied`（典型はsocketの`CAP_NET_RAW`不足） |
| ENOMEM | `OutOfMemory` |
| ENOBUFS（`RegisterUmem`だけ） | `MemlockLimit`（`CAP_IPC_LOCK`なしで`RLIMIT_MEMLOCK`超過。他stageは`Errno(105)`） |
| ENODEV | `NoSuchDevice` |
| EINVAL | `InvalidArgument`（bindではqueue idがreal RX/TX queue数以上が典型） |
| EBUSY | `Busy`（queueに既にAF_XDP poolがある） |
| EOPNOTSUPP（`XDP_ZEROCOPY`付きbind） | `ZeroCopyUnsupported` |
| 他のEOPNOTSUPP、socketのEAFNOSUPPORT | `Unsupported` |
| その他 / 範囲外 | `Errno(n)` / `UnreadableErrno` |

`auto`はkernelの暗黙copy fallback（mode bitなしbind）を使わず、まず`XDP_ZEROCOPY`でbindします。
Linux v6.8 `xp_assign_dev`はzero-copy可否を順に判定します。deviceの`xdp_features`が
`NETDEV_XDP_ACT_ZC`全bitを持たなければEOPNOTSUPP、`XDP_USE_SG`時だけ`xdp_zc_max_segs`を検査し
（本profileはSGを要求しない）、最後に`ndo_bpf(XDP_SETUP_XSK_POOL)`の戻り値をそのまま返します。
EOPNOTSUPPとなる`ZeroCopyUnsupported`だけで一回目の
attemptを全てreverse releaseし、新しいsocket/UMEMで`XDP_COPY` transactionを行います
（`zero_copy_fallback() == true`）。EINVALはqueue範囲外やdriver geometry拒否と区別できないため、
EBUSY、ENOMEMと同じくfallbackせずfail closedです。`zero-copy`指定もfallbackしません。

finite fakeは固定長transcript、page-aligned実arena mapping、fd/mapping台帳で、15 stepの各call
へのerrno注入、kernel報告の各不正値、teardown各releaseの失敗、`auto`のfallback成功/失敗を
注入し、exact reverse release、leakなし、二重releaseなしを検証します（XDP-037〜043）。
privileged smoke（`RUSTER_PRIV_XDP=1`、`scripts/priv-xdp-smoke.sh`）は専用netns内だけに作った
veth上でcopy session、ring readiness、EBUSY/EINVAL/ENODEV、vethの`auto`→copy fallbackを実kernel
で検証し、netnsを必ず削除します。initial netnsでは実行を拒否し、env/netns/capability不足は
skipせずfailです（XDP-044）。実kernelではclose直後の同queue再bindが、pool登録解除のdeferred
workのため短時間EBUSYになります。UMEMのpin解除とmemlock accountingも`xdp_put_umem`のdeferred
cleanupと`SOCK_RCU_FREE`で遅延するため、`CAP_IPC_LOCK`なしで`RLIMIT_MEMLOCK`が狭いと直後の
再openは`RegisterUmem/MemlockLimit`（またはENOMEM）になり得ます。`auto`のcopy fallbackは一回目の
UMEMがまだaccountされている間に二つ目を登録するので、少なくともUMEM 2倍のmemlockか
`CAP_IPC_LOCK`が必要です。session builderはどちらも再試行せず、`Bind/Busy`と
`RegisterUmem/MemlockLimit`を含むretry policyはX04です（XDP-045）。

seamの契約はさらに次で固めます（XDP-046）。production実装は`if_nametoindex`のNUL終端と
setsockopt/getsockopt/bindのslice長・socklen一致を常時検査し、FFI前に
`Errno::ArgumentRejected`を返します。`Syscalls::munmap`/`close`は`unsafe fn`で、
`MappedRegion`/`OwnedXdpFd`の一回限りのreleaseだけが呼びます。`MapsRealMemory`は他者による
重なる範囲のunmap/remap/mprotectを契約違反とします。`NativeSession`は明示marker
`PhantomData<*mut ()>`で`!Send + !Sync`です。session fakeは`munmap`でarenaを解放するため
unmap後のaccessはMiriが検出し、lib testはstrict provenanceのMiriでUBなしです。

### XDP program and bpf_link lifecycle (X00D, M2 S2)

X00DはX00Cのbind済みsessionのqueueを、そのsocketへredirectします。libbpf/libxdpにlinkせず、
`bpf(2)`を同じsealed seam（`native_unsafe/syscall.rs`）から`syscall(SYS_bpf, ...)`で呼びます。
owner決定は次のとおりです。

- attachは`bpf_link`（`BPF_LINK_CREATE`、attach type `BPF_XDP`）だけで行い、minimum kernelは
  XDPの`bpf_link`が入った**Linux 5.9**です。netlink（`IFLA_XDP`）attachは使いません。
- 既存のXDP program/linkは置換もdetachもしません。見つかれば`ExistingProgram`でrejectします
  （config `existing-xdp-program = "refuse"`の実装）。
- detachはlink fdのcloseです。linkをbpffsへpinしないので、process crash（SIGKILLを含む）でも
  kernelがfdを閉じて自動detachします。これは他processがlink fdを持たないこと（exec前の`fork`、
  `SCM_RIGHTS`、`pidfd_getfd`がない）を前提とします。
- socketの無いqueueのframeは`XDP_DROP`で捨てます（fail closed、XDP-050）。

APIは`NativeSession`へ統合しました。`attach_xdp(XdpAttachMode::{Native, Generic})`、
`detach_xdp()`、`xdp_attach_mode()`です（configの`XdpAttachModeV1`と一対一）。別型
`XdpAttachment`にしなかったのは、attach中もdatapathが`rings(&mut self)`を借用する必要があり、
sessionを借用するattachment型ではそれができず、所有型にするとsocketより先にlinkを閉じる順序を
型で保証できないためです。統合した`SessionCore`はXDP object（link、program、map）を先頭field
に置くので、Drop/`close`は必ずlinkを最初に閉じ、socketのXSKMAP entryを`BPF_MAP_DELETE_ELEM`で
削除し、programとmapを閉じてから、ring、UMEM、socketを解放します。entry削除が要るのは、v6.8
`xsk_map_node_alloc`がentryごとに`bpf_map_inc`し、socketのmap listがmapを参照し続けるためで、
削除しないとattach/detachや失敗したlinkのたびにmapがsocket closeまで一つずつ残ります。
`close`の分解代入は全ownerをlocal bindingへmoveするので、仮にpanicしても（現状は各releaseが
`Result`を返すため到達しない）残りのbindingは宣言の逆順、つまり同じteardown順でdropされます。

ifindexは`open`時にcallerのnetwork namespaceで解決し、linkは`attach_xdp`時のnamespaceで作られます。
openとattachは同じnamespaceで行う必要があり、間の`setns`は同じifindexの無関係なdeviceへattach
し得ます。

順序は「session open（bind） → XSKMAP作成 → program load → socketをmapへ挿入 → link作成」です。

| # | `AttachStage` | 内容 |
|---|---|---|
| 0 | `Precondition` | 二度目は`AlreadyAttached`、zero-copy sessionへのgenericは`GenericRequiresCopyMode`（syscallなし） |
| 1 | `CreateMap` | `BPF_MAP_TYPE_XSKMAP`、key/value 4 byte、`max_entries = queue + 1`（M2は1 port 1 queueなのでbind queueを覆う最小。`MAX_QUEUE_ID`により最大65536） |
| 2 | `LoadProgram` | `BPF_PROG_TYPE_XDP`、`expected_attach_type = BPF_XDP`、license `MIT OR Apache-2.0`、`BPF_LOG_LEVEL1`で固定4 KiB log |
| 3 | `InsertSocket` | `BPF_MAP_UPDATE_ELEM`（key = queue、value = socket fd、`BPF_NOEXIST`） |
| 4 | `CreateLink` | `BPF_LINK_CREATE`（prog fd、ifindex、`BPF_XDP`、`XDP_FLAGS_DRV_MODE`または`XDP_FLAGS_SKB_MODE`） |

step 1〜3はprocess内のobjectだけを作り、interfaceを変えません。socketをlink作成前にmapへ入れる
ので、最初にredirectされるpacketから届きます。step 4が唯一の外部可視stepでcommit pointで、
kernelはRTNL下でlinkをinstallするかrejectします。native modeでdriverの`ndo_bpf`が途中で失敗すると
driverがlinkを一時的にreset（carrier断）し得ますが、programは残りません。
Linux v6.8 `dev_xdp_attach`はRTNL下で、同modeのlink（`Can't replace active BPF XDP link`）と
netlink attach program（`Can't replace active XDP program with BPF link`）にEBUSY、他modeの
program（`Native and generic XDP can't be active at the same time`）と、Linux 5.15以降ではupper
deviceのprogramにEEXISTを返します（5.9〜5.14はupper deviceを検査しません）。hardware offload
program（`XDP_FLAGS_HW_MODE`）はnative/genericと共存でき、検出もrejectもしません。linkは
`XDP_FLAGS_REPLACE`を持てないため、既存programの検出はlink createで行われ（事前queryのTOCTOUなし）、
既存programには触れません。各stepの失敗は作成済みobjectだけをexact reverse orderで解放し
（link失敗時はXSKMAP entry削除 → program → map）、sessionはattachなしのまま使えます。

programは手組みのoriginal eBPF（6 slot、48 byte）です。

```text
0: 61 12 10 00 00 00 00 00   r2 = *(u32 *)(r1 + 16)   ; xdp_md.rx_queue_index
1: 18 11 00 00 <map fd>      r1 = map_fd ll           ; BPF_PSEUDO_MAP_FD
2: 00 00 00 00 00 00 00 00                            ; ld_imm64 上位32 bit
3: b7 03 00 00 01 00 00 00   r3 = XDP_DROP
4: 85 00 00 00 33 00 00 00   call bpf_redirect_map (51)
5: 95 00 00 00 00 00 00 00   exit
```

`bpf_redirect_map`はslotが空（またはqueueが`max_entries`以上）のとき、flagsの下位2 bitを返します。
fallbackは`XDP_DROP`（fail closed）です。`XDP_PASS`ではmulti-queue RSSで非bind queueに来たframeが
kernel stackへ届き、kernelがrouterのfirewall/NATを迂回してforwardしたり、portのARP/ICMPに応答
したりし得ます。代わりに非bind queueのtrafficは失われるので、M2（1 port 1 queue）ではsingle-queue
deviceを使うかethtool RSS/ntupleで全trafficをbind queueへ寄せることが前提で、portにkernelのL3設定
（address、route）を残してはいけません（XDP-050）。startup時にqueue数/steeringを確認してtyped
errorにするcheckはX04です（XDP-063）。DROP fallbackはprogramがattachされている間だけ効き、attach前と
detach・close・crash（SIGKILL）後はprogramが無いため全queueのframeがkernel stackへ届きます（fail open）。
その間はportにkernel L3設定を残さずforwardingを無効にする運用要件が保護します。

licenseはrepoのSPDX式`MIT OR Apache-2.0`です。v6.8の`license_is_gpl_compatible`は
`gpl_only = true`のhelper（とkfunc）だけを制限し、使う唯一のhelper
`bpf_xdp_redirect_map_proto`は`.gpl_only = false`です（`net/core/filter.c`で確認）。GPL-only
helperが必要になるまで`GPL`は使いません（XDP-049）。

verifier logはstack上の固定4 KiB bufferへ書かせ、kernel出力はuntrustedとして解釈もcopyもせず、
最初のNULまでの長さとtruncation（ENOSPCまたはNULなし）だけを`VerifierLogSummary`としてload失敗の
errorに入れます。errorはvalue-freeな`AttachError{stage, failure, verifier_log}`です。

| errno | stage | `AttachFailure` |
|---|---|---|
| EBUSY、EEXIST | `CreateLink` | `ExistingProgram` |
| EOPNOTSUPP | native `CreateLink` | `NativeXdpUnsupported`（driverにnative XDPなし。slaveがprogramを持つbond masterも） |
| EACCES（verifier logあり） | `LoadProgram` | `VerifierRejected`（verifierはEINVAL/E2BIGでも拒否し得る） |
| EPERM、他のEACCES | any | `PermissionDenied`（`CAP_NET_ADMIN`/`CAP_BPF`、logが空のloadのEACCESはLSM。5.11前はmemlock超過も） |
| EINVAL | any | `InvalidArgument`（link createで消えたdeviceはENODEVではなくEINVAL） |
| E2BIG | any | `TooBig`（insertではqueue ≥ map size） |
| ENOSPC | any | `NoSpace`（log truncation、vethでRX queue数 < peer TX queue数） |
| ENOMEM | any | `OutOfMemory` |
| 他のEOPNOTSUPP | any | `Unsupported` |
| その他 / 範囲外 | any | `Errno(n)` / `UnreadableErrno` |

production seamは常時、map size 0、NUL終端のないobject名、0または`BPF_MAXINSNS`超のinsn数、
128 byte超のlicense、128..=`u32::MAX >> 2`外のlog長、負fd、ifindex 0をFFI前に拒否します。
`union bpf_attr`はこのprofileが書くfieldまでのprefix（create 44/update 32/delete 16/load 72/
link 16 byte、すべて5.9に存在）だけを
8-byte alignで渡し、3つのuser pointer（insns、license、log）はcall中生存するborrowから作ります。
BPF fdは`OwnedBpfFd`（種別付き、Debugでredact、close高々一回）が所有し、raw fdは`syscall.rs`から
出ません。kernelはbpf fdを常に`O_CLOEXEC`で作ります。

finite fakeはattach 4 stepの各callへの注入、全errno分類、log summary、precondition、detachと
attach済みteardown 10 releaseの各失敗、link失敗時のentry削除とその失敗を検証します（XDP-047〜059）。privileged smoke
（`scripts/priv-xdp-smoke.sh`）は専用netns内だけの2-queue veth pairで、native attach後にpeer端
から送ったframeがRX ringへ届くこと、別queueのsocketからの二度目のattachと、`ip link set ...
xdpgeneric obj`で付けた外部programへのattachが両modeで`ExistingProgram`になりprogram idが
不変なこと、detach/generic attach/closeによるdetach、attachしたprocessのSIGKILL後にlinkが
消えることを確認します（XDP-060、XDP-061）。holderのpidはtmp+renameで公開させ、
`/proc/<pid>/exe`がtest binaryであることを確認してから採用し、kill直前にも再確認します。外部program用のELF objectはcompilerなしで
`scripts/priv-xdp-foreign-elf.py`が組み立てます。5.9〜6.xでの実機検証、CI workflow化、link
down/up、netdev削除、reload時のre-attach policyはX04です（XDP-062）。

### AF_XDP RX/Fill engine (X01, M2 S3)

`ruster-io-xdp-native`の`RxFillEngine<'memory>`はdatapath engineのRX/Fill半分です。一workerが
Fill producer、RX consumer、TX producer、Completion consumer、UMEM、authoritative `FrameLedger`を
まとめて所有し、lock、構築後のallocation、packet clone、packet単位`String`、`dyn`を使いません
（ledgerが`!Send + !Sync`なのでengineも同じ）。TX/Completion半分（M2 S4、次節X02）も同じengineと
同じledgerにあり、engineだけがTX descriptorをsubmitできます。

ledgerの前提は「このUMEMのFillへpublishしたのはこのengineだけ」です。これを型で保証するため、
engineは`DatapathRings<'session>`（Fill、Completion、RX、TX、UMEM bytesの一組）をby valueで
一つだけ受け取ります。bundleにはpublic constructorもmember accessもなく
（`compile_fail,E0451`/`E0616` doctest）、別sessionのviewやheap view、すでにpublishに使った
viewを混ぜられません。liveでは`NativeSession::take_datapath(&mut self)`がsessionごとに高々一回
だけ貸し、二回目は`DatapathError::AlreadyTaken`、`rings()`でraw viewを一度でも貸したsessionでは
`RawRingsLent`、bundleを取った後の`rings()`は`RingsError::DatapathTaken`です。engineをdropしても
kernel/driver（zero-copyのhardware RX descriptor、copy modeのdrop path）は以前publishしたframeを
保持し得るため、engineの作り直しにはsessionのclose（新socketと新UMEM）が必要です。testのheap
bundleはtest専用scripted kernelだけが一組として一回だけ作ります。ring memoryへのgeneric性は
このbundleを貸す側（session mappingまたはheap）で表します。

dependencyの決定: `ruster-io-xdp-native`は既存の`ruster-io-xdp`（ledger、token、layout、
FakeKernel）だけに依存し、`ruster-core`には依存しません。core `PacketIo`/`PacketSlot` adapterは
`SlotCompletion::Transmit`にTX publication（S4、X02）が要るため、X04のapp adapterで`RxFrame`の
上に実装します。`ruster-io-xdp`のtest用`test-hooks` feature（generation exhaustionを起こす
ledger hook、supported APIではない）はdev-dependencyからだけ有効にします。

`RxFillEngine::new`は`UmemDomainId`からfreshなledgerを作り（geometryは`UmemConfig`、headroomは
user headroom + `XDP_PACKET_HEADROOM`）、防御的にFill/RX ringが空であることも確かめます。frame
`0..rx_frames`がRX poolで、generated pool（`rx_frames..frame_count`）はFillへ一度もpublishせず、
次々節X03の`allocate_generated`だけが貸します。free RX-pool frameは固定長FIFOで持ち、`refill`は`min(Fill room, free list,
fill_batch)`個を`reserve_fill` → Fillへchunk base address write → Release publish →
`publish_fill`の順に一回で出します。ring操作が失敗すればreserve済みframeを`cancel_fill`で
free listへ戻し、generation exhaustionのframeはquarantineして次へ進みます。free listが空で
Fillにroomがあれば`fill_starved`を数えてすぐ戻り（stallしない、BACKEND-004のRX側）、free
frameがあるのにFillが満杯なら`fill_ring_full`です。

need-wakeupは各refillの最後（publicationがあればそのRelease後）に必ずAcquire観測し、
`RefillReport::need_wakeup`で返します。publishしなかったrefill（Fill満杯、starved）や構築時の
初回refill（`initial_refill()`）でも同じで、別に`fill_needs_wakeup()`がpublishなしに一回のatomic
loadで読みます。zero-copyではkernelがFill枯渇時にflagを立てるため、libxdpと同じく各pollで
flagを見てkickできます（kickは次節X02の`wake_fill()`、いつkickするかのpolicyはX04）。`fill_need_wakeup`はRequiredを観測したrefill数、
`fill_flag_errors`は未知bitを観測したrefill数で、publicationはrollbackしません。

`poll(budget)`はrefillの後、RX ringから`min(budget - pending, pending capacity, available)`個だけ
descriptorを読み、全部を検証してからconsumer cursorをReleaseします。valid frameは`RxAvailable`
としてfixed pending FIFOへ入り、batchが最大`budget`個を一つずつ`RxFrame`として貸します。
lendされずにbatchが終わったframeはpendingに残り、次のpollが新しいdescriptorより先に貸します。
従って一pollのdescriptor作業はinvalidも含めて`budget`以下で、zero budgetはRX ringを観測しません。

RX descriptorは次の順で検証し、どれかに失敗したdescriptorはcoreへ届きません（`rx_invalid`の
reason別counter）。

| 順 | 条件 | reason | frame |
|---|---|---|---|
| 1 | `addr < UMEM byte_len` | `AddressOutsideUmem` | 不変 |
| 2 | `addr / chunk`のframeが`FillOwnedByKernel` | `NotKernelOwned`（重複、generated pool、lease中/TX中/pending/quarantine済み） | 不変 |
| 3 | `options == 0`（`XDP_PKT_CONTD`等） | `UnsupportedOptions` | quarantine |
| 4 | chunk内offset ≥ user headroom + 256 | `DataBeforeHeadroom` | quarantine |
| 5 | `offset + len ≤ chunk size` | `ExceedsFrame` | quarantine |
| 6 | `len ≥ 14`（Ethernet header） | `ShorterThanEthernetHeader` | recycle |

chunk越えはrunt判定より前です（M2 S4で順序を入れ替え）。14 byte未満でもchunk末尾を越える
descriptorはprofile外のgeometryなので、runtとしてrecycleせずquarantineします（XDP-106）。

最後に`UmemLayout::validate_descriptor`を独立な第二gateとして通します。kernelがframeを
profile外のdescriptor（options、headroom、chunk越え）で返した場合、そのframeは
`FrameLedger::quarantine_kernel_fill`で永久に`Quarantined`へ移し、lendもrecycleもしません
（未reviewのkernel契約を再利用しないfail closed）。これによるpool縮小は`frames_quarantined`で
観測します（free listが尽きればstarvationとしても現れますが、縮小そのものの指標ではありません）。
address、所有、headroom、chunk境界が正しく長さだけが14未満のrunt（0を含む）は、kernelがframeを正しく返した上で
packetが使えないだけなので、`FrameLedger::release_kernel_fill`でFreeへ戻してfree listへ入れ、
`rx_runts_recycled`も数えます。kernelがframeを返していない場合（1、2）はledgerに一切触れないので、
重複descriptorが別ownerのframeを奪うことはありません。最小長は60-byte padded minimumではなく
14 byteです。vethなどsoftware deviceはpaddingせずARP requestを42 byteで渡すためで、L2/L3の検証は
coreが行います。data offsetはheadroom以上を要求しexact一致は要求しません（driverがdataを後ろに
置く余地を残す）。前提として、attachするXDP program（X00Dのredirect program）は
`bpf_xdp_adjust_head`の負方向などでdataをheadroomより前へ動かしません。動かすprogramを使うと
全frameが`DataBeforeHeadroom`でquarantineされます。copy modeではdataはexactにchunk +
user headroom + 256にあり、privileged smokeがこれを確認します（XDP-067）。

`RxFrame<'engine, 'memory>`はengineを排他borrowし、`bytes`/`bytes_mut`、`recycle`、
`stage_tx`を持ちます。`bytes_mut`のsliceは`RxFrame`をborrowし、`recycle`/`stage_tx`は`self`を
consumeするので、bytes借用中のrecycleはcompile error（`compile_fail,E0505` doctest）です。
一度に貸せるframeは一つで、明示終端なしのdropはRAIIでrecycleし`rx_abandoned`を数えます。
recycleはledger `recycle_lease`（exact token/generationの`Leased`だけ）とfree listへのpushで、
同じcycleの二度目の完了、pending/kernel所有frameのrecycleはledgerが`WrongState`/`StaleToken`で
拒否します。`stage_tx`はframeを`PendingTx`へ移したmove-onlyの`TxHandoff`（public
constructorなし、`must_use`）を返し、次節の`submit_tx`がTXへ出すか、`cancel_tx_handoff`がfree listへ
戻します。どちらも拒否時はhandoffをそのまま返します。engine methodを通らずにdropされた`TxHandoff`は
frameを`PendingTx`に置き去りにするため、debug buildではassert（`#[should_panic]` testで固定）し、
`tx_handoffs_outstanding()`（ledgerの`PendingTx`数、O(1)）が数え続けます。

UMEM byte accessは`native_unsafe/umem.rs`の`UmemFrames`だけです。mappingとledgerを一つの値に
まとめ、ledgerが`Leased`（user space所有）と記録しているframeについてだけ、その時点のexact
tokenとdescriptorのvisible rangeを自前のgeometryで再計算してからsliceを作ります。sliceは
`UmemFrames`をborrowするので、生存中はledger遷移（Fillへのrecycleを含む）が起きません。kernelは
Fill/TXにpublishされた他のframeを同時に書き得ますが、Rust referenceはlease中の一frameにだけ
作られます。この健全性は二つに依存します。(1) frameが`Leased`へ入るのはpublishされていない
`Free`からか、kernelがRX ringでそのframeを返した後の`FillOwnedByKernel → RxAvailable → Leased`
だけで、ledgerを変更するのはengineだけ。(2) このUMEMのFill/TXへ書けるのはengineだけ。(2)は
once-per-sessionの`DatapathRings`がengineへ全ringを渡すことで型として成り立ちます。
`UmemRegion`（`NativeRings`の一部）はgeometryだけでbyte accessを持ちません。

counter（`RxFillCounters`、OBS-018のRX/Fill半分）はsaturating `u64`で、`polls`、`rx_packets`、
`rx_leased`、`rx_recycled`、`rx_abandoned`、`rx_tx_handoffs`、`tx_handoffs_cancelled`、
`rx_ring_empty`、`rx_backlogged`、`rx_invalid(reason)`、`rx_runts_recycled`、`fill_published`、
`fill_starved`、`fill_ring_full`、`fill_need_wakeup`、`fill_flag_errors`、`frames_quarantined`です。
hot pathは数個の整数更新とflag一回のatomic loadだけでledgerをscanしません。`audit()`はcold pathで
ledger deep audit、free listがFree RX-pool frameとexactに一致すること、pending listが
`RxAvailable`とexactに一致すること、engineがrestで残さないstateが無いことを検査します。runtime
`BackendStats`への接続はX04a（後述「AF_XDP core adapter」）です。

testは`native_unsafe/heap_kernel.rs`（test専用）のscripted kernelで行います。heap上の五regionを
一回だけbundleとしてengineへ貸し、scriptはkernelと同じくraw pointer（atomic cursor、volatile
descriptor、raw byte copy）だけでkernel側を演じます。scriptはFillから取ってRXで返していない
frameを「保持中」として追跡し、packet bytesの読み書きは保持中のframeに限り（lend中のframeには
触れない）、同じframeをFillから二度取ればfailします。invalid descriptor全種、exact境界、重複、
二重完了、starvationと回復、partial Fill、poll budgetとbacklog/empty境界、generation exhaustion、
need-wakeup、corrupt cursor、setup拒否、bundleの一回性と二重publishの不可能性（review PoCの回帰）、
steady-stateとrefusal/starvation pathのallocation zero、io-xdp `FakeKernel`とのdifferential
（seed付きscheduleで各step後にframeごとのstate/generationとdeep auditを比較）を検証します。
differentialは状態を変えないinvalid descriptor（UMEM外、generated pool）を含みますが、quarantineと
runtは含みません。model kernelはprofile外のRXをproduceせず、それを写すmutable ledgerも公開しない
ためで、両pathは直接のtestで固定します。modelはkernelがRXをproduceした時点で`RxAvailable`とするが
native engineはRX ringを読むまで観測できないため、両者を「kernel側保持」へ射影して比較します。
privileged smokeのengine phaseは専用netns veth上でattach後のpeer ARP frameがengineの検証を通り
lend、recycle、refillされ、copy modeのdata offsetが256、bundleの二度目のtakeとraw viewが
拒否されることを確認します（XDP-064〜090）。

### AF_XDP TX/Completion half (X02, M2 S4)

TX/Completion半分は別engineではなく、同じ`RxFillEngine`の子module（`tx_completion.rs`）です。
TX producer、Completion consumer、socketのkick handleもengineが所有し、UMEMの全frameを記録する
ledgerは一つだけです（ledgerを変更するのはこのengineだけ）。名前は互換のため`RxFillEngine`のままです。

state machine（RX pool frameのTX cycle）:

```text
Leased (RxFrame, core rewrites in place)
  │ stage_tx
  ▼
PendingTx (TxHandoff, caller-held) ──cancel_tx_handoff──► Leased ─► Free ─► free list ─► Fill
  │ submit_tx / submit_tx_batch: check(PendingTx) + geometry → reserve_tx
  ▼
TxReserved ──ring write → Release publish──► TxOwnedByKernel (in flight)
  │ reap: exact address                      │ reap: same frame, other address
  ▼                                          ▼
CompletionAvailable ─► Free ─► free list   Quarantined (permanent)
```

**same-frame TX**: `submit_tx(handoff)`と`submit_tx_batch(&mut [Option<TxHandoff>])`はcopyせず、
ledgerが検証したRX geometry（`frame_base + data_offset`、受信長、options 0）をTX descriptorにします。
core `PacketSlot`は長さを変えないので、in-placeで書き換えたbytesがそのまま出ます。submit前に
各handoffを`FrameLedger::check(token, PendingTx)`（domain、generation、state、tokenの非破壊検証）と
layoutによる再検証（hidden domainを含む`ValidatedDescriptor`の一致）で確かめ、一つでも拒否なら何も
submitせず全slotを不変に残します（`TxSubmitError::Handoff{index}`、一件版は
`TxRejection::Invalid`）。batchは一つのTX reservationと一回のRelease publicationで、ledger遷移は
`reserve_tx`（ring write前）、`publish_tx`（publication後）です。publication失敗時は
`cancel_tx_reservation`で全部戻します。

**in-flight上限（BACKEND-004）**: in-flight（TXへpublish済み、未completion）は提出順の固定長list
（容量はTX capacity）で持ち、一回のsubmitは`min(TX ring room, TX capacity - in flight)`個までです。
ring上の未消費descriptorは必ずin-flightの一部なので、ring roomは常に`TX capacity - in flight`以上で、
実際に効くのはin-flight上限です。engine setupは`completion capacity >= tx capacity`
（`CompletionSmallerThanTx`）とTX/Completion ringが空であること（`TxRingNotEmpty`、
`CompletionRingNotEmpty`）を要求するので、全in-flight frameにCompletion slotがあり、Linux copy modeの
completion予約（`xsk_generic_xmit`）が満杯にならない構成です。

**would-block**: 上限で残ったhandoffはslotに不変のまま残り、`TxSubmitReport::blocked()`が理由を
返します。`RingFull`はkernelがまだTX descriptorを消費していない（`wake_tx`して再試行）、
`InflightLimit`はkernelが消費したがcompletionが遅れている（`poll`/`reap_completions`して再試行）、
`Draining`はdrain開始後です。部分submitはerrorではなく通常のback-pressureです。一件の`submit_tx`は
`TxRejected{reason, handoff}`を返し（boxしないので拒否pathもallocationなし）、`into_handoff()`で
再試行するか`cancel_tx_handoff`でfree list（次のrefillでFill）へ戻します。どの拒否でもframeは
strandしません。

**completion**: `reap_completions(budget)`はCompletion ringから`min(budget, available)`個を読み、
全部を処理してからconsumer cursorをReleaseします（残りは`completion_backlogged`）。`poll`は
refillの前にTX capacityをbudgetとしてreapするため、completed frameは同じpollのrefillでFillへ戻れます
（free listが短くてもstallしない）。各addressは次の順で検証します。

| 順 | 条件 | reason | frame |
|---|---|---|---|
| 1 | `addr < UMEM byte_len` | `AddressOutsideUmem` | 不変 |
| 2 | frameが`TxOwnedByKernel` | `NotInFlight`（重複completion、Fill/RX/caller/quarantine所有、generated pool） | 不変 |
| 3 | 提出したexact descriptor address | `AddressMismatch` | quarantine |

1、2はledgerに触れないので、kernelのcompletionが他ownerのframeを解放することはありません。3は
in-flight frameですがLinuxが返すはずの`desc.addr`と違い、kernelが使い終えたか分からないため
`FrameLedger::quarantine_kernel_tx`で永久にquarantineします（fail closed、`frames_quarantined`）。
validなcompletionだけが`complete_tx` → `recycle_completion` → free listです。Linuxは提出順に
completionを出すので該当entryは通常list先頭（O(1)）です。順序が違うcompletionも受理し、list中央から
除去（TX capacity以下のshift）して`tx_completions_reordered`で数えます。resubmit済みframeに対する
古い重複completionはkernel sequenceが無いと区別できない残余で、Linuxは消費したTX descriptorと1:1で
completionを出します。

**completion lag**: `completion_lag()`はO(1)でin-flight数と最古in-flight frameのsubmit時からの
poll数を返します。engineは時計を持たず、時間への換算とhealth化はX04のcallerです。

**need-wakeupとkick handle**: 各submitの最後にTX flagをAcquire観測して`TxSubmitReport::need_wakeup`で
返し、`tx_needs_wakeup()`は一回のatomic loadです。copy modeのLinuxは`sendto`からだけ送信し、flagを
立て続けます。bundleを取るとsessionはengineの生存中borrowされるため、`DatapathRings`はsessionの
所有socketへのshared borrow（private `SocketKick`）も運びます。できるのは`wake_tx()`
（`sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0)`）と`wake_fill()`（`poll(fd, POLLIN, 0)`、sleepしない。
zero-copy driverの`ndo_xsk_wakeup`を起こす）だけで、close/bind/mmap/setsockoptは持ちません。`close`は
sessionをby valueで要するので、fdはkickより長生きします。kick moduleにunsafeはなく、syscallはsealed
seamだけを通り、Linux実装は負のfdをdebug assertionでなく常にlibc前で拒否します。errnoは
`EAGAIN`/`EBUSY`/`ENOBUFS`/`EINTR`をbenignな`KickOutcome::Deferred`、`ENETDOWN`を
`KickError::NetworkDown`、`ENXIO`を`NotBound`、他を`Errno(n)`、seam前の拒否を`Rejected`にします。
kickの失敗はledgerを変えず、publish済みdescriptorはin-flightのままです。`attach_xdp(&mut self)`は
`take_datapath`より前に呼びます（以後sessionはbundleにborrowされています）。

**shutdown drain**: `drain(rounds)`は新規TXとFill publicationを永久に止め（`TxBlocked::Draining`、
`fill_suppressed_draining`）、lendされていないvalid RX frameをfree listへ戻し、最大`rounds`回
「kernelが`NotRequired`と明示しない限り（flag wordが読めないErrでも）TX kick、TX capacity分のreap」を
行います。frameは通常と同じvalidated completion
pathを通って一回だけfree listへ戻り、重複completionは二度目を拒否します。kernelが保持するframeは
返ったことにしません: TXは`DrainOutcome::TxInFlight{frames}`、全体は`FrameAccounting`（free、
`fill_in_kernel`、pending RX、lease、handoff、`tx_in_flight`、quarantine、和はRX pool size）で返します。
Fillへpublishしたframeはkernelが返すかsocketがcloseするまでkernelのもので、shutdownでは想定どおりです
（drain後もpollはRXを処理してfree listへ戻します）。engineは時計を持たないため、callerが`rounds`と
再呼出し（間にsleep）でtimeoutを決めます。`Drained`はcallerが持つhandoff（`tx_handoffs`）を
含まないため、X04のordered shutdownは先にcancelして`tx_handoffs == 0`を自分で確認します。

**audit**: `audit()`はXDP-080に加え、in-flight listの各entryが`TxOwnedByKernel`のexact tokenで重複
せず他のlistにも無いこと、listと`TxOwnedByKernel`数とgauge `tx_inflight`の一致、in-flight ≤ TX
capacity、owner partitionの和がRX pool sizeであることを検査します。すなわち各frameがちょうど一回
数えられていることを確かめます。

**counter**（`TxCounters`、OBS-018のTX/Completion半分）: `tx_submitted`、`tx_ring_full`、
`tx_inflight_limited`、`tx_refused_draining`、`tx_completed`、`tx_completions_reordered`、
`completion_backlogged`、`tx_invalid_completion(reason)`、`tx_need_wakeup`、`tx_flag_errors`、
`tx_kicks`、`fill_kicks`、`kicks_deferred`、`kick_errors`、`drains`、gauge `tx_inflight`と
`tx_inflight_highwater`。hot pathは整数更新だけでledgerをscanしません。

**handoffの出自と重複**: `TxHandoff`は発行engineのprocess内一意identity（engine構築時に一回だけ
static `AtomicU64`から採番。datapathでは触らない）を持ちます。`UmemDomainId::new`はpublicなので
callerが二つのengineに同じdomain値を与えるとdeterministicなkernelでは同じtokenができますが、
identityが違うので別engineのhandoffは`ForeignTokenDomain`で拒否されます。batchは各slotを検証して
`TxReserved`へ移す処理を順に行うので、同じcycleを指す二つ目のslot（偽造でしか作れない）は
`WrongState`となり、それまでのreservationを全てrollbackしてtyped errorを返します（panicしない）。
ring reserve/write/publishの失敗も同じくrollbackし、拒否したbatchはcounterも変えません。

**bind queueのTX queue**: Linux v6.8の`xsk_bind`は`queue < max(real_num_rx_queues,
real_num_tx_queues)`だけを要求し、copy-modeの`__xsk_generic_xmit`は`queue >= real_num_tx_queues`
では黙って何も送りません（kickは`Woken`のまま、TXは`RingFull`、drainは永久に`TxInFlight`）。
そこで`NativeSession::open`はinterface lookup直後、resource取得前に`SessionStage::TxQueueCheck`で
sysfs（`/sys/class/net/<dev>/ifindex`が解決済みifindexと一致することを確認してから
`queues/tx-<queue>`）を調べ、無ければ`SessionFailure::NoTxQueue`、確かめられなければ
`TxQueueUnverifiable`で拒否します。runtimeの`ethtool -L`などで後からTX queueを失ったstallの検出は
X04のhealthです。

**kernel-trustの限界**: copy modeでは`xsk_poll`もtransmit loopを回すので`wake_fill()`もTXを進めます。
`EAGAIN`は主に一回のtransmitが`TX_BATCH_SIZE`（32）に達したことを意味し、すぐ再kickします
（completion slotの予約失敗はsuccessで返ります）。kernelが不正とみなしたTX descriptorはcompletion
なしに消費される（`invalid_descs`）ため、もし起きればそのframeのin-flight slotは失われ、
`completion_lag()`の最古ageが増え続けdrainが`TxInFlight`を返すことで観測されます（descriptorは検証済み
RX geometryから作るので想定外。`XDP_STATISTICS`の監視はX04）。resubmit後に届く古い重複completionは
検出できず、Linuxが消費したTX descriptorごとにcompletionを一つだけ出すという前提はkernel-trust
assumptionの一部です。

testはscripted heap kernelをTX consume（同じframeの二重submitやFill publish中のTX submitでfail）と
completion produce、kick記録/errno注入へ拡張して行います。partial/full ring、in-flight上限とcompletion
lag、短いfree listでの前進、順序違いcompletion、UMEM外/重複/Fill所有/generated pool/address違いの
completion、need-wakeupとerrno mapping、kernelが保持したままのdrainと二度目のdrain、foreign handoff、
setup拒否、corrupt cursor、in-flight listのaudit、各step後のdeep audit、steady-stateのallocation zero、
io-xdp `FakeKernel`のTX lifecycleとのdifferential（modelの`CompletionAvailable`はengineがringを
読むまで`TxOwnedByKernel`へ射影）、in-flight FIFOの`VecDeque` oracleとのproperty test
（capacity 1..=8、全wrap-around位置）を検証します。differentialのmodelは提出順completionしか
出さないため、invalid/重複/順序違いcompletion、quarantine、drainのkernel保持、kick errnoは直接testが
担います。single-threadのtestとMiriは`publish_producer`のRelease→Relaxedのようなordering mutantを
検出できないので、orderingはreviewとprivileged smokeに依存します。privileged smokeのtx phaseは専用netns veth上で
peerのARP requestを同じUMEM frameのままin-placeでARP replyへ書き換え、同じvethからTXし、peer kernelが
`ip neigh`にreplyのMACを学習することで受信を確かめ、completionをreapし、さらにkickもreapもせずに
submitしたままのframe（in-flight 1）をdrainのkickとreapだけで回収して`Drained`を確認してからcloseします
（XDP-091〜111）。generated poolのTXは次節X03、core `PacketIo` adapter、kick policy、runtime
statsはX04a（後述「AF_XDP core adapter」）、health化はX04bです（XDP-112）。

### AF_XDP generated frames (X03, M2 S5)

generated半分も同じ`RxFillEngine`の子module（`generated.rs`）で、同じledgerを使います。UMEM frame
`rx_frames..frame_count`（configの`generated-frames`）がgenerated poolで、RX poolとは別の固定長free
list（cold pathで一回だけ確保）を持ちます。RX/Fill/TX/Completionのring所有とkick handleは変わりません。

state machine（generated pool frame）:

```text
Free (generated free list) ──allocate_generated(len)──► Leased(Generated) = GeneratedFrame
  ▲  ▲  ▲                                                 │   │   │
  │  │  └─────────── cancel (generated_cancelled) ───────┘   │   │
  │  └────────────── drop (generated_abandoned) ─────────────┘   │
  │                                                              │ stage_tx / commit
  │                                                              ▼
  ├── cancel_tx_handoff (generated_cancelled) ─────────── PendingTx = TxHandoff
  │                                                              │ submit_tx(_batch)（X02と同じ上限）
  │                                                              ▼
  └── validated completion (generated_completed) ─────── TxOwnedByKernel ──address違い──► Quarantined
```

`allocate_generated(len: usize)`は次の順に検査し、拒否はblockせずledgerとfree listを変えません。

| 順 | 条件 | 結果 |
|---|---|---|
| 1 | `drain`開始後 | `Rejected(Draining)` |
| 2 | `len == 0` | `Rejected(ZeroLength)` |
| 3 | `len < 14`（RXと同じEthernet header floor） | `Rejected(BelowMinimum)` |
| 4 | `len > frame_size - (headroom + XDP_PACKET_HEADROOM)`（u32を越える値も） | `Rejected(TooLarge)` |
| 5 | generated free listが空 | `Unavailable`（`poll`/`reap_completions`後にretry） |

成功するとledgerの`lease_generated`（`Free`→`Leased(Generated)`、Fillを経由しない）で新しいgenerationの
tokenを取り、descriptor `frame base + headroom`・長さ`len`を`ValidatedDescriptor`として作り（layoutの
検証を二重のgateとして使う）、visible rangeだけをzero化して`GeneratedFrame`を貸します。byte accessは
RXと同じ`UmemFrames::leased_bytes(_mut)`で、ledgerが`Leased`と記録するframeのexactなdescriptor範囲
だけに限られるので、`len`の先やheadroomは到達できません。`GeneratedFrame`はengineを可変借用するので、
RX/generatedを問わず貸せるframeは常に一つで（double lendなし）、bytes借用中のcancel/commitはcompile
errorです。ledgerの`GenerationExhausted`ならframeはquarantineされ、次のfree frameへ進みます。

commitは`stage_tx` + `submit_tx`で、forwarded frameと同じTX ring、同じin-flight上限（TX capacity、
BACKEND-004）、同じ`TxBlocked::RingFull`/`InflightLimit`/`Draining`を使います。拒否されたhandoffは
`TxRejected`でそのまま返り、retryか`cancel_tx_handoff`です。`stage_tx`したhandoffは`submit_tx_batch`で
forwarded frameと混ぜられます。generated用のTX枠予約や公平性は持たず、上限は先着で共有します（X04）。

pool分離: frameが`Free`になる全経路（RX recycle、runt、Fill rollback、handoff cancel、completion、
drainのpending解放、generated cancel/abandon）は`push_free(frame)`一箇所を通り、所属poolはframe index
（`frame >= rx_frames`）だけで決まります。completion addressやhandoffの主張は使いません。refillは
RX free listだけを読むので、Fill ringにgenerated frameが入ることはなく、generated allocationは
generated free listだけを読むのでRX frameを取りません。RX descriptorがgenerated frameを指しても
そのframeは`FillOwnedByKernel`ではないので`NotKernelOwned`で不変、free/staged generated frameへの
completionは`NotInFlight`で不変、in-flight generated frameのaddress違いcompletionはgenerated poolで
quarantineします。

accounting: generated poolの所有者はfree list長、`leased`（0か1）、`tx_handoffs`、gauge
`generated_inflight`、`quarantined`の五つで、`GeneratedAccounting`（O(1)）は常にpool sizeの和です。
RX poolの`FrameAccounting`はledgerのO(1) state countからgenerated分を引いて出します。`audit()`は
両free listのentryが自pool・`Free`・全listで一回だけであること、generated poolにFill/RX stateが
無いこと、generated poolをscanした各state数がengineの記録と一致すること（`GeneratedCount`）、両
partitionの和を検査します。counterの関係は
`generated_allocated = generated_committed + generated_cancelled + generated_abandoned + handoffs + leased`、
`generated_committed = generated_completed + generated_inflight + TX後のgenerated quarantine`です。
`tx_inflight`と`tx_handoffs_outstanding()`は両poolの合計です。drainはgenerated allocationを止め
（`Draining`）、in-flight generated frameを同じ検証付きreapで回収し、`DrainReport::generated_accounting`を
返します。caller保持のgenerated handoffはRXと同様にcallerがcancelします。

testはscripted heap kernel上で、exact visible length（full lengthを0xaaで送った同じframeに42 byteを
割り当て、wire上の43 byte目以降が不変）、zero化、全拒否理由とUnavailableからの回復、cancel/abandon/
handoff cancelのpoolとgeneration、forwarded frameとの共有上限とback-pressure、混在batchの逆順
completionとFillのRX限定、他poolを指すkernel return、generation exhaustion、両poolのaudit検出、
steady-stateのallocation zero、io-xdp `FakeKernel`の`lease_generated`経由lifecycleとのdifferential、
io-conformance generated suiteのsemantics（三つの`GeneratedBatchCompletion`不変条件、成功allocation
だけのownership、拒否後のpool復帰とgeneration、completionのexact frame）をengine層で検証します。
suite自体はcore `GeneratedPacketIo`実装を要求するため、core adapterと一緒にX04で適用します。
privileged smokeのgenerated phaseは専用netns veth上でgenerated poolのframeに42 byteのARP requestを
書いてcommitし、peer kernelが送信元を`ip neigh`に学習することとcompletionを確認し、kickなしで提出した
最後の一つをdrainで回収します（XDP-120〜131）。core adapter、refusalのcore errorへのmapping、
multi-port egress、runtime statsはX04a（次節）、TX枠の公平性はdeferredです（XDP-132）。

### AF_XDP core adapter (X04a, M2 S6)

`ruster-io-xdp-native`は`ruster-core`へ依存するようになり（core自身は外部依存なし）、
`XdpPacketIo<'memory>`がinterfaceごとに一つの`RxFillEngine`（一socket、一queue、一UMEM）の上で
core `PacketIo`、`GeneratedPacketIo`、`PublicationQuiescence`、`BackendStats`を実装します。adapter、
batch（`XdpRxBatch`、`XdpGeneratedBatch`）、slot（`XdpRxSlot`、`XdpGeneratedSlot`）はすべて具体型で
static dispatchだけを使い、packet pathには共有`Mutex`、packet clone、packet単位`String`、
`dyn PacketIo`、allocationがありません（scripted kernel上のsteady-state testでallocation 0）。

```text
            receive(budget)                       commit(egress)
port[rx_start] ─poll─┐                       ┌─ egress == ingress ─► 同じframeをstage/submit（copyなし）
port[+1]       ─poll─┼─► 各portのpending frame ┤
...  (残りbudget0でも ┘   をport順にlend       └─ egress != ingress ─► egressのgenerated frameへexact copy
     reap/refillのみ)                                                  → commit、ingressのRX frameはrecycle
```

multi-port mapping: `XdpPacketIo::new(ports)`は`XdpPort { XdpPortConfig, engine }`の集合を一度だけ
受けます。`XdpPortConfig`は`XdpPortConfig::from_session(interface, &session)`だけで作れ（queue、
negotiated mode、openで読んだMTU、sessionのorigin identity）、datapath bundleが運ぶ同じoriginを
engineが保持するので、別sessionのengineと組んだconfigは`SessionMismatch`で拒否されMTUやmodeを
偽れません。空集合、重複`IfId`、MTU 0、drain済みengineもtyped errorで拒否し、`IfId`順にsortした
boxed sliceへ固定します（cold pathの一回だけのallocation）。以後mappingは変わらず、egress選択は
この固定sliceの二分探索（`O(log ports)`、map/string/trait objectなし）です。runtimeのconfigから
portを作る配線（validated configの`ports()`はIfId順）と`ruster run`はX04bで、前半（M2 S10a）を
後述「`ruster run`」に記します。

RX merge: `receive`は全portを一回ずつpollし、開始portはbatchごとに一つずつrotateします。各pollは
そのportのcompletion reap、Fill refill、残りbudget以下のRX descriptor検証を行い、budgetを使い切った
後のportもbudget 0でpollされreap/refillだけを行います。batchは同じ順にportごとのpending frameを
lendします。batch終了時にlendしなかったframeはengineのpendingに残り、次のbatchが新しいdescriptorより
先にlendします。Fill need-wakeupが立っていればそのportへ`poll(timeout 0)`のkickを一回送ります。

cross-port TX: port Aで受けたframeはAのUMEMにあり、portごとにUMEMが別なのでBのTX descriptorは
それを指せません（shared UMEMのcross-port zero-copyはXDP-136でdeferred。merge blocker 4のsingle
owner証明が要ります）。そこでegressがingressと異なるcommitは、egress engineのgenerated poolから
同じ長さのframeを取り（ここだけは直後に全visible byteを上書きするのでzero化を省く
`ZeroFill::Overwritten`）、visible bytesを一回だけcopyしてBのTX ringへcommitし、AのRX frameを
recycleします。costはcross-port packetごとに一回のframe長`memcpy`と、in-flight中のBのgenerated
frame一つです。copyはegress portの`cross_port_copies`に数えます。egressがingressと同じなら
X02のsame-frame TX（`forwarded_in_place`）です。

generated reserve: 持続的なcross-port trafficがegressのgenerated poolを使い切るとrouter生成の
ARP/ICMPが毎tick `Unavailable`になりneighborがexpireするので、copyはpoolの最後の
`generated_reserve(pool) = max(2, pool / 8)`（poolで上限）frameを取りません。reserveに食い込む
copyは`cross_port_copy_reserved`、poolが空なら`cross_port_copy_unavailable`で拒否し、blockしません。
router生成（`begin_generated`）はreserveを含むpool全体を使えます。複数portのadapterでは、
reserveがpool全体になる0〜2 frameのpool（cross-port copyが一度も届かない。0は`UmemConfig`が先に拒否）を
`GeneratedPoolTooSmall`でsetup時に拒否します（一portなら受理）。`begin_generated`はallocation前に
egress portをsettle（completion reapと負っているkick）するので、完了したframeはその場でpoolへ戻ります。
reserveはportのstats（`copy_reserve`）に出る定数式で、configは持ちません。

TX length bound: forwarded/generatedともTXはegress portの`mtu + 14`（`XdpPortConfig::max_frame_len`、
VLANはM2 profile外）以下に限ります。MTUは`NativeSession::open`がTX queue checkと同じifindex確認済み
sysfs view（`/sys/class/net/<dev>/mtu`、safe std）からresource取得前に一回読み
（`SessionStage::MtuProbe`、読めなければ`SessionFailure::MtuUnverifiable`でfail closed）、
`NativeSession::mtu()`と`XdpPortConfig::from_session`で渡します。configにMTUは無く、kernelのMTUが
実際にcopy-mode TXを決めるためsysfsを選びました。超過したforwarded frameはdescriptorを書く前に拒否して
（`tx_over_mtu`、`tx_rejected`、errorなし）ingressのframeをrecycleし、generatedは`FrameTooLarge`
（`generated_over_mtu`）です。実効上限はframe容量（frame size − headroom）でも切ります。Linux
copy-mode transmitはover-MTU descriptorをcompletionなしで消費し得るため、frameが`TxOwnedByKernel`の
まま残るのを防ぎます。open後のMTU減少は見えないので、その場合はstranded descriptorが再び生じ、
in-flightが残る限りpublicationを全体で延期し得ます（X04b、XDP-157）。

kick policy: portはTXがin-flightの間kickを負います（`kick_owed`）。受理されたsubmitごと、deferred/
失敗したkickの後に立ち、batchの開始ではresetせずbatchをまたいで保持し、in-flightが0になったときだけ
消えます。負っているportは`finish`（batchのdropは`finish`後には何もしない）、`finish`なしのbatch drop、
`receive`、`begin_generated`、`service`、quiescence check、そしてbatch内でそのportのsubmitが最初に
back-pressureで拒否された直後（portごとbatchごとに一回だけ。後の拒否はbatchのsettleに任せる）に
settleされます。settleはcompletionをreapし、in-flightが残り、TX need-wakeupが`NotRequired`でなく、
kernelがまだ消費していないTX descriptorがある（`tx_unconsumed() > 0`）限りkickしてまたreapすることを、
一回あたり`ceil(in_flight / 32) + 2`回のkick以内で繰り返します。kickはkernelにdescriptorを消費させる
ことしかできないので、全部消費済みでcompletionだけが遅れている場合（NICのTX interrupt coalescingや
zero-copy）はkickせずdebtを残し、以後のsettleはreapだけをします（以前はこの状態で毎settle予算を使い切り、
blockされたsubmitごとにも繰り返して2048 entry ringで一tick約4.3k syscallになり得た）。Linux v6.8 copy modeは一回の`sendto`で最大
`TX_BATCH_SIZE`（32）descriptorを送りまだ残れば`EAGAIN`を返すので、60 frameのbatchは`finish`の中の
二回のkickで全部completionまで進みます（以前は32で止まり残りは次のtrafficを待った）。`ENETDOWN`
（link down）はerrorではなくportのlink state（stats `link_down`、`kicks_link_down`）で、kickは負った
ままなので、linkが戻れば新しいtrafficなしに次のsettleで回復します（以前はlink flap後にportが永久に
止まり、generated poolもin-flightのままARPが消え、quiescenceが`TxInFlight`のまま全publicationを
延期した）。それ以外のkick失敗（`EINVAL`等）はbatch errorですがstickyではありません。budgetを使い
切ってin-flightが残れば`kick_budget_exhausted`に数えます。kick数とdeferred数はengineの`tx_kicks`/
`kicks_deferred`です。

error mapping:

| engine | core | finish error |
|---|---|---|
| `TxBlocked::{RingFull, InflightLimit, Draining}`（forwarded/copy/generated） | `tx_rejected` / `rejected`（handoffはcancelでpoolへ、portを即settle） | なし（back-pressure、`tx_blocked`/`generated_tx_blocked`） |
| unknown egress、over-MTU、reserve/空poolによるcopy拒否 | `tx_rejected` | なし |
| `GeneratedAllocError::Unavailable` | `Unavailable` | なし |
| `Rejected(ZeroLength)` | `ZeroLength` | なし |
| `Rejected(TooLarge)`、MTU超過 | `FrameTooLarge` | なし |
| `Rejected(BelowMinimum)`（1〜13 byte） | `FrameTooLarge` | なし |
| `Rejected(Draining)` | `Unavailable` | `XdpIoError::Stopped` |
| `GeneratedAllocError::Ledger` | `Unavailable` | `GeneratedLedger` |
| `TxRejection::{Invalid, Ring}`（adapter自身のhandoff） | `tx_rejected` / `rejected` | `Submit`、adapter停止 |
| RX/Fill/Completion ring破損 | `receive`のErr | `Datapath`、adapter停止 |
| kick `ENETDOWN` | 影響なし（frameはin-flight、kickは負ったまま） | なし（`link_down`、`kicks_link_down`） |
| その他のkick失敗 | 影響なし（frameはin-flight） | `Kick`（stickyでない） |
| unknown egressの`begin_generated` | 各allocateが`Unavailable` | なし（`generated_unknown_egress`） |

coreに"too short"のvariantは無く、core generatorはEthernet header未満を要求しません。runtimeは
`Unavailable`以外のallocation errorをすべて同じに扱う（generated phaseを止め、そのtickの後続generated
phaseをgenerated failureとしてskip）ので、`BelowMinimum`を`ZeroLength`と`FrameTooLarge`のどちらへ
mapしてもruntimeの結果は同じで、最も近い`FrameTooLarge`へmapしcoreは変更しません。`Draining`は
drain後のadapterが`Stop`を返すためruntimeからは到達しません。finish errorはruntimeが全portの
generated ARP/ICMPをskipする原因になるので、本物のfaultだけに限ります。link downは一portの状態で
あってerrorではありません。device削除後の`ENXIO`のような`ENETDOWN`以外の持続的なkick失敗は毎tickの
batch errorになり、quiescenceは`ContinueOldIo`のままです（device削除の扱いはX04b、XDP-157）。
unknown egressのsessionはbatch errorを出しませんが、runtimeは最初の
`Unavailable`でそのtickのARP phaseを止めます（head of line）。これはcoreを変えずには避けられないため、
X04bがsnapshotのinterfaceと同じvalidated configからportを作り、runtimeが要求する全egressにportがある
ことを保証します。

leaked lease/batch: slotが貸すleaseは`RawLease`（engine identity + token + descriptor、move-only、
crate private）としてbatchではなくadapterに記録されるので、`mem::forget`したslotや丸ごと忘れた
batchのframeは次の`next_packet`/`allocate`/`finish`/batch drop/`receive`/`begin_generated`/
`service`/quiescence checkが回収します（engineの`rx_abandoned`/`generated_abandoned`とadapterの
`leases_reclaimed`。RXは`recycled`に入れず、同じbatch内のgeneratedは`abandoned`に入れて三つの不変
条件を保ちます）。忘れたbatchのkick debtもportに残り次のsettleが払います。`RawLease`の全使用
（byte access、resume）はengine identityをalways-onで確かめ、別engineのleaseはpanicします
（同じ`UmemDomainId`で同じtokenでも）。batchを通ってpanicがunwindした場合はleaseやhandoffが操作途中で
残り得るので、adapterを`Stop`にしてfail closedし、unwind中はそれ以外何もしません（lease invariantの
assertが原因のpanicで回収が同じassertを再び踏みprocessがabortするのを避けるため）。記録された
leaseは後の`drain`が回収します。

quiescence: batchはadapterを可変借用するので`try_publication_quiescence`を呼べる時点でbatchは開いて
いません。leaked leaseを回収し、全portをsettle（reapと負っているkick）してから、各portで両poolのlent
frameなし、stageされたhandoffなし、TX in-flightなしを要求します。in-flight TXはactive publicationで
書き換えたbytesを運ぶのでpublicationを延期しますが旧publicationのI/Oは続けられる（`TxInFlight` →
`ContinueOldIo`）、engine-levelでしか起きないlease/handoffの残存は`SkipIo`、drainかfault後は`Stop`
（sticky）です。`current_io_disposition`は回収可能なleaked lease（adapterが記録しているもの）を
strandedと数えず`ContinueOldIo`を返すので、次の`receive`が回収できます。lendしていないRX pending
frameはpublication authorityを持たないので妨げません。

`BackendStats`（OBS-018）: `NAME = "af_xdp"`、`MODE = BackendMode::Copy`です。`MODE`は型としての
静的な主張で、bind modeはportごとにopenで交渉され`auto`はcopyへfallbackし得てportごとに異なり得るので、
保証できるのはcopyだけです。portが実際に交渉したmodeは実行時のdataで、statsの`copy_ports`/
`zero_copy_ports`/`mode`（`copy`、`zero_copy`、`mixed`）と`XdpPortStats::mode`を読みます。
`backend_stats`は全portを合計した`XdpBackendStats`（port数、mode別port数、need-wakeupが今立っている
port数、link downのport数、kickを負っているport数、kernel statsを読めたport数、
`generated_unknown_egress`、`stopped`、`XdpCounters`）を、`port_stats(IfId)`は一portの
`XdpPortStats`（interface、queue、mode、MTU、実効`max_frame`、Fill/TX need-wakeupの現在値、draining、
`link_down`、`kick_owed`、`copy_reserve`、kernel `XDP_STATISTICS`、`XdpCounters`）を返します。どちらも
allocationなしのO(ports)で固定順の`ObservableFields`です。kernel statsはportごとに一回の
`getsockopt(SOL_XDP, XDP_STATISTICS)`（seam経由、fd/長さのalways-on check、Linux v6.8の48 byte
`struct xdp_statistics`と完全一致する長さだけを受理。将来のkernelで構造体が大きくなれば48 byteの
要求は拒否され、kernel statsはfail closedで`kernel_stats_available = false`）をstats呼び出し時
（cold path）にだけ行い、
packet pathでは読みません。`XdpCounters`はRX/Fill（polls、rx_packets/leased/recycled/abandoned、
rx_ring_empty、rx_backlogged、runt、reason別invalid descriptor、fill_published/starved/ring_full/
need_wakeup/flag_errors/suppressed_draining）、TX/Completion（tx_submitted、tx_ring_full、
tx_inflight_limited、tx_refused_draining、tx_completed、reordered、completion_backlogged、invalid
completion、tx_need_wakeup、flag errors、kicks、deferred、kick errors、drains、gauge `tx_inflight`、
high-water、最古in-flight frameのpoll年齢のcompletion lag）、ring占有gauge（Fill占有、未読RX、kernel未消費
TX。各一回のatomic load）、quarantine（両pool合計の`frames_quarantined`、generated poolの現在数、
`generated_quarantined_after_tx`）、generated（allocated/unavailable/committed/cancelled/abandoned/
completed/rejected、gauge inflight。cross-port copyを含む）、adapter（forwarded_in_place、
cross_port_copies、cross_port_copy_unavailable、cross_port_copy_reserved、tx_over_mtu、tx_blocked、
tx_unknown_egress、generated_over_mtu、generated_tx_blocked、leases_reclaimed、kicks_link_down、
kick_budget_exhausted）、kernel（rx_dropped、rx_invalid_descs、tx_invalid_descs、rx_ring_full、
rx_fill_ring_empty_descs、tx_ring_empty_descs）です。合計はsaturating、high-waterとlagは最大値です。

#299 follow-up: `GeneratedCounters::generated_quarantined_after_tx`を追加し、
`generated_committed = generated_completed + generated_inflight + generated_quarantined_after_tx`を
counterだけで閉じました。`RxFillCounters::frames_quarantined`は両poolのquarantineを数え、
`GeneratedAccounting::quarantined`がそのgenerated分です。他engineのgenerated handoff
（`ForeignTokenDomain`、同じ`UmemDomainId`でも）と一batch内の重複generated handoff（`WrongState`）の
拒否をregression testにしました。

conformance: `ruster-io-conformance`のRx（`RxHarness`にdefault付きの`COMMIT_EGRESS`と
`MIN_FRAME_LEN`を追加。既存harnessはWAN/1 byteのまま不変）、Generated、CQ/finite-pool suiteを二つの
scripted kernel上のadapterで実行します。Rx caseはsame-frame in-place pathを記述するのでingress自身
（`CONFORMANCE_LAN`）へcommitし、marker frameをEthernet header長までzero paddingします。cross-port
commitのcopy、reserve/空poolによる拒否、そのcounterはsuiteの対象外で、専用のadapter test（XDP-134、
XDP-160、XDP-165）が担います。harnessはTX submissionをscripted kernelのTX ringから、ringに現れない
reclaimと事前拒否をadapterの`cfg(test)` journalから観測し、free poolはengine ledgerから読みます。
accept budgetは本物のback-pressureで、kernelが消費してcompletionを返さないfiller generated frameで
TX in-flight上限をbudget分だけ残します。finish errorは次のTX kickを`EINVAL`で失敗させます
（`ENETDOWN`はerrorでなくlink state）。generated allocation budgetはadapterの`cfg(test)` gateです。
`RxReceiveErrorHarness`（receive errorはring faultでadapterが停止するのでretry caseに合わない）と
`GeneratedUnknownEgressHarness`（unknown egressは何もallocateしない）は実装しません。harnessは
adapterへ`'static`借用を与えるためkernelをleakするので、Miriはこのharness testをskipし、同じpathを
借用kernelで通す`packet_io_tests`をMiriで実行します。scripted kernelはTX kickでLinux copy modeの送信
roundを再現でき（一kick最大32 descriptor、残れば`EAGAIN`、link downなら`ENETDOWN`）、kernel
`XDP_STATISTICS`もscriptします。

privileged smokeのadapter phaseは専用netns内の二つの1-queue veth pair（`rx00c4`/`rx00c5`、
`rx00c6`/`rx00c7`）を`from_session`のconfigでcopy mode・native attachの二portとして一つの
`XdpPacketIo`に渡し、Aのpeerから AF_PACKETで送ったIPv4/UDP frameをcore `forward_batch`（実MACの
snapshot、static neighbor）で転送し、Bのgenerated poolへのcopyがBのpeerにMAC書き換えとTTL−1、
正しいIPv4 checksum、不変payloadで届くことを確認します。続けて実kernelの`XDP_STATISTICS`をstatsで
読み、Bで60 frameのgenerated burstが`finish`だけで全部completionまで進むこと（二回のkick）、Bを
`ip link set down`（netns内）した間のTXが`ENETDOWN`のlink stateになりerrorにならず、`up`後は新しい
trafficなしにquiescence checkだけでreadyへ戻ることを確認してから両portをdrainします
（XDP-133〜174、IO-013、OBS-018）。

#300 follow-up（M2 S10a）: once-per-batch relieveの`relieved`が`receive`と`begin_generated`で
batchごとに再armされること（XDP-175）と、`finish`が`self`を消費した後の`Drop`が二度settleしない
こと（XDP-176）をtestで固定し、`GeneratedPoolTooSmall`の説明を「0〜2 frame」に直しました。

### `ruster run` (X04b前半, M2 S10a)

`ruster run --config <path>`はx86_64 LinuxのAF_XDP static routerです（他のplatformはconfig検証後に
`unsupported platform`でexit 1）。`ruster-cli`の`run` moduleは起動、run loop、停止をhost
（`PortHost`: preflight、open、inspect、attach、build、close）とdatapath（`Datapath`: core I/O、
drain、stats）、clock、停止flagについてgenericに書き、本番は`LinuxHost`（`NativeSession`、
`RxFillEngine`、`XdpPacketIo`）、testはscripted host（`SimIo` datapath、scripted clock/停止）です。

```text
config validate ─► [backend] af-xdp? ─► signal handler ─► OsRandomKeySource ─► ProductionSequencer
   ─► candidate (generation 1) ─► FullServiceStorage ─► privilege/memlock preflight
   ─► port if1: open ─► XDP-063 checks ─► attach      (IfId順。失敗/停止なら開いた全portを逆順close)
   ─► port if2: open ─► XDP-063 checks ─► attach
   ─► take_datapath/engine (if1, if2) ─► XdpPacketIo ─► activate generation 1 ─► run loop
SIGINT/SIGTERM ─► tick停止 ─► bounded drain ─► final stats取得 ─► adapter/engine drop
   ─► close if2 ─► close if1（各closeはlink closeでdetachしてからsocket/UMEM/ringを解放）
```

起動（failure atomic）: configは`run-sim`と同じlimitでparse/validateし、service bridgeは本番
candidateの構築で一回だけ行います（sim key sourceの捨てcandidateは作らない）。`[backend]`が
`sim`なら`stage=backend code=SIM_BACKEND`で`ruster run-sim`を案内しexit 2です。key sourceは
`OsRandomKeySource::open()`だけで、`run::execute`は`ProductionSequencer<K: ProductionKeySource>`を
受け取るためsim sourceは型で入りません。preflightは`CapEff`に`CAP_NET_ADMIN`、`CAP_NET_RAW`、
`CAP_BPF`+`CAP_PERFMON`（または`CAP_SYS_ADMIN`）を、`CAP_IPC_LOCK`が無ければsoft
`RLIMIT_MEMLOCK` ≥ UMEM合計（page切り上げ、`auto`は2倍、XDP-045）を要求し、不足はresource取得前に
exit 4です。portは`IfId`順にopen（session自身のTX queue/MTU check込み）、XDP-063 check、
configのattach mode（既存programは`ExistingProgram`で拒否し置換しない）の順で、全portのattach後に
各sessionのdatapathを取りengine（`fill_batch` = Fill ring容量、UMEM domainはportの`IfId`から
一意）と`XdpPacketIo`を作り、generation 1をactivateします。engineはsessionを生涯可変借用し
attachも`&mut`を要するので、datapathは全attachの後です（kernel資源を取らない段階で、Fillへ
publishするまでのframeはXDPがsocketへ送りkernelが`rx_fill_ring_empty`で捨てる。kernel stackへは
届かない）。開いたsessionは`OpenedPorts`が所有し、どのstageの失敗でも（stage間で停止flagが立って
も）開いた全portを最後に開いたものから一回ずつcloseします。closeはlinkを先に閉じるので
XDP programは残りません。errorは`startup failed: stage=<stage> [port=if<id>] code=<typed>`
（session/attachは`<stage>/<failure>`、verifier logは長さとtruncationだけ）です。

XDP-063 device check（session open後、attach前）: sessionのifindexをrtnetlink `RTM_GETLINK`で問い合わせ
（netlink socketは常に呼び出し側のnamespace。M2 S10bでsysfsから移行）、RX queue数（`IFLA_NUM_RX_QUEUES`、
driverが確保した数）が1でなければ拒否します。同じ返答のMTUがsessionの読んだMTUと違えば
`UNVERIFIABLE probe=mtu`、MTU + 14がUMEM frameに収まらなければ`MTU_ABOVE_FRAME`です。RSS/ntupleで全
trafficをbind queueへ寄せたoperatorだけが`--allow-multi-queue`で受理できます（warning）。kernel IPv4
address（rtnetlink `RTM_GETADDR` dump、labelに依らずifindexで数える）とportを出口にするmain tableの
IPv4 route（`/proc/net/route`）は拒否、`net.ipv4.ip_forward`と`conf/<dev>/forwarding`はwarningだけです。
拒否の理由: attach中はkernelがportのframeを見ないのでaddressは働かず、detach中（起動前、停止後、
crash/SIGKILLでunpinned linkがauto-detachした後）にkernelがARPに答え、forwardingが有効なら
firewall/NATを迂回してport間をroutingします（fail open、XDP-050）。forwarding sysctlはnamespace
全体の設定で他のinterface（container、VPN）が必要とし得るうえ、port上にaddress/routeが無ければ
kernelはportへのconnected routeを持たないので、拒否は過剰としてwarningにしました。読めないfactは
fail closed（`UNVERIFIABLE probe=...`）です。

run loop: 一threadが停止flagを読み、`Instant`起点のmonotonic wall clockで`run_tick`をconfigの
budgetで呼び、reportを`TickObserver`へ畳み、O(1)のstate table占有を記録します。kickとneed-wakeupは
adapterの`receive`（completion reap、Fill refill、Fill need-wakeupへの`poll`、負っているTX kickの
settle）と`finish`が扱います。RXも生成TX要求も無いtickが64回続くと50 µsからtickごとに倍、上限1 msの
sleepを挟み、busyなtickで即spinへ戻ります。idle時のwake-upは約1 kHzでcoreを使い切らず、idle後の
最初のframeは最大1 ms（+timer slack）RX ringで待ちます。1 msなら2048 entryのRX ringは約2 Mppsまで
取りこぼさず、負荷中はsleepしません。socket fdの`poll`待ちはnative crateに複数fdのsyscallが要るので
deferred（CLI-034）です。tickごとのallocationは0（counting allocatorのtest。health/link watchを毎tick
走らせても0）。backendが自らStop（ring破損等）を
報告するとloopを抜けexit 1です。`--stats-interval`（既定60 s、0で無効）ごとにstdoutへ
`ruster-run-stats kind=periodic`のblock（worker observability、service counter、`af_xdp.*`、
`if<id>.af_xdp_port.*`の`section.key=value`、`end`）をcold pathで出します。counter、gauge、flag、
固定label、generation、`if<id>`だけで、address、MAC、device名、key、seedは出しません。

停止: 一回目のSIGINT/SIGTERMでtickを止め（RX、forward/生成TXとも以後なし。tick間なのでbatchも
caller保持のleaseも無い）、`XdpPacketIo::drain`を一回4 round、1 ms間隔、全体2 sまで繰り返します
（RX/Fill/新規TXを永久に止め、leaked leaseとstaged handoffを回収し、未lendのRX frameを戻し、kickと
reapをする）。二回目のsignal（`FORCE`）はdrainを打ち切り、kick round 0の一回だけで停止と計数をします。
final statsを取り、active publication、adapter、engineをdropしてから全portを逆順にclose（link closeで
detach、socket/UMEM/ringを解放）し、final statsをstdoutへ、summary（`drain calls`、`completed`、
`rx-released`、kernelが持つ`tx-in-flight`、`tx-handoffs`、`fill-in-kernel`、`forced`、`timed-out`、閉じたport数）を
stderrへ出します。exit statusは0（clean。起動中のsignalでrollbackしたときも）、1（起動失敗、backend
fault、fatal health/device event、drain失敗、残ったTX handoff、close error）、2（usage、invalid config、sim backend）、3（期限またはforceでTXが
kernelに残った。detach/closeは済み）、4（capability/memlock不足、何も取得していない）です。

出力: stdout/stderrは`run::output`の別threadが書き、run loop threadは完成した行とstats blockを
容量64のqueueへ`try_send`するだけです。読まれないpipeで詰まっても溢れた分を捨てて`output.dropped`に
数え、tick、停止flag、drain、detachは出力を待ちません。終了時の出力待ちは最大1 sです。adapterのI/Oが
`BackendIoNotReentrant`で1024 tick連続skipされると（`SkipIo`のまま戻らない）backend停止とみなしexit 1、
summaryにはdrainが最後に見たkick失敗を`last-kick-error=`の型付きtokenで出し、`code=`はすべて
variant pathのSCREAMING_SNAKE tokenです。netlink dumpは送信元`nl_pid == 0`とこのsocketの
`nlmsg_pid`を要求し、`NLMSG_DONE`の負のstatusを失敗とします。memlock見積りは5.11前のBPF object分として
portごとに64 KiBを加え、それでも下限です。panicはunwindで`OpenedPorts`がportを閉じてからexit 101です。

M2 S10b（run-time operations、cold pathだけ）:

- 起動retry（XDP-045）: port openの`BIND/BUSY`、`REGISTER_UMEM/MEMLOCK_LIMIT`/`OUT_OF_MEMORY`、
  `ERRNO_11`だけを、開いた全portのrollback後に250 ms〜2 sのbackoffで`--startup-attempts`（既定3）まで
  やり直します。他の失敗は即終了です。
- SIGHUP reload: handlerは`RELOAD`へstoreするだけで、loopがtick境界で取り、起動と同じ
  `load_validated`経路（regular fileだけ、`O_NONBLOCK`）→ `ProductionSequencer`の新candidate →
  `ApplyPlan::for_active`（restart-requiredは拒否、dry run失敗は失敗）を通します。通ったcandidateは
  backendのquiescence probe（reapとkickを含むadapterのcheck、guardは即drop）がOKになったtickの
  publication phaseへ渡し、待つ間はRXを止めて最大200 msです。拒否・失敗は旧generationとstateを変えず、
  適用はPUB-006どおりNAT/FW/ARP stateをflushします。candidateをDeferredで捨てる`run_tick`の挙動に
  依存しないため、probeを先に行います。
- health watch（500 ms）: `XdpPortStats`から最古in-flight frameの提出poll（`polls - oldest_age`）が
  変わらない時間を計り、link up中に1 sでTX stall warning、10 sでfatal。Fill starvation（kernelの
  Fill 0、RXなし、free list枯渇）はwarningだけ、ENETDOWN以外のkick errorが5 s続けばfatal。
  閾値は`--tx-stall-warn-secs`/`--tx-stall-fatal-secs`/`--kick-errors-fatal-secs`（fatal 0でwarnだけ）。
  TX stallはPAUSE floodでwireから起こせるので設定可能にし、既定のfatalはforwarding既定拒否と
  kernel L3拒否によりexit後もfail closedであることを前提にしています（#302 sec M1）。
- link watch（1 s）: 起動時に開きkernel（pid 0）へ`connect()`した一つのrtnetlink socketと事前確保
  bufferでportのifindexを`RTM_GETLINK`し、続けて`RTM_GETADDR` dumpでkernel IPv4 addressを数えます。
  ENODEV（device削除）、startup未満のMTU、frame超のMTU、3回連続のquery失敗（address dumpとforwarding readも別々に数える）は
  fatal、link down/upとframe内のMTU上昇、run中に現れたportのkernel IPv4 addressとkernel forwardingは
  warning/recoveredだけです（attach中はkernelがportのframeを見ないので無害で、fatal exitのdetachこそが
  bypassを作るため。exit時は最後のroundで見えていれば警告行を出し、次の起動は拒否）。
- startup checkはkernel IPv4 forwarding（global/port）を既定で拒否し、`--allow-kernel-forwarding`で
  warningにします。`--strict-config-perms`は起動時とreload時にconfigの所有者とmodeを`fstat`で確認し、
  configは常に`O_NONBLOCK|O_NOCTTY`のregular fileとして読みます。reloadの`Applied`は権威的で、
  commit reportが無ければinvariant違反としてexit 1、停止時の待機中reloadは`STOPPED`として数えます。
- fatal eventはloopを`LoopEnd::Fatal{port, cause}`で抜け、SIGTERMと同じdrain/detach/closeの後exit 1。
  drainは誰もcancelできない失われたTX handoffを`tx_handoffs_outstanding`として報告し、0でなければexit 1
  （XDP-177）。

privilegeのdropと`poll`待機はdeferredです（CLI-034）。operator手順は[`runbook-m2.md`](runbook-m2.md)、
privileged E2Eは`scripts/priv-run-smoke.sh`（三つの専用netns、forward、SIGTERM、reload、link
down/up、MTU超過とdevice削除のfail closed、rollback、XDP-063、SIGKILL後のrestart）です（CLI-008〜059、
XDP-045、XDP-063、XDP-177）。
