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

`receive`はbackend固有errorを返せます。`finish`はerror時にも失われないcompletionを
必ず返し、TX requested/accepted/rejectedを分けます。常に
`accepted + rejected == requested`で、reject slotはbackendがreturn前にrecycle/free
します。これによりAF_XDP ring fullやDPDK partial TXでもrequestを成功と誤認しません。

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
pressureは候補を保持し、publication、forward learning/static、authority変更は未queue候補を
cancelします。`reverse_arp_scheduled`はfailure dispatch自身が`Queued`/`RetryQueued`を作った
場合だけ増やします。同じactive tokenの`InitialQueued`/`Waiting`/`RetryQueued`を反復scanした
場合は`ReverseArpPending`であり、既存actionやtimer-generated retryを新規scheduleとして
二重計上しません。queue済みICMP actionはhistorical eventとしてcancelしません。

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

RFC 1812のerror suppressionとして、invalid/non-host/router-local source、IP
multicast/limited/prefix-network/directed-broadcast destination、Ethernet group destination、
noninitial fragment、ICMP error Types 3/4/5/11/12、protocol 1でtype byteが無いpacket、
reverse route/interface/binding/neighbor不在では生成しません。first fragment
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
`Nat44UdpRuntime::reconcile`でmapping/peerを全flushします。旧generationのpeerが新mappingを
許可することはありません。

mapping keyは`(inside IfId, internal IPv4, internal UDP port)`でremote endpointを含めない
Endpoint-Independent Mappingです。別のremoteへ送っても同じpublic tupleを使います。
filter peerは`(mapping slot, mapping generation, remote IPv4)`で、既知IPの任意remote UDP
portを許し、未接触IPをbyte不変dropします。outboundでpeer slotを確保できなければmappingを
refreshせずdropし、filterを緩めません。live mappingをevictせず、port overloadもしません。
内部portがpool内かつfreeなら保存し、それ以外はcaller seedを混ぜたstartからinclusive poolを
一周だけscanします。randomness、parity、low-class preservationは保証しません。

対象packetの順序は次です。

1. common Ethernet/IPv4 validationとoptions rejection。
2. outboundはoriginal destinationのLPM、TTL、selected outside egress、static/fresh dynamic
   neighborを先に確定。source reverse-LPMがinsideであることを確認。
3. inbound public UDPはlocal deliveryより先にinterceptし、mapping/ADF lookup後、
   translated internal destinationを通常LPMしinside neighborを確定。
4. DF=1/MF=0/offset=0、UDP header/length、全offset、mapping/peer/port transactionを
   mutationなしでplan。
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
RFC 6864 atomic datagramとして保存します。

fragment handling/reassembly、hairpinning、Type 3/Code 4以外のICMP errorとICMP query
NAT、static port forward、複数public address、port randomization/parity、minimal
stateful sliceを越えるfull packet filterはdeferredです。RFC 3022/4787/7857の全機能準拠は
主張しません。

## Outbound-initiated TCP NAT44/NAPT vertical slice

TCP serviceはRFC 3022のtraditional NAPT tuple rewrite、RFC 5382/7857のtimerとmapping/filter
用語、RFC 9293のTCP header、RFC 1624のincremental checksum、RFC 6864のatomic datagram
profileを参照する限定実装です。RFC 5382全体への準拠は主張しません。

`Nat44TcpRuntime`はUDP runtimeとstorage、generation、watermark、allocatorを共有しない
`!Send + !Sync` worker-local ownerです。mapping keyは
`(inside IfId, internal IPv4, internal TCP port)`、session keyは
`(mapping slot, mapping generation, remote IPv4, remote TCP port)`です。複数remote sessionは
同じpublic tupleを再利用しますが、inbound filterはremote address/portのexact matchであり、
RFC 5382が推奨するEndpoint-Independent FilteringやAddress-Dependent Filteringより厳しい
connection-dependent local policyです。protocol-dependent tableなのでUDPとTCPは同じ数値
public portを同時に所有できます。

新mapping/sessionを作れるpacketはinsideからoutsideへ向かうSYN=1、ACK=0、RST=0、FIN=0
だけです。ECE/CWR、TCP options、SYN dataは許可します。既存exact sessionではflagによる
phase遷移を行わず、SYN retransmit、inbound exact SYN（basic simultaneous open）、
SYN-ACK、ACK/data、FIN、RSTを同じ規則で変換します。sequence number、receive window、
ACK妥当性を追跡しないため、flagだけを信頼したFIN/RST cleanupは安全ではありません。
このため全sessionはdefault/minimum 7,440,000ms（2時間4分）、設定上限7日間の単一idle
timerを使い、FIN/RSTも削除・短縮せずsuccessful TX request時にexact sessionをrefresh
するだけです。unmatched inboundはrefreshしません。exact boundaryでsessionがexpireし、
最後のlive linked sessionが無くなったmapping/public portだけが再利用可能です。

admissionとtransaction順はUDP profileに合わせ、次を追加します。

1. IHL=5、DF=1/MF=0/offset=0、protocol=6、IPv4 payload 20 bytes以上を要求する。
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
private sourceや外部から内部へのbypassを許可しません。runtime/config/snapshot mismatch、
hairpinはneighbor処理やstate変更より前にtyped dropします。

TCP fragment association/reassembly、hairpin translation、Type 3/Code 4以外のembedded ICMP
translation、static forwards、sequence/window validation、full RFC 5382 lifecycle、
safe FIN/RST cleanupはdeferredです。

## NAT44 ICMPv4 Fragmentation Needed translation

`Nat44UdpPolicy`または`Nat44TcpPolicy`の`icmpv4_errors`を`ExternalOnly`へ明示設定した
serviceだけが、outside ingress/public IPv4宛てICMPv4 Type 3/Code 4をlocal consumeより前に
interceptします。default `Disabled`は従来どおりunsupported local controlとしてconsume
します。combined serviceでは引用protocolに対応するpolicyだけがopt-in判定を所有するため、
UDPだけを有効にしてもTCP引用をinterceptせず、その逆も同じです。Type/Codeと引用protocolの
peekはouter IPv4 Total Length内だけで行い、link paddingをcandidate bytesとして扱いません。
対象はouter IHL=5、nonfragment、TTL>1、valid ICMP checksumと、validなIPv4 headerを含む
引用です。引用datagramはDF=1/MF=0/offset=0、UDPまたはTCP、public sourceで、IPv4 headerと
transport先頭8 bytesが実際に存在することを要求します。

RFC 5508 REQ-3に従いouter ICMP checksumと引用IPv4 checksumを検証し、引用IPv4 optionsを
IHLで越えてtransportを探し、embedded transport checksumそのものは検証しません。outer
sourceはhost-unicast、router-localでないこと、outsideへreverse LPMされることを要求します。
これはRFC 1812 §5.3.8を根拠にしたlocal strict-uRPF anti-spoof policyであり、asymmetricな
external pathを意図的に拒否するtradeoffがあります。0/8、127/8、multicast、240/4、
limited/selected-prefix network/broadcast、inside/local sourceはstateやresolutionを変更せず
dropします。RFC 5508 REQ-4のexternal-realm profileとして、validな中継router sourceは
引用remote addressと一致する必要がなく、translation後も不変です。

UDPはpublic source portのlive mappingと同generationのremote destination IPv4 ADF peerを
authorityとし、引用remote portはfilter keyにしません。TCPはpublic source portのlive mapping
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
Type 3/Code 4生成はまだありません。DF=0 packetの必要なfragmentation、private→externalの
RFC 5508 REQ-5、hairpin ICMP errorのREQ-7、他のICMP error type/code、ICMP query NAT、
RFC 4884 full supportもdeferredです。

## Minimal IPv4 stateful forward firewall

firewallはopt-inの追加serviceであり、既存`forward_batch*` APIとdefault forwardingを変更
しません。`forward_batch_with_firewall`はplain forwarding、combined APIはUDP/TCP NAT44と
同じworker-local RX transactionで合成します。対象はrouterを通過するunfragmented IPv4
UDP/TCPだけです。ARP、ingress-scoped router-local IPv4、RX phase後に実行するrouter-originated
generated packetはfirewall domain外です。options、reserved flag、MF、nonzero fragment
offset、TCP/UDP以外のforward protocolはsilent typed dropで、ICMP/RSTを生成しません。
RFC 791のfragment fieldsでMF=0/offset=0なら、DF=0とDF=1のどちらもunfragmented datagram
として許可します。ここでRFC 6864のatomic datagramという用語は使いません。

ruleはstable `FirewallRuleId`を持つimmutable sliceで、ingress/egress `IfId|Any`、
canonical source/destination prefix、TCP/UDP、inclusive source/destination port range、
`AllowStateful|Deny`を持ちます。順序どおりfirst-matchし、matchなしはimplicit default deny
です。overlapは順序の意味を持つため許可し、duplicate ID、unknown interface、
noncanonical prefix、reversed range、invalid timeout、zero config generationはpublication
前に拒否します。同一generationと同一rules/snapshot identityのreconcileはno-op、
同一generationの別identityとgeneration regressionは拒否し、forward generationは全stateを
flushします。snapshotのcontent fingerprintとslice identity、rule fingerprintはpublication
時に一度だけ計算してconfig/runtimeへbindし、packet pathのauthority確認はpointer/length/
fingerprintのO(1)比較です。packetごとのsnapshot再hashやrules slice equalityは行いません。

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
forward/reverseで同じcanonical hashを使うlinear open addressingで、established lookupは
cluster終端のempty slotまたはcapacityまでのbounded probeです。new flowだけordered ruleを
scanし、first expired tombstoneをreuseします。live evictionはなく、zero/full capacityはtyped
dropです。probe数とrule evaluation数はcounterで観測できます。

runtime/config/snapshot authorityとIPv4/transport structural/checksum validationはLPMより前に
行います。valid attemptはstate/NAT lookupより前にworker-local security watermarkを単調更新し、
rule/default deny、state full、route/neighbor/NAT missでも戻しません。そのためfuture時刻のdeny
やmiss後に古い時刻でflowが復活することはなく、古いpacketはbyte/state/activity不変の
`FirewallClockRegression`またはNAT clock regressionになります。FW opt-in時のLPM missは
egress不明のためrule評価せず`FirewallRouteUnavailable`でsilent dropし、Type 3/Code 0やARPを
queueしません。NAT inboundもFW state/rule判定をTTL判定より先に行います。

planはflow stateを変更せず、runtime epoch、config generation、slot generationを保持します。
commitはrelease buildでも三者を検証するtyped `Result`で、reconcileはepochを進めるため、
reconcile後またはslot reuse後のstale planをcommitできません。直列packet pathではvalidation、
NAT authority、LPM、FW rule/state、TTL/neighbor、rewrite preflightが成功してbytesを更新した
後にchecked NAT/FW commitを行い、TX requestします。同batchの次packetは直前commitを参照でき、
backend rejectでもTX-request stateを保持します。deny、route/neighbor/NAT/rewrite failureでは
FW flowを作りません。

audited APIはcaller-backed fixed `FirewallAuditBuffer`へ、policy evaluationへ到達した各packetの
`Allow|Drop`、`New|Established`、`Rule(FirewallRuleId)|Default`を順番に記録します。buffer不足は
typed overflow countになり、hot pathにheap、`String`、trait objectを導入しません。

NAT inbound mapping/sessionがあってもexact reverse FW stateが無ければinside neighborより前に
denyします。NAT/FWどちらかのcapacity plan failureでも他方をcommitしません。NAT44 ICMPv4
Type 3/Code 4のquoted canonical tupleをread-only RELATED lookupする機能はdeferredです。
firewallとopt-in NAT ICMP translationを同時に選んだcandidateは、追跡済みであっても現在は
`FirewallRelatedIcmpv4Unsupported`で明示的にfail closedし、NAT/FW state、phase、watermarkを
refresh/deleteしません。

eager dynamic-cache scan/flush、unresolved packet hold queue、gratuitous ARP生成、
ARP Probe/Announcement生成、proxy ARP、VLAN、Address Conflict Detection、実装済み
Echo Reply/Time Exceeded/Destination Unreachable Network以外のICMP生成、
firewall conntrack helper/application inspection、config parser、pcap、AF_XDP、DPDK、binary、thread、
benchmarkはこの
sliceのscope外です。

## backend progression

`ruster-io-sim`はRXとgenerated TXのFIFO、budget、max frame、allocation exhaustion、
cancel/abandon、partial TX/reject、finish errorを決定的に実装します。captureは
`FrameOrigin`でRXとgeneratedを区別します。RX/生成の`Vec<u8>`そのものをTX/dropへmoveし、
packet bytesをcloneしません。次の実I/O backendも同じlease contractを実装し、
backend固有pointerをcoreへ漏らしません。
