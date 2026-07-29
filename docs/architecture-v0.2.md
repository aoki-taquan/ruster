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

fragment handling/reassembly、hairpinning、ICMP error translationとPMTU、TCP/ICMP query
NAT、static port forward、複数public address、port randomization/parity、full packet
filter/firewallはdeferredです。RFC 3022/4787/7857の全機能準拠は主張しません。

eager dynamic-cache scan/flush、unresolved packet hold queue、gratuitous ARP生成、
ARP Probe/Announcement生成、proxy ARP、VLAN、Address Conflict Detection、実装済み
Echo Reply/Time Exceeded/Destination Unreachable Network以外のICMP生成、firewall、
config parser、pcap、AF_XDP、DPDK、binary、thread、
benchmarkはこの
sliceのscope外です。

## backend progression

`ruster-io-sim`はRXとgenerated TXのFIFO、budget、max frame、allocation exhaustion、
cancel/abandon、partial TX/reject、finish errorを決定的に実装します。captureは
`FrameOrigin`でRXとgeneratedを区別します。RX/生成の`Vec<u8>`そのものをTX/dropへmoveし、
packet bytesをcloneしません。次の実I/O backendも同じlease contractを実装し、
backend固有pointerをcoreへ漏らしません。
