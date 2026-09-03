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
read-onlyで検証します。state側の`action_slot`とaction側の`state_index`を双方向backreferenceとして
相互検査し、action arrayを2回、state arrayを1回だけ訪れるためpreflightは`O(A + S)`です。nested
searchはなく、exclusive permitのtotal commitも各arrayを1回clearする`O(A + S)`処理でqueue、limiter、
head/len、watermarkを全flushします。累積counterは保持し、permit Dropとtail backreference corruptionを
含む全preflight errorはruntime不変です。x86_64の現layoutではこのbackreferenceにより
`Icmpv4ErrorStateSlot`は24から32 bytes、`Icmpv4ErrorActionSlot`は584から592 bytesへ各8 bytes増えます。
config/control/integrationのrequired runtime byte計算は`size_of`を使うため、このlayoutへ自動追随します。

worker tick順は `publication/reconcile → RX → resolution timer poll → failure dispatch →
generated ARP → generated ICMP` です。exact timeoutでのARP学習は、ICMP actionがqueueされる前
なら `poll → learn → dispatch` と `learn → poll` の両方で勝ちます。

`ruster-config`はpublication型、generation、hash keyを知りません。`ValidatedConfigV1::into_parts`は、
validated config全体を分解するpublication非依存のtop-level consuming transfer seamです。返される
`ValidatedConfigV1Parts`はpublicな`#[non_exhaustive]` move-only transfer objectで、これはdownstreamの
additive API boundaryです。このboundary自体を、nested inventoryが自動的に全てplannerへ届く証明とは
解釈しません。top-level partsの`into_planning_parts`はcurrent fieldsをnamed tupleへexactに返し、
そのcurrent inventoryは`interfaces/core_interfaces/routes/neighbors/local_ipv4/ipv4_origin`、
`resolution/icmpv4_errors/nat44/firewall`、`tick/storage/required_runtime_bytes`です。control plannerは
その返り値をexactにdestructureします。

config-owned nested seamは別の責務を持ちます。Resolution/ICMPv4 errorのpolicy+storage、UDP/TCP NATの
inside/outside/public address/port range/policy/storage、UDP/TCP pair、firewallのrules/policy/state_slots、
tickの5 budget、および5 realmとrequired bytesを含むruntime storage shapeの各`into_planning_parts`は、
current sourceの`Self`全field exact destructureで構成されています。具体的にはstorage shapeの
`states/actions/dynamic_neighbors/failure_holds`（Resolution）、`states/actions`（ICMPv4 error）、
`mappings/peers/mapping_buckets/mapping_nodes/peer_buckets/peer_nodes/port_owners`（UDP NAT）、
`mappings/sessions/mapping_buckets/mapping_nodes/session_buckets/session_nodes/port_owners`（TCP NAT）、
`resolution/icmpv4_errors/nat44_udp/nat44_tcp/firewall_states/required_bytes`（runtime storage）と、tickの
`rx/resolution_timer_scans/failure_dispatch_scans/generated_arp/generated_icmpv4`を含みます。nested sourceへbehavior-bearing fieldを
追加すると、そのseam自身のexact patternを更新するまでcompile failureになります。seamの返却tupleへfieldを
追加すれば、control側のnamed exact return inventory destructureも更新を要求するため、未転送のまま黙って
捨てる経路を現在のplanner sourceは持ちません。これはcurrent sourceのcompile-time evolution boundaryであり、
任意のfuture implementationが正しく更新されることのruntime証明ではありません。

`ValidatedFirewallV1::into_rules(self) -> Box<[FirewallRule]>`は、上記planner inventoryとは別の、legacy
rules-only caller向けpublic compatibility seamです。このmethodも`rules`、`policy: _policy`、
`state_slots: _state_slots`をnamed bindingした全field exact destructureで、`rules`のBoxをそのままmoveして
返します。policyとstate_slotsを明示的にdiscardする意図はこのlegacy APIに限定され、`..`はありません。
従ってfirewall sourceへfieldが追加されればこのmethodもcompile failureになります。production plannerは
`into_rules`を使わず、`into_planning_parts`からrules、policy、state_slotsを全てpublicationへforwardします。

current value equality、Box pointer identity、source-contractの各testは証明範囲が異なります。nested transfer
testとtop-level transfer testはcurrent fixtureのpolicy/realm/storage/tick/bytesとowned Boxのidentityを実行時に
照合し、planner forwarding testはcandidate authority/shapeへ到達したcurrent nested valuesを照合します。
source-contract testはexact `Self` pattern、control return inventory、plannerが`into_rules`を使わないことを
source上で固定します。したがってこれらを組み合わせても、future fieldの任意の意味や全将来値をruntimeで
検証したとは主張しません。既存Boxはmove-onlyで再確保せず、pointer identity/no reallocationの範囲は
current transfer assertionに限定されます。publication generation、hash key、runtime authorityはcaller/control
またはintegrationの責務であり、config transferへ逆流しません。

`ruster-control`のcold full-service plannerは`ValidatedConfigV1`をconsumeし、caller-suppliedの
`NonZeroU64` generationとUDP/TCP/firewall typed hash keyを組み合わせます。Resolution、
ICMPv4 errors、UDP NAT44、TCP NAT44、firewallの順にservice presenceを確認し、欠落時はvalue-freeな
typed reasonと未変更のconfig/inputs ownershipをmove-only failureでcallerへ返します。確認後は
core interface、route、neighbor、local IPv4、firewall ruleのBoxをcloneせず、新規Box/Vecや
reallocationなしで`PublicationPlan`へmoveします。name/deviceを含むinterface metadata、tick budget、
required runtime bytesは同じgenerationを保持するprivate metadataへまとめ、private-fieldの
`FullServicePlanV1`がpublicationとのcoherentな組をopaqueに保持します。planner-produced
`FullServicePlanV1`からmetadataを保持して進む唯一のpublic consuming transitionは、
`ValidatedCandidate` authorityをmintして同じmetadataと不可分な`FullServiceCandidateV1`へ移します。
publication/metadataを個別に取り出すsplit APIはこのplanner pathへ公開しません。このtransitionは
failure時もplanをconsumeしてownershipを返しません。public `FullServiceCandidateError`は、process
lifetimeで再試行できないforwarding/firewall publication nonce exhaustionを区別します。
planner由来planに対するその他のcandidate validation errorは、caller-correctableなconfig errorではない
`InternalInvariantViolation`へcollapseし、lower-level `PublicationCandidateError`をこのplanner pathの
公開契約へ漏らしません。全variantはsource value、topology、hash keyを保持しないvalue-freeなterminal
authority-minting failureであり、activation/apply failureではありません。optional serviceを含まない
validated config自体の合法性は変更しません。

R10のstatic planningでは、`classify_successor`と`plan_successor`を候補判定と計画結果に分けます。
`classify_successor`はcurrent/next candidateだけを比較して`InPlaceEligible`、
`RestartRequired`、`Rejected`のstatic classificationを返し、`plan_successor`はその結果を
value-onlyでallocation-freeな`PlanOutcome`へ包みます。initial activationはprior candidateがないため
`InitialActivation`（diffなし、next generationあり）となり、successorの`InPlaceEligible`、
`RestartRequired`、`Rejected`は全て`PlanGenerationTransition`（previous/next generation）を持ちます。
successor outcomeは`Rejected`を含めてsemantic `PlanSectionDiff`を保持します。diffはinterface、route、
neighbor、local IPv4、origin policy、tick budget、Resolution/ICMP policy、UDP/TCP configとhash key、
firewall configとhash key、storage shapeを区別し、generation、nonce、snapshot authority、allocation
identity、rule fingerprint自体はsemantic sectionとして扱いません。

static successorのfirst-error orderはgeneration exhaustion、generation monotonicity、UDP→TCP→firewall
hash-key reuse、storage shape、Resolution policy、ICMPv4-error policyです。これらのguardが通った後に
interface bindingを分類します。従ってResolution/ICMP policy-only changeは`InvalidSuccessor`ではなくtyped
`RestartRequired`であり、policyとstorageなどが同時に変わる場合もdiff全体を保持します。このAPIは
candidate-onlyで、backend quiescence、active-failure latch、五runtime preflightを実行しません。
`InPlaceEligible`はactual publicationの許可証ではなく、integrationのpublicationはその後にこれらの
dynamic safety gateを実行して`Deferred`またはtyped rejectionになり得ます。

plannerはgeneration採番、key生成、乱数/syscall、semantic revalidation、runtime/backend accessを
行わず、caller keyのfreshnessも証明しません。全publication履歴に対するkey freshnessはcallerが
保証し、既存successor guardは直前candidateとのkey不一致だけを検査します。`ruster-control`自身は
live activation、runtime storage allocation、apply、rollbackを行わず、cold immutable candidate
境界を維持します。

`ruster-control`のstatic-only owned publication境界は、nonzero generation、固定runtime
storage shape、owned forwarding table、必須UDP/TCP NAT44 input、owned firewall rulesを
`PublicationPlan`へ集約します。`ValidatedCandidate`構築はfull-service presenceと全NAT
directory/node/port-owner shapeを先に検査し、`ValidatedForwardingOwner`を作ってからその
snapshotへUDP/TCP configと`ValidatedFirewallOwner`をbindします。plannerのzero-allocation契約は
zero CPU revalidationを意味せず、このauthority minting境界ではforwarding/firewall validationと
fingerprint/hash構築をcold pathで再実行します。dependent configとfirewall ownerをforwarding
ownerより先にdropするfield順で保持しますが、self-reference、leak、unsafe
pointerは使いません。`authority()`はcandidate lifetimeに制約されたsnapshot/config viewを
allocation、再validation、再hashなしのO(1)で返します。generation前進、直前candidateとの
UDP/TCP/firewall key不一致、固定shape/policyはstatic successor checkだけを提供し、ownerの
installやruntime変更は行いません。

`ruster-control`は`ActivePublication`、runtime adopt/apply、rollback、backend quiescence APIを
公開しません。Resolution/ICMP runtimeには旧snapshotのegress/MAC/IP authorityを持つqueueがあり、
shape/policy一致だけでsuccessorへ接続するとstale出力を許すためです。control crateは
`ruster-config`と`ruster-core`だけに依存し、runtime dependencyを持ちません。

`ruster-integration`はこのcold control境界を崩さず、`ruster-control + ruster-core +
ruster-runtime`へ一方向に依存するcomposition rootです。production constructorは
`FullServiceCandidateV1`にbindされ、Resolution 4、ICMPv4 error 2、UDP NAT44 7、TCP NAT44 7、
firewall 1の計21 backing arrayについてchecked concrete byte totalをcandidate metadataと照合します。
各arrayはfallibleなexact reservation後、capacityがrequested lengthと完全一致する場合だけboxed化し、
infallibleなshrink/reallocationを隠しません。storageのfieldsはprivateで、一つのcoherent setとして
activation ownerへ貸し出され、storageはownerの全runtime borrowより長生きします。

`activate_initial`はworker/backendがauthorityを使い始める前のcold boundaryです。shapeとbyte mismatchは
constructor開始前に検出し、storageを変更せずexact candidate ownershipを返します。成功時はResolution、
ICMPv4 errors、UDP NAT44、TCP NAT44、firewallをexternal storage上に構築し、candidateと五runtimeを
`FullServicePublicationOwner`へ不可分に保持します。initial ownerはbackend未指定のtypestateであり、
`bind_publication_backend`が同時発行したexact owner capabilityを`bind_backend<I>`へ渡した場合だけ
backend-bound typestateへ進みます。`bind_backend`はfallibleなchecked transitionであり、exact backend
identity照合、backendの`check_publication_quiescence`成功、owner post-guard match、`current_io_disposition`が
`ContinueOldIo`であることの全てを満たした場合だけbackend-bound ownerを返します。事前に受理済みのTXが
残るbackendやforeign backend、terminal `Stop`のbackendは`InitialBackendBindError`でfallし、
`InitialBackendBindFailure`はunbound ownerとbinding capabilityを`into_parts()`でretry可能な形のまま保持します。
これにより、new initial authorityがpre-binding work（quiescence未確認のbackend state）を持ち越すことを防ぎます。
成功したownerだけがruntimeの`FullServicePublication<'storage, BoundPublicationBackend<I>>`を実装します。binding
identity exhaustionはcold pathのtyped failureであり、unbound ownerやraw inner backendをpublicationへ渡す
safe escape hatchはありません。ownerとruntime viewのfieldsはprivateで、public accessorはgeneration、
interface metadata、tick、shape/bytesおよびread-only authorityだけを返します。`FullServiceView`のmutable
runtime borrowはtick engineの内部だけがconsumeできるため、callerがNAT keyをcandidateと独立にreconcileする
safe public pathはありません。

active ownerの`FullServicePublicationOwner::plan_successor(&self, next)`は、privateなactive
candidateを借用してcontrol crateの`plan_successor`へ委譲するallocation-free read-only seamです。
candidate authorityやraw candidateをcallerへ公開せず、ownerのgeneration、tick、runtime stateを変更しません。
このstatic reportはactual publicationのdynamic gateとは別物であり、`InPlaceEligible`でもbackend
quiescence、active-failure latch、五runtime preflightの結果次第でdeferまたはrejectされます。

initial constructorはsequentialです。shape/byte precheck後のlate TCP constructor failureではexact
candidateはgeneric `PublicationRejection`から回収できますが、先行runtimeによるstorage clearingとUDPの
process-lifetime runtime identity消費はrollbackしません。このtyped terminal failureを同じstorageへ
retry-safeなatomic abortと解釈してはなりません。

successor publicationは既存owner、そのownerへexactにbindしたpacket backend、既存21-array backingを
再利用できるsame-interface/same-shape境界を実装します。matched backend quiescence guardがliveな間に、
generation前進、直前UDP/TCP/firewall key rotation、固定Resolution/ICMP policy、storage shape、interface
bindingを検査します。storage shapeまたはinterface binding変更はinvalid configへcollapseせず、exact
candidateと旧ownerを保持した`FullServicePublishError::RestartRequired`です。その他のstatic successor
failureもstable typed reasonとexact candidateを返します。Resolution/ICMP policy-only changeも同じ
`RestartRequired`であり、`InvalidSuccessor`にはなりません。

static checks後はResolution、ICMPv4 errors、UDP NAT44、TCP NAT44、firewallの順に五つのpermitを
mutation-freeにpreflightします。どれか一つでも失敗すれば、先行permitはDropされ、全runtime stateと
active candidate、generation/tick/interface metadataは不変です。全permitが揃った場合だけ五つを
失敗分岐のない`commit`でflush/rebindし、`mem::replace`相当でactive candidateを最後にswapします。旧
candidateは退避し、matched guardを明示的に解放してbackendのexclusive borrowを終了した後だけdropします。
これにより旧Box群のdeallocationやallocator lock時間をquiescence区間へ含めません。
成功値の`FullServiceApplyReport`はprevious/new generationと五serviceのtyped flush reportだけを持ち、
candidateのauthority、interface string、rule、hash keyを保持しません。このatomic範囲は同じbackendと同じ
capacityのruntime/authority切替までです。candidate-bound prepared backend/native interface resource swap、
AF_PACKET/XDP `PacketIo`接続、capacity変更時のstorage rebuild、rollbackのcommand/history/operator UXは
実装済みとせず、後続boundaryです。

staticなreject/restart、backend quiescenceによる`Deferred`、および五つのdynamic preflight rejectは、
いずれも入力されたexact candidateを保持し、旧active candidate、generation/tick/interface metadata、
五runtimeの既存stateを変更せずに返します。dynamicなruntime coherence failureだけは安全のためtyped causeを
active-failure latchへ記録し、後続tickもfail-closeします。control enumが将来non-exhaustive variantを追加した
場合もintegrationはproduction panicにせず、candidateを保持したtyped
`UnsupportedStaticClassification`へfail-closeします。

daemonのreload boundaryでは、`systemctl reload ruster`がunitの
`ExecReload=/bin/kill -HUP $MAINPID`を通じて`SIGHUP`を送り、daemonがtick境界で
設定を再読込します。比較対象はparseとsemantic validationが成功した入力のexact
source bytesであり、canonicalizedなsemantic valueではありません。そのためコメント、
空白、source orderだけの変更もchangedとして扱われます。parse/validateに失敗した入力は
`Unchanged`とは扱わず、旧active publicationを維持します。

validated source bytesがactive identityと一致するreloadは`Unchanged`であり、active
generation、既存storage、確立済みのNAT/firewall state・session・mappingを維持し、candidate、
hash key、publicationを生成しません。bytesが異なるreloadを適用すると、callerはhigher
generationとUDP/TCP NAT・firewallのfresh hash keyでcold candidateを作り、eligibleならin-place
publicationへ進みます。五つのpermitのcommitはruntime stateをflush/rebindするため、確立済みの
NAT/firewall sessionとNAT mappingは失われ、通信断が起きます。reloadは無停止ではなく、変更ありの
適用で確立済みsessionが維持されるとは限りません。successorが`RestartRequired`、rejected、または
deferredの場合はpublicationせず旧activeを維持するため、変更あり入力の全てが適用成功を意味するわけでは
ありません。

libraryに旧candidateを復活させるrollback APIはありません。rollbackはcallerが旧config contentを再parse・
validateし、higher generationとpublication履歴上freshなhash keyで新candidateをre-planして通常のsuccessor
として適用する操作です。従ってold candidate resurrectionやgeneration rewindは行わず、全履歴のkey freshnessと
cold start後のgeneration persistenceはcallerの責務です。

`ruster-runtime`の`FullServicePublication`は、具体的なowned publicationやparserを持たず、
candidateのall-or-nothing適用、adapter固有のassociated `ApplyReport`、active full-service viewの借用だけを
抽象化します。成功は`PublicationOutcome::Applied(report)`としてtyped reportをtick callerへ返します。
`PublicationRejection<C, E>`はprivate fieldsでexact candidateを保持し、`Debug`/`Clone`を実装せず、
`into_parts`だけが`(candidate, error)`をmoveで回収します。

publication-capableなpacket backendは`bind_publication_backend(inner)`で作ります。このfactoryはinnerを
consumeするcore-owned `BoundPublicationBackend<I>`と、そのexact wrapperだけに対応するmove-onlyな
`PublicationOwnerBinding<BoundPublicationBackend<I>>`を同時に返します。wrapperのprivate immutable
`NonZeroU64` identityはprocess-globalなatomic counterからallocation-freeにchecked発行します。`u64::MAX`を
最後に0をpermanent exhaustion sentinelとし、その後は全callがtyped
`PublicationBindingIdentityExhausted`を返します。identityはwrap、回復、公開、formatを許しません。wrapperは
immutable inspection以外のgeneric `&mut I`やconsuming extractionをsafeに公開せず、whole innerをdetach、move、
replace、swapするgeneric seamも持ちません。これによりprivate identityを別wrapperへ共有、差替え、再利用して
identity ABAを作ることを防ぎます。これはfactoryへ渡す前からinner `I`が持つalias、`Arc`で共有した
state/physical resource、interior mutabilityまでは禁止しません。そのようなshared stateも含めたauthoritative
quiescence/dispositionを正しく報告することはbackend実装のsemantic trust境界です。

`bind_publication_backend`は`inner: I`に`unsafe trait PublicationBackendAuthority`実装も要求します。
safe operational trait（`PacketIo`/`GeneratedPacketIo`/`PublicationQuiescenceBackend`）はそれぞれの
associated output（`Batch`/`Error`等）を`Self`にして`mem::take(self)`で丸ごとdetachする経路をtypeとして
禁止できないため、この明示unsafe markerで個別trait実装だけでは委譲を許さず、safe `impl`はexact E0277/E0200で
拒否します。実装者はこのwrapperを通じて到達する全safe method（interior-mutability surfaceを含む）を監査し、
whole backendのmove/replace/detachを許さないことを引き受けます。

backend固有のmutationは`unsafe trait PublicationBackendControl`が選ぶclosed command/responseだけを
`BoundPublicationBackend::execute_backend_command`からsafeに実行します。このsafe methodはaudited
`unsafe impl`へ依存し、implementationはwhole innerをmove/replace/swap/returnしてはならず、authoritative stateへの
独立mutable aliasを作ってはなりません。hidden/shared stateをquiescence対象から切り離さず、
`check_publication_quiescence`、`current_io_disposition`、`quiescence_error_disposition`を正しく分類し、terminalな
`Stop`となったbackend valueを再利用しないこともSafety contractです。これはRust memory safetyではなく、safe
command callerへ正しいpublication authorityを保つためのunsafe implementation trust boundaryです。
`SimIo`の`unsafe impl`はclosed command/responseがowned simulatorや独立mutable aliasを含まず、全outstanding stateを
quiescence reportへ残すという局所的な`SAFETY`根拠を持ちます。publicな`BoundSimIoControl`はinject、RX/TX queue
inspection、TX/recycle dequeueだけをsafeに公開します。packet I/O operationはwrapperが
`PacketIo`/`GeneratedPacketIo`としてdelegateします。`SimIo::new`と`Default`はstandalone inner backendであり、
publicationに使う場合はこのfactoryへconsumeします。

runtimeはcandidateの`Option`を調べる前にowner capabilityの`matches_backend`でexact bound wrapperを
borrow-only照合します。same-type foreign wrapperならcandidateの有無にかかわらず
`PublicationOutcome::BackendMismatch { candidate }`を返し、quiescence check、adapter hook、RX、resolution
timer、failure dispatch、generated ARP/ICMPを一切実行しません。candidateは`Option`内でexactに保持し、
active ownerをpoisonしないため、正しいbackendを使う次tickは通常どおり再開できます。

exact backendにcandidateがある場合だけ、sealedなruntime-facing `PublicationQuiescence`がinner backendの
public `PublicationQuiescenceBackend::check_publication_quiescence`を呼びます。external backendが、事前aliasや
shared resourceも含むoutstanding RX/generated lease、accepted TX completion等のauthoritative ownershipを
`check_publication_quiescence`で、現在I/O可否を`current_io_disposition`で、check error後のI/O可否を
`quiescence_error_disposition`で正確に報告し、一度返した`Stop`をbackend valueの寿命中terminalに保つことが
semantic trust境界です。interior mutabilityやshared physical stateをこれらの報告から隠してはなりません。
identity、binding accessor、guard constructorはinner traitへ公開しません。check成功後だけcoreがexact wrapperを
exclusive borrowするraw `PublicationQuiescenceGuard`を作り、safeな
`try_publish_candidate`がowner capabilityでそのprivate identityを照合してopaqueな
`MatchedPublicationQuiescenceGuard`へconsumeします。foreign raw guardならexact candidateを
`PublicationAttemptError::BackendMismatch`で返し、adapter hookを呼びません。照合済みguardだけを受け取る
adapter entryは`unsafe fn publish_candidate_authorized`であり、safe callerは必ずruntime-owned gateを通ります。
matched/raw guardはmove-only、non-`Debug`、`!Send + !Sync`でbackend operationを公開せず、guard解放後だけ
active viewとpacket I/Oへ進めます。このproofは現在のexact backendでpacket ownershipが競合しないことだけを
示し、candidate-bound prepared backendやnative interface resourceをinstall/swapするauthorityではありません。

quiescence failureはcandidateをadapterへ渡さないtyped `Deferred`です。backendはerrorごとに
`ContinueOldIo`、`SkipIo`、`Stop`を返し、未知errorのdefaultは`SkipIo`です。Simのaccepted TX completion
待ちだけは旧active generationでI/Oを継続し、unfinished batchまたはterminal未完了leaseは旧activeを
保持したまま全data phaseをskipします。candidateなしのtickはguardを取得せず、backendのboundedなread-only
current-I/O dispositionを確認します。`SkipIo`はbackendがconflicting ownershipを明示回収するまで継続し、
`Stop`はそのbackend valueの寿命中terminalです。したがってforgotten batch/leaseのsticky busyは次tickにも
全data phaseを抑止します。Simのaccepted TX output queueを明示completionする有限modelは、AF_XDP CQ drainや
native backend quiescenceを実装済みとは主張しません。

`FullServicePublication`は`unsafe trait`です。実装者はcandidate provenance（reject/apply双方で受け取った値を
無改変で返す）、successful publicationのatomic install、binding安定性、`active_status`のimmutable/O(1)/
coherentな報告、`active()`は`ContinueOldIo`観測後だけ呼ばれO(1)/allocation-freeであることを監査契約として
引き受けます。safe `impl`はexact E0200で拒否されます。旧`active_disposition()`のfail-open defaultは廃止され、
必須の`active_status(&self) -> ActivePublicationStatus`（`Absent`/`ContinueOldIo`/`StopOldPublication`）へ
統合しました。backend mismatch判定を含むruntimeの全presence/skip判断はこのimmutable statusだけを参照し、
`active()`（mutable borrow）は呼びません。

`InvalidSuccessor`と`RestartRequired`のように旧activeが健全なcandidate入力errorは`ContinueOldIo`で、その
tickを旧generationのdata phaseへ進めます。一方、FullService preflightでactive runtime/authority coherence
failureまたはterminal runtime epochを検出した場合、ownerは原因をpersistentにlatchして`StopOldPublication`を
返します。`reject_candidate_if_active_stopped`はO(1)・mutation-freeな必須methodで、`run_tick`のexact backend
identity照合直後・backend quiescence要求より前、および安全gate`try_publish_candidate`のraw guard owner match
直後・`unsafe fn publish_candidate_authorized`呼び出しより前の両entryで呼ばれます。latch済みなら同じtyped
causeとexact candidateをguard取得やadapter hook呼び出しなしに返すため、backendがpending TX/unfinished batch/
terminal `Stop`のいずれであってもquiescence呼び出し回数を増やさずに優先rejectします。runtimeはrejectした現
tickとcandidate-freeな後続tickのどちらも`active()`をborrowせず、全data phaseを`ActivePublicationInvalid`と
してskipします。backend側が`ContinueOldIo`でもこのpublication stopを優先します。同じownerへの後続candidateも
五permitへ触れず、latch済みcauseとexact candidateを返します。

quiescenceを経てcandidateが`Applied`または`Rejected`になった直後も、matched guard解放後・data phase前に
`current_io_disposition`を再取得します。hookの実行中にbackendがterminal `Stop`へ遷移していれば、Applied/
Rejectedいずれの結果も変更せずに`TickPhaseSkip::BackendStopped`で全data phaseをskipし、`active()`は呼び
ません。active viewがなければRXを開始せず、残りの全phaseを`NoActivePublication`としてtyped skipします。
一度借用したactive viewはtick終了まで同一generationであり、そのgenerationの`TickBudgets`は48-byte値
`ActiveTickAuthority`（generation + `TickBudgets`）へ集約され、同じ`FullServiceView`が`&ActiveTickAuthority`
だけをby-valueで束ねます。`run_tick`はpublication phase後に一度だけ`active`をborrowしてbudgetを取得するため、
同じtickの`Applied(report)`は新generationのbudgetを、`ContinueOldIo`の`Rejected`/`Deferred`と`Unchanged`は
継続中generationのbudgetを使います。`StopOldPublication`および post-attempt `BackendStopped`ではdata phaseを
実行しません。ownerはsuccessor適用時、preflight/全5コミット後・candidate-last swap直前に`ActiveTickAuthority`
全体を一体で書き換えるため、generationとbudgetsは常にcoherentに更新されます。callerが独立budgetを渡して
publication metadataから逸脱するsafe public escape hatchはありません。RXにはUDP/TCP NAT44、firewall、
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
breakであり、downstream adapterはstruct literalを更新します。現行core full wrapperは3 configを
必須とするため、service pair全体の不在表現はoptional-config composition seamを追加する後続
作業です。64-bit buildではsnapshot 144 bytes、Firewall config 160 bytes、UDP/TCP NAT configは各112 bytes、
`ActiveTickAuthority`（generation + `TickBudgets`）48 bytesへの参照8 bytesで、full view全体を
`size_of::<FullServiceView>() == 576`ちょうどに固定します。1024 tickの回帰fixtureは各tickの
`active`呼出しがexactly once、heap allocationとvalidation/fingerprint/hash/slice scan再実行が
zeroであることを固定します。rootless integration evidenceはvalidated configからplanner candidate、
candidate-bound external storage、cold initial activation、backend-bound `FullServicePublicationOwner`、
`bind_publication_backend(SimIo::new())`、`run_tick(None)`までを一続きに実行し、unchanged publicationの
同一generationでARP ReplyをRX-owned frameからTXへcommitできることを固定します。

`ruster-runtime`の`observability` moduleは、allocation-freeでgeneration-tagged化された
typed snapshotを提供します。`SaturatingCounter`/`HighWatermark`は共にsaturating算術で
overflow panicもwrapもせず、`Readiness`（`Cold`/`Ready`/`Degraded`）は`active_status`から
決定的に導出されます。`ObservabilityRecorder`はfirewall/UDP/TCP NAT44それぞれのcumulative
`processed`/`denied`をtickごとの差分として畳み込み、単tickあたりのhigh watermarkを別途
維持します。backend固有の統計は`BackendObservabilityStats`拡張点（`Copy`必須）を通じて
snapshotへ運ばれ、production crateは`ruster-io-sim`へ依存しないため具体的なSim実装は
integration test側に置きます。snapshot生成自体は文字列を一切生成せず、`Display`/`Debug`
formatはcold consumer側の関心事に限定します。`FullServicePublicationOwner::observability_snapshot`は
persistent active-failure latchから直接readinessを導出するため、backendがbindされているか
どうかに関わらず呼び出せます。

`ruster-sim-scenario`はこのpublic full composition API（parse→validate→plan→initial
activation→`bind_publication_backend`→`run_tick`）だけを経由してmulti-tickのdeterministic
scenarioを駆動します。呼び出し側が渡す論理clock（`MonotonicMillis`）だけを使い、wall clockを
読みません。ingress frameとtyped outcomeはpacket pathに`String`を使わず、同一scenarioの
再実行はbyte単位・順序含めて完全に一致します。golden fixtureはLAN内ARP解決/転送、WAN
route経由のUDP/TCP NAT44、firewall allow/deny、複数tickのdynamic neighbor解決、TTL超過と
ARP解決失敗（max-attempts消尽）によるICMPv4生成をpublic full composition API経由で検証
します。route-unreachable ICMPは前段のfirewall route oracle抑制により、public full
composition API経由では原理的に再現できないため、このgolden fixture集合には含まれません
（core levelのfirewall無し経路は別途検証されています）。

generation-bound `TickBudgets`はactive `FullServiceView`からtick engine内部へmoveされ、RX packet数、
resolution timer scan、failure dispatch scan、generated ARP action、generated ICMPv4 actionを独立に
制限します。RX batchはlexical scopeでwrapperへmoveし、
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
このCodeはLPMが完全にmissした場合だけに限定します。firewallが設定されている場合、route
missはこのICMP生成経路へ到達せず`FirewallRouteUnavailable`をbyte不変で返す意図的な
deviationです。firewall-permitted trafficであっても、外部からrouteのtopologyをICMP応答の
有無で探査できるoracleを与えないための防御的な抑制であり、production full-service
candidateは`PUB-001`によりfirewallを必須とするため、この抑制は常に有効です。

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
`(mapping slot, mapping generation, lifecycle epoch high, lifecycle epoch low, remote IPv4)`
で、mappingは`(inside IfId, internal IPv4, internal UDP port)`です。既知IPの任意remote UDP
portを許し、未接触IPをbyte不変dropします。outboundでpeer slotを確保できなければmappingを
refreshせずdropし、filterを緩めません。live mappingをevictせず、port overloadもしません。
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

fragment handling/reassembly、hairpinning、Type 3/Code 4以外のICMP errorとICMP query
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
再scanで見つけた別のexpired slotは追加deleteせずfirst reuse候補として扱います。このため単一
packetはprobe最大2N、maintenanceも定数倍Nでstrict O(N)であり、expired数を掛けたO(N²)には
なりません。full相当のusable loadが全expiryしても、繰返しattemptが1 slotずつamortized cleanup
し、最終的にempty terminationを回復します。新規flowはcleanupが追いつかない間fail closedで
構いません。cleanupによるdelete/moveはruntime epochを進め、移動前planをrelease buildでも
staleとして拒否します。live evictionはありません。probe、maintenance shift/hash/scan、
rule evaluation数はcounterで観測できます。

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
`FirewallClockRegression`またはNAT clock regressionになります。FW opt-in時のLPM missは
egress不明のためrule評価せず`FirewallRouteUnavailable`でsilent dropし、Type 3/Code 0やARPを
queueしません。NAT inboundもFW state/rule判定をTTL判定より先に行います。

full compositionでもfirewall authorizationはTTL判定とgenerated error captureより先です。
rule/default deny、runtime/config/snapshot authority failure、LPM missはICMP/ARPをqueueしない
silent dropを維持します。認可済みpacketのTTL 0/1は既存のerror suppressionとreverse
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
denyします。NAT/FWどちらかのcapacity plan failureでも他方をcommitしません。NAT44 ICMPv4
Type 3/Code 4は、NAT read-only inspectionが復元したpre-SNAT internal address/portと引用内の
remote address/portから、origin ingress=inside、egress=outsideのcanonical forward tupleを
構成します。UDPもremote portまでexactにfirewall照合し、TCPはNAT sessionとfirewall stateの
両方でendpoint exactを要求します。firewall lookupはkeyed tableを最大capacity回probeし、
live/config generation/interface/tupleのdirect origin一致だけをRELATEDとして許可します。
reverse match、rule scan、expiry cleanup、delete/move、activity/phase/counter/watermark更新は
行いません。退行時刻は状態不変のtyped clock regression、state missは
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

## backend progression

`ruster-io-sim`はRXとgenerated TXのFIFO、budget、max frame、allocation exhaustion、
cancel/abandon、partial TX/reject、finish errorを決定的に実装します。captureは
`FrameOrigin`でRXとgeneratedを区別します。RX/生成の`Vec<u8>`そのものをTX/dropへmoveし、
packet bytesをcloneしません。次の実I/O backendも同じlease contractを実装し、
backend固有pointerをcoreへ漏らしません。

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
backend-owned TX mmap frameへ一度`copy_from_slice`し、`tp_next_offset=0`、
`tp_snaplen=tp_len=payload length`のV3 headerを構築してSEND_REQUESTをRelease publishします。
固定metadataのownershipとchecked generationはframe再利用cycleを区別します。

completionは固定budget内でFIFO headだけを走査し、SEND_REQUESTまたはSENDINGを見た時点で後続を
skipせず停止します。AVAILABLEはSENDINGを観測しなかった直接遷移も含め一度だけreclaimし、
WRONG_FORMATは一度だけAVAILABLEへrecycleします。batchは固定長epoch/scratchでpublish済みportを
deduplicateし、明示finishとDropのどちらも各endpointへ
`send(fd, NULL, 0, MSG_DONTWAIT)`を最大一回だけ試し、失敗をretryしません。kick失敗はすでに
publishしたsubmissionをrejectへ巻き戻さずin-flightに残します。hot submit/completion/reuseは
heap allocationしません。

このsliceはpersistent RX validation cursor、`PacketIo` lease、RXからTXへのadapter接続、poll、
live stats/cleanupを実装しません。従ってIO-012のproduction conformance、実packet送受信、
throughputは引き続きdeferredです。

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
live byte sliceをまだ貸し出しませんが、将来のring/native engineも同じworker localityを維持
するか、別設計の明示的ownership handoffを追加しなければなりません。

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
