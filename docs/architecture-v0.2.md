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
  │    └─ options policy → TTL check → LPM → typed neighbor/interface lookup
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
action ring、dynamic neighbor tableを借用します。すべてのkeyは`(IfId,target IPv4)`です。
intervalは1000ms以上、state TTLはinterval
以上とし、batch単位で注入された`MonotonicMillis`だけを使います。加算deadlineを作らず
順序確認後の差分で判定するため`u64` overflowはありません。逆行はtyped resultとして
action/stateを変更しません。live entryはevictせず、TTL後だけreuseします。runtimeの
生成時は三storageをすべてemptyへ初期化します。processをまたぐstate永続化/resumeは
未実装です。

dynamic neighbor TTLはzeroを拒否するconfigurable policyです。static neighborを最初に
lookupし、static missだけdynamicを参照します。dynamic slotは`elapsed < TTL`だけliveで、
exact boundaryではlazy expiryして転送に使いません。insert時もempty/expired slotだけを
reuseし、liveな別keyをevictしません。既存keyのMAC/refresh時刻更新は追加capacity不要です。
periodic scanはなく、lookup/insert時のbounded linear lazy maintenanceです。

control planeがstatic neighbor snapshotを公開する同じworker tickでは、次のpacketを処理
する前に、そのsnapshotのneighbor sliceを`ResolutionRuntime::reconcile_static`へ渡します。
これによりstatic keyと一致するdynamic slot、resolution state、queued actionを削除し、
wrapped action ringのunrelated FIFOを維持します。static公開後に同keyのARPを受けた場合も
merge pathが同じcleanupを行います。

同じkeyのactionは一つだけqueueできます。抑制deadlineはenqueue時でなく、generated
leaseをcommitしてTX requestedになった注入時刻から開始します。allocation/build失敗時は
actionを保持しdeadlineを開始しません。backendのpartial rejectでもcommit済みなので
抑制を開始します。commit済みARP Requestの次回生成は、deadline後に新しいtraffic missが
来た場合だけです。allocation/build失敗で未commitの保持actionはexecutorを再実行できます。
target `0.0.0.0`、IPv4
multicast、limited broadcast、およびcanonical connected routeから確定できるdirected
broadcastにはARP Requestを生成しません。directed broadcast判定はpacketを選択したroute
だけでなく、snapshot内の同一egressにある全connected routeを確認します。source local
IPv4自身がtargetになる場合も生成しません。

生成する通常RequestはRFC 894のEthernet minimum framingに合わせた、FCSを含まない
60 bytesです。先頭42 bytesをRFC 826の
Ethernet/IPv4 ARP（Ethernet destination broadcast、SHA/source MACはlocal、SPAはnonzero
local IPv4、THA zero、TPA target）として書き、残り18 bytesを必ずzero paddingします。
THA zeroは決定的なlocal profile choiceであり、RFCのMUSTとは主張しません。

これはRFC 826の通常ARP Request生成/mergeとRFC 1122 §2.3.2.1のflood prevention/stale
entry TTLまでです。timer-only retry/max attempts/Failed、unresolved packet
hold/replay（RFC 1122 §2.3.2.2、RFC 1812 §3.3.2）、multi-worker resolution ownership/
SPSCは未実装です。最初のpacketは解決後に自動再送されません。

## IPv4 scope

v0.2 bootstrapはEthernet II上のIPv4 datagramを転送します。

- IPv4 Total Lengthより後ろはlink paddingとして解析結果から除外する。
- IHLが示すoptionsをheader length/checksumの対象にする。
- option固有の意味論は未実装のため`Ipv4OptionsUnsupported`でbytes不変dropする。
- fragment offsetやMFに関係なく、このsliceはL4を参照しないためdatagramとして転送する。
- TTLは1減算し、header checksumはRFC 1624のincremental updateで更新する。

## ICMPv4 local control scope

RFC 792とRFC 1122 §3.2.2.6に従い、ingress `IfId`にbindingされたdestinationだけを
router自身へのlocal deliveryとして扱います。同じaddressが別interfaceにbindingされて
いてもlocal扱いせず、通常のL3 forwardingへ進めます。local判定はIPv4
version/IHL/Total Length/header checksum検証後、forwardingのTTL expiry/LPM/ARPより前です。
したがってTTL 0/1のlocal Echo Requestにも応答し、reply TTLは受信値から独立した64です。

実装profileはIHL=5、protocol=1、unfragmented、Echo Request Type 8/Code 0です。ICMP message
範囲はIPv4 Total Lengthで閉じ、Internet checksumはodd lengthを含む全messageで検証します。
全validation/admissionを終えるまでbytesを変更しません。replyは同じRX leaseをingressへ
commitし、次だけを書き換えます。

- Ethernet destinationをrequest source、sourceをingress Interface MACにする。
- IPv4 source/destinationを交換し、TTLを64にする。
- RFC 6864のatomic datagram profileとしてID=0、DF=1、MF=0、fragment offset=0にする。
- ICMP Typeを0へ変え、IPv4/ICMP checksumをRFC 1624で正しく更新する。

DSCP/ECN、Total Length、protocol、ICMP identifier/sequence/data、IPv4 Total Length後の
link paddingは保存します。IPv4 address pairの交換はone's-complement sumを変えないため、
IPv4 checksum更新対象はTTL/protocol word、ID、flags/offsetです。

RFC 1812 §§4.2.2.11, 4.2.3.1, 5.3.7に基づくnarrow anti-amplification profileとして、
replyを生成する前に次を要求します。

- IPv4 sourceがingress上のunicast hostである。`0/8`、`127/8`、multicast、`240/4`、
  limited/directed broadcast、connected network address、ingress-local claimはdropする。
- Ethernet sourceがnonzero unicastである。
- Ethernet destinationがingress Interface MACと完全一致する。broadcast、multicast、
  foreign unicast宛てのIP-local frameには応答しない。

validなlocal non-ICMPと、checksum-validなunfragmented non-Echo ICMPは
`Ipv4LocalUnsupported`でbyte不変consumeし、routing/ARPへ流しません。malformed/truncated
Echo、invalid checksum、nonzero Echo code、source/L2 admission failureはstable
`DropReason`でbyte不変dropします。

IPv4 reassemblyはRFC 1122 §3.2.1.4に対する現時点の明示deviationです。local ICMP fragmentは
reassemblyや応答を行わず`Icmpv4FragmentUnsupported`でdropします。Timestamp等の他ICMP query、
IPv4 options、ICMP error生成（TTL Exceeded/Destination Unreachableを含む）、rate limit、
PMTU処理はdeferredです。

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
- 学習成功時だけmatching resolution state/actionをcancelし、unrelated FIFOを維持する。

Reply admissionへsolicited-only制約は追加しません。`ArpReplyUnsupported`と
`ArpTargetNotLocal`のstable reason番号は互換性のためretired/reservedとして維持します。

RFC 5227 §2.4のaddress conflict detection/defenseは未実装です。foreign SHAが同じingressの
local SPAを名乗り、そのlocal addressをTPAにしたrequestも通常requestとしてdirected reply
するだけで、conflict状態やdefensive announcementを生成しません。正常なlocal target requestを
追加policyでdropしないことを優先した明示deviationです。

eager cache scan/flush、timer retry、unresolved packet hold queue、gratuitous ARP生成、
ARP Probe/Announcement生成、proxy ARP、VLAN、Address Conflict Detection、Echo Reply以外の
ICMP生成、NAT、firewall、config parser、pcap、AF_XDP、DPDK、binary、thread、
benchmarkはこの
sliceのscope外です。

## backend progression

`ruster-io-sim`はRXとgenerated TXのFIFO、budget、max frame、allocation exhaustion、
cancel/abandon、partial TX/reject、finish errorを決定的に実装します。captureは
`FrameOrigin`でRXとgeneratedを区別します。RX/生成の`Vec<u8>`そのものをTX/dropへmoveし、
packet bytesをcloneしません。次の実I/O backendも同じlease contractを実装し、
backend固有pointerをcoreへ漏らしません。
