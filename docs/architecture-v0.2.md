# Architecture v0.2

## 境界

`ruster-core`はNIC、thread、OS、設定形式を知りません。worker-ownedな`PacketIo`から
GATでbatchを借用し、batchから一度に一つのcore所有`PacketLease`を得ます。backendの
raw `PacketSlot`はcallerへ返りません。leaseはzero-sizeな`Rc` markerで`!Send + !Sync`
となり、live slotをworker間で移動できません。

packet leaseには二つの正常な終端があります。

1. forwardするslotは、in-place rewrite後にegress `IfId`を付けて`commit`する。
2. dropするslotは、stableな`DropReason`を付けて`recycle`する。

leaseを未完了のままdropした場合、coreのRAII実装が`LeaseAbandoned` lifecycle completion
をbackendへ必ず返します。これはforwardingの`DropReason`とは別です。batchからまだ
leaseしていないslotはRX backendの所有下に残ります。coreからUMEM、mbuf、simの`Vec`
は見えません。

`receive`はbackend固有errorを返せます。`finish`はerror時にも失われないcompletionを
必ず返し、TX requested/accepted/rejectedを分けます。常に
`accepted + rejected == requested`で、reject slotはbackendがreturn前にrecycle/free
します。これによりAF_XDP ring fullやDPDK partial TXでもrequestを成功と誤認しません。

## forwarding transaction

処理はvalidate/decideとmutate/commitの二段階です。

```text
Ethernet validate
  ├─ IPv4 version/IHL/Total Length/header checksum validate
  │    → options policy → TTL check → LPM → typed neighbor/interface lookup
  │    → TTL/checksum/MAC rewrite → commit
  └─ Ethernet/IPv4 ARP profile validate → ingress local target lookup
       → request bufferをARP replyへrewrite → ingressへcommit
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

resolution runtimeも`!Send + !Sync`で、caller提供のlinear fixed tableとaction ringだけを
借用します。keyは`(IfId,target IPv4)`です。intervalは1000ms以上、state TTLはinterval
以上とし、batch単位で注入された`MonotonicMillis`だけを使います。加算deadlineを作らず
順序確認後の差分で判定するため`u64` overflowはありません。逆行はtyped resultとして
action/stateを変更しません。live entryはevictせず、TTL後だけreuseします。runtimeの
生成時はcaller storageをすべてemptyへ初期化します。processをまたぐstate永続化/resumeは
未実装です。

同じkeyのactionは一つだけqueueできます。抑制deadlineはenqueue時でなく、generated
leaseをcommitしてTX requestedになった注入時刻から開始します。allocation/build失敗時は
actionを保持しdeadlineを開始しません。backendのpartial rejectでもcommit済みなので
抑制を開始します。retryは新しいtraffic missでだけ起きます。target `0.0.0.0`、IPv4
multicast、limited broadcast、およびcanonical connected routeから確定できるdirected
broadcastにはARP Requestを生成しません。directed broadcast判定はpacketを選択したroute
だけでなく、snapshot内の同一egressにある全connected routeを確認します。source local
IPv4自身がtargetになる場合も生成しません。

生成する通常RequestはRFC 894のEthernet minimum framingに合わせた、FCSを含まない
60 bytesです。先頭42 bytesをRFC 826の
Ethernet/IPv4 ARP（Ethernet destination broadcast、SHA/source MACはlocal、SPAはnonzero
local IPv4、THA zero、TPA target）として書き、残り18 bytesを必ずzero paddingします。
THA zeroは決定的なlocal profile choiceであり、RFCのMUSTとは主張しません。

これはRFC 826の通常ARP Request生成とRFC 1122 §2.3.2.1のflood preventionまでです。
reply learning/cache/aging/flush、timer-only retry/max attempts/Failed、unresolved packet
hold/replay（RFC 1122 §2.3.2.2、RFC 1812 §3.3.2）、multi-worker resolution ownership/
SPSCは未実装です。最初のpacketは解決後に自動再送されません。

## IPv4 scope

v0.2 bootstrapはEthernet II上のIPv4 datagramを転送します。

- IPv4 Total Lengthより後ろはlink paddingとして解析結果から除外する。
- IHLが示すoptionsをheader length/checksumの対象にする。
- option固有の意味論は未実装のため`Ipv4OptionsUnsupported`でbytes不変dropする。
- fragment offsetやMFに関係なく、このsliceはL4を参照しないためdatagramとして転送する。
- TTLは1減算し、header checksumはRFC 1624のincremental updateで更新する。

## ARP responder scope

Ethernet II / IPv4 profile（HTYPE 1、PTYPE 0x0800、HLEN 6、PLEN 4）のARP Requestだけを
扱います。opcode profileはRFC 826に加えてRFC 5494/IANA ARP Parameters registryに
基づき、Replyと未対応opcodeを別reasonにします。TPAがingress interfaceのlocal IPv4と
一致するとき、同じRX bufferを次のreplyへ書き換えてingressへcommitします。

- Ethernet destinationとTHAはrequest SHA、Ethernet sourceとSHAはlocal interface MAC。
- SPAはrequest TPA、TPAはrequest SPA。ARP ProbeのSPA `0.0.0.0`にもTPA zeroでreplyする。
- request THAは無視し、Ethernet sourceとrequest SHAの一致も要求しない。
- 42 byte以後はpadding/tailとして長さと内容を保存する。
- ARP Reply、unknown opcode、nonlocal targetはstable reasonでbytes不変recycleする。
- 学習やneighbor snapshot更新は一切行わない。

RFC 5227 §2.4のaddress conflict detection/defenseは未実装です。foreign SHAがlocal SPAを
名乗り、同じlocal addressをTPAにしたrequestも通常requestとしてdirected replyするだけで、
conflict状態やdefensive announcementを生成しません。正常なlocal target requestを
追加policyでdropしないことを優先した明示deviationです。

ARP learning/cache/aging/flush、timer retry、unresolved packet hold queue、gratuitous
ARP、ARP Probe/Announcement生成、proxy ARP、VLAN、Address Conflict Detection、ICMP生成、
NAT、firewall、config parser、pcap、AF_XDP、DPDK、binary、thread、benchmarkはこの
sliceのscope外です。

## backend progression

`ruster-io-sim`はRXとgenerated TXのFIFO、budget、max frame、allocation exhaustion、
cancel/abandon、partial TX/reject、finish errorを決定的に実装します。captureは
`FrameOrigin`でRXとgeneratedを区別します。RX/生成の`Vec<u8>`そのものをTX/dropへmoveし、
packet bytesをcloneしません。次の実I/O backendも同じlease contractを実装し、
backend固有pointerをcoreへ漏らしません。
