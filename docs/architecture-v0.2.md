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
  → IPv4 version/IHL/Total Length/header checksum validate
  → options policy → TTL check → LPM → typed neighbor lookup → typed interface lookup
  → TTL/checksum/MAC rewrite → commit
```

leaseからmutable sliceを一度だけ取得し、同じsliceをimmutable reborrowして全判断を
終えます。rewrite直前に全rangeを再検証するため、drop時のpacket bytesは入力と同一です。
packet terminal traceの`TxRequested`はcommit後に記録しますが、wire送信やbackend accept
を意味しません。finish後の`BatchCompleted`だけがaggregate accepted/rejectedを示します。
ordered outcome/tokenを導入するまではpacket単位accepted traceを主張しません。
`TraceSink`はpanic禁止の契約で、productionの`NoTrace`はallocationしません。
`VecTrace`はsim crateだけに存在します。

route、interface、neighborはvalidated immutable snapshotのborrowed sliceです。routeは
canonical prefixだけを受け付け、lookupは`/0`と`/32`を含むlongest-prefix matchです。
gateway routeはnext-hopを、connected routeはpacket destinationをneighbor targetにします。

snapshot公開前にcontrol planeが守る不変条件は次の通りです。

- route prefix/length、interface `IfId`、neighbor `(IfId, target)`は重複しない。
- routeとneighborが参照するegress `IfId`はinterface snapshot内で解決できる。

routeに対応するneighborがまだ無いこと自体はvalidです。ARP解決前の通常状態として
forwarding時に`NeighborUnresolved`でbytes不変recycleします。

## IPv4 scope

v0.2 bootstrapはEthernet II上のIPv4 datagramを転送します。

- IPv4 Total Lengthより後ろはlink paddingとして解析結果から除外する。
- IHLが示すoptionsをheader length/checksumの対象にする。
- option固有の意味論は未実装のため`Ipv4OptionsUnsupported`でbytes不変dropする。
- fragment offsetやMFに関係なく、このsliceはL4を参照しないためdatagramとして転送する。
- TTLは1減算し、header checksumはRFC 1624のincremental updateで更新する。

ARP、ICMP生成、NAT、firewall、config parser、pcap、AF_XDP、DPDK、binary、thread、
benchmarkはこのPRのscope外です。

## backend progression

`ruster-io-sim`はFIFOとbudgetを決定的に実装します。RXの`Vec<u8>`そのものをTX/dropへ
moveし、packet bytesをcloneしません。次の実I/O backendも同じlease contractを実装し、
backend固有pointerをcoreへ漏らしません。
