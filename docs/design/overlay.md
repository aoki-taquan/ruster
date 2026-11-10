# L2のブリッジ、L2を運ぶトンネル、SRv6、IS-ISとOSPF

状態: 叩き台（2026-11-10）。理想の設計図であり、今のコードの説明ではない。

関連: [`../charter.md`](../charter.md)の「作るもの」、[`tables.md`](tables.md)（FEの表）、
[`fe-internals.md`](fe-internals.md)（1パケットの処理の順番）、[`fe-ce-split.md`](fe-ce-split.md)（FEとCEの線引き）、
[`router-box.md`](router-box.md)（FRRの橋渡し役）。

## 用語

- ブリッジ: 一つのブロードキャストの届く範囲（IEEE 802.1Qのbridge）。FEはブリッジをいくつでも持てる。
- メンバー: ブリッジに入っているインターフェース。ポート、VLANのサブインターフェース、VXLANのインターフェース、
  EtherIPのインターフェースのどれか。一つのインターフェースは一つのブリッジにしか入らない。
- IRB（integrated routing and bridging）: ブリッジに付いたL3のインターフェース。ブリッジと同じ名前を持つ。
- BUM: ブロードキャスト、宛先を学んでいないユニキャスト、マルチキャストのフレーム。
- フラッディング: BUMのフレームを、受けたメンバー以外の全メンバーへ送ること。
- VTEP: VXLANのトンネルの端（RFC 7348）。VNIはVXLANのネットワークの番号（24 bit）。
- SID: SRv6のセグメントの識別子。IPv6アドレスの形をしている（RFC 8986）。SRHはそのリストを運ぶ
  拡張ヘッダ（RFC 8754）。

## 1. ブリッジ

### 形

```
         ブリッジ br0（IRBのアドレス 192.0.2.1/24）
        ┌──────────┬──────────┬───────────────┐
      ポート p1   ポート p2   p3.10（VLAN 10）   vx100（VXLAN VNI 100）
```

- メンバーにはアドレスを付けない。L3として振る舞うのはIRBだけ。
- メンバーのポート（VLANのサブインターフェースがメンバーなら、その親のポート）は、自分のMAC以外の宛先の
  フレームも受ける必要がある（ホストやIRB宛て）。FEはそのポートごとに、何も受けないAF_PACKETのsocketを
  開いたままにし、`PACKET_MR_PROMISC`でpromiscuousにする。Linuxはpromiscuousの利用者を数えるので、
  socketを閉じれば（FEが落ちても）FEの分だけが戻り、運用者やtcpdumpの分は残る。
- IRBは、名前がブリッジと同じインターフェース。MAC、MTU、VRF、アドレスを持つ普通のインターフェースで、
  経路、firewall、NAT、受け渡しの分類、neighd、RA、DHCPはどれもIRBの名前で書く。IRBが無いブリッジは
  L2だけで働く。
- ブリッジはVLANを区別しない（IEEE 802.1Qの言葉ではVLAN-unawareのbridge）。VLANごとのブリッジにしたいときは、
  VLANのサブインターフェースをメンバーにし、VLANごとに別のブリッジを作る。

### 受信したフレーム

FEのL2の入口（[`fe-internals.md`](fe-internals.md)の2.）で、VLANのタグを見てサブインターフェースを決めた後、
PPPoEや受け渡しの分類より前に、次の順で扱う。トンネル（VXLAN、EtherIP）のメンバーでは、外側を外した後の
内側のフレームが、そのメンバーで受けたフレームになる。

```
受けたインターフェースがメンバーでない → 今までどおり（L3の処理へ）
宛先が01-80-C2-00-00-00から0F（IEEE 802.1Qで橋渡ししない範囲）→ 捨てる
送信元MACがユニキャストなら学ぶ（下の「MACの表」）
宛先MAC
 ├ IRBのMAC → IRBで受けたフレームとして、L3の処理へ
 ├ ブロードキャスト、マルチキャスト → ほかのメンバーへフラッディングし、IRBがあればIRBでも受ける
 ├ 表にあるユニキャスト → そのメンバーへ送る（受けたメンバーと同じなら捨てる）
 └ 表に無いユニキャスト → フラッディング
```

- 表にあるメンバーへ送るときは、受けたbufferをそのまま送る（VLANのタグの付け外しはbufferの中で行う）。
- フラッディングでは、受けたbufferを、起動時に確保した置き場へ一度写し、送る先のメンバーごとに、そのポートの
  生成用のbufferへ写して送る。受けたbufferは、IRBでも受けるならL3の処理へ渡し、そうでなければ返す。
  ICMPエラーやフラグメントと同じく「FEが作るパケット」の扱いで、一回りで写す数に上限を付け、溢れたら捨てて数える。
- VXLANのメンバーで受けたBUMは、ほかのVXLANのメンバーへは送らない（どのVTEPも自分で全部のVTEPへ送るため。
  RFC 8365の8.3と同じ考え方）。

### MACの表

MACアドレスの学習はパケットの到着ペースで起きるので、表はFEが持つ（[`fe-ce-split.md`](fe-ce-split.md)）。

| 項目 | 内容 |
|---|---|
| キー | ブリッジ、MACアドレス |
| 値 | メンバー（VXLANならVTEPのアドレスも）、最後に見た時刻、学んだか静的か |

- 学ぶ: メンバーで受けたフレームの送信元MAC（ユニキャストのとき）。同じMACを別のメンバーで見たら、
  そのメンバーへ移す（MACの移動として数える）。
- 静的なエントリ: CE（confd）が表`ruster-bridge`に書く。学習で上書きしない。静的なエントリのMACを
  別のメンバーで受けても、フレームは転送する（移さない）。
- エージング: 最後に見てからブリッジのエージング時間（既定300秒、IEEE 802.1Qの推奨値）を過ぎたエントリは
  使わない。一回りで片付ける数には上限を付ける。
- 上限: ブリッジごとの上限と、FE全体の容量（起動時の引数）がある。どちらかに達したら新しいMACを学ばず、
  そのMAC宛てはフラッディングになる。学べなかった数を数える。
- 表が変わったとき: メンバーでなくなったインターフェースの学んだエントリは消す。ブリッジのエージング時間が
  変わっても、学んだエントリは残す。
- workerが複数になったら、各workerが自分の表を持つ。workerの間で表を合わせない（受けたworkerごとに学ぶので、
  初めのうちはフラッディングが多くなる）。

### IRBから出るパケット

転送するパケット、ICMPエラー、フラグメント、kernelのパケット、CEが送るフレームのどれも、出口がIRBなら、
宛先MACでMACの表を引いて、そのメンバーから送る。表に無ければフラッディングする。

- ARPとND: neighdはIRBを普通のインターフェースとして扱う。neighdがIRBへ送るARP RequestやNS
  （ブロードキャスト、マルチキャスト）はフラッディングになり、ReplyやNA（ユニキャスト）は学んだメンバーへ出る。
  ホストからのARP Request（ブロードキャスト）は、フラッディングと同時にIRBで受け、neighdへ渡る。
- IRBのMTUは、どのメンバーのMTUより大きくしない（confdが確かめる）。ブリッジするフレームは
  分割できず、出口のメンバーに入らなければ捨てて数える。

### 準拠するもの

- IEEE 802.1Q: 8.6（転送の処理）、8.7（学習）、8.8（filtering database）、8.6.3と表8-1（橋渡ししない予約の
  アドレス）、エージング時間の既定300秒。
- 外していること: スパニングツリー（STP、RSTP）は持たない。ループを作らないのは運用者。VLAN-awareな
  ブリッジは持たない（上の「形」）。

## 2. 表

[`tables.md`](tables.md)の形で、表`ruster-bridge`を足す。書き手はconfd。項目の名前はIEEE 802.1Qcpの
YANG（`ieee802-dot1q-bridge`）に合わせる。

| 行 | キー | 値 | 備考 |
|---|---|---|---|
| ブリッジ | 名前 | エージング時間（秒）、学ぶMACの上限 | `bridge/component/filtering-database/aging-time`。上限は独自 |
| メンバー | インターフェース | ブリッジの名前 | `bridge-port/bridge-name`（インターフェースの拡張）を別の行にしたもの |
| 静的なMAC | ブリッジ、MACアドレス | メンバーのインターフェース | `filtering-database/filtering-entry` |

- IRBは表「インターフェース」の行で、名前がブリッジと同じもの。種類の拡張は無い。
- 一つのインターフェースは一つのブリッジにだけ入る（キーがインターフェースなので、表の形で決まる）。
- メンバーの行が指すブリッジやインターフェースが無いときは、ほかの表と同じく無効として持つ。

FEが作る状態（読むだけ）:

| 状態 | 中身 |
|---|---|
| MACの表 | ブリッジ、MAC、メンバー、学んだか静的か、最後に見てからの秒数 |
| ブリッジごとの数 | 学んだ数、移した数、期限で消した数、上限で学べなかった数、フラッディングした数と捨てた数、同じメンバーへの宛先で捨てた数、予約のアドレスで捨てた数 |

VXLAN、EtherIP、SRv6の表は、下のそれぞれの節に書く。

## 3. VXLAN

### 形

VXLANのインターフェースはブリッジのメンバーで、一つのVNIを表す（RFC 7348）。表は`ruster-if-vxlan`の行
（キーはインターフェース）で、同じ名前のインターフェースの行がMAC、MTUを持つ。書き手はconfd。

| 項目 | 内容 |
|---|---|
| VNI | 1から16777215 |
| 送信元 | ルータのアドレス（IPv4かIPv6）。外側の送信元になり、このアドレス宛てを受ける |
| VTEPの一覧 | 相手のVTEPのアドレス（1から64個）。BUMを一つずつ包んで送る相手（head-end replication）。全体の設定に書く |

- 外側はdefaultのVRFで送る。UDPの宛先ポートは4789だけ。内側の送信元MACはいつも学ぶ。下側のVRF、ポート、
  学ぶかを選ぶのは、要る場面が出てから。
- 一つのブリッジに置けるVXLANのメンバーは一つ（VXLANのメンバーから来たBUMはほかのVXLANのメンバーへ送らない
  ため）。VXLANのメンバーには静的なMACを置かない（VTEPを持たないため）。

### 送る

```
外側のEthernet | 外側のIPv4/IPv6 | UDP | VXLAN（8バイト: Iフラグ、VNI）| 内側のEthernetフレーム（FCSなし）
```

- 宛先のVTEPは、MACの表のエントリが持つVTEPのアドレス。BUMは一覧の全部のVTEPへ一つずつ送る。
- UDPの送信元ポートは、内側のフレームのフロー（内側のIPのアドレスとポート、無ければMACアドレス）のhashから
  49152から65535の範囲で決める（RFC 7348の5.）。同じフローは同じポートになり、下側のECMPで順番が崩れない。
- 外側のIPv4はDFを立てる（RFC 7348の4.3: VTEPは分割しない）。TTLとHop Limitは64。
- UDPのchecksumは、IPv4では0にする。IPv6では計算する（RFC 7348の5.）。受けるときは、checksumを確かめない。
- 内側にVLANのタグは付けない（RFC 7348の6.1）。
- 外側は下側のVRFで経路を引き直し、近隣を引いて送る（今のトンネルと同じ道）。VXLANのインターフェースの
  MTUは下側の出口のMTUから50（IPv4）か70（IPv6）を引いたものにし、入らないフレームは捨てて数える
  （FEの`overlay_too_big`）。今のconfdは、下側を1500として確かめる。

### 受ける

- ルータの送信元アドレス宛てのUDP 4789で、VNIが一致するVXLANのインターフェースがあり、送信元がVTEPの一覧に
  あるときだけ外す。外した内側のフレームは、そのVXLANのインターフェースで受けたフレームになる（上のブリッジの
  処理へ）。Iフラグが無い、一覧に無いVTEPからのもの、内側にVLANのタグがあるものは捨てて数える。
- 外側がフラグメントなら捨てる（VTEPは分割しないので、届くのは途中で分割されたものだけ）。

### 準拠するもの

- RFC 7348。外していること: マルチキャストの下側（4.2）は持たず、BUMはVTEPの一覧へ一つずつ送る。

## 4. EtherIP

- RFC 3378。IPのプロトコル番号97で、2バイトのヘッダ（版3、残りは0）の後にEthernetのフレーム（FCSなし）を運ぶ。
- 外側はIPv4かIPv6。相手は一つ。表は`ruster-if-tunnel`のEtherIPの行（キーはインターフェース、値は送信元と相手）。
  同じ名前のインターフェースの行がMAC、MTUを持つ。外側はdefaultのVRFで送る（下側のVRFを選ぶのは、要る場面が出てから）。
- EtherIPのインターフェースはブリッジのメンバーにだけなる。
- 受けるのは、送信元アドレス宛てのプロトコル97で、相手から来たものだけ。版が3でなければ捨てて数える。
- 外側は分割しない。MTUは下側の出口のMTUから36（IPv4）か56（IPv6）を引いたもの（内側のEthernetの14、EtherIPの2、
  外側のIPの20か40）。入らないフレームは捨てて数える（FEの`overlay_too_big`）。
- 外側はポートかVLANのサブインターフェースから出す。トンネル、PPPoE、IRBからは出さない。
- 外していること: RFC 3378は外側の分割を禁じていないが、FEは分割も組み立てもしない。

## 5. SRv6

### 表

SIDは、RFC 8986では経路の表の一部として扱われる。そのため書き手はribdで、設定の静的なSIDと方針はconfdが
送り手としてribdへ渡す（静的経路と同じ道。ribdは経路の一つとして選んでFEへ書く）。FPMが運ぶzebraのSRv6の
経路（`seg6local`と`seg6`のencap）を`ruster-frr`がribdへ渡すのはまだ。

| 表 | キー | 値 |
|---|---|---|
| ローカルのSID（`ruster-fib`の経路の動作`srv6-local`） | defaultのVRF、SIDのプレフィックス（IPv6） | 動作: End / End.X（インターフェースと次の転送先のアドレス） / End.DT4（VRF） / End.DT6（VRF） |
| 包む方針（`ruster-fib`の経路の動作`srv6-encap`） | VRF、経路のプレフィックス | 外側の送信元、SIDのリスト（1から8個）、H.Encaps.Redか。外側はdefaultのVRFで送る |

- SIDはdefaultのVRFにだけ置く（下側のVRFを選ぶのは、要る場面が出てから）。
- 外側の送信元は、FE全体で一つの値にせず、方針の行ごとに持つ。confdが`[srv6]`の送信元を全部の方針に入れる。
  表を一つ減らし、ribdは値をそのまま運ぶだけで済むため。
- FEは方針ごとに、FEの中だけのインターフェース（名前は`srv6 <VRF> <プレフィックス>`）を作り、その経路の出口にする。
- End.XのインターフェースがFEに無いか無効なら、そのSIDは無いものとして扱う。

FEが作る状態（読むだけ）: SIDごとの数はまだ。今は捨てた理由（`SRV6_*`）ごとの数だけ。

### SIDのパケットを受けたとき（RFC 8754の4.3、RFC 8986の4.）

defaultのVRFで受けた、受けたインターフェースのMAC宛てのIPv6で、宛先がローカルのSIDに一致したら、
そのSIDの動作で扱う（core `srv6.rs`）。一致しないパケットはSRHを見ずに普通に転送する（RFC 8754の4.2、通過するノード）。

```
End（4.1）、End.X（4.2）:
  SRHがあり、Segments Left != 0
   ├ Hop Limit <= 1 → ICMPv6 Time Exceeded（code 0）
   ├ Last Entryが長さを超える、またはSegments Left > Last Entry + 1
   │   → ICMPv6 Parameter Problem（code 0、Segments Leftの位置）
   └ Segments Leftを1減らし、宛先をSegment List[Segments Left]にする。Hop Limitは続く転送で1減る
       End: defaultのVRFで引き直す（新しい宛先もローカルのSIDなら、続けて扱う。4個まで）
       End.X: 値の次の転送先へ送る
  それ以外 → 「上位のヘッダ」
End.DT6（4.6）、End.DT4（4.7）:
  SRHがあり、Segments Left != 0 → ICMPv6 Parameter Problem（code 0、Segments Leftの位置）
  上位のヘッダが41（End.DT6）か4（End.DT4）→ 外側のIPv6とその拡張ヘッダを全部外し、
      値のVRFで内側を、同じインターフェースで受けたものとして転送する（内側のTTLとHop Limitは普通の転送と同じく減らす）
  それ以外 → 「上位のヘッダ」
上位のヘッダ: 設定で許すものは無い。全部ICMPv6 Parameter Problem（code 4、SR Upper-layer Header Error、
  上位のヘッダの位置。RFC 8986の4.1.1）。SIDへのpingにもこのエラーを返す
```

- ICMPエラーの宛先は外側の送信元。速さの上限は今のICMPv6のエラーと同じ。
- SIDへのパケットで、種類が4でないRouting headerのSegments Leftが0でなければ、Parameter Problem
  （code 0、Routing Typeの位置。RFC 8200の4.4）にする。
- SRHのflags、tag、TLV（HMACなど）は読まない（RFC 8754の4.3.1.1.1、TLVを処理する設定は無い）。
- 外していること: HMAC（RFC 8754の2.1.2）と送信元（5.1）は確かめない。5.1はSR domainの端のaccess listで
  守る形で、ノードで必ずすることではない。SIDへのフラグメントは組み立てずに捨てる。続けて扱うSIDの数だけ
  Hop Limitを減らすのではなく、1回だけ減らす。

### H.Encaps（RFC 8986の5.1）

経路の次の転送先に包む方針があれば、FIBを引いた後、内側のパケットを包む（core `srv6.rs`）。core では、方針ごとに
FEの中だけのインターフェースを一つ置き、その経路の出口にする（DS-Liteのトンネルと同じ形）。

- 外側のIPv6: 送信元は方針の送信元、宛先はSIDのリストの最初のSID。Hop Limitは64（RFC 2473の6.3）。
  Flow Labelは内側のフローのhash（RFC 6437、RFC 8754の5.5）。Traffic Classは内側から写す。内側のTTLとHop Limitは
  普通の転送で1減っている（S05）。
- SRH: SIDのリストを逆順に入れ、Segments LeftとLast Entryはリストの長さ−1。次のヘッダは4（IPv4）か41（IPv6）。
  SIDが1個ならSRHは付けない。H.Encaps.Red（5.2）を選ぶと、最初のSIDをSRHに入れず、Last Entryは長さ−2。
- 包んだ後はdefaultのVRFで最初のSIDを引いて送る。その先がトンネルや別の方針なら捨てる。
- 包むと長くなる分（40、SRHがあれば8 + 16 × SRHのSIDの数）が出口のMTUに入らなければ、IPv4（DF=1）は
  Fragmentation Needed、IPv6はPacket Too Bigを内側の送信元へ返す。MTUは出口のMTUから長くなる分を引いた値。
  DF=0のIPv4は包む前に分割する。外側は分割しない。
- 外していること: H.Encaps.L2は作らない。SRHにflags、tag、TLVは入れない。

## 6. IS-ISとOSPF（FRR）

### 設定と経路

- 全体の設定の`[isis]`（NET、レベル、インターフェースごとのmetricとpassive）と`[ospf]`、`[ospf6]`
  （router-id、area、インターフェースごとのcost、network type、passive）。lockの形には既定値も全部書く
  （`crates/config`の`isis.rs`、`ospf.rs`）。confdが確かめる（`crates/confd/src/isis_ospf.rs`）。defaultのVRFだけで、
  インターフェースはポート、VLAN、ブリッジ（IRB）。名前は12文字まで、アドレスは設定に書いたもの（送り手からのものは不可）。
- `ruster-frr`は`frr`の部分で受け取り、`frr.conf`に`interface rp-<名前>`の節と`router isis ruster`、`router ospf`、
  `router ospf6`を書く（`crates/frr/src/isis_ospf.rs`）。
- 経路はBGPと同じく、zebraがFPMで`ruster-frr`へ渡し、`ruster-frr`が送り手`frr`としてribdへ渡す。
  プロトコルの間の選択（administrative distance）はzebraが行い、ribdはzebraが選んだ経路だけを受ける。

### 問題: kernelからはTUN（L3）しか見えない

- IS-ISのPDUはIPではない。ISO 10589のフレームを、LLC（DSAPとSSAPが0xFE）で、マルチキャストのMAC
  （AllL1ISs 01-80-C2-00-00-14、AllL2ISs 01-80-C2-00-00-15、point-to-pointではAllISs 09-00-2B-00-00-05）へ送る。
  isisdはインターフェースごとにAF_PACKETのsocketでフレームを読み書きするので、L2のデバイスが要る。
  L3のTUNの上では動かない。
- OSPFはIP（プロトコル89）なのでTUNを通る。ただし確かめると、ポートが二つ以上あると足りない:
  - TUNはVRFに一つで、どのポートのアドレスもそこに付く。ospfdは受けたパケットを送信元のサブネットで
    インターフェースに振り分けられるが、送るHello（224.0.0.5、224.0.0.6）はTUNへ一つ出るだけで、FEには
    どのポートへ出すかが分からない（送信元のアドレスで決めることはできるが、FEに特別な処理が要る）。
  - OSPFv3はインターフェースごとのlink-localアドレスで話し、インターフェースを番号で区別する。ポートが
    全部一つのTUNに見えると、ospf6dはポートを区別できない。
  - DR/BDRの選出、インターフェースのリンクの状態、MTUの確かめ（Database Description）も、ポートごとに要る。

### 決定: ルーティングプロトコルを動かすポートごとのTAP

IS-ISかOSPFを動かすインターフェース（ポート、VLANのサブインターフェース、IRB）ごとに、kernelのnetnsに
TAPのデバイスを一つ置く。

```
 ポート p1 ⇄ FE ⇄ TAP rp-p1（kernelのnetns、VRFのデバイスの下）⇄ isisd、ospfd
               ⇄ TUN rt-default（ほかのルータ宛ての通信）
```

- 作るのはconfd（`--kernel`のとき、TUNと同じく。`crates/confd/src/kernel.rs`）。名前は`rp-<インターフェース名>`。
  MACとMTUはそのインターフェースのもの（MTUは1500まで: FEがTAPから受けるフレームの大きさ）。ARPを切り
  （`NOARP`。kernelはARPもNDもDADもしない）、`addrgenmode none`でアドレスを自分で作らせず、`accept_ra`を0にして
  Router Solicitationも出させない。そのインターフェースのアドレスは、link-localも含めてTUNではなくTAPに付ける。
  link-localは同じMACから作るので、FEのポートのlink-localと同じになる。IS-ISもOSPFも動かさなくなった
  インターフェースのTAPは消し、アドレスはTUNへ戻す。
- FEは、TAPへの行があるインターフェースの`rp-<名前>`を、TUNと同じく1秒ごとに見て開く（`TUNSETIFF`に`IFF_TAP`）。
- FEからTAPへ: 受け渡しの分類に、種類`isis`（宛先MACが上の三つで、LLCのDSAPとSSAPが0xFE）と
  `ospf`（IPのプロトコル89で、224.0.0.5、224.0.0.6、ff02::5、ff02::6、またはルータのアドレス宛て）を足し、
  渡し先に「受けたインターフェースのTAP」を足す。行（`isis-<名前>`、`ospf-<名前>`、毎秒1000、まとめて500）は
  confdが、設定でIS-ISやOSPFを動かすインターフェースにだけ書く。フレームはEthernetのまま、変えずに書く。
  マルチキャストは転送の前に、ルータのアドレス宛てのOSPFはルータ宛ての分類のところで取り出す。
- TAPからFEへ:
  - LLCのフレーム（IS-IS）と、宛先がリンクローカルのマルチキャスト（224.0.0.0/24、ff02::/16）のIPは、
    そのインターフェースからそのまま送る（IRBならブリッジへ）。
  - IPv6のリンクローカルのユニキャスト（OSPFv3のbroadcastのリンクで、近隣へのDatabase Descriptionなど）は、
    FEの近隣の表で相手のMACを入れて、そのインターフェースから送る。表に無ければneighdに解決を頼んで捨てる。
    NOARPのTAPでは、kernelはユニキャストの宛先MACに自分のMACを入れるため。
  - それ以外のIPは、そのインターフェースのVRFのTUNから読んだパケットと同じに扱う（kernelのパケットとして転送。
    TTLは減らさない）。TAPには接続の経路が付き、zebraはIS-ISやOSPFの経路をTAP向けに入れるので、ルータ自身の
    通信（OSPFv2の近隣へのユニキャスト、iBGPなど）がTAPから出てくるため。
  - ARPとNDはTAPから出てこない（NOARP）。
- zebraはTAPのデバイスとアドレスを見るので、isisdとospfdはインターフェースごとに動き、経路の次の転送先は
  TAPの番号で届く。`ruster-frr`は1秒ごとにTAPの番号を読み、`rp-<名前>`をFEのインターフェースの名前に戻して
  ribdへ渡す。インターフェースが分かるので、link-localの次の転送先（IS-ISやOSPFv3のIPv6）も渡せる。

### 選ばなかった方法

- 受け渡しのsocketでCEのプロセスへ渡し、そのプロセスがTAPへ書く: 中継が一つ増える。FEはすでにTUNを
  開いて読み書きしているので、TAPも同じ形で持てる。
- OSPFだけはTUNで通す: ポートが一つの構成でしか動かない（上の「問題」）。IS-ISと同じTAPに揃える。

### 確かめたこと（netns `isis`、`ospf`）

- `rp_filter`: TAPのアドレス宛ての通信はTUNから届く。looseでも足りない: Linuxのlooseは、受けたデバイスに
  IPv4アドレスが一つも無いと落とす（全部のアドレスがTAPへ移るとTUNには無い）。confdはTUN、TAP、`all`を0にする。
- NOARPのTAPでは、`nodad`を付けないIPv6アドレスもtentativeにならない（DADをしない）。`addrgenmode none`なら
  link-localも自分では作らない。
- TAPを通る経路: zebraはIS-IS、OSPFの経路をkernelにTAP向けのゲートウェイで入れ、FPMにはTAPの番号で渡す。
  kernelがその経路で送るパケットはTAPから出てきて、FEがTUNのものと同じに転送する。ribdへは`ruster-frr`が
  FEのインターフェースに戻して渡すので、OSPFv3とIS-ISのIPv6のlink-localの次の転送先も使える。
- TAPのリンクの状態: TAPのcarrierはFEが開いている間だけup（TUNのドライバの振る舞い）。FEが止まればisisdと
  ospfdはすぐ気づく。FEは1秒ごとにポートのcarrierを見て、`TUNSETCARRIER`でTAPに写す: ポートはそのポート、
  VLANのサブインターフェースは親のポート、IRBはメンバーのどれかがupならup（VXLANやEtherIPのメンバーは常にup）。表で無効にしたインターフェースは
  down。ポートの切断にはhold time（IS-ISは既定30秒、OSPFはRouterDeadInterval 40秒）を待たずに気づく
  （netns `ospf`で、相手側のvethを落として1秒ほどで隣接が消えるのを確かめた）。
- OSPFのbroadcastのリンクは、DRを選ぶまでRouterDeadInterval（40秒）待つ。netnsの`ospf`はそのため1分ほどかかる。

## 7. BGP EVPN（見送り）

BGP EVPNは見送る（2026-11-10 owner決定。ルーティングデーモンの見直しと一緒に考え直す）。FRRのFPMは、type-3の
VTEP、相手の近隣、L2のMACの送り直しを運ばないので、kernelを経路の入口に使う例外が要るため。

## 8. 作る順番

1. ブリッジとIRB（FEのMACの表、表`ruster-bridge`、confdの`[[bridge]]`、netnsの試験）。VLANのサブインターフェースのメンバーも。
2. EtherIP（ブリッジのメンバーになるトンネルの形を決める）。
3. VXLAN（静的なVTEPの一覧）。
4. IS-ISとOSPFのTAP、`ruster-frr`の`[isis]`、`[ospf]`、`[ospf6]`。
5. SRv6のローカルのSID（End、End.X、End.DT4、End.DT6）とH.Encaps。
