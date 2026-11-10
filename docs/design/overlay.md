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

VXLANのインターフェースはブリッジのメンバーで、一つのVNIを表す（RFC 7348）。表は`ruster-if-vxlan`
（インターフェースの種類の拡張）と、VTEPの一覧の表。書き手はconfd。

| 項目 | 内容 |
|---|---|
| VNI | 1から16777215 |
| 送信元 | ルータのアドレス（IPv4かIPv6）。外側の送信元になり、このアドレス宛てを受ける |
| 下側のVRF | 外側のパケットを送るVRF（[`tables.md`](tables.md)の「下側のVRF」と同じ） |
| UDPの宛先ポート | 既定4789（IANA） |
| VTEPの一覧 | 行ごとに（インターフェース、相手のVTEPのアドレス）。BUMを一つずつ包んで送る相手（head-end replication） |
| 学ぶか | 内側の送信元MACを、VTEPのアドレスと一緒に学ぶか（既定は学ぶ。BGP EVPNで静的に入れるときは学ばない） |

### 送る

```
外側のEthernet | 外側のIPv4/IPv6 | UDP | VXLAN（8バイト: Iフラグ、VNI）| 内側のEthernetフレーム（FCSなし）
```

- 宛先のVTEPは、MACの表のエントリが持つVTEPのアドレス。BUMは一覧の全部のVTEPへ一つずつ送る。
- UDPの送信元ポートは、内側のフレームのフロー（内側のIPのアドレスとポート、無ければMACアドレス）のhashから
  49152から65535の範囲で決める（RFC 7348の5.）。同じフローは同じポートになり、下側のECMPで順番が崩れない。
- 外側のIPv4はDFを立てる（RFC 7348の4.3: VTEPは分割しない）。TTLとHop Limitは64。
- UDPのchecksumは、IPv4では0にする。IPv6では計算する（RFC 7348の5.、RFC 6935）。受けるときは、どちらでも0を受け入れる。
- 内側にVLANのタグは付けない（RFC 7348の6.1）。
- 外側は下側のVRFで経路を引き直し、近隣を引いて送る（今のトンネルと同じ道）。VXLANのインターフェースの
  MTUは下側の出口のMTUから50（IPv4）か70（IPv6）を引いたものにし、入らないフレームは捨てて数える。

### 受ける

- ルータの送信元アドレス宛てのUDP 4789で、VNIが一致するVXLANのインターフェースがあり、送信元がVTEPの一覧に
  あるときだけ外す。外した内側のフレームは、そのVXLANのインターフェースで受けたフレームになる（上のブリッジの
  処理へ）。Iフラグが無い、一覧に無いVTEPからのもの、内側にVLANのタグがあるものは捨てて数える。
- 外側がフラグメントなら捨てる（VTEPは分割しないので、届くのは途中で分割されたものだけ）。

### 準拠するもの

- RFC 7348。外していること: マルチキャストの下側（4.2）は持たず、BUMはVTEPの一覧へ一つずつ送る。

## 4. EtherIP

- RFC 3378。IPのプロトコル番号97で、2バイトのヘッダ（版3、残りは0）の後にEthernetのフレーム（FCSなし）を運ぶ。
- 外側はIPv4かIPv6。相手は一つ。表は`ruster-if-tunnel`の種類にEtherIPを足す（送信元、相手、下側のVRF）。
- EtherIPのインターフェースはブリッジのメンバーにだけなる。
- 受けるのは、送信元アドレス宛てのプロトコル97で、相手から来たものだけ。版が3でなければ捨てて数える。
- 外側は分割しない。MTUは下側の出口のMTUから22（IPv4）か42（IPv6）を引いたもの。入らないフレームは捨てて数える。
- 外していること: RFC 3378は外側の分割を禁じていないが、FEは分割も組み立てもしない。

## 5. SRv6

### 表

SIDは、RFC 8986では経路の表の一部として扱われる。そのため書き手はribdで、FPMが運ぶzebraのSRv6の経路
（`seg6local`と`seg6`のencap）を`ruster-frr`がribdへ渡し、設定の静的なSIDはconfdが送り手としてribdへ渡す。

| 表 | キー | 値 |
|---|---|---|
| ローカルのSID（`ruster-fib`の行の種類） | VRF（下側）、SIDのプレフィックス | 動作: End / End.X（次の転送先: インターフェースとアドレス） / End.DT4（VRF） / End.DT6（VRF） |
| 包む方針（`ruster-fib`の次の転送先の拡張） | 経路のプレフィックス（どのVRFでも） | SIDのリスト（1個以上）。外側は下側のVRFで送る |
| 包むときの送信元 | FE全体で一つ（`ruster-fe`） | IPv6アドレス |

FEが作る状態（読むだけ）: SIDごとに、処理した数と、ICMPエラーにした数。

### SIDのパケットを受けたとき（RFC 8754の4.3、RFC 8986の4.）

IPv6の宛先が、下側のVRFのローカルのSIDに一致したら、そのSIDの動作で扱う。一致しないパケットはSRHを
見ずに普通に転送する（RFC 8754の4.2、通過するノード）。

```
End、End.X:
  SRHがある
   ├ Segments Left = 0 → SRHの次のヘッダを処理する（下の「SRHの後」）
   ├ Hop Limit <= 1 → ICMPv6 Time Exceeded（code 0）
   ├ Last Entryが長さを超える、またはSegments Left > Last Entry + 1
   │   → ICMPv6 Parameter Problem（code 0、Segments Leftの位置）
   └ Hop Limitを1減らし、Segments Leftを1減らし、宛先をSegment List[Segments Left]にする
       End: 下側のVRFで引き直して送る。End.X: 値の次の転送先へ送る
  SRHが無い → 「SRHの後」
End.DT4、End.DT6:
  SRHがあり、Segments Left != 0 → ICMPv6 Parameter Problem（code 0、Segments Leftの位置）
  次のヘッダが4（End.DT4）か41（End.DT6）→ 外側のIPv6とその拡張ヘッダを全部外し、
      値のVRFで内側を転送する（内側のTTLとHop Limitは普通の転送と同じく減らす）
  それ以外 → 「SRHの後」
SRHの後: ルータ宛てとして扱えるもの（ICMPv6のEcho）はkernelへ渡し、それ以外は
  ICMPv6 Parameter Problem（code 4、SR Upper-layer Header Error。RFC 8986の4.1.1）
```

- ICMPエラーの宛先は外側の送信元。速さの上限は今のICMPv6のエラーと同じ。
- ルータのSIDでないアドレス宛てで、Segments Leftが0でないSRHは、今のIPv6の処理と同じく
  Parameter Problem（code 0、Routing Typeの位置。RFC 8200の4.4）にする。
- SRHのTLV（HMACなど）は読まずに飛ばす（RFC 8754の2.1）。外していること: HMAC（RFC 8754の2.1.2）は確かめない。

### H.Encaps（RFC 8986の5.1）

経路の次の転送先に包む方針があれば、FIBを引いた後、内側のパケットを包む。

- 外側のIPv6: 送信元はFE全体の送信元、宛先はSIDのリストの最初のSID。Hop Limitは64。Flow Labelは内側の
  フローのhash（RFC 6437）。Traffic Classは内側から写す。
- SRH: SIDのリストを逆順に入れ、Segments LeftとLast Entryはリストの長さ−1。次のヘッダは4（IPv4）か41（IPv6）。
- 包んだ後は下側のVRFで最初のSIDを引き直して送る（今のトンネルと同じく、引き直しは2段まで）。
- 包むと長くなる分（40 + 8 + 16 × SIDの数）が出口のMTUに入らなければ、IPv4（DF=1）はFragmentation Needed、
  IPv6はPacket Too Bigを内側の送信元へ返す。MTUは出口のMTUから長くなる分を引いた値。DF=0のIPv4は
  包む前に分割する。
- 外していること: H.Encaps.Red（最初のSIDをSRHに入れない形）とH.Encaps.L2は作らない。

## 6. IS-ISとOSPF（FRR）

### 設定と経路

- 全体の設定に`[isis]`（NETのarea、レベル、インターフェースごとのmetricとpassive）と`[ospf]`、`[ospf6]`
  （router-id、area、インターフェースごとのcost、network type、passive）を足す。lockの形には既定値も全部書く。
- `ruster-frr`は今の`frr`の部分に入れて受け取り、`frr.conf`の`router isis`、`router ospf`、`router ospf6`と
  インターフェースの節を書く。
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

- 作るのはconfd（`--kernel`のとき、TUNと同じく）。名前は`rp-<インターフェース名>`（Linuxの15文字に
  入らなければconfdが断る）。MACはそのインターフェースのMACと同じにし、ARPを切る（`NOARP`。kernelは
  ARPもNDもDADもしない）。そのインターフェースのアドレスは、TUNではなくTAPに付ける。link-localは同じMACから
  作るので、FEのポートのlink-localと同じになる。
- FEからTAPへ: 受け渡しの分類に、種類`isis`（宛先MACが上の三つで、LLCのDSAPとSSAPが0xFE）と
  `ospf`（IPのプロトコル89で、224.0.0.5、224.0.0.6、ff02::5、ff02::6、またはルータのアドレス宛て）を足し、
  渡し先に「受けたインターフェースのTAP」を足す。行はconfdが、設定でIS-ISやOSPFを動かすインターフェースに
  だけ書く。フレームはEthernetのまま、変えずに書く。
- TAPからFEへ:
  - LLCのフレーム（IS-IS）と、宛先がリンクローカルのマルチキャスト（224.0.0.0/24、ff02::/16）のIPは、
    そのインターフェースからそのまま送る（IRBならブリッジへ）。
  - それ以外のIPは、そのインターフェースのVRFのTUNから読んだパケットと同じに扱う（kernelのパケットとして転送）。
    zebraはIS-ISやOSPFの経路をkernelにもTAP向けに入れるので、ルータ自身の通信（iBGPなど）がTAPから出てくるため。
  - ARPとNDはTAPから出てこない（NOARP）。
- zebraはTAPのデバイスとアドレスを見るので、isisdとospfdはインターフェースごとに動き、経路の次の転送先は
  TAPの番号で届く。`ruster-frr`は`rp-<名前>`をFEのインターフェースの名前に戻してribdへ渡す。
  インターフェースが分かるので、link-localの次の転送先（IS-ISやOSPFv3のIPv6）も渡せる。

### 選ばなかった方法

- 受け渡しのsocketでCEのプロセスへ渡し、そのプロセスがTAPへ書く: 中継が一つ増える。FEはすでにTUNを
  開いて読み書きしているので、TAPも同じ形で持てる。
- OSPFだけはTUNで通す: ポートが一つの構成でしか動かない（上の「問題」）。IS-ISと同じTAPに揃える。

### 実装で確かめること

- TAPに付けたアドレス宛ての通信は、FEからはTUNで届く。kernelの`rp_filter`をlooseか0にする。
- TAPのリンクの状態（FEが開いている間だけup）をポートのリンクの状態に合わせるか。合わせればisisdとospfdが
  ポートの切断にすぐ気づく。

## 7. BGP EVPN（未決）

charterはBGP EVPN（RFC 7432、RFC 8365）をFRRで使うと決めた。できるかどうかは別のagentが調べている。
決まっていないこと:

- zebraとbgpdは、VNIとMACアドレスをkernelのVXLANとbridgeのデバイスから知る。kernelにはTUNとTAPしか
  無いので、何をkernelに見せるか（kernelにVXLANとbridgeのデバイスを置き、データは流さない、など）。
- 受けたtype-2（MAC/IP）とtype-3（Inclusive Multicast Ethernet Tag）の経路を、FPMで受けられるか
  （`dplane_fpm_nl`が近隣とMACの更新を運ぶか）。受けられないなら、どこから読むか。
- 受けた値を誰がFEへ書くか。MACの静的なエントリとVTEPの一覧の書き手はconfdなので、`ruster-frr`が
  送り手としてconfdへ渡すか、別の書き手を置くか（「一つの表に書き手は一つ」との兼ね合い）。
- FEが学んだMACを、bgpdへどう知らせるか（type-2の広告に要る）。
- ARPとNDの抑制（RFC 7432の10.）をneighdで持つか。

## 8. 作る順番

1. ブリッジとIRB（FEのMACの表、表`ruster-bridge`、confdの`[[bridge]]`、netnsの試験）。VLANのサブインターフェースのメンバーも。
2. EtherIP（ブリッジのメンバーになるトンネルの形を決める）。
3. VXLAN（静的なVTEPの一覧）。
4. IS-ISとOSPFのTAP、`ruster-frr`の`[isis]`、`[ospf]`、`[ospf6]`。
5. SRv6のローカルのSID（End、End.X、End.DT4、End.DT6）とH.Encaps。
6. BGP EVPN（調べた結果を見てから）。
