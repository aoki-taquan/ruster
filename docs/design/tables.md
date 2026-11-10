# FEの表の一覧

状態: 叩き台（2026-11-06）。理想の設計図であり、今のコードの説明ではない。

関連: [`overview.md`](overview.md)（プロセスと書き手）、[`control-protocol.md`](control-protocol.md)（メッセージ形式）。

## 方針

- FEが転送に使うデータは、すべてこの文書の表のどれかに入る。ここに無いものをFEは知らない。
- 表はYANGで表す。標準モジュールが合うものは標準を使い、合わないものだけ`ruster-*`の独自モジュールにする。
- 書き手は`ruster-confd`、`ruster-ribd`、`ruster-neighd`の三つだけ。外のデーモンが知った値（DHCPで得た
  アドレス、PPPoEのセッションなど）は`ruster-confd`か`ruster-ribd`を通して入る。
- FEが計算で作る値は表に書かせない。たとえばIPv6のsolicited-nodeマルチキャストの受信は、アドレスの表から
  FEが自分で決める。逆に、設定から導ける値でも計算が複雑なもの（MAP-Eのアドレスやポート範囲）は
  `ruster-confd`が計算し、FEには結果だけを書く。FEを単純に保つため。
- 表をまたぐ参照（インターフェース、VRF）の先が無いときは、エントリを無効として保持する
  （[`control-protocol.md`](control-protocol.md)の「エラー」）。
- 表の容量（NATセッションの最大数など）は表ではなく、FEの起動時の引数にする。FEは起動時に全部を
  確保し、動作中に確保しない。
- FEの動作の既定はRFCどおりにする。RFCから外したほうがよい使い方がある動作は、表の値で選べるように
  する（既定はRFCどおり）。選べる動作は、それぞれの表の節に書く。

## 一覧

| 表 | YANGモジュール | VRFの軸 | 書き手 | 値の出どころ |
|---|---|---|---|---|
| VRF | `ietf-network-instance`（RFC 8529） | — | confd | 設定 |
| インターフェース | `ietf-interfaces`（RFC 8343）+ 種類ごとの拡張 | 各インターフェースが一つのVRFに属する | confd | 設定、PPPoEのデーモン |
| アドレス、MTU | `ietf-ip`（RFC 8344） | インターフェース経由 | confd | 設定、DHCP、PPPoE（IPCP）、DHCPv6-PD、MAP-E計算 |
| インターフェースごとの動作 | `ruster-if-ip` | インターフェース経由 | confd | 設定 |
| 経路（FIB）、SRv6のローカルのSIDと包む方針 | `ruster-fib` | VRFごと | ribd | 設定、直結、DHCP、ルーティングデーモン |
| 近隣 | `ruster-neighbor` | インターフェース経由 | neighd | ARP、ND |
| NAT | `ietf-nat`（RFC 8512）の一部 + VRFの結び付け | VRFごと | confd | 設定、MAP-E計算 |
| firewall | `ietf-access-control-list`（RFC 8519）+ `ruster-firewall` | VRFごと | confd | 設定 |
| ブリッジ、メンバー、静的なMAC | `ruster-bridge`（`ieee802-dot1q-bridge`の項目の名前） | — | confd | 設定 |
| VTEPの一覧 | `ruster-if-vxlan` | インターフェース経由 | confd | 設定 |
| ルータ宛て通信の分類 | `ruster-punt` | 全体で一つ | confd | 設定 |
| FE全体の動作 | `ruster-fe` | 全体で一つ | confd | 設定 |

`ietf-nat`、`ietf-access-control-list`、`ietf-network-instance`にIANAのSIDが割り当てられているかは
確かめていない。無ければ、独自モジュールと同じ実験用の範囲から自分で割り当てる。

## VRF

`ietf-network-instance`の`network-instance`（名前、有効か）をそのまま使う。インターフェースは同じRFCの
`bind-ni-name`でVRFに属する。何も指定しなければ`default`。

## インターフェース

`ietf-interfaces`の`interface`（名前、種類、有効か）を共通の部分とし、種類ごとの項目を拡張で足す。

| 種類 | 拡張 | 主な項目 | 備考 |
|---|---|---|---|
| Ethernet | — | MACアドレス | 物理ポート。FEが起動時に受け取ったNICと名前で結び付く |
| VLAN | `ietf-if-vlan-encapsulation`の形 | 親、タグ1つまたは2つ | 標準はまだdraft（draft-ietf-netmod-sub-intf-vlan-model-18）。形を合わせ、RFCになったら置き換える |
| PPPoE | `ruster-if-pppoe` | 親、セッションID、相手のMAC | セッションの確立は外のデーモン。FEは包むのと外すのだけ |
| IPトンネル | `ruster-if-tunnel` | 種類（IPv4 in IPv6、IPv6 in IPv4、GRE、EtherIP）、下側のVRF、送信元、宛先 | DS-Liteはこれ一つで表せる。EtherIPは別の行（インターフェースごと）で、ブリッジのメンバーにだけなる |
| VXLAN | `ruster-if-vxlan` | VNI、送信元、下側のVRF、UDPのポート、学ぶか | ブリッジのメンバーにだけなる。VTEPの一覧は別の行 |
| IRB | — | — | 名前がブリッジと同じインターフェース（[`overlay.md`](overlay.md)） |
| loopback | — | — | 特定のポートに属さないルータのアドレス用 |

ブリッジ、VXLAN、EtherIP、SRv6の表の中身は[`overlay.md`](overlay.md)に書く。

### 「下側のVRF」

トンネルの外側のパケット（包んだ後）がどのVRFの経路で送られるかを示す。トンネルの内側のVRFは、
トンネルのインターフェースが属するVRF。これで「外側はdefault、内側は利用者のVRF」が表せる。

## アドレス、MTU

`ietf-ip`のIPv4/IPv6の`address`（アドレス、プレフィックス長、出どころ）と`mtu`を使う。

- 出どころ（`origin`）には、設定、DHCP、リンクローカル、などが入る。FEは区別しないが、`show`で見える。
- IPv6のリンクローカルアドレスも、confdが決めて書く。FEは自分では作らない。
- `ietf-ip`のうち近隣のリストとIPv6の自動設定の項目は使わない（近隣は`ruster-neighbor`、自動設定はCEの仕事）。

## インターフェースごとの動作（`ruster-if-ip`）

ルータとしての細かい動作をインターフェースごとに切り替える。

- 送信元アドレスの検証（uRPF）: 無効 / loose / strict
- ICMP Redirectを送るか
- ICMP Unreachableを送るか
- 届いたARP/NDをneighdへ渡すか（無効にするとこのインターフェースでは近隣を学ばない）

## 経路（`ruster-fib`）

[`control-protocol.md`](control-protocol.md)の形のとおり。VRFごとに、宛先プレフィックスから次のどれかを引く。

- 転送: 次の転送先のリスト（出力インターフェースと、任意で次の転送先のアドレス）。複数ならECMP。
  PPPoEやトンネルのように相手が一つしかないインターフェースでは、アドレスを書かない。
- ルータ宛て（local）、黙って捨てる（discard）、ICMP Unreachableを返す（reject）。
- 別のVRFで引き直す（lookup-vrf）。
- SRv6のローカルのSID（End、End.X、End.DT4、End.DT6）。次の転送先には、SRv6で包むSIDのリストを付けられる
  （[`overlay.md`](overlay.md)の5.）。

VRFをまたぐ転送には二つの方法がある。次の転送先の出力インターフェースが別のVRFに属していれば、
そのまま送る（インターフェースが自分のVRFを持っているので、FEに追加の処理は要らない）。
宛先を別のVRFで引き直したいときはlookup-vrfを使う。どの経路を漏らすかはribdが決める
（[`ce-processes.md`](ce-processes.md)）。

VRFをまたぐ通信の扱いは次のとおり。細かい動作は必要な場面が出てから決める。

- firewall: 受信した側のVRFのforwardのルールで判定する。
- NAT: セッションは行きと戻りのVRFを両方覚える（例: 利用者のVRFからインターネット用のVRFへ出るときのNAPT）。
- 片方向だけ漏らした設定は、`ruster`の検証で警告する。

## 近隣（`ruster-neighbor`）

インターフェースとIPアドレスから、相手のMACアドレスを引く。IPv4（ARP）もIPv6（ND）も同じ表。

FEが作る状態（読むだけ）: 解決待ちの宛先と、その間待たせているパケットの数。

## NAT

`ietf-nat`の`instances/instance`を使い、VRFへの結び付けだけを`ruster-nat`で足す。使うのは次の部分だけ。

| 使い方 | `ietf-nat`の項目 |
|---|---|
| 送信元アドレスとポートを変換する（NAPT） | NATの種類`napt44`、外側のアドレス（`external-ip-address-pool`） |
| ポート範囲を限ったNAPT（MAP-E） | `port-set-restrict`の`psid-offset`、`psid-len`、`psid` |
| 外から内へのポート開放 | NATの種類`dst-nat`、静的な対応（`mapping-table`） |
| IPv6のプレフィックス変換 | NATの種類`nptv6` |
| 制限 | `port-quota`、`mapping-limits`、`connection-limits` |
| タイマー | `policy/timers`（UDP、TCPの各段階、ICMP、フラグメント） |

- 外側のアドレスを固定値でなく「このインターフェースのアドレス」で指定する方法は`ietf-nat`に無いので、
  `ruster-nat`で足す（PPPoEやDHCPでアドレスが変わるため）。
- 動的な対応（実際のセッション）はFEが作る状態で、表には書かない。`ietf-nat`では`mapping-table`が設定側に
  置かれているが、rusterでは静的な対応だけをここに書き、動的な対応は読むだけの状態として見せる。
- NAT64、CLAT、SIITなどは、使う場面が出たら同じモジュールの範囲で足す。
- 選べる動作（既定はRFCどおり）:
  - 外からの戻りの絞り方（filtering）。
  - 変換したフラグメント可能なデータグラムのIPv4のIDが、最大の寿命の間に繰り返さないよう速さを限るか
    （RFC 6864 5.2）。限ると、内側のホストが共有する宛先への速い通信が落ちることがある。
  - 内側のホストごとに対応を作る速さの上限（RFC 6888 REQ-5 b）。値を変えるか、上限を外せる。

## firewall

ルールの書き方は`ietf-access-control-list`を使う。照合できる項目はEthernet、IPv4/IPv6、TCP/UDP/ICMPの
ヘッダの値と、入出力インターフェース。動作は許可、破棄、拒否。

`ietf-access-control-list`は1パケットずつの照合しか表せず、通信の状態を追う仕組みが無い。そこで
`ruster-firewall`で次を足す。

- どこに適用するか（VRFごと）
  - 転送するパケット（forward）
  - ルータ宛てのパケット（input）
  - ルータ自身が送るパケット（output。kernelからTUNで出てくるもの）
- 状態を追うか。追う場合、確立済みの通信と、それに関連する通信（ICMPエラーなど）を先に許可する。
- ルールに当たらなかったときの既定の動作。
- 状態のタイマー。

ルールのインターフェースへの適用（`ietf-access-control-list`の`attachment-points`）も使える。
状態を追う適用（`ruster-firewall`）と1パケットずつの適用が両方あるときは、1パケットずつの方を先に見る。

FEが作る状態（読むだけ）: 追っている通信の一覧、ルールごとの一致数。

### IPv6

IPv4とIPv6の転送に同じfirewallを使う。決めること（RFC 4890、RFC 6092を参考にする）:

- 状態の表は一つで、IPv4とIPv6の通信を一緒に持つ。容量も共有する。
- ルールは一つの家族（IPv4かIPv6）のprefixを持ち、その家族のパケットにだけ当たる。
  プロトコルは`tcp`、`udp`、`icmp`（ICMPv4）、`icmpv6`。
- IPv6の拡張ヘッダ（Hop-by-Hop、Routing、Destination Options、Fragment）は、決まった数まで
  たどって上位のヘッダを見つける。見つからないものは落とす。
- 先頭でないフラグメントは、firewallがあるあいだ落とす（IPv4のような追跡は後で足す）。
- ICMPv6のEchoは、ICMPv4と同じくidで状態を追う。エラー（Destination Unreachable、
  Packet Too Big、Time Exceeded、Parameter Problem）は、中身が追っている通信に当たるときだけ通す。
  Packet Too Bigは経路のMTUを知るのに要る（RFC 4890 4.3.1）。
- NDはリンクの外へ転送しないので、forwardのルールの対象にならない。
- ルータ自身が作るICMPとICMPv6のエラーは、IPv4と同じくforwardのルールを通らない。

## ルータ宛て通信の分類（`ruster-punt`）

ルータ宛て、またはCEが処理すべきパケットの分類と渡し先、上限を決める。

| 項目 | 内容 |
|---|---|
| 分類の名前 | 例: `arp`、`nd`、`dhcpv4`、`dhcpv6`、`ra`、`pppoe-discovery`、`ppp-control`、`bgp`、`ssh`、`other` |
| 一致条件 | 決まった種類（`arp`、`nd`、`pppoe-discovery`、`ppp-control`、TAPへの`isis`、`ospf`と、kernelへの`icmp-error`、`icmp`、`tcp-syn`、`tcp`、`udp`、`other`）か、IPのプロトコルとTCP/UDPの宛先ポートの範囲 |
| インターフェース | 受けたインターフェース。省略するとどれでも |
| 渡し先 | CEのsocketの名前 / kernel（そのVRFのTUN） / 受けたインターフェースのTAP（IS-IS、OSPF。[`overlay.md`](overlay.md)の6.） / 捨てる |
| 上限 | 毎秒のパケット数と、まとめて許す数 |

- `arp`、`nd`（渡し先はneighd）と、kernelへの種類の分類（`icmp-error`から`other`まで）は、設定が無くても
  最初からある。消せない。同じ名前の行で変えられるのは上限だけ（kernelへの種類は捨てるにもできる）。
  行を消すと既定の上限（毎秒2000、まとめて200）に戻る。
- ルータ宛ての通信は、まずIPのプロトコルとポートの行に当て、当たらなければその種類の分類でkernelへ渡す
  （firewallのinputを通った後）。同じパケットに当たりうる行が二つあれば、その表は断る。
- 渡し先がCEのプロセスの行は、PPPoEのDiscoveryとセッションの中のPPPの制御、IPのプロトコルとポートで
  255.255.255.255やff02::/16宛てのもの（DHCP、DHCPv6）を、転送の前に取り出して渡す。ルータのアドレス宛ての
  ものもinput firewallの後で渡す。どれもEthernetのフレームのまま。
- 優先度は持たない。分類ごとに別の上限を持つので、溢れた分類がほかの分類を押し出さない。
- kernelへの分類の上限は、VRFごとに別に数える。

FEが作る状態（読むだけ）: 分類ごとの受け渡し数と捨てた数。

## FE全体の動作（`ruster-fe`）

インターフェースやVRFに属さない設定。

- ICMPエラーを生成する速さの上限
- 解決待ちのパケットを待たせる数と時間
- フラグメントの組み立てを待つ時間

## FEが作る状態（読むだけ）

`state.sock`から読める。表には書けない。

| 状態 | 置き場所 |
|---|---|
| インターフェースのリンク状態、カウンタ、`if-index` | `ietf-interfaces`の状態の項目 |
| 解決待ちの近隣 | `ruster-neighbor`の状態 |
| NATのセッション | `ruster-nat`の状態 |
| firewallで追っている通信、ルールごとの一致数 | `ruster-firewall`の状態、`ietf-access-control-list`の統計 |
| ルータ宛て通信の受け渡し数と捨てた数 | `ruster-punt`の状態 |
| MACの表と、ブリッジごとの数 | `ruster-bridge`の状態 |
| SRv6のSIDごとの数 | `ruster-fib`の状態 |
| 各表の使用量と容量 | `ruster-fe`の状態 |

## 通知

FEからCEへ、Observeで届く。

| 通知 | 受け取る側 |
|---|---|
| 近隣の解決依頼 | neighd |
| リンク状態の変化 | confd、ribd、neighd |
| 表の使用量が上限に近い | confd |

## 未決事項

- `ietf-nat`、`ietf-access-control-list`、`ietf-network-instance`、`ieee802-dot1q-bridge`のSIDの有無。
- VLANの標準モデルがRFCにならないまま変わったときの扱い。
- IPv6のRA（ルータ広告）を受け取る側（ホストとして動くインターフェース）をどう扱うか。
- マルチキャストの転送（IGMP/MLD、PIM）は扱っていない。必要になったら表を足す。
- QoS（帯域制御、優先制御）は扱っていない。必要になったら表を足す。
