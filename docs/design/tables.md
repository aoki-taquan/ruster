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

## 一覧

| 表 | YANGモジュール | VRFの軸 | 書き手 | 値の出どころ |
|---|---|---|---|---|
| VRF | `ietf-network-instance`（RFC 8529） | — | confd | 設定 |
| インターフェース | `ietf-interfaces`（RFC 8343）+ 種類ごとの拡張 | 各インターフェースが一つのVRFに属する | confd | 設定、PPPoEのデーモン |
| アドレス、MTU | `ietf-ip`（RFC 8344） | インターフェース経由 | confd | 設定、DHCP、PPPoE（IPCP）、DHCPv6-PD、MAP-E計算 |
| インターフェースごとの動作 | `ruster-if-ip` | インターフェース経由 | confd | 設定 |
| 経路（FIB） | `ruster-fib` | VRFごと | ribd | 設定、直結、DHCP、ルーティングデーモン |
| 近隣 | `ruster-neighbor` | インターフェース経由 | neighd | ARP、ND |
| NAT | `ietf-nat`（RFC 8512）の一部 + VRFの結び付け | VRFごと | confd | 設定、MAP-E計算 |
| firewall | `ietf-access-control-list`（RFC 8519）+ `ruster-firewall` | VRFごと | confd | 設定 |
| ルータ宛て通信の分類 | `ruster-punt` | 全体で一つ | confd | 設定 |
| WireGuardのセッション鍵 | `ruster-wireguard` | インターフェース経由 | confd | 鍵交換のデーモン |
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
| IPトンネル | `ruster-if-tunnel` | 種類（IPv4 in IPv6、IPv6 in IPv4、GRE）、下側のVRF、送信元、宛先 | DS-Liteはこれ一つで表せる |
| WireGuard | `ruster-if-wireguard` | 下側のVRF、待ち受けポート、相手（公開鍵、接続先、許可するアドレス） | 鍵交換は外のデーモン。暗号化と復号はFE |
| loopback | — | — | 特定のポートに属さないルータのアドレス用 |

VXLANなど他のトンネルは、使う場面が出たら同じ形で足す。

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

## ルータ宛て通信の分類（`ruster-punt`）

ルータ宛て、またはCEが処理すべきパケットの分類と渡し先、上限を決める。

| 項目 | 内容 |
|---|---|
| 分類の名前 | 例: `arp`、`nd`、`dhcpv4`、`dhcpv6`、`ra`、`pppoe-discovery`、`ppp-control`、`wireguard-handshake`、`bgp`、`ssh`、`other` |
| 一致条件 | 決まった種類（ARP、ND、PPPoEなど）か、IPのプロトコルとポート |
| 渡し先 | CEのsocketの名前 / kernel（そのVRFのTUN） / 捨てる |
| 上限 | 毎秒のパケット数と、まとめて許す数 |
| 優先度 | 溢れたときに先に捨てる順 |

- ARPとNDの分類と渡し先（neighd）は、設定が無くても最初からある。消せない。
- ルータ宛てでどの分類にも当たらないものは`other`としてkernelへ渡す（firewallのinputを通った後）。

FEが作る状態（読むだけ）: 分類ごとの受け渡し数と捨てた数。

## WireGuardのセッション鍵（`ruster-wireguard`）

- 鍵交換は外のデーモンが行い、できたセッション鍵（送信用、受信用、番号、期限）をconfdへ渡す。
  confdがFEへ書く。
- FEは、送ろうとしたときに有効なセッションが無ければ「鍵交換が要る」と通知する。
  近隣の解決依頼と同じ形。
- WireGuardの鍵は2分ほどで入れ替わる。confdを経由する分の遅れが問題になるかは、
  CEの各プロセスの文書で確かめる。

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
| WireGuardのセッションの状態 | `ruster-wireguard`の状態 |
| 各表の使用量と容量 | `ruster-fe`の状態 |

## 通知

FEからCEへ、Observeで届く。

| 通知 | 受け取る側 |
|---|---|
| 近隣の解決依頼 | neighd |
| リンク状態の変化 | confd、ribd、neighd |
| WireGuardの鍵交換が要る | confd（から鍵交換のデーモンへ） |
| 表の使用量が上限に近い | confd |

## 未決事項

- `ietf-nat`、`ietf-access-control-list`、`ietf-network-instance`のSIDの有無。
- VLANの標準モデルがRFCにならないまま変わったときの扱い。
- WireGuardの鍵をconfd経由で渡すときの遅れ。
- IPv6のRA（ルータ広告）を受け取る側（ホストとして動くインターフェース）をどう扱うか。
- マルチキャストの転送（IGMP/MLD、PIM）は扱っていない。必要になったら表を足す。
- QoS（帯域制御、優先制御）は扱っていない。必要になったら表を足す。
