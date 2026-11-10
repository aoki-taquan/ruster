# CEの各プロセス

状態: 叩き台（2026-11-06）。理想の設計図であり、今のコードの説明ではない。

関連: [`overview.md`](overview.md)（プロセスの一覧）、[`tables.md`](tables.md)（FEの表）、
[`control-protocol.md`](control-protocol.md)（メッセージ形式）。

ここでは`ruster-confd`、`ruster-ribd`、`ruster-neighd`と、CLIの`ruster`の中身と、外のデーモンとの
つなぎ方を決める。既製のソフトの橋渡し役と自作の制御（PPPoE、DHCPクライアント）は
[`router-box.md`](router-box.md)。

## 共通の決まり

- 三つのデーモンは、どれも「入力から、FEに書くべき表を計算する」形にする。
  入力が同じなら結果も同じ。FEへは、前に書いた内容との差分だけを送る。
- 外から値を受け取るときは、値ごとに有効期限を付けてもらう。送り手が落ちても、値は期限まで残り、
  期限が来たら消える。送り手は期限の前に送り直して延ばす。
  「送り手が落ちたら何秒保つか」を別に決める必要が無くなる。
- 送り手は、接続し直して値を全部送ったら「送り終わった」を送る。受け取った側が起動し直したときに使う。
- 受け取り口は送り手ごとにsocketを分け、送り手が書ける範囲を設定で限る（下の「送り手」）。
- メッセージは全部[`control-protocol.md`](control-protocol.md)の形式。CEどうしも同じ。

## socketの権限

socketを開けるプロセスは、表を書き換えたり、設定（PPPoEのパスワードを含む）を読んだりできる。そこで
socketはルータのプロセスだけが開けるようにする。決まりはファイルの権限だけで作る
（`crates/proto/src/daemon.rs`）。

- socketを作るプロセスは、無いディレクトリを0750で、socketを0660で作る（umaskによらない）。持ち主と
  グループだけが入れて、つなげる。隣のlockのファイルは0600。
- グループは、置いたディレクトリにset-group-IDの印があればそのディレクトリのグループ、無ければ作った
  プロセスのグループ。作ったディレクトリにも印が引き継がれるので、一番上のディレクトリのグループが
  下の全部のsocketに届く。

置き方は二つある。

| 置き方 | 用意すること |
|---|---|
| 全部をrootで動かす（netnsの試験） | 無し。グループもrootになる |
| プロセスごとにユーザーを分ける | ルータのプロセスが共有するグループ（例: `ruster`）を作り、各プロセスをそのグループで動かす。一番上のディレクトリはそのグループとset-group-IDの印を付けて先に作る（`install -d -m 2750 -g ruster /run/ruster`、systemdならtmpfiles.dの`d /run/ruster 2750 root ruster`） |

分けるときのユーザーと、各プロセスが開くsocketは次のとおり。rootが要るのは、AF_XDPやAF_PACKETを使う
FEと、TUNを作る`confd --kernel`だけ（capabilityで絞ってもよい）。

| プロセス | ユーザー | 作るsocket | つなぐ、送るsocket |
|---|---|---|---|
| `ruster-fe` | root | `fe/config.sock`、`fe/route.sock`、`fe/neigh.sock`、`fe/state.sock`、`fe/punt/*.sock` | 各プロセスの`<名前>/punt.sock` |
| `ruster-confd` | root（`--kernel`）、無ければ専用 | `confd/config.sock`、`confd/part.sock`、`confd/source/*.sock` | `fe/config.sock`、`neighd/config.sock`、`ribd/source/confd.sock` |
| `ruster-ribd` | 専用 | `ribd/source/*.sock` | `fe/route.sock` |
| `ruster-neighd` | 専用 | `neighd/config.sock`、`neighd/punt.sock` | `fe/neigh.sock`、`fe/punt/arp-nd.sock`、`confd/part.sock` |
| `ruster-pppoed`、`ruster-dhcpc` | 専用 | `<名前>/punt.sock` | `fe/punt/<名前>.sock`、`confd/part.sock`、`confd/source/*.sock`、`ribd/source/<名前>.sock` |
| `ruster-kea` | 専用 | `kea/punt.sock` | `fe/punt/kea.sock`、`confd/part.sock` |
| `ruster-unbound`、`ruster-frr` | 専用 | 無し | `confd/part.sock`（frrは`ribd/source/frr.sock`も） |
| `ruster`（CLI） | グループの運用者 | 無し | `confd/config.sock`、`fe/state.sock`、`confd/source/*.sock`、`ribd/source/*.sock` |

限界: グループは一つなので、グループに入ったプロセスはどのsocketも開ける。たとえば`ruster-unbound`も
`confd/part.sock`から`pppoe`の部分（パスワード）を受け取れ、`fe/route.sock`へ書ける。プロセスごとに
開けるsocketを絞るには、socketをグループの違うディレクトリに分ける必要があり、まだしていない。
接続の相手のユーザーを確かめる方法（`SO_PEERCRED`）は、Rustの標準libraryでは安定していないので使わない。

## `ruster-confd`（設定管理）

### 持つもの

| 持つもの | 中身 | 保存 |
|---|---|---|
| 設定 | 全体の設定（[`router-box.md`](router-box.md)）。各プロセスへ担当の部分を配る | ファイル。過去の版も残す |
| 動的な値 | 外のデーモンから受け取った値（DHCPで得たアドレスなど）。有効期限付き | 保存しない |

FEに書く表は「設定」と「動的な値」から計算する。

### 設定と、FEの表は別の形

設定は運用者が書きやすい形、FEの表は転送に必要な形で、一対一には対応しない。例:

- 設定「`wan0`のIPv4アドレスは送り手`dhcp-wan0`から受け取る」→ 受け取ったら、FEのアドレスの表に書く。
- 設定「MAP-Eを使う。ルールはこれ、IPv6プレフィックスは送り手`pd-wan0`から」→ プレフィックスを受け取ったら、
  IPv4アドレス、ポート範囲（PSID）、トンネルの送信元を計算し、FEのアドレス、トンネル、NATの表に書く。
- 設定の静的経路 → FEではなく`ruster-ribd`へ渡す。
- 設定の静的な近隣 → FEではなく`ruster-neighd`へ渡す。

設定のYANGモジュールは標準（`ietf-interfaces`、`ietf-nat`など）を土台に、送り手の指定やMAP-Eのルールの
ような部分を`ruster-config-*`で足す。

### 送り手

外のデーモンからの値は、設定で宣言した送り手からだけ受け取る。

```
送り手 dhcp-wan0 { 種類 dhcp-client; インターフェース wan0; }
送り手 pppoe-wan1 { 種類 pppoe; 親 eth1; }
```

- 送り手ごとに`/run/ruster/confd/source/<名前>.sock`ができる。外のデーモンはそこへ書く。
  値は表の行として書き（`ruster-source`の表、鍵は送り手の名前）、それぞれに有効期限（秒）を付ける。
  confdは受け取った時から数え、送り直されたら数え直す（`crates/confd/src/source.rs`）。
- 送り手の種類ごとに、書ける値が決まっている。

| 種類 | 書ける値 |
|---|---|
| dhcp-client | IPv4アドレス、DNSサーバ |
| dhcpv6-client | IPv6アドレス（IA_NA）、委任されたプレフィックス（IA_PD）、DNSサーバ |
| pppoe | PPPoEのセッション（ID、相手のMAC）、IPCPで得たアドレス、DNSサーバ |

どのインターフェースの値になるかは設定が決める（`ipv4-from`など）。DS-LiteのAFTRやMAP-Eのルールは、
今は設定に書く。

経路はconfdではなく`ruster-ribd`へ渡す（DHCPのdefault経路など）。

外のデーモンの設定（PPPoEの認証情報など）も、confdが全体の設定から担当の部分を配る。既製のソフトの設定に
変えるのは橋渡し役で、confdは既製のソフトの設定の形を知らない。

### 反映の流れ

APIやCLIから候補を受け、各プロセスへ候補、差分、確定を配る。目指す形と今の作り（差分、版、確認付きの反映）は
[`router-box.md`](router-box.md)の「反映の流れ」に書く。
FE、ribd、neighdへは表として書き、橋渡し役などへは`confd/part.sock`で担当のモジュールの部分を渡す。
confd自身の担当の部分は自分で検証し（YANGの制約、参照先があるか、意味の矛盾）、差分（FEの表がどう変わるか、
ribdへ渡す経路）を出し、確定したらFEへ反映する。受け取った設定は番号付きの版としてファイルに残す。

### kernel側への設定

ルータ宛て通信を終端するkernelのnetnsに、VRFデバイス、TUN、アドレスを設定するのもconfd。
一方向で、kernelから読むことはしない。

### 起動し直したとき

固定の待ち時間は使わない。送り手が「送り終わった」と知らせる（BGPのGraceful RestartとEnd-of-RIBと同じ考え方）。

```
confd再起動
 → FEへresync-begin（FEは今の表のまま転送を続ける）
 → 設定から決まる値はすぐ送る
 → 送り手が接続し直して値を送り、最後に「送り終わった」を送る
 → 宣言した全送り手の「送り終わった」が揃ったらresync-end（送り直されなかったエントリだけ消える）
```

- 戻ってこない送り手のために、送り手ごとに上限時間を持つ。過ぎたら「送り終わった」とみなす。
  既定値は送り手の種類で決める（同じ箱の中のデーモンの`pppoe`は10秒）。設定の`sync-wait`で変えられる。
- 動的な値をファイルに残して読み戻す方法は取らない。残した値と実際の値がずれる問題を抱えるため。

## `ruster-ribd`（経路の選択）

### 入力

経路の提供元（送り手）ごとに、VRF、宛先プレフィックス、次の転送先、優先度、metric、有効期限を受け取る。
形は`ietf-routing`（RFC 8349）に合わせる。

| 送り手 | 中身 |
|---|---|
| confd | 設定の静的経路、アドレスから決まる直結経路 |
| DHCP client、PPPoE | default経路 |
| ルーティングデーモン | BGP、OSPFなどの経路 |

送り手の宣言とsocketの分け方はconfdと同じ（`/run/ruster/ribd/source/<名前>.sock`）。

### 選び方

1. VRFと宛先ごとに、優先度が最も高い（数値が小さい）送り手の経路を選ぶ。
2. 同じ優先度なら、metricが小さいもの。
3. それでも同じなら、全部をECMPの次の転送先にする。

### 次の転送先の解決

FEの経路の表は「出力インターフェースと、直接つながった次の転送先」しか持たない。BGPの経路のように
次の転送先が直接つながっていないときは、ribdが別の経路をたどって、直接つながった次の転送先に置き換えてから
FEへ書く。たどった先の経路が変われば、それに依存する経路も書き直す。

送り手は、自分の次の転送先がどう解決されたかを購読できる（BGPが到達性を判断するため）。

### 送り手が落ちたとき

値の有効期限に従う。BGPのように「接続が切れても一定時間は経路を残す」ものは、送り手が接続のときに
保持時間を宣言する。

ribd自身が起動し直したときは、confdと同じく送り手の「送り終わった」を待ってからFEの古い経路を消す。

### VRFの間の経路

FEは二つの道具だけを持つ（[`tables.md`](tables.md)の「経路」）。

- 次の転送先の出力インターフェースが別のVRFに属していてよい。
- 「VRF Xで引き直す」という経路の動作。

どの経路を別のVRFへ漏らすかはribdが決める。設定に「VRF AはVRF Bから、このプレフィックスの経路を取り込む」
という取り込みの規則を書く。BGP L3VPNのroute targetのような仕組みはルーティングデーモンの仕事で、
rusterでは作らない。取り込みの規則の細かい書き方は、必要な場面が出てから決める。

### 規模

100万経路を扱う。更新は差分で受け取り、差分でFEへ書く。FEへの書き込みは短い間の更新をまとめて送る。

## `ruster-neighd`（近隣の解決）

### 仕事

- FEの解決依頼を受け、ARP RequestまたはNSを送る。応答が来たらFEの近隣の表に書く。来なければ再送し、
  諦めたら「解決できない」として書く（FEは待たせていたパケットを捨て、ICMP Host Unreachableを返す）。
- ルータ自身のアドレスへのARP RequestとNSに応答する。
- IPv6のアドレスが追加されたら重複検出（DAD）を行い、結果をconfdへ返す。
- アドレスが追加されたら告知（Gratuitous ARP、Unsolicited NA）を送る。
- 設定の静的な近隣（confdから受け取る）も、近隣の表の書き手として書く。

### 近隣がまだ使われているか

NDでは、使われている近隣だけを確かめ直す（RFC 4861の状態遷移）。使われているかどうかはFEしか知らない。

- FEは近隣の表のエントリごとに「使われた」印を持ち、パケットが通ったら印を付ける。
- neighdは定期的に印を読んで消す。印のあるエントリだけ確かめ直し、無いものは期限で消す。

### IPv6のアドレスの状態

- confdはIPv6アドレスを「仮」としてFEに書く。FEは仮のアドレスを送信元に使わず、DADに関わるパケットだけを扱う。
- neighdがDADを行い、結果をconfdへ返す。confdは「使える」か「重複」に書き換える。
- `ietf-ip`のアドレスの状態（tentative、preferred、duplicateなど）をそのまま使う。

### RA（ルータ広告）

LANへのRA（RFC 4861の6.2）はneighdが送る。設定は全体の設定の`[[ra]]`で、neighdは`confd/part.sock`の
モジュール`ra`で受け取る（[`router-box.md`](router-box.md)の「自作の制御」）。ほかのルータのRAは読まない。

## `ruster`（CLI）

常駐しない。人が使う道具で、他のプロセスと同じメッセージ形式で話す普通の利用者。

| 使い方 | 話す相手 |
|---|---|
| 設定の編集、差分、確定、戻す | confd |
| 経路の表示（候補を全部含む） | ribd |
| 近隣の表示 | neighd |
| 転送の状態（カウンタ、NATセッション、firewallの通信、受け渡しの数） | FEの`state.sock` |

- 表示は人向けの表と、機械向けのJSON（RFC 7951）の両方。
- 各socketのメッセージを覗いて解読するデバッグ用の機能も持つ。

CLIが特別な権限や裏口を持たないので、他の道具（監視、自動化）も同じことができる。

## つながりの一覧

| 送る側 | 受ける側 | 中身 |
|---|---|---|
| confd | FE | インターフェース、アドレス、NAT、firewall、トンネル、受け渡しの分類 |
| ribd | FE | 経路 |
| neighd | FE | 近隣 |
| FE | neighd | 解決依頼、「使われた」印、ARP/NDのフレーム |
| FE | confd | リンク状態、表の使用量 |
| confd | ribd | 静的経路、直結経路 |
| confd | neighd | 静的な近隣、DADの依頼 |
| neighd | confd | DADの結果 |
| 外のデーモン | confd | 送り手として、アドレス、PPPoEのセッション、プレフィックス、鍵 |
| 外のデーモン | ribd | 送り手として、経路 |
| 外のデーモン | FE | 受け渡しのsocketで、DHCP、PPPoE、RAなどのフレーム |
| CLI | 全部 | 設定と表示 |

## 未決事項

- ribdの優先度の既定値（静的、直結、DHCP、BGPなど）。
- VRFの間で経路を漏らす取り込みの規則の書き方と、VRFをまたぐNATとfirewallの細かい動作（必要な場面が出てから）。
