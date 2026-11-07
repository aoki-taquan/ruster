# 全体像

状態: 叩き台（2026-11-06）。理想の設計図であり、今のコードの説明ではない。

関連: [`../charter.md`](../charter.md)、[`fe-ce-split.md`](fe-ce-split.md)（FEとCEの線引き）、
[`control-protocol.md`](control-protocol.md)（メッセージ形式）。

## プロセスの一覧

### rusterが作るもの

転送に最低限必要なものだけ。これだけで静的経路のルータとして動く。

| プロセス | 役割 | FEへ書く表 | 常駐 |
|---|---|---|---|
| `ruster-fe` | 転送部。表を持ち、表に従って転送する | — | する |
| `ruster-confd` | 設定管理。設定を保持し、検証してFEと各プロセスへ配る | インターフェース、アドレス、NAT、firewall、トンネル、ルータ宛て通信の分類 | する |
| `ruster-ribd` | 経路の選択。各提供元の経路から一つを選び、FIBを書く | 経路（FIB） | する |
| `ruster-neighd` | 近隣の解決。ARPとND（NS/NA、自分のアドレスのDAD） | 近隣 | する |
| `ruster`（CLI） | 人が使う道具。設定の編集、検証、反映、`show` | 書かない（`ruster-confd`へ頼む） | しない |

FEとCEの全プロセスは、同じメッセージ形式のライブラリを使う。

### rusterの外にあるもの

別のプロジェクトとして作るか、既製のものを使う。rusterのrepositoryには入れない。

| 種類 | 例 | rusterとのつながり |
|---|---|---|
| ルーティングプロトコル | BGP、OSPF（自作のデーモン） | 経路を`ruster-ribd`へ渡す。BGPのTCPはkernelで終端 |
| アドレスの取得 | DHCP client、DHCPv6-PD client | 受け取ったアドレスを`ruster-confd`へ、経路を`ruster-ribd`へ渡す。フレームはFEから直接受け取る |
| リンクの確立 | PPPoE（PADI/PADO、LCP、IPCP、IPv6CP） | セッションを`ruster-confd`へ渡す。フレームはFEから直接受け取る |
| LAN向けのサービス | DHCP server、RA | フレームをFEとやり取りするだけ |
| アプリケーション | DNS、NTP、SSH、管理API | kernelのsocketで動く。FEとは直接話さない |
| 鍵交換 | WireGuardのハンドシェイク、IKE | 鍵を`ruster-confd`へ渡す（暗号処理そのものはFE） |

外のデーモンがFEの表へ直接書くことはない。経路は`ruster-ribd`、それ以外は`ruster-confd`を通す。
これでFEの表の書き手はrusterの三つのプロセスだけになる。

### 経路の選択を`ruster-ribd`に置く理由

- 経路の提供元は一つではない（設定の静的経路、アドレスから決まる直結経路、DHCPのdefault経路、BGP）。
  どれかを選ぶ処理がどこかに要る。
- 外のルーティングデーモンにこれを任せると、そのデーモンが無い構成では静的経路すら入らない。
- 選択はプロトコルではないので、charterの「プロトコルは作らない」と矛盾しない。
- `ruster-ribd`は経路の提供元に向けて標準の`ietf-routing`（RFC 8349）の形を見せる。FEへは選んだ結果だけを
  `ruster-fib`で書く。

## 構成図

```
                     人 ── ruster（CLI）
                              │ 設定の編集・反映、show
                              ▼
 外のデーモン ──────────→ ruster-confd ───────────────┐
 （DHCP client、PPPoE、        │ 静的経路、直結経路     │ インターフェース、アドレス、
   WireGuard鍵交換など）       ▼                       │ NAT、firewall、トンネル、分類
 ルーティングデーモン ──→ ruster-ribd ──────── FIB ──┤
                                                       ▼
                          ruster-neighd ── 近隣 ──→ ruster-fe ⇄ NIC
                               ▲                  │  │
                               └── ARP/ND フレーム ─┘  │ ルータ宛てのTCP/UDP（TUN）
 DHCP、PPPoE、RAのデーモン ⇄── フレーム ─────────────┤  ▼
                                                   kernel（専用netns）
                                                      ⇅ socket
                                       BGP、DNS、SSH、NTP、管理API
```

## VRF

VRF（一つのルータの中に、互いに独立した経路表を複数持つ仕組み）は、ルータの基本機能として最初から持つ。

- インターフェースはどれか一つのVRFに属する。何も指定しなければ`default`。
- FIB、NAT、firewallの表はVRFごとに分かれる。近隣の表はインターフェースに属するので、VRFを持たない。
- `ruster-ribd`はVRFごとに経路を選ぶ。VRFの間で経路を漏らすのもribdで、FEは「別のVRFのインターフェースへ送る」と「別のVRFで引き直す」だけを持つ。
- ルータ宛ての通信もVRFを保つ。VRFごとにTUNを持ち、kernel側はLinuxのVRFデバイスで分ける（[`fe-ce-split.md`](fe-ce-split.md)）。
- VRFの定義には標準の`ietf-network-instance`（RFC 8529）の形を使う。

## 三つの流れ

### 1. 通過するパケット

```
NIC → I/O層 → worker（表を引いて処理）→ I/O層 → NIC
```

- CEは一切関わらない。workerは表を読むだけで、表への書き込みは制御用のthreadが行う。
- 次の転送先の近隣が表に無ければ、FEは`ruster-neighd`へ解決依頼を出す。そのパケットは次の転送先ごとに
  少数だけFEで待たせ、溢れたら捨てる。
- NATやfirewallの状態はFEの中で作られ、CEへは出ない（見るのは`show`だけ）。

### 2. 制御（表の更新）

```
外のデーモン → ruster-confd / ruster-ribd / ruster-neighd → FEの制御用thread → 新しい版の表 → worker
```

- CEはFEへiPATCHを送る。FEの制御用threadは新しい版の表を作り、workerは処理の切れ目で新しい版へ
  切り替える。workerはlockを取らない（方法は「FEの中身」の文書で決める）。
- FEは反映し終えてから応答を返す。応答が返った時点で、全workerが新しい表を使っている。
- 通知（近隣の解決依頼、リンク状態の変化）は逆向きに、FEからCEへObserveで届く。

### 3. ルータ宛ての通信

FEは、ルータ宛ての通信を分類し、種類ごとに上限を付けてから渡す。

| 種類 | 渡し先 | 通り道 |
|---|---|---|
| ARP、ND | `ruster-neighd` | 専用のUnix datagram socket |
| DHCP、DHCPv6、RS/RA、PPPoE | 担当の外のデーモン | 専用のUnix datagram socket |
| それ以外のTCP/UDP、ICMPのEcho | kernel | TUN |
| トンネルの中身（MAP-E、DS-Lite、WireGuard） | 渡さない | FEがトンネルを外して転送する |

kernelから外へ出るパケットはTUNからFEへ戻り、FEが経路を引いて送り出す。kernelはフォワーディングをしない。

## 起動と障害

- systemdが起動する。順番は`ruster-fe`、`ruster-confd`、`ruster-ribd`と`ruster-neighd`、外のデーモン。
- 起動直後のFEの表は空で、何も転送しない（どのインターフェースも有効になっていないため）。
- **CEのプロセスが落ちたとき**: FEは表を最後の状態のまま保って転送を続ける。再起動したプロセスは
  自分の表を全部送り直す（送られなかったエントリはFEが消す）。
- **FEが落ちたとき**: 転送は止まる。再起動したFEに、書き手の三つのプロセスが接続し直して表を全部送り直す。
  NATやfirewallの状態は失われる。
- **`ruster-confd`の設定**: 設定は`ruster-confd`がファイルに保存する。CLIからの反映は、検証、差分の表示、
  反映の順に進む。反映に失敗したら、一つ前の設定を新しい版として反映し直す。
- **外のデーモンが落ちたとき**: 渡した値には有効期限が付いていて、期限まで残る（[`ce-processes.md`](ce-processes.md)）。

## 置き方

置き方は決めない。同じプロセスの組み合わせを、1台にまとめても、FEとCEを別々の場所に置いても
使えるように、柔軟にしておく。

そのために守ること:

- FEとCEは、決まった形式のメッセージだけでつながる。同じメッセージは、Unix socketでも
  ネットワーク越しでも運べるようにする。
- FEは、動く場所の違いをI/O層の違いとして扱う。転送の処理は置き方で変えない。
- ルータ宛ての通信の終端（kernelとTUN）は、FEと同じ場所に置く。

## 設計の前提として今のコードと違う点

実装を置き換えるときに影響する。

- `ruster-core`には見直し前のARPの処理（学習、待たせ、再送）が残っている。
- AF_XDPのnative部分はx86_64でしか動かない。DPU（ARM）ではaarch64対応が要る。

## 未決事項

- FEとCEが別マシンにあるときの認証（TLSのクライアント証明書など）。
