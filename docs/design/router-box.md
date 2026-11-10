# ルータ箱としての組み立て

状態: 叩き台（2026-11-10）。理想の設計図であり、今のコードの説明ではない。

関連: [`../charter.md`](../charter.md)の「作るもの」のルータ箱としての組み立て、
[`ce-processes.md`](ce-processes.md)（CEの各プロセス）、[`tables.md`](tables.md)（FEの表）。

FEと、rusterのCE（confd、ribd、neighd）に、既製のソフト（FRR、Kea、Unbound）と自作の制御
（PPPoE、DHCPクライアント、RA）を足して、一つのルータ箱として動かす。そのための設定の分け方と、
既製のソフトのつなぎ方を決める。

## 用語

- 全体の設定: 運用者が書く、ルータ箱の設定。FEの表とは別の形。
- 橋渡し役: 既製のソフト一つとrusterをつなぐ、rusterのプロセス。

## 設定の三段

```
全体の設定（運用者が書く。ファイル。版を残す）
  │ 各プロセスが自分の担当の部分だけを読む
  ├─ confd            インターフェース、アドレス、NAT、firewall、トンネル → FEの表
  ├─ ribd             静的経路、経路の優先度
  ├─ neighd           静的な近隣、RA
  ├─ ruster-frr       BGP、OSPFなど → FRRの設定
  ├─ ruster-kea       DHCPのサーバ → Keaの設定
  ├─ ruster-unbound   DNS → Unboundの設定
  ├─ ruster-pppoed    PPPoEの認証情報
  └─ ruster-dhcpc     WAN側のDHCPクライアント
FEの表（CORECONF）: confd、ribd、neighdだけが書く
```

- 全体の設定には、FEの表に当たる値（PPPoEのセッション番号と相手のMAC、MAP-Eのプレフィックスなど、
  実行中に決まる値）を書かない。それらは担当のプロセスが得て、confdへ送り手として渡す。
- 全体の設定の型はYANGで決める。標準のモジュール（`ietf-interfaces`、`ietf-ip`、`ietf-routing`、
  `ietf-nat`、`ietf-dhcp`など）を土台に、足りない部分を`ruster-*`のモジュールで足す。
- 各プロセスは、全体の設定のうち自分の担当のモジュールだけを読む。担当の外の部分は読まない。

### 反映の流れ

中央の管理プロセスは置かない。常駐しないCLIが、関係するプロセスへ順に話す。

```
CLI: 全体の設定の候補を読み、型を検証する
CLI → 各プロセス: 候補の版（担当の部分）
各プロセス: 意味を検証し、差分を返す（FEの表、FRRの設定、消えるNATセッションなど）
CLI: 差分を人に見せる
CLI → 各プロセス: 確定
各プロセス: 反映する
```

- どれか一つでも検証に失敗したら、どのプロセスにも確定を送らない。
- 確定の後に一つが反映に失敗したら、CLIが全員へ一つ前の版を新しい版として送り直す。
- 版はファイルとして残し、番号で戻せる。「N分以内に確認しなければ戻す」も、CLIが全員へ前の版を
  送ることで行う。CLIが終わっていても戻すため、戻す時刻は各プロセスが持つ。
- 起動したプロセスは、確定した最新の版を自分で読む。

## 橋渡し役

既製のソフト一つにつき一つ。仕事は三つ。

1. 全体の設定の担当の部分を、相手のソフトの設定に変えて書き、相手に読み直させる。
2. 相手から得た値を、rusterのCEのプロセスへ送り手として渡す。
3. 相手が必要とする動的な値（WAN側で得たDNSサーバなど）を、ほかのCEのプロセスから受け取って設定に入れる。

- 既製のソフトの起動と再起動はsystemdに任せる。橋渡し役は相手を起動しない。
- 既製のソフトは、ルータ宛て通信を終端するkernelのnetnsで動く。FEから見るとTUNの先のホストになる。
- 相手のソフトの設定のうち、全体の設定で表せない部分は、運用者が書いたファイルを取り込めるようにする
  （FRRのroute-mapなど）。取り込んだ部分は橋渡し役が解釈しない。

### FRR（`ruster-frr`）

- FRRのzebraに、外の転送部へ経路を渡すFPM（`dplane_fpm_nl`）を使わせる。`ruster-frr`がFPMの受け手になり、
  受けた経路をribdへ送り手`frr`として渡す。kernelの経路表は使わない。
- BGPなどのTCPは、kernelで終端する（TUN経由）。
- zebraにはFEのインターフェースとアドレスが見えない。インターフェースの状態と直結経路は、
  `ruster-frr`がconfdから受け取ってzebraへ教える。教え方（FPMの逆向き、vtyshなど）は作るときに決める。

### Kea（`ruster-kea`）

- LANのポートはFEが持ち、kernelからは見えない。DHCPのフレームは、FEの受け渡しの表でLANのポートから
  `ruster-kea`へ渡す。
- `ruster-kea`はDHCPのリレー（DHCPv4はRFC 1542とRFC 3046、DHCPv6はRFC 8415のrelay-forw）として振る舞い、
  kernelのnetnsのKeaへUDPで渡す。Keaの返事はクライアントへのフレームに戻し、FEの受け渡しで送り出す。
- Keaの設定は制御用のsocketで入れ替える。

### Unbound（`ruster-unbound`）

- Unboundは、ルータのLAN側のアドレスで待ち受ける（TUN経由）。
- 問い合わせを許す範囲は、全体の設定のLANのプレフィックスから作る。
- 上流のDNSサーバは、全体の設定に書くか、`ruster-dhcpc`や`ruster-pppoed`がWAN側で得た値を使う。
- 設定は`unbound-control`で入れ替える。

## 自作の制御

| プロセス | 中身 | 得た値の渡し先 |
|---|---|---|
| `ruster-pppoed` | PPPoEのDiscovery（RFC 2516）、LCP（RFC 1661）、認証（PAP、CHAP: RFC 1994）、IPCP（RFC 1332）、IPv6CP（RFC 5072） | セッションとアドレスはconfd、経路はribd、DNSサーバは`ruster-unbound` |
| `ruster-dhcpc` | DHCPv4（RFC 2131）、DHCPv6（RFC 8415）とプレフィックスの委任 | アドレスとプレフィックスはconfd、経路はribd、DNSサーバは`ruster-unbound` |
| neighd（RA） | LANへのRA（RFC 4861の6節） | なし。広告するプレフィックスはconfdから受け取る |

- PPPoEとDHCPのフレームは、FEの受け渡しの表で担当のプロセスへ渡す（[`fe-ce-split.md`](fe-ce-split.md)の
  「L2の制御のフレーム」）。
- 委任されたプレフィックスからLANのアドレスとMAP-Eの値を計算するのはconfd。全体の設定に「LANのIPv6は
  送り手`dhcpc-wan`の委任から、サブネット番号1」のように書く。
- RAはNDの一部なのでneighdに置く。

## 今の設定ファイルからの移り方

今の`ruster apply`のTOMLは、FEの表をほぼそのまま書いた形。次の順で移す。

1. 全体の設定の型（YANG）と書き方を決め、confdの担当の部分を読めるようにする。今のTOMLは捨てる。
2. 実行中に決まる値を、全体の設定から外す。
   - PPPoEのセッション番号と相手のMAC → `ruster-pppoed`から。それまでは送り手を手で書く道具で渡す。
   - MAP-Eのプレフィックス → `ruster-dhcpc`の委任から。
3. 反映の流れを、CLIが各プロセスへ話す形にする。

## 確かめ方

netnsの試験に、FRR、Kea、Unboundを実際に動かす構成を足す。今のnetnsの試験と同じくローカルで回し、CIには入れない。
FRR、Kea、UnboundはUbuntuのパッケージを使う。

- FRR: 隣のnetnsのFRRとBGPを張り、受けた経路でFEが転送する。
- Kea: LANのホストがDHCPでアドレスを得て、WANへ出られる。DHCPv6も同じ。
- Unbound: LANのホストが名前を引ける。
- PPPoE: 隣のnetnsのPPPoEサーバ（`pppoe-server`）とセッションを張り、MAP-EやNATの外側として使う。
- DHCPクライアント: 隣のnetnsのKeaからアドレスとプレフィックスを得て、LANのRAとMAP-Eに使う。

## 作る順番

1. 全体の設定と反映の流れ（上の「移り方」の1と3）。
2. Unbound。橋渡し役の型を決める。
3. Kea（リレーを含む）と、neighdのRA。
4. `ruster-dhcpc`（MAP-Eのプレフィックスを全体の設定から外す）。
5. FRR。
6. `ruster-pppoed`。

## 未決事項

- 全体の設定の書き方（TOML、YANGのJSON表現（RFC 7951）、波括弧の形など）。
- `ruster-frr`がzebraへインターフェースを教える方法。
- 確定と戻しを、CLIが途中で落ちたときにも揃える方法（版番号を全員で比べるなど）。
