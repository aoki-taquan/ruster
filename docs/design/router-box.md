# ルータ箱としての組み立て

状態: 叩き台（2026-11-10）。理想の設計図であり、今のコードの説明ではない。

関連: [`../charter.md`](../charter.md)の「作るもの」のルータ箱としての組み立て、
[`ce-processes.md`](ce-processes.md)（CEの各プロセス）、[`tables.md`](tables.md)（FEの表）。

FEと、rusterのCE（confd、ribd、neighd）に、既製のソフト（FRR、Kea、Unbound）と自作の制御
（PPPoE、DHCPクライアント、RA）を足して、一つのルータ箱として動かす。そのための設定の分け方と、
既製のソフトのつなぎ方を決める。

## 用語

- 全体の設定: 運用者が書く、ルータ箱の設定。FEの表とは別の形。`ruster.toml`と`ruster.lock`の二つからなる。
- 橋渡し役: 既製のソフト一つとrusterをつなぐ、rusterのプロセス。

## 設定の三段

```
API、CLI ─ ruster.toml（省略してよい）、またはlockの形をそのまま
  ▼
confd: 全体の設定を預かる。解決してlockの形にし、版を残し、確定と戻しを行う
  │ 各プロセスへ担当の部分だけを配る（lockの形）
  ├─ confd自身        インターフェース、アドレス、NAT、firewall、トンネル → FEの表
  ├─ ribd             静的経路、経路の優先度
  ├─ neighd           静的な近隣、RA
  ├─ ruster-frr       BGP、OSPFなど → FRRの設定
  ├─ ruster-kea       DHCPのサーバ → Keaの設定
  ├─ ruster-unbound   DNS → Unboundの設定
  ├─ ruster-pppoed    PPPoEの認証情報
  └─ ruster-dhcpc     WAN側のDHCPクライアント
FEの表（CORECONF）: confd、ribd、neighdだけが書く。どれもFEと直接つなぐ
```

- 設定を預かって配るのはconfd。confdはFEの表の書き手でもあるが、ほかのプロセスとFEの間を中継はしない。
  ribdやneighdはconfdから設定を受け取り、FEへは自分で書く。

- 全体の設定には、FEの表に当たる値（PPPoEのセッション番号と相手のMAC、MAP-Eのプレフィックスなど、
  実行中に決まる値）を書かない。それらは担当のプロセスが得て、confdへ送り手として渡す。
- 全体の設定の型はYANGで決める。標準のモジュール（`ietf-interfaces`、`ietf-ip`、`ietf-routing`、
  `ietf-nat`、`ietf-dhcp`など）を土台に、足りない部分を`ruster-*`のモジュールで足す。
- 各プロセスは、confdから自分の担当のモジュールだけを受け取る。担当の外の部分は受け取らない。
  受け取り口は`/run/ruster/confd/part.sock`。プロセスがつないで担当のモジュールの名前（`dns`など）を
  POSTで送ると、confdはそのモジュールの部分をlockの形のTOMLでPUTし、変わるたびにPUTし直す。
  プロセスは受け入れたか断ったかをPUTへの応答で返す（`crates/confd/src/part.rs`）。

### `ruster.toml`と`ruster.lock`

Cargoの`Cargo.toml`と`Cargo.lock`に倣う。どちらもTOMLで書く。ファイルは入れ方の一つで、設定の正本は
confdが持つ。APIからも同じ形で入れられる。

- `ruster.toml`は人が書く。既定値と、ほかの設定から導ける値は省いてよい。
- `ruster.lock`は、`ruster.toml`をconfdが解決したもの。全てのパラメータを明示し、省略は無い。
  YANGで言えば、全体の設定のインスタンスを既定値も含めて書いたもの（RFC 6243の`report-all`）。
- 各プロセスはlockの形の設定だけを受け取り、既定値を持たない。必須の値が無ければエラーにする。
- 解決は共有のライブラリで行う。confdが使い、CLIも手元で解決の結果を見るのに使う。
- lockに入れる値と入れない値の線引き:
  - 入れる: 既定値と、設定だけから決まる値（PPPoEのMTUは親のMTUから8を引く、など）。
  - 入れない: 実行中の値と、実行中の値に依存する導出（委任されたプレフィックス、PPPoEのセッション、
    デフォルト経路から決まるfirewallの外側など）。これらは担当のプロセスが実行中に計算する。
    lockには値をどの送り手から受け取るかだけを書く。
  - 入れない: 既製のソフト（FRR、Kea、Unbound）の設定そのもの。橋渡し役がlockから作る。
- 一度解決したlockの値は、rusterを更新しても変わらない。既定値の変更を取り込むのは、運用者が明示して
  解決し直したときだけ（`cargo update`に当たる）。
- `ruster.toml`があるときは、lockを手で直さない。機械が設定を作るときは、lockの形を直接入れてよい。
- lockの形には版番号を付ける。パラメータを消したり意味を変えたりするときは版番号を上げ、古い版を
  新しい版へ書き換える（confdが行う）。

### 反映の流れ

```
API、CLI → confd: 全体の設定の候補
confd: 解決し、型を検証する
confd → 各プロセス: 候補の版（担当の部分）
各プロセス: 意味を検証し、差分を返す（FEの表、FRRの設定、消えるNATセッションなど）
confd → API、CLI: 差分
API、CLI → confd: 確定
confd → 各プロセス: 確定
各プロセス: 反映する
```

- 今は候補と確定を分けていない。confdは新しい設定を全員へ送り、どれか一つが断ったら全員へ一つ前の設定を
  送り直す（`ruster apply`）。候補、差分、確定の形にするのは後で行う。
- どれか一つでも検証に失敗したら、どのプロセスにも確定を送らない。
- 確定の後に一つが反映に失敗したら、confdが全員へ一つ前の版を新しい版として送り直す。
- 全員が受け取った設定を、confdは番号付きの版として`--state-dir`のファイルに残す（lockの形と、
  `ruster.toml`で来たときはその文。最新の50個。`crates/confd/src/versions.rs`）。
  `ruster rollback N`は版Nの設定を新しい設定と同じ道で送り、新しい版にする（間の版は消さない）。
  「N分以内に確認しなければ戻す」はまだ。
- 起動したプロセスは、confdから確定した最新の版を受け取る。confdが起動し直したときは、残した最新の版を
  読んで配り直す。起動時に渡すファイルは、版がまだ無いときだけ読み、版1になる。

## 橋渡し役

既製のソフト一つにつき一つ。仕事は三つ。

1. confdから受け取った担当の部分を、相手のソフトの設定に変えて書き、相手に読み直させる。
2. 相手から得た値を、rusterのCEのプロセスへ送り手として渡す。
3. 相手が必要とする動的な値（WAN側で得たDNSサーバなど）を、ほかのCEのプロセスから受け取って設定に入れる。

- 担当の部分は`confd/part.sock`から受け取り、受け入れたか断ったかを返す（「設定の三段」）。相手のソフトの
  設定に書けない、または相手が読み直せないときは断り、書く前のファイルに戻す。confdは前の版に戻す。
- 既製のソフトの起動と再起動はsystemdに任せる。橋渡し役は相手を起動しない。
- 既製のソフトは、ルータ宛て通信を終端するkernelのnetnsで動く。FEから見るとTUNの先のホストになる。
- 相手のソフトの設定のうち、全体の設定で表せない部分は、運用者が書いたファイルを取り込めるようにする
  （FRRのroute-mapなど）。取り込んだ部分は橋渡し役が解釈しない。

### FRR（`ruster-frr`）

- FRRのzebraに、外の転送部へ経路を渡すFPM（`dplane_fpm_nl`）を使わせる。`ruster-frr`がFPMの受け手になり、
  受けた経路をribdへ送り手`frr`として渡す。kernelの経路表は使わない。FPMはTCPだけなので、`ruster-frr`は
  kernelのnetnsの`127.0.0.1:2620`で待ち、zebraの`frr`ユーザーのsocketからの接続だけを受ける。
- BGPなどのTCPは、kernelで終端する（TUN経由）。
- 設定は全体の設定の`[bgp]`（default VRFだけ）。`ruster-frr`は`confd/part.sock`のモジュール`frr`で受け取り、
  FRRの`frr.conf`を全部書いて`frr-reload.py`で読ませる。運用者のファイル（`include`）は最後にそのまま足す。
  取り込みは全部受け、送り出しは`networks`だけにする（RFC 8212の明示的な方針。ある近隣の経路を別の近隣へ流さない）。
- zebraへインターフェースは教えない。confdがkernelのnetnsのTUNにルータのアドレスを付けるので、zebraは
  そこから直結のプレフィックスを知り、直結の近隣の次の転送先を到達できるとみなす。FEのポートのリンクの
  状態はzebraに伝わらない（BGPのholdで切れる）。
- 次の転送先: zebraはTUNしか見ないので、FPMの経路はゲートウェイのアドレスとTUNの番号で来る。`ruster-frr`は、
  ゲートウェイを含むdefault VRFのインターフェースのプレフィックス（confdが部分`frr`の`connected`に入れる）から
  FEのインターフェースを決め、ribdへ「そのインターフェースとゲートウェイ」で渡す。ribdは次の転送先を
  再帰的に解決しない（ce-processes.mdの「次の転送先の解決」はまだ）ので、近隣はインターフェースの
  サブネットにあるものだけにする（multihopのBGPはまだ）。kernelの既定経路で次の転送先を解決させる
  `ip nht resolve-via-default`は使わない（解決しても`ruster-frr`がFEのインターフェースを決められないため）。
- IPv6の近隣へ広告する次の転送先のlink-localは、FEのそのポートのもの（MACから作る）にする。bgpdは
  TUNのlink-localを渡すが、それにはFEのどのポートも答えない。受けた経路は、link-localではなくグローバルの
  次の転送先を使わせる（どのインターフェースか分かるため）。どちらもroute-mapで行う。
- zebraはFPMに加えてkernelのnetnsにも経路を入れるが、行き先は全部TUNなので転送には効かない。

### Kea（`ruster-kea`）

- LANのポートはFEが持ち、kernelからは見えない。DHCPのフレームは、FEの受け渡しの表でLANのポートから
  `ruster-kea`へ渡す。表の行はconfdが書く。全体の設定の`[[dhcp]]`のインターフェースごとに、UDPの67番
  （ブロードキャストと、更新のときのルータのアドレス宛て）を`kea`へ渡す行`dhcp-<インターフェース名>`。
- `ruster-kea`はDHCPのリレー（DHCPv4はRFC 1542とRFC 3046、DHCPv6はRFC 8415のrelay-forw）として振る舞い、
  kernelのnetnsのKeaへUDPで渡す。Keaの返事はクライアントへのフレームに戻し、FEの受け渡しで送り出す。
- Keaはkernelのnetnsのloopback（`lo/127.0.0.1`、変えられる）で、`dhcp-socket-type: udp`で待ち受ける。
  `ruster-kea`はインターフェースのアドレスのUDP 67番からリレーし、Keaは`giaddr`の67番へ返す。Keaの
  `giaddr`と同じアドレスでは待ち受けない（返事が自分に届いてしまう）。server identifierはインターフェースの
  アドレスにし、更新の要求もFEが`ruster-kea`へ渡す。
- `ruster-kea`はサブネットを一つのファイルに書き、運用者の`kea-dhcp4.conf`が`Dhcp4`の中で`<?include?>`で
  取り込む。lease database、制御用のsocket、ログは運用者のファイルに書く。書いたら制御用のsocketで
  `config-reload`を送る。Keaが断ったら前のファイルに戻して断る。Keaが動いていなければ受け入れる
  （起動したときに読む）。
- DHCPv6は全体の設定の`[[dhcp6]]`。confdはUDPの547番を`kea`へ渡す行`dhcp6-<インターフェース名>`を書き、
  `dhcp`の部分に入れて渡す。`ruster-kea`はインターフェースのグローバルなアドレスのUDP 547番からKeaの
  dhcp6（`lo/::1`）へRelay-forwardを送り、KeaはRelay-replyをそのアドレスへ返す。クライアントへの返事は
  ルータのリンクローカルアドレスから、クライアントが最後に送ってきたフレームのMACへ送る。Keaのdhcp6の
  ファイルも同じく運用者の`kea-dhcp6.conf`が取り込む。クライアントがDHCPv6を使うには、`[[ra]]`で
  `managed`か`other`を立てる。

### Unbound（`ruster-unbound`）

- Unboundは、ルータのLAN側のアドレスで待ち受ける（TUN経由）。
- 問い合わせを許す範囲は、全体の設定のLANのプレフィックスから作る。
- 上流のDNSサーバは、全体の設定に書くか（`upstream`）、`ruster-dhcpc`や`ruster-pppoed`がWAN側で得た値を
  使う（`upstream-from`に送り手の名前を書く）。得た値は送り手としてconfdへ渡り、confdは`dns`の部分を
  `ruster-unbound`へ渡すとき、その送り手が今持つDNSサーバを別の欄（`upstream-found`）で添える。lockの
  ファイルには入れない。`ruster-unbound`は`upstream`の後にそれらへforwardする。値が変われば部分を渡し直す。
- `ruster-unbound`は、待ち受け、許す範囲、上流を一つのファイルに書き、運用者の`unbound.conf`がそれを
  `include-toplevel:`で取り込む。ほかの設定（`local-data`など）は運用者のファイルに書く。
- 書いたら`systemctl restart unbound`（変えられる）で読み直させる。`unbound-control reload`では、
  新しい待ち受けのアドレスが開かれないため。

## 自作の制御

| プロセス | 中身 | 得た値の渡し先 |
|---|---|---|
| `ruster-pppoed` | PPPoEのDiscovery（RFC 2516）、LCP（RFC 1661）、認証（PAP、CHAP: RFC 1994）、IPCP（RFC 1332）、IPv6CP（RFC 5072） | セッション、アドレス、DNSサーバはconfd（DNSサーバはconfdから`ruster-unbound`へ）、経路はribd |
| `ruster-dhcpc` | DHCPv4（RFC 2131）、DHCPv6（RFC 8415）とプレフィックスの委任 | アドレス、プレフィックス、DNSサーバはconfd（DNSサーバはconfdから`ruster-unbound`へ）、経路はribd |
| neighd（RA） | LANへのRA（RFC 4861の6節） | なし。広告するプレフィックスはconfdから受け取る |

- PPPoEとDHCPのフレームは、FEの受け渡しの表で担当のプロセスへ渡す（[`fe-ce-split.md`](fe-ce-split.md)の
  「L2の制御のフレーム」）。
- 委任されたプレフィックスからLANのアドレスとMAP-Eの値を計算するのはconfd。全体の設定に「LANのIPv6は
  送り手`dhcp6-wan`の委任から、サブネット番号1」と書く（`ipv6-from = { source = "dhcp6-wan", subnet = 1 }`）。
  confdはそのサブネットの/64を作り、ルータのアドレスはその::1にする（MACからのEUI-64にしないのは、
  機器を替えてもアドレスが変わらないようにするため）。
- RAはNDの一部なのでneighdに置く。設定は全体の設定の`[[ra]]`（インターフェースごと）で、neighdは
  `confd/part.sock`のモジュール`ra`で受け取る。neighdがconfdから受けている表（インターフェースとアドレス）は
  FEの表と同じ形で、RAの設定はその形に無いため。広告するプレフィックスは、インターフェースのIPv6アドレスの
  /64からlockの形に入れる。DHCPv6-PDで委任されたプレフィックスは実行中の値なので、lockには送り手を
  `prefix-from`に書くだけにする。インターフェースに`ipv6-from`があれば、`[[ra]]`の`prefix-from`は
  その送り手になり、confdが委任から作った/64を、委任の寿命を付けてneighdへ渡す部分に足す。

## 今の設定ファイルからの移り方

今の`ruster apply`のTOMLは、FEの表をほぼそのまま書いた形。次の順で移す。

1. lockの形（YANGの型と、そのTOMLでの書き方）を決め、confdが読めるようにする。
   既定値はconfdの各所から外し、解決のライブラリへ集める。今のTOMLは、型が変わるまで`ruster.toml`として
   読み、解決してlockの形にする。
2. 実行中に決まる値を、全体の設定から外す。
   - PPPoEのセッション番号と相手のMAC、IPCPで得たアドレス → 送り手（種類`pppoe`）から。設定のPPPoEの
     インターフェースは親と送り手の名前だけを書く（`pppoe = { parent = "wan", source = "pppoe-wan" }`）。
     FEのセッションのインターフェースは、送り手がセッションを持つ間だけある。送り手は`ruster-pppoed`か、
     手で書く道具（`ruster source`）。
   - MAP-Eのプレフィックス → `ruster-dhcpc`の委任から（`[map-e]`の`prefix-from`。固定の`prefix`も書ける）。
3. confdが各プロセスへ担当の部分を配り、候補、差分、確定を揃える形にする。
4. `ruster.toml`と、それを解決してlockの形にする機能。
5. APIから設定を入れる口。

## 確かめ方

netnsの試験に、FRR、Kea、Unboundを実際に動かす構成を足す。今のnetnsの試験と同じくローカルで回し、CIには入れない。
FRR、Kea、UnboundはUbuntuのパッケージを使う。

- FRR: 隣のnetnsのFRRとBGPを張り、受けた経路でFEが転送する。
- Kea: LANのホストがDHCPでアドレスを得て、WANへ出られる。DHCPv6も同じ。
- Unbound: LANのホストが名前を引ける。
- PPPoE: 隣のnetnsのPPPoEサーバ（`pppoe-server`）とセッションを張り、MAP-EやNATの外側として使う。
- DHCPクライアント: 隣のnetnsのKeaからアドレスとプレフィックスを得て、LANのRAとMAP-Eに使う。

## 作る順番

1. `ruster.lock`と反映の流れ（上の「移り方」の1から3）。`ruster.toml`の新しい書き方は、lockの形が落ち着いてから。
2. Unbound。橋渡し役の型を決める。
3. Kea（リレーを含む）と、neighdのRA。
4. `ruster-dhcpc`（MAP-Eのプレフィックスを全体の設定から外す）。
5. FRR。
6. `ruster-pppoed`。

## 未決事項

- APIの形（CORECONFのままか、外から使いやすい形を足すか）。
