# ruster

どこでも動き、何にでも使えるソフトウェアルータです。同じ転送部が、ソフトウェアのルータ箱、
router as a service、DPUで動くことを目指しています。ハードウェアスイッチは対象外です。

何を作り、何を作らないかは[`docs/charter.md`](docs/charter.md)で決めています。
作業を選ぶときはまずそれを読んでください。

## 構成

ルータを転送部（FE）と制御部（CE）に分けます。

- FEは表を持ち、表に従ってパケットを転送するだけです。パケットの到着ペースで変わる状態
  （NATやfirewallの状態）だけをFEに置きます。
- CEは別々のプロセスです。ARP/ND、経路の選択、設定の管理はここで行います。
- 一つの表を書くのは一つのプロセスだけです。間に共有DBやメッセージバスは置きません。
  プロセスどうしは、固定の場所のUnix socketで決まった形式のメッセージをやりとりします
  （YANG + CBOR、CORECONFの操作、CoAPの枠組み）。
- CEのプロセスが落ちても、FEは持っている表で転送を続けます。

| プロセス | 役目 | 書く表 |
|---|---|---|
| `ruster-fe` | パケットの転送。AF_XDPかAF_PACKETの上で動く | — |
| `ruster-confd` | 設定ファイルを読み、各プロセスへ渡す | インターフェース、アドレス |
| `ruster-ribd` | 送り手（confdや外のデーモン）の経路から選び、FEへ渡す | 経路 |
| `ruster-neighd` | ARPとND。FEから受け取って答え、問い合わせる。LANへRAを送る | 近隣 |
| `ruster-pppoed` | PPPoEのセッションを張る（Discovery、LCP、PAP/CHAP、IPCP、IPv6CP）。得た値はまだ標準出力に書くだけ | — |
| `ruster-unbound` | confdから設定の`[dns]`を受け取り、Unboundの設定に書いて読み直させる | — |
| `ruster-kea` | confdから設定の`[[dhcp]]`と`[[dhcp6]]`を受け取ってKeaの設定に書き、LANとKeaの間でDHCPとDHCPv6をリレーする | — |

ルーティングデーモン、DHCP、DNSはrusterに組み込みません。外のデーモンがconfdやribdへ渡します。DNSのサーバはUnboundで、`ruster-unbound`がconfdの設定をUnboundの設定に変えます。DHCPのサーバはKeaで、`ruster-kea`が同じように設定を変え、FEから渡されたDHCPをKeaへリレーします。ルーティングデーモンはFRRで、`ruster-frr`が設定の`[bgp]`をFRRの設定に変え、zebraからFPMで受けた経路をribdへ渡します。

設計の詳細は`docs/design/`にあります。

| 文書 | 中身 |
|---|---|
| [`overview.md`](docs/design/overview.md) | 全体の形、通信の流れ、VRF、起動と落ちたとき |
| [`fe-ce-split.md`](docs/design/fe-ce-split.md) | 何をFEとCEのどちらに置くか |
| [`control-protocol.md`](docs/design/control-protocol.md) | メッセージの形式とsocketの置き場所 |
| [`tables.md`](docs/design/tables.md) | FEの表の一覧 |
| [`fe-internals.md`](docs/design/fe-internals.md) | FEの中の仕事の分け方とスレッドの置き方 |
| [`ce-processes.md`](docs/design/ce-processes.md) | confd、ribd、neighdの役目 |
| [`implementation-plan.md`](docs/design/implementation-plan.md) | 作る順番と、今どこまでできたか |

## 今の状態

今どこまでできたかは[`implementation-plan.md`](docs/design/implementation-plan.md)の一か所だけに書きます。

今動いている範囲は次のとおりです。

- IPv4とIPv6の転送。近隣はneighdがARPとNDで解決する。ICMPとICMPv6のエラーを返す。
- ルータ宛ての通信は、種類ごとに数を抑えてVRFごとのTUNでkernelに渡す。
- VRFは複数持てる。別のVRFのインターフェースへ送る経路と、lookup-vrfで経路を漏らせる。
- VLAN（802.1Q）のサブインターフェースを持てる。AF_PACKETでは、kernelが外したタグをバックエンドがフレームに戻す。
- 経路は静的なもの、直結、FRRのBGP（直結の近隣だけ）。

実際のNICや回線ではまだ試していません。

ARPとNDの解決はneighdが行い、FEは受けたARPとNDをneighdへ渡します。
default VRFの転送のfirewallは、設定ファイルの規則でFEが使います。IPv4とIPv6の両方で、状態を追います（IPv6の先頭でないフラグメントは落とします）。アドレスを書かないtcp/udpの規則はIPv6にも効くので、`ingress`を書かない規則は、IPv6では外からLANへの通信も通します。ルータ自身はLANのホストと同じ扱いで、規則では`rt-default`と書きます（ルータ宛ては`egress = "rt-default"`、ルータが出す通信は`ingress = "rt-default"`）。
default VRFのNAPT（UDP、TCP、ICMP）も、設定ファイルの`[nat]`でFEが使います。
DS-LiteのB4として、設定ファイルの`tunnel`のインターフェースでIPv4をIPv6に包んでAFTRへ送れます。
MAP-EのCEとして、設定ファイルの`[map-e]`から共有のIPv4 address、PSID、CEのIPv6 addressを計算し、PSIDのポートの組でNAPTしてBRへ送れます。ルータ自身のIPv4も同じです。
PPPoEのセッション（RFC 2516）を、設定ファイルの`pppoe`のインターフェースで使えます。FEは包むのと外すのだけを行います。セッションは`ruster-pppoed`が張りますが、得た値（セッションの番号、ACのMAC、アドレス）は、まだ手で設定ファイルに写します。
FEは、egressのMTUより長いIPv4のdatagramをフラグメントにし（Don't Fragmentが無いもの）、NATはフラグメントになったdatagramも変換します。

## 動かす

ビルドします。

```bash
cargo build --workspace --locked
```

confdが読む設定ファイルはTOMLです。書き方の全体は`crates/config`の説明にあります。既定値を全部埋めたlockの形（`ruster resolve`の出力）もそのまま読めます。

```toml
[[interface]]
name = "lan"                  # FEのポート（Linuxのデバイス名）
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"
ipv6 = ["2001:db8:1::1/64"]   # リンクローカルアドレスはMACから自動で付く
# mtu = 1500                  # 省略すると1500
# enabled = true              # 省略するとtrue

[[interface]]
name = "wan"
mac = "02:00:00:00:00:02"
ipv4 = "198.51.100.2/24"

[[route]]
prefix = "0.0.0.0/0"
interface = "wan"
via = "198.51.100.1"          # 省略すると直結の経路
```

起動はFEが先です。ほかのプロセスは、相手のsocketができるまで10秒待ちます。socketは
`/run/ruster`の下にでき、`--run-dir`で場所を変えられます。

```bash
sudo ruster-fe lan wan &         # 転送するデバイスを並べる。rootが要る
ruster-ribd &                    # 送り手を省略すると confd:1
ruster-neighd &
ruster-confd --kernel router.toml &   # --kernel: ルータ宛ての通信のTUNとアドレスも作る
```

FEは既定でAF_XDPを使い、各デバイスのqueue 0にXDPのプログラムを付けます（`--xdp-attach native|generic`、
`--zero-copy`）。`--backend af-packet`ではAF_PACKETを使います。AF_PACKETはkernelからフレームを取り上げないので、
FEに渡すデバイスにはkernelのアドレスや経路を付けず、kernelでの転送も切っておきます。
どちらでも、FEのポートのMACはデバイスのMACと同じにします。

ルータ宛ての通信（ping、SSH、DNSなど）は、VRFごとのTUN（`rt-<VRF名>`）でルータのkernelに渡ります。
`confd --kernel`がTUNとVRFデバイスを作ってルータのアドレスを付け、kernelでの転送を止めます。
既定経路を置き換えるので、ルータ専用のnetnsで動かします。FEのポートは、どのバックエンドでも
アドレスの無いVRFに入れておきます（kernelがポートで受けたフレームを自分宛てとして扱わないように）。

どのプロセスも準備ができるとsystemdに知らせるので、unitは`Type=notify`にできます。FEはSIGTERMかSIGINTで、
kernelに渡したフレームが戻るのを最大1秒待ってから止まります（二度目のシグナルですぐ止まる）。

相手のプロセスが落ちると、残ったプロセスは1秒ごとにつなぎ直し、自分の表を全部送り直します。
CEのプロセスが落ちている間も、FEは持っている表で転送を続けます。同じプロセスを二重に起動すると、
後の方は起動のときに止まります。

### `ruster`コマンド

```bash
ruster check router.toml                     # confdと同じ読み方で設定ファイルを確かめる
ruster resolve router.toml                   # 既定値を全部埋めた形（lockの形）を表示する
ruster apply router.toml                     # 確かめてから、動いているconfdの設定を置き換える
ruster show                                  # FEが持っている表を全部表示する
ruster route add --source routed 203.0.113.0/24 dev wan via 198.51.100.1
ruster route del --source routed 203.0.113.0/24
```

`apply`は、confdが変わった分をFE、ribd、neighdへ送り、全部が受け取ってから答えます。どれかが断ると
confdは前の設定に戻します。新しい設定はconfdのメモリにだけあり、confdを起動し直すと起動時のファイルを読みます。

`route`は、ルーティングデーモンと同じように、ribdの送り手（ここでは`routed`。ribdを`confd:1 routed:20`の
ように起動しておく）として経路を書きます。ribdは送り手の優先度で選んでFEへ渡します。

### netnsでの試験

2台のホストとルータを別々のnetnsに作り、vethでつないで、IPv4とIPv6の両方向にpingが通ること、各プロセスを起動し直しても転送が戻ることを確かめます。
rootが要るのでCIでは回していません。
どのスクリプトも`FE_BACKEND=af-packet`を付けるとAF_PACKETで回ります。

```bash
cargo build --workspace --locked
sudo scripts/netns-skeleton.sh target/debug                       # AF_XDP
sudo FE_BACKEND=af-packet scripts/netns-skeleton.sh target/debug  # AF_PACKET
sudo scripts/netns-vrf.sh target/debug       # VRF: 同じアドレスの2つのVRFと、片方だけの漏らし
sudo scripts/netns-vlan.sh target/debug      # VLAN: 同じポートの2つのVLANとタグなしの上流
sudo scripts/netns-firewall6.sh target/debug # IPv6のfirewall: 外へ出るTCPとping6の戻りだけが入る
sudo scripts/netns-all.sh target/debug       # 全部を両方のバックエンドで（組み合わせの構成も含む）
```

機能を組み合わせた構成の試験は、`netns-vlan-nat.sh`（VLANの上のNATとfirewall）、`netns-pppoe-nat.sh`
（PPPoEの上のNATとfirewall）、`netns-map-e-pppoe.sh`（PPPoEの上のMAP-E）、`netns-vrf-vlan.sh`（VLANごとのVRF）、
`netns-dslite-firewall6.sh`（DS-LiteとIPv6のfirewall）、`netns-vrf-firewall.sh`（VRFとfirewall）です。
`netns-pppoed.sh`は、`pppoe-server`（パッケージ`pppoe`と`ppp`）を相手に、pppoedのセッションをIPCPとIPv6CPまで張ります（FEは通さない）。
`netns-dns.sh`は、LANのホストがルータのUnboundで名前を引けることを確かめます（`unbound`と`dig`が要る）。
`netns-dhcp.sh`は、LANのホストがKeaからアドレスを得てWANへ出られることを確かめます（`kea-dhcp4-server`と`udhcpc`が要る）。`netns-dhcp6.sh`はDHCPv6で同じことを確かめます（`kea-dhcp6-server`と`busybox`）。`netns-ra.sh`は、LANのホストがneighdのRAでSLAACのアドレスと既定経路を得ることを確かめます。`netns-dhcpc.sh`は、`ruster-dhcpc`がISP側のKeaからWANのIPv4アドレスと委任されたプレフィックスを得て、LANのホストがNATでISP側へ出られることを確かめます（`kea-dhcp4-server`と`kea-dhcp6-server`）。`netns-map-e-pd.sh`は、MAP-EのプレフィックスをDHCPv6-PDから得て同じことを確かめます。`netns-bgp.sh`は、隣のnetnsのFRRとBGPを張り、受けた経路でLANのホストがその先へ届くことと、取り下げで経路が消えることを確かめます（`frr`が要る）。どれもインターネットにはつながない。

## 開発

stable Rustだけで確かめられます。mergeの前に次の4つを実行します。CIも同じものを1つのjobで回します。

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --doc --workspace --all-features --locked
```

- 進め方の決まりは[`AGENTS.md`](AGENTS.md)にあります。
- レビューで出たMedium以下の指摘は、`backlog`ラベルの[issue](https://github.com/aoki-taquan/ruster/issues?q=label%3Abacklog)にしています。

### crate

| crate | 中身 |
|---|---|
| `fe` | FE（`ruster-fe`） |
| `confd`、`ribd`、`neighd`、`pppoed`、`dhcpc` | CEのプロセス |
| `unbound`、`kea`、`frr` | Unbound、Kea、FRRの橋渡し役（`ruster-unbound`、`ruster-kea`、`ruster-frr`。Keaの方はDHCPv4とDHCPv6のリレーも、FRRの方はFPMの受け手も） |
| `cli` | `ruster`コマンド |
| `config` | 設定の書き方（`ruster.toml`と、既定値を全部埋めたlockの形）と、その解決 |
| `proto` | プロセス間のメッセージ（CBOR、CoAPの枠組み、表、接続、起動まわり） |
| `core` | パケットの検証と転送の判断。packet bufferは借りるだけで、割り当てをしない |
| `io-afpacket`、`io-xdp`、`io-xdp-native`、`io-sim` | FEのI/O層（AF_PACKET、AF_XDP、試験用のsim） |
| `io-conformance` | I/O層が共通に満たす試験 |
| `e2e` | sim上で4つのプロセスをつないだ試験 |
| `bench` | NICなしで`core`の性能を測る |

2026年3月の試作はGit tag
[`prototype-v0.1`](https://github.com/aoki-taquan/ruster/tree/prototype-v0.1)に残しています。
そのRustの実装はcopyせず、使うのはRFCと、入力と期待値の例だけです。

## ライセンス

MIT OR Apache-2.0
