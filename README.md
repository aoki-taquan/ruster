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
| `ruster-neighd` | ARP。FEから受け取って答え、問い合わせる | 近隣 |

ルーティングデーモン、DHCP、DNSはrusterに組み込みません。外のデーモンがconfdやribdへ渡します。

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

- IPv4の転送だけ。
- VRFは`default`の一つだけ。
- 経路は静的なものと直結だけ。

実際のNICや回線ではまだ試していません。

`ruster-core`には、見直し前の作りのARPの処理がまだ残っています（neighdへ移した後に消す）。
NAT、firewall、フラグメントの処理もcoreにあり、表としてFEにつなぐのはこれからです。

## 動かす

ビルドします。

```bash
cargo build --workspace --locked
```

confdが読む設定ファイルはTOMLです。

```toml
[[interface]]
name = "lan"                  # FEのポート（Linuxのデバイス名）
mac = "02:00:00:00:00:01"
ipv4 = "192.0.2.1/24"
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
ruster-confd router.toml &
```

FEは既定でAF_XDPを使い、各デバイスのqueue 0にXDPのプログラムを付けます（`--xdp-attach native|generic`、
`--zero-copy`）。`--backend af-packet`ではAF_PACKETを使います。AF_PACKETはkernelからフレームを取り上げないので、
FEに渡すデバイスにはkernelのアドレスや経路を付けず、kernelでの転送も切っておきます。
どちらでも、FEのポートのMACはデバイスのMACと同じにします。

どのプロセスも準備ができるとsystemdに知らせるので、unitは`Type=notify`にできます。FEはSIGTERMかSIGINTで、
kernelに渡したフレームが戻るのを最大1秒待ってから止まります（二度目のシグナルですぐ止まる）。

相手のプロセスが落ちると、残ったプロセスは1秒ごとにつなぎ直し、自分の表を全部送り直します。
CEのプロセスが落ちている間も、FEは持っている表で転送を続けます。

### netnsでの試験

2台のホストとルータを別々のnetnsに作り、vethでつないで、両方向にpingが通ること、各プロセスを起動し直しても転送が戻ることを確かめます。
rootが要るのでCIでは回していません。

```bash
cargo build --workspace --locked
sudo scripts/netns-skeleton.sh target/debug                       # AF_XDP
sudo FE_BACKEND=af-packet scripts/netns-skeleton.sh target/debug  # AF_PACKET
```

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
| `confd`、`ribd`、`neighd` | CEのプロセス |
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
