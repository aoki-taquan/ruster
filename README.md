# ruster

自宅ラボで実用でき、挙動を自分で説明できるソフトウェアルータを、パケット処理コアから作るプロジェクトです。

`main`の旧実装は [`prototype-v0.1`](docs/prototype-v0.1.md) として固定しました。現在の
active treeは、そのコードを継承しないv0.2のゼロベース実装です。

## v0.2 bootstrap

この最初の縦切りは、外部依存を持たない二つのlibrary crateだけで構成します。

- `ruster-core`: backend所有packetを借用し、Ethernet II / IPv4検証、LPM、
  TTL/checksum/MAC rewrite、local IPv4向けARP reply、static neighbor miss時の
  ARP Request生成actionを扱う。
- `ruster-io-sim`: rootやNICなしでRX/generated TXのFIFO、budget、TX/drop、
  traceを決定的に検証する。

```text
inject Vec<u8>
      │
      ▼
sim RX slot ──borrow──► ruster-core ──commit──► sim TX slot
                            │
                            └──recycle────────► drop capture
```

fast pathはpacket batchをworkerが専有します。共有`Mutex`、packet単位の`String`、
packet clone、`dyn PacketIo`を導入しません。simの`Vec`はcold I/O境界に閉じています。
ARP replyも同じRX bufferをin-placeで書き換え、受信interfaceへcommitします。現在の
ARP profileはinterfaceごとにlocal IPv4を一つだけ持つ静的snapshotです。

static neighbor missでは元IPv4 packetをbyte不変でrecycleした後、worker-localな固定
storageで1秒に一度までARP Requestを生成できます。RX batchとgenerated TX sessionは
二相に分離し、生成frameもbackend所有bufferを借用します。これはrequest generationと
flood suppressionまでであり、reply学習やpacket holdを含むactive resolutionではありません。

## 開発

stable Rustだけで検証できます。

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo test --doc --workspace
RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --no-deps
cargo check --workspace
```

設計契約と非対象は[architecture v0.2](docs/architecture-v0.2.md)、要件とRFC根拠は
[requirements](docs/requirements-v0.2.md)を参照してください。
