# Ruster

Rustで実装するソフトウェアルータ。ネットワーク学習を目的としたプロジェクト。

## クイックリファレンス

```bash
# ビルド
cargo build

# テスト（ユニットテスト）
cargo test

# フォーマット・リント
cargo fmt
cargo clippy

# E2Eテスト（Docker/Containerlab必要）
cargo test --test e2e -- --ignored --test-threads=1
```

## プロジェクト構造

```
src/
├── capture/    # パケットキャプチャ (AF_PACKET等)
├── config/     # 設定ファイルパース・バリデーション
├── dataplane/  # データプレーン処理パイプライン
├── protocol/   # プロトコル実装 (Ethernet, IPv4, ICMP等)
├── error.rs    # エラー型定義
├── lib.rs      # ライブラリエントリポイント
└── main.rs     # バイナリエントリポイント
```

## 設計原則

1. **L1はLinuxに委任**: ハードウェア固有の設定はLinuxの機能を活用
2. **L2以上は自前実装**: スイッチング・ルーティングをユーザースペースで処理
3. **外部ライブラリ非依存**: ネットワーク処理部分（パケット解析、ルーティング）は独自実装
4. **設定の透明性**: lockファイルによる完全な設定可視化

## テスト

- **ユニットテスト**: プロトコルパース、ルーティングテーブル等
- **E2Eテスト**: Containerlabを使用。Dockerが必要。`tests/e2e/`以下に配置

E2Eテストはシングルスレッド実行が必要（`--test-threads=1`）

## 注意事項

- ruster実行時はAF_PACKET使用のためroot権限が必要
