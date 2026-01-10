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
cargo test --test e2e --features e2e
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

## GitHub CLI使用ルール

**重要**: `gh issue view` や `gh pr view` は必ず `--json` フラグを使用すること。

GitHub Projects (classic) の廃止により、素の `gh issue view` はエラーになる。

```bash
# NG - エラーになる
gh issue view 8

# OK - 必要なフィールドを指定
gh issue view 8 --json title,labels,state
gh pr view 42 --json number,title,state,url
```

## 並列開発ワークフロー

固定スロット方式でworktreeを使用:

```bash
# 事前に作成済み
/home/aoki/ruster    # メインリポジトリ
/home/aoki/ruster-1  # スロット1
/home/aoki/ruster-2  # スロット2
...
/home/aoki/ruster-5  # スロット5

# 各スロットでClaude Codeを起動
cd ~/ruster-1 && claude
> /issue-start 9
```

- `wip`ラベルで重複作業を防止
- 各スロットは独立して並列作業可能

## テスト

- **ユニットテスト**: プロトコルパース、ルーティングテーブル等
- **E2Eテスト**: Containerlabを使用。Dockerが必要。`tests/e2e/`以下に配置

E2Eテストは動的トポロジー名により並列実行可能

## 注意事項

- ruster実行時はAF_PACKET使用のためroot権限が必要
