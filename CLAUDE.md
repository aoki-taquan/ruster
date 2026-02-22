# ruster — CLAUDE.md

## Project Overview

ruster は自宅ラボ向けフルスクラッチソフトウェアルータ。v0.1 は L2/L3 転送 + NAT を最小有効プロダクトとして実装する。

### Workspace 構成 (5 crates)

| Crate | パッケージ名 | 役割 |
|-------|-------------|------|
| `crates/config` | ruster-config | 設定ロード・検証 (`router.toml`) |
| `crates/control` | ruster-control | validate → plan → apply フロー |
| `crates/dataplane` | ruster-dataplane | パケット処理・転送エンジン |
| `crates/observe` | ruster-observe | 統計・カウンタ・可観測性 |
| `crates/main` | ruster | エントリポイント |

### Key Files

- `router.toml.example` — 設定ファイルの完全サンプル
- `docs/v0.1-requirements.md` — v0.1 要件定義
- `docs/v0.1-implementation-issues.md` — Issue 分解 (I-001〜I-014)
- `docs/router-toml-schema-v0.1.md` — router.toml スキーマ定義
- `docs/rfc-matrix.md` — RFC 準拠管理マトリクス

---

## Build / Test / Lint

```bash
# ビルド
cargo build --workspace

# テスト
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# フォーマットチェック
cargo fmt --all -- --check

# 一括 CI チェック
make ci
```

---

## Issue-Driven Development

### Issues

v0.1 の実装は Issue #86–#99 (I-001〜I-014) で管理する。

| Milestone | Issues |
|-----------|--------|
| M1: Bootstrap & Config | #86 (I-001), #87 (I-002), #88 (I-003), #89 (I-004) |
| M2: L2/L3 Dataplane | #90 (I-005), #91 (I-006), #92 (I-007), #93 (I-008) |
| M3: NAT/FW | #94 (I-009), #95 (I-010), #96 (I-011) |
| M4: Operations & Testing | #97 (I-012), #98 (I-013), #99 (I-014) |

### ブランチ命名

```
issue/<num>-<slug>
```

例: `issue/87-dpdk-base`, `issue/90-packet-parse`

### ワークフロー

1. `issue-start` skill で Issue 着手 → worktree 作成 + `wip` ラベル付与
2. 実装・テスト
3. `issue-pr` skill で PR 作成 → CI pass → `wip` ラベル削除

---

## Git Worktree

並行作業は `.worktrees/` 配下の Git worktree で行う。

```bash
# worktree 作成
make worktree-start NUM=87 DESC=dpdk-base

# worktree 一覧
make worktree-list

# worktree 削除
make worktree-clean NUM=87 DESC=dpdk-base
```

配置: `.worktrees/<NUM>-<DESC>/`

---

## Teammate Mode (tmux)

tmux セッション `ruster-team` で最大 4 ペイン (lead + w1/w2/w3) の並行作業を行う。

```bash
# チーム起動
make team-start

# チーム停止
make team-stop
```

---

## RFC Comment Conventions

### RFC-REF（準拠根拠）

```rust
// RFC-REF: RFC 791 Section 3.1
// IPv4 header の Total Length は header + data の合計バイト数
```

### RFC-DEVIATION（非準拠の明示）

```rust
// RFC-DEVIATION:
// reason: home-lab 用途で実装コストを優先
// impact: 特定の相互接続で非互換の可能性
// issue: #95
// plan: v0.2 で準拠化
```

CI (`rfc-check.yml`) で `RFC-DEVIATION` コメントに `reason`, `impact`, `issue`, `plan` が揃っていない場合は失敗する。

---

## gh CLI ルール

- `gh issue view` は必ず `--json` フラグ付きで使用する
- 例: `gh issue view 87 --json title,labels,state,milestone`
- HTML 出力を使わない（パース不安定のため）
